//! `warden label` — v1-native CRUD for `[[labels]]` entries.
//!
//! Sibling of `warden group` / `warden device`: list / show / add / set /
//! remove, `--into <file>` target selection, and the pre-promote
//! validating writer on every mutation. Singular verb, like every other
//! entity family.
//!
//! # One structural difference from every other entity command
//!
//! A label's identity is the **pair** `(kind, id)`, not `id` alone — the
//! validator deliberately legalises `personal` as a `department`
//! and `personal` as a `device-type` in the same config. The id-keyed
//! helpers in
//! [`super::target`] ([`upsert_id_keyed`](super::target::upsert_id_keyed),
//! [`find_target_for_id`](super::target::find_target_for_id)) would treat
//! those two rows as one and silently overwrite the first with the
//! second, so this module carries pair-keyed equivalents. The parts of
//! the pipeline that carry the safety properties —
//! [`read_or_empty`] and [`write_value_validated`], the latter running
//! the full loader against the *staged* bytes before the rename — are
//! the shared ones, unchanged.
//!
//! Because the pair is the identity, `show` / `set` / `remove` take an
//! optional `--kind` to disambiguate. It is only ever *needed* when one
//! id exists under two kinds; omitting it when the id is unique behaves
//! exactly like the other entity verbs.

use std::path::{Path, PathBuf};

use anyhow::bail;
use toml::Value;

use super::audit_emit::{current_uid, persist_cli_mutation_audit};
use super::format_config_errors;
use super::ipc_reload;
use super::target::{
    owner_candidate_files, read_or_empty, resolve_target_file, write_value_validated, EntityClass,
};
use crate::config::audit::{AuditEvent, AuditRecord, AuditResult};
use crate::config::loader::load_config;
use crate::config::schema::{ConfigV1, Id, Label, LabelKind};

/// How many referring entities `remove` names before eliding the rest.
const MAX_REFERENCES_SHOWN: usize = 5;

pub fn run_list(config_path: &Path) -> anyhow::Result<()> {
    let now = time::OffsetDateTime::now_utc();
    let loaded = load_config(config_path, now).map_err(format_config_errors)?;
    if loaded.config.labels.is_empty() {
        println!("no labels configured");
        println!(
            "add one with: warden label add <id> --kind <{}> [--display-name <name>]",
            LabelKind::valid_values().replace(", ", "|")
        );
        return Ok(());
    }
    println!("configured labels ({}):", loaded.config.labels.len());
    // Grouped by kind rather than printed in file order: the vocabulary
    // is read one dimension at a time ("who are the owners?"), and that
    // is also the shape the pickers will present.
    for kind in LabelKind::ALL {
        let of_kind: Vec<&Label> = loaded
            .config
            .labels
            .iter()
            .filter(|l| l.kind == kind)
            .collect();
        if of_kind.is_empty() {
            continue;
        }
        println!("  [{kind}]");
        for l in of_kind {
            match &l.description {
                Some(d) => println!("    {} \"{}\" — {d}", l.id.as_str(), l.display_name),
                None => println!("    {} \"{}\"", l.id.as_str(), l.display_name),
            }
        }
    }
    Ok(())
}

pub fn run_show(config_path: &Path, id: &str, kind: Option<&str>) -> anyhow::Result<()> {
    let kind = parse_kind_opt(kind)?;
    let now = time::OffsetDateTime::now_utc();
    let loaded = load_config(config_path, now).map_err(format_config_errors)?;
    let label = select_label(&loaded.config.labels, id, kind)?;
    print!("{}", render_label_detail(label));
    Ok(())
}

/// The body of `warden label show` — one field per line. Pure so it is
/// unit-testable; `run_show` prints it verbatim.
fn render_label_detail(l: &Label) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();

    let _ = writeln!(out, "id:           {}", l.id.as_str());
    let _ = writeln!(out, "kind:         {}", l.kind);
    let _ = writeln!(out, "display_name: {}", l.display_name);
    // `description` is inert — nothing reads it at runtime. Echoing it
    // here is the ONLY way the operator gets it back, which is the
    // entire justification for persisting the field.
    match &l.description {
        Some(d) => {
            let _ = writeln!(out, "description:  {d}");
        }
        None => {
            let _ = writeln!(out, "description:  (none)");
        }
    }

    out
}

// ── the writing seam ───────────────────────────────────────────
//
// The pipeline lives in `add_inner` / `set_inner` / `remove_inner`; the
// `run_*` verbs below are thin wrappers that print and reload.
//
// The TUI cannot call the `run_*` verbs: those are CLI-shaped and
// `println!` their outcome, which on a raw-mode alternate screen bypasses
// ratatui's diff buffer and staircases one column per line. So the split
// is the same one `groups.rs` already carries — replicate the *pipeline*,
// not the entry point, so there is one implementation rather than two
// that drift.
//
// All three are **sync**: the caller owns the post-write reload, so a TUI
// Save that changes several things costs one reload, not one per writer.
//
// `kind` arrives already parsed — `parse_kind` stays in the `run_*`, where
// the operator's raw string is.

/// What `add_inner` actually wrote, for the caller's toast and audit line.
//
// `Debug` on all three reports: a test that asserts a seam REFUSED writes
// `.unwrap_err()`, and that needs `T: Debug` to render the unexpected
// success. Without it the refusal tests cannot be written at all.
#[derive(Debug)]
pub(crate) struct AddReport {
    pub id: String,
    pub target_path: PathBuf,
}

/// What `set_inner` actually wrote.
#[derive(Debug)]
pub(crate) struct SetReport {
    pub id: String,
    // Both were `#[allow(dead_code)]` until the Labels tab's CRUD needed
    // to say WHICH file its Save landed in. That tab now reads them, in
    // `submit_label_edit`'s audit line and success message, so the
    // allowance is gone.
    pub fields: Vec<String>,
    pub target_path: PathBuf,
}

/// What `remove_inner` actually removed.
#[derive(Debug)]
pub(crate) struct RemoveReport {
    pub id: String,
    /// Read by the Labels tab's delete audit line; see
    /// [`SetReport`] for the allowance this used to carry.
    pub target_path: PathBuf,
}

/// Declare a vocabulary value. **Sync** — caller owns the post-write reload.
///
/// Builds a whole row and hands it to [`upsert_label`], NOT to
/// [`upsert_id_keyed`](super::target::upsert_id_keyed): a label's identity
/// is the `(kind, id)` PAIR (module header), and the id-keyed
/// helper would overwrite an existing `owner` row when a `device-type` of
/// the same id is added. `same_id_under_two_kinds_coexists` is that loss,
/// pinned.
pub(crate) fn add_inner(
    config_path: &Path,
    id: &str,
    kind: LabelKind,
    display_name: Option<&str>,
    description: Option<&str>,
    into: Option<&Path>,
) -> anyhow::Result<AddReport> {
    let _ = Id::new(id).map_err(|e| anyhow::anyhow!("invalid id: {e}"))?;

    let now = time::OffsetDateTime::now_utc();
    let loaded = load_config(config_path, now).map_err(format_config_errors)?;
    if loaded
        .config
        .labels
        .iter()
        .any(|l| l.kind == kind && l.id.as_str() == id)
    {
        bail!(
            "label \"{id}\" already exists with kind \"{kind}\". Use \
             `warden label set {id} <field> <value> --kind {kind}` or pick a different id."
        );
    }

    let mut tbl = toml::map::Map::new();
    tbl.insert("id".into(), Value::String(id.to_string()));
    tbl.insert("kind".into(), Value::String(kind.as_str().to_string()));
    tbl.insert(
        "display_name".into(),
        Value::String(display_name.unwrap_or(id).to_string()),
    );
    if let Some(d) = description {
        tbl.insert("description".into(), Value::String(d.to_string()));
    }

    let target_path = resolve_target_file(config_path, EntityClass::Labels, into)?;
    let (mut doc, _) = read_or_empty(&target_path)?;
    // A create, and the returned flag is what says so. `upsert_label`
    // replaces a matched (kind, id) row outright, so a replace reached from
    // here would reset every field this builder omits.
    anyhow::ensure!(
        upsert_label(&mut doc, kind, id, Value::Table(tbl))?,
        "label \"{id}\" (kind {kind}) appeared in {} between the duplicate check and the \
         write; nothing was changed",
        target_path.display()
    );
    write_value_validated(config_path, &target_path, &doc)?;
    audit(config_path, &target_path, "label.add", id);
    Ok(AddReport {
        id: id.to_string(),
        target_path,
    })
}

/// Write every field in `fields` in one validated write. **Mirrors
/// `groups::set_fields_inner` / `subnets::set_fields_inner`** — the
/// atomicity the two siblings already have and the one
/// `submit_label_edit` in the TUI was still missing: a
/// `set_inner`-per-field loop let a validator refusal on the second
/// field leave the first one written, so Discard stopped discarding —
/// the exact partial-apply trap already closed for subnets.
///
/// `field == "kind"` is refused here rather than folded in: moving a
/// label between vocabularies needs the destination-collision and
/// source-still-referenced checks [`set_inner`] runs on that path, and a
/// generic "diff N scalars, write once" helper has no sound way to
/// interleave them with an unrelated field's write in the same call. No
/// caller needs it to — `submit_label_edit` only ever diffs
/// `display_name`/`description`, and a CLI kind move stays single-field.
pub(crate) fn set_fields_inner(
    config_path: &Path,
    id: &str,
    kind: Option<LabelKind>,
    fields: &[(&str, &str)],
    into: Option<&Path>,
) -> anyhow::Result<SetReport> {
    anyhow::ensure!(
        !fields.iter().any(|(f, _)| *f == "kind"),
        "a kind change must go through the single-field path — batching it \
         with other fields would skip its collision/reference checks"
    );

    let now = time::OffsetDateTime::now_utc();
    let loaded = load_config(config_path, now).map_err(format_config_errors)?;
    // Resolve which row we are editing BEFORE touching a file, so an
    // ambiguous id is refused rather than silently resolved to whichever
    // row happens to come first on disk.
    let label = select_label(&loaded.config.labels, id, kind)?;
    let current_kind = label.kind;

    let target_path = find_label_file(config_path, current_kind, id, into)?;
    let (mut doc, _) = read_or_empty(&target_path)?;
    let entry = find_label_entry_mut(&mut doc, current_kind, id)?.ok_or_else(|| {
        anyhow::anyhow!(
            "label \"{id}\" (kind {current_kind}) not found in {}. Use `--into <file>` to \
             target a different include.",
            target_path.display()
        )
    })?;
    // In-memory only: a bad field value bails here, before any write, so
    // earlier fields in the same call never reach disk.
    for (field, value) in fields {
        apply_label_field(entry, field, value)?;
    }
    write_value_validated(config_path, &target_path, &doc)?;

    let fields_after = fields
        .iter()
        .map(|(f, v)| format!("{f}={v}"))
        .collect::<Vec<_>>()
        .join(",");
    audit_with_fields(config_path, &target_path, "label.set", id, fields_after);

    Ok(SetReport {
        id: id.to_string(),
        fields: fields.iter().map(|(f, _)| (*f).to_string()).collect(),
        target_path,
    })
}

/// Edit one field of one label. **Sync** — caller owns the post-write reload.
///
/// `kind` is the *selector*, not a new value: `None` means "disambiguate
/// via [`select_label`]", which refuses an id carried by two kinds rather
/// than editing whichever row is first on disk. Setting `field = "kind"`
/// is how the row is MOVED between vocabularies, and that path re-runs the
/// collision check against the destination pair and refuses the move while
/// any device still reads the kind being left — checks [`set_fields_inner`]
/// deliberately does not fold in, so that one field stays on this path and
/// everything else is a thin wrapper over the batch setter.
pub(crate) fn set_inner(
    config_path: &Path,
    id: &str,
    kind: Option<LabelKind>,
    field: &str,
    value: &str,
    into: Option<&Path>,
) -> anyhow::Result<SetReport> {
    if field != "kind" {
        return set_fields_inner(config_path, id, kind, &[(field, value)], into);
    }

    let now = time::OffsetDateTime::now_utc();
    let loaded = load_config(config_path, now).map_err(format_config_errors)?;
    // Resolve which row we are editing BEFORE touching a file, so an
    // ambiguous id is refused rather than silently resolved to whichever
    // row happens to come first on disk.
    let label = select_label(&loaded.config.labels, id, kind)?;
    let current_kind = label.kind;

    let new_kind = parse_kind(value)?;
    // A `--kind` move used to be able to subject the row's id to a
    // stricter contract: moving INTO the tag vocabulary required the
    // id to also be a `TagSlug` (letter-led, max 32), so `4chan` could
    // not make the move. That kind was removed, and the three
    // that remain share one id contract — so there is nothing left for
    // a move to re-check.
    if new_kind != current_kind {
        if loaded
            .config
            .labels
            .iter()
            .any(|l| l.kind == new_kind && l.id.as_str() == id)
        {
            bail!("label \"{id}\" already exists with kind \"{new_kind}\"");
        }
        // A move OUT of `current_kind` strands every device reading that
        // kind's field, which is the same loss `remove` refuses — so it
        // refuses in the same words. The collision check above guards the
        // DESTINATION vocabulary and says nothing about the one being left.
        let refs = references_to(&loaded.config, label);
        if !refs.is_empty() {
            bail!(
                "label \"{id}\" (kind {current_kind}) is still used by {}. Change or clear \
                 those values first — warden will not rewrite them for you.",
                elide(&refs)
            );
        }
    }

    let target_path = find_label_file(config_path, current_kind, id, into)?;
    let (mut doc, _) = read_or_empty(&target_path)?;
    let entry = find_label_entry_mut(&mut doc, current_kind, id)?.ok_or_else(|| {
        anyhow::anyhow!(
            "label \"{id}\" (kind {current_kind}) not found in {}. Use `--into <file>` to \
             target a different include.",
            target_path.display()
        )
    })?;
    apply_label_field(entry, field, value)?;
    write_value_validated(config_path, &target_path, &doc)?;
    audit_with_fields(
        config_path,
        &target_path,
        "label.set",
        id,
        format!("{field}={value}"),
    );
    Ok(SetReport {
        id: id.to_string(),
        fields: vec![field.to_string()],
        target_path,
    })
}

/// A removal that happened, plus the kind it resolved to.
///
/// The resolved kind is not on [`RemoveReport`], and `run_remove` names it
/// in its success line even when the operator omitted `--kind` — so the
/// private core carries it and the public seam does not.
struct RemovedLabel {
    report: RemoveReport,
    kind: LabelKind,
}

/// The whole removal pipeline, with the one outcome
/// `anyhow::Result<RemoveReport>` cannot express: `Ok(None)` means the
/// label was already absent.
///
/// That distinction is not decoration. `remove` is idempotent:
/// removing something that is not there exits 0 with a no-op line, and
/// `remove_absent_label_is_idempotent` pins it. An `Err` would make the
/// verb exit non-zero on the one path that must not.
fn remove_if_present(
    config_path: &Path,
    id: &str,
    kind: Option<LabelKind>,
    into: Option<&Path>,
) -> anyhow::Result<Option<RemovedLabel>> {
    let now = time::OffsetDateTime::now_utc();
    let loaded = load_config(config_path, now).map_err(format_config_errors)?;

    let matches: Vec<&Label> = loaded
        .config
        .labels
        .iter()
        .filter(|l| l.id.as_str() == id && kind.is_none_or(|k| l.kind == k))
        .collect();
    let label = match matches.len() {
        0 => return Ok(None),
        1 => matches[0],
        _ => bail!("{}", ambiguous_message(id, &matches)),
    };

    // The verb refuses, the validator warns. Removing a
    // label that entities still use would leave the config in the exact
    // state the vocabulary exists to report, without the operator ever
    // asking for it.
    let refs = references_to(&loaded.config, label);
    if !refs.is_empty() {
        bail!(
            "label \"{id}\" (kind {}) is still used by {}. Change or clear those values first \
             — warden will not rewrite them for you.",
            label.kind,
            elide(&refs)
        );
    }

    let label_kind = label.kind;
    let target_path = find_label_file(config_path, label_kind, id, into)?;
    let (mut doc, _) = read_or_empty(&target_path)?;
    if !remove_label(&mut doc, label_kind, id)? {
        // The pre-check above already PROVED this label exists in the merged
        // config, so "not found" here means it lives in a different file —
        // typically a wrong `--into`. Exiting 0 with a clean no-op message
        // would tell the operator it was removed when it was not. `set` bails
        // loudly in the same situation; this is the asymmetry, closed.
        bail!(
            "label \"{id}\" (kind {label_kind}) exists in the merged config but not in \
             {} — it is declared in another file. Re-run without --into to let warden \
             find it, or point --into at the file that declares it.",
            target_path.display()
        );
    }
    write_value_validated(config_path, &target_path, &doc)?;
    audit(config_path, &target_path, "label.remove", id);
    Ok(Some(RemovedLabel {
        report: RemoveReport {
            id: id.to_string(),
            target_path,
        },
        kind: label_kind,
    }))
}

/// Remove a label. **Sync** — caller owns the post-write reload.
///
/// Refuses while any entity still uses the value, with the same words the
/// CLI verb uses. Unlike the verb, an already-absent label is an **error**
/// here rather than a no-op: the return type carries no way to say
/// "nothing happened", so a caller holding a row that has since vanished
/// learns it instead of being told the removal succeeded. The CLI reaches
/// [`remove_if_present`] directly to keep its idempotent exit 0.
//
// `submit_label_modal` drives this from the delete confirm. The
// `#[allow(dead_code)]` it carried while only tests called it is
// therefore gone.
pub(crate) fn remove_inner(
    config_path: &Path,
    id: &str,
    kind: Option<LabelKind>,
    into: Option<&Path>,
) -> anyhow::Result<RemoveReport> {
    remove_if_present(config_path, id, kind, into)?
        .map(|removed| removed.report)
        // `select_label`'s two spellings verbatim, rather than a third one
        // for the same condition.
        .ok_or_else(|| match kind {
            Some(k) => anyhow::anyhow!("label not found: {id} (kind {k})"),
            None => anyhow::anyhow!("label not found: {id}"),
        })
}

// ── the printing verbs ─────────────────────────────────────────

pub async fn run_add(
    config_path: &Path,
    socket_path: &Path,
    id: &str,
    kind: &str,
    display_name: Option<&str>,
    description: Option<&str>,
    into: Option<&Path>,
) -> anyhow::Result<()> {
    // Deliberately re-validated here as well as inside `add_inner`:
    // `Id::new` ran BEFORE `parse_kind` in the monolithic verb, so dropping
    // it would flip `warden label add Bad_Id colour` from naming the id to
    // naming the kind. The seam is a cut, not a redesign — and one
    // idempotent re-check is cheaper than a reordered message.
    let _ = Id::new(id).map_err(|e| anyhow::anyhow!("invalid id: {e}"))?;
    let kind = parse_kind(kind)?;
    let report = add_inner(config_path, id, kind, display_name, description, into)?;
    println!(
        "added label {} (kind {kind}) → {}",
        report.id,
        report.target_path.display()
    );

    let outcome = ipc_reload::attempt_reload(socket_path).await;
    ipc_reload::report_reload_outcome(&outcome);

    Ok(())
}

pub async fn run_set(
    config_path: &Path,
    socket_path: &Path,
    id: &str,
    field: &str,
    value: &str,
    kind: Option<&str>,
    into: Option<&Path>,
) -> anyhow::Result<()> {
    let selector = parse_kind_opt(kind)?;
    let report = set_inner(config_path, id, selector, field, value, into)?;
    println!("updated {}.{field} = {value}", report.id);

    let outcome = ipc_reload::attempt_reload(socket_path).await;
    ipc_reload::report_reload_outcome(&outcome);

    Ok(())
}

pub async fn run_remove(
    config_path: &Path,
    socket_path: &Path,
    id: &str,
    kind: Option<&str>,
    into: Option<&Path>,
) -> anyhow::Result<()> {
    let selector = parse_kind_opt(kind)?;
    let Some(removed) = remove_if_present(config_path, id, selector, into)? else {
        // Removing something that is not there is a no-op, not
        // a failure. No reload either — nothing changed on disk.
        println!("label \"{id}\" not found — nothing to remove");
        return Ok(());
    };
    println!(
        "removed label {} (kind {})",
        removed.report.id, removed.kind
    );

    let outcome = ipc_reload::attempt_reload(socket_path).await;
    ipc_reload::report_reload_outcome(&outcome);

    Ok(())
}

// ── selection ──────────────────────────────────────────────────

fn parse_kind(s: &str) -> anyhow::Result<LabelKind> {
    s.parse::<LabelKind>().map_err(|e| anyhow::anyhow!("{e}"))
}

fn parse_kind_opt(s: Option<&str>) -> anyhow::Result<Option<LabelKind>> {
    s.map(parse_kind).transpose()
}

/// Resolve `<id> [--kind K]` to exactly one label, or explain why it
/// cannot. Never guesses: an id carried by two kinds with no `--kind`
/// is an error, because picking one would mean editing a row the
/// operator did not name.
fn select_label<'a>(
    labels: &'a [Label],
    id: &str,
    kind: Option<LabelKind>,
) -> anyhow::Result<&'a Label> {
    let matches: Vec<&Label> = labels
        .iter()
        .filter(|l| l.id.as_str() == id && kind.is_none_or(|k| l.kind == k))
        .collect();
    match matches.len() {
        0 => match kind {
            Some(k) => bail!("label not found: {id} (kind {k})"),
            None => bail!("label not found: {id}"),
        },
        1 => Ok(matches[0]),
        _ => bail!("{}", ambiguous_message(id, &matches)),
    }
}

fn ambiguous_message(id: &str, matches: &[&Label]) -> String {
    let kinds: Vec<&str> = matches.iter().map(|l| l.kind.as_str()).collect();
    format!(
        "label \"{id}\" exists under several kinds ({}) — pass `--kind <{}>` to say which one",
        kinds.join(", "),
        kinds.join("|")
    )
}

/// Everything still using this label's value, as operator-facing names.
/// Empty means the label is safe to remove.
///
/// Every `[[devices]]` field that carries this label's value.
///
/// **One search now, and it used to be two.** A `tag` label's uses were
/// `TagSlug`s in `tags` arrays on five entity types, matched exactly on
/// the id, and needed a whole second walk (`tag_references_to`) plus a
/// cross-check against an independent collector to keep the carrier set
/// honest. The tag-model cutover removed that kind and the arrays it
/// walked; what is left is the metadata search, which was always the
/// simple half: a scalar `Option<String>` on `[[devices]]`, matched
/// loosely (id *or* display name) because the device carries free text.
fn references_to(config: &ConfigV1, label: &Label) -> Vec<String> {
    let field = label.kind.device_field();
    let mut out = Vec::new();
    for d in &config.devices {
        let value = match label.kind {
            LabelKind::Owner => d.owner.as_deref(),
            LabelKind::DeviceType => d.device_type.as_deref(),
            LabelKind::Department => d.department.as_deref(),
        };
        if value.is_some_and(|v| label.matches_value(v)) {
            out.push(format!("device {}.{field}", d.id));
        }
    }
    out
}

fn elide(refs: &[String]) -> String {
    if refs.len() <= MAX_REFERENCES_SHOWN {
        return refs.join(", ");
    }
    format!(
        "{} and {} more",
        refs[..MAX_REFERENCES_SHOWN].join(", "),
        refs.len() - MAX_REFERENCES_SHOWN
    )
}

// ── pair-keyed TOML surgery ────────────────────────────────────

/// Identity predicate on a raw row: the `(kind, id)` PAIR. Every helper
/// below routes through it, so none of them can confuse an `owner`
/// entry with a `tag` entry that happens to share an id.
///
/// Private to this module: no caller outside it exists. It was
/// `pub(super)` for a time, when a Tags tab's `rename_tag_label_id`
/// called it from `super::tags` — the predicate travelled with its
/// caller rather than being re-spelled there, since a copy would be a
/// second definition of identity, the exact confusion this function
/// exists to prevent. That caller and the module it lived in are gone.
///
/// Recorded rather than silently narrowed: widening it again needs the
/// argument above, not just a compile error.
fn row_matches(item: &Value, kind: LabelKind, id: &str) -> bool {
    item.get("id").and_then(|v| v.as_str()) == Some(id)
        && item.get("kind").and_then(|v| v.as_str()) == Some(kind.as_str())
}

/// Pair-keyed counterpart of
/// [`upsert_id_keyed`](super::target::upsert_id_keyed). Returns `true`
/// if a new row was appended, `false` if an existing one was replaced.
fn upsert_label(doc: &mut Value, kind: LabelKind, id: &str, entry: Value) -> anyhow::Result<bool> {
    let table = doc
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("config root is not a TOML table"))?;
    let array = table
        .entry(EntityClass::Labels.toml_key().to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    let arr = labels_array_mut(array)?;
    for item in arr.iter_mut() {
        if row_matches(item, kind, id) {
            *item = entry;
            return Ok(false);
        }
    }
    arr.push(entry);
    Ok(true)
}

fn remove_label(doc: &mut Value, kind: LabelKind, id: &str) -> anyhow::Result<bool> {
    let table = doc
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("config root is not a TOML table"))?;
    let Some(array) = table.get_mut(EntityClass::Labels.toml_key()) else {
        return Ok(false);
    };
    let arr = labels_array_mut(array)?;
    let before = arr.len();
    arr.retain(|item| !row_matches(item, kind, id));
    Ok(arr.len() < before)
}

fn find_label_entry_mut<'a>(
    doc: &'a mut Value,
    kind: LabelKind,
    id: &str,
) -> anyhow::Result<Option<&'a mut Value>> {
    let table = doc
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("config root is not a TOML table"))?;
    let Some(array) = table.get_mut(EntityClass::Labels.toml_key()) else {
        return Ok(None);
    };
    Ok(labels_array_mut(array)?
        .iter_mut()
        .find(|item| row_matches(item, kind, id)))
}

fn labels_array_mut(value: &mut Value) -> anyhow::Result<&mut Vec<Value>> {
    value.as_array_mut().ok_or_else(|| {
        anyhow::anyhow!(
            "`{}` must be an array of tables",
            EntityClass::Labels.toml_key()
        )
    })
}

/// Locate the include file that owns `(kind, id)`.
///
/// Pair-keyed counterpart of
/// [`resolve_existing_target_file`](super::target::resolve_existing_target_file):
/// the id-keyed original would return the file holding the *homonym*
/// under another kind, and the caller would then fail to find its row
/// there. Candidate files come from the same include graph the loader
/// merged, so an entity in a hand-written `includes = [...]` glob is
/// found too. Falls back to the default creation target when nothing
/// matches, so a genuine not-found surfaces the normal error.
fn find_label_file(
    master: &Path,
    kind: LabelKind,
    id: &str,
    into: Option<&Path>,
) -> anyhow::Result<PathBuf> {
    if into.is_some() {
        return resolve_target_file(master, EntityClass::Labels, into);
    }
    for path in owner_candidate_files(master, &[EntityClass::Labels]) {
        let Ok(raw) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(value) = raw.parse::<Value>() else {
            continue;
        };
        if let Some(Value::Array(arr)) = value.get(EntityClass::Labels.toml_key()) {
            if arr.iter().any(|item| row_matches(item, kind, id)) {
                return Ok(path);
            }
        }
    }
    resolve_target_file(master, EntityClass::Labels, None)
}

fn apply_label_field(entry: &mut Value, field: &str, value: &str) -> anyhow::Result<()> {
    let tbl = entry
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("label entry is not a TOML table"))?;
    match field {
        "display_name" => {
            if value.is_empty() {
                bail!("display_name cannot be empty");
            }
            tbl.insert("display_name".into(), Value::String(value.to_string()));
        }
        "description" => {
            // An empty string clears the field rather than storing "",
            // so `set description ""` is the way to undo one.
            if value.is_empty() {
                tbl.remove("description");
            } else {
                tbl.insert("description".into(), Value::String(value.to_string()));
            }
        }
        "kind" => {
            let parsed = parse_kind(value)?;
            tbl.insert("kind".into(), Value::String(parsed.as_str().to_string()));
        }
        other => bail!("unknown field: {other}. Valid: display_name, description, kind"),
    }
    Ok(())
}

// ── shared tail ────────────────────────────────────────────────

fn audit(config_path: &Path, target: &Path, action: &'static str, id: &str) {
    let id = id.to_string();
    let target = target.to_path_buf();
    persist_cli_mutation_audit(config_path, move || {
        AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
            .with_uid(current_uid())
            .with_action(action)
            .with_scope("label")
            .with_target_id(id)
            .with_files([config_path, target.as_path()])
    });
}

fn audit_with_fields(
    config_path: &Path,
    target: &Path,
    action: &'static str,
    id: &str,
    fields_after: String,
) {
    let id = id.to_string();
    let target = target.to_path_buf();
    persist_cli_mutation_audit(config_path, move || {
        AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
            .with_uid(current_uid())
            .with_action(action)
            .with_scope("label")
            .with_target_id(id)
            .with_fields_after(fields_after)
            .with_files([config_path, target.as_path()])
    });
}

#[cfg(test)]
mod tests;
