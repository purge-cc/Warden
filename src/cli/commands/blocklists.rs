//! `warden blocklist` — v1-native CRUD for `[[blocklists]]` entries.
//!
//! Blocklists are external lists a profile reaches via its `lists`
//! override table or the list's own `base` direction. Each has a
//! stable [`Id`], a URL, a `format` (domains / adguard / hosts), and
//! optional fetch knobs (update interval, max entries, enabled flag,
//! auth_token_ref).
//!
//! A cross-reference check against `secrets.toml` runs when
//! `auth_token_ref` is set: a missing ref yields a warning (not an
//! error), matching the warn-not-error pattern used elsewhere for
//! secrets.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use toml::Value;

use super::audit_emit::{current_uid, persist_cli_mutation_audit};
use super::format_config_errors;
use super::ipc_reload;
// `Profile.blocklists` was removed, so the
// `apply_blocklists_change_inline` cascade helper is dead in this file.
use super::target::{
    read_or_empty, remove_id_keyed, resolve_existing_target_file, resolve_target_file,
    upsert_id_keyed, write_value_validated, write_values_validated, EntityClass, StagedWrite,
};
use crate::config::audit::{AuditEvent, AuditRecord, AuditResult};
use crate::config::loader::load_config;
use crate::config::schema::blocklist::{Blocklist, BlocklistBase, BlocklistFormat, BlocklistTrust};
use crate::config::schema::Id;
use crate::config::secrets::{load_secrets, secrets_path_for};
use crate::ipc::protocol::{IpcCommand, IpcResponse};
use crate::ipc::socket_client::send_command;
use crate::lists::manager::merge_sources_with_blocklists;
use crate::lists::source_key::{canonical_url_key, is_url_source, SourceBitMap};
use crate::lists::status::BlocklistStatusDto;

// ── retired: RULE_DANGLING_REF ──────────────────────────────────────
//
// `RULE_DANGLING_REF` and `format_rule_dangling_ref` were deleted here,
// together with their in-file tests and the two pins in
// `tests/frozen_strings_s43.rs`. The const read:
//
//     Cannot remove '{id}': still referenced by {n} entry/entries:
//     {list}. Use --cascade to also remove these references.
//
// It was doubly dead. It named `--cascade`, a flag that was deleted after
// establishing it did nothing; and the refusal it worded had no
// production emitter, because the profile↔list join became tags — no
// profile enumerates a blocklist id any more, so the cross-reference it
// reported cannot exist. No operator could ever have been shown it.
//
// Retired rather than reworded on purpose. A frozen-strings suite earns
// its authority from every pin being a string an operator can actually
// receive; a pin guarding text with no emitter teaches the next reader
// that entries in that suite are decorative, which is how the whole set
// stops being trusted. If a cascade-aware `blocklist remove` is built
// later it will need its own wording, pinned when it has a caller.
//
// Left as a comment, not silence, so the next reader who greps the old
// name in `DONE.md` or the review archive finds out where it went.

// ── Is this list actually filtering anything? ───────────────────────
//
// In the tag model a list names no profile and a profile names no list:
// a list filters for a client when their tag sets intersect. That
// indirection is the feature, and it is also why a subscription can be
// silently inert — nothing in the config is *wrong*, the tags simply
// never meet. A list in that state occupies a filter slot and RAM,
// downloads on schedule, reports success, and blocks nothing.
//
// Everything below answers one question — "does this list reach anyone?"
// — from the config alone, so `list` (which has no socket) and `show`
// give the same verdict. Whether the daemon has actually *installed* the
// list is a live measurement and stays in `show`'s `Runtime status:`
// block, which asks the daemon over IPC.

/// Operator-facing marker for a list that filters nothing.
///
/// Shouty on purpose and unique in the tree on purpose: it is what an
/// operator greps a long `blocklist list` for, and what the tests below
/// assert on. An empty "used by" field would read as a rendering
/// accident; this cannot.
pub const NOT_ENFORCED: &str = "NOT ENFORCED";

/// Every route by which a blocklist can reach a client, plus the doors
/// that shut it out no matter how its tags line up.
///
/// The three carrier lists hold entity ids, sorted by the order the
/// config iterates them (profiles come from a `BTreeMap`, so the output
/// is deterministic across runs).
#[derive(Debug, Default, PartialEq, Eq)]
struct Enforcement {
    /// Profiles whose own tags reach the list — it filters for every
    /// client that lands on one of them.
    profiles: Vec<String>,
    /// Devices reached by their own tags or their groups' tags, whatever
    /// profile the resolver chain lands them on.
    devices: Vec<String>,
    /// Subnets whose tags reach the anonymous clients on them (a device
    /// with its own record never inherits subnet tags).
    subnets: Vec<String>,
    /// `enabled = false` — the list is never fetched and never gets a
    /// filter slot.
    disabled: bool,
    /// The list holds no bit in the engine's source map, so no profile
    /// mask can point at it.
    no_filter_slot: bool,
}

impl Enforcement {
    /// Why this list filters nothing, or `None` when it does reach someone.
    ///
    /// Three independent doors, each with a different fix, so each names
    /// itself rather than collapsing into one "inert" verdict. Ordered
    /// most fundamental first — a disabled list's reach is irrelevant.
    fn blocked_reason(&self) -> Option<&'static str> {
        if self.disabled {
            return Some("enabled = false, so it is never fetched");
        }
        if self.no_filter_slot {
            return Some("it holds no slot in the filter engine's source map");
        }
        // "it has no tags of its own" is retired, not moved. Tags
        // stopped deciding anything, so an untagged list is not inert — it is
        // inherited by every profile from its own `kind`. The reason that
        // replaces it is the only one left that can make a list inert:
        // every profile saying `ignore`.
        if self.profiles.is_empty() {
            return Some("every profile ignores it (profiles.<id>.lists)");
        }
        None
    }

    /// Counts only — the names live in `show`, which has room for them.
    fn carriers_phrase(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if !self.profiles.is_empty() {
            parts.push(plural(self.profiles.len(), "profile"));
        }
        if !self.devices.is_empty() {
            parts.push(plural(self.devices.len(), "device"));
        }
        if !self.subnets.is_empty() {
            parts.push(plural(self.subnets.len(), "subnet"));
        }
        parts.join(", ")
    }

    /// The verdict as it appears on a `blocklist list` row.
    fn one_line(&self) -> String {
        match self.blocked_reason() {
            Some(reason) => format!("{NOT_ENFORCED} ({reason})"),
            None => format!("enforced by {}", self.carriers_phrase()),
        }
    }
}

fn plural(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("{n} {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

/// The 64-slot map the filter engine indexes lists by, built exactly the
/// way `warden start` builds it — legacy `[lists].sources` merged with
/// every enabled `[[blocklists]]` URL, then translated to bits.
///
/// A list with no slot holds no bit in any profile's mask, so it filters
/// nothing however well its tags line up. `None` means the map could not
/// be built at all (more than 64 sources, which `warden start` refuses
/// outright); in that case no slot claim is made either way, because a
/// guess here would be a fabricated measurement.
fn filter_slots(config: &crate::config::schema::ConfigV1) -> Option<SourceBitMap> {
    let (merged, _trust) = merge_sources_with_blocklists(&config.lists.sources, &config.blocklists);
    SourceBitMap::build(&merged, &config.blocklists).ok()
}

/// Work out who, if anyone, this list reaches.
///
/// The test is [`effective_direction`](crate::config::schema::effective_direction)
/// — the engine's own per-pair
/// predicate, called rather than copied. A read verb whose answer can
/// disagree with the filter it reports on is worse than no answer, and this
/// product has already paid for one duplicated tag rule that drifted.
///
/// # The narrowed answer is the feature
///
/// This used to walk three axes — profiles, devices, subnets — because tag
/// intersection could attach a list to any of them. It cannot any more:
/// direction is a property of the `(profile, list)` pair, so the only axis
/// that can carry a list is the **profile**. The device and subnet rows stay
/// in [`Enforcement`] and stay empty; they are what `show` prints when a
/// pre-v3 config is being read back, and emptying them here rather than
/// deleting the fields keeps that difference visible instead of silently
/// re-labelling it.
///
/// A device reaches a list through its profile, so "who does this list
/// reach" is answered one hop earlier than it used to be.
fn analyse_enforcement(
    config: &crate::config::schema::ConfigV1,
    b: &crate::config::schema::Blocklist,
    slots: Option<&SourceBitMap>,
) -> Enforcement {
    use crate::config::schema::{effective_direction, ListPolicy};

    let mut out = Enforcement {
        disabled: !b.enabled,
        no_filter_slot: slots.is_some_and(|s| s.bit_for_v1_id(&b.id).is_none()),
        ..Enforcement::default()
    };

    for (profile_id, profile) in &config.profiles {
        if effective_direction(profile, b) != ListPolicy::Ignore {
            out.profiles.push(profile_id.clone());
        }
    }
    out
}

fn name_list(names: &[String]) -> String {
    if names.is_empty() {
        "<none>".to_string()
    } else {
        names.join(", ")
    }
}

/// The main `blocklist list` row.
///
/// **`kind` is on it deliberately.** The tabular view is where an
/// operator answers "what have I got installed" at a glance, and until
/// now every row read identically whether the list blocked its domains
/// or permitted them — the one field that inverts a list's meaning was
/// visible only in `blocklist show <id>`, one command per list. With
/// allow-direction lists reachable from a URL, that is the field you
/// scan the table for.
///
/// Pure so the tests can render a row without a config on disk.
fn format_list_row(b: &crate::config::schema::Blocklist) -> String {
    let auth = b
        .auth_token_ref
        .as_deref()
        .map(|r| format!(" auth_token_ref={r}"))
        .unwrap_or_default();
    format!(
        "  {id} \"{name}\" url={url} format={fmt:?} kind={kind} update={update}h \
         enabled={on}{auth}",
        id = b.id.as_str(),
        name = b.display_name,
        url = b.url,
        fmt = b.format,
        kind = kind_label(b.base),
        update = b.update_interval_hours,
        on = if b.enabled { "on" } else { "off" },
    )
}

/// The `accept_unsigned_allow:` block of `blocklist show`.
///
/// The bare boolean is not enough on its own: `true` on a list where the
/// field does nothing reads exactly like `true` on a list where it is
/// the only thing standing between a stranger and the operator's
/// blocklist. The note says which one this is.
///
/// There is deliberately no branch for allow + remote-unsigned +
/// `false`: that config does not load, so `show` never reaches a list in
/// that state.
///
/// Pure so the tests can render every branch without a config on disk.
fn format_show_consent(b: &crate::config::schema::Blocklist) -> Vec<String> {
    let mut out = vec![format!(
        "accept_unsigned_allow:  {}",
        b.accept_unsigned_allow
    )];
    if b.accept_unsigned_allow {
        let note = if b.base == BlocklistBase::Allow && b.trust == BlocklistTrust::RemoteUnsigned {
            "(load-bearing: whoever controls this URL decides which domains stop being \
             blocked, at every refresh, with no review)"
        } else {
            "(no effect on this list: it applies only to an allow-direction list on a \
             remote unsigned source)"
        };
        out.push(format!("                        {note}"));
    }
    out
}

/// The continuation line printed under every `blocklist list` row: the
/// verdict on whether this list reaches anyone.
///
/// It used to lead with `tags=…`, the set that decided applicability. Tags
/// stopped deciding at the cutover and a later cleanup removed them, so
/// the line now carries only what is still true — which profiles enforce
/// the list, via `effective_direction`.
///
/// Pure so the tests can render both verdicts without a config on disk.
fn format_list_enforcement_line(e: &Enforcement) -> String {
    format!("      {}", e.one_line())
}

/// Closing note naming every inert list, printed once after the rows.
///
/// Empty when every list reaches someone — a "0 lists are not enforced"
/// line on a healthy config would train the operator to skip the block
/// that matters.
fn format_inert_footer(inert: &[String]) -> Vec<String> {
    if inert.is_empty() {
        return Vec::new();
    }
    let consequence = if inert.len() == 1 {
        "It downloads on schedule, reports success, and filters nothing."
    } else {
        "They download on schedule, report success, and filter nothing."
    };
    vec![
        String::new(),
        format!("{NOT_ENFORCED}: {}.", inert.join(", ")),
        consequence.to_string(),
        "Run `warden blocklist show <id>` for the tags involved and how to fix it.".to_string(),
    ]
}

/// The command that would make this list start filtering, or `None` when
/// there is nothing honest to suggest.
fn fix_hint(b: &crate::config::schema::Blocklist, e: &Enforcement) -> Option<String> {
    if e.disabled {
        return Some(format!(
            "Turn it on with: warden blocklist set {} enabled true",
            b.id.as_str()
        ));
    }
    if e.no_filter_slot {
        // Reaching here means the source map was built and this list is
        // missing from it. There is no single-command fix, and inventing
        // one would send the operator somewhere useless.
        return None;
    }
    // The fix is no longer "make a tag match". A list is inert
    // only when every profile overrides it to `ignore`, so the remedy names
    // the override — and names the raw config key rather than a CLI verb,
    // since a fix suggestion that points at a command that does not exist
    // would be the phantom-verb defect this repo has a gate for.
    Some(format!(
        "Remove the `ignore` override: drop `{} = \"ignore\"` from a profile's \
         `lists` table, or set it to \"deny\" / \"allow\"",
        b.id.as_str()
    ))
}

/// The `Used by …` + `Enforcement:` block printed by `blocklist show`.
///
/// Pure so every branch is testable without a config file or a daemon,
/// matching how `warden lists show` renders its corpus block.
fn format_show_enforcement(b: &crate::config::schema::Blocklist, e: &Enforcement) -> Vec<String> {
    let mut out = vec![
        format!("Used by profiles:       {}", name_list(&e.profiles)),
        format!("Used by devices:        {}", name_list(&e.devices)),
        format!("Used by subnets:        {}", name_list(&e.subnets)),
    ];
    match e.blocked_reason() {
        Some(reason) => {
            // Consequence first, cause second: the reasons differ in
            // shape (one is a clause, one names a field), and appending
            // "so this list filters nothing" to each produced a sentence
            // with two `so`s in it.
            out.push(format!(
                "Enforcement:            {NOT_ENFORCED} — this list filters nothing: {reason}."
            ));
            if let Some(fix) = fix_hint(b, e) {
                out.push(format!("                        {fix}"));
            }
        }
        None => {
            out.push(format!(
                "Enforcement:            enforced by {} — that is what the config resolves to.",
                e.carriers_phrase()
            ));
            out.push(
                "                        Whether the daemon has the list installed is the \
                 Runtime status above."
                    .to_string(),
            );
        }
    }
    out
}

pub fn run_list(config_path: &Path) -> anyhow::Result<()> {
    let now = time::OffsetDateTime::now_utc();
    let loaded = load_config(config_path, now).map_err(format_config_errors)?;
    if loaded.config.blocklists.is_empty() {
        println!("no blocklists configured");
        println!("add one with: warden blocklist add <id> --url <url> --format domains");
        return Ok(());
    }
    println!(
        "configured blocklists ({}):",
        loaded.config.blocklists.len()
    );
    let slots = filter_slots(&loaded.config);
    let mut inert: Vec<String> = Vec::new();
    for b in &loaded.config.blocklists {
        println!("{}", format_list_row(b));
        let enforcement = analyse_enforcement(&loaded.config, b, slots.as_ref());
        println!("{}", format_list_enforcement_line(&enforcement));
        if enforcement.blocked_reason().is_some() {
            inert.push(b.id.as_str().to_string());
        }
    }
    for line in format_inert_footer(&inert) {
        println!("{line}");
    }
    Ok(())
}

pub async fn run_show(config_path: &Path, socket_path: &Path, id: &str) -> anyhow::Result<()> {
    let now = time::OffsetDateTime::now_utc();
    let loaded = load_config(config_path, now).map_err(format_config_errors)?;
    let b = loaded
        .config
        .blocklists
        .iter()
        .find(|x| x.id.as_str() == id)
        .with_context(|| format!("blocklist not found: {id}"))?;
    println!("id:                     {}", b.id.as_str());
    println!("display_name:           {}", b.display_name);
    println!("url:                    {}", b.url);
    println!("format:                 {:?}", b.format);
    println!("kind:                   {}", kind_label(b.base));
    println!("trust:                  {}", trust_label(b.trust));
    for line in format_show_consent(b) {
        println!("{line}");
    }
    println!("update_interval_hours:  {}", b.update_interval_hours);
    println!("max_entries:            {}", b.max_entries);
    println!("enabled:                {}", b.enabled);
    match b.auth_token_ref.as_deref() {
        Some(r) => println!("auth_token_ref:         {r}"),
        None => println!("auth_token_ref:         <none>"),
    }

    // Append a runtime block from the live daemon if
    // reachable. IPC failure is non-fatal — config-only output is
    // still useful when the daemon is down for editing.
    print_runtime_block(socket_path, id, &b.url).await;

    // The reverse lookup this label used to promise: profiles no longer
    // enumerate blocklists, so "who uses this list" is the set of
    // entities whose tags intersect it. Computed from the config, which
    // is why it sits *after* the runtime block — the two answer different
    // questions and the wording below sends the operator between them.
    println!();
    let slots = filter_slots(&loaded.config);
    let enforcement = analyse_enforcement(&loaded.config, b, slots.as_ref());
    for line in format_show_enforcement(b, &enforcement) {
        println!("{line}");
    }
    Ok(())
}

/// Query the running daemon for `id`'s runtime telemetry
/// and print it as a `Runtime status:` block. Silent no-op if the
/// daemon is unreachable (offline-edit case is the same one that
/// motivates the legacy config-only fallback in `run_status`).
/// One `BlocklistStats` round-trip. `Err` carries the operator-facing
/// reason the query could not be answered at all, which is distinct from
/// `Ok(vec![])` — "the daemon answered, and knows nothing about this
/// source".
async fn query_blocklist_stats(
    socket_path: &Path,
    query: &str,
) -> Result<Vec<BlocklistStatusDto>, &'static str> {
    let cmd = IpcCommand::BlocklistStats {
        source_id: Some(query.to_string()),
    };
    match send_command(socket_path, &cmd).await {
        Ok(IpcResponse::BlocklistStatsList { stats }) => Ok(stats),
        Ok(_) => Err("<unexpected daemon response>"),
        Err(_) => Err("<daemon unreachable>"),
    }
}

/// Query by `url` first, falling back to `id`.
///
/// The status registry is keyed on the **source string**, which for a v2
/// `[[blocklists]]` entry is its URL — not its id. Querying by id alone
/// meant every v2 list printed `<no telemetry — reload may be pending>`
/// forever: on the live daemon `blocklist show privacy-tracking` reported
/// no telemetry for a source that was active, fetched, and truncating.
/// The daemon-side lookup does try `slug_for_id`, but that map only
/// covers legacy slug-form sources (`privacy/ads`), so an id like
/// `privacy-tracking` fell through to a substring match that cannot hit
/// `https://lists.purge.cc/tracking.txt`.
///
/// The id retry is kept for exactly those legacy slug-form sources, where
/// the registry key is the slug and the URL is what does not match. Only
/// one extra round-trip, only on the miss path.
async fn print_runtime_block(socket_path: &Path, id: &str, url: &str) {
    let mut stats = match query_blocklist_stats(socket_path, url).await {
        Ok(s) => s,
        Err(msg) => {
            println!();
            println!("Runtime status:         {msg}");
            return;
        }
    };
    if stats.is_empty() && url != id {
        stats = query_blocklist_stats(socket_path, id)
            .await
            .unwrap_or_default();
    }
    println!();
    if stats.is_empty() {
        // The IPC layer returns an empty list (not an Error response)
        // when no source matches — surface that so the operator knows
        // the daemon is up but doesn't know about this id (typical
        // when the list was added but a reload hasn't happened yet).
        println!("Runtime status:         <no telemetry — reload may be pending>");
        return;
    }
    let s: &BlocklistStatusDto = &stats[0];
    println!("Runtime status:");
    println!("  source:               {}", s.source);
    println!("  entries:              {}", s.entries);
    println!("  parsed_ok:            {}", s.parsed_ok);
    println!("  parsed_skipped:       {}", s.parsed_skipped);
    // Printed only when non-zero, and loudly when it is: a zero line here
    // would read as reassurance on the 99% of lists that are fine, which
    // is how the condition stayed invisible in the first place. The
    // remedy is named inline because a bare count tells the operator a
    // number, not what to do about it — and it names the GLOBAL knob
    // because the per-`[[blocklists]]` `max_entries` never reaches the
    // parser.
    if s.parsed_truncated > 0 {
        println!(
            "  REFUSED:              {} entries over [lists] max_entries — this cycle kept the last good body; raise the GLOBAL value: warden lists set max_entries <n>",
            s.parsed_truncated
        );
    }
    match s.fetched_at.as_deref() {
        Some(ts) => println!("  last update:          {ts}"),
        None => println!("  last update:          <never>"),
    }
    println!("  last outcome:         {}", s.last_outcome);
    match (s.delta_pct_vs_prev, s.prev_entries) {
        (Some(pct), Some(prev)) => {
            println!(
                "  delta vs prev:        {pct:+.1}% ({prev} → {})",
                s.entries
            )
        }
        _ => println!("  delta vs prev:        —"),
    }
}

/// The CLI-side companion to the validator's
/// [`UNSIGNED_ALLOW_LIST_REQUIRES_ACK`](crate::config::schema::validator::UNSIGNED_ALLOW_LIST_REQUIRES_ACK).
///
/// That string is frozen and speaks TOML — "set accept_unsigned_allow =
/// true on the list" — because its home is a config diagnostic. An
/// operator who reaches it by typing a command has not opened the file
/// and does not want to: the answer they need is a flag. One line, kept
/// separate rather than folded in, so the frozen text stays verbatim and
/// the two surfaces do not have to agree on wording forever.
pub const ACCEPT_UNSIGNED_ALLOW_FLAG_HINT: &str =
    "On the command line, declare it with --accept-unsigned-allow on this verb.";

/// Direction knobs `warden blocklist add` can stamp on a new entry.
///
/// **Why a struct and not two more parameters.** `run_add` /
/// `run_add_silent` are called from outside this module — the TUI add
/// flow and `cli/commands/lists.rs` — and neither of those surfaces has
/// a direction to express: they create deny-lists, which is what
/// [`Default`] means here. Bundling the new knobs keeps those call
/// sites compiling unchanged while `run_add_with_direction` carries the
/// CLI's extra intent.
#[derive(Debug, Clone, Copy, Default)]
pub struct AddDirection<'a> {
    /// `--kind` as the operator typed it (`deny` / `allow`). `None`
    /// means the schema default, [`BlocklistBase::Deny`].
    pub kind: Option<&'a str>,
    /// `--accept-unsigned-allow`: the operator declaring, per list, that
    /// they accept a remote unsigned source deciding what stops being
    /// blocked. Meaningless unless `base = allow`.
    pub accept_unsigned_allow: bool,
}

/// The three doors between a list and `base = allow`, answered together.
///
/// All are already enforced by [`run_set_kind_with_ack`]; this exists
/// so a second surface can ask the same question without reimplementing
/// it. The TUI is that surface, and the part it would get wrong is not
/// the boolean algebra — it is `file_tags_empty`. See the field.
///
/// **The caller chooses the order the answers are reported, and the two
/// callers deliberately disagree.** The CLI reports consent first: when
/// both are missing the security explanation is the one worth reading,
/// and the tag rule is met on the retry. The TUI reports the tag first,
/// because there the tag is fixable without leaving the modal, and
/// collecting a typed consent for a save you are then going to refuse is
/// worse than a re-prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllowDirectionGates {
    /// The list is remote and unsigned and nobody — not the file, not
    /// this invocation — has declared [`AddDirection::accept_unsigned_allow`].
    ///
    /// Scoped to [`BlocklistTrust::RemoteUnsigned`] on purpose, matching
    /// the verb it was extracted from: on `trust = signed` the answer is
    /// the parking-lot message, and consent does not unblock that case at
    /// all. The validator's own error keys off `!= Local` instead — that
    /// asymmetry is documented at its raise site and is not a bug here.
    pub needs_consent: bool,
}

/// Evaluate the gate on a prospective `base = allow`.
///
/// # It used to evaluate three
///
/// `needs_tag` ("an untagged allow-list permits nothing, so tag it
/// first") and `needs_non_system_tag` ("`uncategorized` is the widest
/// audience wearing a choice's clothes") were both true only while tag
/// intersection decided which lists reached which client. A cutover ended
/// that — an allow-direction list is inherited by every profile that does
/// not override it, tagged or not — and left them answering a constant
/// `false`. A later cleanup removed the field they read, so there is nothing
/// left to answer with.
///
/// **A gate whose answer cannot vary is worse than an absent one:** it
/// reads as a live check to whoever greps for it, and the two parameters
/// it took (`file_tags_empty`, `file_tags_contain_system`) made every
/// caller look like it was still consulting the file.
///
/// What the third gate genuinely bought — that a permanent, universal
/// allow is *visible* — is not lost: it is a WARN at every load,
/// `ALLOW_DIRECTION_LIST_STANDING_EXPOSURE`, which is where a standing
/// exposure belongs, and `f24_the_standing_exposure_warning_still_fires_on_the_allow_branch`
/// asserts it rather than assuming it.
pub fn allow_direction_gates(
    trust: BlocklistTrust,
    consent_in_file: bool,
    consent_declared_now: bool,
) -> AllowDirectionGates {
    AllowDirectionGates {
        needs_consent: trust == BlocklistTrust::RemoteUnsigned
            && !consent_in_file
            && !consent_declared_now,
    }
}

/// Deny-direction `add` — the shape every pre-existing caller wants.
/// See [`run_add_with_direction`] for the direction-aware entry point.
///
/// # The retired `tags` parameter
///
/// `_tags` is accepted and ignored. `--tag` was removed from the
/// clap tree, and the inner `run_add_*` family lost the parameter
/// outright — but this wrapper's remaining caller is a test helper in
/// `tui/mod.rs`. Narrowing the signature here would break that test
/// for no gain, so the argument stays and the `_` prefix is
/// what makes its retirement visible at the call site rather than
/// silent.
///
/// Exactly the treatment [`allow_direction_gates`] already gives its two
/// tag arguments, for exactly the same reason. Whoever removes the last
/// caller removes the parameter with it.
#[allow(clippy::too_many_arguments)]
pub async fn run_add(
    config_path: &Path,
    socket_path: &Path,
    id: &str,
    display_name: Option<&str>,
    url: &str,
    format: Option<&str>,
    update_interval_hours: Option<u32>,
    max_entries: Option<u64>,
    enabled: Option<bool>,
    auth_token_ref: Option<&str>,
    _tags: &[String],
    skip_head_check: bool,
    into: Option<&Path>,
) -> anyhow::Result<()> {
    run_add_with_direction(
        config_path,
        socket_path,
        id,
        display_name,
        url,
        format,
        update_interval_hours,
        max_entries,
        enabled,
        auth_token_ref,
        skip_head_check,
        into,
        AddDirection::default(),
    )
    .await
}

/// `warden blocklist add <id> --url <url> [--kind allow
/// --accept-unsigned-allow]`.
///
/// The direction-aware front door. Everything about the write, the
/// gates and the audit lives in [`run_add_silent_with_direction`]; this
/// wrapper only turns the outcome into operator-visible lines.
#[allow(clippy::too_many_arguments)]
pub async fn run_add_with_direction(
    config_path: &Path,
    socket_path: &Path,
    id: &str,
    display_name: Option<&str>,
    url: &str,
    format: Option<&str>,
    update_interval_hours: Option<u32>,
    max_entries: Option<u64>,
    enabled: Option<bool>,
    auth_token_ref: Option<&str>,
    skip_head_check: bool,
    into: Option<&Path>,
    direction: AddDirection<'_>,
) -> anyhow::Result<()> {
    let result = run_add_silent_with_direction(
        config_path,
        socket_path,
        id,
        display_name,
        url,
        format,
        update_interval_hours,
        max_entries,
        enabled,
        auth_token_ref,
        skip_head_check,
        into,
        direction,
    )
    .await?;
    for warn in &result.warnings {
        eprintln!("warning: {warn}");
    }
    println!("added blocklist {id} → {}", result.target_path.display());
    ipc_reload::report_reload_outcome(&result.reload_outcome);
    Ok(())
}

/// Outcome of a successful `run_add_silent` call. Carries the on-disk
/// target file the new entry landed in, any operator-visible warnings
/// (auth-token-ref soft-failures), and the IPC reload outcome — the
/// CLI wrapper turns these into `println!`/`eprintln!` lines, the TUI
/// surfaces them in the modal/footer.
pub struct AddOutcome {
    pub target_path: std::path::PathBuf,
    pub warnings: Vec<String>,
    pub reload_outcome: ipc_reload::ReloadOutcome,
}

/// Quiet variant of [`run_add`] — same write + reload pipeline but no
/// `println!`/`eprintln!`. The TUI catalog picker and Add-mode submit
/// flow call this so terminal raw mode + alt-screen don't get
/// scrambled by stray stdout.
///
/// Runs a three-gate
/// pre-flight before persisting:
/// 1. **URL valid** — `scheme()` must be `http`/`https`.
/// 2. **Dedup** — refuses if any existing blocklist has the same id (kept)
///    or the same URL (new).
/// 3. **HEAD probe** — synchronous reachability check (3 s timeout)
///    via the shared async reqwest client. Skipped when
///    `skip_head_check = true` (CLI `--skip-head-check`, TUI advanced
///    button). Failure surfaces the [`super::super::super::config::schema::validator::LIST_URL_NOT_REACHABLE`]
///    frozen string with the underlying detail.
///
/// It used to take a `tags` slice — the slugs the operator typed via CLI
/// `--tag` or the TUI chip picker — validated through `TagSlug::try_from`
/// and persisted into the entry's `tags` array. That flag and field are
/// both gone; a list's reach is now its `base`
/// plus each profile's `profiles.<id>.lists` override.
#[allow(clippy::too_many_arguments)]
pub async fn run_add_silent(
    config_path: &Path,
    socket_path: &Path,
    id: &str,
    display_name: Option<&str>,
    url: &str,
    format: Option<&str>,
    update_interval_hours: Option<u32>,
    max_entries: Option<u64>,
    enabled: Option<bool>,
    auth_token_ref: Option<&str>,
    skip_head_check: bool,
    into: Option<&Path>,
) -> anyhow::Result<AddOutcome> {
    run_add_silent_with_direction(
        config_path,
        socket_path,
        id,
        display_name,
        url,
        format,
        update_interval_hours,
        max_entries,
        enabled,
        auth_token_ref,
        skip_head_check,
        into,
        AddDirection::default(),
    )
    .await
}

/// [`run_add_silent`] plus the direction the operator asked for.
///
/// **Three gates run before anything is written**, all only when
/// `base = allow`:
///
/// 1. **Consent.** A list created from a URL is `trust =
///    remote-unsigned` by construction, and an allow-direction list
///    decides what stops being blocked — so without
///    `--accept-unsigned-allow` this refuses with the validator's own
///    frozen
///    [`UNSIGNED_ALLOW_LIST_REQUIRES_ACK`](crate::config::schema::validator::UNSIGNED_ALLOW_LIST_REQUIRES_ACK).
///    Refusing *here* rather than letting `write_value_validated` roll
///    the write back matters: the rollback path leaves an audit row for
///    a mutation that was staged and undone, and tells the operator
///    their config was rejected when it was their command that was.
/// 2. **Tags — RETIRED, never fires.**
///    [`ALLOW_LIST_REQUIRES_TAG`] said: allow-lists are not auto-promoted
///    to `uncategorized`, so an untagged one applies to no device and
///    permits nothing. That was true only while tag intersection decided
///    which lists reached which clients. It does not — a list's direction
///    now reaches every profile that does not override it — so the
///    premise is gone and [`allow_direction_gates`] answers `false`.
/// 3. **Not the system tag — RETIRED, never fires.**
///    [`ALLOW_LIST_CANNOT_USE_SYSTEM_TAG`] said: gate 2 asks who the
///    exemption is for, and `uncategorized` is the one answer that widens
///    rather than narrows. Same premise, same fate.
///
/// Both are kept **numbered and quoted** rather than deleted: what a gate
/// bought is the argument a future reader needs before restoring it, and
/// the standing exposure gate 2 half-covered is now a WARN at every load
/// (`ALLOW_DIRECTION_LIST_STANDING_EXPOSURE`), which is where a permanent
/// condition belongs.
///
/// Consent is checked first: when several are missing, the security
/// explanation is the one worth reading, and the tag rules are met on
/// the retry.
#[allow(clippy::too_many_arguments)]
pub async fn run_add_silent_with_direction(
    config_path: &Path,
    socket_path: &Path,
    id: &str,
    display_name: Option<&str>,
    url: &str,
    format: Option<&str>,
    update_interval_hours: Option<u32>,
    max_entries: Option<u64>,
    enabled: Option<bool>,
    auth_token_ref: Option<&str>,
    skip_head_check: bool,
    into: Option<&Path>,
    direction: AddDirection<'_>,
) -> anyhow::Result<AddOutcome> {
    let _ = Id::new(id).map_err(|e| anyhow::anyhow!("invalid id: {e}"))?;
    if !is_url_source(url) {
        bail!("url must start with http:// or https:// — got \"{url}\"");
    }
    let parsed_format = match format {
        Some(f) => Some(parse_format(f)?),
        None => None,
    };

    let kind = match direction.kind {
        Some(k) => parse_kind(k)?,
        None => BlocklistBase::Deny,
    };
    // `add` takes a URL, so the source is remote and unsigned — there is
    // no `--trust` on this verb and nothing for one to choose between.
    // `import-local` is the local-trust door.
    let trust = BlocklistTrust::RemoteUnsigned;
    if kind == BlocklistBase::Allow {
        // Same door as `set-kind`, through the same predicate. The entry
        // does not exist yet, so there is no file to have declared consent
        // (`consent_in_file = false`).
        let gates = allow_direction_gates(trust, false, direction.accept_unsigned_allow);
        if gates.needs_consent {
            bail!(
                "{}\n{}",
                crate::config::schema::validator::format_unsigned_allow_list_requires_ack(
                    id, trust
                ),
                ACCEPT_UNSIGNED_ALLOW_FLAG_HINT
            );
        }
    }

    let now = time::OffsetDateTime::now_utc();
    let loaded = load_config(config_path, now).map_err(format_config_errors)?;
    if loaded.config.blocklists.iter().any(|b| b.id.as_str() == id) {
        bail!("blocklist \"{id}\" already exists");
    }
    // Compare on the CANONICAL key, not
    // byte-exactly. `…/ads.txt` and `…/ads.txt/` are one source: they
    // share a cache file and its ETag (`source_to_cache_stem` keys on the
    // URL alone), so a 304 for one silently satisfies the other and the
    // last write wins the body. Stays a hard error — `add` is creating a
    // new entry, so no existing config breaks.
    let canonical = canonical_url_key(url);
    if let Some(existing) = loaded
        .config
        .blocklists
        .iter()
        .find(|b| canonical_url_key(&b.url) == canonical)
    {
        bail!(
            "list URL already added as \"{}\" — use that id or remove it first",
            existing.id.as_str()
        );
    }

    if !skip_head_check {
        probe_url_reachable(url).await?;
    }

    let mut warnings: Vec<String> = Vec::new();
    if let Some(r) = auth_token_ref {
        let secrets_path = secrets_path_for(config_path);
        match load_secrets(&secrets_path) {
            Ok(secrets) => {
                if secrets.get(r).is_none() {
                    warnings.push(format!(
                        "auth_token_ref \"{r}\" is not defined in {}. The list will be \
                         fetched anonymously until you add it to secrets.toml.",
                        secrets_path.display()
                    ));
                }
            }
            Err(_) => {
                warnings.push(format!(
                    "secrets file at {} is missing or unreadable — \
                     auth_token_ref \"{r}\" will not resolve until it is created.",
                    secrets_path.display()
                ));
            }
        }
    }

    let mut tbl = toml::map::Map::new();
    tbl.insert("id".into(), Value::String(id.to_string()));
    tbl.insert(
        "display_name".into(),
        Value::String(display_name.unwrap_or(id).to_string()),
    );
    tbl.insert("url".into(), Value::String(url.to_string()));
    // Written explicitly, never left to the serde defaults. A
    // `[[blocklists]]` row with no `kind` and no `trust` reads as a
    // deny-list only if you happen to know what the defaults are — and
    // the field that decides whether a list blocks or unblocks is not
    // one to leave implicit in the operator's own file. The TUI reads
    // these keys too.
    tbl.insert("base".into(), Value::String(kind_label(kind).to_string()));
    tbl.insert(
        "trust".into(),
        Value::String(trust_label(trust).to_string()),
    );
    // Consent, on the other hand, is written only when declared: a
    // `accept_unsigned_allow = false` on every deny-list is noise that
    // teaches the operator to skip the line on the one list where it
    // carries a decision. Absent means the schema default, false.
    if direction.accept_unsigned_allow {
        tbl.insert("accept_unsigned_allow".into(), Value::Boolean(true));
    }
    if let Some(f) = parsed_format {
        tbl.insert("format".into(), Value::String(format_label(f).to_string()));
    }
    if let Some(h) = update_interval_hours {
        tbl.insert("update_interval_hours".into(), Value::Integer(h as i64));
    }
    if let Some(m) = max_entries {
        tbl.insert("max_entries".into(), Value::Integer(m as i64));
    }
    if let Some(e) = enabled {
        tbl.insert("enabled".into(), Value::Boolean(e));
    }
    if let Some(r) = auth_token_ref {
        tbl.insert("auth_token_ref".into(), Value::String(r.to_string()));
    }
    // No `tags` key is written. `--tag` is gone, so there is
    // nothing operator-supplied left to persist, and synthesising one
    // would be warden writing a value the operator never asked for into
    // their file. The validator's auto-promote pass still stamps
    // `["uncategorized"]` on a `base = deny` entry at reload — that is
    // the loader's business, and a value the loader synthesises must not
    // be round-tripped back into the file by a writer.

    let target_path = resolve_target_file(config_path, EntityClass::Blocklists, into)?;
    let (mut doc, _) = read_or_empty(&target_path)?;
    upsert_id_keyed(
        &mut doc,
        EntityClass::Blocklists.toml_key(),
        id,
        Value::Table(tbl),
    )?;
    write_value_validated(config_path, &target_path, &doc)?;

    // Blocklist add is supply-chain-relevant — record the URL
    // the operator subscribed so a later silent re-point is attributable.
    //
    // Since `add` can create an allow-direction list, the URL alone no
    // longer describes the mutation: the same line could be a subscription
    // to a deny-list or the moment a remote party gained the power to
    // unblock domains. The deny shape is left byte-identical so existing
    // audit readers are unaffected; the allow case says so explicitly.
    let id_for_audit = id.to_string();
    let url_for_audit = if kind == BlocklistBase::Allow {
        format!(
            "{url} kind=allow accept_unsigned_allow={}",
            direction.accept_unsigned_allow
        )
    } else {
        url.to_string()
    };
    let target_for_audit = target_path.clone();
    persist_cli_mutation_audit(config_path, move || {
        AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
            .with_uid(current_uid())
            .with_action("blocklist.add")
            .with_scope("blocklist")
            .with_target_id(id_for_audit)
            .with_fields_after(url_for_audit)
            .with_files([config_path, target_for_audit.as_path()])
    });

    let reload_outcome = ipc_reload::attempt_reload(socket_path).await;
    Ok(AddOutcome {
        target_path,
        warnings,
        reload_outcome,
    })
}

pub async fn run_set(
    config_path: &Path,
    socket_path: &Path,
    id: &str,
    field: &str,
    value: &str,
    into: Option<&Path>,
) -> anyhow::Result<()> {
    let target_path = resolve_existing_target_file(config_path, EntityClass::Blocklists, id, into)?;
    let (mut doc, _) = read_or_empty(&target_path)?;
    let entry =
        find_id_entry_mut(&mut doc, EntityClass::Blocklists.toml_key(), id)?.ok_or_else(|| {
            anyhow::anyhow!("blocklist \"{id}\" not found in {}", target_path.display())
        })?;
    // Snapshot the prior URL before mutating so a `set url`
    // (re-pointing a list's source — the supply-chain action) records
    // before→after for attributability.
    let old_url = if field == "url" {
        entry
            .as_table()
            .and_then(|t| t.get("url"))
            .and_then(|v| v.as_str())
            .map(str::to_string)
    } else {
        None
    };
    apply_blocklist_field(entry, field, value, config_path)?;
    write_value_validated(config_path, &target_path, &doc)?;
    let id_for_audit = id.to_string();
    let fields_after = format!("{field}={value}");
    let target_for_audit = target_path.clone();
    persist_cli_mutation_audit(config_path, move || {
        let mut rec = AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
            .with_uid(current_uid())
            .with_action("blocklist.set")
            .with_scope("blocklist")
            .with_target_id(id_for_audit)
            .with_fields_after(fields_after)
            .with_files([config_path, target_for_audit.as_path()]);
        if let Some(old) = old_url {
            rec = rec.with_fields_before(old);
        }
        rec
    });
    println!("updated {id}.{field} = {value}");

    let outcome = ipc_reload::attempt_reload(socket_path).await;
    ipc_reload::report_reload_outcome(&outcome);

    Ok(())
}

/// Remove a blocklist entry: drop every `profiles.<id>.lists` override
/// naming it, then drop the `[[blocklists]]` row, then fire one reload.
///
/// **This doc used to say "There is no cascade"**, on the premise that a
/// profile never enumerates blocklist ids. `Profile.lists` gave
/// them exactly that, and the validator refuses an override naming a row
/// that does not exist (`CrossRefMiss`, ERROR) — so the premise died and the
/// cascade is load-bearing again.
///
/// The old `--cascade` flag is deliberately *not* revived: see
/// [`run_remove_silent`] for why the cascade is unconditional.
pub async fn run_remove(
    config_path: &Path,
    socket_path: &Path,
    id: &str,
    into: Option<&Path>,
) -> anyhow::Result<()> {
    // Remove of an absent blocklist is idempotent (exit 0). The
    // shared `run_remove_silent` (also a TUI seat) keeps its hard-error
    // contract; the CLI wrapper does the idempotent pre-check so scripts
    // get a uniform "remove of absent" exit code across the entity verbs.
    // If the config won't load, fall through and let run_remove_silent
    // surface the real error.
    let now = time::OffsetDateTime::now_utc();
    let exists = load_config(config_path, now)
        .map(|l| l.config.blocklists.iter().any(|b| b.id.as_str() == id))
        .unwrap_or(true);
    if !exists {
        println!("blocklist \"{id}\" not found — nothing to remove");
        return Ok(());
    }
    let outcome = run_remove_silent(config_path, socket_path, id, into, false).await?;
    for line in &outcome.cascade_log {
        println!("{line}");
    }
    println!("removed blocklist {id}");
    ipc_reload::report_reload_outcome(&outcome.reload_outcome);
    Ok(())
}

/// Outcome of [`run_remove_silent`]. Carries the cascade trace lines
/// the CLI wrapper turns into `println!` and the IPC reload outcome.
pub struct RemoveOutcome {
    /// One line per cascade step (e.g.
    /// `"  cascade: removed \"X\" from profile \"Y\" → /path/file"`).
    /// Empty when `cascade=false` or no refs needed dropping.
    pub cascade_log: Vec<String>,
    pub reload_outcome: ipc_reload::ReloadOutcome,
}

/// Quiet variant of [`run_remove`] — same write + reload pipeline but
/// no `println!`. The TUI list-delete confirm flow calls this so
/// raw mode + alt-screen don't get scrambled by stray stdout.
pub async fn run_remove_silent(
    config_path: &Path,
    socket_path: &Path,
    id: &str,
    into: Option<&Path>,
    cascade: bool,
) -> anyhow::Result<RemoveOutcome> {
    // **The comment that used to sit here was the defect.** It read: "profiles
    // no longer enumerate blocklists, so the v1 cross-ref check + cascade is
    // structurally a no-op now" — and then assigned `Vec::new()` on the
    // strength of it. The premise died when profiles gained `Profile.lists`
    // and the validator gained a rule refusing an override that names no
    // `[[blocklists]]` row (`CrossRefMiss` — an ERROR, not a WARN).
    //
    // A defence written in prose fails no build, and this one had gone from
    // true to false without anything going red.
    //
    // **The symptom was measured, and it is not the one the dead premise
    // suggests.** `write_value_validated` validates the staged bytes *before*
    // promoting anything, so the removal never bricked a later boot: it failed
    // outright, quoting the operator's own profile back at them, and no verb
    // could remove such a list at all. Fail-closed and unusable, rather than
    // fail-open — worth knowing, because it means no config on disk was ever
    // damaged by this.
    //
    // **The cascade is unconditional, and `cascade` still only reaches the
    // audit row.** The CLI has offered no `--cascade` flag for some time and
    // passes `false`; honouring the flag would leave the CLI exactly as broken
    // while looking repaired. Nor is there a policy question to defer to the
    // operator: the row is being deleted in this same mutation, so the
    // override names something that will not exist a moment later. Removing a
    // dead name is cleanup, not a change of intent — and the trace lines below
    // keep it visible rather than silent.
    let target_path = resolve_existing_target_file(config_path, EntityClass::Blocklists, id, into)?;

    // Which profiles name this list?
    //
    // A config that will not load cannot be enumerated, so the cascade is
    // skipped there rather than guessed at, and the pre-promote validation
    // below is what refuses — the same fail-closed outcome as before this
    // repair, never a half-applied removal.
    let overriding_profiles: Vec<String> =
        match load_config(config_path, time::OffsetDateTime::now_utc()) {
            Ok(loaded) => loaded
                .config
                .profiles
                .iter()
                .filter(|(_, p)| p.lists.keys().any(|k| k.as_str() == id))
                .map(|(key, _)| key.to_string())
                .collect(),
            Err(_) => Vec::new(),
        };

    // Stage every file this mutation touches, reading each exactly ONCE. A
    // profile override and the blocklist row frequently live in the same file
    // (the single-file master layout); two `StagedWrite`s to one path would
    // have the second built from stale on-disk bytes and silently drop the
    // first edit.
    let mut docs: BTreeMap<PathBuf, (Value, Option<String>)> = BTreeMap::new();
    let mut order: Vec<PathBuf> = Vec::new();
    let mut cascade_log: Vec<String> = Vec::new();

    for profile_id in &overriding_profiles {
        let p_path =
            resolve_existing_target_file(config_path, EntityClass::Profiles, profile_id, None)?;
        if !docs.contains_key(&p_path) {
            docs.insert(p_path.clone(), read_or_empty(&p_path)?);
            order.push(p_path.clone());
        }
        let (doc, _) = docs.get_mut(&p_path).expect("doc just staged");
        if !drop_profile_list_override(doc, profile_id, id)? {
            // The loaded (merged) config says this profile overrides the list,
            // but the file that owns the profile id carries no such key — a
            // profile whose table is split across two includes would do it.
            // Refuse loudly instead of removing the row and leaving behind a
            // reference this verb cannot reach.
            bail!(
                "profile \"{profile_id}\" overrides blocklist \"{id}\" in the loaded config, \
                 but no `lists.{id}` key was found in {} — refusing to remove the list and leave \
                 a reference behind. Drop the override by hand, then retry.",
                p_path.display()
            );
        }
        cascade_log.push(format!(
            "  cascade: removed \"{id}\" from profile \"{profile_id}\" → {}",
            p_path.display()
        ));
    }

    if !docs.contains_key(&target_path) {
        docs.insert(target_path.clone(), read_or_empty(&target_path)?);
        order.push(target_path.clone());
    }
    // **References before row.** `write_values_validated` promotes in the
    // given order, so the blocklist's own slice goes LAST: no inter-rename
    // intermediate is a tree where an override outlives what it names. When
    // the row and an override share a file, the two edits share one staged doc
    // and land in the same rename anyway.
    order.retain(|p| p != &target_path);
    order.push(target_path.clone());

    let (doc, _) = docs.get_mut(&target_path).expect("doc just staged");
    // Snapshot the removed list's URL before dropping it so the
    // persistent record carries the source that stopped filtering.
    let removed_url = find_id_entry_mut(doc, EntityClass::Blocklists.toml_key(), id)?
        .and_then(|e| e.as_table())
        .and_then(|t| t.get("url"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let removed = remove_id_keyed(doc, EntityClass::Blocklists.toml_key(), id)?;
    if !removed {
        bail!("blocklist \"{id}\" not found in {}", target_path.display());
    }

    let writes: Vec<StagedWrite> = order
        .iter()
        .map(|path| {
            let (doc, raw) = &docs[path];
            Ok(StagedWrite {
                final_path: path.clone(),
                content: super::toml_write::render_preserving(raw.as_deref().unwrap_or(""), doc)
                    .with_context(|| format!("serialise {}", path.display()))?,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    // One validation of the COMBINED final state, then the renames. A tree the
    // loader would reject is never promoted, so the on-disk state only ever
    // moves valid → valid.
    write_values_validated(config_path, &writes)?;
    // **`cascade` is the parameter; `cascade_refs` is what happened.** Emitting
    // the parameter here would now be a lie: the CLI passes `false` and
    // cascades anyway, so every CLI removal that dropped an override would be
    // recorded as `cascade = false`. An audit field that reports an argument
    // rather than an outcome is worse than an absent one — it is read as
    // evidence. Both are emitted: the caller's intent, and the measured count.
    tracing::info!(
        target: "audit",
        action = "blocklists.remove",
        source = %id,
        cascade_requested = cascade,
        cascade_refs = cascade_log.len(),
        "CLI mutation"
    );
    let id_for_audit = id.to_string();
    let target_for_audit = target_path.clone();
    persist_cli_mutation_audit(config_path, move || {
        let mut rec = AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
            .with_uid(current_uid())
            .with_action("blocklist.remove")
            .with_scope("blocklist")
            .with_target_id(id_for_audit)
            .with_files([config_path, target_for_audit.as_path()]);
        if let Some(url) = removed_url {
            rec = rec.with_fields_before(url);
        }
        rec
    });

    // This is the ONE reload that lands the whole compound
    // mutation (for cascade, the loop wrote N profile files) in the
    // daemon's view at once.
    let reload_outcome = ipc_reload::attempt_reload(socket_path).await;
    Ok(RemoveOutcome {
        cascade_log,
        reload_outcome,
    })
}

/// Drop `lists.<list_id>` from the `[profiles.<profile_id>]` table in `doc`.
/// Returns whether a key was actually removed.
///
/// Profiles are a **named map** (`[profiles.kids]`), not an array of tables —
/// the split `entity_tags::tags_array_mut` documents. Getting that wrong finds
/// nothing and reports success, which is why the caller treats `false` as an
/// error rather than as "nothing to do".
///
/// An empty `lists` table is left in place rather than pruned: `lists = {}`
/// and an absent `lists` deserialise identically, so removing it
/// would be a cosmetic edit to a file the operator wrote, in a mutation that
/// is about something else.
fn drop_profile_list_override(
    doc: &mut Value,
    profile_id: &str,
    list_id: &str,
) -> anyhow::Result<bool> {
    let Some(lists) = doc
        .as_table_mut()
        .and_then(|root| root.get_mut(EntityClass::Profiles.toml_key()))
        .and_then(|v| v.as_table_mut())
        .and_then(|t| t.get_mut(profile_id))
        .and_then(|v| v.as_table_mut())
        .and_then(|t| t.get_mut("lists"))
    else {
        return Ok(false);
    };
    let tbl = lists
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("profile \"{profile_id}\" `lists` is not a TOML table"))?;
    Ok(tbl.remove(list_id).is_some())
}

/// Refusal emitted by `warden blocklist set <id> <field> <value>` when
/// `<field>` is not one this generic applier owns.
///
/// **Why it names other verbs.** `kind`, `trust` and
/// `accept_unsigned_allow` are deliberately absent from the settable
/// list: each one changes what warden *permits*, and the dedicated verbs
/// run pre-write gates (untagged allow-list, unsigned-allow consent)
/// that a blind field-setter cannot. But the old message stopped at the
/// list of valid names, so an operator who typed
/// `blocklist set mylist kind allow` read "unknown field" beside an
/// enumeration that omitted `kind` and concluded warden had no way to
/// flip a list's direction — while `set-kind` sat two lines below it in
/// `--help`. Naming the verbs costs one clause and closes that dead end.
pub const BLOCKLIST_SET_UNKNOWN_FIELD: &str =
    "unknown field: {field}. Valid: display_name, url, format, update_interval_hours, \
     max_entries, enabled, auth_token_ref. Direction and provenance are not set here — \
     use: warden blocklist set-kind <id> <deny|allow> / warden blocklist set-trust <id> \
     <local|remote-unsigned>. Both accept --accept-unsigned-allow, which declares consent \
     for a remote allow-list.";

/// Substitute `{field}` into [`BLOCKLIST_SET_UNKNOWN_FIELD`].
pub fn format_blocklist_set_unknown_field(field: &str) -> String {
    BLOCKLIST_SET_UNKNOWN_FIELD.replace("{field}", field)
}

fn apply_blocklist_field(
    entry: &mut Value,
    field: &str,
    value: &str,
    config_path: &Path,
) -> anyhow::Result<()> {
    let tbl = entry
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("blocklist entry is not a TOML table"))?;
    match field {
        "display_name" => {
            if value.is_empty() {
                bail!("display_name cannot be empty");
            }
            tbl.insert("display_name".into(), Value::String(value.to_string()));
        }
        "url" => {
            if !is_url_source(value) {
                bail!("url must start with http:// or https://");
            }
            // Mirror `add`'s dedup gate (run_add_silent, above): refuse to
            // point this list at a URL already owned by a *different*
            // blocklist, otherwise `set url` could silently create two
            // lists sharing one source — a dup `add` would have rejected.
            // The HEAD reachability probe `add` also runs is intentionally
            // not added here: this field-applier is sync, and wiring the
            // async probe in would need the `set` dispatch reworked.
            let self_id = tbl.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let now = time::OffsetDateTime::now_utc();
            // Same canonical key as the
            // `add` gate. Byte-exact here would have let `set url` add a
            // trailing slash and manufacture the very cache-file collision
            // `add` refuses.
            let canonical = canonical_url_key(value);
            if let Ok(loaded) = load_config(config_path, now) {
                if let Some(existing) =
                    loaded.config.blocklists.iter().find(|b| {
                        canonical_url_key(&b.url) == canonical && b.id.as_str() != self_id
                    })
                {
                    bail!(
                        "list URL already added as \"{}\" — use that id or remove it first",
                        existing.id.as_str()
                    );
                }
            } else {
                // Config didn't load for the pre-check; the post-write
                // validator still backstops, but record the skip.
                tracing::debug!("blocklist set url: dedup pre-check skipped (config did not load)");
            }
            tbl.insert("url".into(), Value::String(value.to_string()));
        }
        "format" => {
            let f = parse_format(value)?;
            tbl.insert("format".into(), Value::String(format_label(f).to_string()));
        }
        "update_interval_hours" => {
            let n: u32 = value.parse().ok().filter(|&n| n > 0).ok_or_else(|| {
                anyhow::anyhow!("update_interval_hours must be a positive integer (>= 1)")
            })?;
            tbl.insert("update_interval_hours".into(), Value::Integer(n as i64));
        }
        // Deprecated legacy field name. Accepts the same
        // value, emits a stderr WARN, routes to the canonical key.
        // Remove in v0.5.0.
        "refresh_interval_hours" => {
            eprintln!(
                "warning: field name 'refresh_interval_hours' is deprecated, use \
                 'update_interval_hours' (removal in v0.5.0)"
            );
            let n: u32 = value.parse().ok().filter(|&n| n > 0).ok_or_else(|| {
                anyhow::anyhow!("update_interval_hours must be a positive integer (>= 1)")
            })?;
            tbl.insert("update_interval_hours".into(), Value::Integer(n as i64));
        }
        "max_entries" => {
            let n: u64 = value
                .parse()
                .map_err(|_| anyhow::anyhow!("max_entries must be a positive integer"))?;
            tbl.insert("max_entries".into(), Value::Integer(n as i64));
        }
        "enabled" => {
            let b = match value {
                "true" | "yes" | "on" | "1" => true,
                "false" | "no" | "off" | "0" => false,
                _ => bail!("enabled must be true or false, got \"{value}\""),
            };
            tbl.insert("enabled".into(), Value::Boolean(b));
        }
        "auth_token_ref" => {
            if value.is_empty() || value == "none" {
                tbl.remove("auth_token_ref");
            } else {
                let secrets_path = secrets_path_for(config_path);
                if let Ok(secrets) = load_secrets(&secrets_path) {
                    if secrets.get(value).is_none() {
                        eprintln!(
                            "warning: auth_token_ref \"{value}\" is not defined in {}",
                            secrets_path.display()
                        );
                    }
                }
                tbl.insert("auth_token_ref".into(), Value::String(value.to_string()));
            }
        }
        other => bail!("{}", format_blocklist_set_unknown_field(other)),
    }
    Ok(())
}

fn parse_format(s: &str) -> anyhow::Result<BlocklistFormat> {
    match s {
        "domains" => Ok(BlocklistFormat::Domains),
        "adguard" => Ok(BlocklistFormat::Adguard),
        "hosts" => Ok(BlocklistFormat::Hosts),
        other => bail!("unknown format \"{other}\". Valid: domains, adguard, hosts"),
    }
}

/// TUI-facing entry point for
/// the reachability probe. The TUI Add modal calls this
/// directly before invoking the per-mode write pipeline so the
/// inline error message reads identically to the CLI form. Empty
/// URL is a no-op success (caller already validated the format).
pub async fn probe_url_for_tui(url: &str) -> anyhow::Result<()> {
    if url.is_empty() {
        return Ok(());
    }
    probe_url_reachable(url).await
}

/// Synchronous
/// reachability probe with a 3-second timeout. Tries `HEAD` first;
/// some upstreams (e.g. raw GitHub paths via certain CDNs) reject HEAD
/// with 405, in which case we retry once with `GET` and abort the body
/// read. Both the 405 retry and the final pass-through accept any 2xx
/// or 3xx — the daemon's actual fetch happens later, this only weeds
/// out typos and dead URLs.
///
/// Returns `Err` formatted via
/// [`format_list_url_not_reachable`](crate::config::schema::validator::format_list_url_not_reachable) so the
/// TUI inline error and the CLI stderr line read identically.
async fn probe_url_reachable(url: &str) -> anyhow::Result<()> {
    use crate::config::schema::validator::format_list_url_not_reachable;

    // Build the probe client through the shared list-client builder so the
    // pre-flight uses the same User-Agent / redirect / TLS policy as the
    // daemon's real fetch — a bare reqwest client could pass or fail
    // differently from the actual download. Keep the short 3s probe timeout.
    let client = crate::lists::http_client::build_list_client(std::time::Duration::from_secs(3))
        .map_err(|e| anyhow::anyhow!("{}", format_list_url_not_reachable(url, &e.to_string())))?;

    let head = client.head(url).send().await;
    let resp = match head {
        Ok(r) if r.status().as_u16() == 405 => client.get(url).send().await,
        Ok(r) => Ok(r),
        Err(e) => Err(e),
    };
    match resp {
        Ok(r) => {
            let status = r.status();
            if status.is_success() || status.is_redirection() {
                Ok(())
            } else {
                bail!(
                    "{}",
                    format_list_url_not_reachable(url, &format!("HTTP {}", status.as_u16()))
                );
            }
        }
        Err(e) => {
            let detail = if e.is_timeout() {
                "timeout after 3s".to_string()
            } else if e.is_connect() {
                "connection refused".to_string()
            } else {
                e.to_string()
            };
            bail!("{}", format_list_url_not_reachable(url, &detail));
        }
    }
}

/// Wire token for a format, delegated to the schema enum.
///
/// Kept as a named wrapper so the ~8 call sites read the same as before;
/// what changed is that it no longer re-declares the mapping. A local
/// copy of this map in the TUI silently survived the `Block` → `Deny`
/// rename and made the Lists modal unable to save at all;
/// these three helpers were the remaining duplicates of the same idea.
fn format_label(f: BlocklistFormat) -> &'static str {
    f.wire_str()
}

/// Does a `[[blocklists]]` entry for `list_id` exist on disk?
///
/// **The surviving half of `file_tags_of`.** That function read the file's
/// own `tags` array, and two TUI call sites used its `Ok(None)` — "the id
/// is in the running config but in no config file" — as an existence
/// probe. `tui/tabs/lists.rs` says so in a comment and asked, by name, for
/// this function rather than a deletion: `submit_edit_modal` upserts by
/// id, so an edit opened against an entry another writer had removed would
/// APPEND it back, resurrecting it silently.
///
/// `Ok(false)` is a definite absence. `Err` is an unreadable or missing
/// entity file, which a caller must NOT collapse into "absent" — that is
/// the distinction the tags version was careful about and the reason this
/// returns a `Result<bool>` rather than a `bool`.
pub fn blocklist_entry_exists(
    config_path: &Path,
    list_id: &str,
    into: Option<&Path>,
) -> anyhow::Result<bool> {
    let target = resolve_existing_target_file(config_path, EntityClass::Blocklists, list_id, into)?;
    let (doc, _) = read_or_empty(&target)?;
    let Some(table) = doc.as_table() else {
        bail!("config root is not a TOML table");
    };
    let Some(array) = table
        .get(EntityClass::Blocklists.toml_key())
        .and_then(|v| v.as_array())
    else {
        return Ok(false);
    };
    Ok(array
        .iter()
        .any(|item| item.get("id").and_then(|v| v.as_str()) == Some(list_id)))
}

/// The list exactly as its own file declares it, with no loader in the
/// way.
///
/// `Blocklist` deserialises **purely** — no pass rewrites a row on its way
/// in — so every field here is the file's own word.
///
/// Two claims that used to live in this paragraph are gone because both
/// premises are: it named `auto_promote_blocklists` in the present tense as
/// something the validator "runs", and that function no longer exists
/// anywhere in `src/`; and it ended "tags included", a field
/// removed and the loader now strips. The remaining sentence is the part
/// that still holds and is still the reason this helper exists.
///
/// Used only by the degraded path in [`run_set_kind_with_ack`]. It had a
/// second caller, `run_tag_remove`, until that verb was deleted —
/// named here without a link because a `[...]` reference to a function
/// that no longer exists fails `cargo doc` under
/// `-D rustdoc::broken_intra_doc_links`, a gate leg that runs late enough
/// to be missed. Nothing on the happy path should reach for it:
/// when the config loads, the loaded view is richer (includes resolved,
/// defaults applied consistently) and is what every other verb uses.
fn file_blocklist_view(tbl: &toml::value::Table, list_id: &str) -> anyhow::Result<Blocklist> {
    Value::Table(tbl.clone())
        .try_into::<Blocklist>()
        .with_context(|| format!("blocklist '{list_id}' cannot be read from its own file"))
}

/// Decide what a mutation verb may do when `load_config` has failed.
///
/// **Why this exists.** Every blocklist verb loads the whole config
/// before it touches anything, which is right: a mutation computed
/// against a config nobody can load is a mutation against a guess. But
/// the validator now refuses `base = allow` + `tags = ["uncategorized"]`
/// outright, and an operator who already has that on disk — from a
/// hand-edit, or from a build predating the gate — would find that the
/// two commands that repair it are themselves refused by the load they
/// begin with. The only exit left would be hand-editing the TOML, which
/// is the surface the whole gate exists to close.
///
/// So a verb whose direction can only *narrow* what the config permits
/// keeps working, reading the entry from its own file. `is_repair` is
/// that judgement, and it belongs to the caller: only it knows whether
/// this particular invocation narrows.
///
/// Nothing is weakened by this. The post-write `write_value_validated`
/// still validates the entire config and rolls the write back if the
/// result does not load — so a degraded mutation that fails to repair
/// anything leaves the file exactly as it was, with the real errors
/// reported.
fn degraded_mutation_view(
    tbl: &toml::value::Table,
    list_id: &str,
    is_repair: bool,
    errs: Vec<crate::config::error::ConfigError>,
) -> anyhow::Result<Blocklist> {
    if !is_repair {
        return Err(format_config_errors(errs));
    }
    file_blocklist_view(tbl, list_id)
}

fn find_id_entry_mut<'a>(
    doc: &'a mut Value,
    key: &str,
    find_value: &str,
) -> anyhow::Result<Option<&'a mut Value>> {
    let table = doc
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("config root is not a TOML table"))?;
    let Some(array) = table.get_mut(key) else {
        return Ok(None);
    };
    let arr = array
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("`{key}` must be an array of tables"))?;
    for item in arr.iter_mut() {
        if let Some(id) = item.get("id").and_then(|v| v.as_str()) {
            if id == find_value {
                return Ok(Some(item));
            }
        }
    }
    Ok(None)
}

// ── Per-list mutation verbs (set-kind / set-trust /
//    import-local) + their frozen operator-facing strings. ──────
//
// The `set-category` verb and its `BLOCKLIST_SET_CATEGORY_OK` const were
// removed along with the Category entity.

pub const BLOCKLIST_SET_KIND_OK: &str = "Blocklist '{id}' kind set to {kind}.";

pub fn format_blocklist_set_kind_ok(id: &str, kind: &str) -> String {
    BLOCKLIST_SET_KIND_OK
        .replace("{id}", id)
        .replace("{kind}", kind)
}

/// A sibling of `BLOCKLIST_SET_KIND_OK` rather than a shared polymorphic
/// "kind"-or-"trust" format helper, so `warden audit tail` and the
/// operator-facing stdout line both speak the same vocabulary as the
/// audit `action` tag (`blocklist.set_trust` vs `blocklist.set_kind` are
/// distinct mutations).
pub const BLOCKLIST_SET_TRUST_OK: &str = "Blocklist '{id}' trust set to {trust}.";

pub fn format_blocklist_set_trust_ok(id: &str, trust: &str) -> String {
    BLOCKLIST_SET_TRUST_OK
        .replace("{id}", id)
        .replace("{trust}", trust)
}

/// RETIRED — kept as a `pub` const, **never emitted**.
///
/// **`AllowDirectionGates` no longer has a tag axis at all** — the struct
/// carries exactly one field, `needs_consent`. It is not that the
/// gate answers "no" on tags; the question is gone, so no verb and no TUI
/// path can reach this. Stated that way on purpose: an earlier draft of
/// this note said the gate "returns `needs_tag: false`", which names a
/// field a future reader greps for and does not find — the same
/// prose-that-lies this lane exists to remove, reintroduced by the removal.
///
/// It is kept, and deliberately so: what a security gate *bought* is the
/// argument a future reader needs before restoring it, and that argument is
/// the doc below.
///
/// **Its text names `--tag`, a flag `blocklist add` no longer has, and
/// describes an auto-promotion that no longer runs** (`auto_promote_blocklists`
/// is absent from `src/`). Left as written rather than repaired: it is
/// unreachable, and editing a frozen surface nobody can see is churn.
/// Anyone who makes it reachable again owns updating it first.
///
/// A prior cleanup removed its cross-file byte-pin from
/// `tests/frozen_strings_entity_contracts.rs` — a frozen *contract* asserts a
/// live promise, and this is a record. The inline pin below stays, which is
/// the point of the split: the record's wording is what is worth freezing.
///
/// Original doc follows.
///
/// Refusal shown when an operator tries
/// to create or convert a `base = allow` blocklist without any tags.
///
/// This keeps allow-lists out of the `uncategorized` auto-promotion on
/// purpose: auto-allowing domains for **every** device is a security
/// risk, so the operator has to say who the exemption is for. The cost
/// of that decision was a silent no-op — an allow-list that installs,
/// shows up in `blocklist list`, and filters nothing. This message
/// closes the door and explains the asymmetry, because "allow-lists
/// need a tag but deny-lists don't" is otherwise arbitrary-looking.
pub const ALLOW_LIST_REQUIRES_TAG: &str =
    "an allow-list needs at least one --tag: allow-lists are not auto-promoted to \
     \"uncategorized\" (auto-allowing domains for every device is a security risk), \
     so an untagged one would install and filter nothing. Deny-lists are auto-promoted \
     and need no tag.";

/// RETIRED — kept as a `pub` const, **never emitted**, for the same reason
/// as [`ALLOW_LIST_REQUIRES_TAG`]: the tag axis left `AllowDirectionGates`
/// entirely, and the argument below is why the gate existed.
///
/// The `uncategorized` sentinel it names is itself retired — a prior
/// cleanup removed the field and the loader strips it — so the exposure this
/// described is not reachable by the route it describes.
///
/// **What replaced it is NOT a superset, and calling it one would misread
/// both.** This refused a list that reached *nobody* by the tag route and
/// could be talked into reaching everybody. `ALLOW_DIRECTION_LIST_STANDING_EXPOSURE`
/// announces the opposite condition: a list that already permits its domains
/// in every profile that does not override it. Different questions about
/// different states.
///
/// No hole opens, and the reason is coverage rather than equivalence: the
/// consent gate (`needs_consent`) is untouched, and the new WARN fires on
/// `enabled && base == Allow` (in `validator.rs`) with **no trust and no
/// tag condition** — so every list the old pair could have applied to is
/// now announced at every load, along with many it never saw.
///
/// Original doc follows.
///
/// Refusal shown when an operator tries to satisfy [`ALLOW_LIST_REQUIRES_TAG`]
/// with the system sentinel itself.
///
/// The tag rule asks *who* the exemption is for. `uncategorized` is the
/// one answer that is not a narrowing: every newly-discovered device and
/// every device carried across the v1→v2 migration is stamped with it, so
/// an allow-list tagged this way reaches exactly the population nobody has
/// looked at yet — the widest audience in the config, chosen through the
/// door built to prevent choosing it.
///
/// So this is not a second usability rule alongside
/// [`ALLOW_LIST_REQUIRES_TAG`]; it is the same security rule, closing the
/// way around it. The two are worded to be read together: that one says
/// an untagged allow-list permits nothing, this one says a
/// system-tagged one permits everything for everyone.
///
/// Shared verbatim by all four write verbs and pinned byte-for-byte by
/// the inline `tests` module below.
pub const ALLOW_LIST_CANNOT_USE_SYSTEM_TAG: &str =
    "an allow-list cannot use the \"uncategorized\" tag: every device warden has not been \
     told about carries it by default, so this would permit the list's domains for every \
     unconfigured device on the network — the widest exposure available, reached through \
     the rule that exists to narrow it. Choose a tag that names who the exemption is for.";

// The `{cat}` slot is gone — the Category entity was removed, and
// blocklists carry no category or tags field. The validator
// auto-promotes an untagged `base = deny` list to `"uncategorized"`
// at load, for safety by default.
pub const BLOCKLIST_IMPORT_LOCAL_OK: &str =
    "Imported '{path}' as blocklist '{id}' (kind={kind}, {n} entries).";

// ── Lists edit modal frozen strings ────────────────
//
// Pinned byte-for-byte by `tests/frozen_strings_s53.rs` and the inline
// asserts in `blocklists.rs` `tests` module below. Same tone family
// as the other set-* strings: present-tense, list id quoted, no trailing
// period, ≤ 60 chars.

/// Save flow success — daemon reload landed.
pub const LIST_EDIT_OK: &str = "List '{id}' updated; reload OK";

pub fn format_list_edit_ok(id: &str) -> String {
    LIST_EDIT_OK.replace("{id}", id)
}

/// Delete flow success — list removed and daemon reload landed.
pub const LIST_DELETE_OK: &str = "List '{id}' deleted; reload OK";

pub fn format_list_delete_ok(id: &str) -> String {
    LIST_DELETE_OK.replace("{id}", id)
}

/// Confirm-step mismatch — operator typed something other than the
/// exact list id, abort the destructive op and bounce to Edit mode.
pub const LIST_DELETE_CONFIRM_FAILED: &str = "Confirmation failed; list not deleted";

/// Save / delete completed on disk but the daemon was unreachable for
/// the hot reload — TOML is durable, daemon will pick up on next start.
pub const LIST_EDIT_DAEMON_UNREACHABLE: &str = "Saved to disk; restart daemon to apply";

pub fn format_blocklist_import_local_ok(path: &str, id: &str, kind: &str, n: usize) -> String {
    BLOCKLIST_IMPORT_LOCAL_OK
        .replace("{path}", path)
        .replace("{id}", id)
        .replace("{kind}", kind)
        .replace("{n}", &n.to_string())
}

// `warden blocklist set-category` was removed along with the `Category`
// entity.

/// `warden blocklist set-kind <list-id> <deny|allow>` with no consent
/// declared. See [`run_set_kind_with_ack`] — this is that function with
/// `accept_unsigned_allow = false`.
///
/// It used to say this was the only thing the TUI could honestly pass,
/// having never asked. That stopped being true when the Lists surface
/// grew a typed-id consent gate: both of its paths now call
/// [`run_set_kind_with_ack`] with whatever the operator actually
/// declared. The principle behind the old wording did not change — a
/// consent nobody asked for is not a consent — it was satisfied by
/// building the question rather than by refusing the write.
///
/// What remains is a convenience for callers that genuinely have nothing
/// to declare, which today is the test suite.
pub async fn run_set_kind(
    config_path: &Path,
    socket_path: &Path,
    list_id: &str,
    kind_str: &str,
    into: Option<&Path>,
) -> anyhow::Result<()> {
    run_set_kind_with_ack(config_path, socket_path, list_id, kind_str, false, into).await
}

/// `warden blocklist set-kind <list-id> <deny|allow>
/// [--accept-unsigned-allow]`.
///
/// Three pre-write gates run when the destination is `allow`, in this
/// order:
///
/// 1. **Consent**, when the list is `trust = remote-unsigned` and
///    neither the file nor the command line declares it. The frozen
///    [`UNSIGNED_ALLOW_LIST_REQUIRES_ACK`](crate::config::schema::validator::UNSIGNED_ALLOW_LIST_REQUIRES_ACK)
///    plus [`ACCEPT_UNSIGNED_ALLOW_FLAG_HINT`]. Scoped to
///    `remote-unsigned` deliberately: on `trust = signed` the answer is
///    the parking-lot message, not "declare consent", and consent does
///    not unblock that case at all.
/// 2. **Tags — RETIRED, never fires.**
///    [`ALLOW_LIST_REQUIRES_TAG`], for **any** trust.
/// 3. **Not the system tag — RETIRED, never fires.**
///    [`ALLOW_LIST_CANNOT_USE_SYSTEM_TAG`], for **any** trust. It was read
///    off the raw entry rather than the loaded config, and that rule
///    OUTLIVES the gate: the loaded config carries the sentinel on every
///    auto-promoted deny-list, so any future check of a `tags` array has
///    to read the file or it refuses the ordinary case and catches
///    nothing.
///
/// Gate 2 used to be gated on `trust == local`, from a time when a
/// remote allow-list could not exist: on a remote list the check never
/// ran, the write went through, and the validator rolled it back on the
/// trust rule instead. Now that remote allow-lists are the normal case
/// that branch is the main road, and an untagged one would land
/// silently mute — installed, green, permitting nothing.
///
/// Consent goes first because when both are missing the security
/// explanation is the one worth reading; the tag rule is met on the
/// retry.
pub async fn run_set_kind_with_ack(
    config_path: &Path,
    socket_path: &Path,
    list_id: &str,
    kind_str: &str,
    accept_unsigned_allow: bool,
    into: Option<&Path>,
) -> anyhow::Result<()> {
    let kind = parse_kind(kind_str)?;
    let now = time::OffsetDateTime::now_utc();

    // The entry's own file is opened BEFORE the config is loaded, which
    // inverts the order every other verb uses. The reason is the
    // direction this verb can travel: `allow → deny` is the repair for a
    // config the validator refuses, and a repair that begins by loading
    // the thing it repairs cannot run. See `degraded_mutation_view`.
    // No `pre_hash` / `post_hash` on a CLI-mutation row.
    //
    // `AuditEvent::CliMutation`'s own doc comment says these two are
    // unused, and it is right: `format_detail` short-circuits every
    // CliMutation into `format_cli_mutation_detail`, which never reads
    // either field. So the value was computed, serialised, and could not
    // be surfaced by any renderer.
    //
    // Not free, either — `audit::tree_hash([config_path])` opens and
    // SHA-256s the master on every mutating blocklist verb, twice
    // (before and after). Dropping it makes the comment true and stops
    // paying for a field with no reader.
    let target_path =
        resolve_existing_target_file(config_path, EntityClass::Blocklists, list_id, into)?;
    let (mut doc, _) = read_or_empty(&target_path)?;
    let entry = find_id_entry_mut(&mut doc, EntityClass::Blocklists.toml_key(), list_id)?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "blocklist '{list_id}' not found in {}",
                target_path.display()
            )
        })?;
    let tbl = entry
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("blocklist entry is not a TOML table"))?;

    let blist = match load_config(config_path, now) {
        Ok(loaded) => loaded
            .config
            .blocklists
            .iter()
            .find(|b| b.id.as_str() == list_id)
            .with_context(|| format!("blocklist '{list_id}' not found"))?
            .clone(),
        // Only the narrowing direction survives a config that will not
        // load. `→ allow` widens what is permitted and stays gated on a
        // config someone can read.
        Err(errs) => degraded_mutation_view(tbl, list_id, kind == BlocklistBase::Deny, errs)?,
    };
    let before = kind_label(blist.base).to_string();
    let after = kind_label(kind).to_string();

    if kind == BlocklistBase::Allow {
        // The list's own file may already carry the consent from an
        // earlier declaration, in which case the operator is not asked
        // twice for a risk their config already records.
        let gates = allow_direction_gates(
            blist.trust,
            blist.accept_unsigned_allow,
            accept_unsigned_allow,
        );
        if gates.needs_consent {
            bail!(
                "{}\n{}",
                crate::config::schema::validator::format_unsigned_allow_list_requires_ack(
                    list_id,
                    blist.trust
                ),
                ACCEPT_UNSIGNED_ALLOW_FLAG_HINT
            );
        }
    }
    // Persist the consent alongside the direction it authorises. Split
    // across two commands it would not be a consent at all — the write
    // in between is the state the next reload refuses.
    if accept_unsigned_allow {
        tbl.insert("accept_unsigned_allow".into(), Value::Boolean(true));
    }
    tbl.insert("base".into(), Value::String(after.clone()));
    let validate_outcome = write_value_validated(config_path, &target_path, &doc);

    match validate_outcome {
        Ok(()) => {
            persist_audit(
                config_path,
                |files| {
                    AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
                        .with_uid(current_uid())
                        .with_action("blocklist.set_kind")
                        .with_target_id(list_id.to_string())
                        .with_fields_before(before.clone())
                        .with_fields_after(after.clone())
                        .with_files(files)
                },
                &[config_path, &target_path],
            );

            println!("{}", format_blocklist_set_kind_ok(list_id, &after));

            let outcome = ipc_reload::attempt_reload(socket_path).await;
            ipc_reload::report_reload_outcome(&outcome);
            Ok(())
        }
        Err(e) => {
            // Still emit an audit row for the rejected attempt so the
            // operator's intent is on record. No hash fields: the row is
            // a CliMutation, and `format_detail` never renders them for
            // that event. (This branch used to record `post_hash =
            // pre_hash` to say "the on-disk config did NOT change" — true,
            // but expressed in a field with no reader. `result =
            // rejected` already says it, and that one IS rendered.)
            let err_msg = e.to_string();
            persist_audit(
                config_path,
                |files| {
                    AuditRecord::new(AuditEvent::CliMutation, AuditResult::Rejected)
                        .with_uid(current_uid())
                        .with_action("blocklist.set_kind")
                        .with_target_id(list_id.to_string())
                        .with_fields_before(before.clone())
                        .with_fields_after(after.clone())
                        .with_errors([err_msg.clone()])
                        .with_files(files)
                },
                &[config_path, &target_path],
            );
            Err(e)
        }
    }
}

/// Every profile for which `list` is effectively an allow-list.
///
/// Asked through [`crate::config::schema::effective_direction`] — the one predicate
/// (`config/schema/blocklist.rs`), never a local re-derivation. A second
/// copy is what that costs: `effective_tags`
/// was computed in two places that answered differently, the validator saw a
/// superset of what the resolver did, and the "device not filtered" WARN went
/// silent on devices that really were uncovered — a false negative on a
/// security warning.
///
/// Returns profile **keys** in `BTreeMap` order, so a refusal naming several
/// is stable across runs and the operator fixes them in one pass.
///
/// Says nothing about [`Blocklist::enabled`]: a disabled list holds no bit
/// and produces no verdict, but `set-trust` is about what the row will permit
/// once it is enabled again, and a gate that lapses when a list is toggled
/// off is a gate with a trivial bypass.
#[must_use]
pub fn profiles_where_list_is_allow(
    config: &crate::config::schema::ConfigV1,
    list: &Blocklist,
) -> Vec<String> {
    use crate::config::schema::{effective_direction, ListPolicy};
    config
        .profiles
        .iter()
        .filter(|(_, p)| effective_direction(p, list) == ListPolicy::Allow)
        .map(|(key, _)| key.to_string())
        .collect()
}

/// Appended to the unsigned-allow refusal when what makes the list an
/// allow-list is a **profile override** rather than its own `base`.
///
/// **Why it lives here and not in `config/schema/validator.rs`.** The two
/// layers refuse for the same reason and deliberately do not share a string:
/// the design gives the validator the *enforcement* seat — the backstop for
/// a hand-edited TOML, where the only readers are the loader and a log — and
/// the verb the *readable* seat, where the operator is standing at a prompt
/// with a flag they can type. This is the verb's half.
///
/// **Why it names the profiles.** The consent lives on the list's row; the
/// offence lives in the profile. A refusal naming only the list sends the
/// operator to `[[blocklists]]`, where `base = "deny"` looks entirely
/// correct and there is nothing to fix.
pub const UNSIGNED_ALLOW_VIA_PROFILE_OVERRIDE: &str =
    "This list's own base is not allow, but these profiles override it to allow: {profiles}. \
     Going remote-unsigned hands whoever controls the URL the power to unblock any domain \
     for them, at every refresh.";

/// Substitute `{profiles}` into [`UNSIGNED_ALLOW_VIA_PROFILE_OVERRIDE`].
#[must_use]
pub fn format_unsigned_allow_via_profile_override(profiles: &[String]) -> String {
    UNSIGNED_ALLOW_VIA_PROFILE_OVERRIDE.replace("{profiles}", &profiles.join(", "))
}

/// `warden blocklist set-trust <list-id> <local|remote-unsigned>
/// [--accept-unsigned-allow]`. `signed` is refused by [`parse_trust`]
/// before anything here runs (parked, not yet supported). Same Rejected-audit
/// pattern as [`run_set_kind`].
///
/// **The transition everybody forgets.** This verb changes no `kind`, so
/// it reads as unrelated to allow-lists — but taking an allow-direction
/// list from `local` to `remote-unsigned` is precisely the moment a file
/// the operator wrote becomes a subscription somebody else can edit, and
/// it is the same risk `set-kind` gates. Without the gate here the
/// command succeeds, the config is written, and the *next* reload
/// refuses it: the operator ends up with a daemon that will not come
/// back for a command warden told them had worked.
///
/// A deny-list going remote is untouched — no unblocking power, no
/// declaration to make, and it is the ordinary shape of every subscribed
/// list.
pub async fn run_set_trust(
    config_path: &Path,
    socket_path: &Path,
    list_id: &str,
    trust_str: &str,
    accept_unsigned_allow: bool,
    into: Option<&Path>,
) -> anyhow::Result<()> {
    let trust = parse_trust(trust_str)?;
    let now = time::OffsetDateTime::now_utc();
    let loaded = load_config(config_path, now).map_err(format_config_errors)?;
    let blist = loaded
        .config
        .blocklists
        .iter()
        .find(|b| b.id.as_str() == list_id)
        .with_context(|| format!("blocklist '{list_id}' not found"))?;
    let before = trust_label(blist.trust).to_string();
    let after = trust_label(trust).to_string();

    // The same gate `set-kind` runs, reached from the other side: the kind stays
    // put and the trust moves under it. Same consent, same flag, same
    // "already declared in the file" exemption.
    //
    // **This comment used to say "same condition", and that is the part that
    // went stale.** It was true while direction was a global property of the
    // list: one place to read, one answer. Per-profile direction overrides
    // changed that, so a list can be `base = "deny"` and still be an
    // allow-list for every profile that overrides it — and this gate, reading
    // `base` alone, waved exactly that case through. Measured before the
    // repair: the verb printed success, the file was written, and the
    // resulting config *loaded clean*, because the validator's own consent
    // check keys on `base` too. So the state this produced was not a config
    // that fails to start — it was a standing unconsented exemption that
    // nothing reported.
    //
    // The question is asked through `effective_direction` now, via
    // `profiles_where_list_is_allow`, so the verb and the validator cannot
    // answer it differently.
    //
    // `base == Allow` stays an **independent disjunct** rather than being
    // folded into the profile scan. A config with no profiles at all, or one
    // where every existing profile overrides to deny, still has a row that
    // permits for any profile added later — and that standing power is what
    // the ack is about.
    let allowing_profiles = profiles_where_list_is_allow(&loaded.config, blist);
    let allows_somewhere = blist.base == BlocklistBase::Allow || !allowing_profiles.is_empty();
    if trust == BlocklistTrust::RemoteUnsigned
        && allows_somewhere
        && !blist.accept_unsigned_allow
        && !accept_unsigned_allow
    {
        let mut msg = crate::config::schema::validator::format_unsigned_allow_list_requires_ack(
            list_id, trust,
        );
        // Only when the override is the *reason*. With `base = "allow"` the
        // primary message already describes the row the operator is looking
        // at, and naming profiles as well would read as a second, different
        // problem.
        if blist.base != BlocklistBase::Allow {
            msg.push('\n');
            msg.push_str(&format_unsigned_allow_via_profile_override(
                &allowing_profiles,
            ));
        }
        bail!("{msg}\n{ACCEPT_UNSIGNED_ALLOW_FLAG_HINT}");
    }

    let target_path =
        resolve_existing_target_file(config_path, EntityClass::Blocklists, list_id, into)?;
    let (mut doc, _) = read_or_empty(&target_path)?;
    let entry = find_id_entry_mut(&mut doc, EntityClass::Blocklists.toml_key(), list_id)?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "blocklist '{list_id}' not found in {}",
                target_path.display()
            )
        })?;
    let tbl = entry
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("blocklist entry is not a TOML table"))?;
    // One write for the move and the declaration that authorises it —
    // split across two commands, the state in between is the one the
    // next reload refuses.
    if accept_unsigned_allow {
        tbl.insert("accept_unsigned_allow".into(), Value::Boolean(true));
    }
    tbl.insert("trust".into(), Value::String(after.clone()));
    let validate_outcome = write_value_validated(config_path, &target_path, &doc);

    match validate_outcome {
        Ok(()) => {
            persist_audit(
                config_path,
                |files| {
                    AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
                        .with_uid(current_uid())
                        .with_action("blocklist.set_trust")
                        .with_target_id(list_id.to_string())
                        .with_fields_before(before.clone())
                        .with_fields_after(after.clone())
                        .with_files(files)
                },
                &[config_path, &target_path],
            );

            println!("{}", format_blocklist_set_trust_ok(list_id, &after));

            let outcome = ipc_reload::attempt_reload(socket_path).await;
            ipc_reload::report_reload_outcome(&outcome);
            Ok(())
        }
        Err(e) => {
            let err_msg = e.to_string();
            persist_audit(
                config_path,
                |files| {
                    AuditRecord::new(AuditEvent::CliMutation, AuditResult::Rejected)
                        .with_uid(current_uid())
                        .with_action("blocklist.set_trust")
                        .with_target_id(list_id.to_string())
                        .with_fields_before(before.clone())
                        .with_fields_after(after.clone())
                        .with_errors([err_msg.clone()])
                        .with_files(files)
                },
                &[config_path, &target_path],
            );
            Err(e)
        }
    }
}

/// `warden blocklist import-local <path> --id <list-id> --kind <deny|allow>
/// [--tag <slug>]… [--display-name "..."]`.
///
/// Copies `path` to a managed location under
/// `<config-parent>/lists/<id>.txt`, then registers a `[[blocklists]]`
/// row with `trust = "local"`, the operator-supplied `kind`,
/// and a derived `display_name`. Format auto-detects from file content
/// (plain newline-separated strings resolve to `domains`; mixed
/// `||domain^` content resolves to `adguard`).
///
/// There is no `--category`: the `Category` entity was removed entirely.
///
/// **There is no `--tag` either, and the two tag gates it fed are dead.**
/// This used to read "`--kind allow` **requires** at least one `--tag`",
/// which stopped being true once tag intersection stopped deciding
/// filtering: `AllowDirectionGates` lost
/// its tag axis outright (the struct has only `needs_consent`), the flag
/// left the clap tree, and the `uncategorized` auto-promotion the asymmetry
/// rested on no longer runs. A doc naming a flag the binary does not have is
/// the phantom-verb defect `scripts/check_phantom_verbs.sh` gates for,
/// reached from the other side.
///
/// What still gates an allow-direction list is the **consent** rule
/// (`accept_unsigned_allow` on a remote source), which is untouched, plus
/// the standing-exposure WARN at every load. The two retired refusals are
/// kept as record at [`ALLOW_LIST_REQUIRES_TAG`] and
/// [`ALLOW_LIST_CANNOT_USE_SYSTEM_TAG`], each carrying why it existed.
///
/// The validator requires every blocklist `url`
/// to begin with `http://` or `https://`. For an imported local file
/// the natural URL would be `file:///…`, but the validator lives outside
/// this module's scope to change. This sidesteps the gap by writing a
/// synthetic `https://imported.local/<id>.txt` placeholder URL — the
/// entry validates and the local file lives next to it on disk. The
/// placeholder URL is documented in the audit row so operators can find
/// it via `warden audit tail`.
#[allow(clippy::too_many_arguments)]
pub async fn run_import_local(
    config_path: &Path,
    socket_path: &Path,
    src: &Path,
    list_id: &str,
    kind_str: &str,
    display_name: Option<&str>,
    into: Option<&Path>,
) -> anyhow::Result<()> {
    let _ = Id::new(list_id).map_err(|e| anyhow::anyhow!("invalid id: {e}"))?;
    let kind = parse_kind(kind_str)?;
    // The trust this verb is about to write, named once and read twice: the
    // gates below judge it, and the `[[blocklists]]` row further down stores
    // it. Deriving both from one binding is what makes the gate call track
    // the verb — if `import-local` ever grows a `--trust` flag, the gate
    // follows without anyone remembering to update it.
    let trust = BlocklistTrust::Local;

    // The gates are evaluated by the SHARED function, never by a private
    // copy. This call site is why the rule is written down. It used to carry
    // its own inline pair of tag checks; a prior cutover retired those two arms
    // inside `allow_direction_gates` (they lost their premise when tag
    // intersection stopped deciding anything) and this verb, reading its own
    // copy, went on refusing. The other three direction-setting verbs
    // accepted what this one rejected, and the remedy its message named —
    // `--tag` — no longer exists on any verb. A refusal that cannot be
    // satisfied in its own terms, on the only route to an allow-list whose
    // file the operator owns.
    //
    // Destructured exhaustively, with no `..`, on purpose: a fourth gate
    // added to `AllowDirectionGates` breaks the build HERE instead of being
    // silently skipped by this verb. The comment that used to sit on the
    // test below claimed this call site "needs its own proof" — prose is
    // exactly the defence that does not fail a build.
    // Still destructured, and still WITHOUT a `..`: that is the trip-wire
    // the comment above describes — a second gate must break the build here
    // rather than be silently skipped by this verb. A prior cleanup removed
    // the two retired tag gates that used to be bound with `_` here.
    let AllowDirectionGates { needs_consent } = allow_direction_gates(trust, false, false);
    if kind == BlocklistBase::Allow {
        // Consent first, matching the order the other three verbs document:
        // when several gates are unmet, the security explanation is the one
        // worth reading. It is inert here — `import-local` writes
        // `trust = local`, the operator authored the file — and asked anyway,
        // because the answer comes from the shared function rather than from
        // an assumption restated at this call site. That is the whole point
        // of routing through it: if the gates ever refuse something for local
        // trust, this verb inherits the refusal without anyone remembering.
        if needs_consent {
            bail!(
                "{}\n{}",
                crate::config::schema::validator::format_unsigned_allow_list_requires_ack(
                    list_id, trust
                ),
                ACCEPT_UNSIGNED_ALLOW_FLAG_HINT
            );
        }
    }
    if !src.exists() {
        bail!("source file does not exist: {}", src.display());
    }
    if !src.is_file() {
        bail!("source path is not a regular file: {}", src.display());
    }

    let now = time::OffsetDateTime::now_utc();
    let loaded = load_config(config_path, now).map_err(format_config_errors)?;
    if loaded
        .config
        .blocklists
        .iter()
        .any(|b| b.id.as_str() == list_id)
    {
        bail!("blocklist '{list_id}' already exists");
    }

    // Copy source to the managed location.
    let parent = config_path.parent().unwrap_or_else(|| Path::new("."));
    let lists_dir = parent.join("lists");
    std::fs::create_dir_all(&lists_dir)
        .with_context(|| format!("create {}", lists_dir.display()))?;
    let dest = lists_dir.join(format!("{list_id}.txt"));
    std::fs::copy(src, &dest)
        .with_context(|| format!("copy {} → {}", src.display(), dest.display()))?;

    // Tally entries + auto-detect format.
    let raw = std::fs::read_to_string(&dest).unwrap_or_default();
    let format = autodetect_format(&raw);
    let n_entries = count_entries(&raw, format);

    let mut tbl = toml::map::Map::new();
    tbl.insert("id".into(), Value::String(list_id.to_string()));
    tbl.insert(
        "display_name".into(),
        Value::String(display_name.unwrap_or(list_id).to_string()),
    );
    // Synthetic URL — see DECISION OUTSIDE DOC in the doc-comment above.
    tbl.insert(
        "url".into(),
        Value::String(format!("https://imported.local/{list_id}.txt")),
    );
    tbl.insert(
        "format".into(),
        Value::String(format_label(format).to_string()),
    );
    tbl.insert("base".into(), Value::String(kind_label(kind).to_string()));
    tbl.insert(
        "trust".into(),
        Value::String(trust_label(trust).to_string()),
    );
    // No `category` field — the entity was removed. No `tags` key
    // either: `--tag` is gone, so there is nothing operator-supplied
    // to persist, and the loader's auto-promotion of an untagged
    // deny-list must not be round-tripped into the file by a writer.

    let target_path = resolve_target_file(config_path, EntityClass::Blocklists, into)?;
    let (mut doc, _) = read_or_empty(&target_path)?;
    upsert_id_keyed(
        &mut doc,
        EntityClass::Blocklists.toml_key(),
        list_id,
        Value::Table(tbl),
    )?;
    let validate_outcome = write_value_validated(config_path, &target_path, &doc);

    match validate_outcome {
        Ok(()) => {
            let path_str = dest.display().to_string();
            let kind_str_owned = kind_label(kind).to_string();
            persist_audit(
                config_path,
                |files| {
                    AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
                        .with_uid(current_uid())
                        .with_action("blocklist.import_local")
                        .with_target_id(list_id.to_string())
                        .with_fields_before("")
                        .with_fields_after(format!("kind={kind_str_owned}, trust=local"))
                        .with_files(files)
                },
                &[config_path, &target_path],
            );

            println!(
                "{}",
                format_blocklist_import_local_ok(&path_str, list_id, kind_label(kind), n_entries)
            );

            let outcome = ipc_reload::attempt_reload(socket_path).await;
            ipc_reload::report_reload_outcome(&outcome);
            Ok(())
        }
        Err(e) => {
            // Best-effort cleanup: a rejected import shouldn't leave the
            // managed-location file lingering. Silent on failure (operator
            // can clean up by hand if needed).
            let _ = std::fs::remove_file(&dest);
            Err(e)
        }
    }
}

// ── Helpers shared by the new mutation verbs ───────────────────────

fn parse_kind(s: &str) -> anyhow::Result<BlocklistBase> {
    match s {
        // Wire format renamed
        // from `block` to `deny`. No v1 alias is accepted.
        "deny" => Ok(BlocklistBase::Deny),
        "allow" => Ok(BlocklistBase::Allow),
        // The third state. Accepted here rather than left
        // CLI-unreachable — the migration and a hand-edited TOML can both
        // produce it, and a value the product writes but its own CLI
        // cannot name is a surface that reads as broken. It needs no gate:
        // an inert list permits nothing, so there is no exposure to price.
        // The validator WARNs about it at every load.
        "ignore" => Ok(BlocklistBase::Ignore),
        other => bail!("unknown kind '{other}'. Valid: deny, allow, ignore"),
    }
}

fn parse_trust(s: &str) -> anyhow::Result<BlocklistTrust> {
    match s {
        "local" => Ok(BlocklistTrust::Local),
        "remote-unsigned" => Ok(BlocklistTrust::RemoteUnsigned),
        // `signed` is intentionally absent from the CLI surface — the
        // validator refuses it with `TRUST_SIGNED_NOT_YET_SUPPORTED`
        // and the operator typing it through the CLI gets the same parking-
        // lot message at reload time. Refusing here surfaces it earlier
        // with a helper hint that points at the supported values.
        "signed" => bail!(
            "trust 'signed' is not supported in this version. Use 'local' for trusted allow-lists or 'remote-unsigned' for deny-only lists."
        ),
        other => bail!("unknown trust '{other}'. Valid: local, remote-unsigned"),
    }
}

/// Wire token for a kind. See [`format_label`] for why this delegates.
fn kind_label(k: BlocklistBase) -> &'static str {
    k.wire_str()
}

/// Wire token for a trust level. See [`format_label`] for why this delegates.
fn trust_label(t: BlocklistTrust) -> &'static str {
    t.wire_str()
}

fn autodetect_format(raw: &str) -> BlocklistFormat {
    // Adguard rule files commonly start every line with `||` /
    // `@@||`; `/etc/hosts` files usually start lines with an IP.
    // Default to `domains` for anything else (the lists.purge.cc
    // model).
    let mut has_adguard = false;
    let mut has_hosts = false;
    for line in raw.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if t.starts_with("||") || t.starts_with("@@") {
            has_adguard = true;
            break;
        }
        // Accept either a space or a tab after the sink IP — tab-separated
        // hosts files are common and previously fell through to `domains`.
        if let Some(rest) = t
            .strip_prefix("0.0.0.0")
            .or_else(|| t.strip_prefix("127.0.0.1"))
        {
            if rest.starts_with([' ', '\t']) {
                has_hosts = true;
            }
        }
    }
    if has_adguard {
        BlocklistFormat::Adguard
    } else if has_hosts {
        BlocklistFormat::Hosts
    } else {
        BlocklistFormat::Domains
    }
}

fn count_entries(raw: &str, _format: BlocklistFormat) -> usize {
    raw.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .count()
}

/// Thin signature adapter over the single audit seam
/// [`super::audit_emit::persist_cli_mutation_audit`]. The blocklist verbs
/// build their record with an explicit `files` list, so this forwards that
/// list into the seam's no-arg closure. The failure policy lives entirely
/// in the seam — this adapter adds none of its own.
fn persist_audit<F>(config_path: &Path, build: F, files: &[&Path])
where
    F: FnOnce(Vec<&Path>) -> AuditRecord,
{
    let files: Vec<&Path> = files.to_vec();
    persist_cli_mutation_audit(config_path, move || build(files));
}

#[cfg(test)]
mod tests;
