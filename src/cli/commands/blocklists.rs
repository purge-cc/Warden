//! `warden blocklist` — v1-native CRUD for `[[blocklists]]` entries.
//!
//! Blocklists are external lists subscribed to by profiles (via their
//! `blocklists = [...]` field). Each has a stable [`Id`], a URL, a
//! `format` (domains / adguard / hosts), and optional fetch knobs
//! (update interval, max entries, enabled flag, auth_token_ref).
//!
//! S33 adds a cross-reference check against `secrets.toml` when
//! `auth_token_ref` is set: a missing ref yields a warning (not an
//! error) to match the S32 warn-not-error pattern for secrets.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use toml::Value;

use super::audit_emit::{current_uid, persist_cli_mutation_audit};
use super::ipc_reload;
// Sprint A of `lists_categories_v2` removed `Profile.blocklists`, so the
// `apply_blocklists_change_inline` cascade helper is dead in this file.
// Sprint B may reintroduce equivalent helpers for tag-based mutation.
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
// It was doubly dead. It named `--cascade`, a flag cli-h5 deleted after
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
        // `plp-s3`: "it has no tags of its own" is retired, not moved. Tags
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
/// predicate, called rather than copied (P5). A read verb whose answer can
/// disagree with the filter it reports on is worse than no answer, and this
/// product has already paid for one duplicated tag rule that drifted (D11).
///
/// # `plp-s3` narrowed the answer, and the narrowing is the feature
///
/// This used to walk three axes — profiles, devices, subnets — because tag
/// intersection could attach a list to any of them. It cannot any more:
/// direction is a property of the `(profile, list)` pair, so the only axis
/// that can carry a list is the **profile**. The device and subnet rows stay
/// in [`Enforcement`] and stay empty; they are what `show` prints when a
/// pre-v3 config is being read back, and emptying them here rather than
/// deleting the fields keeps that difference visible instead of silently
/// re-labelling it. S5 removes them with the rest of the tag surface.
///
/// A device reaches a list through its profile, so "who does this list
/// reach" is answered one hop earlier than it used to be — which is exactly
/// the ceremony collapse `_docs/features/profile_list_policy.md` §1.1 E4
/// asks for.
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
/// stopped deciding at the `plp-s3` cutover and `plp-s5a` removed them, so
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
    // `plp-s3`: the fix is no longer "make a tag match". A list is inert
    // only when every profile overrides it to `ignore`, so the remedy names
    // the override — and names the config key rather than a verb, because
    // the operator-facing verb (`warden profile list-policy`) lands in S4 and
    // pointing at a command that does not exist yet is the phantom-verb
    // defect this repo has a gate for.
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
    let loaded = load_config(config_path, now).map_err(format_errs)?;
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
    let loaded = load_config(config_path, now).map_err(format_errs)?;
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

    // Sprint 43 T2: append a runtime block from the live daemon if
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

/// Sprint 43 T2: query the running daemon for `id`'s runtime telemetry
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
    // remedy is named inline because "truncated: 2370261" on its own
    // tells the operator a number, not what to do about it.
    if s.parsed_truncated > 0 {
        println!(
            "  TRUNCATED:            {} entries dropped — raise `max_entries` for this list",
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
/// intersection decided which lists reached which client. `plp-s3` ended
/// that — an allow-direction list is inherited by every profile that does
/// not override it, tagged or not — and left them answering a constant
/// `false`. `plp-s5a` removed the field they read, so there is nothing
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
/// `_tags` is accepted and ignored. `plp-s5c` removed `--tag` from the
/// clap tree, and the inner `run_add_*` family lost the parameter
/// outright — but this wrapper's remaining caller is a test helper in
/// `tui/mod.rs`, which belongs to a different lane of the same sprint.
/// Narrowing the signature here would break that lane's branch
/// mid-flight for no gain, so the argument stays and the `_` prefix is
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
/// scrambled by stray stdout (the pre-S53.2 behaviour you saw on
/// `add_feedback.png`).
///
/// **Sprint C T5 of `lists_categories_v2`:** runs the §6.1 three-gate
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
/// and persisted into the entry's `tags` array. `plp-s5c` removed the
/// flag and `plp-s5a` removed the field; a list's reach is now its `base`
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
/// 2. **Tags — RETIRED by `plp-s3`, never fires.**
///    [`ALLOW_LIST_REQUIRES_TAG`] said: allow-lists are not auto-promoted
///    to `uncategorized` (D2), so an untagged one applies to no device and
///    permits nothing. That was true only while tag intersection decided
///    which lists reached which clients. It does not — a list's direction
///    now reaches every profile that does not override it — so the
///    premise is gone and [`allow_direction_gates`] answers `false`.
/// 3. **Not the system tag — RETIRED by `plp-s3`, never fires.**
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
        //
        // `plp-s5c` removed `--tag`, so the two tag arguments are literals
        // rather than a reading of anything: a list this verb creates has
        // no tags, full stop. They are passed rather than dropped because
        // the signature is shared with the TUI and IPC callers, which do
        // still read a real file — retiring the parameters is theirs to
        // do, not this lane's. Both are ignored inside the predicate
        // either way: `needs_tag` / `needs_non_system_tag` have answered
        // `false` since plp-s3.
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
    let loaded = load_config(config_path, now).map_err(format_errs)?;
    if loaded.config.blocklists.iter().any(|b| b.id.as_str() == id) {
        bail!("blocklist \"{id}\" already exists");
    }
    // `tag_model_consolidation` §3.2: compare on the CANONICAL key, not
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
    // `plp-s5c`: no `tags` key is written. `--tag` is gone, so there is
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

    // audit-01: blocklist add is supply-chain-relevant — record the URL
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
    // audit-01: snapshot the prior URL before mutating so a `set url`
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

    // Sprint 36 HR2: post-write hot reload via the shared helper.
    let outcome = ipc_reload::attempt_reload(socket_path).await;
    ipc_reload::report_reload_outcome(&outcome);

    Ok(())
}

/// Remove a blocklist entry: drop every `profiles.<id>.lists` override
/// naming it, then drop the `[[blocklists]]` row, then fire one reload.
///
/// **This doc said "There is no cascade" until F22**, on the premise that a
/// profile never enumerates blocklist ids. `profile_list_policy` §4 S2 gave
/// them `Profile.lists`, and the validator refuses an override naming a row
/// that does not exist (`CrossRefMiss`, ERROR) — so the premise died and the
/// cascade is load-bearing again.
///
/// The `--cascade` flag deleted in cli-h5 is deliberately *not* revived: see
/// [`run_remove_silent`] for why the cascade is unconditional.
pub async fn run_remove(
    config_path: &Path,
    socket_path: &Path,
    id: &str,
    into: Option<&Path>,
) -> anyhow::Result<()> {
    // verbs-02: remove of an absent blocklist is idempotent (exit 0). The
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
    // **The comment that used to sit here was the defect.** It read: "Sprint A
    // of `lists_categories_v2` (D1, D5): profiles no longer enumerate
    // blocklists, so the v1 cross-ref check + cascade is structurally a no-op
    // now" — and then assigned `Vec::new()` on the strength of it. The premise
    // died in `profile_list_policy` §4 S2, which gave profiles `Profile.lists`
    // and gave the validator a rule refusing an override that names no
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
    // audit row.** The CLI has offered no `--cascade` since cli-h5 and passes
    // `false`; honouring the flag would leave the CLI exactly as broken while
    // looking repaired. Nor is there a policy question to defer to the
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
    // audit-01: snapshot the removed list's URL before dropping it so the
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

    // Sprint 36 HR2: post-write hot reload via the shared helper.
    // Sprint 43 T3 (R2 atomicity): for cascade, the loop wrote N profile
    // files; this is the ONE reload that lands the whole compound
    // mutation in the daemon's view at once.
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
/// and an absent `lists` deserialise identically (`plp_s2`), so removing it
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
            // `tag_model_consolidation` §3.2: same canonical key as the
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
        // S42 T4 — deprecated legacy field name. Accepts the same
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

/// Sprint C T5 of `lists_categories_v2`: TUI-facing entry point for
/// the §6.1 gate-3 reachability probe. The TUI Add modal calls this
/// directly before invoking the per-mode write pipeline so the
/// inline error message reads identically to the CLI form. Empty
/// URL is a no-op success (caller already validated the format).
pub async fn probe_url_for_tui(url: &str) -> anyhow::Result<()> {
    if url.is_empty() {
        return Ok(());
    }
    probe_url_reachable(url).await
}

/// Sprint C T5 of `lists_categories_v2`: §6.1 gate 3 — synchronous
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
/// rename and made the Lists modal unable to save at all
/// (`s-tui-lists-edit-save-rejected`); these three helpers were the
/// remaining duplicates of the same idea.
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
/// anywhere in `src/`; and it ended "tags included", a field `plp-s5a`
/// removed and the loader now strips. The remaining sentence is the part
/// that still holds and is still the reason this helper exists.
///
/// Used only by the degraded path in [`run_set_kind_with_ack`]. It had a
/// second caller, `run_tag_remove`, until `plp-s5c` deleted the verb —
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
        return Err(format_errs(errs));
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

fn format_errs(errs: Vec<crate::config::error::ConfigError>) -> anyhow::Error {
    let mut msg = format!("cannot load config ({} error(s)):", errs.len());
    for e in &errs {
        msg.push_str("\n  - ");
        msg.push_str(&e.to_string());
    }
    anyhow::anyhow!(msg)
}

// ── S50 T3: per-list mutation verbs (set-kind / set-trust /
//    import-local) + their frozen operator-facing strings (§9). ──────
//
// Sprint A of `lists_categories_v2` (Q2-A) removed the `set-category`
// verb and its `BLOCKLIST_SET_CATEGORY_OK` const — the Category entity
// is gone. Sprint C reintroduces equivalent operator surface as
// `warden blocklist tag add/remove` with its own frozen string.

pub const BLOCKLIST_SET_KIND_OK: &str = "Blocklist '{id}' kind set to {kind}.";

pub fn format_blocklist_set_kind_ok(id: &str, kind: &str) -> String {
    BLOCKLIST_SET_KIND_OK
        .replace("{id}", id)
        .replace("{kind}", kind)
}

/// **DECISION OUTSIDE DOC (S50 T3):** §9 of `_docs/features/lists_categories_v1.md`
/// names `BLOCKLIST_SET_KIND_OK` but does NOT list a `BLOCKLIST_SET_TRUST_OK`.
/// The orchestrator kickoff explicitly flagged the ambiguity and asked the
/// agent to pick a pattern consistent with the other set-* messages. The
/// alternatives were (a) reuse `BLOCKLIST_SET_KIND_OK` with a polymorphic
/// "kind"-or-"trust" format helper or (b) coin a sibling for the trust
/// verb. T3 picked (b) so `warden audit tail` and the operator-facing
/// stdout line both speak the same vocabulary as the audit `action` tag
/// (`blocklist.set_trust` vs `blocklist.set_kind` are distinct mutations).
/// T5's `tests/frozen_strings_s50.rs` mirror MAY pin this string; the §9
/// table is the source of truth for intent and the orchestrator audit
/// can drop this if it elects to consolidate the two messages later.
pub const BLOCKLIST_SET_TRUST_OK: &str = "Blocklist '{id}' trust set to {trust}.";

pub fn format_blocklist_set_trust_ok(id: &str, trust: &str) -> String {
    BLOCKLIST_SET_TRUST_OK
        .replace("{id}", id)
        .replace("{trust}", trust)
}

/// RETIRED — kept as a `pub` const, **never emitted**.
///
/// **`AllowDirectionGates` no longer has a tag axis at all** — the struct
/// carries exactly one field, `needs_consent` (`:607`). It is not that the
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
/// `plp-s5f` removed its cross-file byte-pin from
/// `tests/frozen_strings_entity_contracts.rs` — a frozen *contract* asserts a
/// live promise, and this is a record. The inline pin below stays, which is
/// the point of the split: the record's wording is what is worth freezing.
///
/// Original doc follows.
///
/// `tag_model_consolidation` §3.3 — refusal shown when an operator tries
/// to create or convert a `base = allow` blocklist without any tags.
///
/// D2 keeps allow-lists out of the `uncategorized` auto-promotion on
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
/// The `uncategorized` sentinel it names is itself retired — `plp-s5a`
/// removed the field and the loader strips it — so the exposure this
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
/// `enabled && base == Allow` (`validator.rs:3980`) with **no trust and no
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

// Sprint A of `lists_categories_v2` (Q2-A): the `{cat}` slot is gone
// — Category entity removed, lists carry `tags` directly. Sprint C
// extends this with a `{tags}` slot once the operator-facing tag
// picker lands; the validator auto-promotes `base = deny` lists with
// empty tags to `["uncategorized"]` in T3 so behaviour stays safe by
// default in the meantime.
pub const BLOCKLIST_IMPORT_LOCAL_OK: &str =
    "Imported '{path}' as blocklist '{id}' (kind={kind}, {n} entries).";

// ── Sprint 53 — Lists edit modal frozen strings (§6) ────────────────
//
// Pinned byte-for-byte by `tests/frozen_strings_s53.rs` and the inline
// asserts in `blocklists.rs` `tests` module below. Same tone family
// as S35/S36/S50 strings: present-tense, list id quoted, no trailing
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

// `warden blocklist set-category` removed in Sprint A of
// `lists_categories_v2` (Q2-A): the `Category` entity is gone; lists
// carry `tags: Vec<TagSlug>` directly. Sprint C reintroduces the
// equivalent operator surface as `warden blocklist tag add/remove`.

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
/// 2. **Tags — RETIRED by `plp-s3`, never fires.**
///    [`ALLOW_LIST_REQUIRES_TAG`], for **any** trust.
/// 3. **Not the system tag — RETIRED by `plp-s3`, never fires.**
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
            // R4: still emit an audit row for the rejected attempt so the
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
/// (`config/schema/blocklist.rs`), never a local re-derivation. D11 of
/// `tag_model_consolidation` is what a second copy costs: `effective_tags`
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
/// F20's table gives the validator the *enforcement* seat — the backstop for
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
/// before anything here runs (parking lot, S51+). Same Rejected-audit
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
    let loaded = load_config(config_path, now).map_err(format_errs)?;
    let blist = loaded
        .config
        .blocklists
        .iter()
        .find(|b| b.id.as_str() == list_id)
        .with_context(|| format!("blocklist '{list_id}' not found"))?;
    let before = trust_label(blist.trust).to_string();
    let after = trust_label(trust).to_string();

    // The gate `set-kind` runs, reached from the other side: the kind stays
    // put and the trust moves under it. Same consent, same flag, same
    // "already declared in the file" exemption.
    //
    // **This comment used to say "same condition", and that is the part that
    // went stale.** It was true while direction was a global property of the
    // list: one place to read, one answer. `profile_list_policy` made
    // direction per-profile, so a list can be `base = "deny"` and still be an
    // allow-list for every profile that overrides it — and this gate, reading
    // `base` alone, waved exactly that case through. Measured before the
    // repair (F21): the verb printed success, the file was written, and the
    // resulting config *loaded clean*, because the validator's own consent
    // check keys on `base` too (F20, closed in the lane that owns
    // `validator.rs`). So the state this produced was not a config that fails
    // to start — it was a standing unconsented exemption that nothing
    // reported.
    //
    // The question is asked through `effective_direction` now, via
    // `profiles_where_list_is_allow`, so the verb and the validator cannot
    // answer it differently (D11).
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
/// row with `trust = "local"`, the operator-supplied `kind` and `tags`,
/// and a derived `display_name`. Format auto-detects from file content
/// (T3 picks `domains` for plain newline-separated strings; mixed
/// `||domain^` content gets `adguard`).
///
/// There is no `--category`: `Category` was removed entirely in Sprint A
/// of `lists_categories_v2` and tags took its place. The earlier version
/// of this comment still documented the flag.
///
/// **There is no `--tag` either, and the two tag gates it fed are dead.**
/// This used to read "`--kind allow` **requires** at least one `--tag`",
/// which stopped being true at the plp cutover: `AllowDirectionGates` lost
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
/// **DECISION OUTSIDE DOC (S50 T3):** the validator at
/// `src/config/schema/validator.rs:197` requires every blocklist `url`
/// to begin with `http://` or `https://`. For an imported local file
/// the natural URL would be `file:///…`, but rewriting the validator
/// is OUT OF SCOPE for T3 (orchestrator constraint: "Do NOT touch
/// src/config/schema/"). T3 sidesteps the gap by writing a synthetic
/// `https://imported.local/<id>.txt` placeholder URL — the entry
/// validates and the local file lives next to it on disk. A future
/// phase (likely the validator-loosening companion to T5) will teach
/// the loader to prefer the local copy when `trust = local`. Until
/// then the placeholder URL is documented in the audit row so
/// operators can find it via `warden audit tail`.
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

    // P5: the gates are evaluated by the SHARED function, never by a private
    // copy. This call site is why the rule is written down. It used to carry
    // its own inline pair of tag checks; `plp-s3` retired those two arms
    // inside `allow_direction_gates` (they lost their premise when tag
    // intersection stopped deciding anything) and this verb, reading its own
    // copy, went on refusing. The other three direction-setting verbs
    // accepted what this one rejected, and the remedy its message named —
    // `--tag` — is refused by `warden blocklist tag`, retired in the same
    // sprint. A refusal that cannot be satisfied in its own terms, on the
    // only route to an allow-list whose file the operator owns.
    //
    // Destructured exhaustively, with no `..`, on purpose: a fourth gate
    // added to `AllowDirectionGates` breaks the build HERE instead of being
    // silently skipped by this verb. The comment that used to sit on the
    // test below claimed this call site "needs its own proof" — prose is
    // exactly the defence that does not fail a build.
    // Still destructured, and still WITHOUT a `..`: that is the trip-wire
    // the comment above describes — a second gate must break the build here
    // rather than be silently skipped by this verb. `plp-s5a` removed the
    // two retired tag gates that used to be bound with `_` here.
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
    let loaded = load_config(config_path, now).map_err(format_errs)?;
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
    // Sprint A of `lists_categories_v2` (Q2-A): no `category` field. An empty
    // `plp-s5c`: no `tags` key. Same reason as `add` — `--tag` is gone,
    // so there is nothing operator-supplied to persist, and the loader's
    // auto-promotion of an untagged deny-list must not be round-tripped
    // into the file by a writer.

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
        // Sprint A of `lists_categories_v2` (Q3): wire format renamed
        // from `block` to `deny`. D15 abolishes v1 alias.
        "deny" => Ok(BlocklistBase::Deny),
        "allow" => Ok(BlocklistBase::Allow),
        // plp-s3b: the third state. Accepted here rather than left
        // CLI-unreachable — the migration and a hand-edited TOML can both
        // produce it, and a value the product writes but its own CLI
        // cannot name is a surface that reads as broken. It needs no gate:
        // an inert list permits nothing, so there is no exposure to price.
        // The validator WARNs about it at every load (P6).
        "ignore" => Ok(BlocklistBase::Ignore),
        other => bail!("unknown kind '{other}'. Valid: deny, allow, ignore"),
    }
}

fn parse_trust(s: &str) -> anyhow::Result<BlocklistTrust> {
    match s {
        "local" => Ok(BlocklistTrust::Local),
        "remote-unsigned" => Ok(BlocklistTrust::RemoteUnsigned),
        // `signed` is intentionally absent from the CLI surface — the
        // validator (S50 T2) refuses it with `TRUST_SIGNED_NOT_YET_SUPPORTED`
        // and the operator typing it through the CLI gets the same parking-
        // lot message at reload time. Refusing here surfaces it earlier
        // with a helper hint that points at the supported values.
        "signed" => bail!(
            "trust 'signed' is not supported in this version (parked S51+). Use 'local' for trusted allow-lists or 'remote-unsigned' for deny-only lists."
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
/// in the seam (audit-02) — this adapter adds none of its own.
fn persist_audit<F>(config_path: &Path, build: F, files: &[&Path])
where
    F: FnOnce(Vec<&Path>) -> AuditRecord,
{
    let files: Vec<&Path> = files.to_vec();
    persist_cli_mutation_audit(config_path, move || build(files));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn mk_master(dir: &tempfile::TempDir) -> PathBuf {
        let master = dir.path().join("config.toml");
        std::fs::write(
            &master,
            r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#,
        )
        .unwrap();
        master
    }

    fn fake_socket(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("ghost.sock")
    }

    // ── allow_direction_gates: the shared predicate ──────────────────
    //
    // The verb-level tests below exercise these rules through a real
    // file and a real validator, which is what proves them WIRED. These
    // assert the rules themselves, so a second consumer (the TUI) can
    // rely on them without re-deriving the truth table from a config
    // fixture.

    /// Consent is asked for exactly one trust level. `Local` needs none
    /// — the operator authored the file. `Signed` is refused outright by
    /// `parse_trust` and by the validator, and telling that operator to
    /// "declare consent" would be advice that does not work.
    #[test]
    fn consent_gate_fires_only_on_remote_unsigned() {
        for (trust, want) in [
            (BlocklistTrust::RemoteUnsigned, true),
            (BlocklistTrust::Local, false),
            (BlocklistTrust::Signed, false),
        ] {
            let g = allow_direction_gates(trust, false, false);
            assert_eq!(
                g.needs_consent,
                want,
                "{trust:?} should {}ask for consent",
                if want { "" } else { "not " }
            );
        }
    }

    /// Either declaration satisfies it — the file's, or this
    /// invocation's. A list set up from the CLI and later edited must
    /// not be asked again for a risk its own TOML already records.
    #[test]
    fn either_declaration_satisfies_the_consent_gate() {
        let base = || allow_direction_gates(BlocklistTrust::RemoteUnsigned, false, false);
        assert!(base().needs_consent, "neither declared → ask");

        for (in_file, now) in [(true, false), (false, true), (true, true)] {
            assert!(
                !allow_direction_gates(BlocklistTrust::RemoteUnsigned, in_file, now).needs_consent,
                "in_file={in_file} now={now} should satisfy the gate"
            );
        }
    }

    /// **This pin outlived the gate on purpose, and the asymmetry is
    /// deliberate.** `plp-s5f` removed the cross-file byte-pin on this
    /// const from `tests/frozen_strings_entity_contracts.rs`, because a
    /// frozen *contract* announces a live promise and this refusal has been
    /// unreachable since the plp cutover (`needs_non_system_tag: false`).
    ///
    /// The const itself is kept as record — the argument a future reader
    /// needs before restoring the gate — and a record is worth exactly its
    /// wording, so the wording keeps a pin. What changed is which claim the
    /// pin makes: not "five surfaces say this today" but "this is what
    /// warden said, verbatim, and it must not drift while nobody is
    /// reading it".
    ///
    /// Original note: the refusal an operator reads is the whole product of
    /// this gate; three verbs and both TUI paths routed through it, so a
    /// reword in one place must not silently become five different answers.
    #[test]
    fn tmc_allow_list_cannot_use_system_tag_const_pinned() {
        assert_eq!(
            ALLOW_LIST_CANNOT_USE_SYSTEM_TAG,
            "an allow-list cannot use the \"uncategorized\" tag: every device warden has not been told about carries it by default, so this would permit the list's domains for every unconfigured device on the network — the widest exposure available, reached through the rule that exists to narrow it. Choose a tag that names who the exemption is for."
        );
    }

    #[tokio::test]
    async fn add_blocklist_valid_url() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        run_add(
            &master,
            &sock,
            "privacy-ads",
            Some("Privacy: ads"),
            "https://lists.purge.cc/privacy/ads.txt",
            Some("domains"),
            None,
            None,
            None,
            None,
            &[],
            true,
            None,
        )
        .await
        .unwrap();
        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        assert_eq!(loaded.config.blocklists.len(), 1);
    }

    // ── the id gate is what makes the whole-row write safe ──────────
    //
    // `upsert_id_keyed` REPLACES the row it matches (`*item = entry`),
    // and both writers here hand it a table built from scratch. That is
    // only safe while neither can reach an id that already exists — so
    // the refusal is not a nicety about duplicate ids, it is the reason
    // no field can be silently reset to its serde default. Losing it
    // turns either verb into a partial update that keeps exactly the
    // keys the caller happened to pass.

    /// The URL is deliberately different on the second call: the
    /// canonical-URL gate sits next to the id gate and would refuse
    /// first, which would leave the id gate untested.
    #[tokio::test]
    async fn add_refuses_a_taken_id_and_leaves_the_row_intact() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        run_add(
            &master,
            &sock,
            "privacy-ads",
            Some("Privacy: ads"),
            "https://lists.purge.cc/ads.txt",
            Some("domains"),
            Some(6),
            Some(1_234_567),
            None,
            None,
            &[],
            true,
            None,
        )
        .await
        .expect("the first add creates the row");

        let err = add_list_result(&master, &sock, "privacy-ads", "https://other.example/x.txt")
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("already exists"),
            "expected the id refusal, got: {err}",
        );

        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        assert_eq!(loaded.config.blocklists.len(), 1);
        let b = &loaded.config.blocklists[0];
        // The second call passed none of these. Had the write gone
        // through, the row would carry the defaults instead.
        assert_eq!(b.url, "https://lists.purge.cc/ads.txt");
        assert_eq!(b.display_name, "Privacy: ads");
        assert_eq!(b.update_interval_hours, 6);
        assert_eq!(b.max_entries, 1_234_567);
    }

    /// The same gate on the other whole-row writer.
    #[tokio::test]
    async fn import_local_refuses_a_taken_id_and_leaves_the_row_intact() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        let src = dir.path().join("seed.txt");
        std::fs::write(&src, "bad.example\n").unwrap();
        run_import_local(&master, &sock, &src, "mycompany", "deny", None, None)
            .await
            .expect("the first import creates the row");
        let before = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        let before = before.config.blocklists[0].clone();

        let other = dir.path().join("other.txt");
        std::fs::write(&other, "worse.example\n").unwrap();
        let err = run_import_local(&master, &sock, &other, "mycompany", "allow", None, None)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("already exists"),
            "expected the id refusal, got: {err}",
        );

        let after = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        assert_eq!(after.config.blocklists.len(), 1);
        let after = &after.config.blocklists[0];
        assert_eq!(after.url, before.url);
        assert_eq!(
            after.base, before.base,
            "a refused import must not flip the direction"
        );
        assert_eq!(after.trust, before.trust);
    }

    // ── tag_model_consolidation §3.2 — the add / set-url dedup gates ──

    /// D3 exactly as it happened on the live box: `privacy-ads` and
    /// `ads` both point at `lists.purge.cc/ads.txt`. The byte-exact gate
    /// this replaces let the second one in whenever the two spellings
    /// differed cosmetically.
    #[tokio::test]
    async fn tmc_add_refuses_a_canonically_duplicate_url() {
        for twin in [
            "https://lists.purge.cc/ads.txt/", // trailing slash
            "https://Lists.Purge.CC/ads.txt",  // host case
            "https://lists.purge.cc:443/ads.txt", // default port
                                               // An upper-case SCHEME is deliberately absent: the
                                               // url-shape gate above the dedup gate is a
                                               // case-sensitive `starts_with("https://")`, so
                                               // `HTTPS://…` is refused as a malformed URL before
                                               // dedup ever runs — and the validator applies the
                                               // same check, so no config can contain one either.
                                               // `canonical_url_key` still lowercases the scheme
                                               // (RFC 3986 says it is case-insensitive); that arm
                                               // is exercised by its own unit tests, not here.
        ] {
            let dir = tempfile::tempdir().unwrap();
            let master = mk_master(&dir);
            let sock = fake_socket(&dir);
            add_list(
                &master,
                &sock,
                "privacy-ads",
                "https://lists.purge.cc/ads.txt",
            )
            .await;

            let err = add_list_result(&master, &sock, "ads", twin)
                .await
                .unwrap_err();
            assert!(
                err.to_string().contains("privacy-ads"),
                "the refusal must name the list that already owns the URL, got: {err}",
            );
            let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
            assert_eq!(
                loaded.config.blocklists.len(),
                1,
                "{twin} must not have been added",
            );
        }
    }

    /// Pins the reasoning behind the omitted case above: an upper-case
    /// scheme never reaches the dedup gate because the url-shape check
    /// refuses it first. If that check is ever made case-insensitive,
    /// this test fails and the dedup case becomes reachable.
    #[tokio::test]
    async fn tmc_add_refuses_an_uppercase_scheme_before_reaching_dedup() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        let err = add_list_result(&master, &sock, "ads", "HTTPS://lists.purge.cc/ads.txt")
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("must start with http://"),
            "expected the url-shape refusal, got: {err}",
        );
    }

    /// The gate must not become "refuse anything similar" — a different
    /// path on the same host is a different source.
    #[tokio::test]
    async fn tmc_add_still_accepts_a_genuinely_different_url() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        add_list(&master, &sock, "ads", "https://lists.purge.cc/ads.txt").await;
        add_list(
            &master,
            &sock,
            "tracking",
            "https://lists.purge.cc/tracking.txt",
        )
        .await;
        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        assert_eq!(loaded.config.blocklists.len(), 2);
    }

    /// `set url` is the third door onto the same collision: pointing an
    /// existing list at a cosmetic variant of another list's URL would
    /// manufacture the shared cache file `add` refuses.
    #[tokio::test]
    async fn tmc_set_url_refuses_a_canonical_duplicate_of_another_list() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        add_list(&master, &sock, "ads", "https://lists.purge.cc/ads.txt").await;
        add_list(
            &master,
            &sock,
            "tracking",
            "https://lists.purge.cc/tracking.txt",
        )
        .await;

        let err = run_set(
            &master,
            &sock,
            "tracking",
            "url",
            "https://lists.purge.cc/ads.txt/",
            None,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("ads"), "{err}");

        // Re-pointing a list at its OWN url (cosmetic variant) is not a
        // duplicate — it must still be allowed.
        run_set(
            &master,
            &sock,
            "tracking",
            "url",
            "https://lists.purge.cc/tracking.txt/",
            None,
        )
        .await
        .expect("a list may be re-pointed at its own source");
    }

    async fn add_list(master: &Path, sock: &Path, id: &str, url: &str) {
        add_list_result(master, sock, id, url)
            .await
            .unwrap_or_else(|e| panic!("adding {id} should succeed: {e}"));
    }

    async fn add_list_result(
        master: &Path,
        sock: &Path,
        id: &str,
        url: &str,
    ) -> anyhow::Result<()> {
        run_add(
            master,
            sock,
            id,
            None,
            url,
            None,
            None,
            None,
            None,
            None,
            &[],
            true, // skip the HEAD probe — these URLs are not reachable from a test
            None,
        )
        .await
    }

    #[tokio::test]
    async fn add_blocklist_rejects_bad_url() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        let err = run_add(
            &master,
            &sock,
            "x",
            None,
            "not-a-url",
            None,
            None,
            None,
            None,
            None,
            &[],
            true,
            None,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("http"));
    }

    // ── Sprint C T5 of `lists_categories_v2`: --tag + --skip-head-check ──

    /// T5: dedup gate refuses a second list with the same URL even
    /// when the operator picks a fresh id. Surface message names the
    /// existing id so the operator knows which entry already covers it.
    #[tokio::test]
    async fn lc2_c_t5_add_refuses_duplicate_url_naming_existing_id() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        let url = "https://example.com/dedup.txt";
        run_add(
            &master,
            &sock,
            "first",
            None,
            url,
            None,
            None,
            None,
            None,
            None,
            &[],
            true,
            None,
        )
        .await
        .unwrap();
        let err = run_add(
            &master,
            &sock,
            "second",
            None,
            url,
            None,
            None,
            None,
            None,
            None,
            &[],
            true,
            None,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("already added as \"first\""));
    }

    /// T5: empty tags = unwritten field. The validator's auto-promote
    /// pass takes over at reload time and pins `base = deny` to
    /// `["uncategorized"]` (D2 keeps `base = allow` empty). Here we
    /// confirm the pre-validator on-disk shape: no `tags = [...]` line
    /// in any of the TOML files under the master's parent dir.
    #[tokio::test]
    async fn lc2_c_t5_add_with_no_tags_does_not_emit_tags_array() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        run_add(
            &master,
            &sock,
            "no-tags",
            None,
            "https://example.com/no-tags.txt",
            None,
            None,
            None,
            None,
            None,
            &[],
            true,
            None,
        )
        .await
        .unwrap();
        // Walk every TOML under the dir tree; locate the entry's
        // segment (regardless of whether it landed in master or in a
        // sharded `blocklists.d/*.toml` file) and confirm no explicit
        // `tags` array is written.
        fn read_all_toml(root: &std::path::Path, out: &mut Vec<String>) {
            if let Ok(rd) = std::fs::read_dir(root) {
                for e in rd.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        read_all_toml(&p, out);
                    } else if p.extension().and_then(|s| s.to_str()) == Some("toml") {
                        if let Ok(s) = std::fs::read_to_string(&p) {
                            out.push(s);
                        }
                    }
                }
            }
        }
        let mut all_toml: Vec<String> = Vec::new();
        read_all_toml(master.parent().unwrap(), &mut all_toml);
        let segment = all_toml
            .iter()
            .flat_map(|raw| raw.split("[[blocklists]]"))
            .find(|seg| seg.contains("\"no-tags\""))
            .map(|s| s.to_string())
            .expect("new entry must exist on disk somewhere");
        assert!(
            !segment.contains("tags = ["),
            "did not expect tags array in raw TOML, got:\n{segment}"
        );
    }

    #[tokio::test]
    async fn add_blocklist_rejects_bad_format() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        let err = run_add(
            &master,
            &sock,
            "x",
            None,
            "https://example.com/x.txt",
            Some("bogus"),
            None,
            None,
            None,
            None,
            &[],
            true,
            None,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("unknown format"));
    }

    // Sprint B T2 (rewireato — drop with justification): the pre-v2
    // `remove_blocklist_referenced_by_profile_fails_with_rule_dangling_ref`
    // test pinned the SN3 dangling-ref refusal when removing a blocklist
    // referenced by `profile.blocklists`. That field is gone in v2 — a
    // blocklist's lifecycle is now decoupled from any profile (lists are
    // tagged, profiles inherit tags). Sprint C reintroduces an equivalent
    // operator-facing check for the new mutation surface
    // (`warden blocklist tag remove <id> <tag>` may want to refuse if it
    // would leave a profile with no effective tags), but that lives on
    // the new tag-mutation CLI, not the legacy `blocklists remove` path.
    // The companion `remove_blocklist_without_refs_succeeds_without_cascade`
    // test below preserves the no-references happy path.
    //
    // Sprint B T2 (rewireato — drop with justification): the pre-v2
    // `remove_blocklist_with_cascade_removes_id_from_every_profile_then_drops_blocklist`
    // test pinned the cascade behaviour for the same `profile.blocklists`
    // field. Same rationale — `profile.blocklists` no longer exists, so
    // there is nothing to cascade. Sprint C's tag-removal CLI will
    // introduce its own cascade semantics if needed.

    #[tokio::test]
    async fn remove_blocklist_without_refs_succeeds_without_cascade() {
        // Belt-and-braces: the no-references path still works (cascade
        // = false) so we don't regress the post-S33 baseline behaviour.
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        run_add(
            &master,
            &sock,
            "privacy-ads",
            None,
            "https://example.com/x.txt",
            None,
            None,
            None,
            None,
            None,
            &[],
            true,
            None,
        )
        .await
        .unwrap();
        run_remove(&master, &sock, "privacy-ads", None)
            .await
            .unwrap();
        let loaded =
            crate::config::loader::load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        assert!(loaded.config.blocklists.is_empty());
    }

    #[tokio::test]
    async fn remove_absent_blocklist_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        // verbs-02: remove of an absent blocklist returns Ok (exit 0) via the
        // CLI wrapper's pre-check; run_remove_silent keeps its hard-error
        // contract for the TUI seat.
        assert!(run_remove(&master, &sock, "ghost", None).await.is_ok());
    }

    #[tokio::test]
    async fn set_enabled_field() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        run_add(
            &master,
            &sock,
            "privacy-ads",
            None,
            "https://example.com/x.txt",
            None,
            None,
            None,
            Some(true),
            None,
            &[],
            true,
            None,
        )
        .await
        .unwrap();
        run_set(&master, &sock, "privacy-ads", "enabled", "false", None)
            .await
            .unwrap();
        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        assert!(!loaded.config.blocklists[0].enabled);
    }

    #[tokio::test]
    async fn set_format_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        run_add(
            &master,
            &sock,
            "privacy-ads",
            None,
            "https://example.com/x.txt",
            Some("domains"),
            None,
            None,
            None,
            None,
            &[],
            true,
            None,
        )
        .await
        .unwrap();
        run_set(&master, &sock, "privacy-ads", "format", "adguard", None)
            .await
            .unwrap();
        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        assert_eq!(loaded.config.blocklists[0].format, BlocklistFormat::Adguard);
    }

    // ── Sprint 36 HR2: hot-reload wiring ───────────────────────────────

    // ── S50 T3: per-list mutation verbs ────────────────────────────────

    // BLOCKLIST_SET_CATEGORY_OK pinned test removed — Sprint A of
    // `lists_categories_v2` (Q2-A) deleted the const along with the
    // Category entity. Sprint C reintroduces equivalent for tags.

    #[test]
    fn s50_t3_blocklist_set_kind_const_pinned() {
        assert_eq!(
            BLOCKLIST_SET_KIND_OK,
            "Blocklist '{id}' kind set to {kind}."
        );
    }

    #[test]
    fn s50_t3_blocklist_set_trust_const_pinned_decision_outside_doc() {
        // §9 of the design doc does not explicitly list
        // BLOCKLIST_SET_TRUST_OK; the orchestrator kickoff flagged
        // the ambiguity. T3 chose the sibling-coining path documented
        // on the const itself (audit `action` tag stays distinct).
        assert_eq!(
            BLOCKLIST_SET_TRUST_OK,
            "Blocklist '{id}' trust set to {trust}."
        );
    }

    /// The refusal an operator hits when they try to flip a list's
    /// direction through the generic field setter. Frozen because it is
    /// the only place warden gets to say "the verb you want exists" —
    /// before this, the message listed the settable fields, `kind` was
    /// not among them, and the honest reading was "warden cannot do
    /// this".
    #[test]
    fn cli_surface_blocklist_set_unknown_field_const_pinned() {
        assert_eq!(
            BLOCKLIST_SET_UNKNOWN_FIELD,
            "unknown field: {field}. Valid: display_name, url, format, \
             update_interval_hours, max_entries, enabled, auth_token_ref. Direction and \
             provenance are not set here — use: warden blocklist set-kind <id> \
             <deny|allow> / warden blocklist set-trust <id> <local|remote-unsigned>. Both \
             accept --accept-unsigned-allow, which declares consent for a remote \
             allow-list."
        );
    }

    #[test]
    fn cli_surface_format_set_unknown_field_substitutes_field() {
        let s = format_blocklist_set_unknown_field("kind");
        assert!(s.starts_with("unknown field: kind."), "{s}");
        assert!(!s.contains("{field}"), "{s}");
    }

    /// The emitter, not just the const: `blocklist set <id> kind allow`
    /// must reach the operator with the two dedicated verbs named.
    #[test]
    fn cli_surface_set_kind_through_generic_setter_names_the_dedicated_verbs() {
        let mut entry = Value::Table(toml::map::Map::new());
        let dir = tempfile::tempdir().unwrap();
        let err =
            apply_blocklist_field(&mut entry, "kind", "allow", &dir.path().join("config.toml"))
                .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("warden blocklist set-kind"), "{msg}");
        assert!(msg.contains("warden blocklist set-trust"), "{msg}");
        assert!(msg.contains("--accept-unsigned-allow"), "{msg}");
    }

    #[test]
    fn s50_t3_blocklist_import_local_const_pinned() {
        // Sprint A of lists_categories_v2 (Q2-A): the `{cat}` slot is
        // gone. Sprint C extends with `{tags}` once the picker lands.
        assert_eq!(
            BLOCKLIST_IMPORT_LOCAL_OK,
            "Imported '{path}' as blocklist '{id}' (kind={kind}, {n} entries)."
        );
    }

    // s50_t3_format_set_category_substitutes_id_and_cat removed:
    // BLOCKLIST_SET_CATEGORY_OK + format_blocklist_set_category_ok
    // deleted by Sprint A of lists_categories_v2 (Q2-A).

    #[test]
    fn s50_t3_format_set_kind_substitutes_id_and_kind() {
        let s = format_blocklist_set_kind_ok("priv-ads", "allow");
        assert_eq!(s, "Blocklist 'priv-ads' kind set to allow.");
    }

    #[test]
    fn s50_t3_format_set_trust_substitutes_id_and_trust() {
        let s = format_blocklist_set_trust_ok("priv-ads", "local");
        assert_eq!(s, "Blocklist 'priv-ads' trust set to local.");
    }

    #[test]
    fn s50_t3_format_import_local_substitutes_all_fields() {
        let s = format_blocklist_import_local_ok("/tmp/whitelist.txt", "mycompany", "allow", 12);
        assert!(s.contains("'/tmp/whitelist.txt'"), "got: {s}");
        assert!(s.contains("'mycompany'"), "got: {s}");
        assert!(s.contains("kind=allow"), "got: {s}");
        assert!(s.contains("12 entries"), "got: {s}");
    }

    #[test]
    fn s50_t3_parse_kind_accepts_deny_and_allow_only() {
        // Sprint A of lists_categories_v2 (Q3): wire format renamed
        // `block` → `deny`. D15 abolishes v1 alias.
        assert_eq!(parse_kind("deny").unwrap(), BlocklistBase::Deny);
        assert_eq!(parse_kind("allow").unwrap(), BlocklistBase::Allow);
        assert!(parse_kind("forward").is_err());
    }

    #[test]
    fn s50_t3_parse_trust_refuses_signed_with_helpful_hint() {
        assert_eq!(parse_trust("local").unwrap(), BlocklistTrust::Local);
        assert_eq!(
            parse_trust("remote-unsigned").unwrap(),
            BlocklistTrust::RemoteUnsigned
        );
        let err = parse_trust("signed").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("signed"), "got: {msg}");
        assert!(
            msg.contains("local") || msg.contains("remote-unsigned"),
            "got: {msg}"
        );
    }

    #[test]
    fn s50_t3_autodetect_format_picks_adguard_for_pipe_pipe_lines() {
        assert_eq!(
            autodetect_format("||ads.example.com^\n||trk.example.com^\n"),
            BlocklistFormat::Adguard
        );
    }

    #[test]
    fn s50_t3_autodetect_format_picks_hosts_for_zero_zero_zero_zero_lines() {
        assert_eq!(
            autodetect_format("0.0.0.0 ads.example\n0.0.0.0 trk.example\n"),
            BlocklistFormat::Hosts
        );
    }

    #[test]
    fn s50_t3_autodetect_format_defaults_to_domains() {
        assert_eq!(
            autodetect_format("good.example\nmycompany.example\n"),
            BlocklistFormat::Domains
        );
    }

    #[test]
    fn s50_t3_count_entries_skips_blank_and_comment_lines() {
        let raw = "# header\n\nfoo\nbar\n# trailer\n";
        assert_eq!(count_entries(raw, BlocklistFormat::Domains), 2);
    }

    // `s50_t3_set_category_writes_field_and_loads_back` deleted in
    // `tag_model_consolidation` §3.4: its `#[ignore]` reason said
    // "Sprint C reintroduces the equivalent", and Sprint C shipped it —
    // `warden blocklist tag add|remove`, covered by the
    // `lc2_c_t7_grp2_tag_*` tests below. An ignored test whose reason
    // has expired is a permanently-skipped test nobody will delete
    // later.

    // ── cli-surface: flipping direction on an existing list ───────────

    /// Helper: a remote-unsigned deny-list carrying one tag, created the
    /// way an operator would. The tag matters — without it the
    /// untagged-allow gate fires first and masks whatever the test is
    /// actually about.
    async fn add_tagged_remote_deny(master: &std::path::Path, sock: &std::path::Path, id: &str) {
        run_add(
            master,
            sock,
            id,
            None,
            &format!("https://example.com/{id}.txt"),
            None,
            None,
            None,
            None,
            None,
            &[],
            true,
            None,
        )
        .await
        .unwrap();
    }

    /// Assert `--accept-unsigned-allow` exists on `blocklist <verb>`
    /// with the frozen spelling and the frozen action. The names are
    /// CONTRACT §3, so a rename here breaks other surfaces, not just
    /// this one.
    fn assert_verb_carries_ack_flag(verb: &str) {
        use clap::CommandFactory;
        let cmd = crate::cli::Cli::command();
        let sub = cmd
            .find_subcommand("blocklist")
            .expect("`warden blocklist` must exist")
            .clone()
            .find_subcommand(verb)
            .unwrap_or_else(|| panic!("`warden blocklist {verb}` must exist"))
            .clone();
        let ack = sub
            .get_arguments()
            .find(|a| a.get_id() == "accept_unsigned_allow")
            .unwrap_or_else(|| panic!("{verb} must offer --accept-unsigned-allow"));
        assert_eq!(ack.get_long(), Some("accept-unsigned-allow"));
        assert!(matches!(ack.get_action(), clap::ArgAction::SetTrue));
    }

    #[test]
    fn cli_surface_set_kind_carries_the_ack_flag() {
        assert_verb_carries_ack_flag("set-kind");
    }

    // ── cli-surface: the read surface (DoD 6) ─────────────────────────

    /// Built from TOML rather than a struct literal: `Blocklist` gains
    /// fields, and a literal here would have to be repaired by every
    /// unrelated schema change. Deserialising also exercises the same
    /// defaults an operator's file gets.
    fn bl(kind: &str, trust: &str, ack: bool) -> crate::config::schema::Blocklist {
        toml::from_str(&format!(
            r#"
id = "svc"
display_name = "Service"
url = "https://example.com/svc.txt"
base = "{kind}"
trust = "{trust}"
accept_unsigned_allow = {ack}
"#
        ))
        .expect("fixture must deserialise")
    }

    #[test]
    fn cli_surface_show_always_states_the_consent() {
        for (kind, trust, ack) in [
            ("deny", "remote-unsigned", false),
            ("allow", "local", false),
            ("allow", "remote-unsigned", true),
        ] {
            let lines = format_show_consent(&bl(kind, trust, ack));
            assert_eq!(
                lines[0],
                format!("accept_unsigned_allow:  {ack}"),
                "{kind}/{trust}/{ack}"
            );
        }
    }

    /// `true` on a list where the field decides who may unblock domains
    /// must not read like `true` on a list where it does nothing.
    #[test]
    fn cli_surface_show_distinguishes_a_load_bearing_consent_from_an_inert_one() {
        let load_bearing = format_show_consent(&bl("allow", "remote-unsigned", true));
        assert_eq!(load_bearing.len(), 2);
        assert!(load_bearing[1].contains("load-bearing"), "{load_bearing:?}");

        let inert = format_show_consent(&bl("deny", "remote-unsigned", true));
        assert_eq!(inert.len(), 2);
        assert!(inert[1].contains("no effect on this list"), "{inert:?}");

        // Nothing declared, nothing to explain.
        assert_eq!(format_show_consent(&bl("allow", "local", false)).len(), 1);
    }

    /// DoD 6, the table half: without `kind` on the row, a deny-list and
    /// an allow-list render identically and the operator has to run
    /// `show` once per list to find out which is which.
    #[test]
    fn cli_surface_list_row_shows_the_direction() {
        assert!(
            format_list_row(&bl("allow", "remote-unsigned", true)).contains("kind=allow"),
            "{}",
            format_list_row(&bl("allow", "remote-unsigned", true))
        );
        assert!(
            format_list_row(&bl("deny", "remote-unsigned", false)).contains("kind=deny"),
            "{}",
            format_list_row(&bl("deny", "remote-unsigned", false))
        );
    }

    #[test]
    fn cli_surface_set_trust_carries_the_ack_flag() {
        assert_verb_carries_ack_flag("set-trust");
    }

    /// Helper: a local, tagged **allow**-list — the shape an operator
    /// gets from `blocklist import-local --kind allow`, and the starting
    /// point of the transition that DoD 5 is about.
    async fn add_local_tagged_allow(master: &std::path::Path, sock: &std::path::Path, id: &str) {
        let src = master.parent().unwrap().join(format!("{id}-seed.txt"));
        std::fs::write(&src, "permitted.example\n").unwrap();
        run_import_local(master, sock, &src, id, "allow", None, None)
            .await
            .unwrap();
    }

    /// DoD 5 — the transition everybody forgets. `set-trust` changes no
    /// `kind`, so it looks like it has nothing to do with allow-lists.
    /// But taking an allow-list from `local` to `remote-unsigned` is
    /// exactly the moment a file the operator wrote becomes a
    /// subscription somebody else edits — and without this gate the
    /// command is accepted, the config is written, and the NEXT reload
    /// refuses it. The operator is then looking at a daemon that will
    /// not start because of a command warden told them had worked.
    #[tokio::test]
    async fn cli_surface_set_trust_remote_on_an_allow_list_without_ack_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        add_local_tagged_allow(&master, &sock, "svc-b").await;
        let err = run_set_trust(&master, &sock, "svc-b", "remote-unsigned", false, None)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(ACCEPT_UNSIGNED_ALLOW_FLAG_HINT),
            "must name the flag that unblocks it, got:\n{msg}"
        );
        assert!(
            !msg.contains("nothing written"),
            "pre-flight, not a post-write revert:\n{msg}"
        );
        // And the list is untouched — still local, still loading.
        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        assert_eq!(loaded.config.blocklists[0].trust, BlocklistTrust::Local);
    }

    /// DoD 5, happy path: same transition, consent declared, and the
    /// config that lands still loads.
    #[tokio::test]
    async fn cli_surface_set_trust_remote_on_an_allow_list_with_ack_persists() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        add_local_tagged_allow(&master, &sock, "svc-b").await;
        run_set_trust(&master, &sock, "svc-b", "remote-unsigned", true, None)
            .await
            .unwrap();
        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        let b = &loaded.config.blocklists[0];
        assert_eq!(b.trust, BlocklistTrust::RemoteUnsigned);
        assert_eq!(b.base, BlocklistBase::Allow);
        assert!(b.accept_unsigned_allow);
    }

    /// The gate must not spread. A deny-list going remote carries no
    /// unblocking power and is the ordinary case for every list warden
    /// ships — demanding consent there would be a new refusal on a path
    /// that never needed one.
    #[tokio::test]
    async fn cli_surface_set_trust_remote_on_a_deny_list_needs_no_ack() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        let src = dir.path().join("seed.txt");
        std::fs::write(&src, "bad.example\n").unwrap();
        run_import_local(&master, &sock, &src, "svc-a", "deny", None, None)
            .await
            .unwrap();
        run_set_trust(&master, &sock, "svc-a", "remote-unsigned", false, None)
            .await
            .expect("a deny-list may go remote with nothing to declare");
    }

    /// DoD 4, one direction: an existing remote list becomes an
    /// allow-list, consent declared on the same command line, and the
    /// consent is persisted so the next reload does not refuse it.
    #[tokio::test]
    async fn cli_surface_set_kind_allow_with_ack_persists_the_consent() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        add_tagged_remote_deny(&master, &sock, "svc-b").await;
        run_set_kind_with_ack(&master, &sock, "svc-b", "allow", true, None)
            .await
            .unwrap();
        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        let b = &loaded.config.blocklists[0];
        assert_eq!(b.base, BlocklistBase::Allow);
        assert!(
            b.accept_unsigned_allow,
            "the flag must land in the file, or the next reload refuses the config \
             the CLI just accepted"
        );
    }

    /// DoD 4, the other direction: back to deny, and the flip is not
    /// blocked by anything the allow side needed.
    #[tokio::test]
    async fn cli_surface_set_kind_flips_back_to_deny() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        add_tagged_remote_deny(&master, &sock, "svc-b").await;
        run_set_kind_with_ack(&master, &sock, "svc-b", "allow", true, None)
            .await
            .unwrap();
        run_set_kind(&master, &sock, "svc-b", "deny", None)
            .await
            .unwrap();
        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        assert_eq!(loaded.config.blocklists[0].base, BlocklistBase::Deny);
    }

    /// Consent already recorded on the list = no need to re-declare it
    /// on every later flip. Otherwise `set-kind deny` then `set-kind
    /// allow` would demand the flag a second time for a risk the
    /// operator's own file already carries.
    #[tokio::test]
    async fn cli_surface_set_kind_allow_needs_no_flag_when_the_file_already_consents() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        add_tagged_remote_deny(&master, &sock, "svc-b").await;
        run_set_kind_with_ack(&master, &sock, "svc-b", "allow", true, None)
            .await
            .unwrap();
        run_set_kind(&master, &sock, "svc-b", "deny", None)
            .await
            .unwrap();
        run_set_kind(&master, &sock, "svc-b", "allow", None)
            .await
            .expect("consent is already on the list");
    }

    /// Brief point 4: the untagged-allow bail used to be gated on
    /// `trust == local`, so on a remote list it never ran and the write
    /// went through to a validator rollback. Now that remote allow-lists
    /// are the normal case, that branch is the main road — and an
    /// untagged one would land mute.
    #[tokio::test]
    async fn cli_surface_untagged_allow_on_remote_trust_needs_only_consent_now() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        run_add(
            &master,
            &sock,
            "svc-b",
            None,
            "https://example.com/svc-b.txt",
            None,
            None,
            None,
            None,
            None,
            &[],
            true,
            None,
        )
        .await
        .unwrap();
        // WITHOUT consent: still refused, and by the consent gate. The
        // consent gate did not move — whoever controls a remote URL adds
        // domains at every refresh, which is a third-party risk rather than
        // an operator declaration.
        let err = run_set_kind(&master, &sock, "svc-b", "allow", None)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("accept_unsigned_allow"),
            "the surviving refusal must be the CONSENT one, got: {err}"
        );
        assert!(
            !err.to_string().contains("--tag"),
            "the tag gate is retired and must not be the reason: {err}"
        );
        // WITH consent: accepted, untagged and all.
        run_set_kind_with_ack(&master, &sock, "svc-b", "allow", true, None)
            .await
            .expect("consent declared, and the tag gate is retired");
    }

    #[tokio::test]
    async fn s50_t3_set_kind_to_allow_with_remote_unsigned_is_rejected_and_reverts() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        run_add(
            &master,
            &sock,
            "x",
            None,
            "https://example.com/x.txt",
            None,
            None,
            None,
            None,
            None,
            &[],
            true,
            None,
        )
        .await
        .unwrap();
        let err = run_set_kind(&master, &sock, "x", "allow", None)
            .await
            .unwrap_err();
        assert!(err.to_string().to_ascii_lowercase().contains("trust"));
        // Loader must read back the original kind=block — the file
        // was reverted by validate_or_revert.
        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        assert_eq!(loaded.config.blocklists[0].base, BlocklistBase::Deny);
    }

    #[tokio::test]
    async fn s50_t3_set_trust_local_then_set_kind_allow_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        run_add(
            &master,
            &sock,
            "trusted",
            None,
            "https://example.com/x.txt",
            None,
            None,
            None,
            None,
            None,
            // Retired `_tags` argument — see `run_add`'s doc comment.
            //
            // The comment that stood here said the flip to `allow`
            // "requires the list to carry a tag in the file", from
            // `tag_model_consolidation` §3.3. That premise died at the
            // `plp-s3` cutover: `allow_direction_gates` has answered
            // `needs_tag = false` ever since, and `plp-s5c` removed
            // `--tag` outright, so there is no longer any way for this
            // setup to satisfy the rule it described. The property under
            // test — local trust makes `allow` legal — is untouched, and
            // is now tested without the tag it never actually needed.
            &[],
            true,
            None,
        )
        .await
        .unwrap();
        run_set_trust(&master, &sock, "trusted", "local", false, None)
            .await
            .unwrap();
        run_set_kind(&master, &sock, "trusted", "allow", None)
            .await
            .unwrap();
        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        assert_eq!(loaded.config.blocklists[0].trust, BlocklistTrust::Local);
        assert_eq!(loaded.config.blocklists[0].base, BlocklistBase::Allow);
    }

    /// The flip stays legal for a tagged list — the gate must refuse
    /// only the inert case, not `allow` in general.
    #[tokio::test]
    async fn tmc_set_kind_allow_is_allowed_when_the_list_carries_a_tag() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        let src = dir.path().join("seed.txt");
        std::fs::write(&src, "good.example\n").unwrap();
        run_import_local(&master, &sock, &src, "x", "deny", None, None)
            .await
            .unwrap();
        run_set_kind(&master, &sock, "x", "allow", None)
            .await
            .expect("a tagged list may become an allow-list");
        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        assert_eq!(loaded.config.blocklists[0].base, BlocklistBase::Allow);
    }

    #[tokio::test]
    async fn s50_t3_set_trust_signed_refused_with_parking_hint() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        run_add(
            &master,
            &sock,
            "x",
            None,
            "https://example.com/x.txt",
            None,
            None,
            None,
            None,
            None,
            &[],
            true,
            None,
        )
        .await
        .unwrap();
        let err = run_set_trust(&master, &sock, "x", "signed", false, None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("signed"));
    }

    #[tokio::test]
    async fn s50_t3_import_local_copies_file_and_registers_blocklist() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        let src = dir.path().join("seed.txt");
        std::fs::write(&src, "good.example\nmycompany.example\n").unwrap();
        // `tag_model_consolidation` §3.3: an allow-list must be tagged,
        // otherwise it installs and filters nothing.
        run_import_local(&master, &sock, &src, "mycompany", "allow", None, None)
            .await
            .unwrap();
        let dest = master.parent().unwrap().join("lists").join("mycompany.txt");
        assert!(dest.exists());
        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        let imported = loaded
            .config
            .blocklists
            .iter()
            .find(|b| b.id.as_str() == "mycompany")
            .unwrap();
        assert_eq!(imported.base, BlocklistBase::Allow);
        assert_eq!(imported.trust, BlocklistTrust::Local);
        // The `--tag` assertion that stood here left with the flag in
        // `plp-s5c`. What it guaranteed — that an operator-supplied tag
        // reaches the file — has no operator-supplied tag to guarantee
        // any more. The rest of this test is untouched and is the part
        // that was ever about `import-local`: the file is copied into the
        // managed directory and the entry lands with the direction and
        // trust the verb promises.
    }

    #[tokio::test]
    async fn s50_t3_import_local_refuses_missing_source() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        let ghost = dir.path().join("does-not-exist.txt");
        let err = run_import_local(&master, &sock, &ghost, "x", "deny", None, None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }

    // ── tag_model_consolidation §3.3 — close the inert-allow-list door

    /// INVERTED by `plp-s4` F18. This test used to assert that an untagged
    /// allow import is refused, and it was correct while tag intersection
    /// decided which lists reached which clients: an untagged allow-list
    /// permitted nothing, so refusing it saved the operator from installing
    /// an inert list.
    ///
    /// `plp-s3` retired that premise inside `allow_direction_gates` — a
    /// list's direction now reaches every profile that does not override it,
    /// tagged or not — but this verb kept a private copy of the check and
    /// went on refusing. Three verbs accepted what the fourth rejected, and
    /// the `--tag` its message prescribed is refused by `warden blocklist
    /// tag`, retired in the same sprint. The operator's only route to an
    /// allow-list whose file they own was closed by a refusal that could not
    /// be satisfied in its own terms.
    ///
    /// The assertion now runs the other way. Left INVERTED rather than
    /// deleted because a deleted test proves nothing about the direction the
    /// behaviour moved in, and this one moved in the direction that a future
    /// reader would most plausibly "fix" back.
    #[tokio::test]
    async fn plp_import_local_accepts_an_untagged_allow_list() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        let src = dir.path().join("seed.txt");
        std::fs::write(&src, "good.example\n").unwrap();
        run_import_local(&master, &sock, &src, "mycompany", "allow", None, None)
            .await
            .expect("an untagged allow-list is legal since the tag gates were retired");
        assert!(
            master
                .parent()
                .unwrap()
                .join("lists")
                .join("mycompany.txt")
                .exists(),
            "an accepted import must copy the file into the managed directory"
        );
        let written = std::fs::read_to_string(&master).unwrap();
        assert!(
            written.contains("base = \"allow\""),
            "the row must record the direction the operator asked for:\n{written}"
        );
    }

    /// Deny-lists keep the `uncategorized` auto-promotion, so they need
    /// no tag — the asymmetry is deliberate (D2) and must not regress
    /// into "every import needs a tag".
    #[tokio::test]
    async fn tmc_import_local_still_accepts_an_untagged_deny_list() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        let src = dir.path().join("seed.txt");
        std::fs::write(&src, "bad.example\n").unwrap();
        run_import_local(&master, &sock, &src, "ads", "deny", None, None)
            .await
            .expect("a deny-list needs no consent and no tag");
        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        let imported = loaded
            .config
            .blocklists
            .iter()
            .find(|b| b.id.as_str() == "ads")
            .expect("the list must have landed");
        // The tag assertion this carried went with the field. What it was
        // ever about on the deny side survives as the direction: routing
        // `import-local` through the shared gate must not have widened
        // anything, and a deny-list still lands unchallenged.
        assert_eq!(imported.base, BlocklistBase::Deny);
    }

    /// The second door: flipping an untagged list to `allow` strips it
    /// of the auto-promotion that was making it work, and it silently
    /// stops filtering.
    #[tokio::test]
    async fn tmc_set_kind_allow_accepts_an_untagged_list_now() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        let src = dir.path().join("seed.txt");
        std::fs::write(&src, "bad.example\n").unwrap();
        // A local-trust list, so the trust gate does not fire first and
        // mask the one under test. It lands with NO `tags` key in the
        // file — `uncategorized` is applied at load, not persisted,
        // which is exactly why the gate reads the file.
        run_import_local(&master, &sock, &src, "x", "deny", None, None)
            .await
            .unwrap();
        run_set_kind(&master, &sock, "x", "allow", None)
            .await
            .expect("trust = local needs no consent, and the tag gate is retired");
        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        let b = loaded
            .config
            .blocklists
            .iter()
            .find(|b| b.id.as_str() == "x")
            .unwrap();
        assert_eq!(b.base, BlocklistBase::Allow);
    }

    // ── the third door: `uncategorized` is not an answer to "which tag?"
    //
    // The gate above asks the operator to name who an allow-list is for.
    // These four pin that the sentinel is not an acceptable name at any
    // of the four verbs that can write one — including `tag add`, which
    // creates nothing and flips no direction and was outside every gate
    // until now.

    /// The deny side of F18: routing `import-local` through the shared gate
    /// must not have widened anything. A deny-list still needs no tag, and
    /// still lands.
    ///
    /// Present because the two inverted tests above cannot tell "the gates
    /// were routed" from "the two bails were deleted" — with `trust = local`
    /// all three arms answer false either way. Neither can this one. The
    /// wiring is held structurally instead: the call site destructures
    /// `AllowDirectionGates` exhaustively, so a fourth gate breaks the build
    /// there rather than being skipped in silence.
    #[tokio::test]
    async fn plp_import_local_still_accepts_an_untagged_deny_list() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        let src = dir.path().join("seed.txt");
        std::fs::write(&src, "good.example\n").unwrap();
        run_import_local(&master, &sock, &src, "ads2", "deny", None, None)
            .await
            .expect("an untagged deny-list has always been legal");
        let written = std::fs::read_to_string(&master).unwrap();
        assert!(
            written.contains("base = \"deny\""),
            "the row must record the direction the operator asked for:\n{written}"
        );
    }

    // ── the way back out ──────────────────────────────────────────────
    //
    // Some configs do not load. Every verb in this file starts by loading,
    // so without the degraded path below, an operator whose disk is already
    // in a refused state — hand-edited, or restored from an older backup —
    // would find that the commands that repair it fail on the error they are
    // repairing, leaving hand-editing the TOML as the only exit.
    //
    // **`plp-s3` had to re-point this fixture, and that is worth reading.**
    // The refused state used to be `kind = allow` + `tags =
    // ["uncategorized"]`. §2.5 retires that ERROR — the sentinel stopped
    // meaning "the widest audience" when tags stopped deciding the audience
    // — so the old fixture now loads clean and the deadlock it modelled is
    // unreachable through that door. The property is not gone, so the
    // fixture moves to a door that is still shut: the **consent** gate,
    // which §2.5 leaves exactly where it was.

    /// A file in a refused state, written directly. No verb will produce
    /// one, which is the point: this is what an operator's disk looks like
    /// when they reach for a repair.
    ///
    /// Refused by the consent gate — a remote-unsigned allow-list with no
    /// `accept_unsigned_allow`.
    fn master_with_a_refused_allow_list(dir: &tempfile::TempDir) -> PathBuf {
        let master = dir.path().join("config.toml");
        std::fs::write(
            &master,
            r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]

[[blocklists]]
id = "guest"
display_name = "Guest exemptions"
url = "https://example.com/guests.txt"
format = "domains"
base = "allow"
trust = "remote-unsigned"
"#,
        )
        .unwrap();
        master
    }

    #[tokio::test]
    async fn tmc_set_kind_deny_repairs_a_config_that_no_longer_loads() {
        let dir = tempfile::tempdir().unwrap();
        let master = master_with_a_refused_allow_list(&dir);
        let sock = fake_socket(&dir);
        // Precondition: the config really is unloadable. Without this the
        // test could pass against a fixture that quietly stopped being
        // refused, and would then prove nothing about the deadlock.
        assert!(
            load_config(&master, time::OffsetDateTime::now_utc()).is_err(),
            "the fixture must be in the refused state"
        );

        run_set_kind(&master, &sock, "guest", "deny", None)
            .await
            .expect("the narrowing direction must work on a config that does not load");

        let loaded = load_config(&master, time::OffsetDateTime::now_utc())
            .expect("the repair must leave a loadable config");
        assert_eq!(loaded.config.blocklists[0].base, BlocklistBase::Deny);
    }

    /// The leniency is scoped to repairs. Asking for MORE permission
    /// while the config is unreadable is refused with the load errors,
    /// because a widening mutation computed against a config nobody can
    /// load is a mutation against a guess.
    #[tokio::test]
    async fn tmc_set_kind_allow_still_demands_a_loadable_config() {
        let dir = tempfile::tempdir().unwrap();
        let master = master_with_a_refused_allow_list(&dir);
        let sock = fake_socket(&dir);
        let err = run_set_kind(&master, &sock, "guest", "allow", None)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("cannot load config"),
            "the widening direction must surface the load failure: {err}"
        );
    }

    // ── cli-surface: `blocklist add` becomes direction-aware ──────────
    //
    // What used to sit here was `tmc_blocklist_add_has_no_kind_flag_so_it
    // _cannot_create_an_allow_list`, a deliberate sentinel: it asserted
    // `add` had NO `--kind`, with the note "if --kind is ever added to
    // add, this test fails and whoever adds it has to decide about the
    // gate". An earlier lane was that whoever, and the decision is the
    // tests below — `add` gets `--kind`, and every door it opens is
    // gated BEFORE the write.
    //
    // ── `cli_surface_blocklist_add_keeps_the_tag_flag` was the SECOND
    //    sentinel in that pair, and `plp-s5c` is the whoever it was
    //    waiting for. It went red on the commit that deleted `--tag`,
    //    which is the sentinel working, not a break to patch green.
    //
    // Its stated reason was: "losing `--tag` would silently re-open the
    // inert allow-list hole from a different direction" — an untagged
    // allow-list matched no client, so it installed and filtered nothing.
    // That premise died at the `plp-s3` cutover: a list's direction now
    // reaches every profile that does not override it, tagged or not, so
    // an untagged allow-list is not inert. It is the ordinary case.
    // `cli_surface_add_allow_without_tags_is_now_accepted` below covers
    // exactly that, and inverted the same claim one sprint earlier.
    //
    // Not replaced with its inverse here, because a stronger version
    // already exists: `cli::plp_s5c_tag_surface_tests::
    // no_verb_carries_a_tag_flag` walks the WHOLE clap tree rather than
    // this one verb, and keys on the argument id rather than the rendered
    // help — a `hide = true` flag is invisible in help and still typeable.

    /// The flag names are frozen by CONTRACT §3 — other surfaces assert
    /// on them, so a rename here is a cross-lane break, not a local one.
    #[test]
    fn cli_surface_blocklist_add_has_kind_and_ack_flags() {
        use clap::CommandFactory;
        let cmd = crate::cli::Cli::command();
        let add = cmd
            .find_subcommand("blocklist")
            .and_then(|c| c.clone().find_subcommand("add").cloned())
            .expect("`warden blocklist add` must exist");
        let kind = add
            .get_arguments()
            .find(|a| a.get_id() == "kind")
            .expect("`blocklist add` must offer --kind");
        assert_eq!(kind.get_long(), Some("kind"));
        let ack = add
            .get_arguments()
            .find(|a| a.get_id() == "accept_unsigned_allow")
            .expect("`blocklist add` must offer --accept-unsigned-allow");
        assert_eq!(ack.get_long(), Some("accept-unsigned-allow"));
        assert!(
            matches!(ack.get_action(), clap::ArgAction::SetTrue),
            "--accept-unsigned-allow is a declaration, not a value"
        );
    }

    /// DoD 3: the refusal lands BEFORE the config is written, not as a
    /// post-write rollback. A rollback would leave the operator reading
    /// an error about a file that (correctly) never changed, and the
    /// audit row would claim an attempted mutation the CLI never staged.
    #[tokio::test]
    async fn cli_surface_add_allow_from_url_without_ack_is_refused_before_write() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        let before = std::fs::read_to_string(&master).unwrap();
        let err = run_add_with_direction(
            &master,
            &sock,
            "svc-b",
            None,
            "https://example.com/service-b.txt",
            Some("domains"),
            None,
            None,
            None,
            None,
            true,
            None,
            AddDirection {
                kind: Some("allow"),
                accept_unsigned_allow: false,
            },
        )
        .await
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(
                &crate::config::schema::validator::format_unsigned_allow_list_requires_ack(
                    "svc-b",
                    BlocklistTrust::RemoteUnsigned,
                )
            ),
            "must carry the frozen validator string verbatim, got:\n{msg}"
        );
        assert!(
            msg.contains(ACCEPT_UNSIGNED_ALLOW_FLAG_HINT),
            "and the CLI-side hint naming the flag, got:\n{msg}"
        );
        // The needle that separates "refused before the write" from
        // "written, refused, rolled back". Measured, not assumed: with
        // the pre-flight gate disabled the post-write refusal reaches
        // here carrying the same frozen string plus the staged path and
        // the reverter's `nothing written` tail — so the assertion above
        // does not discriminate on its own, and neither does the
        // untouched-config one below.
        assert!(
            !msg.contains("nothing written"),
            "must be a pre-flight refusal, not a post-write revert:\n{msg}"
        );
        assert_eq!(
            std::fs::read_to_string(&master).unwrap(),
            before,
            "config must be untouched"
        );
        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        assert!(loaded.config.blocklists.is_empty(), "nothing was created");
    }

    /// DoD 2: the whole point of the lane — an allow-direction list
    /// created straight from a URL, and the config it produces LOADS.
    /// Asserting the load is the assertion that matters: a write that
    /// the next reload refuses is exactly the failure this lane exists
    /// to prevent.
    #[tokio::test]
    async fn cli_surface_add_allow_from_url_with_ack_writes_and_reloads_clean() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        run_add_with_direction(
            &master,
            &sock,
            "svc-b",
            None,
            "https://example.com/service-b.txt",
            Some("domains"),
            None,
            None,
            None,
            None,
            true,
            None,
            AddDirection {
                kind: Some("allow"),
                accept_unsigned_allow: true,
            },
        )
        .await
        .unwrap();
        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        let b = loaded
            .config
            .blocklists
            .iter()
            .find(|b| b.id.as_str() == "svc-b")
            .expect("entry must round-trip");
        assert_eq!(b.base, BlocklistBase::Allow);
        assert_eq!(b.trust, BlocklistTrust::RemoteUnsigned);
        assert!(b.accept_unsigned_allow);
    }

    /// Brief point 7 — every config mutation in this repo leaves an
    /// audit row, and the new door must not be the exception. The URL
    /// alone no longer describes what happened: the same `blocklist.add`
    /// line could be an ordinary subscription or the moment a remote
    /// party gained the power to unblock domains, so the allow path
    /// records the direction and the consent.
    #[tokio::test]
    async fn cli_surface_allow_add_is_audited_with_direction_and_consent() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        run_add_with_direction(
            &master,
            &sock,
            "svc-b",
            None,
            "https://example.com/service-b.txt",
            Some("domains"),
            None,
            None,
            None,
            None,
            true,
            None,
            AddDirection {
                kind: Some("allow"),
                accept_unsigned_allow: true,
            },
        )
        .await
        .unwrap();
        let log = crate::cli::commands::audit::audit_log_path_for(&master);
        let rows = crate::config::audit::tail(&log, 50).expect("audit log must exist");
        let rec = rows
            .iter()
            .filter_map(|(_, r)| r.as_ref().ok())
            .find(|r| r.action.as_deref() == Some("blocklist.add"))
            .expect("the creation path must emit an audit row");
        assert_eq!(rec.target_id.as_deref(), Some("svc-b"));
        let after = rec.fields_after.as_deref().unwrap_or_default();
        assert!(after.contains("kind=allow"), "{after}");
        assert!(after.contains("accept_unsigned_allow=true"), "{after}");
        assert!(
            after.contains("https://example.com/service-b.txt"),
            "the URL stays on the row — a later silent re-point is what \
             audit-01 exists to attribute: {after}"
        );
    }

    /// The deny row is byte-identical to what it was before this lane —
    /// existing audit readers key on a bare URL there.
    #[tokio::test]
    async fn cli_surface_deny_add_audit_row_is_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        add_tagged_remote_deny(&master, &sock, "svc-a").await;
        let log = crate::cli::commands::audit::audit_log_path_for(&master);
        let rows = crate::config::audit::tail(&log, 50).expect("audit log must exist");
        let rec = rows
            .iter()
            .filter_map(|(_, r)| r.as_ref().ok())
            .find(|r| r.action.as_deref() == Some("blocklist.add"))
            .expect("row must exist");
        assert_eq!(
            rec.fields_after.as_deref(),
            Some("https://example.com/svc-a.txt")
        );
    }

    /// The operator's original ask, end to end and from the CLI only:
    /// one list to block service A, one to permit service B.
    #[tokio::test]
    async fn cli_surface_deny_and_allow_lists_coexist_from_urls_alone() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        run_add_with_direction(
            &master,
            &sock,
            "svc-a",
            None,
            "https://example.com/service-a.txt",
            Some("domains"),
            None,
            None,
            None,
            None,
            true,
            None,
            AddDirection::default(),
        )
        .await
        .unwrap();
        run_add_with_direction(
            &master,
            &sock,
            "svc-b",
            None,
            "https://example.com/service-b.txt",
            Some("domains"),
            None,
            None,
            None,
            None,
            true,
            None,
            AddDirection {
                kind: Some("allow"),
                accept_unsigned_allow: true,
            },
        )
        .await
        .unwrap();
        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        let by = |id: &str| {
            loaded
                .config
                .blocklists
                .iter()
                .find(|b| b.id.as_str() == id)
                .unwrap_or_else(|| panic!("{id} must exist"))
                .base
        };
        assert_eq!(by("svc-a"), BlocklistBase::Deny);
        assert_eq!(by("svc-b"), BlocklistBase::Allow);
    }

    /// The untagged-allow gate reaches the new door too. An allow-list
    /// with no tags is not auto-promoted (D2), so it would install,
    /// report success and permit nothing.
    #[tokio::test]
    async fn cli_surface_add_allow_without_tags_is_now_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        run_add_with_direction(
            &master,
            &sock,
            "svc-b",
            None,
            "https://example.com/service-b.txt",
            Some("domains"),
            None,
            None,
            None,
            None,
            true,
            None,
            AddDirection {
                kind: Some("allow"),
                accept_unsigned_allow: true,
            },
        )
        .await
        .expect("the tag gate is retired — an untagged allow-list is a legal declaration now");
        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        let b = loaded
            .config
            .blocklists
            .iter()
            .find(|b| b.id.as_str() == "svc-b")
            .expect("the list must have landed");
        assert_eq!(b.base, BlocklistBase::Allow);
    }

    /// Brief point 2: the written entry says what it is. Relying on the
    /// serde defaults produced a `[[blocklists]]` row with no `kind` and
    /// no `trust` — the operator reading their own TOML could not tell a
    /// deny-list from an allow-list, and neither could a reviewer.
    #[tokio::test]
    async fn cli_surface_add_writes_kind_and_trust_explicitly() {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        run_add(
            &master,
            &sock,
            "plain",
            None,
            "https://example.com/plain.txt",
            None,
            None,
            None,
            None,
            None,
            &[],
            true,
            None,
        )
        .await
        .unwrap();
        let segment = entry_segment_on_disk(&master, "plain");
        assert!(segment.contains("base = \"deny\""), "{segment}");
        assert!(segment.contains("trust = \"remote-unsigned\""), "{segment}");
        // Consent is written only when declared: a `false` on every
        // deny-list is noise that trains the operator to skip the line
        // on the one list where it means something.
        assert!(!segment.contains("accept_unsigned_allow"), "{segment}");
    }

    /// Read every TOML under the master's dir tree and return the
    /// `[[blocklists]]` segment carrying `id`. Sharding means the entry
    /// may land in master or in `blocklists.d/*.toml`.
    fn entry_segment_on_disk(master: &std::path::Path, id: &str) -> String {
        fn read_all_toml(root: &std::path::Path, out: &mut Vec<String>) {
            if let Ok(rd) = std::fs::read_dir(root) {
                for e in rd.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        read_all_toml(&p, out);
                    } else if p.extension().and_then(|s| s.to_str()) == Some("toml") {
                        if let Ok(s) = std::fs::read_to_string(&p) {
                            out.push(s);
                        }
                    }
                }
            }
        }
        let mut all_toml: Vec<String> = Vec::new();
        read_all_toml(master.parent().unwrap(), &mut all_toml);
        all_toml
            .iter()
            .flat_map(|raw| raw.split("[[blocklists]]"))
            .find(|seg| seg.contains(&format!("\"{id}\"")))
            .map(|s| s.to_string())
            .unwrap_or_else(|| panic!("entry {id} must exist on disk somewhere"))
    }

    #[test]
    fn cli_surface_accept_unsigned_allow_flag_hint_pinned() {
        assert_eq!(
            ACCEPT_UNSIGNED_ALLOW_FLAG_HINT,
            "On the command line, declare it with --accept-unsigned-allow on \
             this verb."
        );
    }

    #[tokio::test]
    async fn blocklists_add_triggers_reload_when_daemon_up() {
        use super::super::hr2_test_support::{
            assert_single_reload_with_resolved_token, env_home, seed_token_for_test, stub_reload_ok,
        };

        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = dir.path().join("stub.sock");
        let (server, recorded) = stub_reload_ok(sock.clone()).await;

        let _env = env_home(dir.path()).await;
        seed_token_for_test(dir.path());
        run_add(
            &master,
            &sock,
            "privacy-ads",
            Some("Privacy: ads"),
            "https://lists.purge.cc/privacy/ads.txt",
            Some("domains"),
            None,
            None,
            None,
            None,
            &[],
            true,
            None,
        )
        .await
        .unwrap();

        server.await.unwrap();
        assert_single_reload_with_resolved_token(&recorded);
    }

    // ── Enforcement report ─────────────────────────────────────────
    //
    // The defect these pin: a subscribed list whose tags meet nobody's
    // occupies a filter slot, downloads on schedule, reports success and
    // blocks nothing — and until now no read verb could say so. Every
    // assertion below therefore checks BOTH directions. An assertion that
    // only looked for an absent profile name would pass just as happily
    // if the whole report were deleted.

    /// Load a master config from a TOML string through the real
    /// `load_config`, so validation and the untagged-deny-list
    /// auto-promotion run exactly as they do for the live command.
    fn load_master(toml: &str) -> (tempfile::TempDir, crate::config::schema::ConfigV1) {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        std::fs::write(&master, toml).unwrap();
        let now = time::OffsetDateTime::now_utc();
        let loaded =
            load_config(&master, now).unwrap_or_else(|e| panic!("fixture must load: {e:?}"));
        (dir, loaded.config)
    }

    fn find_list<'a>(
        config: &'a crate::config::schema::ConfigV1,
        id: &str,
    ) -> &'a crate::config::schema::Blocklist {
        config
            .blocklists
            .iter()
            .find(|b| b.id.as_str() == id)
            .unwrap_or_else(|| panic!("fixture has no blocklist {id}"))
    }

    /// The three artefacts every test below inspects: the computed
    /// report, the `blocklist list` row, and the `blocklist show` block.
    fn report(config: &crate::config::schema::ConfigV1, id: &str) -> (Enforcement, String, String) {
        let b = find_list(config, id);
        let slots = filter_slots(config);
        let e = analyse_enforcement(config, b, slots.as_ref());
        let row = format_list_enforcement_line(&e);
        let show = format_show_enforcement(b, &e).join("\n");
        (e, row, show)
    }

    /// One list the only profile inherits, one it overrides to `ignore`.
    ///
    /// `plp-s3`: the inert arm used to be "carries a tag nothing else in the
    /// config has". Tags reach nothing now, so inertness has exactly one
    /// cause left and the fixture states it.
    const TWO_LISTS: &str = r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"
lists = { reaches-nobody = "ignore" }

[[blocklists]]
id = "reaches-someone"
display_name = "Reaches someone"
url = "https://lists.purge.cc/ads.txt"

[[blocklists]]
id = "reaches-nobody"
display_name = "Reaches nobody"
url = "https://lists.purge.cc/orphan.txt"

[upstream]
servers = ["192.0.2.1:53"]
"#;

    #[test]
    fn an_enforced_list_and_an_inert_one_render_differently() {
        let (_dir, config) = load_master(TWO_LISTS);
        let (live_e, live_row, live_show) = report(&config, "reaches-someone");
        let (dead_e, dead_row, dead_show) = report(&config, "reaches-nobody");

        assert!(live_row.contains("enforced by 1 profile"), "{live_row}");
        assert!(!live_row.contains(NOT_ENFORCED), "{live_row}");
        assert!(dead_row.contains(NOT_ENFORCED), "{dead_row}");
        assert!(dead_row.contains("every profile ignores it"), "{dead_row}");
        assert_ne!(live_row, dead_row);

        assert_eq!(live_e.profiles, vec!["default".to_string()]);
        assert!(dead_e.profiles.is_empty());

        assert!(
            live_show.contains("Used by profiles:       default"),
            "{live_show}"
        );
        assert!(!live_show.contains(NOT_ENFORCED), "{live_show}");
        assert!(dead_show.contains(NOT_ENFORCED), "{dead_show}");
        assert!(
            dead_show.contains("Used by profiles:       <none>"),
            "{dead_show}"
        );
        // The fix must name what the operator actually has to change.
        assert!(
            dead_show.contains("reaches-nobody = \"ignore\""),
            "{dead_show}"
        );
    }

    #[test]
    fn only_the_inert_list_reaches_the_closing_note() {
        let (_dir, config) = load_master(TWO_LISTS);
        let inert: Vec<String> = config
            .blocklists
            .iter()
            .filter(|b| {
                analyse_enforcement(&config, b, filter_slots(&config).as_ref())
                    .blocked_reason()
                    .is_some()
            })
            .map(|b| b.id.as_str().to_string())
            .collect();
        assert_eq!(inert, vec!["reaches-nobody".to_string()]);

        let footer = format_inert_footer(&inert).join("\n");
        assert!(footer.contains("reaches-nobody"), "{footer}");
        assert!(!footer.contains("reaches-someone"), "{footer}");
        // Silence on a healthy config: a "0 lists are not enforced" line
        // would train the operator to skip the block that matters.
        assert!(format_inert_footer(&[]).is_empty());
    }

    #[test]
    fn a_disabled_list_is_not_enforced_even_when_its_tags_match() {
        let (_dir, config) = load_master(
            r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"
tags = ["ads"]

[[blocklists]]
id = "switched-off"
display_name = "Switched off"
url = "https://lists.purge.cc/ads.txt"
tags = ["ads"]
enabled = false

[upstream]
servers = ["192.0.2.1:53"]
"#,
        );
        let (e, row, show) = report(&config, "switched-off");
        // The tag DOES meet the profile — the report must not stop at the
        // intersection and call that enforcement.
        assert_eq!(e.profiles, vec!["default".to_string()]);
        assert!(row.contains(NOT_ENFORCED), "{row}");
        assert!(row.contains("enabled = false"), "{row}");
        assert!(
            show.contains("warden blocklist set switched-off enabled true"),
            "{show}"
        );
    }

    /// `plp-s3` inverted this test, and the inversion is the record.
    ///
    /// It was `an_untagged_allow_list_is_told_it_has_no_tags_not_that_nobody_carries_them`,
    /// and it defended a real distinction: an untagged **allow**-list was the
    /// one shape that reached this report with `tags = []` (D2 kept
    /// allow-lists out of `uncategorized` auto-promotion), and blaming "no
    /// profile carries any of its tags" would have been false — there were
    /// none to carry.
    ///
    /// Tags no longer reach lists at all, so an untagged allow-list is not
    /// inert; it is **inherited by every profile as allow-direction**, which
    /// is the most reachable a list can be. Reporting NOT ENFORCED for it
    /// would now be the false negative the whole report exists to avoid.
    ///
    /// The exposure has not gone unremarked: it moved to a load-time WARN
    /// (`ALLOW_DIRECTION_LIST_STANDING_EXPOSURE`, §2.5), which is where a
    /// standing risk belongs — re-stated at every load rather than once, in a
    /// read verb the operator may never run.
    #[test]
    fn an_untagged_allow_list_is_enforced_everywhere_not_inert() {
        let (_dir, config) = load_master(
            r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"
tags = ["ads"]

[[blocklists]]
id = "untagged-allow"
display_name = "Untagged allow"
url = "https://lists.purge.cc/allow.txt"
base = "allow"
trust = "local"

[upstream]
servers = ["192.0.2.1:53"]
"#,
        );
        let (e, row, show) = report(&config, "untagged-allow");
        assert_eq!(
            e.profiles,
            vec!["default".to_string()],
            "an allow-direction list is inherited by every profile that does \
             not override it — tags stopped gating that in `plp-s3`"
        );
        assert!(
            !row.contains(NOT_ENFORCED),
            "reporting a live allow-list as inert is the false negative this \
             report must never produce: {row}"
        );
        assert!(
            !row.contains("has no tags of its own"),
            "the retired reason must not fire — it would describe the \
             opposite of what the daemon does: {row}"
        );
        assert!(show.contains("Used by profiles:       default"), "{show}");
    }

    #[test]
    fn the_closing_note_agrees_with_itself_in_the_singular() {
        // Regression: the singular branch used to read "It downloads on
        // schedule, report success, and filter nothing" — only the first
        // verb was inflected.
        let one = format_inert_footer(&["only-one".to_string()]).join("\n");
        assert!(
            one.contains("It downloads on schedule, reports success, and filters nothing."),
            "{one}"
        );
        let two = format_inert_footer(&["a".to_string(), "b".to_string()]).join("\n");
        assert!(
            two.contains("They download on schedule, report success, and filter nothing."),
            "{two}"
        );
    }

    /// `plp-s3` replaced four tests here, and the replacement is smaller for
    /// a reason worth stating.
    ///
    /// They were `a_device_tag_alone_makes_a_list_enforced`,
    /// `a_group_tag_reaches_its_member_devices`,
    /// `a_subnet_tag_does_not_leak_onto_an_explicit_device_record` and
    /// `an_empty_group_carries_a_tag_to_nobody` — four axes a list could
    /// reach an operator's network through, and four ways the report could
    /// answer wrongly. There is now **one** axis: a `(profile, list)` pair.
    /// A device reaches a list through its profile and through nothing else,
    /// so the report cannot mis-attribute across axes that no longer exist.
    ///
    /// The property those four defended survives intact and is what this
    /// pins: **no false negative.** Telling an operator a list is NOT
    /// ENFORCED when it is filtering is the one error this report must never
    /// make — it sends them to fix something that already works, and worse,
    /// invites them to "fix" it into a state that is different.
    #[test]
    fn a_list_no_profile_ignores_is_enforced_by_every_profile() {
        let (_dir, config) = load_master(
            r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[profiles.kids]
display_name = "Kids"

[[blocklists]]
id = "inherited"
display_name = "Inherited by all"
url = "https://lists.purge.cc/inherited.txt"

[upstream]
servers = ["192.0.2.1:53"]
"#,
        );
        let (e, row, show) = report(&config, "inherited");
        assert_eq!(
            e.profiles,
            vec!["default".to_string(), "kids".to_string()],
            "a list with no override is inherited by EVERY profile — that is \
             what `base` means, and it is the change `plp-s3` makes"
        );
        assert!(!row.contains(NOT_ENFORCED), "{row}");
        assert!(row.contains("enforced by 2 profiles"), "{row}");
        assert!(
            show.contains("Used by profiles:       default, kids"),
            "{show}"
        );
    }

    /// The other side: a list every profile overrides to `ignore` really is
    /// inert, and the report says so.
    ///
    /// The positive arm above is what stops this from being satisfied by a
    /// report that calls everything inert.
    #[test]
    fn a_list_every_profile_ignores_is_reported_inert() {
        let (_dir, config) = load_master(
            r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"
lists = { shunned = "ignore" }

[profiles.kids]
display_name = "Kids"
lists = { shunned = "ignore" }

[[blocklists]]
id = "shunned"
display_name = "Shunned"
url = "https://lists.purge.cc/shunned.txt"

[upstream]
servers = ["192.0.2.1:53"]
"#,
        );
        let (e, row, show) = report(&config, "shunned");
        assert!(e.profiles.is_empty());
        assert!(row.contains(NOT_ENFORCED), "{row}");
        assert!(
            row.contains("every profile ignores it"),
            "the reason must name the override that caused it, got: {row}"
        );
        assert!(
            show.contains("`ignore`"),
            "the fix must point at the override to remove, got: {show}"
        );
    }

    /// One profile ignores it, one does not: enforced, and attributed to the
    /// profile that still carries it.
    ///
    /// This is the case v2 could not express at all (§1.2) — the whole
    /// reason the workstream exists — so a report that collapsed it to
    /// all-or-nothing would hide the feature from the operator who just used
    /// it.
    #[test]
    fn a_partially_ignored_list_names_the_profiles_that_keep_it() {
        let (_dir, config) = load_master(
            r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[profiles.marketing]
display_name = "Marketing"
lists = { social = "ignore" }

[[blocklists]]
id = "social"
display_name = "Social"
url = "https://lists.purge.cc/social.txt"

[upstream]
servers = ["192.0.2.1:53"]
"#,
        );
        let (e, row, _) = report(&config, "social");
        assert_eq!(e.profiles, vec!["default".to_string()]);
        assert!(!row.contains(NOT_ENFORCED), "{row}");
        assert!(row.contains("enforced by 1 profile"), "{row}");
    }
}
