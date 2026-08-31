//! IPC protocol types — JSON command/response enums for CLI↔daemon communication.
//!
//! Protocol: newline-delimited JSON. Each message is one JSON object terminated
//! by `\n`. The client sends one command, the server sends one response, then
//! the connection closes.
//!
//! # Authorization (P0-3)
//!
//! Commands are classified into three tiers via [`CommandTier`]:
//!
//! - `ReadOnly` — no authentication required. These commands are safe to
//!   expose to any process that can connect to the socket: they reveal
//!   nothing sensitive and change no state. The CLI sends them with no
//!   `token` field.
//! - `Mutating` — token required. Change daemon state (flush cache,
//!   reload config) but do not expose PII.
//! - `Admin` — token required. Shut down the daemon or expose the query
//!   log, tracking stats, or per-device stats (all of which are PII).
//!
//! # T5 backward-decode compatibility (Sprint 42)
//!
//! Variants renamed in T5 (Client* → Device*) carry `#[serde(alias = ...)]`
//! pointing at their legacy wire name, so a pre-T5 CLI can still send
//! `"client_stats"` / `"client_add"` / `"get_all_clients"` / etc and the
//! T5 daemon decodes them correctly. The CLI↔daemon pair is still shipped
//! in lockstep (see the note on `IpcResponse::QueryLogs`), but aliases
//! cover any in-flight message boundary crossing a partial upgrade.
//!
//! Mutating and Admin commands carry an optional `token` field. The CLI
//! auto-discovers the plaintext token from a standard file path and
//! attaches it; the daemon verifies it with `auth::token::verify_token`
//! (constant-time) against the hash in `settings.api.token_hash`. If no
//! hash is configured, Mutating/Admin commands are refused with a plain-
//! English error telling the operator to run `warden token generate`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::config::schema::blocklist::ListPolicy;
use crate::config::schema::profile::BlockResponseV1;
use crate::config::settings::{ClientConfig, EcsMode};

/// Privilege tier required to execute a command.
///
/// See the module docs for the rationale behind each tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandTier {
    /// Open to any process that can connect to the socket.
    ReadOnly,
    /// Changes daemon state — requires a valid token.
    Mutating,
    /// Can shut the daemon down or expose PII — requires a valid token.
    Admin,
}

/// Command sent from CLI to daemon via Unix socket.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpcCommand {
    /// Request daemon status (uptime, listen address, domain count, cache stats).
    Status,
    /// Test if a domain would be blocked by the running daemon's filter.
    Query { domain: String },
    /// Flush DNS cache — all entries or a single domain.
    CacheFlush {
        domain: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<String>,
    },
    /// Trigger config + list reload (equivalent to SIGHUP).
    Reload {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<String>,
    },
    /// §4.7 Phase 2 T1: drop the in-memory cache entry for a list
    /// source AND unlink its `<stem>.cache` + `<stem>.meta` sidecars
    /// from disk. `id` is the source string as configured in
    /// `lists.sources` (legacy slash slug or raw URL). Forces a
    /// re-download on the next refresh cycle. Tier `Mutating` —
    /// affects daemon state, no PII exposed.
    ForgetList {
        id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<String>,
    },
    /// Request graceful shutdown (equivalent to SIGTERM).
    Shutdown {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<String>,
    },
    /// Get the current number of domains in the filter engine.
    DomainCount,
    /// Get tracking stats (global counters, top-N, time-series).
    TrackingStats {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<String>,
    },
    /// Get per-device stats table.
    #[serde(alias = "client_stats")]
    DeviceStats {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<String>,
    },
    /// Get the full device view — mapped (configured in `[[devices]]`)
    /// and unmapped (observed via stats but never configured) together
    /// with their counters and an optional MAC from the ARP table.
    ///
    /// **Tier: `ReadOnly`, and that does not match what the response
    /// carries.** [`MappedDeviceDto`] returns `name`, `owner`,
    /// `department`, `mac`, `mac_aliases` and `notes` for every
    /// configured device — the broadest disclosure on this socket —
    /// while the narrower [`Self::DeviceStats`], covering one device,
    /// requires `Admin`. [`CommandTier::Admin`] is defined as the tier
    /// for commands that expose PII, so the two cannot both be right.
    ///
    /// The tier here is ergonomic: the TUI dashboard polls this on
    /// every refresh and has to work on an install with no token.
    /// What actually bounds the disclosure is the socket, not the
    /// tier — `bind_socket` sets `0o600` and every connection is
    /// checked for `SO_PEERCRED` uid equality against the daemon's own
    /// uid, so any caller that reaches this could read the config file
    /// directly. That makes the mismatch a defence-in-depth gap rather
    /// than a bypass.
    #[serde(alias = "get_all_clients")]
    GetAllDevices,
    /// Get recent query log entries with optional filters.
    ///
    /// The `client` filter field is retained (not renamed to `device`)
    /// per §14.4 punto 3 R4 — it refers to the query-log filter's
    /// operator-typed target name, which is an API surface with
    /// semantics stable beyond T5. Renaming would break muscle memory
    /// for operators running ad-hoc log queries.
    QueryLogs {
        limit: usize,
        #[serde(default)]
        client: Option<String>,
        #[serde(default)]
        blocked_only: bool,
        #[serde(default)]
        domain: Option<String>,
        /// Sprint 41: only entries within the last `since_secs` seconds.
        /// `None` means no time cutoff. `#[serde(default)]` makes older
        /// callers (that don't carry the field at all) still parse.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        since_secs: Option<u64>,
        /// `qlog-paging-cursor`: resume point handed back by a previous
        /// response's `next_cursor`. `None` reads the live tail — which is
        /// what every pre-paging caller sends, and what
        /// `#[serde(default)]` keeps them able to send.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cursor: Option<crate::tracking::query_log::QueryLogCursor>,
        /// `qlog-advanced-filter-form`: Tier-1 client predicates, ANDed
        /// with each other and with `client` / `domain` / `blocked_only`.
        /// `None` means the operator never opened the form — the field is
        /// purely additive and the four existing controls are untouched.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        advanced: Option<AdvancedClientFilterDto>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<String>,
    },
    /// Add a configured device. Tier: `Admin`. The daemon serializes
    /// the call against other device mutations via a write lock,
    /// re-runs the v1 validator on the resulting config (catching
    /// duplicate name/IP/(owner, device) plus charset/length checks
    /// for tags), atomically rewrites `config.toml`, and triggers a
    /// hot reload. Same wire format as a `[[devices]]` TOML block —
    /// a `ClientConfig` (the v0 legacy struct kept as the `[[devices]]`
    /// pass-through type per §14.4 judgment call) value serialized
    /// through the existing serde derive on that struct. The `client`
    /// field name on the wire is retained for decode-compat with
    /// pre-T5 CLI senders.
    #[serde(alias = "client_add")]
    DeviceAdd {
        client: ClientConfig,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<String>,
    },
    /// Update fields of an existing device by name. Tier: `Admin`.
    /// Partial-patch semantics: each `DevicePatch` field uses an
    /// extra `Option` layer so the wire can distinguish "omitted —
    /// leave alone" (outer `None`) from "explicitly cleared" (outer
    /// `Some(None)`) for nullable fields like `mac` and `owner`. The
    /// patch is applied to the current on-disk state, validated, and
    /// written under the same write lock as `DeviceAdd`.
    #[serde(alias = "client_update")]
    DeviceUpdate {
        /// Friendly name of the device to update. The patch may
        /// rename it via `patch.new_name`.
        name: String,
        patch: DevicePatch,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<String>,
    },
    /// Remove a configured device by name. Tier: `Admin`. Errors if
    /// the name is not found. Same write lock + validate + reload
    /// flow as the other device mutations — even though removal
    /// can't introduce duplicates, the validator still runs so a
    /// dangling schedule reference (a `[[schedules]]` entry pointing
    /// at the now-removed device) gets surfaced before the write.
    #[serde(alias = "client_remove")]
    DeviceRemove {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<String>,
    },
    /// Promote an observed-but-unmapped IP into a configured device.
    /// Tier: `Admin`.
    ///
    /// **Strictly requires a MAC pin from the live ARP table** for
    /// the given IP. If the resolver's ARP snapshot has no entry,
    /// the call is rejected with a "wait for ARP, then retry" hint.
    /// The MAC requirement is load-bearing per project rules "MAC + IP
    /// for client identification — IP-only is bypassable in 30
    /// seconds": a DHCP collision could re-bind the IP to a
    /// different physical device after promotion, silently moving
    /// the wrong device into the configured device's profile slot.
    ///
    /// On success, builds a `ClientConfig` with the ARP-resolved MAC
    /// and runs the same write-lock + validate + reload pipeline as
    /// `DeviceAdd`. Metadata fields (owner, device, department) are
    /// passed through verbatim — the form that opens the promote
    /// modal in the TUI fills them in directly.
    #[serde(alias = "client_promote")]
    DevicePromote {
        /// IP address of the unmapped device to promote. Must
        /// currently be present in the daemon's ARP snapshot.
        ip: std::net::IpAddr,
        /// Friendly name to assign to the new mapping.
        name: String,
        /// Profile to bind the new device to. Validator enforces
        /// this references an existing `[profiles.*]` section.
        profile: String,
        /// Optional human-friendly fields; same semantics as the
        /// matching fields on `ClientConfig`.
        #[serde(default)]
        owner: Option<String>,
        #[serde(default, alias = "device")]
        device_type: Option<String>,
        #[serde(default)]
        department: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<String>,
    },
    /// Sprint 38 QLP5: apply a partial update to the `[tracking]`
    /// section of the v1 master. Tier: `Admin` — the query log
    /// contains PII so mutations of its settings share the tier of
    /// the reads that expose it.
    ///
    /// The handler runs under the same write lock as the entity
    /// editors, re-reads the master as a `toml::Value`, applies the
    /// patch field-by-field (partial semantics — absent fields leave
    /// the master alone), runs the CS2 `atomic_write_and_validate`
    /// helper against the v1 loader, and triggers the shared S36
    /// `attempt_reload` so the daemon picks up the change without a
    /// restart.
    TrackingConfigUpdate {
        patch: TrackingPatch,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<String>,
    },
    /// Sprint 43 T1: read per-source runtime telemetry.
    ///
    /// `source_id = None` returns a snapshot of every configured
    /// `[lists].sources` entry. `source_id = Some("ads")` (or any
    /// canonical `[[blocklists]].id`, or the legacy slash-form slug)
    /// resolves a single entry via the resolver's `slug_to_id` bridge.
    ///
    /// **Tier: `ReadOnly`.** No token gate — the TUI Lists tab and any
    /// operator running `warden blocklist show` polls this on every
    /// refresh, so requiring an admin token would defeat the whole
    /// "see what the daemon thinks" loop. Sensitive metadata (source
    /// URLs, auth tokens) is NOT exposed; only counts, timestamps, and
    /// a sample of skipped lines.
    BlocklistStats {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_id: Option<String>,
    },
    /// Sprint 44 follow-up (`s44-hits-ipc-verb`): snapshot the per-record
    /// `LocalRecordsHits` counter for the TUI's `Leaf::LocalDns` `hits`
    /// column. The counter itself is wired hot-path-side since T3; this
    /// verb exposes the read surface so the TUI no longer renders `—`.
    ///
    /// **Tier: `ReadOnly`.** No token gate, mirroring `BlocklistStats`:
    /// the payload reveals only counts + the operator's own record names
    /// (already in their config), and the TUI polls it on a slow cadence.
    LocalRecordsHits,
    /// `logs-tab`: a page of the daemon's own recent `tracing` events —
    /// the source behind the TUI's `Leaf::Logs`. Reads the in-process
    /// ring buffer (`tracking::log_ring`); nothing is read from disk and
    /// no journald permission is involved.
    ///
    /// **Tier: `Admin`.** Log lines routinely carry client IPs and query
    /// names (`dns/handler.rs` formats both into its `warn!`/`error!`
    /// text), so this is PII by the same reasoning that puts `QueryLogs`
    /// in this tier — not by analogy with `BlocklistStats`, which exposes
    /// counts only.
    ///
    /// Both filters are applied **during** the newest-to-oldest walk, so
    /// a page filtered to `error` reaches the bottom of the ring instead
    /// of returning whatever few errors sit in the newest `limit` rows.
    /// They AND with each other, matching the query log's convention.
    DaemonLogs {
        limit: usize,
        /// Exact level to keep. `None` is "every level".
        #[serde(default, skip_serializing_if = "Option::is_none")]
        level: Option<crate::tracking::log_ring::LogLevel>,
        /// Case-insensitive substring over the message and the target.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        contains: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<String>,
    },
    /// §4.26 Phase 1: create a v1 `[profiles.<id>]` entry with the given
    /// `display_name`. All other fields default; subsequent mutations go
    /// through `ProfileUpdate`. Refuses if `id` already exists.
    /// **Tier: `Mutating`.**
    ProfileCreate {
        id: String,
        display_name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<String>,
    },
    /// §4.26 Phase 1: patch fields on an existing v1 profile. `patch`
    /// uses double-Option semantics for nullable fields (block_response,
    /// blocked_ttl_secs) so the wire format distinguishes "omitted, no
    /// change" from "set to None (inherit from `[server]` defaults)".
    /// Multi-field mutates (e.g. the `ecs` subtree) land atomically in
    /// a single TOML rewrite. **Tier: `Mutating`.**
    ProfileUpdate {
        id: String,
        patch: ProfileUpdatePatch,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<String>,
    },
    /// §4.26 Phase 1: remove a v1 profile entry. Refuses if any device,
    /// subnet, or schedule still references the id. **Tier: `Mutating`.**
    ProfileDelete {
        id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<String>,
    },
    /// §4.11-4 (CS9): this node's live cluster state — role, peer, generations
    /// and content hashes, the secondary's last-sync age / poll status, and (on
    /// a primary) the connected-secondary roster with contribution weights.
    /// Tier `ReadOnly` (no token — mirrors `Status`); `cluster`-feature only, so
    /// it is absent from the default build.
    #[cfg(feature = "cluster")]
    ClusterStatus,
}

/// Partial update for a configured device. Each field uses
/// `Option<Option<T>>` for nullable types so the wire format can
/// distinguish "omitted, don't touch" from "explicitly cleared". For
/// non-nullable fields (`new_name`, `ip`, `profile`), a plain
/// `Option<T>` suffices because there is no "cleared" state to
/// represent.
///
/// The double-Option pattern is the canonical way to express PATCH
/// semantics in serde — outer `None` is skipped on serialize via
/// `skip_serializing_if`, so a wire payload that omits the field
/// deserializes back to outer `None`. Outer `Some(None)` survives
/// the roundtrip as a JSON `null` and tells the handler "set this
/// field to None on the stored ClientConfig".
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct DevicePatch {
    /// New friendly name (renames the device). The handler enforces
    /// the new name does not collide with an existing device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_name: Option<String>,
    /// New IP address. The handler enforces the new IP does not
    /// collide with another configured device's IP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<std::net::IpAddr>,
    /// Profile name. Validator enforces this references an existing
    /// `[profiles.*]` section.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// MAC pin. Outer `None` = leave alone. `Some(None)` = clear the
    /// pin. `Some(Some("..."))` = set/replace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<Option<String>>,
    /// New network name. Outer `None` = leave alone. `Some(None)` =
    /// clear it. `Some(Some("..."))` = set/replace. Same
    /// leave-alone/clear/set semantics as `mac`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_name: Option<Option<String>>,
    /// New wildcard flag. `None` = leave alone, `Some(v)` = set to `v`.
    /// No "clear" state needed — it's a plain bool, not nullable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_name_wildcard: Option<bool>,
    /// Additional MACs this device uses (see `ClientConfig::mac_aliases`).
    /// Full-list replacement: `None` = leave the existing aliases
    /// alone, `Some(vec![])` = drop every alias,
    /// `Some(vec!["..."])` = replace with this list. Daemon re-validates
    /// format + cross-client uniqueness before writing to disk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac_aliases: Option<Vec<String>>,
    /// Operator-friendly owner label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<Option<String>>,
    /// Device type / category label (e.g. "Smart TV", "Stampante").
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "device")]
    pub device_type: Option<Option<String>>,
    /// Logical group label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub department: Option<Option<String>>,
    /// Full group membership replacement. `None` = leave the existing
    /// memberships alone. `Some(vec![])` =
    /// clear every membership. `Some(vec!["foo"])` = replace with
    /// exactly that list.
    ///
    /// **Full-list, so a short list DELETES.** §4.64 G4: the TUI form
    /// was single-select and emitted `Some(vec![first])`, which turned
    /// every Save — including a bare rename — into a silent purge of the
    /// device's other memberships. The form is a multi-select now and
    /// sends the whole list; anything else writing this field must too.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<String>>,
    /// In-process notes. Outer `None` = leave alone. `Some(None)` =
    /// clear.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<Option<String>>,
    /// **RETIRED — captured only so it can be REPORTED, never applied.**
    ///
    /// `tags` was removed from the product by the profile-list-policy
    /// workstream. This field exists because removing it outright is not
    /// neutral: `DevicePatch` carries no `deny_unknown_fields`, so serde
    /// drops an unknown `tags` key in silence, applies the rest of the
    /// patch, and answers OK. The operator's rename lands and their tag
    /// vanishes with no diagnostic — which is the exact failure the tag
    /// model died of, reintroduced at a different layer.
    ///
    /// **The skew is reachable, not theoretical.** Measured on
    /// `the lab host` 2026-08-26: `/usr/local/bin/warden` is a raw ELF,
    /// there is no libexec copy, and `make upgrade` writes libexec only —
    /// so after an upgrade the daemon is new and the CLI on `PATH` is
    /// old, permanently (`upgrade-leaves-stale-cli-on-path`). That old
    /// CLI still sends `tags`, and `device update` is the one path where
    /// it otherwise *succeeds*: the request never touches the config file
    /// it would write a rejected `schema_version` into.
    ///
    /// Strip-and-report rather than refuse, matching
    /// `normalise_deprecated_keys`' `ip_denylists` precedent
    /// (`config/loader.rs:1458`) — the operator's other edits still apply,
    /// and both entry points into the product now behave the same way.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "tags")]
    pub retired_tags: Option<Vec<String>>,
}

/// Is a captured retired `tags` key worth reporting to the operator?
///
/// **Presence is not intent.** `DevicePatch.tags` was a full-list
/// replacement, not a delta, so an older client submits the field on every
/// save whether or not the operator touched it — an old TUI's device form
/// round-trips the whole record. A bare `Some(_)` therefore fires on a
/// device that never had a tag, and a warning about a key the operator did
/// not use is noise. This workstream treats noise as the same defect as
/// silence: both train the operator to stop reading.
///
/// So report only a NON-EMPTY value. That is the closest reachable
/// approximation of intent now that the stored field is gone and an echo can
/// no longer be told from a change by comparison — which is exactly what the
/// pre-removal handler did, in the test named
/// `device_update_refuses_a_tag_change_but_not_a_tag_echo`.
///
/// [`ProfileUpdatePatch::retired_tags`] applies the same rule through a
/// different mechanism: it is a **delta**, so a non-empty `add`/`remove` IS
/// unambiguous intent and is refused outright. The two paths differ in what
/// they do because their wire shapes differ in what they can express — not
/// because the product is inconsistent about what a retired key means.
pub fn retired_tags_worth_reporting(tags: Option<&Vec<String>>) -> bool {
    tags.is_some_and(|t| !t.is_empty())
}

#[cfg(test)]
mod retired_tags_reporting_tests {
    use super::retired_tags_worth_reporting;

    /// Pins all three states. A mutation to `is_some()` turns the middle row
    /// red; a mutation to `false` turns the last row red. Without the middle
    /// row the predicate could be `is_some()` and still pass.
    #[test]
    fn only_a_non_empty_retired_tags_key_is_reported() {
        assert!(
            !retired_tags_worth_reporting(None),
            "absent key: the client never sent it"
        );
        assert!(
            !retired_tags_worth_reporting(Some(&vec![])),
            "empty list: an older client round-tripping a device that has no \
             tags — presence is not intent, and warning here is noise"
        );
        assert!(
            retired_tags_worth_reporting(Some(&vec!["kids".to_string()])),
            "non-empty: the closest reachable approximation of intent"
        );
    }
}

/// §4.26 Phase 1: partial update for a v1 `[profiles.<id>]` entry.
///
/// Field shape mirrors `DevicePatch`:
/// - `Option<T>` for non-nullable fields → outer `None` means "no change".
/// - `Option<Option<T>>` for nullable schema fields → outer `None` =
///   "no change", `Some(None)` = "set to `None` (inherit from `[server]`
///   default)", `Some(Some(x))` = "set to `x`".
/// - `admin_rules` uses an explicit add/remove pair so the patch is a
///   delta, not a full-list replacement; the handler appends/removes
///   refs without rewriting the whole `Vec<Id>`.
/// - `ecs` is its own patch struct so the `[profile.X.ecs]` subtree
///   mutates atomically (mode + prefixes in one TOML write) instead of
///   forcing N round-trips. `EcsPatch::clear = true` sets
///   `Profile.ecs = None` (inherit upstream defaults).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ProfileUpdatePatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_response: Option<Option<BlockResponseV1>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_ttl_secs: Option<Option<u32>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_all: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_rules: Option<AdminRulesPatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecs: Option<EcsPatch>,
    /// **RETIRED — captured only so it can be REFUSED, never applied.**
    ///
    /// `plp-s5a` removed `Profile.tags`, the field this delta wrote.
    /// Deleting the wire field with it would not be neutral:
    /// `ProfileUpdatePatch` carries no `deny_unknown_fields`, so serde
    /// would drop an unknown `tags` key in silence, apply the rest of the
    /// patch and answer OK — the operator's tag edit vanishing with no
    /// diagnostic, which is precisely the failure the tag model died of.
    ///
    /// The skew that reaches it is measured, not hypothetical: after
    /// `make upgrade` the daemon is new and the `warden` on `PATH` is old
    /// (`upgrade-leaves-stale-cli-on-path`), and an old TUI's profile
    /// modal submits its whole patch on every save.
    ///
    /// **Refused, not stripped — deliberately different from
    /// [`DevicePatch::retired_tags`].** That one strips and reports so the
    /// operator's other device edits still land. Here the refusal already
    /// existed before the field was retired (`plp-s3`), and downgrading a
    /// loud rejection to a silent strip in the sprint that removes the
    /// field would be a behaviour change smuggled inside a deletion.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "tags")]
    pub retired_tags: Option<TagsPatch>,
    /// `profile_list_policy` §4 S4: delta over `Profile.lists`, the
    /// per-profile direction override map.
    ///
    /// **This is the only write path for a per-profile override.** Both
    /// the CLI (`cli::commands::profiles_v1`) and the TUI
    /// (`tui::ipc_poller`) reach `[profiles.<id>]` through
    /// [`IpcCommand::ProfileUpdate`] and nothing else, so the consent gate
    /// that a `Allow` override has to pay lives in the handler rather than
    /// once per surface. Callers expose the daemon's refusal; they do not
    /// re-implement it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lists: Option<ListPolicyPatch>,
}

/// `profile_list_policy` §4 S4: delta over a profile's
/// `lists: BTreeMap<Id, ListPolicy>` field — the per-`(profile, list)`
/// direction override.
///
/// **Why this is NOT shaped like [`AdminRulesPatch`] / [`TagsPatch`].**
/// Those are deltas over a *set*, and a set cannot express three states.
/// `deny → allow` would become two operations instead of one, and — the
/// part that actually breaks the model — `ignore` would be
/// indistinguishable from *absent, therefore inherit `base`*. That
/// distinction is the whole of
/// [`effective_direction`](crate::config::schema::blocklist::effective_direction):
/// a key present with [`ListPolicy::Ignore`] says "this profile does not
/// apply the list"; a key absent says "whatever the list's own `base`
/// says". So this is a delta over a *map*: `set` carries the value, and
/// removal is its own list.
///
/// Semantics, frozen, deliberately mirroring [`TagsPatch`] so a reader who
/// knows one knows both:
/// - `set` on a key already present overwrites (idempotent, not an error);
/// - `clear` of a key already absent is a no-op;
/// - `set` is applied **before** `clear`, so a key in both ends removed;
/// - an all-empty patch is a legal no-op — and writes nothing at all, not
///   even an empty `lists = {}` table (see the handler).
///
/// List ids are `String` on the wire, validated through
/// [`Id::new`](crate::config::schema::Id) before anything is applied, and
/// checked against the `[[blocklists]]` actually on disk — the same
/// "String on the wire, validated on apply" rule the two sibling patches
/// follow.
///
/// **An override cannot declare consent, and that is why there is no
/// third field here.** `allow_direction_gates` reads
/// `consent_in_file || consent_declared_now`; at the daemon there is no
/// operator to ask, so a `consent_declared_now` could only arrive on this
/// wire — self-declared by any client that can reach the socket. Worse, a
/// consent field here would have to rewrite the `[[blocklists]]` row,
/// widening the declaration to **every other profile** that overrides that
/// list: a side effect at a different radius than the edit. Consent stays
/// what project rules §Neutrality says it is — a per-list property, declared
/// once, applying at every refresh — and `warden blocklist set-trust
/// <id> remote-unsigned --accept-unsigned-allow` remains the one place to
/// declare it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ListPolicyPatch {
    /// `(list-id → policy)` pairs to write into `profiles.<id>.lists`.
    #[serde(default)]
    pub set: BTreeMap<String, ListPolicy>,
    /// Ids to REMOVE from the map — the pair goes back to inheriting the
    /// list's `base`. Different from `set: Ignore`, which declares "this
    /// profile does not apply it".
    #[serde(default)]
    pub clear: Vec<String>,
}

/// §4.26 Phase 1: delta over a profile's `admin_rules: Vec<Id>` field.
/// Ids are kept as `String` on the wire — the daemon validates them
/// through `Id::new` before applying.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AdminRulesPatch {
    #[serde(default)]
    pub add: Vec<String>,
    #[serde(default)]
    pub remove: Vec<String>,
}

/// The wire shape of a tag delta an **old** client may still send.
///
/// It was the add/remove delta over any entity's `tags: Vec<TagSlug>`
/// field. `plp-s5a` removed that field everywhere, so nothing applies one
/// any more: the type survives only so
/// [`ProfileUpdatePatch::retired_tags`] can deserialise such a request and
/// refuse it by name instead of letting serde discard it in silence.
///
/// The one semantic still load-bearing is that an **all-empty** patch is
/// not a tag write. Every edit modal resends its whole buffer, so a save
/// that touched only a display name arrives carrying an empty delta;
/// refusing that would make unrelated fields unwritable through a rule
/// about tags.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct TagsPatch {
    #[serde(default)]
    pub add: Vec<String>,
    #[serde(default)]
    pub remove: Vec<String>,
}

/// §4.26 Phase 1: patch the per-profile `[profile.X.ecs]` subtree.
///
/// `clear = true` sets `Profile.ecs = None` (inherit upstream defaults)
/// and the `mode` / `source_prefix_*` fields are ignored. Otherwise
/// each `Some(...)` value lands on the corresponding `ProfileEcsConfig`
/// field; absent fields preserve the existing value.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct EcsPatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<EcsMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_prefix_v4: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_prefix_v6: Option<u8>,
    #[serde(default)]
    pub clear: bool,
}

/// Partial update for `[tracking]` config. Sprint 38 QLP5.
///
/// Every field is an `Option<T>` — absent on the wire means "leave
/// this key in the master alone"; present means "overwrite to the
/// given value". None of the tracking knobs are nullable in the
/// config (there is no "unset" state), so the single-Option form is
/// sufficient and simpler than `DevicePatch`'s double-Option.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct TrackingPatch {
    /// Toggle query logging. Flipping this drives attach/detach of
    /// the writer on reload (S38 QLP1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_log_enabled: Option<bool>,
    /// Days of history to keep. Validator rejects `0` and values
    /// above `365` per QLP3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_days: Option<u32>,
    /// What to log per query. QLP3 enum — the type handles its own
    /// wire shape (string for All/BlockedOnly, table for Sampled).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_mode: Option<crate::config::settings::LogMode>,
}

impl IpcCommand {
    /// Return the privilege tier required to execute this command.
    pub fn tier(&self) -> CommandTier {
        match self {
            Self::Status
            | Self::Query { .. }
            | Self::DomainCount
            | Self::GetAllDevices
            | Self::BlocklistStats { .. }
            | Self::LocalRecordsHits => CommandTier::ReadOnly,
            Self::CacheFlush { .. }
            | Self::Reload { .. }
            | Self::ForgetList { .. }
            | Self::ProfileCreate { .. }
            | Self::ProfileUpdate { .. }
            | Self::ProfileDelete { .. } => CommandTier::Mutating,
            Self::Shutdown { .. }
            | Self::DaemonLogs { .. }
            | Self::QueryLogs { .. }
            | Self::TrackingStats { .. }
            | Self::DeviceStats { .. }
            | Self::DeviceAdd { .. }
            | Self::DeviceUpdate { .. }
            | Self::DeviceRemove { .. }
            | Self::DevicePromote { .. }
            | Self::TrackingConfigUpdate { .. } => CommandTier::Admin,
            #[cfg(feature = "cluster")]
            Self::ClusterStatus => CommandTier::ReadOnly,
        }
    }

    /// Canonical audit-action name for this command, e.g.
    /// `"profile.delete"`. Emitted by the IPC auth path so a
    /// token-rejection audit line names the *verb* that was attempted,
    /// not just its privilege tier (s-4.32-disc-8). Dot-form, no
    /// version suffix — matches the existing audit `action` convention
    /// (`rule.add`, `cname_block`, `local_records.add`). Pinned
    /// byte-for-byte by `tests/frozen_strings_ipc_actions.rs`.
    pub fn action_name(&self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Query { .. } => "query",
            Self::CacheFlush { .. } => "cache.flush",
            Self::Reload { .. } => "reload",
            Self::ForgetList { .. } => "list.forget",
            Self::Shutdown { .. } => "shutdown",
            Self::DomainCount => "domain.count",
            Self::TrackingStats { .. } => "tracking.stats",
            Self::DeviceStats { .. } => "device.stats",
            Self::GetAllDevices => "devices.get_all",
            Self::QueryLogs { .. } => "query.logs",
            Self::DaemonLogs { .. } => "daemon.logs",
            Self::DeviceAdd { .. } => "device.add",
            Self::DeviceUpdate { .. } => "device.update",
            Self::DeviceRemove { .. } => "device.remove",
            Self::DevicePromote { .. } => "device.promote",
            Self::TrackingConfigUpdate { .. } => "tracking.config.update",
            Self::BlocklistStats { .. } => "blocklist.stats",
            Self::LocalRecordsHits => "local_records.hits",
            Self::ProfileCreate { .. } => "profile.create",
            Self::ProfileUpdate { .. } => "profile.update",
            Self::ProfileDelete { .. } => "profile.delete",
            #[cfg(feature = "cluster")]
            Self::ClusterStatus => "cluster.status",
        }
    }

    /// Return the token attached to this command, if any. ReadOnly commands
    /// have no token slot and return `None`.
    pub fn token(&self) -> Option<&str> {
        match self {
            Self::CacheFlush { token, .. }
            | Self::Reload { token }
            | Self::ForgetList { token, .. }
            | Self::Shutdown { token }
            | Self::TrackingStats { token }
            | Self::DeviceStats { token }
            | Self::QueryLogs { token, .. }
            | Self::DaemonLogs { token, .. }
            | Self::DeviceAdd { token, .. }
            | Self::DeviceUpdate { token, .. }
            | Self::DeviceRemove { token, .. }
            | Self::DevicePromote { token, .. }
            | Self::TrackingConfigUpdate { token, .. }
            | Self::ProfileCreate { token, .. }
            | Self::ProfileUpdate { token, .. }
            | Self::ProfileDelete { token, .. } => token.as_deref(),
            Self::Status
            | Self::Query { .. }
            | Self::DomainCount
            | Self::GetAllDevices
            | Self::BlocklistStats { .. }
            | Self::LocalRecordsHits => None,
            #[cfg(feature = "cluster")]
            Self::ClusterStatus => None,
        }
    }

    /// Return a copy of this command with the token field populated (for
    /// variants that have one). ReadOnly commands are returned unchanged.
    ///
    /// Used by the CLI client to attach the auto-discovered token
    /// transparently before sending.
    pub fn with_token(self, t: Option<String>) -> Self {
        match self {
            Self::CacheFlush { domain, .. } => Self::CacheFlush { domain, token: t },
            Self::Reload { .. } => Self::Reload { token: t },
            Self::ForgetList { id, .. } => Self::ForgetList { id, token: t },
            Self::Shutdown { .. } => Self::Shutdown { token: t },
            Self::TrackingStats { .. } => Self::TrackingStats { token: t },
            Self::DeviceStats { .. } => Self::DeviceStats { token: t },
            // Destructured EXHAUSTIVELY on purpose — no `..`. This arm is
            // on the path of every real request (`socket_client::send_command`
            // calls it whenever a token is discovered) and on the path of no
            // unit test, because tests build `IpcCommand` directly. A `..`
            // here silently resets any field it swallows to the value written
            // on the construct side, which is the `build_blocklist_value` /
            // `upsert_id_keyed` class project rules documents. With the wildcard
            // gone, the next field added to the variant fails the build here
            // instead of vanishing on the wire.
            Self::QueryLogs {
                limit,
                client,
                blocked_only,
                domain,
                since_secs,
                cursor,
                advanced,
                token: _,
            } => Self::QueryLogs {
                limit,
                client,
                blocked_only,
                domain,
                since_secs,
                cursor,
                advanced,
                token: t,
            },
            // Exhaustively destructured for the same reason as `QueryLogs`
            // above: this arm runs on every real request and in no unit
            // test, so a `..` would silently reset a swallowed field to
            // whatever the construct side wrote.
            Self::DaemonLogs {
                limit,
                level,
                contains,
                token: _,
            } => Self::DaemonLogs {
                limit,
                level,
                contains,
                token: t,
            },
            Self::DeviceAdd { client, .. } => Self::DeviceAdd { client, token: t },
            Self::DeviceUpdate { name, patch, .. } => Self::DeviceUpdate {
                name,
                patch,
                token: t,
            },
            Self::DeviceRemove { name, .. } => Self::DeviceRemove { name, token: t },
            Self::DevicePromote {
                ip,
                name,
                profile,
                owner,
                device_type,
                department,
                ..
            } => Self::DevicePromote {
                ip,
                name,
                profile,
                owner,
                device_type,
                department,
                token: t,
            },
            Self::TrackingConfigUpdate { patch, .. } => {
                Self::TrackingConfigUpdate { patch, token: t }
            }
            Self::ProfileCreate {
                id, display_name, ..
            } => Self::ProfileCreate {
                id,
                display_name,
                token: t,
            },
            Self::ProfileUpdate { id, patch, .. } => Self::ProfileUpdate {
                id,
                patch,
                token: t,
            },
            Self::ProfileDelete { id, .. } => Self::ProfileDelete { id, token: t },
            #[cfg(feature = "cluster")]
            c @ Self::ClusterStatus => c,
            other @ (Self::Status
            | Self::Query { .. }
            | Self::DomainCount
            | Self::GetAllDevices
            | Self::BlocklistStats { .. }
            | Self::LocalRecordsHits) => other,
        }
    }
}

/// Sprint C T3 of `lists_categories_v2` (§5.4 / §8.5): per-list-state
/// counts the daemon reports back on every `warden status` call so the
/// operator can spot blocklist health at a glance — `Active` is healthy,
/// `Pending` is "never refreshed yet", `Failed` is "max consecutive
/// retries hit", and `stale_over_7d` flags Active lists whose
/// `last_success` predates a 7-day cutoff.
///
/// Counts are computed at status-handler time (cheap walk over
/// `list_state.lists`) — no per-tick caching, so a `warden reload` or
/// a refresh tick that flips a status surfaces immediately on the next
/// status query. Defaults to `Default::default()` (all zeros) when
/// decoded from a pre-Sprint-C daemon, so the CLI keeps rendering an
/// empty section without erroring.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListDiagnostics {
    /// Lists whose latest refresh succeeded — currently contributing
    /// to the filter (D9 stale-cache fallback aside).
    pub active: u32,
    /// Lists that have never completed a successful refresh — fresh
    /// install or refresh task hasn't run yet.
    pub pending: u32,
    /// Lists that have hit `max_consecutive_failures` and flipped to
    /// `Failed`. With a stale `cache_path` (D9) they continue to
    /// protect; without it they contribute nothing.
    pub failed: u32,
    /// Active lists whose `last_success` is older than 7 days — useful
    /// drift signal even when the state machine is happy.
    pub stale_over_7d: u32,
}

/// §4.45 (Hermes T1.8): appended to [`IpcResponse::Ok`]`::message` by
/// device / tracking / profile mutation handlers when their best-effort
/// reload signal was dropped because the capacity-1 reload channel was
/// already full. The on-disk write succeeded; the next reload pass
/// (coalescer drain or schedule tick, ≤ 60s) will pick the change up.
///
/// Exported as a `pub const` so operators, downstream tooling, and
/// integration tests can string-match this exact substring to
/// differentiate "live now" from "queued behind a pending reload"
/// without protocol-shape changes.
pub const RELOAD_PENDING_SUFFIX: &str = "; reload already pending, takes effect within ~60s";

/// Response sent from daemon to CLI via Unix socket.
///
/// Sprint F bumped the `TrackingStats` variant past clippy's
/// `large_enum_variant` heuristic by adding two more `[u64; 10]` arrays
/// for the 24h-rolling QTYPE distributions. The enum is allocated once
/// per IPC reply (not stored in collections), so the stack-size concern
/// the lint guards against doesn't apply here. Boxing the new arrays
/// would force a heap alloc per reply for no real win.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpcResponse {
    /// Daemon status information.
    Status {
        /// PID of the running daemon.
        pid: u32,
        /// Listen address.
        listen: String,
        /// Upstream mode (plain/doh/dot).
        upstream_mode: String,
        /// Number of upstream servers.
        upstream_count: usize,
        /// Number of domains in the filter engine.
        domain_count: usize,
        /// Number of entries in the DNS cache.
        cache_entries: u64,
        /// Number of configured list sources.
        list_count: usize,
        /// Daemon uptime in seconds.
        uptime_secs: u64,
        /// T2.9 / H-20: silent-drop counters for the query-log write
        /// path. `None` when no writer is attached (`query_log_enabled
        /// = false`); `Some(_)` carries the three per-surface
        /// `AtomicU64` snapshots. `#[serde(default)]` so pre-T2.9 CLI
        /// readers decoding a new daemon's response just see `None`,
        /// and a new CLI reading a pre-T2.9 daemon's response sees the
        /// same.
        #[serde(default)]
        query_log_drops: Option<crate::tracking::query_log::QueryLogDropSnapshot>,
        /// §4.19 — daemon binary version (`CARGO_PKG_VERSION` at build
        /// time). Empty string when decoded from a pre-§4.19 daemon.
        #[serde(default)]
        version: String,
        /// §4.19 — configured weighted cache capacity
        /// (`cache.max_entries`). 0 when decoded from a pre-§4.19
        /// daemon — the dashboard's existing `cache_capacity`
        /// extrapolation is the legacy fallback.
        #[serde(default)]
        cache_cap: u64,
        /// mem2608-s3 — flushed weighted cache occupancy
        /// (`DnsCache::flushed_usage().weighted_size`), directly
        /// comparable to `cache_cap` — both are moka weight units, not
        /// entry counts (`dns::cache::DnsCache::new`: positive entries
        /// cost 10 units, negative cost 1). `cache_entries` stays a raw
        /// count and is NOT comparable to `cache_cap`; this field is.
        /// 0 when decoded from a pre-mem2608-s3 daemon, same fallback
        /// convention as `cache_cap` above.
        #[serde(default)]
        cache_weighted_size: u64,
        /// §4.19 — number of blocklist sources that completed their
        /// most recent refresh successfully (`LastOutcome::Ok`). 0 when
        /// decoded from a pre-§4.19 daemon.
        #[serde(default)]
        lists_active: u32,
        /// §4.19 — total number of configured blocklist sources
        /// (registry slot count). 0 when decoded from a pre-§4.19
        /// daemon — `list_count` is the legacy fallback.
        #[serde(default)]
        lists_total: u32,
        /// Number of blocklist sources whose most recent refresh hit the
        /// `max_entries` cap and dropped entries on the floor.
        ///
        /// Distinct from `lists_active` on purpose: a truncated source is
        /// *also* active — it fetched, it parsed, it reported `Ok`. That
        /// is exactly why the old `lists: 8/8 sources active` line could
        /// print while 19% of the corpus was missing, and why this needs
        /// its own counter rather than a tweak to the active tally.
        ///
        /// 0 when decoded from a daemon that predates the counter, which
        /// is indistinguishable from "nothing truncated" — acceptable,
        /// since the alternative is failing the status call outright.
        #[serde(default)]
        lists_truncated: u32,
        /// Set when the last refresh cycle was refused outright because
        /// the merged **deduplicated** corpus exceeded
        /// `[lists] max_total_domains`.
        ///
        /// Needs its own channel for the same reason `lists_truncated`
        /// does, only more so: in this state every source fetched, parsed
        /// and reported `Ok`, so `lists_active`/`lists_total` reads `N/N`
        /// while the daemon serves the *previous* generation. No
        /// per-source field can express a cycle-level outcome.
        ///
        /// `None` when decoded from a daemon that predates the guard,
        /// which is indistinguishable from "nothing refused" — the same
        /// trade-off `lists_truncated` already makes, and the same reason:
        /// the alternative is failing the status call outright.
        #[serde(default)]
        lists_corpus_refusal: Option<crate::lists::status::CorpusRefusal>,
        /// The last completed list-reload cycle: a monotonic sequence number
        /// and what that cycle did. Lets a caller that triggered a refresh
        /// wait for *its own* cycle and then report the outcome, instead of
        /// signalling and claiming success about work that has not happened.
        ///
        /// **`Option`, and it must stay one.** `None` here means "this daemon
        /// does not report cycles" — an older build. A bare `CycleMark` would
        /// default to `seq: 0`, which is byte-identical to "no cycle has
        /// completed yet", so a new CLI against an old daemon would wait for a
        /// counter that is never going to move and burn its whole timeout on
        /// every single refresh. With `None` the caller can tell "cannot
        /// answer" from "has not answered yet" and fall back cleanly.
        #[serde(default)]
        lists_cycle: Option<crate::lists::status::CycleMark>,
        /// Sprint C T3 of `lists_categories_v2` (§5.4 / §8.5): per-
        /// state counts (Active / Pending / Failed / Stale > 7d)
        /// derived from `data/list_state.toml`. Default-empty when
        /// decoded from a pre-Sprint-C daemon — the CLI's "Lists:"
        /// section in `warden status` still renders cleanly with the
        /// zero counts, just no health signal.
        #[serde(default)]
        lc2_list_diagnostics: ListDiagnostics,
        /// §4.13 — sampled daemon resource footprint (RSS / VSZ / fd
        /// count / user-mode CPU%) plus the configured `rss_warn_mb`
        /// threshold so the TUI can colourise without re-reading
        /// config. `None` when the sampler hasn't produced a first
        /// sample yet OR when decoded from a pre-§4.13 daemon (the
        /// `#[serde(default)]` collapses both cases to `None`).
        #[serde(default)]
        resource_budget: Option<crate::resource_budget::ResourceBudgetSnapshot>,
    },
    /// Result of a domain query check.
    QueryResult {
        domain: String,
        blocked: bool,
        /// §4.2 G1a — block attribution: what caused the block, as a
        /// stable `kind:value` string (`list:<name>`, `rule:<pattern>`)
        /// or a bare kind (`admin_block`, `cname_loop`,
        /// `cname_depth_exceeded`) built from
        /// [`crate::filter::cname::BlockSource::describe`]. `None` for
        /// allowed domains and for blocks with no profile context.
        /// `#[serde(default)]` keeps pre-G1a CLI/TUI clients parsing a
        /// new daemon's reply, and a new client reading a pre-G1a
        /// daemon sees `None`; `skip_serializing_if` omits it on the
        /// allowed path so the wire stays minimal.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        blocked_by: Option<String>,
    },
    /// Generic success response.
    Ok { message: String },
    /// §4.7 Phase 2 T1: ack for `IpcCommand::ForgetList`. `was_cached`
    /// echoes whether the source had any in-memory or on-disk state
    /// before the call — `false` is the idempotent / no-op case, not
    /// an error.
    ListForgotten { id: String, was_cached: bool },
    /// Domain count response.
    DomainCount { count: usize },
    /// Tracking stats (global + top-N + time-series).
    TrackingStats {
        queries_total: u64,
        blocked_total: u64,
        blocked_pct: f64,
        cache_hit_rate: f64,
        /// Subset of cache hits served from negative entries (NXDOMAIN/NODATA).
        /// Defaults to 0 when deserializing responses from pre-Sprint-25 daemons.
        #[serde(default)]
        cache_negative_hits: u64,
        uptime_secs: u64,
        top_blocked: Vec<DomainCount>,
        top_queried: Vec<DomainCount>,
        hourly: Vec<TimeBucketDto>,
        daily: Vec<TimeBucketDto>,
        /// Rolling 24-hour averages computed from the hourly buckets.
        /// Match the same units as `cache_hit_rate` / `blocked_pct` (0–100).
        /// Default to 0.0 for pre-Sprint-27 daemons.
        #[serde(default)]
        cache_hit_rate_24h: f64,
        #[serde(default)]
        blocked_pct_24h: f64,
        /// Delta between the most recent hour and the previous hour,
        /// expressed in the same percentage-point units. Positive means
        /// the most recent hour was higher than the one before. Default
        /// to 0.0 for pre-Sprint-27 daemons.
        #[serde(default)]
        cache_hit_rate_delta_1h: f64,
        #[serde(default)]
        blocked_pct_delta_1h: f64,
        /// §4.6 per-`TypeBucket` query distribution in canonical bucket
        /// order (`A, AAAA, TXT, PTR, NS, SOA, SRV, SVCB, HTTPS, Other`).
        /// Defaults to all-zero on pre-§4.6 daemons so a freshly-upgraded
        /// CLI/TUI can still parse responses from an older `warden`.
        #[serde(default = "zero_qtype_distribution")]
        qtype_distribution: [u64; crate::tracking::TYPE_BUCKET_COUNT],
        /// Sprint E per-`TypeBucket` BLOCKED query distribution. Same
        /// canonical bucket order as `qtype_distribution`. Defaults to
        /// all-zero on pre-Sprint-E daemons so the QTYPE chart card
        /// shows only the Total bar (Blocked bar muted) until both ends
        /// of the wire are upgraded.
        #[serde(default = "zero_qtype_distribution")]
        qtype_blocked_distribution: [u64; crate::tracking::TYPE_BUCKET_COUNT],
        /// Sprint F — same shape as `qtype_distribution` but summed over
        /// the trailing 24 hourly buckets (rolling window) rather than
        /// cumulative-since-daemon-start. Drives the Dashboard QTYPE
        /// chart card so the bars stay proportional to live activity
        /// even on long-running daemons. Defaults to all-zero on
        /// pre-Sprint-F daemons; the chart falls back to its cold-start
        /// `collecting…` placeholder until both ends of the wire are
        /// upgraded.
        #[serde(default = "zero_qtype_distribution")]
        qtype_distribution_24h: [u64; crate::tracking::TYPE_BUCKET_COUNT],
        /// Sprint F — same shape as `qtype_blocked_distribution` but
        /// summed over the trailing 24 hourly buckets. Drives the
        /// Blocked bar of the QTYPE chart card. Defaults to all-zero
        /// on pre-Sprint-F daemons.
        #[serde(default = "zero_qtype_distribution")]
        qtype_blocked_distribution_24h: [u64; crate::tracking::TYPE_BUCKET_COUNT],
        /// Sprint §4.4 P1 — domains currently in the prefetch hit-tracker
        /// pool. Defaults to 0 on pre-§4.4 daemons. Phase 1/2 surfaces
        /// this purely for visibility; the Phase 2/2 background refresh
        /// worker will be the first DNS-side consumer.
        #[serde(default)]
        prefetch_pool_size: u32,
        /// Cumulative prefetch promotions since the tracker was last
        /// reset. Defaults to 0 on pre-§4.4 daemons.
        #[serde(default)]
        prefetch_promotions_total: u64,
        /// Cumulative prefetch demotions since the tracker was last
        /// reset. Defaults to 0 on pre-§4.4 daemons.
        #[serde(default)]
        prefetch_demotions_total: u64,
        /// Sprint B Dashboard v2 — top-5 Tier 1 blocklists by recent
        /// block count. The label is resolved daemon-side via the
        /// `bit → "scope/topic"` snapshot built at start.rs from
        /// `source_bits.iter_urls()` × `Catalog::entries()`. Empty on
        /// pre-Sprint-B daemons (`#[serde(default)]`), so a TUI
        /// without this field renders the placeholder "collecting…"
        /// instead of breaking.
        #[serde(default)]
        top_blocked_lists: Vec<ListBlockCount>,
        /// 24h-rolling Top-N by per-domain block count. Each
        /// `DomainCount` carries both lifetime `count` and
        /// `count_24h`; the rank order is by `count_24h`. Empty on
        /// pre-Sprint-N daemons (`#[serde(default)]`), so the TUI
        /// renders the row-4 `Top Blocked Domains (24h)` card as
        /// `collecting…` until the daemon ships.
        #[serde(default)]
        top_blocked_24h: Vec<DomainCount>,
        /// 24h-rolling Top-N by per-domain query count. Mirror of
        /// `top_blocked_24h` for the narrow-fallback layout.
        #[serde(default)]
        top_queried_24h: Vec<DomainCount>,
        /// 24h-rolling Top-5 lists by block count. Same labelling
        /// discipline as `top_blocked_lists`. Empty on pre-Sprint-N
        /// daemons.
        #[serde(default)]
        top_blocked_lists_24h: Vec<ListBlockCount>,
    },
    /// Per-device stats table. The `clients` field name on the wire is
    /// retained for T5 decode-compat with pre-T5 CLI readers.
    #[serde(alias = "client_list")]
    DeviceList { clients: Vec<DeviceStatEntry> },
    /// Mapped + unmapped device view (Sprint 22 `GetAllDevices`).
    #[serde(alias = "client_view")]
    DeviceView(DeviceViewDto),
    /// Query log entries plus the state the TUI needs to render a
    /// useful empty-state message. `logging_enabled` mirrors
    /// `tracking.query_log_enabled`; `file_state` records the outcome of
    /// the on-disk read so the TUI can distinguish "disabled" from
    /// "empty" from "file unreadable". Sprint 37 wire break: CLI and
    /// daemon must be released in lockstep — no `PROTOCOL_VERSION`
    /// constant exists yet in this codebase. T5 adds `#[serde(alias)]`
    /// on renamed variants to give one release cycle of decode-compat
    /// per §3 R1.
    QueryLogs {
        entries: Vec<QueryLogDto>,
        logging_enabled: bool,
        file_state: QueryLogFileState,
        /// `qlog-paging-cursor`: resume point for the next (older) page.
        /// `None` means the walk reached the end of the retained window.
        /// `#[serde(default)]` lets a pre-paging daemon's response decode.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        next_cursor: Option<crate::tracking::query_log::QueryLogCursor>,
        /// The `cursor` sent with the request named a file that had
        /// rotated under it, so this page is the live tail. The TUI
        /// resets its page index and says so.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        cursor_stale: bool,
    },
    /// `logs-tab`: reply to [`IpcCommand::DaemonLogs`]. Newest entry
    /// first.
    DaemonLogs {
        entries: Vec<DaemonLogDto>,
        /// Events discarded because a producer found the ring's lock
        /// held. Surfaced so a gap in the operator's pane is visible
        /// rather than silent — the capture path drops rather than
        /// blocks, and that trade has to be legible.
        #[serde(default)]
        dropped: u64,
        /// Ring capacity, so the TUI can say "showing N of at most C"
        /// instead of implying it holds everything the daemon ever said.
        #[serde(default)]
        capacity: usize,
    },
    /// Sprint 43 T1: per-blocklist runtime telemetry. List length is
    /// `1` when `source_id = Some(_)` resolved a match; the full source
    /// list otherwise. Order matches `[lists].sources` for the all-
    /// sources case (so the operator's TUI table renders top-to-bottom
    /// in the same order as their config file).
    BlocklistStatsList {
        stats: Vec<crate::lists::status::BlocklistStatusDto>,
    },
    /// Sprint 44 follow-up (`s44-hits-ipc-verb`): per-record local-DNS
    /// hit-count snapshot. Order matches the daemon-side DashMap
    /// iteration which is unspecified — the TUI builds its own
    /// `(scope, domain) → count` lookup at render time.
    LocalRecordsHitsList { entries: Vec<LocalRecordsHitEntry> },
    /// §4.11-4 (CS9): reply to [`IpcCommand::ClusterStatus`]. Carries the whole
    /// view as one DTO (reused by the 4b dashboard dot + Cluster tab).
    /// `cluster`-feature only.
    #[cfg(feature = "cluster")]
    ClusterStatus { status: ClusterStatusDto },
    /// Error response.
    Error { message: String },
}

/// §4.11-4 (CS9): this node's cluster view, as returned over IPC. On a
/// secondary the `roster` is empty and the `last_*` / `converged` fields carry
/// the poll telemetry; on a primary the secondary-only fields are inert and
/// `roster` holds the self-row + every connected peer. `cluster`-feature only.
#[cfg(feature = "cluster")]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClusterStatusDto {
    /// `false` ⇒ this node isn't an active cluster member (disabled, or this
    /// daemon lacks an observe handle); the rest is default and the CLI prints
    /// the standalone hint.
    pub enabled: bool,
    /// `"primary"` / `"secondary"`.
    pub role: String,
    /// The primary's base URL a secondary polls (`None` on a primary).
    pub peer: Option<String>,
    /// Policy bundle generation (primary's authoritative counter; 0 on a
    /// secondary, which tracks hashes not generations).
    pub config_generation: u64,
    /// Current policy content hash (primary) / last-applied (secondary).
    pub config_hash: String,
    /// Secondary: seconds since the last *successful* sync; `None` if never.
    pub last_sync_secs: Option<u64>,
    /// Secondary: whether the most recent poll tick succeeded.
    pub last_poll_ok: bool,
    /// Secondary: the most recent poll error (`None` after a success).
    pub last_error: Option<String>,
    /// Secondary: `true` once synced at least once AND the last poll was ok.
    pub converged: bool,
    /// Primary: self-row first, then connected peers. Empty on a secondary.
    pub roster: Vec<RosterEntryDto>,
}

/// §4.11-4 (CS9): one roster row — a node's identity + workload + contribution
/// weight, as computed by [`crate::cluster::observe`]. `cluster`-feature only.
#[cfg(feature = "cluster")]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RosterEntryDto {
    /// `node_name` if advertised, else the address (or "this node" for self).
    pub name: String,
    /// Source IP, or `"local"` for the self-row.
    pub addr: String,
    /// `true` for the local node's own row.
    pub is_self: bool,
    /// `true` when the last sample is within the stale window (always true for
    /// self).
    pub online: bool,
    pub total_queries: u64,
    pub total_blocked: u64,
    /// Windowed queries/sec from the sample delta.
    pub qps: f64,
    /// Block rate over the latest cumulative sample.
    pub blocked_pct: f64,
    /// Share of Σ(qps over online nodes), as a percentage.
    pub share_pct: f64,
}

/// Sprint 44 follow-up (`s44-hits-ipc-verb`): one row of the local-DNS
/// hit-count snapshot.
///
/// `scope` is the operator-facing tag — `"global"` for the
/// `[[local_dns.records]]` table, or `"profile:<id>"` for a single
/// profile's `Profile.local_records` array. The shape mirrors
/// `LocalRecordsScopeKey::as_display()` byte-for-byte so the TUI's
/// `(scope_tag, domain)` lookup is a plain string compare and the
/// daemon enum stays internal (no `LocalRecordsScopeKey` over the wire).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalRecordsHitEntry {
    pub scope: String,
    pub domain: String,
    pub count: u64,
}

/// `#[serde(default)]` helper for the §4.6 `qtype_distribution` field —
/// returns the canonical 10-bucket all-zero array. Standalone fn because
/// serde cannot derive `Default` for arbitrary array lengths.
fn zero_qtype_distribution() -> [u64; crate::tracking::TYPE_BUCKET_COUNT] {
    [0; crate::tracking::TYPE_BUCKET_COUNT]
}

/// Asynchronous notification published by the daemon to interested
/// subscribers. Distinct from [`IpcResponse`] — notifications are
/// fire-and-forget; the publisher does not await an ack.
///
/// Sprint 43 T2 introduces the enum + the publishing channel
/// ([`tokio::sync::broadcast`]). The subscriber transport (a long-poll
/// IPC verb that streams notifications back over the same socket
/// protocol) is deferred to T3 once a real consumer drives the
/// concrete shape — the existing request/response socket model would
/// otherwise constrain the design prematurely. Until then, TUI and
/// CLI consumers fall back to the 30 s lazy poll on
/// [`IpcCommand::BlocklistStats`] (acceptance §6).
///
/// New variants must remain serde-stable across releases — once a
/// subscriber endpoint exists in T3+, every payload shape becomes a
/// wire contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpcNotification {
    /// Fired once per list refresh completion (success OR failure).
    /// `id` is the verbatim source string the manager refreshed —
    /// legacy slug-form (`"privacy/ads"`) or raw URL — matching the
    /// keys in [`crate::lists::status::ListStatusRegistry`].
    /// Subscribers re-fetch via `IpcCommand::BlocklistStats` to read
    /// the new payload; the notification carries no body so the wire
    /// format stays small under high-update load.
    ListStatsUpdated { id: String },
}

/// Domain + hit count pair (for top-N lists).
///
/// `scope` is the category of the list that caused the block
/// (`privacy` / `security` / `content` / `services`), derived from the
/// source-id prefix (`privacy/ads` → `privacy`). Optional because the
/// daemon is allowed to ship the field empty until the filter-engine
/// scope resolver is wired in; the TUI tally renders a "pending" state
/// when all entries are `None`. Backward-compatible via `#[serde(default)]`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DomainCount {
    pub domain: String,
    pub count: u64,
    /// 24h-rolling block (or query) count for this domain. Drives the
    /// Dashboard row-4 cards retitled to `(24h)`. Defaults to 0 on
    /// pre-Sprint-N daemons so the TUI sees an empty list and renders
    /// the `collecting…` placeholder instead of misleading zeros.
    #[serde(default)]
    pub count_24h: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// Sprint B Dashboard v2 — one entry of `top_blocked_lists`. The label
/// is resolved daemon-side via the `bit → "scope/topic"` snapshot built
/// at start.rs from `source_bits.iter_urls()` × `Catalog::entries()`.
/// The TUI receives ready-to-render strings; bit numbers stay
/// daemon-internal (D8 in `_docs/features/dashboard_v2.md`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListBlockCount {
    pub label: String,
    pub count: u64,
    /// 24h-rolling block count for this list. See `DomainCount.count_24h`
    /// for the back-compat semantics.
    #[serde(default)]
    pub count_24h: u64,
}

/// Time-series bucket DTO (for hourly/daily stats).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TimeBucketDto {
    pub timestamp: u64,
    pub queries: u64,
    pub blocked: u64,
    pub cache_hits: u64,
}

/// Per-device stats entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeviceStatEntry {
    pub name: String,
    pub ip: String,
    pub queries: u64,
    pub blocked: u64,
    pub blocked_pct: f64,
    pub cache_hits: u64,
    pub profile: String,
    pub last_seen: u64,
}

/// Full device view response body — mapped devices come from v1
/// `[[devices]]` joined with live stats, unmapped devices come from
/// observed IPs that never appeared in config. SN3 removed the legacy
/// `block_unmapped` flag; the TUI now reads the effective "unmapped →
/// REFUSED" behaviour by checking whether `server.default_profile` is
/// unset.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeviceViewDto {
    pub mapped: Vec<MappedDeviceDto>,
    pub unmapped: Vec<UnmappedDeviceDto>,
}

/// A configured device joined with its live stats. Counters are 0 if
/// the device is configured but has never sent a query since startup.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MappedDeviceDto {
    pub ip: String,
    pub name: String,
    /// MAC pin from `[[devices]]` config (uppercase normalized). `None`
    /// when the operator didn't pin one.
    pub mac: Option<String>,
    /// Additional MACs this device uses — iOS / Android / macOS
    /// randomisation can rotate the active MAC over weeks. Uppercase
    /// normalized. Empty when the device has only a primary MAC or
    /// no MAC at all. `#[serde(default)]` keeps the wire format
    /// backward-compatible with pre-Sprint-27 daemons.
    #[serde(default)]
    pub mac_aliases: Vec<String>,
    pub profile: String,
    pub owner: Option<String>,
    #[serde(default, alias = "device")]
    pub device_type: Option<String>,
    pub department: Option<String>,
    pub queries: u64,
    /// Queries since the start of the current calendar day (UTC). Used
    /// by the Dashboard's Top Devices card. Defaults to 0 so older
    /// daemons (pre-2026-04-29) deserialize cleanly into newer DTOs.
    #[serde(default)]
    pub queries_today: u64,
    pub blocked: u64,
    /// Sum of the last 24h of BLOCKED queries for this device. Drives
    /// the Dashboard Top Devices (24h) card. `#[serde(default)]` keeps
    /// pre-Sprint-N daemons forward-compatible — older payloads default
    /// to 0, which the TUI treats as "no 24h data" and falls back to
    /// the `collecting…` placeholder on the card.
    #[serde(default)]
    pub blocked_24h: u64,
    pub cache_hits: u64,
    pub last_seen: u64,
    /// Whether the device is "online now" — last_seen within
    /// `tracking::engine::ONLINE_WINDOW_SECS` of the daemon's clock
    /// at the moment the response was built.
    pub online: bool,
    /// MAC OUI vendor name resolved at IPC build time via the
    /// disk-resident `oui::OuiTable`. `None` when the daemon has no
    /// OUI table loaded, the MAC is missing, or the prefix isn't in
    /// the registry. Locally-administered MACs (iOS / Android
    /// randomization) get the literal `(randomized)` so the TUI can
    /// distinguish them from "lookup failed". `#[serde(default)]`
    /// keeps older daemons forward-compatible with newer TUI clients.
    #[serde(default)]
    pub vendor: Option<String>,
    /// Group memberships (v1 `Device.groups: Vec<Id>` projected to
    /// strings), in the file's order — `DeviceIndex.groups` is
    /// `dev.groups.clone()` and nothing sorts it. The TUI Edit form
    /// seeds its multi-select from this list and sends it back whole.
    /// `#[serde(default)]` for back-compat with pre-S44 daemons.
    #[serde(default)]
    pub groups: Vec<String>,
    /// Free-form operator memo (v1 `Device.notes`). The daemon never
    /// reads this — pure metadata. `#[serde(default)]` for back-compat.
    #[serde(default)]
    pub notes: Option<String>,
    /// Bare DNS name this device answers to, if any (2026-08-10 device-
    /// network-name design spec). `#[serde(default)]` keeps the wire
    /// format compatible with pre-this-feature daemons.
    #[serde(default)]
    pub network_name: Option<String>,
    #[serde(default)]
    pub network_name_wildcard: bool,
    /// Stable v1 identifier (`Device.id`). The TUI uses this as the
    /// IPC key for Update / Remove instead of the operator-typed
    /// `name` (which is `display_name`) — display names can be edited
    /// freely and may diverge from `slug(name)`, so identifying by
    /// derived slug is wrong. `#[serde(default)]` keeps pre-S44
    /// daemons forward-compatible (older payloads omit the field; the
    /// TUI then falls back to the slug-derived id, matching the
    /// previous behaviour).
    #[serde(default)]
    pub id: Option<String>,
    /// Per-hour query counts for the last 24 hours, oldest-first
    /// (`hourly_queries[0]` = "23 hours ago", `[23]` = current hour).
    /// Drives the Devices tab side-card sparkline. Empty when the
    /// daemon doesn't expose the ring (pre-S44) or when no queries
    /// have been recorded for this device. `#[serde(default)]` keeps
    /// older daemons forward-compatible.
    #[serde(default)]
    pub hourly_queries: Vec<u64>,
    /// Sprint C T4 of `lists_categories_v2` (D14, §8.1): D14 opt-out
    /// flag. When `true`, the resolver short-circuits filtering for
    /// this device but keeps monitoring active. Surfaced as the
    /// `[⚠ UNFILTERED]` badge on the Devices tab card. Defaults to
    /// `false` for back-compat with pre-Sprint-C daemons.
    #[serde(default)]
    pub unfiltered: bool,
}

/// An observed device that is NOT in `[[devices]]`. Has live counters
/// and a best-effort MAC from the ARP table (may be missing for fresh
/// devices outside the local L2 segment).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UnmappedDeviceDto {
    pub ip: String,
    /// Best-effort MAC from the current ARP snapshot. `None` when the
    /// device has not yet been ARP-resolved.
    pub mac: Option<String>,
    pub queries: u64,
    /// Queries since the start of the current calendar day (UTC).
    /// `#[serde(default)]` for back-compat with older daemons.
    #[serde(default)]
    pub queries_today: u64,
    pub blocked: u64,
    /// Sum of the last 24h of BLOCKED queries for this device. See
    /// `MappedDeviceDto::blocked_24h` for the full back-compat contract.
    #[serde(default)]
    pub blocked_24h: u64,
    pub last_seen: u64,
    pub online: bool,
    /// MAC OUI vendor name (see `MappedDeviceDto::vendor` for the
    /// full contract). `#[serde(default)]` for back-compat.
    #[serde(default)]
    pub vendor: Option<String>,
    /// Per-hour queries for the last 24h, oldest-first. Same contract
    /// as `MappedDeviceDto::hourly_queries`.
    #[serde(default)]
    pub hourly_queries: Vec<u64>,
}

/// Outcome of the daemon's attempt to read the query-log file. Paired
/// with `logging_enabled` on `IpcResponse::QueryLogs`, it drives the
/// TUI's four-way empty-state picker (see Sprint 37 §3 D4).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum QueryLogFileState {
    /// File exists and was read successfully.
    Ok,
    /// Path resolved but no file on disk (fresh install, nothing
    /// written yet, or writer has not yet flushed).
    Missing,
    /// Path resolved but reading failed (permissions, I/O error). The
    /// daemon logs the underlying error via `tracing::warn!`.
    Unreadable,
}

/// Everything one query-log read needs, as a single value.
///
/// **Not a wire type** — `IpcCommand::QueryLogs` stays flat so the JSON
/// shape is unchanged. This is the *call* shape, shared by the daemon
/// handler and the TUI poller.
///
/// It exists because both of those functions crossed seven parameters
/// once paging and the advanced form landed, and a parameter list that
/// grows by one per feature is a request object that has not been
/// admitted yet: every caller has to keep seven positional arguments in
/// the right order, and adding an eighth silently re-orders nothing but
/// makes every call site harder to read. Bundling them also means the
/// next dimension (Tier 2's resolved client-IP set) adds a field rather
/// than another argument to thread through two signatures.
#[derive(Debug, Clone, Default)]
pub struct QueryLogRequest {
    pub limit: usize,
    pub client: Option<String>,
    pub blocked_only: bool,
    pub domain: Option<String>,
    pub since_secs: Option<u64>,
    /// `None` reads the live tail.
    pub cursor: Option<crate::tracking::query_log::QueryLogCursor>,
    /// `None` when the operator has not used the advanced form.
    pub advanced: Option<AdvancedClientFilterDto>,
}

/// Wire form of the Query Log's Tier-1 advanced client filter.
///
/// **Deliberately flat.** Three optional patterns, each paired with a
/// boolean polarity, rather than a `Vec` of tagged predicate objects: the
/// dimension set is closed by operator decision (MAC was dropped, and
/// owner / department / device-type are Tier 2 and need a Labels join
/// resolved *before* the walk), so a flat record says exactly what exists
/// and needs no discriminant to decode.
///
/// `*_exclude` inverts its own predicate. Predicates are ANDed; there is
/// no OR — see [`crate::tracking::query_log::Polarity`] for why.
///
/// Every field is `#[serde(default)]`, so a pre-form caller that omits
/// the whole object and a caller that sends a partly-filled one both
/// decode to "filter on what is present".
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdvancedClientFilterDto {
    /// Glob over `client_name` (`*` only, never regex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub name_exclude: bool,
    /// Glob over the textual `client_ip`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ip_exclude: bool,
    /// CIDR tested against `client_ip` directly — NOT resolved to a set of
    /// known device IPs, which would drop unmapped devices in the subnet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subnet: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub subnet_exclude: bool,
}

impl AdvancedClientFilterDto {
    /// Nothing to filter on. A blank form must not install a predicate
    /// that matches everything or nothing.
    pub fn is_empty(&self) -> bool {
        self.name.as_ref().is_none_or(|s| s.trim().is_empty())
            && self.ip.as_ref().is_none_or(|s| s.trim().is_empty())
            && self.subnet.as_ref().is_none_or(|s| s.trim().is_empty())
    }

    /// Compile to the walker's already-parsed form. Every glob is built
    /// and every CIDR parsed exactly once, here.
    pub fn compile(&self) -> crate::tracking::query_log::AdvancedFilter {
        use crate::tracking::query_log::{AdvancedFilter, Polarity};
        let pol = |ex: bool| {
            if ex {
                Polarity::Exclude
            } else {
                Polarity::Include
            }
        };
        let mut out = AdvancedFilter::default();
        if let Some(n) = self
            .name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            out = out.with_name(n, pol(self.name_exclude));
        }
        if let Some(i) = self.ip.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            out = out.with_ip(i, pol(self.ip_exclude));
        }
        if let Some(sn) = self
            .subnet
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            out = out.with_subnets([sn], pol(self.subnet_exclude));
        }
        out
    }
}

/// Query log entry DTO.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QueryLogDto {
    pub timestamp: String,
    pub client_ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    pub domain: String,
    pub query_type: String,
    pub result: String,
    pub response_time_us: u64,
    /// §4.5 Sprint 2/2 — mirrors `QueryLogEntry::cname_chain_via`. `Some(hop)`
    /// when the row is a CNAME chain block; the TUI renders the row as
    /// `domain → hop` plus a `[CNAME]` badge. `None` otherwise. Back-compat
    /// via `#[serde(default)]` so older daemons / older tail JSONLs read
    /// back unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cname_chain_via: Option<String>,
}

/// One captured `tracing` event, as it crosses the wire.
///
/// `timestamp` is formatted daemon-side in the same
/// `YYYY-MM-DDTHH:MM:SSZ` shape [`QueryLogDto`] uses, so the TUI renders
/// both tables with one convention.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonLogDto {
    pub timestamp: String,
    pub level: crate::tracking::log_ring::LogLevel,
    /// Module path of the emitting callsite (`purge_warden::lists::manager`).
    /// Structured metadata, not a parsed prefix — it costs nothing to
    /// carry and it is the honest second dimension for "which subsystem
    /// said this".
    pub target: String,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_status_roundtrip() {
        let cmd = IpcCommand::Status;
        let json = serde_json::to_string(&cmd).unwrap();
        assert_eq!(json, r#"{"type":"status"}"#);
        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, cmd);
    }

    #[test]
    fn command_query_roundtrip() {
        let cmd = IpcCommand::Query {
            domain: "google.com".into(),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"domain\":\"google.com\""));
        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, cmd);
    }

    #[test]
    fn command_cache_flush_all_roundtrip() {
        let cmd = IpcCommand::CacheFlush {
            domain: None,
            token: None,
        };
        let json = serde_json::to_string(&cmd).unwrap();
        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, cmd);
    }

    #[test]
    fn command_cache_flush_domain_roundtrip() {
        let cmd = IpcCommand::CacheFlush {
            domain: Some("example.com".into()),
            token: None,
        };
        let json = serde_json::to_string(&cmd).unwrap();
        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, cmd);
    }

    #[test]
    fn response_status_roundtrip() {
        let resp = IpcResponse::Status {
            pid: 1234,
            listen: "127.0.0.1:15353".into(),
            upstream_mode: "plain".into(),
            upstream_count: 2,
            domain_count: 500_000,
            cache_entries: 1234,
            list_count: 3,
            uptime_secs: 3600,
            query_log_drops: None,
            version: String::new(),
            cache_cap: 0,
            lists_active: 0,
            lists_total: 0,
            lists_truncated: 0,
            lists_corpus_refusal: None,
            lists_cycle: None,
            lc2_list_diagnostics: ListDiagnostics::default(),
            resource_budget: None,
            cache_weighted_size: 0,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, resp);
    }

    /// T2.9 / H-20: a pre-T2.9 daemon's `Status` payload (without
    /// `query_log_drops`) must still decode into the new struct shape
    /// thanks to `#[serde(default)]`. Pins the wire-back-compat
    /// guarantee for the freeze period before CLI/daemon are released
    /// in lockstep.
    #[test]
    fn response_status_legacy_without_drop_counters_deserializes() {
        let legacy = r#"{"type":"status","pid":1,"listen":"127.0.0.1:53","upstream_mode":"plain","upstream_count":1,"domain_count":0,"cache_entries":0,"list_count":0,"uptime_secs":0}"#;
        let parsed: IpcResponse = serde_json::from_str(legacy).unwrap();
        match parsed {
            IpcResponse::Status {
                query_log_drops, ..
            } => assert!(query_log_drops.is_none()),
            other => panic!("expected Status, got {other:?}"),
        }
    }

    /// T2.9 / H-20: a fresh-daemon `Status` payload carries the new
    /// `query_log_drops: Some(_)` field intact through round-trip.
    #[test]
    fn response_status_with_drop_counters_roundtrip() {
        use crate::tracking::query_log::QueryLogDropSnapshot;
        let resp = IpcResponse::Status {
            pid: 1234,
            listen: "127.0.0.1:15353".into(),
            upstream_mode: "plain".into(),
            upstream_count: 2,
            domain_count: 500_000,
            cache_entries: 1234,
            list_count: 3,
            uptime_secs: 3600,
            query_log_drops: Some(QueryLogDropSnapshot {
                channel_full: 7,
                flush_open_errors: 1,
                flush_write_errors: 42,
            }),
            version: String::new(),
            cache_cap: 0,
            lists_active: 0,
            lists_total: 0,
            lists_truncated: 0,
            lists_corpus_refusal: None,
            lists_cycle: None,
            lc2_list_diagnostics: ListDiagnostics::default(),
            resource_budget: None,
            cache_weighted_size: 0,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"channel_full\":7"));
        assert!(json.contains("\"flush_write_errors\":42"));
        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, resp);
    }

    /// §4.19 — a pre-§4.19 daemon's Status payload (without `version`,
    /// `cache_cap`, `lists_active`, `lists_total`) must still decode
    /// thanks to `#[serde(default)]`. Pins back-compat for the freeze
    /// period before CLI/daemon are released in lockstep.
    #[test]
    fn response_status_legacy_without_s419_fields_deserializes() {
        let legacy = r#"{"type":"status","pid":1,"listen":"127.0.0.1:53","upstream_mode":"plain","upstream_count":1,"domain_count":0,"cache_entries":0,"list_count":0,"uptime_secs":0}"#;
        let parsed: IpcResponse = serde_json::from_str(legacy).unwrap();
        match parsed {
            IpcResponse::Status {
                version,
                cache_cap,
                lists_active,
                lists_total,
                lists_truncated,
                ..
            } => {
                assert_eq!(version, "");
                assert_eq!(cache_cap, 0);
                assert_eq!(lists_active, 0);
                assert_eq!(lists_total, 0);
                // The truncation counter joins the same back-compat
                // contract: a CLI built with it must not fail to read a
                // daemon built without it.
                assert_eq!(lists_truncated, 0);
            }
            other => panic!("expected Status, got {other:?}"),
        }
    }

    /// §4.19 — a fresh-daemon Status payload carries the new fields
    /// intact through round-trip with realistic values.
    #[test]
    fn response_status_s419_fields_roundtrip() {
        let resp = IpcResponse::Status {
            pid: 1234,
            listen: "127.0.0.1:15353".into(),
            upstream_mode: "plain".into(),
            upstream_count: 2,
            domain_count: 500_000,
            cache_entries: 1234,
            list_count: 8,
            uptime_secs: 3600,
            query_log_drops: None,
            version: "0.7.4".into(),
            cache_cap: 10_000,
            lists_active: 7,
            lists_total: 8,
            lists_truncated: 0,
            lists_corpus_refusal: None,
            lists_cycle: None,
            lc2_list_diagnostics: ListDiagnostics::default(),
            resource_budget: None,
            cache_weighted_size: 4_120,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"version\":\"0.7.4\""));
        assert!(json.contains("\"cache_cap\":10000"));
        assert!(json.contains("\"lists_active\":7"));
        assert!(json.contains("\"lists_total\":8"));
        assert!(json.contains("\"cache_weighted_size\":4120"));
        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, resp);
    }

    /// mem2608-s3 — a pre-mem2608-s3 daemon's Status payload (without
    /// `cache_weighted_size`) must still decode thanks to
    /// `#[serde(default)]`. Same back-compat contract as `cache_cap`
    /// itself: a CLI built with this field must not fail to read a
    /// daemon built without it.
    #[test]
    fn response_status_legacy_without_cache_weighted_size_deserializes() {
        let legacy = r#"{"type":"status","pid":1,"listen":"127.0.0.1:53","upstream_mode":"plain","upstream_count":1,"domain_count":0,"cache_entries":0,"list_count":0,"uptime_secs":0}"#;
        let parsed: IpcResponse = serde_json::from_str(legacy).unwrap();
        match parsed {
            IpcResponse::Status {
                cache_weighted_size,
                ..
            } => assert_eq!(cache_weighted_size, 0),
            other => panic!("expected Status, got {other:?}"),
        }
    }

    /// §4.13 — pre-§4.13 daemon payload (no `resource_budget`) decodes
    /// cleanly thanks to `#[serde(default)]`; the field is `None`.
    #[test]
    fn response_status_legacy_without_resource_budget_deserializes() {
        let legacy = r#"{"type":"status","pid":1,"listen":"127.0.0.1:53","upstream_mode":"plain","upstream_count":1,"domain_count":0,"cache_entries":0,"list_count":0,"uptime_secs":0}"#;
        let parsed: IpcResponse = serde_json::from_str(legacy).unwrap();
        match parsed {
            IpcResponse::Status {
                resource_budget, ..
            } => assert!(resource_budget.is_none()),
            other => panic!("expected Status, got {other:?}"),
        }
    }

    /// §4.13 — a fresh daemon Status payload carries a non-empty
    /// resource_budget through round-trip.
    #[test]
    fn response_status_with_resource_budget_roundtrip() {
        use crate::resource_budget::ResourceBudgetSnapshot;
        let resp = IpcResponse::Status {
            pid: 1234,
            listen: "127.0.0.1:15353".into(),
            upstream_mode: "plain".into(),
            upstream_count: 1,
            domain_count: 1_000,
            cache_entries: 10,
            list_count: 1,
            uptime_secs: 60,
            query_log_drops: None,
            version: "0.13.0".into(),
            cache_cap: 5_000,
            lists_active: 1,
            lists_total: 1,
            lists_truncated: 0,
            lists_corpus_refusal: None,
            lists_cycle: None,
            lc2_list_diagnostics: ListDiagnostics::default(),
            cache_weighted_size: 300,
            resource_budget: Some(ResourceBudgetSnapshot {
                rss_mb: 42,
                vsz_mb: 280,
                fd_count: 18,
                cpu_user_pct: 3,
                rss_warn_mb: 256,
            }),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"rss_mb\":42"));
        assert!(json.contains("\"rss_warn_mb\":256"));
        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, resp);
    }

    #[test]
    fn response_query_result_roundtrip() {
        let resp = IpcResponse::QueryResult {
            domain: "ads.example.com".into(),
            blocked: true,
            blocked_by: Some("list:ads".into()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, resp);
    }

    #[test]
    fn response_ok_roundtrip() {
        let resp = IpcResponse::Ok {
            message: "cache flushed".into(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, resp);
    }

    #[test]
    fn response_error_roundtrip() {
        let resp = IpcResponse::Error {
            message: "unknown command".into(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, resp);
    }

    /// §4.7 Phase 2 T1: `IpcCommand::ForgetList` and the matching
    /// `IpcResponse::ListForgotten` round-trip cleanly across serde
    /// AND `ForgetList` is classified `Mutating` so the auth gate
    /// requires a token. Also covers `with_token` adding the token
    /// after construction (the CLI client's flow).
    #[test]
    fn forget_list_command_and_response_serde_round_trip() {
        let cmd = IpcCommand::ForgetList {
            id: "privacy/ads".into(),
            token: Some("plaintext-token".into()),
        };
        assert_eq!(cmd.tier(), CommandTier::Mutating);
        assert_eq!(cmd.token(), Some("plaintext-token"));

        let json = serde_json::to_string(&cmd).unwrap();
        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, cmd);

        let cmd_no_token = IpcCommand::ForgetList {
            id: "privacy/ads".into(),
            token: None,
        };
        let with_t = cmd_no_token.with_token(Some("tok".into()));
        assert_eq!(with_t.token(), Some("tok"));

        let resp = IpcResponse::ListForgotten {
            id: "privacy/ads".into(),
            was_cached: true,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, resp);
    }

    #[test]
    fn response_domain_count_roundtrip() {
        let resp = IpcResponse::DomainCount { count: 123456 };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, resp);
    }

    #[test]
    fn all_command_variants_deserialize() {
        let cases = [
            r#"{"type":"status"}"#,
            r#"{"type":"query","domain":"test.com"}"#,
            r#"{"type":"cache_flush","domain":null}"#,
            r#"{"type":"reload"}"#,
            r#"{"type":"shutdown"}"#,
            r#"{"type":"domain_count"}"#,
            r#"{"type":"tracking_stats"}"#,
            r#"{"type":"client_stats"}"#,
            r#"{"type":"query_logs","limit":20}"#,
            r#"{"type":"query_logs","limit":10,"client":"laptop","blocked_only":true}"#,
            // Sprint 41: since_secs added with `#[serde(default)]` so
            // older callers (no field at all) still parse; newer callers
            // can set it to apply a rolling time cutoff.
            r#"{"type":"query_logs","limit":10,"since_secs":3600}"#,
        ];
        for json in cases {
            let _: IpcCommand = serde_json::from_str(json).unwrap();
        }
    }

    #[test]
    fn tracking_stats_response_roundtrip() {
        let resp = IpcResponse::TrackingStats {
            queries_total: 1000,
            blocked_total: 200,
            blocked_pct: 20.0,
            cache_hit_rate: 85.5,
            cache_negative_hits: 42,
            uptime_secs: 3600,
            top_blocked: vec![DomainCount {
                domain: "ads.com".into(),
                count: 50,
                count_24h: 0,
                scope: Some("privacy".into()),
            }],
            top_queried: vec![DomainCount {
                domain: "google.com".into(),
                count: 200,
                count_24h: 0,
                scope: None,
            }],
            hourly: vec![TimeBucketDto {
                timestamp: 1000,
                queries: 100,
                blocked: 20,
                cache_hits: 80,
            }],
            daily: vec![],
            cache_hit_rate_24h: 80.0,
            blocked_pct_24h: 20.0,
            cache_hit_rate_delta_1h: 2.5,
            blocked_pct_delta_1h: -1.0,
            qtype_distribution: [700, 200, 5, 1, 0, 0, 0, 0, 80, 14],
            qtype_blocked_distribution: [50, 30, 1, 0, 0, 0, 0, 0, 4, 2],
            qtype_distribution_24h: [80, 22, 0, 0, 0, 0, 0, 0, 8, 1],
            qtype_blocked_distribution_24h: [5, 3, 0, 0, 0, 0, 0, 0, 0, 0],
            prefetch_pool_size: 7,
            prefetch_promotions_total: 12,
            prefetch_demotions_total: 5,
            top_blocked_lists: Vec::new(),
            top_blocked_24h: Vec::new(),
            top_queried_24h: Vec::new(),
            top_blocked_lists_24h: Vec::new(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, resp);
    }

    /// Sprint §4.4 P1 — pre-§4.4 daemon emits TrackingStats without the
    /// three `prefetch_*` fields. The post-upgrade CLI/TUI must still
    /// deserialize that payload, defaulting all three to zero.
    #[test]
    fn tracking_stats_response_legacy_missing_prefetch_fields() {
        let legacy_json = serde_json::json!({
            "type": "tracking_stats",
            "queries_total": 500,
            "blocked_total": 50,
            "blocked_pct": 10.0,
            "cache_hit_rate": 60.0,
            "cache_negative_hits": 3,
            "uptime_secs": 120,
            "top_blocked": [],
            "top_queried": [],
            "hourly": [],
            "daily": [],
            "qtype_distribution": [400, 90, 0, 0, 0, 0, 0, 0, 0, 10]
        });
        let parsed: IpcResponse = serde_json::from_value(legacy_json).unwrap();
        match parsed {
            IpcResponse::TrackingStats {
                prefetch_pool_size,
                prefetch_promotions_total,
                prefetch_demotions_total,
                qtype_blocked_distribution,
                ..
            } => {
                assert_eq!(prefetch_pool_size, 0);
                assert_eq!(prefetch_promotions_total, 0);
                assert_eq!(prefetch_demotions_total, 0);
                // Sprint E — pre-Sprint-E daemons emit no
                // `qtype_blocked_distribution`; serde default fills in
                // the canonical 10-bucket all-zero array.
                assert_eq!(qtype_blocked_distribution, [0u64; 10]);
            }
            other => panic!("expected TrackingStats, got {other:?}"),
        }
    }

    /// Legacy migration: a pre-Sprint-25 daemon emits TrackingStats
    /// without the new `cache_negative_hits` field. The TUI (post-upgrade)
    /// must still deserialize that payload, defaulting the counter to 0.
    #[test]
    fn tracking_stats_response_legacy_missing_negative_hits() {
        let legacy_json = serde_json::json!({
            "type": "tracking_stats",
            "queries_total": 500,
            "blocked_total": 50,
            "blocked_pct": 10.0,
            "cache_hit_rate": 60.0,
            "uptime_secs": 120,
            "top_blocked": [],
            "top_queried": [],
            "hourly": [],
            "daily": []
        });
        let parsed: IpcResponse = serde_json::from_value(legacy_json).unwrap();
        match parsed {
            IpcResponse::TrackingStats {
                cache_negative_hits,
                ..
            } => assert_eq!(cache_negative_hits, 0),
            other => panic!("expected TrackingStats, got {other:?}"),
        }
    }

    /// Legacy migration (Sprint 27): a pre-scope daemon emits DomainCount
    /// entries without the `scope` field. The TUI must default them to
    /// `None` so the wire format is forward-compatible.
    #[test]
    fn domain_count_accepts_missing_scope_as_none() {
        let legacy = serde_json::json!({
            "domain": "ads.example",
            "count": 100,
        });
        let parsed: DomainCount = serde_json::from_value(legacy).unwrap();
        assert_eq!(parsed.scope, None);
        assert_eq!(parsed.domain, "ads.example");
        assert_eq!(parsed.count, 100);
    }

    /// And the new field round-trips when populated.
    #[test]
    fn domain_count_roundtrips_populated_scope() {
        let dc = DomainCount {
            domain: "tracker.example".into(),
            count: 42,
            count_24h: 0,
            scope: Some("privacy".into()),
        };
        let json = serde_json::to_string(&dc).unwrap();
        let parsed: DomainCount = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, dc);
    }

    #[test]
    fn device_list_response_roundtrip() {
        let resp = IpcResponse::DeviceList {
            clients: vec![DeviceStatEntry {
                name: "laptop".into(),
                ip: "192.168.1.42".into(),
                queries: 500,
                blocked: 50,
                blocked_pct: 10.0,
                cache_hits: 400,
                profile: "default".into(),
                last_seen: 1704110000,
            }],
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, resp);
    }

    /// T5 decode-compat: a pre-T5 daemon (or CLI playback) sending the
    /// legacy `client_list` variant tag must still decode into the T5
    /// `DeviceList` variant. Pairs with the serde aliases on the
    /// `IpcResponse` enum and satisfies §3 R1's IPC decode-compat
    /// requirement for one release cycle.
    #[test]
    fn legacy_client_list_variant_decodes_into_device_list() {
        let legacy_json = r#"{"type":"client_list","clients":[{"name":"laptop","ip":"192.168.1.42","queries":1,"blocked":0,"blocked_pct":0.0,"cache_hits":0,"profile":"default","last_seen":1700000000}]}"#;
        let parsed: IpcResponse = serde_json::from_str(legacy_json).unwrap();
        match parsed {
            IpcResponse::DeviceList { clients } => {
                assert_eq!(clients.len(), 1);
                assert_eq!(clients[0].name, "laptop");
            }
            other => panic!("expected DeviceList, got {other:?}"),
        }
    }

    /// T5 decode-compat (command side): legacy `"client_stats"` tag must
    /// deserialize into the renamed `DeviceStats` variant.
    #[test]
    fn legacy_client_stats_command_decodes_into_device_stats() {
        let legacy_json = r#"{"type":"client_stats"}"#;
        let parsed: IpcCommand = serde_json::from_str(legacy_json).unwrap();
        assert!(matches!(parsed, IpcCommand::DeviceStats { token: None }));
    }

    /// T5 decode-compat: legacy `"get_all_clients"` tag must deserialize
    /// into the renamed `GetAllDevices` variant.
    #[test]
    fn legacy_get_all_clients_command_decodes_into_get_all_devices() {
        let legacy_json = r#"{"type":"get_all_clients"}"#;
        let parsed: IpcCommand = serde_json::from_str(legacy_json).unwrap();
        assert!(matches!(parsed, IpcCommand::GetAllDevices));
    }

    // --- P0-3: command tier classification ---

    #[test]
    fn readonly_commands_have_readonly_tier() {
        assert_eq!(IpcCommand::Status.tier(), CommandTier::ReadOnly);
        assert_eq!(IpcCommand::DomainCount.tier(), CommandTier::ReadOnly);
        assert_eq!(
            IpcCommand::Query {
                domain: "google.com".into()
            }
            .tier(),
            CommandTier::ReadOnly
        );
    }

    #[test]
    fn mutating_commands_have_mutating_tier() {
        assert_eq!(
            IpcCommand::CacheFlush {
                domain: None,
                token: None
            }
            .tier(),
            CommandTier::Mutating
        );
        assert_eq!(
            IpcCommand::Reload { token: None }.tier(),
            CommandTier::Mutating
        );
    }

    #[test]
    fn admin_commands_have_admin_tier() {
        assert_eq!(
            IpcCommand::Shutdown { token: None }.tier(),
            CommandTier::Admin
        );
        assert_eq!(
            IpcCommand::TrackingStats { token: None }.tier(),
            CommandTier::Admin
        );
        assert_eq!(
            IpcCommand::DeviceStats { token: None }.tier(),
            CommandTier::Admin
        );
        assert_eq!(
            IpcCommand::QueryLogs {
                limit: 10,
                client: None,
                blocked_only: false,
                domain: None,
                since_secs: None,
                cursor: None,
                advanced: None,
                token: None
            }
            .tier(),
            CommandTier::Admin
        );
    }

    #[test]
    fn with_token_attaches_to_gated_commands() {
        let tok = Some("ps_abc123".to_string());
        let attached = IpcCommand::Reload { token: None }.with_token(tok.clone());
        assert_eq!(attached.token(), Some("ps_abc123"));

        let shutdown = IpcCommand::Shutdown { token: None }.with_token(tok.clone());
        assert_eq!(shutdown.token(), Some("ps_abc123"));

        let logs = IpcCommand::QueryLogs {
            limit: 10,
            client: None,
            blocked_only: false,
            domain: None,
            since_secs: None,
            cursor: None,
            advanced: None,
            token: None,
        }
        .with_token(tok.clone());
        assert_eq!(logs.token(), Some("ps_abc123"));
    }

    #[test]
    fn with_token_is_noop_on_readonly() {
        let tok = Some("ps_abc123".to_string());
        let status = IpcCommand::Status.with_token(tok.clone());
        // ReadOnly commands have no token slot, so token() returns None.
        assert_eq!(status.token(), None);
        assert_eq!(status, IpcCommand::Status);
    }

    #[test]
    fn old_clients_without_token_field_still_parse() {
        // Mutating commands with no `token` field in JSON must deserialize
        // (the field defaults to None). This covers CLI clients that pre-date
        // the P0-3 change, and the round-trip of an un-tokened command.
        let cases = [
            r#"{"type":"cache_flush","domain":null}"#,
            r#"{"type":"reload"}"#,
            r#"{"type":"shutdown"}"#,
            r#"{"type":"tracking_stats"}"#,
            r#"{"type":"device_stats"}"#,
        ];
        for json in cases {
            let cmd: IpcCommand = serde_json::from_str(json).unwrap();
            assert_eq!(cmd.token(), None);
        }
    }

    #[test]
    fn token_serializes_only_when_set() {
        let no_tok = IpcCommand::Reload { token: None };
        let with_tok = IpcCommand::Reload {
            token: Some("ps_abc".into()),
        };
        let no_json = serde_json::to_string(&no_tok).unwrap();
        let with_json = serde_json::to_string(&with_tok).unwrap();
        // `skip_serializing_if = Option::is_none` should keep the wire format
        // minimal when no token is attached.
        assert!(!no_json.contains("token"), "got {no_json}");
        assert!(with_json.contains("\"token\":\"ps_abc\""));
    }

    /// **The trip-wire for the field-drop class.**
    ///
    /// `socket_client::send_command` runs every token-bearing request
    /// through `with_token` — so that arm is on the path of every real
    /// `QueryLogs` request and on the path of no other test, because
    /// tests build `IpcCommand` directly. When the arm destructured with
    /// `..`, a field added to the variant was silently reset to whatever
    /// the construct side wrote: paging would have been dead in
    /// production with the whole suite green.
    ///
    /// The `let … else` below destructures EXHAUSTIVELY. That is the
    /// point: the next field added to `QueryLogs` fails to compile here
    /// rather than vanishing on the wire. Do not replace it with `..`.
    #[test]
    fn with_token_preserves_every_query_logs_field() {
        let cursor = crate::tracking::query_log::QueryLogCursor {
            file: "/var/lib/purge-warden/query.log".into(),
            offset: 8192,
            inode: 4242,
        };
        let advanced = AdvancedClientFilterDto {
            name: Some("*ioel*".into()),
            name_exclude: true,
            subnet: Some("192.0.2.0/24".into()),
            ..Default::default()
        };
        let cmd = IpcCommand::QueryLogs {
            limit: 40,
            client: Some("laptop".into()),
            blocked_only: true,
            domain: Some("ads.example".into()),
            since_secs: Some(3600),
            cursor: Some(cursor.clone()),
            advanced: Some(advanced.clone()),
            token: None,
        };
        let IpcCommand::QueryLogs {
            limit,
            client,
            blocked_only,
            domain,
            since_secs,
            cursor: carried,
            advanced: carried_advanced,
            token,
        } = cmd.with_token(Some("tok".into()))
        else {
            panic!("with_token must not change the variant");
        };
        assert_eq!(limit, 40);
        assert_eq!(client.as_deref(), Some("laptop"));
        assert!(blocked_only);
        assert_eq!(domain.as_deref(), Some("ads.example"));
        assert_eq!(since_secs, Some(3600));
        assert_eq!(
            carried,
            Some(cursor),
            "the resume cursor must survive token attachment — without this \
             every paged request silently reads the live tail"
        );
        // Bound to a NAME, not matched against a literal. A pattern like
        // `advanced: None` would compile, satisfy the exhaustiveness the
        // doc comment above is asking for, and assert nothing about the
        // field — a trip-wire that fires on the build and then tests
        // nothing is the failure mode this test is guarding against.
        assert_eq!(
            carried_advanced,
            Some(advanced),
            "the advanced filter must survive token attachment — without \
             this every advanced search silently reads the whole log"
        );
        assert_eq!(token.as_deref(), Some("tok"));
    }

    /// A pre-paging caller sends no `cursor`; a pre-paging daemon sends
    /// no `next_cursor` / `cursor_stale`. Both must still decode.
    #[test]
    fn query_logs_wire_is_compatible_in_both_directions() {
        let cmd: IpcCommand = serde_json::from_str(r#"{"type":"query_logs","limit":20}"#).unwrap();
        let IpcCommand::QueryLogs { cursor, .. } = cmd else {
            panic!("expected query_logs");
        };
        assert!(cursor.is_none(), "absent cursor decodes as live tail");

        let resp: IpcResponse = serde_json::from_str(
            r#"{"type":"query_logs","entries":[],"logging_enabled":true,"file_state":"Ok"}"#,
        )
        .unwrap();
        let IpcResponse::QueryLogs {
            next_cursor,
            cursor_stale,
            ..
        } = resp
        else {
            panic!("expected query_logs");
        };
        assert!(next_cursor.is_none());
        assert!(!cursor_stale);

        // And a cursor-bearing command survives the round trip.
        let with_cursor = IpcCommand::QueryLogs {
            limit: 40,
            client: None,
            blocked_only: false,
            domain: None,
            since_secs: None,
            cursor: Some(crate::tracking::query_log::QueryLogCursor {
                file: "/var/lib/purge-warden/query.log.2026-04-07".into(),
                offset: 123,
                inode: 9,
            }),
            advanced: Some(AdvancedClientFilterDto {
                ip: Some("192.0.2.*".into()),
                ip_exclude: true,
                ..Default::default()
            }),
            token: None,
        };
        let json = serde_json::to_string(&with_cursor).unwrap();
        let back: IpcCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(back, with_cursor);
    }

    #[test]
    fn query_logs_response_roundtrip() {
        let resp = IpcResponse::QueryLogs {
            entries: vec![QueryLogDto {
                timestamp: "2026-04-08T15:00:00Z".into(),
                client_ip: "192.168.1.1".into(),
                client_name: Some("laptop".into()),
                domain: "google.com".into(),
                query_type: "A".into(),
                result: "ALLOWED".into(),
                response_time_us: 500,
                cname_chain_via: None,
            }],
            logging_enabled: true,
            file_state: QueryLogFileState::Ok,
            next_cursor: None,
            cursor_stale: false,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, resp);
    }

    #[test]
    fn query_log_dto_with_cname_chain_via_round_trips() {
        // §4.5 Sprint 2/2: the IPC DTO mirrors `QueryLogEntry`'s new
        // `cname_chain_via` field so the TUI receives the offending hop
        // for the `[CNAME]` badge + `qname → offending` rendering.
        let dto = QueryLogDto {
            timestamp: "2026-05-08T12:00:00Z".into(),
            client_ip: "10.0.0.42".into(),
            client_name: Some("phone".into()),
            domain: "apex.example.com".into(),
            query_type: "A".into(),
            result: "BLOCKED".into(),
            response_time_us: 999,
            cname_chain_via: Some("offending.tracker.example".into()),
        };
        let json = serde_json::to_string(&dto).unwrap();
        assert!(json.contains("\"cname_chain_via\":\"offending.tracker.example\""));
        let parsed: QueryLogDto = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, dto);
    }

    #[test]
    fn query_log_dto_without_cname_chain_via_skips_field() {
        // Non-CNAME outcomes must not surface a spurious
        // `cname_chain_via: null` on the IPC wire — keeps the byte
        // shape identical for older TUIs / tail consumers.
        let dto = QueryLogDto {
            timestamp: "2026-05-08T12:00:00Z".into(),
            client_ip: "10.0.0.1".into(),
            client_name: None,
            domain: "google.com".into(),
            query_type: "A".into(),
            result: "ALLOWED".into(),
            response_time_us: 100,
            cname_chain_via: None,
        };
        let json = serde_json::to_string(&dto).unwrap();
        assert!(!json.contains("cname_chain_via"));
    }

    #[test]
    fn query_log_dto_legacy_payload_parses_with_cname_chain_via_none() {
        // Pre-S4.5-P2 daemons emit DTOs without the field. The
        // `#[serde(default)]` decoration lets a newer TUI parse them
        // back as `cname_chain_via: None` without erroring.
        let legacy_json = r#"{
            "timestamp":"2026-04-08T15:00:00Z",
            "client_ip":"10.0.0.1",
            "client_name":"laptop",
            "domain":"google.com",
            "query_type":"A",
            "result":"ALLOWED",
            "response_time_us":500
        }"#;
        let parsed: QueryLogDto = serde_json::from_str(legacy_json).unwrap();
        assert!(parsed.cname_chain_via.is_none());
    }

    // ── s23-mapped-dto-dedup wire-format pin ─────────────────────────
    // Guards against accidental nesting or field renames from the
    // MappedDeviceSnapshot/MappedDeviceDto collapse. The DTO is the
    // single source of truth for mapped-device metadata shape, and the
    // resolver's snapshot wraps it rather than duplicating fields — so
    // if anyone (re)introduces `#[serde(flatten)] meta:` or moves a
    // field out of the DTO, this test fails loudly. The TUI + every
    // downstream consumer parses this exact flat shape.

    #[test]
    fn mapped_device_dto_roundtrip() {
        let dto = MappedDeviceDto {
            ip: "192.168.1.42".into(),
            name: "alex-laptop".into(),
            mac: Some("AA:BB:CC:DD:EE:FF".into()),
            mac_aliases: Vec::new(),
            profile: "default".into(),
            owner: Some("Alex".into()),
            device_type: Some("ThinkPad".into()),
            department: Some("home".into()),
            queries: 42,
            queries_today: 9,
            blocked: 7,
            blocked_24h: 0,
            cache_hits: 13,
            last_seen: 1_700_000_000,
            online: true,
            vendor: Some("Lenovo".into()),
            groups: Vec::new(),
            notes: None,
            network_name: None,
            network_name_wildcard: false,
            id: None,
            hourly_queries: Vec::new(),
            unfiltered: false,
        };
        let json = serde_json::to_string(&dto).unwrap();
        let parsed: MappedDeviceDto = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, dto);
    }

    /// The device view really does put operator-private metadata on the
    /// wire, for a command that needs no token.
    ///
    /// This exists because the variant's own rustdoc used to claim the
    /// opposite — that the response "excludes `notes` and any field the
    /// operator might treat as confidential" — while `notes`, `owner`
    /// and `department` were all being serialized. A tier justified on
    /// a false description of its own payload is worse than an
    /// unjustified one, so the description is now pinned.
    #[test]
    fn device_view_carries_operator_private_fields() {
        let dto = MappedDeviceDto {
            ip: "192.168.1.42".into(),
            name: "alex-laptop".into(),
            mac: Some("AA:BB:CC:DD:EE:FF".into()),
            mac_aliases: vec!["11:22:33:44:55:66".into()],
            profile: "default".into(),
            owner: Some("Alex".into()),
            device_type: Some("ThinkPad".into()),
            department: Some("home".into()),
            queries: 0,
            queries_today: 0,
            blocked: 0,
            blocked_24h: 0,
            cache_hits: 0,
            last_seen: 0,
            online: false,
            vendor: None,
            groups: Vec::new(),
            notes: Some("spare key under the mat".into()),
            network_name: None,
            network_name_wildcard: false,
            id: None,
            hourly_queries: Vec::new(),
            unfiltered: false,
        };
        let json = serde_json::to_string(&dto).unwrap();
        for field in ["notes", "owner", "department", "mac", "mac_aliases"] {
            assert!(
                json.contains(&format!("\"{field}\"")),
                "{field} reaches the wire; any tier rationale has to account for it"
            );
        }
        assert!(json.contains("spare key under the mat"));
        assert_eq!(IpcCommand::GetAllDevices.tier(), CommandTier::ReadOnly);
    }

    #[test]
    fn mapped_device_dto_wire_shape_is_flat() {
        // Every field is a top-level JSON key — NO nesting under
        // "meta" / "counters" / etc. If the test grows a nested object
        // after this comment, the dedup refactor has regressed and a
        // silently-shipping TUI breakage is one commit away.
        let dto = MappedDeviceDto {
            ip: "192.168.1.42".into(),
            name: "alex-laptop".into(),
            mac: None,
            mac_aliases: Vec::new(),
            profile: "default".into(),
            owner: None,
            device_type: None,
            department: None,
            queries: 0,
            queries_today: 0,
            blocked: 0,
            blocked_24h: 0,
            cache_hits: 0,
            last_seen: 0,
            online: false,
            vendor: Some("Lenovo".into()),
            groups: Vec::new(),
            notes: None,
            network_name: None,
            network_name_wildcard: false,
            id: None,
            hourly_queries: Vec::new(),
            unfiltered: false,
        };
        let json = serde_json::to_string(&dto).unwrap();

        for key in [
            "\"ip\":",
            "\"name\":",
            "\"mac\":",
            "\"profile\":",
            "\"owner\":",
            "\"device_type\":",
            "\"department\":",
            "\"queries\":",
            "\"queries_today\":",
            "\"blocked\":",
            "\"cache_hits\":",
            "\"last_seen\":",
            "\"online\":",
            "\"vendor\":",
        ] {
            assert!(json.contains(key), "missing top-level key {key} in {json}");
        }
        // Nothing nested — the wire format must stay flat for the TUI
        // and any third-party operator tooling that parses the JSON.
        assert!(!json.contains("\"meta\":"), "unexpected nesting: {json}");
        assert!(
            !json.contains("\"counters\":"),
            "unexpected nesting: {json}"
        );
    }

    // ── S43 T2: IpcNotification serde stability ─────────────────
    // The publishing channel is wired in T2; the subscriber endpoint
    // lands in T3. These tests pin the wire shape now so a future
    // refactor cannot silently rename or restructure variants once
    // subscribers exist.

    #[test]
    fn ipc_notification_list_stats_updated_roundtrip() {
        let n = IpcNotification::ListStatsUpdated {
            id: "privacy/ads".into(),
        };
        let json = serde_json::to_string(&n).unwrap();
        // Tag style matches IpcCommand / IpcResponse for consistency.
        assert_eq!(
            json, r#"{"type":"list_stats_updated","id":"privacy/ads"}"#,
            "wire shape must stay stable across releases — subscribers parse this verbatim"
        );
        let parsed: IpcNotification = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, n);
    }

    #[test]
    fn ipc_notification_list_stats_updated_carries_raw_url_id() {
        // Source ids in `[lists].sources` may be raw URLs (not slugs).
        // The notification id field passes them through verbatim — no
        // canonicalisation, since the registry is keyed on the same
        // raw string.
        let n = IpcNotification::ListStatsUpdated {
            id: "https://example.com/blocklist.txt".into(),
        };
        let json = serde_json::to_string(&n).unwrap();
        let parsed: IpcNotification = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, n);
    }

    #[test]
    fn device_view_dto_roundtrip_after_sn3_flag_removal() {
        // Post-SN3 the envelope carries only `mapped` + `unmapped`. This
        // test pins the wire shape against accidental field creep (e.g. a
        // future refactor re-adding `block_unmapped` would fail the
        // serialise→deserialise equality check and the absence-in-JSON
        // guard below).
        let view = DeviceViewDto {
            mapped: vec![MappedDeviceDto {
                ip: "10.0.0.5".into(),
                name: "kids-tablet".into(),
                mac: None,
                mac_aliases: Vec::new(),
                profile: "kids".into(),
                owner: None,
                device_type: None,
                department: None,
                queries: 1,
                queries_today: 1,
                blocked: 0,
                blocked_24h: 0,
                cache_hits: 0,
                last_seen: 0,
                online: false,
                vendor: None,
                groups: Vec::new(),
                notes: None,
                network_name: None,
                network_name_wildcard: false,
                id: None,
                hourly_queries: Vec::new(),
                unfiltered: false,
            }],
            unmapped: vec![UnmappedDeviceDto {
                ip: "10.0.0.99".into(),
                mac: None,
                queries: 3,
                queries_today: 2,
                blocked: 1,
                blocked_24h: 0,
                last_seen: 0,
                online: false,
                vendor: None,
                hourly_queries: Vec::new(),
            }],
        };
        let json = serde_json::to_string(&view).unwrap();
        let parsed: DeviceViewDto = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, view);
        assert!(
            !json.contains("block_unmapped"),
            "wire format must not carry legacy block_unmapped: {json}",
        );
    }

    /// Sprint B Dashboard v2 — `top_blocked_lists` round-trips intact
    /// through serde_json. Pinning the wire shape so a future field
    /// rename surfaces as a test failure rather than a silent break of
    /// the TUI poller.
    #[test]
    fn tracking_stats_roundtrip_includes_top_blocked_lists() {
        use crate::tracking::TYPE_BUCKET_COUNT;
        let resp = IpcResponse::TrackingStats {
            queries_total: 100,
            blocked_total: 12,
            blocked_pct: 12.0,
            cache_hit_rate: 50.0,
            cache_negative_hits: 2,
            uptime_secs: 600,
            top_blocked: Vec::new(),
            top_queried: Vec::new(),
            hourly: Vec::new(),
            daily: Vec::new(),
            cache_hit_rate_24h: 50.0,
            blocked_pct_24h: 12.0,
            cache_hit_rate_delta_1h: 0.0,
            blocked_pct_delta_1h: 0.0,
            qtype_distribution: [0; TYPE_BUCKET_COUNT],
            qtype_blocked_distribution: [0; TYPE_BUCKET_COUNT],
            qtype_distribution_24h: [0; TYPE_BUCKET_COUNT],
            qtype_blocked_distribution_24h: [0; TYPE_BUCKET_COUNT],
            prefetch_pool_size: 0,
            prefetch_promotions_total: 0,
            prefetch_demotions_total: 0,
            top_blocked_lists: vec![
                ListBlockCount {
                    label: "privacy/ads".into(),
                    count: 42,
                    count_24h: 0,
                },
                ListBlockCount {
                    label: "security/malicious".into(),
                    count: 7,
                    count_24h: 0,
                },
            ],
            top_blocked_24h: Vec::new(),
            top_queried_24h: Vec::new(),
            top_blocked_lists_24h: Vec::new(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"top_blocked_lists\""));
        assert!(json.contains("\"label\":\"privacy/ads\""));
        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            IpcResponse::TrackingStats {
                top_blocked_lists, ..
            } => {
                assert_eq!(top_blocked_lists.len(), 2);
                assert_eq!(top_blocked_lists[0].label, "privacy/ads");
                assert_eq!(top_blocked_lists[0].count, 42);
                assert_eq!(top_blocked_lists[1].label, "security/malicious");
                assert_eq!(top_blocked_lists[1].count, 7);
            }
            other => panic!("expected TrackingStats, got {other:?}"),
        }
    }

    /// Sprint B Dashboard v2 — JSON emitted by a pre-Sprint-B daemon
    /// (no `top_blocked_lists` field) decodes into the new variant
    /// with an empty vec, so a Sprint-B-aware CLI/TUI talking to an
    /// older daemon degrades gracefully to the "collecting…"
    /// placeholder rather than a parse error.
    #[test]
    fn tracking_stats_legacy_decodes_with_empty_top_blocked_lists() {
        // Hand-crafted JSON without `top_blocked_lists`. Mirrors the
        // shape of a pre-Sprint-B `IpcResponse::TrackingStats`.
        let legacy = r#"{
            "type": "tracking_stats",
            "queries_total": 1,
            "blocked_total": 0,
            "blocked_pct": 0.0,
            "cache_hit_rate": 0.0,
            "uptime_secs": 1,
            "top_blocked": [],
            "top_queried": [],
            "hourly": [],
            "daily": []
        }"#;
        let parsed: IpcResponse = serde_json::from_str(legacy).unwrap();
        match parsed {
            IpcResponse::TrackingStats {
                top_blocked_lists, ..
            } => {
                assert!(top_blocked_lists.is_empty());
            }
            other => panic!("expected TrackingStats, got {other:?}"),
        }
    }
}
