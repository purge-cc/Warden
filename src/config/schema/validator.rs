//! Semantic validation for [`ConfigV1`] — cross-reference checks, id
//! uniqueness, retired-id enforcement (N8), and scalar invariants.
//!
//! Per design doc §13-Sprint-28 step 7. Returns the complete list of
//! problems (not just the first) so the operator fixes the whole config
//! in one pass.
//!
//! Serde handles the "wrong type" / "unknown field" layer; this module
//! handles everything the type system cannot express on its own.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use time::OffsetDateTime;

use super::super::cidr::Cidr;
use super::super::error::{ConfigError, ErrorContext};
use super::super::secrets::Secrets;
// Deliberate config→filter edge (rev-2606 schema-validator-05): admin rule
// text must be validated by the SAME parser the filter engine consumes, so
// `config lint` accepts exactly what the engine will enforce. A second
// hand-rolled grammar here would drift and re-create the silent-rule bug.
use super::blocklist::{effective_direction, BlocklistBase, BlocklistTrust, ListPolicy};
use super::cluster::validate_peer_url;
use super::id::Id;
use super::label::{Label, LabelKind};
use super::retired::{RetiredEntry, RetiredType};
use super::{
    ClusterRole, ConfigV1, ScheduleTargetType, REPLICATED_BUT_ALLOWED_IN_A_SECONDARY_MASTER,
    REPLICATED_SECTIONS, SCHEMA_VERSION_V1,
};
use crate::config::loader::{is_cluster_drop_in, ProvenanceMap};
use crate::config::settings::UpstreamMode;
use crate::filter::rules::parse_rule_checked;

/// Collector for the validator's operator-facing audit WARNs.
///
/// Every WARN this module raises has two audiences: the daemon, which
/// wants it in journald (`tracing::warn!(target: "audit", …)`), and
/// `warden config lint`, which wants it as *data* so it can print it and
/// pick an exit code. Before `s-rev2606-lint-warn-fixture-flaky-parallel`
/// lint got its copy by installing a thread-scoped `tracing` subscriber
/// and reading the events back out — using the process-global tracing
/// dispatcher as a data channel, which made the lint tests racy against
/// every other test thread touching that global. This type is the data
/// channel instead; the `tracing::warn!` calls stayed exactly where they
/// were, so journald output is unchanged.
///
/// `silent` exists for the **tests**, which drive `validate_collect`
/// directly and must not write to the process-global `tracing` dispatcher
/// while doing it. Seven call sites in this file's test module use it.
///
/// It used to have a production caller too: the loader's single-file fast
/// path validated once through [`super::load::load_from_str`] (emitting) and
/// then re-ran [`validate_collect`] silently just to harvest the same
/// messages as data. `s1-followup-load-from-str-collect` collapsed that into
/// one pass via [`super::load::load_from_str_collect`], which took `absorb`
/// — the method that folded the harvest back in — to zero callers, so it was
/// deleted with it.
#[derive(Debug)]
pub struct AuditWarnings {
    emit: bool,
    msgs: Vec<String>,
}

impl AuditWarnings {
    /// Collect **and** let each site log to `tracing` as usual. This is
    /// what every production caller uses.
    pub fn emitting() -> Self {
        Self {
            emit: true,
            msgs: Vec::new(),
        }
    }

    /// Collect only — no `tracing` events. For a second harvesting pass
    /// over a config whose WARNs have already been logged once.
    pub fn silent() -> Self {
        Self {
            emit: false,
            msgs: Vec::new(),
        }
    }

    /// Whether the calling site should also fire its `tracing::warn!`.
    /// The macro stays *at the site* so its structured fields
    /// (`device = …`, `blocklist = …`) survive; only the message text is
    /// hoisted into a local so both channels get the same bytes.
    pub(crate) fn emit(&self) -> bool {
        self.emit
    }

    /// Record one operator-facing warning message.
    pub(crate) fn push(&mut self, msg: String) {
        self.msgs.push(msg);
    }

    /// The collected messages, in validation order.
    pub fn into_messages(self) -> Vec<String> {
        self.msgs
    }
}

/// Validate a loaded [`ConfigV1`]. Returns `Ok(())` if everything lines
/// up, or a vector of [`ConfigError`] covering every problem found.
///
/// `now` is injected so tests can drive the N8 90-day window
/// deterministically.
///
/// Audit WARNs go to `tracing` only. Callers that also need them as data
/// (`warden config lint`) use [`validate_collect`].
/// Secrets-unaware form: the `auth_token_ref` cross-check (s4 config-m4) is
/// skipped. Kept so [`crate::config::schema::load::load_from_str`] — whose
/// signature the whole codebase depends on — stays unchanged; the production
/// loader calls [`validate_collect`] with the resolved table instead.
pub fn validate(config: &ConfigV1, now: OffsetDateTime) -> Result<(), Vec<ConfigError>> {
    validate_collect(config, now, &mut AuditWarnings::emitting(), None, None)
}

/// [`validate`] plus an [`AuditWarnings`] collector: every operator WARN
/// raised during the pass is pushed into `warns` as well as (when
/// `warns.emit()`) logged on the `audit` tracing target.
/// `secrets` carries the resolved `secrets.toml` table when the caller has
/// one (s4 config-m4). `None` means "not available at this call site" and
/// disables only the `auth_token_ref` cross-check — never any other rule.
/// `provenance` follows the same convention exactly: the loader's
/// `entity_path → (file, line)` sidecar when the caller has one, `None`
/// otherwise, disabling only the cluster secondary-master cross-check
/// (§5.1). Both are *data*, not filesystem access, so this stays a pure
/// function of its arguments and its tests need no filesystem.
pub fn validate_collect(
    config: &ConfigV1,
    now: OffsetDateTime,
    warns: &mut AuditWarnings,
    secrets: Option<&Secrets>,
    provenance: Option<&ProvenanceMap>,
) -> Result<(), Vec<ConfigError>> {
    let mut errs = Vec::new();

    check_schema_version(config, &mut errs);
    let profile_ids = collect_profile_ids(config, &mut errs);
    let blocklist_ids = collect_unique_ids(&config.blocklists, |b| &b.id, "blocklists", &mut errs);
    let device_ids = collect_unique_ids(&config.devices, |d| &d.id, "devices", &mut errs);
    let group_ids = collect_unique_ids(&config.groups, |g| &g.id, "groups", &mut errs);
    let _subnet_ids = collect_unique_ids(&config.subnets, |s| &s.id, "subnets", &mut errs);
    let schedule_ids = collect_unique_ids(&config.schedules, |s| &s.id, "schedules", &mut errs);
    let admin_rule_ids =
        collect_unique_ids(&config.admin_rules, |a| &a.id, "admin_rules", &mut errs);

    check_retired_uniqueness(&config.retired, &mut errs);
    check_retired_window(config, now, &mut errs);

    check_server_defaults(config, &profile_ids, &mut errs, warns);
    check_tracking(config, &mut errs);
    check_lists(config, &mut errs);
    check_security(config, &mut errs, warns);
    check_anti_bypass(config, warns);
    check_cache(config, &mut errs, warns);
    check_dnssec(config, &mut errs);
    check_local_dns(config, &mut errs, warns);
    check_upstream_ecs(config, &mut errs);
    check_upstream_servers(config, &mut errs);
    check_backup(config, &mut errs);
    check_blocklists(config, &mut errs, warns, secrets);
    check_custom_lists(config, &mut errs);
    check_profiles(config, &blocklist_ids, &admin_rule_ids, &mut errs, warns);
    check_devices(
        config,
        &profile_ids,
        &group_ids,
        &admin_rule_ids,
        &mut errs,
        warns,
    );
    check_groups(config, &profile_ids, &device_ids, &mut errs);
    check_labels(config, &mut errs, warns);
    check_subnets(config, &profile_ids, &mut errs);
    check_level5_refuses_everything(config, warns);
    check_schedules(
        config,
        &profile_ids,
        &device_ids,
        &group_ids,
        now,
        &mut errs,
        warns,
    );
    check_admin_rules(config, &mut errs);
    check_resource_budget(config, &mut errs);
    check_cluster(config, &mut errs);
    check_secondary_master_is_policy_free(config, provenance, &mut errs);
    check_api(config, &mut errs, warns);
    check_group_priority_conflicts(config, &mut errs);
    check_profile_list_coverage(config, warns);
    check_blocklist_base_trust(config, &mut errs, warns);
    check_unmounted_custom_lists(config, warns);
    let _ = schedule_ids; // currently no further cross-ref needs it; kept for symmetry.

    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs)
    }
}

// ── scalar / structural checks ─────────────────────────────────

fn check_schema_version(config: &ConfigV1, errs: &mut Vec<ConfigError>) {
    if config.schema_version != SCHEMA_VERSION_V1 {
        errs.push(ConfigError::VersionMismatch(
            ErrorContext::new(format!(
                "schema_version = {}; this binary supports only schema_version = {}",
                config.schema_version, SCHEMA_VERSION_V1
            ))
            .with_entity("schema_version")
            .with_suggestion(format!(
                "set `schema_version = {SCHEMA_VERSION_V1}` at the top of config.toml"
            )),
        ));
    }
}

// ── id collection helpers ──────────────────────────────────────

fn collect_unique_ids<T>(
    items: &[T],
    get_id: impl Fn(&T) -> &Id,
    section: &str,
    errs: &mut Vec<ConfigError>,
) -> HashSet<Id> {
    let mut seen: HashSet<Id> = HashSet::new();
    for (idx, item) in items.iter().enumerate() {
        let id = get_id(item);
        if !seen.insert(id.clone()) {
            errs.push(ConfigError::DuplicateId(
                ErrorContext::new(format!(
                    "{section}[{idx}]: id \"{id}\" is already used by another entry"
                ))
                .with_entity(format!("{section}.{id}"))
                .with_suggestion(
                    "rename one of the two entries, or retire the old id via [[retired]]"
                        .to_string(),
                ),
            ));
        }
    }
    seen
}

fn collect_profile_ids(config: &ConfigV1, errs: &mut Vec<ConfigError>) -> HashSet<Id> {
    let mut ids: HashSet<Id> = HashSet::new();
    for key in config.profiles.keys() {
        match Id::try_from(key.as_str()) {
            Ok(id) => {
                ids.insert(id);
            }
            Err(ConfigError::InvalidId(ctx)) => {
                errs.push(ConfigError::InvalidId(ErrorContext {
                    entity: Some(format!("profiles.{key}")),
                    ..ctx
                }));
            }
            Err(other) => errs.push(other),
        }
    }
    ids
}

// ── [server] ───────────────────────────────────────────────────

/// Does this bind address make the daemon answer on **every** interface?
///
/// `IpAddr::is_unspecified()` alone is not the answer. `::ffff:0.0.0.0`
/// is the IPv4-mapped spelling of the wildcard: the kernel binds it as
/// one, but its octets are not all zero so `Ipv6Addr::is_unspecified()`
/// returns false. A config with that `listen` and an empty `allow_from`
/// therefore validated clean and produced an **open resolver** — a DNS
/// amplification vector — while this very check read green.
///
/// The tree already draws this distinction one module over: the
/// SSRF guard at `lists/http_client.rs:214-218` maps `::ffff:127.0.0.1`
/// down so it is rejected exactly like `127.0.0.1`. Same reasoning,
/// previously applied in only one of the two places that need it.
///
/// A mapped *specific* address stays legal: `::ffff:192.0.2.53` binds
/// one address and is no more open than `192.0.2.53`.
pub fn binds_every_interface(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.is_unspecified(),
            None => v6.is_unspecified(),
        },
        std::net::IpAddr::V4(v4) => v4.is_unspecified(),
    }
}

/// One spelling per address.
///
/// `::ffff:10.0.0.5` and `10.0.0.5` are the same host, so anything that
/// indexes devices by address has to agree on which of the two it means —
/// the same normalisation [`binds_every_interface`] applies to the bind
/// address, for the same reason.
fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

fn check_server_defaults(
    config: &ConfigV1,
    profile_ids: &HashSet<Id>,
    errs: &mut Vec<ConfigError>,
    warns: &mut AuditWarnings,
) {
    if let Some(default) = &config.server.default_profile {
        if !profile_ids.contains(default) {
            errs.push(ConfigError::CrossRefMiss(
                ErrorContext::new(format!(
                    "server.default_profile \"{default}\" is not defined in [profiles]"
                ))
                .with_entity("server.default_profile")
                .with_suggestion(format!(
                    "add a [profiles.{default}] block, or drop the default_profile field to require a subnet / direct mapping for every client"
                )),
            ));
        }
    }
    if config.server.default_blocked_ttl_secs == 0 {
        errs.push(ConfigError::ValidationFailed(
            ErrorContext::new("server.default_blocked_ttl_secs must be greater than 0".to_string())
                .with_entity("server.default_blocked_ttl_secs"),
        ));
    }
    // `server.allow_from` is the source-IP ACL — a malformed entry is a
    // security-control failure that must surface at `config lint` /
    // reload time, not only when `warden start` first parses it. Mirror
    // the subnet-CIDR check in `check_subnets`; `Cidr::parse` is the same
    // parser the boot path (`start.rs`) uses, so lint / reload / boot agree.
    for (i, entry) in config.server.allow_from.iter().enumerate() {
        if let Err(e) = Cidr::parse(entry) {
            errs.push(ConfigError::ValidationFailed(
                ErrorContext::new(format!(
                    "server.allow_from[{i}] \"{entry}\" is not a valid CIDR: {e}"
                ))
                .with_entity("server.allow_from"),
            ));
        } else if Cidr::input_has_host_bits(entry) {
            // cidr-02: `Cidr::parse` silently masks host bits, so
            // `192.0.2.10/8` (operator meant `/32`) widens this ACL by 24
            // bits with no error. WARN — it's documented behaviour, but on a
            // source-IP allow-list a too-wide entry is a security footgun.
            let msg = format!(
                "server.allow_from[{i}] \"{entry}\" has host bits set below its prefix; \
                 it is masked to the network — did you mean a narrower prefix (e.g. /32)?"
            );
            if warns.emit() {
                tracing::warn!(target: "audit", "{msg}");
            }
            warns.push(msg);
        }
    }
    // rev-2606 init-01: an unspecified bind (0.0.0.0 / ::) with an
    // empty allow_from answers DNS for ANYONE who can route to the
    // host — an open resolver (amplification + cache-probe surface).
    // The DNS handler treats an empty ACL as "accept all"
    // (`dns/handler.rs` `source_allowed`), so the refusal must happen
    // here. Loopback or address-pinned binds with an empty ACL stay
    // legal — only the every-interface + every-source combination is
    // refused. The `--listen` flag path re-asserts this after CLI
    // overrides land (main.rs), since those apply post-validation.
    if binds_every_interface(config.server.listen.ip()) && config.server.allow_from.is_empty() {
        errs.push(ConfigError::ValidationFailed(
            ErrorContext::new(format!(
                "server.listen binds every interface ({}) but server.allow_from is empty — \
                 an open resolver: anyone who can reach this host can query it",
                config.server.listen
            ))
            .with_entity("server.allow_from")
            .with_suggestion(
                "list the client networks allowed to query, e.g. allow_from = \
                 [\"192.168.1.0/24\", \"127.0.0.0/8\"]; or allow_from = [\"0.0.0.0/0\", \"::/0\"] \
                 to deliberately answer everyone; or bind one address in server.listen",
            ),
        ));
    }
    // rev-2606 schema-validator-02: scalar gates on the daemon-startup
    // fields. A zero TCP timeout expires every TCP query instantly; port
    // 0 binds a kernel-chosen ephemeral port — clients can never be
    // pointed at it.
    if config.server.tcp_timeout_secs == 0 {
        errs.push(ConfigError::ValidationFailed(
            ErrorContext::new("server.tcp_timeout_secs must be >= 1 (got 0)".to_string())
                .with_entity("server.tcp_timeout_secs")
                .with_suggestion("set server.tcp_timeout_secs = 10 (the default) or drop the key"),
        ));
    }
    if config.server.listen.port() == 0 {
        errs.push(ConfigError::ValidationFailed(
            ErrorContext::new(
                "server.listen port 0 binds a random ephemeral port — clients can never \
                 be configured to reach it"
                    .to_string(),
            )
            .with_entity("server.listen")
            .with_suggestion("use port 53 for production or 15353 for unprivileged testing"),
        ));
    }
}

// ── [tracking] ─────────────────────────────────────────────────

/// Sprint 38 QLP3: validate the new `retention_days` + `log_mode`
/// knobs. Error messages target non-experts (memory
/// `feedback_usability_first`) — they name the exact field and the
/// acceptable range.
fn check_tracking(config: &ConfigV1, errs: &mut Vec<ConfigError>) {
    let tracking = &config.tracking;
    if tracking.top_n_limit == 0 {
        errs.push(ConfigError::ValidationFailed(
            ErrorContext::new("tracking.top_n_limit must be >= 1 (got 0)".to_string())
                .with_entity("tracking.top_n_limit")
                .with_suggestion("set tracking.top_n_limit = 20 for the default top-N list"),
        ));
    }
    if tracking.retention_days < 1 || tracking.retention_days > 365 {
        errs.push(ConfigError::ValidationFailed(
            ErrorContext::new(format!(
                "tracking.retention_days must be between 1 and 365 (got {})",
                tracking.retention_days
            ))
            .with_entity("tracking.retention_days")
            .with_suggestion("set tracking.retention_days = 7 for a weekly window"),
        ));
    }
    if let crate::config::settings::LogMode::Sampled { allowed_rate } = tracking.log_mode {
        if !(0.0..=1.0).contains(&allowed_rate) || !allowed_rate.is_finite() {
            errs.push(ConfigError::ValidationFailed(
                ErrorContext::new(format!(
                    "tracking.log_mode.sampled.allowed_rate must be between 0.0 and 1.0 (got {allowed_rate})"
                ))
                .with_entity("tracking.log_mode.sampled.allowed_rate")
                .with_suggestion("0.1 samples 1-in-10 allowed queries; 0.0 keeps only blocked"),
            ));
        }
    }
    // settings-02 (rev-2606): a zero interval feeds `Duration::from_secs(0)`
    // into `tokio::time::interval`, which panics — and the release profile's
    // `panic = "abort"` takes the whole daemon down at task spawn. The timer
    // sinks floor to 1 s as a backstop; reject here so the operator learns at
    // lint time, not from a dead daemon.
    if tracking.top_n_interval_secs == 0 {
        errs.push(ConfigError::ValidationFailed(
            ErrorContext::new("tracking.top_n_interval_secs must be >= 1 (got 0)".to_string())
                .with_entity("tracking.top_n_interval_secs")
                .with_suggestion(
                    "set tracking.top_n_interval_secs = 10 (the default) or drop the key",
                ),
        ));
    }
    if tracking.snapshot_interval_secs == 0 {
        errs.push(ConfigError::ValidationFailed(
            ErrorContext::new("tracking.snapshot_interval_secs must be >= 1 (got 0)".to_string())
                .with_entity("tracking.snapshot_interval_secs")
                .with_suggestion(
                    "set tracking.snapshot_interval_secs = 120 (the default) or drop the key",
                ),
        ));
    }
}

// ── [lists] ────────────────────────────────────────────────────

/// `lists.update_interval_secs = 0` (`settings-02`). The list manager
/// already clamps its refresh ticker to 60 s at construction, so a zero
/// here is silently reinterpreted rather than fatal — reject it so the
/// operator's intent and the running cadence cannot diverge without a
/// diagnostic. Frozen (pinned by `tests/frozen_strings_numeric_gates.rs`).
pub const LISTS_UPDATE_INTERVAL_ZERO: &str =
    "lists: `update_interval_secs` must be >= 1 (0 would stall the refresh \
     timer). The default is 43200 (12 hours).";

/// `lists.max_entries = 0` (`settings-03`). The parser treats the cap as
/// "truncate at N", so 0 truncates every list to zero domains — the daemon
/// runs normally with filtering silently off. The field docs always said
/// 0 is rejected at validation time; this gate makes that true. Frozen.
pub const LISTS_MAX_ENTRIES_ZERO: &str =
    "lists: `max_entries` must be >= 1 — 0 truncates every list to zero \
     domains, silently disabling filtering. The default is 5000000; raise \
     the value instead of using 0 for \"unlimited\".";

/// `lists.max_body_bytes = 0` (`settings-03`). 0 aborts every download at
/// the first byte, so every list eventually flips Failed. Frozen.
pub const LISTS_MAX_BODY_BYTES_ZERO: &str =
    "lists: `max_body_bytes` must be >= 1 — 0 refuses every list download. \
     The default is 209715200 (200 MB).";

/// `lists.shrink_guard_max_drop_pct` out of the 1..=100 range (rev-2606
/// §06 `manager-01`). It is a percentage: 0 would refuse a list that
/// shrinks at all (and is ambiguous with "disabled" — use
/// `shrink_guard_enabled = false` for that), and >100 is meaningless.
/// Frozen (pinned by `tests/frozen_strings_numeric_gates.rs`).
pub const LISTS_SHRINK_GUARD_PCT_INVALID: &str =
    "lists: `shrink_guard_max_drop_pct` must be 1..=100 — it is the percent \
     a list may shrink in one refresh before the prior list is kept. The \
     default is 90; set `shrink_guard_enabled = false` to disable the guard \
     instead of using 0.";

/// Validate the legacy `[lists]` pipeline section (rev-2606
/// `settings-02`/`settings-03`). These knobs drive the blocklist
/// download pipeline until S31/S32 retire the section, so a bad scalar
/// here degrades filtering for every profile at once.
fn check_lists(config: &ConfigV1, errs: &mut Vec<ConfigError>) {
    let lists = &config.lists;
    if lists.update_interval_secs == 0 {
        errs.push(ConfigError::ValidationFailed(
            ErrorContext::new(LISTS_UPDATE_INTERVAL_ZERO.to_string())
                .with_entity("lists.update_interval_secs"),
        ));
    }
    if lists.max_entries == 0 {
        errs.push(ConfigError::ValidationFailed(
            ErrorContext::new(LISTS_MAX_ENTRIES_ZERO.to_string()).with_entity("lists.max_entries"),
        ));
    }
    if lists.max_body_bytes == 0 {
        errs.push(ConfigError::ValidationFailed(
            ErrorContext::new(LISTS_MAX_BODY_BYTES_ZERO.to_string())
                .with_entity("lists.max_body_bytes"),
        ));
    }
    if lists.shrink_guard_max_drop_pct == 0 || lists.shrink_guard_max_drop_pct > 100 {
        errs.push(ConfigError::ValidationFailed(
            ErrorContext::new(LISTS_SHRINK_GUARD_PCT_INVALID.to_string())
                .with_entity("lists.shrink_guard_max_drop_pct"),
        ));
    }
}

// ── [security] (rev-2606 config-01 / settings-12) ─────────────

/// `security.rrl.responses_per_second = 0` zeroes the per-window budget —
/// every response throttled, a self-DoS. Frozen (pinned by
/// `tests/frozen_strings_numeric_gates.rs`).
pub const SECURITY_RRL_RPS_ZERO: &str =
    "security.rrl: `responses_per_second` must be >= 1 when rrl is enabled \
     (0 throttles every response — a self-DoS). The default is 100; set \
     `enabled = false` to turn RRL off instead.";

/// `security.rrl.window_secs` outside 1..=86400. 0 resets the counter on
/// every probe (RRL silently off); past-u32 values used to truncate the
/// budget to 0 (throttle-all). `{n}` substituted at construction. Frozen
/// (the template).
pub const SECURITY_RRL_WINDOW_OUT_OF_RANGE: &str =
    "security.rrl: `window_secs` must be 1..=86400 (got {n}). The default \
     is 15.";

/// Substitute `{n}` into [`SECURITY_RRL_WINDOW_OUT_OF_RANGE`]. Public so
/// the frozen-strings test exercises const and helper together.
pub fn format_security_rrl_window_out_of_range(n: u64) -> String {
    SECURITY_RRL_WINDOW_OUT_OF_RANGE.replace("{n}", &n.to_string())
}

/// `security.rate_limit.queries_per_second = 0` — buckets never refill, so
/// every client is starved once its initial burst is spent. Frozen.
pub const SECURITY_RATE_LIMIT_QPS_ZERO: &str =
    "security.rate_limit: `queries_per_second` must be >= 1 when rate_limit \
     is enabled (0 starves every client once its burst is spent). The \
     default is 100; set `enabled = false` to turn rate limiting off \
     instead.";

/// `security.rate_limit.burst = 0` — buckets start and stay at 0 tokens,
/// rejecting 100% of queries for every client. Frozen.
pub const SECURITY_RATE_LIMIT_BURST_ZERO: &str =
    "security.rate_limit: `burst` must be >= 1 when rate_limit is enabled \
     (0 rejects every query from every client). The default is 200.";

/// `security.tunneling.entropy_threshold` NaN / infinite / <= 0. NaN
/// comparisons are all-false, so detection silently never fires; 0 or a
/// negative flags every name with >= 8 bytes of non-apex labels as
/// suspicious (REFUSED). `{n}` substituted at construction. Frozen (the
/// template).
pub const SECURITY_TUNNELING_ENTROPY_INVALID: &str =
    "security.tunneling: `entropy_threshold` must be a finite number > 0.0 \
     (got {n}). NaN silently disables entropy detection; 0 refuses nearly \
     every subdomain query. The default is 3.5.";

/// Substitute `{n}` into [`SECURITY_TUNNELING_ENTROPY_INVALID`]. Public so
/// the frozen-strings test exercises const and helper together.
pub fn format_security_tunneling_entropy_invalid(n: f64) -> String {
    SECURITY_TUNNELING_ENTROPY_INVALID.replace("{n}", &n.to_string())
}

/// `security.tunneling.label_len_threshold = 0` — every label satisfies
/// `len >= 0`, so every name with a non-apex label is REFUSED. Frozen.
pub const SECURITY_TUNNELING_LABEL_LEN_ZERO: &str =
    "security.tunneling: `label_len_threshold` must be >= 1 when tunneling \
     detection is enabled (0 refuses every subdomain query). The default \
     is 48.";

/// `security.tunneling.max_unbroken_run = 0` — every label has a run of
/// at least 0, so every name with a non-apex label is REFUSED. Frozen.
pub const SECURITY_TUNNELING_MAX_RUN_ZERO: &str =
    "security.tunneling: `max_unbroken_run` must be >= 1 when tunneling \
     detection is enabled (0 refuses every subdomain query). The default \
     is 40.";

/// `security.tunneling.entropy_min_len = 0` — restores the pre-fix
/// behaviour this gate exists to prevent: entropy over a 1-2 byte string
/// is meaningless, and the check fires on ordinary hostnames. Frozen.
pub const SECURITY_TUNNELING_ENTROPY_MIN_LEN_ZERO: &str =
    "security.tunneling: `entropy_min_len` must be >= 1 when tunneling \
     detection is enabled (0 lets the entropy heuristic fire on names too \
     short for it to mean anything). The default is 64.";

/// An `exempt_domains` entry that is empty or malformed. A blank or
/// dot-only entry would be compared against every name. Frozen.
pub const SECURITY_TUNNELING_EXEMPT_MALFORMED: &str =
    "security.tunneling: every `exempt_domains` entry must be a non-empty \
     domain name (no empty strings, no bare dots, no whitespace).";

/// An `exempt_domains` entry covering an entire registrable domain. Legal
/// and often what the operator means, but it disarms every tunneling check
/// for every name under it — including names the operator has never seen.
/// Re-emitted on **every** load so a standing exemption does not go quiet.
/// `{d}` substituted at construction. Frozen (the template).
pub const SECURITY_TUNNELING_EXEMPT_BROAD: &str =
    "security.tunneling: `exempt_domains` entry `{d}` covers an entire \
     registrable domain — every name under it skips both the shape gates \
     and the per-client subdomain rate counter. Narrow it to the specific \
     hostname if you can.";

/// Substitute `{d}` into [`SECURITY_TUNNELING_EXEMPT_BROAD`]. Public so the
/// frozen-strings test exercises const and helper together.
pub fn format_security_tunneling_exempt_broad(d: &str) -> String {
    SECURITY_TUNNELING_EXEMPT_BROAD.replace("{d}", d)
}

/// A single-label `exempt_domains` entry (`\"com\"`). Exempting a whole TLD
/// is not a targeted concession — it disables tunneling detection for a
/// large share of the namespace by the back door, which the operator can
/// do openly with `enabled = false`. Refused rather than warned. Frozen.
pub const SECURITY_TUNNELING_EXEMPT_SINGLE_LABEL: &str =
    "security.tunneling: `exempt_domains` entries must have at least two \
     labels (got a single-label entry). Exempting a whole TLD disables \
     tunneling detection for most of the namespace — use `enabled = false` \
     if that is the intent.";

/// `security.tunneling.subdomain_rate = 0` — the per-(client, base) rate
/// check trips on the first cache-miss query. Frozen.
pub const SECURITY_TUNNELING_SUBDOMAIN_RATE_ZERO: &str =
    "security.tunneling: `subdomain_rate` must be >= 1 when tunneling \
     detection is enabled (0 refuses the first upstream lookup per base \
     domain). The default is 50.";

/// `security.tunneling.window_secs = 0` — the rate window resets on every
/// probe, so the rate check never accumulates (silently off). Frozen.
pub const SECURITY_TUNNELING_WINDOW_ZERO: &str =
    "security.tunneling: `window_secs` must be >= 1 when tunneling \
     detection is enabled (0 disables the rate check). The default is 60.";

// ── N1 — `[anti_bypass]` enabled with nothing to enforce ──────────
//
// `AntiBypassConfig::default()` is `enabled = true, extra_domains = []`,
// and `warden init` never writes the section — so this is the state of
// essentially every install. With `neutrality-01` there is no compiled-in
// seed to fall back on, the resulting set is empty, and
// `SecurityLayer::from_config` drops the checker to `None` rather than
// make every query walk a set that cannot match. The drop is right; the
// silence was the defect. The operator's own config asserts a protection
// that does not exist, and nothing — not the log, not `warden config
// lint` — ever said so.

/// Emitted when `[anti_bypass] enabled = true` but no domain source is
/// configured: the checker is never built, and the query path is exactly
/// as it would be with the section switched off.
///
/// Two things this text must keep saying, both load-bearing:
///
/// 1. The remedy is `anti_bypass.extra_domains` and **only** that. It is
///    the sole field `AntiBypass::new` reads.
/// 2. A `[[blocklists]]` subscription is **not** a source for this check.
///    Nothing joins the two — no field, no `BlocklistBase` variant, no
///    CLI verb. List domains are enforced by the filter engine (where an
///    allow rule can override them); `extra_domains` is enforced in
///    `check_pre_query`, ahead of the engine, where nothing can. Pointing
///    an operator at a list here would send them somewhere that cannot
///    produce the behaviour they just asked for.
///
/// Names no provider, by construction — project rules §Neutrality applies to
/// frozen strings too (that is exactly how `neutrality-08` hid).
pub const ANTI_BYPASS_ENABLED_NO_DOMAINS: &str =
    "[anti_bypass] enabled = true but has no domains to block — \
     `anti_bypass.extra_domains` is empty, so no resolver name is refused \
     and the setting protects nothing. warden ships no built-in resolver \
     list; add the names you want refused to `anti_bypass.extra_domains`. \
     A [[blocklists]] subscription does not feed this check — list domains \
     are enforced by the filter engine, where allow rules can override them.";

/// Whether `[anti_bypass]` claims to be on while having nothing to
/// enforce — the condition behind [`ANTI_BYPASS_ENABLED_NO_DOMAINS`].
///
/// Shared with the boot-time emitter in `cli::commands::start` so the two
/// channels cannot drift onto different predicates.
///
/// Deliberately narrow. `SecurityLayer::from_config` has a *second*
/// silent drop — `security.enabled = false` discards every sub-checker,
/// including a populated anti-bypass set — which this does not cover. That
/// is a different condition with a different remedy, and widening the
/// predicate here would make the message above wrong for half the configs
/// that trip it. It is covered separately, by
/// [`security_master_switch_drops_anti_bypass`] /
/// [`SECURITY_DISABLED_DROPS_ANTI_BYPASS`] below — this paragraph used to
/// say the gap was simply uncovered, which is how a known hazard stays a
/// comment instead of becoming a check.
pub fn anti_bypass_has_no_domain_source(config: &ConfigV1) -> bool {
    config.anti_bypass.enabled && config.anti_bypass.extra_domains.is_empty()
}

// ── `[security] enabled = false` silently kills `[anti_bypass]` ────
//
// `SecurityLayer::from_config` returns an all-`None` layer when the master
// switch is off, short-circuiting before the per-feature branches that
// would otherwise honour `anti_bypass.enabled`. An operator who turns off
// RRL / rate-limiting / tunneling with one flag also loses DoH-bypass
// refusal, and the only trace is an INFO line reading "security layer
// disabled".
//
// Found the expensive way, which is why it gets a check rather than a
// comment: during the `neutrality-01` CT smoke the probe config set
// `[security] enabled = false` to stop RRL throttling the probe, and a
// resolver hostname listed in `extra_domains` resolved anyway. Read
// without a control arm that looks like proof the change worked. It was
// proof of nothing — the whole security layer was off.

/// Emitted when the security master switch is off while `[anti_bypass]`
/// asks to be on. WARN, never an error: the config is internally
/// contradictory but perfectly loadable, and the daemon aborts on any
/// `ConfigError` — refusing here would take DNS off the air over a
/// contradiction the operator may well have meant.
///
/// The text must keep naming **both** exits. Telling an operator only to
/// re-enable the master switch would silently re-arm RRL, rate limiting
/// and tunneling detection — the three things they were switching off
/// when they reached for it.
///
/// Names no provider, by construction (§Neutrality binds frozen strings —
/// `neutrality-08` was a vendor name hiding inside one).
pub const SECURITY_DISABLED_DROPS_ANTI_BYPASS: &str =
    "[security] enabled = false switches off every security sub-checker, \
     and `[anti_bypass]` is one of them — its `enabled = true` and its \
     `extra_domains` are read at load and then never reach the query path, \
     so no resolver name is refused. Pick the exit you meant: set \
     `security.enabled = true` and switch off only the sub-features you \
     do not want (`security.rrl`, `security.rate_limit` and \
     `security.tunneling` each have their own `enabled`), or set \
     `anti_bypass.enabled = false` so the config stops claiming a \
     protection that is not running.";

/// Whether the master switch is silently discarding a populated
/// anti-bypass configuration — the condition behind
/// [`SECURITY_DISABLED_DROPS_ANTI_BYPASS`].
///
/// Keyed on `anti_bypass.enabled` alone, **not** on `extra_domains` being
/// non-empty. An operator with an empty list already gets
/// [`ANTI_BYPASS_ENABLED_NO_DOMAINS`]; the two conditions overlap on the
/// default config and that is correct — they are two different reasons
/// the same section enforces nothing, with two different remedies, and an
/// operator who fixes one still needs to know about the other.
pub fn security_master_switch_drops_anti_bypass(config: &ConfigV1) -> bool {
    !config.security.enabled && config.anti_bypass.enabled
}

// ── `safe_search = true` after `neutrality-04` ────────────────────
//
// The flag used to make the resolver inject eight vendor CNAME rewrites
// compiled into the binary. That table was a Key Design Rule 10 violation
// and is gone; `profiles::safesearch::populate` now contributes nothing,
// so a profile serves the same rewrites with the flag set or clear.
//
// Retiring the field outright needs `config/schema/profile.rs`. Until
// that happens the honest thing is to say so on every load, exactly as
// `neutrality-01` did for `[anti_bypass]` when its built-in list went:
// the drop was right, the silence was the defect.

/// Emitted per profile carrying `safe_search = true`.
///
/// Fires whenever the flag is set — **not** only when the profile has no
/// `[[rewrites]]`. The flag is inert in both cases, and a warning that
/// went quiet as soon as the operator added an unrelated rewrite rule
/// would be worse than none: it would read as "fixed".
///
/// Names no vendor and no hostname. It cannot suggest what to redirect
/// where without warden holding the opinion this change removed — the
/// operator takes those values from whichever search engines they
/// actually care about.
pub const SAFE_SEARCH_FLAG_SELECTS_NOTHING: &str =
    "`safe_search = true` no longer selects any rewrite. warden used to \
     compile in a table of search-engine redirects and inject it here; \
     that table named specific vendors, was invisible in your config and \
     could not be corrected without a new build, so it was removed. The \
     effective rewrite set is now exactly this profile's `[[rewrites]]`, \
     with the flag on or off. Add the redirects your search engines \
     document as `[[rewrites]]` entries on this profile; the flag itself \
     enforces nothing.";

/// `local_dns.ttl_secs` outside 1..=86400 (rev-2606 cfg-validator-01).
/// The per-record override has carried this exact bound since S44 (DR5)
/// while the fallback — the value actually stamped on every record
/// without an override, on the NODATA negative answer, and inherited by
/// profile-scope records — was never checked: 0 loads clean and serves
/// cache-busting 0-TTL answers. `{n}` substituted at construction.
/// Frozen (the template).
pub const LOCAL_DNS_TTL_OUT_OF_RANGE: &str =
    "local_dns: `ttl_secs` must be 1..=86400 (got {n}) — it is the served \
     TTL for every record without a per-record override, the NODATA \
     negative TTL, and the fallback for profile-scope records. The default \
     is 3600.";

/// Substitute `{n}` into [`LOCAL_DNS_TTL_OUT_OF_RANGE`]. Public so the
/// frozen-strings test exercises const and helper together.
pub fn format_local_dns_ttl_out_of_range(n: u32) -> String {
    LOCAL_DNS_TTL_OUT_OF_RANGE.replace("{n}", &n.to_string())
}

/// Validate the `[security.*]` scalar knobs (rev-2606 `config-01` +
/// `settings-12` + the `schema-validator-02` float leg). Every gate is
/// scoped to its sub-section's `enabled` flag (all default `true`), so a
/// disabled section with stale values cannot brick an existing config —
/// the error fires at the moment the value would start mattering.
fn check_security(config: &ConfigV1, errs: &mut Vec<ConfigError>, warns: &mut AuditWarnings) {
    let sec = &config.security;
    if !sec.enabled {
        return;
    }

    if sec.rrl.enabled {
        if sec.rrl.responses_per_second == 0 {
            errs.push(ConfigError::ValidationFailed(
                ErrorContext::new(SECURITY_RRL_RPS_ZERO.to_string())
                    .with_entity("security.rrl.responses_per_second"),
            ));
        }
        if !(1..=86_400).contains(&sec.rrl.window_secs) {
            errs.push(ConfigError::ValidationFailed(
                ErrorContext::new(format_security_rrl_window_out_of_range(sec.rrl.window_secs))
                    .with_entity("security.rrl.window_secs"),
            ));
        }
    }

    if sec.rate_limit.enabled {
        if sec.rate_limit.queries_per_second == 0 {
            errs.push(ConfigError::ValidationFailed(
                ErrorContext::new(SECURITY_RATE_LIMIT_QPS_ZERO.to_string())
                    .with_entity("security.rate_limit.queries_per_second"),
            ));
        }
        if sec.rate_limit.burst == 0 {
            errs.push(ConfigError::ValidationFailed(
                ErrorContext::new(SECURITY_RATE_LIMIT_BURST_ZERO.to_string())
                    .with_entity("security.rate_limit.burst"),
            ));
        }
    }

    if sec.tunneling.enabled {
        let entropy = sec.tunneling.entropy_threshold;
        if !entropy.is_finite() || entropy <= 0.0 {
            errs.push(ConfigError::ValidationFailed(
                ErrorContext::new(format_security_tunneling_entropy_invalid(entropy))
                    .with_entity("security.tunneling.entropy_threshold"),
            ));
        }
        if sec.tunneling.label_len_threshold == 0 {
            errs.push(ConfigError::ValidationFailed(
                ErrorContext::new(SECURITY_TUNNELING_LABEL_LEN_ZERO.to_string())
                    .with_entity("security.tunneling.label_len_threshold"),
            ));
        }
        if sec.tunneling.subdomain_rate == 0 {
            errs.push(ConfigError::ValidationFailed(
                ErrorContext::new(SECURITY_TUNNELING_SUBDOMAIN_RATE_ZERO.to_string())
                    .with_entity("security.tunneling.subdomain_rate"),
            ));
        }
        if sec.tunneling.window_secs == 0 {
            errs.push(ConfigError::ValidationFailed(
                ErrorContext::new(SECURITY_TUNNELING_WINDOW_ZERO.to_string())
                    .with_entity("security.tunneling.window_secs"),
            ));
        }
        if sec.tunneling.max_unbroken_run == 0 {
            errs.push(ConfigError::ValidationFailed(
                ErrorContext::new(SECURITY_TUNNELING_MAX_RUN_ZERO.to_string())
                    .with_entity("security.tunneling.max_unbroken_run"),
            ));
        }
        if sec.tunneling.entropy_min_len == 0 {
            errs.push(ConfigError::ValidationFailed(
                ErrorContext::new(SECURITY_TUNNELING_ENTROPY_MIN_LEN_ZERO.to_string())
                    .with_entity("security.tunneling.entropy_min_len"),
            ));
        }

        // `exempt_domains` disarms every tunneling check for a suffix, and
        // those checks run before the filter engine — so a malformed or
        // over-broad entry cannot be caught or narrowed downstream. Two
        // tiers deliberately:
        //
        //   refuse  — malformed, or a bare TLD (a concession so wide it is
        //             `enabled = false` wearing a disguise)
        //   warn    — an entire registrable domain, which is a legitimate
        //             thing to want and the operator's call to make. Warned
        //             on EVERY load rather than once, so a standing
        //             exemption stays visible instead of going quiet.
        for entry in &sec.tunneling.exempt_domains {
            let trimmed = entry.trim();
            let bare = trimmed.trim_matches('.');
            if bare.is_empty() || trimmed.chars().any(char::is_whitespace) {
                errs.push(ConfigError::ValidationFailed(
                    ErrorContext::new(SECURITY_TUNNELING_EXEMPT_MALFORMED.to_string())
                        .with_entity("security.tunneling.exempt_domains"),
                ));
                continue;
            }
            let labels = bare.split('.').filter(|l| !l.is_empty()).count();
            if labels < 2 {
                errs.push(ConfigError::ValidationFailed(
                    ErrorContext::new(SECURITY_TUNNELING_EXEMPT_SINGLE_LABEL.to_string())
                        .with_entity("security.tunneling.exempt_domains"),
                ));
            } else if labels == 2 {
                let msg = format_security_tunneling_exempt_broad(bare);
                if warns.emit() {
                    tracing::warn!(target: "audit", entity = "security.tunneling.exempt_domains", "{msg}");
                }
                warns.push(msg);
            }
        }
    }
}

/// N1 — WARN when `[anti_bypass]` is switched on with nothing to enforce.
///
/// **Never an error, deliberately.** The daemon load path aborts on any
/// `ConfigError` and `scripts/install.sh` Phase 3.5 aborts an upgrade on
/// any non-zero from `warden config lint` — and this is the shape of
/// essentially every install, both live CTs included. Promoting it would
/// take working DNS off the air at the next restart to complain about a
/// config that serves perfectly well. The config is valid; it just does
/// less than it says.
///
/// Separate from [`check_security`] on purpose: that function returns
/// early when `security.enabled` is false, and this diagnostic has to
/// hold for every config, not a subset of them.
fn check_anti_bypass(config: &ConfigV1, warns: &mut AuditWarnings) {
    if anti_bypass_has_no_domain_source(config) {
        // Same shape as the other audit WARNs: the macro stays at the
        // site so its structured field survives into journald, and the
        // text is hoisted so both channels carry identical bytes.
        if warns.emit() {
            tracing::warn!(target: "audit", entity = "anti_bypass", "{ANTI_BYPASS_ENABLED_NO_DOMAINS}");
        }
        warns.push(ANTI_BYPASS_ENABLED_NO_DOMAINS.to_string());
    }

    // The master-switch drop. Separate condition, separate remedy, and
    // deliberately NOT folded into the predicate above — see
    // `anti_bypass_has_no_domain_source`. Both can fire on one config;
    // they are two different reasons the section enforces nothing.
    if security_master_switch_drops_anti_bypass(config) {
        if warns.emit() {
            tracing::warn!(target: "audit", entity = "anti_bypass", "{SECURITY_DISABLED_DROPS_ANTI_BYPASS}");
        }
        warns.push(SECURITY_DISABLED_DROPS_ANTI_BYPASS.to_string());
    }
}

// ── [cache] (rev-2606 settings-11 / schema-validator-02) ──────

/// `cache.min_ttl_secs > cache.max_ttl_secs` — the clamp chain
/// (`.max(min).min(max)`) then silently pins every TTL to `max_ttl_secs`.
/// `{min}`/`{max}` substituted at construction. Frozen (the template,
/// pinned by `tests/frozen_strings_numeric_gates.rs`).
pub const CACHE_TTL_BOUNDS_INVERTED: &str =
    "cache: `min_ttl_secs` ({min}) must be <= `max_ttl_secs` ({max}) — an \
     inverted pair silently pins every cached TTL to max_ttl_secs. The \
     defaults are 60 and 3600.";

/// Substitute `{min}`/`{max}` into [`CACHE_TTL_BOUNDS_INVERTED`]. Public so
/// the frozen-strings test exercises const and helper together.
pub fn format_cache_ttl_bounds_inverted(min: u64, max: u64) -> String {
    CACHE_TTL_BOUNDS_INVERTED
        .replace("{min}", &min.to_string())
        .replace("{max}", &max.to_string())
}

/// `cache.prefetch_threshold` outside the documented `(0.0, 1.0)` open
/// interval (or NaN). NaN/0 never trigger prefetch while `prefetch = true`
/// claims the feature is on. `{n}` substituted at construction. Frozen
/// (the template).
pub const CACHE_PREFETCH_THRESHOLD_INVALID: &str =
    "cache: `prefetch_threshold` must be a finite fraction strictly between \
     0.0 and 1.0 (got {n}). The default is 0.1 — refresh when 10% of the \
     TTL remains; set `prefetch = false` to turn prefetching off instead.";

/// Substitute `{n}` into [`CACHE_PREFETCH_THRESHOLD_INVALID`]. Public so
/// the frozen-strings test exercises const and helper together.
pub fn format_cache_prefetch_threshold_invalid(n: f64) -> String {
    CACHE_PREFETCH_THRESHOLD_INVALID.replace("{n}", &n.to_string())
}

/// Upper bound for `cache.stale_buffer_secs` (24 h). RFC 8767 permits a much
/// longer serve-stale window, but leaving it unbounded lets a single failed
/// refresh pin a dead answer for days — 24 h is the sane ceiling. The message
/// in [`CACHE_STALE_BUFFER_TOO_LARGE`] pins the same literal.
const CACHE_STALE_BUFFER_MAX_SECS: u64 = 86_400;

/// `cache.stale_buffer_secs` (cache-03) above the 24 h cap. `{n}` substituted
/// at construction. Frozen (the template, pinned by
/// `tests/frozen_strings_numeric_gates.rs`).
pub const CACHE_STALE_BUFFER_TOO_LARGE: &str =
    "cache: `stale_buffer_secs` must be <= 86400 (24 h) — the serve-stale \
     window (RFC 8767) is capped so a single failed refresh can't pin a dead \
     answer indefinitely (got {n}). The default is 300.";

/// Substitute `{n}` into [`CACHE_STALE_BUFFER_TOO_LARGE`]. Public so the
/// frozen-strings test exercises const and helper together.
pub fn format_cache_stale_buffer_too_large(n: u64) -> String {
    CACHE_STALE_BUFFER_TOO_LARGE.replace("{n}", &n.to_string())
}

/// `cache.cname_max_depth = 0`. An error: the first CNAME record trips the
/// cap, and a chain past the cap counts as blocked, so every CNAME'd name in
/// the corpus becomes unresolvable. Frozen.
pub const CACHE_CNAME_MAX_DEPTH_ZERO: &str =
    "cache: `cname_max_depth` must be >= 1 — at 0 the first CNAME record \
     already exceeds the cap, and a chain past the cap counts as blocked, so \
     every CNAME'd name stops resolving. It is a depth limit, not an on/off \
     switch. The default is 16.";

/// `cache.cname_max_depth` above the walkers' clamp. A WARN, not an error:
/// the clamp already makes the value behave exactly as `16`, so the config
/// is safe — it just states a depth warden does not follow. `{n}`
/// substituted at construction. Frozen (the template).
///
/// The `16` in the text is [`crate::filter::cname::MAX_HOPS`] spelled out —
/// a frozen string cannot interpolate — so
/// `cache_cname_max_depth_message_states_the_real_cap` asserts the two agree.
pub const CACHE_CNAME_MAX_DEPTH_ABOVE_CAP: &str =
    "cache: `cname_max_depth` is {n}, but both CNAME chain walkers clamp to \
     16 hops, so the extra depth is never followed. Set it to 16 or lower so \
     the config says what warden does.";

/// Substitute `{n}` into [`CACHE_CNAME_MAX_DEPTH_ABOVE_CAP`]. Public so the
/// frozen-strings test exercises const and helper together.
pub fn format_cache_cname_max_depth_above_cap(n: usize) -> String {
    CACHE_CNAME_MAX_DEPTH_ABOVE_CAP.replace("{n}", &n.to_string())
}

/// Validate the `[cache]` scalar knobs (rev-2606 `settings-11` + the
/// `schema-validator-02` cache leg). The TTL-pair check is unconditional
/// (the cache always runs); the prefetch threshold is scoped to
/// `prefetch = true`, matching the enabled-flag doctrine in
/// [`check_security`].
fn check_cache(config: &ConfigV1, errs: &mut Vec<ConfigError>, warns: &mut AuditWarnings) {
    let cache = &config.cache;
    if cache.min_ttl_secs > cache.max_ttl_secs {
        errs.push(ConfigError::ValidationFailed(
            ErrorContext::new(format_cache_ttl_bounds_inverted(
                cache.min_ttl_secs,
                cache.max_ttl_secs,
            ))
            .with_entity("cache.min_ttl_secs"),
        ));
    }
    if cache.prefetch {
        let t = cache.prefetch_threshold;
        if !t.is_finite() || t <= 0.0 || t >= 1.0 {
            errs.push(ConfigError::ValidationFailed(
                ErrorContext::new(format_cache_prefetch_threshold_invalid(t))
                    .with_entity("cache.prefetch_threshold"),
            ));
        }
    }
    // cache-03: cap the serve-stale window. Unconditional (the cache always
    // runs); the default 300 is well under the cap, so existing configs and an
    // unset field are unaffected.
    if cache.stale_buffer_secs > CACHE_STALE_BUFFER_MAX_SECS {
        errs.push(ConfigError::ValidationFailed(
            ErrorContext::new(format_cache_stale_buffer_too_large(cache.stale_buffer_secs))
                .with_entity("cache.stale_buffer_secs"),
        ));
    }
    // Both ends of this range are invisible to the operator at runtime, and
    // they are not the same defect. `0` makes the very first CNAME record
    // trip the cap, so every CNAME'd name becomes unresolvable — refuse it.
    // Above the walkers' clamp the value is already harmless (it behaves
    // exactly as the clamp), so refusing would take the daemon down over a
    // config that resolves correctly; the cost is only that the file states
    // a depth warden does not follow, which is a WARN.
    let depth = cache.cname_max_depth;
    if depth == 0 {
        errs.push(ConfigError::ValidationFailed(
            ErrorContext::new(CACHE_CNAME_MAX_DEPTH_ZERO.to_string())
                .with_entity("cache.cname_max_depth"),
        ));
    } else if depth > crate::filter::cname::MAX_HOPS {
        let msg = format_cache_cname_max_depth_above_cap(depth);
        if warns.emit() {
            tracing::warn!(target: "audit", "{msg}");
        }
        warns.push(msg);
    }
}

// ── [dnssec] (rev-2606 settings-13) ───────────────────────────

/// A `[dnssec]` DoS cap is 0 while `mode != "off"`. The §4.10 engine is
/// fail-closed, so a zero cap (chain depth, query budget, NSEC3
/// iterations, signature budget, verdict-cache TTL) makes effectively
/// every signed zone SERVFAIL. `{field}`/`{default}` substituted at
/// construction. Frozen (the template, pinned by
/// `tests/frozen_strings_numeric_gates.rs`).
pub const DNSSEC_CAP_ZERO: &str =
    "dnssec: `{field}` must be >= 1 when `mode` is not \"off\" (a zero cap \
     makes every signed zone fail validation — the engine is fail-closed). \
     The default is {default}.";

/// Substitute `{field}`/`{default}` into [`DNSSEC_CAP_ZERO`]. Public so
/// the frozen-strings test exercises const and helper together.
pub fn format_dnssec_cap_zero(field: &str, default: u64) -> String {
    DNSSEC_CAP_ZERO
        .replace("{field}", field)
        .replace("{default}", &default.to_string())
}

/// Validate the `[dnssec]` DoS caps (rev-2606 `settings-13`). The section
/// is parsed on every build (the validation *machinery* is behind the
/// default-off `dnssec` cargo feature, the config struct is not), so the
/// gate runs unconditionally — scoped to `mode != off`, mirroring the
/// enabled-flag doctrine: a default `mode = "off"` section is inert no
/// matter what the caps say.
fn check_dnssec(config: &ConfigV1, errs: &mut Vec<ConfigError>) {
    let dnssec = &config.dnssec;
    if dnssec.mode == crate::config::settings::DnssecMode::Off {
        return;
    }
    let caps: [(&str, u64, u64); 5] = [
        ("max_chain_depth", u64::from(dnssec.max_chain_depth), 10),
        ("max_queries", u64::from(dnssec.max_queries), 30),
        (
            "max_nsec3_iterations",
            u64::from(dnssec.max_nsec3_iterations),
            150,
        ),
        (
            "max_signature_verifications",
            u64::from(dnssec.max_signature_verifications),
            256,
        ),
        ("cache_ttl_secs", dnssec.cache_ttl_secs, 3600),
    ];
    for (field, value, default) in caps {
        if value == 0 {
            errs.push(ConfigError::ValidationFailed(
                ErrorContext::new(format_dnssec_cap_zero(field, default))
                    .with_entity(format!("dnssec.{field}")),
            ));
        }
    }
}

// ── [local_dns] ────────────────────────────────────────────────

/// Validate the **global** `[local_dns]` records. Mirrors the per-profile
/// pass in [`check_profiles`]: the shared helper
/// [`crate::config::validator::validate_local_records_v2`] returns
/// `Vec<String>`, which we wrap into `ConfigError::ValidationFailed`.
///
/// Without this pass a global `[local_dns]` section reaching the daemon by
/// hand-edit / `warden migrate` / `warden config restore` is *served*
/// (`LocalRecords::build(&config.local_dns)` in `start.rs`) yet never run
/// through DR16 reserved-IP refusal, DR9 public-suffix-wildcard refusal,
/// the CNAME-loop / A+CNAME-conflict checks, or duplicate detection — while
/// the byte-identical record is refused per-profile. That asymmetry defeats
/// the §10.1 "misconfig fails loudly at load time" guarantee (A6).
fn check_local_dns(config: &ConfigV1, errs: &mut Vec<ConfigError>, warns: &mut AuditWarnings) {
    // rev-2606 cfg-validator-01: the fallback TTL is checked even when the
    // global records list is empty — profile-scope records inherit it as
    // their DR5 fallback (resolver passes `config.local_dns.ttl_secs` into
    // every `ProfileLocalRecords::build`).
    if !(1..=86_400).contains(&config.local_dns.ttl_secs) {
        errs.push(ConfigError::ValidationFailed(
            ErrorContext::new(format_local_dns_ttl_out_of_range(config.local_dns.ttl_secs))
                .with_entity("local_dns.ttl_secs"),
        ));
    }

    if !(1..=86_400).contains(&config.local_dns.dynamic_ttl_secs) {
        errs.push(ConfigError::ValidationFailed(
            ErrorContext::new(format!(
                "local_dns: dynamic_ttl_secs={} is out of range (allowed: 1..=86400)",
                config.local_dns.dynamic_ttl_secs
            ))
            .with_entity("local_dns.dynamic_ttl_secs"),
        ));
    }

    if config.local_dns.records.is_empty() {
        return;
    }
    let mut local_errors: Vec<String> = Vec::new();
    crate::config::validator::validate_local_records_v2_collect(
        &config.local_dns.records,
        "local_dns",
        &mut local_errors,
        warns,
    );
    for msg in local_errors {
        errs.push(ConfigError::ValidationFailed(
            ErrorContext::new(msg).with_entity("local_dns"),
        ));
    }
}

// ── [upstream.ecs] ─────────────────────────────────────────────

/// Range-check the **global** `[upstream.ecs]` source prefixes at load.
/// The per-profile path checks `profile.ecs` prefixes whenever they are
/// set (cfg-validator-05), but a profile with no per-profile override
/// inherits these globals, so an out-of-range value here flows to
/// `EdnsClientSubnet::new` → `Err(PrefixOutOfRange)` → silently disabled
/// ECS, contradicting the documented `0..=32` / `0..=128` contract with
/// no startup diagnostic.
fn check_upstream_ecs(config: &ConfigV1, errs: &mut Vec<ConfigError>) {
    let ecs = &config.upstream.ecs;
    if ecs.source_prefix_v4 > 32 {
        errs.push(ConfigError::ValidationFailed(
            ErrorContext::new(format!(
                "upstream.ecs.source_prefix_v4 must be 0..=32 (got {})",
                ecs.source_prefix_v4
            ))
            .with_entity("upstream.ecs.source_prefix_v4")
            .with_suggestion("set upstream.ecs.source_prefix_v4 = 0 to disable ECS for IPv4"),
        ));
    }
    if ecs.source_prefix_v6 > 128 {
        errs.push(ConfigError::ValidationFailed(
            ErrorContext::new(format!(
                "upstream.ecs.source_prefix_v6 must be 0..=128 (got {})",
                ecs.source_prefix_v6
            ))
            .with_entity("upstream.ecs.source_prefix_v6")
            .with_suggestion("set upstream.ecs.source_prefix_v6 = 0 to disable ECS for IPv6"),
        ));
    }
}

// ── upstream / fallback / forwarding servers (rev-2606) ───────
//   schema-validator-02 = emptiness gate (P1-5);
//   rev2606-upstream-server-shape-lint = per-entry shape parse.

/// `upstream.servers = []`. Boot fails on an empty server list anyway;
/// rejecting at lint closes the lint-vs-boot split (`config lint` is sold
/// as the pre-deploy gate, N4). Frozen (pinned by
/// `tests/frozen_strings_numeric_gates.rs`).
pub const UPSTREAM_SERVERS_EMPTY: &str =
    "upstream: `servers` must list at least one resolver — with none, every \
     cache miss fails. warden does not choose one for you: set it with \
     `warden init --upstream <addr:port>` or edit `upstream.servers`.";

/// `[upstream.fallback].servers = []`. A fallback with no resolver can never
/// take over when the primary circuit-breaks; the constructor bails at boot.
/// Frozen (pinned by `tests/frozen_strings_rev2606_upstream.rs`).
pub const UPSTREAM_FALLBACK_SERVERS_EMPTY: &str =
    "upstream.fallback: `servers` is empty — a fallback with no resolver can \
     never take over. Remove the [upstream.fallback] table or list at least \
     one server.";

/// A `[[forwarding]]` zone with no `servers`. The zone drops every matching
/// query; the constructor bails at boot. Frozen (pinned by
/// `tests/frozen_strings_rev2606_upstream.rs`).
pub const FORWARDING_SERVERS_EMPTY: &str =
    "forwarding: `servers` is empty — a forwarding zone with no resolver drops \
     every matching query. List at least one server or remove the zone.";

/// Validate every upstream server list at lint (rev-2606): the primary
/// `[upstream]`, the optional `[upstream.fallback]`, and each `[[forwarding]]`
/// zone (the three share an identical `Vec<String>` + [`UpstreamMode`] shape,
/// and a typo in any one bricks boot identically). Each list gets the same
/// treatment: non-empty (the generalised P1-5 gate) plus a per-entry shape
/// parse via the SAME functions the transport constructors run at boot
/// ([`crate::upstream::shape`]), so a malformed server fails `config lint`
/// instead of first boot. Shape failures are ERRORs (exit 1) — a malformed
/// entry bricks boot, it is not advisory. The shape check is offline (syntax,
/// not DNS resolvability — see the `shape` module doc).
fn check_upstream_servers(config: &ConfigV1, errs: &mut Vec<ConfigError>) {
    // §5.3: a cluster secondary's master carries no policy — `[upstream]`
    // arrives in the primary's bundle. Demanding it here would make that
    // master unbootable, so the node would never poll, so the bundle that
    // supplies it would never arrive.
    //
    // The guard is on the CONJUNCTION, not on the call. `check_server_list`
    // does emptiness AND the per-entry shape parse behind one early `return`,
    // so skipping the call would silently excuse a MALFORMED upstream too —
    // which is a correctness failure, not the absence this defers.
    //
    // Scoped to this list alone. `[upstream.fallback]` and `[[forwarding]]`
    // below stay unconditional: both are opt-in sections, and an operator who
    // wrote one asked for it. Their absence is not the pre-first-sync state.
    let upstream_deferred_to_the_bundle =
        config.upstream.servers.is_empty() && policy_arrives_from_a_primary(config);
    if !upstream_deferred_to_the_bundle {
        // Same refusal, better instruction. A node scaffolded as a secondary
        // that has not joined yet is refused for the right reason — nothing
        // will bring it an upstream until it syncs — but `UPSTREAM_SERVERS_EMPTY`
        // sends it to `warden init --upstream`, which is the ONE thing it must
        // not do: hand-writing `[upstream]` is what the §5.1 guard then
        // refuses. This is a re-phrasing, not a second exemption: same check,
        // same error, same exit code.
        let awaiting_join = config.upstream.servers.is_empty()
            && !config.cluster.enabled
            && config.cluster.role == ClusterRole::Secondary;
        check_server_list(
            config.upstream.mode,
            &config.upstream.servers,
            "upstream.servers",
            if awaiting_join {
                CLUSTER_SECONDARY_NOT_YET_JOINED
            } else {
                UPSTREAM_SERVERS_EMPTY
            },
            errs,
        );
    }
    if let Some(fb) = &config.upstream.fallback {
        check_server_list(
            fb.mode,
            &fb.servers,
            "upstream.fallback.servers",
            UPSTREAM_FALLBACK_SERVERS_EMPTY,
            errs,
        );
    }
    for zone in &config.forwarding {
        let entity = format!("forwarding[{}].servers", zone.suffix);
        check_server_list(
            zone.mode,
            &zone.servers,
            &entity,
            FORWARDING_SERVERS_EMPTY,
            errs,
        );
    }
}

/// Non-empty + per-entry shape for one upstream server list. `entity` is the
/// TOML path used in the error's `for <entity>` decoration; `empty_msg` is the
/// frozen emptiness string for this list.
fn check_server_list(
    mode: UpstreamMode,
    servers: &[String],
    entity: &str,
    empty_msg: &str,
    errs: &mut Vec<ConfigError>,
) {
    if servers.is_empty() {
        errs.push(ConfigError::ValidationFailed(
            ErrorContext::new(empty_msg.to_string()).with_entity(entity.to_string()),
        ));
        return;
    }
    for (i, s) in servers.iter().enumerate() {
        if let Err(e) = crate::upstream::shape::validate_server_shape(mode, s) {
            errs.push(ConfigError::ValidationFailed(
                ErrorContext::new(format!("{entity}[{i}] ({mode}): {e}"))
                    .with_entity(format!("{entity}[{i}]")),
            ));
        }
    }
}

// ── [backup] (rev-2606 schema-validator-02) ───────────────────

/// Validate `backup.auto_interval` at lint (rev-2606
/// `schema-validator-02`). The typed parser + bounds
/// ([`crate::config::schema::backup::BackupConfig::auto_interval_parsed`])
/// already exist but only ran when the systemd timer fired `--auto` —
/// a typo'd interval passed `config lint` and surfaced hours later in
/// the journal. The error text comes from the typed
/// `IntervalParseError` Display impls.
fn check_backup(config: &ConfigV1, errs: &mut Vec<ConfigError>) {
    if let Err(e) = config.backup.auto_interval_parsed() {
        errs.push(ConfigError::ValidationFailed(
            ErrorContext::new(format!("backup: {e}"))
                .with_entity("backup.auto_interval")
                .with_suggestion(
                    "use a whole number of hours or days, e.g. auto_interval = \"24h\" or \"7d\"",
                ),
        ));
    }
}

// ── [cluster] (§4.11) ──────────────────────────────────────────

/// `cluster.enabled = true` but no `token_hash` set. Frozen (R-pinned by
/// `tests/frozen_strings_cluster.rs`).
pub const CLUSTER_ENABLED_REQUIRES_TOKEN_HASH: &str =
    "cluster: `token_hash` is required when `enabled = true`. \
     Run `warden cluster token` on the primary to generate one.";

/// A node scaffolded as a secondary (`role = "secondary"`) that has not
/// joined yet (`enabled = false`) and therefore has no `[upstream]`.
///
/// Replaces [`UPSTREAM_SERVERS_EMPTY`] for exactly that state. The verdict is
/// identical — the config is refused, same exit code, from the same check —
/// but the generic text sends the operator to `warden init --upstream`, and
/// hand-writing `[upstream]` into a secondary's master is precisely what
/// [`CLUSTER_SECONDARY_MASTER_CARRIES_POLICY`] then refuses. Printing an
/// instruction whose only outcome is a second refusal is worse than printing
/// none. Frozen (pinned by `tests/frozen_strings_cluster.rs`).
pub const CLUSTER_SECONDARY_NOT_YET_JOINED: &str =
    "cluster: this node is configured as a secondary but has not joined a \
     primary yet, so no policy has arrived and `upstream.servers` is empty. \
     Run `warden cluster join --peer <primary-url> --token-file <path>`. Do \
     NOT add an [upstream] here — a secondary's policy comes from its primary, \
     and a master carrying its own is refused.";

/// `role = "secondary"` but no `peer` set. Frozen.
pub const CLUSTER_SECONDARY_REQUIRES_PEER: &str =
    "cluster: `peer` is required when `role = \"secondary\"`. \
     Set it to the primary's API base URL, e.g. peer = \"https://192.0.2.10:8053\".";

/// An `allow_peer` entry is not a valid CIDR. `{entry}`/`{reason}` are
/// substituted at error-construction time. Frozen (the template, not the
/// substituted result).
pub const CLUSTER_ALLOW_PEER_INVALID_CIDR: &str =
    "cluster: `allow_peer` entry '{entry}' is not a valid CIDR ({reason}). \
     Use forms like 192.0.2.10/32 or 192.0.2.0/24.";

/// `role = "secondary"` but `peer` is not an acceptable URL (`poll-02` /
/// `schema-validator-12`). `{peer}`/`{reason}` substituted at construction.
/// Frozen (the template).
pub const CLUSTER_SECONDARY_PEER_INVALID: &str =
    "cluster: `peer` '{peer}' is not a valid URL ({reason}). \
     Use the primary's https:// API base URL, e.g. peer = \"https://192.0.2.10:8053\".";

/// `enabled = true` with `poll_interval_secs = 0` (`poll-03`). A zero period
/// panics the secondary poll ticker, so the node never syncs. Frozen.
pub const CLUSTER_POLL_INTERVAL_ZERO: &str =
    "cluster: `poll_interval_secs` must be >= 1 when `enabled = true` \
     (0 stops the secondary from ever syncing). The default is 15.";

/// A `cluster.enabled` secondary whose MASTER carries replicated policy.
///
/// The loader would merge it with the primary's bundle, and the merge shapes
/// fail **differently**: a singleton like `[upstream]` is a hard error, but an
/// array-of-tables (`[[blocklists]]`, `[[devices]]`, …) is *silent
/// concatenation* (`loader.rs`), and a named map with a different id is a
/// *silent union*. The operator experience without this guard is the worst
/// available ordering — the loud failure comes first, the operator deletes
/// `[upstream]` to make sync start, and is then left with the silent ones. The
/// secondary permanently filters a superset of the primary and sync reports
/// success (§5.1).
///
/// The offending sections are appended with their `file:line`. Frozen (pinned
/// by `tests/frozen_strings_cluster.rs`).
pub const CLUSTER_SECONDARY_MASTER_CARRIES_POLICY: &str =
    "cluster: this node is a secondary, so its policy arrives from the \
     primary — but the master config carries policy of its own. The loader \
     would MERGE the two, concatenating lists silently, and this node would \
     filter more than the primary does. Move these sections out of the \
     master (the primary supplies them):";

/// §5.1 — refuse a cluster secondary whose master carries replicated policy.
///
/// Runs at **every** load, not only at `cluster join`: a join-time check does
/// not stop an operator adding a device a month later, and the hazard is the
/// merge, which happens on every boot.
///
/// `provenance` is `None` when the caller has no map (the pure
/// [`validate`] entry point and its tests), which disables **only** this
/// cross-check — the same `Option<&T>` shape and semantics as the `secrets`
/// parameter, and for the same reason: the map is *data*, so `validate_collect`
/// stays a pure function of its arguments and its tests need no filesystem.
///
/// **Reported at SECTION granularity, deliberately.** The provenance map also
/// carries per-entity keys (`blocklists.ads`), but §5's remedy is "move these
/// sections out of the master" — an operator does not delete row 2, they move
/// the section. Naming every row would bury the instruction in a list.
///
/// **Refuse, never sanitise.** Rewriting an operator's config to make our own
/// feature work is worse than refusing: `join` is not the moment to discover
/// that warden deleted the device list.
fn check_secondary_master_is_policy_free(
    config: &ConfigV1,
    provenance: Option<&ProvenanceMap>,
    errs: &mut Vec<ConfigError>,
) {
    if !policy_arrives_from_a_primary(config) {
        return;
    }
    let Some(map) = provenance else {
        return;
    };

    let offenders = replicated_policy_outside_the_drop_in(map);
    if offenders.is_empty() {
        return;
    }
    errs.push(ConfigError::ValidationFailed(
        ErrorContext::new(format!(
            "{CLUSTER_SECONDARY_MASTER_CARRIES_POLICY} {}",
            describe_policy_origins(&offenders)
        ))
        .with_entity("cluster.role"),
    ));
}

/// One replicated section found somewhere other than the sync-owned drop-in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyOrigin {
    /// The top-level TOML section, e.g. `blocklists`.
    pub section: &'static str,
    /// The file it was defined in.
    pub file: std::path::PathBuf,
    /// 1-based line of the section heading.
    pub line: usize,
}

/// Every replicated section in `provenance` that originates OUTSIDE the
/// sync-owned drop-in — i.e. policy this node wrote for itself.
///
/// Public because `cluster join` runs the same scan against the RAW master
/// before writing anything, so the operator is given their real config's path
/// rather than the staging temp file's. Two implementations of one rule drift;
/// this is the rule.
///
/// Reported at SECTION granularity, deliberately. The map also carries
/// per-entity keys (`blocklists.ads`), but §5's remedy is "move these sections
/// out of the master" — an operator does not delete row 2, they move the
/// section. Naming every row would bury the instruction in a list.
#[must_use]
pub fn replicated_policy_outside_the_drop_in(provenance: &ProvenanceMap) -> Vec<PolicyOrigin> {
    let mut found = Vec::new();
    for section in REPLICATED_SECTIONS {
        if REPLICATED_BUT_ALLOWED_IN_A_SECONDARY_MASTER.contains(section) {
            continue;
        }
        // Both the bare section key and the per-entity keys must be
        // consulted, and the drop-in filter must run INSIDE the search rather
        // than on its result.
        //
        // A plain table records its own key (`upstream`), but a named map
        // written only as `[profiles.default]` records NO bare `profiles` key
        // — so the section key alone misses `[profiles.*]` entirely, which is
        // the section most likely to be hand-written on a second node. And
        // filtering *after* picking the first sub-key is the same blindness
        // one step later: `ProvenanceMap` is a `BTreeMap`, so on a secondary
        // holding `profiles.local-only` beside the bundle's
        // `profiles.default`, the sorted-first entry is the legitimate one
        // and the search stops on it. Either mistake lets a real offender
        // through while every other case still reports correctly.
        let sub_prefix = format!("{section}.");
        let offender = provenance
            .iter()
            .filter(|(key, _)| key.as_str() == *section || key.starts_with(&sub_prefix))
            .find(|(_, (file, _))| !is_cluster_drop_in(file));
        if let Some((_, (file, line))) = offender {
            found.push(PolicyOrigin {
                section,
                file: file.clone(),
                line: *line,
            });
        }
    }
    found
}

/// Render [`PolicyOrigin`]s as `section (file:line), …` for an operator.
#[must_use]
pub fn describe_policy_origins(origins: &[PolicyOrigin]) -> String {
    origins
        .iter()
        .map(|o| format!("{} ({}:{})", o.section, o.file.display(), o.line))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Does this node replicate its policy from a primary?
///
/// If so it is not required to carry that policy in its own master (§5.3) —
/// the checks that fire purely on a policy section being **absent** are
/// deferred to the merged tree, where the primary's bundle supplies it.
///
/// **Scoped to ABSENCE, on purpose.** A malformed policy entry still fails,
/// on every role: this predicate never reaches a correctness check.
///
/// **`enabled` is part of the predicate and must stay.** `role` alone says
/// where policy *would* come from; `enabled` says whether this node is
/// actually syncing. A node with `role = "secondary"` and `enabled = false`
/// has scaffolded the intent but not joined, so nothing will ever bring it an
/// `[upstream]` — exempting it would yield a config that loads and a daemon
/// that resolves nothing, which fails at query time instead of at load time.
/// That state is refused (see `an_unjoined_secondary_gets_no_exemption`), and
/// `warden init --cluster-secondary` is expected to produce it.
fn policy_arrives_from_a_primary(config: &ConfigV1) -> bool {
    config.cluster.enabled && config.cluster.role == ClusterRole::Secondary
}

/// Validate the `[cluster]` section (§4.11). Inert sprint: this only
/// enforces the structural invariants that CS2/CS8 imply at the schema
/// level — the runtime (poll loop, endpoints, failover) lands later.
///
/// Rules:
/// - `enabled = true` ⇒ `token_hash` must be non-empty (CS2 — a cluster
///   with no shared secret cannot authenticate).
/// - `role = "secondary"` ⇒ `peer` must be non-empty (CS1 — a follower
///   needs a primary to poll).
/// - every `allow_peer` entry must parse as a CIDR (defence-in-depth gate
///   wired in a later phase; we reject malformed entries now so they never
///   reach that code path).
fn check_cluster(config: &ConfigV1, errs: &mut Vec<ConfigError>) {
    let cluster = &config.cluster;

    if cluster.enabled {
        let has_hash = cluster
            .token_hash
            .as_deref()
            .is_some_and(|h| !h.trim().is_empty());
        if !has_hash {
            errs.push(ConfigError::MissingRequired(
                ErrorContext::new(CLUSTER_ENABLED_REQUIRES_TOKEN_HASH.to_string())
                    .with_entity("cluster.token_hash"),
            ));
        }

        // poll-03: a zero poll period panics `tokio::time::interval`, which on
        // the `panic = "abort"` release profile takes the daemon down (or, under
        // tokio::spawn, silently never syncs). Reject it at lint time.
        if cluster.poll_interval_secs == 0 {
            errs.push(ConfigError::ValidationFailed(
                ErrorContext::new(CLUSTER_POLL_INTERVAL_ZERO.to_string())
                    .with_entity("cluster.poll_interval_secs"),
            ));
        }
    }

    if cluster.role == ClusterRole::Secondary {
        match cluster.peer.as_deref() {
            Some(p) if !p.trim().is_empty() => {
                // poll-02 / schema-validator-12: a secondary sends the plaintext
                // cluster token to `peer` on every poll, so it must be a real
                // https:// URL (loopback http:// allowed). Lint-time defence in
                // depth behind the same check at `cluster join`.
                if let Err(reason) = validate_peer_url(p) {
                    errs.push(ConfigError::ValidationFailed(
                        ErrorContext::new(
                            CLUSTER_SECONDARY_PEER_INVALID
                                .replace("{peer}", p.trim())
                                .replace("{reason}", &reason),
                        )
                        .with_entity("cluster.peer"),
                    ));
                }
            }
            _ => {
                errs.push(ConfigError::MissingRequired(
                    ErrorContext::new(CLUSTER_SECONDARY_REQUIRES_PEER.to_string())
                        .with_entity("cluster.peer"),
                ));
            }
        }
    }

    for (i, entry) in cluster.allow_peer.iter().enumerate() {
        if let Err(reason) = Cidr::parse(entry) {
            errs.push(ConfigError::ValidationFailed(
                ErrorContext::new(
                    CLUSTER_ALLOW_PEER_INVALID_CIDR
                        .replace("{entry}", entry)
                        .replace("{reason}", &reason),
                )
                .with_entity(format!("cluster.allow_peer[{i}]")),
            ));
        }
    }
}

// ── [api] (rev-2606 §07) ───────────────────────────────────────

/// `api.enabled = true` but no `token_hash` set. Without it every request
/// is rejected with a bare 401 and no hint. Frozen (pinned by
/// `tests/frozen_strings_api.rs`).
pub const API_ENABLED_REQUIRES_TOKEN_HASH: &str =
    "api: `token_hash` is required when `enabled = true`. \
     Run `warden token generate` to create one.";

/// `api.listen` is non-loopback but TLS is not configured — the bearer
/// token would travel in cleartext on every request. Frozen.
pub const API_NONLOOPBACK_REQUIRES_TLS: &str =
    "api: `listen` is non-loopback but TLS is not configured — bearer \
     tokens would travel in cleartext. Set both `tls_cert` and `tls_key`, \
     or bind a loopback address (default 127.0.0.1:8053).";

/// Exactly one of `api.tls_cert` / `api.tls_key` is set — the server
/// requires the pair and otherwise falls back to plain HTTP. Frozen.
pub const API_TLS_PAIR_INCOMPLETE: &str =
    "api: `tls_cert` and `tls_key` must be set together — with only one, \
     the server silently falls back to plain HTTP.";

/// rev-2606 §07 addendum: `metrics_enabled` on a non-loopback `api.listen`
/// serves `GET /metrics` operational telemetry (query rate, block ratio,
/// device count) UNAUTHENTICATED to the whole network — `/metrics` sits
/// outside the auth layer by design, and the validator-forced TLS encrypts
/// but does not authenticate the scrape. A posture WARN (audit log), NOT a
/// refusal: a deliberate public-TLS scrape behind the operator's own network
/// ACL is a valid setup. `{addr}` substituted at construction. Frozen (pinned
/// by `tests/frozen_strings_api.rs`).
pub const API_METRICS_PUBLIC_UNAUTH: &str =
    "api: `metrics_enabled = true` with a non-loopback `listen` ({addr}) serves \
     GET /metrics (query rate, block ratio, device count) UNAUTHENTICATED to the \
     whole network — TLS encrypts but does not authenticate it. Bind the API to \
     loopback, restrict /metrics with your own network ACL, or set \
     `metrics_enabled = false` if this is unintended.";

/// Substitute `{addr}` into [`API_METRICS_PUBLIC_UNAUTH`]. Public so the
/// frozen-strings test exercises const and helper together.
pub fn format_api_metrics_public_unauth(addr: &SocketAddr) -> String {
    API_METRICS_PUBLIC_UNAUTH.replace("{addr}", &addr.to_string())
}

/// Validate the `[api]` section (rev-2606 `api-auth-07-01`/`07-02`).
/// Inert when `enabled = false`, mirroring `[cluster]`.
///
/// Rules:
/// - `enabled = true` ⇒ `token_hash` must be non-empty (otherwise the
///   server binds and 401s every request with no diagnostic).
/// - `enabled = true` + non-loopback `listen` ⇒ both `tls_cert` and
///   `tls_key` must be set (otherwise `spawn_api_server` takes the
///   plain-HTTP branch and bearer tokens cross the network in clear).
/// - `enabled = true` ⇒ `tls_cert`/`tls_key` set together or not at all
///   (a half pair silently degrades to plain HTTP).
/// - `enabled = true` + `metrics_enabled` + non-loopback `listen` ⇒ audit
///   WARN (rev-2606 §07 addendum) — `/metrics` is served unauthenticated
///   network-wide; a posture notice, not a refusal.
fn check_api(config: &ConfigV1, errs: &mut Vec<ConfigError>, warns: &mut AuditWarnings) {
    let api = &config.api;
    if !api.enabled {
        return;
    }

    let has_hash = api
        .token_hash
        .as_deref()
        .is_some_and(|h| !h.trim().is_empty());
    if !has_hash {
        errs.push(ConfigError::MissingRequired(
            ErrorContext::new(API_ENABLED_REQUIRES_TOKEN_HASH.to_string())
                .with_entity("api.token_hash"),
        ));
    }

    let tls_pair = (api.tls_cert.is_some(), api.tls_key.is_some());
    match tls_pair {
        (true, false) | (false, true) => {
            errs.push(ConfigError::ValidationFailed(
                ErrorContext::new(API_TLS_PAIR_INCOMPLETE.to_string()).with_entity(if tls_pair.0 {
                    "api.tls_key"
                } else {
                    "api.tls_cert"
                }),
            ));
        }
        (false, false) if !api.listen.ip().is_loopback() => {
            errs.push(ConfigError::ValidationFailed(
                ErrorContext::new(API_NONLOOPBACK_REQUIRES_TLS.to_string())
                    .with_entity("api.listen"),
            ));
        }
        _ => {}
    }

    // rev-2606 §07 addendum: `/metrics` sits outside the auth layer by design,
    // so `metrics_enabled` on a non-loopback bind exposes operational telemetry
    // unauthenticated network-wide (TLS encrypts but doesn't authenticate). WARN
    // via the audit log, not a refusal — a deliberate public-TLS scrape behind a
    // network ACL is a valid setup, so we surface it without blocking boot.
    if api.metrics_enabled && !api.listen.ip().is_loopback() {
        let msg = format_api_metrics_public_unauth(&api.listen);
        if warns.emit() {
            tracing::warn!(target: "audit", "{msg}");
        }
        warns.push(msg);
    }
}

// ── [[blocklists]] ─────────────────────────────────────────────

/// True if a URL embeds `userinfo` (`scheme://user[:pass]@host/…`).
/// Dependency-free authority scan (the config layer must not pull in
/// reqwest/url): take the substring after `://`, cut it at the first
/// `/`, `?`, or `#` to isolate the authority, and look for `@`. A `@`
/// elsewhere in the path is correctly ignored (blocklist-01).
fn url_has_embedded_userinfo(url: &str) -> bool {
    let after_scheme = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme)
        .contains('@')
}

/// A CIDR that covers its whole address family, and WHICH family it covers.
///
/// Parsed, not textual. Two reasons the string cannot answer this:
/// `Cidr::parse` reads the prefix with `str::parse::<u8>`, which accepts
/// `/00` — a catch-all an `ends_with("/0")` test calls an ordinary subnet —
/// and the text alone does not say whether the coverage is v4 or v6, which
/// is the half that matters to every caller.
///
/// `None` when the entry does not parse; `check_subnets` already reports
/// that as its own error.
fn catch_all_family(cidr: &str) -> Option<CatchAll> {
    match Cidr::parse(cidr).ok()? {
        Cidr::V4 { prefix: 0, .. } => Some(CatchAll::V4),
        Cidr::V6 { prefix: 0, .. } => Some(CatchAll::V6),
        _ => None,
    }
}

/// Which address family a `/0` subnet covers. `Cidr::contains` is
/// family-strict, so a v4 default route says nothing about v6 clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CatchAll {
    V4,
    V6,
}

/// `lint-warn-no-default-profile` — the config is valid, and the daemon will
/// REFUSE every query from any source it does not recognise.
///
/// SN2 made this the deliberate way to express "unmapped clients get nothing":
/// leaving `[server].default_profile` unset means resolver level 5 falls
/// through to REFUSED. That is a legitimate restrictive posture (design rule 5
/// says the default profile must be the strictest), so this is a **WARN and
/// never an error** — refusing the load would break the operators who chose it
/// on purpose.
///
/// It has to be *said*, though. The reported footgun is a fresh install that
/// lints clean, starts clean, and answers nothing, with no diagnostic anywhere
/// connecting the silence to the missing key. `config lint` printing
/// `default_profile: <none>` in its summary is not that diagnostic: it states
/// the field's value, not the consequence, and it prints on stdout among the
/// entity counts rather than in the warnings block an operator reads.
///
/// Suppressed only when BOTH families carry a `/0`. A `/0` covers level 4
/// for its own family and no further: `Cidr::contains` answers `false` on a
/// family mismatch, so a lone `0.0.0.0/0` leaves every IPv6 client falling
/// through to level 5 and being REFUSED — which is exactly what this warning
/// is for. Suppressing on either one alone silences the diagnostic on the
/// ordinary dual-stack LAN it was written to describe.
fn check_level5_refuses_everything(config: &ConfigV1, warns: &mut AuditWarnings) {
    if config.server.default_profile.is_some() {
        return;
    }
    let (mut v4_covered, mut v6_covered) = (false, false);
    for subnet in &config.subnets {
        for cidr in &subnet.cidrs {
            match catch_all_family(cidr) {
                Some(CatchAll::V4) => v4_covered = true,
                Some(CatchAll::V6) => v6_covered = true,
                None => {}
            }
        }
    }
    if v4_covered && v6_covered {
        return;
    }
    let msg = NO_DEFAULT_PROFILE_REFUSES_UNMATCHED.to_string();
    if warns.emit() {
        tracing::warn!(target: "audit", "{msg}");
    }
    warns.push(msg);
}

/// Authority (host) of a URL, without a URL parser.
///
/// Same constraint as [`url_has_embedded_userinfo`] above: the config layer
/// must not pull in `url`/`reqwest` — those belong to the fetcher. Hand-rolled
/// scanning is therefore the sanctioned shape here, and the drift risk it
/// creates is answered by the cross-check test
/// `blocklist_url_policy_agrees_with_the_fetcher`, which runs this against the
/// real [`crate::lists::http_client::validate_list_url`].
fn url_host_of(url: &str) -> &str {
    let after_scheme = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    // Userinfo, when present, precedes the last `@`.
    let hostport = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    // An IPv6 literal is bracketed; its inner colons are not a port
    // separator, so the bracket form has to be peeled before the port split.
    if let Some(inner) = hostport
        .strip_prefix('[')
        .and_then(|s| s.split_once(']'))
        .map(|(h, _)| h)
    {
        return inner;
    }
    hostport.split_once(':').map(|(h, _)| h).unwrap_or(hostport)
}

/// Mirror of `lists::http_client::is_disallowed_ipv4`.
fn fetch_disallowed_v4(v4: Ipv4Addr) -> bool {
    if v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_multicast()
        || v4.is_unspecified()
    {
        return true;
    }
    let [a, b, _, _] = v4.octets();
    // CGNAT: 100.64.0.0/10
    if a == 100 && (64..=127).contains(&b) {
        return true;
    }
    // "this network": 0.0.0.0/8
    a == 0
}

/// Mirror of `lists::http_client::is_disallowed_ipv6`.
fn fetch_disallowed_v6(v6: Ipv6Addr) -> bool {
    if v6.is_loopback() || v6.is_multicast() || v6.is_unspecified() {
        return true;
    }
    let segs = v6.segments();
    // ULA fc00::/7
    if (segs[0] & 0xfe00) == 0xfc00 {
        return true;
    }
    // Link-local fe80::/10
    if (segs[0] & 0xffc0) == 0xfe80 {
        return true;
    }
    // IPv4-mapped — forward, so `::ffff:127.0.0.1` is caught like `127.0.0.1`.
    if let Some(v4) = v6.to_ipv4_mapped() {
        return fetch_disallowed_v4(v4);
    }
    false
}

/// True when `host` is an IP literal the fetcher refuses to dial.
///
/// A DNS name returns `false`: resolving it here would be a network call in
/// the validator, and the fetcher's own guard re-checks the resolved address
/// anyway. This aligns the *statically decidable* half of the policy, which is
/// the half a lint can honestly own.
fn host_is_unfetchable(host: &str) -> bool {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => fetch_disallowed_v4(v4),
        Ok(IpAddr::V6(v6)) => fetch_disallowed_v6(v6),
        Err(_) => false,
    }
}

fn check_blocklists(
    config: &ConfigV1,
    errs: &mut Vec<ConfigError>,
    warns: &mut AuditWarnings,
    secrets: Option<&Secrets>,
) {
    for (i, b) in config.blocklists.iter().enumerate() {
        if !b.url.starts_with("http://") && !b.url.starts_with("https://") {
            errs.push(ConfigError::ValidationFailed(
                ErrorContext::new(format!(
                    "blocklists[{i}].url must begin with http:// or https:// (got \"{}\")",
                    b.url
                ))
                .with_entity(format!("blocklists.{}", b.id)),
            ));
        }
        // blocklist-01 (rev-2606 §05): refuse credentials embedded in the URL
        // (`https://user:pass@host/…`). They would live in the 0640 master,
        // surface in `config show` / diff output, and bypass the N9 secrets
        // model — the supported path for an authenticated list is
        // `auth_token_ref` (a token from secrets.toml). The fetcher already
        // refuses these (`lists::http_client::validate_list_url`); aligning the
        // validator closes the lint-clean-but-can't-fetch split. The URL is
        // NOT echoed (it carries the credential). Dependency-free authority
        // scan — the config layer must not pull in reqwest/url.
        if url_has_embedded_userinfo(&b.url) {
            errs.push(ConfigError::ValidationFailed(
                ErrorContext::new(format!(
                    "blocklists[{i}].url must not embed credentials; use auth_token_ref for an authenticated list"
                ))
                .with_entity(format!("blocklists.{}", b.id)),
            ));
        }
        // rev-2606 §05 schema-validator-03 — close the lint-vs-runtime split
        // A6/§10.1 forbids, on a security control. The fetcher
        // (`lists::http_client::validate_list_url`) is https-only and refuses
        // private / loopback / link-local / CGNAT / unspecified literals, so a
        // list failing either rule lints clean today and then never fetches:
        // `consecutive_failures` climbs, the list flips Failed, and it filters
        // nothing — silently.
        //
        // WARN, not a refusal, and the asymmetry is forced rather than
        // preferred. A refusal here is a daemon that will not start on any
        // config already carrying such a list, and warden's own error path
        // treats every `ConfigError` at load as fatal. The same argument that
        // keeps a toothless `[anti_bypass]` non-fatal applies unchanged: the
        // diagnostic must reach the operator without taking their resolver
        // down to deliver it.
        if b.url.starts_with("http://") {
            let msg = format_blocklist_url_cleartext_http(b.id.as_str());
            if warns.emit() {
                tracing::warn!(target: "audit", blocklist = %b.id.as_str(), "{msg}");
            }
            warns.push(msg);
        }
        let host = url_host_of(&b.url);
        if host_is_unfetchable(host) {
            let msg = format_blocklist_url_unfetchable_host(b.id.as_str(), host);
            if warns.emit() {
                tracing::warn!(target: "audit", blocklist = %b.id.as_str(), "{msg}");
            }
            warns.push(msg);
        }
        if b.update_interval_hours == 0 {
            errs.push(ConfigError::ValidationFailed(
                ErrorContext::new(format!(
                    "blocklists[{i}].update_interval_hours must be greater than 0"
                ))
                .with_entity(format!("blocklists.{}", b.id)),
            ));
        }
        if b.max_entries == 0 {
            errs.push(ConfigError::ValidationFailed(
                ErrorContext::new(format!(
                    "blocklists[{i}].max_entries must be greater than 0"
                ))
                .with_entity(format!("blocklists.{}", b.id)),
            ));
        }
        // blocklist-02 (rev-2606): the manager increments first, then
        // compares `count >= max`, so 0 flips the list to Failed on its
        // FIRST transient error (one 503 = list dead until manual reset).
        // The backup section's `disable_after_failures = 0` means the
        // opposite ("never") — reject 0 here rather than silently pick
        // a semantic.
        if b.max_consecutive_failures == 0 {
            errs.push(ConfigError::ValidationFailed(
                ErrorContext::new(format!(
                    "blocklists[{i}].max_consecutive_failures must be >= 1 (got 0) — 0 \
                     would mark the list Failed on its first transient fetch error. \
                     The default is 5."
                ))
                .with_entity(format!("blocklists.{}", b.id)),
            ));
        }
        if b.display_name.trim().is_empty() {
            errs.push(ConfigError::MissingRequired(
                ErrorContext::new(format!("blocklists[{i}].display_name must not be empty"))
                    .with_entity(format!("blocklists.{}", b.id)),
            ));
        }
        // rev-2606 schema-validator-11: length + control-char bounds
        // (emptiness already handled above with its frozen message).
        check_display_text(
            &b.display_name,
            &format!("blocklists.{}", b.id),
            "display_name",
            DISPLAY_NAME_MAX_BYTES,
            false,
            errs,
        );
        // **`ALLOW_LIST_NO_TAGS_NO_EFFECT` is no longer emitted here, and
        // retiring it is a correctness fix, not a cleanup.**
        //
        // It said an untagged allow-list "has no effect", which was true
        // only because tag intersection decided which lists reached a
        // profile. `plp-s3` cut that: direction is inherited by every
        // profile from the list's own `kind`, so an untagged allow-list is
        // now maximally live — it permits its domains everywhere. The
        // string would have kept loading, kept looking reassuring, and
        // described the opposite of what the daemon does. A diagnostic that
        // lies is worse than a missing one (project rules §Neutrality, on the
        // `signed` WARN).
        //
        // `_docs/features/profile_list_policy.md` §2.2 retires the property
        // outright ("Allow-list senza tag = inerte → ritirato — perde la
        // premessa"), and §2.5 names the replacement: a standing-exposure
        // WARN on the direction itself, for every trust, emitted below in
        // `check_blocklist_base_trust`. **`plp-s5f` has since retired the
        // const and its frozen-string test**; the replacement is byte-pinned
        // in `tests/frozen_strings_plp_profile_diagnostics.rs`.
        // **`ALLOW_LIST_USES_SYSTEM_TAG` is no longer raised, and it is the
        // same retirement as the WARN above — one rule, both severities.**
        //
        // It refused a `base = allow` list tagged `uncategorized`, on the
        // grounds that warden gave that tag to every device it had not been
        // configured for, so the list lifted blocks for all of them. True
        // while tag intersection decided the audience. It does not: in v3 an
        // allow-direction list is inherited by every profile that does not
        // override it, so the sentinel is not what makes it wide — the
        // direction is, and the operator typed that.
        //
        // Keeping the ERROR would have refused a load for a reason that no
        // longer applies, on a config the same binary's `blocklist` verbs now
        // accept. `_docs/features/profile_list_policy.md` §2.5 declines to
        // transfer the refusal and moves the visibility it bought into
        // `ALLOW_DIRECTION_LIST_STANDING_EXPOSURE`, which fires at every load
        // for every allow-direction list — a superset of what this caught.
        //
        // **`plp-s5f` has since retired the const, its suggestion and their
        // frozen-string tests.** Nothing replaces the ERROR: §2.5 declined to
        // transfer it, and the visibility it bought lives in the WARN named
        // above, which fires for every allow-direction list at every load.

        // s4 config-m4 — `auth_token_ref` must name a secret that exists.
        //
        // Gated on `is_loaded()`: a missing `secrets.toml` yields an empty
        // table with `loaded == false`, and an operator who has not set up
        // secrets at all must still boot. Only a *populated* file that omits
        // the named key is a dangling reference.
        //
        // Until this check existed the two mitigations downstream
        // (`lists::source_key::SourceTokenMap::from_config` at token-map
        // build, `cli::commands::blocklists` at `blocklist add`) both warned
        // and then fetched anonymously — so a typo booted clean and surfaced
        // as an opaque fetch failure one refresh interval later. Wording is
        // kept deliberately close to theirs so the operator hears one message.
        if let (Some(ref_name), Some(table)) = (b.auth_token_ref.as_deref(), secrets) {
            if table.is_loaded() && table.get(ref_name).is_none() {
                let known = table.names();
                let suggestion = if known.is_empty() {
                    format!(
                        "add `{ref_name} = \"<token>\"` to secrets.toml, or drop auth_token_ref \
                         to fetch this list anonymously (the file currently defines no secrets)"
                    )
                } else {
                    format!(
                        "add `{ref_name} = \"<token>\"` to secrets.toml, drop auth_token_ref to \
                         fetch anonymously, or use one of the names already defined: {}",
                        known.join(", ")
                    )
                };
                errs.push(ConfigError::CrossRefMiss(
                    ErrorContext::new(format!(
                        "blocklists[{i}] \"{}\".auth_token_ref \"{ref_name}\" is not defined in \
                         secrets.toml; the list would be fetched anonymously",
                        b.id
                    ))
                    .with_entity(format!("blocklists.{}", b.id))
                    .with_suggestion(suggestion),
                ));
            }
        }
    }
    check_blocklist_duplicate_urls(config, warns);
    check_orphan_legacy_sources(config, warns);
}

/// `tag_model_consolidation` §3.2 — two or more **enabled** blocklists
/// resolving to the same canonical source URL.
///
/// **WARN, never fatal.** The live production config already contains a
/// duplicate pair (D3); making this an error would stop the daemon from
/// starting and take household DNS offline. `warden config lint` already
/// captures every `target = "audit"` WARN and exits `2`, which is the
/// channel that makes it impossible to ignore.
///
/// Disabled lists are skipped: a parked duplicate downloads nothing,
/// touches no cache file, and burns no bitmask slot, so warning about it
/// would be noise on a config the operator has already neutralised.
///
/// Groups are reported one line per collision with every colliding id
/// named, not one line per list — the operator needs to see the pair to
/// know which one to remove. Iteration order follows the config so the
/// ids in the message are stable across reloads.
fn check_blocklist_duplicate_urls(config: &ConfigV1, warns: &mut AuditWarnings) {
    for (key, ids) in duplicate_url_groups(config) {
        let msg = format_blocklist_duplicate_url(&ids, &key);
        if warns.emit() {
            tracing::warn!(target: "audit", blocklists = %ids.join(","), "{msg}");
        }
        warns.push(msg);
    }
}

/// Report every `[lists].sources` entry that cannot filter.
///
/// An entry there is fetched on schedule and counted as a live source,
/// but only a `[[blocklists]]` entry carries an id and a
/// [`BlocklistBase`], and only those let a profile reach a list — by
/// inheriting the base or by naming the id in `profiles.<id>.lists`. So
/// an entry with no corresponding `[[blocklists]]` row downloads forever
/// and filters nothing, while `warden status` reports it as working.
///
/// A **warning**, not an error. Configurations in the field already hold
/// entries like this — some of them the only thing keeping a resolver's
/// list of sources looking populated — and refusing to load would turn a
/// list that quietly filters nothing into a daemon that does not start
/// at all. The second failure is much worse than the first. Warning
/// surfaces it in `warden config lint` (which exits non-zero on
/// warnings) and in the log at every reload, without anyone losing DNS.
///
/// An empty `sources` array is silent, which matters: it is the shape
/// every correctly-migrated config has.
fn check_orphan_legacy_sources(config: &ConfigV1, warns: &mut AuditWarnings) {
    for source in orphan_legacy_sources(config) {
        let msg = format_legacy_source_not_enforced(&source);
        if warns.emit() {
            tracing::warn!(target: "audit", source = %source, "{msg}");
        }
        warns.push(msg);
    }
}

/// Pure half of [`check_orphan_legacy_sources`]: the `[lists].sources`
/// entries that no enabled `[[blocklists]]` row corresponds to.
///
/// A source and a list correspond when the list's id equals the source's
/// id form (`privacy/ads` and `privacy-ads` are one list) or their URLs
/// match once canonicalised.
///
/// # F24 — the clause that used to be here, and the harm it did
///
/// The filter read `b.enabled && !b.tags.is_empty()`, on the reasoning
/// that a list with no tags could not be reached either, so pointing the
/// operator at it would be a second dead end. That reasoning died at the
/// plp cutover: reachability is now
/// [`effective_direction`](super::blocklist::effective_direction) over
/// `base` + `profiles.<id>.lists`, and a list's `tags` decide nothing.
///
/// What the stale clause produced was not a stale message but a **false
/// one, with a destructive repair**. `auto_promote_blocklists` stamped
/// `tags = ["uncategorized"]` on a `base = deny` list and deliberately
/// **not** on a `base = allow` one (D2), so two configs one word apart
/// diverged here: the deny branch matched and stayed silent, and the
/// allow branch — a perfectly reachable list that every profile inherits
/// — was reported as reaching nobody, immediately above
/// [`ALLOW_DIRECTION_LIST_STANDING_EXPOSURE`] saying every profile
/// permits every domain it carries. Two warnings about one list that
/// cannot both be true, and the false one prints
/// `warden lists remove` / `warden lists add`: an operator who trusts the
/// tool loses the exemption they configured on purpose.
///
/// The question the check asks — *can anything reach this source?* — is
/// legitimate and kept. Only the answer was wrong. Pinned by
/// `f24_a_list_source_backed_by_an_allow_list_is_not_called_unreachable`
/// and its two neighbours, which compare the two branches rather than
/// asserting that some warning fired.
///
/// Still gated on `enabled`: a disabled row cannot be reached by any
/// profile, so a source pointing at one is as orphaned as a source
/// pointing at nothing.
///
/// Says nothing about a row every profile overrides to
/// [`ListPolicy::Ignore`] — see [`inert_blocklists`] for what does, and
/// the gap noted there for what still does not.
///
/// Split out from the reporting so the rule can be tested without
/// capturing a `tracing` subscriber, matching
/// [`duplicate_url_groups`] next door.
pub fn orphan_legacy_sources(config: &ConfigV1) -> Vec<String> {
    config
        .lists
        .sources
        .iter()
        .filter(|source| {
            let id_form = source.replace('/', "-");
            let key = crate::lists::source_key::canonical_url_key(source);
            !config.blocklists.iter().filter(|b| b.enabled).any(|b| {
                b.id.as_str() == id_form
                    || crate::lists::source_key::canonical_url_key(&b.url) == key
            })
        })
        .cloned()
        .collect()
}

/// Pure half of [`check_blocklist_duplicate_urls`]: every canonical-URL
/// collision among enabled blocklists, as `(canonical_key, ids)`.
///
/// Split out so the rule is testable without capturing a `tracing`
/// subscriber, and so any future surface (TUI badge, `warden status`)
/// reads the same list the WARN does instead of re-deriving it.
///
/// Only groups of 2+ are returned. Config order is preserved so the ids
/// in the operator-facing message are stable across reloads.
pub fn duplicate_url_groups(config: &ConfigV1) -> Vec<(String, Vec<&str>)> {
    let mut groups: Vec<(String, Vec<&str>)> = Vec::new();
    for b in config.blocklists.iter().filter(|b| b.enabled) {
        let key = crate::lists::source_key::canonical_url_key(&b.url);
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, ids)) => ids.push(b.id.as_str()),
            None => groups.push((key, vec![b.id.as_str()])),
        }
    }
    groups.retain(|(_, ids)| ids.len() > 1);
    groups
}

// ── [profiles.*] ───────────────────────────────────────────────

/// Ids are unique among custom lists, and disjoint from blocklist ids.
///
/// The cross-kind rule is deliberate and differs from `labels`, where the
/// same id under two kinds is legal. The two list kinds sit side by side in
/// the operator's interface and share the column that says which profiles
/// use them; two different things under one name, one leaf apart, is a
/// confusion the model should not be able to express.
fn check_custom_lists(config: &ConfigV1, errs: &mut Vec<ConfigError>) {
    if config.custom_list_limits.max_file_bytes == 0 {
        errs.push(ConfigError::ValidationFailed(
            ErrorContext::new(
                "[custom_list_limits] max_file_bytes must be greater than 0".to_string(),
            )
            .with_entity("custom_list_limits".to_string())
            .with_suggestion(
                "remove the key to take the default, or set a positive byte count".to_string(),
            ),
        ));
    }

    let blocklist_ids: HashSet<&Id> = config.blocklists.iter().map(|b| &b.id).collect();
    let mut seen: HashSet<&Id> = HashSet::new();
    for (i, cl) in config.custom_lists.iter().enumerate() {
        let entity = format!("custom_lists.{}", cl.id);
        if !seen.insert(&cl.id) {
            errs.push(ConfigError::DuplicateId(
                ErrorContext::new(format!(
                    "custom_lists[{i}]: id \"{}\" is already declared",
                    cl.id
                ))
                .with_entity(entity.clone())
                .with_suggestion("rename one of the two entries".to_string()),
            ));
        }
        if blocklist_ids.contains(&cl.id) {
            errs.push(ConfigError::DuplicateId(
                ErrorContext::new(format!(
                    "custom_lists[{i}]: id \"{}\" is already used by a blocklist",
                    cl.id
                ))
                .with_entity(entity)
                .with_suggestion(
                    "rename one of the two — the two list kinds share one id space so a \
                     profile mount is never ambiguous"
                        .to_string(),
                ),
            ));
        }
    }
}

fn check_profiles(
    config: &ConfigV1,
    blocklist_ids: &HashSet<Id>,
    admin_rule_ids: &HashSet<Id>,
    errs: &mut Vec<ConfigError>,
    warns: &mut AuditWarnings,
) {
    let custom_list_ids: HashSet<&Id> = config.custom_lists.iter().map(|c| &c.id).collect();

    for (key, profile) in &config.profiles {
        // Skip cross-ref checks if the profile key itself is invalid —
        // we already pushed an InvalidId error in `collect_profile_ids`.
        let entity = format!("profiles.{key}");
        // Emptiness NOT required: Profile.display_name carries
        // #[serde(default)], so an omitted field deserialises to "".
        check_display_text(
            &profile.display_name,
            &entity,
            "display_name",
            DISPLAY_NAME_MAX_BYTES,
            false,
            errs,
        );
        // `blocklist_ids` sat here behind a `let _ =` suppression from
        // Sprint A of `lists_categories_v2` onward, threaded in and unused,
        // with a comment reserving the seat for a later sprint's
        // list-applicability check. This is that check
        // (`profile_list_policy.md` §4 S2) — every list a profile names in
        // its `lists` override must actually exist.
        //
        // Iteration order is `BTreeMap`'s, so a profile naming several
        // unknown ids reports them sorted and reports ALL of them: the
        // operator fixes one pass instead of rerunning the loader per typo.
        for (list_ref, policy) in &profile.lists {
            if !blocklist_ids.contains(list_ref) {
                errs.push(ConfigError::CrossRefMiss(
                    ErrorContext::new(format_profile_list_policy_unknown_list(
                        key,
                        list_ref.as_str(),
                    ))
                    .with_entity(entity.clone())
                    .with_suggestion(PROFILE_LIST_POLICY_UNKNOWN_LIST_SUGGESTION.to_string()),
                ));
                continue;
            }
            // `plp-s4b` / §2.3 — the load-time half of the override consent
            // gate. The IPC handler refuses this at write time and names the
            // verb that repairs it; this is the backstop for the one route
            // that does not pass through a verb, a hand-edited TOML.
            //
            // Only `Allow` costs anything: `Deny` and `Ignore` narrow what the
            // profile permits, so they have nothing to declare. `clear`ing an
            // override is not represented here at all — an absent key inherits
            // the list's `base`, and `base = allow` on an unconsented remote
            // row is already refused by `check_blocklists`.
            if *policy != ListPolicy::Allow {
                continue;
            }
            // Unreachable: `blocklist_ids` is collected from
            // `config.blocklists`, and the `continue` above already handled
            // every id absent from it. Written as a `continue` rather than an
            // `expect` because a validator that panics on a malformed config
            // is worse than one that lets the next check report it — and
            // there is no fail-open hiding here, only a pair that cannot
            // exist.
            let Some(b) = config.blocklists.iter().find(|b| &b.id == list_ref) else {
                continue;
            };
            // Deliberately NOT gated on `b.enabled`. A disabled list holds no
            // source bit and produces no verdict today, but `warden blocklist
            // set <id> --enabled true` flips that back with nothing to re-run
            // the gate. Gate the declaration, not its current reachability.
            //
            // The predicate is `trust != Local` rather than the
            // `trust == RemoteUnsigned` that `allow_direction_gates` uses, to
            // match the sibling `UNSIGNED_ALLOW_LIST_REQUIRES_ACK` check
            // immediately below in `check_blocklists`: the two consent
            // refusals are one property and must read identically. The pair
            // differs only on `Signed`, which is refused outright elsewhere by
            // `TRUST_SIGNED_NOT_YET_SUPPORTED`, so `!= Local` is never the
            // laxer of the two.
            if b.trust != BlocklistTrust::Local && !b.accept_unsigned_allow {
                errs.push(ConfigError::UnsignedAllowListRequiresAck(
                    ErrorContext::new(format_profile_list_policy_unsigned_allow_requires_ack(
                        key,
                        list_ref.as_str(),
                        b.trust,
                    ))
                    .with_entity(entity.clone())
                    .with_suggestion(
                        PROFILE_LIST_POLICY_UNSIGNED_ALLOW_REQUIRES_ACK_SUGGESTION.to_string(),
                    ),
                ));
            }
        }
        for r_ref in &profile.admin_rules {
            if !admin_rule_ids.contains(r_ref) {
                errs.push(ConfigError::CrossRefMiss(
                    ErrorContext::new(format!(
                        "profile \"{key}\" references admin_rule \"{r_ref}\" which is not defined"
                    ))
                    .with_entity(entity.clone())
                    .with_suggestion(format!(
                        "add a [[admin_rules]] entry with id = \"{r_ref}\" or drop the reference"
                    )),
                ));
            }
        }
        for cl_ref in &profile.custom_lists {
            if !custom_list_ids.contains(cl_ref) {
                errs.push(ConfigError::CrossRefMiss(
                    ErrorContext::new(format!(
                        "profile \"{key}\" references custom_list \"{cl_ref}\" which is not defined"
                    ))
                    .with_entity(entity.clone())
                    .with_suggestion(format!(
                        "add a [[custom_lists]] entry with id = \"{cl_ref}\" or drop the reference"
                    )),
                ));
            }
        }
        if let Some(ttl) = profile.blocked_ttl_secs {
            if ttl == 0 {
                errs.push(ConfigError::ValidationFailed(
                    ErrorContext::new(format!(
                        "profile \"{key}\".blocked_ttl_secs must be greater than 0"
                    ))
                    .with_entity(entity.clone()),
                ));
            }
        }
        // S44 T1 (DM1) — per-profile local DNS records v2 validation. The
        // helper lives in the legacy validator module so the global path
        // ([`check_local_dns`]) and this per-profile path share a single
        // implementation (R7-style single-seat). It returns `Vec<String>`
        // (matching the legacy validator's aggregation shape); we wrap each
        // string in `ConfigError::ValidationFailed` here.
        if !profile.local_records.is_empty() {
            let mut local_errors: Vec<String> = Vec::new();
            crate::config::validator::validate_local_records_v2_collect(
                &profile.local_records,
                &format!("profiles.{key}.local_records"),
                &mut local_errors,
                warns,
            );
            for msg in local_errors {
                errs.push(ConfigError::ValidationFailed(
                    ErrorContext::new(msg).with_entity(entity.clone()),
                ));
            }
        }

        // §4.8 §2/2 T1 — per-profile ECS policy validation. Range checks
        // fire whenever a prefix override is SET, regardless of `mode`
        // (cfg-validator-05, rev-2606): with the mode inherited from
        // `[upstream.ecs]` rather than written on the profile, an
        // out-of-range prefix used to load clean and then
        // `EdnsClientSubnet::new(..).ok()` silently dropped ECS for the
        // profile at query time. A set-but-out-of-range value is a
        // misconfiguration in every mode (`coarse`/`off` ignore the
        // field, but it would arm itself the moment the mode changes).
        // Frozen recovery hints live in
        // [`ECS_PROFILE_PREFIX_V4_OUT_OF_RANGE`] /
        // [`ECS_PROFILE_PREFIX_V6_OUT_OF_RANGE`].
        if let Some(ecs) = &profile.ecs {
            if let Some(p) = ecs.source_prefix_v4 {
                if p > 32 {
                    errs.push(ConfigError::ValidationFailed(
                        ErrorContext::new(format_ecs_profile_prefix_v4_out_of_range(key, p))
                            .with_entity(entity.clone()),
                    ));
                }
            }
            if let Some(p) = ecs.source_prefix_v6 {
                if p > 128 {
                    errs.push(ConfigError::ValidationFailed(
                        ErrorContext::new(format_ecs_profile_prefix_v6_out_of_range(key, p))
                            .with_entity(entity.clone()),
                    ));
                }
            }
        }

        // §4.12 — per-profile rewrite_rules validation. Shadow warnings
        // (DR6) consult the same profile's local_records AND the global
        // [local_dns] table (rev-2606 cfg-validator-07) — both precede
        // rewrites at runtime, so both shadow.
        if !profile.rewrite_rules.is_empty() {
            let mut rewrite_errors: Vec<String> = Vec::new();
            let mut rewrite_warnings: Vec<String> = Vec::new();
            crate::config::validator::validate_rewrite_rules(
                &profile.rewrite_rules,
                &format!("profiles.{key}.rewrite_rules"),
                &profile.local_records,
                &config.local_dns.records,
                &mut rewrite_errors,
                &mut rewrite_warnings,
            );
            for msg in rewrite_errors {
                errs.push(ConfigError::ValidationFailed(
                    ErrorContext::new(msg).with_entity(entity.clone()),
                ));
            }
            for warning in rewrite_warnings {
                let msg = format!("profiles.{key}: {warning}");
                if warns.emit() {
                    tracing::warn!(target: "audit", "{msg}");
                }
                warns.push(msg);
            }
        }

        // neutrality-04 — the flag is inert. Emitted before the audit
        // below so an operator reading the log sees WHY the audit found
        // nothing, rather than concluding their SafeSearch is healthy.
        if profile.safe_search {
            let msg = format!("profiles.{key}: {SAFE_SEARCH_FLAG_SELECTS_NOTHING}");
            if warns.emit() {
                tracing::warn!(target: "audit", entity = %entity, "{msg}");
            }
            warns.push(msg);
        }

        // rev-2606 profile-02 — §4.53 SafeSearch effective-set audit.
        // Kept through neutrality-04 although `populate` no longer
        // injects anything: it is the one path that audits the EFFECTIVE
        // set via the same function the resolver serves from, so an
        // operator-supplied engine table would arrive already covered.
        // Today it can only report cycles and shadows the operator
        // authored themselves.
        if profile.safe_search {
            let mut safesearch_warnings: Vec<String> = Vec::new();
            crate::config::validator::audit_safesearch_effective_rewrites(
                &profile.rewrite_rules,
                &profile.local_records,
                &config.local_dns.records,
                &mut safesearch_warnings,
            );
            for warning in safesearch_warnings {
                let msg = format!("profiles.{key}: {warning}");
                if warns.emit() {
                    tracing::warn!(target: "audit", "{msg}");
                }
                warns.push(msg);
            }
        }
    }
}

// ── Sprint 43 T4: SN3 frozen string for soft-cap warning ──────

/// Sprint 43 T4 (SN3): operator-facing warning emitted when a device's
/// `allow_rules + deny_rules` count exceeds the **soft cap** of 64. T6
/// pins this string byte-for-byte via `tests/frozen_strings_s43.rs`.
/// Operators see it via `tracing::warn!(target: "audit")` at validator
/// pass time — boot, reload, and any IPC-driven rewrite all run the
/// validator, so the warning surfaces wherever the cap is exceeded.
pub const LIST_PRUNE_WARN: &str =
    "Device '{id}' has {n} rules (soft cap: 64). Run `warden device rules {id} prune` to clean up dead refs.";

/// Substitute `{id}` and `{n}` into [`LIST_PRUNE_WARN`]. Kept on the
/// public surface so T6's frozen-strings test can exercise both the
/// const AND the template-substitution helper without re-implementing
/// the latter.
pub fn format_list_prune_warn(device_id: &str, n: usize) -> String {
    LIST_PRUNE_WARN
        .replace("{id}", device_id)
        .replace("{n}", &n.to_string())
}

/// Sprint 43 T4 (DM6): hard cap above which the validator refuses the
/// config. Beyond 128 entries on a single device the operator has
/// drifted far past the soft cap; the resolver chain continues to work,
/// but the operator experience (TUI Rules tab, prune CLI) starts to
/// degrade and a future memory-pressure incident becomes plausible.
pub const DEVICE_RULES_HARD_CAP: usize = 128;

// ── §4.8 §2/2 (T1): per-profile ECS validator frozen strings ──

/// Sprint 48 §2/2 T1 — IPv4 source-prefix out-of-range under
/// `[profiles.<key>.ecs] mode = "subnet"`. Frozen byte-for-byte by
/// `tests/frozen_strings_s48_ecs_profile.rs`.
pub const ECS_PROFILE_PREFIX_V4_OUT_OF_RANGE: &str =
    "profiles.{key}.ecs.source_prefix_v4: {n} is out of range 0..=32 — typical 24 \
     for CDN-routing accuracy, 0 to opt out of address forwarding per RFC 7871 \
     §7.1.2; drop the field to inherit from [upstream.ecs] or set mode = \"off\" \
     to disable ECS for this profile";

/// Sprint 48 §2/2 T1 — IPv6 source-prefix out-of-range under
/// `[profiles.<key>.ecs] mode = "subnet"`. Frozen byte-for-byte by
/// `tests/frozen_strings_s48_ecs_profile.rs`.
pub const ECS_PROFILE_PREFIX_V6_OUT_OF_RANGE: &str =
    "profiles.{key}.ecs.source_prefix_v6: {n} is out of range 0..=128 — typical 56 \
     for CDN-routing accuracy, 0 to opt out of address forwarding per RFC 7871 \
     §7.1.2; drop the field to inherit from [upstream.ecs] or set mode = \"off\" \
     to disable ECS for this profile";

/// Substitute `{key}` (profile id) and `{n}` (offending value) into
/// [`ECS_PROFILE_PREFIX_V4_OUT_OF_RANGE`].
pub fn format_ecs_profile_prefix_v4_out_of_range(profile_key: &str, n: u8) -> String {
    ECS_PROFILE_PREFIX_V4_OUT_OF_RANGE
        .replace("{key}", profile_key)
        .replace("{n}", &n.to_string())
}

/// Substitute `{key}` (profile id) and `{n}` (offending value) into
/// [`ECS_PROFILE_PREFIX_V6_OUT_OF_RANGE`].
pub fn format_ecs_profile_prefix_v6_out_of_range(profile_key: &str, n: u8) -> String {
    ECS_PROFILE_PREFIX_V6_OUT_OF_RANGE
        .replace("{key}", profile_key)
        .replace("{n}", &n.to_string())
}

/// Sprint 43 T4 (DM6): soft cap. Beyond 64 the validator emits a
/// frozen [`LIST_PRUNE_WARN`] but accepts the config.
pub const DEVICE_RULES_SOFT_CAP: usize = 64;

// ── operator free-text bounds (rev-2606 schema-validator-11) ───

/// Byte cap for `display_name` on every entity.
const DISPLAY_NAME_MAX_BYTES: usize = 128;
/// Byte cap for device free-text metadata (`owner`, `device_type`,
/// `department`, `notes`).
const FREE_TEXT_MAX_BYTES: usize = 1024;

/// rev-2606 schema-validator-11 — shared bounds for operator free-text.
///
/// These strings flow verbatim into TUI rows and journal lines, so
/// control characters (newlines, tabs, ANSI escape sequences) are
/// refused as a terminal-injection surface, and multi-KB values (the
/// A6 pasted-content typo class) are capped. `require_nonempty` is
/// false for `Profile.display_name` (its `#[serde(default)]` makes an
/// omitted field indistinguishable from an empty one) and for fields
/// whose emptiness is checked elsewhere.
fn check_display_text(
    value: &str,
    entity: &str,
    field: &str,
    max_bytes: usize,
    require_nonempty: bool,
    errs: &mut Vec<ConfigError>,
) {
    if value.trim().is_empty() {
        if require_nonempty {
            errs.push(ConfigError::MissingRequired(
                ErrorContext::new(format!("{entity}.{field} must not be empty"))
                    .with_entity(entity.to_string()),
            ));
        }
        // No early return. `str::trim` cuts on the Unicode White_Space
        // property, and six of those code points are ALSO control
        // characters — TAB, LF, VT, FF, CR, NEL — so a value that trims to
        // empty can be made entirely of the bytes this check exists to keep
        // out of TUI rows and journal lines. Only the length check is
        // skipped: an all-whitespace value has nothing worth a second error.
    } else if value.len() > max_bytes {
        errs.push(ConfigError::ValidationFailed(
            ErrorContext::new(format!(
                "{entity}.{field} is {} bytes (max {max_bytes})",
                value.len()
            ))
            .with_entity(entity.to_string())
            .with_suggestion(format!("shorten {field} to <= {max_bytes} bytes")),
        ));
    }
    if let Some(c) = value.chars().find(|c| c.is_control()) {
        errs.push(ConfigError::ValidationFailed(
            ErrorContext::new(format!(
                "{entity}.{field} contains a control character ({c:?}) — newlines, tabs, and escape sequences are not allowed"
            ))
            .with_entity(entity.to_string())
            .with_suggestion(format!("remove control characters from {field}")),
        ));
    }
}

// ── [[devices]] ────────────────────────────────────────────────

fn check_devices(
    config: &ConfigV1,
    profile_ids: &HashSet<Id>,
    group_ids: &HashSet<Id>,
    admin_rule_ids: &HashSet<Id>,
    errs: &mut Vec<ConfigError>,
    warns: &mut AuditWarnings,
) {
    let mut seen_ip: HashMap<IpAddr, Id> = HashMap::new();
    let mut seen_mac: HashMap<String, Id> = HashMap::new();
    // Collision universe for network_name: every domain already claimed
    // by a static local_dns record (global + every profile scope).
    // Built once, outside the per-device loop — O(records), not
    // O(devices × records).
    let mut local_dns_domains: HashSet<String> = HashSet::new();
    for r in &config.local_dns.records {
        local_dns_domains.insert(r.domain.trim().trim_end_matches('.').to_ascii_lowercase());
    }
    for profile in config.profiles.values() {
        for r in &profile.local_records {
            local_dns_domains.insert(r.domain.trim().trim_end_matches('.').to_ascii_lowercase());
        }
    }
    let mut seen_network_name: HashMap<String, Id> = HashMap::new();
    for (i, d) in config.devices.iter().enumerate() {
        let entity = format!("devices.{}", d.id);
        check_display_text(
            &d.display_name,
            &entity,
            "display_name",
            DISPLAY_NAME_MAX_BYTES,
            true,
            errs,
        );
        for (field, value) in [
            ("owner", &d.owner),
            ("device_type", &d.device_type),
            ("department", &d.department),
            ("notes", &d.notes),
        ] {
            if let Some(v) = value {
                check_display_text(v, &entity, field, FREE_TEXT_MAX_BYTES, false, errs);
            }
        }
        if d.ip.is_none() && d.mac.is_none() && d.mac_aliases.is_empty() {
            errs.push(ConfigError::ValidationFailed(
                ErrorContext::new(format!(
                    "devices[{i}] \"{}\" has no identity field (ip / mac / mac_aliases all unset)",
                    d.id
                ))
                .with_entity(entity.clone())
                .with_suggestion(
                    "set at least one of ip, mac, or mac_aliases so the resolver can match queries to this device".to_string(),
                ),
            ));
        }
        if let Some(ip) = d.ip {
            // Keyed on the canonical form: two devices spelling the same host
            // as `10.0.0.5` and `::ffff:10.0.0.5` are a duplicate pin, and a
            // raw `IpAddr` key makes them two distinct entries that both
            // validate. Both spellings are named when they differ — the
            // operator greps their config for the address the message shows.
            let canon = canonical_ip(ip);
            if let Some(other) = seen_ip.insert(canon, d.id.clone()) {
                let shown = if canon == ip {
                    format!("{ip}")
                } else {
                    format!("{ip} ({canon})")
                };
                errs.push(ConfigError::ValidationFailed(
                    ErrorContext::new(format!(
                        "devices[{i}] \"{}\" reuses IP {shown} already pinned to device \"{other}\"",
                        d.id
                    ))
                    .with_entity(entity.clone()),
                ));
            }
        }
        let mut this_macs: Vec<String> = Vec::new();
        if let Some(mac) = &d.mac {
            match normalise_mac(mac) {
                Some(n) => this_macs.push(n),
                None => errs.push(ConfigError::ValidationFailed(
                    ErrorContext::new(format!(
                        "devices[{i}].mac \"{mac}\" is not a valid MAC (expected XX:XX:XX:XX:XX:XX)"
                    ))
                    .with_entity(entity.clone()),
                )),
            }
        }
        for (j, alias) in d.mac_aliases.iter().enumerate() {
            match normalise_mac(alias) {
                Some(n) => {
                    if this_macs.contains(&n) {
                        errs.push(ConfigError::ValidationFailed(
                            ErrorContext::new(format!(
                                "devices[{i}].mac_aliases[{j}] \"{alias}\" duplicates this device's own MAC"
                            ))
                            .with_entity(entity.clone()),
                        ));
                    } else {
                        this_macs.push(n);
                    }
                }
                None => errs.push(ConfigError::ValidationFailed(
                    ErrorContext::new(format!(
                        "devices[{i}].mac_aliases[{j}] \"{alias}\" is not a valid MAC"
                    ))
                    .with_entity(entity.clone()),
                )),
            }
        }
        for mac in &this_macs {
            if let Some(other) = seen_mac.insert(mac.clone(), d.id.clone()) {
                errs.push(ConfigError::ValidationFailed(
                    ErrorContext::new(format!(
                        "devices[{i}] \"{}\" claims MAC {mac} already owned by device \"{other}\"",
                        d.id
                    ))
                    .with_entity(entity.clone()),
                ));
            }
        }
        if let Some(profile) = &d.profile {
            if !profile_ids.contains(profile) {
                errs.push(ConfigError::CrossRefMiss(
                    ErrorContext::new(format!(
                        "devices[{i}] \"{}\".profile \"{profile}\" is not defined",
                        d.id
                    ))
                    .with_entity(entity.clone())
                    .with_suggestion(format!(
                        "add a [profiles.{profile}] block, remove the profile field, or rely on a group / subnet"
                    )),
                ));
            }
        }
        for g_ref in &d.groups {
            if !group_ids.contains(g_ref) {
                errs.push(ConfigError::CrossRefMiss(
                    ErrorContext::new(format!(
                        "devices[{i}] \"{}\".groups references \"{g_ref}\" which is not defined",
                        d.id
                    ))
                    .with_entity(entity.clone()),
                ));
            }
        }
        // Sprint 43 T4 (DM1, DM6): per-device overlay cross-refs + caps.
        // The dangling-id pass reuses the already-built `admin_rule_ids`
        // set — Rust lens optimisation per §8: profile + device + group
        // checks all share one HashSet probe, no rebuild per call site.
        for r_ref in &d.allow_rules {
            if !admin_rule_ids.contains(r_ref) {
                errs.push(ConfigError::CrossRefMiss(
                    ErrorContext::new(format!(
                        "devices[{i}] \"{}\".allow_rules references admin_rule \"{r_ref}\" which is not defined",
                        d.id
                    ))
                    .with_entity(entity.clone())
                    .with_suggestion(format!(
                        "add a [[admin_rules]] entry with id = \"{r_ref}\" or remove the reference"
                    )),
                ));
            }
        }
        for r_ref in &d.deny_rules {
            if !admin_rule_ids.contains(r_ref) {
                errs.push(ConfigError::CrossRefMiss(
                    ErrorContext::new(format!(
                        "devices[{i}] \"{}\".deny_rules references admin_rule \"{r_ref}\" which is not defined",
                        d.id
                    ))
                    .with_entity(entity.clone())
                    .with_suggestion(format!(
                        "add a [[admin_rules]] entry with id = \"{r_ref}\" or remove the reference"
                    )),
                ));
            }
        }
        let total_rules = d.allow_rules.len() + d.deny_rules.len();
        if total_rules > DEVICE_RULES_HARD_CAP {
            errs.push(ConfigError::ValidationFailed(
                ErrorContext::new(format!(
                    "devices[{i}] \"{}\" has {total_rules} rules (allow_rules + deny_rules), \
                     exceeding the hard cap of {DEVICE_RULES_HARD_CAP}. Trim entries before reload.",
                    d.id
                ))
                .with_entity(entity.clone())
                .with_suggestion(format!(
                    "remove unused entries from devices.{}.allow_rules / deny_rules, or run `warden device rules {} prune` to drop dangling references",
                    d.id, d.id
                )),
            ));
        } else if total_rules > DEVICE_RULES_SOFT_CAP {
            // Soft cap: do NOT block. Emit the frozen LIST_PRUNE_WARN
            // string on the `audit` tracing target. No `errs.push`, so the
            // daemon proceeds. audit-02: this reaches journald on hot-reload
            // and is captured by `warden config lint`, but is NOT written to
            // the persistent audit.log — no audit-target layer routes to
            // AuditWriter, and at boot it is dropped entirely (validate()
            // runs before init_tracing, per B3b).
            let msg = format_list_prune_warn(d.id.as_str(), total_rules);
            if warns.emit() {
                tracing::warn!(target: "audit", "{msg}");
            }
            warns.push(msg);
        }

        // WITHDRAWN at the plp cutover (was: `unfiltered = true` is
        // mutually exclusive with non-empty `tags`, D3 + D14, ERROR).
        //
        // The rule priced a real contradiction: `unfiltered` short-
        // circuits the resolver, so an inherited tag would have been
        // dead weight the operator believed was filtering. Tags stopped
        // reaching the resolver at S3, so the pairing is no longer a
        // contradiction — it is one live field and one inert one, and
        // refusing to load a config over it takes a resolver down to
        // correct a field that changes nothing.
        //
        // `format_device_unfiltered_with_tags` is deliberately left
        // standing: `tests/frozen_strings_lc2_engine.rs` still imports the
        // const, and `cli/commands/devices.rs:1019` still bails on the same
        // pairing. That leaves the CLI refusing what the validator now
        // accepts — the same CLI-refuses / validator-accepts asymmetry
        // project rules documents for the allow-list tag gate. Named for lane
        // 5c, which owns `devices.rs`; not repaired here, because a lane
        // silently loosening a refusal in a file it does not own is how the
        // two layers stopped agreeing in the first place.

        // network_name: FQDN-label syntax (reuses the same rule as
        // local_dns domains) + wildcard-without-name mutex + collision
        // detection against every other device and against the
        // local_dns domains collected above the loop. All of it lives
        // here rather than in a second pass: the checks share `name`,
        // and a name that is malformed is still worth reporting as a
        // collision, so splitting them would only cost the operator a
        // second edit cycle.
        if let Some(name) = &d.network_name {
            if !crate::config::validator::is_valid_fqdn_syntax(name) {
                errs.push(ConfigError::ValidationFailed(
                    ErrorContext::new(format_network_name_invalid_fqdn(d.id.as_str(), name))
                        .with_entity(entity.clone())
                        .with_suggestion(
                            "use only letters, digits, and hyphens; no leading/trailing hyphen"
                                .to_string(),
                        ),
                ));
            }
            // Collisions are checked unconditionally once `name` is Some
            // — a name can be both malformed AND colliding, and the
            // operator needs both errors in one pass, not one per edit.
            let key = name.trim().trim_end_matches('.').to_ascii_lowercase();
            if let Some(other) = seen_network_name.insert(key.clone(), d.id.clone()) {
                errs.push(ConfigError::ValidationFailed(
                    ErrorContext::new(format!(
                        "devices[{i}] \"{}\".network_name \"{name}\" is already used by device \"{other}\"",
                        d.id
                    ))
                    .with_entity(entity.clone()),
                ));
            }
            if local_dns_domains.contains(&key) {
                errs.push(ConfigError::ValidationFailed(
                    ErrorContext::new(format!(
                        "devices[{i}] \"{}\".network_name \"{name}\" is already used by a local_dns record",
                        d.id
                    ))
                    .with_entity(entity.clone())
                    .with_suggestion(
                        "rename the device's network_name, or remove the conflicting local_dns record"
                            .to_string(),
                    ),
                ));
            }
        } else if d.network_name_wildcard {
            errs.push(ConfigError::ValidationFailed(
                ErrorContext::new(format_network_name_wildcard_without_name(d.id.as_str()))
                    .with_entity(entity.clone())
                    .with_suggestion(
                        "set network_name, or clear network_name_wildcard".to_string(),
                    ),
            ));
        }

        // `plp-s3`: the "this device is silently unfiltered" WARN moved to
        // the PROFILE. A device no longer carries policy — it inherits its
        // profile's, so the question "is anything filtering here?" has
        // exactly one place to be asked, and asking it per device would
        // repeat one profile's answer once per member. See
        // `check_profile_list_coverage`.
    }
}

// ── [[groups]] ─────────────────────────────────────────────────

fn check_groups(
    config: &ConfigV1,
    profile_ids: &HashSet<Id>,
    device_ids: &HashSet<Id>,
    errs: &mut Vec<ConfigError>,
) {
    for (i, g) in config.groups.iter().enumerate() {
        let entity = format!("groups.{}", g.id);
        check_display_text(
            &g.display_name,
            &entity,
            "display_name",
            DISPLAY_NAME_MAX_BYTES,
            true,
            errs,
        );
        if !profile_ids.contains(&g.profile) {
            errs.push(ConfigError::CrossRefMiss(
                ErrorContext::new(format!(
                    "groups[{i}] \"{}\".profile \"{}\" is not defined",
                    g.id, g.profile
                ))
                .with_entity(entity.clone()),
            ));
        }
        for d_ref in &g.devices {
            if !device_ids.contains(d_ref) {
                errs.push(ConfigError::CrossRefMiss(
                    ErrorContext::new(format!(
                        "groups[{i}] \"{}\".devices references \"{d_ref}\" which is not defined",
                        g.id
                    ))
                    .with_entity(entity.clone()),
                ));
            }
        }
    }
}

// ── [[labels]] ─────────────────────────────────────────────────

/// §4.66 L1 — the rules over `[[labels]]`, plus the WARN the vocabulary
/// raises against `[[devices]]`.
///
/// - **R1** `(kind, id)` is unique. The same `id` under two different
///   kinds is legal — `personal` may be both a department and a
///   device-type.
/// - **R3** a device metadata value outside its vocabulary is a **WARN**,
///   never an error.
///
/// **R4 is gone with its kind.** It said a `kind = "tag"` id had to
/// additionally satisfy `check_tag_kind_id` — an ERROR, because the
/// alternative was a declared name no entity could ever attach. `plp-s5a`
/// removed `LabelKind::Tag`, so there is no fourth kind and no fourth
/// rule.
///
/// The three surviving kinds are treated identically, including by the
/// device-metadata WARN: every one of them now has a
/// [`device_field`](LabelKind::device_field) to check against, which was
/// exactly what `tag` did not. Uniqueness on the pair, display text and
/// description bounds are per-entry and kind-blind, as before.
fn check_labels(config: &ConfigV1, errs: &mut Vec<ConfigError>, warns: &mut AuditWarnings) {
    // R1 — uniqueness on the PAIR. `collect_unique_ids` cannot be reused
    // here: it keys on `Id` alone and would reject the legal
    // cross-kind homonym.
    let mut seen: HashSet<(LabelKind, &Id)> = HashSet::new();
    for (i, l) in config.labels.iter().enumerate() {
        let entity = format!("labels.{}.{}", l.kind, l.id);
        if !seen.insert((l.kind, &l.id)) {
            errs.push(ConfigError::DuplicateId(
                ErrorContext::new(format!(
                    "labels[{i}]: kind \"{}\" already declares id \"{}\"",
                    l.kind, l.id
                ))
                .with_entity(entity.clone())
                .with_suggestion(
                    "rename one of the two entries — the same id under a different kind is \
                     legal, the same id under the same kind is not"
                        .to_string(),
                ),
            ));
        }

        check_display_text(
            &l.display_name,
            &entity,
            "display_name",
            DISPLAY_NAME_MAX_BYTES,
            true,
            errs,
        );
        if let Some(desc) = &l.description {
            // Same bound the device free-text metadata gets: a label
            // description is prose of exactly that class.
            check_display_text(
                desc,
                &entity,
                "description",
                FREE_TEXT_MAX_BYTES,
                false,
                errs,
            );
        }
    }

    check_device_metadata_vocabulary(config, warns);
}

/// R3 — WARN for a device metadata value no label declares.
///
/// **Silent when the vocabulary for that kind is empty**, and that guard
/// is the difference between a useful check and an unreadable one. Every
/// config on disk today has zero `[[labels]]`; the two CTs between them
/// carry 26 metadata assignments. Without the guard, shipping this
/// feature would print 26 WARNs at every load on boxes that have not
/// opted into curating anything — and a diagnostic that is red on every
/// healthy config stops being read, which costs more than it ever
/// catches. An empty vocabulary means "not curating this dimension", not
/// "nothing is legal".
///
/// Nothing is rewritten. The WARN names the value and the command that
/// would adopt it; the operator decides whether the value is a member of
/// the vocabulary or a typo.
///
/// **§4.66 L5 guard 3 — `tag` has no counterpart here, deliberately.**
/// The `let Some(field)` below drops it, because a tag is not a device
/// field; and a "tag used but not declared" WARN must not exist.
///
/// **The conclusion stands; its original evidence does not, and the
/// swap is recorded rather than quietly re-argued.** This used to read
/// "`auto_promote_blocklists` synthesises `uncategorized` onto every
/// untagged deny-list at **every** load ... so the symmetric WARN would
/// fire once per promoted list per load — measured at 23 across the two
/// live boxes, 2026-08-06". That function no longer exists anywhere in
/// `src/`: `plp-s5a` removed the `tags` field and the promotion pass with
/// it, so the count of 23 is a measurement of a build that is gone.
///
/// What replaces it is stronger, not weaker: there is no tag vocabulary
/// left to be used-but-not-declared. `Device` has no `tags` field, the
/// loader strips the key, and `effective_direction` over `base` +
/// `profiles.<id>.lists` is what decides reachability. A WARN about tag
/// declarations would now be red on **every** config rather than merely
/// on healthy ones — the same arithmetic as the empty-vocabulary guard
/// above, reached by a shorter route, and the same conclusion: a
/// diagnostic that is red on every healthy config stops being read.
fn check_device_metadata_vocabulary(config: &ConfigV1, warns: &mut AuditWarnings) {
    for kind in LabelKind::ALL {
        let field = kind.device_field();
        let vocabulary: Vec<&Label> = config.labels.iter().filter(|l| l.kind == kind).collect();
        if vocabulary.is_empty() {
            continue;
        }
        for d in &config.devices {
            let value = match kind {
                LabelKind::Owner => d.owner.as_deref(),
                LabelKind::DeviceType => d.device_type.as_deref(),
                LabelKind::Department => d.department.as_deref(),
            };
            let Some(value) = value.filter(|v| !v.trim().is_empty()) else {
                continue;
            };
            if vocabulary.iter().any(|l| l.matches_value(value)) {
                continue;
            }
            let msg =
                format_device_metadata_unknown_label(d.id.as_str(), field, value, kind.as_str());
            if warns.emit() {
                tracing::warn!(target: "audit", device = %d.id.as_str(), field = %field, "{msg}");
            }
            warns.push(msg);
        }
    }
}

// ── [[subnets]] ────────────────────────────────────────────────

fn check_subnets(config: &ConfigV1, profile_ids: &HashSet<Id>, errs: &mut Vec<ConfigError>) {
    // rev-2606 schema-validator-08: every (normalized CIDR, priority,
    // subnet, profile, original spelling) seen across ALL subnets, for
    // the duplicate-ambiguity check below.
    let mut seen_cidrs: Vec<(Cidr, i32, &Id, &Id, &str)> = Vec::new();
    for (i, s) in config.subnets.iter().enumerate() {
        let entity = format!("subnets.{}", s.id);
        check_display_text(
            &s.display_name,
            &entity,
            "display_name",
            DISPLAY_NAME_MAX_BYTES,
            true,
            errs,
        );
        if s.cidrs.is_empty() {
            errs.push(ConfigError::MissingRequired(
                ErrorContext::new(format!("subnets[{i}] \"{}\".cidrs must not be empty", s.id))
                    .with_entity(entity.clone()),
            ));
        }
        for (j, c) in s.cidrs.iter().enumerate() {
            match Cidr::parse(c) {
                Err(e) => {
                    errs.push(ConfigError::ValidationFailed(
                        ErrorContext::new(format!(
                            "subnets[{i}] \"{}\".cidrs[{j}] \"{c}\" is not a valid CIDR: {e}",
                            s.id
                        ))
                        .with_entity(entity.clone()),
                    ));
                }
                Ok(parsed) => {
                    seen_cidrs.push((parsed, s.priority, &s.id, &s.profile, c));
                }
            }
        }
        if !profile_ids.contains(&s.profile) {
            errs.push(ConfigError::CrossRefMiss(
                ErrorContext::new(format!(
                    "subnets[{i}] \"{}\".profile \"{}\" is not defined",
                    s.id, s.profile
                ))
                .with_entity(entity.clone()),
            ));
        }
    }
    // rev-2606 schema-validator-08: byte-identical CIDR in ≥2 subnets at
    // EQUAL priority with DIFFERENT profiles is the subnet analogue of
    // the DM2 group ambiguity — the resolver tie-break (priority DESC,
    // then id ASC) would pick a deterministic-but-arbitrary winner with
    // no diagnostic. Distinct priorities (deliberate overlay) and same
    // profile (harmless redundancy) stay clean. O(n²) over the CIDR
    // count is fine at the ≤~50-subnet design target.
    let mut reported: Vec<(Cidr, i32)> = Vec::new();
    for (idx, &(cidr, prio, _, _, spelling)) in seen_cidrs.iter().enumerate() {
        if reported.contains(&(cidr, prio)) {
            continue;
        }
        let cluster: Vec<_> = seen_cidrs[idx..]
            .iter()
            .filter(|(c2, p2, _, _, _)| *c2 == cidr && *p2 == prio)
            .collect();
        let distinct_profiles: HashSet<&Id> =
            cluster.iter().map(|(_, _, _, prof, _)| *prof).collect();
        if distinct_profiles.len() > 1 {
            reported.push((cidr, prio));
            let subnet_list = cluster
                .iter()
                .map(|(_, _, sid, prof, _)| format!("{sid} → {prof}"))
                .collect::<Vec<_>>()
                .join(", ");
            let first_subnet = cluster[0].2;
            errs.push(ConfigError::ValidationFailed(
                ErrorContext::new(format!(
                    "cidr \"{spelling}\" is declared by multiple subnets at the same priority ({prio}) but different profiles: {subnet_list}"
                ))
                .with_entity(format!("subnets.{first_subnet}"))
                .with_suggestion(
                    "raise the priority of the winning subnet, remove the duplicate CIDR, or harmonise the profiles".to_string(),
                ),
            ));
        }
    }
}

// ── [[schedules]] ──────────────────────────────────────────────

fn check_schedules(
    config: &ConfigV1,
    profile_ids: &HashSet<Id>,
    device_ids: &HashSet<Id>,
    group_ids: &HashSet<Id>,
    now: OffsetDateTime,
    errs: &mut Vec<ConfigError>,
    warns: &mut AuditWarnings,
) {
    for (i, s) in config.schedules.iter().enumerate() {
        let entity = format!("schedules.{}", s.id);
        check_display_text(
            &s.display_name,
            &entity,
            "display_name",
            DISPLAY_NAME_MAX_BYTES,
            true,
            errs,
        );
        if !profile_ids.contains(&s.profile) {
            errs.push(ConfigError::CrossRefMiss(
                ErrorContext::new(format!(
                    "schedules[{i}] \"{}\".profile \"{}\" is not defined",
                    s.id, s.profile
                ))
                .with_entity(entity.clone()),
            ));
        }
        let target_universe = match s.target_type {
            ScheduleTargetType::Device => device_ids,
            ScheduleTargetType::Group => group_ids,
        };
        if !target_universe.contains(&s.target_id) {
            errs.push(ConfigError::CrossRefMiss(
                ErrorContext::new(format!(
                    "schedules[{i}] \"{}\".target_id \"{}\" is not a defined {:?}",
                    s.id, s.target_id, s.target_type
                ))
                .with_entity(entity.clone())
                .with_suggestion(
                    "adjust target_type, or add the missing entity definition".to_string(),
                ),
            ));
        }
        if parse_days(&s.days).is_none() {
            errs.push(ConfigError::ValidationFailed(
                ErrorContext::new(format!(
                    "schedules[{i}] \"{}\".days {:?}: expected a list of mon/tue/wed/thu/fri/sat/sun/weekdays/weekends/all",
                    s.id, s.days
                ))
                .with_entity(entity.clone()),
            ));
        }
        match parse_hours(&s.hours) {
            None => errs.push(ConfigError::ValidationFailed(
                ErrorContext::new(format!(
                    "schedules[{i}] \"{}\".hours \"{}\": expected HH:MM-HH:MM (24h)",
                    s.id, s.hours
                ))
                .with_entity(entity.clone()),
            )),
            Some((sh, sm, eh, em)) => {
                // Zero-length window guard, mirroring the res-13 carve-out
                // in `ParsedSchedule::parse`/`parse_v1`: `00:00-00:00` is
                // the canonical always-on form (midnight wrap covers the
                // whole day; the previously suggested `00:00-23:59` is
                // end-exclusive and leaves minute 23:59 unmatched —
                // rev-2606 devices-01). Any other equal pair is almost
                // certainly an operator typo and stays an error.
                if sh == eh && sm == em && !(sh == 0 && sm == 0) {
                    errs.push(ConfigError::ValidationFailed(
                        ErrorContext::new(format!(
                            "schedules[{i}] \"{}\".hours \"{}\": start and end are equal (use 00:00-00:00 for all day)",
                            s.id, s.hours
                        ))
                        .with_entity(entity.clone()),
                    ));
                }
            }
        }
        if let Some(exp) = s.expires_at {
            if exp <= now {
                // WARN, not error: expired schedules are inert at resolver
                // build (`ParsedSchedule::is_active` checks expiry first),
                // so the row is harmless on-disk residue. A hard error here
                // would refuse boot/reload/and every CLI mutation the moment
                // a one-shot schedule (e.g. `warden device quiet`) passes
                // its expiry — rev-2606 schema-validator-01. No `errs.push`
                // so load proceeds; the audit target captures the
                // diagnostic for the operator.
                let msg = format!(
                    "schedules[{i}] \"{}\".expires_at {exp} is in the past — schedule is inactive and will be pruned automatically; run `warden schedule remove {}` to drop it now",
                    s.id,
                    s.id
                );
                if warns.emit() {
                    tracing::warn!(target: "audit", schedule = %s.id.as_str(), "{msg}");
                }
                warns.push(msg);
            }
        }
    }
}

// ── [[admin_rules]] ────────────────────────────────────────────

fn check_admin_rules(config: &ConfigV1, errs: &mut Vec<ConfigError>) {
    for (i, r) in config.admin_rules.iter().enumerate() {
        if r.rule.trim().is_empty() {
            errs.push(ConfigError::MissingRequired(
                ErrorContext::new(format!(
                    "admin_rules[{i}] \"{}\".rule must not be empty",
                    r.id
                ))
                .with_entity(format!("admin_rules.{}", r.id)),
            ));
            continue;
        }
        // rev-2606 schema-validator-05: dry-run the engine's own parser so
        // a rule the resolver build would silently drop (broken regex,
        // unknown modifier, malformed domain, …) is a lint/load error, not
        // a filtering gap the operator discovers from traffic.
        if let Err(e) = parse_rule_checked(&r.rule) {
            errs.push(ConfigError::ValidationFailed(
                ErrorContext::new(format!(
                    "admin_rules[{i}] \"{}\".rule \"{}\": {e}",
                    r.id, r.rule
                ))
                .with_entity(format!("admin_rules.{}", r.id))
                .with_suggestion(e.suggestion().to_string()),
            ));
        }
    }
}

// ── [resource_budget] ──────────────────────────────────────────

/// §4.13 — scalar invariants for the resource-budget sampler:
/// `tick_secs >= 1` and `rss_warn_mb >= 1`. A zero tick would spin the
/// async loop without yielding; a zero warn threshold would render
/// every sample red.
fn check_resource_budget(config: &ConfigV1, errs: &mut Vec<ConfigError>) {
    if config.resource_budget.tick_secs == 0 {
        errs.push(ConfigError::ValidationFailed(
            ErrorContext::new("resource_budget.tick_secs must be >= 1".to_string())
                .with_entity("resource_budget.tick_secs")
                .with_suggestion("set resource_budget.tick_secs = 5 for the default cadence"),
        ));
    }
    if config.resource_budget.rss_warn_mb == 0 {
        errs.push(ConfigError::ValidationFailed(
            ErrorContext::new("resource_budget.rss_warn_mb must be >= 1".to_string())
                .with_entity("resource_budget.rss_warn_mb")
                .with_suggestion(
                    "leave the field unset to inherit the meminfo-derived default (50% MemTotal)",
                ),
        ));
    }
}

// ── group-priority conflict (DM2) ──────────────────────────────

/// Detect the case where a device belongs to multiple groups that all
/// share the highest priority but resolve to different profiles. That
/// is the ambiguity DM2 forbids — the resolver would have no principled
/// way to pick one.
///
/// Membership is the union of BOTH join directions — group-side
/// `[[groups]].devices` and device-side `[[devices]].groups` — because
/// the resolver unions both (`profiles/resolver.rs::build_resolver_map`)
/// and the CLI/TUI join path writes the device side. rev-2606
/// schema-validator-04: this check used to see only the group side, so
/// a conflict joined via `d.groups` linted clean and the resolver
/// tie-broke by id silently.
fn check_group_priority_conflicts(config: &ConfigV1, errs: &mut Vec<ConfigError>) {
    let groups_by_id: BTreeMap<&Id, &super::group::Group> =
        config.groups.iter().map(|g| (&g.id, g)).collect();
    // For each device, collect (priority, profile, group-id) triples of
    // groups it belongs to, deduped by group id so a symmetric listing
    // (device in `g.devices` AND group in `d.groups`) counts once.
    let mut per_device: BTreeMap<&Id, Vec<(i32, &Id, &Id)>> = BTreeMap::new();
    let mut seen: HashSet<(&Id, &Id)> = HashSet::new();
    for g in &config.groups {
        for d in &g.devices {
            if seen.insert((d, &g.id)) {
                per_device
                    .entry(d)
                    .or_default()
                    .push((g.priority, &g.profile, &g.id));
            }
        }
    }
    for d in &config.devices {
        for gid in &d.groups {
            // Dangling gids are a CrossRefMiss from check_devices; skip.
            let Some(g) = groups_by_id.get(gid) else {
                continue;
            };
            if seen.insert((&d.id, &g.id)) {
                per_device
                    .entry(&d.id)
                    .or_default()
                    .push((g.priority, &g.profile, &g.id));
            }
        }
    }
    for (device, memberships) in per_device {
        // Find the max priority.
        let Some(&(max_prio, _, _)) = memberships.iter().max_by_key(|(p, _, _)| *p) else {
            continue;
        };
        let top: Vec<_> = memberships
            .iter()
            .filter(|(p, _, _)| *p == max_prio)
            .collect();
        // Distinct profile count among the top-priority memberships.
        let distinct: HashSet<&Id> = top.iter().map(|(_, pr, _)| *pr).collect();
        if distinct.len() > 1 {
            let group_list = top
                .iter()
                .map(|(_, p, g)| format!("{g} → {p}"))
                .collect::<Vec<_>>()
                .join(", ");
            errs.push(ConfigError::ValidationFailed(
                ErrorContext::new(format!(
                    "device \"{device}\" is in multiple groups with the same priority ({max_prio}) but different profiles: {group_list}"
                ))
                .with_entity(format!("devices.{device}"))
                .with_suggestion(
                    "raise the priority of the winning group, remove the device from one group, or harmonise the profiles".to_string(),
                ),
            ));
        }
    }
}

// ── Sprint 49 T2: categories + kind/trust compatibility ────────

/// W2.1: operator-facing message emitted when a blocklist declares
/// `base = allow` on a source that is not `trust = local` **and** has
/// not declared `accept_unsigned_allow = true`.
///
/// **What replaced what.** This supersedes the retired
/// `ALLOW_LIST_REQUIRES_LOCAL_TRUST`, which refused the combination
/// categorically. That rule cost an operator who wanted to guarantee a
/// service a manual download and re-import as a local file — a copy
/// that then never updated — and the message stated a requirement
/// (`trust=local`) that this validator no longer enforces. It was
/// deleted rather than reworded: a confidently-phrased sentence
/// describing a rule that no longer exists is worse than none.
///
/// The message leads with the *consequence*, not the rule. An operator
/// who is refused needs to know what they would have been exposed to,
/// and which single field changes the answer — the previous wording
/// gave them a prohibition and left them to find the workaround.
///
/// `{id}` is the blocklist id, `{got}` is the observed [`BlocklistTrust`]
/// (`signed`, `remote-unsigned` — kebab-case to match the on-wire form).
/// `{got}` is not decorative: `base = allow` + `trust = signed` reaches
/// this message through the co-occurrence path, so the placeholder does
/// render values other than `remote-unsigned`.
///
/// Pinned byte-for-byte in `tests/frozen_strings_unsigned_allow.rs`; the
/// inline `tests` module below mirrors the pin so a rewording surfaces
/// earlier.
pub const UNSIGNED_ALLOW_LIST_REQUIRES_ACK: &str =
    "Blocklist '{id}' has kind=allow but trust='{got}'. A remote allow-list can unblock any domain it lists, and its content can change at every refresh with no review. Set accept_unsigned_allow = true on the list to accept that risk, or use `warden blocklist import-local` to import a local file.";

/// Substitute `{id}` and `{got}` into [`UNSIGNED_ALLOW_LIST_REQUIRES_ACK`].
/// Kept on the public surface so the frozen-strings test can exercise
/// both the constant and the substitution without re-implementing the
/// latter.
pub fn format_unsigned_allow_list_requires_ack(blocklist_id: &str, got: BlocklistTrust) -> String {
    UNSIGNED_ALLOW_LIST_REQUIRES_ACK
        .replace("{id}", blocklist_id)
        .replace("{got}", trust_kebab(got))
}

/// W2.1: operator-facing WARN emitted at **every** load for a blocklist
/// that carries `base = allow`, a remote-unsigned source, and the
/// operator's declared `accept_unsigned_allow = true`.
///
/// **Why it fires every time.** The consent is recorded once, in the
/// TOML, and then quietly keeps applying at every refresh — the exact
/// shape of risk that gets accepted on a Tuesday and forgotten by
/// Friday. Emitting the WARN on each load (and through
/// `warden config lint`, which exits non-zero on audit WARNs) keeps the
/// standing exposure visible instead of letting a one-time decision go
/// silent. It is not a nag about a mistake: the operator did nothing
/// wrong, and there is no config change that both keeps the list and
/// silences this.
///
/// Deliberately **not** emitted for `trust = local` (the operator
/// authored the file — no third party, nothing to warn about) nor for
/// `trust = signed` (the text would claim a signed list is unsigned,
/// which is false; that combination is refused elsewhere anyway).
///
/// `{id}` is the blocklist id. WARN style in this file is
/// lowercase-initial with `"{id}"` in double quotes, matching
/// [`ALLOW_DIRECTION_LIST_STANDING_EXPOSURE`] — its neighbour on the same
/// allow-direction branch, and the style exemplar since
/// `ALLOW_LIST_NO_TAGS_NO_EFFECT` (the one this used to name) was retired
/// in `plp-s5f`.
pub const UNSIGNED_ALLOW_LIST_ACCEPTED: &str =
    "allow-list \"{id}\" is remote and unsigned — whoever controls its URL can unblock any domain by adding it, at every refresh, with no review";

/// Substitute `{id}` into [`UNSIGNED_ALLOW_LIST_ACCEPTED`].
pub fn format_unsigned_allow_list_accepted(blocklist_id: &str) -> String {
    UNSIGNED_ALLOW_LIST_ACCEPTED.replace("{id}", blocklist_id)
}

/// Suggestion attached to [`UNSIGNED_ALLOW_LIST_REQUIRES_ACK`].
///
/// Frozen alongside the message it accompanies: an error that refuses
/// without naming the field that unblocks it is how the previous gate
/// earned its reputation, so the remedy is part of the locked surface
/// rather than incidental prose. `pub` for the same reason the format
/// helpers are — `tests/frozen_strings_unsigned_allow.rs` pins it
/// byte-for-byte from outside the crate, which a private const makes
/// impossible.
pub const UNSIGNED_ALLOW_LIST_REQUIRES_ACK_SUGGESTION: &str =
    "set accept_unsigned_allow = true on this list if you trust its publisher, or set base = \"deny\" if this is a deny-direction list";

/// Sprint 50 T2 (`_docs/features/lists_categories_v1.md` §9 row 5, W2.1):
/// operator-facing message emitted when a blocklist declares
/// `trust = signed`. The signed-feed path is parked for a later sprint
/// (§2 W2.1: "`signed` is parked (S51+)"); meanwhile the validator
/// refuses the variant so a config does not silently land in a state
/// the daemon cannot honour.
///
/// **Parameterless.** No `{…}` placeholders — the value is constant
/// per the design doc. T5 will mirror this byte-for-byte into
/// `tests/frozen_strings_s50.rs`; the inline `tests` module below pins
/// it as a defence-in-depth check that lights up earlier.
pub const TRUST_SIGNED_NOT_YET_SUPPORTED: &str =
    "trust=signed is not supported in this version. Use trust=local for trusted allow-lists or trust=remote-unsigned for block-only lists.";

/// Operator-facing message emitted when a `[[devices]]` entry sets a
/// `network_name` that is not syntactically a domain name. The rule is
/// the same one `local_dns` records are held to
/// ([`crate::config::validator::is_valid_fqdn_syntax`]) — a device's
/// network name is served from the same answer path, so accepting a
/// looser syntax here would only defer the failure to query time.
///
/// `{id}` is the device id, `{name}` the offending name.
pub const NETWORK_NAME_INVALID_FQDN: &str =
    "devices.{id}.network_name '{name}' is not a valid FQDN label \
     (1-63 chars, alphanumeric + hyphen, no leading/trailing hyphen).";

/// Substitute `{id}` / `{name}` into [`NETWORK_NAME_INVALID_FQDN`].
pub fn format_network_name_invalid_fqdn(id: &str, name: &str) -> String {
    NETWORK_NAME_INVALID_FQDN
        .replace("{id}", id)
        .replace("{name}", name)
}

/// Operator-facing message emitted when a `[[devices]]` entry sets
/// `network_name_wildcard = true` with no `network_name` to widen. The
/// flag only ever means "also answer `*.<network_name>`", so on its own
/// it is silently inert — refuse it rather than let the operator believe
/// a wildcard is being served.
///
/// `{id}` is the device id.
pub const NETWORK_NAME_WILDCARD_WITHOUT_NAME: &str =
    "devices.{id}.network_name_wildcard=true has no effect without network_name set.";

/// Substitute `{id}` into [`NETWORK_NAME_WILDCARD_WITHOUT_NAME`].
pub fn format_network_name_wildcard_without_name(id: &str) -> String {
    NETWORK_NAME_WILDCARD_WITHOUT_NAME.replace("{id}", id)
}

// ── what replaced the lists_categories_v2 §5.4 reload validations ──
//
// This block held rows 1-3 of the design doc §5.4 table, all keyed on the
// tag model, plus row 4's `uncategorized`-sentinel ERROR. `plp-s3` cut tags
// out of the filtering decision and `plp-s5a` removed the field, so all four
// became strings the product could not emit; `plp-s5f` retired them.
//
// What stands here now is their replacement, byte-pinned from outside the
// crate in `tests/frozen_strings_plp_profile_diagnostics.rs` -- whose header
// carries the withdrawn->replacement table, so a reader who greps a retired
// constant name lands on what took its place instead of on nothing.

/// `plp-s3` — emitted when a profile filters on **no list at all** while the
/// config has at least one enabled list to filter on.
///
/// This is what `_docs/features/profile_list_policy.md` §2.2 puts in place of
/// the tag model's "device not filtered" WARN, and it is the same signal one
/// hop earlier: a device inherits its profile's policy, so a profile that
/// ignores every list leaves every device on it silently exposed. Asking per
/// device would repeat one profile's answer once per member.
///
/// **Guarded on the config having enabled lists**, deliberately: a config
/// with no lists yet is a fresh install, not a misconfiguration, and a WARN
/// that fires on every profile of every new config is a WARN nobody reads —
/// the failure mode project rules §Neutrality documents twice for detectors.
///
/// WARN and not ERROR: a profile that deliberately filters nothing is
/// legitimate (a guest profile with `block_all`, an admin bypass). What is
/// forbidden is the **silence**, which is the same rule `base = "ignore"`
/// pays under P6.
///
/// `{id}` is the profile id.
pub const PROFILE_FILTERS_NO_LISTS: &str =
    "profile \"{id}\" filters on no list — every device resolving to it is unfiltered by lists";

/// Substitute `{id}` into [`PROFILE_FILTERS_NO_LISTS`].
pub fn format_profile_filters_no_lists(profile_id: &str) -> String {
    PROFILE_FILTERS_NO_LISTS.replace("{id}", profile_id)
}

/// `_docs/features/profile_list_policy.md` §4 S2 — emitted when
/// `profiles.<id>.lists` names a blocklist id that no `[[blocklists]]`
/// entry defines.
///
/// **An ERROR, not a WARN, and that asymmetry is the whole point.** The
/// tag model this replaces let a profile name a tag that no list carried
/// (`profiles.kids.tags = ["security"]` on the live host, matching
/// nothing): the operator expressed a segmentation intent, the loader
/// accepted it, and the intent was silently discarded — no error, no
/// warning, nothing in `warden status`. That is defect E2 in the design
/// doc §1.1, and it is the failure this workstream exists to repair. A
/// list-policy override naming a list that does not exist is the same
/// shape, so it is refused at load rather than logged and dropped.
///
/// `{profile}` profile key · `{list}` the unresolvable blocklist id.
pub const PROFILE_LIST_POLICY_UNKNOWN_LIST: &str =
    "profile \"{profile}\" sets lists.{list} but no [[blocklists]] entry has id \"{list}\"";

/// Substitute `{profile}` and `{list}` into
/// [`PROFILE_LIST_POLICY_UNKNOWN_LIST`].
pub fn format_profile_list_policy_unknown_list(profile_key: &str, list_id: &str) -> String {
    PROFILE_LIST_POLICY_UNKNOWN_LIST
        .replace("{profile}", profile_key)
        .replace("{list}", list_id)
}

/// Suggestion attached to [`PROFILE_LIST_POLICY_UNKNOWN_LIST`].
///
/// Names both repairs, because either can be the right one: the id may be
/// a typo (fix the override) or the list may have been removed while the
/// override outlived it (drop the override).
pub const PROFILE_LIST_POLICY_UNKNOWN_LIST_SUGGESTION: &str =
    "add a [[blocklists]] entry with that id, or remove the entry from this profile's `lists`";

/// `_docs/features/profile_list_policy.md` §4 S4 / §2.3 — emitted when
/// `profiles.<id>.lists.<list> = "allow"` names a list whose own
/// `[[blocklists]]` row is remote and carries no
/// `accept_unsigned_allow = true`.
///
/// **The load-time backstop for override-scope consent.** The sibling check
/// [`UNSIGNED_ALLOW_LIST_REQUIRES_ACK`] keys on `b.base == Allow` — the
/// *list's* own direction — and says nothing about a per-profile override.
/// Measured on this branch before the check existed: an override to `allow`
/// on an unsigned remote list with no ack passed the entire config layer.
///
/// **The two layers cover different WRITERS — they are not belt-and-braces
/// on one path.** `profiles.<id>.lists` has exactly three writer classes:
/// `IpcCommand::ProfileUpdate` (both the CLI, which writes only over IPC, and
/// the TUI), the two migrators at `cli/commands/migrate.rs:676` and `:1109`,
/// which assemble the TOML table directly, and a text editor. The IPC handler
/// cannot see the last two; a load-time check cannot give the first a
/// readable refusal *before* the write. Drop either layer and a whole class of
/// writer goes unguarded.
///
/// **An ERROR, not a WARN, and the instrument matters.** The `base = ignore`
/// and `base = allow` notices next door are WARNs because those states are
/// legitimate-if-declared, and what is forbidden there is the *silence*. This
/// is not that: an unconsented allow on a remote list is the canonical bypass
/// — whoever controls the URL unblocks any domain they add, at every refresh,
/// for every profile naming it `allow`. The precedent is
/// [`UNSIGNED_ALLOW_LIST_REQUIRES_ACK`], which already ERRORs on the identical
/// exposure at list scope.
///
/// **Why a load-time ERROR is safe on a live resolver**, given that it stops
/// the daemon starting: no migration can produce the state it refuses.
/// **Both** migrators derive every emitted override from the list's own row:
/// `migrate.rs:665` (v2→v3) as `if applies { l.kind.as_str() } else
/// { "ignore" }`, and `migrate.rs:1097` (v1→v3) as `if subscribed.contains(id)
/// { base.as_str() } else { "ignore" }` — the second under a comment at
/// `:1044` stating that `base` is read after the rename so the direction is
/// "never a second derivation of it". Direction is a global attribute of the
/// list before v3, so neither migrator can emit `allow` for a pair whose list
/// is not already `base = allow`; and such a row, if remote and unconsented,
/// is already refused today by [`UNSIGNED_ALLOW_LIST_REQUIRES_ACK`]. This
/// therefore adds zero migration failures on any path, v1 or v2. The
/// hand-written case survives the migrator verbatim (`migrate.rs:654` skips a
/// profile that already carries `lists`), which is exactly the route this
/// backstop exists for.
///
/// **It names the profile as well as the list, deliberately.** The ack lives
/// on the list's row; the offence lives in the profile. An error naming only
/// the list sends the operator to stare at a row that looks perfectly fine.
///
/// `{profile}` profile key · `{list}` blocklist id · `{got}` the observed
/// [`BlocklistTrust`], kebab-case to match the on-wire form.
pub const PROFILE_LIST_POLICY_UNSIGNED_ALLOW_REQUIRES_ACK: &str =
    "profile \"{profile}\" sets lists.{list} = \"allow\" but blocklist '{list}' has trust='{got}' and no accept_unsigned_allow. A remote allow-list can unblock any domain it lists, and its content can change at every refresh with no review.";

/// Substitute `{profile}`, `{list}` and `{got}` into
/// [`PROFILE_LIST_POLICY_UNSIGNED_ALLOW_REQUIRES_ACK`].
pub fn format_profile_list_policy_unsigned_allow_requires_ack(
    profile_key: &str,
    list_id: &str,
    got: BlocklistTrust,
) -> String {
    PROFILE_LIST_POLICY_UNSIGNED_ALLOW_REQUIRES_ACK
        .replace("{profile}", profile_key)
        .replace("{list}", list_id)
        .replace("{got}", trust_kebab(got))
}

/// Suggestion attached to
/// [`PROFILE_LIST_POLICY_UNSIGNED_ALLOW_REQUIRES_ACK`].
///
/// Names the list-scoped repair first because that is where the declaration
/// belongs: consent is a property of the list, declared once, applying to
/// every profile that overrides it. The override-scoped repair is second
/// because dropping the override is the right move when the operator did not
/// mean to take the exposure at all.
pub const PROFILE_LIST_POLICY_UNSIGNED_ALLOW_REQUIRES_ACK_SUGGESTION: &str =
    "set accept_unsigned_allow = true on that blocklist if you trust its publisher, or drop the \"allow\" override from this profile";

/// Emitted for a `[lists].sources` entry with no enabled `[[blocklists]]`
/// row to match it. The entry is downloaded on schedule and filters
/// nothing, which is invisible from anywhere else in the output — so the
/// message says both what happens and what to type.
///
/// **It used to enumerate "profile, device, group or subnet".** Under the
/// tag model any of the four could reach a list, by carrying a tag the
/// list carried. Under plp only a **profile** can — by inheriting the
/// list's `base` or by naming its id in `profiles.<id>.lists` — so three
/// quarters of that sentence named entities that cannot reach a list at
/// all, and sent the operator looking for a knob that no longer exists.
/// The repair it prints is unchanged and still correct: this warning
/// fires only when there is genuinely no row, and `lists add` is what
/// creates one.
///
/// `{source}` is the entry as written in the config.
pub const LEGACY_SOURCE_NOT_ENFORCED: &str =
    "list source \"{source}\" is downloaded but filters nothing — it has no \
     [[blocklists]] entry, so no profile can apply a direction to it. Run \
     `warden lists remove {source}` then `warden lists add {source}` to \
     subscribe to it properly.";

/// Substitute `{source}` into [`LEGACY_SOURCE_NOT_ENFORCED`].
pub fn format_legacy_source_not_enforced(source: &str) -> String {
    LEGACY_SOURCE_NOT_ENFORCED.replace("{source}", source)
}

/// `plp-s3` / `_docs/features/profile_list_policy.md` §2.5 — emitted at
/// **every** load, for **every** trust, for each enabled allow-direction
/// list.
///
/// # Why this exists and why it is not a refusal
///
/// An allow-direction list permits its domains in every profile that does
/// not override it. Until this sprint that state was unreachable: the third
/// `allow_direction_gates` bail refused an allow-list tagged
/// `uncategorized`, on the grounds that the sentinel is *the widest audience
/// available*, dressed up as a choice, and that every list carries it
/// already through auto-promotion. With tags out of the filtering path that
/// premise is gone, and §2.5 declines to transfer the refusal: `allow` is a
/// word the operator types, not a trap they inherit, and refusing an explicit
/// declaration is the defect that retired the old
/// `base = allow ⇒ trust = local` rule.
///
/// What the gate genuinely bought was **visibility**, and that does transfer.
/// The exposure is standing — it re-applies at every refresh — so it is
/// re-stated at every load rather than once at write time, exactly like
/// [`UNSIGNED_ALLOW_LIST_ACCEPTED`].
///
/// Paired with [`PROFILE_FILTERS_NO_LISTS`] and with the `ignore` WARN: a
/// list that permits for everyone and a list that does nothing are both
/// legitimate **only if declared**. What is forbidden is the silence — the
/// 2026-05-07 shape, eight lists filtering nothing with no signal.
///
/// `{id}` is the blocklist id.
pub const ALLOW_DIRECTION_LIST_STANDING_EXPOSURE: &str =
    "allow-list \"{id}\" is allow-direction — every profile that does not override it permits every domain this list carries, at every refresh";

/// Substitute `{id}` into [`ALLOW_DIRECTION_LIST_STANDING_EXPOSURE`].
pub fn format_allow_direction_list_standing_exposure(blocklist_id: &str) -> String {
    ALLOW_DIRECTION_LIST_STANDING_EXPOSURE.replace("{id}", blocklist_id)
}

/// `lint-warn-base-ignore-list-is-inert` — P6 of
/// `_docs/features/profile_list_policy.md` §2.1.
///
/// A list with `base = "ignore"` is loaded, refreshed, counted and shown,
/// and contributes **nothing** to any profile that does not override it.
/// That is a legitimate state — the operator asked for it — and it is
/// also, byte for byte, the shape of the 2026-05-07 incident: eight lists
/// added, ~40 minutes of network-wide zero-blocking, no error and no
/// warning, because an untagged list intersected no device's tags.
///
/// **What the old model bought and this replaces.** Until the cutover an
/// orphan list was impossible by construction: `auto_promote_blocklists`
/// stamped `uncategorized` on every untagged deny-list, so a list always
/// reached somebody. The sentinel is gone with the tag model, and P6 is
/// what buys the property back — not by forbidding the state, but by
/// refusing to let it be silent. It fires at **every** load, like
/// [`UNSIGNED_ALLOW_LIST_ACCEPTED`] and
/// [`ALLOW_DIRECTION_LIST_STANDING_EXPOSURE`], because the condition is
/// standing rather than a one-time write.
///
/// **Deliberately not emitted for a per-profile `ignore` override.** That
/// is the narrow form — one profile, reviewed, written next to the
/// profile it affects — and it is the *point* of the workstream. Warning
/// on it would fire once per (profile, list) pair on a migrated config and
/// teach operators to skim past the one WARN here that means "this list
/// reaches nobody at all". Symmetric with the last row of §2.5, which
/// declines to warn on a per-profile `allow` for the same reason.
///
/// Says nothing about `enabled`: a disabled list already announces itself
/// as off in every surface, and conflating "the operator turned it off"
/// with "the operator made it inert" would report one fact twice.
///
/// `{id}` is the blocklist id.
pub const BASE_IGNORE_LIST_IS_INERT: &str =
    "list \"{id}\" has base = \"ignore\" — it is downloaded and refreshed but filters nothing in any profile that does not override it";

/// Substitute `{id}` into [`BASE_IGNORE_LIST_IS_INERT`].
pub fn format_base_ignore_list_is_inert(blocklist_id: &str) -> String {
    BASE_IGNORE_LIST_IS_INERT.replace("{id}", blocklist_id)
}

/// A custom list whose file reads cleanly and holds no rule.
///
/// `{id}` is the custom list id.
pub const CUSTOM_LIST_EMPTY: &str =
    "custom list \"{id}\" is mounted and empty — it filters nothing";

/// Substitute `{id}` into [`CUSTOM_LIST_EMPTY`].
pub fn format_custom_list_empty(list_id: &str) -> String {
    CUSTOM_LIST_EMPTY.replace("{id}", list_id)
}

/// A custom list no profile mounts.
///
/// INFO, not WARN: a staging drawer for triage is a workflow the product
/// sells, and a chronic WARN on a deliberate state drowns the skipped-line
/// WARN that does need acting on.
///
/// `{id}` is the custom list id.
pub const CUSTOM_LIST_UNMOUNTED: &str =
    "custom list \"{id}\" exists and filters nothing: no profile mounts it";

/// Substitute `{id}` into [`CUSTOM_LIST_UNMOUNTED`].
pub fn format_custom_list_unmounted(list_id: &str) -> String {
    CUSTOM_LIST_UNMOUNTED.replace("{id}", list_id)
}

/// `lint-warn-no-default-profile` — emitted when `[server].default_profile`
/// is unset and no subnet carries a `/0`, so resolver level 5 REFUSES every
/// unmatched source.
///
/// Takes no substitution: the condition is a property of the whole config,
/// not of one entity.
pub const NO_DEFAULT_PROFILE_REFUSES_UNMATCHED: &str =
    "[server].default_profile is unset — every client that is not a configured device \
     and not inside a configured subnet will get REFUSED for every query. Set \
     default_profile to a profile id if that is not what you intended.";

/// rev-2606 §05 `schema-validator-03` — a `http://` blocklist URL.
///
/// The fetcher is https-only, so this list can be lint-clean and still never
/// update. The message names the consequence, not just the rule, because the
/// symptom an operator actually sees is a list stuck at `Failed`.
///
/// `{id}` is the blocklist id.
pub const BLOCKLIST_URL_CLEARTEXT_HTTP: &str =
    "blocklist \"{id}\" uses a cleartext http:// URL — the downloader is https-only, \
     so this list will never update";

/// rev-2606 §05 `schema-validator-03` — a blocklist URL whose host is an IP
/// literal the downloader refuses to dial (private, loopback, link-local,
/// CGNAT, multicast, broadcast or unspecified).
///
/// `{id}` is the blocklist id; `{host}` is the host as written.
pub const BLOCKLIST_URL_UNFETCHABLE_HOST: &str =
    "blocklist \"{id}\" points at \"{host}\", an address the downloader refuses \
     (private, loopback, link-local, CGNAT or unspecified) — so this list will never update";

/// Substitute `{id}` into [`BLOCKLIST_URL_CLEARTEXT_HTTP`].
pub fn format_blocklist_url_cleartext_http(blocklist_id: &str) -> String {
    BLOCKLIST_URL_CLEARTEXT_HTTP.replace("{id}", blocklist_id)
}

/// Substitute `{id}` and `{host}` into [`BLOCKLIST_URL_UNFETCHABLE_HOST`].
pub fn format_blocklist_url_unfetchable_host(blocklist_id: &str, host: &str) -> String {
    BLOCKLIST_URL_UNFETCHABLE_HOST
        .replace("{id}", blocklist_id)
        .replace("{host}", host)
}

/// §4.66 L1 R3 — emitted when a device carries an `owner`,
/// `device_type`, or `department` value that no `[[labels]]` entry of
/// the corresponding kind declares (by id or by display name).
///
/// Uniform across the three **device-metadata** kinds: they are the same
/// construct, so the diagnostic has no per-kind exception among them.
/// the retired `LabelKind::Tag` has no counterpart and must not grow one — see
/// [`check_device_metadata_vocabulary`] for the arithmetic.
///
/// WARN, never an error: the three fields are free-form `Option<String>`
/// that no resolver reads, so an unknown value costs nothing at runtime.
/// It is worth reporting because a *near*-duplicate does cost something
/// to a human — the deployment that motivated this rule had
/// `department = "Personal"` living next to `department = "Persona"`.
///
/// Only fires once the operator has declared at least one label of that
/// kind: an empty vocabulary means the dimension is not being curated,
/// not that every value in it is wrong.
///
/// The message carries the command that would adopt the value, because
/// warden must never adopt it on the operator's behalf — that is the
/// same posture the untagged-allow-list WARN takes, and the same scar
/// (`tags = ["uncategorized"]` written into files that never had it)
/// that it exists to avoid repeating.
///
/// `{id}` device id · `{field}` TOML field name · `{value}` the value as
/// written · `{kind}` the label kind that governs the field.
pub const DEVICE_METADATA_UNKNOWN_LABEL: &str =
    "device \"{id}\".{field} = \"{value}\" is not declared in the [[labels]] vocabulary — \
     run `warden label add <id> --kind {kind} --display-name \"{value}\"` to adopt it, or \
     correct the device";

/// Substitute every placeholder into [`DEVICE_METADATA_UNKNOWN_LABEL`].
pub fn format_device_metadata_unknown_label(
    device_id: &str,
    field: &str,
    value: &str,
    kind: &str,
) -> String {
    DEVICE_METADATA_UNKNOWN_LABEL
        .replace("{id}", device_id)
        .replace("{field}", field)
        .replace("{value}", value)
        .replace("{kind}", kind)
}

/// `tag_model_consolidation` §3.2 — emitted when two or more enabled
/// blocklists resolve to the same canonical source URL.
///
/// Duplicates are not merely wasteful. `lists::manager::source_to_cache_stem`
/// derives the on-disk cache name from the **URL alone**, so twin entries
/// share one cache body and one `.meta` sidecar: they see each other's ETag,
/// a `304` for one silently satisfies the other, and the last writer wins the
/// body — while `ListStatus` stays keyed per-id and can disagree with the file
/// it points at. Each twin also burns one of the 64 bitmask slots.
///
/// WARN at load (never fatal — the live config already contains a duplicate,
/// and refusing to start would take household DNS offline); surfaces as an
/// error through `warden config lint`, which exits `2` on warnings.
///
/// `{ids}` is the comma-separated list of every colliding blocklist id,
/// `{url}` the canonical key they share.
pub const BLOCKLIST_DUPLICATE_URL: &str =
    "blocklists {ids} resolve to the same source URL \"{url}\" — they share one cache file and its ETag; remove all but one";

/// Substitute `{ids}` and `{url}` into [`BLOCKLIST_DUPLICATE_URL`].
pub fn format_blocklist_duplicate_url(ids: &[&str], canonical_url: &str) -> String {
    BLOCKLIST_DUPLICATE_URL
        .replace("{ids}", &ids.join(", "))
        .replace("{url}", canonical_url)
}

// ── Sprint C of lists_categories_v2 — T5 add-list pre-flight ──────
//
// The Add-list flow runs three synchronous gates before persisting a
// new `[[blocklists]]` entry: URL parse, dedup, and reachability
// (HEAD probe with a 3-second timeout). Failure on the third gate
// bubbles the message below to the operator (TUI inline error or CLI
// stderr) so they can confirm the URL with a browser before retrying.
// The `--skip-head-check` CLI flag and the modal's advanced affordance
// bypass the probe for operators who already trust the source.

/// §6.1 gate 3 — emitted when the synchronous reachability probe on a
/// new blocklist URL fails (timeout, non-2xx, network error). Hard
/// block per operator decision C2.g; advanced operators bypass via
/// `--skip-head-check`.
///
/// `{url}` is the candidate URL, `{detail}` is the underlying reason
/// (timeout, status code, parse error). The detail is operator-facing
/// so a typo'd hostname surfaces alongside the generic refusal.
pub const LIST_URL_NOT_REACHABLE: &str =
    "Cannot reach '{url}': {detail}. Verify the URL in a browser, then retry — or pass --skip-head-check to add the list anyway.";

/// Substitute `{url}` and `{detail}` into [`LIST_URL_NOT_REACHABLE`].
pub fn format_list_url_not_reachable(url: &str, detail: &str) -> String {
    LIST_URL_NOT_REACHABLE
        .replace("{url}", url)
        .replace("{detail}", detail)
}

/// Map [`BlocklistTrust`] to the kebab-case spelling used on the wire
/// (matches `#[serde(rename_all = "kebab-case")]` on the enum).
/// Centralising the mapping keeps the operator-facing message consistent
/// with the TOML form an operator typed.
fn trust_kebab(t: BlocklistTrust) -> &'static str {
    match t {
        BlocklistTrust::Local => "local",
        BlocklistTrust::Signed => "signed",
        BlocklistTrust::RemoteUnsigned => "remote-unsigned",
    }
}

/// Trust/kind validation. Two checks:
///
/// 1. **W2.1 allow-direction consent.** A blocklist with `base = allow`
///    whose trust is not `local` is refused *unless* the operator set
///    `accept_unsigned_allow = true` on it; with the flag it loads and
///    raises a standing WARN instead.
/// 2. **Parking-lot enforcement for `trust = signed`.** The signed-feed
///    path ships in a future sprint (S51+); meanwhile we refuse the
///    variant so a config does not silently land in a state the daemon
///    cannot honour.
///
/// **Why check 1 stopped being categorical.** Refusing every remote
/// allow-list did not remove the risk, it relocated it: the operator
/// downloaded the list by hand and re-imported it as a local file, and
/// that private copy then never updated. Meanwhile the TUI offered a
/// Block/Allow toggle on remote lists, wrote the change, and watched
/// the validator roll it back. The risk is real and unchanged —
/// whoever controls an allow-list's URL decides what warden stops
/// blocking, at every refresh, with no review — so it is now
/// *declared* per list rather than prohibited.
///
/// **The allow direction stays soft (W1.2).** Nothing here widens it:
/// an allow-direction list does not pierce `block_all` and never beats
/// an admin `$important` deny. This pass decides only whether the
/// config is admissible, never how a query is evaluated.
///
/// **Co-occurrence (base = allow + trust = signed).** Both errors fire,
/// unchanged — the operator gets the full picture in one pass instead
/// of having to reload twice.
///
/// **Asymmetry worth knowing.** The *error* keys off `trust != Local`,
/// but the *warn* keys off `trust == RemoteUnsigned`. They are not the
/// same set: `signed` sits in the first and not the second. That is
/// deliberate — the WARN's text says the list "is remote and
/// unsigned", which of a signed list would simply be false, and a
/// diagnostic that lies is worse than a missing one. A `signed`
/// allow-list with consent is therefore refused (by check 2) and
/// silent (from this check), which is the honest combination.
fn check_blocklist_base_trust(
    config: &ConfigV1,
    errs: &mut Vec<ConfigError>,
    warns: &mut AuditWarnings,
) {
    for b in &config.blocklists {
        let entity = format!("blocklists.{}", b.id);

        // `plp-s3` / §2.5 — the standing-exposure WARN, for EVERY trust.
        //
        // An allow-direction list permits its domains in every profile that
        // does not override it. Before this sprint no such list could exist:
        // `allow_direction_gates` refused an untagged one, and refused a
        // `uncategorized`-tagged one as "the widest audience wearing a
        // choice's clothes". Tags no longer decide, so that refusal has lost
        // its premise — and §2.5 declines to transfer it, because refusing a
        // word the operator typed is the defect that killed the old
        // `base = allow ⇒ trust = local` rule.
        //
        // What the third gate *bought* was visibility, and that does
        // transfer: the exposure is declared, permanent, and re-stated at
        // every load, on the model of `UNSIGNED_ALLOW_LIST_ACCEPTED`.
        //
        // Deliberately NOT emitted for a per-profile override
        // (`profiles.X.lists = { l = "allow" }`): that is already the narrow
        // form the old gate wanted and could not express, and warning on it
        // would teach operators to skim past the WARN that matters.
        if b.enabled && b.base == BlocklistBase::Allow {
            let msg = format_allow_direction_list_standing_exposure(b.id.as_str());
            if warns.emit() {
                tracing::warn!(target: "audit", blocklist = %b.id.as_str(), "{msg}");
            }
            warns.push(msg);
        }

        // `plp-s3b` / P6 — the `base = "ignore"` twin of the WARN above.
        // A list that permits for everyone and a list that does nothing
        // are both legitimate ONLY if declared; what is forbidden is the
        // silence. Not gated on `enabled`: see `BASE_IGNORE_LIST_IS_INERT`.
        if b.base == BlocklistBase::Ignore {
            let msg = format_base_ignore_list_is_inert(b.id.as_str());
            if warns.emit() {
                tracing::warn!(target: "audit", blocklist = %b.id.as_str(), "{msg}");
            }
            warns.push(msg);
        }

        if b.base == BlocklistBase::Allow && b.trust != BlocklistTrust::Local {
            if !b.accept_unsigned_allow {
                errs.push(ConfigError::UnsignedAllowListRequiresAck(
                    ErrorContext::new(format_unsigned_allow_list_requires_ack(
                        b.id.as_str(),
                        b.trust,
                    ))
                    .with_entity(entity.clone())
                    .with_suggestion(UNSIGNED_ALLOW_LIST_REQUIRES_ACK_SUGGESTION.to_string()),
                ));
            } else if b.trust == BlocklistTrust::RemoteUnsigned {
                let msg = format_unsigned_allow_list_accepted(b.id.as_str());
                if warns.emit() {
                    tracing::warn!(target: "audit", blocklist = %b.id.as_str(), "{msg}");
                }
                warns.push(msg);
            }
        }

        if b.trust == BlocklistTrust::Signed {
            errs.push(ConfigError::TrustSignedNotYetSupported(
                ErrorContext::new(TRUST_SIGNED_NOT_YET_SUPPORTED)
                    .with_entity(entity)
                    .with_suggestion(
                        "use trust = \"local\" for trusted allow-lists, or trust = \"remote-unsigned\" for deny-direction lists".to_string(),
                    ),
            ));
        }
    }
}

/// `plp-s3` — [`PROFILE_FILTERS_NO_LISTS`]: every profile that ignores every
/// enabled list.
///
/// Direction per pair comes from [`effective_direction`], the same predicate
/// the publish-time projection uses (P5). A second copy of the inheritance
/// rule here is precisely D11: the validator saw a superset of what the
/// resolver applied, and the coverage WARN went silent on devices that really
/// were uncovered — a false negative on a safety signal.
///
/// **This is the substitute for two withdrawn tag passes**, and it is why
/// they could be withdrawn rather than merely deleted:
///
/// - `check_profile_tag_inheritance` (`PROFILE_CONTRIBUTES_NO_TAGS`) asked
///   whether a profile contributed any tags. Under plp a profile's
///   contribution is its list policy, and "contributes nothing" is exactly
///   the condition below — one hop *later*, so it catches the case the tag
///   version could not: a profile carrying tags that no list happened to
///   match still looked healthy to it.
/// - `check_tag_intersections`' list side (`BLOCKLIST_TAGS_MATCH_NOTHING`)
///   asked the mirror question of a list. That one has **no** replacement
///   here and its partial replacement lives in [`inert_blocklists`] — see
///   the gap recorded there.
///
/// **Note the doc-comment this replaces.** `check_tag_intersections`' block
/// ran into this function's own with no blank line between them, so rustdoc
/// attached the whole "zero-intersection tag diagnostics" preamble to
/// `check_profile_list_coverage` — a function that reads no tag at all. A
/// defence made of prose does not fail a build; this one had already
/// stopped being true and nothing said so.
fn check_profile_list_coverage(config: &ConfigV1, warns: &mut AuditWarnings) {
    if !config.blocklists.iter().any(|b| b.enabled) {
        return;
    }
    for (profile_key, profile) in &config.profiles {
        let filters = config
            .blocklists
            .iter()
            .filter(|b| b.enabled)
            .any(|b| effective_direction(profile, b) != ListPolicy::Ignore);
        if !filters {
            let msg = format_profile_filters_no_lists(profile_key);
            if warns.emit() {
                tracing::warn!(target: "audit", profile = %profile_key, "{msg}");
            }
            warns.push(msg);
        }
    }
}

/// Why a blocklist is installed but participates in zero resolutions.
///
/// **One variant, deliberately.** Two others (`AllowListNoTags`,
/// `TagsMatchNothing`) stood here unproduced after the plp cutover and were
/// removed in `plp-s5f`. Both were tag-keyed, and the first was actively
/// false: it reported an untagged allow-direction list as filtering nothing,
/// when such a list is inherited by every profile that does not override it
/// — F24's claim rendered in `warden status` instead of `config lint`. An
/// operator acting on it removes a working exemption.
///
/// Keep it a single-variant enum rather than collapsing it to a unit: the
/// gap recorded on [`inert_blocklists`] needs a second reason (*declared
/// inert* and *made inert by unanimous override* are different facts for an
/// operator), and a `match` is where that lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InertListReason {
    /// `base = "ignore"` and no profile overrides it to anything else —
    /// P6 of `_docs/features/profile_list_policy.md` §2.1.
    ///
    /// The only variant [`inert_blocklists`] produces.
    BaseIgnore,
    /// A custom list whose file reads cleanly and holds no rule.
    CustomListEmpty,
    /// A custom list no profile mounts. Legitimate as a staging drawer,
    /// which is why this is the INFO of the pair and not a second WARN.
    CustomListUnmounted,
}

impl InertListReason {
    /// The operator-facing sentence, reusing the frozen string the
    /// matching load-time WARN already emits — so `warden status`,
    /// `warden config lint` and journalctl all say the same thing.
    pub fn message(self, list_id: &str) -> String {
        match self {
            InertListReason::BaseIgnore => format_base_ignore_list_is_inert(list_id),
            InertListReason::CustomListEmpty => format_custom_list_empty(list_id),
            InertListReason::CustomListUnmounted => format_custom_list_unmounted(list_id),
        }
    }
}

/// `tag_model_consolidation` §3.3 — every blocklist that is installed
/// but filters nothing, with the reason.
///
/// **Detection is not new here.** The condition already fires as a load-time
/// WARN ([`BASE_IGNORE_LIST_IS_INERT`]) and is already caught by
/// `warden config lint`; what was missing is that the operator never saw it
/// without going looking. This exposes the same predicate so `warden status`
/// can render it, rather than adding a second copy of the rule.
///
/// # What this used to return, and why it was wrong
///
/// Two tag-keyed predicates: `base = allow` with empty `tags`, and a tagged
/// list whose tags intersected no entity. Both were computed from a field
/// that stopped deciding anything at S3, and the first one was **F24's claim
/// at a second surface** — an allow-direction list every profile inherits,
/// rendered by `warden status` as installed-but-filtering-nothing. An
/// operator acting on that removes a working exemption.
///
/// # The narrowing, and what it deliberately does not cover
///
/// A `base = "ignore"` list that **some** profile overrides to `deny` or
/// `allow` is not returned: it filters for that profile, so listing it under
/// `inert:` would be the same species of false claim in the other direction.
/// The load-time WARN still fires for it, and its text carries the qualifier
/// ("…in any profile that does not override it") that makes both statements
/// true at once.
///
/// **Gap, reported rather than papered over:** a `base = "deny"` list that
/// **every** profile overrides to `ignore` is genuinely inert and appears
/// neither here nor as a load-time WARN. Covering it needs a new WARN and a
/// new frozen string — a surface this lane does not own — and inventing the
/// detection here alone would break the one-place invariant `status.rs:600`
/// documents by making `warden status` report what `config lint` does not.
///
/// **Not gated on `enabled`**, matching [`BASE_IGNORE_LIST_IS_INERT`]
/// exactly: this is a projection of that WARN, and a projection that filters
/// rows the WARN emits is a second rule wearing the first one's name.
///
/// Config order is preserved so repeated runs list them the same way.
pub fn inert_blocklists(config: &ConfigV1) -> Vec<(&str, InertListReason)> {
    // A config with no profiles makes the `all()` below vacuously true, so
    // every ignore-direction list would be reported inert on the strength of
    // a claim no profile actually made. Vacuous truth is not a measurement.
    if config.profiles.is_empty() {
        return Vec::new();
    }
    config
        .blocklists
        .iter()
        .filter(|b| {
            b.base == BlocklistBase::Ignore
                && config
                    .profiles
                    .values()
                    .all(|p| effective_direction(p, b) == ListPolicy::Ignore)
        })
        .map(|b| (b.id.as_str(), InertListReason::BaseIgnore))
        .collect()
}

/// Collect the "no profile mounts it" line for every declared custom list.
///
/// Collect-only, deliberately: this is the **data** channel, which is what
/// `warden config lint` renders. It does not log, because a config load can
/// run before the process has installed a `tracing` subscriber, and a
/// diagnostic emitted into no subscriber is a diagnostic that does not
/// exist. The daemon logs the same line from its own load path, where a
/// subscriber is guaranteed — one predicate, one data site, one log site.
fn check_unmounted_custom_lists(config: &ConfigV1, warns: &mut AuditWarnings) {
    for (id, reason) in inert_custom_lists(config) {
        warns.push(reason.message(id.as_str()));
    }
}

/// Every custom list that is declared but filters nothing, with the reason.
///
/// The empty case needs the compiled store, which only a caller that has
/// loaded the packs holds; the unmounted case is derivable from the config
/// alone. This returns the second, and a caller with a store adds the first
/// — one rule, two call sites, rather than two copies of the predicate.
pub fn inert_custom_lists(config: &ConfigV1) -> Vec<(Id, InertListReason)> {
    let mounted: HashSet<&Id> = config
        .profiles
        .values()
        .flat_map(|p| p.custom_lists.iter())
        .collect();
    config
        .custom_lists
        .iter()
        .filter(|cl| !mounted.contains(&cl.id))
        .map(|cl| (cl.id.clone(), InertListReason::CustomListUnmounted))
        .collect()
}

// ── [[retired]] ────────────────────────────────────────────────

fn check_retired_uniqueness(retired: &[RetiredEntry], errs: &mut Vec<ConfigError>) {
    let mut seen: HashMap<(RetiredType, Id), usize> = HashMap::new();
    for (i, r) in retired.iter().enumerate() {
        if let Some(prev) = seen.insert((r.entity_type, r.id.clone()), i) {
            errs.push(ConfigError::DuplicateId(
                ErrorContext::new(format!(
                    "retired[{i}] duplicates retired[{prev}] (id \"{}\", type \"{:?}\")",
                    r.id, r.entity_type
                ))
                .with_entity(format!("retired.{}", r.id)),
            ));
        }
    }
}

fn check_retired_window(config: &ConfigV1, now: OffsetDateTime, errs: &mut Vec<ConfigError>) {
    // Build a per-type set of currently-quarantined ids.
    let mut quarantine: HashMap<RetiredType, HashMap<Id, OffsetDateTime>> = HashMap::new();
    for r in &config.retired {
        // retired-01: a future `retired_at` is nonsensical — an entity can't
        // have been retired later than now. It also breaks `is_active` (a
        // negative age reads as "< 90 days" → quarantined forever) and the
        // "<90 days ago" wording below. Reject it as its own error rather
        // than silently quarantining the id permanently.
        if r.retired_at > now {
            errs.push(ConfigError::ValidationFailed(
                ErrorContext::new(format!(
                    "[[retired]] id \"{}\" has retired_at {} in the future",
                    r.id, r.retired_at
                ))
                .with_entity(format!("retired.{}", r.id))
                .with_suggestion(
                    "set retired_at to when the id was actually retired (not a future date)"
                        .to_string(),
                ),
            ));
            continue;
        }
        if r.is_active(now) {
            quarantine
                .entry(r.entity_type)
                .or_default()
                .insert(r.id.clone(), r.retired_at);
        }
    }

    let check = |kind: RetiredType,
                 id: &Id,
                 section: &str,
                 errs: &mut Vec<ConfigError>,
                 quarantine: &HashMap<RetiredType, HashMap<Id, OffsetDateTime>>| {
        if let Some(map) = quarantine.get(&kind) {
            if let Some(retired_at) = map.get(id) {
                // retired-01: state the window END (actionable) instead of the
                // old "(<90 days ago)" — all entries here have a past
                // retired_at (future ones errored above).
                let until =
                    *retired_at + time::Duration::days(super::retired::RETIREMENT_WINDOW_DAYS);
                errs.push(ConfigError::IdRecentlyRetired(
                    ErrorContext::new(format!(
                        "id \"{id}\" is quarantined (retired at {retired_at}); reuse is blocked until {until}"
                    ))
                    .with_entity(format!("{section}.{id}"))
                    .with_suggestion(
                        "pick a different id, or wait until the quarantine window ends and remove the [[retired]] entry".to_string(),
                    ),
                ));
            }
        }
    };

    for b in &config.blocklists {
        check(
            RetiredType::Blocklist,
            &b.id,
            "blocklists",
            errs,
            &quarantine,
        );
    }
    for key in config.profiles.keys() {
        if let Ok(id) = Id::try_from(key.as_str()) {
            check(RetiredType::Profile, &id, "profiles", errs, &quarantine);
        }
    }
    for d in &config.devices {
        check(RetiredType::Device, &d.id, "devices", errs, &quarantine);
    }
    for g in &config.groups {
        check(RetiredType::Group, &g.id, "groups", errs, &quarantine);
    }
    for s in &config.subnets {
        check(RetiredType::Subnet, &s.id, "subnets", errs, &quarantine);
    }
    for s in &config.schedules {
        check(RetiredType::Schedule, &s.id, "schedules", errs, &quarantine);
    }
    for a in &config.admin_rules {
        check(
            RetiredType::AdminRule,
            &a.id,
            "admin_rules",
            errs,
            &quarantine,
        );
    }
}

// ── small parsers (days / hours) ───────────────────────────────

fn parse_days(specs: &[String]) -> Option<u8> {
    let mut mask: u8 = 0;
    for spec in specs {
        match spec.to_ascii_lowercase().as_str() {
            "mon" => mask |= 1 << 0,
            "tue" => mask |= 1 << 1,
            "wed" => mask |= 1 << 2,
            "thu" => mask |= 1 << 3,
            "fri" => mask |= 1 << 4,
            "sat" => mask |= 1 << 5,
            "sun" => mask |= 1 << 6,
            "weekdays" => mask |= 0b0011111,
            "weekends" => mask |= 0b1100000,
            "all" => mask |= 0b1111111,
            _ => return None,
        }
    }
    if mask == 0 {
        return None;
    }
    Some(mask)
}

fn parse_hours(hours: &str) -> Option<(u8, u8, u8, u8)> {
    let (a, b) = hours.split_once('-')?;
    let (sh, sm) = parse_time(a)?;
    let (eh, em) = parse_time(b)?;
    Some((sh, sm, eh, em))
}

fn parse_time(s: &str) -> Option<(u8, u8)> {
    let (h, m) = s.trim().split_once(':')?;
    let h: u8 = h.parse().ok()?;
    let m: u8 = m.parse().ok()?;
    if h > 23 || m > 59 {
        return None;
    }
    Some((h, m))
}

fn normalise_mac(mac: &str) -> Option<String> {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    if !parts
        .iter()
        .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return None;
    }
    Some(mac.to_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::{
        blocklist::Blocklist, device::Device, group::Group, profile::Profile, schedule::Schedule,
        subnet::Subnet, ServerGlobals,
    };
    use time::macros::datetime;

    fn now() -> OffsetDateTime {
        datetime!(2026-04-22 12:00:00 UTC)
    }

    fn blocklist(id: &str) -> Blocklist {
        Blocklist {
            id: Id::new(id).unwrap(),
            display_name: id.into(),
            url: "https://example.com/list.txt".into(),
            format: super::super::blocklist::BlocklistFormat::Domains,
            update_interval_hours: 12,
            max_entries: 1000,
            enabled: true,
            auth_token_ref: None,
            base: super::super::blocklist::BlocklistBase::default(),
            trust: super::super::blocklist::BlocklistTrust::default(),
            accept_unsigned_allow: false,
            max_consecutive_failures: 5,
        }
    }

    fn profile_default() -> Profile {
        Profile {
            display_name: "Default".into(),
            block_response: None,
            blocked_ttl_secs: None,
            admin_rules: vec![],
            block_all: false,
            local_records: vec![],
            ecs: None,
            rewrite_rules: vec![],
            safe_search: false,
            custom_lists: vec![],
            // Enumerated rather than `..Default::default()` to match this
            // helper's existing style: spelling every field out is what makes
            // a new one a compile error here instead of a silent default.
            lists: std::collections::BTreeMap::new(),
        }
    }

    fn device(id: &str, ip: &str, profile: Option<&str>) -> Device {
        Device {
            id: Id::new(id).unwrap(),
            display_name: id.into(),
            ip: Some(ip.parse().unwrap()),
            mac: None,
            mac_aliases: vec![],
            profile: profile.map(|p| Id::new(p).unwrap()),
            groups: vec![],
            owner: None,
            device_type: None,
            department: None,
            notes: None,
            allow_rules: vec![],
            deny_rules: vec![],
            override_profile_deny: false,
            unfiltered: false,
            network_name: None,
            network_name_wildcard: false,
        }
    }

    fn group(id: &str, profile: &str, priority: i32, devices: &[&str]) -> Group {
        Group {
            id: Id::new(id).unwrap(),
            display_name: id.into(),
            profile: Id::new(profile).unwrap(),
            priority,
            devices: devices.iter().map(|d| Id::new(*d).unwrap()).collect(),
        }
    }

    /// s4 config-m4 — build a REAL, loaded [`Secrets`] via the public
    /// `load_secrets` path on a 0600 temp file.
    ///
    /// Do not be tempted by `Secrets::empty()` / `Secrets::default()` here:
    /// both carry `loaded: false`, the cross-check is gated on
    /// `is_loaded()`, and a test built on either would skip the check
    /// entirely and pass against broken code. Mirrors the same-reason
    /// helpers at `lists::source_key::tests::make_secrets_with` and
    /// `lists::manager::tests::secrets_with` (`entries` is private, so the
    /// load path is the only way to a populated table).
    fn loaded_secrets_with(names: &[&str]) -> Secrets {
        use std::fs;
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::{AtomicUsize, Ordering};
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let pid = std::process::id();
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("purge-cfgm4-{pid}-{n}"));
        fs::create_dir_all(&dir).unwrap();
        let sp = dir.join("secrets.toml");
        {
            let mut f = fs::File::create(&sp).unwrap();
            for name in names {
                writeln!(f, "{name} = \"token-value\"").unwrap();
            }
        }
        let mut perm = fs::metadata(&sp).unwrap().permissions();
        perm.set_mode(0o600);
        fs::set_permissions(&sp, perm).unwrap();
        let secrets = crate::config::secrets::load_secrets(&sp).unwrap();
        let _ = fs::remove_dir_all(&dir);
        assert!(secrets.is_loaded(), "helper must produce a LOADED table");
        secrets
    }

    #[test]
    fn s4_m4_dangling_auth_token_ref_is_crossrefmiss() {
        let mut c = basic_config();
        c.blocklists[0].auth_token_ref = Some("ghost-ref".into());
        let secrets = loaded_secrets_with(&["corp-list-token", "vendor-token"]);

        let errs = validate_collect(
            &c,
            now(),
            &mut AuditWarnings::silent(),
            Some(&secrets),
            None,
        )
        .expect_err("a dangling auth_token_ref must fail the validator pass");

        let miss = errs
            .iter()
            .find(|e| matches!(e, ConfigError::CrossRefMiss(_)))
            .unwrap_or_else(|| panic!("expected a CrossRefMiss, got {errs:?}"));
        let ConfigError::CrossRefMiss(ctx) = miss else {
            unreachable!()
        };
        assert!(ctx.reason.contains("ghost-ref"), "{ctx:?}");
        // The part that makes it actionable rather than merely reported:
        // the operator is told which names DO exist.
        let sugg = ctx.suggestion.as_deref().unwrap_or_default();
        assert!(sugg.contains("corp-list-token"), "{sugg}");
        assert!(sugg.contains("vendor-token"), "{sugg}");
    }

    #[test]
    fn s4_m4_resolvable_ref_and_unloaded_secrets_both_pass() {
        // A ref that resolves is silent.
        let mut c = basic_config();
        c.blocklists[0].auth_token_ref = Some("corp-list-token".into());
        let secrets = loaded_secrets_with(&["corp-list-token"]);
        assert!(
            validate_collect(
                &c,
                now(),
                &mut AuditWarnings::silent(),
                Some(&secrets),
                None
            )
            .is_ok(),
            "a resolvable ref must not be flagged"
        );

        // No secrets.toml yet → the check is skipped, not failed. An
        // operator who has not set up secrets at all must still boot.
        let mut c2 = basic_config();
        c2.blocklists[0].auth_token_ref = Some("ghost-ref".into());
        let absent = Secrets::empty();
        assert!(!absent.is_loaded());
        assert!(
            validate_collect(
                &c2,
                now(),
                &mut AuditWarnings::silent(),
                Some(&absent),
                None
            )
            .is_ok(),
            "an unloaded secrets table must skip the cross-check"
        );
        // Same for a call site that has no table at all.
        assert!(
            validate_collect(&c2, now(), &mut AuditWarnings::silent(), None, None).is_ok(),
            "None must skip the cross-check"
        );
    }

    fn basic_config() -> ConfigV1 {
        let mut c = ConfigV1 {
            schema_version: SCHEMA_VERSION_V1,
            server: ServerGlobals {
                default_profile: None,
                default_block_response: super::super::profile::BlockResponseV1::Zero,
                default_blocked_ttl_secs: 60,
                ..ServerGlobals::default()
            },
            blocklists: vec![blocklist("privacy-ads")],
            ..ConfigV1::test_scaffold()
        };
        c.profiles.insert("default".into(), profile_default());
        c
    }

    // ── happy path ────────────────────────────────────────

    #[test]
    fn empty_schema_version_1_passes() {
        let c = ConfigV1 {
            schema_version: SCHEMA_VERSION_V1,
            server: ServerGlobals {
                default_blocked_ttl_secs: 60,
                ..ServerGlobals::default()
            },
            ..ConfigV1::test_scaffold()
        };
        assert!(validate(&c, now()).is_ok());
    }

    #[test]
    fn basic_config_passes() {
        assert!(validate(&basic_config(), now()).is_ok());
    }

    #[test]
    fn blocklist_url_with_userinfo_is_refused() {
        // blocklist-01: credentials in the URL are refused, and the
        // credential is NOT echoed back in the error.
        let mut c = basic_config();
        c.blocklists[0].url = "https://user:sekret@lists.example/a.txt".into();
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e.context().reason.contains("must not embed credentials")),
            "got {errs:?}"
        );
        assert!(
            !errs.iter().any(|e| e.context().reason.contains("sekret")),
            "credential leaked into error: {errs:?}"
        );
    }

    /// `file://` is refused, and that refusal is intentional.
    ///
    /// A `file:///…` blocklist URL parses fine at the schema layer, so it
    /// is easy to believe it is supported — a fixture in
    /// `schema::blocklist`'s tests used one for years and read as if it
    /// were. It is not: an operator-authored local list goes through the
    /// `imported.local` bridge, which resolves under `<config_dir>/lists`
    /// and applies the W2.1 trust check. Widening this to real `file://`
    /// URLs would let a config name any path on the box and skip that
    /// check, so if this test ever fails, the fix is almost certainly to
    /// restore the refusal rather than to delete the test.
    #[test]
    fn blocklist_file_url_is_refused_so_the_import_bridge_stays_the_only_local_path() {
        let mut c = basic_config();
        c.blocklists[0].url = "file:///etc/shadow".into();
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e.context().reason.contains("must begin with http")),
            "got {errs:?}"
        );

        // Control: the bridge form IS accepted, so this test cannot pass
        // merely because `basic_config()` is broken.
        let mut ok = basic_config();
        ok.blocklists[0].url = "https://imported.local/trusted.txt".into();
        assert!(
            validate(&ok, now()).is_ok(),
            "the imported.local bridge must remain valid"
        );
    }

    #[test]
    fn blocklist_url_with_path_at_sign_is_allowed() {
        // blocklist-01: a `@` in the PATH (not the authority) is fine.
        let mut c = basic_config();
        c.blocklists[0].url = "https://lists.example/lists/@team/a.txt".into();
        assert!(validate(&c, now()).is_ok());
    }

    #[test]
    fn future_retired_at_is_refused() {
        // retired-01: a future retired_at is its own error (not a permanent
        // silent quarantine).
        let mut c = basic_config();
        c.retired.push(RetiredEntry {
            id: Id::new("legacy").unwrap(),
            entity_type: RetiredType::Device,
            retired_at: datetime!(2099-01-01 00:00:00 UTC),
        });
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e.context().reason.contains("in the future")),
            "got {errs:?}"
        );
    }

    /// schema-02 (rev-2606): `ConfigV1::test_scaffold()` is a VALID config —
    /// the manual `Default` pins `schema_version = SCHEMA_VERSION_V1`
    /// instead of the derive's 0, which `validate` rejects. Internal
    /// construction sites no longer need to hand-patch the version.
    #[test]
    fn config_v1_default_validates_clean() {
        assert!(validate(&ConfigV1::test_scaffold(), now()).is_ok());
    }

    // ── [cluster] (§4.11) ──────────────────────────────────

    #[test]
    fn cluster_default_is_inert_and_valid() {
        // The default `[cluster]` (disabled, primary) adds no errors —
        // proves the section is inert.
        let mut errs = Vec::new();
        check_cluster(&basic_config(), &mut errs);
        assert!(
            errs.is_empty(),
            "default cluster must produce no errors: {errs:?}"
        );
        assert!(validate(&basic_config(), now()).is_ok());
    }

    #[test]
    fn cluster_enabled_without_token_hash_errors() {
        let mut c = ConfigV1::test_scaffold();
        c.cluster.enabled = true;
        c.cluster.token_hash = None;
        let mut errs = Vec::new();
        check_cluster(&c, &mut errs);
        assert_eq!(errs.len(), 1);
        assert!(errs[0].to_string().contains("token_hash"));
    }

    #[test]
    fn cluster_enabled_with_blank_token_hash_errors() {
        let mut c = ConfigV1::test_scaffold();
        c.cluster.enabled = true;
        c.cluster.token_hash = Some("   ".into());
        let mut errs = Vec::new();
        check_cluster(&c, &mut errs);
        assert_eq!(errs.len(), 1);
    }

    #[test]
    fn cluster_enabled_with_token_hash_ok() {
        let mut c = ConfigV1::test_scaffold();
        c.cluster.enabled = true;
        c.cluster.token_hash = Some("a".repeat(64));
        let mut errs = Vec::new();
        check_cluster(&c, &mut errs);
        assert!(errs.is_empty(), "{errs:?}");
    }

    #[test]
    fn cluster_secondary_without_peer_errors() {
        let mut c = ConfigV1::test_scaffold();
        c.cluster.role = ClusterRole::Secondary;
        c.cluster.peer = None;
        let mut errs = Vec::new();
        check_cluster(&c, &mut errs);
        assert_eq!(errs.len(), 1);
        assert!(errs[0].to_string().contains("peer"));
    }

    #[test]
    fn cluster_secondary_with_peer_ok() {
        let mut c = ConfigV1::test_scaffold();
        c.cluster.role = ClusterRole::Secondary;
        c.cluster.peer = Some("https://192.0.2.10:8053".into());
        let mut errs = Vec::new();
        check_cluster(&c, &mut errs);
        assert!(errs.is_empty(), "{errs:?}");
    }

    #[test]
    fn cluster_invalid_allow_peer_cidr_errors() {
        let mut c = ConfigV1::test_scaffold();
        c.cluster.allow_peer = vec!["not-a-cidr".into(), "192.0.2.0/24".into()];
        let mut errs = Vec::new();
        check_cluster(&c, &mut errs);
        assert_eq!(errs.len(), 1, "only the bad entry errors: {errs:?}");
        assert!(errs[0].to_string().contains("not-a-cidr"));
    }

    #[test]
    fn cluster_valid_secondary_config_validates() {
        // A complete, enabled secondary passes the full validator.
        let mut c = basic_config();
        c.cluster.enabled = true;
        c.cluster.role = ClusterRole::Secondary;
        c.cluster.peer = Some("https://192.0.2.10:8053".into());
        c.cluster.token_hash = Some("b".repeat(64));
        c.cluster.allow_peer = vec!["192.0.2.10/32".into()];
        assert!(validate(&c, now()).is_ok(), "{:?}", validate(&c, now()));
    }

    #[test]
    fn cluster_secondary_plaintext_offbox_peer_errors() {
        // poll-02 / schema-validator-12: a plaintext http:// peer off loopback
        // would leak the bearer token; rejected at lint.
        let mut c = ConfigV1::test_scaffold();
        c.cluster.role = ClusterRole::Secondary;
        c.cluster.peer = Some("http://192.0.2.10:8053".into());
        let mut errs = Vec::new();
        check_cluster(&c, &mut errs);
        assert_eq!(errs.len(), 1, "{errs:?}");
        assert!(errs[0].to_string().contains("peer"));
        // A loopback http:// peer (the CT-smoke rig) is still accepted.
        let mut c2 = ConfigV1::test_scaffold();
        c2.cluster.role = ClusterRole::Secondary;
        c2.cluster.peer = Some("http://127.0.0.1:18080".into());
        let mut errs2 = Vec::new();
        check_cluster(&c2, &mut errs2);
        assert!(errs2.is_empty(), "loopback http peer must pass: {errs2:?}");
    }

    #[test]
    fn cluster_zero_poll_interval_when_enabled_errors() {
        // poll-03: 0 would panic the secondary ticker (panic = "abort").
        let mut c = ConfigV1::test_scaffold();
        c.cluster.enabled = true;
        c.cluster.token_hash = Some("a".repeat(64));
        c.cluster.poll_interval_secs = 0;
        let mut errs = Vec::new();
        check_cluster(&c, &mut errs);
        assert_eq!(errs.len(), 1, "{errs:?}");
        assert!(errs[0].to_string().contains("poll_interval_secs"));
    }

    // ── §5.3: a secondary's master carries no policy ──────

    /// A secondary's master carries no policy by design (§5.3), so the
    /// policy-COMPLETENESS checks must not refuse it before its first
    /// bundle arrives. Without this, a joined secondary produces a master
    /// that cannot boot, so the node never polls, so the bundle that would
    /// supply `[upstream]` never arrives.
    ///
    /// Deliberately NOT a blanket exemption: see the three siblings below.
    #[test]
    fn a_policy_free_secondary_master_validates_before_its_first_sync() {
        let mut c = ConfigV1::test_scaffold();
        c.upstream.servers.clear();
        c.cluster.enabled = true;
        c.cluster.role = ClusterRole::Secondary;
        c.cluster.peer = Some("https://192.0.2.10:8053".into());
        c.cluster.token_hash = Some("00".repeat(32));

        validate(&c, now())
            .expect("a policy-free secondary master must load; the bundle brings the policy");
    }

    /// The exemption is scoped to ABSENCE, not to correctness. A secondary
    /// whose upstream is present but malformed still fails.
    ///
    /// Green today; it goes red against a guard placed around the
    /// `check_server_list` CALL rather than around the emptiness, because
    /// that one function does emptiness AND the per-entry shape parse.
    #[test]
    fn the_secondary_exemption_does_not_excuse_a_malformed_upstream() {
        let mut c = ConfigV1::test_scaffold();
        c.upstream.servers = vec!["not a resolver at all".into()];
        c.cluster.enabled = true;
        c.cluster.role = ClusterRole::Secondary;
        c.cluster.peer = Some("https://192.0.2.10:8053".into());
        c.cluster.token_hash = Some("00".repeat(32));

        assert!(
            validate(&c, now()).is_err(),
            "absence is excused on a secondary; malformed policy is not"
        );
    }

    /// The exemption covers `upstream.servers` and NOTHING ELSE.
    /// `[upstream.fallback]` is opt-in: an operator who writes it asked for
    /// a fallback, and one with no resolver can never take over — its
    /// absence is not the pre-first-sync state the exemption exists for.
    ///
    /// This is the test that catches an implementer guarding
    /// `check_upstream_servers` at FUNCTION level instead of at its first
    /// `check_server_list` call. A grep for the predicate cannot see that
    /// mistake: it would still appear only in this file.
    #[test]
    fn the_secondary_exemption_does_not_cover_an_empty_upstream_fallback() {
        let mut c = ConfigV1::test_scaffold();
        c.upstream.servers.clear();
        c.upstream.fallback = Some(crate::config::settings::FallbackConfig {
            mode: c.upstream.mode,
            servers: Vec::new(),
        });
        c.cluster.enabled = true;
        c.cluster.role = ClusterRole::Secondary;
        c.cluster.peer = Some("https://192.0.2.10:8053".into());
        c.cluster.token_hash = Some("00".repeat(32));

        let errs = validate(&c, now())
            .expect_err("an explicitly-written fallback must still be complete on a secondary");
        assert!(
            errs.iter()
                .any(|e| e.to_string().contains("upstream.fallback")),
            "the fallback must be the thing refused, not something else: {errs:?}"
        );
    }

    /// And it is scoped to secondaries. A PRIMARY with no upstream is the
    /// neutrality-03 refusal and must stay refused — warden still does not
    /// choose a resolver for anyone.
    #[test]
    fn a_primary_with_no_upstream_is_still_refused() {
        let mut c = ConfigV1::test_scaffold();
        c.upstream.servers.clear();
        c.cluster.enabled = true;
        c.cluster.role = ClusterRole::Primary;
        c.cluster.token_hash = Some("00".repeat(32));

        let errs = validate(&c, now()).expect_err("warden does not choose a resolver for anyone");
        assert!(
            errs.iter()
                .any(|e| e.to_string().contains("must list at least one resolver")),
            "the upstream emptiness must be the refusal: {errs:?}"
        );
    }

    /// Cluster-disabled is not a secondary. A node that has scaffolded
    /// `role = "secondary"` but not yet joined is NOT syncing, so nothing
    /// will bring it an upstream; exempting it would produce a config that
    /// loads and a daemon that resolves nothing.
    #[test]
    fn an_unjoined_secondary_gets_no_exemption() {
        let mut c = ConfigV1::test_scaffold();
        c.upstream.servers.clear();
        c.cluster.enabled = false;
        c.cluster.role = ClusterRole::Secondary;
        c.cluster.peer = Some("https://192.0.2.10:8053".into());

        assert!(
            validate(&c, now()).is_err(),
            "an unjoined secondary is not a bootable node"
        );
    }

    // ── [api] (rev-2606 §07) ──────────────────────────────

    #[test]
    fn api_disabled_section_inert_ok() {
        // Mirrors `[cluster]`: a disabled section is never validated, so
        // a half-written `[api]` block can sit in the config harmlessly.
        let mut c = ConfigV1::test_scaffold();
        c.api.enabled = false;
        c.api.listen = "0.0.0.0:8053".parse().unwrap();
        c.api.token_hash = None;
        c.api.tls_cert = Some("/etc/warden/api.crt".into());
        c.api.tls_key = None;
        let mut errs = Vec::new();
        check_api(&c, &mut errs, &mut AuditWarnings::emitting());
        assert!(errs.is_empty(), "disabled [api] must be inert: {errs:?}");
    }

    #[test]
    fn api_enabled_without_token_hash_errors() {
        let mut c = ConfigV1::test_scaffold();
        c.api.enabled = true;
        c.api.token_hash = None;
        let mut errs = Vec::new();
        check_api(&c, &mut errs, &mut AuditWarnings::emitting());
        assert_eq!(errs.len(), 1, "{errs:?}");
        assert!(errs[0].to_string().contains("token_hash"));
    }

    #[test]
    fn api_enabled_with_blank_token_hash_errors() {
        let mut c = ConfigV1::test_scaffold();
        c.api.enabled = true;
        c.api.token_hash = Some("   ".into());
        let mut errs = Vec::new();
        check_api(&c, &mut errs, &mut AuditWarnings::emitting());
        assert_eq!(errs.len(), 1, "{errs:?}");
    }

    #[test]
    fn api_enabled_with_token_loopback_ok() {
        // Default listen is 127.0.0.1:8053 — plain HTTP on loopback is fine.
        let mut c = ConfigV1::test_scaffold();
        c.api.enabled = true;
        c.api.token_hash = Some("a".repeat(64));
        let mut errs = Vec::new();
        check_api(&c, &mut errs, &mut AuditWarnings::emitting());
        assert!(errs.is_empty(), "{errs:?}");
    }

    #[test]
    fn api_enabled_nonloopback_without_tls_errors() {
        // api-auth-07-01: cleartext bearer tokens off-host are refused.
        // 0.0.0.0 (unspecified) counts as non-loopback.
        for listen in ["10.0.0.1:8053", "0.0.0.0:8053", "[::]:8053"] {
            let mut c = ConfigV1::test_scaffold();
            c.api.enabled = true;
            c.api.token_hash = Some("a".repeat(64));
            c.api.listen = listen.parse().unwrap();
            let mut errs = Vec::new();
            check_api(&c, &mut errs, &mut AuditWarnings::emitting());
            assert_eq!(errs.len(), 1, "listen {listen}: {errs:?}");
            assert!(errs[0].to_string().contains("non-loopback"));
        }
    }

    #[test]
    fn api_enabled_nonloopback_with_tls_ok() {
        let mut c = ConfigV1::test_scaffold();
        c.api.enabled = true;
        c.api.token_hash = Some("a".repeat(64));
        c.api.listen = "10.0.0.1:8053".parse().unwrap();
        c.api.tls_cert = Some("/etc/warden/api.crt".into());
        c.api.tls_key = Some("/etc/warden/api.key".into());
        let mut errs = Vec::new();
        check_api(&c, &mut errs, &mut AuditWarnings::emitting());
        assert!(errs.is_empty(), "{errs:?}");
    }

    #[test]
    fn api_metrics_on_public_warns_not_errors() {
        // rev-2606 §07 addendum: `metrics_enabled` + non-loopback (with TLS set,
        // so the cleartext rule passes) is a posture WARN, not a hard error —
        // `check_api` must still validate clean. The warn is an audit-log
        // side-effect (like cidr-02); here we pin that it does NOT block boot.
        let mut c = ConfigV1::test_scaffold();
        c.api.enabled = true;
        c.api.token_hash = Some("a".repeat(64));
        c.api.metrics_enabled = true;
        c.api.listen = "10.0.0.1:8053".parse().unwrap();
        c.api.tls_cert = Some("/etc/warden/api.crt".into());
        c.api.tls_key = Some("/etc/warden/api.key".into());
        let mut errs = Vec::new();
        check_api(&c, &mut errs, &mut AuditWarnings::emitting());
        assert!(
            errs.is_empty(),
            "metrics on a public TLS bind must WARN, not refuse: {errs:?}"
        );
    }

    #[test]
    fn api_tls_half_pair_errors_either_direction() {
        // A half pair silently degrades to plain HTTP — rejected even on
        // loopback (the operator clearly intended TLS).
        for (cert, key, missing) in [
            (Some("/etc/warden/api.crt"), None, "tls_key"),
            (None, Some("/etc/warden/api.key"), "tls_cert"),
        ] {
            let mut c = ConfigV1::test_scaffold();
            c.api.enabled = true;
            c.api.token_hash = Some("a".repeat(64));
            c.api.tls_cert = cert.map(Into::into);
            c.api.tls_key = key.map(Into::into);
            let mut errs = Vec::new();
            check_api(&c, &mut errs, &mut AuditWarnings::emitting());
            assert_eq!(errs.len(), 1, "missing {missing}: {errs:?}");
            assert!(errs[0].to_string().contains("set together"));
        }
    }

    #[test]
    fn api_enabled_valid_config_validates() {
        // Full-validator integration: a complete, enabled [api] passes.
        let mut c = basic_config();
        c.api.enabled = true;
        c.api.token_hash = Some("c".repeat(64));
        assert!(validate(&c, now()).is_ok(), "{:?}", validate(&c, now()));
    }

    #[test]
    fn api_enabled_no_token_fails_full_validate() {
        // The rule is wired into `validate()`, not just unit-reachable.
        let mut c = basic_config();
        c.api.enabled = true;
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| matches!(e, ConfigError::MissingRequired(_))
                    && e.to_string().contains("api"))
        );
    }

    // ── schema_version ────────────────────────────────────

    #[test]
    fn schema_version_0_rejected() {
        let mut c = basic_config();
        c.schema_version = 0;
        let errs = validate(&c, now()).unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, ConfigError::VersionMismatch(_))));
    }

    #[test]
    fn schema_version_1_rejected() {
        // Sprint A of `lists_categories_v2` bumped SCHEMA_VERSION_V1
        // from 1 to 2 (Q4 + D15). The validator now refuses configs
        // declaring `schema_version = 1` — operators run
        // `warden migrate` to upgrade.
        let mut c = basic_config();
        c.schema_version = 1;
        let errs = validate(&c, now()).unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, ConfigError::VersionMismatch(_))));
    }

    // ── duplicate id per entity kind ─────────────────────

    #[test]
    fn duplicate_blocklist_id_rejected() {
        let mut c = basic_config();
        c.blocklists.push(blocklist("privacy-ads"));
        let errs = validate(&c, now()).unwrap_err();
        assert!(errs.iter().any(
            |e| matches!(e, ConfigError::DuplicateId(ctx) if ctx.reason.contains("privacy-ads"))
        ));
    }

    #[test]
    fn duplicate_device_id_rejected() {
        let mut c = basic_config();
        c.devices
            .push(device("iphone", "10.0.0.1", Some("default")));
        c.devices
            .push(device("iphone", "10.0.0.2", Some("default")));
        let errs = validate(&c, now()).unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, ConfigError::DuplicateId(_))));
    }

    // ── cross-ref misses ──────────────────────────────────

    #[test]
    fn device_referencing_unknown_profile_rejected() {
        let mut c = basic_config();
        c.devices.push(device("iphone", "10.0.0.1", Some("ghost")));
        let errs = validate(&c, now()).unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, ConfigError::CrossRefMiss(ctx) if ctx.reason.contains("ghost"))));
    }

    // Sprint B T2 (rewireato — drop with justification): the pre-v2
    // `profile_referencing_unknown_blocklist_rejected` test pinned the
    // dangling-id refusal on `profile.blocklists`. That field is gone in
    // v2 and the tag-intersection model has no structural equivalent —
    // a tag that no list happens to carry is harmless and surfaces, if
    // anything, as the §5.4 row 2 reload-time WARN
    // (`PROFILE_CONTRIBUTES_NO_TAGS`) handled in T3. Sibling cross-ref
    // checks (`group_referencing_unknown_device_rejected`,
    // `subnet_referencing_unknown_profile_rejected`, etc.) preserve
    // CrossRef coverage on every other entity.

    #[test]
    fn group_referencing_unknown_device_rejected() {
        let mut c = basic_config();
        c.groups.push(group("family", "default", 0, &["iphone"]));
        let errs = validate(&c, now()).unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, ConfigError::CrossRefMiss(_))));
    }

    #[test]
    fn subnet_referencing_unknown_profile_rejected() {
        let mut c = basic_config();
        c.subnets.push(Subnet {
            id: Id::new("vlan").unwrap(),
            display_name: "VLAN".into(),
            cidrs: vec!["10.0.0.0/8".into()],
            profile: Id::new("ghost").unwrap(),
            priority: 0,
        });
        let errs = validate(&c, now()).unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, ConfigError::CrossRefMiss(_))));
    }

    // ── rev-2606 schema-validator-08: duplicate subnet CIDRs ──────

    fn test_subnet(id: &str, cidr: &str, profile: &str, priority: i32) -> Subnet {
        Subnet {
            id: Id::new(id).unwrap(),
            display_name: id.into(),
            cidrs: vec![cidr.into()],
            profile: Id::new(profile).unwrap(),
            priority,
        }
    }

    #[test]
    fn duplicate_cidr_equal_priority_different_profiles_rejected() {
        let mut c = basic_config();
        c.profiles.insert("strict".into(), profile_default());
        c.subnets
            .push(test_subnet("lan-a", "10.0.0.0/24", "default", 10));
        c.subnets
            .push(test_subnet("lan-b", "10.0.0.0/24", "strict", 10));
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            errs.iter().any(|e| matches!(
                e,
                ConfigError::ValidationFailed(ctx)
                    if ctx.reason.contains("declared by multiple subnets")
                       && ctx.reason.contains("lan-a")
                       && ctx.reason.contains("lan-b")
            )),
            "ambiguous duplicate CIDR must be rejected: {errs:?}"
        );
    }

    #[test]
    fn duplicate_cidr_normalized_before_compare() {
        // Host bits are masked by Cidr::parse — different spellings of
        // the same network still collide.
        let mut c = basic_config();
        c.profiles.insert("strict".into(), profile_default());
        c.subnets
            .push(test_subnet("lan-a", "10.0.0.0/24", "default", 0));
        c.subnets
            .push(test_subnet("lan-b", "10.0.0.99/24", "strict", 0));
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            errs.iter().any(|e| matches!(
                e,
                ConfigError::ValidationFailed(ctx)
                    if ctx.reason.contains("declared by multiple subnets")
            )),
            "normalized-equal CIDRs must collide: {errs:?}"
        );
    }

    #[test]
    fn duplicate_cidr_distinct_priorities_accepted() {
        // Deliberate overlay: higher priority deterministically wins.
        let mut c = basic_config();
        c.profiles.insert("strict".into(), profile_default());
        c.subnets
            .push(test_subnet("lan-a", "10.0.0.0/24", "default", 10));
        c.subnets
            .push(test_subnet("lan-b", "10.0.0.0/24", "strict", 20));
        assert!(validate(&c, now()).is_ok());
    }

    #[test]
    fn duplicate_cidr_same_profile_accepted() {
        // Harmless redundancy — no ambiguity to resolve.
        let mut c = basic_config();
        c.subnets
            .push(test_subnet("lan-a", "10.0.0.0/24", "default", 10));
        c.subnets
            .push(test_subnet("lan-b", "10.0.0.0/24", "default", 10));
        assert!(validate(&c, now()).is_ok());
    }

    // ── rev-2606 schema-validator-11: display_name / free-text bounds ──

    #[test]
    fn empty_display_name_rejected_per_entity() {
        // Device / Group / Subnet / Schedule require a non-blank
        // display_name (the blocklist arm predates this and keeps its
        // own frozen message).
        let mut c = basic_config();
        let mut d = device("phone", "10.0.0.1", Some("default"));
        d.display_name = "   ".into();
        c.devices.push(d);
        let mut g = group("iot", "default", 0, &[]);
        g.display_name = String::new();
        c.groups.push(g);
        let errs = validate(&c, now()).unwrap_err();
        for entity in ["devices.phone", "groups.iot"] {
            assert!(
                errs.iter().any(|e| matches!(
                    e,
                    ConfigError::MissingRequired(ctx)
                        if ctx.entity.as_deref() == Some(entity)
                           && ctx.reason.contains("display_name")
                )),
                "missing empty-display_name error for {entity}: {errs:?}"
            );
        }
    }

    #[test]
    fn empty_profile_display_name_accepted() {
        // Profile.display_name has #[serde(default)] — an omitted field
        // deserialises to "" and must stay legal.
        let mut c = basic_config();
        let mut p = profile_default();
        p.display_name = String::new();
        c.profiles.insert("bare".into(), p);
        assert!(validate(&c, now()).is_ok());
    }

    #[test]
    fn oversized_display_name_rejected() {
        let mut c = basic_config();
        let mut d = device("phone", "10.0.0.1", Some("default"));
        d.display_name = "x".repeat(129);
        c.devices.push(d);
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            errs.iter().any(|e| matches!(
                e,
                ConfigError::ValidationFailed(ctx)
                    if ctx.entity.as_deref() == Some("devices.phone")
                       && ctx.reason.contains("129 bytes (max 128)")
            )),
            "{errs:?}"
        );
    }

    #[test]
    fn control_chars_in_display_name_rejected() {
        // ANSI escape into a TUI row / journal line = terminal
        // injection surface.
        let mut c = basic_config();
        let mut d = device("phone", "10.0.0.1", Some("default"));
        d.display_name = "evil\x1b[2Jname".into();
        c.devices.push(d);
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            errs.iter().any(|e| matches!(
                e,
                ConfigError::ValidationFailed(ctx)
                    if ctx.entity.as_deref() == Some("devices.phone")
                       && ctx.reason.contains("control character")
            )),
            "{errs:?}"
        );
    }

    #[test]
    fn device_free_text_bounds_enforced() {
        let mut c = basic_config();
        let mut d = device("phone", "10.0.0.1", Some("default"));
        d.notes = Some("n".repeat(1025));
        d.owner = Some("ed\nwardo".into());
        c.devices.push(d);
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            errs.iter().any(|e| matches!(
                e,
                ConfigError::ValidationFailed(ctx)
                    if ctx.reason.contains("notes") && ctx.reason.contains("max 1024")
            )),
            "oversized notes must be rejected: {errs:?}"
        );
        assert!(
            errs.iter().any(|e| matches!(
                e,
                ConfigError::ValidationFailed(ctx)
                    if ctx.reason.contains("owner") && ctx.reason.contains("control character")
            )),
            "newline in owner must be rejected: {errs:?}"
        );
        // Absent / sane free-text stays legal.
        let mut ok = basic_config();
        let mut d2 = device("tab", "10.0.0.2", Some("default"));
        d2.notes = Some("bought 2024, lives in the kitchen".into());
        ok.devices.push(d2);
        assert!(validate(&ok, now()).is_ok());
    }

    #[test]
    fn schedule_device_target_checked_against_devices_only() {
        let mut c = basic_config();
        // A group called `kids` exists — schedule with target_type=device
        // must still reject because there is no DEVICE called kids.
        c.groups.push(group("kids", "default", 0, &[]));
        c.schedules.push(Schedule {
            id: Id::new("focus").unwrap(),
            display_name: "focus".into(),
            target_type: ScheduleTargetType::Device,
            target_id: Id::new("kids").unwrap(),
            profile: Id::new("default").unwrap(),
            days: vec!["all".into()],
            hours: "22:00-06:00".into(),
            expires_at: None,
        });
        let errs = validate(&c, now()).unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, ConfigError::CrossRefMiss(ctx) if ctx.reason.contains("kids"))));
    }

    // ── schedule semantics ────────────────────────────────

    #[test]
    fn schedule_invalid_days_rejected() {
        let mut c = basic_config();
        c.devices.push(device("edo", "10.0.0.1", Some("default")));
        c.schedules.push(Schedule {
            id: Id::new("x").unwrap(),
            display_name: "x".into(),
            target_type: ScheduleTargetType::Device,
            target_id: Id::new("edo").unwrap(),
            profile: Id::new("default").unwrap(),
            days: vec!["baday".into()],
            hours: "09:00-17:00".into(),
            expires_at: None,
        });
        let errs = validate(&c, now()).unwrap_err();
        assert!(errs.iter().any(
            |e| matches!(e, ConfigError::ValidationFailed(ctx) if ctx.reason.contains("days"))
        ));
    }

    #[test]
    fn schedule_invalid_hours_rejected() {
        let mut c = basic_config();
        c.devices.push(device("edo", "10.0.0.1", Some("default")));
        c.schedules.push(Schedule {
            id: Id::new("x").unwrap(),
            display_name: "x".into(),
            target_type: ScheduleTargetType::Device,
            target_id: Id::new("edo").unwrap(),
            profile: Id::new("default").unwrap(),
            days: vec!["all".into()],
            hours: "bad".into(),
            expires_at: None,
        });
        let errs = validate(&c, now()).unwrap_err();
        assert!(errs.iter().any(
            |e| matches!(e, ConfigError::ValidationFailed(ctx) if ctx.reason.contains("hours"))
        ));
    }

    #[test]
    fn schedule_past_expiry_accepted_as_inert() {
        // rev-2606 schema-validator-01 regression: an expired one-shot
        // schedule on disk must NOT fail validation — the old hard error
        // bricked boot, reload, and every CLI mutation the moment a
        // `warden device quiet` window lapsed. The row is inert at
        // resolver build and gets pruned; validation only WARNs.
        let mut c = basic_config();
        c.devices.push(device("edo", "10.0.0.1", Some("default")));
        c.schedules.push(Schedule {
            id: Id::new("x").unwrap(),
            display_name: "x".into(),
            target_type: ScheduleTargetType::Device,
            target_id: Id::new("edo").unwrap(),
            profile: Id::new("default").unwrap(),
            days: vec!["all".into()],
            hours: "22:00-06:00".into(),
            expires_at: Some(datetime!(2020-01-01 00:00:00 UTC)),
        });
        validate(&c, now()).expect("expired schedule must not fail validation");
    }

    #[test]
    fn schedule_future_expiry_accepted() {
        let mut c = basic_config();
        c.devices.push(device("edo", "10.0.0.1", Some("default")));
        c.schedules.push(Schedule {
            id: Id::new("x").unwrap(),
            display_name: "x".into(),
            target_type: ScheduleTargetType::Device,
            target_id: Id::new("edo").unwrap(),
            profile: Id::new("default").unwrap(),
            days: vec!["all".into()],
            hours: "22:00-06:00".into(),
            expires_at: Some(datetime!(2999-01-01 00:00:00 UTC)),
        });
        validate(&c, now()).expect("future expiry is a valid one-shot schedule");
    }

    #[test]
    fn schedule_all_day_midnight_form_accepted() {
        // rev-2606 devices-01: `00:00-00:00` is the engine's canonical
        // always-on window (res-13 carve-out in ParsedSchedule::parse_v1)
        // and what `warden device quiet` writes — the validator must
        // mirror the engine, not reject the one form that has no
        // end-exclusivity hole.
        let mut c = basic_config();
        c.devices.push(device("edo", "10.0.0.1", Some("default")));
        c.schedules.push(Schedule {
            id: Id::new("x").unwrap(),
            display_name: "x".into(),
            target_type: ScheduleTargetType::Device,
            target_id: Id::new("edo").unwrap(),
            profile: Id::new("default").unwrap(),
            days: vec!["all".into()],
            hours: "00:00-00:00".into(),
            expires_at: None,
        });
        validate(&c, now()).expect("00:00-00:00 is the canonical all-day form");
    }

    #[test]
    fn schedule_other_equal_start_end_rejected_with_all_day_hint() {
        let mut c = basic_config();
        c.devices.push(device("edo", "10.0.0.1", Some("default")));
        c.schedules.push(Schedule {
            id: Id::new("x").unwrap(),
            display_name: "x".into(),
            target_type: ScheduleTargetType::Device,
            target_id: Id::new("edo").unwrap(),
            profile: Id::new("default").unwrap(),
            days: vec!["all".into()],
            hours: "09:00-09:00".into(),
            expires_at: None,
        });
        let errs = validate(&c, now()).unwrap_err();
        assert!(errs.iter().any(|e| matches!(
            e,
            ConfigError::ValidationFailed(ctx)
                if ctx.reason.contains("start and end are equal")
                    && ctx.reason.contains("00:00-00:00")
        )));
    }

    // ── server.default_profile ────────────────────────────

    #[test]
    fn server_default_profile_unknown_rejected() {
        let mut c = basic_config();
        c.server.default_profile = Some(Id::new("ghost").unwrap());
        let errs = validate(&c, now()).unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, ConfigError::CrossRefMiss(_))));
    }

    // ── retired-id policy (N8) ────────────────────────────

    #[test]
    fn retired_id_reuse_within_window_blocked() {
        let mut c = basic_config();
        c.retired.push(RetiredEntry {
            id: Id::new("privacy-ads").unwrap(),
            entity_type: RetiredType::Blocklist,
            retired_at: datetime!(2026-04-01 00:00:00 UTC),
        });
        let errs = validate(&c, now()).unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, ConfigError::IdRecentlyRetired(_))));
    }

    #[test]
    fn retired_id_reuse_past_window_allowed() {
        let mut c = basic_config();
        c.retired.push(RetiredEntry {
            id: Id::new("privacy-ads").unwrap(),
            entity_type: RetiredType::Blocklist,
            // 120 days ago at `now()` = before the 90-day window.
            retired_at: datetime!(2025-12-01 00:00:00 UTC),
        });
        assert!(validate(&c, now()).is_ok());
    }

    #[test]
    fn retired_id_different_type_is_independent() {
        // Retiring a `device` named "default" does NOT block a profile
        // called "default" — the quarantine is per-entity-type.
        let mut c = basic_config();
        c.retired.push(RetiredEntry {
            id: Id::new("default").unwrap(),
            entity_type: RetiredType::Device,
            retired_at: datetime!(2026-04-01 00:00:00 UTC),
        });
        assert!(validate(&c, now()).is_ok());
    }

    // ── DM2 group priority conflicts ──────────────────────

    #[test]
    fn ambiguous_group_priority_rejected() {
        let mut c = basic_config();
        c.profiles.insert("strict".into(), profile_default());
        c.profiles.insert("lenient".into(), profile_default());
        c.devices.push(device("edo", "10.0.0.1", None));
        c.groups.push(group("a", "strict", 10, &["edo"]));
        c.groups.push(group("b", "lenient", 10, &["edo"]));
        let errs = validate(&c, now()).unwrap_err();
        assert!(errs.iter().any(|e| matches!(e, ConfigError::ValidationFailed(ctx) if ctx.reason.contains("same priority"))));
    }

    #[test]
    fn clear_priority_winner_accepted() {
        let mut c = basic_config();
        c.profiles.insert("strict".into(), profile_default());
        c.profiles.insert("lenient".into(), profile_default());
        c.devices.push(device("edo", "10.0.0.1", None));
        c.groups.push(group("a", "strict", 20, &["edo"]));
        c.groups.push(group("b", "lenient", 10, &["edo"]));
        assert!(validate(&c, now()).is_ok());
    }

    #[test]
    fn ambiguous_priority_via_device_side_groups_rejected() {
        // rev-2606 schema-validator-04: the primary CLI join path writes
        // `[[devices]].groups`, which this check used to be blind to —
        // the exact conflict below linted clean and the resolver
        // tie-broke by id silently.
        let mut c = basic_config();
        c.profiles.insert("strict".into(), profile_default());
        c.profiles.insert("lenient".into(), profile_default());
        let mut d = device("edo", "10.0.0.1", None);
        d.groups = vec![Id::new("a").unwrap(), Id::new("b").unwrap()];
        c.devices.push(d);
        c.groups.push(group("a", "strict", 10, &[]));
        c.groups.push(group("b", "lenient", 10, &[]));
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            errs.iter().any(|e| matches!(
                e,
                ConfigError::ValidationFailed(ctx)
                    if ctx.reason.contains("same priority")
                       && ctx.entity.as_deref() == Some("devices.edo")
            )),
            "device-side membership conflict must be caught: {errs:?}"
        );
    }

    #[test]
    fn ambiguous_priority_via_mixed_directions_rejected() {
        // One membership group-side, the other device-side — the union
        // must see both.
        let mut c = basic_config();
        c.profiles.insert("strict".into(), profile_default());
        c.profiles.insert("lenient".into(), profile_default());
        let mut d = device("edo", "10.0.0.1", None);
        d.groups = vec![Id::new("b").unwrap()];
        c.devices.push(d);
        c.groups.push(group("a", "strict", 10, &["edo"]));
        c.groups.push(group("b", "lenient", 10, &[]));
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            errs.iter().any(|e| matches!(
                e,
                ConfigError::ValidationFailed(ctx) if ctx.reason.contains("same priority")
            )),
            "mixed-direction conflict must be caught: {errs:?}"
        );
    }

    #[test]
    fn symmetric_membership_not_double_counted() {
        // A device listed in `g.devices` AND carrying the same group in
        // `d.groups` is ONE membership — no self-conflict, and a clean
        // config stays clean.
        let mut c = basic_config();
        c.profiles.insert("strict".into(), profile_default());
        let mut d = device("edo", "10.0.0.1", None);
        d.groups = vec![Id::new("a").unwrap()];
        c.devices.push(d);
        c.groups.push(group("a", "strict", 10, &["edo"]));
        assert!(validate(&c, now()).is_ok());
    }

    // ── rev-2606 schema-validator-07/-09 — WITHDRAWN at the plp cutover ──
    //
    // `typo_tagged_config_still_validates_ok` and its `slug()` helper lived
    // here. The test built a config whose tags all missed and asserted
    // `validate(...).is_ok()` — the WARN-only posture of the intersection
    // diagnostics. Those diagnostics are gone, and `is_ok()` was true before
    // they existed and stays true after: it never distinguished the emitting
    // build from the silent one. Removed rather than left green, because a
    // suite that keeps such a test reads as coverage of a rule nothing
    // enforces.
    //
    // What the rule became is `PROFILE_FILTERS_NO_LISTS`, asserted
    // positively — with a control arm — in
    // `a_profile_that_ignores_every_list_is_warned_about`.

    #[test]
    fn dangling_device_side_group_ref_no_panic_in_conflict_check() {
        // A dangling gid in `d.groups` is a CrossRefMiss from
        // check_devices; the conflict check must skip it, not panic.
        let mut c = basic_config();
        let mut d = device("edo", "10.0.0.1", None);
        d.groups = vec![Id::new("ghost-group").unwrap()];
        c.devices.push(d);
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| matches!(e, ConfigError::CrossRefMiss(_))),
            "dangling group ref still reported: {errs:?}"
        );
    }

    // ── devices: identity + MAC ──────────────────────────

    #[test]
    fn device_with_no_identity_rejected() {
        let mut c = basic_config();
        c.devices.push(Device {
            id: Id::new("ghost").unwrap(),
            display_name: "ghost".into(),
            ip: None,
            mac: None,
            mac_aliases: vec![],
            profile: None,
            groups: vec![],
            owner: None,
            device_type: None,
            department: None,
            notes: None,
            allow_rules: vec![],
            deny_rules: vec![],
            override_profile_deny: false,
            unfiltered: false,
            network_name: None,
            network_name_wildcard: false,
        });
        let errs = validate(&c, now()).unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, ConfigError::ValidationFailed(ctx) if ctx.reason.contains("no identity"))));
    }

    #[test]
    fn duplicate_ip_rejected() {
        let mut c = basic_config();
        c.devices.push(device("a", "10.0.0.1", Some("default")));
        c.devices.push(device("b", "10.0.0.1", Some("default")));
        let errs = validate(&c, now()).unwrap_err();
        assert!(errs.iter().any(
            |e| matches!(e, ConfigError::ValidationFailed(ctx) if ctx.reason.contains("reuses IP"))
        ));
    }

    #[test]
    fn shared_mac_across_devices_rejected() {
        let mut c = basic_config();
        c.devices.push(Device {
            id: Id::new("a").unwrap(),
            display_name: "A".into(),
            ip: None,
            mac: Some("AA:BB:CC:DD:EE:01".into()),
            mac_aliases: vec![],
            profile: Some(Id::new("default").unwrap()),
            ..device("a", "10.0.0.1", Some("default"))
        });
        c.devices[0].ip = None;
        c.devices.push(Device {
            id: Id::new("b").unwrap(),
            display_name: "B".into(),
            ip: None,
            mac: Some("aa:bb:cc:dd:ee:01".into()),
            mac_aliases: vec![],
            profile: Some(Id::new("default").unwrap()),
            ..device("b", "10.0.0.2", Some("default"))
        });
        c.devices[1].ip = None;
        let errs = validate(&c, now()).unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, ConfigError::ValidationFailed(ctx) if ctx.reason.contains("already owned"))));
    }

    // ── server.default_blocked_ttl_secs sanity ────────────

    #[test]
    fn server_default_ttl_zero_rejected() {
        let mut c = basic_config();
        c.server.default_blocked_ttl_secs = 0;
        let errs = validate(&c, now()).unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, ConfigError::ValidationFailed(ctx) if ctx.reason.contains("default_blocked_ttl_secs"))));
    }

    // ── server.listen × server.allow_from open-resolver gate ──────
    // rev-2606 init-01: the unspecified-bind + empty-ACL combination is
    // an open resolver (the DNS handler accepts ALL sources on an empty
    // ACL). These pins keep the three "the validator already refuses"
    // comments (dns/handler.rs, start.rs ×2) true.

    #[test]
    fn unspecified_bind_with_empty_allow_from_rejected() {
        let mut c = basic_config();
        c.server.listen = "0.0.0.0:53".parse().unwrap();
        c.server.allow_from = vec![];
        let errs = validate(&c, now()).unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, ConfigError::ValidationFailed(ctx) if ctx.reason.contains("open resolver"))));
    }

    #[test]
    fn unspecified_v6_bind_with_empty_allow_from_rejected() {
        let mut c = basic_config();
        c.server.listen = "[::]:53".parse().unwrap();
        c.server.allow_from = vec![];
        let errs = validate(&c, now()).unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, ConfigError::ValidationFailed(ctx) if ctx.reason.contains("open resolver"))));
    }

    /// rev-detect F1, adjacent consequence. `::ffff:0.0.0.0` is the
    /// IPv4-mapped spelling of the wildcard. The kernel binds it as one
    /// — proved by binding it and then receiving a datagram addressed to
    /// a specific host address — but `Ipv6Addr::is_unspecified()` is
    /// false for it, because its octets are not all zero.
    ///
    /// So this exact config used to validate clean: warden answered on
    /// every interface, from every source, with no ACL. An open resolver
    /// is a DNS amplification vector, which makes this the more
    /// dangerous half of the same root cause.
    #[test]
    fn ipv4_mapped_unspecified_bind_with_empty_allow_from_rejected() {
        let mut c = basic_config();
        c.server.listen = "[::ffff:0.0.0.0]:53".parse().unwrap();
        c.server.allow_from = vec![];
        let errs = validate(&c, now()).unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, ConfigError::ValidationFailed(ctx) if ctx.reason.contains("open resolver"))),
            "a mapped-form wildcard binds every interface exactly as 0.0.0.0 does; got {errs:?}");
    }

    /// Control arm: the mapped form of a SPECIFIC address is not a
    /// wildcard and must stay legal with an empty ACL, exactly as its
    /// plain form does. Without this the fix above could be "reject
    /// anything IPv4-mapped", which would break a legitimate bind.
    #[test]
    fn ipv4_mapped_specific_bind_with_empty_allow_from_stays_legal() {
        let mut c = basic_config();
        c.server.listen = "[::ffff:192.0.2.53]:53".parse().unwrap();
        c.server.allow_from = vec![];
        let res = validate(&c, now());
        if let Err(errs) = res {
            assert!(
                !errs.iter().any(|e| matches!(
                    e,
                    ConfigError::ValidationFailed(ctx) if ctx.reason.contains("open resolver")
                )),
                "a pinned address is not an open resolver, mapped or not; got {errs:?}"
            );
        }
    }

    #[test]
    fn unspecified_bind_with_allow_from_accepted() {
        let mut c = basic_config();
        c.server.listen = "0.0.0.0:53".parse().unwrap();
        c.server.allow_from = vec!["192.168.1.0/24".into(), "127.0.0.0/8".into()];
        assert!(validate(&c, now()).is_ok());
    }

    #[test]
    fn unspecified_bind_with_explicit_allow_all_accepted() {
        // Answering everyone is a deliberate opt-in, not a refusal.
        let mut c = basic_config();
        c.server.listen = "0.0.0.0:53".parse().unwrap();
        c.server.allow_from = vec!["0.0.0.0/0".into(), "::/0".into()];
        assert!(validate(&c, now()).is_ok());
    }

    #[test]
    fn loopback_bind_with_empty_allow_from_accepted() {
        let mut c = basic_config();
        c.server.listen = "127.0.0.1:15353".parse().unwrap();
        c.server.allow_from = vec![];
        assert!(validate(&c, now()).is_ok());
    }

    // ── blocklist sanity ──────────────────────────────────

    #[test]
    fn blocklist_missing_scheme_rejected() {
        let mut c = basic_config();
        c.blocklists[0].url = "lists.example.com/a.txt".into();
        let errs = validate(&c, now()).unwrap_err();
        assert!(errs.iter().any(
            |e| matches!(e, ConfigError::ValidationFailed(ctx) if ctx.reason.contains("http://"))
        ));
    }

    #[test]
    fn blocklist_zero_update_interval_rejected() {
        let mut c = basic_config();
        c.blocklists[0].update_interval_hours = 0;
        let errs = validate(&c, now()).unwrap_err();
        assert!(errs
            .iter()
            .any(|e| matches!(e, ConfigError::ValidationFailed(ctx) if ctx.reason.contains("update_interval_hours"))));
    }

    // ── deny_unknown_fields walker ───────────────────────

    #[test]
    fn every_schema_struct_denies_unknown_fields() {
        // We probe each struct by deserialising a TOML payload that is
        // legal for the struct's required fields plus ONE extra field
        // that should not exist. If the struct forgot
        // `#[serde(deny_unknown_fields)]`, the probe succeeds and the
        // test fails with a clear message naming the offender.
        //
        // NOTE: when a new entity is added in a future sprint, remember
        // to extend this list. The cost of forgetting is a typo in a
        // real operator's config being silently ignored.
        let cases: &[(&str, &str)] = &[
            (
                "ConfigV1",
                "schema_version = 3\nextra = true\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
            ),
            (
                "ServerGlobals (inside ConfigV1)",
                "schema_version = 3\n[server]\nextra_field = 1\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
            ),
            (
                "Blocklist",
                "id = \"x\"\ndisplay_name = \"x\"\nurl = \"https://example.com/\"\nextra = 1\n",
            ),
            (
                "Profile",
                "display_name = \"x\"\nextra = 1\n",
            ),
            (
                "Device",
                "id = \"x\"\ndisplay_name = \"x\"\nextra = 1\n",
            ),
            (
                "Group",
                "id = \"x\"\ndisplay_name = \"x\"\nprofile = \"p\"\nextra = 1\n",
            ),
            (
                "Subnet",
                "id = \"x\"\ndisplay_name = \"x\"\ncidrs = [\"10.0.0.0/8\"]\nprofile = \"p\"\nextra = 1\n",
            ),
            (
                "Schedule",
                "id = \"x\"\ndisplay_name = \"x\"\ntarget_type = \"device\"\ntarget_id = \"d\"\nprofile = \"p\"\ndays = [\"all\"]\nhours = \"00:00-23:59\"\nextra = 1\n",
            ),
            (
                "AdminRule",
                "id = \"x\"\nrule = \"||x^\"\nextra = 1\n",
            ),
            (
                "RetiredEntry",
                "id = \"x\"\ntype = \"device\"\nretired_at = \"2026-04-01T00:00:00Z\"\nextra = 1\n",
            ),
        ];

        use super::super::admin_rule::AdminRule as AR;
        use super::super::blocklist::Blocklist as BL;
        use super::super::device::Device as DV;
        use super::super::group::Group as GR;
        use super::super::profile::Profile as PR;
        use super::super::retired::RetiredEntry as RT;
        use super::super::schedule::Schedule as SC;
        use super::super::subnet::Subnet as SN;

        let mut failures: Vec<String> = Vec::new();

        for (name, src) in cases {
            let accepts_unknown = match *name {
                "ConfigV1" => toml::from_str::<ConfigV1>(src).is_ok(),
                "ServerGlobals (inside ConfigV1)" => toml::from_str::<ConfigV1>(src).is_ok(),
                "Blocklist" => toml::from_str::<BL>(src).is_ok(),
                "Profile" => toml::from_str::<PR>(src).is_ok(),
                "Device" => toml::from_str::<DV>(src).is_ok(),
                "Group" => toml::from_str::<GR>(src).is_ok(),
                "Subnet" => toml::from_str::<SN>(src).is_ok(),
                "Schedule" => toml::from_str::<SC>(src).is_ok(),
                "AdminRule" => toml::from_str::<AR>(src).is_ok(),
                "RetiredEntry" => toml::from_str::<RT>(src).is_ok(),
                _ => unreachable!(),
            };
            if accepts_unknown {
                failures.push((*name).to_string());
            }
        }

        assert!(
            failures.is_empty(),
            "these schema structs accept unknown fields (missing #[serde(deny_unknown_fields)]?): {failures:?}"
        );
    }

    // ── Sprint 38 QLP3: [tracking] knobs ─────────────────────

    fn has_entity(errs: &[ConfigError], entity: &str) -> bool {
        errs.iter().any(|e| match e {
            ConfigError::ValidationFailed(ctx) => ctx.entity.as_deref() == Some(entity),
            _ => false,
        })
    }

    #[test]
    fn tracking_config_rejects_retention_days_out_of_range() {
        let mut c = basic_config();
        c.tracking.retention_days = 0;
        let errs = validate(&c, now()).unwrap_err();
        assert!(has_entity(&errs, "tracking.retention_days"));

        c.tracking.retention_days = 366;
        let errs = validate(&c, now()).unwrap_err();
        assert!(has_entity(&errs, "tracking.retention_days"));

        // Valid range endpoints pass.
        for ok in [1u32, 7, 365] {
            c.tracking.retention_days = ok;
            assert!(
                validate(&c, now()).is_ok(),
                "retention_days = {ok} should pass"
            );
        }
    }

    // ── rev-2606 settings-02 — zero intervals abort the daemon ───

    #[test]
    fn tracking_zero_intervals_rejected() {
        let mut c = basic_config();
        c.tracking.top_n_interval_secs = 0;
        let errs = validate(&c, now()).unwrap_err();
        assert!(has_entity(&errs, "tracking.top_n_interval_secs"));

        c.tracking.top_n_interval_secs = 1;
        c.tracking.snapshot_interval_secs = 0;
        let errs = validate(&c, now()).unwrap_err();
        assert!(has_entity(&errs, "tracking.snapshot_interval_secs"));

        c.tracking.snapshot_interval_secs = 1;
        assert!(validate(&c, now()).is_ok(), "1-second intervals are valid");
    }

    #[test]
    fn lists_zero_update_interval_rejected() {
        let mut c = basic_config();
        c.lists.update_interval_secs = 0;
        let errs = validate(&c, now()).unwrap_err();
        assert!(has_entity(&errs, "lists.update_interval_secs"));

        c.lists.update_interval_secs = 1;
        assert!(
            validate(&c, now()).is_ok(),
            "update_interval_secs = 1 is valid"
        );
    }

    #[test]
    fn lists_shrink_guard_pct_out_of_range_rejected() {
        // rev-2606 §06 manager-01: 0 and >100 are misconfigurations.
        let mut c = basic_config();
        for bad in [0u8, 101, 255] {
            c.lists.shrink_guard_max_drop_pct = bad;
            let errs = validate(&c, now()).unwrap_err();
            assert!(
                has_entity(&errs, "lists.shrink_guard_max_drop_pct"),
                "shrink_guard_max_drop_pct = {bad} should be rejected"
            );
        }
        for ok in [1u8, 90, 100] {
            c.lists.shrink_guard_max_drop_pct = ok;
            assert!(
                validate(&c, now()).is_ok(),
                "shrink_guard_max_drop_pct = {ok} is valid"
            );
        }
    }

    // ── rev-2606 config-01 / settings-12 — [security] scalars ────

    #[test]
    fn security_rrl_zero_rps_rejected() {
        let mut c = basic_config();
        c.security.rrl.responses_per_second = 0;
        let errs = validate(&c, now()).unwrap_err();
        assert!(has_entity(&errs, "security.rrl.responses_per_second"));

        c.security.rrl.responses_per_second = 1;
        assert!(validate(&c, now()).is_ok());
    }

    #[test]
    fn security_rrl_window_out_of_range_rejected() {
        let mut c = basic_config();
        for bad in [0u64, 86_401, (u32::MAX as u64) + 16] {
            c.security.rrl.window_secs = bad;
            let errs = validate(&c, now()).unwrap_err();
            assert!(
                has_entity(&errs, "security.rrl.window_secs"),
                "window_secs = {bad} should be rejected"
            );
        }
        for ok in [1u64, 15, 86_400] {
            c.security.rrl.window_secs = ok;
            assert!(validate(&c, now()).is_ok(), "window_secs = {ok} is valid");
        }
    }

    #[test]
    fn security_rate_limit_zeroes_rejected() {
        let mut c = basic_config();
        c.security.rate_limit.queries_per_second = 0;
        let errs = validate(&c, now()).unwrap_err();
        assert!(has_entity(&errs, "security.rate_limit.queries_per_second"));

        c.security.rate_limit.queries_per_second = 1;
        c.security.rate_limit.burst = 0;
        let errs = validate(&c, now()).unwrap_err();
        assert!(has_entity(&errs, "security.rate_limit.burst"));

        c.security.rate_limit.burst = 1;
        assert!(validate(&c, now()).is_ok());
    }

    #[test]
    fn security_tunneling_invalid_entropy_rejected() {
        let mut c = basic_config();
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, 0.0, -3.5] {
            c.security.tunneling.entropy_threshold = bad;
            let errs = validate(&c, now()).unwrap_err();
            assert!(
                has_entity(&errs, "security.tunneling.entropy_threshold"),
                "entropy_threshold = {bad} should be rejected"
            );
        }
        // Large finite values are a legitimate way to soften the heuristic.
        for ok in [0.1, 3.5, 100.0] {
            c.security.tunneling.entropy_threshold = ok;
            assert!(
                validate(&c, now()).is_ok(),
                "entropy_threshold = {ok} is valid"
            );
        }
    }

    #[test]
    fn security_tunneling_zero_integers_rejected() {
        let mut c = basic_config();
        c.security.tunneling.label_len_threshold = 0;
        let errs = validate(&c, now()).unwrap_err();
        assert!(has_entity(&errs, "security.tunneling.label_len_threshold"));

        c.security.tunneling.label_len_threshold = 1;
        c.security.tunneling.subdomain_rate = 0;
        let errs = validate(&c, now()).unwrap_err();
        assert!(has_entity(&errs, "security.tunneling.subdomain_rate"));

        c.security.tunneling.subdomain_rate = 1;
        c.security.tunneling.window_secs = 0;
        let errs = validate(&c, now()).unwrap_err();
        assert!(has_entity(&errs, "security.tunneling.window_secs"));

        c.security.tunneling.window_secs = 1;
        c.security.tunneling.max_unbroken_run = 0;
        let errs = validate(&c, now()).unwrap_err();
        assert!(has_entity(&errs, "security.tunneling.max_unbroken_run"));

        c.security.tunneling.max_unbroken_run = 1;
        c.security.tunneling.entropy_min_len = 0;
        let errs = validate(&c, now()).unwrap_err();
        assert!(has_entity(&errs, "security.tunneling.entropy_min_len"));

        c.security.tunneling.entropy_min_len = 1;
        assert!(validate(&c, now()).is_ok());
    }

    /// `exempt_domains` disarms checks that run before the filter engine,
    /// so a bad entry cannot be narrowed downstream. Malformed and bare-TLD
    /// entries are refused; a whole registrable domain is allowed but
    /// warned. Both arms asserted — a test that only checks the rejections
    /// would also pass against a validator that rejects everything.
    #[test]
    fn security_tunneling_exempt_domains_gated() {
        let mut c = basic_config();

        for bad in ["", "   ", ".", "..", "exam ple.com"] {
            c.security.tunneling.exempt_domains = vec![bad.to_string()];
            let errs = validate(&c, now()).unwrap_err();
            assert!(
                has_entity(&errs, "security.tunneling.exempt_domains"),
                "malformed entry {bad:?} must be refused"
            );
        }

        // A bare TLD is `enabled = false` in disguise.
        c.security.tunneling.exempt_domains = vec!["com".to_string()];
        let errs = validate(&c, now()).unwrap_err();
        assert!(has_entity(&errs, "security.tunneling.exempt_domains"));

        // Two labels: legal, the operator's call, but warned every load.
        c.security.tunneling.exempt_domains = vec!["a2z.com".to_string()];
        assert!(validate(&c, now()).is_ok());

        // Deeper entries are the narrow, encouraged form — no warning.
        c.security.tunneling.exempt_domains = vec![
            "minerva.devices.a2z.com".to_string(),
            "x.y.example.org".to_string(),
        ];
        assert!(validate(&c, now()).is_ok());
    }

    /// The exemption gates ride the section's `enabled` flag like every
    /// other tunneling gate — a stale entry in a disabled section must not
    /// brick the config.
    #[test]
    fn security_tunneling_exempt_gates_scoped_to_enabled() {
        let mut c = basic_config();
        c.security.tunneling.enabled = false;
        c.security.tunneling.exempt_domains = vec!["com".to_string(), String::new()];
        assert!(validate(&c, now()).is_ok());
    }

    /// Disabled sections are inert: stale zero values in a section the
    /// operator turned off must not brick the config (backward compat —
    /// the gate fires when the value starts mattering).
    #[test]
    fn security_gates_scoped_to_enabled_flags() {
        let mut c = basic_config();
        c.security.rrl.responses_per_second = 0;
        c.security.rate_limit.burst = 0;
        c.security.tunneling.entropy_threshold = f64::NAN;

        c.security.rrl.enabled = false;
        c.security.rate_limit.enabled = false;
        c.security.tunneling.enabled = false;
        assert!(
            validate(&c, now()).is_ok(),
            "disabled sub-sections must not be validated"
        );

        // Master switch off ⇒ everything inert regardless of sub-flags.
        c.security.rrl.enabled = true;
        c.security.rate_limit.enabled = true;
        c.security.tunneling.enabled = true;
        c.security.enabled = false;
        assert!(
            validate(&c, now()).is_ok(),
            "security.enabled = false must skip every gate"
        );
    }

    // ── rev-2606 settings-11 / schema-validator-02 — [cache] ─────

    #[test]
    fn cache_inverted_ttl_pair_rejected() {
        let mut c = basic_config();
        c.cache.min_ttl_secs = 3601;
        c.cache.max_ttl_secs = 3600;
        let errs = validate(&c, now()).unwrap_err();
        assert!(has_entity(&errs, "cache.min_ttl_secs"));

        // min == max is a legitimate "pin every TTL" config.
        c.cache.min_ttl_secs = 3600;
        assert!(validate(&c, now()).is_ok(), "min == max is valid");
    }

    #[test]
    fn dynamic_ttl_secs_zero_is_rejected() {
        let mut c = basic_config();
        c.local_dns.dynamic_ttl_secs = 0;
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e.to_string().contains("dynamic_ttl_secs")),
            "expected a dynamic_ttl_secs error, got: {errs:?}"
        );
    }

    #[test]
    fn cache_prefetch_threshold_out_of_range_rejected() {
        let mut c = basic_config();
        c.cache.prefetch = true;
        for bad in [f64::NAN, f64::INFINITY, 0.0, -0.1, 1.0, 1.5] {
            c.cache.prefetch_threshold = bad;
            let errs = validate(&c, now()).unwrap_err();
            assert!(
                has_entity(&errs, "cache.prefetch_threshold"),
                "prefetch_threshold = {bad} should be rejected"
            );
        }
        for ok in [0.01, 0.1, 0.99] {
            c.cache.prefetch_threshold = ok;
            assert!(
                validate(&c, now()).is_ok(),
                "prefetch_threshold = {ok} is valid"
            );
        }
        // Scoped to the enabled flag: junk is inert when prefetch is off.
        c.cache.prefetch = false;
        c.cache.prefetch_threshold = f64::NAN;
        assert!(
            validate(&c, now()).is_ok(),
            "prefetch = false must skip the threshold gate"
        );
    }

    #[test]
    fn cache_stale_buffer_over_cap_rejected() {
        let mut c = basic_config();
        // Unset ⇒ default 300 ⇒ valid (basic_config()); the 24 h cap boundary
        // is accepted; one second over is refused.
        assert!(
            validate(&c, now()).is_ok(),
            "default stale_buffer_secs is valid"
        );
        c.cache.stale_buffer_secs = 86_400;
        assert!(validate(&c, now()).is_ok(), "86400 (the 24 h cap) is valid");

        c.cache.stale_buffer_secs = 86_401;
        let errs = validate(&c, now()).unwrap_err();
        assert!(has_entity(&errs, "cache.stale_buffer_secs"));
    }

    /// `0` is refused; above the clamp is only warned about.
    ///
    /// The asymmetry is the point. At `0` every CNAME'd name stops resolving,
    /// so loading the config is worse than refusing it. Above the clamp the
    /// walkers already behave as `16`, so refusing would take a daemon down
    /// over a config that resolves perfectly well.
    #[test]
    fn cache_cname_max_depth_zero_rejected_above_cap_warned() {
        let mut c = basic_config();
        assert!(
            validate(&c, now()).is_ok(),
            "the default cname_max_depth is valid"
        );

        c.cache.cname_max_depth = 0;
        let errs = validate(&c, now()).unwrap_err();
        assert!(has_entity(&errs, "cache.cname_max_depth"));

        c.cache.cname_max_depth = crate::filter::cname::MAX_HOPS + 8;
        assert!(
            validate(&c, now()).is_ok(),
            "above the clamp the config still LOADS — the clamp makes it safe"
        );
        let warns = warns_for(&c);
        assert!(
            warns.iter().any(|w| w.contains("clamp to 16 hops")),
            "but the operator is told the extra depth is never followed: {warns:?}"
        );

        for ok in [1, crate::filter::cname::MAX_HOPS] {
            c.cache.cname_max_depth = ok;
            assert!(
                validate(&c, now()).is_ok(),
                "cname_max_depth = {ok} is inside the range"
            );
            assert!(
                !warns_for(&c).iter().any(|w| w.contains("cname_max_depth")),
                "an in-range value must be silent"
            );
        }
    }

    /// The message spells the cap as a literal because a frozen string cannot
    /// interpolate a constant. This is what keeps the two from drifting.
    #[test]
    fn cache_cname_max_depth_message_states_the_real_cap() {
        let cap = crate::filter::cname::MAX_HOPS.to_string();
        assert!(
            CACHE_CNAME_MAX_DEPTH_ABOVE_CAP.contains(&format!("clamp to {cap} hops")),
            "message must state the real cap ({cap}): {CACHE_CNAME_MAX_DEPTH_ABOVE_CAP}"
        );
        let got = format_cache_cname_max_depth_above_cap(99);
        assert!(got.contains("is 99,"));
        assert!(!got.contains("{n}"));
    }

    /// `Device.ip` is an `IpAddr`, so `::ffff:10.0.0.5` deserialises as a
    /// `V6` and a raw key makes it a different device from `10.0.0.5`. The
    /// mapped pin is then dead config: `devices_by_ip` never matches it, the
    /// operator sees the device listed, and its queries fall through.
    #[test]
    fn mapped_and_bare_v4_pins_collide() {
        let mut c = basic_config();
        c.devices = vec![
            device("bare", "10.0.0.5", None),
            device("mapped", "::ffff:10.0.0.5", None),
        ];
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            errs.iter().any(
                |e| matches!(e, ConfigError::ValidationFailed(ctx) if ctx.reason.contains("reuses IP"))
            ),
            "the two spellings of one host must collide, got: {errs:?}"
        );

        // Control: two genuinely different hosts still validate, so the
        // assertion above is about normalisation and not about the check
        // firing on any pair of devices.
        c.devices = vec![
            device("bare", "10.0.0.5", None),
            device("other", "::ffff:10.0.0.6", None),
        ];
        assert!(
            validate(&c, now()).is_ok(),
            "distinct addresses must not collide"
        );
    }

    /// `check_display_text` used to return at its emptiness guard, so a
    /// value made only of whitespace never reached the control-character
    /// scan — and the two sets overlap, so "whitespace-only" is not
    /// "harmless". Worst on the optional free-text fields, where the early
    /// return produced no error at all.
    #[test]
    fn whitespace_only_control_chars_are_refused() {
        // U+0085 NEL and the LF/TAB pair are all White_Space AND control.
        for payload in ["\u{85}", "\n\t", "\u{0b}\u{0c}"] {
            let mut c = basic_config();
            let mut d = device("tv", "10.0.0.5", None);
            d.notes = Some(payload.to_string());
            c.devices = vec![d];
            let errs = validate(&c, now()).unwrap_err();
            assert!(
                errs.iter()
                    .any(|e| e.to_string().contains("control character")),
                "{payload:?} trims to empty but is pure control bytes, got: {errs:?}"
            );
        }

        // Control: ordinary whitespace on an optional field is still fine.
        // Without this the check could reject every blank value and pass.
        let mut c = basic_config();
        let mut d = device("tv", "10.0.0.5", None);
        d.notes = Some("   ".to_string());
        c.devices = vec![d];
        assert!(
            validate(&c, now()).is_ok(),
            "a space-only optional field carries no control bytes"
        );
    }

    // ── rev-2606 blocklist-02 — max_consecutive_failures ─────────

    #[test]
    fn blocklist_zero_max_consecutive_failures_rejected() {
        let mut c = basic_config();
        let mut b = blocklist("zero-tolerance");
        b.max_consecutive_failures = 0;
        c.blocklists.push(b);
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            errs.iter().any(|e| matches!(
                e,
                ConfigError::ValidationFailed(ctx)
                    if ctx.reason.contains("max_consecutive_failures")
            )),
            "expected max_consecutive_failures rejection: {errs:?}"
        );

        c.blocklists.last_mut().unwrap().max_consecutive_failures = 1;
        assert!(validate(&c, now()).is_ok(), "1 is valid");
    }

    // ── rev-2606 schema-validator-02 — server/upstream/backup ────

    #[test]
    fn server_zero_tcp_timeout_rejected() {
        let mut c = basic_config();
        c.server.tcp_timeout_secs = 0;
        let errs = validate(&c, now()).unwrap_err();
        assert!(has_entity(&errs, "server.tcp_timeout_secs"));

        c.server.tcp_timeout_secs = 1;
        assert!(validate(&c, now()).is_ok());
    }

    #[test]
    fn server_listen_port_zero_rejected() {
        let mut c = basic_config();
        c.server.listen = "127.0.0.1:0".parse().unwrap();
        let errs = validate(&c, now()).unwrap_err();
        assert!(has_entity(&errs, "server.listen"));

        c.server.listen = "127.0.0.1:15353".parse().unwrap();
        assert!(validate(&c, now()).is_ok());
    }

    #[test]
    fn upstream_empty_servers_rejected() {
        let mut c = basic_config();
        c.upstream.servers.clear();
        let errs = validate(&c, now()).unwrap_err();
        assert!(has_entity(&errs, "upstream.servers"));

        // Non-empty AND shape-valid for the default (plain) mode. rev-2606
        // added per-entry shape validation, so a DoH URL here (the previous
        // placeholder) is now correctly rejected under `mode = "plain"`.
        c.upstream.servers = vec!["1.1.1.1:53".into()];
        assert!(validate(&c, now()).is_ok());
    }

    // ── rev-2606 rev2606-upstream-server-shape-lint ───────────

    #[test]
    fn upstream_malformed_plain_server_rejected() {
        let mut c = basic_config();
        // default mode = plain; a bare hostname (no IP:port) is malformed.
        c.upstream.servers = vec!["dns.google".into()];
        let errs = validate(&c, now()).unwrap_err();
        assert!(has_entity(&errs, "upstream.servers[0]"));
    }

    #[test]
    fn upstream_doh_url_valid_under_doh_mode_http_rejected() {
        let mut c = basic_config();
        c.upstream.mode = UpstreamMode::Doh;
        c.upstream.servers = vec!["https://1.1.1.1/dns-query".into()];
        assert!(validate(&c, now()).is_ok());
        // ...but a cleartext http:// URL is rejected under the same mode.
        c.upstream.servers = vec!["http://1.1.1.1/dns-query".into()];
        assert!(has_entity(
            &validate(&c, now()).unwrap_err(),
            "upstream.servers[0]"
        ));
    }

    #[test]
    fn upstream_fallback_empty_and_malformed_rejected() {
        use crate::config::settings::FallbackConfig;
        let mut c = basic_config();
        // empty fallback servers.
        c.upstream.fallback = Some(FallbackConfig {
            mode: UpstreamMode::Plain,
            servers: vec![],
        });
        assert!(has_entity(
            &validate(&c, now()).unwrap_err(),
            "upstream.fallback.servers"
        ));
        // malformed DoT fallback entry (no port).
        c.upstream.fallback = Some(FallbackConfig {
            mode: UpstreamMode::Dot,
            servers: vec!["dns.quad9.net".into()],
        });
        assert!(has_entity(
            &validate(&c, now()).unwrap_err(),
            "upstream.fallback.servers[0]"
        ));
        // valid DoT fallback entry passes.
        c.upstream.fallback = Some(FallbackConfig {
            mode: UpstreamMode::Dot,
            servers: vec!["dns.quad9.net:853".into()],
        });
        assert!(validate(&c, now()).is_ok());
    }

    #[test]
    fn forwarding_malformed_and_valid_servers() {
        use crate::config::settings::ForwardingZoneConfig;
        let mut c = basic_config();
        // malformed (no port) — entity carries the zone suffix.
        c.forwarding = vec![ForwardingZoneConfig {
            suffix: "corp.example.com".into(),
            mode: UpstreamMode::Plain,
            servers: vec!["10.0.0.1".into()],
        }];
        assert!(has_entity(
            &validate(&c, now()).unwrap_err(),
            "forwarding[corp.example.com].servers[0]"
        ));
        // valid IP:port passes.
        c.forwarding = vec![ForwardingZoneConfig {
            suffix: "corp.example.com".into(),
            mode: UpstreamMode::Plain,
            servers: vec!["10.0.0.1:53".into()],
        }];
        assert!(validate(&c, now()).is_ok());
    }

    #[test]
    fn backup_unparseable_auto_interval_rejected() {
        let mut c = basic_config();
        for bad in ["9999h", "24", "h", "1.5d", ""] {
            c.backup.auto_interval = Some(bad.into());
            let errs = validate(&c, now()).unwrap_err();
            assert!(
                has_entity(&errs, "backup.auto_interval"),
                "auto_interval = {bad:?} should be rejected"
            );
        }
        for ok in ["24h", "7d"] {
            c.backup.auto_interval = Some(ok.into());
            assert!(
                validate(&c, now()).is_ok(),
                "auto_interval = {ok:?} is valid"
            );
        }
        c.backup.auto_interval = None;
        assert!(validate(&c, now()).is_ok(), "unset auto_interval is valid");
    }

    // ── rev-2606 settings-13 — [dnssec] caps ─────────────────────

    #[test]
    fn dnssec_zero_caps_rejected_when_mode_active() {
        use crate::config::settings::DnssecMode;
        let mut c = basic_config();
        c.dnssec.mode = DnssecMode::Validate;

        c.dnssec.max_chain_depth = 0;
        let errs = validate(&c, now()).unwrap_err();
        assert!(has_entity(&errs, "dnssec.max_chain_depth"));
        c.dnssec.max_chain_depth = 1;

        c.dnssec.max_queries = 0;
        let errs = validate(&c, now()).unwrap_err();
        assert!(has_entity(&errs, "dnssec.max_queries"));
        c.dnssec.max_queries = 1;

        c.dnssec.max_nsec3_iterations = 0;
        let errs = validate(&c, now()).unwrap_err();
        assert!(has_entity(&errs, "dnssec.max_nsec3_iterations"));
        c.dnssec.max_nsec3_iterations = 1;

        c.dnssec.max_signature_verifications = 0;
        let errs = validate(&c, now()).unwrap_err();
        assert!(has_entity(&errs, "dnssec.max_signature_verifications"));
        c.dnssec.max_signature_verifications = 1;

        c.dnssec.cache_ttl_secs = 0;
        let errs = validate(&c, now()).unwrap_err();
        assert!(has_entity(&errs, "dnssec.cache_ttl_secs"));
        c.dnssec.cache_ttl_secs = 1;

        assert!(validate(&c, now()).is_ok(), "caps of 1 are valid");

        // log-only counts as active too.
        c.dnssec.mode = DnssecMode::LogOnly;
        c.dnssec.max_queries = 0;
        let errs = validate(&c, now()).unwrap_err();
        assert!(has_entity(&errs, "dnssec.max_queries"));
    }

    /// mode = "off" (the default) is inert: zero caps must not brick a
    /// config on a binary that never validates (backward compat).
    #[test]
    fn dnssec_caps_inert_when_mode_off() {
        let mut c = basic_config();
        c.dnssec.max_chain_depth = 0;
        c.dnssec.cache_ttl_secs = 0;
        assert!(
            validate(&c, now()).is_ok(),
            "mode = off must skip the cap gates"
        );
    }

    // ── rev-2606 settings-03 — [lists] caps fail-open at 0 ───────

    #[test]
    fn lists_zero_caps_rejected() {
        let mut c = basic_config();
        c.lists.max_entries = 0;
        let errs = validate(&c, now()).unwrap_err();
        assert!(has_entity(&errs, "lists.max_entries"));

        c.lists.max_entries = 1;
        c.lists.max_body_bytes = 0;
        let errs = validate(&c, now()).unwrap_err();
        assert!(has_entity(&errs, "lists.max_body_bytes"));

        c.lists.max_body_bytes = 1;
        assert!(validate(&c, now()).is_ok(), "caps of 1 are valid");
    }

    // ── Sprint 43 T4 — DM1 / DM6 device overlay validation ───────

    fn admin_rule(id: &str, rule: &str) -> super::super::admin_rule::AdminRule {
        super::super::admin_rule::AdminRule {
            id: Id::new(id).unwrap(),
            rule: rule.into(),
        }
    }

    #[test]
    fn device_allow_rules_dangling_id_rejected() {
        let mut c = basic_config();
        let mut d = device("phone", "10.0.0.1", Some("default"));
        d.allow_rules = vec![Id::new("does-not-exist").unwrap()];
        c.devices.push(d);
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            errs.iter().any(|e| matches!(
                e,
                ConfigError::CrossRefMiss(ctx)
                    if ctx.reason.contains("does-not-exist")
                       && ctx.reason.contains("allow_rules")
            )),
            "expected dangling allow_rules ref error: {errs:?}"
        );
    }

    #[test]
    fn device_deny_rules_dangling_id_rejected() {
        let mut c = basic_config();
        let mut d = device("phone", "10.0.0.1", Some("default"));
        d.deny_rules = vec![Id::new("ghost-rule").unwrap()];
        c.devices.push(d);
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            errs.iter().any(|e| matches!(
                e,
                ConfigError::CrossRefMiss(ctx)
                    if ctx.reason.contains("ghost-rule")
                       && ctx.reason.contains("deny_rules")
            )),
            "expected dangling deny_rules ref error: {errs:?}"
        );
    }

    #[test]
    fn device_with_known_rule_ids_accepted() {
        let mut c = basic_config();
        c.admin_rules
            .push(admin_rule("dev-allow-bank", "@@||bank.example^"));
        c.admin_rules
            .push(admin_rule("dev-deny-tiktok", "||tiktok.com^"));
        let mut d = device("phone", "10.0.0.1", Some("default"));
        d.allow_rules = vec![Id::new("dev-allow-bank").unwrap()];
        d.deny_rules = vec![Id::new("dev-deny-tiktok").unwrap()];
        c.devices.push(d);
        assert!(validate(&c, now()).is_ok());
    }

    // ── rev-2606 schema-validator-05: admin rule text parse-validated ──

    #[test]
    fn admin_rule_broken_regex_rejected() {
        let mut c = basic_config();
        c.admin_rules.push(admin_rule("bad-re", "/broken(/"));
        let errs = validate(&c, now()).unwrap_err();
        let hits: Vec<_> = errs
            .iter()
            .filter(|e| {
                matches!(
                    e,
                    ConfigError::ValidationFailed(ctx)
                        if ctx.entity.as_deref() == Some("admin_rules.bad-re")
                )
            })
            .collect();
        assert_eq!(hits.len(), 1, "exactly one parse error: {errs:?}");
        let ConfigError::ValidationFailed(ctx) = hits[0] else {
            unreachable!()
        };
        assert!(
            ctx.reason.contains("failed to compile"),
            "reason carries the RuleParseError detail: {}",
            ctx.reason
        );
        assert!(
            ctx.suggestion.is_some(),
            "parse errors carry a next-step suggestion"
        );
    }

    #[test]
    fn admin_rule_unknown_modifier_rejected() {
        let mut c = basic_config();
        c.admin_rules
            .push(admin_rule("aaaa-only", "||example.com^$dnstype=AAAA"));
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            errs.iter().any(|e| matches!(
                e,
                ConfigError::ValidationFailed(ctx)
                    if ctx.entity.as_deref() == Some("admin_rules.aaaa-only")
                       && ctx.reason.contains("unknown modifier '$dnstype=AAAA'")
            )),
            "unknown modifier surfaces at lint: {errs:?}"
        );
    }

    #[test]
    fn admin_rule_empty_still_missing_required_only() {
        // The emptiness check stays first and short-circuits — an empty
        // rule must NOT also produce a parse error (double report).
        let mut c = basic_config();
        c.admin_rules.push(admin_rule("empty-rule", "   "));
        let errs = validate(&c, now()).unwrap_err();
        let mine: Vec<_> = errs
            .iter()
            .filter(|e| {
                let (ConfigError::MissingRequired(ctx) | ConfigError::ValidationFailed(ctx)) = e
                else {
                    return false;
                };
                ctx.entity.as_deref() == Some("admin_rules.empty-rule")
            })
            .collect();
        assert_eq!(mine.len(), 1, "{errs:?}");
        assert!(
            matches!(mine[0], ConfigError::MissingRequired(_)),
            "empty rule keeps the MissingRequired shape: {:?}",
            mine[0]
        );
    }

    #[test]
    fn admin_rule_two_broken_rules_two_errors() {
        // Complete-list contract: every broken rule is reported.
        let mut c = basic_config();
        c.admin_rules.push(admin_rule("bad-one", "/foo/bar"));
        c.admin_rules.push(admin_rule("bad-two", "||ads.*.com^"));
        let errs = validate(&c, now()).unwrap_err();
        for entity in ["admin_rules.bad-one", "admin_rules.bad-two"] {
            assert!(
                errs.iter().any(|e| matches!(
                    e,
                    ConfigError::ValidationFailed(ctx)
                        if ctx.entity.as_deref() == Some(entity)
                )),
                "missing error for {entity}: {errs:?}"
            );
        }
    }

    #[test]
    fn admin_rule_valid_shapes_accepted() {
        let mut c = basic_config();
        for (id, rule) in [
            ("r1", "||tiktok.com^"),
            ("r2", "@@||wikipedia.org^"),
            ("r3", "||malware.example^$important"),
            ("r4", "||*.ads.example.com^"),
            ("r5", "||*.cdn.example.com^$noapex"),
            ("r6", "/ad[0-9]+\\.example\\.com/"),
            ("r7", "@@/safe-cdn[0-9]+/"),
            ("r8", "/DoubleClick/"),
            ("r9", "plain.example.com"),
            ("r10", "@@example.com"),
        ] {
            c.admin_rules.push(admin_rule(id, rule));
        }
        assert!(validate(&c, now()).is_ok());
    }

    #[test]
    fn device_rules_hard_cap_129_rejected() {
        let mut c = basic_config();
        // Inject 129 admin rules so cross-refs all resolve, then point
        // every one of them from the device. The total count = 129
        // exceeds the hard cap of 128 by 1.
        for n in 0..129u32 {
            c.admin_rules.push(admin_rule(
                &format!("rule-{n}"),
                &format!("||t{n}.example^"),
            ));
        }
        let mut d = device("phone", "10.0.0.1", Some("default"));
        d.allow_rules = (0..129)
            .map(|n| Id::new(format!("rule-{n}")).unwrap())
            .collect();
        c.devices.push(d);
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            errs.iter().any(|e| matches!(
                e,
                ConfigError::ValidationFailed(ctx)
                    if ctx.reason.contains("hard cap") && ctx.reason.contains("128")
            )),
            "expected hard-cap rejection, got: {errs:?}"
        );
    }

    #[test]
    fn device_rules_at_hard_cap_128_accepted() {
        // Exactly 128 entries (split allow + deny) is the boundary.
        // Validator must accept; only `> 128` rejects.
        let mut c = basic_config();
        for n in 0..128u32 {
            c.admin_rules.push(admin_rule(
                &format!("rule-{n}"),
                &format!("||t{n}.example^"),
            ));
        }
        let mut d = device("phone", "10.0.0.1", Some("default"));
        d.allow_rules = (0..64)
            .map(|n| Id::new(format!("rule-{n}")).unwrap())
            .collect();
        d.deny_rules = (64..128)
            .map(|n| Id::new(format!("rule-{n}")).unwrap())
            .collect();
        c.devices.push(d);
        assert!(
            validate(&c, now()).is_ok(),
            "128 entries (64+64) is exactly at the cap and must be accepted"
        );
    }

    #[test]
    fn device_rules_soft_cap_warn_does_not_block() {
        // Soft cap = 64. Going from 65 to 128 emits LIST_PRUNE_WARN
        // via tracing::warn but does NOT push a ConfigError (operator
        // can still boot and prune later).
        let mut c = basic_config();
        for n in 0..70u32 {
            c.admin_rules.push(admin_rule(
                &format!("rule-{n}"),
                &format!("||t{n}.example^"),
            ));
        }
        let mut d = device("phone", "10.0.0.1", Some("default"));
        d.allow_rules = (0..70)
            .map(|n| Id::new(format!("rule-{n}")).unwrap())
            .collect();
        c.devices.push(d);
        assert!(validate(&c, now()).is_ok());
    }

    #[test]
    fn list_prune_warn_const_is_pinned() {
        // T6 will turn this into a frozen-strings file; T4 pins the
        // const here so any unintentional rewording lights up before
        // the holistic pass.
        assert_eq!(
            LIST_PRUNE_WARN,
            "Device '{id}' has {n} rules (soft cap: 64). Run `warden device rules {id} prune` to clean up dead refs."
        );
    }

    #[test]
    fn list_prune_warn_format_helper_substitutes() {
        let s = format_list_prune_warn("alex-iphone", 70);
        assert!(s.contains("'alex-iphone'"));
        assert!(s.contains("70 rules"));
        assert!(s.contains("warden device rules alex-iphone prune"));
    }

    #[test]
    fn tracking_config_rejects_sampled_rate_out_of_range() {
        use crate::config::settings::LogMode;
        let mut c = basic_config();
        c.tracking.log_mode = LogMode::Sampled { allowed_rate: -0.1 };
        let errs = validate(&c, now()).unwrap_err();
        assert!(has_entity(&errs, "tracking.log_mode.sampled.allowed_rate"));

        c.tracking.log_mode = LogMode::Sampled { allowed_rate: 1.5 };
        let errs = validate(&c, now()).unwrap_err();
        assert!(has_entity(&errs, "tracking.log_mode.sampled.allowed_rate"));

        c.tracking.log_mode = LogMode::Sampled {
            allowed_rate: f32::NAN,
        };
        let errs = validate(&c, now()).unwrap_err();
        assert!(has_entity(&errs, "tracking.log_mode.sampled.allowed_rate"));

        // Valid rates at boundaries pass.
        for rate in [0.0_f32, 0.5, 1.0] {
            c.tracking.log_mode = LogMode::Sampled { allowed_rate: rate };
            assert!(validate(&c, now()).is_ok(), "rate = {rate} should pass");
        }
    }

    // ── kind/trust compatibility — the W2.1 gate, now consent-based ──
    //
    // `ALLOW_LIST_REQUIRES_LOCAL_TRUST` and its helper were deleted with
    // the categorical gate: the sentence "Allow-direction lists require
    // trust=local" became false the moment `accept_unsigned_allow`
    // started admitting remote allow-lists. `tests/frozen_strings_s49.rs`
    // is the tombstone; the replacements are pinned in
    // `tests/frozen_strings_unsigned_allow.rs` and mirrored below.

    /// Defence-in-depth mirror of
    /// `tests/frozen_strings_unsigned_allow.rs` — lights up earlier than
    /// the integration target when someone rewords the refusal.
    #[test]
    fn unsigned_allow_list_requires_ack_const_is_pinned() {
        assert_eq!(
            UNSIGNED_ALLOW_LIST_REQUIRES_ACK,
            "Blocklist '{id}' has kind=allow but trust='{got}'. A remote allow-list can unblock any domain it lists, and its content can change at every refresh with no review. Set accept_unsigned_allow = true on the list to accept that risk, or use `warden blocklist import-local` to import a local file."
        );
    }

    #[test]
    fn unsigned_allow_list_requires_ack_format_helper_substitutes() {
        let s = format_unsigned_allow_list_requires_ack("trusted-internal", BlocklistTrust::Signed);
        assert!(s.contains("'trusted-internal'"));
        assert!(s.contains("trust='signed'"));
        assert!(s.contains("kind=allow"));
        assert!(s.contains("`warden blocklist import-local`"));

        // `RemoteUnsigned` must round-trip through the kebab-case spelling
        // (matches the on-wire form an operator typed in TOML).
        let s = format_unsigned_allow_list_requires_ack("x", BlocklistTrust::RemoteUnsigned);
        assert!(s.contains("trust='remote-unsigned'"));
    }

    #[test]
    fn unsigned_allow_list_accepted_const_is_pinned() {
        assert_eq!(
            UNSIGNED_ALLOW_LIST_ACCEPTED,
            "allow-list \"{id}\" is remote and unsigned — whoever controls its URL can unblock any domain by adding it, at every refresh, with no review"
        );
    }

    #[test]
    fn unsigned_allow_list_accepted_format_helper_substitutes() {
        let s = format_unsigned_allow_list_accepted("vendor-allow");
        assert!(s.contains("\"vendor-allow\""));
        assert!(!s.contains("{id}"), "placeholder left unsubstituted: {s}");
    }

    /// Sprint 50 T2: byte-for-byte pin for the new frozen string.
    /// `tests/frozen_strings_s50.rs` (T5 deliverable) will mirror this
    /// assertion into the dedicated frozen-strings file; pinning here as
    /// well guards against accidental rewording during the inter-phase
    /// window (same defence-in-depth pattern as
    /// [`allow_list_requires_local_trust_const_is_pinned`]).
    #[test]
    fn trust_signed_not_yet_supported_const_is_pinned() {
        assert_eq!(
            TRUST_SIGNED_NOT_YET_SUPPORTED,
            "trust=signed is not supported in this version. Use trust=local for trusted allow-lists or trust=remote-unsigned for block-only lists."
        );
    }

    // ── Sprint A of lists_categories_v2: byte-pinned frozen strings ──
    //
    // Same defence-in-depth pattern as the S49 / S50 pins above. T3
    // wires the validator emit paths; the byte-pin here lets a code
    // reviewer catch a silent rename even if T3 has not landed yet.

    #[test]
    fn network_name_invalid_fqdn_const_is_pinned() {
        assert_eq!(
            NETWORK_NAME_INVALID_FQDN,
            "devices.{id}.network_name '{name}' is not a valid FQDN label (1-63 chars, alphanumeric + hyphen, no leading/trailing hyphen)."
        );
    }

    #[test]
    fn network_name_invalid_fqdn_format_helper_substitutes() {
        let s = format_network_name_invalid_fqdn("desktop-1", "bad domain!");
        assert!(s.contains("devices.desktop-1.network_name"));
        assert!(s.contains("'bad domain!'"));
        assert!(!s.contains("{id}"));
        assert!(!s.contains("{name}"));
    }

    #[test]
    fn network_name_wildcard_without_name_const_is_pinned() {
        assert_eq!(
            NETWORK_NAME_WILDCARD_WITHOUT_NAME,
            "devices.{id}.network_name_wildcard=true has no effect without network_name set."
        );
    }

    #[test]
    fn network_name_wildcard_without_name_format_helper_substitutes() {
        let s = format_network_name_wildcard_without_name("desktop-1");
        assert!(s.contains("devices.desktop-1.network_name_wildcard"));
        assert!(!s.contains("{id}"));
    }

    // ── rev-2606 §05 schema-validator-03 ──────────────────────────────
    //
    // The lint and the fetcher must agree on which list URLs can ever be
    // downloaded. They cannot share code — the fetcher owns `url`/`reqwest`
    // and the config layer is deliberately free of both — so the guard
    // against drift is this cross-check rather than a shared call.

    /// What `check_blocklists` would accept without any diagnostic,
    /// composed from the same predicates the emit sites use.
    fn lint_accepts_silently(url: &str) -> bool {
        (url.starts_with("http://") || url.starts_with("https://"))
            && !url.starts_with("http://")
            && !url_has_embedded_userinfo(url)
            && !host_is_unfetchable(url_host_of(url))
    }

    #[test]
    fn blocklist_url_policy_agrees_with_the_fetcher() {
        // Compared on the three axes this rule aligns: scheme, embedded
        // userinfo, and the host-address policy. URL *well-formedness* is
        // deliberately NOT compared — `Url::parse` owns that and the config
        // layer has no parser, so every case below is syntactically valid
        // for both sides.
        let cases = [
            "https://lists.purge.cc/privacy/ads.txt",
            "http://lists.purge.cc/privacy/ads.txt",
            "https://user:pass@lists.purge.cc/ads.txt",
            "https://192.0.2.10/ads.txt",
            "https://10.0.0.1/ads.txt",
            "https://192.168.1.1/ads.txt",
            "https://172.16.0.1/ads.txt",
            "https://127.0.0.1/ads.txt",
            "https://169.254.1.1/ads.txt",
            "https://100.64.0.1/ads.txt",
            "https://0.0.0.0/ads.txt",
            "https://[::1]/ads.txt",
            "https://[fc00::1]/ads.txt",
            "https://[fe80::1]/ads.txt",
            "https://[::ffff:127.0.0.1]/ads.txt",
            // RFC 3849 documentation prefix, not a real provider's address:
            // a public v6 literal is needed here and a vendor one would put a
            // named service into src/ for no reason (project rules Rule 10).
            "https://[2001:db8::1]/ads.txt",
            "https://lists.purge.cc:8443/ads.txt",
            "https://192.0.2.10:8443/ads.txt",
        ];
        for url in cases {
            let fetcher_ok = crate::lists::http_client::validate_list_url(url).is_ok();
            let lint_ok = lint_accepts_silently(url);
            assert_eq!(
                lint_ok, fetcher_ok,
                "lint and fetcher disagree on {url}: lint_ok={lint_ok}, \
                 fetcher_ok={fetcher_ok} — a config that lints clean and can \
                 never download is exactly the split this rule closes"
            );
        }
    }

    /// The table above is only evidence if it contains both polarities.
    /// Without this, a `lint_accepts_silently` hardwired to `false` (or a
    /// fetcher that refused everything) would pass it.
    #[test]
    fn the_url_agreement_table_covers_both_verdicts() {
        assert!(
            lint_accepts_silently("https://lists.purge.cc/ads.txt"),
            "a plain https list on a public host must be accepted silently"
        );
        assert!(
            !lint_accepts_silently("http://lists.purge.cc/ads.txt"),
            "cleartext http must be diagnosed"
        );
        assert!(
            !lint_accepts_silently("https://10.0.0.1/ads.txt"),
            "an RFC1918 host must be diagnosed"
        );
    }

    #[test]
    fn url_host_of_peels_userinfo_port_and_ipv6_brackets() {
        assert_eq!(
            url_host_of("https://lists.purge.cc/ads.txt"),
            "lists.purge.cc"
        );
        assert_eq!(
            url_host_of("https://u:p@lists.purge.cc/ads.txt"),
            "lists.purge.cc"
        );
        assert_eq!(
            url_host_of("https://lists.purge.cc:8443/ads.txt"),
            "lists.purge.cc"
        );
        // The inner colons of an IPv6 literal must not be read as a port.
        assert_eq!(url_host_of("https://[fe80::1]:8443/ads.txt"), "fe80::1");
        assert_eq!(url_host_of("https://192.0.2.10"), "192.0.2.10");
    }

    #[test]
    fn blocklist_url_diagnostic_consts_are_pinned() {
        assert_eq!(
            BLOCKLIST_URL_CLEARTEXT_HTTP,
            "blocklist \"{id}\" uses a cleartext http:// URL — the downloader is https-only, so this list will never update"
        );
        assert_eq!(
            BLOCKLIST_URL_UNFETCHABLE_HOST,
            "blocklist \"{id}\" points at \"{host}\", an address the downloader refuses (private, loopback, link-local, CGNAT or unspecified) — so this list will never update"
        );
        let s = format_blocklist_url_unfetchable_host("corp-list", "10.0.0.1");
        assert!(s.contains("\"corp-list\"") && s.contains("\"10.0.0.1\""));
        assert!(!s.contains("{id}") && !s.contains("{host}"));
    }

    // ── Sprint B T3 — 3 new §5.4 frozen strings ────────────────────

    // ── Sprint C T5 — Add-list pre-flight gate 3 ──────────────────

    #[test]
    fn list_url_not_reachable_const_is_pinned() {
        assert_eq!(
            LIST_URL_NOT_REACHABLE,
            "Cannot reach '{url}': {detail}. Verify the URL in a browser, then retry — or pass --skip-head-check to add the list anyway."
        );
    }

    #[test]
    fn list_url_not_reachable_format_helper_substitutes() {
        let s =
            format_list_url_not_reachable("https://example.invalid/list.txt", "connection refused");
        assert!(s.contains("'https://example.invalid/list.txt'"));
        assert!(s.contains("connection refused"));
        assert!(!s.contains("{url}"));
        assert!(!s.contains("{detail}"));
    }

    // ── plp cutover — what replaced the §5.4 tag rows ──────────────
    //
    // Rows 0-3 of the `lists_categories_v2` §5.4 table were emit-path
    // tests for four tag diagnostics. Three of them (rows 1-3) asserted
    // only `validate(...).is_ok()`, which the validator returns whether
    // the WARN fires or not — they were green against a validator that
    // emitted nothing, and stayed green when the emit sites left at S3.
    // A test that passes on the state the product preserves in failure is
    // not evidence, so they are gone rather than kept as decoration.
    //
    // What replaced them:
    //
    // | withdrawn | replacement |
    // |---|---|
    // | row 0 `DEVICE_UNFILTERED_WITH_TAGS` (ERROR) | none — the contradiction it priced no longer exists; inverted below |
    // | row 1 `DEVICE_NOT_FILTERED_NO_TAGS` | `PROFILE_FILTERS_NO_LISTS`, asserted below |
    // | row 2 `PROFILE_CONTRIBUTES_NO_TAGS` | `PROFILE_FILTERS_NO_LISTS`, asserted below |
    // | row 3 `ALLOW_LIST_NO_TAGS_NO_EFFECT` | premise inverted — an untagged allow-list now applies everywhere, and `ALLOW_DIRECTION_LIST_STANDING_EXPOSURE` is the honest signal (`f24_the_standing_exposure_warning_still_fires_on_the_allow_branch`) |
    // | row 4 `UNCATEGORIZED_MISSING_AT_RELOAD` (ERROR) | none — the `uncategorized` sentinel is retired, so there is no registry left to miss it |
    //
    // **The constants themselves are gone as of `plp-s5f`**, along with the
    // frozen-string tests that byte-pinned them. Until then they stood
    // declared-and-unemitted, which is worse than absent: a byte-pin on a
    // string the product cannot produce is green by construction, and reads
    // to the next person as proof the diagnostic still exists. The
    // replacements named above are pinned from outside the crate in
    // `tests/frozen_strings_plp_profile_diagnostics.rs`.

    /// The substitute for §5.4 rows 1 and 2, asserted rather than assumed:
    /// a profile that ignores every enabled list is named in the warnings.
    ///
    /// It asks one hop later than the tag rows did — a device inherits its
    /// profile's policy, so the profile is where the answer is — and it
    /// catches the case the tag version could not: a profile carrying tags
    /// that no list matched still looked healthy to `PROFILE_CONTRIBUTES_NO_TAGS`.
    #[test]
    fn a_profile_that_ignores_every_list_is_warned_about() {
        let mut c = basic_config();
        let list_id = c.blocklists[0].id.clone();
        c.profiles
            .get_mut("default")
            .unwrap()
            .lists
            .insert(list_id, ListPolicy::Ignore);

        let mut warns = AuditWarnings::silent();
        assert!(validate_collect(&c, now(), &mut warns, None, None).is_ok());
        let msgs = warns.into_messages();
        let expected = format_profile_filters_no_lists("default");
        assert!(
            msgs.contains(&expected),
            "expected {expected:?}, got {msgs:?}"
        );
    }

    /// Control arm for the test above. Without it, the assertion there also
    /// passes against a validator that warned about *every* profile — which
    /// is the failure mode this whole class of WARN dies of, and the one
    /// project rules names twice for detectors.
    #[test]
    fn a_profile_that_filters_one_list_is_silent() {
        let c = basic_config();
        assert!(
            c.profiles["default"].lists.is_empty(),
            "fixture must inherit, or the control arm proves nothing"
        );
        let mut warns = AuditWarnings::silent();
        assert!(validate_collect(&c, now(), &mut warns, None, None).is_ok());
        let unexpected = format_profile_filters_no_lists("default");
        let msgs = warns.into_messages();
        assert!(
            !msgs.contains(&unexpected),
            "the profile inherits `base = deny` on an enabled list — it filters. \
             got {msgs:?}"
        );
    }

    // ── device.network_name — FQDN syntax + wildcard mutex ─────────

    #[test]
    fn device_network_name_bad_fqdn_syntax_is_rejected() {
        let mut c = basic_config();
        let mut d = device("desktop-1", "192.0.2.50", None);
        d.network_name = Some("bad domain!".to_string());
        c.devices.push(d);
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            errs.iter().any(|e| e.to_string().contains("network_name")),
            "expected a network_name FQDN error, got: {errs:?}"
        );
    }

    #[test]
    fn device_network_name_wildcard_without_name_is_rejected() {
        let mut c = basic_config();
        let mut d = device("desktop-1", "192.0.2.50", None);
        d.network_name_wildcard = true;
        c.devices.push(d);
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e.to_string().contains("network_name_wildcard")),
            "expected a network_name_wildcard mutex error, got: {errs:?}"
        );
    }

    #[test]
    fn device_network_name_valid_fqdn_is_accepted() {
        let mut c = basic_config();
        let mut d = device("desktop-1", "192.0.2.50", None);
        d.network_name = Some("desktop-1".to_string());
        c.devices.push(d);
        assert!(validate(&c, now()).is_ok());
    }

    #[test]
    fn device_network_name_collides_with_another_device_is_rejected() {
        let mut c = basic_config();
        let mut d1 = device("desktop-1", "192.0.2.50", None);
        d1.network_name = Some("shared-name".to_string());
        let mut d2 = device("other-box", "192.0.2.51", None);
        d2.network_name = Some("shared-name".to_string());
        c.devices.push(d1);
        c.devices.push(d2);
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            errs.iter().any(|e| e.to_string().contains("already used")),
            "expected a network_name collision error, got: {errs:?}"
        );
    }

    #[test]
    fn device_network_name_collides_with_local_dns_record_is_rejected() {
        let mut c = basic_config();
        let mut d = device("desktop-1", "192.0.2.50", None);
        d.network_name = Some("nas".to_string());
        c.devices.push(d);
        c.local_dns
            .records
            .push(crate::config::settings::LocalDnsRecord {
                domain: "nas".to_string(),
                record_type: crate::config::settings::LocalDnsRecordType::A,
                value: "192.0.2.60".to_string(),
                match_subdomains: false,
                ttl_secs: None,
            });
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            errs.iter().any(|e| e.to_string().contains("already used")),
            "expected a network_name/local_dns collision error, got: {errs:?}"
        );
    }

    /// The two collision messages above share the phrase "already used",
    /// so a test keyed on it alone cannot tell which arm fired — swap
    /// the device-vs-device and device-vs-local_dns branches and both
    /// still pass. These two pin the discriminating half of each
    /// message, and at the same time exercise the key normalisation
    /// (case-fold + trailing dot) that nothing else covers: without it
    /// `NAS.` and `nas` are two names claiming one record.
    #[test]
    fn device_network_name_device_collision_is_normalised_and_names_the_other_device() {
        let mut c = basic_config();
        let mut d1 = device("desktop-1", "192.0.2.50", None);
        d1.network_name = Some("NAS.".to_string());
        let mut d2 = device("other-box", "192.0.2.51", None);
        d2.network_name = Some("nas".to_string());
        c.devices.push(d1);
        c.devices.push(d2);
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            errs.iter().any(|e| {
                let s = e.to_string();
                s.contains("already used by device") && s.contains("desktop-1")
            }),
            "expected a device-vs-device collision naming \"desktop-1\", got: {errs:?}"
        );
    }

    #[test]
    fn device_network_name_local_dns_collision_is_normalised_and_names_local_dns() {
        let mut c = basic_config();
        let mut d = device("desktop-1", "192.0.2.50", None);
        d.network_name = Some("NAS.".to_string());
        c.devices.push(d);
        c.local_dns
            .records
            .push(crate::config::settings::LocalDnsRecord {
                domain: "nas".to_string(),
                record_type: crate::config::settings::LocalDnsRecordType::A,
                value: "192.0.2.60".to_string(),
                match_subdomains: false,
                ttl_secs: None,
            });
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e.to_string().contains("already used by a local_dns record")),
            "expected a device-vs-local_dns collision, got: {errs:?}"
        );
    }

    /// The per-profile `local_records` scope is part of the same
    /// collision universe as the global `[local_dns]` table — a device
    /// name that shadows a profile-scoped record is just as broken.
    #[test]
    fn device_network_name_collides_with_profile_local_record_is_rejected() {
        let mut c = basic_config();
        let mut d = device("desktop-1", "192.0.2.50", None);
        d.network_name = Some("printer".to_string());
        c.devices.push(d);
        c.profiles.get_mut("default").unwrap().local_records.push(
            crate::config::settings::LocalDnsRecord {
                domain: "printer".to_string(),
                record_type: crate::config::settings::LocalDnsRecordType::A,
                value: "192.0.2.70".to_string(),
                match_subdomains: false,
                ttl_secs: None,
            },
        );
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e.to_string().contains("already used by a local_dns record")),
            "expected a device-vs-profile-local_records collision, got: {errs:?}"
        );
    }

    // ── inert_blocklists — the plp predicate ────────────────────────

    /// The one shape [`inert_blocklists`] reports: `base = "ignore"` with
    /// every profile inheriting it. The message is the load-time WARN's own
    /// frozen string, so `warden status` and `config lint` cannot drift.
    #[test]
    fn a_base_ignore_list_no_profile_overrides_is_inert() {
        let mut c = basic_config();
        c.blocklists[0].base = BlocklistBase::Ignore;
        let rows = inert_blocklists(&c);
        assert_eq!(rows.len(), 1, "got {rows:?}");
        assert_eq!(rows[0].0, "privacy-ads");
        assert_eq!(rows[0].1, InertListReason::BaseIgnore);
        assert_eq!(
            rows[0].1.message("privacy-ads"),
            format_base_ignore_list_is_inert("privacy-ads"),
            "the projection must reuse the WARN's string, not paraphrase it"
        );
    }

    /// The narrowing, asserted. A profile that overrides the list to `deny`
    /// filters with it, so calling it inert in `warden status` would be F24's
    /// false claim pointed the other way — and an operator acting on
    /// "inert" removes a list that is doing work.
    ///
    /// **Two profiles, and the second one is not decoration.** Written with
    /// only `basic_config()`'s single profile, this test passed against
    /// `any()` as happily as against `all()` — over a one-element iterator
    /// they are the same function. The mutation caught it. The fixture now
    /// has one profile that inherits `ignore` and one that overrides to
    /// `deny`, which is the smallest shape where the two disagree.
    #[test]
    fn a_base_ignore_list_one_profile_overrides_is_not_inert() {
        let mut c = basic_config();
        c.blocklists[0].base = BlocklistBase::Ignore;
        let list_id = c.blocklists[0].id.clone();
        c.profiles.insert("kids".into(), profile_default());
        c.profiles
            .get_mut("kids")
            .unwrap()
            .lists
            .insert(list_id, ListPolicy::Deny);
        assert_eq!(c.profiles.len(), 2, "one profile makes all() == any()");
        assert!(
            inert_blocklists(&c).is_empty(),
            "`kids` denies with it — got {:?}",
            inert_blocklists(&c)
        );
    }

    /// Control arm for both tests above. An ordinary deny-direction list is
    /// never inert, and without this a predicate that returned everything —
    /// or nothing — would still satisfy one of the two.
    #[test]
    fn an_ordinary_deny_list_is_not_inert() {
        let c = basic_config();
        assert_eq!(c.blocklists[0].base, BlocklistBase::Deny);
        assert!(inert_blocklists(&c).is_empty());
    }

    /// **The vacuous-truth guard.** `all()` over an empty profile map is
    /// true, so without the early return a config with no profiles would
    /// report every ignore-direction list inert on the strength of a claim
    /// no profile made. Reported for the record: with zero profiles nothing
    /// resolves at all, and that is not a fact about any one list.
    #[test]
    fn a_config_with_no_profiles_reports_nothing_inert() {
        let mut c = basic_config();
        c.blocklists[0].base = BlocklistBase::Ignore;
        c.profiles.clear();
        assert!(
            inert_blocklists(&c).is_empty(),
            "vacuous truth is not a measurement — got {:?}",
            inert_blocklists(&c)
        );
    }

    /// The tag-keyed predicate this replaced is gone, and its variants must
    /// never come back into production: an untagged `base = allow` list is
    /// reached by every profile that inherits it, so `AllowListNoTags` was
    /// F24's claim rendered in `warden status`.
    #[test]
    fn an_untagged_allow_list_is_not_reported_inert() {
        let mut c = basic_config();
        c.blocklists[0].base = BlocklistBase::Allow;
        c.blocklists[0].trust = BlocklistTrust::Local;
        assert!(
            inert_blocklists(&c).is_empty(),
            "an allow-direction list applies to every profile that inherits it \
             — got {:?}",
            inert_blocklists(&c)
        );
    }

    // ── `[lists].sources` entries that cannot filter ────────────────

    /// The shape the diagnostic exists for: a source recorded in the
    /// channel that downloads but cannot filter, with nothing to match
    /// it.
    #[test]
    fn legacy_source_with_no_list_is_reported() {
        let mut c = basic_config();
        c.blocklists.clear();
        c.lists.sources = vec!["privacy/ads".to_string()];
        assert_eq!(orphan_legacy_sources(&c), vec!["privacy/ads".to_string()]);
    }

    /// Warning, not error. A config in the field that holds one of these
    /// boots today; refusing to load would take a working resolver down
    /// to fix a list that was already filtering nothing.
    #[test]
    fn legacy_source_with_no_list_still_loads() {
        let mut c = basic_config();
        c.blocklists.clear();
        c.lists.sources = vec!["privacy/ads".to_string()];

        let mut warns = AuditWarnings::silent();
        assert!(
            validate_collect(&c, now(), &mut warns, None, None).is_ok(),
            "an orphan source must never stop the daemon from starting"
        );
        let msgs = warns.into_messages();
        assert!(
            msgs.iter().any(|m| m.contains("filters nothing")),
            "expected the orphan-source warning, got: {msgs:?}"
        );
    }

    /// The shape every migrated config has. It must stay silent, or the
    /// warning becomes noise operators learn to scroll past.
    #[test]
    fn no_legacy_sources_is_silent() {
        let c = basic_config();
        assert!(c.lists.sources.is_empty());
        assert!(orphan_legacy_sources(&c).is_empty());
    }

    /// A source that names a real list is not orphaned — the slug and
    /// the list id are the same list spelled two ways.
    #[test]
    fn legacy_source_matching_a_list_by_id_is_silent() {
        let mut c = basic_config();
        let id = c.blocklists[0].id.as_str().to_string();
        c.lists.sources = vec![id.replace('-', "/")];
        assert!(
            orphan_legacy_sources(&c).is_empty(),
            "slug form and id form name one list; got {:?}",
            orphan_legacy_sources(&c)
        );
    }

    /// Matching by URL too, so a source written as a URL alongside the
    /// list that fetches it is not reported twice.
    #[test]
    fn legacy_source_matching_a_list_by_url_is_silent() {
        let mut c = basic_config();
        c.lists.sources = vec![c.blocklists[0].url.clone()];
        assert!(orphan_legacy_sources(&c).is_empty());
    }

    /// **Inverted at the plp cutover — this test asserted the opposite,
    /// and it was the pin holding F24 in place.** It read
    /// `legacy_source_matching_an_untagged_list_is_reported`, on the
    /// premise that a list with no tags could not be reached. Tags stopped
    /// deciding reachability at S3, so an untagged list is reached by every
    /// profile that inherits its `base` — and reporting it as unreachable
    /// printed a `warden lists remove` at a working list.
    ///
    /// Kept and inverted rather than deleted: a deletion sprint that leaves
    /// its old pins standing is this repo's neutrality-#5 scar, and a test
    /// that quietly disappears takes the record of the old rule with it.
    #[test]
    fn legacy_source_matching_an_untagged_list_is_silent() {
        let mut c = basic_config();
        c.lists.sources = vec![c.blocklists[0].url.clone()];
        assert!(
            orphan_legacy_sources(&c).is_empty(),
            "an untagged list is reachable through its base — got {:?}",
            orphan_legacy_sources(&c)
        );
    }

    /// A disabled list is never fetched, so a source pointing at one is
    /// as inert as a source pointing at nothing.
    #[test]
    fn legacy_source_matching_a_disabled_list_is_reported() {
        let mut c = basic_config();
        c.blocklists[0].enabled = false;
        c.lists.sources = vec![c.blocklists[0].url.clone()];
        assert_eq!(orphan_legacy_sources(&c).len(), 1);
    }

    /// The message has to name the source and both halves of the fix —
    /// it is the only place this failure is ever explained.
    #[test]
    fn legacy_source_warning_names_the_source_and_the_fix() {
        let msg = format_legacy_source_not_enforced("privacy/ads");
        assert!(msg.contains("privacy/ads"));
        assert!(msg.contains("warden lists remove privacy/ads"));
        assert!(msg.contains("warden lists add privacy/ads"));
        assert!(!msg.contains("{source}"), "placeholder left unsubstituted");
    }

    // ── F24 — the two contradictory warnings on one list ────────────
    //
    // Measured by lane 4a on two configs a single word apart, run
    // through `warden config lint`. The `base = "allow"` branch emitted
    // BOTH of these about the same list:
    //
    //   1. "downloaded but filters nothing — no profile, device, group
    //      or subnet can reach it"          (LEGACY_SOURCE_NOT_ENFORCED)
    //   2. "every profile that does not override it permits every domain
    //      this list carries"   (ALLOW_DIRECTION_LIST_STANDING_EXPOSURE)
    //
    // They cannot both be true, and the false one is the first. The harm
    // is not the wording: the repair it prints is `warden lists remove`
    // then `warden lists add`, which destroys a working allow-list and
    // the exemption the operator configured on purpose.
    //
    // The asymmetry was manufactured one layer up, in the LOADER:
    // `auto_promote_blocklists` stamped `tags = ["uncategorized"]` on a
    // `base = deny` list and deliberately not on a `base = allow` one
    // (D2), and `orphan_legacy_sources` filtered on `!tags.is_empty()`.
    // Past tense throughout: that pass no longer exists in `src/` — see
    // the note on guard 3 in `check_device_metadata_vocabulary`.
    // So these helpers run the same two steps `config lint` runs, in the
    // same order. A test that called `validate_collect` alone would see
    // `tags = []` on BOTH branches, fail before the patch for the wrong
    // reason, and stop discriminating once the predicate is fixed.

    /// The pipeline `warden config lint` runs.
    ///
    /// **It used to run a loader-side promotion first** — the step that
    /// stamped `tags = ["uncategorized"]` on every untagged `base = deny`
    /// list, and deliberately not on a `base = allow` one, which is what
    /// manufactured the F24 asymmetry described above. `plp-s5a` removed
    /// the tag field, so there is nothing left to promote and the two
    /// branches now differ only in the word under test.
    fn lint_warnings(c: ConfigV1) -> Vec<String> {
        let mut warns = AuditWarnings::silent();
        let _ = validate_collect(&c, now(), &mut warns, None, None);
        warns.into_messages()
    }

    /// The two configs 4a compared. `trust = local` on both so the
    /// allow branch is not short-circuited by the unsigned-allow ack
    /// ERROR — the only difference that reaches the validator is the
    /// one word under test.
    fn f24_config(base: BlocklistBase) -> ConfigV1 {
        let mut c = basic_config();
        c.blocklists[0].base = base;
        c.blocklists[0].trust = BlocklistTrust::Local;
        c.lists.sources = vec![c.blocklists[0].url.clone()];
        c
    }

    #[test]
    fn f24_a_list_source_backed_by_an_allow_list_is_not_called_unreachable() {
        let deny = lint_warnings(f24_config(BlocklistBase::Deny));
        let allow = lint_warnings(f24_config(BlocklistBase::Allow));

        // Control arm. The deny branch never made this claim — without
        // it, an assertion on the allow branch alone would also pass
        // against a validator that had simply stopped emitting the
        // warning for everyone.
        assert!(
            !deny.iter().any(|m| m.contains("filters nothing")),
            "control arm broken: the deny branch must never claim the \
             source filters nothing. got: {deny:?}"
        );

        assert!(
            !allow
                .iter()
                .any(|m| m.contains("downloaded but filters nothing")),
            "F24: the source is backed by an enabled allow-direction list \
             that every profile inherits — calling it unreachable is false, \
             and the repair it prints deletes the list. got: {allow:?}"
        );
    }

    /// The half of the pair that is TRUE must survive. Deleting the
    /// false warning by silencing the whole check would pass the test
    /// above and leave the operator with no signal at all.
    #[test]
    fn f24_the_standing_exposure_warning_still_fires_on_the_allow_branch() {
        let allow = lint_warnings(f24_config(BlocklistBase::Allow));
        let expected = format_allow_direction_list_standing_exposure("privacy-ads");
        assert!(
            allow.contains(&expected),
            "the true half of the F24 pair must still be emitted. \
             expected {expected:?}, got: {allow:?}"
        );
    }

    /// The destructive repair must not be printed about a list that
    /// works. This is the operator-facing harm, asserted directly:
    /// `warden lists remove` on a working allow-list drops the
    /// exemption, and the next refresh does not bring it back.
    #[test]
    fn f24_no_remove_then_add_suggestion_for_a_working_allow_list() {
        let allow = lint_warnings(f24_config(BlocklistBase::Allow));
        assert!(
            !allow.iter().any(|m| m.contains("warden lists remove")),
            "a working allow-list must never be pointed at `lists remove`. \
             got: {allow:?}"
        );
    }

    // ── Sprint B T4 — auto-promote validator pass ─────────────────

    // ── tag_model_consolidation §3.2 — duplicate source URL ────────

    /// D3 as it exists on the live CT: two enabled lists pointing at
    /// one source. They share a cache file and its ETag, so this must
    /// be reported — and reported as a WARN, never an error.
    #[test]
    fn tmc_duplicate_url_groups_reports_both_ids() {
        let mut c = basic_config();
        c.blocklists = vec![blocklist("privacy-ads"), blocklist("ads")];
        c.blocklists[0].url = "https://lists.purge.cc/ads.txt".into();
        c.blocklists[1].url = "https://lists.purge.cc/ads.txt".into();
        let groups = duplicate_url_groups(&c);
        assert_eq!(groups.len(), 1, "one collision expected: {groups:?}");
        assert_eq!(groups[0].1, vec!["privacy-ads", "ads"]);
    }

    /// The point of the canonical key: a trailing slash / uppercase
    /// host / default port are the SAME source, and the byte-exact
    /// comparison this replaces missed all three.
    #[test]
    fn tmc_duplicate_url_groups_sees_through_cosmetic_url_differences() {
        let mut c = basic_config();
        c.blocklists = vec![blocklist("a"), blocklist("b"), blocklist("c")];
        c.blocklists[0].url = "https://lists.purge.cc/ads.txt".into();
        c.blocklists[1].url = "https://Lists.Purge.CC:443/ads.txt/".into();
        c.blocklists[2].url = "HTTPS://lists.purge.cc/ads.txt".into();
        let groups = duplicate_url_groups(&c);
        assert_eq!(groups.len(), 1, "{groups:?}");
        assert_eq!(groups[0].1, vec!["a", "b", "c"]);
    }

    /// Different paths are different sources — no false positive.
    #[test]
    fn tmc_duplicate_url_groups_silent_on_distinct_urls() {
        let mut c = basic_config();
        c.blocklists = vec![blocklist("ads"), blocklist("tracking")];
        c.blocklists[0].url = "https://lists.purge.cc/ads.txt".into();
        c.blocklists[1].url = "https://lists.purge.cc/tracking.txt".into();
        assert!(duplicate_url_groups(&c).is_empty());
    }

    /// A disabled twin downloads nothing, touches no cache file and
    /// burns no bitmask slot — warning about a config the operator has
    /// already neutralised is noise.
    #[test]
    fn tmc_duplicate_url_groups_ignores_disabled_lists() {
        let mut c = basic_config();
        c.blocklists = vec![blocklist("live"), blocklist("parked")];
        c.blocklists[0].url = "https://lists.purge.cc/ads.txt".into();
        c.blocklists[1].url = "https://lists.purge.cc/ads.txt".into();
        c.blocklists[1].enabled = false;
        assert!(duplicate_url_groups(&c).is_empty());
    }

    /// §2.1 hard constraint: the live config ALREADY contains a
    /// duplicate. If this ever became an error, the daemon would refuse
    /// to start and a household would lose DNS. Pin it as non-fatal.
    #[test]
    fn tmc_duplicate_url_is_warn_never_a_load_error() {
        let mut c = basic_config();
        c.blocklists = vec![blocklist("privacy-ads"), blocklist("ads")];
        c.blocklists[0].url = "https://lists.purge.cc/ads.txt".into();
        c.blocklists[1].url = "https://lists.purge.cc/ads.txt".into();
        let mut errs: Vec<ConfigError> = Vec::new();
        check_blocklists(&c, &mut errs, &mut AuditWarnings::emitting(), None);
        assert!(
            errs.is_empty(),
            "duplicate URLs must never be fatal at load: {errs:?}"
        );
    }

    // ── the W2.1 truth table, row by row ───────────────────────────
    //
    // | kind  | trust           | accept_unsigned_allow | outcome            |
    // |-------|-----------------|-----------------------|--------------------|
    // | deny  | any             | —                     | OK                 |
    // | allow | local           | —                     | OK                 |
    // | allow | remote-unsigned | false                 | ERROR (needs ack)  |
    // | allow | remote-unsigned | true                  | WARN, loads        |
    // | allow | signed          | any                   | ERROR (signed)     |
    //
    // Helper: run the full validator and hand back both channels, so a
    // row can assert on what did NOT fire as well as what did. Several
    // of these rows are about absence.
    fn validate_rows(c: &ConfigV1) -> (Vec<ConfigError>, Vec<String>) {
        let mut warns = AuditWarnings::silent();
        let errs = validate_collect(c, now(), &mut warns, None, None)
            .err()
            .unwrap_or_default();
        (errs, warns.into_messages())
    }

    // ── §4.66 L1 — [[labels]] ──────────────────────────────────────

    fn label(id: &str, kind: LabelKind, display_name: &str) -> Label {
        Label {
            id: Id::new(id).unwrap(),
            kind,
            display_name: display_name.into(),
            description: None,
        }
    }

    /// R1 — the pair is the identity, so the same id under two kinds is
    /// legal. The differential against the duplicate test below.
    #[test]
    fn labels_same_id_under_two_kinds_is_legal() {
        let mut c = basic_config();
        c.labels = vec![
            label("personal", LabelKind::Department, "Personal"),
            label("personal", LabelKind::DeviceType, "Personal"),
        ];
        let (errs, _) = validate_rows(&c);
        assert!(errs.is_empty(), "got: {errs:?}");
    }

    /// R1 — the same id under the SAME kind is a duplicate.
    #[test]
    fn labels_duplicate_pair_is_an_error() {
        let mut c = basic_config();
        c.labels = vec![
            label("personal", LabelKind::Department, "Personal"),
            label("personal", LabelKind::Department, "Personale"),
        ];
        let (errs, _) = validate_rows(&c);
        assert!(
            errs.iter()
                .any(|e| matches!(e, ConfigError::DuplicateId(_))),
            "got: {errs:?}"
        );
    }

    /// R3 — the near-duplicate that motivated the whole entity.
    /// `Personal` is declared, `Persona` is not, so only the second
    /// device warns.
    #[test]
    fn labels_warn_on_a_value_outside_the_vocabulary() {
        let mut c = basic_config();
        c.labels = vec![label("personal", LabelKind::Department, "Personal")];
        let mut ok = device("good", "10.0.0.1", None);
        ok.department = Some("Personal".into());
        let mut typo = device("typo", "10.0.0.2", None);
        typo.department = Some("Persona".into());
        c.devices = vec![ok, typo];

        let (errs, warns) = validate_rows(&c);
        assert!(errs.is_empty(), "a stray value must never fail the load");
        let hits: Vec<&String> = warns
            .iter()
            .filter(|w| w.contains("not declared in the [[labels]] vocabulary"))
            .collect();
        assert_eq!(hits.len(), 1, "exactly the typo must warn. got: {warns:?}");
        assert!(hits[0].contains("Persona"), "got: {}", hits[0]);
        assert!(hits[0].contains("department"), "got: {}", hits[0]);
    }

    /// R3 — the id also satisfies the vocabulary, not just the display
    /// name. Both spellings of the same label are inside.
    #[test]
    fn labels_accept_the_id_as_well_as_the_display_name() {
        let mut c = basic_config();
        c.labels = vec![label("alex", LabelKind::Owner, "Alex")];
        let mut by_id = device("a", "10.0.0.1", None);
        by_id.owner = Some("alex".into());
        let mut by_name = device("b", "10.0.0.2", None);
        by_name.owner = Some("Alex".into());
        c.devices = vec![by_id, by_name];

        let (_, warns) = validate_rows(&c);
        assert!(
            !warns
                .iter()
                .any(|w| w.contains("not declared in the [[labels]] vocabulary")),
            "got: {warns:?}"
        );
    }

    /// R3 — the guard that keeps this diagnostic readable. Every config
    /// on disk today has zero labels and plenty of metadata; if an empty
    /// vocabulary meant "nothing is legal", shipping the feature would
    /// paint every existing deployment red at every load.
    #[test]
    fn labels_empty_vocabulary_warns_about_nothing() {
        let mut c = basic_config();
        let mut d = device("a", "10.0.0.1", None);
        d.owner = Some("Alex".into());
        d.device_type = Some("Apple TV".into());
        d.department = Some("Persona".into());
        c.devices = vec![d];
        assert!(c.labels.is_empty());

        let (errs, warns) = validate_rows(&c);
        assert!(errs.is_empty(), "got: {errs:?}");
        assert!(
            !warns
                .iter()
                .any(|w| w.contains("not declared in the [[labels]] vocabulary")),
            "got: {warns:?}"
        );
    }

    /// R3 — a vocabulary declared for one kind must not police another.
    /// Declaring owners says nothing about which departments are legal.
    #[test]
    fn labels_one_kinds_vocabulary_does_not_police_another() {
        let mut c = basic_config();
        c.labels = vec![label("alex", LabelKind::Owner, "Alex")];
        let mut d = device("a", "10.0.0.1", None);
        d.owner = Some("Alex".into());
        d.department = Some("Persona".into()); // no department vocabulary
        c.devices = vec![d];

        let (_, warns) = validate_rows(&c);
        assert!(
            !warns
                .iter()
                .any(|w| w.contains("not declared in the [[labels]] vocabulary")),
            "got: {warns:?}"
        );
    }

    /// The WARN names the command that would adopt the value — warden
    /// must never adopt it itself.
    #[test]
    fn device_metadata_unknown_label_string_is_actionable() {
        let s = format_device_metadata_unknown_label("iphone", "owner", "Alex", "owner");
        assert!(s.contains("device \"iphone\".owner = \"Alex\""), "got: {s}");
        assert!(s.contains("warden label add"), "got: {s}");
        assert!(s.contains("--kind owner"), "got: {s}");
        assert!(!s.contains('{'), "every placeholder must be filled: {s}");
    }

    // ── §4.66 L5 — the `tag` kind ──────────────────────────────────

    /// GUARD 1, the other half — the constraint belongs to the tag
    /// namespace, not to the string. The very ids refused above are
    /// ordinary owners.
    #[test]
    fn labels_the_slug_constraint_binds_only_the_tag_kind() {
        let over_long = "a".repeat(33);
        let mut c = basic_config();
        c.labels = vec![
            label("4chan", LabelKind::Owner, "4chan"),
            label(&over_long, LabelKind::Department, "Long"),
        ];
        let (errs, _) = validate_rows(&c);
        assert!(errs.is_empty(), "got: {errs:?}");
    }

    /// Row 3 — the default posture. An operator who flips a remote list
    /// to allow-direction without saying anything is refused, and told
    /// what the risk is rather than just that the combination is
    /// forbidden.
    #[test]
    fn unsigned_allow_without_ack_is_refused() {
        let mut c = basic_config();
        // Default trust is RemoteUnsigned → flipping to Allow trips it.
        c.blocklists[0].base = BlocklistBase::Allow;
        let (errs, _) = validate_rows(&c);
        assert!(
            errs.iter().any(|e| matches!(
                e,
                ConfigError::UnsignedAllowListRequiresAck(ctx)
                    if ctx.reason.contains("'privacy-ads'")
                       && ctx.reason.contains("'remote-unsigned'")
            )),
            "expected UnsignedAllowListRequiresAck, got: {errs:?}"
        );
    }

    // ── plp-s4b: the same consent property at OVERRIDE scope ────────

    /// Put a `lists` override on the default profile naming blocklist 0.
    fn with_override(policy: ListPolicy) -> ConfigV1 {
        let mut c = basic_config();
        let id: Id = "privacy-ads".try_into().expect("valid id");
        c.profiles
            .get_mut("default")
            .expect("default profile")
            .lists
            .insert(id, policy);
        c
    }

    /// `plp-s4b` — an `allow` override on a remote-unsigned list with no ack
    /// is refused at load, naming BOTH the profile and the list.
    ///
    /// The list's own `base` stays `deny`, so `UNSIGNED_ALLOW_LIST_REQUIRES_ACK`
    /// at list scope does not fire: before this check the config loaded clean,
    /// with a live allow-direction override and consent declared nowhere.
    #[test]
    fn plp_s4b_unconsented_allow_override_is_refused_at_load() {
        let c = with_override(ListPolicy::Allow);
        assert_eq!(
            c.blocklists[0].base,
            BlocklistBase::Deny,
            "the list-scope check must not be what fires here"
        );
        let (errs, _) = validate_rows(&c);
        let hit = errs
            .iter()
            .find(|e| matches!(e, ConfigError::UnsignedAllowListRequiresAck(_)))
            .unwrap_or_else(|| panic!("expected a refusal, got: {errs:?}"));
        let ConfigError::UnsignedAllowListRequiresAck(ctx) = hit else {
            unreachable!()
        };
        assert!(
            ctx.reason.contains("privacy-ads"),
            "must name the list: {}",
            ctx.reason
        );
        assert!(
            ctx.reason.contains("default"),
            "must name the PROFILE too — the ack lives on the list's row but \
             the offence lives in the profile, and an error naming only the \
             list sends the operator to stare at a row that looks fine: {}",
            ctx.reason
        );
        assert!(
            ctx.suggestion.is_some(),
            "a refusal must name the knob that unblocks it"
        );
    }

    /// The control arm. Same override, same list, the operator's declaration
    /// on the row: it loads.
    ///
    /// Without this the test above would stay green on a check that refused
    /// every override of a remote list regardless of consent.
    #[test]
    fn plp_s4b_a_consented_allow_override_loads() {
        let mut c = with_override(ListPolicy::Allow);
        c.blocklists[0].accept_unsigned_allow = true;
        let (errs, _) = validate_rows(&c);
        assert!(
            !errs
                .iter()
                .any(|e| matches!(e, ConfigError::UnsignedAllowListRequiresAck(_))),
            "consent on the row must satisfy the override too, got: {errs:?}"
        );
    }

    /// `trust = local` is the operator's own file — no third party, nothing
    /// to consent to. Pins that the gate keys on trust, not on the word
    /// "allow".
    #[test]
    fn plp_s4b_an_allow_override_on_a_local_list_needs_no_ack() {
        let mut c = with_override(ListPolicy::Allow);
        c.blocklists[0].trust = BlocklistTrust::Local;
        let (errs, _) = validate_rows(&c);
        assert!(
            !errs
                .iter()
                .any(|e| matches!(e, ConfigError::UnsignedAllowListRequiresAck(_))),
            "got: {errs:?}"
        );
    }

    /// `Deny` and `Ignore` narrow what the profile permits, so they pay
    /// nothing — on the very list whose `Allow` is refused.
    ///
    /// Without this arm the refusal test would also pass on a check that
    /// refused every override of an unconsented remote list, which is a
    /// different bug wearing the same green.
    #[test]
    fn plp_s4b_deny_and_ignore_overrides_are_not_gated_at_load() {
        for policy in [ListPolicy::Deny, ListPolicy::Ignore] {
            let c = with_override(policy);
            let (errs, _) = validate_rows(&c);
            assert!(
                !errs
                    .iter()
                    .any(|e| matches!(e, ConfigError::UnsignedAllowListRequiresAck(_))),
                "{policy:?} must not be gated, got: {errs:?}"
            );
        }
    }

    /// A disabled list is still gated. It holds no source bit today, but
    /// `warden blocklist set <id> --enabled true` flips that back with
    /// nothing to re-run the gate — so the declaration is what is checked,
    /// not its current reachability.
    #[test]
    fn plp_s4b_a_disabled_list_does_not_exempt_the_override() {
        let mut c = with_override(ListPolicy::Allow);
        c.blocklists[0].enabled = false;
        let (errs, _) = validate_rows(&c);
        assert!(
            errs.iter()
                .any(|e| matches!(e, ConfigError::UnsignedAllowListRequiresAck(_))),
            "a disabled list must not buy an exemption, got: {errs:?}"
        );
    }

    /// Row 3, the operator-facing half: the refusal carries the frozen
    /// text and a suggestion naming the field that unblocks it. An
    /// error that refuses without saying which knob to turn is how this
    /// gate earned its reputation.
    #[test]
    fn unsigned_allow_refusal_carries_frozen_text_and_suggestion() {
        let mut c = basic_config();
        c.blocklists[0].base = BlocklistBase::Allow;
        let (errs, _) = validate_rows(&c);
        let ctx = errs
            .iter()
            .find_map(|e| match e {
                ConfigError::UnsignedAllowListRequiresAck(ctx) => Some(ctx),
                _ => None,
            })
            .expect("UnsignedAllowListRequiresAck present");
        assert_eq!(
            ctx.reason,
            format_unsigned_allow_list_requires_ack("privacy-ads", BlocklistTrust::RemoteUnsigned)
        );
        assert_eq!(ctx.entity.as_deref(), Some("blocklists.privacy-ads"));
        assert_eq!(
            ctx.suggestion.as_deref(),
            Some("set accept_unsigned_allow = true on this list if you trust its publisher, or set base = \"deny\" if this is a deny-direction list")
        );
    }

    // ── the sentinel is not an answer to "which tag?" ──────────────
    //
    // The CLI verbs and both TUI paths refuse this before writing. This
    // pass is the backstop for the surface none of them can see: a
    // hand-edited TOML, a file restored from a backup taken before the
    // gates existed, or a bundle arriving on a cluster secondary. It
    // lives in `check_blocklists`, which `validate_collect` runs, so the
    // initial load, the daemon's reload and `cluster::apply_bundle` all
    // inherit it rather than each needing to remember.

    /// End to end through the real parse-promote-validate path, from
    /// TOML an operator could have typed. The struct-level tests above
    /// prove the predicate; this proves the file never becomes a running
    /// config — which is the property the CLI and TUI gates cannot
    /// deliver, because neither of them is in the room when someone
    /// opens the file in an editor.
    #[test]
    fn a_hand_written_allow_list_tagged_with_the_sentinel_now_loads() {
        let src = r#"
schema_version = 3

[upstream]
servers = ["192.0.2.1:53"]

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[[blocklists]]
id = "guest-exemptions"
display_name = "Guest exemptions"
url = "https://example.com/guests.txt"
format = "domains"
base = "allow"
trust = "local"
tags = ["uncategorized"]
"#;
        // `plp-s3` §2.5: the hand-edited path was the ONLY one this ERROR
        // still guarded once the write verbs refused first. Both are retired
        // together — a load refusal for a reason the same binary's verbs no
        // longer apply is worse than no refusal, because the operator has no
        // way to see why the two disagree.
        super::super::load::load_from_str(src, None, now())
            .expect("the system-tag refusal is retired; this config must load");
    }

    /// The same file with the direction flipped loads. Together with the
    /// test above this pins that the refusal is about the pairing, not
    /// about the tag or the file.
    #[test]
    fn the_same_hand_written_list_loads_as_a_deny_list() {
        let src = r#"
schema_version = 3

[upstream]
servers = ["192.0.2.1:53"]

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[[blocklists]]
id = "guest-exemptions"
display_name = "Guest exemptions"
url = "https://example.com/guests.txt"
format = "domains"
base = "deny"
trust = "local"
tags = ["uncategorized"]
"#;
        super::super::load::load_from_str(src, None, now())
            .expect("a deny-list filed under the sentinel is the ordinary case");
    }

    /// Row 4 — the whole point of the change. Consent declared: the
    /// config LOADS, and the warning fires anyway so the risk stays
    /// visible at every single load rather than being acknowledged once
    /// and forgotten.
    #[test]
    fn unsigned_allow_with_ack_loads_and_warns() {
        let mut c = basic_config();
        c.blocklists[0].base = BlocklistBase::Allow;
        c.blocklists[0].accept_unsigned_allow = true;
        let (errs, warns) = validate_rows(&c);
        assert!(
            errs.is_empty(),
            "declared consent must load, got errors: {errs:?}"
        );
        assert!(
            warns.contains(&format_unsigned_allow_list_accepted("privacy-ads")),
            "expected the acceptance WARN, got: {warns:?}"
        );
    }

    /// Row 2 — a local file is authored by the operator, so there is no
    /// third party to trust and nothing to accept. It must stay silent:
    /// warning here would train operators to ignore the warning that
    /// matters.
    #[test]
    fn allow_with_local_trust_loads_without_the_unsigned_warn() {
        let mut c = basic_config();
        c.blocklists[0].base = BlocklistBase::Allow;
        c.blocklists[0].trust = BlocklistTrust::Local;
        let (errs, warns) = validate_rows(&c);
        assert!(
            errs.is_empty(),
            "kind=allow + trust=local must load: {errs:?}"
        );
        assert!(
            !warns.iter().any(|w| w.contains("is remote and unsigned")),
            "a local allow-list is not remote: {warns:?}"
        );
    }

    /// Row 2 again, with the ack set for good measure — a redundant
    /// flag on a local list must not conjure a warning about a remote
    /// risk that does not exist.
    #[test]
    fn ack_on_a_local_allow_list_is_inert() {
        let mut c = basic_config();
        c.blocklists[0].base = BlocklistBase::Allow;
        c.blocklists[0].trust = BlocklistTrust::Local;
        c.blocklists[0].accept_unsigned_allow = true;
        let (errs, warns) = validate_rows(&c);
        assert!(errs.is_empty(), "must still load: {errs:?}");
        assert!(
            !warns.iter().any(|w| w.contains("is remote and unsigned")),
            "ack must be inert on a local list: {warns:?}"
        );
    }

    /// Row 5 co-occurrence — unchanged behaviour. `allow` + `signed`
    /// with no ack emits BOTH errors, exactly as it did before the gate
    /// fell, so the operator sees the whole picture in one pass.
    #[test]
    fn allow_plus_signed_without_ack_emits_both_errors() {
        let mut c = basic_config();
        c.blocklists[0].base = BlocklistBase::Allow;
        c.blocklists[0].trust = BlocklistTrust::Signed;
        let (errs, _) = validate_rows(&c);
        assert!(
            errs.iter()
                .any(|e| matches!(e, ConfigError::UnsignedAllowListRequiresAck(_))),
            "expected the ack error alongside the signed one: {errs:?}"
        );
        assert!(
            errs.iter()
                .any(|e| matches!(e, ConfigError::TrustSignedNotYetSupported(_))),
            "expected TrustSignedNotYetSupported: {errs:?}"
        );
    }

    /// Row 5 with consent — a state the contract's table does not
    /// cover, so it is pinned here rather than left to be discovered.
    ///
    /// `signed` is still parked, so the config is still refused; that
    /// part is settled. The open question was the WARN, and it must NOT
    /// fire: its text says the list "is remote and unsigned", which of
    /// a `trust = signed` list is simply false. A warning that lies is
    /// worse than a missing one — it is the sentence an operator quotes
    /// back when the audit asks why they ignored it.
    #[test]
    fn allow_plus_signed_with_ack_is_still_refused_and_never_warns_unsigned() {
        let mut c = basic_config();
        c.blocklists[0].base = BlocklistBase::Allow;
        c.blocklists[0].trust = BlocklistTrust::Signed;
        c.blocklists[0].accept_unsigned_allow = true;
        let (errs, warns) = validate_rows(&c);
        assert!(
            errs.iter()
                .any(|e| matches!(e, ConfigError::TrustSignedNotYetSupported(_))),
            "signed stays parked regardless of consent: {errs:?}"
        );
        assert!(
            !errs
                .iter()
                .any(|e| matches!(e, ConfigError::UnsignedAllowListRequiresAck(_))),
            "consent satisfies the ack gate even on signed: {errs:?}"
        );
        assert!(
            !warns.iter().any(|w| w.contains("is remote and unsigned")),
            "must not claim a signed list is unsigned: {warns:?}"
        );
    }

    /// Row 1 — the untouched majority. A deny-direction list is the
    /// default and this whole pass must stay invisible to it, ack set
    /// or not.
    #[test]
    fn deny_direction_never_touched_by_the_ack_gate() {
        for ack in [false, true] {
            let mut c = basic_config();
            c.blocklists[0].base = BlocklistBase::Deny;
            c.blocklists[0].accept_unsigned_allow = ack;
            let (errs, warns) = validate_rows(&c);
            assert!(errs.is_empty(), "deny must load (ack={ack}): {errs:?}");
            assert!(
                !warns.iter().any(|w| w.contains("is remote and unsigned")),
                "deny must not warn (ack={ack}): {warns:?}"
            );
        }
    }

    #[test]
    fn trust_signed_alone_emits_only_signed_error() {
        // base = Deny + trust=Signed → only the parking-lot error fires;
        // the W2.1 (allow) check does NOT. S50 T2 also pins the
        // emitted `ErrorContext::reason` to the frozen
        // [`TRUST_SIGNED_NOT_YET_SUPPORTED`] string byte-for-byte; the
        // S49 T2 placeholder no longer leaks through.
        let mut c = basic_config();
        c.blocklists[0].trust = BlocklistTrust::Signed;
        let errs = validate(&c, now()).unwrap_err();
        let has_signed = errs
            .iter()
            .any(|e| matches!(e, ConfigError::TrustSignedNotYetSupported(_)));
        let has_allow = errs
            .iter()
            .any(|e| matches!(e, ConfigError::UnsignedAllowListRequiresAck(_)));
        assert!(
            has_signed,
            "expected TrustSignedNotYetSupported in: {errs:?}"
        );
        assert!(
            !has_allow,
            "UnsignedAllowListRequiresAck should NOT fire on kind=Deny: {errs:?}"
        );

        // Byte-for-byte: the offending error must carry the frozen
        // string verbatim (entity field localises which blocklist
        // tripped, but the reason text matches §9 row 5 exactly).
        let signed = errs
            .iter()
            .find_map(|e| match e {
                ConfigError::TrustSignedNotYetSupported(ctx) => Some(ctx),
                _ => None,
            })
            .expect("TrustSignedNotYetSupported variant present");
        assert_eq!(signed.reason, TRUST_SIGNED_NOT_YET_SUPPORTED);
        assert_eq!(signed.entity.as_deref(), Some("blocklists.privacy-ads"));
    }

    // ── §4.8 §2/2 T1: per-profile ECS validator ────────────────

    fn profile_with_ecs(ecs: super::super::ProfileEcsConfig) -> Profile {
        Profile {
            ecs: Some(ecs),
            ..profile_default()
        }
    }

    #[test]
    fn profile_ecs_subnet_prefix_v4_too_large_rejected() {
        let mut c = basic_config();
        c.profiles.insert(
            "tweaked".into(),
            profile_with_ecs(super::super::ProfileEcsConfig {
                mode: Some(super::super::super::settings::EcsMode::Subnet),
                source_prefix_v4: Some(33),
                source_prefix_v6: None,
            }),
        );
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            errs.iter().any(|e| matches!(
                e,
                ConfigError::ValidationFailed(ctx)
                    if ctx.reason.contains("source_prefix_v4") && ctx.reason.contains("33")
            )),
            "expected v4 prefix-range error, got: {errs:?}"
        );
    }

    #[test]
    fn profile_ecs_subnet_prefix_v6_too_large_rejected() {
        let mut c = basic_config();
        c.profiles.insert(
            "tweaked".into(),
            profile_with_ecs(super::super::ProfileEcsConfig {
                mode: Some(super::super::super::settings::EcsMode::Subnet),
                source_prefix_v4: None,
                source_prefix_v6: Some(129),
            }),
        );
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            errs.iter().any(|e| matches!(
                e,
                ConfigError::ValidationFailed(ctx)
                    if ctx.reason.contains("source_prefix_v6") && ctx.reason.contains("129")
            )),
            "expected v6 prefix-range error, got: {errs:?}"
        );
    }

    /// cfg-validator-05 (rev-2606): a set-but-out-of-range prefix is
    /// rejected even when `mode` is inherited (None) — pre-fix it loaded
    /// clean and `EdnsClientSubnet::new(..).ok()` silently disabled ECS
    /// for the profile at query time.
    #[test]
    fn profile_ecs_inherited_mode_out_of_range_prefix_rejected() {
        let mut c = basic_config();
        c.profiles.insert(
            "tweaked".into(),
            profile_with_ecs(super::super::ProfileEcsConfig {
                mode: None,
                source_prefix_v4: Some(200),
                source_prefix_v6: None,
            }),
        );
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            errs.iter().any(|e| matches!(
                e,
                ConfigError::ValidationFailed(ctx)
                    if ctx.reason.contains("source_prefix_v4") && ctx.reason.contains("200")
            )),
            "expected v4 prefix-range error with inherited mode, got: {errs:?}"
        );

        // In-range overrides with inherited mode stay valid.
        c.profiles.insert(
            "tweaked".into(),
            profile_with_ecs(super::super::ProfileEcsConfig {
                mode: None,
                source_prefix_v4: Some(24),
                source_prefix_v6: Some(56),
            }),
        );
        assert!(validate(&c, now()).is_ok());
    }

    #[test]
    fn profile_ecs_subnet_valid_prefixes_pass() {
        let mut c = basic_config();
        c.profiles.insert(
            "ok".into(),
            profile_with_ecs(super::super::ProfileEcsConfig {
                mode: Some(super::super::super::settings::EcsMode::Subnet),
                source_prefix_v4: Some(24),
                source_prefix_v6: Some(56),
            }),
        );
        assert!(validate(&c, now()).is_ok());
    }

    #[test]
    fn profile_ecs_coarse_rejects_out_of_range_prefixes() {
        // cfg-validator-05 (rev-2606): pre-fix, coarse ignored explicit
        // prefix values entirely (out-of-range accepted as inert). A set
        // value is now range-checked in every mode — coarse hardcodes
        // /24 + /56 at runtime, but a broken override would arm itself
        // the moment the operator switches the mode to subnet.
        let mut c = basic_config();
        c.profiles.insert(
            "coarse-anyway".into(),
            profile_with_ecs(super::super::ProfileEcsConfig {
                mode: Some(super::super::super::settings::EcsMode::Coarse),
                source_prefix_v4: Some(99),
                source_prefix_v6: Some(200),
            }),
        );
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            errs.iter().any(|e| matches!(
                e,
                ConfigError::ValidationFailed(ctx) if ctx.reason.contains("source_prefix_v4")
            )),
            "coarse + out-of-range prefix must be rejected: {errs:?}"
        );

        // In-range overrides under coarse stay valid (inert but legal).
        c.profiles.insert(
            "coarse-anyway".into(),
            profile_with_ecs(super::super::ProfileEcsConfig {
                mode: Some(super::super::super::settings::EcsMode::Coarse),
                source_prefix_v4: Some(24),
                source_prefix_v6: Some(56),
            }),
        );
        assert!(validate(&c, now()).is_ok());
    }

    #[test]
    fn profile_ecs_off_rejects_out_of_range_prefixes() {
        // cfg-validator-05 (rev-2606): same as coarse — `off` ignores the
        // fields at runtime, but a set-but-broken value is rejected at
        // lint so it cannot lie dormant.
        let mut c = basic_config();
        c.profiles.insert(
            "off".into(),
            profile_with_ecs(super::super::ProfileEcsConfig {
                mode: Some(super::super::super::settings::EcsMode::Off),
                source_prefix_v4: Some(99),
                source_prefix_v6: Some(200),
            }),
        );
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            errs.iter().any(|e| matches!(
                e,
                ConfigError::ValidationFailed(ctx) if ctx.reason.contains("source_prefix_v6")
            )),
            "off + out-of-range prefix must be rejected: {errs:?}"
        );
    }

    #[test]
    fn profile_ecs_absent_passes() {
        let mut c = basic_config();
        c.profiles
            .insert("none".into(), profile_with_ecs(Default::default()));
        // ecs subtable Some but every field None → no validation fires.
        assert!(validate(&c, now()).is_ok());
    }

    // ── §4.13 resource_budget ─────────────────────────────────

    #[test]
    fn resource_budget_tick_secs_zero_rejected() {
        let mut c = basic_config();
        c.resource_budget.tick_secs = 0;
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| matches!(e, ConfigError::ValidationFailed(ctx)
                if ctx.entity.as_deref() == Some("resource_budget.tick_secs"))),
            "expected ValidationFailed on resource_budget.tick_secs, got {errs:?}",
        );
    }

    #[test]
    fn resource_budget_rss_warn_mb_zero_rejected() {
        let mut c = basic_config();
        c.resource_budget.rss_warn_mb = 0;
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| matches!(e, ConfigError::ValidationFailed(ctx)
                if ctx.entity.as_deref() == Some("resource_budget.rss_warn_mb"))),
            "expected ValidationFailed on resource_budget.rss_warn_mb, got {errs:?}",
        );
    }

    #[test]
    fn resource_budget_defaults_pass() {
        // basic_config() inherits defaults via `..ConfigV1::test_scaffold()`,
        // which calls `ResourceBudgetConfig::default()` → tick_secs = 5,
        // rss_warn_mb derived. Validation must accept it.
        assert!(validate(&basic_config(), now()).is_ok());
    }

    // ── N1 — `[anti_bypass] enabled = true` with no domain source ──
    //
    // `AntiBypassConfig::default()` is `enabled = true, extra_domains =
    // []`, and `warden init` never writes the section — so this is the
    // state of essentially every install, including both live CTs. The
    // set is empty, `SecurityLayer::from_config` drops the checker to
    // `None`, and the operator's config asserts a protection that does
    // not exist. Dropping it is correct (see the handler); being silent
    // about it is not.

    /// Collect the audit WARNs a config raises, without touching the
    /// process-global tracing dispatcher (see [`AuditWarnings::silent`]).
    fn warns_for(c: &ConfigV1) -> Vec<String> {
        let mut warns = AuditWarnings::silent();
        let _ = validate_collect(c, now(), &mut warns, None, None);
        warns.into_messages()
    }

    #[test]
    fn n1_anti_bypass_enabled_with_no_domains_warns() {
        let c = basic_config();
        assert!(
            c.anti_bypass.enabled && c.anti_bypass.extra_domains.is_empty(),
            "precondition: the default shape is enabled-with-no-domains"
        );
        let warns = warns_for(&c);
        assert!(
            warns.iter().any(|w| w.contains("has no domains to block")),
            "expected ANTI_BYPASS_ENABLED_NO_DOMAINS, got: {warns:?}"
        );
    }

    // ── lint-warn-no-default-profile ──────────────────────────────────
    //
    // A config with no `default_profile` is VALID and the daemon then
    // REFUSES every unmatched query. That is a legitimate posture, so the
    // diagnostic is a WARN; the defect was that it was silent, and a fresh
    // install linted clean while answering nothing.

    #[test]
    fn no_default_profile_warns_that_level5_refuses_everything() {
        let c = basic_config();
        assert!(
            c.server.default_profile.is_none() && c.subnets.is_empty(),
            "precondition: this is the fresh-install shape the footgun needs"
        );
        assert!(
            validate(&c, now()).is_ok(),
            "it must stay VALID — a refusal here would break every operator \
             who chose the restrictive posture on purpose"
        );
        let warns = warns_for(&c);
        assert!(
            warns
                .iter()
                .any(|w| w.contains("will get REFUSED for every query")),
            "expected NO_DEFAULT_PROFILE_REFUSES_UNMATCHED, got: {warns:?}"
        );
    }

    #[test]
    fn a_set_default_profile_is_silent() {
        let mut c = basic_config();
        c.server.default_profile = Some(Id::new("default").unwrap());
        let warns = warns_for(&c);
        assert!(
            !warns.iter().any(|w| w.contains("will get REFUSED")),
            "level 5 resolves — nothing to warn about: {warns:?}"
        );
    }

    /// The suppression arm. Catch-alls in BOTH families answer level 4 for
    /// every client, so level 5 is unreachable and the warning would be
    /// noise.
    ///
    /// Without this test the check could be `default_profile.is_none()`
    /// alone and still pass the two above — i.e. the catch-all branch would
    /// be unproven, which is how a diagnostic starts crying wolf.
    #[test]
    fn a_catch_all_subnet_suppresses_the_level5_warning() {
        let mut c = basic_config();
        c.subnets = vec![Subnet {
            id: Id::new("everything").unwrap(),
            display_name: "Everything".into(),
            cidrs: vec!["0.0.0.0/0".into(), "::/0".into()],
            profile: Id::new("default").unwrap(),
            priority: 0,
        }];
        let warns = warns_for(&c);
        assert!(
            !warns.iter().any(|w| w.contains("will get REFUSED")),
            "/0 in both families covers level 4, so level 5 never runs: {warns:?}"
        );
    }

    /// The defect this split exists for. A v4 default route says nothing
    /// about IPv6 clients — `Cidr::contains` is family-strict — so they do
    /// still fall through to level 5 and get REFUSED. Suppressing the
    /// warning on the v4 entry alone is the diagnostic lying about the one
    /// condition it exists to report, on the ordinary shape of a dual-stack
    /// LAN handing out SLAAC addresses.
    #[test]
    fn v4_catch_all_alone_still_warns_for_v6() {
        let mut c = basic_config();
        c.subnets = vec![Subnet {
            id: Id::new("v4-only").unwrap(),
            display_name: "v4 only".into(),
            cidrs: vec!["0.0.0.0/0".into()],
            profile: Id::new("default").unwrap(),
            priority: 0,
        }];
        let warns = warns_for(&c);
        assert!(
            warns
                .iter()
                .any(|w| w.contains("will get REFUSED for every query")),
            "IPv6 is uncovered, so the warning must still fire: {warns:?}"
        );

        // And symmetrically: a v6-only default route leaves IPv4 on level 5.
        c.subnets[0].cidrs = vec!["::/0".into()];
        let warns = warns_for(&c);
        assert!(
            warns
                .iter()
                .any(|w| w.contains("will get REFUSED for every query")),
            "IPv4 is uncovered, so the warning must still fire: {warns:?}"
        );
    }

    #[test]
    fn cidr_catch_all_detection_is_exact() {
        assert_eq!(catch_all_family("0.0.0.0/0"), Some(CatchAll::V4));
        assert_eq!(catch_all_family("::/0"), Some(CatchAll::V6));
        assert_eq!(catch_all_family(" 0.0.0.0/0 "), Some(CatchAll::V4));
        // A /0 is the only default route; nothing else may suppress the warn.
        assert_eq!(catch_all_family("10.0.0.0/8"), None);
        assert_eq!(catch_all_family("0.0.0.0/24"), None);
        assert_eq!(catch_all_family("fd00::/8"), None);
        // Unparseable entries are check_subnets' error, not a catch-all.
        assert_eq!(catch_all_family("not-a-cidr"), None);
    }

    /// `Cidr::parse` reads the prefix with `str::parse::<u8>`, which accepts
    /// `00`. The textual `ends_with("/0")` test this replaced did not, so a
    /// real default route was read as an ordinary subnet — a spurious WARN,
    /// and `warden config lint` exits 2 on warnings.
    #[test]
    fn slash_double_zero_is_a_catch_all() {
        assert_eq!(catch_all_family("0.0.0.0/00"), Some(CatchAll::V4));
        assert_eq!(catch_all_family("::/00"), Some(CatchAll::V6));
    }

    #[test]
    fn no_default_profile_const_is_pinned() {
        assert_eq!(
            NO_DEFAULT_PROFILE_REFUSES_UNMATCHED,
            "[server].default_profile is unset — every client that is not a configured device and not inside a configured subnet will get REFUSED for every query. Set default_profile to a profile id if that is not what you intended."
        );
    }

    #[test]
    fn n1_anti_bypass_with_an_operator_domain_is_silent() {
        let mut c = basic_config();
        c.anti_bypass.extra_domains = vec!["doh.example.net".to_string()];
        let warns = warns_for(&c);
        assert!(
            !warns.iter().any(|w| w.contains("has no domains to block")),
            "a configured domain builds a real checker — no warning: {warns:?}"
        );
    }

    #[test]
    fn n1_anti_bypass_disabled_is_silent() {
        // Off-and-empty is coherent: the operator asserts nothing.
        let mut c = basic_config();
        c.anti_bypass.enabled = false;
        let warns = warns_for(&c);
        assert!(
            !warns.iter().any(|w| w.contains("has no domains to block")),
            "a disabled section must not warn: {warns:?}"
        );
    }

    // ── the master switch silently kills `[anti_bypass]` ───────────
    //
    // `SecurityLayer::from_config` returns an all-`None` layer when
    // `security.enabled` is false, short-circuiting before the branch
    // that would honour `anti_bypass.enabled`. Reproduced during the
    // neutrality-01 CT smoke, where a probe config disabled the security
    // layer to stop RRL throttling and a listed resolver name resolved
    // anyway — which read as "the change works" and proved nothing.

    #[test]
    fn master_switch_off_with_anti_bypass_on_warns() {
        let mut c = basic_config();
        c.security.enabled = false;
        c.anti_bypass.enabled = true;
        c.anti_bypass.extra_domains = vec!["doh.example.net".to_string()];
        let warns = warns_for(&c);
        assert!(
            warns
                .iter()
                .any(|w| w.contains("switches off every security sub-checker")),
            "expected SECURITY_DISABLED_DROPS_ANTI_BYPASS, got: {warns:?}"
        );
    }

    /// The predicate must key on `anti_bypass.enabled`, not on the
    /// domain list being non-empty. A populated list is the *worse*
    /// case — the operator did the work and gets nothing — but an empty
    /// one is still a config claiming a protection that is not running.
    #[test]
    fn master_switch_warn_does_not_depend_on_a_populated_list() {
        let mut c = basic_config();
        c.security.enabled = false;
        assert!(
            c.anti_bypass.extra_domains.is_empty(),
            "precondition: default shape has no domains"
        );
        let warns = warns_for(&c);
        assert!(
            warns
                .iter()
                .any(|w| w.contains("switches off every security sub-checker")),
            "got: {warns:?}"
        );
        // Both diagnostics fire here, deliberately: two different reasons
        // the section enforces nothing, two different remedies. Fixing
        // one leaves the other true.
        assert!(
            warns.iter().any(|w| w.contains("has no domains to block")),
            "the N1 warning must still fire alongside it: {warns:?}"
        );
    }

    /// Control arm. Without it the assertions above would pass just as
    /// well on a predicate that fired unconditionally.
    #[test]
    fn master_switch_on_is_silent() {
        let mut c = basic_config();
        assert!(
            c.security.enabled,
            "precondition: the master switch defaults on"
        );
        c.anti_bypass.enabled = true;
        let warns = warns_for(&c);
        assert!(
            !warns
                .iter()
                .any(|w| w.contains("switches off every security sub-checker")),
            "got: {warns:?}"
        );

        // …and an operator who stood the section down together with the
        // layer has a coherent config, so that is silent too.
        let mut c = basic_config();
        c.security.enabled = false;
        c.anti_bypass.enabled = false;
        let warns = warns_for(&c);
        assert!(
            !warns
                .iter()
                .any(|w| w.contains("switches off every security sub-checker")),
            "off-and-stood-down is coherent: {warns:?}"
        );
    }

    /// Same guard rail as N1's: WARN, never an error. A contradictory
    /// config still loads — the daemon aborts on any `ConfigError`, and
    /// refusing here would take DNS off the air over a contradiction the
    /// operator may have meant.
    #[test]
    fn master_switch_contradiction_is_a_warning_never_an_error() {
        let mut c = basic_config();
        c.security.enabled = false;
        c.anti_bypass.enabled = true;
        assert!(validate(&c, now()).is_ok(), "must not block the load");
    }

    // ── neutrality-04 — `safe_search = true` selects nothing ────────

    #[test]
    fn neutrality04_safe_search_profile_warns_that_the_flag_is_inert() {
        let mut c = basic_config();
        let mut p = profile_default();
        p.safe_search = true;
        c.profiles.insert("kids".into(), p);
        let warns = warns_for(&c);
        assert!(
            warns
                .iter()
                .any(|w| w.contains("no longer selects any rewrite")),
            "expected SAFE_SEARCH_FLAG_SELECTS_NOTHING, got: {warns:?}"
        );
        assert!(
            warns
                .iter()
                .any(|w| w.contains("profiles.kids:") && w.contains("no longer selects")),
            "the warning must name the profile it belongs to: {warns:?}"
        );
    }

    /// Fires on the flag alone. An operator who has `[[rewrites]]` AND
    /// the flag set still has an inert flag, so a warning that went
    /// quiet once any rewrite existed would read as "fixed" while
    /// nothing had changed.
    #[test]
    fn neutrality04_safe_search_warn_survives_authored_rewrites() {
        let mut c = basic_config();
        let mut p = profile_default();
        p.safe_search = true;
        p.rewrite_rules = vec![crate::config::settings::RewriteRule {
            from: "www.example-int".into(),
            to: "safe.example-int".into(),
            match_subdomains: false,
        }];
        c.profiles.insert("kids".into(), p);
        let warns = warns_for(&c);
        assert!(
            warns
                .iter()
                .any(|w| w.contains("no longer selects any rewrite")),
            "got: {warns:?}"
        );
    }

    /// Control arm: a profile that does not set the flag is silent.
    #[test]
    fn neutrality04_safe_search_off_is_silent() {
        let c = basic_config();
        assert!(
            !c.profiles["default"].safe_search,
            "precondition: the default profile does not set it"
        );
        let warns = warns_for(&c);
        assert!(
            !warns
                .iter()
                .any(|w| w.contains("no longer selects any rewrite")),
            "got: {warns:?}"
        );
    }

    /// The guard rail on the whole lane: this config is **valid**. Both
    /// live CTs carry it, and the daemon load path aborts on any
    /// `ConfigError` — turning this diagnostic fatal would take the
    /// house off DNS at the next restart.
    #[test]
    fn n1_anti_bypass_toothless_config_is_a_warning_never_an_error() {
        let c = basic_config();
        assert!(
            validate(&c, now()).is_ok(),
            "enabled-with-no-domains must never block the load"
        );
    }

    /// The warning must not send the operator somewhere that cannot
    /// work. Nothing joins a `[[blocklists]]` subscription to
    /// `AntiBypassConfig` — no field, no `BlocklistBase` variant, no CLI
    /// verb — so a list is a filter-engine path, not a checker source.
    #[test]
    fn n1_anti_bypass_warning_points_at_extra_domains_only() {
        let warns = warns_for(&basic_config());
        let w = warns
            .iter()
            .find(|w| w.contains("has no domains to block"))
            .expect("the warning must be present to check its remedy");
        assert!(
            w.contains("anti_bypass.extra_domains"),
            "the remedy must name the field that actually feeds the checker: {w}"
        );
    }

    fn custom_list_master(extra: &str) -> String {
        format!(
            r#"
schema_version = 3

[upstream]
servers = ["192.0.2.1:53"]

[server]
default_profile = "kids"

[[custom_lists]]
id = "minecraft"

[profiles.kids]
{extra}
"#
        )
    }

    #[test]
    fn a_duplicate_custom_list_id_is_refused() {
        let src = custom_list_master("").replace(
            "[profiles.kids]",
            "[[custom_lists]]\nid = \"minecraft\"\n\n[profiles.kids]",
        );
        let cfg: ConfigV1 = toml::from_str(&src).unwrap();
        let errs = validate(&cfg, now()).unwrap_err();
        assert!(
            errs.iter().any(|e| matches!(e, ConfigError::DuplicateId(c)
                if c.reason.contains("minecraft"))),
            "expected DuplicateId naming the id, got {errs:?}"
        );
    }

    #[test]
    fn a_custom_list_id_colliding_with_a_blocklist_id_is_refused() {
        // A NEW cross-kind rule. `labels` deliberately permits the same id
        // under two kinds; this does not, because the two entities are
        // adjacent in the operator's mental model and in the interface.
        let src = custom_list_master("").replace(
            "[[custom_lists]]",
            "[[blocklists]]\nid = \"minecraft\"\ndisplay_name = \"Minecraft\"\nurl = \"https://lists.example.invalid/a.txt\"\n\n[[custom_lists]]",
        );
        let cfg: ConfigV1 = toml::from_str(&src).unwrap();
        let errs = validate(&cfg, now()).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| matches!(e, ConfigError::DuplicateId(_))),
            "a custom list must not share an id with a blocklist, got {errs:?}"
        );
    }

    #[test]
    fn a_profile_naming_an_undeclared_custom_list_is_refused() {
        let src = custom_list_master("custom_lists = [\"nope\"]");
        let cfg: ConfigV1 = toml::from_str(&src).unwrap();
        let errs = validate(&cfg, now()).unwrap_err();
        assert!(
            errs.iter().any(|e| matches!(e, ConfigError::CrossRefMiss(c)
                if c.reason.contains("nope"))),
            "expected CrossRefMiss naming the id, got {errs:?}"
        );
    }

    #[test]
    fn a_profile_naming_a_declared_custom_list_validates() {
        // Negative control: without it, a validator that refuses every
        // mount would pass the test above.
        let src = custom_list_master("custom_lists = [\"minecraft\"]");
        let cfg: ConfigV1 = toml::from_str(&src).unwrap();
        assert!(
            validate(&cfg, now()).is_ok(),
            "a valid mount must be accepted"
        );
    }

    #[test]
    fn a_custom_list_mounted_by_nobody_is_reported() {
        let src = custom_list_master("");
        let cfg: ConfigV1 = toml::from_str(&src).unwrap();
        let inert = inert_custom_lists(&cfg);
        assert!(
            inert
                .iter()
                .any(|(id, r)| id.as_str() == "minecraft"
                    && *r == InertListReason::CustomListUnmounted),
            "an unmounted custom list must be reported: {inert:?}"
        );
    }

    #[test]
    fn a_mounted_custom_list_is_not_reported_as_unmounted() {
        // Negative control. Without it, a predicate that reports every
        // custom list passes the test above.
        let src = custom_list_master("custom_lists = [\"minecraft\"]");
        let cfg: ConfigV1 = toml::from_str(&src).unwrap();
        assert!(inert_custom_lists(&cfg).is_empty());
    }

    #[test]
    fn the_unmounted_report_reaches_the_lint_channel() {
        // `warden config lint` renders the messages the validator collects
        // in-band, so a diagnostic that only reached `tracing` would be
        // invisible there — the divergence that makes an operator stop
        // trusting the lint.
        let src = custom_list_master("");
        let cfg: ConfigV1 = toml::from_str(&src).unwrap();
        let mut warns = AuditWarnings::silent();
        validate_collect(&cfg, now(), &mut warns, None, None).expect("fixture must validate");
        let msgs = warns.into_messages();
        assert!(
            msgs.iter()
                .any(|m| m == &format_custom_list_unmounted("minecraft")),
            "the unmounted line must reach the lint channel: {msgs:?}"
        );
    }

    #[test]
    fn a_zero_file_cap_is_refused() {
        let src = custom_list_master("").replace(
            "[[custom_lists]]",
            "[custom_list_limits]\nmax_file_bytes = 0\n\n[[custom_lists]]",
        );
        let cfg: ConfigV1 = toml::from_str(&src).unwrap();
        let errs = validate(&cfg, now()).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e.to_string().contains("max_file_bytes")),
            "a zero cap makes every list unreadable at the next load, got {errs:?}"
        );
    }
}
