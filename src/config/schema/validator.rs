//! Semantic validation for [`ConfigV1`] — cross-reference checks, id
//! uniqueness, retired-id enforcement, and scalar invariants.
//!
//! Returns the complete list of problems (not just the first) so the
//! operator fixes the whole config in one pass.
//!
//! Serde handles the "wrong type" / "unknown field" layer; this module
//! handles everything the type system cannot express on its own.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use time::OffsetDateTime;

use super::super::cidr::Cidr;
use super::super::error::{ConfigError, ErrorContext};
use super::super::secrets::Secrets;
// Deliberate config→filter edge: admin rule text must be validated by the
// SAME parser the filter engine consumes, so `config lint` accepts exactly
// what the engine will enforce. A second hand-rolled grammar here would
// drift and re-create the silent-rule bug.
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
/// pick an exit code. This type is the data channel; the `tracing::warn!`
/// calls stay at their call sites, so journald output is unaffected.
///
/// `silent` exists for tests, which drive `validate_collect` directly and
/// must not write to the process-global `tracing` dispatcher while doing
/// it.
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
/// `now` is injected so tests can drive the retired-id 90-day window
/// deterministically.
///
/// Audit WARNs go to `tracing` only. Callers that also need them as data
/// (`warden config lint`) use [`validate_collect`].
/// Secrets-unaware form: the `auth_token_ref` cross-check is skipped. Kept
/// so [`crate::config::schema::load::load_from_str`] — whose signature the
/// whole codebase depends on — stays unchanged; the production loader
/// calls [`validate_collect`] with the resolved table instead.
pub fn validate(config: &ConfigV1, now: OffsetDateTime) -> Result<(), Vec<ConfigError>> {
    validate_collect(config, now, &mut AuditWarnings::emitting(), None, None)
}

/// [`validate`] plus an [`AuditWarnings`] collector: every operator WARN
/// raised during the pass is pushed into `warns` as well as (when
/// `warns.emit()`) logged on the `audit` tracing target.
/// `secrets` carries the resolved `secrets.toml` table when the caller has
/// one. `None` means "not available at this call site" and disables only
/// the `auth_token_ref` cross-check — never any other rule.
/// `provenance` follows the same convention exactly: the loader's
/// `entity_path → (file, line)` sidecar when the caller has one, `None`
/// otherwise, disabling only the cluster secondary-master cross-check.
/// Both are *data*, not filesystem access, so this stays a pure
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
            // `Cidr::parse` silently masks host bits, so an entry like
            // `192.168.1.5/8` (operator meant `/32`) widens this ACL by 24
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
    // An unspecified bind (0.0.0.0 / ::) with an empty allow_from answers
    // DNS for ANYONE who can route to the host — an open resolver
    // (amplification + cache-probe surface).
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
    // Scalar gates on the daemon-startup fields. A zero TCP timeout
    // expires every TCP query instantly; port 0 binds a kernel-chosen
    // ephemeral port — clients can never be pointed at it.
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

/// Validates the `retention_days` + `log_mode` knobs. Error messages
/// target non-experts — they name the exact field and the acceptable
/// range.
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
    // A zero interval feeds `Duration::from_secs(0)` into
    // `tokio::time::interval`, which panics — and the release profile's
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

/// `lists.update_interval_secs = 0`. The list manager already clamps its
/// refresh ticker to 60 s at construction, so a zero here is silently
/// reinterpreted rather than fatal — reject it so the operator's intent
/// and the running cadence cannot diverge without a diagnostic. Frozen
/// (pinned by `tests/frozen_strings_numeric_gates.rs`).
pub const LISTS_UPDATE_INTERVAL_ZERO: &str =
    "lists: `update_interval_secs` must be >= 1 (0 would stall the refresh \
     timer). The default is 43200 (12 hours).";

/// `lists.max_entries = 0`. The parser treats the cap as "truncate at N",
/// so 0 truncates every list to zero domains — the daemon runs normally
/// with filtering silently off. Frozen.
pub const LISTS_MAX_ENTRIES_ZERO: &str =
    "lists: `max_entries` must be >= 1 — 0 truncates every list to zero \
     domains, silently disabling filtering. The default is 20000000; raise \
     the value instead of using 0 for \"unlimited\".";

/// `lists.max_body_bytes = 0`. 0 aborts every download at the first byte,
/// so every list eventually flips Failed. Frozen.
pub const LISTS_MAX_BODY_BYTES_ZERO: &str =
    "lists: `max_body_bytes` must be >= 1 — 0 refuses every list download. \
     The default is 536870912 (512 MB).";

/// `lists.shrink_guard_max_drop_pct` out of the 1..=100 range. It is a
/// percentage: 0 would refuse a list that shrinks at all (and is
/// ambiguous with "disabled" — use `shrink_guard_enabled = false` for
/// that), and >100 is meaningless. Frozen (pinned by
/// `tests/frozen_strings_numeric_gates.rs`).
pub const LISTS_SHRINK_GUARD_PCT_INVALID: &str =
    "lists: `shrink_guard_max_drop_pct` must be 1..=100 — it is the percent \
     a list may shrink in one refresh before the prior list is kept. The \
     default is 90; set `shrink_guard_enabled = false` to disable the guard \
     instead of using 0.";

/// Validate the legacy `[lists]` pipeline section. These knobs drive the
/// blocklist download pipeline, so a bad scalar here degrades filtering
/// for every profile at once.
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

// ── [security] ──────────────────────────────────────────────

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

// ── `[anti_bypass]` enabled with nothing to enforce ──────────
//
// `AntiBypassConfig::default()` is `enabled = true, extra_domains = []`,
// and `warden init` never writes the section — so this is the state of
// essentially every install. Warden ships no compiled-in seed of
// resolver domains to fall back on, so the resulting set is empty, and
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
/// Names no provider, by construction — CLAUDE.md §Neutrality applies to
/// frozen strings too.
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
/// Names no provider, by construction — CLAUDE.md §Neutrality binds
/// frozen strings too.
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

// ── `safe_search = true` is now inert ────────────────────────────
//
// The flag used to make the resolver inject vendor CNAME rewrites
// compiled into the binary. That table was a neutrality violation and is
// gone; `profiles::safesearch::populate` now contributes nothing, so a
// profile serves the same rewrites with the flag set or clear.
//
// Retiring the field outright needs a schema change in
// `config/schema/profile.rs`. Until that happens, the honest thing is to
// say so on every load rather than let the config silently claim a
// protection that is not running.

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

/// `local_dns.ttl_secs` outside 1..=86400. The per-record override has
/// long carried this exact bound while the fallback — the value actually
/// stamped on every record without an override, on the NODATA negative
/// answer, and inherited by profile-scope records — was never checked: 0
/// loads clean and serves cache-busting 0-TTL answers. `{n}` substituted
/// at construction. Frozen (the template).
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

/// Validate the `[security.*]` scalar knobs. Every gate is scoped to its
/// sub-section's `enabled` flag (all default `true`), so a disabled
/// section with stale values cannot brick an existing config — the error
/// fires at the moment the value would start mattering.
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

/// WARN when `[anti_bypass]` is switched on with nothing to enforce.
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

// ── [cache] ─────────────────────────────────────────────────

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

/// `cache.stale_buffer_secs` above the 24 h cap. `{n}` substituted
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

/// Validate the `[cache]` scalar knobs. The TTL-pair check is
/// unconditional (the cache always runs); the prefetch threshold is
/// scoped to `prefetch = true`, matching the enabled-flag doctrine in
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
    // Cap the serve-stale window. Unconditional (the cache always
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

// ── [dnssec] ────────────────────────────────────────────────

/// A `[dnssec]` DoS cap is 0 while `mode != "off"`. The DNSSEC engine is
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

/// Validate the `[dnssec]` DoS caps. The section is parsed on every build
/// (the validation *machinery* is behind the default-off `dnssec` cargo
/// feature, the config struct is not), so the gate runs unconditionally —
/// scoped to `mode != off`, mirroring the enabled-flag doctrine: a default
/// `mode = "off"` section is inert no matter what the caps say.
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
/// through reserved-IP refusal, public-suffix-wildcard refusal, the
/// CNAME-loop / A+CNAME-conflict checks, or duplicate detection — while
/// the byte-identical record is refused per-profile. That asymmetry defeats
/// the "misconfig fails loudly at load time" guarantee.
fn check_local_dns(config: &ConfigV1, errs: &mut Vec<ConfigError>, warns: &mut AuditWarnings) {
    // The fallback TTL is checked even when the
    // global records list is empty — profile-scope records inherit it as
    // their fallback (resolver passes `config.local_dns.ttl_secs` into
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
/// set, but a profile with no per-profile override
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

// ── upstream / fallback / forwarding servers ───────────────────

/// `upstream.servers = []`. Boot fails on an empty server list anyway;
/// rejecting at lint closes the lint-vs-boot split — `config lint` is
/// sold as the pre-deploy gate. Frozen (pinned by
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

/// Validate every upstream server list at lint: the primary
/// `[upstream]`, the optional `[upstream.fallback]`, and each `[[forwarding]]`
/// zone (the three share an identical `Vec<String>` + [`UpstreamMode`] shape,
/// and a typo in any one bricks boot identically). Each list gets the same
/// treatment: non-empty, plus a per-entry shape
/// parse via the SAME functions the transport constructors run at boot
/// ([`crate::upstream::shape`]), so a malformed server fails `config lint`
/// instead of first boot. Shape failures are ERRORs (exit 1) — a malformed
/// entry bricks boot, it is not advisory. The shape check is offline (syntax,
/// not DNS resolvability — see the `shape` module doc).
fn check_upstream_servers(config: &ConfigV1, errs: &mut Vec<ConfigError>) {
    // A cluster secondary's master carries no policy — `[upstream]`
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
        // not do: hand-writing `[upstream]` is what the policy-free-master
        // guard below then refuses. This is a re-phrasing, not a second exemption: same check,
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

// ── [backup] ────────────────────────────────────────────────

/// Validate `backup.auto_interval` at lint. The typed parser + bounds
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

// ── [cluster] ────────────────────────────────────────────────

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
     Set it to the primary's API base URL, e.g. peer = \"https://10.10.1.94:8053\".";

/// An `allow_peer` entry is not a valid CIDR. `{entry}`/`{reason}` are
/// substituted at error-construction time. Frozen (the template, not the
/// substituted result).
pub const CLUSTER_ALLOW_PEER_INVALID_CIDR: &str =
    "cluster: `allow_peer` entry '{entry}' is not a valid CIDR ({reason}). \
     Use forms like 10.10.1.94/32 or 10.10.1.0/24.";

/// `role = "secondary"` but `peer` is not an acceptable URL.
/// `{peer}`/`{reason}` substituted at construction.
/// Frozen (the template).
pub const CLUSTER_SECONDARY_PEER_INVALID: &str =
    "cluster: `peer` '{peer}' is not a valid URL ({reason}). \
     Use the primary's https:// API base URL, e.g. peer = \"https://10.10.1.94:8053\".";

/// `enabled = true` with `poll_interval_secs = 0`. A zero period
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
/// success.
///
/// The offending sections are appended with their `file:line`. Frozen (pinned
/// by `tests/frozen_strings_cluster.rs`).
pub const CLUSTER_SECONDARY_MASTER_CARRIES_POLICY: &str =
    "cluster: this node is a secondary, so its policy arrives from the \
     primary — but the master config carries policy of its own. The loader \
     would MERGE the two, concatenating lists silently, and this node would \
     filter more than the primary does. Move these sections out of the \
     master (the primary supplies them):";

/// Refuse a cluster secondary whose master carries replicated policy.
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
/// carries per-entity keys (`blocklists.ads`), but the remedy is "move these
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
/// per-entity keys (`blocklists.ads`), but the remedy is "move these sections
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
/// If so it is not required to carry that policy in its own master —
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

/// Validate the `[cluster]` section — the structural invariants implied
/// at the schema level.
///
/// Rules:
/// - `enabled = true` ⇒ `token_hash` must be non-empty (a cluster
///   with no shared secret cannot authenticate).
/// - `role = "secondary"` ⇒ `peer` must be non-empty (a follower
///   needs a primary to poll).
/// - every `allow_peer` entry must parse as a CIDR — it gates a
///   defence-in-depth network check; malformed entries are rejected here
///   so they never reach that code path.
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

        // A zero poll period panics `tokio::time::interval`, which on
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
                // A secondary sends the plaintext
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

// ── [api] ───────────────────────────────────────────────────────

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

/// `metrics_enabled` on a non-loopback `api.listen`
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

/// Validate the `[api]` section.
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
///   WARN — `/metrics` is served unauthenticated
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

    // `/metrics` sits outside the auth layer by design,
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
/// elsewhere in the path is correctly ignored.
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

/// The config is valid, and the daemon will
/// REFUSE every query from any source it does not recognise.
///
/// This is the deliberate way to express "unmapped clients get nothing":
/// leaving `[server].default_profile` unset means resolver level 5 falls
/// through to REFUSED. That is a legitimate restrictive posture (the
/// default profile must be the strictest), so this is a **WARN and
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
        // Refuse credentials embedded in the URL
        // (`https://user:pass@host/…`). They would live in the 0640 master,
        // surface in `config show` / diff output, and bypass the secrets
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
        // Close the lint-vs-runtime split on a security control. The fetcher
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
        // The manager increments first, then
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
        // Length + control-char bounds
        // (emptiness already handled above with its frozen message).
        check_display_text(
            &b.display_name,
            &format!("blocklists.{}", b.id),
            "display_name",
            DISPLAY_NAME_MAX_BYTES,
            false,
            errs,
        );
        // No diagnostic here for an untagged or system-tagged allow-list:
        // direction is inherited by every profile from the list's own
        // `kind`, so such a list is maximally live rather than inert — a
        // diagnostic saying otherwise would describe behaviour the daemon
        // no longer has. The standing-exposure WARN for every
        // allow-direction list, regardless of tags, is emitted below in
        // `check_blocklist_base_trust`.

        // `auth_token_ref` must name a secret that exists.
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

/// Two or more **enabled** blocklists
/// resolving to the same canonical source URL.
///
/// **WARN, never fatal.** A duplicate blocklist pair is not a defect —
/// the resolver still works, just wastefully — so making this an error
/// would refuse to start over information rather than a failure.
/// `warden config lint` already
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
/// Reachability is
/// [`effective_direction`](super::blocklist::effective_direction) over
/// `base` + `profiles.<id>.lists` — a list's `tags` decide nothing about
/// whether it is reachable, so this correspondence check must not filter
/// on tags. Doing so once produced a false positive: a perfectly
/// reachable `base = allow` list, inherited by every profile, was
/// reported as unreachable immediately next to
/// [`ALLOW_DIRECTION_LIST_STANDING_EXPOSURE`] saying every profile
/// permits every domain it carries — two warnings about one list that
/// cannot both be true. Pinned by
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
        // Every list a profile names in its `lists` override must actually
        // exist.
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
            // The load-time half of the override consent
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
        // Per-profile local DNS records validation. The
        // helper lives in the legacy validator module so the global path
        // ([`check_local_dns`]) and this per-profile path share a single
        // implementation. It returns `Vec<String>`
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

        // Per-profile ECS policy validation. Range checks
        // fire whenever a prefix override is SET, regardless of `mode`:
        // with the mode inherited from
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

        // Per-profile rewrite_rules validation. Shadow warnings
        // consult the same profile's local_records AND the global
        // [local_dns] table — both precede
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

        // The flag is inert. Emitted before the audit
        // below so an operator reading the log sees WHY the audit found
        // nothing, rather than concluding their SafeSearch is healthy.
        if profile.safe_search {
            let msg = format!("profiles.{key}: {SAFE_SEARCH_FLAG_SELECTS_NOTHING}");
            if warns.emit() {
                tracing::warn!(target: "audit", entity = %entity, "{msg}");
            }
            warns.push(msg);
        }

        // SafeSearch effective-set audit.
        // Kept although `populate` no longer
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

// ── frozen string for soft-cap warning ─────────────────────────

/// Operator-facing warning emitted when a device's
/// `allow_rules + deny_rules` count exceeds the **soft cap** of 64.
/// Pinned byte-for-byte via `tests/frozen_strings_s43.rs`.
/// Operators see it via `tracing::warn!(target: "audit")` at validator
/// pass time — boot, reload, and any IPC-driven rewrite all run the
/// validator, so the warning surfaces wherever the cap is exceeded.
pub const LIST_PRUNE_WARN: &str =
    "Device '{id}' has {n} rules (soft cap: 64). Run `warden device rules {id} prune` to clean up dead refs.";

/// Substitute `{id}` and `{n}` into [`LIST_PRUNE_WARN`]. Kept on the
/// public surface so the frozen-strings test can exercise both the
/// const AND the template-substitution helper without re-implementing
/// the latter.
pub fn format_list_prune_warn(device_id: &str, n: usize) -> String {
    LIST_PRUNE_WARN
        .replace("{id}", device_id)
        .replace("{n}", &n.to_string())
}

/// Hard cap above which the validator refuses the
/// config. Beyond 128 entries on a single device the operator has
/// drifted far past the soft cap; the resolver chain continues to work,
/// but the operator experience (TUI Rules tab, prune CLI) starts to
/// degrade and a future memory-pressure incident becomes plausible.
pub const DEVICE_RULES_HARD_CAP: usize = 128;

// ── per-profile ECS validator frozen strings ───────────────────

/// IPv4 source-prefix out-of-range under
/// `[profiles.<key>.ecs] mode = "subnet"`. Frozen byte-for-byte by
/// `tests/frozen_strings_s48_ecs_profile.rs`.
pub const ECS_PROFILE_PREFIX_V4_OUT_OF_RANGE: &str =
    "profiles.{key}.ecs.source_prefix_v4: {n} is out of range 0..=32 — typical 24 \
     for CDN-routing accuracy, 0 to opt out of address forwarding per RFC 7871 \
     §7.1.2; drop the field to inherit from [upstream.ecs] or set mode = \"off\" \
     to disable ECS for this profile";

/// IPv6 source-prefix out-of-range under
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

/// Soft cap. Beyond 64 the validator emits a
/// frozen [`LIST_PRUNE_WARN`] but accepts the config.
pub const DEVICE_RULES_SOFT_CAP: usize = 64;

// ── operator free-text bounds ───────────────────────────────────

/// Byte cap for `display_name` on every entity.
const DISPLAY_NAME_MAX_BYTES: usize = 128;
/// Byte cap for device free-text metadata (`owner`, `device_type`,
/// `department`, `notes`).
const FREE_TEXT_MAX_BYTES: usize = 1024;

/// Shared bounds for operator free-text.
///
/// These strings flow verbatim into TUI rows and journal lines, so
/// control characters (newlines, tabs, ANSI escape sequences) are
/// refused as a terminal-injection surface, and multi-KB values (the
/// pasted-content typo class) are capped. `require_nonempty` is
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
        // Per-device overlay cross-refs + caps.
        // The dangling-id pass reuses the already-built `admin_rule_ids`
        // set: profile + device + group
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
            // daemon proceeds. This reaches journald on hot-reload
            // and is captured by `warden config lint`, but is NOT written to
            // the persistent audit.log — no audit-target layer routes to
            // AuditWriter, and at boot it is dropped entirely (`validate()`
            // runs before tracing is initialised).
            let msg = format_list_prune_warn(d.id.as_str(), total_rules);
            if warns.emit() {
                tracing::warn!(target: "audit", "{msg}");
            }
            warns.push(msg);
        }

        // `unfiltered = true` is no longer refused for having non-empty
        // `tags`. `unfiltered` short-circuits the resolver, so an
        // inherited tag is dead weight rather than a contradiction —
        // refusing the load would take a resolver down to correct a
        // field that changes nothing.
        //
        // `format_device_unfiltered_with_tags` is deliberately left
        // standing: `tests/frozen_strings_lc2_engine.rs` still imports the
        // const, and `cli/commands/devices.rs` still bails on the same
        // pairing. That leaves the CLI refusing what the validator now
        // accepts — the same CLI-refuses / validator-accepts asymmetry
        // CLAUDE.md documents for the allow-list tag gate.

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

        // The "this device is silently unfiltered" WARN moved to
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

/// The rules over `[[labels]]`, plus the WARN the vocabulary
/// raises against `[[devices]]`.
///
/// - `(kind, id)` is unique. The same `id` under two different
///   kinds is legal — `personal` may be both a department and a
///   device-type.
/// - a device metadata value outside its vocabulary is a **WARN**,
///   never an error.
///
/// There used to be a fourth kind, `tag`, whose id additionally had to
/// satisfy `check_tag_kind_id` as an ERROR — the alternative was a
/// declared name no entity could ever attach. That kind is gone, so the
/// three surviving kinds are treated identically, including by the
/// device-metadata WARN: every one of them has a
/// [`device_field`](LabelKind::device_field) to check against, which
/// `tag` did not. Uniqueness on the pair, display text and
/// description bounds are per-entry and kind-blind, as before.
fn check_labels(config: &ConfigV1, errs: &mut Vec<ConfigError>, warns: &mut AuditWarnings) {
    // Uniqueness on the PAIR. `collect_unique_ids` cannot be reused
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

/// WARN for a device metadata value no label declares.
///
/// **Silent when the vocabulary for that kind is empty**, and that guard
/// is the difference between a useful check and an unreadable one. A
/// config with no `[[labels]]` for a kind is not curating that
/// dimension, so warning about every metadata value would be red on
/// every healthy config that has not opted in — and a diagnostic that is
/// red on every healthy config stops being read, which costs more than
/// it ever catches. An empty vocabulary means "not curating this
/// dimension", not "nothing is legal".
///
/// Nothing is rewritten. The WARN names the value and the command that
/// would adopt it; the operator decides whether the value is a member of
/// the vocabulary or a typo.
///
/// `tag` has no counterpart here, deliberately: the `let Some(field)`
/// below drops it, because a tag is not a device field, and there is no
/// tag vocabulary left to be used-but-not-declared — `Device` has no
/// `tags` field, the loader strips the key, and `effective_direction`
/// over `base` + `profiles.<id>.lists` is what decides reachability. A
/// WARN about tag declarations would be red on **every** config rather
/// than merely on healthy ones — the same arithmetic as the
/// empty-vocabulary guard above.
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
    // Every (normalized CIDR, priority,
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
    // Byte-identical CIDR in ≥2 subnets at
    // EQUAL priority with DIFFERENT profiles is the subnet analogue of
    // the group-priority ambiguity below — the resolver tie-break (priority DESC,
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
                // Zero-length window guard, mirroring the carve-out
                // in `ParsedSchedule::parse`/`parse_v1`: `00:00-00:00` is
                // the canonical always-on form (midnight wrap covers the
                // whole day; `00:00-23:59` is
                // end-exclusive and leaves minute 23:59 unmatched).
                // Any other equal pair is almost
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
                // its expiry. No `errs.push`
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
        // Dry-run the engine's own parser so
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

/// Scalar invariants for the resource-budget sampler:
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

// ── group-priority conflict ─────────────────────────────────────

/// Detect the case where a device belongs to multiple groups that all
/// share the highest priority but resolve to different profiles. That
/// ambiguity is forbidden — the resolver would have no principled
/// way to pick one.
///
/// Membership is the union of BOTH join directions — group-side
/// `[[groups]].devices` and device-side `[[devices]].groups` — because
/// the resolver unions both (`profiles/resolver.rs::build_resolver_map`)
/// and the CLI/TUI join path writes the device side.
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

// ── kind/trust compatibility ────────────────────────────────────

/// Operator-facing message emitted when a blocklist declares
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

/// Operator-facing WARN emitted at **every** load for a blocklist
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
/// allow-direction branch.
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

/// Operator-facing message emitted when a blocklist declares
/// `trust = signed`. The signed-feed path is parked for a future
/// sprint; meanwhile the validator refuses the variant so a config
/// does not silently land in a state the daemon cannot honour.
///
/// **Parameterless.** No `{…}` placeholders — the value is constant.
/// The inline `tests` module below pins it as a defence-in-depth check.
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

// ── operator diagnostics for list reachability ────────────────────
//
// A retired generation of this block was keyed on a tag-based
// filtering model that no longer exists. What stands here now is its
// replacement, byte-pinned from outside the crate in
// `tests/frozen_strings_plp_profile_diagnostics.rs` — whose header
// carries a withdrawn -> replacement table, so a reader who greps a
// retired constant name lands on what took its place instead of on
// nothing.

/// Emitted when a profile filters on **no list at all** while the
/// config has at least one enabled list to filter on.
///
/// This replaces
/// the tag model's "device not filtered" WARN, and it is the same signal one
/// hop earlier: a device inherits its profile's policy, so a profile that
/// ignores every list leaves every device on it silently exposed. Asking per
/// device would repeat one profile's answer once per member.
///
/// **Guarded on the config having enabled lists**, deliberately: a config
/// with no lists yet is a fresh install, not a misconfiguration, and a WARN
/// that fires on every profile of every new config is a WARN nobody reads —
/// the failure mode CLAUDE.md §Neutrality documents twice for detectors.
///
/// WARN and not ERROR: a profile that deliberately filters nothing is
/// legitimate (a guest profile with `block_all`, an admin bypass). What is
/// forbidden is the **silence**, which is the same rule a list overridden to
/// `ignore` is held to.
///
/// `{id}` is the profile id.
pub const PROFILE_FILTERS_NO_LISTS: &str =
    "profile \"{id}\" filters on no list — every device resolving to it is unfiltered by lists";

/// Substitute `{id}` into [`PROFILE_FILTERS_NO_LISTS`].
pub fn format_profile_filters_no_lists(profile_id: &str) -> String {
    PROFILE_FILTERS_NO_LISTS.replace("{id}", profile_id)
}

/// Emitted when
/// `profiles.<id>.lists` names a blocklist id that no `[[blocklists]]`
/// entry defines.
///
/// **An ERROR, not a WARN, and that asymmetry is the whole point.** The
/// tag model this replaces let a profile name a tag that no list carried:
/// the operator expressed a segmentation intent, the loader
/// accepted it, and the intent was silently discarded — no error, no
/// warning, nothing in `warden status`. A
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

/// Emitted when
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

/// Emitted at
/// **every** load, for **every** trust, for each enabled allow-direction
/// list.
///
/// # Why this exists and why it is not a refusal
///
/// An allow-direction list permits its domains in every profile that does
/// not override it. That state used to be unreachable: the third
/// `allow_direction_gates` bail refused an allow-list tagged
/// `uncategorized`, on the grounds that the sentinel is *the widest audience
/// available*, dressed up as a choice, and that every list carries it
/// already through auto-promotion. With tags out of the filtering path that
/// premise is gone, and the refusal does not transfer: `allow` is a
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
/// legitimate **only if declared**. What is forbidden is the silence —
/// lists filtering nothing with no signal.
///
/// `{id}` is the blocklist id.
pub const ALLOW_DIRECTION_LIST_STANDING_EXPOSURE: &str =
    "allow-list \"{id}\" is allow-direction — every profile that does not override it permits every domain this list carries, at every refresh";

/// Substitute `{id}` into [`ALLOW_DIRECTION_LIST_STANDING_EXPOSURE`].
pub fn format_allow_direction_list_standing_exposure(blocklist_id: &str) -> String {
    ALLOW_DIRECTION_LIST_STANDING_EXPOSURE.replace("{id}", blocklist_id)
}

/// A list with `base = "ignore"` is loaded, refreshed, counted and shown,
/// and contributes **nothing** to any profile that does not override it.
/// That is a legitimate state — the operator asked for it — but it is
/// also a silent-zero-blocking hazard if nothing says so.
///
/// **What the old model bought and this replaces.** An orphan list used
/// to be impossible by construction: `auto_promote_blocklists`
/// stamped `uncategorized` on every untagged deny-list, so a list always
/// reached somebody. That sentinel is gone with the tag model, and this
/// buys the property back — not by forbidding the state, but by
/// refusing to let it be silent. It fires at **every** load, like
/// [`UNSIGNED_ALLOW_LIST_ACCEPTED`] and
/// [`ALLOW_DIRECTION_LIST_STANDING_EXPOSURE`], because the condition is
/// standing rather than a one-time write.
///
/// **Deliberately not emitted for a per-profile `ignore` override.** That
/// is the narrow form — one profile, reviewed, written next to the
/// profile it affects. Warning
/// on it would fire once per (profile, list) pair on a migrated config and
/// teach operators to skim past the one WARN here that means "this list
/// reaches nobody at all".
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

/// Emitted when `[server].default_profile`
/// is unset and no subnet carries a `/0`, so resolver level 5 REFUSES every
/// unmatched source.
///
/// Takes no substitution: the condition is a property of the whole config,
/// not of one entity.
pub const NO_DEFAULT_PROFILE_REFUSES_UNMATCHED: &str =
    "[server].default_profile is unset — every client that is not a configured device \
     and not inside a configured subnet will get REFUSED for every query. Set \
     default_profile to a profile id if that is not what you intended.";

/// A `http://` blocklist URL.
///
/// The fetcher is https-only, so this list can be lint-clean and still never
/// update. The message names the consequence, not just the rule, because the
/// symptom an operator actually sees is a list stuck at `Failed`.
///
/// `{id}` is the blocklist id.
pub const BLOCKLIST_URL_CLEARTEXT_HTTP: &str =
    "blocklist \"{id}\" uses a cleartext http:// URL — the downloader is https-only, \
     so this list will never update";

/// A blocklist URL whose host is an IP
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

/// Emitted when a device carries an `owner`,
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

/// Emitted when two or more enabled
/// blocklists resolve to the same canonical source URL.
///
/// Duplicates are not merely wasteful. `lists::manager::source_to_cache_stem`
/// derives the on-disk cache name from the **URL alone**, so twin entries
/// share one cache body and one `.meta` sidecar: they see each other's ETag,
/// a `304` for one silently satisfies the other, and the last writer wins the
/// body — while `ListStatus` stays keyed per-id and can disagree with the file
/// it points at. Each twin also burns one of the 64 bitmask slots.
///
/// WARN at load (never fatal — a duplicate is not a defect, and refusing
/// to start over it would take a working config offline); surfaces as an
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

// ── add-list pre-flight ─────────────────────────────────────────
//
// The Add-list flow runs three synchronous gates before persisting a
// new `[[blocklists]]` entry: URL parse, dedup, and reachability
// (HEAD probe with a 3-second timeout). Failure on the third gate
// bubbles the message below to the operator (TUI inline error or CLI
// stderr) so they can confirm the URL with a browser before retrying.
// The `--skip-head-check` CLI flag and the modal's advanced affordance
// bypass the probe for operators who already trust the source.

/// Emitted when the synchronous reachability probe on a
/// new blocklist URL fails (timeout, non-2xx, network error). Hard
/// block; advanced operators bypass via
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
/// 1. **Allow-direction consent.** A blocklist with `base = allow`
///    whose trust is not `local` is refused *unless* the operator set
///    `accept_unsigned_allow = true` on it; with the flag it loads and
///    raises a standing WARN instead.
/// 2. **Parking-lot enforcement for `trust = signed`.** The signed-feed
///    path is not supported yet; meanwhile we refuse the
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
/// **The allow direction stays soft.** Nothing here widens it:
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

        // The standing-exposure WARN, for EVERY trust.
        //
        // An allow-direction list permits its domains in every profile that
        // does not override it. That state used to be unreachable:
        // `allow_direction_gates` refused an untagged one, and refused a
        // `uncategorized`-tagged one as "the widest audience wearing a
        // choice's clothes". Tags no longer decide, so that refusal has lost
        // its premise — and the refusal does not transfer, because refusing a
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

        // The `base = "ignore"` twin of the WARN above.
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

/// [`PROFILE_FILTERS_NO_LISTS`]: every profile that ignores every
/// enabled list.
///
/// Direction per pair comes from [`effective_direction`], the same predicate
/// the publish-time projection uses. A second copy of the inheritance
/// rule here matters: the validator must see the same superset the
/// resolver applies, or the coverage WARN goes silent on devices that
/// really are uncovered — a false negative on a safety signal.
///
/// **This is the substitute for two withdrawn tag-based passes:**
///
/// - One asked whether a profile contributed any tags. A profile's
///   contribution is now its list policy, and "contributes nothing" is
///   exactly the condition below — one hop *later*, so it catches a case
///   the tag version could not: a profile carrying tags that no list
///   happened to match still looked healthy to it.
/// - The other asked the mirror question of a list. That one has **no**
///   replacement here and its partial replacement lives in
///   [`inert_blocklists`] — see the gap recorded there.
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
/// **One variant, deliberately.** A tag-keyed pair of variants used to
/// stand here and was removed: one of them was actively false, reporting
/// an untagged allow-direction list as filtering nothing, when such a
/// list is inherited by every profile that does not override it. An
/// operator acting on it would remove a working exemption.
///
/// Keep it a single-variant enum rather than collapsing it to a unit: the
/// gap recorded on [`inert_blocklists`] needs a second reason (*declared
/// inert* and *made inert by unanimous override* are different facts for an
/// operator), and a `match` is where that lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InertListReason {
    /// `base = "ignore"` and no profile overrides it to anything else.
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

/// Every blocklist that is installed
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
/// that no longer decides anything, and the first one made a false claim
/// at this surface — an allow-direction list every profile inherits,
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
        // A future `retired_at` is nonsensical — an entity can't
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
                // State the window END (actionable) — all entries here have a
                // past retired_at (future ones errored above).
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
mod tests;
