//! Version-1 configuration schema — the in-memory data model that drives
//! the purge-warden daemon.
//!
//! This module owns every entity struct (Blocklist, Profile, Device, Group,
//! Subnet, Schedule, AdminRule) and the top-level [`ConfigV1`]
//! aggregate. Every struct applies `#[serde(deny_unknown_fields)]` so that
//! typos surface at load time, and every id field uses the [`id::Id`]
//! newtype so that charset / length invariants are enforced at
//! construction (parse-don't-validate).
//!
//! `ConfigV1` is the **single source of truth** for the
//! daemon: the master `config.toml` carries both entity-model sections
//! (`[[devices]]`, `[[groups]]`, `[[subnets]]`, `[[schedules]]`,
//! `[[blocklists]]`, `[[admin_rules]]`, `[profiles.*]`, `[[retired]]`)
//! **and** the daemon-wide sections (`[upstream]`, `[cache]`, `[tracking]`,
//! `[security]`, `[socket]`, `[api]`, `[forwarding]`, `[local_dns]`,
//! `[ip_blocklists]`, `[anti_bypass]`, `[lists]`). The latter are held as
//! pass-through fields that reuse the legacy [`crate::config::settings`]
//! types unchanged.

pub mod admin_rule;
pub mod backup;
pub mod blocklist;
pub mod cluster;
pub mod custom_list;
pub mod device;
pub mod group;
pub mod id;
pub mod label;
pub mod load;
pub mod profile;
pub mod resource_budget;
pub mod retired;
pub mod retired_keys;
pub mod schedule;
pub mod subnet;
pub mod validator;

pub use admin_rule::AdminRule;
pub use backup::BackupConfig;
pub use blocklist::{
    effective_direction, Blocklist, BlocklistBase, BlocklistFormat, BlocklistTrust, ListPolicy,
};
pub use cluster::{ClusterConfig, ClusterRole};
pub use custom_list::{CustomList, CustomListLimits, DEFAULT_MAX_FILE_BYTES};
pub use device::Device;
pub use group::Group;
pub use id::Id;
pub use label::{Label, LabelKind};
pub use profile::{BlockResponseV1, Profile, ProfileEcsConfig};
pub use resource_budget::ResourceBudgetConfig;
pub use retired::{RetiredEntry, RetiredType, RETIREMENT_WINDOW_DAYS};
pub use schedule::{Schedule, ScheduleTargetType};
pub use subnet::Subnet;

use std::collections::BTreeMap;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::config::settings::{
    AntiBypassConfig, ApiConfig, CacheConfig, DnssecConfig, ForwardingZoneConfig,
    IpBlocklistConfig, ListsConfig, LocalDnsConfig, SecurityConfig, SocketConfig, TrackingConfig,
    UpstreamConfig,
};

/// Fixed schema discriminant. Declared as a `u32` rather than a phantom
/// enum variant so the TOML representation is a plain integer:
/// `schema_version = 3`. The validator (or manual check) rejects any
/// value other than [`SCHEMA_VERSION_V1`]. The legacy name
/// `SCHEMA_VERSION_V1` is kept to minimise churn on call sites; treat the
/// constant as "the schema version this binary supports", whatever the
/// numeric value is.
///
/// **A bump is an OUTAGE risk, not a code risk, and the remedy is an
/// ORDER.** `check_schema_version`
/// demands equality, not `>=`, so an older version on disk under a newer
/// binary is *refused*, not degraded: the daemon does not start. Every
/// upgrade path that installs this binary must therefore migrate and lint
/// **before** it restarts anything, and abort while the old daemon is
/// still serving if either step fails. That sequence lives in
/// `scripts/upgrade_config_gate.sh`, is called by `make upgrade` and by
/// `scripts/install.sh` Phase 3.5, and is fenced by
/// `scripts/check_upgrade_config_gate.sh`.
pub const SCHEMA_VERSION_V1: u32 = 3;

fn default_blocked_ttl_secs() -> u32 {
    60
}

fn default_listen() -> SocketAddr {
    "127.0.0.1:15353".parse().unwrap()
}

fn default_log_level() -> String {
    "info".into()
}

fn default_tcp_timeout_secs() -> u64 {
    10
}

/// `pub(crate)` so `cluster::policy::ClusterServerPolicy` can point its own
/// serde default at the SAME function rather than re-declaring the value. It
/// carried a bare `#[serde(default)]` — `bool::default()` = `false` — so a
/// bundle with a present-but-partial `[server]` table silently disabled MAC
/// enforcement.
///
/// **Named in a code span, deliberately not linked.** `src/cluster/` is behind
/// `#[cfg(feature = "cluster")]` and that feature is OFF by default, so an
/// intra-doc link here does not resolve in an ordinary `cargo doc` — and
/// `RUSTDOCFLAGS="-D rustdoc::broken_intra_doc_links"` turns that into a build
/// failure. Any doc reference from ungated code into a feature-gated module
/// has to stay prose.
pub(crate) fn default_enforce_device_mac() -> bool {
    true
}

/// Globals under the `[server]` table.
///
/// Carries two groups of fields:
///
/// - **Resolver defaults** used by the 5-level resolver chain:
///   [`Self::default_profile`] is the level-5 fallback, and the
///   [`Self::default_block_response`] / [`Self::default_blocked_ttl_secs`]
///   fields are the per-profile fallbacks.
/// - **Daemon-startup** fields ported 1:1 from the legacy
///   [`crate::config::settings::ServerConfig`]:
///   [`Self::listen`] / [`Self::log_level`] / [`Self::tcp_timeout_secs`]
///   / [`Self::enforce_device_mac`] / [`Self::allow_from`]. These live
///   here so the daemon can boot directly from a `ConfigV1` without a
///   second parse pass against legacy `Settings`.
///
/// The `block_unmapped_clients` flag is **gone** in v1. Its effect
/// is now expressed by leaving [`Self::default_profile`] unset (`None`)
/// → level-5 resolves to REFUSED.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerGlobals {
    /// Address the DNS server binds to (UDP+TCP).
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// `tracing` filter level (`trace` / `debug` / `info` / `warn` / `error`).
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Idle timeout (seconds) for incoming TCP connections.
    #[serde(default = "default_tcp_timeout_secs")]
    pub tcp_timeout_secs: u64,
    /// Verify the device's MAC at query time for devices that pin one.
    /// Ergonomic safeguard — carried forward into v1 unchanged.
    ///
    /// Renamed from `enforce_client_mac`; the serde alias plus the
    /// loader WARN branch accept the legacy key for one release cycle.
    #[serde(default = "default_enforce_device_mac", alias = "enforce_client_mac")]
    pub enforce_device_mac: bool,
    /// Source-IP allow list (CIDRs) for incoming DNS queries. Empty
    /// means "no ACL, accept every source the bind address reaches".
    #[serde(default)]
    pub allow_from: Vec<String>,
    /// Profile used by level 5 of the resolver chain when no
    /// device / group / subnet matches. `None` → REFUSED.
    #[serde(default)]
    pub default_profile: Option<Id>,
    /// Fallback block response when a profile's
    /// [`profile::Profile::block_response`] is `None`.
    #[serde(default)]
    pub default_block_response: BlockResponseV1,
    /// Fallback TTL (seconds) when a profile's
    /// [`profile::Profile::blocked_ttl_secs`] is `None`.
    #[serde(default = "default_blocked_ttl_secs")]
    pub default_blocked_ttl_secs: u32,
}

/// Manual `Default` so the rust-side fallback matches the serde-side
/// `#[serde(default = …)]` expressions. `#[derive(Default)]` would give
/// numeric zero / empty strings which the validator then rejects — creating
/// a surprising failure mode for any caller that constructs
/// [`ConfigV1`] or [`ServerGlobals`] by `Default` with no `[server]`
/// section.
impl Default for ServerGlobals {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            log_level: default_log_level(),
            tcp_timeout_secs: default_tcp_timeout_secs(),
            enforce_device_mac: default_enforce_device_mac(),
            allow_from: Vec::new(),
            default_profile: None,
            default_block_response: BlockResponseV1::default(),
            default_blocked_ttl_secs: default_blocked_ttl_secs(),
        }
    }
}

/// The top-level v1 configuration, as parsed from `config.toml` after
/// include resolution.
///
/// The master file holds every top-level section the daemon needs at boot
/// time: entity-model collections ([`Self::devices`], [`Self::groups`],
/// [`Self::subnets`], [`Self::schedules`], [`Self::blocklists`],
/// [`Self::admin_rules`], [`Self::profiles`]) plus the daemon-wide
/// pass-through tables ([`Self::upstream`], [`Self::cache`],
/// [`Self::tracking`], …) that still reuse the legacy
/// [`crate::config::settings`] types. The pass-through fields land here
/// so the daemon can boot from a single `load_config` call.
///
/// `profiles` is a named-map (`[profiles.<id>]`)
/// while every other entity collection is an array-of-tables. The map
/// key is the profile id — the validator ensures every key parses as a
/// valid [`Id`].
/// Note on `PartialEq`: the pass-through sections (e.g.
/// [`UpstreamConfig`], [`CacheConfig`]) are legacy types that do not
/// implement `PartialEq`, so neither does `ConfigV1`. Tests that want to
/// assert two configs are semantically identical should compare on
/// `toml::to_string(&config)` instead.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigV1 {
    /// Must equal [`SCHEMA_VERSION_V1`]. Enforced by
    /// [`validator::validate`].
    pub schema_version: u32,

    /// Glob patterns for include resolution. Empty in a single-file
    /// deployment.
    #[serde(default)]
    pub includes: Vec<String>,

    #[serde(default)]
    pub server: ServerGlobals,

    #[serde(default)]
    pub retired: Vec<RetiredEntry>,

    #[serde(default)]
    pub blocklists: Vec<Blocklist>,

    /// Named-map of profiles. Keys are id strings; the validator
    /// converts each to [`Id`] at load time, so a key like `"BAD ID"`
    /// surfaces as a [`crate::config::error::ConfigError::InvalidId`].
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,

    /// Accepts the legacy `[[clients]]` section name via serde alias
    /// so older masters continue to parse. Pairs with
    /// the loader's `normalise_deprecated_keys` branch which also
    /// emits the deprecation WARN at load time (belt-and-braces:
    /// the serde alias covers direct `toml::from_str::<ConfigV1>` paths
    /// that bypass the loader).
    #[serde(default, alias = "clients")]
    pub devices: Vec<Device>,

    #[serde(default)]
    pub groups: Vec<Group>,

    #[serde(default)]
    pub subnets: Vec<Subnet>,

    #[serde(default)]
    pub schedules: Vec<Schedule>,

    #[serde(default)]
    pub admin_rules: Vec<AdminRule>,

    /// Operator-authored rule files. Each compiles into the admin-rule seat
    /// of every profile that mounts it; none consumes a source bit.
    #[serde(default)]
    pub custom_lists: Vec<CustomList>,

    /// Ceilings for the custom-list file reader. Named `custom_list_limits`
    /// because `custom_lists` is already the entity array, and TOML cannot
    /// hold both under one name.
    #[serde(default)]
    pub custom_list_limits: CustomListLimits,

    /// The controlled vocabulary for the device metadata
    /// fields and for tag slugs. Advisory only: nothing in the resolver
    /// chain consults it, and a device value outside the vocabulary
    /// loads with a WARN rather than an error.
    ///
    /// `#[serde(default)]` is load-bearing, not decoration: no config
    /// that exists today carries a `[[labels]]` key, and the two boxes
    /// that would stop deserialising without it serve household DNS.
    #[serde(default)]
    pub labels: Vec<Label>,

    // ── pass-through sections ─────────────────────────────────────
    //
    // These carry the daemon-wide config that has not yet been ported
    // to a fresh v1 shape. Reuse the legacy structs 1:1.
    // `deny_unknown_fields` on `ConfigV1` still catches any
    // typo at the top level; typos inside these sections fall through
    // to the legacy deserialiser (no `deny_unknown_fields` on most
    // legacy types, same as on v0).
    #[serde(default)]
    pub upstream: UpstreamConfig,

    /// DNSSEC validation of upstream answers. Opt-in, OFF by default;
    /// the whole `[dnssec]` section may be omitted. Parsed unconditionally so a
    /// `mode = "validate"` config deserialises on any build. The validation
    /// machinery is behind the default-OFF `dnssec` cargo feature.
    #[serde(default)]
    pub dnssec: DnssecConfig,

    #[serde(default)]
    pub cache: CacheConfig,

    #[serde(default)]
    pub tracking: TrackingConfig,

    #[serde(default)]
    pub security: SecurityConfig,

    #[serde(default)]
    pub anti_bypass: AntiBypassConfig,

    #[serde(default)]
    pub socket: SocketConfig,

    #[serde(default)]
    pub api: ApiConfig,

    #[serde(default)]
    pub forwarding: Vec<ForwardingZoneConfig>,

    #[serde(default)]
    pub local_dns: LocalDnsConfig,

    #[serde(default, alias = "ip_denylists")]
    pub ip_blocklists: IpBlocklistConfig,

    /// Legacy `[lists]` section — retained as the driver for the blocklist
    /// download pipeline. Every list id
    /// referenced by a profile must match a `lists.sources` entry.
    #[serde(default)]
    pub lists: ListsConfig,

    /// Sampler cadence + RSS warn threshold. Omit the whole
    /// `[resource_budget]` section to inherit the defaults
    /// (`tick_secs = 5`, `rss_warn_mb = 50% of /proc/meminfo MemTotal`
    /// or `256` MB if meminfo is unreadable).
    #[serde(default)]
    pub resource_budget: ResourceBudgetConfig,

    /// `[backup]` — where `warden config backup` writes archives and the
    /// TUI restore picker reads them. Tooling-only (the daemon ignores
    /// it). Omit the section to default to `<config-parent>/backups`.
    #[serde(default)]
    pub backup: BackupConfig,

    /// Primary/secondary cluster replication. Opt-in, OFF by
    /// default; the whole `[cluster]` section may be omitted. Parsed +
    /// validated unconditionally. Node-local
    /// identity: never replicated to a peer.
    #[serde(default)]
    pub cluster: ClusterConfig,
}

/// Manual `Default` so a Rust-side `ConfigV1::default()` carries a real
/// `schema_version`. `#[derive(Default)]` gave
/// `schema_version = 0`, which [`validator::validate`] unconditionally
/// rejects — the exact trap the [`ServerGlobals`] manual impl above
/// documents, reintroduced one struct down. `schema_version` has no
/// `#[serde(default)]`, so the parse path is unaffected: a TOML missing
/// the key still fails to deserialize.
///
/// **This is deliberately NOT a config that validates.**
/// `upstream.servers` has no default (see
/// [`crate::config::settings::UpstreamConfig::servers`]), so the default
/// names no resolver and [`validator::validate`] refuses it with
/// `UPSTREAM_SERVERS_EMPTY`. That refusal is the whole point: warden will
/// not pick a resolver on the operator's behalf. Test fixtures that need a
/// config which *does* validate use `ConfigV1::test_scaffold` (test-only,
/// defined at the foot of this file).
impl Default for ConfigV1 {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION_V1,
            includes: Vec::new(),
            server: ServerGlobals::default(),
            retired: Vec::new(),
            blocklists: Vec::new(),
            profiles: BTreeMap::new(),
            devices: Vec::new(),
            groups: Vec::new(),
            subnets: Vec::new(),
            schedules: Vec::new(),
            admin_rules: Vec::new(),
            custom_lists: Vec::new(),
            custom_list_limits: CustomListLimits::default(),
            labels: Vec::new(),
            upstream: UpstreamConfig::default(),
            dnssec: DnssecConfig::default(),
            cache: CacheConfig::default(),
            tracking: TrackingConfig::default(),
            security: SecurityConfig::default(),
            anti_bypass: AntiBypassConfig::default(),
            socket: SocketConfig::default(),
            api: ApiConfig::default(),
            forwarding: Vec::new(),
            local_dns: LocalDnsConfig::default(),
            ip_blocklists: IpBlocklistConfig::default(),
            lists: ListsConfig::default(),
            resource_budget: ResourceBudgetConfig::default(),
            backup: BackupConfig::default(),
            cluster: ClusterConfig::default(),
        }
    }
}

/// Placeholder secret-bearing fields are replaced with on display
/// surfaces.
pub const REDACTION_PLACEHOLDER: &str = "***";

impl ConfigV1 {
    /// Replace every credential-bearing value for export over a display
    /// surface (`GET /api/config`). Shape contract (observable behaviour):
    /// field set → `Some("***")` so operators
    /// see it exists; field unset → `None` (`api.token_hash` then omits
    /// via `skip_serializing_if`; `cluster.token_hash` serialises as JSON
    /// `null` — both unchanged).
    ///
    /// Guarded by `guard_redacted_config_has_no_secret_shaped_plaintext`:
    /// add new secret fields HERE and to that test's fixture, or the
    /// guard fails.
    #[must_use]
    pub fn redacted(mut self) -> Self {
        if self.api.token_hash.is_some() {
            self.api.token_hash = Some(REDACTION_PLACEHOLDER.into());
        }
        if self.cluster.token_hash.is_some() {
            self.cluster.token_hash = Some(REDACTION_PLACEHOLDER.into());
        }
        self
    }
}

// ── cluster replication: the section classification, as DATA ──
//
// The exhaustive `let ConfigV1 { … }` destructuring in
// `every_config_section_is_classified_replicated_or_node_local` is the
// compile-time trip-wire: add a field to `ConfigV1` and that test stops
// building until the field is classified. It cannot be *read* at runtime,
// though, so the guards that need the classification would have had to
// re-type it in prose — and prose does not fail a build.
//
// These three lists are that same classification as data, partitioning every
// top-level key of a serialised `ConfigV1`. The partition is enforced by
// `the_section_classification_consts_partition_every_config_key`, so a new
// field must be added to exactly one of them or the suite goes red.
//
// Ungated on purpose: `src/cluster/` is behind `#[cfg(feature = "cluster")]`
// and that feature is OFF by default, but `config::schema::validator` — the
// consumer — is always compiled.

/// Every top-level section the primary replicates to a secondary, mirroring
/// the fields of `cluster::policy::ClusterPolicyBundle`.
pub const REPLICATED_SECTIONS: &[&str] = &[
    "schema_version",
    "server",
    "retired",
    "blocklists",
    "profiles",
    "devices",
    "groups",
    "subnets",
    "schedules",
    "admin_rules",
    "labels",
    "upstream",
    "dnssec",
    "cache",
    "security",
    "anti_bypass",
    "forwarding",
    "local_dns",
    "ip_blocklists",
    "lists",
];

/// Sections that never cross the wire. Replicating any of
/// these would overwrite the secondary's own identity with the primary's.
pub const NODE_LOCAL_SECTIONS: &[&str] = &[
    // A `[[custom_lists]]` row is a pointer to a file on THIS node's disk.
    // Replication ships config sections, not files, so a replicated pointer
    // would name a file the secondary does not have — and an unreadable pack
    // is a load error, so the secondary would refuse to start. Not
    // replicating is strictly safer than replicating half of it. Its limits
    // table follows it: ceilings for a reader that never runs are noise.
    "custom_lists",
    "custom_list_limits",
    "tracking",
    "socket",
    "api",
    "resource_budget",
    "backup",
    "cluster",
];

/// Neither replicated nor node-local. `includes` is a list of path globs
/// resolved against the LOCAL filesystem: replicating it would point the
/// secondary at paths that need not exist on it, and the bundle it would
/// arrive in IS the merge those globs feed.
pub const SECTIONS_EXCLUDED_FROM_REPLICATION: &[&str] = &["includes"];

/// Replicated sections a cluster secondary's **master** may nonetheless
/// carry, so a guard built from [`REPLICATED_SECTIONS`] must subtract them.
/// Both entries are load-bearing:
///
/// - `schema_version` is on the keep-list — *every* master carries it, and
///   the bundle's copy is a compatibility check, not policy to install.
///   Forbidding it would refuse every secondary that exists.
/// - `server` is the one split-merge singleton (`loader.rs`
///   `SPLIT_MERGE_SINGLETONS`): the master keeps node-local `server.listen`
///   while the bundle supplies the policy fields. A duplicate *sub-key* is
///   already a hard `DuplicateId`, and that finer check is the correct one —
///   a coarse section-level refusal here would clobber it and make a legal
///   secondary unloadable.
pub const REPLICATED_BUT_ALLOWED_IN_A_SECONDARY_MASTER: &[&str] = &["schema_version", "server"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_config_deserialises() {
        // Deliberately declares NO `[upstream]` — this test's subject is what
        // the pass-through defaults produce, and the upstream default is now
        // one of the things being asserted (see the bottom of the fn).
        let src = r#"
schema_version = 3
"#;
        let c: ConfigV1 = toml::from_str(src).unwrap();
        assert_eq!(c.schema_version, SCHEMA_VERSION_V1);
        assert!(c.profiles.is_empty());
        assert!(c.devices.is_empty());
        // Pass-through defaults still produce sensible daemon config.
        assert_eq!(c.server.listen.port(), 15353);
        assert_eq!(c.server.default_blocked_ttl_secs, 60);
        assert!(c.server.enforce_device_mac);
        assert!(
            c.upstream.servers.is_empty(),
            "a config naming no upstream must deserialise to none — warden picks nobody"
        );
    }

    #[test]
    fn top_level_unknown_field_rejected() {
        let err = toml::from_str::<ConfigV1>(
            r#"
schema_version = 3
mystery = 1

[upstream]
servers = ["192.0.2.1:53"]
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn dnssec_section_defaults_and_modes() {
        use crate::config::settings::DnssecMode;

        // Absent [dnssec] → off + design-doc cap defaults.
        let c: ConfigV1 =
            toml::from_str("schema_version = 3\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n")
                .unwrap();
        assert_eq!(c.dnssec.mode, DnssecMode::Off);
        assert_eq!(c.dnssec.max_chain_depth, 10);
        assert_eq!(c.dnssec.max_queries, 30);
        assert_eq!(c.dnssec.max_nsec3_iterations, 150);
        assert_eq!(c.dnssec.cache_ttl_secs, 3600);

        // Modes parse from kebab-case spelling.
        let validate: ConfigV1 =
            toml::from_str("schema_version = 3\n[dnssec]\nmode = \"validate\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n").unwrap();
        assert_eq!(validate.dnssec.mode, DnssecMode::Validate);
        let log_only: ConfigV1 =
            toml::from_str("schema_version = 3\n[dnssec]\nmode = \"log-only\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n").unwrap();
        assert_eq!(log_only.dnssec.mode, DnssecMode::LogOnly);

        // A partial override keeps the other caps at their defaults
        // (container-level `#[serde(default)]`).
        let partial: ConfigV1 =
            toml::from_str("schema_version = 3\n[dnssec]\nmax_queries = 12\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n").unwrap();
        assert_eq!(partial.dnssec.mode, DnssecMode::Off);
        assert_eq!(partial.dnssec.max_queries, 12);
        assert_eq!(partial.dnssec.max_chain_depth, 10);

        // An unknown key in [dnssec] is rejected (deny_unknown_fields).
        assert!(
            toml::from_str::<ConfigV1>("schema_version = 3\n[dnssec]\nmoed = \"validate\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n")
                .is_err()
        );
    }

    #[test]
    fn server_passthrough_fields_accepted() {
        // The master config holds both entity-model and daemon-wide
        // sections; this test pins that ConfigV1 accepts them in one
        // parse pass without falling through to an unknown-field error.
        let src = r#"
schema_version = 3

[server]
listen = "0.0.0.0:53"
log_level = "info"
allow_from = ["10.0.0.0/8"]
default_profile = "default"

[upstream]
mode = "doh"
servers = ["https://1.1.1.1/dns-query"]

[cache]
max_entries = 20000

[socket]
path = "/run/purge-warden/control.sock"

[tracking]
enabled = true
query_log_enabled = true
retention_days = 7
log_mode = "blocked_only"
"#;
        let c: ConfigV1 = toml::from_str(src).unwrap();
        assert_eq!(c.server.listen.to_string(), "0.0.0.0:53");
        assert_eq!(c.server.allow_from, vec!["10.0.0.0/8".to_string()]);
        assert_eq!(
            c.server.default_profile.as_ref().map(|i| i.as_str()),
            Some("default")
        );
        assert_eq!(c.upstream.servers.len(), 1);
        assert_eq!(c.cache.max_entries, 20_000);
        assert_eq!(
            c.socket.path,
            std::path::Path::new("/run/purge-warden/control.sock")
        );
        assert!(c.tracking.query_log_enabled);
        assert_eq!(c.tracking.retention_days, 7);
        assert_eq!(
            c.tracking.log_mode,
            crate::config::settings::LogMode::BlockedOnly
        );
    }

    #[test]
    fn server_block_unmapped_clients_rejected_as_unknown_field() {
        // The legacy `block_unmapped_clients` flag does not exist
        // in v1. An operator migrating a legacy config must delete it
        // and set `default_profile` instead. The deny_unknown_fields
        // guard on ServerGlobals makes this fail loudly at parse time.
        let err = toml::from_str::<ConfigV1>(
            r#"
schema_version = 3

[server]
block_unmapped_clients = true

[upstream]
servers = ["192.0.2.1:53"]
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn full_config_roundtrips() {
        let src = r#"
schema_version = 3
includes = ["devices.d/*.toml"]

[server]
default_profile = "default"
default_block_response = "zero"
default_blocked_ttl_secs = 90

[[blocklists]]
id = "privacy-ads"
display_name = "Privacy: Ads"
url = "https://lists.purge.cc/privacy/ads.txt"

[profiles.default]
display_name = "Default"

[[devices]]
id = "iphone"
display_name = "iPhone"
ip = "10.10.1.107"
profile = "default"

[[groups]]
id = "iot"
display_name = "IoT"
profile = "default"
devices = ["iphone"]

[[subnets]]
id = "lan"
display_name = "LAN"
cidrs = ["10.10.1.0/24"]
profile = "default"

[[schedules]]
id = "quiet"
display_name = "Quiet"
target_type = "device"
target_id = "iphone"
profile = "default"
days = ["all"]
hours = "22:00-07:00"

[[admin_rules]]
id = "allow-github"
rule = "@@||github.com^"

[upstream]
servers = ["192.0.2.1:53"]
"#;
        let c: ConfigV1 = toml::from_str(src).unwrap();
        assert_eq!(c.schema_version, 3);
        assert_eq!(c.server.default_blocked_ttl_secs, 90);
        assert_eq!(c.blocklists.len(), 1);
        assert_eq!(c.profiles.len(), 1);
        assert_eq!(c.devices.len(), 1);
        assert_eq!(c.groups.len(), 1);
        assert_eq!(c.subnets.len(), 1);
        assert_eq!(c.schedules.len(), 1);
        assert_eq!(c.admin_rules.len(), 1);

        // Compare via TOML serialisation — the pass-through legacy types
        // do not implement `PartialEq`, and a string-level compare is a
        // stronger check anyway (fields that derive serde equivalence
        // must produce the same output).
        let serialised = toml::to_string(&c).unwrap();
        let back: ConfigV1 = toml::from_str(&serialised).unwrap();
        assert_eq!(toml::to_string(&back).unwrap(), serialised);
    }

    #[test]
    fn schema_version_required() {
        let err = toml::from_str::<ConfigV1>("includes = []").unwrap_err();
        assert!(err.to_string().contains("schema_version"));
    }

    // ── secret redaction ───────────────────────────

    /// Maximal secret-bearing fixture. When adding any config field that
    /// carries a credential, populate it here — this fixture feeds the
    /// deny-by-default leak guard below, and an unpopulated field evades
    /// it (serialises as null/absent).
    fn secret_bearing_config() -> ConfigV1 {
        let src = r#"
schema_version = 3

[api]
enabled = true
token_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
tls_cert = "/etc/purge-warden/api.crt"
tls_key = "/etc/purge-warden/api.key"

[cluster]
enabled = true
token_hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

[[blocklists]]
id = "privacy-ads"
display_name = "Privacy: Ads"
url = "https://lists.purge.cc/privacy/ads.txt"
auth_token_ref = "privacy-ads-token"

[upstream]
servers = ["192.0.2.1:53"]
"#;
        toml::from_str(src).unwrap()
    }

    /// Secret-shape key patterns (per JSON object key, any depth).
    /// Deliberately precise: substring-`token` would false-positive
    /// `auth_token_ref` (a NAME referencing `secrets.toml`, not a
    /// credential), substring-`key` would false-positive the `tls_key`
    /// PATH (filesystem-guarded config, not a credential).
    fn is_secret_shaped(key: &str) -> bool {
        let k = key.to_ascii_lowercase();
        k == "token_hash"
            || k.ends_with("_token_hash")
            || k == "token"
            || k.ends_with("_token")
            || k == "secret"
            || k.ends_with("_secret")
            || k.starts_with("secret_")
            || k.contains("password")
            || k.contains("passphrase")
            || k == "private_key"
            || k.ends_with("_private_key")
            || k == "api_key"
            || k.ends_with("_api_key")
            || k == "apikey"
    }

    /// Recursively collect `(path, value)` for every secret-shaped key.
    fn collect_secret_keys(
        v: &serde_json::Value,
        path: String,
        hits: &mut Vec<(String, serde_json::Value)>,
    ) {
        match v {
            serde_json::Value::Object(map) => {
                for (k, child) in map {
                    let child_path = if path.is_empty() {
                        k.clone()
                    } else {
                        format!("{path}.{k}")
                    };
                    if is_secret_shaped(k) {
                        hits.push((child_path.clone(), child.clone()));
                    }
                    collect_secret_keys(child, child_path, hits);
                }
            }
            serde_json::Value::Array(items) => {
                for (i, child) in items.iter().enumerate() {
                    collect_secret_keys(child, format!("{path}[{i}]"), hits);
                }
            }
            _ => {}
        }
    }

    /// Deny-by-default leak guard: serialise the maximal fixture through
    /// `redacted()` and walk every key — anything secret-shaped must be
    /// `"***"` or null. A future credential field that someone forgets to
    /// add to `redacted()` (but populates in the fixture) fails here.
    #[test]
    fn guard_redacted_config_has_no_secret_shaped_plaintext() {
        let json = serde_json::to_value(secret_bearing_config().redacted()).unwrap();
        let mut hits = Vec::new();
        collect_secret_keys(&json, String::new(), &mut hits);
        assert!(!hits.is_empty(), "guard must see at least the two hashes");
        for (path, value) in &hits {
            let ok = value.is_null() || value.as_str() == Some(REDACTION_PLACEHOLDER);
            assert!(ok, "secret-shaped field leaked plaintext: {path} = {value}");
        }
    }

    /// Anti-rot in both directions: the unredacted fixture's matched set
    /// must equal exactly the known secret fields. A new populated secret
    /// field changes the set (routing its author here, where the fixture
    /// comment routes them on to `redacted()`); a pattern regression that
    /// stops matching `token_hash` shrinks it.
    #[test]
    fn guard_pattern_list_still_sees_known_secrets() {
        let json = serde_json::to_value(secret_bearing_config()).unwrap();
        let mut hits = Vec::new();
        collect_secret_keys(&json, String::new(), &mut hits);
        let mut paths: Vec<String> = hits.into_iter().map(|(p, _)| p).collect();
        paths.sort();
        assert_eq!(
            paths,
            vec![
                "api.token_hash".to_string(),
                "cluster.token_hash".to_string()
            ],
            "secret-shape pattern set drifted"
        );
    }

    /// Pins the Some-"***" / None-omit shape contract byte-for-byte:
    /// unset hashes stay unset (api omits via skip_serializing_if;
    /// cluster serialises as JSON null).
    #[test]
    fn redacted_preserves_unset_shape() {
        let c = toml::from_str::<ConfigV1>(
            "schema_version = 3\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        )
        .unwrap();
        let json = serde_json::to_value(c.redacted()).unwrap();
        assert!(
            json["api"].get("token_hash").is_none(),
            "unset api.token_hash must be omitted"
        );
        assert!(
            json["cluster"]["token_hash"].is_null(),
            "unset cluster.token_hash must stay null"
        );
    }

    #[test]
    fn redacted_replaces_set_hashes_with_placeholder() {
        let c = secret_bearing_config().redacted();
        assert_eq!(c.api.token_hash.as_deref(), Some(REDACTION_PLACEHOLDER));
        assert_eq!(c.cluster.token_hash.as_deref(), Some(REDACTION_PLACEHOLDER));
        // Paths are config, not credentials — deliberately untouched.
        assert!(c.api.tls_key.is_some());
        // The secrets.toml NAME reference is likewise untouched.
        assert_eq!(
            c.blocklists[0].auth_token_ref.as_deref(),
            Some("privacy-ads-token")
        );
    }

    /// A [`ConfigV1::default`] that actually validates — the scaffold for
    /// unit-test fixtures whose subject is devices / labels / rules /
    /// anything but upstream policy.
    ///
    /// `ConfigV1::default()` has no default upstream, so it
    /// is refused by the validator. Fixtures that don't care about upstream
    /// policy just need *a* loadable config, so this gives them RFC 5737
    /// TEST-NET-1: reserved for documentation, unroutable, and naming
    /// nobody.
    ///
    /// Test-only on purpose. Production code must keep hitting
    /// [`ConfigV1::default`] so that a real config which names no resolver
    /// is refused rather than quietly handed one.
    ///
    /// Lives INSIDE `mod tests` rather than beside it, and that placement is
    /// forced from both sides: below the test module clippy refuses it
    /// (`items_after_test_module`), and above it the file would gain a second
    /// `#[cfg(test)]` ahead of production code — exactly the kind of blind
    /// spot a stray provider default could hide in. An inherent impl is
    /// crate-visible from wherever it is written, so `pub(crate)` here
    /// reaches every other test module.
    impl ConfigV1 {
        pub(crate) fn test_scaffold() -> Self {
            Self {
                upstream: crate::config::settings::UpstreamConfig {
                    servers: vec!["192.0.2.1:53".to_string()],
                    ..crate::config::settings::UpstreamConfig::default()
                },
                ..Self::default()
            }
        }
    }

    /// Every top-level [`ConfigV1`] section is classified: **replicated** to a
    /// cluster secondary, **node-local** (never crosses the wire), or
    /// **excluded with a reason**. The destructuring below is exhaustive — no
    /// `..` rest pattern — so adding a field to `ConfigV1` breaks THIS BUILD
    /// until someone decides which set it belongs to.
    ///
    /// **This is the test whose absence lost `[[labels]]`.** The bundle carried
    /// blocklists, devices and profiles that reference tags while the vocabulary
    /// declaring them stayed home, because
    /// `ClusterPolicyBundle::from_config` copies field by field and nothing
    /// forced the omission to be noticed.
    ///
    /// **It lives here, away from the thing it protects, deliberately.**
    /// `src/cluster/` is behind `#[cfg(feature = "cluster")]` and that feature is
    /// OFF by default, so a copy of this test next to the bundle would never fire
    /// for a contributor running a plain `cargo test` — precisely the
    /// invisible-to-the-default-build hazard this test exists to catch. The
    /// half that needs the feature (the bundle round-trip) stays in
    /// `cluster::policy::tests::the_bundle_replicates_the_label_vocabulary`; this
    /// half names only `ConfigV1`, so it runs for everyone.
    ///
    /// **If this stops compiling, do not add the field to the pattern and move
    /// on.** Decide first: if it is policy, it also belongs in
    /// `ClusterPolicyBundle` *and* in that struct's `from_config`.
    #[test]
    fn every_config_section_is_classified_replicated_or_node_local() {
        let ConfigV1 {
            // ── replicated: must have a matching ClusterPolicyBundle field ──
            schema_version: _,
            server: _,
            retired: _,
            blocklists: _,
            profiles: _,
            devices: _,
            groups: _,
            subnets: _,
            schedules: _,
            admin_rules: _,
            labels: _,
            upstream: _,
            dnssec: _,
            cache: _,
            security: _,
            anti_bypass: _,
            forwarding: _,
            local_dns: _,
            ip_blocklists: _,
            lists: _,

            // ── node-local. Replicating any of these would
            // overwrite the secondary's own identity with the primary's.
            custom_lists: _,
            custom_list_limits: _,
            tracking: _,
            socket: _,
            api: _,
            resource_budget: _,
            backup: _,
            cluster: _,

            // ── excluded, with a reason ──
            // `includes` is a list of path globs resolved against the LOCAL
            // filesystem. Replicating it would point the secondary at paths
            // that need not exist on it — and the bundle it would arrive in
            // IS the merge those globs feed.
            includes: _,
        } = ConfigV1::test_scaffold();
    }

    /// The runtime half of the classification above. The destructuring is a
    /// compile-time trip-wire but cannot be iterated; the guards that consume
    /// the classification read [`REPLICATED_SECTIONS`] and friends instead.
    /// This test is what stops the two from drifting: a new `ConfigV1` field
    /// breaks the destructuring's build, and then breaks THIS unless it is
    /// added to exactly one of the three lists.
    #[test]
    fn the_section_classification_consts_partition_every_config_key() {
        let value = toml::Value::try_from(ConfigV1::default())
            .expect("a default config serialises to a TOML table");
        let mut actual: Vec<&str> = value
            .as_table()
            .expect("top level is a table")
            .keys()
            .map(String::as_str)
            .collect();
        actual.sort_unstable();

        let mut classified: Vec<&str> = REPLICATED_SECTIONS
            .iter()
            .chain(NODE_LOCAL_SECTIONS)
            .chain(SECTIONS_EXCLUDED_FROM_REPLICATION)
            .copied()
            .collect();
        let before_dedup = classified.len();
        classified.sort_unstable();
        classified.dedup();
        assert_eq!(
            before_dedup,
            classified.len(),
            "a section is classified twice; the three lists must be disjoint"
        );

        assert_eq!(
            classified, actual,
            "every top-level ConfigV1 section must be classified exactly once: \
             replicated to a cluster secondary, node-local (CS3), or excluded \
             with a reason"
        );
    }

    /// The destructuring above forces every field into exactly one bucket,
    /// but it cannot see which bucket is *right* — any classification makes
    /// the build move again, including a harmful one. This names the one
    /// case where the wrong bucket is an outage rather than a lint.
    ///
    /// A `[[custom_lists]]` row points at `packs/<id>.txt` on the node's own
    /// disk. Replication ships config sections, never files, so a replicated
    /// row would reach a secondary with no such file — and an unreadable pack
    /// is a load error, so that secondary refuses to start. The primary would
    /// take it down by syncing.
    ///
    /// If a later sprint teaches replication to ship pack bodies, this test
    /// is the thing to delete, and deleting it should require saying so.
    #[test]
    fn a_custom_list_declaration_never_crosses_the_wire() {
        for key in ["custom_lists", "custom_list_limits"] {
            assert!(
                !REPLICATED_SECTIONS.contains(&key),
                "'{key}' must not be replicated: it points at a file on this \
                 node's disk that replication cannot carry, and the secondary \
                 refuses to start on a pack it cannot read"
            );
            assert!(
                NODE_LOCAL_SECTIONS.contains(&key),
                "'{key}' must be node-local"
            );
        }
    }

    /// The subtraction the secondary-master guard performs must be a
    /// subtraction, not a smuggling route: an entry here that is not
    /// replicated in the first place would silently widen what a secondary's
    /// master may carry.
    #[test]
    fn every_master_allowed_exception_is_actually_a_replicated_section() {
        for exception in REPLICATED_BUT_ALLOWED_IN_A_SECONDARY_MASTER {
            assert!(
                REPLICATED_SECTIONS.contains(exception),
                "'{exception}' is exempted from the secondary-master guard but is \
                 not a replicated section, so the exemption grants something the \
                 guard never covered"
            );
        }
    }
}
