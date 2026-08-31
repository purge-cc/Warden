//! Server configuration with nested TOML sections and serde defaults.
//!
//! Config layering: defaults → TOML file → CLI args.
//!
//! Almost every field has a sensible default. The one deliberate exception
//! is `upstream.servers`, which defaults to EMPTY and is therefore refused
//! by the validator (`UPSTREAM_SERVERS_EMPTY`) — see [`UpstreamConfig`].
//! An empty config file is consequently **not** valid: it names no
//! resolver, and warden will not name one for the operator.

#[cfg(test)]
use std::net::Ipv4Addr;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use serde::{Deserialize, Deserializer, Serialize};

// ── Defaults ────────────────────────────────────────────────────

fn default_listen() -> SocketAddr {
    "127.0.0.1:15353".parse().unwrap()
}

fn default_log_level() -> String {
    "info".into()
}

fn default_blocked_ttl_secs() -> u32 {
    60
}

fn default_tcp_timeout_secs() -> u64 {
    10
}

fn default_upstream_timeout_ms() -> u64 {
    5000
}

fn default_update_interval_secs() -> u64 {
    // 12h. After Sprint 24 Phase 1.2 (s24-list-cache-freshness-check)
    // this value has DUAL purpose: it is the background update period
    // AND the disk cache freshness threshold. The freshness check in
    // refresh() skips HTTP entirely when the on-disk cache age is
    // below this number, so a higher value reduces upstream traffic
    // for unchanged content. Matched to the purge.cc list update
    // cadence — server-side lists are not republished more often
    // than once every 12h, so a tighter interval would just produce
    // 304s without changing the merged domain map.
    43_200
}

fn default_cache_max_entries() -> u64 {
    10_000
}

fn default_cache_max_ttl_secs() -> u64 {
    3600
}

fn default_cache_min_ttl_secs() -> u64 {
    60
}

fn default_cache_negative_ttl_secs() -> u64 {
    300
}

fn default_cache_stale_buffer_secs() -> u64 {
    300
}

fn default_cache_prefetch() -> bool {
    true
}

fn default_cache_prefetch_threshold() -> f64 {
    0.1
}

fn default_cache_prefetch_max_concurrent() -> usize {
    16
}

fn default_cache_cname_max_depth() -> usize {
    16
}

// ── Sprint §4.4 P1 — prefetch hit-frequency tracker defaults ───
//
// Sprint §4.4 P2 (2026-05-06) flipped the master flag to `true` after
// CT burn-in: 6-min synthetic warm of cnn.com on `the lab host`
// produced 9/10 cache hits at Query time = 0msec, RSS drift +708 KB
// over 9 minutes (no leak), regression clean. Operators picking up
// the new binary now get proactive refresh by default; explicit
// opt-out via `prefetch_tracker_enabled = false` under [cache] still
// works. See `_docs/features/cache_prefetching.md` and the
// `tracking::prefetch::PrefetchTrackerConfig` mirror.

fn default_cache_prefetch_tracker_enabled() -> bool {
    true
}

fn default_cache_prefetch_tracker_window_secs() -> u64 {
    300
}

fn default_cache_prefetch_tracker_min_hits() -> u32 {
    3
}

fn default_cache_prefetch_tracker_max_pool_size() -> u32 {
    1024
}

// ── Sprint §4.4 P2 — background refresh worker pacing ─────────────
//
// `tick_secs` is how often the worker scans the promoted-domain set.
// `lead_secs` is how far ahead of TTL expiry the worker will refresh
// an entry. Both are independent of the Sprint 17 `prefetch_threshold`
// (% of TTL) which still drives Approach A's reactive path.

fn default_cache_prefetch_tracker_tick_secs() -> u64 {
    30
}

fn default_cache_prefetch_tracker_lead_secs() -> u64 {
    10
}

fn default_local_dns_ttl_secs() -> u32 {
    3600
}

fn default_local_dns_dynamic_ttl_secs() -> u32 {
    30
}

fn default_local_dns_nodata_for_missing_types() -> bool {
    true
}

fn default_socket_path() -> PathBuf {
    PathBuf::from("./control.sock")
}

fn default_api_listen() -> SocketAddr {
    "127.0.0.1:8053".parse().unwrap()
}

fn default_api_rate_limit() -> u32 {
    60
}

// ── Security defaults ──────────────────────────────────────────

// rrl-01 (rev-2606): was 5. RRL buckets by /24, and a home LAN is exactly
// one /24 — at 5 resp/s × 15 s the whole household shared a 75-responses-
// per-15-s budget across every response class (post-9f60205 hoist), which
// normal multi-device browsing exceeds. 100 resp/s (= 1500/window) sits
// ~4-7× above real LAN peaks while reflection floods (thousands/s) still
// trip it.
fn default_rrl_responses_per_second() -> u32 {
    100
}

fn default_rrl_window_secs() -> u64 {
    15
}

fn default_rrl_slip_rate() -> u32 {
    2
}

fn default_rate_limit_qps() -> u32 {
    100
}

fn default_rate_limit_burst() -> u32 {
    200
}

fn default_tunneling_entropy_threshold() -> f64 {
    3.5
}

fn default_tunneling_label_len_threshold() -> usize {
    48
}

/// Longest run of characters containing no `-`, within the non-apex
/// labels, before the name is flagged. Replaces concatenated entropy as
/// the primary shape signal — see [`TunnelingConfig::entropy_min_len`]
/// for why entropy could not do this job.
///
/// 40 is derived, not guessed: the longest legitimate run measured over
/// 8 days of live traffic (942 distinct names) is 32, while iodine and
/// dnscat2 emit unbroken payload labels of 40-63. The one legitimate
/// name above 40 is a 63-char hex token, which sits at the DNS label
/// ceiling and no threshold can separate — that is what
/// `exempt_domains` is for.
fn default_tunneling_max_unbroken_run() -> usize {
    40
}

/// Minimum concatenated length before the entropy heuristic is allowed
/// to run at all. Below this the entropy signal is inert.
///
/// Shannon entropy *per character* is bounded by `log2(len)`, so on
/// short strings it measures alphabet size and length rather than
/// randomness. Measured over the same corpus: below 56 the gate starts
/// refusing legitimate AWS ELB hostnames (the worst scores 4.572, well
/// above a hex tunnel's `log2(16) = 4.0` ceiling). 64 keeps a margin
/// over the measured cliff at 55.
fn default_tunneling_entropy_min_len() -> usize {
    64
}

fn default_tunneling_subdomain_rate() -> u32 {
    50
}

fn default_tunneling_window_secs() -> u64 {
    60
}

// Per-section `enabled` defaults. Each section gets its own one-line
// helper so a future flip of one default does NOT silently retune
// unrelated features. Pre-T2.5 a single shared `default_tracking_enabled`
// was wired to six independent toggles (tracking + four security
// sub-sections + anti-bypass); see review `settings-01` / FIX_PLAN H-10.
// Today every helper returns `true`, but each can flip independently.
fn default_tracking_enabled() -> bool {
    true
}

fn default_security_enabled() -> bool {
    true
}

fn default_rrl_enabled() -> bool {
    true
}

fn default_rate_limit_enabled() -> bool {
    true
}

fn default_tunneling_enabled() -> bool {
    true
}

fn default_anti_bypass_enabled() -> bool {
    true
}

fn default_snapshot_interval_secs() -> u64 {
    120
}

fn default_top_n_limit() -> usize {
    20
}

fn default_top_n_interval_secs() -> u64 {
    10
}

fn default_max_devices() -> usize {
    1024
}

fn default_query_log_path() -> PathBuf {
    PathBuf::from("./query.log")
}

fn default_query_log_max_size_mb() -> u64 {
    100
}

fn default_query_log_max_files() -> usize {
    7
}

/// Sprint 38 QLP3: named default closes the Sprint 37 QL3 gap where a
/// partial `[tracking]` section with no `query_log_enabled` line
/// deserialised via the bare `#[serde(default)]` path to `bool::default()`
/// (i.e. `false`) — disagreeing with the struct-level `impl Default`
/// which flips to `true` on S37.
fn default_query_log_enabled() -> bool {
    true
}

/// Sprint 38 QLP3: `retention_days` is the primary on-disk retention
/// knob. `7` matches the S38 design's "weekly window" contract with
/// operator cron archival — see `_docs/features/query_log_policy_v1.md` D2.
fn default_retention_days() -> u32 {
    7
}

// ── Back-compat deserialisers ────────────────────────────────────
//
// T2.5 H-11: pre-T2.5, `ApiConfig` carried `String::new()` sentinels
// for `token_hash` / `tls_cert` / `tls_key`, and operator configs on
// disk (including the live CT master and `cli/commands/token.rs`'s
// regenerate output) literally write `token_hash = ""` when the value
// is unset. After the migration to `Option<String>` / `Option<PathBuf>`
// these helpers preserve byte-for-byte back-compat: an empty string in
// the TOML still parses as `None`, and an absent field still defaults
// to `None` via `#[serde(default)]`.

/// Deserialise `Option<String>`, mapping an empty string to `None`.
fn empty_string_as_none<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    Ok(opt.filter(|s| !s.is_empty()))
}

/// Deserialise `Option<PathBuf>`, mapping an empty string to `None`.
fn empty_string_as_none_pathbuf<'de, D>(deserializer: D) -> Result<Option<PathBuf>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    Ok(opt.filter(|s| !s.is_empty()).map(PathBuf::from))
}

// §4.41: the v0 top-level `Settings` aggregate struct was retired here.
// `ConfigV1` (src/config/schema/mod.rs) is the single config model; it
// reuses the sub-struct types defined below (`ServerConfig`,
// `UpstreamConfig`, `ListsConfig`, …) as pass-through sections, and
// `ClientConfig` / `ScheduleConfig` survive as the IPC `[[devices]]`
// wire type + migration exchange type. Only the `Settings` envelope,
// its `from_file*` / `apply_cli_overrides` impl, and `SettingsLoadError`
// were deleted — see also `config/writer.rs` (v0 `write_config` gone).

// ── [server] ────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// TTL (seconds) for canned blocked responses (A→0.0.0.0, AAAA→::).
    #[serde(default = "default_blocked_ttl_secs")]
    pub blocked_ttl_secs: u32,
    /// Idle timeout (seconds) for incoming TCP connections.
    #[serde(default = "default_tcp_timeout_secs")]
    pub tcp_timeout_secs: u64,
    /// Verify the device's hardware address (MAC) at query time for
    /// clients whose `[[clients]]` entry pins a MAC (P0-2).
    ///
    /// When `true` (default): if a client config pins a MAC, the daemon
    /// consults the local ARP table at query time. If the ARP table maps
    /// the source IP to a *different* MAC than the one pinned in config,
    /// the daemon logs a warning and applies the default profile to that
    /// query instead of the pinned client's profile. This raises the bar
    /// against LAN-side profile spoofing (ARP-poisoned profile hijack).
    ///
    /// The check is *forgiving of DHCP churn*: if the ARP table has no
    /// entry for the source IP (stale cache, not yet resolved), the
    /// daemon trusts the configured profile. Only a *mismatch* triggers
    /// the fallback.
    ///
    /// Leaving this on is safe for **every** deployment shape:
    ///
    /// - **Home**: parent pins their phone's MAC to an unrestricted
    ///   profile → works as intended. Kid's tablet has no MAC pin → uses
    ///   the default (strict) profile.
    /// - **Company**: no `[[clients]]` entries at all → every device
    ///   falls through to the default profile → this flag has no effect.
    ///   Set `[profiles.default]` to the strict profile and you're done.
    ///
    /// Set to `false` only if you need the old behavior (IP-only
    /// matching, no MAC verification) — e.g. for debugging.
    /// T5 renamed from `enforce_client_mac`; the legacy key is accepted
    /// via the serde alias on direct `ConfigV1` parses — the loader's
    /// WARN branch is the primary retro-compat surface.
    #[serde(default = "default_enforce_device_mac", alias = "enforce_client_mac")]
    pub enforce_device_mac: bool,
    /// Source-IP allow list (CIDRs) for incoming DNS queries (P0-5).
    ///
    /// When empty and `listen` binds a specific interface (loopback or
    /// private), all sources are accepted — standard behavior. When
    /// non-empty, queries from any source not in one of the listed CIDRs
    /// are refused with REFUSED.
    ///
    /// **Required** (non-empty) when `listen` binds all interfaces
    /// (`0.0.0.0:*` or `[::]:*`). The validator refuses to start
    /// otherwise — this prevents accidentally running an open resolver.
    ///
    /// ```toml
    /// [server]
    /// listen = "0.0.0.0:53"
    /// allow_from = ["10.0.0.0/8", "192.168.1.0/24"]
    /// ```
    #[serde(default)]
    pub allow_from: Vec<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            log_level: default_log_level(),
            blocked_ttl_secs: default_blocked_ttl_secs(),
            tcp_timeout_secs: default_tcp_timeout_secs(),
            enforce_device_mac: default_enforce_device_mac(),
            allow_from: Vec::new(),
        }
    }
}

fn default_enforce_device_mac() -> bool {
    true
}

// ── [upstream] ──────────────────────────────────────────────────

/// Upstream resolution mode.
///
/// ```toml
/// [upstream]
/// mode = "doh"
/// servers = ["https://resolver.example.net/dns-query"]
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamMode {
    /// Plain UDP DNS (port 53) — fastest, no encryption.
    #[default]
    Plain,
    /// DNS-over-HTTPS (RFC 8484) — encrypted, blends with HTTPS traffic.
    Doh,
    /// DNS-over-TLS (RFC 7858) — encrypted, dedicated port 853.
    Dot,
    /// DNS-over-QUIC (RFC 9250) — encrypted over QUIC, dedicated port 853.
    /// Requires building with the `doq` cargo feature; otherwise a
    /// `mode = "doq"` config is rejected at startup with a clear error (the
    /// variant always deserializes so the diagnostic is actionable, not a
    /// generic serde "unknown variant").
    Doq,
}

impl std::fmt::Display for UpstreamMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plain => write!(f, "plain"),
            Self::Doh => write!(f, "doh"),
            Self::Dot => write!(f, "dot"),
            Self::Doq => write!(f, "doq"),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpstreamConfig {
    /// Resolution mode: "plain", "doh", "dot", or "doq".
    #[serde(default)]
    pub mode: UpstreamMode,
    /// Server addresses. Format depends on mode:
    /// - plain: "IP:port" (e.g. "192.0.2.1:53")
    /// - doh: URL (e.g. "https://resolver.example.net/dns-query")
    /// - dot: "host:port" (e.g. "192.0.2.1:853")
    /// - doq: "host:port" (e.g. "resolver.example.net:853"); requires the `doq` feature
    ///
    /// neutrality-10: there is deliberately **no** default. `#[serde(default)]`
    /// yields an EMPTY vector, which the validator refuses with the frozen
    /// `UPSTREAM_SERVERS_EMPTY`. This used to default to a named provider's
    /// pair, so a config that merely omitted `servers` routed the household's
    /// whole query stream to a company warden — not the operator — chose. No
    /// non-empty value is neutral: any address favours someone. Same reasoning
    /// as `init`'s `NO_DEFAULT_UPSTREAMS`; see project rules §Neutrality.
    ///
    /// Both default paths must stay empty, and they are reached by different
    /// configs: this attribute fires when `[upstream]` is present but `servers`
    /// is absent, while [`UpstreamConfig::default`] fires when the whole
    /// `[upstream]` section is omitted (`ConfigV1` carries it as
    /// `#[serde(default)]`). Repairing one leaves the other open.
    #[serde(default)]
    pub servers: Vec<String>,
    /// Per-query timeout in milliseconds.
    #[serde(default = "default_upstream_timeout_ms")]
    pub timeout_ms: u64,
    /// Optional fallback upstream (used when primary circuit-breaks).
    #[serde(default)]
    pub fallback: Option<FallbackConfig>,
    /// DoT-specific tuning (connection pool size, etc.).
    #[serde(default)]
    pub dot: DotUpstreamConfig,
    /// EDNS Client Subnet (RFC 7871) configuration. Off by default —
    /// LAN-only deploys can omit the section entirely.
    #[serde(default)]
    pub ecs: EcsConfig,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            mode: UpstreamMode::default(),
            // neutrality-10: empty on purpose — see the `servers` field doc.
            // This is the branch a config that omits `[upstream]` entirely
            // lands on; the field attribute never runs for it.
            servers: Vec::new(),
            timeout_ms: default_upstream_timeout_ms(),
            fallback: None,
            dot: DotUpstreamConfig::default(),
            ecs: EcsConfig::default(),
        }
    }
}

/// EDNS Client Subnet (RFC 7871) policy. §4.8 Sprint 1/2 reads only
/// `enabled` + `source_prefix_v4/v6`; `mode` is reserved for Sprint 2/2's
/// per-profile policy and is currently a no-op.
///
/// Default is OFF (`enabled = false`). When omitted from the TOML, the
/// daemon emits no ECS option on outbound queries — identical wire
/// behaviour to pre-§4.8 baseline. LAN-only deploys leave this section
/// off; CDN-routing deploys opt in.
///
/// ```toml
/// # Privacy-preserving infra-ready (Sprint 1 default when enabled):
/// [upstream.ecs]
/// enabled = true
/// source_prefix_v4 = 0    # zero address bytes on wire (RFC §7.1.2)
/// source_prefix_v6 = 0
/// mode = "off"            # Sprint 2 will read this; ignored in Sprint 1
/// ```
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct EcsConfig {
    /// Master toggle. When false, no ECS option is emitted on any
    /// outbound transport (DoH, DoT, plain). Plain transport stays on
    /// `hickory_resolver::Resolver` — when true, plain switches to a
    /// raw socket path that supports ECS injection.
    #[serde(default)]
    pub enabled: bool,
    /// IPv4 source prefix length (0..=32). Default `0` per RFC 7871
    /// §7.1.2 — the recursive resolver MUST NOT add client address
    /// information to its queries when the source prefix is zero, which
    /// is the privacy-safe default.
    #[serde(default = "default_ecs_source_prefix_v4")]
    pub source_prefix_v4: u8,
    /// IPv6 source prefix length (0..=128). Default `0`, same rationale
    /// as `source_prefix_v4`.
    #[serde(default = "default_ecs_source_prefix_v6")]
    pub source_prefix_v6: u8,
    /// Sprint 2/2 reserved field. Currently no-op — Sprint 1 always
    /// emits the anonymous form when `enabled = true`. Sprint 2 will
    /// promote this to a per-profile knob.
    #[serde(default)]
    pub mode: EcsMode,
}

impl Default for EcsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            source_prefix_v4: default_ecs_source_prefix_v4(),
            source_prefix_v6: default_ecs_source_prefix_v6(),
            mode: EcsMode::default(),
        }
    }
}

impl EcsConfig {
    /// Build the outbound ECS option that upstreams should attach to
    /// every query. Returns `None` when ECS is disabled (LAN-only
    /// deploys, default), in which case upstreams emit zero EDNS
    /// extensions on the wire.
    ///
    /// Sprint 1/2 always emits the **anonymous** form (RFC 7871 §7.1.2:
    /// `source_prefix = 0`, address all-zero) regardless of the `mode`
    /// or `source_prefix_v{4,6}` fields — those fields are reserved for
    /// Sprint 2/2's per-profile policy. Sprint 1 stands up the
    /// wire-format infrastructure with privacy-first defaults; only
    /// Sprint 2 promotes the prefix to a per-client value.
    ///
    /// IPv4 family is chosen unconditionally for the anonymous option:
    /// the address is `0.0.0.0` so the family choice is moot from a
    /// privacy standpoint, and v4 is the more common upstream-side
    /// expectation (RFC 7871 examples + Blocky/Google-DNS conventions).
    pub fn build_outbound_option(&self) -> Option<crate::dns::edns::EdnsClientSubnet> {
        if !self.enabled {
            return None;
        }
        Some(crate::dns::edns::EdnsClientSubnet::anonymous(
            crate::dns::edns::AddressFamily::V4,
        ))
    }
}

fn default_ecs_source_prefix_v4() -> u8 {
    0
}

fn default_ecs_source_prefix_v6() -> u8 {
    0
}

/// ECS routing policy. Sprint 1/2 reads only `Off` semantically (the
/// codec emits the anonymous zero-bytes form regardless when `enabled`
/// is true). Sprint 2/2 will activate `Coarse` (truncate to a fixed
/// privacy-safe prefix) and `Subnet` (forward the per-profile prefix).
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EcsMode {
    /// No address forwarding — anonymous form only.
    #[default]
    Off,
    /// Sprint 2 reserved: coarse-grained truncation.
    Coarse,
    /// Sprint 2 reserved: per-profile source-prefix forwarding.
    Subnet,
}

/// DoT connection-pool tuning. Applies to every DoT upstream — primary,
/// fallback, and per-zone in `[[forwarding]]`. Kept as a nested table
/// (`[upstream.dot]`) so the TOML stays flat at the top level and only
/// users who want non-default pool sizing touch it.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DotUpstreamConfig {
    /// Number of persistent TLS connections per DoT server. Default 4
    /// — two orders of magnitude below an RPi's fd budget and enough
    /// to hide the serialisation tax on busy LANs. Must be ≥ 1.
    #[serde(default = "default_dot_pool_size")]
    pub pool_size: usize,
}

impl Default for DotUpstreamConfig {
    fn default() -> Self {
        Self {
            pool_size: default_dot_pool_size(),
        }
    }
}

fn default_dot_pool_size() -> usize {
    4
}

/// Fallback upstream configuration (activated when primary circuit-breaks).
///
/// ```toml
/// [upstream.fallback]
/// mode = "plain"
/// servers = ["192.0.2.1:53", "192.0.2.2:53"]
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FallbackConfig {
    pub mode: UpstreamMode,
    pub servers: Vec<String>,
}

// ── [lists] ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListsConfig {
    #[serde(default)]
    pub sources: Vec<String>,
    #[serde(
        default = "default_update_interval_secs",
        alias = "refresh_interval_secs"
    )]
    pub update_interval_secs: u64,
    /// Maximum allowed size (bytes) for a single blocklist download.
    ///
    /// Streaming cap enforced by the hardened HTTP client — if a response
    /// exceeds this size, the download aborts mid-stream rather than
    /// buffering the whole body in memory. Prevents OOM from malicious
    /// servers that omit `Content-Length`, and bounds worst-case memory
    /// use during list refresh.
    ///
    /// **Default:** 200 MB. Chosen because real purge.cc lists have
    /// grown past 100 MB (e.g. `security/malicious` hit ~114 MB in
    /// April 2026). Operators on resource-constrained hardware (e.g. a
    /// Raspberry Pi Zero 2 W with 512 MB RAM) may want to lower this —
    /// a full list download briefly holds its full size in memory, and
    /// a 200 MB body on a 512 MB device is a significant spike. For a
    /// Pi, 50-100 MB and a curated smaller list is safer.
    ///
    /// Must be non-zero. `0` is treated as a misconfiguration and
    /// rejected at validation time.
    #[serde(default = "default_max_list_body_bytes")]
    pub max_body_bytes: usize,
    /// Maximum number of entries (domains) to load from a single list.
    ///
    /// Prevents OOM from adversarial or unexpectedly large list content.
    /// When a list exceeds this limit, the remainder is silently dropped
    /// with a warn-level log naming the list. Each list is capped
    /// independently; the merged domain map may exceed this if multiple
    /// lists contribute different domains.
    ///
    /// **Default:** 10,000,000. Was 5,000,000, which sat *below* four of
    /// the eight live purge.cc lists — the daemon silently discarded 19%
    /// of its corpus. See `default_max_list_entries`.
    ///
    /// Must be non-zero.
    #[serde(default = "default_max_list_entries")]
    pub max_entries: usize,
    /// Ceiling on the **merged, deduplicated** domain corpus, in entries.
    ///
    /// [`Self::max_entries`] bounds a single list and therefore bounds
    /// nothing in aggregate: eight sources at 10,000,000 each is 80,000,000
    /// on paper. What actually holds the live corpus near 12.3 M is that
    /// the lists overlap heavily — around 2.4× — and overlap is a property
    /// of the lists an operator happens to subscribe to, not a guarantee
    /// the daemon enforces. This is the bound on the merged map.
    ///
    /// Enforced on the deduplicated union, measured before any part of the
    /// new generation is installed. Three bands:
    ///
    /// - below 90 % of this value — install, quietly;
    /// - at or above 90 % — install anyway, and warn;
    /// - above it — refuse the whole refresh cycle and keep serving the
    ///   previous generation, so a corpus that would not fit never
    ///   half-replaces one that does.
    ///
    /// A refusal is not a per-source failure: every list downloaded and
    /// parsed correctly, the *merged* result was simply too large. `warden
    /// status` says so explicitly and names the list contributing the most
    /// domains no other list supplies.
    ///
    /// **Default:** 14,000,000. This is a memory budget, so it is yours to
    /// set — a box with tens of GB free has no reason to stop at the
    /// default. The number **was** chosen to sit just under a step in the
    /// memory curve: the domain map used to keep 16 shards of power-of-two
    /// buckets at 7/8 maximum load, so crossing 14,680,064 entries doubled
    /// every shard's allocation and roughly doubled the map's footprint
    /// (~690 MB → ~1.37 GB at the then-measured 41 bytes per bucket).
    ///
    /// **`mem-t6` removed that step.** Each shard is now an exact-size
    /// sorted slice — no buckets, no load factor, no allocation cliff — so
    /// memory grows linearly with the domain count. The value is kept at
    /// 14,000,000 deliberately, now as a plain memory budget rather than a
    /// threshold: changing it would move the behaviour of every existing
    /// installation for a reason that is not a safety one. Raise it freely if
    /// you have the RAM, and expect the cost to arrive in steps.
    ///
    /// `0` disables the check entirely, including the extra counting pass
    /// over the refresh spill that measures the union — so disabling it
    /// costs nothing per cycle.
    #[serde(default = "default_max_total_domains")]
    pub max_total_domains: usize,
    /// Directory for cached list files. After downloading a list, the raw
    /// body is saved to `{cache_dir}/{source_id}.cache` and HTTP headers
    /// (ETag, Last-Modified) to a `.meta` sidecar. On restart, cached
    /// files are loaded before any network request, enabling offline
    /// startup and conditional (304) refreshes.
    ///
    /// Relative paths are resolved against the config file's parent
    /// directory. **Default:** `"lists"`.
    #[serde(default = "default_cache_dir")]
    pub cache_dir: PathBuf,
    /// §4.7 Phase 2 T2: threshold (in seconds) past which a list is
    /// considered "stale" and the TUI Lists tab renders a non-alarm
    /// `Stale` badge in muted color. Compared against
    /// `now - ListStatus.last_refresh_at`.
    ///
    /// **Default:** 86 400 (24 h) — twice the default
    /// `update_interval_secs` of 43 200 (12 h), so a single missed
    /// refresh cycle does not trip the badge but a sustained outage
    /// does. Operators on a longer custom interval should raise this
    /// to at least 2× their interval to avoid false positives.
    #[serde(default = "default_staleness_threshold_secs")]
    pub staleness_threshold_secs: u64,
    /// rev-2606 §06 `manager-01`: when `true`, a refresh whose freshly
    /// downloaded body shrinks a previously-healthy list by more than
    /// [`Self::shrink_guard_max_drop_pct`] percent is **refused** — the
    /// prior on-disk cache is kept, the source is marked `Failed` with an
    /// operator-visible reason, and the daemon keeps serving the last-good
    /// list. This closes the silent fail-open where an endpoint that
    /// returns `200 OK` with an empty body or an HTML error page would
    /// overwrite the good cache with ~0 domains and persist that across
    /// restarts. Mirrors Pi-hole / AdGuard "keep the prior gravity on an
    /// empty download".
    ///
    /// **Default:** `true`. Set `false` only if you intentionally serve
    /// lists that legitimately collapse to near-zero between refreshes
    /// (very unusual for a blocklist). Recover a list that the guard
    /// refused with `warden lists forget <source>`.
    #[serde(default = "default_shrink_guard_enabled")]
    pub shrink_guard_enabled: bool,
    /// rev-2606 §06 `manager-01`: the maximum single-cycle shrink, as a
    /// percentage of the previous unique-domain count, that the retention
    /// guard tolerates before refusing the refresh. A drop **strictly
    /// greater** than this trips the guard; a drop equal to or below it is
    /// accepted (lists do get pruned upstream, so this must not be a hard
    /// "never shrink").
    ///
    /// **Default:** 90 — a list losing >90% of its domains in one cycle is
    /// the empty-body / error-page signature, not organic churn. Valid
    /// range 1..=100; rejected at validation time otherwise. The first
    /// fetch of a brand-new source has no baseline and is always accepted,
    /// so this never bricks initial provisioning.
    #[serde(default = "default_shrink_guard_max_drop_pct")]
    pub shrink_guard_max_drop_pct: u8,
}

impl Default for ListsConfig {
    fn default() -> Self {
        Self {
            sources: Vec::new(),
            update_interval_secs: default_update_interval_secs(),
            max_body_bytes: default_max_list_body_bytes(),
            max_entries: default_max_list_entries(),
            max_total_domains: default_max_total_domains(),
            cache_dir: default_cache_dir(),
            staleness_threshold_secs: default_staleness_threshold_secs(),
            shrink_guard_enabled: default_shrink_guard_enabled(),
            shrink_guard_max_drop_pct: default_shrink_guard_max_drop_pct(),
        }
    }
}

/// rev-2606 §06 `manager-01`: retention guard on by default — a security
/// product must not silently fail open when an upstream serves garbage.
fn default_shrink_guard_enabled() -> bool {
    true
}

/// rev-2606 §06 `manager-01`: a >90% single-cycle collapse is the
/// empty-body / error-page signature. See
/// [`ListsConfig::shrink_guard_max_drop_pct`].
fn default_shrink_guard_max_drop_pct() -> u8 {
    90
}

/// §4.7 Phase 2 T2: 24-hour staleness window for the TUI Lists badge.
/// See [`ListsConfig::staleness_threshold_secs`] for rationale.
fn default_staleness_threshold_secs() -> u64 {
    86_400
}

fn default_max_list_body_bytes() -> usize {
    // 200 MB — fits today's largest purge.cc lists with headroom.
    // See the `max_body_bytes` doc comment above for rationale.
    200 * 1024 * 1024
}

/// Global `[lists] max_entries` fallback, inherited by every
/// `[[blocklists]]` entry that does not set its own. Kept in step with
/// [`crate::lists::parser::DEFAULT_MAX_LIST_ENTRIES`], which carries the
/// measured rationale for 10M.
///
/// Note for operators upgrading: this default is only inherited by a
/// `[[blocklists]]` entry that does not pin its own `max_entries`. A
/// config that still pins the old `5000000` keeps that lower cap — and
/// exceeding a cap no longer truncates the overflow, it **refuses the
/// whole source** and keeps the previous generation. So a pinned 5M on a
/// list that has since grown past it makes that list disappear rather
/// than shrink. Re-pin or drop the override.
fn default_max_list_entries() -> usize {
    10_000_000
}

/// Global `[lists] max_total_domains` default — the ceiling on the merged
/// deduplicated corpus. See [`ListsConfig::max_total_domains`] for the
/// bands and for why this number and not another.
///
/// 14,000,000 was chosen to sit just under the 14,680,064-entry point at
/// which the old hash representation doubled every shard's bucket
/// allocation. `mem-t6` replaced that representation with exact-size
/// sorted slices, so **the point no longer exists** and the value survives
/// as a memory budget rather than as a cliff-avoidance number. It remains
/// a conservative default for the low-power positioning, and must never be
/// compared
/// against at runtime, which is why enforcement reads only this value.
/// Revisit the default if the domain map ever moves off power-of-two
/// bucket tables, since the step it avoids would no longer exist.
fn default_max_total_domains() -> usize {
    14_000_000
}

fn default_cache_dir() -> PathBuf {
    PathBuf::from("lists")
}

// ── [cache] ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CacheConfig {
    #[serde(default = "default_cache_max_entries")]
    pub max_entries: u64,
    #[serde(default = "default_cache_max_ttl_secs")]
    pub max_ttl_secs: u64,
    #[serde(default = "default_cache_min_ttl_secs")]
    pub min_ttl_secs: u64,
    #[serde(default = "default_cache_negative_ttl_secs")]
    pub negative_ttl_secs: u64,
    /// cache-03 (RFC 8767 serve-stale): seconds an expired entry stays
    /// servable as a stale fallback when upstream is unreachable — added to
    /// each entry's TTL by the moka expire-after policy. Default 300; RFC 8767
    /// permits much longer (up to days). The validator caps it at 86_400.
    /// Unset ⇒ 300 ⇒ byte-identical to the pre-knob hardcoded `STALE_BUFFER`.
    #[serde(default = "default_cache_stale_buffer_secs")]
    pub stale_buffer_secs: u64,
    /// Enable TTL-triggered prefetching. When a cache hit is within the last
    /// `prefetch_threshold` fraction of its TTL, serve immediately and spawn a
    /// background upstream refresh so the next query gets a fresh entry.
    #[serde(default = "default_cache_prefetch")]
    pub prefetch: bool,
    /// Fraction of TTL remaining that triggers prefetch (0.0–1.0, exclusive).
    /// Default 0.1 means "when 10% of TTL remains."
    #[serde(default = "default_cache_prefetch_threshold")]
    pub prefetch_threshold: f64,
    /// Maximum concurrent background prefetch tasks.
    #[serde(default = "default_cache_prefetch_max_concurrent")]
    pub prefetch_max_concurrent: usize,
    /// Maximum CNAME chain depth inspected when checking upstream responses
    /// against the filter. Default 16 (was hardcoded 8).
    #[serde(default = "default_cache_cname_max_depth")]
    pub cname_max_depth: usize,
    /// Sprint §4.4 P1 — master toggle for the hit-frequency tracker that
    /// underlies proactive prefetch. **Default `false`** — Phase 1 ships
    /// the data plane only; flipping to `true` populates the prefetch set
    /// for Phase 2/2 to consume. Independent from the existing
    /// `prefetch` (TTL-triggered Approach A) flag — both can be on
    /// together once Phase 2/2 ships.
    #[serde(default = "default_cache_prefetch_tracker_enabled")]
    pub prefetch_tracker_enabled: bool,
    /// Sliding-window length in seconds for the hit counter.
    #[serde(default = "default_cache_prefetch_tracker_window_secs")]
    pub prefetch_tracker_window_secs: u64,
    /// Minimum hits within a window for a domain to enter the prefetch set.
    #[serde(default = "default_cache_prefetch_tracker_min_hits")]
    pub prefetch_tracker_min_hits: u32,
    /// Soft cap on tracked domains. Sized for Pi Zero 2 W (512 MB RAM)
    /// at the default; bump on bigger boxes.
    #[serde(default = "default_cache_prefetch_tracker_max_pool_size")]
    pub prefetch_tracker_max_pool_size: u32,
    /// Sprint §4.4 P2 — interval in seconds at which the background
    /// refresh worker scans the promoted-domain set. Default 30.
    #[serde(default = "default_cache_prefetch_tracker_tick_secs")]
    pub prefetch_tracker_tick_secs: u64,
    /// Sprint §4.4 P2 — refresh an entry when its remaining TTL drops
    /// below this many seconds. Distinct from `prefetch_threshold`
    /// (Sprint 17 fraction-of-TTL gate); both can be on simultaneously.
    /// Default 10.
    #[serde(default = "default_cache_prefetch_tracker_lead_secs")]
    pub prefetch_tracker_lead_secs: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: default_cache_max_entries(),
            max_ttl_secs: default_cache_max_ttl_secs(),
            min_ttl_secs: default_cache_min_ttl_secs(),
            negative_ttl_secs: default_cache_negative_ttl_secs(),
            stale_buffer_secs: default_cache_stale_buffer_secs(),
            prefetch: default_cache_prefetch(),
            prefetch_threshold: default_cache_prefetch_threshold(),
            prefetch_max_concurrent: default_cache_prefetch_max_concurrent(),
            cname_max_depth: default_cache_cname_max_depth(),
            prefetch_tracker_enabled: default_cache_prefetch_tracker_enabled(),
            prefetch_tracker_window_secs: default_cache_prefetch_tracker_window_secs(),
            prefetch_tracker_min_hits: default_cache_prefetch_tracker_min_hits(),
            prefetch_tracker_max_pool_size: default_cache_prefetch_tracker_max_pool_size(),
            prefetch_tracker_tick_secs: default_cache_prefetch_tracker_tick_secs(),
            prefetch_tracker_lead_secs: default_cache_prefetch_tracker_lead_secs(),
        }
    }
}

// §4.41: the orphaned v0 `BlockResponse` enum was retired here. The v1
// block-response type is `config::schema::profile::BlockResponseV1`; the
// v0 3-variant enum (Zero / Nxdomain / Refused) had no live referents
// once the resolver moved onto the v1 schema.

// ── [[clients]] ────────────────────────────────────────────────

/// Client configuration — maps a device to a profile.
///
/// ```toml
/// [[clients]]
/// name = "laptop"
/// ip = "192.168.1.42"
/// mac = "AA:BB:CC:DD:EE:FF"
/// profile = "default"
/// ```
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ClientConfig {
    /// Friendly device name (unique identifier).
    pub name: String,
    /// Client IP address for identification.
    pub ip: IpAddr,
    /// Optional MAC address for identification (ARP table lookup, Sprint 8).
    #[serde(default)]
    pub mac: Option<String>,
    /// Additional MACs that also belong to this device. Modern OSes
    /// rotate their MAC per SSID or on a timer (iOS "Private Wi-Fi
    /// Address", Android/macOS randomisation), so a single physical
    /// device can present several different MACs over weeks. Listing
    /// them here lets the resolver treat any of them as a valid pin
    /// for this client without duplicating the row.
    ///
    /// The primary `mac` is still the one shown in the TUI's MAC
    /// column and reported in stats; aliases are only consulted by
    /// the ARP→profile resolver and by the uniqueness check. Format
    /// and uniqueness are validated the same as `mac`.
    ///
    /// Defaults to an empty list, so pre-Sprint-27 configs keep
    /// working unchanged.
    #[serde(default)]
    pub mac_aliases: Vec<String>,
    /// Profile name to apply (must exist in [profiles.*]).
    pub profile: String,
    /// Optional owner (free text). Never used by the filter engine — purely descriptive metadata.
    #[serde(default)]
    pub owner: Option<String>,
    /// Optional device type / category (free text, e.g. "iPad", "Smart TV").
    /// The `(owner, device_type)` pair is enforced unique across clients.
    /// Accepts the legacy `device` alias for v0.x configs (renamed in v0.4.3).
    #[serde(default, alias = "device")]
    pub device_type: Option<String>,
    /// Optional department / logical group (free text, e.g. "famiglia").
    #[serde(default)]
    pub department: Option<String>,
    /// Optional single-group membership coming from the TUI form.
    /// The v1 schema's `Device.groups` is a `Vec<Id>`; the TUI form
    /// enforces one group per device, but the wire stays a singular
    /// optional so existing v0 callers / tests don't carry the field
    /// at all (`#[serde(default)]`). The IPC v1 handler converts this
    /// to a `Vec<String>` of length 0 or 1 when it builds the v1
    /// entity TOML.
    #[serde(default)]
    pub group: Option<String>,
    /// Optional free-form notes (e.g. "compleanno: gennaio"). Ignored by the engine.
    #[serde(default)]
    pub notes: Option<String>,
}

// Test-only Default impl. Kept out of production builds so no code path
// can construct a `ClientConfig` with an unspecified IP + empty name +
// empty profile — a struct that is syntactically valid but semantically
// broken and would only fail at aggregate (cross-row) validation.
//
// Test sites use this via `..Default::default()` for ergonomic construction.
// Production construction (CLI, IPC) must set every field explicitly.
#[cfg(test)]
impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            mac: None,
            mac_aliases: Vec::new(),
            profile: String::new(),
            owner: None,
            device_type: None,
            department: None,
            group: None,
            notes: None,
        }
    }
}

// ── [[schedules]] ──────────────────────────────────

/// Schedule configuration — time-based profile overrides for clients.
///
/// Multiple schedules per client are allowed; first match wins (top to bottom).
///
/// ```toml
/// [[schedules]]
/// client = "tablet"
/// profile = "night"
/// days = ["weekdays"]
/// hours = "21:00-07:00"
///
/// # Sprint 23: optional one-shot expiry. After this RFC 3339 timestamp
/// # passes the schedule is treated as inactive AND pruned from the file
/// # by the next handle_schedule_tick (s23-schedule-tick-prune). Used by
/// # `warden client quiet --for 15m` to time-box block_all overrides.
/// [[schedules]]
/// client = "tablet"
/// profile = "blocked"
/// days = ["all"]
/// hours = "00:00-23:59"
/// expires_at = "2026-04-13T22:30:00Z"
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScheduleConfig {
    /// Client name (must match a `[[clients]]` entry).
    pub client: String,
    /// Profile to activate during this schedule (must exist in [profiles.*]).
    pub profile: String,
    /// Days when the schedule is active.
    /// Individual: "mon","tue","wed","thu","fri","sat","sun"
    /// Shortcuts: "weekdays" (mon-fri), "weekends" (sat-sun), "all"
    pub days: Vec<String>,
    /// Time range in 24h format "HH:MM-HH:MM". Midnight wrapping supported
    /// (e.g. "22:00-06:00" means 22:00→midnight→06:00).
    pub hours: String,
    /// Optional one-shot expiry — when set, the schedule stops being
    /// active after this UTC timestamp regardless of `days`/`hours`,
    /// AND the next `handle_schedule_tick` prunes it from the TOML
    /// file. Used by Sprint 23's `warden client quiet --for 15m`
    /// helper to time-box temporary overrides without leaving stale
    /// entries around forever.
    ///
    /// Validator rejects schedules where `expires_at` is in the past
    /// at create time so a typo can't accidentally land a "schedule
    /// that's already expired" entry. Stored as `time::OffsetDateTime`
    /// (per project rules "use time, not chrono"); the serde feature on
    /// the `time` crate handles RFC 3339 wire format.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub expires_at: Option<time::OffsetDateTime>,
}

// ── [socket] ──────────────────────────────────────────────────

/// Unix socket configuration for CLI↔daemon IPC.
///
/// ```toml
/// [socket]
/// path = "/run/purge-warden/control.sock"
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SocketConfig {
    /// Path to the Unix domain socket.
    /// Dev default: `./control.sock`
    /// Prod: `/run/purge-warden/control.sock`
    #[serde(default = "default_socket_path")]
    pub path: PathBuf,
}

impl Default for SocketConfig {
    fn default() -> Self {
        Self {
            path: default_socket_path(),
        }
    }
}

// ── [tracking] ────────────────────────────────────────────────

/// Stats tracking configuration — per-client counters, top-N, query log.
///
/// Sprint 37 flipped `query_log_enabled`'s default from `false` to
/// `true` so a fresh install shows DNS activity in the TUI without an
/// operator config edit, matching the Pi-hole / AdGuard Home
/// expectation. Existing configs with an explicit value — either
/// `true` or `false` — are unaffected; only deployments with no
/// `[tracking]` section at all pick up the new default on restart.
///
/// ```toml
/// [tracking]
/// enabled = true
/// snapshot_interval_secs = 120
/// top_n_limit = 20
/// query_log_enabled = true
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TrackingConfig {
    /// Enable stats tracking (global + per-device counters).
    #[serde(default = "default_tracking_enabled")]
    pub enabled: bool,
    /// How often to write stats snapshot to disk (seconds).
    #[serde(default = "default_snapshot_interval_secs")]
    pub snapshot_interval_secs: u64,
    /// Number of top domains to track.
    #[serde(default = "default_top_n_limit")]
    pub top_n_limit: usize,
    /// How often to recompute top-N from frequency maps (seconds).
    #[serde(default = "default_top_n_interval_secs")]
    pub top_n_interval_secs: u64,
    /// Maximum number of devices to track.
    ///
    /// T5 renamed from `max_clients`; the serde alias plus the loader
    /// WARN branch accept the legacy key for one release cycle.
    #[serde(default = "default_max_devices", alias = "max_clients")]
    pub max_devices: usize,
    /// Enable query logging to file. Sprint 38 QLP3 promotes the bare
    /// `#[serde(default)]` to a named default so a partial `[tracking]`
    /// section without this line still picks up S37's `true` default.
    #[serde(default = "default_query_log_enabled")]
    pub query_log_enabled: bool,
    /// Path to the query log file.
    #[serde(default = "default_query_log_path")]
    pub query_log_path: PathBuf,
    /// Max query log file size before rotation (MB). Post-Sprint 38 QLP2
    /// this is a *per-day* backstop — rotation is primarily calendar-
    /// based (`retention_days` drives deletion); a single day that
    /// exceeds the cap is split into numeric-suffix files.
    #[serde(default = "default_query_log_max_size_mb")]
    pub query_log_max_size_mb: u64,
    /// Max number of per-day numeric-suffix overflow files (Sprint 38
    /// QLP2 backstop). Normal operation is one file per day; this cap
    /// only kicks in when a single day's traffic exceeds
    /// `query_log_max_size_mb`.
    #[serde(default = "default_query_log_max_files")]
    pub query_log_max_files: usize,
    /// How many days of `query.log.YYYY-MM-DD` files to keep on disk.
    /// Primary retention knob after Sprint 38 QLP2 — older files are
    /// pruned by the writer at UTC midnight rotation. Range `[1, 365]`,
    /// validated at config load.
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
    /// How much to log per query. Sprint 38 QLP3. `All` logs everything
    /// (desktop / server default). `BlockedOnly` logs only queries whose
    /// result is `BLOCKED` — the Pi-recommended setting. `Sampled`
    /// always logs blocked queries and a fraction (`allowed_rate`) of
    /// allowed queries.
    #[serde(default)]
    pub log_mode: LogMode,
}

impl Default for TrackingConfig {
    fn default() -> Self {
        Self {
            enabled: default_tracking_enabled(),
            snapshot_interval_secs: default_snapshot_interval_secs(),
            top_n_limit: default_top_n_limit(),
            top_n_interval_secs: default_top_n_interval_secs(),
            max_devices: default_max_devices(),
            query_log_enabled: default_query_log_enabled(),
            query_log_path: default_query_log_path(),
            query_log_max_size_mb: default_query_log_max_size_mb(),
            query_log_max_files: default_query_log_max_files(),
            retention_days: default_retention_days(),
            log_mode: LogMode::default(),
        }
    }
}

/// Per-query logging decision (Sprint 38 QLP3 / design doc D3).
///
/// The enum drives an early-return branch at the top of
/// `StatsEngine::log_query_event` so `BlockedOnly` and `Sampled`'s
/// short-circuit skip the entire `QueryLogEntry` construction cost
/// (timestamp formatting, domain `String` alloc) on queries that won't
/// be logged.
///
/// TOML forms accepted:
/// ```toml
/// log_mode = "all"
/// log_mode = "blocked_only"
/// log_mode = { sampled = { allowed_rate = 0.1 } }
/// ```
/// The first two are the overwhelming common case; the table form is
/// only used when operators want the sampling variant (TUI always emits
/// the hardcoded `0.1` rate per QLP5 §3).
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(try_from = "LogModeRepr", into = "LogModeRepr")]
pub enum LogMode {
    /// Log every query. Desktop / server default.
    #[default]
    All,
    /// Log only queries whose `result == "BLOCKED"`. Pi-recommended.
    BlockedOnly,
    /// Log all blocked queries and a fraction of allowed queries at
    /// the given rate. Validator requires `0.0 <= allowed_rate <= 1.0`.
    Sampled { allowed_rate: f32 },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
enum LogModeRepr {
    Simple(String),
    Sampled { sampled: SampledRepr },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct SampledRepr {
    allowed_rate: f32,
}

impl TryFrom<LogModeRepr> for LogMode {
    type Error = String;
    fn try_from(repr: LogModeRepr) -> Result<Self, Self::Error> {
        match repr {
            LogModeRepr::Simple(s) => match s.as_str() {
                "all" => Ok(LogMode::All),
                "blocked_only" => Ok(LogMode::BlockedOnly),
                other => Err(format!(
                    "log_mode: unknown variant \"{other}\"; expected \"all\", \
                     \"blocked_only\", or the table form \
                     {{ sampled = {{ allowed_rate = <0.0..=1.0> }} }}"
                )),
            },
            LogModeRepr::Sampled { sampled } => Ok(LogMode::Sampled {
                allowed_rate: sampled.allowed_rate,
            }),
        }
    }
}

impl From<LogMode> for LogModeRepr {
    fn from(mode: LogMode) -> Self {
        match mode {
            LogMode::All => LogModeRepr::Simple("all".into()),
            LogMode::BlockedOnly => LogModeRepr::Simple("blocked_only".into()),
            LogMode::Sampled { allowed_rate } => LogModeRepr::Sampled {
                sampled: SampledRepr { allowed_rate },
            },
        }
    }
}

// ── [api] ─────────────────────────────────────────────────────

/// REST API configuration — optional HTTP server for programmatic access.
///
/// ```toml
/// [api]
/// enabled = true
/// listen = "127.0.0.1:8053"
/// token_hash = "abc123..."
/// ```
///
/// T2.5 H-11: `token_hash`, `tls_cert`, `tls_key` are `Option`-typed
/// (was `String::new()` sentinel pre-T2.5). For back-compat the
/// deserialiser still accepts `key = ""` from on-disk configs and
/// interprets it as `None`; serialisation skips `None` so the round-
/// trip output omits the key entirely. Consumers must still check
/// `.is_some()` (or use `.as_deref()` at the boundary).
///
/// Validator rules (`check_api`, rev-2606 `api-auth-07-01`/`07-02`;
/// all inert when `enabled = false`):
/// - `enabled = true` ⇒ `token_hash` must be set and non-blank.
/// - `enabled = true` + non-loopback `listen` ⇒ both `tls_cert` and
///   `tls_key` must be set (no cleartext bearer tokens off-host).
/// - `tls_cert` / `tls_key` must be set together — a half pair would
///   silently fall back to plain HTTP.
///
/// Loopback `listen` without TLS is allowed (plain HTTP stays local).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiConfig {
    /// Enable the REST API server.
    #[serde(default)]
    pub enabled: bool,
    /// Mount the `GET /metrics` OpenMetrics endpoint. Off by default —
    /// opt in to enable Prometheus / Grafana scraping. When `false` the
    /// route is not registered on the router (cleaner than returning 404
    /// from a registered handler — no surface for endpoint enumeration).
    #[serde(default)]
    pub metrics_enabled: bool,
    /// Listen address for the API server.
    ///
    /// TOML wire format is a string (e.g. `"127.0.0.1:8053"`); parsed
    /// to `SocketAddr` at deserialization so a typo fails fast at
    /// config load instead of late at server bind. Mirrors the
    /// fail-fast behaviour of `ServerConfig.listen`.
    #[serde(default = "default_api_listen")]
    pub listen: SocketAddr,
    /// Path to TLS certificate (required if listen is non-loopback).
    #[serde(
        default,
        deserialize_with = "empty_string_as_none_pathbuf",
        skip_serializing_if = "Option::is_none"
    )]
    pub tls_cert: Option<PathBuf>,
    /// Path to TLS private key (required if listen is non-loopback).
    #[serde(
        default,
        deserialize_with = "empty_string_as_none_pathbuf",
        skip_serializing_if = "Option::is_none"
    )]
    pub tls_key: Option<PathBuf>,
    /// SHA-256 hash of the API token (set by `warden token generate`).
    #[serde(
        default,
        deserialize_with = "empty_string_as_none",
        skip_serializing_if = "Option::is_none"
    )]
    pub token_hash: Option<String>,
    /// Max authenticated API requests per minute per client IP (fixed
    /// window, enforced by `api::rate_limit::ApiRateLimiter`; over-budget
    /// requests get `429` + `Retry-After`). `0` disables the limiter.
    /// `/healthz` and `/metrics` are exempt — monitoring pollers never
    /// count against it.
    #[serde(default = "default_api_rate_limit")]
    pub rate_limit_per_minute: u32,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            metrics_enabled: false,
            listen: default_api_listen(),
            tls_cert: None,
            tls_key: None,
            token_hash: None,
            rate_limit_per_minute: default_api_rate_limit(),
        }
    }
}

// ── [security] ───────────────────────────────────────────────────

/// Top-level security configuration with nested sub-sections.
///
/// ```toml
/// [security]
/// enabled = true
///
/// [security.rrl]
/// responses_per_second = 100
///
/// [security.rate_limit]
/// queries_per_second = 100
///
/// [security.tunneling]
/// entropy_threshold = 3.5
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityConfig {
    /// Master switch for all security features.
    #[serde(default = "default_security_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub rrl: RrlConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub tunneling: TunnelingConfig,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rrl: RrlConfig::default(),
            rate_limit: RateLimitConfig::default(),
            tunneling: TunnelingConfig::default(),
        }
    }
}

/// Response Rate Limiting — prevents the server from being used as a
/// DNS amplification reflector. Tracks response rate per destination:
/// per exact client address inside `server.allow_from`, per /24 (IPv4) or
/// /48 (IPv6) prefix outside it.
///
/// ```toml
/// [security.rrl]
/// enabled = true
/// responses_per_second = 100
/// window_secs = 15
/// slip_rate = 2
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RrlConfig {
    #[serde(default = "default_rrl_enabled")]
    pub enabled: bool,
    /// Max responses per second before throttling, per RRL bucket.
    ///
    /// The bucket is the exact client address for sources inside a
    /// configured `server.allow_from` CIDR, and the /24 (or /48) prefix
    /// for everyone else — see [`crate::security::rrl::client_key`]. It
    /// used to be the prefix unconditionally, which made this an aggregate
    /// ceiling for an entire household rather than a per-device one.
    ///
    /// # Sizing note for operators (Part C, `security-rrl-cli-and-prefix-scope`)
    ///
    /// The effective budget is `responses_per_second * window_secs`, not a
    /// per-second cap: at the defaults that is 100 × 15 = 1500 responses
    /// per 15s window.
    ///
    /// The live the lab host CT runs `responses_per_second = 5` — 20×
    /// stricter than this default, with no recorded decision behind it.
    /// Under the old prefix keying that was 75 responses per 15s for the
    /// **whole house**, which is what let a 500-query burst from one dev
    /// box throttle a Philips Hue bridge on 2026-07-28. Per-client keying
    /// makes 5 far less dangerous, since the budget is now per device —
    /// but it is still tight for a browser: a single page load can issue
    /// 30-50 lookups, so two heavy loads inside one window can exhaust 75.
    ///
    /// Unresolved deliberately: whether that box should be restored to the
    /// default or keep a documented low value is an operator decision, and
    /// changing it is a live-config edit on a resolver serving real
    /// household DNS. Flagged, not silently "fixed".
    #[serde(default = "default_rrl_responses_per_second")]
    pub responses_per_second: u32,
    /// Sliding window in seconds for tracking response rates.
    #[serde(default = "default_rrl_window_secs")]
    pub window_secs: u64,
    /// Slip rate: 1-in-N throttled responses get a TC (truncated) reply
    /// instead of being dropped. Forces legitimate clients to retry via TCP.
    /// 0 = drop all, 1 = always TC, 2 = 50% TC, etc.
    #[serde(default = "default_rrl_slip_rate")]
    pub slip_rate: u32,
}

impl Default for RrlConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            responses_per_second: default_rrl_responses_per_second(),
            window_secs: default_rrl_window_secs(),
            slip_rate: default_rrl_slip_rate(),
        }
    }
}

/// Per-client query rate limiting via token bucket.
///
/// ```toml
/// [security.rate_limit]
/// enabled = true
/// queries_per_second = 100
/// burst = 200
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitConfig {
    #[serde(default = "default_rate_limit_enabled")]
    pub enabled: bool,
    /// Sustained queries per second allowed per client IP.
    #[serde(default = "default_rate_limit_qps")]
    pub queries_per_second: u32,
    /// Burst capacity — how many queries can be sent instantly before throttling.
    #[serde(default = "default_rate_limit_burst")]
    pub burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            queries_per_second: default_rate_limit_qps(),
            burst: default_rate_limit_burst(),
        }
    }
}

/// DNS tunneling detection heuristics.
///
/// ```toml
/// [security.tunneling]
/// enabled = true
/// label_len_threshold = 48
/// max_unbroken_run = 40
/// entropy_threshold = 3.5
/// entropy_min_len = 64
/// subdomain_rate = 50
/// window_secs = 60
/// exempt_domains = []
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TunnelingConfig {
    #[serde(default = "default_tunneling_enabled")]
    pub enabled: bool,
    /// Shannon entropy threshold over the concatenated non-apex labels.
    ///
    /// Only consulted once the concatenation reaches
    /// [`Self::entropy_min_len`]. This gate was the primary shape signal
    /// until it was measured: it refused 92% of one live server's
    /// traffic while being unable to see a tunnel that encodes with 11
    /// or fewer distinct symbols (entropy per character cannot exceed
    /// `log2(alphabet)`). It is kept, and kept configurable, but it is
    /// no longer load-bearing.
    #[serde(default = "default_tunneling_entropy_threshold")]
    pub entropy_threshold: f64,
    /// Label length threshold — labels this long or longer are
    /// suspicious. Catches payloads that pad with `-` to stay under
    /// [`Self::max_unbroken_run`].
    #[serde(default = "default_tunneling_label_len_threshold")]
    pub label_len_threshold: usize,
    /// Longest `-`-free run within the non-apex labels before the name
    /// is flagged. The primary shape signal.
    #[serde(default = "default_tunneling_max_unbroken_run")]
    pub max_unbroken_run: usize,
    /// Concatenated non-apex length below which [`Self::entropy_threshold`]
    /// is never evaluated.
    #[serde(default = "default_tunneling_entropy_min_len")]
    pub entropy_min_len: usize,
    /// Max cache-missing queries per (client, base domain) per window
    /// before flagging (tunneling-rate-01: cached repeats don't count,
    /// and one client's fan-out can't exhaust another's budget).
    #[serde(default = "default_tunneling_subdomain_rate")]
    pub subdomain_rate: u32,
    /// Window in seconds for subdomain rate tracking.
    #[serde(default = "default_tunneling_window_secs")]
    pub window_secs: u64,
    /// Suffixes exempt from *every* tunneling check — both the shape
    /// gates and the per-`(client, base)` rate counter.
    ///
    /// The operator's escape hatch. The shape gates run before profile
    /// resolution and before the filter engine, so no allow rule can
    /// reach a name they refuse; without this list a false positive has
    /// no remedy short of disabling tunneling detection outright.
    ///
    /// Matching is by label boundary: `a2z.com` exempts `x.y.a2z.com`
    /// but not `evil-a2z.com`.
    #[serde(default)]
    pub exempt_domains: Vec<String>,
}

impl Default for TunnelingConfig {
    fn default() -> Self {
        Self {
            enabled: default_tunneling_enabled(),
            entropy_threshold: default_tunneling_entropy_threshold(),
            label_len_threshold: default_tunneling_label_len_threshold(),
            max_unbroken_run: default_tunneling_max_unbroken_run(),
            entropy_min_len: default_tunneling_entropy_min_len(),
            subdomain_rate: default_tunneling_subdomain_rate(),
            window_secs: default_tunneling_window_secs(),
            exempt_domains: Vec::new(),
        }
    }
}

// ── [anti_bypass] ────────────────────────────────────────────────

/// Anti-bypass: refuse queries for the resolver domains **the operator
/// names**, so clients cannot circumvent the filter by using an external
/// resolver.
///
/// ```toml
/// [anti_bypass]
/// enabled = true
/// extra_domains = ["my-vpn-dns.example.com"]
/// ```
///
/// **`enabled = true` on its own does nothing.** `neutrality-01` deleted the
/// built-in resolver list — warden holds no opinion about which resolvers
/// exist — so the checker refuses exactly the names below and no others. That
/// pairing (`enabled` true, `extra_domains` empty) is the *default*, which is
/// why the validator warns about it on every load rather than staying quiet
/// about a security setting that is on and inert.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AntiBypassConfig {
    #[serde(default = "default_anti_bypass_enabled")]
    pub enabled: bool,
    /// The resolver names to refuse — **the whole list, not an addition to
    /// one.** Empty means nothing is refused.
    #[serde(default)]
    pub extra_domains: Vec<String>,
}

impl Default for AntiBypassConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            extra_domains: Vec::new(),
        }
    }
}

// ── [[forwarding]] ──────────────────────────────────────────────

/// Conditional DNS forwarding — route queries for specific domain suffixes
/// to specific upstream resolvers (split DNS).
///
/// ```toml
/// [[forwarding]]
/// suffix = "local"
/// mode = "plain"
/// servers = ["192.168.1.1:53"]
///
/// [[forwarding]]
/// suffix = "corp.example.com"
/// mode = "dot"
/// servers = ["vpn-dns.example.com:853"]
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ForwardingZoneConfig {
    /// Domain suffix to match (e.g. "local", "corp.example.com").
    /// Queries ending in this suffix are forwarded to the zone's upstream.
    pub suffix: String,
    /// Upstream mode for this zone.
    #[serde(default)]
    pub mode: UpstreamMode,
    /// Upstream servers for this zone.
    pub servers: Vec<String>,
}

// ── [ip_blocklists] ─────────────────────────────────────────────

/// IP blocklist configuration — block responses that resolve to known-bad IPs.
///
/// ```toml
/// [ip_blocklists]
/// enabled = true
/// sources = ["https://example.com/bad-ips.txt"]
/// inline = ["1.2.3.4", "fd00::bad"]
/// ```
///
/// The legacy TOML section name `[ip_denylists]` is still accepted via a
/// serde alias on the parent struct — operators running pre-v0.4.4 configs
/// see a deprecation WARN at load but the daemon starts normally.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct IpBlocklistConfig {
    #[serde(default)]
    pub enabled: bool,
    /// URL sources for IP blocklists (one IP per line, # comments).
    #[serde(default)]
    pub sources: Vec<String>,
    /// Inline IPs to block (always applied).
    #[serde(default)]
    pub inline: Vec<String>,
}

// ── [local_dns] ─────────────────────────────────────────────────

/// Local DNS records — static A/AAAA/CNAME entries that bypass filtering.
///
/// ```toml
/// [local_dns]
/// ttl_secs = 3600
///
/// [[local_dns.records]]
/// domain = "nas.home"
/// type = "A"
/// value = "192.168.1.50"
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LocalDnsConfig {
    /// Fallback TTL (seconds) for local DNS responses. Precedence
    /// (rev-2606 cfg-validator-01/02): a record's own `ttl_secs` wins
    /// where set; this value covers every record without an override
    /// (both global and profile scope), the auto-generated PTR records
    /// of non-overridden entries, and the NODATA negative TTL. Validator
    /// enforces `1..=86_400` — the same DR5 bound as the per-record
    /// override. Default 3600.
    #[serde(default = "default_local_dns_ttl_secs")]
    pub ttl_secs: u32,
    /// TTL (seconds) for `network_name` dynamic-device answers
    /// specifically — deliberately short and distinct from
    /// [`Self::ttl_secs`], since the underlying IP can change between
    /// resolver refreshes. Validator enforces `1..=86_400`, same DR5
    /// bound as `ttl_secs`. Default 30.
    #[serde(default = "default_local_dns_dynamic_ttl_secs")]
    pub dynamic_ttl_secs: u32,
    /// When `true` (default), a query for a locally-defined name whose
    /// qtype has no local record is answered NODATA (NOERROR + SOA)
    /// instead of being forwarded upstream. Prevents internal hostnames
    /// leaking to the public resolver and the AAAA-first NXDOMAIN trap
    /// (RFC 2308 negative caching is per-name, so an upstream NXDOMAIN
    /// for a private TLD can suppress the A record we DO hold). Set
    /// `false` to restore split-horizon fall-through for missing types.
    #[serde(default = "default_local_dns_nodata_for_missing_types")]
    pub nodata_for_missing_types: bool,
    /// Static DNS records.
    #[serde(default)]
    pub records: Vec<LocalDnsRecord>,
}

impl Default for LocalDnsConfig {
    fn default() -> Self {
        Self {
            ttl_secs: default_local_dns_ttl_secs(),
            dynamic_ttl_secs: default_local_dns_dynamic_ttl_secs(),
            nodata_for_missing_types: default_local_dns_nodata_for_missing_types(),
            records: Vec::new(),
        }
    }
}

/// A single local DNS record entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct LocalDnsRecord {
    /// Domain name (e.g. "nas.home").
    pub domain: String,
    /// Record type: A, AAAA, or CNAME.
    #[serde(rename = "type")]
    pub record_type: LocalDnsRecordType,
    /// Value: IPv4 address, IPv6 address, or target domain name.
    pub value: String,
    /// S44 DM2: opt-in subdomain matching. When `true` the record matches
    /// the apex AND every descendant via longest-suffix-match. The validator
    /// rejects this on public suffixes (DR9) and on the empty domain (DR10).
    /// Default `false` keeps Sprint 18 exact-match semantics for existing
    /// configs (R1 additive only).
    #[serde(default)]
    pub match_subdomains: bool,
    /// S44 DM3: per-record TTL override. `None` falls back to
    /// `[local_dns].ttl_secs`. Validator enforces `1..=86_400`. Honored
    /// on BOTH scopes since rev-2606 cfg-validator-02 (the global path
    /// previously served the fallback regardless); the record's derived
    /// PTR entries inherit the same effective TTL.
    #[serde(default)]
    pub ttl_secs: Option<u32>,
}

/// Supported local DNS record types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum LocalDnsRecordType {
    A,
    AAAA,
    CNAME,
}

/// §4.12 — a single domain-rewrite rule.
///
/// Rewrites a queried qname before resolution begins. Useful for domain
/// migrations (`api.old.com → api.new.com`) and "fake CNAME" without
/// committing a `[[local_dns.records]]` row.
///
/// ```toml
/// [[profiles.employees.rewrite_rules]]
/// from = "api.old.com"
/// to = "api.new.com"
/// match_subdomains = false
/// ```
///
/// Hot-path semantics live in `crate::dns::rewrite::ProfileRewriteRules`;
/// validation lives in `crate::config::validator::validate_rewrite_rules`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct RewriteRule {
    /// Source FQDN to match. Empty + `match_subdomains` is refused
    /// (would match every query). Public suffixes refused when
    /// `match_subdomains: true` (footgun).
    pub from: String,
    /// Replacement FQDN. Single-pass at runtime — the result is NOT
    /// re-fed into the rewrite table (DR2 depth=1).
    pub to: String,
    /// Mirrors `LocalDnsRecord.match_subdomains` (S44 DM2). When `true`,
    /// `from` matches the apex AND any descendant; the descendant's
    /// label prefix is preserved when rewriting onto `to` (e.g.
    /// `api.old.com → api.new.com` for `*.old.com → *.new.com`).
    #[serde(default)]
    pub match_subdomains: bool,
}

// ── DNSSEC validation (§4.10) ─────────────────────────────────────────────
//
// Opt-in, OFF by default. The `[dnssec]` section is parsed *unconditionally*
// (these types are not behind the `dnssec` cargo feature) so that an operator's
// `mode = "validate"` deserialises on any build; the validation machinery
// itself lives in the feature-gated `crate::dnssec` module. **§4.10-1 ships
// this scaffold inert** — nothing reads `mode` or the DoS caps yet; they wire
// up in §4.10-2..4.

/// DNSSEC validation mode (§4.10). Default [`DnssecMode::Off`] — DNSSEC is
/// opt-in.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DnssecMode {
    /// No DNSSEC processing (default). The AD bit is not set; upstream answers
    /// are returned unmodified.
    #[default]
    Off,
    /// Validate signatures and reject bogus answers with SERVFAIL (§4.10-4).
    Validate,
    /// Validate but never block: log/count bogus answers and still return them.
    /// For staged rollout and debugging (§4.10-4).
    LogOnly,
}

impl std::fmt::Display for DnssecMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Off => write!(f, "off"),
            Self::Validate => write!(f, "validate"),
            Self::LogOnly => write!(f, "log-only"),
        }
    }
}

/// `[dnssec]` configuration section (§4.10). The DoS caps and cache TTL carry
/// the design-doc defaults. **Inert in §4.10-1** — parsed and stored but not
/// yet consumed; validation and cap enforcement land in later sprints.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnssecConfig {
    /// Validation mode. Default `off`.
    pub mode: DnssecMode,
    /// DoS cap: maximum DS→DNSKEY chain depth to follow. Default 10.
    pub max_chain_depth: u8,
    /// DoS cap: maximum upstream queries per validation. Default 30.
    pub max_queries: u16,
    /// DoS cap: maximum NSEC3 hash iterations to accept. Default 150.
    pub max_nsec3_iterations: u16,
    /// DoS cap: maximum total RRSIG signature verifications per chain validation
    /// (KeyTrap / CVE-2023-50387 guard). Counted globally across the whole walk —
    /// every hop's DS/DNSKEY checks, the NSEC/NSEC3 denial proofs, and the final
    /// answer share this one budget, so the per-hop cost cannot be multiplied by
    /// `max_chain_depth` / `max_queries` hops. Default 256: a legitimate walk
    /// fetches at most `max_queries` (30) RRsets and spends ~1 verification each
    /// (a few for a multi-key / multi-algorithm zone), so 256 clears the deepest
    /// real chain with wide margin while bounding a colliding-16-bit-key-tag flood
    /// to 256 crypto operations total instead of O(keys × sigs × hops).
    pub max_signature_verifications: u16,
    /// Validation-result cache TTL, in seconds. Default 3600 (1 hour).
    pub cache_ttl_secs: u64,
}

impl Default for DnssecConfig {
    fn default() -> Self {
        Self {
            mode: DnssecMode::Off,
            max_chain_depth: 10,
            max_queries: 30,
            max_nsec3_iterations: 150,
            max_signature_verifications: 256,
            cache_ttl_secs: 3600,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_mode_doq_parses_and_displays() {
        // The `doq` variant always deserializes (feature-independent) so a
        // feature-off binary rejects it at startup with a clear error rather
        // than a generic serde "unknown variant".
        #[derive(serde::Deserialize)]
        struct W {
            mode: UpstreamMode,
        }
        let w: W = toml::from_str(r#"mode = "doq""#).expect("mode = \"doq\" must parse");
        assert_eq!(w.mode, UpstreamMode::Doq);
        assert_eq!(w.mode.to_string(), "doq");

        // Full upstream block with bare host:port servers (no scheme prefix,
        // consistent with `dot`).
        let cfg: UpstreamConfig = toml::from_str(
            r#"
mode = "doq"
servers = ["dns.quad9.net:853"]
"#,
        )
        .expect("doq upstream config parses");
        assert_eq!(cfg.mode, UpstreamMode::Doq);
        assert_eq!(cfg.servers, vec!["dns.quad9.net:853".to_string()]);
    }

    #[test]
    fn deserialize_client_without_metadata_fields_is_retrocompat() {
        // §4.41: rewritten off the v0 `Settings` `[[clients]]` envelope
        // onto a direct `ClientConfig` parse — `ClientConfig` survives as
        // the IPC `[[devices]]` wire type. A pre-Sprint-22 client block
        // must still deserialize cleanly: owner/device/department/tags/
        // notes default to None / empty vec. If anyone removes
        // `#[serde(default)]` from `tags`, every existing config breaks.
        let toml = r#"
name = "legacy-laptop"
ip = "192.168.1.42"
mac = "AA:BB:CC:DD:EE:FF"
profile = "default"
"#;
        let c: ClientConfig = toml::from_str(toml).expect("legacy client should deserialize");
        assert_eq!(c.name, "legacy-laptop");
        assert_eq!(c.profile, "default");
        assert!(c.owner.is_none(), "owner must default to None");
        assert!(c.device_type.is_none(), "device must default to None");
        assert!(c.department.is_none(), "department must default to None");
        assert!(c.notes.is_none(), "notes must default to None");
    }

    // ── ScheduleConfig expires_at (Sprint 23 s23-schedule-expires-at) ──
    //
    // §4.41: rewritten off the v0 `Settings` `[[schedules]]` envelope
    // onto direct `ScheduleConfig` parses — `ScheduleConfig` survives as
    // the migration exchange type consumed by `profiles::schedule`.

    #[test]
    fn schedule_without_expires_at_is_retrocompat() {
        // A pre-Sprint-23 schedule block must deserialize with
        // expires_at = None. Every existing config on disk relies on
        // this — without #[serde(default)] the old configs would
        // hard-fail at parse time after upgrade.
        let toml = r#"
client = "tablet"
profile = "night"
days = ["weekdays"]
hours = "21:00-07:00"
"#;
        let sched: ScheduleConfig = toml::from_str(toml).expect("legacy schedule must parse");
        assert!(sched.expires_at.is_none());
    }

    #[test]
    fn schedule_expires_at_rfc3339_roundtrip() {
        let toml = r#"
client = "tablet"
profile = "blocked"
days = ["all"]
hours = "00:00-23:59"
expires_at = "2026-04-13T22:30:00Z"
"#;
        let sched: ScheduleConfig = toml::from_str(toml).unwrap();
        let exp = sched.expires_at.expect("expires_at must parse");
        assert_eq!(exp.year(), 2026);
        assert_eq!(exp.hour(), 22);

        // Forward path: serialized form must round-trip back.
        let back = toml::to_string(&sched).unwrap();
        let sched2: ScheduleConfig = toml::from_str(&back).unwrap();
        assert_eq!(sched2.expires_at, Some(exp));
    }

    // ── T2.5 H-10: per-section enabled defaults are decoupled ────
    //
    // Pre-T2.5 a single `default_tracking_enabled()` was wired to six
    // unrelated `enabled` toggles via `#[serde(default = ...)]`. These
    // tests pin the post-fix shape: each section deserialises its own
    // default from a partial TOML that omits the `enabled` line, so a
    // future flip of one helper cannot leak into the others. Round-trip
    // through `toml::from_str(...)` exercises serde's named-default
    // path — the very call the shared helper used to feed.

    #[test]
    fn h10_default_tracking_enabled_isolated_from_security_helpers() {
        let s: TrackingConfig = toml::from_str("").unwrap();
        assert!(
            s.enabled,
            "tracking.enabled must default to true via its own helper"
        );
    }

    #[test]
    fn h10_default_security_enabled_isolated() {
        let s: SecurityConfig = toml::from_str("").unwrap();
        assert!(
            s.enabled,
            "security.enabled must default to true via its own helper"
        );
    }

    #[test]
    fn h10_default_rrl_enabled_isolated() {
        let s: RrlConfig = toml::from_str("").unwrap();
        assert!(
            s.enabled,
            "security.rrl.enabled must default to true via its own helper"
        );
    }

    #[test]
    fn h10_default_rate_limit_enabled_isolated() {
        let s: RateLimitConfig = toml::from_str("").unwrap();
        assert!(
            s.enabled,
            "security.rate_limit.enabled must default to true via its own helper"
        );
    }

    #[test]
    fn h10_default_tunneling_enabled_isolated() {
        let s: TunnelingConfig = toml::from_str("").unwrap();
        assert!(
            s.enabled,
            "security.tunneling.enabled must default to true via its own helper"
        );
    }

    #[test]
    fn h10_default_anti_bypass_enabled_isolated() {
        let s: AntiBypassConfig = toml::from_str("").unwrap();
        assert!(
            s.enabled,
            "anti_bypass.enabled must default to true via its own helper"
        );
    }

    // ── T2.5 / M-02: subsection default-fixpoint discipline ──────
    //
    // §4.41: the whole-`Settings` round-trip fixpoint test and the v0
    // `ApiConfig` sentinel→Option migration tests were retired with the
    // `Settings` envelope. The per-subsection fixpoint check below
    // survives — it covers every staying pass-through sub-struct
    // directly, which is the coverage that actually guards
    // `#[serde(default = "...")]` vs `impl Default` drift.

    #[test]
    fn m02_settings_default_subsection_defaults_are_internally_consistent() {
        // M-02 corollary: each top-level subsection round-trips
        // independently — a regression that affects only one section
        // (e.g. someone adds a #[serde(default)] field with no
        // matching impl Default constructor) is named in the failure
        // message instead of being lost in a bulk round-trip dump.
        macro_rules! check {
            ($name:literal, $ty:ty) => {{
                let v = <$ty as Default>::default();
                let first = toml::to_string(&v).expect(concat!($name, ": default serializes"));
                let parsed: $ty =
                    toml::from_str(&first).expect(concat!($name, ": default re-parses"));
                let second =
                    toml::to_string(&parsed).expect(concat!($name, ": re-parsed re-serializes"));
                assert_eq!(
                    first, second,
                    "{}: TOML round-trip is not a fixpoint",
                    $name
                );
            }};
        }
        check!("ServerConfig", ServerConfig);
        check!("UpstreamConfig", UpstreamConfig);
        check!("ListsConfig", ListsConfig);
        check!("CacheConfig", CacheConfig);
        check!("SocketConfig", SocketConfig);
        check!("TrackingConfig", TrackingConfig);
        check!("ApiConfig", ApiConfig);
        check!("SecurityConfig", SecurityConfig);
        check!("AntiBypassConfig", AntiBypassConfig);
        check!("LocalDnsConfig", LocalDnsConfig);
        check!("IpBlocklistConfig", IpBlocklistConfig);
        check!("DnssecConfig", DnssecConfig);
    }

    /// §5-review (settings-fixpoint-test-gaps): the `m02` macro covers
    /// only `Default`-bearing top-level sections, so `LogMode::Sampled`
    /// (the table form `{ sampled = { allowed_rate = .. } }`, distinct
    /// from the default `All`) had no round-trip coverage — the riskiest
    /// uncovered serde path. Exercise it through its `TrackingConfig`
    /// envelope so a break in the `LogModeRepr` try_from/into shim fails
    /// loudly.
    #[test]
    fn m02b_log_mode_sampled_round_trips() {
        let t = TrackingConfig {
            log_mode: LogMode::Sampled { allowed_rate: 0.25 },
            ..Default::default()
        };
        let first = toml::to_string(&t).expect("TrackingConfig+Sampled serializes");
        let parsed: TrackingConfig =
            toml::from_str(&first).expect("TrackingConfig+Sampled re-parses");
        assert!(
            matches!(
                parsed.log_mode,
                LogMode::Sampled { allowed_rate } if (allowed_rate - 0.25).abs() < f32::EPSILON
            ),
            "Sampled.allowed_rate did not survive the TOML round-trip"
        );
        let second = toml::to_string(&parsed).expect("TrackingConfig+Sampled re-serializes");
        assert_eq!(
            first, second,
            "TrackingConfig + LogMode::Sampled TOML round-trip is not a fixpoint"
        );
    }

    /// §4.7 Phase 2 T2: the staleness threshold defaults to 24 h
    /// (86_400 s) when the operator's TOML omits the field, AND a
    /// pre-Phase-2 config (no `staleness_threshold_secs` line under
    /// `[lists]`) deserialises with the same value via
    /// `#[serde(default = "default_staleness_threshold_secs")]`.
    #[test]
    fn staleness_threshold_config_field_default_86400() {
        // Programmatic default — Default::default() round-trip.
        let cfg = ListsConfig::default();
        assert_eq!(cfg.staleness_threshold_secs, 86_400);

        // TOML deserialisation default — operator omits the field.
        let toml = r#"
            sources = []
            update_interval_secs = 43200
        "#;
        let parsed: ListsConfig = toml::from_str(toml).expect("parse legacy lists config");
        assert_eq!(parsed.staleness_threshold_secs, 86_400);

        // Explicit value wins over default.
        let toml_explicit = r#"
            sources = []
            staleness_threshold_secs = 7200
        "#;
        let parsed_explicit: ListsConfig = toml::from_str(toml_explicit).unwrap();
        assert_eq!(parsed_explicit.staleness_threshold_secs, 7200);
    }
}

#[cfg(test)]
mod dynamic_ttl_tests {
    use super::*;

    #[test]
    fn local_dns_config_default_has_dynamic_ttl_30() {
        assert_eq!(LocalDnsConfig::default().dynamic_ttl_secs, 30);
    }

    #[test]
    fn dynamic_ttl_secs_deserialises_from_toml() {
        let toml_src = r#"
ttl_secs = 3600
dynamic_ttl_secs = 15
"#;
        let cfg: LocalDnsConfig = toml::from_str(toml_src).unwrap();
        assert_eq!(cfg.dynamic_ttl_secs, 15);
    }
}
