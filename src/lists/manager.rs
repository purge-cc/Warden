//! List download manager with periodic background refresh.
//!
//! `ListManager` orchestrates the full list lifecycle:
//! 1. Resolve source IDs to URLs via the [`Catalog`]
//! 2. Download each list via HTTP (with If-Modified-Since / ETag)
//! 3. Parse all lists into a bitmask-tagged `HashMap<domain, u64>`
//! 4. Atomically swap the domain map into the [`FilterEngine`] via `ArcSwap`
//!
//! Each source is assigned a unique bit index (0-63). A domain's bitmask
//! indicates which lists contain it. Profiles use this for per-list filtering.
//!
//! On 304 Not Modified or download failure, the manager re-uses the
//! previously cached response body for that source, ensuring the merged
//! domain map always contains domains from ALL sources.
//!
//! The background refresh runs on a configurable interval (default 60 min).
//! If a refresh fails entirely, the previous domain map stays live.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ahash::RandomState;
use compact_str::CompactString;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::{mpsc, oneshot};
use tokio::time::interval as tokio_interval;

use super::catalog::Catalog;
use super::detector::ListFormat;
use super::parser::{parse_list_streaming, DomainSink};
use super::readiness::ReadinessGate;
use super::source_key::{SourceBitMap, SourceTokenMap, SourceTrustMap};
use super::status::{
    compute_delta_pct, format_blocklist_shrink_refused, CorpusRefusal, CycleOutcome, LastOutcome,
    ListStatus, ListStatusRegistry, ParsedCounts, BLOCKLIST_DELTA_WARN, DELTA_WARN_THRESHOLD_PCT,
};
use crate::config::schema::BlocklistTrust;
use crate::filter::engine::{ListPolicy, PolicyMasks, SortedShard, DOMAIN_SHARDS};
// Only named by the neutrality-06 direction tests, which assert on
// `SortedShard::split`'s return type. Producing code stores raw source
// bits and never constructs a `DomainMasks`.
#[cfg(test)]
use crate::filter::engine::DomainMasks;
use crate::filter::FilterEngine;
use crate::ipc::protocol::IpcNotification;

/// Synthetic URL host reserved by `warden blocklist import-local` for
/// `trust = local` blocklists. The validator at
/// `src/config/schema/validator.rs:197` only accepts `http(s)://` schemes
/// (rewriting it was OUT OF SCOPE for S50 T3 — see the doc-comment at
/// `src/cli/commands/blocklists.rs:855-866`), so T3 sidesteps the gap by
/// writing this synthetic placeholder. T5.5 closes the loop by teaching
/// the list-manager to intercept this host in `download_list` and read
/// the body from `<config_dir>/lists/<id>.<ext>` on disk.
const IMPORTED_LOCAL_HOST: &str = "imported.local";

// Body size cap is now a per-ListManager field sourced from
// `settings.lists.max_body_bytes` (default 200 MB). See `ListManager::new`
// and `read_bounded_body` for the flow. The rationale for making this
// configurable — and why the old hardcoded value was too low — is in
// _docs/reviews/2026-04-09_security-meeting.md: the first smoke test of Sprint 19 revealed that
// `security/malicious` had grown to ~114 MB in the wild, exceeding both
// the old 100 MB constant and the 50 MB value P0-1 mistakenly aligned to.

/// Minimum refresh interval (60 seconds). Prevents accidental tight loops.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// `mem2608-s7` — emitted once at startup when a [`ListManager`] is built
/// with no cache directory.
///
/// The cost is named because the alternative is silence: with no
/// `cache_dir` the raw text of every list stays in `ListCache.body` beside
/// the domain map, and the end-of-cycle sweep that would drop it is gated
/// on `cache_dir.is_some()`. At the corpus this product targets that is a
/// few hundred MB of duplicate residency, and `resolve_body_reader` clones
/// each body again for every parse.
///
/// Frozen string: it is an operator-facing diagnostic, and it names a
/// consequence rather than a state, so it stays greppable across releases.
const LIST_CACHE_DIR_UNSET_WARNING: &str =
    "no list cache directory configured: every downloaded list body stays resident in RAM \
     for the life of the process, and is copied again on each refresh — expect roughly \
     double the memory of a cached deployment. Set `lists.cache_dir` to a writable path.";

/// Out-of-band commands the refresh loop accepts in addition to its
/// scheduled ticker. Sent over an `mpsc` channel wired by `start.rs`;
/// the loop's `tokio::select!` either ticks (normal refresh) or drains
/// one command per iteration.
///
/// §4.7 Phase 2 T1: the only variant today is `Forget`, the surgical
/// escape hatch from a cache poisoned by a list maintainer. New variants
/// can land here as future polish items (e.g. force-refresh-one)
/// without touching the IPC plumbing path.
#[derive(Debug)]
pub enum ListManagerCommand {
    /// Forget a list source: drop its in-memory cache entry and
    /// unlink the `<stem>.cache` + `<stem>.meta` sidecar on disk.
    /// Best-effort — unlink failures are logged but never fail the
    /// request. The oneshot carries `was_cached`: true when the
    /// source had any state (in-memory entry OR on-disk file) before
    /// the call.
    Forget {
        source: String,
        ack: oneshot::Sender<bool>,
    },
}

/// How much younger than `interval` a cached body must be to count as
/// fresh (`mem2608-t0`).
///
/// Without it the scheduled refresh **can never fetch**, by construction.
/// The ticker is fixed-period and anchored at spawn (`spawn_refresh_loop`),
/// but the cycle anchor `now` is read *inside* `refresh` — strictly after
/// the tick fires. So the age at the next tick is `interval − δ` for some
/// `δ > 0`, `whole_seconds()` floors that to `interval − 1`, and the body
/// reads fresh forever. Measured on the lab host 2026-08-13/16: five
/// consecutive cycles alternating fetch / skip, an effective 24 h interval
/// against a configured 12 h.
///
/// Five seconds is three orders of magnitude above the tick→anchor
/// scheduler latency this absorbs, and 8 % of [`MIN_REFRESH_INTERVAL`] at
/// the tightest interval the config will accept — so it can shorten a
/// cycle but never collapse one. The other half of the fix is
/// [`ListManager::refresh_at`] stamping the cycle anchor rather than the
/// download's completion; that half removes the *unbounded* term (the
/// serial fetch lag, 119–421 s measured), and this one removes what is
/// left. Neither half works alone: see `PLAN-a.md` §1.
const CACHE_FRESHNESS_MARGIN: Duration = Duration::from_secs(5);

/// Pure freshness predicate used by `refresh()` to decide whether to
/// skip an HTTP request. Returns true when the cached entry was fetched
/// more than [`CACHE_FRESHNESS_MARGIN`] short of `interval` ago.
/// Extracted as a free function so the rule can be unit-tested without a
/// `ListManager` or a real HashMap entry.
///
/// The margin is subtracted from `interval` (saturating, so a margin at
/// or above the interval cannot invert the predicate into "always
/// fresh") rather than added to `age`, which would overflow on a
/// far-future `fetched_at`.
fn is_cache_fresh(fetched_at: OffsetDateTime, now: OffsetDateTime, interval: Duration) -> bool {
    let age = now - fetched_at;
    if age.is_negative() {
        // Clock skew or fetched_at in the future — treat as not fresh
        // so a misconfigured timestamp does not freeze updates.
        return false;
    }
    let interval_secs = interval.saturating_sub(CACHE_FRESHNESS_MARGIN).as_secs() as i64;
    age.whole_seconds() < interval_secs
}

/// Whether a refresh cycle is allowed to reach the network.
///
/// The boot caller is `load_corpus_before_bind` in `start.rs`, which runs
/// [`RefreshMode::CacheOnly`] so the DNS listener can bind on the
/// persisted corpus instead of waiting on HTTP — per
/// `_docs/features/boot_list_persistence.md` §2.1/§2.2. `start.rs` no
/// longer calls [`ListManager::refresh`] at boot at all; the one inline
/// `refresh()` left there is `handle_reload`'s, which runs **after** the
/// bind. Do not restore an inline network refresh ahead of the bind on
/// the belief that this is unwired scaffolding — that is the 199 s boot
/// this mechanism exists to remove.
///
/// Everything below the fetch — spill, `corpus_guard`, the
/// shrink guard, the corpus digest, `build_shard` / `swap_shard` — is
/// shared by both modes on purpose: two strands of map-building code
/// would drift, and those guards are exactly where a silently unfiltered
/// boot comes from.
///
/// See `_docs/features/boot_list_persistence.md` §2.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshMode {
    /// Conditional GETs, the age-based freshness shortcut, 304 handling.
    /// The background loop, the signal-loop reload, and `warden lists
    /// refresh`.
    Network,
    /// Zero HTTP. The on-disk `.cache` is used at **any** age — a cache
    /// too old to be fresh is still infinitely better than no filtering,
    /// and the background cycle behind the listener is what refreshes it.
    CacheOnly,
}

/// §4.31: thin adapter over [`hardened_atomic_write`](crate::config::atomic_write::hardened_atomic_write) so the
/// `.cache` / `.meta` sidecar writes here share the same fsync +
/// mode-preservation contract as every config-mutation path.
/// Returns `std::io::Result` because the call-sites in `refresh()`
/// already log + continue on a per-list write failure; mapping the
/// richer `AtomicWriteError` through to `io::Error` keeps the
/// callsite untouched.
fn atomic_write(path: &Path, content: &[u8]) -> std::io::Result<()> {
    crate::config::atomic_write::hardened_atomic_write(
        path,
        content,
        crate::config::atomic_write::AtomicWriteOpts::default(),
    )
    .map_err(std::io::Error::other)
}

/// Per-URL cached state: HTTP conditional headers + last successful body
/// + the wall-clock timestamp of the most recent successful fetch.
///
/// On 304 Not Modified or download failure, the cached `body` is re-used
/// when building the merged domain map, so no source's domains are lost.
///
/// `fetched_at` is the freshness check anchor used by `s24-list-cache-freshness-check`
/// in Phase 1.2: `refresh()` skips the HTTP request when
/// `now - fetched_at < refresh_interval`, eliminating crash-loop
/// amplification (100 restarts in 12h → 0 upstream fetches if bodies
/// are still fresh). Defaults to `OffsetDateTime::now_utc()` for new
/// in-memory entries — every existing call site of `or_default()`
/// either immediately overwrites with a parsed-meta value
/// (`load_disk_cache`) or with a post-download stamp (`download_list`),
/// so the `now_utc()` default is only ever observable on a freshly-
/// constructed entry that has not yet been used to gate a refresh.
#[derive(Debug, Clone)]
struct ListCache {
    etag: Option<String>,
    last_modified: Option<String>,
    /// Last successfully downloaded body text. Re-parsed into the merged map
    /// on every refresh cycle (even on 304) to ensure all sources contribute.
    ///
    /// **Only ever `Some` when there is no `cache_dir`** — with one, the body
    /// goes to disk and `refresh` clears this at the end of every cycle. That
    /// makes the retention latent rather than live, and `mem2608-s7` narrows
    /// it further: `lists.cache_dir` is a non-optional config field with a
    /// default, and every production construction passes `Some(_)`, so no
    /// operator can reach this state. A future call site can.
    ///
    /// Two costs if one ever does, and the second is not in the design doc:
    /// the bodies are resident for the life of the process, **and**
    /// [`ListManager::resolve_body_reader`] hands out `body.clone()` — a full
    /// second copy of the largest list, per source, per cycle. See
    /// [`LIST_CACHE_DIR_UNSET_WARNING`].
    body: Option<String>,
    /// Wall-clock UTC timestamp of the most recent successful fetch
    /// (`200 OK` or `304 Not Modified` — both confirm the cached
    /// content is current). Persisted to the `.meta` sidecar as an
    /// RFC 3339 line so it survives daemon restarts.
    fetched_at: OffsetDateTime,
}

impl Default for ListCache {
    fn default() -> Self {
        Self {
            etag: None,
            last_modified: None,
            body: None,
            fetched_at: OffsetDateTime::now_utc(),
        }
    }
}

/// Manages list downloads, parsing, and periodic refresh into the FilterEngine.
///
/// Owns a shared `reqwest::Client` (connection pooling), a per-URL cache,
/// and a reference to the `FilterEngine` for atomic domain map swaps.
pub struct ListManager {
    client: reqwest::Client,
    filter: Arc<FilterEngine>,
    sources: Vec<String>,
    catalog: Catalog,
    refresh_interval: Duration,
    /// Per-URL cache: conditional headers + last body for 304/error resilience.
    cache: HashMap<String, ListCache>,
    /// The operator's list policy, projected onto this manager's bit
    /// assignment by [`SourceBitMap::project_policy`].
    ///
    /// Defaults to empty, which is block-nothing/allow-nothing, so every
    /// existing construction site keeps inert semantics; `start.rs` and
    /// `update.rs` opt in from config via [`Self::set_list_policy`].
    ///
    /// **Held as masks, never as config.** It arrives already projected, so
    /// the manager never re-derives a bit from an id and cannot disagree with
    /// the projection the shards were published against.
    policy_masks: PolicyMasks,
    /// Source → bit index mapping. Each source gets a unique bit (0-63).
    /// rev-2606 §06 carryover-5: the typed [`SourceBitMap`] facade rather
    /// than the raw `HashMap<String, u8>` — the manager's fetch loop keys
    /// by URL via [`SourceBitMap::bit_for_url`], and the typed surface
    /// keeps the id/legacy channels reachable without a parallel map.
    source_bits: SourceBitMap,
    /// Source → resolved bearer token (Sprint 32 N9; §4.24 P2-B typed
    /// facade). Lookups by legacy slash-form source key (manager's
    /// fetch path) via [`SourceTokenMap::token_for_url`]; lookups by
    /// canonical v1 [`crate::config::schema::id::Id`] via
    /// [`SourceTokenMap::token_for_v1_id`] (new typed surface).
    /// Presence turns the outbound HTTP request into
    /// `Authorization: Bearer <v>`; absence leaves the request
    /// untouched. See the `SourceTokenMap` doc-comment for the
    /// pure-v1 latent gap rationale.
    source_tokens: SourceTokenMap,
    /// Maximum body size allowed per blocklist download, from
    /// `settings.lists.max_body_bytes`. Enforced mid-stream by
    /// [`read_bounded_body`] so a malicious or misconfigured server
    /// cannot OOM the daemon.
    max_body_bytes: usize,
    /// Maximum entries per list, from `settings.lists.max_entries`.
    ///
    /// Bounds **one** source, and therefore bounds nothing in aggregate:
    /// eight sources at 10 M each is 80 M on paper. See
    /// [`Self::max_total_domains`] for the ceiling on the merged corpus.
    max_entries: usize,
    /// Ceiling on the **deduplicated** merged corpus, from
    /// `settings.lists.max_total_domains`. `None` when the operator set
    /// `0`, which disables the guard and its counting pass alike.
    ///
    /// Stored as an `Option` rather than a `usize::MAX` sentinel on
    /// purpose: the warn band is a fraction of this value, and a sentinel
    /// would put that arithmetic one careless multiplication away from
    /// overflowing. `None` makes the whole band unreachable.
    max_total_domains: Option<usize>,
    /// rev-2606 §06 `manager-01`: retention guard on/off, from
    /// `settings.lists.shrink_guard_enabled` (default `true`). When on, a
    /// freshly downloaded body that shrinks a previously-healthy list past
    /// [`Self::shrink_guard_max_drop_pct`] is refused — the prior cache is
    /// kept and the source flips `Failed` with a visible reason instead of
    /// silently overwriting the good cache with ~0 domains.
    shrink_guard_enabled: bool,
    /// rev-2606 §06 `manager-01`: max single-cycle shrink (percent of the
    /// prior unique-domain count) the guard tolerates; a drop strictly
    /// greater trips. From `settings.lists.shrink_guard_max_drop_pct`
    /// (default 90).
    shrink_guard_max_drop_pct: u8,
    /// Optional directory for on-disk list caching. When set, downloaded
    /// list bodies are persisted as `{stem}.cache` files with `.meta`
    /// sidecars holding HTTP ETag/Last-Modified. On construction,
    /// [`load_disk_cache`](Self::load_disk_cache) pre-populates the
    /// in-memory cache from these files so the first refresh can use
    /// conditional requests and survive network outages.
    cache_dir: Option<PathBuf>,
    /// Latching "this process has installed a filter generation" flag,
    /// shared with the DNS handler. See
    /// `_docs/features/boot_list_persistence.md` §2.4.
    ///
    /// [`ReadinessGate`] has no `close`, and its atomic is private to
    /// `lists::readiness` — a sibling module, so nothing in here can
    /// reach it. "Never closes" is enforced by the type, not by the
    /// comment at the open site.
    filter_ready: Option<ReadinessGate>,
    /// Per-source runtime telemetry (S43 T1, DM3). Built once from the
    /// configured `sources`, shared with the IPC layer via the same
    /// `Arc<ListStatusRegistry>`. Each `refresh()` call atomically swaps
    /// in a fresh [`ListStatus`] per source.
    status_registry: Arc<ListStatusRegistry>,
    /// Optional persistence path for `prev_entries`. When set, every
    /// successful `refresh()` writes `{path}` atomically so `delta_pct_vs_prev`
    /// survives daemon restarts. `None` in tests / ephemeral runs.
    status_persistence_path: Option<PathBuf>,
    /// Sprint 43 T2: optional broadcast channel for
    /// [`IpcNotification::ListStatsUpdated`]. Published once per source
    /// at the end of each refresh cycle (success OR failure). `None`
    /// when no subscribers are wired (e.g. tests, or daemon configs
    /// where the IPC subscriber endpoint is disabled). Send errors
    /// (no live subscribers) are intentionally swallowed — broadcast
    /// is fire-and-forget.
    notification_tx: Option<tokio::sync::broadcast::Sender<IpcNotification>>,
    /// S50 T5.5: per-source trust map used by the `imported.local`
    /// loader-bridge for the W2.1 defence-in-depth check at fetch time.
    /// Sources missing from this map default to
    /// [`BlocklistTrust::RemoteUnsigned`] — the safe assumption when no
    /// explicit trust is wired (legacy `lists.sources` entries that
    /// pre-date the v1 `[[blocklists]].trust` field).
    ///
    /// §4.24 Phase 2 (P2-A) replaced the raw `HashMap<String,
    /// BlocklistTrust>` with the typed [`SourceTrustMap`] facade so
    /// future consumers (TUI inspect, audit attribution) can resolve
    /// trust by canonical [`Id`](crate::config::schema::id::Id) without
    /// monkey-patching a reverse lookup through the URL.
    source_trust: SourceTrustMap,
    /// S50 T5.5: directory containing `config.toml`, used to resolve
    /// synthetic `imported.local` URLs to `<config_dir>/lists/<id>.<ext>`
    /// on disk. `None` disables the bridge entirely (tests + ephemeral
    /// runs); the manager falls back to the HTTP path for every URL,
    /// including `imported.local` ones — which then fail at
    /// `validate_list_url` with a `DisallowedHost` error, surfacing the
    /// misconfiguration rather than silently doing nothing.
    local_bridge_dir: Option<PathBuf>,
    /// Sprint B of `lists_categories_v2` (T5, D8/D9/D10): in-memory
    /// view of `data/list_state.toml`. Persisted atomically through
    /// [`Self::record_blocklist_success`] / [`Self::record_blocklist_failure`]
    /// at every transition. `Arc<Mutex<…>>` because the manager is
    /// shared across the refresh task + the optional reload-time
    /// resolver rebuild (Sprint C will read the same handle to drive
    /// list_applies status checks).
    list_state: Arc<std::sync::Mutex<crate::config::list_state::ListState>>,
    /// Path on disk for `list_state.toml`. `None` in tests / ephemeral
    /// runs — the helpers still mutate the in-memory state but skip
    /// the atomic write.
    list_state_path: Option<PathBuf>,
    /// Sprint C T2 of `lists_categories_v2` (§14.2.b refresh wire-in):
    /// maps a source string (the keys of `sources` / `source_bits`,
    /// either legacy slash-form like `"privacy/ads"` or a raw URL like
    /// `"https://lists.purge.cc/…"`) to the canonical
    /// [`crate::config::schema::Id`] used by the retry state machine
    /// **and** the blocklist's per-list `max_consecutive_failures`
    /// threshold.
    ///
    /// Pre-Sprint-C the refresh loop kept its source-string keys, while
    /// `record_blocklist_success` / `record_blocklist_failure` keyed on
    /// canonical `Id` — the cross-reference closes that gap so each
    /// refresh cycle drives the state machine.
    ///
    /// Wired by [`Self::set_source_blocklist_map`] from the daemon's
    /// `start.rs`, which has access to `[[blocklists]]` (canonical id +
    /// max_consecutive_failures) and the `merged_sources` it derives
    /// from `lists.sources` ∪ `[[blocklists]].url`.
    source_to_blocklist: HashMap<String, (crate::config::schema::Id, u32)>,
    /// rev-2606 §06 `parser-02`: source-string → operator-declared parse
    /// format, populated by [`Self::set_source_format_map`] from `start.rs`.
    /// Holds **only** sources whose `[[blocklists]]` row declares `hosts` or
    /// `adguard`; a declared (or omitted) `domains` is absent so the parse
    /// dispatch falls back to content auto-detection. Keyed identically to
    /// [`Self::source_to_blocklist`] (url / slash-form / canonical id) so the
    /// refresh loop's `source`-string lookup hits regardless of source form.
    source_to_format: HashMap<String, super::detector::ListFormat>,
    /// §4.7 Phase 2 T1: out-of-band command channel drained by the
    /// refresh loop's `tokio::select!`. `None` for tests / ephemeral
    /// runs that never call [`Self::set_command_channel`] — the loop
    /// then degrades to ticker-only and the IPC `ForgetList` handler
    /// is unreachable.
    cmd_rx: Option<mpsc::Receiver<ListManagerCommand>>,
    /// §11 T5: digest of the corpus behind the currently-installed
    /// generation — SHA-256 over each source's `(id, bit, body hash)` in
    /// iteration order. A cycle that recomputes the same digest is
    /// rebuilding a map byte-identical to the live one, so it skips pass 2
    /// entirely: no map build, no swap, no cluster re-encode.
    ///
    /// In-memory only, and deliberately so. It is cleared whenever this
    /// cycle's view of any source is incomplete, and it starts `None` — so
    /// the first refresh after a restart always builds, which is required:
    /// there is no map yet.
    installed_corpus_digest: Option<[u8; 32]>,
    /// Test-only: how many cycles actually ran pass 2. The §11 T5
    /// short-circuit is otherwise invisible from outside — a skipped
    /// rebuild and a rebuild that produces the same map are
    /// indistinguishable through every public accessor, so a test without
    /// this would pass whether or not the short-circuit fired.
    #[cfg(test)]
    rebuild_count: usize,
    /// Test-only: how many cycles the `mem2608-s1` T3 probe settled without
    /// walking the sources. Same reason as `rebuild_count`, one level up: a
    /// probed cycle and a parsed-then-skipped cycle install the same map and
    /// log the same lines, so the saving is invisible to every assertion
    /// that does not count this. A probe that silently never fires is the
    /// failure mode with no symptom.
    #[cfg(test)]
    probe_skips: usize,
}

#[cfg(test)]
thread_local! {
    /// Test-only: how many sources **this thread** built a dedup set for.
    ///
    /// `mem2608-s1` T2's saving is "the set was not built", and no output
    /// distinguishes that from "the set was built and agreed with the
    /// carried number" — same counts, same map, same log lines. Without
    /// this counter the T2 test would pass on the unfixed code, which is
    /// the failure mode this lane keeps finding in other people's tests.
    ///
    /// Thread-local rather than a `static`, because the suite runs tests in
    /// parallel threads and a shared counter would make one test's
    /// arithmetic depend on its neighbours. A `#[tokio::test]` drives its
    /// future on the thread that starts it, so a refresh's sinks are all
    /// built here.
    static SOURCES_MEASURED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl ListManager {
    /// Create a new list manager.
    ///
    /// `sources` are list IDs (e.g. `"privacy/ads"`) or raw URLs.
    /// `refresh_interval` is clamped to a minimum of 60 seconds.
    /// `source_bits` maps each source to its bit index for bitmask tagging.
    /// `max_body_bytes` is the per-download size cap; typical value is
    /// `settings.lists.max_body_bytes` (default 200 MB).
    /// `max_entries` is the per-list entry cap; typical value is
    /// `settings.lists.max_entries` (default
    /// [`DEFAULT_MAX_LIST_ENTRIES`](super::parser::DEFAULT_MAX_LIST_ENTRIES)).
    /// A source past it is refused whole, so the cap counts validated
    /// domains only — see [`ParsedCounts::parsed_truncated`].
    /// `cache_dir` enables on-disk persistence when `Some`; pass `None`
    /// to disable (tests, ephemeral runs).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client: reqwest::Client,
        filter: Arc<FilterEngine>,
        sources: Vec<String>,
        catalog: Catalog,
        refresh_interval: Duration,
        source_bits: SourceBitMap,
        max_body_bytes: usize,
        max_entries: usize,
        cache_dir: Option<PathBuf>,
    ) -> Self {
        Self::with_tokens(
            client,
            filter,
            sources,
            catalog,
            refresh_interval,
            source_bits,
            SourceTokenMap::default(),
            max_body_bytes,
            max_entries,
            cache_dir,
        )
    }

    /// Construct with an additional `source_tokens` facade
    /// (Sprint 32 N9; §4.24 P2-B typed). Lookups happen by legacy
    /// slash-form source key on the manager's fetch path; values are
    /// resolved bearer tokens from `secrets.toml`. Callers that have
    /// no secrets pass [`SourceTokenMap::default`] — behaviour is
    /// identical to [`Self::new`].
    #[allow(clippy::too_many_arguments)]
    pub fn with_tokens(
        client: reqwest::Client,
        filter: Arc<FilterEngine>,
        sources: Vec<String>,
        catalog: Catalog,
        refresh_interval: Duration,
        source_bits: SourceBitMap,
        source_tokens: SourceTokenMap,
        max_body_bytes: usize,
        max_entries: usize,
        cache_dir: Option<PathBuf>,
    ) -> Self {
        let refresh_interval = refresh_interval.max(MIN_REFRESH_INTERVAL);
        let status_registry = Arc::new(ListStatusRegistry::new(&sources));
        // Startup: `FilterEngine::shard_index` is seeded per process, so a
        // spill partition left by a previous (crashed) daemon is silent
        // garbage to this one — ~15/16 of every list would be unreachable
        // if it were ever resumed. Delete, never resume.
        if let Some(dir) = cache_dir.as_deref() {
            purge_shard_spill(dir);
        }
        Self {
            client,
            filter,
            sources,
            catalog,
            refresh_interval,
            cache: HashMap::new(),
            policy_masks: PolicyMasks::default(),
            source_bits,
            source_tokens,
            max_body_bytes,
            max_entries,
            // Off unless the caller opts in via `set_max_total_domains`,
            // so no existing construction site silently acquires a
            // ceiling — and, more to the point, so none of them silently
            // acquires the counting pass's cost.
            max_total_domains: None,
            // rev-2606 §06 manager-01: guard on by default so the product
            // behaviour (and every test that builds a manager) gets the
            // protective path; start.rs overrides from config via
            // `set_shrink_guard`.
            shrink_guard_enabled: true,
            shrink_guard_max_drop_pct: 90,
            cache_dir,
            filter_ready: None,
            status_registry,
            status_persistence_path: None,
            notification_tx: None,
            source_trust: SourceTrustMap::default(),
            local_bridge_dir: None,
            list_state: Arc::new(std::sync::Mutex::new(
                crate::config::list_state::ListState::default(),
            )),
            list_state_path: None,
            source_to_blocklist: HashMap::new(),
            source_to_format: HashMap::new(),
            cmd_rx: None,
            installed_corpus_digest: None,
            #[cfg(test)]
            rebuild_count: 0,
            #[cfg(test)]
            probe_skips: 0,
        }
    }

    /// Sprint B of `lists_categories_v2` (T5): wire the persistent
    /// retry-state machine. Replaces the in-memory empty default with
    /// the state read from disk and remembers `path` so the per-
    /// transition helpers can write back atomically.
    ///
    /// Idempotent — calling twice with different state is fine, the
    /// second call wins.
    pub fn set_list_state(
        &mut self,
        state: crate::config::list_state::ListState,
        path: Option<PathBuf>,
    ) {
        *self.list_state.lock().unwrap_or_else(|e| e.into_inner()) = state;
        self.list_state_path = path;
    }

    /// Sprint B of `lists_categories_v2` (T5): handle to the in-memory
    /// list state. The Sprint C resolver-rebuild path will read this
    /// to populate the `Option<&ListState>` argument
    /// `ResolvedProfile::build_v1` accepts in T2; for now the handle
    /// lets the daemon's reload pipeline reach it.
    pub fn list_state_handle(&self) -> Arc<std::sync::Mutex<crate::config::list_state::ListState>> {
        self.list_state.clone()
    }

    /// Sprint C T2 of `lists_categories_v2` (§14.2.b refresh wire-in):
    /// register the source-string → (canonical `Id`,
    /// `max_consecutive_failures`) mapping the refresh loop consults
    /// when it needs to drive the retry state machine.
    ///
    /// `start.rs` builds `map` from the same `merged_sources` +
    /// `[[blocklists]]` view used to seed [`SourceBitMap`], so every
    /// source the manager refreshes either has a canonical id (and a
    /// per-list threshold) here, or it is a legacy slash-form / raw
    /// URL with no `[[blocklists]]` row — the latter case skips the
    /// state-machine call by design (state machine only tracks
    /// canonical-id blocklists).
    ///
    /// Idempotent — calling twice replaces the prior map. No side
    /// effects on existing `list_state` entries; the next refresh
    /// cycle simply uses the new lookup.
    pub fn set_source_blocklist_map(
        &mut self,
        map: HashMap<String, (crate::config::schema::Id, u32)>,
    ) {
        self.source_to_blocklist = map;
    }

    /// rev-2606 §06 `parser-02`: register the source-string → declared parse
    /// format map. `start.rs` builds it from the same `[[blocklists]]` view as
    /// [`Self::set_source_blocklist_map`], inserting only sources that declare
    /// `hosts`/`adguard` (a `domains`/omitted format is left out so the parse
    /// dispatch defers to auto-detection). Idempotent — the next refresh cycle
    /// uses the new lookup.
    pub fn set_source_format_map(&mut self, map: HashMap<String, super::detector::ListFormat>) {
        self.source_to_format = map;
    }

    /// Sprint B of `lists_categories_v2` (T5): record a successful
    /// blocklist refresh, transitioning the entry to Active and
    /// stamping its cache_path. Persists to disk if a state-file
    /// path was wired via [`Self::set_list_state`].
    ///
    /// Public so the Sprint C refresh-loop wire-in can call it once
    /// the source→blocklist mapping is plumbed (currently the
    /// refresh task keys on legacy slash-form / URL strings; the
    /// state-machine keys on canonical [`Id`](crate::config::schema::Id)).
    pub fn record_blocklist_success(
        &self,
        blocklist_id: &crate::config::schema::Id,
        cache_path: PathBuf,
    ) {
        let now = time::OffsetDateTime::now_utc();
        // Recover a poisoned lock instead of panicking — a panic here would
        // tear down the background refresh loop. The critical section holds
        // no invariant a poisoning panic could leave half-broken (a counter
        // bump + an atomic file write), so the inner state is safe to reuse.
        let mut state = self.list_state.lock().unwrap_or_else(|e| e.into_inner());
        let entry = state.lists.entry(blocklist_id.clone()).or_default();
        entry.record_success(now, cache_path);
        if let Some(path) = self.list_state_path.as_ref() {
            if let Err(e) = state.write_atomic(path) {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "failed to persist list_state.toml after success"
                );
            }
        }
    }

    /// Sprint B of `lists_categories_v2` (T5): record a failed
    /// blocklist refresh. Increments `consecutive_failures`;
    /// transitions to Failed when the threshold is reached. Persists
    /// to disk if a state-file path was wired.
    ///
    /// Returns `true` when this call flipped the entry to Failed
    /// (i.e. crossed the threshold). The caller may use the boolean
    /// for an audit-log line on the transition itself.
    pub fn record_blocklist_failure(
        &self,
        blocklist_id: &crate::config::schema::Id,
        max_consecutive_failures: u32,
    ) -> bool {
        let now = time::OffsetDateTime::now_utc();
        // Recover a poisoned lock instead of panicking — a panic here would
        // tear down the background refresh loop. The critical section holds
        // no invariant a poisoning panic could leave half-broken (a counter
        // bump + an atomic file write), so the inner state is safe to reuse.
        let mut state = self.list_state.lock().unwrap_or_else(|e| e.into_inner());
        let entry = state.lists.entry(blocklist_id.clone()).or_default();
        let flipped = entry.record_failure(now, max_consecutive_failures);
        if let Some(path) = self.list_state_path.as_ref() {
            if let Err(e) = state.write_atomic(path) {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "failed to persist list_state.toml after failure"
                );
            }
        }
        flipped
    }

    /// rev-2606 §06 `manager-01`: decide whether a freshly downloaded
    /// body's unique-domain count is acceptable versus the prior cycle.
    ///
    /// Baseline is the prior `unique_domains` (the dedup- and
    /// order-independent per-source count), falling back to the persisted
    /// `prev_entries` when no unique baseline exists yet (a v1→v2 upgrade
    /// or a source that only ever recorded the merged-map delta). When no
    /// baseline exists at all — the first fetch of a brand-new source —
    /// the body is always accepted so initial provisioning is never
    /// bricked. The guard being disabled is also an unconditional accept.
    ///
    /// Trip is exact integer arithmetic (no float-percent floor
    /// ambiguity): a drop *strictly greater* than `max_drop_pct` percent
    /// trips, i.e. `fresh * 100 < baseline * (100 - max_drop_pct)`. An
    /// accepted refresh whose movement (shrink OR growth) still exceeds
    /// [`DELTA_WARN_THRESHOLD_PCT`] carries that delta so the caller can
    /// emit the loud-but-allowed supply-chain canary warning.
    fn shrink_verdict(&self, prev: Option<&ListStatus>, fresh_unique: u64) -> ShrinkVerdict {
        compute_shrink_verdict(
            self.shrink_guard_enabled,
            self.shrink_guard_max_drop_pct,
            prev,
            fresh_unique,
        )
    }

    /// `mem2608-s1` T3 — decide whether this cycle can be settled from the
    /// cached bodies' **bytes**, without parsing any of them.
    ///
    /// Returns `Some` only when every source would take the fresh-cache arm
    /// **and** the digest folded from their bodies equals the one describing
    /// the installed generation. `None` means "walk the sources as usual" and
    /// is the answer to every doubt: a missing bit, an unreadable body, a
    /// source with no prior status, one byte different — all fall through to
    /// the full path. The failure direction is a wasted read, never a skipped
    /// rebuild.
    ///
    /// **Why re-hash instead of trusting a stored hash.** The `.cache`
    /// directory is a trust boundary this module already guards
    /// (`cache_dir_lax_mode`), and the sidecar's `size=` cannot see a body
    /// whose bytes changed at constant length. A digest built from metadata
    /// would declare "nothing changed" for exactly the tampering a skipped
    /// rebuild would then pin in place. Reading the bodies costs one
    /// sequential pass and ~64 KB; parsing them costs 220 MiB.
    ///
    /// **The two hashes must agree byte-for-byte or this silently never
    /// fires.** The parse path hashes what the parser consumes
    /// ([`HashingReader`]); this hashes the whole file. They agree because
    /// the parser reads to EOF and its format sniff consumes through the
    /// same reader (`sniff_format_reader` takes `&mut R`, so the prefix is
    /// counted once and replayed from a separate cursor). A no-op probe is
    /// pure cost with no symptom, which is why a test asserts it *fires*
    /// rather than only that it is correct when it does.
    ///
    /// **`mode` is here only to decide `verified_fresh`**, never to gate the
    /// probe: the shortcut is worth taking under either mode. The probe
    /// enforces `is_cache_fresh` itself, so a settled source *is* interval-
    /// fresh even on a `CacheOnly` boot — but stamping a verified refresh
    /// there would mean a cycle that issued no HTTP and was never allowed to
    /// still reported one, which is the freshness lie
    /// `boot_list_persistence.md` §2.8 prohibits. Keeping the rule uniform —
    /// *no `CacheOnly` cycle stamps a verified refresh, by any route* — is
    /// worth more than the one extra green row this path could claim.
    fn probe_unchanged_corpus(
        &self,
        resolved: &[(String, String)],
        now: OffsetDateTime,
        interval: Duration,
        mode: RefreshMode,
    ) -> Option<ProbeOutcome> {
        let installed = self.installed_corpus_digest?;
        // No disk cache means the bodies live in RAM (or nowhere); that
        // path has its own problems (see `mem2608-s7`) and is not worth a
        // second code path here.
        self.cache_dir.as_ref()?;

        let mut digest_ctx = new_corpus_digest_ctx(&self.policy_masks);
        let mut pending = Vec::with_capacity(resolved.len());
        let mut spilled = 0u64;

        for (source, url) in resolved {
            let bit = self.source_bits.bit_for_url(source.as_str())?;
            let cached = self.cache.get(url.as_str())?;
            if !is_cache_fresh(cached.fetched_at, now, interval) {
                return None;
            }
            // Every counter this cycle would report has to come from the
            // previous one — the bodies are unchanged, so they are the same
            // counters. A source that has never reported cannot be settled
            // this way.
            let prev = self.status_registry.status_for_url(source)?;
            if prev.last_outcome != LastOutcome::Ok {
                return None;
            }
            // Deliberately the same opener the parse path uses, so the
            // §4.7-T3 `size=` validation still runs and a body the loop
            // would have rejected is never quietly accepted here.
            let reader = self.resolve_body_reader(url, source)?;
            let body_hash = hash_body(reader).ok()?;
            let declared_format = self.source_to_format.get(source.as_str()).copied();
            fold_corpus_digest(
                &mut digest_ctx,
                source,
                1u64 << bit,
                self.max_entries,
                declared_format,
                &body_hash,
            );
            spilled += prev.parsed_ok;
            pending.push(PendingStatus {
                source: source.clone(),
                bit,
                counts: ParsedCounts {
                    parsed_ok: prev.parsed_ok,
                    unique_domains: prev.unique_domains,
                    parsed_skipped: prev.parsed_skipped,
                    parsed_skipped_samples: prev.parsed_skipped_samples.clone(),
                    parsed_truncated: prev.parsed_truncated,
                },
                prev_status: Some(prev.clone()),
                message: "list fresh, skipping HTTP and reusing cache",
                age_secs: Some((now - cached.fetched_at).whole_seconds()),
                // Same rule as the cache-hit arm below (`matches!(mode,
                // Network)`), reached by a different route. Spelled out
                // rather than inherited, as the field doc requires.
                verified_fresh: matches!(mode, RefreshMode::Network),
            });
        }

        // `spilled == 0` would make the caller log "no domains loaded" and
        // keep the current map — right outcome, wrong reason, and it would
        // read as a broken cycle in the journal.
        if spilled == 0 {
            return None;
        }

        let digest: [u8; 32] = <sha2::Sha256 as sha2::Digest>::finalize(digest_ctx.clone()).into();
        (digest == installed).then_some(ProbeOutcome {
            digest_ctx,
            spilled,
            pending,
        })
    }

    /// S50 T5.5: wire the `imported.local` loader-bridge.
    ///
    /// `source_trust` is the typed [`SourceTrustMap`] facade built by
    /// [`merge_sources_with_blocklists`]; lookups happen by fetch URL
    /// at line `download_list` via [`SourceTrustMap::trust_for_url`].
    /// `config_dir` is the directory containing `config.toml`; the
    /// bridge resolves `https://imported.local/<id>.<ext>` to
    /// `<config_dir>/lists/<id>.<ext>` on disk for sources whose
    /// trust is [`BlocklistTrust::Local`].
    ///
    /// Without this call the manager falls back to the HTTP path for
    /// every URL — `imported.local` then fails fast at the URL-guard
    /// (`DisallowedHost`) which surfaces the misconfiguration in
    /// `tracing::warn!` rather than silently dropping the source.
    ///
    /// Matches the existing `set_*` `&mut self` convention used by
    /// `set_status_persistence_path`, `set_notification_channel`, etc.
    /// so call sites can chain it after construction without the
    /// builder-by-value awkwardness.
    pub fn set_local_bridge(&mut self, source_trust: SourceTrustMap, config_dir: PathBuf) {
        self.source_trust = source_trust;
        self.local_bridge_dir = Some(config_dir);
    }

    /// Get a shared handle to the per-source [`ListStatusRegistry`].
    ///
    /// Callers (typically `cli::commands::start`) clone this `Arc` into
    /// `DaemonState` so the IPC layer can answer
    /// `IpcCommand::BlocklistStats` reads without touching the manager.
    pub fn status_registry(&self) -> Arc<ListStatusRegistry> {
        self.status_registry.clone()
    }

    /// Wire up persistence for the registry's `prev_entries` field.
    ///
    /// Loads existing values from `path` immediately (silent no-op if
    /// the file does not exist or is malformed — boot must always
    /// succeed). After this call, every successful `refresh()` writes
    /// the registry back to `path` atomically.
    pub fn set_status_persistence_path(&mut self, path: PathBuf) {
        self.status_registry
            .load_persisted(&path, self.max_entries as u64);
        self.status_persistence_path = Some(path);
    }

    /// rev-2606 §06 `manager-01`: wire the retention-guard config from
    /// `settings.lists`. Matches the existing `set_*` `&mut self`
    /// convention. `max_drop_pct` is validated to 1..=100 at config-load
    /// time (`check_lists`); the manager does not re-validate but a
    /// caller-supplied `0` would simply make every shrink trip.
    /// Install the per-profile list policy this manager publishes with.
    ///
    /// Built by [`SourceBitMap::project_policy`] from the same `SourceBitMap`
    /// the manager holds, so ids became bits exactly once and against this
    /// generation's assignment — `_docs/features/profile_list_policy.md`
    /// §2.4. Opt-in so no existing construction site silently changes
    /// direction semantics.
    pub fn set_list_policy(&mut self, masks: PolicyMasks) {
        self.policy_masks = masks;
    }

    /// Swap the HTTP client used for downloads.
    ///
    /// Exists for exactly one transition: the manager is constructed with
    /// the *tight* client so the caller's **inline** `refresh().await` —
    /// boot (`start.rs`, before the DNS listener binds) and reload (inside
    /// the signal loop's `select!`, whose sibling arm is SIGTERM) — cannot
    /// be held open by a slow source. Once that inline refresh has
    /// returned, the caller swaps in the bulk client
    /// (`http_client::build_bulk_list_client`) so the **background** loop,
    /// which blocks nothing, is free to take the minutes a 180 MB list
    /// legitimately needs on a slow link.
    ///
    /// The distinction is blocking-ness, not importance: an inline refresh
    /// costs DNS availability or shutdown latency while it runs, so it
    /// falls back to the on-disk cache instead of waiting. The background
    /// loop pays nothing for waiting, so it waits.
    ///
    /// Call it BEFORE [`Self::spawn_refresh_loop`]; afterwards the manager
    /// has moved into the spawned task and is unreachable.
    pub fn set_download_client(&mut self, client: reqwest::Client) {
        self.client = client;
    }

    /// Hand the manager the shared readiness gate.
    ///
    /// The manager only ever **opens** it. Seeding is `start.rs`'s job
    /// (it is the only place that knows whether any list is configured)
    /// and nothing closes it — see [`Self::refresh_with_mode`]. Keeping
    /// those three responsibilities in three places is what makes
    /// "never closes" checkable by reading one function; taking a
    /// [`ReadinessGate`] rather than a bare `Arc<AtomicBool>` is what
    /// makes it enforced by the compiler rather than merely documented.
    pub fn set_filter_ready_gate(&mut self, gate: ReadinessGate) {
        self.filter_ready = Some(gate);
    }

    pub fn set_shrink_guard(&mut self, enabled: bool, max_drop_pct: u8) {
        self.shrink_guard_enabled = enabled;
        self.shrink_guard_max_drop_pct = max_drop_pct;
    }

    /// Wire the global corpus ceiling from `settings.lists`, in
    /// **deduplicated** domains.
    ///
    /// `0` disables the guard, and disables its cost with it: the counting
    /// pass is a second full read of the spill, so a disabled guard must
    /// not pay for a verdict nobody asked for.
    ///
    /// The ceiling is the operator's memory budget for their box, not a
    /// constant measured on ours.
    ///
    /// **Corrected 2026-08-17 (lane-C).** This comment used to assert
    /// "today's hash representation has a doubling step at 16 shards ×
    /// 1,048,576 buckets × 7/8 = 14,680,064 entries" — true when written,
    /// and stale from the moment `mem-t6` (2026-08-16) landed: each shard
    /// is now a [`crate::filter::engine::SortedShard`], an exact-size
    /// sorted slice built by `build_shard` from a plain sorted `Vec`,
    /// not a `HashMap`. There is no bucket table, no 7/8 load factor,
    /// and no doubling step at 14,680,064 any more — see
    /// `crate::filter::engine`'s module doc for the representation and
    /// `src/config/settings.rs`'s `default_max_total_domains` doc, which
    /// already carried this correction. This function's own doc did not,
    /// so it kept citing a cliff the representation it describes no
    /// longer has — exactly the kind of stale-but-confident number this
    /// project has been burned by before (see project rules's Hot-Path
    /// Locking section on divided-by-two-windows rates). 14,000,000
    /// remains the shipped default as a plain memory budget, not as
    /// cliff-avoidance; it must never be compared against here.
    pub fn set_max_total_domains(&mut self, max: usize) {
        self.max_total_domains = (max > 0).then_some(max);
    }

    /// rev-2606 §06 `manager-01`: load persisted retention-guard baselines
    /// WITHOUT wiring the save-back path. Used by the `warden lists refresh`
    /// foreground refresh so its single guarded cycle compares against the
    /// daemon's baselines, while the short-lived CLI process never writes
    /// `list_stats.json` (which could otherwise leave a root-owned file the
    /// daemon user cannot later replace). Contrast
    /// [`Self::set_status_persistence_path`], which both loads AND arms the
    /// save-back used by the long-running daemon.
    pub fn load_status_baselines(&self, path: &Path) {
        self.status_registry
            .load_persisted(path, self.max_entries as u64);
    }

    /// rev-2606 §06 `manager-01`: like [`Self::record_blocklist_failure`]
    /// but also stamps `cache_path` because the caller (the retention
    /// guard) has just re-parsed the prior cache successfully, so a
    /// real cache file is confirmed present. This closes a guard-widened
    /// fail-open: with a lost/empty `list_state.toml`, repeated guard
    /// trips would otherwise reach the failure threshold with
    /// `cache_path = None`, and a `Failed` entry without a cache pointer
    /// drops out of every profile (D9, `list_applies`) even though a
    /// healthy cache is sitting on disk. Stamping the path first makes the
    /// D9 stale-cache fallback keep the list applying.
    pub fn record_blocklist_failure_with_cache(
        &self,
        blocklist_id: &crate::config::schema::Id,
        max_consecutive_failures: u32,
        cache_path: PathBuf,
    ) -> bool {
        let now = time::OffsetDateTime::now_utc();
        let mut state = self.list_state.lock().unwrap_or_else(|e| e.into_inner());
        let entry = state.lists.entry(blocklist_id.clone()).or_default();
        // Stamp BEFORE the transition so a threshold flip to Failed carries
        // a valid D9 pointer even on a cold start with no prior success.
        entry.cache_path = Some(cache_path);
        let flipped = entry.record_failure(now, max_consecutive_failures);
        if let Some(path) = self.list_state_path.as_ref() {
            if let Err(e) = state.write_atomic(path) {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "failed to persist list_state.toml after retention-guard trip"
                );
            }
        }
        flipped
    }

    /// Replace the internal status registry with a caller-owned handle.
    ///
    /// Used by the reload path so the IPC layer's existing
    /// `Arc<ListStatusRegistry>` (held by `DaemonState`) keeps receiving
    /// updates after a config reload that recreates the manager. The
    /// reload-time manager sees the same registry the boot-time manager
    /// did, and atomic swaps land in the same slots.
    ///
    /// Sources whose entries do NOT appear in the registry's slot map
    /// (i.e. sources added by the reload that the boot did not know
    /// about) are silently ignored on update — see
    /// `ListStatusRegistry::update`. T1 accepts this: changing the
    /// `[lists].sources` set requires a daemon restart for the new
    /// sources to surface in IPC stats. Tracked as a §14.1 pitfall and
    /// resolved by T2's `IpcNotification::ListStatsUpdated` push model.
    pub fn attach_status_registry(&mut self, reg: Arc<ListStatusRegistry>) {
        self.status_registry = reg;
    }

    /// Wire a broadcast sender for [`IpcNotification`] events.
    ///
    /// Once attached, every `refresh()` cycle publishes one
    /// [`IpcNotification::ListStatsUpdated`] per source after its
    /// status slot is updated (success OR failure path). Send errors
    /// (no live subscribers) are silently ignored — the channel is
    /// fire-and-forget by design.
    ///
    /// Sprint 43 T2 introduces this. The subscriber endpoint that
    /// fans events back to TUI / CLI consumers lands in T3; until
    /// then no subscribers exist and the broadcast is a no-op
    /// (cheap — Tokio's broadcast send returns `Err(SendError)`
    /// immediately when receiver count is zero, which we drop).
    pub fn set_notification_channel(
        &mut self,
        tx: tokio::sync::broadcast::Sender<IpcNotification>,
    ) {
        self.notification_tx = Some(tx);
    }

    /// §4.7 Phase 2 T1: wire the receiver end of the out-of-band command
    /// channel. The matching `Sender<ListManagerCommand>` lives in
    /// `DaemonState::list_cmd_tx`, so `handle_forget_list` can reach the
    /// refresh loop without owning the manager.
    ///
    /// Idempotent — calling twice replaces the prior receiver. Must be
    /// called before [`Self::spawn_refresh_loop`]; once the manager has
    /// moved into the spawn task the receiver is owned by it.
    pub fn set_command_channel(&mut self, rx: mpsc::Receiver<ListManagerCommand>) {
        self.cmd_rx = Some(rx);
    }

    /// §4.7 Phase 2 T1: drop the in-memory cache entry for `source`
    /// and unlink its `<stem>.cache` + `<stem>.meta` sidecars from
    /// the on-disk cache directory.
    ///
    /// Idempotent. Best-effort on disk: `ErrorKind::NotFound` is
    /// silently absorbed (the file was already gone — desired
    /// outcome); any other unlink error is logged at `warn!` but
    /// does not affect the return value.
    ///
    /// Returns `true` when the source had any state — either an
    /// in-memory cache entry (keyed by either the source string or
    /// the catalog-resolved URL, since callers may pass slug or URL)
    /// or at least one disk sidecar that was successfully removed.
    ///
    /// Not on the DNS hot path — invoked from the refresh task only
    /// after a `ListManagerCommand::Forget` arrives over the mpsc
    /// channel, so the `&mut self` borrow does not race the filter
    /// engine's `ArcSwap` blocklist map.
    pub fn forget_source(&mut self, source: &str) -> bool {
        let url = self.catalog.resolve(source);
        let dropped_by_source = self.cache.remove(source).is_some();
        let dropped_by_url = url
            .as_deref()
            .map(|u| self.cache.remove(u).is_some())
            .unwrap_or(false);
        let was_in_memory = dropped_by_source || dropped_by_url;

        let mut disk_had_files = false;
        if let Some(cache_dir) = self.cache_dir.clone() {
            let stem = source_to_cache_stem(source);
            let cache_path = cache_dir.join(format!("{stem}.cache"));
            let meta_path = cache_dir.join(format!("{stem}.meta"));
            for path in [&cache_path, &meta_path] {
                match std::fs::remove_file(path) {
                    Ok(()) => {
                        disk_had_files = true;
                        // rev-2606 §06 carryover-2: the source string is
                        // operator-supplied over IPC; Debug-format it so a
                        // newline / ANSI escape can't spoof or corrupt the
                        // log line.
                        tracing::info!(
                            source = ?source,
                            path = %path.display(),
                            "list cache file forgotten"
                        );
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => tracing::warn!(
                        source = ?source,
                        path = %path.display(),
                        error = %e,
                        "failed to unlink list cache file during forget"
                    ),
                }
            }
        }

        // rev-2606 §06 manager-01: forget is the operator's recovery verb
        // for a list the retention guard refused. Reset the status
        // baseline (so the next fetch is treated as a first fetch and
        // accepted) and persist immediately — otherwise a restart between
        // forget and the next refresh would re-seed the stale baseline from
        // disk and the guard would re-trip ("forget didn't work"). Reset
        // both the source string and the resolved URL key, but only slots
        // that already exist (no phantom rows for a typo'd source).
        let mut reset_any = self.status_registry.reset_baseline(source);
        if let Some(u) = url.as_deref() {
            reset_any |= self.status_registry.reset_baseline(u);
        }
        if reset_any {
            if let Some(path) = self.status_persistence_path.as_ref() {
                if let Err(e) = self.status_registry.save(path) {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "failed to persist list_stats.json after forget"
                    );
                }
            }
        }

        was_in_memory || disk_had_files
    }

    /// Download all configured lists, merge into bitmask-tagged map, and swap.
    ///
    /// Each source is downloaded (or served from cache on 304/error). Domains
    /// are parsed into a `HashMap<CompactString, u64>` where the u64 is the
    /// OR of all lists that contain that domain. This deduplicates automatically
    /// while preserving per-list membership information.
    ///
    /// **Memory strategy**: body strings are never kept in the in-memory cache.
    /// Fresh downloads are parsed, persisted to disk, then the `String` drops.
    /// On 304 / download error, the body is read from the on-disk `.cache`
    /// file, parsed, then dropped. At most one body string exists at a time.
    ///
    /// **Sprint C T2/T3 of `lists_categories_v2` (§14.2.b/d wire-in).**
    /// Each refresh cycle that hits the HTTP path (or the cache-fresh
    /// shortcut) drives the retry state machine via
    /// [`Self::record_blocklist_success`] / [`Self::record_blocklist_failure`]
    /// — see `source_to_blocklist` for the canonical-id mapping. A
    /// `Failed → Active` transition (D8 recovery on the first
    /// successful refresh after the threshold flipped) becomes
    /// effective on the resolver only at the **next** explicit
    /// `warden reload` or the next 12-hour refresh tick. Sprint C
    /// design doc §14.2.d closed this as `doc-only` — the resolver
    /// rebuild lag matches the refresh cadence operators already
    /// expect for list health, and a per-transition rebuild would
    /// add lock contention without changing observable behaviour
    /// during the 12 h window.
    ///
    /// Returns the total number of unique domains in the merged map.
    /// Measure this cycle's **deduplicated** corpus and decide whether it
    /// may be installed.
    ///
    /// Must be called after `spill.flush()` and before pass 2 touches
    /// anything. Pass 2 builds *and installs* one shard at a time, so once
    /// it starts there is no longer a previous generation to keep.
    ///
    /// The per-list `max_entries` cap cannot stand in for this: it bounds
    /// one source, so eight sources at 10 M each is 80 M on paper. Only
    /// overlap between the lists holds the live corpus near 12.3 M, and
    /// overlap is a property of the lists, not a guarantee the daemon
    /// enforces.
    ///
    /// `serving` is the domain count already installed in the engine, and
    /// it is the whole boot-versus-reload discriminator — see
    /// [`CorpusVerdict::InstallOverCeiling`]. Passed in rather than read
    /// off `self.filter` so the decision is a function of its inputs, the
    /// same way [`compute_shrink_verdict`] takes its baseline explicitly.
    /// The one production caller passes `self.filter.domain_count()`.
    fn corpus_guard(&self, spill: &ShardSpill, serving: usize) -> CorpusVerdict {
        let Some(ceiling) = self.max_total_domains else {
            return CorpusVerdict::Unmeasured;
        };

        let mut novel_by_bit = [0u64; 64];
        let mut per_shard = Vec::with_capacity(DOMAIN_SHARDS);
        for idx in 0..DOMAIN_SHARDS {
            match spill.count_unique(idx, &mut novel_by_bit) {
                Ok(n) => per_shard.push(n as usize),
                Err(e) => {
                    // `build_shard` is about to read the same spill and
                    // will fail on it too, which marks the cycle degraded
                    // and keeps that shard's previous generation. Carrying
                    // on unmeasured is the lesser evil: this guard is
                    // resource management, not stability, so it must not
                    // turn an I/O blip into a refused corpus.
                    tracing::error!(
                        shard = idx,
                        error = %e,
                        "cannot count shard spill; installing this cycle without the global corpus guard"
                    );
                    return CorpusVerdict::Unmeasured;
                }
            }
        }

        let unique: u64 = per_shard.iter().map(|&n| n as u64).sum();
        if unique > ceiling as u64 {
            // Refusing keeps the previous generation — which only exists
            // if one is serving. At a cold start `serving` is 0: the
            // engine was built empty and the disk cache restores ETag
            // sidecars, never bodies. Refusing there does not "keep" the
            // old corpus, it installs nothing, and the daemon comes up
            // answering every query unfiltered. That is not the ceiling
            // doing its job, it is the whole filtering policy failing
            // open on a restart.
            //
            // So the ceiling stops being a wall and becomes a budget
            // exactly when there is nothing behind it to protect, up to
            // the hard cap below.
            if serving == 0 && u128::from(unique) <= cold_start_hard_cap(ceiling) {
                return CorpusVerdict::InstallOverCeiling {
                    unique,
                    ceiling,
                    per_shard,
                };
            }
            return CorpusVerdict::Refuse {
                unique,
                ceiling,
                novel_by_bit: Box::new(novel_by_bit),
            };
        }
        // 90 % of the operator's own value, as a cross-multiplication so
        // that no configured ceiling can overflow the arithmetic and no
        // small one is distorted by integer division.
        let warn = u128::from(unique) * 10 >= (ceiling as u128) * 9;
        CorpusVerdict::Install {
            unique,
            per_shard,
            warn,
        }
    }

    /// Run a network refresh cycle. Retained as the name every existing
    /// caller uses; see [`Self::refresh_with_mode`] for the boot path.
    pub async fn refresh(&mut self) -> usize {
        self.refresh_at(OffsetDateTime::now_utc()).await
    }

    /// Run one refresh cycle under the given [`RefreshMode`], anchored now.
    ///
    /// The boot path's entry point — see [`Self::refresh_at_with_mode`] for
    /// what the two parameters mean and why they are one function.
    pub async fn refresh_with_mode(&mut self, mode: RefreshMode) -> usize {
        self.refresh_at_with_mode(OffsetDateTime::now_utc(), mode)
            .await
    }

    /// [`Self::refresh`] with the cycle anchor supplied by the caller.
    ///
    /// Network mode — the anchor is orthogonal to the mode, and every
    /// existing caller of this wanted the network.
    pub(crate) async fn refresh_at(&mut self, now: OffsetDateTime) -> usize {
        self.refresh_at_with_mode(now, RefreshMode::Network).await
    }

    /// Run one refresh cycle: `mode` decides where domains may come from,
    /// `now` decides what "current" means while they arrive.
    ///
    /// The two arrived from different branches — `mode` from the boot path,
    /// `now` from the freshness work — and they are one function because
    /// they are independent axes of the same cycle, not competing ways to
    /// parameterise it. Keeping them apart would have meant a
    /// cache-only cycle that could not be anchored, which is precisely the
    /// combination the boot path needs.
    ///
    /// Every configured source is streamed into a [`ShardSpill`] in pass
    /// 1 (subject to the shrink guard and the corpus digest), then pass 2
    /// builds and installs the shard(s) subject to `corpus_guard`. Under
    /// [`RefreshMode::Network`] a source may reach `download_list`
    /// (conditional GET, the age-based freshness shortcut, 304 handling);
    /// under [`RefreshMode::CacheOnly`] `download_list` is never called —
    /// a source without a usable on-disk `.cache` contributes nothing
    /// this cycle instead of falling back to the network.
    ///
    /// `now` is the instant the cycle is reckoned from: it decides
    /// freshness (`is_cache_fresh`), it is stamped into `fetched_at` for
    /// every source this cycle validates, and it timestamps the status
    /// registry. One anchor for the whole cycle, taken once — a cycle that
    /// re-read the clock per source would give each source a different
    /// idea of when "now" was, which is the drift `mem2608-t0` exists to
    /// remove. Supplying it lets a test drive the production relationship
    /// the scheduler actually has — *a cycle that began `d` seconds ago is
    /// completing now* — without waiting `d` seconds.
    ///
    /// Returns `self.filter.domain_count()` once the cycle settles: the
    /// domains the engine actually serves, whether this cycle installed a
    /// fresh generation, skipped an unchanged rebuild, or refused/kept
    /// the previous one.
    ///
    /// See `_docs/features/boot_list_persistence.md` §2.2.
    pub(crate) async fn refresh_at_with_mode(
        &mut self,
        now: OffsetDateTime,
        mode: RefreshMode,
    ) -> usize {
        // Cycle entry: a spill partition is only valid for the process
        // that wrote it, so anything still on disk is garbage regardless
        // of who left it there. Never resumed.
        if let Some(dir) = self.cache_dir.as_deref() {
            purge_shard_spill(dir);
        }
        let estimated = self.filter.domain_count().max(100_000);
        let mut spill = ShardSpill::open(self.cache_dir.as_deref());
        // Success-path status writes, applied after pass 2 supplies
        // `entries`.
        let mut pending: Vec<PendingStatus> = Vec::new();
        // Accepted spill records this cycle. Zero means no source
        // contributed anything, which is the shard-at-a-time equivalent of
        // the flat producer's `merged.is_empty()` gate.
        let mut spilled = 0u64;
        // §11 T5: digest of everything actually streamed this cycle, in
        // order. `digest_valid` drops to false the moment a source's
        // contribution is unknown (missing bit, no body, stream error) —
        // the digest then describes something other than the corpus and
        // must not be allowed to authorise skipping a rebuild.
        let mut digest_ctx = new_corpus_digest_ctx(&self.policy_masks);
        let mut digest_valid = true;

        let resolved: Vec<(String, String)> = self
            .sources
            .iter()
            .filter_map(|source| {
                let url = self.catalog.resolve(source);
                if url.is_none() {
                    tracing::warn!(source = source.as_str(), "unknown list ID, skipping");
                }
                url.map(|u| (source.clone(), u))
            })
            .collect();

        let interval = self.refresh_interval;

        // ── mem2608-s1 T3: settle an unchanged corpus without parsing it ──
        //
        // Measured on the lab host 2026-08-16: a cycle where every source
        // took the fresh-cache arm cost +220.3 MiB of VmHWM and 43 s of
        // CPU, issued zero HTTP requests, and installed nothing. All of it
        // was spent rebuilding a digest the daemon already held. The probe
        // rebuilds that digest from the bodies' bytes alone — no parse, no
        // spill, no dedup set, ~64 KB of buffer — and when it matches, the
        // loop below has nothing left to do.
        let probe = self.probe_unchanged_corpus(&resolved, now, interval, mode);
        let probed = probe.is_some();
        if let Some(outcome) = probe {
            digest_ctx = outcome.digest_ctx;
            spilled = outcome.spilled;
            pending = outcome.pending;
            #[cfg(test)]
            {
                self.probe_skips += 1;
            }
        }
        // Iterating nothing is how the probe skips the walk. Deliberately
        // not an `if/else` around the loop: this file is going to meet a
        // large rewrite of `refresh` on another branch, and a 500-line
        // re-indentation is exactly the diff that hides a lost hunk in a
        // merge. `resolved` itself stays intact — the corpus-refusal
        // reporting below still reads it.
        let sources_to_walk: &[(String, String)] = if probed { &[] } else { &resolved };

        for (source, url) in sources_to_walk {
            let bit = match self.source_bits.bit_for_url(source.as_str()) {
                Some(b) => b,
                None => {
                    tracing::error!(
                        source = source.as_str(),
                        "source missing from bit map, skipping"
                    );
                    digest_valid = false;
                    continue;
                }
            };
            let bit_mask = 1u64 << bit;

            let max_entries = self.max_entries;

            // Snapshot the previous status BEFORE the refresh — used to
            // compute `delta_pct_vs_prev` and to carry-forward "last
            // good" entries on a failure cycle.
            let prev_status = self.status_registry.status_for_url(source);

            // Sprint C T2 of `lists_categories_v2` (§14.2.b): the
            // refresh loop keys on the source string, but the retry
            // state machine keys on canonical `Id`. Look the meta up
            // once per source per cycle so each match arm below can
            // drive `record_blocklist_*` without re-walking the map.
            // Sources without a `[[blocklists]]` row (legacy slash-
            // form pre-v1 catalog entries) skip the state machine —
            // it only tracks canonical-id blocklists.
            let blocklist_meta = self.source_to_blocklist.get(source.as_str()).cloned();
            // rev-2606 §06 parser-02: the operator-declared parse format for
            // this source, if its `[[blocklists]]` row declared hosts/adguard.
            // `None` (domains / omitted / legacy slash-form) defers to
            // content auto-detection inside `parse_list_into_map`.
            let declared_format = self.source_to_format.get(source.as_str()).copied();
            // Compute cache_path inline so the immutable borrow on
            // `self.cache_dir` releases before `self.download_list`
            // takes `&mut self`.
            let cache_path_for_record: std::path::PathBuf = self
                .cache_dir
                .as_ref()
                .map(|dir| dir.join(format!("{}.cache", source_to_cache_stem(source))))
                .unwrap_or_default();

            // Phase 1.2 freshness check: if we have a cached entry and
            // its fetched_at is younger than the refresh interval, skip
            // the HTTP request entirely. Read the body straight from
            // disk (or in-memory fallback if disk cache is disabled),
            // parse, merge, continue. This is the crash-loop
            // amplification fix: 100 restarts in 12 hours → 0 upstream
            // fetches when bodies are still fresh on disk.
            if let Some(cached) = self.cache.get(url.as_str()) {
                // CacheOnly ignores age entirely (§2.3). `Network` keeps
                // the Phase 1.2 behaviour: skip HTTP only while the body
                // is younger than the refresh interval.
                let use_cache = matches!(mode, RefreshMode::CacheOnly)
                    || is_cache_fresh(cached.fetched_at, now, interval);
                if use_cache {
                    if let Some(reader) = self.resolve_body_reader(url, source) {
                        match parse_source_into_spill_counted(
                            reader,
                            bit_mask,
                            &mut spill,
                            max_entries,
                            source,
                            declared_format,
                            // The body on disk is the one the last cycle
                            // counted; counting it again costs ~144 MiB to
                            // reproduce the same number (`mem2608-s1` T2).
                            UniqueCount::carry_or_measure(prev_status.as_deref()),
                        ) {
                            Ok((counts, body_hash)) => {
                                spilled += counts.parsed_ok;
                                fold_corpus_digest(
                                    &mut digest_ctx,
                                    source,
                                    bit_mask,
                                    max_entries,
                                    declared_format,
                                    &body_hash,
                                );
                                // Reaching this arm under `Network` means
                                // `is_cache_fresh` held (see `use_cache`
                                // above) — a genuine, interval-bounded
                                // confirmation. Under `CacheOnly` the
                                // same arm runs for a body of any age
                                // (§2.3), so it is not verified-fresh.
                                //
                                // Computed once and reused below (both for
                                // `PendingStatus` and for gating
                                // `record_blocklist_success`) rather than
                                // re-derived from the ambient `mode` at
                                // each site: two independent
                                // `matches!(mode, ...)` spellings of the
                                // same fact are how a future push site
                                // changes one and silently leaves the
                                // other on the old default. See the field
                                // doc on `PendingStatus::verified_fresh`.
                                let verified_fresh = matches!(mode, RefreshMode::Network);
                                pending.push(PendingStatus {
                                    source: source.clone(),
                                    bit,
                                    counts,
                                    prev_status: prev_status.clone(),
                                    message: cache_hit_message(mode),
                                    age_secs: Some((now - cached.fetched_at).whole_seconds()),
                                    verified_fresh,
                                });
                                // Sprint C T2 / D9: a cache that outlived a
                                // failure recovers the list from `Failed`.
                                // That reasoning holds only under `Network`,
                                // where the arm above required the body to
                                // be younger than `refresh_interval` — a
                                // genuine confirmation the list is healthy.
                                // Under `CacheOnly` the body can be
                                // arbitrarily old (§2.3), so recording this
                                // as a success would let a permanently dead
                                // upstream disarm `max_consecutive_failures`
                                // forever on a box that restarts more often
                                // than a refresh cycle — the same class of
                                // harm `_docs/features/boot_list_persistence.md`
                                // §2.8 prohibits for `fetched_at`, arriving
                                // through the state machine instead.
                                if verified_fresh {
                                    if let Some((id, _)) = &blocklist_meta {
                                        self.record_blocklist_success(
                                            id,
                                            cache_path_for_record.clone(),
                                        );
                                    }
                                }
                                continue;
                            }
                            Err(e) => {
                                // Partial ingest already rolled back. Treat
                                // a broken cache read exactly like a failed
                                // refresh rather than silently shipping a
                                // truncated list. Under `Network` this
                                // falls through to `download_list` below;
                                // under `CacheOnly` the explicit stop a few
                                // lines down takes it instead — say which
                                // one actually happens rather than always
                                // claiming HTTP.
                                tracing::warn!(
                                    source = source.as_str(),
                                    error = %e,
                                    "{}",
                                    match mode {
                                        RefreshMode::CacheOnly =>
                                            "failed to stream fresh cache body; source contributes nothing this cycle",
                                        RefreshMode::Network =>
                                            "failed to stream fresh cache body, falling back to HTTP",
                                    }
                                );
                            }
                        }
                    }
                    // Fresh-by-timestamp but no body on disk. Under
                    // `Network` this falls through to the HTTP path so we
                    // recover; under `CacheOnly` the explicit stop a few
                    // lines down takes it instead — say which one actually
                    // happens rather than always claiming HTTP.
                    tracing::warn!(
                        source = source.as_str(),
                        "{}",
                        match mode {
                            RefreshMode::CacheOnly =>
                                "cache marked fresh but body missing; source contributes nothing this cycle",
                            RefreshMode::Network =>
                                "cache marked fresh but body missing, falling back to HTTP",
                        }
                    );
                }
            }

            // CacheOnly stops here. Reaching `download_list` below would
            // undo the entire point of the mode, so the exit is explicit
            // rather than implied by the arms above — a source with no
            // `.cache` file, or one whose body failed to stream, must
            // contribute nothing this cycle instead of quietly falling
            // back to the network the listener is waiting on.
            //
            // `digest_valid` is deliberately left untouched here. An
            // earlier version of this comment set it `false`, reasoning
            // that this source's contribution is "unknown" — the same
            // justification the genuine-attempt failure arms use. That
            // was wrong: every path that falls through to this point (no
            // cache entry, no resolvable body, or a resolved reader whose
            // parse failed) never calls `fold_corpus_digest`, and the one
            // arm that does write to `spill` before failing (a resolved
            // reader whose parse errors) has that write rolled back
            // before falling through — so nothing here adds to `spill`
            // either, provided the rollback itself succeeds (a rollback
            // failure is a separate gap in `parse_source_into_spill`, not
            // this arm's to fix). The
            // contribution is *known* to be zero, not unknown. Unlike the
            // `Network`-mode download-failure arms, there is no
            // outstanding network attempt a retry could resolve
            // differently — this is just what is on disk right now.
            //
            // The comparison that matters is not two `CacheOnly` cycles —
            // this mode runs once per process, so there is no second
            // cycle to compare against — but boot-`CacheOnly`'s digest
            // against the first `Network` cycle that follows it. Every
            // source in that transition resolves to one of: a
            // still-fresh cache re-folding the same body hash (same
            // contribution); a 304 re-parsing the retained body (same
            // contribution); a 200 whose body is unchanged (same hash) or
            // has changed (different hash, forcing a rebuild); a download
            // failure that still has a cache, re-folding the same
            // retained body boot already folded (same contribution); a
            // download failure with no cache, which invalidates the
            // digest itself; or — this arm's case — a source with no
            // cache at boot, which contributed nothing to the boot
            // digest, now downloading and folding for the first time,
            // changing the digest and forcing a rebuild. Every branch
            // either reproduces the boot digest from byte-identical
            // inputs or invalidates it, so authorising the skip here is
            // correct, not merely harmless.
            if matches!(mode, RefreshMode::CacheOnly) {
                tracing::warn!(
                    source = source.as_str(),
                    "no usable disk cache at boot; source contributes nothing this cycle"
                );
                continue;
            }

            // rev-2606 §06 manager-01: snapshot the in-memory cache
            // entry's conditional-request state BEFORE download_list
            // mutates it (a 200 stamps the response's etag/last-modified +
            // fetched_at=now). On a guard trip we restore this so the
            // retained on-disk body keeps its matching conditional headers
            // and the poisoned cycle is not mistaken for a fresh refresh.
            let pre_download: Option<(Option<String>, Option<String>, OffsetDateTime)> = self
                .cache
                .get(url.as_str())
                .map(|c| (c.etag.clone(), c.last_modified.clone(), c.fetched_at));

            match self.download_list(source, url, now).await {
                Ok(FetchResult::Fresh(body)) => {
                    // rev-2606 §06 manager-01: partition this body into the
                    // spill first so we can MEASURE this refresh before
                    // deciding whether to trust it. The body is already
                    // resident (the download produced it), so streaming
                    // over a borrowed `Cursor` adds no copy — and a guard
                    // trip below still rolls nothing back, matching the
                    // pre-existing behaviour where a refused body's domains
                    // stay in this cycle's map.
                    let counts = match parse_source_into_spill_counted(
                        std::io::Cursor::new(body.as_bytes()),
                        bit_mask,
                        &mut spill,
                        max_entries,
                        source,
                        declared_format,
                        // The one arm whose count is actually consulted:
                        // `shrink_verdict` below trips on it. Measured,
                        // never carried — but sized from the prior count so
                        // the set does not pay a final rehash.
                        UniqueCount::measure(prev_status.as_deref()),
                    ) {
                        Ok((c, body_hash)) => {
                            fold_corpus_digest(
                                &mut digest_ctx,
                                source,
                                bit_mask,
                                max_entries,
                                declared_format,
                                &body_hash,
                            );
                            c
                        }
                        Err(e) => {
                            // REACHABLE since the cap became fail-closed:
                            // `parse_source_into_spill` returns Err when a
                            // source exceeds `max_entries`, rolling its
                            // spill back so the prior generation stands.
                            // (The older reading — "unreachable, `body` is
                            // a String so the cursor cannot fail" — still
                            // holds for the I/O case, which is why this was
                            // handled rather than unwrapped.)
                            //
                            // The message stays generic because `e` carries
                            // the specific reason, and that reason is what
                            // lands in the operator-visible `Failed` status
                            // below. Do not re-word it as "parse error":
                            // the common case now is a refused cap, not
                            // malformed input.
                            tracing::error!(
                                source = source.as_str(),
                                error = %e,
                                "source refused this cycle; keeping the previous generation"
                            );
                            let status = ListStatus::from_failure(
                                prev_status.as_deref(),
                                e.to_string(),
                                now,
                            );
                            self.status_registry.update_for_url(source, status);
                            publish_list_stats_updated(&self.notification_tx, source);
                            digest_valid = false;
                            continue;
                        }
                    };
                    spilled += counts.parsed_ok;
                    let fresh_unique = counts.unique_domains;

                    match self.shrink_verdict(prev_status.as_deref(), fresh_unique) {
                        ShrinkVerdict::Refuse {
                            drop_pct,
                            got,
                            kept,
                        } => {
                            // Retention guard tripped. Keep the prior cache
                            // on disk, mark the source Failed with a visible
                            // reason, and re-parse the prior good body so
                            // this source keeps blocking this cycle.
                            let reason = format_blocklist_shrink_refused(drop_pct, got, kept);
                            tracing::warn!(
                                target: "audit",
                                source = source.as_str(),
                                bit,
                                got,
                                kept,
                                drop_pct,
                                threshold_pct = self.shrink_guard_max_drop_pct,
                                "{}",
                                reason
                            );
                            // Restore-or-remove the in-memory cache entry so
                            // the conditional headers keep validating the
                            // RETAINED disk body and the freshness shortcut
                            // does not treat this poisoned cycle as fresh.
                            match pre_download {
                                Some((etag, last_modified, fetched_at)) => {
                                    let entry = self.cache.entry(url.clone()).or_default();
                                    entry.etag = etag;
                                    entry.last_modified = last_modified;
                                    entry.fetched_at = fetched_at;
                                    entry.body = None;
                                }
                                None => {
                                    self.cache.remove(url.as_str());
                                }
                            }
                            // Re-parse the prior good body (mirrors the Err
                            // arm's stale-cache fallback). Track whether a
                            // cache is confirmed present for the D9 stamp.
                            let cache_present = if let Some(reader) =
                                self.resolve_body_reader(url, source)
                            {
                                match parse_source_into_spill_counted(
                                    reader,
                                    bit_mask,
                                    &mut spill,
                                    max_entries,
                                    source,
                                    declared_format,
                                    // The retained prior body — by
                                    // definition the one the prior count
                                    // describes, and nothing here reads it.
                                    UniqueCount::carry_or_measure(prev_status.as_deref()),
                                ) {
                                    Ok((c, body_hash)) => {
                                        spilled += c.parsed_ok;
                                        // The retained body is spilled too,
                                        // so it is part of what this cycle
                                        // built and folds in after the
                                        // refused one.
                                        fold_corpus_digest(
                                            &mut digest_ctx,
                                            source,
                                            bit_mask,
                                            max_entries,
                                            declared_format,
                                            &body_hash,
                                        );
                                        true
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            source = source.as_str(),
                                            error = %e,
                                            "failed to stream retained cache body after guard trip"
                                        );
                                        digest_valid = false;
                                        false
                                    }
                                }
                            } else {
                                digest_valid = false;
                                false
                            };
                            let status =
                                ListStatus::from_failure(prev_status.as_deref(), reason, now);
                            self.status_registry.update_for_url(source, status);
                            publish_list_stats_updated(&self.notification_tx, source);
                            // Drive the state machine like any failed refresh.
                            // Stamp cache_path when the cache is confirmed
                            // present so a threshold flip to Failed still
                            // applies via D9 even from a lost-state cold
                            // start (guard-widened fail-open closed).
                            if let Some((id, max_consec)) = &blocklist_meta {
                                let flipped = if cache_present {
                                    self.record_blocklist_failure_with_cache(
                                        id,
                                        *max_consec,
                                        cache_path_for_record.clone(),
                                    )
                                } else {
                                    self.record_blocklist_failure(id, *max_consec)
                                };
                                if flipped {
                                    tracing::warn!(
                                        target: "audit",
                                        source = source.as_str(),
                                        blocklist_id = %id.as_str(),
                                        max_consecutive_failures = *max_consec,
                                        "blocklist transitioned to Failed (retention guard)"
                                    );
                                }
                            }
                            continue;
                        }
                        ShrinkVerdict::Accept { delta_warn } => {
                            pending.push(PendingStatus {
                                source: source.clone(),
                                bit,
                                counts,
                                prev_status: prev_status.clone(),
                                message: "list downloaded and parsed",
                                age_secs: None,
                                // Reachable only under `Network` (`CacheOnly`
                                // never calls `download_list`) — a genuine
                                // download completed this cycle.
                                verified_fresh: true,
                            });
                            // status-01 fold: loud-but-allowed supply-chain
                            // canary. Fires only on the actually-fetched
                            // path (not cache re-reads), so source reorder /
                            // shadowing churn never trips it.
                            if let Some(delta) = delta_warn {
                                tracing::warn!(
                                    target: "audit",
                                    source = source.as_str(),
                                    bit,
                                    delta_pct = delta,
                                    "{}",
                                    BLOCKLIST_DELTA_WARN
                                );
                            }
                        }
                    }

                    // Persist to disk; body String drops at end of this arm.
                    if let Some(ref dir) = self.cache_dir {
                        let entry = self.cache.get(url.as_str());
                        let fetched_at = entry
                            .map(|c| c.fetched_at)
                            .unwrap_or_else(OffsetDateTime::now_utc);
                        write_cache_to_disk(
                            dir,
                            source,
                            &body,
                            entry.and_then(|c| c.etag.as_deref()),
                            entry.and_then(|c| c.last_modified.as_deref()),
                            fetched_at,
                        );
                    } else {
                        // No disk cache — keep body in memory as fallback.
                        let entry = self.cache.entry(url.clone()).or_default();
                        entry.body = Some(body);
                        // Default already set fetched_at to now_utc(); explicit
                        // refresh in case the entry pre-existed from a previous
                        // download cycle. The cycle anchor, not the clock, for
                        // the same reason as `download_list` (`mem2608-t0`).
                        entry.fetched_at = now;
                    }
                    // Sprint C T2: drive the state machine — Active.
                    if let Some((id, _)) = &blocklist_meta {
                        self.record_blocklist_success(id, cache_path_for_record.clone());
                    }
                }
                Ok(FetchResult::NotModified) => {
                    if let Some(reader) = self.resolve_body_reader(url, source) {
                        match parse_source_into_spill_counted(
                            reader,
                            bit_mask,
                            &mut spill,
                            max_entries,
                            source,
                            declared_format,
                            // 304 is the server saying the bytes are the
                            // ones we already counted.
                            UniqueCount::carry_or_measure(prev_status.as_deref()),
                        ) {
                            Ok((counts, body_hash)) => {
                                spilled += counts.parsed_ok;
                                fold_corpus_digest(
                                    &mut digest_ctx,
                                    source,
                                    bit_mask,
                                    max_entries,
                                    declared_format,
                                    &body_hash,
                                );
                                pending.push(PendingStatus {
                                    source: source.clone(),
                                    bit,
                                    counts,
                                    prev_status: prev_status.clone(),
                                    message: "list not modified, using cache",
                                    age_secs: None,
                                    // Reachable only under `Network` — a 304
                                    // is a genuine, current confirmation
                                    // from the upstream.
                                    verified_fresh: true,
                                });
                            }
                            Err(e) => {
                                tracing::warn!(
                                    source = source.as_str(),
                                    error = %e,
                                    "failed to stream cache body on 304"
                                );
                                digest_valid = false;
                            }
                        }
                    } else {
                        digest_valid = false;
                    }
                    // Persist the bumped fetched_at to disk so a daemon
                    // restart sees the cache as still-fresh and skips
                    // the HTTP altogether next cycle. Only the .meta
                    // file is rewritten — the .cache body is unchanged
                    // by definition of HTTP 304. §4.7 Phase 2 T3:
                    // preserve the body size by stat'ing the existing
                    // .cache file (the body bytes did not change).
                    if let Some(ref dir) = self.cache_dir {
                        if let Some(entry) = self.cache.get(url.as_str()) {
                            let stem = source_to_cache_stem(source);
                            let cache_path = dir.join(format!("{stem}.cache"));
                            let meta_path = dir.join(format!("{stem}.meta"));
                            let body_size = std::fs::metadata(&cache_path)
                                .ok()
                                .and_then(|m| usize::try_from(m.len()).ok());
                            write_meta_file(
                                &meta_path,
                                source,
                                entry.etag.as_deref(),
                                entry.last_modified.as_deref(),
                                entry.fetched_at,
                                body_size,
                            );
                        }
                    }
                    // Sprint C T2: 304 Not Modified is a successful
                    // refresh from the state machine's POV — the cache
                    // we are validating against is still fresh.
                    if let Some((id, _)) = &blocklist_meta {
                        self.record_blocklist_success(id, cache_path_for_record.clone());
                    }
                }
                Err(e) => {
                    // Always record the failure in the registry — the
                    // operator wants to see the failed-attempt timestamp
                    // and reason. If a cached body is available we still
                    // parse it so the merged map keeps this source's
                    // domains, but `last_outcome` reflects the failed
                    // upstream — `entries` is carried forward from the
                    // previous successful cycle (handled by `from_failure`).
                    let reason = e.to_string();
                    if let Some(reader) = self.resolve_body_reader(url, source) {
                        match parse_source_into_spill_counted(
                            reader,
                            bit_mask,
                            &mut spill,
                            max_entries,
                            source,
                            declared_format,
                            // The download failed; this is the cached body
                            // from the cycle that produced the prior count.
                            UniqueCount::carry_or_measure(prev_status.as_deref()),
                        ) {
                            Ok((counts, body_hash)) => {
                                spilled += counts.parsed_ok;
                                fold_corpus_digest(
                                    &mut digest_ctx,
                                    source,
                                    bit_mask,
                                    max_entries,
                                    declared_format,
                                    &body_hash,
                                );
                            }
                            Err(stream_err) => {
                                tracing::warn!(
                                    source = source.as_str(),
                                    error = %stream_err,
                                    "failed to stream cache body after download failure"
                                );
                                digest_valid = false;
                            }
                        }
                        tracing::warn!(
                            source = source.as_str(),
                            error = %e,
                            "download failed, using cached version"
                        );
                    } else {
                        tracing::error!(
                            source = source.as_str(),
                            error = %e,
                            "download failed, no cache available"
                        );
                        digest_valid = false;
                    }
                    let status = ListStatus::from_failure(prev_status.as_deref(), reason, now);
                    self.status_registry.update_for_url(source, status);
                    publish_list_stats_updated(&self.notification_tx, source);
                    // Sprint C T2: drive the state machine — increment
                    // `consecutive_failures`, flip to Failed at the
                    // per-list `max_consecutive_failures` threshold.
                    if let Some((id, max_consec)) = &blocklist_meta {
                        let flipped = self.record_blocklist_failure(id, *max_consec);
                        if flipped {
                            tracing::warn!(
                                target: "audit",
                                source = source.as_str(),
                                blocklist_id = %id.as_str(),
                                max_consecutive_failures = *max_consec,
                                "blocklist transitioned to Failed after threshold reached"
                            );
                        }
                    }
                }
            }
        }

        // ── Pass 2: build and install one shard at a time ─────────────
        //
        // This is where the memory saving lands. Each iteration
        // materialises roughly a sixteenth of a generation, hands it to
        // the engine, and lets the displaced sixteenth drop — so a
        // complete new generation never coexists with the outgoing one.
        // `estimated` is captured before the first swap: `domain_count()`
        // is a sum taken across shards at different instants, and during
        // this loop it straddles two generations. Fine as a capacity hint,
        // not something to build an invariant on.
        let mut added_by_bit = [0u64; 64];
        let mut total = 0usize;
        let mut degraded = false;
        // Did a complete new generation actually reach the engine this cycle?
        // The T5 digest is stored only when this is true — see below.
        let mut installed = false;
        // Set when the global corpus guard refused this cycle. Carries the
        // measured union, the operator's ceiling, and the per-source novel
        // contributions that tell them which list to drop.
        let mut corpus_refused: Option<(u64, usize, Box<[u64; 64]>)> = None;

        // §11 T5: every source streamed to a byte-identical body, in the
        // same order, under the same parse settings — so pass 2 would
        // rebuild the map that is already installed. Skip it: no map
        // build, no swap, no cluster re-encode. This is most cycles.
        let corpus_digest: Option<[u8; 32]> =
            digest_valid.then(|| <sha2::Sha256 as sha2::Digest>::finalize(digest_ctx).into());
        let unchanged =
            spilled > 0 && corpus_digest.is_some() && corpus_digest == self.installed_corpus_digest;

        // The spill has to be flushed before *either* the counting pass or
        // pass 2 can read it back, so it is done once here rather than as
        // an arm of the chain below — the guard needs to sit between the
        // flush and the first `build_shard`, and an `if`-chain cannot bind
        // a value in one arm and match on it in the next.
        let rebuilding = !unchanged && spilled > 0;
        let flush_err = rebuilding.then(|| spill.flush().err()).flatten();
        // ── Global corpus guard ───────────────────────────────────────
        //
        // Measured here and nowhere later. Pass 2 builds *and installs*
        // one shard at a time, so once that loop starts the new generation
        // is already live and "keep the previous one" has stopped being an
        // option. It also sits above `per_shard`, so a refusal costs no
        // shard allocation at all.
        //
        // This used to carry a second reason: a clustering primary
        // allocated one full flat map from `estimated`, so a guard placed
        // below that test would have skipped exactly the nodes carrying the
        // largest corpora. Cluster sync S1 deleted that branch — every node
        // takes the sharded path now — so only the first reason remains.
        // It is sufficient on its own: the placement does not change.
        let corpus_verdict = if rebuilding && flush_err.is_none() {
            // What is installed right now, which at a cold start is 0 and
            // is the guard's boot-versus-reload discriminator.
            self.corpus_guard(&spill, self.filter.domain_count())
        } else {
            CorpusVerdict::Unmeasured
        };

        if unchanged {
            total = self.filter.domain_count();
            tracing::info!(
                total,
                "no list body changed since the installed generation, skipping rebuild"
            );
        } else if spilled == 0 {
            tracing::debug!("no domains loaded, keeping current domain map");
        } else if let Some(e) = flush_err {
            tracing::error!(error = %e, "failed to flush shard spill, keeping current domain map");
            // Nothing was installed; report what is still live.
            total = self.filter.domain_count();
        } else if let CorpusVerdict::Refuse {
            unique,
            ceiling,
            novel_by_bit,
        } = corpus_verdict
        {
            // ── Global corpus guard: refuse the cycle ─────────────────
            //
            // Nothing is built and nothing is swapped, so the previous
            // generation stays live in full. `installed` stays false, so
            // the digest is cleared below and the next cycle re-measures
            // rather than concluding nothing changed and skipping for
            // ever.
            corpus_refused = Some((unique, ceiling, novel_by_bit));
            // Report what is actually serving, not what this cycle
            // measured and threw away — same rule the `degraded` arm
            // follows, and `refresh()`'s return value is that number.
            total = self.filter.domain_count();
            if total == 0 {
                // Past the cold-start hard cap with nothing installed.
                // The reload wording below would be a lie here — there is
                // no previous generation, so this is not a conservative
                // hold, it is the daemon about to answer every query
                // unfiltered. Say that, and say what fixes it, because
                // `serving=0` sitting in a field nobody reads is how this
                // went unnoticed for a whole restart.
                tracing::error!(
                    target: "audit",
                    unique,
                    ceiling,
                    serving = total,
                    hard_cap = %cold_start_hard_cap(ceiling),
                    "refresh refused: merged corpus is past twice max_total_domains and NOTHING \
                     IS INSTALLED — no previous generation exists to fall back on, so DNS will \
                     answer UNFILTERED. Raise `lists.max_total_domains` or drop a list"
                );
            } else {
                tracing::error!(
                    target: "audit",
                    unique,
                    ceiling,
                    serving = total,
                    "refresh refused: merged corpus exceeds max_total_domains. The corpus is now \
                     FROZEN at the previous generation — domains published upstream after this \
                     point will NOT be blocked, and this state persists across every future \
                     refresh until the corpus shrinks or the ceiling is raised. `warden status` \
                     reports it on every check"
                );
            }
        } else {
            #[cfg(test)]
            {
                self.rebuild_count += 1;
            }
            if let CorpusVerdict::Install {
                unique, warn: true, ..
            } = &corpus_verdict
            {
                tracing::warn!(
                    target: "audit",
                    unique = *unique,
                    ceiling = self.max_total_domains.unwrap_or(0),
                    "merged corpus is at or past 90% of max_total_domains; installing anyway"
                );
            }
            if let CorpusVerdict::InstallOverCeiling {
                unique, ceiling, ..
            } = &corpus_verdict
            {
                // Deliberately a WARN and not an ERROR. The operator is
                // over their budget and must act, but the daemon is
                // filtering — which is the opposite of the state the
                // ERROR above reports, and the two must not read alike.
                tracing::warn!(
                    target: "audit",
                    unique = *unique,
                    ceiling = *ceiling,
                    "merged corpus EXCEEDS max_total_domains but nothing was installed to fall \
                     back on, so it is being installed anyway rather than starting up unfiltered. \
                     Memory will exceed the configured budget. Raise `lists.max_total_domains` to \
                     the corpus you actually want, or drop a list"
                );
            }
            // The guard's per-shard counts are exact, so pass 2's maps are
            // sized to what they will actually hold. The fallback divides
            // the *previous* generation's size by 16, which over-allocates
            // on a shrinking corpus and rehashes on a growing one.
            //
            // Exhaustive on purpose: a verdict added later that carries
            // exact counts must not silently fall into the `None` arm and
            // lose them. The compiler is the reminder, not this comment.
            let exact_per_shard = match &corpus_verdict {
                CorpusVerdict::Install { per_shard, .. }
                | CorpusVerdict::InstallOverCeiling { per_shard, .. } => Some(per_shard.clone()),
                CorpusVerdict::Unmeasured | CorpusVerdict::Refuse { .. } => None,
            };
            let per_shard = estimated / DOMAIN_SHARDS + 1;

            // neutrality-06: bound before the shard loop so the borrow of
            // `spill` below does not contend with a `self` field read.
            //
            // plp-s1: minted ONCE, here, and cloned into all 16 shards. This
            // is the single publish point `_docs/features/profile_list_policy.md`
            // §2.4 requires — `ListPolicy::publish` is the only way to take a
            // generation id, so a corpus that reaches the engine without
            // passing through this line does not exist.
            let policy = ListPolicy::publish(self.policy_masks.clone());

            for idx in 0..DOMAIN_SHARDS {
                let capacity = exact_per_shard
                    .as_ref()
                    .and_then(|v| v.get(idx).copied())
                    .unwrap_or(per_shard);
                match spill.build_shard(idx, capacity, &mut added_by_bit, &policy) {
                    Ok(shard) => {
                        total += shard.len();
                        self.filter.swap_shard_sorted(idx, shard);
                    }
                    Err(e) => {
                        // The engine keeps serving this shard's previous
                        // generation. That is the hybrid-consistency state
                        // sharding already accepts (some shards new, some
                        // old) — not a torn read — so the remaining shards
                        // still get installed.
                        tracing::error!(
                            shard = idx,
                            error = %e,
                            "failed to build domain shard from spill, keeping its previous generation"
                        );
                        degraded = true;
                    }
                }
            }

            if degraded {
                // Report what is actually installed, not what this cycle
                // managed to build.
                total = self.filter.domain_count();
            } else {
                installed = true;
                // Must track `SortedShard`'s entry type, not the old
                // `DomainMasks` pair: 24 B + 8 B = 32 B, against 24 + 16 = 40.
                // Left stale, this over-reports by 25 % on the one
                // operator-facing memory number this workstream exists to
                // move, and nothing fails to say so.
                let est_bytes = total * std::mem::size_of::<(CompactString, u64)>();
                tracing::info!(
                    total,
                    est_mb = est_bytes / (1024 * 1024),
                    spill = if spill.is_disk() { "disk" } else { "memory" },
                    "domain map updated (estimated map payload)"
                );
            }
        }

        // The digest must describe the generation that is actually live, and
        // this is keyed on an install having completed rather than on a case
        // analysis of the ways one can fail.
        //
        // Getting this wrong is not a cosmetic bug. Store this cycle's digest
        // without installing it and the next cycle recomputes the same digest,
        // decides nothing changed, and skips again — the daemon then serves a
        // stale blocklist silently and indefinitely, even after the underlying
        // problem clears. A full spill dir is exactly how that happens: the
        // partition writes hundreds of MB into the lists dir at production
        // scale, `flush` fails, and nothing is installed.
        self.installed_corpus_digest = if installed {
            corpus_digest
        } else if unchanged {
            // Nothing was rebuilt because nothing needed to be; the digest
            // already describes the live generation.
            self.installed_corpus_digest
        } else {
            None
        };

        // Publish the cycle-level refusal state. Written on EVERY cycle,
        // not only on refusals: a stale refusal left standing after a
        // later cycle installs successfully would be the same lie in the
        // opposite direction.
        //
        // `novel_by_bit` is the counting pass's own array, so this never
        // reads `added_by_bit`. It is order-dependent by construction and
        // every renderer says so — it tells the operator which list to
        // drop, and nothing else.
        //
        // Taken before the `map` below consumes it: the payload is boxed,
        // so this is no longer a `Copy` tuple.
        let corpus_was_refused = corpus_refused.is_some();
        // The cycle mark rides alongside the refusal payload and answers a
        // different question: `corpus_refusal()` says WHAT went wrong, the
        // mark says THAT a cycle ended and which one. A caller polling for
        // its own refresh needs the second — the first reads `None` for
        // "installed", for "still running" and for "skipped" alike.
        //
        // **The mark is written LAST, and the order is the whole contract.**
        // It is the publish barrier: a reader that sees a new `seq` must be
        // guaranteed to see the payload belonging to it. Written first — as
        // this was until an external audit caught it — the reader can pair a
        // NEW mark with the PREVIOUS refusal, and `report_reload_outcome`
        // breaks out of its poll on the first changed `seq` rather than
        // re-reading. The output then contradicts itself inside one screen:
        // "installed." followed by the corpus block rendering CORPUS REFUSED
        // from the stale payload. `handle_status` reads them in the mirror
        // order (payload first, mark second), so the two orders compose.
        self.status_registry.set_corpus_refusal(corpus_refused.map(
            |(unique, ceiling, novel_by_bit)| {
                let mut novel_by_source: Vec<(String, u64)> = resolved
                    .iter()
                    .filter_map(|(source, _)| {
                        let bit = self.source_bits.bit_for_url(source.as_str())?;
                        Some((
                            source.clone(),
                            novel_by_bit.get(usize::from(bit)).copied().unwrap_or(0),
                        ))
                    })
                    .collect();
                novel_by_source.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                CorpusRefusal {
                    unique,
                    ceiling: ceiling as u64,
                    novel_by_source,
                }
            },
        ));
        // The publish. Everything a reader needs is in place above, so a
        // reader that sees this `seq` sees a consistent pair.
        self.status_registry.record_cycle(if corpus_was_refused {
            CycleOutcome::Refused
        } else {
            CycleOutcome::Installed
        });

        // Success-path status updates, now that `entries` is known.
        for p in pending {
            // On the skip path pass 2 never ran, so `added_by_bit` is all
            // zeroes — but nothing changed, so the previous cycle's
            // `entries` is still the right answer and is carried forward.
            //
            // A refused cycle carries forward for the same reason and a
            // sharper one: `entries` describes the generation that is
            // *serving*, and on a refusal that is still the previous one.
            // Reporting the refused corpus's per-source contributions here
            // would restate the very conflation this guard exists to end —
            // those numbers belong in the refusal diagnostic, not in a
            // field that means "what this source contributes to the map
            // you are querying".
            let added = if unchanged || corpus_was_refused {
                p.prev_status.as_ref().map_or(0, |s| s.entries)
            } else {
                added_by_bit.get(usize::from(p.bit)).copied().unwrap_or(0)
            };
            // §2.8: a non-`verified_fresh` entry (CacheOnly cache-hit only
            // — see the field doc on `PendingStatus`) must not be recorded
            // as a successful refresh. `ListStatus::from_refresh` would
            // stamp `last_outcome = Ok` and `last_refresh_at = now`, which
            // is exactly the "reads green in the TUI" failure mode this
            // design prohibits — here via the status fields rather than
            // `fetched_at`. Leaving the registry untouched carries the
            // prior status forward verbatim; the source's domains still
            // reached the map via `added` above regardless of this branch.
            if p.verified_fresh {
                update_list_status_ok(
                    &self.status_registry,
                    &p.source,
                    added,
                    p.counts,
                    p.prev_status.as_deref(),
                    now,
                );
                publish_list_stats_updated(&self.notification_tx, &p.source);
            }
            match p.age_secs {
                Some(age_secs) => tracing::info!(
                    source = p.source.as_str(),
                    bit = p.bit,
                    added,
                    age_secs,
                    "{}",
                    p.message
                ),
                None => {
                    tracing::info!(
                        source = p.source.as_str(),
                        bit = p.bit,
                        added,
                        "{}",
                        p.message
                    )
                }
            }
        }

        // Persist `prev_entries` for every known source. Failure to
        // write is a logged warning, not a hard error — the daemon
        // keeps running with in-memory state.
        if let Some(ref path) = self.status_persistence_path {
            if let Err(e) = self.status_registry.save(path) {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "failed to persist list_stats.json"
                );
            }
        }

        // Never resumed, so never left behind.
        drop(spill);
        if let Some(dir) = self.cache_dir.as_deref() {
            purge_shard_spill(dir);
        }

        // Free any in-memory body strings that may remain (disk cache is
        // the authoritative copy). This keeps steady-state RSS proportional
        // to the domain map, not to the sum of all raw list texts.
        if self.cache_dir.is_some() {
            for entry in self.cache.values_mut() {
                entry.body = None;
            }
        }

        // Latching readiness gate (`boot_list_persistence.md` §2.4).
        //
        // Keyed on the OBSERVABLE — the engine holds domains — rather
        // than on `installed`, so no arm of the install chain can forget
        // to open it, and the `unchanged` skip-rebuild path (which
        // installs nothing precisely because the live generation is
        // already correct) opens it too.
        //
        // There is no `else` to add: `ReadinessGate` has no `close`,
        // and its atomic is private to a sibling module. This position
        // — AFTER the swap that installs the generation — is still on
        // us, and is pinned by the manager gate tests below.
        if let Some(gate) = &self.filter_ready {
            if self.filter.domain_count() > 0 {
                gate.open();
            }
        }

        total
    }

    /// Resolve a source's cached body as a stream, checking the in-memory
    /// cache first, then falling back to the on-disk `.cache` file.
    ///
    /// The disk arm is the one that matters: it used to be a
    /// `std::fs::read_to_string` of a body up to ~200 MB, resident for the
    /// whole parse and stacked on top of whatever the reload already held.
    /// Streaming it costs one line plus the reader's buffer.
    fn resolve_body_reader(&self, url: &str, source: &str) -> Option<BodyReader> {
        // `trust = local`: the OPERATOR'S file is the body. The cached copy is
        // an artefact of the last bridge run, and reading it is what let
        // `sighup-ignores-bridge-body` survive its own fix.
        //
        // Measured twice on a live isolated daemon. First with lane C's fix
        // alone: append a domain, SIGHUP, "no list body changed since the
        // installed generation", domain not blocked. Then with a repair placed
        // in `probe_unchanged_corpus` only — SAME RESULT, because the digest
        // that decides is folded by the main parse loop, which reaches its body
        // through THIS function at three separate call sites. Fixing one of
        // four look-alike sites is how the second attempt failed; this is the
        // one they all share.
        //
        // `is_cache_fresh` skips the fetch that would refresh the copy, so
        // without this the operator's file is never re-read at all.
        if let Some(path) = self
            .local_bridge_dir
            .as_deref()
            .and_then(|dir| imported_local_disk_path(url, dir))
        {
            // ONLY when it has content. An EMPTY local body is the poisoned
            // case the retention guard exists for, and it is reachable on a
            // local file too — a truncating editor, an interrupted write, a
            // failed generator. Preferring it here would let a zero-byte file
            // wipe the corpus, and would break
            // `retention_guard_keeps_prior_cache_on_empty_200`, whose whole
            // point is that after the guard refuses a poisoned body the map is
            // re-parsed FROM THE RETAINED CACHE. Measured: that test went red
            // on the first, unconditional version of this branch.
            //
            // So: a non-empty local file wins over the cache (that is the edit
            // the operator just made); an empty or unreadable one falls through
            // to the cache path, where the guard's retained copy is.
            let usable = std::fs::metadata(&path)
                .map(|m| m.len() > 0)
                .unwrap_or(false);
            if usable {
                if let Ok(f) = std::fs::File::open(&path) {
                    return Some(BodyReader::Disk(std::io::BufReader::new(f)));
                }
            }
        }
        // Fast path: body still in memory (only when cache_dir is None).
        //
        // `mem2608-s7`: "fast" is relative — this `clone()` copies the whole
        // body, so the no-cache_dir path pays a full duplicate of the
        // largest list on every parse, on top of retaining it. Left as a
        // clone rather than a borrow because the borrow would be held
        // across `&mut self` in the caller; the real answer is that this
        // path should not exist, which is what the startup warning says.
        if let Some(body) = self.cache.get(url).and_then(|c| c.body.clone()) {
            return Some(BodyReader::Memory(std::io::Cursor::new(body)));
        }
        // Slow path: stream from the disk cache.
        self.open_body_from_disk(source).map(BodyReader::Disk)
    }

    /// Open a source's on-disk `.cache` body for streaming, after the
    /// §4.7 Phase 2 T3 size check.
    ///
    /// The check validates against the `size=` line in the matching
    /// `.meta` sidecar; a byte count differing by more than 1 % rejects
    /// the body so the next cycle re-downloads rather than parsing a
    /// corrupted cache. It is a supply-chain check on external list
    /// bodies, so streaming does not get to drop it.
    ///
    /// Two deliberate differences from the `read_to_string` version it
    /// replaces. The size now comes from `File::metadata().len()` — for a
    /// successful `read_to_string` that is exactly `body.len()`, so the
    /// predicate sees the same number. And it is taken from the **open
    /// handle**, not by re-`stat`ing the path, which closes a
    /// re-resolution window between check and read that the old code did
    /// not have. The check still runs *before* any byte is parsed, so the
    /// fail-closed property is preserved.
    fn open_body_from_disk(&self, source: &str) -> Option<std::io::BufReader<std::fs::File>> {
        let cache_dir = self.cache_dir.as_ref()?;
        let stem = source_to_cache_stem(source);
        let cache_path = cache_dir.join(format!("{stem}.cache"));
        let file = match std::fs::File::open(&cache_path) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(source, error = %e, "failed to read disk cache");
                return None;
            }
        };
        // Same `u64` → `usize` idiom as the 304 arm's body-size stat.
        let actual = match file
            .metadata()
            .ok()
            .and_then(|m| usize::try_from(m.len()).ok())
        {
            Some(n) => n,
            None => {
                tracing::warn!(source, path = %cache_path.display(), "cannot stat disk cache");
                return None;
            }
        };

        let meta_path = cache_dir.join(format!("{stem}.meta"));
        let parsed = load_meta_file(&meta_path);
        if !validate_cached_body_size(parsed.size, actual) {
            let expected = parsed.size.unwrap_or(0);
            let diff_pct = if expected > 0 {
                (actual.abs_diff(expected) as f64 / expected as f64) * 100.0
            } else {
                0.0
            };
            tracing::warn!(
                source,
                path = %cache_path.display(),
                expected_size = expected,
                actual_size = actual,
                diff_pct = format!("{diff_pct:.2}"),
                "cached body size diverges from .meta — discarding, will re-download on next refresh"
            );
            return None;
        }

        tracing::debug!(source, path = %cache_path.display(), "streaming list body from disk");
        Some(std::io::BufReader::with_capacity(SPILL_WRITE_BUF, file))
    }

    /// Read a source's cached body from disk as a `String`.
    ///
    /// Thin wrapper over [`Self::open_body_from_disk`] so the §4.7-T3 size
    /// validation has exactly one implementation. The refresh path streams
    /// instead of materialising the body, so this now exists only for the
    /// in-file tests that assert the validation predicate end-to-end.
    #[cfg(test)]
    fn read_body_from_disk(&self, source: &str) -> Option<String> {
        let mut reader = self.open_body_from_disk(source)?;
        let mut body = String::new();
        match reader.read_to_string(&mut body) {
            Ok(_) => Some(body),
            Err(e) => {
                tracing::warn!(source, error = %e, "failed to read disk cache");
                None
            }
        }
    }

    /// Download a single list. Returns the body on 200, or `NotModified` on 304.
    ///
    /// The URL is validated against [`super::http_client::validate_list_url`]
    /// before the request fires (P0-1: reject non-HTTPS and literal
    /// private/loopback/link-local hosts). Redirects are already constrained
    /// by the hardened redirect policy in the `reqwest::Client`.
    ///
    /// The response body is streamed through [`read_bounded_body`], aborting
    /// at `MAX_BODY_SIZE`. This closes the OOM vector where a malicious server
    /// omits `Content-Length` and streams unbounded bytes into `resp.text()`.
    ///
    /// `source` is the catalog id / raw URL the caller used to pick this
    /// download; it keys into `source_tokens` to attach an
    /// `Authorization: Bearer <value>` header when the blocklist declared
    /// an `auth_token_ref` in the v1 config (Sprint 32 N9).
    /// `cycle_anchor` is [`Self::refresh_at`]'s `now`, and it — not the
    /// instant this download finishes — is what gets stamped into
    /// `fetched_at` on every successful validation (`mem2608-t0`).
    ///
    /// Stamping completion is what made the scheduled refresh unable to
    /// fetch: sources are fetched serially in one loop, so a source's
    /// completion is its queue position plus its own download after the
    /// tick (119–421 s measured across 14 lists on the lab host), and the
    /// next fixed-period tick then finds an age exactly that much short of
    /// the interval. **The slower the download, the more certain the
    /// skip.** Anchoring is also the honest reading: `fetched-at` means
    /// "the cycle this body was validated in", and being early can only
    /// make a body look staler than it is, never fresher.
    async fn download_list(
        &mut self,
        source: &str,
        url: &str,
        cycle_anchor: OffsetDateTime,
    ) -> Result<FetchResult, ListError> {
        // S50 T5.5 loader-bridge: intercept synthetic `imported.local`
        // URLs BEFORE the HTTPS-only URL guard would refuse them. The
        // bridge reads from `<config_dir>/lists/<id>.<ext>` on disk for
        // local-trust blocklists and bypasses the HTTP stack entirely.
        // Falls through to HTTP for every other URL.
        if let Some(dir) = &self.local_bridge_dir {
            let trust = self
                .source_trust
                .trust_for_url(source)
                .unwrap_or(BlocklistTrust::RemoteUnsigned);
            match try_bridge_imported_local(url, trust, dir, self.max_body_bytes) {
                LocalBridgeOutcome::NotLocal => {} // fall through to HTTP path
                LocalBridgeOutcome::Loaded { body, path } => {
                    tracing::info!(
                        source = source,
                        path = %path.display(),
                        bytes = body.len(),
                        "imported-local bridge loaded list body from disk"
                    );
                    // **Deliberately returns WITHOUT stamping `fetched_at`,
                    // and without creating a cache entry.** `mem2608-t0`
                    // briefly "fixed" that as an oversight and it was not
                    // one: with no entry, `is_cache_fresh` at the top of
                    // the refresh loop never fires for this source, so an
                    // `imported.local` list is re-read from the operator's
                    // file on **every** cycle.
                    //
                    // That is the behaviour a local list needs. The
                    // freshness shortcut exists to avoid an HTTP request —
                    // network cost and crash-loop amplification — and a
                    // local file has neither. Opting the bridge in buys
                    // nothing (the shortcut still parses, just from a
                    // stale `.cache` copy) and costs the operator's edit
                    // going invisible until the interval elapses. It also
                    // silently disarms the retention guard: the poisoned
                    // body is never fetched, so `shrink_verdict` never
                    // measures it and the source reports `Ok`.
                    //
                    // Pinned by `a_bridge_source_never_takes_the_freshness_shortcut`
                    // and by the three `retention_guard_*` tests, whose
                    // comments state this precondition outright.
                    return Ok(FetchResult::Fresh(body));
                }
                LocalBridgeOutcome::Refused(reason) => {
                    return Err(ListError::Download {
                        url: super::http_client::redact_userinfo(url),
                        reason,
                    });
                }
            }
        }

        // Pre-flight URL validation (first hop — redirect policy covers the rest).
        // rev-2606 §06 manager-04b: redact_userinfo on the `url` field so a
        // credential embedded in a list URL never lands in the stored failure
        // reason / IPC status / logs. validate_list_url itself refuses
        // userinfo URLs (and its own message is already redacted).
        super::http_client::validate_list_url(url).map_err(|e| ListError::Download {
            url: super::http_client::redact_userinfo(url),
            reason: e.to_string(),
        })?;

        let mut req = self.client.get(url);

        // rev-2606 §06 source_key-02: attach the bearer header via the
        // URL→v1-id fallback so a pure-v1 `[[blocklists]]` row with an
        // `auth_token_ref` (whose `source` string is the raw URL, which misses
        // the slash-form token key) is not fetched anonymously. The immutable
        // borrows end with this block, before the cache reads below.
        if let Some(token) =
            resolve_bearer_token(&self.source_tokens, &self.source_to_blocklist, source)
        {
            req = req.header("Authorization", format!("Bearer {token}"));
        }

        if let Some(cache) = self.cache.get(url) {
            if let Some(etag) = &cache.etag {
                req = req.header("If-None-Match", etag);
            }
            if let Some(lm) = &cache.last_modified {
                req = req.header("If-Modified-Since", lm);
            }
        }

        let resp = req.send().await.map_err(|e| ListError::Download {
            url: super::http_client::redact_userinfo(url),
            reason: super::http_client::redact_userinfo(&classify_fetch_error(&e)),
        })?;

        if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
            // Server confirmed the cached content is still current: bump
            // fetched_at on the existing entry so the freshness check
            // (Phase 1.2) treats this round as a "successful refresh"
            // and avoids re-asking until another full interval passes.
            // The body on disk is unchanged; the caller only rewrites
            // the .meta file.
            let cache = self.cache.entry(url.to_string()).or_default();
            cache.fetched_at = cycle_anchor;
            return Ok(FetchResult::NotModified);
        }

        if !resp.status().is_success() {
            return Err(ListError::Download {
                url: super::http_client::redact_userinfo(url),
                reason: format!("HTTP {}", resp.status()),
            });
        }

        let etag = resp
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let last_modified = resp
            .headers()
            .get("last-modified")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // Advertised Content-Length is still worth an early fail if present,
        // but the real safety is in the streamed read below.
        if let Some(cl) = resp.content_length() {
            // Treat a length that overflows usize (only reachable on a 32-bit
            // target) as "too large" rather than letting an `as usize` cast
            // truncate it past this early guard. Mirrors the `usize::try_from`
            // clamp in `read_bounded_body_bytes`.
            let cl = usize::try_from(cl).unwrap_or(usize::MAX);
            if cl > self.max_body_bytes {
                return Err(ListError::TooLarge {
                    url: super::http_client::redact_userinfo(url),
                    size: cl,
                    max: self.max_body_bytes,
                });
            }
        }

        let body = read_bounded_body(resp, url, self.max_body_bytes).await?;

        let cache = self.cache.entry(url.to_string()).or_default();
        cache.etag = etag;
        cache.last_modified = last_modified;
        // Stamp the fresh-fetch timestamp explicitly: or_default() returns
        // now_utc() on a NEW entry but on a subsequent refresh the entry
        // already exists and would otherwise keep the previous fetched_at.
        // The freshness check (Phase 1.2) reads this field on every cycle,
        // so it has to track every successful 200 OK.
        cache.fetched_at = cycle_anchor;

        Ok(FetchResult::Fresh(body))
    }

    /// Spawn a background task that refreshes lists on the configured
    /// interval AND drains the out-of-band command channel wired by
    /// [`Self::set_command_channel`] (§4.7 Phase 2 T1).
    ///
    /// The loop uses `tokio::select!` between the ticker and the
    /// receiver. When `cmd_rx` is `None` (tests / ephemeral runs that
    /// never wired the channel) the receiver branch resolves to
    /// `std::future::pending()` and the loop degrades to ticker-only.
    pub fn spawn_refresh_loop(mut self) -> tokio::task::JoinHandle<()> {
        let interval = self.refresh_interval;
        let mut cmd_rx = self.cmd_rx.take();
        tokio::spawn(async move {
            let mut ticker = tokio_interval(interval);
            // The first tick is NOT skipped any more. It used to be, because
            // `start.rs` refreshed inline at boot and an immediate second
            // cycle would have been redundant. Boot now loads from disk and
            // never touches the network (`load_corpus_before_bind`), so
            // discarding this tick would leave a restarted box up to
            // `update_interval_secs` (12 h by default) behind — and a box
            // that restarts more often than that, permanently behind.
            //
            // It is cheap: `load_disk_cache` has already restored the ETag /
            // Last-Modified headers, so an unchanged list costs one 304, and
            // only genuinely stale lists transfer. The corpus digest then
            // matches the generation boot installed, so the map is not
            // rebuilt either.
            loop {
                // `refresh()` is awaited INSIDE the arm, so the command
                // branch below does not drain while a refresh runs. This is
                // the task that carries the bulk client
                // (`set_download_client`, swapped in by the caller), so the
                // window is now minutes rather than the old always-failing
                // ~3 — a refresh that actually downloads ~600 MB at 1 MB/s
                // takes about ten.
                //
                // Deliberately left as-is HERE, and only here. The one
                // command on this channel is `Forget`, whose IPC caller
                // gives up after the 5s client-side response timeout
                // (`socket_client.rs`) — a bar the old window already blew
                // past, so nothing operator-visible changed.
                //
                // Do NOT generalise that to the daemon's other blocking
                // refresh. `start.rs` no longer refreshes inline at boot (it
                // loads from disk instead — see
                // `_docs/features/boot_list_persistence.md`), but the signal
                // loop's `select!` still does, and that one keeps the tight
                // client on purpose: its sibling arm is SIGTERM against a
                // `Type=simple` unit with no `TimeoutStopSec` (90s →
                // SIGKILL), so starving it costs a clean shutdown. This one
                // costs a `Forget` that was already timing out.
                //
                // If a second command variant is ever added, re-check this:
                // the fix would be to run `refresh()` in a spawned task and
                // keep the select! free, not to shrink the timeouts back.
                tokio::select! {
                    _ = ticker.tick() => {
                        tracing::info!("scheduled list update starting");
                        self.refresh().await;
                    }
                    Some(cmd) = recv_or_pending(&mut cmd_rx) => {
                        match cmd {
                            ListManagerCommand::Forget { source, ack } => {
                                let was_cached = self.forget_source(&source);
                                let _ = ack.send(was_cached);
                            }
                        }
                    }
                }
            }
        })
    }

    /// Pre-populate in-memory cache headers from on-disk `.meta` files.
    ///
    /// Only loads ETag / Last-Modified so the first `refresh()` can send
    /// conditional requests (304). Body text is NOT loaded — `refresh()`
    /// reads bodies from disk on demand, keeping at most one in memory at
    /// a time. This avoids the startup RSS spike that occurred when all
    /// list bodies were loaded into memory simultaneously.
    pub fn load_disk_cache(&mut self) {
        let cache_dir = match &self.cache_dir {
            Some(dir) => dir.clone(),
            None => {
                // `mem2608-s7`. Not reachable from any config — `lists
                // .cache_dir` is a `PathBuf` with a serde default, and all
                // three production constructions pass `Some(_)` — so this
                // warns the *next* call site rather than the operator. It
                // is here because the failure mode is invisible: bodies
                // stay resident, `refresh` never clears them (the sweep at
                // the end of the cycle is gated on `cache_dir.is_some()`),
                // and `resolve_body_reader` clones each one in full on
                // every parse. No log line, no error, roughly twice the
                // RAM.
                tracing::warn!(target: "audit", "{}", LIST_CACHE_DIR_UNSET_WARNING);
                return;
            }
        };

        // rev-2606 §06 carryover-3: the cache is trusted on read (its body
        // is parsed straight into the filter map). If the directory is
        // group- or world-writable, a local non-daemon user could plant a
        // `.cache` body and steer filtering. Warn at startup so the
        // operator can tighten the mode; warn-only — we do not refuse to
        // boot (the daemon may legitimately run in a permissive dev tree).
        if let Some(mode) = cache_dir_lax_mode(&cache_dir) {
            tracing::warn!(
                target: "audit",
                path = %cache_dir.display(),
                mode = format!("{mode:04o}"),
                "list cache directory is group/world-writable — a local user could \
                 plant a cache body the daemon trusts; tighten to 0750 or stricter"
            );
        }

        for source in &self.sources {
            let url = match self.catalog.resolve(source) {
                Some(u) => u,
                None => continue,
            };

            let stem = source_to_cache_stem(source);
            let cache_path = cache_dir.join(format!("{stem}.cache"));
            let meta_path = cache_dir.join(format!("{stem}.meta"));

            // Only check that the cache file exists; don't load it.
            if !cache_path.exists() {
                continue;
            }

            let parsed = load_meta_file(&meta_path);

            let entry = self.cache.entry(url).or_default();
            entry.etag = parsed.etag;
            entry.last_modified = parsed.last_modified;
            // Legacy meta files (pre-Sprint-24) have no fetched-at line:
            // stamp them as now_utc() on first read so they look fresh and
            // do not trigger an HTTP burst on the next refresh cycle. The
            // real timestamp will become accurate after the first
            // successful 200/304 response.
            entry.fetched_at = parsed.fetched_at.unwrap_or_else(OffsetDateTime::now_utc);

            tracing::info!(
                source = source.as_str(),
                path = %cache_path.display(),
                has_etag = entry.etag.is_some(),
                fetched_at = %entry.fetched_at,
                "disk cache available (headers loaded, body deferred)"
            );
        }
    }

    /// Remove `.cache` / `.meta` files for sources no longer in the config.
    pub fn cleanup_stale_caches(&self) {
        let cache_dir = match &self.cache_dir {
            Some(dir) => dir,
            None => return,
        };

        let active_stems: HashSet<String> = self
            .sources
            .iter()
            .map(|s| source_to_cache_stem(s))
            .collect();

        let entries = match std::fs::read_dir(cache_dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let stem = name
                .strip_suffix(".cache")
                .or_else(|| name.strip_suffix(".meta"));
            if let Some(stem) = stem {
                if !active_stems.contains(stem) {
                    if let Err(e) = std::fs::remove_file(entry.path()) {
                        tracing::warn!(
                            file = %entry.path().display(),
                            error = %e,
                            "failed to remove stale cache file"
                        );
                    } else {
                        tracing::info!(file = %name, "removed stale list cache file");
                    }
                }
            }
        }
    }
}

/// Build a successful [`ListStatus`] from a refresh cycle and atomically
/// swap it into the registry. Extracted helper so the three success-path
/// arms in [`ListManager::refresh`] (freshness-skip, fresh download,
/// 304 not modified) all go through the same code, ensuring identical
/// `delta_pct_vs_prev` and `prev_entries` semantics.
fn update_list_status_ok(
    registry: &ListStatusRegistry,
    source: &str,
    entries: u64,
    counts: ParsedCounts,
    prev: Option<&ListStatus>,
    now: OffsetDateTime,
) {
    let status = ListStatus::from_refresh(entries, counts, prev, now);
    registry.update_for_url(source, status);
}

/// Publish [`IpcNotification::ListStatsUpdated`] for `source` if a
/// notification channel is wired. Send errors (no live subscribers
/// → `broadcast::error::SendError`) are intentionally swallowed —
/// the channel is fire-and-forget by design (T2 docstring on
/// [`ListManager::set_notification_channel`]).
fn publish_list_stats_updated(
    tx: &Option<tokio::sync::broadcast::Sender<IpcNotification>>,
    source: &str,
) {
    if let Some(sender) = tx {
        let _ = sender.send(IpcNotification::ListStatsUpdated {
            id: source.to_string(),
        });
    }
}

/// Common 3-step sequence shared by the three "happy" arms of
/// [`ListManager::refresh`]: parse `body` into `merged`, record the
/// successful outcome in the status registry, and publish the IPC
/// `ListStatsUpdated` notification.
///
/// The arms differ only in surrounding context (logging granularity and
/// post-parse work like disk persistence or meta-file refresh) — those
/// stay at the call sites. The error arm does NOT route through here:
/// it uses [`ListStatus::from_failure`] instead, so `prev_entries` is
/// carried forward from the previous successful cycle.
///
/// Returns the source's [`ParsedCounts`], with `unique_domains` supplied by
/// the sink (see [`ShardSpillSink`]).
///
/// # Errors
///
/// On any I/O or UTF-8 error from `reader`, everything this call spilled is
/// rolled back before the error propagates, so the spill is byte-identical
/// to its state before the call. That restores the all-or-nothing invariant
/// the old `read_to_string` had for free by failing before the parse
/// started, and it is what stops a truncated body from being ingested
/// partially and then read as a legitimate sub-threshold shrink.
fn parse_source_into_spill_counted<R: BufRead>(
    reader: R,
    bit_mask: u64,
    spill: &mut ShardSpill,
    max_entries: usize,
    source: &str,
    declared: Option<ListFormat>,
    counting: UniqueCount,
) -> std::io::Result<(ParsedCounts, [u8; 32])> {
    let mark = spill.mark();
    let mut reader = HashingReader::new(reader);
    let mut sink = match counting {
        UniqueCount::Measure(hint) => {
            ShardSpillSink::measuring(spill, hint.map(|n| n.get() as usize))
        }
        UniqueCount::Carried(_) => ShardSpillSink::counting_nothing(spill),
    };
    match parse_list_streaming(
        &mut reader,
        bit_mask,
        &mut sink,
        max_entries,
        source,
        declared,
    ) {
        // Fail closed on a cap hit (step 3 of
        // `lists-truncation-silent-19pct`). Enforced HERE, in the one
        // function every refresh path funnels through, rather than at the
        // five call sites or in the retention guard — the guard runs at
        // only one of them, so hooking it would have left four paths still
        // ingesting half a list.
        //
        // Rolling back the spill and returning `Err` reuses machinery that
        // already exists and is already tested: callers mark the source
        // `Failed` with this reason via `ListStatus::from_failure`, keep
        // the previous generation on disk, and keep blocking with it. That
        // is exactly the retained-prior-generation behaviour step 3 asks
        // for, so it needs no new state.
        //
        // ORDERING: this is only safe because the cap was raised first
        // (step 2). Against the old 5M cap it would have refused four of
        // the eight live sources outright and taken coverage from -19% to
        // roughly -60%.
        Ok(counts) if counts.parsed_truncated > 0 => {
            let reason = super::status::format_blocklist_truncation_refused(
                max_entries,
                counts.parsed_truncated,
            );
            tracing::error!(
                target: "audit",
                source,
                max_entries,
                dropped = counts.parsed_truncated,
                "{}",
                reason
            );
            if let Err(rollback_err) = spill.rollback(&mark) {
                tracing::error!(
                    source,
                    error = %rollback_err,
                    "failed to roll back truncated list ingest; this cycle's map may be incomplete"
                );
            }
            Err(std::io::Error::other(reason))
        }
        Ok(mut counts) => {
            // The measured count when there is one, the carried one
            // otherwise. Never both, and never zero-by-omission — see
            // [`UniqueCount`].
            counts.unique_domains = match (sink.unique_domains(), counting) {
                (Some(measured), _) => measured,
                (None, UniqueCount::Carried(prior)) => prior.get(),
                // Unreachable: `counting_nothing` is only built for the
                // `Carried` arm. Handled rather than unwrapped because the
                // failure mode of getting it wrong is a silently disarmed
                // retention guard, not a panic.
                (None, UniqueCount::Measure(_)) => 0,
            };
            Ok((counts, reader.finish()))
        }
        Err(e) => {
            if let Err(rollback_err) = spill.rollback(&mark) {
                tracing::error!(
                    source,
                    error = %rollback_err,
                    "failed to roll back partial list ingest; this cycle's map may be incomplete"
                );
            }
            Err(e)
        }
    }
}

/// Always-measure flavour of [`parse_source_into_spill_counted`].
///
/// **Test-only on purpose.** Measuring is the right default for a test
/// asserting counts, and the wrong default for a refresh arm re-reading an
/// unchanged body — that is the ~144 MiB `mem2608-s1` T2 removes. Gating
/// this to `cfg(test)` means a future production call site cannot reach the
/// convenient name and quietly pay for a count nobody reads: it has to name
/// a [`UniqueCount`], which is where the decision belongs.
#[cfg(test)]
fn parse_source_into_spill<R: BufRead>(
    reader: R,
    bit_mask: u64,
    spill: &mut ShardSpill,
    max_entries: usize,
    source: &str,
    declared: Option<ListFormat>,
) -> std::io::Result<(ParsedCounts, [u8; 32])> {
    parse_source_into_spill_counted(
        reader,
        bit_mask,
        spill,
        max_entries,
        source,
        declared,
        UniqueCount::Measure(None),
    )
}

/// What [`ListManager::probe_unchanged_corpus`] hands back when a cycle
/// can be settled from bytes alone: the digest context it folded (so the
/// caller's own `unchanged` test sees exactly the fold the walk would have
/// produced), the parsed-line total carried forward from the last cycle,
/// and the per-source status updates the walk would have queued.
struct ProbeOutcome {
    digest_ctx: sha2::Sha256,
    spilled: u64,
    pending: Vec<PendingStatus>,
}

/// SHA-256 of every byte of a cached body, streamed.
///
/// `fill_buf`/`consume` rather than [`HashingReader`] + `io::copy`: the
/// adapter hashes in both `read` and `consume`, which is self-consistent
/// for the parser (one access pattern, every cycle) but not something to
/// bet a cross-path digest comparison on. This loop hashes each byte
/// exactly once by construction, and the buffer is the `BufReader`'s —
/// nothing accumulates.
fn hash_body<R: BufRead>(mut reader: R) -> std::io::Result<[u8; 32]> {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    loop {
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() {
            break;
        }
        let n = chunk.len();
        hasher.update(chunk);
        reader.consume(n);
    }
    Ok(hasher.finalize().into())
}

/// Start a cycle's corpus digest, seeded with the cycle-level inputs that
/// change what the same bytes build.
///
/// **The direction policy belongs here, and its absence was a live defect.**
/// The digest decides whether pass 2 runs; the published [`ListPolicy`] is
/// what routes each domain into `allow_mask` or `block_mask`. So with the two
/// disconnected, an operator who flipped a list's direction and reloaded got
/// no rebuild whenever no list body had changed — and the flip silently did
/// not take effect. Harmless in the deny→allow direction (warden keeps
/// blocking); **not** harmless in the other one, where a revoked exemption
/// keeps exempting until some unrelated list happens to change.
///
/// `set_list_policy` deliberately does not clear `installed_corpus_digest`
/// instead: the digest describes what the installed generation was built
/// from, and the policy is one of those inputs, exactly like `max_entries`
/// and the declared format already folded per source.
///
/// **`plp-s3` widened what has to be folded in, and getting this wrong is
/// the same defect one level up.** The old seed was one `u64`. Direction is
/// now per profile, so an operator who changes `profiles.kids.lists` without
/// touching any list body must still get a rebuild — otherwise the override
/// is accepted, written, and never served. Every profile's pair is folded,
/// in sorted id order so the digest is a function of the policy and not of
/// `HashMap` iteration order.
fn new_corpus_digest_ctx(masks: &PolicyMasks) -> sha2::Sha256 {
    use sha2::Digest;
    let mut ctx = sha2::Sha256::new();
    ctx.update(masks.base.allow.to_le_bytes());
    ctx.update(masks.base.block.to_le_bytes());
    let mut ids: Vec<&CompactString> = masks.per_profile.keys().collect();
    ids.sort_unstable();
    for id in ids {
        let m = masks.per_profile[id];
        ctx.update((id.len() as u64).to_le_bytes());
        ctx.update(id.as_bytes());
        ctx.update(m.allow.to_le_bytes());
        ctx.update(m.block.to_le_bytes());
    }
    ctx
}

/// Fold one source's contribution into the cycle's corpus digest.
///
/// The body hash alone is not enough: a change to `max_entries` or to the
/// operator-declared format changes what the same bytes parse into, and
/// must therefore force a rebuild. The source id is length-prefixed so two
/// different source lists cannot concatenate to the same digest.
fn fold_corpus_digest(
    ctx: &mut sha2::Sha256,
    source: &str,
    bit_mask: u64,
    max_entries: usize,
    declared: Option<ListFormat>,
    body_hash: &[u8; 32],
) {
    use sha2::Digest;
    ctx.update((source.len() as u64).to_le_bytes());
    ctx.update(source.as_bytes());
    ctx.update(bit_mask.to_le_bytes());
    ctx.update((max_entries as u64).to_le_bytes());
    ctx.update([match declared {
        None => 0u8,
        Some(ListFormat::DomainOnly) => 1,
        Some(ListFormat::Hosts) => 2,
        Some(ListFormat::AdGuard) => 3,
    }]);
    ctx.update(body_hash);
}

/// A success-path status update held back until pass 2 can supply the
/// `entries` delta.
///
/// The flat producer computed `entries` as `merged.len()` after minus
/// before — the source's *net-new* contribution in iteration order. That
/// number does not exist until domains from every source have met each
/// other, which under shard-at-a-time only happens in pass 2. It is
/// reconstructed exactly there (first-occurrence-in-spill-order per bit,
/// and spill order *is* source-iteration order), so these updates wait
/// rather than reporting a different quantity.
struct PendingStatus {
    source: String,
    bit: u8,
    counts: ParsedCounts,
    prev_status: Option<Arc<ListStatus>>,
    /// Log line to emit once `added` is known — kept verbatim so operator
    /// greps against these messages keep matching.
    message: &'static str,
    /// `Some` only for the cache-freshness arm, which logs it.
    age_secs: Option<i64>,
    /// Whether this entry is a **verified-fresh** refresh — i.e. whether
    /// the consumer loop should stamp [`ListStatus::from_refresh`]
    /// (`last_outcome = Ok`, `last_refresh_at = now`) at all.
    ///
    /// `false` only for the `RefreshMode::CacheOnly` cache-hit arm: the
    /// body it read may be an arbitrary age (§2.3), so recording it as a
    /// just-verified refresh would be exactly the freshness lie
    /// `_docs/features/boot_list_persistence.md` §2.8 prohibits — a dead
    /// upstream would read green in the TUI. Decided at each push site
    /// rather than read from the enclosing `mode` inside the consumer
    /// loop, so a future push site added under `CacheOnly` must decide
    /// this explicitly instead of silently inheriting "stamp" from a
    /// loop-wide default.
    verified_fresh: bool,
}

/// rev-2606 §06 carryover-3: return the permission bits of `cache_dir` when
/// it is group- or world-writable on a Unix host, else `None`.
///
/// The cache is trusted on read — its body is parsed straight into the
/// filter map — so a writable cache dir lets a local non-daemon user plant
/// a `.cache` body and steer filtering. Split from the warn site so the
/// predicate is unit-testable. No-op (always `None`) off Unix (Windows
/// ACLs are out of scope; the daemon targets Linux).
#[cfg(unix)]
fn cache_dir_lax_mode(cache_dir: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    // Dir may not exist yet (first boot creates it) — nothing to check.
    let mode = std::fs::metadata(cache_dir).ok()?.permissions().mode();
    (mode & 0o022 != 0).then_some(mode & 0o7777)
}

#[cfg(not(unix))]
fn cache_dir_lax_mode(_cache_dir: &Path) -> Option<u32> {
    None
}

/// Convert a source ID to a filesystem-safe cache file stem.
///
/// Catalog IDs like `"privacy/ads"` become `"privacy_ads-<hash8>"`.
/// Raw URLs are sanitized the same way (any char outside `[A-Za-z0-9._-]`
/// is replaced with `_`) and then suffixed with the first 8 hex chars of
/// the SHA-256 of the original (un-sanitized) source string.
///
/// The hash suffix disambiguates URLs that sanitize to identical stems
/// — without it, `https://a.example/list.txt` and `https://b.example/list.txt`
/// could collide on disk. With it, two source strings that differ in any
/// byte produce different stems with overwhelming probability (32-bit
/// suffix; collision risk negligible for ≤64 sources).
///
/// **Format compatibility:** the stem layout changed in T3.4 (M-23). The
/// previous layout had no hash suffix, so files written by older binaries
/// will not be found under the new stem. `cleanup_stale_caches()` sweeps
/// any orphaned files automatically on the next startup or reload, and
/// `refresh()` re-downloads the affected lists once (no `If-Modified-Since`
/// headers since the in-memory cache also misses). Operators see one
/// extra refresh cycle on first startup after the upgrade; no manual
/// migration step required.
pub fn source_to_cache_stem(source: &str) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;

    let mut sanitized: String = source
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let digest = Sha256::digest(source.as_bytes());
    sanitized.push('-');
    for byte in &digest[..4] {
        // Append in place — `write!` to a String is infallible.
        let _ = write!(sanitized, "{byte:02x}");
    }
    sanitized
}

/// Parsed contents of a `.meta` sidecar file.
///
/// `fetched_at` is `None` when the file predates Sprint 24 Phase 1.1
/// (no `fetched-at=` line). Callers that need a concrete timestamp
/// fall back to `OffsetDateTime::now_utc()` so legacy caches behave as
/// "freshly stamped on first read after upgrade" — this avoids a
/// startup HTTP burst when the daemon is restarted onto the new
/// binary, at the cost of a one-time 24h max staleness window.
///
/// `size` is `None` when the file predates §4.7 Phase 2 T3 (no
/// `size=` line). Callers fall back to "trust the body" on missing
/// size — see [`validate_cached_body_size`].
struct ParsedMeta {
    etag: Option<String>,
    last_modified: Option<String>,
    fetched_at: Option<OffsetDateTime>,
    size: Option<usize>,
}

/// Load ETag, Last-Modified, and (optionally) fetched-at + size from a
/// `.meta` sidecar file.
fn load_meta_file(path: &Path) -> ParsedMeta {
    let mut parsed = ParsedMeta {
        etag: None,
        last_modified: None,
        fetched_at: None,
        size: None,
    };
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return parsed,
    };
    for line in content.lines() {
        if let Some(v) = line.strip_prefix("etag=") {
            if !v.is_empty() {
                parsed.etag = Some(v.to_string());
            }
        } else if let Some(v) = line.strip_prefix("last-modified=") {
            if !v.is_empty() {
                parsed.last_modified = Some(v.to_string());
            }
        } else if let Some(v) = line.strip_prefix("fetched-at=") {
            if !v.is_empty() {
                match OffsetDateTime::parse(v, &Rfc3339) {
                    Ok(ts) => parsed.fetched_at = Some(ts),
                    Err(e) => tracing::warn!(
                        path = %path.display(),
                        value = v,
                        error = %e,
                        "ignoring invalid fetched-at in .meta — treating as legacy entry"
                    ),
                }
            }
        } else if let Some(v) = line.strip_prefix("size=") {
            // §4.7 Phase 2 T3: optional size= byte-count line.
            // Missing OR malformed -> None (back-compat: pre-T3 .meta
            // files load with legacy trust via `validate_cached_body_size`).
            if !v.is_empty() {
                match v.parse::<usize>() {
                    Ok(n) => parsed.size = Some(n),
                    Err(e) => tracing::warn!(
                        path = %path.display(),
                        value = v,
                        error = %e,
                        "ignoring invalid size in .meta — treating as legacy entry"
                    ),
                }
            }
        }
    }
    parsed
}

/// Persist a downloaded list body, HTTP headers, and the fetch
/// timestamp to disk as a `.cache` + `.meta` sidecar pair.
///
/// `fetched_at` is serialized as an RFC 3339 line in the `.meta`
/// sidecar so the freshness check (Phase 1.2) can reconstruct the
/// cache's age across daemon restarts. Pass `OffsetDateTime::now_utc()`
/// for fresh fetches.
///
/// s-4.31-disc-3 — paired-rename, meta-last. Both sidecars are first
/// staged in full (`.cache.new` / `.meta.new`, written + fsynced via
/// the §4.31 [`atomic_write`] helper), then promoted with two
/// `fs::rename`s — `.cache` first, `.meta` second. A crash mid-stage
/// leaves only stray `.new` files (the live pair is untouched). A
/// crash *between* the two renames leaves `.cache` fresh + `.meta`
/// stale; `read_body_from_disk`'s §4.7-T3 size predicate discards a
/// `.cache` whose byte count diverges from the `.meta` `size=` line,
/// forcing a re-download on the next refresh — the same recovery path
/// as upstream-changed content. The reverse rename order (`.meta`
/// first) would instead pass the size check against the wrong body
/// and silently parse a stale cache as valid, so the ordering is
/// load-bearing.
fn write_cache_to_disk(
    cache_dir: &Path,
    source: &str,
    body: &str,
    etag: Option<&str>,
    last_modified: Option<&str>,
    fetched_at: OffsetDateTime,
) {
    let stem = source_to_cache_stem(source);
    let cache_path = cache_dir.join(format!("{stem}.cache"));
    let meta_path = cache_dir.join(format!("{stem}.meta"));
    let cache_tmp = cache_dir.join(format!("{stem}.cache.new"));
    let meta_tmp = cache_dir.join(format!("{stem}.meta.new"));

    // §4.7 Phase 2 T3: stamp the exact byte size so the next boot can
    // refuse a `.cache` that has drifted. Always `Some(_)` here — the
    // 304 (content-unchanged) path uses `write_meta_file` directly.
    let meta_content = build_meta_content(etag, last_modified, fetched_at, Some(body.len()));

    // Stage both sidecars in full before promoting either.
    if let Err(e) = atomic_write(&cache_tmp, body.as_bytes()) {
        tracing::warn!(source, error = %e, "failed to stage list cache temp");
        return;
    }
    if let Err(e) = atomic_write(&meta_tmp, meta_content.as_bytes()) {
        tracing::warn!(source, error = %e, "failed to stage list meta temp");
        let _ = std::fs::remove_file(&cache_tmp);
        return;
    }

    // Promote — `.cache` first, `.meta` last (see fn docs: the
    // crash-between-renames state must be `.cache`-fresh / `.meta`-stale
    // so the §4.7-T3 size predicate recovers it).
    if let Err(e) = std::fs::rename(&cache_tmp, &cache_path) {
        tracing::warn!(source, error = %e, "failed to promote list cache temp");
        let _ = std::fs::remove_file(&cache_tmp);
        let _ = std::fs::remove_file(&meta_tmp);
        return;
    }
    if let Err(e) = std::fs::rename(&meta_tmp, &meta_path) {
        tracing::warn!(source, error = %e, "failed to promote list meta temp");
        let _ = std::fs::remove_file(&meta_tmp);
        // `.cache` is already live; the §4.7-T3 size predicate recovers
        // the `.cache`-fresh / `.meta`-stale state on the next boot.
    }
}

/// rev-2606 §06 `manager-04a`: strip ASCII control characters from an
/// upstream-supplied header value before it is written into the
/// line-oriented `.meta` sidecar.
///
/// The `.meta` format has no internal escaping: a `\n` smuggled into an
/// `ETag` / `Last-Modified` value would forge a `fetched-at=` / `size=`
/// line and poison the freshness / size validation on the next load.
/// Today this is unreachable — `HeaderValue::to_str()` already rejects
/// CR/LF and other control bytes — so this is defence-in-depth that moves
/// the invariant from "the HTTP stack happens to sanitise" into the
/// writer itself. Stripping (rather than rejecting) keeps a slightly
/// mangled ETag usable: the worst case is one wasted conditional request.
fn sanitize_meta_value(value: &str) -> Cow<'_, str> {
    if value.bytes().any(|b| b.is_ascii_control()) {
        Cow::Owned(value.chars().filter(|c| !c.is_ascii_control()).collect())
    } else {
        Cow::Borrowed(value)
    }
}

/// Build the `.meta` sidecar's plaintext content (etag / last-modified
/// / fetched-at / optional `size=`). Split out of [`write_meta_file`]
/// so [`write_cache_to_disk`] can stage the `.meta` body alongside the
/// `.cache` body before promoting the pair (s-4.31-disc-3).
///
/// `size` is the size of the matching `.cache` body. The 200-OK and
/// 304 paths pass `Some(_)`; `None` is reserved for the rare case
/// where the cache file is missing or inaccessible — the resulting
/// `.meta` carries no `size=` line and the next load falls back to
/// legacy "trust the body" semantics.
///
/// rev-2606 §06 `manager-04a`: `etag` / `last_modified` are
/// upstream-supplied and run through [`sanitize_meta_value`] so they
/// cannot inject extra `.meta` lines.
fn build_meta_content(
    etag: Option<&str>,
    last_modified: Option<&str>,
    fetched_at: OffsetDateTime,
    size: Option<usize>,
) -> String {
    let fetched_at_str = fetched_at
        .format(&Rfc3339)
        .unwrap_or_else(|_| String::new());
    let size_line = match size {
        Some(n) => format!("size={n}\n"),
        // Skip the size line entirely so the next load sees `None`
        // and applies legacy-compat trust (pre-§4.7-T3 behaviour).
        None => String::new(),
    };
    format!(
        "etag={}\nlast-modified={}\nfetched-at={}\n{}",
        sanitize_meta_value(etag.unwrap_or("")),
        sanitize_meta_value(last_modified.unwrap_or("")),
        fetched_at_str,
        size_line,
    )
}

/// Write only the `.meta` sidecar atomically. Used by the 304
/// branch of `refresh()` so a content-unchanged response can bump
/// `fetched-at` without rewriting the (large) `.cache` body file.
fn write_meta_file(
    meta_path: &Path,
    source: &str,
    etag: Option<&str>,
    last_modified: Option<&str>,
    fetched_at: OffsetDateTime,
    size: Option<usize>,
) {
    let meta_content = build_meta_content(etag, last_modified, fetched_at, size);
    if let Err(e) = atomic_write(meta_path, meta_content.as_bytes()) {
        tracing::warn!(
            source,
            error = %e,
            "failed to write list meta file"
        );
    }
}

/// §4.7 Phase 2 T3: predicate for cache-body byte-size sanity check.
///
/// Returns `true` (accept) when:
/// - `expected` is `None` — pre-T3 `.meta` files have no `size=` line;
///   the load path trusts the body unconditionally for back-compat.
/// - `expected == Some(0)` — division by zero would NaN the ratio;
///   treat zero-byte expectations as a trust signal (the empty-body
///   case is a degenerate corner already; falsely failing it adds
///   no signal).
/// - `|actual - expected| / expected < 0.01` — within 1 %, within
///   normal supply-chain churn for a healthy list.
///
/// Returns `false` (reject, force re-download) when the deviation
/// exceeds 1 %. The 1 % threshold is hardcoded per §11.3: typical
/// 5 MB lists give a 50 KB / ~1000-entry floor, below which
/// corruption is indistinguishable from organic churn.
///
/// `pub` so §4.7 T3 integration tests (`tests/`) can exercise the
/// predicate directly without going through the private
/// [`ListManager::open_body_from_disk`] path.
pub fn validate_cached_body_size(expected: Option<usize>, actual: usize) -> bool {
    match expected {
        None | Some(0) => true,
        Some(exp) => {
            let diff = actual.abs_diff(exp);
            // diff / exp < 0.01  <=>  diff * 100 < exp.
            // Integer arithmetic — no float rounding noise.
            diff.saturating_mul(100) < exp
        }
    }
}

/// Read an HTTP response body into a `String`, bounded by `max_bytes`.
///
/// Streams chunks from the response and tracks a running byte count; aborts
/// mid-stream with [`ListError::TooLarge`] as soon as the cap would be
/// exceeded. This closes the OOM primitive where a malicious server omits
/// `Content-Length` and sends unbounded bytes: `resp.text().await` would
/// have read to EOF, but this loop stops on the first chunk that crosses the
/// threshold.
///
/// `max_bytes` is supplied by the caller (usually from
/// `settings.lists.max_body_bytes`) so the same streaming guard serves both
/// blocklist downloads and IP blocklist downloads — both paths pass the same
/// cap, and neither can outgrow the operator's budget without them noticing.
///
/// After accumulating the bytes, decodes them as UTF-8 *lossily*: any
/// invalid sequence becomes U+FFFD rather than failing the whole download.
/// List files are domain-per-line ASCII/UTF-8, so a stray bad byte then
/// costs only the line it lands on (`is_valid_domain` rejects the U+FFFD),
/// not the entire list. Lossy is sandbox-safe — U+FFFD cannot forge an
/// `@@` allow / regex / `$important` rule.
pub(crate) async fn read_bounded_body(
    resp: reqwest::Response,
    url: &str,
    max_bytes: usize,
) -> Result<String, ListError> {
    let body_bytes = read_bounded_body_bytes(resp, url, max_bytes).await?;
    Ok(decode_body(body_bytes))
}

/// Turn a downloaded body into a `String` **without copying it**
/// (`mem2608-s1` T1).
///
/// `String::from_utf8` takes the `Vec` by value and reuses its allocation
/// when the bytes are valid UTF-8 — which every production list is. The
/// previous form, `String::from_utf8_lossy(&body_bytes).into_owned()`,
/// returned `Cow::Borrowed` for valid input and then `into_owned()` copied
/// the whole thing, so a 172 MB list was briefly resident **twice**: the
/// 256 MB `Vec` (it doubles from zero — `content_length()` is `None` for
/// every gzip-served list) plus a fresh 172 MB `String`, with the `Vec`
/// still borrowed and therefore still alive.
///
/// The lossy path is preserved exactly, and only for the case that needs
/// it: a single invalid byte costs the line it lands on
/// (`is_valid_domain` rejects U+FFFD), not the whole list. Sandbox-safe —
/// U+FFFD cannot synthesise an `@@` allow / regex / `$important` rule, so
/// a mangled byte can never widen what an external list expresses.
///
/// Split into its own function so the no-copy property is testable: a
/// `String` that reused the buffer keeps the `Vec`'s capacity, and one
/// that was copied has capacity equal to its length.
fn decode_body(body_bytes: Vec<u8>) -> String {
    match String::from_utf8(body_bytes) {
        Ok(body) => body,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    }
}

/// Bytes-flavoured sibling of [`read_bounded_body`]. Catalog JSON
/// fetches and any other consumer that wants to feed `serde_json::
/// from_slice` (or similar) without paying for a UTF-8 round-trip
/// uses this directly. The streaming loop is the same — same
/// `Content-Length` clamp, same per-chunk projected-size guard.
pub(crate) async fn read_bounded_body_bytes(
    resp: reqwest::Response,
    url: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, ListError> {
    let mut resp = resp;
    // Use the advertised Content-Length as a Vec capacity HINT only — clamp
    // to `max_bytes` so a dishonest server claiming TBs cannot OOM us at
    // allocation time. The streaming `projected > max_bytes` check below
    // remains the actual bound; Content-Length is never trusted as truth.
    let initial = resp
        .content_length()
        .and_then(|cl| usize::try_from(cl).ok())
        .map_or(0, |cl| cl.min(max_bytes));
    let mut body_bytes: Vec<u8> = Vec::with_capacity(initial);
    while let Some(chunk) = resp.chunk().await.map_err(|e| ListError::Download {
        url: url.to_string(),
        reason: classify_fetch_error(&e),
    })? {
        let projected = body_bytes.len().saturating_add(chunk.len());
        if projected > max_bytes {
            return Err(ListError::TooLarge {
                url: url.to_string(),
                size: projected,
                max: max_bytes,
            });
        }
        body_bytes.extend_from_slice(&chunk);
    }
    Ok(body_bytes)
}

/// Maximum number of list sources supported by the bitmask scheme.
/// Each source is assigned one bit in a `u64`, so 64 is the hard cap.
/// The config validator (`config::validator`) enforces the same cap at
/// boot, so this is a defence-in-depth guard for `build_source_bit_map`
/// callers that bypass the validator (e.g. embedded test fixtures).
pub const MAX_LIST_SOURCES: usize = 64;

/// Errors returned by [`build_source_bit_map`].
#[derive(Debug, thiserror::Error)]
pub enum BitMapBuildError {
    /// Too many list sources for the `u64` bitmask scheme.
    /// Operator-facing message names the cap and the next command per
    /// `feedback_usability_first`.
    #[error(
        "too many list sources: {got} configured, max {max} supported \
         (each source consumes one bit of a u64 bitmask). Edit \
         `config.toml` to reduce the `[lists].sources` list to {max} \
         entries or fewer, then retry."
    )]
    TooManySources { got: usize, max: usize },
}

/// S50 T5.5: unify legacy `lists.sources` with v1 `[[blocklists]]` URLs
/// so the manager sees the full set of subscribed lists, and produce the
/// per-source trust map for the [`set_local_bridge`](ListManager::set_local_bridge)
/// defence-in-depth check.
///
/// **Why this lives in `src/lists/`:** keeping the merge logic next to
/// the manager (rather than duplicated at every call site that
/// constructs one) means start.rs / update.rs just pass the loaded
/// config in and get back the two values they need. The bridge contract
/// (which URLs reach `download_list`, with which trust) stays internal
/// to the lists subsystem.
///
/// **Disabled entries** are skipped in the merged source vector — they
/// must not show up as a downloadable source — but their trust IS still
/// recorded in the map. A subsequent `enabled = true` flip + reload
/// then picks up the correct trust without recomputing anything.
///
/// **De-duplication** is by URL string AND by logical list (rev-2606
/// init-scaffold-silent-no-blocking). If a v1 `[[blocklists]].url`
/// already appears in `lists.sources`, it is not pushed twice — but the
/// trust entry IS recorded so the bridge still has it. Additionally,
/// when a catalog-resolvable slug in `lists.sources` kebab-translates
/// to a `[[blocklists]].id` (the dual-channel shape: same list wired
/// through both channels), the entity's URL is NOT appended: the slug
/// channel fetches the list, and [`SourceBitMap::build`]'s slash-form
/// translation seeds `by_v1_id` with the slug's bit, so the profile
/// mask points at the bit the download actually populates. Without
/// this, the two channels get separate bits, the entity loop re-points
/// `by_v1_id` at the never-populated URL bit, and the daemon holds
/// millions of domains while blocking nothing. The skip is gated on
/// catalog resolvability so a non-catalog slug + same-id entity (the
/// `imported.local` bridge shape) keeps its URL fetch.
pub fn merge_sources_with_blocklists(
    legacy: &[String],
    blocklists: &[crate::config::schema::Blocklist],
) -> (Vec<String>, SourceTrustMap) {
    let already: HashSet<&str> = legacy.iter().map(String::as_str).collect();
    // Kebab-id → catalog URL for every catalog-resolvable slug in the
    // legacy channel. Built once per merge (boot / reload / schedule
    // tick — cold paths); `Catalog::fallback()` is offline + sync.
    let legacy_resolved: HashMap<String, String> = {
        let catalog = crate::lists::catalog::Catalog::fallback();
        legacy
            .iter()
            .filter(|s| !crate::lists::source_key::is_url_source(s))
            .filter_map(|s| catalog.resolve(s).map(|url| (s.replace('/', "-"), url)))
            .collect()
    };
    let mut sources: Vec<String> = legacy.to_vec();
    let trust = SourceTrustMap::build(blocklists);
    for b in blocklists.iter() {
        if !b.enabled || already.contains(b.url.as_str()) {
            continue;
        }
        if let Some(slug_url) = legacy_resolved.get(b.id.as_str()) {
            if slug_url != b.url.as_str() {
                tracing::warn!(
                    blocklist = %b.id,
                    entity_url = %b.url,
                    catalog_url = %slug_url,
                    "[lists].sources slug shadows this [[blocklists]] row: the slug's \
                     catalog URL is fetched and the row's url is ignored — drop the \
                     slug from [lists].sources to fetch the row's url instead"
                );
            }
            continue;
        }
        sources.push(b.url.clone());
    }
    (sources, trust)
}

/// Build the source → bit index [`SourceBitMap`] from a list of source IDs.
/// Assigns bit 0 to the first source, bit 1 to the second, etc.
/// Returns [`BitMapBuildError::TooManySources`] when more than
/// [`MAX_LIST_SOURCES`] entries are supplied.
///
/// rev-2606 §06 carryover-5: thin wrapper over [`SourceBitMap::build`]
/// with no `[[blocklists]]` catalogue (URL/legacy channels only). Kept as
/// a convenience for callers (and tests) that have just a `sources` slice;
/// the frozen `TooManySources` message lives in `SourceBitMap::build`.
pub fn build_source_bit_map(sources: &[String]) -> Result<SourceBitMap, BitMapBuildError> {
    SourceBitMap::build(sources, &[])
}

/// Result of a single list download.
enum FetchResult {
    /// 200 OK with the response body text.
    Fresh(String),
    /// 304 Not Modified — use cached body.
    NotModified,
}

/// rev-2606 §06 `manager-01`: pure decision core of the retention guard,
/// split out of [`ListManager::shrink_verdict`] so it is unit-testable
/// without constructing a manager.
///
/// Baseline is the prior `unique_domains`, falling back to the persisted
/// `prev_entries` when no unique baseline exists (a v1→v2 upgrade or a
/// source that only ever recorded the merged-map delta). No baseline →
/// unconditional accept (first fetch of a brand-new source must never be
/// bricked). Guard disabled → unconditional accept.
///
/// Trip is exact integer arithmetic: `fresh * 100 < baseline * (100 -
/// max_drop_pct)`, i.e. a drop *strictly greater* than `max_drop_pct`
/// percent. An accepted refresh whose movement (shrink OR growth) still
/// exceeds [`DELTA_WARN_THRESHOLD_PCT`] carries that delta for the canary.
fn compute_shrink_verdict(
    enabled: bool,
    max_drop_pct: u8,
    prev: Option<&ListStatus>,
    fresh_unique: u64,
) -> ShrinkVerdict {
    if !enabled {
        return ShrinkVerdict::Accept { delta_warn: None };
    }
    let baseline = prev.and_then(|p| {
        if p.unique_domains > 0 {
            Some(p.unique_domains)
        } else {
            p.prev_entries.filter(|&n| n > 0)
        }
    });
    let baseline = match baseline {
        Some(b) => b,
        None => return ShrinkVerdict::Accept { delta_warn: None },
    };

    let trip = (fresh_unique as u128) * 100 < (baseline as u128) * (100 - max_drop_pct as u128);
    if trip {
        // drop_pct for the operator-facing reason (floor; the trip
        // decision above is the exact gate).
        let drop = baseline.saturating_sub(fresh_unique);
        let drop_pct = ((drop as u128 * 100) / baseline as u128) as u32;
        return ShrinkVerdict::Refuse {
            drop_pct,
            got: fresh_unique,
            kept: baseline,
        };
    }

    let delta_warn =
        compute_delta_pct(fresh_unique, baseline).filter(|d| d.abs() >= DELTA_WARN_THRESHOLD_PCT);
    ShrinkVerdict::Accept { delta_warn }
}

/// rev-2606 §06 `manager-01`: outcome of the retention-guard check on a
/// freshly downloaded body. See [`ListManager::shrink_verdict`].
#[derive(Debug)]
enum ShrinkVerdict {
    /// Trust the fresh body. `delta_warn` is `Some(pct)` when the accepted
    /// movement still exceeded [`DELTA_WARN_THRESHOLD_PCT`] — the caller
    /// emits the supply-chain canary warning but proceeds normally.
    Accept { delta_warn: Option<f32> },
    /// Refuse the fresh body: it shrank the list past the threshold. The
    /// caller keeps the prior cache, marks the source `Failed`, and
    /// re-parses the prior good body. Fields feed the operator-facing
    /// reason string.
    Refuse { drop_pct: u32, got: u64, kept: u64 },
}

/// Pure decision core of the cache-hit log message, split out so the
/// `RefreshMode` → message mapping is unit-testable without constructing
/// a manager or driving a refresh cycle — the same move
/// [`compute_shrink_verdict`] uses for the retention guard.
///
/// This pins the mapping only. [`PendingStatus::message`]'s own doc says
/// the strings are kept verbatim "so operator greps keep matching", and
/// the `CacheOnly`-vs-`Network` distinction is not cosmetic: it is what
/// stops a boot logging "list fresh, skipping HTTP" (implying a recent,
/// interval-bounded confirmation) about a cache that may be months old.
/// Swapping the two arms previously passed every test in this file.
///
/// What this does **not** cover: that the cache-hit call site passes the
/// `mode` the cycle is actually running under. That is a call-site
/// property, not a property of this mapping, and no unit test of a pure
/// function can observe it.
fn cache_hit_message(mode: RefreshMode) -> &'static str {
    match mode {
        RefreshMode::CacheOnly => "boot: loaded from disk cache, no HTTP",
        RefreshMode::Network => "list fresh, skipping HTTP and reusing cache",
    }
}

/// Outcome of attempting the S50 T5.5 `imported.local` loader-bridge.
#[derive(Debug)]
pub(crate) enum LocalBridgeOutcome {
    /// URL host is not the synthetic `imported.local` sentinel — caller
    /// must use the HTTP path.
    NotLocal,
    /// URL host matched and the on-disk file was read successfully.
    Loaded { body: String, path: PathBuf },
    /// URL host matched but the bridge refused: trust mismatch
    /// (defence-in-depth W2.1), missing file, or oversize. The string
    /// is operator-facing — it points at the path or the policy.
    Refused(String),
}

/// S50 T5.5 loader-bridge: turn `https://imported.local/<id>.<ext>` into
/// the on-disk file at `<config_dir>/lists/<id>.<ext>`.
///
/// **Why this exists.** S50 T3 introduced `warden blocklist import-local`
/// with a synthetic URL placeholder because the URL validator at
/// `src/config/schema/validator.rs:197` only accepts `http(s)://` and the
/// validator-loosening was OUT OF SCOPE for T3 (full root-cause +
/// decision trail in `_docs/features/lists_categories_v1.md` §15.9 and §15.11
/// DECISION OUTSIDE DOC #2). S50 T5.5 closes the loop in the list-manager
/// rather than the validator: the synthetic host stays put on the wire
/// and in audit logs, but `download_list` intercepts it before the URL
/// guard fires.
///
/// **Refusal contract.**
/// - Host != `imported.local` → [`LocalBridgeOutcome::NotLocal`] (caller
///   uses the HTTP path; no error).
/// - Host == `imported.local` but `trust != Local` → refuse. **This check
///   is load-bearing, not redundant.** It used to read as defence in
///   depth behind the validator's `base = allow` ⇒ `trust = local` rule
///   (S50 T2, then named `ALLOW_LIST_REQUIRES_LOCAL_TRUST`). That rule was
///   superseded on 2026-08-01 by per-list consent — see
///   `_docs/features/lists_categories_v1.md` §15.14 — so a `base = allow`
///   entry with `accept_unsigned_allow = true` now clears the validator on
///   `trust = remote-unsigned`, and a `base = deny` entry never went
///   through that rule at all. The validator has no `imported.local`
///   check of its own, which makes this the only place the synthetic host
///   is bound to local trust: without it a config could point the bridge
///   at attacker-controlled `lists/` content.
/// - File missing on disk → refuse with the expected path in the error
///   message (operator-debugging-friendly).
/// - File larger than `max_body_bytes` → refuse with the same per-list
///   cap the HTTP path enforces (defence-in-depth: a runaway local file
///   shouldn't OOM the daemon either).
///
/// `<id>` is derived from the URL path (the last segment), preserving
/// the extension if any. T3's writer always uses `<id>.txt`, but the
/// bridge accepts whatever T3 chose to file as the synthetic path so a
/// future format-aware import (`*.toml`, `*.json`) keeps working without
/// re-touching this code.
pub(crate) fn try_bridge_imported_local(
    url: &str,
    trust: BlocklistTrust,
    config_dir: &Path,
    max_body_bytes: usize,
) -> LocalBridgeOutcome {
    let parsed = match reqwest::Url::parse(url) {
        Ok(u) => u,
        // Unparseable URL: not our problem — let the HTTP guard speak.
        Err(_) => return LocalBridgeOutcome::NotLocal,
    };

    if parsed.host_str() != Some(IMPORTED_LOCAL_HOST) {
        return LocalBridgeOutcome::NotLocal;
    }

    if !matches!(trust, BlocklistTrust::Local) {
        return LocalBridgeOutcome::Refused(format!(
            "imported-local URL {url} requires trust=local, got trust={trust:?}; \
             refusing for defence-in-depth (W2.1)"
        ));
    }

    let id_with_ext = match imported_local_id_from_path(parsed.path()) {
        Some(id) => id,
        None => {
            return LocalBridgeOutcome::Refused(format!(
                "imported-local URL {url} path missing list id segment"
            ));
        }
    };

    let on_disk = config_dir.join("lists").join(&id_with_ext);

    let metadata = match std::fs::metadata(&on_disk) {
        Ok(m) => m,
        Err(e) => {
            return LocalBridgeOutcome::Refused(format!(
                "imported-local list file {} not readable: {e}",
                on_disk.display()
            ));
        }
    };

    if usize::try_from(metadata.len()).unwrap_or(usize::MAX) > max_body_bytes {
        return LocalBridgeOutcome::Refused(format!(
            "imported-local list file {} is {} bytes (max {max_body_bytes} bytes)",
            on_disk.display(),
            metadata.len()
        ));
    }

    match std::fs::read_to_string(&on_disk) {
        Ok(body) => LocalBridgeOutcome::Loaded {
            body,
            path: on_disk,
        },
        Err(e) => LocalBridgeOutcome::Refused(format!(
            "imported-local list file {} read failed: {e}",
            on_disk.display()
        )),
    }
}

/// rev-2606 §06 `source_key-02`: resolve the bearer token for a fetch
/// `source`. The token map is keyed by the legacy slash-form blocklist id, so
/// a pure-v1 `[[blocklists]]` row — whose `source` string is the raw URL —
/// misses [`SourceTokenMap::token_for_url`]. On a miss, fall back through the
/// `source_to_blocklist` reverse map (raw URL / slash / canonical id →
/// canonical `Id`) to [`SourceTokenMap::token_for_v1_id`], so an
/// `auth_token_ref` list gets its `Authorization: Bearer` header instead of
/// fetching anonymously. Returns a borrow of the token (lifetime tied to
/// `tokens`); the caller copies it into the header before any later borrow.
fn resolve_bearer_token<'a>(
    tokens: &'a SourceTokenMap,
    source_to_blocklist: &HashMap<String, (crate::config::schema::Id, u32)>,
    source: &str,
) -> Option<&'a str> {
    tokens.token_for_url(source).or_else(|| {
        source_to_blocklist
            .get(source)
            .and_then(|(id, _)| tokens.token_for_v1_id(id))
    })
}

/// Extract the last path segment of an `imported.local` URL — that's the
/// list id (with whatever extension T3 wrote). Returns `None` for empty
/// or root-only paths.
///
/// `Url::parse` always normalises an empty path to `/`, so a
/// well-formed `imported.local` URL produces at least `"/"` here. We
/// reject the no-segment case explicitly so a typo
/// (`https://imported.local/` with no id) surfaces as a refusal rather
/// than reading from `<config_dir>/lists/` itself.
fn imported_local_id_from_path(path: &str) -> Option<String> {
    let trimmed = path.trim_start_matches('/');
    // Reject sub-paths — a single segment is the contract. rev-2606 §06
    // roundup nit: explicitly reject a `..` segment so non-traversal is a
    // property of this function, not merely of "directories aren't readable
    // as files" (a bare `..` resolves to `<config_dir>/lists/..` = the config
    // dir; the read happens to fail today only because it is a directory).
    if trimmed.is_empty() || trimmed.contains('/') || trimmed == ".." {
        return None;
    }
    Some(trimmed.to_string())
}

/// lane-C 2026-08-17: cheap identity of an `imported.local` blocklist's
/// on-disk file, used to detect operator edits that `[[blocklists]]`
/// itself never records — the URL, `kind` and `trust` on that row do not
/// change when the operator edits the file's *content*.
///
/// `mtime` + `size` is the prefilter every one of the three external
/// reviewers this sprint's design doc consulted converged on
/// (`_docs/features/consult_2608_five_decisions.md` §4): cheap, and a
/// content hash of an operator-authored allow/deny list buys nothing a
/// timestamp does not already tell you. `inode` catches the case
/// `mtime`+`size` cannot: many editors save via write-temp-then-rename,
/// which can reuse the same mtime+size on a genuinely different file
/// (e.g. a symlink swap or an atomic replace) — the inode changes even
/// when both do not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LocalFileStamp {
    mtime_nanos: i128,
    size: u64,
    inode: u64,
}

/// Resolve the on-disk path an `imported.local` URL reads from, without
/// touching the filesystem — the same derivation
/// [`try_bridge_imported_local`] uses, kept separate rather than shared
/// so this stays a pure path computation callable from a fingerprint
/// (which must not itself read the file the way the bridge does).
fn imported_local_disk_path(url: &str, config_dir: &Path) -> Option<PathBuf> {
    let parsed = reqwest::Url::parse(url).ok()?;
    if parsed.host_str() != Some(IMPORTED_LOCAL_HOST) {
        return None;
    }
    let id_with_ext = imported_local_id_from_path(parsed.path())?;
    Some(config_dir.join("lists").join(id_with_ext))
}

/// Stamp a `trust = local` blocklist row's on-disk file — `None` for any
/// row that is not an `imported.local` source (nothing to stat) or whose
/// file is currently unreadable (missing, permission denied): a missing
/// file stamps the same as "not a local source", and the transition
/// FROM a real stamp TO `None` (or back) still changes the fingerprint,
/// which is the behaviour that matters — a file that just disappeared
/// must still invalidate the reuse gate so the next cycle's refusal (via
/// [`try_bridge_imported_local`]'s existing "not readable" path) is not
/// hidden behind a stale "nothing changed" skip.
pub(crate) fn stat_local_source(url: &str, config_dir: &Path) -> Option<LocalFileStamp> {
    use std::os::unix::fs::MetadataExt;
    let path = imported_local_disk_path(url, config_dir)?;
    let meta = std::fs::metadata(&path).ok()?;
    Some(LocalFileStamp {
        mtime_nanos: i128::from(meta.mtime()) * 1_000_000_000 + i128::from(meta.mtime_nsec()),
        size: meta.size(),
        inode: meta.ino(),
    })
}

/// §4.7 Phase 2 T1 helper: receive from an optional `mpsc::Receiver`,
/// or wait forever if the channel was never wired. Used inside
/// `tokio::select!` so the `cmd_rx`-less code path (tests / ephemeral
/// runs) does not spin.
///
/// Cancel-safe: both `Receiver::recv` and `std::future::pending` are
/// safe to drop mid-await, which is what `tokio::select!` does when
/// the other branch wins.
async fn recv_or_pending(
    rx: &mut Option<mpsc::Receiver<ListManagerCommand>>,
) -> Option<ListManagerCommand> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

/// Turn a `reqwest::Error` into a diagnosis-friendly string.
///
/// Before this, every transport failure — a dead host, a proxy fault, and a
/// slow peer timing out under load — rendered as the same opaque
/// `"error sending request for url ..."` text (`reqwest::Error`'s `Display`
/// doesn't surface its cause). That ambiguity cost real diagnosis time
/// during the 2026-07-23 `lists.purge.cc` outage. This walks the error's
/// source chain to label the concrete cause up front; the original
/// `reqwest::Error` text is still appended so nothing is lost.
pub(crate) fn classify_fetch_error(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        // A timeout raised while the body was streaming is a different
        // diagnosis from a peer that never answered, and saying "peer did
        // not respond" of a server that answered in 120ms and then sent
        // bytes for the whole window sends the operator to inspect the
        // wrong end.
        //
        // `is_decode()` is the predicate that actually fires:
        // `read_bounded_body_bytes` reads with `Response::chunk`, and
        // reqwest re-wraps the body-timeout error through `error::decode`
        // on the way out. `is_body()` is the kind the timeout wrappers
        // themselves emit, so it is checked too — inert on this path today,
        // and the branch should not depend on which of the two survives the
        // re-wrap. A connect-phase timeout is `Kind::Request` and so keeps
        // the peer-side label below, which is correct: there, the peer
        // really did not answer.
        //
        // The wording stays neutral between the two causes on purpose: with
        // the bulk client this fires either because the transfer outran the
        // total ceiling or because the stream went idle, and those are
        // indistinguishable from the error alone. Naming only one would be
        // the same kind of confident-and-wrong this branch exists to fix.
        if e.is_decode() || e.is_body() {
            return format!(
                "timeout while streaming the response body (the transfer stalled, or did not \
                 finish before the deadline — typically a large list on a slow link): {e}"
            );
        }
        return format!(
            "timeout (peer did not respond before the deadline, e.g. overloaded or slow-path): {e}"
        );
    }
    if e.is_connect() {
        let mut cause: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(e);
        while let Some(c) = cause {
            if let Some(io_err) = c.downcast_ref::<std::io::Error>() {
                let text = io_err.to_string();
                let label = match io_err.kind() {
                    std::io::ErrorKind::ConnectionRefused => {
                        "connection refused (host up but nothing listening — proxy/upstream down)"
                    }
                    std::io::ErrorKind::TimedOut => "connect timed out",
                    _ if text.contains("lookup")
                        || text.contains("resolve")
                        || text.contains("Name or service not known")
                        || text.contains("nodename nor servname") =>
                    {
                        "DNS resolution failed (dead/unregistered host)"
                    }
                    _ => "connect error",
                };
                return format!("{label}: {e}");
            }
            cause = c.source();
        }
        return format!("connect failed, cause unavailable: {e}");
    }
    format!("error: {e}")
}

/// Errors during list download.
#[derive(Debug, thiserror::Error)]
pub enum ListError {
    #[error("download failed for {url}: {reason}")]
    Download { url: String, reason: String },
    #[error("response too large for {url}: {size} bytes (max {max} bytes)")]
    TooLarge {
        url: String,
        size: usize,
        max: usize,
    },
}

// ── Shard spill: the low-peak reload producer (§11 T3) ────────────────
//
// `refresh()` used to allocate one flat full-corpus `HashMap`, fill it from
// every source and hand it over whole — so a complete new generation and
// the outgoing one were both resident, and the box peaked at 2.02 GB
// against 780 MB steady. A flat map cannot be partitioned before it is
// fully built, so the fix has to happen in the producer:
//
//   pass 1  stream each source once, route every accepted domain to the
//           spill for `FilterEngine::shard_index(domain)` — one line plus
//           16 write buffers resident, never a map;
//   pass 2  per shard: read its spill, build ~1/16 of a generation,
//           `swap_shard`, let the displaced shard drop, move on.
//
// Peak becomes the outgoing generation (released a sixteenth at a time)
// plus the single shard in flight.

/// Directory under `cache_dir` holding the per-shard spill files.
const SHARD_SPILL_DIR: &str = ".shard";

/// Write buffering per shard spill file. 16 × 64 KiB = 1 MiB resident for
/// the whole partition pass.
const SPILL_WRITE_BUF: usize = 64 * 1024;

/// Length byte reserved to introduce a bit-change record. Unambiguous
/// because a domain record's length byte is a real domain length, and
/// `is_valid_domain` caps that far below 255.
const SPILL_BIT_TAG: u8 = 0xFF;

/// Spill file name for shard `idx`. The **only** name this module ever
/// creates or unlinks inside [`SHARD_SPILL_DIR`] — cleanup enumerates
/// these constructed names rather than deleting a directory wholesale.
fn spill_file_name(idx: usize) -> String {
    format!("shard-{idx}.spill")
}

/// Delete every spill file this module could have written under
/// `cache_dir`, then the (now empty) directory.
///
/// Deletion is by constructed name only — never `remove_dir_all`, never a
/// path derived from directory contents. A spill partition is valid solely
/// for the process that wrote it (`FilterEngine::shard_index` is seeded per
/// process via `OnceLock<RandomState>`), so one left behind by a crashed
/// daemon is silent garbage to a fresh one and must be removed, never
/// resumed. Called on manager construction *and* on every cycle entry.
fn purge_shard_spill(cache_dir: &Path) {
    let dir = cache_dir.join(SHARD_SPILL_DIR);
    if !dir.is_dir() {
        return;
    }
    for idx in 0..DOMAIN_SHARDS {
        let path = dir.join(spill_file_name(idx));
        match std::fs::remove_file(&path) {
            Ok(()) => tracing::debug!(path = %path.display(), "removed stale shard spill"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "failed to remove shard spill")
            }
        }
    }
    // Only succeeds when nothing else is in there — deliberately not
    // recursive.
    let _ = std::fs::remove_dir(&dir);
}

/// Walk one disk spill file's records, handing each `(domain, bit)` to `f`
/// in write order.
///
/// Shared by [`ShardSpill::count_unique`] and [`ShardSpill::build_shard`]
/// so the two cannot drift on the record format. That matters more than
/// ordinary de-duplication here: the counting pass decides whether a
/// corpus is installed at all and the build pass then materialises it, so
/// a decoder that disagreed by even one record would let the daemon refuse
/// a corpus it could have served, or install one that was cleared under a
/// different count.
fn read_spill_records(path: &Path, mut f: impl FnMut(&str, u64)) -> std::io::Result<()> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::with_capacity(SPILL_WRITE_BUF, file);
    let mut bit = 0u64;
    let mut len = [0u8; 1];
    let mut domain = [0u8; SPILL_BIT_TAG as usize];
    loop {
        match reader.read_exact(&mut len) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
        if len[0] == SPILL_BIT_TAG {
            let mut raw = [0u8; 8];
            reader.read_exact(&mut raw)?;
            bit = u64::from_le_bytes(raw);
            continue;
        }
        let n = len[0] as usize;
        reader.read_exact(&mut domain[..n])?;
        // Written from a `&str`, so this is UTF-8 by construction; a
        // corrupt spill is a bug in this file, not untrusted input, hence
        // the explicit error rather than a lossy conversion.
        let s = std::str::from_utf8(&domain[..n]).map_err(std::io::Error::other)?;
        f(s, bit);
    }
    Ok(())
}

/// One shard's spill file plus the bookkeeping the partition pass needs.
struct SpillWriter {
    file: std::io::BufWriter<std::fs::File>,
    /// Bytes handed to the writer so far. `BufWriter` has no `tell`, and
    /// this is the rollback anchor, so it is tracked explicitly.
    written: u64,
    /// Bit most recently written to this file, so a run of domains from
    /// one source costs one 9-byte record instead of 8 bytes per entry.
    last_bit: Option<u64>,
}

/// Where the partition pass routes accepted domains.
enum ShardSpill {
    /// Disk-backed — the configuration that reaches the §11 T3 target.
    Disk {
        dir: PathBuf,
        writers: Vec<SpillWriter>,
    },
    /// The documented fallback for `cache_dir: None` (a supported config:
    /// bodies are then kept in memory and there is no disk to spill to)
    /// and for a spill directory that cannot be created. 16 packed
    /// `Vec<(CompactString, u64)>` — no bucket waste, but the whole
    /// pre-dedup corpus is resident, so this lands near ~1.2 GB rather
    /// than ~830 MB. Correct, just not the win.
    Memory {
        buckets: Vec<Vec<(CompactString, u64)>>,
    },
}

impl ShardSpill {
    /// Open a spill for this cycle. Falls back to [`ShardSpill::Memory`]
    /// when there is no cache directory, or when the spill directory or
    /// any of its files cannot be created — a reload that costs more RAM
    /// beats a reload that does not happen.
    fn open(cache_dir: Option<&Path>) -> Self {
        let Some(cache_dir) = cache_dir else {
            return Self::memory();
        };
        let dir = cache_dir.join(SHARD_SPILL_DIR);
        if let Err(e) = std::fs::create_dir_all(&dir) {
            tracing::warn!(
                path = %dir.display(),
                error = %e,
                "cannot create shard spill dir, falling back to in-memory partition (higher reload peak)"
            );
            return Self::memory();
        }
        let mut writers = Vec::with_capacity(DOMAIN_SHARDS);
        for idx in 0..DOMAIN_SHARDS {
            let path = dir.join(spill_file_name(idx));
            match std::fs::File::create(&path) {
                Ok(file) => writers.push(SpillWriter {
                    file: std::io::BufWriter::with_capacity(SPILL_WRITE_BUF, file),
                    written: 0,
                    last_bit: None,
                }),
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "cannot create shard spill file, falling back to in-memory partition (higher reload peak)"
                    );
                    drop(writers);
                    purge_shard_spill(cache_dir);
                    return Self::memory();
                }
            }
        }
        Self::Disk { dir, writers }
    }

    fn memory() -> Self {
        Self::Memory {
            buckets: (0..DOMAIN_SHARDS).map(|_| Vec::new()).collect(),
        }
    }

    /// True when this cycle is spilling to disk (i.e. is on the low-peak
    /// path). Reported once per reload so an operator can tell which
    /// regime produced the numbers in the log.
    fn is_disk(&self) -> bool {
        matches!(self, Self::Disk { .. })
    }

    /// Snapshot each shard's current extent, for [`Self::rollback`].
    fn mark(&self) -> Vec<u64> {
        match self {
            Self::Disk { writers, .. } => writers.iter().map(|w| w.written).collect(),
            Self::Memory { buckets } => buckets.iter().map(|b| b.len() as u64).collect(),
        }
    }

    /// Discard everything written since `mark`.
    ///
    /// This is what makes a mid-stream failure equivalent to the old
    /// `read_to_string` behaviour. `read_to_string` failed *before* the
    /// parse, so nothing was ever mutated on error; streaming fails
    /// *during*, so without this a truncated body would leave a partial
    /// ingest behind and could read as a legitimate sub-threshold shrink —
    /// ratcheting the retention guard's baseline down on a supply-chain
    /// failure. Rolling back restores the old all-or-nothing invariant
    /// instead of inventing accounting for a state that used to be
    /// unreachable.
    fn rollback(&mut self, mark: &[u64]) -> std::io::Result<()> {
        match self {
            Self::Disk { writers, .. } => {
                for (w, &offset) in writers.iter_mut().zip(mark) {
                    w.file.flush()?;
                    let f = w.file.get_mut();
                    f.set_len(offset)?;
                    // `set_len` truncates but leaves the cursor where it
                    // was; without the seek the next write would open a
                    // hole of zero bytes past the truncation point.
                    f.seek(std::io::SeekFrom::Start(offset))?;
                    w.written = offset;
                    // The bit-change record for the rolled-back source may
                    // itself be gone; forget it so the next source re-emits.
                    w.last_bit = None;
                }
            }
            Self::Memory { buckets } => {
                for (b, &len) in buckets.iter_mut().zip(mark) {
                    b.truncate(len as usize);
                }
            }
        }
        Ok(())
    }

    /// Route one accepted domain to its shard.
    ///
    /// The shard is chosen by [`FilterEngine::shard_index`] and nothing
    /// else — the engine probes with the same function, and any second
    /// implementation of `hash % 16` would disagree with it silently.
    fn push(&mut self, domain: &str, bit: u64) -> std::io::Result<()> {
        let idx = FilterEngine::shard_index(domain);
        match self {
            Self::Disk { writers, .. } => {
                let w = &mut writers[idx];
                if w.last_bit != Some(bit) {
                    w.file.write_all(&[SPILL_BIT_TAG])?;
                    w.file.write_all(&bit.to_le_bytes())?;
                    w.written += 9;
                    w.last_bit = Some(bit);
                }
                let bytes = domain.as_bytes();
                // `is_valid_domain` already bounds this well under the
                // 0xFF sentinel; the guard documents the invariant rather
                // than trusting it silently.
                debug_assert!(bytes.len() < SPILL_BIT_TAG as usize);
                w.file.write_all(&[bytes.len() as u8])?;
                w.file.write_all(bytes)?;
                w.written += 1 + bytes.len() as u64;
            }
            Self::Memory { buckets } => {
                buckets[idx].push((CompactString::new(domain), bit));
            }
        }
        Ok(())
    }

    /// Flush every write buffer. Must run once between the two passes —
    /// pass 2 reopens the files for reading.
    fn flush(&mut self) -> std::io::Result<()> {
        if let Self::Disk { writers, .. } = self {
            for w in writers {
                w.file.flush()?;
            }
        }
        Ok(())
    }

    /// Count shard `idx`'s **deduplicated** domains without consuming it.
    ///
    /// This is the quantity the global corpus guard enforces on, and it has
    /// to be available before pass 2 installs anything. Pass 2 builds *and
    /// installs* one shard at a time — that is the whole point of the
    /// sharded producer — so by the time a post-loop check could observe
    /// the true unique total, all 16 shards are already live and "refuse
    /// the cycle, keep the previous generation" is no longer on the table.
    ///
    /// Takes `&self` deliberately. [`Self::build_shard`] is destructive: it
    /// `remove_file`s the spill it consumed and `mem::take`s the memory
    /// bucket. A shared borrow makes the second of those impossible to
    /// write here rather than merely discouraged, and the first is simply
    /// absent. `novel_by_bit` is the caller's own array — it must never be
    /// `build_shard`'s `added_by_bit`, which feeds each source's reported
    /// `entries`.
    ///
    /// Dedups on `hash_one(domain)` into a `HashSet<u64, RandomState>`, the
    /// idiom [`ShardSpillSink`] already documents: hashes rather than
    /// domains, so the peak is ~9 B per distinct domain for one shard at a
    /// time, and a 64-bit collision would undercount by one against a
    /// multi-million-entry ceiling — unobservable.
    ///
    /// `novel_by_bit` accumulates first-occurrence-in-spill-order counts,
    /// exactly as `build_shard` does. That makes it **order-dependent**: a
    /// domain shared by two sources is attributed wholly to whichever
    /// merged first. It is a diagnostic for "which list would free the most
    /// room", never an input to the enforcement decision, which stays on
    /// the order-independent union total this returns.
    fn count_unique(&self, idx: usize, novel_by_bit: &mut [u64; 64]) -> std::io::Result<u64> {
        let hasher = RandomState::new();
        let mut seen: HashSet<u64, RandomState> = HashSet::with_hasher(RandomState::new());

        let mut observe = |domain: &str, bit: u64, seen: &mut HashSet<u64, RandomState>| {
            if seen.insert(hasher.hash_one(domain)) {
                if let Some(slot) = novel_by_bit.get_mut(bit.trailing_zeros() as usize) {
                    *slot += 1;
                }
            }
        };

        match self {
            Self::Disk { dir, .. } => {
                // Deliberately no `remove_file` afterwards: pass 2 still
                // has to read this. See the `&self` note above.
                read_spill_records(&dir.join(spill_file_name(idx)), |s, bit| {
                    observe(s, bit, &mut seen);
                })?;
            }
            Self::Memory { buckets } => {
                // Deliberately by reference, never `mem::take`.
                for (domain, bit) in &buckets[idx] {
                    observe(domain, *bit, &mut seen);
                }
            }
        }

        Ok(seen.len() as u64)
    }

    /// Build shard `idx`'s slice of the new generation and hand it over.
    ///
    /// `added_by_bit` accumulates, per list bit, the number of domains
    /// whose *first* occurrence in spill order belongs to that bit. Spill
    /// order is source-iteration order, so that count is exactly the
    /// `merged.len()` delta the flat producer reported as a source's
    /// `entries` — reconstructed without ever holding the flat map.
    ///
    /// `policy` is the direction map of the generation being published, and
    /// is handed in rather than derived so every shard of one cycle carries
    /// the **same** `Arc` — see `ListPolicy` for why the pairing matters.
    fn build_shard(
        &mut self,
        idx: usize,
        capacity: usize,
        added_by_bit: &mut [u64; 64],
        policy: &Arc<ListPolicy>,
    ) -> std::io::Result<SortedShard> {
        // Raw pushes, duplicates included — the same domain arrives once per
        // source that carries it. `capacity` is the DISTINCT count from the
        // corpus guard, so this may grow past it before the dedup below;
        // `from_sorted_entries` returns the slack when it boxes.
        //
        // neutrality-06: direction is a per-source property, so a bit is
        // either allow-direction or block-direction for every domain it
        // tags. That routing used to happen here, stamping each entry with a
        // `DomainMasks` pair; it now happens at probe time from the shard's
        // policy, which is why only the raw source bit is stored. The
        // spill record format is unchanged either way. Before neutrality-06
        // every entry was stamped `block_only`, which made a `base = allow`
        // list *block* the domains it was imported to permit.
        let mut raw: Vec<(CompactString, u64)> = Vec::with_capacity(capacity);

        match self {
            Self::Disk { dir, .. } => {
                let path = dir.join(spill_file_name(idx));
                read_spill_records(&path, |s, bit| raw.push((CompactString::new(s), bit)))?;
                // Release the disk as we go, so a 16-shard corpus never
                // keeps 16 spills alive once the first is consumed. The
                // reader is dropped inside `read_spill_records`.
                if let Err(e) = std::fs::remove_file(&path) {
                    tracing::warn!(path = %path.display(), error = %e, "failed to remove consumed shard spill");
                }
            }
            Self::Memory { buckets } => {
                // `take` frees this bucket as the shard is built, so the
                // packed vectors are released a sixteenth at a time too.
                raw.extend(std::mem::take(&mut buckets[idx]));
            }
        }

        // STABLE sort, load-bearing. `added_by_bit` credits a domain's FIRST
        // occurrence in spill order, and spill order is source-iteration
        // order, so the count must equal the `merged.len()` delta the flat
        // producer reported as that source's `entries`. `sort_by` preserves
        // the original order within a run of equal domains, so the run's
        // first element IS the first occurrence. `sort_unstable_by` is
        // faster, compiles, passes every type check — and silently credits
        // an arbitrary source. Do not "optimise" it.
        raw.sort_by(|a, b| a.0.cmp(&b.0));

        // Credit BETWEEN the sort and the dedup, and neither side is
        // arbitrary: after the OR-merge below the survivor carries every
        // source's bits, so "which bit first introduced this domain" is no
        // longer recoverable from it; before the sort the equal domains are
        // not yet adjacent, so a run start cannot be identified at all.
        for i in 0..raw.len() {
            if i == 0 || raw[i].0 != raw[i - 1].0 {
                if let Some(slot) = added_by_bit.get_mut(raw[i].1.trailing_zeros() as usize) {
                    *slot += 1;
                }
            }
        }

        // `dedup_by` passes the pair in reverse slice order and drops `a`, so
        // `b` is the earlier element and survives — OR the later bits into it.
        raw.dedup_by(|a, b| {
            if a.0 == b.0 {
                b.1 |= a.1;
                true
            } else {
                false
            }
        });

        // A refusal here lands in `build_shard`'s existing `Err` arm at the
        // call site, which keeps this shard's previous generation, marks the
        // cycle degraded and continues with the remaining shards. That is
        // deliberate rather than a fallback: the spill this shard was built
        // from has already been consumed (`remove_file` / `mem::take` above),
        // so the shard cannot be rebuilt within the cycle at any price, and a
        // degraded cycle withholds its digest so the next one rebuilds.
        SortedShard::from_sorted_entries(raw, Arc::clone(policy))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

/// Hard cap on a cold-start install that is over `max_total_domains`:
/// **twice** the operator's ceiling, as a `u128` so no configured value
/// can overflow the comparison.
///
/// Why 2×. **The constant is unchanged; its justification was rebuilt by
/// `mem-t6` and the old one is preserved below because it is the more
/// instructive half.**
///
/// *Today, under exact-size sorted shards.* Memory is linear in the entry
/// count, so "at most 2× the ceiling" means exactly "at most twice the RAM
/// the operator budgeted" — a bounded, nameable price stated in the units
/// the operator chose. That is a plainer argument than the one it replaces,
/// and it happens to license the same number.
///
/// *Before `mem-t6`, and why the reasoning mattered.* The domain map was
/// [`DOMAIN_SHARDS`] shards of power-of-two buckets held at 7/8 load, so
/// memory was a **step function** and the whole argument ran through that:
///
/// 1. **Any factor strictly inside a step bought nothing.** Levels sat at
///    fixed positions — the default 14,000,000 ceiling was picked to sit
///    just under the one at 14,680,064, where every shard's allocation
///    doubled and the map went ~690 MB → ~1.37 GB. A corpus at 1.4× and
///    one at 1.6× of some ceiling routinely landed on the same level and
///    cost the same bytes.
///
/// 2. **`n → 2n` advanced the level by exactly one**, for every `n`, so 2×
///    was "at most one doubling of the budgeted footprint" — the tightest
///    factor with a structural rather than rhetorical meaning.
///
/// **Neither point survives a linear curve**, and that is the lesson worth
/// keeping: a constant whose stated reason has quietly become false is more
/// dangerous than one with no stated reason, because the next person tunes
/// against a step that is not there. Point 1 in particular *inverts* — under
/// a linear curve, refusing between 1.4× and 1.6× does save proportional
/// bytes.
///
/// **The 2026-08-05 incident still indicts the old behaviour**, on
/// arithmetic rather than on levels: 14,359,682 unique against a 14,000,000
/// ceiling is 1.026×, which even under a linear curve is ~2.6 % more memory
/// — on the order of 11 MB. The daemon served 0 domains to save 11 MB. The
/// conclusion held; only the reasoning had to be re-derived.
///
/// Past 2× the overshoot stops being bounded by anything the operator chose,
/// which is a real memory ceiling and is refused as one.
///
/// This bound applies **only** when nothing is serving. With a live
/// generation to keep, the ceiling stays a hard wall at 1.0×: refusing
/// costs the operator the *new* domains, not all of them.
fn cold_start_hard_cap(ceiling: usize) -> u128 {
    ceiling as u128 * 2
}

/// What the global corpus guard decided about this cycle's spill.
///
/// The decision is taken on the **union** count, which is independent of
/// the order the sources merged in. `novel_by_bit` rides along only as an
/// operator diagnostic and must never enter the comparison — attributing
/// shared domains to whichever source happened to merge first is exactly
/// the order-dependence this guard removes.
enum CorpusVerdict {
    /// No ceiling configured, or the spill could not be counted. Install
    /// whatever pass 2 manages to build.
    Unmeasured,
    /// The corpus fits. `per_shard` carries each shard's exact unique
    /// count, which sizes pass 2's maps precisely instead of dividing the
    /// *previous* generation's size by 16.
    Install {
        unique: u64,
        per_shard: Vec<usize>,
        /// At or past 90 % of the operator's ceiling. Installs anyway —
        /// this band exists to give warning before the wall, not to be a
        /// second wall.
        warn: bool,
    },
    /// Over the ceiling, but **nothing is serving** — a cold start, where
    /// there is no previous generation for a refusal to keep. Install
    /// anyway, loudly, up to [`cold_start_hard_cap`].
    ///
    /// This variant exists so the install path can say so out loud
    /// instead of being indistinguishable from a normal one. It carries
    /// `per_shard` for the same reason [`Self::Install`] does: the
    /// counting pass already ran and its counts are exact, and a corpus
    /// that is over the ceiling is the last one that should be paying
    /// rehashes on a guessed size.
    InstallOverCeiling {
        unique: u64,
        ceiling: usize,
        per_shard: Vec<usize>,
    },
    /// Over the ceiling with a generation to keep, or past
    /// [`cold_start_hard_cap`] with none. Refuse the whole cycle.
    ///
    /// The two are one variant because the *action* is identical —
    /// build nothing, swap nothing. They are **not** one message: the
    /// refusal is reported against `serving` at the log site, because
    /// "keeping the previous generation" is the reassuring half of this
    /// sentence and is false when there is none.
    Refuse {
        unique: u64,
        ceiling: usize,
        /// Per list bit, domains whose first occurrence in spill order
        /// belongs to that bit — "which list would free the most room".
        ///
        /// Boxed: 64 counters is 512 B, and inlining that into the enum
        /// would make every verdict — overwhelmingly `Install` — pay for
        /// the rare refusal, in a value the async `refresh` future holds.
        novel_by_bit: Box<[u64; 64]>,
    },
}

/// [`DomainSink`] that partitions straight into [`ShardSpill`] and counts
/// the source's deduplicated contribution as it goes.
///
/// The dedup set is why this type exists rather than a bare closure. The
/// frozen `accept(&mut self, &str, u64) -> io::Result<()>` returns nothing,
/// so the parse skeleton cannot tell whether a domain was already seen and
/// cannot compute `ParsedCounts::unique_domains` — the metric the retention
/// guard trips on. Computing it here keeps that guard exact without
/// depending on how the sibling lane resolves the gap.
///
/// Hashes, not domains, are stored, and the set is dropped before pass 2
/// begins so it never stacks with the shard in flight. A 64-bit collision
/// would undercount by one against a percentage threshold — unobservable.
///
/// **It is ~144 MiB at the production corpus, and ~216 MiB while it grows
/// — not the "tens of MB" this comment claimed until `mem2608-s1` T5.**
/// The largest source carries ~8.4 M unique domains; hashbrown needs
/// 8.4 M ÷ 0.875 = 9.6 M slots and rounds to **16 777 216** buckets ×
/// 9 B (8 B hash + 1 B control) = 144 MiB. The step is what bites:
/// anything above 7.34 M unique in one source lands on that size. And
/// growth is allocate-rehash-then-free, so at the final step the 72 MiB
/// predecessor is still resident beside it — 216 MiB, against 220.3 MiB
/// of `VmHWM` measured on a zero-HTTP cycle (the lab host 2026-08-16).
/// That measurement is the whole finding: the understatement in this
/// comment is why nobody looked here for a month.
///
/// Two consequences, both implemented:
/// - the set is built **only where its output is read** — see
///   [`UniqueCount`]; the fresh-cache, 304 and download-failure arms
///   consult a carried-forward count instead;
/// - where it *is* built, it is sized from the previous cycle's count, so
///   the final doubling-and-rehash does not happen at all.
struct ShardSpillSink<'a> {
    spill: &'a mut ShardSpill,
    /// `None` when this source's `unique_domains` is being carried
    /// forward rather than measured. Not an empty set: an empty set would
    /// report `0`, and `0` is the shrink guard's "no baseline, accept
    /// anything" sentinel (`compute_shrink_verdict`).
    seen: Option<HashSet<u64, RandomState>>,
    hasher: RandomState,
}

impl<'a> ShardSpillSink<'a> {
    /// `capacity` is a hint from the previous cycle's count; `None` means
    /// "start empty and grow", which costs the rehash transient above.
    fn measuring(spill: &'a mut ShardSpill, capacity: Option<usize>) -> Self {
        #[cfg(test)]
        SOURCES_MEASURED.with(|c| c.set(c.get() + 1));
        let seen = match capacity {
            Some(n) => HashSet::with_capacity_and_hasher(n, RandomState::new()),
            None => HashSet::with_hasher(RandomState::new()),
        };
        Self {
            spill,
            seen: Some(seen),
            hasher: RandomState::new(),
        }
    }

    /// A sink that spills but does not count, for the arms where the body
    /// is unchanged and last cycle's count is the same number.
    fn counting_nothing(spill: &'a mut ShardSpill) -> Self {
        Self {
            spill,
            seen: None,
            hasher: RandomState::new(),
        }
    }

    /// Distinct domains accepted from this source, when measured.
    fn unique_domains(&self) -> Option<u64> {
        self.seen.as_ref().map(|s| s.len() as u64)
    }
}

impl DomainSink for ShardSpillSink<'_> {
    fn accept(&mut self, domain: &str, bit: u64) -> std::io::Result<()> {
        if let Some(seen) = self.seen.as_mut() {
            seen.insert(self.hasher.hash_one(domain));
        }
        self.spill.push(domain, bit)
    }
}

/// How a source's `unique_domains` is obtained this cycle (`mem2608-s1` T2).
///
/// The count exists for one consumer — the retention guard's baseline — and
/// only the `Fresh` (200 OK) arm consults it. The other three arms re-read a
/// body that has not changed, so measuring it again costs ~144 MiB to
/// reproduce a number the previous cycle already recorded.
///
/// **The zero is the whole reason this is a type and not a `bool`.**
/// `compute_shrink_verdict` treats `unique_domains == 0` as *no baseline —
/// accept anything*, so carrying a zero forward would silently disarm the
/// guard written after the 19 % silent-truncation incident: the next real
/// download could shrink a list by 99 % and install. [`std::num::NonZeroU64`] makes
/// that state unrepresentable rather than merely unlikely — there is no
/// constructor that carries a zero, so a future call site cannot reintroduce
/// it by forgetting a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UniqueCount {
    /// Build the dedup set. The payload sizes it from the last known count.
    Measure(Option<std::num::NonZeroU64>),
    /// Reuse a known-good count for a body that did not change.
    Carried(std::num::NonZeroU64),
}

impl UniqueCount {
    /// The last count this source reported, if it reported a usable one.
    fn prior(prev: Option<&ListStatus>) -> Option<std::num::NonZeroU64> {
        prev.and_then(|p| std::num::NonZeroU64::new(p.unique_domains))
    }

    /// For the 200-OK arm: always measure — the body is new, so no prior
    /// count describes it — but size the set from the prior count.
    fn measure(prev: Option<&ListStatus>) -> Self {
        Self::Measure(Self::prior(prev))
    }

    /// For the arms that re-read an unchanged body. Falls back to
    /// measuring when there is no usable prior, so a first cycle after a
    /// restart-with-no-stats still produces a real baseline.
    fn carry_or_measure(prev: Option<&ListStatus>) -> Self {
        match Self::prior(prev) {
            Some(n) => Self::Carried(n),
            None => Self::Measure(None),
        }
    }
}

/// §11 T5: `BufRead` adapter that SHA-256s every byte the parser actually
/// consumes, on the way past.
///
/// Content-hashing rather than trusting `ETag` / `size=` is deliberate.
/// The `.cache` directory is a trust boundary this module already worries
/// about (`cache_dir_lax_mode`); a digest built from HTTP metadata would
/// declare "nothing changed" for a locally-tampered body, which is exactly
/// the case where a skipped rebuild would pin the tampering in place.
/// Hashing the bytes costs roughly a twentieth of the parse they are being
/// fed to, so it is free in context.
struct HashingReader<R> {
    inner: R,
    hasher: sha2::Sha256,
}

impl<R: BufRead> HashingReader<R> {
    fn new(inner: R) -> Self {
        use sha2::Digest;
        Self {
            inner,
            hasher: sha2::Sha256::new(),
        }
    }

    fn finish(self) -> [u8; 32] {
        use sha2::Digest;
        self.hasher.finalize().into()
    }
}

impl<R: BufRead> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use sha2::Digest;
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

impl<R: BufRead> BufRead for HashingReader<R> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        self.inner.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        use sha2::Digest;
        // `fill_buf` is idempotent until `consume`, so re-calling it here
        // hands back the very bytes about to be consumed. `consume` cannot
        // report an error; a failure here can only mean the buffer is
        // already gone, in which case there is nothing to hash and the
        // parser is about to see the same error.
        if let Ok(buf) = self.inner.fill_buf() {
            let n = amt.min(buf.len());
            self.hasher.update(&buf[..n]);
        }
        self.inner.consume(amt);
    }
}

/// A source's cached body, opened for streaming.
///
/// The in-memory arm exists because `cache_dir: None` is a supported
/// configuration in which bodies are held in RAM and there is no disk copy
/// to stream from.
enum BodyReader {
    Memory(std::io::Cursor<String>),
    Disk(std::io::BufReader<std::fs::File>),
}

impl Read for BodyReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Memory(c) => c.read(buf),
            Self::Disk(r) => r.read(buf),
        }
    }
}

impl BufRead for BodyReader {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        match self {
            Self::Memory(c) => c.fill_buf(),
            Self::Disk(r) => r.fill_buf(),
        }
    }
    fn consume(&mut self, amt: usize) {
        match self {
            Self::Memory(c) => c.consume(amt),
            Self::Disk(r) => r.consume(amt),
        }
    }
}

#[cfg(test)]
impl ListManager {
    /// The client downloads currently go out on.
    ///
    /// Test-only, and it exists for exactly one obligation
    /// (`boot_list_persistence.md` §4.8): the **bulk** client must be in the
    /// manager's hand before the first refresh of any mode, which is an
    /// ordering property with no other observable. Behavioural discrimination
    /// would cost a 30 s test — the two clients differ only in deadlines —
    /// so the caller compares `{:?}` against a freshly built bulk client and
    /// asserts first that the two spellings differ at all.
    pub(crate) fn download_client(&self) -> &reqwest::Client {
        &self.client
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lists::catalog::Catalog;
    use crate::lists::parser::DEFAULT_MAX_LIST_ENTRIES;

    /// Generous per-test body cap (200 MB) — matches production default.
    /// Real-network tests need at least this much because the official
    /// purge.cc lists have grown past 100 MB.
    const TEST_CAP: usize = 200 * 1024 * 1024;

    /// Small cap (50 MB) for the OOM regression test — it streams 60 MB
    /// and must abort before reading the full body.
    const TEST_SMALL_CAP: usize = 50 * 1024 * 1024;

    #[test]
    fn list_cache_default_has_no_headers() {
        let cache = ListCache::default();
        assert!(cache.etag.is_none());
        assert!(cache.last_modified.is_none());
        assert!(cache.body.is_none());
    }

    #[test]
    fn min_refresh_interval_clamped() {
        let client = reqwest::Client::new();
        let filter = Arc::new(FilterEngine::new());
        let catalog = Catalog::fallback();
        let mgr = ListManager::new(
            client,
            filter,
            vec![],
            catalog,
            Duration::from_secs(0),
            SourceBitMap::default(),
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            None,
        );
        assert!(mgr.refresh_interval >= MIN_REFRESH_INTERVAL);
    }

    #[tokio::test]
    async fn refresh_with_no_sources_keeps_empty() {
        let client = reqwest::Client::new();
        let filter = Arc::new(FilterEngine::new());
        let catalog = Catalog::fallback();
        let mut mgr = ListManager::new(
            client,
            filter.clone(),
            vec![],
            catalog,
            Duration::from_secs(3600),
            SourceBitMap::default(),
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            None,
        );
        let count = mgr.refresh().await;
        assert_eq!(count, 0);
        assert_eq!(filter.domain_count(), 0);
    }

    #[tokio::test]
    async fn refresh_with_unknown_source_logs_warning() {
        let client = reqwest::Client::new();
        let filter = Arc::new(FilterEngine::new());
        let catalog = Catalog::fallback();
        let mut mgr = ListManager::new(
            client,
            filter.clone(),
            vec!["nonexistent/list".to_string()],
            catalog,
            Duration::from_secs(3600),
            SourceBitMap::default(),
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            None,
        );
        let count = mgr.refresh().await;
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn download_real_purge_cc_list() {
        let client = reqwest::Client::builder()
            .user_agent("purge-warden/test")
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap();
        let filter = Arc::new(FilterEngine::new());
        let catalog = Catalog::fallback();
        let source_bits = build_source_bit_map(&["privacy/ads".into()]).expect("at-cap accept");
        let mut mgr = ListManager::new(
            client,
            filter.clone(),
            vec!["privacy/ads".to_string()],
            catalog,
            Duration::from_secs(3600),
            source_bits,
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            None,
        );
        let count = mgr.refresh().await;
        assert!(filter.domain_count() == count);
    }

    #[tokio::test]
    async fn download_raw_url_source() {
        let client = reqwest::Client::builder()
            .user_agent("purge-warden/test")
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap();
        let filter = Arc::new(FilterEngine::new());
        let catalog = Catalog::fallback();
        let url = "https://lists.purge.cc/base_ads.txt".to_string();
        let source_bits = build_source_bit_map(std::slice::from_ref(&url)).expect("at-cap accept");
        let mut mgr = ListManager::new(
            client,
            filter.clone(),
            vec![url],
            catalog,
            Duration::from_secs(3600),
            source_bits,
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            None,
        );
        let count = mgr.refresh().await;
        assert!(filter.domain_count() == count);
    }

    #[test]
    fn build_source_bit_map_assigns_sequential_bits() {
        let sources = vec!["a".into(), "b".into(), "c".into()];
        let map = build_source_bit_map(&sources).expect("at-cap accept");
        assert_eq!(map.bit_for_url("a"), Some(0));
        assert_eq!(map.bit_for_url("b"), Some(1));
        assert_eq!(map.bit_for_url("c"), Some(2));
    }

    #[test]
    fn build_source_bit_map_accepts_at_cap_64() {
        let sources: Vec<String> = (0..64).map(|i| format!("list/{i}")).collect();
        let map = build_source_bit_map(&sources).expect("64 sources is the boundary");
        assert_eq!(map.len(), 64);
        assert_eq!(map.bit_for_url("list/0"), Some(0));
        assert_eq!(map.bit_for_url("list/63"), Some(63));
    }

    #[test]
    fn build_source_bit_map_errors_one_over_cap() {
        let sources: Vec<String> = (0..65).map(|i| format!("list/{i}")).collect();
        let err = build_source_bit_map(&sources).expect_err("65 sources exceeds u64 cap");
        let msg = err.to_string();
        assert!(
            msg.contains("65"),
            "message must report actual count: {msg}"
        );
        assert!(msg.contains("64"), "message must report cap: {msg}");
        assert!(
            msg.contains("config.toml"),
            "message must point to config.toml: {msg}"
        );
    }

    // §4.24 Phase C — `build_source_bit_map_with_v1_aliases` (May 6
    // hotfix workaround) and its two manager-level regression pins are
    // gone. Equivalent coverage now lives in
    // `src/lists/source_key.rs::tests` against the typed
    // [`SourceBitMap`] surface (`build_pure_v1_config_seeds_v1_id_alias_
    // from_blocklist`, `build_skips_disabled_blocklists`).

    // --- read_bounded_body (P0-1) ---

    /// Mock HTTP server helper used by streaming-body tests.
    ///
    /// Spawns a task that accepts one TCP connection, reads (and discards)
    /// the request, writes the given headers, then streams `total_bytes`
    /// bytes of `0x61` ('a') in 1 MiB chunks. Closes the connection when
    /// done or aborts if the client gives up.
    async fn spawn_mock_stream_server(
        headers: &'static str,
        total_bytes: usize,
    ) -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => return,
            };

            // Drain the request line + headers (enough for reqwest to be happy).
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf).await;

            if stream.write_all(headers.as_bytes()).await.is_err() {
                return;
            }

            let chunk = vec![b'a'; 1024 * 1024];
            let mut sent = 0;
            while sent < total_bytes {
                let remaining = total_bytes - sent;
                let to_send = remaining.min(chunk.len());
                if stream.write_all(&chunk[..to_send]).await.is_err() {
                    return;
                }
                sent += to_send;
            }
        });

        addr
    }

    /// Oversized body with no `Content-Length` — the historical OOM vector.
    /// The streaming reader must abort mid-stream rather than buffer all
    /// 60 MiB before checking.
    #[tokio::test]
    async fn read_bounded_body_aborts_on_oversized_stream_no_content_length() {
        // 60 MiB, no Content-Length, connection: close — server signals EOF by
        // closing the socket. `resp.text()` would have read to EOF; we must not.
        let addr = spawn_mock_stream_server(
            "HTTP/1.1 200 OK\r\n\
             Connection: close\r\n\
             Content-Type: text/plain\r\n\
             \r\n",
            60 * 1024 * 1024,
        )
        .await;

        let client = reqwest::Client::new();
        let url = format!("http://{addr}/blocklist.txt");
        let resp = client.get(&url).send().await.unwrap();
        // Use a small cap so the 60 MiB stream trips it.
        let result = read_bounded_body(resp, &url, TEST_SMALL_CAP).await;

        match result {
            Err(ListError::TooLarge { size, .. }) => {
                // We should have aborted on the first chunk past the cap,
                // not after reading all 60 MiB into memory.
                assert!(
                    size > TEST_SMALL_CAP,
                    "size {size} should exceed cap {TEST_SMALL_CAP}"
                );
                assert!(
                    size <= TEST_SMALL_CAP + 1024 * 1024,
                    "size {size} should be close to cap + one chunk (not the full 60 MiB)"
                );
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    /// Small body well under the cap — happy path.
    #[tokio::test]
    async fn read_bounded_body_accepts_small_body() {
        // 1 KiB body — trivially under the cap.
        let headers = "HTTP/1.1 200 OK\r\n\
                       Content-Length: 1024\r\n\
                       Content-Type: text/plain\r\n\
                       \r\n";
        let addr = spawn_mock_stream_server(headers, 1024).await;

        let client = reqwest::Client::new();
        let url = format!("http://{addr}/blocklist.txt");
        let resp = client.get(&url).send().await.unwrap();
        let body = read_bounded_body(resp, &url, TEST_CAP).await.unwrap();
        assert_eq!(body.len(), 1024);
        assert!(body.chars().all(|c| c == 'a'));
    }

    /// M-22: a `Content-Length` larger than `max_bytes` must NOT translate
    /// into a `Vec::with_capacity(huge)` — the hint is clamped to `max_bytes`
    /// before pre-allocation. The streaming bound then trips on actual
    /// chunks. Server announces a body 4× the cap and streams accordingly;
    /// the abort comes from the streaming check, not from an OOM allocation.
    #[tokio::test]
    async fn read_bounded_body_clamps_oversized_content_length_hint() {
        let oversized = TEST_SMALL_CAP * 4;
        let headers = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Length: {oversized}\r\n\
             Content-Type: text/plain\r\n\
             \r\n",
        );
        // SAFETY: tests Box::leak the format!()-d header so spawn_mock_stream_server
        // can take a 'static str. Test-only; one allocation per test invocation.
        let headers_static: &'static str = Box::leak(headers.into_boxed_str());
        let addr = spawn_mock_stream_server(headers_static, oversized).await;

        let client = reqwest::Client::new();
        let url = format!("http://{addr}/blocklist.txt");
        let resp = client.get(&url).send().await.unwrap();
        let result = read_bounded_body(resp, &url, TEST_SMALL_CAP).await;
        match result {
            Err(ListError::TooLarge { size, max, .. }) => {
                assert_eq!(max, TEST_SMALL_CAP);
                assert!(
                    size > TEST_SMALL_CAP,
                    "size {size} should exceed cap {TEST_SMALL_CAP}"
                );
            }
            other => panic!("expected TooLarge for oversized Content-Length stream, got {other:?}"),
        }
    }

    /// Mock server variant that streams a fixed raw-byte payload once, then
    /// closes. Unlike [`spawn_mock_stream_server`] (which only sends `'a'`),
    /// this lets a test deliver bytes that are NOT valid UTF-8.
    async fn spawn_mock_bytes_server(payload: &'static [u8]) -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => return,
            };
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf).await;
            let header = format!(
                "HTTP/1.1 200 OK\r\n\
                 Connection: close\r\n\
                 Content-Length: {}\r\n\
                 Content-Type: text/plain\r\n\
                 \r\n",
                payload.len()
            );
            if stream.write_all(header.as_bytes()).await.is_err() {
                return;
            }
            let _ = stream.write_all(payload).await;
        });

        addr
    }

    /// A single invalid UTF-8 byte must NOT fail the whole download (the
    /// prior strict `from_utf8` behaviour). Lossy decode turns the bad byte
    /// into U+FFFD, so only the line carrying it is dropped by
    /// `is_valid_domain` — the rest of the list still blocks. "One bad byte
    /// costs one domain, not the list."
    #[tokio::test]
    async fn read_bounded_body_lossy_keeps_list_on_bad_byte() {
        // 0xFF is invalid UTF-8. Line 1 is a clean domain; line 2 carries the
        // bad byte at its head.
        let addr = spawn_mock_bytes_server(b"good.com\n\xFFbad.example\n").await;

        let client = reqwest::Client::new();
        let url = format!("http://{addr}/blocklist.txt");
        let resp = client.get(&url).send().await.unwrap();

        // Does NOT error — strict `String::from_utf8` would have failed here.
        let body = read_bounded_body(resp, &url, TEST_CAP).await.unwrap();
        assert!(
            body.contains('\u{FFFD}'),
            "bad byte should decode to U+FFFD"
        );

        // Blast radius is one line: good.com survives, the U+FFFD-mangled
        // line is rejected by is_valid_domain.
        let parsed = crate::lists::parser::parse_domain_list(&body);
        assert!(parsed.contains("good.com"), "clean domain must survive");
        assert_eq!(parsed.len(), 1, "only the clean domain should parse");
    }

    /// Invalid URL validation at the pre-flight step. Ensures private-IP
    /// literal URLs are rejected by `download_list` before any HTTP is sent.
    #[tokio::test]
    async fn download_list_rejects_loopback_literal() {
        let catalog = Catalog::fallback();
        let filter = Arc::new(FilterEngine::new());
        let url = "https://127.0.0.1/blocklist.txt".to_string();
        let source_bits = build_source_bit_map(std::slice::from_ref(&url)).expect("at-cap accept");
        let mut mgr = ListManager::new(
            reqwest::Client::new(),
            filter.clone(),
            vec![url],
            catalog,
            Duration::from_secs(3600),
            source_bits,
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            None,
        );
        // refresh() does not propagate per-URL errors; it logs and continues.
        // So we assert that the download fails by observing zero domains
        // merged (the only source was rejected).
        let count = mgr.refresh().await;
        assert_eq!(count, 0);
        assert_eq!(filter.domain_count(), 0);
    }

    /// `http://` URLs are rejected by the pre-flight scheme check.
    #[tokio::test]
    async fn download_list_rejects_http_scheme() {
        let catalog = Catalog::fallback();
        let filter = Arc::new(FilterEngine::new());
        let url = "http://lists.purge.cc/base_ads.txt".to_string();
        let source_bits = build_source_bit_map(std::slice::from_ref(&url)).expect("at-cap accept");
        let mut mgr = ListManager::new(
            reqwest::Client::new(),
            filter.clone(),
            vec![url],
            catalog,
            Duration::from_secs(3600),
            source_bits,
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            None,
        );
        let count = mgr.refresh().await;
        assert_eq!(count, 0);
    }

    // --- disk cache ---

    #[test]
    fn source_to_cache_stem_catalog_id() {
        // Stem now ends with `-<hash8>` (T3.4 M-23). The sanitised prefix is
        // preserved verbatim; only the suffix is new.
        let privacy = source_to_cache_stem("privacy/ads");
        assert!(privacy.starts_with("privacy_ads-"), "got {privacy}");
        let suffix = privacy.strip_prefix("privacy_ads-").unwrap();
        assert_eq!(suffix.len(), 8);
        assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));

        let security = source_to_cache_stem("security/malicious");
        assert!(
            security.starts_with("security_malicious-"),
            "got {security}"
        );
    }

    #[test]
    fn source_to_cache_stem_raw_url() {
        let stem = source_to_cache_stem("https://lists.purge.cc/ads.txt");
        assert!(
            stem.starts_with("https___lists.purge.cc_ads.txt-"),
            "got {stem}"
        );
        // No path separators or colons — safe as a filename
        assert!(!stem.contains('/'));
        assert!(!stem.contains(':'));
    }

    /// M-23: two distinct sources whose sanitised forms collide must
    /// produce distinct stems. Pre-fix `https://a.example/list.txt` and
    /// `https://b.example/list.txt` sanitised to different stems already,
    /// but `privacy/ads` and `privacy@ads` BOTH sanitised to `privacy_ads`
    /// and silently overwrote each other on disk. The hash suffix breaks
    /// the collision by keying on the original (un-sanitised) bytes.
    #[test]
    fn source_to_cache_stem_disambiguates_sanitisation_collisions() {
        let a = source_to_cache_stem("privacy/ads");
        let b = source_to_cache_stem("privacy@ads");
        let c = source_to_cache_stem("privacy:ads");
        // All sanitise to the same prefix...
        assert!(a.starts_with("privacy_ads-"));
        assert!(b.starts_with("privacy_ads-"));
        assert!(c.starts_with("privacy_ads-"));
        // ...but the suffixes disambiguate.
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    /// M-23: same source must always produce the same stem (deterministic
    /// across binaries). SHA-256 is stable; `Hasher::default()` is not.
    #[test]
    fn source_to_cache_stem_is_deterministic() {
        let a = source_to_cache_stem("privacy/ads");
        let b = source_to_cache_stem("privacy/ads");
        assert_eq!(a, b);
    }

    // ── is_cache_fresh (s24 Phase 1.2) ────────────────────────────

    #[test]
    fn is_cache_fresh_recent_entry_is_fresh() {
        let now = OffsetDateTime::now_utc();
        let just_now = now - time::Duration::seconds(30);
        assert!(is_cache_fresh(just_now, now, Duration::from_secs(3600)));
    }

    #[test]
    fn is_cache_fresh_old_entry_is_stale() {
        let now = OffsetDateTime::now_utc();
        let two_hours_ago = now - time::Duration::hours(2);
        assert!(!is_cache_fresh(
            two_hours_ago,
            now,
            Duration::from_secs(3600)
        ));
    }

    #[test]
    fn is_cache_fresh_at_exact_interval_is_stale() {
        // Boundary: age == interval → stale, so a refresh fires
        // exactly at the interval mark instead of one cycle later.
        let now = OffsetDateTime::now_utc();
        let one_hour_ago = now - time::Duration::hours(1);
        assert!(!is_cache_fresh(
            one_hour_ago,
            now,
            Duration::from_secs(3600)
        ));
    }

    /// `mem2608-t0`, the unit half. A tick one full interval after the
    /// cycle that stamped the body must find it stale — including when
    /// the stamp is a hair short of a full interval old, which is the only
    /// case production ever produces.
    ///
    /// `is_cache_fresh_at_exact_interval_is_stale` above pins `age ==
    /// interval`, an instant the daemon cannot reach: the anchor is read
    /// after the tick fires, so the age is always `interval − δ`. That
    /// test was green for the whole time the defect was live.
    #[test]
    fn is_cache_fresh_a_hair_under_the_interval_is_stale() {
        let now = OffsetDateTime::now_utc();
        let interval = Duration::from_secs(43_200);
        for short_by_ms in [1i64, 900, 2_000, 4_999] {
            let fetched_at =
                now - time::Duration::seconds(43_200) + time::Duration::milliseconds(short_by_ms);
            assert!(
                !is_cache_fresh(fetched_at, now, interval),
                "a body {short_by_ms} ms short of a full interval read as fresh — this is the \
                 tick that can never fetch"
            );
        }
    }

    /// The margin shortens a cycle; it must not collapse one. At the
    /// tightest interval the config accepts, a body from the middle of the
    /// previous cycle is still fresh.
    #[test]
    fn is_cache_fresh_margin_does_not_swallow_the_minimum_interval() {
        let now = OffsetDateTime::now_utc();
        let half_a_minimum = now - time::Duration::seconds(30);
        assert!(is_cache_fresh(half_a_minimum, now, MIN_REFRESH_INTERVAL));
    }

    /// A margin at or above the interval must not invert the predicate
    /// into "always fresh" — saturating, not wrapping.
    #[test]
    fn is_cache_fresh_degenerate_interval_never_reads_fresh() {
        let now = OffsetDateTime::now_utc();
        let a_moment_ago = now - time::Duration::milliseconds(1);
        assert!(!is_cache_fresh(
            a_moment_ago,
            now,
            CACHE_FRESHNESS_MARGIN / 2
        ));
    }

    #[test]
    fn is_cache_fresh_future_timestamp_is_stale() {
        // Clock skew or corrupt meta file: fetched_at in the future
        // must NOT freeze updates. Treat as stale to force a fetch.
        let now = OffsetDateTime::now_utc();
        let in_an_hour = now + time::Duration::hours(1);
        assert!(!is_cache_fresh(in_an_hour, now, Duration::from_secs(3600)));
    }

    // ── atomic_write (s24 Phase 1.2) ──────────────────────────────

    #[test]
    fn atomic_write_writes_through_tmp_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("data.cache");
        atomic_write(&target, b"hello").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "hello");
        // Tmp file should be gone after a successful rename.
        assert!(!dir.path().join("data.cache.tmp").exists());
    }

    #[test]
    fn atomic_write_overwrites_existing_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("data.cache");
        std::fs::write(&target, "old").unwrap();
        atomic_write(&target, b"new").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "new");
    }

    #[test]
    fn meta_file_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let source = "privacy/ads";
        let stamp = OffsetDateTime::now_utc();
        write_cache_to_disk(
            dir.path(),
            source,
            "example.com\nads.tracker.io\n",
            Some("W/\"abc123\""),
            Some("Thu, 10 Apr 2026 12:00:00 GMT"),
            stamp,
        );

        let stem = source_to_cache_stem(source);
        let cache_path = dir.path().join(format!("{stem}.cache"));
        let meta_path = dir.path().join(format!("{stem}.meta"));

        assert!(cache_path.exists());
        assert!(meta_path.exists());

        let body = std::fs::read_to_string(&cache_path).unwrap();
        assert_eq!(body, "example.com\nads.tracker.io\n");

        let parsed = load_meta_file(&meta_path);
        assert_eq!(parsed.etag.as_deref(), Some("W/\"abc123\""));
        assert_eq!(
            parsed.last_modified.as_deref(),
            Some("Thu, 10 Apr 2026 12:00:00 GMT")
        );
        // RFC 3339 round-trip preserves second-precision; the time
        // crate's default OffsetDateTime is nanosecond, so we compare
        // via re-formatting both sides through RFC 3339 to drop
        // sub-second noise that the on-disk format does not carry
        // (the formatter does, but parser keeps it). Asserting the
        // re-parsed value equals the formatted-then-parsed version is
        // the cleanest round-trip pin.
        let parsed_ts = parsed
            .fetched_at
            .expect("fetched_at must be present after a Phase-1.1 write");
        let stamp_str = stamp.format(&Rfc3339).unwrap();
        let stamp_round = OffsetDateTime::parse(&stamp_str, &Rfc3339).unwrap();
        assert_eq!(parsed_ts, stamp_round);
    }

    #[test]
    fn meta_file_missing_returns_empty() {
        let parsed = load_meta_file(Path::new("/nonexistent/path.meta"));
        assert!(parsed.etag.is_none());
        assert!(parsed.last_modified.is_none());
        assert!(parsed.fetched_at.is_none());
    }

    #[test]
    fn meta_file_empty_values() {
        let dir = tempfile::tempdir().unwrap();
        let meta_path = dir.path().join("test.meta");
        std::fs::write(&meta_path, "etag=\nlast-modified=\nfetched-at=\n").unwrap();

        let parsed = load_meta_file(&meta_path);
        assert!(parsed.etag.is_none(), "empty etag should be None");
        assert!(
            parsed.last_modified.is_none(),
            "empty last-modified should be None"
        );
        assert!(
            parsed.fetched_at.is_none(),
            "empty fetched-at should be None"
        );
    }

    #[test]
    fn build_meta_content_strips_control_chars_from_header_values() {
        // rev-2606 §06 manager-04a: a newline smuggled into an ETag must
        // not forge an extra .meta line. The line-oriented parser must see
        // exactly four logical fields, none of them an injected size= /
        // fetched-at=.
        let now = OffsetDateTime::now_utc();
        let hostile_etag = "\"abc\"\nsize=999999999\nfetched-at=2000-01-01T00:00:00Z";
        let content = build_meta_content(
            Some(hostile_etag),
            Some("Mon,\r\n01 Jan 2024"),
            now,
            Some(42),
        );
        // Round-trip through the real parser: the forged values must NOT
        // take effect.
        let dir = tempfile::tempdir().unwrap();
        let meta_path = dir.path().join("hostile.meta");
        std::fs::write(&meta_path, &content).unwrap();
        let parsed = load_meta_file(&meta_path);
        assert_eq!(
            parsed.size,
            Some(42),
            "the real size= line must win, not the injected one"
        );
        assert_eq!(
            parsed.etag.as_deref(),
            Some("\"abc\"size=999999999fetched-at=2000-01-01T00:00:00Z"),
            "control chars stripped, value flattened onto one line"
        );
        // The legitimate fetched-at must parse (the forged one was inert).
        assert!(parsed.fetched_at.is_some());
        // No raw control byte survived into the file.
        assert!(!content.bytes().any(|b| b == b'\r'));
    }

    #[test]
    fn meta_file_legacy_format_has_no_fetched_at() {
        // Pre-Sprint-24 .meta files only have etag + last-modified lines.
        // load_meta_file must parse them without losing the existing
        // fields and return fetched_at = None so the load_disk_cache
        // path can fall back to now_utc() instead of crashing.
        let dir = tempfile::tempdir().unwrap();
        let meta_path = dir.path().join("legacy.meta");
        std::fs::write(
            &meta_path,
            "etag=\"old\"\nlast-modified=Thu, 01 Jan 1970 00:00:00 GMT\n",
        )
        .unwrap();

        let parsed = load_meta_file(&meta_path);
        assert_eq!(parsed.etag.as_deref(), Some("\"old\""));
        assert_eq!(
            parsed.last_modified.as_deref(),
            Some("Thu, 01 Jan 1970 00:00:00 GMT")
        );
        assert!(
            parsed.fetched_at.is_none(),
            "legacy meta has no fetched-at line"
        );
    }

    #[test]
    fn meta_file_invalid_fetched_at_is_ignored() {
        // Garbage in the fetched-at field must not crash parsing —
        // load_meta_file logs a warning and returns None for that
        // field, leaving the other fields intact.
        let dir = tempfile::tempdir().unwrap();
        let meta_path = dir.path().join("bad.meta");
        std::fs::write(
            &meta_path,
            "etag=\"x\"\nlast-modified=\nfetched-at=not-a-timestamp\n",
        )
        .unwrap();

        let parsed = load_meta_file(&meta_path);
        assert_eq!(parsed.etag.as_deref(), Some("\"x\""));
        assert!(parsed.fetched_at.is_none());
    }

    #[test]
    fn load_disk_cache_loads_headers_only() {
        let dir = tempfile::tempdir().unwrap();
        let source = "privacy/ads";

        // Write a cached list to disk
        write_cache_to_disk(
            dir.path(),
            source,
            "cached.example.com\n",
            Some("\"etag1\""),
            None,
            OffsetDateTime::now_utc(),
        );

        let client = reqwest::Client::new();
        let filter = Arc::new(FilterEngine::new());
        let catalog = Catalog::fallback();
        let source_bits = build_source_bit_map(&[source.to_string()]).expect("at-cap accept");

        let mut mgr = ListManager::new(
            client,
            filter,
            vec![source.to_string()],
            catalog,
            Duration::from_secs(3600),
            source_bits,
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            Some(dir.path().to_path_buf()),
        );

        assert!(mgr.cache.is_empty(), "cache should start empty");
        mgr.load_disk_cache();

        // Headers loaded, body deferred to refresh() for on-demand disk read
        let url = "https://lists.purge.cc/ads.txt";
        let entry = mgr.cache.get(url).expect("cache entry should exist");
        assert!(
            entry.body.is_none(),
            "body should NOT be loaded into memory"
        );
        assert_eq!(entry.etag.as_deref(), Some("\"etag1\""));
        assert!(entry.last_modified.is_none());

        // Body is still readable from disk via resolve_body
        let body = mgr.read_body_from_disk(source);
        assert_eq!(body.as_deref(), Some("cached.example.com\n"));

        // Phase 1.1: fetched_at must be populated to a real value, not
        // the UNIX_EPOCH sentinel a derive(Default) would have left.
        // The Phase 1.2 freshness check reads this field, so it has
        // to be load-bearing on round-trip.
        let entry = mgr.cache.get("https://lists.purge.cc/ads.txt").unwrap();
        assert!(
            entry.fetched_at > OffsetDateTime::UNIX_EPOCH,
            "fetched_at must be a real timestamp after round-trip"
        );
    }

    #[test]
    fn load_disk_cache_legacy_meta_falls_back_to_now() {
        // A pre-Sprint-24 .meta file (no fetched-at line) should NOT
        // crash load_disk_cache. The cache entry should get a fresh
        // now_utc() stamp so the freshness check (Phase 1.2) treats
        // the legacy cache as just-stamped, avoiding a startup HTTP
        // burst on the first run after a binary upgrade.
        let dir = tempfile::tempdir().unwrap();
        let source = "privacy/ads";

        // Manually write a legacy-format cache pair (no fetched-at line).
        let stem = source_to_cache_stem(source);
        std::fs::write(
            dir.path().join(format!("{stem}.cache")),
            "legacy.example.com\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join(format!("{stem}.meta")),
            "etag=\"old\"\nlast-modified=\n",
        )
        .unwrap();

        let before = OffsetDateTime::now_utc();
        let client = reqwest::Client::new();
        let filter = Arc::new(FilterEngine::new());
        let catalog = Catalog::fallback();
        let source_bits = build_source_bit_map(&[source.to_string()]).expect("at-cap accept");

        let mut mgr = ListManager::new(
            client,
            filter,
            vec![source.to_string()],
            catalog,
            Duration::from_secs(3600),
            source_bits,
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            Some(dir.path().to_path_buf()),
        );
        mgr.load_disk_cache();

        let entry = mgr
            .cache
            .get("https://lists.purge.cc/ads.txt")
            .expect("legacy cache should still load");
        assert_eq!(entry.etag.as_deref(), Some("\"old\""));
        assert!(
            entry.fetched_at >= before,
            "legacy cache should get a fresh now_utc() stamp on load"
        );
    }

    #[tokio::test]
    async fn refresh_skips_http_when_cache_is_fresh() {
        // The crash-loop fix in action. The configured URL is a
        // loopback literal that download_list() validates and
        // rejects (see download_list_rejects_loopback_literal). If
        // the freshness check correctly skips download_list, the
        // body is read straight from the on-disk .cache file and
        // parsed into the filter engine. If the freshness check
        // does NOT fire, download_list runs first, the URL is
        // rejected, and the filter engine ends up empty — the
        // assertion catches that regression.
        let dir = tempfile::tempdir().unwrap();
        let url = "https://127.0.0.1/blocklist.txt".to_string();

        // Write a body for the source so resolve_body() can read it
        // from disk during the freshness skip path.
        let stem = source_to_cache_stem(&url);
        std::fs::write(
            dir.path().join(format!("{stem}.cache")),
            "skipfresh.example.com\n",
        )
        .unwrap();
        // Also write a meta file so load_disk_cache populates the
        // in-memory entry with a real fetched_at — load_disk_cache
        // requires the .cache file to exist before reading meta.
        let now = OffsetDateTime::now_utc();
        let now_rfc3339 = now.format(&Rfc3339).unwrap();
        std::fs::write(
            dir.path().join(format!("{stem}.meta")),
            format!("etag=\nlast-modified=\nfetched-at={now_rfc3339}\n"),
        )
        .unwrap();

        let client = reqwest::Client::new();
        let filter = Arc::new(FilterEngine::new());
        let catalog = Catalog::fallback();
        let source_bits = build_source_bit_map(std::slice::from_ref(&url)).expect("at-cap accept");

        let mut mgr = ListManager::new(
            client,
            filter.clone(),
            vec![url.clone()],
            catalog,
            Duration::from_secs(3600),
            source_bits,
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            Some(dir.path().to_path_buf()),
        );
        mgr.load_disk_cache();

        // Sanity: cache has the entry and fetched_at is recent.
        let entry_before = mgr.cache.get(&url).expect("entry should be loaded");
        assert!(entry_before.fetched_at >= now - time::Duration::seconds(2));
        let fetched_at_before = entry_before.fetched_at;

        let count = mgr.refresh().await;

        // Freshness skip path read the body from disk and parsed it,
        // so the filter engine ends up with the one domain. If the
        // skip had failed, download_list would have rejected the
        // loopback URL and count would be 0.
        assert_eq!(count, 1);
        assert!(filter.is_blocked("skipfresh.example.com"));

        // The entry's fetched_at should be unchanged because no
        // download (200 or 304) actually happened.
        let entry_after = mgr.cache.get(&url).unwrap();
        assert_eq!(entry_after.fetched_at, fetched_at_before);
    }

    /// CacheOnly must serve a 30-day-old cache without touching the
    /// network.
    ///
    /// The URL is a loopback literal that `download_list` REFUSES
    /// (`download_list_rejects_loopback_literal`), but **`count` cannot
    /// be the discriminator here**: the manager's pre-existing
    /// crash-loop-resilience behaviour re-parses the retained on-disk
    /// cache whenever `download_list` fails (see the `Err(e)` arm in
    /// `refresh_with_mode`, and the module doc comment — "On 304 Not
    /// Modified or download failure, the manager re-uses the previously
    /// cached response body"). Since this fixture's `.cache` file is
    /// exactly what both CacheOnly's skip path AND that HTTP-failure
    /// fallback would parse, `count == 1` either way. Verified
    /// empirically: hardcoding `mode = RefreshMode::Network` at the top
    /// of `refresh_with_mode` still passes a `count`/`is_blocked`-only
    /// version of this test.
    ///
    /// The real discriminator is the status registry — but not "does
    /// `last_outcome` read `Ok`". A CacheOnly cache-hit is not a
    /// verified-fresh refresh (the body may be this old on purpose,
    /// §2.3), so per `boot_list_persistence.md` §2.8 it must not be
    /// *recorded* as one: the registry is left exactly as it was
    /// pre-seeded (`NeverFetched`, `last_refresh_at: None`), not stamped
    /// `Ok` with `last_refresh_at = now`. A genuine HTTP attempt, by
    /// contrast, always moves the registry off that default — `Ok` via
    /// `update_list_status_ok` on success, `Failed` via `from_failure` on
    /// the sibling test below (`refresh_records_failure_in_status`). See
    /// `cache_only_leaves_prior_status_untouched` for the sharper pin:
    /// a *non-default* prior status also survives this cycle byte for
    /// byte, which a bug that merely swapped `Ok` for some other stamp
    /// could otherwise slip past a `NeverFetched`-only check.
    ///
    /// The cache is deliberately far outside `refresh_interval`, which
    /// is the whole point — this pins `boot_list_persistence.md` §2.3
    /// (age is never a reason to refuse) against a future re-introduction
    /// of an age gate.
    #[tokio::test]
    async fn cache_only_refresh_serves_a_stale_cache_without_http() {
        use crate::lists::status::LastOutcome;

        let dir = tempfile::tempdir().unwrap();
        let url = "https://127.0.0.1/blocklist.txt".to_string();
        let stem = source_to_cache_stem(&url);
        std::fs::write(
            dir.path().join(format!("{stem}.cache")),
            "stale.example.com\n",
        )
        .unwrap();
        let old = OffsetDateTime::now_utc() - time::Duration::days(30);
        std::fs::write(
            dir.path().join(format!("{stem}.meta")),
            format!(
                "etag=\nlast-modified=\nfetched-at={}\n",
                old.format(&Rfc3339).unwrap()
            ),
        )
        .unwrap();

        let filter = Arc::new(FilterEngine::new());
        let source_bits = build_source_bit_map(std::slice::from_ref(&url)).expect("at-cap accept");
        let mut mgr = ListManager::new(
            reqwest::Client::new(),
            filter.clone(),
            vec![url.clone()],
            Catalog::fallback(),
            Duration::from_secs(3600),
            source_bits,
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            Some(dir.path().to_path_buf()),
        );
        mgr.load_disk_cache();
        let reg = mgr.status_registry();

        let count = mgr.refresh_with_mode(RefreshMode::CacheOnly).await;

        assert_eq!(
            count, 1,
            "CacheOnly must load a 30-day-old cache — age is not a gate"
        );
        assert!(filter.is_blocked("stale.example.com"));
        let status = reg.status_for_url(&url).unwrap();
        assert!(
            matches!(status.last_outcome, LastOutcome::NeverFetched),
            "CacheOnly must not claim a verified-fresh refresh for a \
             cache that may be months old (§2.8) — the registry must \
             stay at its pre-seeded default, not be stamped Ok: got {:?}",
            status.last_outcome
        );
        assert!(
            status.last_refresh_at.is_none(),
            "CacheOnly must not stamp last_refresh_at — that is the \
             field the TUI stale badge reads, and stamping it `now` for \
             a 30-day-old body is the exact lie §2.8 prohibits"
        );
    }

    /// Sharper than the test above: seeds a **non-default** prior status
    /// (as if a real refresh had already run earlier in this process's
    /// lifetime) and asserts it survives a CacheOnly cache-hit cycle
    /// unchanged, field for field. The default-`NeverFetched` case above
    /// would still pass a bug that stamped some *other* fixed value on
    /// this path; only comparing against an arbitrary known prior value
    /// pins "carry forward" as the actual behaviour rather than "happens
    /// to leave the zero value alone".
    #[tokio::test]
    async fn cache_only_leaves_prior_status_untouched() {
        use crate::lists::status::LastOutcome;

        let dir = tempfile::tempdir().unwrap();
        let url = "https://127.0.0.1/blocklist.txt".to_string();
        let stem = source_to_cache_stem(&url);
        std::fs::write(
            dir.path().join(format!("{stem}.cache")),
            "stale.example.com\n",
        )
        .unwrap();
        let old = OffsetDateTime::now_utc() - time::Duration::days(30);
        std::fs::write(
            dir.path().join(format!("{stem}.meta")),
            format!(
                "etag=\nlast-modified=\nfetched-at={}\n",
                old.format(&Rfc3339).unwrap()
            ),
        )
        .unwrap();

        let filter = Arc::new(FilterEngine::new());
        let source_bits = build_source_bit_map(std::slice::from_ref(&url)).expect("at-cap accept");
        let mut mgr = ListManager::new(
            reqwest::Client::new(),
            filter.clone(),
            vec![url.clone()],
            Catalog::fallback(),
            Duration::from_secs(3600),
            source_bits,
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            Some(dir.path().to_path_buf()),
        );
        mgr.load_disk_cache();
        let reg = mgr.status_registry();

        // Seed a known, non-default prior status — as if this process had
        // already recorded a real refresh outcome earlier in its
        // lifetime — so "unchanged" is a meaningful claim rather than a
        // restatement of the freshly-constructed default.
        let seeded_last_refresh = OffsetDateTime::now_utc() - time::Duration::hours(9);
        let prior = ListStatus {
            entries: 42,
            last_outcome: LastOutcome::Failed {
                reason: "prior network attempt failed".to_string(),
            },
            fetched_at: Some(seeded_last_refresh),
            last_refresh_at: Some(seeded_last_refresh),
            prev_entries: Some(37),
            ..ListStatus::default()
        };
        reg.update_for_url(&url, prior.clone());

        mgr.refresh_with_mode(RefreshMode::CacheOnly).await;

        // The list still contributes its domains to the map ...
        assert!(filter.is_blocked("stale.example.com"));
        // ... but its health/freshness reporting is exactly what it was
        // before this cycle — this is the assertion that fails if
        // `update_list_status_ok` / `ListStatus::from_refresh` is ever
        // reinstated on the CacheOnly cache-hit path.
        let status = reg.status_for_url(&url).unwrap();
        assert_eq!(
            *status, prior,
            "CacheOnly must carry the prior status forward untouched (§2.8)"
        );
    }

    /// The discriminating half. Identical fixture, `Network` mode: the
    /// cache is stale, so the freshness shortcut does NOT fire and
    /// `download_list` genuinely runs.
    ///
    /// It refuses the loopback literal — but the manager's pre-existing
    /// (and correct) crash-loop-resilience behaviour then falls back to
    /// the retained on-disk cache in the `Err(e)` arm, so `count` comes
    /// out to 1, identical to the CacheOnly test above. That fallback is
    /// intentional (it is what lets a source keep blocking through a
    /// transient failure) and this test must not weaken it to force a 0.
    /// `count` therefore cannot be the discriminator; the fact that HTTP
    /// was attempted and refused shows up only in the status registry,
    /// which the failed download attempt stamps `Failed` regardless of
    /// whether the fallback parse succeeds (see
    /// `refresh_records_failure_in_status`, same `Err(e)` arm, same
    /// `ListStatus::from_failure` call, unconditional).
    ///
    /// Without the `last_outcome` assertion, this test (and the one
    /// above) both pass on a `refresh_with_mode` that ignores `mode`
    /// entirely — confirmed by temporarily hardcoding
    /// `RefreshMode::Network` at the top of `refresh_with_mode` and
    /// re-running the CacheOnly test above alone.
    #[tokio::test]
    async fn network_refresh_with_a_stale_cache_still_reaches_http() {
        use crate::lists::status::LastOutcome;

        let dir = tempfile::tempdir().unwrap();
        let url = "https://127.0.0.1/blocklist.txt".to_string();
        let stem = source_to_cache_stem(&url);
        std::fs::write(
            dir.path().join(format!("{stem}.cache")),
            "stale.example.com\n",
        )
        .unwrap();
        let old = OffsetDateTime::now_utc() - time::Duration::days(30);
        std::fs::write(
            dir.path().join(format!("{stem}.meta")),
            format!(
                "etag=\nlast-modified=\nfetched-at={}\n",
                old.format(&Rfc3339).unwrap()
            ),
        )
        .unwrap();

        let filter = Arc::new(FilterEngine::new());
        let source_bits = build_source_bit_map(std::slice::from_ref(&url)).expect("at-cap accept");
        let mut mgr = ListManager::new(
            reqwest::Client::new(),
            filter.clone(),
            vec![url.clone()],
            Catalog::fallback(),
            Duration::from_secs(3600),
            source_bits,
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            Some(dir.path().to_path_buf()),
        );
        mgr.load_disk_cache();
        let reg = mgr.status_registry();

        let count = mgr.refresh_with_mode(RefreshMode::Network).await;

        assert_eq!(
            count, 1,
            "Network mode falls back to the retained cache on a failed \
             download, same as CacheOnly for this fixture — the \
             discriminator is last_outcome, not count"
        );
        let status = reg.status_for_url(&url).unwrap();
        assert!(
            matches!(status.last_outcome, LastOutcome::Failed { .. }),
            "Network mode must have attempted HTTP and recorded the \
             refusal: got {:?}",
            status.last_outcome
        );
    }

    /// Closes a gap the two tests above cannot: both their fixtures have
    /// a `.cache` file to fall back on, so neither one exercises the
    /// branch that actually enforces zero HTTP — `refresh_with_mode`'s
    /// explicit `continue` for a source with no usable disk cache
    /// (`boot_list_persistence.md` §2.2 test obligation 1: "CacheOnly
    /// performs zero HTTP").
    ///
    /// With nothing on disk to fall back to, a genuine HTTP attempt is
    /// distinguishable from no attempt at all: `download_list` failing
    /// with no cache to swallow the failure stamps `Failed` (there is
    /// nothing else the Err(e) arm's `else` branch — "download failed,
    /// no cache available" — can record); CacheOnly's explicit
    /// zero-HTTP exit never touches the status registry at all, leaving
    /// it at its pre-seeded `NeverFetched` default.
    #[tokio::test]
    async fn cache_only_with_no_disk_cache_makes_zero_http_calls() {
        use crate::lists::status::LastOutcome;

        let dir = tempfile::tempdir().unwrap();
        let url = "https://127.0.0.1/blocklist.txt".to_string();
        // Deliberately no .cache / .meta written: this source has never
        // been fetched, so there is nothing to fall back to.

        let filter = Arc::new(FilterEngine::new());
        let source_bits = build_source_bit_map(std::slice::from_ref(&url)).expect("at-cap accept");
        let mut mgr = ListManager::new(
            reqwest::Client::new(),
            filter,
            vec![url.clone()],
            Catalog::fallback(),
            Duration::from_secs(3600),
            source_bits,
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            Some(dir.path().to_path_buf()),
        );
        let reg = mgr.status_registry();

        let count = mgr.refresh_with_mode(RefreshMode::CacheOnly).await;

        assert_eq!(count, 0, "no cache on disk, nothing to serve");
        let status = reg.status_for_url(&url).unwrap();
        assert!(
            matches!(status.last_outcome, LastOutcome::NeverFetched),
            "CacheOnly must not call download_list even when there is no \
             cache to fall back on — the registry must stay at its \
             pre-seeded NeverFetched default (a Failed outcome would mean \
             HTTP was attempted, and an Ok outcome would be just as wrong): \
             got {:?}",
            status.last_outcome
        );
    }

    // ── ListStatusRegistry wiring (s43-t1) ──────────────────────

    /// `ListManager::status_registry()` exposes a registry pre-seeded
    /// with one slot per configured source, all in `NeverFetched` state.
    #[test]
    fn status_registry_pre_populated_for_each_source() {
        use crate::lists::status::LastOutcome;
        let client = reqwest::Client::new();
        let filter = Arc::new(FilterEngine::new());
        let catalog = Catalog::fallback();
        let sources = vec!["privacy/ads".to_string(), "security/malicious".into()];
        let bits = build_source_bit_map(&sources).expect("at-cap accept");
        let mgr = ListManager::new(
            client,
            filter,
            sources.clone(),
            catalog,
            Duration::from_secs(3600),
            bits,
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            None,
        );
        let reg = mgr.status_registry();
        assert_eq!(reg.len(), 2);
        for src in &sources {
            let s = reg.status_for_url(src).unwrap();
            assert_eq!(s.entries, 0);
            assert_eq!(s.last_outcome, LastOutcome::NeverFetched);
        }
    }

    /// After a refresh that pulls a real list (privacy/ads from the
    /// purge.cc test endpoint), the registry slot for that source
    /// transitions to `Ok` with non-zero entries and a populated
    /// `fetched_at`. This is the end-to-end T1 acceptance: refresh
    /// updates entries + fetched_at atomically.
    /// Hits the real `privacy/ads` source (`https://lists.purge.cc/ads.txt`)
    /// — needs egress. Excluded from the default `cargo test` leg per
    /// `tests-depend-on-live-cdn-gate-hostage` (P2): a CDN fault must never
    /// fail this repo's own merge gate. Run explicitly, with egress, via:
    /// `cargo test --lib -- --ignored lists::manager::tests::refresh_populates_list_status_for_real_source`
    #[tokio::test]
    #[ignore = "hits real https://lists.purge.cc — run with `cargo test -- --ignored`"]
    async fn refresh_populates_list_status_for_real_source() {
        use crate::lists::status::LastOutcome;
        let client = reqwest::Client::builder()
            .user_agent("purge-warden/test")
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap();
        let filter = Arc::new(FilterEngine::new());
        let catalog = Catalog::fallback();
        let source = "privacy/ads".to_string();
        let bits = build_source_bit_map(std::slice::from_ref(&source)).expect("at-cap accept");
        let mut mgr = ListManager::new(
            client,
            filter,
            vec![source.clone()],
            catalog,
            Duration::from_secs(3600),
            bits,
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            None,
        );
        let reg = mgr.status_registry();
        let count = mgr.refresh().await;
        let status = reg.status_for_url(&source).unwrap();
        assert_eq!(status.entries as usize, count);
        assert!(status.entries > 0, "real upstream must contribute domains");
        assert_eq!(status.last_outcome, LastOutcome::Ok);
        assert!(status.fetched_at.is_some());
        // First refresh — no prior data to compute delta against.
        assert!(status.delta_pct_vs_prev.is_none());
    }

    /// Persistence round-trip: refresh once, drop the manager,
    /// reconstruct, set persistence path → registry pre-seeded with
    /// `prev_entries` from the prior cycle.
    /// Hits the real `privacy/ads` source twice (fresh refresh + reload) —
    /// needs egress. Excluded from the default `cargo test` leg per
    /// `tests-depend-on-live-cdn-gate-hostage` (P2). Run explicitly, with
    /// egress, via:
    /// `cargo test --lib -- --ignored lists::manager::tests::list_stats_persistence_round_trip`
    #[tokio::test]
    #[ignore = "hits real https://lists.purge.cc — run with `cargo test -- --ignored`"]
    async fn list_stats_persistence_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let stats_path = dir.path().join("list_stats.json");

        // First lifecycle: refresh, persist.
        {
            let client = reqwest::Client::builder()
                .user_agent("purge-warden/test")
                .timeout(Duration::from_secs(15))
                .build()
                .unwrap();
            let filter = Arc::new(FilterEngine::new());
            let catalog = Catalog::fallback();
            let source = "privacy/ads".to_string();
            let bits = build_source_bit_map(std::slice::from_ref(&source)).expect("at-cap accept");
            let mut mgr = ListManager::new(
                client,
                filter,
                vec![source.clone()],
                catalog,
                Duration::from_secs(3600),
                bits,
                TEST_CAP,
                DEFAULT_MAX_LIST_ENTRIES,
                None,
            );
            mgr.set_status_persistence_path(stats_path.clone());
            let count = mgr.refresh().await;
            assert!(count > 0);
            assert!(stats_path.exists(), "refresh must persist list_stats.json");
        }

        // Second lifecycle: fresh manager, set persistence path,
        // registry must be pre-seeded with prev_entries for the source.
        {
            let client = reqwest::Client::new();
            let filter = Arc::new(FilterEngine::new());
            let catalog = Catalog::fallback();
            let source = "privacy/ads".to_string();
            let bits = build_source_bit_map(std::slice::from_ref(&source)).expect("at-cap accept");
            let mut mgr = ListManager::new(
                client,
                filter,
                vec![source.clone()],
                catalog,
                Duration::from_secs(3600),
                bits,
                TEST_CAP,
                DEFAULT_MAX_LIST_ENTRIES,
                None,
            );
            mgr.set_status_persistence_path(stats_path.clone());
            let reg = mgr.status_registry();
            let seeded = reg.status_for_url(&source).unwrap();
            // No refresh yet, so entries=0 + NeverFetched, but
            // prev_entries was loaded from disk.
            assert!(
                seeded.prev_entries.is_some(),
                "second-lifecycle manager must pre-load prev_entries from disk"
            );
            assert!(seeded.prev_entries.unwrap() > 0);
        }
    }

    /// A failed download with no cached body still updates the registry
    /// — last_outcome flips to Failed and fetched_at is bumped.
    #[tokio::test]
    async fn refresh_records_failure_in_status() {
        use crate::lists::status::LastOutcome;
        let catalog = Catalog::fallback();
        let filter = Arc::new(FilterEngine::new());
        // Loopback URL is rejected at validate_list_url before any
        // HTTP — same regression hook used by other tests in this file.
        let url = "https://127.0.0.1/blocklist.txt".to_string();
        let bits = build_source_bit_map(std::slice::from_ref(&url)).expect("at-cap accept");
        let mut mgr = ListManager::new(
            reqwest::Client::new(),
            filter,
            vec![url.clone()],
            catalog,
            Duration::from_secs(3600),
            bits,
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            None,
        );
        let reg = mgr.status_registry();
        mgr.refresh().await;
        let status = reg.status_for_url(&url).unwrap();
        assert!(matches!(status.last_outcome, LastOutcome::Failed { .. }));
        assert!(status.fetched_at.is_some());
        // First-ever attempt with no prior data → entries stays 0.
        assert_eq!(status.entries, 0);
    }

    /// A failed download must NOT stamp `fetched_at`.
    ///
    /// The tempting "optimisation" is to stamp it anyway so the
    /// freshness check skips the HTTP next time. It suppresses
    /// legitimate retries and poisons freshness: a list dead for six
    /// months would read as fresh at every boot. The fix for a slow boot
    /// is that boot does not consult the network, not that failures are
    /// recorded dishonestly. See `boot_list_persistence.md` §2.8.
    ///
    /// `before == after` alone is reachable two ways: a download was
    /// attempted and correctly did not stamp on failure (what this pins),
    /// or no download was ever attempted (the freshness gate took the
    /// cache-hit path and `download_list` was never reached — `fetched_at`
    /// is just as untouched then, for a reason this test does not care
    /// about). The fixture defeats the second cause on its own — the cache
    /// is 30 days old against a 1 h `refresh_interval`, so
    /// `is_cache_fresh` is false and `Network` mode cannot take the
    /// cache-hit path — but "the fixture happens to defeat it" is not the
    /// same as "the test asserts it". The registry check below is that
    /// assertion: `last_outcome` only leaves its `NeverFetched` default on
    /// a genuine attempt (`update_list_status_ok` on success,
    /// `ListStatus::from_failure` here), so `Failed` proves `download_list`
    /// was actually entered — every `from_failure` site sits inside its
    /// match. (Two of the three follow a download that succeeded and was
    /// then refused downstream — a parse refusal or a shrink-guard trip;
    /// neither is reachable from this fixture's loopback URL, which only
    /// reaches the download-`Err` site.) That is enough to close the gap
    /// a mutated freshness gate would otherwise slip through underneath
    /// the `fetched_at` assertion alone.
    #[tokio::test]
    async fn a_failed_download_does_not_stamp_fetched_at() {
        use crate::lists::status::LastOutcome;

        let dir = tempfile::tempdir().unwrap();
        // Loopback literal: `download_list` refuses it, which is a
        // failure without needing a server that hangs.
        let url = "https://127.0.0.1/blocklist.txt".to_string();
        let stem = source_to_cache_stem(&url);
        std::fs::write(
            dir.path().join(format!("{stem}.cache")),
            "kept.example.com\n",
        )
        .unwrap();
        let old = OffsetDateTime::now_utc() - time::Duration::days(30);
        std::fs::write(
            dir.path().join(format!("{stem}.meta")),
            format!(
                "etag=\nlast-modified=\nfetched-at={}\n",
                old.format(&Rfc3339).unwrap()
            ),
        )
        .unwrap();

        let filter = Arc::new(FilterEngine::new());
        let source_bits = build_source_bit_map(std::slice::from_ref(&url)).expect("at-cap accept");
        let mut mgr = ListManager::new(
            reqwest::Client::new(),
            filter.clone(),
            vec![url.clone()],
            Catalog::fallback(),
            Duration::from_secs(3600),
            source_bits,
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            Some(dir.path().to_path_buf()),
        );
        mgr.load_disk_cache();
        let before = mgr.cache.get(&url).expect("entry loaded").fetched_at;
        let reg = mgr.status_registry();

        mgr.refresh_with_mode(RefreshMode::Network).await;

        // Proves `download_list` was actually reached and actually
        // failed — without this, a mutated freshness gate that always
        // takes the cache-hit path would leave `fetched_at` untouched
        // for an unrelated reason and this test would still pass.
        assert!(
            matches!(
                reg.status_for_url(&url)
                    .expect("status seeded")
                    .last_outcome,
                LastOutcome::Failed { .. }
            ),
            "fixture must actually reach download_list and fail; a \
             cache-hit skip would leave fetched_at unchanged for the \
             wrong reason"
        );

        let after = mgr.cache.get(&url).expect("entry still present").fetched_at;
        assert_eq!(
            before, after,
            "a failed download must leave fetched_at alone — stamping it \
             would make a permanently-dead list read as fresh forever"
        );
    }

    // ── Sprint C T2 (lists_categories_v2 §14.2.b) ─────────────────────
    // Refresh-loop wire-in for `record_blocklist_*`. Pre-Sprint-C the
    // refresh loop kept its source-string keys but never drove the
    // canonical-id state machine, leaving `consecutive_failures` and
    // `status` permanently at their defaults. These three pins cover
    // the failure path (single increment), the threshold transition
    // to Failed, and the cache-fresh success path that recovers a
    // prior Failed back to Active per D9.

    fn lc2_t2_setup(
        url: &str,
        max_consec: u32,
    ) -> (
        ListManager,
        crate::config::schema::Id,
        std::path::PathBuf,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let bits =
            build_source_bit_map(std::slice::from_ref(&url.to_string())).expect("at-cap accept");
        let mut mgr = ListManager::new(
            reqwest::Client::new(),
            Arc::new(FilterEngine::new()),
            vec![url.to_string()],
            Catalog::fallback(),
            Duration::from_secs(3600),
            bits,
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            Some(dir.path().to_path_buf()),
        );
        let state_path = dir.path().join("list_state.toml");
        mgr.set_list_state(
            crate::config::list_state::ListState::default(),
            Some(state_path.clone()),
        );
        let blocklist_id = crate::config::schema::Id::new("test-blocklist").unwrap();
        let mut map = HashMap::new();
        map.insert(url.to_string(), (blocklist_id.clone(), max_consec));
        mgr.set_source_blocklist_map(map);
        (mgr, blocklist_id, state_path, dir)
    }

    /// Sprint C T2 row 1: a single failed refresh increments
    /// `consecutive_failures` to 1 and stamps `last_attempt`, but
    /// stays under the threshold so the status remains `Pending`
    /// (default for a never-succeeded list). Persisted to disk so the
    /// daemon can survive a restart without losing the counter.
    #[tokio::test]
    async fn refresh_failure_persists_consecutive_count() {
        let url = "https://127.0.0.1/lc2-c-t2-blocklist.txt";
        let (mut mgr, blocklist_id, state_path, _dir) = lc2_t2_setup(url, 5);
        mgr.refresh().await;
        let state = mgr
            .list_state_handle()
            .lock()
            .expect("list_state lock")
            .clone();
        let entry = state
            .lists
            .get(&blocklist_id)
            .expect("state machine must have an entry after refresh");
        assert_eq!(entry.consecutive_failures, 1);
        assert!(entry.last_attempt.is_some());
        assert_eq!(
            entry.status,
            crate::config::list_state::ListStatus::Pending,
            "1 of 5 failures must NOT flip to Failed yet",
        );
        // Persisted to disk per write_atomic.
        assert!(state_path.exists(), "list_state.toml must be persisted");
    }

    /// Sprint C T2 row 2: at the per-list `max_consecutive_failures`
    /// threshold, the Nth failure flips the status to `Failed` (D8).
    /// Pin the boundary so a future regression that off-by-ones the
    /// counter or fails to flip surfaces here.
    #[tokio::test]
    async fn refresh_failure_max_consecutive_flips_to_failed() {
        let url = "https://127.0.0.1/lc2-c-t2-flip.txt";
        let (mut mgr, blocklist_id, _state_path, _dir) = lc2_t2_setup(url, 3);
        // Three consecutive failures = threshold reached.
        mgr.refresh().await;
        mgr.refresh().await;
        mgr.refresh().await;
        let state = mgr
            .list_state_handle()
            .lock()
            .expect("list_state lock")
            .clone();
        let entry = state.lists.get(&blocklist_id).expect("state machine entry");
        assert_eq!(entry.consecutive_failures, 3);
        assert_eq!(
            entry.status,
            crate::config::list_state::ListStatus::Failed,
            "3 of 3 failures must flip to Failed",
        );
    }

    /// Sprint C T2 row 3: the cache-fresh path (Phase 1.2 freshness
    /// skip) is also a successful refresh from the state machine's
    /// POV — the cache is healthy, the list is healthy. A list that
    /// was previously `Failed` recovers to `Active` when its cache
    /// outlives the failure window (D9 stale-cache fallback turned
    /// recovery path).
    #[tokio::test]
    async fn refresh_success_persists_active_state() {
        // Reuse the cache-fresh harness — pre-seed a real disk cache
        // so the freshness skip path engages, parse_and_account runs,
        // and Sprint C T2 records the success.
        let dir = tempfile::tempdir().unwrap();
        let url = "https://127.0.0.1/lc2-c-t2-fresh.txt";

        let stem = source_to_cache_stem(url);
        std::fs::write(
            dir.path().join(format!("{stem}.cache")),
            "fresh.example.com\n",
        )
        .unwrap();
        let now = OffsetDateTime::now_utc();
        let now_rfc3339 = now.format(&Rfc3339).unwrap();
        std::fs::write(
            dir.path().join(format!("{stem}.meta")),
            format!("etag=\nlast-modified=\nfetched-at={now_rfc3339}\n"),
        )
        .unwrap();

        let bits =
            build_source_bit_map(std::slice::from_ref(&url.to_string())).expect("at-cap accept");
        let mut mgr = ListManager::new(
            reqwest::Client::new(),
            Arc::new(FilterEngine::new()),
            vec![url.to_string()],
            Catalog::fallback(),
            Duration::from_secs(3600),
            bits,
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            Some(dir.path().to_path_buf()),
        );
        let state_path = dir.path().join("list_state.toml");
        // Pre-seed the state with a Failed entry so this test pins
        // the recovery-from-Failed transition explicitly.
        let mut prior = crate::config::list_state::ListState::default();
        let blocklist_id = crate::config::schema::Id::new("recovers").unwrap();
        let prior_entry = crate::config::list_state::ListStatusEntry {
            status: crate::config::list_state::ListStatus::Failed,
            last_success: None,
            last_attempt: Some(now),
            consecutive_failures: 5,
            cache_path: None,
        };
        prior.lists.insert(blocklist_id.clone(), prior_entry);
        mgr.set_list_state(prior, Some(state_path));
        let mut map = HashMap::new();
        map.insert(url.to_string(), (blocklist_id.clone(), 5));
        mgr.set_source_blocklist_map(map);

        mgr.load_disk_cache();
        mgr.refresh().await;
        let state = mgr
            .list_state_handle()
            .lock()
            .expect("list_state lock")
            .clone();
        let entry = state.lists.get(&blocklist_id).expect("state machine entry");
        assert_eq!(
            entry.status,
            crate::config::list_state::ListStatus::Active,
            "cache-fresh refresh must recover Failed → Active",
        );
        assert_eq!(entry.consecutive_failures, 0);
        assert!(entry.last_success.is_some());
        assert!(
            entry.cache_path.is_some(),
            "cache_path must be stamped so D9 stale-cache fallback works",
        );
    }

    /// The CacheOnly mirror of the test above: a list that was previously
    /// `Failed` must NOT recover to `Active` when the only thing that
    /// happened is a stale cache getting reloaded at boot.
    ///
    /// Sprint C T2's recovery reasoning (D9: "the cache outlived the
    /// failure") depends on the cache being verified fresh —
    /// `Network`'s `is_cache_fresh` gate is exactly that verification,
    /// and `refresh_success_persists_active_state` above pins the
    /// recovery it authorises. `CacheOnly` has no such gate (§2.3: age is
    /// never a reason to refuse), so recording the same "success" would
    /// let an upstream that has been dead for months disarm
    /// `max_consecutive_failures` forever on a box that restarts more
    /// often than one refresh cycle
    /// (`_docs/features/boot_list_persistence.md` §2.8).
    ///
    /// Before this fix, `source_to_blocklist` being empty in every other
    /// CacheOnly fixture meant `record_blocklist_success` was never
    /// actually exercised by this cycle's cache-hit arm — this test wires
    /// `set_source_blocklist_map` specifically so it is.
    #[tokio::test]
    async fn cache_only_stale_cache_does_not_recover_failed_list_state() {
        let dir = tempfile::tempdir().unwrap();
        let url = "https://127.0.0.1/lc2-c-t2-stale-cacheonly.txt";

        let stem = source_to_cache_stem(url);
        std::fs::write(
            dir.path().join(format!("{stem}.cache")),
            "stale-failed.example.com\n",
        )
        .unwrap();
        let old = OffsetDateTime::now_utc() - time::Duration::days(30);
        std::fs::write(
            dir.path().join(format!("{stem}.meta")),
            format!(
                "etag=\nlast-modified=\nfetched-at={}\n",
                old.format(&Rfc3339).unwrap()
            ),
        )
        .unwrap();

        let bits =
            build_source_bit_map(std::slice::from_ref(&url.to_string())).expect("at-cap accept");
        let filter = Arc::new(FilterEngine::new());
        let mut mgr = ListManager::new(
            reqwest::Client::new(),
            filter.clone(),
            vec![url.to_string()],
            Catalog::fallback(),
            Duration::from_secs(3600),
            bits,
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            Some(dir.path().to_path_buf()),
        );
        let state_path = dir.path().join("list_state.toml");
        // Pre-seed a Failed entry, same shape as the Network recovery
        // test above, so this pins the opposite outcome under CacheOnly.
        let mut prior = crate::config::list_state::ListState::default();
        let blocklist_id = crate::config::schema::Id::new("stays-failed").unwrap();
        let prior_entry = crate::config::list_state::ListStatusEntry {
            status: crate::config::list_state::ListStatus::Failed,
            last_success: None,
            last_attempt: Some(old),
            consecutive_failures: 5,
            cache_path: None,
        };
        prior.lists.insert(blocklist_id.clone(), prior_entry);
        mgr.set_list_state(prior, Some(state_path));
        let mut map = HashMap::new();
        map.insert(url.to_string(), (blocklist_id.clone(), 5));
        mgr.set_source_blocklist_map(map);

        mgr.load_disk_cache();
        let count = mgr.refresh_with_mode(RefreshMode::CacheOnly).await;

        assert_eq!(count, 1, "the stale cache must still load and filter");
        assert!(filter.is_blocked("stale-failed.example.com"));

        let state = mgr
            .list_state_handle()
            .lock()
            .expect("list_state lock")
            .clone();
        let entry = state.lists.get(&blocklist_id).expect("state machine entry");
        assert_eq!(
            entry.status,
            crate::config::list_state::ListStatus::Failed,
            "a CacheOnly load of a stale cache must NOT recover Failed → \
             Active — that recovery is only earned by a verified-fresh \
             cache under Network (D9)",
        );
        assert_eq!(
            entry.consecutive_failures, 5,
            "record_blocklist_success must not run under CacheOnly"
        );
        assert!(entry.last_success.is_none());
    }

    /// The gate opens on a cycle that installs a generation, and stays
    /// open across a later cycle that installs nothing.
    ///
    /// Assert 2 is what still discriminates: `open()`'s call site
    /// hoisted above `swap_shard`, guard left intact (the M4 mutation).
    /// On this fixture's cold boot the engine is empty until the swap,
    /// so the guard is false at the hoisted position, the open never
    /// fires, and this assertion — which expects the gate open right
    /// after a successful install — is what catches it. `ReadinessGate`
    /// cannot forbid this on its own: `open()` compiles at any call
    /// site, so only a test that watches *when* it runs can.
    ///
    /// Assert 3 ("a cycle that installs nothing must not close the
    /// gate") is, since the newtype, in the same position as
    /// `readiness_gate_is_never_closed_by_an_empty_cycle` below — the
    /// implementation it was written against no longer compiles. It
    /// stays as a regression net on that axis, not because it still
    /// discriminates.
    #[tokio::test]
    async fn readiness_gate_latches_open_across_a_failing_cycle() {
        let dir = tempfile::tempdir().unwrap();
        let url = "https://127.0.0.1/blocklist.txt".to_string();
        let stem = source_to_cache_stem(&url);
        std::fs::write(
            dir.path().join(format!("{stem}.cache")),
            "latch.example.com\n",
        )
        .unwrap();
        let now = OffsetDateTime::now_utc();
        std::fs::write(
            dir.path().join(format!("{stem}.meta")),
            format!(
                "etag=\nlast-modified=\nfetched-at={}\n",
                now.format(&Rfc3339).unwrap()
            ),
        )
        .unwrap();

        let filter = Arc::new(FilterEngine::new());
        let source_bits = build_source_bit_map(std::slice::from_ref(&url)).expect("at-cap accept");
        let mut mgr = ListManager::new(
            reqwest::Client::new(),
            filter.clone(),
            vec![url.clone()],
            Catalog::fallback(),
            Duration::from_secs(3600),
            source_bits,
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            Some(dir.path().to_path_buf()),
        );
        let gate = ReadinessGate::new(false);
        mgr.set_filter_ready_gate(gate.clone());
        mgr.load_disk_cache();

        assert!(
            !gate.is_open(),
            "gate must start closed — nothing is installed yet"
        );

        let count = mgr.refresh_with_mode(RefreshMode::CacheOnly).await;
        assert_eq!(count, 1);
        assert!(
            gate.is_open(),
            "a cycle that installs a generation opens the gate — and opens \
             it AFTER the generation is installed: hoisting the open above \
             `swap_shard` leaves `domain_count()` at 0 on this cold-boot \
             cycle, so the gate never opens and this assertion fires"
        );

        // Now a cycle that installs nothing: delete the cache body so
        // CacheOnly finds no usable source at all.
        std::fs::remove_file(dir.path().join(format!("{stem}.cache"))).unwrap();
        mgr.refresh_with_mode(RefreshMode::CacheOnly).await;

        assert!(
            gate.is_open(),
            "a cycle that installs nothing must NOT close the gate — the \
             previous generation is still live and filtering"
        );
    }

    /// The latch, tested where it could actually fail — a **regression
    /// net**, no longer a discriminating test, and that demotion is the
    /// deliverable of Task 3b rather than a weakening.
    ///
    /// It was written to kill `gate.store(self.filter.domain_count() > 0)`
    /// — an implementation with an `else` that closes the gate. The test
    /// above cannot see that one, because after the cache is removed the
    /// engine still holds the domain it installed, so `domain_count() > 0`
    /// stays true. Here the engine is empty when the empty cycle runs, so
    /// the bad implementation stored `false` and this assertion caught it.
    ///
    /// Since the gate became a [`ReadinessGate`] that implementation does
    /// not **compile**: there is no `store`, no `close` — both pinned by
    /// the type's two `compile_fail` doctests — and the atomic is private
    /// to a sibling module too. That last part is NOT something a doctest
    /// can pin (it only ever sees the crate boundary, never a module
    /// boundary inside it); `scripts/check_readiness_gate_placement.sh`
    /// does instead. So the honest answer to "which wrong implementation
    /// does this kill" is now: none that are expressible. It stays
    /// because the type could be loosened — a `pub` field, a `close`
    /// method — and this is the test that would then catch the loosening
    /// being *used*.
    #[tokio::test]
    async fn readiness_gate_is_never_closed_by_an_empty_cycle() {
        let dir = tempfile::tempdir().unwrap();
        // No .cache and no .meta written at all: CacheOnly finds
        // nothing, installs nothing, and the engine stays empty.
        let url = "https://127.0.0.1/blocklist.txt".to_string();

        let filter = Arc::new(FilterEngine::new());
        let source_bits = build_source_bit_map(std::slice::from_ref(&url)).expect("at-cap accept");
        let mut mgr = ListManager::new(
            reqwest::Client::new(),
            filter.clone(),
            vec![url.clone()],
            Catalog::fallback(),
            Duration::from_secs(3600),
            source_bits,
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            Some(dir.path().to_path_buf()),
        );
        // Pre-opened, as it would be after any earlier successful cycle
        // in a long-running daemon.
        let gate = ReadinessGate::new(true);
        mgr.set_filter_ready_gate(gate.clone());
        mgr.load_disk_cache();

        mgr.refresh_with_mode(RefreshMode::CacheOnly).await;

        assert_eq!(filter.domain_count(), 0, "fixture sanity: engine is empty");
        assert!(
            gate.is_open(),
            "the gate is LATCHING — an empty cycle must not close it even \
             when the engine holds nothing. A daemon that has served a \
             generation must never go back to SERVFAILing every query."
        );
    }

    #[test]
    fn cleanup_stale_caches_removes_old_files() {
        let dir = tempfile::tempdir().unwrap();

        // Write cache for a source that IS still configured
        write_cache_to_disk(
            dir.path(),
            "privacy/ads",
            "body",
            None,
            None,
            OffsetDateTime::now_utc(),
        );
        // Write cache for a source that is NOT configured
        write_cache_to_disk(
            dir.path(),
            "content/adult",
            "body",
            None,
            None,
            OffsetDateTime::now_utc(),
        );

        let client = reqwest::Client::new();
        let filter = Arc::new(FilterEngine::new());
        let catalog = Catalog::fallback();
        let source_bits =
            build_source_bit_map(&["privacy/ads".to_string()]).expect("at-cap accept");

        let mgr = ListManager::new(
            client,
            filter,
            vec!["privacy/ads".to_string()],
            catalog,
            Duration::from_secs(3600),
            source_bits,
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            Some(dir.path().to_path_buf()),
        );

        mgr.cleanup_stale_caches();

        // privacy/ads files should remain (active source).
        let active_stem = source_to_cache_stem("privacy/ads");
        assert!(dir.path().join(format!("{active_stem}.cache")).exists());
        assert!(dir.path().join(format!("{active_stem}.meta")).exists());
        // content/adult files should be removed (no longer in config).
        let stale_stem = source_to_cache_stem("content/adult");
        assert!(!dir.path().join(format!("{stale_stem}.cache")).exists());
        assert!(!dir.path().join(format!("{stale_stem}.meta")).exists());
    }

    // ── S50 T5.5: imported.local loader-bridge ─────────────────────────
    //
    // The bridge intercepts synthetic `imported.local` URLs in
    // `download_list` and reads from `<config_dir>/lists/<id>.<ext>` on
    // disk. Tests here cover the four contract clauses spelled out in
    // the kickoff brief:
    //   (1) Local trust + file present → Loaded.
    //   (2) Local trust + file missing → Refused with the path in the
    //       error message.
    //   (3) Non-local trust → Refused (defence-in-depth W2.1) even
    //       though the validator should already have caught it.
    //   (4) Path → id extraction is correct for the `.txt` happy path
    //       and refuses the no-segment / sub-path / root edge cases.
    //
    // The bridge is a pure free function (no `ListManager`, no async,
    // no HTTP client), so each test stands up a `tempdir`, writes a
    // file, calls `try_bridge_imported_local`, and asserts on the
    // outcome.

    /// Convenience: build the `<dir>/lists/` directory under a tempdir
    /// and write `body` into `<dir>/lists/<filename>`. Returns the
    /// tempdir handle so the caller controls cleanup.
    fn write_imported_local_file(filename: &str, body: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let lists_dir = dir.path().join("lists");
        std::fs::create_dir_all(&lists_dir).unwrap();
        std::fs::write(lists_dir.join(filename), body).unwrap();
        dir
    }

    #[test]
    fn imported_local_url_with_trust_local_loads_from_disk() {
        let body = "mycompany.example\ninternal.example\n";
        let dir = write_imported_local_file("mycompany.txt", body);
        let outcome = try_bridge_imported_local(
            "https://imported.local/mycompany.txt",
            BlocklistTrust::Local,
            dir.path(),
            TEST_CAP,
        );
        match outcome {
            LocalBridgeOutcome::Loaded { body: got, path } => {
                assert_eq!(got, body);
                assert_eq!(path, dir.path().join("lists").join("mycompany.txt"));
            }
            other => panic!("expected Loaded, got {other:?}"),
        }
    }

    /// neutrality-06, end to end — a `base = allow` list must reach the
    /// engine as an ALLOW, and the contested domain must come out
    /// forwarded.
    ///
    /// This is the whole chain in one test: config `[[blocklists]]` →
    /// `SourceBitMap::allow_bits` → the manager's refresh → the shard
    /// builder → `FilterEngine`. It runs entirely on the `imported.local`
    /// bridge, so no network: fitting, since `base = allow` requires
    /// `trust = local` anyway.
    ///
    /// Before the fix the allow list's domains were merged into
    /// `block_mask`, so importing an allow list *blocked* what it was
    /// meant to permit.
    #[tokio::test]
    async fn neutrality06_allow_direction_list_reaches_engine_as_allow() {
        let dir = tempfile::tempdir().unwrap();
        let lists_dir = dir.path().join("lists");
        std::fs::create_dir_all(&lists_dir).unwrap();
        std::fs::write(
            lists_dir.join("ads.txt"),
            "shared.example\nblocked.example\n",
        )
        .unwrap();
        std::fs::write(lists_dir.join("compat.txt"), "shared.example\n").unwrap();

        let deny_url = "https://imported.local/ads.txt".to_string();
        let allow_url = "https://imported.local/compat.txt".to_string();

        let mk = |id: &str, url: &str, base: crate::config::schema::BlocklistBase| {
            crate::config::schema::Blocklist {
                id: crate::config::schema::id::Id::new(id).unwrap(),
                display_name: id.to_string(),
                url: url.to_string(),
                format: Default::default(),
                update_interval_hours: 12,
                max_entries: 5_000_000,
                enabled: true,
                auth_token_ref: None,
                base,
                trust: BlocklistTrust::Local,
                accept_unsigned_allow: false,
                max_consecutive_failures: 5,
            }
        };
        let blocklists = vec![
            mk("ads", &deny_url, crate::config::schema::BlocklistBase::Deny),
            mk(
                "compat",
                &allow_url,
                crate::config::schema::BlocklistBase::Allow,
            ),
        ];

        let sources = vec![deny_url.clone(), allow_url.clone()];
        let source_bits = SourceBitMap::build(&sources, &blocklists).unwrap();
        let policy = source_bits.project_policy(&blocklists, &std::collections::BTreeMap::new());
        assert_eq!(
            policy.base.allow, 0b10,
            "compat must own bit 1 as allow-direction"
        );

        let filter = Arc::new(FilterEngine::new());
        let mut mgr = ListManager::new(
            reqwest::Client::new(),
            filter.clone(),
            sources,
            Catalog::fallback(),
            Duration::from_secs(3600),
            source_bits,
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            None,
        );
        mgr.set_local_bridge(SourceTrustMap::build(&blocklists), dir.path().to_path_buf());
        mgr.set_list_policy(policy);
        mgr.refresh().await;

        let shared = filter.list_membership("shared.example");
        assert_eq!(
            shared.allow_mask, 0b10,
            "the allow list's bit must land in allow_mask, not block_mask"
        );
        assert_eq!(
            shared.block_mask, 0b01,
            "the deny list's bit must still land in block_mask"
        );

        let blocked = filter.list_membership("blocked.example");
        assert_eq!(blocked.allow_mask, 0);
        assert_eq!(blocked.block_mask, 0b01);
    }

    /// neutrality-06 in the `cluster` build — the same guarantee as
    /// `neutrality06_allow_direction_list_reaches_engine_as_allow`, exercised
    /// in the feature configuration where the install path used to fork.
    ///
    /// A clustering primary used to accumulate the whole corpus into one flat
    /// block-mask map to publish its sync artifact, and the local install rode
    /// that same flat map. Direction was dropped on the way, so a primary
    /// silently reverted to the inversion the sharded path had just been fixed
    /// for. Cluster sync S1 deleted the artifact and with it the fork — every
    /// node now installs shard-at-a-time via `swap_shard`.
    ///
    /// **The `cluster` gate stays deliberately.** Nothing in the body needs the
    /// feature any more, but the defect this pins was invisible with `cluster`
    /// off: it lived inside a `#[cfg(feature = "cluster")]` branch. The ungated
    /// sibling covers the default build; this covers the build where the
    /// install used to be conditional, so a cluster-only install path
    /// reintroduced later fails here rather than shipping unnoticed.
    #[cfg(feature = "cluster")]
    #[tokio::test]
    async fn cluster_build_allow_direction_survives_sharded_install() {
        let dir = tempfile::tempdir().unwrap();
        let lists_dir = dir.path().join("lists");
        std::fs::create_dir_all(&lists_dir).unwrap();
        std::fs::write(lists_dir.join("ads.txt"), "shared.example\n").unwrap();
        std::fs::write(lists_dir.join("compat.txt"), "shared.example\n").unwrap();

        let deny_url = "https://imported.local/ads.txt".to_string();
        let allow_url = "https://imported.local/compat.txt".to_string();
        let mk = |id: &str, url: &str, base: crate::config::schema::BlocklistBase| {
            crate::config::schema::Blocklist {
                id: crate::config::schema::id::Id::new(id).unwrap(),
                display_name: id.to_string(),
                url: url.to_string(),
                format: Default::default(),
                update_interval_hours: 12,
                max_entries: 5_000_000,
                enabled: true,
                auth_token_ref: None,
                base,
                trust: BlocklistTrust::Local,
                accept_unsigned_allow: false,
                max_consecutive_failures: 5,
            }
        };
        let blocklists = vec![
            mk("ads", &deny_url, crate::config::schema::BlocklistBase::Deny),
            mk(
                "compat",
                &allow_url,
                crate::config::schema::BlocklistBase::Allow,
            ),
        ];
        let sources = vec![deny_url, allow_url];
        let source_bits = SourceBitMap::build(&sources, &blocklists).unwrap();
        let policy = source_bits.project_policy(&blocklists, &std::collections::BTreeMap::new());

        let filter = Arc::new(FilterEngine::new());
        let mut mgr = ListManager::new(
            reqwest::Client::new(),
            filter.clone(),
            sources,
            Catalog::fallback(),
            Duration::from_secs(3600),
            source_bits,
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            None,
        );
        mgr.set_local_bridge(SourceTrustMap::build(&blocklists), dir.path().to_path_buf());
        mgr.set_list_policy(policy);
        mgr.refresh().await;

        let shared = filter.list_membership("shared.example");
        assert_eq!(
            shared.allow_mask, 0b10,
            "a sharded rebuild must install the allow direction"
        );
        assert_eq!(shared.block_mask, 0b01);
    }

    #[test]
    fn imported_local_url_with_trust_local_missing_file_errors() {
        // No `lists/` directory at all: tempdir is bare.
        let dir = tempfile::tempdir().unwrap();
        let outcome = try_bridge_imported_local(
            "https://imported.local/missing.txt",
            BlocklistTrust::Local,
            dir.path(),
            TEST_CAP,
        );
        match outcome {
            LocalBridgeOutcome::Refused(reason) => {
                let expected_path = dir.path().join("lists").join("missing.txt");
                assert!(
                    reason.contains(&expected_path.display().to_string()),
                    "error message should include the missing path; got: {reason}"
                );
                assert!(
                    reason.contains("not readable"),
                    "error message should explain why; got: {reason}"
                );
            }
            other => panic!("expected Refused, got {other:?}"),
        }
    }

    #[test]
    fn imported_local_url_with_trust_remote_unsigned_refuses() {
        // File exists, but trust is wrong — defence-in-depth.
        let dir = write_imported_local_file("mycompany.txt", "should.not.read.example\n");
        let outcome = try_bridge_imported_local(
            "https://imported.local/mycompany.txt",
            BlocklistTrust::RemoteUnsigned,
            dir.path(),
            TEST_CAP,
        );
        match outcome {
            LocalBridgeOutcome::Refused(reason) => {
                assert!(
                    reason.contains("requires trust=local"),
                    "error message should explain the W2.1 violation; got: {reason}"
                );
                assert!(
                    reason.contains("W2.1"),
                    "error message should reference the invariant id; got: {reason}"
                );
            }
            other => panic!("expected Refused for non-local trust, got {other:?}"),
        }
    }

    #[test]
    fn imported_local_url_with_trust_signed_also_refuses() {
        // `signed` is parked S51+ but defence-in-depth covers it too —
        // a future agent who flips trust to "signed" should see the
        // same refusal until signing is actually implemented.
        let dir = write_imported_local_file("mycompany.txt", "should.not.read.example\n");
        let outcome = try_bridge_imported_local(
            "https://imported.local/mycompany.txt",
            BlocklistTrust::Signed,
            dir.path(),
            TEST_CAP,
        );
        assert!(matches!(outcome, LocalBridgeOutcome::Refused(_)));
    }

    #[test]
    fn imported_local_url_extracts_id_correctly_from_path() {
        // Happy path: single .txt segment.
        assert_eq!(
            imported_local_id_from_path("/mycompany.txt").as_deref(),
            Some("mycompany.txt")
        );
        // Without leading slash too (defensive — Url::parse always
        // produces a leading slash, but the helper is more useful as a
        // pure function on raw strings).
        assert_eq!(
            imported_local_id_from_path("mycompany.txt").as_deref(),
            Some("mycompany.txt")
        );
        // Root-only path: no id segment.
        assert_eq!(imported_local_id_from_path("/"), None);
        // Empty path.
        assert_eq!(imported_local_id_from_path(""), None);
        // Sub-path: refuse so a typo can't traverse into a nested dir.
        assert_eq!(imported_local_id_from_path("/sub/mycompany.txt"), None);
        // Trailing-slash form is also a sub-path attempt.
        assert_eq!(imported_local_id_from_path("/mycompany/"), None);
        // Non-`.txt` extensions still pass through — T3 picks `.txt`
        // today but the bridge stays format-agnostic.
        assert_eq!(
            imported_local_id_from_path("/internal.toml").as_deref(),
            Some("internal.toml")
        );
    }

    #[test]
    fn imported_local_id_rejects_dotdot_segment() {
        // rev-2606 §06 roundup nit: a bare `..` segment must be refused so
        // non-traversal is a property of the function, not merely of "a
        // directory isn't readable as a file".
        assert_eq!(imported_local_id_from_path(".."), None);
        assert_eq!(imported_local_id_from_path("/.."), None);
        assert_eq!(imported_local_id_from_path("//.."), None);
        // A normal single segment still resolves.
        assert_eq!(
            imported_local_id_from_path("/list.txt").as_deref(),
            Some("list.txt")
        );
    }

    #[test]
    fn pure_v1_auth_token_ref_attaches_bearer_via_v1_id_fallback() {
        // rev-2606 §06 source_key-02: a pure-v1 blocklist's source string is
        // the raw URL, so the slash-form `by_url` token key misses. The
        // fallback through `source_to_blocklist` → `token_for_v1_id` must still
        // supply the bearer instead of fetching anonymously.
        use crate::config::schema::{
            Blocklist, BlocklistBase, BlocklistFormat, BlocklistTrust, ConfigV1, Id,
        };

        // A real `Secrets` via the public load path (entries are private).
        fn secrets_with(name: &str, value: &str) -> crate::config::secrets::Secrets {
            use std::io::Write as _;
            use std::os::unix::fs::PermissionsExt as _;
            use std::sync::atomic::{AtomicUsize, Ordering};
            static SEQ: AtomicUsize = AtomicUsize::new(0);
            let pid = std::process::id();
            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!("purge-mgr-stkn-{pid}-{n}"));
            std::fs::create_dir_all(&dir).unwrap();
            let sp = dir.join("secrets.toml");
            {
                let mut f = std::fs::File::create(&sp).unwrap();
                writeln!(f, "{name} = \"{value}\"").unwrap();
            }
            let mut perm = std::fs::metadata(&sp).unwrap().permissions();
            perm.set_mode(0o600);
            std::fs::set_permissions(&sp, perm).unwrap();
            let secrets = crate::config::secrets::load_secrets(&sp).unwrap();
            let _ = std::fs::remove_dir_all(&dir);
            secrets
        }

        let url = "https://corp.example.com/private.txt";
        let mut config = ConfigV1::test_scaffold();
        config.blocklists.push(Blocklist {
            id: Id::new("security-malicious").unwrap(),
            display_name: "sec".to_string(),
            url: url.to_string(),
            format: BlocklistFormat::Domains,
            update_interval_hours: 12,
            max_entries: 5_000_000,
            enabled: true,
            auth_token_ref: Some("sec-token".to_string()),
            base: BlocklistBase::Deny,
            trust: BlocklistTrust::RemoteUnsigned,
            accept_unsigned_allow: false,
            max_consecutive_failures: 5,
        });
        let secrets = secrets_with("sec-token", "bearer-xyz");
        let tokens = SourceTokenMap::build(&config, &secrets);

        // Pure-v1 source == raw URL → the slash-form by_url key misses.
        assert_eq!(tokens.token_for_url(url), None);

        // start.rs maps the raw URL to the canonical Id in source_to_blocklist.
        let mut s2b: HashMap<String, (Id, u32)> = HashMap::new();
        s2b.insert(url.to_string(), (Id::new("security-malicious").unwrap(), 5));

        // Fallback resolves the bearer; an unknown source still yields nothing.
        assert_eq!(resolve_bearer_token(&tokens, &s2b, url), Some("bearer-xyz"));
        assert_eq!(
            resolve_bearer_token(&tokens, &s2b, "https://other.example/x"),
            None
        );
    }

    #[test]
    fn imported_local_url_non_imported_host_falls_through_to_http() {
        // A regular https URL must NOT be intercepted — the bridge has
        // to be invisible to the existing fetch path.
        let dir = tempfile::tempdir().unwrap();
        let outcome = try_bridge_imported_local(
            "https://lists.purge.cc/ads.txt",
            BlocklistTrust::RemoteUnsigned,
            dir.path(),
            TEST_CAP,
        );
        assert!(matches!(outcome, LocalBridgeOutcome::NotLocal));
    }

    #[test]
    fn imported_local_url_unparseable_falls_through_to_http() {
        // Malformed URLs are not the bridge's problem — the existing
        // URL guard / HTTP client surfaces those errors with their
        // existing error vocabulary. Bridge stays out of the way.
        let dir = tempfile::tempdir().unwrap();
        let outcome = try_bridge_imported_local(
            "not a url at all",
            BlocklistTrust::Local,
            dir.path(),
            TEST_CAP,
        );
        assert!(matches!(outcome, LocalBridgeOutcome::NotLocal));
    }

    #[test]
    fn imported_local_url_missing_id_segment_refuses() {
        // `https://imported.local/` (no segment) must NOT silently
        // resolve to `<config_dir>/lists/` itself — a typo must surface
        // as a refusal, not a directory read.
        let dir = tempfile::tempdir().unwrap();
        let outcome = try_bridge_imported_local(
            "https://imported.local/",
            BlocklistTrust::Local,
            dir.path(),
            TEST_CAP,
        );
        match outcome {
            LocalBridgeOutcome::Refused(reason) => {
                assert!(
                    reason.contains("missing list id segment"),
                    "error should explain the empty-segment case; got: {reason}"
                );
            }
            other => panic!("expected Refused for empty path, got {other:?}"),
        }
    }

    #[test]
    fn imported_local_url_oversize_file_refuses() {
        // Defence-in-depth: a runaway local file shouldn't OOM the
        // daemon any more than a runaway HTTP body would. The HTTP
        // path uses `read_bounded_body`; the bridge mirrors via a
        // `metadata().len()` check before reading.
        let dir = write_imported_local_file("oversize.txt", "0123456789ABCDEF\n");
        // Cap of 4 bytes — strictly smaller than the 17-byte body.
        let outcome = try_bridge_imported_local(
            "https://imported.local/oversize.txt",
            BlocklistTrust::Local,
            dir.path(),
            4,
        );
        match outcome {
            LocalBridgeOutcome::Refused(reason) => {
                assert!(
                    reason.contains("17 bytes"),
                    "error message should report the actual size; got: {reason}"
                );
                assert!(
                    reason.contains("max 4 bytes"),
                    "error message should report the cap; got: {reason}"
                );
            }
            other => panic!("expected Refused for oversize file, got {other:?}"),
        }
    }

    #[test]
    fn stat_local_source_none_for_non_local_url() {
        let dir = write_imported_local_file("mycompany.txt", "a.example\n");
        assert!(
            stat_local_source("https://lists.example.invalid/a.txt", dir.path()).is_none(),
            "a non-imported.local URL has no file to stamp"
        );
    }

    #[test]
    fn stat_local_source_none_for_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            stat_local_source("https://imported.local/absent.txt", dir.path()).is_none(),
            "a missing file stamps as None, same as a non-local URL — both mean \
             'nothing to compare', and the transition INTO this state still \
             changes the fingerprint by construction (Some -> None)"
        );
    }

    #[test]
    fn stat_local_source_changes_on_content_edit() {
        let dir = write_imported_local_file("mycompany.txt", "a.example\n");
        let before = stat_local_source("https://imported.local/mycompany.txt", dir.path());
        assert!(before.is_some());

        std::thread::sleep(std::time::Duration::from_millis(10));
        std::fs::write(
            dir.path().join("lists/mycompany.txt"),
            "a.example\nb.example\n",
        )
        .unwrap();
        let after = stat_local_source("https://imported.local/mycompany.txt", dir.path());

        assert_ne!(
            before, after,
            "a size+mtime change on the same file must move the stamp"
        );
    }

    #[test]
    fn stat_local_source_stable_across_repeat_reads() {
        let dir = write_imported_local_file("mycompany.txt", "a.example\n");
        let a = stat_local_source("https://imported.local/mycompany.txt", dir.path());
        let b = stat_local_source("https://imported.local/mycompany.txt", dir.path());
        assert_eq!(
            a, b,
            "reading an unchanged file twice must stamp identically"
        );
    }

    #[test]
    fn set_local_bridge_attaches_trust_map_and_dir() {
        // Builder-method smoke: after `.set_local_bridge(...)`, the
        // manager's bridge fields are populated and a subsequent
        // construction via `new` (no builder call) leaves them empty.
        // §4.24 Phase 2 (P2-A): the trust map is now the typed
        // `SourceTrustMap` — fixture builds it via `::build(blocklists)`
        // (no hand-constructed HashMap) per §11.4 test discipline.
        let client = reqwest::Client::new();
        let filter = Arc::new(FilterEngine::new());
        let catalog = Catalog::fallback();
        let dir = tempfile::tempdir().unwrap();

        let imported_url = "https://imported.local/mycompany.txt".to_string();
        let blocklists = vec![crate::config::schema::Blocklist {
            id: crate::config::schema::id::Id::new("mycompany").unwrap(),
            display_name: "mycompany".to_string(),
            url: imported_url.clone(),
            format: Default::default(),
            update_interval_hours: 12,
            max_entries: 5_000_000,
            enabled: true,
            auth_token_ref: None,
            base: crate::config::schema::BlocklistBase::Allow,
            trust: BlocklistTrust::Local,
            accept_unsigned_allow: false,
            max_consecutive_failures: 5,
        }];
        let trust = SourceTrustMap::build(&blocklists);

        let mgr_no_bridge = ListManager::new(
            client.clone(),
            filter.clone(),
            vec![],
            catalog.clone(),
            Duration::from_secs(3600),
            SourceBitMap::default(),
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            None,
        );
        assert!(mgr_no_bridge.local_bridge_dir.is_none());
        assert!(mgr_no_bridge.source_trust.is_empty());

        let mut mgr_with_bridge = ListManager::new(
            client,
            filter,
            vec![],
            catalog,
            Duration::from_secs(3600),
            SourceBitMap::default(),
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            None,
        );
        mgr_with_bridge.set_local_bridge(trust.clone(), dir.path().to_path_buf());

        assert_eq!(
            mgr_with_bridge.local_bridge_dir.as_deref(),
            Some(dir.path())
        );
        // Trust was wired by URL; the typed lookup confirms it.
        assert_eq!(
            mgr_with_bridge.source_trust.trust_for_url(&imported_url),
            Some(BlocklistTrust::Local),
        );
        // And by canonical v1 id — the symmetry Phase 2 unlocked.
        assert_eq!(
            mgr_with_bridge
                .source_trust
                .trust_for_v1_id(&crate::config::schema::id::Id::new("mycompany").unwrap()),
            Some(BlocklistTrust::Local),
        );
    }

    #[test]
    fn merge_sources_with_blocklists_appends_url_and_records_trust() {
        // Helper used by start.rs / update.rs to unify legacy
        // `lists.sources` with v1 `[[blocklists]]` URLs in one place.
        // T3's `import-local` only writes the `[[blocklists]]` row; this
        // helper ensures the URL also reaches the manager AND its trust
        // is wired for the loader-bridge defence-in-depth check.
        use crate::config::schema::id::Id;
        use crate::config::schema::{Blocklist, BlocklistBase, BlocklistTrust};

        let legacy = vec!["privacy/ads".to_string()];
        let blocklists = vec![
            Blocklist {
                id: Id::new("mycompany").unwrap(),
                display_name: "mycompany".to_string(),
                url: "https://imported.local/mycompany.txt".to_string(),
                format: Default::default(),
                update_interval_hours: 12,
                max_entries: 5_000_000,
                enabled: true,
                auth_token_ref: None,
                base: BlocklistBase::Allow,
                trust: BlocklistTrust::Local,
                accept_unsigned_allow: false,
                max_consecutive_failures: 5,
            },
            Blocklist {
                // Disabled — must NOT appear in merged sources.
                id: Id::new("paused").unwrap(),
                display_name: "paused".to_string(),
                url: "https://example.com/paused.txt".to_string(),
                format: Default::default(),
                update_interval_hours: 12,
                max_entries: 5_000_000,
                enabled: false,
                auth_token_ref: None,
                base: BlocklistBase::Deny,
                trust: BlocklistTrust::RemoteUnsigned,
                accept_unsigned_allow: false,
                max_consecutive_failures: 5,
            },
        ];

        let (sources, trust) = merge_sources_with_blocklists(&legacy, &blocklists);
        assert_eq!(sources.len(), 2, "legacy + 1 enabled blocklist URL");
        assert_eq!(sources[0], "privacy/ads");
        assert_eq!(sources[1], "https://imported.local/mycompany.txt");
        // §4.24 Phase 2 (P2-A): trust map is now the typed `SourceTrustMap`.
        // Lookups go through `trust_for_url` / `trust_for_v1_id` instead
        // of HashMap::get — pinning the call-site contract.
        assert_eq!(
            trust.trust_for_url("https://imported.local/mycompany.txt"),
            Some(BlocklistTrust::Local),
        );
        assert_eq!(
            trust.trust_for_v1_id(&Id::new("mycompany").unwrap()),
            Some(BlocklistTrust::Local),
            "v1-id lookup is the new Phase 2 contract",
        );
        // Disabled entries are excluded from sources but DO surface in
        // the trust map — a future enable-then-reload should pick up
        // the right trust without recomputing.
        assert_eq!(
            trust.trust_for_url("https://example.com/paused.txt"),
            Some(BlocklistTrust::RemoteUnsigned),
        );
        assert_eq!(
            trust.trust_for_v1_id(&Id::new("paused").unwrap()),
            Some(BlocklistTrust::RemoteUnsigned),
        );
    }

    #[test]
    fn merge_sources_with_blocklists_does_not_duplicate_when_url_already_in_sources() {
        // If an operator listed the URL in BOTH legacy `lists.sources`
        // AND `[[blocklists]]` (forward-compat for the post-T6 world
        // where `lists.sources` becomes the canonical view), the merge
        // must not duplicate.
        use crate::config::schema::id::Id;
        use crate::config::schema::{Blocklist, BlocklistBase, BlocklistTrust};

        let legacy = vec![
            "privacy/ads".to_string(),
            "https://imported.local/mycompany.txt".to_string(),
        ];
        let blocklists = vec![Blocklist {
            id: Id::new("mycompany").unwrap(),
            display_name: "mycompany".to_string(),
            url: "https://imported.local/mycompany.txt".to_string(),
            format: Default::default(),
            update_interval_hours: 12,
            max_entries: 5_000_000,
            enabled: true,
            auth_token_ref: None,
            base: BlocklistBase::Allow,
            trust: BlocklistTrust::Local,
            accept_unsigned_allow: false,
            max_consecutive_failures: 5,
        }];

        let (sources, _) = merge_sources_with_blocklists(&legacy, &blocklists);
        assert_eq!(sources, legacy, "no duplicate URL after merge");
    }

    /// §4.7 Phase 2 T1: `forget_source` removes any in-memory cache
    /// entry for a configured source, regardless of whether the
    /// HashMap was keyed by slug or by catalog-resolved URL.
    #[test]
    fn forget_removes_in_memory_entry() {
        let client = reqwest::Client::new();
        let filter = Arc::new(FilterEngine::new());
        let catalog = Catalog::fallback();
        let mut mgr = ListManager::new(
            client,
            filter,
            vec!["privacy/ads".to_string()],
            catalog,
            Duration::from_secs(3600),
            SourceBitMap::default(),
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            None,
        );

        let resolved_url = mgr
            .catalog
            .resolve("privacy/ads")
            .expect("privacy/ads in fallback catalog");
        mgr.cache.insert(
            resolved_url.clone(),
            ListCache {
                etag: Some("\"abc\"".into()),
                last_modified: None,
                body: Some("example.com".into()),
                fetched_at: OffsetDateTime::now_utc(),
            },
        );
        assert!(mgr.cache.contains_key(&resolved_url));

        let was_cached = mgr.forget_source("privacy/ads");
        assert!(was_cached, "in-memory entry was present before forget");
        assert!(
            !mgr.cache.contains_key(&resolved_url),
            "in-memory entry must be gone after forget"
        );
    }

    /// §4.7 Phase 2 T1: when a cache_dir is wired, `forget_source`
    /// unlinks both the `<stem>.cache` body file and the `<stem>.meta`
    /// sidecar. Files not present are absorbed silently.
    #[test]
    fn forget_deletes_cache_and_meta_files() {
        let tmp = tempfile::tempdir().unwrap();
        let client = reqwest::Client::new();
        let filter = Arc::new(FilterEngine::new());
        let catalog = Catalog::fallback();
        let mut mgr = ListManager::new(
            client,
            filter,
            vec!["privacy/ads".to_string()],
            catalog,
            Duration::from_secs(3600),
            SourceBitMap::default(),
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            Some(tmp.path().to_path_buf()),
        );

        let stem = source_to_cache_stem("privacy/ads");
        let cache_path = tmp.path().join(format!("{stem}.cache"));
        let meta_path = tmp.path().join(format!("{stem}.meta"));
        std::fs::write(&cache_path, b"example.com\nads.example.org\n").unwrap();
        std::fs::write(&meta_path, b"etag=\"abc\"\nfetched-at=\n").unwrap();
        assert!(cache_path.exists());
        assert!(meta_path.exists());

        let was_cached = mgr.forget_source("privacy/ads");
        assert!(was_cached, "disk files were present before forget");
        assert!(!cache_path.exists(), "<stem>.cache must be unlinked");
        assert!(!meta_path.exists(), "<stem>.meta must be unlinked");
    }

    /// §4.7 Phase 2 T1: idempotency — forgetting a source we never
    /// cached (no HashMap entry, no disk files) returns `false`
    /// without error. A second call after a successful forget also
    /// returns `false`.
    #[test]
    fn forget_returns_false_when_source_not_cached() {
        let tmp = tempfile::tempdir().unwrap();
        let client = reqwest::Client::new();
        let filter = Arc::new(FilterEngine::new());
        let catalog = Catalog::fallback();
        let mut mgr = ListManager::new(
            client,
            filter,
            vec!["privacy/ads".to_string()],
            catalog,
            Duration::from_secs(3600),
            SourceBitMap::default(),
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            Some(tmp.path().to_path_buf()),
        );

        // Never-cached source.
        assert!(!mgr.forget_source("privacy/never-seen"));

        // Cache an entry, forget once (true), forget again (false).
        let url = mgr
            .catalog
            .resolve("privacy/ads")
            .expect("privacy/ads in fallback catalog");
        mgr.cache.insert(url, ListCache::default());
        assert!(mgr.forget_source("privacy/ads"));
        assert!(
            !mgr.forget_source("privacy/ads"),
            "second forget on already-cleared source returns false"
        );
    }

    /// §4.7 Phase 2 T3: `write_cache_to_disk` stamps `size=<bytes>`
    /// into the `.meta` sidecar, and `load_meta_file` parses it back
    /// into `ParsedMeta.size`.
    #[test]
    fn meta_size_field_serializes_and_deserializes() {
        let tmp = tempfile::tempdir().unwrap();
        let body = "example.com\nads.example.org\n";
        let now = OffsetDateTime::now_utc();
        write_cache_to_disk(
            tmp.path(),
            "privacy/ads",
            body,
            Some("\"etag\""),
            Some("Wed, 21 Oct 2024 07:28:00 GMT"),
            now,
        );

        let stem = source_to_cache_stem("privacy/ads");
        let meta_path = tmp.path().join(format!("{stem}.meta"));
        let parsed = load_meta_file(&meta_path);
        assert_eq!(parsed.size, Some(body.len()));

        // Round-trip sanity: meta file contains the size= line verbatim.
        let raw = std::fs::read_to_string(&meta_path).unwrap();
        assert!(
            raw.contains(&format!("size={}\n", body.len())),
            "meta missing size= line: {raw}"
        );
    }

    /// §4.7 Phase 2 T3: actual within 1 % of expected passes the
    /// validator — supply-chain churn at typical list size is allowed
    /// through without forcing a re-download.
    #[test]
    fn validate_size_within_one_percent_passes() {
        // 0.5 % drift on a 5 MB list — well within tolerance.
        let expected = 5_000_000_usize;
        let actual = expected + 25_000; // +0.5 %
        assert!(validate_cached_body_size(Some(expected), actual));
        // And the symmetric shrink case (a list that lost a few entries).
        assert!(validate_cached_body_size(Some(expected), expected - 25_000));
        // Exact match always passes.
        assert!(validate_cached_body_size(Some(expected), expected));
    }

    /// §4.7 Phase 2 T3: a 1.5 % size drift fails the validator and
    /// triggers the re-download path on the next refresh cycle. Floor
    /// edge case: exactly 1 % must reject (the predicate is `< 1 %`).
    #[test]
    fn validate_size_one_point_five_percent_diff_fails() {
        let expected = 5_000_000_usize;
        // +1.5 % drift — outside tolerance.
        let actual = expected + 75_000;
        assert!(!validate_cached_body_size(Some(expected), actual));
        // Symmetric shrink case.
        assert!(!validate_cached_body_size(
            Some(expected),
            expected - 75_000
        ));
        // Exact 1 % must reject (boundary is strictly less than).
        assert!(!validate_cached_body_size(
            Some(expected),
            expected + 50_000
        ));
    }

    /// §4.7 Phase 2 T3: pre-T3 `.meta` files have no `size=` line.
    /// `ParsedMeta.size == None` must be treated as "trust the body"
    /// so an upgrade from Phase 1 to Phase 2 does not force a
    /// re-download burst.
    #[test]
    fn validate_missing_meta_size_passes_legacy_compat() {
        // None expected => always pass, irrespective of actual size.
        assert!(validate_cached_body_size(None, 0));
        assert!(validate_cached_body_size(None, 1));
        assert!(validate_cached_body_size(None, usize::MAX));
        // Zero expected => degenerate but accepted (the empty-body
        // case is rare; falsely rejecting it adds no signal).
        assert!(validate_cached_body_size(Some(0), 0));
        assert!(validate_cached_body_size(Some(0), 1_000_000));
    }

    /// §4.7 Phase 2 T3: when `.meta` records `size=N` but the
    /// `.cache` file on disk has been truncated by > 1 % (corruption,
    /// partial write, ENOSPC mid-fsync), `read_body_from_disk`
    /// returns `None` so the next refresh forces an HTTP re-fetch.
    #[test]
    fn load_disk_cache_skips_invalidated_body() {
        let tmp = tempfile::tempdir().unwrap();
        let client = reqwest::Client::new();
        let filter = Arc::new(FilterEngine::new());
        let catalog = Catalog::fallback();
        let mgr = ListManager::new(
            client,
            filter,
            vec!["privacy/ads".to_string()],
            catalog,
            Duration::from_secs(3600),
            SourceBitMap::default(),
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            Some(tmp.path().to_path_buf()),
        );

        let stem = source_to_cache_stem("privacy/ads");
        let cache_path = tmp.path().join(format!("{stem}.cache"));
        let meta_path = tmp.path().join(format!("{stem}.meta"));

        // Write a small body but record a meta size that claims the
        // body is 10x larger — simulates on-disk truncation.
        let body = "example.com\n";
        std::fs::write(&cache_path, body).unwrap();
        std::fs::write(
            &meta_path,
            format!(
                "etag=\nlast-modified=\nfetched-at=\nsize={}\n",
                body.len() * 10
            ),
        )
        .unwrap();

        // `.cache` body is 10x smaller than expected — validator
        // rejects, read returns None, next refresh re-downloads.
        let result = mgr.read_body_from_disk("privacy/ads");
        assert!(
            result.is_none(),
            "size-diff body must be rejected; read returned Some()"
        );

        // Cross-check: a body within tolerance is accepted.
        std::fs::write(
            &meta_path,
            format!("etag=\nlast-modified=\nfetched-at=\nsize={}\n", body.len()),
        )
        .unwrap();
        let result_ok = mgr.read_body_from_disk("privacy/ads");
        assert_eq!(result_ok.as_deref(), Some(body));
    }

    /// s-4.31-disc-3: `write_cache_to_disk` stages `.cache.new` +
    /// `.meta.new` then promotes both via rename. On success no `.new`
    /// temps are left behind, and the promoted pair is internally
    /// consistent — the `.meta` `size=` matches the `.cache` body, so
    /// `read_body_from_disk`'s §4.7-T3 predicate accepts it without a
    /// spurious re-download. (The crash-recovery side — divergent
    /// `.cache` vs stale `.meta` → re-download — is already pinned by
    /// `load_disk_cache_skips_invalidated_body` above.)
    #[test]
    fn write_cache_to_disk_leaves_no_new_files_on_success() {
        let tmp = tempfile::tempdir().unwrap();
        let source = "privacy/ads";
        let stem = source_to_cache_stem(source);
        let body = "tracker.example\nads.example\n";

        write_cache_to_disk(
            tmp.path(),
            source,
            body,
            Some("\"etag-123\""),
            Some("Wed, 14 May 2026 00:00:00 GMT"),
            OffsetDateTime::now_utc(),
        );

        let cache_path = tmp.path().join(format!("{stem}.cache"));
        let meta_path = tmp.path().join(format!("{stem}.meta"));
        let cache_tmp = tmp.path().join(format!("{stem}.cache.new"));
        let meta_tmp = tmp.path().join(format!("{stem}.meta.new"));

        assert_eq!(std::fs::read_to_string(&cache_path).unwrap(), body);
        assert!(
            std::fs::read_to_string(&meta_path)
                .unwrap()
                .contains(&format!("size={}", body.len())),
            "meta must stamp the body size"
        );
        assert!(!cache_tmp.exists(), "stray .cache.new left after success");
        assert!(!meta_tmp.exists(), "stray .meta.new left after success");

        // The promoted pair is internally consistent — the §4.7-T3
        // size predicate accepts it (no spurious re-download).
        let client = reqwest::Client::new();
        let filter = Arc::new(FilterEngine::new());
        let catalog = Catalog::fallback();
        let mgr = ListManager::new(
            client,
            filter,
            vec![source.to_string()],
            catalog,
            Duration::from_secs(3600),
            SourceBitMap::default(),
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            Some(tmp.path().to_path_buf()),
        );
        assert_eq!(mgr.read_body_from_disk(source).as_deref(), Some(body));
    }

    // ── rev-2606 §06 manager-01: retention guard ──────────────────

    fn prev_with_unique(unique: u64) -> ListStatus {
        ListStatus {
            entries: unique,
            unique_domains: unique,
            last_outcome: crate::lists::status::LastOutcome::Ok,
            ..ListStatus::default()
        }
    }

    #[test]
    fn shrink_verdict_first_fetch_always_accepts() {
        // No prior status → no baseline → accept even an empty body, so
        // initial provisioning is never bricked.
        assert!(matches!(
            compute_shrink_verdict(true, 90, None, 0),
            ShrinkVerdict::Accept { .. }
        ));
    }

    #[test]
    fn shrink_verdict_disabled_accepts_catastrophic_drop() {
        let prev = prev_with_unique(1000);
        assert!(matches!(
            compute_shrink_verdict(false, 90, Some(&prev), 0),
            ShrinkVerdict::Accept { .. }
        ));
    }

    #[test]
    fn shrink_verdict_trips_on_collapse_to_zero() {
        let prev = prev_with_unique(1000);
        match compute_shrink_verdict(true, 90, Some(&prev), 0) {
            ShrinkVerdict::Refuse {
                drop_pct,
                got,
                kept,
            } => {
                assert_eq!((drop_pct, got, kept), (100, 0, 1000));
            }
            other => panic!("expected Refuse, got {other:?}"),
        }
    }

    #[test]
    fn shrink_verdict_boundary_exact_threshold_accepts_just_over_trips() {
        let prev = prev_with_unique(1000);
        // Exactly 90% drop (fresh = 100 = 10% of baseline) → accept.
        assert!(matches!(
            compute_shrink_verdict(true, 90, Some(&prev), 100),
            ShrinkVerdict::Accept { .. }
        ));
        // Just over 90% (fresh = 99) → trip.
        assert!(matches!(
            compute_shrink_verdict(true, 90, Some(&prev), 99),
            ShrinkVerdict::Refuse { .. }
        ));
    }

    #[test]
    fn shrink_verdict_legitimate_prune_accepts() {
        // An 80% upstream prune is below the 90% threshold → accepted.
        let prev = prev_with_unique(1000);
        assert!(matches!(
            compute_shrink_verdict(true, 90, Some(&prev), 200),
            ShrinkVerdict::Accept { .. }
        ));
    }

    #[test]
    fn shrink_verdict_large_swing_accepts_with_delta_warn() {
        let prev = prev_with_unique(1000);
        // 60% shrink: under the 90% refusal but over the 50% canary.
        match compute_shrink_verdict(true, 90, Some(&prev), 400) {
            ShrinkVerdict::Accept { delta_warn } => {
                let d = delta_warn.expect("a 60% shrink must arm the canary");
                assert!(d <= -DELTA_WARN_THRESHOLD_PCT);
            }
            other => panic!("expected Accept, got {other:?}"),
        }
        // A 1000x GROWTH is also a canary signal.
        match compute_shrink_verdict(true, 90, Some(&prev), 1_000_000) {
            ShrinkVerdict::Accept { delta_warn } => {
                assert!(delta_warn.expect("growth canary").abs() >= DELTA_WARN_THRESHOLD_PCT);
            }
            other => panic!("expected Accept, got {other:?}"),
        }
    }

    #[test]
    fn shrink_verdict_falls_back_to_prev_entries_when_no_unique_baseline() {
        // v1→v2 upgrade: prior cycle has only the persisted entries
        // baseline (unique_domains == 0). The guard still trips.
        let prev = ListStatus {
            unique_domains: 0,
            prev_entries: Some(1000),
            ..ListStatus::default()
        };
        assert!(matches!(
            compute_shrink_verdict(true, 90, Some(&prev), 0),
            ShrinkVerdict::Refuse { .. }
        ));
    }

    /// Pins the `RefreshMode` → cache-hit message mapping.
    ///
    /// Swapping the two arms of `cache_hit_message` previously compiled
    /// and passed every test in this file — the distinction is not
    /// cosmetic, it is what stops a boot logging "list fresh, skipping
    /// HTTP" (a phrase implying a recent, interval-bounded confirmation,
    /// per `PendingStatus::message`'s doc) about a cache that may be
    /// months old. This test does NOT cover whether the cache-hit call
    /// site in `refresh_with_mode` passes the `mode` the cycle is
    /// actually running under — only that the mapping itself is correct
    /// once a `mode` reaches it.
    #[test]
    fn cache_hit_message_pins_the_mode_mapping() {
        assert_eq!(
            cache_hit_message(RefreshMode::CacheOnly),
            "boot: loaded from disk cache, no HTTP",
        );
        assert_eq!(
            cache_hit_message(RefreshMode::Network),
            "list fresh, skipping HTTP and reusing cache",
        );
    }

    /// A manager whose single source is served by the imported.local
    /// bridge from a file on disk — lets a test control the "downloaded"
    /// body byte-for-byte without HTTP (the URL guard rejects a loopback
    /// mock). The bridge file lives at `<dir>/lists/poison.txt`; the cache
    /// is a SEPARATE `<dir>/cache` so a retained `.cache` survives a
    /// bridge-file overwrite.
    fn bridge_manager(body: &str) -> (ListManager, String, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let url = "https://imported.local/poison.txt".to_string();
        let lists_dir = dir.path().join("lists");
        std::fs::create_dir_all(&lists_dir).unwrap();
        std::fs::write(lists_dir.join("poison.txt"), body).unwrap();
        let cache_dir = dir.path().join("cache");
        std::fs::create_dir_all(&cache_dir).unwrap();

        let bits = build_source_bit_map(std::slice::from_ref(&url)).expect("at-cap accept");
        let mut mgr = ListManager::new(
            reqwest::Client::new(),
            Arc::new(FilterEngine::new()),
            vec![url.clone()],
            Catalog::fallback(),
            Duration::from_secs(3600),
            bits,
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            Some(cache_dir),
        );
        let bl = crate::config::schema::Blocklist {
            id: crate::config::schema::id::Id::new("poison").unwrap(),
            display_name: "poison".to_string(),
            url: url.clone(),
            format: Default::default(),
            update_interval_hours: 12,
            max_entries: 5_000_000,
            enabled: true,
            auth_token_ref: None,
            base: crate::config::schema::BlocklistBase::Deny,
            trust: BlocklistTrust::Local,
            accept_unsigned_allow: false,
            max_consecutive_failures: 5,
        };
        mgr.set_local_bridge(SourceTrustMap::build(&[bl]), dir.path().to_path_buf());
        (mgr, url, dir)
    }

    fn write_bridge_body(dir: &tempfile::TempDir, body: &str) {
        std::fs::write(dir.path().join("lists").join("poison.txt"), body).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn cache_dir_lax_mode_flags_group_world_writable() {
        // rev-2606 §06 carryover-3.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(cache_dir_lax_mode(dir.path()), Some(0o777));
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
        assert_eq!(cache_dir_lax_mode(dir.path()), None, "0750 is not lax");
        // A non-existent dir is not flagged (first boot creates it).
        assert_eq!(cache_dir_lax_mode(&dir.path().join("nope")), None);
    }

    /// A SECOND attempt at pinning the fix in-suite, and it does not pin it
    /// either. Kept, with the negative result, so the next reader does not spend
    /// the same hour.
    ///
    /// The idea was sound: seed `cache` with a FRESH entry holding the OLD body,
    /// which is the state the defect lives in on a live daemon between scheduled
    /// cycles, then assert the operator's edit still lands. `resolve_body_reader`
    /// tries `cache.body` first, so without the local-file branch it should have
    /// returned the seeded three domains.
    ///
    /// Measured: with that branch forced off, this test STAYS GREEN. The bridge
    /// runs during `refresh()` and overwrites the seeded entry before anything
    /// reads it, so the seeding never survives to matter.
    ///
    /// Two attempts, two negative results. What they establish together is not
    /// "the fix is unpinnable" but something narrower and useful: **this harness
    /// re-bridges on every refresh, so no in-process test can hold a cache entry
    /// stale against the file**. Pinning it needs a harness that can suppress the
    /// bridge for one cycle — which does not exist and is a real piece of work,
    /// not an oversight.
    ///
    /// Until then the pin is the live isolated-daemon run recorded in
    /// `sighup-ignores-bridge-body`: append, SIGHUP, `lists reloaded count`
    /// 300000 -> 300001.
    #[tokio::test]
    async fn a_stale_but_fresh_cache_entry_does_not_hide_an_edited_local_body() {
        let old = "a.example.com\nb.example.com\nc.example.com\n";
        let (mut mgr, url, dir) = bridge_manager(old);
        assert_eq!(mgr.refresh().await, 3);

        // The operator edits their file...
        write_bridge_body(
            &dir,
            "a.example.com\nb.example.com\nc.example.com\nd.example.com\n",
        );

        // ...but a cache entry from "the last fetch" is still FRESH, so the
        // freshness shortcut fires and nothing re-reads the file. This is the
        // state a live daemon reaches between scheduled cycles.
        mgr.cache.insert(
            url.clone(),
            ListCache {
                etag: None,
                last_modified: None,
                body: Some(old.into()),
                fetched_at: OffsetDateTime::now_utc(),
            },
        );

        assert_eq!(
            mgr.refresh().await,
            4,
            "a fresh cache entry must not hide the operator's edit — 3 means the \
             seeded body was parsed instead of the file on disk"
        );
    }

    /// The core poison chain: a previously-good list whose upstream flips
    /// to an empty 200 must NOT lose its on-disk cache or stop blocking,
    /// and the outage must survive a daemon restart.
    /// End-to-end: an operator's edit to a `trust = local` body is picked up by
    /// the next refresh — the property `sighup-ignores-bridge-body` is about,
    /// driven through the manager's real `refresh()` rather than asserted on a
    /// fingerprint.
    ///
    /// # Why this needs no mocked HTTP client
    ///
    /// The task that filed this test assumed one, because `drive_gate_reload`'s
    /// rebuild branch fetches over the network. That is true of a REMOTE source.
    /// With only an `imported.local` source there is no fetch to mock: the bridge
    /// reads the file from disk, and [`bridge_manager`] already builds exactly
    /// that shape for the retention-guard tests below.
    ///
    /// # What it does NOT pin — measured, not assumed
    ///
    /// **This test passes with the fix REMOVED.** Mutation run: force
    /// `resolve_body_reader`'s local-file branch off, and this stays green while
    /// the three retention-guard tests below also stay green. The prediction
    /// written before the run said it would go red on 4 vs 3. It did not.
    ///
    /// The reason is the harness, not the assertion: every `refresh()` here goes
    /// through the bridge, which re-copies the file into the cache, so
    /// `resolve_body_reader` receives a fresh copy either way. The real defect
    /// needs `is_cache_fresh` to SKIP the fetch — and, as the retention-guard
    /// test below already documents, "the bridge path leaves no in-memory cache
    /// entry, so the freshness shortcut does not fire". This harness cannot
    /// reach the state the defect lives in.
    ///
    /// So what pins the fix is the live isolated-daemon run recorded in
    /// `sighup-ignores-bridge-body`'s closure note: append, SIGHUP, and
    /// `lists reloaded count` moving 300000 -> 300001. Reproducing that in-process
    /// needs a harness that can age a cache entry into freshness without a
    /// re-bridge, which does not exist yet.
    ///
    /// # What it DOES pin
    ///
    /// That an edited `trust = local` body reaches the corpus through the real
    /// `refresh()` path at all — a regression net for the bridge itself, which
    /// is worth keeping. It is simply not the net for the caching defect, and
    /// saying so here is the point: a test whose doc claims a catch it does not
    /// have is worse than no test, because the next reader stops looking.
    #[tokio::test]
    async fn a_local_body_edit_is_picked_up_by_the_next_refresh() {
        let (mut mgr, _url, dir) = bridge_manager("a.example.com\nb.example.com\nc.example.com\n");

        assert_eq!(
            mgr.refresh().await,
            3,
            "the initial body defines the corpus"
        );

        // The operator edits their own file — the exact scenario, no network.
        write_bridge_body(
            &dir,
            "a.example.com\nb.example.com\nc.example.com\nd.example.com\n",
        );

        assert_eq!(
            mgr.refresh().await,
            4,
            "an edited local body must reach the corpus; 3 means the cached copy \
             was re-read instead of the operator's file"
        );
    }

    #[tokio::test]
    async fn retention_guard_keeps_prior_cache_on_empty_200() {
        use crate::lists::status::LastOutcome;
        let good = "a.example.com\nb.example.com\nc.example.com\nd.example.com\n";
        let (mut mgr, url, dir) = bridge_manager(good);
        let stem = source_to_cache_stem(&url);
        let cache_file = dir.path().join("cache").join(format!("{stem}.cache"));

        // Refresh 1: good body accepted, cache written, domains in the map.
        assert_eq!(mgr.refresh().await, 4);
        assert_eq!(std::fs::read_to_string(&cache_file).unwrap(), good);
        let st = mgr.status_registry().status_for_url(&url).unwrap();
        assert!(matches!(st.last_outcome, LastOutcome::Ok));
        assert_eq!(st.unique_domains, 4);

        // Upstream goes bad: empty 200.
        write_bridge_body(&dir, "");

        // Refresh 2: guard trips. (The bridge path leaves no in-memory
        // cache entry, so the freshness shortcut does not fire and the
        // empty body is re-fetched and measured.)
        let total2 = mgr.refresh().await;
        // Prior list retained on disk...
        assert_eq!(
            std::fs::read_to_string(&cache_file).unwrap(),
            good,
            "good cache must survive a poisoned refresh"
        );
        // ...and still in the merged map (re-parsed from the retained cache).
        assert_eq!(total2, 4, "merged map keeps the prior list's domains");
        // ...status reflects the refusal with an operator-readable reason.
        match &mgr
            .status_registry()
            .status_for_url(&url)
            .unwrap()
            .last_outcome
        {
            LastOutcome::Failed { reason } => {
                assert!(reason.contains("refresh refused"), "got: {reason}");
                assert!(
                    reason.contains("forget"),
                    "reason must name the recovery verb"
                );
            }
            other => panic!("expected Failed, got {other:?}"),
        }

        // Simulated restart: a fresh manager over the same cache_dir loads
        // the retained good cache and still serves it.
        let bits = build_source_bit_map(std::slice::from_ref(&url)).expect("at-cap");
        let mut mgr2 = ListManager::new(
            reqwest::Client::new(),
            Arc::new(FilterEngine::new()),
            vec![url.clone()],
            Catalog::fallback(),
            Duration::from_secs(3600),
            bits,
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            Some(dir.path().join("cache")),
        );
        mgr2.load_disk_cache();
        assert_eq!(
            mgr2.refresh().await,
            4,
            "after restart the retained list is still served from cache"
        );
    }

    /// A legitimate large-but-sub-threshold prune (75% < 90%) is accepted
    /// and DOES overwrite the cache — the guard must not block real upstream
    /// pruning.
    #[tokio::test]
    async fn retention_guard_accepts_legitimate_prune() {
        use crate::lists::status::LastOutcome;
        let good = "a.example.com\nb.example.com\nc.example.com\nd.example.com\n";
        let (mut mgr, url, dir) = bridge_manager(good);
        let stem = source_to_cache_stem(&url);
        let cache_file = dir.path().join("cache").join(format!("{stem}.cache"));
        assert_eq!(mgr.refresh().await, 4);

        // 4 → 1 domain = 75% drop, under the 90% threshold.
        let pruned = "a.example.com\n";
        write_bridge_body(&dir, pruned);
        assert_eq!(mgr.refresh().await, 1);
        assert_eq!(
            std::fs::read_to_string(&cache_file).unwrap(),
            pruned,
            "an accepted prune overwrites the cache"
        );
        assert!(matches!(
            mgr.status_registry()
                .status_for_url(&url)
                .unwrap()
                .last_outcome,
            LastOutcome::Ok
        ));
    }

    /// First fetch of a brand-new source that returns an empty 200 is
    /// accepted (no baseline) — provisioning must not be bricked.
    #[tokio::test]
    async fn retention_guard_first_fetch_empty_accepts() {
        use crate::lists::status::LastOutcome;
        let (mut mgr, url, _dir) = bridge_manager("");
        assert_eq!(mgr.refresh().await, 0);
        assert!(matches!(
            mgr.status_registry()
                .status_for_url(&url)
                .unwrap()
                .last_outcome,
            LastOutcome::Ok
        ));
    }

    /// `warden lists forget <source>` disarms the guard: after a trip, a
    /// forget resets the baseline (and removes the cache the operator chose
    /// to discard), so the next fetch is treated as a first fetch and
    /// accepted even though it is tiny.
    #[tokio::test]
    async fn forget_disarms_retention_guard() {
        use crate::lists::status::LastOutcome;
        let good = "a.example.com\nb.example.com\nc.example.com\nd.example.com\n";
        let (mut mgr, url, dir) = bridge_manager(good);
        // Persist baselines so we can prove the disarm survives a restart.
        let stats_path = dir.path().join("list_stats.json");
        mgr.set_status_persistence_path(stats_path.clone());
        assert_eq!(mgr.refresh().await, 4);

        // Poison → trip.
        write_bridge_body(&dir, "");
        mgr.refresh().await;
        assert!(matches!(
            mgr.status_registry()
                .status_for_url(&url)
                .unwrap()
                .last_outcome,
            LastOutcome::Failed { .. }
        ));

        // Operator forgets the list: baseline reset, cache removed, stats
        // file rewritten so the disarm survives a restart.
        assert!(mgr.forget_source(&url));
        let persisted = std::fs::read_to_string(&stats_path).unwrap();
        assert!(
            !persisted.contains("imported.local"),
            "forget must drop the source's baseline from list_stats.json, got: {persisted}"
        );

        // Next fetch is tiny but accepted (guard disarmed → first fetch).
        write_bridge_body(&dir, "only.example.com\n");
        assert_eq!(mgr.refresh().await, 1);
        assert!(matches!(
            mgr.status_registry()
                .status_for_url(&url)
                .unwrap()
                .last_outcome,
            LastOutcome::Ok
        ));
    }

    // ── classify_fetch_error (tests-offline-cdn) ────────────────────

    /// A dead-host / proxy-fault outage (2026-07-23 `lists.purge.cc`) and a
    /// slow peer under load both used to render as the same opaque
    /// `"error sending request for url ..."` text. This asserts the
    /// connect-refused case is now labelled distinctly. Offline-safe: binds
    /// a local port then drops the listener before connecting, so nothing
    /// leaves the host.
    #[tokio::test]
    async fn classify_fetch_error_labels_connection_refused() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener); // nothing listens on `addr` anymore

        let client = reqwest::Client::new();
        let err = client
            .get(format!("http://{addr}/x"))
            .send()
            .await
            .unwrap_err();

        let msg = classify_fetch_error(&err);
        assert!(
            msg.starts_with("connection refused"),
            "expected a connection-refused label, got: {msg}"
        );
    }

    /// Same distinguishability check for the timeout case: a peer that
    /// accepts the connection but never responds must be labelled
    /// "timeout", not the same generic text as a refused connection.
    #[tokio::test]
    async fn classify_fetch_error_labels_timeout() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Accept the connection and then just hold it open, sending nothing.
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            std::mem::forget(stream); // keep the socket open, never respond
        });

        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(100))
            .build()
            .unwrap();
        let err = client
            .get(format!("http://{addr}/x"))
            .send()
            .await
            .unwrap_err();

        let msg = classify_fetch_error(&err);
        assert!(
            msg.starts_with("timeout"),
            "expected a timeout label, got: {msg}"
        );
        assert!(
            msg.contains("peer did not respond"),
            "a silent peer must keep the peer-side label, got: {msg}"
        );
    }

    /// The body-phase sibling. A peer that answers promptly and then streams
    /// too slowly must NOT be described as one that "did not respond" — that
    /// text sent a real diagnosis to the wrong end of the wire while four
    /// 100-180 MB lists failed every refresh on a 1 MB/s link.
    ///
    /// The distinguishing needle is the phrase, not merely the word
    /// "timeout": both branches start with it, so asserting `starts_with`
    /// would pass on the very bug this pins.
    #[tokio::test]
    async fn classify_fetch_error_labels_body_stream_timeout_distinctly() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Answer immediately, promise a body, then never finish sending it.
        tokio::spawn(async move {
            let (mut stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf).await;
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\nabc")
                .await;
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(300))
            .build()
            .unwrap();
        let resp = client
            .get(format!("http://{addr}/list.txt"))
            .send()
            .await
            .expect("headers arrive promptly");
        let err = resp
            .bytes()
            .await
            .expect_err("the body never completes within 300ms");

        assert!(err.is_timeout(), "expected a timeout, got: {err}");
        let msg = classify_fetch_error(&err);
        assert!(
            msg.contains("streaming the response body"),
            "expected the body-stream label, got: {msg}"
        );
        assert!(
            !msg.contains("peer did not respond"),
            "the peer DID respond — that label is false here: {msg}"
        );
    }

    // ── Shard-spill producer (§11 T3) ─────────────────────────────────

    /// A manager whose sources are all served from the `imported.local`
    /// bridge, so a refresh can be driven end-to-end with byte-exact
    /// bodies and no HTTP. Returns the manager, the source URLs in bit
    /// order, and the temp dir (kept alive by the caller).
    fn spill_manager(bodies: &[&str]) -> (ListManager, Vec<String>, tempfile::TempDir) {
        spill_manager_with_cap(bodies, DEFAULT_MAX_LIST_ENTRIES)
    }

    /// [`spill_manager`] with an explicit per-list entry cap, so a test can
    /// drive the cap's fail-closed path on a six-line fixture instead of a
    /// ten-million-line one. The cap the refresh path reads is the
    /// manager's own field — `Blocklist::max_entries` below is inert here.
    fn spill_manager_with_cap(
        bodies: &[&str],
        max_entries: usize,
    ) -> (ListManager, Vec<String>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let lists_dir = dir.path().join("lists");
        std::fs::create_dir_all(&lists_dir).unwrap();
        let cache_dir = dir.path().join("cache");
        std::fs::create_dir_all(&cache_dir).unwrap();

        let mut urls = Vec::new();
        let mut blocklists = Vec::new();
        for (i, body) in bodies.iter().enumerate() {
            let name = format!("src{i}");
            std::fs::write(lists_dir.join(format!("{name}.txt")), body).unwrap();
            let url = format!("https://imported.local/{name}.txt");
            blocklists.push(crate::config::schema::Blocklist {
                id: crate::config::schema::id::Id::new(&name).unwrap(),
                display_name: name.clone(),
                url: url.clone(),
                format: Default::default(),
                update_interval_hours: 12,
                max_entries: 5_000_000,
                enabled: true,
                auth_token_ref: None,
                base: crate::config::schema::BlocklistBase::Deny,
                trust: BlocklistTrust::Local,
                accept_unsigned_allow: false,
                max_consecutive_failures: 5,
            });
            urls.push(url);
        }

        let bits = build_source_bit_map(&urls).expect("at-cap accept");
        let mut mgr = ListManager::new(
            reqwest::Client::new(),
            Arc::new(FilterEngine::new()),
            urls.clone(),
            Catalog::fallback(),
            Duration::from_secs(3600),
            bits,
            TEST_CAP,
            max_entries,
            Some(cache_dir),
        );
        mgr.set_local_bridge(SourceTrustMap::build(&blocklists), dir.path().to_path_buf());
        (mgr, urls, dir)
    }

    /// A manager whose sources are ordinary remote URLs already present in
    /// the on-disk cache, with in-memory entries stamped `fetched_at`.
    ///
    /// This is the harness for anything that exercises the **fresh-cache
    /// arm** or the T3 probe, and it exists because `spill_manager` cannot:
    /// its sources go through the `imported.local` bridge, which returns
    /// before any cache entry is created and therefore never takes the
    /// freshness shortcut at all (see `download_list`). A test built on the
    /// bridge would either not reach the arm, or reach it only because
    /// something stamped `fetched_at` that should not have — which is
    /// exactly the regression that broke three `retention_guard_*` tests.
    ///
    /// No HTTP is possible here and none should happen: every source is
    /// cache-fresh, so the loop must never reach `download_list`. If a
    /// change makes it fall through, the test fails with a network error
    /// rather than passing quietly — a loud failure, which is what we want
    /// from a harness whose whole point is "the request was not made".
    fn cached_manager(bodies: &[&str]) -> (ListManager, Vec<String>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let cache_dir = dir.path().join("cache");
        std::fs::create_dir_all(&cache_dir).unwrap();

        let urls: Vec<String> = (0..bodies.len())
            .map(|i| format!("https://lists.invalid/src{i}.txt"))
            .collect();
        let bits = build_source_bit_map(&urls).expect("at-cap accept");
        let mut mgr = ListManager::new(
            reqwest::Client::new(),
            Arc::new(FilterEngine::new()),
            urls.clone(),
            Catalog::fallback(),
            Duration::from_secs(3600),
            bits,
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            Some(cache_dir.clone()),
        );
        for (url, body) in urls.iter().zip(bodies) {
            write_cache_to_disk(&cache_dir, url, body, None, None, OffsetDateTime::now_utc());
            mgr.cache.insert(
                url.clone(),
                ListCache {
                    etag: None,
                    last_modified: None,
                    body: None,
                    fetched_at: OffsetDateTime::now_utc(),
                },
            );
        }
        (mgr, urls, dir)
    }

    /// Rewrite a cached source's body on disk, keeping `.meta` consistent
    /// so the §4.7-T3 size check still accepts it.
    fn rewrite_cached_body(dir: &tempfile::TempDir, url: &str, body: &str) {
        write_cache_to_disk(
            &dir.path().join("cache"),
            url,
            body,
            None,
            None,
            OffsetDateTime::now_utc(),
        );
    }

    /// The precondition three `retention_guard_*` tests state in their own
    /// comments, pinned so it cannot be "fixed" again.
    ///
    /// An `imported.local` source must be re-read from the operator's file
    /// on every cycle. `mem2608-t0` briefly stamped `fetched_at` on that
    /// arm — reasoning that a source which never records a validation time
    /// is an oversight — and the stamp created a cache entry, which armed
    /// the freshness shortcut, which meant a poisoned local body was never
    /// re-read and the retention guard never saw it. Every gate said `Ok`.
    ///
    /// The absence of that stamp is load-bearing, not an oversight.
    #[tokio::test]
    async fn a_bridge_source_never_takes_the_freshness_shortcut() {
        let (mut mgr, urls, dir) = spill_manager(&["a.example\n"]);
        assert_eq!(mgr.refresh().await, 1);
        assert!(
            !mgr.cache.contains_key(&urls[0]),
            "the bridge arm created a cache entry — that arms the freshness shortcut for a \
             local file, so the operator's next edit goes unseen and a poisoned body never \
             reaches the retention guard"
        );

        // The operator edits the file; the very next cycle must see it,
        // with no interval to wait out.
        std::fs::write(
            dir.path().join("lists").join("src0.txt"),
            "a.example\nb.example\n",
        )
        .unwrap();
        assert_eq!(
            mgr.refresh().await,
            2,
            "an edited local list was not re-read on the next cycle"
        );
    }

    /// The partition and the probe must agree.
    ///
    /// `FilterEngine::shard_index` is seeded per process, and the engine
    /// probes exactly the shard it names — so a producer that routed a
    /// domain anywhere else stores it where nothing will ever look. That
    /// failure is invisible to a `domain_count()` assertion (the entry
    /// exists, it is just unreachable) and shows up only as a lookup miss.
    #[tokio::test]
    async fn refresh_routes_every_domain_to_the_shard_the_engine_probes() {
        let a = "alpha.example\nbeta.example\nshared.example\n";
        let b = "gamma.example\nshared.example\ndelta.example\n";
        let (mut mgr, _urls, _dir) = spill_manager(&[a, b]);

        let total = mgr.refresh().await;
        assert_eq!(total, 5, "alpha/beta/gamma/delta/shared, shared deduped");
        assert_eq!(mgr.filter.domain_count(), 5);

        for d in [
            "alpha.example",
            "beta.example",
            "gamma.example",
            "delta.example",
            "shared.example",
        ] {
            let masks = mgr.filter.list_membership(d);
            assert!(
                !masks.is_empty(),
                "{d} was spilled but is unreachable — producer and engine disagree on its shard"
            );
        }
        // A domain nobody listed must still miss, or the assertion above
        // would pass for a map that matched everything.
        assert!(mgr.filter.list_membership("absent.example").is_empty());

        // Bits are per source and OR together on the shared domain.
        let shared = mgr.filter.list_membership("shared.example");
        assert_eq!(
            shared.block_mask.count_ones(),
            2,
            "shared.example must carry both sources' bits"
        );
        assert_eq!(shared.allow_mask, 0, "block_only semantics preserved");
    }

    /// Spill files are a per-process artefact and must never outlive the
    /// cycle that wrote them.
    #[tokio::test]
    async fn refresh_leaves_no_spill_behind() {
        let (mut mgr, _urls, dir) = spill_manager(&["a.example\nb.example\n"]);
        let spill_dir = dir.path().join("cache").join(SHARD_SPILL_DIR);
        mgr.refresh().await;
        assert!(
            !spill_dir.exists(),
            "spill dir survived the cycle that created it"
        );
    }

    /// A partition written by a previous process is garbage to this one —
    /// `shard_index` reseeds, so ~15/16 of it would land in the wrong
    /// shard. It must be deleted both at construction and on cycle entry,
    /// never resumed.
    #[tokio::test]
    async fn stale_spill_is_purged_and_never_resumed() {
        let dir = tempfile::tempdir().unwrap();
        let cache_dir = dir.path().join("cache");
        let spill_dir = cache_dir.join(SHARD_SPILL_DIR);
        std::fs::create_dir_all(&spill_dir).unwrap();
        // A plausible-looking spill from a crashed daemon.
        let stale = spill_dir.join(spill_file_name(3));
        std::fs::write(&stale, b"\xffgarbage-from-a-dead-process").unwrap();
        // A file this module never creates must be left alone — cleanup
        // deletes constructed names only, never the directory wholesale.
        let foreign = spill_dir.join("not-ours.txt");
        std::fs::write(&foreign, b"keep me").unwrap();

        let urls = vec!["https://example.invalid/list.txt".to_string()];
        let bits = build_source_bit_map(&urls).expect("at-cap accept");
        let _mgr = ListManager::new(
            reqwest::Client::new(),
            Arc::new(FilterEngine::new()),
            urls,
            Catalog::fallback(),
            Duration::from_secs(3600),
            bits,
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            Some(cache_dir),
        );

        assert!(!stale.exists(), "stale spill survived construction");
        assert!(
            foreign.exists(),
            "cleanup deleted a file it did not create — scoping is wrong"
        );
    }

    /// `entries` is the source's *net-new* contribution in iteration
    /// order — the `merged.len()` delta the flat producer reported. With
    /// shard-at-a-time that number only exists in pass 2, so this pins
    /// that it is still reconstructed exactly rather than quietly
    /// replaced by the source's own deduped count.
    #[tokio::test]
    async fn entries_still_counts_only_net_new_domains() {
        let a = "one.example\ntwo.example\n";
        let b = "two.example\nthree.example\n";
        let (mut mgr, urls, _dir) = spill_manager(&[a, b]);
        mgr.refresh().await;

        let s0 = mgr.status_registry.status_for_url(&urls[0]).unwrap();
        let s1 = mgr.status_registry.status_for_url(&urls[1]).unwrap();

        assert_eq!(s0.entries, 2, "first source contributes both its domains");
        assert_eq!(
            s1.entries, 1,
            "two.example was already in the map — only three.example is net-new"
        );
        // unique_domains is order-independent and counts each source's own
        // deduped contribution, so both sources report 2.
        assert_eq!(s0.unique_domains, 2);
        assert_eq!(s1.unique_domains, 2);
    }

    /// The retention guard trips on `unique_domains`, which must stay
    /// immune to a body that repeats one domain N times. The frozen
    /// [`DomainSink::accept`] hands the skeleton no way to learn a domain
    /// was already seen, so the skeleton cannot compute this — the sink
    /// does, and this is what proves it.
    #[tokio::test]
    async fn unique_domains_ignores_in_list_duplicates() {
        let body = "dup.example\ndup.example\ndup.example\nother.example\n";
        let (mut mgr, urls, _dir) = spill_manager(&[body]);
        mgr.refresh().await;

        let s = mgr.status_registry.status_for_url(&urls[0]).unwrap();
        assert_eq!(
            s.unique_domains, 2,
            "three copies of dup.example are one unique domain"
        );
        assert_eq!(
            s.parsed_ok, 4,
            "parsed_ok stays pre-dedup — that difference is the point"
        );
        assert_eq!(mgr.filter.domain_count(), 2);
    }

    /// The entry cap must count domains, never candidate lines.
    ///
    /// A Hosts body carries rows a format extractor discards outright: an
    /// IPv6 line with no `0.0.0.0`/`127.0.0.1` prefix, a loopback alias, a
    /// broadcast row. None of them is a domain the source contributes, so
    /// none may be charged against its cap. Counting them meant a body
    /// whose real domain count sat *at or under* the cap could still push
    /// the "dropped" tally above zero — and since the cap became
    /// fail-closed, above zero refuses the **whole source**: spill rolled
    /// back, previous generation retained, that blocklist gone from the
    /// merged map until an operator noticed.
    ///
    /// Driven through `refresh()` on purpose. The counter that had this
    /// defect lived in a private copy of the parse skeleton that only
    /// `refresh()` reached, so every test that hand-built a `ShardSpill`
    /// and called the inner function was blind to it by construction —
    /// which is how a silent 19% corpus drop shipped with a green suite.
    #[tokio::test]
    async fn refresh_installs_a_hosts_source_whose_noise_lines_reach_the_cap() {
        use crate::lists::status::LastOutcome;
        // Three accepted lines meet a cap of three exactly — the duplicate
        // keeps the *unique* domain count at two, strictly under it. The
        // three rows that follow are pure hosts noise.
        let body = concat!(
            "0.0.0.0 alpha.example\n",
            "0.0.0.0 alpha.example\n",
            "0.0.0.0 beta.example\n",
            "::1 ip6-localhost\n",
            "127.0.0.1 localhost\n",
            "255.255.255.255 broadcast\n",
        );
        let (mut mgr, urls, _dir) = spill_manager_with_cap(&[body], 3);
        let count = mgr.refresh().await;

        let s = mgr.status_registry.status_for_url(&urls[0]).unwrap();
        // This is the load-bearing assertion. `parsed_truncated` below is
        // NOT: the refusal path builds its status with
        // `ListStatus::from_failure`, which carries the *previous* cycle's
        // counters forward, so the fresh over-count never reaches the
        // registry and that field reads 0 on broken code too.
        assert_eq!(
            s.last_outcome,
            LastOutcome::Ok,
            "the source was refused whole over lines that carry no domain"
        );
        assert_eq!(count, 2, "both unique domains must reach the merged map");
        assert!(mgr.filter.is_blocked("alpha.example"));
        assert!(mgr.filter.is_blocked("beta.example"));
        assert_eq!(s.parsed_ok, 3, "the duplicate line still parses");
        assert_eq!(s.unique_domains, 2, "under the cap of 3, not at it");
        assert_eq!(
            s.parsed_truncated, 0,
            "an installed source under its cap must report nothing dropped"
        );
    }

    /// The control arm for the test above: when the domains *themselves*
    /// run past the cap the source must still be refused whole. Without
    /// this, "count domains, not lines" could be satisfied by a counter
    /// that never fires at all.
    #[tokio::test]
    async fn refresh_refuses_a_hosts_source_whose_domains_exceed_the_cap() {
        use crate::lists::status::LastOutcome;
        let body = concat!(
            "0.0.0.0 one.example\n",
            "0.0.0.0 two.example\n",
            "0.0.0.0 three.example\n",
            "0.0.0.0 four.example\n",
            "0.0.0.0 five.example\n",
        );
        let (mut mgr, urls, _dir) = spill_manager_with_cap(&[body], 3);
        let count = mgr.refresh().await;

        assert_eq!(count, 0, "a source over its cap must be refused whole");
        assert!(!mgr.filter.is_blocked("one.example"));
        let s = mgr.status_registry.status_for_url(&urls[0]).unwrap();
        match &s.last_outcome {
            LastOutcome::Failed { reason } => assert!(
                reason.contains("max_entries"),
                "the refusal must name the knob to raise: {reason}"
            ),
            other => panic!("expected a cap refusal, got {other:?}"),
        }
    }

    /// A reader that fails mid-body must leave the spill byte-identical to
    /// its pre-call state.
    ///
    /// This is the invariant `read_to_string` used to provide for free by
    /// failing before the parse began. Without it a truncated download
    /// ingests partially and can read as a legitimate sub-threshold
    /// shrink, ratcheting the retention guard's baseline down on exactly
    /// the supply-chain failure the guard exists to catch.
    #[test]
    fn partial_stream_error_rolls_the_spill_back() {
        /// Yields `head`, then errors — a truncated body, not a short one.
        struct FailAfter {
            head: std::io::Cursor<Vec<u8>>,
        }
        impl Read for FailAfter {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                match self.head.read(buf)? {
                    0 => Err(std::io::Error::other("simulated mid-body I/O failure")),
                    n => Ok(n),
                }
            }
        }
        impl BufRead for FailAfter {
            fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
                if self.head.position() as usize >= self.head.get_ref().len() {
                    return Err(std::io::Error::other("simulated mid-body I/O failure"));
                }
                self.head.fill_buf()
            }
            fn consume(&mut self, amt: usize) {
                self.head.consume(amt);
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let mut spill = ShardSpill::open(Some(dir.path()));
        assert!(spill.is_disk(), "test must exercise the disk path");

        // A first, complete source.
        let good = std::io::Cursor::new(b"kept.example\n".to_vec());
        parse_source_into_spill(
            good,
            1,
            &mut spill,
            100,
            "good",
            Some(ListFormat::DomainOnly),
        )
        .expect("complete body parses");
        let after_good = spill.mark();

        // A second source that dies part-way through.
        let bad = FailAfter {
            head: std::io::Cursor::new(b"dropped.example\nalso-dropped.example\n".to_vec()),
        };
        let err =
            parse_source_into_spill(bad, 2, &mut spill, 100, "bad", Some(ListFormat::DomainOnly))
                .expect_err("a mid-body failure must surface");
        assert_eq!(err.kind(), std::io::ErrorKind::Other);

        assert_eq!(
            spill.mark(),
            after_good,
            "the failed source left bytes in the spill"
        );

        // And the built shards contain only the first source.
        spill.flush().unwrap();
        let mut added = [0u64; 64];
        let mut found = Vec::new();
        let policy = ListPolicy::publish_uniform(0);
        for idx in 0..DOMAIN_SHARDS {
            let shard = spill.build_shard(idx, 4, &mut added, &policy).unwrap();
            for (d, bits) in shard.iter() {
                found.push((d.to_string(), shard.split_base(bits).block_mask));
            }
        }
        assert_eq!(found, vec![("kept.example".to_string(), 1)]);
    }

    /// neutrality-06 — a source whose blocklist row carries `base = allow`
    /// must contribute to `allow_mask`, never to `block_mask`.
    ///
    /// Before this test the shard builder stamped
    /// `DomainMasks::block_only(bit)` on every entry regardless of
    /// direction, so an allow-direction list did not merely fail to allow:
    /// it **blocked** the domains it was imported to permit. Direction is a
    /// per-source property, so it rides in as a bitmask of allow-direction
    /// bits — the spill record format is unchanged.
    #[test]
    fn neutrality06_allow_direction_source_populates_allow_mask() {
        let dir = tempfile::tempdir().unwrap();
        let mut spill = ShardSpill::open(Some(dir.path()));

        // bit 0 — a deny list carrying two domains.
        parse_source_into_spill(
            std::io::Cursor::new(b"shared.example\nblocked.example\n".to_vec()),
            1 << 0,
            &mut spill,
            100,
            "deny-list",
            Some(ListFormat::DomainOnly),
        )
        .unwrap();

        // bit 1 — an allow list that re-opens one of them.
        parse_source_into_spill(
            std::io::Cursor::new(b"shared.example\n".to_vec()),
            1 << 1,
            &mut spill,
            100,
            "allow-list",
            Some(ListFormat::DomainOnly),
        )
        .unwrap();

        spill.flush().unwrap();

        let allow_bits: u64 = 1 << 1;
        let mut added = [0u64; 64];
        let mut found: HashMap<String, DomainMasks> = HashMap::new();
        let policy = ListPolicy::publish_uniform(allow_bits);
        for idx in 0..DOMAIN_SHARDS {
            let shard = spill.build_shard(idx, 4, &mut added, &policy).unwrap();
            for (d, bits) in shard.iter() {
                found.insert(d.to_string(), shard.split_base(bits));
            }
        }

        let shared = found
            .get("shared.example")
            .copied()
            .expect("shared.example must be present");
        assert_eq!(
            shared.allow_mask, 0b10,
            "the allow-direction source's bit belongs in allow_mask"
        );
        assert_eq!(
            shared.block_mask, 0b01,
            "the deny-direction source's bit belongs in block_mask"
        );

        let blocked = found
            .get("blocked.example")
            .copied()
            .expect("blocked.example must be present");
        assert_eq!(
            blocked.allow_mask, 0,
            "a domain no allow list carries must have an empty allow_mask"
        );
        assert_eq!(blocked.block_mask, 0b01);
    }

    /// Direction routing must not depend on the order sources reach the
    /// spill — and an allow-direction source must be able to create an
    /// entry, not only decorate one that a deny source already made.
    ///
    /// `build_shard`'s insert closure has two arms: a *vacant* arm that
    /// stamps the direction on a brand-new entry, and an *occupied* arm
    /// that ORs a bit into the existing entry. The sibling test above
    /// spills the deny source first, so its allow bit only ever reaches
    /// the occupied arm and the vacant arm is only ever exercised with a
    /// block bit. This test spills the **allow source first**, which:
    ///
    ///   - drives the contested domain through the mirror path (vacant
    ///     with an allow bit, then occupied with a block bit), and
    ///   - covers a domain carried *only* by the allow source, the one
    ///     shape that reaches `v.insert` with `allow_mask` non-zero.
    ///
    /// That second case is what a regression to unconditional
    /// `block_only` stamping would hit first: a pure allow-list domain
    /// would come back blocked, which is the exact neutrality-06 defect.
    #[test]
    fn allow_direction_routing_survives_reversed_spill_order() {
        let dir = tempfile::tempdir().unwrap();
        let mut spill = ShardSpill::open(Some(dir.path()));

        // bit 1 — the allow list, spilled FIRST this time.
        parse_source_into_spill(
            std::io::Cursor::new(b"shared.example\nallow-only.example\n".to_vec()),
            1 << 1,
            &mut spill,
            100,
            "allow-list",
            Some(ListFormat::DomainOnly),
        )
        .unwrap();

        // bit 0 — the deny list, arriving after.
        parse_source_into_spill(
            std::io::Cursor::new(b"shared.example\nblocked.example\n".to_vec()),
            1 << 0,
            &mut spill,
            100,
            "deny-list",
            Some(ListFormat::DomainOnly),
        )
        .unwrap();

        spill.flush().unwrap();

        let allow_bits: u64 = 1 << 1;
        let mut added = [0u64; 64];
        let mut found: HashMap<String, DomainMasks> = HashMap::new();
        let policy = ListPolicy::publish_uniform(allow_bits);
        for idx in 0..DOMAIN_SHARDS {
            let shard = spill.build_shard(idx, 4, &mut added, &policy).unwrap();
            for (d, bits) in shard.iter() {
                found.insert(d.to_string(), shard.split_base(bits));
            }
        }

        // The contested domain lands with BOTH masks populated regardless
        // of which source got there first.
        let shared = found
            .get("shared.example")
            .copied()
            .expect("shared.example must be present");
        assert_eq!(
            shared.allow_mask, 0b10,
            "allow-first ordering must still route the allow source's bit to allow_mask"
        );
        assert_eq!(
            shared.block_mask, 0b01,
            "the later deny source must OR its bit into block_mask, not overwrite the entry"
        );

        // A domain no deny source ever names: the vacant-insert allow arm.
        let allow_only = found
            .get("allow-only.example")
            .copied()
            .expect("allow-only.example must be present");
        assert_eq!(
            allow_only.allow_mask, 0b10,
            "a domain only an allow-direction source carries belongs in allow_mask"
        );
        assert_eq!(
            allow_only.block_mask, 0,
            "an allow-only domain must carry no block bits — stamping one here is \
             the neutrality-06 defect, where an allow list blocked what it should permit"
        );

        let blocked = found
            .get("blocked.example")
            .copied()
            .expect("blocked.example must be present");
        assert_eq!(blocked.allow_mask, 0);
        assert_eq!(blocked.block_mask, 0b01);
    }

    /// The in-RAM fallback (`cache_dir: None`, or an uncreatable spill
    /// dir) must partition identically to the disk path — it costs more
    /// memory, never different domains.
    #[test]
    fn memory_fallback_partitions_identically_to_disk() {
        let body = "one.example\ntwo.example\nthree.example\nfour.example\none.example\n";

        let build = |spill: &mut ShardSpill| {
            parse_source_into_spill(
                std::io::Cursor::new(body.as_bytes()),
                1,
                spill,
                100,
                "s",
                Some(ListFormat::DomainOnly),
            )
            .unwrap();
            spill.flush().unwrap();
            let mut added = [0u64; 64];
            let mut per_shard: Vec<Vec<String>> = Vec::new();
            let policy = ListPolicy::publish_uniform(0);
            for idx in 0..DOMAIN_SHARDS {
                let mut names: Vec<String> = spill
                    .build_shard(idx, 4, &mut added, &policy)
                    .unwrap()
                    .iter()
                    .map(|(k, _)| k.to_string())
                    .collect();
                names.sort();
                per_shard.push(names);
            }
            (per_shard, added)
        };

        let dir = tempfile::tempdir().unwrap();
        let mut disk = ShardSpill::open(Some(dir.path()));
        assert!(disk.is_disk());
        let mut mem = ShardSpill::open(None);
        assert!(!mem.is_disk());

        let (disk_shards, disk_added) = build(&mut disk);
        let (mem_shards, mem_added) = build(&mut mem);

        assert_eq!(disk_shards, mem_shards, "disk and memory partitions differ");
        assert_eq!(disk_added, mem_added);
        assert_eq!(
            disk_shards.iter().map(Vec::len).sum::<usize>(),
            4,
            "one.example appears twice in the body but once in the map"
        );
    }

    // ── The global corpus guard, driven through `refresh()` ───────────

    /// A manager that re-reads every body from the `imported.local` bridge
    /// on **every** cycle (zero refresh interval), so a test can change the
    /// corpus between refreshes instead of being served the disk cache.
    ///
    /// `on_disk == false` leaves `cache_dir` unset, which is what selects
    /// [`ShardSpill::Memory`] — the F14 divergence the DoD requires every
    /// case to cover.
    fn guard_manager(bodies: &[&str], on_disk: bool) -> (ListManager, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let lists_dir = dir.path().join("lists");
        std::fs::create_dir_all(&lists_dir).unwrap();
        let cache_dir = dir.path().join("cache");
        std::fs::create_dir_all(&cache_dir).unwrap();

        let mut urls = Vec::new();
        let mut blocklists = Vec::new();
        for (i, body) in bodies.iter().enumerate() {
            let name = format!("src{i}");
            std::fs::write(lists_dir.join(format!("{name}.txt")), body).unwrap();
            let url = format!("https://imported.local/{name}.txt");
            blocklists.push(crate::config::schema::Blocklist {
                id: crate::config::schema::id::Id::new(&name).unwrap(),
                display_name: name.clone(),
                url: url.clone(),
                format: Default::default(),
                update_interval_hours: 12,
                max_entries: 5_000_000,
                enabled: true,
                auth_token_ref: None,
                base: crate::config::schema::BlocklistBase::Deny,
                trust: BlocklistTrust::Local,
                accept_unsigned_allow: false,
                max_consecutive_failures: 5,
            });
            urls.push(url);
        }

        let bits = build_source_bit_map(&urls).expect("at-cap accept");
        let mut mgr = ListManager::new(
            reqwest::Client::new(),
            Arc::new(FilterEngine::new()),
            urls,
            Catalog::fallback(),
            // Note this does NOT become zero: `ListManager::new` clamps it
            // up to `MIN_REFRESH_INTERVAL` (60 s). A second cycle therefore
            // cannot be made to re-read by shortening the interval — see
            // `expire_bodies`.
            Duration::ZERO,
            bits,
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            on_disk.then(|| cache_dir.clone()),
        );
        mgr.set_local_bridge(SourceTrustMap::build(&blocklists), dir.path().to_path_buf());
        (mgr, dir)
    }

    /// Rewrite one bridge body in place, for a second cycle.
    fn rewrite_body(dir: &tempfile::TempDir, i: usize, body: &str) {
        std::fs::write(dir.path().join("lists").join(format!("src{i}.txt")), body).unwrap();
    }

    /// Drop the in-memory body cache so the next cycle re-reads the bridge.
    ///
    /// Needed only on the `cache_dir: None` (memory-spill) arm, and it is
    /// not a contrivance: with a cache dir the manager keeps **no**
    /// in-memory `cache` entry at all (bodies go to disk), so the freshness
    /// shortcut never fires and every cycle re-downloads. Without one the
    /// body is retained in memory and `MIN_REFRESH_INTERVAL` (60 s, clamped
    /// in `new`) makes it fresh, so a second cycle in the same test second
    /// would silently re-parse the *old* corpus and take the `unchanged`
    /// path. Calling this on both arms keeps them symmetric.
    fn expire_bodies(mgr: &mut ListManager) {
        mgr.cache.clear();
    }

    /// **The regression the reverted implementation caused.**
    ///
    /// `7611767` accumulated a *pre-dedup* line count and compared it to a
    /// ceiling derived from the *deduplicated* map. Live, that is
    /// Σ`parsed_ok` 29,542,862 against a merged unique 12,346,316 — a
    /// ~2.4× overlap — so the budget emptied mid-cycle and refused sources
    /// nowhere near any real limit.
    ///
    /// Here: 8 records pre-dedup, 5 distinct domains, ceiling 6. A guard
    /// measuring the pre-dedup sum refuses; a guard measuring the union
    /// accepts. **Driving `refresh()` end to end is the whole point** —
    /// the reverted code's own test carried four assertions and still
    /// could not see this, because it hand-built the budget struct and
    /// called `parse_source_into_spill` directly, so the real
    /// `spilled`-versus-ceiling computation was never exercised.
    #[tokio::test]
    async fn refresh_accepts_a_corpus_whose_pre_dedup_sum_exceeds_the_budget() {
        for on_disk in [true, false] {
            let (mut mgr, _dir) = guard_manager(
                &[
                    "a.example\nb.example\nc.example\nd.example\n",
                    "a.example\nb.example\nc.example\ne.example\n",
                ],
                on_disk,
            );
            // 8 records spilled, 5 distinct. The ceiling sits between them.
            mgr.set_max_total_domains(6);

            let total = mgr.refresh().await;

            assert_eq!(
                total, 5,
                "the union is 5 and fits under 6; only a pre-dedup count \
                 (8) refuses this (on_disk={on_disk})"
            );
            assert_eq!(mgr.filter.domain_count(), 5, "on_disk={on_disk}");
            for d in [
                "a.example",
                "b.example",
                "c.example",
                "d.example",
                "e.example",
            ] {
                assert!(
                    !mgr.filter.list_membership(d).is_empty(),
                    "{d} missing from the installed generation (on_disk={on_disk})"
                );
            }
            // A domain nobody listed must still miss, or the loop above
            // would pass against a map that matched everything.
            assert!(mgr.filter.list_membership("absent.example").is_empty());

            // And no source was blamed. This is the half the reverted code
            // got visibly wrong: it marked sources Failed for exceeding a
            // budget none of them had actually exhausted.
            use crate::lists::status::LastOutcome;
            let snap = mgr.status_registry.snapshot();
            assert_eq!(snap.len(), 2, "on_disk={on_disk}");
            for (source, st) in &snap {
                assert_eq!(
                    st.last_outcome,
                    LastOutcome::Ok,
                    "{source} was refused under a budget the corpus fits (on_disk={on_disk})"
                );
            }
            assert_eq!(
                snap.iter().map(|(_, s)| s.entries).sum::<u64>(),
                5,
                "per-source novel contributions must sum to the union"
            );
        }
    }

    /// The control arm: a ceiling **below** the union must refuse the whole
    /// cycle, keep the previous generation intact, and clear the digest.
    ///
    /// The digest assertion is the one with teeth. `installed_corpus_digest`
    /// is what lets a cycle decide "no body changed, skip the rebuild". Store
    /// this cycle's digest without having installed it and the next cycle
    /// computes the same digest, concludes nothing changed, and skips again —
    /// the daemon then serves a stale corpus silently and indefinitely, even
    /// after the operator raises the ceiling.
    ///
    /// Paired with a `ceiling = 10` arm so the refusal is shown to be caused
    /// by the ceiling rather than by anything else about the second cycle.
    #[tokio::test]
    async fn refresh_refuses_the_cycle_and_keeps_the_previous_generation() {
        const OLD: [&str; 5] = [
            "a.example",
            "b.example",
            "c.example",
            "d.example",
            "e.example",
        ];
        const NEW: [&str; 6] = [
            "f.example",
            "g.example",
            "h.example",
            "i.example",
            "j.example",
            "k.example",
        ];

        for on_disk in [true, false] {
            for ceiling in [4usize, 10] {
                let refuses = ceiling < NEW.len();
                let (mut mgr, dir) = guard_manager(
                    &[
                        "a.example\nb.example\nc.example\n",
                        "d.example\ne.example\n",
                    ],
                    on_disk,
                );

                // Cycle 1, guard disabled: establish a generation to keep.
                assert_eq!(mgr.refresh().await, 5, "on_disk={on_disk}");
                assert!(
                    mgr.installed_corpus_digest.is_some(),
                    "cycle 1 installed, so its digest must be stored"
                );
                let entries_before: Vec<u64> = mgr
                    .status_registry
                    .snapshot()
                    .iter()
                    .map(|(_, s)| s.entries)
                    .collect();

                // Cycle 2: a different, larger corpus.
                rewrite_body(&dir, 0, "f.example\ng.example\nh.example\n");
                rewrite_body(&dir, 1, "i.example\nj.example\nk.example\n");
                expire_bodies(&mut mgr);
                mgr.set_max_total_domains(ceiling);

                let total = mgr.refresh().await;

                if refuses {
                    assert_eq!(
                        total, 5,
                        "a refused cycle must report the generation still serving, \
                         not the one it measured and discarded (on_disk={on_disk})"
                    );
                    assert_eq!(mgr.filter.domain_count(), 5, "on_disk={on_disk}");
                    for d in OLD {
                        assert!(
                            !mgr.filter.list_membership(d).is_empty(),
                            "{d} was evicted by a refused cycle (on_disk={on_disk})"
                        );
                    }
                    for d in NEW {
                        assert!(
                            mgr.filter.list_membership(d).is_empty(),
                            "{d} from the refused corpus reached the engine (on_disk={on_disk})"
                        );
                    }
                    assert!(
                        mgr.installed_corpus_digest.is_none(),
                        "a refused cycle stored its digest — the next cycle would decide \
                         nothing changed and skip for ever (on_disk={on_disk})"
                    );

                    // The cycle-level refusal must actually reach the
                    // registry, which is what every reporting surface
                    // reads. Without this the assertions above are also
                    // satisfied by the `unchanged` fast path, which keeps
                    // the same generation for an entirely different reason
                    // — they cannot tell "refused" from "nothing to do".
                    let refusal = mgr
                        .status_registry
                        .corpus_refusal()
                        .expect("a refused cycle published no refusal state");
                    assert_eq!(refusal.unique, 6, "on_disk={on_disk}");
                    assert_eq!(refusal.ceiling, 4, "on_disk={on_disk}");
                    // Actionable: the operator has to be told which list
                    // to drop, per source, or the refusal is a dead end.
                    assert_eq!(refusal.novel_by_source.len(), 2, "on_disk={on_disk}");
                    assert_eq!(
                        refusal.novel_by_source.iter().map(|(_, n)| n).sum::<u64>(),
                        6,
                        "novel contributions must account for the whole refused corpus"
                    );
                    assert_eq!(
                        mgr.status_registry
                            .snapshot()
                            .iter()
                            .map(|(_, s)| s.entries)
                            .collect::<Vec<_>>(),
                        entries_before,
                        "`entries` must keep describing the generation that is serving \
                         (on_disk={on_disk})"
                    );
                } else {
                    // Same second cycle, same corpus, roomy ceiling: the
                    // refusal above is attributable to the ceiling alone.
                    assert_eq!(total, 6, "on_disk={on_disk}");
                    for d in NEW {
                        assert!(
                            !mgr.filter.list_membership(d).is_empty(),
                            "{d} missing under a roomy ceiling (on_disk={on_disk})"
                        );
                    }
                    assert!(mgr.installed_corpus_digest.is_some());
                    // Cleared on a successful install. A refusal left
                    // standing after a later cycle installs would be the
                    // same lie pointing the other way.
                    assert!(
                        mgr.status_registry.corpus_refusal().is_none(),
                        "an installed cycle left a refusal set (on_disk={on_disk})"
                    );
                }
            }
        }
    }

    /// The P0, end to end through `refresh()`: a **first** cycle over the
    /// ceiling must install, not come up serving nothing.
    ///
    /// Hit in production on 2026-08-05 during a routine restart. The
    /// daemon logged `serving=0`, then logged `DNS server listening` and
    /// answered every query — the house was entirely unfiltered and
    /// nothing loud said so. Every existing corpus-guard test through
    /// `refresh()` is cycle-1-installs → cycle-2-refuses, i.e. the
    /// hot-reload shape, in which "keep the previous generation" is both
    /// true and correct. **This is the first one that refuses on the
    /// first cycle**, which is the only shape the bug lives in.
    ///
    /// Both directions are asserted off the same corpus so the install is
    /// attributable to the ceiling and not to the corpus being small: 5
    /// domains install against a ceiling of 4, and refuse against a
    /// ceiling of 2, whose hard cap of 4 they are genuinely past.
    #[tokio::test]
    async fn a_cold_start_over_the_ceiling_installs_instead_of_serving_nothing() {
        const CORPUS: [&str; 5] = [
            "a.example",
            "b.example",
            "c.example",
            "d.example",
            "e.example",
        ];
        let bodies = [
            "a.example\nb.example\nc.example\n",
            "d.example\ne.example\n",
        ];

        for on_disk in [true, false] {
            // 5 over a ceiling of 4, hard cap 8: install anyway.
            let (mut mgr, _dir) = guard_manager(&bodies, on_disk);
            mgr.set_max_total_domains(4);

            assert_eq!(
                mgr.refresh().await,
                5,
                "a first cycle over the ceiling served nothing — there was no previous \
                 generation to keep, so the refusal unfiltered the whole network \
                 (on_disk={on_disk})"
            );
            for d in CORPUS {
                assert!(
                    !mgr.filter.list_membership(d).is_empty(),
                    "{d} never reached the engine on a cold start (on_disk={on_disk})"
                );
            }
            assert!(
                mgr.status_registry.corpus_refusal().is_none(),
                "a cycle that installed published a refusal (on_disk={on_disk})"
            );
            // An installed cycle stores its digest, so the next one can
            // still take the unchanged fast path.
            assert!(
                mgr.installed_corpus_digest.is_some(),
                "the over-ceiling install stored no digest (on_disk={on_disk})"
            );

            // Same corpus, ceiling 2, hard cap 4: genuinely past the cap,
            // so the refusal stands and is reported.
            let (mut mgr, _dir) = guard_manager(&bodies, on_disk);
            mgr.set_max_total_domains(2);

            assert_eq!(
                mgr.refresh().await,
                0,
                "past the hard cap the guard must still refuse (on_disk={on_disk})"
            );
            for d in CORPUS {
                assert!(
                    mgr.filter.list_membership(d).is_empty(),
                    "{d} was installed past the hard cap (on_disk={on_disk})"
                );
            }
            let refusal = mgr
                .status_registry
                .corpus_refusal()
                .expect("a refused cold start published no refusal state");
            assert_eq!(refusal.unique, 5, "on_disk={on_disk}");
            assert_eq!(refusal.ceiling, 2, "on_disk={on_disk}");
        }
    }

    /// All four bands off one spill, so each is shown to be reached by the
    /// ceiling alone rather than by anything else about the corpus.
    ///
    /// The 90 % band exists to warn *before* the wall, so the load-bearing
    /// assertion is that it still yields `Install`. And the threshold is a
    /// fraction of the **operator's** value: the 14,680,064 hash-table
    /// doubling point was a property of one representation on one box, and
    /// cabling it in would have made our hardware the product's upper limit.
    /// `mem-t6` has since removed that representation and with it the
    /// doubling point — which is the argument's own vindication, not a
    /// footnote to it: a constant hard-wired then would be wrong now.
    ///
    /// Every band here is measured with a generation **serving**, which is
    /// the case in which the ceiling is a wall. `serving` used to be read
    /// off the manager, where it was silently 0 — so this test asserted
    /// reload semantics while exercising the boot path. The boot bands are
    /// [`a_cold_start_has_no_generation_to_keep_so_the_ceiling_is_a_budget`].
    #[test]
    fn the_guard_bands_are_taken_against_the_operators_own_ceiling() {
        // Any non-zero count: the guard branches on "is anything
        // installed", never on how much.
        const SERVING: usize = 5;

        let dir = tempfile::tempdir().unwrap();
        let mut spill = ShardSpill::open(Some(dir.path()));
        let body: String = (0..9).map(|i| format!("d{i}.example\n")).collect();
        parse_source_into_spill(
            std::io::Cursor::new(body.into_bytes()),
            1,
            &mut spill,
            100,
            "s",
            Some(ListFormat::DomainOnly),
        )
        .unwrap();
        spill.flush().unwrap();

        let (mut mgr, _d) = guard_manager(&["ignored.example\n"], true);

        // 9 of 12 = 75 %: install, quietly.
        mgr.set_max_total_domains(12);
        assert!(
            matches!(
                mgr.corpus_guard(&spill, SERVING),
                CorpusVerdict::Install {
                    unique: 9,
                    warn: false,
                    ..
                }
            ),
            "75 % must not warn — the band would be noise at every ceiling"
        );

        // 9 of 10 = exactly 90 %: install, and warn.
        mgr.set_max_total_domains(10);
        assert!(
            matches!(
                mgr.corpus_guard(&spill, SERVING),
                CorpusVerdict::Install {
                    unique: 9,
                    warn: true,
                    ..
                }
            ),
            "the warn band must still INSTALL — it is a warning, not a second wall"
        );

        // 9 over 8: refuse.
        mgr.set_max_total_domains(8);
        assert!(matches!(
            mgr.corpus_guard(&spill, SERVING),
            CorpusVerdict::Refuse {
                unique: 9,
                ceiling: 8,
                ..
            }
        ));

        // Exactly at the ceiling is NOT over it.
        mgr.set_max_total_domains(9);
        assert!(
            matches!(
                mgr.corpus_guard(&spill, SERVING),
                CorpusVerdict::Install { unique: 9, .. }
            ),
            "refusal must be strictly greater than the ceiling"
        );

        // 0 disables. Not merely "never refuses" — `Unmeasured` is how the
        // counting pass is skipped, so a disabled guard costs nothing.
        mgr.set_max_total_domains(0);
        assert!(matches!(
            mgr.corpus_guard(&spill, SERVING),
            CorpusVerdict::Unmeasured
        ));
    }

    /// The boot bands, off one spill, as the mirror of
    /// [`the_guard_bands_are_taken_against_the_operators_own_ceiling`].
    ///
    /// With nothing serving, refusing does not keep anything — it installs
    /// nothing and the daemon answers unfiltered. So over the ceiling
    /// becomes install-and-shout, and the wall moves out to
    /// [`cold_start_hard_cap`]. Ten domains against ceilings of 12 / 8 / 5
    /// / 4 walks under, over, exactly at 2×, and past 2×, so each band is
    /// reached by the ceiling alone.
    #[test]
    fn a_cold_start_has_no_generation_to_keep_so_the_ceiling_is_a_budget() {
        // The whole discriminator. `refresh` passes
        // `self.filter.domain_count()`, which is 0 until a generation is
        // installed: the engine is built empty and the disk cache
        // restores ETag sidecars, never bodies.
        const NOTHING_SERVING: usize = 0;

        let dir = tempfile::tempdir().unwrap();
        let mut spill = ShardSpill::open(Some(dir.path()));
        let body: String = (0..10).map(|i| format!("d{i}.example\n")).collect();
        parse_source_into_spill(
            std::io::Cursor::new(body.into_bytes()),
            1,
            &mut spill,
            100,
            "s",
            Some(ListFormat::DomainOnly),
        )
        .unwrap();
        spill.flush().unwrap();

        let (mut mgr, _d) = guard_manager(&["ignored.example\n"], true);

        // Under the ceiling: boot changes nothing about the fitting case.
        mgr.set_max_total_domains(12);
        assert!(
            matches!(
                mgr.corpus_guard(&spill, NOTHING_SERVING),
                CorpusVerdict::Install { unique: 10, .. }
            ),
            "an empty filter must not perturb a corpus that fits"
        );

        // 10 over 8 — a refusal here is the P0: it keeps nothing and
        // serves nothing.
        mgr.set_max_total_domains(8);
        assert!(
            matches!(
                mgr.corpus_guard(&spill, NOTHING_SERVING),
                CorpusVerdict::InstallOverCeiling {
                    unique: 10,
                    ceiling: 8,
                    ..
                }
            ),
            "over the ceiling with nothing to fall back on must INSTALL, not serve zero"
        );

        // Exactly 2× the ceiling is NOT past the cap — the same
        // strictly-greater rule the ceiling itself uses.
        mgr.set_max_total_domains(5);
        assert!(
            matches!(
                mgr.corpus_guard(&spill, NOTHING_SERVING),
                CorpusVerdict::InstallOverCeiling { unique: 10, .. }
            ),
            "exactly at the hard cap must install; refusal is strictly past it"
        );

        // Past 2×: a real memory ceiling, refused as one.
        mgr.set_max_total_domains(4);
        assert!(
            matches!(
                mgr.corpus_guard(&spill, NOTHING_SERVING),
                CorpusVerdict::Refuse {
                    unique: 10,
                    ceiling: 4,
                    ..
                }
            ),
            "past the hard cap the guard must still refuse — the cap is the memory wall"
        );

        // A ceiling of 0 disables the guard before any of this is reached,
        // so the boot branch cannot resurrect a measurement the operator
        // turned off.
        mgr.set_max_total_domains(0);
        assert!(matches!(
            mgr.corpus_guard(&spill, NOTHING_SERVING),
            CorpusVerdict::Unmeasured
        ));
    }

    /// The same spill and ceiling decided both ways by `serving` alone.
    ///
    /// The two band tests above each hold one side fixed; this pins the
    /// **discriminator itself**, so a future change that reads boot-ness
    /// off something else — a generation counter, a boot flag — has to
    /// keep this exact contrast working.
    #[test]
    fn serving_is_the_only_thing_that_separates_the_two_over_ceiling_verdicts() {
        let dir = tempfile::tempdir().unwrap();
        let mut spill = ShardSpill::open(Some(dir.path()));
        let body: String = (0..10).map(|i| format!("d{i}.example\n")).collect();
        parse_source_into_spill(
            std::io::Cursor::new(body.into_bytes()),
            1,
            &mut spill,
            100,
            "s",
            Some(ListFormat::DomainOnly),
        )
        .unwrap();
        spill.flush().unwrap();

        let (mut mgr, _d) = guard_manager(&["ignored.example\n"], true);
        mgr.set_max_total_domains(8);

        assert!(
            matches!(
                mgr.corpus_guard(&spill, 0),
                CorpusVerdict::InstallOverCeiling { .. }
            ),
            "nothing serving → install"
        );
        assert!(
            matches!(mgr.corpus_guard(&spill, 1), CorpusVerdict::Refuse { .. }),
            "a single domain serving is a generation to keep → refuse, exactly as before"
        );
    }

    /// F3 through `refresh()`: the counting pass must not shift what each
    /// source reports as its contribution.
    ///
    /// `added_by_bit` is what feeds `entries`, and `build_shard` mutates
    /// it. Running a second pass over the same spill first is exactly the
    /// kind of change that perturbs it silently, so the disabled guard —
    /// which skips the pass entirely — is the control.
    #[tokio::test]
    async fn the_counting_pass_does_not_move_reported_entries() {
        let bodies = [
            "a.example\nb.example\nshared.example\n",
            "c.example\nshared.example\nd.example\n",
        ];

        let mut observed = Vec::new();
        for ceiling in [0usize, 1_000_000] {
            let (mut mgr, _dir) = guard_manager(&bodies, true);
            mgr.set_max_total_domains(ceiling);
            let total = mgr.refresh().await;
            let mut entries: Vec<(String, u64)> = mgr
                .status_registry
                .snapshot()
                .iter()
                .map(|(s, st)| (s.clone(), st.entries))
                .collect();
            entries.sort();
            observed.push((total, entries));
        }

        assert_eq!(
            observed[0], observed[1],
            "the counting pass changed reported entries"
        );
        // Pinned, so the equality above cannot be satisfied by both arms
        // being equally wrong.
        assert_eq!(observed[0].0, 5, "a,b,c,d,shared");
        assert_eq!(
            observed[0].1.iter().map(|(_, n)| n).sum::<u64>(),
            5,
            "net-new contributions must still sum to the map"
        );
    }

    // ── The counting pass (global corpus guard) ───────────────────────

    /// Two sources with real cross-source overlap, spilled in bit order.
    /// Pre-dedup 10 records, 8 distinct domains — the shape the whole
    /// guard exists to tell apart.
    fn overlapping_spill(spill: &mut ShardSpill) {
        parse_source_into_spill(
            std::io::Cursor::new(
                b"a.example\nb.example\nc.example\nshared1.example\nshared2.example\n".to_vec(),
            ),
            1,
            spill,
            100,
            "s0",
            Some(ListFormat::DomainOnly),
        )
        .unwrap();
        parse_source_into_spill(
            std::io::Cursor::new(
                b"d.example\ne.example\nshared1.example\nshared2.example\nf.example\n".to_vec(),
            ),
            2,
            spill,
            100,
            "s1",
            Some(ListFormat::DomainOnly),
        )
        .unwrap();
        spill.flush().unwrap();
    }

    /// F1: shards are hash-disjoint on the **domain alone**, so the
    /// per-shard unique counts sum to the exact global unique count. That
    /// is the load-bearing assumption of the whole design — if it were
    /// false the guard would need cross-shard reconciliation it does not
    /// do, and would silently under-count.
    ///
    /// Asserted against the build loop rather than against a hand-written
    /// constant, so the two producers cannot drift apart.
    #[test]
    fn count_unique_sums_to_the_build_loop_total_on_both_variants() {
        let check = |spill: &mut ShardSpill| {
            overlapping_spill(spill);

            let mut novel = [0u64; 64];
            let counted: u64 = (0..DOMAIN_SHARDS)
                .map(|idx| spill.count_unique(idx, &mut novel).unwrap())
                .sum();

            // The build loop is the reference implementation.
            let mut added = [0u64; 64];
            let policy = ListPolicy::publish_uniform(0);
            let built: usize = (0..DOMAIN_SHARDS)
                .map(|idx| {
                    spill
                        .build_shard(idx, 4, &mut added, &policy)
                        .unwrap()
                        .len()
                })
                .sum();

            assert_eq!(
                counted, built as u64,
                "counting pass and build loop disagree on the unique total"
            );
            assert_eq!(counted, 8, "a,b,c,d,e,f,shared1,shared2");
            // Pre-dedup is 10 records: a count that matched it would mean
            // the pass is not deduplicating at all — the reverted bug.
            assert_ne!(counted, 10, "counted the pre-dedup record count");
            assert_eq!(
                novel, added,
                "per-bit novelty must match what build_shard attributes"
            );
            assert_eq!(
                &novel[..2],
                &[5, 3],
                "first-occurrence wins, in spill order"
            );
        };

        let dir = tempfile::tempdir().unwrap();
        let mut disk = ShardSpill::open(Some(dir.path()));
        assert!(disk.is_disk(), "disk arm must exercise the disk path");
        check(&mut disk);

        let mut mem = ShardSpill::open(None);
        assert!(!mem.is_disk(), "memory arm must exercise the fallback");
        check(&mut mem);
    }

    /// F2: `build_shard` is destructive — it `remove_file`s the consumed
    /// spill and `mem::take`s the memory bucket. The counting pass runs
    /// *before* it on the same spill, so if it inherited either behaviour
    /// the generation built afterwards would be silently empty.
    ///
    /// This is the single easiest thing in the design to get wrong, so it
    /// is asserted against a control arm that never ran the count.
    #[test]
    fn count_unique_leaves_the_spill_intact_for_the_build_pass() {
        let harvest = |spill: &mut ShardSpill, count_first: bool| {
            overlapping_spill(spill);
            if count_first {
                let mut novel = [0u64; 64];
                for idx in 0..DOMAIN_SHARDS {
                    spill.count_unique(idx, &mut novel).unwrap();
                }
            }
            let mut added = [0u64; 64];
            let mut names: Vec<String> = Vec::new();
            let policy = ListPolicy::publish_uniform(0);
            for idx in 0..DOMAIN_SHARDS {
                names.extend(
                    spill
                        .build_shard(idx, 4, &mut added, &policy)
                        .unwrap()
                        .iter()
                        .map(|(k, _)| k.to_string()),
                );
            }
            names.sort();
            (names, added)
        };

        for is_disk in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let open = |sub: &str| {
                if is_disk {
                    let p = dir.path().join(sub);
                    std::fs::create_dir_all(&p).unwrap();
                    ShardSpill::open(Some(&p))
                } else {
                    ShardSpill::open(None)
                }
            };

            let mut counted = open("counted");
            let (with_count, added_with) = harvest(&mut counted, true);
            let mut control = open("control");
            let (without_count, added_without) = harvest(&mut control, false);

            assert_eq!(
                with_count.len(),
                8,
                "the count pass consumed the spill (is_disk={is_disk})"
            );
            assert_eq!(
                with_count, without_count,
                "counting changed what the build pass produced (is_disk={is_disk})"
            );
            // F3: `added_by_bit` feeds each source's reported `entries`.
            // The counting pass must not perturb it.
            assert_eq!(
                added_with, added_without,
                "the count pass moved added_by_bit (is_disk={is_disk})"
            );
        }
    }

    /// Fail-closed on a cap hit, at the spill producer: a refused source
    /// leaves the spill byte-identical, so the previous generation survives.
    ///
    /// Producer-level, so it cannot see what `refresh()` decides on top —
    /// the end-to-end arms are
    /// `refresh_installs_a_hosts_source_whose_noise_lines_reach_the_cap` and
    /// `refresh_refuses_a_hosts_source_whose_domains_exceed_the_cap`, and
    /// they are the ones that matter. Until S2 this module carried a private
    /// copy of `parse_list_streaming`, so a test at this level was blind to
    /// the counter the daemon actually ran: the live daemon dropped
    /// 2,370,261 domains while every parser test stayed green.
    #[test]
    fn spill_counts_the_entries_the_cap_drops() {
        let dir = tempfile::tempdir().unwrap();
        let mut spill = ShardSpill::open(Some(dir.path()));

        // Comment and blank lines past the cap must NOT inflate the count —
        // otherwise a list with a long trailing licence header reports
        // phantom truncation and step 3 would reject it outright.
        let body = b"a.example\nb.example\nc.example\nd.example\ne.example\n# trailing comment\n\n";

        // Seed a prior good source, so the rollback assertion below is
        // about *retaining* a previous generation rather than about an
        // empty spill trivially staying empty.
        parse_source_into_spill(
            std::io::Cursor::new(b"kept.example\n".to_vec()),
            1,
            &mut spill,
            100,
            "prior",
            Some(ListFormat::DomainOnly),
        )
        .expect("prior source parses");
        let after_prior = spill.mark();

        // Step 3: a source that exceeds its cap is refused WHOLE, not
        // ingested half-way.
        let err = parse_source_into_spill(
            std::io::Cursor::new(body.to_vec()),
            2,
            &mut spill,
            3,
            "capped",
            Some(ListFormat::DomainOnly),
        )
        .expect_err("a truncated list must be refused, not silently half-loaded");

        let msg = err.to_string();
        assert!(
            msg.contains('2'),
            "the reason must carry the dropped count so the operator can size the cap: {msg}"
        );
        assert!(
            msg.contains("max_entries"),
            "the reason must name the knob to change: {msg}"
        );
        assert_eq!(
            spill.mark(),
            after_prior,
            "the refused source left bytes in the spill — the prior generation was corrupted"
        );

        // Control arm: identical body, cap above the entry count. Proves
        // the refusal keys on truncation and not merely on this body.
        let mut spill_roomy = ShardSpill::open(Some(dir.path()));
        let (roomy, _) = parse_source_into_spill(
            std::io::Cursor::new(body.to_vec()),
            1,
            &mut spill_roomy,
            100,
            "roomy",
            Some(ListFormat::DomainOnly),
        )
        .expect("an untruncated body must still be accepted");

        assert_eq!(roomy.parsed_ok, 5);
        assert_eq!(
            roomy.parsed_truncated, 0,
            "an untruncated list must report zero"
        );
    }

    /// Every partition decision must route through
    /// [`FilterEngine::shard_index`]. A second implementation of
    /// `hash % 16` would disagree with the probe side silently, so this
    /// asserts the placement directly rather than trusting the call site.
    #[test]
    fn spill_places_each_domain_in_shard_index_s_shard() {
        let domains: Vec<String> = (0..500).map(|i| format!("host{i}.example")).collect();
        let body = format!("{}\n", domains.join("\n"));

        let dir = tempfile::tempdir().unwrap();
        let mut spill = ShardSpill::open(Some(dir.path()));
        parse_source_into_spill(
            std::io::Cursor::new(body.as_bytes()),
            1,
            &mut spill,
            10_000,
            "s",
            Some(ListFormat::DomainOnly),
        )
        .unwrap();
        spill.flush().unwrap();

        let mut added = [0u64; 64];
        let mut seen = 0usize;
        let policy = ListPolicy::publish_uniform(0);
        for idx in 0..DOMAIN_SHARDS {
            let shard = spill.build_shard(idx, 64, &mut added, &policy).unwrap();
            for (d, _) in shard.iter() {
                assert_eq!(
                    FilterEngine::shard_index(d),
                    idx,
                    "{d} was spilled to shard {idx} but the engine probes \
                     shard {}",
                    FilterEngine::shard_index(d)
                );
                seen += 1;
            }
        }
        assert_eq!(seen, domains.len());
    }

    /// §11 T5: a cycle whose list bodies are all byte-identical to the
    /// installed generation must not rebuild or swap; a cycle where one
    /// body changed must.
    #[tokio::test]
    async fn unchanged_corpus_skips_the_rebuild_and_a_changed_one_does_not() {
        let (mut mgr, _urls, dir) = spill_manager(&["a.example\nb.example\n"]);

        assert_eq!(mgr.refresh().await, 2);
        assert_eq!(mgr.rebuild_count, 1, "the first cycle must build the map");
        assert!(mgr.installed_corpus_digest.is_some());
        let digest_after_first = mgr.installed_corpus_digest;

        // Nothing touched the body: same bytes, same order, same settings.
        assert_eq!(mgr.refresh().await, 2, "the map still reports its size");
        assert_eq!(
            mgr.rebuild_count, 1,
            "an unchanged corpus rebuilt the map anyway — the T5 short-circuit did not fire"
        );
        assert_eq!(mgr.installed_corpus_digest, digest_after_first);
        // The map is intact, not merely un-rebuilt.
        assert!(!mgr.filter.list_membership("a.example").is_empty());
        assert_eq!(mgr.filter.domain_count(), 2);

        // One byte of one body changes -> the digest changes -> rebuild.
        std::fs::write(
            dir.path().join("lists").join("src0.txt"),
            "a.example\nb.example\nc.example\n",
        )
        .unwrap();
        // Expire the freshness shortcut so the bridge re-reads the file.
        for entry in mgr.cache.values_mut() {
            entry.fetched_at = OffsetDateTime::now_utc() - Duration::from_secs(86_400);
        }

        assert_eq!(mgr.refresh().await, 3);
        assert_eq!(
            mgr.rebuild_count, 2,
            "a changed body must force a rebuild — the short-circuit is not a cache"
        );
        assert_ne!(
            mgr.installed_corpus_digest, digest_after_first,
            "the digest must track the corpus"
        );
        assert!(!mgr.filter.list_membership("c.example").is_empty());
    }

    /// The T5 digest may only be stored when a generation actually reached
    /// the engine.
    ///
    /// Storing it after a cycle that installed nothing is the worst bug this
    /// lane can ship: the next cycle recomputes the same digest, concludes
    /// nothing changed, skips again — and the daemon serves a stale blocklist
    /// silently and indefinitely, even after the underlying failure clears.
    /// A cycle that parses nothing installs nothing, and is the cheap way to
    /// reach that state on purpose; a spill `flush` failing under ENOSPC is
    /// the way to reach it by accident.
    #[tokio::test]
    async fn digest_is_not_stored_when_nothing_was_installed() {
        let (mut mgr, _urls, _dir) = spill_manager(&["# nothing but a comment\n"]);

        assert_eq!(mgr.refresh().await, 0, "no domains to install");
        assert_eq!(
            mgr.rebuild_count, 0,
            "pass 2 must not run for an empty corpus"
        );
        assert!(
            mgr.installed_corpus_digest.is_none(),
            "a cycle that installed nothing recorded a digest — the next cycle would \
             match it, skip the rebuild, and pin a stale map forever"
        );
    }

    /// A `CacheOnly` boot whose sources are only partially backed by disk
    /// cache must still leave `installed_corpus_digest` valid.
    ///
    /// The no-usable-cache stop inside `refresh_with_mode`'s `CacheOnly`
    /// branch (see the comment on that arm) deliberately does not set
    /// `digest_valid = false`: that source's
    /// contribution is known to be zero, not unknown, so the digest still
    /// describes the corpus that was actually installed. Getting this
    /// wrong is not cosmetic — `installed_corpus_digest` is what lets the
    /// first background `Network` refresh decide "no body changed, skip
    /// the rebuild" instead of rebuilding, and skipping on a digest that
    /// does not actually describe the corpus is the failure this module's
    /// own comment calls "the daemon then serves a stale blocklist
    /// silently and indefinitely".
    ///
    /// Two sources, deliberately: `kept` has a `.cache` file and
    /// contributes a domain; `missing` has none. A single-source fixture
    /// cannot observe this property — with only one source there is no
    /// "some accounted for, some not" state, only "accounted for" or
    /// "nothing accounted for", and the latter (see
    /// `cache_only_with_no_disk_cache_makes_zero_http_calls`) never
    /// installs anything at all, so it can't tell a valid digest from a
    /// merely-absent one either.
    #[tokio::test]
    async fn cache_only_boot_with_partial_cache_coverage_keeps_digest_valid() {
        let dir = tempfile::tempdir().unwrap();

        let kept_url = "https://127.0.0.1/kept.txt".to_string();
        let stem = source_to_cache_stem(&kept_url);
        std::fs::write(
            dir.path().join(format!("{stem}.cache")),
            "kept.example.com\n",
        )
        .unwrap();
        let old = OffsetDateTime::now_utc() - time::Duration::days(30);
        std::fs::write(
            dir.path().join(format!("{stem}.meta")),
            format!(
                "etag=\nlast-modified=\nfetched-at={}\n",
                old.format(&Rfc3339).unwrap()
            ),
        )
        .unwrap();

        let missing_url = "https://127.0.0.1/missing.txt".to_string();
        // Deliberately no .cache / .meta written for this one — never
        // fetched, so `load_disk_cache` below leaves no in-memory entry
        // for it and it reaches the no-usable-cache stop by the "no
        // cache entry at all" route.

        let filter = Arc::new(FilterEngine::new());
        let urls = vec![kept_url.clone(), missing_url];
        let source_bits = build_source_bit_map(&urls).expect("at-cap accept");
        let mut mgr = ListManager::new(
            reqwest::Client::new(),
            filter.clone(),
            urls,
            Catalog::fallback(),
            Duration::from_secs(3600),
            source_bits,
            TEST_CAP,
            DEFAULT_MAX_LIST_ENTRIES,
            Some(dir.path().to_path_buf()),
        );
        mgr.load_disk_cache();

        let count = mgr.refresh_with_mode(RefreshMode::CacheOnly).await;

        // Sanity: the fixture exercises both routes it claims to — one
        // domain installed (from `kept`), nothing from `missing`.
        assert_eq!(count, 1, "only `kept` has a body to contribute");
        assert!(filter.is_blocked("kept.example.com"));

        // The assertion with teeth: restoring `digest_valid = false` on
        // the no-usable-cache arm makes this `None` instead, and every
        // first background refresh after a boot like this one would
        // rebuild the corpus it just finished loading, rather than only
        // rebuilding when something actually changed.
        assert!(
            mgr.installed_corpus_digest.is_some(),
            "a CacheOnly boot whose sources are all accounted for must leave the \
             digest valid — restoring `digest_valid = false` on the no-cache arm \
             makes this None and re-rebuilds every first background refresh"
        );
    }

    /// A `kind` flip must reach the map even when no body changed.
    ///
    /// `build_shard` routes by `allow_bits`, but until this fix the digest
    /// that decides whether `build_shard` runs at all did not include them.
    /// So `set_allow_bits` + reload on an unchanged corpus skipped the
    /// rebuild and the flip did nothing — silently, and in the
    /// allow→deny direction that means a revoked exemption keeps
    /// exempting.
    #[tokio::test]
    async fn flipping_a_list_direction_forces_a_rebuild_on_an_unchanged_corpus() {
        let (mut mgr, _urls, _dir) = spill_manager(&["a.example\n"]);
        assert_eq!(mgr.refresh().await, 1);
        assert_eq!(mgr.rebuild_count, 1);

        // Nothing about the bodies changes — only the operator's policy.
        mgr.set_list_policy(PolicyMasks {
            base: crate::filter::engine::ProfileMasks { allow: 1, block: 0 },
            ..PolicyMasks::default()
        });

        assert_eq!(mgr.refresh().await, 1);
        assert_eq!(
            mgr.rebuild_count, 2,
            "the direction flip did not rebuild — the map still routes this source the \
             way the previous policy said, and nothing tells the operator"
        );
        assert_eq!(
            mgr.probe_skips, 0,
            "and the probe must not settle a cycle whose policy inputs moved"
        );
    }

    // ── mem2608-s7: the no-cache_dir path ─────────────────────────────

    /// The warning has to name the cost, because a deployment that hits
    /// this gets no other signal — it simply uses more memory. A warning
    /// that said only "no cache directory configured" would be true and
    /// useless.
    #[test]
    fn the_cache_dir_warning_names_the_cost() {
        let w = LIST_CACHE_DIR_UNSET_WARNING;
        assert!(
            w.contains("RAM"),
            "the warning must say where the cost lands"
        );
        assert!(
            w.contains("double"),
            "the warning must quantify: an operator cannot act on 'uses more memory'"
        );
        assert!(
            w.contains("lists.cache_dir"),
            "and it must name the knob that fixes it"
        );
    }

    /// Retention is the chosen behaviour, not an accident — pin it so a
    /// later memory pass cannot "optimise" it into a coverage loss.
    ///
    /// Without a `cache_dir` the in-memory body is the **only** copy: drop
    /// it and the next 304, the next failed download, and every
    /// freshness-skip lose that source's domains entirely. Trading
    /// filtering coverage for RAM is the wrong trade for a filter, so the
    /// body stays and the warning carries the cost instead.
    #[tokio::test]
    async fn without_a_cache_dir_the_body_is_retained_deliberately() {
        let (mut mgr, urls, _dir) = spill_manager(&["a.example\n"]);
        mgr.cache_dir = None;

        assert_eq!(mgr.refresh().await, 1);
        assert!(
            mgr.cache
                .get(&urls[0])
                .and_then(|c| c.body.as_ref())
                .is_some(),
            "the body was dropped with no disk copy to fall back on — this source \
             stops filtering on the next cycle that does not download"
        );
    }

    // ── mem2608-s1 T1: one body copy, not two ─────────────────────────

    /// The single-copy property, pinned so the second copy cannot return.
    ///
    /// Capacity is the observable: `String::from_utf8` moves the `Vec`'s
    /// allocation, so the capacity survives; `from_utf8_lossy(&v)
    /// .into_owned()` builds a fresh buffer sized to the content. At the
    /// production 172 MB list the difference is 172 MB of transient
    /// resident memory, which is not something a unit test can weigh —
    /// but the copy that causes it is exactly what this measures.
    #[test]
    fn decode_body_reuses_the_download_buffer() {
        let mut body = Vec::with_capacity(4096);
        body.extend_from_slice(b"a.example\n");
        let decoded = decode_body(body);

        assert_eq!(decoded, "a.example\n");
        assert_eq!(
            decoded.capacity(),
            4096,
            "the decode allocated a second buffer — on a 172 MB list that is a full \
             second copy, live while the first is still borrowed"
        );
    }

    /// The lossy fallback still applies where it must, and only there.
    /// `read_bounded_body_lossy_keeps_list_on_bad_byte` covers the same
    /// property end-to-end through the HTTP path; this one pins the seam
    /// itself, so a future refactor of `read_bounded_body` cannot quietly
    /// turn a bad byte into a failed download.
    #[test]
    fn decode_body_falls_back_to_lossy_on_invalid_utf8() {
        let decoded = decode_body(vec![b'a', 0xff, b'\n']);
        assert!(
            decoded.contains('\u{FFFD}'),
            "invalid bytes must become U+FFFD, not fail the whole list"
        );
    }

    // ── mem2608-s1 T3: the fresh-cache probe ──────────────────────────

    /// The saving, stated as the property that produces it: a cycle whose
    /// sources are all cache-fresh and whose bodies are unchanged must not
    /// parse a single one of them.
    ///
    /// `rebuild_count` cannot express this — it is 1 on both sides of the
    /// fix, because the §11 T5 short-circuit already skipped pass 2. What
    /// changed is pass **1**, and the 220 MiB lives there.
    #[tokio::test]
    async fn an_all_fresh_cycle_parses_no_body() {
        let (mut mgr, _urls, _dir) = cached_manager(&["a.example\n", "b.example\n"]);

        assert_eq!(mgr.refresh().await, 2, "first cycle installs");
        assert_eq!(
            mgr.probe_skips, 0,
            "nothing is installed to compare against"
        );

        assert_eq!(mgr.refresh().await, 2, "the map still reports its size");
        assert_eq!(
            mgr.probe_skips, 1,
            "the probe did not fire on an all-fresh, unchanged cycle — every source was \
             re-parsed to rebuild a digest the daemon already held"
        );
        assert_eq!(mgr.rebuild_count, 1, "and pass 2 stayed skipped");
        assert_eq!(
            mgr.filter.domain_count(),
            2,
            "the map is intact, not merely unrebuilt"
        );
    }

    /// The probe reaches `PendingStatus` by a different route than the
    /// cache-hit arm, and must reach the same answer about `verified_fresh`.
    ///
    /// The invariant: **no `CacheOnly` cycle stamps a verified refresh, by
    /// any route.** The probe enforces `is_cache_fresh` itself, so it is
    /// tempting to call its sources verified even on a boot — but a cycle
    /// that issued no HTTP, and was never allowed to, reporting a refresh is
    /// the freshness lie `boot_list_persistence.md` §2.8 prohibits: a dead
    /// upstream reads green in the TUI.
    ///
    /// This exists because the two branches that produced the probe and the
    /// `verified_fresh` field never saw each other. The merge had to pick an
    /// answer, and an unpinned merge decision is one the next merge picks
    /// differently.
    ///
    /// Mutation caught: `verified_fresh: matches!(mode, Network)` at the
    /// probe's push site swapped for a bare `true` — the CacheOnly half goes
    /// red. (A bare `false` is caught by the Network half.)
    #[tokio::test]
    async fn the_probe_does_not_stamp_a_refresh_on_a_cache_only_cycle() {
        for (mode, expected) in [
            (RefreshMode::Network, true),
            (RefreshMode::CacheOnly, false),
        ] {
            let (mut mgr, urls, _dir) = cached_manager(&["a.example\n"]);
            assert_eq!(mgr.refresh().await, 1, "first cycle installs");

            let before = mgr
                .status_registry
                .status_for_url(&urls[0])
                .unwrap()
                .last_refresh_at;

            // Far enough ahead to be distinguishable, close enough that
            // `is_cache_fresh` still holds — or the probe returns None and
            // this test would pass for the wrong reason.
            let later = OffsetDateTime::now_utc() + std::time::Duration::from_secs(5);
            mgr.refresh_at_with_mode(later, mode).await;
            assert_eq!(
                mgr.probe_skips, 1,
                "fixture precondition: the probe must fire in {mode:?}, or this \
                 test is asserting about a path it never took"
            );

            let after = mgr
                .status_registry
                .status_for_url(&urls[0])
                .unwrap()
                .last_refresh_at;
            assert_eq!(
                after != before,
                expected,
                "in {mode:?} the probe should{} have stamped a refresh",
                if expected { "" } else { " NOT" }
            );
        }
    }

    /// The probe must be a check, not a cache. A body whose bytes changed
    /// but whose length did not — so `.meta`'s `size=` still validates —
    /// must still rebuild.
    ///
    /// This is why the digest is recomputed from the bodies rather than
    /// read from a `sha256=` sidecar line: a stored hash cannot see this
    /// edit, and a skipped rebuild would pin it in place. The `.cache`
    /// directory is a trust boundary (`cache_dir_lax_mode` warns about it),
    /// so "someone wrote to it" is a case with a threat model, not a
    /// hypothetical.
    #[tokio::test]
    async fn a_planted_cache_edit_of_identical_size_still_rebuilds() {
        let (mut mgr, urls, dir) = cached_manager(&["aaa.example\n"]);
        assert_eq!(mgr.refresh().await, 1);
        assert_eq!(mgr.rebuild_count, 1);

        // Same byte count, different bytes, straight into the trusted
        // cache — the sidecar's size= still matches.
        let stem = source_to_cache_stem(&urls[0]);
        let cache_path = dir.path().join("cache").join(format!("{stem}.cache"));
        let before = std::fs::metadata(&cache_path).unwrap().len();
        std::fs::write(&cache_path, "bbb.example\n").unwrap();
        assert_eq!(
            std::fs::metadata(&cache_path).unwrap().len(),
            before,
            "the fixture must keep the length identical or it proves nothing"
        );

        assert_eq!(mgr.refresh().await, 1, "one domain either way");
        assert_eq!(
            mgr.probe_skips, 0,
            "the probe accepted a body it had not read — it is a cache, not a check"
        );
        assert_eq!(
            mgr.rebuild_count, 2,
            "a planted edit did not force a rebuild"
        );
        assert!(
            !mgr.filter.list_membership("bbb.example").is_empty(),
            "the rebuilt map must reflect what is actually on disk"
        );
    }

    // ── mem2608-s1 T2: not counting must not mean counting zero ───────

    /// The saving itself: an arm that re-reads an unchanged body must not
    /// rebuild the ~144 MiB dedup set to reproduce a number it already has.
    ///
    /// Fails on the unfixed code, where every arm measures. src1 is held
    /// out of phase so the T3 probe cannot settle the cycle — otherwise
    /// this would pass for T3's reason instead of T2's, which is the same
    /// trap `an_all_fresh_cycle_parses_no_body` sets on purpose.
    #[tokio::test]
    async fn an_unchanged_body_is_not_re_counted() {
        let (mut mgr, urls, dir) = cached_manager(&["a.example\n", "solo.example\n"]);

        assert_eq!(mgr.refresh().await, 2);
        let after_first = SOURCES_MEASURED.with(|c| c.get());
        assert_eq!(
            after_first, 2,
            "the installing cycle must measure both sources — it has no prior count"
        );

        // One body changes on disk, so the probe cannot settle the cycle
        // and the walk runs. Both sources are still cache-fresh, so both
        // take the arm that re-reads a body whose count is already known.
        rewrite_cached_body(&dir, &urls[1], "solo.example\nextra.example\n");
        assert_eq!(mgr.refresh().await, 3);
        assert_eq!(
            mgr.probe_skips, 0,
            "the walk must have run for this to prove anything"
        );

        assert_eq!(
            SOURCES_MEASURED.with(|c| c.get()),
            after_first,
            "a body that did not change was counted again — that is the ~144 MiB T2 \
             removes, spent reproducing a number the previous cycle already recorded"
        );
    }

    /// The fail-open hazard T2 could have introduced, pinned.
    ///
    /// `compute_shrink_verdict` reads `unique_domains == 0` as *no
    /// baseline — accept anything*. So a cycle that stops measuring and
    /// writes `0` does not merely lose a statistic: it disarms the
    /// retention guard for the **next** download, which is the guard
    /// written after the 19 % silent-truncation incident. The carried
    /// count is a `NonZeroU64` for exactly this reason.
    ///
    /// The property is in the type, so it is tested in the type: a count
    /// may be carried only when it is a usable baseline, and zero is not.
    ///
    /// Tested here rather than end-to-end because the end-to-end route
    /// does not exist in-process: carrying happens on the fresh-cache /
    /// 304 / download-failure arms, and the shrink that would expose a
    /// disarmed guard has to arrive as a **200**, which no in-process test
    /// can produce (the URL guard refuses loopback and plain http, and the
    /// `imported.local` bridge deliberately never takes the fresh-cache
    /// arm). What survives is the exact hazard — a zero reaching
    /// `compute_shrink_verdict` as a baseline — asserted at the seam that
    /// decides it.
    #[test]
    fn a_zero_count_is_never_carried_forward() {
        // The state that would disarm the guard: a prior status whose
        // `unique_domains` is 0. `compute_shrink_verdict` reads that as
        // "no baseline — accept anything", so carrying it would let the
        // next 200 shrink a list by 99% and install.
        //
        // Spelled as a struct literal rather than `default()` + reassignment
        // so the two fields the test is *about* are visible at the binding,
        // and so `clippy::field_reassign_with_default` stays satisfied.
        // Still `mut`: the second half of the test reuses this binding. The
        // lint fires on `default()` *immediately* followed by assignment,
        // which the literal above already avoids — so `mut` is not a leftover.
        let mut prev = ListStatus {
            unique_domains: 0,
            prev_entries: None,
            ..Default::default()
        };
        assert!(
            matches!(
                UniqueCount::carry_or_measure(Some(&prev)),
                UniqueCount::Measure(_)
            ),
            "a zero was carried forward — the next download's shrink guard would then have \
             no baseline and accept anything, which is the 19% silent-truncation class"
        );
        assert!(
            matches!(
                compute_shrink_verdict(true, 90, Some(&prev), 0),
                ShrinkVerdict::Accept { .. }
            ),
            "this is why: a zero baseline accepts an empty body outright"
        );

        // A usable prior is carried, and carried exactly.
        prev.unique_domains = 5_000;
        match UniqueCount::carry_or_measure(Some(&prev)) {
            UniqueCount::Carried(n) => assert_eq!(n.get(), 5_000),
            other => panic!("a usable prior count must be carried, got {other:?}"),
        }

        // And the arm that must always measure does, prior or not.
        assert!(matches!(
            UniqueCount::measure(Some(&prev)),
            UniqueCount::Measure(Some(_))
        ));
        assert!(matches!(
            UniqueCount::measure(None),
            UniqueCount::Measure(None)
        ));
    }

    // ── mem2608-t0: the tick that could never fetch ───────────────────
    //
    // These drive the relationship the daemon has, not the predicate on
    // its own: a fixed-period tick, and a stamp written while the cycle
    // runs. `refresh_at` supplies the cycle anchor, so "the cycle began
    // 456 s ago" is expressible without waiting 456 s. 456 s is measured
    // — the 2026-08-15 13:22:52 cycle on the lab host took exactly that to
    // fetch its 14 lists.
    //
    // Written against `is_cache_fresh`'s call site rather than against
    // `is_cache_fresh`, because every unit-level formulation of this
    // property passes on the broken code: the bug is which instant gets
    // stamped, and a unit test hands that instant in ready-made.

    /// A tick one full interval after a cycle that took 456 s must
    /// re-fetch. On the pre-fix code the stamp is the download's
    /// completion, so the age at the next tick is `interval − 456 s`,
    /// `is_cache_fresh` says fresh, and the cycle reuses the cache — the
    /// effective interval doubles and the operator is told nothing.
    /// Which half of T0 actually makes the next tick fetch — asserted as a
    /// difference, because the two halves are not interchangeable and the
    /// tempting single-half fixes both fail here.
    ///
    /// A cycle ticks at `tick` and takes 456 s (measured: the lab host,
    /// 2026-08-15 13:22:52). The next fixed-period tick lands at
    /// `tick + interval`. The only thing that differs between the broken
    /// and the fixed daemon is **which instant got stamped**.
    ///
    /// The first assertion is the defect, and it must keep holding: it is
    /// what stops someone from "fixing" T0 by inflating
    /// `CACHE_FRESHNESS_MARGIN` past a cycle duration instead. That is SoT
    /// option (b) standing alone, and it is unbounded — the margin would
    /// have to exceed the slowest cycle on the slowest network, a number
    /// that grows with the corpus. Measured on the two live hosts the
    /// deficit differs by two orders of magnitude (4–36 s on proxmox,
    /// 315–422 s on zima), so any margin large enough for one is either
    /// wrong for the other or swallows a whole cycle.
    #[test]
    fn the_anchor_not_the_margin_is_what_makes_the_next_tick_stale() {
        let interval = Duration::from_secs(43_200);
        let tick = OffsetDateTime::now_utc() - time::Duration::seconds(43_200);
        let next_tick = tick + interval;
        let cycle_duration = time::Duration::seconds(456);

        assert!(
            is_cache_fresh(tick + cycle_duration, next_tick, interval),
            "a completion stamp read as STALE at the next tick — then the margin has been \
             grown to cover a whole cycle, which is the unbounded, per-host-tuned fix this \
             design rejected"
        );

        assert!(
            !is_cache_fresh(tick, next_tick, interval),
            "a cycle-anchor stamp still read as fresh one full interval later — the \
             scheduled refresh can never fetch"
        );
    }

    /// The stamping half, on a production path a test can actually reach.
    ///
    /// No in-process test can drive the 200 / 304 arms — `validate_list_url`
    /// refuses loopback and plain `http`, by design — but the
    /// no-`cache_dir` arm stamps the same variable from the same cycle
    /// anchor, one `match` away in the same function. Pre-fix all four
    /// sites read `OffsetDateTime::now_utc()`, so this fails on today's
    /// code; post-fix the stamp is the anchor the cycle was reckoned from,
    /// whenever the body actually arrived.
    #[tokio::test]
    async fn a_cycle_stamps_its_anchor_not_its_completion() {
        let (mut mgr, urls, _dir) = spill_manager(&["a.example\n"]);
        mgr.cache_dir = None; // the arm that retains the body in memory
        let tick = OffsetDateTime::now_utc() - time::Duration::seconds(456);

        assert_eq!(mgr.refresh_at(tick).await, 1);

        let stamped = mgr
            .cache
            .get(&urls[0])
            .map(|c| c.fetched_at)
            .expect("this arm records a validation time");
        assert_eq!(
            stamped, tick,
            "the cycle stamped {stamped} instead of its anchor {tick} — any later instant \
             hands the next fixed-period tick an age short of a full interval, which is \
             fresh by construction"
        );
    }

    /// The alternation is per-source, so the fix has to be per-source.
    /// One list is deliberately out of phase — the state a failed download
    /// or a differently-timed cycle leaves behind — and each must be judged
    /// on its own clock. A test that drives every source in lockstep passes
    /// while the defect survives.
    #[tokio::test]
    async fn an_out_of_phase_source_is_judged_on_its_own_clock() {
        let (mut mgr, urls, _dir) = cached_manager(&["a.example\n", "x.example\n"]);
        let interval = mgr.refresh_interval;
        let now = OffsetDateTime::now_utc();

        // src0 was validated at this cycle's anchor; src1 three hours
        // before it, so a full interval has already passed for src1 alone.
        mgr.cache.get_mut(&urls[0]).unwrap().fetched_at = now;
        mgr.cache.get_mut(&urls[1]).unwrap().fetched_at = now - interval - interval;

        assert!(
            is_cache_fresh(mgr.cache[&urls[0]].fetched_at, now, interval),
            "the in-phase source must still be served from cache"
        );
        assert!(
            !is_cache_fresh(mgr.cache[&urls[1]].fetched_at, now, interval),
            "the out-of-phase source must be judged stale on its OWN clock, not on the \
             cycle's — sources drift apart whenever one fails or lands in another cycle"
        );

        // And the loop acts on that difference: the stale one attempts a
        // fetch (which fails against an unresolvable host) and is recorded
        // Failed, while the fresh one is served from cache and stays Ok.
        mgr.refresh_at(now).await;
        assert!(matches!(
            mgr.status_registry
                .status_for_url(&urls[0])
                .unwrap()
                .last_outcome,
            LastOutcome::Ok
        ));
        assert!(
            matches!(
                mgr.status_registry
                    .status_for_url(&urls[1])
                    .unwrap()
                    .last_outcome,
                LastOutcome::Failed { .. }
            ),
            "the out-of-phase source was not even attempted"
        );
    }

    // ── Reload peak measurement (§11 T3, the number this lane exists for)
    //
    // Run each arm in its OWN process — `VmHWM` is a high-water mark that
    // never decreases, so measuring both arms in one process lets the
    // first poison the second and reports "no improvement" on working
    // code:
    //
    //   cargo test --lib -- --ignored --exact --nocapture \
    //       lists::manager::tests::perf_reload_peak_flat_producer
    //   cargo test --lib -- --ignored --exact --nocapture \
    //       lists::manager::tests::perf_reload_peak_sharded_producer
    //
    // Both arms load the SAME corpus into the SAME engine state (a full
    // previous generation already installed, so the coexistence the
    // sharding exists to bound is real), then run one producer.

    /// **The cost measurement for the global corpus guard.** The one
    /// number that decides whether the design is acceptable, and it is
    /// deliberately measured rather than estimated — the estimate was
    /// 1-3 s at the production corpus, which is exactly the sort of claim
    /// this workstream has repeatedly found to be wrong.
    ///
    /// Run it on the CT, in its own process:
    ///
    /// ```text
    /// cargo test --lib -- --ignored --exact --nocapture \
    ///     lists::manager::tests::perf_corpus_guard_counting_pass
    /// ```
    ///
    /// It prints one `GUARD_COST` line. The absolute count time matters
    /// less than `overhead_pct`: the build pass is work the cycle was
    /// always going to do, and both passes read the same spill, so their
    /// ratio is what the guard actually adds. Scale by roughly 6× for the
    /// live 12.3 M corpus against this 2 M fixture, and note the whole
    /// reload is dominated by download and parse, neither of which is
    /// timed here.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "measurement, not a gate: allocates ~0.2 GB and needs its own process"]
    fn perf_corpus_guard_counting_pass() {
        let dir = tempfile::tempdir().unwrap();
        let corpus = perf_corpus(dir.path());
        let spill_dir = dir.path().join("spill");
        std::fs::create_dir_all(&spill_dir).unwrap();

        let mut spill = ShardSpill::open(Some(&spill_dir));
        assert!(spill.is_disk(), "the guard's cost is a disk-spill property");
        let body = std::fs::read_to_string(&corpus).unwrap();
        parse_source_into_spill(
            std::io::Cursor::new(body.as_bytes()),
            1,
            &mut spill,
            PERF_CORPUS_DOMAINS + 1,
            "perf",
            Some(ListFormat::DomainOnly),
        )
        .unwrap();
        drop(body);
        spill.flush().unwrap();

        // ── the pass the guard adds ──
        let t0 = std::time::Instant::now();
        let mut novel_by_bit = [0u64; 64];
        let mut unique = 0u64;
        for idx in 0..DOMAIN_SHARDS {
            unique += spill.count_unique(idx, &mut novel_by_bit).unwrap();
        }
        let count_ms = t0.elapsed().as_secs_f64() * 1000.0;

        // ── the pass it precedes, for scale ──
        let t1 = std::time::Instant::now();
        let mut added_by_bit = [0u64; 64];
        let mut built = 0usize;
        let policy = ListPolicy::publish_uniform(0);
        for idx in 0..DOMAIN_SHARDS {
            built += spill
                .build_shard(
                    idx,
                    unique as usize / DOMAIN_SHARDS + 1,
                    &mut added_by_bit,
                    &policy,
                )
                .unwrap()
                .len();
        }
        let build_ms = t1.elapsed().as_secs_f64() * 1000.0;

        println!(
            "GUARD_COST domains={unique} count_ms={count_ms:.0} build_ms={build_ms:.0} \
             overhead_pct={:.1}",
            count_ms / build_ms * 100.0
        );
        assert_eq!(
            unique as usize, PERF_CORPUS_DOMAINS,
            "counted the wrong corpus"
        );
        assert_eq!(
            built, PERF_CORPUS_DOMAINS,
            "the count pass consumed the spill"
        );
    }

    /// Peak resident set since process start, in KiB.
    #[cfg(target_os = "linux")]
    fn vm_hwm_kb() -> u64 {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmHWM:") {
                return rest
                    .split_whitespace()
                    .next()
                    .unwrap()
                    .parse()
                    .expect("VmHWM is a number");
            }
        }
        panic!("no VmHWM in /proc/self/status");
    }

    /// Drop the peak back to the current RSS.
    ///
    /// Without this the *setup* — which installs the previous generation
    /// the flat way — leaves a high-water mark the measured arm can never
    /// read below, flooring the sharded arm at the flat arm's cost and
    /// reporting no improvement on working code. Verified to work on this
    /// kernel before being relied on; the assertion below keeps it that
    /// way, because a silently-failing reset is worse than none.
    #[cfg(target_os = "linux")]
    fn reset_vm_hwm() {
        std::fs::write("/proc/self/clear_refs", "5").expect("clear_refs=5 must be writable");
    }

    /// Domains matching the production corpus's measured shape: 20 bytes
    /// mean, i.e. inline in `CompactString` (§7 measured 20.3 B/domain).
    #[cfg(target_os = "linux")]
    const PERF_CORPUS_DOMAINS: usize = 2_000_000;

    #[cfg(target_os = "linux")]
    fn perf_corpus(dir: &Path) -> PathBuf {
        let path = dir.join("corpus.txt");
        let mut out =
            std::io::BufWriter::with_capacity(1 << 20, std::fs::File::create(&path).unwrap());
        for i in 0..PERF_CORPUS_DOMAINS {
            writeln!(out, "dom{i:07}xy.example").unwrap();
        }
        out.flush().unwrap();
        path
    }

    /// Install a full generation, the way a running daemon already holds
    /// one when a reload starts.
    #[cfg(target_os = "linux")]
    fn perf_install_previous_generation(engine: &FilterEngine, path: &Path) {
        let body = std::fs::read_to_string(path).unwrap();
        let mut map: HashMap<CompactString, u64, RandomState> =
            HashMap::with_capacity_and_hasher(PERF_CORPUS_DOMAINS, RandomState::new());
        crate::lists::parser::parse_list_into_map(
            &body,
            1,
            &mut map,
            usize::MAX,
            "perf",
            Some(ListFormat::DomainOnly),
        );
        engine.swap_domain_map(map);
    }

    /// Baseline arm: exactly what `refresh()` used to do — one flat
    /// full-corpus map, filled from a `read_to_string` of the body, handed
    /// over whole.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "measurement, not a gate: allocates ~0.5 GB and needs its own process"]
    fn perf_reload_peak_flat_producer() {
        let dir = tempfile::tempdir().unwrap();
        let path = perf_corpus(dir.path());
        let engine = FilterEngine::new();
        perf_install_previous_generation(&engine, &path);
        let before_reset = vm_hwm_kb();
        reset_vm_hwm();
        let baseline = vm_hwm_kb();
        assert!(
            baseline < before_reset,
            "clear_refs did not reset VmHWM ({before_reset} -> {baseline}); \
             the measurement would be floored by the setup and is not valid"
        );

        // ── the old producer ──
        let body = std::fs::read_to_string(&path).unwrap();
        let mut merged: HashMap<CompactString, u64, RandomState> =
            HashMap::with_capacity_and_hasher(engine.domain_count(), RandomState::new());
        crate::lists::parser::parse_list_into_map(
            &body,
            1,
            &mut merged,
            usize::MAX,
            "perf",
            Some(ListFormat::DomainOnly),
        );
        drop(body);
        merged.shrink_to_fit();
        let total = merged.len();
        engine.swap_domain_map(merged);
        // ──────────────────────

        let peak = vm_hwm_kb();
        println!(
            "ARM=flat domains={total} baseline_hwm_kb={baseline} peak_hwm_kb={peak} \
             peak_mb={:.1}",
            peak as f64 / 1024.0
        );
        assert_eq!(total, PERF_CORPUS_DOMAINS);
        assert_eq!(engine.domain_count(), PERF_CORPUS_DOMAINS);
    }

    /// The shard-at-a-time producer: the same corpus, the same installed
    /// generation, partitioned to spill and installed one sixteenth at a
    /// time.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "measurement, not a gate: allocates ~0.2 GB and needs its own process"]
    fn perf_reload_peak_sharded_producer() {
        let dir = tempfile::tempdir().unwrap();
        let path = perf_corpus(dir.path());
        let engine = FilterEngine::new();
        perf_install_previous_generation(&engine, &path);
        let before_reset = vm_hwm_kb();
        reset_vm_hwm();
        let baseline = vm_hwm_kb();
        assert!(
            baseline < before_reset,
            "clear_refs did not reset VmHWM ({before_reset} -> {baseline}); \
             the measurement would be floored by the setup and is not valid"
        );

        // ── the new producer ──
        let estimated = engine.domain_count();
        let mut spill = ShardSpill::open(Some(dir.path()));
        assert!(spill.is_disk(), "must measure the disk path");
        parse_source_into_spill(
            std::io::BufReader::with_capacity(SPILL_WRITE_BUF, std::fs::File::open(&path).unwrap()),
            1,
            &mut spill,
            usize::MAX,
            "perf",
            Some(ListFormat::DomainOnly),
        )
        .unwrap();
        spill.flush().unwrap();
        let mut added = [0u64; 64];
        let mut total = 0usize;
        let policy = ListPolicy::publish_uniform(0);
        for idx in 0..DOMAIN_SHARDS {
            let shard = spill
                .build_shard(idx, estimated / DOMAIN_SHARDS + 1, &mut added, &policy)
                .unwrap();
            total += shard.len();
            engine.swap_shard_sorted(idx, shard);
        }
        // ──────────────────────

        let peak = vm_hwm_kb();
        println!(
            "ARM=sharded domains={total} baseline_hwm_kb={baseline} peak_hwm_kb={peak} \
             peak_mb={:.1}",
            peak as f64 / 1024.0
        );
        assert_eq!(total, PERF_CORPUS_DOMAINS);
        assert_eq!(engine.domain_count(), PERF_CORPUS_DOMAINS);
    }

    // ── S0c: HTTP compression on list downloads ───────────────────────
    //
    // warden built reqwest with no compression feature, so it advertised no
    // `Accept-Encoding` and decoded nothing, while the origin had been
    // serving compressed responses all along — ~3.3x across the published
    // corpus (679.6 MB against ~206.9 MB).
    //
    // **What these tests reach, and what they do not.** They drive the real
    // client constructors (`build_bulk_list_client_with`), the real body
    // reader (`read_bounded_body`) and the real parser, over a real socket.
    // They do NOT reach `ListManager::download_list`, which is where the
    // conditional-GET headers are actually attached: that method runs
    // `http_client::validate_list_url` first, which refuses `http://` AND
    // refuses loopback IP literals, so no `TcpListener` on 127.0.0.1 is
    // addressable from it by construction. Reaching it would take TLS plus a
    // resolver override in the production builder — a test hook in an SSRF
    // guard, which is a worse trade than this gap.
    //
    // So the 304 tests below pin the **protocol contract** `download_list`
    // depends on (its header names and its 304 branch are transcribed from
    // `manager.rs:2145-2168`), not `download_list`'s own bookkeeping. Where
    // the real path can cross an encoding boundary is answered in NOTES.md
    // by reading the code, which is the only honest instrument here.
    //
    // Verified by mutation on 2026-08-13, because a green test that cannot
    // go red is decoration:
    //
    // | mutation | goes red |
    // |---|---|
    // | `.no_gzip()` on `base_builder` (kills the feature's effect, not the feature) | `list_client_advertises_gzip` ("sent no Accept-Encoding at all"), `gzip_shrinks_the_response_on_the_wire` ("56890 B not materially below 56890 B"), `gzip_body_round_trips_through_the_production_reader`, `unchanged_list_still_yields_304_under_gzip`, `decompressed_size_is_bounded_even_when_the_wire_is_tiny` |
    // | mock answers 304 to ANY `If-None-Match` | `changed_content_survives_a_cross_encoding_validator`, `identity_era_validator_costs_a_refetch_not_a_false_304` |
    //
    // Note the split in that second row: `unchanged_list_still_yields_304_
    // under_gzip` stays GREEN under a trust-any-validator server. It has to —
    // it pins that 304 still HAPPENS. Only the pair covers both directions,
    // which is why neither is redundant.

    /// A mock origin shaped like the published one.
    ///
    /// The load-bearing detail is that it recomputes its ETag from the
    /// **current** body on every request and appends an encoding suffix when
    /// it compresses — mirroring `"6a7c9943-8fcac6c-zstd"` under zstd against
    /// `"6a7c9943-8fcac6c"` under identity. A mock that answered 304 to any
    /// `If-None-Match` would make
    /// [`changed_content_survives_a_cross_encoding_validator`] pass while
    /// testing nothing; verified by mutation, see that test's comment.
    struct MockOrigin {
        body: std::sync::Mutex<Vec<u8>>,
        compress: std::sync::atomic::AtomicBool,
        /// Bytes written to the socket for the most recent response body.
        /// Measured at the socket, not read back from a header the client
        /// could not independently verify.
        last_body_bytes: std::sync::atomic::AtomicUsize,
        /// `Accept-Encoding` as it arrived on the most recent request.
        last_accept_encoding: std::sync::Mutex<Option<String>>,
        last_status: std::sync::atomic::AtomicU16,
        requests: std::sync::atomic::AtomicUsize,
    }

    impl MockOrigin {
        fn new(body: &str, compress: bool) -> Arc<Self> {
            Arc::new(Self {
                body: std::sync::Mutex::new(body.as_bytes().to_vec()),
                compress: std::sync::atomic::AtomicBool::new(compress),
                last_body_bytes: std::sync::atomic::AtomicUsize::new(0),
                last_accept_encoding: std::sync::Mutex::new(None),
                last_status: std::sync::atomic::AtomicU16::new(0),
                requests: std::sync::atomic::AtomicUsize::new(0),
            })
        }

        fn set_body(&self, body: &str) {
            *self.body.lock().unwrap() = body.as_bytes().to_vec();
        }

        fn set_compress(&self, on: bool) {
            self.compress.store(on, std::sync::atomic::Ordering::SeqCst);
        }

        fn accept_encoding(&self) -> Option<String> {
            self.last_accept_encoding.lock().unwrap().clone()
        }

        fn body_bytes_on_wire(&self) -> usize {
            self.last_body_bytes
                .load(std::sync::atomic::Ordering::SeqCst)
        }

        fn last_status(&self) -> u16 {
            self.last_status.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn request_count(&self) -> usize {
            self.requests.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    /// Content-derived ETag plus the origin's encoding suffix.
    ///
    /// Derived from the body so it tracks content — which is the property
    /// that makes a false 304 impossible to manufacture merely by changing
    /// encodings, and the property the test would silently lose if this
    /// returned a constant.
    fn origin_etag(body: &[u8], compress: bool) -> String {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        body.hash(&mut h);
        if compress {
            format!("\"{:x}-gzip\"", h.finish())
        } else {
            format!("\"{:x}\"", h.finish())
        }
    }

    fn gzip_bytes(raw: &[u8]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(raw).unwrap();
        enc.finish().unwrap()
    }

    /// A body with the shape of a real blocklist: many similar lines. Entropy
    /// matters here — asserting a compression ratio against random bytes
    /// would be asserting that gzip fails.
    fn synthetic_blocklist(n: usize) -> String {
        (0..n)
            .map(|i| format!("tracker-{i}.ads.example.com\n"))
            .collect()
    }

    /// Case-insensitive single-header lookup over a raw request head.
    fn header_of(head: &str, name: &str) -> Option<String> {
        head.lines()
            .filter_map(|l| l.split_once(':'))
            .find(|(k, _)| k.trim().eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim().to_string())
    }

    /// Serve [`MockOrigin`] on an ephemeral port. One response per
    /// connection (`Connection: close`) — keep-alive would buy nothing here
    /// and costs request-framing bugs in the mock.
    async fn spawn_mock_origin(origin: Arc<MockOrigin>) -> std::net::SocketAddr {
        use std::sync::atomic::Ordering;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                let origin = Arc::clone(&origin);
                tokio::spawn(async move {
                    // Read the request head. Loop until the terminator so a
                    // split read cannot truncate the headers we assert on.
                    let mut raw = Vec::new();
                    let mut buf = [0u8; 1024];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => raw.extend_from_slice(&buf[..n]),
                        }
                        if raw.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let head = String::from_utf8_lossy(&raw).into_owned();

                    *origin.last_accept_encoding.lock().unwrap() =
                        header_of(&head, "accept-encoding");
                    let inm = header_of(&head, "if-none-match");
                    origin.requests.fetch_add(1, Ordering::SeqCst);

                    // Snapshot the shared state and drop the guard BEFORE any
                    // await — a MutexGuard held across an await point is both
                    // a clippy error and a deadlock waiting to happen.
                    let body_now = origin.body.lock().unwrap().clone();
                    let compress = origin.compress.load(Ordering::SeqCst);

                    // The origin compresses only when the client asked. This
                    // is the negotiation the whole change depends on: with no
                    // `Accept-Encoding`, an origin serves identity and warden
                    // pays full price — which is exactly what it did.
                    let client_accepts_gzip = origin
                        .accept_encoding()
                        .is_some_and(|v| v.to_ascii_lowercase().contains("gzip"));
                    let compress = compress && client_accepts_gzip;

                    let etag = origin_etag(&body_now, compress);

                    // 304 only when the validator matches the representation
                    // this request would produce RIGHT NOW.
                    if inm.as_deref() == Some(etag.as_str()) {
                        origin.last_status.store(304, Ordering::SeqCst);
                        origin.last_body_bytes.store(0, Ordering::SeqCst);
                        let resp = format!(
                            "HTTP/1.1 304 Not Modified\r\n\
                             ETag: {etag}\r\n\
                             Connection: close\r\n\r\n"
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                        return;
                    }

                    let payload = if compress {
                        gzip_bytes(&body_now)
                    } else {
                        body_now
                    };
                    let encoding_header = if compress {
                        "Content-Encoding: gzip\r\n"
                    } else {
                        ""
                    };
                    let head_out = format!(
                        "HTTP/1.1 200 OK\r\n\
                         Content-Type: text/plain\r\n\
                         Content-Length: {}\r\n\
                         {encoding_header}\
                         ETag: {etag}\r\n\
                         Vary: Accept-Encoding\r\n\
                         Connection: close\r\n\r\n",
                        payload.len()
                    );
                    if stream.write_all(head_out.as_bytes()).await.is_err() {
                        return;
                    }
                    if stream.write_all(&payload).await.is_err() {
                        return;
                    }
                    origin.last_status.store(200, Ordering::SeqCst);
                    origin
                        .last_body_bytes
                        .store(payload.len(), Ordering::SeqCst);
                });
            }
        });

        addr
    }

    fn test_bulk_client() -> reqwest::Client {
        crate::lists::http_client::build_bulk_list_client_with(
            Duration::from_secs(20),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .unwrap()
    }

    /// DoD 1 — the request advertises gzip.
    ///
    /// Asserted on the **inbound** request at the server, not on the client's
    /// configuration: `reqwest` exposes no getter for its accepted encodings,
    /// so the only observable proof that the `Cargo.toml` feature took effect
    /// is the header that reached a socket.
    ///
    /// This is also the test that fails if someone removes `gzip` from the
    /// feature list — the feature is the entire mechanism, and there is no
    /// line of warden code to break instead.
    #[tokio::test]
    async fn list_client_advertises_gzip() {
        let origin = MockOrigin::new(&synthetic_blocklist(10), true);
        let addr = spawn_mock_origin(Arc::clone(&origin)).await;

        let client = test_bulk_client();
        let url = format!("http://{addr}/list.txt");
        let resp = client.get(&url).send().await.unwrap();
        assert!(resp.status().is_success());
        let _ = resp.bytes().await.unwrap();

        let ae = origin
            .accept_encoding()
            .expect("production list client sent no Accept-Encoding at all");
        assert!(
            ae.to_ascii_lowercase().contains("gzip"),
            "Accept-Encoding must offer gzip, got: {ae}"
        );
    }

    /// DoD 2 — measurably fewer bytes on the wire.
    ///
    /// The assertion is **relational**, deliberately. An absolute byte total
    /// would encode one compression level over one body shape and would fail
    /// while being correct the moment the origin changed either. `< half` is
    /// far below the ~3.3x the corpus measures, so it cannot flake on
    /// entropy, and it is still a claim gzip-off cannot satisfy.
    #[tokio::test]
    async fn gzip_shrinks_the_response_on_the_wire() {
        let body = synthetic_blocklist(2000);
        let uncompressed = body.len();
        let origin = MockOrigin::new(&body, true);
        let addr = spawn_mock_origin(Arc::clone(&origin)).await;

        let client = test_bulk_client();
        let url = format!("http://{addr}/list.txt");
        let resp = client.get(&url).send().await.unwrap();
        let got = resp.bytes().await.unwrap();

        let on_wire = origin.body_bytes_on_wire();
        assert!(
            on_wire < uncompressed / 2,
            "on-wire {on_wire} B not materially below uncompressed {uncompressed} B"
        );
        // The client still sees the full body: the saving is transport-only.
        assert_eq!(
            got.len(),
            uncompressed,
            "decoded body must be the full uncompressed length"
        );
        println!(
            "S0c wire measurement: uncompressed={uncompressed} B, on-wire={on_wire} B, \
             ratio={:.2}x",
            uncompressed as f64 / on_wire as f64
        );
    }

    /// DoD 3 — the content survives the round trip, exactly.
    ///
    /// Runs the real `read_bounded_body` (the function `download_list` uses)
    /// and the real parser, then compares the parsed domain set against the
    /// set the uncompressed body contained. Byte-length equality alone would
    /// not catch a codec that corrupts bytes in place.
    #[tokio::test]
    async fn gzip_body_round_trips_through_the_production_reader() {
        let body = synthetic_blocklist(500);
        let origin = MockOrigin::new(&body, true);
        let addr = spawn_mock_origin(Arc::clone(&origin)).await;

        let client = test_bulk_client();
        let url = format!("http://{addr}/list.txt");
        let resp = client.get(&url).send().await.unwrap();
        let text = read_bounded_body(resp, &url, TEST_CAP).await.unwrap();

        assert_eq!(text, body, "decompressed body differs from the original");

        let parsed = crate::lists::parser::parse_domain_list(&text);
        let expected = crate::lists::parser::parse_domain_list(&body);
        assert_eq!(parsed.len(), 500, "wrong domain count: {}", parsed.len());
        assert_eq!(parsed, expected, "parsed domain set differs");
        // Confirm the wire really was compressed, so this is not a green
        // round-trip over an identity response that proves nothing.
        assert!(
            origin.body_bytes_on_wire() < body.len(),
            "server served identity — the round trip did not cross the codec"
        );
    }

    /// DoD 4 — an unchanged list still yields 304 under compression.
    ///
    /// The header names and the 304 detection mirror `download_list`
    /// (`manager.rs:2145-2168`): `If-None-Match` from the cached validator,
    /// `NOT_MODIFIED` short-circuits before any body read.
    #[tokio::test]
    async fn unchanged_list_still_yields_304_under_gzip() {
        let body = synthetic_blocklist(300);
        let origin = MockOrigin::new(&body, true);
        let addr = spawn_mock_origin(Arc::clone(&origin)).await;
        let client = test_bulk_client();
        let url = format!("http://{addr}/list.txt");

        let first = client.get(&url).send().await.unwrap();
        assert!(first.status().is_success());
        let etag = first
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .expect("origin must send an ETag to cache");
        let _ = first.bytes().await.unwrap();
        assert!(
            etag.ends_with("-gzip\""),
            "expected the encoding-suffixed validator, got {etag}"
        );

        // Nothing changed — replay the validator.
        let second = client
            .get(&url)
            .header("If-None-Match", &etag)
            .send()
            .await
            .unwrap();
        assert_eq!(
            second.status(),
            reqwest::StatusCode::NOT_MODIFIED,
            "unchanged list must still 304 — conditional GET is what keeps a \
             refresh cycle cheap"
        );
        assert_eq!(origin.request_count(), 2);
        assert_eq!(origin.last_status(), 304);
    }

    /// DoD 5 — an encoding change must not manufacture a false 304.
    ///
    /// The dangerous failure is silent: warden concluding a list is unchanged
    /// when it changed, then serving stale filtering rules with no error and
    /// no log. The validator is encoding-specific at the origin, so this
    /// walks a validator across that boundary while the content also changes.
    ///
    /// **Verified by mutation on 2026-08-13**, because a green test that
    /// cannot go red is decoration. Replacing the mock's match check with
    /// `if inm.is_some() { 304 }` — a server that trusts any validator —
    /// fails this test on the status assertion, and would fail on the
    /// stale-domain assertion below it too. The
    /// [`unchanged_list_still_yields_304_under_gzip`] sibling stays green
    /// under that mutation, which is precisely why both are needed: one pins
    /// that 304 still happens, the other that it does not happen wrongly.
    #[tokio::test]
    async fn changed_content_survives_a_cross_encoding_validator() {
        let old_body = "stale-tracker.example.com\n";
        let origin = MockOrigin::new(old_body, true);
        let addr = spawn_mock_origin(Arc::clone(&origin)).await;
        let client = test_bulk_client();
        let url = format!("http://{addr}/list.txt");

        // 1. Cache a validator obtained under gzip.
        let first = client.get(&url).send().await.unwrap();
        let gzip_etag = first
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .unwrap();
        let _ = first.bytes().await.unwrap();

        // 2. The list changes, AND the origin stops compressing — the
        //    encoding boundary the cached validator now has to cross.
        let new_body = "fresh-tracker.example.com\n";
        origin.set_body(new_body);
        origin.set_compress(false);

        // 3. Replay the gzip-era validator against the identity response.
        let second = client
            .get(&url)
            .header("If-None-Match", &gzip_etag)
            .send()
            .await
            .unwrap();
        assert_ne!(
            second.status(),
            reqwest::StatusCode::NOT_MODIFIED,
            "FALSE 304: a stale validator from another encoding suppressed a \
             body that actually changed — warden would filter on stale rules \
             with no error and no log"
        );
        assert!(second.status().is_success());

        // The body is the assertion that matters: a 200 carrying the old
        // content would be the same defect wearing a different status.
        let text = read_bounded_body(second, &url, TEST_CAP).await.unwrap();
        let parsed = crate::lists::parser::parse_domain_list(&text);
        assert!(
            parsed.contains("fresh-tracker.example.com"),
            "new domain missing after the encoding change: {parsed:?}"
        );
        assert!(
            !parsed.contains("stale-tracker.example.com"),
            "served the STALE domain across the encoding boundary: {parsed:?}"
        );
    }

    /// The post-upgrade transition, recorded because its cost is real and
    /// its direction is the opposite of the one the risk was framed as.
    ///
    /// A warden built before this change cached identity validators. The
    /// first refresh after the upgrade replays them under gzip, and the
    /// origin's suffixed ETag cannot match — so every list re-downloads in
    /// full exactly once. That is a spurious **200**, not a false 304: an
    /// encoding suffix makes a validator MORE specific, never less, so this
    /// boundary can only cost bandwidth, never correctness. One cycle, then
    /// the cache holds gzip-era validators and 304s resume.
    #[tokio::test]
    async fn identity_era_validator_costs_a_refetch_not_a_false_304() {
        let body = synthetic_blocklist(50);
        // The origin serves identity first — warden before this change.
        let origin = MockOrigin::new(&body, false);
        let addr = spawn_mock_origin(Arc::clone(&origin)).await;
        let url = format!("http://{addr}/list.txt");

        let plain = crate::lists::http_client::build_list_client(Duration::from_secs(10)).unwrap();
        let first = plain.get(&url).send().await.unwrap();
        let identity_etag = first
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .unwrap();
        let _ = first.bytes().await.unwrap();
        assert!(
            !identity_etag.ends_with("-gzip\""),
            "identity leg must not carry the gzip suffix: {identity_etag}"
        );

        // Now the upgraded client, same unchanged content, replaying the
        // identity-era validator.
        origin.set_compress(true);
        let second = test_bulk_client()
            .get(&url)
            .header("If-None-Match", &identity_etag)
            .send()
            .await
            .unwrap();
        assert!(
            second.status().is_success(),
            "expected a full 200 refetch on the first post-upgrade cycle"
        );
        let text = read_bounded_body(second, &url, TEST_CAP).await.unwrap();
        assert_eq!(text, body, "the refetched body must still be correct");
    }

    /// The security property this change WEAKENS, pinned before it can rot.
    ///
    /// `reqwest` removes `Content-Length` from a response it decodes
    /// (documented at `async_impl/client.rs:1226`), so the early-fail guard
    /// in `download_list` (`manager.rs:2191`) is **dead for every compressed
    /// response** — `resp.content_length()` returns `None` and the check is
    /// skipped entirely.
    ///
    /// That is survivable only because the real bound was never that guard:
    /// `read_bounded_body_bytes` counts the chunks it actually receives, and
    /// after decoding those are **decompressed** bytes. So the cap still
    /// measures the axis that can exhaust memory. What compression changes is
    /// the attacker's cost — a few KB on the wire now buys the full
    /// `max_body_bytes` of warden's allocator — which makes the streaming
    /// bound load-bearing where it used to be defence in depth.
    #[tokio::test]
    async fn decompressed_size_is_bounded_even_when_the_wire_is_tiny() {
        const CAP: usize = 1024 * 1024;
        // ~4 MiB that gzips to a few KB: past the cap decompressed, trivial
        // compressed. The shape of a decompression bomb, at test scale.
        let body = "bomb.example.com\n".repeat(256 * 1024);
        assert!(body.len() > 4 * CAP);
        let origin = MockOrigin::new(&body, true);
        let addr = spawn_mock_origin(Arc::clone(&origin)).await;

        let client = test_bulk_client();
        let url = format!("http://{addr}/list.txt");
        let resp = client.get(&url).send().await.unwrap();

        // The dead guard, demonstrated rather than asserted from the docs.
        assert!(
            resp.content_length().is_none(),
            "reqwest kept Content-Length on a decoded response — the early \
             guard in download_list may be live again; re-check manager.rs:2191"
        );

        let result = read_bounded_body(resp, &url, CAP).await;
        match result {
            Err(ListError::TooLarge { size, max, .. }) => {
                assert_eq!(max, CAP);
                assert!(size > CAP, "size {size} should exceed cap {CAP}");
            }
            other => panic!(
                "a body that decompresses past max_body_bytes must be refused, got {other:?}"
            ),
        }
        assert!(
            origin.body_bytes_on_wire() < CAP / 10,
            "the wire payload was not small — this did not model a bomb"
        );
    }
}
