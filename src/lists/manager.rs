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
// Only named by the direction tests, which assert on
// `SortedShard::split`'s return type. Producing code stores raw source
// bits and never constructs a `DomainMasks`.
#[cfg(test)]
use crate::filter::engine::DomainMasks;
use crate::filter::FilterEngine;
use crate::ipc::protocol::IpcNotification;

/// Synthetic URL host reserved by `warden blocklist import-local` for
/// `trust = local` blocklists. The validator at
/// `src/config/schema/validator.rs` only accepts `http(s)://` schemes,
/// so a locally-imported list is given this placeholder host instead of
/// a real URL. The list-manager intercepts this host in `download_list`
/// and reads the body from `<config_dir>/lists/<id>.<ext>` on disk.
const IMPORTED_LOCAL_HOST: &str = "imported.local";

// Body size cap is a per-ListManager field sourced from
// `settings.lists.max_body_bytes` (default 200 MB). See `ListManager::new`
// and `read_bounded_body` for the flow. It is configurable rather than a
// fixed constant because published lists grow over time — a
// currently-published blocklist can exceed 100 MB in the wild.

/// Minimum refresh interval (60 seconds). Prevents accidental tight loops.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// Emitted once at startup when a [`ListManager`] is built
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
/// The only variant today is `Forget`, the surgical
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
/// fresh.
///
/// Without it the scheduled refresh **can never fetch**, by construction.
/// The ticker is fixed-period and anchored at spawn (`spawn_refresh_loop`),
/// but the cycle anchor `now` is read *inside* `refresh` — strictly after
/// the tick fires. So the age at the next tick is `interval − δ` for some
/// `δ > 0`, `whole_seconds()` floors that to `interval − 1`, and the body
/// reads fresh forever — measured in production as an effective refresh
/// interval double the configured one, alternating fetch / skip every
/// other cycle.
///
/// Five seconds is three orders of magnitude above the tick→anchor
/// scheduler latency this absorbs, and 8 % of [`MIN_REFRESH_INTERVAL`] at
/// the tightest interval the config will accept — so it can shorten a
/// cycle but never collapse one. The other half of the fix is
/// [`ListManager::refresh_at`] stamping the cycle anchor rather than the
/// download's completion; that half removes the *unbounded* term (the
/// serial fetch lag), and this one removes what is left. Neither half
/// works alone.
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
/// persisted corpus instead of waiting on HTTP. `start.rs` does not call
/// [`ListManager::refresh`] at boot at all; the one inline `refresh()`
/// left there is `handle_reload`'s, which runs **after** the bind. Do
/// not restore an inline network refresh ahead of the bind on the
/// belief that this is unwired scaffolding — that reintroduces the slow
/// boot this mechanism exists to remove.
///
/// Everything below the fetch — spill, `corpus_guard`, the
/// shrink guard, the corpus digest, `build_shard` / `swap_shard` — is
/// shared by both modes on purpose: two strands of map-building code
/// would drift, and those guards are exactly where a silently unfiltered
/// boot comes from.
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

/// Thin adapter over [`hardened_atomic_write`](crate::config::atomic_write::hardened_atomic_write) so the
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
    /// The typed [`SourceBitMap`] facade rather than a raw
    /// `HashMap<String, u8>` — the manager's fetch loop keys by URL via
    /// [`SourceBitMap::bit_for_url`], and the typed surface keeps the
    /// id/legacy channels reachable without a parallel map.
    source_bits: SourceBitMap,
    /// Source → resolved bearer token, via the typed [`SourceTokenMap`]
    /// facade. Lookups by legacy slash-form source key (manager's
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
    /// Retention guard on/off, from
    /// `settings.lists.shrink_guard_enabled` (default `true`). When on, a
    /// freshly downloaded body that shrinks a previously-healthy list past
    /// [`Self::shrink_guard_max_drop_pct`] is refused — the prior cache is
    /// kept and the source flips `Failed` with a visible reason instead of
    /// silently overwriting the good cache with ~0 domains.
    shrink_guard_enabled: bool,
    /// Max single-cycle shrink (percent of the
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
    /// shared with the DNS handler.
    ///
    /// [`ReadinessGate`] has no `close`, and its atomic is private to
    /// `lists::readiness` — a sibling module, so nothing in here can
    /// reach it. "Never closes" is enforced by the type, not by the
    /// comment at the open site.
    filter_ready: Option<ReadinessGate>,
    /// Per-source runtime telemetry. Built once from the
    /// configured `sources`, shared with the IPC layer via the same
    /// `Arc<ListStatusRegistry>`. Each `refresh()` call atomically swaps
    /// in a fresh [`ListStatus`] per source.
    status_registry: Arc<ListStatusRegistry>,
    /// Optional persistence path for `prev_entries`. When set, every
    /// successful `refresh()` writes `{path}` atomically so `delta_pct_vs_prev`
    /// survives daemon restarts. `None` in tests / ephemeral runs.
    status_persistence_path: Option<PathBuf>,
    /// Optional broadcast channel for
    /// [`IpcNotification::ListStatsUpdated`]. Published once per source
    /// at the end of each refresh cycle (success OR failure). `None`
    /// when no subscribers are wired (e.g. tests, or daemon configs
    /// where the IPC subscriber endpoint is disabled). Send errors
    /// (no live subscribers) are intentionally swallowed — broadcast
    /// is fire-and-forget.
    notification_tx: Option<tokio::sync::broadcast::Sender<IpcNotification>>,
    /// Per-source trust map used by the `imported.local`
    /// loader-bridge for its defence-in-depth check at fetch time.
    /// Sources missing from this map default to
    /// [`BlocklistTrust::RemoteUnsigned`] — the safe assumption when no
    /// explicit trust is wired (legacy `lists.sources` entries that
    /// pre-date the v1 `[[blocklists]].trust` field).
    ///
    /// The typed [`SourceTrustMap`] facade, rather than a raw
    /// `HashMap<String, BlocklistTrust>`, so consumers (TUI inspect,
    /// audit attribution) can resolve trust by canonical
    /// [`Id`](crate::config::schema::id::Id) without monkey-patching a
    /// reverse lookup through the URL.
    source_trust: SourceTrustMap,
    /// Directory containing `config.toml`, used to resolve
    /// synthetic `imported.local` URLs to `<config_dir>/lists/<id>.<ext>`
    /// on disk. `None` disables the bridge entirely (tests + ephemeral
    /// runs); the manager falls back to the HTTP path for every URL,
    /// including `imported.local` ones — which then fail at
    /// `validate_list_url` with a `DisallowedHost` error, surfacing the
    /// misconfiguration rather than silently doing nothing.
    local_bridge_dir: Option<PathBuf>,
    /// In-memory view of `data/list_state.toml`. Persisted atomically
    /// through
    /// [`Self::record_blocklist_success`] / [`Self::record_blocklist_failure`]
    /// at every transition. `Arc<Mutex<…>>` because the manager is
    /// shared across the refresh task and the reload-time resolver
    /// rebuild, which reads the same handle to drive list_applies
    /// status checks.
    list_state: Arc<std::sync::Mutex<crate::config::list_state::ListState>>,
    /// Path on disk for `list_state.toml`. `None` in tests / ephemeral
    /// runs — the helpers still mutate the in-memory state but skip
    /// the atomic write.
    list_state_path: Option<PathBuf>,
    /// Maps a source string (the keys of `sources` / `source_bits`,
    /// either legacy slash-form like `"privacy/ads"` or a raw URL like
    /// `"https://lists.purge.cc/…"`) to the canonical
    /// [`crate::config::schema::Id`] used by the retry state machine
    /// **and** the blocklist's per-list `max_consecutive_failures`
    /// threshold.
    ///
    /// The refresh loop keeps source-string keys, while
    /// `record_blocklist_success` / `record_blocklist_failure` key on
    /// canonical `Id` — this cross-reference is what lets each refresh
    /// cycle drive the state machine.
    ///
    /// Wired by [`Self::set_source_blocklist_map`] from the daemon's
    /// `start.rs`, which has access to `[[blocklists]]` (canonical id +
    /// max_consecutive_failures) and the `merged_sources` it derives
    /// from `lists.sources` ∪ `[[blocklists]].url`.
    source_to_blocklist: HashMap<String, (crate::config::schema::Id, u32)>,
    /// Source-string → operator-declared parse
    /// format, populated by [`Self::set_source_format_map`] from `start.rs`.
    /// Holds **only** sources whose `[[blocklists]]` row declares `hosts` or
    /// `adguard`; a declared (or omitted) `domains` is absent so the parse
    /// dispatch falls back to content auto-detection. Keyed identically to
    /// [`Self::source_to_blocklist`] (url / slash-form / canonical id) so the
    /// refresh loop's `source`-string lookup hits regardless of source form.
    source_to_format: HashMap<String, super::detector::ListFormat>,
    /// Out-of-band command channel drained by the
    /// refresh loop's `tokio::select!`. `None` for tests / ephemeral
    /// runs that never call [`Self::set_command_channel`] — the loop
    /// then degrades to ticker-only and the IPC `ForgetList` handler
    /// is unreachable.
    cmd_rx: Option<mpsc::Receiver<ListManagerCommand>>,
    /// Digest of the corpus behind the currently-installed
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
    /// Test-only: how many cycles actually ran pass 2. This
    /// short-circuit is otherwise invisible from outside — a skipped
    /// rebuild and a rebuild that produces the same map are
    /// indistinguishable through every public accessor, so a test without
    /// this would pass whether or not the short-circuit fired.
    #[cfg(test)]
    rebuild_count: usize,
    /// Test-only: how many cycles settled without
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
    /// The saving being tested is "the set was not built", and no output
    /// distinguishes that from "the set was built and agreed with the
    /// carried number" — same counts, same map, same log lines. Without
    /// this counter the test would pass on the unfixed code.
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

    /// Construct with an additional `source_tokens` facade.
    /// Lookups happen by legacy
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
            // Guard on by default so the product
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

    /// Wire the persistent
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

    /// Handle to the in-memory list state, used by the daemon's reload
    /// pipeline (the resolver rebuild reads it to populate the
    /// `Option<&ListState>` argument `ResolvedProfile::build_v1`
    /// accepts).
    pub fn list_state_handle(&self) -> Arc<std::sync::Mutex<crate::config::list_state::ListState>> {
        self.list_state.clone()
    }

    /// Register the source-string → (canonical `Id`,
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

    /// Register the source-string → declared parse
    /// format map. `start.rs` builds it from the same `[[blocklists]]` view as
    /// [`Self::set_source_blocklist_map`], inserting only sources that declare
    /// `hosts`/`adguard` (a `domains`/omitted format is left out so the parse
    /// dispatch defers to auto-detection). Idempotent — the next refresh cycle
    /// uses the new lookup.
    pub fn set_source_format_map(&mut self, map: HashMap<String, super::detector::ListFormat>) {
        self.source_to_format = map;
    }

    /// Record a successful
    /// blocklist refresh, transitioning the entry to Active and
    /// stamping its cache_path. Persists to disk if a state-file
    /// path was wired via [`Self::set_list_state`].
    ///
    /// Public so the refresh loop can call it once the
    /// source→blocklist mapping is plumbed (the refresh task keys on
    /// legacy slash-form / URL strings; the state-machine keys on
    /// canonical [`Id`](crate::config::schema::Id)).
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

    /// Record a failed
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
    /// project has been burned by before (see CLAUDE.md's Hot-Path
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
                            // spill back. The source then freezes at the
                            // body it last ingested — re-parsed below — so
                            // it keeps blocking instead of dropping out of
                            // the corpus this cycle installs.
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
                                "source refused this cycle; keeping its last good body"
                            );
                            let status = ListStatus::from_failure(
                                prev_status.as_deref(),
                                e.to_string(),
                                now,
                            );
                            self.status_registry.update_for_url(source, status);
                            publish_list_stats_updated(&self.notification_tx, source);
                            // Restore-or-remove the in-memory cache entry so
                            // the conditional headers keep validating the
                            // RETAINED body and the next cycle re-asks
                            // upstream instead of taking this poisoned one
                            // for a fresh refresh. `body` is deliberately
                            // left alone: with no cache dir it IS the
                            // retained body, and nothing else holds a copy.
                            match pre_download {
                                Some((etag, last_modified, fetched_at)) => {
                                    let entry = self.cache.entry(url.clone()).or_default();
                                    entry.etag = etag;
                                    entry.last_modified = last_modified;
                                    entry.fetched_at = fetched_at;
                                }
                                None => {
                                    self.cache.remove(url.as_str());
                                }
                            }
                            // Re-parse the retained body under the same cap.
                            // An operator who LOWERED the cap can have a
                            // retained body that fails it too; then the
                            // source contributes nothing and the status
                            // stamped above already says why.
                            //
                            // Deliberately NOT `resolve_body_reader`, which
                            // the neighbouring guard arm uses: that prefers
                            // a local-bridge source's live file, and here
                            // that file is the very body the cap just
                            // refused — so it would guarantee a second
                            // refusal for every bridged list. What is wanted
                            // is the last body actually ingested: the
                            // in-memory copy when there is no cache dir, the
                            // `.cache` file otherwise.
                            let retained = self
                                .cache
                                .get(url.as_str())
                                .and_then(|c| c.body.clone())
                                .map(|b| BodyReader::Memory(std::io::Cursor::new(b)))
                                .or_else(|| self.open_body_from_disk(source).map(BodyReader::Disk));
                            match retained {
                                Some(reader) => {
                                    match parse_source_into_spill_counted(
                                        reader,
                                        bit_mask,
                                        &mut spill,
                                        max_entries,
                                        source,
                                        declared_format,
                                        // The retained body is the one the
                                        // prior count describes.
                                        UniqueCount::carry_or_measure(prev_status.as_deref()),
                                    ) {
                                        Ok((c, _)) => spilled += c.parsed_ok,
                                        Err(retained_err) => tracing::warn!(
                                            source = source.as_str(),
                                            error = %retained_err,
                                            "failed to stream retained cache body after a refused refresh"
                                        ),
                                    }
                                }
                                None => tracing::warn!(
                                    source = source.as_str(),
                                    "no retained body to fall back on; source contributes nothing this cycle"
                                ),
                            }
                            // Unconditionally false, unlike the guard arm
                            // below, which folds the retained body's hash
                            // and keeps the digest valid. The digest is what
                            // lets a later cycle conclude "nothing changed"
                            // and skip the rebuild entirely; the cost of
                            // opting out is one extra rebuild per refused
                            // cycle, which is not worth widening that path
                            // for.
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
            // Minted here rather than beside the refusal payload below,
            // because the ERROR lines are what an operator or a log
            // scraper actually sees and they are emitted first. A refusal
            // that does not say how long it has stood reads identically on
            // day one and on day fourteen — which is how nine consecutive
            // refusals went unnoticed. `now` is the cycle's timestamp, so
            // the log and `warden status` name the same instant.
            let freeze = self.status_registry.note_refused_cycle(now);
            let frozen_since = freeze
                .since
                .and_then(|t| t.format(&Rfc3339).ok())
                .unwrap_or_else(|| "unknown".to_string());
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
                    since = %frozen_since,
                    consecutive = freeze.consecutive,
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
                    since = %frozen_since,
                    consecutive = freeze.consecutive,
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
                // The only thing that ends a freeze. Deliberately on this
                // side of the `degraded` branch: a partial shard build
                // leaves some of the previous generation serving, so the
                // corpus is still frozen and the streak must survive it.
                self.status_registry.note_installed_cycle();
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
mod tests;
