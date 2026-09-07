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
//! On 304 Not Modified or download failure, the manager attempts to parse a
//! retained response body for that source. A missing or rejected retained body
//! contributes nothing to that failure-path cycle; a hot refresh then keeps
//! the complete live corpus rather than installing a partial generation.
//!
//! The background refresh runs on a configurable interval (default 60 min).
//! If a refresh fails entirely, the previous domain map stays live.

use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::{BufRead, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use ahash::RandomState;
use compact_str::CompactString;
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::{mpsc, oneshot};

#[cfg(test)]
use super::cancellation::WorkerHook;
use super::cancellation::{self, Cancelled, RefreshCancellation};
use super::catalog::Catalog;
use super::detector::ListFormat;
use super::parser::{parse_list_streaming, DomainSink};
use super::readiness::ReadinessGate;
use super::source_key::{ResolvedSourcePlan, SourceBitMap, SourceTokenMap, SourceTrustMap};
use super::status::{
    compute_delta_pct, format_blocklist_shrink_refused, CorpusRefusal, CycleOutcome, LastOutcome,
    ListStatus, ListStatusRegistry, ParsedCounts, ServedState, BLOCKLIST_DELTA_WARN,
    DELTA_WARN_THRESHOLD_PCT,
};
use crate::common::domain::is_valid_domain;
use crate::config::list_schedule_state::{CanonicalScheduleOutcome, ListScheduleState};
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

/// A durable rollback record makes a batch of manifest selections one corpus
/// admission rather than independent per-source changes.
const CACHE_ROLLBACK_JOURNAL: &str = ".warden-cache-rollback-v1.json";
const MAX_ROLLBACK_JOURNAL_BYTES: u64 = 1024 * 1024;

// Body size cap is a per-ListManager field sourced from
// `settings.lists.max_body_bytes` (default
// `config::settings::DEFAULT_MAX_LIST_BODY_BYTES`). See `ListManager::new`
// and `read_bounded_body` for the flow. It is configurable rather than a
// fixed constant because published lists grow over time — a
// currently-published blocklist can exceed 100 MB in the wild.

/// Minimum refresh interval (60 seconds). Prevents accidental tight loops.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// Longest cadence used while a cycle leaves a degraded generation serving.
///
/// A successful recovery immediately returns to the configured cadence; this
/// cap only bounds how long the manager waits before trying to recover.
const MAX_DEGRADED_REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// Bound degraded-cycle retries independently of constructor validation so
/// scheduling keeps its safety floor if a future caller supplies an interval
/// below [`MIN_REFRESH_INTERVAL`].
fn degraded_refresh_interval(refresh_interval: Duration) -> Duration {
    refresh_interval
        .min(MAX_DEGRADED_REFRESH_INTERVAL)
        .max(MIN_REFRESH_INTERVAL)
}

/// One deadline rule backs both selection and sleeping so a future anchor is
/// never allowed to postpone either path.
fn schedule_deadline(
    schedule: &SourceSchedule,
    entry: &crate::config::list_schedule_state::CanonicalScheduleEntry,
    now: OffsetDateTime,
) -> OffsetDateTime {
    if entry.last_attempt > now {
        return now;
    }
    let cadence = match entry.outcome {
        CanonicalScheduleOutcome::Success => schedule.interval,
        CanonicalScheduleOutcome::Failure => degraded_refresh_interval(schedule.interval),
    };
    time::Duration::try_from(cadence)
        .ok()
        .and_then(|cadence| entry.last_attempt.checked_add(cadence))
        .unwrap_or(OffsetDateTime::new_utc(time::Date::MAX, time::Time::MAX))
}

/// Emitted once at startup when a [`ListManager`] is built
/// with no cache directory.
///
/// The cost is named because the alternative is silence: with no
/// `cache_dir` the raw text of every list stays in `ListCache.body` beside
/// the domain map, and the end-of-cycle sweep that would drop it is gated
/// on `cache_dir.is_some()`. At the corpus this product targets that is a
/// few hundred MB of duplicate residency, and `resolve_retained_body_reader` clones
/// each body again for every parse.
///
/// Frozen string: it is an operator-facing diagnostic, and it names a
/// consequence rather than a state, so it stays greppable across releases.
const LIST_CACHE_DIR_UNSET_WARNING: &str =
    "no list cache directory configured: every downloaded list body stays resident in RAM \
     for the life of the process, and is copied again on each refresh — expect roughly \
     double the memory of a cached deployment. Set `lists.cache_dir` to a writable path.";

/// Out-of-band commands accepted alongside the canonical deadline scheduler.
/// `Forget` changes retained state; `ForceRefresh` bypasses only due selection,
/// so both variants share the refresh loop's single ownership of cache state.
pub enum ListManagerCommand {
    /// Forget a list source: drop its in-memory cache entry and
    /// unlink its cache bodies and `<stem>.meta` manifest on disk.
    /// Best-effort — unlink failures are logged but never fail the
    /// request. The oneshot carries `was_cached`: true when the
    /// source had any state (in-memory entry OR on-disk file) before
    /// the call.
    Forget {
        source: String,
        accepted: oneshot::Sender<ListManagerCommandDisposition>,
        completion: oneshot::Sender<bool>,
    },
    /// Run all enabled sources now. The IPC route deliberately lands later;
    /// this keeps the scheduler seam typed and independently testable.
    ForceRefresh {
        accepted: oneshot::Sender<ListManagerCommandDisposition>,
        completion: oneshot::Sender<ForceRefreshCompletion>,
    },
}

/// Immutable completion payload for an operator-forced cycle.
#[derive(Clone)]
pub struct ForceRefreshCompletion {
    pub snapshot: crate::lists::status::RegistrySnapshot,
    pub max_total_domains: Option<usize>,
}

/// How the list-manager controller accepted an out-of-band command.
///
/// Acceptance is separate from completion: a refresh can take minutes, while
/// the controller must promptly tell callers whether their work has started,
/// joined an active refresh, or is queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListManagerCommandDisposition {
    Started,
    JoinedInFlight,
    Queued,
    CoalescedQueued,
}

impl ListManagerCommandDisposition {
    /// Stable wire/audit spelling for controller admission.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::JoinedInFlight => "joined_in_flight",
            Self::Queued => "queued",
            Self::CoalescedQueued => "coalesced_queued",
        }
    }
}

/// Owns one running list-manager controller generation.
///
/// Retirement drops command intake and queued requests, cancels preparation,
/// and waits only for the active worker (including any commit already begun).
pub struct ListManagerTask {
    retire_tx: oneshot::Sender<()>,
    join: tokio::task::JoinHandle<()>,
}

/// The private result carried across the blocking-worker boundary.
///
/// `snapshot` is the exact immutable value installed at this refresh's
/// completed-publication boundary. It must travel with the worker result:
/// loading the shared registry after the worker returns could instead see a
/// later reload's `ConfigRejected` or `SkippedUnchanged` publication.
struct RefreshCompletion {
    domain_count: usize,
    snapshot: crate::lists::status::RegistrySnapshot,
}

impl ListManagerTask {
    /// Gracefully retire this manager generation.
    pub async fn retire(self) -> Result<(), tokio::task::JoinError> {
        let Self { retire_tx, join } = self;
        let _ = retire_tx.send(());
        join.await
    }

    /// Whether the controller already exited, including a terminal worker
    /// panic.
    pub fn is_finished(&self) -> bool {
        self.join.is_finished()
    }

    #[cfg(all(test, not(feature = "cluster")))]
    pub(crate) fn finished_for_test() -> Self {
        let (retire_tx, _retire_rx) = oneshot::channel();
        let join = tokio::spawn(async {});
        Self { retire_tx, join }
    }
}

/// How much younger than `interval` a cached body must be to count as
/// fresh.
///
/// Compatibility sources still use age freshness, whereas planned sources
/// use canonical per-source deadlines. The margin prevents a cycle started
/// just before an age deadline from treating the body as fresh again, which
/// would defer the next acquisition by a whole interval.
///
/// Five seconds absorbs scheduler latency without collapsing the minimum
/// cadence; successful validation is stamped at the cycle anchor, not at
/// serial download completion.
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
    /// Normal daemon work: acquire only canonical sources whose ledger says
    /// they are due, while retaining every other source in the corpus.
    Scheduled,
    /// Operator or recovery work: attempt every enabled source. Conditional
    /// requests remain valid; only the cadence gate is bypassed.
    Force,
    /// Zero HTTP. The manifest-selected on-disk body is used at **any** age — a cache
    /// too old to be fresh is still infinitely better than no filtering,
    /// and the background cycle behind the listener is what refreshes it.
    CacheOnly,
}

/// Thin adapter over [`hardened_atomic_write`](crate::config::atomic_write::hardened_atomic_write) so the
/// cache-body / `.meta` manifest writes here share the same fsync +
/// mode-preservation contract as every config-mutation path.
/// Keeps `AtomicWriteError` intact so manifest commits can distinguish a
/// post-rename parent-fsync ambiguity from a definite failure.
fn atomic_write(
    path: &Path,
    content: &[u8],
) -> Result<(), crate::config::atomic_write::AtomicWriteError> {
    crate::config::atomic_write::hardened_atomic_write(
        path,
        content,
        crate::config::atomic_write::AtomicWriteOpts::default(),
    )
}

#[cfg(test)]
fn atomic_write_without_parent_fsync(path: &Path, content: &[u8]) -> std::io::Result<()> {
    crate::config::atomic_write::hardened_atomic_write(
        path,
        content,
        crate::config::atomic_write::AtomicWriteOpts {
            fsync_parent: false,
            ..Default::default()
        },
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
/// (`load_disk_cache`) or after an accepted download candidate,
/// so the `now_utc()` default is only ever observable on a freshly-
/// constructed entry that has not yet been used to gate a refresh.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// [`ListManager::resolve_retained_body_reader`] hands out `body.clone()` — a full
    /// second copy of the largest list, per source, per cycle. See
    /// [`LIST_CACHE_DIR_UNSET_WARNING`].
    body: Option<String>,
    /// Wall-clock UTC timestamp of the most recent successful fetch
    /// (`200 OK` or `304 Not Modified` — both confirm the cached
    /// content is current). Persisted to the `.meta` sidecar as an
    /// RFC 3339 line so it survives daemon restarts.
    fetched_at: OffsetDateTime,
}

#[derive(Clone)]
struct SourceSchedule {
    key: crate::lists::source_key::CanonicalSourceScheduleKey,
    interval: Duration,
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
    /// Representative → exact fetch URL. Production construction receives
    /// this from `ResolvedSourcePlan`; compatibility constructors resolve it
    /// once while they still own a catalog.
    fetch_urls: HashMap<String, String>,
    /// Present only for plan-backed managers so command aliases use the same
    /// generation that owns fetch and cache identity.
    source_plan: Option<ResolvedSourcePlan>,
    refresh_interval: Duration,
    /// Canonical cadence is plan-owned; compatibility managers retain the
    /// global interval and therefore keep their historical all-source work.
    source_schedules: HashMap<String, SourceSchedule>,
    /// Durable scheduling is intentionally separate from display health.
    schedule_state: ListScheduleState,
    schedule_state_path: Option<PathBuf>,
    /// A malformed sidecar means its absence is not evidence that legacy
    /// timestamps may safely author the first canonical ledger rows.
    allow_legacy_schedule_seed: bool,
    /// Compatibility anchors are considered once at construction; later
    /// missing rows are deliberately due immediately.
    legacy_schedule_seed_pending: bool,
    /// Legacy `.meta` files had no real fetch timestamp.  Their synthetic
    /// freshness remains a boot-compatibility aid, never a scheduler anchor.
    legacy_cache_timestamp_urls: HashSet<String>,
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
    /// Maximum decoded input bytes allowed per blocklist download, from
    /// `settings.lists.max_body_bytes`. Disk-backed HTTP stages chunks while
    /// resident fallbacks use [`read_bounded_body`]; this is not a
    /// process-memory budget.
    max_body_bytes: usize,
    /// Maximum entries per list, from `settings.lists.max_entries`.
    ///
    /// Bounds **one** source, and therefore bounds nothing in aggregate:
    /// eight sources at 10 M each is 80 M on paper. See
    /// [`Self::max_total_domains`] for the ceiling on the merged corpus.
    max_entries: usize,
    /// Plan-derived caps for canonical sources. Compatibility constructors
    /// fall back to `max_entries`, which remains the hard ceiling.
    source_max_entries: HashMap<String, usize>,
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
    /// list bodies are persisted as immutable `{stem}.body-<sha256>` files
    /// selected by `.meta` sidecars holding HTTP validators. On construction,
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
    /// shared across the refresh task and the daemon status diagnostics.
    list_state: Arc<std::sync::Mutex<crate::config::list_state::ListState>>,
    /// Path on disk for `list_state.toml`. `None` in tests / ephemeral
    /// runs — the helpers still mutate the in-memory state but skip
    /// the atomic write.
    list_state_path: Option<PathBuf>,
    /// Maps each planned source alias to its retry-state Id and failure
    /// threshold. Sources without an owning `[[blocklists]]` row are absent.
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
    #[cfg(test)]
    worker_hook: Option<WorkerHook>,
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
    static FAIL_NTH_SHARD_SPILL_WRITE: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static FAIL_SHARD_SPILL_ROLLBACK_AT: std::cell::Cell<Option<SpillRollbackSite>> = const { std::cell::Cell::new(None) };
    static FAIL_NTH_SHARD_SPILL_ROLLBACK_TRUNCATE: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static FAIL_NTH_SHARD_SPILL_ROLLBACK_SEEK: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static FAIL_NTH_SHARD_SPILL_FLUSH: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static FAIL_NTH_SHARD_SPILL_SYNC: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static FAIL_NTH_SHARD_SPILL_VALIDATION_READ: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static FAIL_NTH_SHARD_SPILL_GUARD_COUNT: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static TRUNCATE_FINAL_SHARD_SPILL_RECORD_BEFORE_VALIDATE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NTH_SHARD_BUILD: std::cell::Cell<Option<(usize, usize)>> = const { std::cell::Cell::new(None) };
    static FAIL_NEXT_SHARD_SPILL_DIR_CREATE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NTH_SHARD_SPILL_FILE_CREATE: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static FAIL_NEXT_CACHE_MANIFEST_WRITE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NEXT_CACHE_MANIFEST_PARENT_FSYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NTH_CACHE_MANIFEST_WRITE: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static CRASH_AFTER_NTH_CACHE_MANIFEST_COMMIT: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static FAIL_NTH_STREAMED_CACHE_BODY_WRITE: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    // Lets the bridge tests mutate the path after the opened handle was
    // measured. Thread-local keeps parallel tests independent.
    static IMPORTED_LOCAL_AFTER_METADATA_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static STAGED_CACHE_READER_CONSTRUCTED_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static STREAMED_CACHE_BODY_AFTER_PERSIST_HOOK: std::cell::RefCell<Option<StreamedCacheBodyAfterPersistHook>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
type StreamedCacheBodyAfterPersistHook = Box<dyn FnOnce(&Path)>;

#[cfg(test)]
fn fail_nth_shard_spill_write_for_test(n: usize) {
    assert!(n > 0);
    FAIL_NTH_SHARD_SPILL_WRITE.with(|remaining| {
        assert!(
            remaining.replace(Some(n)).is_none(),
            "shard spill write failure hook already armed"
        );
    });
}

#[cfg(test)]
fn fail_shard_spill_write_for_test() -> bool {
    FAIL_NTH_SHARD_SPILL_WRITE.with(|remaining| match remaining.get() {
        Some(1) => {
            remaining.set(None);
            true
        }
        Some(n) => {
            remaining.set(Some(n - 1));
            false
        }
        None => false,
    })
}

#[cfg(test)]
fn fail_shard_spill_rollback_at_for_test(site: SpillRollbackSite) {
    FAIL_SHARD_SPILL_ROLLBACK_AT.with(|armed| {
        assert!(
            armed.replace(Some(site)).is_none(),
            "shard spill rollback failure hook already armed"
        );
    });
}

#[cfg(test)]
fn fail_shard_spill_rollback_for_test(site: SpillRollbackSite) -> bool {
    FAIL_SHARD_SPILL_ROLLBACK_AT.with(|armed| match armed.get() {
        Some(requested) if requested == site => {
            armed.set(None);
            true
        }
        _ => false,
    })
}

#[cfg(test)]
fn fail_nth_shard_spill_rollback_truncate_for_test(n: usize) {
    assert!(n > 0);
    FAIL_NTH_SHARD_SPILL_ROLLBACK_TRUNCATE.with(|remaining| {
        assert!(
            remaining.replace(Some(n)).is_none(),
            "shard spill rollback-truncate failure hook already armed"
        );
    });
}

#[cfg(test)]
fn fail_shard_spill_rollback_truncate_for_test() -> bool {
    FAIL_NTH_SHARD_SPILL_ROLLBACK_TRUNCATE.with(|remaining| match remaining.get() {
        Some(1) => {
            remaining.set(None);
            true
        }
        Some(n) => {
            remaining.set(Some(n - 1));
            false
        }
        None => false,
    })
}

#[cfg(test)]
fn fail_nth_shard_spill_rollback_seek_for_test(n: usize) {
    assert!(n > 0);
    FAIL_NTH_SHARD_SPILL_ROLLBACK_SEEK.with(|remaining| {
        assert!(
            remaining.replace(Some(n)).is_none(),
            "shard spill rollback-seek failure hook already armed"
        );
    });
}

#[cfg(test)]
fn fail_shard_spill_rollback_seek_for_test() -> bool {
    FAIL_NTH_SHARD_SPILL_ROLLBACK_SEEK.with(|remaining| match remaining.get() {
        Some(1) => {
            remaining.set(None);
            true
        }
        Some(n) => {
            remaining.set(Some(n - 1));
            false
        }
        None => false,
    })
}

#[cfg(test)]
fn fail_nth_shard_spill_flush_for_test(n: usize) {
    assert!(n > 0);
    FAIL_NTH_SHARD_SPILL_FLUSH.with(|remaining| remaining.set(Some(n)));
}

#[cfg(test)]
fn fail_shard_spill_flush_for_test() -> bool {
    FAIL_NTH_SHARD_SPILL_FLUSH.with(|remaining| match remaining.get() {
        Some(1) => {
            remaining.set(None);
            true
        }
        Some(n) => {
            remaining.set(Some(n - 1));
            false
        }
        None => false,
    })
}

#[cfg(test)]
fn fail_nth_shard_spill_sync_for_test(n: usize) {
    assert!(n > 0);
    FAIL_NTH_SHARD_SPILL_SYNC.with(|remaining| {
        assert!(
            remaining.replace(Some(n)).is_none(),
            "shard spill sync failure hook already armed"
        );
    });
}

#[cfg(test)]
fn fail_shard_spill_sync_for_test() -> bool {
    FAIL_NTH_SHARD_SPILL_SYNC.with(|remaining| match remaining.get() {
        Some(1) => {
            remaining.set(None);
            true
        }
        Some(n) => {
            remaining.set(Some(n - 1));
            false
        }
        None => false,
    })
}

#[cfg(test)]
fn fail_nth_shard_spill_validation_read_for_test(n: usize) {
    assert!(n > 0);
    FAIL_NTH_SHARD_SPILL_VALIDATION_READ.with(|remaining| {
        assert!(
            remaining.replace(Some(n)).is_none(),
            "shard spill validation-read failure hook already armed"
        );
    });
}

#[cfg(test)]
fn fail_shard_spill_validation_read_for_test() -> bool {
    FAIL_NTH_SHARD_SPILL_VALIDATION_READ.with(|remaining| match remaining.get() {
        Some(1) => {
            remaining.set(None);
            true
        }
        Some(n) => {
            remaining.set(Some(n - 1));
            false
        }
        None => false,
    })
}

#[cfg(test)]
fn fail_nth_shard_spill_guard_count_for_test(n: usize) {
    assert!(n > 0);
    FAIL_NTH_SHARD_SPILL_GUARD_COUNT.with(|remaining| {
        assert!(
            remaining.replace(Some(n)).is_none(),
            "shard spill guard-count failure hook already armed"
        );
    });
}

#[cfg(test)]
fn fail_shard_spill_guard_count_for_test() -> bool {
    FAIL_NTH_SHARD_SPILL_GUARD_COUNT.with(|remaining| match remaining.get() {
        Some(1) => {
            remaining.set(None);
            true
        }
        Some(n) => {
            remaining.set(Some(n - 1));
            false
        }
        None => false,
    })
}

#[cfg(test)]
fn truncate_final_shard_spill_record_before_validate_for_test() {
    TRUNCATE_FINAL_SHARD_SPILL_RECORD_BEFORE_VALIDATE.with(|armed| {
        assert!(
            !armed.replace(true),
            "shard spill exact-boundary truncation hook already armed"
        );
    });
}

#[cfg(test)]
fn take_truncate_final_shard_spill_record_before_validate_for_test() -> bool {
    TRUNCATE_FINAL_SHARD_SPILL_RECORD_BEFORE_VALIDATE.with(|armed| armed.replace(false))
}

#[cfg(test)]
fn fail_nth_shard_build_for_test(n: usize) {
    fail_nth_shard_builds_for_test(n, 1);
}

#[cfg(test)]
fn fail_nth_shard_builds_for_test(n: usize, failures: usize) {
    assert!(n > 0);
    assert!(failures > 0);
    FAIL_NTH_SHARD_BUILD.with(|remaining| {
        assert!(
            remaining.replace(Some((n, failures))).is_none(),
            "shard build failure hook already armed"
        );
    });
}

#[cfg(test)]
fn fail_shard_build_for_test() -> bool {
    FAIL_NTH_SHARD_BUILD.with(|remaining| match remaining.get() {
        Some((1, 1)) => {
            remaining.set(None);
            true
        }
        Some((1, failures)) => {
            remaining.set(Some((1, failures - 1)));
            true
        }
        Some((n, failures)) => {
            remaining.set(Some((n - 1, failures)));
            false
        }
        None => false,
    })
}

#[cfg(test)]
fn fail_next_shard_spill_dir_create_for_test() {
    FAIL_NEXT_SHARD_SPILL_DIR_CREATE.with(|fail| {
        assert!(
            !fail.replace(true),
            "shard spill directory-create failure hook already armed"
        );
    });
}

#[cfg(test)]
fn fail_shard_spill_dir_create_for_test() -> bool {
    FAIL_NEXT_SHARD_SPILL_DIR_CREATE.with(|fail| fail.replace(false))
}

#[cfg(test)]
fn fail_nth_shard_spill_file_create_for_test(n: usize) {
    assert!(n > 0);
    FAIL_NTH_SHARD_SPILL_FILE_CREATE.with(|remaining| {
        assert!(
            remaining.replace(Some(n)).is_none(),
            "shard spill file-create failure hook already armed"
        );
    });
}

#[cfg(test)]
fn fail_shard_spill_file_create_for_test() -> bool {
    FAIL_NTH_SHARD_SPILL_FILE_CREATE.with(|remaining| match remaining.get() {
        Some(1) => {
            remaining.set(None);
            true
        }
        Some(n) => {
            remaining.set(Some(n - 1));
            false
        }
        None => false,
    })
}

#[cfg(test)]
fn fail_next_cache_manifest_write_for_test() {
    FAIL_NEXT_CACHE_MANIFEST_WRITE.with(|fail| {
        assert!(
            !fail.replace(true),
            "cache manifest failure hook already armed"
        );
    });
}

#[cfg(test)]
fn fail_nth_streamed_cache_body_write_for_test(n: usize) {
    assert!(n > 0);
    FAIL_NTH_STREAMED_CACHE_BODY_WRITE.with(|remaining| {
        assert!(
            remaining.replace(Some(n)).is_none(),
            "streamed cache-body write failure hook already armed"
        );
    });
}

#[cfg(test)]
fn fail_streamed_cache_body_write_for_test() -> bool {
    FAIL_NTH_STREAMED_CACHE_BODY_WRITE.with(|remaining| match remaining.get() {
        Some(1) => {
            remaining.set(None);
            true
        }
        Some(n) => {
            remaining.set(Some(n - 1));
            false
        }
        None => false,
    })
}

#[cfg(test)]
fn fail_next_cache_manifest_parent_fsync_for_test() {
    FAIL_NEXT_CACHE_MANIFEST_PARENT_FSYNC.with(|fail| {
        assert!(
            !fail.replace(true),
            "cache manifest parent-fsync failure hook already armed"
        );
    });
}

#[cfg(test)]
fn fail_nth_cache_manifest_write_for_test(n: usize) {
    assert!(n > 0);
    FAIL_NTH_CACHE_MANIFEST_WRITE.with(|remaining| {
        assert!(
            remaining.replace(Some(n)).is_none(),
            "cache manifest failure hook already armed"
        );
    });
}

#[cfg(test)]
fn crash_after_nth_cache_manifest_commit_for_test(n: usize) {
    assert!(n > 0);
    CRASH_AFTER_NTH_CACHE_MANIFEST_COMMIT.with(|remaining| {
        assert!(
            remaining.replace(Some(n)).is_none(),
            "cache manifest crash hook already armed"
        );
    });
}

#[cfg(test)]
fn fail_cache_manifest_write_for_test() -> bool {
    FAIL_NTH_CACHE_MANIFEST_WRITE.with(|remaining| match remaining.get() {
        Some(1) => {
            remaining.set(None);
            true
        }
        Some(n) => {
            remaining.set(Some(n - 1));
            false
        }
        None => false,
    })
}

#[cfg(test)]
fn crash_after_cache_manifest_commit_for_test() {
    CRASH_AFTER_NTH_CACHE_MANIFEST_COMMIT.with(|remaining| match remaining.get() {
        Some(1) => {
            remaining.set(None);
            panic!("injected process interruption after cache manifest commit");
        }
        Some(n) => remaining.set(Some(n - 1)),
        None => {}
    });
}

#[cfg(test)]
fn set_imported_local_after_metadata_hook_for_test(hook: impl FnOnce() + 'static) {
    IMPORTED_LOCAL_AFTER_METADATA_HOOK.with(|slot| {
        assert!(
            slot.borrow().is_none(),
            "imported-local test hook already armed"
        );
        *slot.borrow_mut() = Some(Box::new(hook));
    });
}

#[cfg(test)]
fn run_imported_local_after_metadata_hook_for_test() {
    let hook = IMPORTED_LOCAL_AFTER_METADATA_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(test)]
fn set_staged_cache_reader_constructed_hook_for_test(hook: impl FnOnce() + 'static) {
    STAGED_CACHE_READER_CONSTRUCTED_HOOK.with(|slot| {
        assert!(
            slot.borrow().is_none(),
            "staged cache reader test hook already armed"
        );
        *slot.borrow_mut() = Some(Box::new(hook));
    });
}

#[cfg(test)]
fn run_staged_cache_reader_constructed_hook_for_test() {
    let hook = STAGED_CACHE_READER_CONSTRUCTED_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(test)]
fn set_streamed_cache_body_after_persist_hook_for_test(hook: impl FnOnce(&Path) + 'static) {
    STREAMED_CACHE_BODY_AFTER_PERSIST_HOOK.with(|slot| {
        assert!(
            slot.borrow().is_none(),
            "streamed cache-body post-persist test hook already armed"
        );
        *slot.borrow_mut() = Some(Box::new(hook));
    });
}

#[cfg(test)]
fn run_streamed_cache_body_after_persist_hook_for_test(path: &Path) {
    let hook = STREAMED_CACHE_BODY_AFTER_PERSIST_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook(path);
    }
}

impl ListManager {
    /// Create a new list manager.
    ///
    /// `sources` are list IDs (e.g. `"privacy/ads"`) or raw URLs.
    /// `refresh_interval` is clamped to a minimum of 60 seconds.
    /// `source_bits` maps each source to its bit index for bitmask tagging.
    /// `max_body_bytes` is the per-download size cap; typical value is
    /// `settings.lists.max_body_bytes` (default
    /// [`crate::config::settings::DEFAULT_MAX_LIST_BODY_BYTES]).
    /// `max_entries` is the global lists-section entry cap applied to each
    /// source; typical value is `settings.lists.max_entries` (default
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
        let fetch_urls = sources
            .iter()
            .filter_map(|source| catalog.resolve(source).map(|url| (source.clone(), url)))
            .collect();
        Self::with_fetch_urls(
            client,
            filter,
            sources,
            fetch_urls,
            None,
            refresh_interval,
            source_bits,
            source_tokens,
            max_body_bytes,
            max_entries,
            cache_dir,
        )
    }

    /// Construct a manager from the generation's resolved fetch plan.
    #[allow(clippy::too_many_arguments)]
    pub fn with_plan_and_tokens(
        client: reqwest::Client,
        filter: Arc<FilterEngine>,
        plan: ResolvedSourcePlan,
        refresh_interval: Duration,
        source_bits: SourceBitMap,
        source_tokens: SourceTokenMap,
        max_body_bytes: usize,
        max_entries: usize,
        cache_dir: Option<PathBuf>,
    ) -> Self {
        let sources = plan.representatives();
        let fetch_urls = plan.fetch_urls();
        Self::with_fetch_urls(
            client,
            filter,
            sources,
            fetch_urls,
            Some(plan),
            refresh_interval,
            source_bits,
            source_tokens,
            max_body_bytes,
            max_entries,
            cache_dir,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn with_fetch_urls(
        client: reqwest::Client,
        filter: Arc<FilterEngine>,
        sources: Vec<String>,
        fetch_urls: HashMap<String, String>,
        source_plan: Option<ResolvedSourcePlan>,
        refresh_interval: Duration,
        source_bits: SourceBitMap,
        source_tokens: SourceTokenMap,
        max_body_bytes: usize,
        max_entries: usize,
        cache_dir: Option<PathBuf>,
    ) -> Self {
        let refresh_interval = refresh_interval.max(MIN_REFRESH_INTERVAL);
        let status_registry = match source_plan.as_ref() {
            Some(plan) => Arc::new(ListStatusRegistry::from_plan(plan)),
            None => Arc::new(ListStatusRegistry::new(&sources)),
        };
        // Startup: `FilterEngine::shard_index` is seeded per process, so a
        // spill partition left by a previous (crashed) daemon is silent
        // garbage to this one — ~15/16 of every list would be unreachable
        // if it were ever resumed. Delete, never resume.
        if let Some(dir) = cache_dir.as_deref() {
            purge_shard_spill(dir);
        }
        let source_schedules = source_plan
            .as_ref()
            .map(|plan| {
                plan.sources()
                    .map(|source| {
                        (
                            source.representative().to_string(),
                            SourceSchedule {
                                key: source.schedule_key().clone(),
                                interval: Duration::from_secs(
                                    source.effective_update_interval_secs(),
                                )
                                .max(MIN_REFRESH_INTERVAL),
                            },
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self {
            client,
            filter,
            sources,
            fetch_urls,
            source_plan,
            refresh_interval,
            source_schedules,
            schedule_state: ListScheduleState::default(),
            schedule_state_path: None,
            allow_legacy_schedule_seed: true,
            legacy_schedule_seed_pending: true,
            legacy_cache_timestamp_urls: HashSet::new(),
            cache: HashMap::new(),
            policy_masks: PolicyMasks::default(),
            source_bits,
            source_tokens,
            max_body_bytes,
            max_entries,
            source_max_entries: HashMap::new(),
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
            #[cfg(test)]
            worker_hook: None,
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

    /// Install the canonical scheduler ledger read by the process owner.
    /// Read failures are handled at the boundary so a bad sidecar cannot
    /// prevent retained filtering from starting.
    pub fn set_schedule_state(
        &mut self,
        state: ListScheduleState,
        path: Option<PathBuf>,
        allow_legacy_seed: bool,
    ) {
        self.schedule_state = state;
        self.schedule_state_path = path;
        self.allow_legacy_schedule_seed = allow_legacy_seed;
        self.legacy_schedule_seed_pending = allow_legacy_seed;
    }

    fn persist_schedule_state(&self) {
        if let Some(path) = &self.schedule_state_path {
            if let Err(error) = self.schedule_state.write_atomic(path) {
                tracing::warn!(path = %path.display(), %error, "failed to persist list scheduling state");
            }
        }
    }

    fn source_deadline(&self, source: &str, now: OffsetDateTime) -> Option<OffsetDateTime> {
        let schedule = self.source_schedules.get(source)?;
        let Some(entry) = self.schedule_state.lookup(&schedule.key) else {
            return Some(now);
        };
        Some(schedule_deadline(schedule, entry, now))
    }

    fn source_is_due(&self, source: &str, now: OffsetDateTime) -> bool {
        self.source_deadline(source, now)
            .is_none_or(|deadline| deadline <= now)
    }

    fn seed_schedule_state(&mut self, now: OffsetDateTime) {
        let mut changed = false;
        if self.source_plan.is_some() {
            let current_keys: BTreeSet<_> = self
                .source_schedules
                .values()
                .map(|schedule| schedule.key.clone())
                .collect();
            let before = self.schedule_state.clone();
            self.schedule_state.prune(&current_keys);
            changed = self.schedule_state != before;
        }
        if !self.allow_legacy_schedule_seed || !self.legacy_schedule_seed_pending {
            if changed {
                self.persist_schedule_state();
            }
            return;
        }
        for (source, schedule) in &self.source_schedules {
            if self.schedule_state.lookup(&schedule.key).is_some() {
                continue;
            }
            let Some(url) = self.fetch_urls.get(source) else {
                continue;
            };
            // A retained representation is the minimum evidence a legacy
            // timestamp can describe; otherwise this source is due now.
            if self.resolve_retained_body_reader(url, source).is_none() {
                continue;
            }
            let legacy = self.source_plan.as_ref().and_then(|plan| {
                let aliases = plan
                    .sources()
                    .find(|planned| planned.representative() == source)?
                    .id_aliases();
                let state = self.list_state.lock().unwrap_or_else(|e| e.into_inner());
                aliases
                    .iter()
                    .filter_map(|id| state.lists.get(id).cloned())
                    .filter_map(|entry| entry.last_attempt.map(|anchor| (anchor, entry)))
                    // A future clock-skewed alias must not hide an older,
                    // usable compatibility anchor.
                    .filter(|(anchor, _)| *anchor <= now)
                    .max_by_key(|(anchor, _)| *anchor)
            });
            let cache_anchor = (!self.legacy_cache_timestamp_urls.contains(url))
                .then(|| self.cache.get(url).map(|entry| entry.fetched_at))
                .flatten()
                // As above, discard bad future evidence before comparing it
                // with an older valid alias timestamp.
                .filter(|anchor| *anchor <= now);
            let (anchor, outcome) = match (legacy, cache_anchor) {
                (Some(legacy), Some(cache)) if legacy.0 >= cache => {
                    let (legacy, entry) = legacy;
                    let failed = entry.consecutive_failures > 0;
                    (
                        legacy,
                        if failed {
                            CanonicalScheduleOutcome::Failure
                        } else {
                            CanonicalScheduleOutcome::Success
                        },
                    )
                }
                (_, Some(cache)) => (cache, CanonicalScheduleOutcome::Success),
                (Some((legacy, entry)), None) => (
                    legacy,
                    if entry.consecutive_failures > 0 {
                        CanonicalScheduleOutcome::Failure
                    } else {
                        CanonicalScheduleOutcome::Success
                    },
                ),
                (None, None) => continue,
            };
            if self
                .schedule_state
                .seed_if_absent(schedule.key.clone(), anchor, outcome)
            {
                changed = true;
            }
        }
        if changed {
            self.persist_schedule_state();
        }
        self.legacy_schedule_seed_pending = false;
    }

    fn record_schedule_attempts(
        &mut self,
        attempts: &HashSet<String>,
        successes: &HashSet<String>,
        now: OffsetDateTime,
    ) {
        if attempts.is_empty() {
            return;
        }
        for source in attempts {
            if let Some(schedule) = self.source_schedules.get(source) {
                if successes.contains(source) {
                    self.schedule_state
                        .record_success(schedule.key.clone(), now);
                } else {
                    self.schedule_state
                        .record_failure(schedule.key.clone(), now);
                }
            }
        }
        self.persist_schedule_state();
    }

    fn next_schedule_wait(&self, now: OffsetDateTime) -> Duration {
        self.source_schedules
            .values()
            .map(|schedule| {
                let deadline = self
                    .source_deadline_for_schedule(schedule, now)
                    .unwrap_or(now);
                if deadline <= now {
                    Duration::ZERO
                } else {
                    (deadline - now).try_into().unwrap_or(Duration::MAX)
                }
            })
            .min()
            .unwrap_or(self.refresh_interval)
    }

    fn next_loop_wait(&self, now: OffsetDateTime) -> Duration {
        let next = self.next_schedule_wait(now);
        if self.status_registry.cycle().generation_degraded {
            degraded_refresh_interval(next)
        } else {
            next
        }
    }

    fn source_deadline_for_schedule(
        &self,
        schedule: &SourceSchedule,
        now: OffsetDateTime,
    ) -> Option<OffsetDateTime> {
        let entry = self.schedule_state.lookup(&schedule.key)?;
        Some(schedule_deadline(schedule, entry, now))
    }

    /// Handle to the in-memory list state for daemon diagnostics.
    pub fn list_state_handle(&self) -> Arc<std::sync::Mutex<crate::config::list_state::ListState>> {
        self.list_state.clone()
    }

    /// Register the source-string → (canonical `Id`,
    /// `max_consecutive_failures`) mapping the refresh loop consults
    /// when it needs to drive the retry state machine.
    ///
    /// `start.rs` derives this map from the same resolved source plan used by
    /// the manager and [`SourceBitMap`]. Sources without a blocklist owner do
    /// not participate in the retry state machine.
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

    /// Record a source failure, stamping only the retained cache body that
    /// was accepted in this failure-path cycle.
    fn record_blocklist_failure_for_source(
        &self,
        blocklist_id: &crate::config::schema::Id,
        max_consecutive_failures: u32,
        retained_cache_path: Option<PathBuf>,
    ) -> bool {
        match retained_cache_path {
            Some(cache_path) => self.record_blocklist_failure_with_cache(
                blocklist_id,
                max_consecutive_failures,
                cache_path,
            ),
            None => self.record_blocklist_failure(blocklist_id, max_consecutive_failures),
        }
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
    fn shrink_verdict(
        &self,
        prev: Option<&ListStatus>,
        fresh_unique: u64,
        max_entries: usize,
    ) -> ShrinkVerdict {
        compute_shrink_verdict(
            self.shrink_guard_enabled,
            self.shrink_guard_max_drop_pct,
            prev,
            fresh_unique,
            max_entries,
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
    /// The probe is available in either compatibility mode for retained bodies,
    /// except that scheduled work excludes `imported.local`: its live candidate must reach
    /// the bridge. The probe enforces `is_cache_fresh` itself, so a settled
    /// source *is* interval-fresh even on a `CacheOnly` boot — but stamping a
    /// verified refresh there would mean a cycle that issued no HTTP and was
    /// never allowed to still reported one, which is the freshness lie
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
        // Planned scheduled work must parse every retained non-due body: its
        // per-source health and spill guards are part of scheduler semantics.
        if matches!(mode, RefreshMode::Scheduled) && !self.source_schedules.is_empty() {
            return None;
        }
        let installed = self.installed_corpus_digest?;
        // No disk cache means the bodies live in RAM (or nowhere); that
        // path has its own problems (see `mem2608-s7`) and is not worth a
        // second code path here.
        self.cache_dir.as_ref()?;

        let mut digest_ctx = new_corpus_digest_ctx(&self.policy_masks);
        let mut pending = Vec::with_capacity(resolved.len());
        let mut spilled = 0u64;

        for (source, url) in resolved {
            // Scheduled or forced work must validate imported.local through the
            // bridge. Its current operator file is a candidate, never a
            // fresh-cache or digest-probe input.
            if matches!(mode, RefreshMode::Scheduled | RefreshMode::Force)
                && is_imported_local_url(url)
            {
                return None;
            }
            if matches!(mode, RefreshMode::Force)
                || (matches!(mode, RefreshMode::Scheduled)
                    && self.source_schedules.contains_key(source)
                    && self.source_is_due(source, now))
            {
                return None;
            }
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
            // Same retained-body opener as the parse path, including the
            // §4.7-T3 size validation.
            let reader = self.resolve_retained_body_reader(url, source)?;
            let body_hash = hash_retained_body(reader).ok()?;
            let declared_format = self.source_to_format.get(source.as_str()).copied();
            fold_corpus_digest(
                &mut digest_ctx,
                source,
                1u64 << bit,
                self.source_max_entries
                    .get(source.as_str())
                    .copied()
                    .unwrap_or(self.max_entries),
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
                // Same rule as the cache-hit arm below, reached by a different
                // route. Spelled out
                // rather than inherited, as the field doc requires.
                verified_fresh: self.source_schedules.is_empty()
                    && matches!(mode, RefreshMode::Scheduled),
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
    /// `source_trust` is the typed [`SourceTrustMap`] facade built from the
    /// resolved source plan; lookups happen by fetch URL
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
            .load_persisted(&path, self.max_entries, &self.source_max_entries);
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

    /// State of the latest completed generation attempt.
    #[must_use]
    pub fn served_state(&self) -> ServedState {
        self.status_registry.cycle().served_state
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
    /// This is an installed-union entry ceiling, not a process-memory budget.
    /// Peak memory also depends on raw rows, domain lengths and allocator
    /// retention.
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
            .load_persisted(path, self.max_entries, &self.source_max_entries);
    }

    /// Install the caps resolved by the source plan.
    pub fn set_source_max_entries(&mut self, caps: HashMap<String, usize>) {
        self.source_max_entries = caps
            .into_iter()
            .map(|(source, cap)| (source, cap.min(self.max_entries)))
            .collect();
    }

    #[cfg(test)]
    pub(crate) fn source_max_entries_for(&self, source: &str) -> usize {
        self.source_max_entries
            .get(source)
            .copied()
            .unwrap_or(self.max_entries)
    }

    /// Record a failed refresh after the retention guard confirmed a cached
    /// body, preserving that cache path in retry state.
    pub fn record_blocklist_failure_with_cache(
        &self,
        blocklist_id: &crate::config::schema::Id,
        max_consecutive_failures: u32,
        cache_path: PathBuf,
    ) -> bool {
        let now = time::OffsetDateTime::now_utc();
        let mut state = self.list_state.lock().unwrap_or_else(|e| e.into_inner());
        let entry = state.lists.entry(blocklist_id.clone()).or_default();
        // Stamp before the transition so the failure records the confirmed cache.
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
    /// Reload publishes the new source plan into this registry before the
    /// replacement manager starts updating its slots.
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

    #[cfg(test)]
    pub(crate) fn set_worker_hook_for_test(&mut self, hook: impl FnMut(&str) + Send + 'static) {
        self.worker_hook = Some(Box::new(hook));
    }

    /// §4.7 Phase 2 T1: drop the in-memory cache entry for `source`
    /// and unlink its cache bodies + `<stem>.meta` sidecar from
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
        let representative = match self.representative_for_command(source) {
            Some(representative) => representative,
            None => return false,
        };
        let url = self.fetch_urls.get(&representative).cloned();
        let was_in_memory = url
            .as_deref()
            .map(|url| self.cache.remove(url).is_some())
            .unwrap_or(false);
        if let Some(url) = &url {
            self.legacy_cache_timestamp_urls.remove(url);
        }

        let mut disk_had_files = false;
        if let Some(cache_dir) = self.cache_dir.clone() {
            let stem = source_to_cache_stem(&representative);
            let cache_path = cache_dir.join(format!("{stem}.cache"));
            let meta_path = cache_dir.join(format!("{stem}.meta"));
            let mut paths = vec![cache_path, meta_path];
            paths.extend(generation_body_paths(&cache_dir, &stem));
            for path in paths {
                match std::fs::remove_file(&path) {
                    Ok(()) => {
                        disk_had_files = true;
                        // rev-2606 §06 carryover-2: the source string is
                        // operator-supplied over IPC; Debug-format it so a
                        // newline / ANSI escape can't spoof or corrupt the
                        // log line.
                        tracing::info!(
                            source = ?representative,
                            path = %path.display(),
                            "list cache file forgotten"
                        );
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => tracing::warn!(
                        source = ?representative,
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
        let reset_any = self.status_registry.reset_baseline(&representative);
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

    fn representative_for_command(&self, source: &str) -> Option<String> {
        if let Some(plan) = self.source_plan.as_ref() {
            return plan.representative_for_source(source).map(str::to_string);
        }
        self.sources
            .iter()
            .find(|representative| {
                *representative == source
                    || crate::lists::source_key::canonical_url_key(representative)
                        == crate::lists::source_key::canonical_url_key(source)
            })
            .cloned()
            .or_else(|| {
                self.fetch_urls
                    .iter()
                    .find(|(_, url)| {
                        crate::lists::source_key::canonical_url_key(url)
                            == crate::lists::source_key::canonical_url_key(source)
                    })
                    .map(|(representative, _)| representative.clone())
            })
    }

    /// Download all configured lists, merge into bitmask-tagged map, and swap.
    ///
    /// Each source is downloaded (or served from cache on 304/error). Domains
    /// are parsed into a `HashMap<CompactString, u64>` where the u64 is the
    /// OR of all lists that contain that domain. This deduplicates automatically
    /// while preserving per-list membership information.
    ///
    /// **Memory strategy**: disk-backed fresh HTTP bodies stream into an
    /// unselected generation and are parsed from that file. Retained disk
    /// bodies stream too; only no-cache and imported-local bridges are
    /// resident.
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
    /// The global `max_entries` cap applies per source, so eight sources
    /// at 10 M each is 80 M on paper. Only
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
    fn corpus_guard(
        &self,
        spill: &mut ShardSpill,
        serving: usize,
    ) -> std::io::Result<CorpusVerdict> {
        let Some(ceiling) = self.max_total_domains else {
            return Ok(CorpusVerdict::Unmeasured);
        };

        let mut novel_by_bit = [0u64; 64];
        let mut per_shard = Vec::with_capacity(DOMAIN_SHARDS);
        for idx in 0..DOMAIN_SHARDS {
            per_shard.push(spill.count_unique(idx, &mut novel_by_bit)? as usize);
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
            // With no installed generation, admit a bounded entry-count
            // exception so startup does not leave filtering unavailable.
            if serving == 0 && u128::from(unique) <= cold_start_hard_cap(ceiling) {
                return Ok(CorpusVerdict::InstallOverCeiling {
                    unique,
                    ceiling,
                    per_shard,
                });
            }
            return Ok(CorpusVerdict::Refuse {
                unique,
                ceiling,
                novel_by_bit: Box::new(novel_by_bit),
            });
        }
        // 90 % of the operator's own value, as a cross-multiplication so
        // that no configured ceiling can overflow the arithmetic and no
        // small one is distorted by integer division.
        let warn = u128::from(unique) * 10 >= (ceiling as u128) * 9;
        Ok(CorpusVerdict::Install {
            unique,
            per_shard,
            warn,
        })
    }

    /// Run the normal scheduler cycle: planned sources acquire only when due;
    /// non-due sources still parse retained bodies to preserve the corpus.
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

    /// Run one cycle and return the immutable view published at completion.
    ///
    /// This is for one-shot callers that must render the result they just
    /// produced, rather than re-reading a registry that another cycle could
    /// have replaced meanwhile.
    pub async fn refresh_with_mode_snapshot(
        &mut self,
        mode: RefreshMode,
    ) -> crate::lists::status::RegistrySnapshot {
        self.refresh_at_with_mode_completion(OffsetDateTime::now_utc(), mode)
            .await
            .expect("foreground refresh has no cancellation signal")
            .snapshot
    }

    /// Completion for a foreground forced refresh, including the exact
    /// manager ceiling (zero means explicitly disabled).
    pub async fn force_refresh_completion(&mut self) -> ForceRefreshCompletion {
        let snapshot = self.refresh_with_mode_snapshot(RefreshMode::Force).await;
        ForceRefreshCompletion {
            snapshot,
            max_total_domains: Some(self.max_total_domains.unwrap_or(0)),
        }
    }

    /// [`Self::refresh`] with the cycle anchor supplied by the caller.
    ///
    /// Scheduled mode — the anchor is orthogonal to the mode.
    pub(crate) async fn refresh_at(&mut self, now: OffsetDateTime) -> usize {
        self.refresh_at_with_mode(now, RefreshMode::Scheduled).await
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
    /// [`RefreshMode::Scheduled`] a due source may reach `download_list`
    /// (conditional GET, the age-based freshness shortcut, 304 handling);
    /// under [`RefreshMode::CacheOnly`] `download_list` is never called —
    /// a source without a usable manifest-selected body contributes nothing
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
        self.refresh_at_with_mode_completion(now, mode)
            .await
            .expect("foreground refresh has no cancellation signal")
            .domain_count
    }

    /// Private refresh form used by the actor worker. In addition to the
    /// public domain count, it returns the immutable snapshot produced at the
    /// exact completed-cycle publication boundary.
    async fn refresh_at_with_mode_completion(
        &mut self,
        now: OffsetDateTime,
        mode: RefreshMode,
    ) -> Result<RefreshCompletion, Cancelled> {
        cancellation::checkpoint("start")?;
        if !matches!(mode, RefreshMode::CacheOnly) {
            self.seed_schedule_state(now);
        }
        // Cycle entry: a spill partition is only valid for the process
        // that wrote it, so anything still on disk is garbage regardless
        // of who left it there. Never resumed.
        if let Some(dir) = self.cache_dir.as_deref() {
            purge_shard_spill(dir);
        }
        let estimated = self.filter.domain_count().max(100_000);
        let spill_cleanup = SpillCleanup(self.cache_dir.clone());
        let mut spill = match ShardSpill::open(self.cache_dir.as_deref()) {
            Ok(spill) => spill,
            Err(error) => {
                let path = self
                    .cache_dir
                    .as_deref()
                    .map(|dir| dir.join(SHARD_SPILL_DIR));
                tracing::error!(
                    path = ?path.as_deref().map(Path::display),
                    %error,
                    "cannot initialize disk shard spill; refusing list refresh (fix cache directory access or explicitly disable disk cache)"
                );
                cancellation::begin_commit()?;
                let snapshot = self
                    .status_registry
                    .record_cycle_with_qualifiers_and_served_state(
                        CycleOutcome::SpillRollbackFailed,
                        true,
                        true,
                        self.filter.domain_count(),
                        None,
                    );
                return Ok(RefreshCompletion {
                    domain_count: self.filter.domain_count(),
                    snapshot,
                });
            }
        };
        // Success-path status writes, applied after pass 2 supplies
        // `entries`.
        let mut pending: Vec<PendingStatus> = Vec::new();
        // Fresh disk bodies are immutable staging files until the complete
        // corpus reaches the engine. Keep only commit metadata here.
        let mut pending_cache_admissions: Vec<PendingCacheAdmission> = Vec::new();
        // Delay 304 freshness so cancellation leaves retained metadata unchanged.
        let mut pending_cache_revalidations: Vec<PendingCacheRevalidation> = Vec::new();
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
        // A failed rollback leaves an uncertain spill, so this cycle cannot publish it.
        let mut spill_rollback_failed = false;
        // A source only counts as covered once this cycle has a usable body
        // for it. A hot refresh may never replace a complete live corpus
        // with the subset that happened to parse.
        let mut source_coverage_complete = true;

        let resolved: Vec<(String, String)> = self
            .sources
            .iter()
            .filter_map(|source| {
                let url = self.fetch_urls.get(source).cloned();
                if url.is_none() {
                    tracing::warn!(
                        source = source.as_str(),
                        "source has no resolved fetch URL, skipping"
                    );
                    source_coverage_complete = false;
                }
                url.map(|url| (source.clone(), url))
            })
            .collect();

        let interval = self.refresh_interval;
        let mut schedule_attempts = HashSet::new();
        let mut schedule_successes = HashSet::new();

        // ── mem2608-s1 T3: settle an unchanged corpus without parsing it ──
        //
        // Measured on the lab host 2026-08-16: a cycle where every source
        // took the fresh-cache arm cost +220.3 MiB of VmHWM and 43 s of
        // CPU, issued zero HTTP requests, and installed nothing. All of it
        // was spent rebuilding a digest the daemon already held. The probe
        // rebuilds that digest from the bodies' bytes alone — no parse, no
        // spill, no dedup set, ~64 KB of buffer — and when it matches, the
        // loop below has nothing left to do.
        let probe =
            cancellation::checked(self.probe_unchanged_corpus(&resolved, now, interval, mode))?;
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
            cancellation::checkpoint("source")?;
            let bit = match self.source_bits.bit_for_url(source.as_str()) {
                Some(b) => b,
                None => {
                    tracing::error!(
                        source = source.as_str(),
                        "source missing from bit map, skipping"
                    );
                    digest_valid = false;
                    source_coverage_complete = false;
                    continue;
                }
            };
            let bit_mask = 1u64 << bit;

            let max_entries = self
                .source_max_entries
                .get(source.as_str())
                .copied()
                .unwrap_or(self.max_entries);

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
                .and_then(|dir| selected_cache_body_path(dir, source))
                .unwrap_or_default();

            // A non-due source is still part of this generation: stream its
            // retained body without touching health or scheduling state.
            let mut source_due = matches!(mode, RefreshMode::Force)
                || (matches!(mode, RefreshMode::Scheduled)
                    && self.source_schedules.get(source).map_or_else(
                        || {
                            self.cache.get(url.as_str()).is_none_or(|cached| {
                                !is_cache_fresh(cached.fetched_at, now, interval)
                            })
                        },
                        |_| self.source_is_due(source, now),
                    ));

            // A non-due planned source can be disk-backed without an
            // in-memory metadata entry.  The retained-body resolver is the
            // authority for whether it can safely stay non-due.
            let use_retained = matches!(mode, RefreshMode::CacheOnly) || !source_due;
            if use_retained {
                if let Some(reader) = self.resolve_retained_body_reader(url, source) {
                    match cancellation::checked(parse_retained_source_into_spill_counted(
                        reader,
                        bit_mask,
                        &mut spill,
                        max_entries,
                        source,
                        declared_format,
                        // The body on disk is the one the last cycle
                        // counted; counting it again costs ~144 MiB to
                        // reproduce the same number (`mem2608-s1` T2).
                        UniqueCount::carry_or_measure(prev_status.as_deref(), max_entries),
                    ))? {
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
                            // Reaching this arm under compatibility scheduling means
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
                            let verified_fresh = self.source_schedules.is_empty()
                                && matches!(mode, RefreshMode::Scheduled);
                            pending.push(PendingStatus {
                                source: source.clone(),
                                bit,
                                counts,
                                prev_status: prev_status.clone(),
                                message: cache_hit_message(mode),
                                age_secs: self
                                    .cache
                                    .get(url.as_str())
                                    .map(|cached| (now - cached.fetched_at).whole_seconds()),
                                verified_fresh,
                            });
                            if verified_fresh {
                                if let Some((id, _)) = &blocklist_meta {
                                    self.record_blocklist_success(
                                        id,
                                        cache_path_for_record.clone(),
                                    );
                                }
                            }
                            // Sprint C T2 / D9: a cache that outlived a
                            // failure recovers the list from `Failed`.
                            // That reasoning holds only under compatibility scheduling,
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
                            continue;
                        }
                        Err(e) => {
                            source_due = true;
                            poison_refresh_on_spill_rollback(
                                &e,
                                source,
                                &mut spill_rollback_failed,
                            );
                            // Partial ingest already rolled back. Treat
                            // a broken cache read exactly like a failed
                            // refresh rather than silently shipping a
                            // truncated list. Outside CacheOnly this
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
                                    RefreshMode::Scheduled | RefreshMode::Force =>
                                        "failed to stream fresh cache body, falling back to HTTP",
                                }
                            );
                        }
                    }
                } else {
                    source_due = true;
                    tracing::warn!(
                        source = source.as_str(),
                        "retained list body missing or unusable"
                    );
                }
            }

            // CacheOnly stops here. Reaching `download_list` below would
            // undo the entire point of the mode, so the exit is explicit
            // rather than implied by the arms above — a source with no
            // selected body, or one whose body failed to stream, must
            // contribute nothing this cycle instead of quietly falling
            // back to the network the listener is waiting on.
            //
            // This source contributes no records here. A failed spill rollback
            // poisons the cycle and prevents installation.
            //
            if matches!(mode, RefreshMode::CacheOnly) {
                // A partial boot may install its usable sources, but must
                // force the first network cycle to establish full coverage.
                source_coverage_complete = false;
                digest_valid = false;
                tracing::warn!(
                    source = source.as_str(),
                    "no usable disk cache at boot; source contributes nothing this cycle"
                );
                continue;
            }

            if source_due {
                schedule_attempts.insert(source.clone());
            }

            match cancellation::checked(self.download_list(source, url).await)? {
                Ok(FetchResult::Fresh(candidate)) => {
                    // Measure the candidate before admitting it to the corpus.
                    let fresh_mark = spill.mark();
                    let (counts, body_hash) = match cancellation::checked(
                        parse_fresh_download_into_spill_counted(
                            &candidate,
                            bit_mask,
                            &mut spill,
                            max_entries,
                            source,
                            declared_format,
                            // The one arm whose count is actually consulted:
                            // `shrink_verdict` below trips on it. Measured,
                            // never carried — but sized from the prior count so
                            // the set does not pay a final rehash.
                            UniqueCount::measure(prev_status.as_deref(), max_entries),
                        ),
                    )? {
                        Ok(parsed) => parsed,
                        Err(e) => {
                            poison_refresh_on_spill_rollback(
                                &e,
                                source,
                                &mut spill_rollback_failed,
                            );
                            // Keep a refused candidate out and try the retained body.
                            tracing::error!(
                                source = source.as_str(),
                                error = %e,
                                "source candidate refused; attempting retained-body fallback"
                            );
                            let status =
                                status_from_spill_parse_error(prev_status.as_deref(), &e, now);
                            self.status_registry.update_for_url(source, status);
                            publish_list_stats_updated(&self.notification_tx, source);
                            // Re-parse the retained body under the same cap.
                            // An operator who LOWERED the cap can have a
                            // retained body that fails it too; then the
                            // source contributes nothing and the status
                            // stamped above already says why.
                            //
                            // A fallback may use only a previously accepted
                            // body, never the candidate just refused above.
                            let retained = self.resolve_retained_body_reader(url, source);
                            let mut retained_cache_path = None;
                            let mut retained_accepted = false;
                            match retained {
                                Some(reader) => {
                                    let cache_path =
                                        reader.retained_cache_path().map(Path::to_path_buf);
                                    match cancellation::checked(
                                        parse_retained_source_into_spill_counted(
                                            reader,
                                            bit_mask,
                                            &mut spill,
                                            max_entries,
                                            source,
                                            declared_format,
                                            // The retained body is the one the
                                            // prior count describes.
                                            UniqueCount::carry_or_measure(
                                                prev_status.as_deref(),
                                                max_entries,
                                            ),
                                        ),
                                    )? {
                                        Ok((c, retained_hash)) => {
                                            spilled += c.parsed_ok;
                                            retained_cache_path = cache_path;
                                            retained_accepted = true;
                                            // The usable input is the retained
                                            // body, not the rejected candidate.
                                            // Folding it lets this cycle truthfully
                                            // skip when it reproduces the live
                                            // corpus while its source row remains
                                            // Failed for the candidate attempt.
                                            fold_corpus_digest(
                                                &mut digest_ctx,
                                                source,
                                                bit_mask,
                                                max_entries,
                                                declared_format,
                                                &retained_hash,
                                            );
                                            tracing::info!(
                                                source = source.as_str(),
                                                "refused candidate; retained body accepted"
                                            );
                                        }
                                        Err(retained_err) => {
                                            poison_refresh_on_spill_rollback(
                                                &retained_err,
                                                source,
                                                &mut spill_rollback_failed,
                                            );
                                            tracing::warn!(
                                                source = source.as_str(),
                                                error = %retained_err,
                                                "refused candidate; retained-body fallback failed"
                                            );
                                        }
                                    }
                                }
                                None => tracing::warn!(
                                    source = source.as_str(),
                                    "refused candidate; retained-body fallback unavailable"
                                ),
                            }
                            if !retained_accepted {
                                source_coverage_complete = false;
                            }
                            if let Some((id, max_consec)) = &blocklist_meta {
                                let flipped = self.record_blocklist_failure_for_source(
                                    id,
                                    *max_consec,
                                    retained_cache_path,
                                );
                                if flipped {
                                    tracing::warn!(
                                        target: "audit",
                                        source = source.as_str(),
                                        blocklist_id = %id.as_str(),
                                        max_consecutive_failures = *max_consec,
                                        "blocklist transitioned to Failed after cap refusal"
                                    );
                                }
                            }
                            continue;
                        }
                    };
                    let fresh_unique = counts.unique_domains;

                    match self.shrink_verdict(prev_status.as_deref(), fresh_unique, max_entries) {
                        ShrinkVerdict::Refuse {
                            drop_pct,
                            got,
                            kept,
                        } => {
                            // Retention guard rejected the candidate; this
                            // failure path attempts the retained body.
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
                            let mut retained_accepted = false;
                            let retained_cache_path = match spill
                                .rollback(&fresh_mark, SpillRollbackSite::FreshRetentionGuard)
                            {
                                Ok(()) => {
                                    // Use the last accepted body, never the refused bridge file.
                                    let retained = self.resolve_retained_body_reader(url, source);
                                    match retained {
                                        Some(reader) => {
                                            let cache_path =
                                                reader.retained_cache_path().map(Path::to_path_buf);
                                            match cancellation::checked(
                                                parse_retained_source_into_spill_counted(
                                                    reader,
                                                    bit_mask,
                                                    &mut spill,
                                                    max_entries,
                                                    source,
                                                    declared_format,
                                                    UniqueCount::carry_or_measure(
                                                        prev_status.as_deref(),
                                                        max_entries,
                                                    ),
                                                ),
                                            )? {
                                                Ok((c, retained_hash)) => {
                                                    spilled += c.parsed_ok;
                                                    retained_accepted = true;
                                                    fold_corpus_digest(
                                                        &mut digest_ctx,
                                                        source,
                                                        bit_mask,
                                                        max_entries,
                                                        declared_format,
                                                        &retained_hash,
                                                    );
                                                    cache_path
                                                }
                                                Err(e) => {
                                                    poison_refresh_on_spill_rollback(
                                                        &e,
                                                        source,
                                                        &mut spill_rollback_failed,
                                                    );
                                                    tracing::warn!(
                                                        source = source.as_str(),
                                                        error = %e,
                                                        "retained-body fallback failed after guard trip"
                                                    );
                                                    digest_valid = false;
                                                    None
                                                }
                                            }
                                        }
                                        None => {
                                            digest_valid = false;
                                            None
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::error!(
                                        source = source.as_str(),
                                        error = %e,
                                        "failed to remove refused candidate from shard spill; keeping current domain map"
                                    );
                                    spill_rollback_failed = true;
                                    digest_valid = false;
                                    None
                                }
                            };
                            if !retained_accepted {
                                source_coverage_complete = false;
                            }
                            let status =
                                ListStatus::from_failure(prev_status.as_deref(), reason, now);
                            self.status_registry.update_for_url(source, status);
                            publish_list_stats_updated(&self.notification_tx, source);
                            if let Some((id, max_consec)) = &blocklist_meta {
                                let flipped = self.record_blocklist_failure_for_source(
                                    id,
                                    *max_consec,
                                    retained_cache_path,
                                );
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
                            let (staged_body, resident_body) = match cancellation::checked(
                                candidate
                                    .body
                                    .into_cache_admission(self.cache_dir.as_deref(), source),
                            )? {
                                Ok(parts) => parts,
                                Err(error) => {
                                    tracing::warn!(source, %error, "failed to persist list cache generation; restoring retained body");
                                    if let Err(rollback) = spill.rollback(
                                        &fresh_mark,
                                        SpillRollbackSite::FreshCacheAdmission,
                                    ) {
                                        tracing::error!(source, %rollback, "failed to remove uncommitted candidate from shard spill");
                                        spill_rollback_failed = true;
                                    }
                                    let mut retained_path = None;
                                    let mut retained_accepted = false;
                                    if let Some(reader) =
                                        self.resolve_retained_body_reader(url, source)
                                    {
                                        retained_path =
                                            reader.retained_cache_path().map(Path::to_path_buf);
                                        match cancellation::checked(
                                            parse_retained_source_into_spill_counted(
                                                reader,
                                                bit_mask,
                                                &mut spill,
                                                max_entries,
                                                source,
                                                declared_format,
                                                UniqueCount::carry_or_measure(
                                                    prev_status.as_deref(),
                                                    max_entries,
                                                ),
                                            ),
                                        )? {
                                            Ok((counts, retained_hash)) => {
                                                spilled += counts.parsed_ok;
                                                retained_accepted = true;
                                                fold_corpus_digest(
                                                    &mut digest_ctx,
                                                    source,
                                                    bit_mask,
                                                    max_entries,
                                                    declared_format,
                                                    &retained_hash,
                                                );
                                            }
                                            Err(retained_error) => {
                                                poison_refresh_on_spill_rollback(
                                                    &retained_error,
                                                    source,
                                                    &mut spill_rollback_failed,
                                                );
                                                retained_path = None;
                                            }
                                        }
                                    }
                                    if !retained_accepted {
                                        source_coverage_complete = false;
                                    }
                                    let status = ListStatus::from_failure(
                                        prev_status.as_deref(),
                                        "failed to persist downloaded cache generation".to_string(),
                                        now,
                                    );
                                    self.status_registry.update_for_url(source, status);
                                    publish_list_stats_updated(&self.notification_tx, source);
                                    if let Some((id, max_consec)) = &blocklist_meta {
                                        self.record_blocklist_failure_for_source(
                                            id,
                                            *max_consec,
                                            retained_path,
                                        );
                                    }
                                    continue;
                                }
                            };
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
                                message: "list downloaded and parsed",
                                age_secs: None,
                                // Reachable only outside CacheOnly (`CacheOnly`
                                // never calls `download_list`) — a genuine
                                // download completed this cycle.
                                verified_fresh: true,
                            });
                            pending_cache_admissions.push(PendingCacheAdmission {
                                source: source.clone(),
                                url: url.clone(),
                                etag: candidate.etag,
                                last_modified: candidate.last_modified,
                                staged: staged_body,
                                body: resident_body,
                                previous_cache_path: cache_path_for_record.clone(),
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
                }
                Ok(FetchResult::NotModified) => {
                    let mut accepted_cached_body = false;
                    let mut cap_refusal = None;
                    if let Some(reader) = self.resolve_retained_body_reader(url, source) {
                        match cancellation::checked(parse_retained_source_into_spill_counted(
                            reader,
                            bit_mask,
                            &mut spill,
                            max_entries,
                            source,
                            declared_format,
                            // 304 is the server saying the bytes are the
                            // ones we already counted.
                            UniqueCount::carry_or_measure(prev_status.as_deref(), max_entries),
                        ))? {
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
                                pending_cache_revalidations.push(PendingCacheRevalidation {
                                    status: PendingStatus {
                                        source: source.clone(),
                                        bit,
                                        counts,
                                        prev_status: prev_status.clone(),
                                        message: "list not modified, using cache",
                                        age_secs: None,
                                        verified_fresh: true,
                                    },
                                    url: url.clone(),
                                    cache_path: cache_path_for_record.clone(),
                                });
                                accepted_cached_body = true;
                            }
                            Err(e) => {
                                cap_refusal = e.cap_refusal();
                                poison_refresh_on_spill_rollback(
                                    &e,
                                    source,
                                    &mut spill_rollback_failed,
                                );
                                tracing::warn!(
                                    source = source.as_str(),
                                    error = %e,
                                    "failed to stream cache body on 304"
                                );
                            }
                        }
                    }
                    if !accepted_cached_body {
                        // A conditional 304 is useful only if the exact
                        // retained representation can be admitted.  Retry
                        // once without validators; a malformed retry 304 is
                        // rejected in `download_list` and cannot loop.
                        if let Ok(FetchResult::Fresh(candidate)) = cancellation::checked(
                            self.download_list_with_mode(source, url, RequestMode::Unconditional)
                                .await,
                        )? {
                            let retry_mark = spill.mark();
                            match cancellation::checked(parse_fresh_download_into_spill_counted(
                                &candidate,
                                bit_mask,
                                &mut spill,
                                max_entries,
                                source,
                                declared_format,
                                UniqueCount::measure(prev_status.as_deref(), max_entries),
                            ))? {
                                Ok((counts, body_hash)) => match self.shrink_verdict(
                                    prev_status.as_deref(),
                                    counts.unique_domains,
                                    max_entries,
                                ) {
                                    ShrinkVerdict::Accept { delta_warn } => {
                                        let cache_parts = match cancellation::checked(
                                            candidate.body.into_cache_admission(
                                                self.cache_dir.as_deref(),
                                                source,
                                            ),
                                        )? {
                                            Ok(parts) => Some(parts),
                                            Err(error) => {
                                                tracing::warn!(source, %error, "failed to persist unconditional retry; restoring retained body");
                                                None
                                            }
                                        };
                                        if let Some((staged_body, resident_body)) = cache_parts {
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
                                                message: "list downloaded after unusable 304 cache",
                                                age_secs: None,
                                                verified_fresh: true,
                                            });
                                            pending_cache_admissions.push(PendingCacheAdmission {
                                                source: source.clone(),
                                                url: url.clone(),
                                                etag: candidate.etag,
                                                last_modified: candidate.last_modified,
                                                staged: staged_body,
                                                body: resident_body,
                                                previous_cache_path: cache_path_for_record.clone(),
                                            });
                                            if let Some(delta) = delta_warn {
                                                tracing::warn!(target: "audit", source = source.as_str(), bit, delta_pct = delta, "{}", BLOCKLIST_DELTA_WARN);
                                            }
                                            continue;
                                        }
                                        if let Err(error) = spill.rollback(
                                            &retry_mark,
                                            SpillRollbackSite::RetryCacheAdmission,
                                        ) {
                                            tracing::error!(source, %error, "failed to roll back retry candidate after persistence failure");
                                            spill_rollback_failed = true;
                                        }
                                        let mut retained_path = None;
                                        let mut retained_accepted = false;
                                        if let Some(reader) =
                                            self.resolve_retained_body_reader(url, source)
                                        {
                                            retained_path =
                                                reader.retained_cache_path().map(Path::to_path_buf);
                                            match cancellation::checked(
                                                parse_retained_source_into_spill_counted(
                                                    reader,
                                                    bit_mask,
                                                    &mut spill,
                                                    max_entries,
                                                    source,
                                                    declared_format,
                                                    UniqueCount::carry_or_measure(
                                                        prev_status.as_deref(),
                                                        max_entries,
                                                    ),
                                                ),
                                            )? {
                                                Ok((counts, hash)) => {
                                                    retained_accepted = true;
                                                    spilled += counts.parsed_ok;
                                                    fold_corpus_digest(
                                                        &mut digest_ctx,
                                                        source,
                                                        bit_mask,
                                                        max_entries,
                                                        declared_format,
                                                        &hash,
                                                    );
                                                }
                                                Err(error) => {
                                                    retained_path = None;
                                                    poison_refresh_on_spill_rollback(
                                                        &error,
                                                        source,
                                                        &mut spill_rollback_failed,
                                                    );
                                                }
                                            }
                                        }
                                        if !retained_accepted {
                                            source_coverage_complete = false;
                                        }
                                        let status = ListStatus::from_failure(
                                            prev_status.as_deref(),
                                            "failed to persist downloaded cache generation"
                                                .to_string(),
                                            now,
                                        );
                                        self.status_registry.update_for_url(source, status);
                                        publish_list_stats_updated(&self.notification_tx, source);
                                        if let Some((id, max_consec)) = &blocklist_meta {
                                            self.record_blocklist_failure_for_source(
                                                id,
                                                *max_consec,
                                                retained_path,
                                            );
                                        }
                                        continue;
                                    }
                                    ShrinkVerdict::Refuse {
                                        drop_pct,
                                        got,
                                        kept,
                                    } => {
                                        if let Err(error) = spill.rollback(
                                            &retry_mark,
                                            SpillRollbackSite::RetryRetentionGuard,
                                        ) {
                                            tracing::error!(source, %error, "failed to roll back refused retry candidate");
                                            spill_rollback_failed = true;
                                        }
                                        let reason =
                                            format_blocklist_shrink_refused(drop_pct, got, kept);
                                        tracing::warn!(target: "audit", source = source.as_str(), bit, got, kept, drop_pct, "{}", reason);
                                        let mut retained_path = None;
                                        let mut retained_accepted = false;
                                        if let Some(reader) =
                                            self.resolve_retained_body_reader(url, source)
                                        {
                                            retained_path =
                                                reader.retained_cache_path().map(Path::to_path_buf);
                                            match cancellation::checked(
                                                parse_retained_source_into_spill_counted(
                                                    reader,
                                                    bit_mask,
                                                    &mut spill,
                                                    max_entries,
                                                    source,
                                                    declared_format,
                                                    UniqueCount::carry_or_measure(
                                                        prev_status.as_deref(),
                                                        max_entries,
                                                    ),
                                                ),
                                            )? {
                                                Ok((counts, hash)) => {
                                                    retained_accepted = true;
                                                    spilled += counts.parsed_ok;
                                                    fold_corpus_digest(
                                                        &mut digest_ctx,
                                                        source,
                                                        bit_mask,
                                                        max_entries,
                                                        declared_format,
                                                        &hash,
                                                    );
                                                }
                                                Err(error) => {
                                                    retained_path = None;
                                                    poison_refresh_on_spill_rollback(
                                                        &error,
                                                        source,
                                                        &mut spill_rollback_failed,
                                                    );
                                                }
                                            }
                                        }
                                        if !retained_accepted {
                                            source_coverage_complete = false;
                                        }
                                        let status = ListStatus::from_failure(
                                            prev_status.as_deref(),
                                            reason,
                                            now,
                                        );
                                        self.status_registry.update_for_url(source, status);
                                        publish_list_stats_updated(&self.notification_tx, source);
                                        if let Some((id, max_consec)) = &blocklist_meta {
                                            self.record_blocklist_failure_for_source(
                                                id,
                                                *max_consec,
                                                retained_path,
                                            );
                                        }
                                        continue;
                                    }
                                },
                                Err(error) => {
                                    cap_refusal = error.cap_refusal();
                                    poison_refresh_on_spill_rollback(
                                        &error,
                                        source,
                                        &mut spill_rollback_failed,
                                    );
                                }
                            }
                        }
                        let status = match cap_refusal {
                            Some(cap) => ListStatus::from_cap_refusal(
                                prev_status.as_deref(),
                                cap.max_entries,
                                cap.dropped,
                                now,
                            ),
                            None => ListStatus::from_failure(
                                prev_status.as_deref(),
                                "received 304 but the matching cached body was unusable"
                                    .to_string(),
                                now,
                            ),
                        };
                        self.status_registry.update_for_url(source, status);
                        publish_list_stats_updated(&self.notification_tx, source);
                        if let Some((id, max_consec)) = &blocklist_meta {
                            self.record_blocklist_failure(id, *max_consec);
                        }
                        source_coverage_complete = false;
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
                    let mut retained_cap_refusal = None;
                    let mut retained_cache_path = None;
                    let mut retained_accepted = false;
                    if let Some(reader) = self.resolve_retained_body_reader(url, source) {
                        let cache_path = reader.retained_cache_path().map(Path::to_path_buf);
                        match cancellation::checked(parse_retained_source_into_spill_counted(
                            reader,
                            bit_mask,
                            &mut spill,
                            max_entries,
                            source,
                            declared_format,
                            // The download failed; this is the cached body
                            // from the cycle that produced the prior count.
                            UniqueCount::carry_or_measure(prev_status.as_deref(), max_entries),
                        ))? {
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
                                retained_cache_path = cache_path;
                                retained_accepted = true;
                                tracing::warn!(
                                    source = source.as_str(),
                                    error = %e,
                                    "download failed; fallback body accepted"
                                );
                            }
                            Err(stream_err) => {
                                retained_cap_refusal = stream_err.cap_refusal();
                                poison_refresh_on_spill_rollback(
                                    &stream_err,
                                    source,
                                    &mut spill_rollback_failed,
                                );
                                tracing::warn!(
                                    source = source.as_str(),
                                    error = %stream_err,
                                    "download failed; retained-body fallback failed"
                                );
                                digest_valid = false;
                            }
                        }
                    } else {
                        tracing::error!(
                            source = source.as_str(),
                            error = %e,
                            "download failed; retained-body fallback unavailable"
                        );
                        digest_valid = false;
                    }
                    if !retained_accepted {
                        source_coverage_complete = false;
                    }
                    let status = match retained_cap_refusal {
                        Some(cap) => ListStatus::from_cap_refusal(
                            prev_status.as_deref(),
                            cap.max_entries,
                            cap.dropped,
                            now,
                        ),
                        None => ListStatus::from_failure(prev_status.as_deref(), reason, now),
                    };
                    self.status_registry.update_for_url(source, status);
                    publish_list_stats_updated(&self.notification_tx, source);
                    // Sprint C T2: drive the state machine — increment
                    // `consecutive_failures`, flip to Failed at the
                    // per-list `max_consecutive_failures` threshold.
                    if let Some((id, max_consec)) = &blocklist_meta {
                        let flipped = self.record_blocklist_failure_for_source(
                            id,
                            *max_consec,
                            retained_cache_path,
                        );
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

        cancellation::checkpoint("parsed")?;

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
        let source_coverage_incomplete = !source_coverage_complete;
        // An incomplete first load installs whichever sources were usable:
        // retaining zero domains would make the node more unfiltered. Once a
        // corpus is live, preserve it whole instead of publishing a subset.
        let keep_live_for_incomplete_coverage =
            source_coverage_incomplete && self.filter.domain_count() > 0;
        if source_coverage_incomplete {
            digest_valid = false;
        }

        let mut added_by_bit = [0u64; 64];
        let mut total = 0usize;
        let mut degraded = false;
        let mut published_shards = 0usize;
        // Did a complete new generation actually reach the engine this cycle?
        // The T5 digest is stored only when this is true — see below.
        let mut installed = false;
        // Set when the global corpus guard refused this cycle. Carries the
        // measured union, the operator's ceiling, and the per-source novel
        // contributions that tell them which list to drop.
        let mut corpus_refused: Option<(u64, usize, Box<[u64; 64]>)> = None;

        // The digest includes accepted empty bodies, so a repeated empty
        // corpus skips the same rebuild as a populated one.
        let corpus_digest: Option<[u8; 32]> =
            digest_valid.then(|| <sha2::Sha256 as sha2::Digest>::finalize(digest_ctx).into());
        let unchanged = !spill.is_poisoned()
            && corpus_digest.is_some()
            && corpus_digest == self.installed_corpus_digest;
        // A fully validated empty corpus replaces any prior generation.
        let complete_empty_install = spilled == 0
            && source_coverage_complete
            && !spill_rollback_failed
            && !spill.is_poisoned();

        // The spill has to be flushed before *either* the counting pass or
        // pass 2 can read it back, so it is done once here rather than as
        // an arm of the chain below — the guard needs to sit between the
        // flush and the first `build_shard`, and an `if`-chain cannot bind
        // a value in one arm and match on it in the next.
        let preparing = !spill.is_poisoned()
            && !spill_rollback_failed
            && !keep_live_for_incomplete_coverage
            && spilled > 0;
        let rebuilding = preparing && !unchanged;
        let flush_err = preparing.then(|| spill.flush().err()).flatten();
        let flush_failed = flush_err.is_some();
        let prepare_err = (preparing && flush_err.is_none())
            .then(|| spill.prepare_validate().err())
            .flatten();
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
        let corpus_guard = if rebuilding && flush_err.is_none() && prepare_err.is_none() {
            // What is installed right now, which at a cold start is 0 and
            // is the guard's boot-versus-reload discriminator.
            cancellation::checked(self.corpus_guard(&mut spill, self.filter.domain_count()))?
        } else {
            Ok(CorpusVerdict::Unmeasured)
        };
        // A count/read/rewind error poisons the spill. This has to be read
        // after the guard so cache admission and digest reuse reject it too.
        cancellation::checkpoint("validated")?;
        let spill_poisoned = spill.is_poisoned();

        if spill_rollback_failed {
            total = self.filter.domain_count();
            tracing::error!(
                total,
                "retained current domain map after a shard spill rollback failure"
            );
        } else if let Some(e) = flush_err {
            tracing::error!(error = %e, "failed to flush shard spill, keeping current domain map");
            // Nothing was installed; report what is still live.
            total = self.filter.domain_count();
        } else if let Some(e) = prepare_err {
            tracing::error!(error = %e, "failed to validate shard spill, keeping current domain map");
            total = self.filter.domain_count();
        } else if let Err(e) = &corpus_guard {
            total = self.filter.domain_count();
            tracing::error!(
                error = %e,
                total,
                "failed to measure merged corpus from shard spill; rejecting candidate before publication"
            );
        } else if spill_poisoned {
            total = self.filter.domain_count();
            tracing::error!(
                total,
                "retained current domain map after a shard spill storage failure"
            );
        } else if unchanged {
            total = self.filter.domain_count();
            tracing::info!(
                total,
                "no list body changed since the installed generation, skipping rebuild"
            );
        } else if keep_live_for_incomplete_coverage {
            total = self.filter.domain_count();
            tracing::warn!(
                total,
                "source coverage incomplete; kept the complete previous domain map"
            );
        } else if spilled == 0 {
            if complete_empty_install {
                let policy = ListPolicy::publish(self.policy_masks.clone());
                for idx in 0..DOMAIN_SHARDS {
                    let shard = SortedShard::from_sorted_entries(Vec::new(), policy.clone())
                        .expect("an empty shard is sorted");
                    cancellation::begin_commit()?;
                    self.filter.swap_shard_sorted(idx, shard);
                    cancellation::checkpoint("after_swap")?;
                }
                installed = true;
                self.status_registry.note_installed_cycle();
                tracing::debug!("installed complete empty domain map");
            } else {
                total = self.filter.domain_count();
                tracing::debug!("no domains loaded, keeping current domain map");
            }
        } else if let Ok(CorpusVerdict::Refuse {
            unique,
            ceiling,
            novel_by_bit,
        }) = corpus_guard
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
            let corpus_verdict =
                corpus_guard.expect("guard errors are handled before shard publication");
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
                // Deliberately a WARN and not an ERROR: filtering remains
                // available, unlike the unfiltered state reported above.
                tracing::warn!(
                    target: "audit",
                    unique = *unique,
                    ceiling = *ceiling,
                    "merged corpus EXCEEDS max_total_domains but nothing was installed to fall \
                     back on, so it is being installed anyway rather than starting up unfiltered. \
                     max_total_domains is an entry-count ceiling, not a process-memory budget. \
                     Raise it to the corpus you actually want, or drop a list"
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
                let built = match cancellation::checked(spill.build_shard(idx, capacity, &policy))?
                {
                    Ok(built) => Some(built),
                    Err(first_error) => {
                        tracing::warn!(
                            shard = idx,
                            error = %first_error,
                            "failed to build domain shard from spill; retrying once"
                        );
                        match cancellation::checked(
                            spill
                                .rewind_shard(idx)
                                .and_then(|()| spill.build_shard(idx, capacity, &policy)),
                        )? {
                            Ok(built) => Some(built),
                            Err(retry_error) => {
                                tracing::error!(
                                    shard = idx,
                                    first_error = %first_error,
                                    error = %retry_error,
                                    "failed to build domain shard from spill after retry, keeping its previous generation"
                                );
                                degraded = true;
                                None
                            }
                        }
                    }
                };
                if let Some(built) = built {
                    let len = built.shard.len();
                    cancellation::begin_commit()?;
                    self.filter.swap_shard_sorted(idx, built.shard);
                    cancellation::checkpoint("after_swap")?;
                    for (aggregate, added) in added_by_bit.iter_mut().zip(built.added_by_bit) {
                        *aggregate += added;
                    }
                    spill.release_after_swap(idx);
                    total += len;
                    published_shards += 1;
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

        cancellation::begin_commit()?;

        for revalidation in pending_cache_revalidations {
            let PendingCacheRevalidation {
                status,
                url,
                cache_path,
            } = revalidation;
            let source = &status.source;
            let blocklist_meta = self.source_to_blocklist.get(source.as_str());
            let mut metadata_committed = true;
            if let Some(ref dir) = self.cache_dir {
                if let Some(entry) = self.cache.get(url.as_str()) {
                    let stem = source_to_cache_stem(source);
                    let meta_path = dir.join(format!("{stem}.meta"));
                    let parsed = load_meta_file(&meta_path);
                    if let Some(body_path) = selected_body_path(dir, &stem, &parsed) {
                        let body_size = std::fs::metadata(&body_path)
                            .ok()
                            .and_then(|m| usize::try_from(m.len()).ok());
                        if let Some(body_size) = body_size {
                            if let Err(e) = write_meta_file(
                                &meta_path,
                                entry.etag.as_deref(),
                                entry.last_modified.as_deref(),
                                &url,
                                now,
                                Some(body_size),
                                manifest_from_meta(&stem, &parsed),
                            ) {
                                tracing::warn!(source, error = %e, "failed to update list cache metadata");
                                metadata_committed = false;
                            }
                        } else {
                            metadata_committed = false;
                        }
                    } else {
                        metadata_committed = false;
                    }
                } else {
                    metadata_committed = false;
                }
            }
            if metadata_committed {
                schedule_successes.insert(source.clone());
                self.legacy_cache_timestamp_urls.remove(&url);
                if let Some(entry) = self.cache.get_mut(url.as_str()) {
                    entry.fetched_at = now;
                }
                if let Some((id, _)) = blocklist_meta {
                    self.record_blocklist_success(id, cache_path);
                }
                pending.push(status);
            } else {
                // Keep the validated body, but never claim success for stale metadata.
                let failure = ListStatus::from_failure(
                    status.prev_status.as_deref(),
                    "validated cache body but failed to update cache metadata".to_string(),
                    now,
                );
                self.status_registry.update_for_url(source, failure);
                publish_list_stats_updated(&self.notification_tx, source);
                if let Some((id, max_consec)) = blocklist_meta {
                    self.record_blocklist_failure(id, *max_consec);
                }
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
        self.installed_corpus_digest = if installed && !source_coverage_incomplete {
            corpus_digest
        } else if unchanged && !spill_poisoned {
            // Nothing was rebuilt because nothing needed to be; the digest
            // already describes the live generation.
            self.installed_corpus_digest
        } else {
            None
        };

        let cache_admission_sources: HashSet<String> = pending_cache_admissions
            .iter()
            .map(|admission| admission.source.clone())
            .collect();
        let mut cache_admission_committed = HashSet::new();
        if !spill_poisoned && ((installed && !source_coverage_incomplete) || unchanged) {
            let transaction = match self.cache_dir.as_deref() {
                Some(dir)
                    if pending_cache_admissions
                        .iter()
                        .any(|admission| admission.staged.is_some()) =>
                {
                    commit_cache_admissions_transaction(dir, &pending_cache_admissions, now)
                }
                _ => CorpusManifestCommit::Durable,
            };
            let committed_body_gc: Vec<(String, String)> =
                if transaction == CorpusManifestCommit::Durable {
                    pending_cache_admissions
                        .iter()
                        .filter_map(|admission| {
                            admission
                                .staged
                                .as_ref()
                                .map(|staged| (admission.source.clone(), staged.basename.clone()))
                        })
                        .collect()
                } else {
                    Vec::new()
                };
            for admission in pending_cache_admissions {
                let PendingCacheAdmission {
                    source,
                    url,
                    etag,
                    last_modified,
                    staged,
                    body,
                    previous_cache_path,
                } = admission;
                let in_memory = staged.is_none();
                if transaction == CorpusManifestCommit::Durable {
                    let cache_path = staged.as_ref().map_or_else(
                        || previous_cache_path.clone(),
                        |staged| staged.body_path.clone(),
                    );
                    if !is_imported_local_url(&url) || in_memory {
                        let entry = self.cache.entry(url.clone()).or_default();
                        if !is_imported_local_url(&url) {
                            entry.etag = etag;
                            entry.last_modified = last_modified;
                        }
                        entry.fetched_at = now;
                        if in_memory {
                            entry.body = body;
                        }
                    }
                    if let Some((id, _)) = self.source_to_blocklist.get(source.as_str()) {
                        self.record_blocklist_success(id, cache_path);
                    }
                    schedule_successes.insert(source.clone());
                    self.legacy_cache_timestamp_urls.remove(&url);
                    cache_admission_committed.insert(source);
                } else {
                    tracing::warn!(
                        source,
                        "accepted list corpus cache transaction did not commit"
                    );
                    let previous = self.status_registry.status_for_url(&source);
                    let status = ListStatus::from_failure(
                        previous.as_deref(),
                        "installed list corpus but failed to commit cache metadata".to_string(),
                        now,
                    );
                    self.status_registry.update_for_url(&source, status);
                    publish_list_stats_updated(&self.notification_tx, &source);
                    if let Some((id, max_consec)) = self.source_to_blocklist.get(source.as_str()) {
                        self.record_blocklist_failure_for_source(
                            id,
                            *max_consec,
                            previous_cache_path.is_file().then_some(previous_cache_path),
                        );
                    }
                }
            }
            // The journal deletion above is the only corpus commit point.
            // Do not reclaim an old selected body before it is durable.
            if transaction == CorpusManifestCommit::Durable {
                if let Some(dir) = self.cache_dir.as_deref() {
                    for (source, selected) in committed_body_gc {
                        let stem = source_to_cache_stem(&source);
                        remove_legacy_body(dir, &stem);
                        garbage_collect_generation_bodies(dir, &stem, &selected);
                    }
                }
            }
        }

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
            let added = if !installed {
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
            let cache_admission_ready = !cache_admission_sources.contains(&p.source)
                || cache_admission_committed.contains(&p.source);
            if p.verified_fresh
                && !spill_poisoned
                && (installed || unchanged)
                && cache_admission_ready
            {
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

        if installed {
            // A completed install can move overlap ownership without changing fetch health.
            for (source, _) in &resolved {
                let entries = self
                    .source_bits
                    .bit_for_url(source)
                    .and_then(|bit| added_by_bit.get(usize::from(bit)).copied())
                    .unwrap_or(0);
                if let Some(previous) = self.status_registry.status_for_url(source) {
                    let mut reconciled = (*previous).clone();
                    reconciled.entries = entries;
                    self.status_registry.update_for_url(source, reconciled);
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

        // Preserve the closed wire enum: every path that failed to complete
        // an install maps conservatively to the pre-existing rollback value.
        // Current readers use `generation_degraded` to distinguish that from
        // an actual spill rollback. A cold partial build is still Installed.
        let generation_degraded = !corpus_was_refused
            && (spill_rollback_failed
                || spill_poisoned
                || keep_live_for_incomplete_coverage
                || (spilled == 0 && !complete_empty_install)
                || flush_failed
                || degraded);
        let cycle_outcome = if corpus_was_refused {
            CycleOutcome::Refused
        } else if generation_degraded {
            CycleOutcome::SpillRollbackFailed
        } else if unchanged {
            CycleOutcome::SkippedUnchanged
        } else {
            CycleOutcome::Installed
        };
        let served_state = if installed {
            if complete_empty_install {
                ServedState::IntentionalEmpty
            } else if source_coverage_incomplete {
                ServedState::Partial
            } else {
                ServedState::Complete
            }
        } else if degraded && published_shards > 0 {
            ServedState::Partial
        } else {
            self.status_registry.cycle().served_state
        };
        // This is deliberately after all status rows, refusal payload, and
        // freeze mutations. `record_cycle_with_qualifiers` publishes one
        // immutable completed snapshot for IPC/API readers.
        let snapshot = self
            .status_registry
            .record_cycle_with_qualifiers_and_served_state(
                cycle_outcome,
                source_coverage_incomplete,
                generation_degraded,
                total,
                Some(served_state),
            );

        // Never resumed, so never left behind.
        drop(spill);
        drop(spill_cleanup);

        // Free any in-memory body strings that may remain (disk cache is
        // the authoritative copy). This keeps steady-state RSS proportional
        // to the domain map, not to the sum of all raw list texts.
        if self.cache_dir.is_some() {
            for entry in self.cache.values_mut() {
                entry.body = None;
            }
        }

        // The served state distinguishes an accepted empty generation from
        // an unavailable source set. The latch never closes.
        if let Some(gate) = &self.filter_ready {
            if served_state.is_ready_for_bind() {
                gate.open();
            }
        }

        if !matches!(mode, RefreshMode::CacheOnly) {
            self.record_schedule_attempts(&schedule_attempts, &schedule_successes, now);
        }

        Ok(RefreshCompletion {
            domain_count: total,
            snapshot,
        })
    }

    /// Resolve only a body that was accepted by an earlier cycle: the
    /// in-memory retained copy or the validated manifest-selected body. Failure paths
    /// must use this, never the live `imported.local` bridge: the bridge may
    /// be the candidate that this very cycle rejected for trust, body size,
    /// or a retention guard.
    fn resolve_retained_body_reader(&self, url: &str, source: &str) -> Option<BodyReader> {
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
        // Slow path: stream the manifest-selected disk body.
        self.open_body_from_disk(source)
    }

    /// Open a source's manifest-selected body for streaming, after the
    /// §4.7 Phase 2 T3 size check.
    ///
    /// Generation manifests require an exact `size=` match; legacy sidecars
    /// retain the existing 1 % compatibility predicate. It is a supply-chain
    /// check on external list bodies, so streaming does not get to drop it.
    ///
    /// Two deliberate differences from the `read_to_string` version it
    /// replaces. The size now comes from `File::metadata().len()` — for a
    /// successful `read_to_string` that is exactly `body.len()`, so the
    /// predicate sees the same number. And it is taken from the **open
    /// handle**, not by re-`stat`ing the path, which closes a
    /// re-resolution window between check and read that the old code did
    /// not have. The check still runs *before* any byte is parsed, so the
    /// fail-closed property is preserved.
    fn open_body_from_disk(&self, source: &str) -> Option<BodyReader> {
        let cache_dir = self.cache_dir.as_ref()?;
        let stem = source_to_cache_stem(source);
        let meta_path = cache_dir.join(format!("{stem}.meta"));
        let parsed = load_meta_file(&meta_path);
        let cache_path = match selected_body_path(cache_dir, &stem, &parsed) {
            Some(path) => path,
            None => {
                tracing::warn!(source, path = %meta_path.display(), "invalid cache manifest");
                return None;
            }
        };
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

        let fetch_url = self.fetch_urls.get(source)?;
        if !cache_identity_matches(source, fetch_url, &parsed) {
            tracing::warn!(
                source,
                path = %cache_path.display(),
                "cached body belongs to a different resolved URL, will re-download"
            );
            return None;
        }
        if !validate_selected_body_size(&stem, &parsed, actual) {
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

        let expected_sha256 = manifest_from_meta(&stem, &parsed).and_then(|manifest| {
            let mut digest = [0u8; 32];
            hex::decode_to_slice(manifest.sha256, &mut digest).ok()?;
            Some(digest)
        });
        tracing::debug!(source, path = %cache_path.display(), "streaming list body from disk");
        Some(BodyReader::RetainedCache {
            reader: std::io::BufReader::with_capacity(SPILL_WRITE_BUF, file),
            path: cache_path,
            expected_sha256,
        })
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
    /// Disk-backed HTTP bodies stream into an unselected generation; the
    /// explicit no-cache-dir path retains its bounded resident body.
    ///
    /// `source` is the catalog id / raw URL the caller used to pick this
    /// download; it keys into `source_tokens` to attach an
    /// `Authorization: Bearer <value>` header when the blocklist declared
    /// an `auth_token_ref` in the v1 config (Sprint 32 N9).
    /// A successful download returns an uncommitted candidate. Its validators
    /// describe the body only after parsing and retention checks accept it.
    async fn download_list(&mut self, source: &str, url: &str) -> Result<FetchResult, ListError> {
        self.download_list_with_mode(source, url, RequestMode::Conditional)
            .await
    }

    async fn download_list_with_mode(
        &mut self,
        source: &str,
        url: &str,
        request_mode: RequestMode,
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
                    // Do not create a compatibility freshness entry here:
                    // canonical deadlines decide when local input is acquired.
                    // Between deadlines, the cycle parses the committed
                    // retained body, so an edit cannot bypass the retention
                    // guard or silently alter a non-due generation.
                    return Ok(FetchResult::Fresh(Box::new(FreshDownload {
                        body: FreshBody::Resident(body),
                        etag: None,
                        last_modified: None,
                    })));
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

        let mut sent_conditional_validator = false;
        if matches!(request_mode, RequestMode::Conditional) {
            if let Some(cache) = self.cache.get(url) {
                if let Some(etag) = &cache.etag {
                    req = req.header("If-None-Match", etag);
                    sent_conditional_validator = true;
                }
                if cache.etag.is_none() {
                    if let Some(lm) = &cache.last_modified {
                        req = req.header("If-Modified-Since", lm);
                        sent_conditional_validator = true;
                    }
                }
            }
        }

        let resp = cancellation::wait(req.send(), "http_send")
            .await?
            .map_err(|e| ListError::Download {
                url: super::http_client::redact_userinfo(url),
                reason: super::http_client::redact_userinfo(&classify_fetch_error(&e)),
            })?;
        cancellation::checkpoint("http_headers")?;

        if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
            if !not_modified_is_admissible(sent_conditional_validator) {
                // A server may emit a broken unconditional 304. It cannot
                // validate any body, and must not create a cache record that
                // later makes an unrelated on-disk body look admitted.
                return Err(ListError::Download {
                    url: super::http_client::redact_userinfo(url),
                    reason: "HTTP 304 without a conditional cache validator".to_string(),
                });
            }
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

        let body = match self.cache_dir.as_deref() {
            Some(cache_dir) => FreshBody::Staged(
                stage_bounded_response_body(resp, url, source, cache_dir, self.max_body_bytes)
                    .await?,
            ),
            None => FreshBody::Resident(read_bounded_body(resp, url, self.max_body_bytes).await?),
        };

        Ok(FetchResult::Fresh(Box::new(FreshDownload {
            body,
            etag,
            last_modified,
        })))
    }

    /// Spawn the controller for the background refresh generation.
    ///
    /// The controller exclusively owns this manager. Scheduled and forced
    /// refreshes move that whole value through one `spawn_blocking` worker and
    /// back; command receipt continues on the runtime while parsing and shard
    /// work run off its worker threads.
    pub fn spawn_refresh_loop(self) -> ListManagerTask {
        self.spawn_refresh_loop_after(Duration::ZERO)
    }

    /// Start a controller after a foreground refresh has already completed.
    ///
    /// Unlike [`Self::spawn_refresh_loop`], its first scheduled deadline is
    /// derived from the manager's normal cadence, avoiding an immediate
    /// duplicate of that completed foreground cycle during reload.
    pub(crate) fn spawn_refresh_loop_after_refresh(self) -> ListManagerTask {
        let wait = self.next_loop_wait(OffsetDateTime::now_utc());
        self.spawn_refresh_loop_after(wait)
    }

    fn spawn_refresh_loop_after(mut self, initial_wait: Duration) -> ListManagerTask {
        let cmd_rx = self.cmd_rx.take();
        let (retire_tx, retire_rx) = oneshot::channel();
        let join = tokio::spawn(list_manager_controller(
            self,
            cmd_rx,
            retire_rx,
            tokio::time::Instant::now() + initial_wait,
        ));
        ListManagerTask { retire_tx, join }
    }

    /// Move one refresh through the controller's owned blocking-worker path.
    ///
    /// Reload uses this before it creates its successor controller. The
    /// public refresh APIs intentionally remain `usize`-returning; Force
    /// completions use the private [`RefreshCompletion`] instead.
    pub(crate) async fn refresh_in_blocking(
        self,
        mode: RefreshMode,
    ) -> Result<(Self, usize), tokio::task::JoinError> {
        match spawn_list_refresh_worker(self, mode, RefreshCancellation::default()).await? {
            RefreshWorkerOutcome::Completed {
                manager,
                completion,
            } => Ok((manager, completion.domain_count)),
            RefreshWorkerOutcome::Cancelled { .. } => {
                unreachable!("replacement worker has no cancellation sender")
            }
        }
    }

    /// Pre-populate in-memory cache headers from on-disk `.meta` files.
    ///
    /// Only loads ETag / Last-Modified so the first `refresh()` can send
    /// conditional requests (304). Body text is NOT loaded; `refresh()`
    /// streams bodies from disk on demand, avoiding a whole-body startup
    /// residency spike.
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
                // and `resolve_retained_body_reader` clones each one in full on
                // every parse. No log line, no error, roughly twice the
                // RAM.
                tracing::warn!(target: "audit", "{}", LIST_CACHE_DIR_UNSET_WARNING);
                return;
            }
        };

        if let Err(error) = recover_cache_manifest_journal(&cache_dir) {
            tracing::error!(path = %rollback_journal_path(&cache_dir).display(), %error, "cannot recover cache manifest transaction; refusing disk cache load");
            return;
        }

        // rev-2606 §06 carryover-3: the cache is trusted on read (its body
        // is parsed straight into the filter map). If the directory is
        // group- or world-writable, a local non-daemon user could plant a
        // cached body and steer filtering. Warn at startup so the
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
            let url = match self.fetch_urls.get(source) {
                Some(url) => url.clone(),
                None => continue,
            };

            let stem = source_to_cache_stem(source);
            let meta_path = cache_dir.join(format!("{stem}.meta"));
            let parsed = load_meta_file(&meta_path);
            let cache_path = match selected_body_path(&cache_dir, &stem, &parsed) {
                Some(path) => path,
                None => continue,
            };

            // Only check that the cache file exists; don't load it.
            if !cache_path.exists() {
                continue;
            }

            if !cache_identity_matches(source, &url, &parsed) {
                tracing::info!(
                    source = source.as_str(),
                    path = %cache_path.display(),
                    "disk cache identity does not match this fetch generation"
                );
                continue;
            }

            let has_real_fetched_at = parsed.fetched_at.is_some();
            let entry = self.cache.entry(url.clone()).or_default();
            entry.etag = parsed.etag;
            entry.last_modified = parsed.last_modified;
            // Legacy meta files (pre-Sprint-24) have no fetched-at line:
            // stamp them as now_utc() on first read so they look fresh and
            // do not trigger an HTTP burst on the next refresh cycle. The
            // real timestamp will become accurate after the first
            // successful 200/304 response.
            entry.fetched_at = parsed.fetched_at.unwrap_or_else(OffsetDateTime::now_utc);
            if has_real_fetched_at {
                self.legacy_cache_timestamp_urls.remove(&url);
            } else {
                self.legacy_cache_timestamp_urls.insert(url.clone());
            }

            tracing::info!(
                source = source.as_str(),
                path = %cache_path.display(),
                has_etag = entry.etag.is_some(),
                fetched_at = %entry.fetched_at,
                "disk cache available (headers loaded, body deferred)"
            );
        }
    }

    /// Remove legacy files and exact generation bodies for removed sources;
    /// also reclaim active-stem generation orphans selected by no valid manifest.
    pub fn cleanup_stale_caches(&self) {
        let cache_dir = match &self.cache_dir {
            Some(dir) => dir,
            None => return,
        };

        let journal_path = rollback_journal_path(cache_dir);
        match journal_path.try_exists() {
            Ok(false) => {}
            Ok(true) => {
                tracing::warn!(path = %journal_path.display(), "cache manifest rollback journal remains; skipping cache cleanup");
                return;
            }
            Err(error) => {
                tracing::warn!(path = %journal_path.display(), %error, "cannot determine whether cache manifest rollback journal remains; skipping cache cleanup");
                return;
            }
        }

        let active_stems: HashSet<String> = self
            .sources
            .iter()
            .map(|s| source_to_cache_stem(s))
            .collect();

        for stem in &active_stems {
            cleanup_active_generation_orphans(cache_dir, stem);
        }

        let entries = match std::fs::read_dir(cache_dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let stem = name
                .strip_suffix(".cache")
                .or_else(|| name.strip_suffix(".meta"))
                .or_else(|| generation_body_stem(&name));
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

/// Startup cleanup may reclaim only exact generation names that a valid
/// manifest does not select. Unreadable or malformed manifests are untouched.
fn cleanup_active_generation_orphans(cache_dir: &Path, stem: &str) {
    let meta = load_meta_file(&cache_dir.join(format!("{stem}.meta")));
    let selected = match meta.load_state {
        MetaLoadState::Unreadable => return,
        MetaLoadState::Missing => None,
        MetaLoadState::Loaded => match (meta.body.as_deref(), meta.sha256.as_deref()) {
            (None, None) if !meta.manifest_invalid => None,
            (Some(_), Some(_)) => match manifest_from_meta(stem, &meta) {
                Some(manifest) => {
                    let path = cache_dir.join(manifest.body);
                    if !path.is_file() {
                        return;
                    }
                    Some(path)
                }
                None => return,
            },
            _ => return,
        },
    };
    if selected.is_some() {
        remove_legacy_body(cache_dir, stem);
    }
    for path in generation_body_paths(cache_dir, stem) {
        if selected.as_ref() == Some(&path) {
            continue;
        }
        if let Err(error) = std::fs::remove_file(&path) {
            tracing::warn!(path = %path.display(), error = %error, "failed to remove stale list cache generation");
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

/// A cap refusal's structured measurements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SpillCapRefusal {
    max_entries: usize,
    dropped: u64,
}

/// A parse failure plus whether its spill rollback left uncertain records.
#[derive(Debug)]
struct SpillParseError {
    failure: SpillParseFailure,
    rollback: Option<std::io::Error>,
}

#[derive(Debug)]
enum SpillParseFailure {
    Parse(std::io::Error),
    CapRefusal(SpillCapRefusal),
}

impl SpillParseError {
    fn after_rollback(parse: std::io::Error, rollback: std::io::Result<()>) -> Self {
        Self {
            failure: SpillParseFailure::Parse(parse),
            rollback: rollback.err(),
        }
    }

    fn refused_at_cap(max_entries: usize, dropped: u64, rollback: std::io::Result<()>) -> Self {
        Self {
            failure: SpillParseFailure::CapRefusal(SpillCapRefusal {
                max_entries,
                dropped,
            }),
            rollback: rollback.err(),
        }
    }

    #[cfg(test)]
    fn kind(&self) -> std::io::ErrorKind {
        match &self.failure {
            SpillParseFailure::Parse(error) => error.kind(),
            SpillParseFailure::CapRefusal(_) => std::io::ErrorKind::Other,
        }
    }

    fn cap_refusal(&self) -> Option<SpillCapRefusal> {
        match &self.failure {
            SpillParseFailure::Parse(_) => None,
            SpillParseFailure::CapRefusal(refusal) => Some(*refusal),
        }
    }

    fn rollback_error(&self) -> Option<&std::io::Error> {
        self.rollback.as_ref()
    }
}

impl std::fmt::Display for SpillParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.failure {
            SpillParseFailure::Parse(error) => error.fmt(f),
            SpillParseFailure::CapRefusal(refusal) => {
                super::status::format_blocklist_truncation_refused(
                    refusal.max_entries,
                    refusal.dropped,
                )
                .fmt(f)
            }
        }
    }
}

impl std::error::Error for SpillParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.failure {
            SpillParseFailure::Parse(error) => Some(error),
            SpillParseFailure::CapRefusal(_) => None,
        }
    }
}

fn status_from_spill_parse_error(
    prev: Option<&ListStatus>,
    error: &SpillParseError,
    now: OffsetDateTime,
) -> ListStatus {
    match error.cap_refusal() {
        Some(cap) => ListStatus::from_cap_refusal(prev, cap.max_entries, cap.dropped, now),
        None => ListStatus::from_failure(prev, error.to_string(), now),
    }
}

fn poison_refresh_on_spill_rollback(
    error: &SpillParseError,
    source: &str,
    spill_rollback_failed: &mut bool,
) {
    if let Some(rollback) = error.rollback_error() {
        tracing::error!(
            source,
            error = %rollback,
            "failed to roll back shard spill; keeping current domain map"
        );
        *spill_rollback_failed = true;
    }
}

struct ParsedSpillBody {
    counts: ParsedCounts,
    digest: [u8; 32],
    len: usize,
}

struct SpillParseOptions {
    declared: Option<ListFormat>,
    counting: UniqueCount,
    rollback_site: SpillRollbackSite,
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
    options: SpillParseOptions,
) -> Result<ParsedSpillBody, SpillParseError> {
    let mark = spill.mark();
    let mut reader = HashingReader::new(reader);
    let mut sink = match options.counting {
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
        options.declared,
    ) {
        // Cap refusals are atomic: no candidate rows remain in the spill.
        Ok(counts) if counts.parsed_truncated > 0 => {
            tracing::error!(
                target: "audit",
                source,
                max_entries,
                dropped = counts.parsed_truncated,
                "source exceeded its effective entry cap; refusing its candidate"
            );
            Err(SpillParseError::refused_at_cap(
                max_entries,
                counts.parsed_truncated,
                spill.rollback(&mark, options.rollback_site),
            ))
        }
        Ok(mut counts) => {
            // The measured count when there is one, the carried one
            // otherwise. Never both, and never zero-by-omission — see
            // [`UniqueCount`].
            counts.unique_domains = match (sink.unique_domains(), options.counting) {
                (Some(measured), _) => measured,
                (None, UniqueCount::Carried(prior)) => prior.get(),
                // Unreachable: `counting_nothing` is only built for the
                // `Carried` arm. Handled rather than unwrapped because the
                // failure mode of getting it wrong is a silently disarmed
                // retention guard, not a panic.
                (None, UniqueCount::Measure(_)) => 0,
            };
            let (digest, len) = reader.finish();
            Ok(ParsedSpillBody {
                counts,
                digest,
                len,
            })
        }
        Err(e) => Err(SpillParseError::after_rollback(
            e,
            spill.rollback(&mark, options.rollback_site),
        )),
    }
}

/// Parse either a disk-backed fresh generation or one of the two deliberate
/// resident bridges through the same parser and spill transaction.
fn parse_fresh_download_into_spill_counted(
    candidate: &FreshDownload,
    bit_mask: u64,
    spill: &mut ShardSpill,
    max_entries: usize,
    source: &str,
    declared: Option<ListFormat>,
    counting: UniqueCount,
) -> Result<(ParsedCounts, [u8; 32]), SpillParseError> {
    let mark = spill.mark();
    let reader = candidate.body.open_reader().map_err(|error| {
        SpillParseError::after_rollback(
            error,
            spill.rollback(&mark, SpillRollbackSite::FreshReaderOpen),
        )
    })?;
    match parse_source_into_spill_counted(
        reader,
        bit_mask,
        spill,
        max_entries,
        source,
        SpillParseOptions {
            declared,
            counting,
            rollback_site: SpillRollbackSite::FreshParse,
        },
    ) {
        Ok(parsed)
            if candidate.body.staged().is_none_or(|staged| {
                parsed.len == staged.len && parsed.digest == staged.digest
            }) =>
        {
            Ok((parsed.counts, parsed.digest))
        }
        Ok(_) => Err(SpillParseError::after_rollback(
            std::io::Error::other(
                "fresh staged cache body length or SHA-256 changed while parsing",
            ),
            spill.rollback(&mark, SpillRollbackSite::FreshVerification),
        )),
        Err(error) => Err(error),
    }
}

/// Parse a retained representation as one transaction.  Manifest generations
/// are admitted only when the bytes consumed by the parser match their
/// committed digest; the outer mark also covers a post-parse mismatch.
fn parse_retained_source_into_spill_counted(
    reader: BodyReader,
    bit_mask: u64,
    spill: &mut ShardSpill,
    max_entries: usize,
    source: &str,
    declared: Option<ListFormat>,
    counting: UniqueCount,
) -> Result<(ParsedCounts, [u8; 32]), SpillParseError> {
    let mark = spill.mark();
    let expected = reader.expected_sha256();
    match parse_source_into_spill_counted(
        reader,
        bit_mask,
        spill,
        max_entries,
        source,
        SpillParseOptions {
            declared,
            counting,
            rollback_site: SpillRollbackSite::RetainedParse,
        },
    ) {
        Ok(parsed) if expected.is_none_or(|expected| expected == parsed.digest) => {
            Ok((parsed.counts, parsed.digest))
        }
        Ok(_) => Err(SpillParseError::after_rollback(
            std::io::Error::other("retained cache body SHA-256 does not match manifest"),
            spill.rollback(&mark, SpillRollbackSite::RetainedVerification),
        )),
        Err(error) => Err(error),
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
) -> Result<(ParsedCounts, [u8; 32]), SpillParseError> {
    let parsed = parse_source_into_spill_counted(
        reader,
        bit_mask,
        spill,
        max_entries,
        source,
        SpillParseOptions {
            declared,
            counting: UniqueCount::Measure(None),
            rollback_site: SpillRollbackSite::DirectTest,
        },
    )?;
    Ok((parsed.counts, parsed.digest))
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
        cancellation::io_checkpoint("cache_hash")?;
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() {
            break;
        }
        let n = chunk.len().min(8 * 1024);
        hasher.update(&chunk[..n]);
        reader.consume(n);
    }
    Ok(hasher.finalize().into())
}

fn hash_retained_body(reader: BodyReader) -> std::io::Result<[u8; 32]> {
    let expected = reader.expected_sha256();
    let actual = hash_body(reader)?;
    match expected {
        Some(expected) if expected != actual => Err(std::io::Error::other(
            "retained cache body SHA-256 does not match manifest",
        )),
        _ => Ok(actual),
    }
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

/// A fresh body that parsed successfully but is not yet allowed to select a
/// new manifest or claim source success.
struct PendingCacheAdmission {
    source: String,
    url: String,
    etag: Option<String>,
    last_modified: Option<String>,
    staged: Option<StagedCacheBody>,
    body: Option<String>,
    previous_cache_path: PathBuf,
}

struct PendingCacheRevalidation {
    status: PendingStatus,
    url: String,
    cache_path: PathBuf,
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
/// `load_state` distinguishes a missing legacy sidecar from an unreadable one.
struct ParsedMeta {
    load_state: MetaLoadState,
    etag: Option<String>,
    last_modified: Option<String>,
    fetched_at: Option<OffsetDateTime>,
    size: Option<usize>,
    resolved_url: Option<String>,
    has_resolved_url: bool,
    body: Option<String>,
    sha256: Option<String>,
    manifest_invalid: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MetaLoadState {
    Missing,
    Loaded,
    Unreadable,
}

#[derive(Clone, Copy)]
struct GenerationManifest<'a> {
    body: &'a str,
    sha256: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GenerationFileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CacheFileContract {
    #[cfg(unix)]
    uid: u32,
    #[cfg(unix)]
    gid: u32,
    #[cfg(unix)]
    mode: u32,
}

/// A cache generation stays bound to this inode until its manifest commits.
struct StagedCacheBody {
    source: String,
    body_path: PathBuf,
    basename: String,
    sha256: String,
    len: usize,
    digest: [u8; 32],
    file: std::fs::File,
    identity: GenerationFileIdentity,
    contract: CacheFileContract,
    owns_body: bool,
}

impl Drop for StagedCacheBody {
    fn drop(&mut self) {
        if self.owns_body {
            if let Some(dir) = self.body_path.parent() {
                discard_unselected_staged_body(dir, &self.source, self);
            }
        }
    }
}

impl StagedCacheBody {
    fn reader(&self) -> std::io::Result<std::io::BufReader<std::io::Take<std::fs::File>>> {
        self.verify_handle_metadata()?;
        self.verify_path_identity()?;
        let mut file = self.file.try_clone()?;
        file.seek(SeekFrom::Start(0))?;
        let limit = self
            .len
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("staged cache body length overflow"))?;
        let limit = u64::try_from(limit)
            .map_err(|_| std::io::Error::other("staged cache body length overflow"))?;
        Ok(std::io::BufReader::with_capacity(
            SPILL_WRITE_BUF,
            file.take(limit),
        ))
    }

    fn verify_for_publication(&self) -> std::io::Result<()> {
        self.verify_handle_metadata()?;
        if !generation_file_matches(&self.file, self.len, self.digest)? {
            return Err(std::io::Error::other(
                "staged cache body no longer matches its hash",
            ));
        }
        self.verify_path_identity()
    }

    fn verify_handle_metadata(&self) -> std::io::Result<()> {
        let identity = verify_generation_file_contract(&self.file, &self.contract)?;
        if identity != self.identity {
            return Err(std::io::Error::other(
                "staged cache body handle identity changed",
            ));
        }
        let expected_len = u64::try_from(self.len)
            .map_err(|_| std::io::Error::other("staged cache body length overflow"))?;
        let actual_len = self.file.metadata()?.len();
        if actual_len != expected_len {
            return Err(std::io::Error::other(
                "staged cache body length changed before parsing",
            ));
        }
        Ok(())
    }

    fn verify_path_identity(&self) -> std::io::Result<()> {
        verify_generation_path_identity(&self.body_path, self.identity, &self.contract)
    }
}

struct CreatedGenerationBody {
    path: PathBuf,
    identity: GenerationFileIdentity,
    contract: CacheFileContract,
}

fn ensure_regular_generation_file(file: &std::fs::File) -> std::io::Result<()> {
    if !file.metadata()?.file_type().is_file() {
        return Err(std::io::Error::other(
            "cache generation is not a regular file",
        ));
    }
    Ok(())
}

fn open_regular_generation_file(path: &Path) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    #[cfg(not(unix))]
    let file = std::fs::File::open(path)?;
    ensure_regular_generation_file(&file)?;
    Ok(file)
}

fn cache_file_contract(file: &std::fs::File) -> std::io::Result<CacheFileContract> {
    ensure_regular_generation_file(file)?;
    #[cfg(unix)]
    {
        let metadata = file.metadata()?;
        let mode = metadata.mode() & 0o777;
        Ok(CacheFileContract {
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode,
        })
    }
    #[cfg(not(unix))]
    Ok(CacheFileContract {})
}

fn streamed_cache_file_contract(file: &std::fs::File) -> std::io::Result<CacheFileContract> {
    let contract = cache_file_contract(file)?;
    #[cfg(unix)]
    if contract.mode != 0o640 {
        return Err(std::io::Error::other(
            "cache generation does not have the required 0640 mode",
        ));
    }
    Ok(contract)
}

fn generation_file_identity(file: &std::fs::File) -> std::io::Result<GenerationFileIdentity> {
    let metadata = file.metadata()?;
    #[cfg(unix)]
    {
        Ok(GenerationFileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Ok(GenerationFileIdentity {})
    }
}

fn verify_generation_file_contract(
    file: &std::fs::File,
    expected: &CacheFileContract,
) -> std::io::Result<GenerationFileIdentity> {
    if cache_file_contract(file)? != *expected {
        return Err(std::io::Error::other(
            "cache generation ownership or mode does not match its stage",
        ));
    }
    generation_file_identity(file)
}

/// A pathname is trusted only while it still names the verified inode.
fn verify_generation_path_identity(
    path: &Path,
    expected_identity: GenerationFileIdentity,
    contract: &CacheFileContract,
) -> std::io::Result<()> {
    let path_file = open_regular_generation_file(path)?;
    if verify_generation_file_contract(&path_file, contract)? != expected_identity {
        return Err(std::io::Error::other(
            "cache generation pathname no longer names its verified inode",
        ));
    }
    Ok(())
}

struct SpillCleanup(Option<PathBuf>);
impl Drop for SpillCleanup {
    fn drop(&mut self) {
        if let Some(dir) = &self.0 {
            purge_shard_spill(dir);
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheRollbackJournal {
    version: u8,
    entries: Vec<CacheRollbackEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheRollbackEntry {
    stem: String,
    /// Exact prior `.meta` bytes, or no prior manifest at all.
    prior_meta: Option<Vec<u8>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CorpusManifestCommit {
    Durable,
    DurabilityUncertain,
    Failed,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ManifestCommit {
    Durable,
    DurabilityUncertain,
}

fn generation_basename(stem: &str, sha256: &str) -> String {
    format!("{stem}.body-{sha256}")
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn manifest_from_meta<'a>(stem: &str, meta: &'a ParsedMeta) -> Option<GenerationManifest<'a>> {
    if meta.load_state != MetaLoadState::Loaded || meta.manifest_invalid {
        return None;
    }
    match (meta.body.as_deref(), meta.sha256.as_deref()) {
        (None, None) => None,
        (Some(body), Some(sha256))
            if valid_sha256(sha256) && body == generation_basename(stem, sha256) =>
        {
            Some(GenerationManifest { body, sha256 })
        }
        _ => None,
    }
}

/// Select only a complete, stem-bound manifest. Invalid generation fields
/// never fall back to the legacy body.
fn selected_body_path(cache_dir: &Path, stem: &str, meta: &ParsedMeta) -> Option<PathBuf> {
    if meta.load_state == MetaLoadState::Unreadable {
        return None;
    }
    match (meta.body.as_deref(), meta.sha256.as_deref()) {
        (None, None) if !meta.manifest_invalid => Some(cache_dir.join(format!("{stem}.cache"))),
        (Some(_), Some(_)) => manifest_from_meta(stem, meta).map(|m| cache_dir.join(m.body)),
        _ => None,
    }
}

fn selected_cache_body_path(cache_dir: &Path, source: &str) -> Option<PathBuf> {
    let stem = source_to_cache_stem(source);
    let meta = load_meta_file(&cache_dir.join(format!("{stem}.meta")));
    selected_body_path(cache_dir, &stem, &meta)
}

fn validate_selected_body_size(stem: &str, meta: &ParsedMeta, actual: usize) -> bool {
    if meta.load_state == MetaLoadState::Unreadable {
        return false;
    }
    match manifest_from_meta(stem, meta) {
        Some(_) => meta.size == Some(actual),
        None if meta.body.is_none() && meta.sha256.is_none() && !meta.manifest_invalid => {
            validate_cached_body_size(meta.size, actual)
        }
        None => false,
    }
}

fn generation_body_stem(name: &str) -> Option<&str> {
    let (stem, sha256) = name.rsplit_once(".body-")?;
    valid_sha256(sha256).then_some(stem)
}

fn generation_body_paths(cache_dir: &Path, stem: &str) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(cache_dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name();
            let name = name.to_str()?;
            (generation_body_stem(name) == Some(stem)).then_some(entry.path())
        })
        .collect()
}

/// A legacy sidecar can identify a raw URL representative from its stem, but
/// a catalog slug can move without changing that stem.
fn cache_identity_matches(source: &str, fetch_url: &str, meta: &ParsedMeta) -> bool {
    match meta.resolved_url.as_deref() {
        Some(stored) => stored == fetch_url,
        // Old raw-URL sidecars had no resolved-url line. They are safe only
        // when their source spelling is the exact URL this generation fetches.
        None => {
            !meta.has_resolved_url
                && crate::lists::source_key::is_url_source(source)
                && source == fetch_url
        }
    }
}

/// Load ETag, Last-Modified, and (optionally) fetched-at + size from a
/// `.meta` sidecar file.
fn load_meta_file(path: &Path) -> ParsedMeta {
    let mut parsed = ParsedMeta {
        load_state: MetaLoadState::Missing,
        etag: None,
        last_modified: None,
        fetched_at: None,
        size: None,
        resolved_url: None,
        has_resolved_url: false,
        body: None,
        sha256: None,
        manifest_invalid: false,
    };
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return parsed,
        Err(error) => {
            parsed.load_state = MetaLoadState::Unreadable;
            tracing::warn!(path = %path.display(), error = %error, "cannot read cache manifest");
            return parsed;
        }
    };
    parsed.load_state = MetaLoadState::Loaded;
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
        } else if let Some(v) = line.strip_prefix("resolved-url=") {
            parsed.has_resolved_url = true;
            if !v.is_empty() {
                parsed.resolved_url = Some(v.to_string());
            }
        } else if let Some(v) = line.strip_prefix("body=") {
            if parsed.body.replace(v.to_string()).is_some() {
                parsed.manifest_invalid = true;
            }
        } else if let Some(v) = line.strip_prefix("sha256=") {
            if parsed.sha256.replace(v.to_string()).is_some() {
                parsed.manifest_invalid = true;
            }
        }
    }
    parsed
}

/// Persist a downloaded list body before atomically committing its manifest.
///
/// `fetched_at` is serialized as an RFC 3339 line in the `.meta`
/// sidecar so the freshness check (Phase 1.2) can reconstruct the
/// cache's age across daemon restarts. Pass `OffsetDateTime::now_utc()`
/// for fresh fetches.
///
#[cfg(test)]
fn write_cache_to_disk(
    cache_dir: &Path,
    source: &str,
    resolved_url: &str,
    body: &str,
    etag: Option<&str>,
    last_modified: Option<&str>,
    fetched_at: OffsetDateTime,
) -> std::io::Result<PathBuf> {
    let staged = stage_cache_body(cache_dir, source, body)?;
    commit_staged_cache_body(
        cache_dir,
        source,
        resolved_url,
        &staged,
        etag,
        last_modified,
        fetched_at,
    )?;
    Ok(staged.body_path.clone())
}

fn stage_cache_body(
    cache_dir: &Path,
    source: &str,
    body: &str,
) -> std::io::Result<StagedCacheBody> {
    let stem = source_to_cache_stem(source);
    let digest = hash_body(std::io::Cursor::new(body.as_bytes()))?;
    let sha256 = hex::encode(digest);
    let basename = generation_basename(&stem, &sha256);
    let body_path = cache_dir.join(&basename);
    atomic_write_body_confirmed(&body_path, body.as_bytes(), body.len(), digest)?;
    let file = open_regular_generation_file(&body_path)?;
    let contract = cache_file_contract(&file)?;
    let identity = verify_generation_file_contract(&file, &contract)?;
    if !generation_file_matches(&file, body.len(), digest)? {
        return Err(std::io::Error::other(
            "staged cache body does not match the expected content",
        ));
    }
    let staged = StagedCacheBody {
        source: source.to_owned(),
        body_path,
        basename,
        sha256,
        len: body.len(),
        digest,
        file,
        identity,
        contract,
        owns_body: true,
    };
    cancellation::io_checkpoint("staged_body")?;
    Ok(staged)
}

/// A private, O_EXCL-backed cache spool. It becomes a generation only after
/// its streamed bytes, mode, and file contents are durable.
struct StreamedCacheBody {
    cache_dir: PathBuf,
    source: String,
    temp_path: Option<PathBuf>,
    writer: Option<std::io::BufWriter<tempfile::NamedTempFile>>,
    temp_identity: GenerationFileIdentity,
    temp_contract: CacheFileContract,
    decoder: LossyUtf8CacheWriter,
    decoded_len: usize,
    created_body: Option<CreatedGenerationBody>,
}

impl StreamedCacheBody {
    fn new(cache_dir: &Path, source: &str) -> std::io::Result<Self> {
        let stem = source_to_cache_stem(source);
        let temp = tempfile::Builder::new()
            .prefix(&format!(".{stem}.download-"))
            .tempfile_in(cache_dir)?;
        #[cfg(unix)]
        temp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o640))?;
        let temp_contract = streamed_cache_file_contract(temp.as_file())?;
        let temp_identity = verify_generation_file_contract(temp.as_file(), &temp_contract)?;
        let temp_path = temp.path().to_path_buf();
        let mut temp = temp;
        temp.disable_cleanup(true);
        Ok(Self {
            cache_dir: cache_dir.to_path_buf(),
            source: source.to_owned(),
            temp_path: Some(temp_path),
            writer: Some(std::io::BufWriter::with_capacity(SPILL_WRITE_BUF, temp)),
            temp_identity,
            temp_contract,
            decoder: LossyUtf8CacheWriter::new(),
            decoded_len: 0,
            created_body: None,
        })
    }

    fn write_chunk(&mut self, chunk: &[u8]) -> std::io::Result<()> {
        cancellation::io_checkpoint("staged_body_write")?;
        #[cfg(test)]
        if fail_streamed_cache_body_write_for_test() {
            return Err(std::io::Error::other(
                "injected streamed cache-body write failure",
            ));
        }
        let (decoder, writer) = (&mut self.decoder, &mut self.writer);
        decoder.write_chunk(writer.as_mut().expect("streamed body writer exists"), chunk)?;
        cancellation::io_checkpoint("staged_body_write")?;
        Ok(())
    }

    fn finish(mut self) -> std::io::Result<StagedCacheBody> {
        let (len, digest) = {
            let (decoder, writer) = (&mut self.decoder, &mut self.writer);
            decoder.finish(writer.as_mut().expect("streamed body writer exists"))?
        };
        cancellation::io_checkpoint("staged_body_flush")?;
        let writer = self.writer.as_mut().expect("streamed body writer exists");
        writer.flush()?;
        cancellation::io_checkpoint("staged_body_sync")?;
        writer.get_ref().as_file().sync_all()?;

        let temp = self
            .writer
            .take()
            .expect("streamed body writer exists")
            .into_inner()
            .map_err(|error| error.into_error())?;
        let temp_path = self.temp_path.clone().expect("streamed body path exists");
        let stem = source_to_cache_stem(&self.source);
        let sha256 = hex::encode(digest);
        let basename = generation_basename(&stem, &sha256);
        let body_path = self.cache_dir.join(&basename);

        cancellation::io_checkpoint("staged_body_promote")?;
        verify_streamed_cache_temp_for_promotion(
            &temp,
            &temp_path,
            self.temp_identity,
            &self.temp_contract,
        )?;
        let contract = self.temp_contract;
        let (file, identity, created) = match temp.persist_noclobber(&body_path) {
            Ok(file) => {
                let identity = verify_generation_file_contract(&file, &contract)?;
                if identity != self.temp_identity {
                    return Err(std::io::Error::other(
                        "promoted cache generation does not match its staged inode",
                    ));
                }
                self.created_body = Some(CreatedGenerationBody {
                    path: body_path.clone(),
                    identity,
                    contract,
                });
                #[cfg(test)]
                run_streamed_cache_body_after_persist_hook_for_test(&body_path);
                let destination = open_regular_generation_file(&body_path)?;
                if verify_generation_file_contract(&destination, &contract)? != identity {
                    return Err(std::io::Error::other(
                        "promoted cache generation pathname no longer names its staged inode",
                    ));
                }
                if !generation_file_matches(&destination, len, digest)? {
                    return Err(std::io::Error::other(
                        "new cache generation does not match its staged content",
                    ));
                }
                (destination, identity, true)
            }
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                drop(error.file);
                let existing = open_regular_generation_file(&body_path)?;
                let identity = verify_generation_file_contract(&existing, &contract)?;
                if !generation_file_matches(&existing, len, digest)? {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        "content-addressed cache body already exists with different bytes",
                    ));
                }
                existing.sync_all()?;
                let current = open_regular_generation_file(&body_path)?;
                if verify_generation_file_contract(&current, &contract)? != identity {
                    return Err(std::io::Error::other(
                        "content-addressed cache body changed during collision reuse",
                    ));
                }
                (existing, identity, false)
            }
            Err(error) => {
                let source = error.error;
                drop(error.file);
                return Err(source);
            }
        };

        if created {
            cancellation::io_checkpoint("staged_body_parent_fsync")?;
            fsync_cache_dir(&self.cache_dir)?;
        }

        let staged = StagedCacheBody {
            source: self.source.clone(),
            body_path,
            basename,
            sha256,
            len,
            digest,
            file,
            identity,
            contract,
            owns_body: created,
        };
        self.created_body = None;
        Ok(staged)
    }
}

impl Drop for StreamedCacheBody {
    fn drop(&mut self) {
        let temp_path = self.temp_path.take();
        drop(self.writer.take());
        let created_body = self.created_body.take();
        let mut changed = false;
        if let Some(path) = temp_path {
            match remove_generation_if_matches(&path, self.temp_identity, &self.temp_contract) {
                Ok(removed) => changed |= removed,
                Err(error) => tracing::warn!(
                    path = %path.display(),
                    source = %self.source,
                    %error,
                    "refusing to remove a substituted streamed list cache staging"
                ),
            }
        }
        if let Some(created) = created_body {
            match remove_generation_if_matches(&created.path, created.identity, &created.contract) {
                Ok(removed) => changed |= removed,
                Err(error) => tracing::warn!(
                    path = %created.path.display(),
                    source = %self.source,
                    %error,
                    "refusing to remove a substituted streamed list cache body"
                ),
            }
        }
        if changed {
            if let Err(error) = fsync_cache_dir(&self.cache_dir) {
                tracing::warn!(
                    path = %self.cache_dir.display(),
                    source = %self.source,
                    %error,
                    "failed to durably remove streamed list cache staging"
                );
            }
        }
    }
}

fn verify_streamed_cache_temp_for_promotion(
    temp: &tempfile::NamedTempFile,
    temp_path: &Path,
    expected_identity: GenerationFileIdentity,
    contract: &CacheFileContract,
) -> std::io::Result<()> {
    if verify_generation_file_contract(temp.as_file(), contract)? != expected_identity {
        return Err(std::io::Error::other(
            "streamed cache staging handle identity changed before promotion",
        ));
    }
    verify_generation_path_identity(temp_path, expected_identity, contract)
}

/// Incremental `String::from_utf8_lossy` preserving decoder state across
/// HTTP chunks while writing only UTF-8 bytes to the cache generation.
struct LossyUtf8CacheWriter {
    pending: [u8; 4],
    pending_len: usize,
    written: usize,
    hasher: sha2::Sha256,
}

impl LossyUtf8CacheWriter {
    fn new() -> Self {
        use sha2::Digest;
        Self {
            pending: [0; 4],
            pending_len: 0,
            written: 0,
            hasher: sha2::Sha256::new(),
        }
    }

    fn write_chunk(
        &mut self,
        writer: &mut std::io::BufWriter<tempfile::NamedTempFile>,
        mut input: &[u8],
    ) -> std::io::Result<()> {
        self.resolve_pending(writer, &mut input)?;
        while !input.is_empty() {
            match std::str::from_utf8(input) {
                Ok(_) => {
                    self.write_bytes(writer, input)?;
                    break;
                }
                Err(error) => {
                    let valid = error.valid_up_to();
                    if valid > 0 {
                        self.write_bytes(writer, &input[..valid])?;
                        input = &input[valid..];
                    }
                    match error.error_len() {
                        Some(invalid) => {
                            self.write_bytes(writer, "\u{FFFD}".as_bytes())?;
                            input = &input[invalid..];
                        }
                        None => {
                            if input.len() > self.pending.len() {
                                return Err(std::io::Error::other(
                                    "invalid UTF-8 decoder carry exceeds four bytes",
                                ));
                            }
                            self.pending[..input.len()].copy_from_slice(input);
                            self.pending_len = input.len();
                            return Ok(());
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn finish(
        &mut self,
        writer: &mut std::io::BufWriter<tempfile::NamedTempFile>,
    ) -> std::io::Result<(usize, [u8; 32])> {
        if self.pending_len > 0 {
            let mut bytes = [0; 4];
            bytes[..self.pending_len].copy_from_slice(&self.pending[..self.pending_len]);
            let pending = String::from_utf8_lossy(&bytes[..self.pending_len]);
            self.write_bytes(writer, pending.as_bytes())?;
            self.pending_len = 0;
        }
        use sha2::Digest;
        Ok((self.written, self.hasher.clone().finalize().into()))
    }

    fn resolve_pending(
        &mut self,
        writer: &mut std::io::BufWriter<tempfile::NamedTempFile>,
        input: &mut &[u8],
    ) -> std::io::Result<()> {
        while self.pending_len > 0 {
            match std::str::from_utf8(&self.pending[..self.pending_len]) {
                Ok(_) => {
                    self.write_pending(writer, self.pending_len)?;
                    self.pending_len = 0;
                }
                Err(error) if error.valid_up_to() > 0 => {
                    let valid = error.valid_up_to();
                    self.write_pending(writer, valid)?;
                    self.drop_pending_prefix(valid);
                }
                Err(error) => match error.error_len() {
                    Some(invalid) => {
                        self.write_bytes(writer, "\u{FFFD}".as_bytes())?;
                        self.drop_pending_prefix(invalid);
                    }
                    None => {
                        let Some((&byte, rest)) = input.split_first() else {
                            return Ok(());
                        };
                        if self.pending_len == self.pending.len() {
                            return Err(std::io::Error::other(
                                "invalid UTF-8 decoder carry exceeds four bytes",
                            ));
                        }
                        self.pending[self.pending_len] = byte;
                        self.pending_len += 1;
                        *input = rest;
                    }
                },
            }
        }
        Ok(())
    }

    fn write_pending(
        &mut self,
        writer: &mut std::io::BufWriter<tempfile::NamedTempFile>,
        len: usize,
    ) -> std::io::Result<()> {
        let mut bytes = [0; 4];
        bytes[..len].copy_from_slice(&self.pending[..len]);
        self.write_bytes(writer, &bytes[..len])
    }

    fn drop_pending_prefix(&mut self, len: usize) {
        self.pending.copy_within(len..self.pending_len, 0);
        self.pending_len -= len;
    }

    fn write_bytes(
        &mut self,
        writer: &mut std::io::BufWriter<tempfile::NamedTempFile>,
        bytes: &[u8],
    ) -> std::io::Result<()> {
        let written = self
            .written
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::other("lossy cache body length overflow"))?;
        writer.write_all(bytes)?;
        use sha2::Digest;
        self.hasher.update(bytes);
        self.written = written;
        Ok(())
    }
}

/// Stream a decoded HTTP response into an unselected content-addressed body.
async fn stage_bounded_response_body(
    resp: reqwest::Response,
    url: &str,
    source: &str,
    cache_dir: &Path,
    max_bytes: usize,
) -> Result<StagedCacheBody, ListError> {
    let mut resp = resp;
    let mut staged =
        StreamedCacheBody::new(cache_dir, source).map_err(|error| ListError::Download {
            url: super::http_client::redact_userinfo(url),
            reason: format!("cannot create streamed cache body: {error}"),
        })?;
    while let Some(chunk) = cancellation::wait(resp.chunk(), "http_chunk")
        .await?
        .map_err(|error| ListError::Download {
            url: super::http_client::redact_userinfo(url),
            reason: classify_fetch_error(&error),
        })?
    {
        let projected =
            bounded_body_growth(staged.decoded_len, chunk.len(), max_bytes).map_err(|size| {
                ListError::TooLarge {
                    url: super::http_client::redact_userinfo(url),
                    size,
                    max: max_bytes,
                }
            })?;
        staged
            .write_chunk(&chunk)
            .map_err(|error| ListError::Download {
                url: super::http_client::redact_userinfo(url),
                reason: format!("cannot write streamed cache body: {error}"),
            })?;
        staged.decoded_len = projected;
        cancellation::checkpoint("http_body_chunk")?;
    }
    let staged = staged.finish().map_err(|error| ListError::Download {
        url: super::http_client::redact_userinfo(url),
        reason: format!("cannot finalize streamed cache body: {error}"),
    })?;
    cancellation::checkpoint("staged_body")?;
    Ok(staged)
}

#[cfg(test)]
fn commit_staged_cache_body(
    cache_dir: &Path,
    source: &str,
    resolved_url: &str,
    staged: &StagedCacheBody,
    etag: Option<&str>,
    last_modified: Option<&str>,
    fetched_at: OffsetDateTime,
) -> std::io::Result<ManifestCommit> {
    let commit = commit_staged_cache_manifest(
        cache_dir,
        source,
        resolved_url,
        staged,
        etag,
        last_modified,
        fetched_at,
    )?;
    let stem = source_to_cache_stem(source);
    match commit {
        ManifestCommit::Durable => {
            remove_legacy_body(cache_dir, &stem);
            garbage_collect_generation_bodies(cache_dir, &stem, &staged.basename);
            Ok(ManifestCommit::Durable)
        }
        ManifestCommit::DurabilityUncertain => {
            tracing::warn!(path = %cache_dir.join(format!("{stem}.meta")).display(), "cache manifest landed but parent fsync failed; retaining prior bodies");
            Ok(ManifestCommit::DurabilityUncertain)
        }
    }
}

/// Select a staged body without reclaiming anything. Corpus transactions defer
/// all collection until their journal deletion is durable.
fn commit_staged_cache_manifest(
    cache_dir: &Path,
    source: &str,
    resolved_url: &str,
    staged: &StagedCacheBody,
    etag: Option<&str>,
    last_modified: Option<&str>,
    fetched_at: OffsetDateTime,
) -> std::io::Result<ManifestCommit> {
    staged.verify_for_publication()?;
    let stem = source_to_cache_stem(source);
    let meta_path = cache_dir.join(format!("{stem}.meta"));
    let meta_content = build_meta_content(
        etag,
        last_modified,
        resolved_url,
        fetched_at,
        Some(staged.len),
        Some(GenerationManifest {
            body: &staged.basename,
            sha256: &staged.sha256,
        }),
    );

    match write_cache_manifest(&meta_path, meta_content.as_bytes())? {
        ManifestCommit::Durable => Ok(ManifestCommit::Durable),
        ManifestCommit::DurabilityUncertain => Ok(ManifestCommit::DurabilityUncertain),
    }
}

fn rollback_journal_path(cache_dir: &Path) -> PathBuf {
    cache_dir.join(CACHE_ROLLBACK_JOURNAL)
}

fn valid_journal_stem(stem: &str) -> bool {
    let Some((_, suffix)) = stem.rsplit_once('-') else {
        return false;
    };
    stem.bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        && suffix.len() == 8
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn journal_meta_path(cache_dir: &Path, stem: &str) -> std::io::Result<PathBuf> {
    if !valid_journal_stem(stem) {
        return Err(std::io::Error::other("invalid rollback journal cache stem"));
    }
    Ok(cache_dir.join(format!("{stem}.meta")))
}

fn read_small_cache_file(path: &Path) -> std::io::Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    if file.metadata()?.len() > MAX_ROLLBACK_JOURNAL_BYTES {
        return Err(std::io::Error::other("rollback journal is too large"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_ROLLBACK_JOURNAL_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_ROLLBACK_JOURNAL_BYTES {
        return Err(std::io::Error::other("rollback journal is too large"));
    }
    Ok(bytes)
}

fn fsync_cache_dir(cache_dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(cache_dir)?.sync_all()
}

fn load_rollback_journal(cache_dir: &Path) -> std::io::Result<Option<CacheRollbackJournal>> {
    let path = rollback_journal_path(cache_dir);
    let bytes = match read_small_cache_file(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let journal: CacheRollbackJournal = serde_json::from_slice(&bytes)
        .map_err(|error| std::io::Error::other(format!("invalid rollback journal: {error}")))?;
    if journal.version != 1 || journal.entries.is_empty() {
        return Err(std::io::Error::other(
            "invalid rollback journal version or entries",
        ));
    }
    let mut stems = HashSet::new();
    for entry in &journal.entries {
        journal_meta_path(cache_dir, &entry.stem)?;
        if !stems.insert(&entry.stem) {
            return Err(std::io::Error::other(
                "duplicate rollback journal cache stem",
            ));
        }
    }
    Ok(Some(journal))
}

fn persist_rollback_journal(
    cache_dir: &Path,
    admissions: &[PendingCacheAdmission],
) -> std::io::Result<()> {
    let mut entries = Vec::new();
    let mut stems = HashSet::new();
    for admission in admissions {
        if admission.staged.is_none() {
            continue;
        }
        let stem = source_to_cache_stem(&admission.source);
        if !stems.insert(stem.clone()) {
            return Err(std::io::Error::other("duplicate cache manifest admission"));
        }
        let meta_path = journal_meta_path(cache_dir, &stem)?;
        let prior_meta = match read_small_cache_file(&meta_path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        entries.push(CacheRollbackEntry { stem, prior_meta });
    }
    let journal = CacheRollbackJournal {
        version: 1,
        entries,
    };
    let bytes = serde_json::to_vec(&journal).map_err(|error| {
        std::io::Error::other(format!("cannot serialize rollback journal: {error}"))
    })?;
    if bytes.len() as u64 > MAX_ROLLBACK_JOURNAL_BYTES {
        return Err(std::io::Error::other("rollback journal is too large"));
    }
    atomic_write(&rollback_journal_path(cache_dir), &bytes).map_err(std::io::Error::other)
}

/// Idempotently restore all prior manifests before removing the journal.
fn recover_cache_manifest_journal(cache_dir: &Path) -> std::io::Result<()> {
    let Some(journal) = load_rollback_journal(cache_dir)? else {
        return Ok(());
    };
    for entry in journal.entries {
        let meta_path = journal_meta_path(cache_dir, &entry.stem)?;
        match entry.prior_meta {
            Some(bytes) => atomic_write(&meta_path, &bytes).map_err(std::io::Error::other)?,
            None => match std::fs::remove_file(&meta_path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            },
        }
    }
    // Covers removals; restored files already fsync their parent individually.
    fsync_cache_dir(cache_dir)?;
    std::fs::remove_file(rollback_journal_path(cache_dir))?;
    fsync_cache_dir(cache_dir)
}

/// Commit every fresh manifest under one rollback journal. The journal's
/// durable deletion is the corpus cache commit point.
fn commit_cache_admissions_transaction(
    cache_dir: &Path,
    admissions: &[PendingCacheAdmission],
    now: OffsetDateTime,
) -> CorpusManifestCommit {
    if let Err(error) = recover_cache_manifest_journal(cache_dir) {
        tracing::warn!(%error, "cannot recover earlier cache manifest transaction");
        return CorpusManifestCommit::Failed;
    }
    if let Err(error) = persist_rollback_journal(cache_dir, admissions) {
        tracing::warn!(%error, "cannot durably persist cache manifest rollback journal");
        let _ = recover_cache_manifest_journal(cache_dir);
        return CorpusManifestCommit::Failed;
    }
    for admission in admissions {
        let Some(staged) = admission.staged.as_ref() else {
            continue;
        };
        match commit_staged_cache_manifest(
            cache_dir,
            &admission.source,
            &admission.url,
            staged,
            admission.etag.as_deref(),
            admission.last_modified.as_deref(),
            now,
        ) {
            Ok(ManifestCommit::Durable) => {
                #[cfg(test)]
                crash_after_cache_manifest_commit_for_test();
            }
            Ok(ManifestCommit::DurabilityUncertain) | Err(_) => {
                if let Err(error) = recover_cache_manifest_journal(cache_dir) {
                    tracing::error!(%error, "cannot roll back failed cache manifest transaction");
                }
                return CorpusManifestCommit::Failed;
            }
        }
    }
    match std::fs::remove_file(rollback_journal_path(cache_dir)) {
        Ok(()) => match fsync_cache_dir(cache_dir) {
            Ok(()) => CorpusManifestCommit::Durable,
            Err(error) => {
                tracing::warn!(%error, "cache manifest transaction journal deletion is durability-uncertain");
                CorpusManifestCommit::DurabilityUncertain
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match fsync_cache_dir(cache_dir) {
                Ok(()) => CorpusManifestCommit::Durable,
                Err(error) => {
                    tracing::warn!(%error, "cache manifest transaction journal deletion is durability-uncertain");
                    CorpusManifestCommit::DurabilityUncertain
                }
            }
        }
        Err(error) => {
            tracing::warn!(%error, "cannot remove cache manifest rollback journal");
            if let Err(error) = recover_cache_manifest_journal(cache_dir) {
                tracing::error!(%error, "cannot roll back failed cache manifest transaction");
            }
            CorpusManifestCommit::Failed
        }
    }
}

fn discard_unselected_staged_body(cache_dir: &Path, source: &str, staged: &StagedCacheBody) {
    let stem = source_to_cache_stem(source);
    let selected = selected_cache_body_path(cache_dir, source);
    if selected.as_deref() == Some(staged.body_path.as_path()) {
        return;
    }
    if let Err(error) = staged.verify_path_identity() {
        tracing::warn!(
            path = %staged.body_path.display(),
            source,
            stem,
            %error,
            "refusing to remove a substituted unselected list cache body"
        );
        return;
    }
    let removed =
        match remove_generation_if_matches(&staged.body_path, staged.identity, &staged.contract) {
            Ok(removed) => removed,
            Err(error) => {
                tracing::warn!(
                    path = %staged.body_path.display(),
                    source,
                    stem,
                    %error,
                    "failed to remove unselected staged list cache body"
                );
                false
            }
        };
    if removed {
        if let Err(error) = fsync_cache_dir(cache_dir) {
            tracing::warn!(
                path = %cache_dir.display(),
                source,
                %error,
                "failed to durably remove unselected staged list cache body"
            );
        }
    }
}

fn remove_generation_if_matches(
    path: &Path,
    expected_identity: GenerationFileIdentity,
    contract: &CacheFileContract,
) -> std::io::Result<bool> {
    let file = match open_regular_generation_file(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if verify_generation_file_contract(&file, contract)? != expected_identity {
        return Ok(false);
    }
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// A parent-fsync error arrives after rename. Only that exact ambiguity may
/// select matching bytes; all earlier failures leave the old manifest live.
fn atomic_write_confirmed(path: &Path, content: &[u8]) -> std::io::Result<ManifestCommit> {
    #[cfg(test)]
    if FAIL_NEXT_CACHE_MANIFEST_PARENT_FSYNC.with(|fail| fail.replace(false)) {
        atomic_write_without_parent_fsync(path, content)?;
        return Ok(ManifestCommit::DurabilityUncertain);
    }
    match atomic_write(path, content) {
        Ok(()) => Ok(ManifestCommit::Durable),
        Err(crate::config::atomic_write::AtomicWriteError::Fsync {
            path: failed_path, ..
        }) if failed_path == path.parent().unwrap_or_else(|| Path::new("."))
            && file_matches_content(path, content) =>
        {
            Ok(ManifestCommit::DurabilityUncertain)
        }
        Err(error) => Err(std::io::Error::other(error)),
    }
}

fn file_matches_content(path: &Path, content: &[u8]) -> bool {
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let Ok(actual_len) = file.metadata().and_then(|meta| {
        usize::try_from(meta.len()).map_err(|_| std::io::Error::other("file too large"))
    }) else {
        return false;
    };
    if actual_len != content.len() {
        return false;
    }
    let mut reader = std::io::BufReader::with_capacity(SPILL_WRITE_BUF, file);
    let mut buffer = [0u8; 64 * 1024];
    let mut offset = 0;
    while offset < content.len() {
        let want = (content.len() - offset).min(buffer.len());
        let Ok(read) = reader.read(&mut buffer[..want]) else {
            return false;
        };
        if read == 0 || buffer[..read] != content[offset..offset + read] {
            return false;
        }
        offset += read;
    }
    true
}

fn write_cache_manifest(path: &Path, content: &[u8]) -> std::io::Result<ManifestCommit> {
    #[cfg(test)]
    if FAIL_NEXT_CACHE_MANIFEST_WRITE.with(|fail| fail.replace(false))
        || fail_cache_manifest_write_for_test()
    {
        return Err(std::io::Error::other(
            "injected cache manifest write failure",
        ));
    }
    atomic_write_confirmed(path, content)
}

/// Generation bodies are never reread into RAM to resolve an ambiguous
/// post-rename error; length and digest are checked through a bounded reader.
fn atomic_write_body_confirmed(
    path: &Path,
    content: &[u8],
    expected_len: usize,
    expected_digest: [u8; 32],
) -> std::io::Result<()> {
    match atomic_write(path, content) {
        Ok(()) => Ok(()),
        Err(_error) if generation_body_matches(path, expected_len, expected_digest) => Ok(()),
        Err(error) => Err(std::io::Error::other(error)),
    }
}

fn generation_body_matches(path: &Path, expected_len: usize, expected_digest: [u8; 32]) -> bool {
    let Ok(file) = open_regular_generation_file(path) else {
        return false;
    };
    generation_file_matches(&file, expected_len, expected_digest).unwrap_or(false)
}

fn generation_file_matches(
    file: &std::fs::File,
    expected_len: usize,
    expected_digest: [u8; 32],
) -> std::io::Result<bool> {
    use sha2::Digest;

    ensure_regular_generation_file(file)?;
    let actual_len = usize::try_from(file.metadata()?.len())
        .map_err(|_| std::io::Error::other("body too large"))?;
    if actual_len != expected_len {
        return Ok(false);
    }
    let limit = expected_len
        .checked_add(1)
        .ok_or_else(|| std::io::Error::other("cache generation length overflow"))?;
    let limit = u64::try_from(limit)
        .map_err(|_| std::io::Error::other("cache generation length overflow"))?;
    let mut reader_file = file.try_clone()?;
    reader_file.seek(SeekFrom::Start(0))?;
    let mut reader = std::io::BufReader::with_capacity(SPILL_WRITE_BUF, reader_file.take(limit));
    let mut hasher = sha2::Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut bytes = 0usize;
    loop {
        cancellation::io_checkpoint("generation_hash")?;
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes = bytes
            .checked_add(read)
            .ok_or_else(|| std::io::Error::other("cache generation length overflow"))?;
        hasher.update(&buffer[..read]);
    }
    let actual_digest: [u8; 32] = hasher.finalize().into();
    Ok(bytes == expected_len && actual_digest == expected_digest)
}

fn garbage_collect_generation_bodies(cache_dir: &Path, stem: &str, selected: &str) {
    for path in generation_body_paths(cache_dir, stem) {
        if path.file_name().and_then(|name| name.to_str()) == Some(selected) {
            continue;
        }
        if let Err(error) = std::fs::remove_file(&path) {
            tracing::warn!(path = %path.display(), error = %error, "failed to remove obsolete list cache body");
        }
    }
}

fn remove_legacy_body(cache_dir: &Path, stem: &str) {
    let path = cache_dir.join(format!("{stem}.cache"));
    match std::fs::remove_file(&path) {
        Ok(()) => tracing::debug!(path = %path.display(), "removed retired legacy list cache body"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            tracing::warn!(path = %path.display(), error = %error, "failed to remove retired legacy list cache body")
        }
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

/// Build the `.meta` sidecar's plaintext content.
///
/// `size` is the selected body's byte length. Generation manifests record it
/// exactly; legacy metadata may omit it and retain compatibility behavior.
///
/// rev-2606 §06 `manager-04a`: `etag` / `last_modified` are
/// upstream-supplied and run through [`sanitize_meta_value`] so they
/// cannot inject extra `.meta` lines.
/// `resolved_url` remains exact because cache admission compares it byte for
/// byte; config and fetch URL validation reject userinfo before this writer.
fn build_meta_content(
    etag: Option<&str>,
    last_modified: Option<&str>,
    resolved_url: &str,
    fetched_at: OffsetDateTime,
    size: Option<usize>,
    manifest: Option<GenerationManifest<'_>>,
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
    let manifest_lines = manifest.map_or_else(String::new, |manifest| {
        format!("body={}\nsha256={}\n", manifest.body, manifest.sha256)
    });
    format!(
        "etag={}\nlast-modified={}\nresolved-url={}\nfetched-at={}\n{}{}",
        sanitize_meta_value(etag.unwrap_or("")),
        sanitize_meta_value(last_modified.unwrap_or("")),
        sanitize_meta_value(resolved_url),
        fetched_at_str,
        size_line,
        manifest_lines,
    )
}

/// Write only the `.meta` sidecar atomically. Used by the 304
/// branch of `refresh()` so a content-unchanged response can bump
/// `fetched-at` without rewriting the selected body file.
fn write_meta_file(
    meta_path: &Path,
    etag: Option<&str>,
    last_modified: Option<&str>,
    resolved_url: &str,
    fetched_at: OffsetDateTime,
    size: Option<usize>,
    manifest: Option<GenerationManifest<'_>>,
) -> std::io::Result<()> {
    let meta_content = build_meta_content(
        etag,
        last_modified,
        resolved_url,
        fetched_at,
        size,
        manifest,
    );
    write_cache_manifest(meta_path, meta_content.as_bytes()).map(|_| ())
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

/// Read a resident fallback HTTP body into a `String`, bounded by `max_bytes`.
///
/// Streams chunks from the response and tracks a running byte count; aborts
/// mid-stream with [`ListError::TooLarge`] as soon as the cap would be
/// exceeded. This closes the OOM primitive where a malicious server omits
/// `Content-Length` and sends unbounded bytes: `resp.text().await` would
/// have read to EOF, but this loop stops on the first chunk that crosses the
/// threshold.
///
/// This path is used only where a body cannot be safely staged. The cap limits
/// decoded input bytes; it is not a process-memory budget.
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

/// Turn a resident fallback body into a `String` **without copying it**
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

fn bounded_body_growth(current: usize, added: usize, max: usize) -> Result<usize, usize> {
    match current.checked_add(added) {
        Some(projected) if projected <= max => Ok(projected),
        Some(projected) => Err(projected),
        None => Err(usize::MAX),
    }
}

const RESIDENT_BODY_INITIAL_CAPACITY_MAX: usize = 1024 * 1024;

fn bounded_body_initial_capacity(content_length: Option<u64>, max: usize) -> usize {
    content_length
        .and_then(|length| usize::try_from(length).ok())
        .map_or(0, |length| {
            length.min(max).min(RESIDENT_BODY_INITIAL_CAPACITY_MAX)
        })
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
    // Use Content-Length only as a small allocation hint. The independent
    // hint cap prevents a dishonest header from forcing a cap-sized reserve.
    // The streaming guard remains the actual byte bound.
    let initial = bounded_body_initial_capacity(resp.content_length(), max_bytes);
    let mut body_bytes: Vec<u8> = Vec::with_capacity(initial);
    while let Some(chunk) = cancellation::wait(resp.chunk(), "http_chunk")
        .await?
        .map_err(|e| ListError::Download {
            url: url.to_string(),
            reason: classify_fetch_error(&e),
        })?
    {
        bounded_body_growth(body_bytes.len(), chunk.len(), max_bytes).map_err(|size| {
            ListError::TooLarge {
                url: url.to_string(),
                size,
                max: max_bytes,
            }
        })?;
        body_bytes.extend_from_slice(&chunk);
        cancellation::checkpoint("http_body_chunk")?;
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

/// Compatibility projection for callers without the selected catalog.
///
/// Manager construction uses [`ResolvedSourcePlan`](crate::lists::source_key::ResolvedSourcePlan).
/// This helper preserves first occurrence when a read-only caller needs a
/// fallback catalog projection.
pub fn merge_sources_with_blocklists(
    legacy: &[String],
    blocklists: &[crate::config::schema::Blocklist],
) -> (Vec<String>, SourceTrustMap) {
    let catalog = crate::lists::catalog::Catalog::fallback();
    let mut seen: HashSet<String> = HashSet::new();
    let mut catalog_legacy_ids = HashSet::new();
    let mut sources = Vec::new();
    for source in legacy {
        let catalog_url = catalog.resolve(source);
        let resolved = catalog_url.clone().unwrap_or_else(|| source.clone());
        if !crate::lists::source_key::is_url_source(source) && catalog_url.is_some() {
            if let Ok(id) = crate::config::schema::Id::new(source.replace('/', "-")) {
                catalog_legacy_ids.insert(id);
            }
        }
        if seen.insert(crate::lists::source_key::canonical_url_key(&resolved)) {
            sources.push(source.clone());
        }
    }
    let trust = SourceTrustMap::build(blocklists);
    for b in blocklists.iter().filter(|b| b.enabled) {
        if catalog_legacy_ids.contains(&b.id) {
            continue;
        }
        if !seen.insert(crate::lists::source_key::canonical_url_key(&b.url)) {
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
/// Compatibility wrapper for callers that only have source strings.
pub fn build_source_bit_map(sources: &[String]) -> Result<SourceBitMap, BitMapBuildError> {
    SourceBitMap::build(sources, &[])
}

/// Result of a single list download.
enum FetchResult {
    /// 200 OK candidate awaiting validation.
    Fresh(Box<FreshDownload>),
    /// 304 Not Modified — use cached body.
    NotModified,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RequestMode {
    Conditional,
    Unconditional,
}

struct FreshDownload {
    body: FreshBody,
    etag: Option<String>,
    last_modified: Option<String>,
}

/// A 200 body stays resident only when there is nowhere safe to stage it;
/// imported local bodies deliberately use this bridge.
enum FreshBody {
    Staged(StagedCacheBody),
    Resident(String),
}

impl FreshBody {
    fn open_reader(&self) -> std::io::Result<FreshBodyReader<'_>> {
        match self {
            Self::Staged(staged) => {
                let reader = staged.reader()?;
                #[cfg(test)]
                run_staged_cache_reader_constructed_hook_for_test();
                Ok(FreshBodyReader::Staged(reader))
            }
            Self::Resident(body) => Ok(FreshBodyReader::Resident(std::io::Cursor::new(
                body.as_bytes(),
            ))),
        }
    }

    fn staged(&self) -> Option<&StagedCacheBody> {
        match self {
            Self::Staged(staged) => Some(staged),
            Self::Resident(_) => None,
        }
    }

    /// Produce the existing content-addressed stage or retain the explicitly
    /// resident body. Imported local sources take the latter branch.
    fn into_cache_admission(
        self,
        cache_dir: Option<&Path>,
        source: &str,
    ) -> std::io::Result<(Option<StagedCacheBody>, Option<String>)> {
        match self {
            Self::Staged(staged) => Ok((Some(staged), None)),
            Self::Resident(body) => match cache_dir {
                Some(cache_dir) => {
                    stage_cache_body(cache_dir, source, &body).map(|staged| (Some(staged), None))
                }
                None => Ok((None, Some(body))),
            },
        }
    }
}

enum FreshBodyReader<'a> {
    Staged(std::io::BufReader<std::io::Take<std::fs::File>>),
    Resident(std::io::Cursor<&'a [u8]>),
}

impl Read for FreshBodyReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Staged(reader) => reader.read(buf),
            Self::Resident(reader) => reader.read(buf),
        }
    }
}

impl BufRead for FreshBodyReader<'_> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        match self {
            Self::Staged(reader) => reader.fill_buf(),
            Self::Resident(reader) => reader.fill_buf(),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self {
            Self::Staged(reader) => reader.consume(amt),
            Self::Resident(reader) => reader.consume(amt),
        }
    }
}

/// A 304 can validate only the cache representation named by a request
/// validator. An unconditional 304 is malformed and carries no cache trust.
fn not_modified_is_admissible(sent_conditional_validator: bool) -> bool {
    sent_conditional_validator
}

/// rev-2606 §06 `manager-01`: pure decision core of the retention guard,
/// split out of [`ListManager::shrink_verdict`] so it is unit-testable
/// without constructing a manager.
///
/// Baseline is the prior `unique_domains`, falling back to the persisted
/// `prev_entries` when no unique baseline exists (a v1→v2 upgrade or a
/// source that only ever recorded the merged-map delta), capped at this
/// source's current effective entry limit. No baseline → unconditional
/// accept (first fetch of a brand-new source must never be bricked). Guard
/// disabled → unconditional accept.
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
    max_entries: usize,
) -> ShrinkVerdict {
    if !enabled {
        return ShrinkVerdict::Accept { delta_warn: None };
    }
    let cap = u64::try_from(max_entries).unwrap_or(u64::MAX);
    let baseline = prev.and_then(|p| {
        if p.unique_domains > 0 {
            Some(p.unique_domains.min(cap))
        } else {
            p.prev_entries
                .map(|entries| entries.min(cap))
                .filter(|&n| n > 0)
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
/// the `CacheOnly`-vs-scheduled distinction is not cosmetic: it is what
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
        RefreshMode::Scheduled => "list not due, reusing retained cache",
        RefreshMode::Force => "list forced, reusing retained cache",
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
///   shouldn't OOM the daemon either). Metadata and bounded reading use one
///   opened handle, so replacement or growth between them cannot bypass it.
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

    let mut file = match std::fs::File::open(&on_disk) {
        Ok(file) => file,
        Err(e) => {
            return LocalBridgeOutcome::Refused(format!(
                "imported-local list file {} not readable: {e}",
                on_disk.display()
            ));
        }
    };

    let metadata = match file.metadata() {
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

    #[cfg(test)]
    run_imported_local_after_metadata_hook_for_test();

    // Read at most one byte past the cap. The metadata check rejects a
    // known-oversized file cheaply, while this loop closes the growth race
    // without ever reading or allocating an unbounded body. Turning the Vec
    // into a String moves its allocation on valid UTF-8, so no second whole
    // body is kept beyond the returned String.
    let initial_capacity = usize::try_from(metadata.len())
        .unwrap_or(max_body_bytes)
        .min(max_body_bytes);
    let mut bytes = Vec::with_capacity(initial_capacity);
    let mut chunk = [0_u8; 8 * 1024];
    loop {
        if cancellation::checkpoint("local_read").is_err() {
            return LocalBridgeOutcome::Refused(Cancelled.to_string());
        }
        let remaining = max_body_bytes.saturating_sub(bytes.len());
        // Once at the cap, ask for exactly one more byte to distinguish an
        // exact-cap body from a body that grew after metadata was sampled.
        let read_len = if remaining == 0 {
            1
        } else {
            remaining.min(chunk.len())
        };
        let read = match file.read(&mut chunk[..read_len]) {
            Ok(read) => read,
            Err(e) => {
                return LocalBridgeOutcome::Refused(format!(
                    "imported-local list file {} read failed: {e}",
                    on_disk.display()
                ));
            }
        };
        if read == 0 {
            break;
        }

        if let Err(size) = bounded_body_growth(bytes.len(), read, max_body_bytes) {
            return LocalBridgeOutcome::Refused(format!(
                "imported-local list file {} is {size} bytes (max {max_body_bytes} bytes)",
                on_disk.display()
            ));
        }
        bytes.extend_from_slice(&chunk[..read]);
    }

    match String::from_utf8(bytes) {
        Ok(body) => LocalBridgeOutcome::Loaded {
            body,
            path: on_disk,
        },
        Err(e) => LocalBridgeOutcome::Refused(format!(
            "imported-local list file {} read failed: invalid UTF-8 ({})",
            on_disk.display(),
            e.utf8_error()
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

/// Whether a URL is the synthetic local-import sentinel.
fn is_imported_local_url(url: &str) -> bool {
    reqwest::Url::parse(url)
        .ok()
        .is_some_and(|parsed| parsed.host_str() == Some(IMPORTED_LOCAL_HOST))
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

enum QueuedManagerWork {
    Force {
        completions: Vec<oneshot::Sender<ForceRefreshCompletion>>,
    },
    Forget {
        source: String,
        completion: oneshot::Sender<bool>,
    },
}

enum ActiveManagerWork {
    Scheduled,
    Force {
        completions: Vec<oneshot::Sender<ForceRefreshCompletion>>,
    },
}

struct ActiveRefresh {
    work: ActiveManagerWork,
    join: tokio::task::JoinHandle<RefreshWorkerOutcome>,
    cancellation: RefreshCancellation,
    registry: Arc<ListStatusRegistry>,
    seq_at_start: u64,
}

fn start_refresh_worker(manager: ListManager, mode: RefreshMode) -> ActiveRefresh {
    let work = match mode {
        RefreshMode::Scheduled => ActiveManagerWork::Scheduled,
        RefreshMode::Force => ActiveManagerWork::Force {
            completions: Vec::new(),
        },
        RefreshMode::CacheOnly => unreachable!("cache-only boot stays outside the controller"),
    };
    let registry = manager.status_registry();
    let seq_at_start = registry.cycle().seq;
    let cancellation = RefreshCancellation::default();
    let join = spawn_list_refresh_worker(manager, mode, cancellation.clone());
    ActiveRefresh {
        work,
        join,
        cancellation,
        registry,
        seq_at_start,
    }
}

enum RefreshWorkerOutcome {
    Completed {
        manager: ListManager,
        completion: RefreshCompletion,
    },
    Cancelled {
        manager: ListManager,
    },
}

fn spawn_list_refresh_worker(
    mut manager: ListManager,
    mode: RefreshMode,
    cancellation: RefreshCancellation,
) -> tokio::task::JoinHandle<RefreshWorkerOutcome> {
    #[cfg(test)]
    if let Some(hook) = manager.worker_hook.take() {
        cancellation.set_hook(hook);
    }
    let runtime = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        runtime.block_on(cancellation.scope(async move {
            let result = manager
                .refresh_at_with_mode_completion(OffsetDateTime::now_utc(), mode)
                .await;
            match result {
                Ok(completion) => {
                    // A completed snapshot can precede return to the controller.
                    cancellation::checkpoint("worker_return")
                        .expect("completed commit is not cancellable");
                    RefreshWorkerOutcome::Completed {
                        manager,
                        completion,
                    }
                }
                Err(Cancelled) => RefreshWorkerOutcome::Cancelled { manager },
            }
        }))
    })
}

fn accept_while_active(
    cmd: ListManagerCommand,
    active: &mut ActiveRefresh,
    queued: &mut std::collections::VecDeque<QueuedManagerWork>,
) {
    match cmd {
        ListManagerCommand::Forget {
            source,
            accepted,
            completion,
        } => {
            let _ = accepted.send(ListManagerCommandDisposition::Queued);
            queued.push_back(QueuedManagerWork::Forget { source, completion });
        }
        ListManagerCommand::ForceRefresh {
            accepted,
            completion,
        } => {
            if matches!(active.work, ActiveManagerWork::Force { .. })
                && queued.is_empty()
                && active.registry.cycle().seq == active.seq_at_start
            {
                let _ = accepted.send(ListManagerCommandDisposition::JoinedInFlight);
                let ActiveManagerWork::Force { completions } = &mut active.work else {
                    unreachable!();
                };
                completions.push(completion);
            } else if let Some(QueuedManagerWork::Force { completions }) = queued.back_mut() {
                let _ = accepted.send(ListManagerCommandDisposition::CoalescedQueued);
                completions.push(completion);
            } else {
                let _ = accepted.send(ListManagerCommandDisposition::Queued);
                queued.push_back(QueuedManagerWork::Force {
                    completions: vec![completion],
                });
            }
        }
    }
}

fn accept_when_idle(
    cmd: ListManagerCommand,
    manager: &mut ListManager,
) -> Option<QueuedManagerWork> {
    match cmd {
        ListManagerCommand::Forget {
            source,
            accepted,
            completion,
        } => {
            let _ = accepted.send(ListManagerCommandDisposition::Started);
            let _ = completion.send(manager.forget_source(&source));
            None
        }
        ListManagerCommand::ForceRefresh {
            accepted,
            completion,
        } => {
            let _ = accepted.send(ListManagerCommandDisposition::Started);
            Some(QueuedManagerWork::Force {
                completions: vec![completion],
            })
        }
    }
}

fn drop_command_intake(mut rx: mpsc::Receiver<ListManagerCommand>) {
    use std::task::{Context, Poll, Waker};

    rx.close();
    // Unlike try_recv on our Tokio version, poll_recv accounts for permits
    // still held by senders and never blocks on a send in progress.
    let mut context = Context::from_waker(Waker::noop());
    loop {
        match rx.poll_recv(&mut context) {
            Poll::Ready(Some(command)) => drop(command),
            Poll::Ready(None) => return,
            Poll::Pending => break,
        }
    }
    // Tokio permits can send after receiver drop, stranding their responders
    // behind a stale sender. Only pre-close reservations can reach this sink;
    // it owns no manager and retirement never waits for those callers.
    tokio::spawn(async move {
        while let Some(command) = rx.recv().await {
            drop(command);
        }
    });
}

/// Controller side of [`ListManager::spawn_refresh_loop`].
///
/// A worker panic is terminal. We intentionally drop all outstanding
/// completion senders instead of returning guessed cache or registry state.
async fn list_manager_controller(
    manager: ListManager,
    mut cmd_rx: Option<mpsc::Receiver<ListManagerCommand>>,
    mut retire_rx: oneshot::Receiver<()>,
    mut next_deadline: tokio::time::Instant,
) {
    let mut manager = Some(manager);
    let mut active: Option<ActiveRefresh> = None;
    let mut queued = std::collections::VecDeque::new();
    let mut retiring = false;
    loop {
        // Check before dispatching queued work as well as in select: a ready
        // worker must not let a retirement request lose to its next Force.
        if !retiring
            && !matches!(
                retire_rx.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            )
        {
            retiring = true;
        }
        if retiring {
            if let Some(rx) = cmd_rx.take() {
                drop_command_intake(rx);
            }
            queued.clear();
            if let Some(worker) = &active {
                worker.cancellation.cancel();
            } else {
                return;
            }
        }
        if let Some(active_refresh) = active.as_mut() {
            tokio::select! {
                biased;
                _ = &mut retire_rx, if !retiring => { retiring = true; }
                result = &mut active_refresh.join => {
                    let active_refresh = active.take().expect("active worker must still exist");
                    match result {
                        Ok(RefreshWorkerOutcome::Completed { manager: returned, completion: refresh_completion }) => {
                            if let ActiveManagerWork::Force { completions } = active_refresh.work {
                                for responder in completions {
                                    let _ = responder.send(ForceRefreshCompletion {
                                        snapshot: refresh_completion.snapshot.clone(),
                                        max_total_domains: Some(returned.max_total_domains.unwrap_or(0)),
                                    });
                                }
                            }
                            manager = Some(returned);
                            tracing::debug!(count = refresh_completion.domain_count, "list refresh worker completed");
                            next_deadline = tokio::time::Instant::now()
                                + manager.as_ref().expect("worker returned manager")
                                    .next_loop_wait(OffsetDateTime::now_utc());
                        }
                        Ok(RefreshWorkerOutcome::Cancelled { manager: returned }) => {
                            manager = Some(returned);
                        }
                        Err(error) => {
                            // The controller cannot safely continue without
                            // its exclusively-owned manager. Panic here so
                            // ListManagerTask::retire surfaces the worker
                            // JoinError instead of treating it as a normal
                            // completed retirement.
                            tracing::error!(%error, "list refresh worker ended abnormally; failing manager controller");
                            panic!("list refresh worker ended abnormally: {error}");
                        }
                    }
                }
                command = recv_or_pending(&mut cmd_rx), if !retiring => {
                    match command {
                        Some(command) => accept_while_active(
                            command,
                            active_refresh,
                            &mut queued,
                        ),
                        None => cmd_rx = None,
                    }
                }
            }
            continue;
        }

        if let Some(work) = queued.pop_front() {
            match work {
                QueuedManagerWork::Forget { source, completion } => {
                    let was_cached = manager
                        .as_mut()
                        .expect("idle manager")
                        .forget_source(&source);
                    let _ = completion.send(was_cached);
                }
                QueuedManagerWork::Force { completions } => {
                    let mut worker = start_refresh_worker(
                        manager.take().expect("idle manager"),
                        RefreshMode::Force,
                    );
                    let ActiveManagerWork::Force {
                        completions: worker_completions,
                    } = &mut worker.work
                    else {
                        unreachable!();
                    };
                    worker_completions.extend(completions);
                    active = Some(worker);
                }
            }
            continue;
        }

        tokio::select! {
            biased;
            _ = &mut retire_rx, if !retiring => { retiring = true; }
            _ = tokio::time::sleep_until(next_deadline) => {
                tracing::info!("scheduled list update starting");
                active = Some(start_refresh_worker(
                    manager.take().expect("idle manager"),
                    RefreshMode::Scheduled,
                ));
            }
            command = recv_or_pending(&mut cmd_rx), if !retiring => {
                match command {
                    Some(command) => {
                        if let Some(work) = accept_when_idle(command, manager.as_mut().expect("idle manager")) {
                            let QueuedManagerWork::Force { completions } = work else { unreachable!(); };
                            let mut worker = start_refresh_worker(
                                manager.take().expect("idle manager"),
                                RefreshMode::Force,
                            );
                            let ActiveManagerWork::Force { completions: worker_completions } = &mut worker.work else { unreachable!(); };
                            worker_completions.extend(completions);
                            active = Some(worker);
                        }
                    }
                    None => cmd_rx = None,
                }
            }
        }
    }
}

/// Receive from an optional command channel, or park forever if the manager
/// was started without one. Both branches are cancellation-safe in `select!`.
async fn recv_or_pending(
    rx: &mut Option<mpsc::Receiver<ListManagerCommand>>,
) -> Option<ListManagerCommand> {
    match rx {
        Some(receiver) => receiver.recv().await,
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
    #[error(transparent)]
    Cancelled(#[from] Cancelled),
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
// `refresh()` partitions accepted rows into disk-backed shard spills rather
// than materialising one flat full-corpus map. That avoids a full second
// generation, but peak memory remains input-dependent: raw duplicates,
// domain payloads, allocator retention and retained readers all matter.
//
//   pass 1  stream each source once, route every accepted domain to the
//           spill for `FilterEngine::shard_index(domain)` — one line plus
//           16 write buffers resident, never a map;
//   pass 2  per shard: read its spill, build ~1/16 of a generation,
//           `swap_shard`, let the displaced shard drop, move on.
//
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

/// Walk one sealed spill reader's records, handing each `(domain, bit)` to
/// `f` in write order.
///
/// Shared by [`ShardSpill::count_unique`] and [`ShardSpill::build_shard`]
/// so the two cannot drift on the record format. That matters more than
/// ordinary de-duplication here: the counting pass decides whether a
/// corpus is installed at all and the build pass then materialises it, so
/// a decoder that disagreed by even one record would let the daemon refuse
/// a corpus it could have served, or install one that was cleared under a
/// different count.
fn read_spill_records(
    reader: &mut impl Read,
    mut f: impl FnMut(&str, u64) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let mut bit = None;
    let mut len = [0u8; 1];
    let mut domain = [0u8; SPILL_BIT_TAG as usize];
    loop {
        cancellation::io_checkpoint("spill_read")?;
        match reader.read_exact(&mut len) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
        if len[0] == SPILL_BIT_TAG {
            let mut raw = [0u8; 8];
            reader.read_exact(&mut raw)?;
            let next_bit = u64::from_le_bytes(raw);
            if next_bit == 0 || !next_bit.is_power_of_two() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "shard spill bit tag is zero or not one-hot",
                ));
            }
            bit = Some(next_bit);
            continue;
        }
        let n = len[0] as usize;
        reader.read_exact(&mut domain[..n])?;
        // Written from a `&str`, so this is UTF-8 by construction; a
        // corrupt spill is a bug in this file, not untrusted input, hence
        // the explicit error rather than a lossy conversion.
        let s = std::str::from_utf8(&domain[..n]).map_err(std::io::Error::other)?;
        let bit = bit.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "shard spill domain appeared before a bit tag",
            )
        })?;
        f(s, bit)?;
    }
    Ok(())
}

fn validate_spill_record(idx: usize, domain: &str, bit: u64) -> std::io::Result<()> {
    cancellation::io_checkpoint("spill_validate")?;
    if bit == 0 || !bit.is_power_of_two() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "shard spill bit is zero or not one-hot",
        ));
    }
    if !is_valid_domain(domain) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "shard spill has an invalid domain",
        ));
    }
    if FilterEngine::shard_index(domain) != idx {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "shard spill domain is routed to the wrong shard",
        ));
    }
    Ok(())
}

fn validate_spill_records(idx: usize, reader: &mut impl Read) -> std::io::Result<()> {
    read_spill_records(reader, |domain, bit| {
        #[cfg(test)]
        if fail_shard_spill_validation_read_for_test() {
            return Err(std::io::Error::other(
                "injected shard spill validation-read failure",
            ));
        }
        validate_spill_record(idx, domain, bit)
    })
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
    /// Start of the final domain record for the exact-boundary regression
    /// hook.
    #[cfg(test)]
    last_domain_start: Option<u64>,
}

/// Names the transaction boundary used by rollback fault-injection tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SpillRollbackSite {
    FreshParse,
    RetainedParse,
    FreshRetentionGuard,
    FreshCacheAdmission,
    RetryCacheAdmission,
    RetryRetentionGuard,
    FreshReaderOpen,
    FreshVerification,
    RetainedVerification,
    #[cfg(test)]
    DirectTest,
}

/// Where the partition pass routes accepted domains.
enum ShardSpill {
    /// Disk-backed — the configuration that reaches the §11 T3 target.
    Disk {
        dir: PathBuf,
        writers: Vec<SpillWriter>,
        /// Readers opened and validated before any shard may publish. They
        /// pin the validated filesystem objects through the build pass.
        readers: Option<Vec<Option<std::io::BufReader<std::fs::File>>>>,
        poisoned: bool,
    },
    /// The documented `cache_dir: None` mode. 16 packed
    /// `Vec<(CompactString, u64)>` keep the whole pre-dedup corpus resident.
    /// Correct, but not low-peak.
    Memory {
        buckets: Vec<Vec<(CompactString, u64)>>,
        poisoned: bool,
    },
}

struct BuiltShard {
    shard: SortedShard,
    added_by_bit: [u64; 64],
    #[cfg(test)]
    shape: ShardBuildShape,
}

/// Allocation shape captured immediately before a raw shard is sorted and
/// deduplicated. Test-only so the production builder has no telemetry path.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ShardBuildShape {
    raw_rows: usize,
    raw_capacity: usize,
    previous_capacity: Option<usize>,
    raw_heap_capacity: usize,
}

impl BuiltShard {
    #[cfg(test)]
    fn merge_added_by_bit(self, aggregate: &mut [u64; 64]) -> SortedShard {
        for (aggregate, added) in aggregate.iter_mut().zip(self.added_by_bit) {
            *aggregate += added;
        }
        self.shard
    }
}

impl ShardSpill {
    /// Open a spill for this cycle. Memory mode is an explicit
    /// `cache_dir: None` configuration; disk setup failures refuse the cycle.
    fn open(cache_dir: Option<&Path>) -> std::io::Result<Self> {
        let Some(cache_dir) = cache_dir else {
            return Ok(Self::memory());
        };
        let dir = cache_dir.join(SHARD_SPILL_DIR);
        #[cfg(test)]
        if fail_shard_spill_dir_create_for_test() {
            return Err(std::io::Error::other(
                "injected shard spill directory creation failure",
            ));
        }
        std::fs::create_dir_all(&dir)?;
        let mut writers = Vec::with_capacity(DOMAIN_SHARDS);
        for idx in 0..DOMAIN_SHARDS {
            let path = dir.join(spill_file_name(idx));
            #[cfg(test)]
            let file = if fail_shard_spill_file_create_for_test() {
                Err(std::io::Error::other(
                    "injected shard spill file creation failure",
                ))
            } else {
                std::fs::File::create(&path)
            };
            #[cfg(not(test))]
            let file = std::fs::File::create(&path);
            match file {
                Ok(file) => writers.push(SpillWriter {
                    file: std::io::BufWriter::with_capacity(SPILL_WRITE_BUF, file),
                    written: 0,
                    last_bit: None,
                    #[cfg(test)]
                    last_domain_start: None,
                }),
                Err(e) => {
                    drop(writers);
                    purge_shard_spill(cache_dir);
                    return Err(e);
                }
            }
        }
        Ok(Self::Disk {
            dir,
            writers,
            readers: None,
            poisoned: false,
        })
    }

    fn memory() -> Self {
        Self::Memory {
            buckets: (0..DOMAIN_SHARDS).map(|_| Vec::new()).collect(),
            poisoned: false,
        }
    }

    fn poisoned_error() -> std::io::Error {
        std::io::Error::other("shard spill is poisoned by an earlier storage failure")
    }

    fn is_poisoned(&self) -> bool {
        match self {
            Self::Disk { poisoned, .. } | Self::Memory { poisoned, .. } => *poisoned,
        }
    }

    fn poison(&mut self) {
        match self {
            Self::Disk { poisoned, .. } | Self::Memory { poisoned, .. } => *poisoned = true,
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
            Self::Memory { buckets, .. } => buckets.iter().map(|b| b.len() as u64).collect(),
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
    fn rollback(&mut self, mark: &[u64], site: SpillRollbackSite) -> std::io::Result<()> {
        #[cfg(test)]
        if fail_shard_spill_rollback_for_test(site) {
            self.poison();
            return Err(std::io::Error::other(
                "injected shard spill rollback failure",
            ));
        }
        #[cfg(not(test))]
        let _ = site;
        let result = (|| {
            match self {
                Self::Disk { writers, .. } => {
                    for (w, &offset) in writers.iter_mut().zip(mark) {
                        w.file.flush()?;
                        let f = w.file.get_mut();
                        #[cfg(test)]
                        if fail_shard_spill_rollback_truncate_for_test() {
                            Err(std::io::Error::other(
                                "injected shard spill rollback truncate failure",
                            ))?;
                        }
                        f.set_len(offset)?;
                        // `set_len` truncates but leaves the cursor where it
                        // was; without the seek the next write would open a
                        // hole of zero bytes past the truncation point.
                        #[cfg(test)]
                        if fail_shard_spill_rollback_seek_for_test() {
                            Err(std::io::Error::other(
                                "injected shard spill rollback seek failure",
                            ))?;
                        }
                        f.seek(std::io::SeekFrom::Start(offset))?;
                        w.written = offset;
                        // The bit-change record for the rolled-back source may
                        // itself be gone; forget it so the next source re-emits.
                        w.last_bit = None;
                        #[cfg(test)]
                        {
                            w.last_domain_start = None;
                        }
                    }
                }
                Self::Memory { buckets, .. } => {
                    for (b, &len) in buckets.iter_mut().zip(mark) {
                        b.truncate(len as usize);
                    }
                }
            }
            Ok(())
        })();
        if result.is_err() {
            self.poison();
        }
        result
    }

    /// Route one accepted domain to its shard.
    ///
    /// The shard is chosen by [`FilterEngine::shard_index`] and nothing
    /// else — the engine probes with the same function, and any second
    /// implementation of `hash % 16` would disagree with it silently.
    fn push(&mut self, domain: &str, bit: u64) -> std::io::Result<()> {
        if self.is_poisoned() {
            return Err(Self::poisoned_error());
        }
        #[cfg(test)]
        if fail_shard_spill_write_for_test() {
            self.poison();
            return Err(std::io::Error::other("injected shard spill write failure"));
        }
        let idx = FilterEngine::shard_index(domain);
        let result = (|| {
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
                    #[cfg(test)]
                    {
                        w.last_domain_start = Some(w.written);
                    }
                    w.file.write_all(&[bytes.len() as u8])?;
                    w.file.write_all(bytes)?;
                    w.written += 1 + bytes.len() as u64;
                }
                Self::Memory { buckets, .. } => {
                    buckets[idx].push((CompactString::new(domain), bit));
                }
            }
            Ok(())
        })();
        if result.is_err() {
            self.poison();
        }
        result
    }

    /// Flush every write buffer. Must run once between the two passes —
    /// pass 2 reopens the files for reading.
    fn flush(&mut self) -> std::io::Result<()> {
        if self.is_poisoned() {
            return Err(Self::poisoned_error());
        }
        #[cfg(test)]
        if fail_shard_spill_flush_for_test() {
            self.poison();
            return Err(std::io::Error::other("injected shard spill flush failure"));
        }
        let result = (|| {
            if let Self::Disk { writers, .. } = self {
                for w in writers {
                    cancellation::io_checkpoint("spill_flush")?;
                    w.file.flush()?;
                    #[cfg(test)]
                    if fail_shard_spill_sync_for_test() {
                        Err(std::io::Error::other("injected shard spill sync failure"))?;
                    }
                    w.file.get_ref().sync_data()?;
                }
            }
            Ok(())
        })();
        if result.is_err() {
            self.poison();
        }
        result
    }

    /// Seal every shard before any counting or publication. Disk readers are
    /// retained so later path replacement cannot change what build consumes.
    fn prepare_validate(&mut self) -> std::io::Result<()> {
        if self.is_poisoned() {
            return Err(Self::poisoned_error());
        }
        let result = (|| match self {
            Self::Disk {
                dir,
                writers,
                readers,
                ..
            } => {
                #[cfg(test)]
                if take_truncate_final_shard_spill_record_before_validate_for_test() {
                    let writer = writers
                        .iter_mut()
                        .find(|writer| writer.last_domain_start.is_some())
                        .ok_or_else(|| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "cannot truncate an empty shard spill",
                            )
                        })?;
                    writer
                        .file
                        .get_mut()
                        .set_len(writer.last_domain_start.unwrap())?;
                }

                let mut sealed = Vec::with_capacity(DOMAIN_SHARDS);
                for (idx, writer) in writers.iter().enumerate() {
                    let file = std::fs::File::open(dir.join(spill_file_name(idx)))?;
                    let actual = file.metadata()?.len();
                    if actual != writer.written {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!(
                                "shard spill extent mismatch for shard {idx}: expected {}, found {actual}",
                                writer.written
                            ),
                        ));
                    }
                    let mut reader = std::io::BufReader::with_capacity(SPILL_WRITE_BUF, file);
                    validate_spill_records(idx, &mut reader)?;
                    reader.rewind()?;
                    sealed.push(Some(reader));
                }
                *readers = Some(sealed);
                Ok(())
            }
            Self::Memory { buckets, .. } => {
                for (idx, bucket) in buckets.iter().enumerate() {
                    for (domain, bit) in bucket {
                        validate_spill_record(idx, domain, *bit)?;
                    }
                }
                Ok(())
            }
        })();
        if result.is_err() {
            self.poison();
        }
        result
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
    /// The sealed reader is rewound after this pass, then build consumes the
    /// same validated handle. `novel_by_bit` is separate from build's
    /// `added_by_bit`, which feeds each source's reported `entries`.
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
    fn count_unique(&mut self, idx: usize, novel_by_bit: &mut [u64; 64]) -> std::io::Result<u64> {
        if self.is_poisoned() {
            return Err(Self::poisoned_error());
        }
        let result = (|| {
            #[cfg(test)]
            if fail_shard_spill_guard_count_for_test() {
                return Err(std::io::Error::other(
                    "injected shard spill guard-count failure",
                ));
            }
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
                Self::Disk { dir, readers, .. } => {
                    if let Some(readers) = readers {
                        let reader =
                            readers
                                .get_mut(idx)
                                .and_then(Option::as_mut)
                                .ok_or_else(|| {
                                    std::io::Error::new(
                                        std::io::ErrorKind::InvalidInput,
                                        "invalid shard index",
                                    )
                                })?;
                        read_spill_records(reader, |s, bit| {
                            observe(s, bit, &mut seen);
                            Ok(())
                        })?;
                        reader.rewind()?;
                    } else {
                        // Direct spill unit tests may exercise counting without
                        // the refresh barrier; production never takes this arm.
                        let file = std::fs::File::open(dir.join(spill_file_name(idx)))?;
                        let mut reader = std::io::BufReader::with_capacity(SPILL_WRITE_BUF, file);
                        read_spill_records(&mut reader, |s, bit| {
                            observe(s, bit, &mut seen);
                            Ok(())
                        })?;
                    }
                }
                Self::Memory { buckets, .. } => {
                    let bucket = buckets.get(idx).ok_or_else(|| {
                        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid shard index")
                    })?;
                    // Deliberately by reference, never `mem::take`.
                    for (domain, bit) in bucket {
                        cancellation::io_checkpoint("spill_count")?;
                        observe(domain, *bit, &mut seen);
                    }
                }
            }

            Ok(seen.len() as u64)
        })();
        if result.is_err() {
            self.poison();
        }
        result
    }

    fn rewind_shard(&mut self, idx: usize) -> std::io::Result<()> {
        if self.is_poisoned() {
            return Err(Self::poisoned_error());
        }
        match self {
            Self::Disk { readers, .. } => readers
                .as_mut()
                .and_then(|readers| readers.get_mut(idx))
                .and_then(Option::as_mut)
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid shard index")
                })?
                .rewind(),
            Self::Memory { buckets, .. } => buckets.get(idx).map(|_| ()).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid shard index")
            }),
        }
    }

    fn release_after_swap(&mut self, idx: usize) {
        match self {
            Self::Disk { dir, readers, .. } => {
                if let Some(reader) = readers.as_mut().and_then(|readers| readers.get_mut(idx)) {
                    *reader = None;
                }
                let path = dir.join(spill_file_name(idx));
                if let Err(error) = std::fs::remove_file(&path) {
                    tracing::warn!(path = %path.display(), %error, "failed to remove consumed shard spill");
                }
            }
            Self::Memory { buckets, .. } => {
                if let Some(bucket) = buckets.get_mut(idx) {
                    *bucket = Vec::new();
                }
            }
        }
    }

    /// Build shard `idx`'s slice of the new generation and hand it over.
    ///
    /// The returned `added_by_bit` counts, per list bit, the domains
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
        policy: &Arc<ListPolicy>,
    ) -> std::io::Result<BuiltShard> {
        if self.is_poisoned() {
            return Err(Self::poisoned_error());
        }
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
        #[cfg(test)]
        let mut previous_capacity = None;
        let mut raw = match self {
            Self::Disk { dir, readers, .. } => {
                let mut raw = Vec::with_capacity(capacity);
                if let Some(readers) = readers {
                    let reader =
                        readers
                            .get_mut(idx)
                            .and_then(Option::as_mut)
                            .ok_or_else(|| {
                                std::io::Error::new(
                                    std::io::ErrorKind::InvalidInput,
                                    "invalid shard index",
                                )
                            })?;
                    read_spill_records(reader, |s, bit| {
                        #[cfg(test)]
                        let capacity_before_push = raw.capacity();
                        raw.push((CompactString::new(s), bit));
                        #[cfg(test)]
                        if raw.capacity() != capacity_before_push {
                            previous_capacity = Some(capacity_before_push);
                        }
                        Ok(())
                    })?;
                } else {
                    // Kept for direct spill unit tests; refresh always builds
                    // through the sealed readers prepared above.
                    let path = dir.join(spill_file_name(idx));
                    let file = std::fs::File::open(&path)?;
                    let mut reader = std::io::BufReader::with_capacity(SPILL_WRITE_BUF, file);
                    read_spill_records(&mut reader, |s, bit| {
                        #[cfg(test)]
                        let capacity_before_push = raw.capacity();
                        raw.push((CompactString::new(s), bit));
                        #[cfg(test)]
                        if raw.capacity() != capacity_before_push {
                            previous_capacity = Some(capacity_before_push);
                        }
                        Ok(())
                    })?;
                }
                raw
            }
            Self::Memory { buckets, .. } => {
                // Keep the retained input bucket intact until its shard has
                // swapped. Cloning it is the one replay copy this mode
                // needs; unlike disk, do not also reserve `capacity` first.
                let bucket = buckets.get(idx).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid shard index")
                })?;
                let mut raw = Vec::with_capacity(bucket.len());
                for entry in bucket {
                    cancellation::io_checkpoint("spill_load")?;
                    #[cfg(test)]
                    let capacity_before_push = raw.capacity();
                    raw.push(entry.clone());
                    #[cfg(test)]
                    if raw.capacity() != capacity_before_push {
                        previous_capacity = Some(capacity_before_push);
                    }
                }
                raw
            }
        };

        #[cfg(test)]
        let shape = ShardBuildShape {
            raw_rows: raw.len(),
            raw_capacity: raw.capacity(),
            previous_capacity,
            raw_heap_capacity: raw
                .iter()
                .filter(|(domain, _)| domain.is_heap_allocated())
                .map(|(domain, _)| domain.capacity())
                .sum(),
        };

        // STABLE sort, load-bearing. `added_by_bit` credits a domain's FIRST
        // occurrence in spill order, and spill order is source-iteration
        // order, so the count must equal the `merged.len()` delta the flat
        // producer reported as that source's `entries`. `sort_by` preserves
        // the original order within a run of equal domains, so the run's
        // first element IS the first occurrence. `sort_unstable_by` is
        // faster, compiles, passes every type check — and silently credits
        // an arbitrary source. Do not "optimise" it.
        cancellation::io_checkpoint("before_sort")?;
        raw.sort_by(|a, b| a.0.cmp(&b.0));
        cancellation::io_checkpoint("after_sort")?;

        // Credit BETWEEN the sort and the dedup, and neither side is
        // arbitrary: after the OR-merge below the survivor carries every
        // source's bits, so "which bit first introduced this domain" is no
        // longer recoverable from it; before the sort the equal domains are
        // not yet adjacent, so a run start cannot be identified at all.
        let mut added_by_bit = [0u64; 64];
        for i in 0..raw.len() {
            cancellation::io_checkpoint("shard_count")?;
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

        #[cfg(test)]
        if fail_shard_build_for_test() {
            return Err(std::io::Error::other("injected shard build failure"));
        }

        cancellation::io_checkpoint("shard_built")?;
        let shard = SortedShard::from_sorted_entries(raw, Arc::clone(policy))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(BuiltShard {
            shard,
            added_by_bit,
            #[cfg(test)]
            shape,
        })
    }
}

/// Hard cap on a cold-start install that is over `max_total_domains`:
/// **twice** the operator's ceiling, as a `u128` so no configured value
/// can overflow the comparison.
///
/// Why 2×: this is a bounded entry-count exception for cold start, avoiding
/// an unfiltered daemon when no prior generation exists. It is not a memory
/// bound; accepted-input memory remains dependent on row shape and payloads.
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
    /// `max_total_domains` is disabled. Install whatever pass 2 builds.
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
/// Its allocation and rehash peak depend on the source's unique count and
/// allocator. A carried prior count is only a capacity hint, not a bound.
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
    /// The last count this source reported, bounded to the current effective
    /// cap before it becomes an allocation or retained-body baseline.
    fn prior(prev: Option<&ListStatus>, max_entries: usize) -> Option<std::num::NonZeroU64> {
        let cap = u64::try_from(max_entries).unwrap_or(u64::MAX);
        prev.and_then(|p| std::num::NonZeroU64::new(p.unique_domains.min(cap)))
    }

    /// For the 200-OK arm: always measure — the body is new, so no prior
    /// count describes it — but size the set from the prior count.
    fn measure(prev: Option<&ListStatus>, max_entries: usize) -> Self {
        Self::Measure(Self::prior(prev, max_entries))
    }

    /// For the arms that re-read an unchanged body. Falls back to
    /// measuring when there is no usable prior, so a first cycle after a
    /// restart-with-no-stats still produces a real baseline.
    fn carry_or_measure(prev: Option<&ListStatus>, max_entries: usize) -> Self {
        match Self::prior(prev, max_entries) {
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
    len: usize,
}

impl<R: BufRead> HashingReader<R> {
    fn new(inner: R) -> Self {
        use sha2::Digest;
        Self {
            inner,
            hasher: sha2::Sha256::new(),
            len: 0,
        }
    }

    fn finish(self) -> ([u8; 32], usize) {
        use sha2::Digest;
        (self.hasher.finalize().into(), self.len)
    }
}

impl<R: BufRead> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use sha2::Digest;
        cancellation::io_checkpoint("parse_read")?;
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        self.len = self.len.saturating_add(n);
        Ok(n)
    }
}

impl<R: BufRead> BufRead for HashingReader<R> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        cancellation::io_checkpoint("parse_read")?;
        self.inner
            .fill_buf()
            .map(|buf| &buf[..buf.len().min(8 * 1024)])
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
            self.len = self.len.saturating_add(n);
        }
        self.inner.consume(amt);
    }
}

/// A source body opened for streaming, with its origin retained for
/// failure-path retry-state stamping.
///
/// The in-memory arm exists because `cache_dir: None` is a supported
/// configuration in which bodies are held in RAM and there is no disk copy
/// to stream from.
enum BodyReader {
    Memory(std::io::Cursor<String>),
    RetainedCache {
        reader: std::io::BufReader<std::fs::File>,
        path: PathBuf,
        expected_sha256: Option<[u8; 32]>,
    },
}

impl BodyReader {
    fn retained_cache_path(&self) -> Option<&Path> {
        match self {
            Self::RetainedCache { path, .. } => Some(path),
            Self::Memory(_) => None,
        }
    }

    fn expected_sha256(&self) -> Option<[u8; 32]> {
        match self {
            Self::Memory(_) => None,
            Self::RetainedCache {
                expected_sha256, ..
            } => *expected_sha256,
        }
    }
}

impl Read for BodyReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Memory(c) => c.read(buf),
            Self::RetainedCache { reader, .. } => reader.read(buf),
        }
    }
}

impl BufRead for BodyReader {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        match self {
            Self::Memory(c) => c.fill_buf(),
            Self::RetainedCache { reader, .. } => reader.fill_buf(),
        }
    }
    fn consume(&mut self, amt: usize) {
        match self {
            Self::Memory(c) => c.consume(amt),
            Self::RetainedCache { reader, .. } => reader.consume(amt),
        }
    }
}

#[cfg(test)]
mod tests;
