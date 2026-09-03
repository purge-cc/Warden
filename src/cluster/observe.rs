//! Observability lift for cluster sync.
//!
//! A secondary CONVERGES on its primary, but without this the live state
//! was invisible: the poll loop's last-applied hashes / sync time / last error
//! lived only in [`super::poll::run`]'s task locals, and the primary DROPPED
//! every secondary's heartbeat stats. This module lifts both into ONE shared
//! handle the IPC `ClusterStatus` reader can consume without touching the
//! convergence path:
//!
//!   * **secondary** — [`SyncStatus`] in an [`ArcSwap`]; the poll loop
//!     write-throughs the whole struct at the END of each tick (success or
//!     failure). The reader is new; the convergence locals are unchanged.
//!   * **primary** — a bounded per-peer [`Roster`] behind a `Mutex` (the
//!     heartbeat handler is low-frequency and off the DNS hot path, so a lock
//!     is fine here, unlike the query path). Each heartbeat records the peer's
//!     stats + stamps `last_seen`, and piggybacks a `record_self` sample of the
//!     primary's own counters so the contribution-share denominator (Σ qps)
//!     includes the local node without a separate sampling task.
//!
//! Contribution weight is rate-based: `qps = Δtotal_queries / Δt` between a
//! node's two most recent samples; `share = qps / Σ(qps over online nodes)`.
//! `ClusterStats` carries only cumulative counters, so the delta is the only
//! way to express "current load", and it avoids the boot-uptime skew a
//! cumulative-total share would have. A node is `online` when its last sample
//! is within `stale_secs` (= 3 × `poll_interval_secs`, set at boot).
//!
//! Everything here is `cluster`-feature only (the whole module is gated at
//! [`crate::cluster`]); the default build never sees it.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

use arc_swap::ArcSwap;

use crate::config::schema::ClusterRole;

use super::dto::ClusterStats;
use super::state::ClusterState;

/// Max stored length (in characters) of a peer-advertised node name.
/// The label is display-only (roster / status views); clamping stops a peer from
/// pinning an arbitrarily long string in the bounded roster.
const MAX_NODE_NAME_LEN: usize = 64;

/// Truncate a peer-supplied node name to [`MAX_NODE_NAME_LEN`] characters,
/// respecting UTF-8 char boundaries (never splitting a multi-byte scalar).
fn clamp_node_name(name: String) -> String {
    if name.chars().count() <= MAX_NODE_NAME_LEN {
        return name;
    }
    name.chars().take(MAX_NODE_NAME_LEN).collect()
}

/// The secondary's lifted poll telemetry. Stored whole in an [`ArcSwap`]
/// and replaced at the end of every poll tick — readers always see a
/// self-consistent snapshot. Role + peer are boot identity and live on
/// [`ClusterObserve`], not here, so this is pure per-tick telemetry.
#[derive(Debug, Clone, Default)]
pub struct SyncStatus {
    /// Last-applied policy bundle content hash (`None` before the first sync).
    pub last_config_hash: Option<String>,
    /// When the most recent *successful* poll completed. Stays put across a
    /// failing tick so "last-sync age" reflects the last good sync, not the
    /// last attempt.
    pub last_sync: Option<Instant>,
    /// Whether the most recent tick succeeded.
    pub last_poll_ok: bool,
    /// The most recent tick's error (`None` after a success).
    pub last_error: Option<String>,
    /// True once at least one poll has succeeded since boot — distinguishes
    /// "never synced yet" from "synced, currently erroring".
    pub synced_at_least_once: bool,
}

/// A secondary's policy-sync health, in the three states a node must
/// be able to tell apart. **Two states are not enough**: with an age alone,
/// "never synced" and "synced a very long time ago" read identically, and the
/// remedy for them is different (the first needs a join/token, the second needs
/// the primary back).
///
/// **This is the SECONDARY axis only.** [`RosterRow::online`] is the *other*
/// staleness axis — a primary deciding whether a peer's heartbeat is recent
/// enough (`stale_secs`). They answer different questions on different nodes
/// and must not be unified.
///
/// **Why there is no age threshold here.** `Stale` is defined as *"the most
/// recent poll tick failed"*, not *"the last good sync is older than
/// `stale_secs`"*, and that is deliberate:
///
///  * every successful tick refreshes `last_sync`, so while polls succeed the
///    age cannot grow — the two definitions only ever disagree in one
///    direction, and
///  * the poll loop uses [`tokio::time::MissedTickBehavior::Skip`]; a slow but
///    *successful* poll can push the age past `3 × poll_interval_secs` with
///    nothing wrong, which an age-based rule would report as a fault and then
///    flap on.
///
/// One definition, used by the log edge and by both renderers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncHealth {
    /// No poll has succeeded **since this process booted**. Note what this does
    /// *not* say: a secondary that joined earlier still loads its last-good
    /// bundle from `cluster.d/` at startup and filters with it, so
    /// this is "unconfirmed policy", not "no policy".
    NeverSynced,
    /// Synced at least once and the most recent tick succeeded.
    Current,
    /// Synced at least once, and the most recent tick failed — the applied
    /// policy stands but is no longer being confirmed. Filtering continues:
    /// degrade audibly, never refuse.
    Stale,
}

impl SyncHealth {
    /// Classify a **secondary's** telemetry.
    ///
    /// Both inputs are available on the wire as well as in [`SyncStatus`]:
    /// `ClusterStatusDto.last_sync_secs.is_some()` is exactly
    /// `synced_at_least_once` (the poll loop writes `last_sync` and
    /// `synced_at_least_once` on the same success branch), so the CLI and TUI
    /// renderers classify with this same function rather than re-deriving it.
    ///
    /// **Precondition: the caller has already established that this node is a
    /// secondary.** A primary never writes [`SyncStatus`], so feeding it a
    /// primary's default telemetry yields `NeverSynced`, which of a primary is
    /// meaningless. [`ClusterObserve::sync_view`] enforces that with the role
    /// it holds; a renderer holding only a wire DTO must branch on `role`
    /// first.
    #[must_use]
    pub fn of_secondary(synced_at_least_once: bool, last_poll_ok: bool) -> Self {
        match (synced_at_least_once, last_poll_ok) {
            (false, _) => Self::NeverSynced,
            (true, true) => Self::Current,
            (true, false) => Self::Stale,
        }
    }

    /// True for everything that is not `Current` — the states an operator has
    /// to be told about.
    #[must_use]
    pub fn is_degraded(self) -> bool {
        !matches!(self, Self::Current)
    }
}

/// What a renderer needs to answer the question — *"which policy am I
/// applying, and how old is that answer?"* — without reaching into
/// [`ClusterObserve`] itself.
///
/// **`confirmed_secs_ago` is the age of the last *confirmation*, not of the
/// policy.** A tick that gets a 304 (bundle unchanged) is a success and
/// refreshes it, so a policy authored three days ago and re-confirmed twelve
/// seconds ago reports twelve. Render it as "confirmed Ns ago"; "N seconds
/// old" would be false in exactly the case an operator would care about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncView {
    pub health: SyncHealth,
    /// Last-applied policy bundle hash (`None` before the first sync of this
    /// process — the on-disk bundle may still be in force).
    pub applied_hash: Option<String>,
    /// Seconds since the last *successful* poll; `None` when there has not
    /// been one since boot.
    pub confirmed_secs_ago: Option<u64>,
    /// Whether the most recent tick succeeded (`health` folds this together
    /// with `synced_at_least_once`; kept here so a renderer can show the error
    /// without re-deriving).
    pub last_poll_ok: bool,
    /// The most recent tick's error.
    pub last_error: Option<String>,
}

/// The transition, if any, that this poll tick represents — the **only** thing
/// the poll loop should log about staleness.
///
/// Before this existed the loop warned on **every** failed tick: at a 15 s
/// interval an overnight outage is ~2 000 identical lines, which is how a log
/// stops being read. Edge-triggering it costs one line per crossing.
///
/// The variant is returned as data rather than logged in place so a test can
/// assert the **absence** of a second line while the condition persists
/// (`edge == Steady`) without standing up a `tracing` capture — this repo's
/// tracing-capture fixture is known to race under the parallel test runner.
/// Call [`SyncEdge::log`] to emit it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncEdge {
    /// Health is unchanged since the previous tick — say nothing. This is the
    /// common case, and it is the whole point.
    Steady,
    /// First tick of this process, and it failed with no prior successful sync
    /// (typically: boot with the primary unreachable). Logged once — without
    /// this variant the *worst* state would be the quietest, since
    /// `NeverSynced → NeverSynced` is not a transition.
    NeverSyncedYet { error: Option<String> },
    /// First successful sync since boot (from either the boot state or
    /// `NeverSynced`).
    FirstSync { hash: Option<String> },
    /// Crossed `Current → Stale`: polls are failing, the last-good policy
    /// stands.
    Degraded {
        error: Option<String>,
        confirmed_secs_ago: Option<u64>,
    },
    /// Crossed `Stale → Current`.
    Recovered {
        hash: Option<String>,
        /// How many ticks failed in the degraded run just ended.
        failed_polls: u32,
        /// How long the degraded run lasted.
        degraded_secs: Option<u64>,
    },
}

impl SyncEdge {
    /// Emit this edge at the level it deserves. A no-op for [`Self::Steady`],
    /// which is what keeps a persisting failure quiet.
    pub fn log(&self) {
        match self {
            Self::Steady => {}
            Self::NeverSyncedYet { error } => {
                tracing::warn!(
                    error = error.as_deref().unwrap_or("unknown"),
                    "cluster secondary: no successful sync since boot; the primary is \
                     unreachable. Any policy bundle already on disk stays in force and \
                     filtering continues; this warning will not repeat until the state changes"
                );
            }
            Self::FirstSync { hash } => {
                tracing::info!(
                    hash = hash.as_deref().unwrap_or("-"),
                    "cluster secondary: first successful policy sync since boot"
                );
            }
            Self::Degraded {
                error,
                confirmed_secs_ago,
            } => {
                tracing::warn!(
                    error = error.as_deref().unwrap_or("unknown"),
                    confirmed_secs_ago = confirmed_secs_ago.unwrap_or(0),
                    "cluster secondary: policy sync degraded; keeping the last-good policy and \
                     retrying. Lists keep refreshing on their own schedule — filtering is NOT \
                     interrupted. This warning is edge-triggered and will not repeat until it \
                     recovers"
                );
            }
            Self::Recovered {
                hash,
                failed_polls,
                degraded_secs,
            } => {
                tracing::info!(
                    hash = hash.as_deref().unwrap_or("-"),
                    failed_polls = failed_polls,
                    degraded_secs = degraded_secs.unwrap_or(0),
                    "cluster secondary: policy sync recovered"
                );
            }
        }
    }
}

/// Edge-detector state: the health class the previous tick landed in (`None`
/// before the first tick of this process) plus the running degraded-run
/// counters.
#[derive(Debug, Default)]
struct EdgeState {
    phase: Option<SyncHealth>,
    failed_polls: u32,
    degraded_since: Option<Instant>,
}

/// One node's running sample pair, used to derive a rate. `prev` is the prior
/// sample; the delta `last - prev` over the elapsed wall-clock is the qps.
struct RosterEntry {
    node_name: Option<String>,
    last_seen: Instant,
    last: ClusterStats,
    prev: Option<(ClusterStats, Instant)>,
    /// The `config_generation` this node last **advertised** in its heartbeat.
    /// Retained (rather than synthesised at render time) so `/api/cluster/status`
    /// reports what the peer actually said; `0` on the self-row, whose real
    /// generation is the cluster-wide one from [`ClusterObserve::generations`].
    config_generation: u64,
}

impl RosterEntry {
    fn new(
        node_name: Option<String>,
        stats: ClusterStats,
        config_generation: u64,
        now: Instant,
    ) -> Self {
        Self {
            node_name,
            last_seen: now,
            last: stats,
            prev: None,
            config_generation,
        }
    }

    /// Rotate the current sample into `prev` and store the new one. A `None`
    /// name leaves the existing label alone (a heartbeat may omit it).
    fn update(
        &mut self,
        node_name: Option<String>,
        stats: ClusterStats,
        config_generation: u64,
        now: Instant,
    ) {
        self.prev = Some((self.last.clone(), self.last_seen));
        self.last = stats;
        self.last_seen = now;
        self.config_generation = config_generation;
        if node_name.is_some() {
            self.node_name = node_name;
        }
    }

    /// Queries/sec from the sample delta. `0.0` until a second sample exists.
    /// `saturating_sub` guards a counter reset (peer restart): a negative
    /// delta becomes 0 rather than a nonsense rate.
    fn qps(&self) -> f64 {
        match &self.prev {
            Some((p, pt)) => {
                let dt = self.last_seen.saturating_duration_since(*pt).as_secs_f64();
                if dt > 0.0 {
                    self.last.total_queries.saturating_sub(p.total_queries) as f64 / dt
                } else {
                    0.0
                }
            }
            None => 0.0,
        }
    }

    /// Block rate over the latest cumulative sample (not windowed — a coarse
    /// "how much of this node's traffic is blocked" signal).
    fn blocked_pct(&self) -> f64 {
        if self.last.total_queries > 0 {
            self.last.total_blocked as f64 / self.last.total_queries as f64 * 100.0
        } else {
            0.0
        }
    }
}

/// A flattened, computed roster row — what the IPC handler maps onto the wire
/// DTO. Kept observe-local (no `ipc::protocol` dependency) so the cluster
/// module doesn't reach back into the IPC layer.
#[derive(Debug, Clone)]
pub struct RosterRow {
    /// `node_name` if the node advertised one, else its address (or
    /// "this node" for the local self-row).
    pub name: String,
    /// Source IP, or `"local"` for the self-row.
    pub addr: String,
    /// True for the local node's own row.
    pub is_self: bool,
    /// True when the last sample is within the stale window. Always true for
    /// the self-row.
    pub online: bool,
    pub total_queries: u64,
    pub total_blocked: u64,
    /// Cumulative cache hits from the node's latest sample. Not rendered by the
    /// roster views (they show rates, not cache), but carried so
    /// `/api/cluster/status` can report the peer's stats without inventing a
    /// zero for the one counter the row dropped.
    pub cache_hits: u64,
    pub qps: f64,
    pub blocked_pct: f64,
    /// Share of Σ(qps over online nodes) × 100. `0.0` for offline rows and
    /// when the cluster is idle (Σ qps == 0).
    pub share_pct: f64,
    /// The `config_generation` this node last advertised (`0` on the self-row).
    pub config_generation: u64,
}

/// Bounded per-peer roster + the primary's own self-sample. Eviction is
/// stalest-first at `cap` (logged — never a silent drop).
struct Roster {
    cap: usize,
    self_entry: Option<RosterEntry>,
    peers: HashMap<IpAddr, RosterEntry>,
}

impl Roster {
    fn new(cap: usize) -> Self {
        Self {
            cap,
            self_entry: None,
            peers: HashMap::new(),
        }
    }

    fn record_peer(
        &mut self,
        ip: IpAddr,
        node_name: Option<String>,
        stats: ClusterStats,
        config_generation: u64,
        now: Instant,
    ) {
        // The name is peer-supplied (untrusted) — clamp its length
        // before it enters the bounded roster so a peer cannot pin an oversized
        // display label. `record_self` (trusted local config) is not clamped.
        let node_name = node_name.map(clamp_node_name);
        if let Some(e) = self.peers.get_mut(&ip) {
            e.update(node_name, stats, config_generation, now);
            return;
        }
        if self.peers.len() >= self.cap {
            // Evict the stalest peer so a churn of source IPs can't grow the
            // map without bound. Logged so a hit on the cap is visible.
            if let Some(oldest) = self
                .peers
                .iter()
                .min_by_key(|(_, e)| e.last_seen)
                .map(|(k, _)| *k)
            {
                self.peers.remove(&oldest);
                tracing::warn!(
                    cap = self.cap,
                    evicted = %oldest,
                    "cluster roster at capacity; evicted stalest peer"
                );
            }
        }
        self.peers.insert(
            ip,
            RosterEntry::new(node_name, stats, config_generation, now),
        );
    }

    fn record_self(&mut self, node_name: Option<String>, stats: ClusterStats, now: Instant) {
        // The self-row carries generation 0: this node's own generation is the
        // cluster-wide one (`ClusterObserve::generations`), not something it
        // advertises to itself.
        match &mut self.self_entry {
            Some(e) => e.update(node_name, stats, 0, now),
            None => self.self_entry = Some(RosterEntry::new(node_name, stats, 0, now)),
        }
    }

    /// Build the computed rows: self first, then peers. Share is a second pass
    /// over the online rows only (an offline peer's stale qps must not pad the
    /// denominator).
    fn snapshot(&self, now: Instant, stale_secs: u64, self_name: Option<&str>) -> Vec<RosterRow> {
        let mut rows: Vec<RosterRow> = Vec::with_capacity(self.peers.len() + 1);
        if let Some(e) = &self.self_entry {
            rows.push(RosterRow {
                name: self_name
                    .map(str::to_owned)
                    .unwrap_or_else(|| "this node".into()),
                addr: "local".into(),
                is_self: true,
                online: true,
                total_queries: e.last.total_queries,
                total_blocked: e.last.total_blocked,
                cache_hits: e.last.cache_hits,
                qps: e.qps(),
                blocked_pct: e.blocked_pct(),
                share_pct: 0.0,
                config_generation: e.config_generation,
            });
        }
        for (ip, e) in &self.peers {
            let online = now.saturating_duration_since(e.last_seen).as_secs() <= stale_secs;
            rows.push(RosterRow {
                name: e.node_name.clone().unwrap_or_else(|| ip.to_string()),
                addr: ip.to_string(),
                is_self: false,
                online,
                total_queries: e.last.total_queries,
                total_blocked: e.last.total_blocked,
                cache_hits: e.last.cache_hits,
                qps: e.qps(),
                blocked_pct: e.blocked_pct(),
                share_pct: 0.0,
                config_generation: e.config_generation,
            });
        }
        let sum_qps: f64 = rows.iter().filter(|r| r.online).map(|r| r.qps).sum();
        if sum_qps > 0.0 {
            for r in &mut rows {
                r.share_pct = if r.online {
                    r.qps / sum_qps * 100.0
                } else {
                    0.0
                };
            }
        }
        rows
    }
}

/// The single shared observability handle, cloned into the API server (the
/// heartbeat handler writes the roster) and the daemon IPC state (the
/// `ClusterStatus` handler reads everything). A node is one role at a time, so
/// only the matching half is populated:
///
///   * primary   — `state = Some`, roster fed by heartbeats, `sync` unused.
///   * secondary — `state = None`, `sync` fed by the poll loop, roster unused.
pub struct ClusterObserve {
    /// This node's role (echoed into the status view).
    pub role: ClusterRole,
    /// This node's optional human-readable name (the self-row label, and what
    /// a secondary advertises in its heartbeats).
    pub node_name: Option<String>,
    /// The primary's base URL a secondary polls (`None` on a primary).
    pub peer: Option<String>,
    /// A peer is stale once its last sample is older than this — 3 ×
    /// `poll_interval_secs`, computed at boot.
    pub stale_secs: u64,
    sync: ArcSwap<SyncStatus>,
    roster: Mutex<Roster>,
    state: Option<std::sync::Arc<ClusterState>>,
    /// Edge-detector state for [`Self::note_tick`]. A `Mutex` (not an atomic):
    /// the poll loop is one writer at one tick per `poll_interval_secs`, far
    /// off the DNS hot path, and it matches the roster's locking above.
    edge: Mutex<EdgeState>,
}

impl ClusterObserve {
    /// Primary node: holds the serve-state (for generations/hashes) + a roster.
    #[must_use]
    pub fn new_primary(
        node_name: Option<String>,
        state: std::sync::Arc<ClusterState>,
        stale_secs: u64,
        roster_cap: usize,
    ) -> Self {
        Self {
            role: ClusterRole::Primary,
            node_name,
            peer: None,
            stale_secs,
            sync: ArcSwap::from_pointee(SyncStatus::default()),
            roster: Mutex::new(Roster::new(roster_cap)),
            state: Some(state),
            edge: Mutex::new(EdgeState::default()),
        }
    }

    /// Secondary node: holds the poll telemetry; roster + state stay empty.
    #[must_use]
    pub fn new_secondary(node_name: Option<String>, peer: String, stale_secs: u64) -> Self {
        Self {
            role: ClusterRole::Secondary,
            node_name,
            peer: Some(peer),
            stale_secs,
            sync: ArcSwap::from_pointee(SyncStatus::default()),
            roster: Mutex::new(Roster::new(0)),
            state: None,
            edge: Mutex::new(EdgeState::default()),
        }
    }

    /// Write-through the secondary's latest poll telemetry (poll-loop side).
    pub fn store_sync(&self, status: SyncStatus) {
        self.sync.store(std::sync::Arc::new(status));
    }

    /// Read the secondary's latest poll telemetry (IPC reader side).
    #[must_use]
    pub fn load_sync(&self) -> std::sync::Arc<SyncStatus> {
        self.sync.load_full()
    }

    /// The staleness view: *"which policy am I applying, and how old is that
    /// answer?"* — `None` on a primary, which has no sync of its own to report
    /// (its `SyncStatus` is never written, so classifying it would report a
    /// meaningless `NeverSynced`; the role check lives here because this is
    /// where the role is).
    ///
    /// `now` is passed in rather than read from the clock so a caller can test
    /// ages deterministically, matching [`Self::roster_snapshot`].
    #[must_use]
    pub fn sync_view(&self, now: Instant) -> Option<SyncView> {
        if self.role != ClusterRole::Secondary {
            return None;
        }
        let s = self.load_sync();
        Some(SyncView {
            health: SyncHealth::of_secondary(s.synced_at_least_once, s.last_poll_ok),
            applied_hash: s.last_config_hash.clone(),
            confirmed_secs_ago: s
                .last_sync
                .map(|t| now.saturating_duration_since(t).as_secs()),
            last_poll_ok: s.last_poll_ok,
            last_error: s.last_error.clone(),
        })
    }

    /// Fold one poll tick's outcome into the edge detector and report whether
    /// it is a transition worth logging.
    ///
    /// **Call this exactly once per tick, from the poll loop, with the same
    /// [`SyncStatus`] handed to [`Self::store_sync`]** — it is the replacement
    /// for the per-tick `warn!` the loop used to emit on every failure. Order
    /// relative to `store_sync` does not matter (they touch different state),
    /// but calling it twice for one tick would report the second call as
    /// `Steady` and lose nothing except the counters' accuracy.
    ///
    /// Deliberately **not** `#[must_use]`: the poll loop's existing
    /// `store_sync` call site must keep compiling untouched, and a `must_use`
    /// here would only move the failure to a different lane's file.
    pub fn note_tick(&self, status: &SyncStatus, now: Instant) -> SyncEdge {
        let health = SyncHealth::of_secondary(status.synced_at_least_once, status.last_poll_ok);
        let mut st = self.edge.lock().unwrap_or_else(|e| e.into_inner());
        let prev = st.phase;
        st.phase = Some(health);

        if !status.last_poll_ok {
            st.failed_polls = st.failed_polls.saturating_add(1);
            if st.degraded_since.is_none() {
                st.degraded_since = Some(now);
            }
        }

        // `prev == Some(health)` is the persisting condition: the tick changed
        // nothing an operator needs a second line about.
        if prev == Some(health) {
            return SyncEdge::Steady;
        }

        match health {
            // Only reachable as the very first tick of the process: once
            // `synced_at_least_once` is set it never clears, so nothing
            // transitions *into* NeverSynced later.
            SyncHealth::NeverSynced => SyncEdge::NeverSyncedYet {
                error: status.last_error.clone(),
            },
            SyncHealth::Current => {
                let degraded_secs = st
                    .degraded_since
                    .map(|t| now.saturating_duration_since(t).as_secs());
                let failed_polls = st.failed_polls;
                st.failed_polls = 0;
                st.degraded_since = None;
                // A recovery is only a recovery if there was something to
                // recover from; the boot → Current and NeverSynced → Current
                // paths are a first sync.
                if prev == Some(SyncHealth::Stale) {
                    SyncEdge::Recovered {
                        hash: status.last_config_hash.clone(),
                        failed_polls,
                        degraded_secs,
                    }
                } else {
                    SyncEdge::FirstSync {
                        hash: status.last_config_hash.clone(),
                    }
                }
            }
            SyncHealth::Stale => SyncEdge::Degraded {
                error: status.last_error.clone(),
                confirmed_secs_ago: status
                    .last_sync
                    .map(|t| now.saturating_duration_since(t).as_secs()),
            },
        }
    }

    /// Record a peer heartbeat (primary side). Recovers a poisoned lock rather
    /// than panicking the heartbeat handler.
    pub fn record_peer(
        &self,
        ip: IpAddr,
        node_name: Option<String>,
        stats: ClusterStats,
        config_generation: u64,
        now: Instant,
    ) {
        self.roster
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record_peer(ip, node_name, stats, config_generation, now);
    }

    /// Sample the primary's own counters into the self-row (primary side).
    /// Piggybacked on each inbound heartbeat so self-qps shares the
    /// secondaries' cadence.
    pub fn record_self(&self, stats: ClusterStats, now: Instant) {
        let name = self.node_name.clone();
        self.roster
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record_self(name, stats, now);
    }

    /// Snapshot the roster as computed rows (IPC reader side).
    #[must_use]
    pub fn roster_snapshot(&self, now: Instant) -> Vec<RosterRow> {
        self.roster
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .snapshot(now, self.stale_secs, self.node_name.as_deref())
    }

    /// The primary's `(config_gen, config_hash)`; `None` on a secondary (no
    /// serve-state).
    #[must_use]
    pub fn generations(&self) -> Option<(u64, String)> {
        self.state
            .as_ref()
            .map(|s| (s.config_generation(), s.policy().hash.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats(q: u64, b: u64) -> ClusterStats {
        ClusterStats {
            total_queries: q,
            total_blocked: b,
            cache_hits: 0,
        }
    }

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, n])
    }

    #[test]
    fn qps_zero_until_second_sample() {
        let mut r = Roster::new(8);
        let t0 = Instant::now();
        r.record_peer(ip(1), None, stats(100, 10), 0, t0);
        let rows = r.snapshot(t0, 45, None);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].qps, 0.0);
        assert!(rows[0].online);
    }

    #[test]
    fn qps_from_delta_over_elapsed() {
        let mut r = Roster::new(8);
        let t0 = Instant::now();
        r.record_peer(ip(1), Some("sec-a".into()), stats(100, 10), 0, t0);
        let t1 = t0 + std::time::Duration::from_secs(10);
        r.record_peer(ip(1), None, stats(300, 40), 0, t1);
        let rows = r.snapshot(t1, 45, None);
        // 200 queries over 10s = 20 qps; name retained from first sample.
        assert!((rows[0].qps - 20.0).abs() < 1e-6);
        assert_eq!(rows[0].name, "sec-a");
        assert!((rows[0].blocked_pct - (40.0 / 300.0 * 100.0)).abs() < 1e-6);
    }

    #[test]
    fn counter_reset_clamps_to_zero() {
        let mut r = Roster::new(8);
        let t0 = Instant::now();
        r.record_peer(ip(1), None, stats(500, 50), 0, t0);
        let t1 = t0 + std::time::Duration::from_secs(5);
        // Peer restarted: counter went backwards.
        r.record_peer(ip(1), None, stats(3, 0), 0, t1);
        let rows = r.snapshot(t1, 45, None);
        assert_eq!(rows[0].qps, 0.0);
    }

    #[test]
    fn share_splits_over_online_only() {
        let mut r = Roster::new(8);
        let t0 = Instant::now();
        // self: 10 qps, peer-a: 30 qps, peer-b: will be stale → excluded.
        r.record_self(Some("prim".into()), stats(0, 0), t0);
        r.record_peer(ip(1), Some("a".into()), stats(0, 0), 0, t0);
        r.record_peer(ip(2), Some("b".into()), stats(0, 0), 0, t0);
        let t1 = t0 + std::time::Duration::from_secs(10);
        r.record_self(None, stats(100, 0), t1);
        r.record_peer(ip(1), None, stats(300, 0), 0, t1);
        // Snapshot at t0+50 (= t1+40): peer-a's last sample (t1) is 40s old →
        // online (≤ 45); peer-b's (t0) is 50s old → stale, so it drops out of
        // the share denominator.
        let t2 = t1 + std::time::Duration::from_secs(40);
        let rows = r.snapshot(t2, 45, Some("prim"));
        let self_row = rows.iter().find(|r| r.is_self).unwrap();
        let a = rows.iter().find(|r| r.name == "a").unwrap();
        let b = rows.iter().find(|r| r.name == "b").unwrap();
        assert!(!b.online);
        assert_eq!(b.share_pct, 0.0);
        // self 10 qps + a 30 qps = 40 total → 25% / 75%.
        assert!((self_row.share_pct - 25.0).abs() < 1e-6);
        assert!((a.share_pct - 75.0).abs() < 1e-6);
    }

    #[test]
    fn eviction_is_stalest_first_at_cap() {
        let mut r = Roster::new(2);
        let t0 = Instant::now();
        r.record_peer(ip(1), None, stats(1, 0), 0, t0);
        let t1 = t0 + std::time::Duration::from_secs(1);
        r.record_peer(ip(2), None, stats(1, 0), 0, t1);
        // ip(1) is stalest; inserting ip(3) evicts it.
        let t2 = t1 + std::time::Duration::from_secs(1);
        r.record_peer(ip(3), None, stats(1, 0), 0, t2);
        let rows = r.snapshot(t2, 999, None);
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|row| row.addr != ip(1).to_string()));
    }

    /// The generation is retained per peer (and updated on the next beat), so
    /// `/api/cluster/status` can report what the peer actually advertised
    /// instead of a synthesised constant.
    #[test]
    fn peer_config_generation_is_retained_and_updated() {
        let mut r = Roster::new(8);
        let t0 = Instant::now();
        r.record_peer(ip(1), None, stats(1, 0), 7, t0);
        assert_eq!(r.snapshot(t0, 45, None)[0].config_generation, 7);
        let t1 = t0 + std::time::Duration::from_secs(1);
        r.record_peer(ip(1), None, stats(2, 0), 9, t1);
        assert_eq!(r.snapshot(t1, 45, None)[0].config_generation, 9);
    }

    /// A primary has no sync of its own; its `SyncStatus` is never written, so
    /// classifying it would report `NeverSynced` — a lie about a node that is
    /// the source of truth. The role check belongs here, where the role is.
    #[test]
    fn sync_view_is_none_on_a_primary() {
        let state = std::sync::Arc::new(ClusterState::new(
            ClusterRole::Primary,
            1,
            "a".repeat(64),
            Vec::new(),
        ));
        let obs = ClusterObserve::new_primary(Some("prim".into()), state, 45, 8);
        assert!(obs.sync_view(Instant::now()).is_none());
    }

    #[test]
    fn sync_view_reports_the_applied_hash_and_its_confirmation_age() {
        let obs = ClusterObserve::new_secondary(None, "https://192.0.2.10:8080".into(), 45);
        let t0 = Instant::now();
        obs.store_sync(SyncStatus {
            last_config_hash: Some("deadbeef".into()),
            last_sync: Some(t0),
            last_poll_ok: true,
            last_error: None,
            synced_at_least_once: true,
        });
        let v = obs
            .sync_view(t0 + std::time::Duration::from_secs(12))
            .expect("a secondary always has a view");
        assert_eq!(v.health, SyncHealth::Current);
        assert_eq!(v.applied_hash.as_deref(), Some("deadbeef"));
        assert_eq!(v.confirmed_secs_ago, Some(12));
    }

    #[test]
    fn peer_node_name_is_clamped() {
        // A peer advertising a huge label cannot pin it in the roster.
        let mut r = Roster::new(8);
        let t0 = Instant::now();
        r.record_peer(ip(1), Some("x".repeat(500)), stats(1, 0), 0, t0);
        let rows = r.snapshot(t0, 45, None);
        assert_eq!(rows.len(), 1);
        assert!(
            rows[0].name.chars().count() <= MAX_NODE_NAME_LEN,
            "peer node_name must be clamped to {MAX_NODE_NAME_LEN} chars, got {}",
            rows[0].name.chars().count()
        );
    }
}
