//! In-daemon bounded ring buffer of `tracing` events — the data source
//! behind the TUI's Logs leaf and `IpcCommand::DaemonLogs`.
//!
//! # Why this exists rather than journald or the audit log
//!
//! The operator asked for a tab showing "tutti i messaggi per categoria
//! (da aggiornamenti ad errori)". Two cheaper sources were measured and
//! rejected (`_docs/reviews/2026-08-24_logs-tab-source-scout.md`):
//!
//! - **`AuditRecord` + `list_state.toml`** carry config-change history and
//!   list-refresh status and **no error log at all** — `dns/handler.rs`
//!   alone has 19 `tracing::error!`/`warn!` sites that write neither, so an
//!   operator filtering to "errors" would read a near-empty pane.
//! - **journald** is unreadable by the daemon's own user: `id purge-warden`
//!   returns `groups=987(purge-warden)` on both live boxes, and reading the
//!   unit's journal would need `systemd-journal` — which grants the *entire
//!   system journal* to a network-facing daemon.
//!
//! Capturing `tracing` events in-process needs no new permission and keeps
//! the category **semantic**: the level already *is* error/warn/info, so
//! nothing has to be inferred from message text.
//!
//! # Hot-path contract (CLAUDE.md Design Rule 1)
//!
//! `dns/handler.rs` emits from the query path, so this layer sits on it.
//! Three properties keep the cost at zero for a query that succeeds:
//!
//! 1. **The INFO floor is a PER-LAYER filter** ([`capture_layer`] applies
//!    `.with_filter(LevelFilter::INFO)`), never a `Layer::enabled`
//!    override. `Layered::enabled` ANDs across layers, so a layer that
//!    answers `false` for `DEBUG` disables that callsite for **every**
//!    layer — a Logs tab that silences the operator's own `--log-level
//!    debug` output in the log file. A per-layer filter cannot veto a
//!    sibling; that is the whole reason the API exists. Pinned by
//!    `debug_events_still_reach_the_log_file`.
//! 2. **That filter also supplies `max_level_hint`.** A layer whose hint
//!    is `None` forces the *process-wide* max level to `TRACE`, which
//!    un-disables every `debug!` callsite on the query path — they would
//!    start running a filter call per query instead of being statically
//!    off. At the default INFO the global max is unchanged from today.
//! 3. **The producer never blocks.** [`LogRing::push`] uses `try_lock`: on
//!    contention it bumps [`LogRing::dropped`] and returns. Design Rule 1
//!    forbids *global serialisation* on the query path — a lock that is
//!    never waited on does not serialise. The reader (IPC, off the hot
//!    path) takes the blocking `lock()`.
//!
//! What a captured event costs the emitting thread: one `String` (message
//! plus any structured fields), one `try_lock`, one `VecDeque` pop+push.
//! On the query path that is paid only by the failure branches, which
//! already format and write the same text through the `fmt` layer.
//!
//! # Bound
//!
//! [`LOG_RING_CAPACITY`] entries, oldest evicted first, and every message
//! truncated at [`MAX_MESSAGE_LEN`] bytes. An unbounded event log on a
//! daemon that runs for months is a memory leak with a nicer name.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock, TryLockError};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tracing::field::{Field, Visit};
use tracing::level_filters::LevelFilter;
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::filter::Filtered;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

/// Entries retained in the ring. At ~120 bytes per entry (a `String` plus
/// its header, a timestamp, a `&'static str` and a discriminant) this is
/// roughly 120 KB resident — small enough to keep on a Pi Zero, deep
/// enough that the operator can scroll a boot sequence and its aftermath.
pub const LOG_RING_CAPACITY: usize = 1000;

/// Byte ceiling on one captured message. A single pathological event (a
/// formatted config dump, an upstream returning kilobytes of garbage)
/// must not be able to consume the ring's whole memory budget. Truncation
/// appends `…` so a clipped line is visibly clipped rather than silently
/// short.
pub const MAX_MESSAGE_LEN: usize = 512;

/// Severity of a captured event. Narrower than `tracing::Level` on
/// purpose: `DEBUG`/`TRACE` are never captured (see the module docs), so
/// a variant for them would be a state this type can't hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Error,
    Warn,
    Info,
}

impl LogLevel {
    /// `None` for `DEBUG`/`TRACE` — the two levels this buffer refuses.
    /// Callers on the capture path have already been filtered by
    /// [`CAPTURE_FLOOR`]; this is the belt to that suspenders.
    pub fn from_tracing(level: &Level) -> Option<Self> {
        match *level {
            Level::ERROR => Some(Self::Error),
            Level::WARN => Some(Self::Warn),
            Level::INFO => Some(Self::Info),
            _ => None,
        }
    }
}

/// One captured event.
///
/// `target` is `&'static str` because `tracing::Metadata::target` already
/// is — the module path is baked into the callsite, so carrying it costs
/// no allocation.
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub ts: OffsetDateTime,
    pub level: LogLevel,
    pub target: &'static str,
    pub message: String,
}

/// Bounded MPSC-ish event store: many emitting threads push, one IPC
/// handler reads.
#[derive(Debug)]
pub struct LogRing {
    buf: Mutex<VecDeque<LogEntry>>,
    /// Events discarded because a producer found the lock held. Surfaced
    /// over IPC so a gap in the pane is visible rather than silent.
    dropped: AtomicU64,
    capacity: usize,
}

/// ASCII-case-insensitive `str::contains` that allocates nothing.
///
/// `needle` must already be ASCII-lowercased, and only the haystack byte is
/// folded, so neither side is copied. Every caller lowers once, outside its
/// scan: [`LogRing::snapshot`] before it takes the buffer lock, the
/// query-log filter by construction — its needles exist only as a
/// `LoweredNeedle` or as a `Glob` segment, and both lower on the way in.
///
/// Both scans are places an allocation here would be expensive. `snapshot`
/// runs this once per retained entry **inside the buffer lock**, which
/// [`LogRing::push`] refuses to wait on — a cost here is paid in log lines
/// the operator never sees — and the query-log filter runs it once per line
/// of a file that can reach hundreds of megabytes.
///
/// ASCII-only is sufficient and deliberate: targets are Rust module paths,
/// domains are ASCII after IDNA, and messages are operator-facing ASCII. A
/// full Unicode fold would need the allocation this exists to avoid.
pub(super) fn contains_ascii_ci(haystack: &str, needle: &str) -> bool {
    let (hay, ndl) = (haystack.as_bytes(), needle.as_bytes());
    // `windows(0)` panics, so the empty needle cannot reach the scan.
    if ndl.is_empty() {
        return true;
    }
    if ndl.len() > hay.len() {
        return false;
    }
    hay.windows(ndl.len())
        .any(|w| w.iter().zip(ndl).all(|(h, n)| h.to_ascii_lowercase() == *n))
}

impl LogRing {
    pub fn new(capacity: usize) -> Self {
        // Clamped because a zero-capacity ring cannot merely be empty —
        // it hangs. `push`'s eviction loop tests `len() >= capacity`,
        // which at zero no `pop_front` can ever falsify, and it spins
        // there holding the lock every producer `try_lock`s: capture
        // dies for the process lifetime with no panic to say so.
        let capacity = capacity.max(1);
        Self {
            // Pre-allocated so the steady-state push does not allocate
            // inside the critical section.
            buf: Mutex::new(VecDeque::with_capacity(capacity)),
            dropped: AtomicU64::new(0),
            capacity,
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Append one event, evicting the oldest if the ring is full.
    ///
    /// **Never blocks.** `try_lock` failing with `WouldBlock` means the
    /// IPC reader (or another producer) holds the lock; the event is
    /// dropped and counted. A *poisoned* lock is recovered instead of
    /// counted: poisoning is permanent, so treating it as contention
    /// would silently kill capture for the daemon's remaining lifetime
    /// while a counter nobody reads climbed.
    pub fn push(&self, entry: LogEntry) {
        let mut buf = match self.buf.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        // Pop BEFORE push. Pushing first takes the length to capacity+1,
        // which reallocates the pre-sized `VecDeque` — an allocation
        // inside the critical section this type advertises as free of
        // them.
        while buf.len() >= self.capacity {
            buf.pop_front();
        }
        buf.push_back(entry);
    }

    /// Newest-first page of up to `limit` entries matching both filters.
    ///
    /// Filters are applied **during** the walk, not to a fixed slice —
    /// the same convention the query-log walker uses, and the reason a
    /// filter to `error` can reach the bottom of the ring instead of
    /// returning whatever few errors happen to sit in the newest page.
    ///
    /// `contains` matches ASCII-case-insensitively against the message and
    /// the target.
    pub fn snapshot(
        &self,
        limit: usize,
        level: Option<LogLevel>,
        contains: Option<&str>,
    ) -> Vec<LogEntry> {
        // Lowered once, out here, because the alternative is lowering the
        // haystack once per entry — two `String`s each — inside a lock
        // whose every held microsecond is an event `push` throws away.
        let needle = contains.map(str::to_ascii_lowercase);
        let buf = match self.buf.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        // The chain stays lazy under the lock on purpose: `take` stops the
        // walk at `limit`, so the clone count is the page size and not the
        // ring size. Collecting the level-matching entries first to filter
        // them outside the lock would clone up to the whole ring to save
        // work that no longer allocates.
        buf.iter()
            .rev()
            .filter(|e| level.is_none_or(|want| e.level == want))
            .filter(|e| {
                needle.as_deref().is_none_or(|n| {
                    contains_ascii_ci(&e.message, n) || contains_ascii_ci(e.target, n)
                })
            })
            .take(limit)
            .cloned()
            .collect()
    }

    /// Entries currently retained, ignoring filters. Test-facing.
    pub fn len(&self) -> usize {
        match self.buf.lock() {
            Ok(guard) => guard.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for LogRing {
    fn default() -> Self {
        Self::new(LOG_RING_CAPACITY)
    }
}

/// Process-wide ring. `tracing` subscribers are global and installed once
/// at startup, so the buffer they feed is too. Tests build their own
/// [`LogRing`] instead of touching this.
pub fn global() -> &'static std::sync::Arc<LogRing> {
    static GLOBAL: OnceLock<std::sync::Arc<LogRing>> = OnceLock::new();
    GLOBAL.get_or_init(|| std::sync::Arc::new(LogRing::default()))
}

/// `tracing_subscriber::Layer` that copies INFO-and-above events into a
/// [`LogRing`]. See the module docs for the hot-path contract.
#[derive(Debug, Clone)]
pub struct LogRingLayer {
    ring: std::sync::Arc<LogRing>,
}

impl LogRingLayer {
    pub fn new(ring: std::sync::Arc<LogRing>) -> Self {
        Self { ring }
    }
}

/// The level floor. `tracing::Level` orders `ERROR < WARN < INFO < DEBUG <
/// TRACE`, so `LevelFilter::INFO` admits exactly error/warn/info.
///
/// Deliberately NOT a `Layer::enabled` override — see the module docs,
/// property 1. Applied by [`capture_layer`], which is the only sanctioned
/// way to compose this layer.
pub const CAPTURE_FLOOR: LevelFilter = LevelFilter::INFO;

impl<S: Subscriber> Layer<S> for LogRingLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        // Belt to the per-layer filter's suspenders: a caller that
        // composed this layer without `capture_layer` must not panic here, nor
        // coerce a DEBUG line into looking like INFO.
        let Some(level) = LogLevel::from_tracing(meta.level()) else {
            return;
        };
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        self.ring.push(LogEntry {
            ts: OffsetDateTime::now_utc(),
            level,
            target: meta.target(),
            message: visitor.finish(),
        });
    }
}

/// The capture layer with its per-layer level filter attached. This — not
/// a bare [`LogRingLayer`] — is what belongs in a subscriber stack.
pub fn capture_layer<S>(ring: std::sync::Arc<LogRing>) -> Filtered<LogRingLayer, LevelFilter, S>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    LogRingLayer::new(ring).with_filter(CAPTURE_FLOOR)
}

/// The daemon's whole subscriber stack: operator filter → `fmt` → ring.
///
/// **Built on `registry()`, not on `fmt()`.** Per-layer filters need a
/// `Registry` at the base; `fmt::Subscriber` panics at runtime with
/// *"does not currently support filters"*. The `EnvFilter` is added as a
/// plain layer, so it still governs the whole stack exactly as it did
/// before the ring existed — the ring is downstream of `--log-level`, not
/// a way around it.
///
/// Exists as a library function because the install site is `main.rs`,
/// which **none of the five gate commands execute**. A lib test drives
/// this same function; `main.rs` is left a call site.
///
/// `writer` defaults are the caller's business: pass `std::io::stdout` to
/// reproduce what `tracing_subscriber::fmt()` did here before (its default
/// `MakeWriter` is `io::stdout`, despite the neighbouring `is_terminal`
/// check naming stderr).
pub fn subscriber<W>(
    filter: EnvFilter,
    ansi: bool,
    writer: W,
    ring: std::sync::Arc<LogRing>,
) -> impl Subscriber + Send + Sync + 'static
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(ansi)
                .with_writer(writer),
        )
        .with(capture_layer(ring))
}

/// [`subscriber`] over the process-wide [`global`] ring, installed as the
/// global default. One call per process; a second one panics, exactly as
/// `tracing_subscriber`'s own `init()` does.
pub fn install<W>(filter: EnvFilter, ansi: bool, writer: W)
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    subscriber(filter, ansi, writer, std::sync::Arc::clone(global())).init();
}

/// Flattens an event's fields into one line: the `message` field first,
/// then ` key=value` for every other field.
///
/// Structured fields carry the context a bare message often omits —
/// `tracing::warn!(source = %id, "refresh failed")` is useless without
/// `id`. Rendering them into the same string keeps the ring one flat list
/// instead of a nested map the TUI would have to lay out.
#[derive(Default)]
struct MessageVisitor {
    message: String,
    fields: String,
}

impl MessageVisitor {
    fn finish(self) -> String {
        let mut out = self.message;
        out.push_str(&self.fields);
        truncate_message(out)
    }
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write as _;
        if field.name() == "message" {
            // `write!` to a String is infallible; the Result is discarded
            // rather than unwrapped so a formatting impl that panics is
            // the only way to lose a line here.
            let _ = write!(self.message, "{value:?}");
        } else {
            let _ = write!(self.fields, " {}={:?}", field.name(), value);
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        use std::fmt::Write as _;
        if field.name() == "message" {
            self.message.push_str(value);
        } else {
            let _ = write!(self.fields, " {}={}", field.name(), value);
        }
    }
}

/// Clip to [`MAX_MESSAGE_LEN`] bytes on a char boundary, marking the clip.
fn truncate_message(mut s: String) -> String {
    if s.len() <= MAX_MESSAGE_LEN {
        return s;
    }
    let mut end = MAX_MESSAGE_LEN;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
    s.push('…');
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn entry(level: LogLevel, message: &str) -> LogEntry {
        LogEntry {
            ts: OffsetDateTime::UNIX_EPOCH,
            level,
            target: "purge_warden::test",
            message: message.to_string(),
        }
    }

    #[test]
    fn ring_never_exceeds_capacity_and_evicts_the_oldest() {
        // The bound is the whole reason this is a ring and not a Vec. A
        // daemon that runs for months would otherwise accumulate one
        // String per event forever.
        let ring = LogRing::new(4);
        for i in 0..10 {
            ring.push(entry(LogLevel::Info, &format!("event {i}")));
        }
        assert_eq!(ring.len(), 4, "ring must not grow past its capacity");
        let seen = ring.snapshot(10, None, None);
        assert_eq!(seen.len(), 4);
        // Newest first, and the six oldest are gone.
        assert_eq!(seen[0].message, "event 9");
        assert_eq!(seen[3].message, "event 6");
    }

    #[test]
    fn snapshot_walks_the_whole_ring_for_a_filtered_level() {
        // Filtering a fixed newest-page would show ~no errors here: the
        // single error is the OLDEST entry. The walk has to reach it.
        let ring = LogRing::new(100);
        ring.push(entry(LogLevel::Error, "the only error"));
        for i in 0..50 {
            ring.push(entry(LogLevel::Info, &format!("noise {i}")));
        }
        let errors = ring.snapshot(10, Some(LogLevel::Error), None);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].message, "the only error");
    }

    #[test]
    fn snapshot_contains_matches_message_and_target_case_insensitively() {
        let ring = LogRing::new(10);
        ring.push(entry(LogLevel::Warn, "Refresh FAILED for list x"));
        ring.push(entry(LogLevel::Info, "all good"));
        assert_eq!(ring.snapshot(10, None, Some("failed")).len(), 1);
        assert_eq!(ring.snapshot(10, None, Some("PURGE_WARDEN")).len(), 2);
        assert_eq!(ring.snapshot(10, None, Some("nothing here")).len(), 0);
    }

    #[test]
    fn snapshot_ands_level_and_contains() {
        let ring = LogRing::new(10);
        ring.push(entry(LogLevel::Error, "upstream timeout"));
        ring.push(entry(LogLevel::Info, "upstream configured"));
        let hits = ring.snapshot(10, Some(LogLevel::Error), Some("upstream"));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].message, "upstream timeout");
    }

    #[test]
    fn zero_capacity_is_clamped_instead_of_hanging_the_pusher() {
        // Assert the clamp BEFORE pushing. Without it the push below does
        // not fail, it spins forever holding the lock — one wedged test
        // takes the whole `--lib` run with it, which is a far worse
        // failure than a red assertion.
        let ring = LogRing::new(0);
        assert_eq!(ring.capacity(), 1, "capacity 0 must be clamped, not stored");

        ring.push(entry(LogLevel::Info, "first"));
        ring.push(entry(LogLevel::Info, "second"));
        assert_eq!(ring.len(), 1, "the clamped ring still holds exactly one");
        assert_eq!(ring.snapshot(10, None, None)[0].message, "second");
        assert_eq!(ring.dropped(), 0, "eviction is not a drop");
    }

    #[test]
    fn snapshot_applies_limit_after_both_filters() {
        // `limit` caps MATCHES, not entries walked. The three hits are the
        // oldest entries here, so a limit applied to the raw walk instead
        // of to the survivors would return an empty page — the same
        // property `snapshot_walks_the_whole_ring_for_a_filtered_level`
        // pins for `level`, restated for the two filters together because
        // the `contains` arm is what changed.
        let ring = LogRing::new(100);
        for i in 0..3 {
            ring.push(entry(LogLevel::Error, &format!("upstream timeout {i}")));
        }
        for i in 0..20 {
            ring.push(entry(LogLevel::Info, &format!("noise {i}")));
        }
        let hits = ring.snapshot(2, Some(LogLevel::Error), Some("UPSTREAM"));
        assert_eq!(hits.len(), 2, "limit must cap matches, not the walk");
        // Newest-first among the matches.
        assert_eq!(hits[0].message, "upstream timeout 2");
        assert_eq!(hits[1].message, "upstream timeout 1");
    }

    #[test]
    fn snapshot_folds_ascii_only_and_says_so() {
        // Case folding is ASCII-only, so a non-ASCII letter matches just
        // itself. That is a real narrowing against a Unicode fold, and it
        // is pinned rather than commented: the Unicode form costs one
        // `String` per entry inside a lock `push` refuses to wait for, and
        // the query log's operator-facing filter already answers this way
        // — folding one way here and the other way there would be worse
        // than folding narrowly in both.
        let ring = LogRing::new(10);
        ring.push(entry(LogLevel::Warn, "\u{c4} alert raised"));
        assert_eq!(
            ring.snapshot(10, None, Some("\u{e4}")).len(),
            0,
            "a lowercase non-ASCII needle must not reach its uppercase form",
        );
        assert_eq!(
            ring.snapshot(10, None, Some("\u{c4}")).len(),
            1,
            "the same letter still matches itself",
        );
        // ASCII in the same message folds as it always did.
        assert_eq!(ring.snapshot(10, None, Some("ALERT")).len(), 1);
    }

    #[test]
    fn contains_ascii_ci_folds_the_haystack_only() {
        assert!(contains_ascii_ci("Refresh FAILED for list x", "failed"));
        assert!(contains_ascii_ci("purge_warden::lists", "warden"));
        // The needle is NOT folded — lowering it is the caller's job, and
        // this is the assertion that says so. `snapshot` lowers it once
        // per call instead of once per entry.
        assert!(!contains_ascii_ci("Refresh FAILED", "FAILED"));
        // An empty needle matches; a needle longer than the haystack
        // cannot. Both are answered before `windows`, which panics on 0.
        assert!(contains_ascii_ci("x", ""));
        assert!(!contains_ascii_ci("x", "xyz"));
        // Byte windows over multi-byte UTF-8 must not mis-answer.
        assert!(contains_ascii_ci("caf\u{e9} unreachable", "unreach"));
        assert!(!contains_ascii_ci("caf\u{e9}", "cafe"));
    }

    #[test]
    fn a_producer_that_finds_the_lock_held_drops_and_counts() {
        // The hot-path contract: `push` must return without waiting. If
        // this ever blocks, the test hangs rather than failing — which is
        // why the assertion is on the COUNTER, not on the timing.
        let ring = LogRing::new(10);
        let held = ring.buf.lock().unwrap();
        ring.push(entry(LogLevel::Error, "dropped on the floor"));
        assert_eq!(ring.dropped(), 1, "a contended push must be counted");
        assert_eq!(held.len(), 0, "and must not have landed");
        drop(held);
        ring.push(entry(LogLevel::Error, "this one lands"));
        assert_eq!(ring.len(), 1);
        assert_eq!(ring.dropped(), 1, "an uncontended push counts nothing");
    }

    #[test]
    fn a_poisoned_lock_is_recovered_not_counted_as_a_drop() {
        // Poisoning is permanent. Counting it as contention would mean a
        // single panic under the reader's lock silently ends capture for
        // the daemon's lifetime.
        let ring = Arc::new(LogRing::new(10));
        let poisoner = Arc::clone(&ring);
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.buf.lock().unwrap();
            panic!("poison the mutex");
        })
        .join();
        assert!(ring.buf.is_poisoned(), "precondition: the lock is poisoned");
        ring.push(entry(LogLevel::Error, "after the poison"));
        assert_eq!(ring.dropped(), 0, "poisoning is not contention");
        assert_eq!(ring.len(), 1, "capture must survive a poisoned lock");
    }

    #[test]
    fn a_long_message_is_clipped_visibly() {
        let long = "x".repeat(MAX_MESSAGE_LEN * 2);
        let out = truncate_message(long);
        assert!(out.len() <= MAX_MESSAGE_LEN + '…'.len_utf8());
        assert!(out.ends_with('…'), "a clipped line must show it is clipped");
    }

    #[test]
    fn truncation_lands_on_a_char_boundary() {
        // A multi-byte char straddling the cut would panic `String::truncate`.
        let s = "à".repeat(MAX_MESSAGE_LEN); // 2 bytes each
        let out = truncate_message(s);
        assert!(out.ends_with('…'));
        assert!(out.is_char_boundary(out.len() - '…'.len_utf8()));
    }

    #[test]
    fn level_maps_only_the_three_captured_levels() {
        assert_eq!(LogLevel::from_tracing(&Level::ERROR), Some(LogLevel::Error));
        assert_eq!(LogLevel::from_tracing(&Level::WARN), Some(LogLevel::Warn));
        assert_eq!(LogLevel::from_tracing(&Level::INFO), Some(LogLevel::Info));
        assert_eq!(LogLevel::from_tracing(&Level::DEBUG), None);
        assert_eq!(LogLevel::from_tracing(&Level::TRACE), None);
    }

    // ── The composed stack ────────────────────────────────────────────
    //
    // These drive `subscriber()` — the same fmt+EnvFilter+ring stack
    // `main.rs` builds, because that is the thing that has to be right.
    // Against the layer alone they would assert our own `enabled()` and
    // prove nothing about what the daemon installs.
    //
    // `set_default` (thread-local), never `set_global_default`: the lib
    // test binary's global slot is already claimed by
    // `dns::handler::GateRefusalCapture`.

    /// A `MakeWriter` that keeps what the `fmt` layer wrote, so a test can
    /// assert on the LOG FILE side of the composition and not only on the
    /// ring side.
    #[derive(Clone, Default)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("test writer").extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedBuf {
        type Writer = SharedBuf;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn stack_capturing(
        ring: Arc<LogRing>,
        directive: &str,
        sink: SharedBuf,
    ) -> impl tracing::Subscriber {
        subscriber(EnvFilter::new(directive), false, sink, ring)
    }

    #[test]
    fn debug_events_still_reach_the_log_file() {
        // The Logs tab must not silence the daemon's own logging. An
        // `enabled()` override on the layer would do exactly that:
        // `Layered::enabled` ANDs across layers, so one layer answering
        // `false` for DEBUG disables that callsite for the `fmt` layer
        // too — at `--log-level debug` the operator's log file would have
        // gone quiet the day this tab shipped. This is the pin on the
        // per-layer filter; it was RED against the first draft of this
        // module, which did override `enabled`.
        let ring = Arc::new(LogRing::new(10));
        let sink = SharedBuf::default();
        {
            let _guard = tracing::subscriber::set_default(stack_capturing(
                Arc::clone(&ring),
                "debug",
                sink.clone(),
            ));
            tracing::debug!("a debug line the operator asked for");
        }
        let written = String::from_utf8(sink.0.lock().expect("test writer").clone())
            .expect("fmt output is utf8");
        assert!(
            written.contains("a debug line the operator asked for"),
            "the fmt layer lost the line: {written:?}"
        );
        assert!(ring.is_empty(), "and it must not have entered the ring");
    }

    #[test]
    fn the_capture_layer_declares_an_info_ceiling() {
        // A layer whose `max_level_hint` is `None` lifts the process-wide
        // max to TRACE, un-disabling every `debug!` callsite on the query
        // path. The per-layer filter is what supplies the hint, so this
        // asserts on the FILTERED layer — what `capture_layer` builds.
        let layer = LogRingLayer::new(Arc::new(LogRing::new(1))).with_filter(CAPTURE_FLOOR);
        assert_eq!(
            Layer::<tracing_subscriber::Registry>::max_level_hint(&layer),
            Some(LevelFilter::INFO),
            "the ring layer must declare an INFO ceiling"
        );
    }

    fn stack(ring: Arc<LogRing>, directive: &str) -> impl tracing::Subscriber {
        subscriber(EnvFilter::new(directive), false, std::io::sink, ring)
    }

    #[test]
    fn the_composed_stack_captures_info_warn_and_error() {
        let ring = Arc::new(LogRing::new(10));
        {
            let _guard = tracing::subscriber::set_default(stack(Arc::clone(&ring), "info"));
            tracing::error!("boom");
            tracing::warn!("careful");
            tracing::info!("fyi");
        }
        let seen = ring.snapshot(10, None, None);
        assert_eq!(seen.len(), 3);
        assert_eq!(seen[0].level, LogLevel::Info);
        assert_eq!(seen[2].level, LogLevel::Error);
        assert_eq!(seen[2].message, "boom");
    }

    #[test]
    fn debug_events_never_enter_the_ring() {
        // Corner pin on the ring's CONTENT. Note it is guarded twice —
        // by the per-layer filter AND by the `from_tracing` belt in
        // `on_event` — so it does NOT go red when the floor alone is
        // mutated. `the_capture_layer_declares_an_info_ceiling` is the
        // single-guarded pin on the floor itself; this one exists so a
        // future refactor that removes both is caught.
        let ring = Arc::new(LogRing::new(10));
        {
            let _guard = tracing::subscriber::set_default(stack(Arc::clone(&ring), "debug"));
            tracing::debug!("per-query noise");
            tracing::trace!("even noisier");
            tracing::info!("this one counts");
        }
        let seen = ring.snapshot(10, None, None);
        assert_eq!(seen.len(), 1, "only the info line may be captured");
        assert_eq!(seen[0].message, "this one counts");
    }

    #[test]
    fn the_env_filter_still_governs_what_reaches_the_ring() {
        // The ring is downstream of the operator's `--log-level`, not a
        // way around it. At `warn` an info line must not be captured.
        let ring = Arc::new(LogRing::new(10));
        {
            let _guard = tracing::subscriber::set_default(stack(Arc::clone(&ring), "warn"));
            tracing::info!("below the operator's floor");
            tracing::warn!("at the floor");
        }
        let seen = ring.snapshot(10, None, None);
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].level, LogLevel::Warn);
    }

    #[test]
    fn structured_fields_are_carried_next_to_the_message() {
        // `warn!(source = %id, "refresh failed")` is useless without id.
        let ring = Arc::new(LogRing::new(10));
        {
            let _guard = tracing::subscriber::set_default(stack(Arc::clone(&ring), "info"));
            tracing::warn!(source = "list-x", attempt = 3, "refresh failed");
        }
        let seen = ring.snapshot(10, None, None);
        assert_eq!(seen.len(), 1);
        assert!(
            seen[0].message.starts_with("refresh failed"),
            "message leads: {:?}",
            seen[0].message
        );
        assert!(
            seen[0].message.contains("source=list-x"),
            "{:?}",
            seen[0].message
        );
        assert!(
            seen[0].message.contains("attempt=3"),
            "{:?}",
            seen[0].message
        );
    }

    #[test]
    fn the_target_is_captured_for_free_from_the_callsite() {
        let ring = Arc::new(LogRing::new(10));
        {
            let _guard = tracing::subscriber::set_default(stack(Arc::clone(&ring), "info"));
            tracing::info!("hello");
        }
        let seen = ring.snapshot(10, None, None);
        assert_eq!(seen[0].target, "purge_warden::tracking::log_ring::tests");
    }
}
