//! Append-only query log with buffered writes and calendar rotation.
//!
//! Entries are sent via a bounded channel from the DNS handler hot path
//! to a background writer task. The writer buffers entries and flushes
//! periodically (1 s) or when the buffer is full.
//!
//! Rotation (Sprint 38 QLP2) is **calendar-based**: at UTC midnight the
//! writer closes `query.log`, renames it to `query.log.YYYY-MM-DD`
//! with yesterday's date, and opens a fresh `query.log`. `max_size_mb`
//! survives as a **per-day backstop** only — if a single day's traffic
//! exceeds it, the file is rotated mid-day to
//! `query.log.YYYY-MM-DD.N` so the calendar stream stays intact.
//! Files older than `retention_days` are pruned on every midnight
//! rotation (names that don't parse as a dated sibling are ignored).
//!
//! Cabled into the hot path via `StatsEngine::log_query_event`, which is
//! a no-op when no writer is attached. `start.rs` builds the writer at
//! daemon startup and at every `handle_reload` that flips
//! `query_log_enabled` from `false` to `true`; the engine's
//! `attach_query_log` / `detach_query_log` pair (Sprint 38 QLP1) drives
//! the atomic swap on the engine's `ArcSwap<Option<Arc<QueryLog>>>` slot.
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

/// Mode for a query-log file warden creates.
///
/// The log records every domain every device on the network asked for, so
/// it is the same class of data as the config audit trail — and gets the
/// same bits as [`crate::config::audit::AUDIT_FILE_MODE`]. The constants
/// are deliberately separate symbols: `tracking` and `config::audit` are
/// unrelated subsystems that happen to agree on a value, not one policy
/// with two call sites.
///
/// Without an explicit mode the file lands at `0o666 & !umask`, which is
/// `0o600` under the unit's `UMask=0077` but `0o644` — world-readable —
/// in a manual foreground run or when `query_log_path` points outside the
/// `0o750` state directory.
const QUERY_LOG_FILE_MODE: u32 = 0o640;

/// A single query log entry (serialized as one JSON line).
///
/// `Debug` is intentionally NOT derived (M-39): `client_ip`, `client_name`,
/// and `domain` are PII and must not surface through `?entry` /
/// `panic!("{entry:?}")` / `assert_eq!` failure messages. Use the explicit
/// [`Display`](std::fmt::Display) impl below when an operator-facing
/// textual form is needed —
/// it emits only the non-PII metadata (timestamp, query type, result,
/// response time), which the FIX_PLAN identifies as "enough for
/// correlation".
#[derive(Clone, Serialize, Deserialize)]
pub struct QueryLogEntry {
    pub timestamp: String,
    pub client_ip: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    pub domain: String,
    pub query_type: String,
    pub result: String,
    pub response_time_us: u64,
    /// §4.5 Sprint 2/2 — offending hop in a CNAME chain block. `Some(name)`
    /// when the result is a CNAME chain block (the original `domain` is the
    /// queried apex; `cname_chain_via` is the hop in the chain that
    /// triggered the block). `None` for any non-CNAME-block outcome.
    /// `#[serde(default)]` keeps pre-S4.5-P2 JSONL files parseable —
    /// missing field reads back as `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cname_chain_via: Option<String>,
    /// §4.12 — original qname when a per-profile rewrite fired. The
    /// `domain` field carries the rewritten (effective) name used for
    /// resolution; `rewrote_from` is the name the client asked for.
    /// `None` on every query that didn't rewrite. `#[serde(default)]`
    /// keeps pre-§4.12 JSONL files parseable — missing field reads
    /// back as `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewrote_from: Option<String>,
}

impl std::fmt::Display for QueryLogEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "<QueryLogEntry timestamp={} query_type={} result={} response_time_us={} \
             client_ip=*** client_name=*** domain=***>",
            self.timestamp, self.query_type, self.result, self.response_time_us
        )
    }
}

/// Channel capacity for query log entries.
const LOG_CHANNEL_CAP: usize = 1024;

/// Flush buffer after this many entries.
const FLUSH_THRESHOLD: usize = 100;

/// Counters for the three silent-drop surfaces on the query-log write path
/// (H-20). Atomics-only — the sender increment runs on the daemon hot path
/// (DNS handler → `log_query_event` → `QueryLog::log`), and the writer-task
/// increments run in the background flush loop. `Relaxed` ordering matches
/// the rest of `tracking/`: these are diagnostic counters, not synchronisation
/// barriers, and the only memory they fence is themselves.
///
/// Each counter pinpoints a distinct degradation mode so the operator's
/// `warden status` triage can name what's wrong:
///
/// * `channel_full` — the bounded sender's `try_send` returned
///   `TrySendError::Full` because the writer task is consuming slower than
///   the DNS handler is producing. Indicates disk-flush back-pressure or
///   an over-busy single-tenant runtime.
/// * `flush_open_errors` — `OpenOptions::open` on the active log file
///   failed inside the writer task (e.g. parent dir removed, EACCES after a
///   permission churn). Whole buffer is cleared; counter increments once
///   per failed open (i.e. once per flush cycle, not once per entry).
/// * `flush_write_errors` — `writeln!` into the opened file returned an
///   `io::Error` (disk full, device disconnected). Increments once per
///   entry that failed to land — a fully-failing flush of 100 entries
///   bumps the counter by 100 so the rate of loss is visible.
#[derive(Debug, Default)]
pub(super) struct QueryLogDropCounters {
    pub channel_full: AtomicU64,
    pub flush_open_errors: AtomicU64,
    pub flush_write_errors: AtomicU64,
}

/// Plain-data snapshot of [`QueryLogDropCounters`], handed back to
/// `StatsEngine::query_log_drop_counters` and onward to the IPC `Status`
/// response. Defaulting to all-zeros keeps `#[serde(default)]` decode
/// compat with pre-T2.9 daemons clean.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryLogDropSnapshot {
    pub channel_full: u64,
    pub flush_open_errors: u64,
    pub flush_write_errors: u64,
}

impl QueryLogDropCounters {
    pub(super) fn snapshot(&self) -> QueryLogDropSnapshot {
        QueryLogDropSnapshot {
            channel_full: self.channel_full.load(Ordering::Relaxed),
            flush_open_errors: self.flush_open_errors.load(Ordering::Relaxed),
            flush_write_errors: self.flush_write_errors.load(Ordering::Relaxed),
        }
    }
}

/// Query log writer handle — holds the sender side of the channel.
pub struct QueryLog {
    tx: mpsc::Sender<QueryLogEntry>,
    task: tokio::task::JoinHandle<()>,
    drops: Arc<QueryLogDropCounters>,
}

impl QueryLog {
    /// Start the query log writer. Returns the handle for sending entries.
    ///
    /// `max_size_bytes` is a **per-day backstop** (Sprint 38 QLP2): if a
    /// single day's traffic exceeds this, the file is rotated mid-day
    /// with a numeric suffix (`query.log.YYYY-MM-DD.N`) so the daily
    /// calendar stream is not corrupted. Normal operation is one file
    /// per day.
    ///
    /// `max_files_per_day` caps the number of numeric-suffix overflow
    /// files per day before the oldest is dropped (runaway-day guard).
    ///
    /// `retention_days` drives deletion at each UTC-midnight rotation —
    /// files older than `retention_days` whose name parses as
    /// `query.log.YYYY-MM-DD*` are removed.
    pub fn start(
        path: PathBuf,
        max_size_bytes: u64,
        max_files_per_day: usize,
        retention_days: u32,
    ) -> Self {
        let (tx, rx) = mpsc::channel(LOG_CHANNEL_CAP);
        let drops = Arc::new(QueryLogDropCounters::default());
        let task = tokio::spawn(writer_loop(
            rx,
            path,
            max_size_bytes,
            max_files_per_day,
            retention_days,
            Arc::clone(&drops),
        ));
        Self { tx, task, drops }
    }

    /// Send an entry to the log writer (non-blocking, drops if channel full).
    pub fn log(&self, entry: QueryLogEntry) {
        // try_send avoids blocking the hot path; on Full, bump the
        // counter so the operator can see the channel is saturating.
        if self.tx.try_send(entry).is_err() {
            self.drops.channel_full.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Drop-counter snapshot for `warden status` (H-20).
    pub fn drop_counters(&self) -> QueryLogDropSnapshot {
        self.drops.snapshot()
    }

    /// Shutdown: drop sender, wait for writer to flush.
    pub async fn shutdown(self) {
        drop(self.tx);
        let _ = self.task.await;
    }
}

/// Current UTC calendar date — the single source of truth for daily
/// rotation. UTC is deliberate: operators in different timezones all
/// see the same daily rollover. Do not "fix" this to local time —
/// mixed-timezone households and cross-DST days would produce
/// unpredictable filenames.
fn today_utc() -> time::Date {
    time::OffsetDateTime::now_utc().date()
}

/// Background writer loop: receive entries, buffer, flush to file,
/// rotate at UTC midnight (Sprint 38 QLP2).
///
/// Day-change detection runs on every iteration. The loop wakes at
/// least once per second (flush timeout), so the midnight rotation
/// fires within ≤ 1 second of UTC 00:00:00.
async fn writer_loop(
    mut rx: mpsc::Receiver<QueryLogEntry>,
    path: PathBuf,
    max_size_bytes: u64,
    max_files_per_day: usize,
    retention_days: u32,
    drops: Arc<QueryLogDropCounters>,
) {
    let mut buffer: Vec<QueryLogEntry> = Vec::with_capacity(FLUSH_THRESHOLD);
    let flush_interval = Duration::from_secs(1);
    let mut current_day = today_utc();

    loop {
        let entry = tokio::time::timeout(flush_interval, rx.recv()).await;

        let should_exit = match entry {
            Ok(Some(e)) => {
                buffer.push(e);
                // Drain any additional ready entries
                while buffer.len() < FLUSH_THRESHOLD {
                    match rx.try_recv() {
                        Ok(e) => buffer.push(e),
                        Err(_) => break,
                    }
                }
                if buffer.len() >= FLUSH_THRESHOLD {
                    flush_buffer(
                        &mut buffer,
                        &path,
                        max_size_bytes,
                        max_files_per_day,
                        current_day,
                        &drops,
                    );
                }
                false
            }
            Ok(None) => {
                // Channel closed — flush remaining and exit
                if !buffer.is_empty() {
                    flush_buffer(
                        &mut buffer,
                        &path,
                        max_size_bytes,
                        max_files_per_day,
                        current_day,
                        &drops,
                    );
                }
                true
            }
            Err(_) => {
                // Timeout — flush whatever we have
                if !buffer.is_empty() {
                    flush_buffer(
                        &mut buffer,
                        &path,
                        max_size_bytes,
                        max_files_per_day,
                        current_day,
                        &drops,
                    );
                }
                false
            }
        };

        if should_exit {
            return;
        }

        // Daily rotation check — runs after every flush so yesterday's
        // pending entries always land in yesterday's file.
        let today = today_utc();
        if today != current_day {
            if !buffer.is_empty() {
                flush_buffer(
                    &mut buffer,
                    &path,
                    max_size_bytes,
                    max_files_per_day,
                    current_day,
                    &drops,
                );
            }
            rotate_daily(&path, current_day);
            prune_old_files(&path, retention_days);
            current_day = today;
        }
    }
}

/// Write buffered entries to the log file, rotating if needed.
fn flush_buffer(
    buffer: &mut Vec<QueryLogEntry>,
    path: &Path,
    max_size_bytes: u64,
    max_files_per_day: usize,
    today: time::Date,
    drops: &QueryLogDropCounters,
) {
    // Check if the per-day size backstop kicks in before writing.
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.len() >= max_size_bytes {
            rotate_on_size_backstop(path, today, max_files_per_day);
        }
    }

    // `.mode()` supplies the `mode` argument of `open(2)`, which the kernel
    // applies ONLY when `O_CREAT` actually creates the file, and then ANDs
    // with the process umask. Two consequences, both wanted:
    //
    //  * it is a ceiling, not a guarantee — under `UMask=0077` the file
    //    still lands at `0o600`, which is tighter, never wider;
    //  * an EXISTING file keeps whatever mode it has. Warden must not
    //    re-mode a log the operator deliberately loosened, and this runs on
    //    every flush, so forcing the bits here would fight them forever and
    //    cost a `chmod(2)` per flush. `AuditWriter::append` settles for the
    //    same ceiling for the same reason; only the one-time
    //    `AuditWriter::open` forces the exact mode.
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(QUERY_LOG_FILE_MODE)
        .open(path);

    match file {
        Ok(f) => {
            // M-37: BufWriter aggregates per-entry writes into 8 KB
            // syscalls; serde_json::to_writer writes JSON bytes
            // directly into the buffer with no intermediate `String`
            // allocation per entry. Default capacity is 8 KB —
            // adequate for a typical 100-entry batch (~150-200 bytes
            // per entry) so most batches fit into 1-3 syscalls.
            let mut writer = std::io::BufWriter::new(f);
            let mut buffered_entries: u64 = 0;
            for entry in buffer.drain(..) {
                // BufWriter aggregates writes; per-entry failure only
                // surfaces when the internal buffer hits a syscall
                // boundary and the underlying `write` returns Err.
                // `serde_json::to_writer` and `BufWriter::write_all`
                // return different error types; chain via `map_err` to
                // unify on `io::Error` so the failure check stays a
                // single boolean branch.
                let res = serde_json::to_writer(&mut writer, &entry)
                    .map_err(std::io::Error::other)
                    .and_then(|()| writer.write_all(b"\n"));
                if res.is_err() {
                    drops.flush_write_errors.fetch_add(1, Ordering::Relaxed);
                } else {
                    buffered_entries += 1;
                }
            }
            // Force the final syscall. If it fails, the entries that
            // landed in the BufWriter never reached disk — bump
            // `flush_write_errors` by the buffered count so the H-20
            // loss rate stays accurate (T2.9 baseline: a fully-failing
            // flush of 100 entries should bump the counter by ~100).
            if writer.flush().is_err() {
                drops
                    .flush_write_errors
                    .fetch_add(buffered_entries, Ordering::Relaxed);
            }
        }
        Err(e) => {
            drops.flush_open_errors.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(error = %e, path = %path.display(), "cannot open query log");
            buffer.clear();
        }
    }
}

/// Midnight-UTC rollover (Sprint 38 QLP2): rename `query.log` →
/// `query.log.<yesterday_date>`. Idempotent — if `query.log` doesn't
/// exist, or if yesterday's dated file already exists (e.g. restart
/// across midnight), fall through to the numeric-suffix backstop so
/// no history is overwritten.
fn rotate_daily(path: &Path, yesterday: time::Date) {
    if !path.exists() {
        return;
    }
    let base = daily_path(path, yesterday, None);
    if !base.exists() {
        if let Err(e) = std::fs::rename(path, &base) {
            tracing::warn!(error = %e, from = %path.display(), to = %base.display(), "daily rotation rename failed");
        }
        return;
    }
    // Collision: hand off to the backstop so today's entries land in a
    // new `query.log.<yesterday>.N` rather than clobbering the existing
    // dated file.
    for idx in 1..=MAX_MIDNIGHT_COLLISION_SUFFIX {
        let candidate = daily_path(path, yesterday, Some(idx));
        if !candidate.exists() {
            if let Err(e) = std::fs::rename(path, &candidate) {
                tracing::warn!(
                    error = %e,
                    from = %path.display(),
                    to = %candidate.display(),
                    "daily rotation collision rename failed"
                );
            }
            return;
        }
    }
    // M-38: do NOT `remove_file(path)` here. Pre-fix the writer
    // destroyed the day's active log on collision exhaustion — a
    // pathological-but-real scenario (clogged log dir, hand-dropped
    // sibling files, restart loop across midnight) would silently
    // wipe live data. Leave the file in place and keep appending;
    // tomorrow's rotation runs against a different date and is
    // overwhelmingly likely to succeed. Surface the situation as
    // `error!` (not `warn!`) so it lands in the operator's alert
    // channel — the dated log files are accumulating and need manual
    // cleanup before this writer can rotate cleanly again.
    tracing::error!(
        path = %path.display(),
        "daily rotation exhausted all {MAX_MIDNIGHT_COLLISION_SUFFIX} collision suffixes; \
         leaving query.log in place — clear stale `query.log.<date>*` siblings to unblock rotation"
    );
}

/// Safety cap on the collision-suffix loop inside `rotate_daily`. In
/// practice one or two collisions are plausible on a daemon restart
/// sequence across midnight; anything above that is pathological.
const MAX_MIDNIGHT_COLLISION_SUFFIX: usize = 100;

/// Same-day size-backstop rotation (Sprint 38 QLP2): a single day
/// exceeded `max_size_bytes`, so rotate `query.log` →
/// `query.log.<today>.<N>` where N is the next free suffix up to
/// `max_files_per_day`. Once all suffixes are used, the oldest is
/// dropped and the others are shifted up — mirrors the pre-S38
/// size-only scheme but anchored to the day so the daily calendar
/// stream stays intact.
fn rotate_on_size_backstop(path: &Path, today: time::Date, max_files_per_day: usize) {
    if max_files_per_day == 0 {
        return;
    }
    for idx in 1..=max_files_per_day {
        let candidate = daily_path(path, today, Some(idx));
        if !candidate.exists() {
            let _ = std::fs::rename(path, &candidate);
            return;
        }
    }
    // All suffixes occupied: drop the oldest, shift others up, then
    // rotate.
    let oldest = daily_path(path, today, Some(1));
    let _ = std::fs::remove_file(&oldest);
    for idx in 1..max_files_per_day {
        let from = daily_path(path, today, Some(idx + 1));
        let to = daily_path(path, today, Some(idx));
        let _ = std::fs::rename(&from, &to);
    }
    let last = daily_path(path, today, Some(max_files_per_day));
    let _ = std::fs::rename(path, &last);
}

/// Build the dated rotation path:
///   `None`      → `<parent>/<stem>.YYYY-MM-DD`
///   `Some(n)`   → `<parent>/<stem>.YYYY-MM-DD.<n>`
///
/// Replaces the pre-S38 numeric-only `rotated_path`. Sprint 38 QLP2
/// §3 calls for the same signature so the reader (QLP4) can compose
/// daily paths without reinventing the encoding.
pub(super) fn daily_path(path: &Path, date: time::Date, backstop_idx: Option<usize>) -> PathBuf {
    let date_fmt = time::macros::format_description!("[year]-[month]-[day]");
    let date_str = date.format(&date_fmt).unwrap_or_default();
    let mut p = path.as_os_str().to_owned();
    p.push(".");
    p.push(&date_str);
    if let Some(n) = backstop_idx {
        p.push(format!(".{n}"));
    }
    PathBuf::from(p)
}

/// Sprint 38 QLP6: one-shot migration of pre-S38 size-rotated
/// siblings (`query.log.1`..`.9`) to the new calendar-based naming
/// (`query.log.YYYY-MM-DD`) using each file's mtime as the date.
///
/// Idempotent: if no legacy `query.log.N` files exist, this is a
/// silent no-op. Collision with an existing dated sibling (e.g. the
/// daemon already rotated today and then an operator dropped in an
/// old `.1` by hand) falls through to the numeric backstop suffix so
/// no history is overwritten.
///
/// Files whose numeric suffix parses but whose mtime is invalid are
/// skipped and logged — the migrator never panics on malformed state
/// because it runs before the writer task starts; any failure that
/// blocks startup would be a self-inflicted DoS.
pub fn migrate_legacy_rotated_files(path: &Path) {
    let Some(parent) = path.parent() else {
        return;
    };
    let stem = match path.file_name().and_then(|s| s.to_str()) {
        Some(s) => s.to_string(),
        None => return,
    };
    let date_fmt = time::macros::format_description!("[year]-[month]-[day]");

    let mut migrated_any = false;
    for n in 1..=9u32 {
        let legacy = parent.join(format!("{stem}.{n}"));
        if !legacy.exists() {
            continue;
        }
        let Ok(meta) = std::fs::metadata(&legacy) else {
            continue;
        };
        let Ok(mtime_sys) = meta.modified() else {
            tracing::warn!(
                path = %legacy.display(),
                "legacy rotation migrator: mtime unavailable, skipping"
            );
            continue;
        };
        let mtime: time::OffsetDateTime = mtime_sys.into();
        let date = mtime.to_offset(time::UtcOffset::UTC).date();
        let Ok(date_str) = date.format(&date_fmt) else {
            continue;
        };

        let primary = parent.join(format!("{stem}.{date_str}"));
        let target = if !primary.exists() {
            primary
        } else {
            // Collision: pick the first free backstop suffix.
            let mut chosen = None;
            for idx in 1..=MAX_MIDNIGHT_COLLISION_SUFFIX {
                let candidate = parent.join(format!("{stem}.{date_str}.{idx}"));
                if !candidate.exists() {
                    chosen = Some(candidate);
                    break;
                }
            }
            match chosen {
                Some(c) => c,
                None => {
                    tracing::warn!(
                        path = %legacy.display(),
                        "legacy rotation migrator: all collision slots taken, leaving file in place"
                    );
                    continue;
                }
            }
        };

        if let Err(e) = std::fs::rename(&legacy, &target) {
            tracing::warn!(
                error = %e,
                from = %legacy.display(),
                to = %target.display(),
                "legacy rotation migrator: rename failed"
            );
            continue;
        }
        tracing::info!(
            from = %legacy.display(),
            to = %target.display(),
            "migrated legacy rotated query log to calendar filename"
        );
        migrated_any = true;
    }

    if migrated_any {
        // D8 follow-up: surface the semantics change to operators who
        // are clearly migrating from a pre-S38 install.
        tracing::warn!(
            "query log: `query_log_max_size_mb` is now a per-day backstop, \
             not the primary retention knob. Legacy `query.log.N` files \
             have been renamed using their mtime. Consider setting \
             `retention_days = 7` in [tracking] if you haven't already."
        );
    }
}

/// Sprint 38 QLP2: delete `query.log.YYYY-MM-DD*` siblings whose
/// embedded date is older than `retention_days`. Files whose names
/// don't parse as a dated sibling of `path` are ignored — a
/// hand-dropped `query.log.backup` or an operator's `.tar.gz` snapshot
/// is not touched.
pub(super) fn prune_old_files(path: &Path, retention_days: u32) {
    let Some(parent) = path.parent() else {
        return;
    };
    let stem = match path.file_name().and_then(|s| s.to_str()) {
        Some(s) => s.to_string(),
        None => return,
    };
    let prefix = format!("{stem}.");
    let today = today_utc();
    let cutoff = match today.checked_sub(time::Duration::days(retention_days as i64)) {
        Some(d) => d,
        None => return,
    };

    let entries = match std::fs::read_dir(parent) {
        Ok(it) => it,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(|s| s.to_string()) else {
            continue;
        };
        let Some(rest) = name.strip_prefix(&prefix) else {
            continue;
        };
        // The date portion is the first 10 chars; anything after a
        // second `.` is the backstop suffix and is irrelevant for the
        // age test.
        let date_part = rest.split('.').next().unwrap_or(rest);
        let date_fmt = time::macros::format_description!("[year]-[month]-[day]");
        let Ok(date) = time::Date::parse(date_part, &date_fmt) else {
            continue;
        };
        if date < cutoff {
            if let Err(e) = std::fs::remove_file(entry.path()) {
                tracing::warn!(
                    error = %e,
                    path = %entry.path().display(),
                    "prune_old_files: rm failed"
                );
            }
        }
    }
}

/// Resolve the absolute query-log path regardless of whether the writer
/// is currently attached. Shared by the writer (at daemon startup) and
/// the reader (at every IPC poll) so they never disagree about where
/// the file lives.
///
/// Absolute inputs are returned as-is. Relative inputs (including the
/// default `./query.log`) are joined against the daemon's mutable-state
/// directory so a `/etc/purge-warden/config.toml` install puts the log
/// at `/var/lib/purge-warden/query.log` — aligned with the rest of the
/// FHS state tree. Dev / single-file installs resolve relative paths
/// beside the config as before.
///
/// Never consults `std::env::current_dir` — the daemon's cwd is `/`
/// under systemd, and the Sprint 37 bug that motivated this helper was
/// precisely the reader using that cwd as a fallback.
pub fn resolved_query_log_path(configured: &Path, config_path: &Path) -> PathBuf {
    let raw = if configured.is_absolute() {
        configured.to_path_buf()
    } else {
        crate::cli::commands::start::state_dir_for(
            config_path.parent().unwrap_or_else(|| Path::new(".")),
        )
        .join(configured)
    };
    // Sprint 39: drop embedded `./` components so log lines read
    // `/var/lib/purge-warden/query.log` instead of the cosmetically
    // ugly `/var/lib/purge-warden/./query.log` produced by joining a
    // `./query.log` onto the state dir. POSIX treats them as
    // identical so no filesystem behaviour changes — this is purely
    // operator-facing.
    let cleaned: PathBuf = raw
        .components()
        .filter(|c| !matches!(c, std::path::Component::CurDir))
        .collect();
    if cleaned.as_os_str().is_empty() {
        raw
    } else {
        cleaned
    }
}

/// Resume point for the next (older) page of the query log.
///
/// **`(file, offset)`, not a bare offset** — `read_log_entries_with_state`
/// walks the rotated `query.log.YYYY-MM-DD` siblings, so a page boundary
/// can land in a different file from the one the page started in. An
/// offset alone cannot say which.
///
/// `offset` is the byte offset of the **oldest entry already returned**,
/// so the next page walks backward over `[0, offset)` — an exclusive end.
/// The log is append-only, so an offset into bytes already written is
/// stable across polls; that is what lets a paged-back TUI keep
/// re-fetching the same page on its 3 s tick without drifting.
///
/// `inode` is the anti-rotation guard. Rotation renames `query.log` to
/// `query.log.DATE` and opens a fresh one at the same path, after which
/// `offset` addresses unrelated bytes. Comparing `st_ino` on resume turns
/// that from "silently wrong rows in an audit tool" into an explicit
/// `cursor_stale` and a restart from the live tail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryLogCursor {
    /// Absolute path of the file the next page resumes in.
    pub file: String,
    /// Exclusive end offset — the next page reads `[0, offset)`.
    pub offset: u64,
    /// `st_ino` of `file` when the cursor was minted.
    pub inode: u64,
}

/// The filter chain, resolved once per request instead of once per file.
///
/// Two properties are the reason this is a struct and not four more
/// parameters:
///
/// 1. **The needles are lowered exactly once.** `tail_collect_from` used to
///    lower them per call, and `read_log_entries_with_state` calls it once
///    per rotated sibling — so a 7-day read lowered each needle seven
///    times. Holding [`LoweredNeedle`]s here makes it once per request,
///    and the type invariant survives because `LoweredNeedle::new` is
///    still the only constructor.
/// 2. **It is owned.** `handle_query_logs` moves the whole filter set into
///    a `spawn_blocking` closure, which needs `'static`.
#[derive(Debug, Clone, Default)]
pub struct QueryLogFilters {
    client: Option<LoweredNeedle>,
    blocked_only: bool,
    domain: Option<LoweredNeedle>,
    cutoff_epoch: Option<i64>,
    /// Tier-1 advanced client filter, already compiled. `None` when the
    /// operator has not opened the form — the additive property in one
    /// field: the `c` / `/` / `b` / `t` controls behave exactly as before.
    advanced: Option<AdvancedFilter>,
}

impl QueryLogFilters {
    /// Build the chain, lowering both needles once.
    pub fn new(
        client: Option<&str>,
        blocked_only: bool,
        domain: Option<&str>,
        cutoff_epoch: Option<i64>,
    ) -> Self {
        Self {
            client: client.map(LoweredNeedle::new),
            blocked_only,
            domain: domain.map(LoweredNeedle::new),
            cutoff_epoch,
            advanced: None,
        }
    }

    /// Attach the compiled Tier-1 advanced filter. An empty one is
    /// dropped rather than stored, so the per-row path pays nothing when
    /// the operator has not used the form.
    pub fn with_advanced(mut self, advanced: AdvancedFilter) -> Self {
        self.advanced = (!advanced.is_empty()).then_some(advanced);
        self
    }

    /// The absolute epoch cutoff, if a time window is active.
    pub fn cutoff_epoch(&self) -> Option<i64> {
        self.cutoff_epoch
    }
}

/// One page of the query log plus everything the caller needs to ask for
/// the next one.
///
/// `Debug` is intentionally NOT derived, for the same reason
/// [`QueryLogEntry`] does not derive it (M-39): the entries carry
/// `client_ip` / `client_name` / `domain`, and a derived `Debug` on the
/// wrapper would put all three back into `?page` and into `assert_eq!`
/// failure messages — re-opening the PII leak through the container.
pub struct QueryLogPage {
    pub entries: Vec<QueryLogEntry>,
    /// State of the **primary** `query.log`, unchanged in meaning from
    /// the pre-paging reader: it drives the TUI's empty-state picker and
    /// says nothing about the siblings.
    pub file_state: crate::ipc::protocol::QueryLogFileState,
    /// Resume point for the next older page. `None` means the walk
    /// reached the end of the retained window — there is nothing older.
    pub next_cursor: Option<QueryLogCursor>,
    /// The supplied cursor named a file that had rotated (or vanished)
    /// under it, so this page was served from the live tail instead. The
    /// TUI resets its page index and says so rather than presenting
    /// unrelated rows as page N.
    pub cursor_stale: bool,
}

/// What one file's reverse walk yielded, and where to resume inside it.
struct TailSlice {
    entries: Vec<QueryLogEntry>,
    /// Byte offset of the **oldest** entry pushed, i.e. the exclusive end
    /// for the next walk over this same file. `None` when nothing matched,
    /// which means the walk consumed the file (or the cutoff cut it off)
    /// and the next page belongs to an older sibling.
    ///
    /// Sound because pushes are strictly offset-decreasing: within a chunk
    /// the walker pops lines newest-first, the pre-newline `head` is older
    /// than every line after it, and each subsequent chunk starts lower.
    oldest_offset: Option<u64>,
}

/// Tail-read the last `limit` entries (matching the filters) from a
/// single query log file (Sprint 38 QLP4).
///
/// Seeks to EOF and walks backwards in 8 KB chunks, parsing complete
/// JSON-line entries and applying the filters as it goes. Stops when
/// it has collected `limit` matches or reaches BOF. Total I/O is
/// `O(returned entries + chunk_size)` — at S38 scale (700 MB across a
/// week) this keeps the 1 Hz TUI poll in the microsecond range.
///
/// Returns the same `QueryLogFileState` vocabulary as the multi-file
/// variant so callers don't need to distinguish path types.
pub fn read_log_entries_tail(
    path: &Path,
    limit: usize,
    client_filter: Option<&str>,
    blocked_only: bool,
    domain_filter: Option<&str>,
    cutoff_epoch: Option<i64>,
) -> (Vec<QueryLogEntry>, crate::ipc::protocol::QueryLogFileState) {
    let filters = QueryLogFilters::new(client_filter, blocked_only, domain_filter, cutoff_epoch);
    let (slice, state) = read_one_file_tail(path, None, limit, &filters);
    (slice.entries, state)
}

/// Open `path`, resolve the walk's exclusive end offset, and run the
/// reverse walk once. `end_offset` of `None` means "start at EOF".
///
/// Split out of [`read_log_entries_tail`] so the paged reader can call it
/// per file in the rotated chain without re-implementing the open /
/// classify dance, and so `QueryLogFileState` keeps exactly one producer.
fn read_one_file_tail(
    path: &Path,
    end_offset: Option<u64>,
    limit: usize,
    filters: &QueryLogFilters,
) -> (TailSlice, crate::ipc::protocol::QueryLogFileState) {
    use crate::ipc::protocol::QueryLogFileState;
    let empty = || TailSlice {
        entries: Vec::new(),
        oldest_offset: None,
    };
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return (empty(), QueryLogFileState::Missing);
        }
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "query log unreadable"
            );
            return (empty(), QueryLogFileState::Unreadable);
        }
    };
    // A cursor offset is clamped to the current length rather than
    // trusted: a truncate-in-place (logrotate `copytruncate`) leaves the
    // inode intact, so the inode guard cannot catch it and a seek past
    // EOF would read nothing with no diagnostic.
    let start = match file.seek(SeekFrom::End(0)) {
        Ok(eof) => end_offset.map_or(eof, |o| o.min(eof)),
        Err(_) => return (empty(), QueryLogFileState::Unreadable),
    };
    (
        tail_collect_from(&mut file, start, limit, filters),
        QueryLogFileState::Ok,
    )
}

/// Core reverse-chunk walker. Separated from `read_log_entries_tail`
/// so the rotated-file walker can reuse the same I/O logic on each
/// sibling without re-opening-by-path semantics.
///
/// Walks backward over `[0, start_offset)` — `start_offset` is an
/// **exclusive** end, so passing the offset of an already-returned entry
/// resumes strictly below it. Passing EOF reads the live tail, which is
/// what every pre-paging caller does.
///
/// `filters.cutoff_epoch` activates Sprint 41 early termination: once at
/// least one entry has been pushed AND we observe `CUTOFF_TOLERANCE_MISSES`
/// consecutive entries older than the cutoff, the walker stops.
/// The tolerance window absorbs out-of-order clusters near the boundary.
///
/// Every byte index into `chunk` maps to file offset `pos + i`, including
/// after the carry is appended: `carry` holds exactly the bytes at
/// `[pos + read_size, pos + read_size + carry.len())`, so the buffer stays
/// contiguous in file terms. That identity is what makes the returned
/// `oldest_offset` a real byte position and not a guess.
fn tail_collect_from(
    file: &mut std::fs::File,
    start_offset: u64,
    limit: usize,
    filters: &QueryLogFilters,
) -> TailSlice {
    const CHUNK: u64 = 8 * 1024;
    let mut pos = start_offset;

    // `carry` holds bytes from an earlier chunk whose line-start lies
    // in a chunk we haven't read yet. Reassembled by prepending the
    // next chunk's bytes (older on disk).
    let mut carry: Vec<u8> = Vec::new();
    let mut entries: Vec<QueryLogEntry> = Vec::with_capacity(limit.min(64));
    let mut oldest_offset: Option<u64> = None;
    let mut consec_older: usize = 0;

    // Nested loops mean `break` alone can't exit the outer one; a
    // labelled block lets early termination unwind cleanly.
    'outer: while pos > 0 && entries.len() < limit {
        let read_size = pos.min(CHUNK);
        pos -= read_size;
        if file.seek(SeekFrom::Start(pos)).is_err() {
            break;
        }
        let mut chunk = vec![0u8; read_size as usize];
        if file.read_exact(&mut chunk).is_err() {
            break;
        }
        // Append carry: chunk bytes come FIRST (older in file), carry
        // bytes LAST (newer, held over from the previous iteration).
        chunk.extend_from_slice(&carry);
        carry.clear();

        // The first newline in `chunk` marks the boundary between
        // "bytes that belong to a line which started in an even-older
        // chunk" (left of the newline) and "bytes that form complete
        // lines reachable within this chunk" (right of the newline,
        // plus held-over carry).
        let first_nl = chunk.iter().position(|&b| b == b'\n');
        match first_nl {
            None => {
                // No newline at all — everything is still incomplete;
                // keep carrying. Edge case: BOF reached with no
                // newline means the whole buffer is one final line.
                if pos == 0 {
                    let outcome =
                        classify_line(&chunk, &mut entries, limit, filters, 0, &mut oldest_offset);
                    if update_cutoff_counter(outcome, &mut consec_older, &entries) {
                        break 'outer;
                    }
                } else {
                    carry = chunk;
                }
            }
            Some(nl_idx) => {
                // Bytes [nl_idx+1 .. end] contain zero or more
                // complete lines terminated by '\n' (or terminated by
                // the held-over carry boundary). Iterate them in
                // reverse so entries get pushed newest-first.
                //
                // Offsets are accumulated by hand rather than taken from
                // `split`, which does not expose them: consecutive
                // segments start `len + 1` apart (the +1 is the '\n' the
                // split consumed), and the run starts at `pos + nl_idx + 1`.
                let complete = &chunk[nl_idx + 1..];
                let base = pos + nl_idx as u64 + 1;
                let mut lines: Vec<(u64, &[u8])> = Vec::new();
                let mut rel = 0usize;
                for seg in complete.split(|&b| b == b'\n') {
                    if !seg.is_empty() {
                        lines.push((base + rel as u64, seg));
                    }
                    rel += seg.len() + 1;
                }
                while let Some((line_at, line)) = lines.pop() {
                    let outcome = classify_line(
                        line,
                        &mut entries,
                        limit,
                        filters,
                        line_at,
                        &mut oldest_offset,
                    );
                    if update_cutoff_counter(outcome, &mut consec_older, &entries) {
                        break 'outer;
                    }
                    if entries.len() >= limit {
                        break;
                    }
                }
                if entries.len() >= limit {
                    break;
                }
                // Bytes [0..nl_idx]: if we've reached BOF, these are
                // the first complete line of the file; otherwise
                // they're the tail of a line that continues into an
                // earlier chunk — save as carry.
                let head = &chunk[..nl_idx];
                if pos == 0 {
                    let outcome =
                        classify_line(head, &mut entries, limit, filters, 0, &mut oldest_offset);
                    if update_cutoff_counter(outcome, &mut consec_older, &entries) {
                        break 'outer;
                    }
                } else {
                    carry = head.to_vec();
                }
            }
        }
    }

    TailSlice {
        entries,
        oldest_offset,
    }
}

/// Fold a `classify_line` outcome into the running `consec_older`
/// counter and report whether the reverse walker should now terminate.
/// Returns `true` iff the tolerance window has been exhausted *and* at
/// least one matching entry is already in `entries`. The "at least
/// one" guard is what makes a short test log with only out-of-scope
/// entries still scan to BOF — otherwise we would cut off too early
/// when no matches exist in-window.
#[inline]
fn update_cutoff_counter(
    outcome: LineOutcome,
    consec_older: &mut usize,
    entries: &[QueryLogEntry],
) -> bool {
    match outcome {
        LineOutcome::Pushed => {
            *consec_older = 0;
            false
        }
        LineOutcome::Rejected => false,
        LineOutcome::OlderThanCutoff => {
            *consec_older += 1;
            !entries.is_empty() && *consec_older > CUTOFF_TOLERANCE_MISSES
        }
    }
}

/// Outcome of classifying a single candidate line in the reverse walker.
/// The tail walker needs more information than "push or not": when a time
/// cutoff is active, crossing the cutoff boundary is a separate signal
/// that enables early termination (Sprint 41). Unparseable bytes, empty
/// bytes, and entries that fail the substring filters are collapsed into
/// `Rejected` — callers that only need "pushed vs not" can treat it as a
/// binary outcome.
#[derive(Debug, Clone, Copy)]
enum LineOutcome {
    Pushed,
    Rejected,
    OlderThanCutoff,
}

/// How many consecutive `OlderThanCutoff` lines a caller may observe
/// before the reverse walker is allowed to stop. Small but non-zero so
/// out-of-order clusters near the cutoff boundary (clock skew, concurrent
/// writers flushing in interleaved order) don't abort the scan
/// prematurely. Sprint 41 §5.3.
const CUTOFF_TOLERANCE_MISSES: usize = 64;

/// Parse a single candidate line, apply the filter chain, and push onto
/// `entries` if it matches. Returns the outcome so the caller can drive
/// cutoff-based early termination. Silently drops junk (unparseable JSON,
/// empty bytes) — this is a reader, not a validator.
#[inline]
fn classify_line(
    bytes: &[u8],
    entries: &mut Vec<QueryLogEntry>,
    limit: usize,
    filters: &QueryLogFilters,
    line_at: u64,
    oldest_offset: &mut Option<u64>,
) -> LineOutcome {
    if entries.len() >= limit || bytes.is_empty() {
        return LineOutcome::Rejected;
    }
    let Ok(s) = std::str::from_utf8(bytes) else {
        return LineOutcome::Rejected;
    };
    let Ok(entry) = serde_json::from_str::<QueryLogEntry>(s) else {
        return LineOutcome::Rejected;
    };
    if let Some(cutoff) = filters.cutoff_epoch {
        // Unparseable timestamp → treat as a plain `Rejected`. Neither
        // pushing a mangled entry nor letting it signal "cross the
        // cutoff" is correct, so the conservative choice is to make it
        // non-load-bearing for the early-termination heuristic.
        if let Some(ts) = parse_timestamp_epoch(&entry.timestamp) {
            if ts < cutoff {
                return LineOutcome::OlderThanCutoff;
            }
        }
    }
    if !entry_matches_filters(&entry, filters) {
        return LineOutcome::Rejected;
    }
    entries.push(entry);
    // The walk is strictly offset-decreasing, so every push overwrites
    // this with a lower value and the final one is the oldest returned
    // row — the exclusive end for the next page.
    *oldest_offset = Some(line_at);
    LineOutcome::Pushed
}

/// Parse a log-line timestamp into a unix-seconds epoch. Returns `None`
/// on any parse failure; callers treat that as a rejected line.
///
/// Parses with the SAME well-known RFC 3339 description the writer
/// formats with (`StatsEngine::log_query_event` in `engine.rs`), so the
/// reader and writer share ONE format definition and cannot drift apart.
///
/// query-log-02 (rev-2606): the previous hand-rolled
/// `[...]:[second]Z` description had no fractional-seconds field, so it
/// returned `None` for every production line — the writer emits RFC 3339
/// with nanoseconds (`...:57.745067301Z`) — which silently disabled the
/// `since` time-window filter (the age cutoff in `classify_line` never
/// fired, and the reverse scan never early-terminated). RFC 3339 accepts
/// optional subseconds, so this parses both real production output and
/// the second-precision test fixtures. Uses the `time` crate per
/// project rules common-pitfalls ("don't use chrono").
fn parse_timestamp_epoch(ts: &str) -> Option<i64> {
    time::OffsetDateTime::parse(ts, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(|odt| odt.unix_timestamp())
}

/// A filter needle that is already ASCII-lowercased.
///
/// The invariant is a type and not a comment on purpose. `entry_matches_filters`
/// runs once per log line inside `tail_collect`'s reverse chunk walk, so lowering
/// the needle there would be one allocation per line of a file that can be
/// hundreds of megabytes. Lowering it in the caller is only correct for as long
/// as every caller remembers to — and a comment saying so does not fail a build.
/// [`LoweredNeedle::new`] is the only way to make one, and it lowers.
#[derive(Debug, Clone)]
struct LoweredNeedle(String);

impl LoweredNeedle {
    fn new(needle: &str) -> Self {
        Self(needle.to_ascii_lowercase())
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

/// ASCII-case-insensitive `str::contains`, allocating nothing.
///
/// `needle` must already be lowercase — hold a [`LoweredNeedle`] and this is
/// true by construction. Only the haystack byte is folded, one byte at a time,
/// so neither side is copied. Deliberately ASCII-only: domains are ASCII after
/// IDNA, and a full Unicode fold would need an allocation and a table for a
/// case this filter never sees.
fn contains_ascii_ci(haystack: &str, needle: &str) -> bool {
    let (hay, ndl) = (haystack.as_bytes(), needle.as_bytes());
    if ndl.is_empty() {
        return true;
    }
    if ndl.len() > hay.len() {
        return false;
    }
    hay.windows(ndl.len())
        .any(|w| w.iter().zip(ndl).all(|(h, n)| h.to_ascii_lowercase() == *n))
}

/// A `*`-only glob, ASCII-lowercased once at construction.
///
/// **Not a regex, and that is the requirement rather than a
/// simplification.** This pattern comes straight from an operator's
/// keystrokes into a form whose match runs once per line of a file that
/// can be hundreds of megabytes. A regex engine on that input owns
/// catastrophic backtracking. A `*`-only glob cannot backtrack at all:
/// for a pattern `A*B*C` the leftmost match of each middle segment is
/// always optimal, because taking a later one can only shrink the
/// haystack still available to the segments after it. So the scan is
/// linear and single-pass by construction, not by care.
///
/// A pattern with no `*` is a **substring** match — the semantics the `c`
/// filter has always had, so the advanced form does not quietly redefine
/// what an operator already knows. `*` is the only metacharacter; `?` and
/// character classes are deliberately absent, which leaves one rule to
/// explain and no escape syntax to get wrong.
///
/// Case folding matches [`contains_ascii_ci`] exactly: segments are
/// lowered here, once, and only the haystack byte is folded during the
/// scan. Lowering the haystack per row would allocate once per log line
/// and undo the property [`LoweredNeedle`] exists to hold.
#[derive(Debug, Clone)]
pub struct Glob {
    /// Literal segments between `*`s, already ASCII-lowercased.
    segments: Vec<String>,
    /// `false` for a pattern with no `*` — matched as a substring.
    anchored: bool,
}

impl Glob {
    pub fn new(pattern: &str) -> Self {
        let lowered = pattern.to_ascii_lowercase();
        if lowered.contains('*') {
            Self {
                segments: lowered.split('*').map(str::to_string).collect(),
                anchored: true,
            }
        } else {
            Self {
                segments: vec![lowered],
                anchored: false,
            }
        }
    }

    pub fn matches(&self, hay: &str) -> bool {
        if !self.anchored {
            return contains_ascii_ci(hay, &self.segments[0]);
        }
        let hb = hay.as_bytes();
        let first = self.segments[0].as_bytes();
        let last = self.segments[self.segments.len() - 1].as_bytes();
        // Head and tail are anchored and may not overlap: `a*b` must not
        // match `"a"` by letting the same byte serve both ends.
        if hb.len() < first.len() + last.len() {
            return false;
        }
        if !eq_ascii_ci(&hb[..first.len()], first) {
            return false;
        }
        if !eq_ascii_ci(&hb[hb.len() - last.len()..], last) {
            return false;
        }
        let mut pos = first.len();
        let end = hb.len() - last.len();
        for seg in &self.segments[1..self.segments.len().saturating_sub(1)] {
            let s = seg.as_bytes();
            // `**` yields an empty middle segment; it constrains nothing.
            if s.is_empty() {
                continue;
            }
            match find_ascii_ci(&hb[pos..end], s) {
                Some(i) => pos += i + s.len(),
                None => return false,
            }
        }
        pos <= end
    }
}

/// Byte-wise ASCII-case-insensitive equality. `b` must already be lowered.
fn eq_ascii_ci(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.to_ascii_lowercase() == *y)
}

/// First index at which `needle` (already lowered) occurs in `hay`,
/// folding only the haystack. Allocates nothing.
fn find_ascii_ci(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() > hay.len() {
        return None;
    }
    hay.windows(needle.len())
        .position(|w| eq_ascii_ci(w, needle))
}

/// Whether a predicate selects rows that match it or rows that do not.
///
/// INCLUDE / EXCLUDE per predicate, ANDed across predicates. There is no
/// OR, by operator decision: OR costs precedence, grouping, and a way to
/// render the live expression in a footer already short of cells, and
/// AND-with-per-predicate-polarity already covers the stated cases
/// ("everything except the IoT devices"). OR waits for evidence it is
/// needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Polarity {
    #[default]
    Include,
    Exclude,
}

impl Polarity {
    /// Fold a raw predicate hit into a keep/drop decision.
    #[inline]
    fn keeps(self, hit: bool) -> bool {
        match self {
            Self::Include => hit,
            Self::Exclude => !hit,
        }
    }
}

/// The Tier-1 advanced client filter, **already parsed**.
///
/// Every pattern is compiled and every CIDR parsed once, in
/// [`QueryLogFilters::with_advanced`], so the per-row cost is a match and
/// never a parse. A malformed CIDR is dropped at construction rather than
/// re-failing per line.
///
/// **Subnet is a row-local test, not a resolved set of known client IPs.**
/// Resolving a CIDR against the device table would silently drop queries
/// from *unmapped* devices in that subnet — and unmapped devices are
/// routine enough that the Devices tab has a whole column for them. The
/// design classes subnet as Tier 1 "needs nothing new" for exactly this
/// reason. `Cidr` is a pure parse-and-contains value type; holding one
/// here resolves no configuration, which is what the "no config in the
/// walker" rule actually forbids.
///
/// `client_ip_set` is the seam for Tier 2 (owner / department /
/// device-type). Those genuinely need a Labels join, and that join must
/// happen **before** the walk and arrive here as a plain set — the walker
/// stays dumb, the per-row test is a set lookup, and include/exclude
/// falls out as set membership negated.
#[derive(Debug, Clone, Default)]
pub struct AdvancedFilter {
    name: Option<(Glob, Polarity)>,
    ip: Option<(Glob, Polarity)>,
    subnets: Option<(Vec<crate::config::cidr::Cidr>, Polarity)>,
    client_ip_set: Option<(std::collections::HashSet<IpAddr>, Polarity)>,
}

impl AdvancedFilter {
    pub fn with_name(mut self, pattern: &str, polarity: Polarity) -> Self {
        self.name = Some((Glob::new(pattern), polarity));
        self
    }

    pub fn with_ip(mut self, pattern: &str, polarity: Polarity) -> Self {
        self.ip = Some((Glob::new(pattern), polarity));
        self
    }

    /// Parse one or more CIDRs. Unparseable entries are dropped; if
    /// **none** parse the predicate is not installed at all, so a typo
    /// leaves the operator with an unfiltered view rather than an empty
    /// one — the failure is visible in the row count instead of looking
    /// like "no traffic from that subnet".
    pub fn with_subnets<I: IntoIterator<Item = S>, S: AsRef<str>>(
        mut self,
        cidrs: I,
        polarity: Polarity,
    ) -> Self {
        let parsed: Vec<crate::config::cidr::Cidr> = cidrs
            .into_iter()
            .filter_map(|c| crate::config::cidr::Cidr::parse(c.as_ref()).ok())
            .collect();
        self.subnets = (!parsed.is_empty()).then_some((parsed, polarity));
        self
    }

    /// Tier-2 seam: a client-IP set resolved before the walk.
    pub fn with_client_ip_set(
        mut self,
        ips: std::collections::HashSet<IpAddr>,
        polarity: Polarity,
    ) -> Self {
        self.client_ip_set = Some((ips, polarity));
        self
    }

    pub fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.ip.is_none()
            && self.subnets.is_none()
            && self.client_ip_set.is_none()
    }

    /// AND across predicates, each with its own polarity.
    #[inline]
    fn matches(&self, e: &QueryLogEntry) -> bool {
        if let Some((glob, pol)) = &self.name {
            // A row with no client name cannot match a name pattern. Under
            // EXCLUDE that means it is KEPT, which is the right reading:
            // "not the laptop" includes every unnamed device.
            let hit = e.client_name.as_deref().is_some_and(|n| glob.matches(n));
            if !pol.keeps(hit) {
                return false;
            }
        }
        if let Some((glob, pol)) = &self.ip {
            if !pol.keeps(glob.matches(&e.client_ip.to_string())) {
                return false;
            }
        }
        if let Some((cidrs, pol)) = &self.subnets {
            if !pol.keeps(cidrs.iter().any(|c| c.contains(e.client_ip))) {
                return false;
            }
        }
        if let Some((ips, pol)) = &self.client_ip_set {
            if !pol.keeps(ips.contains(&e.client_ip)) {
                return false;
            }
        }
        true
    }
}

fn entry_matches_filters(e: &QueryLogEntry, filters: &QueryLogFilters) -> bool {
    if filters.blocked_only && e.result != "BLOCKED" {
        return false;
    }
    if let Some(client) = filters.client.as_ref() {
        // Sprint 41: substring match, symmetric with the domain arm
        // below. Operators typing a partial name or an IP prefix used
        // to get zero hits under the old exact-match semantics; the
        // asymmetry was a usability papercut called out by the operator.
        let name_match = e
            .client_name
            .as_deref()
            .is_some_and(|n| contains_ascii_ci(n, client.as_str()));
        let ip_match = contains_ascii_ci(&e.client_ip.to_string(), client.as_str());
        if !name_match && !ip_match {
            return false;
        }
    }
    if let Some(domain) = filters.domain.as_ref() {
        if !contains_ascii_ci(&e.domain, domain.as_str()) {
            return false;
        }
    }
    if let Some(adv) = filters.advanced.as_ref() {
        if !adv.matches(e) {
            return false;
        }
    }
    true
}

/// Read the last `limit` matching entries from the current `query.log`
/// and, if that doesn't satisfy the limit, walk the `query.log.YYYY-
/// MM-DD` siblings in reverse date order until it does (or the
/// retention cap is hit). Sprint 38 QLP4 extends the Sprint 37 helper
/// with multi-file awareness.
///
/// The returned `QueryLogFileState` describes the *current* file: `Ok`
/// if it was read successfully (even if empty), `Missing` if it
/// doesn't exist yet (fresh install), `Unreadable` on any other I/O
/// error. The TUI's empty-state renderer reads this directly.
pub fn read_log_entries_with_state(
    path: &Path,
    limit: usize,
    client_filter: Option<&str>,
    blocked_only: bool,
    domain_filter: Option<&str>,
    retention_days: u32,
    cutoff_epoch: Option<i64>,
) -> (Vec<QueryLogEntry>, crate::ipc::protocol::QueryLogFileState) {
    let filters = QueryLogFilters::new(client_filter, blocked_only, domain_filter, cutoff_epoch);
    let page = read_log_page(path, limit, &filters, retention_days, None);
    (page.entries, page.file_state)
}

/// Read one page of the query log, resuming from `cursor` when given.
///
/// `cursor = None` reads the live tail — byte-identical behaviour to
/// [`read_log_entries_with_state`], which is now a wrapper over this.
/// A cursor resumes strictly below the oldest row of the previous page,
/// which is what stops page *N* from re-walking pages *1..N-1*: the
/// pre-cursor reader always restarted from `SeekFrom::End(0)`, so paging
/// was quadratic in pages and only visibly so once the log was large —
/// exactly when paging is wanted.
///
/// The chain walked is `[query.log, query.log.<newest>, …]`, capped at
/// `retention_days` distinct dates. A cursor names its file by path and
/// pins it by inode, so a rotation mid-session is reported as
/// `cursor_stale` and served from the tail instead of silently returning
/// whatever now lives at that offset.
pub fn read_log_page(
    path: &Path,
    limit: usize,
    filters: &QueryLogFilters,
    retention_days: u32,
    cursor: Option<&QueryLogCursor>,
) -> QueryLogPage {
    // Newest-first: index 0 is the live file, the rest are rotated
    // siblings. Only index 0 can grow, which is why a cursor into any
    // sibling addresses frozen bytes.
    let chain: Vec<PathBuf> = std::iter::once(path.to_path_buf())
        .chain(dated_siblings_newest_first(path, retention_days))
        .collect();

    // Sprint 41: a sibling dated before the cutoff's calendar date cannot
    // carry any entry newer than the cutoff (timestamps inside are all on
    // that date or earlier), so it is never opened.
    let cutoff_date = filters.cutoff_epoch().and_then(|e| {
        time::OffsetDateTime::from_unix_timestamp(e)
            .ok()
            .map(|dt| dt.date())
    });

    let mut cursor_stale = false;
    let mut start_idx = 0usize;
    let mut start_off: Option<u64> = None;
    if let Some(c) = cursor {
        match chain.iter().position(|p| p.to_string_lossy() == c.file) {
            // The inode guard is the whole reason a stale cursor is
            // recoverable. Without it a rotation leaves the path valid
            // and the offset meaningless, and the operator is shown
            // unrelated rows labelled as the page they asked for.
            Some(i) if file_inode(&chain[i]) == Some(c.inode) => {
                start_idx = i;
                start_off = Some(c.offset);
            }
            _ => cursor_stale = true,
        }
    }

    let mut entries: Vec<QueryLogEntry> = Vec::new();
    // (chain index, exclusive end offset) of the oldest row returned so far.
    let mut resume: Option<(usize, u64)> = None;
    let mut primary_state: Option<crate::ipc::protocol::QueryLogFileState> = None;

    for (j, f) in chain.iter().enumerate().skip(start_idx) {
        if entries.len() >= limit {
            break;
        }
        if j > 0 {
            if let (Some(cutoff_d), Some(sibling_d)) = (cutoff_date, parse_sibling_date(path, f)) {
                if sibling_d < cutoff_d {
                    continue;
                }
            }
        }
        // Only the file the cursor named starts mid-file; every older
        // one starts at its own EOF.
        let end = if j == start_idx { start_off } else { None };
        let remaining = limit - entries.len();
        let (slice, state) = read_one_file_tail(f, end, remaining, filters);
        if j == 0 {
            primary_state = Some(state);
        }
        if let Some(off) = slice.oldest_offset {
            resume = Some((j, off));
        }
        entries.extend(slice.entries);
    }

    // A cursor is handed back only when the walk stopped because the page
    // filled. Walking the whole chain without filling it proves there is
    // nothing older, and offering a cursor there would promise a page that
    // does not exist. An `offset` of 0 is kept as-is rather than advanced
    // to the next file: `read_one_file_tail` seeks to 0, collects nothing,
    // and the loop falls through to the older sibling on its own.
    let next_cursor = if limit > 0 && entries.len() >= limit {
        resume.and_then(|(j, off)| {
            file_inode(&chain[j]).map(|inode| QueryLogCursor {
                file: chain[j].to_string_lossy().into_owned(),
                offset: off,
                inode,
            })
        })
    } else {
        None
    };

    QueryLogPage {
        entries,
        // Always describes the PRIMARY file, even when this page was
        // served entirely from a sibling — it drives the TUI's
        // empty-state picker, which is a statement about `query.log`.
        file_state: primary_state.unwrap_or_else(|| probe_file_state(path)),
        next_cursor,
        cursor_stale,
    }
}

/// `st_ino` of `path`, or `None` if it cannot be stat'd.
fn file_inode(path: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|m| m.ino())
}

/// Classify the primary log file without reading it. Used when a cursor
/// starts the page in a rotated sibling, so the loop never touches index
/// 0 but the response must still say whether `query.log` is healthy.
fn probe_file_state(path: &Path) -> crate::ipc::protocol::QueryLogFileState {
    use crate::ipc::protocol::QueryLogFileState;
    match std::fs::File::open(path) {
        Ok(_) => QueryLogFileState::Ok,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => QueryLogFileState::Missing,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "query log unreadable");
            QueryLogFileState::Unreadable
        }
    }
}

/// Parse the `YYYY-MM-DD` date from a rotated-sibling filename such as
/// `query.log.2026-04-20` or `query.log.2026-04-20.3`. Returns `None`
/// for paths that aren't dated siblings — `read_log_entries_with_state`
/// treats those as "keep scanning" (conservative).
fn parse_sibling_date(primary: &Path, sibling: &Path) -> Option<time::Date> {
    let stem = primary.file_name()?.to_str()?;
    let name = sibling.file_name()?.to_str()?;
    let rest = name.strip_prefix(&format!("{stem}."))?;
    let date_part = rest.split('.').next()?;
    let fmt = time::macros::format_description!("[year]-[month]-[day]");
    time::Date::parse(date_part, &fmt).ok()
}

/// Return dated siblings of `path` (shape `query.log.YYYY-MM-DD` or
/// `query.log.YYYY-MM-DD.N`) sorted newest-first and capped at
/// `retention_days`. Files whose names don't parse against the
/// expected shape are ignored — matches the `prune_old_files`
/// tolerance so a hand-dropped `query.log.backup` never gets read
/// during a poll.
fn dated_siblings_newest_first(path: &Path, retention_days: u32) -> Vec<PathBuf> {
    let Some(parent) = path.parent() else {
        return Vec::new();
    };
    let stem = match path.file_name().and_then(|s| s.to_str()) {
        Some(s) => s.to_string(),
        None => return Vec::new(),
    };
    let prefix = format!("{stem}.");
    let entries = match std::fs::read_dir(parent) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let date_fmt = time::macros::format_description!("[year]-[month]-[day]");
    let mut dated: Vec<(time::Date, u32, PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(|s| s.to_string()) else {
            continue;
        };
        let Some(rest) = name.strip_prefix(&prefix) else {
            continue;
        };
        // Date part is always the first 10 chars of `rest`; anything
        // after a second `.` is the backstop index (for tie-breaking
        // within a day).
        let mut parts = rest.splitn(2, '.');
        let date_part = parts.next().unwrap_or("");
        let suffix_part = parts.next();
        let Ok(date) = time::Date::parse(date_part, &date_fmt) else {
            continue;
        };
        let suffix_idx: u32 = suffix_part.and_then(|s| s.parse().ok()).unwrap_or(0);
        dated.push((date, suffix_idx, entry.path()));
    }
    // Newest-first. For the same date, higher backstop suffix is
    // newer (the writer uses next-available-suffix within a day).
    dated.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
    // Window by distinct DATES, not file count (rev-2606 style
    // roundup): a single day can own several size-backstop siblings
    // (`query.log.DATE`, `query.log.DATE.1`, …). Truncating at
    // `retention_days` *files* would let one busy day consume multiple
    // day-slots and silently shrink the multi-file read window below
    // `retention_days` days. Siblings of one date are contiguous after
    // the sort, so a single pass that advances the day counter only on
    // a date change keeps every backstop of an in-window day.
    let mut kept = Vec::new();
    let mut days_seen = 0u32;
    let mut last_date: Option<time::Date> = None;
    for (date, _suffix, path) in dated {
        if last_date != Some(date) {
            if days_seen >= retention_days {
                break;
            }
            days_seen += 1;
            last_date = Some(date);
        }
        kept.push(path);
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn sample_entry(domain: &str, blocked: bool) -> QueryLogEntry {
        QueryLogEntry {
            timestamp: "2026-04-08T15:00:00Z".into(),
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            client_name: Some("laptop".into()),
            domain: domain.into(),
            query_type: "A".into(),
            result: if blocked { "BLOCKED" } else { "ALLOWED" }.into(),
            response_time_us: 500,
            cname_chain_via: None,
            rewrote_from: None,
        }
    }

    #[test]
    fn entry_serialization_roundtrip() {
        let entry = sample_entry("google.com", false);
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: QueryLogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.domain, "google.com");
        assert_eq!(parsed.result, "ALLOWED");
        assert_eq!(parsed.client_name, Some("laptop".into()));
    }

    #[test]
    fn entry_without_client_name() {
        let mut entry = sample_entry("test.com", true);
        entry.client_name = None;
        let json = serde_json::to_string(&entry).unwrap();
        assert!(!json.contains("client_name")); // skip_serializing_if = None
        let parsed: QueryLogEntry = serde_json::from_str(&json).unwrap();
        assert!(parsed.client_name.is_none());
    }

    #[test]
    fn entry_with_cname_chain_via_round_trips() {
        // §4.5 Sprint 2/2: a CNAME chain block populates
        // `cname_chain_via` with the offending hop. The TUI Query Log
        // renders this as `qname → offending` plus a `[CNAME]` badge.
        let mut entry = sample_entry("apex.example.com", true);
        entry.cname_chain_via = Some("offending.tracker.example".into());
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"cname_chain_via\":\"offending.tracker.example\""));
        let parsed: QueryLogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.cname_chain_via.as_deref(),
            Some("offending.tracker.example")
        );
    }

    #[test]
    fn entry_without_cname_chain_via_skips_field() {
        // Pre-S4.5-P2 / non-CNAME-block entries must not surface a
        // spurious `cname_chain_via: null` line — `skip_serializing_if`
        // keeps the JSONL bytes byte-identical to legacy entries.
        let entry = sample_entry("google.com", false);
        let json = serde_json::to_string(&entry).unwrap();
        assert!(!json.contains("cname_chain_via"));
    }

    #[test]
    fn legacy_entry_without_cname_chain_via_field_parses_as_none() {
        // Pre-S4.5-P2 JSONL files (and snapshots from older daemons)
        // do not carry the field. `#[serde(default)]` keeps them
        // readable — the field reads back as `None`.
        let legacy_json = r#"{
            "timestamp":"2026-04-08T15:00:00Z",
            "client_ip":"192.168.1.1",
            "client_name":"laptop",
            "domain":"google.com",
            "query_type":"A",
            "result":"ALLOWED",
            "response_time_us":500
        }"#;
        let parsed: QueryLogEntry = serde_json::from_str(legacy_json).unwrap();
        assert!(parsed.cname_chain_via.is_none());
    }

    #[test]
    fn resolved_query_log_path_passes_through_absolute_input() {
        let out = resolved_query_log_path(
            Path::new("/srv/alt/query.log"),
            Path::new("/tmp/any/config.toml"),
        );
        assert_eq!(out, PathBuf::from("/srv/alt/query.log"));
    }

    #[test]
    fn resolved_query_log_path_joins_relative_against_config_dir() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let out = resolved_query_log_path(Path::new("./query.log"), &config_path);
        assert_eq!(out, dir.path().join("query.log"));
    }

    #[test]
    fn resolved_query_log_path_redirects_etc_master_to_var_lib() {
        // Preserves the Sprint 34 state-dir redirection so the reader
        // looks where the writer actually writes on an FHS v1 install.
        let out = resolved_query_log_path(
            Path::new("./query.log"),
            Path::new("/etc/purge-warden/config.toml"),
        );
        assert_eq!(out, PathBuf::from("/var/lib/purge-warden/query.log"));
    }

    #[test]
    fn resolved_query_log_path_strips_embedded_curdir() {
        // Sprint 39: the legacy join of `./query.log` onto the state
        // dir leaked a `./` component into the final path, producing
        // cosmetically ugly log lines like
        // `/var/lib/purge-warden/./query.log`. The helper now
        // normalizes before returning.
        let out = resolved_query_log_path(
            Path::new("./query.log"),
            Path::new("/etc/purge-warden/config.toml"),
        );
        let s = out.to_string_lossy();
        assert!(
            !s.contains("/./"),
            "output {s} must not carry embedded `./` components"
        );
        assert_eq!(out, PathBuf::from("/var/lib/purge-warden/query.log"));
    }

    #[test]
    fn resolved_query_log_path_ignores_daemon_cwd() {
        // The helper must resolve relative inputs against the config
        // directory, never against `std::env::current_dir`. Proven by
        // resolving under an isolated tempdir and asserting the output
        // is anchored there, regardless of what the test process cwd is.
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let out = resolved_query_log_path(Path::new("./query.log"), &config_path);
        assert!(
            out.starts_with(dir.path()),
            "output {} should be anchored to {}",
            out.display(),
            dir.path().display()
        );
        assert!(!out.starts_with(std::env::current_dir().unwrap_or_default()));
    }

    // ── Sprint 38 QLP2: daily rotation + backstop + prune ────

    fn ymd(y: i32, m: u8, d: u8) -> time::Date {
        time::Date::from_calendar_date(y, time::Month::try_from(m).unwrap(), d).unwrap()
    }

    #[test]
    fn daily_rotate_renames_current_to_dated_and_opens_fresh() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");
        std::fs::write(&log_path, "yesterday's lines\n").unwrap();

        rotate_daily(&log_path, ymd(2026, 4, 22));

        assert!(!log_path.exists(), "query.log moved aside");
        let dated = dir.path().join("query.log.2026-04-22");
        assert!(dated.exists(), "yesterday's dated file created");
        assert_eq!(
            std::fs::read_to_string(&dated).unwrap(),
            "yesterday's lines\n"
        );
    }

    #[test]
    fn daily_rotate_is_idempotent_on_same_day() {
        // Second invocation is a safe no-op when the current file is
        // absent (already rotated). The writer re-creates it lazily on
        // next flush, so we just assert rotate_daily doesn't panic or
        // touch already-dated siblings.
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");
        let dated = dir.path().join("query.log.2026-04-22");
        std::fs::write(&log_path, "one\n").unwrap();

        rotate_daily(&log_path, ymd(2026, 4, 22));
        assert!(dated.exists());

        // Second call: no query.log to rename, so it's a no-op.
        rotate_daily(&log_path, ymd(2026, 4, 22));
        assert_eq!(std::fs::read_to_string(&dated).unwrap(), "one\n");
    }

    #[test]
    fn daily_rotate_handles_collision_via_backstop_suffix() {
        // If a restart-across-midnight scenario produced a file named
        // `query.log.<yesterday>` already, the second rotate_daily
        // must not clobber it — it hands off to the numeric backstop.
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");
        let dated = dir.path().join("query.log.2026-04-22");
        std::fs::write(&dated, "earlier\n").unwrap();
        std::fs::write(&log_path, "later\n").unwrap();

        rotate_daily(&log_path, ymd(2026, 4, 22));

        assert!(!log_path.exists());
        assert_eq!(std::fs::read_to_string(&dated).unwrap(), "earlier\n");
        let collision = dir.path().join("query.log.2026-04-22.1");
        assert_eq!(std::fs::read_to_string(&collision).unwrap(), "later\n");
    }

    #[test]
    fn same_day_size_backstop_produces_numeric_suffix() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");
        std::fs::write(&log_path, "overflow content\n").unwrap();

        rotate_on_size_backstop(&log_path, ymd(2026, 4, 23), 4);

        assert!(!log_path.exists());
        let first = dir.path().join("query.log.2026-04-23.1");
        assert!(first.exists(), "first backstop slot used");
        assert_eq!(
            std::fs::read_to_string(&first).unwrap(),
            "overflow content\n"
        );
    }

    #[test]
    fn same_day_size_backstop_shifts_and_drops_oldest() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");
        // Pre-fill the four slots with "1", "2", "3", "4" — then a new
        // overflow comes in and must push 1 out, shift the rest up.
        for idx in 1..=4u32 {
            std::fs::write(
                dir.path().join(format!("query.log.2026-04-23.{idx}")),
                format!("{idx}\n"),
            )
            .unwrap();
        }
        std::fs::write(&log_path, "5\n").unwrap();

        rotate_on_size_backstop(&log_path, ymd(2026, 4, 23), 4);

        assert!(!log_path.exists());
        for (idx, expected) in [(1u32, "2"), (2, "3"), (3, "4"), (4, "5")] {
            let p = dir.path().join(format!("query.log.2026-04-23.{idx}"));
            assert_eq!(
                std::fs::read_to_string(&p).unwrap().trim_end(),
                expected,
                "slot {idx} should hold {expected}"
            );
        }
    }

    #[test]
    fn prune_old_files_deletes_beyond_retention() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");

        let today = time::OffsetDateTime::now_utc().date();
        // Seed 10 dated files spanning 10 consecutive days up to today.
        for age in 0..10u32 {
            let date = today.checked_sub(time::Duration::days(age as i64)).unwrap();
            let name = format!(
                "query.log.{}",
                date.format(time::macros::format_description!("[year]-[month]-[day]"))
                    .unwrap()
            );
            std::fs::write(dir.path().join(&name), format!("day{age}\n")).unwrap();
        }
        std::fs::write(&log_path, "current\n").unwrap();

        prune_old_files(&log_path, 3);

        let kept: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();

        assert!(
            kept.iter().any(|n| n == "query.log"),
            "current file never pruned"
        );
        // Retention=3 keeps today + 2 days back (< cutoff test uses
        // strict less-than, so cutoff is today-3; anything >= cutoff
        // survives).
        let dated_kept = kept.iter().filter(|n| n.starts_with("query.log.2")).count();
        assert!(
            (3..=4).contains(&dated_kept),
            "expected 3-4 recent dated files to survive; kept: {kept:?}"
        );
    }

    #[test]
    fn prune_old_files_ignores_unrecognised_siblings() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");
        std::fs::write(&log_path, "current\n").unwrap();
        std::fs::write(dir.path().join("query.log.backup"), "hand\n").unwrap();
        std::fs::write(dir.path().join("query.log.save"), "hand\n").unwrap();
        std::fs::write(dir.path().join("other.txt"), "unrelated\n").unwrap();
        // An ancient dated file THAT IS under the prefix gets pruned —
        // use a distant past so it falls outside any plausible
        // retention window.
        std::fs::write(dir.path().join("query.log.2000-01-01"), "ancient\n").unwrap();

        prune_old_files(&log_path, 7);

        assert!(dir.path().join("query.log.backup").exists());
        assert!(dir.path().join("query.log.save").exists());
        assert!(dir.path().join("other.txt").exists());
        assert!(
            !dir.path().join("query.log.2000-01-01").exists(),
            "old dated file pruned"
        );
    }

    #[test]
    fn read_log_with_filters() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");

        let entries = vec![
            sample_entry("google.com", false),
            sample_entry("ads.com", true),
            sample_entry("facebook.com", false),
        ];

        let mut content = String::new();
        for e in &entries {
            content.push_str(&serde_json::to_string(e).unwrap());
            content.push('\n');
        }
        std::fs::write(&log_path, content).unwrap();

        // All entries
        let (all, state) = read_log_entries_tail(&log_path, 10, None, false, None, None);
        assert!(matches!(state, crate::ipc::protocol::QueryLogFileState::Ok));
        assert_eq!(all.len(), 3);

        // Blocked only
        let (blocked, _) = read_log_entries_tail(&log_path, 10, None, true, None, None);
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].domain, "ads.com");

        // Domain filter
        let (google, _) = read_log_entries_tail(&log_path, 10, None, false, Some("google"), None);
        assert_eq!(google.len(), 1);

        // Limit
        let (limited, _) = read_log_entries_tail(&log_path, 2, None, false, None, None);
        assert_eq!(limited.len(), 2);
    }

    // ── qlog-paging-cursor: resume cursor ────────────────────

    /// Domains long enough that the corpus below spans several 8 KB
    /// chunks. Deliberately unique per index so a duplicated or skipped
    /// row at a page boundary is detectable by set size alone.
    fn paging_domain(prefix: &str, i: u32) -> String {
        format!("{prefix}-{i:04}.paging-corpus.example.invalid")
    }

    fn write_paging_file(path: &Path, prefix: &str, n: u32) {
        let mut content = String::new();
        for i in 0..n {
            let e = sample_entry(&paging_domain(prefix, i), false);
            content.push_str(&serde_json::to_string(&e).unwrap());
            content.push('\n');
        }
        std::fs::write(path, content).unwrap();
    }

    /// Project entries to a comparable key. `QueryLogEntry` derives
    /// neither `Debug` nor `PartialEq` (M-39 — the fields are PII), so a
    /// test compares projections rather than the rows themselves.
    fn domains_of(entries: &[QueryLogEntry]) -> Vec<String> {
        entries.iter().map(|e| e.domain.clone()).collect()
    }

    /// Drain every page a cursor walk yields, newest to oldest.
    /// Returns `(all domains in order, number of pages, cursor files touched)`.
    fn drain_pages(
        path: &Path,
        limit: usize,
        filters: &QueryLogFilters,
        retention_days: u32,
    ) -> (Vec<String>, usize, Vec<String>) {
        let mut out = Vec::new();
        let mut pages = 0usize;
        let mut files = Vec::new();
        let mut cursor: Option<QueryLogCursor> = None;
        loop {
            let page = read_log_page(path, limit, filters, retention_days, cursor.as_ref());
            assert!(
                !page.cursor_stale,
                "no rotation happens in this test, so a stale cursor means the \
                 inode guard is misfiring"
            );
            pages += 1;
            out.extend(domains_of(&page.entries));
            match page.next_cursor {
                Some(c) => {
                    files.push(c.file.clone());
                    cursor = Some(c);
                }
                None => break,
            }
            assert!(pages < 100, "cursor walk failed to terminate");
        }
        (out, pages, files)
    }

    /// **The discriminating test.** Every other paging assertion is
    /// satisfiable by an off-by-one: "page 2 is non-empty and differs
    /// from page 1" passes with a one-row skip *and* with a one-row
    /// duplicate. Concatenating every page and demanding it equal the
    /// unpaged read element-wise, in order, at the same length, does not.
    ///
    /// The corpus is sized on purpose:
    /// * `> 2 × 8 KB` in the primary file alone, so page boundaries land
    ///   both inside a chunk and across one — a corpus inside a single
    ///   chunk never exercises the carry reassembly the offsets ride on;
    /// * `250` rows against a limit of `40`, i.e. `> 3 × limit`, so
    ///   there are real middle pages. A corpus of `≤ limit` makes page 2
    ///   empty and "paging works" vacuously true;
    /// * split `100 / 150` across `query.log` and one rotated sibling,
    ///   so page 3 crosses BOF of the primary. That crossing is the only
    ///   thing that proves the cursor must be `(file, offset)` — a bare
    ///   offset cannot say which file offset 0 belongs to.
    #[test]
    fn paged_reads_concatenate_to_the_unpaged_read() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");
        write_paging_file(&log_path, "p", 100);
        write_paging_file(&dir.path().join("query.log.2026-04-07"), "s", 150);

        let primary_len = std::fs::metadata(&log_path).unwrap().len();
        assert!(
            primary_len > 2 * 8 * 1024,
            "corpus must span >2 chunks or the boundary cases go unexercised; \
             primary is {primary_len} B"
        );

        let filters = QueryLogFilters::default();
        let unpaged = read_log_page(&log_path, 10_000, &filters, 7, None);
        let expected = domains_of(&unpaged.entries);
        assert_eq!(expected.len(), 250, "seeded corpus must read back whole");
        assert!(
            unpaged.next_cursor.is_none(),
            "a read that exhausted the chain must not offer a resume point"
        );

        let (paged, pages, cursor_files) = drain_pages(&log_path, 40, &filters, 7);

        assert_eq!(
            paged.len(),
            expected.len(),
            "paged walk returned {} rows against {} unpaged — a skip or a \
             duplicate at a page boundary",
            paged.len(),
            expected.len()
        );
        assert_eq!(paged, expected, "paged walk must reproduce order exactly");
        assert_eq!(
            paged.iter().collect::<std::collections::HashSet<_>>().len(),
            250,
            "a duplicated row would keep the length right and the set wrong"
        );
        assert!(
            pages >= 6,
            "40-row pages over 250 rows must page, got {pages}"
        );

        // The cursor crosses into the sibling: a bare offset could not.
        assert!(
            cursor_files.iter().any(|f| f.ends_with("query.log")),
            "early pages resume inside the primary: {cursor_files:?}"
        );
        assert!(
            cursor_files
                .iter()
                .any(|f| f.ends_with("query.log.2026-04-07")),
            "a page must resume inside the rotated sibling: {cursor_files:?}"
        );
    }

    /// Filters are applied *during* the walk, so a filtered page is not a
    /// fixed byte range — the walker keeps going until `limit` MATCHING
    /// rows. The identity has to survive that.
    ///
    /// The needle matches 100 of 250 rows against a limit of 40, so it is
    /// well below the cap: a needle that saturated the limit would make
    /// "same count" indistinguishable from "the filter is inert".
    #[test]
    fn paging_is_consistent_when_filters_run_during_the_walk() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");
        write_paging_file(&log_path, "p", 100);
        write_paging_file(&dir.path().join("query.log.2026-04-07"), "s", 150);

        // Every `p-` row and no `s-` row: 100 of 250.
        let filters = QueryLogFilters::new(None, false, Some("p-0"), None);
        let unpaged = read_log_page(&log_path, 10_000, &filters, 7, None);
        let expected = domains_of(&unpaged.entries);
        assert_eq!(
            expected.len(),
            100,
            "needle must select a strict subset well under the page limit, \
             or the comparison below is vacuous"
        );

        let (paged, pages, _) = drain_pages(&log_path, 40, &filters, 7);
        assert_eq!(paged, expected);
        assert!(pages >= 3, "100 matches at 40/page must span pages");

        // Negative control: a needle matching nothing must yield nothing
        // and offer no resume point. Without it, a walker that silently
        // ignored the filter would pass the assertion above by accident
        // on any corpus where the needle happens to match everything.
        let none = QueryLogFilters::new(None, false, Some("no-such-domain"), None);
        let empty = read_log_page(&log_path, 40, &none, 7, None);
        assert!(empty.entries.is_empty());
        assert!(empty.next_cursor.is_none());
    }

    /// Rotation renames `query.log` and opens a fresh one at the same
    /// path. The path stays valid and the offset stops meaning anything,
    /// so without the inode guard the operator is served unrelated rows
    /// under the label of the page they asked for.
    #[test]
    fn a_cursor_whose_file_rotated_is_reported_stale_not_silently_honoured() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");
        write_paging_file(&log_path, "p", 100);

        let filters = QueryLogFilters::default();
        let first = read_log_page(&log_path, 40, &filters, 7, None);
        let cursor = first.next_cursor.expect("100 rows at 40/page must page");

        // Rotate: same path, new inode, different content.
        std::fs::rename(&log_path, dir.path().join("query.log.2026-04-07")).unwrap();
        write_paging_file(&log_path, "fresh", 5);

        let after = read_log_page(&log_path, 40, &filters, 7, Some(&cursor));
        assert!(
            after.cursor_stale,
            "a rotated-out cursor must be reported, not honoured"
        );
        assert_eq!(
            after.entries.first().map(|e| e.domain.clone()),
            Some(paging_domain("fresh", 4)),
            "a stale cursor falls back to the live tail"
        );
    }

    /// The pre-paging entry points are wrappers now. They must still
    /// behave byte-identically, and the cheapest proof is that the
    /// wrapper and the paged reader agree on the same corpus.
    #[test]
    fn the_unpaged_wrapper_still_matches_a_cursorless_page() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");
        write_paging_file(&log_path, "p", 60);
        write_paging_file(&dir.path().join("query.log.2026-04-07"), "s", 60);

        let (legacy, state) =
            read_log_entries_with_state(&log_path, 75, None, false, None, 7, None);
        let page = read_log_page(&log_path, 75, &QueryLogFilters::default(), 7, None);
        assert_eq!(domains_of(&legacy), domains_of(&page.entries));
        assert_eq!(state, page.file_state);
        assert_eq!(legacy.len(), 75);
    }

    // ── qlog-advanced-filter-form: Tier-1 client predicates ──

    /// `*` semantics, the ASCII fold, and the two edge cases a
    /// head/tail-anchored matcher gets wrong if written carelessly:
    /// head and tail must not be allowed to overlap, and `**` must
    /// constrain nothing.
    #[test]
    fn glob_matches_star_patterns_case_insensitively() {
        assert!(Glob::new("*ioel*").matches("marco-IOEL-laptop"));
        assert!(Glob::new("*IOEL*").matches("marco-ioel-laptop"));
        assert!(Glob::new("host-*").matches("HOST-01"));
        assert!(Glob::new("*.example").matches("a.b.EXAMPLE"));
        assert!(Glob::new("*").matches(""));
        assert!(Glob::new("**").matches("anything"));
        assert!(Glob::new("a*b*c").matches("aXXbYYc"));
        assert!(!Glob::new("a*b*c").matches("acb"));

        // Head and tail must not share bytes: `ab` has no room for both
        // an `a` prefix and a `b` suffix plus the `*` between… but `ab`
        // DOES, and `a` does not.
        assert!(Glob::new("a*b").matches("ab"));
        assert!(!Glob::new("a*b").matches("a"));

        // No `*` at all == substring, matching what `c` has always meant.
        assert!(Glob::new("ioel").matches("marco-IOEL-laptop"));
        assert!(!Glob::new("ioel").matches("marco-laptop"));

        // A `*`-bearing pattern is ANCHORED, so it is strictly narrower
        // than the substring form — the distinction the operator is
        // buying by typing the star.
        assert!(!Glob::new("ioel*").matches("marco-ioel"));
        assert!(Glob::new("ioel*").matches("ioel-laptop"));
    }

    /// Exclude is the include predicate negated, per predicate — the
    /// operator's stated case is "everything except the IoT devices".
    #[test]
    fn exclude_polarity_inverts_only_its_own_predicate() {
        let mut e = sample_entry("one.example", false);
        e.client_name = Some("iot-bulb".into());
        e.client_ip = IpAddr::V4(Ipv4Addr::new(10, 10, 9, 4));

        let inc = QueryLogFilters::default()
            .with_advanced(AdvancedFilter::default().with_name("iot*", Polarity::Include));
        assert!(entry_matches_filters(&e, &inc));

        let exc = QueryLogFilters::default()
            .with_advanced(AdvancedFilter::default().with_name("iot*", Polarity::Exclude));
        assert!(!entry_matches_filters(&e, &exc));

        // AND across predicates: excluded by name, included by subnet →
        // still excluded. An OR would have kept it, which is exactly the
        // semantics that was declined.
        let both = QueryLogFilters::default().with_advanced(
            AdvancedFilter::default()
                .with_name("iot*", Polarity::Exclude)
                .with_subnets(["10.10.9.0/24"], Polarity::Include),
        );
        assert!(!entry_matches_filters(&e, &both));
    }

    /// A row with no `client_name` cannot match a name pattern, so under
    /// EXCLUDE it is KEPT. "not the laptop" has to include every unnamed
    /// device or the operator loses exactly the rows they were hunting.
    #[test]
    fn an_unnamed_client_survives_a_name_exclusion() {
        let mut e = sample_entry("one.example", false);
        e.client_name = None;

        let exc = QueryLogFilters::default()
            .with_advanced(AdvancedFilter::default().with_name("laptop", Polarity::Exclude));
        assert!(entry_matches_filters(&e, &exc));

        let inc = QueryLogFilters::default()
            .with_advanced(AdvancedFilter::default().with_name("laptop", Polarity::Include));
        assert!(!entry_matches_filters(&e, &inc));
    }

    /// **The reason subnet is a row-local CIDR test and not a resolved
    /// set of known client IPs.** An unmapped device — one the operator
    /// never put in `[[devices]]` — has no entry to resolve, so a set
    /// built from the device table would silently drop its queries. The
    /// device is exactly the one an operator paging the log is usually
    /// looking for.
    ///
    /// The `client_ip_set` arm below is the Tier-2 seam and is asserted
    /// alongside so the two stay visibly distinct.
    #[test]
    fn a_subnet_predicate_matches_devices_that_are_not_in_any_device_table() {
        let mut unmapped = sample_entry("one.example", false);
        unmapped.client_name = None;
        unmapped.client_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 231));

        let by_subnet = QueryLogFilters::default().with_advanced(
            AdvancedFilter::default().with_subnets(["192.0.2.0/24"], Polarity::Include),
        );
        assert!(
            entry_matches_filters(&unmapped, &by_subnet),
            "a CIDR test reaches an unmapped device; a resolved IP set would not"
        );

        // The Tier-2 shape, for contrast: a set resolved before the walk
        // contains only what the join produced.
        let known: std::collections::HashSet<IpAddr> = [IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5))]
            .into_iter()
            .collect();
        let by_set = QueryLogFilters::default()
            .with_advanced(AdvancedFilter::default().with_client_ip_set(known, Polarity::Include));
        assert!(!entry_matches_filters(&unmapped, &by_set));

        let outside = QueryLogFilters::default().with_advanced(
            AdvancedFilter::default().with_subnets(["192.168.0.0/16"], Polarity::Include),
        );
        assert!(!entry_matches_filters(&unmapped, &outside));
    }

    /// An all-blank form must install NOTHING. If it installed a
    /// predicate that matched everything the cost would be per row for no
    /// benefit; if it installed one that matched nothing the log would go
    /// blank for an operator who never opened the form.
    #[test]
    fn an_empty_advanced_filter_is_not_installed() {
        let e = sample_entry("one.example", false);
        let f = QueryLogFilters::default().with_advanced(AdvancedFilter::default());
        assert!(f.advanced.is_none());
        assert!(entry_matches_filters(&e, &f));
    }

    /// The advanced predicates AND with the pre-existing controls rather
    /// than replacing them — the additive property, at the filter level.
    #[test]
    fn advanced_predicates_and_with_the_existing_filters() {
        let mut e = sample_entry("ads.example.com", true);
        e.client_name = Some("laptop".into());

        let both = QueryLogFilters::new(None, true, Some("ads"), None)
            .with_advanced(AdvancedFilter::default().with_name("lap*", Polarity::Include));
        assert!(entry_matches_filters(&e, &both));

        // Same advanced predicate, but the pre-existing domain filter now
        // rejects: the row must be dropped.
        let domain_rejects = QueryLogFilters::new(None, true, Some("tracker"), None)
            .with_advanced(AdvancedFilter::default().with_name("lap*", Polarity::Include));
        assert!(!entry_matches_filters(&e, &domain_rejects));
    }

    /// An unparseable CIDR must not install a predicate that silently
    /// matches nothing. The daemon drops it; the TUI refuses it outright
    /// (`QLOG_FILTER_BAD_CIDR`), so a hand-built IPC call degrades to an
    /// unfiltered view rather than an empty one.
    #[test]
    fn an_unparseable_cidr_installs_no_subnet_predicate() {
        let e = sample_entry("one.example", false);
        let f = AdvancedFilter::default().with_subnets(["not-a-cidr"], Polarity::Include);
        assert!(f.is_empty(), "a filter of only-bad CIDRs is empty");
        assert!(entry_matches_filters(
            &e,
            &QueryLogFilters::default().with_advanced(f)
        ));
    }

    // ── Sprint 38 QLP4: tail reader + rotated-file reader ────

    fn write_entries(path: &Path, domains: &[(&str, bool)]) {
        let mut content = String::new();
        for (domain, blocked) in domains {
            content.push_str(&serde_json::to_string(&sample_entry(domain, *blocked)).unwrap());
            content.push('\n');
        }
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn tail_reader_returns_last_n_entries_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");
        let events: Vec<(String, bool)> = (0..100u32)
            .map(|i| (format!("host-{i:03}.example"), false))
            .collect();
        let mut content = String::new();
        for (d, b) in &events {
            content.push_str(&serde_json::to_string(&sample_entry(d, *b)).unwrap());
            content.push('\n');
        }
        std::fs::write(&log_path, content).unwrap();

        let (entries, _state) = read_log_entries_tail(&log_path, 10, None, false, None, None);
        assert_eq!(entries.len(), 10);
        // Newest first: last 10 seeded entries are host-099 down to host-090.
        assert_eq!(entries[0].domain, "host-099.example");
        assert_eq!(entries[9].domain, "host-090.example");
    }

    #[test]
    fn tail_reader_handles_partial_json_at_boundary() {
        // Write enough entries that the FIRST entry in the file lands
        // in the chunk before EOF — i.e. forces the reverse walker
        // through a chunk boundary. 8 KB chunk size + ~200 B per
        // entry → 50 entries is enough to span at least two chunks on
        // typical disks.
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");
        let mut content = String::new();
        for i in 0..200u32 {
            let mut e = sample_entry(&format!("boundary-{i:04}.example"), i % 7 == 0);
            // Pad domain to make each entry heavy enough that the chunk
            // boundary is very likely to split a line.
            e.domain = format!("{}-{}", e.domain, "x".repeat(60));
            content.push_str(&serde_json::to_string(&e).unwrap());
            content.push('\n');
        }
        std::fs::write(&log_path, content).unwrap();

        let (entries, _) = read_log_entries_tail(&log_path, 150, None, false, None, None);
        assert_eq!(entries.len(), 150);
        // The 150 most recent should be boundary-0050..0199 in reverse.
        assert!(entries[0].domain.starts_with("boundary-0199"));
        assert!(entries[149].domain.starts_with("boundary-0050"));
    }

    #[test]
    fn tail_reader_applies_filters_before_limit() {
        // Mix blocked and allowed; the filter should keep scanning
        // backwards until it has `limit` BLOCKED entries, not just
        // `limit` total.
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");
        let mut events: Vec<(String, bool)> = Vec::new();
        for i in 0..30u32 {
            // Every 5th entry is blocked; we want 5 blocked overall.
            events.push((format!("e-{i:03}.example"), i % 5 == 0));
        }
        let mut content = String::new();
        for (d, b) in &events {
            content.push_str(&serde_json::to_string(&sample_entry(d, *b)).unwrap());
            content.push('\n');
        }
        std::fs::write(&log_path, content).unwrap();

        let (blocked, _) = read_log_entries_tail(&log_path, 5, None, true, None, None);
        assert_eq!(
            blocked.len(),
            5,
            "filter must pull 5 BLOCKED even if that means scanning past earlier allowed entries"
        );
        assert!(blocked.iter().all(|e| e.result == "BLOCKED"));
    }

    #[test]
    fn rotated_reader_fills_across_files() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");
        write_entries(
            &log_path,
            &[
                ("current-a.example", false),
                ("current-b.example", false),
                ("current-c.example", false),
                ("current-d.example", false),
                ("current-e.example", false),
            ],
        );
        let today = time::OffsetDateTime::now_utc().date();
        let yesterday = today.previous_day().unwrap();
        let yesterday_name = format!(
            "query.log.{}",
            yesterday
                .format(time::macros::format_description!("[year]-[month]-[day]"))
                .unwrap()
        );
        let yesterday_path = dir.path().join(&yesterday_name);
        let mut y_events: Vec<(&str, bool)> = Vec::new();
        let y_domains: Vec<String> = (0..10u32)
            .map(|i| format!("yesterday-{i:02}.example"))
            .collect();
        for d in &y_domains {
            y_events.push((d.as_str(), false));
        }
        write_entries(&yesterday_path, &y_events);

        let (entries, state) =
            read_log_entries_with_state(&log_path, 12, None, false, None, 7, None);
        assert!(matches!(state, crate::ipc::protocol::QueryLogFileState::Ok));
        assert_eq!(entries.len(), 12);
        // 5 from current (newest-first), then 7 from yesterday.
        assert_eq!(entries[0].domain, "current-e.example");
        assert_eq!(entries[4].domain, "current-a.example");
        assert!(entries[5].domain.starts_with("yesterday-"));
    }

    #[test]
    fn rotated_reader_respects_retention_cap() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");
        std::fs::write(&log_path, "").unwrap();
        let today = time::OffsetDateTime::now_utc().date();
        // Create 14 dated files. Each with 1 parseable entry.
        for age in 1..=14u32 {
            let date = today.checked_sub(time::Duration::days(age as i64)).unwrap();
            let name = format!(
                "query.log.{}",
                date.format(time::macros::format_description!("[year]-[month]-[day]"))
                    .unwrap()
            );
            write_entries(
                &dir.path().join(&name),
                &[(&format!("dated-{age}.example"), false)],
            );
        }

        let (entries, _state) =
            read_log_entries_with_state(&log_path, 1000, None, false, None, 7, None);
        assert_eq!(
            entries.len(),
            7,
            "only retention_days={{7}} files should be scanned regardless of limit"
        );
    }

    #[test]
    fn rotated_reader_returns_missing_when_all_absent() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");
        let (entries, state) =
            read_log_entries_with_state(&log_path, 10, None, false, None, 7, None);
        assert!(entries.is_empty());
        assert!(matches!(
            state,
            crate::ipc::protocol::QueryLogFileState::Missing
        ));
    }

    // ── Sprint 38 QLP6: legacy rotation migration ────────────

    /// Set the mtime of a file to a target UTC date (noon UTC). Uses
    /// a shell-friendly invocation of `touch -t` so the test works
    /// identically on the Debian CT and locally.
    fn set_mtime_to_noon(path: &Path, date: time::Date) {
        let stamp = format!(
            "{:04}{:02}{:02}1200.00",
            date.year(),
            u8::from(date.month()),
            date.day()
        );
        let status = std::process::Command::new("touch")
            .arg("-t")
            .arg(&stamp)
            .arg(path)
            .status()
            .expect("touch invocation");
        assert!(status.success(), "touch -t {stamp} {path:?} failed");
    }

    #[test]
    fn migrate_legacy_rotated_files_renames_by_mtime() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");
        std::fs::write(&log_path, "current\n").unwrap();

        let legacy1 = dir.path().join("query.log.1");
        std::fs::write(&legacy1, "one\n").unwrap();
        set_mtime_to_noon(&legacy1, ymd(2026, 4, 20));

        let legacy2 = dir.path().join("query.log.2");
        std::fs::write(&legacy2, "two\n").unwrap();
        set_mtime_to_noon(&legacy2, ymd(2026, 4, 19));

        migrate_legacy_rotated_files(&log_path);

        assert!(!legacy1.exists(), "query.log.1 migrated");
        assert!(!legacy2.exists(), "query.log.2 migrated");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("query.log.2026-04-20")).unwrap(),
            "one\n"
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("query.log.2026-04-19")).unwrap(),
            "two\n"
        );
        // Current file untouched.
        assert_eq!(std::fs::read_to_string(&log_path).unwrap(), "current\n");
    }

    #[test]
    fn migrate_legacy_rotated_files_is_noop_when_none_present() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");
        std::fs::write(&log_path, "current\n").unwrap();

        migrate_legacy_rotated_files(&log_path);

        // Only the current file should exist — no spurious files,
        // no panic, no deletion.
        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        assert_eq!(names, vec!["query.log"]);
    }

    #[test]
    fn migrate_legacy_rotated_files_handles_mtime_collision() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");
        std::fs::write(&log_path, "current\n").unwrap();

        // Two legacy files with mtime on the same UTC day → second
        // must fall through to the .1 backstop suffix.
        let legacy1 = dir.path().join("query.log.1");
        std::fs::write(&legacy1, "first\n").unwrap();
        set_mtime_to_noon(&legacy1, ymd(2026, 4, 20));

        let legacy2 = dir.path().join("query.log.2");
        std::fs::write(&legacy2, "second\n").unwrap();
        set_mtime_to_noon(&legacy2, ymd(2026, 4, 20));

        migrate_legacy_rotated_files(&log_path);

        assert!(!legacy1.exists());
        assert!(!legacy2.exists());
        assert_eq!(
            std::fs::read_to_string(dir.path().join("query.log.2026-04-20")).unwrap(),
            "first\n"
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("query.log.2026-04-20.1")).unwrap(),
            "second\n"
        );
    }

    #[test]
    fn migrate_legacy_rotated_files_ignores_unrelated_siblings() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");
        std::fs::write(&log_path, "current\n").unwrap();
        std::fs::write(dir.path().join("query.log.backup"), "hand\n").unwrap();
        std::fs::write(dir.path().join("other.txt"), "unrelated\n").unwrap();
        std::fs::write(dir.path().join("logs.tar.gz"), "archive\n").unwrap();

        migrate_legacy_rotated_files(&log_path);

        assert!(dir.path().join("query.log.backup").exists());
        assert!(dir.path().join("other.txt").exists());
        assert!(dir.path().join("logs.tar.gz").exists());
    }

    // ── Sprint 41: client substring + since cutoff ────────────

    /// Build an entry with a specific UTC timestamp offset (seconds from
    /// "now") for the Sprint 41 cutoff tests. Positive `age_secs` = older.
    fn entry_at_age(domain: &str, age_secs: i64, client_name: Option<&str>) -> QueryLogEntry {
        let ts_epoch = time::OffsetDateTime::now_utc().unix_timestamp() - age_secs;
        let ts = time::OffsetDateTime::from_unix_timestamp(ts_epoch).unwrap();
        let fmt =
            time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
        QueryLogEntry {
            timestamp: ts.format(fmt).unwrap(),
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 84)),
            client_name: client_name.map(String::from),
            domain: domain.into(),
            query_type: "A".into(),
            result: "ALLOWED".into(),
            response_time_us: 100,
            cname_chain_via: None,
            rewrote_from: None,
        }
    }

    fn write_raw_entries(path: &Path, entries: &[QueryLogEntry]) {
        let mut content = String::new();
        for e in entries {
            content.push_str(&serde_json::to_string(e).unwrap());
            content.push('\n');
        }
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn client_filter_substring_matches_partial_name() {
        let e_match = sample_entry("one.example", false);
        assert!(entry_matches_filters(
            &e_match,
            &QueryLogFilters::new(Some("lap"), false, None, None)
        ));
        let mut e_no = sample_entry("two.example", false);
        e_no.client_name = Some("phone-bob".into());
        assert!(!entry_matches_filters(
            &e_no,
            &QueryLogFilters::new(Some("lap"), false, None, None)
        ));
    }

    /// Domains are lowercased at ingestion (project rules rule 3), so before this
    /// fix a capital letter in the domain filter could never match anything —
    /// the filter did not merely inconvenience the operator, it contradicted a
    /// house rule and returned zero rows permanently.
    #[test]
    fn an_uppercase_domain_needle_matches_the_lowercased_stored_domain() {
        let e = sample_entry("ads.example.com", false);
        for needle in ["EXAMPLE", "Example", "eXaMpLe", "example"] {
            assert!(
                entry_matches_filters(&e, &QueryLogFilters::new(None, false, Some(needle), None)),
                "domain needle {needle:?} should match the stored `ads.example.com`"
            );
        }
        assert!(
            !entry_matches_filters(
                &e,
                &QueryLogFilters::new(None, false, Some("TRACKER"), None)
            ),
            "case-insensitivity must not turn into matching everything"
        );
    }

    /// Client names are operator-typed, so unlike domains they can carry
    /// uppercase on BOTH sides. The fold has to reach the haystack too — a fix
    /// that only lowered the needle would pass the domain test above and still
    /// fail here.
    #[test]
    fn a_client_name_matches_whatever_case_either_side_carries() {
        let mut e = sample_entry("one.example", false);
        e.client_name = Some("Marco-iPhone".into());
        for needle in ["marco", "MARCO", "iphone", "IPHONE", "Marco-iPhone"] {
            assert!(
                entry_matches_filters(&e, &QueryLogFilters::new(Some(needle), false, None, None)),
                "client needle {needle:?} should match the stored `Marco-iPhone`"
            );
        }
        assert!(!entry_matches_filters(
            &e,
            &QueryLogFilters::new(Some("bob"), false, None, None)
        ));
    }

    #[test]
    fn lowered_needle_actually_lowers() {
        assert_eq!(LoweredNeedle::new("MiXeD").as_str(), "mixed");
    }

    /// Pins the helper itself, including the two edge cases the windowing
    /// implementation gets wrong if written carelessly.
    #[test]
    fn contains_ascii_ci_matches_regardless_of_haystack_case() {
        assert!(contains_ascii_ci("AdS.ExAmPlE.CoM", "example"));
        assert!(contains_ascii_ci("abc", "abc"));
        assert!(contains_ascii_ci("abc", ""), "empty needle matches");
        assert!(
            !contains_ascii_ci("ab", "abc"),
            "needle longer than haystack"
        );
        assert!(!contains_ascii_ci("abc", "xyz"));
        // A non-ASCII haystack must not panic or mis-slice: `windows` walks
        // BYTES, so this asserts the byte-wise fold stays sound on UTF-8.
        assert!(contains_ascii_ci("caffÈ-LATTE", "latte"));
        assert!(!contains_ascii_ci("caffÈ", "caffe"));
    }

    #[test]
    fn client_filter_substring_matches_partial_ip() {
        let mut e = sample_entry("one.example", false);
        e.client_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 84));
        e.client_name = None;
        assert!(entry_matches_filters(
            &e,
            &QueryLogFilters::new(Some("192.0.2"), false, None, None)
        ));
        assert!(entry_matches_filters(
            &e,
            &QueryLogFilters::new(Some("2.84"), false, None, None)
        ));
        assert!(!entry_matches_filters(
            &e,
            &QueryLogFilters::new(Some("192.168"), false, None, None)
        ));
    }

    #[test]
    fn parse_timestamp_epoch_round_trips() {
        let epoch = parse_timestamp_epoch("2026-04-08T15:32:01Z").unwrap();
        let parsed_back = time::OffsetDateTime::from_unix_timestamp(epoch).unwrap();
        assert_eq!(parsed_back.year(), 2026);
        assert_eq!(parsed_back.hour(), 15);
        assert!(parse_timestamp_epoch("not-a-timestamp").is_none());

        // query-log-02 (rev-2606): the writer formats RFC 3339 with
        // fractional seconds (production lines look like
        // `...:57.745067301Z`). The reader must accept that shape and
        // floor to whole seconds — the pre-fix hand-rolled `[second]Z`
        // description returned None here, the root of the silent
        // `since`-filter no-op.
        let sub = parse_timestamp_epoch("2026-06-10T00:02:57.745067301Z")
            .expect("subsecond production timestamp must parse");
        let whole = parse_timestamp_epoch("2026-06-10T00:02:57Z").unwrap();
        assert_eq!(sub, whole, "subsecond timestamp floors to the same epoch");
    }

    /// query-log-02 (rev-2606): the `since` cutoff must filter the
    /// nanosecond-precision timestamps the writer actually emits. Every
    /// other fixture in this module is second-precision — the one shape
    /// production never writes — which is exactly what let the bug ship:
    /// pre-fix the parser returned None on the fractional run, so the
    /// cutoff branch never fired (older lines slipped through) and the
    /// reverse scan never early-terminated.
    #[test]
    fn classify_line_cutoff_filters_subsecond_production_timestamps() {
        let make = |domain: &str, ts: &str| {
            let mut e = sample_entry(domain, false);
            e.timestamp = ts.into();
            serde_json::to_vec(&e).unwrap()
        };
        let cut = |c: i64| QueryLogFilters::new(None, false, None, Some(c));
        let cutoff = parse_timestamp_epoch("2026-06-10T00:02:30.000000000Z").unwrap();
        let old = make("old.example", "2026-06-10T00:02:10.123456789Z");
        let new = make("new.example", "2026-06-10T00:02:57.745067301Z");

        let mut entries = Vec::new();
        assert!(
            matches!(
                classify_line(&old, &mut entries, 10, &cut(cutoff), 0, &mut None),
                LineOutcome::OlderThanCutoff
            ),
            "a subsecond line older than the cutoff must be excluded + signal termination"
        );
        assert!(
            matches!(
                classify_line(&new, &mut entries, 10, &cut(cutoff), 0, &mut None),
                LineOutcome::Pushed
            ),
            "a subsecond line newer than the cutoff must be kept"
        );
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].domain, "new.example");
    }

    /// rev-2606 style roundup: `dated_siblings_newest_first` must window
    /// by distinct DATE, not file count. A busy day with a size-backstop
    /// sibling must not consume an extra day-slot and shrink the window.
    #[test]
    fn dated_siblings_window_by_distinct_date_not_file_count() {
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("query.log");
        for name in [
            "query.log",
            "query.log.2026-06-10",
            "query.log.2026-06-10.1", // backstop sibling, same day
            "query.log.2026-06-09",
            "query.log.2026-06-08",
        ] {
            std::fs::write(dir.path().join(name), b"x").unwrap();
        }
        let names: Vec<String> = dated_siblings_newest_first(&primary, 2)
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        // 2-day window: both 06-10 siblings + the 06-09 file (2 distinct
        // dates). Pre-fix the file-count truncate stopped after the two
        // 06-10 files — only one day reachable.
        assert!(names.contains(&"query.log.2026-06-10".to_string()));
        assert!(names.contains(&"query.log.2026-06-10.1".to_string()));
        assert!(
            names.contains(&"query.log.2026-06-09".to_string()),
            "second distinct date must stay reachable: {names:?}"
        );
        assert!(
            !names.contains(&"query.log.2026-06-08".to_string()),
            "third date is outside the 2-day window: {names:?}"
        );
    }

    #[test]
    fn since_cutoff_excludes_older_entries() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");
        write_raw_entries(
            &log_path,
            &[
                entry_at_age("old-a.example", 10_800, None), // 3 h old
                entry_at_age("old-b.example", 7_200, None),  // 2 h old
                entry_at_age("recent.example", 600, None),   // 10 min old
            ],
        );

        // 1 h cutoff → only the 10-min entry is in-window.
        let cutoff = time::OffsetDateTime::now_utc().unix_timestamp() - 3_600;
        let (entries, _) = read_log_entries_tail(&log_path, 10, None, false, None, Some(cutoff));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].domain, "recent.example");
    }

    #[test]
    fn since_cutoff_none_means_no_cutoff() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");
        write_raw_entries(
            &log_path,
            &[
                entry_at_age("old.example", 10_800, None),
                entry_at_age("recent.example", 600, None),
            ],
        );
        let (entries, _) = read_log_entries_tail(&log_path, 10, None, false, None, None);
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn since_cutoff_tolerance_absorbs_single_out_of_order_entry() {
        // The walker must not stop the first time it sees an older-
        // than-cutoff line, because clock skew can produce a single
        // stale line sandwiched between in-window ones. The tolerance
        // window (64 misses) keeps the scan going until we are sure
        // we've crossed the boundary.
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");
        write_raw_entries(
            &log_path,
            &[
                entry_at_age("recent-a.example", 1_200, None), // 20 min old (in)
                entry_at_age("stale.example", 10_000, None),   // 2h 46m old (out)
                entry_at_age("recent-b.example", 600, None),   // 10 min old (in)
            ],
        );
        let cutoff = time::OffsetDateTime::now_utc().unix_timestamp() - 3_600;
        let (entries, _) = read_log_entries_tail(&log_path, 10, None, false, None, Some(cutoff));
        // Both in-window entries must be returned; the stale one in
        // between must be silently skipped (not push, not terminate).
        let domains: Vec<_> = entries.iter().map(|e| e.domain.as_str()).collect();
        assert!(domains.contains(&"recent-a.example"));
        assert!(domains.contains(&"recent-b.example"));
        assert!(!domains.contains(&"stale.example"));
    }

    // ── T2.9 / H-20 silent-drop counters ────────────────────

    /// Drop site 1: bounded mpsc channel saturated. We freeze the
    /// writer task with a leaked `Notify` so it never drains, then
    /// flood `LOG_CHANNEL_CAP + 50` entries through `log()` and assert
    /// the overflow lands in `channel_full` exactly. The other two
    /// counters stay at 0 because we never let the writer touch disk.
    #[tokio::test(flavor = "current_thread")]
    async fn h20_channel_full_drops_increment_counter() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");
        let ql = QueryLog::start(log_path, 1_024 * 1_024, 4, 7);

        // Pump the bounded channel to capacity + overflow without ever
        // yielding to the writer task. The writer is a `tokio::spawn`'d
        // task on the same single-threaded runtime, so as long as we
        // never `.await` it cannot drain — every send beyond
        // LOG_CHANNEL_CAP must hit the `channel_full` arm.
        let overflow = 50;
        for i in 0..(LOG_CHANNEL_CAP + overflow) {
            ql.log(sample_entry(&format!("d{i}.example"), false));
        }

        let snap = ql.drop_counters();
        assert_eq!(
            snap.channel_full, overflow as u64,
            "exactly {overflow} entries should have overflowed"
        );
        assert_eq!(snap.flush_open_errors, 0);
        assert_eq!(snap.flush_write_errors, 0);
    }

    /// Drop site 2: `OpenOptions::open` fails inside the writer task.
    /// We point the writer at a path whose parent does not exist —
    /// `create(true)` cannot conjure the missing directory, so every
    /// flush attempt errors out and bumps `flush_open_errors`. We
    /// drive a single flush via `shutdown()` (the channel-closed arm
    /// flushes any buffered remainder) and assert the counter saw
    /// exactly one flush failure.
    #[tokio::test(flavor = "current_thread")]
    async fn h20_flush_open_error_drops_increment_counter() {
        let dir = tempfile::tempdir().unwrap();
        // Parent dir intentionally absent — open() returns ENOENT.
        let log_path = dir.path().join("missing-subdir").join("query.log");
        assert!(!log_path.parent().unwrap().exists());

        let ql = QueryLog::start(log_path, 1_024 * 1_024, 4, 7);
        ql.log(sample_entry("only.example", false));

        // Snapshot the Arc before consuming `ql` so we can read after
        // shutdown drains the writer task.
        let snap_before = ql.drops.clone();
        ql.shutdown().await;

        let snap = snap_before.snapshot();
        assert_eq!(snap.channel_full, 0, "channel had room for the entry");
        assert!(
            snap.flush_open_errors >= 1,
            "missing parent dir should have blocked at least one open: {snap:?}"
        );
        assert_eq!(
            snap.flush_write_errors, 0,
            "no file ever opened, so no per-entry writeln! ran"
        );
    }

    /// Drop site 3: per-entry `writeln!` returns an `io::Error`.
    /// `flush_buffer` is exercised directly with a fresh
    /// `QueryLogDropCounters` and a path that's an existing directory
    /// — `OpenOptions::append(true).open(<dir>)` succeeds on Linux
    /// returning a fd whose `write()` syscall fails with EISDIR. That
    /// drives the `writeln!` arm specifically, isolating
    /// `flush_write_errors` from the open-error path.
    #[test]
    fn h20_flush_write_error_drops_increment_counter() {
        let dir = tempfile::tempdir().unwrap();
        // Pre-create a directory at the log path. `OpenOptions::append`
        // can open a directory fd on Linux; the subsequent `write()`
        // returns EISDIR — which is exactly the per-entry write-error
        // we want to count.
        let dir_as_log = dir.path().join("query.log");
        std::fs::create_dir(&dir_as_log).unwrap();

        let drops = QueryLogDropCounters::default();
        let mut buffer = vec![
            sample_entry("a.example", false),
            sample_entry("b.example", true),
            sample_entry("c.example", false),
        ];
        flush_buffer(
            &mut buffer,
            &dir_as_log,
            1_024 * 1_024,
            4,
            ymd(2026, 4, 26),
            &drops,
        );

        let snap = drops.snapshot();
        // On platforms where opening a directory for append succeeds
        // (Linux), every entry hits a writeln! error. On platforms
        // where the open itself fails (some BSDs / older glibc) the
        // open-error arm fires instead — both are valid expressions of
        // "the writer cannot land bytes here", so we accept either as
        // long as the union is non-zero and the buffer was drained.
        let total_drops = snap.flush_open_errors + snap.flush_write_errors;
        assert!(
            total_drops >= 1,
            "directory-as-log must surface at least one drop: {snap:?}"
        );
        assert!(
            buffer.is_empty(),
            "flush_buffer must drain or clear the buffer regardless of error path"
        );
        assert_eq!(
            snap.channel_full, 0,
            "drop site 1 untouched by direct flush"
        );
    }

    // ── file mode on create ────────────────────────────────

    /// Scoped `umask(2)` override, restored on drop.
    ///
    /// `umask` is per-PROCESS and `cargo test` runs tests as threads in a
    /// single process, so a failing assertion that skipped the restore
    /// would leave every later test in this binary at the loosened mask.
    /// RAII, not a trailing statement.
    struct UmaskGuard(libc::mode_t);

    impl UmaskGuard {
        fn set(mask: libc::mode_t) -> Self {
            // SAFETY: `umask(2)` has no preconditions and cannot fail. It
            // returns the previous mask, which `drop` puts back.
            Self(unsafe { libc::umask(mask) })
        }
    }

    impl Drop for UmaskGuard {
        fn drop(&mut self) {
            // SAFETY: as in `set` — restoring the mask captured there.
            unsafe {
                libc::umask(self.0);
            }
        }
    }

    /// The query log must be CREATED `0o640`, never `0o666 & !umask`.
    ///
    /// The umask is pinned inside the test on purpose, because the value of
    /// this assertion must not depend on which mask the harness happens to
    /// hand us:
    ///
    /// * this dev box runs `0o022` (measured), where fixed gives `0o640`
    ///   and unfixed gives `0o644` — the arm discriminates, by luck;
    /// * the systemd unit runs `UMask=0077`, where fixed gives
    ///   `0o640 & !0o077 == 0o600` and unfixed gives
    ///   `0o666 & !0o077 == 0o600` — IDENTICAL, and the arm would be
    ///   measuring nothing while still reading green.
    ///
    /// Pinning removes the ambient dependency. `0o000` specifically, not a
    /// conventional `0o022`, which would wave through a `.mode(0o660)`
    /// regression (`0o660 & !0o022 == 0o640`).
    #[test]
    fn flush_buffer_creates_log_with_owner_group_only_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");

        // `.mode()` applies only when `O_CREAT` actually creates the file.
        // If anything pre-created it we would be measuring its old mode and
        // proving nothing — the assertion must observe the CREATE path.
        assert!(
            !log_path.exists(),
            "test must observe the CREATE path, not a pre-existing file"
        );

        let drops = QueryLogDropCounters::default();
        let mut buffer = vec![sample_entry("mode.example", false)];
        {
            let _umask = UmaskGuard::set(0o000);
            flush_buffer(
                &mut buffer,
                &log_path,
                1_024 * 1_024,
                4,
                ymd(2026, 8, 14),
                &drops,
            );
        }

        let snap = drops.snapshot();
        assert_eq!(snap.flush_open_errors, 0, "log must have opened: {snap:?}");
        assert_eq!(
            snap.flush_write_errors, 0,
            "entry must have landed: {snap:?}"
        );

        let mode = std::fs::metadata(&log_path).unwrap().permissions().mode() & 0o777;
        // The expected value is a LITERAL, deliberately NOT
        // `QUERY_LOG_FILE_MODE`. Comparing the disk against the constant
        // that produced it is circular — swapping the constant to `0o644`
        // moves both sides and the arm stays green. Measured, not
        // theorised: this assertion passed under exactly that mutation
        // until the literal replaced it. The literal puts the policy
        // itself under test, so loosening the bits has to be a deliberate
        // edit here too.
        assert_eq!(
            mode, 0o640,
            "the query log records every domain every device on the network \
             asked for; it must not be created group-writable or \
             world-readable (got {mode:o})"
        );
    }

    // ── M-37: BufWriter + serde_json::to_writer ────────────

    /// `flush_buffer` must produce one JSON object per line on disk —
    /// the BufWriter swap in M-37 must not drop newlines, batch
    /// entries onto the same line, or skip the final flush. Pin a
    /// 3-entry healthy flush and assert the on-disk content
    /// round-trips through the parser.
    #[test]
    fn m37_buf_writer_produces_one_json_per_line_and_flushes() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");
        let drops = QueryLogDropCounters::default();
        let mut buffer = vec![
            sample_entry("a.example", false),
            sample_entry("b.example", true),
            sample_entry("c.example", false),
        ];

        flush_buffer(
            &mut buffer,
            &log_path,
            1_024 * 1_024,
            4,
            ymd(2026, 4, 27),
            &drops,
        );

        let raw = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = raw.lines().collect();
        assert_eq!(lines.len(), 3, "one line per entry: {raw}");
        for line in &lines {
            // Each line must be a complete, parseable JSON object.
            let _: QueryLogEntry = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("line {line} did not parse: {e}"));
        }
        let domains: Vec<_> = lines
            .iter()
            .filter_map(|l| serde_json::from_str::<QueryLogEntry>(l).ok())
            .map(|e| e.domain)
            .collect();
        assert_eq!(domains, vec!["a.example", "b.example", "c.example"]);

        let snap = drops.snapshot();
        assert_eq!(snap.flush_open_errors, 0);
        assert_eq!(snap.flush_write_errors, 0);
    }

    // ── M-38: midnight collision exhaustion ─────────────────

    /// Pre-fix: after 100 collision-suffix attempts (`query.log.<date>`,
    /// `.1`, `.2`, …, `.100`), `rotate_daily` called `remove_file` on
    /// the live `query.log` — destroying the day's data. Post-fix the
    /// file must stay in place untouched so the writer keeps appending
    /// and tomorrow's rotation can retry against a different date.
    #[test]
    fn m38_rotate_daily_preserves_current_log_on_collision_exhaustion() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");
        let original = b"todays-bytes-must-survive\n";
        std::fs::write(&log_path, original).unwrap();

        // Plant the primary dated sibling + every collision suffix
        // 1..=MAX_MIDNIGHT_COLLISION_SUFFIX so the rotation has nowhere
        // to land.
        let yesterday = ymd(2026, 4, 26);
        let primary = daily_path(&log_path, yesterday, None);
        std::fs::write(&primary, b"primary\n").unwrap();
        for idx in 1..=MAX_MIDNIGHT_COLLISION_SUFFIX {
            let candidate = daily_path(&log_path, yesterday, Some(idx));
            std::fs::write(&candidate, format!("slot-{idx}\n")).unwrap();
        }

        rotate_daily(&log_path, yesterday);

        assert!(
            log_path.exists(),
            "current query.log must NOT be removed on collision exhaustion"
        );
        assert_eq!(
            std::fs::read(&log_path).unwrap(),
            original,
            "current query.log content must be byte-identical post-rotation attempt"
        );
        // None of the planted slots should have been clobbered or
        // removed either — the rotation is meant to be a strict no-op
        // on exhaustion.
        assert_eq!(std::fs::read(&primary).unwrap(), b"primary\n");
        for idx in 1..=MAX_MIDNIGHT_COLLISION_SUFFIX {
            let candidate = daily_path(&log_path, yesterday, Some(idx));
            assert_eq!(
                std::fs::read(&candidate).unwrap(),
                format!("slot-{idx}\n").as_bytes(),
                "slot {idx} must be untouched"
            );
        }
    }

    // ── M-39: PII redaction in Display ──────────────────────

    /// `QueryLogEntry::Display` must NOT surface client IP, client name,
    /// or domain. Anyone logging `entry` via `tracing::error!(%entry, …)`
    /// or `eprintln!("{entry}")` should see only the non-PII metadata.
    #[test]
    fn m39_display_redacts_pii_fields() {
        let entry = sample_entry("secret.internal.corp", true);
        let rendered = format!("{entry}");

        assert!(
            !rendered.contains("secret.internal.corp"),
            "domain must not appear in Display output: {rendered}"
        );
        assert!(
            !rendered.contains("192.168.1.1"),
            "client_ip must not appear in Display output: {rendered}"
        );
        assert!(
            !rendered.contains("laptop"),
            "client_name must not appear in Display output: {rendered}"
        );
        // Non-PII metadata stays visible for correlation.
        assert!(rendered.contains("BLOCKED"));
        assert!(rendered.contains("2026-04-08T15:00:00Z"));
        assert!(rendered.contains("response_time_us=500"));
    }

    /// Healthy path: no drop site fires. Counter snapshot must stay at
    /// all-zeros after a normal flush. Pins that the increments are
    /// gated on the failure arms, not unconditional.
    #[test]
    fn h20_counters_stay_zero_on_healthy_flush() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("query.log");
        let drops = QueryLogDropCounters::default();
        let mut buffer = vec![sample_entry("ok.example", false)];

        flush_buffer(
            &mut buffer,
            &log_path,
            1_024 * 1_024,
            4,
            ymd(2026, 4, 26),
            &drops,
        );

        let snap = drops.snapshot();
        assert_eq!(snap.channel_full, 0);
        assert_eq!(snap.flush_open_errors, 0);
        assert_eq!(snap.flush_write_errors, 0);
        assert!(log_path.exists(), "healthy flush must produce the file");
    }
}
