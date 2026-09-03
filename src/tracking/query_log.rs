//! Append-only query log with buffered writes and calendar rotation.
//!
//! Entries are sent via a bounded channel from the DNS handler hot path
//! to a background writer task. The writer buffers entries and flushes
//! periodically (1 s) or when the buffer is full.
//!
//! Rotation is **calendar-based**: at UTC midnight the
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
//! `attach_query_log` / `detach_query_log` pair drives the atomic swap
//! on the engine's `ArcSwap<Option<Arc<QueryLog>>>` slot.
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

// Shared with the log ring rather than copied: one definition, two scans
// under the same no-allocation constraint, no second copy to drift.
use super::log_ring::contains_ascii_ci;

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
/// `Debug` is intentionally NOT derived: `client_ip`, `client_name`,
/// and `domain` are PII and must not surface through `?entry` /
/// `panic!("{entry:?}")` / `assert_eq!` failure messages. Use the explicit
/// [`Display`](std::fmt::Display) impl below when an operator-facing
/// textual form is needed — it emits only the non-PII metadata
/// (timestamp, query type, result, response time), which is enough for
/// correlation.
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
    /// Offending hop in a CNAME chain block. `Some(name)` when the
    /// result is a CNAME chain block (the original `domain` is the
    /// queried apex; `cname_chain_via` is the hop in the chain that
    /// triggered the block). `None` for any non-CNAME-block outcome.
    /// `#[serde(default)]` keeps older JSONL files parseable —
    /// missing field reads back as `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cname_chain_via: Option<String>,
    /// Original qname when a per-profile rewrite fired. The `domain`
    /// field carries the rewritten (effective) name used for
    /// resolution; `rewrote_from` is the name the client asked for.
    /// `None` on every query that didn't rewrite. `#[serde(default)]`
    /// keeps older JSONL files parseable — missing field reads back
    /// as `None`.
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

/// Counters for the three silent-drop surfaces on the query-log write
/// path. Atomics-only — the sender increment runs on the daemon hot path
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
/// compat with older daemons clean.
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
    /// `max_size_bytes` is a **per-day backstop**: if a
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

    /// Drop-counter snapshot for `warden status`.
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
/// rotate at UTC midnight.
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
            // BufWriter aggregates per-entry writes into 8 KB
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
            // `flush_write_errors` by the buffered count so the
            // loss rate stays accurate (a fully-failing flush of 100
            // entries should bump the counter by ~100).
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

/// Midnight-UTC rollover: rename `query.log` →
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
    // Do NOT `remove_file(path)` here. An earlier version of the writer
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

/// Same-day size-backstop rotation: a single day exceeded
/// `max_size_bytes`, so rotate `query.log` → `query.log.<today>.<N>`
/// where N is the next free suffix up to `max_files_per_day`. Once all
/// suffixes are used, the oldest is dropped and the others are shifted
/// up — mirrors an earlier size-only scheme but anchored to the day so
/// the daily calendar stream stays intact.
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
/// Replaces an earlier numeric-only `rotated_path`. The reader uses the
/// same signature so it can compose daily paths without reinventing the
/// encoding.
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

/// One-shot migration of legacy size-rotated siblings
/// (`query.log.1`..`.9`) to the calendar-based naming
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
        // Surface the semantics change to operators who are clearly
        // migrating from a size-rotated install.
        tracing::warn!(
            "query log: `query_log_max_size_mb` is now a per-day backstop, \
             not the primary retention knob. Legacy `query.log.N` files \
             have been renamed using their mtime. Consider setting \
             `retention_days = 7` in [tracking] if you haven't already."
        );
    }
}

/// Delete `query.log.YYYY-MM-DD*` siblings whose
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
/// under systemd, and the bug that motivated this helper was precisely
/// the reader using that cwd as a fallback.
pub fn resolved_query_log_path(configured: &Path, config_path: &Path) -> PathBuf {
    let raw = if configured.is_absolute() {
        configured.to_path_buf()
    } else {
        crate::cli::commands::start::state_dir_for(
            config_path.parent().unwrap_or_else(|| Path::new(".")),
        )
        .join(configured)
    };
    // Drop embedded `./` components so log lines read
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
/// [`QueryLogEntry`] does not derive it: the entries carry
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
/// single query log file.
///
/// Seeks to EOF and walks backwards in 8 KB chunks, parsing complete
/// JSON-line entries and applying the filters as it goes. Stops when
/// it has collected `limit` matches or reaches BOF. Total I/O is
/// `O(returned entries + chunk_size)` — at typical scale (700 MB across a
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
/// `filters.cutoff_epoch` activates early termination: once at
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
/// that enables early termination. Unparseable bytes, empty
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
/// prematurely.
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
/// An earlier hand-rolled `[...]:[second]Z` description had no
/// fractional-seconds field, so it returned `None` for every production
/// line — the writer emits RFC 3339 with nanoseconds
/// (`...:57.745067301Z`) — which silently disabled the `since`
/// time-window filter (the age cutoff in `classify_line` never fired,
/// and the reverse scan never early-terminated). RFC 3339 accepts
/// optional subseconds, so this parses both real production output and
/// the second-precision test fixtures. Uses the `time` crate per
/// CLAUDE.md common-pitfalls ("don't use chrono").
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
        // Substring match, symmetric with the domain arm below.
        // Operators typing a partial name or an IP prefix used to get
        // zero hits under the old exact-match semantics; the asymmetry
        // was a usability papercut called out by the operator.
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
/// retention cap is hit). Extends the earlier single-file tail reader
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

    // A sibling dated before the cutoff's calendar date cannot carry
    // any entry newer than the cutoff (timestamps inside are all on
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
    // Window by distinct DATES, not file count: a single day can own
    // several size-backstop siblings
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
mod tests;
