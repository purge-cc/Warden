//! Daemon-side Unix socket listener for IPC commands.
//!
//! Listens on a Unix domain socket, spawns one tokio task per connection.
//! Each connection: read one JSON command line → dispatch → write JSON response → close.
//! Socket file is exposed at the canonical path with mode `0o600` (owner-
//! only) atomically: the bind path binds into a per-call temp path,
//! `chmod`s it, then `rename(2)`s into place. Peers resolving the
//! canonical path see `0o600` from the first syscall — closes the TOCTOU
//! window where a separate post-bind `chmod` would briefly expose the
//! socket as `0o666 & ~umask`. §4.32 P0: tightened from `0o660` to
//! `0o600` so a hypothetical second user added to the `purge-warden`
//! group cannot reach the IPC bus; defense in depth alongside the
//! peer-uid gate in `handle_connection`.

use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::dns::cache::DnsCache;
use crate::filter::engine::FilterResult;
use crate::filter::FilterEngine;
use crate::lists::status::{BlocklistStatusDto, ListStatusRegistry};
use crate::profiles::ProfileResolver;
use crate::tracking::StatsEngine;

use super::errors::{ipc_error, IpcError};
use super::protocol::{
    CommandTier, IpcCommand, IpcNotification, IpcResponse, LocalRecordsHitEntry,
};
use crate::auth::token::verify_token;

/// Effective uid of the calling process. Captured once at daemon boot
/// into [`DaemonState::daemon_uid`] and reused for every peer-uid check
/// in [`handle_connection`].
///
/// `geteuid` is async-signal-safe and documented to never fail; the
/// `unsafe` block is a thin FFI wrapper with no soundness obligation
/// the caller can violate.
pub fn current_euid() -> u32 {
    // SAFETY: geteuid is an FFI call into a Linux syscall that takes no
    // arguments, never modifies caller-visible state, and is documented
    // to always succeed (POSIX). The cast from `libc::uid_t` to `u32`
    // is exact on every Linux ABI we target.
    unsafe { libc::geteuid() }
}

/// Shared daemon state accessible to IPC command handlers.
pub struct DaemonState {
    pub filter: Arc<FilterEngine>,
    pub cache: DnsCache,
    pub profiles: Option<Arc<ProfileResolver>>,
    pub stats: Option<Arc<StatsEngine>>,
    pub listen_addr: String,
    pub upstream_mode: String,
    pub upstream_count: usize,
    pub list_count: usize,
    pub started_at: Instant,
    /// Sender to trigger shutdown from IPC. Payload carries the invoker
    /// uid from `SO_PEERCRED` (Sprint 32 N1 audit trail) — `Some(uid)` for
    /// IPC-triggered shutdowns, `None` for signal-driven shutdowns.
    pub shutdown_tx: Option<tokio::sync::mpsc::Sender<Option<u32>>>,
    /// Sender to trigger reload from IPC. Payload carries the invoker uid
    /// from `SO_PEERCRED` — `Some(uid)` for IPC reloads, `None` for
    /// SIGHUP-driven reloads (signals have no peer cred).
    pub reload_tx: Option<tokio::sync::mpsc::Sender<Option<u32>>>,
    /// SHA-256 hash of the daemon's auth token (P0-3). `None` if the
    /// operator has never run `warden token generate`. When `None`, the
    /// daemon refuses all Mutating and Admin IPC commands with a plain-
    /// English error pointing the operator at `warden token generate`.
    ///
    /// Wrapped in an `Arc<ArcSwap<_>>` so that Sprint 35 CS3's
    /// `warden token regenerate` → IPC reload flow can swap in the new
    /// hash atomically, without a daemon restart. `handle_reload` in
    /// `cli::commands::start` stores the reloaded config's hash after
    /// every successful reload; authentication reads through the swap
    /// with `state.api_token_hash.load().as_deref()`.
    pub api_token_hash: Arc<arc_swap::ArcSwap<Option<String>>>,
    /// Path to `config.toml` — used by device mutation handlers to
    /// re-read the current state, apply the change, validate, and
    /// atomically write it back. `None` in tests that don't exercise
    /// the mutation path.
    pub config_path: Option<PathBuf>,
    /// Per-daemon write lock for device mutation handlers. Each
    /// IPC connection runs in its own tokio task, so without this
    /// two concurrent DeviceAdds could read the same config, each
    /// push its own device, and the second write would clobber
    /// the first. The lock is acquired around the whole
    /// read-modify-write-reload cycle. `tokio::sync::Mutex` (not
    /// std) because we hold it across `await` points.
    pub config_write_lock: Arc<tokio::sync::Mutex<()>>,
    /// Sprint 43 T1: shared handle to per-source `ListStatus`. `None`
    /// when the daemon was started with no `[lists].sources` (filter
    /// disabled). The `IpcCommand::BlocklistStats` handler reads
    /// through this Arc; the list manager updates it atomically on each
    /// refresh cycle.
    pub list_statuses: Option<Arc<ListStatusRegistry>>,
    /// Sprint C T3 of `lists_categories_v2` (§5.4 / §8.5): shared
    /// handle to the retry state machine (`data/list_state.toml`).
    /// `None` when no `[lists].sources` are configured. The
    /// `IpcCommand::Status` handler walks `lists.values()` to derive
    /// the per-state counts surfaced as `ListDiagnostics`. The list
    /// manager updates the inner map atomically on every refresh
    /// transition (T2).
    pub list_state: Option<Arc<std::sync::Mutex<crate::config::list_state::ListState>>>,
    /// Sprint 44 follow-up (`s44-hits-ipc-verb`): shared handle to the
    /// per-record `LocalRecordsHits` counter. `None` only in tests that
    /// don't exercise the local-DNS hits path; production always wires
    /// `Some(_)` so the IPC handler returns a live snapshot. When `None`
    /// the handler returns an empty list rather than an error so the
    /// TUI's hits column degrades to "0 known hits" instead of breaking.
    pub local_records_hits: Option<Arc<crate::tracking::LocalRecordsHits>>,
    /// `logs-tab`: the daemon's own recent `tracing` events, for
    /// `IpcCommand::DaemonLogs`. Production wires
    /// `tracking::log_ring::global()` — the same ring the capture layer
    /// installed in `main.rs` pushes into. `None` in tests that don't
    /// exercise the verb; the handler then answers with an empty page
    /// rather than an error, so the TUI shows "no messages" instead of
    /// breaking.
    pub log_ring: Option<Arc<crate::tracking::log_ring::LogRing>>,
    /// Sprint 43 T2: broadcast sender for [`IpcNotification`] events.
    /// Subscribers obtain a receiver via `tx.subscribe()`. Currently
    /// no IPC subscriber endpoint consumes this — T2 wires the
    /// publisher only; T3 adds the long-poll `IpcCommand` that
    /// streams notifications back to TUI / CLI clients. Stored on
    /// `DaemonState` so the future endpoint can subscribe without
    /// re-plumbing through the manager.
    #[allow(dead_code)] // Subscriber endpoint is T3 — channel ships in T2 ready for it.
    pub notification_tx: Option<tokio::sync::broadcast::Sender<IpcNotification>>,
    /// Sprint 43 T4 (D4): IPC-triggered reload coalescer. When present
    /// every `IpcCommand::Reload` runs through this 250 ms debounce
    /// window. SIGHUP-driven reloads bypass it and continue to use
    /// `reload_tx` directly. `None` in tests that don't exercise the
    /// coalescing path.
    pub reload_coalescer: Option<Arc<crate::ipc::ReloadCoalescer>>,
    /// Disk-resident MAC OUI vendor table opened at startup. `None`
    /// when the file is missing or malformed — lookups are simply
    /// skipped and the TUI hides the Vendor row in the device card.
    /// The table is `mmap`-backed so RAM cost in process RSS is
    /// effectively zero (kernel page cache holds the hot pages).
    pub oui_table: Option<Arc<crate::oui::OuiTable>>,
    /// Sprint B Dashboard v2 — bit → "scope/topic" label snapshot for
    /// the `top_blocked_lists` IPC field. Length 64; entries are
    /// `None` for bits without a configured source. Built once at
    /// `start.rs` from `source_bits.iter_urls()` × `Catalog::entries()`
    /// (with URL-stem fallback for non-catalog sources). Replaced
    /// wholesale on hot-reload via the same construction path —
    /// `DaemonState` is rebuilt on full reload, so no `ArcSwap`
    /// indirection is needed here.
    pub list_labels: Arc<Vec<Option<String>>>,
    /// §4.7 Phase 2 T1: ArcSwap-wrapped sender for the
    /// [`ListManagerCommand`](crate::lists::manager::ListManagerCommand)
    /// out-of-band channel drained by `ListManager::spawn_refresh_loop`.
    /// `None` when no `[lists].sources` are configured (no manager
    /// task exists), or in tests that don't exercise the forget path.
    ///
    /// Wrapped in `Arc<ArcSwap<_>>` so the reload path in `handle_reload`
    /// can swap in the new task's `Sender` after rebuilding the manager,
    /// without rebuilding `DaemonState`. The IPC `handle_forget_list`
    /// reads through `.load()` on every call so the post-reload sender
    /// is picked up on the next forget without re-plumbing.
    pub list_cmd_tx: Arc<
        arc_swap::ArcSwap<
            Option<tokio::sync::mpsc::Sender<crate::lists::manager::ListManagerCommand>>,
        >,
    >,
    /// §4.32 P0: effective uid the daemon process runs as, captured
    /// once via [`current_euid`] at `start.rs` daemon init. Every
    /// accepted IPC connection's `SO_PEERCRED` uid must equal this
    /// value or [`handle_connection`] silently drops the stream and
    /// emits an audit warn. Defense in depth alongside the `0o600`
    /// socket mode — the perm check blocks the FD from being opened
    /// by non-owner peers; this check blocks any peer that somehow
    /// inherits the FD anyway (e.g. through a same-uid wrapper
    /// process that drops privileges between `open` and `connect`).
    ///
    /// Tests default to the test process's own euid so the gate is a
    /// no-op for in-process unit fixtures; the `handle_connection`
    /// refusal tests override this field to an arbitrary other uid
    /// to exercise the rejection branch.
    pub daemon_uid: u32,
    /// §4.13 — lock-free handle to the latest resource-budget sample.
    /// `handle_status` reads through `.load_full()` on every call; the
    /// sampler (spawned by `cli::commands::start`) writes the latest
    /// snapshot once per `tick_secs`. Tests that don't exercise the
    /// sampler use `resource_budget::types::new_store()` which keeps
    /// the snapshot as `None` — IPC just reports
    /// `resource_budget: None` in that case.
    pub resource_budget_store: crate::resource_budget::ResourceBudgetStore,
    /// §4.11-4 (CS9) — shared cluster observability handle. `handle_cluster_status`
    /// reads role / generations / hashes, the secondary's poll telemetry, and
    /// the primary's peer roster from here. `Some` only on an enabled cluster
    /// node; `None` ⇒ the handler reports `enabled = false`. Same `Arc` the API
    /// server's heartbeat handler writes through (`ApiState.cluster_observe`).
    /// Behind the `cluster` feature so the default `DaemonState` is unchanged.
    #[cfg(feature = "cluster")]
    pub cluster_observe: Option<Arc<crate::cluster::ClusterObserve>>,
}

/// Bind the IPC socket and start the accept loop. Returns the JoinHandle.
///
/// The bind phase runs synchronously (before spawning) so the caller can
/// handle bind errors (permission denied, address in use) instead of
/// having them silently logged inside a spawned task.
pub async fn spawn_ipc_server(
    socket_path: PathBuf,
    state: Arc<DaemonState>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let listener = bind_socket(&socket_path)?;
    tracing::info!(path = %socket_path.display(), "IPC socket listening");

    Ok(tokio::spawn(async move {
        accept_loop(listener, state, MAX_CONCURRENT_CONNECTIONS).await;
    }))
}

/// Test-only entry: same as [`spawn_ipc_server`] but with a configurable
/// concurrency cap. Exists so the H-07 boundary test can drive cap=2
/// instead of binding 64 idle clients to drive cap=64.
#[cfg(test)]
async fn spawn_ipc_server_with_cap(
    socket_path: PathBuf,
    state: Arc<DaemonState>,
    cap: usize,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let listener = bind_socket(&socket_path)?;
    Ok(tokio::spawn(async move {
        accept_loop(listener, state, cap).await;
    }))
}

/// Bind the Unix socket: remove stale file, create parent dir, bind, set permissions.
fn bind_socket(socket_path: &Path) -> anyhow::Result<UnixListener> {
    // Only remove a stale socket — refuse to clobber any other file type.
    // `symlink_metadata` does not follow symlinks, so a planted symlink
    // trips the "not a socket" branch instead of being followed and
    // possibly removing the target via the unlink syscall.
    match std::fs::symlink_metadata(socket_path) {
        Ok(meta) => {
            use std::os::unix::fs::FileTypeExt;
            if !meta.file_type().is_socket() {
                anyhow::bail!(
                    "{} exists but is not a socket — refusing to remove. \
                     Inspect the file, then run `rm {}` manually if it is safe to delete.",
                    socket_path.display(),
                    socket_path.display()
                );
            }
            std::fs::remove_file(socket_path)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {} // fresh start
        Err(e) => return Err(e.into()),
    }

    // Ensure parent directory exists. rev-2606 api-auth-07-05 / §4.40
    // DISC-3 pattern (mirrors `auth_token::save_token_at`): only chmod
    // the parent when WE created it — a fresh dir would otherwise land
    // at `0o777 & ~umask` (umask-dependent). In production
    // `/run/purge-warden/` pre-exists via systemd and is untouched; this
    // covers ad-hoc / test rigs. 0o700 is consistent with the §4.32
    // fail-closed peer-uid gate: every legitimate IPC peer runs as the
    // daemon user, so nothing else needs traversal.
    if let Some(parent) = socket_path.parent() {
        let pre_existed = parent.exists();
        std::fs::create_dir_all(parent)?;
        if !pre_existed {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }

    let listener = bind_with_atomic_perms(socket_path)?;
    Ok(listener)
}

/// Bind a tokio `UnixListener` so the socket file is observable at the
/// canonical path with mode `0o600` from the very first syscall a peer
/// could resolve it through. Closes the TOCTOU window where a `bind`
/// followed by a separate `chmod` exposes the socket briefly with
/// `0o666 & ~umask` (typically `0o644`).
///
/// Approach: bind to a per-call temp path in the same parent directory,
/// `chmod` it to `0o600`, then `rename(2)` to the canonical path. The
/// rename is atomic — at the canonical path the socket either does not
/// exist, or exists with mode `0o600`. There is no observable
/// intermediate state at the canonical path. This is the pattern used
/// by `systemd-socket-activate` and the standard atomic-write idiom.
///
/// The temp path retains umask-default perms briefly, but its name is
/// per-call (pid + nanos) and only visible to processes that already
/// have read on the parent directory. In production, that parent is
/// `/run/purge-warden/` (group-locked to `purge-warden`); read access
/// to the dir already implies `0o600` access to the socket, so the
/// temp window does not widen the threat model.
fn bind_with_atomic_perms(socket_path: &Path) -> anyhow::Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;

    let parent = socket_path.parent().ok_or_else(|| {
        anyhow::anyhow!("IPC socket path has no parent: {}", socket_path.display())
    })?;
    let stem = socket_path
        .file_name()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "IPC socket path has no file name: {}",
                socket_path.display()
            )
        })?
        .to_string_lossy();

    // Per-call unique temp name. Collisions with attacker-planted files
    // are countered by `O_EXCL`-like behaviour: `UnixListener::bind`
    // fails if the path already exists, so we'd surface that as an
    // error rather than silently clobber.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let temp_name = format!(".{stem}.bind.{}.{nanos}", std::process::id());
    let temp_path = parent.join(temp_name);

    // Bind to the temp path. If a stale temp exists (e.g. previous
    // crashed daemon), fail loudly rather than clobber — the temp
    // path is supposed to be unique-per-call.
    let listener = UnixListener::bind(&temp_path).map_err(|e| {
        anyhow::anyhow!(
            "failed to bind IPC socket at temp path {}: {e}",
            temp_path.display()
        )
    })?;

    // Tighten mode on the temp path before exposing it at the
    // canonical path. After the rename(2) below, peers see `0o600`
    // from the very first stat / connect (§4.32 — owner-only;
    // defense in depth alongside the peer-uid gate).
    if let Err(e) = std::fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(0o600)) {
        // Drop listener (closes FD) and unlink temp before bailing
        // so the next bind attempt starts clean.
        drop(listener);
        std::fs::remove_file(&temp_path).ok();
        return Err(anyhow::anyhow!(
            "failed to chmod IPC socket at temp path {}: {e}",
            temp_path.display()
        ));
    }

    // Atomically swap the temp path into the canonical position.
    // `rename(2)` on the same filesystem is atomic; an observer
    // resolving `socket_path` either sees the prior state (which the
    // H-09 check has already cleared) or the new socket with `0o600`.
    if let Err(e) = std::fs::rename(&temp_path, socket_path) {
        drop(listener);
        std::fs::remove_file(&temp_path).ok();
        return Err(anyhow::anyhow!(
            "failed to rename IPC socket {} -> {}: {e}",
            temp_path.display(),
            socket_path.display()
        ));
    }

    Ok(listener)
}

/// Maximum concurrent in-flight IPC handlers. Each connection holds an
/// FD plus up to `MAX_COMMAND_SIZE + 1` bytes of buffered request data
/// for at least the read-side timeout. 64 is generous for a single-host
/// IPC bus — the TUI uses ~1, the CLI uses 1 per invocation, the API
/// daemon does not consume IPC. A peer that opens connections faster
/// than handlers complete sees the excess streams closed immediately
/// rather than queued, so spawn-flood attacks cannot exhaust FDs, heap,
/// or tokio task slots on the runtime that also services DNS queries.
const MAX_CONCURRENT_CONNECTIONS: usize = 64;

/// First backoff step on a persistent `accept` error. Doubles every
/// consecutive error up to [`ACCEPT_BACKOFF_CAP`].
const ACCEPT_BACKOFF_BASE: std::time::Duration = std::time::Duration::from_millis(100);

/// Cap on the per-error sleep so the accept loop still wakes up on a
/// reasonable cadence even under sustained pressure. 5 s matches the
/// IPC read/write timeout — operators see "IPC degraded" symptoms on
/// the same order of magnitude regardless of which layer is failing.
const ACCEPT_BACKOFF_CAP: std::time::Duration = std::time::Duration::from_secs(5);

/// Pure backoff schedule extracted for unit testing. Maps the index
/// of the consecutive accept error (0-based) to the sleep duration:
///
/// 0 → 100 ms, 1 → 200 ms, 2 → 400 ms, ... saturating at 5 s.
///
/// Reset to 0 on the next successful `accept`. Caller is responsible
/// for the reset + the sleep itself; the helper is total and
/// allocation-free.
fn accept_backoff_for(consecutive_errors: u32) -> std::time::Duration {
    // u32::MIN..=31 doublings cover everything we care about; beyond
    // that the cap dominates anyway. checked_shl avoids the UB that
    // bare `<<` would invoke on shift-by-32-or-more.
    let scaled = ACCEPT_BACKOFF_BASE
        .checked_mul(1_u32.checked_shl(consecutive_errors).unwrap_or(u32::MAX))
        .unwrap_or(ACCEPT_BACKOFF_CAP);
    if scaled > ACCEPT_BACKOFF_CAP {
        ACCEPT_BACKOFF_CAP
    } else {
        scaled
    }
}

/// Accept loop — runs inside a spawned task. Errors are logged, not propagated.
async fn accept_loop(listener: UnixListener, state: Arc<DaemonState>, cap: usize) {
    // Bound concurrent in-flight handlers. `try_acquire_owned` never
    // blocks the accept loop itself — when the cap is hit we drop the
    // freshly-accepted stream, which the peer observes as ECONNRESET.
    // Awaiting on the semaphore in the accept loop would turn the loop
    // itself into a serialization point, defeating the purpose.
    let permits = Arc::new(tokio::sync::Semaphore::new(cap));
    // M-27: consecutive accept errors. Reset on every successful
    // accept. Used to compute exponential backoff so a sustained
    // EMFILE / ENFILE / ENOBUFS storm does not pin the runtime
    // worker at 10 Hz forever (the previous flat 100 ms sleep).
    // Handler-side errors (M-25 timeouts, IO failures inside
    // handle_connection) MUST NOT touch this counter — they live in
    // a different spawned task and the cross-connection backoff
    // here is only the right response to listener-level failures.
    let mut consecutive_errors: u32 = 0;
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                consecutive_errors = 0;
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    tracing::warn!(cap, "IPC busy: dropping connection (concurrency cap hit)");
                    // Dropping the stream closes the FD; the peer
                    // sees ECONNRESET on its next read/write.
                    drop(stream);
                    continue;
                };
                let peer_uid = peer_uid(&stream);
                let state = state.clone();
                tokio::spawn(async move {
                    // Move the permit into the spawned task so it stays
                    // held for the entire handler lifetime. Released on
                    // task exit (success, error, or panic).
                    let _permit = permit;
                    if let Err(e) = handle_connection(stream, peer_uid, &state).await {
                        tracing::warn!(error = %e, "IPC connection error");
                    }
                });
            }
            Err(e) => {
                let backoff = accept_backoff_for(consecutive_errors);
                consecutive_errors = consecutive_errors.saturating_add(1);
                tracing::warn!(
                    error = %e,
                    consecutive_errors,
                    backoff_ms = backoff.as_millis() as u64,
                    "IPC accept error — backing off"
                );
                // tokio::time::sleep (NOT std::thread::sleep) so the
                // backoff yields to the runtime; otherwise a stalled
                // accept_loop would block every other task on the
                // same worker, including DNS dispatch.
                tokio::time::sleep(backoff).await;
            }
        }
    }
}

/// Extract the peer uid from an accepted Unix socket stream via
/// `SO_PEERCRED` (Sprint 32 N1 audit trail, §4.32 enforcement).
///
/// Returns `None` only if the `getsockopt` call fails — extremely unlikely
/// on Linux for a freshly-accepted Unix stream. §4.32 P0 treats a `None`
/// return as a peer-uid mismatch: [`handle_connection`] refuses the
/// connection rather than dispatching to any handler. The audit pipeline
/// records the refusal so the operator can investigate, but the peer
/// itself sees ECONNRESET with no `IpcResponse` body.
///
/// For audit emits *inside* a handler — where the gate has already
/// confirmed `peer_uid == state.daemon_uid` — `None` is structurally
/// unreachable, but the field type stays `Option<u32>` because the
/// audit subscribers and the reload-coalescer's last-uid slot have
/// pre-§4.32 shape and survive a SIGHUP-triggered reload (signals have
/// no peer cred).
fn peer_uid(stream: &UnixStream) -> Option<u32> {
    let fd = stream.as_raw_fd();
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len: libc::socklen_t = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `libc::getsockopt` is an FFI call into the kernel's
    // socket-options API. The four conditions for soundness here:
    //
    // 1. `fd` is a live, open file descriptor for the duration of the
    //    syscall. Upheld by the `stream: &UnixStream` borrow holding
    //    the FD live across this function — `as_raw_fd` does not
    //    transfer ownership, and the kernel only consults `fd`
    //    synchronously inside `getsockopt` before returning.
    //
    // 2. The `optval` pointer is valid for `*optlen` writable bytes
    //    of the right type. Upheld by `cred` being a fully-initialised
    //    `libc::ucred` POD on the stack (every field zeroed above) and
    //    the cast from `&mut cred` producing an exclusive raw pointer
    //    whose lifetime outlives the syscall. The kernel writes at
    //    most `*optlen` = `sizeof(ucred)` bytes, matching the buffer.
    //
    // 3. The `optlen` pointer is valid for `socklen_t`-sized read +
    //    write. Upheld by `len` being a fully-initialised `socklen_t`
    //    on the stack with the correct initial size, and the
    //    exclusive borrow living across the syscall.
    //
    // 4. No cross-thread aliasing on the buffers. Upheld because
    //    `cred` and `len` are stack-locals exclusively borrowed only
    //    by this scope; the kernel does not retain pointers past the
    //    syscall return.
    //
    // Failure modes (errno != 0) cannot leave `cred` partially-written
    // in a way that invalidates the POD assumption — the kernel either
    // populates all of `cred` and returns 0, or returns -1 and we
    // ignore `cred`'s contents.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::from_mut(&mut cred).cast::<libc::c_void>(),
            std::ptr::from_mut(&mut len),
        )
    };
    if rc == 0 {
        Some(cred.uid)
    } else {
        tracing::debug!(
            errno = std::io::Error::last_os_error().raw_os_error(),
            "SO_PEERCRED lookup failed on IPC socket"
        );
        None
    }
}

/// Maximum command line size (64 KiB). Enforced at the reader level via `take()`
/// so memory is bounded before allocation, not checked after.
const MAX_COMMAND_SIZE: u64 = 65_536;

/// Per-side I/O budget on every IPC connection (M-25). Mirrors the
/// 5-second read timeout (`tokio::time::timeout` around `read_line`)
/// onto the write + shutdown halves. A slow-loris peer that accepts
/// the response at 1 B/s — or refuses to read — would otherwise pin
/// the handler task indefinitely and burn one of the 64 H-07
/// concurrency permits until the daemon restart. 5 s is generous for
/// a local Unix-socket round trip (typical <1 ms).
const IPC_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Handle a single IPC connection: read command, dispatch, write response.
///
/// `peer_uid` is the uid of the connecting process, extracted via
/// `SO_PEERCRED` at accept time. Threaded through to every mutating
/// handler so the audit log (Sprint 32 N1, expanded in §4.32) can
/// attribute the action to a specific local user.
///
/// §4.32 P0: BEFORE reading the first byte of the request, this
/// handler enforces the peer-uid gate. The connection is silently
/// dropped (no `IpcResponse` written, peer observes ECONNRESET) when:
///
/// 1. `peer_uid` is `None` — `SO_PEERCRED` failed; fail-closed because
///    a missing uid means we cannot prove the peer is the daemon user.
/// 2. `peer_uid` is `Some(uid)` with `uid != state.daemon_uid`.
///
/// The rejection emits a single audit warn line so operators can spot
/// foreign-uid probes in `journalctl -u purge-warden`. No response is
/// written: leaking "the daemon expects uid X" would slightly widen
/// the discovery surface for an attacker who somehow obtained the
/// socket FD.
async fn handle_connection(
    stream: tokio::net::UnixStream,
    peer_uid: Option<u32>,
    state: &DaemonState,
) -> anyhow::Result<()> {
    // §4.32 P0: peer-uid gate. Fail-closed for ALL verbs (incl.
    // ReadOnly) — the 0o600 socket already blocks non-daemon peers,
    // so keeping ReadOnly open is dead code on production and only
    // widens the design surface. Locked decision D1 in the §4.32
    // plan.
    match peer_uid {
        Some(uid) if uid == state.daemon_uid => {}
        other => {
            tracing::warn!(
                target: "audit",
                event = "ipc.peer_uid.refused",
                peer_uid = ?other,
                daemon_uid = state.daemon_uid,
                "IPC connection refused: peer uid mismatch"
            );
            drop(stream);
            return Ok(());
        }
    }

    let (reader, mut writer) = stream.into_split();
    // Cap the reader at MAX_COMMAND_SIZE + 1 to bound memory allocation
    let limited = reader.take(MAX_COMMAND_SIZE + 1);
    let mut reader = BufReader::new(limited);
    let mut line = String::new();

    let n = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        reader.read_line(&mut line),
    )
    .await
    .map_err(|_| anyhow::anyhow!("IPC read timeout"))??;

    if n == 0 {
        return Ok(()); // Client disconnected without sending
    }

    let response = if line.len() as u64 > MAX_COMMAND_SIZE {
        ipc_error(IpcError::CommandTooLarge)
    } else {
        match serde_json::from_str::<IpcCommand>(line.trim()) {
            Ok(cmd) => dispatch_command(cmd, peer_uid, state).await,
            Err(e) => {
                tracing::warn!(
                    target: "ipc.error",
                    error = %e,
                    "invalid IPC command — JSON decode failed"
                );
                ipc_error(IpcError::InvalidCommand)
            }
        }
    };

    let mut resp_json = serde_json::to_string(&response)?;
    resp_json.push('\n');
    // M-25: bound write_all + shutdown by IPC_WRITE_TIMEOUT so a
    // slow-loris peer cannot pin the handler task. On timeout we drop
    // the connection (the spawned task ends → H-07 permit released
    // automatically). The peer observes ECONNRESET, which matches
    // the over-cap drop path's behavior.
    tokio::time::timeout(IPC_WRITE_TIMEOUT, writer.write_all(resp_json.as_bytes()))
        .await
        .map_err(|_| anyhow::anyhow!("IPC write timeout"))??;
    // Half-close so the peer sees clean EOF on its read side rather
    // than ECONNRESET — runs on EVERY response path (success, parse
    // error, oversize). M-26 unified what used to be a shutdown-on-
    // success-only path.
    tokio::time::timeout(IPC_WRITE_TIMEOUT, writer.shutdown())
        .await
        .map_err(|_| anyhow::anyhow!("IPC shutdown timeout"))??;

    Ok(())
}

/// Dispatch an IPC command to the appropriate handler.
///
/// P0-3: enforces the three-tier authorization gate before routing to
/// the per-command handler. ReadOnly commands pass through unchecked;
/// Mutating and Admin commands must carry a plaintext token that the
/// daemon verifies against `state.api_token_hash` in constant time.
async fn dispatch_command(
    cmd: IpcCommand,
    peer_uid: Option<u32>,
    state: &DaemonState,
) -> IpcResponse {
    // Authorization gate (P0-3).
    if cmd.tier() != CommandTier::ReadOnly {
        if let Some(err_resp) = auth_error_for(&cmd, peer_uid, state) {
            return err_resp;
        }
    }

    match cmd {
        IpcCommand::Status => handle_status(state).await,
        IpcCommand::Query { domain } => handle_query(&domain, state),
        IpcCommand::CacheFlush { domain, .. } => {
            handle_cache_flush(domain.as_deref(), peer_uid, state).await
        }
        IpcCommand::ForgetList { id, .. } => handle_forget_list(id, peer_uid, state).await,
        IpcCommand::Reload { .. } => handle_reload(peer_uid, state).await,
        IpcCommand::Shutdown { .. } => handle_shutdown(peer_uid, state).await,
        IpcCommand::DomainCount => handle_domain_count(state),
        IpcCommand::TrackingStats { .. } => handle_tracking_stats(state),
        IpcCommand::DeviceStats { .. } => handle_device_stats(state),
        IpcCommand::GetAllDevices => handle_get_all_devices(state).await,
        IpcCommand::QueryLogs {
            limit,
            client,
            blocked_only,
            domain,
            since_secs,
            cursor,
            advanced,
            ..
        } => {
            handle_query_logs(
                state,
                crate::ipc::protocol::QueryLogRequest {
                    limit,
                    client,
                    blocked_only,
                    domain,
                    since_secs,
                    cursor,
                    advanced,
                },
            )
            .await
        }
        IpcCommand::DeviceAdd { client, .. } => handle_device_add(state, client, peer_uid).await,
        IpcCommand::DeviceUpdate { name, patch, .. } => {
            handle_device_update(state, name, patch, peer_uid).await
        }
        IpcCommand::DeviceRemove { name, .. } => handle_device_remove(state, name, peer_uid).await,
        IpcCommand::DevicePromote {
            ip,
            name,
            profile,
            owner,
            device_type,
            department,
            ..
        } => {
            handle_device_promote(
                state,
                ip,
                name,
                profile,
                owner,
                device_type,
                department,
                peer_uid,
            )
            .await
        }
        IpcCommand::TrackingConfigUpdate { patch, .. } => {
            handle_tracking_config_update(state, patch, peer_uid).await
        }
        IpcCommand::DaemonLogs {
            limit,
            level,
            contains,
            ..
        } => handle_daemon_logs(state, limit, level, contains.as_deref()),
        IpcCommand::BlocklistStats { source_id } => handle_blocklist_stats(state, source_id),
        IpcCommand::LocalRecordsHits => handle_local_records_hits(state),
        IpcCommand::ProfileCreate {
            id, display_name, ..
        } => handle_profile_create(state, id, display_name, peer_uid).await,
        IpcCommand::ProfileUpdate { id, patch, .. } => {
            handle_profile_update(state, id, patch, peer_uid).await
        }
        IpcCommand::ProfileDelete { id, .. } => handle_profile_delete(state, id, peer_uid).await,
        #[cfg(feature = "cluster")]
        IpcCommand::ClusterStatus => handle_cluster_status(state),
    }
}

/// Verify the token on a Mutating or Admin command. Returns `Some(err_resp)`
/// with a plain-English rejection if the check fails, or `None` if the
/// command is authorized.
///
/// Three failure modes — each gets its own message so the operator knows
/// *what* to do:
///
/// 1. Daemon has no token hash configured → `warden token generate`
/// 2. Command has no token attached → use the `warden` CLI (it auto-
///    discovers from `/var/lib/purge-warden/token`)
/// 3. Token hash mismatch → `warden token regenerate`
///
/// Intentionally keeps **no** per-uid failure lockout (unlike the API's
/// `AuthRateLimiter`): the 0o600 socket + fail-closed peer-uid gate already
/// restrict callers to the daemon uid — who can read the token file directly —
/// and the token is 256-bit, compared in constant time, so brute force is
/// infeasible. Lockout state on the control path would buy nothing; don't add it.
fn auth_error_for(
    cmd: &IpcCommand,
    peer_uid: Option<u32>,
    state: &DaemonState,
) -> Option<IpcResponse> {
    // `auth_error_for` is synchronous (no `.await`), so the ArcSwap guard is
    // simply held across the whole check: `stored_hash` borrows from it and
    // feeds `verify_token` directly, with no clone and no suspension point the
    // guard could outlive.
    let hash_snapshot = state.api_token_hash.load();
    let stored_hash: &str = match hash_snapshot.as_deref() {
        Some(h) if !h.is_empty() => h,
        _ => {
            return Some(ipc_error(IpcError::NoTokenConfigured));
        }
    };

    let submitted = match cmd.token() {
        Some(t) if !t.is_empty() => t,
        _ => {
            return Some(ipc_error(IpcError::TokenRequired));
        }
    };

    if verify_token(submitted, stored_hash) {
        None
    } else {
        tracing::warn!(
            target: "audit",
            event = "ipc.auth.token_mismatch",
            uid = ?peer_uid,
            action = %cmd.action_name(),
            tier = ?cmd.tier(),
            "IPC auth: token mismatch"
        );
        Some(ipc_error(IpcError::TokenMismatch))
    }
}

async fn handle_status(state: &DaemonState) -> IpcResponse {
    // T2.9 / H-20: query-log silent-drop counters. `None` when tracking
    // is off or no writer is currently attached — keeps the CLI's
    // "logging disabled" rendering distinguishable from a healthy zero.
    let query_log_drops = state
        .stats
        .as_ref()
        .and_then(|s| s.query_log_drop_counters());
    let (lists_active, lists_total, lists_truncated) = match &state.list_statuses {
        Some(reg) => {
            let snap = reg.snapshot();
            let total = snap.len() as u32;
            let active = snap
                .iter()
                .filter(|(_, s)| matches!(s.last_outcome, crate::lists::status::LastOutcome::Ok))
                .count() as u32;
            // Counted over every source, not just the active ones: a
            // source that truncated and then failed its next refresh is
            // still serving a partial list from the retained generation.
            let truncated = snap.iter().filter(|(_, s)| s.parsed_truncated > 0).count() as u32;
            (active, total, truncated)
        }
        None => (0, 0, 0),
    };
    // Cycle-level, so it is read straight off the registry rather than
    // derived from the per-source snapshot above — in this state every one
    // of those rows is healthy, which is precisely the problem.
    let lists_corpus_refusal = state
        .list_statuses
        .as_ref()
        .and_then(|reg| reg.corpus_refusal());
    // Read AFTER the refusal above, and the order is deliberate. A cycle
    // that lands between the two reads would pair an older refusal with a
    // newer mark — which makes the caller re-poll, the harmless direction.
    // Reading the mark first could pair a NEW refusal with an OLD seq, and
    // the caller would report the previous cycle's verdict as its own.
    // `map`, not `and_then`: the registry always HAS a mark (seq 0 before
    // the first cycle), so `None` here means one thing only — this daemon
    // has no list subsystem wired, and no cycle is ever coming. A caller
    // must not wait on that, and `None` is how it learns not to.
    let lists_cycle = state.list_statuses.as_ref().map(|reg| reg.cycle());
    // Sprint C T3 of `lists_categories_v2` (§5.4 / §8.5): walk the
    // retry state machine and tally per-state counts. The walk runs
    // under the existing `Mutex` so a concurrent `record_blocklist_*`
    // call serialises through the same lock. `None` (no list_state
    // wired) renders as zeros in the response, and the CLI omits
    // the "Lists" diagnostic section accordingly.
    let lc2_list_diagnostics = match &state.list_state {
        Some(handle) => {
            let now = time::OffsetDateTime::now_utc();
            let stale_cutoff = now - time::Duration::days(7);
            // Recover rather than panic on a poisoned lock: a prior panic
            // elsewhere must not turn a ReadOnly `Status` query into a dropped
            // connection. The snapshot is cloned out immediately, tolerating a
            // possibly-torn read.
            let snap = handle.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let mut active = 0u32;
            let mut pending = 0u32;
            let mut failed = 0u32;
            let mut stale_over_7d = 0u32;
            for entry in snap.lists.values() {
                match entry.status {
                    crate::config::list_state::ListStatus::Active => {
                        active += 1;
                        if let Some(ts) = entry.last_success {
                            if ts < stale_cutoff {
                                stale_over_7d += 1;
                            }
                        }
                    }
                    crate::config::list_state::ListStatus::Pending => pending += 1,
                    crate::config::list_state::ListStatus::Failed => failed += 1,
                }
            }
            crate::ipc::protocol::ListDiagnostics {
                active,
                pending,
                failed,
                stale_over_7d,
            }
        }
        None => crate::ipc::protocol::ListDiagnostics::default(),
    };
    // §4.13 — `Arc<Option<...>>` → owned `Option<...>`. Deref once
    // through the `Arc`; `Option<ResourceBudgetSnapshot>` is `Copy` so
    // we move it out by value without allocating.
    let resource_budget = *state.resource_budget_store.load_full();
    // mem2608-s3 / F-E: flush moka before reading — entry_count() and
    // weighted_size() are each eventually consistent, and a cold read
    // here is exactly what made a live, actively-hit cache print
    // "cache: 0 / 10000 entries". Off the `:53` hot path (this only runs
    // on an operator-initiated `warden status` IPC call), so the await
    // costs nothing that matters. See `DnsCache::flushed_usage`.
    let cache_usage = state.cache.flushed_usage().await;
    IpcResponse::Status {
        pid: std::process::id(),
        listen: state.listen_addr.clone(),
        upstream_mode: state.upstream_mode.clone(),
        upstream_count: state.upstream_count,
        domain_count: state.filter.domain_count(),
        cache_entries: cache_usage.entries,
        list_count: state.list_count,
        uptime_secs: state.started_at.elapsed().as_secs(),
        query_log_drops,
        version: env!("CARGO_PKG_VERSION").to_string(),
        // Not eventually-consistent (a fixed config value, not a moka
        // aggregate) — no flush needed for this one.
        cache_cap: state.cache.max_capacity(),
        cache_weighted_size: cache_usage.weighted_size,
        lists_active,
        lists_truncated,
        lists_corpus_refusal,
        lists_cycle,
        lists_total,
        lc2_list_diagnostics,
        resource_budget,
    }
}

/// §4.11-4 (CS9): build this node's cluster view from the shared observe
/// handle. Returns `enabled = false` when clustering is off (no handle wired),
/// so a `cluster`-feature daemon with `[cluster].enabled = false` still answers
/// cleanly. Primary → generations/hashes + roster (self-row + peers);
/// secondary → poll telemetry (last-sync age, ok/err, converged).
#[cfg(feature = "cluster")]
fn handle_cluster_status(state: &DaemonState) -> IpcResponse {
    use crate::config::schema::ClusterRole;
    use crate::ipc::protocol::{ClusterStatusDto, RosterEntryDto};

    let Some(obs) = state.cluster_observe.as_ref() else {
        return IpcResponse::ClusterStatus {
            status: ClusterStatusDto {
                enabled: false,
                role: "primary".into(),
                peer: None,
                config_generation: 0,
                config_hash: String::new(),
                last_sync_secs: None,
                last_poll_ok: false,
                last_error: None,
                converged: false,
                roster: Vec::new(),
            },
        };
    };

    let role = match obs.role {
        ClusterRole::Primary => "primary",
        ClusterRole::Secondary => "secondary",
    };

    // Primary serve-state: generation + current content hash (None on a
    // secondary, which has no serve-state — it tracks the last-applied hash).
    let (config_generation, primary_config_hash) = obs.generations().unwrap_or((0, String::new()));

    // Secondary poll telemetry.
    let sync = obs.load_sync();
    let last_sync_secs = sync.last_sync.map(|t| t.elapsed().as_secs());
    let converged = sync.synced_at_least_once && sync.last_poll_ok;
    // On a secondary the "current" hash IS the last-applied one; on a primary
    // it is the serve-state's live hash.
    let config_hash = if obs.role == ClusterRole::Secondary {
        sync.last_config_hash.clone().unwrap_or_default()
    } else {
        primary_config_hash
    };

    // Primary roster (self-row + peers); empty on a secondary.
    let roster = obs
        .roster_snapshot(std::time::Instant::now())
        .into_iter()
        .map(|r| RosterEntryDto {
            name: r.name,
            addr: r.addr,
            is_self: r.is_self,
            online: r.online,
            total_queries: r.total_queries,
            total_blocked: r.total_blocked,
            qps: r.qps,
            blocked_pct: r.blocked_pct,
            share_pct: r.share_pct,
        })
        .collect();

    IpcResponse::ClusterStatus {
        status: ClusterStatusDto {
            enabled: true,
            role: role.into(),
            peer: obs.peer.clone(),
            config_generation,
            config_hash,
            last_sync_secs,
            last_poll_ok: sync.last_poll_ok,
            last_error: sync.last_error.clone(),
            converged,
            roster,
        },
    }
}

fn handle_query(domain: &str, state: &DaemonState) -> IpcResponse {
    let normalized = domain.to_ascii_lowercase();
    let normalized = normalized.strip_suffix('.').unwrap_or(&normalized);

    // rev-2606 api-auth-07-04: validate at the trust boundary, mirroring
    // the HTTP twin (`handlers::query_domain` → `validate_api_domain`).
    // The peer-uid gate makes exploitation moot, but the two probe
    // surfaces must agree on what a queryable domain is — and a garbage
    // input now gets a real error instead of a meaningless "not blocked".
    // §4.33: detail to the daemon log, frozen generic on the wire.
    let normalized = match crate::config::schema::admin_rule::validate_domain(normalized) {
        Ok(canonical) => canonical,
        Err(reason) => {
            tracing::warn!(
                target: "ipc.error",
                error = %reason,
                "query: invalid domain rejected at IPC boundary",
            );
            return ipc_error(IpcError::InvalidArgument);
        }
    };
    let normalized = normalized.as_str();

    // §4.2 G1a — surface the block attribution the engine already
    // computes (`evaluate_attributed`), not just the boolean. Off the
    // hot path: this is the on-demand operator probe, not the per-query
    // DNS path. `source` is `Some` only alongside a Block verdict, so
    // `.map(..)` yields `None` for allowed domains automatically. The
    // no-profile fallbacks have no `ResolvedProfile` to attribute
    // against, so `blocked_by` stays `None` there (behaviour otherwise
    // unchanged).
    let (blocked, blocked_by) = match &state.profiles {
        Some(resolver) => match resolver.default_profile() {
            Some(profile) => {
                let (verdict, source) = state.filter.evaluate_attributed(normalized, &profile);
                (
                    verdict == FilterResult::Block,
                    source.map(|s| s.describe(&state.list_labels)),
                )
            }
            // SN2 invariant — when `default_profile` is unset, every
            // ambient query would be REFUSED. The IPC probe doesn't have
            // a client IP to evaluate against, so treat this as "would
            // be blocked" for the `warden query` CLI output.
            None => (true, None),
        },
        None => (state.filter.is_blocked(normalized), None),
    };

    IpcResponse::QueryResult {
        domain: normalized.to_string(),
        blocked,
        blocked_by,
    }
}

async fn handle_cache_flush(
    domain: Option<&str>,
    peer_uid: Option<u32>,
    state: &DaemonState,
) -> IpcResponse {
    match domain {
        Some(d) => {
            state.cache.invalidate_domain(d).await;
            tracing::info!(
                target: "audit",
                action = "cache.flush",
                uid = ?peer_uid,
                domain = %d,
                "IPC mutation"
            );
            IpcResponse::Ok {
                message: format!("cache flushed for {d}"),
            }
        }
        None => {
            state.cache.clear().await;
            tracing::info!(
                target: "audit",
                action = "cache.flush",
                uid = ?peer_uid,
                domain = "*",
                "IPC mutation"
            );
            IpcResponse::Ok {
                message: "cache flushed".into(),
            }
        }
    }
}

/// §4.7 Phase 2 T1: drop a list source's in-memory cache entry AND
/// unlink its `<stem>.cache` + `<stem>.meta` sidecars from disk. The
/// list manager owns the actual mutation; this handler is the IPC
/// shim that sends a [`ListManagerCommand::Forget`](crate::lists::manager::ListManagerCommand::Forget) over the
/// out-of-band channel and awaits the oneshot ack.
///
/// Returns `ListForgotten { id, was_cached }` on success. `was_cached`
/// echoes whether the source had any state before the call —
/// idempotent semantics, so a second forget on a never-cached source
/// is `Ok` with `was_cached: false`, not an error.
///
/// Audit log: emits one record per call per `project_config_safety_v12`
/// — operators can grep the audit stream for unexpected forgets.
async fn handle_forget_list(id: String, peer_uid: Option<u32>, state: &DaemonState) -> IpcResponse {
    use crate::lists::manager::ListManagerCommand;

    let tx_guard = state.list_cmd_tx.load();
    let tx = match tx_guard.as_ref() {
        Some(t) => t.clone(),
        None => {
            return ipc_error(IpcError::ListManagerNotRunning);
        }
    };
    drop(tx_guard);

    let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
    if tx
        .send(ListManagerCommand::Forget {
            source: id.clone(),
            ack: ack_tx,
        })
        .await
        .is_err()
    {
        return ipc_error(IpcError::ListManagerChannelClosed);
    }

    match ack_rx.await {
        Ok(was_cached) => {
            tracing::info!(
                target: "audit",
                action = "list.forget",
                uid = ?peer_uid,
                id = %id,
                was_cached,
                "IPC mutation"
            );
            IpcResponse::ListForgotten { id, was_cached }
        }
        Err(_) => ipc_error(IpcError::ListManagerNoAck),
    }
}

async fn handle_reload(peer_uid: Option<u32>, state: &DaemonState) -> IpcResponse {
    // Sprint 43 T4 (D4): IPC reloads route through the 250 ms
    // coalescer when one is wired. The actual ResolverMap rebuild
    // happens at most once per window — multiple in-flight requests
    // collapse into a single `reload_tx` message. SIGHUP keeps the
    // direct path so signal-driven reloads stay immediate.
    //
    // §4.32 DISC-1: emit `action = "daemon.reload"` audit attribution
    // before handing off to either the coalescer or `reload_tx`. The
    // coalescer's drain-side audit pin (`RULE_RELOAD_BATCHED`) records
    // the eventual rebuild; this emit records the operator-issued
    // request itself so the audit trail covers both endpoints.
    tracing::info!(
        target: "audit",
        action = "daemon.reload",
        uid = ?peer_uid,
        "IPC mutation"
    );

    if let Some(coalescer) = &state.reload_coalescer {
        // A refusal means the coalescer's worker has exited, so nothing
        // will ever service this request. Reporting it as queued would
        // hand the operator a success for a write the daemon will never
        // apply — the one failure this path must not swallow.
        let Some(pending) = coalescer.request(peer_uid).await else {
            return ipc_error(IpcError::ReloadChannelClosed);
        };
        return IpcResponse::Ok {
            message: format!(
                "reload queued (batch position {pending}; rebuild fires within \
                 the {} ms coalescing window)",
                crate::ipc::RELOAD_COALESCE_WINDOW.as_millis()
            ),
        };
    }
    if let Some(tx) = &state.reload_tx {
        match tx.send(peer_uid).await {
            Ok(()) => IpcResponse::Ok {
                message: "reload triggered".into(),
            },
            Err(_) => ipc_error(IpcError::ReloadChannelClosed),
        }
    } else {
        ipc_error(IpcError::ReloadNotAvailable)
    }
}

async fn handle_shutdown(peer_uid: Option<u32>, state: &DaemonState) -> IpcResponse {
    // §4.32 DISC-1: shutdown is the highest-blast-radius IPC action;
    // audit attribution must precede the channel send.
    tracing::info!(
        target: "audit",
        action = "daemon.shutdown",
        uid = ?peer_uid,
        "IPC mutation"
    );

    if let Some(tx) = &state.shutdown_tx {
        match tx.send(peer_uid).await {
            Ok(()) => IpcResponse::Ok {
                message: "shutdown initiated".into(),
            },
            Err(_) => ipc_error(IpcError::ShutdownChannelClosed),
        }
    } else {
        ipc_error(IpcError::ShutdownNotAvailable)
    }
}

fn handle_domain_count(state: &DaemonState) -> IpcResponse {
    IpcResponse::DomainCount {
        count: state.filter.domain_count(),
    }
}

/// Sprint 43 T1: read per-source list telemetry.
///
/// `source_id = None` returns one entry per `[lists].sources`. A
/// `Some(filter)` filter is matched against the registry in three
/// progressively-loose passes:
///   1. exact source string (legacy slug like `"privacy/ads"` or raw URL)
///   2. canonical `[[blocklists]].id` (looked up via the resolver's
///      `slug_to_id` bridge — the v1 id form `"privacy-ads"` resolves
///      back to the slash-form slug used by ListManager)
///   3. case-insensitive substring on the source string
///
/// Pass 3 is permissive on purpose: an operator typing `warden blocklist
/// stats ads` should hit `privacy/ads` without having to remember the
/// full slug. False positives are bounded — at most 64 sources can be
/// configured (`build_source_bit_map` panics over 64).
///
/// When the filter resolves no source, returns an empty
/// `BlocklistStatsList` rather than an `Error` — the caller (TUI / CLI)
/// renders "no matching source" more helpfully than a generic IPC error.
fn handle_blocklist_stats(state: &DaemonState, source_id: Option<String>) -> IpcResponse {
    let Some(registry) = state.list_statuses.as_ref() else {
        return IpcResponse::BlocklistStatsList { stats: Vec::new() };
    };

    let snapshot = registry.snapshot();
    let id_lookup = |source: &str| -> Option<String> {
        state
            .profiles
            .as_ref()
            .and_then(|r| r.id_for_slug(source))
            .map(|id| id.as_str().to_string())
    };

    let filtered = match source_id.as_deref() {
        None | Some("") => snapshot,
        Some(query) => {
            // Pass 1: exact match against the registry key.
            if let Some(slot) = snapshot.iter().find(|(s, _)| s == query) {
                vec![slot.clone()]
            } else if let Some(resolved_slug) =
                state.profiles.as_ref().and_then(|r| r.slug_for_id(query))
            {
                // Pass 2: query is a canonical [[blocklists]].id; map
                // it back to the slug-form the registry is keyed on.
                snapshot
                    .into_iter()
                    .filter(|(s, _)| s == &resolved_slug)
                    .collect()
            } else {
                // Pass 3: case-insensitive substring on the source.
                let needle = query.to_ascii_lowercase();
                snapshot
                    .into_iter()
                    .filter(|(s, _)| s.to_ascii_lowercase().contains(&needle))
                    .collect()
            }
        }
    };

    let stats: Vec<BlocklistStatusDto> = filtered
        .into_iter()
        .map(|(source, status)| {
            let id = id_lookup(&source);
            BlocklistStatusDto::from_status(source, id, &status)
        })
        .collect();
    IpcResponse::BlocklistStatsList { stats }
}

/// Sprint 44 follow-up (`s44-hits-ipc-verb`): snapshot the per-record
/// `LocalRecordsHits` counter and shape it for the TUI.
///
/// Returns an empty list — not an `Error` — when the daemon was started
/// without the counter wired (only happens in tests). The TUI then
/// renders every cell as `0`, which is correct on a boot-fresh daemon.
/// `logs-tab`: a filtered page of the daemon's own `tracing` events.
///
/// Formatting the timestamp happens HERE and not at capture time: the
/// capture path runs on the DNS query path's failure branches, and
/// `OffsetDateTime::format` allocates. Storing the raw `OffsetDateTime`
/// and formatting `limit` of them once per poll moves that cost off the
/// hot path entirely.
///
/// A `None` ring answers with an empty page (see [`DaemonState::log_ring`]).
fn handle_daemon_logs(
    state: &DaemonState,
    limit: usize,
    level: Option<crate::tracking::log_ring::LogLevel>,
    contains: Option<&str>,
) -> IpcResponse {
    let Some(ring) = state.log_ring.as_ref() else {
        return IpcResponse::DaemonLogs {
            entries: Vec::new(),
            dropped: 0,
            capacity: 0,
        };
    };
    // Same shape as `QueryLogDto::timestamp` so the two tables render
    // through one convention.
    let fmt = time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
    let entries = ring
        .snapshot(limit, level, contains)
        .into_iter()
        .map(|e| crate::ipc::protocol::DaemonLogDto {
            // A timestamp that fails to format would be a `time` bug, not
            // an operator-visible condition — degrade to the empty string
            // rather than dropping the line the operator came to read.
            timestamp: e.ts.format(&fmt).unwrap_or_default(),
            level: e.level,
            target: e.target.to_string(),
            message: e.message,
        })
        .collect();
    IpcResponse::DaemonLogs {
        entries,
        dropped: ring.dropped(),
        capacity: ring.capacity(),
    }
}

fn handle_local_records_hits(state: &DaemonState) -> IpcResponse {
    let Some(hits) = state.local_records_hits.as_ref() else {
        return IpcResponse::LocalRecordsHitsList {
            entries: Vec::new(),
        };
    };
    let entries = hits
        .snapshot()
        .into_iter()
        .map(|(scope, domain, count)| LocalRecordsHitEntry {
            scope: scope.as_display().into(),
            domain: domain.into(),
            count,
        })
        .collect();
    IpcResponse::LocalRecordsHitsList { entries }
}

// Stats display path: query counts that exceed `2^53` lose f64 precision,
// but at that point the operator has bigger problems. Ratios are bounded
// to 0..=100 so the rounding stays well within display tolerance.
#[allow(clippy::cast_precision_loss)]
fn handle_tracking_stats(state: &DaemonState) -> IpcResponse {
    use std::sync::atomic::Ordering;

    let Some(engine) = state.stats.as_ref() else {
        return ipc_error(IpcError::TrackingNotEnabled);
    };

    let total = engine.global.total_queries.load(Ordering::Relaxed);
    let blocked = engine.global.total_blocked.load(Ordering::Relaxed);
    let cache_hits = engine.global.total_cache_hits.load(Ordering::Relaxed);
    let cache_negative_hits = engine
        .global
        .total_cache_negative_hits
        .load(Ordering::Relaxed);

    let blocked_pct = if total > 0 {
        (blocked as f64 / total as f64) * 100.0
    } else {
        0.0
    };
    // mem2608-s3 / F-P: the cache can only ever be consulted by queries
    // that survive the block check (handler.rs: evaluate_with_overlay
    // runs before cache.lookup_keyed), and blocked responses are never
    // cached (project rules — instant to generate). A blocked query is
    // therefore a structural non-hit, not an incidental one; counting it
    // in this denominator only ever understated cache effectiveness, and
    // understated it more as the blocklist improved. blocked_pct above is
    // deliberately UNCHANGED — "what fraction of all queries did I
    // block" is correctly a statement about all queries. Only the
    // cache-rate family (this, plus the 24h/delta figures below) excludes
    // blocked queries from the denominator.
    let cacheable = total.saturating_sub(blocked);
    let cache_hit_rate = if cacheable > 0 {
        (cache_hits as f64 / cacheable as f64) * 100.0
    } else {
        0.0
    };

    let top_n = engine.top_n.load();
    // Scope population deferred — see `_docs/features/tui_dashboard_redesign.md`.
    // The filter engine has the information (source_bits + catalog) but
    // exposing a scope resolver + plumbing Arc<FilterEngine> into the
    // stats engine is a follow-up task. Emitting `None` now keeps the
    // wire format stable so the daemon can light up the field without
    // another protocol bump.
    let top_blocked: Vec<super::protocol::DomainCount> = top_n
        .top_blocked
        .iter()
        .map(|(d, c)| super::protocol::DomainCount {
            domain: d.to_string(),
            count: *c,
            count_24h: 0,
            scope: None,
        })
        .collect();
    let top_queried: Vec<super::protocol::DomainCount> = top_n
        .top_queried
        .iter()
        .map(|(d, c)| super::protocol::DomainCount {
            domain: d.to_string(),
            count: *c,
            count_24h: 0,
            scope: None,
        })
        .collect();
    let top_blocked_24h: Vec<super::protocol::DomainCount> = top_n
        .top_blocked_24h
        .iter()
        .map(|(d, lifetime, c24)| super::protocol::DomainCount {
            domain: d.to_string(),
            count: *lifetime,
            count_24h: *c24,
            scope: None,
        })
        .collect();
    let top_queried_24h: Vec<super::protocol::DomainCount> = top_n
        .top_queried_24h
        .iter()
        .map(|(d, lifetime, c24)| super::protocol::DomainCount {
            domain: d.to_string(),
            count: *lifetime,
            count_24h: *c24,
            scope: None,
        })
        .collect();

    let hourly: Vec<super::protocol::TimeBucketDto> = engine
        .time_series
        .hourly_snapshot()
        .into_iter()
        .map(|b| super::protocol::TimeBucketDto {
            timestamp: b.timestamp,
            queries: b.queries,
            blocked: b.blocked,
            cache_hits: b.cache_hits,
        })
        .collect();

    let daily: Vec<super::protocol::TimeBucketDto> = engine
        .time_series
        .daily_snapshot()
        .into_iter()
        .map(|b| super::protocol::TimeBucketDto {
            timestamp: b.timestamp,
            queries: b.queries,
            blocked: b.blocked,
            cache_hits: b.cache_hits,
        })
        .collect();

    let (cache_hit_rate_24h, blocked_pct_24h, cache_hit_rate_delta_1h, blocked_pct_delta_1h) =
        compute_24h_stats(&hourly);

    // Sprint F — per-`TypeBucket` 24h rolling sums computed daemon-side
    // from the internal hourly ring (the wire `TimeBucketDto` stays
    // 4-field; per-type breakdowns never cross the socket). Drives the
    // Dashboard QTYPE chart card.
    let (qtype_distribution_24h, qtype_blocked_distribution_24h) =
        engine.time_series.per_type_24h_snapshot();

    // Sprint §4.4 P1 — surface the prefetch hit-tracker counters.
    // `pool_size` is a live derived value; the cumulative totals come
    // straight from atomic loads. All three are 0 when the tracker is
    // disabled (Phase 1 default).
    let prefetch_pool_size = engine.prefetch_tracker.pool_size().min(u32::MAX as usize) as u32;
    let prefetch_promotions_total = engine.prefetch_tracker.promotions_total();
    let prefetch_demotions_total = engine.prefetch_tracker.demotions_total();

    // Sprint B Dashboard v2 — resolve top-N bits to "scope/topic"
    // labels using the snapshot built at start.rs. The snapshot is
    // length-64 bound; bits in the top-N without a label entry fall
    // back to `list_<bit>` (defensive — never seen in practice).
    let resolve_list_label = |bit: u8| -> String {
        state
            .list_labels
            .get(bit as usize)
            .and_then(|opt| opt.as_ref())
            .cloned()
            .unwrap_or_else(|| format!("list_{bit}"))
    };
    let top_blocked_lists: Vec<super::protocol::ListBlockCount> = top_n
        .top_blocked_lists
        .iter()
        .map(|(bit, count)| super::protocol::ListBlockCount {
            label: resolve_list_label(*bit),
            count: *count,
            count_24h: 0,
        })
        .collect();
    let top_blocked_lists_24h: Vec<super::protocol::ListBlockCount> = top_n
        .top_blocked_lists_24h
        .iter()
        .map(|(bit, lifetime, c24)| super::protocol::ListBlockCount {
            label: resolve_list_label(*bit),
            count: *lifetime,
            count_24h: *c24,
        })
        .collect();

    IpcResponse::TrackingStats {
        queries_total: total,
        blocked_total: blocked,
        blocked_pct,
        cache_hit_rate,
        cache_negative_hits,
        uptime_secs: state.started_at.elapsed().as_secs(),
        top_blocked,
        top_queried,
        hourly,
        daily,
        cache_hit_rate_24h,
        blocked_pct_24h,
        cache_hit_rate_delta_1h,
        blocked_pct_delta_1h,
        qtype_distribution: engine.global.per_type_snapshot(),
        qtype_blocked_distribution: engine.global.blocked_per_type_snapshot(),
        qtype_distribution_24h,
        qtype_blocked_distribution_24h,
        prefetch_pool_size,
        prefetch_promotions_total,
        prefetch_demotions_total,
        top_blocked_lists,
        top_blocked_24h,
        top_queried_24h,
        top_blocked_lists_24h,
    }
}

/// Compute the rolling 24h averages + 1h deltas from the hourly
/// time-series buckets. Returns `(cache_hit_rate_24h, blocked_pct_24h,
/// cache_hit_delta_1h, blocked_pct_delta_1h)` — all in percent
/// (0–100) units matching the cumulative counters.
///
/// The 24h averages are computed as `sum(X) / sum(queries)`, weighting
/// each bucket by its own query volume. The 1h deltas compare the most
/// recent bucket's ratio against the bucket before it. Buckets with
/// zero queries contribute nothing to the average and are treated as
/// `0.0` when computing the delta (no history = no trend to show).
// Stats display path: query counts that exceed `2^53` lose f64 precision,
// but at that point the operator has bigger problems. Ratios are bounded
// to 0..=100 so the rounding stays well within display tolerance.
#[allow(clippy::cast_precision_loss)]
fn compute_24h_stats(hourly: &[super::protocol::TimeBucketDto]) -> (f64, f64, f64, f64) {
    if hourly.is_empty() {
        return (0.0, 0.0, 0.0, 0.0);
    }

    // 24h weighted averages.
    let window: Vec<&super::protocol::TimeBucketDto> = hourly.iter().rev().take(24).collect();
    let sum_q: u64 = window.iter().map(|b| b.queries).sum();
    let sum_b: u64 = window.iter().map(|b| b.blocked).sum();
    let sum_h: u64 = window.iter().map(|b| b.cache_hits).sum();
    // mem2608-s3 / F-P: same correction as handle_tracking_stats above —
    // blocked_24h stays on sum_q (all queries), cache_24h moves to the
    // cacheable population (sum_q - sum_b), matching the live figure's
    // basis so the two never disagree with each other.
    let sum_cacheable = sum_q.saturating_sub(sum_b);
    let (cache_24h, blocked_24h) = (
        if sum_cacheable > 0 {
            (sum_h as f64 / sum_cacheable as f64) * 100.0
        } else {
            0.0
        },
        if sum_q > 0 {
            (sum_b as f64 / sum_q as f64) * 100.0
        } else {
            0.0
        },
    );

    // 1h delta: last bucket's ratio minus previous bucket's ratio.
    let bucket_ratios = |b: &super::protocol::TimeBucketDto| -> (f64, f64) {
        let cacheable = b.queries.saturating_sub(b.blocked);
        let cache = if cacheable == 0 {
            0.0
        } else {
            (b.cache_hits as f64 / cacheable as f64) * 100.0
        };
        let blocked = if b.queries == 0 {
            0.0
        } else {
            (b.blocked as f64 / b.queries as f64) * 100.0
        };
        (cache, blocked)
    };
    let (cache_delta, blocked_delta) = if hourly.len() >= 2 {
        let last = &hourly[hourly.len() - 1];
        let prev = &hourly[hourly.len() - 2];
        let (lc, lb) = bucket_ratios(last);
        let (pc, pb) = bucket_ratios(prev);
        (lc - pc, lb - pb)
    } else {
        (0.0, 0.0)
    };

    (cache_24h, blocked_24h, cache_delta, blocked_delta)
}

#[cfg(test)]
mod window_tests {
    use super::*;
    use crate::ipc::protocol::TimeBucketDto;

    fn bucket(q: u64, b: u64, h: u64) -> TimeBucketDto {
        TimeBucketDto {
            timestamp: 0,
            queries: q,
            blocked: b,
            cache_hits: h,
        }
    }

    #[test]
    fn empty_hourly_returns_zeros() {
        assert_eq!(compute_24h_stats(&[]), (0.0, 0.0, 0.0, 0.0));
    }

    #[test]
    fn twenty_four_hours_weighted_average() {
        // 24 identical buckets — avg equals per-bucket ratio.
        // mem2608-s3 / F-P: cache_24h's denominator is (queries - blocked),
        // not queries. This fixture's 80 hits are ALL of its 80 cacheable
        // queries (100 - 20), so the correct reading is 100%, not the
        // pre-fix 80% (80 hits / 100 all-queries).
        let buckets = vec![bucket(100, 20, 80); 24];
        let (c24, b24, _, _) = compute_24h_stats(&buckets);
        assert!((c24 - 100.0).abs() < 1e-9, "got {c24}");
        assert!((b24 - 20.0).abs() < 1e-9);
    }

    #[test]
    fn one_hour_delta_detects_change() {
        // Two buckets, same 63 cache hits in both: prev has 90 cacheable
        // (100 - 10) → 70%; last has 70 cacheable (100 - 30) → 90%. Delta
        // = +20, unchanged from before F-P — chosen so hit counts stay
        // valid under the new invariant (hits <= cacheable) while
        // reproducing the same intended 70%/90% shape.
        let buckets = vec![bucket(100, 10, 63), bucket(100, 30, 63)];
        let (_, _, cache_delta, blocked_delta) = compute_24h_stats(&buckets);
        assert!((cache_delta - 20.0).abs() < 1e-9, "got {cache_delta}");
        assert!((blocked_delta - 20.0).abs() < 1e-9, "got {blocked_delta}");
    }

    #[test]
    fn zero_query_bucket_does_not_divide_by_zero() {
        // mem2608-s3 / F-P: 60 hits / 75 cacheable (100 - 25) = 80%.
        let buckets = vec![bucket(0, 0, 0), bucket(100, 25, 60)];
        let (c24, b24, _, _) = compute_24h_stats(&buckets);
        assert!((c24 - 80.0).abs() < 1e-9, "got {c24}");
        assert!((b24 - 25.0).abs() < 1e-9);
    }

    #[test]
    fn window_caps_at_24_most_recent_buckets() {
        // 30 buckets — oldest 6 must be ignored. Last 24 sum to 2400 q,
        // so adding a 300-query bucket at position 0 should not shift
        // the average.
        let mut buckets = vec![bucket(300, 300, 0)]; // all blocked, no hits
        buckets.extend(vec![bucket(100, 20, 80); 24]);
        let (c24, b24, _, _) = compute_24h_stats(&buckets);
        // Window is the last 24 → same fixture as
        // twenty_four_hours_weighted_average: 80 hits / 80 cacheable = 100%.
        assert!((c24 - 100.0).abs() < 1e-9, "got {c24}");
        assert!((b24 - 20.0).abs() < 1e-9);
    }
}

fn handle_device_stats(state: &DaemonState) -> IpcResponse {
    use std::sync::atomic::Ordering;

    let Some(engine) = state.stats.as_ref() else {
        return ipc_error(IpcError::TrackingNotEnabled);
    };

    let clients: Vec<super::protocol::DeviceStatEntry> = engine
        .devices
        .iter()
        .map(|entry| {
            let q = entry.value().queries.load(Ordering::Relaxed);
            let b = entry.value().blocked.load(Ordering::Relaxed);
            let pct = if q > 0 {
                (b as f64 / q as f64) * 100.0
            } else {
                0.0
            };
            super::protocol::DeviceStatEntry {
                name: entry.value().name.to_string(),
                ip: entry.key().to_string(),
                queries: q,
                blocked: b,
                blocked_pct: pct,
                cache_hits: entry.value().cache_hits.load(Ordering::Relaxed),
                profile: entry.value().profile.to_string(),
                last_seen: entry.value().last_seen.load(Ordering::Relaxed),
            }
        })
        .collect();

    IpcResponse::DeviceList { clients }
}

async fn handle_get_all_devices(state: &DaemonState) -> IpcResponse {
    use super::protocol::{DeviceViewDto, MappedDeviceDto, UnmappedDeviceDto};
    use std::collections::HashSet;
    use std::net::IpAddr;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(profiles) = state.profiles.as_ref() else {
        // No profile resolver is a configuration/wiring bug, NOT "no
        // clients yet". Surface it as an explicit error so the TUI
        // shows a red banner instead of masking the broken state as
        // "Mapped 0 · Unknown 0".
        return ipc_error(IpcError::NoProfileResolver);
    };

    let now_secs = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(e) => {
            // System clock before UNIX_EPOCH — pathological but not
            // impossible (RTC-less Pi booted before NTP). Log and
            // fall through with 0 so callers see all-offline rather
            // than a silent wrong-answer response.
            tracing::warn!(error = %e, "system clock before UNIX_EPOCH, online counts will be wrong");
            0
        }
    };

    // One call reads all three under consistent ArcSwap guards. Do NOT
    // split this back into separate load calls — it reintroduces the
    // torn-view bug where `block_unmapped` could be from a different
    // generation than the client list (see `snapshot_for_ipc` docs).
    // Refresh the IP→MAC snapshot from `/proc/net/arp` before snapshotting
    // for this IPC call. Without this, any device whose ARP entry landed
    // after the daemon started (or after the last config reload) would
    // show as `(no arp)` in the Unmapped table even though the kernel
    // has the entry. Off the DNS hot path — GetAllDevices is only called
    // from the TUI at ~5s cadence.
    //
    // M-24: `refresh_arp` does a synchronous `/proc/net/arp` parse on
    // the caller's tokio worker. Bounded (<10 ms typical) but the
    // worker pool also services the DNS dispatch path; farm it to
    // the blocking pool so a slow ARP read on a busy LAN cannot
    // briefly steal a DNS worker. `block_on` would deadlock — we
    // `.await` the JoinHandle.
    let arp_refresh = {
        let profiles = Arc::clone(profiles);
        tokio::task::spawn_blocking(move || profiles.refresh_arp()).await
    };
    if let Err(e) = arp_refresh {
        // Panic or cancel inside spawn_blocking. The snapshot below
        // will still serve a (possibly stale) ARP view rather than
        // surface a 500 — same fall-through policy as the
        // SystemTime::UNIX_EPOCH branch above.
        tracing::warn!(error = %e, "ARP refresh task failed; serving previous snapshot");
    }
    let (mapped_snapshots, arp) = profiles.snapshot_for_ipc();

    let observed: Vec<crate::tracking::engine::ObservedDevice> = state
        .stats
        .as_ref()
        .map(|s| s.list_observed_ips())
        .unwrap_or_default();

    // Index observed stats by IP so each mapped device can look up its
    // live counters in O(1). Keeps the join linear in total devices
    // instead of quadratic.
    let stats_by_ip: std::collections::HashMap<IpAddr, &crate::tracking::engine::ObservedDevice> =
        observed.iter().map(|c| (c.ip, c)).collect();

    // Union of ALL configured IPs across all mapped devices — used to
    // filter observed devices into the unmapped list. A single device
    // with both a configured IP and an ARP-learned secondary contributes
    // both addresses to this set.
    let mapped_ips: HashSet<IpAddr> = mapped_snapshots
        .iter()
        .flat_map(|s| s.ips.iter().copied())
        .collect();

    let oui = state.oui_table.as_deref();

    let mapped: Vec<MappedDeviceDto> = mapped_snapshots
        .into_iter()
        .map(|snap| {
            // The snapshot already carries a fully-populated DTO with
            // metadata + primary IP (see `snapshots_from_map`); only
            // the live counters are still zero. Fill them in by
            // summing the stats engine across EVERY IP this device
            // can be reached at — DHCP reassignment moves traffic
            // from old IP to new IP, and the operator wants the
            // total, not a split.
            let mut dto = snap.dto;
            // Hourly buckets sum across every IP this device might
            // present (DHCP reassignment + multi-NIC). Init lazily so
            // a device with a single IP allocates the 24-elem Vec
            // exactly once.
            let mut hourly: Vec<u64> = Vec::new();
            for ip in &snap.ips {
                if let Some(s) = stats_by_ip.get(ip) {
                    dto.queries += s.queries;
                    dto.queries_today += s.queries_today;
                    dto.blocked += s.blocked;
                    dto.blocked_24h += s.blocked_24h;
                    dto.cache_hits += s.cache_hits;
                    dto.last_seen = dto.last_seen.max(s.last_seen);
                    dto.online = dto.online || s.is_online(now_secs);
                    if hourly.is_empty() {
                        hourly = s.hourly_queries.clone();
                    } else if hourly.len() == s.hourly_queries.len() {
                        for (slot, v) in hourly.iter_mut().zip(&s.hourly_queries) {
                            *slot += v;
                        }
                    }
                }
            }
            dto.vendor = lookup_vendor(oui, dto.mac.as_deref());
            dto.hourly_queries = hourly;
            dto
        })
        .collect();

    let unmapped: Vec<UnmappedDeviceDto> = observed
        .iter()
        .filter(|c| !mapped_ips.contains(&c.ip))
        .map(|c| {
            let mac = arp.get(&c.ip).cloned();
            let vendor = lookup_vendor(oui, mac.as_deref());
            UnmappedDeviceDto {
                ip: c.ip.to_string(),
                mac,
                queries: c.queries,
                queries_today: c.queries_today,
                blocked: c.blocked,
                blocked_24h: c.blocked_24h,
                last_seen: c.last_seen,
                online: c.is_online(now_secs),
                vendor,
                hourly_queries: c.hourly_queries.clone(),
            }
        })
        .collect();

    IpcResponse::DeviceView(DeviceViewDto { mapped, unmapped })
}

/// Resolve a MAC's vendor through the daemon's optional OUI table.
/// Returns `None` when the table isn't loaded, the MAC is missing, or
/// the prefix isn't in the registry. Locally-administered MACs (iOS /
/// Android randomization) get the literal `(randomized)` so the TUI
/// can label them distinctly from "lookup failed".
fn lookup_vendor(table: Option<&crate::oui::OuiTable>, mac: Option<&str>) -> Option<String> {
    let mac = mac?;
    if crate::oui::OuiTable::is_randomized(mac) {
        return Some("(randomized)".to_string());
    }
    table?.lookup(mac).map(|s| s.to_string())
}

/// Read the query log and return it over IPC.
///
/// **`s-review-2605-ipc-m2`: the read runs on the blocking pool.** The
/// underlying [`crate::tracking::query_log::read_log_entries_with_state`]
/// tails the primary file and then opens every dated sibling inside the
/// retention window with synchronous `std::fs::File::open` — up to 365
/// files when `retention_days` is set that high, and the sibling walk
/// only short-circuits once `limit` entries have been collected, so a
/// filter that matches little or nothing walks all of them. Running that
/// inline pinned a tokio worker for the whole traversal, and the same
/// worker pool services the DNS dispatch path — a DoS primitive for any
/// caller already holding the admin token.
///
/// Pinned by `query_logs_read_does_not_park_the_runtime_worker`.
///
/// Everything the closure needs is owned (`PathBuf`, `Option<String>`,
/// `Copy` scalars), so unlike the `refresh_arp` precedent above no
/// `Arc::clone` is required.
async fn handle_query_logs(
    state: &DaemonState,
    req: crate::ipc::protocol::QueryLogRequest,
) -> IpcResponse {
    let crate::ipc::protocol::QueryLogRequest {
        limit,
        client,
        blocked_only,
        domain,
        since_secs,
        cursor,
        advanced,
    } = req;
    let Some(engine) = state.stats.as_ref() else {
        return ipc_error(IpcError::TrackingNotEnabled);
    };

    // Prefer the resolved path memoised in the engine (populated by start.rs
    // when the query log is actually attached). When the writer isn't
    // attached (e.g. `query_log_enabled = false` but historical entries
    // still on disk), fall back to the shared resolver that the writer
    // itself uses — never to the raw config string, which would break
    // reads when relative because systemd sets the daemon's cwd to `/`.
    let path_buf: std::path::PathBuf = match engine.query_log_file_path() {
        Some(p) => p,
        None => match state.config_path.as_ref() {
            Some(cp) => crate::tracking::query_log::resolved_query_log_path(
                &engine.config.query_log_path,
                cp,
            ),
            None => engine.config.query_log_path.clone(),
        },
    };
    // Sprint 41: since_secs is a relative duration in seconds; compute
    // an absolute epoch cutoff once here so the reader never re-asks
    // for `now`. Treat a clock reading failure (pre-epoch system clock,
    // not plausible in practice) as "no cutoff" — conservative.
    let cutoff_epoch: Option<i64> = since_secs.and_then(|s| {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        i64::try_from(s).ok().map(|s_i64| now - s_i64)
    });
    // Read everything off `engine` that the response needs BEFORE the
    // await — `state` is a borrow and cannot cross into the closure.
    let retention_days = engine.config.retention_days;
    let logging_enabled = engine.config.query_log_enabled;
    let capped_limit = limit.min(1000); // cap at 1000 entries

    // Lower both needles ONCE per request rather than once per rotated
    // sibling, and hand the walker an owned value — the closure below is
    // `'static`, so a borrowing filter set could not cross into it.
    let mut filters = crate::tracking::query_log::QueryLogFilters::new(
        client.as_deref(),
        blocked_only,
        domain.as_deref(),
        cutoff_epoch,
    );
    // Compile the advanced predicates HERE, once per request — every glob
    // built and every CIDR parsed before the walk starts, so the per-row
    // cost is a match. `compile` is also where an empty form collapses to
    // "no predicate", which keeps a blank advanced filter from costing
    // anything on the read path.
    if let Some(adv) = advanced.filter(|a| !a.is_empty()) {
        filters = filters.with_advanced(adv.compile());
    }

    let read = tokio::task::spawn_blocking(move || {
        crate::tracking::query_log::read_log_page(
            &path_buf,
            capped_limit,
            &filters,
            retention_days,
            cursor.as_ref(),
        )
    })
    .await;

    let (entries, file_state, next_cursor, cursor_stale) = match read {
        Ok(p) => (p.entries, p.file_state, p.next_cursor, p.cursor_stale),
        Err(e) => {
            // Panic or cancellation inside the blocking closure. There
            // is no partial result to serve, so report the same
            // `Unreadable` state the reader itself returns for an I/O
            // failure — the TUI's empty-state renderer already handles
            // it, and no new error variant is needed. No cursor either:
            // handing back a resume point for a page that was never read
            // would let the caller page past rows it has not seen.
            tracing::warn!(error = %e, "query-log read task failed");
            (
                Vec::new(),
                crate::ipc::protocol::QueryLogFileState::Unreadable,
                None,
                false,
            )
        }
    };

    let dto_entries: Vec<super::protocol::QueryLogDto> = entries
        .into_iter()
        .map(|e| super::protocol::QueryLogDto {
            timestamp: e.timestamp,
            client_ip: e.client_ip.to_string(),
            client_name: e.client_name,
            domain: e.domain,
            query_type: e.query_type,
            result: e.result,
            response_time_us: e.response_time_us,
            cname_chain_via: e.cname_chain_via,
        })
        .collect();

    IpcResponse::QueryLogs {
        entries: dto_entries,
        logging_enabled,
        file_state,
        next_cursor,
        cursor_stale,
    }
}

/// Add a configured client. Server-side counterpart of the CLI
/// `warden device add` and the TUI device form modal.
///
/// Loads via the v1 loader so duplicate-detection sees the merged
/// master+includes view, writes the new entity into
/// `devices.d/<id>.toml` (or falls through to the master when no class
/// directory exists), then `validate_or_revert` runs the full v1
/// validator on the staged file. Held under `config_write_lock` so two
/// concurrent IPC device mutations cannot race the read-modify-write
/// cycle. Preserves includes / per-entity files the operator already
/// organised by hand.
async fn handle_device_add(
    state: &DaemonState,
    client: crate::config::settings::ClientConfig,
    peer_uid: Option<u32>,
) -> IpcResponse {
    let Some(config_path) = state.config_path.as_ref() else {
        return ipc_error(IpcError::NoConfigPath);
    };

    // Serialize against other in-flight mutations. Held across the
    // whole load→write→validate→reload cycle so a racing reload from
    // SIGHUP can't observe a half-mutated state either.
    let _guard = state.config_write_lock.lock().await;

    // Slug the operator-typed name into a v1 id. Display name keeps
    // the original (free-form) string so the TUI rendering doesn't
    // lose case / accents / spaces.
    let new_name = client.name.clone();
    let new_id = match crate::cli::commands::target::slug_id(&new_name) {
        Ok(id) => id,
        Err(msg) => {
            tracing::warn!(
                target: "ipc.error",
                name = %new_name,
                error = %msg,
                "device_add v1: slug_id rejected operator-typed name",
            );
            return ipc_error(IpcError::InvalidArgument);
        }
    };

    // Load via the v1 loader so duplicate-detection sees the merged
    // master+includes view (a device defined in `devices.d/foo.toml`
    // would otherwise be invisible to a single-file parse).
    let now = time::OffsetDateTime::now_utc();
    let loaded = match crate::config::loader::load_config(config_path, now) {
        Ok(l) => l,
        Err(errs) => {
            tracing::warn!(
                target: "ipc.error",
                path = %config_path.display(),
                errors = errs.len(),
                "device_add v1: load_config failed",
            );
            return ipc_error(IpcError::ConfigReadFailed);
        }
    };

    // Friendlier than letting the validator surface "duplicate id" /
    // "duplicate ip" — operators typing in the TUI benefit from naming
    // the conflicting field before they see the full validator dump.
    if loaded
        .config
        .devices
        .iter()
        .any(|d| d.id.as_str() == new_id)
    {
        return ipc_error(IpcError::DuplicateDeviceName {
            name: new_name.clone(),
        });
    }
    let new_ip = client.ip;
    if loaded.config.devices.iter().any(|d| d.ip == Some(new_ip)) {
        return ipc_error(IpcError::DuplicateDeviceIp {
            ip: new_ip.to_string(),
        });
    }
    if !client.profile.is_empty() && !loaded.config.profiles.contains_key(&client.profile) {
        return ipc_error(IpcError::ProfileNotFound {
            id: client.profile.to_string(),
        });
    }

    // Pick the target file: a per-id slice under `devices.d/` when the
    // class directory exists (v1 layout), else fall through to the master
    // (legacy single-file or pre-S34 v0 layout). We deliberately do NOT
    // reuse the CLI's `resolve_target_file` here — that one errors when
    // multiple `devices.d/*.toml` already exist, and IPC has no
    // `--into` knob to disambiguate. Per-id files are also easier to
    // diff in a git workflow than a monolithic `auto-migrated.toml`.
    let parent = config_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let class_dir = parent.join("devices.d"); // include-dir-ok: creation default
    let target_path = if class_dir.is_dir() {
        class_dir.join(format!("{new_id}.toml"))
    } else {
        config_path.clone()
    };

    let (mut doc, _) = match crate::cli::commands::target::read_or_empty(&target_path) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(
                target: "ipc.error",
                path = %target_path.display(),
                error = %e,
                "device_add v1: target read_or_empty failed",
            );
            return ipc_error(IpcError::TargetReadFailed);
        }
    };
    let entry = crate::cli::commands::target::client_to_v1_value(&client, &new_id);
    if let Err(e) = crate::cli::commands::target::upsert_id_keyed(
        &mut doc,
        crate::cli::commands::target::EntityClass::Devices.toml_key(),
        &new_id,
        entry,
    ) {
        tracing::warn!(
            target: "ipc.error",
            path = %target_path.display(),
            error = %e,
            "device_add v1: upsert_id_keyed failed",
        );
        return ipc_error(IpcError::StageFailed);
    }
    // Pre-promote validation (rev2606 target-01): validate the staged slice
    // against the merged tree BEFORE the rename; nothing is written on
    // failure. Merges the former write-then-validate-revert two-step — a
    // genuine write I/O error and a cross-ref rejection both surface here.
    if let Err(e) =
        crate::cli::commands::target::write_value_validated(config_path, &target_path, &doc)
    {
        tracing::warn!(
            target: "ipc.error",
            path = %target_path.display(),
            error = %e,
            "device_add v1: staged device rejected before write",
        );
        return ipc_error(IpcError::ValidationFailed);
    }

    tracing::info!(
        target: "audit",
        action = "client.add",
        uid = ?peer_uid,
        id = %new_id,
        name = %new_name,
        ip = %new_ip,
        target = %target_path.display(),
        "IPC mutation"
    );

    // Best-effort reload via `try_send`. The reload channel has
    // capacity 1, so when a reload is already pending the new signal
    // is dropped — and that is the correct outcome: the next reload
    // pass will see our just-written change because the file is
    // already on disk before this point. Using `send().await` here
    // would deadlock under concurrent mutations because we hold the
    // write lock across the await, and the channel may be full while
    // the receiver is itself blocked on the lock during a SIGHUP. The
    // only failure we DO surface is a closed channel — that means the
    // daemon is shutting down and the operator should restart it to
    // observe the change.
    let reload_pending = if let Some(tx) = &state.reload_tx {
        match tx.try_send(peer_uid) {
            Ok(()) => false,
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => true,
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                tracing::warn!(
                    target: "ipc.error",
                    path = %config_path.display(),
                    "device_add v1: reload channel closed after write",
                );
                return ipc_error(IpcError::ConfigSavedReloadClosed);
            }
        }
    } else {
        false
    };

    let base = format!("added client \"{new_name}\" ({new_ip})");
    let message = if reload_pending {
        format!("{base}{}", crate::ipc::protocol::RELOAD_PENDING_SUFFIX)
    } else {
        base
    };
    IpcResponse::Ok { message }
}

/// Apply a partial update to an existing client by name. Same write
/// lock + read-modify-validate-write-reload shape as `handle_device_add`.
///
/// Patch semantics: each field of `DevicePatch` uses an extra `Option`
/// for nullable types so the wire can distinguish "field omitted —
/// leave alone" from "field cleared". Outer `None` skips the
/// assignment entirely; outer `Some(v)` assigns `v` (which may itself
/// be `None` to clear a nullable field). The new state is then
/// validated as a whole, so renaming to an existing name or moving to
/// an existing IP gets caught by the validator's duplicate checks.
async fn handle_device_update(
    state: &DaemonState,
    name: String,
    patch: super::protocol::DevicePatch,
    peer_uid: Option<u32>,
) -> IpcResponse {
    let Some(config_path) = state.config_path.as_ref() else {
        return ipc_error(IpcError::NoConfigPath);
    };

    let _guard = state.config_write_lock.lock().await;

    // Map the operator-typed device name back to its v1 id. The TUI
    // round-trips the original name (whatever the operator typed) so
    // the slug we apply here must match the slug used at add-time.
    let current_id = match crate::cli::commands::target::slug_id(&name) {
        Ok(id) => id,
        Err(msg) => {
            tracing::warn!(
                target: "ipc.error",
                name = %name,
                error = %msg,
                "device_update v1: slug_id rejected operator-typed name",
            );
            return ipc_error(IpcError::InvalidArgument);
        }
    };

    let target_path = match crate::cli::commands::target::find_target_for_id(
        config_path,
        crate::cli::commands::target::EntityClass::Devices,
        &current_id,
    ) {
        Ok(Some(p)) => p,
        Ok(None) => {
            return ipc_error(IpcError::DeviceNotFound { name: name.clone() });
        }
        Err(e) => {
            tracing::warn!(
                target: "ipc.error",
                path = %config_path.display(),
                error = %e,
                "device_update v1: find_target_for_id failed",
            );
            return ipc_error(IpcError::TargetScanFailed);
        }
    };

    let (mut doc, _) = match crate::cli::commands::target::read_or_empty(&target_path) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(
                target: "ipc.error",
                path = %target_path.display(),
                error = %e,
                "device_update v1: target read_or_empty failed",
            );
            return ipc_error(IpcError::TargetReadFailed);
        }
    };

    // Locate the entry inside the resolved file and mutate it in
    // place. We deliberately work on the toml::Value directly (not on
    // the parsed `Device` struct) so unknown / future fields the
    // schema hasn't taught us about survive the round-trip
    // unmodified.
    let entry_arr = doc
        .as_table_mut()
        .and_then(|t| t.get_mut("devices"))
        .and_then(|v| v.as_array_mut());
    let Some(arr) = entry_arr else {
        tracing::warn!(
            target: "ipc.error",
            path = %target_path.display(),
            id = %current_id,
            "device_update v1: target has no [[devices]] (concurrent edit?)",
        );
        return ipc_error(IpcError::ConcurrentEdit);
    };
    let Some(entry) = arr
        .iter_mut()
        .find(|item| item.get("id").and_then(|v| v.as_str()) == Some(current_id.as_str()))
    else {
        tracing::warn!(
            target: "ipc.error",
            path = %target_path.display(),
            id = %current_id,
            "device_update v1: target missing expected id (concurrent edit?)",
        );
        return ipc_error(IpcError::ConcurrentEdit);
    };
    let Some(table) = entry.as_table_mut() else {
        tracing::warn!(
            target: "ipc.error",
            path = %target_path.display(),
            id = %current_id,
            "device_update v1: entry is not a TOML table",
        );
        return ipc_error(IpcError::ConcurrentEdit);
    };

    // Renames change the human-readable display_name only. Changing
    // the v1 `id` requires explicit retired-ids handling (cross-refs
    // from groups / schedules / rules) — the IPC patch path keeps it
    // simple and refuses an id change here. The TUI / CLI can guide
    // the operator to a dedicated rename flow when it lands.
    if let Some(new_name) = patch.new_name.as_deref() {
        table.insert(
            "display_name".into(),
            toml::Value::String(new_name.to_string()),
        );
    }
    if let Some(ip) = patch.ip {
        table.insert("ip".into(), toml::Value::String(ip.to_string()));
    }
    if let Some(profile) = patch.profile.as_deref() {
        table.insert("profile".into(), toml::Value::String(profile.to_string()));
    }
    match patch.mac.clone() {
        Some(Some(m)) if !m.is_empty() => {
            table.insert("mac".into(), toml::Value::String(m));
        }
        Some(_) => {
            table.remove("mac");
        }
        None => {}
    }
    match patch.network_name.clone() {
        Some(Some(n)) if !n.is_empty() => {
            table.insert("network_name".into(), toml::Value::String(n));
        }
        Some(_) => {
            table.remove("network_name");
        }
        None => {}
    }
    if let Some(wildcard) = patch.network_name_wildcard {
        table.insert(
            "network_name_wildcard".into(),
            toml::Value::Boolean(wildcard),
        );
    }
    if let Some(aliases) = patch.mac_aliases.clone() {
        if aliases.is_empty() {
            table.remove("mac_aliases");
        } else {
            table.insert(
                "mac_aliases".into(),
                toml::Value::Array(aliases.into_iter().map(toml::Value::String).collect()),
            );
        }
    }
    match patch.owner.clone() {
        Some(Some(v)) if !v.is_empty() => {
            table.insert("owner".into(), toml::Value::String(v));
        }
        Some(_) => {
            table.remove("owner");
        }
        None => {}
    }
    match patch.device_type.clone() {
        Some(Some(v)) if !v.is_empty() => {
            table.insert("device_type".into(), toml::Value::String(v));
        }
        Some(_) => {
            table.remove("device_type");
        }
        None => {}
    }
    match patch.department.clone() {
        Some(Some(v)) if !v.is_empty() => {
            table.insert("department".into(), toml::Value::String(v));
        }
        Some(_) => {
            table.remove("department");
        }
        None => {}
    }
    // `tags` is retired. It is captured (never applied) purely so that a
    // pre-S5 client sending it is TOLD, instead of having its intent
    // dropped in silence — the failure mode the tag model itself died of.
    // The rest of the patch still lands, matching the `ip_denylists`
    // strip-and-report precedent in `normalise_deprecated_keys`.
    if super::protocol::retired_tags_worth_reporting(patch.retired_tags.as_ref()) {
        let tags = patch
            .retired_tags
            .as_ref()
            .expect("non-empty implies present");
        tracing::warn!(
            target: "audit",
            device = %name,
            tags = ?tags,
            "TAGS_RETIRED — this request carries a `tags` key, which no longer \
             exists in the product. It has been IGNORED; every other field in \
             the request was applied. The sender is almost certainly an older \
             `warden` binary still on PATH after an upgrade — check that \
             `warden --version` matches the running daemon.",
        );
    }
    if let Some(groups) = patch.groups.clone() {
        if groups.is_empty() {
            table.remove("groups");
        } else {
            table.insert(
                "groups".into(),
                toml::Value::Array(groups.into_iter().map(toml::Value::String).collect()),
            );
        }
    }
    match patch.notes.clone() {
        Some(Some(v)) if !v.is_empty() => {
            table.insert("notes".into(), toml::Value::String(v));
        }
        Some(_) => {
            table.remove("notes");
        }
        None => {}
    }

    let final_name = patch.new_name.clone().unwrap_or_else(|| name.clone());

    if let Err(e) =
        crate::cli::commands::target::write_value_validated(config_path, &target_path, &doc)
    {
        tracing::warn!(
            target: "ipc.error",
            path = %target_path.display(),
            error = %e,
            "device_update v1: staged patch rejected before write",
        );
        return ipc_error(IpcError::ValidationFailed);
    }

    tracing::info!(
        target: "audit",
        action = "client.update",
        uid = ?peer_uid,
        id = %current_id,
        from = %name,
        to = %final_name,
        target = %target_path.display(),
        "IPC mutation"
    );

    let reload_pending = if let Some(tx) = &state.reload_tx {
        match tx.try_send(peer_uid) {
            Ok(()) => false,
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => true,
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                tracing::warn!(
                    target: "ipc.error",
                    path = %config_path.display(),
                    "device_update v1: reload channel closed after write",
                );
                return ipc_error(IpcError::ConfigSavedReloadClosed);
            }
        }
    } else {
        false
    };

    let renamed_msg = if name != final_name {
        format!(" (renamed from \"{name}\")")
    } else {
        String::new()
    };
    let base = format!("updated client \"{final_name}\"{renamed_msg}");
    let message = if reload_pending {
        format!("{base}{}", crate::ipc::protocol::RELOAD_PENDING_SUFFIX)
    } else {
        base
    };
    IpcResponse::Ok { message }
}

/// Remove a configured client by name. Same write lock + read-validate
/// -write-reload shape as the other client mutations, with one twist:
/// the validator is still run AFTER the removal because removing a
/// client may leave a `[[schedules]]` entry pointing at a now-missing
/// client name. The validator catches that and the operator gets a
/// clear "schedule references missing client X" error before the file
/// is rewritten — friendlier than letting the next reload land a
/// partially-broken config.
async fn handle_device_remove(
    state: &DaemonState,
    name: String,
    peer_uid: Option<u32>,
) -> IpcResponse {
    let Some(config_path) = state.config_path.as_ref() else {
        return ipc_error(IpcError::NoConfigPath);
    };

    let _guard = state.config_write_lock.lock().await;

    let target_id = match crate::cli::commands::target::slug_id(&name) {
        Ok(id) => id,
        Err(msg) => {
            tracing::warn!(
                target: "ipc.error",
                name = %name,
                error = %msg,
                "device_remove v1: slug_id rejected operator-typed name",
            );
            return ipc_error(IpcError::InvalidArgument);
        }
    };

    let target_path = match crate::cli::commands::target::find_target_for_id(
        config_path,
        crate::cli::commands::target::EntityClass::Devices,
        &target_id,
    ) {
        Ok(Some(p)) => p,
        Ok(None) => {
            return ipc_error(IpcError::DeviceNotFound { name: name.clone() });
        }
        Err(e) => {
            tracing::warn!(
                target: "ipc.error",
                path = %config_path.display(),
                error = %e,
                "device_remove v1: find_target_for_id failed",
            );
            return ipc_error(IpcError::TargetScanFailed);
        }
    };

    let (mut doc, _) = match crate::cli::commands::target::read_or_empty(&target_path) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(
                target: "ipc.error",
                path = %target_path.display(),
                error = %e,
                "device_remove v1: target read_or_empty failed",
            );
            return ipc_error(IpcError::TargetReadFailed);
        }
    };

    let removed = match crate::cli::commands::target::remove_id_keyed(
        &mut doc,
        crate::cli::commands::target::EntityClass::Devices.toml_key(),
        &target_id,
    ) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(
                target: "ipc.error",
                path = %target_path.display(),
                error = %e,
                "device_remove v1: remove_id_keyed failed",
            );
            return ipc_error(IpcError::StageFailed);
        }
    };
    if !removed {
        tracing::warn!(
            target: "ipc.error",
            path = %target_path.display(),
            id = %target_id,
            "device_remove v1: target missing expected id (concurrent edit?)",
        );
        return ipc_error(IpcError::ConcurrentEdit);
    }

    if let Err(e) =
        crate::cli::commands::target::write_value_validated(config_path, &target_path, &doc)
    {
        tracing::warn!(
            target: "ipc.error",
            path = %target_path.display(),
            error = %e,
            "device_remove v1: staged removal rejected before write (likely dangling refs)",
        );
        return ipc_error(IpcError::ValidatorRejected);
    }

    tracing::info!(
        target: "audit",
        action = "client.remove",
        uid = ?peer_uid,
        id = %target_id,
        name = %name,
        target = %target_path.display(),
        "IPC mutation"
    );

    let reload_pending = if let Some(tx) = &state.reload_tx {
        match tx.try_send(peer_uid) {
            Ok(()) => false,
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => true,
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                tracing::warn!(
                    target: "ipc.error",
                    path = %config_path.display(),
                    "device_remove v1: reload channel closed after write",
                );
                return ipc_error(IpcError::ConfigSavedReloadClosed);
            }
        }
    } else {
        false
    };

    let base = format!("removed client \"{name}\"");
    let message = if reload_pending {
        format!("{base}{}", crate::ipc::protocol::RELOAD_PENDING_SUFFIX)
    } else {
        base
    };
    IpcResponse::Ok { message }
}

/// Promote an observed-but-unmapped IP into a configured client.
/// Strict: requires a MAC in the live ARP snapshot for the given IP.
///
/// **Why the MAC is non-negotiable**: per project rules "MAC + IP for
/// client identification — IP-only is bypassable in 30 seconds." A
/// DHCP collision could re-bind the IP to a different physical
/// device after promotion, silently moving the wrong device into
/// the configured client's profile slot. The pin makes the binding
/// survive DHCP reassignment.
///
/// **The ARP snapshot comes from `snapshot_for_ipc`**, not a fresh
/// `/proc/net/arp` read, so the lookup is consistent with the
/// `block_unmapped` flag and mapped-client state the operator just
/// observed in the TUI. If a SIGHUP races the call, the read sees
/// the same generation as the rest of the IPC view, not a torn one.
///
/// On success, builds a `ClientConfig` with the resolved MAC and
/// runs the same write-lock + validate + reload pipeline as
/// `DeviceAdd` (delegated, not duplicated).
#[allow(clippy::too_many_arguments)]
async fn handle_device_promote(
    state: &DaemonState,
    ip: std::net::IpAddr,
    name: String,
    profile: String,
    owner: Option<String>,
    device_type: Option<String>,
    department: Option<String>,
    peer_uid: Option<u32>,
) -> IpcResponse {
    let Some(profiles) = state.profiles.as_ref() else {
        return ipc_error(IpcError::NoProfilesResolverPromote);
    };

    // Pull the ARP snapshot from the same consistent view the TUI
    // saw — see `snapshot_for_ipc` docs for the generation guarantee.
    //
    // We don't refresh ARP here (GetAllDevices already did within the
    // last ~5s poll), and refreshing would clobber the snapshot the
    // unit tests set via `test_only_set_arp_snapshot`. In production
    // the TUI promote form is reached by picking a visible unmapped
    // row, so the MAC the handler needs is guaranteed to be in the
    // last GetAllDevices snapshot.
    let (_mapped, arp) = profiles.snapshot_for_ipc();

    let mac = match arp.get(&ip) {
        Some(m) if !m.is_empty() => m.clone(),
        _ => {
            return ipc_error(IpcError::NoArpMacForPromote { ip: ip.to_string() });
        }
    };

    // §4.32 m1: emit a dedicated audit line for the promote action
    // BEFORE delegating to handle_device_add. Without this, the audit
    // log only carries the inner `client.add` emit, losing the
    // promote-specific context (which IP was promoted, which MAC the
    // ARP table actually returned).
    tracing::info!(
        target: "audit",
        action = "device.promote.v1",
        uid = ?peer_uid,
        ip = %ip,
        mac = %mac,
        name = %name,
        profile = %profile,
        "IPC mutation"
    );

    let client = crate::config::settings::ClientConfig {
        name,
        ip,
        mac: Some(mac),
        // Promote attaches the ARP-resolved MAC as the primary and
        // starts with no aliases. Aliases are added later via Edit
        // when the operator notices the device's MAC has rotated.
        mac_aliases: Vec::new(),
        profile,
        // Promote starts with no group membership; the operator can
        // assign one later via Edit. Forcing a group at promote time
        // would require a picker UI, and most freshly-promoted hosts
        // get their policy from `[server].default_profile` until the
        // operator categorises them.
        group: None,
        owner,
        device_type,
        department,
        notes: None,
    };

    // Delegate to the add path so we get the same write lock,
    // validator, dupe checks, and reload semantics — one canonical
    // path for "client landed in settings", not two.
    handle_device_add(state, client, peer_uid).await
}

/// Sprint 38 QLP5: apply a [`TrackingPatch`](crate::ipc::protocol::TrackingPatch) to the `[tracking]`
/// section of the v1 master. Partial semantics — only fields present
/// on the patch are updated, everything else survives the
/// read-modify-write cycle untouched.
///
/// Shape matches the entity editors: write-lock, per-file `toml::Value`
/// surgery on the master's `[tracking]` table, promote through the
/// overlay-validating `write_value_validated` (layout-preserving — see
/// writer-01), trigger reload through the shared `reload_tx` channel so
/// `apply_query_log_reload` in `start.rs` sees the flip and attaches /
/// detaches the writer accordingly.
async fn handle_tracking_config_update(
    state: &DaemonState,
    patch: crate::ipc::protocol::TrackingPatch,
    peer_uid: Option<u32>,
) -> IpcResponse {
    let Some(config_path) = state.config_path.as_ref() else {
        return ipc_error(IpcError::NoConfigPath);
    };
    let _guard = state.config_write_lock.lock().await;

    // Pre-flight: fail fast on out-of-range values with the frozen
    // operator strings. The v1 loader's validator would also catch
    // these on staged load, but surfacing early keeps the error path
    // clean (no disk rename dance). These read the patch only — no
    // merged tree needed.
    if let Some(rd) = patch.retention_days {
        if !(1..=365).contains(&rd) {
            return ipc_error(IpcError::RetentionDaysOutOfRange);
        }
    }
    if let Some(crate::config::settings::LogMode::Sampled { allowed_rate }) = &patch.log_mode {
        if !(0.0..=1.0).contains(allowed_rate) || !allowed_rate.is_finite() {
            return ipc_error(IpcError::LogModeRateOutOfRange);
        }
    }

    // writer-01 (rev-2606 §05): mutate the master's own `[tracking]`
    // table in place via `toml::Value` surgery, then promote through the
    // overlay-validating writer. The previous `write_config_v1(config,
    // &merged)` re-serialised the WHOLE merged `ConfigV1` (every `.d/`
    // entity + the `includes` array) onto the master — flattening a
    // multi-file layout (or, with non-empty includes, getting refused as
    // duplicate singletons by staged validation). `[tracking]` is a
    // master-only pass-through section (same as `[lists]` in
    // `api::handlers::edit_master_lists_sources`), so editing only the
    // master's table and writing only the master preserves the include
    // layout. `write_value_validated` still overlay-validates {master' +
    // every include} BEFORE the rename, so a bad result is refused with
    // nothing written — the B2c pre-promote guarantee is intact.
    let (mut doc, _) = match crate::cli::commands::target::read_or_empty(config_path) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(
                target: "ipc.error",
                path = %config_path.display(),
                error = %e,
                "tracking_config_update: read master failed",
            );
            return ipc_error(IpcError::ConfigReadFailed);
        }
    };
    {
        let Some(table) = doc.as_table_mut() else {
            tracing::warn!(
                target: "ipc.error",
                path = %config_path.display(),
                "tracking_config_update: config root is not a TOML table",
            );
            return ipc_error(IpcError::ConfigWriteFailed);
        };
        let tracking = table
            .entry("tracking".to_string())
            .or_insert_with(|| toml::Value::Table(Default::default()));
        let Some(tracking_tbl) = tracking.as_table_mut() else {
            tracing::warn!(
                target: "ipc.error",
                path = %config_path.display(),
                "tracking_config_update: [tracking] is not a table",
            );
            return ipc_error(IpcError::ConfigWriteFailed);
        };
        // Partial semantics: only patch-present fields are touched;
        // every other key in the operator's `[tracking]` table survives.
        if let Some(flag) = patch.query_log_enabled {
            tracking_tbl.insert("query_log_enabled".to_string(), toml::Value::Boolean(flag));
        }
        if let Some(rd) = patch.retention_days {
            tracking_tbl.insert(
                "retention_days".to_string(),
                toml::Value::Integer(i64::from(rd)),
            );
        }
        if let Some(mode) = patch.log_mode.clone() {
            match toml::Value::try_from(&mode) {
                Ok(v) => {
                    tracking_tbl.insert("log_mode".to_string(), v);
                }
                Err(e) => {
                    tracing::warn!(
                        target: "ipc.error",
                        path = %config_path.display(),
                        error = %e,
                        "tracking_config_update: serialise log_mode failed",
                    );
                    return ipc_error(IpcError::ConfigWriteFailed);
                }
            }
        }
    }

    if let Err(e) =
        crate::cli::commands::target::write_value_validated(config_path, config_path, &doc)
    {
        tracing::warn!(
            target: "ipc.error",
            path = %config_path.display(),
            error = %e,
            "tracking_config_update: write_value_validated failed",
        );
        return ipc_error(IpcError::ConfigWriteFailed);
    }

    tracing::info!(
        target: "audit",
        action = "tracking.update",
        uid = ?peer_uid,
        query_log_enabled = ?patch.query_log_enabled,
        retention_days = ?patch.retention_days,
        log_mode = ?patch.log_mode.as_ref().map(|m| format!("{m:?}")),
        "IPC mutation"
    );

    let reload_pending = if let Some(tx) = &state.reload_tx {
        match tx.try_send(peer_uid) {
            Ok(()) => false,
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => true,
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                tracing::warn!(
                    target: "ipc.error",
                    path = %config_path.display(),
                    "tracking_config_update: reload channel closed after write",
                );
                return ipc_error(IpcError::ConfigSavedReloadClosed);
            }
        }
    } else {
        false
    };

    let message = if reload_pending {
        format!(
            "tracking config updated{}",
            crate::ipc::protocol::RELOAD_PENDING_SUFFIX
        )
    } else {
        "tracking config updated".into()
    };
    IpcResponse::Ok { message }
}

// ── §4.26 Phase 1: profile mutation handlers ──────────────────────

async fn handle_profile_create(
    state: &DaemonState,
    id: String,
    display_name: String,
    peer_uid: Option<u32>,
) -> IpcResponse {
    let Some(config_path) = state.config_path.as_ref() else {
        return ipc_error(IpcError::NoConfigPath);
    };

    let _guard = state.config_write_lock.lock().await;

    if let Err(e) = crate::config::schema::Id::new(&id) {
        tracing::warn!(
            target: "ipc.error",
            id = %id,
            error = %e,
            "profile_create: validator rejected id",
        );
        return ipc_error(IpcError::InvalidProfileId { id: id.clone() });
    }

    if let Ok(Some(existing_path)) = crate::cli::commands::target::find_target_for_id(
        config_path,
        crate::cli::commands::target::EntityClass::Profiles,
        &id,
    ) {
        tracing::warn!(
            target: "ipc.error",
            id = %id,
            existing = %existing_path.display(),
            "profile_create: id already exists",
        );
        return ipc_error(IpcError::DuplicateProfileId { id: id.clone() });
    }

    let (mut doc, _) = match crate::cli::commands::target::read_or_empty(config_path) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(
                target: "ipc.error",
                path = %config_path.display(),
                error = %e,
                "profile_create: read_or_empty failed",
            );
            return ipc_error(IpcError::ConfigReadFailed);
        }
    };

    let mut entry = toml::value::Table::new();
    entry.insert(
        "display_name".into(),
        toml::Value::String(display_name.clone()),
    );

    if let Err(e) =
        crate::cli::commands::target::upsert_profile(&mut doc, &id, toml::Value::Table(entry))
    {
        tracing::warn!(
            target: "ipc.error",
            id = %id,
            error = %e,
            "profile_create: upsert_profile failed",
        );
        return ipc_error(IpcError::StageFailed);
    }

    if let Err(e) =
        crate::cli::commands::target::write_value_validated(config_path, config_path, &doc)
    {
        tracing::warn!(
            target: "ipc.error",
            id = %id,
            error = %e,
            "profile_create: staged profile rejected before write",
        );
        return ipc_error(IpcError::ValidatorRejected);
    }

    tracing::info!(
        target: "audit",
        action = "profile.create.v1",
        uid = ?peer_uid,
        id = %id,
        display_name = %display_name,
        "IPC mutation"
    );

    let reload_pending = notify_reload(state, peer_uid, &format!("profile create \"{id}\""));

    let base = format!("created profile \"{id}\"");
    let message = if reload_pending {
        format!("{base}{}", crate::ipc::protocol::RELOAD_PENDING_SUFFIX)
    } else {
        base
    };
    IpcResponse::Ok { message }
}

/// The `[[blocklists]]` row `list_id` occupies **on disk**, as its own
/// file declares it.
///
/// `Ok(None)` means no configured file carries a `[[blocklists]]` entry
/// with that id; `Err` means a file that should have carried it could not
/// be read or parsed, which a caller must not quietly turn into "absent".
///
/// **Why this deserialises the whole [`Blocklist`](crate::config::schema::Blocklist) instead of reading the
/// two keys it wants.** `trust` is `#[serde(default)]` and its `Default`
/// is [`BlocklistTrust::RemoteUnsigned`](crate::config::schema::BlocklistTrust::RemoteUnsigned), not `Local` — a row that omits
/// the key is a *remote unsigned* list. Hand-rolling
/// `row.get("trust").and_then(as_str)` would have to re-declare that
/// default at this call site, and the failure mode of getting it wrong is
/// the one that does not make noise: a missing `trust` read as `Local`
/// makes `allow_direction_gates` return `needs_consent = false` and the
/// override sails through. Serde owns the defaults; this asks serde.
///
/// The loaded config is deliberately not consulted, and not only because
/// [`DaemonState`] holds no handle to it: `find_target_for_id` answers
/// about the bytes the next write will sit next to, which is the state
/// this decision is actually about. For `trust` and
/// `accept_unsigned_allow` the loaded view would agree — neither is
/// synthesised by the loader.
///
/// It used to carry the raw `toml::Table` too, because `tags` was exactly
/// the field `auto_promote_blocklists` invented and the tag gates had to
/// read the file rather than the loaded view. `plp-s5a` removed the field
/// and both gates, so the raw row has no reader left.
struct BlocklistRowOnDisk {
    trust: crate::config::schema::blocklist::BlocklistTrust,
    accept_unsigned_allow: bool,
}

fn blocklist_row_on_disk(
    config_path: &Path,
    list_id: &str,
) -> anyhow::Result<Option<BlocklistRowOnDisk>> {
    use crate::cli::commands::target::{find_target_for_id, read_or_empty, EntityClass};

    let Some(target) = find_target_for_id(config_path, EntityClass::Blocklists, list_id)? else {
        return Ok(None);
    };
    let (doc, _) = read_or_empty(&target)?;
    let Some(array) = doc
        .as_table()
        .and_then(|t| t.get(EntityClass::Blocklists.toml_key()))
        .and_then(|v| v.as_array())
    else {
        return Ok(None);
    };
    let Some(raw) = array
        .iter()
        .find(|item| item.get("id").and_then(|v| v.as_str()) == Some(list_id))
        .and_then(|item| item.as_table())
        .cloned()
    else {
        return Ok(None);
    };
    // A row that does not deserialise is a config that does not load, so
    // this is an error and not an absence: answering `Ok(None)` would
    // report a broken row as a typo in the profile patch, and answering
    // "no consent needed" would be worse.
    let typed: crate::config::schema::blocklist::Blocklist =
        toml::Value::Table(raw.clone()).try_into()?;
    Ok(Some(BlocklistRowOnDisk {
        trust: typed.trust,
        accept_unsigned_allow: typed.accept_unsigned_allow,
    }))
}

async fn handle_profile_update(
    state: &DaemonState,
    id: String,
    patch: super::protocol::ProfileUpdatePatch,
    peer_uid: Option<u32>,
) -> IpcResponse {
    let Some(config_path) = state.config_path.as_ref() else {
        return ipc_error(IpcError::NoConfigPath);
    };

    let _guard = state.config_write_lock.lock().await;

    let target_path = match crate::cli::commands::target::find_target_for_id(
        config_path,
        crate::cli::commands::target::EntityClass::Profiles,
        &id,
    ) {
        Ok(Some(p)) => p,
        Ok(None) => {
            return ipc_error(IpcError::ProfileNotFound { id: id.clone() });
        }
        Err(e) => {
            tracing::warn!(
                target: "ipc.error",
                path = %config_path.display(),
                error = %e,
                "profile_update: find_target_for_id failed",
            );
            return ipc_error(IpcError::TargetScanFailed);
        }
    };

    let (mut doc, _) = match crate::cli::commands::target::read_or_empty(&target_path) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(
                target: "ipc.error",
                path = %target_path.display(),
                error = %e,
                "profile_update: target read_or_empty failed",
            );
            return ipc_error(IpcError::TargetReadFailed);
        }
    };

    let entry = match doc
        .as_table_mut()
        .and_then(|t| t.get_mut("profiles"))
        .and_then(|v| v.as_table_mut())
        .and_then(|t| t.get_mut(&id))
        .and_then(|v| v.as_table_mut())
    {
        Some(e) => e,
        None => {
            tracing::warn!(
                target: "ipc.error",
                path = %target_path.display(),
                id = %id,
                "profile_update: target missing [profiles.{id}] (concurrent edit?)",
            );
            return ipc_error(IpcError::ConcurrentEdit);
        }
    };

    if let Some(name) = patch.display_name {
        entry.insert("display_name".into(), toml::Value::String(name));
    }
    match patch.block_response {
        Some(Some(v)) => {
            let s = match v {
                crate::config::schema::profile::BlockResponseV1::Zero => "zero",
                crate::config::schema::profile::BlockResponseV1::Nxdomain => "nxdomain",
                crate::config::schema::profile::BlockResponseV1::Refused => "refused",
                crate::config::schema::profile::BlockResponseV1::SoaNodata => "soa_nodata",
            };
            entry.insert("block_response".into(), toml::Value::String(s.into()));
        }
        Some(None) => {
            entry.remove("block_response");
        }
        None => {}
    }
    match patch.blocked_ttl_secs {
        Some(Some(t)) => {
            entry.insert("blocked_ttl_secs".into(), toml::Value::Integer(t as i64));
        }
        Some(None) => {
            entry.remove("blocked_ttl_secs");
        }
        None => {}
    }
    if let Some(b) = patch.block_all {
        entry.insert("block_all".into(), toml::Value::Boolean(b));
    }
    if let Some(admin) = patch.admin_rules {
        let mut current: Vec<String> = entry
            .get("admin_rules")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        for add in &admin.add {
            if !current.iter().any(|x| x == add) {
                current.push(add.clone());
            }
        }
        current.retain(|x| !admin.remove.contains(x));
        entry.insert(
            "admin_rules".into(),
            toml::Value::Array(current.into_iter().map(toml::Value::String).collect()),
        );
    }
    // `tag_model_consolidation` §3.5: `profile.tags` delta. Slugs are
    // validated HERE rather than left to the post-write validator so a
    // `plp-s3`: a profile `tags` delta is refused, for the same reason as the
    // device path above — see `cli::commands::entity_tags::TAGS_RETIRED`.
    //
    // `plp-s5a` removed `Profile.tags`, so there is no longer a field to
    // write even if the refusal were lifted. The wire field is KEPT (as
    // `retired_tags`, renamed to `tags`) precisely so this refusal stays
    // reachable: `ProfileUpdatePatch` has no `deny_unknown_fields`, so
    // deleting it would make an old client's tag delta vanish into serde
    // with an OK answer.
    if patch
        .retired_tags
        .as_ref()
        .is_some_and(|t| !t.add.is_empty() || !t.remove.is_empty())
    {
        tracing::warn!(
            target: "ipc.error",
            id = %id,
            "profile_update: tags are retired — refusing the write ({})",
            crate::cli::commands::entity_tags::TAGS_RETIRED,
        );
        return ipc_error(IpcError::ValidatorRejected);
    }
    // An all-empty `TagsPatch` falls through the refusal above and is a
    // no-op — it writes NOTHING, not even `tags = []`.
    //
    // `plp-s4b`: it used to write. The apply block that stood here was
    // dead in every branch that mattered — the retirement refusal returns
    // first for any non-empty delta, so the slug loop, the add loop and
    // the retain could only ever run over empty vectors — and its one
    // remaining effect was an unconditional
    // `entry.insert("tags", Array(current))`. On a profile with no `tags`
    // key that inserted `tags = []`: a write on the exact patch the test
    // `an_empty_tags_delta_is_not_refused` documents as "not a tag
    // write", performed on behalf of a TUI form that submits its whole
    // patch on every save, so any scalar edit through the profile modal
    // planted it.
    //
    // It is not cosmetic. `Profile` is `deny_unknown_fields` and S5
    // deletes the `tags` field, so every `tags = []` this planted becomes
    // a config that does not load — the daemon refusing to start on a key
    // no operator ever typed.
    // `profile_list_policy` §4 S4: the per-profile direction override.
    //
    // **This is the whole consent gate for override-scope `allow`, and it
    // is here because this is the only place it can be.** Both operator
    // surfaces write `[profiles.<id>]` through `IpcCommand::ProfileUpdate`
    // — `cli::commands::profiles_v1` and `tui::ipc_poller` — so the
    // override has exactly one writer. P5 ("one function, N callers") is
    // stronger than usual here: one caller.
    if let Some(lists) = patch.lists {
        // Both halves are `String` on the wire. Validate before anything
        // is staged, for the same reason the tag loop above does: the
        // post-write validator rejects the WHOLE file, so one malformed
        // id would take the other fields of this patch down with it.
        for raw in lists.set.keys().chain(lists.clear.iter()) {
            if crate::config::schema::Id::new(raw.as_str()).is_err() {
                tracing::warn!(
                    target: "ipc.error",
                    id = %id,
                    list = %raw,
                    "profile_update: invalid list id in list-policy patch",
                );
                return ipc_error(IpcError::ValidatorRejected);
            }
        }

        // Refusals run over the whole `set` before a single key is
        // applied: a patch that names two lists and gets one wrong writes
        // neither, so a refusal never leaves a half-applied override.
        for (list_id, policy) in &lists.set {
            let row = match blocklist_row_on_disk(config_path, list_id) {
                Ok(Some(row)) => row,
                Ok(None) => {
                    return ipc_error(IpcError::ListPolicyUnknownList {
                        id: id.clone(),
                        list: list_id.clone(),
                    });
                }
                Err(e) => {
                    tracing::warn!(
                        target: "ipc.error",
                        id = %id,
                        list = %list_id,
                        error = %e,
                        "profile_update: cannot read the blocklist row this override names",
                    );
                    return ipc_error(IpcError::TargetReadFailed);
                }
            };

            // Only `Allow` costs anything. `Deny` and `Ignore` narrow what
            // the profile permits, so they have nothing to declare.
            //
            // **`clear` is deliberately NOT gated, and the argument is
            // not "it removes, so it is safe".** Clearing a key makes the
            // pair inherit the list's `base`, which can be `allow` — but
            // `base = allow` + `trust = remote-unsigned` + no ack is not
            // a config that loads at all (`UNSIGNED_ALLOW_LIST_REQUIRES_ACK`),
            // so the only allow a `clear` can inherit is one already
            // declared and already consented to. Gating it would refuse
            // the operator's own standing declaration.
            if *policy != crate::config::schema::blocklist::ListPolicy::Allow {
                continue;
            }

            // `enabled` is deliberately not consulted. A disabled list
            // holds no source bit and produces no verdict today, but
            // `warden blocklist set <id> --enabled true` flips that back
            // with no gate to re-run. Gate the declaration, not its
            // current reachability.
            let gates = crate::cli::commands::blocklists::allow_direction_gates(
                row.trust,
                row.accept_unsigned_allow,
                // **`consent_declared_now` is `false`, always, and this
                // is the point of the whole decision.** The gate reads
                // `consent_in_file || consent_declared_now`; the CLI and
                // TUI can pass `true` because a human typed a
                // confirmation. At the daemon there is nobody to ask, so
                // a `true` here could only have come off this wire —
                // self-declared by whatever client sent the patch.
                false,
            );
            if gates.needs_consent {
                tracing::warn!(
                    target: "audit",
                    action = "profile.list_policy.refused.v1",
                    uid = ?peer_uid,
                    id = %id,
                    list = %list_id,
                    "refused an allow-direction override on an unsigned remote list \
                     with no accept_unsigned_allow on its row",
                );
                return ipc_error(IpcError::OverrideAllowNeedsConsent {
                    id: id.clone(),
                    list: list_id.clone(),
                });
            }
        }

        let mut current: toml::value::Table = entry
            .get("lists")
            .and_then(|v| v.as_table())
            .cloned()
            .unwrap_or_default();
        // `set` BEFORE `clear`, frozen: a key in both ends removed.
        for (list_id, policy) in &lists.set {
            current.insert(
                list_id.clone(),
                toml::Value::String(policy.wire_str().to_string()),
            );
        }
        for list_id in &lists.clear {
            current.remove(list_id);
        }
        // An empty map is REMOVED, never written as `lists = {}`.
        // `Profile::lists` carries `skip_serializing_if =
        // BTreeMap::is_empty` precisely so an empty override table never
        // appears in an operator's file; a handler that inserted one
        // would put back what that attribute exists to keep out, and an
        // all-empty patch is documented as a no-op that writes nothing.
        if current.is_empty() {
            entry.remove("lists");
        } else {
            entry.insert("lists".into(), toml::Value::Table(current));
        }
    }

    if let Some(ecs_patch) = patch.ecs {
        if ecs_patch.clear {
            entry.remove("ecs");
        } else {
            let ecs_value = entry
                .entry("ecs".to_string())
                .or_insert_with(|| toml::Value::Table(Default::default()));
            if let toml::Value::Table(ecs_t) = ecs_value {
                if let Some(mode) = ecs_patch.mode {
                    let s = match mode {
                        crate::config::settings::EcsMode::Off => "off",
                        crate::config::settings::EcsMode::Coarse => "coarse",
                        crate::config::settings::EcsMode::Subnet => "subnet",
                    };
                    ecs_t.insert("mode".into(), toml::Value::String(s.into()));
                }
                if let Some(p4) = ecs_patch.source_prefix_v4 {
                    ecs_t.insert("source_prefix_v4".into(), toml::Value::Integer(p4 as i64));
                }
                if let Some(p6) = ecs_patch.source_prefix_v6 {
                    ecs_t.insert("source_prefix_v6".into(), toml::Value::Integer(p6 as i64));
                }
            }
        }
    }

    if let Err(e) =
        crate::cli::commands::target::write_value_validated(config_path, &target_path, &doc)
    {
        tracing::warn!(
            target: "ipc.error",
            id = %id,
            error = %e,
            "profile_update: staged patch rejected before write",
        );
        return ipc_error(IpcError::ValidatorRejected);
    }

    tracing::info!(
        target: "audit",
        action = "profile.update.v1",
        uid = ?peer_uid,
        id = %id,
        target = %target_path.display(),
        "IPC mutation"
    );

    let reload_pending = notify_reload(state, peer_uid, &format!("profile update \"{id}\""));

    let base = format!("updated profile \"{id}\"");
    let message = if reload_pending {
        format!("{base}{}", crate::ipc::protocol::RELOAD_PENDING_SUFFIX)
    } else {
        base
    };
    IpcResponse::Ok { message }
}

async fn handle_profile_delete(
    state: &DaemonState,
    id: String,
    peer_uid: Option<u32>,
) -> IpcResponse {
    let Some(config_path) = state.config_path.as_ref() else {
        return ipc_error(IpcError::NoConfigPath);
    };

    let _guard = state.config_write_lock.lock().await;

    let target_path = match crate::cli::commands::target::find_target_for_id(
        config_path,
        crate::cli::commands::target::EntityClass::Profiles,
        &id,
    ) {
        Ok(Some(p)) => p,
        Ok(None) => {
            return ipc_error(IpcError::ProfileNotFound { id: id.clone() });
        }
        Err(e) => {
            tracing::warn!(
                target: "ipc.error",
                path = %config_path.display(),
                error = %e,
                "profile_delete: find_target_for_id failed",
            );
            return ipc_error(IpcError::TargetScanFailed);
        }
    };

    let (mut doc, _) = match crate::cli::commands::target::read_or_empty(&target_path) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(
                target: "ipc.error",
                path = %target_path.display(),
                error = %e,
                "profile_delete: target read_or_empty failed",
            );
            return ipc_error(IpcError::TargetReadFailed);
        }
    };

    let removed = match crate::cli::commands::target::remove_profile(&mut doc, &id) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(
                target: "ipc.error",
                id = %id,
                error = %e,
                "profile_delete: remove_profile failed",
            );
            return ipc_error(IpcError::StageFailed);
        }
    };
    if !removed {
        tracing::warn!(
            target: "ipc.error",
            path = %target_path.display(),
            id = %id,
            "profile_delete: target missing [profiles.{id}] (concurrent edit?)",
        );
        return ipc_error(IpcError::ConcurrentEdit);
    }

    if let Err(e) =
        crate::cli::commands::target::write_value_validated(config_path, &target_path, &doc)
    {
        tracing::warn!(
            target: "ipc.error",
            id = %id,
            error = %e,
            "profile_delete: staged removal rejected before write (likely dangling refs)",
        );
        return ipc_error(IpcError::ValidatorRejected);
    }

    tracing::info!(
        target: "audit",
        action = "profile.delete.v1",
        uid = ?peer_uid,
        id = %id,
        target = %target_path.display(),
        "IPC mutation"
    );

    let reload_pending = notify_reload(state, peer_uid, &format!("profile delete \"{id}\""));

    let base = format!("removed profile \"{id}\"");
    let message = if reload_pending {
        format!("{base}{}", crate::ipc::protocol::RELOAD_PENDING_SUFFIX)
    } else {
        base
    };
    IpcResponse::Ok { message }
}

/// Fan-in helper for the profile-mutation handlers. Returns `true` if
/// the best-effort reload signal was dropped because the capacity-1
/// reload channel was already full — the caller should append
/// [`crate::ipc::protocol::RELOAD_PENDING_SUFFIX`] to its operator-
/// facing Ok message in that case. Returns `false` when the signal
/// was sent OR when no `reload_tx` is wired (tests).
///
/// The `Closed` branch preserves the prior behaviour: log at `audit`
/// target and return `false` so the caller still emits a bare Ok. The
/// per-handler inline pattern in the device / tracking handlers
/// upgrades Closed to an `ipc_error`; the profile handlers historically
/// did not, and §4.45 is a UX-only fix — unifying Closed semantics is
/// a separate scope-decision and would risk silently regressing
/// profile-handler error reporting.
fn notify_reload(state: &DaemonState, peer_uid: Option<u32>, op: &str) -> bool {
    if let Some(tx) = &state.reload_tx {
        match tx.try_send(peer_uid) {
            Ok(()) => false,
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => true,
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                tracing::warn!(
                    target: "audit",
                    uid = ?peer_uid,
                    op,
                    "reload channel closed — daemon may need restart to pick up change"
                );
                false
            }
        }
    } else {
        false
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn server_handles_status_command() {
        let state = Arc::new(test_state());
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        // Start server
        let server_handle = spawn_ipc_server(sock_path.clone(), state).await.unwrap();

        // Connect as client
        let stream = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let (reader, mut writer) = stream.into_split();

        let cmd = serde_json::to_string(&IpcCommand::Status).unwrap();
        writer
            .write_all(format!("{cmd}\n").as_bytes())
            .await
            .unwrap();
        writer.shutdown().await.unwrap();

        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();

        let resp: IpcResponse = serde_json::from_str(line.trim()).unwrap();
        match resp {
            IpcResponse::Status { listen, .. } => {
                assert_eq!(listen, "127.0.0.1:15353");
            }
            other => panic!("unexpected response: {other:?}"),
        }

        server_handle.abort();
    }

    #[tokio::test]
    async fn server_handles_query_command() {
        let state = Arc::new(test_state());
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        let server_handle = spawn_ipc_server(sock_path.clone(), state).await.unwrap();

        let stream = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let (reader, mut writer) = stream.into_split();

        let cmd = serde_json::to_string(&IpcCommand::Query {
            domain: "test.com".into(),
        })
        .unwrap();
        writer
            .write_all(format!("{cmd}\n").as_bytes())
            .await
            .unwrap();
        writer.shutdown().await.unwrap();

        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();

        let resp: IpcResponse = serde_json::from_str(line.trim()).unwrap();
        match resp {
            IpcResponse::QueryResult {
                domain,
                blocked,
                blocked_by,
            } => {
                assert_eq!(domain, "test.com");
                assert!(!blocked);
                assert!(blocked_by.is_none(), "allowed domain carries no source");
            }
            other => panic!("unexpected response: {other:?}"),
        }

        server_handle.abort();
    }

    /// §4.2 G1a — a blocked domain carries its attribution. A default
    /// profile with `block_all` blocks via the admin layer, so
    /// `evaluate_attributed` reports `BlockSource::AdminBlock` →
    /// `blocked_by = "admin_block"`.
    #[test]
    fn handle_query_attributes_admin_block() {
        use crate::config::schema::{ConfigV1, Id, Profile};
        use crate::profiles::ProfileResolver;

        let mut config = ConfigV1::test_scaffold();
        config.schema_version = 3;
        config.profiles.insert(
            "strict".into(),
            Profile {
                block_all: true,
                ..Default::default()
            },
        );
        config.server.default_profile = Some(Id::new("strict").unwrap());
        let bit_map = crate::lists::source_key::SourceBitMap::default();

        let mut state = test_state();
        state.profiles = Some(Arc::new(ProfileResolver::build(
            &config,
            &bit_map,
            &crate::config::custom_list::CustomListStore::new(),
        )));

        match handle_query("anything.example", &state) {
            IpcResponse::QueryResult {
                blocked,
                blocked_by,
                ..
            } => {
                assert!(blocked);
                assert_eq!(blocked_by.as_deref(), Some("admin_block"));
            }
            other => panic!("expected QueryResult, got {other:?}"),
        }
    }

    /// rev-2606 api-auth-07-04: the IPC probe validates at the trust
    /// boundary like its HTTP twin. Garbage gets the frozen
    /// InvalidArgument wire string (no input echo, no internal detail),
    /// not a meaningless "not blocked" verdict.
    #[test]
    fn handle_query_rejects_invalid_domain() {
        let state = test_state();
        for bad in [
            "not a domain!",
            "..",
            "localhost", // single-label — HTTP twin rejects it too
            "exa_mple.com",
            "",
        ] {
            match handle_query(bad, &state) {
                IpcResponse::Error { message } => {
                    assert_eq!(
                        message,
                        crate::ipc::errors::IPC_ERROR_INVALID_ARGUMENT,
                        "frozen generic on the wire for {bad:?}"
                    );
                }
                other => panic!("expected Error for {bad:?}, got {other:?}"),
            }
        }
    }

    /// Valid input still resolves — case-normalised, trailing dot
    /// stripped, same canonical form the HTTP twin produces.
    #[test]
    fn handle_query_accepts_valid_domain() {
        let state = test_state();
        match handle_query("Example.COM.", &state) {
            IpcResponse::QueryResult { domain, .. } => {
                assert_eq!(domain, "example.com");
            }
            other => panic!("expected QueryResult, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn server_handles_cache_flush() {
        // P0-3: CacheFlush is Mutating, so we need a state with a token
        // configured and the command must carry the matching token.
        let state = Arc::new(test_state_with_token("ps_cacheflush_test"));
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        let server_handle = spawn_ipc_server(sock_path.clone(), state).await.unwrap();

        let stream = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let (reader, mut writer) = stream.into_split();

        let cmd = serde_json::to_string(&IpcCommand::CacheFlush {
            domain: None,
            token: Some("ps_cacheflush_test".into()),
        })
        .unwrap();
        writer
            .write_all(format!("{cmd}\n").as_bytes())
            .await
            .unwrap();
        writer.shutdown().await.unwrap();

        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();

        let resp: IpcResponse = serde_json::from_str(line.trim()).unwrap();
        match resp {
            IpcResponse::Ok { message } => {
                assert!(message.contains("flushed"));
            }
            other => panic!("unexpected response: {other:?}"),
        }

        server_handle.abort();
    }

    #[tokio::test]
    async fn server_handles_domain_count() {
        let state = Arc::new(test_state());
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        let server_handle = spawn_ipc_server(sock_path.clone(), state).await.unwrap();

        let stream = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let (reader, mut writer) = stream.into_split();

        let cmd = serde_json::to_string(&IpcCommand::DomainCount).unwrap();
        writer
            .write_all(format!("{cmd}\n").as_bytes())
            .await
            .unwrap();
        writer.shutdown().await.unwrap();

        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();

        let resp: IpcResponse = serde_json::from_str(line.trim()).unwrap();
        match resp {
            IpcResponse::DomainCount { count } => {
                assert_eq!(count, 0);
            }
            other => panic!("unexpected response: {other:?}"),
        }

        server_handle.abort();
    }

    #[tokio::test]
    async fn server_handles_invalid_json() {
        let state = Arc::new(test_state());
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        let server_handle = spawn_ipc_server(sock_path.clone(), state).await.unwrap();

        let stream = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let (reader, mut writer) = stream.into_split();

        writer.write_all(b"not json\n").await.unwrap();
        writer.shutdown().await.unwrap();

        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();

        let resp: IpcResponse = serde_json::from_str(line.trim()).unwrap();
        match resp {
            IpcResponse::Error { message } => {
                assert!(message.contains("invalid command"));
            }
            other => panic!("unexpected response: {other:?}"),
        }

        server_handle.abort();
    }

    #[test]
    fn accept_backoff_doubles_then_caps_at_5s() {
        // M-27: the schedule must double from 100 ms and saturate at
        // 5 s. Pin every step so a future tweak that drops the cap or
        // changes the base must update this test deliberately.
        use std::time::Duration;
        assert_eq!(accept_backoff_for(0), Duration::from_millis(100));
        assert_eq!(accept_backoff_for(1), Duration::from_millis(200));
        assert_eq!(accept_backoff_for(2), Duration::from_millis(400));
        assert_eq!(accept_backoff_for(3), Duration::from_millis(800));
        assert_eq!(accept_backoff_for(4), Duration::from_millis(1_600));
        assert_eq!(accept_backoff_for(5), Duration::from_millis(3_200));
        // 100 ms * 64 = 6400 ms → clamped to cap.
        assert_eq!(accept_backoff_for(6), Duration::from_secs(5));
        // Far beyond doubling range — must still cap, not overflow.
        assert_eq!(accept_backoff_for(31), Duration::from_secs(5));
        assert_eq!(accept_backoff_for(32), Duration::from_secs(5));
        assert_eq!(accept_backoff_for(u32::MAX), Duration::from_secs(5));
    }

    #[test]
    fn ipc_write_timeout_constant_matches_read_timeout() {
        // M-25: the write-side timeout is intentionally identical to
        // the read-side timeout (5 s, hard-coded inside read_line's
        // tokio::time::timeout call). Pinning the constant here
        // protects against accidental drift if either side is later
        // tuned without the other.
        assert_eq!(IPC_WRITE_TIMEOUT, std::time::Duration::from_secs(5));
    }

    #[tokio::test]
    async fn write_all_with_timeout_returns_elapsed_when_peer_buffer_stays_full() {
        // M-25: prove the timeout primitive used by handle_connection
        // returns Err(Elapsed) when the underlying write_all cannot
        // make progress. A real Unix socket has a kernel-side
        // ~200 KiB receive buffer that absorbs our small JSON
        // responses, so reproducing slow-loris through it would
        // require bytes we don't otherwise need to write. Using
        // `tokio::io::duplex(8)` pairs two streams sharing an 8-byte
        // ring: with `_hold_reader` parked and a 1 KiB payload, the
        // writer fills the ring then blocks until the reader drains.
        // We use a 50 ms test timeout so the assertion runs quickly
        // — the production constant (5 s) is pinned by the sibling
        // `ipc_write_timeout_constant_matches_read_timeout` test.
        use tokio::io::AsyncWriteExt;

        let (mut writer, _hold_reader) = tokio::io::duplex(8);
        let payload = vec![0u8; 1024];

        let res = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            writer.write_all(&payload),
        )
        .await;

        assert!(
            res.is_err(),
            "write_all must time out when peer never drains the buffer, got {res:?}"
        );
    }

    #[tokio::test]
    async fn server_handles_oversize_command_with_clean_shutdown() {
        // M-26: the "command too large" early-return path used to skip
        // writer.shutdown(), so the peer saw ECONNRESET instead of EOF.
        // After unification, both paths half-close cleanly. We assert
        // the peer reads ONE JSON line then EOF (read returns 0).
        let state = Arc::new(test_state());
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("oversize.sock");

        let server_handle = spawn_ipc_server(sock_path.clone(), state).await.unwrap();

        let stream = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let (reader, mut writer) = stream.into_split();

        // Exactly MAX_COMMAND_SIZE + 1 bytes total (65 KiB of 'a' + '\n').
        // line.len() = MAX_COMMAND_SIZE + 1 trips the oversize branch.
        // Sized so the daemon's `take(MAX_COMMAND_SIZE + 1)` consumes
        // every byte — leaving unread bytes in the kernel buffer would
        // cause RST-on-close instead of clean FIN, masking the bug we
        // are testing for.
        let mut payload = vec![b'a'; MAX_COMMAND_SIZE as usize];
        payload.push(b'\n');
        writer.write_all(&payload).await.unwrap();
        writer.shutdown().await.unwrap();

        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let resp: IpcResponse = serde_json::from_str(line.trim()).unwrap();
        match resp {
            IpcResponse::Error { message } => {
                assert_eq!(message, "command too large");
            }
            other => panic!("unexpected response: {other:?}"),
        }

        // Daemon must half-close after the error response so the peer
        // sees EOF on the next read, not a hung socket.
        let mut tail = Vec::new();
        let trailing = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut tail),
        )
        .await
        .expect("daemon must half-close after oversize-command response")
        .unwrap();
        assert_eq!(
            trailing, 0,
            "expected clean EOF after oversize response, got {trailing} extra bytes"
        );

        server_handle.abort();
    }

    #[tokio::test]
    async fn socket_permissions_are_0600() {
        use std::os::unix::fs::PermissionsExt;

        let state = Arc::new(test_state());
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        let server_handle = spawn_ipc_server(sock_path.clone(), state).await.unwrap();

        let meta = std::fs::metadata(&sock_path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        // §4.32 P0: tightened from 0o660 to 0o600 — owner-only. Group
        // members can no longer reach the IPC bus.
        assert_eq!(mode, 0o600, "socket should be mode 0600, got {:o}", mode);

        server_handle.abort();
    }

    #[tokio::test]
    async fn accept_loop_drops_connections_beyond_cap() {
        // H-07: peers beyond the concurrency cap must see their
        // connection dropped immediately rather than queued, otherwise
        // a local spawn-flood DoS can exhaust FDs / heap / tokio task
        // slots on the runtime that also services DNS queries.
        //
        // Setup: spawn the server with cap=2, then open three clients
        // that connect but never write. The first two are accepted
        // and their handlers block in `read_line` (5s read timeout).
        // The third must be accepted-then-dropped, which the client
        // observes as immediate EOF on read.

        let state = Arc::new(test_state());
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("cap-test.sock");

        let server = spawn_ipc_server_with_cap(sock_path.clone(), state, 2)
            .await
            .unwrap();

        // Open two connections that hold their permits open. We keep
        // the streams alive; the daemon-side handlers are blocked
        // reading.
        let _hold_a = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let _hold_b = tokio::net::UnixStream::connect(&sock_path).await.unwrap();

        // Brief yield so the accept loop spawns the two handlers and
        // they each grab a permit before the next connect.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Third connection: accept happens, but try_acquire_owned
        // fails and the daemon drops the stream. The client sees
        // EOF (read returns 0) on its read end.
        let mut probe = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let mut buf = [0u8; 1];
        let read_n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::io::AsyncReadExt::read(&mut probe, &mut buf),
        )
        .await
        .expect("daemon must close the over-cap connection within timeout")
        .unwrap();
        assert_eq!(
            read_n, 0,
            "over-cap connection must be closed by daemon, got {read_n} bytes"
        );

        server.abort();
    }

    #[tokio::test]
    async fn accept_loop_recovers_capacity_after_drop() {
        // H-07: a permit released by handler exit must let the next
        // connection through. Validates the semaphore's release path
        // (tokio's `OwnedSemaphorePermit::drop`) is wired correctly.
        let state = Arc::new(test_state());
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("cap-recovery.sock");

        let server = spawn_ipc_server_with_cap(sock_path.clone(), state, 1)
            .await
            .unwrap();

        // Take the only permit, then close immediately so the handler
        // exits and releases.
        {
            let mut hold = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
            // Send an invalid command so the handler completes quickly
            // (writes error response, releases permit).
            tokio::io::AsyncWriteExt::write_all(&mut hold, b"not-json\n")
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::shutdown(&mut hold).await.unwrap();
            // Drain the response so the handler can finish writing.
            let mut sink = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut hold, &mut sink)
                .await
                .ok();
            drop(hold);
        }

        // Brief yield so the server-side handler completes and
        // releases its permit.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Next connection should succeed (cap recovered).
        let mut next = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let cmd = serde_json::to_string(&IpcCommand::Status).unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut next, format!("{cmd}\n").as_bytes())
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::shutdown(&mut next).await.unwrap();

        let mut reader = BufReader::new(next);
        let mut line = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            reader.read_line(&mut line),
        )
        .await
        .expect("post-recovery connection must respond within timeout")
        .unwrap();
        assert!(
            line.contains("\"Status\"") || line.contains("\"status\""),
            "expected Status response, got: {line}"
        );

        server.abort();
    }

    #[tokio::test]
    async fn bind_with_atomic_perms_produces_0600_at_canonical_path() {
        // H-06 / §4.32 P0: pin the atomic-rename path. The previous
        // design did bind→chmod, exposing a TOCTOU window where the
        // canonical socket path was visible at `0o666 & ~umask`
        // (typically `0o644`) until chmod tightened it. The atomic-
        // rename approach binds to a temp path, chmods, then
        // atomically renames into place — peers resolving the
        // canonical path see `0o600` from the first syscall. §4.32
        // tightened the chmod target from `0o660` to `0o600`.
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("atomic-perms.sock");

        let listener = bind_with_atomic_perms(&sock_path).unwrap();
        let mode = std::fs::metadata(&sock_path).unwrap().permissions().mode() & 0o777;
        drop(listener);

        assert_eq!(
            mode, 0o600,
            "atomic-perms bind must produce 0o600 at canonical path, got 0o{mode:o}"
        );
        // After bind, no `.bind.<pid>.<nanos>` temp leftover should
        // remain in the parent directory.
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let name = entry.unwrap().file_name();
            let name_str = name.to_string_lossy();
            assert!(
                !name_str.contains(".bind."),
                "stale bind temp left behind: {name_str}"
            );
        }
    }

    #[tokio::test]
    async fn handle_connection_refuses_uid_mismatch() {
        // §4.32 P0: peer-uid gate. When the connecting peer's SO_PEERCRED
        // uid does not equal `state.daemon_uid`, the daemon must drop the
        // stream silently — no IpcResponse body — and emit an audit warn.
        // Peer observes EOF on read.
        let mut state = test_state();
        // Force daemon_uid to a value that cannot match the test process's
        // own euid. Saturating-add avoids u32 overflow on `geteuid()=u32::MAX`
        // (unreachable on Linux but cheap to defend).
        state.daemon_uid = current_euid().saturating_add(1);
        let state = Arc::new(state);

        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("uid-mismatch.sock");
        let server_handle = spawn_ipc_server(sock_path.clone(), state).await.unwrap();

        let mut probe = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        // Send a valid Status command. If the gate were absent the
        // daemon would write a Status response back; with the gate it
        // closes the stream before reading.
        let cmd = serde_json::to_string(&IpcCommand::Status).unwrap();
        let _ =
            tokio::io::AsyncWriteExt::write_all(&mut probe, format!("{cmd}\n").as_bytes()).await;
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut probe).await;

        let mut buf = Vec::new();
        // Daemon may either:
        //  - close cleanly → read_to_end returns Ok(0) and `buf` is empty.
        //  - return ConnectionReset (ECONNRESET) before our write fully
        //    drained → read_to_end returns Err. Either outcome means
        //    "no IpcResponse landed on the wire", which is the contract.
        let read_outcome = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::io::AsyncReadExt::read_to_end(&mut probe, &mut buf),
        )
        .await
        .expect("daemon must close uid-mismatch stream within timeout");
        match read_outcome {
            Ok(n) => assert_eq!(
                n,
                0,
                "uid-mismatch must close with no body, got {n} bytes: {:?}",
                String::from_utf8_lossy(&buf)
            ),
            Err(e) => assert_eq!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset,
                "expected ConnectionReset on uid-mismatch close, got {e:?}"
            ),
        }
        assert!(
            buf.is_empty(),
            "uid-mismatch path must never write a response body, got {:?}",
            String::from_utf8_lossy(&buf)
        );

        server_handle.abort();
    }

    #[tokio::test]
    async fn handle_connection_accepts_uid_match() {
        // §4.32 P0: the gate must NOT reject the daemon-uid peer (the
        // happy path). Defaulting `state.daemon_uid` to `current_euid()`
        // matches the test process's own uid, so the connection should
        // proceed and a Status response should land on the wire.
        let state = Arc::new(test_state());
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("uid-match.sock");
        let server_handle = spawn_ipc_server(sock_path.clone(), state).await.unwrap();

        let stream = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let cmd = serde_json::to_string(&IpcCommand::Status).unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut writer, format!("{cmd}\n").as_bytes())
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::shutdown(&mut writer)
            .await
            .unwrap();

        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            reader.read_line(&mut line),
        )
        .await
        .expect("uid-match connection must produce a response within timeout")
        .unwrap();
        assert!(
            line.contains("\"status\"") || line.contains("\"Status\""),
            "expected Status response on uid-match path, got: {line}"
        );

        server_handle.abort();
    }

    #[tokio::test]
    async fn handle_connection_refuses_none_peer_uid() {
        // §4.32 P0 / DISC-7: if `SO_PEERCRED` ever fails (extremely
        // unlikely on Linux for an accepted AF_UNIX stream), `peer_uid`
        // returns `None`. The gate must treat None as a refusal —
        // fail-closed — because the daemon cannot prove the peer is
        // its own user without a valid cred. We exercise the branch
        // by calling `handle_connection` directly with a
        // `tokio::net::UnixStream` and `peer_uid = None`.
        let state = Arc::new(test_state());

        // socketpair gives us two halves we can pass to handle_connection
        // without going through accept_loop (which would re-derive
        // peer_uid via SO_PEERCRED).
        let (a, _b) = tokio::net::UnixStream::pair().unwrap();
        let result = handle_connection(a, None, &state).await;
        assert!(
            result.is_ok(),
            "None-uid refusal path must return Ok (silent drop), got {result:?}"
        );
    }

    #[test]
    fn current_euid_matches_libc_geteuid() {
        // §4.32 P0: trivial smoke that `current_euid()` returns the
        // same value as `libc::geteuid()`. Acts as a regression catch
        // if a refactor swaps the syscall (e.g. to `getuid`) which
        // would silently break the daemon-uid gate when the daemon
        // runs setuid.
        // SAFETY: same justification as in `current_euid()` itself.
        let direct = unsafe { libc::geteuid() };
        assert_eq!(current_euid(), direct);
    }

    #[test]
    fn bind_socket_refuses_to_clobber_regular_file() {
        // H-09: a regular file at the socket path must NOT be silently
        // unlinked. The daemon should refuse to bind and surface a plain-
        // English error so the operator can inspect the planted file.
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("not-a-socket");
        std::fs::write(&sock_path, b"operator marker").unwrap();

        let err = bind_socket(&sock_path).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("not a socket"),
            "expected 'not a socket' in error, got: {msg}"
        );
        // The marker file must still be on disk — the bail path must not
        // unlink before reporting the error.
        assert!(sock_path.exists(), "regular file was clobbered");
        let body = std::fs::read(&sock_path).unwrap();
        assert_eq!(body, b"operator marker");
    }

    #[test]
    fn bind_socket_refuses_to_follow_planted_symlink() {
        // H-09: a symlink at the socket path must trip the "not a socket"
        // branch — `symlink_metadata` does not follow, so the link target
        // is never inspected and never unlinked.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("victim");
        std::fs::write(&target, b"do not delete me").unwrap();
        let sock_path = dir.path().join("link.sock");
        std::os::unix::fs::symlink(&target, &sock_path).unwrap();

        let err = bind_socket(&sock_path).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("not a socket"),
            "expected 'not a socket' in error, got: {msg}"
        );
        // Both the symlink and its target must still be intact.
        assert!(sock_path.is_symlink(), "symlink was unlinked");
        assert!(target.exists(), "symlink target was unlinked");
        let body = std::fs::read(&target).unwrap();
        assert_eq!(body, b"do not delete me");
    }

    #[tokio::test]
    async fn bind_socket_removes_stale_socket() {
        // H-09: the legitimate stale-socket case must still work — an
        // actual socket left by a prior run is unlinked before bind.
        // Tokio runtime is required because `tokio::net::UnixListener::bind`
        // registers the FD with the reactor.
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("stale.sock");
        // Create a real socket at the path, then drop the listener so
        // the inode lingers as a stale socket file.
        let stale = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
        drop(stale);
        assert!(sock_path.exists());

        // bind_socket should unlink the stale socket and bind a fresh one.
        let listener = bind_socket(&sock_path).unwrap();
        drop(listener);
        // After bind, the path is again a socket file.
        assert!(sock_path.exists());
    }

    /// rev-2606 api-auth-07-05: a parent directory bind_socket CREATES
    /// must land at 0o700 regardless of umask (was `0o777 & ~umask`).
    #[tokio::test]
    async fn bind_socket_fresh_parent_dir_is_0o700() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("fresh-sub").join("control.sock");
        assert!(!sock_path.parent().unwrap().exists());

        let listener = bind_socket(&sock_path).unwrap();
        drop(listener);

        let mode = std::fs::metadata(sock_path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "freshly-created parent must be 0o700");
    }

    /// DISC-3 symmetry: a PRE-EXISTING parent (production `/run/...`,
    /// systemd-owned) is never re-chmodded.
    #[tokio::test]
    async fn bind_socket_preexisting_parent_mode_untouched() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("owned-by-systemd");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();

        let sock_path = parent.join("control.sock");
        let listener = bind_socket(&sock_path).unwrap();
        drop(listener);

        let mode = std::fs::metadata(&parent).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o755,
            "pre-existing parent must keep its mode"
        );
    }

    fn test_state() -> DaemonState {
        use crate::dns::cache::DnsCache;

        let cache_config = crate::config::settings::CacheConfig::default();
        DaemonState {
            filter: Arc::new(FilterEngine::new()),
            cache: DnsCache::new(&cache_config),
            profiles: None,
            stats: None,
            listen_addr: "127.0.0.1:15353".into(),
            upstream_mode: "plain".into(),
            upstream_count: 2,
            list_count: 0,
            started_at: Instant::now(),
            shutdown_tx: None,
            reload_tx: None,
            api_token_hash: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
            config_path: None,
            config_write_lock: Arc::new(tokio::sync::Mutex::new(())),
            list_statuses: None,
            list_state: None,
            local_records_hits: None,
            log_ring: None,
            notification_tx: None,
            reload_coalescer: None,
            oui_table: None,
            list_labels: Arc::new(vec![None; 64]),
            list_cmd_tx: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
            daemon_uid: current_euid(),
            resource_budget_store: crate::resource_budget::types::new_store(),
            #[cfg(feature = "cluster")]
            cluster_observe: None,
        }
    }

    /// Build a state with a configured token hash for auth tests.
    fn test_state_with_token(token_plaintext: &str) -> DaemonState {
        use crate::auth::token::hash_token;
        use crate::dns::cache::DnsCache;

        let cache_config = crate::config::settings::CacheConfig::default();
        DaemonState {
            filter: Arc::new(FilterEngine::new()),
            cache: DnsCache::new(&cache_config),
            profiles: None,
            stats: None,
            listen_addr: "127.0.0.1:15353".into(),
            upstream_mode: "plain".into(),
            upstream_count: 2,
            list_count: 0,
            started_at: Instant::now(),
            shutdown_tx: None,
            reload_tx: None,
            api_token_hash: Arc::new(arc_swap::ArcSwap::from_pointee(Some(hash_token(
                token_plaintext,
            )))),
            config_path: None,
            config_write_lock: Arc::new(tokio::sync::Mutex::new(())),
            list_statuses: None,
            list_state: None,
            local_records_hits: None,
            log_ring: None,
            notification_tx: None,
            reload_coalescer: None,
            oui_table: None,
            list_labels: Arc::new(vec![None; 64]),
            list_cmd_tx: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
            daemon_uid: current_euid(),
            resource_budget_store: crate::resource_budget::types::new_store(),
            #[cfg(feature = "cluster")]
            cluster_observe: None,
        }
    }

    // --- Sprint 37 QL2: handle_query_logs status fields ---

    fn test_state_with_query_log(
        log_path: &std::path::Path,
        config_dir: &std::path::Path,
        query_log_enabled: bool,
    ) -> DaemonState {
        use crate::dns::cache::DnsCache;
        use crate::tracking::engine::StatsEngine;

        let mut tracking = crate::config::settings::TrackingConfig::default();
        tracking.query_log_enabled = query_log_enabled;
        tracking.query_log_path = log_path.to_path_buf();
        let engine = Arc::new(StatsEngine::new(&tracking));

        let cache_config = crate::config::settings::CacheConfig::default();
        DaemonState {
            filter: Arc::new(FilterEngine::new()),
            cache: DnsCache::new(&cache_config),
            profiles: None,
            stats: Some(engine),
            listen_addr: "127.0.0.1:15353".into(),
            upstream_mode: "plain".into(),
            upstream_count: 2,
            list_count: 0,
            started_at: Instant::now(),
            shutdown_tx: None,
            reload_tx: None,
            api_token_hash: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
            config_path: Some(config_dir.join("config.toml")),
            config_write_lock: Arc::new(tokio::sync::Mutex::new(())),
            list_statuses: None,
            list_state: None,
            local_records_hits: None,
            log_ring: None,
            notification_tx: None,
            reload_coalescer: None,
            oui_table: None,
            list_labels: Arc::new(vec![None; 64]),
            list_cmd_tx: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
            daemon_uid: current_euid(),
            resource_budget_store: crate::resource_budget::types::new_store(),
            #[cfg(feature = "cluster")]
            cluster_observe: None,
        }
    }

    /// Write `n` parseable entries and return the blob, so every log
    /// file in the m2 test below is large enough that the read is
    /// unambiguously still in flight when the canary is polled.
    fn bulk_log_blob(n: usize) -> String {
        let mut s = String::new();
        for i in 0..n {
            let entry = crate::tracking::query_log::QueryLogEntry {
                timestamp: "2026-04-23T10:00:00Z".into(),
                client_ip: "10.0.0.1".parse().unwrap(),
                client_name: None,
                domain: format!("d{i}.example.com"),
                query_type: "A".into(),
                result: "ALLOWED".into(),
                response_time_us: 100,
                cname_chain_via: None,
                rewrote_from: None,
            };
            s.push_str(&serde_json::to_string(&entry).unwrap());
            s.push('\n');
        }
        s
    }

    /// `s-review-2605-ipc-m2`: a `QueryLogs` request must not park a
    /// tokio worker for the duration of its multi-file disk read.
    ///
    /// **The observable is ordering, not latency.** On a single-worker
    /// runtime a task spawned before the read can only make progress if
    /// the handler yields the worker. When the read runs inline in
    /// `poll()` the canary gets zero CPU *no matter how slow the read
    /// is*, so the assertion needs no timing threshold and cannot flake
    /// — which matters in a suite with known environment races.
    ///
    /// The oversized corpus is a robustness aid, not the mechanism: the
    /// domain filter matches nothing, so
    /// `read_log_entries_with_state` never reaches its
    /// `entries.len() >= limit` early break and walks every retained
    /// sibling. That guarantees the `spawn_blocking` join handle is
    /// still pending on its first poll in the fixed build.
    ///
    /// Driven through `dispatch_command` (async in both builds) rather
    /// than `handle_query_logs`, so this test compiles unchanged across
    /// the signature change it is pinning.
    ///
    /// **The read must be `tokio::spawn`ed, not awaited in the test
    /// body.** `#[tokio::test]` drives the body with `block_on` on the
    /// *main* thread, which is not a worker: an earlier version of this
    /// test awaited the dispatch directly, so the inline read parked the
    /// main thread while the worker stayed free to run the canary — and
    /// it **passed against the unfixed handler**. Spawning the read puts
    /// it on the same single worker the canary needs, which is the whole
    /// point. Both tasks are spawned from the block_on thread and land
    /// on the injection queue in FIFO order, so the read is picked up
    /// first.
    ///
    /// **If a future tokio changes that scheduling order, this test
    /// degrades to a false negative, not a flake** — it would go green
    /// while the defect is live, which is the failure mode above and the
    /// one this repo has shipped before. Anyone touching the handler or
    /// bumping tokio should re-confirm it goes *red* against an inline
    /// read before trusting a green run.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn query_logs_read_does_not_park_the_runtime_worker() {
        use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("query.log");
        let blob = bulk_log_blob(8_000);
        std::fs::write(&log, &blob).unwrap();
        // Seven dated siblings — `retention_days` defaults to 7, so all
        // of them are walked.
        for d in 1..=7 {
            std::fs::write(
                dir.path().join(format!("query.log.2026-04-{:02}", 10 + d)),
                &blob,
            )
            .unwrap();
        }

        // `QueryLogs` is not a ReadOnly-tier command — it passes the
        // admin-token gate before reaching the handler.
        let mut state = test_state_with_query_log(&log, dir.path(), true);
        state.api_token_hash = Arc::new(arc_swap::ArcSwap::from_pointee(Some(
            crate::auth::token::hash_token("m2-test-token"),
        )));
        let state = Arc::new(state);

        let canary = Arc::new(AtomicBool::new(false));
        // Captured *inside* the read task, at the instant the read
        // returns: "had the canary already run?"
        let observed = Arc::new(AtomicBool::new(false));

        // Spawned FIRST, so the single worker picks it off the injection
        // queue before the canary. This task — not the test body — is
        // what must be prevented from parking the worker.
        let read_task = tokio::spawn({
            let state = Arc::clone(&state);
            let canary = Arc::clone(&canary);
            let observed = Arc::clone(&observed);
            async move {
                let resp = dispatch_command(
                    IpcCommand::QueryLogs {
                        limit: 1000,
                        client: None,
                        blocked_only: false,
                        // Matches nothing → the limit is never satisfied
                        // → the sibling walk runs to completion.
                        domain: Some("zz-matches-nothing".into()),
                        since_secs: None,
                        cursor: None,
                        advanced: None,
                        token: Some("m2-test-token".into()),
                    },
                    None,
                    &state,
                )
                .await;
                observed.store(canary.load(AtomicOrdering::SeqCst), AtomicOrdering::SeqCst);
                resp
            }
        });

        tokio::spawn({
            let flag = Arc::clone(&canary);
            async move {
                flag.store(true, AtomicOrdering::SeqCst);
            }
        });

        let resp = read_task.await.expect("read task must not panic");

        assert!(
            matches!(resp, IpcResponse::QueryLogs { .. }),
            "handler must still answer a well-formed response: {resp:?}"
        );
        assert!(
            observed.load(AtomicOrdering::SeqCst),
            "a task queued behind the query-log read had still not run by the time the read \
             returned — the read ran inline and parked the runtime worker"
        );
    }

    #[tokio::test]
    async fn query_logs_response_reports_disabled_when_flag_false() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("query.log");
        // File exists with a valid entry — the daemon must still return
        // `logging_enabled = false` when the flag is off, even though
        // the read succeeds.
        let entry = crate::tracking::query_log::QueryLogEntry {
            timestamp: "2026-04-23T10:00:00Z".into(),
            client_ip: "10.0.0.1".parse().unwrap(),
            client_name: None,
            domain: "example.com".into(),
            query_type: "A".into(),
            result: "ALLOWED".into(),
            response_time_us: 100,
            cname_chain_via: None,
            rewrote_from: None,
        };
        std::fs::write(&log, serde_json::to_string(&entry).unwrap() + "\n").unwrap();
        let state = test_state_with_query_log(&log, dir.path(), false);

        let resp = handle_query_logs(
            &state,
            crate::ipc::protocol::QueryLogRequest {
                limit: 10,
                ..Default::default()
            },
        )
        .await;
        match resp {
            IpcResponse::QueryLogs {
                entries,
                logging_enabled,
                file_state,
                ..
            } => {
                assert!(!logging_enabled, "expected logging_enabled=false");
                assert_eq!(file_state, crate::ipc::protocol::QueryLogFileState::Ok);
                assert_eq!(entries.len(), 1);
            }
            other => panic!("expected QueryLogs, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn query_logs_response_reports_missing_when_file_absent() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("query.log"); // deliberately not created
        let state = test_state_with_query_log(&log, dir.path(), true);

        let resp = handle_query_logs(
            &state,
            crate::ipc::protocol::QueryLogRequest {
                limit: 10,
                ..Default::default()
            },
        )
        .await;
        match resp {
            IpcResponse::QueryLogs {
                entries,
                logging_enabled,
                file_state,
                ..
            } => {
                assert!(logging_enabled);
                assert_eq!(file_state, crate::ipc::protocol::QueryLogFileState::Missing);
                assert!(entries.is_empty());
            }
            other => panic!("expected QueryLogs, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn query_logs_response_reports_unreadable_on_permission_error() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("query.log");
        std::fs::write(&log, "{}\n").unwrap();
        // chmod 000 — root can still read on Linux, so skip the assertion
        // for uid 0 (CI runs as a regular user; the Debian CI container
        // doesn't run `cargo test`).
        let mut perms = std::fs::metadata(&log).unwrap().permissions();
        perms.set_mode(0o000);
        std::fs::set_permissions(&log, perms).unwrap();

        if nix_uid_is_zero() {
            return;
        }

        let state = test_state_with_query_log(&log, dir.path(), true);
        let resp = handle_query_logs(
            &state,
            crate::ipc::protocol::QueryLogRequest {
                limit: 10,
                ..Default::default()
            },
        )
        .await;

        // Restore perms so tempdir cleanup succeeds.
        let mut perms = std::fs::metadata(&log).unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&log, perms).unwrap();

        match resp {
            IpcResponse::QueryLogs {
                entries,
                logging_enabled,
                file_state,
                ..
            } => {
                assert!(logging_enabled);
                assert_eq!(
                    file_state,
                    crate::ipc::protocol::QueryLogFileState::Unreadable
                );
                assert!(entries.is_empty());
            }
            other => panic!("expected QueryLogs, got {other:?}"),
        }
    }

    #[cfg(unix)]
    fn nix_uid_is_zero() -> bool {
        // SAFETY: `libc::getuid` is a plain syscall with no arguments
        // and no cross-thread aliasing hazards.
        unsafe { libc::getuid() == 0 }
    }

    #[tokio::test]
    async fn query_logs_response_reports_ok_on_happy_path() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("query.log");
        let entry = crate::tracking::query_log::QueryLogEntry {
            timestamp: "2026-04-23T10:00:00Z".into(),
            client_ip: "10.0.0.1".parse().unwrap(),
            client_name: Some("laptop".into()),
            domain: "google.com".into(),
            query_type: "A".into(),
            result: "ALLOWED".into(),
            response_time_us: 100,
            cname_chain_via: None,
            rewrote_from: None,
        };
        std::fs::write(&log, serde_json::to_string(&entry).unwrap() + "\n").unwrap();

        let state = test_state_with_query_log(&log, dir.path(), true);
        let resp = handle_query_logs(
            &state,
            crate::ipc::protocol::QueryLogRequest {
                limit: 10,
                ..Default::default()
            },
        )
        .await;
        match resp {
            IpcResponse::QueryLogs {
                entries,
                logging_enabled,
                file_state,
                ..
            } => {
                assert!(logging_enabled);
                assert_eq!(file_state, crate::ipc::protocol::QueryLogFileState::Ok);
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].domain, "google.com");
            }
            other => panic!("expected QueryLogs, got {other:?}"),
        }
    }

    // --- P0-3: IPC authorization tests ---

    /// ReadOnly command (Status) works without any token, even when the
    /// daemon has no token configured. This is the "fresh install, no
    /// auth yet" path — warden status must still work.
    #[tokio::test]
    async fn readonly_command_works_without_token() {
        let state = Arc::new(test_state());
        let resp = dispatch_command(IpcCommand::Status, None, &state).await;
        match resp {
            IpcResponse::Status { .. } => {}
            other => panic!("expected Status, got {other:?}"),
        }
    }

    /// mem2608-s3 / F-E — the discriminating regression test. No explicit
    /// flush anywhere in this body: the insert calls `DnsCache::insert`
    /// directly, and the read goes through the full
    /// `dispatch_command` → `handle_status` path exactly as the real
    /// `warden status` IPC round-trip does. Against the pre-fix (sync
    /// `handle_status`, cold `entry_count()`/`weighted_size()` read) this
    /// is flaky-to-failing; against the fix it is deterministic, because
    /// `handle_status` flushes internally before reading.
    #[tokio::test]
    async fn status_reports_cache_occupancy_without_a_manual_flush() {
        let state = Arc::new(test_state());
        state
            .cache
            .insert(
                "nonexistent.example",
                hickory_proto::rr::RecordType::A,
                hickory_proto::rr::DNSClass::IN,
                Vec::new(),
                hickory_proto::op::ResponseCode::NXDomain,
                None,
                None,
            )
            .await;

        let resp = dispatch_command(IpcCommand::Status, None, &state).await;
        match resp {
            IpcResponse::Status {
                cache_entries,
                cache_weighted_size,
                ..
            } => {
                assert_eq!(cache_entries, 1);
                assert_eq!(cache_weighted_size, 1);
            }
            other => panic!("expected Status, got {other:?}"),
        }
    }

    /// mem2608-s3 / F-P — the discriminating denominator test. 4 blocked
    /// queries (never reach the cache, per `evaluate_with_overlay` running
    /// before `cache.lookup_keyed`), 3 non-blocked cache hits, 3 non-blocked
    /// misses: 10 total, 6 cacheable. Under the pre-fix `hits / total`
    /// formula this reads 30%; under `hits / (total - blocked)` it reads
    /// 50%. The two are far enough apart that no rounding ambiguity can
    /// paper over a regression back to the old denominator. Calls
    /// `handle_tracking_stats` directly — it's `Admin`-tier over IPC and
    /// the auth gate is not what this test is about.
    #[test]
    fn tracking_stats_cache_rate_excludes_blocked_from_denominator() {
        use crate::config::settings::TrackingConfig;
        use std::net::{IpAddr, Ipv4Addr};

        let stats = Arc::new(StatsEngine::new(&TrackingConfig::default()));
        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        for _ in 0..4 {
            stats.record_query(
                ip,
                "blocked.example",
                None,
                None,
                hickory_proto::rr::RecordType::A,
                true,
                false,
                None,
            );
        }
        for _ in 0..3 {
            stats.record_query(
                ip,
                "cached.example",
                None,
                None,
                hickory_proto::rr::RecordType::A,
                false,
                true,
                None,
            );
        }
        for _ in 0..3 {
            stats.record_query(
                ip,
                "miss.example",
                None,
                None,
                hickory_proto::rr::RecordType::A,
                false,
                false,
                None,
            );
        }
        let state = DaemonState {
            stats: Some(stats),
            ..test_state()
        };

        let resp = handle_tracking_stats(&state);
        match resp {
            IpcResponse::TrackingStats {
                cache_hit_rate,
                blocked_pct,
                ..
            } => {
                assert!((cache_hit_rate - 50.0).abs() < 1e-9, "got {cache_hit_rate}");
                // blocked_pct is deliberately unaffected — 4/10, all queries.
                assert!((blocked_pct - 40.0).abs() < 1e-9, "got {blocked_pct}");
            }
            other => panic!("expected TrackingStats, got {other:?}"),
        }
    }

    /// Build a coalescer whose worker is alive, plus the receiver that
    /// keeps it that way. Dropping the receiver is the only route out of
    /// the worker's loop, so the caller decides which case it wants.
    fn coalescer_with_worker(
        window: std::time::Duration,
    ) -> (
        Arc<crate::ipc::ReloadCoalescer>,
        tokio::sync::mpsc::Receiver<Option<u32>>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::channel::<Option<u32>>(1);
        let coalescer = Arc::new(crate::ipc::ReloadCoalescer::with_window(tx, window));
        let _worker = coalescer.clone().spawn_worker();
        (coalescer, rx)
    }

    /// The production path — a coalescer is wired — must be able to
    /// report failure. It could not: `request` returned a bare count, so
    /// `IpcError::ReloadChannelClosed` was structurally unreachable and
    /// every write verb ending in a reload printed success against a
    /// daemon that would never apply it.
    #[tokio::test]
    async fn reload_reports_failure_once_the_coalescer_worker_is_gone() {
        let window = std::time::Duration::from_millis(20);
        let (coalescer, rx) = coalescer_with_worker(window);
        let mut state = test_state();
        state.reload_coalescer = Some(coalescer.clone());

        // Kill the worker: drop the receiver, then let one request drive
        // it through a failing send.
        drop(rx);
        assert!(matches!(
            handle_reload(None, &state).await,
            IpcResponse::Ok { .. }
        ));
        tokio::time::sleep(window * 5).await;

        match handle_reload(None, &state).await {
            IpcResponse::Error { message } => assert_eq!(
                message,
                crate::ipc::errors::IPC_ERROR_RELOAD_CHANNEL_CLOSED,
                "the refusal must reach the operator as the existing \
                 reload-channel error, not a new string"
            ),
            other => panic!("expected Error once the worker is gone, got {other:?}"),
        }
    }

    /// Positive control for the test above. A `request` wired to refuse
    /// unconditionally would satisfy it; this pins that a live worker
    /// still queues.
    #[tokio::test]
    async fn reload_still_queues_while_the_coalescer_worker_lives() {
        let window = std::time::Duration::from_millis(20);
        let (coalescer, _rx) = coalescer_with_worker(window);
        let mut state = test_state();
        state.reload_coalescer = Some(coalescer);

        match handle_reload(None, &state).await {
            IpcResponse::Ok { message } => {
                assert!(
                    message.contains("reload queued"),
                    "expected the queued message, got: {message}"
                );
            }
            other => panic!("expected Ok from a live coalescer, got {other:?}"),
        }
    }

    /// Mutating command (Reload) without any token configured on the
    /// daemon is refused with the "run `warden token generate`" message.
    #[tokio::test]
    async fn mutating_rejected_when_no_token_configured() {
        let state = Arc::new(test_state()); // api_token_hash = None
        let resp = dispatch_command(IpcCommand::Reload { token: None }, None, &state).await;
        match resp {
            IpcResponse::Error { message } => {
                assert!(
                    message.contains("warden token generate"),
                    "error should point the user at the exact fix command, got: {message}"
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    /// Admin command (Shutdown) without any token configured is refused.
    /// This is the critical case — we must not silently shut the daemon
    /// down in an unauth state.
    #[tokio::test]
    async fn admin_rejected_when_no_token_configured() {
        let state = Arc::new(test_state());
        let resp = dispatch_command(IpcCommand::Shutdown { token: None }, None, &state).await;
        assert!(matches!(resp, IpcResponse::Error { .. }));
    }

    /// Daemon has a token configured, but the client didn't attach one.
    /// The CLI would normally auto-attach; this path catches raw socket
    /// writers or stale clients.
    #[tokio::test]
    async fn mutating_rejected_when_token_missing_but_configured() {
        let state = Arc::new(test_state_with_token("ps_correctvalue"));
        let resp = dispatch_command(IpcCommand::Reload { token: None }, None, &state).await;
        match resp {
            IpcResponse::Error { message } => {
                assert!(
                    message.contains("warden") && message.contains("auto-discover"),
                    "expected plain-English 'use warden CLI' message, got: {message}"
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    /// Daemon has a token configured; client attaches the wrong token.
    /// Rejection message must point the user at `warden token regenerate`.
    #[tokio::test]
    async fn mutating_rejected_when_token_wrong() {
        let state = Arc::new(test_state_with_token("ps_correctvalue"));
        let resp = dispatch_command(
            IpcCommand::Reload {
                token: Some("ps_wrongvalue".into()),
            },
            None,
            &state,
        )
        .await;
        match resp {
            IpcResponse::Error { message } => {
                assert!(
                    message.contains("warden token regenerate"),
                    "expected regenerate hint, got: {message}"
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    /// Daemon has a token configured; client attaches the correct token.
    /// The command is authorized and dispatched. We can't check actual
    /// reload behavior here (reload_tx is None in test_state), so we
    /// confirm the response is NOT an auth error.
    #[tokio::test]
    async fn mutating_accepted_when_token_correct() {
        let state = Arc::new(test_state_with_token("ps_correctvalue"));
        let resp = dispatch_command(
            IpcCommand::Reload {
                token: Some("ps_correctvalue".into()),
            },
            None,
            &state,
        )
        .await;
        // handle_reload returns Error{message: "reload not available"}
        // when reload_tx is None — confirm the failure is about reload,
        // not about auth.
        match resp {
            IpcResponse::Error { message } => {
                assert!(
                    !message.contains("token"),
                    "auth error leaked through to dispatch, got: {message}"
                );
                assert!(
                    message.contains("reload") || message.contains("channel"),
                    "expected reload/channel error, got: {message}"
                );
            }
            IpcResponse::Ok { .. } => {} // acceptable too
            other => panic!("unexpected response: {other:?}"),
        }
    }

    /// Admin command with the correct token is authorized. QueryLogs
    /// fails early on missing stats engine, but the failure must not be
    /// an auth failure.
    #[tokio::test]
    async fn admin_accepted_when_token_correct() {
        let state = Arc::new(test_state_with_token("ps_correctvalue"));
        let resp = dispatch_command(
            IpcCommand::QueryLogs {
                limit: 10,
                client: None,
                blocked_only: false,
                domain: None,
                since_secs: None,
                cursor: None,
                advanced: None,
                token: Some("ps_correctvalue".into()),
            },
            None,
            &state,
        )
        .await;
        match resp {
            IpcResponse::Error { message } => {
                assert!(
                    !message.contains("token") && !message.contains("admin token"),
                    "auth error leaked through to dispatch, got: {message}"
                );
            }
            IpcResponse::QueryLogs { .. } => {}
            other => panic!("unexpected response: {other:?}"),
        }
    }

    // --- Sprint 22: GetAllDevices ---

    /// GetAllDevices is ReadOnly — no token required even when one is
    /// configured. Footgun escape path depends on this: the operator
    /// who just locked themselves out must be able to see the view
    /// without reading a token file.
    #[test]
    fn get_all_clients_is_readonly() {
        use super::super::protocol::CommandTier;
        assert_eq!(IpcCommand::GetAllDevices.tier(), CommandTier::ReadOnly);
    }

    /// Missing profile resolver is a config/wiring bug, not "no clients
    /// yet" — the handler returns an explicit Error so the TUI renders a
    /// banner instead of silently showing zeros.
    #[tokio::test]
    async fn get_all_clients_errors_when_no_profile_resolver() {
        let state = Arc::new(test_state()); // profiles: None
        let resp = dispatch_command(IpcCommand::GetAllDevices, None, &state).await;
        match resp {
            IpcResponse::Error { message } => {
                assert!(
                    message.contains("profile resolver"),
                    "error should name the missing component, got: {message}"
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    /// When ProfileResolver is present but empty and no client has ever
    /// been observed, the view is legitimately empty (not an error).
    #[tokio::test]
    async fn get_all_clients_empty_view_on_zero_clients() {
        use crate::config::schema::ConfigV1;
        use crate::profiles::ProfileResolver;

        let mut config = ConfigV1::test_scaffold();
        config.schema_version = 3;
        let bit_map = crate::lists::source_key::SourceBitMap::default();
        let profiles = Arc::new(ProfileResolver::build(
            &config,
            &bit_map,
            &crate::config::custom_list::CustomListStore::new(),
        ));

        let cache_config = crate::config::settings::CacheConfig::default();
        let state = Arc::new(DaemonState {
            filter: Arc::new(FilterEngine::new()),
            cache: DnsCache::new(&cache_config),
            profiles: Some(profiles),
            stats: None,
            listen_addr: "127.0.0.1:15353".into(),
            upstream_mode: "plain".into(),
            upstream_count: 2,
            list_count: 0,
            started_at: Instant::now(),
            shutdown_tx: None,
            reload_tx: None,
            api_token_hash: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
            config_path: None,
            config_write_lock: Arc::new(tokio::sync::Mutex::new(())),
            list_statuses: None,
            list_state: None,
            local_records_hits: None,
            log_ring: None,
            notification_tx: None,
            reload_coalescer: None,
            oui_table: None,
            list_labels: Arc::new(vec![None; 64]),
            list_cmd_tx: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
            daemon_uid: current_euid(),
            resource_budget_store: crate::resource_budget::types::new_store(),
            #[cfg(feature = "cluster")]
            cluster_observe: None,
        });

        let resp = dispatch_command(IpcCommand::GetAllDevices, None, &state).await;
        match resp {
            IpcResponse::DeviceView(view) => {
                assert!(view.mapped.is_empty());
                assert!(view.unmapped.is_empty());
            }
            other => panic!("expected DeviceView, got {other:?}"),
        }
    }

    /// With a profile resolver containing a mapped device and a stats
    /// engine that observed both that mapped device and an unknown IP,
    /// the response must split them correctly and carry the metadata
    /// from v1 `[[devices]]`.
    #[tokio::test]
    async fn get_all_clients_splits_mapped_and_unmapped() {
        use crate::config::schema::{ConfigV1, Device, Id, Profile};
        use crate::config::settings::TrackingConfig;
        use crate::profiles::ProfileResolver;
        use crate::tracking::StatsEngine;
        use std::net::{IpAddr, Ipv4Addr};

        let mut config = ConfigV1::test_scaffold();
        config.schema_version = 3;
        config.profiles.insert(
            "default".into(),
            Profile {
                display_name: "Default".into(),
                ..Default::default()
            },
        );
        config.devices.push(Device {
            id: Id::new("alex-laptop").unwrap(),
            display_name: "alex-laptop".into(),
            ip: Some("192.168.1.42".parse().unwrap()),
            mac: None,
            mac_aliases: vec![],
            profile: Some(Id::new("default").unwrap()),
            groups: vec![],
            owner: Some("Alex".into()),
            device_type: Some("ThinkPad T14".into()),
            department: Some("home".into()),
            notes: None,
            allow_rules: vec![],
            deny_rules: vec![],
            override_profile_deny: false,
            unfiltered: false,
            network_name: None,
            network_name_wildcard: false,
        });

        let bit_map = crate::lists::source_key::SourceBitMap::default();
        let profiles = Arc::new(ProfileResolver::build(
            &config,
            &bit_map,
            &crate::config::custom_list::CustomListStore::new(),
        ));

        let stats = Arc::new(StatsEngine::new(&TrackingConfig::default()));
        let mapped_ip: IpAddr = Ipv4Addr::new(192, 168, 1, 42).into();
        let unmapped_ip: IpAddr = Ipv4Addr::new(10, 0, 0, 99).into();
        stats.record_query(
            mapped_ip,
            "good.com",
            Some("alex-laptop"),
            Some("default"),
            hickory_proto::rr::RecordType::A,
            false,
            false,
            None,
        );
        stats.record_query(
            mapped_ip,
            "ads.example",
            None,
            None,
            hickory_proto::rr::RecordType::A,
            true,
            false,
            None,
        );
        stats.record_query(
            unmapped_ip,
            "random.example",
            None,
            None,
            hickory_proto::rr::RecordType::A,
            false,
            false,
            None,
        );

        let cache_config = crate::config::settings::CacheConfig::default();
        let state = Arc::new(DaemonState {
            filter: Arc::new(FilterEngine::new()),
            cache: DnsCache::new(&cache_config),
            profiles: Some(profiles),
            stats: Some(stats),
            listen_addr: "127.0.0.1:15353".into(),
            upstream_mode: "plain".into(),
            upstream_count: 2,
            list_count: 0,
            started_at: Instant::now(),
            shutdown_tx: None,
            reload_tx: None,
            api_token_hash: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
            config_path: None,
            config_write_lock: Arc::new(tokio::sync::Mutex::new(())),
            list_statuses: None,
            list_state: None,
            local_records_hits: None,
            log_ring: None,
            notification_tx: None,
            reload_coalescer: None,
            oui_table: None,
            list_labels: Arc::new(vec![None; 64]),
            list_cmd_tx: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
            daemon_uid: current_euid(),
            resource_budget_store: crate::resource_budget::types::new_store(),
            #[cfg(feature = "cluster")]
            cluster_observe: None,
        });

        let resp = dispatch_command(IpcCommand::GetAllDevices, None, &state).await;
        match resp {
            IpcResponse::DeviceView(view) => {
                assert_eq!(view.mapped.len(), 1);
                let m = &view.mapped[0];
                assert_eq!(m.name, "alex-laptop");
                assert_eq!(m.ip, "192.168.1.42");
                assert_eq!(m.owner.as_deref(), Some("Alex"));
                assert_eq!(m.device_type.as_deref(), Some("ThinkPad T14"));
                assert_eq!(m.department.as_deref(), Some("home"));
                assert_eq!(m.queries, 2);
                assert_eq!(m.blocked, 1);
                assert!(m.online);

                assert_eq!(view.unmapped.len(), 1);
                let u = &view.unmapped[0];
                assert_eq!(u.ip, "10.0.0.99");
                assert_eq!(u.queries, 1);
                assert!(u.online);
            }
            other => panic!("expected DeviceView, got {other:?}"),
        }
    }

    // ── s23-ipc-client-mutations: DeviceAdd handler tests ──────────

    /// Build a DaemonState wired to a temp config file + auth token,
    /// suitable for exercising client mutation handlers end-to-end
    /// (including the validator + atomic write path).
    fn test_state_with_config_path(
        token_plaintext: &str,
        config_path: PathBuf,
    ) -> (DaemonState, tokio::sync::mpsc::Receiver<Option<u32>>) {
        use crate::auth::token::hash_token;
        use crate::dns::cache::DnsCache;

        let cache_config = crate::config::settings::CacheConfig::default();
        let (reload_tx, reload_rx) = tokio::sync::mpsc::channel::<Option<u32>>(1);
        let state = DaemonState {
            filter: Arc::new(FilterEngine::new()),
            cache: DnsCache::new(&cache_config),
            profiles: None,
            stats: None,
            listen_addr: "127.0.0.1:15353".into(),
            upstream_mode: "plain".into(),
            upstream_count: 2,
            list_count: 0,
            started_at: Instant::now(),
            shutdown_tx: None,
            reload_tx: Some(reload_tx),
            api_token_hash: Arc::new(arc_swap::ArcSwap::from_pointee(Some(hash_token(
                token_plaintext,
            )))),
            config_path: Some(config_path),
            config_write_lock: Arc::new(tokio::sync::Mutex::new(())),
            list_statuses: None,
            list_state: None,
            local_records_hits: None,
            log_ring: None,
            notification_tx: None,
            reload_coalescer: None,
            oui_table: None,
            list_labels: Arc::new(vec![None; 64]),
            list_cmd_tx: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
            daemon_uid: current_euid(),
            resource_budget_store: crate::resource_budget::types::new_store(),
            #[cfg(feature = "cluster")]
            cluster_observe: None,
        };
        (state, reload_rx)
    }

    /// Returns a `(TempDir, PathBuf)` pair so the tempdir's Drop cleans
    /// up automatically when the caller's binding (typically `_dir`)
    /// goes out of scope. Avoids the previous `/tmp/purge-warden-test-…`
    /// fixtures that two parallel tests with the same suffix could
    /// collide on.
    fn client_mutation_temp_config(content: &str, suffix: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(format!("config-{suffix}.toml"));
        std::fs::write(&path, content).unwrap();
        (dir, path)
    }

    /// §4.27-A: load the v1 config and return its devices for
    /// post-mutation assertions. Replaces the pre-migration
    /// `Settings::from_file(&path).clients` verification — the IPC
    /// device handlers are now v1-native and write `[[devices]]`.
    fn load_devices(path: &std::path::Path) -> Vec<crate::config::schema::Device> {
        crate::config::loader::load_config(path, time::OffsetDateTime::now_utc())
            .expect("v1 config must load")
            .config
            .devices
    }

    #[tokio::test]
    async fn client_add_happy_path_writes_and_reloads() {
        let initial = r#"
schema_version = 3

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#;
        let (_dir, path) = client_mutation_temp_config(initial, "happy");
        let (state, mut reload_rx) = test_state_with_config_path("tok-happy", path.clone());
        let state = Arc::new(state);

        let client = crate::config::settings::ClientConfig {
            name: "alex-laptop".into(),
            ip: "192.168.1.42".parse().unwrap(),
            mac: None,
            mac_aliases: Vec::new(),
            profile: "default".into(),
            owner: Some("Alex".into()),
            device_type: Some("ThinkPad".into()),
            department: None,
            group: None,
            notes: None,
        };
        let cmd = IpcCommand::DeviceAdd {
            client,
            token: Some("tok-happy".into()),
        };

        let resp = dispatch_command(cmd, None, &state).await;
        match &resp {
            IpcResponse::Ok { message } => {
                assert!(message.contains("alex-laptop"), "got {message}");
            }
            other => panic!("expected Ok, got {other:?}"),
        }

        // Verify the file was actually rewritten with the v1 device.
        let devices = load_devices(&path);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].id.as_str(), "alex-laptop");
        assert_eq!(devices[0].owner.as_deref(), Some("Alex"));

        // Verify the reload signal fired (drains the channel).
        assert!(reload_rx.try_recv().is_ok(), "reload signal must be sent");
    }

    #[tokio::test]
    async fn client_add_rejects_duplicate_name_with_named_error() {
        let initial = r#"
schema_version = 3

[profiles.default]
display_name = "Default"

[[devices]]
id = "laptop"
display_name = "laptop"
ip = "192.168.1.42"
profile = "default"

[upstream]
servers = ["192.0.2.1:53"]
"#;
        let (_dir, path) = client_mutation_temp_config(initial, "dup-name");
        let (state, _rx) = test_state_with_config_path("tok-dup-name", path.clone());
        let state = Arc::new(state);

        let dup = crate::config::settings::ClientConfig {
            name: "laptop".into(),
            ip: "192.168.1.99".parse().unwrap(),
            mac: None,
            mac_aliases: Vec::new(),
            profile: "default".into(),
            owner: None,
            device_type: None,
            department: None,
            group: None,
            notes: None,
        };
        let cmd = IpcCommand::DeviceAdd {
            client: dup,
            token: Some("tok-dup-name".into()),
        };

        let resp = dispatch_command(cmd, None, &state).await;
        match resp {
            IpcResponse::Error { message } => {
                assert!(
                    message.contains("\"laptop\""),
                    "error must name the offending client: {message}"
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }

        // File must NOT have been mutated.
        let devices = load_devices(&path);
        assert_eq!(devices.len(), 1, "duplicate add must not append");
    }

    #[tokio::test]
    async fn client_add_rejects_duplicate_ip_with_named_error() {
        let initial = r#"
schema_version = 3

[profiles.default]
display_name = "Default"

[[devices]]
id = "laptop"
display_name = "laptop"
ip = "192.168.1.42"
profile = "default"

[upstream]
servers = ["192.0.2.1:53"]
"#;
        let (_dir, path) = client_mutation_temp_config(initial, "dup-ip");
        let (state, _rx) = test_state_with_config_path("tok-dup-ip", path.clone());
        let state = Arc::new(state);

        let dup = crate::config::settings::ClientConfig {
            name: "phone".into(),
            ip: "192.168.1.42".parse().unwrap(), // same IP
            mac: None,
            mac_aliases: Vec::new(),
            profile: "default".into(),
            owner: None,
            device_type: None,
            department: None,
            group: None,
            notes: None,
        };
        let cmd = IpcCommand::DeviceAdd {
            client: dup,
            token: Some("tok-dup-ip".into()),
        };

        let resp = dispatch_command(cmd, None, &state).await;
        match resp {
            IpcResponse::Error { message } => {
                assert!(
                    message.contains("192.168.1.42"),
                    "error must name the offending IP: {message}"
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn client_add_requires_admin_token() {
        let (_dir, path) = client_mutation_temp_config(
            "schema_version = 3\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
            "auth",
        );
        let (state, _rx) = test_state_with_config_path("tok-auth", path.clone());
        let state = Arc::new(state);

        let client = crate::config::settings::ClientConfig {
            name: "x".into(),
            ip: "192.168.1.42".parse().unwrap(),
            mac: None,
            mac_aliases: Vec::new(),
            profile: "default".into(),
            owner: None,
            device_type: None,
            department: None,
            group: None,
            notes: None,
        };
        // No token attached — admin gate must reject.
        let cmd = IpcCommand::DeviceAdd {
            client,
            token: None,
        };
        let resp = dispatch_command(cmd, None, &state).await;
        match resp {
            IpcResponse::Error { message } => {
                assert!(
                    message.contains("admin token") || message.contains("token"),
                    "auth error must mention token: {message}"
                );
            }
            other => panic!("expected auth Error, got {other:?}"),
        }

        // Verify file was NOT mutated by an unauthenticated request.
        assert!(
            load_devices(&path).is_empty(),
            "unauthenticated add must not write"
        );
    }

    #[tokio::test]
    async fn client_add_validator_catches_unknown_profile() {
        let (_dir, path) = client_mutation_temp_config(
            "schema_version = 3\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
            "validator",
        );
        let (state, _rx) = test_state_with_config_path("tok-val", path.clone());
        let state = Arc::new(state);

        let client = crate::config::settings::ClientConfig {
            name: "tablet".into(),
            ip: "10.0.0.50".parse().unwrap(),
            mac: None,
            mac_aliases: Vec::new(),
            profile: "ghost-profile".into(), // not configured
            owner: None,
            device_type: None,
            department: None,
            group: None,
            notes: None,
        };
        let cmd = IpcCommand::DeviceAdd {
            client,
            token: Some("tok-val".into()),
        };
        let resp = dispatch_command(cmd, None, &state).await;
        match resp {
            IpcResponse::Error { message } => {
                assert!(
                    message.contains("ghost-profile") || message.contains("validation"),
                    "validator error must surface the unknown profile: {message}"
                );
            }
            other => panic!("expected validation Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn client_add_concurrent_calls_serialize_through_write_lock() {
        // Two concurrent DeviceAdds must both succeed and both rows
        // must end up on disk — without the write lock the second
        // would overwrite the first's append.
        let (_dir, path) = client_mutation_temp_config(
            "schema_version = 3\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
            "concurrent",
        );
        let (state, _rx) = test_state_with_config_path("tok-conc", path.clone());
        let state = Arc::new(state);

        let mk_client = |name: &str, ip: &str| crate::config::settings::ClientConfig {
            name: name.into(),
            ip: ip.parse().unwrap(),
            mac: None,
            mac_aliases: Vec::new(),
            profile: "default".into(),
            owner: None,
            device_type: None,
            department: None,
            group: None,
            notes: None,
        };

        let s1 = state.clone();
        let s2 = state.clone();
        let c1 = mk_client("one", "192.168.1.1");
        let c2 = mk_client("two", "192.168.1.2");

        let h1 = tokio::spawn(async move {
            dispatch_command(
                IpcCommand::DeviceAdd {
                    client: c1,
                    token: Some("tok-conc".into()),
                },
                None,
                &s1,
            )
            .await
        });
        let h2 = tokio::spawn(async move {
            dispatch_command(
                IpcCommand::DeviceAdd {
                    client: c2,
                    token: Some("tok-conc".into()),
                },
                None,
                &s2,
            )
            .await
        });

        let r1 = h1.await.unwrap();
        let r2 = h2.await.unwrap();
        assert!(matches!(r1, IpcResponse::Ok { .. }));
        assert!(matches!(r2, IpcResponse::Ok { .. }));

        // Both must be on disk — no clobbering.
        let devices = load_devices(&path);
        assert_eq!(
            devices.len(),
            2,
            "both concurrent adds must persist (write lock works)"
        );
        let ids: Vec<&str> = devices.iter().map(|d| d.id.as_str()).collect();
        assert!(ids.contains(&"one"));
        assert!(ids.contains(&"two"));
    }

    // ── s23-ipc-client-mutations: DeviceUpdate handler tests ──────

    #[tokio::test]
    async fn client_update_partial_patch_only_touches_provided_fields() {
        let initial = r#"
schema_version = 3

[profiles.default]
display_name = "Default"

[[devices]]
id = "alex-laptop"
display_name = "alex-laptop"
ip = "192.168.1.42"
mac = "AA:BB:CC:DD:EE:FF"
profile = "default"
owner = "Alex"
device_type = "ThinkPad"
department = "home"
tags = ["trusted"]

[upstream]
servers = ["192.0.2.1:53"]
"#;
        let (_dir, path) = client_mutation_temp_config(initial, "update-partial");
        let (state, mut reload_rx) = test_state_with_config_path("tok-up", path.clone());
        let state = Arc::new(state);

        // Patch only `owner` and leave everything else alone.
        let patch = super::super::protocol::DevicePatch {
            owner: Some(Some("Sam".into())),
            ..Default::default()
        };
        let cmd = IpcCommand::DeviceUpdate {
            name: "alex-laptop".into(),
            patch,
            token: Some("tok-up".into()),
        };
        let resp = dispatch_command(cmd, None, &state).await;
        assert!(matches!(resp, IpcResponse::Ok { .. }), "got {resp:?}");

        let devices = load_devices(&path);
        let d = &devices[0];
        assert_eq!(d.id.as_str(), "alex-laptop", "id unchanged");
        assert_eq!(
            d.ip.map(|ip| ip.to_string()).as_deref(),
            Some("192.168.1.42"),
            "ip unchanged"
        );
        assert_eq!(d.mac.as_deref(), Some("AA:BB:CC:DD:EE:FF"), "mac unchanged");
        assert_eq!(
            d.profile.as_ref().map(|p| p.as_str()),
            Some("default"),
            "profile unchanged"
        );
        assert_eq!(d.owner.as_deref(), Some("Sam"), "owner patched");
        assert_eq!(
            d.device_type.as_deref(),
            Some("ThinkPad"),
            "device unchanged"
        );
        assert!(reload_rx.try_recv().is_ok());
    }

    // ── device-network-name (2026-08-10 design spec), Task 9: DevicePatch
    // write side ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn device_update_sets_network_name() {
        let initial = r#"
schema_version = 3

[profiles.default]
display_name = "Default"

[[devices]]
id = "alex-laptop"
display_name = "alex-laptop"
ip = "192.168.1.42"
profile = "default"

[upstream]
servers = ["192.0.2.1:53"]
"#;
        let (_dir, path) = client_mutation_temp_config(initial, "update-netname-set");
        let (state, _reload_rx) = test_state_with_config_path("tok-up", path.clone());
        let state = Arc::new(state);

        let patch = super::super::protocol::DevicePatch {
            network_name: Some(Some("desktop-1".into())),
            ..Default::default()
        };
        let cmd = IpcCommand::DeviceUpdate {
            name: "alex-laptop".into(),
            patch,
            token: Some("tok-up".into()),
        };
        let resp = dispatch_command(cmd, None, &state).await;
        assert!(matches!(resp, IpcResponse::Ok { .. }), "got {resp:?}");

        let row = raw_device(&path, "alex-laptop");
        assert_eq!(
            row.get("network_name").and_then(|v| v.as_str()),
            Some("desktop-1")
        );
    }

    #[tokio::test]
    async fn device_update_clears_network_name_on_some_none() {
        let initial = r#"
schema_version = 3

[profiles.default]
display_name = "Default"

[[devices]]
id = "alex-laptop"
display_name = "alex-laptop"
ip = "192.168.1.42"
profile = "default"
network_name = "desktop-1"

[upstream]
servers = ["192.0.2.1:53"]
"#;
        let (_dir, path) = client_mutation_temp_config(initial, "update-netname-clear");
        let (state, _reload_rx) = test_state_with_config_path("tok-up", path.clone());
        let state = Arc::new(state);

        let patch = super::super::protocol::DevicePatch {
            network_name: Some(None),
            ..Default::default()
        };
        let cmd = IpcCommand::DeviceUpdate {
            name: "alex-laptop".into(),
            patch,
            token: Some("tok-up".into()),
        };
        let resp = dispatch_command(cmd, None, &state).await;
        assert!(matches!(resp, IpcResponse::Ok { .. }), "got {resp:?}");

        let row = raw_device(&path, "alex-laptop");
        assert!(row.get("network_name").is_none());
    }

    /// **DoD 3 of `plp-s5e`.** `DevicePatch` has no `tags` field any more.
    ///
    /// This replaces `device_update_refuses_a_tag_change_but_not_a_tag_echo`,
    /// whose two arms both built a `DevicePatch { tags: … }` and cannot
    /// compile now. Arm 2's property is the one that survives — a rename must
    /// not be blocked by a tag field riding along — and a pre-S5 client is
    /// exactly what exercises it today, so that is what is asserted here.
    ///
    /// **Arm 1's guarantee CHANGED SHAPE rather than exiting.** A tag *change*
    /// used to be refused loudly (`TAGS_RETIRED`, `ValidatorRejected`). There
    /// is no field left to change and `DevicePatch` carries no
    /// `#[serde(deny_unknown_fields)]`, so serde would drop the key in silence
    /// — the operator's rename landing while their tag vanished with no
    /// diagnostic, which is precisely how the tag model died in the first
    /// place. `retired_tags` captures the key so the daemon can WARN instead,
    /// and this test pins BOTH halves: the other fields land, and the retired
    /// key is observed rather than swallowed.
    ///
    /// Strip-and-report, not refuse — the `ip_denylists` precedent in
    /// `normalise_deprecated_keys`. Refusing would cost the operator a
    /// legitimate rename to punish a key they did not know was dead.
    #[tokio::test]
    async fn a_pre_s5_payload_still_carrying_tags_applies_its_other_fields() {
        let initial = r#"
schema_version = 3

[profiles.default]
display_name = "Default"

[[devices]]
id = "alex-laptop"
display_name = "alex-laptop"
ip = "192.168.1.42"
profile = "default"
tags = ["work"]

[upstream]
servers = ["192.0.2.1:53"]
"#;
        let (_dir, path) = client_mutation_temp_config(initial, "pre-s5-tags");
        let (state, _reload_rx) = test_state_with_config_path("tok-t", path.clone());
        let state = Arc::new(state);

        // The payload a pre-S5 CLI/TUI still puts on the wire. Built from raw
        // JSON on purpose: the whole point is that `tags` is a key the struct
        // no longer has, so it cannot be expressed as a struct literal.
        let patch: super::super::protocol::DevicePatch =
            serde_json::from_str(r#"{"tags":["kids"],"new_name":"sam-thinkpad","owner":"Sam"}"#)
                .expect("a pre-S5 payload carrying `tags` must still deserialize");

        // The retired key is CAPTURED, not dropped. Without this the daemon
        // cannot tell a pre-S5 client from a current one and the WARN never
        // fires. Deleting `rename = "tags"` from the field turns this red
        // while every other assertion below stays green — which is the point:
        // those assertions pass just as well when the key is silently lost.
        assert_eq!(
            patch.retired_tags.as_deref(),
            Some(&["kids".to_string()][..]),
            "a retired `tags` key must be observed so it can be reported"
        );

        let resp = dispatch_command(
            IpcCommand::DeviceUpdate {
                name: "alex-laptop".into(),
                patch,
                token: Some("tok-t".into()),
            },
            None,
            &state,
        )
        .await;
        assert!(
            matches!(resp, IpcResponse::Ok { .. }),
            "a retired key must not cost the operator the rest of the patch, got {resp:?}"
        );

        // Load-bearing: BOTH live fields landed. Mutate the `new_name` or the
        // `owner` arm of `apply_device_patch` and this goes red — which is
        // what separates it from a test that only proves serde didn't panic.
        let row = raw_device(&path, "alex-laptop");
        assert_eq!(
            row.get("display_name").and_then(|v| v.as_str()),
            Some("sam-thinkpad"),
            "the rename must land"
        );
        assert_eq!(
            row.get("owner").and_then(|v| v.as_str()),
            Some("Sam"),
            "the scalar edit must land"
        );
        // Weaker by construction — no code path can write `tags` any more — but
        // it is the statement that the ignored key did not leak to disk.
        assert_eq!(
            row.get("tags")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>()),
            Some(vec!["work"]),
            "the retired key must not be written through"
        );
    }

    #[tokio::test]
    async fn device_update_leaves_network_name_alone_when_patch_field_is_none() {
        let initial = r#"
schema_version = 3

[profiles.default]
display_name = "Default"

[[devices]]
id = "alex-laptop"
display_name = "alex-laptop"
ip = "192.168.1.42"
profile = "default"
network_name = "desktop-1"

[upstream]
servers = ["192.0.2.1:53"]
"#;
        let (_dir, path) = client_mutation_temp_config(initial, "update-netname-untouched");
        let (state, _reload_rx) = test_state_with_config_path("tok-up", path.clone());
        let state = Arc::new(state);

        // network_name omitted from the patch entirely (outer None).
        let patch = super::super::protocol::DevicePatch {
            owner: Some(Some("Sam".into())),
            ..Default::default()
        };
        let cmd = IpcCommand::DeviceUpdate {
            name: "alex-laptop".into(),
            patch,
            token: Some("tok-up".into()),
        };
        let resp = dispatch_command(cmd, None, &state).await;
        assert!(matches!(resp, IpcResponse::Ok { .. }), "got {resp:?}");

        let row = raw_device(&path, "alex-laptop");
        assert_eq!(
            row.get("network_name").and_then(|v| v.as_str()),
            Some("desktop-1"),
            "network_name must survive an unrelated patch"
        );
    }

    /// Clearing `network_name` while the patch also (re)asserts
    /// `network_name_wildcard = true` collides with the validator's
    /// wildcard-without-name mutex (`0edbd49d`) — the wildcard flag is a
    /// plain bool on `DevicePatch` (no "clear" state), so a form that
    /// always resends its current buffer value, as Task 10's
    /// `edit_patch_from` does, ends up asking for a name-less wildcard.
    /// This documents the resulting behavior at the IPC layer rather
    /// than papering over it: the staged write is validator-refused and
    /// the on-disk row is untouched (not partially written).
    #[tokio::test]
    async fn device_update_clear_name_with_wildcard_still_set_is_validator_refused() {
        let initial = r#"
schema_version = 3

[profiles.default]
display_name = "Default"

[[devices]]
id = "alex-laptop"
display_name = "alex-laptop"
ip = "192.168.1.42"
profile = "default"
network_name = "desktop-1"
network_name_wildcard = true

[upstream]
servers = ["192.0.2.1:53"]
"#;
        let (_dir, path) = client_mutation_temp_config(initial, "update-netname-wildcard-mutex");
        let (state, _reload_rx) = test_state_with_config_path("tok-up", path.clone());
        let state = Arc::new(state);

        let patch = super::super::protocol::DevicePatch {
            network_name: Some(None),
            network_name_wildcard: Some(true),
            ..Default::default()
        };
        let cmd = IpcCommand::DeviceUpdate {
            name: "alex-laptop".into(),
            patch,
            token: Some("tok-up".into()),
        };
        let resp = dispatch_command(cmd, None, &state).await;
        assert!(
            matches!(resp, IpcResponse::Error { .. }),
            "expected validator refusal, got {resp:?}"
        );

        let row = raw_device(&path, "alex-laptop");
        assert_eq!(
            row.get("network_name").and_then(|v| v.as_str()),
            Some("desktop-1"),
            "refused write must leave the file untouched"
        );
        assert_eq!(
            row.get("network_name_wildcard").and_then(|v| v.as_bool()),
            Some(true),
            "refused write must leave the file untouched"
        );
    }

    /// Read one `[[devices]]` row straight out of the **file**.
    ///
    /// Not `load_devices`: a struct-level read passes on a file that lost
    /// a key and got it back from a `serde` default — the exact shape of
    /// the `accept_unsigned_allow` scar. §4.64 G2 made the same call for
    /// `[[groups]]` (`raw_group` in `tui/mod.rs`).
    fn raw_device(config_path: &std::path::Path, id: &str) -> toml::value::Table {
        let text = std::fs::read_to_string(config_path).unwrap();
        let doc: toml::Value = toml::from_str(&text).unwrap();
        doc.get("devices")
            .and_then(|v| v.as_array())
            .expect("[[devices]] array must exist in the file")
            .iter()
            .find(|item| item.get("id").and_then(|v| v.as_str()) == Some(id))
            .unwrap_or_else(|| panic!("device {id} not in the file"))
            .as_table()
            .unwrap()
            .clone()
    }

    /// A `MappedDeviceDto` shaped like the one `handle_get_all_devices`
    /// serves for the fixture below — the value the TUI's Edit modal is
    /// actually seeded from.
    fn two_group_dto() -> super::super::protocol::MappedDeviceDto {
        super::super::protocol::MappedDeviceDto {
            ip: "192.168.1.42".into(),
            name: "alex-laptop".into(),
            mac: Some("AA:BB:CC:DD:EE:FF".into()),
            mac_aliases: Vec::new(),
            profile: "default".into(),
            owner: None,
            device_type: None,
            department: None,
            queries: 0,
            queries_today: 0,
            blocked: 0,
            blocked_24h: 0,
            cache_hits: 0,
            last_seen: 0,
            online: false,
            vendor: None,
            groups: vec!["phones".into(), "kids".into()],
            notes: None,
            network_name: None,
            network_name_wildcard: false,
            id: Some("alex-laptop".into()),
            hourly_queries: Vec::new(),
            unfiltered: false,
        }
    }

    const TWO_GROUP_CONFIG: &str = r#"
schema_version = 3

[profiles.default]
display_name = "Default"

[[groups]]
id = "phones"
display_name = "Phones"
profile = "default"
priority = 7

[[groups]]
id = "kids"
display_name = "Kids"
profile = "default"
priority = 3

[[devices]]
id = "alex-laptop"
display_name = "alex-laptop"
ip = "192.168.1.42"
mac = "AA:BB:CC:DD:EE:FF"
profile = "default"
groups = ["phones", "kids"]
tags = ["trusted"]

[upstream]
servers = ["192.0.2.1:53"]
"#;

    /// **The §4.64 G4 gate.** A device in TWO groups, edited from the TUI
    /// in a way that touches only the name, must come out of the file
    /// still carrying BOTH memberships, in the file's own order.
    ///
    /// Drives the real chain and nothing hand-rolled: `edit_form_from`
    /// (the DTO → form seed the modal-open path uses) → typing in the
    /// name field → `device_update_patch` (the builder `submit_form`
    /// calls) → `dispatch_command` (the daemon's write). A rebuilt patch
    /// here would test the test, not the TUI.
    #[tokio::test]
    async fn tui_edit_of_a_two_group_device_keeps_both_memberships_in_the_file() {
        let (_dir, path) = client_mutation_temp_config(TWO_GROUP_CONFIG, "multigroup");
        let (state, mut reload_rx) = test_state_with_config_path("tok-mg", path.clone());
        let state = Arc::new(state);

        // Open the modal on the device, change the NAME and nothing
        // else, save.
        let mut form = crate::tui::edit_form_from(&two_group_dto());
        form.name = "sam-thinkpad".into();
        let patch = crate::tui::device_update_patch(&form).expect("form must parse");

        let cmd = IpcCommand::DeviceUpdate {
            name: "alex-laptop".into(),
            patch,
            token: Some("tok-mg".into()),
        };
        let resp = dispatch_command(cmd, None, &state).await;
        assert!(matches!(resp, IpcResponse::Ok { .. }), "got {resp:?}");

        let row = raw_device(&path, "alex-laptop");
        let groups: Vec<String> = row
            .get("groups")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().map(|v| v.as_str().unwrap().to_string()).collect())
            .unwrap_or_default();
        assert_eq!(
            groups,
            vec!["phones".to_string(), "kids".to_string()],
            "a rename must not reduce membership, and must not reorder it either \
             — the file said [phones, kids]"
        );
        assert_eq!(
            row.get("display_name").and_then(|v| v.as_str()),
            Some("sam-thinkpad"),
            "the one field the operator DID touch must have landed"
        );
        assert!(reload_rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn client_update_some_none_clears_nullable_field() {
        // Wire-level `Some(None)` distinguishes "explicitly clear" from
        // "leave alone" (which would be outer `None`). This is the
        // load-bearing reason DevicePatch uses Option<Option<T>>.
        let initial = r#"
schema_version = 3

[profiles.default]
display_name = "Default"

[[devices]]
id = "tablet"
display_name = "tablet"
ip = "192.168.1.50"
mac = "AA:BB:CC:DD:EE:01"
profile = "default"
owner = "Alex"

[upstream]
servers = ["192.0.2.1:53"]
"#;
        let (_dir, path) = client_mutation_temp_config(initial, "update-clear");
        let (state, _rx) = test_state_with_config_path("tok-clear", path.clone());
        let state = Arc::new(state);

        // Clear both mac and owner.
        let patch = super::super::protocol::DevicePatch {
            mac: Some(None),
            owner: Some(None),
            ..Default::default()
        };
        let cmd = IpcCommand::DeviceUpdate {
            name: "tablet".into(),
            patch,
            token: Some("tok-clear".into()),
        };
        let resp = dispatch_command(cmd, None, &state).await;
        assert!(matches!(resp, IpcResponse::Ok { .. }));

        let devices = load_devices(&path);
        let d = &devices[0];
        assert!(d.mac.is_none(), "mac must be cleared");
        assert!(d.owner.is_none(), "owner must be cleared");
    }

    #[tokio::test]
    async fn client_update_unknown_name_returns_friendly_error() {
        let (_dir, path) = client_mutation_temp_config(
            "schema_version = 3\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
            "update-unknown",
        );
        let (state, _rx) = test_state_with_config_path("tok-unk", path.clone());
        let state = Arc::new(state);

        let cmd = IpcCommand::DeviceUpdate {
            name: "ghost".into(),
            patch: super::super::protocol::DevicePatch::default(),
            token: Some("tok-unk".into()),
        };
        let resp = dispatch_command(cmd, None, &state).await;
        match resp {
            IpcResponse::Error { message } => {
                assert!(
                    message.contains("ghost"),
                    "error must name the missing client: {message}"
                );
                assert!(
                    message.contains("warden device list"),
                    "error must hint at how to discover existing names: {message}"
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn client_update_to_duplicate_ip_caught_by_validator() {
        // §4.27-A: the v1 IPC update path stages the patch onto the
        // entity file then runs `validate_or_revert`. A patch that
        // moves a device onto another device's IP produces a
        // duplicate-IP config — the validator rejects it and the
        // touched file is rolled back to its pre-edit content.
        //
        // (Pre-§4.27-A this test exercised rename-collision: the v0
        // update path mutated `name`, so renaming to an existing name
        // tripped the v0 validator's name-uniqueness check. The v1 IPC
        // update path only changes `display_name` — not unique-
        // constrained — so the rename-collision case no longer exists.
        // Duplicate-IP is the v1-relevant validate-or-revert case in
        // its place.)
        let initial = r#"
schema_version = 3

[profiles.default]
display_name = "Default"

[[devices]]
id = "alpha"
display_name = "alpha"
ip = "192.168.1.10"
profile = "default"

[[devices]]
id = "bravo"
display_name = "bravo"
ip = "192.168.1.11"
profile = "default"

[upstream]
servers = ["192.0.2.1:53"]
"#;
        let (_dir, path) = client_mutation_temp_config(initial, "update-dup-ip");
        let (state, _rx) = test_state_with_config_path("tok-dupip", path.clone());
        let state = Arc::new(state);

        // Move "alpha" onto bravo's IP — must fail.
        let patch = super::super::protocol::DevicePatch {
            ip: Some("192.168.1.11".parse().unwrap()),
            ..Default::default()
        };
        let cmd = IpcCommand::DeviceUpdate {
            name: "alpha".into(),
            patch,
            token: Some("tok-dupip".into()),
        };
        let resp = dispatch_command(cmd, None, &state).await;
        assert!(matches!(resp, IpcResponse::Error { .. }), "got {resp:?}");

        // Validator rejected before the change stuck — alpha's IP intact.
        let devices = load_devices(&path);
        assert_eq!(devices.len(), 2);
        let alpha = devices
            .iter()
            .find(|d| d.id.as_str() == "alpha")
            .expect("alpha must still be present");
        assert_eq!(
            alpha.ip.map(|ip| ip.to_string()).as_deref(),
            Some("192.168.1.10"),
            "alpha's IP must be reverted"
        );
    }

    #[tokio::test]
    async fn client_update_requires_admin_token() {
        let (_dir, path) = client_mutation_temp_config(
            "schema_version = 3\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
            "update-auth",
        );
        let (state, _rx) = test_state_with_config_path("tok-uauth", path.clone());
        let state = Arc::new(state);

        let cmd = IpcCommand::DeviceUpdate {
            name: "x".into(),
            patch: super::super::protocol::DevicePatch::default(),
            token: None,
        };
        let resp = dispatch_command(cmd, None, &state).await;
        assert!(matches!(resp, IpcResponse::Error { .. }));
    }

    // ── s23-ipc-client-mutations: DeviceRemove handler tests ──────

    #[tokio::test]
    async fn client_remove_happy_path_drops_client_and_reloads() {
        let initial = r#"
schema_version = 3

[profiles.default]
display_name = "Default"

[[devices]]
id = "alex-laptop"
display_name = "alex-laptop"
ip = "192.168.1.42"
profile = "default"

[[devices]]
id = "tablet"
display_name = "tablet"
ip = "192.168.1.50"
profile = "default"

[upstream]
servers = ["192.0.2.1:53"]
"#;
        let (_dir, path) = client_mutation_temp_config(initial, "remove-happy");
        let (state, mut reload_rx) = test_state_with_config_path("tok-rm", path.clone());
        let state = Arc::new(state);

        let cmd = IpcCommand::DeviceRemove {
            name: "alex-laptop".into(),
            token: Some("tok-rm".into()),
        };
        let resp = dispatch_command(cmd, None, &state).await;
        match &resp {
            IpcResponse::Ok { message } => {
                assert!(message.contains("alex-laptop"));
            }
            other => panic!("expected Ok, got {other:?}"),
        }

        let devices = load_devices(&path);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].id.as_str(), "tablet");
        assert!(reload_rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn client_remove_unknown_name_returns_friendly_error() {
        let (_dir, path) = client_mutation_temp_config(
            "schema_version = 3\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
            "remove-unknown",
        );
        let (state, _rx) = test_state_with_config_path("tok-rmx", path.clone());
        let state = Arc::new(state);

        let cmd = IpcCommand::DeviceRemove {
            name: "ghost".into(),
            token: Some("tok-rmx".into()),
        };
        let resp = dispatch_command(cmd, None, &state).await;
        match resp {
            IpcResponse::Error { message } => {
                assert!(
                    message.contains("ghost"),
                    "error must name missing client: {message}"
                );
                assert!(
                    message.contains("warden device list"),
                    "error must hint at how to discover names: {message}"
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn client_remove_dangling_schedule_blocked_by_validator() {
        // Removing a device referenced by a [[schedules]] entry must
        // NOT proceed — the v1 validator (run via `validate_or_revert`
        // after the staged removal) catches the dangling `target_id`
        // and the touched file is rolled back. A sibling "laptop"
        // device is kept so the removal is an ordinary 2→1 case.
        let initial = r#"
schema_version = 3

[profiles.default]
display_name = "Default"

[profiles.kids]
display_name = "Kids"

[[devices]]
id = "laptop"
display_name = "laptop"
ip = "192.168.1.42"
profile = "default"

[[devices]]
id = "tablet"
display_name = "tablet"
ip = "192.168.1.50"
profile = "default"

[[schedules]]
id = "tablet-quiet"
display_name = "Tablet quiet hours"
target_type = "device"
target_id = "tablet"
profile = "kids"
days = ["all"]
hours = "21:00-07:00"

[upstream]
servers = ["192.0.2.1:53"]
"#;
        let (_dir, path) = client_mutation_temp_config(initial, "remove-dangle");
        let (state, _rx) = test_state_with_config_path("tok-dangle", path.clone());
        let state = Arc::new(state);

        let cmd = IpcCommand::DeviceRemove {
            name: "tablet".into(),
            token: Some("tok-dangle".into()),
        };
        // §4.32 sets state.daemon_uid to the test process's euid by
        // default, but `dispatch_command` is called inline (not via
        // `handle_connection`) so the peer-uid gate is not exercised
        // here.
        let resp = dispatch_command(cmd, None, &state).await;
        // §4.33: the wire payload now carries the frozen
        // ValidatorRejected message; the validator's full detail
        // (which named the dangling schedule and hinted `warden
        // schedule remove`) moved to the daemon log via
        // `tracing::warn!(target: "ipc.error", ...)`. The proof that
        // the validator correctly caught the dangling reference is
        // (a) the Error response and (b) the file being unchanged on
        // disk.
        match resp {
            IpcResponse::Error { message } => {
                assert_eq!(
                    message,
                    crate::ipc::errors::IPC_ERROR_VALIDATOR_REJECTED,
                    "expected frozen ValidatorRejected message, got: {message}"
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }

        // File must NOT have been mutated — validator reverted the removal.
        let devices = load_devices(&path);
        assert_eq!(devices.len(), 2, "tablet must still be present");
    }

    #[tokio::test]
    async fn client_remove_requires_admin_token() {
        let (_dir, path) = client_mutation_temp_config(
            "schema_version = 3\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
            "remove-auth",
        );
        let (state, _rx) = test_state_with_config_path("tok-rmauth", path.clone());
        let state = Arc::new(state);

        let cmd = IpcCommand::DeviceRemove {
            name: "x".into(),
            token: None,
        };
        let resp = dispatch_command(cmd, None, &state).await;
        assert!(matches!(resp, IpcResponse::Error { .. }));
    }

    // ── s23-ipc-client-mutations: DevicePromote handler tests ──────

    /// Build a state wired to a config file AND a real ProfileResolver
    /// so DevicePromote can hit `snapshot_for_ipc` for the ARP lookup.
    /// The resolver's ARP snapshot is then overridden via the
    /// test-only setter so tests don't depend on the host's
    /// `/proc/net/arp`.
    fn test_state_with_resolver(
        token_plaintext: &str,
        config_path: PathBuf,
        arp_entries: &[(std::net::IpAddr, &str)],
    ) -> (DaemonState, tokio::sync::mpsc::Receiver<Option<u32>>) {
        use crate::auth::token::hash_token;
        use crate::config::loader;
        use crate::dns::cache::DnsCache;
        use crate::profiles::ProfileResolver;

        let loaded = loader::load_config(&config_path, time::OffsetDateTime::now_utc())
            .unwrap_or_else(|errs| panic!("test fixture config must load: {errs:?}"));
        let bit_map = crate::lists::source_key::SourceBitMap::default();
        let resolver = Arc::new(ProfileResolver::build(
            &loaded.config,
            &bit_map,
            &loaded.custom_lists,
        ));
        resolver.test_only_set_arp_snapshot(arp_entries);

        let cache_config = crate::config::settings::CacheConfig::default();
        let (reload_tx, reload_rx) = tokio::sync::mpsc::channel::<Option<u32>>(1);
        let state = DaemonState {
            filter: Arc::new(FilterEngine::new()),
            cache: DnsCache::new(&cache_config),
            profiles: Some(resolver),
            stats: None,
            listen_addr: "127.0.0.1:15353".into(),
            upstream_mode: "plain".into(),
            upstream_count: 2,
            list_count: 0,
            started_at: Instant::now(),
            shutdown_tx: None,
            reload_tx: Some(reload_tx),
            api_token_hash: Arc::new(arc_swap::ArcSwap::from_pointee(Some(hash_token(
                token_plaintext,
            )))),
            config_path: Some(config_path),
            config_write_lock: Arc::new(tokio::sync::Mutex::new(())),
            list_statuses: None,
            list_state: None,
            local_records_hits: None,
            log_ring: None,
            notification_tx: None,
            reload_coalescer: None,
            oui_table: None,
            list_labels: Arc::new(vec![None; 64]),
            list_cmd_tx: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
            daemon_uid: current_euid(),
            resource_budget_store: crate::resource_budget::types::new_store(),
            #[cfg(feature = "cluster")]
            cluster_observe: None,
        };
        (state, reload_rx)
    }

    #[tokio::test]
    async fn client_promote_happy_path_pins_arp_mac() {
        // Sprint S44 (this commit) retires the Sprint 35 CS1 stub: the
        // IPC mutation handlers are now v1-native via the entity API
        // (resolve_target_file + upsert_id_keyed + validate_or_revert).
        // DevicePromote against a v1 master succeeds, the new device
        // is appended (master has no devices.d/ in this fixture so the
        // entry lands in the master itself), and the reload channel
        // fires. The previous test that asserted Sprint-35-style
        // refusal is inverted here.
        let initial = r#"
schema_version = 3

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#;
        let (_dir, path) = client_mutation_temp_config(initial, "promote-happy");
        let unmapped: std::net::IpAddr = "10.0.0.99".parse().unwrap();
        let (state, mut reload_rx) =
            test_state_with_resolver("tok-prom", path.clone(), &[(unmapped, "AA:BB:CC:DD:EE:99")]);
        let state = Arc::new(state);

        let cmd = IpcCommand::DevicePromote {
            ip: unmapped,
            name: "phone".into(),
            profile: "default".into(),
            owner: Some("Sam".into()),
            device_type: Some("iPhone".into()),
            department: None,
            token: Some("tok-prom".into()),
        };

        let resp = dispatch_command(cmd, None, &state).await;
        match &resp {
            IpcResponse::Ok { message } => {
                assert!(
                    message.contains("phone"),
                    "Ok message must name the promoted device: {message}"
                );
            }
            other => panic!("expected Ok, got {other:?}"),
        }

        // Verify the master was rewritten with the new [[devices]]
        // block. The entry lands in the master because no devices.d/
        // directory was created for this fixture.
        let now = time::OffsetDateTime::now_utc();
        let loaded = crate::config::loader::load_config(&path, now)
            .expect("master must reload as v1 after promote");
        let devices = &loaded.config.devices;
        assert_eq!(devices.len(), 1, "exactly one device after promote");
        assert_eq!(devices[0].id.as_str(), "phone");
        assert_eq!(devices[0].display_name, "phone");
        assert_eq!(devices[0].ip, Some(unmapped));
        assert_eq!(
            devices[0].mac.as_deref(),
            Some("AA:BB:CC:DD:EE:99"),
            "MAC pinned from ARP snapshot"
        );

        assert!(
            reload_rx.try_recv().is_ok(),
            "successful mutation must fire the reload signal"
        );
    }

    #[tokio::test]
    async fn client_promote_rejects_when_arp_has_no_entry() {
        // The ARP table doesn't have the requested IP. Promotion
        // must be refused with the "wait for ARP" hint, NOT silently
        // succeed with mac=None — that would break the MAC-pin
        // requirement and reintroduce the IP-only-identification
        // foot-gun documented in project rules.
        let (_dir, path) = client_mutation_temp_config(
            "schema_version = 3\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
            "promote-no-arp",
        );
        let target_ip: std::net::IpAddr = "10.0.0.50".parse().unwrap();
        let (state, _rx) =
            test_state_with_resolver("tok-noarp", path.clone(), &[/* arp empty for 10.0.0.50 */]);
        let state = Arc::new(state);

        let cmd = IpcCommand::DevicePromote {
            ip: target_ip,
            name: "tablet".into(),
            profile: "default".into(),
            owner: None,
            device_type: None,
            department: None,
            token: Some("tok-noarp".into()),
        };

        let resp = dispatch_command(cmd, None, &state).await;
        match resp {
            IpcResponse::Error { message } => {
                assert!(
                    message.contains("MAC") || message.contains("ARP"),
                    "error must explain why: {message}"
                );
                assert!(
                    message.contains("10.0.0.50"),
                    "error must name the IP: {message}"
                );
                assert!(
                    message.contains("ping") || message.contains("retry"),
                    "error must give a recovery hint: {message}"
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }

        // No client must have been added.
        assert!(load_devices(&path).is_empty());
    }

    #[tokio::test]
    async fn client_promote_validator_runs_via_delegated_add_path() {
        // DevicePromote delegates to handle_device_add, so all the
        // validator-level guarantees from DeviceAdd apply here too:
        // duplicate name, duplicate IP, unknown profile, etc. This
        // test pins the unknown-profile case to confirm delegation
        // didn't bypass validation.
        let (_dir, path) = client_mutation_temp_config(
            "schema_version = 3\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
            "promote-validator",
        );
        let unmapped: std::net::IpAddr = "10.0.0.42".parse().unwrap();
        let (state, _rx) = test_state_with_resolver(
            "tok-promval",
            path.clone(),
            &[(unmapped, "AA:BB:CC:DD:EE:42")],
        );
        let state = Arc::new(state);

        let cmd = IpcCommand::DevicePromote {
            ip: unmapped,
            name: "x".into(),
            profile: "ghost".into(), // not configured
            owner: None,
            device_type: None,
            department: None,
            token: Some("tok-promval".into()),
        };

        let resp = dispatch_command(cmd, None, &state).await;
        assert!(matches!(resp, IpcResponse::Error { .. }));
        assert!(load_devices(&path).is_empty());
    }

    #[tokio::test]
    async fn client_promote_requires_admin_token() {
        let (_dir, path) = client_mutation_temp_config(
            "schema_version = 3\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
            "promote-auth",
        );
        let target_ip: std::net::IpAddr = "10.0.0.42".parse().unwrap();
        let (state, _rx) =
            test_state_with_resolver("tok-promauth", path.clone(), &[(target_ip, "MAC")]);
        let state = Arc::new(state);

        let cmd = IpcCommand::DevicePromote {
            ip: target_ip,
            name: "x".into(),
            profile: "default".into(),
            owner: None,
            device_type: None,
            department: None,
            token: None, // missing
        };
        let resp = dispatch_command(cmd, None, &state).await;
        assert!(matches!(resp, IpcResponse::Error { .. }));
    }

    // ── Sprint 38 QLP5: TrackingConfigUpdate ────────────────

    fn tracking_v1_master() -> String {
        r#"
schema_version = 3

[server]
listen = "127.0.0.1:15353"
default_profile = "default"
default_blocked_ttl_secs = 60

[profiles.default]
display_name = "Default"

[tracking]
enabled = true
query_log_enabled = true
retention_days = 7
log_mode = "all"

[upstream]
servers = ["192.0.2.1:53"]
"#
        .to_string()
    }

    #[test]
    fn tracking_patch_merges_partial_fields() {
        // Pure patch-apply semantics — no file I/O. Pin that leaving a
        // field None doesn't disturb the baseline and that each field
        // assigns independently.
        use crate::config::settings::{LogMode, TrackingConfig};
        use crate::ipc::protocol::TrackingPatch;

        let baseline = TrackingConfig::default();
        let patch = TrackingPatch {
            query_log_enabled: Some(false),
            retention_days: None,
            log_mode: None,
        };
        let mut merged = baseline.clone();
        if let Some(f) = patch.query_log_enabled {
            merged.query_log_enabled = f;
        }
        if let Some(rd) = patch.retention_days {
            merged.retention_days = rd;
        }
        if let Some(mode) = patch.log_mode.clone() {
            merged.log_mode = mode;
        }
        assert!(!merged.query_log_enabled, "flag flipped");
        assert_eq!(merged.retention_days, baseline.retention_days);
        assert!(matches!(merged.log_mode, LogMode::All));
    }

    #[tokio::test]
    async fn handle_tracking_config_update_is_admin_tier() {
        // Belt-and-suspenders for the tier() mapping — QLP5 put the
        // new variant in the Admin arm alongside the other PII-
        // exposing / config-mutating commands.
        use crate::ipc::protocol::{CommandTier, IpcCommand, TrackingPatch};

        let cmd = IpcCommand::TrackingConfigUpdate {
            patch: TrackingPatch::default(),
            token: Some("t".into()),
        };
        assert_eq!(cmd.tier(), CommandTier::Admin);
    }

    #[tokio::test]
    async fn handle_tracking_config_update_happy_path() {
        use crate::ipc::protocol::{IpcCommand, TrackingPatch};

        let (_dir, path) = client_mutation_temp_config(&tracking_v1_master(), "trk-happy");
        let (state, _rx) = test_state_with_config_path("tok-trk", path.clone());
        let state = Arc::new(state);

        let cmd = IpcCommand::TrackingConfigUpdate {
            patch: TrackingPatch {
                query_log_enabled: Some(false),
                retention_days: Some(14),
                log_mode: None,
            },
            token: Some("tok-trk".into()),
        };
        let resp = dispatch_command(cmd, None, &state).await;
        match resp {
            IpcResponse::Ok { .. } => {}
            other => panic!("expected Ok, got {other:?}"),
        }

        // Re-read and assert the mutation landed.
        let reloaded = crate::config::loader::load_config(&path, time::OffsetDateTime::now_utc())
            .expect("reload after patch");
        assert!(!reloaded.config.tracking.query_log_enabled);
        assert_eq!(reloaded.config.tracking.retention_days, 14);
    }

    #[tokio::test]
    async fn handle_tracking_config_update_refuses_invalid_retention() {
        use crate::ipc::protocol::{IpcCommand, TrackingPatch};

        let (_dir, path) = client_mutation_temp_config(&tracking_v1_master(), "trk-bad");
        let (state, _rx) = test_state_with_config_path("tok-trk2", path.clone());
        let state = Arc::new(state);

        let cmd = IpcCommand::TrackingConfigUpdate {
            patch: TrackingPatch {
                query_log_enabled: None,
                retention_days: Some(500),
                log_mode: None,
            },
            token: Some("tok-trk2".into()),
        };
        let resp = dispatch_command(cmd, None, &state).await;
        match resp {
            IpcResponse::Error { message } => {
                assert!(
                    message.contains("retention_days must be between 1 and 365"),
                    "frozen operator string must surface verbatim: {message}"
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }

        // Master unchanged on disk.
        let reloaded = crate::config::loader::load_config(&path, time::OffsetDateTime::now_utc())
            .expect("reload after reject");
        assert_eq!(reloaded.config.tracking.retention_days, 7);
    }

    #[tokio::test]
    async fn handle_tracking_config_update_without_token_is_rejected() {
        // Auth gate sanity: Admin tier → token required. Covered by
        // the shared `auth_error_for` path, but pinned explicitly here
        // so a future refactor that moves TrackingConfigUpdate out of
        // Admin fails loudly.
        use crate::ipc::protocol::{IpcCommand, TrackingPatch};

        let (_dir, path) = client_mutation_temp_config(&tracking_v1_master(), "trk-noauth");
        let (state, _rx) = test_state_with_config_path("tok-trk3", path.clone());
        let state = Arc::new(state);

        let cmd = IpcCommand::TrackingConfigUpdate {
            patch: TrackingPatch {
                query_log_enabled: Some(false),
                retention_days: None,
                log_mode: None,
            },
            token: None,
        };
        let resp = dispatch_command(cmd, None, &state).await;
        assert!(matches!(resp, IpcResponse::Error { .. }));
    }

    // ── BlocklistStats (s43-t1) ─────────────────────────────────

    /// Build a state pre-seeded with a `ListStatusRegistry` covering
    /// two sources, both freshly refreshed. Used by the
    /// `IpcCommand::BlocklistStats` test cases below.
    fn test_state_with_list_statuses() -> DaemonState {
        use crate::dns::cache::DnsCache;
        use crate::lists::status::{ListStatus, ListStatusRegistry, ParsedCounts};
        use time::OffsetDateTime;

        let cache_config = crate::config::settings::CacheConfig::default();
        let registry = Arc::new(ListStatusRegistry::new(&[
            "privacy/ads".into(),
            "security/malicious".into(),
        ]));
        let now = OffsetDateTime::now_utc();
        registry.update_for_url(
            "privacy/ads",
            ListStatus::from_refresh(
                42,
                ParsedCounts {
                    parsed_ok: 42,
                    unique_domains: 42,
                    parsed_skipped: 1,
                    parsed_skipped_samples: vec!["bad-line".into()],
                    parsed_truncated: 0,
                },
                None,
                now,
            ),
        );
        registry.update_for_url(
            "security/malicious",
            ListStatus::from_refresh(7, ParsedCounts::default(), None, now),
        );

        DaemonState {
            filter: Arc::new(FilterEngine::new()),
            cache: DnsCache::new(&cache_config),
            profiles: None,
            stats: None,
            listen_addr: "127.0.0.1:15353".into(),
            upstream_mode: "plain".into(),
            upstream_count: 2,
            list_count: 2,
            started_at: Instant::now(),
            shutdown_tx: None,
            reload_tx: None,
            api_token_hash: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
            config_path: None,
            config_write_lock: Arc::new(tokio::sync::Mutex::new(())),
            list_statuses: Some(registry),
            list_state: None,
            local_records_hits: None,
            log_ring: None,
            notification_tx: None,
            reload_coalescer: None,
            oui_table: None,
            list_labels: Arc::new(vec![None; 64]),
            list_cmd_tx: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
            daemon_uid: current_euid(),
            resource_budget_store: crate::resource_budget::types::new_store(),
            #[cfg(feature = "cluster")]
            cluster_observe: None,
        }
    }

    #[tokio::test]
    async fn blocklist_stats_no_filter_returns_every_source() {
        let state = Arc::new(test_state_with_list_statuses());
        let resp =
            dispatch_command(IpcCommand::BlocklistStats { source_id: None }, None, &state).await;
        match resp {
            IpcResponse::BlocklistStatsList { stats } => {
                assert_eq!(stats.len(), 2);
                let keys: std::collections::HashSet<_> =
                    stats.iter().map(|s| s.source.clone()).collect();
                assert!(keys.contains("privacy/ads"));
                assert!(keys.contains("security/malicious"));
                let ads = stats.iter().find(|s| s.source == "privacy/ads").unwrap();
                assert_eq!(ads.entries, 42);
                assert_eq!(ads.parsed_ok, 42);
                assert_eq!(ads.parsed_skipped, 1);
                assert_eq!(ads.last_outcome, "ok");
            }
            other => panic!("expected BlocklistStatsList, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn blocklist_stats_exact_match_returns_one_entry() {
        let state = Arc::new(test_state_with_list_statuses());
        let resp = dispatch_command(
            IpcCommand::BlocklistStats {
                source_id: Some("privacy/ads".into()),
            },
            None,
            &state,
        )
        .await;
        match resp {
            IpcResponse::BlocklistStatsList { stats } => {
                assert_eq!(stats.len(), 1);
                assert_eq!(stats[0].source, "privacy/ads");
                assert_eq!(stats[0].entries, 42);
            }
            other => panic!("expected BlocklistStatsList, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn blocklist_stats_substring_fallback_resolves() {
        // Operator types `"ads"` (no exact / no slug match) — the
        // case-insensitive substring fallback hits `privacy/ads`.
        let state = Arc::new(test_state_with_list_statuses());
        let resp = dispatch_command(
            IpcCommand::BlocklistStats {
                source_id: Some("ads".into()),
            },
            None,
            &state,
        )
        .await;
        match resp {
            IpcResponse::BlocklistStatsList { stats } => {
                assert_eq!(stats.len(), 1);
                assert_eq!(stats[0].source, "privacy/ads");
            }
            other => panic!("expected BlocklistStatsList, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn blocklist_stats_unknown_source_returns_empty_list() {
        let state = Arc::new(test_state_with_list_statuses());
        let resp = dispatch_command(
            IpcCommand::BlocklistStats {
                source_id: Some("nonexistent".into()),
            },
            None,
            &state,
        )
        .await;
        match resp {
            IpcResponse::BlocklistStatsList { stats } => {
                assert!(stats.is_empty());
            }
            other => panic!("expected BlocklistStatsList, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn blocklist_stats_no_registry_returns_empty_list() {
        // Daemon started without [lists].sources: list_statuses = None.
        // Command must NOT error — the TUI polls this on startup before
        // it knows whether the daemon was configured with any sources.
        let state = Arc::new(test_state());
        let resp =
            dispatch_command(IpcCommand::BlocklistStats { source_id: None }, None, &state).await;
        match resp {
            IpcResponse::BlocklistStatsList { stats } => assert!(stats.is_empty()),
            other => panic!("expected empty BlocklistStatsList, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn blocklist_stats_is_read_only_tier_no_token_needed() {
        // Tier gate: ReadOnly. The command must succeed without any
        // token — the test_state_with_list_statuses fixture has
        // `api_token_hash = None`, which would reject any tier above
        // ReadOnly. If this test fails the dispatch returned an Error
        // (NO_TOKEN_CONFIGURED_MSG).
        let state = Arc::new(test_state_with_list_statuses());
        let resp =
            dispatch_command(IpcCommand::BlocklistStats { source_id: None }, None, &state).await;
        assert!(
            matches!(resp, IpcResponse::BlocklistStatsList { .. }),
            "expected stats list, got {resp:?}"
        );
        // Tier check at the type level — pinned in case a future
        // refactor accidentally moves the variant out of ReadOnly.
        let cmd = IpcCommand::BlocklistStats { source_id: None };
        assert_eq!(cmd.tier(), CommandTier::ReadOnly);
        assert_eq!(cmd.token(), None);
    }

    // ── DaemonLogs (`logs-tab`) ──────────────────────────────────────

    /// A `DaemonState` wired to a ring holding three events of three
    /// different levels, so the handler exercises the filter walk and the
    /// DTO mapping rather than just the empty path.
    fn test_state_with_log_ring() -> DaemonState {
        use crate::tracking::log_ring::{LogEntry, LogLevel, LogRing};

        let ring = Arc::new(LogRing::new(64));
        for (level, message) in [
            (LogLevel::Error, "upstream timeout"),
            (LogLevel::Warn, "refresh failed"),
            (LogLevel::Info, "listening on 0.0.0.0:53"),
        ] {
            ring.push(LogEntry {
                ts: time::OffsetDateTime::UNIX_EPOCH,
                level,
                target: "purge_warden::test",
                message: message.to_string(),
            });
        }
        let mut state = test_state_with_token("ps_correctvalue");
        state.log_ring = Some(ring);
        state
    }

    #[tokio::test]
    async fn daemon_logs_is_admin_gated() {
        // Log text carries client IPs and query names. An unauthenticated
        // reader of this verb would be an unauthenticated reader of a
        // slice of the query stream.
        let cmd = IpcCommand::DaemonLogs {
            limit: 10,
            level: None,
            contains: None,
            token: None,
        };
        assert_eq!(cmd.tier(), CommandTier::Admin);

        let state = Arc::new(test_state_with_log_ring());
        let resp = dispatch_command(cmd, None, &state).await;
        match resp {
            IpcResponse::Error { message } => {
                assert!(
                    message.to_lowercase().contains("token"),
                    "expected a token refusal, got: {message}"
                );
            }
            other => panic!("an untokened DaemonLogs must be refused, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn daemon_logs_returns_newest_first_with_the_ring_bound() {
        let state = Arc::new(test_state_with_log_ring());
        let resp = dispatch_command(
            IpcCommand::DaemonLogs {
                limit: 10,
                level: None,
                contains: None,
                token: Some("ps_correctvalue".into()),
            },
            None,
            &state,
        )
        .await;
        match resp {
            IpcResponse::DaemonLogs {
                entries,
                dropped,
                capacity,
            } => {
                assert_eq!(entries.len(), 3);
                assert_eq!(entries[0].message, "listening on 0.0.0.0:53");
                assert_eq!(entries[2].message, "upstream timeout");
                // Formatted daemon-side in the QueryLogDto shape.
                assert_eq!(entries[0].timestamp, "1970-01-01T00:00:00Z");
                assert_eq!(entries[0].target, "purge_warden::test");
                assert_eq!(dropped, 0);
                assert_eq!(capacity, 64, "the bound must travel with the page");
            }
            other => panic!("expected DaemonLogs, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn daemon_logs_filters_are_applied_by_the_daemon() {
        // The point of sending the filters down: the walk applies them,
        // so the TUI never has to search a page it was already handed.
        let state = Arc::new(test_state_with_log_ring());
        let resp = dispatch_command(
            IpcCommand::DaemonLogs {
                limit: 10,
                level: Some(crate::tracking::log_ring::LogLevel::Error),
                contains: None,
                token: Some("ps_correctvalue".into()),
            },
            None,
            &state,
        )
        .await;
        match resp {
            IpcResponse::DaemonLogs { entries, .. } => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].message, "upstream timeout");
            }
            other => panic!("expected DaemonLogs, got {other:?}"),
        }

        let resp = dispatch_command(
            IpcCommand::DaemonLogs {
                limit: 10,
                level: None,
                contains: Some("FAILED".into()),
                token: Some("ps_correctvalue".into()),
            },
            None,
            &state,
        )
        .await;
        match resp {
            IpcResponse::DaemonLogs { entries, .. } => {
                assert_eq!(entries.len(), 1, "case-insensitive substring");
                assert_eq!(entries[0].message, "refresh failed");
            }
            other => panic!("expected DaemonLogs, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn daemon_logs_without_a_ring_answers_empty_not_error() {
        // Same degradation contract as LocalRecordsHits: a test-seam
        // state must not fail the whole tab poll.
        let mut state = test_state_with_token("ps_correctvalue");
        state.log_ring = None;
        let state = Arc::new(state);
        let resp = dispatch_command(
            IpcCommand::DaemonLogs {
                limit: 10,
                level: None,
                contains: None,
                token: Some("ps_correctvalue".into()),
            },
            None,
            &state,
        )
        .await;
        match resp {
            IpcResponse::DaemonLogs {
                entries, capacity, ..
            } => {
                assert!(entries.is_empty());
                assert_eq!(capacity, 0);
            }
            other => panic!("expected an empty DaemonLogs, got {other:?}"),
        }
    }

    // ── LocalRecordsHits (s44-hits-ipc-verb) ─────────────────────────

    /// Build a DaemonState wired with a populated `LocalRecordsHits`
    /// fixture so the IPC handler exercises the full snapshot →
    /// `LocalRecordsHitEntry` mapping path.
    fn test_state_with_local_records_hits() -> DaemonState {
        use crate::dns::cache::DnsCache;
        use crate::tracking::{LocalRecordsHits, LocalRecordsScopeKey};
        use compact_str::CompactString;

        let hits = Arc::new(LocalRecordsHits::new());
        // 2 global hits on nas.home, 1 global on intranet.home, 5
        // profile-scoped hits on example.test under `kids`.
        for _ in 0..2 {
            hits.record_hit(LocalRecordsScopeKey::Global, "nas.home");
        }
        hits.record_hit(LocalRecordsScopeKey::Global, "intranet.home");
        for _ in 0..5 {
            hits.record_hit(
                LocalRecordsScopeKey::Profile(CompactString::new("kids")),
                "example.test",
            );
        }

        let cache_config = crate::config::settings::CacheConfig::default();
        DaemonState {
            filter: Arc::new(FilterEngine::new()),
            cache: DnsCache::new(&cache_config),
            profiles: None,
            stats: None,
            listen_addr: "127.0.0.1:15353".into(),
            upstream_mode: "plain".into(),
            upstream_count: 2,
            list_count: 0,
            started_at: Instant::now(),
            shutdown_tx: None,
            reload_tx: None,
            api_token_hash: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
            config_path: None,
            config_write_lock: Arc::new(tokio::sync::Mutex::new(())),
            list_statuses: None,
            list_state: None,
            local_records_hits: Some(hits),
            log_ring: None,
            notification_tx: None,
            reload_coalescer: None,
            oui_table: None,
            list_labels: Arc::new(vec![None; 64]),
            list_cmd_tx: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
            daemon_uid: current_euid(),
            resource_budget_store: crate::resource_budget::types::new_store(),
            #[cfg(feature = "cluster")]
            cluster_observe: None,
        }
    }

    #[tokio::test]
    async fn local_records_hits_returns_empty_list_when_state_has_none() {
        // DaemonState without a wired counter (test seam) must respond
        // with an empty list — never an Error — so the TUI degrades to
        // "no hits known yet" instead of failing the whole tab poll.
        let state = Arc::new(test_state());
        assert!(state.local_records_hits.is_none());
        let resp = dispatch_command(IpcCommand::LocalRecordsHits, None, &state).await;
        match resp {
            IpcResponse::LocalRecordsHitsList { entries } => {
                assert!(entries.is_empty(), "expected empty list, got {entries:?}");
            }
            other => panic!("expected LocalRecordsHitsList, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn local_records_hits_returns_global_and_profile_entries() {
        // Counter has 3 keys (2 global + 1 profile). The handler must
        // surface every key with its count + the operator-facing scope
        // tag (`global` / `profile:<id>`).
        let state = Arc::new(test_state_with_local_records_hits());
        let resp = dispatch_command(IpcCommand::LocalRecordsHits, None, &state).await;
        let entries = match resp {
            IpcResponse::LocalRecordsHitsList { entries } => entries,
            other => panic!("expected LocalRecordsHitsList, got {other:?}"),
        };
        assert_eq!(entries.len(), 3, "expected 3 distinct keys");

        let by_key: std::collections::HashMap<(String, String), u64> = entries
            .iter()
            .map(|e| ((e.scope.clone(), e.domain.clone()), e.count))
            .collect();
        assert_eq!(by_key.get(&("global".into(), "nas.home".into())), Some(&2));
        assert_eq!(
            by_key.get(&("global".into(), "intranet.home".into())),
            Some(&1)
        );
        assert_eq!(
            by_key.get(&("profile:kids".into(), "example.test".into())),
            Some(&5),
            "profile-scoped key must serialise as `profile:<id>`",
        );
    }

    #[tokio::test]
    async fn local_records_hits_is_read_only_tier_no_token_needed() {
        // Same gating contract as BlocklistStats — counts + names the
        // operator already configured aren't PII, the TUI polls on a
        // slow tick, and a token gate would defeat the read loop.
        let state = Arc::new(test_state_with_local_records_hits());
        let resp = dispatch_command(IpcCommand::LocalRecordsHits, None, &state).await;
        assert!(
            matches!(resp, IpcResponse::LocalRecordsHitsList { .. }),
            "expected LocalRecordsHitsList, got {resp:?}"
        );
        assert_eq!(IpcCommand::LocalRecordsHits.tier(), CommandTier::ReadOnly);
        assert_eq!(IpcCommand::LocalRecordsHits.token(), None);
    }

    #[test]
    fn local_records_hits_with_token_is_identity() {
        // ReadOnly variants are returned unchanged by `with_token` —
        // the CLI wrapper still calls it on every send. A future
        // refactor that accidentally drops the variant from the
        // `other @ (...)` arm would silently lose the command on the
        // wire; this pin catches that.
        let cmd = IpcCommand::LocalRecordsHits;
        let with = cmd.clone().with_token(Some("ignored".into()));
        assert_eq!(with, cmd);
    }
}
