//! Daemon-side Unix socket listener for IPC commands.
//!
//! Listens on a Unix domain socket, spawns one tokio task per connection.
//! Each connection: read one JSON command line → dispatch → write JSON response → close.
//! Socket file is exposed at the canonical path with mode `0o600` (owner-
//! only) atomically: the bind path binds into a per-call temp path,
//! `chmod`s it, then `rename(2)`s into place. Peers resolving the
//! canonical path see `0o600` from the first syscall — closes the TOCTOU
//! window where a separate post-bind `chmod` would briefly expose the
//! socket as `0o666 & ~umask`. `0o600` (not `0o660`) so a hypothetical
//! second user added to the `purge-warden` group cannot reach the IPC
//! bus; defense in depth alongside the peer-uid gate in
//! `handle_connection`.

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
    /// Per-server upstream list (primary then fallback),
    /// precomputed at boot from `config.upstream.server_list()`. Surfaced
    /// verbatim on `IpcResponse::Status` so the TUI / `warden status`
    /// render the real resolver addresses. Set-once at construction,
    /// matching the no-reload semantics of `upstream_mode`/`upstream_count`.
    pub upstream_servers: Vec<crate::ipc::protocol::UpstreamServerInfo>,
    pub list_count: usize,
    pub started_at: Instant,
    /// Sender to trigger shutdown from IPC. Payload carries the invoker
    /// uid from `SO_PEERCRED` (for the audit trail) — `Some(uid)` for
    /// IPC-triggered shutdowns, `None` for signal-driven shutdowns.
    pub shutdown_tx: Option<tokio::sync::mpsc::Sender<Option<u32>>>,
    /// Sender to trigger reload from IPC. Payload carries the invoker uid
    /// from `SO_PEERCRED` — `Some(uid)` for IPC reloads, `None` for
    /// SIGHUP-driven reloads (signals have no peer cred).
    pub reload_tx: Option<tokio::sync::mpsc::Sender<Option<u32>>>,
    /// SHA-256 hash of the daemon's auth token. `None` if the
    /// operator has never run `warden token generate`. When `None`, the
    /// daemon refuses all Mutating and Admin IPC commands with a plain-
    /// English error pointing the operator at `warden token generate`.
    ///
    /// Wrapped in an `Arc<ArcSwap<_>>` so that `warden token regenerate`'s
    /// IPC reload flow can swap in the new hash atomically, without a
    /// daemon restart. `handle_reload` in
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
    /// Shared handle to per-source `ListStatus`. `None`
    /// when the daemon was started with no `[lists].sources` (filter
    /// disabled). The `IpcCommand::BlocklistStats` handler reads
    /// through this Arc; the list manager updates it atomically on each
    /// refresh cycle.
    pub list_statuses: Option<Arc<ListStatusRegistry>>,
    /// Shared handle to the retry state machine (`data/list_state.toml`).
    /// `None` when no `[lists].sources` are configured. The
    /// `IpcCommand::Status` handler walks `lists.values()` to derive
    /// the per-state counts surfaced as `ListDiagnostics`. The list
    /// manager updates the inner map atomically on every refresh
    /// transition.
    pub list_state: Option<Arc<std::sync::Mutex<crate::config::list_state::ListState>>>,
    /// Shared handle to the per-record `LocalRecordsHits` counter.
    /// `None` only in tests that don't exercise the local-DNS hits path;
    /// production always wires `Some(_)` so the IPC handler returns a
    /// live snapshot. When `None` the handler returns an empty list
    /// rather than an error so the TUI's hits column degrades to "0
    /// known hits" instead of breaking.
    pub local_records_hits: Option<Arc<crate::tracking::LocalRecordsHits>>,
    /// The daemon's own recent `tracing` events, for
    /// `IpcCommand::DaemonLogs`. Production wires
    /// `tracking::log_ring::global()` — the same ring the capture layer
    /// installed in `main.rs` pushes into. `None` in tests that don't
    /// exercise the verb; the handler then answers with an empty page
    /// rather than an error, so the TUI shows "no messages" instead of
    /// breaking.
    pub log_ring: Option<Arc<crate::tracking::log_ring::LogRing>>,
    /// Broadcast sender for [`IpcNotification`] events. Subscribers
    /// obtain a receiver via `tx.subscribe()`. No IPC subscriber
    /// endpoint currently consumes this. Stored on `DaemonState` so a
    /// future endpoint can subscribe without re-plumbing through the
    /// manager.
    #[allow(dead_code)] // No subscriber endpoint wired yet.
    pub notification_tx: Option<tokio::sync::broadcast::Sender<IpcNotification>>,
    /// IPC-triggered reload coalescer. When present every
    /// `IpcCommand::Reload` runs through this 250 ms debounce window.
    /// SIGHUP-driven reloads bypass it and continue to use `reload_tx`
    /// directly. `None` in tests that don't exercise the coalescing
    /// path.
    pub reload_coalescer: Option<Arc<crate::ipc::ReloadCoalescer>>,
    /// Disk-resident MAC OUI vendor table opened at startup. `None`
    /// when the file is missing or malformed — lookups are simply
    /// skipped and the TUI hides the Vendor row in the device card.
    /// The table is `mmap`-backed so RAM cost in process RSS is
    /// effectively zero (kernel page cache holds the hot pages).
    pub oui_table: Option<Arc<crate::oui::OuiTable>>,
    /// Bit → "scope/topic" label snapshot for
    /// the `top_blocked_lists` IPC field. Length 64; entries are
    /// `None` for bits without a configured source. Built once at
    /// `start.rs` from `source_bits.iter_urls()` × `Catalog::entries()`
    /// (with URL-stem fallback for non-catalog sources). Replaced
    /// wholesale on hot-reload via the same construction path —
    /// `DaemonState` is rebuilt on full reload, so no `ArcSwap`
    /// indirection is needed here.
    pub list_labels: Arc<Vec<Option<String>>>,
    /// ArcSwap-wrapped sender for the
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
    /// Effective uid the daemon process runs as, captured
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
    /// Lock-free handle to the latest resource-budget sample.
    /// `handle_status` reads through `.load_full()` on every call; the
    /// sampler (spawned by `cli::commands::start`) writes the latest
    /// snapshot once per `tick_secs`. Tests that don't exercise the
    /// sampler use `resource_budget::types::new_store()` which keeps
    /// the snapshot as `None` — IPC just reports
    /// `resource_budget: None` in that case.
    pub resource_budget_store: crate::resource_budget::ResourceBudgetStore,
    /// Shared cluster observability handle. `handle_cluster_status`
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
/// concurrency cap. Exists so a boundary test can drive cap=2
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

    // Ensure parent directory exists. Mirrors `auth_token::save_token_at`:
    // only chmod the parent when WE created it — a fresh dir would otherwise land
    // at `0o777 & ~umask` (umask-dependent). In production
    // `/run/purge-warden/` pre-exists via systemd and is untouched; this
    // covers ad-hoc / test rigs. 0o700 is consistent with the
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
    // from the very first stat / connect (owner-only;
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
    // stale-socket check at the top of `bind_socket` has already
    // cleared) or the new socket with `0o600`.
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
    // Consecutive accept errors. Reset on every successful accept. Used
    // to compute exponential backoff so a sustained EMFILE / ENFILE /
    // ENOBUFS storm does not pin the runtime worker at a fixed high
    // frequency forever. Handler-side errors (timeouts, IO failures
    // inside handle_connection) MUST NOT touch this counter — they live
    // in a different spawned task and the cross-connection backoff here
    // is only the right response to listener-level failures.
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
/// `SO_PEERCRED`, for the connection audit trail.
///
/// Returns `None` only if the `getsockopt` call fails — extremely unlikely
/// on Linux for a freshly-accepted Unix stream. A `None` return is
/// treated as a peer-uid mismatch: [`handle_connection`] refuses the
/// connection rather than dispatching to any handler. The audit pipeline
/// records the refusal so the operator can investigate, but the peer
/// itself sees ECONNRESET with no `IpcResponse` body.
///
/// For audit emits *inside* a handler — where the gate has already
/// confirmed `peer_uid == state.daemon_uid` — `None` is structurally
/// unreachable, but the field type stays `Option<u32>` because the
/// audit subscribers and the reload-coalescer's last-uid slot also
/// carry SIGHUP-driven reloads, which have no peer cred.
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

/// Per-side I/O budget on every IPC connection. Mirrors the
/// 5-second read timeout (`tokio::time::timeout` around `read_line`)
/// onto the write + shutdown halves. A slow-loris peer that accepts
/// the response at 1 B/s — or refuses to read — would otherwise pin
/// the handler task indefinitely and burn one of the 64 concurrency
/// permits until the daemon restart. 5 s is generous for
/// a local Unix-socket round trip (typical <1 ms).
const IPC_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Handle a single IPC connection: read command, dispatch, write response.
///
/// `peer_uid` is the uid of the connecting process, extracted via
/// `SO_PEERCRED` at accept time. Threaded through to every mutating
/// handler so the audit log can attribute the action to a specific
/// local user.
///
/// BEFORE reading the first byte of the request, this
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
    // Peer-uid gate. Fail-closed for ALL verbs (incl.
    // ReadOnly) — the 0o600 socket already blocks non-daemon peers,
    // so keeping ReadOnly open is dead code on production and only
    // widens the design surface.
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
    // Bound write_all + shutdown by IPC_WRITE_TIMEOUT so a
    // slow-loris peer cannot pin the handler task. On timeout we drop
    // the connection (the spawned task ends → concurrency permit released
    // automatically). The peer observes ECONNRESET, which matches
    // the over-cap drop path's behavior.
    tokio::time::timeout(IPC_WRITE_TIMEOUT, writer.write_all(resp_json.as_bytes()))
        .await
        .map_err(|_| anyhow::anyhow!("IPC write timeout"))??;
    // Half-close so the peer sees clean EOF on its read side rather
    // than ECONNRESET — runs on EVERY response path (success, parse
    // error, oversize), not only on success.
    tokio::time::timeout(IPC_WRITE_TIMEOUT, writer.shutdown())
        .await
        .map_err(|_| anyhow::anyhow!("IPC shutdown timeout"))??;

    Ok(())
}

/// Dispatch an IPC command to the appropriate handler.
///
/// Enforces the three-tier authorization gate before routing to
/// the per-command handler. ReadOnly commands pass through unchecked;
/// Mutating and Admin commands must carry a plaintext token that the
/// daemon verifies against `state.api_token_hash` in constant time.
async fn dispatch_command(
    cmd: IpcCommand,
    peer_uid: Option<u32>,
    state: &DaemonState,
) -> IpcResponse {
    // Authorization gate.
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
    // Query-log silent-drop counters. `None` when tracking
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
    // Read alongside the refusal, and it can legitimately outlive one: the
    // arms that fail to install without refusing (flush error, degraded
    // shard build, empty spill) clear `lists_corpus_refusal` while the
    // previous generation is still what is serving. The freeze is the
    // longer-lived fact — "nothing new has installed since" — and the
    // refusal is "the last cycle was refused, and here is by how much".
    let lists_corpus_freeze = state
        .list_statuses
        .as_ref()
        .and_then(|reg| reg.corpus_freeze());
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
    // Walk the retry state machine and tally per-state counts. The walk
    // runs under the existing `Mutex` so a concurrent `record_blocklist_*`
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
    // `Arc<Option<...>>` → owned `Option<...>`. Deref once
    // through the `Arc`; `Option<ResourceBudgetSnapshot>` is `Copy` so
    // we move it out by value without allocating.
    let resource_budget = *state.resource_budget_store.load_full();
    // Flush moka before reading — entry_count() and weighted_size() are
    // each eventually consistent, and a cold read here can make a live,
    // actively-hit cache print "cache: 0 / 10000 entries". Off the `:53`
    // hot path (this only runs on an operator-initiated `warden status`
    // IPC call), so the await costs nothing that matters. See
    // `DnsCache::flushed_usage`.
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
        lists_corpus_freeze,
        lists_total,
        lc2_list_diagnostics,
        resource_budget,
        upstream_servers: state.upstream_servers.clone(),
    }
}

/// Build this node's cluster view from the shared observe
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

    // Validate at the trust boundary, mirroring
    // the HTTP twin (`handlers::query_domain` → `validate_api_domain`).
    // The peer-uid gate makes exploitation moot, but the two probe
    // surfaces must agree on what a queryable domain is — and a garbage
    // input now gets a real error instead of a meaningless "not blocked".
    // Detail goes to the daemon log; the wire error stays a frozen generic.
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

    // Surface the block attribution the engine already
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
            // When `default_profile` is unset, every
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

/// Drops a list source's in-memory cache entry AND
/// unlinks its `<stem>.cache` + `<stem>.meta` sidecars from disk. The
/// list manager owns the actual mutation; this handler is the IPC
/// shim that sends a [`ListManagerCommand::Forget`](crate::lists::manager::ListManagerCommand::Forget) over the
/// out-of-band channel and awaits the oneshot ack.
///
/// Returns `ListForgotten { id, was_cached }` on success. `was_cached`
/// echoes whether the source had any state before the call —
/// idempotent semantics, so a second forget on a never-cached source
/// is `Ok` with `was_cached: false`, not an error.
///
/// Audit log: emits one record per call — operators can grep the audit
/// stream for unexpected forgets.
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
    // IPC reloads route through the 250 ms
    // coalescer when one is wired. The actual ResolverMap rebuild
    // happens at most once per window — multiple in-flight requests
    // collapse into a single `reload_tx` message. SIGHUP keeps the
    // direct path so signal-driven reloads stay immediate.
    //
    // Emit `action = "daemon.reload"` audit attribution
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
    // Shutdown is the highest-blast-radius IPC action;
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

/// Read per-source list telemetry.
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

/// Snapshot the per-record `LocalRecordsHits` counter and shape it for
/// the TUI.
///
/// Returns an empty list — not an `Error` — when the daemon was started
/// without the counter wired (only happens in tests). The TUI then
/// renders every cell as `0`, which is correct on a boot-fresh daemon.
///
/// A filtered page of the daemon's own `tracing` events.
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
    // The cache can only ever be consulted by queries
    // that survive the block check (handler.rs: evaluate_with_overlay
    // runs before cache.lookup_keyed), and blocked responses are never
    // cached (they're instant to generate). A blocked query is
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
    // Scope population deferred — the filter engine has the information
    // (source_bits + catalog) but exposing a scope resolver + plumbing
    // Arc<FilterEngine> into the stats engine is a follow-up task.
    // Emitting `None` now keeps the wire format stable so the daemon can
    // light up the field without another protocol bump.
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

    // Per-`TypeBucket` 24h rolling sums computed daemon-side
    // from the internal hourly ring (the wire `TimeBucketDto` stays
    // 4-field; per-type breakdowns never cross the socket). Drives the
    // Dashboard QTYPE chart card.
    let (qtype_distribution_24h, qtype_blocked_distribution_24h) =
        engine.time_series.per_type_24h_snapshot();

    // Surface the prefetch hit-tracker counters.
    // `pool_size` is a live derived value; the cumulative totals come
    // straight from atomic loads. All three are 0 when the tracker is
    // disabled by default.
    let prefetch_pool_size = engine.prefetch_tracker.pool_size().min(u32::MAX as usize) as u32;
    let prefetch_promotions_total = engine.prefetch_tracker.promotions_total();
    let prefetch_demotions_total = engine.prefetch_tracker.demotions_total();

    // Resolve top-N bits to "scope/topic"
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
    // Same correction as handle_tracking_stats above —
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
mod window_tests;

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
    // `refresh_arp` does a synchronous `/proc/net/arp` parse on
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
/// **The read runs on the blocking pool.** The
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
    // since_secs is a relative duration in seconds; compute
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
    // (legacy single-file or v0 layout). We deliberately do NOT
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
    // Pre-promote validation: validate the staged slice
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
    // `tags` is retired. It is captured (never applied) purely so that
    // an older client sending it is TOLD, instead of having its intent
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
/// **Why the MAC is non-negotiable**: MAC + IP is required for client
/// identification — IP alone is bypassable in seconds. A
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

    // Emit a dedicated audit line for the promote action
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

/// Apply a [`TrackingPatch`](crate::ipc::protocol::TrackingPatch) to the `[tracking]`
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

    // Mutate the master's own `[tracking]`
    // table in place via `toml::Value` surgery, then promote through the
    // overlay-validating writer. Re-serialising the WHOLE merged
    // `ConfigV1` (every `.d/` entity + the `includes` array) onto the
    // master would flatten a multi-file layout (or, with non-empty
    // includes, get refused as duplicate singletons by staged
    // validation). `[tracking]` is a master-only pass-through section
    // (same as `[lists]` in `api::handlers::edit_master_lists_sources`),
    // so editing only the master's table and writing only the master
    // preserves the include layout. `write_value_validated` still
    // overlay-validates {master + every include} BEFORE the rename, so
    // a bad result is refused with nothing written.
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

// ── Profile mutation handlers ──────────────────────

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
    // A profile `tags` delta is refused, for the same reason as the
    // device path above — see `cli::commands::entity_tags::TAGS_RETIRED`.
    //
    // `Profile.tags` no longer exists as a field to write even if the
    // refusal were lifted. The wire field is KEPT (as `retired_tags`,
    // renamed to `tags`) precisely so this refusal stays reachable:
    // `ProfileUpdatePatch` has no `deny_unknown_fields`, so deleting it
    // would make an old client's tag delta vanish into serde with an OK
    // answer.
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
    // no-op — it writes NOTHING, not even `tags = []`. Pinned by
    // `an_empty_tags_delta_is_not_refused`: `Profile` is
    // `deny_unknown_fields`, so a stray `tags = []` would produce a
    // config that does not load — the daemon refusing to start on a key
    // no operator ever typed.
    //
    // The per-profile direction override.
    //
    // **This is the whole consent gate for override-scope `allow`, and it
    // is here because this is the only place it can be.** Both operator
    // surfaces write `[profiles.<id>]` through `IpcCommand::ProfileUpdate`
    // — `cli::commands::profiles_v1` and `tui::ipc_poller` — so the
    // override has exactly one writer, which is stronger than the usual
    // "one function, many callers" case.
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

    // The custom-list mount delta.
    //
    // One writer, for the same reason the override map above has one: both
    // operator surfaces reach `[profiles.<id>]` through this command.
    //
    // **It carries no gate of its own, and that is a decision rather than
    // an omission.** `allow_direction_gates` prices the standing exposure
    // of an allow-direction list whose body is re-fetched from a URL
    // somebody else controls; a custom list is a local file the operator
    // wrote, re-read from their own disk. Nor is there an existence
    // pre-check: the validator below refuses a profile that mounts an
    // undeclared list, and it judges the whole staged tree, which a check
    // reading one row cannot.
    if let Some(mounts) = patch.custom_lists {
        // Validated before anything is staged, like the two deltas above:
        // the post-write validator rejects the WHOLE file, so one
        // malformed id would take the other fields of this patch down
        // with it.
        for raw in mounts.mount.iter().chain(mounts.unmount.iter()) {
            if crate::config::schema::Id::new(raw.as_str()).is_err() {
                tracing::warn!(
                    target: "ipc.error",
                    id = %id,
                    list = %raw,
                    "profile_update: invalid custom-list id in mount patch",
                );
                return ipc_error(IpcError::ValidatorRejected);
            }
        }

        let mut current: Vec<String> = entry
            .get("custom_lists")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        // `mount` BEFORE `unmount`, frozen: an id in both ends unmounted.
        for add in &mounts.mount {
            if !current.iter().any(|x| x == add) {
                current.push(add.clone());
            }
        }
        current.retain(|x| !mounts.unmount.contains(x));
        // An empty vector is REMOVED, never written as `custom_lists = []`
        // — `Profile::custom_lists` carries `skip_serializing_if =
        // Vec::is_empty` precisely so a profile that mounts nothing does
        // not grow the key, and a handler that inserted one would put back
        // what that attribute exists to keep out.
        if current.is_empty() {
            entry.remove("custom_lists");
        } else {
            entry.insert(
                "custom_lists".into(),
                toml::Value::Array(current.into_iter().map(toml::Value::String).collect()),
            );
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
/// did not, and unifying Closed semantics is a separate scope-decision
/// that would risk silently regressing profile-handler error reporting.
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
mod tests;
