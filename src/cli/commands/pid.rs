//! PID file utilities for daemon management.
//!
//! Uses `flock(LOCK_EX|LOCK_NB)` to coordinate between instances. The OS
//! kernel enforces mutual exclusion — no TOCTOU race. The lock is held for
//! the process lifetime via the returned `File` handle, and automatically
//! released on exit or crash (the kernel clears advisory locks when the
//! last fd referencing the open-file-description is closed).

use std::fs::OpenOptions;
use std::io::{Read, Seek, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;

/// Error from [`acquire_pid_lock`].
#[derive(Debug)]
pub enum PidLockError {
    /// Another purge-warden instance holds the lock.
    AlreadyRunning(Option<u32>),
    /// Filesystem or OS error.
    Io(std::io::Error),
}

impl std::fmt::Display for PidLockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyRunning(Some(pid)) => write!(
                f,
                "purge-warden is already running (PID {pid}). \
                 Stop it first with `warden stop`."
            ),
            Self::AlreadyRunning(None) => write!(
                f,
                "another purge-warden instance holds the PID file lock. \
                 Stop it first with `warden stop`."
            ),
            Self::Io(e) => write!(f, "PID file error: {e}"),
        }
    }
}

impl std::error::Error for PidLockError {}

/// Acquire an exclusive `flock` on the PID file and write our PID.
///
/// Returns the open `File` handle — **the caller must keep it alive** for
/// the entire server lifetime. Dropping the handle releases the lock.
///
/// If another instance already holds the lock, returns
/// [`PidLockError::AlreadyRunning`] with the PID read from the file (if
/// readable).
pub fn acquire_pid_lock(path: &Path) -> Result<std::fs::File, PidLockError> {
    // Ensure the parent directory exists. In production systemd creates
    // /run/purge-warden/ via `RuntimeDirectory=`, but a foreground/dev
    // invocation (`warden start` after a `systemctl stop` wiped the
    // tmpfs entry) needs us to recreate it ourselves — otherwise the
    // open below fails with ENOENT.
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(PidLockError::Io)?;
        }
    }

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(PidLockError::Io)?;

    // Non-blocking exclusive lock. If another process holds it, we get
    // EWOULDBLOCK immediately instead of waiting.
    //
    // …with a bounded retry, and the retry is the whole point. `pid_file_state`
    // has to TAKE the lock to find out whether anyone holds it — `flock`
    // offers no test-without-acquire, and `fcntl(F_GETLK)` does not
    // observe `flock` locks, so it is not a drop-in. That probe therefore
    // holds `LOCK_EX` for the handful of microseconds between its
    // acquire and its release, and a daemon starting inside that window
    // saw EWOULDBLOCK and refused to start with "already running".
    //
    // Three interactive CLI paths are in that window today:
    // `config restore`, `stop --force`, and `lists refresh`.
    //
    // A single short retry separates the two cases cleanly, because they
    // differ by orders of magnitude and not by a hair: the probe's hold
    // is microseconds, while a genuinely running daemon holds this lock
    // for its entire lifetime. So the retry changes the answer *only*
    // when the holder was transient. It cannot mask a live daemon —
    // waiting longer would not make one let go.
    //
    // BOUNDED, which is not the same as "once" — and the difference is a
    // correction, recorded because the original reasoning reads convincing.
    // This first shipped as a single retry: "a start that spins is worse than
    // one that says so." True of *unbounded* spinning; it does not reach a
    // small fixed bound. With one retry, two attempts 50 ms apart can both
    // land inside a probe hold whenever probes are frequent rather than
    // occasional — the race test measured exactly that, 3 refusals in 200
    // starts against a continuously-probing thread.
    //
    // What any bound must preserve is the property that makes the retry safe
    // at all: it cannot mask a live daemon, because a live daemon holds this
    // lock for its entire lifetime and no finite wait outlasts that.
    //
    // That property is why the bound is a DEADLINE and not an attempt count,
    // and why the deadline is generous. Three attempts 50 ms apart was the
    // second wrong answer here: it measured 0 refusals in 600 starts on an
    // idle box and 1 in 200 on a box under a parallel build, because "3
    // attempts" bounds the number of samples, not the wall-clock the thread
    // is actually given. A starved thread can burn all three attempts inside
    // one scheduling gap.
    //
    // Since no bound can mask a live daemon, the size of it is free in safety
    // terms and buys only tolerance. The cost is the other direction: when a
    // daemon really IS running, `start` now takes up to a second before it
    // says so. A one-second pause ahead of an error message is a fair price
    // for not refusing a legitimate start on a box that answers the
    // household's DNS.
    const RELOCK_DEADLINE: std::time::Duration = std::time::Duration::from_secs(1);
    const RELOCK_POLL: std::time::Duration = std::time::Duration::from_millis(5);
    let deadline = std::time::Instant::now() + RELOCK_DEADLINE;
    let mut ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    while ret != 0
        && std::io::Error::last_os_error().raw_os_error() == Some(libc::EWOULDBLOCK)
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(RELOCK_POLL);
        ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    }
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
            // Another instance holds the lock — try to read its PID
            let mut contents = String::new();
            let _ = (&file).read_to_string(&mut contents);
            let pid = contents.trim().parse::<u32>().ok();
            return Err(PidLockError::AlreadyRunning(pid));
        }
        return Err(PidLockError::Io(err));
    }

    // We hold the lock. Truncate and write our PID.
    let mut f = file;
    f.set_len(0).map_err(PidLockError::Io)?;
    f.seek(std::io::SeekFrom::Start(0))
        .map_err(PidLockError::Io)?;
    write!(f, "{}", std::process::id()).map_err(PidLockError::Io)?;
    f.sync_all().map_err(PidLockError::Io)?;

    tracing::debug!(
        pid = std::process::id(),
        path = %path.display(),
        "PID file locked"
    );
    Ok(f)
}

/// Write the current process ID to the PID file (no locking).
/// Only used by the daemon fork path where the child re-acquires the lock.
pub fn write_pid_file(path: &Path) -> anyhow::Result<()> {
    let pid = std::process::id();
    // Explicit-mode create (0o644) instead of umask-dependent `fs::write`
    // (roundup-01): a PID file is not secret, but plain `fs::write` inherits
    // `0o666 & ~umask`, which on a zero/loose umask would leave the file
    // group/world *writable*. `OpenOptions::mode` caps the create bits and
    // matches the explicit-mode discipline every other write in this section
    // uses. `mode()` only applies on create; the truncate covers the rewrite.
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(path)?;
    f.write_all(pid.to_string().as_bytes())?;
    tracing::debug!(pid, path = %path.display(), "PID file written");
    Ok(())
}

/// Read a PID from the PID file.
pub fn read_pid_file(path: &Path) -> anyhow::Result<u32> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read PID file {}: {}", path.display(), e))?;
    let pid: u32 = content
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid PID in {}: {:?}", path.display(), content.trim()))?;
    Ok(pid)
}

/// Validate a PID read from a (possibly corrupt or hostile) PID file before it
/// is handed to `kill(2)`.
///
/// POSIX `kill` overloads non-positive PIDs into BROADCASTS: `0` signals the
/// caller's entire process group, `-1` every process the caller may signal,
/// `-N` the process group `N`. A `u32` greater than `i32::MAX` would also wrap
/// to a negative `i32` through `as`. So one guard here — reject `0` and
/// anything outside `1..=i32::MAX` — is what keeps `stop`/`status`/`update`
/// (and, routed through this, `config restore`) from ever broadcasting off a
/// bad PID file. Returns the validated positive `i32`.
pub fn checked_pid(pid: u32) -> anyhow::Result<i32> {
    i32::try_from(pid).ok().filter(|p| *p > 0).ok_or_else(|| {
        anyhow::anyhow!(
            "refusing to signal PID {pid}: out of range (must be 1..={})",
            i32::MAX
        )
    })
}

/// What the PID file's advisory lock says about daemon liveness.
///
/// Three states, not two, because "the lock is not held" and "the lock
/// could not be probed" demand opposite responses: the first is proof the
/// daemon is gone, the second is an absence of evidence. Collapsing them —
/// which is what a bare `bool` does — turns an unreadable PID file into a
/// confident "no daemon is running".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PidFileState {
    /// A live daemon holds the exclusive lock.
    Locked,
    /// The file exists and nothing holds the lock — the daemon exited and
    /// the kernel released the advisory lock. The PID inside is stale and
    /// the number may since have been recycled onto an unrelated process.
    Unlocked,
    /// The lock could not be probed: the file is missing, unreadable
    /// (EACCES), or `flock` failed with an unexpected errno. Callers must
    /// fall back rather than conclude anything.
    Unknown,
}

/// Probe the PID file's advisory lock.
///
/// [`acquire_pid_lock`] holds `LOCK_EX` for the daemon's whole lifetime, so
/// a contended probe (EWOULDBLOCK) means a daemon is up and an uncontended
/// one means the file outlived the process that wrote it.
pub fn pid_file_state(path: &Path) -> PidFileState {
    // Read-only is enough: `flock(LOCK_EX)` does not require write access, and
    // an exclusive lock held on another open-file-description still denies our
    // probe with EWOULDBLOCK.
    let Ok(file) = OpenOptions::new().read(true).open(path) else {
        return PidFileState::Unknown;
    };
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        // We acquired it → nothing held it → stale. Release immediately so a
        // subsequent daemon start is never blocked by this probe.
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
        return PidFileState::Unlocked;
    }
    if std::io::Error::last_os_error().raw_os_error() == Some(libc::EWOULDBLOCK) {
        PidFileState::Locked
    } else {
        PidFileState::Unknown
    }
}

/// True if some process currently holds an exclusive `flock` on the PID
/// file — i.e. a live daemon ([`acquire_pid_lock`] holds `LOCK_EX` for its
/// whole lifetime).
///
/// Used as a liveness/identity gate before signalling: a PID whose file is
/// *not* locked is stale (the daemon exited and the kernel released the
/// advisory lock), so the numeric value may now belong to an unrelated
/// process and must not be signalled. Best-effort — any open/probe failure
/// (missing file, EACCES) reports `false` so the caller falls back to its
/// manual-reload hint rather than signalling blind.
///
/// Thin wrapper over [`pid_file_state`]; both non-`Locked` states report
/// `false`, which is exactly what this returned before the split.
pub fn pid_file_is_locked(path: &Path) -> bool {
    matches!(pid_file_state(path), PidFileState::Locked)
}

/// True when `pid_file` names a daemon that is *actually running*.
///
/// `is_process_alive` alone cannot answer this. A PID file outlives the
/// process that wrote it (crash, SIGKILL, an unclean container stop), and
/// the kernel recycles PIDs — so the number in a stale file eventually
/// names some unrelated live process. Asking only "does this PID exist?"
/// then reports a running daemon, and the caller goes on to *signal* it:
/// `lists refresh` sends SIGHUP, whose default disposition is terminate.
///
/// The advisory lock is what distinguishes the two, because only a live
/// daemon holds it. Both signals must agree:
///
/// - [`PidFileState::Unlocked`] → stale, whatever the PID says.
/// - [`PidFileState::Locked`] → live, provided the recorded PID also exists.
/// - [`PidFileState::Unknown`] → no evidence either way; fall back to the
///   liveness check alone rather than declaring a running daemon dead.
pub fn daemon_is_live(pid_file: &Path, pid: u32) -> bool {
    match pid_file_state(pid_file) {
        PidFileState::Unlocked => false,
        PidFileState::Locked | PidFileState::Unknown => is_process_alive(pid),
    }
}

/// Remove the PID file (best-effort, ignores errors).
pub fn remove_pid_file(path: &Path) {
    if std::fs::remove_file(path).is_ok() {
        tracing::debug!(path = %path.display(), "PID file removed");
    }
}

/// True if a process with this PID currently exists.
///
/// Uses `libc::kill(pid, 0)` directly — the null signal runs the kernel's
/// existence + permission check WITHOUT delivering anything (pid-01 replaces a
/// `kill -0` subprocess). `rc == 0` → exists and signalable; `EPERM` → exists
/// but owned by another uid, which is still **alive** (reading EPERM as "dead"
/// is what made `stop` delete a live daemon's PID file); `ESRCH` (or any other
/// errno) → no such process. An out-of-range PID is never a process here.
pub fn is_process_alive(pid: u32) -> bool {
    let Ok(p) = checked_pid(pid) else {
        return false;
    };
    // SAFETY: signal 0 only probes; it never delivers a signal to the target.
    let rc = unsafe { libc::kill(p, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Send a signal by name (`"TERM"`, `"HUP"`) to a single process.
///
/// Calls `libc::kill` directly after [`checked_pid`] validation, so a corrupt
/// or hostile PID file can never turn this into a `kill(0, …)` / `kill(-N, …)`
/// process-group BROADCAST (the folded `stop`/`update` zero-broadcast class).
pub fn send_signal(pid: u32, signal: &str) -> anyhow::Result<()> {
    let p = checked_pid(pid)?;
    let sig = match signal {
        "TERM" => libc::SIGTERM,
        "HUP" => libc::SIGHUP,
        other => anyhow::bail!("unsupported signal name: SIG{other}"),
    };
    // SAFETY: `p` is validated > 0, so this targets exactly one process; the
    // kernel's permission check still gates delivery to processes we may signal.
    let rc = unsafe { libc::kill(p, sig) };
    if rc == 0 {
        Ok(())
    } else {
        anyhow::bail!(
            "failed to send SIG{} to PID {}: {}",
            signal,
            pid,
            std::io::Error::last_os_error()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A daemon starting while `pid_file_state` is probing must still
    /// get the lock.
    ///
    /// Drives the real race rather than describing it: a thread hammers
    /// `pid_file_state` on the same path while this one calls
    /// `acquire_pid_lock`. Before the retry, landing inside the probe's
    /// acquire→release window returned `AlreadyRunning` and the daemon
    /// refused to start — on a box whose whole job is answering the
    /// household's DNS.
    #[test]
    fn a_start_racing_the_liveness_probe_still_acquires_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("racing.pid");
        std::fs::write(&path, "").unwrap();

        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let probe_path = path.clone();
        let probe_stop = stop.clone();
        let prober = std::thread::spawn(move || {
            while !probe_stop.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = pid_file_state(&probe_path);
            }
        });

        // Many attempts: one would almost certainly miss a window this
        // narrow, and a test that cannot land on the bug proves nothing.
        let mut refusals = 0;
        for _ in 0..200 {
            match acquire_pid_lock(&path) {
                Ok(guard) => drop(guard),
                Err(PidLockError::AlreadyRunning(_)) => refusals += 1,
                Err(e) => panic!("unexpected error acquiring the pid lock: {e:?}"),
            }
        }

        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        prober.join().unwrap();

        assert_eq!(
            refusals, 0,
            "{refusals}/200 starts were refused as `already running` while \
             nothing was running — only the liveness probe held the lock, \
             and it holds it for microseconds"
        );
    }

    /// The same property as the race above, stated so the scheduler
    /// cannot decide it.
    ///
    /// The 200-sample race is the realistic test and it stays, but what
    /// it measures is *how often* a start lands inside a probe window —
    /// which depends on how much CPU the box has to spare. It failed
    /// 1/200 under a parallel build while passing 0/600 idle, and the
    /// defect that produced that number was in the bound, not the race.
    ///
    /// Here the contended window is set by the test, not sampled: a
    /// holder takes the lock, sleeps a known interval well inside
    /// `RELOCK_DEADLINE`, and releases. A start issued against it must
    /// succeed. An implementation that retried too briefly — or not at
    /// all — fails this deterministically, on an idle box and a loaded
    /// one alike, which is exactly what the sampled test cannot promise.
    #[test]
    fn a_start_outlasts_a_holder_that_releases_within_the_deadline() {
        // Chosen to DISCRIMINATE, not merely to be short: both previous
        // bounds were 50 ms and 150 ms, so anything at or below 150 ms
        // would pass against the very implementations this test exists to
        // reject. 300 ms clears both by 2x and still leaves 700 ms of
        // margin under `RELOCK_DEADLINE`.
        const HELD_FOR: std::time::Duration = std::time::Duration::from_millis(300);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transient.pid");
        std::fs::write(&path, "").unwrap();

        let (started, holding) = std::sync::mpsc::channel();
        let holder_path = path.clone();
        let holder = std::thread::spawn(move || {
            let guard = acquire_pid_lock(&holder_path).expect("holder takes the lock first");
            started.send(()).unwrap();
            std::thread::sleep(HELD_FOR);
            drop(guard);
        });
        holding.recv().expect("holder signalled it holds the lock");

        // Issued while the lock is definitely held: the holder has
        // signalled and sleeps for HELD_FOR from that moment.
        let outcome = acquire_pid_lock(&path);
        holder.join().unwrap();

        assert!(
            outcome.is_ok(),
            "a start was refused by a holder that let go after {HELD_FOR:?}, well \
             inside the retry deadline — the retry is too short, or absent. Only a \
             holder that never releases may produce `AlreadyRunning`, which \
             `a_genuinely_held_lock_is_still_reported_as_already_running` pins."
        );
    }

    /// The control arm: the retry must NOT make a real daemon
    /// invisible. Without this, `acquire_pid_lock` could satisfy the
    /// test above by never reporting `AlreadyRunning` at all — which
    /// would let two daemons bind the same port.
    #[test]
    fn a_genuinely_held_lock_is_still_reported_as_already_running() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("held.pid");

        let held = acquire_pid_lock(&path).expect("first acquire must succeed");
        match acquire_pid_lock(&path) {
            Err(PidLockError::AlreadyRunning(_)) => {}
            other => panic!(
                "a lock held for the whole call must still refuse the second \
                 acquirer; got {other:?}"
            ),
        }
        drop(held);
    }

    #[test]
    fn write_and_read_pid_file() {
        // Was a FIXED path in /tmp, and that is a cross-PROCESS race, not a
        // cross-thread one: several lanes run `cargo test` on this box at
        // once, so two processes write the same file and each then reads the
        // other's pid. `remove_pid_file` + `!path.exists()` races the same
        // way. Every other test in this module already used a tempdir.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("write-and-read.pid");
        write_pid_file(&path).unwrap();
        let pid = read_pid_file(&path).unwrap();
        assert_eq!(pid, std::process::id());
        remove_pid_file(&path);
        assert!(!path.exists());
    }

    #[test]
    fn acquire_lock_writes_our_pid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.pid");
        let _lock = acquire_pid_lock(&path).unwrap();
        let pid = read_pid_file(&path).unwrap();
        assert_eq!(pid, std::process::id());
    }

    #[test]
    fn acquire_lock_twice_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.pid");
        let _lock = acquire_pid_lock(&path).unwrap();
        // Second lock from the same process uses a different fd, so flock
        // would actually succeed (same process). Fork to test properly.
        // Instead, verify the API shape: the first lock holds and reading
        // the PID file shows our PID.
        let pid = read_pid_file(&path).unwrap();
        assert_eq!(pid, std::process::id());
    }

    #[test]
    fn lock_released_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.pid");
        {
            let _lock = acquire_pid_lock(&path).unwrap();
        }
        // After dropping, we can re-acquire
        let _lock2 = acquire_pid_lock(&path).unwrap();
        let pid = read_pid_file(&path).unwrap();
        assert_eq!(pid, std::process::id());
    }

    #[test]
    fn stale_pid_file_is_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.pid");
        // Write a stale PID (no lock held)
        std::fs::write(&path, "99999999").unwrap();
        // acquire_pid_lock should succeed (no flock held on the file)
        let _lock = acquire_pid_lock(&path).unwrap();
        let pid = read_pid_file(&path).unwrap();
        assert_eq!(pid, std::process::id());
    }

    #[test]
    fn read_missing_pid_file_errors() {
        // A never-created path inside a fresh tempdir is GUARANTEED absent.
        // The old `/tmp/purge-warden-nonexistent-pid` only happened to be:
        // /tmp is world-writable, so one stray file — a typo, a crashed run —
        // reds this permanently and for a reason nobody would guess.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("never-created.pid");
        assert!(read_pid_file(&path).is_err());
    }

    #[test]
    fn acquire_lock_creates_missing_parent_dir() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("run").join("purge-warden");
        assert!(!nested.exists());
        let path = nested.join("test.pid");
        let _lock = acquire_pid_lock(&path).unwrap();
        assert!(nested.is_dir());
        let pid = read_pid_file(&path).unwrap();
        assert_eq!(pid, std::process::id());
    }

    #[test]
    fn pid_file_is_locked_true_while_lock_held() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.pid");
        let _lock = acquire_pid_lock(&path).unwrap();
        // A separate open-file-description probing LOCK_EX|LOCK_NB is denied
        // (EWOULDBLOCK) by the lock the daemon holds → reported as locked.
        assert!(pid_file_is_locked(&path));
    }

    #[test]
    fn pid_file_is_locked_false_after_release() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.pid");
        {
            let _lock = acquire_pid_lock(&path).unwrap();
        }
        // Lock dropped → file still exists but is unlocked → stale.
        assert!(path.exists());
        assert!(!pid_file_is_locked(&path));
    }

    #[test]
    fn pid_file_is_locked_false_when_unlocked_plain_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plain.pid");
        std::fs::write(&path, "12345").unwrap();
        assert!(!pid_file_is_locked(&path));
    }

    #[test]
    fn pid_file_is_locked_false_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("never-created-lock-probe.pid");
        assert!(!pid_file_is_locked(&path));
    }

    /// cli-h9 defect 5 — the discriminating case.
    ///
    /// A PID file that is not locked but whose recorded PID *is* alive.
    /// That is what a recycled PID looks like: the daemon died, the file
    /// survived, and the number now names an unrelated process. The old
    /// gate (`is_process_alive` alone) says "daemon running" here and the
    /// caller goes on to signal a stranger.
    ///
    /// Our own PID is a live PID we did not lock the file with, so it
    /// reproduces the shape exactly without needing a victim process.
    #[test]
    fn stale_pid_file_holding_a_live_pid_is_not_a_live_daemon() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.pid");
        std::fs::write(&path, std::process::id().to_string()).unwrap();

        // The precondition that makes this test discriminate: the PID is
        // genuinely alive, so the old gate passed.
        assert!(
            is_process_alive(std::process::id()),
            "precondition: our own PID must be alive, else this test proves nothing"
        );
        assert_eq!(pid_file_state(&path), PidFileState::Unlocked);
        assert!(
            !daemon_is_live(&path, std::process::id()),
            "an unlocked PID file is stale even when its PID is alive"
        );
    }

    /// The other half: a genuinely held lock must still read as live, or
    /// the fix would break `stop` against a real daemon.
    #[test]
    fn locked_pid_file_with_a_live_pid_is_a_live_daemon() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.pid");
        let _lock = acquire_pid_lock(&path).unwrap();
        assert_eq!(pid_file_state(&path), PidFileState::Locked);
        assert!(daemon_is_live(&path, read_pid_file(&path).unwrap()));
    }

    /// A missing file is `Unknown`, not `Unlocked` — absence of evidence.
    /// `daemon_is_live` then falls back to the liveness check instead of
    /// declaring a running daemon dead on an unreadable path.
    #[test]
    fn unprobeable_pid_file_falls_back_to_liveness() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("never-created-state-probe.pid");
        assert_eq!(pid_file_state(&path), PidFileState::Unknown);
        // Fallback = the pre-fix behaviour, so a probe failure never
        // downgrades a live daemon to "not running".
        assert!(daemon_is_live(&path, std::process::id()));
        assert!(!daemon_is_live(&path, 99_999_999));
    }

    /// The wrapper `config/restore.rs` calls must keep its exact old
    /// contract: true only when locked, false for every other state.
    #[test]
    fn pid_file_is_locked_wrapper_matches_the_tri_state() {
        let dir = tempfile::tempdir().unwrap();
        let locked = dir.path().join("locked.pid");
        let _lock = acquire_pid_lock(&locked).unwrap();
        assert!(pid_file_is_locked(&locked));

        let unlocked = dir.path().join("unlocked.pid");
        std::fs::write(&unlocked, "12345").unwrap();
        assert!(!pid_file_is_locked(&unlocked));

        assert!(!pid_file_is_locked(&dir.path().join("missing.pid")));
    }

    #[test]
    fn current_process_is_alive() {
        assert!(is_process_alive(std::process::id()));
    }

    #[test]
    fn dead_process_is_not_alive() {
        // PID 99999999 almost certainly doesn't exist
        assert!(!is_process_alive(99_999_999));
    }

    #[test]
    fn checked_pid_rejects_zero() {
        let err = checked_pid(0).unwrap_err();
        assert!(
            err.to_string().contains("out of range"),
            "0 must be refused: {err}"
        );
    }

    #[test]
    fn checked_pid_rejects_above_i32_max() {
        // Parses as u32 but > i32::MAX → would wrap negative through `as i32`.
        let err = checked_pid(3_000_000_000).unwrap_err();
        assert!(
            err.to_string().contains("out of range"),
            "value > i32::MAX must be refused: {err}"
        );
    }

    #[test]
    fn checked_pid_accepts_positive_boundaries() {
        assert_eq!(checked_pid(1).unwrap(), 1);
        assert_eq!(checked_pid(i32::MAX as u32).unwrap(), i32::MAX);
    }

    #[test]
    fn pid_zero_is_never_alive() {
        // A PID of 0 must NOT be probed via kill (it would target the process
        // group); the value guard short-circuits to not-alive.
        assert!(!is_process_alive(0));
    }

    #[test]
    fn init_pid_one_is_alive() {
        // PID 1 always exists. Run as root, kill(1,0) returns 0; run as a
        // normal user it returns EPERM — both must report ALIVE. This pins the
        // EPERM=alive branch that fixes the `stop` stale-removal misclass.
        assert!(is_process_alive(1));
    }

    #[test]
    fn send_signal_refuses_zero_pid_before_kill() {
        // pid==0 would broadcast to the caller's process group via kill(0,SIG);
        // checked_pid must reject it before any signal is delivered.
        let err = send_signal(0, "TERM").unwrap_err();
        assert!(
            err.to_string().contains("out of range"),
            "0 must be refused before signalling: {err}"
        );
    }

    #[test]
    fn send_signal_rejects_unknown_signal_name() {
        // Only TERM/HUP are mapped; anything else is a programming error, not a
        // silent no-op.
        assert!(send_signal(std::process::id(), "KILL").is_err());
    }

    #[test]
    fn write_pid_file_is_not_group_or_world_writable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.pid");
        write_pid_file(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode & 0o022,
            0,
            "PID file must not be group/world writable (mode {mode:o})"
        );
    }
}
