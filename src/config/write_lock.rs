//! One writer at a time across the config tree — `flock(LOCK_EX)` held for a
//! whole read-modify-write, not merely for the write.
//!
//! # The defect this closes
//!
//! `target::promote_validated` is the single seat every config mutation goes
//! through, from the CLI verbs *and* from the daemon's IPC handlers
//! (`ipc/socket_server.rs` calls `write_value_validated` from **seven** `async
//! fn` handlers — device add/update/remove, tracking-config update, and profile
//! create/update/delete; counted, not estimated). It
//! runs four steps: snapshot the pre-edit bytes, validate the would-be-merged
//! tree, promote each slice by rename, and **on a mid-promotion I/O failure
//! restore the slices it already promoted** from the step-0 snapshot.
//!
//! That rollback is the hazard, and it is not a lost update — it is one
//! process erasing another's *committed* change:
//!
//! | | A stages `[X, Y]` | B stages `[X]` |
//! |---|---|---|
//! | 1 | snapshots X's bytes | |
//! | 2 | promotes X | |
//! | 3 | | promotes X — **B's change is now on disk and valid** |
//! | 4 | rename of Y fails (ENOSPC, EROFS, …) | |
//! | 5 | reverts X to its **step-1** snapshot | |
//!
//! At step 5 B's committed change is gone, B exited 0, and nothing anywhere
//! records that it happened. A serialising lock over steps 1–5 makes the
//! interleaving unrepresentable.
//!
//! The lesser sibling — A and B each computing a new value from their own
//! earlier read, so the second write drops the first's key — is **not** closed
//! by this lock, because the caller's read happens before it is taken. See
//! "What this does not close" below; it is a smaller defect and a separate
//! change.
//!
//! # Why the lock is NOT on the config file
//!
//! **`flock` locks an inode, and promotion replaces the target by `rename`,
//! which swaps the inode.** Locking `config.toml` would give A the lock on the
//! old inode, and B — arriving after A's rename — the lock on the *new* one.
//! Both would proceed, hold what looks like an exclusive lock, and interleave
//! exactly as before.
//!
//! That failure mode is silent and it passes a naive test (one process locks,
//! a second blocks) because the second process only stops blocking once a
//! rename has happened. `rr-concurrent-edit-locking` warns that "wrong locking
//! is worse than the rare lost update" — this is the specific way it goes
//! wrong here. The lock therefore lives on a **side file that is never
//! renamed, never promoted and never part of the config**.
//!
//! # Why `flock` and not the marker file `config/backup.rs` uses
//!
//! That module's `.lock` is a file whose body is `pid:timestamp`, reclaimed
//! when older than `STALE_LOCK_AGE` (5 minutes). It is the right shape there —
//! it guards a long-running archive job and must survive across processes that
//! are not each other's children.
//!
//! It is the wrong shape here. A staleness heuristic **steals the lock from a
//! slow-but-live holder**: a full config load on a box merging a large tree
//! can outlast any age bound, and the moment it does, the guarantee inverts
//! into two concurrent writers who each believe they are alone. `flock` needs
//! no heuristic — the kernel releases it when the holder's descriptor closes,
//! including on `SIGKILL`, so a crashed holder never leaves a lock behind and
//! a live one is never overruled.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use anyhow::Context;

/// File name of the config-tree write lock, under the master's directory.
///
/// Not a `.toml` and not inside a `.d/` directory, so no `includes` glob can
/// match it and the loader never sees it as a slice. A dotfile also keeps it
/// out of an operator's `ls`.
const WRITE_LOCK_FILE: &str = ".warden-config.lock";

/// How long to wait for another writer to finish before giving up.
///
/// A **deadline**, not an attempt count, for the reason `pid.rs` documents at
/// length: an attempt count bounds the number of samples taken, not the
/// wall-clock a starved thread is actually given, so under a parallel build it
/// can burn every attempt inside one scheduling gap.
///
/// Unlike the PID lock, this one is **not** held for a process lifetime — a
/// holder keeps it for one mutation, which is a config load plus a few
/// renames. So waiting is the correct behaviour rather than a mask for a live
/// daemon: the operator's `warden device add` should queue behind another
/// writer, not fail. The bound exists only so a wedged holder cannot hang the
/// CLI forever, and 30 s is chosen to sit well above a slow full-tree load on
/// a small box while still being a wait a human recognises as broken.
const LOCK_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);
/// Poll interval while waiting. Cheap: `flock(LOCK_NB)` on a held lock is a
/// single syscall that fails immediately.
const LOCK_POLL: std::time::Duration = std::time::Duration::from_millis(10);

/// An exclusive claim on the config tree, released when dropped.
///
/// Holding the guard is the whole contract — there is no `unlock` to forget.
/// Dropping it closes the descriptor, which is what releases the `flock`, so
/// an early `return` or a `?` inside the critical section cannot leave the
/// lock held.
#[must_use = "the lock is released as soon as the guard is dropped, so a \
              guard that is not bound to a variable protects nothing"]
#[derive(Debug)]
pub struct ConfigWriteLock {
    /// Kept solely to own the descriptor: the `flock` lives on this fd and
    /// dies with it.
    _file: File,
    path: PathBuf,
}

impl ConfigWriteLock {
    /// The lock file this guard holds. Diagnostics only.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Where the lock for `master`'s tree lives.
///
/// One lock per config **directory**, not per file: a single mutation can
/// stage several slices (`rule add`, `tags rename`), and a per-file lock would
/// let two such mutations interleave across each other's files while each held
/// every lock it thought it needed.
///
/// # The two "no directory" cases
///
/// Only one of them is what a naive `unwrap_or(".")` handles:
///
/// - `Path::new("config.toml").parent()` is `Some("")`, **not** `None` — a bare
///   file name has an *empty* parent. An `unwrap_or_else` alone is dead code
///   for exactly the case it looks like it was written for, and the empty path
///   would flow into `join`, yielding `.warden-config.lock` by accident rather than by
///   decision. It happens to resolve in the working directory, which is why
///   the bug would never have surfaced as a failure — only as a reader
///   believing a guard fired when it did not.
/// - `parent()` is `None` only for a root (`/`), where `.` is the honest
///   answer.
///
/// Both are normalised to `.` so the returned path is explicit at the call
/// site and in any diagnostic that prints it.
pub fn lock_path_for(master: &Path) -> PathBuf {
    let dir = match master.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    dir.join(WRITE_LOCK_FILE)
}

/// The blocking retry itself: `LOCK_EX | LOCK_NB` polled against a deadline.
///
/// Returns `flock`'s last return value; the caller reads `errno` to tell a
/// timeout from a real failure.
fn flock_until(file: &File, wait: std::time::Duration) -> i32 {
    let deadline = std::time::Instant::now() + wait;
    let mut ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    while ret != 0
        && std::io::Error::last_os_error().raw_os_error() == Some(libc::EWOULDBLOCK)
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(LOCK_POLL);
        ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    }
    ret
}

/// [`flock_until`], moved off the reactor when there is one.
///
/// # Why this exists
///
/// The daemon reaches this seat from **seven `async fn` handlers** in
/// `ipc/socket_server.rs`, none of them inside `spawn_blocking` — verified, not
/// assumed. So the `sleep` in [`flock_until`] would run on a tokio worker
/// thread and, under contention, park it for up to [`LOCK_DEADLINE`], starving
/// every other task scheduled on it. Uncontended the cost is one syscall and
/// this is all moot; contention is the entire reason the lock exists.
///
/// `_docs/features/config_edit_locking.md` §3.2.3 called this out before the
/// code existed: *"`flock` … must not be held across an await point on a
/// blocking-thread model"*. This is the containment for it that does not
/// require restructuring seven async handlers.
///
/// **The flavour check is not defensive padding.** `block_in_place` **panics**
/// on a `current_thread` runtime, and this crate has `current_thread` tests
/// (`resource_budget/sampler.rs`, `tracking/query_log.rs`). Calling it
/// unconditionally would turn a lock acquisition into a panic in exactly the
/// tests least likely to be run against a contended lock.
fn wait_for_flock(file: &File, wait: std::time::Duration) -> i32 {
    use tokio::runtime::{Handle, RuntimeFlavor};
    match Handle::try_current() {
        Ok(h) if h.runtime_flavor() == RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(|| flock_until(file, wait))
        }
        // No runtime at all (the CLI, and every sync test), or a
        // single-threaded one where there is no other worker to protect.
        _ => flock_until(file, wait),
    }
}

/// Take the config-tree write lock, waiting up to [`LOCK_DEADLINE`].
///
/// # Errors
///
/// - the lock file cannot be created (the config directory is unwritable);
/// - another writer held the lock for longer than the deadline;
/// - `flock` failed for a reason other than "would block".
///
/// A refusal names the lock path, because an operator who hits it needs to
/// know *which* tree is contended when several `--config` roots are in play.
pub fn acquire(master: &Path) -> anyhow::Result<ConfigWriteLock> {
    acquire_with_deadline(master, LOCK_DEADLINE)
}

/// [`acquire`] with the wait bound as a parameter.
///
/// Exists so the contended path — the poll loop and the refusal it ends in —
/// is testable in milliseconds instead of [`LOCK_DEADLINE`]. Without it that
/// path has no coverage at all: a test can prove `flock` refuses a second
/// claim, which says nothing about whether *this function* waits, gives up at
/// the right time, or produces the error an operator can act on.
fn acquire_with_deadline(
    master: &Path,
    wait: std::time::Duration,
) -> anyhow::Result<ConfigWriteLock> {
    let path = lock_path_for(master);

    // Mirror `promote_validated` step 1, which creates a new slice's parent
    // before writing it: on a fresh tree the directory may not exist yet, and
    // the lock has to be takeable there too or `init` cannot run.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create config directory {}", parent.display()))?;
    }

    // 0o600: the lock carries no content, but a world-writable one in the
    // config directory would let any local user block every config mutation.
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("open config write lock {}", path.display()))?;

    let ret = wait_for_flock(&file, wait);

    if ret != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
            anyhow::bail!(
                "another warden process has been writing this config for over {}s \
                 ({}).\n\
                 Nothing was written. If no other `warden` command and no daemon \
                 reload is running, the holder has wedged — check with \
                 `fuser {}` and retry.",
                wait.as_secs(),
                path.display(),
                path.display()
            );
        }
        return Err(
            anyhow::Error::new(err).context(format!("lock config tree via {}", path.display()))
        );
    }

    Ok(ConfigWriteLock { _file: file, path })
}

// ── What this does not close ────────────────────────────────────────
//
// The lock starts inside `promote_validated`, and the caller's READ happened
// before that — a verb loads the config, edits a `Value`, then calls the
// seat. So two mutations to *different keys of the same file* can still lose
// one:
//
//   A loads → B loads → A promotes → B promotes (from its pre-A view)
//
// B's file is valid and B's own key is right; A's key is gone. That is the
// "rare lost update" the task names, and it is strictly less severe than the
// rollback above: no committed-and-then-erased state, no silent revert of a
// third party, and the operator can see it by re-reading.
//
// Closing it needs the baseline the caller read to travel to the seat, so the
// promotion can refuse when the file moved underneath — optimistic
// concurrency, not a wider lock. Widening the lock to the caller instead would
// mean taking it at ~40 verb entry points and inviting a self-deadlock the
// moment one verb calls another. That is a separate change, and it is not
// pretended here.

#[cfg(test)]
mod tests {
    use super::*;

    /// The lock is a sibling of the master, not the master itself.
    ///
    /// Pins the decision the module header argues: locking the config file
    /// would be defeated by the rename that promotes it.
    #[test]
    fn the_lock_is_a_side_file_never_the_config_itself() {
        let master = Path::new("/etc/purge-warden/config.toml");
        let lock = lock_path_for(master);
        assert_ne!(lock, master, "the lock must never BE the promoted file");
        assert_eq!(lock, Path::new("/etc/purge-warden/.warden-config.lock"));
    }

    /// A bare file name locks in the working directory, EXPLICITLY.
    ///
    /// This test found the real bug: `Path::new("config.toml").parent()` is
    /// `Some("")`, so the original `unwrap_or_else(|| Path::new("."))` never
    /// fired here and the empty parent flowed into `join`. The result
    /// (`.warden-config.lock`) resolved correctly by accident, so nothing would have
    /// broken — the defect was a guard that read as handling a case it did not
    /// touch. Asserting the `./` prefix is what makes the normalisation
    /// deliberate rather than incidental.
    #[test]
    fn a_bare_file_name_locks_in_the_current_directory_explicitly() {
        assert_eq!(
            lock_path_for(Path::new("config.toml")),
            Path::new("./.warden-config.lock"),
            "an empty parent must normalise to `.`, not flow into join as \"\""
        );
    }

    /// A root master also normalises, and by the OTHER branch — `parent()` is
    /// genuinely `None` here. Keeps both arms of the match covered, so a
    /// "simplification" back to a bare `unwrap_or` breaks a test.
    #[test]
    fn a_root_master_normalises_through_the_none_arm() {
        assert_eq!(
            lock_path_for(Path::new("/")),
            Path::new("./.warden-config.lock")
        );
    }

    /// The lock name must not be reachable by an `includes` glob.
    ///
    /// `*.toml` and `*.d/*.toml` are the shapes the loader accepts; a lock
    /// that matched either would be parsed as a config slice and the tree
    /// would fail to load the moment it was taken.
    #[test]
    fn the_lock_name_is_not_a_toml_and_not_in_a_dot_d() {
        assert!(!WRITE_LOCK_FILE.ends_with(".toml"));
        assert!(!WRITE_LOCK_FILE.contains(".d/"));
        assert!(WRITE_LOCK_FILE.starts_with('.'));
    }

    /// Two guards over the same tree cannot coexist — the second waits, and
    /// with the first still held it times out rather than proceeding.
    ///
    /// The deadline is shortened for the test by contending from a thread and
    /// asserting the ORDER of events, not by waiting 30 s: the second acquire
    /// must not return while the first guard is alive.
    #[test]
    fn a_second_writer_does_not_get_the_lock_while_the_first_holds_it() {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        std::fs::write(&master, "").unwrap();

        let first = acquire(&master).unwrap();

        // A non-blocking probe from a SEPARATE process would be the strict
        // test, but `flock` is per-open-file-description: a second `open` in
        // this same process contends correctly, which is what the seat does
        // when the daemon and a CLI verb race.
        let path = lock_path_for(&master);
        let probe = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let rc = unsafe { libc::flock(probe.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_ne!(rc, 0, "a second exclusive claim must not succeed");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EWOULDBLOCK),
            "contention must present as EWOULDBLOCK, not another errno"
        );

        drop(first);

        // Released on drop, with no explicit unlock anywhere.
        let rc = unsafe { libc::flock(probe.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(rc, 0, "dropping the guard must release the lock");
    }

    /// The contended path: `acquire` WAITS, then refuses, and the refusal
    /// carries what the operator needs.
    ///
    /// Covers what the raw-`flock` probe above cannot — that this function
    /// polls rather than failing on the first `EWOULDBLOCK`, that it stops at
    /// its deadline rather than hanging, and that the message names the lock
    /// path. A `bail!` whose text nobody asserts drifts into uselessness.
    #[test]
    fn a_contended_lock_waits_then_refuses_naming_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        std::fs::write(&master, "").unwrap();

        let _held = acquire(&master).unwrap();

        let waited = std::time::Duration::from_millis(120);
        let started = std::time::Instant::now();
        let err = acquire_with_deadline(&master, waited)
            .expect_err("a second acquire must not succeed while the first is held");
        let elapsed = started.elapsed();

        assert!(
            elapsed >= waited,
            "acquire returned after {elapsed:?} but was given {waited:?} — it is not \
             waiting, it is failing on the first EWOULDBLOCK"
        );
        let msg = format!("{err:#}");
        assert!(
            msg.contains(".warden-config.lock"),
            "the refusal must name the lock path; got: {msg}"
        );
        assert!(
            msg.contains("Nothing was written"),
            "the refusal must say the write did not happen; got: {msg}"
        );
    }

    /// Acquiring from inside a MULTI-THREADED tokio runtime must not panic.
    ///
    /// The daemon's seven mutation handlers are `async fn` on the default
    /// `#[tokio::main]` runtime, so this is the production path, and
    /// `block_in_place` is only legal there. Uncontended, so it exercises the
    /// dispatch rather than the wait.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn acquiring_inside_a_multi_thread_runtime_works() {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        let guard = acquire(&master).expect("block_in_place path must succeed");
        assert!(guard.path().exists());
    }

    /// And from a CURRENT-THREAD runtime, where `block_in_place` would panic.
    ///
    /// This crate has `current_thread` tests elsewhere, so the flavour check in
    /// `wait_for_flock` is load-bearing rather than defensive: without it this
    /// test panics instead of failing an assertion.
    #[tokio::test(flavor = "current_thread")]
    async fn acquiring_inside_a_current_thread_runtime_does_not_panic() {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        let guard = acquire(&master).expect("current_thread path must not panic");
        assert!(guard.path().exists());
    }

    /// The lock file is created 0o600, not world-writable.
    #[test]
    fn the_lock_file_is_not_world_writable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        let guard = acquire(&master).unwrap();
        let mode = std::fs::metadata(guard.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "lock mode was {mode:o}");
    }

    /// Acquiring on a tree whose directory does not exist yet must work —
    /// `init` runs before anything is on disk.
    #[test]
    fn a_tree_whose_directory_is_absent_can_still_be_locked() {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("not/created/yet/config.toml");
        let guard = acquire(&master).unwrap();
        assert!(guard.path().exists());
    }
}
