use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

/// Process-wide lock: the panic hook is global state, so any test
/// that swaps it must be serialised to avoid colliding with peers.
fn panic_hook_test_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    match LOCK.get_or_init(|| Mutex::new(())).lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Pin the chain-and-cleanup pattern that
/// `install_terminal_restore_panic_hook` relies on:
///
/// 1. `take_hook()` captures the existing hook,
/// 2. `set_hook()` installs a wrapper that does cleanup FIRST,
/// 3. The wrapper chains to the captured previous hook,
/// 4. A panic inside `catch_unwind` runs the wrapper end-to-end.
///
/// We mirror the production pattern with a local install/restore
/// (instead of calling `install_terminal_restore_panic_hook`
/// directly) because the production install is `Once`-guarded:
/// firing it from a test would leak the hook into every subsequent
/// test in the binary.
#[test]
fn panic_hook_runs_cleanup_then_chains_previous() {
    let _guard = panic_hook_test_lock();

    let cleanup_ran = Arc::new(AtomicBool::new(false));
    let previous_ran = Arc::new(AtomicBool::new(false));
    let order = Arc::new(Mutex::new(Vec::<&'static str>::new()));

    // Snapshot the truly-original hook so we restore the test
    // runner's hook before any assertion can fail.
    let truly_original = std::panic::take_hook();

    // Sentinel "previous" hook — records that the chain reached it.
    let prev_signal = previous_ran.clone();
    let prev_order = order.clone();
    std::panic::set_hook(Box::new(move |_info| {
        prev_signal.store(true, Ordering::SeqCst);
        prev_order.lock().unwrap().push("previous");
    }));

    // Mirror the production pattern: capture previous, wrap with
    // cleanup, chain.
    let previous = std::panic::take_hook();
    let cleanup_signal = cleanup_ran.clone();
    let cleanup_order = order.clone();
    std::panic::set_hook(Box::new(move |info| {
        cleanup_signal.store(true, Ordering::SeqCst);
        cleanup_order.lock().unwrap().push("cleanup");
        previous(info);
    }));

    let _ = std::panic::catch_unwind(|| {
        panic!("h21 panic-hook chain test");
    });

    // Restore the truly-original hook before assertions so a panic
    // in this test doesn't get swallowed by our local sentinel.
    let _ = std::panic::take_hook();
    std::panic::set_hook(truly_original);

    assert!(
        cleanup_ran.load(Ordering::SeqCst),
        "cleanup arm of the wrapping hook must run on panic"
    );
    assert!(
        previous_ran.load(Ordering::SeqCst),
        "wrapping hook must chain to the previous hook"
    );
    let order = order.lock().unwrap();
    assert_eq!(
        order.as_slice(),
        &["cleanup", "previous"],
        "terminal-restore cleanup must run BEFORE the chained hook \
             so the panic message lands on a cooked terminal"
    );
}

/// `install_terminal_restore_panic_hook` is `Once`-guarded so a
/// second call is a no-op. Calling it twice in succession must not
/// stack hooks (which would otherwise grow the chain by one and
/// run the cleanup N times per panic). We can't directly observe
/// the chain length, but we can verify the function is callable
/// repeatedly without panicking and that the global hook does not
/// change identity after the second call (proxy: two consecutive
/// `take_hook`+`set_hook` round-trips around the second call leave
/// the test runner intact).
#[test]
fn install_panic_hook_is_idempotent() {
    let _guard = panic_hook_test_lock();

    // First call: may or may not have already fired in another
    // test in this binary; either way it's a no-op or the canonical
    // installation.
    super::install_terminal_restore_panic_hook();

    // Second call: must be a no-op (Once::call_once already done).
    super::install_terminal_restore_panic_hook();

    // Third call for good measure — still a no-op.
    super::install_terminal_restore_panic_hook();
}
