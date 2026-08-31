use super::TerminalGuard;
use std::cell::Cell;

thread_local! {
    /// Per-thread so the two tests below never race each other, and
    /// reset at the top of each so a single-threaded run
    /// (`--test-threads=1`) doesn't accumulate across them.
    static RESTORE_CALLS: Cell<usize> = const { Cell::new(0) };
}

fn count_restore() {
    RESTORE_CALLS.with(|c| c.set(c.get() + 1));
}

fn restore_calls() -> usize {
    RESTORE_CALLS.with(|c| c.get())
}

/// tui-06 regression. `run` arms the guard right after `enable_raw_mode`,
/// then makes three fallible calls (`execute!(EnterAlternateScreen, …)`,
/// `Terminal::new`, `terminal.clear`). Before the guard, an `Err` from any
/// of them propagated through `?` straight past the hand-written cleanup
/// block at the end of the function and left the operator's shell in raw +
/// alt-screen mode. This pins the shape that makes that impossible: once
/// the guard is armed, an early `?` return still restores.
///
/// The failure is injected rather than provoked from a real tty because
/// the trigger is an ioctl failing on a *live* terminal, which `cargo test`
/// (no tty at all) cannot reproduce.
#[test]
fn terminal_guard_restores_on_early_question_mark_return() {
    fn setup_fails_after_arming() -> anyhow::Result<()> {
        let _restore_guard = TerminalGuard::with_restore(count_restore);
        // Stand-in for `Terminal::new(backend)?` — the size query failing
        // on an exotic pty.
        anyhow::bail!("ioctl failed on a live tty");
    }

    RESTORE_CALLS.with(|c| c.set(0));
    assert!(setup_fails_after_arming().is_err());
    assert_eq!(
        restore_calls(),
        1,
        "an `?` early-return between arming the guard and the end of the \
             scope must still restore the terminal — that skip IS tui-06"
    );
}

/// The clean path keeps working: exactly one restore, not zero (the guard
/// replaced the old manual cleanup block) and not two (a `let _ = ` binding
/// would drop it on the spot and restore twice — once early, once at exit).
#[test]
fn terminal_guard_restores_once_on_clean_return() {
    fn setup_succeeds() -> anyhow::Result<()> {
        let _restore_guard = TerminalGuard::with_restore(count_restore);
        Ok(())
    }

    RESTORE_CALLS.with(|c| c.set(0));
    assert!(setup_succeeds().is_ok());
    assert_eq!(
        restore_calls(),
        1,
        "the clean return must restore exactly once"
    );
}
