//! Terminal event reader — bridges crossterm events into an async channel.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event as CtEvent, KeyEvent};
use tokio::sync::mpsc;

/// How long the reader sleeps between checks while parked across the `$EDITOR`
/// handoff (mod-02). Short enough that resume is near-instant, long enough not
/// to spin a core while the operator edits.
const PARK_POLL: Duration = Duration::from_millis(20);

/// Events consumed by the main TUI loop.
#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    /// A key was pressed.
    Key(KeyEvent),
    /// A bracketed-paste payload arrived as one atomic chunk (rather than a
    /// storm of synthetic key events). Routed to the focused text buffer only;
    /// inert in confirm stages. See `tui::handle_paste`.
    Paste(String),
    /// Tick — triggers a render cycle and data poll check.
    Tick,
    /// Terminal was resized.
    Resize,
    /// The controlling terminal hung up (closed pty). The main loop must break
    /// and exit instead of lingering. Raised by the hangup watchdog — see
    /// [`spawn_event_reader`].
    Eof,
}

/// Polls `fd` for a hangup condition. Returns `Some(true)` if the fd has hung
/// up (`POLLHUP`/`POLLERR`/`POLLNVAL`), `Some(false)` if it is still alive (the
/// timeout elapsed with no hangup), or `None` if `poll()` itself failed.
///
/// `events` is left at 0: `POLLHUP`/`POLLERR`/`POLLNVAL` are reported in
/// `revents` regardless of the requested mask, so the watchdog never wakes on
/// routine input — only on the timeout or an actual hangup.
///
/// A `poll()` interrupted by a signal is **not** a failure — see
/// [`hangup_from_poll_error`].
fn poll_hangup(fd: i32, timeout_ms: i32) -> Option<bool> {
    let mut pfd = libc::pollfd {
        fd,
        events: 0,
        revents: 0,
    };
    // SAFETY: `pfd` is a single valid `pollfd` that outlives the call.
    let n = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    if n < 0 {
        // `event-poll-hangup-eintr-spurious-eof`: EINTR is not a failure.
        // `poll()` returns -1/EINTR whenever a signal is delivered to this
        // process while the watchdog is parked in it, and the caller maps
        // `None` to `Event::Eof`, which tears the dashboard down. So a
        // signal — any signal — would look exactly like the terminal
        // hanging up.
        //
        // Latent rather than live today only because the process installs
        // a handler for SIGHUP alone; the defect is one `signal()` call
        // away from being reachable, and its symptom (the TUI exits on an
        // unrelated signal) reads as a hang-up bug rather than as this.
        //
        // Reported as "still alive": the retry is the caller's next loop
        // iteration, which re-polls immediately. Returning `Some(false)`
        // costs at most one extra pass; returning `None` costs the
        // session.
        return hangup_from_poll_error(&std::io::Error::last_os_error());
    }
    Some(pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0)
}

/// Classify a failed `poll()` into the watchdog's verdict.
///
/// Split out of [`poll_hangup`] so it can be tested at all: the live path
/// needs a signal delivered while the thread is parked inside `poll()`,
/// which is not something a test suite can arrange without racing.
///
/// `Some(false)` — "still alive" — for `EINTR` only. Everything else keeps
/// the old `None`, because a `poll()` that fails for a reason other than a
/// signal genuinely has lost the fd.
fn hangup_from_poll_error(err: &std::io::Error) -> Option<bool> {
    if err.kind() == std::io::ErrorKind::Interrupted {
        Some(false)
    } else {
        None
    }
}

/// One reader-loop emission: an optional input event to forward, plus whether a
/// wall-clock tick is also due this iteration. Returning both lets the loop
/// forward a key *and* a tick from the same pass so ticks never starve under a
/// sustained input burst (a long paste, held auto-repeat) — the original
/// idle-only tick stalled `poll_active_leaf` + the heartbeat dot until typing
/// paused.
#[derive(Debug, PartialEq, Eq)]
struct ReaderEmit {
    event: Option<Event>,
    tick: bool,
}

/// Pure classification of one reader iteration, factored out so the tick
/// scheduling is unit-testable without a real tty or a clock: the caller injects
/// `tick_due` (computed from `last_tick`) and the read outcome.
///
/// `read` is `None` when `poll` timed out (no input), `Some(ev)` when an event
/// was read. Mouse/focus events are ignored; a due tick still rides along.
fn classify(read: Option<CtEvent>, tick_due: bool) -> ReaderEmit {
    let event = match read {
        Some(CtEvent::Key(key)) => Some(Event::Key(key)),
        Some(CtEvent::Resize(_, _)) => Some(Event::Resize),
        Some(CtEvent::Paste(s)) => Some(Event::Paste(s)),
        // Mouse/focus — ignored.
        Some(_) => None,
        // poll timed out — no input event this iteration.
        None => None,
    };
    ReaderEmit {
        event,
        tick: tick_due,
    }
}

/// Spawns the background machinery that feeds the main TUI loop, returning the
/// receiver. Two threads are started:
///
/// * The **reader** runs crossterm's blocking `poll`/`read` and forwards keys,
///   resizes, and ticks.
/// * The **hangup watchdog** independently `poll()`s the terminal fd and sends
///   [`Event::Eof`] when it hangs up.
///
/// The watchdog is necessary because crossterm's reader can wedge in an
/// internal busy-loop when the controlling pty dies: a closed pty master leaves
/// the slave permanently *readable* (`POLLHUP`) while yielding zero bytes, and
/// crossterm neither returns nor surfaces an error — so loop-level detection in
/// the reader is impossible. This is the orphaned-dashboard bug: on an SSH/tmux
/// drop the login shell exits without forwarding `SIGHUP` (Debian bash
/// `huponexit` is off), `warden` is reparented to PID 1 with a closed pty, and
/// the reader pegs a core forever. The watchdog catches that out of band, in
/// well under a second.
pub fn spawn_event_reader(
    tick_rate: Duration,
    suspended: Arc<AtomicBool>,
    parked: Arc<AtomicBool>,
) -> mpsc::UnboundedReceiver<Event> {
    let (tx, rx) = mpsc::unbounded_channel();

    // Hangup watchdog — see the fn-level docs for why this must be separate
    // from the reader thread.
    let watchdog_tx = tx.clone();
    std::thread::spawn(move || loop {
        match poll_hangup(libc::STDIN_FILENO, 500) {
            // Hung up, or poll itself failed — either way the terminal is gone.
            None | Some(true) => {
                let _ = watchdog_tx.send(Event::Eof);
                return;
            }
            // Still alive. Stop watching once the app has quit normally (the
            // receiver is dropped when the main loop breaks).
            Some(false) => {
                if watchdog_tx.is_closed() {
                    return;
                }
            }
        }
    });

    // crossterm's event::poll is blocking, so run it in a dedicated thread.
    std::thread::spawn(move || {
        // Wall-clock tick scheduler. The poll timeout shrinks toward the next
        // tick deadline, and a tick is emitted whenever the window has elapsed
        // regardless of whether input was read — so a sustained input burst
        // cannot starve `Event::Tick` (and with it the active-leaf poll + the
        // heartbeat dot). Single tick-emit site → no double-emit on the idle path.
        let mut last_tick = Instant::now();
        loop {
            // Editor handoff (mod-02): while suspended, the $EDITOR owns the tty.
            // Park — stop calling event::poll/read so no byte is consumed and no
            // Eof is synthesised — and ack via `parked` so the editor flow knows
            // it is safe to leave raw mode. The hangup watchdog keeps running, so
            // a pty death during editing is still caught.
            if suspended.load(Ordering::Acquire) {
                if tx.is_closed() {
                    return; // receiver gone while parked — exit, don't spin
                }
                parked.store(true, Ordering::Release);
                std::thread::sleep(PARK_POLL);
                continue;
            }
            parked.store(false, Ordering::Release);

            let timeout = tick_rate.saturating_sub(last_tick.elapsed());
            let ready = match event::poll(timeout) {
                Ok(ready) => ready,
                // poll() errored — the terminal fd is unusable.
                Err(_) => {
                    let _ = tx.send(Event::Eof);
                    return;
                }
            };
            let read = if ready {
                match event::read() {
                    Ok(ev) => Some(ev),
                    // read() failed after poll said ready — terminal gone (EOF).
                    Err(_) => {
                        let _ = tx.send(Event::Eof);
                        return;
                    }
                }
            } else {
                None
            };

            let tick_due = last_tick.elapsed() >= tick_rate;
            let emit = classify(read, tick_due);
            if let Some(ev) = emit.event {
                if tx.send(ev).is_err() {
                    return; // receiver dropped — TUI is shutting down
                }
            }
            if emit.tick {
                if tx.send(Event::Tick).is_err() {
                    return;
                }
                last_tick = Instant::now();
            }
        }
    });

    rx
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pipe whose write end is closed reports `POLLHUP` on the read end — the
    /// same condition a dead pty raises. Exercises the real `poll()` path that
    /// the watchdog relies on, covering both the alive (timeout) and hung-up
    /// outcomes.
    ///
    /// Two environment hazards, both measured rather than assumed. Neither is a
    /// defect in `poll_hangup`; the rev-2607 pty smoke proved the watchdog
    /// itself sound against a real closed pty.
    ///
    /// 1. A `libc::pipe` fd carries no `O_CLOEXEC`, so any `fork`+`exec`
    ///    elsewhere in this test binary — `tar` in the config backup/restore
    ///    tests, `touch` in the query-log tests — inherits a copy of the write
    ///    end. The pipe then still has a writer once we close ours, no
    ///    `POLLHUP` is raised, and the hangup arm below times out. That is the
    ///    historical flake at this line. Measured directly: holding an
    ///    inherited plain-pipe write end in a live child made `poll_hangup`
    ///    return `Some(false)` after the full timeout, while the same sequence
    ///    on an `O_CLOEXEC` pipe returned `Some(true)` at once. Hence `pipe2`.
    ///
    /// 2. `O_CLOEXEC` closes the fd at `execve`, so a child already forked but
    ///    not yet exec'd still holds it. Under CPU saturation that pre-exec gap
    ///    is scheduler-bound rather than microseconds (measured: 1280 of 2400
    ///    rounds still missed the hangup under a 9300-spawn fork storm), so the
    ///    hangup arm retries to a deadline instead of trusting one 50 ms poll.
    ///
    /// The retry does not weaken the assertion. `POLLHUP` on a writer-less pipe
    /// is level-triggered and permanent, so a correct `poll_hangup` answers
    /// `Some(true)` on its first call, and a broken one — wrong `revents` mask,
    /// wrong `Option` mapping, `poll` misuse — answers `Some(false)`/`None`
    /// forever. The deadline only bounds how long a real regression takes to go
    /// red. The alive arm keeps its single strict poll, so an implementation
    /// that reports a hangup spuriously is still caught on the spot; an extra
    /// inherited writer can only make that arm more true, never falsely true.
    #[test]
    fn poll_hangup_detects_closed_peer() {
        let mut fds = [0i32; 2];
        // SAFETY: `fds` is a valid 2-element array for the pipe2 call.
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        let (read_fd, write_fd) = (fds[0], fds[1]);

        // Write end open, nothing buffered → no hangup, just the timeout.
        assert_eq!(
            poll_hangup(read_fd, 50),
            Some(false),
            "a pipe with a live writer must not report a hangup"
        );

        // Close the write end → the read end hangs up.
        // SAFETY: `write_fd` is a valid open fd.
        unsafe { libc::close(write_fd) };

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut observed = poll_hangup(read_fd, 50);
        while observed != Some(true) && Instant::now() < deadline {
            observed = poll_hangup(read_fd, 50);
        }
        // SAFETY: `read_fd` is still valid. Closed before the assert so a
        // failure does not also leak the fd into the rest of the suite.
        unsafe { libc::close(read_fd) };

        assert_eq!(
            observed,
            Some(true),
            "a pipe with no writers must report POLLHUP"
        );
    }

    use crossterm::event::{KeyCode, KeyModifiers};

    fn key_event(c: char) -> CtEvent {
        CtEvent::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE))
    }

    #[test]
    fn classify_forwards_key_without_tick_when_not_due() {
        let emit = classify(Some(key_event('a')), false);
        assert_eq!(
            emit.event,
            Some(Event::Key(KeyEvent::new(
                KeyCode::Char('a'),
                KeyModifiers::NONE
            )))
        );
        assert!(!emit.tick);
    }

    /// The event-02 starvation regression: under sustained input a due tick must
    /// still ride along the *same* iteration as the key, not wait for an idle
    /// gap. Proves `poll_active_leaf` + the heartbeat keep firing while typing.
    #[test]
    fn classify_emits_key_and_tick_together_when_due() {
        let emit = classify(Some(key_event('a')), true);
        assert!(emit.event.is_some());
        assert!(emit.tick);
    }

    #[test]
    fn classify_idle_timeout_emits_only_tick() {
        let emit = classify(None, true);
        assert_eq!(emit.event, None);
        assert!(emit.tick);
    }

    #[test]
    fn classify_ignored_event_still_ticks_when_due() {
        // Focus events are ignored, but a due tick must not be dropped with them.
        let emit = classify(Some(CtEvent::FocusGained), true);
        assert_eq!(emit.event, None);
        assert!(emit.tick);
    }

    #[test]
    fn classify_ignored_event_emits_nothing_when_not_due() {
        let emit = classify(Some(CtEvent::FocusLost), false);
        assert_eq!(
            emit,
            ReaderEmit {
                event: None,
                tick: false
            }
        );
    }

    #[test]
    fn classify_resize_forwarded() {
        let emit = classify(Some(CtEvent::Resize(80, 24)), false);
        assert_eq!(emit.event, Some(Event::Resize));
        assert!(!emit.tick);
    }

    #[test]
    fn classify_forwards_paste_atomically() {
        let emit = classify(Some(CtEvent::Paste("a.example.com".to_string())), false);
        assert_eq!(emit.event, Some(Event::Paste("a.example.com".to_string())));
        assert!(!emit.tick);
    }

    /// mod-02: when started already suspended the reader must park (ack via
    /// `parked`) without ever reading the tty. Starting suspended means the
    /// park gate trips on the very first iteration, so this is tty-independent
    /// — it exercises the suspend→park ack the $EDITOR handoff relies on.
    #[test]
    fn reader_parks_when_suspended() {
        let suspended = Arc::new(AtomicBool::new(true));
        let parked = Arc::new(AtomicBool::new(false));
        let rx = spawn_event_reader(
            Duration::from_millis(33),
            suspended.clone(),
            Arc::clone(&parked),
        );

        // The reader should ack `parked` promptly without touching stdin.
        let mut acked = false;
        for _ in 0..50 {
            if parked.load(Ordering::Acquire) {
                acked = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(acked, "reader should ack parked while suspended");

        // Clearing suspension is observed; dropping the receiver then exits the
        // thread (no spin-forever leak).
        suspended.store(false, Ordering::Release);
        drop(rx);
    }

    // ── event-poll-hangup-eintr-spurious-eof ───────────────────────────

    /// EINTR must read as "still alive", not as a hang-up.
    ///
    /// The caller collapses `None` and `Some(true)` alike into
    /// `Event::Eof`, which exits the dashboard -- so before this, any
    /// signal delivered while the watchdog sat in `poll()` would look
    /// identical to the terminal closing.
    #[test]
    fn eintr_is_not_a_hangup() {
        let eintr = std::io::Error::from_raw_os_error(libc::EINTR);
        assert_eq!(
            hangup_from_poll_error(&eintr),
            Some(false),
            "a signal is not the terminal going away"
        );
    }

    /// The control arm. Without it, `hangup_from_poll_error` could return
    /// `Some(false)` unconditionally -- which would make the watchdog
    /// blind to a real hang-up and leave the TUI running on a dead pty,
    /// the exact failure the watchdog exists to prevent.
    #[test]
    fn a_genuine_poll_failure_is_still_a_hangup() {
        for errno in [libc::EBADF, libc::EINVAL, libc::ENOMEM] {
            let err = std::io::Error::from_raw_os_error(errno);
            assert_eq!(
                hangup_from_poll_error(&err),
                None,
                "errno {errno} must still tear down the watchdog"
            );
        }
    }
}
