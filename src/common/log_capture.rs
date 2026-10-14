//! Per-thread capture of `tracing` events for lib unit tests.
//!
//! A test that counts events from a callsite other tests also reach cannot
//! capture them with a scoped `tracing::subscriber::set_default`. `tracing`
//! caches each callsite's `Interest` process-wide when the callsite is first
//! reached. While a single scoped dispatcher is the only one registered, that
//! interest comes from the default subscriber of whichever thread got there
//! first; a test thread with no subscriber answers `never`, and from then on
//! the scoped subscriber is never asked about that callsite. Whether the
//! capture sees anything then depends on test order.
//!
//! This module installs one global subscriber, once per test binary. It
//! enables every callsite, so no interest can be cached as `never`, and files
//! each event into the buffer of the thread that armed the capture. Threads
//! that never armed it drop the event after one thread-local read. A binary
//! holds at most one global subscriber, so every lib test that needs a
//! capture shares this one.
//!
//! The buffer is per thread: an event emitted on another thread
//! (`spawn_blocking`, a multi-thread runtime) is not captured.

use std::cell::RefCell;

thread_local! {
    /// Events seen on THIS thread, in order. `Some` only between
    /// [`arm_log_capture`] and [`take_log_capture`]; libtest gives each
    /// test its own thread, so no other test can write here.
    static EVENTS: RefCell<Option<Vec<(tracing::Level, String)>>> =
        const { RefCell::new(None) };
}

/// Pulls the formatted `message` field out of an event. `tracing` exposes it
/// only through the visitor API.
struct MessageVisitor(String);

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}

struct Capture;

impl tracing::Subscriber for Capture {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn event(&self, event: &tracing::Event<'_>) {
        // `try_with` because this can run while a thread is being torn down
        // and its thread-locals are already destroyed.
        let _ = EVENTS.try_with(|cell| {
            let Ok(mut slot) = cell.try_borrow_mut() else {
                return;
            };
            let Some(events) = slot.as_mut() else {
                return; // not a capturing thread — the common case
            };
            let mut visitor = MessageVisitor(String::new());
            event.record(&mut visitor);
            events.push((*event.metadata().level(), visitor.0));
        });
    }

    // Spans are deliberately not stored: this subscriber is live for every
    // test in the binary once installed.
    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
    fn enter(&self, _span: &tracing::span::Id) {}
    fn exit(&self, _span: &tracing::span::Id) {}
}

/// Install the capture (once per process) and start recording on this
/// thread.
pub(crate) fn arm_log_capture() {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        tracing::subscriber::set_global_default(Capture)
            .expect("no other lib test may install a global tracing subscriber");
    });
    // Scoped subscribers on other test threads register and drop at any
    // time; refresh every cached interest before arming the buffer.
    tracing::callsite::rebuild_interest_cache();
    EVENTS.with(|cell| *cell.borrow_mut() = Some(Vec::new()));
}

/// Stop recording on this thread and return every event seen since
/// [`arm_log_capture`], in order, as `(level, message)`.
pub(crate) fn take_log_capture() -> Vec<(tracing::Level, String)> {
    EVENTS.with(|cell| {
        cell.borrow_mut()
            .take()
            .expect("capture was never armed on this thread")
    })
}

fn probe() {
    tracing::warn!("log_capture probe");
}

/// The order dependence this module exists to remove: another thread, with
/// no subscriber of its own, reaches the callsite first. A capture built on
/// a scoped `set_default` loses the test thread's event here; this one keeps
/// it, and does not pick up the other thread's.
#[test]
fn captures_an_event_whose_callsite_another_thread_registered_first() {
    arm_log_capture();
    std::thread::spawn(probe).join().unwrap();
    probe();
    let probes: Vec<_> = take_log_capture()
        .into_iter()
        .filter(|(_, message)| message == "log_capture probe")
        .collect();
    assert_eq!(
        probes,
        vec![(tracing::Level::WARN, "log_capture probe".to_string())]
    );
}
