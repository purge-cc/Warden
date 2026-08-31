//! The latching readiness gate — "this process has installed a filter
//! generation", as a type rather than as a comment.
//!
//! This module is a **sibling** of [`manager`](crate::lists::manager), and
//! that placement is the whole mechanism. Rust makes a private field
//! visible to the module that declares it *and every descendant*, so a
//! `ReadinessGate` declared in `lists::manager` — or in `lists` itself —
//! would leave `gate.0.store(false, …)` compiling inside
//! `refresh_with_mode`, which is exactly the mutation the type exists to
//! forbid. Declared here, no other module can reach the atomic at all.
//! That placement is enforced at build time by
//! `scripts/check_readiness_gate_placement.sh` (wired into `make test`
//! and `make test-fast`) — not by the doctests below, which cannot see a
//! module boundary; see their corrected doc comment for why.
//!
//! See `_docs/features/boot_list_persistence.md` §2.4 for why the gate is
//! one-way, why it is seeded in `start.rs` rather than in the manager, and
//! why the hot-path load is `Relaxed`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// A one-way readiness flag: it can be opened, and never closed.
///
/// Three parties share one gate:
///
/// * `cli::commands::start` **seeds** it — open on nodes that do not build
///   their own filter map, closed on the ones that do. The only place a
///   `false` can enter.
/// * [`ListManager::set_filter_ready_gate`](crate::lists::manager::ListManager::set_filter_ready_gate)
///   hands it to the manager, which only ever **opens** it.
/// * [`ForwardHandler::with_filter_ready`](crate::dns::handler::ForwardHandler::with_filter_ready)
///   hands it to the query path, which only ever **reads** it and refuses
///   every query with SERVFAIL while it is closed.
///
/// The type is the enforcement. `store(false)` is not reachable from
/// outside this module, so "the gate never closes" is a property of the
/// API rather than of a comment plus a test that cannot observe the gate
/// mid-cycle. That distinction is not cosmetic: a "reset at the top of
/// the cycle, recompute at the end" implementation passes every gate test
/// in the suite while SERVFAILing the entire house for the duration of
/// every background refresh.
///
/// # Examples
///
/// ```
/// use purge_warden::lists::readiness::ReadinessGate;
///
/// let gate = ReadinessGate::new(false);
/// assert!(!gate.is_open(), "seeded closed");
///
/// gate.open();
/// assert!(gate.is_open());
///
/// // Idempotent, and shared clones observe the same latch.
/// let other = gate.clone();
/// gate.open();
/// assert!(other.is_open());
/// ```
///
/// # What the doctests below pin — and what they cannot
///
/// A doctest compiles as a *separate crate* linking the lib, so it can
/// only ever observe the **crate** boundary, never a **module** boundary
/// inside it. That bounds what each one below can prove.
///
/// The field is not `pub`, so it cannot be written from outside this
/// crate:
///
/// ```compile_fail
/// use purge_warden::lists::readiness::ReadinessGate;
///
/// let gate = ReadinessGate::new(true);
/// // error[E0616]: field `0` of struct `ReadinessGate` is private
/// gate.0.store(false, std::sync::atomic::Ordering::Release);
/// ```
///
/// This does **not** pin that `lists::manager` — an in-crate sibling —
/// cannot reach the field too; a doctest has no way to observe that,
/// since every in-crate module looks identical from outside the crate.
/// That property comes from *where this type lives* (see the module doc
/// above) and is pinned at build time instead by
/// `scripts/check_readiness_gate_placement.sh` (run by `make test` and
/// `make test-fast`), which fails if a `ReadinessGate` declaration
/// exists anywhere but this file. Move the declaration into `manager.rs`
/// behind a path-preserving `pub use` and this doctest keeps passing
/// while `gate.0.store(false, …)` compiles again inside
/// `refresh_with_mode`.
///
/// And there is deliberately no `pub` method that would close it — this
/// one starts compiling the moment somebody publishes a `close`:
///
/// ```compile_fail
/// use purge_warden::lists::readiness::ReadinessGate;
///
/// let gate = ReadinessGate::new(true);
/// // error[E0599]: no method named `close` found for struct `ReadinessGate`
/// gate.close();
/// ```
///
/// Same limit as above: a `pub(crate)` or `pub(super)` `close` is
/// invisible to a doctest and fully visible to `manager.rs`, so it would
/// compile here silently. `lists::manager`'s test
/// `readiness_gate_is_never_closed_by_an_empty_cycle` catches that
/// narrower case instead, from inside the crate.
#[derive(Clone, Debug)]
pub struct ReadinessGate(Arc<AtomicBool>);

impl ReadinessGate {
    /// Seed the gate: closed on nodes that build their own filter map,
    /// open on those that do not — `start.rs`'s `spawn_lists` predicate.
    /// This is the ONLY place a `false` can enter.
    pub fn new(open: bool) -> Self {
        Self(Arc::new(AtomicBool::new(open)))
    }

    /// Latch it open. Idempotent. There is deliberately no `close`.
    ///
    /// `Release` pairs with nothing in particular — the filter map is
    /// published by `ArcSwap`, with its own ordering — but it costs
    /// nothing here (this runs once per refresh cycle, not per query) and
    /// keeps the store from being reordered before the install it
    /// reports.
    pub fn open(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Hot path: one relaxed load per query.
    ///
    /// `Relaxed` is correct and deliberate. This flag does not publish
    /// the map; `ArcSwap` does. All the flag has to be is
    /// eventually-visible and monotone, and a one-way `bool` needs no
    /// fence for that. Do not "harden" it to `SeqCst` — that is a fence
    /// on every query for no property.
    pub fn is_open(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::ReadinessGate;

    /// Kills an implementation that ignores its argument and always
    /// seeds open (or always closed) — the seed is the one place a
    /// `false` legitimately enters, so a constructor that drops it would
    /// leave every node's gate open at boot and silently delete the
    /// backstop.
    #[test]
    fn new_honours_the_seed() {
        assert!(!ReadinessGate::new(false).is_open());
        assert!(ReadinessGate::new(true).is_open());
    }

    /// Kills an `open()` that is a no-op, and a `is_open()` wired to the
    /// wrong polarity: only "open then read true" satisfies both this
    /// and the seed test above.
    #[test]
    fn open_latches_and_is_shared_across_clones() {
        let gate = ReadinessGate::new(false);
        let clone = gate.clone();

        gate.open();

        assert!(gate.is_open());
        assert!(
            clone.is_open(),
            "clones must share one atomic — a `Clone` that deep-copied the \
             bool would let the manager open a gate the handler never sees"
        );

        // Idempotent: opening twice is not a toggle.
        gate.open();
        assert!(gate.is_open());
    }
}
