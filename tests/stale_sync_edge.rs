#![cfg(feature = "cluster")]
//! Cluster S3 Task 5 — the staleness state machine, driven tick by tick.
//!
//! # What this file is defending
//!
//! Two things that pull in opposite directions:
//!
//!  1. **Never fail open silently** (design doc §9). A secondary whose policy
//!     sync is broken must say so — in the log, once, at the moment it breaks.
//!  2. **A line repeated every 15 s is how a log stops being read.** Before S3
//!     the poll loop warned on *every* failed tick: an overnight outage is
//!     ~2 000 identical lines, and the one line that mattered is the first.
//!
//! So the assertions come in pairs: the transition is reported, **and the
//! ticks after it report nothing**. The second half is the one a careless
//! suite skips, and it is the half that distinguishes an edge detector from
//! the per-tick warn it replaces.
//!
//! # Why the edge is data and not a log call
//!
//! [`ClusterObserve::note_tick`] returns the transition; the caller logs it.
//! That is what lets these tests assert an *absence* by comparing values.
//! Asserting the absence of a `tracing` line would need the global-subscriber
//! capture fixture, which is known to race under the parallel test runner —
//! i.e. the assertion that matters most would be the flakiest one.
//!
//! # Fidelity to the poll loop
//!
//! `ok_tick` / `failed_tick` below mirror how `cluster::poll::run` builds its
//! `SyncStatus` at the end of each tick: `last_sync` and `synced_at_least_once`
//! are loop locals that **survive** a failing tick, and only `last_poll_ok` /
//! `last_error` flip. If that ever stops being true, these tests keep passing
//! while describing a machine that no longer exists — check it there first.

use std::time::{Duration, Instant};

use purge_warden::cluster::observe::{ClusterObserve, SyncEdge, SyncHealth, SyncStatus};

/// RFC 5737 TEST-NET-1 — never a real provider, per the neutrality invariant.
const PEER: &str = "https://192.0.2.10:8443";

fn secondary() -> ClusterObserve {
    ClusterObserve::new_secondary(Some("sec-a".into()), PEER.to_string(), 45)
}

/// A tick that synced. Mirrors the poll loop's success branch.
fn ok_tick(hash: &str, at: Instant) -> SyncStatus {
    SyncStatus {
        last_config_hash: Some(hash.to_string()),
        last_sync: Some(at),
        last_poll_ok: true,
        last_error: None,
        synced_at_least_once: true,
    }
}

/// A tick that failed. The convergence locals carry over untouched — that is
/// the product's resilience, and the reason a naive "did the state change?"
/// assertion is blind here.
fn failed_tick(prev: &SyncStatus, error: &str) -> SyncStatus {
    SyncStatus {
        last_config_hash: prev.last_config_hash.clone(),
        last_sync: prev.last_sync,
        last_poll_ok: false,
        last_error: Some(error.to_string()),
        synced_at_least_once: prev.synced_at_least_once,
    }
}

/// The very first tick of a fresh process, before anything has ever synced.
fn never_synced_tick(error: &str) -> SyncStatus {
    SyncStatus {
        last_config_hash: None,
        last_sync: None,
        last_poll_ok: false,
        last_error: Some(error.to_string()),
        synced_at_least_once: false,
    }
}

// ── the three states ────────────────────────────────────────────────────────

/// The distinction the whole task exists for: an age alone cannot tell "never
/// synced" from "synced once, long ago". Both would render as one number, and
/// the remedies differ (a token/join vs. the primary coming back).
#[test]
fn never_synced_is_not_the_same_state_as_stale() {
    let never = SyncHealth::of_secondary(false, false);
    let stale = SyncHealth::of_secondary(true, false);
    let current = SyncHealth::of_secondary(true, true);

    assert_eq!(never, SyncHealth::NeverSynced);
    assert_eq!(stale, SyncHealth::Stale);
    assert_eq!(current, SyncHealth::Current);
    assert_ne!(never, stale, "collapsing these two is the defect");
    assert!(never.is_degraded() && stale.is_degraded());
    assert!(!current.is_degraded());
}

/// A node that has never synced stays `NeverSynced` even on a tick that
/// "succeeded" in every other sense — the flag, not the poll result, is what
/// says whether policy has ever landed.
#[test]
fn a_successful_flag_without_a_sync_is_still_never_synced() {
    assert_eq!(
        SyncHealth::of_secondary(false, true),
        SyncHealth::NeverSynced
    );
}

// ── edge: the outage ────────────────────────────────────────────────────────

/// The headline behaviour. One `Degraded` on the crossing, then **silence**
/// for as long as the outage lasts.
#[test]
fn a_persisting_outage_reports_one_edge_and_then_nothing() {
    let obs = secondary();
    let t0 = Instant::now();

    let synced = ok_tick("hash-a", t0);
    assert!(matches!(
        obs.note_tick(&synced, t0),
        SyncEdge::FirstSync { .. }
    ));

    // Tick 1 of the outage: the crossing. Reported, with the age of the last
    // confirmation so the operator knows how much policy drift is possible.
    let t1 = t0 + Duration::from_secs(15);
    let down = failed_tick(&synced, "heartbeat HTTP 502");
    match obs.note_tick(&down, t1) {
        SyncEdge::Degraded {
            error,
            confirmed_secs_ago,
        } => {
            assert_eq!(error.as_deref(), Some("heartbeat HTTP 502"));
            assert_eq!(confirmed_secs_ago, Some(15));
        }
        other => panic!("the crossing into stale must be reported, got {other:?}"),
    }

    // Ticks 2..=240 — a full hour at a 15 s interval. Every one of them must
    // be silent. This is the assertion that separates an edge detector from
    // the per-tick `warn!` it replaces.
    for i in 2..=240 {
        let t = t0 + Duration::from_secs(15 * i);
        let still_down = failed_tick(&synced, "heartbeat HTTP 502");
        assert_eq!(
            obs.note_tick(&still_down, t),
            SyncEdge::Steady,
            "tick {i} of the same outage must log nothing"
        );
    }
}

/// Recovery is an edge too, and it carries what the operator wants to know:
/// how long it was broken and how many polls it cost.
#[test]
fn recovery_reports_once_and_then_goes_quiet() {
    let obs = secondary();
    let t0 = Instant::now();
    let synced = ok_tick("hash-a", t0);
    obs.note_tick(&synced, t0);

    let down = failed_tick(&synced, "connection refused");
    for i in 1..=4 {
        obs.note_tick(&down, t0 + Duration::from_secs(15 * i));
    }

    let t_back = t0 + Duration::from_secs(75);
    let back = ok_tick("hash-b", t_back);
    match obs.note_tick(&back, t_back) {
        SyncEdge::Recovered {
            hash,
            failed_polls,
            degraded_secs,
        } => {
            assert_eq!(hash.as_deref(), Some("hash-b"));
            assert_eq!(failed_polls, 4, "one per failed tick in the run just ended");
            // The run began at the first failure (t0 + 15s) and ended at t+75s.
            assert_eq!(degraded_secs, Some(60));
        }
        other => panic!("recovery must be reported, got {other:?}"),
    }

    // …and a healthy cluster says nothing at all, forever.
    for i in 6..=50 {
        let t = t0 + Duration::from_secs(15 * i);
        assert_eq!(
            obs.note_tick(&ok_tick("hash-b", t), t),
            SyncEdge::Steady,
            "a healthy tick must be silent (tick {i})"
        );
    }
}

// ── edge: the dark boot ─────────────────────────────────────────────────────

/// Booting with the primary unreachable is the **worst** state, and a naive
/// edge detector makes it the quietest one: `NeverSynced → NeverSynced` is not
/// a transition, so nothing would ever be logged — while the per-tick warn
/// this replaces at least said *something*. The detector carries a boot phase
/// precisely so the first tick is always an edge.
#[test]
fn a_boot_with_no_primary_is_reported_once_not_never() {
    let obs = secondary();
    let t0 = Instant::now();

    match obs.note_tick(&never_synced_tick("dns error: no route to host"), t0) {
        SyncEdge::NeverSyncedYet { error } => {
            assert_eq!(error.as_deref(), Some("dns error: no route to host"));
        }
        other => panic!("the first dark tick must be reported, got {other:?}"),
    }

    for i in 1..=100 {
        let t = t0 + Duration::from_secs(15 * i);
        assert_eq!(
            obs.note_tick(&never_synced_tick("dns error: no route to host"), t),
            SyncEdge::Steady,
            "tick {i} of a still-dark boot must log nothing"
        );
    }
}

/// When a dark boot finally reaches the primary that is a *first sync*, not a
/// recovery — there was no previous good state to return to, and an operator
/// reading "recovered" would believe policy had been in force all along.
#[test]
fn the_first_sync_after_a_dark_boot_is_not_called_a_recovery() {
    let obs = secondary();
    let t0 = Instant::now();
    obs.note_tick(&never_synced_tick("connection refused"), t0);
    obs.note_tick(
        &never_synced_tick("connection refused"),
        t0 + Duration::from_secs(15),
    );

    let t = t0 + Duration::from_secs(30);
    match obs.note_tick(&ok_tick("hash-a", t), t) {
        SyncEdge::FirstSync { hash } => assert_eq!(hash.as_deref(), Some("hash-a")),
        other => panic!("expected FirstSync, got {other:?}"),
    }
}

// ── edge: the flap ──────────────────────────────────────────────────────────

/// A flapping link reports both edges each time. Two lines per flap is more
/// than the old per-tick warn produced for a *single* blip — and it is the
/// right trade: it makes the flap itself legible, while the case that used to
/// produce thousands of lines now produces two.
#[test]
fn a_flap_reports_every_crossing_in_order() {
    let obs = secondary();
    let t0 = Instant::now();
    let synced = ok_tick("hash-a", t0);
    obs.note_tick(&synced, t0);

    let mut seen = Vec::new();
    for i in 1..=6 {
        let t = t0 + Duration::from_secs(15 * i);
        let edge = if i % 2 == 1 {
            obs.note_tick(&failed_tick(&synced, "timeout"), t)
        } else {
            obs.note_tick(&ok_tick("hash-a", t), t)
        };
        seen.push(matches!(
            edge,
            SyncEdge::Degraded { .. } | SyncEdge::Recovered { .. }
        ));
    }
    assert_eq!(
        seen,
        vec![true; 6],
        "every crossing of a flapping link is an edge"
    );
}

// ── the emitter ─────────────────────────────────────────────────────────────

/// `log()` is the half of the mechanism these tests deliberately do not
/// inspect. Drive every variant through it once so a malformed `tracing` field
/// (or a `Steady` that accidentally logs) is at least exercised rather than
/// shipped untested.
#[test]
fn every_edge_variant_logs_without_panicking() {
    SyncEdge::Steady.log();
    SyncEdge::NeverSyncedYet {
        error: Some("boom".into()),
    }
    .log();
    SyncEdge::NeverSyncedYet { error: None }.log();
    SyncEdge::FirstSync {
        hash: Some("hash-a".into()),
    }
    .log();
    SyncEdge::Degraded {
        error: None,
        confirmed_secs_ago: None,
    }
    .log();
    SyncEdge::Recovered {
        hash: None,
        failed_polls: 3,
        degraded_secs: Some(45),
    }
    .log();
}
