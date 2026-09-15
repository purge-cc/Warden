//! CS8 carve-outs — the two things the guard must NOT block.
//!
//! The refusal in `promote_validated` is deliberately broad: it covers every
//! CLI verb, every TUI save, and the IPC seat at once. Breadth is the point,
//! and it is also the risk — the single most likely way this change breaks the
//! product is by refusing the feature it exists to protect.
//!
//! So both carve-outs are held by test, not by reasoning:
//!
//! 1. **the sync's own install still succeeds on a secondary.** The artifact
//!    receiver stages, validates and installs the complete policy through its
//!    guarded transaction, without entering the operator validating writers.
//!    Its executable regression lives beside the crate-private receiver API;
//!    this file keeps the route fence visible from outside the module.
//! 2. **`warden lists refresh` stays allowed.** It is node-local, and since
//!    S1 gave the secondary a real list manager it now does what it says
//!    (pre-S1 it SIGHUPed a node whose reload path early-returned while
//!    printing "lists will reload" — a lie).
//!
//! The route and retired-interface fences remain active in the default test
//! configuration; the live artifact installer test runs with `cluster`.

// ── carve-out 2: `warden lists refresh` (ungated) ───────────────────────

/// `lists refresh` cannot reach the guard because it writes no config at all
/// — it downloads list bodies into `lists/`. Asserted at the route rather
/// than the outcome: an outcome test would pass just as well on a build where
/// the verb had quietly acquired a config write and was being refused.
///
/// Measured 2026-08-15: `update.rs`'s only `std::fs::write` calls are inside
/// its `#[cfg(test)]` module, which begins at line 222.
#[test]
fn lists_refresh_does_not_route_through_the_validating_writers() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/cli/commands/update.rs"
    ))
    .expect("update.rs is readable");
    let production = src
        .split("#[cfg(test)]")
        .next()
        .expect("update.rs has a body before its test module");
    for writer in [
        "write_value_validated_locked",
        "write_values_validated_locked",
    ] {
        assert!(
            !production.contains(writer),
            "`lists refresh` now routes through {writer}, so the CS8 guard applies to it. \
             That verb is node-local and must stay allowed on a secondary — if the route \
             changed on purpose, the guard needs a carve-out and this test needs replacing."
        );
    }
}

/// The same assertion for the artifact receiver's guarded install route.
/// Its in-module test also exercises the async wrapper and reload signal.
#[test]
fn artifact_receiver_does_not_route_through_the_validating_writers() {
    for relative in [
        "src/cluster/artifact_apply.rs",
        "src/cluster/transaction.rs",
    ] {
        let src = std::fs::read_to_string(format!("{}/{relative}", env!("CARGO_MANIFEST_DIR")))
            .unwrap_or_else(|error| panic!("{relative} is readable: {error}"));
        let production = src
            .split("#[cfg(test)]")
            .next()
            .unwrap_or_else(|| panic!("{relative} has production code before its tests"));
        for writer in [
            "write_value_validated_locked",
            "write_values_validated_locked",
            "promote_validated",
        ] {
            assert!(
                !production.contains(writer),
                "artifact receiver route {relative} enters {writer}; the secondary policy \
                 install would be rejected by the operator-writer guard"
            );
        }
    }
}

/// C5.12 retires the temporary public acquiring interfaces. Keep this source
/// fence deliberately narrow: capability-bearing locked APIs remain valid,
/// while these exact public declarations must never return.
#[test]
fn c512_retired_public_writer_interfaces_stay_absent() {
    let root = env!("CARGO_MANIFEST_DIR");
    for (relative, retired) in [
        (
            "src/cli/commands/target.rs",
            [
                "pub fn write_value_validated(",
                "pub fn write_values_validated(",
                "pub struct StagedWrite",
            ]
            .as_slice(),
        ),
        (
            "src/config/writer.rs",
            ["pub fn write_config_v1("].as_slice(),
        ),
        ("src/config/write_lock.rs", ["pub fn acquire("].as_slice()),
        ("src/config/mod.rs", ["pub mod writer;"].as_slice()),
    ] {
        let source = std::fs::read_to_string(format!("{root}/{relative}"))
            .expect("production source is readable");
        for symbol in retired {
            assert!(
                !source.contains(symbol),
                "C5.12 retired public interface `{symbol}` returned in {relative}"
            );
        }
    }
}
