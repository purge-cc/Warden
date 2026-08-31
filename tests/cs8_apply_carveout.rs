//! CS8 carve-outs — the two things the guard must NOT block.
//!
//! The refusal in `promote_validated` is deliberately broad: it covers every
//! CLI verb, every TUI save, and the IPC seat at once. Breadth is the point,
//! and it is also the risk — the single most likely way this change breaks the
//! product is by refusing the feature it exists to protect.
//!
//! So both carve-outs are held by test, not by reasoning:
//!
//! 1. **the sync's own install still succeeds on a secondary.** `apply.rs`
//!    stages, validates and installs into `cluster.d/` directly and never
//!    touches the validating writers. That is true structurally today; this
//!    file's job is to keep it true. Note the deliberate contrast with
//!    `cs8_secondary_policy_guard.rs`'s
//!    `a_secondary_refuses_a_write_into_the_sync_owned_drop_in`: the same
//!    directory, refused by hand and permitted to the sync.
//! 2. **`warden lists refresh` stays allowed.** It is node-local, and since
//!    S1 gave the secondary a real list manager it now does what it says
//!    (pre-S1 it SIGHUPed a node whose reload path early-returned while
//!    printing "lists will reload" — a lie).
//!
//! Only test 1 needs `--features cluster`; `apply.rs` does not exist without
//! it. Test 2 is a source-level route assertion and is ungated, so the default
//! `cargo test` still runs half this file.

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
    for writer in ["write_value_validated", "write_values_validated"] {
        assert!(
            !production.contains(writer),
            "`lists refresh` now routes through {writer}, so the CS8 guard applies to it. \
             That verb is node-local and must stay allowed on a secondary — if the route \
             changed on purpose, the guard needs a carve-out and this test needs replacing."
        );
    }
}

/// The same assertion for the sync's installer, at the route.
///
/// A live `apply_bundle` call (below) proves the carve-out holds for the
/// bundle this test happens to build. This proves it holds because
/// `apply.rs` does not use that machinery at all — which is the property the
/// design actually relies on.
#[test]
fn apply_does_not_route_through_the_validating_writers() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/cluster/apply.rs"))
        .expect("apply.rs is readable");
    let production = src
        .split("#[cfg(test)]")
        .next()
        .expect("apply.rs has a body before its test module");
    for writer in [
        "write_value_validated",
        "write_values_validated",
        "promote_validated",
    ] {
        assert!(
            !production.contains(writer),
            "cluster apply now routes through {writer}; the CS8 guard would refuse the \
             sync's own install and the secondary would never receive policy again."
        );
    }
}

// ── carve-out 1: the sync's own install (cluster feature) ───────────────

#[cfg(feature = "cluster")]
mod install {
    use purge_warden::cluster::apply::apply_bundle;
    use purge_warden::cluster::policy::ClusterPolicyBundle;

    /// A joined secondary, shaped per §5.3: node-local keep-list only.
    const SECONDARY_MASTER: &str = r#"schema_version = 3
includes = ["cluster.d/*.toml"]

[server]
listen = "127.0.0.1:15353"

[api]
token_hash = ""

[cluster]
enabled = true
role = "secondary"
peer = "https://192.0.2.10:8053"
token_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"#;

    /// Policy only — the CS3 fence (`deny_unknown_fields` on
    /// `ClusterPolicyBundle`) rejects any node-local section here.
    const BUNDLE: &str = r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]

[[devices]]
id = "tablet"
display_name = "Tablet"
ip = "192.0.2.50"
"#;

    /// The install the whole feature exists to perform must still succeed on
    /// a secondary — and it installs `[[devices]]`, the very section
    /// `cs8_secondary_policy_guard.rs` proves an operator cannot write there
    /// by hand.
    #[tokio::test]
    async fn a_secondary_still_installs_a_synced_policy_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        std::fs::write(&master, SECONDARY_MASTER).unwrap();

        // The receiver must outlive the call: `apply_bundle` signals a reload
        // on it and treats a closed channel as a shutdown.
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let hash = ClusterPolicyBundle::hash_of(BUNDLE);

        apply_bundle(&master, BUNDLE, &hash, &tx)
            .await
            .expect("CS8 must not block the sync's own install");

        let installed = dir.path().join("cluster.d/00-cluster-policy.toml");
        assert!(
            installed.exists(),
            "the bundle should be on disk at {}",
            installed.display()
        );
        assert!(std::fs::read_to_string(&installed)
            .unwrap()
            .contains("tablet"));
    }
}
