//! §4.11-3 — secondary apply side: install a synced policy bundle.
//!
//! **Policy (CS3/CS5/CS8).** The bundle is a partial-`ConfigV1` TOML the
//! primary serves (proven to reparse as `ConfigV1` in `cluster::policy`).
//! [`apply_bundle`] reuses the `config restore` discipline — stage →
//! validate-the-full-merge → atomic install → hot-reload:
//!
//! 1. stage a hardened CSPRNG `0o700` dir holding a copy of the node's
//!    master + its sibling `*.d` include dirs, with the new bundle dropped
//!    into `staging/cluster.d/00-cluster-policy.toml`;
//! 2. `loader::load_config` the staged master — this validates the EXACT
//!    merged config the live loader will produce (node-local master MERGED
//!    with the bundle, cross-refs resolved against the real node identity).
//!    A rejection keeps the last-good policy (the caller does not advance
//!    its last-applied hash, so the next tick retries);
//! 3. atomically install the bundle into the LIVE
//!    `cluster.d/00-cluster-policy.toml` (mirror-wiping any stray
//!    sync-managed file) — the node-local master is NEVER written (CS3);
//! 4. signal a hot reload so `handle_reload` rebuilds the resolver from the
//!    merged config — the ordinary reload path every node takes, which
//!    rebuilds this node's own lists from the merged policy.
//!
//! **Map.** There is none. The Tier-1 map is NOT replicated — the secondary
//! builds its own from the replicated policy. See
//! `_docs/features/cluster_sync_policy_only.md` §3.

use std::path::Path;

use tokio::sync::mpsc;

use crate::cli::commands::config::restore::{copy_dir_recursive, StagingDir};
use crate::config::atomic_write::atomic_write_and_validate;
use crate::config::loader;

use super::policy::ClusterPolicyBundle;

/// Sync-owned drop-in directory (sibling of the master; resolved by the
/// loader's `includes = ["cluster.d/*.toml"]` glob).
///
/// Taken from the loader rather than declared here: the secondary-master
/// guard in [`crate::config::schema::validator`] must recognise what this
/// writer produces, and that guard is compiled even when the `cluster`
/// feature is OFF. One literal, two consumers, no way to drift.
use crate::config::loader::CLUSTER_DROP_IN_DIR as CLUSTER_D;

/// The single sync-managed bundle file inside [`CLUSTER_D`].
const BUNDLE_FILE: &str = "00-cluster-policy.toml";

/// Verify, fence, stage, validate, atomically install, and hot-reload a synced
/// policy bundle. Returns `Ok(())` only when the bundle's content hash matched
/// the primary's advertised hash, it parsed as policy-only, the merged config
/// validated, AND the reload was signalled; any earlier failure leaves the live
/// policy untouched and returns `Err` (the poll loop logs + keeps last-good).
///
/// `expected_hash` is the primary's advertised `config_hash` (`apply-03`); the
/// blocking filesystem + full-loader work runs off the async runtime under
/// `spawn_blocking` (`apply-02`).
pub async fn apply_bundle(
    config_path: &Path,
    bundle_toml: &str,
    expected_hash: &str,
    reload_tx: &mpsc::Sender<Option<u32>>,
) -> anyhow::Result<()> {
    // All of the verify/fence/stage/validate/install work below is synchronous
    // blocking I/O (`std::fs`, the full `loader::load_config`, the atomic write)
    // — run it on the blocking pool so a large config + map reload can never
    // stall a tokio worker that also drives the DNS hot path (apply-02).
    let config_path = config_path.to_path_buf();
    let bundle_toml = bundle_toml.to_string();
    let expected_hash = expected_hash.to_string();
    let live_bundle = tokio::task::spawn_blocking(move || {
        stage_validate_install(&config_path, &bundle_toml, &expected_hash)
    })
    .await
    .map_err(|e| anyhow::anyhow!("cluster policy apply task panicked: {e}"))??;

    // Only the reload signal stays on the async path.
    reload_tx
        .send(None)
        .await
        .map_err(|_| anyhow::anyhow!("reload channel closed; daemon shutting down?"))?;
    tracing::info!(
        bundle = %live_bundle.display(),
        "cluster: synced policy bundle applied; reload signalled"
    );
    Ok(())
}

/// The blocking half of [`apply_bundle`]: returns the installed bundle path on
/// success, or `Err` (live policy untouched) on any verify/fence/validate/
/// install failure. Runs under `spawn_blocking`.
fn stage_validate_install(
    config_path: &Path,
    bundle_toml: &str,
    expected_hash: &str,
) -> anyhow::Result<std::path::PathBuf> {
    let config_dir = config_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("config path has no parent: {}", config_path.display()))?;
    let master_name = config_path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("config path has no file name"))?;

    // ── 0a. integrity: the served bytes must match the advertised hash ──
    // (apply-03) — a primary/MITM advertising X while serving Y is rejected
    // before we trust the body. The config hash is sha256 over the TOML text.
    let computed = ClusterPolicyBundle::hash_of(bundle_toml);
    if computed != expected_hash {
        anyhow::bail!(
            "bundle content hash mismatch: primary advertised {expected_hash}, computed \
             {computed}; keeping last-good"
        );
    }

    // ── 0b. CS3 fence: the bundle must be POLICY-ONLY (apply-01) ──────
    // Re-parse as the same allowlist struct the primary emits. `deny_unknown_
    // fields` rejects any node-local section/field (`[api]`/`[socket]`/
    // `[cluster]`/`[tracking]`/…/`includes`/`server.listen`), so an injected
    // bundle can never reach `cluster.d` even though the loader would otherwise
    // merge an `[api]` the secondary's master doesn't declare.
    toml::from_str::<ClusterPolicyBundle>(bundle_toml).map_err(|e| {
        anyhow::anyhow!(
            "received bundle carries non-policy/node-local config (CS3 fence rejects it): {e}; \
             keeping last-good"
        )
    })?;

    // ── 1. stage ────────────────────────────────────────────────────
    // CSPRNG-named 0o700 dir (reused from restore — TOCTOU-safe). Copy the
    // master + every sibling `*.d` include dir (config-shaped, never the
    // state dirs `audit/`/`lists/`/`data/`), then write the new bundle into
    // a fresh staging cluster.d so the loader sees exactly the live merge.
    let staging = StagingDir::create()?;
    let staged_root = staging.path();
    let staged_master = staged_root.join(master_name);
    std::fs::copy(config_path, &staged_master)
        .map_err(|e| anyhow::anyhow!("stage master config: {e}"))?;
    for entry in std::fs::read_dir(config_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if entry.file_type()?.is_dir() && name.to_string_lossy().ends_with(".d") {
            copy_dir_recursive(&entry.path(), &staged_root.join(&name))?;
        }
    }
    let staged_cluster_d = staged_root.join(CLUSTER_D);
    // Mirror semantics: staging cluster.d holds exactly our one bundle.
    let _ = std::fs::remove_dir_all(&staged_cluster_d);
    std::fs::create_dir_all(&staged_cluster_d)?;
    std::fs::write(staged_cluster_d.join(BUNDLE_FILE), bundle_toml)
        .map_err(|e| anyhow::anyhow!("stage policy bundle: {e}"))?;

    // ── 2. validate the FULL merged config ──────────────────────────
    let now = time::OffsetDateTime::now_utc();
    if let Err(errs) = loader::load_config(&staged_master, now) {
        let joined = errs
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        anyhow::bail!("staged cluster policy failed validation; keeping last-good: {joined}");
    }

    // ── 3. atomic install into the LIVE cluster.d (master untouched) ─
    let live_cluster_d = config_dir.join(CLUSTER_D);
    std::fs::create_dir_all(&live_cluster_d)
        .map_err(|e| anyhow::anyhow!("create {}: {e}", live_cluster_d.display()))?;
    let live_bundle = live_cluster_d.join(BUNDLE_FILE);
    atomic_write_and_validate(
        &live_bundle,
        bundle_toml,
        |p: &Path| -> Result<(), String> {
            // The full cross-ref validation already passed on staging; here a
            // cheap TOML parse is the install gate (mirrors restore.rs).
            std::fs::read_to_string(p)
                .map_err(|e| e.to_string())?
                .parse::<toml::Value>()
                .map(|_| ())
                .map_err(|e| e.to_string())
        },
    )
    .map_err(|e| anyhow::anyhow!("install cluster policy at {}: {e}", live_bundle.display()))?;
    mirror_wipe_cluster_d(&live_cluster_d);

    Ok(live_bundle)
}

/// Remove any `*.toml` in the live `cluster.d` that is not our managed
/// bundle — the dir is sync-owned (CS3), so a stray file an operator dropped
/// (or a renamed older bundle) must not leak into the include glob.
/// Best-effort: a removal failure is logged, not fatal.
fn mirror_wipe_cluster_d(live_cluster_d: &Path) {
    let entries = match std::fs::read_dir(live_cluster_d) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_s = name.to_string_lossy();
        if name_s == BUNDLE_FILE {
            continue;
        }
        if name_s.ends_with(".toml") {
            if let Err(e) = std::fs::remove_file(entry.path()) {
                tracing::warn!(
                    path = %entry.path().display(),
                    error = %e,
                    "cluster: failed to mirror-wipe stray cluster.d file"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::policy::ClusterPolicyBundle;

    // neutrality-10: a secondary's OWN master declares no `[upstream]` — the
    // section arrives in `cluster.d/00-cluster-policy.toml`, because the
    // bundle carries `upstream` verbatim from the primary. `[upstream]` is a
    // singleton across the include set, so declaring it here too is a
    // duplicate-singleton error, not a belt-and-braces default. The merged
    // view still has exactly one, which is why removing the default does not
    // break cluster secondaries.
    const MASTER: &str =
        "schema_version = 3\nincludes = [\"cluster.d/*.toml\"]\n\n[server]\nlisten = \"127.0.0.1:15354\"\n";

    #[tokio::test]
    async fn apply_bundle_rejects_unloadable_merge_and_keeps_live() {
        // master with a node-local [server] (listen) + cluster.d include,
        // no profiles — a bundle whose default_profile dangles must fail
        // staging validation and leave the live cluster.d untouched.
        let tmp = tempfile::tempdir().unwrap();
        let master = tmp.path().join("config.toml");
        std::fs::write(&master, MASTER).unwrap();

        let bad_bundle = "schema_version = 3\n\n[server]\ndefault_profile = \"ghost\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n";
        let (tx, _rx) = mpsc::channel::<Option<u32>>(1);
        let res = apply_bundle(
            &master,
            bad_bundle,
            &ClusterPolicyBundle::hash_of(bad_bundle),
            &tx,
        )
        .await;
        assert!(res.is_err(), "dangling default_profile must be rejected");
        // Live cluster.d must not have been created/populated.
        assert!(!tmp.path().join(CLUSTER_D).join(BUNDLE_FILE).exists());
    }

    #[tokio::test]
    async fn apply_bundle_rejects_hash_mismatch() {
        // apply-03: a structurally-valid bundle whose advertised hash is wrong
        // never reaches staging — live cluster.d stays untouched.
        let tmp = tempfile::tempdir().unwrap();
        let master = tmp.path().join("config.toml");
        std::fs::write(&master, MASTER).unwrap();

        let good_bundle = "schema_version = 3\n\n[server]\ndefault_profile = \"default\"\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n";
        let (tx, _rx) = mpsc::channel::<Option<u32>>(1);
        let res = apply_bundle(&master, good_bundle, &"a".repeat(64), &tx).await;
        assert!(res.is_err(), "hash mismatch must be rejected");
        assert!(!tmp.path().join(CLUSTER_D).join(BUNDLE_FILE).exists());
    }

    #[tokio::test]
    async fn apply_bundle_rejects_node_local_injection() {
        // apply-01: a bundle smuggling an [api] token_hash (the master never
        // declared [api]) is fenced out by the policy-only re-parse before it
        // can be staged into cluster.d.
        let tmp = tempfile::tempdir().unwrap();
        let master = tmp.path().join("config.toml");
        std::fs::write(&master, MASTER).unwrap();

        let hostile =
            "schema_version = 3\n\n[server]\ndefault_profile = \"default\"\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[api]\nenabled = true\ntoken_hash = \"attacker\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n";
        let (tx, _rx) = mpsc::channel::<Option<u32>>(1);
        let res = apply_bundle(
            &master,
            hostile,
            &ClusterPolicyBundle::hash_of(hostile),
            &tx,
        )
        .await;
        assert!(res.is_err(), "node-local [api] injection must be fenced");
        assert!(!tmp.path().join(CLUSTER_D).join(BUNDLE_FILE).exists());
    }

    #[tokio::test]
    async fn apply_bundle_installs_valid_merge_and_signals_reload() {
        // master: node-local [server] listen; bundle: [server] default_profile
        // + the profile it names. R3 field-merge makes the split [server] load.
        let tmp = tempfile::tempdir().unwrap();
        let master = tmp.path().join("config.toml");
        std::fs::write(&master, MASTER).unwrap();

        let good_bundle = "schema_version = 3\n\n[server]\ndefault_profile = \"default\"\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n";
        let (tx, mut rx) = mpsc::channel::<Option<u32>>(1);
        apply_bundle(
            &master,
            good_bundle,
            &ClusterPolicyBundle::hash_of(good_bundle),
            &tx,
        )
        .await
        .unwrap();

        // Installed into cluster.d, master untouched, reload signalled.
        let installed = tmp.path().join(CLUSTER_D).join(BUNDLE_FILE);
        assert!(installed.exists());
        assert_eq!(rx.try_recv().unwrap(), None);
        // The merged tree loads (listen from master + default_profile from bundle).
        let loaded = loader::load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        assert_eq!(loaded.config.server.listen.to_string(), "127.0.0.1:15354");
        assert_eq!(
            loaded
                .config
                .server
                .default_profile
                .as_ref()
                .map(|i| i.as_str()),
            Some("default")
        );
    }
}
