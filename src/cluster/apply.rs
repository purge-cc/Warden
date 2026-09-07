//! §4.11-3 — secondary apply side: install a synced policy bundle.
//!
//! **Policy (CS3/CS5/CS8).** The bundle is a partial-`ConfigV1` TOML the
//! primary serves (proven to reparse as `ConfigV1` in `cluster::policy`).
//! [`apply_bundle`] reuses the `config restore` discipline — stage →
//! validate-the-full-merge → atomic install → hot-reload:
//!
//! 1. take the config-tree write guard and descriptor-plan the managed bundle
//!    plus every sync-owned file the mirror pass will remove;
//! 2. validate the intended post-mirror view through a guarded loader overlay. A
//!    rejection keeps the last-good policy, so the next poll retries;
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

use std::path::{Path, PathBuf};

use tokio::sync::mpsc;

use crate::config::atomic_write::{hardened_atomic_write_at, AtomicWriteAtOpts, AtomicWriteError};
use crate::config::loader::{self, LoaderOverlay};
use crate::config::schema::SCHEMA_VERSION_V1;
use crate::config::tree_io::{for_each_dir_name, DestinationIdentity, PinnedTarget, TargetPlan};
use crate::config::write_lock::{acquire_for_write, ConfigWriteLock};

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

/// Independent bounds for receipt memory and descriptor-backed hashing.
const MAX_MIRROR_FILES: usize = 1000;
const MAX_MIRROR_SNAPSHOT_BYTES: u64 = 50 * 1024 * 1024;

/// Verify, fence, stage, validate, atomically install, and hot-reload a synced
/// policy bundle. Returns `Ok(())` only when the bundle's content hash matched
/// the primary's advertised hash, it parsed as policy-only, the merged config
/// validated, AND the reload was signalled. Pre-publication failures leave the
/// live policy untouched; an uncertain post-rename failure is rolled back or
/// reported explicitly (the poll loop keeps the last applied hash).
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
    // blocking I/O (the guarded full loader + atomic write)
    // — run it on the blocking pool so a large config + map reload can never
    // stall a tokio worker that also drives the DNS hot path (apply-02).
    let config_path = config_path.to_path_buf();
    let bundle_toml = bundle_toml.to_string();
    let expected_hash = expected_hash.to_string();
    let live_bundle = tokio::task::spawn_blocking(move || {
        preflight_bundle(&bundle_toml, &expected_hash)?;
        stage_validate_install(&config_path, &bundle_toml)
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
/// success, or `Err` on any fence/validate/install failure. Runs under
/// `spawn_blocking`.
fn stage_validate_install(config_path: &Path, bundle_toml: &str) -> anyhow::Result<PathBuf> {
    // WHY this is first: all live-tree reads, enumeration, validation and
    // mutation must share one writer fence.
    let guard = acquire_for_write(config_path)?;
    let result = stage_validate_install_locked(&guard, config_path, bundle_toml);
    // The async reload may wait for channel capacity; never hold a filesystem
    // lock across that await.
    drop(guard);
    result
}

/// Integrity and policy shape are independent of the live tree, so reject
/// them before entering the blocking writer transaction.
fn preflight_bundle(bundle_toml: &str, expected_hash: &str) -> anyhow::Result<()> {
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

    Ok(())
}

/// Validate the post-mirror tree under the same guard that publishes it.
fn stage_validate_install_locked(
    guard: &ConfigWriteLock,
    config_path: &Path,
    bundle_toml: &str,
) -> anyhow::Result<PathBuf> {
    guard.verify_master(config_path)?;

    // ── 1. snapshot targets + stage their final tree view ──────────
    // Planning occurs before validation and before materialization, so each
    // omission is tied to the inode the later mirror unlink may remove.
    let mut overlay = LoaderOverlay::default();
    let (bundle_plan, mirror_receipts) = plan_live_targets(guard, &mut overlay)?;
    let before_bundle = bundle_plan.read_original()?;
    let live_bundle = bundle_plan.display().to_path_buf();
    overlay.stage_plan_reachable_only(&bundle_plan, bundle_toml.to_string())?;

    // ── 2. validate the intended final merged config ───────────────
    let now = time::OffsetDateTime::now_utc();
    if let Err(errs) = loader::load_config_with_overlay_for_schema_under_guard(
        guard,
        config_path,
        SCHEMA_VERSION_V1,
        now,
        Some(&overlay),
    ) {
        let joined = errs
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        anyhow::bail!("staged cluster policy failed validation; keeping last-good: {joined}");
    }

    // ── 3. atomically install into the live cluster.d ───────────────
    verify_mirror_receipts(guard, &mirror_receipts)?;
    let bundle_target = bundle_plan.materialize()?;
    if let Err(error) = write_bundle(&bundle_target, bundle_toml) {
        return settle_bundle_write_error(&bundle_target, before_bundle.as_deref(), error);
    }
    mirror_wipe_cluster_d(guard, mirror_receipts);

    Ok(live_bundle)
}

/// Plan the bundle and every mirror-wiped file through the guarded root.
struct MirrorReceipt {
    relative: PathBuf,
    destination: DestinationIdentity,
    content_sha256: [u8; 32],
}

fn plan_live_targets<'g>(
    guard: &'g ConfigWriteLock,
    overlay: &mut LoaderOverlay,
) -> anyhow::Result<(TargetPlan<'g>, Vec<MirrorReceipt>)> {
    let tree = guard.tree_io();
    let bundle_relative = Path::new(CLUSTER_D).join(BUNDLE_FILE);
    // This no-follow plan rejects a cluster.d alias before either validation
    // or publication can select a different tree.
    let bundle_plan = tree.plan_root_file_no_follow(&bundle_relative)?;
    let master = tree.master_key();
    let Some(cluster_d) = tree.directory_from(&master, Path::new(CLUSTER_D))? else {
        return Ok((bundle_plan, Vec::new()));
    };
    let mut mirrors = Vec::new();
    let mut mirror_bytes = 0_u64;
    for_each_dir_name(&cluster_d, |name| {
        let name_s = name.to_string_lossy();
        if name_s == BUNDLE_FILE || !name_s.ends_with(".toml") {
            return Ok(());
        }
        let relative = Path::new(CLUSTER_D).join(name);
        let plan = tree.plan_root_file_no_follow(&relative)?;
        anyhow::ensure!(
            !plan.is_new(),
            "cluster mirror member disappeared while planning: {}",
            plan.display().display()
        );
        anyhow::ensure!(
            mirrors.len() < MAX_MIRROR_FILES,
            "cluster mirror file count exceeds hard cap {MAX_MIRROR_FILES}"
        );
        let original_len = plan
            .original_len()
            .ok_or_else(|| anyhow::anyhow!("cluster mirror member has no original inode"))?;
        mirror_bytes = mirror_bytes
            .checked_add(original_len)
            .ok_or_else(|| anyhow::anyhow!("cluster mirror snapshot size overflow"))?;
        anyhow::ensure!(
            mirror_bytes <= MAX_MIRROR_SNAPSHOT_BYTES,
            "cluster mirror snapshot exceeds hard cap {MAX_MIRROR_SNAPSHOT_BYTES} bytes"
        );
        let destination = plan.destination()?;
        let content_sha256 = plan
            .original_sha256()?
            .ok_or_else(|| anyhow::anyhow!("cluster mirror member disappeared"))?;
        anyhow::ensure!(
            plan.destination()? == destination,
            "cluster mirror member changed while fingerprinting: {}",
            plan.display().display()
        );
        overlay.omit_plan(&plan)?;
        mirrors.push(MirrorReceipt {
            relative,
            destination,
            content_sha256,
        });
        Ok(())
    })?;
    mirrors.sort_by(|left, right| left.relative.cmp(&right.relative));
    Ok((bundle_plan, mirrors))
}

fn verify_mirror_receipts(
    guard: &ConfigWriteLock,
    receipts: &[MirrorReceipt],
) -> anyhow::Result<()> {
    for receipt in receipts {
        let current = guard
            .tree_io()
            .plan_root_file_no_follow(&receipt.relative)?;
        verify_mirror_receipt(&current, receipt, "after validation")?;
    }
    Ok(())
}

fn verify_mirror_receipt(
    current: &TargetPlan<'_>,
    receipt: &MirrorReceipt,
    phase: &str,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        current.destination()? == receipt.destination,
        "cluster mirror member changed {phase}: {}",
        current.display().display()
    );
    let digest = current
        .original_sha256()?
        .ok_or_else(|| anyhow::anyhow!("cluster mirror member disappeared {phase}"))?;
    anyhow::ensure!(
        current.destination()? == receipt.destination && digest == receipt.content_sha256,
        "cluster mirror member changed {phase}: {}",
        current.display().display()
    );
    Ok(())
}

/// The full overlay check already passed; retain a syntax gate on the exact
/// descriptor-pinned bytes before their atomic promotion.
fn write_bundle(target: &PinnedTarget<'_>, bundle_toml: &str) -> Result<(), AtomicWriteError> {
    let syntax_check = |staged: &std::fs::File, _display: &Path| -> Result<(), String> {
        use std::io::{Read, Seek};

        let mut staged = staged.try_clone().map_err(|e| e.to_string())?;
        staged.rewind().map_err(|e| e.to_string())?;
        let mut raw = String::new();
        staged.read_to_string(&mut raw).map_err(|e| e.to_string())?;
        raw.parse::<toml::Value>()
            .map(|_| ())
            .map_err(|e| e.to_string())
    };
    hardened_atomic_write_at(
        target,
        bundle_toml.as_bytes(),
        AtomicWriteAtOpts {
            validator: Some(&syntax_check),
            ..Default::default()
        },
    )
}

/// A post-rename fsync failure has a promoted receipt; restore through it so
/// the caller never advances its hash after an uncertain bundle publication.
fn settle_bundle_write_error(
    target: &PinnedTarget<'_>,
    before_bundle: Option<&str>,
    error: AtomicWriteError,
) -> anyhow::Result<PathBuf> {
    let path = target.display().to_path_buf();
    if !error.rename_landed() {
        return Err(anyhow::Error::new(error).context(format!(
            "cluster bundle publish failed before rename at {}; no mirror wipe was attempted",
            path.display()
        )));
    }
    match rollback_bundle(target, before_bundle) {
        Ok(()) => Err(anyhow::Error::new(error).context(format!(
            "cluster bundle rename landed at {} but durable rollback restored the prior bundle",
            path.display()
        ))),
        Err(rollback) => anyhow::bail!(
            "cluster bundle state at {} is uncertain after {error}; rollback could not be proved durable: {rollback:#}",
            path.display()
        ),
    }
}

fn rollback_bundle(target: &PinnedTarget<'_>, before_bundle: Option<&str>) -> anyhow::Result<()> {
    let rollback = target.rollback_target()?;
    match before_bundle {
        Some(bytes) => {
            hardened_atomic_write_at(&rollback, bytes.as_bytes(), AtomicWriteAtOpts::default())
                .map_err(anyhow::Error::new)
        }
        None => rollback.unlink().map_err(Into::into),
    }
}

/// Best-effort mirror cleanup follows a successful bundle publication. Each
/// unlink is descriptor-pinned and fsyncs its parent before the next one.
fn mirror_wipe_cluster_d(guard: &ConfigWriteLock, receipts: Vec<MirrorReceipt>) {
    for receipt in receipts {
        let result = (|| -> anyhow::Result<()> {
            let plan = guard
                .tree_io()
                .plan_root_file_no_follow(&receipt.relative)?;
            // `plan` retains this leaf until unlink, preventing inode reuse
            // across the final check for this member.
            verify_mirror_receipt(&plan, &receipt, "before cleanup")?;
            plan.materialize()?.unlink()?;
            Ok(())
        })();
        if let Err(error) = result {
            tracing::warn!(
                path = %guard.canonical_master().parent().unwrap_or_else(|| Path::new(".")).join(&receipt.relative).display(),
                error = %error,
                "cluster: failed to mirror-wipe stray cluster.d file"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::policy::ClusterPolicyBundle;

    const GOOD_BUNDLE: &str = "schema_version = 4\n\n[server]\ndefault_profile = \"default\"\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n";

    // neutrality-10: a secondary's OWN master declares no `[upstream]` — the
    // section arrives in `cluster.d/00-cluster-policy.toml`, because the
    // bundle carries `upstream` verbatim from the primary. `[upstream]` is a
    // singleton across the include set, so declaring it here too is a
    // duplicate-singleton error, not a belt-and-braces default. The merged
    // view still has exactly one, which is why removing the default does not
    // break cluster secondaries.
    const MASTER: &str =
        "schema_version = 4\nincludes = [\"cluster.d/*.toml\"]\n\n[server]\nlisten = \"127.0.0.1:15354\"\n";

    #[tokio::test]
    async fn apply_bundle_rejects_unloadable_merge_and_keeps_live() {
        // master with a node-local [server] (listen) + cluster.d include,
        // no profiles — a bundle whose default_profile dangles must fail
        // staging validation and leave the live cluster.d untouched.
        let tmp = tempfile::tempdir().unwrap();
        let master = tmp.path().join("config.toml");
        std::fs::write(&master, MASTER).unwrap();

        let bad_bundle = "schema_version = 4\n\n[server]\ndefault_profile = \"ghost\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n";
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

        let (tx, _rx) = mpsc::channel::<Option<u32>>(1);
        let res = apply_bundle(&master, GOOD_BUNDLE, &"a".repeat(64), &tx).await;
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
            "schema_version = 4\n\n[server]\ndefault_profile = \"default\"\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[api]\nenabled = true\ntoken_hash = \"attacker\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n";
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

        let cluster_d = tmp.path().join(CLUSTER_D);
        std::fs::create_dir(&cluster_d).unwrap();
        std::fs::write(
            cluster_d.join(BUNDLE_FILE),
            "schema_version = 4\n\n[server]\ndefault_profile = \"old\"\n\n[profiles.old]\ndisplay_name = \"Old\"\n\n[upstream]\nservers = [\"192.0.2.2:53\"]\n",
        )
        .unwrap();
        let stray = cluster_d.join("stale.toml");
        std::fs::write(&stray, "[upstream]\nservers = [\"192.0.2.3:53\"]\n").unwrap();
        let retained = cluster_d.join("operator-note.txt");
        std::fs::write(&retained, "not config\n").unwrap();

        let (tx, mut rx) = mpsc::channel::<Option<u32>>(1);
        apply_bundle(
            &master,
            GOOD_BUNDLE,
            &ClusterPolicyBundle::hash_of(GOOD_BUNDLE),
            &tx,
        )
        .await
        .unwrap();

        // Installed into cluster.d, master untouched, reload signalled.
        let installed = tmp.path().join(CLUSTER_D).join(BUNDLE_FILE);
        assert_eq!(std::fs::read_to_string(&installed).unwrap(), GOOD_BUNDLE);
        assert!(!stray.exists());
        assert!(retained.exists());
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

    #[test]
    fn apply_transaction_acquires_the_tree_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let tmp = tempfile::tempdir().unwrap();
        let master = tmp.path().join("config.toml");
        std::fs::write(&master, MASTER).unwrap();
        let acquisitions = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&acquisitions);
        crate::config::write_lock::with_test_hook(
            move |event| {
                if event == crate::config::write_lock::TestEvent::WriteRootLocked {
                    seen.fetch_add(1, Ordering::SeqCst);
                }
            },
            || stage_validate_install(&master, GOOD_BUNDLE).unwrap(),
        );
        assert_eq!(acquisitions.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn migration_fence_refuses_before_live_policy_changes() {
        let tmp = tempfile::tempdir().unwrap();
        let master = tmp.path().join("config.toml");
        std::fs::write(&master, MASTER).unwrap();
        let guard = crate::config::write_lock::acquire_for_migration(&master).unwrap();
        crate::config::migration_journal::create_fence(&guard).unwrap();
        drop(guard);

        let (tx, mut rx) = mpsc::channel::<Option<u32>>(1);
        let error = apply_bundle(
            &master,
            GOOD_BUNDLE,
            &ClusterPolicyBundle::hash_of(GOOD_BUNDLE),
            &tx,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("unfinished v3-to-v4 migration"));
        assert!(!tmp.path().join(CLUSTER_D).exists());
        assert!(matches!(
            rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn master_alias_publishes_only_beside_the_canonical_master() {
        let tmp = tempfile::tempdir().unwrap();
        let real_root = tmp.path().join("real");
        let alias_root = tmp.path().join("alias");
        std::fs::create_dir(&real_root).unwrap();
        std::fs::create_dir(&alias_root).unwrap();
        let master = real_root.join("config.toml");
        let alias = alias_root.join("config.toml");
        std::fs::write(&master, MASTER).unwrap();
        std::os::unix::fs::symlink(&master, &alias).unwrap();

        let (tx, mut rx) = mpsc::channel::<Option<u32>>(1);
        apply_bundle(
            &alias,
            GOOD_BUNDLE,
            &ClusterPolicyBundle::hash_of(GOOD_BUNDLE),
            &tx,
        )
        .await
        .unwrap();

        assert_eq!(
            std::fs::read_to_string(real_root.join(CLUSTER_D).join(BUNDLE_FILE)).unwrap(),
            GOOD_BUNDLE
        );
        assert!(!alias_root.join(CLUSTER_D).exists());
        assert_eq!(rx.try_recv().unwrap(), None);
    }

    #[tokio::test]
    async fn exact_include_accepts_the_first_managed_bundle() {
        let tmp = tempfile::tempdir().unwrap();
        let master = tmp.path().join("config.toml");
        std::fs::write(
            &master,
            "schema_version = 4\nincludes = [\"cluster.d/00-cluster-policy.toml\"]\n\n[server]\nlisten = \"127.0.0.1:15354\"\n",
        )
        .unwrap();
        let (tx, mut rx) = mpsc::channel::<Option<u32>>(1);

        apply_bundle(
            &master,
            GOOD_BUNDLE,
            &ClusterPolicyBundle::hash_of(GOOD_BUNDLE),
            &tx,
        )
        .await
        .unwrap();

        assert_eq!(
            std::fs::read_to_string(tmp.path().join(CLUSTER_D).join(BUNDLE_FILE)).unwrap(),
            GOOD_BUNDLE
        );
        assert_eq!(rx.try_recv().unwrap(), None);
    }

    #[tokio::test]
    async fn unselected_bundle_is_rejected_before_mirror_changes() {
        let tmp = tempfile::tempdir().unwrap();
        let master = tmp.path().join("config.toml");
        std::fs::write(
            &master,
            "schema_version = 4\nincludes = [\"cluster.d/old-*.toml\"]\n\n[server]\nlisten = \"127.0.0.1:15354\"\n",
        )
        .unwrap();
        let cluster_d = tmp.path().join(CLUSTER_D);
        std::fs::create_dir(&cluster_d).unwrap();
        let old = cluster_d.join("old-policy.toml");
        std::fs::write(&old, "[upstream]\nservers = [\"192.0.2.2:53\"]\n").unwrap();
        let (tx, mut rx) = mpsc::channel::<Option<u32>>(1);

        let error = apply_bundle(
            &master,
            GOOD_BUNDLE,
            &ClusterPolicyBundle::hash_of(GOOD_BUNDLE),
            &tx,
        )
        .await
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("staged config document was not reached"));
        assert!(old.exists());
        assert!(!cluster_d.join(BUNDLE_FILE).exists());
        assert!(matches!(
            rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn surviving_alias_to_a_mirror_target_aborts_before_publication() {
        let tmp = tempfile::tempdir().unwrap();
        let master = tmp.path().join("config.toml");
        std::fs::write(
            &master,
            "schema_version = 4\nincludes = [\"cluster.d/*.toml\", \"aliases.d/*.toml\"]\n\n[server]\nlisten = \"127.0.0.1:15354\"\n",
        )
        .unwrap();
        let cluster_d = tmp.path().join(CLUSTER_D);
        let aliases_d = tmp.path().join("aliases.d");
        std::fs::create_dir(&cluster_d).unwrap();
        std::fs::create_dir(&aliases_d).unwrap();
        let old = cluster_d.join("old.toml");
        std::fs::write(
            &old,
            "[profiles.old]\ndisplay_name = \"Old\"\n\n[upstream]\nservers = [\"192.0.2.2:53\"]\n",
        )
        .unwrap();
        let alias = aliases_d.join("link.toml");
        std::os::unix::fs::symlink("../cluster.d/old.toml", &alias).unwrap();
        let (tx, mut rx) = mpsc::channel::<Option<u32>>(1);

        let error = apply_bundle(
            &master,
            GOOD_BUNDLE,
            &ClusterPolicyBundle::hash_of(GOOD_BUNDLE),
            &tx,
        )
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains("resolves to an omitted member"),
            "{error:#}"
        );
        assert!(old.exists());
        assert!(alias.symlink_metadata().unwrap().file_type().is_symlink());
        assert!(!cluster_d.join(BUNDLE_FILE).exists());
        assert!(matches!(
            rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn write_guard_is_released_before_backpressured_reload_send() {
        use std::os::unix::io::AsRawFd;
        use std::time::Duration;

        let tmp = tempfile::tempdir().unwrap();
        let master = tmp.path().join("config.toml");
        std::fs::write(&master, MASTER).unwrap();
        let installed = tmp.path().join(CLUSTER_D).join(BUNDLE_FILE);
        let hash = ClusterPolicyBundle::hash_of(GOOD_BUNDLE);
        let (tx, mut rx) = mpsc::channel::<Option<u32>>(1);
        tx.send(Some(7)).await.unwrap();
        let task_master = master.clone();
        let task =
            tokio::spawn(async move { apply_bundle(&task_master, GOOD_BUNDLE, &hash, &tx).await });

        tokio::time::timeout(Duration::from_secs(5), async {
            while !installed.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("bundle publication timed out");
        assert!(
            !task.is_finished(),
            "reload send should still be backpressured"
        );

        let root = std::fs::File::open(tmp.path()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let rc = unsafe { libc::flock(root.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
                if rc == 0 {
                    break;
                }
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EWOULDBLOCK)
                );
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("config root remained locked across reload await");
        assert!(!task.is_finished(), "reload send should still be pending");
        drop(root);

        assert_eq!(rx.recv().await, Some(Some(7)));
        assert_eq!(rx.recv().await, Some(None));
        task.await.unwrap().unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn bundle_write_failures_preserve_or_restore_the_previous_bundle() {
        use crate::config::atomic_write::AtomicWriteTestFailure;
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let master = tmp.path().join("config.toml");
        std::fs::write(&master, MASTER).unwrap();
        let cluster_d = tmp.path().join(CLUSTER_D);
        std::fs::create_dir(&cluster_d).unwrap();
        let bundle = cluster_d.join(BUNDLE_FILE);
        let old = "[profiles.old]\ndisplay_name = \"Old\"\n";
        std::fs::write(&bundle, old).unwrap();
        std::fs::set_permissions(&bundle, std::fs::Permissions::from_mode(0o600)).unwrap();

        let guard = acquire_for_write(&master).unwrap();
        let target = guard
            .tree_io()
            .plan_root_file_no_follow(Path::new("cluster.d/00-cluster-policy.toml"))
            .unwrap()
            .materialize()
            .unwrap();
        let before_rename = hardened_atomic_write_at(
            &target,
            GOOD_BUNDLE.as_bytes(),
            AtomicWriteAtOpts {
                test_failure: Some(AtomicWriteTestFailure::TempFsync),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(!before_rename.rename_landed());
        assert!(settle_bundle_write_error(&target, Some(old), before_rename).is_err());
        assert_eq!(std::fs::read_to_string(&bundle).unwrap(), old);

        let after_rename = hardened_atomic_write_at(
            &target,
            GOOD_BUNDLE.as_bytes(),
            AtomicWriteAtOpts {
                test_failure: Some(AtomicWriteTestFailure::ParentFsync),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(after_rename.rename_landed());
        let error = settle_bundle_write_error(&target, Some(old), after_rename).unwrap_err();
        assert!(error.to_string().contains("durable rollback restored"));
        assert_eq!(std::fs::read_to_string(&bundle).unwrap(), old);
        assert_eq!(
            std::fs::metadata(&bundle).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    #[cfg(unix)]
    fn post_rename_failure_removes_a_first_bundle() {
        use crate::config::atomic_write::AtomicWriteTestFailure;

        let tmp = tempfile::tempdir().unwrap();
        let master = tmp.path().join("config.toml");
        std::fs::write(&master, MASTER).unwrap();
        let bundle = tmp.path().join(CLUSTER_D).join(BUNDLE_FILE);
        let guard = acquire_for_write(&master).unwrap();
        let target = guard
            .tree_io()
            .plan_root_file_no_follow(Path::new("cluster.d/00-cluster-policy.toml"))
            .unwrap()
            .materialize()
            .unwrap();

        let error = hardened_atomic_write_at(
            &target,
            GOOD_BUNDLE.as_bytes(),
            AtomicWriteAtOpts {
                test_failure: Some(AtomicWriteTestFailure::ParentFsync),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(error.rename_landed());
        assert!(settle_bundle_write_error(&target, None, error).is_err());
        assert!(!bundle.exists());
    }

    #[test]
    fn mirror_receipt_fingerprint_rejects_an_identity_collision() {
        let tmp = tempfile::tempdir().unwrap();
        let master = tmp.path().join("config.toml");
        std::fs::write(&master, MASTER).unwrap();
        let cluster_d = tmp.path().join(CLUSTER_D);
        std::fs::create_dir(&cluster_d).unwrap();
        let stray = cluster_d.join("old.toml");
        std::fs::write(&stray, "[profiles.aaa]\ndisplay_name = \"Old\"\n").unwrap();

        let guard = acquire_for_write(&master).unwrap();
        let mut overlay = LoaderOverlay::default();
        let (_bundle, mut receipts) = plan_live_targets(&guard, &mut overlay).unwrap();
        let mut receipt = receipts.pop().unwrap();
        std::fs::write(&stray, "[profiles.bbb]\ndisplay_name = \"New\"\n").unwrap();
        let current = guard
            .tree_io()
            .plan_root_file_no_follow(Path::new("cluster.d/old.toml"))
            .unwrap();
        // Model the hardest lightweight-receipt case: filesystem identity
        // fields collide, while the descriptor-read bytes do not.
        receipt.destination = current.destination().unwrap();
        let error = verify_mirror_receipt(&current, &receipt, "after replacement").unwrap_err();
        assert!(error.to_string().contains("changed after replacement"));
        assert!(stray.exists());
    }

    #[test]
    fn mirror_cap_refuses_before_bundle_publication() {
        let tmp = tempfile::tempdir().unwrap();
        let master = tmp.path().join("config.toml");
        std::fs::write(&master, MASTER).unwrap();
        let cluster_d = tmp.path().join(CLUSTER_D);
        std::fs::create_dir(&cluster_d).unwrap();
        for index in 0..=MAX_MIRROR_FILES {
            std::fs::write(
                cluster_d.join(format!("old-{index:04}.toml")),
                "[profiles.old]\ndisplay_name = \"Old\"\n",
            )
            .unwrap();
        }

        let error = stage_validate_install(&master, GOOD_BUNDLE).unwrap_err();
        assert!(error
            .to_string()
            .contains("mirror file count exceeds hard cap"));
        assert!(!cluster_d.join(BUNDLE_FILE).exists());
        assert_eq!(
            std::fs::read_dir(&cluster_d).unwrap().count(),
            MAX_MIRROR_FILES + 1
        );
    }

    #[test]
    #[cfg(unix)]
    fn mirror_planning_stays_within_a_constrained_descriptor_budget() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "cluster::apply::tests::mirror_descriptor_budget_child",
                "--nocapture",
            ])
            .env("WARDEN_MIRROR_BUDGET_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[cfg(unix)]
    fn mirror_descriptor_budget_child() {
        if std::env::var_os("WARDEN_MIRROR_BUDGET_CHILD").is_none() {
            return;
        }
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
            0
        );
        limit.rlim_cur = limit.rlim_max.min(128);
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);

        let tmp = tempfile::tempdir().unwrap();
        let master = tmp.path().join("config.toml");
        std::fs::write(&master, MASTER).unwrap();
        let cluster_d = tmp.path().join(CLUSTER_D);
        std::fs::create_dir(&cluster_d).unwrap();
        for index in 0..200 {
            std::fs::write(
                cluster_d.join(format!("old-{index:03}.toml")),
                format!("[profiles.old-{index:03}]\ndisplay_name = \"Old {index}\"\n"),
            )
            .unwrap();
        }

        stage_validate_install(&master, GOOD_BUNDLE).unwrap();
        let names = std::fs::read_dir(&cluster_d)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(names, [std::ffi::OsString::from(BUNDLE_FILE)]);
    }
}
