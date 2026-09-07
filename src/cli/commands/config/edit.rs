//! `warden config edit` — open the config file in `$EDITOR` then validate.
//!
//! Fully v1: the editor opens the config file as-is, and the post-edit
//! validation runs through the held write capability so every
//! v1 validator error is surfaced on save. For fresh files the editor is
//! given the init scaffold via [`crate::cli::commands::init::default_config`].
//!
//! §4.28 b9 cli-h1 + DISC-1 (2026-05-13): the editor invocation is now
//! a direct `Command::new(binary).args(extra).arg(config_path)` — the
//! pre-fix `sh -c` wrapper would interpret `$()`, `;`, or backticks in
//! the config path. The first-boot scaffold is now written through
//! [`crate::config::atomic_write::hardened_atomic_create_only_at`] with an
//! explicit `0o640` mode, matching the same pattern that
//! `cli/commands/init.rs:155` adopted in §4.31.

use std::io::Write;
use std::path::Path;

use crate::cli::commands::init::default_config;
use crate::cli::exit_codes::{CONFIG, SUCCESS};
use crate::config::atomic_write::{hardened_atomic_create_only_at, AtomicCreateOnlyAtOpts};
use crate::config::loader::{load_config_for_schema_under_editor_guard, EditorGuardedLoadFailure};
use crate::config::migration_journal;
use crate::config::schema::SCHEMA_VERSION_V1;
use crate::config::write_lock;

/// Open the config in `$EDITOR`; on exit, run the v1 loader + validator
/// and print any resulting errors.
///
/// Returns the intended process exit code: [`CONFIG`] when the file the
/// operator just saved does not validate, [`SUCCESS`] otherwise. Before
/// this the validator's output was printed and then discarded, so
/// `warden config edit && systemctl reload purge-warden` would happily
/// reload a config the daemon refuses — the one command sequence the
/// post-edit validation exists to protect.
///
/// A failure to *launch* the editor stays an `Err` (exit 1): that is the
/// operation failing, not the configuration being invalid.
pub fn run_edit(config_path: &Path) -> anyhow::Result<i32> {
    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());
    run_edit_with_raw_editor_runner(config_path, &editor, |binary, extra_args, target| {
        std::process::Command::new(binary)
            .args(extra_args)
            .arg(target)
            .status()
            .map_err(|e| anyhow::anyhow!("failed to launch {}: {}", binary, e))
    })
}

fn run_edit_with_raw_editor_runner(
    config_path: &Path,
    editor: &str,
    runner: impl FnOnce(&str, &[String], &Path) -> anyhow::Result<std::process::ExitStatus>,
) -> anyhow::Result<i32> {
    let (binary, extra_args) = split_editor_invocation(editor);
    if binary.is_empty() {
        anyhow::bail!("$EDITOR is empty");
    }
    run_edit_with_runner(config_path, &binary, &extra_args, runner)
}

fn run_edit_with_runner(
    config_path: &Path,
    binary: &str,
    extra_args: &[String],
    runner: impl FnOnce(&str, &[String], &Path) -> anyhow::Result<std::process::ExitStatus>,
) -> anyhow::Result<i32> {
    let guard = write_lock::acquire_for_write(config_path)?;
    let canonical_master = guard.canonical_master().to_path_buf();

    let created = {
        let plan = guard.tree_io().plan_master_target()?;
        if !plan.is_new() {
            false
        } else {
            let target = plan.materialize()?;
            let scaffold = default_config();
            let mut spool = tempfile::tempfile()
                .map_err(|e| anyhow::anyhow!("cannot spool default config: {e}"))?;
            spool
                .write_all(scaffold.as_bytes())
                .map_err(|e| anyhow::anyhow!("cannot spool default config: {e}"))?;
            hardened_atomic_create_only_at(
                &target,
                &mut spool,
                scaffold.len() as u64,
                AtomicCreateOnlyAtOpts {
                    mode: Some(0o640),
                    owner: Some(guard.admitted_side_lock_owner()?),
                    #[cfg(test)]
                    test_failure: None,
                },
            )
            .map_err(|e| anyhow::anyhow!("cannot create default config: {e}"))?;
            true
        }
    };
    if created {
        println!(
            "created default v1 config at {}",
            canonical_master.display()
        );
    }

    let status = runner(binary, extra_args, &canonical_master)?;

    guard.recapture_canonical_master_after_editor()?;
    #[cfg(test)]
    write_lock::test_event(write_lock::TestEvent::AfterEditorRecapture);

    if !status.success() {
        anyhow::bail!("{} exited with {}", binary, status);
    }

    #[cfg(test)]
    write_lock::test_event(write_lock::TestEvent::BeforeGuardedValidation);
    verify_post_editor_integrity(&guard)?;

    // Validate after editing via the v1 loader so the operator sees
    // any typos / cross-ref misses with file:line attribution.
    let now = time::OffsetDateTime::now_utc();
    let validation = load_config_for_schema_under_editor_guard(
        &guard,
        &canonical_master,
        SCHEMA_VERSION_V1,
        now,
    );
    #[cfg(test)]
    write_lock::test_event(write_lock::TestEvent::AfterGuardedValidation);
    verify_post_editor_integrity(&guard)?;
    match validation {
        Ok(_) => {
            println!("config is valid");
            Ok(SUCCESS)
        }
        Err(EditorGuardedLoadFailure::Diagnostics(errs)) => {
            eprintln!("config has {} error(s):", errs.len());
            for e in &errs {
                eprintln!("  - {e}");
            }
            Ok(CONFIG)
        }
        Err(EditorGuardedLoadFailure::Operational(err)) => Err(err),
    }
}

fn verify_post_editor_integrity(guard: &write_lock::ConfigWriteLock) -> anyhow::Result<()> {
    guard.tree_io().plan_master_target()?;
    migration_journal::refuse_normal_access(guard.tree_io())?;
    Ok(())
}

/// Split an `$EDITOR` string on ASCII whitespace into `(binary, args)`.
/// Hand-rolled because `shlex` is not in the dep tree and the operator
/// surface we cover is "EDITOR=vim", "EDITOR=vim -X", "EDITOR=code
/// --wait", etc. Operators who need shell-quoted EDITOR values
/// (`EDITOR="vim -c 'set ft=toml'"`) fall back to a wrapper script.
///
/// Shared with the dashboard's Settings-tab `e` handler
/// (`tui::handle_settings_key`) so both `$EDITOR` shell-outs parse the value
/// identically — an empty `binary` means the value had no non-whitespace token.
pub(crate) fn split_editor_invocation(raw: &str) -> (String, Vec<String>) {
    let mut parts = raw.split_whitespace();
    let binary = parts.next().map(String::from).unwrap_or_default();
    let args = parts.map(String::from).collect();
    (binary, args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc, Mutex};

    /// Serialises the EDITOR-mutating tests below. `std::env::set_var` is
    /// process-global, so without this lock they race each other under
    /// `cargo test` parallelism (roundup-01; mirrors the HR2 `ENV_LOCK`
    /// pattern in `hr2_test_support.rs`). Poison is recovered — a panicking
    /// test must not wedge the rest.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn valid_config() -> &'static str {
        "schema_version = 4\n\n[server]\ndefault_profile = \"default\"\n\n\
         [profiles.default]\ndisplay_name = \"Default\"\ntags = [\"uncategorized\"]\n\n\
         [upstream]\nservers = [\"192.0.2.1:53\"]\n"
    }

    fn successful_status() -> std::process::ExitStatus {
        std::process::Command::new("/bin/true").status().unwrap()
    }

    fn failing_status() -> std::process::ExitStatus {
        std::process::Command::new("/bin/false").status().unwrap()
    }

    #[allow(dead_code, reason = "the contender reports while this guard is live")]
    enum HeldGuard {
        Read(crate::config::write_lock::ConfigReadLock),
        Write(crate::config::write_lock::ConfigWriteLock),
    }

    #[test]
    fn split_editor_invocation_plain_binary() {
        let (bin, args) = split_editor_invocation("vim");
        assert_eq!(bin, "vim");
        assert!(args.is_empty());
    }

    #[test]
    fn split_editor_invocation_binary_with_args() {
        let (bin, args) = split_editor_invocation("vim -X");
        assert_eq!(bin, "vim");
        assert_eq!(args, vec!["-X".to_string()]);
    }

    #[test]
    fn split_editor_invocation_multiple_args() {
        let (bin, args) = split_editor_invocation("code --wait --new-window");
        assert_eq!(bin, "code");
        assert_eq!(args, vec!["--wait".to_string(), "--new-window".to_string()]);
    }

    #[test]
    fn split_editor_invocation_collapses_whitespace() {
        let (bin, args) = split_editor_invocation("  vim   -X  ");
        assert_eq!(bin, "vim");
        assert_eq!(args, vec!["-X".to_string()]);
    }

    #[test]
    fn split_editor_invocation_empty_string() {
        let (bin, args) = split_editor_invocation("");
        assert!(bin.is_empty());
        assert!(args.is_empty());
    }

    #[test]
    fn empty_editor_is_rejected_before_config_effects() {
        let tmp = tempfile::tempdir().unwrap();
        let master = tmp.path().join("missing-root/config.toml");
        let result = run_edit_with_raw_editor_runner(&master, "   ", |_, _, _| unreachable!());

        assert!(result.is_err());
        assert!(!master.parent().unwrap().exists());
    }

    #[test]
    #[cfg(unix)]
    fn edit_runner_uses_canonical_target_and_preserves_master_alias() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real.toml");
        let alias = tmp.path().join("alias.toml");
        fs::write(&real, valid_config()).unwrap();
        symlink("real.toml", &alias).unwrap();

        let code = run_edit_with_runner(&alias, "editor", &[], |_, _, target| {
            assert_eq!(target, real);
            Ok(successful_status())
        })
        .unwrap();

        assert_eq!(code, SUCCESS);
        assert!(fs::symlink_metadata(&alias)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    #[cfg(unix)]
    fn edit_scaffolds_dangling_alias_at_canonical_target_before_editor() {
        let tmp = tempfile::tempdir().unwrap();
        let real_dir = tmp.path().join("real");
        fs::create_dir(&real_dir).unwrap();
        let real = real_dir.join("config.toml");
        let alias = tmp.path().join("alias.toml");
        symlink("real/config.toml", &alias).unwrap();

        let code = run_edit_with_runner(&alias, "editor", &[], |_, _, target| {
            assert_eq!(target, real);
            assert!(target.exists(), "scaffold must precede editor launch");
            assert_eq!(
                fs::metadata(target).unwrap().permissions().mode() & 0o777,
                0o640
            );
            let saved = target.with_extension("editor-save");
            fs::write(&saved, valid_config()).unwrap();
            fs::rename(saved, target).unwrap();
            Ok(successful_status())
        })
        .unwrap();

        assert_eq!(code, SUCCESS);
        assert!(fs::symlink_metadata(&alias)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    #[cfg(unix)]
    fn edit_scaffold_uses_the_admitted_lock_owner_before_editor_launch() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let real_dir = tmp.path().join("real");
        fs::create_dir(&real_dir).unwrap();
        let directory = fs::File::open(&real_dir).unwrap();
        assert_eq!(
            unsafe { libc::fchown(directory.as_raw_fd(), 65534, 65534) },
            0
        );
        drop(directory);
        let master = real_dir.join("config.toml");
        let alias = tmp.path().join("alias.toml");
        symlink("real/config.toml", &alias).unwrap();

        assert_eq!(
            run_edit_with_runner(&alias, "editor", &[], |_, _, target| {
                let master = fs::metadata(target).unwrap();
                let lock =
                    fs::metadata(target.parent().unwrap().join(".warden-config.lock")).unwrap();
                assert_eq!((master.uid(), master.gid()), (65534, 65534));
                assert_eq!((lock.uid(), lock.gid()), (65534, 65534));
                assert_eq!(master.mode() & 0o777, 0o640);
                fs::write(target, valid_config()).unwrap();
                Ok(successful_status())
            })
            .unwrap(),
            SUCCESS
        );
        drop(crate::config::write_lock::acquire_for_write(&master).unwrap());

        let failed = real_dir.join("failed.toml");
        assert!(
            run_edit_with_runner(&failed, "editor", &[], |_, _, target| {
                assert_eq!(
                    (
                        fs::metadata(target).unwrap().uid(),
                        fs::metadata(target).unwrap().gid()
                    ),
                    (65534, 65534)
                );
                Ok(failing_status())
            })
            .is_err()
        );
        let lock = fs::metadata(real_dir.join(".warden-config.lock")).unwrap();
        let scaffold = fs::metadata(&failed).unwrap();
        assert_eq!((scaffold.uid(), scaffold.gid()), (65534, 65534));
        assert_eq!((lock.uid(), lock.gid()), (65534, 65534));
        assert_eq!(scaffold.mode() & 0o777, 0o640);
        drop(crate::config::write_lock::acquire_for_write(&failed).unwrap());
    }

    #[test]
    #[cfg(unix)]
    fn edit_accepts_in_place_and_valid_rename_saves() {
        let tmp = tempfile::tempdir().unwrap();
        let master = tmp.path().join("config.toml");
        fs::write(&master, valid_config()).unwrap();
        let in_place = run_edit_with_runner(&master, "editor", &[], |_, _, target| {
            fs::write(target, valid_config()).unwrap();
            Ok(successful_status())
        })
        .unwrap();
        assert_eq!(in_place, SUCCESS);

        let renamed_bytes = format!("{}# renamed\n", valid_config());
        let renamed = run_edit_with_runner(&master, "editor", &[], |_, _, target| {
            let saved = target.with_extension("editor-save");
            fs::write(&saved, &renamed_bytes).unwrap();
            fs::rename(saved, target).unwrap();
            Ok(successful_status())
        })
        .unwrap();
        assert_eq!(renamed, SUCCESS);
        assert_eq!(fs::read_to_string(&master).unwrap(), renamed_bytes);
    }

    #[test]
    #[cfg(unix)]
    fn edit_keeps_invalid_rename_bytes_live_after_schema_validation() {
        let tmp = tempfile::tempdir().unwrap();
        let master = tmp.path().join("config.toml");
        fs::write(&master, valid_config()).unwrap();
        let invalid = "schema_version = 4\n[server]\ndefault_profile = \"missing\"\n";
        let observed_validation = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&observed_validation);
        let renamed = crate::config::write_lock::with_test_hook(
            move |event| {
                if event == crate::config::write_lock::TestEvent::OverlayResolved {
                    observed.store(1, Ordering::SeqCst);
                }
            },
            || {
                run_edit_with_runner(&master, "editor", &[], |_, _, target| {
                    let saved = target.with_extension("editor-save");
                    fs::write(&saved, invalid).unwrap();
                    fs::rename(saved, target).unwrap();
                    Ok(successful_status())
                })
                .unwrap()
            },
        );
        assert_eq!(renamed, CONFIG);
        assert_eq!(observed_validation.load(Ordering::SeqCst), 1);
        assert_eq!(fs::read_to_string(&master).unwrap(), invalid);
    }

    #[test]
    #[cfg(unix)]
    fn edit_fence_refusal_precedes_scaffold_and_editor() {
        let tmp = tempfile::tempdir().unwrap();
        let master = tmp.path().join("config.toml");
        let migration = crate::config::write_lock::acquire_for_migration(&master).unwrap();
        crate::config::migration_journal::create_fence(&migration).unwrap();
        drop(migration);
        let mut launched = false;

        assert!(run_edit_with_runner(&master, "editor", &[], |_, _, _| {
            launched = true;
            Ok(successful_status())
        })
        .is_err());
        assert!(!launched);
        assert!(!master.exists());
    }

    #[test]
    #[cfg(unix)]
    fn edit_holds_the_guard_through_editor_and_validation() {
        const CONTENDER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

        let tmp = tempfile::tempdir().unwrap();
        let master = tmp.path().join("config.toml");
        fs::write(
            &master,
            "schema_version = 4\nincludes = [\"slice.toml\"]\n\n[server]\ndefault_profile = \"default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        )
        .unwrap();
        fs::write(
            tmp.path().join("slice.toml"),
            "[profiles.default]\ndisplay_name = \"Default\"\ntags = [\"uncategorized\"]\n",
        )
        .unwrap();
        let (contended_tx, contended_rx) = mpsc::channel();
        let contended_rx = Arc::new(Mutex::new(contended_rx));
        let (acquired_tx, acquired_rx) = mpsc::channel();
        let live_guards = Arc::new(AtomicUsize::new(0));
        let workers = Arc::new(Mutex::new(Vec::new()));
        let validation_phases = Arc::new(AtomicUsize::new(0));
        let write_acquisitions = Arc::new(AtomicUsize::new(0));
        let path = Arc::new(master.clone());

        let await_contended = {
            let contended_rx = Arc::clone(&contended_rx);
            Arc::new(move |group| {
                let mut seen = [false; 2];
                while !seen.iter().all(|seen| *seen) {
                    let (observed_group, writer) = contended_rx
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .recv_timeout(CONTENDER_TIMEOUT)
                        .expect("bounded contender observation");
                    assert_eq!(observed_group, group);
                    assert!(!seen[usize::from(writer)], "contender reported twice");
                    seen[usize::from(writer)] = true;
                }
            })
        };
        let start_pair = {
            let workers = Arc::clone(&workers);
            let path = Arc::clone(&path);
            let contended = contended_tx.clone();
            let acquired = acquired_tx.clone();
            let live_guards = Arc::clone(&live_guards);
            Arc::new(move |group| {
                for writer in [false, true] {
                    let path = Arc::clone(&path);
                    let contended = contended.clone();
                    let acquired = acquired.clone();
                    let live_guards = Arc::clone(&live_guards);
                    let handle = std::thread::spawn(move || {
                        let mut reported = false;
                        let observe = move |event| {
                            if event == crate::config::write_lock::TestEvent::Contended && !reported
                            {
                                contended.send((group, writer)).unwrap();
                                reported = true;
                            }
                        };
                        let result = if writer {
                            crate::config::write_lock::with_test_hook(observe, || {
                                crate::config::write_lock::acquire_for_write_with_timeout(
                                    &path,
                                    CONTENDER_TIMEOUT,
                                )
                                .map(HeldGuard::Write)
                            })
                        } else {
                            crate::config::write_lock::with_test_hook(observe, || {
                                crate::config::write_lock::acquire_for_read_with_timeout(
                                    &path,
                                    CONTENDER_TIMEOUT,
                                )
                                .map(HeldGuard::Read)
                            })
                        };
                        match result {
                            Ok(_guard) => {
                                let (release_tx, release_rx) = mpsc::channel();
                                live_guards.fetch_add(1, Ordering::SeqCst);
                                acquired.send((group, writer, Ok(release_tx))).unwrap();
                                let _ = release_rx.recv_timeout(CONTENDER_TIMEOUT);
                                live_guards.fetch_sub(1, Ordering::SeqCst);
                            }
                            Err(err) => acquired
                                .send((group, writer, Err(format!("{err:#}"))))
                                .unwrap(),
                        }
                    });
                    workers
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .push(handle);
                }
            })
        };

        crate::config::write_lock::with_test_hook(
            {
                let start_pair = Arc::clone(&start_pair);
                let await_contended = Arc::clone(&await_contended);
                let live_guards = Arc::clone(&live_guards);
                let validation_phases = Arc::clone(&validation_phases);
                let write_acquisitions = Arc::clone(&write_acquisitions);
                move |event| {
                    if event == crate::config::write_lock::TestEvent::WriteRootLocked {
                        write_acquisitions.fetch_add(1, Ordering::SeqCst);
                    }
                    if let crate::config::write_lock::TestEvent::BeforeGuardedValidation
                    | crate::config::write_lock::TestEvent::AfterGuardedValidation = event
                    {
                        let group = validation_phases.fetch_add(1, Ordering::SeqCst) + 1;
                        start_pair(group);
                        await_contended(group);
                        assert_eq!(live_guards.load(Ordering::SeqCst), 0);
                    }
                }
            },
            || {
                let code = run_edit_with_runner(&master, "editor", &[], |_, _, _| {
                    start_pair(0);
                    await_contended(0);
                    assert_eq!(live_guards.load(Ordering::SeqCst), 0);
                    Ok(successful_status())
                })
                .unwrap();
                assert_eq!(code, SUCCESS);
            },
        );

        assert_eq!(validation_phases.load(Ordering::SeqCst), 2);
        assert_eq!(write_acquisitions.load(Ordering::SeqCst), 1);
        let mut entered = [[false; 2]; 3];
        for _ in 0..6 {
            let (group, writer, release) = acquired_rx
                .recv_timeout(CONTENDER_TIMEOUT)
                .expect("bounded post-edit acquisition");
            assert!(group < entered.len());
            assert!(!entered[group][usize::from(writer)]);
            assert!(live_guards.load(Ordering::SeqCst) > 0);
            entered[group][usize::from(writer)] = true;
            release
                .expect("contender must acquire after edit")
                .send(())
                .unwrap();
        }
        assert!(entered.iter().all(|group| group.iter().all(|seen| *seen)));
        for handle in workers
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .drain(..)
        {
            handle.join().unwrap();
        }
        assert_eq!(live_guards.load(Ordering::SeqCst), 0);
    }

    #[test]
    #[cfg(unix)]
    fn edit_errors_release_the_write_guard() {
        let tmp = tempfile::tempdir().unwrap();
        let master = tmp.path().join("config.toml");
        fs::write(&master, valid_config()).unwrap();

        assert!(run_edit_with_runner(&master, "editor", &[], |_, _, _| {
            anyhow::bail!("editor launch failed")
        })
        .is_err());
        drop(crate::config::write_lock::acquire_for_write(&master).unwrap());

        assert!(
            run_edit_with_runner(&master, "editor", &[], |_, _, target| {
                fs::remove_file(target).unwrap();
                Ok(successful_status())
            })
            .is_err()
        );
        fs::write(&master, valid_config()).unwrap();
        drop(crate::config::write_lock::acquire_for_write(&master).unwrap());
    }

    #[test]
    #[cfg(unix)]
    fn edit_recaptures_a_saved_file_before_reporting_a_nonzero_editor_exit() {
        let tmp = tempfile::tempdir().unwrap();
        let master = tmp.path().join("config.toml");
        fs::write(&master, valid_config()).unwrap();
        let saved_bytes = format!("{}# saved despite nonzero\n", valid_config());
        let recaptured = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&recaptured);
        let result = crate::config::write_lock::with_test_hook(
            move |event| match event {
                crate::config::write_lock::TestEvent::AfterEditorRecapture => {
                    observed.fetch_add(1, Ordering::SeqCst);
                }
                crate::config::write_lock::TestEvent::BeforeGuardedValidation => {
                    panic!("nonzero editor exit must skip validation");
                }
                _ => {}
            },
            || {
                run_edit_with_runner(&master, "editor", &[], |_, _, target| {
                    let saved = target.with_extension("editor-save");
                    fs::write(&saved, &saved_bytes).unwrap();
                    fs::rename(saved, target).unwrap();
                    Ok(failing_status())
                })
            },
        );
        assert!(result.is_err());
        assert_eq!(recaptured.load(Ordering::SeqCst), 1);
        assert_eq!(fs::read_to_string(&master).unwrap(), saved_bytes);
        drop(crate::config::write_lock::acquire_for_write(&master).unwrap());
    }

    #[test]
    #[cfg(unix)]
    fn edit_nonzero_save_recaptures_changed_owner_when_privileged() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let master = tmp.path().join("config.toml");
        fs::write(&master, valid_config()).unwrap();
        let original = fs::File::open(&master).unwrap();
        assert_eq!(
            unsafe { libc::fchown(original.as_raw_fd(), 65534, 65534) },
            0
        );
        drop(original);
        let saved_bytes = format!("{}# root editor save\n", valid_config());

        assert!(
            run_edit_with_runner(&master, "editor", &[], |_, _, target| {
                let saved = target.with_extension("editor-save");
                fs::write(&saved, &saved_bytes).unwrap();
                fs::rename(saved, target).unwrap();
                Ok(failing_status())
            })
            .is_err()
        );
        assert_eq!(fs::read_to_string(&master).unwrap(), saved_bytes);
        let meta = fs::metadata(&master).unwrap();
        assert_eq!((meta.uid(), meta.gid()), (65534, 65534));
        drop(crate::config::write_lock::acquire_for_write(&master).unwrap());
    }

    #[test]
    #[cfg(unix)]
    fn edit_reports_recaptured_owner_sync_failure_and_releases_the_guard() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let master = tmp.path().join("config.toml");
        fs::write(&master, valid_config()).unwrap();
        let original = fs::File::open(&master).unwrap();
        assert_eq!(
            unsafe { libc::fchown(original.as_raw_fd(), 65534, 65534) },
            0
        );
        drop(original);

        let result = crate::config::write_lock::with_recaptured_owner_sync_failure(|| {
            run_edit_with_runner(&master, "editor", &[], |_, _, target| {
                let saved = target.with_extension("editor-save");
                fs::write(&saved, valid_config()).unwrap();
                fs::rename(saved, target).unwrap();
                Ok(successful_status())
            })
        });
        assert!(result.is_err());
        let meta = fs::metadata(&master).unwrap();
        assert_eq!((meta.uid(), meta.gid()), (65534, 65534));
        drop(crate::config::write_lock::acquire_for_write(&master).unwrap());
    }

    #[test]
    #[cfg(unix)]
    fn edit_keeps_loader_observed_master_swaps_operational() {
        let tmp = tempfile::tempdir().unwrap();
        let master = tmp.path().join("config.toml");
        let original = format!("includes = [\"*.toml\"]\n{}", valid_config());
        fs::write(&master, &original).unwrap();
        let replacement = tmp.path().join("replacement.toml");
        fs::write(&replacement, &original).unwrap();
        let displaced = tmp.path().join("displaced.toml");
        let swapped = Arc::new(AtomicUsize::new(0));
        let restored = Arc::new(AtomicUsize::new(0));
        let saw_swap = Arc::clone(&swapped);
        let saw_restore = Arc::clone(&restored);
        let master_for_hook = master.clone();
        let result = crate::config::write_lock::with_test_hook(
            move |event| match event {
                crate::config::write_lock::TestEvent::IncludeDirectoryPinned
                    if saw_swap.fetch_add(1, Ordering::SeqCst) == 0 =>
                {
                    fs::rename(&master_for_hook, &displaced).unwrap();
                    fs::rename(&replacement, &master_for_hook).unwrap();
                }
                crate::config::write_lock::TestEvent::AfterGuardedValidation
                    if saw_restore.fetch_add(1, Ordering::SeqCst) == 0 =>
                {
                    fs::remove_file(&master_for_hook).unwrap();
                    fs::rename(&displaced, &master_for_hook).unwrap();
                }
                _ => {}
            },
            || run_edit_with_runner(&master, "editor", &[], |_, _, _| Ok(successful_status())),
        );
        assert!(result.is_err());
        assert_eq!(swapped.load(Ordering::SeqCst), 1);
        assert_eq!(restored.load(Ordering::SeqCst), 1);
        assert_eq!(fs::read_to_string(&master).unwrap(), original);
        drop(crate::config::write_lock::acquire_for_write(&master).unwrap());
    }

    #[test]
    #[cfg(unix)]
    fn edit_keeps_escaping_exact_include_diagnostics_as_config() {
        let tmp = tempfile::tempdir().unwrap();
        let master = tmp.path().join("config.toml");
        fs::write(
            &master,
            format!("includes = [\"slice.toml\"]\n{}", valid_config()),
        )
        .unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        fs::write(outside.path(), "not reachable").unwrap();
        symlink(outside.path(), tmp.path().join("slice.toml")).unwrap();

        assert_eq!(
            run_edit_with_runner(&master, "editor", &[], |_, _, _| Ok(successful_status()))
                .unwrap(),
            CONFIG
        );
        drop(crate::config::write_lock::acquire_for_write(&master).unwrap());
    }

    #[test]
    #[cfg(unix)]
    fn edit_reports_post_editor_fence_and_master_swaps_as_operational_errors() {
        for phase in [
            crate::config::write_lock::TestEvent::BeforeGuardedValidation,
            crate::config::write_lock::TestEvent::AfterGuardedValidation,
        ] {
            for fence in [false, true] {
                let tmp = tempfile::tempdir().unwrap();
                let master = tmp.path().join("config.toml");
                fs::write(&master, valid_config()).unwrap();
                let replacement = tmp.path().join("replacement");
                let replacement_bytes = format!("{}# replacement\n", valid_config());
                fs::write(&replacement, &replacement_bytes).unwrap();
                let leaf = master.clone();
                let journal = tmp.path().join(".warden-migration");
                let result = crate::config::write_lock::with_test_hook(
                    move |event| {
                        if event == phase {
                            if fence {
                                fs::create_dir(&journal).unwrap();
                            } else {
                                fs::rename(&replacement, &leaf).unwrap();
                            }
                        }
                    },
                    || {
                        run_edit_with_runner(&master, "editor", &[], |_, _, _| {
                            Ok(successful_status())
                        })
                    },
                );
                assert!(result.is_err());
                if fence {
                    assert_eq!(fs::read_to_string(&master).unwrap(), valid_config());
                    fs::remove_dir(tmp.path().join(".warden-migration")).unwrap();
                } else {
                    assert_eq!(fs::read_to_string(&master).unwrap(), replacement_bytes);
                }
                drop(crate::config::write_lock::acquire_for_write(&master).unwrap());
            }
        }
    }

    /// cli-h1 regression: a config_path containing shell metacharacters
    /// must not be interpreted by a shell. Pre-fix the `sh -c "$EDITOR
    /// \"$config_path\""` invocation would expand `$(touch …)`. We use
    /// `/bin/true` as EDITOR so the spawn succeeds without depending on
    /// any user-side editor, and the assertion is "the sentinel file
    /// never appears" — meaning `$(touch sentinel)` was not evaluated.
    #[test]
    #[cfg(unix)]
    fn run_edit_does_not_interpret_shell_metacharacters_in_path() {
        let tmp = tempfile::tempdir().unwrap();
        let sentinel = tmp.path().join("pwned-marker");
        assert!(!sentinel.exists());

        // The interpolation we want NOT to happen: if the path were
        // ever fed through `sh -c`, the `$()` would run `touch
        // <sentinel>` and create the file.
        let crafted_name = format!("foo$(touch {}).toml", sentinel.display());
        let config_path = tmp.path().join(&crafted_name);

        let _env = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("EDITOR", "/bin/true");
        let _ = run_edit(&config_path);

        assert!(
            !sentinel.exists(),
            "sentinel `{}` exists — the $() substitution was interpreted",
            sentinel.display()
        );
    }

    /// EDITOR with whitespace-separated args. Use `/usr/bin/env true`
    /// so the binary lookup is portable and the args path is exercised
    /// without depending on a specific editor being installed.
    #[test]
    #[cfg(unix)]
    fn run_edit_handles_editor_with_args() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("c.toml");

        let _env = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("EDITOR", "/usr/bin/env true");
        let result = run_edit(&config_path);
        assert!(
            result.is_ok(),
            "run_edit should succeed when EDITOR carries args, got: {:?}",
            result.err()
        );
    }

    /// The headline fix: an unedited-but-invalid config must not exit 0.
    ///
    /// `EDITOR=/bin/true` leaves the file exactly as written, so the config
    /// the validator sees is the broken one below. Before this the errors
    /// were printed and the command still returned success, so
    /// `warden config edit && systemctl reload purge-warden` reloaded a
    /// config the daemon refuses.
    #[test]
    #[cfg(unix)]
    fn run_edit_exits_config_when_the_saved_file_is_invalid() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("broken.toml");
        // `default_profile` names a profile that does not exist — a
        // cross-ref miss the validator rejects, not a syntax error, so
        // this also proves the full validator runs and not just a parse.
        std::fs::write(
            &config_path,
            "schema_version = 4\n\n[server]\ndefault_profile = \"ghost\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        )
        .unwrap();

        let _env = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("EDITOR", "/bin/true");
        let code = run_edit(&config_path).expect("editor launched fine");
        assert_eq!(
            code, CONFIG,
            "an invalid saved config reported success to the shell"
        );
    }

    /// Control arm for the test above: the same path over a *valid* config
    /// must still be 0. Without this, returning CONFIG unconditionally
    /// would pass the test above and break every real edit.
    #[test]
    #[cfg(unix)]
    fn run_edit_exits_success_when_the_saved_file_is_valid() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("good.toml");
        std::fs::write(
            &config_path,
            "schema_version = 4\n\n[server]\ndefault_profile = \"default\"\n\n\
             [profiles.default]\ndisplay_name = \"Default\"\ntags = [\"uncategorized\"]\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        )
        .unwrap();

        let _env = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("EDITOR", "/bin/true");
        let code = run_edit(&config_path).expect("editor launched fine");
        assert_eq!(code, SUCCESS, "a valid saved config must exit 0");
    }

    /// DISC-1 regression: the first-boot scaffold lands via
    /// hardened_atomic_write with mode 0o640, not a raw fs::write.
    #[test]
    #[cfg(unix)]
    fn run_edit_creates_first_boot_config_via_hardened_atomic_write() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("first-boot.toml");
        assert!(!config_path.exists());

        let _env = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("EDITOR", "/bin/true");
        let result = run_edit(&config_path);
        // The loader may complain about the scaffold's profile shape vs
        // the schema; we only care about the create path landing with
        // the right mode.
        let _ = result;

        assert!(config_path.exists(), "first-boot scaffold must be created");
        let mode = std::fs::metadata(&config_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o640,
            "first-boot scaffold must land mode 0o640; got {:o}",
            mode
        );
    }
}
