//! `warden config edit` — open the config file in `$EDITOR` then validate.
//!
//! Fully v1: the editor opens the config file as-is, and the post-edit
//! validation runs via [`crate::config::loader::load_config`] so every
//! v1 validator error is surfaced on save. For fresh files the editor is
//! given the init scaffold via [`crate::cli::commands::init::default_config`].
//!
//! §4.28 b9 cli-h1 + DISC-1 (2026-05-13): the editor invocation is now
//! a direct `Command::new(binary).args(extra).arg(config_path)` — the
//! pre-fix `sh -c` wrapper would interpret `$()`, `;`, or backticks in
//! the config path. The first-boot scaffold is now written through
//! [`crate::config::atomic_write::hardened_atomic_write`] with an
//! explicit `0o640` mode, matching the same pattern that
//! `cli/commands/init.rs:155` adopted in §4.31.

use std::path::Path;

use crate::cli::commands::init::default_config;
use crate::cli::exit_codes::{CONFIG, SUCCESS};
use crate::config::atomic_write::{hardened_atomic_write, AtomicWriteOpts};

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

    if !config_path.exists() {
        hardened_atomic_write(
            config_path,
            default_config().as_bytes(),
            AtomicWriteOpts {
                mode: Some(0o640),
                ..Default::default()
            },
        )
        .map_err(|e| anyhow::anyhow!("cannot create default config: {e}"))?;
        println!("created default v1 config at {}", config_path.display());
    }

    let (binary, extra_args) = split_editor_invocation(&editor);
    if binary.is_empty() {
        anyhow::bail!("$EDITOR is empty");
    }

    let status = std::process::Command::new(&binary)
        .args(&extra_args)
        .arg(config_path)
        .status()
        .map_err(|e| anyhow::anyhow!("failed to launch {}: {}", binary, e))?;

    if !status.success() {
        anyhow::bail!("{} exited with {}", binary, status);
    }

    // Validate after editing via the v1 loader so the operator sees
    // any typos / cross-ref misses with file:line attribution.
    let now = time::OffsetDateTime::now_utc();
    match crate::config::loader::load_config(config_path, now) {
        Ok(_) => {
            println!("config is valid");
            Ok(SUCCESS)
        }
        Err(errs) => {
            eprintln!("config has {} error(s):", errs.len());
            for e in &errs {
                eprintln!("  - {e}");
            }
            Ok(CONFIG)
        }
    }
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
    use std::sync::Mutex;

    /// Serialises the EDITOR-mutating tests below. `std::env::set_var` is
    /// process-global, so without this lock they race each other under
    /// `cargo test` parallelism (roundup-01; mirrors the HR2 `ENV_LOCK`
    /// pattern in `hr2_test_support.rs`). Poison is recovered — a panicking
    /// test must not wedge the rest.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

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
            "schema_version = 3\n\n[server]\ndefault_profile = \"ghost\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
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
            "schema_version = 3\n\n[server]\ndefault_profile = \"default\"\n\n\
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
