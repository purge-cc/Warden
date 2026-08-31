//! `warden completion <shell>` — emit a shell-completion script.
//!
//! Uses [`clap_complete`] to generate the script from the clap command
//! tree. The output goes to stdout so operators can pipe it wherever
//! their shell expects completion files, e.g.:
//!
//! ```sh
//! warden completion bash  > /etc/bash_completion.d/warden
//! warden completion zsh   > "${fpath[1]}/_warden"
//! warden completion fish  > ~/.config/fish/completions/warden.fish
//! ```
//!
//! Sprint 33 ships a static completion tree (every subcommand / flag
//! clap knows). Entity-ID completion (reading the loaded config and
//! suggesting device / group / subnet ids) is a follow-up — it would
//! need a shell callback rather than a static script. The current
//! surface already handles the 90% case: `warden <TAB>` completes the
//! subcommand name, `warden device <TAB>` completes the action name,
//! `warden device add --<TAB>` completes the flag list.

use clap::CommandFactory;
use clap_complete::{generate, Shell};

use crate::cli::Cli;

/// Supported shells for completion script generation. Maps 1:1 to
/// [`clap_complete::Shell`] but is re-exposed via [`clap::ValueEnum`] so
/// the CLI can accept it with a friendly error on unsupported values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum CompletionShell {
    Bash,
    Zsh,
    Fish,
    Elvish,
    #[value(name = "powershell")]
    PowerShell,
}

impl From<CompletionShell> for Shell {
    fn from(s: CompletionShell) -> Self {
        match s {
            CompletionShell::Bash => Shell::Bash,
            CompletionShell::Zsh => Shell::Zsh,
            CompletionShell::Fish => Shell::Fish,
            CompletionShell::Elvish => Shell::Elvish,
            CompletionShell::PowerShell => Shell::PowerShell,
        }
    }
}

/// Render the completion script for `shell` to stdout.
pub fn run(shell: CompletionShell) -> anyhow::Result<()> {
    let mut cmd = Cli::command();
    generate(
        Shell::from(shell),
        &mut cmd,
        "warden",
        &mut std::io::stdout(),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap_complete::generate;
    use std::io::Cursor;

    #[test]
    fn bash_script_emits_function_definition() {
        let mut cmd = Cli::command();
        let mut buf: Vec<u8> = Vec::new();
        let mut out = Cursor::new(&mut buf);
        generate(Shell::Bash, &mut cmd, "warden", &mut out);
        let script = String::from_utf8(buf).unwrap();
        // A bash completion script always declares an `_warden()`
        // function and registers it with `complete -F`.
        assert!(
            script.contains("_warden()"),
            "bash script should define _warden(): first 200 chars: {}",
            &script.chars().take(200).collect::<String>()
        );
        assert!(script.contains("complete -F"), "must register completion");
    }

    #[test]
    fn zsh_script_emits_compdef() {
        let mut cmd = Cli::command();
        let mut buf: Vec<u8> = Vec::new();
        let mut out = Cursor::new(&mut buf);
        generate(Shell::Zsh, &mut cmd, "warden", &mut out);
        let script = String::from_utf8(buf).unwrap();
        assert!(script.contains("#compdef warden"), "got zsh script");
    }

    #[test]
    fn fish_script_emits_complete_command() {
        let mut cmd = Cli::command();
        let mut buf: Vec<u8> = Vec::new();
        let mut out = Cursor::new(&mut buf);
        generate(Shell::Fish, &mut cmd, "warden", &mut out);
        let script = String::from_utf8(buf).unwrap();
        assert!(
            script.contains("complete -c warden"),
            "fish script uses complete -c"
        );
    }

    #[test]
    fn script_mentions_new_s33_subcommands() {
        // Smoke-test that S33 subcommands appear in the completion
        // output — catches the clap tree falling out of sync with the
        // completion generator.
        let mut cmd = Cli::command();
        let mut buf: Vec<u8> = Vec::new();
        let mut out = Cursor::new(&mut buf);
        generate(Shell::Bash, &mut cmd, "warden", &mut out);
        let script = String::from_utf8(buf).unwrap();
        for sub in &["device", "group", "subnet", "blocklist", "completion"] {
            assert!(script.contains(sub), "bash script should mention '{sub}'");
        }
    }

    /// Sprint 38 QLP8: the new top-level `warden reload` subcommand
    /// must appear in the generated bash completion. Pinning this
    /// here catches the `Commands::Reload` variant being silently
    /// dropped in a future refactor.
    #[test]
    fn script_mentions_warden_reload() {
        let mut cmd = Cli::command();
        let mut buf: Vec<u8> = Vec::new();
        let mut out = Cursor::new(&mut buf);
        generate(Shell::Bash, &mut cmd, "warden", &mut out);
        let script = String::from_utf8(buf).unwrap();
        assert!(
            script.contains("reload"),
            "bash completion should mention 'reload' subcommand"
        );
    }
}
