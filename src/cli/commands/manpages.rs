//! Manpage generation via [`clap_mangen`].
//!
//! Called from `warden init --install-manpages`. Renders one manpage
//! per top-level subcommand plus the root `warden(1)`. Files are
//! written atomically under `/usr/local/share/man/man1/` (or the
//! operator-supplied directory) so a concurrent `man warden` never
//! sees a half-written file.

use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::CommandFactory;
use clap_mangen::Man;

use crate::cli::Cli;
use crate::config::atomic_write::{hardened_atomic_write, AtomicWriteOpts};

/// Default install prefix for manpages. Matches the Debian convention for
/// third-party binaries — `/usr/local/share/man/man1/<name>.1`.
pub const DEFAULT_MAN_DIR: &str = "/usr/local/share/man/man1";

/// Manpage-only atomic-write helper. **Not for config mutation.**
/// Routes through [`hardened_atomic_write`] so even man-page output
/// gets fsync + mode preservation, but skips the validator round-trip
/// a config caller would need. Private to this module so a
/// grep-and-paste cannot land this unchecked writer on a config path.
fn atomic_write_unchecked(path: &Path, content: &str) -> anyhow::Result<()> {
    hardened_atomic_write(path, content.as_bytes(), AtomicWriteOpts::default())
        .map_err(|e| anyhow::anyhow!("{e}"))
}

/// Generate every manpage (root + each subcommand) into `dir`. Returns
/// the list of written paths for display.
pub fn install(dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;

    let cmd = Cli::command();

    let mut written: Vec<PathBuf> = Vec::new();

    // Root manpage: `warden(1)`.
    let root_path = dir.join("warden.1");
    let root_text = render(&cmd)?;
    atomic_write_unchecked(&root_path, &root_text)?;
    written.push(root_path);

    // One manpage per top-level subcommand.
    for sub in cmd.get_subcommands() {
        // Skip built-in clap helpers: they have no useful manpage of
        // their own.
        //
        // This comment was here before the code that honours it. The
        // filter tested `name.is_empty()`, which no clap subcommand ever
        // satisfies — so `help`, the node clap injects into every command
        // tree, was rendered and installed as `warden-help.1`, a manpage
        // documenting the act of asking for a manpage. It shipped to
        // every operator who ran `warden manpages`.
        //
        // Named explicitly rather than filtered by some property of the
        // node, because there is exactly one such node and clap does not
        // mark it as synthetic in a way this API exposes.
        let name = sub.get_name();
        if name.is_empty() || name == "help" {
            continue;
        }
        // The subcommand clap hands us already carries full context
        // (parent flags, aliases). `clap_mangen` reads it verbatim.
        let text = render(sub)?;
        let file_name = format!("warden-{name}.1");
        let path = dir.join(&file_name);
        atomic_write_unchecked(&path, &text)?;
        written.push(path);
    }

    Ok(written)
}

fn render(cmd: &clap::Command) -> anyhow::Result<String> {
    let mut buf: Vec<u8> = Vec::new();
    Man::new(cmd.clone())
        .render(&mut buf)
        .context("rendering manpage")?;
    String::from_utf8(buf).context("manpage was not valid UTF-8 (unexpected)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_creates_root_and_subcommand_manpages() {
        let dir = tempfile::tempdir().unwrap();
        let written = install(dir.path()).unwrap();
        assert!(!written.is_empty(), "must write at least warden.1");

        let root = dir.path().join("warden.1");
        assert!(root.exists(), "warden.1 written");

        // Check a few subcommand pages that are guaranteed to exist.
        for sub in &["device", "group", "subnet", "blocklist", "completion"] {
            let p = dir.path().join(format!("warden-{sub}.1"));
            assert!(p.exists(), "warden-{sub}.1 must be written");
        }
    }

    /// `warden-help.1` must not be installed, and the pages that matter
    /// must still be.
    ///
    /// Both halves in one test on purpose: `install` returning early, or
    /// writing nothing at all, would satisfy "no warden-help.1" perfectly.
    /// The absence only means something alongside evidence that the loop
    /// still ran.
    #[test]
    fn install_skips_claps_injected_help_node() {
        let dir = tempfile::tempdir().unwrap();
        let written = install(dir.path()).unwrap();

        let junk = dir.path().join("warden-help.1");
        assert!(
            !junk.exists(),
            "clap injects a `help` subcommand into every tree; rendering it \
             installs a manpage documenting how to ask for a manpage"
        );
        assert!(
            !written.iter().any(|p| p.ends_with("warden-help.1")),
            "the returned path list must not advertise a page that was not \
             written — `manpages` prints this list to the operator"
        );

        // The control arm: the loop that skips `help` must still be
        // producing real pages.
        assert!(
            dir.path().join("warden-device.1").exists(),
            "the skip must be surgical — warden-device.1 is still expected"
        );
        assert!(written.len() > 10, "wrote only {} page(s)", written.len());
    }

    #[test]
    fn root_manpage_mentions_binary_name() {
        let dir = tempfile::tempdir().unwrap();
        install(dir.path()).unwrap();
        let content = std::fs::read_to_string(dir.path().join("warden.1")).unwrap();
        assert!(
            content.contains("warden"),
            "manpage should include the binary name"
        );
    }

    #[test]
    fn device_manpage_mentions_add_action() {
        let dir = tempfile::tempdir().unwrap();
        install(dir.path()).unwrap();
        let content = std::fs::read_to_string(dir.path().join("warden-device.1")).unwrap();
        // `add` is a subcommand of `warden device`; clap_mangen should
        // mention it in the SUBCOMMANDS section.
        assert!(content.to_lowercase().contains("add"), "must mention add");
    }

    /// Five top-level verbs (`profile`, `device`, `group`, `subnet`,
    /// `default`) exist for scoped rule writes plus `rule undo`. Every
    /// one of them must produce a manpage so
    /// `man warden-default` / `man warden-rule` resolves on a fresh
    /// install. clap_mangen iterates `cmd.get_subcommands()` so this
    /// is automatic; the test pins the result.
    #[test]
    fn t5_scope_verb_manpages_are_generated() {
        let dir = tempfile::tempdir().unwrap();
        install(dir.path()).unwrap();
        for sub in &["profile", "device", "group", "subnet", "default", "rule"] {
            let p = dir.path().join(format!("warden-{sub}.1"));
            assert!(p.exists(), "warden-{sub}.1 must be written for T5 verb");
        }
    }

    /// The `warden rule` manpage should mention the `undo`
    /// sub-action. clap exposes it via `RuleVerb`; clap_mangen surfaces
    /// it in the SUBCOMMANDS section.
    #[test]
    fn rule_manpage_mentions_undo_subaction() {
        let dir = tempfile::tempdir().unwrap();
        install(dir.path()).unwrap();
        let content = std::fs::read_to_string(dir.path().join("warden-rule.1")).unwrap();
        assert!(
            content.to_lowercase().contains("undo"),
            "warden-rule.1 should advertise the `undo` action"
        );
    }

    /// The `warden default` manpage should mention `allow` and
    /// `deny` (`DefaultAction` variants).
    #[test]
    fn default_manpage_mentions_allow_and_deny() {
        let dir = tempfile::tempdir().unwrap();
        install(dir.path()).unwrap();
        let content = std::fs::read_to_string(dir.path().join("warden-default.1")).unwrap();
        let lower = content.to_lowercase();
        assert!(
            lower.contains("allow"),
            "warden-default.1 should mention allow"
        );
        assert!(
            lower.contains("deny"),
            "warden-default.1 should mention deny"
        );
    }

    /// The `warden local-dns` top-level verb must produce a manpage so
    /// `man warden-local-dns` resolves on a fresh install. clap_mangen
    /// iterates `cmd.get_subcommands()` so generation is automatic; the
    /// test pins the result.
    #[test]
    fn s44_local_dns_manpage_is_generated() {
        let dir = tempfile::tempdir().unwrap();
        install(dir.path()).unwrap();
        let p = dir.path().join("warden-local-dns.1");
        assert!(
            p.exists(),
            "warden-local-dns.1 must be written for the S44 T3 verb"
        );
    }

    /// The `warden local-dns` manpage should advertise the
    /// four sub-actions `add` / `remove` / `list` / `show`. clap
    /// surfaces them via `LocalDnsAction`; clap_mangen renders them
    /// in the SUBCOMMANDS section.
    #[test]
    fn s44_local_dns_manpage_mentions_four_subactions() {
        let dir = tempfile::tempdir().unwrap();
        install(dir.path()).unwrap();
        let content = std::fs::read_to_string(dir.path().join("warden-local-dns.1")).unwrap();
        let lower = content.to_lowercase();
        for sub in &["add", "remove", "list", "show"] {
            assert!(
                lower.contains(sub),
                "warden-local-dns.1 should advertise the `{sub}` action"
            );
        }
    }

    /// The manpage should mention "local DNS" / "records" in
    /// the description so an operator running `man warden-local-dns`
    /// confirms it is the right page (vs. the global `[local_dns]`
    /// in `warden.1`). clap_mangen lifts the about-line from
    /// `LocalDnsAction`'s clap doc-comment.
    #[test]
    fn s44_local_dns_manpage_describes_local_dns_surface() {
        let dir = tempfile::tempdir().unwrap();
        install(dir.path()).unwrap();
        let content = std::fs::read_to_string(dir.path().join("warden-local-dns.1")).unwrap();
        let lower = content.to_lowercase();
        // At least one of these tokens MUST appear so the description
        // line is non-empty and describes the right surface.
        assert!(
            lower.contains("local dns")
                || lower.contains("local-dns")
                || lower.contains("dns record"),
            "warden-local-dns.1 should describe the local DNS records surface (got: {} chars)",
            content.len()
        );
    }
}
