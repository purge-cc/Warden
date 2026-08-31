//! cli-h5 — arguments that were accepted and discarded.
//!
//! # The class
//!
//! Every argument the CLI declares must either take effect or be refused.
//! An accepted-and-ignored flag is worse than a missing one: the operator
//! has been told the binary will do something, gets exit 0, and only finds
//! out it did not when the filter they trusted silently lost.
//!
//! Four defects were grouped under this heading. Each is pinned here at
//! the surface an operator actually touches — the clap parse, or the
//! handler's own refusal — because each one's old behaviour *also* exited
//! 0. An assertion that the command succeeded passes on every bug in this
//! file; only assertions about what was excluded, refused, or removed
//! discriminate.
//!
//! Nothing here binds a socket or touches a real config path.

use clap::Parser;
use purge_warden::cli::Cli;

// ── defect 2: `local-dns list --profile` × `--scope` ──────────────────
//
// The `--scope` help said *"Mutually exclusive with `--profile`"* and
// nothing enforced it. The handler's `(Some(id), _)` arm let `--profile`
// win and dropped `--scope` unread — including its value validation, so
// `--profile kids --scope nonsense` exited 0 having silently listed the
// profile.

/// The pair the help promised would be refused.
#[test]
fn local_dns_list_refuses_profile_with_scope() {
    for scope in ["global", "profile", "all", "nonsense"] {
        let argv = vec![
            "warden",
            "local-dns",
            "list",
            "--profile",
            "kids",
            "--scope",
            scope,
        ];
        let err = match Cli::try_parse_from(&argv) {
            Ok(_) => panic!("--profile with --scope {scope} must not parse: {argv:?}"),
            Err(e) => e.to_string(),
        };
        assert!(
            err.contains("--profile") || err.contains("profile"),
            "clap's refusal should name the conflicting arg, got: {err}"
        );
    }
}

/// …and each one alone still parses. A `conflicts_with` that also broke
/// the single-flag forms would be a regression dressed as a fix.
#[test]
fn local_dns_list_still_accepts_either_flag_alone() {
    for argv in [
        vec!["warden", "local-dns", "list"],
        vec!["warden", "local-dns", "list", "--profile", "kids"],
        vec!["warden", "local-dns", "list", "--scope", "global"],
        vec!["warden", "local-dns", "list", "--scope", "profile"],
        vec!["warden", "local-dns", "list", "--scope", "all"],
        vec![
            "warden",
            "local-dns",
            "list",
            "--scope",
            "global",
            "--record-type",
            "A",
        ],
        vec![
            "warden",
            "local-dns",
            "list",
            "--profile",
            "kids",
            "--record-type",
            "A",
        ],
    ] {
        assert!(
            Cli::try_parse_from(&argv).is_ok(),
            "clap rejected a legitimate argv: {argv:?}"
        );
    }
}

/// The help text that made the promise must keep making it — if someone
/// later removes the `conflicts_with`, this line becomes a lie again.
#[test]
fn local_dns_list_scope_help_still_states_the_exclusivity() {
    let help = help_for(&["warden", "local-dns", "list", "--help"]);
    assert!(
        help.contains("Mutually exclusive"),
        "the --scope help must keep documenting the exclusivity it now enforces:\n{help}"
    );
}

// ── defect 4: `blocklist remove --cascade` ────────────────────────────
//
// `--cascade` existed to unlock a refusal (`RULE_DANGLING_REF`) that the
// v2 tag model removed: profiles no longer enumerate blocklists, so the
// cross-reference check has no production emitter and the refusal cannot
// fire. The flag parsed, set an audit field, and did nothing else.
// Verdict: deleted from the CLI surface.

/// The flag must be gone, not merely inert.
#[test]
fn blocklist_remove_no_longer_accepts_cascade() {
    let argv = vec!["warden", "blocklist", "remove", "privacy-ads", "--cascade"];
    assert!(
        Cli::try_parse_from(&argv).is_err(),
        "--cascade was a no-op flag and must no longer parse: {argv:?}"
    );
}

/// The verb itself, and its surviving `--into`, still work.
#[test]
fn blocklist_remove_still_parses_without_cascade() {
    for argv in [
        vec!["warden", "blocklist", "remove", "privacy-ads"],
        vec![
            "warden",
            "blocklist",
            "remove",
            "privacy-ads",
            "--into",
            "blocklists.d/x.toml",
        ],
    ] {
        assert!(
            Cli::try_parse_from(&argv).is_ok(),
            "clap rejected a legitimate argv: {argv:?}"
        );
    }
}

/// A deleted flag must leave no trace in the help — a documented flag the
/// binary rejects is the same defect pointed the other way.
#[test]
fn blocklist_remove_help_does_not_mention_cascade() {
    let help = help_for(&["warden", "blocklist", "remove", "--help"]);
    assert!(
        !help.contains("--cascade"),
        "help still advertises the deleted --cascade flag:\n{help}"
    );
}

// ── defect 1: `config show --resolved --section` ──────────────────────
//
// `--resolved` returned before the section filter was consulted. The
// filtering itself is unit-tested in `cli::commands::config::show` (it
// needs the rendered text); here we only pin that the combination is
// declared and reaches the handler rather than being refused at parse.

#[test]
fn config_show_accepts_resolved_with_section() {
    let argv = vec![
        "warden",
        "config",
        "show",
        "--resolved",
        "--section",
        "devices",
    ];
    assert!(
        Cli::try_parse_from(&argv).is_ok(),
        "--resolved --section must reach the handler, which applies the filter"
    );
}

// ── the --pid-file verb list ──────────────────────────────────────────
//
// The global `--pid-file` help named the verbs that consume it. It listed
// `cache`, which ignores the flag, and omitted two that use it. Correcting
// it, I wrote `update` — the name of the *module* (`commands::update`) that
// `ListsAction::Refresh` dispatches into. The operator-facing verb is
// `lists refresh`; `warden update` was retired and exits 2.
//
// Nothing in the gate catches that: `scripts/check_phantom_verbs.sh` scans
// documentation files, not `src/`, so a retired verb spelled into clap help
// is invisible to every check this repo runs. This test is a narrow guard
// for the one string, not the general help lint — that belongs to whoever
// owns the lint sprint.

/// Every verb named in the `--pid-file` help must actually parse.
#[test]
fn pid_file_help_names_only_real_verbs() {
    for verb in [
        vec!["warden", "start", "--help"],
        vec!["warden", "stop", "--help"],
        vec!["warden", "status", "--help"],
        vec!["warden", "lists", "refresh", "--help"],
        vec!["warden", "config", "restore", "--help"],
    ] {
        let err = match Cli::try_parse_from(&verb) {
            Ok(_) => panic!("--help always short-circuits: {verb:?}"),
            Err(e) => e,
        };
        assert_eq!(
            err.kind(),
            clap::error::ErrorKind::DisplayHelp,
            "a verb named in the --pid-file help does not exist: {verb:?} — got {err}"
        );
    }
}

/// …and the retired spelling must stay retired, so the module name cannot
/// creep back into the help via a copy-paste from a dispatch arm.
#[test]
fn warden_update_is_retired_and_unlisted() {
    let err = match Cli::try_parse_from(["warden", "update"]) {
        Ok(_) => panic!("`warden update` was renamed to `lists refresh` and must not parse"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), clap::error::ErrorKind::InvalidSubcommand);

    let help = help_for(&["warden", "--help"]);
    assert!(
        !help.contains("`update`"),
        "top-level help must not name the retired `update` verb:\n{help}"
    );
}

// ── helper ────────────────────────────────────────────────────────────

/// Render a subcommand's `--help` through clap itself, so these
/// assertions read the same text an operator does.
fn help_for(argv: &[&str]) -> String {
    match Cli::try_parse_from(argv) {
        Ok(_) => panic!("--help should short-circuit parsing: {argv:?}"),
        Err(e) => e.to_string(),
    }
}
