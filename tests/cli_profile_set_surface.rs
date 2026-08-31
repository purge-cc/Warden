//! `warden profile` command surface after the mutation-verb collapse.
//!
//! `profile` used to carry nine single-purpose mutation verbs while every
//! other entity took a generic `set <field> <value>`. The six scalar ones
//! collapsed into `profile set`; the two list-shaped ones became
//! `profile admin-rule add|remove`.
//!
//! This asserts the shape at the clap layer, where an operator meets it:
//! a retired spelling must FAIL to parse, not quietly resolve to
//! something else. Deleting a variant is easy to get half-right — a
//! leftover `#[command(alias = ...)]` or a prefix that still matches
//! would keep the old spelling working and defeat the rename without
//! failing any other test.
//!
//! The per-field parse rules live beside their table, in
//! `src/cli/commands/profiles_v1.rs`.

use clap::error::ErrorKind;
use clap::CommandFactory;
use clap::Parser;
use purge_warden::cli::commands::profiles_v1::ProfileAdminRuleAction;
use purge_warden::cli::{Cli, Commands, ProfileAction};

/// Parse a `warden …` argv, exactly as a shell would hand it over.
fn parses(args: &[&str]) -> bool {
    parse(args).is_ok()
}

fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
    let mut argv = vec!["warden"];
    argv.extend_from_slice(args);
    Cli::try_parse_from(argv)
}

/// Why a parse failed, or `None` if it succeeded.
///
/// A retired verb has to fail *as an unknown subcommand*, and asserting
/// only "did not parse" does not check that. Alias `update` onto `set`
/// and `profile update kids --display-name Kids` still fails — on arity
/// and an unknown flag, not on the verb — so a bare `is_err()` stays
/// green with the rename defeated. This is the discriminating needle.
fn why(args: &[&str]) -> Option<ErrorKind> {
    parse(args).err().map(|e| e.kind())
}

/// Every spelling the collapse retired. None may survive: the rename is
/// hard, with no alias and no deprecation cycle.
const RETIRED: &[&[&str]] = &[
    &["profile", "update", "kids", "--display-name", "Kids"],
    &["profile", "block-response", "kids", "zero"],
    &["profile", "blocked-ttl", "kids", "30"],
    &["profile", "block-all", "kids", "true"],
    &["profile", "ecs", "kids", "--mode", "subnet"],
    &["profile", "ecs-clear", "kids"],
    &["profile", "admin-rule-add", "kids", "kids-allow-wikipedia"],
    &[
        "profile",
        "admin-rule-remove",
        "kids",
        "kids-allow-wikipedia",
    ],
];

#[test]
fn every_retired_profile_verb_is_an_unrecognized_subcommand() {
    for args in RETIRED {
        assert_eq!(
            why(args),
            Some(ErrorKind::InvalidSubcommand),
            "`warden {}` must fail as an unrecognized subcommand — any other \
             outcome means the spelling still resolves to something",
            args.join(" ")
        );
    }
}

#[test]
fn set_replaces_the_six_scalar_verbs() {
    for (field, value) in [
        ("display_name", "Kids"),
        ("block_response", "nxdomain"),
        ("block_response", "clear"),
        ("blocked_ttl", "0"),
        ("block_all", "false"),
        ("ecs.mode", "subnet"),
        ("ecs.prefix_v4", "24"),
        ("ecs.prefix_v6", "56"),
        ("ecs", "none"),
    ] {
        assert!(
            parses(&["profile", "set", "kids", field, value]),
            "`warden profile set kids {field} {value}` must parse"
        );
    }
}

/// `set` takes three positionals, all required. An operator who forgets
/// the value must be told so — never have the field name read as one.
///
/// The needle is the error KIND, not `is_err()`: give `value` a
/// `default_value` and `profile set kids block_all` starts parsing and
/// mutating with a value nobody typed, while a bare `!parses(...)` stays
/// green. Same trap as the retired-verb test above.
#[test]
fn set_requires_id_field_and_value() {
    for args in [
        &["profile", "set"][..],
        &["profile", "set", "kids"],
        &["profile", "set", "kids", "block_all"],
    ] {
        assert_eq!(
            why(args),
            Some(ErrorKind::MissingRequiredArgument),
            "`warden {}` must fail for a MISSING argument, not some other reason",
            args.join(" ")
        );
    }
}

/// Positionals must land on the fields they name. clap assigns them in
/// declaration order, so reordering the struct silently swaps them — and
/// `set <field> <value>` reversed would send the value as the field name,
/// which reads as a typo rather than as a bug.
#[test]
fn set_binds_its_positionals_in_order() {
    let cli = parse(&["profile", "set", "kids", "block_all", "false"]).unwrap();
    let Some(Commands::Profile {
        action: ProfileAction::Set { id, field, value },
    }) = cli.command
    else {
        panic!("`profile set` must parse to ProfileAction::Set");
    };
    assert_eq!(id, "kids");
    assert_eq!(field, "block_all");
    assert_eq!(value, "false");
}

/// Same, for the sub-subcommand. Swapping these two would send the rule
/// id as the profile id — the daemon would answer "no profile with id
/// kids-allow-wikipedia", which looks like operator error, not a bug.
#[test]
fn admin_rule_binds_its_positionals_in_order() {
    for (argv, is_add) in [
        (
            ["profile", "admin-rule", "add", "kids", "kids-allow-wiki"],
            true,
        ),
        (
            ["profile", "admin-rule", "remove", "kids", "kids-allow-wiki"],
            false,
        ),
    ] {
        let cli = parse(&argv).unwrap();
        let Some(Commands::Profile {
            action: ProfileAction::AdminRule { action },
        }) = cli.command
        else {
            panic!("`profile admin-rule` must parse to ProfileAction::AdminRule");
        };
        let (id, rule_id) = match (action, is_add) {
            (ProfileAdminRuleAction::Add { id, rule_id }, true) => (id, rule_id),
            (ProfileAdminRuleAction::Remove { id, rule_id }, false) => (id, rule_id),
            _ => panic!("`{}` parsed to the wrong sub-verb", argv.join(" ")),
        };
        assert_eq!(id, "kids", "first positional is the profile id");
        assert_eq!(rule_id, "kids-allow-wiki", "second is the admin rule id");
    }
}

#[test]
fn admin_rule_is_a_sub_subcommand() {
    assert!(parses(&["profile", "admin-rule", "add", "kids", "r1"]));
    assert!(parses(&["profile", "admin-rule", "remove", "kids", "r1"]));
    // No bare form: `admin-rule` alone must ask which one, and must say
    // so as an unknown sub-verb rather than mistaking `kids` for one.
    assert_eq!(
        why(&["profile", "admin-rule", "kids", "r1"]),
        Some(ErrorKind::InvalidSubcommand)
    );
}

/// The collapse touched only the nine mutation verbs. Everything else on
/// `profile` must still answer — a regression here would mean the enum
/// edit reached further than intended.
///
/// **`profile tag add|remove` left this list in `plp-s5c`, deliberately,
/// and that is not the regression this guard watches for.** They were
/// here as bystanders of the `profile set` collapse: untouched by *that*
/// edit, so listed to prove its blast radius. A later sprint retired the
/// tag model outright, and this lane removed the verbs on purpose — so
/// their absence is the intended state, not an enum edit reaching too
/// far. The guard keeps its job for the six verbs that remain.
///
/// Their absence is pinned instead by
/// `cli::plp_s5c_tag_surface_tests::no_noun_carries_a_tag_sub_verb`,
/// which walks the whole tree rather than one noun.
#[test]
fn the_untouched_profile_verbs_still_parse() {
    for args in [
        &["profile", "list"][..],
        &["profile", "show", "kids"],
        &["profile", "add", "kids", "--display-name", "Kids"],
        &["profile", "remove", "kids"],
        &["profile", "allow", "kids", "wikipedia.org"],
        &["profile", "deny", "kids", "ads.example"],
    ] {
        assert!(parses(args), "`warden {}` must still parse", args.join(" "));
    }

    // The retired pair, asserted from the other side so this file records
    // the change rather than going quiet about it.
    for args in [
        &["profile", "tag", "add", "kids", "family"][..],
        &["profile", "tag", "remove", "kids", "family"],
    ] {
        assert_eq!(
            why(args),
            Some(ErrorKind::InvalidSubcommand),
            "`warden {}` is retired and must be rejected by clap, whose \
             error lists the surviving sub-verbs — `list-policy` among them",
            args.join(" ")
        );
    }
}

/// An unknown field is a runtime refusal, not a clap one — clap takes any
/// string as the positional. Drive the real binary: the refusal must
/// happen before any socket round-trip (so it works with the daemon down)
/// and must name the legal fields, since `set --help` is otherwise the
/// only place they are written down.
///
/// `--config` points inside a tempdir at a file that does not exist, so
/// the run cannot reach a real config however this host is set up.
#[test]
fn an_unknown_field_exits_non_zero_and_names_the_legal_fields() {
    let dir = tempfile::tempdir().unwrap();
    let absent = dir.path().join("config.toml");

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_warden"))
        .args(["--config".as_ref(), absent.as_os_str()])
        .args(["profile", "set", "kids", "nonsense", "x"])
        .output()
        .expect("failed to run the warden binary");

    assert!(
        !out.status.success(),
        "an unknown field must exit non-zero, got {:?}",
        out.status
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("nonsense"),
        "the error must quote what was typed:\n{stderr}"
    );
    for field in [
        "display_name",
        "block_response",
        "blocked_ttl",
        "block_all",
        "ecs.mode",
        "ecs.prefix_v4",
        "ecs.prefix_v6",
    ] {
        assert!(
            stderr.contains(field),
            "the error must list `{field}`:\n{stderr}"
        );
    }
}

// ── `warden profile list-policy` — the clap layer ────────────────────
//
// The three-state override is only usable if the operator can type it.
// These assert the shape where they meet it: arity, the direction token
// position, and that `clear` and `set` stay separate verbs rather than
// one verb with an optional third argument — which is how `clear` and
// `set ignore` would start collapsing into each other.

/// Every accepted spelling parses, including all three directions.
#[test]
fn plp_s4a_list_policy_verbs_parse() {
    for direction in ["deny", "allow", "ignore"] {
        assert!(
            parses(&["profile", "list-policy", "set", "kids", "ads", direction]),
            "set … {direction} must parse"
        );
    }
    assert!(parses(&["profile", "list-policy", "clear", "kids", "ads"]));
    assert!(parses(&["profile", "list-policy", "show", "kids"]));
}

/// `clear` takes no direction, and `set` requires one.
///
/// A `clear` that swallowed a trailing direction would let
/// `list-policy clear kids ads ignore` parse and silently mean something
/// other than what it says — the two verbs express different intentions
/// and must not overlap in argv.
#[test]
fn plp_s4a_list_policy_arity_keeps_clear_and_set_apart() {
    assert!(
        !parses(&["profile", "list-policy", "clear", "kids", "ads", "ignore"]),
        "`clear` must not accept a direction"
    );
    assert!(
        !parses(&["profile", "list-policy", "set", "kids", "ads"]),
        "`set` must require a direction"
    );
    assert!(
        !parses(&["profile", "list-policy", "show"]),
        "`show` must require a profile id"
    );
}

/// The direction is validated by the handler, not by clap.
///
/// Pinned so a later switch to a clap `ValueEnum` is a deliberate change:
/// the accepted tokens come from `ListPolicy::wire_str`, and a second
/// table in the clap layer would be a second place for them to be wrong.
#[test]
fn plp_s4a_an_unknown_direction_parses_and_is_refused_by_the_handler() {
    assert!(
        parses(&["profile", "list-policy", "set", "kids", "ads", "block"]),
        "clap accepts any token here"
    );
    assert!(
        purge_warden::cli::commands::profiles_v1::parse_list_policy("block").is_err(),
        "and the handler is what refuses it"
    );
}

/// clap renders `about` -- the doc comment's first paragraph -- as the row in
/// the parent's command table, and `verbatim_doc_comment` preserves whatever
/// newlines the source had. A summary written across two source lines
/// therefore prints a two-line row beside its one-line siblings.
///
/// This is a real defect this lane shipped and then fixed, caught by running
/// the binary rather than by reading the doc comment: `set` carries
/// `verbatim_doc_comment` (its direction table needs the indentation) and its
/// summary spanned two lines. Nothing else measures this -- the help fence
/// checks for internal references, not for shape -- so it is pinned here
/// instead of left to whoever next renders the page.
#[test]
fn plp_s4a_list_policy_summaries_are_single_line() {
    let cli = Cli::command();
    let profile = cli
        .get_subcommands()
        .find(|c| c.get_name() == "profile")
        .expect("profile verb");
    let list_policy = profile
        .get_subcommands()
        .find(|c| c.get_name() == "list-policy")
        .expect("list-policy verb");

    let mut seen = 0;
    for sub in list_policy.get_subcommands() {
        if sub.get_name() == "help" {
            continue;
        }
        let about = sub
            .get_about()
            .unwrap_or_else(|| panic!("`{}` has no summary", sub.get_name()))
            .to_string();
        assert!(
            !about.contains('\n'),
            "`{}`'s summary spans {} lines, so the command table prints a \
             broken multi-line row: {about:?}",
            sub.get_name(),
            about.lines().count()
        );
        seen += 1;
    }
    assert_eq!(seen, 3, "set, clear and show must all be present");
}

/// `clear` is not `set … ignore`, and the help has to say so where the help
/// is actually read.
///
/// It said so only in `long_about`. Neither the command table nor `-h`
/// renders that, so the distinction the whole three-state model rests on was
/// invisible in both truncated views. Asserting on `about` is what makes this
/// discriminate: an assertion against `long_about` passes on the version that
/// hid it.
#[test]
fn plp_s4a_clear_summary_carries_the_ignore_distinction() {
    let cli = Cli::command();
    let about = cli
        .get_subcommands()
        .find(|c| c.get_name() == "profile")
        .and_then(|c| c.get_subcommands().find(|c| c.get_name() == "list-policy"))
        .and_then(|c| c.get_subcommands().find(|c| c.get_name() == "clear"))
        .and_then(|c| c.get_about())
        .expect("clear verb with a summary")
        .to_string();

    assert!(
        about.contains("set \u{2026} ignore"),
        "the truncated summary must name what `clear` is NOT: {about:?}"
    );
}
