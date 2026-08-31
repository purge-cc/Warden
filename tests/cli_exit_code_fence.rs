//! The exit-code fence: walk the compiled clap tree, drive every leaf verb
//! into a known-failing state, and assert it exits non-zero **for that
//! reason**.
//!
//! # Why a tree walk and not a list
//!
//! A hand-written list of verbs to check is a list someone must remember to
//! extend. This test enumerates [`purge_warden::cli::Cli::command()`] — the
//! same `clap` tree the binary dispatches from — so a verb added tomorrow is
//! covered tonight without anyone touching this file. A new leaf that returns
//! 0 after failing turns this test red on the commit that introduces it.
//!
//! # The trap this test is built to avoid
//!
//! Asserting `exit != 0` proves nothing on its own. `clap` exits **2** on a
//! usage error before any handler runs, so a fence that synthesised a
//! malformed argument vector would pass with a perfect score while testing
//! nothing but the argument parser — and the next person to break a real exit
//! code would still see green.
//!
//! Two independent guards close that hole:
//!
//! 1. **Parse oracle.** Every argument vector is first run through
//!    `Cli::try_parse_from` *in this process*. Only vectors that parse
//!    successfully are ever handed to a subprocess. A verb whose arguments
//!    cannot be synthesised is not silently skipped — it is collected and
//!    reported by [`report_the_fence_boundary`], because the list of verbs
//!    the fence cannot reach is the honest measure of what it protects.
//! 2. **Stderr check.** The child's stderr must not carry clap's usage
//!    markers. Belt and braces: the oracle runs against the same clap version
//!    the binary was built from, but this catches any divergence between
//!    parsing a `Vec<&str>` here and the real `argv` there.
//!
//! # The known-failing state
//!
//! `--config` points at a file whose `server.default_profile` names a profile
//! that does not exist: a cross-reference error, so it parses as TOML and is
//! rejected by the *validator*. That exercises the real failure path rather
//! than a syntax error, and it is uniform — every verb that reads config
//! fails identically. `--pid-file` and the socket path point into the same
//! temp dir at names that do not exist, so no daemon is reachable either.
//!
//! Nothing here binds a socket, touches a real config path, or contacts a
//! host: every invocation is confined to a `tempfile::TempDir`.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::{Command, Stdio};

use clap::{CommandFactory, Parser};
use purge_warden::cli::exit_codes::SUCCESS;
use purge_warden::cli::Cli;

/// Leaf verbs the fence deliberately does not drive, each with the reason.
///
/// This list is the fence's boundary, and it is meant to be read. Anything
/// here is a verb whose exit code no automated gate protects.
const EXCLUDED: &[(&str, &str)] = &[
    // Binds a UDP/TCP listener. Running it under test would put a DNS
    // server on a port, which the sprint's fence forbids outright.
    ("start", "binds a network listener"),
    // Full-screen TUI. With no tty it either wedges or exits for reasons
    // that have nothing to do with the config.
    ("dashboard", "interactive TUI, needs a tty"),
    // Pure code generators: they succeed by design regardless of config,
    // because emitting a completion script does not depend on one.
    (
        "completion",
        "generates a script; config-independent by design",
    ),
    (
        "manpages",
        "generates manpages; config-independent by design",
    ),
    // Creates a system user and FHS directories. Out of bounds for a test
    // process, and its failure modes are about privileges, not exit codes.
    ("init", "creates system users and directories"),
    // Reaches the network to fetch the upstream catalog. A fence that can
    // fail on someone's DNS is a fence nobody trusts.
    ("lists catalog", "performs a network fetch"),
    // NOT SAFE TO RUN. The token path is process-global
    // (`/var/lib/purge-warden/token`, then `$XDG_CONFIG_HOME`, then
    // `$HOME/.config/...`) and is NOT derived from `--config`, so these
    // escape the temp dir no matter how the child is invoked. On a host
    // with a live daemon — the Debian CTs both serve household DNS —
    // `token regenerate` would rotate the running resolver's IPC token
    // from inside `cargo test`, breaking every authenticated IPC call
    // until the daemon reloads. `generate` is listed too: it is harmless
    // only because a token already exists, which is not a property a test
    // should depend on.
    (
        "token generate",
        "writes a process-global token path outside the temp dir",
    ),
    (
        "token regenerate",
        "would rotate a live daemon's IPC token from inside cargo test",
    ),
];

/// Leaf verbs that exit **0** in the known-failing state, each reviewed and
/// judged legitimate. This list is asserted exactly, not as a ratio.
///
/// A ratio does not do the job the fence exists for. At 94/103 a threshold
/// of "75% must fail" still passes when a tenth verb starts returning 0
/// after failing — one regression moves the ratio by a percentage point, and
/// the verb's name would appear only in an `eprintln!` nobody reads without
/// `--nocapture`. That is exactly the silent regression the fence is meant
/// to prevent.
///
/// So the assertion is set equality. Adding a verb that wrongly exits 0
/// fails **with its name**. Fixing one of these also fails, which is correct
/// friction: the fix should shrink this list in the same commit.
///
/// Every entry below was checked by hand against the broken-config state:
///
/// - the three `remove` verbs, `security tunneling unexempt` and
///   `cluster leave` report "not found / not a member / not exempt —
///   nothing to do". Idempotent removal is a deliberate contract, and a
///   no-op is a success. (`security tunneling exempt` is NOT here: adding
///   proceeds to `write_value_validated`, which refuses on a broken
///   config, so it exits non-zero as it should.)
/// - `config render-default` is pure: it prints the built-in scaffold
///   TOML from `init::default_config()` and never reads `--config` at
///   all (the packaging build captures its stdout as the seed config —
///   see `pkg/build.sh`). Nothing here touches the broken config or the
///   dead daemon, so there is nothing for either to fail on.
///
/// `tags check` and `tags rename` LEFT this list in `plp-s5c`, and the
/// fence is what noticed. They were here because `check` validated a
/// slug against a regex with no I/O, and `rename <x> <x>` short-circuited
/// before the config loaded — both genuinely exited 0 in a broken state.
/// Every `warden tags …` verb now refuses and exits non-zero, so the
/// entries went stale on that commit and the fence said so by name,
/// exactly as its own instructions promise. A retired verb exiting 0 was
/// the weaker behaviour anyway: it read as "did what you asked".
/// - `audit tail` prints an empty log. Showing an empty log is a correct
///   answer to the question asked.
/// - `config backup` archives whatever is on disk. Backing up a *broken*
///   config is arguably the point of having the command.
/// - `firewall-rules` is the one worth revisiting: `main.rs` deliberately
///   falls back to `ConfigV1::default()` on an unloadable config, so it
///   emits iptables rules for the *default* listen address while the
///   operator's real one is unknown. Flagged to the orchestrator rather
///   than changed — the leniency is explicit and predates this sprint.
const KNOWN_ZERO: &[&str] = &[
    "audit tail",
    "cluster leave",
    "config backup",
    "config render-default",
    "firewall-rules",
    "lists remove",
    "local-dns remove",
    "security tunneling unexempt",
    "subnet remove",
];

/// A leaf command path plus the argv that provably parses into it.
struct Leaf {
    /// Space-joined command path, e.g. `config lint`.
    path: String,
    /// Argument vector *after* the leading `warden`, config and pid flags.
    args: Vec<String>,
}

/// Placeholder value for one argument, chosen from its declared value name.
///
/// `resolve <IP>` takes an `IpAddr`: feeding it `"x"` produces a clap usage
/// error, which is exactly the false pass this fence exists to prevent. The
/// mapping is by value-name substring because that is what clap exposes at
/// runtime; anything unmatched falls through to a plain token and, if that
/// fails to parse, the leaf is reported as unreachable rather than skipped.
fn placeholder_for(value_name: &str) -> &'static str {
    let n = value_name.to_ascii_uppercase();
    let has = |needle: &str| n.contains(needle);

    if has("IP") || has("ADDR") || has("PEER") || has("HOST") {
        // Parses as both IpAddr and, with the port, SocketAddr consumers.
        if has("LISTEN") || has("SOCKET_ADDR") {
            return "127.0.0.1:15353";
        }
        return "127.0.0.1";
    }
    if has("CIDR") || has("SUBNET") {
        return "127.0.0.0/8";
    }
    if has("MAC") {
        return "00:11:22:33:44:55";
    }
    if has("PORT") {
        return "15353";
    }
    if has("SECS") || has("SECONDS") || has("INTERVAL") || has("COUNT") || has("NUM") || has("PCT")
    {
        return "1";
    }
    if has("BYTES") || has("SIZE") || has("MAX") || has("LIMIT") || has("THRESHOLD") {
        return "1";
    }
    if has("BOOL") {
        return "true";
    }
    if has("URL") {
        return "https://example.invalid/list.txt";
    }
    if has("PATH") || has("FILE") || has("DIR") || has("ARCHIVE") {
        // Deliberately absent: a path that does not exist is itself a
        // failing state for the verbs that read one.
        return "/nonexistent/fence-placeholder";
    }
    if has("DOMAIN") {
        return "fence-placeholder.invalid";
    }
    "fence-placeholder"
}

/// Synthesise one level's arguments: the subcommand name, then the values
/// that level demands.
///
/// `include_optional_positionals` is the fallback pass. Some verbs make a
/// positional *conditionally* required — `config restore [ARCHIVE]` is
/// "required unless `--list` or `--latest`" — which clap models as an arg
/// group, so the argument itself reports `is_required_set() == false` and a
/// minimal invocation fails to parse. Rather than special-casing those
/// verbs, the walker retries with optional positionals filled in.
fn level_args(cmd: &clap::Command, include_optional_positionals: bool) -> Vec<String> {
    let mut args = vec![cmd.get_name().to_string()];
    for arg in cmd.get_arguments() {
        let positional = arg.is_positional();
        let wanted = arg.is_required_set() || (include_optional_positionals && positional);
        if !wanted {
            continue;
        }
        let value_name = arg
            .get_value_names()
            .and_then(|names| names.first().map(|n| n.to_string()))
            .unwrap_or_else(|| arg.get_id().to_string());
        if let Some(long) = arg.get_long() {
            args.push(format!("--{long}"));
        }
        if !matches!(
            arg.get_action(),
            clap::ArgAction::SetTrue | clap::ArgAction::SetFalse
        ) {
            args.push(placeholder_for(&value_name).to_string());
        }
    }
    args
}

/// Walk the compiled clap tree and return every leaf with a parseable argv.
///
/// Leaves whose arguments could not be synthesised land in `unreachable`
/// instead of being dropped.
fn walk_tree(unreachable: &mut Vec<(String, String)>) -> Vec<Leaf> {
    let root = Cli::command();
    let mut leaves = Vec::new();
    let excluded: BTreeSet<&str> = EXCLUDED.iter().map(|(p, _)| *p).collect();
    for sub in root.get_subcommands() {
        collect(sub, &[], &[], &mut leaves, unreachable, &excluded);
    }
    leaves
}

/// Recurse one level.
///
/// `argv_prefix` carries the ancestors' names **and their arguments**, in
/// order. That matters: `warden device rules <DEVICE_ID> prune` puts a
/// required positional on the *parent*, between the two subcommand names.
/// A walker that only read the leaf's own arguments would emit
/// `device rules prune` and be told a required argument was missing —
/// which is how this was caught.
fn collect(
    cmd: &clap::Command,
    path_prefix: &[String],
    argv_prefix: &[String],
    out: &mut Vec<Leaf>,
    unreachable: &mut Vec<(String, String)>,
    excluded: &BTreeSet<&str>,
) {
    let mut path = path_prefix.to_vec();
    path.push(cmd.get_name().to_string());
    let path_str = path.join(" ");

    if excluded.contains(path_str.as_str()) {
        return;
    }

    let subs: Vec<&clap::Command> = cmd.get_subcommands().collect();
    if !subs.is_empty() {
        // Parents contribute their own name + any arguments they demand.
        let mut next_argv = argv_prefix.to_vec();
        next_argv.extend(level_args(cmd, false));
        for sub in subs {
            collect(sub, &path, &next_argv, out, unreachable, excluded);
        }
        return;
    }

    // Leaf. Try the minimal invocation first, then the fallback that also
    // fills optional positionals.
    let mut last_err = String::from("no attempt made");
    for with_optionals in [false, true] {
        let mut args = argv_prefix.to_vec();
        args.extend(level_args(cmd, with_optionals));

        // The parse oracle. Anything that does not survive this never
        // reaches a subprocess, so a non-zero exit downstream cannot be a
        // usage error.
        let probe: Vec<String> = std::iter::once("warden".to_string())
            .chain(args.iter().cloned())
            .collect();
        match Cli::try_parse_from(&probe) {
            Ok(_) => {
                out.push(Leaf {
                    path: path_str,
                    args,
                });
                return;
            }
            Err(e) => last_err = e.kind().as_str().unwrap_or("parse error").to_string(),
        }
    }
    unreachable.push((path_str, last_err));
}

/// Write the broken config every child is pointed at: valid TOML, rejected
/// by the cross-reference validator.
fn write_broken_config(dir: &Path) -> std::path::PathBuf {
    let path = dir.join("broken.toml");
    std::fs::write(
        &path,
        "schema_version = 3\n\n[server]\ndefault_profile = \"no-such-profile\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    )
    .unwrap();
    path
}

struct Run {
    code: Option<i32>,
    stderr: String,
}

/// Run one leaf against the broken config in an isolated temp dir.
fn run_leaf(leaf: &Leaf, config: &Path, pid_file: &Path) -> Run {
    let out = Command::new(env!("CARGO_BIN_EXE_warden"))
        .arg("--config")
        .arg(config)
        .arg("--pid-file")
        .arg(pid_file)
        .args(&leaf.args)
        .stdin(Stdio::null())
        .env("EDITOR", "/bin/false")
        .output()
        .unwrap_or_else(|e| panic!("could not spawn `warden {}`: {e}", leaf.path));

    Run {
        code: out.status.code(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// True when the child died in the argument parser rather than in a handler.
///
/// The needle is `Usage:` and nothing else, because it is the only marker
/// that *discriminates*. The obvious additions do not: `warden device
/// set-unfiltered <id> <value>` rejects a bad boolean from inside its
/// handler with `Error: invalid value 'x'. Use one of: true, false, …` —
/// a correct, non-zero, handler-side failure that a naive `"invalid value"`
/// needle would have misread as a parser death and excluded from the fence.
/// Verified both ways: clap's own errors always carry a `Usage:` block;
/// that handler's message carries none.
fn looks_like_a_usage_error(stderr: &str) -> bool {
    stderr.contains("Usage:")
}

/// The fence.
///
/// Every leaf that reads the config or needs the daemon must exit non-zero
/// here, and must do so from its handler rather than from clap.
///
/// Verbs that legitimately succeed in this state are not asserted against —
/// they are counted and printed. The point is not a perfect score; it is that
/// no verb can *silently* start returning 0 after failing.
#[test]
fn every_leaf_verb_fails_loudly_in_a_known_failing_state() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_broken_config(dir.path());
    let pid_file = dir.path().join("absent.pid");

    let mut unreachable = Vec::new();
    let leaves = walk_tree(&mut unreachable);
    assert!(
        leaves.len() > 50,
        "the tree walk found only {} leaves — it is not walking the real tree",
        leaves.len()
    );

    let mut failed_correctly = Vec::new();
    let mut succeeded = Vec::new();
    let mut usage_errors = Vec::new();

    for leaf in &leaves {
        let run = run_leaf(leaf, &config, &pid_file);

        // A verb that died in the parser is a fence failure, not a verb
        // failure: it means this test would pass without testing anything.
        if looks_like_a_usage_error(&run.stderr) {
            usage_errors.push(leaf.path.clone());
            continue;
        }

        match run.code {
            Some(SUCCESS) => succeeded.push(leaf.path.clone()),
            Some(_) => failed_correctly.push(leaf.path.clone()),
            None => panic!("`warden {}` was killed by a signal", leaf.path),
        }
    }

    assert!(
        usage_errors.is_empty(),
        "these verbs died in clap despite passing the parse oracle — the fence \
         is measuring the argument parser, not the exit codes:\n  {}",
        usage_errors.join("\n  ")
    );

    let checked = failed_correctly.len() + succeeded.len();
    eprintln!(
        "exit-code fence: {}/{checked} leaves failed correctly, {} succeeded, \
         {} excluded, {} unreachable",
        failed_correctly.len(),
        succeeded.len(),
        EXCLUDED.len(),
        unreachable.len(),
    );

    // The load-bearing assertion: set equality against the reviewed list,
    // NOT a ratio. See `KNOWN_ZERO` for why a threshold cannot do this job.
    let observed: BTreeSet<&str> = succeeded.iter().map(String::as_str).collect();
    let expected: BTreeSet<&str> = KNOWN_ZERO.iter().copied().collect();

    let newly_zero: Vec<&&str> = observed.difference(&expected).collect();
    assert!(
        newly_zero.is_empty(),
        "these verbs exit 0 after failing against a broken config and a dead \
         daemon, and are not in the reviewed KNOWN_ZERO list:\n  {}\n\n\
         Either fix the verb's exit code, or add it to KNOWN_ZERO with the \
         reason it is legitimate.",
        newly_zero
            .iter()
            .map(|s| **s)
            .collect::<Vec<_>>()
            .join("\n  ")
    );

    let no_longer_zero: Vec<&&str> = expected.difference(&observed).collect();
    assert!(
        no_longer_zero.is_empty(),
        "these verbs are listed in KNOWN_ZERO but no longer exit 0:\n  {}\n\n\
         If you fixed them, delete them from KNOWN_ZERO in the same commit — \
         a stale entry is a hole the next regression can hide in.",
        no_longer_zero
            .iter()
            .map(|s| **s)
            .collect::<Vec<_>>()
            .join("\n  ")
    );

    // A sanity floor underneath the set check: if some change made the
    // whole tree stop reading config, `succeeded` and `KNOWN_ZERO` could
    // both be satisfied while the fence tested nothing meaningful.
    assert!(
        failed_correctly.len() > 50,
        "only {} verbs failed at all — the known-failing state is no longer failing",
        failed_correctly.len()
    );
}

/// Write a config that loads cleanly but points at a socket that does not
/// exist, so the daemon is unreachable while the config is fine.
///
/// **This second state is load-bearing.** A broken config alone does not
/// exercise the sprint's headline fix. `warden status` against a broken
/// config returns `CONFIG` from an early return and never reaches the
/// daemon-unreachable branch — proven by control arm: sabotaging that
/// branch to return `SUCCESS` left the whole fence green. Two states, two
/// distinct code paths.
fn write_valid_config(dir: &Path) -> std::path::PathBuf {
    let path = dir.join("valid.toml");
    std::fs::write(
        &path,
        "schema_version = 3\n\n[server]\nlisten = \"127.0.0.1:15353\"\n\
         default_profile = \"default\"\n\n[socket]\npath = \"/nonexistent/fence.sock\"\n\n\
         [profiles.default]\ndisplay_name = \"Default\"\ntags = [\"uncategorized\"]\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    )
    .unwrap();
    path
}

/// The verbs the audit found returning 0 after doing nothing, pinned to
/// their **exact** codes in **both** failing states. Named individually so a
/// regression points at the verb, and asserted exactly so a verb cannot
/// drift from `FAILURE` to `CONFIG` (or back) unnoticed — that drift is how
/// the control arm above slipped through a mere "non-zero" assertion.
///
/// `lists refresh` is `SUCCESS` against a valid config on purpose: with no
/// daemon it performs a *foreground* download, and a download that completes
/// is the operation succeeding. Only its config-failure form is a failure.
#[test]
fn the_named_regressions_stay_fixed() {
    const CONFIG_CODE: i32 = purge_warden::cli::exit_codes::CONFIG;
    const FAILURE_CODE: i32 = purge_warden::cli::exit_codes::FAILURE;

    let dir = tempfile::tempdir().unwrap();
    let broken = write_broken_config(dir.path());
    let pid_file = dir.path().join("absent.pid");

    // `config edit` rewrites nothing (EDITOR=/bin/false in run_leaf makes
    // the launch fail) so each case gets its own valid config to be safe.
    let valid_dir = tempfile::tempdir().unwrap();
    let valid = write_valid_config(valid_dir.path());

    // (argv, code against a VALID config with the daemon down, code against
    //  a BROKEN config)
    let cases: &[(&[&str], i32, i32)] = &[
        (&["status"], FAILURE_CODE, CONFIG_CODE),
        (&["status", "--json"], FAILURE_CODE, CONFIG_CODE),
        (&["reload"], FAILURE_CODE, FAILURE_CODE),
        (&["stop"], FAILURE_CODE, FAILURE_CODE),
        (&["lists", "refresh"], SUCCESS, CONFIG_CODE),
        (&["config", "lint"], SUCCESS, CONFIG_CODE),
        (&["resolve", "127.0.0.1"], SUCCESS, CONFIG_CODE),
    ];

    for (argv, valid_code, broken_code) in cases {
        let leaf = Leaf {
            path: argv.join(" "),
            args: argv.iter().map(|s| s.to_string()).collect(),
        };
        for (config, expected, state) in [
            (&valid, *valid_code, "a valid config with the daemon down"),
            (&broken, *broken_code, "a config that does not load"),
        ] {
            let run = run_leaf(&leaf, config, &pid_file);
            assert!(
                !looks_like_a_usage_error(&run.stderr),
                "`warden {}` died in clap, so its exit code proves nothing:\n{}",
                leaf.path,
                run.stderr
            );
            assert_eq!(
                run.code,
                Some(expected),
                "`warden {}` against {state} exited {:?}, expected {expected}.\nstderr:\n{}",
                leaf.path,
                run.code,
                run.stderr
            );
        }
    }
}

/// `config edit` gets its own test: `run_leaf` sets `EDITOR=/bin/false` so
/// the shared harness would always see the editor-launch failure (exit 1)
/// rather than the post-edit validation this sprint changed.
#[test]
fn config_edit_reports_an_invalid_saved_config() {
    let dir = tempfile::tempdir().unwrap();
    let broken = write_broken_config(dir.path());

    let out = Command::new(env!("CARGO_BIN_EXE_warden"))
        .arg("--config")
        .arg(&broken)
        .args(["config", "edit"])
        // A no-op editor: the file is saved exactly as written, so the
        // validator sees the broken config.
        .env("EDITOR", "/bin/true")
        .stdin(Stdio::null())
        .output()
        .expect("spawn warden config edit");

    assert_eq!(
        out.status.code(),
        Some(purge_warden::cli::exit_codes::CONFIG),
        "`warden config edit` reported success after saving an invalid config"
    );

    // Control arm: a valid config through the same path must be 0, or the
    // assertion above would pass for a command that always fails.
    let valid_dir = tempfile::tempdir().unwrap();
    let valid = write_valid_config(valid_dir.path());
    let ok = Command::new(env!("CARGO_BIN_EXE_warden"))
        .arg("--config")
        .arg(&valid)
        .args(["config", "edit"])
        .env("EDITOR", "/bin/true")
        .stdin(Stdio::null())
        .output()
        .expect("spawn warden config edit");
    assert_eq!(
        ok.status.code(),
        Some(SUCCESS),
        "a valid config must survive `config edit`"
    );
}

/// `warden status --json` with the daemon down must emit JSON.
///
/// The `json` flag was simply never consulted on that branch, so a
/// monitoring script got human prose *and* exit 0 — neither usable, in
/// precisely the state the script exists to detect. Parsing the output is
/// the only assertion that actually proves the flag is honoured; checking
/// the exit code alone would pass on the old prose renderer.
#[test]
fn status_json_down_is_json() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("valid.toml");
    std::fs::write(
        &config,
        "schema_version = 3\n\n[server]\nlisten = \"127.0.0.1:15353\"\n\
         default_profile = \"default\"\n\n[socket]\npath = \"/nonexistent/fence.sock\"\n\n\
         [profiles.default]\ndisplay_name = \"Default\"\ntags = [\"uncategorized\"]\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    )
    .unwrap();
    let pid_file = dir.path().join("absent.pid");

    let out = Command::new(env!("CARGO_BIN_EXE_warden"))
        .arg("--config")
        .arg(&config)
        .arg("--pid-file")
        .arg(&pid_file)
        .args(["status", "--json"])
        .stdin(Stdio::null())
        .output()
        .expect("spawn warden status --json");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("`warden status --json` emitted non-JSON with the daemon down ({e}):\n{stdout}")
    });

    assert_eq!(
        parsed.get("running"),
        Some(&serde_json::Value::Bool(false)),
        "the JSON must carry the running discriminator: {parsed}"
    );
    assert_ne!(
        out.status.code(),
        Some(SUCCESS),
        "status reported success while the daemon was down"
    );

    // Control arm: a *valid* config must not be reported as a config error,
    // or the assertions above would pass for the wrong reason.
    assert_eq!(
        parsed
            .get("config_errors")
            .and_then(|v| v.as_array())
            .map(Vec::len),
        Some(0),
        "a valid config was reported as broken: {parsed}"
    );
}

/// The diagnostic verbs must distinguish "the answer is no" from "I could
/// not get an answer" — the whole reason code 3 exists.
#[test]
fn a_negative_answer_is_not_a_failure() {
    let dir = tempfile::tempdir().unwrap();
    // No `default_profile`, so level 5 falls through to REFUSED.
    let config = dir.path().join("refuse.toml");
    std::fs::write(
        &config,
        "schema_version = 3\n\n[server]\nlisten = \"127.0.0.1:15353\"\n\n\
         [profiles.default]\ndisplay_name = \"Default\"\ntags = [\"uncategorized\"]\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    )
    .unwrap();
    let blocklist = dir.path().join("deny.txt");
    std::fs::write(&blocklist, "tracker.example.com\n").unwrap();
    let pid_file = dir.path().join("absent.pid");

    let run = |args: Vec<String>| -> Option<i32> {
        Command::new(env!("CARGO_BIN_EXE_warden"))
            .arg("--config")
            .arg(&config)
            .arg("--pid-file")
            .arg(&pid_file)
            .args(&args)
            .stdin(Stdio::null())
            .output()
            .expect("spawn warden")
            .status
            .code()
    };

    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();

    assert_eq!(
        run(s(&["resolve", "10.0.0.1"])),
        Some(purge_warden::cli::exit_codes::NEGATIVE),
        "a REFUSED source IP must be code 3, not an error"
    );
    let bl = blocklist.display().to_string();
    assert_eq!(
        run(s(&["query", "tracker.example.com", "--blocklist", &bl])),
        Some(purge_warden::cli::exit_codes::NEGATIVE),
        "a BLOCKED domain must be code 3"
    );
    assert_eq!(
        run(s(&["query", "example.org", "--blocklist", &bl])),
        Some(SUCCESS),
        "an ALLOWED domain must be code 0"
    );
    // ...and "I could not reach the daemon" must NOT masquerade as either
    // verdict. This is the pairing that protects a filter-verification
    // script from reading an outage as a successful block.
    assert_eq!(
        run(s(&["query", "example.org"])),
        Some(purge_warden::cli::exit_codes::FAILURE),
        "an unreachable daemon must be 1, distinct from both verdicts"
    );
}

/// Print — and pin — what the fence cannot reach.
///
/// The brief for this sprint asked for this list explicitly, and it matters
/// more than the count of verbs covered: it is the difference between "the
/// gate protects the CLI" and "the gate protects the part of the CLI we
/// could automate". A verb that becomes unreachable later shows up as a
/// change in this number.
#[test]
fn report_the_fence_boundary() {
    let mut unreachable = Vec::new();
    let leaves = walk_tree(&mut unreachable);

    eprintln!("── exit-code fence boundary ──");
    eprintln!("leaves reachable with a synthesised argv: {}", leaves.len());
    for (path, reason) in &EXCLUDED
        .iter()
        .map(|(p, r)| (p.to_string(), r.to_string()))
        .collect::<Vec<_>>()
    {
        eprintln!("  excluded  {path} — {reason}");
    }
    for (path, reason) in &unreachable {
        eprintln!("  unreachable  {path} — argv could not be synthesised ({reason})");
    }

    // The boundary is allowed to exist, but not to grow silently. If a new
    // verb takes an argument shape `placeholder_for` cannot satisfy, this
    // fails and the fix is to teach the placeholder mapping, not to widen
    // the allowance.
    assert!(
        unreachable.len() <= 2,
        "{} leaves cannot be driven by the fence — teach placeholder_for their \
         value names rather than letting the boundary grow:\n  {}",
        unreachable.len(),
        unreachable
            .iter()
            .map(|(p, r)| format!("{p} ({r})"))
            .collect::<Vec<_>>()
            .join("\n  ")
    );
}
