//! **Two verbs that write a config the next load will not accept** —
//! `profile_list_policy.md` §4 S4, findings F21 and F22.
//!
//! Both defects have the same root: the verb asks a question about the
//! *list's own row* (`base`, "does any profile enumerate this?") that stopped
//! being the whole answer when this workstream moved direction into
//! `profiles.<id>.lists`. The repair for both is the same predicate,
//! [`effective_direction`], which is why they share a file.
//!
//! # What these tests assert, and what they deliberately do not
//!
//! **F21 asserts the verb refuses — never that the resulting config is
//! refused by the validator.** Today it is not: `check_blocklist_base_trust`
//! keys on `b.base == Allow` alone (`validator.rs`), so the state
//! `set-trust` currently writes loads *clean*, with no ERROR and no WARN.
//! That is finding F20, and closing it belongs to the lane that owns
//! `config/schema/validator.rs`. Asserting on the load here would couple this
//! file's red/green to that lane's diff and would go green for a reason that
//! has nothing to do with the verb. So the measurement is the one this lane
//! controls: `run_set_trust` returns `Err`, and the on-disk bytes are
//! **unchanged**.
//!
//! The two layers are not redundant. F20's own table: the validator is the
//! backstop for a hand-edited TOML, the verb is the readable refusal that
//! names the flag. Either alone leaves a route open.
//!
//! # The control arms are the load-bearing rows
//!
//! A gate that refuses *every* `set-trust` to `remote-unsigned` passes both
//! F21 refusal rows. [`set_trust_remote_unsigned_is_untouched_when_no_profile_allows`]
//! is what separates "gates on the effective direction" from "gates on
//! nothing" — it is the ordinary shape of every subscribed deny-list, and if
//! it ever goes red the verb has become unusable for its main use.
//!
//! Likewise [`removing_a_list_leaves_an_unrelated_override_alone`]: a cascade
//! that empties every `lists` table satisfies the F22 row on its own.

use std::path::{Path, PathBuf};

use purge_warden::cli::commands::blocklists::{
    profiles_where_list_is_allow, run_remove, run_set_trust, ACCEPT_UNSIGNED_ALLOW_FLAG_HINT,
};
use purge_warden::config::loader::load_config;
use purge_warden::config::schema::{Id, ListPolicy};

/// A socket path that does not exist. Every verb here ends with
/// `ipc_reload::attempt_reload`, which degrades to a reported outcome rather
/// than an error when nothing is listening — so no daemon is needed, and the
/// verb's own `Result` still means what it says.
fn dead_socket(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("no-such-daemon.sock")
}

fn load_ok(master: &Path) -> purge_warden::config::schema::ConfigV1 {
    load_config(master, time::OffsetDateTime::now_utc())
        .unwrap_or_else(|e| panic!("config must load: {e:?}"))
        .config
}

/// One master file carrying a list and a profile that overrides it.
///
/// **Every fixture declares its own `[profiles.default]`, deliberately.** The
/// template used to inject it, and that silently weakened one row: a profile
/// with no override *inherits* `base`, so a `base = "allow"` list was already
/// "allow for `default`" and the row meant to isolate the base arm was in fact
/// exercising the override arm. Mutation testing is what surfaced it — the
/// row stayed green against a gate with the base disjunct removed. Making the
/// profile set explicit at each fixture is what keeps that from recurring
/// invisibly.
///
/// Single-file layout on purpose: the split-file lookup has its own cover in
/// `find_target_for_id`, and what is under test here is the gate and the
/// cascade, not the resolution of the target path.
///
/// The upstream address is RFC 5737 TEST-NET-1 — warden ships no provider
/// defaults (project rules §Neutrality) and a fixture is not a place to
/// reintroduce one by habit.
fn write_master(dir: &tempfile::TempDir, body: &str) -> PathBuf {
    let master = dir.path().join("config.toml");
    std::fs::write(
        &master,
        format!(
            r#"schema_version = 3

[upstream]
mode = "plain"
servers = ["192.0.2.1:53"]

[server]
default_profile = "default"

{body}
"#
        ),
    )
    .expect("write master");
    master
}

// ── F21 — `set-trust` is blind to a per-profile allow override ────────

/// The four-step reproduction, verbatim.
///
/// 1. list `shared` is `base = "deny"`, `trust = "local"` — legal, nothing
///    to consent to.
/// 2. profile `kids` overrides it to `allow` — legal, because `trust =
///    "local"` means the operator authored the file.
/// 3. `set-trust shared remote-unsigned` — the row's own `base` is still
///    `deny`, so the gate as written sees nothing to ask about.
/// 4. the list is now a subscription somebody else edits, `kids` treats it as
///    an allow-list, and no `accept_unsigned_allow` was ever declared.
///
/// Step 3 is the one that has to stop. Note what is asserted: the verb
/// errors **and nothing was written**. A gate that bails after the write
/// leaves exactly the state it was meant to prevent.
#[tokio::test]
async fn set_trust_remote_unsigned_refuses_when_a_profile_overrides_to_allow() {
    let dir = tempfile::tempdir().unwrap();
    let master = write_master(
        &dir,
        r#"[[blocklists]]
id = "shared"
display_name = "Shared"
url = "https://lists.purge.cc/shared.txt"
base = "deny"
trust = "local"

[profiles.default]
display_name = "Default"

[profiles.kids]
display_name = "Kids"
lists = { shared = "allow" }
"#,
    );
    let before = std::fs::read_to_string(&master).unwrap();

    let res = run_set_trust(
        &master,
        &dead_socket(&dir),
        "shared",
        "remote-unsigned",
        false,
        None,
    )
    .await;

    let err = res.expect_err("set-trust must refuse: profile 'kids' overrides 'shared' to allow");
    let msg = err.to_string();
    assert!(
        msg.contains("kids"),
        "the refusal must name the profile carrying the override — the consent \
         lives on the list's row but the offence lives in the profile, and a \
         message naming only the list sends the operator to a row that looks \
         fine. got: {msg}"
    );
    assert_eq!(
        std::fs::read_to_string(&master).unwrap(),
        before,
        "a refused set-trust must leave the file byte-identical"
    );
}

/// The `base = "allow"` arm, isolated: **every** profile in the tree
/// overrides the list to `deny`, so no profile's effective direction is
/// allow and the list's own base is the only thing left to fire on.
///
/// Kept as its own row because the repair is a disjunction — the gate fires
/// on the list's base *or* on any profile's override — and a disjunction with
/// an unreachable arm is one nobody notices losing.
///
/// **The isolation is the whole point, and the first version of this row did
/// not have it.** It carried no override at all, next to a template that
/// injected a bare `[profiles.default]`. A profile with no override *inherits*
/// `base`, so `effective_direction(default, exempt)` was already `Allow` and
/// the profile scan fired on its own: the row passed against a gate with the
/// base check deleted. Measured, not reasoned — the mutation stayed green.
///
/// Why the arm is worth keeping rather than deleting as redundant: a profile
/// added to this config tomorrow inherits `base` and is exempted by a list
/// nobody consented to. That standing power is exactly what the ack prices,
/// and it is what `check_blocklist_base_trust` refuses at load for the same
/// reason — the verb and the validator agreeing here is not an accident.
#[tokio::test]
async fn set_trust_remote_unsigned_refuses_a_base_allow_list_every_profile_overrides_to_deny() {
    let dir = tempfile::tempdir().unwrap();
    let master = write_master(
        &dir,
        r#"[[blocklists]]
id = "exempt"
display_name = "Exempt"
url = "https://lists.purge.cc/exempt.txt"
base = "allow"
trust = "local"
tags = ["work"]

[profiles.default]
display_name = "Default"
lists = { exempt = "deny" }
"#,
    );
    let before = std::fs::read_to_string(&master).unwrap();

    let res = run_set_trust(
        &master,
        &dead_socket(&dir),
        "exempt",
        "remote-unsigned",
        false,
        None,
    )
    .await;

    let err = res.expect_err("an allow-direction list going remote still needs consent");
    // **`is_err()` alone cannot see this gate, and asserting only that was
    // this row's second defect.** The state the mutation produces —
    // `base = "allow"` + `trust = "remote-unsigned"` + no ack — is one the
    // *validator* also refuses, and `write_value_validated` runs it against
    // the staged bytes before promoting. So with the verb's gate deleted the
    // command still errors and still writes nothing: the row stayed green,
    // and the run time went from 0.02 s to 9 s because a whole config load
    // had quietly become the thing under test.
    //
    // The flag hint is the needle that separates the layers. It is a CLI
    // string; the validator's refusal carries
    // `UNSIGNED_ALLOW_LIST_REQUIRES_ACK_SUGGESTION` instead, which names the
    // TOML key and no flag. Pinned by the const rather than a literal so a
    // rewording moves both together instead of silently un-pinning this.
    assert!(
        err.to_string().contains(ACCEPT_UNSIGNED_ALLOW_FLAG_HINT),
        "the refusal must come from the verb, which names the flag to type — \
         not from the validator backstop underneath it. got: {err}"
    );
    assert_eq!(std::fs::read_to_string(&master).unwrap(), before);
}

/// The predicate itself, asked directly: a profile that overrides a list to
/// `deny` is **not** one the list allows.
///
/// The gate rows above exercise `profiles_where_list_is_allow` through
/// `run_set_trust`, where a wrong answer can be masked by the validator
/// underneath. This row has nothing underneath it.
#[test]
fn the_predicate_excludes_a_profile_that_overrides_to_deny() {
    let dir = tempfile::tempdir().unwrap();
    let master = write_master(
        &dir,
        r#"[[blocklists]]
id = "ads"
display_name = "Ads"
url = "https://lists.purge.cc/ads.txt"
base = "deny"
trust = "local"

[profiles.default]
display_name = "Default"

[profiles.kids]
display_name = "Kids"
lists = { ads = "deny" }
"#,
    );
    let cfg = load_ok(&master);
    let list = cfg
        .blocklists
        .iter()
        .find(|b| b.id.as_str() == "ads")
        .unwrap();
    assert!(
        profiles_where_list_is_allow(&cfg, list).is_empty(),
        "neither an inherited deny nor an explicit deny override is an allow"
    );
}

/// **The control arm.** Same shape as the F21 row, except the override says
/// `deny` — so the effective direction is deny for every profile and there is
/// no unblocking power to price.
///
/// Without this row a gate that refuses unconditionally is indistinguishable
/// from a correct one, and `set-trust` would be broken for the ordinary case
/// (a subscribed deny-list) while both F21 rows stayed green.
#[tokio::test]
async fn set_trust_remote_unsigned_is_untouched_when_no_profile_allows() {
    let dir = tempfile::tempdir().unwrap();
    let master = write_master(
        &dir,
        r#"[[blocklists]]
id = "ads"
display_name = "Ads"
url = "https://lists.purge.cc/ads.txt"
base = "deny"
trust = "local"

[profiles.default]
display_name = "Default"

[profiles.kids]
display_name = "Kids"
lists = { ads = "deny" }
"#,
    );

    run_set_trust(
        &master,
        &dead_socket(&dir),
        "ads",
        "remote-unsigned",
        false,
        None,
    )
    .await
    .expect("a deny-everywhere list going remote asks nothing of the operator");

    let cfg = load_ok(&master);
    let b = cfg
        .blocklists
        .iter()
        .find(|b| b.id.as_str() == "ads")
        .unwrap();
    assert_eq!(
        b.trust,
        purge_warden::config::schema::BlocklistTrust::RemoteUnsigned,
        "the move must actually have landed, not merely not-errored"
    );
}

/// Consent declared on the command line lets the override case through, and
/// the declaration is written to the list's row so it keeps applying at every
/// later load.
///
/// This is the row that proves the gate is a *gate* and not a prohibition:
/// the operator can still express the policy, they just have to say so.
#[tokio::test]
async fn set_trust_remote_unsigned_accepts_the_override_case_with_consent() {
    let dir = tempfile::tempdir().unwrap();
    let master = write_master(
        &dir,
        r#"[[blocklists]]
id = "shared"
display_name = "Shared"
url = "https://lists.purge.cc/shared.txt"
base = "deny"
trust = "local"

[profiles.default]
display_name = "Default"

[profiles.kids]
display_name = "Kids"
lists = { shared = "allow" }
"#,
    );

    run_set_trust(
        &master,
        &dead_socket(&dir),
        "shared",
        "remote-unsigned",
        true,
        None,
    )
    .await
    .expect("declared consent must be honoured");

    let cfg = load_ok(&master);
    let b = cfg
        .blocklists
        .iter()
        .find(|b| b.id.as_str() == "shared")
        .unwrap();
    assert!(
        b.accept_unsigned_allow,
        "the consent must be recorded on the row, so it re-applies at every load"
    );
}

// ── F22 — `blocklist remove` leaves the override dangling ─────────────

/// Removing a list a profile overrides must drop the override in the same
/// mutation.
///
/// The assertion that counts is **the resulting tree loads**. A test that
/// only counted `cascade_log` lines would stay green against an
/// implementation that prints the trace and never touches the TOML — the
/// exact shape of the defect being repaired, where a comment described a
/// cleanup that did not run.
#[tokio::test]
async fn removing_a_list_cascades_the_profile_override_and_the_tree_still_loads() {
    let dir = tempfile::tempdir().unwrap();
    let master = write_master(
        &dir,
        r#"[[blocklists]]
id = "gambling"
display_name = "Gambling"
url = "https://lists.purge.cc/gambling.txt"
base = "deny"
trust = "local"

[profiles.default]
display_name = "Default"

[profiles.kids]
display_name = "Kids"
lists = { gambling = "allow" }
"#,
    );

    run_remove(&master, &dead_socket(&dir), "gambling", None)
        .await
        .expect("removing a list a profile overrides must succeed");

    let cfg = load_ok(&master);
    assert!(cfg.blocklists.is_empty(), "the list's row must be gone");
    assert!(
        cfg.profiles["kids"].lists.is_empty(),
        "the override naming the removed list must be gone too — it is a \
         reference to something that no longer exists, and the loader refuses \
         a dangling one"
    );
}

/// **The control arm.** A cascade that empties every `lists` table satisfies
/// the row above. This one pins that it removes exactly the dead reference.
#[tokio::test]
async fn removing_a_list_leaves_an_unrelated_override_alone() {
    let dir = tempfile::tempdir().unwrap();
    let master = write_master(
        &dir,
        r#"[[blocklists]]
id = "gambling"
display_name = "Gambling"
url = "https://lists.purge.cc/gambling.txt"
base = "deny"
trust = "local"

[[blocklists]]
id = "ads"
display_name = "Ads"
url = "https://lists.purge.cc/ads.txt"
base = "deny"
trust = "local"

[profiles.default]
display_name = "Default"

[profiles.kids]
display_name = "Kids"
lists = { gambling = "allow", ads = "ignore" }
"#,
    );

    run_remove(&master, &dead_socket(&dir), "gambling", None)
        .await
        .expect("remove must succeed");

    let cfg = load_ok(&master);
    let kids = &cfg.profiles["kids"].lists;
    assert_eq!(
        kids.get(&Id::new("ads").unwrap()),
        Some(&ListPolicy::Ignore),
        "the surviving list's override must be untouched"
    );
    assert_eq!(kids.len(), 1, "only the dead reference leaves");
}

/// The split-file layout: the list lives in one include, the profile that
/// overrides it in another.
///
/// **The two rows above cannot see this.** Both are single-file masters, so
/// the cascade's edit and the row's removal collapse into one `StagedWrite`
/// and land in a single rename — the multi-file path is never entered. This
/// row is the one where `resolve_existing_target_file(.., Profiles, ..)` has
/// to find a file the blocklist does not live in, and where two slices are
/// staged and promoted.
///
/// **What it still does not prove, stated rather than implied.** The promote
/// *order* — profile slices first, blocklist row last — is a crash-safety
/// property: it bounds what an operator finds on disk if the CLI dies between
/// two renames. No in-process assertion can observe it without fault
/// injection, because `write_values_validated` validates the combined state
/// before promoting anything, so every intermediate is invisible to a caller
/// that runs to completion. The ordering is therefore still prose here, as it
/// is at the `remove_admin_rule_by_id` model this follows.
#[tokio::test]
async fn removing_a_list_cascades_into_a_profile_living_in_another_file() {
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("config.toml");
    // `includes` is a top-level key: it must precede every table, or TOML
    // parses it as a member of the last one.
    std::fs::write(
        &master,
        r#"schema_version = 3
includes = ["conf.d/*.toml"]

[upstream]
mode = "plain"
servers = ["192.0.2.1:53"]

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"
"#,
    )
    .expect("write master");
    let confd = dir.path().join("conf.d");
    std::fs::create_dir_all(&confd).expect("mkdir conf.d");
    std::fs::write(
        confd.join("lists.toml"),
        r#"[[blocklists]]
id = "gambling"
display_name = "Gambling"
url = "https://lists.purge.cc/gambling.txt"
base = "deny"
trust = "local"
"#,
    )
    .expect("write lists include");
    std::fs::write(
        confd.join("kids.toml"),
        r#"[profiles.kids]
display_name = "Kids"
lists = { gambling = "allow" }
"#,
    )
    .expect("write profile include");

    run_remove(&master, &dead_socket(&dir), "gambling", None)
        .await
        .expect("the override lives in a different file, and must still be cascaded");

    let cfg = load_ok(&master);
    assert!(cfg.blocklists.is_empty(), "the list's row must be gone");
    assert!(
        cfg.profiles["kids"].lists.is_empty(),
        "the override in conf.d/kids.toml must be gone too"
    );
    // Both slices really were written — a cascade that only edited the
    // in-memory doc would still satisfy the load above if the loader happened
    // to read the same tree, so name the bytes.
    assert!(
        !std::fs::read_to_string(confd.join("kids.toml"))
            .unwrap()
            .contains("gambling"),
        "the profile include on disk must no longer mention the removed list"
    );
}
