//! `warden profile list-policy` — the operator's way into the three-state
//! direction model, and the read verb that shows what a profile applies.
//!
//! # What the read verb used to answer with
//!
//! `warden profile show` printed `tags` — inert since the direction moved
//! onto the profile — and did not print `lists`, which decides everything.
//! The verb an operator reaches for to answer *"what does this profile
//! actually apply?"* answered with the retired mechanism. A feature that
//! cannot be inspected is not shipped, so the read half is pinned here
//! beside the write half.
//!
//! # Why provenance cannot be derived by comparison
//!
//! `base = deny` overridden to `deny` and `base = deny` never mentioned
//! have the same *effect* and different *intentions*: the first survives a
//! later change to `base`, the second follows it. An implementation that
//! decided "overridden" by comparing the effective direction against the
//! list's `base` would call that row inherited and hide the declaration.
//! Every fixture profile below therefore carries such a row —
//! `same-as-base` — and asserting on it is what makes these tests
//! discriminate rather than merely pass.
//!
//! # Why the write assertions read the file
//!
//! The daemon's `Ok` message is generated whether or not the override
//! reached disk. Every write below goes through a real `socket_server`
//! over a tempdir socket and is asserted against the re-parsed master, and
//! the round-trip test then reads that same file back through
//! `load_config` and the renderer — so the write half and the read half
//! are measured against one artefact rather than two mocks.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use purge_warden::auth::token::hash_token;
use purge_warden::cli::commands::profiles_v1::{
    format_list_policy_row, list_policy_clear_command, list_policy_rows, list_policy_set_command,
    parse_list_policy, ListPolicyRow, LIST_POLICY_DISABLED_NOTE, LIST_POLICY_INHERITED,
    LIST_POLICY_OVERRIDDEN, LIST_POLICY_TOKENS,
};
use purge_warden::config::loader::load_config;
use purge_warden::config::schema::blocklist::ListPolicy;
use purge_warden::dns::cache::DnsCache;
use purge_warden::filter::FilterEngine;
use purge_warden::ipc::protocol::{IpcCommand, IpcResponse};
use purge_warden::ipc::socket_client;
use purge_warden::ipc::socket_server::{spawn_ipc_server, DaemonState};

/// Five lists chosen so each row of the renderer is separately falsifiable.
///
/// - `inherits` — `base = deny`, never overridden anywhere.
/// - `flipped` — overridden to `allow` on `kids`; its row carries
///   `trust = "local"` so the override is about direction, not consent.
/// - `same-as-base` — overridden to `deny`, which its `base` already is.
///   **The discriminating row.** A renderer deriving provenance by
///   comparison prints "inherited" here and passes every other assertion.
/// - `switched-off` — `enabled = false`, so its direction applies nothing
///   whatever it says.
/// - `unsigned-no-ack` — omits `trust` deliberately: the field defaults to
///   `RemoteUnsigned`, not `Local`, so this is the shape an operator's row
///   has when they never thought about trust at all. An `allow` override
///   on it must be refused.
///
/// Upstream is RFC 5737 TEST-NET-1 and every list URL is first-party —
/// warden ships no provider defaults and a fixture is not the place to
/// introduce one.
const MASTER_SEED: &str = r#"schema_version = 3

[server]
default_profile = "default"

[upstream]
mode = "plain"
servers = ["192.0.2.1:53"]

[[blocklists]]
id = "inherits"
display_name = "Inherited"
url = "https://lists.purge.cc/privacy/ads.txt"
base = "deny"
trust = "local"

[[blocklists]]
id = "flipped"
display_name = "Flipped here"
url = "https://lists.purge.cc/privacy/tracking.txt"
base = "deny"
trust = "local"

[[blocklists]]
id = "same-as-base"
display_name = "Declared, same value"
url = "https://lists.purge.cc/content/gambling.txt"
base = "deny"
trust = "local"

[[blocklists]]
id = "switched-off"
display_name = "Disabled"
url = "https://lists.purge.cc/content/social.txt"
base = "deny"
trust = "local"
enabled = false

[[blocklists]]
id = "unsigned-no-ack"
display_name = "Unsigned, no ack"
url = "https://lists.purge.cc/privacy/malware.txt"
base = "deny"

[profiles.default]
display_name = "Default"

[profiles.kids]
display_name = "Kids"
lists = { flipped = "allow", same-as-base = "deny" }
"#;

// ── fixture ─────────────────────────────────────────────────────────

struct Fixture {
    _tmp: tempfile::TempDir,
    _server: tokio::task::JoinHandle<()>,
    socket_path: PathBuf,
    master: PathBuf,
    token: String,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self._server.abort();
    }
}

/// Shape mirrors `tests/plp_s4b_ipc_list_policy.rs`. A local copy rather
/// than an import: that file belongs to another lane, and a shared harness
/// would make one lane's fixture edit break the other's tests.
async fn spawn_fixture() -> Fixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let master = tmp.path().join("config.toml");
    std::fs::write(&master, MASTER_SEED).expect("seed master config");
    let socket_path = tmp.path().join("control.sock");

    let token = "test-token-very-secret".to_string();
    let token_hash = hash_token(&token);

    let cache_config = purge_warden::config::settings::CacheConfig::default();
    let state = DaemonState {
        filter: Arc::new(FilterEngine::new()),
        cache: DnsCache::new(&cache_config),
        profiles: None,
        stats: None,
        listen_addr: "127.0.0.1:15353".into(),
        upstream_mode: "plain".into(),
        upstream_count: 0,
        upstream_servers: Vec::new(),
        list_count: 0,
        started_at: Instant::now(),
        shutdown_tx: None,
        reload_tx: None,
        api_token_hash: Arc::new(arc_swap::ArcSwap::from_pointee(Some(token_hash))),
        config_path: Some(master.clone()),
        config_write_lock: Arc::new(tokio::sync::Mutex::new(())),
        list_statuses: None,
        list_state: None,
        local_records_hits: None,
        log_ring: None,
        notification_tx: None,
        reload_coalescer: None,
        oui_table: None,
        list_labels: Arc::new(vec![None; 64]),
        list_cmd_tx: Arc::new(arc_swap::ArcSwap::from_pointee(None)),
        daemon_uid: purge_warden::ipc::socket_server::current_euid(),
        resource_budget_store: purge_warden::resource_budget::types::new_store(),
        #[cfg(feature = "cluster")]
        cluster_observe: None,
    };

    let handle = spawn_ipc_server(socket_path.clone(), Arc::new(state))
        .await
        .expect("spawn_ipc_server");
    tokio::task::yield_now().await;

    Fixture {
        _tmp: tmp,
        _server: handle,
        socket_path,
        master,
        token,
    }
}

/// Send a command the CLI built, with the fixture's token attached.
///
/// `socket_client::send_command` honours a token the caller already set —
/// the documented contract it grew for `token regenerate` — so this reuses
/// the CLI's own command builder unchanged and only supplies the
/// credential the CLI would otherwise discover from a system path.
async fn send(fx: &Fixture, cmd: IpcCommand) -> IpcResponse {
    let cmd = match cmd {
        IpcCommand::ProfileUpdate { id, patch, .. } => IpcCommand::ProfileUpdate {
            id,
            patch,
            token: Some(fx.token.clone()),
        },
        other => other,
    };
    socket_client::send_command(&fx.socket_path, &cmd)
        .await
        .expect("send_command")
}

/// `profiles.<id>.lists` as the FILE holds it, re-parsed rather than
/// grepped: a mis-nested emit shows up as a wrong-shaped document instead
/// of a substring that happens to be present.
fn lists_on_disk(fx: &Fixture, profile: &str) -> Option<toml::value::Table> {
    let doc: toml::Value = std::fs::read_to_string(&fx.master)
        .expect("read master")
        .parse()
        .expect("master must re-parse");
    doc.get("profiles")?
        .get(profile)?
        .get("lists")?
        .as_table()
        .cloned()
}

/// Read the master back through the real loader and render `profile`'s
/// rows with the shipped renderer.
fn rows_from_disk(fx: &Fixture, profile: &str) -> Vec<ListPolicyRow> {
    let loaded = load_config(&fx.master, time::OffsetDateTime::now_utc())
        .unwrap_or_else(|e| panic!("master must load: {e:?}"));
    let prof = loaded
        .config
        .profiles
        .get(profile)
        .unwrap_or_else(|| panic!("no [profiles.{profile}]"));
    list_policy_rows(prof, &loaded.config.blocklists)
}

fn row<'a>(rows: &'a [ListPolicyRow], id: &str) -> &'a ListPolicyRow {
    rows.iter()
        .find(|r| r.list_id == id)
        .unwrap_or_else(|| panic!("no row for {id}"))
}

fn expect_ok(resp: IpcResponse, what: &str) -> String {
    match resp {
        IpcResponse::Ok { message } => message,
        other => panic!("expected Ok for {what}, got {other:?}"),
    }
}

fn expect_err(resp: IpcResponse, what: &str) -> String {
    match resp {
        IpcResponse::Error { message } => message,
        other => panic!("expected an error for {what}, got {other:?}"),
    }
}

// ── 1. the read verb: provenance ────────────────────────────────────

/// DoD #4 — inherited and overridden are told apart on a profile carrying
/// both, and the same-as-`base` row is what makes the test discriminate.
#[test]
fn plp_s4a_show_tells_inherited_from_overridden() {
    let dir = tempfile::tempdir().expect("tempdir");
    let master = dir.path().join("config.toml");
    std::fs::write(&master, MASTER_SEED).expect("seed");
    let loaded = load_config(&master, time::OffsetDateTime::now_utc()).expect("fixture must load");
    let prof = loaded.config.profiles.get("kids").expect("kids");
    let rows = list_policy_rows(prof, &loaded.config.blocklists);

    let inherited = row(&rows, "inherits");
    assert!(
        !inherited.overridden,
        "a list this profile never names is inherited, got {inherited:?}"
    );
    assert_eq!(inherited.policy, ListPolicy::Deny);

    let flipped = row(&rows, "flipped");
    assert!(
        flipped.overridden,
        "an overridden list says so: {flipped:?}"
    );
    assert_eq!(flipped.policy, ListPolicy::Allow);

    // The discriminator: same effect as `base`, different intention.
    let same = row(&rows, "same-as-base");
    assert!(
        same.overridden,
        "an override whose value equals `base` is still an override — \
         provenance is the key's presence, not a comparison: {same:?}"
    );
    assert_eq!(same.policy, ListPolicy::Deny);

    // Both provenances must be legible in the rendered text, not only in
    // the struct — the operator reads the line, not the field.
    let rendered = format_list_policy_row(inherited);
    assert!(
        rendered.contains(LIST_POLICY_INHERITED) && !rendered.contains(LIST_POLICY_OVERRIDDEN),
        "inherited row rendered as {rendered:?}"
    );
    let rendered = format_list_policy_row(same);
    assert!(
        rendered.contains(LIST_POLICY_OVERRIDDEN) && !rendered.contains(LIST_POLICY_INHERITED),
        "same-as-base row rendered as {rendered:?}"
    );
}

/// A switched-off list is annotated, never collapsed into `ignore`.
///
/// `effective_direction` deliberately says nothing about `enabled`, which
/// makes every enumerating caller responsible for the distinction: the
/// operator turning a list off is not the profile ignoring it, and folding
/// the two would make re-enabling the list look like a policy change on
/// every profile at once.
#[test]
fn plp_s4a_a_disabled_list_is_annotated_not_reported_as_ignore() {
    let dir = tempfile::tempdir().expect("tempdir");
    let master = dir.path().join("config.toml");
    std::fs::write(&master, MASTER_SEED).expect("seed");
    let loaded = load_config(&master, time::OffsetDateTime::now_utc()).expect("fixture must load");
    let prof = loaded.config.profiles.get("kids").expect("kids");
    let rows = list_policy_rows(prof, &loaded.config.blocklists);

    let off = row(&rows, "switched-off");
    assert!(!off.enabled, "the fixture row must be disabled: {off:?}");
    assert_eq!(
        off.policy,
        ListPolicy::Deny,
        "its declared direction is unchanged by being switched off"
    );
    let rendered = format_list_policy_row(off);
    assert!(
        rendered.contains(LIST_POLICY_DISABLED_NOTE),
        "a disabled list must say so: {rendered:?}"
    );
    assert!(
        !rendered.contains(ListPolicy::Ignore.wire_str()),
        "disabled must not be reported as the `ignore` direction: {rendered:?}"
    );

    // An enabled row must NOT carry the note, or the assertion above
    // would pass on a renderer that appends it unconditionally.
    let on = row(&rows, "inherits");
    assert!(
        !format_list_policy_row(on).contains(LIST_POLICY_DISABLED_NOTE),
        "an enabled list must not be annotated as disabled"
    );
}

// ── 2. the write verbs: the file, and the round trip ────────────────

/// DoD #2 — each of the three states written by the CLI's own command
/// builder lands on disk and reads back through the renderer.
#[tokio::test]
async fn plp_s4a_each_of_the_three_states_round_trips_through_the_file() {
    let fx = spawn_fixture().await;

    for policy in LIST_POLICY_TOKENS {
        let resp = send(&fx, list_policy_set_command("default", "inherits", policy)).await;
        expect_ok(resp, policy.wire_str());

        let table = lists_on_disk(&fx, "default").expect("lists table after set");
        assert_eq!(
            table.get("inherits").and_then(|v| v.as_str()),
            Some(policy.wire_str()),
            "the file must carry the direction just set ({policy:?})"
        );

        let rows = rows_from_disk(&fx, "default");
        let r = row(&rows, "inherits");
        assert_eq!(r.policy, policy, "read back through the loader");
        assert!(r.overridden, "an override read back is still an override");
    }
}

/// DoD #3 — `clear` and `set … ignore` are different declarations, and the
/// files they produce differ.
///
/// The whole three-state model rests on this: an absent key follows the
/// list's `base` wherever it goes, a key holding `ignore` keeps saying
/// "not here" after `base` changes. Collapsing one into the other is the
/// easiest way to lose the model while every other test stays green.
#[tokio::test]
async fn plp_s4a_clear_is_not_set_ignore() {
    let fx = spawn_fixture().await;

    let resp = send(
        &fx,
        list_policy_set_command("default", "inherits", ListPolicy::Ignore),
    )
    .await;
    expect_ok(resp, "set ignore");
    let after_ignore = lists_on_disk(&fx, "default").expect("lists table after set ignore");
    assert_eq!(
        after_ignore.get("inherits").and_then(|v| v.as_str()),
        Some("ignore"),
        "`set ignore` writes the key"
    );

    let resp = send(&fx, list_policy_clear_command("default", "inherits")).await;
    expect_ok(resp, "clear");
    let after_clear = lists_on_disk(&fx, "default");
    assert!(
        after_clear
            .as_ref()
            .and_then(|t| t.get("inherits"))
            .is_none(),
        "`clear` removes the key, it does not set a direction: {after_clear:?}"
    );

    assert_ne!(
        after_ignore.get("inherits"),
        after_clear.as_ref().and_then(|t| t.get("inherits")),
        "the two verbs must not produce the same file"
    );

    // And the difference is visible where the operator reads it.
    let rows = rows_from_disk(&fx, "default");
    let r = row(&rows, "inherits");
    assert!(!r.overridden, "a cleared pair inherits again: {r:?}");
    assert_eq!(
        r.policy,
        ListPolicy::Deny,
        "and follows the list's own base"
    );
}

/// `clear` on a profile that has exactly one override empties the table,
/// and an empty table is removed rather than left as `lists = {}`.
#[tokio::test]
async fn plp_s4a_clearing_the_last_override_leaves_no_lists_table() {
    let fx = spawn_fixture().await;

    expect_ok(
        send(
            &fx,
            list_policy_set_command("default", "inherits", ListPolicy::Allow),
        )
        .await,
        "set",
    );
    expect_ok(
        send(&fx, list_policy_clear_command("default", "inherits")).await,
        "clear",
    );

    assert!(
        lists_on_disk(&fx, "default").is_none(),
        "an emptied override map is removed, not written as an empty table"
    );
}

// ── 3. the refusal reaches the operator ─────────────────────────────

/// The consent refusal is the COMMON case, not the edge one:
/// `BlocklistTrust` defaults to `RemoteUnsigned`, so a `[[blocklists]]`
/// row that never mentions trust is unsigned-remote — which is every row
/// on both live hosts.
///
/// This lane does not re-implement the gate; it must surface it. The
/// assertion is therefore that the refusal is **actionable**: it names the
/// profile, the list, and the list-level verb that unblocks the situation.
/// A refusal pointing at a field the interface gives no way to set is the
/// defect this repo has already paid for once.
#[tokio::test]
async fn plp_s4a_an_unconsented_allow_override_is_refused_actionably() {
    let fx = spawn_fixture().await;

    let resp = send(
        &fx,
        list_policy_set_command("kids", "unsigned-no-ack", ListPolicy::Allow),
    )
    .await;
    let msg = expect_err(resp, "allow override on an unsigned list with no ack");

    assert!(msg.contains("unsigned-no-ack"), "names the list: {msg}");
    assert!(msg.contains("kids"), "names the profile: {msg}");
    assert!(
        msg.contains("warden blocklist set-trust"),
        "names the verb that resolves it: {msg}"
    );
    assert!(
        msg.contains("--accept-unsigned-allow"),
        "names the flag that resolves it: {msg}"
    );
    assert!(
        lists_on_disk(&fx, "kids")
            .and_then(|t| t.get("unsigned-no-ack").cloned())
            .is_none(),
        "a refused override writes nothing"
    );

    // Positive arm: the same verb, the same profile, a list whose row does
    // not need the declaration. Without this the assertions above would
    // stay green on a build where every override was refused.
    expect_ok(
        send(
            &fx,
            list_policy_set_command("kids", "inherits", ListPolicy::Allow),
        )
        .await,
        "allow on a local-trust list",
    );
    assert_eq!(
        lists_on_disk(&fx, "kids")
            .expect("lists table")
            .get("inherits")
            .and_then(|v| v.as_str()),
        Some("allow"),
    );
}

/// `deny` and `ignore` never pay the consent gate — they narrow what the
/// profile permits, so they have nothing to declare. Pinned on the same
/// unconsented row that refuses `allow` above, so this is a statement
/// about the direction and not about the list.
#[tokio::test]
async fn plp_s4a_deny_and_ignore_on_an_unconsented_list_are_not_refused() {
    let fx = spawn_fixture().await;

    for policy in [ListPolicy::Deny, ListPolicy::Ignore] {
        let resp = send(
            &fx,
            list_policy_set_command("kids", "unsigned-no-ack", policy),
        )
        .await;
        expect_ok(resp, policy.wire_str());
        assert_eq!(
            lists_on_disk(&fx, "kids")
                .expect("lists table")
                .get("unsigned-no-ack")
                .and_then(|v| v.as_str()),
            Some(policy.wire_str()),
        );
    }
}

// ── 4. the token parser ─────────────────────────────────────────────

/// Every `ListPolicy` variant has a CLI spelling, and the exhaustive
/// `match` below is the trip-wire: a fourth variant fails this build
/// rather than quietly having no way to be typed.
#[test]
fn plp_s4a_parse_list_policy_covers_every_variant() {
    let all = [ListPolicy::Deny, ListPolicy::Allow, ListPolicy::Ignore];
    for variant in all {
        // Exhaustive on purpose — adding a variant is a compile error here.
        let token = match variant {
            ListPolicy::Deny => "deny",
            ListPolicy::Allow => "allow",
            ListPolicy::Ignore => "ignore",
        };
        assert_eq!(
            parse_list_policy(token).expect("must parse"),
            variant,
            "the CLI spelling of {variant:?} must be the config spelling"
        );
        assert_eq!(
            token,
            variant.wire_str(),
            "the CLI must not invent a spelling the config file does not use"
        );
        assert!(
            LIST_POLICY_TOKENS.contains(&variant),
            "{variant:?} missing from the accepted-token table the help prints"
        );
    }
}

#[test]
fn plp_s4a_parse_list_policy_refuses_anything_else() {
    for bad in ["block", "Deny", "", "allow-all", "none"] {
        let err = parse_list_policy(bad)
            .expect_err(&format!("{bad:?} must not parse"))
            .to_string();
        for token in LIST_POLICY_TOKENS {
            assert!(
                err.contains(token.wire_str()),
                "the refusal must list what IS accepted; missing {}: {err}",
                token.wire_str()
            );
        }
    }
}
