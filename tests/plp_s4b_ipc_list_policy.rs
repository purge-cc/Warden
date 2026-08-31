//! `profile_list_policy` §4 S4 lane 4b — `ListPolicyPatch` on the IPC wire,
//! and the consent gate at the one place every override write passes.
//!
//! # Why the gate is here and not on each surface
//!
//! Both operator surfaces write `[profiles.<id>]` through
//! `IpcCommand::ProfileUpdate` and nothing else — `cli::commands::profiles_v1`
//! and `tui::ipc_poller`. The per-profile override therefore has exactly one
//! writer, so the CLI and TUI lanes that follow expose this refusal instead of
//! re-implementing it.
//!
//! # Why the daemon is the last line, not a redundant one
//!
//! Measured on this branch: the validator's `UNSIGNED_ALLOW_LIST_REQUIRES_ACK`
//! check keys on `b.base == BlocklistBase::Allow` — the **list's** base
//! (`config/schema/validator.rs:4184`). It says nothing about
//! `profiles.<id>.lists.<list> = "allow"`. So an override-scope allow on an
//! unsigned remote list with no ack passes the whole config layer today, and
//! the refusal these tests pin is the only one standing.
//!
//! # The shape of the assertions
//!
//! A test that only asserted "the response was an error" would stay green if
//! the gate were never wired and something unrelated failed first. Every
//! refusal here is therefore paired with a **positive arm** — the same list,
//! the same patch, with `accept_unsigned_allow = true` on its row — that must
//! land the override on disk. Two arms, or nothing has been measured.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use purge_warden::auth::token::hash_token;
use purge_warden::config::schema::blocklist::ListPolicy;
use purge_warden::dns::cache::DnsCache;
use purge_warden::filter::FilterEngine;
use purge_warden::ipc::protocol::{IpcCommand, IpcResponse, ListPolicyPatch, ProfileUpdatePatch};
use purge_warden::ipc::socket_client;
use purge_warden::ipc::socket_server::{spawn_ipc_server, DaemonState};

/// Three lists spanning the whole gate surface, and two profiles.
///
/// `unsigned-no-ack` omits `trust` on purpose: the field's `Default` is
/// `RemoteUnsigned`, not `Local`, and a handler that read the key by hand and
/// defaulted the other way would fail **open** on exactly this row.
///
/// Upstream is RFC 5737 TEST-NET-1 — warden ships no provider defaults
/// (project rules §Neutrality) and a fixture is not the place to reintroduce one.
const MASTER_SEED: &str = r#"schema_version = 3

[server]
default_profile = "default"

[upstream]
mode = "plain"
servers = ["192.0.2.1:53"]

[[blocklists]]
id = "unsigned-no-ack"
display_name = "Unsigned, no ack"
url = "https://lists.purge.cc/privacy/ads.txt"

[[blocklists]]
id = "unsigned-with-ack"
display_name = "Unsigned, consented"
url = "https://lists.purge.cc/privacy/tracking.txt"
trust = "remote-unsigned"
accept_unsigned_allow = true

[[blocklists]]
id = "operator-local"
display_name = "Operator's own file"
url = "https://lists.purge.cc/content/gambling.txt"
trust = "local"

[profiles.default]
display_name = "Default"

[profiles.kids]
display_name = "Kids"
"#;

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

fn read_master(fx: &Fixture) -> String {
    std::fs::read_to_string(&fx.master).expect("read master")
}

/// The `profiles.<id>.lists` table as the FILE holds it, re-parsed.
///
/// Reads through `toml::Value` rather than grepping the text so a mis-nested
/// emit (an override table swallowing a following scalar) shows up as a
/// wrong-shaped document, not as a substring that happens to be present.
fn lists_on_disk(fx: &Fixture, profile: &str) -> Option<toml::value::Table> {
    let doc: toml::Value = read_master(fx).parse().expect("master must re-parse");
    doc.get("profiles")?
        .get(profile)?
        .get("lists")?
        .as_table()
        .cloned()
}

fn profile_table(fx: &Fixture, profile: &str) -> toml::value::Table {
    let doc: toml::Value = read_master(fx).parse().expect("master must re-parse");
    doc.get("profiles")
        .and_then(|v| v.get(profile))
        .and_then(|v| v.as_table())
        .cloned()
        .unwrap_or_else(|| panic!("no [profiles.{profile}] in master"))
}

async fn send(fx: &Fixture, profile: &str, patch: ProfileUpdatePatch) -> IpcResponse {
    socket_client::send_command(
        &fx.socket_path,
        &IpcCommand::ProfileUpdate {
            id: profile.into(),
            patch,
            token: Some(fx.token.clone()),
        },
    )
    .await
    .expect("send_command")
}

fn policy_patch(set: &[(&str, ListPolicy)], clear: &[&str]) -> ProfileUpdatePatch {
    ProfileUpdatePatch {
        lists: Some(ListPolicyPatch {
            set: set.iter().map(|(k, v)| ((*k).to_string(), *v)).collect(),
            clear: clear.iter().map(|s| (*s).to_string()).collect(),
        }),
        ..Default::default()
    }
}

fn expect_err(resp: IpcResponse, what: &str) -> String {
    match resp {
        IpcResponse::Error { message } => message,
        other => panic!("expected an error for {what}, got {other:?}"),
    }
}

fn expect_ok(resp: IpcResponse, what: &str) -> String {
    match resp {
        IpcResponse::Ok { message } => message,
        other => panic!("expected Ok for {what}, got {other:?}"),
    }
}

// ── 1. the wire type ────────────────────────────────────────────────

/// DoD #2 — every variant and both empty fields survive the round trip.
///
/// Walks all three `ListPolicy` variants in one patch because the reason this
/// is a map delta and not a set delta is that a set cannot carry three states;
/// a round-trip that exercised only `Deny` would pass on the shape this type
/// was explicitly not given.
#[test]
fn plp_s4b_list_policy_patch_round_trips_every_variant() {
    let patch = ListPolicyPatch {
        set: [
            ("a-deny".to_string(), ListPolicy::Deny),
            ("b-allow".to_string(), ListPolicy::Allow),
            ("c-ignore".to_string(), ListPolicy::Ignore),
        ]
        .into_iter()
        .collect(),
        clear: vec!["d-cleared".to_string()],
    };

    let json = serde_json::to_string(&patch).expect("serialise");
    let back: ListPolicyPatch = serde_json::from_str(&json).expect("deserialise");
    assert_eq!(back, patch, "round trip must be lossless; json was {json}");

    // The three tokens are the schema's own, not a second spelling invented
    // on the wire: a rename that missed this type would show up here.
    assert!(json.contains(r#""b-allow":"allow""#), "json was {json}");
    assert!(json.contains(r#""c-ignore":"ignore""#), "json was {json}");
}

/// Both fields are `#[serde(default)]`, so an absent field decodes as empty —
/// a client that only ever clears need not send `set` at all.
#[test]
fn plp_s4b_list_policy_patch_fields_default_to_empty() {
    let empty: ListPolicyPatch = serde_json::from_str("{}").expect("empty object decodes");
    assert!(empty.set.is_empty() && empty.clear.is_empty());
    assert_eq!(empty, ListPolicyPatch::default());

    let only_clear: ListPolicyPatch =
        serde_json::from_str(r#"{"clear":["x"]}"#).expect("clear-only decodes");
    assert!(only_clear.set.is_empty());
    assert_eq!(only_clear.clear, vec!["x".to_string()]);
}

/// `ProfileUpdatePatch` skips the field when it is `None`, so every existing
/// caller's payload is byte-identical to what it sent before this sprint.
#[test]
fn plp_s4b_absent_list_policy_is_not_serialised() {
    let json = serde_json::to_string(&ProfileUpdatePatch::default()).expect("serialise");
    assert!(
        !json.contains("lists"),
        "an untouched patch must not mention lists; json was {json}"
    );
}

// ── 2. the consent gate, both arms ──────────────────────────────────

/// DoD #3, negative arm. An `allow` override on a `trust = remote-unsigned`
/// list with no `accept_unsigned_allow` on its row is refused, **and leaves no
/// trace on the file**.
///
/// The assertion is on the file, not on the response: a refusal that had
/// already written would be a far worse defect than a refusal that failed to
/// refuse, and only the file can tell them apart.
#[tokio::test]
async fn plp_s4b_allow_override_without_consent_is_refused_and_writes_nothing() {
    let fx = spawn_fixture().await;
    let before = read_master(&fx);

    let msg = expect_err(
        send(
            &fx,
            "kids",
            policy_patch(&[("unsigned-no-ack", ListPolicy::Allow)], &[]),
        )
        .await,
        "an unconsented allow override",
    );

    assert!(
        msg.contains("unsigned-no-ack"),
        "the refusal must name the list; got: {msg}"
    );
    assert!(
        msg.contains("blocklist set-trust"),
        "the refusal must name the verb that declares consent; got: {msg}"
    );
    assert_eq!(
        read_master(&fx),
        before,
        "a refused patch must leave the file byte-identical"
    );
    assert!(lists_on_disk(&fx, "kids").is_none());
}

/// DoD #3, positive arm — **the control that makes the negative arm mean
/// something**. Same profile, same policy, a list whose row already carries
/// the operator's declaration: the write lands.
///
/// It also carries `display_name` in the same patch. That is deliberate and it
/// tests a second property: `Profile` declares `lists` last because TOML
/// cannot emit a bare scalar after a table inside the same table, and this
/// handler edits the raw table where key order is the map's, not the struct's.
/// If the render mis-nested the scalar into `[profiles.kids.lists]`, this arm
/// fails — so ordering and gating are separated by construction.
#[tokio::test]
async fn plp_s4b_allow_override_with_consent_on_the_row_is_written() {
    let fx = spawn_fixture().await;

    let mut patch = policy_patch(&[("unsigned-with-ack", ListPolicy::Allow)], &[]);
    patch.display_name = Some("Kids Renamed".into());
    expect_ok(send(&fx, "kids", patch).await, "a consented allow override");

    let lists = lists_on_disk(&fx, "kids").expect("the override table must exist");
    assert_eq!(
        lists.get("unsigned-with-ack").and_then(|v| v.as_str()),
        Some("allow"),
        "master:\n{}",
        read_master(&fx)
    );

    // The scalar in the same patch survived as a scalar of the PROFILE, not as
    // a key of the override table.
    let prof = profile_table(&fx, "kids");
    assert_eq!(
        prof.get("display_name").and_then(|v| v.as_str()),
        Some("Kids Renamed"),
        "the scalar must land on the profile, not inside `lists`. master:\n{}",
        read_master(&fx)
    );
    assert!(
        !lists.contains_key("display_name"),
        "the override table swallowed the scalar — mis-nested emit. master:\n{}",
        read_master(&fx)
    );
}

/// The gate keys on `trust`, not on "allow is always suspicious". A list the
/// operator authored themselves has no third party to consent to.
#[tokio::test]
async fn plp_s4b_allow_override_on_a_local_list_needs_no_consent() {
    let fx = spawn_fixture().await;
    expect_ok(
        send(
            &fx,
            "kids",
            policy_patch(&[("operator-local", ListPolicy::Allow)], &[]),
        )
        .await,
        "an allow override on a local list",
    );
    let lists = lists_on_disk(&fx, "kids").expect("override table");
    assert_eq!(
        lists.get("operator-local").and_then(|v| v.as_str()),
        Some("allow")
    );
}

/// `Deny` and `Ignore` narrow what the profile permits, so the gate must not
/// fire for them — on the very list whose `allow` is refused.
///
/// Without this arm the negative test above would also pass on a handler that
/// refused every override of `unsigned-no-ack` regardless of direction, which
/// would be a different bug wearing the same green.
#[tokio::test]
async fn plp_s4b_deny_and_ignore_overrides_are_never_gated() {
    let fx = spawn_fixture().await;

    expect_ok(
        send(
            &fx,
            "kids",
            policy_patch(&[("unsigned-no-ack", ListPolicy::Deny)], &[]),
        )
        .await,
        "a deny override on the ungated list",
    );
    assert_eq!(
        lists_on_disk(&fx, "kids").and_then(|t| t
            .get("unsigned-no-ack")
            .and_then(|v| v.as_str().map(String::from))),
        Some("deny".to_string())
    );

    expect_ok(
        send(
            &fx,
            "kids",
            policy_patch(&[("unsigned-no-ack", ListPolicy::Ignore)], &[]),
        )
        .await,
        "an ignore override on the ungated list",
    );
    assert_eq!(
        lists_on_disk(&fx, "kids").and_then(|t| t
            .get("unsigned-no-ack")
            .and_then(|v| v.as_str().map(String::from))),
        Some("ignore".to_string()),
        "`set` on a present key overwrites — idempotent, not an error"
    );
}

/// A patch that names two lists and gets one of them wrong writes **neither**.
///
/// The refusals run over the whole `set` before a single key is applied, so a
/// gate failure can never leave a half-applied override behind.
#[tokio::test]
async fn plp_s4b_a_refused_key_takes_the_whole_patch_with_it() {
    let fx = spawn_fixture().await;
    let before = read_master(&fx);

    expect_err(
        send(
            &fx,
            "kids",
            policy_patch(
                &[
                    ("operator-local", ListPolicy::Deny),
                    ("unsigned-no-ack", ListPolicy::Allow),
                ],
                &[],
            ),
        )
        .await,
        "a mixed patch with one refused key",
    );

    assert_eq!(read_master(&fx), before);
    assert!(
        lists_on_disk(&fx, "kids").is_none(),
        "the legal key must not have landed either"
    );
}

// ── 3. unknown / malformed ids ──────────────────────────────────────

/// DoD, refusal #1. An id no `[[blocklists]]` declares is refused **by name**,
/// rather than left to the post-write validator's `CrossRefMiss` — which
/// rejects the whole file and would take the other fields of the same patch
/// down with the typo.
#[tokio::test]
async fn plp_s4b_an_override_naming_an_unknown_list_is_refused_by_name() {
    let fx = spawn_fixture().await;
    let before = read_master(&fx);

    let mut patch = policy_patch(&[("no-such-list", ListPolicy::Deny)], &[]);
    patch.display_name = Some("Should Not Land".into());

    let msg = expect_err(send(&fx, "kids", patch).await, "an unknown list id");
    assert!(
        msg.contains("no-such-list"),
        "the refusal must name the id; got: {msg}"
    );
    assert_eq!(read_master(&fx), before);
    assert_eq!(
        profile_table(&fx, "kids")
            .get("display_name")
            .and_then(|v| v.as_str()),
        Some("Kids"),
        "the sibling field of the same patch must be untouched"
    );
}

/// A malformed id is refused before anything is staged, same as a malformed
/// tag slug — the `clear` half included, which a check written only over `set`
/// would miss.
#[tokio::test]
async fn plp_s4b_a_malformed_id_is_refused_in_both_halves() {
    let fx = spawn_fixture().await;
    let before = read_master(&fx);

    expect_err(
        send(
            &fx,
            "kids",
            policy_patch(&[("NOT A VALID ID", ListPolicy::Deny)], &[]),
        )
        .await,
        "a malformed id in `set`",
    );
    expect_err(
        send(&fx, "kids", policy_patch(&[], &["NOT A VALID ID"])).await,
        "a malformed id in `clear`",
    );
    assert_eq!(read_master(&fx), before);
}

// ── 4. set / clear ordering and the empty patch ─────────────────────

/// DoD #4 — `set` is applied BEFORE `clear`, so a key in both ends removed.
///
/// Uses `Deny`, not `Allow`: on a gated list this test would be measuring the
/// consent gate instead of the ordering, and would still be green if the two
/// halves ran in the wrong order.
#[tokio::test]
async fn plp_s4b_set_is_applied_before_clear_so_a_key_in_both_ends_removed() {
    let fx = spawn_fixture().await;

    // Seed two overrides so the map survives the clear and the assertion is
    // about the one key, not about the table vanishing.
    expect_ok(
        send(
            &fx,
            "kids",
            policy_patch(
                &[
                    ("operator-local", ListPolicy::Deny),
                    ("unsigned-no-ack", ListPolicy::Deny),
                ],
                &[],
            ),
        )
        .await,
        "seeding two overrides",
    );

    expect_ok(
        send(
            &fx,
            "kids",
            policy_patch(
                &[("unsigned-no-ack", ListPolicy::Ignore)],
                &["unsigned-no-ack"],
            ),
        )
        .await,
        "the same key in set and clear",
    );

    let lists = lists_on_disk(&fx, "kids").expect("the other override keeps the table alive");
    assert!(
        !lists.contains_key("unsigned-no-ack"),
        "`set` runs first, so the key ends REMOVED; got {lists:?}"
    );
    assert_eq!(
        lists.get("operator-local").and_then(|v| v.as_str()),
        Some("deny"),
        "the untouched override must survive"
    );
}

/// `clear` of a key that was never there is a no-op, not an error.
#[tokio::test]
async fn plp_s4b_clearing_an_absent_key_is_a_no_op() {
    let fx = spawn_fixture().await;
    expect_ok(
        send(&fx, "kids", policy_patch(&[], &["operator-local"])).await,
        "clearing an absent key",
    );
    assert!(lists_on_disk(&fx, "kids").is_none());
}

/// An all-empty patch writes **nothing** — not even `lists = {}`.
///
/// `Profile::lists` carries `skip_serializing_if = BTreeMap::is_empty` so an
/// empty override table never appears in an operator's file. A handler that
/// inserted one would put back exactly what that attribute keeps out, and the
/// TUI's profile modal submits its whole patch on every save, so a scalar-only
/// edit would carry an empty `ListPolicyPatch` and plant it everywhere.
#[tokio::test]
async fn plp_s4b_an_empty_list_policy_patch_writes_no_lists_key() {
    let fx = spawn_fixture().await;
    expect_ok(
        send(&fx, "kids", policy_patch(&[], &[])).await,
        "an all-empty patch",
    );
    assert!(
        lists_on_disk(&fx, "kids").is_none(),
        "master:\n{}",
        read_master(&fx)
    );
    assert!(
        !profile_table(&fx, "kids").contains_key("lists"),
        "master:\n{}",
        read_master(&fx)
    );
}

/// Emptying the map REMOVES the key rather than leaving `lists = {}` behind,
/// for the same reason.
#[tokio::test]
async fn plp_s4b_clearing_the_last_override_removes_the_table() {
    let fx = spawn_fixture().await;
    expect_ok(
        send(
            &fx,
            "kids",
            policy_patch(&[("operator-local", ListPolicy::Deny)], &[]),
        )
        .await,
        "seeding one override",
    );
    assert!(lists_on_disk(&fx, "kids").is_some());

    expect_ok(
        send(&fx, "kids", policy_patch(&[], &["operator-local"])).await,
        "clearing the last override",
    );
    assert!(
        !profile_table(&fx, "kids").contains_key("lists"),
        "an emptied map must be removed, not written as `lists = {{}}`. master:\n{}",
        read_master(&fx)
    );
}

// ── 5. the adjacent defect this lane repaired ───────────────────────

/// `plp-s4b`: an all-empty `TagsPatch` used to write `tags = []` into a
/// profile that had no `tags` key.
///
/// The apply block it came from was dead in every branch that mattered — the
/// `plp-s3` retirement refusal returns first for any non-empty delta — and its
/// one surviving effect was an unconditional insert, performed on the exact
/// patch `an_empty_tags_delta_is_not_refused` documents as "not a tag write".
///
/// Not cosmetic: `Profile` is `deny_unknown_fields` and S5 deletes the field,
/// so every `tags = []` this planted would become a config that does not load.
#[tokio::test]
async fn plp_s4b_an_empty_tags_patch_plants_no_tags_key() {
    let fx = spawn_fixture().await;
    expect_ok(
        send(
            &fx,
            "kids",
            ProfileUpdatePatch {
                display_name: Some("Kids Again".into()),
                ..Default::default()
            },
        )
        .await,
        "an empty tags delta alongside a scalar",
    );

    let prof = profile_table(&fx, "kids");
    assert_eq!(
        prof.get("display_name").and_then(|v| v.as_str()),
        Some("Kids Again"),
        "the scalar it accompanied must still land"
    );
    assert!(
        !prof.contains_key("tags"),
        "an empty delta is not a tag write. master:\n{}",
        read_master(&fx)
    );
}

// ── 6. the lists live in a DIFFERENT file from the profile ──────────

/// Master that keeps NOTHING but the include graph: the blocklists live in
/// `blocklists.d/`, the profiles in `profiles.d/`.
const SPLIT_MASTER: &str = r#"schema_version = 3
includes = ["blocklists.d/*.toml", "profiles.d/*.toml"]

[server]
default_profile = "default"

[upstream]
mode = "plain"
servers = ["192.0.2.1:53"]
"#;

const SPLIT_BLOCKLISTS: &str = r#"[[blocklists]]
id = "unsigned-no-ack"
display_name = "Unsigned, no ack"
url = "https://lists.purge.cc/privacy/ads.txt"

[[blocklists]]
id = "unsigned-with-ack"
display_name = "Unsigned, consented"
url = "https://lists.purge.cc/privacy/tracking.txt"
trust = "remote-unsigned"
accept_unsigned_allow = true
"#;

const SPLIT_PROFILES: &str = r#"[profiles.default]
display_name = "Default"

[profiles.kids]
display_name = "Kids"
"#;

/// Same daemon, a config split across three files.
async fn spawn_split_fixture() -> Fixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let master = tmp.path().join("config.toml");
    std::fs::write(&master, SPLIT_MASTER).expect("seed master");
    std::fs::create_dir_all(tmp.path().join("blocklists.d")).expect("blocklists.d");
    std::fs::create_dir_all(tmp.path().join("profiles.d")).expect("profiles.d");
    std::fs::write(
        tmp.path().join("blocklists.d").join("lists.toml"),
        SPLIT_BLOCKLISTS,
    )
    .expect("seed blocklists");
    std::fs::write(
        tmp.path().join("profiles.d").join("profiles.toml"),
        SPLIT_PROFILES,
    )
    .expect("seed profiles");

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

/// The profile's `lists` table as the file that actually owns the profile
/// holds it — `profiles.d/profiles.toml`, not the master.
fn split_lists_on_disk(fx: &Fixture, profile: &str) -> Option<toml::value::Table> {
    let path = fx
        .master
        .parent()
        .expect("parent")
        .join("profiles.d")
        .join("profiles.toml");
    let raw = std::fs::read_to_string(path).expect("read profiles include");
    let doc: toml::Value = raw.parse().expect("profiles include must re-parse");
    doc.get("profiles")?
        .get(profile)?
        .get("lists")?
        .as_table()
        .cloned()
}

/// The fragile half of this lane: the blocklist row the gate has to read can
/// live in a different include from the profile being written.
///
/// A fixture with both in the master would exercise neither
/// `find_target_for_id` on the blocklists class nor the fact that the handler
/// reads a document it is not holding open — it would pass on a handler that
/// looked the row up in the profile's own file and found nothing.
///
/// Negative arm: the write must be refused and neither file touched.
#[tokio::test]
async fn plp_s4b_the_gate_finds_a_row_that_lives_in_another_include() {
    let fx = spawn_split_fixture().await;
    let master_before = read_master(&fx);
    let profiles_path = fx
        .master
        .parent()
        .unwrap()
        .join("profiles.d")
        .join("profiles.toml");
    let profiles_before = std::fs::read_to_string(&profiles_path).expect("read");

    let msg = expect_err(
        send(
            &fx,
            "kids",
            policy_patch(&[("unsigned-no-ack", ListPolicy::Allow)], &[]),
        )
        .await,
        "an unconsented allow override, list in another include",
    );
    assert!(
        msg.contains("unsigned-no-ack") && msg.contains("blocklist set-trust"),
        "got: {msg}"
    );
    assert_eq!(read_master(&fx), master_before, "master must be untouched");
    assert_eq!(
        std::fs::read_to_string(&profiles_path).expect("read"),
        profiles_before,
        "the profiles include must be untouched"
    );
}

/// Positive arm of the cross-file case — the control without which the
/// refusal above could be a lookup that simply fails on every split config.
///
/// This is the arm that would go red if `blocklist_row_on_disk` resolved
/// against the profile's file instead of the blocklist's: the consented row
/// would look absent, and an absent row is refused as an unknown id.
#[tokio::test]
async fn plp_s4b_a_consented_row_in_another_include_is_found_and_the_write_lands() {
    let fx = spawn_split_fixture().await;

    expect_ok(
        send(
            &fx,
            "kids",
            policy_patch(&[("unsigned-with-ack", ListPolicy::Allow)], &[]),
        )
        .await,
        "a consented allow override, list in another include",
    );

    let lists = split_lists_on_disk(&fx, "kids")
        .expect("the override must land in the file that owns the profile");
    assert_eq!(
        lists.get("unsigned-with-ack").and_then(|v| v.as_str()),
        Some("allow")
    );
    // The override went to the profile's own include, not to the master.
    //
    // Asserted structurally, not with a substring. `contains("lists")` was the
    // first spelling and it is a needle that matches something else: the
    // master's own `includes = ["blocklists.d/*.toml", ...]` line carries
    // "lists" inside "blocklists.d", so the assertion failed on a master that
    // was completely correct.
    let master_doc: toml::Value = read_master(&fx).parse().expect("master must re-parse");
    assert!(
        master_doc.get("profiles").is_none(),
        "master must not have grown a profiles table. master:\n{}",
        read_master(&fx)
    );
}
