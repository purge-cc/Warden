use super::*;
use std::path::PathBuf;

fn mk_master(dir: &tempfile::TempDir) -> PathBuf {
    let master = dir.path().join("config.toml");
    std::fs::write(
        &master,
        r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#,
    )
    .unwrap();
    master
}

fn fake_socket(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("ghost.sock")
}

// ── allow_direction_gates: the shared predicate ──────────────────
//
// The verb-level tests below exercise these rules through a real
// file and a real validator, which is what proves them WIRED. These
// assert the rules themselves, so a second consumer (the TUI) can
// rely on them without re-deriving the truth table from a config
// fixture.

/// Consent is asked for exactly one trust level. `Local` needs none
/// — the operator authored the file. `Signed` is refused outright by
/// `parse_trust` and by the validator, and telling that operator to
/// "declare consent" would be advice that does not work.
#[test]
fn consent_gate_fires_only_on_remote_unsigned() {
    for (trust, want) in [
        (BlocklistTrust::RemoteUnsigned, true),
        (BlocklistTrust::Local, false),
        (BlocklistTrust::Signed, false),
    ] {
        let g = allow_direction_gates(trust, false, false);
        assert_eq!(
            g.needs_consent,
            want,
            "{trust:?} should {}ask for consent",
            if want { "" } else { "not " }
        );
    }
}

/// Either declaration satisfies it — the file's, or this
/// invocation's. A list set up from the CLI and later edited must
/// not be asked again for a risk its own TOML already records.
#[test]
fn either_declaration_satisfies_the_consent_gate() {
    let base = || allow_direction_gates(BlocklistTrust::RemoteUnsigned, false, false);
    assert!(base().needs_consent, "neither declared → ask");

    for (in_file, now) in [(true, false), (false, true), (true, true)] {
        assert!(
            !allow_direction_gates(BlocklistTrust::RemoteUnsigned, in_file, now).needs_consent,
            "in_file={in_file} now={now} should satisfy the gate"
        );
    }
}

/// **This pin outlived the gate on purpose, and the asymmetry is
/// deliberate.** `plp-s5f` removed the cross-file byte-pin on this
/// const from `tests/frozen_strings_entity_contracts.rs`, because a
/// frozen *contract* announces a live promise and this refusal has been
/// unreachable since the plp cutover (`needs_non_system_tag: false`).
///
/// The const itself is kept as record — the argument a future reader
/// needs before restoring the gate — and a record is worth exactly its
/// wording, so the wording keeps a pin. What changed is which claim the
/// pin makes: not "five surfaces say this today" but "this is what
/// warden said, verbatim, and it must not drift while nobody is
/// reading it".
///
/// Original note: the refusal an operator reads is the whole product of
/// this gate; three verbs and both TUI paths routed through it, so a
/// reword in one place must not silently become five different answers.
#[test]
fn tmc_allow_list_cannot_use_system_tag_const_pinned() {
    assert_eq!(
        ALLOW_LIST_CANNOT_USE_SYSTEM_TAG,
        "an allow-list cannot use the \"uncategorized\" tag: every device warden has not been told about carries it by default, so this would permit the list's domains for every unconfigured device on the network — the widest exposure available, reached through the rule that exists to narrow it. Choose a tag that names who the exemption is for."
    );
}

#[tokio::test]
async fn add_blocklist_valid_url() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    run_add(
        &master,
        &sock,
        "privacy-ads",
        Some("Privacy: ads"),
        "https://lists.purge.cc/privacy/ads.txt",
        Some("domains"),
        None,
        None,
        None,
        None,
        &[],
        true,
        None,
    )
    .await
    .unwrap();
    let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
    assert_eq!(loaded.config.blocklists.len(), 1);
}

// ── the id gate is what makes the whole-row write safe ──────────
//
// `upsert_id_keyed` REPLACES the row it matches (`*item = entry`),
// and both writers here hand it a table built from scratch. That is
// only safe while neither can reach an id that already exists — so
// the refusal is not a nicety about duplicate ids, it is the reason
// no field can be silently reset to its serde default. Losing it
// turns either verb into a partial update that keeps exactly the
// keys the caller happened to pass.

/// The URL is deliberately different on the second call: the
/// canonical-URL gate sits next to the id gate and would refuse
/// first, which would leave the id gate untested.
#[tokio::test]
async fn add_refuses_a_taken_id_and_leaves_the_row_intact() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    run_add(
        &master,
        &sock,
        "privacy-ads",
        Some("Privacy: ads"),
        "https://lists.purge.cc/ads.txt",
        Some("domains"),
        Some(6),
        Some(1_234_567),
        None,
        None,
        &[],
        true,
        None,
    )
    .await
    .expect("the first add creates the row");

    let err = add_list_result(&master, &sock, "privacy-ads", "https://other.example/x.txt")
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("already exists"),
        "expected the id refusal, got: {err}",
    );

    let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
    assert_eq!(loaded.config.blocklists.len(), 1);
    let b = &loaded.config.blocklists[0];
    // The second call passed none of these. Had the write gone
    // through, the row would carry the defaults instead.
    assert_eq!(b.url, "https://lists.purge.cc/ads.txt");
    assert_eq!(b.display_name, "Privacy: ads");
    assert_eq!(b.update_interval_hours, 6);
    assert_eq!(b.max_entries, 1_234_567);
}

/// The same gate on the other whole-row writer.
#[tokio::test]
async fn import_local_refuses_a_taken_id_and_leaves_the_row_intact() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    let src = dir.path().join("seed.txt");
    std::fs::write(&src, "bad.example\n").unwrap();
    run_import_local(&master, &sock, &src, "mycompany", "deny", None, None)
        .await
        .expect("the first import creates the row");
    let before = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
    let before = before.config.blocklists[0].clone();

    let other = dir.path().join("other.txt");
    std::fs::write(&other, "worse.example\n").unwrap();
    let err = run_import_local(&master, &sock, &other, "mycompany", "allow", None, None)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("already exists"),
        "expected the id refusal, got: {err}",
    );

    let after = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
    assert_eq!(after.config.blocklists.len(), 1);
    let after = &after.config.blocklists[0];
    assert_eq!(after.url, before.url);
    assert_eq!(
        after.base, before.base,
        "a refused import must not flip the direction"
    );
    assert_eq!(after.trust, before.trust);
}

// ── tag_model_consolidation §3.2 — the add / set-url dedup gates ──

/// D3 exactly as it happened on the live box: `privacy-ads` and
/// `ads` both point at `lists.purge.cc/ads.txt`. The byte-exact gate
/// this replaces let the second one in whenever the two spellings
/// differed cosmetically.
#[tokio::test]
async fn tmc_add_refuses_a_canonically_duplicate_url() {
    for twin in [
        "https://lists.purge.cc/ads.txt/", // trailing slash
        "https://Lists.Purge.CC/ads.txt",  // host case
        "https://lists.purge.cc:443/ads.txt", // default port
                                           // An upper-case SCHEME is deliberately absent: the
                                           // url-shape gate above the dedup gate is a
                                           // case-sensitive `starts_with("https://")`, so
                                           // `HTTPS://…` is refused as a malformed URL before
                                           // dedup ever runs — and the validator applies the
                                           // same check, so no config can contain one either.
                                           // `canonical_url_key` still lowercases the scheme
                                           // (RFC 3986 says it is case-insensitive); that arm
                                           // is exercised by its own unit tests, not here.
    ] {
        let dir = tempfile::tempdir().unwrap();
        let master = mk_master(&dir);
        let sock = fake_socket(&dir);
        add_list(
            &master,
            &sock,
            "privacy-ads",
            "https://lists.purge.cc/ads.txt",
        )
        .await;

        let err = add_list_result(&master, &sock, "ads", twin)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("privacy-ads"),
            "the refusal must name the list that already owns the URL, got: {err}",
        );
        let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
        assert_eq!(
            loaded.config.blocklists.len(),
            1,
            "{twin} must not have been added",
        );
    }
}

/// Pins the reasoning behind the omitted case above: an upper-case
/// scheme never reaches the dedup gate because the url-shape check
/// refuses it first. If that check is ever made case-insensitive,
/// this test fails and the dedup case becomes reachable.
#[tokio::test]
async fn tmc_add_refuses_an_uppercase_scheme_before_reaching_dedup() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    let err = add_list_result(&master, &sock, "ads", "HTTPS://lists.purge.cc/ads.txt")
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("must start with http://"),
        "expected the url-shape refusal, got: {err}",
    );
}

/// The gate must not become "refuse anything similar" — a different
/// path on the same host is a different source.
#[tokio::test]
async fn tmc_add_still_accepts_a_genuinely_different_url() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    add_list(&master, &sock, "ads", "https://lists.purge.cc/ads.txt").await;
    add_list(
        &master,
        &sock,
        "tracking",
        "https://lists.purge.cc/tracking.txt",
    )
    .await;
    let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
    assert_eq!(loaded.config.blocklists.len(), 2);
}

/// `set url` is the third door onto the same collision: pointing an
/// existing list at a cosmetic variant of another list's URL would
/// manufacture the shared cache file `add` refuses.
#[tokio::test]
async fn tmc_set_url_refuses_a_canonical_duplicate_of_another_list() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    add_list(&master, &sock, "ads", "https://lists.purge.cc/ads.txt").await;
    add_list(
        &master,
        &sock,
        "tracking",
        "https://lists.purge.cc/tracking.txt",
    )
    .await;

    let err = run_set(
        &master,
        &sock,
        "tracking",
        "url",
        "https://lists.purge.cc/ads.txt/",
        None,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("ads"), "{err}");

    // Re-pointing a list at its OWN url (cosmetic variant) is not a
    // duplicate — it must still be allowed.
    run_set(
        &master,
        &sock,
        "tracking",
        "url",
        "https://lists.purge.cc/tracking.txt/",
        None,
    )
    .await
    .expect("a list may be re-pointed at its own source");
}

async fn add_list(master: &Path, sock: &Path, id: &str, url: &str) {
    add_list_result(master, sock, id, url)
        .await
        .unwrap_or_else(|e| panic!("adding {id} should succeed: {e}"));
}

async fn add_list_result(master: &Path, sock: &Path, id: &str, url: &str) -> anyhow::Result<()> {
    run_add(
        master,
        sock,
        id,
        None,
        url,
        None,
        None,
        None,
        None,
        None,
        &[],
        true, // skip the HEAD probe — these URLs are not reachable from a test
        None,
    )
    .await
}

#[tokio::test]
async fn add_blocklist_rejects_bad_url() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    let err = run_add(
        &master,
        &sock,
        "x",
        None,
        "not-a-url",
        None,
        None,
        None,
        None,
        None,
        &[],
        true,
        None,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("http"));
}

// ── Sprint C T5 of `lists_categories_v2`: --tag + --skip-head-check ──

/// T5: dedup gate refuses a second list with the same URL even
/// when the operator picks a fresh id. Surface message names the
/// existing id so the operator knows which entry already covers it.
#[tokio::test]
async fn lc2_c_t5_add_refuses_duplicate_url_naming_existing_id() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    let url = "https://example.com/dedup.txt";
    run_add(
        &master,
        &sock,
        "first",
        None,
        url,
        None,
        None,
        None,
        None,
        None,
        &[],
        true,
        None,
    )
    .await
    .unwrap();
    let err = run_add(
        &master,
        &sock,
        "second",
        None,
        url,
        None,
        None,
        None,
        None,
        None,
        &[],
        true,
        None,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("already added as \"first\""));
}

/// T5: empty tags = unwritten field. The validator's auto-promote
/// pass takes over at reload time and pins `base = deny` to
/// `["uncategorized"]` (D2 keeps `base = allow` empty). Here we
/// confirm the pre-validator on-disk shape: no `tags = [...]` line
/// in any of the TOML files under the master's parent dir.
#[tokio::test]
async fn lc2_c_t5_add_with_no_tags_does_not_emit_tags_array() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    run_add(
        &master,
        &sock,
        "no-tags",
        None,
        "https://example.com/no-tags.txt",
        None,
        None,
        None,
        None,
        None,
        &[],
        true,
        None,
    )
    .await
    .unwrap();
    // Walk every TOML under the dir tree; locate the entry's
    // segment (regardless of whether it landed in master or in a
    // sharded `blocklists.d/*.toml` file) and confirm no explicit
    // `tags` array is written.
    fn read_all_toml(root: &std::path::Path, out: &mut Vec<String>) {
        if let Ok(rd) = std::fs::read_dir(root) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    read_all_toml(&p, out);
                } else if p.extension().and_then(|s| s.to_str()) == Some("toml") {
                    if let Ok(s) = std::fs::read_to_string(&p) {
                        out.push(s);
                    }
                }
            }
        }
    }
    let mut all_toml: Vec<String> = Vec::new();
    read_all_toml(master.parent().unwrap(), &mut all_toml);
    let segment = all_toml
        .iter()
        .flat_map(|raw| raw.split("[[blocklists]]"))
        .find(|seg| seg.contains("\"no-tags\""))
        .map(|s| s.to_string())
        .expect("new entry must exist on disk somewhere");
    assert!(
        !segment.contains("tags = ["),
        "did not expect tags array in raw TOML, got:\n{segment}"
    );
}

#[tokio::test]
async fn add_blocklist_rejects_bad_format() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    let err = run_add(
        &master,
        &sock,
        "x",
        None,
        "https://example.com/x.txt",
        Some("bogus"),
        None,
        None,
        None,
        None,
        &[],
        true,
        None,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("unknown format"));
}

// Sprint B T2 (rewireato — drop with justification): the pre-v2
// `remove_blocklist_referenced_by_profile_fails_with_rule_dangling_ref`
// test pinned the SN3 dangling-ref refusal when removing a blocklist
// referenced by `profile.blocklists`. That field is gone in v2 — a
// blocklist's lifecycle is now decoupled from any profile (lists are
// tagged, profiles inherit tags). Sprint C reintroduces an equivalent
// operator-facing check for the new mutation surface
// (`warden blocklist tag remove <id> <tag>` may want to refuse if it
// would leave a profile with no effective tags), but that lives on
// the new tag-mutation CLI, not the legacy `blocklists remove` path.
// The companion `remove_blocklist_without_refs_succeeds_without_cascade`
// test below preserves the no-references happy path.
//
// Sprint B T2 (rewireato — drop with justification): the pre-v2
// `remove_blocklist_with_cascade_removes_id_from_every_profile_then_drops_blocklist`
// test pinned the cascade behaviour for the same `profile.blocklists`
// field. Same rationale — `profile.blocklists` no longer exists, so
// there is nothing to cascade. Sprint C's tag-removal CLI will
// introduce its own cascade semantics if needed.

#[tokio::test]
async fn remove_blocklist_without_refs_succeeds_without_cascade() {
    // Belt-and-braces: the no-references path still works (cascade
    // = false) so we don't regress the post-S33 baseline behaviour.
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    run_add(
        &master,
        &sock,
        "privacy-ads",
        None,
        "https://example.com/x.txt",
        None,
        None,
        None,
        None,
        None,
        &[],
        true,
        None,
    )
    .await
    .unwrap();
    run_remove(&master, &sock, "privacy-ads", None)
        .await
        .unwrap();
    let loaded =
        crate::config::loader::load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
    assert!(loaded.config.blocklists.is_empty());
}

#[tokio::test]
async fn remove_absent_blocklist_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    // verbs-02: remove of an absent blocklist returns Ok (exit 0) via the
    // CLI wrapper's pre-check; run_remove_silent keeps its hard-error
    // contract for the TUI seat.
    assert!(run_remove(&master, &sock, "ghost", None).await.is_ok());
}

#[tokio::test]
async fn set_enabled_field() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    run_add(
        &master,
        &sock,
        "privacy-ads",
        None,
        "https://example.com/x.txt",
        None,
        None,
        None,
        Some(true),
        None,
        &[],
        true,
        None,
    )
    .await
    .unwrap();
    run_set(&master, &sock, "privacy-ads", "enabled", "false", None)
        .await
        .unwrap();
    let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
    assert!(!loaded.config.blocklists[0].enabled);
}

#[tokio::test]
async fn set_format_roundtrips() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    run_add(
        &master,
        &sock,
        "privacy-ads",
        None,
        "https://example.com/x.txt",
        Some("domains"),
        None,
        None,
        None,
        None,
        &[],
        true,
        None,
    )
    .await
    .unwrap();
    run_set(&master, &sock, "privacy-ads", "format", "adguard", None)
        .await
        .unwrap();
    let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
    assert_eq!(loaded.config.blocklists[0].format, BlocklistFormat::Adguard);
}

// ── Sprint 36 HR2: hot-reload wiring ───────────────────────────────

// ── S50 T3: per-list mutation verbs ────────────────────────────────

// BLOCKLIST_SET_CATEGORY_OK pinned test removed — Sprint A of
// `lists_categories_v2` (Q2-A) deleted the const along with the
// Category entity. Sprint C reintroduces equivalent for tags.

#[test]
fn s50_t3_blocklist_set_kind_const_pinned() {
    assert_eq!(
        BLOCKLIST_SET_KIND_OK,
        "Blocklist '{id}' kind set to {kind}."
    );
}

#[test]
fn s50_t3_blocklist_set_trust_const_pinned_decision_outside_doc() {
    // §9 of the design doc does not explicitly list
    // BLOCKLIST_SET_TRUST_OK; the orchestrator kickoff flagged
    // the ambiguity. T3 chose the sibling-coining path documented
    // on the const itself (audit `action` tag stays distinct).
    assert_eq!(
        BLOCKLIST_SET_TRUST_OK,
        "Blocklist '{id}' trust set to {trust}."
    );
}

/// The refusal an operator hits when they try to flip a list's
/// direction through the generic field setter. Frozen because it is
/// the only place warden gets to say "the verb you want exists" —
/// before this, the message listed the settable fields, `kind` was
/// not among them, and the honest reading was "warden cannot do
/// this".
#[test]
fn cli_surface_blocklist_set_unknown_field_const_pinned() {
    assert_eq!(
        BLOCKLIST_SET_UNKNOWN_FIELD,
        "unknown field: {field}. Valid: display_name, url, format, \
         update_interval_hours, max_entries, enabled, auth_token_ref. Direction and \
         provenance are not set here — use: warden blocklist set-kind <id> \
         <deny|allow> / warden blocklist set-trust <id> <local|remote-unsigned>. Both \
         accept --accept-unsigned-allow, which declares consent for a remote \
         allow-list."
    );
}

#[test]
fn cli_surface_format_set_unknown_field_substitutes_field() {
    let s = format_blocklist_set_unknown_field("kind");
    assert!(s.starts_with("unknown field: kind."), "{s}");
    assert!(!s.contains("{field}"), "{s}");
}

/// The emitter, not just the const: `blocklist set <id> kind allow`
/// must reach the operator with the two dedicated verbs named.
#[test]
fn cli_surface_set_kind_through_generic_setter_names_the_dedicated_verbs() {
    let mut entry = Value::Table(toml::map::Map::new());
    let dir = tempfile::tempdir().unwrap();
    let err = apply_blocklist_field(&mut entry, "kind", "allow", &dir.path().join("config.toml"))
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("warden blocklist set-kind"), "{msg}");
    assert!(msg.contains("warden blocklist set-trust"), "{msg}");
    assert!(msg.contains("--accept-unsigned-allow"), "{msg}");
}

#[test]
fn s50_t3_blocklist_import_local_const_pinned() {
    // Sprint A of lists_categories_v2 (Q2-A): the `{cat}` slot is
    // gone. Sprint C extends with `{tags}` once the picker lands.
    assert_eq!(
        BLOCKLIST_IMPORT_LOCAL_OK,
        "Imported '{path}' as blocklist '{id}' (kind={kind}, {n} entries)."
    );
}

// s50_t3_format_set_category_substitutes_id_and_cat removed:
// BLOCKLIST_SET_CATEGORY_OK + format_blocklist_set_category_ok
// deleted by Sprint A of lists_categories_v2 (Q2-A).

#[test]
fn s50_t3_format_set_kind_substitutes_id_and_kind() {
    let s = format_blocklist_set_kind_ok("priv-ads", "allow");
    assert_eq!(s, "Blocklist 'priv-ads' kind set to allow.");
}

#[test]
fn s50_t3_format_set_trust_substitutes_id_and_trust() {
    let s = format_blocklist_set_trust_ok("priv-ads", "local");
    assert_eq!(s, "Blocklist 'priv-ads' trust set to local.");
}

#[test]
fn s50_t3_format_import_local_substitutes_all_fields() {
    let s = format_blocklist_import_local_ok("/tmp/whitelist.txt", "mycompany", "allow", 12);
    assert!(s.contains("'/tmp/whitelist.txt'"), "got: {s}");
    assert!(s.contains("'mycompany'"), "got: {s}");
    assert!(s.contains("kind=allow"), "got: {s}");
    assert!(s.contains("12 entries"), "got: {s}");
}

#[test]
fn s50_t3_parse_kind_accepts_deny_and_allow_only() {
    // Sprint A of lists_categories_v2 (Q3): wire format renamed
    // `block` → `deny`. D15 abolishes v1 alias.
    assert_eq!(parse_kind("deny").unwrap(), BlocklistBase::Deny);
    assert_eq!(parse_kind("allow").unwrap(), BlocklistBase::Allow);
    assert!(parse_kind("forward").is_err());
}

#[test]
fn s50_t3_parse_trust_refuses_signed_with_helpful_hint() {
    assert_eq!(parse_trust("local").unwrap(), BlocklistTrust::Local);
    assert_eq!(
        parse_trust("remote-unsigned").unwrap(),
        BlocklistTrust::RemoteUnsigned
    );
    let err = parse_trust("signed").unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("signed"), "got: {msg}");
    assert!(
        msg.contains("local") || msg.contains("remote-unsigned"),
        "got: {msg}"
    );
}

#[test]
fn s50_t3_autodetect_format_picks_adguard_for_pipe_pipe_lines() {
    assert_eq!(
        autodetect_format("||ads.example.com^\n||trk.example.com^\n"),
        BlocklistFormat::Adguard
    );
}

#[test]
fn s50_t3_autodetect_format_picks_hosts_for_zero_zero_zero_zero_lines() {
    assert_eq!(
        autodetect_format("0.0.0.0 ads.example\n0.0.0.0 trk.example\n"),
        BlocklistFormat::Hosts
    );
}

#[test]
fn s50_t3_autodetect_format_defaults_to_domains() {
    assert_eq!(
        autodetect_format("good.example\nmycompany.example\n"),
        BlocklistFormat::Domains
    );
}

#[test]
fn s50_t3_count_entries_skips_blank_and_comment_lines() {
    let raw = "# header\n\nfoo\nbar\n# trailer\n";
    assert_eq!(count_entries(raw, BlocklistFormat::Domains), 2);
}

// `s50_t3_set_category_writes_field_and_loads_back` deleted in
// `tag_model_consolidation` §3.4: its `#[ignore]` reason said
// "Sprint C reintroduces the equivalent", and Sprint C shipped it —
// `warden blocklist tag add|remove`, covered by the
// `lc2_c_t7_grp2_tag_*` tests below. An ignored test whose reason
// has expired is a permanently-skipped test nobody will delete
// later.

// ── cli-surface: flipping direction on an existing list ───────────

/// Helper: a remote-unsigned deny-list carrying one tag, created the
/// way an operator would. The tag matters — without it the
/// untagged-allow gate fires first and masks whatever the test is
/// actually about.
async fn add_tagged_remote_deny(master: &std::path::Path, sock: &std::path::Path, id: &str) {
    run_add(
        master,
        sock,
        id,
        None,
        &format!("https://example.com/{id}.txt"),
        None,
        None,
        None,
        None,
        None,
        &[],
        true,
        None,
    )
    .await
    .unwrap();
}

/// Assert `--accept-unsigned-allow` exists on `blocklist <verb>`
/// with the frozen spelling and the frozen action. The names are
/// CONTRACT §3, so a rename here breaks other surfaces, not just
/// this one.
fn assert_verb_carries_ack_flag(verb: &str) {
    use clap::CommandFactory;
    let cmd = crate::cli::Cli::command();
    let sub = cmd
        .find_subcommand("blocklist")
        .expect("`warden blocklist` must exist")
        .clone()
        .find_subcommand(verb)
        .unwrap_or_else(|| panic!("`warden blocklist {verb}` must exist"))
        .clone();
    let ack = sub
        .get_arguments()
        .find(|a| a.get_id() == "accept_unsigned_allow")
        .unwrap_or_else(|| panic!("{verb} must offer --accept-unsigned-allow"));
    assert_eq!(ack.get_long(), Some("accept-unsigned-allow"));
    assert!(matches!(ack.get_action(), clap::ArgAction::SetTrue));
}

#[test]
fn cli_surface_set_kind_carries_the_ack_flag() {
    assert_verb_carries_ack_flag("set-kind");
}

// ── cli-surface: the read surface (DoD 6) ─────────────────────────

/// Built from TOML rather than a struct literal: `Blocklist` gains
/// fields, and a literal here would have to be repaired by every
/// unrelated schema change. Deserialising also exercises the same
/// defaults an operator's file gets.
fn bl(kind: &str, trust: &str, ack: bool) -> crate::config::schema::Blocklist {
    toml::from_str(&format!(
        r#"
id = "svc"
display_name = "Service"
url = "https://example.com/svc.txt"
base = "{kind}"
trust = "{trust}"
accept_unsigned_allow = {ack}
"#
    ))
    .expect("fixture must deserialise")
}

#[test]
fn cli_surface_show_always_states_the_consent() {
    for (kind, trust, ack) in [
        ("deny", "remote-unsigned", false),
        ("allow", "local", false),
        ("allow", "remote-unsigned", true),
    ] {
        let lines = format_show_consent(&bl(kind, trust, ack));
        assert_eq!(
            lines[0],
            format!("accept_unsigned_allow:  {ack}"),
            "{kind}/{trust}/{ack}"
        );
    }
}

/// `true` on a list where the field decides who may unblock domains
/// must not read like `true` on a list where it does nothing.
#[test]
fn cli_surface_show_distinguishes_a_load_bearing_consent_from_an_inert_one() {
    let load_bearing = format_show_consent(&bl("allow", "remote-unsigned", true));
    assert_eq!(load_bearing.len(), 2);
    assert!(load_bearing[1].contains("load-bearing"), "{load_bearing:?}");

    let inert = format_show_consent(&bl("deny", "remote-unsigned", true));
    assert_eq!(inert.len(), 2);
    assert!(inert[1].contains("no effect on this list"), "{inert:?}");

    // Nothing declared, nothing to explain.
    assert_eq!(format_show_consent(&bl("allow", "local", false)).len(), 1);
}

/// DoD 6, the table half: without `kind` on the row, a deny-list and
/// an allow-list render identically and the operator has to run
/// `show` once per list to find out which is which.
#[test]
fn cli_surface_list_row_shows_the_direction() {
    assert!(
        format_list_row(&bl("allow", "remote-unsigned", true)).contains("kind=allow"),
        "{}",
        format_list_row(&bl("allow", "remote-unsigned", true))
    );
    assert!(
        format_list_row(&bl("deny", "remote-unsigned", false)).contains("kind=deny"),
        "{}",
        format_list_row(&bl("deny", "remote-unsigned", false))
    );
}

#[test]
fn cli_surface_set_trust_carries_the_ack_flag() {
    assert_verb_carries_ack_flag("set-trust");
}

/// Helper: a local, tagged **allow**-list — the shape an operator
/// gets from `blocklist import-local --kind allow`, and the starting
/// point of the transition that DoD 5 is about.
async fn add_local_tagged_allow(master: &std::path::Path, sock: &std::path::Path, id: &str) {
    let src = master.parent().unwrap().join(format!("{id}-seed.txt"));
    std::fs::write(&src, "permitted.example\n").unwrap();
    run_import_local(master, sock, &src, id, "allow", None, None)
        .await
        .unwrap();
}

/// DoD 5 — the transition everybody forgets. `set-trust` changes no
/// `kind`, so it looks like it has nothing to do with allow-lists.
/// But taking an allow-list from `local` to `remote-unsigned` is
/// exactly the moment a file the operator wrote becomes a
/// subscription somebody else edits — and without this gate the
/// command is accepted, the config is written, and the NEXT reload
/// refuses it. The operator is then looking at a daemon that will
/// not start because of a command warden told them had worked.
#[tokio::test]
async fn cli_surface_set_trust_remote_on_an_allow_list_without_ack_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    add_local_tagged_allow(&master, &sock, "svc-b").await;
    let err = run_set_trust(&master, &sock, "svc-b", "remote-unsigned", false, None)
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains(ACCEPT_UNSIGNED_ALLOW_FLAG_HINT),
        "must name the flag that unblocks it, got:\n{msg}"
    );
    assert!(
        !msg.contains("nothing written"),
        "pre-flight, not a post-write revert:\n{msg}"
    );
    // And the list is untouched — still local, still loading.
    let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
    assert_eq!(loaded.config.blocklists[0].trust, BlocklistTrust::Local);
}

/// DoD 5, happy path: same transition, consent declared, and the
/// config that lands still loads.
#[tokio::test]
async fn cli_surface_set_trust_remote_on_an_allow_list_with_ack_persists() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    add_local_tagged_allow(&master, &sock, "svc-b").await;
    run_set_trust(&master, &sock, "svc-b", "remote-unsigned", true, None)
        .await
        .unwrap();
    let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
    let b = &loaded.config.blocklists[0];
    assert_eq!(b.trust, BlocklistTrust::RemoteUnsigned);
    assert_eq!(b.base, BlocklistBase::Allow);
    assert!(b.accept_unsigned_allow);
}

/// The gate must not spread. A deny-list going remote carries no
/// unblocking power and is the ordinary case for every list warden
/// ships — demanding consent there would be a new refusal on a path
/// that never needed one.
#[tokio::test]
async fn cli_surface_set_trust_remote_on_a_deny_list_needs_no_ack() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    let src = dir.path().join("seed.txt");
    std::fs::write(&src, "bad.example\n").unwrap();
    run_import_local(&master, &sock, &src, "svc-a", "deny", None, None)
        .await
        .unwrap();
    run_set_trust(&master, &sock, "svc-a", "remote-unsigned", false, None)
        .await
        .expect("a deny-list may go remote with nothing to declare");
}

/// DoD 4, one direction: an existing remote list becomes an
/// allow-list, consent declared on the same command line, and the
/// consent is persisted so the next reload does not refuse it.
#[tokio::test]
async fn cli_surface_set_kind_allow_with_ack_persists_the_consent() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    add_tagged_remote_deny(&master, &sock, "svc-b").await;
    run_set_kind_with_ack(&master, &sock, "svc-b", "allow", true, None)
        .await
        .unwrap();
    let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
    let b = &loaded.config.blocklists[0];
    assert_eq!(b.base, BlocklistBase::Allow);
    assert!(
        b.accept_unsigned_allow,
        "the flag must land in the file, or the next reload refuses the config \
         the CLI just accepted"
    );
}

/// DoD 4, the other direction: back to deny, and the flip is not
/// blocked by anything the allow side needed.
#[tokio::test]
async fn cli_surface_set_kind_flips_back_to_deny() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    add_tagged_remote_deny(&master, &sock, "svc-b").await;
    run_set_kind_with_ack(&master, &sock, "svc-b", "allow", true, None)
        .await
        .unwrap();
    run_set_kind(&master, &sock, "svc-b", "deny", None)
        .await
        .unwrap();
    let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
    assert_eq!(loaded.config.blocklists[0].base, BlocklistBase::Deny);
}

/// Consent already recorded on the list = no need to re-declare it
/// on every later flip. Otherwise `set-kind deny` then `set-kind
/// allow` would demand the flag a second time for a risk the
/// operator's own file already carries.
#[tokio::test]
async fn cli_surface_set_kind_allow_needs_no_flag_when_the_file_already_consents() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    add_tagged_remote_deny(&master, &sock, "svc-b").await;
    run_set_kind_with_ack(&master, &sock, "svc-b", "allow", true, None)
        .await
        .unwrap();
    run_set_kind(&master, &sock, "svc-b", "deny", None)
        .await
        .unwrap();
    run_set_kind(&master, &sock, "svc-b", "allow", None)
        .await
        .expect("consent is already on the list");
}

/// Brief point 4: the untagged-allow bail used to be gated on
/// `trust == local`, so on a remote list it never ran and the write
/// went through to a validator rollback. Now that remote allow-lists
/// are the normal case, that branch is the main road — and an
/// untagged one would land mute.
#[tokio::test]
async fn cli_surface_untagged_allow_on_remote_trust_needs_only_consent_now() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    run_add(
        &master,
        &sock,
        "svc-b",
        None,
        "https://example.com/svc-b.txt",
        None,
        None,
        None,
        None,
        None,
        &[],
        true,
        None,
    )
    .await
    .unwrap();
    // WITHOUT consent: still refused, and by the consent gate. The
    // consent gate did not move — whoever controls a remote URL adds
    // domains at every refresh, which is a third-party risk rather than
    // an operator declaration.
    let err = run_set_kind(&master, &sock, "svc-b", "allow", None)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("accept_unsigned_allow"),
        "the surviving refusal must be the CONSENT one, got: {err}"
    );
    assert!(
        !err.to_string().contains("--tag"),
        "the tag gate is retired and must not be the reason: {err}"
    );
    // WITH consent: accepted, untagged and all.
    run_set_kind_with_ack(&master, &sock, "svc-b", "allow", true, None)
        .await
        .expect("consent declared, and the tag gate is retired");
}

#[tokio::test]
async fn s50_t3_set_kind_to_allow_with_remote_unsigned_is_rejected_and_reverts() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    run_add(
        &master,
        &sock,
        "x",
        None,
        "https://example.com/x.txt",
        None,
        None,
        None,
        None,
        None,
        &[],
        true,
        None,
    )
    .await
    .unwrap();
    let err = run_set_kind(&master, &sock, "x", "allow", None)
        .await
        .unwrap_err();
    assert!(err.to_string().to_ascii_lowercase().contains("trust"));
    // Loader must read back the original kind=block — the file
    // was reverted by validate_or_revert.
    let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
    assert_eq!(loaded.config.blocklists[0].base, BlocklistBase::Deny);
}

#[tokio::test]
async fn s50_t3_set_trust_local_then_set_kind_allow_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    run_add(
        &master,
        &sock,
        "trusted",
        None,
        "https://example.com/x.txt",
        None,
        None,
        None,
        None,
        None,
        // Retired `_tags` argument — see `run_add`'s doc comment.
        //
        // The comment that stood here said the flip to `allow`
        // "requires the list to carry a tag in the file", from
        // `tag_model_consolidation` §3.3. That premise died at the
        // `plp-s3` cutover: `allow_direction_gates` has answered
        // `needs_tag = false` ever since, and `plp-s5c` removed
        // `--tag` outright, so there is no longer any way for this
        // setup to satisfy the rule it described. The property under
        // test — local trust makes `allow` legal — is untouched, and
        // is now tested without the tag it never actually needed.
        &[],
        true,
        None,
    )
    .await
    .unwrap();
    run_set_trust(&master, &sock, "trusted", "local", false, None)
        .await
        .unwrap();
    run_set_kind(&master, &sock, "trusted", "allow", None)
        .await
        .unwrap();
    let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
    assert_eq!(loaded.config.blocklists[0].trust, BlocklistTrust::Local);
    assert_eq!(loaded.config.blocklists[0].base, BlocklistBase::Allow);
}

/// The flip stays legal for a tagged list — the gate must refuse
/// only the inert case, not `allow` in general.
#[tokio::test]
async fn tmc_set_kind_allow_is_allowed_when_the_list_carries_a_tag() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    let src = dir.path().join("seed.txt");
    std::fs::write(&src, "good.example\n").unwrap();
    run_import_local(&master, &sock, &src, "x", "deny", None, None)
        .await
        .unwrap();
    run_set_kind(&master, &sock, "x", "allow", None)
        .await
        .expect("a tagged list may become an allow-list");
    let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
    assert_eq!(loaded.config.blocklists[0].base, BlocklistBase::Allow);
}

#[tokio::test]
async fn s50_t3_set_trust_signed_refused_with_parking_hint() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    run_add(
        &master,
        &sock,
        "x",
        None,
        "https://example.com/x.txt",
        None,
        None,
        None,
        None,
        None,
        &[],
        true,
        None,
    )
    .await
    .unwrap();
    let err = run_set_trust(&master, &sock, "x", "signed", false, None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("signed"));
}

#[tokio::test]
async fn s50_t3_import_local_copies_file_and_registers_blocklist() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    let src = dir.path().join("seed.txt");
    std::fs::write(&src, "good.example\nmycompany.example\n").unwrap();
    // `tag_model_consolidation` §3.3: an allow-list must be tagged,
    // otherwise it installs and filters nothing.
    run_import_local(&master, &sock, &src, "mycompany", "allow", None, None)
        .await
        .unwrap();
    let dest = master.parent().unwrap().join("lists").join("mycompany.txt");
    assert!(dest.exists());
    let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
    let imported = loaded
        .config
        .blocklists
        .iter()
        .find(|b| b.id.as_str() == "mycompany")
        .unwrap();
    assert_eq!(imported.base, BlocklistBase::Allow);
    assert_eq!(imported.trust, BlocklistTrust::Local);
    // The `--tag` assertion that stood here left with the flag in
    // `plp-s5c`. What it guaranteed — that an operator-supplied tag
    // reaches the file — has no operator-supplied tag to guarantee
    // any more. The rest of this test is untouched and is the part
    // that was ever about `import-local`: the file is copied into the
    // managed directory and the entry lands with the direction and
    // trust the verb promises.
}

#[tokio::test]
async fn s50_t3_import_local_refuses_missing_source() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    let ghost = dir.path().join("does-not-exist.txt");
    let err = run_import_local(&master, &sock, &ghost, "x", "deny", None, None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("does not exist"));
}

// ── tag_model_consolidation §3.3 — close the inert-allow-list door

/// INVERTED by `plp-s4` F18. This test used to assert that an untagged
/// allow import is refused, and it was correct while tag intersection
/// decided which lists reached which clients: an untagged allow-list
/// permitted nothing, so refusing it saved the operator from installing
/// an inert list.
///
/// `plp-s3` retired that premise inside `allow_direction_gates` — a
/// list's direction now reaches every profile that does not override it,
/// tagged or not — but this verb kept a private copy of the check and
/// went on refusing. Three verbs accepted what the fourth rejected, and
/// the `--tag` its message prescribed is refused by `warden blocklist
/// tag`, retired in the same sprint. The operator's only route to an
/// allow-list whose file they own was closed by a refusal that could not
/// be satisfied in its own terms.
///
/// The assertion now runs the other way. Left INVERTED rather than
/// deleted because a deleted test proves nothing about the direction the
/// behaviour moved in, and this one moved in the direction that a future
/// reader would most plausibly "fix" back.
#[tokio::test]
async fn plp_import_local_accepts_an_untagged_allow_list() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    let src = dir.path().join("seed.txt");
    std::fs::write(&src, "good.example\n").unwrap();
    run_import_local(&master, &sock, &src, "mycompany", "allow", None, None)
        .await
        .expect("an untagged allow-list is legal since the tag gates were retired");
    assert!(
        master
            .parent()
            .unwrap()
            .join("lists")
            .join("mycompany.txt")
            .exists(),
        "an accepted import must copy the file into the managed directory"
    );
    let written = std::fs::read_to_string(&master).unwrap();
    assert!(
        written.contains("base = \"allow\""),
        "the row must record the direction the operator asked for:\n{written}"
    );
}

/// Deny-lists keep the `uncategorized` auto-promotion, so they need
/// no tag — the asymmetry is deliberate (D2) and must not regress
/// into "every import needs a tag".
#[tokio::test]
async fn tmc_import_local_still_accepts_an_untagged_deny_list() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    let src = dir.path().join("seed.txt");
    std::fs::write(&src, "bad.example\n").unwrap();
    run_import_local(&master, &sock, &src, "ads", "deny", None, None)
        .await
        .expect("a deny-list needs no consent and no tag");
    let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
    let imported = loaded
        .config
        .blocklists
        .iter()
        .find(|b| b.id.as_str() == "ads")
        .expect("the list must have landed");
    // The tag assertion this carried went with the field. What it was
    // ever about on the deny side survives as the direction: routing
    // `import-local` through the shared gate must not have widened
    // anything, and a deny-list still lands unchallenged.
    assert_eq!(imported.base, BlocklistBase::Deny);
}

/// The second door: flipping an untagged list to `allow` strips it
/// of the auto-promotion that was making it work, and it silently
/// stops filtering.
#[tokio::test]
async fn tmc_set_kind_allow_accepts_an_untagged_list_now() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    let src = dir.path().join("seed.txt");
    std::fs::write(&src, "bad.example\n").unwrap();
    // A local-trust list, so the trust gate does not fire first and
    // mask the one under test. It lands with NO `tags` key in the
    // file — `uncategorized` is applied at load, not persisted,
    // which is exactly why the gate reads the file.
    run_import_local(&master, &sock, &src, "x", "deny", None, None)
        .await
        .unwrap();
    run_set_kind(&master, &sock, "x", "allow", None)
        .await
        .expect("trust = local needs no consent, and the tag gate is retired");
    let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
    let b = loaded
        .config
        .blocklists
        .iter()
        .find(|b| b.id.as_str() == "x")
        .unwrap();
    assert_eq!(b.base, BlocklistBase::Allow);
}

// ── the third door: `uncategorized` is not an answer to "which tag?"
//
// The gate above asks the operator to name who an allow-list is for.
// These four pin that the sentinel is not an acceptable name at any
// of the four verbs that can write one — including `tag add`, which
// creates nothing and flips no direction and was outside every gate
// until now.

/// The deny side of F18: routing `import-local` through the shared gate
/// must not have widened anything. A deny-list still needs no tag, and
/// still lands.
///
/// Present because the two inverted tests above cannot tell "the gates
/// were routed" from "the two bails were deleted" — with `trust = local`
/// all three arms answer false either way. Neither can this one. The
/// wiring is held structurally instead: the call site destructures
/// `AllowDirectionGates` exhaustively, so a fourth gate breaks the build
/// there rather than being skipped in silence.
#[tokio::test]
async fn plp_import_local_still_accepts_an_untagged_deny_list() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    let src = dir.path().join("seed.txt");
    std::fs::write(&src, "good.example\n").unwrap();
    run_import_local(&master, &sock, &src, "ads2", "deny", None, None)
        .await
        .expect("an untagged deny-list has always been legal");
    let written = std::fs::read_to_string(&master).unwrap();
    assert!(
        written.contains("base = \"deny\""),
        "the row must record the direction the operator asked for:\n{written}"
    );
}

// ── the way back out ──────────────────────────────────────────────
//
// Some configs do not load. Every verb in this file starts by loading,
// so without the degraded path below, an operator whose disk is already
// in a refused state — hand-edited, or restored from an older backup —
// would find that the commands that repair it fail on the error they are
// repairing, leaving hand-editing the TOML as the only exit.
//
// **`plp-s3` had to re-point this fixture, and that is worth reading.**
// The refused state used to be `kind = allow` + `tags =
// ["uncategorized"]`. §2.5 retires that ERROR — the sentinel stopped
// meaning "the widest audience" when tags stopped deciding the audience
// — so the old fixture now loads clean and the deadlock it modelled is
// unreachable through that door. The property is not gone, so the
// fixture moves to a door that is still shut: the **consent** gate,
// which §2.5 leaves exactly where it was.

/// A file in a refused state, written directly. No verb will produce
/// one, which is the point: this is what an operator's disk looks like
/// when they reach for a repair.
///
/// Refused by the consent gate — a remote-unsigned allow-list with no
/// `accept_unsigned_allow`.
fn master_with_a_refused_allow_list(dir: &tempfile::TempDir) -> PathBuf {
    let master = dir.path().join("config.toml");
    std::fs::write(
        &master,
        r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]

[[blocklists]]
id = "guest"
display_name = "Guest exemptions"
url = "https://example.com/guests.txt"
format = "domains"
base = "allow"
trust = "remote-unsigned"
"#,
    )
    .unwrap();
    master
}

#[tokio::test]
async fn tmc_set_kind_deny_repairs_a_config_that_no_longer_loads() {
    let dir = tempfile::tempdir().unwrap();
    let master = master_with_a_refused_allow_list(&dir);
    let sock = fake_socket(&dir);
    // Precondition: the config really is unloadable. Without this the
    // test could pass against a fixture that quietly stopped being
    // refused, and would then prove nothing about the deadlock.
    assert!(
        load_config(&master, time::OffsetDateTime::now_utc()).is_err(),
        "the fixture must be in the refused state"
    );

    run_set_kind(&master, &sock, "guest", "deny", None)
        .await
        .expect("the narrowing direction must work on a config that does not load");

    let loaded = load_config(&master, time::OffsetDateTime::now_utc())
        .expect("the repair must leave a loadable config");
    assert_eq!(loaded.config.blocklists[0].base, BlocklistBase::Deny);
}

/// The leniency is scoped to repairs. Asking for MORE permission
/// while the config is unreadable is refused with the load errors,
/// because a widening mutation computed against a config nobody can
/// load is a mutation against a guess.
#[tokio::test]
async fn tmc_set_kind_allow_still_demands_a_loadable_config() {
    let dir = tempfile::tempdir().unwrap();
    let master = master_with_a_refused_allow_list(&dir);
    let sock = fake_socket(&dir);
    let err = run_set_kind(&master, &sock, "guest", "allow", None)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("cannot load config"),
        "the widening direction must surface the load failure: {err}"
    );
}

// ── cli-surface: `blocklist add` becomes direction-aware ──────────
//
// What used to sit here was `tmc_blocklist_add_has_no_kind_flag_so_it
// _cannot_create_an_allow_list`, a deliberate sentinel: it asserted
// `add` had NO `--kind`, with the note "if --kind is ever added to
// add, this test fails and whoever adds it has to decide about the
// gate". An earlier lane was that whoever, and the decision is the
// tests below — `add` gets `--kind`, and every door it opens is
// gated BEFORE the write.
//
// ── `cli_surface_blocklist_add_keeps_the_tag_flag` was the SECOND
//    sentinel in that pair, and `plp-s5c` is the whoever it was
//    waiting for. It went red on the commit that deleted `--tag`,
//    which is the sentinel working, not a break to patch green.
//
// Its stated reason was: "losing `--tag` would silently re-open the
// inert allow-list hole from a different direction" — an untagged
// allow-list matched no client, so it installed and filtered nothing.
// That premise died at the `plp-s3` cutover: a list's direction now
// reaches every profile that does not override it, tagged or not, so
// an untagged allow-list is not inert. It is the ordinary case.
// `cli_surface_add_allow_without_tags_is_now_accepted` below covers
// exactly that, and inverted the same claim one sprint earlier.
//
// Not replaced with its inverse here, because a stronger version
// already exists: `cli::plp_s5c_tag_surface_tests::
// no_verb_carries_a_tag_flag` walks the WHOLE clap tree rather than
// this one verb, and keys on the argument id rather than the rendered
// help — a `hide = true` flag is invisible in help and still typeable.

/// The flag names are frozen by CONTRACT §3 — other surfaces assert
/// on them, so a rename here is a cross-lane break, not a local one.
#[test]
fn cli_surface_blocklist_add_has_kind_and_ack_flags() {
    use clap::CommandFactory;
    let cmd = crate::cli::Cli::command();
    let add = cmd
        .find_subcommand("blocklist")
        .and_then(|c| c.clone().find_subcommand("add").cloned())
        .expect("`warden blocklist add` must exist");
    let kind = add
        .get_arguments()
        .find(|a| a.get_id() == "kind")
        .expect("`blocklist add` must offer --kind");
    assert_eq!(kind.get_long(), Some("kind"));
    let ack = add
        .get_arguments()
        .find(|a| a.get_id() == "accept_unsigned_allow")
        .expect("`blocklist add` must offer --accept-unsigned-allow");
    assert_eq!(ack.get_long(), Some("accept-unsigned-allow"));
    assert!(
        matches!(ack.get_action(), clap::ArgAction::SetTrue),
        "--accept-unsigned-allow is a declaration, not a value"
    );
}

/// DoD 3: the refusal lands BEFORE the config is written, not as a
/// post-write rollback. A rollback would leave the operator reading
/// an error about a file that (correctly) never changed, and the
/// audit row would claim an attempted mutation the CLI never staged.
#[tokio::test]
async fn cli_surface_add_allow_from_url_without_ack_is_refused_before_write() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    let before = std::fs::read_to_string(&master).unwrap();
    let err = run_add_with_direction(
        &master,
        &sock,
        "svc-b",
        None,
        "https://example.com/service-b.txt",
        Some("domains"),
        None,
        None,
        None,
        None,
        true,
        None,
        AddDirection {
            kind: Some("allow"),
            accept_unsigned_allow: false,
        },
    )
    .await
    .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains(
            &crate::config::schema::validator::format_unsigned_allow_list_requires_ack(
                "svc-b",
                BlocklistTrust::RemoteUnsigned,
            )
        ),
        "must carry the frozen validator string verbatim, got:\n{msg}"
    );
    assert!(
        msg.contains(ACCEPT_UNSIGNED_ALLOW_FLAG_HINT),
        "and the CLI-side hint naming the flag, got:\n{msg}"
    );
    // The needle that separates "refused before the write" from
    // "written, refused, rolled back". Measured, not assumed: with
    // the pre-flight gate disabled the post-write refusal reaches
    // here carrying the same frozen string plus the staged path and
    // the reverter's `nothing written` tail — so the assertion above
    // does not discriminate on its own, and neither does the
    // untouched-config one below.
    assert!(
        !msg.contains("nothing written"),
        "must be a pre-flight refusal, not a post-write revert:\n{msg}"
    );
    assert_eq!(
        std::fs::read_to_string(&master).unwrap(),
        before,
        "config must be untouched"
    );
    let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
    assert!(loaded.config.blocklists.is_empty(), "nothing was created");
}

/// DoD 2: the whole point of the lane — an allow-direction list
/// created straight from a URL, and the config it produces LOADS.
/// Asserting the load is the assertion that matters: a write that
/// the next reload refuses is exactly the failure this lane exists
/// to prevent.
#[tokio::test]
async fn cli_surface_add_allow_from_url_with_ack_writes_and_reloads_clean() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    run_add_with_direction(
        &master,
        &sock,
        "svc-b",
        None,
        "https://example.com/service-b.txt",
        Some("domains"),
        None,
        None,
        None,
        None,
        true,
        None,
        AddDirection {
            kind: Some("allow"),
            accept_unsigned_allow: true,
        },
    )
    .await
    .unwrap();
    let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
    let b = loaded
        .config
        .blocklists
        .iter()
        .find(|b| b.id.as_str() == "svc-b")
        .expect("entry must round-trip");
    assert_eq!(b.base, BlocklistBase::Allow);
    assert_eq!(b.trust, BlocklistTrust::RemoteUnsigned);
    assert!(b.accept_unsigned_allow);
}

/// Brief point 7 — every config mutation in this repo leaves an
/// audit row, and the new door must not be the exception. The URL
/// alone no longer describes what happened: the same `blocklist.add`
/// line could be an ordinary subscription or the moment a remote
/// party gained the power to unblock domains, so the allow path
/// records the direction and the consent.
#[tokio::test]
async fn cli_surface_allow_add_is_audited_with_direction_and_consent() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    run_add_with_direction(
        &master,
        &sock,
        "svc-b",
        None,
        "https://example.com/service-b.txt",
        Some("domains"),
        None,
        None,
        None,
        None,
        true,
        None,
        AddDirection {
            kind: Some("allow"),
            accept_unsigned_allow: true,
        },
    )
    .await
    .unwrap();
    let log = crate::cli::commands::audit::audit_log_path_for(&master);
    let rows = crate::config::audit::tail(&log, 50).expect("audit log must exist");
    let rec = rows
        .iter()
        .filter_map(|(_, r)| r.as_ref().ok())
        .find(|r| r.action.as_deref() == Some("blocklist.add"))
        .expect("the creation path must emit an audit row");
    assert_eq!(rec.target_id.as_deref(), Some("svc-b"));
    let after = rec.fields_after.as_deref().unwrap_or_default();
    assert!(after.contains("kind=allow"), "{after}");
    assert!(after.contains("accept_unsigned_allow=true"), "{after}");
    assert!(
        after.contains("https://example.com/service-b.txt"),
        "the URL stays on the row — a later silent re-point is what \
         audit-01 exists to attribute: {after}"
    );
}

/// The deny row is byte-identical to what it was before this lane —
/// existing audit readers key on a bare URL there.
#[tokio::test]
async fn cli_surface_deny_add_audit_row_is_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    add_tagged_remote_deny(&master, &sock, "svc-a").await;
    let log = crate::cli::commands::audit::audit_log_path_for(&master);
    let rows = crate::config::audit::tail(&log, 50).expect("audit log must exist");
    let rec = rows
        .iter()
        .filter_map(|(_, r)| r.as_ref().ok())
        .find(|r| r.action.as_deref() == Some("blocklist.add"))
        .expect("row must exist");
    assert_eq!(
        rec.fields_after.as_deref(),
        Some("https://example.com/svc-a.txt")
    );
}

/// The operator's original ask, end to end and from the CLI only:
/// one list to block service A, one to permit service B.
#[tokio::test]
async fn cli_surface_deny_and_allow_lists_coexist_from_urls_alone() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    run_add_with_direction(
        &master,
        &sock,
        "svc-a",
        None,
        "https://example.com/service-a.txt",
        Some("domains"),
        None,
        None,
        None,
        None,
        true,
        None,
        AddDirection::default(),
    )
    .await
    .unwrap();
    run_add_with_direction(
        &master,
        &sock,
        "svc-b",
        None,
        "https://example.com/service-b.txt",
        Some("domains"),
        None,
        None,
        None,
        None,
        true,
        None,
        AddDirection {
            kind: Some("allow"),
            accept_unsigned_allow: true,
        },
    )
    .await
    .unwrap();
    let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
    let by = |id: &str| {
        loaded
            .config
            .blocklists
            .iter()
            .find(|b| b.id.as_str() == id)
            .unwrap_or_else(|| panic!("{id} must exist"))
            .base
    };
    assert_eq!(by("svc-a"), BlocklistBase::Deny);
    assert_eq!(by("svc-b"), BlocklistBase::Allow);
}

/// The untagged-allow gate reaches the new door too. An allow-list
/// with no tags is not auto-promoted (D2), so it would install,
/// report success and permit nothing.
#[tokio::test]
async fn cli_surface_add_allow_without_tags_is_now_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    run_add_with_direction(
        &master,
        &sock,
        "svc-b",
        None,
        "https://example.com/service-b.txt",
        Some("domains"),
        None,
        None,
        None,
        None,
        true,
        None,
        AddDirection {
            kind: Some("allow"),
            accept_unsigned_allow: true,
        },
    )
    .await
    .expect("the tag gate is retired — an untagged allow-list is a legal declaration now");
    let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
    let b = loaded
        .config
        .blocklists
        .iter()
        .find(|b| b.id.as_str() == "svc-b")
        .expect("the list must have landed");
    assert_eq!(b.base, BlocklistBase::Allow);
}

/// Brief point 2: the written entry says what it is. Relying on the
/// serde defaults produced a `[[blocklists]]` row with no `kind` and
/// no `trust` — the operator reading their own TOML could not tell a
/// deny-list from an allow-list, and neither could a reviewer.
#[tokio::test]
async fn cli_surface_add_writes_kind_and_trust_explicitly() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    run_add(
        &master,
        &sock,
        "plain",
        None,
        "https://example.com/plain.txt",
        None,
        None,
        None,
        None,
        None,
        &[],
        true,
        None,
    )
    .await
    .unwrap();
    let segment = entry_segment_on_disk(&master, "plain");
    assert!(segment.contains("base = \"deny\""), "{segment}");
    assert!(segment.contains("trust = \"remote-unsigned\""), "{segment}");
    // Consent is written only when declared: a `false` on every
    // deny-list is noise that trains the operator to skip the line
    // on the one list where it means something.
    assert!(!segment.contains("accept_unsigned_allow"), "{segment}");
}

/// Read every TOML under the master's dir tree and return the
/// `[[blocklists]]` segment carrying `id`. Sharding means the entry
/// may land in master or in `blocklists.d/*.toml`.
fn entry_segment_on_disk(master: &std::path::Path, id: &str) -> String {
    fn read_all_toml(root: &std::path::Path, out: &mut Vec<String>) {
        if let Ok(rd) = std::fs::read_dir(root) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    read_all_toml(&p, out);
                } else if p.extension().and_then(|s| s.to_str()) == Some("toml") {
                    if let Ok(s) = std::fs::read_to_string(&p) {
                        out.push(s);
                    }
                }
            }
        }
    }
    let mut all_toml: Vec<String> = Vec::new();
    read_all_toml(master.parent().unwrap(), &mut all_toml);
    all_toml
        .iter()
        .flat_map(|raw| raw.split("[[blocklists]]"))
        .find(|seg| seg.contains(&format!("\"{id}\"")))
        .map(|s| s.to_string())
        .unwrap_or_else(|| panic!("entry {id} must exist on disk somewhere"))
}

#[test]
fn cli_surface_accept_unsigned_allow_flag_hint_pinned() {
    assert_eq!(
        ACCEPT_UNSIGNED_ALLOW_FLAG_HINT,
        "On the command line, declare it with --accept-unsigned-allow on \
         this verb."
    );
}

#[tokio::test]
async fn blocklists_add_triggers_reload_when_daemon_up() {
    use super::super::hr2_test_support::{
        assert_single_reload_with_resolved_token, env_home, seed_token_for_test, stub_reload_ok,
    };

    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = dir.path().join("stub.sock");
    let (server, recorded) = stub_reload_ok(sock.clone()).await;

    let _env = env_home(dir.path()).await;
    seed_token_for_test(dir.path());
    run_add(
        &master,
        &sock,
        "privacy-ads",
        Some("Privacy: ads"),
        "https://lists.purge.cc/privacy/ads.txt",
        Some("domains"),
        None,
        None,
        None,
        None,
        &[],
        true,
        None,
    )
    .await
    .unwrap();

    server.await.unwrap();
    assert_single_reload_with_resolved_token(&recorded);
}

// ── Enforcement report ─────────────────────────────────────────
//
// The defect these pin: a subscribed list whose tags meet nobody's
// occupies a filter slot, downloads on schedule, reports success and
// blocks nothing — and until now no read verb could say so. Every
// assertion below therefore checks BOTH directions. An assertion that
// only looked for an absent profile name would pass just as happily
// if the whole report were deleted.

/// Load a master config from a TOML string through the real
/// `load_config`, so validation and the untagged-deny-list
/// auto-promotion run exactly as they do for the live command.
fn load_master(toml: &str) -> (tempfile::TempDir, crate::config::schema::ConfigV1) {
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("config.toml");
    std::fs::write(&master, toml).unwrap();
    let now = time::OffsetDateTime::now_utc();
    let loaded = load_config(&master, now).unwrap_or_else(|e| panic!("fixture must load: {e:?}"));
    (dir, loaded.config)
}

fn find_list<'a>(
    config: &'a crate::config::schema::ConfigV1,
    id: &str,
) -> &'a crate::config::schema::Blocklist {
    config
        .blocklists
        .iter()
        .find(|b| b.id.as_str() == id)
        .unwrap_or_else(|| panic!("fixture has no blocklist {id}"))
}

/// The three artefacts every test below inspects: the computed
/// report, the `blocklist list` row, and the `blocklist show` block.
fn report(config: &crate::config::schema::ConfigV1, id: &str) -> (Enforcement, String, String) {
    let b = find_list(config, id);
    let slots = filter_slots(config);
    let e = analyse_enforcement(config, b, slots.as_ref());
    let row = format_list_enforcement_line(&e);
    let show = format_show_enforcement(b, &e).join("\n");
    (e, row, show)
}

/// One list the only profile inherits, one it overrides to `ignore`.
///
/// `plp-s3`: the inert arm used to be "carries a tag nothing else in the
/// config has". Tags reach nothing now, so inertness has exactly one
/// cause left and the fixture states it.
const TWO_LISTS: &str = r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"
lists = { reaches-nobody = "ignore" }

[[blocklists]]
id = "reaches-someone"
display_name = "Reaches someone"
url = "https://lists.purge.cc/ads.txt"

[[blocklists]]
id = "reaches-nobody"
display_name = "Reaches nobody"
url = "https://lists.purge.cc/orphan.txt"

[upstream]
servers = ["192.0.2.1:53"]
"#;

#[test]
fn an_enforced_list_and_an_inert_one_render_differently() {
    let (_dir, config) = load_master(TWO_LISTS);
    let (live_e, live_row, live_show) = report(&config, "reaches-someone");
    let (dead_e, dead_row, dead_show) = report(&config, "reaches-nobody");

    assert!(live_row.contains("enforced by 1 profile"), "{live_row}");
    assert!(!live_row.contains(NOT_ENFORCED), "{live_row}");
    assert!(dead_row.contains(NOT_ENFORCED), "{dead_row}");
    assert!(dead_row.contains("every profile ignores it"), "{dead_row}");
    assert_ne!(live_row, dead_row);

    assert_eq!(live_e.profiles, vec!["default".to_string()]);
    assert!(dead_e.profiles.is_empty());

    assert!(
        live_show.contains("Used by profiles:       default"),
        "{live_show}"
    );
    assert!(!live_show.contains(NOT_ENFORCED), "{live_show}");
    assert!(dead_show.contains(NOT_ENFORCED), "{dead_show}");
    assert!(
        dead_show.contains("Used by profiles:       <none>"),
        "{dead_show}"
    );
    // The fix must name what the operator actually has to change.
    assert!(
        dead_show.contains("reaches-nobody = \"ignore\""),
        "{dead_show}"
    );
}

#[test]
fn only_the_inert_list_reaches_the_closing_note() {
    let (_dir, config) = load_master(TWO_LISTS);
    let inert: Vec<String> = config
        .blocklists
        .iter()
        .filter(|b| {
            analyse_enforcement(&config, b, filter_slots(&config).as_ref())
                .blocked_reason()
                .is_some()
        })
        .map(|b| b.id.as_str().to_string())
        .collect();
    assert_eq!(inert, vec!["reaches-nobody".to_string()]);

    let footer = format_inert_footer(&inert).join("\n");
    assert!(footer.contains("reaches-nobody"), "{footer}");
    assert!(!footer.contains("reaches-someone"), "{footer}");
    // Silence on a healthy config: a "0 lists are not enforced" line
    // would train the operator to skip the block that matters.
    assert!(format_inert_footer(&[]).is_empty());
}

#[test]
fn a_disabled_list_is_not_enforced_even_when_its_tags_match() {
    let (_dir, config) = load_master(
        r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"
tags = ["ads"]

[[blocklists]]
id = "switched-off"
display_name = "Switched off"
url = "https://lists.purge.cc/ads.txt"
tags = ["ads"]
enabled = false

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );
    let (e, row, show) = report(&config, "switched-off");
    // The tag DOES meet the profile — the report must not stop at the
    // intersection and call that enforcement.
    assert_eq!(e.profiles, vec!["default".to_string()]);
    assert!(row.contains(NOT_ENFORCED), "{row}");
    assert!(row.contains("enabled = false"), "{row}");
    assert!(
        show.contains("warden blocklist set switched-off enabled true"),
        "{show}"
    );
}

/// `plp-s3` inverted this test, and the inversion is the record.
///
/// It was `an_untagged_allow_list_is_told_it_has_no_tags_not_that_nobody_carries_them`,
/// and it defended a real distinction: an untagged **allow**-list was the
/// one shape that reached this report with `tags = []` (D2 kept
/// allow-lists out of `uncategorized` auto-promotion), and blaming "no
/// profile carries any of its tags" would have been false — there were
/// none to carry.
///
/// Tags no longer reach lists at all, so an untagged allow-list is not
/// inert; it is **inherited by every profile as allow-direction**, which
/// is the most reachable a list can be. Reporting NOT ENFORCED for it
/// would now be the false negative the whole report exists to avoid.
///
/// The exposure has not gone unremarked: it moved to a load-time WARN
/// (`ALLOW_DIRECTION_LIST_STANDING_EXPOSURE`, §2.5), which is where a
/// standing risk belongs — re-stated at every load rather than once, in a
/// read verb the operator may never run.
#[test]
fn an_untagged_allow_list_is_enforced_everywhere_not_inert() {
    let (_dir, config) = load_master(
        r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"
tags = ["ads"]

[[blocklists]]
id = "untagged-allow"
display_name = "Untagged allow"
url = "https://lists.purge.cc/allow.txt"
base = "allow"
trust = "local"

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );
    let (e, row, show) = report(&config, "untagged-allow");
    assert_eq!(
        e.profiles,
        vec!["default".to_string()],
        "an allow-direction list is inherited by every profile that does \
         not override it — tags stopped gating that in `plp-s3`"
    );
    assert!(
        !row.contains(NOT_ENFORCED),
        "reporting a live allow-list as inert is the false negative this \
         report must never produce: {row}"
    );
    assert!(
        !row.contains("has no tags of its own"),
        "the retired reason must not fire — it would describe the \
         opposite of what the daemon does: {row}"
    );
    assert!(show.contains("Used by profiles:       default"), "{show}");
}

#[test]
fn the_closing_note_agrees_with_itself_in_the_singular() {
    // Regression: the singular branch used to read "It downloads on
    // schedule, report success, and filter nothing" — only the first
    // verb was inflected.
    let one = format_inert_footer(&["only-one".to_string()]).join("\n");
    assert!(
        one.contains("It downloads on schedule, reports success, and filters nothing."),
        "{one}"
    );
    let two = format_inert_footer(&["a".to_string(), "b".to_string()]).join("\n");
    assert!(
        two.contains("They download on schedule, report success, and filter nothing."),
        "{two}"
    );
}

/// `plp-s3` replaced four tests here, and the replacement is smaller for
/// a reason worth stating.
///
/// They were `a_device_tag_alone_makes_a_list_enforced`,
/// `a_group_tag_reaches_its_member_devices`,
/// `a_subnet_tag_does_not_leak_onto_an_explicit_device_record` and
/// `an_empty_group_carries_a_tag_to_nobody` — four axes a list could
/// reach an operator's network through, and four ways the report could
/// answer wrongly. There is now **one** axis: a `(profile, list)` pair.
/// A device reaches a list through its profile and through nothing else,
/// so the report cannot mis-attribute across axes that no longer exist.
///
/// The property those four defended survives intact and is what this
/// pins: **no false negative.** Telling an operator a list is NOT
/// ENFORCED when it is filtering is the one error this report must never
/// make — it sends them to fix something that already works, and worse,
/// invites them to "fix" it into a state that is different.
#[test]
fn a_list_no_profile_ignores_is_enforced_by_every_profile() {
    let (_dir, config) = load_master(
        r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[profiles.kids]
display_name = "Kids"

[[blocklists]]
id = "inherited"
display_name = "Inherited by all"
url = "https://lists.purge.cc/inherited.txt"

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );
    let (e, row, show) = report(&config, "inherited");
    assert_eq!(
        e.profiles,
        vec!["default".to_string(), "kids".to_string()],
        "a list with no override is inherited by EVERY profile — that is \
         what `base` means, and it is the change `plp-s3` makes"
    );
    assert!(!row.contains(NOT_ENFORCED), "{row}");
    assert!(row.contains("enforced by 2 profiles"), "{row}");
    assert!(
        show.contains("Used by profiles:       default, kids"),
        "{show}"
    );
}

/// The other side: a list every profile overrides to `ignore` really is
/// inert, and the report says so.
///
/// The positive arm above is what stops this from being satisfied by a
/// report that calls everything inert.
#[test]
fn a_list_every_profile_ignores_is_reported_inert() {
    let (_dir, config) = load_master(
        r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"
lists = { shunned = "ignore" }

[profiles.kids]
display_name = "Kids"
lists = { shunned = "ignore" }

[[blocklists]]
id = "shunned"
display_name = "Shunned"
url = "https://lists.purge.cc/shunned.txt"

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );
    let (e, row, show) = report(&config, "shunned");
    assert!(e.profiles.is_empty());
    assert!(row.contains(NOT_ENFORCED), "{row}");
    assert!(
        row.contains("every profile ignores it"),
        "the reason must name the override that caused it, got: {row}"
    );
    assert!(
        show.contains("`ignore`"),
        "the fix must point at the override to remove, got: {show}"
    );
}

/// One profile ignores it, one does not: enforced, and attributed to the
/// profile that still carries it.
///
/// This is the case v2 could not express at all (§1.2) — the whole
/// reason the workstream exists — so a report that collapsed it to
/// all-or-nothing would hide the feature from the operator who just used
/// it.
#[test]
fn a_partially_ignored_list_names_the_profiles_that_keep_it() {
    let (_dir, config) = load_master(
        r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[profiles.marketing]
display_name = "Marketing"
lists = { social = "ignore" }

[[blocklists]]
id = "social"
display_name = "Social"
url = "https://lists.purge.cc/social.txt"

[upstream]
servers = ["192.0.2.1:53"]
"#,
    );
    let (e, row, _) = report(&config, "social");
    assert_eq!(e.profiles, vec!["default".to_string()]);
    assert!(!row.contains(NOT_ENFORCED), "{row}");
    assert!(row.contains("enforced by 1 profile"), "{row}");
}
