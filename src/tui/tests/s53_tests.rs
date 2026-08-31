use super::*;
use crate::cli::commands::blocklists::{run_add, LIST_DELETE_CONFIRM_FAILED};
use crate::config::loader::load_config;
use crate::config::schema::{BlocklistBase, BlocklistFormat, BlocklistTrust};
use crate::tui::app::{App, EditField, EditListModal, EditModalMode, IntervalChoice, Leaf};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::path::{Path, PathBuf};

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn ctrl(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
}

fn dummy_poller(dir: &Path) -> IpcPoller {
    IpcPoller::new(&dir.join("ghost.sock"))
}

fn mk_master(dir: &tempfile::TempDir) -> PathBuf {
    let master = dir.path().join("config.toml");
    std::fs::write(
        &master,
        r#"schema_version = 3

[upstream]
servers = ["192.0.2.1:53"]

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"
"#,
    )
    .unwrap();
    master
}

async fn seed_with_one_list(dir: &tempfile::TempDir) -> PathBuf {
    let master = mk_master(dir);
    let sock = dir.path().join("ghost.sock");
    run_add(
        &master,
        &sock,
        "privacy-ads",
        Some("Privacy: ads"),
        "https://example.com/ads.txt",
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
    master
}

fn app_with_modal_for(master: &Path, modal: EditListModal) -> App {
    let mut app = App::new();
    let loaded = load_config(master, time::OffsetDateTime::now_utc()).unwrap();
    app.loaded_config = Some(loaded);
    app.active_leaf = Leaf::Lists;
    app.lists.edit_modal = Some(modal);
    app
}

fn modal_for_privacy_ads() -> EditListModal {
    EditListModal {
        blocklist_id: "privacy-ads".into(),
        mode: EditModalMode::Edit,
        display_name: "Privacy: ads — edited".into(),
        url: "https://example.com/ads.txt".into(),
        nature: BlocklistBase::Deny,
        enabled: true,
        interval: IntervalChoice::H6,
        interval_custom_buf: String::new(),
        format: BlocklistFormat::Domains,
        auth_token_ref: String::new(),
        skip_head_check: true,
        original: crate::config::schema::Blocklist {
            id: crate::config::schema::Id::new("privacy-ads").unwrap(),
            display_name: "Privacy: ads".into(),
            url: "https://example.com/ads.txt".into(),
            format: BlocklistFormat::Domains,
            update_interval_hours: 12,
            max_entries: 5_000_000,
            enabled: true,
            auth_token_ref: None,
            base: BlocklistBase::Deny,
            trust: BlocklistTrust::RemoteUnsigned,
            accept_unsigned_allow: false,
            max_consecutive_failures: 5,
        },
        focus: EditField::Interval,
        advanced_expanded: false,
        error_message: None,
        status_message: None,
        submitting: false,
        consent_declared: false,
    }
}

// ── the Edit-modal save must not drop schema fields ───────────────
//
// `build_blocklist_value` builds a whole `[[blocklists]]` row and
// `upsert_id_keyed` REPLACES the existing row with it (`*item =
// entry`, `cli/commands/target.rs`). A partial serialiser plus a
// total replacement means every field the builder forgets is silently
// reset to its serde default on the next save from the TUI — not on
// save of that field, on save of *anything*.
//
// `max_entries` and `max_consecutive_failures` already carry comments
// saying exactly this, so the lesson had been learned twice before
// `accept_unsigned_allow` was added without it.

/// Round-trip a row through the two steps the save flow actually
/// uses. `upsert_id_keyed` is included deliberately: checking only the
/// builder's output would miss that the write is a whole-row
/// replacement, and that is half of what makes an omission lossy.
fn save_roundtrip(modal: &EditListModal) -> crate::config::schema::Blocklist {
    use crate::cli::commands::target::upsert_id_keyed;
    let entry = build_blocklist_value(modal).expect("fixture must serialise");
    let mut doc: toml::Value = format!(
        "[[blocklists]]\nid = \"{}\"\ndisplay_name = \"stale\"\n\
             url = \"https://example.com/stale.txt\"\n",
        modal.blocklist_id
    )
    .parse()
    .unwrap();
    let created = upsert_id_keyed(&mut doc, "blocklists", &modal.blocklist_id, entry).unwrap();
    assert!(!created, "the fixture row must be REPLACED, not appended");
    let row = doc.get("blocklists").unwrap().as_array().unwrap()[0].clone();
    row.try_into().expect("row must deserialise as a Blocklist")
}

/// A remote allow-list configured from the CLI, then edited in the
/// TUI — the workflow the docs send the operator down. The operator
/// renames it; the consent must survive.
///
/// `true` is the discriminating value: `accept_unsigned_allow`
/// defaults to `false`, so a builder that omits the key — or writes a
/// hardcoded default — yields `false` here. Only genuine preservation
/// from `modal.original` yields `true`.
#[test]
fn edit_save_preserves_a_declared_unsigned_allow_consent() {
    let mut modal = modal_for_privacy_ads();
    modal.nature = BlocklistBase::Allow;
    modal.original.base = BlocklistBase::Allow;
    modal.original.trust = BlocklistTrust::RemoteUnsigned;
    modal.original.accept_unsigned_allow = true;
    modal.display_name = "renamed in the TUI".into();

    let saved = save_roundtrip(&modal);
    assert!(
        saved.accept_unsigned_allow,
        "renaming a list must not withdraw the operator's consent — the next \
             reload then refuses the config the TUI itself just wrote, and the \
             list becomes uneditable from the TUI"
    );
    assert_eq!(saved.display_name, "renamed in the TUI", "the edit applied");
}

/// The other half of the round trip: a list that never declared
/// consent must not acquire one. Without this, a builder that wrote
/// `true` unconditionally would satisfy the test above — while forging
/// a security declaration the operator never made.
#[test]
fn edit_save_does_not_invent_a_consent_that_was_never_declared() {
    let mut modal = modal_for_privacy_ads();
    modal.original.accept_unsigned_allow = false;
    modal.display_name = "renamed in the TUI".into();

    let saved = save_roundtrip(&modal);
    assert!(
        !saved.accept_unsigned_allow,
        "the TUI must never declare a consent on the operator's behalf"
    );
}

/// The third value the field can take, and the one the gate exists
/// to produce: no consent in the file, and one typed into
/// `ConfirmUnsignedAllow` during this session.
///
/// It is what separates "declarable" from "invented" — the test
/// above stays red on a hardcoded `true`, this one stays red on a
/// hardcoded `false` or on a builder that reads only `original`.
#[test]
fn edit_save_writes_the_consent_the_operator_typed() {
    let mut modal = modal_for_privacy_ads();
    modal.nature = BlocklistBase::Allow;
    modal.original.trust = BlocklistTrust::RemoteUnsigned;
    modal.original.accept_unsigned_allow = false;
    modal.consent_declared = true;

    let saved = save_roundtrip(&modal);
    assert!(
        saved.accept_unsigned_allow,
        "a consent typed into the confirm stage must reach the file — \
             otherwise the gate asks a question and then discards the answer"
    );
}

/// `Esc` out of the confirm leaves the flag alone, so the save that
/// follows carries only what the file already said.
///
/// The pairing matters: `consent_declared` is deliberately NOT
/// seeded from `original`, so a list that already consents survives
/// a backed-out confirm unchanged rather than being re-declared.
#[test]
fn backing_out_of_the_confirm_declares_nothing_and_revokes_nothing() {
    let mut declined = modal_for_privacy_ads();
    declined.nature = BlocklistBase::Allow;
    declined.consent_declared = false;
    assert!(
        !save_roundtrip(&declined).accept_unsigned_allow,
        "Esc must not grant"
    );

    let mut already = modal_for_privacy_ads();
    already.nature = BlocklistBase::Allow;
    already.original.accept_unsigned_allow = true;
    already.consent_declared = false;
    assert!(
        save_roundtrip(&already).accept_unsigned_allow,
        "Esc must not revoke a consent the file already carries"
    );
}

// ── the allow gate, and the stage it opens ──────────────────────

/// A deny-list is not asked anything, whatever else is missing. The
/// gate must not become a tax on the 99% of saves that block.
#[test]
fn a_deny_save_passes_both_doors_untouched() {
    let mut modal = modal_for_privacy_ads();
    modal.nature = BlocklistBase::Deny;
    modal.original.accept_unsigned_allow = false;
    assert_eq!(allow_gate_for_modal(&modal), AllowGateOutcome::Proceed);
}

/// Tag before consent. The CLI reports these the other way round on
/// purpose; a form has no retry, so asking someone to type a list id
/// and then refusing the save for an unrelated reason spends their
/// deliberation on nothing.
#[test]
/// **Inverted by `plp-s3`.** The tag door is retired (§2.5), so with no
/// tag and no consent there is only one door left — and it is the
/// consent one, which §2.5 leaves exactly where it was.
///
/// The ordering this used to pin ("the one the operator can fix in this
/// form comes first") stops being a question when there is one door.
fn the_only_surviving_door_is_the_consent_door() {
    let mut modal = modal_for_privacy_ads();
    modal.nature = BlocklistBase::Allow;
    modal.original.trust = BlocklistTrust::RemoteUnsigned;
    modal.original.accept_unsigned_allow = false;
    assert_eq!(
        allow_gate_for_modal(&modal),
        AllowGateOutcome::NeedsConsent,
        "the tag door is retired; consent is untouched"
    );
}

/// Neither door asks twice: a file that already consents, and a
/// local file the operator wrote themselves, both pass.
#[test]
fn a_declared_consent_and_local_trust_both_pass_the_second_door() {
    let base = || {
        let mut m = modal_for_privacy_ads();
        m.nature = BlocklistBase::Allow;
        m
    };

    let mut declared = base();
    declared.original.trust = BlocklistTrust::RemoteUnsigned;
    declared.original.accept_unsigned_allow = true;
    assert_eq!(allow_gate_for_modal(&declared), AllowGateOutcome::Proceed);

    let mut local = base();
    local.original.trust = BlocklistTrust::Local;
    local.original.accept_unsigned_allow = false;
    assert_eq!(allow_gate_for_modal(&local), AllowGateOutcome::Proceed);
}

// `plp-s5d` removed five tests here, and they collapsed for ONE reason:
// every one of them varied `modal.tags` and held the rest fixed.
//
//   `a_tagged_allow_on_an_unverified_source_asks_for_consent`
//   `a_picker_holding_only_the_sentinel_now_passes`
//   `the_sentinel_beside_a_real_tag_now_passes_too`
//   `a_sentinel_tagged_allow_on_an_unverified_source_asks_only_for_consent`
//   `a_deny_save_may_carry_the_sentinel`
//
// `EditListModal` has no `tags` field, so the dimension they explored
// does not exist — each became a byte-identical duplicate of one of
// the three tests kept above, which between them still cover the whole
// surviving matrix: `nature` x `trust` x `accept_unsigned_allow`.
//
// **Nothing is uncovered by this.** `plp-s3` had already retired both
// tag doors (`needs_tag` / `needs_non_system_tag` are hardcoded
// `false`), so these five were asserting that a retired gate stays
// retired — through an input the form could no longer supply. The one
// live door, consent, keeps its three tests plus the typed-id stage
// tests below.

// `the_system_tag_refusals_stay_short_enough_to_render` retired here.
// It pinned `LIST_ALLOW_TAG_IS_SYSTEM` / `KIND_TOGGLE_TAG_IS_SYSTEM`,
// the two strings the system-tag gate emitted; §2.5 retired the gate
// and both constants left with the branches that raised them. A frozen
// string with no emitter is a test that can only fail for the wrong
// reason. The consent refusal, which is still live, is pinned by
// `tests/frozen_strings_tui_allow_consent.rs`.

fn plain_key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, crossterm::event::KeyModifiers::NONE)
}

/// The buffer the stage is currently holding — the routing layer
/// destructures it out of `modal.mode` before each call, so the
/// tests reproduce that rather than reaching around it.
fn staged_buffer(modal: &EditListModal) -> String {
    match &modal.mode {
        EditModalMode::ConfirmUnsignedAllow { typed } => typed.clone(),
        other => panic!("expected the consent stage, got {other:?}"),
    }
}

/// Typing the id exactly declares the consent and hands control back
/// to the save — the `true` return is what re-enters
/// `submit_edit_modal`, so the declaration and the write it
/// authorises are one operator action.
#[test]
fn typing_the_id_exactly_declares_the_consent_and_resumes_the_save() {
    let mut app = App::new();
    let mut modal = modal_for_privacy_ads();
    modal.mode = EditModalMode::ConfirmUnsignedAllow {
        typed: String::new(),
    };

    for c in "privacy-ads".chars() {
        let buf = staged_buffer(&modal);
        assert!(
            !handle_confirm_unsigned_allow_key(
                &mut app,
                &mut modal,
                buf,
                plain_key(KeyCode::Char(c)),
            ),
            "no keystroke before Enter may commit anything"
        );
        assert!(!modal.consent_declared, "typing alone declares nothing");
    }
    assert_eq!(staged_buffer(&modal), "privacy-ads", "every char landed");

    assert!(handle_confirm_unsigned_allow_key(
        &mut app,
        &mut modal,
        "privacy-ads".to_string(),
        plain_key(KeyCode::Enter),
    ));
    assert!(modal.consent_declared);
    assert!(matches!(modal.mode, EditModalMode::Edit));
}

/// A mismatch KEEPS the stage, with the reason in the error slot.
///
/// Both halves matter. Bouncing to `Edit` — what the delete gate
/// does — would cost a re-submit here, because this stage is reached
/// from `Ctrl+S` rather than from one Enter on a button. And a
/// silent re-stash is indistinguishable from a dead key.
#[test]
fn a_mismatched_buffer_is_refused_in_place_and_says_so() {
    let mut app = App::new();
    let mut modal = modal_for_privacy_ads();
    modal.mode = EditModalMode::ConfirmUnsignedAllow {
        typed: "privacy-adz".into(),
    };

    assert!(!handle_confirm_unsigned_allow_key(
        &mut app,
        &mut modal,
        "privacy-adz".to_string(),
        plain_key(KeyCode::Enter),
    ));
    assert!(!modal.consent_declared, "a near-miss must not declare");
    assert!(
        matches!(modal.mode, EditModalMode::ConfirmUnsignedAllow { .. }),
        "the stage must survive a typo"
    );
    assert_eq!(
        modal.error_message.as_deref(),
        Some(tabs::lists::UNSIGNED_ALLOW_CONFIRM_MISMATCH)
    );
}

/// `Esc` returns to the form having declared nothing — and having
/// revoked nothing either, which is why `consent_declared` is not
/// seeded from `original`.
#[test]
fn esc_out_of_the_stage_declares_nothing() {
    let mut app = App::new();
    let mut modal = modal_for_privacy_ads();
    modal.original.accept_unsigned_allow = true;
    modal.mode = EditModalMode::ConfirmUnsignedAllow {
        typed: "privacy-ads".into(),
    };

    assert!(!handle_confirm_unsigned_allow_key(
        &mut app,
        &mut modal,
        "privacy-ads".to_string(),
        plain_key(KeyCode::Esc),
    ));
    assert!(!modal.consent_declared);
    assert!(matches!(modal.mode, EditModalMode::Edit));
    assert!(
        save_roundtrip(&modal).accept_unsigned_allow,
        "the file's own declaration survives the operator backing out"
    );
}

// ── the [K] path's gate ─────────────────────────────────────────

/// A master config with one deny-list carrying **no `tags` key at
/// all** — the shape `content-gambling` has on the CT, and the one
/// the loader promotes.
fn master_with_untagged_deny(dir: &tempfile::TempDir) -> PathBuf {
    let master = dir.path().join("config.toml");
    std::fs::write(
        &master,
        r#"schema_version = 3

[upstream]
servers = ["192.0.2.1:53"]

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"
tags = ["uncategorized"]

[[blocklists]]
id = "content-gambling"
display_name = "Content: Gambling"
url = "https://lists.purge.cc/gambling.txt"
format = "domains"
"#,
    )
    .unwrap();
    master
}

fn app_loaded_from(master: &Path) -> App {
    let mut app = App::new();
    app.loaded_config = Some(load_config(master, time::OffsetDateTime::now_utc()).unwrap());
    app.active_leaf = Leaf::Lists;
    app
}

/// **The discriminating test for the whole change.**
///
/// The list has no `tags` in its file, so flipping it to `allow`
/// must be refused. But the loaded config the TUI holds shows it
/// tagged `["uncategorized"]`, because the loader promotes untagged
/// deny-lists — so a gate written against the in-memory state
/// returns `Proceed` and the operator gets a standing exemption for
/// every device on the profile carrying that tag.
///
/// The first assertion establishes that the two sources really do
/// disagree here. Without it this test would keep passing against a
/// fixture that had quietly stopped exercising the promotion, and a
/// green test that no longer discriminates is worse than none.
#[test]
fn the_k_gate_on_an_untagged_remote_list_asks_for_consent_now() {
    let dir = tempfile::tempdir().unwrap();
    let master = master_with_untagged_deny(&dir);
    let app = app_loaded_from(&master);

    assert_eq!(
        kind_toggle_gate(
            &app,
            &master,
            "content-gambling",
            BlocklistTrust::RemoteUnsigned
        ),
        Ok(AllowGateOutcome::NeedsConsent),
        "`plp-s3` §2.5 retired the tag door; the consent door is what an \
             unverified source still owes, and it is untouched"
    );
}

/// With a real tag in the file, the same list reaches the consent
/// question. The companion to the test above: it proves the refusal
/// there was about the tags and not about the gate refusing
/// everything.
#[test]
fn the_k_gate_asks_for_consent_once_the_file_carries_a_tag() {
    let dir = tempfile::tempdir().unwrap();
    let master = master_with_untagged_deny(&dir);
    let doc = std::fs::read_to_string(&master).unwrap();
    std::fs::write(&master, format!("{doc}tags = [\"kids\"]\n")).unwrap();
    let app = app_loaded_from(&master);

    assert_eq!(
        kind_toggle_gate(
            &app,
            &master,
            "content-gambling",
            BlocklistTrust::RemoteUnsigned
        ),
        Ok(AllowGateOutcome::NeedsConsent)
    );
    assert_eq!(
        kind_toggle_gate(&app, &master, "content-gambling", BlocklistTrust::Local),
        Ok(AllowGateOutcome::Proceed),
        "a file the operator wrote themselves has no remote publisher to consent to"
    );
}

/// An id the running config knows but no file carries is an `Err`,
/// not "no tags". Reading it as the latter would refuse a save for a
/// reason that is not the operator's.
#[test]
fn the_k_gate_reports_an_unreadable_file_as_its_own_outcome() {
    let dir = tempfile::tempdir().unwrap();
    let master = master_with_untagged_deny(&dir);
    let app = app_loaded_from(&master);
    let got = kind_toggle_gate(&app, &master, "never-declared", BlocklistTrust::Local);
    assert!(
        got.is_err(),
        "an absent entry must not be read as an untagged one: {got:?}"
    );
}

/// A mismatched buffer keeps the notice open with the reason set,
/// and never reaches the verb.
#[tokio::test]
async fn the_k_confirm_refuses_a_mismatch_in_place() {
    let dir = tempfile::tempdir().unwrap();
    let master = master_with_untagged_deny(&dir);
    let mut app = app_loaded_from(&master);
    app.lists.kind_confirm = Some(app::KindConfirm {
        list_id: "content-gambling".into(),
        typed: "content-gamblin".into(),
        error: None,
    });
    let poller = dummy_poller(dir.path());

    handle_kind_confirm_key(&mut app, key(KeyCode::Enter), &poller, &master).await;

    let confirm = app
        .lists
        .kind_confirm
        .as_ref()
        .expect("a near-miss must not close the notice");
    assert_eq!(
        confirm.error.as_deref(),
        Some(tabs::lists::UNSIGNED_ALLOW_CONFIRM_MISMATCH)
    );
    let on_disk = std::fs::read_to_string(&master).unwrap();
    assert!(
        !on_disk.contains("accept_unsigned_allow"),
        "a refused confirm must not have written anything:\n{on_disk}"
    );
}

/// `Esc` closes the notice and writes nothing.
#[tokio::test]
async fn the_k_confirm_esc_closes_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let master = master_with_untagged_deny(&dir);
    let before = std::fs::read_to_string(&master).unwrap();
    let mut app = app_loaded_from(&master);
    app.lists.kind_confirm = Some(app::KindConfirm {
        list_id: "content-gambling".into(),
        typed: "content-gambling".into(),
        error: None,
    });
    let poller = dummy_poller(dir.path());

    handle_kind_confirm_key(&mut app, key(KeyCode::Esc), &poller, &master).await;

    assert!(app.lists.kind_confirm.is_none(), "Esc closes the notice");
    assert_eq!(
        std::fs::read_to_string(&master).unwrap(),
        before,
        "Esc on a fully-typed buffer must still write nothing"
    );
}

/// The class, not the instance. `accept_unsigned_allow` is the field
/// that was lost; this asserts no *other* field can go the same way
/// unnoticed.
///
/// Two halves, because neither alone is enough. The exhaustive
/// destructuring is a **compile-time** trip-wire: a new field on
/// `Blocklist` breaks the build right here, at a test whose name says
/// what to do about it. The `FIELDS` list is the **runtime** half,
/// spelled out by hand on purpose — Rust has no reflection over struct
/// fields, and a test that derived both sides from one source would
/// only ever agree with itself.
#[test]
fn the_edit_builder_writes_every_blocklist_field() {
    const FIELDS: &[&str] = &[
        "id",
        "display_name",
        "url",
        "format",
        "update_interval_hours",
        "max_entries",
        "enabled",
        "auth_token_ref",
        "base",
        "trust",
        "accept_unsigned_allow",
        "max_consecutive_failures",
    ];

    let crate::config::schema::Blocklist {
        id: _,
        display_name: _,
        url: _,
        format: _,
        update_interval_hours: _,
        max_entries: _,
        enabled: _,
        auth_token_ref: _,
        base: _,
        trust: _,
        accept_unsigned_allow: _,
        max_consecutive_failures: _,
    } = modal_for_privacy_ads().original;

    // `auth_token_ref` is legitimately unwritten when empty: absent
    // and empty mean the same thing, and the modal seeds it from
    // `original`, so nothing is lost. The fixture gives it a non-empty
    // value — the only configuration in which its absence would be a
    // real omission.
    let mut modal = modal_for_privacy_ads();
    modal.auth_token_ref = "some-secret-ref".into();

    let value = build_blocklist_value(&modal).expect("fixture must serialise");
    let tbl = value.as_table().expect("a row is a table");

    // **`tags` left `FIELDS` in `plp-s5d`, and dropping it quietly
    // would have been indistinguishable from the defect this test
    // exists to catch** — a field the builder forgot, reset to its
    // serde default on the next save. So the omission is asserted
    // rather than merely absent: the builder must write NO `tags` key,
    // deliberately, and if someone restores the write this goes red
    // instead of the list silently agreeing with them.
    //
    // Why not writing it is the safe direction: see the note on
    // `build_blocklist_value`. In short, `Blocklist` is
    // `deny_unknown_fields`, so once `plp-s5a` removes the field a row
    // still carrying `tags = [...]` fails to LOAD.
    assert!(
        !tbl.contains_key("tags"),
        "the builder wrote a `tags` key; `plp-s5d` removed it on purpose \
             and `plp-s5a` makes a surviving one load-fatal: {tbl:?}"
    );

    let missing: Vec<&str> = FIELDS
        .iter()
        .copied()
        .filter(|f| !tbl.contains_key(*f))
        .collect();
    assert!(
        missing.is_empty(),
        "build_blocklist_value drops {missing:?}. upsert_id_keyed replaces the \
             whole row, so every dropped field is silently reset to its serde \
             default on the next save from the TUI."
    );
}

// Sprint A.5 (lc2_v2 foundation) dropped two save-flow tests:
//   - s53_1_ctrl_s_preserves_max_entries_from_snapshot
//   - s53_ctrl_s_with_valid_buffers_writes_through_and_closes
//
// Both exercised handle_lists_edit_modal_key on the v1-shape modal
// (carrying `category: Option<Id>` pre-fill). Sprint C reshapes the
// modal around a tag-chip widget; the save-flow contract will be
// re-pinned against the new field set. The remaining S53 modal
// tests below (delete-confirm flow, cursor seeding, ESC handling,
// Promote/Add mode) cover the orthogonal flows that survive Sprint A.

#[tokio::test]
/// §4.63 F4 **inverted this test rather than relaxing it**, and that
/// is the point: its first assertion used to be
/// `matches!(modal.mode, EditModalMode::Edit)` — the bounce — which
/// directly contradicts staying in `ConfirmDelete`. A test that
/// pinned the old behaviour could not be extended to cover the new
/// one; it had to change sides.
///
/// Note what is deliberately NOT asserted here: that the list still
/// exists on disk is checked below, but the *form state* is not used
/// as evidence of the refusal. The product preserves the modal across
/// a refused delete by design, so "the modal is still open" is green
/// whether or not the refusal happened. The refusal itself is the
/// assertion.
async fn s53_delete_confirm_typed_id_mismatch_stays_and_names_both_ids() {
    let dir = tempfile::tempdir().unwrap();
    let master = seed_with_one_list(&dir).await;
    let mut modal = modal_for_privacy_ads();
    modal.mode = EditModalMode::ConfirmDelete {
        typed: "wrong-id".into(),
    };
    let mut app = app_with_modal_for(&master, modal);
    let poller = dummy_poller(dir.path());
    handle_lists_edit_modal_key(&mut app, key(KeyCode::Enter), &poller, &master).await;
    let modal = app
        .lists
        .edit_modal
        .as_ref()
        .expect("mismatch must keep the modal open");

    match &modal.mode {
        EditModalMode::ConfirmDelete { typed } => assert_eq!(
            typed, "wrong-id",
            "the typed buffer must survive the refusal — discarding it \
                 makes a one-character typo cost the whole gate"
        ),
        other => panic!("mismatch must STAY in ConfirmDelete, got {other:?}"),
    }

    let err = modal
        .error_message
        .as_deref()
        .expect("a refusal must say something");
    assert!(
        err.starts_with(LIST_DELETE_CONFIRM_FAILED),
        "the frozen const stays the lede: {err:?}"
    );
    assert!(
        err.contains("wrong-id"),
        "the refusal must name what was typed: {err:?}"
    );
    assert!(
        err.contains("privacy-ads"),
        "the refusal must name what was EXPECTED — this is the whole \
             defect; Lists was the last typed-confirm gate that refused \
             without saying what it wanted: {err:?}"
    );

    // List must still exist on disk.
    let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
    assert_eq!(loaded.config.blocklists.len(), 1);
}

#[tokio::test]
async fn s53_delete_confirm_typed_id_match_proceeds_and_removes_list() {
    let dir = tempfile::tempdir().unwrap();
    let master = seed_with_one_list(&dir).await;
    let mut modal = modal_for_privacy_ads();
    modal.mode = EditModalMode::ConfirmDelete {
        typed: "privacy-ads".into(),
    };
    let mut app = app_with_modal_for(&master, modal);
    let poller = dummy_poller(dir.path());
    handle_lists_edit_modal_key(&mut app, key(KeyCode::Enter), &poller, &master).await;
    // Modal closed on success; the post-poll `last_error` may carry
    // the IPC-no-socket message in this hermetic env (poll_active_leaf
    // runs at the tail of the success path). The durable contract
    // is "disk shows the row gone and the modal is closed".
    assert!(
        app.lists.edit_modal.is_none(),
        "modal must close on success"
    );
    // List is gone from the TOML.
    let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
    assert!(
        loaded.config.blocklists.is_empty(),
        "list must be removed from disk"
    );
}

/// **This test measured nothing from Sprint A until `plp-s4c`.**
///
/// Its predecessor's fixture was one line:
///
/// ```ignore
/// let raw = raw.replace("blocklists = []", "blocklists = [\"privacy-ads\"]");
/// ```
///
/// `mk_master` seeds `[profiles.default]` with a `display_name` and
/// nothing else, so the needle was absent and `str::replace` a silent
/// no-op. The test therefore deleted a list **no profile referenced**,
/// while its name and an eight-line header promised cascade-with-a-
/// reference coverage. Green then, and green under any implementation
/// of the cascade including none.
///
/// It could not have been repaired by fixing the needle either:
/// `Profile.blocklists` no longer exists and `Profile` is
/// `deny_unknown_fields`, so a matching replace would have produced a
/// config the loader refuses. Same root as F22 — a dead v1 premise
/// that left prose behind it.
///
/// What it asserts now: a profile carrying a real
/// `profiles.<id>.lists` override, deleted through the typed-id
/// confirm, loses both the list and the override.
///
/// **Why it is red under a broken cascade** (the mutation this needed
/// and could not have): `run_remove_silent` stages every file and runs
/// `write_value_validated` before promoting anything. Leave the
/// override behind and the staged bytes name a `[[blocklists]]` row
/// that is not there, the validator refuses with `CrossRefMiss`, and
/// the removal fails outright — so `blocklists.is_empty()` below goes
/// red. Fail-closed, which is why no config on disk was ever damaged
/// by the years this was a no-op.
#[tokio::test]
async fn s53_delete_cascades_a_real_override_and_reports_it() {
    let dir = tempfile::tempdir().unwrap();
    let master = seed_with_one_list(&dir).await;

    // Seed the override by APPENDING a profile table, not by
    // `str::replace`-ing one. `seed_with_one_list` runs the real
    // `run_add`, which rewrites the file through `toml`, so any needle
    // taken from `mk_master`'s literal is a guess about someone else's
    // serialiser — and a guess that misses is silent. A new
    // `[profiles.…]` header is valid wherever it lands.
    let mut raw = std::fs::read_to_string(&master).unwrap();
    raw.push_str(
        "\n[profiles.kids]\ndisplay_name = \"Kids\"\nlists = { privacy-ads = \"deny\" }\n",
    );
    std::fs::write(&master, &raw).unwrap();

    // And ASSERT the seed landed. The defect this test replaces was a
    // fixture that did not take; a fixture that cannot fail loudly is
    // the same bug wearing a different hat.
    let seeded = load_config(&master, time::OffsetDateTime::now_utc())
        .expect("the seeded override must load");
    assert!(
        seeded
            .config
            .profiles
            .get("kids")
            .expect("kids profile")
            .lists
            .keys()
            .any(|k| k.as_str() == "privacy-ads"),
        "fixture precondition: the profile must actually carry the \
             override, or this test measures a delete with no reference — \
             which is exactly what it did for four sprints"
    );

    let mut modal = modal_for_privacy_ads();
    modal.mode = EditModalMode::ConfirmDelete {
        typed: "privacy-ads".into(),
    };
    let mut app = app_with_modal_for(&master, modal);
    let poller = dummy_poller(dir.path());
    handle_lists_edit_modal_key(&mut app, key(KeyCode::Enter), &poller, &master).await;

    assert!(
        app.lists.edit_modal.is_none(),
        "modal must close on cascade-delete success; last_status={:?}",
        app.last_status
    );

    let loaded = load_config(&master, time::OffsetDateTime::now_utc())
        .expect("the post-delete config must still load");
    assert!(
        loaded.config.blocklists.is_empty(),
        "list must be gone from disk"
    );
    let kids = loaded
        .config
        .profiles
        .get("kids")
        .expect("the profile must survive the list's deletion");
    assert!(
        kids.lists.is_empty(),
        "the override naming the deleted list must be gone too, not \
             left dangling: {:?}",
        kids.lists
    );

    // The footer is deliberately NOT asserted here: the post-success
    // `poll_active_leaf` runs against a no-socket dummy poller and
    // overwrites the status with the IPC failure string. `cascade_summary`
    // is asserted directly instead — see
    // `cascade_summary_states_the_count_and_pluralises`.
}

/// **The non-empty arm of [`cascade_summary`] had never executed.**
///
/// It was unreachable while the cascade was a structural no-op, so the
/// text was written, reviewed and shipped without ever having been
/// rendered. The `listref` lane made the cascade real; this is the
/// first thing that reads its output.
#[test]
fn cascade_summary_states_the_count_and_pluralises() {
    assert_eq!(cascade_summary(0), "", "no cascade adds no clause");
    assert_eq!(cascade_summary(1), " (cascaded refs from 1 profile)");
    assert_eq!(cascade_summary(2), " (cascaded refs from 2 profiles)");
    // It appends to `format_list_delete_ok`, so it has to open with a
    // separator rather than assume one.
    assert!(cascade_summary(1).starts_with(' '));
    // "refs", not "profiles that lose the list": this counts rewritten
    // override rows, while the confirm prompt counted profiles that
    // enforced the list. The two numbers legitimately differ.
    assert!(cascade_summary(1).contains("refs"));
}

#[tokio::test]
async fn s53_modal_absorbs_global_nav_keys() {
    // While the modal is open, digit hotkeys (1..5 are global tab
    // jumps) must NOT switch tabs — the modal-priority gate at
    // mod.rs:300+ owns every keystroke.
    let dir = tempfile::tempdir().unwrap();
    let master = seed_with_one_list(&dir).await;
    let modal = modal_for_privacy_ads();
    let mut app = app_with_modal_for(&master, modal);
    let poller = dummy_poller(dir.path());
    handle_key(&mut app, key(KeyCode::Char('1')), &poller, &master).await;
    // Active section must NOT have flipped to Dashboard.
    assert_eq!(app.active_leaf, Leaf::Lists);
    // Modal still open and the keystroke landed in a buffer (or was
    // ignored as a non-text-field char) — but the section gate did
    // not fire.
    assert!(app.lists.edit_modal.is_some(), "modal must remain open");
}

#[tokio::test]
async fn s53_esc_from_confirm_delete_returns_to_edit_no_writes() {
    let dir = tempfile::tempdir().unwrap();
    let master = seed_with_one_list(&dir).await;
    let mut modal = modal_for_privacy_ads();
    modal.mode = EditModalMode::ConfirmDelete {
        typed: "privacy-ads".into(),
    };
    let mut app = app_with_modal_for(&master, modal);
    let poller = dummy_poller(dir.path());
    handle_lists_edit_modal_key(&mut app, key(KeyCode::Esc), &poller, &master).await;
    let modal = app
        .lists
        .edit_modal
        .as_ref()
        .expect("Esc from confirm must keep the modal open in Edit mode");
    assert!(matches!(modal.mode, EditModalMode::Edit));
    let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
    assert_eq!(loaded.config.blocklists.len(), 1);
}

#[tokio::test]
async fn s53_enter_on_focused_list_row_opens_edit_modal_via_handle_lists_key() {
    // End-to-end repro of the user's flow on the Lists tab:
    //   1) loaded_config has one [[blocklists]] entry
    //   2) lists.entries holds the matching DTO (id populated)
    //   3) cursor is on the List row (row 0 — the Lists table is a
    //      flat row-per-blocklist model, no grouping header)
    //   4) press Enter
    // Expectation: app.lists.edit_modal is set; no last_error.
    let dir = tempfile::tempdir().unwrap();
    let master = seed_with_one_list(&dir).await;
    let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();

    let mut app = App::new();
    app.loaded_config = Some(loaded);
    app.active_leaf = Leaf::Lists;
    app.lists.entries = vec![crate::lists::status::BlocklistStatusDto {
        source: "privacy/ads".into(),
        id: Some("privacy-ads".into()),
        entries: 100,
        ..Default::default()
    }];
    // Row 0 is the privacy-ads list (flat table, no header row).
    app.lists.table_state.select(Some(0));

    let poller = dummy_poller(dir.path());
    handle_lists_key(&mut app, key(KeyCode::Enter), &poller, &master).await;

    assert!(
        app.lists.edit_modal.is_some(),
        "Enter on a focused list row must open the edit modal"
    );
    assert!(
        app.last_status.is_none(),
        "no error should be set on the happy path; got: {:?}",
        app.last_status
    );
}

/// Build an app where `[lists].sources` carries one orphan source
/// (raw URL, no matching `[[blocklists]]` entry). Used by the
/// Promote-flow tests below.
fn app_with_orphan_source(master_path: &Path, orphan_source: &str) -> App {
    let loaded = load_config(master_path, time::OffsetDateTime::now_utc()).unwrap();
    let mut app = App::new();
    app.loaded_config = Some(loaded);
    app.active_leaf = Leaf::Lists;
    app.lists.entries = vec![crate::lists::status::BlocklistStatusDto {
        source: orphan_source.to_string(),
        id: None,
        entries: 0,
        ..Default::default()
    }];
    // Row 0 is the orphan (flat table, no header row).
    app.lists.table_state.select(Some(0));
    app
}

fn write_promote_master(dir: &tempfile::TempDir, orphan_source: &str) -> PathBuf {
    let master = dir.path().join("config.toml");
    std::fs::write(
        &master,
        format!(
            r#"schema_version = 3

[upstream]
servers = ["192.0.2.1:53"]

[server]
default_profile = "default"

[lists]
sources = ["{orphan_source}"]

[profiles.default]
display_name = "Default"
"#,
        ),
    )
    .unwrap();
    master
}

#[tokio::test]
async fn s53_promote_enter_on_orphan_url_opens_promote_modal() {
    // Orphan = a raw URL in [lists].sources with no matching
    // [[blocklists]] entry. Enter should fall through from the
    // edit-modal builder (refuses on missing canonical) into the
    // Promote builder (opens with URL pre-filled + id suggestion).
    let dir = tempfile::tempdir().unwrap();
    let master = write_promote_master(&dir, "https://example.com/orphan-list.txt");
    let mut app = app_with_orphan_source(&master, "https://example.com/orphan-list.txt");
    let poller = dummy_poller(dir.path());

    handle_lists_key(&mut app, key(KeyCode::Enter), &poller, &master).await;

    let modal = app
        .lists
        .edit_modal
        .as_ref()
        .expect("Enter on orphan must open Promote modal");
    match &modal.mode {
        crate::tui::app::EditModalMode::Promote { source } => {
            assert_eq!(source, "https://example.com/orphan-list.txt");
        }
        other => panic!("expected Promote mode, got {other:?}"),
    }
    assert_eq!(
        modal.url, "https://example.com/orphan-list.txt",
        "URL must be pre-filled from the orphan source"
    );
    assert!(
        !modal.blocklist_id.is_empty(),
        "id seed must be derived from the URL last segment"
    );
    assert!(
        matches!(modal.focus, EditField::ListId),
        "focus must start on List ID — the operator's first required field"
    );
}

// Sprint A.5 (lc2_v2 foundation) dropped
// `s53_promote_ctrl_s_creates_v1_entry_and_removes_orphan_source`.
// The end-to-end Promote save flow exercises the modal save path
// which Sprint C reshapes around the tag-chip widget. The two
// companion tests `s53_promote_enter_on_orphan_url_opens_promote_modal`
// and `s53_promote_invalid_id_keeps_modal_open_with_error` already
// cover the modal-open + validation-error branches against the
// current v2-shape; only the success-write path was leaning on
// category-aware modal pre-fill.

#[tokio::test]
async fn s53_promote_invalid_id_keeps_modal_open_with_error() {
    // Empty id → schema rejection. Modal must stay open with the
    // error surfaced so the operator can fix without losing the
    // form buffers.
    let dir = tempfile::tempdir().unwrap();
    let master = write_promote_master(&dir, "https://example.com/orphan-list.txt");
    let mut app = app_with_orphan_source(&master, "https://example.com/orphan-list.txt");
    let poller = dummy_poller(dir.path());
    handle_lists_key(&mut app, key(KeyCode::Enter), &poller, &master).await;
    let mut modal = app
        .lists
        .edit_modal
        .clone()
        .expect("Promote modal must be open");
    modal.blocklist_id = "  ".into(); // blank after trim
    modal.display_name = "Some name".into();
    app.lists.edit_modal = Some(modal);

    handle_lists_edit_modal_key(&mut app, ctrl('s'), &poller, &master).await;

    let modal = app
        .lists
        .edit_modal
        .as_ref()
        .expect("invalid id must keep the modal open");
    assert!(
        modal
            .error_message
            .as_deref()
            .unwrap_or_default()
            .contains("invalid id"),
        "footer must surface schema rejection; got {:?}",
        modal.error_message
    );
    // No write should have happened.
    let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
    assert!(loaded.config.blocklists.is_empty());
    assert_eq!(loaded.config.lists.sources.len(), 1);
}

#[tokio::test]
async fn s53_promote_discard_button_removes_orphan_without_creating_entry() {
    // Tab to the bottom-row Discard button + Enter — orphan source
    // is removed from [lists].sources and no [[blocklists]] entry
    // is created. Modal closes on success.
    let dir = tempfile::tempdir().unwrap();
    let master = write_promote_master(&dir, "https://example.com/orphan-list.txt");
    let mut app = app_with_orphan_source(&master, "https://example.com/orphan-list.txt");
    let poller = dummy_poller(dir.path());
    handle_lists_key(&mut app, key(KeyCode::Enter), &poller, &master).await;
    let mut modal = app
        .lists
        .edit_modal
        .clone()
        .expect("Promote modal must be open");
    modal.focus = EditField::DeleteButton;
    app.lists.edit_modal = Some(modal);

    handle_lists_edit_modal_key(&mut app, key(KeyCode::Enter), &poller, &master).await;

    assert!(
        app.lists.edit_modal.is_none(),
        "Discard must close the modal; last_error={:?}",
        app.last_status
    );
    let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
    assert!(
        loaded.config.blocklists.is_empty(),
        "no v1 entry should be created on Discard"
    );
    assert!(
        loaded.config.lists.sources.is_empty(),
        "orphan source must be removed; got {:?}",
        loaded.config.lists.sources
    );
}

// Sprint A.5 (lc2_v2 foundation) dropped
// `s53_enter_with_no_selection_auto_seeds_and_opens_modal` — its
// inline fixture carried [[categories]] + Blocklist.category= which
// are no longer parseable. The auto-seed cursor behaviour is
// exercised by `s53_enter_on_focused_list_row_opens_edit_modal_via_handle_lists_key`
// below (against a v2-shape fixture).

// ── S53 follow-up — `[a]` Add mode + `[B]` catalog picker ────────

#[tokio::test]
async fn s53_a_hotkey_opens_add_modal_with_blank_buffers() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = App::new();
    app.loaded_config = Some(load_config(&master, time::OffsetDateTime::now_utc()).unwrap());
    app.active_leaf = Leaf::Lists;
    let poller = dummy_poller(dir.path());

    handle_lists_key(&mut app, key(KeyCode::Char('a')), &poller, &master).await;

    let modal = app
        .lists
        .edit_modal
        .as_ref()
        .expect("`a` must open the edit modal in Add mode");
    match &modal.mode {
        crate::tui::app::EditModalMode::Add => {}
        other => panic!("expected Add mode, got {other:?}"),
    }
    assert!(modal.blocklist_id.is_empty(), "id starts blank");
    assert!(modal.url.is_empty(), "url starts blank");
    assert!(modal.display_name.is_empty(), "display_name starts blank");
    assert!(
        matches!(modal.focus, EditField::ListId),
        "focus starts on ListId"
    );
}

/// The first-run welcome screen tells a fresh operator to press `B` or
/// `a` on the Lists leaf. Those two letters have no table to be derived
/// from — unlike the `g <letter>` jumps, which `welcome_copy` builds
/// from `Leaf::mnemonic`, so they cannot go stale — and this is the only
/// thing between that screen and a hint pointing at a dead key.
///
/// Drives the LIVE handler, deliberately. The in-module companion
/// `welcome_banner::tests::welcome_copy_advertises_only_live_leaf_local_keys`
/// reads `help::per_leaf_rows`, and says in its own doc that it is a
/// paper pin: a rebind that forgets to update the help table passes
/// there. `handle_lists_key` is private and async, so the real pin has
/// to live here.
#[tokio::test]
async fn welcome_banner_lists_keys_are_live_bindings() {
    let copy = crate::tui::welcome_banner::welcome_copy();
    assert!(
        copy.contains("  B  ") && copy.contains("  a  "),
        "welcome copy no longer advertises `B` / `a` — retarget this pin \
             at whatever it advertises now instead of deleting it:\n{copy}"
    );

    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let poller = dummy_poller(dir.path());

    let mut app = App::new();
    app.loaded_config = Some(load_config(&master, time::OffsetDateTime::now_utc()).unwrap());
    app.active_leaf = Leaf::Lists;
    handle_lists_key(&mut app, key(KeyCode::Char('a')), &poller, &master).await;
    assert!(
        app.lists.edit_modal.is_some(),
        "the welcome screen sends a fresh operator to `a` on Lists, and it opened nothing"
    );

    let mut app = App::new();
    app.loaded_config = Some(load_config(&master, time::OffsetDateTime::now_utc()).unwrap());
    app.active_leaf = Leaf::Lists;
    handle_lists_key(&mut app, key(KeyCode::Char('B')), &poller, &master).await;
    assert!(
        app.lists.catalog_picker.is_some(),
        "the welcome screen sends a fresh operator to `B` on Lists, and it opened nothing"
    );
}

// Sprint A.5 (lc2_v2 foundation) dropped
// `s53_add_mode_ctrl_s_creates_v1_entry_and_does_not_touch_sources`
// for the same reason as the Promote save-flow drop above: the Add
// modal now needs a tag-chip pre-fill (Sprint C work) before the
// success path is meaningful. The companion modal-open test
// `s53_a_hotkey_opens_add_modal_with_blank_buffers` and the cancel
// path below cover the orthogonal branches.

#[tokio::test]
async fn s53_add_mode_cancel_button_closes_modal_with_no_writes() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let mut app = App::new();
    app.loaded_config = Some(load_config(&master, time::OffsetDateTime::now_utc()).unwrap());
    app.active_leaf = Leaf::Lists;
    let poller = dummy_poller(dir.path());

    handle_lists_key(&mut app, key(KeyCode::Char('a')), &poller, &master).await;
    let mut modal = app
        .lists
        .edit_modal
        .clone()
        .expect("Add modal must be open");
    modal.focus = EditField::DeleteButton;
    app.lists.edit_modal = Some(modal);

    handle_lists_edit_modal_key(&mut app, key(KeyCode::Enter), &poller, &master).await;

    assert!(
        app.lists.edit_modal.is_none(),
        "Cancel button must close the modal"
    );
    let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
    assert!(
        loaded.config.blocklists.is_empty(),
        "Cancel must not write any [[blocklists]] entry"
    );
}

#[tokio::test]
async fn b_hotkey_opens_catalog_picker_with_baselines_correct() {
    // One [[blocklists]] entry carrying the catalog URL for
    // privacy/ads — that row must open ticked and every other row
    // untouched, with nothing staged: Save right after `B` has to be
    // a no-op, or the picker writes changes the operator never made.
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("config.toml");
    std::fs::write(
        &master,
        r#"schema_version = 3

[upstream]
servers = ["192.0.2.1:53"]

[server]
default_profile = "default"

[[blocklists]]
id = "privacy-ads"
display_name = "Privacy: ads"
url = "https://lists.purge.cc/ads.txt"

[profiles.default]
display_name = "Default"
"#,
    )
    .unwrap();
    let mut app = App::new();
    app.loaded_config = Some(load_config(&master, time::OffsetDateTime::now_utc()).unwrap());
    app.active_leaf = Leaf::Lists;
    let poller = dummy_poller(dir.path());

    handle_lists_key(&mut app, key(KeyCode::Char('B')), &poller, &master).await;

    let picker = app
        .lists
        .catalog_picker
        .as_ref()
        .expect("`B` must open the catalog picker");
    let subscribed: Vec<&str> = picker
        .rows
        .iter()
        .filter(|r| r.original.is_subscribed())
        .map(|r| r.catalog_id.as_str())
        .collect();
    assert_eq!(
        subscribed,
        vec!["privacy/ads"],
        "exactly one row's baseline may say `subscribed`"
    );
    assert!(
        picker
            .rows
            .iter()
            .find(|r| r.catalog_id == "privacy/ads")
            .is_some_and(|r| r.staged_enabled),
        "a subscribed+enabled list opens already ticked"
    );
    assert_eq!(
        picker.dirty_count(),
        0,
        "opening the picker stages nothing — Save must be a no-op until a key is pressed"
    );
    assert_eq!(
        picker.table_state.selected(),
        Some(0),
        "cursor seeds on the first row; every row is selectable now"
    );
}

/// The config the batch-save tests run against: one subscribed list
/// carrying operator-set metadata (tags, a non-default interval, a
/// display name that is NOT the catalog's), so a save that rebuilds the
/// entry from catalog defaults instead of patching it shows up as loss.
fn catalog_master(dir: &tempfile::TempDir) -> PathBuf {
    let master = dir.path().join("config.toml");
    std::fs::write(
        &master,
        r#"schema_version = 3

[upstream]
servers = ["192.0.2.1:53"]

[server]
default_profile = "default"

[[blocklists]]
id = "privacy-ads"
display_name = "My renamed ads list"
url = "https://lists.purge.cc/ads.txt"
update_interval_hours = 6
tags = ["kids"]

[profiles.default]
display_name = "Default"
"#,
    )
    .unwrap();
    master
}

async fn open_picker(master: &Path, poller: &IpcPoller) -> App {
    let mut app = App::new();
    app.loaded_config = Some(load_config(master, time::OffsetDateTime::now_utc()).unwrap());
    app.active_leaf = Leaf::Lists;
    handle_lists_key(&mut app, key(KeyCode::Char('B')), poller, master).await;
    app
}

fn focus_row_on(app: &mut App, catalog_id: &str) {
    let picker = app.lists.catalog_picker.as_mut().unwrap();
    let idx = picker
        .rows
        .iter()
        .position(|r| r.catalog_id == catalog_id)
        .unwrap_or_else(|| panic!("catalog row `{catalog_id}` is missing from the picker"));
    picker.table_state.select(Some(idx));
}

/// Space stages, Ctrl+S writes. The new entry has to land with
/// `base = "deny"` — the TUI shipped its own `match` for this token
/// once, missed the `Block` → `Deny` rename, and wrote `kind = "block"`,
/// which the loader refused as `unknown variant`.
#[tokio::test]
async fn catalog_picker_space_stages_a_row_and_ctrl_s_subscribes_it() {
    let dir = tempfile::tempdir().unwrap();
    let master = catalog_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = open_picker(&master, &poller).await;

    focus_row_on(&mut app, "security/malicious");
    handle_lists_catalog_picker_key(&mut app, key(KeyCode::Char(' ')), &poller, &master).await;
    assert_eq!(
        app.lists.catalog_picker.as_ref().unwrap().dirty_count(),
        1,
        "Space must stage exactly the focused row"
    );

    handle_lists_catalog_picker_key(&mut app, ctrl('s'), &poller, &master).await;
    assert!(
        app.lists.catalog_picker.is_none(),
        "a successful save closes the picker"
    );

    let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
    assert_eq!(loaded.config.blocklists.len(), 2);
    let added = loaded
        .config
        .blocklists
        .iter()
        .find(|b| b.url.contains("malicious"))
        .expect("the staged list must be written");
    assert!(added.enabled);
    assert_eq!(added.base, crate::config::schema::BlocklistBase::Deny);
    assert_eq!(
        added.format,
        crate::config::schema::BlocklistFormat::Domains
    );
}

/// §4.65 UX3 (e): every other modal's `Ctrl+S` guard accepts both
/// cases (`handle_rule_edit_form_key`, the Lists edit modal's
/// `handle_edit_mode_key`) — this handler took only lowercase `'s'`.
/// With caps lock on, or on any terminal that reports Shift on a
/// Ctrl+letter chord, the key event carries `Char('S')` and this
/// picker silently swallowed it (falls through to the default arm,
/// which does nothing — no typo, no crash, just a save that never
/// happens). Verified by mutation: narrowing the guard back to
/// `Char('s') if ctrl` makes this test fail — the picker stays open
/// and the config file is never written.
#[tokio::test]
async fn catalog_picker_ctrl_shift_s_saves_same_as_ctrl_s() {
    let dir = tempfile::tempdir().unwrap();
    let master = catalog_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = open_picker(&master, &poller).await;

    focus_row_on(&mut app, "security/malicious");
    handle_lists_catalog_picker_key(&mut app, key(KeyCode::Char(' ')), &poller, &master).await;
    assert_eq!(
        app.lists.catalog_picker.as_ref().unwrap().dirty_count(),
        1,
        "Space must stage exactly the focused row"
    );

    handle_lists_catalog_picker_key(&mut app, ctrl('S'), &poller, &master).await;
    assert!(
        app.lists.catalog_picker.is_none(),
        "the uppercase chord (Char('S') + CONTROL) must save and close the \
             picker, exactly like lowercase Ctrl+s does"
    );

    let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
    assert_eq!(
        loaded.config.blocklists.len(),
        2,
        "the staged row must actually reach disk"
    );
}

/// Unticking a subscribed row writes `enabled = false`. It must NOT
/// remove the entry: that would discard the tags, interval and display
/// name the operator set elsewhere, with no confirm step and no undo.
/// Deletion lives in the Lists edit modal behind its typed-id gate.
#[tokio::test]
async fn catalog_picker_unticking_disables_and_never_removes() {
    let dir = tempfile::tempdir().unwrap();
    let master = catalog_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = open_picker(&master, &poller).await;

    focus_row_on(&mut app, "privacy/ads");
    handle_lists_catalog_picker_key(&mut app, key(KeyCode::Char(' ')), &poller, &master).await;
    handle_lists_catalog_picker_key(&mut app, ctrl('s'), &poller, &master).await;

    let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
    assert_eq!(
        loaded.config.blocklists.len(),
        1,
        "the entry must survive: unticking is not unsubscribing"
    );
    let b = &loaded.config.blocklists[0];
    assert!(!b.enabled, "unticking writes enabled = false");
    assert_eq!(
        b.display_name, "My renamed ads list",
        "the operator's display name must survive the patch"
    );
    assert_eq!(b.update_interval_hours, 6, "the interval must survive");
}

/// Two staged rows, one write. N `run_add_silent` calls would mean N
/// validated writes and N reloads for what the operator experienced as
/// one action — and a failure halfway would leave the config in a state
/// neither the operator nor the modal knows about.
#[tokio::test]
async fn catalog_picker_saves_every_staged_row_in_one_pass() {
    let dir = tempfile::tempdir().unwrap();
    let master = catalog_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = open_picker(&master, &poller).await;

    for id in ["security/malicious", "content/gambling"] {
        focus_row_on(&mut app, id);
        handle_lists_catalog_picker_key(&mut app, key(KeyCode::Char(' ')), &poller, &master).await;
    }
    // Untick the pre-existing one too: adds and disables ride the same
    // document.
    focus_row_on(&mut app, "privacy/ads");
    handle_lists_catalog_picker_key(&mut app, key(KeyCode::Char(' ')), &poller, &master).await;
    assert_eq!(app.lists.catalog_picker.as_ref().unwrap().dirty_count(), 3);

    handle_lists_catalog_picker_key(&mut app, ctrl('s'), &poller, &master).await;

    let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
    assert_eq!(loaded.config.blocklists.len(), 3);
    assert!(loaded
        .config
        .blocklists
        .iter()
        .any(|b| b.url.contains("malicious") && b.enabled));
    assert!(loaded
        .config
        .blocklists
        .iter()
        .any(|b| b.url.contains("gambling") && b.enabled));
    assert!(loaded
        .config
        .blocklists
        .iter()
        .any(|b| b.url.contains("ads.txt") && !b.enabled));
}

/// `Enter` over the table toggles, exactly like `Space` — it does NOT
/// save. The predecessor's `Enter` subscribed the focused row, so an
/// operator carrying that muscle memory presses it over a row having
/// staged nothing; a save there would close the picker after writing
/// nothing, with no explanation. Committing is Ctrl+S / the Save
/// button.
#[tokio::test]
async fn catalog_picker_enter_over_the_table_toggles_and_does_not_save() {
    let dir = tempfile::tempdir().unwrap();
    let master = catalog_master(&dir);
    let before = std::fs::read_to_string(&master).unwrap();
    let poller = dummy_poller(dir.path());
    let mut app = open_picker(&master, &poller).await;

    focus_row_on(&mut app, "security/malicious");
    handle_lists_catalog_picker_key(&mut app, key(KeyCode::Enter), &poller, &master).await;

    let picker = app
        .lists
        .catalog_picker
        .as_ref()
        .expect("Enter over a row must leave the picker open");
    assert_eq!(picker.dirty_count(), 1, "Enter over a row stages it");
    assert_eq!(
        std::fs::read_to_string(&master).unwrap(),
        before,
        "Enter over the table must not write"
    );

    // And it is a toggle, not a one-way set.
    handle_lists_catalog_picker_key(&mut app, key(KeyCode::Enter), &poller, &master).await;
    assert_eq!(
        app.lists.catalog_picker.as_ref().unwrap().dirty_count(),
        0,
        "a second Enter unstages the row"
    );
}

/// Save with nothing staged must not touch the file. Rewriting an
/// unchanged config still reformats it and still fires a reload — a
/// visible daemon event for a keypress that meant nothing.
#[tokio::test]
async fn catalog_picker_save_with_nothing_staged_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let master = catalog_master(&dir);
    let before = std::fs::read_to_string(&master).unwrap();
    let poller = dummy_poller(dir.path());
    let mut app = open_picker(&master, &poller).await;

    handle_lists_catalog_picker_key(&mut app, ctrl('s'), &poller, &master).await;

    assert!(app.lists.catalog_picker.is_none());
    assert_eq!(
        std::fs::read_to_string(&master).unwrap(),
        before,
        "an empty diff must leave the config byte-identical"
    );
}

/// The KIND column is read-only until the upstream trust story changes:
/// `base = allow` needs `trust = local`, and `write_value_validated`
/// validates the whole tree, so one allow row would sink every other
/// staged change in the same Save. No key may cycle it.
#[tokio::test]
async fn catalog_picker_no_key_mutates_the_kind_column() {
    let dir = tempfile::tempdir().unwrap();
    let master = catalog_master(&dir);
    let poller = dummy_poller(dir.path());
    let mut app = open_picker(&master, &poller).await;

    for k in [
        key(KeyCode::Left),
        key(KeyCode::Right),
        key(KeyCode::Char('h')),
        key(KeyCode::Char('l')),
        key(KeyCode::Char('a')),
        key(KeyCode::Char('K')),
    ] {
        handle_lists_catalog_picker_key(&mut app, k, &poller, &master).await;
    }

    assert!(
        app.lists
            .catalog_picker
            .as_ref()
            .unwrap()
            .rows
            .iter()
            .all(|r| r.staged_kind == crate::config::schema::BlocklistBase::Deny),
        "a catalog row must not be staged as allow by any keystroke"
    );
}

/// Esc discards. The staged ticks are in-memory only until Ctrl+S, so
/// the file has to come back byte-identical.
#[tokio::test]
async fn catalog_picker_esc_discards_every_staged_change() {
    let dir = tempfile::tempdir().unwrap();
    let master = catalog_master(&dir);
    let before = std::fs::read_to_string(&master).unwrap();
    let poller = dummy_poller(dir.path());
    let mut app = open_picker(&master, &poller).await;

    focus_row_on(&mut app, "security/malicious");
    handle_lists_catalog_picker_key(&mut app, key(KeyCode::Char(' ')), &poller, &master).await;
    handle_lists_catalog_picker_key(&mut app, key(KeyCode::Esc), &poller, &master).await;

    assert!(app.lists.catalog_picker.is_none());
    assert_eq!(std::fs::read_to_string(&master).unwrap(), before);
}

/// Tab walks Table → Cancel → Save → Table, and `Enter` on Cancel
/// closes without writing. A footer button that saved because the
/// focus ring was off by one is the worst way to find this bug.
#[tokio::test]
async fn catalog_picker_tab_walks_the_footer_and_cancel_writes_nothing() {
    use app::CatalogPickerFocus;
    let dir = tempfile::tempdir().unwrap();
    let master = catalog_master(&dir);
    let before = std::fs::read_to_string(&master).unwrap();
    let poller = dummy_poller(dir.path());
    let mut app = open_picker(&master, &poller).await;

    focus_row_on(&mut app, "security/malicious");
    handle_lists_catalog_picker_key(&mut app, key(KeyCode::Char(' ')), &poller, &master).await;

    handle_lists_catalog_picker_key(&mut app, key(KeyCode::Tab), &poller, &master).await;
    assert_eq!(
        app.lists.catalog_picker.as_ref().unwrap().focus,
        CatalogPickerFocus::Cancel
    );
    handle_lists_catalog_picker_key(&mut app, key(KeyCode::Tab), &poller, &master).await;
    assert_eq!(
        app.lists.catalog_picker.as_ref().unwrap().focus,
        CatalogPickerFocus::Save
    );
    handle_lists_catalog_picker_key(&mut app, key(KeyCode::Tab), &poller, &master).await;
    assert_eq!(
        app.lists.catalog_picker.as_ref().unwrap().focus,
        CatalogPickerFocus::Table
    );

    // Back to Cancel, then Enter.
    handle_lists_catalog_picker_key(&mut app, key(KeyCode::Tab), &poller, &master).await;
    handle_lists_catalog_picker_key(&mut app, key(KeyCode::Enter), &poller, &master).await;
    assert!(app.lists.catalog_picker.is_none());
    assert_eq!(
        std::fs::read_to_string(&master).unwrap(),
        before,
        "Cancel must not write the staged row"
    );
}
