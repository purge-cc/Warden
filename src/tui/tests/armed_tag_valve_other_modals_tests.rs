use super::*;
use crate::tui::app::{App, Leaf};

fn k(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn ctrl_s() -> KeyEvent {
    KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL)
}

fn poller() -> IpcPoller {
    IpcPoller::new(Path::new("/nonexistent/purge-warden-armed-valve.sock"))
}

/// A real, valid master config in a tempdir.
///
/// **The pre-N14 version of this module used a nonexistent path, and
/// that stopped being adequate the moment the chord started saving.**
/// Subnets and Groups keep the form OPEN on a failed submit, so
/// against a missing config the submit fails, the form survives, and
/// the pending slug survives with it — nothing is dropped, so nothing
/// is announced, and the test would fail while the code was right.
/// (Which it did, first run: `subnet modal: id is required`.) The save
/// has to actually land for the drop to be real.
fn mk_cfg(dir: &tempfile::TempDir) -> PathBuf {
    let master = dir.path().join("config.toml");
    std::fs::write(
            &master,
            "schema_version = 3\n\n             [upstream]\nservers = [\"192.0.2.1:53\"]\n\n             [server]\ndefault_profile = \"default\"\n\n             [profiles.default]\ndisplay_name = \"Default\"\n",
        )
        .unwrap();
    master
}

// `plp-s5d` removed the `arm_valve_then_ctrl_s!` macro and its two
// remaining users, `ctrl_s_saves_the_subnet_modal_and_reports_the_dropped_tag`
// and `ctrl_s_saves_the_group_modal_and_reports_the_dropped_tag`.
//
// They armed the §4.65 UX2 valve (a typed slug waiting on a second
// `Enter`), sent `Ctrl+s`, and asserted the save both FIRED and
// announced the slug it dropped. Neither modal has a picker any more,
// so there is no valve to arm and no slug to drop — the whole
// `dropped_tag_leads` notice went with the pickers in these two submit
// paths.
//
// **N14 itself is not a tag guarantee and does NOT retire with them**,
// so it is retargeted rather than dropped — the same move `plp-s4c`
// made for the profile modal's half, whose replacement sits directly
// below. What N14 says is that `Ctrl+S` reaches the submit path from
// ANY field instead of falling through to `KeyCode::Char(c)` and
// appending a literal `s`; the two tests below assert exactly that,
// standing on the last field in each Edit ring, which is where an
// operator is most likely to be when they reach for the chord.

#[tokio::test]
async fn ctrl_s_saves_the_subnet_modal_from_the_last_field() {
    use crate::tui::subnet_modal::{FormField, FormMode, Stage, SubnetModal};

    let dir = tempfile::tempdir().unwrap();
    let cfg = mk_cfg(&dir);
    let mut app = App::new();
    // **Stand on the leaf that owns the modal.** A default `App` sits
    // on Dashboard, which is in `poll_active_leaf`'s polling cohort, so
    // the post-save poll fails against the ghost socket and REPLACES
    // the status this test reads. Subnets and Groups are in the offline
    // cohort and never poll, which is why production never sees that.
    app.active_leaf = Leaf::Subnets;
    let mut modal = SubnetModal::open_add(vec!["default".to_string()], 0);
    match &mut modal.stage {
        Stage::EditingForm(f) => {
            // `mode = Add` so the save can complete against the fixture
            // config: Edit needs an `original` snapshot, and a form that
            // cannot save proves nothing about the chord.
            f.mode = FormMode::Add;
            f.id = "lan".into();
            f.display_name = "LAN".into();
            f.cidrs = "192.0.2.0/24".into();
            f.priority_input = "7".into();
            f.focused = FormField::Priority;
        }
        other => panic!("expected EditingForm, got {other:?}"),
    }
    app.subnets.modal = Some(modal);

    handle_subnet_modal_key(&mut app, ctrl_s(), &poller(), &cfg).await;

    // The chord reached the submit path. Pre-N14 it was swallowed, or
    // appended a literal `s` to the focused field and left the form in
    // `EditingForm` — which is what the panic message names, because a
    // bare "didn't submit" would not tell the next reader which of the
    // two regressions they are looking at.
    match &app.subnets.modal.as_ref().expect("modal still open").stage {
        Stage::Submitted(_) => {}
        other => panic!(
            "Ctrl+s from the last field must reach the submit path — it was \
                 swallowed, or it appended a literal `s` the way it did before \
                 N14. Got {other:?}"
        ),
    }
}

#[tokio::test]
async fn ctrl_s_saves_the_group_modal_from_the_last_field() {
    use crate::tui::group_modal::{FormField, FormMode, GroupModal, Stage};

    let dir = tempfile::tempdir().unwrap();
    let cfg = mk_cfg(&dir);
    let mut app = App::new();
    app.active_leaf = Leaf::Groups;
    let mut modal = GroupModal::open_add(vec!["default".to_string()], 0);
    match &mut modal.stage {
        Stage::EditingForm(f) => {
            f.mode = FormMode::Add;
            f.id = "phones".into();
            f.display_name = "Phones".into();
            f.priority_input = "7".into();
            f.focused = FormField::Priority;
        }
        other => panic!("expected EditingForm, got {other:?}"),
    }
    app.groups.modal = Some(modal);

    handle_group_modal_key(&mut app, ctrl_s(), &poller(), &cfg).await;

    match &app.groups.modal.as_ref().expect("modal still open").stage {
        Stage::Submitted(_) => {}
        other => panic!(
            "Ctrl+s from the last field must reach the submit path — it was \
                 swallowed, or it appended a literal `s` the way it did before \
                 N14. Got {other:?}"
        ),
    }
}

/// The profile modal's half of `arm_valve_then_ctrl_s!` retired with
/// the tag picker it armed: this form no longer has one, so there is
/// no slug for a save to drop and nothing to report. The macro is
/// still exercised by the Subnets and Groups twins above.
///
/// N14 still has to hold on the field that replaced it, and that is
/// what this asserts: `Ctrl+S` saves from a per-list override row,
/// which is the deepest field in the Edit ring and therefore the one
/// an operator is most likely to be standing on. Written against a
/// ghost socket, so the save FAILS — which is still the point, just not
/// the same point it used to be.
///
/// **`profile-01` (2026-08-28 review) inverted the passing signal.**
/// Before that fix, `submit_profile_modal` dropped to `Stage::Submitted`
/// on every outcome including a refused save, so this test's proof that
/// "the chord did something" was `Stage::Submitted(_)` — a modal still
/// in `EditingForm` meant the keystroke never reached the submit path.
/// After the fix, a `Failed` outcome deliberately KEEPS the form open
/// (mirrors `submit_subnet_modal` / `submit_local_dns_modal`), so
/// `Stage::Submitted(_)` is no longer reachable from this path at all —
/// asserting it here would be asserting the regression `profile-01`
/// fixed. The signal that the chord was not swallowed is now
/// `form.error_message` carrying the poller's refusal.
#[tokio::test]
async fn ctrl_s_saves_the_profile_modal_from_a_list_override_row() {
    use crate::tui::profile_modal::{FormField, ProfileModal, Stage};

    let dir = tempfile::tempdir().unwrap();
    let cfg = mk_cfg(&dir);
    let mut app = App::new();
    app.active_leaf = Leaf::Profiles;
    let profile = crate::config::schema::Profile::default();
    let lists = vec![
        toml::from_str::<crate::config::schema::blocklist::Blocklist>(
            "id = \"ads\"\ndisplay_name = \"Ads\"\nurl = \"https://lists.invalid/ads.txt\"\n",
        )
        .unwrap(),
    ];
    let mut modal = ProfileModal::open_edit("kids", &profile, lists, vec![]);
    match &mut modal.stage {
        Stage::EditingForm(f) => {
            f.focused = FormField::ListOverride(0);
            // Focus alone stages no diff — `resolve_edit_patch` would see
            // an empty patch and short-circuit to "unchanged" before ever
            // dialling the poller, proving nothing about profile-01's
            // guard. `cycle_dropdown` is a no-op on `ListOverride` by
            // design (see its own exhaustive match); `cycle_list_policy`
            // is the row's actual mutator, so use that to stage a real
            // change for the ghost socket to refuse.
            f.cycle_list_policy(true);
        }
        other => panic!("expected EditingForm, got {other:?}"),
    }
    app.profiles.modal = Some(modal);

    let mut ctrl_s = k(KeyCode::Char('s'));
    ctrl_s.modifiers = KeyModifiers::CONTROL;
    handle_profile_modal_key(&mut app, ctrl_s, &poller(), &cfg).await;

    match &app.profiles.modal.as_ref().expect("modal still open").stage {
        Stage::EditingForm(f) => assert!(
            f.error_message.is_some(),
            "Ctrl+S on a panel row must reach the submit path and report the \
             refusal, not sit silent — it was swallowed if error_message is None"
        ),
        other => panic!("a refused save must keep the form open (profile-01), got {other:?}"),
    }
}

/// `profile-01`, direct: a refused Add needs no daemon round-trip — `id`
/// is validated locally in `try_resolve_add` before the poller is ever
/// dialled — so this is the plainest repro of "leaves the form open
/// with the operator's typed fields intact," independent of the Ctrl+S
/// chord/IPC-refusal path the test above covers.
#[tokio::test]
async fn refused_profile_add_keeps_the_form_open_with_typed_fields_intact() {
    use crate::tui::profile_modal::{ProfileModal, Stage};

    let dir = tempfile::tempdir().unwrap();
    let cfg = mk_cfg(&dir);
    let mut app = App::new();
    app.active_leaf = Leaf::Profiles;

    let mut modal = ProfileModal::open_add();
    match &mut modal.stage {
        // `id` stays blank on purpose — that is what `try_resolve_add`
        // refuses. `display_name` is the operator-typed content that
        // must survive the refusal.
        Stage::EditingForm(f) => f.display_name = "My Kids Profile".to_string(),
        other => panic!("expected EditingForm, got {other:?}"),
    }
    app.profiles.modal = Some(modal);

    handle_profile_modal_key(&mut app, ctrl_s(), &poller(), &cfg).await;

    match &app
        .profiles
        .modal
        .as_ref()
        .expect("form must stay open")
        .stage
    {
        Stage::EditingForm(f) => {
            assert_eq!(
                f.display_name, "My Kids Profile",
                "the operator's typed field must survive a refused save"
            );
            assert_eq!(
                f.error_message.as_deref(),
                Some("id is required"),
                "the refusal must land on the form's own error line"
            );
        }
        other => panic!("a refused Add must keep the form open (profile-01), got {other:?}"),
    }
}

/// Open an Edit modal on a profile that already declares overrides,
/// with three lists in the panel.
fn profile_modal_with_lists() -> crate::tui::profile_modal::ProfileModal {
    use crate::config::schema::blocklist::{Blocklist, ListPolicy};
    use crate::config::schema::{Id, Profile};
    let lists: Vec<Blocklist> = ["ads", "news", "social"]
            .iter()
            .map(|id| {
                toml::from_str::<Blocklist>(&format!(
                    "id = \"{id}\"\ndisplay_name = \"{id}\"\nurl = \"https://lists.invalid/{id}.txt\"\n"
                ))
                .unwrap()
            })
            .collect();
    let profile = Profile {
        lists: std::collections::BTreeMap::from([
            (Id::new("ads").unwrap(), ListPolicy::Allow),
            (Id::new("social").unwrap(), ListPolicy::Ignore),
        ]),
        ..Default::default()
    };
    crate::tui::profile_modal::ProfileModal::open_edit("kids", &profile, lists, vec![])
}

/// **The `_` arm this dispatch used to have was the hazard.**
///
/// `KeyCode::Right`'s match fell through to `form.cycle_dropdown(true)`
/// for every field it did not name. Adding a panel row without an arm
/// would have sent the operator's arrow into `block_response_idx` or
/// `ecs_mode_idx` — an edit to a field they are not looking at, and one
/// a test that only checked "the list policy changed" would never see.
/// So this asserts on the fields that must NOT move.
#[tokio::test]
async fn an_arrow_on_a_panel_row_touches_no_other_field() {
    use crate::tui::profile_modal::{FormField, Stage};

    let dir = tempfile::tempdir().unwrap();
    let cfg = mk_cfg(&dir);
    let mut app = App::new();
    app.active_leaf = Leaf::Profiles;
    let mut modal = profile_modal_with_lists();
    match &mut modal.stage {
        Stage::EditingForm(f) => {
            f.focused = FormField::ListOverride(1);
            f.block_response_idx = 2;
            f.ecs_mode_idx = 3;
        }
        other => panic!("expected EditingForm, got {other:?}"),
    }
    app.profiles.modal = Some(modal);

    for code in [KeyCode::Right, KeyCode::Left, KeyCode::Char(' ')] {
        handle_profile_modal_key(&mut app, k(code), &poller(), &cfg).await;
    }

    match &app.profiles.modal.as_ref().unwrap().stage {
        Stage::EditingForm(f) => {
            assert_eq!(f.block_response_idx, 2, "block_response must not move");
            assert_eq!(f.ecs_mode_idx, 3, "ecs mode must not move");
            assert_eq!(
                f.focused,
                FormField::ListOverride(1),
                "an arrow changes the value, never the focus"
            );
        }
        other => panic!("modal must still be editing, got {other:?}"),
    }
}

/// `i` twice, through the real dispatch — the half of decision D that
/// says `ignore` has to be REACHABLE from the TUI.
///
/// Through the handler and not just `press_ignore` because the wiring
/// is what breaks: `i` sits inside the `KeyCode::Char(c)` arm next to
/// the text-buffer fallthrough, and a form whose `text_field_buf`
/// answered for a panel row would swallow it.
#[tokio::test]
async fn i_twice_declares_ignore_through_the_key_handler() {
    use crate::config::schema::blocklist::ListPolicy;
    use crate::config::schema::Id;
    use crate::tui::profile_modal::{FormField, Stage};

    let dir = tempfile::tempdir().unwrap();
    let cfg = mk_cfg(&dir);
    let mut app = App::new();
    app.active_leaf = Leaf::Profiles;
    let mut modal = profile_modal_with_lists();
    match &mut modal.stage {
        Stage::EditingForm(f) => f.focused = FormField::ListOverride(1), // news
        other => panic!("expected EditingForm, got {other:?}"),
    }
    app.profiles.modal = Some(modal);
    let news = Id::new("news").unwrap();

    handle_profile_modal_key(&mut app, k(KeyCode::Char('i')), &poller(), &cfg).await;
    match &app.profiles.modal.as_ref().unwrap().stage {
        Stage::EditingForm(f) => {
            assert_eq!(f.lists_draft.get(&news), None, "one press only arms");
            assert_eq!(f.ignore_armed, Some(1));
        }
        other => panic!("{other:?}"),
    }

    handle_profile_modal_key(&mut app, k(KeyCode::Char('i')), &poller(), &cfg).await;
    match &app.profiles.modal.as_ref().unwrap().stage {
        Stage::EditingForm(f) => {
            assert_eq!(f.lists_draft.get(&news), Some(&ListPolicy::Ignore));
        }
        other => panic!("{other:?}"),
    }
}

/// Any other letter between the two presses disarms, so the
/// deliberation has to be two CONSECUTIVE presses.
#[tokio::test]
async fn a_stray_letter_disarms_the_ignore_valve() {
    use crate::config::schema::blocklist::ListPolicy;
    use crate::config::schema::Id;
    use crate::tui::profile_modal::{FormField, Stage};

    let dir = tempfile::tempdir().unwrap();
    let cfg = mk_cfg(&dir);
    let mut app = App::new();
    app.active_leaf = Leaf::Profiles;
    let mut modal = profile_modal_with_lists();
    match &mut modal.stage {
        Stage::EditingForm(f) => f.focused = FormField::ListOverride(1),
        other => panic!("expected EditingForm, got {other:?}"),
    }
    app.profiles.modal = Some(modal);

    for c in ['i', 'x', 'i'] {
        handle_profile_modal_key(&mut app, k(KeyCode::Char(c)), &poller(), &cfg).await;
    }
    match &app.profiles.modal.as_ref().unwrap().stage {
        Stage::EditingForm(f) => assert_ne!(
            f.lists_draft.get(&Id::new("news").unwrap()),
            Some(&ListPolicy::Ignore),
            "i · x · i must not commit — the two presses have to be consecutive"
        ),
        other => panic!("{other:?}"),
    }
}

/// **DoD 4, at the handler.** Walking the whole panel and backing out
/// with `Esc` must leave the profile's declarations exactly as the
/// file had them.
///
/// The patch is resolved BEFORE the `Esc`, because after it the modal
/// is gone and any assertion would be about a value the product
/// preserves in every outcome — vacuous. What is measured is that
/// NAVIGATION (which moves focus, disarms valves and clears errors)
/// does not mutate the draft.
#[tokio::test]
async fn walking_the_panel_and_pressing_esc_declares_nothing() {
    use crate::ipc::protocol::ProfileUpdatePatch;
    use crate::tui::profile_modal::{resolve_edit_patch, FormField, Stage};

    let dir = tempfile::tempdir().unwrap();
    let cfg = mk_cfg(&dir);
    let mut app = App::new();
    app.active_leaf = Leaf::Profiles;
    app.profiles.modal = Some(profile_modal_with_lists());

    // Down through every field including all three panel rows, then
    // back up again.
    for code in [KeyCode::Down, KeyCode::Up] {
        for _ in 0..14 {
            handle_profile_modal_key(&mut app, k(code), &poller(), &cfg).await;
        }
    }

    match &app.profiles.modal.as_ref().expect("still open").stage {
        Stage::EditingForm(f) => {
            assert!(
                matches!(f.focused, FormField::ListOverride(_))
                    || f.visible_fields().contains(&f.focused),
                "focus stayed inside the ring"
            );
            let patch = resolve_edit_patch(f, f.original.as_ref().unwrap()).unwrap();
            assert_eq!(
                patch,
                ProfileUpdatePatch::default(),
                "navigating the panel is not an edit: {patch:?}"
            );
        }
        other => panic!("{other:?}"),
    }

    handle_profile_modal_key(&mut app, k(KeyCode::Esc), &poller(), &cfg).await;
    assert!(app.profiles.modal.is_none(), "Esc closes the modal");
}
