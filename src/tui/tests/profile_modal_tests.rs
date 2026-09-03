use super::*;
use crate::config::schema::blocklist::BlocklistBase;

use crate::config::schema::BlocklistTrust;

/// A `[[blocklists]]` row for the override panel's tests.
///
/// Domains use the RFC 2606 `.invalid` TLD: a fixture must not name a
/// real provider, and `src/` must not carry third-party domain
/// knowledge in either direction (CLAUDE.md Rule 10).
fn mk_list(id: &str, base: BlocklistBase, trust: BlocklistTrust, ack: bool) -> Blocklist {
    Blocklist {
        id: Id::new(id).unwrap(),
        display_name: id.to_string(),
        url: format!("https://lists.invalid/{id}.txt"),
        format: Default::default(),
        update_interval_hours: 12,
        max_entries: 1_000_000,
        enabled: true,
        auth_token_ref: None,
        base,
        trust,
        accept_unsigned_allow: ack,
        max_consecutive_failures: 5,
    }
}

/// Two deny-base lists and one allow-base list, id-ordered as
/// `build_profile_edit_modal` hands them over.
fn mk_lists() -> Vec<Blocklist> {
    vec![
        mk_list(
            "ads",
            BlocklistBase::Deny,
            BlocklistTrust::RemoteUnsigned,
            false,
        ),
        mk_list("news", BlocklistBase::Allow, BlocklistTrust::Local, false),
        mk_list(
            "social",
            BlocklistBase::Deny,
            BlocklistTrust::RemoteUnsigned,
            false,
        ),
    ]
}

/// Two `[[custom_lists]]` rows for the mount panel's tests, id-ordered
/// as `build_profile_edit_modal` hands them over.
fn mk_custom_lists() -> Vec<CustomList> {
    ["handheld", "home-exceptions"]
        .into_iter()
        .map(|id| CustomList {
            id: Id::new(id).unwrap(),
            display_name: id.to_string(),
            description: String::new(),
        })
        .collect()
}

fn mk_profile() -> Profile {
    Profile {
        display_name: "Kids".into(),
        block_response: Some(BlockResponseV1::Nxdomain),
        blocked_ttl_secs: Some(60),
        block_all: true,
        admin_rules: vec![
            crate::config::schema::Id::new("rule-a").unwrap(),
            crate::config::schema::Id::new("rule-b").unwrap(),
        ],
        ecs: Some(ProfileEcsConfig {
            mode: Some(EcsMode::Coarse),
            source_prefix_v4: Some(24),
            source_prefix_v6: None,
        }),
        ..Default::default()
    }
}

// ── Field navigation ──────────────────────────────────────────────

#[test]
fn add_form_cycles_four_fields() {
    let mut f = ProfileForm::new_add();
    assert_eq!(f.focused, FormField::Id);
    f.focus_next();
    assert_eq!(f.focused, FormField::DisplayName);
    f.focus_next();
    assert_eq!(f.focused, FormField::Submit);
    f.focus_next();
    assert_eq!(f.focused, FormField::Cancel, "Discard button is last");
    f.focus_next();
    assert_eq!(f.focused, FormField::Id, "Add form wraps after Cancel");
}

#[test]
fn edit_form_cycles_head_then_every_list_then_tail_skipping_id() {
    let mut f = ProfileForm::new_edit("kids", &mk_profile(), mk_lists(), mk_custom_lists());
    assert_eq!(f.focused, FormField::DisplayName, "Edit starts past Id");
    let order = [
        FormField::BlockResponse,
        FormField::BlockedTtl,
        FormField::BlockAll,
        FormField::AdminRules,
        FormField::EcsMode,
        FormField::EcsPrefixV4,
        FormField::EcsPrefixV6,
        FormField::EcsClear,
        // One focus target per configured blocklist, in snapshot order.
        FormField::ListOverride(0),
        FormField::ListOverride(1),
        FormField::ListOverride(2),
        // Then one per declared custom list, AFTER the overrides — the
        // order the body renders them in. A ring that disagreed would
        // scroll to the wrong panel.
        FormField::CustomListMount(0),
        FormField::CustomListMount(1),
        FormField::Submit,
        FormField::Cancel,
        FormField::DisplayName,
    ];
    for expected in order {
        f.focus_next();
        assert_eq!(f.focused, expected);
    }
    // Id is never visited in Edit mode.
    f.focus_prev();
    assert_eq!(f.focused, FormField::Cancel, "prev from DisplayName wraps");
}

/// A config with no `[[blocklists]]` and no `[[custom_lists]]` must not
/// put a row in either ring that answers no key — and must not index an
/// empty snapshot.
#[test]
fn edit_form_ring_tolerates_zero_configured_lists() {
    let mut f = ProfileForm::new_edit("kids", &mk_profile(), Vec::new(), Vec::new());
    let ring = f.visible_fields();
    assert!(
        !ring.iter().any(|x| matches!(x, FormField::ListOverride(_))),
        "no panel rows without lists: {ring:?}"
    );
    assert!(
        !ring
            .iter()
            .any(|x| matches!(x, FormField::CustomListMount(_))),
        "no mount rows without custom lists: {ring:?}"
    );
    // Walk the whole ring twice; a panic here is the regression.
    for _ in 0..(ring.len() * 2) {
        f.focus_next();
    }
    assert_eq!(f.focused, FormField::DisplayName);
    f.focused = FormField::EcsClear;
    f.focus_next();
    assert_eq!(
        f.focused,
        FormField::Submit,
        "with no lists the head runs straight into the tail"
    );
}

// ── Edit snapshot capture ─────────────────────────────────────────

#[test]
fn edit_modal_captures_full_snapshot_at_open() {
    let modal = ProfileModal::open_edit("kids", &mk_profile(), vec![], vec![]);
    let form = modal.form().unwrap();
    assert_eq!(form.mode, FormMode::Edit);
    let orig = form.original.as_ref().expect("Edit captures a snapshot");
    assert_eq!(orig.id, "kids");
    assert_eq!(orig.display_name, "Kids");
    assert_eq!(orig.block_response, Some(BlockResponseV1::Nxdomain));
    assert_eq!(orig.blocked_ttl_secs, Some(60));
    assert!(orig.block_all);
    assert_eq!(orig.admin_rules, vec!["rule-a", "rule-b"]);
    assert_eq!(orig.ecs.as_ref().unwrap().mode, Some(EcsMode::Coarse));
    // Form buffers pre-filled from the snapshot.
    assert_eq!(form.block_response_idx, 2); // nxdomain
    assert_eq!(form.blocked_ttl_input, "60");
    assert_eq!(form.admin_rules_input, "rule-a, rule-b");
    assert_eq!(form.ecs_mode_idx, 2); // coarse
    assert_eq!(form.ecs_v4_input, "24");
    assert_eq!(form.ecs_v6_input, "");
}

// ── resolve_edit_patch — the heart of the modal ───────────────────

#[test]
fn resolve_empty_patch_when_nothing_changed() {
    let modal = ProfileModal::open_edit("kids", &mk_profile(), vec![], vec![]);
    let form = modal.form().unwrap();
    let patch = resolve_edit_patch(form, form.original.as_ref().unwrap()).unwrap();
    assert_eq!(
        patch,
        ProfileUpdatePatch::default(),
        "an untouched Edit form must produce an empty patch"
    );
}

#[test]
fn resolve_block_response_inherit_emits_some_none() {
    let mut modal = ProfileModal::open_edit("kids", &mk_profile(), vec![], vec![]);
    let form = modal.form_mut().unwrap();
    form.block_response_idx = 0; // (inherit)
    let patch = resolve_edit_patch(form, form.original.as_ref().unwrap()).unwrap();
    assert_eq!(
        patch.block_response,
        Some(None),
        "picking (inherit) clears block_response to inherit"
    );
}

#[test]
fn resolve_blank_display_name_falls_back_to_the_id() {
    // The field's own placeholder promises "blank = the id"
    // (`form_body`'s `display name` row, `Some("blank = the id")`).
    // Writing a literal empty string instead would contradict it and
    // blank the operator's table row.
    let mut modal = ProfileModal::open_edit("kids", &mk_profile(), vec![], vec![]);
    let form = modal.form_mut().unwrap();
    form.display_name = "   ".into(); // blank after trim
    let patch = resolve_edit_patch(form, form.original.as_ref().unwrap()).unwrap();
    assert_eq!(
        patch.display_name.as_deref(),
        Some("kids"),
        "a blank display_name must default to the id"
    );
}

#[test]
fn resolve_untouched_form_with_already_blank_display_name_emits_no_patch() {
    // Regression: a profile whose display_name is already blank on disk
    // (built via `..Default::default()`, a common test-fixture shape —
    // see the integration cohort's `profile_modal_with_lists`) must diff
    // as UNCHANGED when the operator never touches the field. Change
    // detection has to run on the raw buffer against the raw original,
    // not on the id-substituted one, or merely navigating the form with
    // no edit at all would synthesize a display_name patch.
    let profile = Profile {
        display_name: String::new(),
        ..Default::default()
    };
    let modal = ProfileModal::open_edit("kids", &profile, vec![], vec![]);
    let form = modal.form().unwrap();
    let patch = resolve_edit_patch(form, form.original.as_ref().unwrap()).unwrap();
    assert_eq!(
        patch,
        ProfileUpdatePatch::default(),
        "an untouched form must produce an empty patch even when the \
         original display_name is itself blank"
    );
}

#[test]
fn resolve_block_response_set_emits_some_some() {
    let p = Profile {
        block_response: None,
        ..mk_profile()
    };
    let mut modal = ProfileModal::open_edit("kids", &p, vec![], vec![]);
    let form = modal.form_mut().unwrap();
    form.block_response_idx = 3; // refused
    let patch = resolve_edit_patch(form, form.original.as_ref().unwrap()).unwrap();
    assert_eq!(patch.block_response, Some(Some(BlockResponseV1::Refused)));
}

#[test]
fn resolve_blocked_ttl_empty_emits_some_none() {
    let mut modal = ProfileModal::open_edit("kids", &mk_profile(), vec![], vec![]);
    let form = modal.form_mut().unwrap();
    form.blocked_ttl_input.clear(); // empty = inherit
    let patch = resolve_edit_patch(form, form.original.as_ref().unwrap()).unwrap();
    assert_eq!(patch.blocked_ttl_secs, Some(None));
}

#[test]
fn resolve_bad_ttl_returns_err() {
    let mut modal = ProfileModal::open_edit("kids", &mk_profile(), vec![], vec![]);
    let form = modal.form_mut().unwrap();
    form.blocked_ttl_input = "abc".into();
    let err = resolve_edit_patch(form, form.original.as_ref().unwrap()).unwrap_err();
    assert!(err.contains("blocked_ttl_secs"), "got: {err}");
}

#[test]
fn resolve_admin_rules_diff_computes_add_and_remove() {
    let mut modal = ProfileModal::open_edit("kids", &mk_profile(), vec![], vec![]);
    let form = modal.form_mut().unwrap();
    // snapshot is "rule-a, rule-b" → keep b, drop a, add c.
    form.admin_rules_input = "rule-b, rule-c".into();
    let patch = resolve_edit_patch(form, form.original.as_ref().unwrap()).unwrap();
    let ar = patch.admin_rules.expect("admin_rules delta present");
    assert_eq!(ar.add, vec!["rule-c"]);
    assert_eq!(ar.remove, vec!["rule-a"]);
}

#[test]
fn resolve_admin_rules_dedups_typed_duplicates() {
    let mut modal = ProfileModal::open_edit("kids", &mk_profile(), vec![], vec![]);
    let form = modal.form_mut().unwrap();
    // Operator types the same new id twice; the add delta must carry
    // it exactly once, not emit a duplicate into the patch.
    form.admin_rules_input = "rule-a, rule-b, rule-c, rule-c".into();
    let patch = resolve_edit_patch(form, form.original.as_ref().unwrap()).unwrap();
    let ar = patch.admin_rules.expect("admin_rules delta present");
    assert_eq!(ar.add, vec!["rule-c"]);
    assert!(ar.remove.is_empty());
}

// ── plp §4 S4: the per-list override delta ────────────────────────

#[test]
fn resolve_lists_delta_sets_a_declared_override() {
    let mut modal = ProfileModal::open_edit("kids", &mk_profile(), mk_lists(), vec![]);
    let form = modal.form_mut().unwrap();
    form.focused = FormField::ListOverride(2); // social
    form.cycle_list_policy(true); // inherit -> Block (explicit)
    let patch = resolve_edit_patch(form, form.original.as_ref().unwrap()).unwrap();
    let lp = patch.lists.expect("lists delta present");
    assert_eq!(lp.set.get("social"), Some(&ListPolicy::Deny));
    assert!(lp.clear.is_empty());
}

#[test]
fn resolve_lists_delta_clears_a_withdrawn_override() {
    let p = Profile {
        lists: BTreeMap::from([(Id::new("ads").unwrap(), ListPolicy::Allow)]),
        ..mk_profile()
    };
    let mut modal = ProfileModal::open_edit("kids", &p, mk_lists(), vec![]);
    let form = modal.form_mut().unwrap();
    form.focused = FormField::ListOverride(0); // ads, currently Allow
    form.cycle_list_policy(true); // Allow -> inherit
    let patch = resolve_edit_patch(form, form.original.as_ref().unwrap()).unwrap();
    let lp = patch.lists.expect("lists delta present");
    assert!(lp.set.is_empty());
    assert_eq!(lp.clear, vec!["ads"]);
}

/// **DoD 4, in the form that can actually fail.**
///
/// "Open and close with Esc leaves the file alone" is vacuous: the
/// modal never writes, so it passes on a completely broken draft. This
/// asserts on the SAVE path instead — the one place a seeding bug is
/// observable — and it is the mutation that matters: seed `lists_draft`
/// empty in `new_edit` and the diff reads every existing key as
/// withdrawn, so an operator who opened this profile to rename it
/// loses every override they had.
#[test]
fn an_untouched_profile_with_overrides_emits_no_list_patch() {
    let p = Profile {
        lists: BTreeMap::from([
            (Id::new("ads").unwrap(), ListPolicy::Allow),
            (Id::new("social").unwrap(), ListPolicy::Ignore),
        ]),
        ..mk_profile()
    };
    let mut modal = ProfileModal::open_edit("kids", &p, mk_lists(), vec![]);
    let form = modal.form_mut().unwrap();
    // An edit to an UNRELATED field, so the patch is non-empty and the
    // assertion below cannot pass merely because nothing was sent.
    form.display_name = "Kids (renamed)".into();
    let patch = resolve_edit_patch(form, form.original.as_ref().unwrap()).unwrap();
    assert_eq!(patch.display_name.as_deref(), Some("Kids (renamed)"));
    assert_eq!(
        patch.lists, None,
        "an untouched panel must not withdraw the operator's own overrides"
    );
}

/// `set` carries only what CHANGED. An override the operator did not
/// touch is not re-declared, so an unrelated edit does not show up in
/// the daemon's audit log as a list-policy decision.
#[test]
fn resolve_lists_delta_omits_an_untouched_declaration() {
    let p = Profile {
        lists: BTreeMap::from([
            (Id::new("ads").unwrap(), ListPolicy::Allow),
            (Id::new("news").unwrap(), ListPolicy::Deny),
        ]),
        ..mk_profile()
    };
    let mut modal = ProfileModal::open_edit("kids", &p, mk_lists(), vec![]);
    let form = modal.form_mut().unwrap();
    form.focused = FormField::ListOverride(1); // news: Deny -> Allow
    form.cycle_list_policy(true);
    let patch = resolve_edit_patch(form, form.original.as_ref().unwrap()).unwrap();
    let lp = patch.lists.expect("lists delta present");
    assert_eq!(lp.set.len(), 1, "only the touched row travels: {lp:?}");
    assert_eq!(lp.set.get("news"), Some(&ListPolicy::Allow));
    assert!(lp.clear.is_empty());
}

// ── plp §4 S4 / decision D: how `ignore` is reached ───────────────

/// **DoD 5, the "not from a bare arrow" half.**
///
/// Exhaustive over the starting states AND both directions, walked
/// long enough to close every cycle. Asserting on the DRAFT rather
/// than on the effective direction is deliberate: a list whose own
/// `base` is `ignore` reaches effective `Ignore` through the cycle's
/// `inherit` step, which is correct — that is the operator's own
/// standing declaration on the list, and P6 already WARNs about it at
/// every load. What must never happen is an arrow WRITING `ignore`
/// into this profile.
#[test]
fn no_arrow_ever_declares_ignore() {
    for start in [
        None,
        Some(ListPolicy::Deny),
        Some(ListPolicy::Allow),
        Some(ListPolicy::Ignore),
    ] {
        for forward in [true, false] {
            let p = Profile {
                lists: start
                    .map(|v| BTreeMap::from([(Id::new("ads").unwrap(), v)]))
                    .unwrap_or_default(),
                ..mk_profile()
            };
            let mut modal = ProfileModal::open_edit("kids", &p, mk_lists(), vec![]);
            let form = modal.form_mut().unwrap();
            form.focused = FormField::ListOverride(0);
            for step in 0..8 {
                form.cycle_list_policy(forward);
                assert_ne!(
                    form.lists_draft.get(&Id::new("ads").unwrap()),
                    Some(&ListPolicy::Ignore),
                    "start={start:?} forward={forward} step={step}: an arrow \
                     declared ignore"
                );
            }
        }
    }
}

/// The arrow cycle still reaches every state it is supposed to, so
/// the test above cannot pass by the cycle being broken outright.
#[test]
fn the_arrow_cycle_reaches_inherit_deny_and_allow() {
    let mut modal = ProfileModal::open_edit("kids", &mk_profile(), mk_lists(), vec![]);
    let form = modal.form_mut().unwrap();
    form.focused = FormField::ListOverride(0);
    let ads = Id::new("ads").unwrap();
    let mut seen = Vec::new();
    for _ in 0..3 {
        form.cycle_list_policy(true);
        seen.push(form.lists_draft.get(&ads).copied());
    }
    assert!(seen.contains(&Some(ListPolicy::Deny)), "{seen:?}");
    assert!(seen.contains(&Some(ListPolicy::Allow)), "{seen:?}");
    assert!(seen.contains(&None), "{seen:?}");
}

/// From `ignore` both arrows are a one-way door out, and it opens
/// toward MORE filtering — the same contract the Lists modal's
/// `nature` row states in its own hint.
#[test]
fn an_arrow_leaves_ignore_toward_deny_in_both_directions() {
    for forward in [true, false] {
        let p = Profile {
            lists: BTreeMap::from([(Id::new("ads").unwrap(), ListPolicy::Ignore)]),
            ..mk_profile()
        };
        let mut modal = ProfileModal::open_edit("kids", &p, mk_lists(), vec![]);
        let form = modal.form_mut().unwrap();
        form.focused = FormField::ListOverride(0);
        form.cycle_list_policy(forward);
        assert_eq!(
            form.lists_draft.get(&Id::new("ads").unwrap()),
            Some(&ListPolicy::Deny),
            "forward={forward}"
        );
    }
}

/// **DoD 5, the "reachable" half.** Two presses, and only two.
#[test]
fn two_presses_of_i_declare_ignore_and_one_does_not() {
    let mut modal = ProfileModal::open_edit("kids", &mk_profile(), mk_lists(), vec![]);
    let form = modal.form_mut().unwrap();
    form.focused = FormField::ListOverride(0);
    let ads = Id::new("ads").unwrap();

    assert!(!form.press_ignore(), "the first press only arms");
    assert_eq!(
        form.lists_draft.get(&ads),
        None,
        "arming must not write anything"
    );
    assert!(form.press_ignore(), "the second press commits");
    assert_eq!(form.lists_draft.get(&ads), Some(&ListPolicy::Ignore));
    assert_eq!(form.ignore_armed, None, "committing spends the valve");
}

/// Arming is per-ROW. Arming on one list and pressing `i` on another
/// must arm the second, not commit it — otherwise a stray arm on a row
/// the operator has left makes the *next* row inert on one keypress.
#[test]
fn the_ignore_valve_does_not_carry_across_rows() {
    let mut modal = ProfileModal::open_edit("kids", &mk_profile(), mk_lists(), vec![]);
    let form = modal.form_mut().unwrap();
    form.focused = FormField::ListOverride(0);
    assert!(!form.press_ignore());
    form.focused = FormField::ListOverride(2);
    assert!(
        !form.press_ignore(),
        "a different row re-arms, never commits"
    );
    assert_eq!(form.lists_draft.get(&Id::new("social").unwrap()), None);
}

/// An arrow between the two presses cancels the declaration.
#[test]
fn an_arrow_spends_the_armed_ignore_valve() {
    let mut modal = ProfileModal::open_edit("kids", &mk_profile(), mk_lists(), vec![]);
    let form = modal.form_mut().unwrap();
    form.focused = FormField::ListOverride(0);
    assert!(!form.press_ignore());
    form.cycle_list_policy(true);
    assert_eq!(form.ignore_armed, None);
    assert!(
        !form.press_ignore(),
        "after an arrow the next `i` arms again rather than committing"
    );
    assert_ne!(
        form.lists_draft.get(&Id::new("ads").unwrap()),
        Some(&ListPolicy::Ignore)
    );
}

// ── the two readouts must not drift apart ─────────────────────────

/// `declared_for` and `effective_for` answer different questions off
/// the same map, and this pins them against each other: whenever a
/// policy is DECLARED, it is also the EFFECTIVE one. Inline
/// `effective_for`'s arithmetic instead of calling
/// `effective_direction` and this is the assertion that survives to
/// catch the copy drifting — the D11 class in miniature.
#[test]
fn a_declared_policy_is_always_the_effective_one() {
    for declared in [ListPolicy::Deny, ListPolicy::Allow, ListPolicy::Ignore] {
        for list in mk_lists() {
            let p = Profile {
                lists: BTreeMap::from([(list.id.clone(), declared)]),
                ..mk_profile()
            };
            let modal = ProfileModal::open_edit("kids", &p, mk_lists(), vec![]);
            let form = modal.form().unwrap();
            assert_eq!(form.declared_for(&list), Some(declared));
            assert_eq!(
                form.effective_for(&list),
                declared,
                "list {} base {:?}",
                list.id.as_str(),
                list.base
            );
        }
    }
}

/// And with nothing declared, the effective direction is the list's
/// own `base` — including for `base = allow`, which is what makes the
/// panel a readout rather than a constant.
#[test]
fn an_undeclared_list_shows_its_own_base() {
    let modal = ProfileModal::open_edit("kids", &mk_profile(), mk_lists(), vec![]);
    let form = modal.form().unwrap();
    for list in mk_lists() {
        assert_eq!(form.declared_for(&list), None);
        assert_eq!(form.effective_for(&list), list.base.as_policy());
    }
}

// ── the consent guidance is guidance, and it is conditional ───────

/// The notice fires on a PENDING allow, and only there.
///
/// `BlocklistTrust` defaults to `RemoteUnsigned` and every
/// `[[blocklists]]` row on both live hosts omits the key, so a notice
/// keyed on trust alone would be on for every row of every profile —
/// and a hint that is always on is one nobody reads. The `ads` fixture
/// is exactly that shape: remote, unsigned, unconsented.
#[test]
fn the_consent_notice_only_fires_on_a_pending_allow() {
    let lists = mk_lists();
    let unsigned = &lists[0]; // ads: remote-unsigned, no ack
    let local = &lists[1]; // news: trust = local

    let modal = ProfileModal::open_edit("kids", &mk_profile(), mk_lists(), vec![]);
    let form = modal.form().unwrap();

    assert_eq!(
        list_row_hint(form, 0, unsigned, None),
        LIST_OVERRIDE_HINT,
        "inheriting a deny costs nothing and must say nothing"
    );
    assert_eq!(
        list_row_hint(form, 0, unsigned, Some(ListPolicy::Deny)),
        LIST_OVERRIDE_HINT,
        "a declared deny narrows what the profile permits"
    );
    assert!(
        list_row_hint(form, 0, unsigned, Some(ListPolicy::Allow)).contains("set-trust"),
        "a pending allow on an unconsented remote list names the fix"
    );
    assert_eq!(
        list_row_hint(form, 1, local, Some(ListPolicy::Allow)),
        LIST_OVERRIDE_HINT,
        "trust = local has nothing to declare"
    );

    let consented = mk_list(
        "ads",
        BlocklistBase::Deny,
        BlocklistTrust::RemoteUnsigned,
        true,
    );
    assert_eq!(
        list_row_hint(form, 0, &consented, Some(ListPolicy::Allow)),
        LIST_OVERRIDE_HINT,
        "a list whose row already declares the consent is done paying"
    );
}

/// The notice has to survive the help region intact — the recovery
/// command is the whole point of it, and it is at the end.
///
/// Measured against the real render, not against a character count:
/// the region is three banded rows of a 70-column modal and the
/// arithmetic between those two facts is exactly what a count would
/// get wrong.
#[test]
fn the_consent_notice_survives_the_help_region_whole() {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    // Twice the grid's label column — longer than any list id in a
    // real config, and long enough that a hint budgeted for a short
    // one would be cut here.
    let long = "content-adult-and-gambling-x32";
    let lists = vec![mk_list(
        long,
        BlocklistBase::Deny,
        BlocklistTrust::RemoteUnsigned,
        false,
    )];
    let p = Profile {
        lists: BTreeMap::from([(Id::new(long).unwrap(), ListPolicy::Allow)]),
        ..mk_profile()
    };
    let mut modal = ProfileModal::open_edit("kids", &p, lists, vec![]);
    modal.form_mut().unwrap().focused = FormField::ListOverride(0);

    let mut term = Terminal::new(TestBackend::new(80, 30)).unwrap();
    term.draw(|f| render_overlay(f, f.area(), &modal)).unwrap();
    let dump = dump_buffer(term.backend().buffer());

    for needle in ["set-trust", long, "--accept-unsigned-allow"] {
        assert!(
            dump.contains(needle),
            "the recovery command must reach the operator whole \
             (missing {needle:?}):\n{dump}"
        );
    }
}

/// A list id can be four times the grid's label column
/// (`Id::MAX_LEN` is 64, `GRID_LABEL_W` is 18). Unfitted it shifts the
/// value column right and runs off the 70-cell modal, where the widget
/// clips it with no ellipsis — "the operator reads a truncated string
/// as a complete one", which `modal_form::value_row` says this module
/// answers everywhere else. `push_row_lead` now fits the label; this
/// is the fence.
#[test]
fn a_list_id_longer_than_the_label_column_does_not_break_the_grid() {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    let long = "a".repeat(crate::config::schema::Id::MAX_LEN);
    let lists = vec![mk_list(
        &long,
        BlocklistBase::Deny,
        BlocklistTrust::RemoteUnsigned,
        false,
    )];
    let modal = ProfileModal::open_edit("kids", &mk_profile(), lists, vec![]);
    // Tall enough for the whole body — see the note in
    // `declared_and_inherited_are_distinguishable_on_the_same_direction`.
    let mut term = Terminal::new(TestBackend::new(100, 60)).unwrap();
    term.draw(|f| render_overlay(f, f.area(), &modal)).unwrap();
    let dump = dump_buffer(term.backend().buffer());

    let row = dump
        .lines()
        .find(|l| l.contains("aaaa"))
        .expect("the row renders at all");
    assert!(
        row.contains('\u{2026}'),
        "an over-long label announces its own cut:\n{row}"
    );
    // The direction still lands in the value column, which is the
    // property an unfitted label destroys.
    assert!(
        row.contains(LIST_POLICY_BLOCK),
        "the value column survives a 64-character id:\n{row}"
    );
}

/// A config with no `[[blocklists]]` renders an explanation, not a
/// blank section — and not a focusable row that answers no key.
///
/// **Asserted on a full-height render, and the reason is a real
/// limitation worth stating rather than hiding.** The empty-state row
/// is not in the focus ring, so nothing ever anchors the viewport on
/// it; at the 80x24 floor the field window is 2 rows and this row is
/// below them. That is the same deal every non-focusable row on this
/// form already takes — the `id` row in Edit mode scrolls away exactly
/// so — and the alternative is worse: a ring entry that answers no key
/// is the defect `add_preview_sections` documents. The band under the
/// title carries the same fact on every render at every size
/// ("Lists: profiles.<id>.lists, else that list's own base"), so an
/// operator at the floor is not left without it.
#[test]
fn the_empty_panel_says_where_lists_come_from() {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    let modal = ProfileModal::open_edit("kids", &mk_profile(), Vec::new(), vec![]);
    let mut term = Terminal::new(TestBackend::new(100, 60)).unwrap();
    term.draw(|f| render_overlay(f, f.area(), &modal)).unwrap();
    let dump = dump_buffer(term.backend().buffer());
    assert!(
        dump.contains("none configured"),
        "an empty panel names its state:\n{dump}"
    );
    assert!(
        dump.contains(LIST_PANEL_EMPTY),
        "and points at the surface that fixes it:\n{dump}"
    );
}

/// **The measurement behind [`LIST_FAILURE_NOTE_ROWS`].**
///
/// The daemon's override-consent refusal is ~540 rendered characters
/// and wraps to **9** rows at this width; the recovery command sits in
/// rows 5 to 7. At `modal_form::HINT_ROWS` (2) the operator reads the
/// problem and none of the answer. At 8 the command is whole and the
/// cut — one row of trailing prose — is named by
/// `hint_or_error_rows`'s own residual note.
///
/// 8 rather than 9 leaves one interior row unspent at the floor
/// (head 2 + note 8 + keys 1 = 11 of 12), so a future head change
/// cannot silently drive the region to zero.
#[test]
fn floor_submit_failure_keeps_the_keys_row_and_names_the_cut() {
    let refusal = crate::ipc::errors::IpcError::OverrideAllowNeedsConsent {
        id: "kids".into(),
        list: "privacy-tracking".into(),
    }
    .operator_message();

    let mut modal = ProfileModal::open_edit("kids", &mk_profile(), mk_lists(), vec![]);
    modal.finish(SubmitOutcome::Failed(refusal));
    let dump = render_at_floor(&modal);

    for needle in [
        "set-trust",
        "privacy-tracking",
        "--accept-unsigned-allow",
        "[any key] close",
    ] {
        assert!(
            dump.contains(needle),
            "the refusal's recovery command and the key legend must both \
             survive the floor (missing {needle:?}):\n{dump}"
        );
    }
}

#[test]
fn resolve_ecs_clear_toggle_emits_clear_patch() {
    let mut modal = ProfileModal::open_edit("kids", &mk_profile(), vec![], vec![]);
    let form = modal.form_mut().unwrap();
    form.ecs_clear = true;
    let patch = resolve_edit_patch(form, form.original.as_ref().unwrap()).unwrap();
    let ecs = patch.ecs.expect("clear toggle emits an ecs patch");
    assert!(ecs.clear);
    assert_eq!(ecs.mode, None);
    assert_eq!(ecs.source_prefix_v4, None);
}

#[test]
fn resolve_ecs_clear_noop_when_no_original_ecs() {
    let p = Profile {
        ecs: None,
        ..mk_profile()
    };
    let mut modal = ProfileModal::open_edit("kids", &p, vec![], vec![]);
    let form = modal.form_mut().unwrap();
    form.ecs_clear = true;
    let patch = resolve_edit_patch(form, form.original.as_ref().unwrap()).unwrap();
    assert_eq!(
        patch.ecs, None,
        "clearing an already-absent ecs subtree is a no-op"
    );
}

#[test]
fn resolve_ecs_set_mode_on_fresh_profile_creates_subtree() {
    let p = Profile {
        ecs: None,
        ..mk_profile()
    };
    let mut modal = ProfileModal::open_edit("kids", &p, vec![], vec![]);
    let form = modal.form_mut().unwrap();
    form.ecs_mode_idx = 2; // coarse
    let patch = resolve_edit_patch(form, form.original.as_ref().unwrap()).unwrap();
    let ecs = patch.ecs.expect("setting a mode creates the subtree");
    assert_eq!(ecs.mode, Some(EcsMode::Coarse));
    assert!(!ecs.clear);
}

#[test]
fn resolve_ecs_per_field_clear_returns_err() {
    // mk_profile has ecs.mode = Some(Coarse). Picking (inherit) on the
    // mode dropdown while the subtree survives is the D1 trap.
    let mut modal = ProfileModal::open_edit("kids", &mk_profile(), vec![], vec![]);
    let form = modal.form_mut().unwrap();
    form.ecs_mode_idx = 0; // (inherit) — but subtree still has v4=24
    let err = resolve_edit_patch(form, form.original.as_ref().unwrap()).unwrap_err();
    assert!(
        err.contains("clear ecs"),
        "per-field ecs clear must point at the whole-subtree toggle, got: {err}"
    );
}

#[test]
fn resolve_bad_ecs_prefix_returns_err() {
    let mut modal = ProfileModal::open_edit("kids", &mk_profile(), vec![], vec![]);
    let form = modal.form_mut().unwrap();
    form.ecs_v4_input = "99".into(); // > 32
    let err = resolve_edit_patch(form, form.original.as_ref().unwrap()).unwrap_err();
    assert!(err.contains("source_prefix_v4"), "got: {err}");
}

// ── Add resolve + lifecycle ───────────────────────────────────────

#[test]
fn add_form_rejects_empty_id() {
    let modal = ProfileModal::open_add();
    let err = modal.form().unwrap().try_resolve_add().unwrap_err();
    assert!(err.contains("id"), "got: {err}");
}

#[test]
fn add_form_defaults_display_name_to_id() {
    let mut modal = ProfileModal::open_add();
    modal.form_mut().unwrap().id = "guests".into();
    let (id, dn) = modal.form().unwrap().try_resolve_add().unwrap();
    assert_eq!(id, "guests");
    assert_eq!(dn, "guests");
}

#[test]
fn modal_finish_transitions_to_submitted() {
    let mut modal = ProfileModal::open_add();
    assert!(!modal.is_submitted());
    modal.finish(SubmitOutcome::Ok("done".into()));
    assert!(modal.is_submitted());
}

#[test]
fn remove_modal_carries_reference_summary() {
    let modal = ProfileModal::open_remove("kids", "Kids", "2 devices reference this".into());
    let rc = modal.remove().unwrap();
    assert_eq!(rc.id, "kids");
    assert_eq!(rc.reference_summary, "2 devices reference this");
}

#[test]
fn dropdown_cycle_wraps_both_directions() {
    let mut f = ProfileForm::new_edit("kids", &mk_profile(), vec![], vec![]);
    f.focused = FormField::BlockResponse;
    f.block_response_idx = 0;
    f.cycle_dropdown(false); // backward from 0 wraps to last
    assert_eq!(f.block_response_idx, BLOCK_RESPONSE_OPTIONS.len() - 1);
    f.cycle_dropdown(true); // forward wraps back to 0
    assert_eq!(f.block_response_idx, 0);
}

#[test]
fn toggle_flips_only_the_focused_toggle() {
    let mut f = ProfileForm::new_edit("kids", &mk_profile(), vec![], vec![]);
    f.focused = FormField::EcsClear;
    assert!(!f.ecs_clear);
    f.toggle();
    assert!(f.ecs_clear);
    assert!(
        f.block_all,
        "block_all (from mk_profile) untouched by EcsClear toggle"
    );
}

// ── Archetype-F body (shared modal_form) ──────────────────────────

/// Flatten the whole body — pinned head, field region and pinned tail
/// — into one string for content assertions.
///
/// Deliberately NOT what the operator sees: `render_scroll_body` shows
/// a *window* onto the field region. Every past instance of the clip
/// defect had a correct line vector and a wrong render, so anything
/// about visibility is asserted on the buffer, below.
fn render_text(form: &ProfileForm, width: u16) -> String {
    let (body, _) = form_body(form, width);
    body.head
        .iter()
        .chain(body.fields.iter())
        .chain(body.tail.iter())
        .map(|l| {
            l.spans
                .iter()
                .map(|s| s.content.as_ref())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// §4.61 Wave 2c changed two affordances here, both by archetype:
/// the grey `Field │ Value` header is replaced by labelled section
/// bands, and the drawn `_` caret is replaced by the real terminal
/// cursor (which `form_body` returns a target for, and
/// `ModalRender::place_cursor` puts on screen).
#[test]
fn add_form_renders_section_band_cursor_target_and_actions() {
    let mut modal = ProfileModal::open_add();
    let form = modal.form_mut().unwrap();
    form.id = "kids".into(); // focus defaults to Id on Add
    let text = render_text(form, 70);
    assert!(text.contains("IDENTITY"), "labelled section band:\n{text}");
    assert!(
        !text.contains("Field") && !text.contains("Value"),
        "the legacy grid header is gone:\n{text}"
    );
    assert!(text.contains('◀'), "active row carries the focus marker");
    assert!(text.contains("Save"), "Save action present");
    assert!(text.contains("Discard"), "Discard action present");

    let (_, cursor) = form_body(form, 70);
    assert_eq!(
        cursor,
        Some((2, 4)),
        "the hardware cursor targets the focused row (2 = the section \
         band's header + hairline; §4.65 UX1(c)'s 2 blurb rows that \
         used to sit under them are gone as of 2026-08-07) at the end \
         of `kids`"
    );
}

#[test]
fn grid_edit_focused_dropdown_is_angle_wrapped() {
    let mut modal = ProfileModal::open_edit("kids", &mk_profile(), vec![], vec![]);
    let form = modal.form_mut().unwrap();
    form.focused = FormField::BlockResponse; // mk_profile → nxdomain
    let text = render_text(form, 70);
    assert!(
        text.contains("‹ nxdomain ›"),
        "a focused dropdown value is wrapped to signal ←/→ cycles it"
    );
}

/// The two booleans moved from a `‹ yes ›` selector to a radio row:
/// both options stay on screen, and each side declares what it *means*
/// (`block all` = Yes is `Blocking`, No is `Healthy`), so the colour
/// comes from the value rather than from this module. ←/→ and Space
/// still flip it — the key handler is untouched (D7′).
#[test]
fn edit_toggle_renders_a_two_option_radio() {
    let mut modal = ProfileModal::open_edit("kids", &mk_profile(), vec![], vec![]);
    let form = modal.form_mut().unwrap();
    form.focused = FormField::BlockAll; // mk_profile block_all = true
    let text = render_text(form, 70);
    assert!(
        text.contains("● Yes") && text.contains("○ No"),
        "the selected side is filled, the other is hollow:\n{text}"
    );
    form.block_all = false;
    let text = render_text(form, 70);
    assert!(
        text.contains("○ Yes") && text.contains("● No"),
        "flipping the value moves the fill:\n{text}"
    );
}

#[test]
fn grid_inline_error_replaces_the_hint_line() {
    let mut modal = ProfileModal::open_edit("kids", &mk_profile(), vec![], vec![]);
    let form = modal.form_mut().unwrap();
    form.error_message = Some("blocked_ttl_secs must be an integer".into());
    let text = render_text(form, 70);
    assert!(text.contains("⚠ blocked_ttl_secs must be an integer"));
    // The hint for the focused field is suppressed while an error pends.
    assert!(!text.contains("human label shown in the table"));
}

#[test]
fn grid_edit_id_is_read_only_without_caret() {
    let modal = ProfileModal::open_edit("kids", &mk_profile(), vec![], vec![]);
    let form = modal.form().unwrap();
    assert_eq!(form.focused, FormField::DisplayName);
    let text = render_text(form, 70);
    assert!(text.contains("kids"), "id value still shown");
    assert!(!text.contains("kids_"), "read-only id carries no caret");
    assert!(
        !text.contains("(read-only)"),
        "dim styling signals read-only, not literal suffix text"
    );
}

#[test]
fn grid_ecs_rows_lose_selector_wrap_when_cleared() {
    // mk_profile → ecs.mode = coarse. Focused + not cleared = angle
    // wrap; focused + `clear ecs` on = read-only (dimmed), no wrap.
    let mut modal = ProfileModal::open_edit("kids", &mk_profile(), vec![], vec![]);
    let form = modal.form_mut().unwrap();
    form.focused = FormField::EcsMode;
    assert!(
        render_text(form, 70).contains("‹ coarse ›"),
        "live ecs mode is a focusable selector"
    );
    form.ecs_clear = true;
    let cleared = render_text(form, 70);
    assert!(cleared.contains("coarse"), "value still shown");
    assert!(
        !cleared.contains("‹ coarse ›"),
        "a cleared ecs row is inert (read-only), so it drops the selector wrap"
    );
}

// ── §3.5 tag-model-consolidation: populated tags field ────────────

fn dump_buffer(buf: &ratatui::buffer::Buffer) -> String {
    let mut out = String::new();
    for y in 0..buf.area.height {
        for x in 0..buf.area.width {
            out.push_str(buf[(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

/// The override panel at its tallest — every configured list focused
/// deep in the ring — must not push Save/Discard off the bottom.
/// Renders the real `render_overlay`, not the line vector, because
/// every past instance of that defect had a correct vector and a wrong
/// render.
///
/// Inherits the job the tags-picker version of this test did: it is
/// the free proof that the Archetype-F body did not lose a property
/// the flat body had.
#[test]
fn render_overlay_keeps_save_discard_visible_with_a_full_list_panel() {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    // Twelve lists, deeper than any viewport this modal ever gets.
    let lists: Vec<Blocklist> = (0..12)
        .map(|i| {
            mk_list(
                &format!("list-{i:02}"),
                BlocklistBase::Deny,
                BlocklistTrust::RemoteUnsigned,
                false,
            )
        })
        .collect();
    let mut modal = ProfileModal::open_edit("kids", &mk_profile(), lists, vec![]);
    modal.form_mut().unwrap().focused = FormField::ListOverride(11);

    let mut term = Terminal::new(TestBackend::new(100, 30)).unwrap();
    term.draw(|f| render_overlay(f, f.area(), &modal)).unwrap();
    let dump = dump_buffer(term.backend().buffer());

    assert!(
        dump.contains("list-11"),
        "the focused row must be on screen:\n{dump}"
    );
    assert!(
        dump.contains("Save") && dump.contains("Discard"),
        "the button row must survive a full panel, not be clipped off \
         the bottom:\n{dump}"
    );
}

/// The three words a panel row's value column can hold.
const DIRECTION_WORDS: [&str; 3] = [LIST_POLICY_BLOCK, LIST_POLICY_ALLOW, LIST_POLICY_IGNORE];

/// Find the rendered row for `id`: the line where the id appears
/// **left of** a direction word.
///
/// Not "the line contains the id" — a list id appears in the hint
/// region too (the armed confirm names it, the consent notice names it
/// twice), and a hint line would satisfy a substring search while
/// proving nothing about the row. Not a fixed column cut either:
/// `VALUE_COL` is an offset inside the modal's inner rect, while a
/// dump line starts at the terminal's left edge — centring margin plus
/// border — so a cut at 22 lands mid-label, and slicing there by BYTE
/// would panic on the `\u{2502}` border rather than return `false`.
///
/// Relative order needs no slicing at all: `str::find` returns byte
/// offsets, and byte order is character order.
fn panel_row<'a>(dump: &'a str, id: &str) -> &'a str {
    dump.lines()
        .find(|l| {
            let Some(id_at) = l.find(id) else {
                return false;
            };
            DIRECTION_WORDS
                .iter()
                .filter_map(|w| l.find(w))
                .any(|word_at| id_at < word_at)
        })
        .unwrap_or_else(|| panic!("no panel row for {id:?} in:\n{dump}"))
}

/// The value column of a panel row — everything from its direction
/// word onward, so two rows can be compared without their labels
/// (which differ by construction) making the comparison vacuous.
fn panel_value(row: &str) -> &str {
    let at = DIRECTION_WORDS
        .iter()
        .filter_map(|w| row.find(w))
        .min()
        .unwrap_or_else(|| panic!("no direction word in row: {row:?}"));
    row[at..].trim_end()
}

/// **DoD 3.** A profile that declares an override on one list and
/// inherits on another must render the two differently — and the
/// discriminating case is two rows with the same *effect*.
///
/// `ads` and `social` are both `base = deny`; the profile declares
/// `deny` on `ads` only. Same word, same colour, same everything the
/// resolver acts on. If the panel flattens provenance, these two rows
/// are byte-identical and the operator cannot see which of them
/// survives a change to the list's `base`.
///
/// Both directions are asserted on purpose. "The declared row omits
/// the mark" alone passes a build that marks nothing; "the inherited
/// row carries it" alone passes one that marks everything. Together
/// they fail a SWAP of the two arms in `list_policy_value`, which is
/// the mutation a delete-one-arm mutation cannot reach.
#[test]
fn declared_and_inherited_are_distinguishable_on_the_same_direction() {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    let p = Profile {
        lists: BTreeMap::from([(Id::new("ads").unwrap(), ListPolicy::Deny)]),
        ..mk_profile()
    };
    let modal = ProfileModal::open_edit("kids", &p, mk_lists(), vec![]);
    // Tall enough for the WHOLE body. `render_modal` asks for
    // `head + fields + tail + 2` rows and `centered_rect` clamps that
    // to the anchor, so a terminal merely taller than the 80x24 floor
    // still cuts the last panel rows — this test failed on 40 with the
    // third list one row below the frame.
    let mut term = Terminal::new(TestBackend::new(100, 60)).unwrap();
    term.draw(|f| render_overlay(f, f.area(), &modal)).unwrap();
    let dump = dump_buffer(term.backend().buffer());

    let declared = panel_row(&dump, "ads");
    let inherited = panel_row(&dump, "social");

    assert!(
        declared.contains(LIST_POLICY_BLOCK),
        "a declared deny still reads as a deny:\n{dump}"
    );
    assert!(
        !declared.contains(LIST_POLICY_INHERITED.trim()),
        "a declared override must NOT be marked inherited:\n{declared}"
    );
    assert!(
        inherited.contains(LIST_POLICY_BLOCK) && inherited.contains(LIST_POLICY_INHERITED.trim()),
        "an inherited deny must say so:\n{inherited}"
    );
    // The point of the pair, stated directly — on the VALUE columns.
    // Comparing whole lines would be vacuous: the labels are `ads` and
    // `social`, so the lines differ whatever the values say.
    assert_ne!(
        panel_value(declared),
        panel_value(inherited),
        "two rows with the same effect and different provenance must \
         not render the same value:\n{dump}"
    );
    // The third row proves the panel reads `base`, not a constant.
    assert!(
        panel_row(&dump, "news").contains(LIST_POLICY_ALLOW),
        "a base = allow list inherits Allow:\n{dump}"
    );
}

// ── §4.61 Wave 2c — fail-before evidence (pre-migration) ──────────
//
// Two properties of the CURRENT fixed-body modal, pinned before it is
// migrated so the defect cannot be mis-attributed to the migration.
// Both assertions invert in the migration commit.

/// The tab content rect a Filtering leaf gets at the declared 80×24
/// floor: 24 − 4 header − 5 menu card − 1 footer legend = 14 rows,
/// leaving the modal **12 interior rows** (§4.61 §4.2).
const FLOOR_ANCHOR: Rect = Rect {
    x: 0,
    y: 9,
    width: 80,
    height: 14,
};

/// **DoD 5, the reachable half.** The armed `ignore` valve has to be
/// visible, and it has to name the list.
///
/// The valve's state lives on the form and its copy in a const, but
/// the WIRING is this module's: `list_row_hint` picks the armed branch
/// and `form_body` hands the result to `rows.field`. Return the
/// resting hint there instead and every logic test stays green while
/// the operator presses `i` twice with nothing on screen having asked
/// them to — the failure mode a mutation run on the Lists surface
/// already proved this ecosystem dies of.
#[test]
fn the_armed_ignore_valve_is_visible_and_names_the_list() {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    let mut modal = ProfileModal::open_edit("kids", &mk_profile(), mk_lists(), vec![]);
    let form = modal.form_mut().unwrap();
    form.focused = FormField::ListOverride(2); // social
    assert!(!form.press_ignore(), "the first press only arms");

    let mut term = Terminal::new(TestBackend::new(100, 44)).unwrap();
    term.draw(|f| render_overlay(f, f.area(), &modal)).unwrap();
    let dump = dump_buffer(term.backend().buffer());

    assert!(
        dump.contains("press [i] again"),
        "the confirm must be on screen before the second press:\n{dump}"
    );
    assert!(
        dump.contains("'social'"),
        "the confirm must name the list it will make inert:\n{dump}"
    );
    // Arming writes nothing.
    assert!(
        panel_row(&dump, "social").contains(LIST_POLICY_BLOCK),
        "an armed row still shows its current policy:\n{dump}"
    );
}

fn render_at_floor(modal: &ProfileModal) -> String {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    let backend = TestBackend::new(80, 24);
    let mut term = Terminal::new(backend).unwrap();
    term.draw(|f| render_overlay(f, FLOOR_ANCHOR, modal))
        .unwrap();
    dump_buffer(term.backend().buffer())
}

/// Was `floor_repro_action_row_dies_at_the_d18_budget` — inverted by
/// the Wave-2c migration. `ScrollBody` allocates the tail *first*, so
/// the action row survives a budget the fields do not fit in.
///
/// The two things a clip silently takes away are the action row and
/// the focused field, so both are asserted **together**: a modal that
/// keeps Save but scrolls the focused row off screen is just as blind.
/// Every focusable row is checked, because the field set is variable
/// and a viewport that works for the first row can fail for the last.
#[test]
fn floor_edit_keeps_the_action_row_and_the_focused_field_on_screen() {
    for (field, needle) in [
        (FormField::DisplayName, "display name"),
        (FormField::BlockResponse, "block response"),
        (FormField::BlockedTtl, "blocked ttl"),
        (FormField::BlockAll, "block all"),
        (FormField::AdminRules, "admin rules"),
        (FormField::EcsMode, "ecs mode"),
        (FormField::EcsPrefixV4, "ecs prefix v4"),
        (FormField::EcsPrefixV6, "ecs prefix v6"),
        (FormField::EcsClear, "clear ecs"),
        // The list id in the label column, not the word "Lists" —
        // that would also match the section band one row above it.
        (FormField::ListOverride(0), "ads"),
        (FormField::ListOverride(2), "social"),
    ] {
        let mut modal = ProfileModal::open_edit("kids", &mk_profile(), mk_lists(), vec![]);
        modal.form_mut().unwrap().focused = field;
        let dump = render_at_floor(&modal);
        assert!(
            dump.contains("Save") && dump.contains("Discard"),
            "{field:?}: the action row must survive the 12-row \
             budget:\n{dump}"
        );
        assert!(
            dump.contains(needle),
            "{field:?}: the focused row must be inside the \
             viewport:\n{dump}"
        );
    }
}

/// Was `floor_add_fits_without_scrolling`, and the inversion is the
/// point of §4.65 UX1(b)+(c).
///
/// Add used to be two fields in a four-row budget, so "no scrollbar
/// thumb" was a meaningful property and a stray spacer was the whole
/// risk. It now carries every section Edit has, so it scrolls at the
/// floor by construction — asserting it does not would be asserting the
/// modal is shorter than its spec, and the row count is a function of
/// the spec.
///
/// The budget behind it moved twice and the second move went the other
/// way: §4.65 UX1(c) spent rows on five two-line blurbs, and 2026-08-07
/// took them back but spent one on the two-row heading band. Net at the
/// D18 floor, the field viewport is **2** rows (`12 − 6 tail − 4 head`),
/// which is why this asserts the focused row and the action row are on
/// screen *together* rather than counting either alone.
///
/// What survives the change is the property that actually protects the
/// operator, and it is the one §4.63 S2a+S2c was filed against on the
/// Devices form: **the action row and the focused field on screen
/// together**. A form that keeps `Save` while scrolling the row under
/// the cursor out of view lets an operator commit blind, and so does
/// the reverse.
#[test]
fn floor_add_keeps_the_action_row_and_the_focused_field_on_screen() {
    for (field, needle) in [
        (FormField::Id, "id"),
        (FormField::DisplayName, "display name"),
    ] {
        let mut modal = ProfileModal::open_add();
        modal.form_mut().unwrap().focused = field;
        let dump = render_at_floor(&modal);
        assert!(
            dump.contains("Save") && dump.contains("Discard"),
            "{field:?}: action row visible:\n{dump}"
        );
        assert!(
            dump.contains(needle),
            "{field:?}: the focused row must be inside the \
             viewport:\n{dump}"
        );
    }
}

/// §4.65 UX1(b): the operator asked why Add shows only the name. It now
/// shows the whole shape of a profile — and every row the Add wire
/// cannot carry says so instead of taking input it would drop.
///
/// `IpcCommand::ProfileCreate` carries `id` + `display_name` and
/// nothing else, so a widened focus ring would reproduce §4.64 G4's
/// defect: a field the operator fills and the submit path discards in
/// silence. Both halves are asserted — the sections are **there**, and
/// the ring is **not** widened.
#[test]
fn add_shows_every_section_and_offers_none_it_cannot_carry() {
    let modal = ProfileModal::open_add();
    let form = modal.form().unwrap();
    let text = render_text(form, 62);

    for section in ["IDENTITY", "BLOCKING", "POLICY", "ECS"] {
        assert!(
            text.contains(section),
            "Add must show the {section} section:\n{text}"
        );
    }
    for label in [
        "block response",
        "blocked ttl",
        "block all",
        "admin rules",
        "ecs mode",
        "clear ecs",
    ] {
        assert!(text.contains(label), "Add must name {label}:\n{text}");
    }
    assert_eq!(
        text.matches("set after creating").count(),
        8,
        "every row the Add wire cannot carry, and that a later Edit \
         CAN, states when it becomes available:\n{text}"
    );
    // The two Policy rows Edit cannot set either keep Edit's copy: a
    // row that will never be editable here must not promise it will.
    assert_eq!(
        text.matches("read-only here").count(),
        2,
        "local records / rewrite rules are read-only on both forms, \
         so Add must not say they arrive with the next Edit:\n{text}"
    );

    // The ring is what decides whether a value can be typed and lost.
    assert_eq!(
        FormField::ADD_FIELDS,
        [
            FormField::Id,
            FormField::DisplayName,
            FormField::Submit,
            FormField::Cancel,
        ],
        "widening the Add focus ring puts a field in reach that \
         ProfileCreate cannot transport"
    );
}

/// §4.68 DoD, **at the floor**: the two description rows are on screen,
/// they fill the modal interior with `bg_main` `Rgb(15,15,15)` in teal
/// `Rgb(13,148,136)`, they are NOT on the title's `Rgb(51,51,51)`, and
/// `Save` / `Discard` survived the head growing by a row.
///
/// Both modes, and Add is the one that decides this lane: it is the
/// narrowest budget on the surface. At `avail = 12` the tail takes 6
/// ([`HELP_REGION`]'s 3 rows, banded, plus spacer + keys + actions) and
/// the head now takes 4, leaving a **2-row** field viewport.
///
/// Asserting the actions is not ceremony. §4.63 S2a+S2c grew the Devices
/// form without re-deriving this budget and cost it `Save`, `Cancel` and
/// 9 of 13 fields — while the focus ring still reached the buttons that
/// were no longer drawn, so the operator could commit blind.
/// `render_body_fixed` does not wrap and prints no marker where it cuts.
#[test]
fn floor_the_description_band_renders_on_its_own_strip_with_the_actions() {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    for (mode, modal) in [
        ("Add", ProfileModal::open_add()),
        (
            "Edit",
            ProfileModal::open_edit("kids", &mk_profile(), vec![], vec![]),
        ),
    ] {
        let (_, desc) = band_text(modal.form().unwrap());
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| render_overlay(f, FLOOR_ANCHOR, &modal))
            .unwrap();
        println!("--- {mode} ---");
        modal_form::desc_band2_assert::assert_two_row_band(
            term.backend().buffer(),
            desc,
            &["Save", "Discard"],
        );
    }
}

/// Replaces `every_section_carries_its_blurb` (§4.65 UX1(c), retired
/// 2026-08-07): the explanation is in the heading now, once, on both
/// field sets — and no section under it carries prose of its own.
///
/// The negative half is the load-bearing one. Nine `section_with_blurb`
/// call sites became `section`, and a missed one would leave a form
/// that explains itself twice while every positive needle still passes.
#[test]
fn the_heading_explains_the_form_and_no_section_repeats_it() {
    for (mode, modal) in [
        ("Add", ProfileModal::open_add()),
        (
            "Edit",
            ProfileModal::open_edit("kids", &mk_profile(), vec![], vec![]),
        ),
    ] {
        let form = modal.form().unwrap();
        let text = render_text(form, 62);
        let (_, desc) = band_text(form);

        for line in desc {
            assert!(
                text.contains(line),
                "{mode}: description row missing or clipped: \
                 {line:?}\n{text}"
            );
        }
        // The retired blurbs, verbatim. Any one of them back on screen
        // means a `section_with_blurb` call survived the sweep.
        for gone in [
            "The id is what devices and subnets point at",
            "Block response and ttl shape the answer",
            "Admin rules override the lists, for this profile only.",
            "These change what warden reveals to the upstream",
            "Tags are the join to blocklists: a list applies to this",
        ] {
            assert!(
                !text.contains(gone),
                "{mode}: a per-section blurb survived: {gone:?}\n{text}"
            );
        }
    }
}

/// A description row that outruns the row is clipped at the rect edge
/// with no marker — `render_body_fixed` does not wrap. The copy is
/// written to a budget, so the budget is a test rather than a comment.
///
/// Migrated from `no_blurb_line_outruns_the_narrow_build_pass`, whose
/// budget was **re-derived rather than carried over**: it said "64-column
/// modal → 62-cell interior → 61 on the scrollbar pass", but this modal
/// is [`MODAL_W`] = 70. The old constant was a sibling surface's number,
/// and it was merely too tight rather than too loose — which is the way
/// that hides. Take the width from the constant, not from a comment.
#[test]
fn no_desc_row_outruns_the_narrow_build_pass() {
    // −2 chrome, −1 for the scrollbar column on the narrow pass,
    // −2 for `desc_band2`'s indent.
    const BUDGET: usize = MODAL_W as usize - 5;
    for modal in [
        ProfileModal::open_add(),
        ProfileModal::open_edit("kids", &mk_profile(), vec![], vec![]),
    ] {
        let (_, desc) = band_text(modal.form().unwrap());
        for line in desc {
            let n = line.chars().count();
            assert!(n <= BUDGET, "description row is {n} cells: {line:?}");
        }
    }
}

/// §4.65 UX1(c): the help region is three rows on a band of its own.
///
/// Asserted on the rendered buffer's **cells**, not on the line vector:
/// a `Span`'s background paints only its own characters, so a region
/// built from unpadded lines would carry the right style on a third of
/// the row and read as a rendering artefact. That is the same defect
/// `section_band` pads around.
#[test]
fn the_help_region_is_three_banded_rows() {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    // Deliberately no assertion on `HELP_REGION` itself: `assert!`
    // short-circuits, so a constant check placed first is the one that
    // fails and the buffer below never runs. The rendered cells ARE
    // the property; the constant is the mechanism.
    let modal = ProfileModal::open_edit("kids", &mk_profile(), vec![], vec![]);
    let backend = TestBackend::new(100, 40);
    let mut term = Terminal::new(backend).unwrap();
    term.draw(|f| render_overlay(f, f.area(), &modal)).unwrap();
    let buf = term.backend().buffer().clone();

    // The hint's own text locates the region; the two rows under it are
    // its padding, and all three must be banded edge to edge.
    let hint = field_hint(FormField::DisplayName);
    let needle: String = hint.chars().take(20).collect();
    let (x0, y0) = (0..buf.area.height)
        .find_map(|y| {
            let row: String = (0..buf.area.width).map(|x| buf[(x, y)].symbol()).collect();
            row.find(&needle).map(|i| (i as u16, y))
        })
        .expect("the focused row's hint reaches the help region");

    let bg = buf[(x0, y0)].bg;
    assert_ne!(
        bg,
        buf[(x0, y0 - 1)].bg,
        "the band must be distinct from the row above it"
    );
    for dy in 0..3u16 {
        let y = y0 + dy;
        // Walk the whole interior, not one cell: a half-painted band
        // is exactly what an unpadded line produces.
        for x in x0..(x0 + 40) {
            assert_eq!(
                buf[(x, y)].bg,
                bg,
                "help-region row {dy} is not banded at column {x}"
            );
        }
    }
}

#[test]
#[ignore = "visual aid: cargo test profile_visual_dump -- --ignored --nocapture"]
fn profile_visual_dump() {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    for (name, modal) in [
        ("add", ProfileModal::open_add()),
        (
            "edit",
            ProfileModal::open_edit("kids", &mk_profile(), vec![], vec![]),
        ),
    ] {
        let mut term = Terminal::new(TestBackend::new(80, 44)).unwrap();
        term.draw(|f| render_overlay(f, f.area(), &modal)).unwrap();
        println!(
            "--- {name}, roomy anchor ---\n{}",
            dump_buffer(term.backend().buffer())
        );
        println!(
            "--- {name}, the 80x24 floor ---\n{}",
            render_at_floor(&modal)
        );
    }
}

/// Was `floor_repro_modal_is_full_bleed_at_the_floor` — inverted by
/// the D18 anchor. The overlay now centres inside the tab content
/// rect, so the header, the menu card and the footer legend keep
/// their rows (§4.62 N1: nothing transient may occlude them).
#[test]
fn floor_modal_stays_inside_the_content_rect() {
    let modal = ProfileModal::open_edit("kids", &mk_profile(), vec![], vec![]);
    let dump = render_at_floor(&modal);
    let rows: Vec<&str> = dump.lines().collect();
    for (y, row) in rows.iter().take(FLOOR_ANCHOR.y as usize).enumerate() {
        assert!(
            row.trim().is_empty(),
            "row {y} is above the anchor and must be untouched:\n{dump}"
        );
    }
    assert!(
        rows[23].trim().is_empty(),
        "row 23 is the footer legend's and must be untouched:\n{dump}"
    );
    assert!(
        rows[9].contains('\u{256d}') && rows[22].contains('\u{2570}'),
        "the frame occupies exactly the anchor's 14 rows:\n{dump}"
    );
}

/// The viewport follows focus to the LAST field, on both field sets.
/// In Edit that is the last per-list override row, whose index is the
/// operator's list count — derived from `visible_fields()` rather than
/// written down, so a ring that stops splicing panel rows fails here
/// instead of quietly asserting about `EcsClear`.
#[test]
fn viewport_follows_focus_to_the_last_field() {
    let last_add = *FormField::ADD_FIELDS
        .iter()
        .rfind(|f| !matches!(f, FormField::Submit | FormField::Cancel))
        .unwrap();
    assert_eq!(last_add, FormField::DisplayName);
    let mut modal = ProfileModal::open_add();
    modal.form_mut().unwrap().focused = last_add;
    let dump = render_at_floor(&modal);
    assert!(dump.contains("display name"), "Add's last row:\n{dump}");

    let mut modal = ProfileModal::open_edit("kids", &mk_profile(), mk_lists(), mk_custom_lists());
    let last_edit = *modal
        .form()
        .unwrap()
        .visible_fields()
        .iter()
        .rfind(|f| !matches!(f, FormField::Submit | FormField::Cancel))
        .unwrap();
    // The mount panel is now the deepest thing in the ring, so this is
    // the row the viewport has furthest to travel to.
    assert_eq!(last_edit, FormField::CustomListMount(1));
    modal.form_mut().unwrap().focused = last_edit;
    let dump = render_at_floor(&modal);
    assert!(
        dump.contains("home-exceptions"),
        "the focused mount row is on screen:\n{dump}"
    );
    assert!(
        dump.contains("Save"),
        "with the action row still pinned:\n{dump}"
    );
}

// ── Custom-list mount panel ───────────────────────────────────────

/// A config with custom lists but no blocklists still gets its mount
/// rows: the two panels are spliced independently, so an empty one must
/// not swallow the other.
#[test]
fn edit_form_ring_splices_mounts_with_no_blocklists_at_all() {
    let f = ProfileForm::new_edit("kids", &mk_profile(), Vec::new(), mk_custom_lists());
    let ring = f.visible_fields();
    let mounts: Vec<_> = ring
        .iter()
        .filter(|x| matches!(x, FormField::CustomListMount(_)))
        .copied()
        .collect();
    assert_eq!(
        mounts,
        [FormField::CustomListMount(0), FormField::CustomListMount(1)],
        "both mount rows survive an empty override panel: {ring:?}"
    );
}

#[test]
fn the_mount_draft_is_seeded_from_the_profile() {
    let p = Profile {
        custom_lists: vec![Id::new("handheld").unwrap()],
        ..mk_profile()
    };
    let f = ProfileForm::new_edit("kids", &p, mk_lists(), mk_custom_lists());
    assert!(f.mounts(&mk_custom_lists()[0]), "handheld is mounted");
    assert!(
        !f.mounts(&mk_custom_lists()[1]),
        "home-exceptions is not mounted"
    );
}

/// **The seeding is what keeps an unrelated edit from unmounting
/// everything.** Seeded empty, the diff would read every existing mount
/// as dropped, and renaming a profile would silently stop three lists
/// filtering the devices that point at it.
#[test]
fn renaming_a_profile_does_not_unmount_its_lists() {
    let p = Profile {
        custom_lists: vec![
            Id::new("handheld").unwrap(),
            Id::new("home-exceptions").unwrap(),
        ],
        ..mk_profile()
    };
    let mut f = ProfileForm::new_edit("kids", &p, mk_lists(), mk_custom_lists());
    f.display_name = "Kids and guests".into();
    let orig = f.original.clone().unwrap();
    let patch = resolve_edit_patch(&f, &orig).unwrap();
    assert_eq!(patch.display_name.as_deref(), Some("Kids and guests"));
    assert!(
        patch.custom_lists.is_none(),
        "an untouched mount panel emits no delta: {:?}",
        patch.custom_lists
    );
}

#[test]
fn mounting_emits_only_the_new_id() {
    let p = Profile {
        custom_lists: vec![Id::new("handheld").unwrap()],
        ..mk_profile()
    };
    let mut f = ProfileForm::new_edit("kids", &p, mk_lists(), mk_custom_lists());
    f.focused = FormField::CustomListMount(1); // home-exceptions
    f.toggle_custom_list_mount();
    let orig = f.original.clone().unwrap();
    let delta = resolve_edit_patch(&f, &orig)
        .unwrap()
        .custom_lists
        .expect("a mount is a change");
    assert_eq!(delta.mount, ["home-exceptions"]);
    assert!(
        delta.unmount.is_empty(),
        "the untouched mount is not re-declared: {:?}",
        delta.unmount
    );
}

#[test]
fn unmounting_emits_only_the_dropped_id() {
    let p = Profile {
        custom_lists: vec![
            Id::new("handheld").unwrap(),
            Id::new("home-exceptions").unwrap(),
        ],
        ..mk_profile()
    };
    let mut f = ProfileForm::new_edit("kids", &p, mk_lists(), mk_custom_lists());
    f.focused = FormField::CustomListMount(0); // handheld
    f.toggle_custom_list_mount();
    let orig = f.original.clone().unwrap();
    let delta = resolve_edit_patch(&f, &orig)
        .unwrap()
        .custom_lists
        .expect("an unmount is a change");
    assert!(
        delta.mount.is_empty(),
        "nothing was mounted: {:?}",
        delta.mount
    );
    assert_eq!(delta.unmount, ["handheld"]);
}

/// Two presses land back where they started, and the patch says so —
/// an operator who changes their mind mid-form does not spend a write.
#[test]
fn toggling_a_mount_twice_leaves_the_patch_empty() {
    let mut f = ProfileForm::new_edit("kids", &mk_profile(), mk_lists(), mk_custom_lists());
    f.focused = FormField::CustomListMount(0);
    f.toggle_custom_list_mount();
    f.toggle_custom_list_mount();
    let orig = f.original.clone().unwrap();
    assert_eq!(
        resolve_edit_patch(&f, &orig).unwrap(),
        ProfileUpdatePatch::default(),
        "a round trip is not a change"
    );
}

/// A mount row absorbs `i` the way every non-panel row does — it is not
/// a second `ignore` valve. Pinned because `press_ignore` keys off
/// `focused_list_row`, which is a DIFFERENT index space: an off-by-one
/// there would declare `Ignore` on whatever blocklist shares the index.
#[test]
fn the_ignore_valve_does_not_reach_a_mount_row() {
    let mut f = ProfileForm::new_edit("kids", &mk_profile(), mk_lists(), mk_custom_lists());
    f.focused = FormField::CustomListMount(0);
    assert!(!f.press_ignore(), "no declaration lands from a mount row");
    assert!(f.ignore_armed.is_none(), "and nothing is armed");
    assert!(
        f.lists_draft.is_empty(),
        "no blocklist override was written: {:?}",
        f.lists_draft
    );
}

/// A focus index that outlived a shorter snapshot must miss, not index
/// out of range.
#[test]
fn a_stale_mount_focus_is_inert_rather_than_a_panic() {
    let mut f = ProfileForm::new_edit("kids", &mk_profile(), mk_lists(), mk_custom_lists());
    f.focused = FormField::CustomListMount(9);
    assert!(f.focused_custom_list_row().is_none());
    f.toggle_custom_list_mount();
    assert!(f.custom_lists_draft.is_empty());
}

// ── Key dispatch ─────────────────────────────────────────────────

fn mount_app(profile: Profile) -> crate::tui::app::App {
    let mut app = crate::tui::app::App::new();
    app.active_leaf = crate::tui::app::Leaf::Profiles;
    app.profiles.modal = Some(ProfileModal::open_edit(
        "kids",
        &profile,
        mk_lists(),
        mk_custom_lists(),
    ));
    app
}

fn dead_poller() -> crate::tui::ipc_poller::IpcPoller {
    crate::tui::ipc_poller::IpcPoller::new(std::path::Path::new(
        "/nonexistent/purge-warden-mount-panel.sock",
    ))
}

fn dead_cfg() -> &'static std::path::Path {
    std::path::Path::new("/nonexistent/purge-warden-mount-panel.toml")
}

async fn press(app: &mut crate::tui::app::App, code: crossterm::event::KeyCode) {
    let key = crossterm::event::KeyEvent::new(code, crossterm::event::KeyModifiers::NONE);
    crate::tui::handle_profile_modal_key(app, key, &dead_poller(), dead_cfg()).await;
}

fn form_of(app: &crate::tui::app::App) -> &ProfileForm {
    match &app.profiles.modal.as_ref().unwrap().stage {
        Stage::EditingForm(f) => f,
        other => panic!("expected EditingForm, got {other:?}"),
    }
}

/// All three keys the legend advertises flip the row, and each is its
/// own arm rather than a fall-through.
#[tokio::test]
async fn both_arrows_and_space_flip_a_mount_row() {
    use crossterm::event::KeyCode;
    for code in [KeyCode::Right, KeyCode::Left, KeyCode::Char(' ')] {
        let mut app = mount_app(mk_profile());
        match &mut app.profiles.modal.as_mut().unwrap().stage {
            Stage::EditingForm(f) => f.focused = FormField::CustomListMount(0),
            other => panic!("expected EditingForm, got {other:?}"),
        }
        press(&mut app, code).await;
        let ids: Vec<&str> = form_of(&app)
            .custom_lists_draft
            .iter()
            .map(|i| i.as_str())
            .collect();
        assert_eq!(ids, ["handheld"], "{code:?} must mount the focused row");
    }
}

/// **The `_` arm is the hazard this pins.** `KeyCode::Right`'s match
/// falls through to `cycle_dropdown` for every field it does not name,
/// so a mount row absorbed by the catch-all would edit `block_response`
/// or `ecs_mode` — a field the operator is not looking at, and one a
/// test that only checked "the mount changed" would never see.
#[tokio::test]
async fn an_arrow_on_a_mount_row_moves_no_dropdown() {
    use crossterm::event::KeyCode;
    let mut app = mount_app(mk_profile());
    let (br, ecs, block_all) = {
        let f = form_of(&app);
        (f.block_response_idx, f.ecs_mode_idx, f.block_all)
    };
    match &mut app.profiles.modal.as_mut().unwrap().stage {
        Stage::EditingForm(f) => f.focused = FormField::CustomListMount(1),
        other => panic!("expected EditingForm, got {other:?}"),
    }
    press(&mut app, KeyCode::Right).await;
    let f = form_of(&app);
    assert_eq!(f.block_response_idx, br, "block response must not move");
    assert_eq!(f.ecs_mode_idx, ecs, "ecs mode must not move");
    assert_eq!(f.block_all, block_all, "block all must not flip");
    assert!(
        f.custom_lists_draft
            .contains(&Id::new("home-exceptions").unwrap()),
        "the row the operator IS looking at changed"
    );
}

// ── Render ───────────────────────────────────────────────────────

/// Render the modal tall enough that the field region does not scroll,
/// so both panels are on screen at once.
///
/// The 80\u{d7}24 floor is a different question and has its own test
/// (`viewport_follows_focus_to_the_last_field`): there the viewport is
/// two rows and the panel is reached by focus. What these assertions are
/// about is the SHAPE of a row, which needs the row rendered, not the
/// window that carries it.
fn render_tall(modal: &ProfileModal) -> String {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    let mut term = Terminal::new(TestBackend::new(80, 64)).unwrap();
    term.draw(|f| render_overlay(f, f.area(), modal)).unwrap();
    dump_buffer(term.backend().buffer())
}

/// The panel names every declared list and shows the mounted one's
/// state. A handler test cannot see this: it asserts about a draft set,
/// and the operator reads a row.
#[test]
fn the_mount_panel_names_every_declared_list_and_marks_the_mounted_one() {
    let p = Profile {
        custom_lists: vec![Id::new("handheld").unwrap()],
        ..mk_profile()
    };
    let modal = ProfileModal::open_edit("kids", &p, mk_lists(), mk_custom_lists());
    let dump = render_tall(&modal);

    assert!(
        dump.contains("CUSTOM LISTS"),
        "the section names itself:\n{dump}"
    );
    for id in ["handheld", "home-exceptions"] {
        assert!(dump.contains(id), "{id} must have a row:\n{dump}");
    }
    let mounted_row = dump
        .lines()
        .find(|l| l.contains("handheld"))
        .expect("handheld has a row");
    assert!(
        mounted_row.contains(CUSTOM_LIST_BOX_ON) && mounted_row.contains(CUSTOM_LIST_MOUNTED),
        "a mounted row is checked and named: {mounted_row:?}"
    );
    let unmounted_row = dump
        .lines()
        .find(|l| l.contains("home-exceptions"))
        .expect("home-exceptions has a row");
    assert!(
        unmounted_row.contains(CUSTOM_LIST_BOX_OFF),
        "an unmounted row shows the empty box: {unmounted_row:?}"
    );
    assert!(
        !unmounted_row.contains(CUSTOM_LIST_MOUNTED),
        "and does not claim to be mounted: {unmounted_row:?}"
    );
}

/// **The mount panel and the Profiles detail panel must name the same
/// relation with the same word.** Two surfaces that call one thing two
/// things teach the operator they are two things.
///
/// Not a restatement of the constant's own line: this fails if either
/// side is changed alone, which is the only way the pair can drift.
#[test]
fn the_mount_word_is_the_one_the_detail_panel_already_uses() {
    let sibling = crate::tui::tabs::profiles::PROFILE_CUSTOM_LISTS_NONE;
    assert!(
        sibling.contains(CUSTOM_LIST_MOUNTED),
        "the panel says {CUSTOM_LIST_MOUNTED:?} where the detail panel says {sibling:?}"
    );
}

/// With nothing declared the panel says so AND says where to fix it —
/// an empty panel with no pointer leaves the operator nowhere to go.
#[test]
fn an_empty_mount_panel_points_at_the_leaf_that_fills_it() {
    let modal = ProfileModal::open_edit("kids", &mk_profile(), mk_lists(), Vec::new());
    let dump = render_tall(&modal);
    assert!(
        dump.contains("CUSTOM LISTS"),
        "the section still renders:\n{dump}"
    );
    assert!(
        dump.contains(CUSTOM_LIST_PANEL_EMPTY),
        "the pointer survives the row's width budget:\n{dump}"
    );
}

/// **The colour split is the one claim `dump_buffer` cannot see.** It
/// reads symbols, so every render test here passes with both arms of
/// `mount_value_kind` swapped, or with one kind returned
/// unconditionally. A mounted list and an inert one would then be the
/// same colour on the surface whose job is showing which is which.
#[test]
fn a_mounted_row_and_an_unmounted_row_are_not_the_same_colour() {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    let p = Profile {
        custom_lists: vec![Id::new("handheld").unwrap()],
        ..mk_profile()
    };
    let modal = ProfileModal::open_edit("kids", &p, mk_lists(), mk_custom_lists());
    let mut term = Terminal::new(TestBackend::new(80, 64)).unwrap();
    term.draw(|f| render_overlay(f, f.area(), &modal)).unwrap();
    let buf = term.backend().buffer();

    // The checkbox opens the value, and no id in the fixture carries a
    // bracket, so the first `[` on a row is the start of its value.
    let value_fg = |needle: &str| {
        let y = (0..buf.area.height)
            .find(|&y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol())
                    .collect::<String>()
                    .contains(needle)
            })
            .unwrap_or_else(|| panic!("{needle} must have a row"));
        let x = (0..buf.area.width)
            .find(|&x| buf[(x, y)].symbol() == "[")
            .unwrap_or_else(|| panic!("{needle}'s row must carry a checkbox"));
        buf[(x, y)].fg
    };

    let mounted = value_fg("handheld");
    let unmounted = value_fg("home-exceptions");
    assert_eq!(
        mounted,
        ValueKind::Healthy.color(),
        "a mounted row reads as active"
    );
    assert_eq!(
        unmounted,
        ValueKind::Editable.color(),
        "an unmounted row recedes rather than warning"
    );
    assert_ne!(mounted, unmounted, "and the two must be distinguishable");
}

/// The focused row carries the `‹ ›` marker the sibling panel uses for
/// "a key changes this", and the value it wraps is not clipped by it.
#[test]
fn a_focused_mount_row_keeps_its_marker_and_its_value() {
    let p = Profile {
        custom_lists: vec![Id::new("handheld").unwrap()],
        ..mk_profile()
    };
    let mut modal = ProfileModal::open_edit("kids", &p, mk_lists(), mk_custom_lists());
    modal.form_mut().unwrap().focused = FormField::CustomListMount(0);
    let dump = render_tall(&modal);
    let row = dump
        .lines()
        .find(|l| l.contains("handheld"))
        .expect("handheld has a row");
    assert!(
        row.contains('\u{2039}') && row.contains('\u{203a}'),
        "the focus markers survive: {row:?}"
    );
    assert!(
        row.contains(CUSTOM_LIST_MOUNTED),
        "and the value they wrap is whole: {row:?}"
    );
}

#[test]
fn no_inline_test_module_remains_in_profile_modal() {
    crate::tui::cfg_scan::assert_no_inline_test_module(
        "profile_modal.rs",
        include_str!("../profile_modal.rs"),
    );
}
