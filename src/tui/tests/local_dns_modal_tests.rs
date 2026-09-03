use super::*;

fn rec(domain: &str, value: &str, ms: bool, ttl: Option<u32>) -> LocalDnsRecord {
    LocalDnsRecord {
        domain: domain.into(),
        record_type: LocalDnsRecordType::A,
        value: value.into(),
        match_subdomains: ms,
        ttl_secs: ttl,
    }
}

#[test]
fn s44_form_field_next_cycles_through_all_eight_in_order() {
    let mut f = FormField::Domain;
    let order = [
        FormField::RecordType,
        FormField::Value,
        FormField::MatchSubdomains,
        FormField::Ttl,
        FormField::Profile,
        FormField::Submit,
        FormField::Cancel,
        FormField::Domain,
    ];
    for expected in order {
        f = f.next();
        assert_eq!(f, expected);
    }
}

#[test]
fn s44_form_field_prev_walks_backwards_and_wraps() {
    let f = FormField::Domain;
    assert_eq!(f.prev(), FormField::Cancel);
    assert_eq!(FormField::RecordType.prev(), FormField::Domain);
}

#[test]
fn s44_add_modal_form_validation_rejects_empty_domain() {
    let modal = LocalDnsModal::open_add(vec!["default".into(), "kids".into()], 0);
    let form = modal.form().unwrap();
    let err = form.try_resolve().unwrap_err();
    assert!(err.contains("domain"), "empty domain must error: {err}");
}

#[test]
fn s44_add_modal_form_validation_rejects_empty_value() {
    let mut modal = LocalDnsModal::open_add(vec!["default".into()], 0);
    let form = modal.form_mut().unwrap();
    form.domain = "nas.home".into();
    // value left empty
    let err = modal.form().unwrap().try_resolve().unwrap_err();
    assert!(err.contains("value"), "empty value must error: {err}");
}

#[test]
fn s44_add_modal_form_validation_rejects_invalid_ttl() {
    let mut modal = LocalDnsModal::open_add(vec!["default".into()], 0);
    let form = modal.form_mut().unwrap();
    form.domain = "nas.home".into();
    form.value = "192.168.1.50".into();
    form.ttl_input = "not-a-number".into();
    let err = modal.form().unwrap().try_resolve().unwrap_err();
    assert!(err.contains("ttl_secs"), "bad TTL must error: {err}");
}

#[test]
fn s44_add_modal_form_validation_rejects_zero_ttl_inline() {
    // Regression: `0` parses as a u32 (it IS a non-negative integer),
    // so the old parse-only check let it through and the operator only
    // learned it was invalid after Apply hit the DR5 config validator.
    // The inline range check must now reject it up front.
    let mut modal = LocalDnsModal::open_add(vec!["default".into()], 0);
    let form = modal.form_mut().unwrap();
    form.domain = "nas.home".into();
    form.value = "192.168.1.50".into();
    form.ttl_input = "0".into();
    let err = modal.form().unwrap().try_resolve().unwrap_err();
    assert!(
        err.contains("out of range"),
        "TTL 0 must be rejected inline: {err}"
    );
}

#[test]
fn s44_parse_ttl_empty_is_none_and_range_is_enforced() {
    // Empty → None (use the [local_dns].ttl_secs default) must stay
    // valid — the optional case the modal relies on.
    assert_eq!(parse_ttl(""), Ok(None));
    assert_eq!(parse_ttl("   "), Ok(None), "whitespace-only is still empty");
    // In-range boundaries accepted.
    assert_eq!(parse_ttl("1"), Ok(Some(1)));
    assert_eq!(parse_ttl("86400"), Ok(Some(86_400)));
    assert_eq!(parse_ttl("3600"), Ok(Some(3600)));
    // Out-of-range rejected inline (mirrors DR5's 1..=86_400 window).
    assert!(parse_ttl("0").unwrap_err().contains("out of range"));
    assert!(parse_ttl("86401").unwrap_err().contains("out of range"));
    // Non-integer still hits the parse-error branch, unchanged.
    assert!(parse_ttl("abc").unwrap_err().contains("ttl_secs"));
}

#[test]
fn s44_add_modal_form_resolves_global_scope_when_profile_idx_zero() {
    let mut modal = LocalDnsModal::open_add(vec!["default".into(), "kids".into()], 0);
    let form = modal.form_mut().unwrap();
    form.domain = "nas.home".into();
    form.value = "192.168.1.50".into();
    let (scope, spec) = modal.form().unwrap().try_resolve().unwrap();
    assert_eq!(scope, LocalRecordScope::Global);
    assert_eq!(spec.domain, "nas.home");
    assert_eq!(spec.value, "192.168.1.50");
    assert_eq!(spec.record_type, LocalDnsRecordType::A);
    assert!(!spec.match_subdomains);
    assert_eq!(spec.ttl_secs, None);
}

#[test]
fn s44_add_modal_form_resolves_profile_scope_when_profile_idx_nonzero() {
    let mut modal = LocalDnsModal::open_add(vec!["default".into(), "kids".into()], 0);
    let form = modal.form_mut().unwrap();
    form.domain = "example.test".into();
    form.value = "192.0.2.50".into();
    form.profile_idx = 2; // 0=Global, 1=default, 2=kids
    form.match_subdomains = true;
    form.ttl_input = "7200".into();
    let (scope, spec) = modal.form().unwrap().try_resolve().unwrap();
    assert_eq!(scope, LocalRecordScope::Profile("kids".into()));
    assert_eq!(spec.domain, "example.test");
    assert!(spec.match_subdomains);
    assert_eq!(spec.ttl_secs, Some(7200));
}

#[test]
fn s44_add_modal_form_canonicalises_domain_to_lowercase() {
    let mut modal = LocalDnsModal::open_add(vec![], 0);
    let form = modal.form_mut().unwrap();
    form.domain = "  NAS.Home  ".into();
    form.value = "192.168.1.50".into();
    let (_, spec) = modal.form().unwrap().try_resolve().unwrap();
    assert_eq!(spec.domain, "nas.home", "domain trimmed + lowercased");
}

#[test]
fn s44_add_modal_dropdown_lists_global_plus_each_profile() {
    let modal = LocalDnsModal::open_add(vec!["default".into(), "kids".into(), "guest".into()], 0);
    let form = modal.form().unwrap();
    assert_eq!(form.profile_options_len(), 4); // 1 Global + 3 profiles
    assert_eq!(form.profile_option_label(), "Global");
}

#[test]
fn s44_add_modal_default_profile_idx_clamps_to_options_len() {
    // open_add called with default_idx=99 against 2 profiles → 3
    // options total → idx must clamp to options_len-1, not panic.
    let modal = LocalDnsModal::open_add(vec!["default".into(), "kids".into()], 99);
    let form = modal.form().unwrap();
    assert!(
        form.profile_idx < form.profile_options_len(),
        "idx must clamp to options_len"
    );
}

// ── Edit modal ────────────────────────────────────────────────────

#[test]
fn s44_edit_modal_prefills_from_row() {
    let r = rec("example.test", "192.0.2.50", true, Some(3600));
    let modal = LocalDnsModal::open_edit(
        LocalRecordScope::Profile("kids".into()),
        &r,
        vec!["default".into(), "kids".into()],
    );
    let form = modal.form().unwrap();
    assert_eq!(form.mode, FormMode::Edit);
    assert_eq!(form.domain, "example.test");
    assert_eq!(form.value, "192.0.2.50");
    assert!(form.match_subdomains);
    assert_eq!(form.ttl_input, "3600");
    assert_eq!(
        form.profile_idx, 2,
        "kids is option 2 (after Global, default)"
    );
    assert!(
        form.original.is_some(),
        "Edit captures the original snapshot"
    );
}

#[test]
fn s44_edit_modal_falls_back_to_global_when_profile_id_unknown() {
    let r = rec("nas.home", "192.168.1.50", false, None);
    // Original scope is profile 'ghost' but the snapshot only knows
    // about 'default' — the dropdown lands on Global instead of
    // panicking on a missing profile id.
    let modal = LocalDnsModal::open_edit(
        LocalRecordScope::Profile("ghost".into()),
        &r,
        vec!["default".into()],
    );
    assert_eq!(modal.form().unwrap().profile_idx, 0);
}

// ── Remove modal — tiered confirm ─────────────────────────────────

#[test]
fn s44_remove_modal_global_exact_match_uses_single_keypress_tier() {
    let r = rec("nas.home", "192.168.1.50", false, None);
    let modal = LocalDnsModal::open_remove(LocalRecordScope::Global, &r);
    let rc = modal.remove().unwrap();
    assert_eq!(rc.tier, ConfirmTier::SingleKeypress);
    assert!(rc.typed_phrase_matches(), "single-keypress is always ready");
}

#[test]
fn s44_remove_modal_global_match_subdomains_uses_typed_phrase_tier() {
    let r = rec("example.test", "192.0.2.50", true, None);
    let modal = LocalDnsModal::open_remove(LocalRecordScope::Global, &r);
    let rc = modal.remove().unwrap();
    assert_eq!(rc.tier, ConfirmTier::TypedPhrase);
    assert!(
        !rc.typed_phrase_matches(),
        "empty buffer must NOT satisfy typed-phrase confirm"
    );
}

#[test]
fn s44_remove_modal_profile_scope_always_uses_single_keypress_tier() {
    // Even with match_subdomains=true, profile-scope removals stay
    // at the cheap tier — the blast radius is bounded by the profile.
    let r = rec("example.test", "192.0.2.50", true, None);
    let modal = LocalDnsModal::open_remove(LocalRecordScope::Profile("kids".into()), &r);
    assert_eq!(modal.remove().unwrap().tier, ConfirmTier::SingleKeypress);
}

#[test]
fn s44_remove_modal_typed_phrase_accepts_exact_domain_case_insensitive() {
    let r = rec("example.test", "192.0.2.50", true, None);
    let mut modal = LocalDnsModal::open_remove(LocalRecordScope::Global, &r);
    let rc = modal.remove_mut().unwrap();
    rc.buffer = "example.test".into();
    assert!(
        rc.typed_phrase_matches(),
        "case-insensitive match accepts mixed case input"
    );
}

#[test]
fn s44_remove_modal_typed_phrase_rejects_wrong_domain() {
    let r = rec("example.test", "192.0.2.50", true, None);
    let mut modal = LocalDnsModal::open_remove(LocalRecordScope::Global, &r);
    let rc = modal.remove_mut().unwrap();
    rc.buffer = "evil.com".into();
    assert!(!rc.typed_phrase_matches());
}

// ── Cycling helpers ───────────────────────────────────────────────

#[test]
fn s44_cycle_record_type_walks_a_aaaa_cname_and_wraps() {
    assert_eq!(
        cycle_record_type_next(LocalDnsRecordType::A),
        LocalDnsRecordType::AAAA
    );
    assert_eq!(
        cycle_record_type_next(LocalDnsRecordType::AAAA),
        LocalDnsRecordType::CNAME
    );
    assert_eq!(
        cycle_record_type_next(LocalDnsRecordType::CNAME),
        LocalDnsRecordType::A
    );
    assert_eq!(
        cycle_record_type_prev(LocalDnsRecordType::A),
        LocalDnsRecordType::CNAME
    );
}

// ── Lifecycle ─────────────────────────────────────────────────────

#[test]
fn s44_modal_finish_transitions_to_submitted() {
    let mut modal = LocalDnsModal::open_add(vec![], 0);
    assert!(!modal.is_submitted());
    modal.finish(SubmitOutcome::Ok("done".into()));
    assert!(modal.is_submitted());
}

#[test]
fn s44_modal_form_accessors_only_yield_some_in_editing_stage() {
    let mut modal = LocalDnsModal::open_add(vec![], 0);
    assert!(modal.form().is_some());
    assert!(modal.remove().is_none());
    modal.finish(SubmitOutcome::Failed("x".into()));
    assert!(modal.form().is_none());
    assert!(modal.remove().is_none());
}

// ── Form render ───────────────────────────────────────────────────

/// Flatten the whole body — head, field region, tail — into one
/// string for content assertions.
fn render_text(form: &AddForm, width: u16) -> String {
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

#[test]
fn form_renders_banded_title_labelled_sections_and_actions() {
    // Replaces `grid_form_renders_header_caret_and_active_marker`.
    // Two of its assertions were pinning the surface this wave
    // removes, and are gone deliberately:
    //   * `Field` / `Value` — the legacy `│`-ruled grid header, which
    //     Archetype F replaces with labelled section bands;
    //   * `nas_` — the fake `_` caret. The ecosystem rows carry none;
    //     the real terminal cursor marks the insertion point, and it
    //     is asserted in `floor_hardware_cursor_sits_in_the_focused_
    //     text_field`, where a buffer dump cannot reach.
    let mut modal = LocalDnsModal::open_add(vec!["kids".into()], 0);
    let form = modal.form_mut().unwrap();
    form.domain = "nas".into(); // focus defaults to Domain
    let text = render_text(form, 60);

    assert!(text.contains("Add local DNS record"), "banded title");
    for section in ["RECORD", "MATCHING", "SCOPE"] {
        assert!(text.contains(section), "missing {section} section band");
    }
    assert!(text.contains("nas"), "the typed value is on its row");
    assert!(text.contains('◀'), "active row carries the focus marker");
    assert!(
        text.contains("name to answer locally"),
        "validation line shows the focused field's hint"
    );
    assert!(text.contains("Save"), "Save action present");
    assert!(text.contains("Discard"), "Discard action present");
}

#[test]
fn grid_form_focused_selector_is_wrapped_in_angle_brackets() {
    let mut modal = LocalDnsModal::open_add(vec![], 0);
    let form = modal.form_mut().unwrap();
    form.focused = FormField::RecordType;
    let text = render_text(form, 60);
    assert!(
        text.contains("‹ A ›"),
        "a focused selector value is wrapped to signal ←/→ cycles it"
    );
}

#[test]
fn grid_form_inline_error_replaces_the_hint_line() {
    let mut modal = LocalDnsModal::open_add(vec![], 0);
    let form = modal.form_mut().unwrap();
    form.error_message = Some("value is required".into());
    let text = render_text(form, 60);
    assert!(text.contains("⚠ value is required"), "error shows inline");
    // The hint for the (default-focused) Domain field is suppressed
    // while an error is pending.
    assert!(!text.contains("name to answer locally"));
}

// ── §4.61 Wave 2b — Archetype F at the 80×24 floor ────────────────
//
// Everything below asserts on the RENDERED BUFFER, never on the line
// vector. Every past instance of `lists-modal-min-height-clip` had a
// correct line vector; the defect lived only in what reached the
// screen.

/// The D18 anchor at the declared floor. `ui.rs::layout_chunks` gives
/// a 4-row header, a 5-row menu card (Network is a multi-leaf
/// section) and a 1-row footer, so a leaf tab's content rect on an
/// 80×24 terminal is exactly `(0, 9, 80, 14)` — 12 interior rows once
/// the modal frame takes its two.
fn floor_anchor() -> Rect {
    Rect::new(0, 9, 80, 14)
}

fn draw_at_floor(modal: &LocalDnsModal) -> ratatui::buffer::Buffer {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
    term.draw(|f| render_overlay(f, floor_anchor(), modal))
        .unwrap();
    term.backend().buffer().clone()
}

/// Row-by-row cell-symbol dump. No ANSI ever enters a `TestBackend`
/// buffer — styling is a per-cell `Style`, not interleaved escapes —
/// so this is a faithful plain-text reconstruction of the screen.
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

fn dump_at_floor(modal: &LocalDnsModal) -> String {
    dump_buffer(&draw_at_floor(modal))
}

/// A form with a distinct, greppable value in every field, so a
/// `label + value` row assertion cannot be satisfied by accident from
/// the hint line or the title band.
fn floor_form(focus: FormField) -> LocalDnsModal {
    let mut modal = LocalDnsModal::open_add(vec!["kids".into()], 0);
    let form = modal.form_mut().unwrap();
    form.domain = "nas.home".into();
    form.value = "10.9.9.9".into();
    form.ttl_input = "300".into();
    form.focused = focus;
    modal
}

/// `(label, on-row evidence)` for each editable field — the two
/// strings that must land on the SAME screen row for that field to be
/// genuinely visible.
const FLOOR_ROWS: [(FormField, &str, &str); 6] = [
    (FormField::Domain, "domain", "nas.home"),
    (FormField::RecordType, "type", "\u{2039} A \u{203a}"),
    (FormField::Value, "value", "10.9.9.9"),
    (FormField::MatchSubdomains, "match subdomains", "No"),
    (FormField::Ttl, "ttl", "300"),
    (FormField::Profile, "profile", "\u{2039} Global \u{203a}"),
];

#[test]
fn floor_action_row_and_focused_field_are_on_screen_together() {
    // DoD 3. A clipped modal still lets Tab reach the Save it has cut,
    // so the operator commits blind — the two things a clip silently
    // takes away are the action row and the field under focus, and the
    // only assertion that catches it demands BOTH in one render.
    for (focus, label, evidence) in FLOOR_ROWS {
        let s = dump_at_floor(&floor_form(focus));
        assert!(
            s.contains("Save"),
            "{focus:?}: action row off-screen at 80\u{d7}24:\n{s}"
        );
        assert!(
            s.lines().any(|l| l.contains(label) && l.contains(evidence)),
            "{focus:?}: focused row ('{label}' + '{evidence}') off-screen \
             at 80\u{d7}24:\n{s}"
        );
    }
}

#[test]
fn floor_viewport_follows_focus_to_the_last_field() {
    // DoD 4. A viewport pinned to page one would satisfy the test
    // above for the first fields and still hide the last.
    let last = dump_at_floor(&floor_form(FormField::Profile));
    assert!(
        last.lines()
            .any(|l| l.contains("profile") && l.contains("\u{2039} Global \u{203a}")),
        "focused last field is off-screen:\n{last}"
    );
    let first = dump_at_floor(&floor_form(FormField::Domain));
    assert!(
        first
            .lines()
            .any(|l| l.contains("domain") && l.contains("nas.home")),
        "focused first field is off-screen:\n{first}"
    );
    assert!(
        !first.contains("\u{2039} Global \u{203a}"),
        "a 4-row viewport cannot be showing both ends at once — the \
         viewport is not moving:\n{first}"
    );
}

#[test]
fn floor_modal_never_paints_outside_the_content_anchor() {
    // DoD 2 / §4.62 N1: the header, the menu card and the footer
    // legend are off limits to anything transient.
    let anchor = floor_anchor();
    for modal in [
        floor_form(FormField::Domain),
        LocalDnsModal::open_remove(
            LocalRecordScope::Global,
            &rec("wild.home", "10.9.9.9", true, None),
        ),
        {
            let mut m = LocalDnsModal::open_add(vec![], 0);
            m.finish(SubmitOutcome::Ok("added nas.home".into()));
            m
        },
    ] {
        let buf = draw_at_floor(&modal);
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                if anchor.contains(ratatui::layout::Position { x, y }) {
                    continue;
                }
                assert_eq!(
                    buf[(x, y)].symbol(),
                    " ",
                    "the modal painted ({x},{y}), outside the content rect \
                     {anchor:?}:\n{}",
                    dump_buffer(&buf)
                );
            }
        }
    }
}

#[test]
fn a_long_typed_phrase_buffer_scrolls_left_and_keeps_the_caret() {
    // The buffer row used to ride a plain `ProseRow`, which truncates
    // on the right (`fit`) — backwards for text being typed INTO,
    // since the caret and whatever was just typed sit at the end.
    // `tail_fit` keeps the tail instead. "xxx_" is the only needle
    // that discriminates: the pre-fix render also ends in an
    // ellipsis, just on the other side, so an assertion on `…` alone
    // would still pass unfixed.
    let mut modal = LocalDnsModal::open_remove(
        LocalRecordScope::Global,
        &rec("wild.home", "10.9.9.9", true, None),
    );
    modal.remove_mut().unwrap().buffer = "x".repeat(200);
    let s = dump_at_floor(&modal);
    assert!(
        s.contains("xxx_"),
        "the caret must stay visible at the end of a long buffer:\n{s}"
    );
    assert!(
        s.contains('\u{2026}'),
        "the horizontal scroll must be marked:\n{s}"
    );
}

#[test]
fn floor_typed_phrase_confirm_keeps_the_input_row_on_screen() {
    // An Archetype-C body gets exactly 4 scrolling rows at the floor
    // and has no `focus_row` to scroll to, so a fifth prose row is
    // unreachable — silently. The row that would vanish here is the
    // one the operator types into, on the highest-blast-radius gesture
    // in the module.
    let mut modal = LocalDnsModal::open_remove(
        LocalRecordScope::Global,
        &rec("wild.home", "10.9.9.9", true, None),
    );
    modal.remove_mut().unwrap().buffer = "wild.ho".into();
    let s = dump_at_floor(&modal);
    assert!(
        s.contains("wild.ho_"),
        "typed-phrase buffer off-screen at 80\u{d7}24 — the operator \
         confirms a wildcard removal blind:\n{s}"
    );
    assert!(
        s.contains("wild.home"),
        "the record being removed is off-screen:\n{s}"
    );
}

/// Chrome and indents stripped, so a domain that had to wrap across
/// two rows reads back contiguous. `…` is deliberately kept — it is
/// exactly what the transcription target must never produce.
fn dechrome(dump: &str) -> String {
    dump.chars()
        .filter(|c| {
            !matches!(
                c,
                ' ' | '\n'
                    | '\u{2502}'
                    | '\u{2500}'
                    | '\u{256d}'
                    | '\u{256e}'
                    | '\u{2570}'
                    | '\u{256f}'
                    | '\u{258c}'
                    | '\u{2588}'
                    | '\u{25c0}'
            )
        })
        .collect()
}

/// The gate compares the buffer against `rc.spec.domain` **alone**, so
/// the domain has to be on screen whole — and it has to be legible as
/// its own token.
///
/// Two distinct failures live here. The row was
/// `"{domain} ({type}) → {value}"`, so (a) past the interior width the
/// domain was ellipsised and no keystroke sequence could satisfy the
/// gate, and (b) even rendered whole, three fields on one row do not
/// say where the string the operator must type ends.
#[test]
fn typed_phrase_confirm_renders_a_long_domain_in_full_at_the_floor() {
    // 62 chars: past the 60 usable cells a `prose_row` leaves at the
    // 62-column interior, and well inside a legal DNS name.
    for n in 55..=64usize {
        let domain = format!("remove-me-{}.endsentinel", "x".repeat(n - 22));
        assert_eq!(domain.len(), n, "fixture must be exactly {n} chars");
        let modal = LocalDnsModal::open_remove(
            LocalRecordScope::Global,
            &rec(&domain, "10.9.9.9", true, None),
        );
        let s = dump_at_floor(&modal);
        // The domain wraps, so its tail is NOT contiguous on one row —
        // that is the fix working. What must never appear is a `…`,
        // and nothing else in this stage is long enough to produce
        // one.
        assert!(
            !s.contains('\u{2026}'),
            "a {n}-char domain was ellipsised — the gate compares \
             against all {n} bytes and the cut ones are \
             unrecoverable:\n{s}"
        );
        assert!(
            dechrome(&s).contains(&domain),
            "a {n}-char domain is not recoverable from the screen — \
             the operator cannot type what the gate demands:\n{s}"
        );
    }
}

/// Where the wrap runs out of budget, measured rather than reasoned
/// about.
///
/// The typed-phrase body is 3 prose rows plus the domain's own, so the
/// domain may spend 3 lines — 177 characters at the 59-cell wrap —
/// against Archetype C's 6-row content budget. At 178 it needs a
/// fourth and the body wants 7.
///
/// **What gets cut is the input row, not the domain.** `scroll_layout`
/// serves the tail, then the head, and the field region takes what is
/// left from the *front* — so the domain renders whole and the row the
/// operator types into falls off the bottom. They can see the string
/// to transcribe and not what they are transcribing. Silent by
/// construction: with no `choices` there is no focus target, the
/// viewport is pinned at offset 0, `ScrollBody::scrollable` is false
/// and not even a scrollbar appears.
///
/// A legal DNS name runs to 253, so this is reachable. Pinned rather
/// than fixed because the remedy is a scroll affordance for a
/// focus-less notice, which this module does not have. If that lands,
/// this test is the one to update.
#[test]
fn past_177_chars_the_wrap_costs_the_typed_phrase_input_its_row() {
    let probe = |len: usize| {
        let domain = format!("{}.endsentinel", "x".repeat(len - 12));
        assert_eq!(domain.len(), len);
        let mut modal = LocalDnsModal::open_remove(
            LocalRecordScope::Global,
            &rec(&domain, "10.9.9.9", true, None),
        );
        modal.remove_mut().unwrap().buffer = "ZZQQ".into();
        let s = dump_at_floor(&modal);
        // The domain, and the row the operator types into.
        (dechrome(&s).contains(&domain), s.contains("ZZQQ_"), s)
    };

    let (domain_whole, input_visible, dump) = probe(177);
    assert!(
        domain_whole && input_visible,
        "177 chars is inside the budget — both the domain and the \
         input row must be on screen:\n{dump}"
    );

    let (domain_whole, input_visible, dump) = probe(178);
    assert!(
        domain_whole,
        "the domain is cut at 178 — the overflow moved, so re-derive \
         both this test and `remove_notice`'s doc:\n{dump}"
    );
    assert!(
        !input_visible,
        "the input row survives at 178 — the budget changed, so update \
         this test and `remove_notice`'s doc together:\n{dump}"
    );
}

/// The answer to "does `hint_or_error_rows` need the verbatim
/// contract too?" — no, and this is why.
///
/// The refusal names the domain (`the domain is '…' — you typed '…'`)
/// and rides a 2-row region that ellipsises, so for a long domain that
/// message IS cut. That is acceptable precisely because the refusal is
/// no longer the operator's only sight of the string: the verbatim
/// prose row above it carries the domain whole, with a refusal pending
/// or without one. A hint is guidance about a transcription target,
/// never the target itself.
#[test]
fn a_refusal_never_becomes_the_only_sight_of_the_domain() {
    let domain = format!("refuse-me-{}.endsentinel", "x".repeat(42));
    assert_eq!(domain.len(), 64);
    let mut modal = LocalDnsModal::open_remove(
        LocalRecordScope::Global,
        &rec(&domain, "10.9.9.9", true, None),
    );
    let rc = modal.remove_mut().unwrap();
    rc.buffer = "wrong".into();
    assert!(!rc.confirm_or_refuse(), "fixture must be a mismatch");

    let s = dump_at_floor(&modal);
    assert!(
        s.contains('\u{26a0}'),
        "the refusal never reached the screen:\n{s}"
    );
    assert!(
        dechrome(&s).contains(&domain),
        "with a refusal pending the domain is no longer recoverable \
         whole — the operator has nothing left to transcribe:\n{s}"
    );
}

/// Contract item 5: the transcription target gets a row of its own.
///
/// The gate wants the domain and nothing else. A composite row showing
/// `domain (TYPE) → value` leaves the operator guessing where the
/// string they must type ends — a defect the length fix alone does not
/// touch.
#[test]
fn typed_phrase_confirm_gives_the_domain_a_row_of_its_own() {
    let modal = LocalDnsModal::open_remove(
        LocalRecordScope::Global,
        &rec("nas.home", "10.9.9.9", true, None),
    );
    let s = dump_at_floor(&modal);
    let row = s
        .lines()
        .find(|l| l.contains("nas.home"))
        .expect("the domain must be on screen");
    assert!(
        !row.contains("10.9.9.9"),
        "the gate compares against the domain alone, but its row also \
         carries the record value — nothing says where to stop \
         typing:\n{row}"
    );
}

/// The budget claim, measured rather than reasoned about: a refusal
/// must not cost the typed-phrase input its row at the D18 floor.
///
/// `remove_notice` leaves `hint_rows` at `None` and always ships a
/// non-empty `hint`, so `notice_body` reserves `HINT_ROWS` either way
/// and the error *displaces* the hint inside that region. That is the
/// argument; this is the measurement. The failure mode it guards is
/// silent — with no `choices` there is no focus target, so a row
/// pushed past the viewport is unreachable by any keystroke and
/// nothing announces it.
#[test]
fn floor_typed_phrase_refusal_keeps_the_input_row() {
    let mut modal = LocalDnsModal::open_remove(
        LocalRecordScope::Global,
        &rec("wild.home", "10.9.9.9", true, None),
    );
    let rc = modal.remove_mut().unwrap();
    rc.buffer = "wild.ho".into();
    assert!(!rc.confirm_or_refuse(), "fixture must be a mismatch");

    let s = dump_at_floor(&modal);
    assert!(
        s.contains('\u{26a0}'),
        "the refusal never reached the screen at 80\u{d7}24:\n{s}"
    );
    assert!(
        s.contains("wild.ho_"),
        "the refusal pushed the typed-phrase buffer off-screen \u{2014} \
         the operator now confirms a wildcard removal blind:\n{s}"
    );
    assert!(
        s.contains("wild.home"),
        "the refusal pushed the record being removed off-screen:\n{s}"
    );
}

/// The other half of the budget claim: the prose region is the same
/// three rows with a refusal pending as without one.
///
/// Weaker than the floor render above — it cannot see a row that
/// falls off the viewport — but it pins *where* the refusal lives, so
/// a later change that moves it into prose fails here with a reason
/// rather than at the floor with a geometry puzzle.
#[test]
fn refusal_costs_no_prose_row() {
    let mut modal = LocalDnsModal::open_remove(
        LocalRecordScope::Global,
        &rec("wild.home", "10.9.9.9", true, None),
    );
    let quiet = remove_notice(modal.remove().unwrap(), MODAL_W - 2)
        .prose
        .len();

    let rc = modal.remove_mut().unwrap();
    rc.buffer = "nope".into();
    rc.confirm_or_refuse();
    let spec = remove_notice(modal.remove().unwrap(), MODAL_W - 2);

    // Four since S3 split the composite row: the gate compares
    // against `rc.spec.domain` alone, so the domain gets a verbatim
    // row of its own and `(TYPE) → value` rides the row below it.
    assert_eq!(quiet, 4, "the typed-phrase prose budget is four rows");
    assert_eq!(
        spec.prose.len(),
        quiet,
        "a refusal must ride the error slot, not a prose row"
    );
    assert!(
        spec.error.is_some(),
        "the refusal never reached the notice at all"
    );
}

/// Enter with nothing typed is not a mistake to report — the operator
/// has not attempted the phrase yet, and the prompt row already says
/// what to do. Enter stays inert there, deliberately.
#[test]
fn confirm_or_refuse_is_quiet_on_an_empty_buffer() {
    let mut modal = LocalDnsModal::open_remove(
        LocalRecordScope::Global,
        &rec("wild.home", "10.9.9.9", true, None),
    );
    let rc = modal.remove_mut().unwrap();
    assert!(!rc.confirm_or_refuse(), "an empty buffer cannot submit");
    assert!(
        rc.error.is_none(),
        "nothing was typed, so there is nothing to reject: {:?}",
        rc.error
    );
}

/// A match submits and leaves nothing behind. Also covers the
/// single-keypress tier, where `typed_phrase_matches` is always true
/// and no refusal is reachable.
#[test]
fn confirm_or_refuse_is_silent_when_it_says_yes() {
    for (domain, ms) in [("wild.home", true), ("nas.home", false)] {
        let mut modal = LocalDnsModal::open_remove(
            LocalRecordScope::Global,
            &rec(domain, "10.9.9.9", ms, None),
        );
        let rc = modal.remove_mut().unwrap();
        if ms {
            rc.buffer = domain.into();
        }
        assert!(rc.confirm_or_refuse(), "{domain} should be ready to submit");
        assert!(rc.error.is_none(), "a yes must carry no complaint");
    }
}

/// A refusal describes one buffer. Editing that buffer must retract
/// it, or the screen contradicts itself: a message naming a phrase
/// the operator has already moved past.
#[test]
fn editing_the_buffer_retracts_the_refusal() {
    for edit in ["push", "backspace"] {
        let mut modal = LocalDnsModal::open_remove(
            LocalRecordScope::Global,
            &rec("wild.home", "10.9.9.9", true, None),
        );
        let rc = modal.remove_mut().unwrap();
        rc.buffer = "nope".into();
        rc.confirm_or_refuse();
        assert!(rc.error.is_some(), "fixture must start refused");

        match edit {
            "push" => rc.push_char('x'),
            _ => rc.backspace(),
        }
        assert!(
            rc.error.is_none(),
            "{edit} left a stale refusal: {:?}",
            rc.error
        );
    }
}

#[test]
fn floor_hardware_cursor_sits_in_the_focused_text_field() {
    // The ecosystem rows carry no `_` caret — the real terminal cursor
    // marks the insertion point (D7', same as the Lists reference), so
    // the only way to assert it is through the backend's cursor.
    use ratatui::backend::{Backend, TestBackend};
    use ratatui::Terminal;
    let modal = floor_form(FormField::Domain);
    let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
    term.draw(|f| render_overlay(f, floor_anchor(), &modal))
        .unwrap();
    let pos = term.backend_mut().get_cursor_position().unwrap();
    let dump = dump_buffer(term.backend().buffer());
    let row = dump.lines().nth(pos.y as usize).unwrap_or("");
    assert!(
        row.contains("domain") && row.contains("nas.home"),
        "cursor row {} is not the focused domain field:\n{dump}",
        pos.y
    );
    // Column: modal inner-left + VALUE_COL + what has been typed.
    let inner_x = (80 - MODAL_W) / 2 + 1;
    assert_eq!(
        pos.x,
        inner_x + modal_form::VALUE_COL as u16 + "nas.home".chars().count() as u16,
        "cursor is not at the end of the typed value:\n{dump}"
    );
}

#[test]
fn no_inline_test_module_remains_in_local_dns_modal() {
    crate::tui::cfg_scan::assert_no_inline_test_module(
        "local_dns_modal.rs",
        include_str!("../local_dns_modal.rs"),
    );
}
