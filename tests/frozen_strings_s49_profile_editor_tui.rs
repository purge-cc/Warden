//! §4.26 Phase 2 — Profiles tab (TUI) frozen strings.
//!
//! Pins byte-for-byte the operator-facing strings coined in §4.26 Phase 2:
//! the profile modal title bars, the synthetic `(inherit)` dropdown
//! option, the per-field-ecs-clear refusal hint, and the side-card
//! drill-out targets (which name the dedicated surfaces — Tags tab,
//! Local DNS tab, `warden rewrite` — so a rename forces a coordinated
//! update here + in `CONFIG_GUIDE.md` / `CONFIG_GUIDE.public.md`).
//!
//! Pairs with `frozen_strings_s49_profile_editor.rs` (Phase 1, which pins
//! the daemon audit actions + CLI parse errors). Phase 2's TUI submit
//! flows *through* the Phase 1 IPC handlers, so the audit strings are
//! NOT re-pinned here — they stay covered by the Phase 1 file.
//!
//! When one of these strings MUST change for a legitimate reason (UX
//! re-wording, a tab rename), update the literal here AND the mirrored
//! copy in the user docs in the same commit. Byte-for-byte equality has
//! no escape hatch — that is the entire point of this trip-wire (pattern
//! `frozen_strings_s49_profile_editor.rs`).

// ── Modal title bars (profile_modal.rs::render_overlay) ──────────────

const MODAL_TITLE_ADD: &str = " Add profile ";
const MODAL_TITLE_EDIT: &str = " Edit profile ";
const MODAL_TITLE_REMOVE: &str = " Remove profile ";
const MODAL_TITLE_DONE: &str = " Profile — done ";
const MODAL_TITLE_FAILED: &str = " Profile — failed ";

// ── Synthetic dropdown option + the D1-limitation disclosure ─────────

/// The clear-to-inherit dropdown option for the two nullable enum fields
/// (`block_response`, `ecs.mode`). Operator-facing — index 0 of both
/// `BLOCK_RESPONSE_OPTIONS` and `ECS_MODE_OPTIONS`.
const INHERIT_OPTION: &str = "(inherit)";

/// The per-field-ecs-clear refusal points the operator at the
/// whole-subtree toggle (the D1 limitation, deferred as
/// `s-4.26-p2-disc-1`). Pin the actionable fragment.
const ECS_CLEAR_HINT: &str = "clear ecs";

// ── Side-card drill-out targets (tabs/profiles.rs) — RETIRED ─────────
// tui-wave1 `profiles-summary` replaced the "manage in Tags/Local DNS/
// rewrite tab" pointer block with the offline "What it blocks" summary.
// Those drill-out strings no longer exist in tabs/profiles.rs; the
// replacement literals are pinned by tests/frozen_strings_tui_t1.rs.
// The old `s49_tui_drill_out_targets_are_pinned` test is removed below.

// ── Empty-state copy (tabs/profiles.rs) ──────────────────────────────

const EMPTY_STATE: &str = "no profiles configured.";

fn modal_src() -> &'static str {
    include_str!("../src/tui/profile_modal.rs")
}

fn tab_src() -> &'static str {
    include_str!("../src/tui/tabs/profiles.rs")
}

#[test]
fn s49_tui_modal_titles_are_pinned() {
    let src = modal_src();
    for title in [
        MODAL_TITLE_ADD,
        MODAL_TITLE_EDIT,
        MODAL_TITLE_REMOVE,
        MODAL_TITLE_DONE,
        MODAL_TITLE_FAILED,
    ] {
        let needle = format!("\"{title}\"");
        assert!(
            src.contains(&needle),
            "profile_modal.rs must spell the modal title exactly as `{title}` \
             (looked for literal `{needle}`)"
        );
    }
}

#[test]
fn s49_tui_inherit_option_is_pinned() {
    let src = modal_src();
    let needle = format!("\"{INHERIT_OPTION}\"");
    assert!(
        src.contains(&needle),
        "profile_modal.rs must spell the clear-to-inherit dropdown option \
         exactly as `{INHERIT_OPTION}` — it is load-bearing for the \
         block_response / ecs.mode clear semantics"
    );
}

#[test]
fn s49_tui_ecs_clear_hint_is_pinned() {
    let src = modal_src();
    assert!(
        src.contains(ECS_CLEAR_HINT),
        "profile_modal.rs must mention `{ECS_CLEAR_HINT}` — the per-field \
         ecs clear refusal points operators at the whole-subtree toggle \
         (D1 limitation, TODO s-4.26-p2-disc-1)"
    );
}

// s49_tui_drill_out_targets_are_pinned RETIRED by tui-wave1/profiles-summary
// (the drill-out pointer block it guarded was replaced by the "What it blocks"
// summary; see tests/frozen_strings_tui_t1.rs).

#[test]
fn s49_tui_empty_state_is_pinned() {
    let src = tab_src();
    assert!(
        src.contains(EMPTY_STATE),
        "tabs/profiles.rs empty state must read exactly `{EMPTY_STATE}`"
    );
}
