//! Sprint 43 (Lists Management) — SN3 frozen-strings test (R3).
//!
//! Pins every operator-facing string declared in
//! `_docs/features/lists_management.md` §2 SN3 byte-for-byte. The test
//! BLOCKS the `v0.4.6-lists-management` tag: if any const drifts from
//! the table, the tag step refuses to cut.
//!
//! Layout: one assertion per const + one substitution test per format
//! helper. The consts live in their respective home modules (see §2
//! SN3 "Status" column). Phases T2/T3/T4 shipped four of them ahead
//! of T6; phase T5 shipped the remaining nine. T6 only locks them.
//!
//! When a string MUST change for legitimate reasons (ux re-wording,
//! typo fix), update the literal here AND the §2 SN3 table in the
//! design doc in the same commit, then add a §14.N delta-vs-intent
//! note documenting why the byte-for-byte pin slipped.

use purge_warden::cli::commands::rules::{
    format_rule_applied_default, format_rule_applied_device, format_rule_applied_profile,
    format_rule_refused_override, format_rule_undo_ok, Action, RULES_BATCH_DEFAULT_CONFIRM,
    RULES_BATCH_DEFAULT_CONFIRM_CLI, RULES_BATCH_TYPE_CONFIRM, RULE_APPLIED_DEFAULT,
    RULE_APPLIED_DEVICE, RULE_APPLIED_PROFILE, RULE_REFUSED_OVERRIDE, RULE_UNDO_EMPTY,
    RULE_UNDO_OK,
};
use purge_warden::config::schema::admin_rule::{format_rule_invalid_domain, RULE_INVALID_DOMAIN};
use purge_warden::config::schema::validator::{format_list_prune_warn, LIST_PRUNE_WARN};
use purge_warden::ipc::{format_rule_reload_batched, RULE_RELOAD_BATCHED};
use purge_warden::tui::LISTS_TAB_EMPTY;

// ── T2 — visibility surfaces ─────────────────────────────────────────

#[test]
fn lists_tab_empty_byte_for_byte() {
    assert_eq!(
        LISTS_TAB_EMPTY,
        "No blocklists configured. Run `warden blocklist add <id> --url <url>` to add one."
    );
}

// ── T3 — list↔profile assignment ergonomics ──────────────────────────
//
// `rule_dangling_ref_byte_for_byte` and
// `rule_dangling_ref_format_substitutes_id_n_and_list` were deleted with
// the const they pinned. Both are recorded here rather than removed
// silently, because a shrinking frozen suite is exactly the shape of an
// assertion someone dropped to make a build pass.
//
// The string recommended `--cascade`, a flag cli-h5 removed, and worded a
// refusal with no production emitter: the profile↔list join became tags,
// so no profile enumerates a blocklist id and the cross-reference the
// refusal reported cannot occur. Its second assertion above literally
// required the text to keep naming the deleted flag
// (`assert!(s.contains("--cascade"))`) — a pin holding a string to a lie.
//
// Retired deliberately, with the operator's decision, in the same commit
// as the const. See `src/cli/commands/blocklists.rs` for the full note.

// ── T4 — per-device overlay foundation ───────────────────────────────

#[test]
fn rule_reload_batched_byte_for_byte() {
    assert_eq!(
        RULE_RELOAD_BATCHED,
        "{n} rule changes batched in this reload window."
    );
}

#[test]
fn rule_reload_batched_format_substitutes_n() {
    assert_eq!(
        format_rule_reload_batched(7),
        "7 rule changes batched in this reload window."
    );
}

#[test]
fn list_prune_warn_byte_for_byte() {
    assert_eq!(
        LIST_PRUNE_WARN,
        "Device '{id}' has {n} rules (soft cap: 64). Run `warden device rules {id} prune` to clean up dead refs."
    );
}

#[test]
fn list_prune_warn_format_substitutes_id_and_n() {
    let s = format_list_prune_warn("pc-gioele", 70);
    assert!(s.contains("'pc-gioele'"), "{s}");
    assert!(s.contains("70 rules"), "{s}");
    assert!(s.contains("soft cap: 64"), "{s}");
    assert!(s.contains("warden device rules pc-gioele prune"), "{s}");
}

// ── T5 — scope-menu, CLI rule verbs, undo, validation ────────────────

#[test]
fn rule_refused_override_byte_for_byte() {
    assert_eq!(
        RULE_REFUSED_OVERRIDE,
        "Cannot allow '{domain}' for device '{device}': profile '{profile}' explicitly denies it. To override, add `override_profile_deny = true` to the device entry and retry."
    );
}

#[test]
fn rule_refused_override_format_substitutes_all_three() {
    let s = format_rule_refused_override("youtube.com", "pc-gioele", "kids");
    assert!(s.contains("'youtube.com'"), "{s}");
    assert!(s.contains("'pc-gioele'"), "{s}");
    assert!(s.contains("'kids'"), "{s}");
    assert!(s.contains("override_profile_deny = true"), "{s}");
}

#[test]
fn rule_applied_device_byte_for_byte() {
    assert_eq!(
        RULE_APPLIED_DEVICE,
        "{verb} {domain} on {device}. Other devices unaffected. To undo: warden rule undo"
    );
}

#[test]
fn rule_applied_device_format_picks_verb_per_action() {
    let allow = format_rule_applied_device(Action::Allow, "example.com", "pc");
    assert!(allow.starts_with("Allowed example.com on pc."), "{allow}");
    assert!(allow.contains("Other devices unaffected"), "{allow}");
    assert!(allow.contains("To undo: warden rule undo"), "{allow}");

    let deny = format_rule_applied_device(Action::Deny, "tracker.example", "iphone");
    assert!(
        deny.starts_with("Blocked tracker.example on iphone."),
        "{deny}"
    );
}

#[test]
fn rule_applied_profile_byte_for_byte() {
    assert_eq!(
        RULE_APPLIED_PROFILE,
        "{verb} {domain} on profile '{profile}'. Affects {n} devices currently. To undo: warden rule undo"
    );
}

#[test]
fn rule_applied_profile_format_substitutes_action_domain_profile_n() {
    let s = format_rule_applied_profile(Action::Allow, "smoke.example", "default", 6);
    // CT smoke on 2026-04-25 emitted exactly this string for `warden
    // profile allow default smoke-test.example` — pin that shape.
    assert_eq!(
        s,
        "Allowed smoke.example on profile 'default'. Affects 6 devices currently. To undo: warden rule undo"
    );
}

#[test]
fn rule_applied_default_byte_for_byte() {
    assert_eq!(
        RULE_APPLIED_DEFAULT,
        "{verb} {domain} for unknown devices. Existing devices on a profile are unaffected. To undo: warden rule undo"
    );
}

#[test]
fn rule_applied_default_format_substitutes_action_and_domain() {
    let s = format_rule_applied_default(Action::Allow, "doubleclick.net");
    // CT smoke on 2026-04-25 emitted exactly this — pin the shape so
    // the cache-invalidation assertion the smoke ran against keeps
    // landing on the same operator string.
    assert_eq!(
        s,
        "Allowed doubleclick.net for unknown devices. Existing devices on a profile are unaffected. To undo: warden rule undo"
    );

    let deny = format_rule_applied_default(Action::Deny, "spy.example");
    assert!(
        deny.starts_with("Blocked spy.example for unknown devices."),
        "{deny}"
    );
}

#[test]
fn rule_undo_ok_byte_for_byte() {
    assert_eq!(RULE_UNDO_OK, "Removed last rule '{id}' ({rule_string}).");
}

#[test]
fn rule_undo_ok_format_substitutes_id_and_rule_string() {
    let s = format_rule_undo_ok("auto-deny-deadbeef", "||tracker.example^");
    assert_eq!(
        s,
        "Removed last rule 'auto-deny-deadbeef' (||tracker.example^)."
    );
}

#[test]
fn rule_undo_empty_byte_for_byte() {
    assert_eq!(
        RULE_UNDO_EMPTY,
        "No rule to undo: admin_rules list is empty."
    );
}

#[test]
fn rules_batch_type_confirm_byte_for_byte() {
    // Note: trailing space — readline-style prompt on the same line.
    assert_eq!(RULES_BATCH_TYPE_CONFIRM, "Type the scope id to confirm: ");
}

#[test]
fn rules_batch_default_confirm_byte_for_byte() {
    assert_eq!(
        RULES_BATCH_DEFAULT_CONFIRM,
        "This affects every unknown device on your network. Type DEFAULT to confirm: "
    );
}

#[test]
fn rules_batch_default_confirm_cli_alias_matches() {
    // The `_CLI` alias is a separate symbol so the CLI dispatcher and
    // the TUI submit path can diverge later if the wording needs to.
    // For T5/T6 they MUST be identical so the operator sees the same
    // text in both surfaces.
    assert_eq!(RULES_BATCH_DEFAULT_CONFIRM_CLI, RULES_BATCH_DEFAULT_CONFIRM);
}

#[test]
fn rule_invalid_domain_byte_for_byte() {
    assert_eq!(
        RULE_INVALID_DOMAIN,
        "'{input}' is not a valid domain (got: {reason}). Examples: example.com, mail.google.com"
    );
}

#[test]
fn rule_invalid_domain_format_substitutes_input_and_reason() {
    let s = format_rule_invalid_domain("xn--ple", "punycode round-trip mismatch");
    assert!(s.starts_with("'xn--ple' is not a valid domain"), "{s}");
    assert!(s.contains("punycode round-trip mismatch"), "{s}");
    assert!(s.contains("Examples: example.com, mail.google.com"), "{s}");
}
