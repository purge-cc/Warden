//! rev-2606 `rev2606-config-io-hygiene`: byte-pins for the operator-facing
//! refusal / hint strings this fix sprint introduces. Same intent as
//! `tests/frozen_strings_entity_contracts.rs` — a silent rename the inline
//! tests miss surfaces here at code review (RR3 frozen-strings).
//!
//! Each case drives a crafted single-file config through the real loader
//! (`load_config` runs the full validate pass) and asserts the exact
//! message an operator would see from `warden config lint` / boot / reload.

use std::path::Path;

use purge_warden::config::error::ConfigError;
use purge_warden::config::loader::load_config;
use time::macros::datetime;

const BASE: &str = "schema_version = 3\n\n[server]\ndefault_profile = \"default\"\n\n[profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n";

fn errors_for(extra: &str) -> Vec<ConfigError> {
    let tmp = tempfile::tempdir().unwrap();
    let master = tmp.path().join("config.toml");
    std::fs::write(&master, format!("{BASE}\n{extra}")).unwrap();
    load_config(Path::new(&master), datetime!(2026-04-22 12:00:00 UTC))
        .expect_err("config must be rejected")
}

fn has_reason(errs: &[ConfigError], exact: &str) -> bool {
    errs.iter().any(|e| e.context().reason == exact)
}

fn any_reason_contains(errs: &[ConfigError], needle: &str) -> bool {
    errs.iter().any(|e| e.context().reason.contains(needle))
}

#[test]
fn loader_02_same_file_deprecated_conflict_message() {
    let errs = errors_for("[ip_denylists]\nenabled = true\n\n[ip_blocklists]\nenabled = true\n");
    assert!(
        has_reason(
            &errs,
            "file declares both `ip_denylists` (deprecated) and `ip_blocklists`; \
             the `ip_denylists` value would be silently dropped"
        ),
        "got {errs:?}"
    );
}

/// **Re-pinned in `plp-s5f`.** The old text ended "or move each category's
/// members onto the relevant entity's `tags`" — a manual route to a field
/// `plp-s5a` deleted and the loader now strips, so an operator who followed
/// it got their intent silently discarded. Reached by a real config
/// (`errors_for` runs the loader), so this was live advice, not stale prose.
#[test]
fn loader_01_categories_migration_hint() {
    let errs = errors_for("[[categories]]\nid = \"ads\"\ndisplay_name = \"Ads\"\n");
    assert!(
        errs.iter().any(|e| e.context().suggestion.as_deref()
            == Some(
                "`categories` was removed in schema_version 2, and the per-entity `tags` that \
                 replaced it have themselves been retired — the loader strips them. Run \
                 `warden migrate v1-to-v3` to convert a v1 config: it writes \
                 `profiles.<id>.lists`, which is what decides filtering now"
            )),
        "got {errs:?}"
    );
}

/// The hint must not grow a manual route back. Separate from the byte-pin
/// above because that one dies to any reword and gets re-frozen against
/// whatever the code then says; this one survives rewording and fails the
/// specific regression that already happened once — telling an operator to
/// write into a field the loader discards.
#[test]
fn loader_01_categories_hint_offers_no_route_through_tags() {
    let errs = errors_for("[[categories]]\nid = \"ads\"\ndisplay_name = \"Ads\"\n");
    let hint = errs
        .iter()
        .find_map(|e| e.context().suggestion.clone())
        .expect("the categories key must carry a directed suggestion");
    assert!(
        !hint.contains("move each"),
        "the manual tags route discards the operator's intent at load: {hint}"
    );
    assert!(
        hint.contains("profiles.<id>.lists"),
        "the hint must name what actually decides filtering: {hint}"
    );
}

#[test]
fn blocklist_01_userinfo_refusal_message() {
    let errs = errors_for(
        "[[blocklists]]\nid = \"x\"\ndisplay_name = \"X\"\nurl = \"https://u:p@h.example/a.txt\"\n",
    );
    assert!(
        has_reason(
            &errs,
            "blocklists[0].url must not embed credentials; use auth_token_ref for an authenticated list"
        ),
        "got {errs:?}"
    );
}

#[test]
fn retired_01_future_date_message() {
    // The retired_at value is a dynamic timestamp, so pin the stable head +
    // tail rather than the full Display.
    let errs = errors_for(
        "[[retired]]\nid = \"leg\"\ntype = \"device\"\nretired_at = \"2099-01-01T00:00:00Z\"\n",
    );
    assert!(
        any_reason_contains(&errs, "[[retired]] id \"leg\" has retired_at ")
            && any_reason_contains(&errs, " in the future"),
        "got {errs:?}"
    );
}
