//! rev-2606 s-sched-disc-1 — the daemon's 60 s schedule tick was gated on
//! `has_schedules`, a bool frozen at boot and never refreshed by reload. A box
//! that booted with zero schedules had the tick disarmed for the life of the
//! process, so the FIRST `warden device quiet <dev> --for 1m` (which writes a
//! one-shot `[[schedules]]` block and reloads) took effect but then OVERSTAYED
//! its `expires_at` forever — nothing re-evaluated or pruned it.
//!
//! The fix recomputes the gate from each accepted reload's config
//! (`handle_reload` now returns `Some(!config.schedules.is_empty())`). The
//! signal loop itself is private and 16-arg, so this test pins the two halves
//! the gate now tracks, against the REAL on-disk load path:
//!   1. an empty-schedule config loads with `schedules.is_empty()` — boot ⇒
//!      gate false (zero per-60 s I/O on a schedule-free box, e.g. the Pi);
//!   2. after a quiet-shaped one-shot row is appended, `load_config` reports
//!      `!schedules.is_empty()` — the exact value `handle_reload` returns, so
//!      the reload arms the tick (the bug: it never did);
//!   3. `prune_expired_schedules` — the work the re-armed tick performs every
//!      60 s — drops the lapsed row and keeps a still-future one.
//!
//! The end-to-end "device un-quiets within ~60 s of expiry without a manual
//! reload" is CT-smoke-proven on the isolated `:15353` daemon (see DONE.md).

use purge_warden::cli::commands::schedules::prune_expired_schedules;
use purge_warden::config::loader::{load_config, LoadedConfig};

fn now() -> time::OffsetDateTime {
    time::OffsetDateTime::UNIX_EPOCH + time::Duration::days(20_600)
}

/// Minimal v2 config with the entities a `warden device quiet` schedule
/// references (a `blocked` profile + a target device), mirroring what
/// `run_quiet` materialises before appending the one-shot row.
const BASE: &str = r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"
tags = ["uncategorized"]

[profiles.blocked]
display_name = "Blocked"
block_all = true

[[devices]]
id = "x"
display_name = "Test device"
ip = "10.0.0.9"

[upstream]
servers = ["192.0.2.1:53"]
"#;

fn write_config(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
    let path = dir.join("config.toml");
    std::fs::write(&path, body).expect("write config");
    path
}

fn load_ok(path: &std::path::Path) -> LoadedConfig {
    match load_config(path, now()) {
        Ok(loaded) => loaded,
        Err(errs) => panic!("expected clean load, got: {errs:?}"),
    }
}

#[test]
fn empty_schedule_config_reports_no_schedules() {
    let tmp = tempfile::tempdir().unwrap();
    let path = write_config(tmp.path(), BASE);
    // Boot computes `has_schedules = !schedules.is_empty()` from this — false,
    // so the tick arm stays disarmed and the box does zero per-60 s config I/O.
    assert!(load_ok(&path).config.schedules.is_empty());
}

#[test]
fn appended_quiet_schedule_flips_presence_and_prunes_when_expired() {
    let tmp = tempfile::tempdir().unwrap();
    // A quiet whose window has already lapsed, plus a still-future one, so the
    // prune must be selective (drop the expired, keep the live).
    let past = (now() - time::Duration::hours(1))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let future = (now() + time::Duration::hours(1))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let body = format!(
        r#"{BASE}
[[schedules]]
id = "quiet-x-expired"
display_name = "Quiet device x"
target_type = "device"
target_id = "x"
profile = "blocked"
days = ["all"]
hours = "00:00-00:00"
expires_at = "{past}"

[[schedules]]
id = "quiet-x-future"
display_name = "Quiet device x"
target_type = "device"
target_id = "x"
profile = "blocked"
days = ["all"]
hours = "00:00-00:00"
expires_at = "{future}"
"#
    );
    let path = write_config(tmp.path(), &body);

    // Reload sees the appended schedules ⇒ `handle_reload` returns Some(true)
    // ⇒ the signal loop arms the tick (pre-fix: the boot-frozen flag stayed
    // false and the tick never fired).
    let loaded = load_ok(&path);
    assert!(
        !loaded.config.schedules.is_empty(),
        "a quiet-written schedule must make the reload report has_schedules=true"
    );
    assert_eq!(loaded.config.schedules.len(), 2);

    // The work the re-armed 60 s tick performs: drop the lapsed row, keep the
    // future one.
    let pruned = prune_expired_schedules(&path, &loaded, now()).expect("prune");
    assert_eq!(pruned, vec!["quiet-x-expired".to_string()]);

    // The pruned config still loads and holds only the future schedule.
    let after = load_ok(&path);
    let ids: Vec<&str> = after
        .config
        .schedules
        .iter()
        .map(|s| s.id.as_str())
        .collect();
    assert_eq!(ids, vec!["quiet-x-future"]);
}
