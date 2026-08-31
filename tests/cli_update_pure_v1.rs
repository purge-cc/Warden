//! Post-§4.24 follow-up — `cli-update-pure-v1-loader-migration`.
//!
//! Pins `warden update`'s foreground path against the same bug-class as
//! the 2026-05-06 silent-no-blocking incident: pre-fix, the path used
//! the legacy `Settings::from_file` loader and silently exited with
//! `"no list sources configured"` whenever `[lists].sources = []` even
//! if `[[blocklists]]` was populated. Post-fix it threads the v1
//! loader + `merge_sources_with_blocklists` + `SourceBitMap::build`
//! and reaches the actual download path.
//!
//! **Why imported.local for the fixture URL.** `validate_list_url` in
//! `src/lists/http_client.rs` rejects non-HTTPS schemes and loopback IPs
//! — a mock HTTP server on `127.0.0.1` would be refused before any
//! request lands. The S50 T5.5 loader-bridge intercepts
//! `https://imported.local/<id>.<ext>` URLs before the URL guard and
//! reads from `<config-parent>/lists/<id>.<ext>` on disk for
//! `trust = "local"` blocklists. That gives us a hermetic end-to-end
//! path with zero network and zero new dev-deps.
//!
//! The test also pins the bridge wiring at `update.rs` (added in this
//! sprint for parity with the daemon path at `start.rs:374`). Without
//! that wiring, the bridge interception in `lists::manager` would not
//! fire on the foreground tool and trust=local blocklists would fail.

use std::path::{Path, PathBuf};

use purge_warden::cli::commands::update::run_update;

const FAKE_BLOCKLIST_BODY: &str = "doubleclick.net\ngoogle-analytics.com\n";

/// Write a master `config.toml` + a single `[[blocklists]]` row pointing
/// at `https://imported.local/<list_id>.txt` with `trust = "local"`,
/// plus the matching on-disk body file at `<dir>/lists/<list_id>.txt`.
/// `lists.sources = []` recreates the post-S53 / post-2026-05-06 hotfix
/// steady state — the exact bug-trigger condition.
fn write_pure_v1_fixture(dir: &Path, list_id: &str) -> PathBuf {
    let master = dir.join("config.toml");
    std::fs::write(
        &master,
        format!(
            r#"schema_version = 3

[server]
listen = "0.0.0.0:53"
default_profile = "default"
allow_from = ["127.0.0.0/8"]

[lists]
sources = []
cache_dir = "lists"

[[blocklists]]
id = "{list_id}"
display_name = "Test list"
url = "https://imported.local/{list_id}.txt"
format = "domains"
trust = "local"
update_interval_hours = 24
max_entries = 1_000_000
enabled = true

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#
        ),
    )
    .unwrap();

    let lists_src = dir.join("lists");
    std::fs::create_dir_all(&lists_src).unwrap();
    std::fs::write(
        lists_src.join(format!("{list_id}.txt")),
        FAKE_BLOCKLIST_BODY,
    )
    .unwrap();

    master
}

/// Empty-config fixture (no sources, no blocklists). Pre- and post-fix
/// both produce the early-exit message.
fn write_empty_fixture(dir: &Path) -> PathBuf {
    let master = dir.join("config.toml");
    std::fs::write(
        &master,
        r#"schema_version = 3

[server]
listen = "0.0.0.0:53"
default_profile = "default"
allow_from = ["127.0.0.0/8"]

[lists]
sources = []
cache_dir = "lists"

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#,
    )
    .unwrap();
    master
}

/// Disabled-blocklist fixture: a single blocklist with `enabled = false`.
/// `merge_sources_with_blocklists` skips disabled rows, so
/// `merged_sources.is_empty() == true` and the early-exit fires.
fn write_disabled_blocklist_fixture(dir: &Path) -> PathBuf {
    let master = dir.join("config.toml");
    std::fs::write(
        &master,
        r#"schema_version = 3

[server]
listen = "0.0.0.0:53"
default_profile = "default"
allow_from = ["127.0.0.0/8"]

[lists]
sources = []
cache_dir = "lists"

[[blocklists]]
id = "disabled-list"
display_name = "Disabled"
url = "https://imported.local/disabled-list.txt"
format = "domains"
trust = "local"
update_interval_hours = 24
max_entries = 1_000_000
enabled = false

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#,
    )
    .unwrap();
    master
}

fn count_cache_files(cache_dir: &Path) -> usize {
    let entries = match std::fs::read_dir(cache_dir) {
        Ok(rd) => rd,
        Err(_) => return 0,
    };
    entries
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .and_then(|s| s.to_str())
                .map(|ext| ext == "cache")
                .unwrap_or(false)
        })
        .count()
}

/// Resolve the lists cache directory for a given fixture config.
///
/// Mirrors `lists_cache_dir(config_path, &cfg)` from `start.rs` for
/// the dev-path case (non-`/etc` config). `state_dir_for` is identity
/// for non-`/etc` parents, so `<config-parent>/<cache_dir>` is the
/// final resolution. Hardcoded here because `lists_cache_dir` is
/// `pub(crate)` (exposed only to in-crate callers); duplicating the
/// 2-line resolution avoids polluting the public API surface.
fn cache_dir_for(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .expect("test config_path always has a tempdir parent")
        .join("lists")
}

#[tokio::test(flavor = "current_thread")]
async fn pure_v1_config_actually_downloads_post_fix() {
    // The bug-trigger scenario from 2026-05-06: empty `[lists].sources`,
    // populated `[[blocklists]]`. Pre-fix `Settings::from_file` would
    // hit the early-exit at line 34 and silently no-op. Post-fix the v1
    // loader sees the `[[blocklists]]` row, the imported.local bridge
    // resolves it, the manager writes a `.cache` file in the lists dir.
    let tmp = tempfile::tempdir().unwrap();
    let master = write_pure_v1_fixture(tmp.path(), "test-pure-v1");
    let nonexistent_pid = tmp.path().join("nonexistent.pid");
    let nonexistent_sock = tmp.path().join("nonexistent.sock");

    run_update(&master, &nonexistent_pid, &nonexistent_sock)
        .await
        .map(|code| assert_eq!(code, 0, "pure-v1 refresh must exit SUCCESS"))
        .expect("run_update must succeed end-to-end on pure-v1 config");

    let cache_dir = cache_dir_for(&master);
    assert!(
        count_cache_files(&cache_dir) >= 1,
        "expected at least one *.cache file in {} after pure-v1 update; \
         pre-fix this asserted because the loader silently exited early",
        cache_dir.display(),
    );
}

#[tokio::test(flavor = "current_thread")]
async fn empty_config_still_short_circuits() {
    // Both `[lists].sources` and `[[blocklists]]` empty: the early-exit
    // is still the right behaviour. The new `merged_sources.is_empty()`
    // guard at line 38 must catch this exactly the same way the old
    // `settings.lists.sources.is_empty()` did.
    let tmp = tempfile::tempdir().unwrap();
    let master = write_empty_fixture(tmp.path());
    let nonexistent_pid = tmp.path().join("nonexistent.pid");
    let nonexistent_sock = tmp.path().join("nonexistent.sock");

    run_update(&master, &nonexistent_pid, &nonexistent_sock)
        .await
        .map(|code| assert_eq!(code, 0, "no-sources refresh is success, not failure"))
        .expect("run_update must succeed even with no sources");

    let cache_dir = cache_dir_for(&master);
    assert_eq!(
        count_cache_files(&cache_dir),
        0,
        "empty config must not produce cache files in {}",
        cache_dir.display(),
    );
}

#[tokio::test(flavor = "current_thread")]
async fn disabled_blocklist_short_circuits() {
    // `merge_sources_with_blocklists` skips disabled rows
    // (`manager.rs:1198` `if b.enabled && !already.contains(...)`),
    // so `merged_sources.is_empty()` and the early-exit fires.
    // No cache file should be written.
    let tmp = tempfile::tempdir().unwrap();
    let master = write_disabled_blocklist_fixture(tmp.path());
    let nonexistent_pid = tmp.path().join("nonexistent.pid");
    let nonexistent_sock = tmp.path().join("nonexistent.sock");

    run_update(&master, &nonexistent_pid, &nonexistent_sock)
        .await
        .map(|code| assert_eq!(code, 0, "disabled-only refresh is success"))
        .expect("run_update must succeed when only disabled blocklists exist");

    let cache_dir = cache_dir_for(&master);
    assert_eq!(
        count_cache_files(&cache_dir),
        0,
        "disabled blocklist must not contribute fetched cache entries",
    );
}

#[tokio::test(flavor = "current_thread")]
async fn nonexistent_pid_file_falls_through_to_foreground() {
    // The pid-file branch at update.rs:19-27 errors when the file is
    // missing (`pid::read_pid_file` returns Err). The function must
    // then enter the foreground branch and respect the empty-config
    // early-exit rather than panicking or returning Err.
    let tmp = tempfile::tempdir().unwrap();
    let master = write_empty_fixture(tmp.path());
    let nonexistent_pid = tmp.path().join("absolutely-not-a-pid-file");
    let nonexistent_sock = tmp.path().join("nonexistent.sock");

    run_update(&master, &nonexistent_pid, &nonexistent_sock)
        .await
        .map(|code| {
            assert_eq!(
                code, 0,
                "missing pid file falls through to a successful foreground run"
            )
        })
        .expect("missing pid file must not propagate as an error");
}
