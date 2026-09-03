use super::*;
use crate::config::schema::{ConfigV1, Profile};
use crate::config::settings::DnssecMode;

// ── shared list-manager wiring ───────────────────────────────────

fn wiring_blocklist(id: &str, url: &str, enabled: bool) -> crate::config::schema::Blocklist {
    crate::config::schema::Blocklist {
        id: crate::config::schema::Id::new(id).unwrap(),
        display_name: id.to_string(),
        url: url.to_string(),
        format: crate::config::schema::BlocklistFormat::Hosts,
        update_interval_hours: 12,
        max_entries: 5_000_000,
        enabled,
        auth_token_ref: None,
        base: crate::config::schema::BlocklistBase::Deny,
        trust: crate::config::schema::BlocklistTrust::RemoteUnsigned,
        accept_unsigned_allow: false,
        max_consecutive_failures: 7,
    }
}

/// A source string reaches the manager in three shapes depending on
/// how the operator pinned the list, and all three have to resolve
/// back to the same row — the bearer-token fallback, the declared
/// parse format and the retry state machine all key on this map.
#[test]
fn build_source_maps_keys_every_shape_a_source_arrives_in() {
    let lists = vec![wiring_blocklist(
        "privacy-tracking",
        "https://lists.example.test/tracking.txt",
        true,
    )];
    let (by_source, formats) = build_source_maps(&lists);

    let id = crate::config::schema::Id::new("privacy-tracking").unwrap();
    for key in [
        "https://lists.example.test/tracking.txt",
        "privacy/tracking",
        "privacy-tracking",
    ] {
        assert_eq!(
            by_source.get(key),
            Some(&(id.clone(), 7u32)),
            "{key} must resolve to the canonical id and its own threshold"
        );
        assert_eq!(
            formats.get(key),
            Some(&crate::lists::detector::ListFormat::Hosts),
            "{key} must carry the declared parse format"
        );
    }
}

/// An omitted format must stay absent rather than resolve to a
/// guess: absence is what leaves the parse dispatch on content
/// auto-detection. A disabled row is not refreshed, so it has no
/// business in either map.
#[test]
fn build_source_maps_omits_undeclared_formats_and_disabled_rows() {
    let mut plain = wiring_blocklist("ads-basic", "https://lists.example.test/ads.txt", true);
    plain.format = crate::config::schema::BlocklistFormat::Domains;
    let off = wiring_blocklist("ads-off", "https://lists.example.test/off.txt", false);
    let (by_source, formats) = build_source_maps(&[plain, off]);

    assert!(by_source.contains_key("https://lists.example.test/ads.txt"));
    assert!(
        !formats.contains_key("https://lists.example.test/ads.txt"),
        "a `domains` row must leave the format map untouched"
    );
    assert!(
        !by_source.contains_key("https://lists.example.test/off.txt"),
        "a disabled row is never refreshed and must not be mapped"
    );
}

fn wiring_for(config: &ConfigV1, config_path: &Path, wb: ListStateWriteback) -> ManagerWiring {
    let sources: Vec<String> = config.blocklists.iter().map(|b| b.url.clone()).collect();
    let bits = crate::lists::source_key::SourceBitMap::build(&sources, &config.blocklists)
        .expect("bit assignment");
    let masks = bits.project_policy(&config.blocklists, &config.profiles);
    ManagerWiring::from_config(
        config,
        config_path,
        crate::lists::source_key::SourceTrustMap::build(&config.blocklists),
        config_path.parent().unwrap().to_path_buf(),
        masks,
        wb,
    )
}

/// Every field must be derived, not defaulted. The destructuring is
/// the assertion: a field added to `ManagerWiring` and left out of
/// `from_config` stops this compiling, which is the only thing that
/// caught the last three setters after they were added at one site
/// and forgotten at the other two.
#[test]
fn manager_wiring_derives_every_field_from_config() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    let mut config = ConfigV1::test_scaffold();
    config.blocklists = vec![wiring_blocklist(
        "privacy-tracking",
        "https://lists.example.test/tracking.txt",
        true,
    )];
    config.lists.max_total_domains = 4_242_424;
    config.lists.shrink_guard_enabled = true;
    config.lists.shrink_guard_max_drop_pct = 33;

    let ManagerWiring {
        source_trust,
        bridge_config_dir,
        policy_masks,
        shrink_guard_enabled,
        shrink_guard_max_drop_pct,
        max_total_domains,
        source_to_blocklist,
        source_to_format,
        list_state,
        list_state_path: state_path,
    } = wiring_for(&config, &config_path, ListStateWriteback::Persist);

    assert!(shrink_guard_enabled);
    assert_eq!(shrink_guard_max_drop_pct, 33);
    assert_eq!(max_total_domains, 4_242_424);
    assert!(!source_to_blocklist.is_empty(), "token fallback needs this");
    assert!(!source_to_format.is_empty(), "parse dispatch needs this");
    assert_eq!(state_path, Some(list_state_path(&config_path)));
    assert_eq!(bridge_config_dir.as_path(), dir.path());
    // Bound so the pattern stays exhaustive; these carry no cheap
    // assertion of their own.
    let _ = (source_trust, policy_masks, list_state);
}

/// The foreground refresh reads list state but must not write it
/// back — a one-shot command clobbering the counters the running
/// daemon owns is worse than a foreground run that records nothing.
#[test]
fn foreground_writeback_is_read_only_while_the_daemon_persists() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    let config = ConfigV1::test_scaffold();

    let daemon = wiring_for(&config, &config_path, ListStateWriteback::Persist);
    let foreground = wiring_for(&config, &config_path, ListStateWriteback::ReadOnly);

    assert!(daemon.list_state_path.is_some());
    assert!(foreground.list_state_path.is_none());
}

/// The shared wiring only defends anything if it is the only path.
///
/// These setters were hand-maintained at three sites; the manager's
/// constructor defaults each of them, so a site that omits one fails
/// neither the compiler nor the suite — it just degrades, silently,
/// from the first reload on. Pinning that each appears exactly once
/// in this file, inside `ManagerWiring::apply`, and never in the
/// foreground refresh, is what makes the next omission impossible
/// rather than merely discouraged.
#[test]
fn shared_manager_setters_have_exactly_one_call_site() {
    let start_src = include_str!("../start.rs");
    let update_src = include_str!("../update.rs");
    for setter in [
        "local_bridge",
        "list_policy",
        "shrink_guard",
        "max_total_domains",
        "source_blocklist_map",
        "source_format_map",
        "list_state",
    ] {
        // Assembled at runtime so the needle cannot match itself in
        // the source text it is scanning.
        let needle = format!("mgr.set_{setter}(");
        assert_eq!(
            start_src.matches(&needle).count(),
            1,
            "{needle} must have exactly one call site, inside ManagerWiring::apply"
        );
        assert_eq!(
            update_src.matches(&needle).count(),
            0,
            "the foreground refresh must reach {needle} through ManagerWiring::apply"
        );
    }
}

// ── N1 — the drop is loud at boot too ────────────────────────────
//
// There is no second emitter here, and that is a measured decision
// rather than an omission. `main.rs` loads the config BEFORE
// `init_tracing` (it needs `server.log_level` out of it), so the
// validator's WARN from that load really is dropped — but
// `run_start` then calls `collect_loaded_files` for the audit Boot
// record, which runs a second full `load_config` with the subscriber
// already installed. That is what puts every validator audit WARN on
// the boot log.
//
// A dedicated re-emitter was written here first and deleted after
// running the daemon: it printed the whole paragraph TWICE at every
// start. Verified by booting the debug binary on 127.0.0.1:15353
// with `enabled = true, extra_domains = []` — the log carries the
// anti-bypass line and `PROFILE_CONTRIBUTES_NO_TAGS`, neither of
// which has any emitter outside the validator.
//
// The residual fragility is real but systemic, not specific to this
// warning: boot visibility for ALL of them rides on that audit-path
// load. Guarding one warning with a bespoke emitter while twelve
// others stay exposed buys inconsistency, not safety. Flagged at the
// call site; the general fix belongs in its own change.

fn cfg_with_anti_bypass(enabled: bool, domains: &[&str]) -> ConfigV1 {
    let mut c = ConfigV1::test_scaffold();
    c.anti_bypass.enabled = enabled;
    c.anti_bypass.extra_domains = domains.iter().map(|d| d.to_string()).collect();
    c
}

/// Safe mode inherits `AntiBypassConfig::default()` — on, empty — so
/// it trips the same predicate as any other install. Honest rather
/// than noisy: safe mode REFUSEs every query, so nothing bypasses
/// anything, but the config it reports still says `enabled = true`.
/// Pinned so the next person to touch safe mode sees the coupling.
#[test]
fn n1_safe_mode_inherits_the_toothless_shape() {
    use crate::config::schema::validator::anti_bypass_has_no_domain_source;
    assert!(
        anti_bypass_has_no_domain_source(&safe_mode_config()),
        "safe mode carries AntiBypassConfig::default() — enabled, empty"
    );
    // Control: the predicate is not vacuously true.
    assert!(!anti_bypass_has_no_domain_source(&cfg_with_anti_bypass(
        true,
        &["doh.example.net"]
    )));
    assert!(!anti_bypass_has_no_domain_source(&cfg_with_anti_bypass(
        false,
        &[]
    )));
}

/// neutrality-07 — safe mode must not name a third-party resolver.
///
/// Safe mode used to hardcode `1.1.1.1:53`, so a recovery session sent
/// its DNS to one named company chosen by warden. It is dead
/// configuration to boot: safe mode sets `default_profile = None`, so
/// the resolver REFUSEs at level 5 and the upstream is never reached —
/// the entry exists only to satisfy the validator's non-empty check.
/// A reserved documentation address (RFC 5737 TEST-NET-1) satisfies it
/// while naming nobody and staying unroutable. See CLAUDE.md
/// §Neutrality.
#[test]
fn neutrality07_safe_mode_names_no_third_party_resolver() {
    let cfg = safe_mode_config();
    assert!(
        cfg.server.default_profile.is_none(),
        "safe mode REFUSEs every query; if this ever changes the upstream \
         below stops being unreachable and needs rethinking, not just renaming"
    );
    for probe in [
        "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "208.67.", "94.140.",
    ] {
        assert!(
            !cfg.upstream.servers.iter().any(|s| s.contains(probe)),
            "safe mode must not route recovery traffic to {probe}"
        );
    }
    assert!(
        !cfg.upstream.servers.is_empty(),
        "the validator refuses an empty server list, so safe mode still needs one entry"
    );
}

/// A DNSSEC mode of `off` is always accepted, on any build.
#[test]
fn check_dnssec_build_accepts_off_on_any_build() {
    let config = ConfigV1::test_scaffold(); // dnssec.mode defaults to Off
    assert!(check_dnssec_build(&config).is_ok());
}

/// Without the `dnssec` feature, a non-`off` mode is refused with an
/// actionable error (mirrors the DoQ feature bail).
#[cfg(not(feature = "dnssec"))]
#[test]
fn check_dnssec_build_errors_when_feature_off() {
    let mut config = ConfigV1::test_scaffold();
    config.dnssec.mode = DnssecMode::Validate;
    let err = check_dnssec_build(&config).unwrap_err().to_string();
    assert!(err.contains("--features dnssec"), "actionable hint: {err}");
}

/// With the `dnssec` feature, a non-`off` mode is accepted (the engine is
/// present; response-path wiring is §4.10-4).
#[cfg(feature = "dnssec")]
#[test]
fn check_dnssec_build_accepts_mode_when_feature_on() {
    let mut config = ConfigV1::test_scaffold();
    config.dnssec.mode = DnssecMode::Validate;
    assert!(check_dnssec_build(&config).is_ok());
}

/// Sprint A of `lists_categories_v2` (D1, D5) removed
/// `Profile.blocklists`. The companion helper `profiles_with_empty_lists`
/// is currently a Sprint-B-deferred stub that returns `Vec::new()`.
/// This test pins the stub behaviour: every config — empty or not —
/// yields an empty "no lists subscribed" set until Sprint B rewires
/// the function around tag intersection.
///
/// The Sprint A.5 sweep dropped the two companion tests
/// (`profiles_with_empty_lists_flags_empty_profile`,
/// `profiles_with_empty_lists_sorted_alphabetically`) because they
/// pinned the v1-shape (single explicit `Profile::default()` →
/// flagged) which the stub no longer reports. Sprint B will
/// reintroduce equivalents around the tag-intersection model.
#[test]
fn profiles_with_empty_lists_pinned_to_sprint_a_stub() {
    let mut config = ConfigV1::test_scaffold();
    config.schema_version = 3;
    config.profiles.insert("default".into(), Profile::default());
    config.profiles.insert("kids".into(), Profile::default());

    // Stub returns empty regardless of profile state.
    assert!(profiles_with_empty_lists(&config).is_empty());
}

/// Sprint 32 N1: the audit log path resolves next to the config
/// master. On the pre-S34 monolithic CT layout that places it at
/// `/var/lib/purge-warden/audit/audit.log`.
#[test]
fn audit_log_path_is_sibling_audit_dir() {
    let p = audit_log_path(Path::new("/var/lib/purge-warden/config.toml"));
    assert_eq!(p, Path::new("/var/lib/purge-warden/audit/audit.log"));
}

/// Sprint 34: when the master lives under `/etc/<pkg>/`, the audit log
/// is redirected to `/var/lib/<pkg>/audit/audit.log` because `/etc` is
/// read-only under the daemon's `ProtectSystem=strict` hardening.
#[test]
fn audit_log_path_etc_master_redirects_to_var_lib() {
    let p = audit_log_path(Path::new("/etc/purge-warden/config.toml"));
    assert_eq!(p, Path::new("/var/lib/purge-warden/audit/audit.log"));
}

#[test]
fn state_dir_for_passes_through_non_etc_paths() {
    // Dev / single-file install: state beside the config.
    assert_eq!(
        state_dir_for(Path::new("/tmp/my-dev-dir")),
        Path::new("/tmp/my-dev-dir"),
    );
    assert_eq!(
        state_dir_for(Path::new("/var/lib/purge-warden")),
        Path::new("/var/lib/purge-warden"),
    );
}

#[test]
fn state_dir_for_etc_master_redirects_to_var_lib() {
    // v1 FHS layout.
    assert_eq!(
        state_dir_for(Path::new("/etc/purge-warden")),
        Path::new("/var/lib/purge-warden"),
    );
    // Any subpath under /etc/<pkg>/ still maps to /var/lib/<pkg>/.
    assert_eq!(
        state_dir_for(Path::new("/etc/purge-warden/staging")),
        Path::new("/var/lib/purge-warden"),
    );
}

/// cli-h9 defect 4: `--daemon` computed its log directory as
/// `<config-parent>/logs` instead of routing through [`state_dir_for`]
/// like the audit log, lists cache, stats snapshot and query log all
/// do. On the production layout that is `/etc/purge-warden/logs` — a
/// path under `ProtectSystem=strict`, where `open_panic_fallback_log`'s
/// `create_dir_all` takes EACCES and the daemon never launches.
///
/// The assertion is on the `/etc` master specifically: every other
/// input produced the same answer before and after the fix, so a test
/// built on a dev path would pass on the bug.
#[test]
fn daemon_log_dir_for_etc_master_lands_under_var_lib() {
    assert_eq!(
        daemon_log_dir(Path::new("/etc/purge-warden/config.toml")),
        Path::new("/var/lib/purge-warden/logs"),
    );
}

/// …and the dev workflow keeps logs beside the config. `state_dir_for`
/// is the identity outside `/etc`, so routing through it must not move
/// a repo-local or temp-dir daemon's logs.
#[test]
fn daemon_log_dir_stays_beside_a_non_etc_config() {
    assert_eq!(
        daemon_log_dir(Path::new("/tmp/my-dev-dir/config.toml")),
        Path::new("/tmp/my-dev-dir/logs"),
    );
    assert_eq!(
        daemon_log_dir(Path::new("/var/lib/purge-warden/config.toml")),
        Path::new("/var/lib/purge-warden/logs"),
    );
}

// §4.24 Phase 2 P2-B: the former `build_source_tokens_*` tests
// moved to `lists::source_key::tests::token_map_*` when the helper
// graduated into `SourceTokenMap::build`. They cover the same
// kebab→slash key shape AND the new typed v1-id lookup.

/// H-22: a freshly created `daemon-stderr.log` lands at mode 0o600,
/// not the umask-default 0o644 — panic output may carry config
/// fragments or stack frames that should not be readable by other
/// local users.
#[test]
fn panic_fallback_log_created_with_mode_0o600() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let (_file, path) = open_panic_fallback_log(dir.path()).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "daemon-stderr.log mode = {mode:o}, want 600");
}

/// H-22: an existing `daemon-stderr.log` at a wider mode (e.g. left
/// behind by an earlier build before this fix) is forced back to
/// 0o600 on the next daemon boot. `OpenOptions::mode` only affects
/// creation, so the explicit `set_permissions` call is what closes
/// the upgrade path.
#[test]
fn panic_fallback_log_existing_file_forced_to_0o600() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("daemon-stderr.log");
    std::fs::write(&path, b"prior boot output\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let pre_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(pre_mode, 0o644, "test setup mode = {pre_mode:o}, want 644");

    let (_file, _path) = open_panic_fallback_log(dir.path()).unwrap();

    let post_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        post_mode, 0o600,
        "post-open mode = {post_mode:o}, want 600 (existing file should be re-chmod'd)"
    );
}

/// H-22: the helper creates the log directory if missing — daemon
/// boot must not fail just because `<config_dir>/logs/` does not
/// exist yet on first start.
#[test]
fn panic_fallback_log_creates_missing_directory() {
    let parent = tempfile::tempdir().unwrap();
    let nested = parent.path().join("nested").join("logs");
    assert!(!nested.exists());
    let (_file, path) = open_panic_fallback_log(&nested).unwrap();
    assert!(nested.exists(), "log dir should be created");
    assert!(path.exists(), "log file should be created");
}

/// The refusal has to name the flag, say what it actually did, and
/// point at the verb that works — it is the only explanation an
/// operator whose script just broke will get.
#[test]
fn blocklist_flag_refusal_names_the_flag_and_the_replacement() {
    let msg = START_BLOCKLIST_FLAG_RETIRED;
    assert!(msg.contains("--blocklist"), "must name the flag: {msg}");
    assert!(
        msg.contains("warden blocklist import-local"),
        "must name the verb that loads a local file: {msg}"
    );
    assert!(
        msg.contains("--kind"),
        "the suggested command must be one that actually runs: {msg}"
    );
}

// start-01: a minimal, valid v1 master with a distinguishable `token_hash`
// and an empty list set, so a reload either (a) aborts at the secrets gate
// before the auth-hash store, or (b) reaches the relocated store via the
// empty-sources success path. Both arms avoid any network fetch.
#[cfg(not(feature = "cluster"))]
fn write_reload_master(dir: &Path) -> PathBuf {
    let config_path = dir.join("config.toml");
    std::fs::write(
        &config_path,
        "schema_version = 3\n\n\
         [server]\nlisten = \"127.0.0.1:15353\"\ndefault_profile = \"default\"\n\
         allow_from = [\"10.0.0.0/24\"]\n\n\
         [api]\ntoken_hash = \"NEWHASH\"\n\n\
         [lists]\nsources = []\n\n\
         [profiles.default]\ndisplay_name = \"Default\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    )
    .unwrap();
    config_path
}

/// start-01: a reload rejected at the secrets gate must rotate NOTHING —
/// the in-memory admin token hash stays the pre-reload value even though
/// the on-disk config carries a new one. Pins "a rejected reload changes
/// nothing" against the pre-fix ordering (store-before-secrets-gate).
#[cfg(not(feature = "cluster"))]
#[tokio::test]
async fn reload_rejected_secrets_leaves_token_hash_unchanged() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let config_path = write_reload_master(dir.path());

    // Sibling secrets file at a WIDENED mode (0644) — `load_secrets`
    // rejects any group/other access, aborting the reload at the gate.
    let secrets_path = secrets::secrets_path_for(&config_path);
    std::fs::write(&secrets_path, "x = \"y\"\n").unwrap();
    let mut perm = std::fs::metadata(&secrets_path).unwrap().permissions();
    perm.set_mode(0o644);
    std::fs::set_permissions(&secrets_path, perm).unwrap();

    let api_token_hash = Arc::new(arc_swap::ArcSwap::from_pointee(Some("OLDHASH".to_string())));
    let acl_handle: Arc<arc_swap::ArcSwapOption<Vec<crate::config::cidr::Cidr>>> =
        Arc::new(arc_swap::ArcSwapOption::empty());
    let filter = Arc::new(FilterEngine::new());
    let audit_writer = AuditWriter::open(dir.path().join("audit.log")).unwrap();
    let (notification_tx, _rx) = tokio::sync::broadcast::channel(8);
    let list_cmd_tx_swap = Arc::new(arc_swap::ArcSwap::from_pointee(None));
    let mut refresh_handle: Option<tokio::task::JoinHandle<()>> = None;
    let mut current_files: Vec<PathBuf> = Vec::new();
    let mut current_hash: Option<String> = None;

    handle_reload(
        &config_path,
        &reqwest::Client::new(),
        &filter,
        None,
        &mut refresh_handle,
        &mut None,
        &audit_writer,
        &mut current_files,
        &mut current_hash,
        &api_token_hash,
        &acl_handle,
        None,
        None,
        &notification_tx,
        &list_cmd_tx_swap,
        None,
        std::marker::PhantomData,
        None,
    )
    .await;

    assert_eq!(
        api_token_hash.load_full().as_ref(),
        &Some("OLDHASH".to_string()),
        "a reload rejected at the secrets gate must NOT rotate the token hash"
    );
    // P0-5: the ACL store sits past the secrets gate, so a rejected reload
    // must leave the ACL untouched (still empty here) even though the
    // on-disk config carries an `allow_from`.
    assert!(
        acl_handle.load().is_none(),
        "a reload rejected at the secrets gate must NOT swap the source ACL"
    );
}

/// start-01 (no regression): a reload that passes every gate still rotates
/// the hash. With no secrets file (gate trivially passes) and empty sources,
/// the reload reaches the relocated store and the hash becomes the new one.
#[cfg(not(feature = "cluster"))]
#[tokio::test]
async fn reload_accepted_rotates_token_hash() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = write_reload_master(dir.path());
    // No secrets file → `load_secrets` returns Ok(empty); the gate passes.

    let api_token_hash = Arc::new(arc_swap::ArcSwap::from_pointee(Some("OLDHASH".to_string())));
    // P0-5: start empty so the assertion below proves the accepted reload
    // itself derived + swapped the ACL from the on-disk `allow_from`.
    let acl_handle: Arc<arc_swap::ArcSwapOption<Vec<crate::config::cidr::Cidr>>> =
        Arc::new(arc_swap::ArcSwapOption::empty());
    let filter = Arc::new(FilterEngine::new());
    let audit_writer = AuditWriter::open(dir.path().join("audit.log")).unwrap();
    let (notification_tx, _rx) = tokio::sync::broadcast::channel(8);
    let list_cmd_tx_swap = Arc::new(arc_swap::ArcSwap::from_pointee(None));
    let mut refresh_handle: Option<tokio::task::JoinHandle<()>> = None;
    let mut current_files: Vec<PathBuf> = Vec::new();
    let mut current_hash: Option<String> = None;

    handle_reload(
        &config_path,
        &reqwest::Client::new(),
        &filter,
        None,
        &mut refresh_handle,
        &mut None,
        &audit_writer,
        &mut current_files,
        &mut current_hash,
        &api_token_hash,
        &acl_handle,
        None,
        None,
        &notification_tx,
        &list_cmd_tx_swap,
        None,
        std::marker::PhantomData,
        None,
    )
    .await;

    assert_eq!(
        api_token_hash.load_full().as_ref(),
        &Some("NEWHASH".to_string()),
        "a fully-accepted reload must still rotate the token hash"
    );
    // P0-5 hot-reload: the accepted reload must live-swap the ACL from the
    // config's `allow_from = ["10.0.0.0/24"]` — the fix for the pre-sprint
    // "ACL is restart-only" bug.
    let acl = acl_handle
        .load_full()
        .expect("accepted reload must set the ACL");
    assert_eq!(
        acl.len(),
        1,
        "reloaded ACL must carry the single configured CIDR"
    );
}

// ── reload-gate (incident 2026-07-27 F2) ────────────────────────
//
// The gate's predicate is "did anything the list pipeline consumes
// change?", NOT "did the config tree hash change". The operator's
// real workflow — adding an allow rule to a device — changes the
// tree hash but nothing the pipeline consumes, and must still skip
// the 9.9 M-domain rebuild. These tests pin both directions.

/// Write `body` as a v1 master in `dir` and load it. Panics on a
/// validation error so a malformed fixture fails loudly rather than
/// silently degrading the assertion below it.
#[cfg(not(feature = "cluster"))]
fn load_fixture(dir: &Path, body: &str) -> (PathBuf, crate::config::schema::ConfigV1) {
    let config_path = dir.join("config.toml");
    std::fs::write(&config_path, body).unwrap();
    let loaded = crate::config::loader::load_config(&config_path, time::OffsetDateTime::now_utc())
        .unwrap_or_else(|errs| {
            panic!(
                "fixture must validate: {}",
                errs.iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ")
            )
        });
    (config_path, loaded.config)
}

/// A master with one list source, one admin allow rule, and one
/// device referencing it. `extra_allow` appends a second rule id to
/// the device so a caller can vary ONLY the device's allow set.
#[cfg(not(feature = "cluster"))]
fn gate_master(sources: &str, max_entries: u64, extra_allow: bool) -> String {
    let device_allow = if extra_allow {
        "[\"allow-one\", \"allow-two\"]"
    } else {
        "[\"allow-one\"]"
    };
    format!(
        "schema_version = 3\n\n\
         [server]\nlisten = \"127.0.0.1:15353\"\ndefault_profile = \"default\"\n\n\
         [lists]\nsources = {sources}\nmax_entries = {max_entries}\n\n\
         [profiles.default]\ndisplay_name = \"Default\"\n\n\
         [[admin_rules]]\nid = \"allow-one\"\nrule = \"@@||example.com^\"\n\n\
         [[admin_rules]]\nid = \"allow-two\"\nrule = \"@@||example.org^\"\n\n\
         [[devices]]\nid = \"pc-test\"\ndisplay_name = \"Test PC\"\n\
         ip = \"10.0.0.5\"\nallow_rules = {device_allow}\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n"
    )
}

/// The operator's real case: adding an allow rule to a device
/// changes the config tree hash but nothing the list pipeline
/// consumes. The fingerprint must be identical — a gate built on
/// the tree hash would leave the bug exactly in the flow that
/// caused the incident.
#[cfg(not(feature = "cluster"))]
#[test]
fn lists_fingerprint_ignores_a_device_allow_rule_change() {
    let dir = tempfile::tempdir().unwrap();
    let before = dir.path().join("before");
    let after = dir.path().join("after");
    std::fs::create_dir_all(&before).unwrap();
    std::fs::create_dir_all(&after).unwrap();
    let src = "[\"https://lists.example.invalid/a.txt\"]";
    let (_, cfg_a) = load_fixture(&before, &gate_master(src, 5_000_000, false));
    let (_, cfg_b) = load_fixture(&after, &gate_master(src, 5_000_000, true));

    let secrets = crate::config::secrets::Secrets::default();
    assert_eq!(
        ListsFingerprint::from_config(&cfg_a, &secrets, &before),
        ListsFingerprint::from_config(&cfg_b, &secrets, &after),
        "a device allow-rule change must not invalidate the list fingerprint"
    );
}

/// The boot helper hands the store to the resolver it builds.
///
/// `build_profile_resolver` is the daemon's cold-start path, and the
/// seam test in the loader covers `load_config` -> `ProfileResolver`
/// directly, not this. Without an assertion here the boot wiring is
/// proven by the type system alone: passing an empty store instead of
/// the loaded one type-checks, and would leave the daemon filtering
/// with none of the operator's own rules while every test stays green.
#[test]
fn the_boot_resolver_carries_the_custom_list_store() {
    use crate::config::custom_list::{CompiledCustomList, CustomListStore};
    use compact_str::CompactString;

    let mut config = crate::config::schema::ConfigV1 {
        schema_version: 3,
        ..Default::default()
    };
    config.profiles.insert(
        "kids".into(),
        crate::config::schema::Profile {
            custom_lists: vec![crate::config::schema::Id::new("minecraft").unwrap()],
            ..Default::default()
        },
    );
    config.server.default_profile = Some(crate::config::schema::Id::new("kids").unwrap());

    let mut store = CustomListStore::new();
    store.insert(
        crate::config::schema::Id::new("minecraft").unwrap(),
        CompiledCustomList {
            allow: vec![CompactString::new("mc.example.com")],
            deny: vec![CompactString::new("ads.example.com")],
            skipped: 0,
        },
    );

    let resolver = build_profile_resolver(&config, &SourceBitMap::default(), &store);
    let rp = resolver
        .default_profile()
        .expect("default_profile must resolve to kids");
    assert!(
        rp.allow_domains.contains("mc.example.com"),
        "the boot resolver must carry the pack's allow rule"
    );
    assert!(
        rp.deny_domains.contains("ads.example.com"),
        "the boot resolver must carry the pack's deny rule"
    );
}

/// A custom list edit reaches the resolver without paying for a
/// corpus rebuild. Two halves, both required.
///
/// (a) alone is green for a feature that compiles nothing. (b) alone is
/// green for an implementation that rebuilds the whole domain corpus on
/// every rule the operator adds from the query log — seconds of stall
/// for one domain.
///
/// Modelled on `lists_fingerprint_ignores_a_device_allow_rule_change`:
/// a device allow rule is also compiled into the resolver and also sits
/// outside the list pipeline. One directory for both loads, so the pack
/// edit is the only variable.
#[cfg(not(feature = "cluster"))]
#[test]
fn a_custom_list_edit_does_not_invalidate_the_list_fingerprint() {
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("config.toml");
    std::fs::write(
        &master,
        "schema_version = 3\n\n\
         [server]\nlisten = \"127.0.0.1:15353\"\ndefault_profile = \"kids\"\n\n\
         [lists]\nsources = [\"https://lists.example.invalid/a.txt\"]\n\n\
         [[custom_lists]]\nid = \"minecraft\"\n\n\
         [profiles.kids]\ncustom_lists = [\"minecraft\"]\n\n\
         [upstream]\nservers = [\"192.0.2.1:53\"]\n",
    )
    .unwrap();
    std::fs::create_dir(dir.path().join("packs")).unwrap();
    let pack = dir.path().join("packs").join("minecraft.txt");
    std::fs::write(&pack, "@@||one.example.com^\n").unwrap();

    let now = time::OffsetDateTime::now_utc();
    let secrets = crate::config::secrets::Secrets::default();
    let before = crate::config::loader::load_config(&master, now).expect("fixture must load");
    let fp_before = ListsFingerprint::from_config(&before.config, &secrets, dir.path());

    std::fs::write(&pack, "@@||one.example.com^\n@@||two.example.com^\n").unwrap();
    let after = crate::config::loader::load_config(&master, now).expect("fixture must reload");
    let fp_after = ListsFingerprint::from_config(&after.config, &secrets, dir.path());

    // (a) the corpus rebuild is NOT triggered
    assert_eq!(
        fp_before, fp_after,
        "a custom list edit must not invalidate the list fingerprint — \
         the resolver swap sits above that gate and already applied it"
    );

    // (b) but the edit IS live
    let id = crate::config::schema::Id::new("minecraft").unwrap();
    assert_eq!(after.custom_lists[&id].allow.len(), 2);
    assert!(after.custom_lists[&id]
        .allow
        .iter()
        .any(|d| d == "two.example.com"));
}

/// Adding a list source must invalidate the fingerprint — the
/// pipeline genuinely has new work to do.
#[cfg(not(feature = "cluster"))]
#[test]
fn lists_fingerprint_changes_when_a_source_is_added() {
    let dir = tempfile::tempdir().unwrap();
    let before = dir.path().join("before");
    let after = dir.path().join("after");
    std::fs::create_dir_all(&before).unwrap();
    std::fs::create_dir_all(&after).unwrap();
    let (_, cfg_a) = load_fixture(
        &before,
        &gate_master(
            "[\"https://lists.example.invalid/a.txt\"]",
            5_000_000,
            false,
        ),
    );
    let (_, cfg_b) = load_fixture(
        &after,
        &gate_master(
            "[\"https://lists.example.invalid/a.txt\", \"https://lists.example.invalid/b.txt\"]",
            5_000_000,
            false,
        ),
    );

    let secrets = crate::config::secrets::Secrets::default();
    assert_ne!(
        ListsFingerprint::from_config(&cfg_a, &secrets, &before),
        ListsFingerprint::from_config(&cfg_b, &secrets, &after),
        "a new list source must invalidate the fingerprint"
    );
}

/// Trap #1 of the incident brief: `lists.max_entries` changes what
/// the parser *keeps* from an unchanged URL set. A naive gate that
/// only diffs source URLs misses it and would serve a truncated map
/// while reporting success.
#[cfg(not(feature = "cluster"))]
#[test]
fn lists_fingerprint_changes_when_only_max_entries_changes() {
    let dir = tempfile::tempdir().unwrap();
    let before = dir.path().join("before");
    let after = dir.path().join("after");
    std::fs::create_dir_all(&before).unwrap();
    std::fs::create_dir_all(&after).unwrap();
    let src = "[\"https://lists.example.invalid/a.txt\"]";
    let (_, cfg_a) = load_fixture(&before, &gate_master(src, 5_000_000, false));
    let (_, cfg_b) = load_fixture(&after, &gate_master(src, 1_000_000, false));

    let secrets = crate::config::secrets::Secrets::default();
    assert_ne!(
        ListsFingerprint::from_config(&cfg_a, &secrets, &before),
        ListsFingerprint::from_config(&cfg_b, &secrets, &after),
        "max_entries changes the parse result on an unchanged URL set"
    );
}

/// lane-C 2026-08-17: `max_total_domains` changes what the corpus
/// guard enforces on an unchanged URL set — same class of trap as
/// `max_entries` above, and it shipped missing from the struct.
/// Mutation prediction written first: deleting the
/// `max_total_domains: config.lists.max_total_domains,` line from
/// `ListsFingerprint::compute` makes this test the only one that goes
/// red — every other fingerprint test holds the ceiling fixed and
/// varies something else, so none of them would notice.
#[cfg(not(feature = "cluster"))]
#[test]
fn lists_fingerprint_changes_when_only_max_total_domains_changes() {
    let dir = tempfile::tempdir().unwrap();
    let before = dir.path().join("before");
    let after = dir.path().join("after");
    std::fs::create_dir_all(&before).unwrap();
    std::fs::create_dir_all(&after).unwrap();
    let src = "[\"https://lists.example.invalid/a.txt\"]";
    let base = gate_master(src, 5_000_000, false);
    let low = base.replacen(
        "max_entries = 5000000\n",
        "max_entries = 5000000\nmax_total_domains = 8000000\n",
        1,
    );
    let high = base.replacen(
        "max_entries = 5000000\n",
        "max_entries = 5000000\nmax_total_domains = 20000000\n",
        1,
    );
    let (_, cfg_a) = load_fixture(&before, &low);
    let (_, cfg_b) = load_fixture(&after, &high);

    let secrets = crate::config::secrets::Secrets::default();
    let live = ListsFingerprint::from_config(&cfg_a, &secrets, &before);
    let reloaded = ListsFingerprint::from_config(&cfg_b, &secrets, &after);
    assert_ne!(
        live, reloaded,
        "max_total_domains changes what the corpus guard enforces on an \
         unchanged URL set — a fingerprint that misses it lets the reuse \
         gate skip the rebuild, so `warden lists set max_total_domains` \
         reports success while the live corpus_guard keeps the old ceiling"
    );
    assert!(
        !should_reuse_live_lists(true, Some(&live), &reloaded),
        "a max_total_domains-only change must force a rebuild so the new \
         ceiling actually reaches ListManager::set_max_total_domains"
    );
}

/// A minimal master with one `[[blocklists]]` row on the
/// `imported.local` bridge, `trust = "local"`. No devices or admin
/// rules — `sighup-ignores-bridge-body` is about the bridge's own
/// file, not the device-allow-rule trap `gate_master` exists for.
#[cfg(not(feature = "cluster"))]
fn local_source_master(list_id: &str) -> String {
    format!(
        "schema_version = 3\n\n\
         [server]\nlisten = \"127.0.0.1:15353\"\ndefault_profile = \"default\"\n\n\
         [profiles.default]\ndisplay_name = \"Default\"\n\n\
         [[blocklists]]\nid = \"{list_id}\"\ndisplay_name = \"Local\"\n\
         url = \"https://imported.local/{list_id}.txt\"\ntrust = \"local\"\n\n\
         [upstream]\nservers = [\"192.0.2.1:53\"]\n"
    )
}

/// `sighup-ignores-bridge-body`. The bridge
/// (`lists::manager::try_bridge_imported_local`) re-reads this file
/// fresh on every `refresh()` call — but nothing in `[[blocklists]]`
/// changes when the operator edits the file's *content* in place, so
/// the fingerprint must stat the file itself. Mutation prediction
/// written first: reverting the `local_stamp` field to always `None`
/// (as if `BlocklistFingerprint` never grew it) makes this test the
/// only one that goes red — every other fingerprint test uses a
/// remote URL and never touches a `trust = local` row.
#[cfg(not(feature = "cluster"))]
#[test]
fn lists_fingerprint_changes_when_a_local_source_file_is_edited() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("lists")).unwrap();
    let list_path = dir.path().join("lists").join("housepolicy.txt");
    std::fs::write(&list_path, "ads.example\n").unwrap();

    let (_, cfg) = load_fixture(dir.path(), &local_source_master("housepolicy"));
    let secrets = crate::config::secrets::Secrets::default();
    let before_edit = ListsFingerprint::from_config(&cfg, &secrets, dir.path());

    // Same path, same config row, DIFFERENT content — an in-place
    // edit, exactly what an operator's editor does. Sleep past
    // typical filesystem mtime granularity so the timestamp genuinely
    // moves; size also changes here as a second, timestamp-independent
    // signal.
    std::thread::sleep(std::time::Duration::from_millis(10));
    std::fs::write(
        &list_path,
        "ads.example\ntracker.example\nnew-entry.example\n",
    )
    .unwrap();

    let after_edit = ListsFingerprint::from_config(&cfg, &secrets, dir.path());

    assert_ne!(
        before_edit, after_edit,
        "editing a trust=local list's on-disk content must invalidate the \
         fingerprint — otherwise a SIGHUP right after the edit takes the \
         reuse-gate skip path, logs 'reusing live blocklist (no rebuild)', \
         and the daemon keeps serving the pre-edit file indefinitely"
    );
    assert!(
        !should_reuse_live_lists(true, Some(&before_edit), &after_edit),
        "an edited local source must force a rebuild so refresh() actually \
         re-reads the file through the imported.local bridge"
    );
}

/// The companion direction: an untouched local file must NOT force a
/// rebuild on every unrelated reload (e.g. a device allow-rule edit
/// sent as its own SIGHUP). Same fail-safe-only-one-way discipline as
/// `lists_fingerprint_ignores_a_device_allow_rule_change`.
#[cfg(not(feature = "cluster"))]
#[test]
fn lists_fingerprint_ignores_an_untouched_local_source() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("lists")).unwrap();
    std::fs::write(
        dir.path().join("lists").join("housepolicy.txt"),
        "ads.example\n",
    )
    .unwrap();

    let (_, cfg) = load_fixture(dir.path(), &local_source_master("housepolicy"));
    let secrets = crate::config::secrets::Secrets::default();
    let fp_a = ListsFingerprint::from_config(&cfg, &secrets, dir.path());
    let fp_b = ListsFingerprint::from_config(&cfg, &secrets, dir.path());

    assert_eq!(
        fp_a, fp_b,
        "an unchanged local source must not spuriously invalidate the fingerprint"
    );
}

/// DoD #2 + #3 at the gate rather than at the fingerprint: a moved
/// fingerprint must actually decide "rebuild". Kept as a predicate
/// test because the rebuild itself calls
/// `fetch_catalog_or_fallback` → `lists.purge.cc`, and this suite
/// takes no network.
#[cfg(not(feature = "cluster"))]
#[test]
fn reuse_gate_rebuilds_when_the_pipeline_inputs_moved() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    let c = dir.path().join("c");
    for d in [&a, &b, &c] {
        std::fs::create_dir_all(d).unwrap();
    }
    let one = "[\"https://lists.example.invalid/a.txt\"]";
    let two = "[\"https://lists.example.invalid/a.txt\", \"https://lists.example.invalid/b.txt\"]";
    let secrets = crate::config::secrets::Secrets::default();

    let (_, base) = load_fixture(&a, &gate_master(one, 5_000_000, false));
    let (_, added_source) = load_fixture(&b, &gate_master(two, 5_000_000, false));
    let (_, tighter_cap) = load_fixture(&c, &gate_master(one, 1_000_000, false));

    let live = ListsFingerprint::from_config(&base, &secrets, &a);

    assert!(
        !should_reuse_live_lists(
            true,
            Some(&live),
            &ListsFingerprint::from_config(&added_source, &secrets, &b)
        ),
        "a new list source must force a rebuild"
    );
    assert!(
        !should_reuse_live_lists(
            true,
            Some(&live),
            &ListsFingerprint::from_config(&tighter_cap, &secrets, &c)
        ),
        "a max_entries change must force a rebuild even though every URL is \
         identical — the naive URL-only gate misses exactly this"
    );
    assert!(
        should_reuse_live_lists(true, Some(&live), &live),
        "an unchanged pipeline must reuse the live manager"
    );
}

/// With no live refresh loop there is no live `ListManager` to
/// reuse, so a matching fingerprint must NOT be enough to skip.
/// Fail-safe direction: when in doubt, rebuild.
#[cfg(not(feature = "cluster"))]
#[test]
fn reuse_gate_rebuilds_when_no_live_refresh_loop_exists() {
    let dir = tempfile::tempdir().unwrap();
    let (_, cfg) = load_fixture(
        dir.path(),
        &gate_master(
            "[\"https://lists.example.invalid/a.txt\"]",
            5_000_000,
            false,
        ),
    );
    let fp = ListsFingerprint::from_config(
        &cfg,
        &crate::config::secrets::Secrets::default(),
        dir.path(),
    );

    assert!(
        !should_reuse_live_lists(false, Some(&fp), &fp),
        "a matching fingerprint with no live refresh loop must still rebuild"
    );
    assert!(
        !should_reuse_live_lists(true, None, &fp),
        "an unseeded fingerprint must rebuild"
    );
}

/// What survived a reload — every field is an observable the
/// incident brief names as a trap, read directly rather than through
/// a log line.
#[cfg(not(feature = "cluster"))]
struct GateOutcome {
    /// `None` means the reload was *rejected*; the skip path is a
    /// success path and must not be confused with one.
    returned: Option<bool>,
    /// The live refresh loop must not be aborted or orphaned.
    refresh_alive: bool,
    /// The `ForgetList` IPC sender must not be replaced — the
    /// handler would then be talking to a dead channel.
    cmd_tx_preserved: bool,
    cmd_tx_open: bool,
    /// Sprint 32 N1: exactly one audit record per call, and the
    /// post-hash must be written back or the *next* reload's
    /// `pre_hash` lies.
    audit_ok_records: usize,
    hash_written: bool,
}

/// Drive `handle_reload` against `reload_body` with the live-manager
/// state seeded from `seed_body`. Both bodies land at the SAME path,
/// which is how a real reload sees an operator's edit.
#[cfg(not(feature = "cluster"))]
async fn drive_gate_reload(dir: &Path, seed_body: &str, reload_body: &str) -> GateOutcome {
    let (config_path, seed_cfg) = load_fixture(dir, seed_body);
    let seed_fp =
        ListsFingerprint::from_config(&seed_cfg, &crate::config::secrets::Secrets::default(), dir);
    std::fs::write(&config_path, reload_body).unwrap();

    // Stand-ins for the state a live `ListManager` owns. The refresh
    // task never completes on its own, so `is_finished()` afterwards
    // reads exactly one thing: did the reload abort the live loop?
    let mut refresh_handle = Some(tokio::spawn(std::future::pending::<()>()));
    let (list_cmd_tx, _list_cmd_rx) = tokio::sync::mpsc::channel(16);
    let seeded_tx = Arc::new(Some(list_cmd_tx));
    let list_cmd_tx_swap = Arc::new(arc_swap::ArcSwap::from(seeded_tx.clone()));
    let mut lists_fingerprint = Some(seed_fp);

    let api_token_hash = Arc::new(arc_swap::ArcSwap::from_pointee(None));
    let acl_handle: Arc<arc_swap::ArcSwapOption<Vec<crate::config::cidr::Cidr>>> =
        Arc::new(arc_swap::ArcSwapOption::empty());
    let filter = Arc::new(FilterEngine::new());
    let audit_path = dir.join("audit.log");
    let audit_writer = AuditWriter::open(audit_path.clone()).unwrap();
    let (notification_tx, _rx) = tokio::sync::broadcast::channel(8);
    let mut current_files: Vec<PathBuf> = Vec::new();
    let mut current_hash: Option<String> = None;

    // A gate that fails to fire falls through to
    // `fetch_catalog_or_fallback` (lists.purge.cc) and a full
    // refresh. The timeout turns that regression into a named
    // failure instead of a hang; the skip path returns in ~1 ms.
    let returned = tokio::time::timeout(
        Duration::from_secs(20),
        handle_reload(
            &config_path,
            &reqwest::Client::new(),
            &filter,
            None,
            &mut refresh_handle,
            &mut lists_fingerprint,
            &audit_writer,
            &mut current_files,
            &mut current_hash,
            &api_token_hash,
            &acl_handle,
            None,
            None,
            &notification_tx,
            &list_cmd_tx_swap,
            None,
            std::marker::PhantomData,
            None,
        ),
    )
    .await
    .expect("skip path must not reach the network: handle_reload did not return promptly");

    let audit_ok_records = std::fs::read_to_string(&audit_path)
        .unwrap_or_default()
        .lines()
        .filter(|l| l.contains("\"result\":\"ok\""))
        .count();

    GateOutcome {
        returned,
        refresh_alive: refresh_handle.as_ref().is_some_and(|h| !h.is_finished()),
        cmd_tx_preserved: Arc::ptr_eq(&seeded_tx, &list_cmd_tx_swap.load_full()),
        cmd_tx_open: list_cmd_tx_swap
            .load()
            .as_ref()
            .as_ref()
            .is_some_and(|tx| !tx.is_closed()),
        audit_ok_records,
        hash_written: current_hash.is_some(),
    }
}

/// DoD #1: a reload whose config is byte-identical must reuse the
/// live manager. Asserted on the live-state observables, never on a
/// log line.
#[cfg(not(feature = "cluster"))]
#[tokio::test]
async fn reload_with_identical_config_reuses_the_live_manager() {
    let dir = tempfile::tempdir().unwrap();
    let body = gate_master(
        "[\"https://lists.example.invalid/a.txt\"]",
        5_000_000,
        false,
    );
    let out = drive_gate_reload(dir.path(), &body, &body).await;

    assert!(
        out.refresh_alive,
        "the skip path must not abort or orphan the live refresh loop"
    );
    assert!(
        out.cmd_tx_preserved,
        "the skip path must not replace list_cmd_tx_swap — ForgetList would \
         then hold a sender to a dead channel"
    );
    assert!(
        out.cmd_tx_open,
        "the preserved ForgetList sender must be live"
    );
    assert_eq!(
        out.returned,
        Some(false),
        "a skip is a SUCCESS path: None would mean 'rejected' and freeze the \
         schedule-tick gate"
    );
    assert_eq!(
        out.audit_ok_records, 1,
        "Sprint 32 N1: exactly one audit record per reload, skip included"
    );
    assert!(
        out.hash_written,
        "the post-hash must be written back or the NEXT reload's pre_hash lies"
    );
}

/// DoD #4 — the operator's real case, and the reason the gate is not
/// built on the config tree hash. Adding an allow rule to a device
/// moves the tree hash but nothing the list pipeline consumes, so
/// the 9.9 M-domain rebuild must still be skipped. A hash gate would
/// have left the incident's bug exactly where it was.
#[cfg(not(feature = "cluster"))]
#[tokio::test]
async fn reload_after_a_device_allow_rule_change_reuses_the_live_manager() {
    let dir = tempfile::tempdir().unwrap();
    let src = "[\"https://lists.example.invalid/a.txt\"]";
    let before = gate_master(src, 5_000_000, false);
    let after = gate_master(src, 5_000_000, true);
    assert_ne!(before, after, "the fixture must actually differ on disk");

    let out = drive_gate_reload(dir.path(), &before, &after).await;

    assert!(
        out.refresh_alive,
        "adding a device allow rule must not cost a blocklist rebuild"
    );
    assert!(
        out.cmd_tx_preserved,
        "list_cmd_tx_swap must survive the skip"
    );
    assert_eq!(out.returned, Some(false), "a skip is a success path");
    assert_eq!(out.audit_ok_records, 1, "exactly one audit record");
    assert!(out.hash_written, "the new tree hash must still be recorded");
}

// ── boot_list_persistence.md §2.1 / §2.4 — the pre-bind load ─────
//
// Boot ordering is not directly unit-testable: `run_server` is one
// ~1200-line function that ends in a socket bind. What IS testable is
// the piece the bind now depends on — `load_corpus_before_bind` — plus
// the predicate that decides which side of it a node lands on. The two
// things these tests cannot reach are stated in the task report rather
// than papered over with an assertion that would pass either way:
// that the caller binds only after this returns, and that the gate seed
// spells `!spawn_lists` at that one call site.

/// A source URL that cannot resolve to anything: port 1 on loopback,
/// refused instantly and with no DNS lookup. Neutral — RFC-reserved
/// loopback, no third-party host (CLAUDE.md §Neutrality).
const DEAD_SOURCE: &str = "https://127.0.0.1:1/blocklist.txt";

fn boot_test_manager(cache_dir: &Path, source: &str) -> ListManager {
    let sources = vec![source.to_string()];
    let bits = crate::lists::manager::build_source_bit_map(&sources)
        .expect("one source is inside the 64-bit cap");
    ListManager::new(
        // The *tight* client, exactly as `run_server` builds it, so a
        // test that observes a bulk client has observed an install.
        crate::lists::http_client::build_list_client(Duration::from_secs(30)).unwrap(),
        Arc::new(FilterEngine::new()),
        vec![source.to_string()],
        Catalog::fallback(),
        Duration::from_secs(3600),
        bits,
        200 * 1024 * 1024,
        crate::lists::parser::DEFAULT_MAX_LIST_ENTRIES,
        Some(cache_dir.to_path_buf()),
    )
}

/// Branch (a): a populated cache boots the map with **no** network.
///
/// The count alone cannot prove that — on a download failure the `Err`
/// arm re-parses the retained `.cache`, so `1` comes back either way.
/// The registry can: it records what was *attempted*. Against this
/// fixture (a source that can never succeed) `last_outcome` is what
/// discriminates — `NeverFetched` under `CacheOnly`, `Failed` once a
/// download is actually attempted and refused. `last_refresh_at` stays
/// `None` either way: it stamps only on a *successful* refresh
/// (`lists::status::ListStatus`, distinct from `fetched_at`, which
/// stamps on any attempt), so asserting it here pins §2.8 — a cache
/// read is never recorded as list health — without itself telling
/// this mutant apart from correct code.
///
/// Mutation caught: `RefreshMode::CacheOnly` → `Network` in
/// `load_corpus_before_bind`. The source is unreachable, so that
/// variant still returns 1 from the cache fallback and still returns
/// promptly — `last_outcome` is what separates them.
///
/// Deliberately does NOT assert on the download client. It is bulk here
/// too, but asserting it after the call proves only that the install
/// happened *somewhere* — see the refusal test below for the ordered
/// version.
#[tokio::test]
async fn boot_loads_the_disk_cache_without_attempting_a_download() {
    use crate::lists::status::LastOutcome;
    use time::format_description::well_known::Rfc3339;

    let dir = tempfile::tempdir().unwrap();
    let stem = crate::lists::manager::source_to_cache_stem(DEAD_SOURCE);
    std::fs::write(
        dir.path().join(format!("{stem}.cache")),
        "cached.example.com\n",
    )
    .unwrap();
    // Older than `boot_test_manager`'s 3600s refresh interval, so a
    // `CacheOnly` -> `Network` mutant cannot take the `is_cache_fresh`
    // shortcut and skip HTTP for a reason unrelated to the mode under
    // test — it must instead hit the refused loopback source and fall
    // into the `Err` arm that re-parses this retained cache. No
    // `size=` line: `load_meta_file` leaves `size: None` and
    // `validate_cached_body_size` then accepts the body, so the
    // assertions below are unchanged.
    let stale_fetch = time::OffsetDateTime::now_utc() - time::Duration::hours(2);
    std::fs::write(
        dir.path().join(format!("{stem}.meta")),
        format!("fetched-at={}\n", stale_fetch.format(&Rfc3339).unwrap()),
    )
    .unwrap();

    let mut mgr = boot_test_manager(dir.path(), DEAD_SOURCE);
    let reg = mgr.status_registry();

    let count = tokio::time::timeout(
        Duration::from_secs(20),
        load_corpus_before_bind(&mut mgr, Duration::from_secs(3600)),
    )
    .await
    .expect("a populated cache must let boot return — it must not reach branch (c)");

    assert_eq!(count, 1, "the cached domain must be installed");
    let status = reg
        .status_for_url(DEAD_SOURCE)
        .expect("the source must have a registry slot");
    assert!(
        matches!(status.last_outcome, LastOutcome::NeverFetched),
        "boot must not record a refresh attempt it never made: got {:?}",
        status.last_outcome
    );
    assert!(
        status.last_refresh_at.is_none(),
        "boot must leave the freshness baseline unstamped (§2.8): got {:?}",
        status.last_refresh_at
    );
}

/// Branch (c): with lists configured and nothing obtainable from either
/// disk or network, the pre-bind load **never returns**, so the caller
/// never reaches the bind. §2.4's primary guard.
///
/// The timing margin is deliberate and one-sided. The retry backoff is
/// injected as an hour, so the correct implementation is parked in a
/// sleep for the whole test; the mutant — branch (c) deleted — returns
/// after one refused TCP connect on loopback, three orders of magnitude
/// inside the 2 s deadline. A wall-clock assertion in a suite that is
/// flaky under load is only honest with a margin like that.
///
/// The second assertion is obligation §4.8: `mgr.download_client()` is
/// observed at the moment the future is dropped, mid-sleep inside
/// branch (c) — so this proves the bulk client is installed **before
/// branch (c) parks**, no more. It cannot distinguish "installed first"
/// from "installed after branch (b)'s Network cycle but before the
/// sleep": both leave the client bulk by the time this test looks.
///
/// Mutations caught: (1) branch (c)'s `while count == 0` loop removed —
/// the timeout returns `Ok(0)`; (2) `install_bulk_download_client`
/// deleted, or moved to after the `tokio::time::sleep` this test parks
/// in — the client observed is still the tight one, because that
/// statement never runs before the future is dropped.
#[tokio::test]
async fn boot_refuses_to_return_when_no_map_can_be_built() {
    let dir = tempfile::tempdir().unwrap();
    let mut mgr = boot_test_manager(dir.path(), DEAD_SOURCE);

    let tight = format!(
        "{:?}",
        crate::lists::http_client::build_list_client(Duration::from_secs(30)).unwrap()
    );
    let bulk = format!(
        "{:?}",
        crate::lists::http_client::build_bulk_list_client().unwrap()
    );
    assert_ne!(
        tight, bulk,
        "the instrument must discriminate: if `reqwest` stops printing \
         its deadlines, this test proves nothing and must fail loudly \
         rather than pass vacuously"
    );

    let outcome = tokio::time::timeout(
        Duration::from_secs(2),
        load_corpus_before_bind(&mut mgr, Duration::from_secs(3600)),
    )
    .await;

    assert!(
        outcome.is_err(),
        "with lists configured and no map obtainable, the pre-bind load \
         must not return — returning is the bind, and binding without a \
         filter map is the failure this whole change exists to prevent. \
         Returned {outcome:?}"
    );
    assert_eq!(
        format!("{:?}", mgr.download_client()),
        bulk,
        "the bulk client must already be installed before branch (c) \
         parks (§4.8)"
    );
}

/// §2.1 — the background loop's first tick fires immediately, not after
/// `update_interval_secs`.
///
/// It lives here rather than in `lists::manager` because it is a
/// property of the boot contract: the skip was correct only while
/// `start.rs` refreshed inline. Without it, a box restarted more often
/// than its refresh interval (12 h by default) would never update its
/// lists at all — the amplification loop this sprint exists to break.
///
/// Observed through the status registry, not the domain count: the
/// cache fallback keeps the count identical across "refreshed" and
/// "did not refresh", which is exactly the blindness §4.1 warns about.
/// A stamped `last_refresh_at` means a cycle genuinely ran.
///
/// Mutation caught: restoring `ticker.tick().await; // skip it` in
/// `spawn_refresh_loop` — the registry then stays unstamped, because
/// the next tick is an hour away.
#[tokio::test]
async fn the_background_loop_does_not_discard_its_first_tick() {
    let dir = tempfile::tempdir().unwrap();
    let stem = crate::lists::manager::source_to_cache_stem(DEAD_SOURCE);
    std::fs::write(
        dir.path().join(format!("{stem}.cache")),
        "cached.example.com\n",
    )
    .unwrap();

    let mut mgr = boot_test_manager(dir.path(), DEAD_SOURCE);
    mgr.load_disk_cache();
    let reg = mgr.status_registry();
    assert!(
        reg.status_for_url(DEAD_SOURCE)
            .is_none_or(|s| s.last_refresh_at.is_none()),
        "fixture precondition: nothing has refreshed yet"
    );

    // An hour: the mutant's next tick is far outside any margin this
    // test could plausibly be granted by a loaded machine.
    let handle = mgr.spawn_refresh_loop();

    let mut stamped = false;
    for _ in 0..250 {
        if reg
            .status_for_url(DEAD_SOURCE)
            .is_some_and(|s| s.last_refresh_at.is_some())
        {
            stamped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    handle.abort();

    assert!(
        stamped,
        "the first tick must run a refresh cycle immediately after the \
         bind; discarding it leaves a restarted box up to one full \
         update interval behind"
    );
}

/// §2.4 / §4.5c — the gate seed follows `spawn_lists`, and `spawn_lists`
/// is not "are any blocklists configured".
///
/// A config whose sources live only in `[lists].sources` has an empty
/// `config.blocklists` while being fully configured: it must build its
/// own map, so the gate seeds CLOSED (`!true`).
///
/// Mutation caught: reading the predicate off `config.blocklists`
/// instead of the merged sources — that variant returns `false` here,
/// seeding the gate open on a node that has no map yet, which is the
/// unfiltered-answer P0.
#[test]
fn sources_only_in_the_lists_section_still_build_a_map() {
    let config = ConfigV1::test_scaffold();
    assert!(
        config.blocklists.is_empty(),
        "fixture precondition: the obvious wrong predicate must be \
         empty here, or this test cannot tell the two apart"
    );
    assert!(
        boot_spawns_list_manager(
            &["https://lists.example.invalid/a.txt".to_string()],
            &config
        ),
        "a node with sources builds its own map — the readiness gate \
         seeds closed and branches (b)/(c) apply"
    );
}

/// §2.4's one legitimate empty-map bind — branch (d). No sources means
/// no manager, so the refusal in `load_corpus_before_bind` is never
/// reached (it is only called inside `if spawn_lists`), and the gate
/// seeds OPEN (`!false`) because nothing on this node would ever open
/// it. Without this, obligation §4.3 could be "satisfied" by refusing
/// every empty map, which would take DNS down on every install that
/// deliberately runs unfiltered.
///
/// Mutation caught: `merged_sources.is_empty()` early return deleted or
/// inverted.
#[test]
fn no_sources_means_no_list_manager_and_an_open_gate() {
    let config = ConfigV1::test_scaffold();
    assert!(
        !boot_spawns_list_manager(&[], &config),
        "filtering disabled must stay bindable"
    );
}

/// Phase 1b S1: replication carries **policy, not the built map**, so a
/// secondary derives its own Tier-1 bitmask from the replicated policy
/// exactly as a standalone node does. It therefore runs its own list
/// manager, and the readiness gate seeds CLOSED — the manager it does run
/// is what opens it.
///
/// This test asserts the *opposite* of the one it replaces, deliberately.
/// The predicate carried an `is_cluster_secondary` early return from the
/// era when sync shipped the domain map; S1 deleted that transfer while
/// this branch was in flight, and the two met at the merge. Had the early
/// return landed, a secondary would have had no map from either direction:
/// none built locally, and none arriving. The old test would have kept
/// that green.
///
/// Mutation caught: re-adding any secondary-specific early return — the
/// second assertion goes red the moment the role changes the answer.
///
/// Feature-gated because `ClusterRole` is; run with
/// `cargo test --features cluster`.
#[cfg(feature = "cluster")]
#[test]
fn a_cluster_secondary_builds_its_own_map() {
    use crate::config::schema::ClusterRole;
    let sources = vec!["https://lists.example.invalid/a.txt".to_string()];

    let mut config = ConfigV1::test_scaffold();
    assert!(
        boot_spawns_list_manager(&sources, &config),
        "fixture precondition: with sources present and no cluster role \
         this must already be true, or the role cannot be shown to be \
         irrelevant below"
    );

    config.cluster.enabled = true;
    config.cluster.role = ClusterRole::Secondary;
    assert!(
        boot_spawns_list_manager(&sources, &config),
        "S1 made replication policy-only: a secondary builds its own map, \
         so the role must not change this answer. Returning false here \
         leaves the node with no filter map at all"
    );
}

// --- catalog preference (boot_list_persistence §3.0) ------------

/// Bind a loopback listener that counts every inbound connection and
/// answers each one with a proxy error, then drops it.
///
/// Pointing a `reqwest` client's proxy at this address makes every
/// request — whatever URL `Catalog::fetch` hardcodes — terminate here
/// instead of on the internet, and makes "did the code attempt a
/// network call at all?" **directly observable** rather than inferred
/// from a return value both branches produce. The 502 (rather than a
/// bare drop) keeps the failure deterministic and immediate.
fn spawn_connection_counter() -> (std::net::SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = count.clone();
    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf).await;
            let _ = stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await;
        }
    });
    (addr, count)
}

/// A catalog carrying an id that is deliberately **not** in
/// `FALLBACK_ENTRIES`, so "this came from disk" is distinguishable
/// from "this is `Catalog::fallback()`". Without the distinctive id an
/// implementation that ignored the persisted file entirely would pass.
fn probe_catalog() -> Catalog {
    Catalog::from_entries(vec![crate::lists::catalog::CatalogEntry {
        scope: "probe".to_string(),
        topic: Some("marker".to_string()),
        name: "probe".to_string(),
        url: "http://127.0.0.1:1/probe.txt".to_string(),
        entries: 0,
        updated_at: String::new(),
        format: crate::config::schema::BlocklistFormat::Domains,
    }])
}

/// The policy itself, which is the part a future edit is most likely
/// to get backwards.
///
/// With a catalog on disk and a client whose every request lands on a
/// dead loopback proxy:
/// - `Disk` returns the persisted entries **with zero connections** —
///   this is the load-bearing assertion, and it is what fails if the
///   `Disk` early return is dropped and boot goes back to fetching in
///   front of the bind.
/// - `Network` returns the same entries via the fetch-failure arm, but
///   only after actually trying — pinning that the persisted copy beats
///   `FALLBACK_ENTRIES` on a reload with no egress.
#[tokio::test]
async fn catalog_preference_disk_skips_the_network_and_network_tries_it() {
    let dir = tempfile::tempdir().unwrap();
    probe_catalog().save_to_disk(dir.path()).expect("save");

    let (addr, connections) = spawn_connection_counter();
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://{addr}")).unwrap())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let from_disk = fetch_catalog_or_fallback(&client, dir.path(), CatalogPreference::Disk).await;
    assert_eq!(
        from_disk.resolve("probe/marker").as_deref(),
        Some("http://127.0.0.1:1/probe.txt"),
        "Disk must return the persisted catalog, not FALLBACK_ENTRIES"
    );
    assert_eq!(
        connections.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "Disk must not touch the network: this call sits ~530 lines in \
         front of the DNS bind, and a dead link there is up to 30s of \
         household downtime"
    );

    let from_network =
        fetch_catalog_or_fallback(&client, dir.path(), CatalogPreference::Network).await;
    assert_eq!(
        from_network.resolve("probe/marker").as_deref(),
        Some("http://127.0.0.1:1/probe.txt"),
        "a failed fetch must fall back to the persisted copy, which is \
         newer than the compiled-in FALLBACK_ENTRIES"
    );
    assert!(
        connections.load(std::sync::atomic::Ordering::SeqCst) > 0,
        "Network must actually attempt the fetch — it is the only path \
         that ever refreshes the persisted catalog"
    );
}

/// The other half of the fallback chain: no persisted catalog and no
/// reachable network must still yield a usable catalog, never an empty
/// one. `FALLBACK_ENTRIES` is the floor under both preferences.
#[tokio::test]
async fn no_disk_copy_and_no_network_falls_back_to_builtin_entries() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, _connections) = spawn_connection_counter();
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://{addr}")).unwrap())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    for pref in [CatalogPreference::Disk, CatalogPreference::Network] {
        let catalog = fetch_catalog_or_fallback(&client, dir.path(), pref).await;
        assert!(
            catalog.resolve("privacy/ads").is_some(),
            "{pref:?} with neither disk nor network must still resolve the \
             built-in slugs — an empty catalog makes every source unresolvable"
        );
    }
    assert!(
        Catalog::load_from_disk(dir.path()).is_none(),
        "a failed fetch must never persist Catalog::fallback(): freezing \
         the compiled-in entries onto disk stops the next boot from ever \
         fetching a real catalog"
    );
}

/// The `Ok`-arm persistence guard (Minor 3, task 5 review): a fetch
/// that succeeds with zero entries must not be persisted. Predicate
/// test for the same reason the reuse gate
/// (`reuse_gate_rebuilds_when_the_pipeline_inputs_moved`) is one —
/// `Catalog::fetch` hardcodes `https://lists.purge.cc/index.json`, so
/// no offline test can drive `fetch_catalog_or_fallback` into its
/// `Ok` arm at all; this is the seam that actually can be exercised
/// without egress.
#[test]
fn empty_fetched_catalog_is_not_worth_persisting() {
    assert!(
        !catalog_worth_persisting(&Catalog::from_entries(vec![])),
        "an HTTP 200 carrying zero entries must not be persisted — it \
         would freeze every later boot onto an empty catalog"
    );
}

/// Companion to the above: a normal non-empty fetch must still be
/// persisted — a guard that is inverted, or that always returns
/// `false`, would silently make catalog persistence inert.
#[test]
fn nonempty_fetched_catalog_is_worth_persisting() {
    assert!(
        catalog_worth_persisting(&probe_catalog()),
        "a non-empty fetched catalog must still be persisted"
    );
}

/// The one property **no offline test can observe**: that a
/// *successful* fetch persists.
///
/// `Catalog::fetch` hardcodes `https://lists.purge.cc/index.json`, so
/// the `Ok` arm is unreachable without egress — and deleting
/// `save_to_disk` from it leaves the entire offline suite green (47
/// tests, measured) while making the feature inert in production:
/// nothing is ever written, so every boot finds no disk copy and
/// fetches in front of the bind, exactly as before this task.
///
/// Ignored and never wired into the tri-gate, for the reason spelled
/// out on `lists::catalog::tests::fetch_live_catalog`: a network test
/// that gates commits is one purge.cc outage away from blocking all
/// work. Run it when touching this helper:
/// `cargo test --lib -- --ignored cli::commands::start::tests::network_preference_persists`
#[tokio::test]
#[ignore = "hits real https://lists.purge.cc — run with `cargo test -- --ignored`"]
async fn network_preference_persists_a_fetched_catalog() {
    let dir = tempfile::tempdir().unwrap();
    let client = reqwest::Client::builder()
        .user_agent("purge-warden/test")
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let fetched = fetch_catalog_or_fallback(&client, dir.path(), CatalogPreference::Network).await;
    // Discriminates "we reached the live catalog" from "the fetch failed
    // and we got FALLBACK_ENTRIES" — the fallback carries no timestamps,
    // and both resolve the same slugs, so slug resolution cannot tell
    // them apart. Without this the test would fail on a box with no
    // egress and blame the feature.
    assert!(
        fetched
            .entries()
            .first()
            .is_some_and(|e| !e.updated_at.is_empty()),
        "precondition: this test needs egress to lists.purge.cc — it got \
         the compiled-in fallback instead of a live catalog"
    );

    let persisted = Catalog::load_from_disk(dir.path()).expect(
        "a successful fetch must leave a catalog on disk — without this the \
         feature is inert: boot finds nothing and fetches, every time, in \
         front of the bind",
    );
    assert_eq!(
        persisted.resolve("privacy/ads"),
        fetched.resolve("privacy/ads"),
        "the persisted copy must be the catalog just fetched"
    );
}

// ── the supervisor keeps watching the REST API after it binds ────

/// The API is optional, so its arm must park when no task was spawned.
/// A future that resolved on `None` would make the supervisor `select!`
/// spin at full speed instead of waiting on signals.
#[tokio::test]
async fn api_task_exit_parks_forever_when_no_api_task_was_spawned() {
    let mut handle: Option<JoinHandle<()>> = None;
    let parked = tokio::time::timeout(Duration::from_millis(50), api_task_exit(&mut handle)).await;
    assert!(parked.is_err(), "the disabled arm must never complete");
}

/// A resolved `JoinHandle` panics when polled again, so the helper
/// retires it as it reports and the arm's guard reads that same
/// `Option`. Without the retirement the supervisor is one loop
/// iteration away from panicking on its own supervision.
#[tokio::test]
async fn api_task_exit_retires_the_handle_it_reports_on() {
    let mut handle = Some(tokio::spawn(async {}));
    assert!(api_task_exit(&mut handle).await.is_ok());
    assert!(handle.is_none(), "a reported handle must be retired");

    let parked = tokio::time::timeout(Duration::from_millis(50), api_task_exit(&mut handle)).await;
    assert!(parked.is_err(), "a retired handle must park, not panic");
}

/// Every signal the daemon handles drops this future mid-await, because
/// another arm won the race. A still-running API task has to survive
/// that, or the first SIGHUP silently un-supervises the API.
#[tokio::test]
async fn api_task_exit_keeps_a_running_handle_when_another_arm_wins() {
    let mut handle = Some(tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(30)).await;
    }));
    let lost = tokio::time::timeout(Duration::from_millis(50), api_task_exit(&mut handle)).await;
    assert!(lost.is_err(), "a 30 s task cannot finish inside 50 ms");
    let survivor = handle.expect("a running API task must survive a lost race");
    survivor.abort();
}

/// A panic inside the API task reaches the supervisor as a `JoinError`
/// it can report, rather than as a silent disappearance.
#[tokio::test]
async fn api_task_exit_surfaces_a_panic_in_the_api_task() {
    let mut handle = Some(tokio::spawn(async {
        panic!("api task blew up");
    }));
    let err = api_task_exit(&mut handle).await.unwrap_err();
    assert!(
        err.is_panic(),
        "a panicking API task must report as a panic"
    );
}
