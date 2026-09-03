use super::*;
use crate::config::schema::{
    blocklist::Blocklist, device::Device, group::Group, profile::Profile, schedule::Schedule,
    subnet::Subnet, ServerGlobals,
};
use time::macros::datetime;

fn now() -> OffsetDateTime {
    datetime!(2026-04-22 12:00:00 UTC)
}

fn blocklist(id: &str) -> Blocklist {
    Blocklist {
        id: Id::new(id).unwrap(),
        display_name: id.into(),
        url: "https://example.com/list.txt".into(),
        format: super::super::blocklist::BlocklistFormat::Domains,
        update_interval_hours: 12,
        max_entries: 1000,
        enabled: true,
        auth_token_ref: None,
        base: super::super::blocklist::BlocklistBase::default(),
        trust: super::super::blocklist::BlocklistTrust::default(),
        accept_unsigned_allow: false,
        max_consecutive_failures: 5,
    }
}

fn profile_default() -> Profile {
    Profile {
        display_name: "Default".into(),
        block_response: None,
        blocked_ttl_secs: None,
        admin_rules: vec![],
        block_all: false,
        local_records: vec![],
        ecs: None,
        rewrite_rules: vec![],
        safe_search: false,
        custom_lists: vec![],
        // Enumerated rather than `..Default::default()` to match this
        // helper's existing style: spelling every field out is what makes
        // a new one a compile error here instead of a silent default.
        lists: std::collections::BTreeMap::new(),
    }
}

fn device(id: &str, ip: &str, profile: Option<&str>) -> Device {
    Device {
        id: Id::new(id).unwrap(),
        display_name: id.into(),
        ip: Some(ip.parse().unwrap()),
        mac: None,
        mac_aliases: vec![],
        profile: profile.map(|p| Id::new(p).unwrap()),
        groups: vec![],
        owner: None,
        device_type: None,
        department: None,
        notes: None,
        allow_rules: vec![],
        deny_rules: vec![],
        override_profile_deny: false,
        unfiltered: false,
        network_name: None,
        network_name_wildcard: false,
    }
}

fn group(id: &str, profile: &str, priority: i32, devices: &[&str]) -> Group {
    Group {
        id: Id::new(id).unwrap(),
        display_name: id.into(),
        profile: Id::new(profile).unwrap(),
        priority,
        devices: devices.iter().map(|d| Id::new(*d).unwrap()).collect(),
    }
}

/// s4 config-m4 — build a REAL, loaded [`Secrets`] via the public
/// `load_secrets` path on a 0600 temp file.
///
/// Do not be tempted by `Secrets::empty()` / `Secrets::default()` here:
/// both carry `loaded: false`, the cross-check is gated on
/// `is_loaded()`, and a test built on either would skip the check
/// entirely and pass against broken code. Mirrors the same-reason
/// helpers at `lists::source_key::tests::make_secrets_with` and
/// `lists::manager::tests::secrets_with` (`entries` is private, so the
/// load path is the only way to a populated table).
fn loaded_secrets_with(names: &[&str]) -> Secrets {
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    let pid = std::process::id();
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("purge-cfgm4-{pid}-{n}"));
    fs::create_dir_all(&dir).unwrap();
    let sp = dir.join("secrets.toml");
    {
        let mut f = fs::File::create(&sp).unwrap();
        for name in names {
            writeln!(f, "{name} = \"token-value\"").unwrap();
        }
    }
    let mut perm = fs::metadata(&sp).unwrap().permissions();
    perm.set_mode(0o600);
    fs::set_permissions(&sp, perm).unwrap();
    let secrets = crate::config::secrets::load_secrets(&sp).unwrap();
    let _ = fs::remove_dir_all(&dir);
    assert!(secrets.is_loaded(), "helper must produce a LOADED table");
    secrets
}

#[test]
fn s4_m4_dangling_auth_token_ref_is_crossrefmiss() {
    let mut c = basic_config();
    c.blocklists[0].auth_token_ref = Some("ghost-ref".into());
    let secrets = loaded_secrets_with(&["corp-list-token", "vendor-token"]);

    let errs = validate_collect(
        &c,
        now(),
        &mut AuditWarnings::silent(),
        Some(&secrets),
        None,
    )
    .expect_err("a dangling auth_token_ref must fail the validator pass");

    let miss = errs
        .iter()
        .find(|e| matches!(e, ConfigError::CrossRefMiss(_)))
        .unwrap_or_else(|| panic!("expected a CrossRefMiss, got {errs:?}"));
    let ConfigError::CrossRefMiss(ctx) = miss else {
        unreachable!()
    };
    assert!(ctx.reason.contains("ghost-ref"), "{ctx:?}");
    // The part that makes it actionable rather than merely reported:
    // the operator is told which names DO exist.
    let sugg = ctx.suggestion.as_deref().unwrap_or_default();
    assert!(sugg.contains("corp-list-token"), "{sugg}");
    assert!(sugg.contains("vendor-token"), "{sugg}");
}

#[test]
fn s4_m4_resolvable_ref_and_unloaded_secrets_both_pass() {
    // A ref that resolves is silent.
    let mut c = basic_config();
    c.blocklists[0].auth_token_ref = Some("corp-list-token".into());
    let secrets = loaded_secrets_with(&["corp-list-token"]);
    assert!(
        validate_collect(
            &c,
            now(),
            &mut AuditWarnings::silent(),
            Some(&secrets),
            None
        )
        .is_ok(),
        "a resolvable ref must not be flagged"
    );

    // No secrets.toml yet → the check is skipped, not failed. An
    // operator who has not set up secrets at all must still boot.
    let mut c2 = basic_config();
    c2.blocklists[0].auth_token_ref = Some("ghost-ref".into());
    let absent = Secrets::empty();
    assert!(!absent.is_loaded());
    assert!(
        validate_collect(
            &c2,
            now(),
            &mut AuditWarnings::silent(),
            Some(&absent),
            None
        )
        .is_ok(),
        "an unloaded secrets table must skip the cross-check"
    );
    // Same for a call site that has no table at all.
    assert!(
        validate_collect(&c2, now(), &mut AuditWarnings::silent(), None, None).is_ok(),
        "None must skip the cross-check"
    );
}

fn basic_config() -> ConfigV1 {
    let mut c = ConfigV1 {
        schema_version: SCHEMA_VERSION_V1,
        server: ServerGlobals {
            default_profile: None,
            default_block_response: super::super::profile::BlockResponseV1::Zero,
            default_blocked_ttl_secs: 60,
            ..ServerGlobals::default()
        },
        blocklists: vec![blocklist("privacy-ads")],
        ..ConfigV1::test_scaffold()
    };
    c.profiles.insert("default".into(), profile_default());
    c
}

// ── happy path ────────────────────────────────────────

#[test]
fn empty_schema_version_1_passes() {
    let c = ConfigV1 {
        schema_version: SCHEMA_VERSION_V1,
        server: ServerGlobals {
            default_blocked_ttl_secs: 60,
            ..ServerGlobals::default()
        },
        ..ConfigV1::test_scaffold()
    };
    assert!(validate(&c, now()).is_ok());
}

#[test]
fn basic_config_passes() {
    assert!(validate(&basic_config(), now()).is_ok());
}

#[test]
fn blocklist_url_with_userinfo_is_refused() {
    // blocklist-01: credentials in the URL are refused, and the
    // credential is NOT echoed back in the error.
    let mut c = basic_config();
    c.blocklists[0].url = "https://user:sekret@lists.example/a.txt".into();
    let errs = validate(&c, now()).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.context().reason.contains("must not embed credentials")),
        "got {errs:?}"
    );
    assert!(
        !errs.iter().any(|e| e.context().reason.contains("sekret")),
        "credential leaked into error: {errs:?}"
    );
}

/// `file://` is refused, and that refusal is intentional.
///
/// A `file:///…` blocklist URL parses fine at the schema layer, so it
/// is easy to believe it is supported — a fixture in
/// `schema::blocklist`'s tests used one for years and read as if it
/// were. It is not: an operator-authored local list goes through the
/// `imported.local` bridge, which resolves under `<config_dir>/lists`
/// and applies the W2.1 trust check. Widening this to real `file://`
/// URLs would let a config name any path on the box and skip that
/// check, so if this test ever fails, the fix is almost certainly to
/// restore the refusal rather than to delete the test.
#[test]
fn blocklist_file_url_is_refused_so_the_import_bridge_stays_the_only_local_path() {
    let mut c = basic_config();
    c.blocklists[0].url = "file:///etc/shadow".into();
    let errs = validate(&c, now()).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.context().reason.contains("must begin with http")),
        "got {errs:?}"
    );

    // Control: the bridge form IS accepted, so this test cannot pass
    // merely because `basic_config()` is broken.
    let mut ok = basic_config();
    ok.blocklists[0].url = "https://imported.local/trusted.txt".into();
    assert!(
        validate(&ok, now()).is_ok(),
        "the imported.local bridge must remain valid"
    );
}

#[test]
fn blocklist_url_with_path_at_sign_is_allowed() {
    // blocklist-01: a `@` in the PATH (not the authority) is fine.
    let mut c = basic_config();
    c.blocklists[0].url = "https://lists.example/lists/@team/a.txt".into();
    assert!(validate(&c, now()).is_ok());
}

#[test]
fn future_retired_at_is_refused() {
    // retired-01: a future retired_at is its own error (not a permanent
    // silent quarantine).
    let mut c = basic_config();
    c.retired.push(RetiredEntry {
        id: Id::new("legacy").unwrap(),
        entity_type: RetiredType::Device,
        retired_at: datetime!(2099-01-01 00:00:00 UTC),
    });
    let errs = validate(&c, now()).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.context().reason.contains("in the future")),
        "got {errs:?}"
    );
}

/// schema-02 (rev-2606): `ConfigV1::test_scaffold()` is a VALID config —
/// the manual `Default` pins `schema_version = SCHEMA_VERSION_V1`
/// instead of the derive's 0, which `validate` rejects. Internal
/// construction sites no longer need to hand-patch the version.
#[test]
fn config_v1_default_validates_clean() {
    assert!(validate(&ConfigV1::test_scaffold(), now()).is_ok());
}

// ── [cluster] (§4.11) ──────────────────────────────────

#[test]
fn cluster_default_is_inert_and_valid() {
    // The default `[cluster]` (disabled, primary) adds no errors —
    // proves the section is inert.
    let mut errs = Vec::new();
    check_cluster(&basic_config(), &mut errs);
    assert!(
        errs.is_empty(),
        "default cluster must produce no errors: {errs:?}"
    );
    assert!(validate(&basic_config(), now()).is_ok());
}

#[test]
fn cluster_enabled_without_token_hash_errors() {
    let mut c = ConfigV1::test_scaffold();
    c.cluster.enabled = true;
    c.cluster.token_hash = None;
    let mut errs = Vec::new();
    check_cluster(&c, &mut errs);
    assert_eq!(errs.len(), 1);
    assert!(errs[0].to_string().contains("token_hash"));
}

#[test]
fn cluster_enabled_with_blank_token_hash_errors() {
    let mut c = ConfigV1::test_scaffold();
    c.cluster.enabled = true;
    c.cluster.token_hash = Some("   ".into());
    let mut errs = Vec::new();
    check_cluster(&c, &mut errs);
    assert_eq!(errs.len(), 1);
}

#[test]
fn cluster_enabled_with_token_hash_ok() {
    let mut c = ConfigV1::test_scaffold();
    c.cluster.enabled = true;
    c.cluster.token_hash = Some("a".repeat(64));
    let mut errs = Vec::new();
    check_cluster(&c, &mut errs);
    assert!(errs.is_empty(), "{errs:?}");
}

#[test]
fn cluster_secondary_without_peer_errors() {
    let mut c = ConfigV1::test_scaffold();
    c.cluster.role = ClusterRole::Secondary;
    c.cluster.peer = None;
    let mut errs = Vec::new();
    check_cluster(&c, &mut errs);
    assert_eq!(errs.len(), 1);
    assert!(errs[0].to_string().contains("peer"));
}

#[test]
fn cluster_secondary_with_peer_ok() {
    let mut c = ConfigV1::test_scaffold();
    c.cluster.role = ClusterRole::Secondary;
    c.cluster.peer = Some("https://192.0.2.10:8053".into());
    let mut errs = Vec::new();
    check_cluster(&c, &mut errs);
    assert!(errs.is_empty(), "{errs:?}");
}

#[test]
fn cluster_invalid_allow_peer_cidr_errors() {
    let mut c = ConfigV1::test_scaffold();
    c.cluster.allow_peer = vec!["not-a-cidr".into(), "10.10.1.0/24".into()];
    let mut errs = Vec::new();
    check_cluster(&c, &mut errs);
    assert_eq!(errs.len(), 1, "only the bad entry errors: {errs:?}");
    assert!(errs[0].to_string().contains("not-a-cidr"));
}

#[test]
fn cluster_valid_secondary_config_validates() {
    // A complete, enabled secondary passes the full validator.
    let mut c = basic_config();
    c.cluster.enabled = true;
    c.cluster.role = ClusterRole::Secondary;
    c.cluster.peer = Some("https://192.0.2.10:8053".into());
    c.cluster.token_hash = Some("b".repeat(64));
    c.cluster.allow_peer = vec!["192.0.2.10/32".into()];
    assert!(validate(&c, now()).is_ok(), "{:?}", validate(&c, now()));
}

#[test]
fn cluster_secondary_plaintext_offbox_peer_errors() {
    // poll-02 / schema-validator-12: a plaintext http:// peer off loopback
    // would leak the bearer token; rejected at lint.
    let mut c = ConfigV1::test_scaffold();
    c.cluster.role = ClusterRole::Secondary;
    c.cluster.peer = Some("http://192.0.2.10:8053".into());
    let mut errs = Vec::new();
    check_cluster(&c, &mut errs);
    assert_eq!(errs.len(), 1, "{errs:?}");
    assert!(errs[0].to_string().contains("peer"));
    // A loopback http:// peer (the CT-smoke rig) is still accepted.
    let mut c2 = ConfigV1::test_scaffold();
    c2.cluster.role = ClusterRole::Secondary;
    c2.cluster.peer = Some("http://127.0.0.1:18080".into());
    let mut errs2 = Vec::new();
    check_cluster(&c2, &mut errs2);
    assert!(errs2.is_empty(), "loopback http peer must pass: {errs2:?}");
}

#[test]
fn cluster_zero_poll_interval_when_enabled_errors() {
    // poll-03: 0 would panic the secondary ticker (panic = "abort").
    let mut c = ConfigV1::test_scaffold();
    c.cluster.enabled = true;
    c.cluster.token_hash = Some("a".repeat(64));
    c.cluster.poll_interval_secs = 0;
    let mut errs = Vec::new();
    check_cluster(&c, &mut errs);
    assert_eq!(errs.len(), 1, "{errs:?}");
    assert!(errs[0].to_string().contains("poll_interval_secs"));
}

// ── §5.3: a secondary's master carries no policy ──────

/// A secondary's master carries no policy by design (§5.3), so the
/// policy-COMPLETENESS checks must not refuse it before its first
/// bundle arrives. Without this, a joined secondary produces a master
/// that cannot boot, so the node never polls, so the bundle that would
/// supply `[upstream]` never arrives.
///
/// Deliberately NOT a blanket exemption: see the three siblings below.
#[test]
fn a_policy_free_secondary_master_validates_before_its_first_sync() {
    let mut c = ConfigV1::test_scaffold();
    c.upstream.servers.clear();
    c.cluster.enabled = true;
    c.cluster.role = ClusterRole::Secondary;
    c.cluster.peer = Some("https://192.0.2.10:8053".into());
    c.cluster.token_hash = Some("00".repeat(32));

    validate(&c, now())
        .expect("a policy-free secondary master must load; the bundle brings the policy");
}

/// The exemption is scoped to ABSENCE, not to correctness. A secondary
/// whose upstream is present but malformed still fails.
///
/// Green today; it goes red against a guard placed around the
/// `check_server_list` CALL rather than around the emptiness, because
/// that one function does emptiness AND the per-entry shape parse.
#[test]
fn the_secondary_exemption_does_not_excuse_a_malformed_upstream() {
    let mut c = ConfigV1::test_scaffold();
    c.upstream.servers = vec!["not a resolver at all".into()];
    c.cluster.enabled = true;
    c.cluster.role = ClusterRole::Secondary;
    c.cluster.peer = Some("https://192.0.2.10:8053".into());
    c.cluster.token_hash = Some("00".repeat(32));

    assert!(
        validate(&c, now()).is_err(),
        "absence is excused on a secondary; malformed policy is not"
    );
}

/// The exemption covers `upstream.servers` and NOTHING ELSE.
/// `[upstream.fallback]` is opt-in: an operator who writes it asked for
/// a fallback, and one with no resolver can never take over — its
/// absence is not the pre-first-sync state the exemption exists for.
///
/// This is the test that catches an implementer guarding
/// `check_upstream_servers` at FUNCTION level instead of at its first
/// `check_server_list` call. A grep for the predicate cannot see that
/// mistake: it would still appear only in this file.
#[test]
fn the_secondary_exemption_does_not_cover_an_empty_upstream_fallback() {
    let mut c = ConfigV1::test_scaffold();
    c.upstream.servers.clear();
    c.upstream.fallback = Some(crate::config::settings::FallbackConfig {
        mode: c.upstream.mode,
        servers: Vec::new(),
    });
    c.cluster.enabled = true;
    c.cluster.role = ClusterRole::Secondary;
    c.cluster.peer = Some("https://192.0.2.10:8053".into());
    c.cluster.token_hash = Some("00".repeat(32));

    let errs = validate(&c, now())
        .expect_err("an explicitly-written fallback must still be complete on a secondary");
    assert!(
        errs.iter()
            .any(|e| e.to_string().contains("upstream.fallback")),
        "the fallback must be the thing refused, not something else: {errs:?}"
    );
}

/// And it is scoped to secondaries. A PRIMARY with no upstream is the
/// neutrality-03 refusal and must stay refused — warden still does not
/// choose a resolver for anyone.
#[test]
fn a_primary_with_no_upstream_is_still_refused() {
    let mut c = ConfigV1::test_scaffold();
    c.upstream.servers.clear();
    c.cluster.enabled = true;
    c.cluster.role = ClusterRole::Primary;
    c.cluster.token_hash = Some("00".repeat(32));

    let errs = validate(&c, now()).expect_err("warden does not choose a resolver for anyone");
    assert!(
        errs.iter()
            .any(|e| e.to_string().contains("must list at least one resolver")),
        "the upstream emptiness must be the refusal: {errs:?}"
    );
}

/// Cluster-disabled is not a secondary. A node that has scaffolded
/// `role = "secondary"` but not yet joined is NOT syncing, so nothing
/// will bring it an upstream; exempting it would produce a config that
/// loads and a daemon that resolves nothing.
#[test]
fn an_unjoined_secondary_gets_no_exemption() {
    let mut c = ConfigV1::test_scaffold();
    c.upstream.servers.clear();
    c.cluster.enabled = false;
    c.cluster.role = ClusterRole::Secondary;
    c.cluster.peer = Some("https://192.0.2.10:8053".into());

    assert!(
        validate(&c, now()).is_err(),
        "an unjoined secondary is not a bootable node"
    );
}

// ── [api] (rev-2606 §07) ──────────────────────────────

#[test]
fn api_disabled_section_inert_ok() {
    // Mirrors `[cluster]`: a disabled section is never validated, so
    // a half-written `[api]` block can sit in the config harmlessly.
    let mut c = ConfigV1::test_scaffold();
    c.api.enabled = false;
    c.api.listen = "0.0.0.0:8053".parse().unwrap();
    c.api.token_hash = None;
    c.api.tls_cert = Some("/etc/warden/api.crt".into());
    c.api.tls_key = None;
    let mut errs = Vec::new();
    check_api(&c, &mut errs, &mut AuditWarnings::emitting());
    assert!(errs.is_empty(), "disabled [api] must be inert: {errs:?}");
}

#[test]
fn api_enabled_without_token_hash_errors() {
    let mut c = ConfigV1::test_scaffold();
    c.api.enabled = true;
    c.api.token_hash = None;
    let mut errs = Vec::new();
    check_api(&c, &mut errs, &mut AuditWarnings::emitting());
    assert_eq!(errs.len(), 1, "{errs:?}");
    assert!(errs[0].to_string().contains("token_hash"));
}

#[test]
fn api_enabled_with_blank_token_hash_errors() {
    let mut c = ConfigV1::test_scaffold();
    c.api.enabled = true;
    c.api.token_hash = Some("   ".into());
    let mut errs = Vec::new();
    check_api(&c, &mut errs, &mut AuditWarnings::emitting());
    assert_eq!(errs.len(), 1, "{errs:?}");
}

#[test]
fn api_enabled_with_token_loopback_ok() {
    // Default listen is 127.0.0.1:8053 — plain HTTP on loopback is fine.
    let mut c = ConfigV1::test_scaffold();
    c.api.enabled = true;
    c.api.token_hash = Some("a".repeat(64));
    let mut errs = Vec::new();
    check_api(&c, &mut errs, &mut AuditWarnings::emitting());
    assert!(errs.is_empty(), "{errs:?}");
}

#[test]
fn api_enabled_nonloopback_without_tls_errors() {
    // api-auth-07-01: cleartext bearer tokens off-host are refused.
    // 0.0.0.0 (unspecified) counts as non-loopback.
    for listen in ["10.0.0.1:8053", "0.0.0.0:8053", "[::]:8053"] {
        let mut c = ConfigV1::test_scaffold();
        c.api.enabled = true;
        c.api.token_hash = Some("a".repeat(64));
        c.api.listen = listen.parse().unwrap();
        let mut errs = Vec::new();
        check_api(&c, &mut errs, &mut AuditWarnings::emitting());
        assert_eq!(errs.len(), 1, "listen {listen}: {errs:?}");
        assert!(errs[0].to_string().contains("non-loopback"));
    }
}

#[test]
fn api_enabled_nonloopback_with_tls_ok() {
    let mut c = ConfigV1::test_scaffold();
    c.api.enabled = true;
    c.api.token_hash = Some("a".repeat(64));
    c.api.listen = "10.0.0.1:8053".parse().unwrap();
    c.api.tls_cert = Some("/etc/warden/api.crt".into());
    c.api.tls_key = Some("/etc/warden/api.key".into());
    let mut errs = Vec::new();
    check_api(&c, &mut errs, &mut AuditWarnings::emitting());
    assert!(errs.is_empty(), "{errs:?}");
}

#[test]
fn api_metrics_on_public_warns_not_errors() {
    // rev-2606 §07 addendum: `metrics_enabled` + non-loopback (with TLS set,
    // so the cleartext rule passes) is a posture WARN, not a hard error —
    // `check_api` must still validate clean. The warn is an audit-log
    // side-effect (like cidr-02); here we pin that it does NOT block boot.
    let mut c = ConfigV1::test_scaffold();
    c.api.enabled = true;
    c.api.token_hash = Some("a".repeat(64));
    c.api.metrics_enabled = true;
    c.api.listen = "10.0.0.1:8053".parse().unwrap();
    c.api.tls_cert = Some("/etc/warden/api.crt".into());
    c.api.tls_key = Some("/etc/warden/api.key".into());
    let mut errs = Vec::new();
    check_api(&c, &mut errs, &mut AuditWarnings::emitting());
    assert!(
        errs.is_empty(),
        "metrics on a public TLS bind must WARN, not refuse: {errs:?}"
    );
}

#[test]
fn api_tls_half_pair_errors_either_direction() {
    // A half pair silently degrades to plain HTTP — rejected even on
    // loopback (the operator clearly intended TLS).
    for (cert, key, missing) in [
        (Some("/etc/warden/api.crt"), None, "tls_key"),
        (None, Some("/etc/warden/api.key"), "tls_cert"),
    ] {
        let mut c = ConfigV1::test_scaffold();
        c.api.enabled = true;
        c.api.token_hash = Some("a".repeat(64));
        c.api.tls_cert = cert.map(Into::into);
        c.api.tls_key = key.map(Into::into);
        let mut errs = Vec::new();
        check_api(&c, &mut errs, &mut AuditWarnings::emitting());
        assert_eq!(errs.len(), 1, "missing {missing}: {errs:?}");
        assert!(errs[0].to_string().contains("set together"));
    }
}

#[test]
fn api_enabled_valid_config_validates() {
    // Full-validator integration: a complete, enabled [api] passes.
    let mut c = basic_config();
    c.api.enabled = true;
    c.api.token_hash = Some("c".repeat(64));
    assert!(validate(&c, now()).is_ok(), "{:?}", validate(&c, now()));
}

#[test]
fn api_enabled_no_token_fails_full_validate() {
    // The rule is wired into `validate()`, not just unit-reachable.
    let mut c = basic_config();
    c.api.enabled = true;
    let errs = validate(&c, now()).unwrap_err();
    assert!(errs
        .iter()
        .any(|e| matches!(e, ConfigError::MissingRequired(_)) && e.to_string().contains("api")));
}

// ── schema_version ────────────────────────────────────

#[test]
fn schema_version_0_rejected() {
    let mut c = basic_config();
    c.schema_version = 0;
    let errs = validate(&c, now()).unwrap_err();
    assert!(errs
        .iter()
        .any(|e| matches!(e, ConfigError::VersionMismatch(_))));
}

#[test]
fn schema_version_1_rejected() {
    // Sprint A of `lists_categories_v2` bumped SCHEMA_VERSION_V1
    // from 1 to 2 (Q4 + D15). The validator now refuses configs
    // declaring `schema_version = 1` — operators run
    // `warden migrate` to upgrade.
    let mut c = basic_config();
    c.schema_version = 1;
    let errs = validate(&c, now()).unwrap_err();
    assert!(errs
        .iter()
        .any(|e| matches!(e, ConfigError::VersionMismatch(_))));
}

// ── duplicate id per entity kind ─────────────────────

#[test]
fn duplicate_blocklist_id_rejected() {
    let mut c = basic_config();
    c.blocklists.push(blocklist("privacy-ads"));
    let errs = validate(&c, now()).unwrap_err();
    assert!(errs
        .iter()
        .any(|e| matches!(e, ConfigError::DuplicateId(ctx) if ctx.reason.contains("privacy-ads"))));
}

#[test]
fn duplicate_device_id_rejected() {
    let mut c = basic_config();
    c.devices
        .push(device("iphone", "10.0.0.1", Some("default")));
    c.devices
        .push(device("iphone", "10.0.0.2", Some("default")));
    let errs = validate(&c, now()).unwrap_err();
    assert!(errs
        .iter()
        .any(|e| matches!(e, ConfigError::DuplicateId(_))));
}

// ── cross-ref misses ──────────────────────────────────

#[test]
fn device_referencing_unknown_profile_rejected() {
    let mut c = basic_config();
    c.devices.push(device("iphone", "10.0.0.1", Some("ghost")));
    let errs = validate(&c, now()).unwrap_err();
    assert!(errs
        .iter()
        .any(|e| matches!(e, ConfigError::CrossRefMiss(ctx) if ctx.reason.contains("ghost"))));
}

// Sprint B T2 (rewireato — drop with justification): the pre-v2
// `profile_referencing_unknown_blocklist_rejected` test pinned the
// dangling-id refusal on `profile.blocklists`. That field is gone in
// v2 and the tag-intersection model has no structural equivalent —
// a tag that no list happens to carry is harmless and surfaces, if
// anything, as the §5.4 row 2 reload-time WARN
// (`PROFILE_CONTRIBUTES_NO_TAGS`) handled in T3. Sibling cross-ref
// checks (`group_referencing_unknown_device_rejected`,
// `subnet_referencing_unknown_profile_rejected`, etc.) preserve
// CrossRef coverage on every other entity.

#[test]
fn group_referencing_unknown_device_rejected() {
    let mut c = basic_config();
    c.groups.push(group("family", "default", 0, &["iphone"]));
    let errs = validate(&c, now()).unwrap_err();
    assert!(errs
        .iter()
        .any(|e| matches!(e, ConfigError::CrossRefMiss(_))));
}

#[test]
fn subnet_referencing_unknown_profile_rejected() {
    let mut c = basic_config();
    c.subnets.push(Subnet {
        id: Id::new("vlan").unwrap(),
        display_name: "VLAN".into(),
        cidrs: vec!["10.0.0.0/8".into()],
        profile: Id::new("ghost").unwrap(),
        priority: 0,
    });
    let errs = validate(&c, now()).unwrap_err();
    assert!(errs
        .iter()
        .any(|e| matches!(e, ConfigError::CrossRefMiss(_))));
}

// ── rev-2606 schema-validator-08: duplicate subnet CIDRs ──────

fn test_subnet(id: &str, cidr: &str, profile: &str, priority: i32) -> Subnet {
    Subnet {
        id: Id::new(id).unwrap(),
        display_name: id.into(),
        cidrs: vec![cidr.into()],
        profile: Id::new(profile).unwrap(),
        priority,
    }
}

#[test]
fn duplicate_cidr_equal_priority_different_profiles_rejected() {
    let mut c = basic_config();
    c.profiles.insert("strict".into(), profile_default());
    c.subnets
        .push(test_subnet("lan-a", "10.0.0.0/24", "default", 10));
    c.subnets
        .push(test_subnet("lan-b", "10.0.0.0/24", "strict", 10));
    let errs = validate(&c, now()).unwrap_err();
    assert!(
        errs.iter().any(|e| matches!(
            e,
            ConfigError::ValidationFailed(ctx)
                if ctx.reason.contains("declared by multiple subnets")
                   && ctx.reason.contains("lan-a")
                   && ctx.reason.contains("lan-b")
        )),
        "ambiguous duplicate CIDR must be rejected: {errs:?}"
    );
}

#[test]
fn duplicate_cidr_normalized_before_compare() {
    // Host bits are masked by Cidr::parse — different spellings of
    // the same network still collide.
    let mut c = basic_config();
    c.profiles.insert("strict".into(), profile_default());
    c.subnets
        .push(test_subnet("lan-a", "10.0.0.0/24", "default", 0));
    c.subnets
        .push(test_subnet("lan-b", "10.0.0.99/24", "strict", 0));
    let errs = validate(&c, now()).unwrap_err();
    assert!(
        errs.iter().any(|e| matches!(
            e,
            ConfigError::ValidationFailed(ctx)
                if ctx.reason.contains("declared by multiple subnets")
        )),
        "normalized-equal CIDRs must collide: {errs:?}"
    );
}

#[test]
fn duplicate_cidr_distinct_priorities_accepted() {
    // Deliberate overlay: higher priority deterministically wins.
    let mut c = basic_config();
    c.profiles.insert("strict".into(), profile_default());
    c.subnets
        .push(test_subnet("lan-a", "10.0.0.0/24", "default", 10));
    c.subnets
        .push(test_subnet("lan-b", "10.0.0.0/24", "strict", 20));
    assert!(validate(&c, now()).is_ok());
}

#[test]
fn duplicate_cidr_same_profile_accepted() {
    // Harmless redundancy — no ambiguity to resolve.
    let mut c = basic_config();
    c.subnets
        .push(test_subnet("lan-a", "10.0.0.0/24", "default", 10));
    c.subnets
        .push(test_subnet("lan-b", "10.0.0.0/24", "default", 10));
    assert!(validate(&c, now()).is_ok());
}

// ── rev-2606 schema-validator-11: display_name / free-text bounds ──

#[test]
fn empty_display_name_rejected_per_entity() {
    // Device / Group / Subnet / Schedule require a non-blank
    // display_name (the blocklist arm predates this and keeps its
    // own frozen message).
    let mut c = basic_config();
    let mut d = device("phone", "10.0.0.1", Some("default"));
    d.display_name = "   ".into();
    c.devices.push(d);
    let mut g = group("iot", "default", 0, &[]);
    g.display_name = String::new();
    c.groups.push(g);
    let errs = validate(&c, now()).unwrap_err();
    for entity in ["devices.phone", "groups.iot"] {
        assert!(
            errs.iter().any(|e| matches!(
                e,
                ConfigError::MissingRequired(ctx)
                    if ctx.entity.as_deref() == Some(entity)
                       && ctx.reason.contains("display_name")
            )),
            "missing empty-display_name error for {entity}: {errs:?}"
        );
    }
}

#[test]
fn empty_profile_display_name_accepted() {
    // Profile.display_name has #[serde(default)] — an omitted field
    // deserialises to "" and must stay legal.
    let mut c = basic_config();
    let mut p = profile_default();
    p.display_name = String::new();
    c.profiles.insert("bare".into(), p);
    assert!(validate(&c, now()).is_ok());
}

#[test]
fn oversized_display_name_rejected() {
    let mut c = basic_config();
    let mut d = device("phone", "10.0.0.1", Some("default"));
    d.display_name = "x".repeat(129);
    c.devices.push(d);
    let errs = validate(&c, now()).unwrap_err();
    assert!(
        errs.iter().any(|e| matches!(
            e,
            ConfigError::ValidationFailed(ctx)
                if ctx.entity.as_deref() == Some("devices.phone")
                   && ctx.reason.contains("129 bytes (max 128)")
        )),
        "{errs:?}"
    );
}

#[test]
fn control_chars_in_display_name_rejected() {
    // ANSI escape into a TUI row / journal line = terminal
    // injection surface.
    let mut c = basic_config();
    let mut d = device("phone", "10.0.0.1", Some("default"));
    d.display_name = "evil\x1b[2Jname".into();
    c.devices.push(d);
    let errs = validate(&c, now()).unwrap_err();
    assert!(
        errs.iter().any(|e| matches!(
            e,
            ConfigError::ValidationFailed(ctx)
                if ctx.entity.as_deref() == Some("devices.phone")
                   && ctx.reason.contains("control character")
        )),
        "{errs:?}"
    );
}

#[test]
fn device_free_text_bounds_enforced() {
    let mut c = basic_config();
    let mut d = device("phone", "10.0.0.1", Some("default"));
    d.notes = Some("n".repeat(1025));
    d.owner = Some("ed\nwardo".into());
    c.devices.push(d);
    let errs = validate(&c, now()).unwrap_err();
    assert!(
        errs.iter().any(|e| matches!(
            e,
            ConfigError::ValidationFailed(ctx)
                if ctx.reason.contains("notes") && ctx.reason.contains("max 1024")
        )),
        "oversized notes must be rejected: {errs:?}"
    );
    assert!(
        errs.iter().any(|e| matches!(
            e,
            ConfigError::ValidationFailed(ctx)
                if ctx.reason.contains("owner") && ctx.reason.contains("control character")
        )),
        "newline in owner must be rejected: {errs:?}"
    );
    // Absent / sane free-text stays legal.
    let mut ok = basic_config();
    let mut d2 = device("tab", "10.0.0.2", Some("default"));
    d2.notes = Some("bought 2024, lives in the kitchen".into());
    ok.devices.push(d2);
    assert!(validate(&ok, now()).is_ok());
}

#[test]
fn schedule_device_target_checked_against_devices_only() {
    let mut c = basic_config();
    // A group called `kids` exists — schedule with target_type=device
    // must still reject because there is no DEVICE called kids.
    c.groups.push(group("kids", "default", 0, &[]));
    c.schedules.push(Schedule {
        id: Id::new("focus").unwrap(),
        display_name: "focus".into(),
        target_type: ScheduleTargetType::Device,
        target_id: Id::new("kids").unwrap(),
        profile: Id::new("default").unwrap(),
        days: vec!["all".into()],
        hours: "22:00-06:00".into(),
        expires_at: None,
    });
    let errs = validate(&c, now()).unwrap_err();
    assert!(errs
        .iter()
        .any(|e| matches!(e, ConfigError::CrossRefMiss(ctx) if ctx.reason.contains("kids"))));
}

// ── schedule semantics ────────────────────────────────

#[test]
fn schedule_invalid_days_rejected() {
    let mut c = basic_config();
    c.devices.push(device("edo", "10.0.0.1", Some("default")));
    c.schedules.push(Schedule {
        id: Id::new("x").unwrap(),
        display_name: "x".into(),
        target_type: ScheduleTargetType::Device,
        target_id: Id::new("edo").unwrap(),
        profile: Id::new("default").unwrap(),
        days: vec!["baday".into()],
        hours: "09:00-17:00".into(),
        expires_at: None,
    });
    let errs = validate(&c, now()).unwrap_err();
    assert!(errs
        .iter()
        .any(|e| matches!(e, ConfigError::ValidationFailed(ctx) if ctx.reason.contains("days"))));
}

#[test]
fn schedule_invalid_hours_rejected() {
    let mut c = basic_config();
    c.devices.push(device("edo", "10.0.0.1", Some("default")));
    c.schedules.push(Schedule {
        id: Id::new("x").unwrap(),
        display_name: "x".into(),
        target_type: ScheduleTargetType::Device,
        target_id: Id::new("edo").unwrap(),
        profile: Id::new("default").unwrap(),
        days: vec!["all".into()],
        hours: "bad".into(),
        expires_at: None,
    });
    let errs = validate(&c, now()).unwrap_err();
    assert!(errs
        .iter()
        .any(|e| matches!(e, ConfigError::ValidationFailed(ctx) if ctx.reason.contains("hours"))));
}

#[test]
fn schedule_past_expiry_accepted_as_inert() {
    // rev-2606 schema-validator-01 regression: an expired one-shot
    // schedule on disk must NOT fail validation — the old hard error
    // bricked boot, reload, and every CLI mutation the moment a
    // `warden device quiet` window lapsed. The row is inert at
    // resolver build and gets pruned; validation only WARNs.
    let mut c = basic_config();
    c.devices.push(device("edo", "10.0.0.1", Some("default")));
    c.schedules.push(Schedule {
        id: Id::new("x").unwrap(),
        display_name: "x".into(),
        target_type: ScheduleTargetType::Device,
        target_id: Id::new("edo").unwrap(),
        profile: Id::new("default").unwrap(),
        days: vec!["all".into()],
        hours: "22:00-06:00".into(),
        expires_at: Some(datetime!(2020-01-01 00:00:00 UTC)),
    });
    validate(&c, now()).expect("expired schedule must not fail validation");
}

#[test]
fn schedule_future_expiry_accepted() {
    let mut c = basic_config();
    c.devices.push(device("edo", "10.0.0.1", Some("default")));
    c.schedules.push(Schedule {
        id: Id::new("x").unwrap(),
        display_name: "x".into(),
        target_type: ScheduleTargetType::Device,
        target_id: Id::new("edo").unwrap(),
        profile: Id::new("default").unwrap(),
        days: vec!["all".into()],
        hours: "22:00-06:00".into(),
        expires_at: Some(datetime!(2999-01-01 00:00:00 UTC)),
    });
    validate(&c, now()).expect("future expiry is a valid one-shot schedule");
}

#[test]
fn schedule_all_day_midnight_form_accepted() {
    // rev-2606 devices-01: `00:00-00:00` is the engine's canonical
    // always-on window (res-13 carve-out in ParsedSchedule::parse_v1)
    // and what `warden device quiet` writes — the validator must
    // mirror the engine, not reject the one form that has no
    // end-exclusivity hole.
    let mut c = basic_config();
    c.devices.push(device("edo", "10.0.0.1", Some("default")));
    c.schedules.push(Schedule {
        id: Id::new("x").unwrap(),
        display_name: "x".into(),
        target_type: ScheduleTargetType::Device,
        target_id: Id::new("edo").unwrap(),
        profile: Id::new("default").unwrap(),
        days: vec!["all".into()],
        hours: "00:00-00:00".into(),
        expires_at: None,
    });
    validate(&c, now()).expect("00:00-00:00 is the canonical all-day form");
}

#[test]
fn schedule_other_equal_start_end_rejected_with_all_day_hint() {
    let mut c = basic_config();
    c.devices.push(device("edo", "10.0.0.1", Some("default")));
    c.schedules.push(Schedule {
        id: Id::new("x").unwrap(),
        display_name: "x".into(),
        target_type: ScheduleTargetType::Device,
        target_id: Id::new("edo").unwrap(),
        profile: Id::new("default").unwrap(),
        days: vec!["all".into()],
        hours: "09:00-09:00".into(),
        expires_at: None,
    });
    let errs = validate(&c, now()).unwrap_err();
    assert!(errs.iter().any(|e| matches!(
        e,
        ConfigError::ValidationFailed(ctx)
            if ctx.reason.contains("start and end are equal")
                && ctx.reason.contains("00:00-00:00")
    )));
}

// ── server.default_profile ────────────────────────────

#[test]
fn server_default_profile_unknown_rejected() {
    let mut c = basic_config();
    c.server.default_profile = Some(Id::new("ghost").unwrap());
    let errs = validate(&c, now()).unwrap_err();
    assert!(errs
        .iter()
        .any(|e| matches!(e, ConfigError::CrossRefMiss(_))));
}

// ── retired-id policy (N8) ────────────────────────────

#[test]
fn retired_id_reuse_within_window_blocked() {
    let mut c = basic_config();
    c.retired.push(RetiredEntry {
        id: Id::new("privacy-ads").unwrap(),
        entity_type: RetiredType::Blocklist,
        retired_at: datetime!(2026-04-01 00:00:00 UTC),
    });
    let errs = validate(&c, now()).unwrap_err();
    assert!(errs
        .iter()
        .any(|e| matches!(e, ConfigError::IdRecentlyRetired(_))));
}

#[test]
fn retired_id_reuse_past_window_allowed() {
    let mut c = basic_config();
    c.retired.push(RetiredEntry {
        id: Id::new("privacy-ads").unwrap(),
        entity_type: RetiredType::Blocklist,
        // 120 days ago at `now()` = before the 90-day window.
        retired_at: datetime!(2025-12-01 00:00:00 UTC),
    });
    assert!(validate(&c, now()).is_ok());
}

#[test]
fn retired_id_different_type_is_independent() {
    // Retiring a `device` named "default" does NOT block a profile
    // called "default" — the quarantine is per-entity-type.
    let mut c = basic_config();
    c.retired.push(RetiredEntry {
        id: Id::new("default").unwrap(),
        entity_type: RetiredType::Device,
        retired_at: datetime!(2026-04-01 00:00:00 UTC),
    });
    assert!(validate(&c, now()).is_ok());
}

// ── DM2 group priority conflicts ──────────────────────

#[test]
fn ambiguous_group_priority_rejected() {
    let mut c = basic_config();
    c.profiles.insert("strict".into(), profile_default());
    c.profiles.insert("lenient".into(), profile_default());
    c.devices.push(device("edo", "10.0.0.1", None));
    c.groups.push(group("a", "strict", 10, &["edo"]));
    c.groups.push(group("b", "lenient", 10, &["edo"]));
    let errs = validate(&c, now()).unwrap_err();
    assert!(errs.iter().any(
        |e| matches!(e, ConfigError::ValidationFailed(ctx) if ctx.reason.contains("same priority"))
    ));
}

#[test]
fn clear_priority_winner_accepted() {
    let mut c = basic_config();
    c.profiles.insert("strict".into(), profile_default());
    c.profiles.insert("lenient".into(), profile_default());
    c.devices.push(device("edo", "10.0.0.1", None));
    c.groups.push(group("a", "strict", 20, &["edo"]));
    c.groups.push(group("b", "lenient", 10, &["edo"]));
    assert!(validate(&c, now()).is_ok());
}

#[test]
fn ambiguous_priority_via_device_side_groups_rejected() {
    // rev-2606 schema-validator-04: the primary CLI join path writes
    // `[[devices]].groups`, which this check used to be blind to —
    // the exact conflict below linted clean and the resolver
    // tie-broke by id silently.
    let mut c = basic_config();
    c.profiles.insert("strict".into(), profile_default());
    c.profiles.insert("lenient".into(), profile_default());
    let mut d = device("edo", "10.0.0.1", None);
    d.groups = vec![Id::new("a").unwrap(), Id::new("b").unwrap()];
    c.devices.push(d);
    c.groups.push(group("a", "strict", 10, &[]));
    c.groups.push(group("b", "lenient", 10, &[]));
    let errs = validate(&c, now()).unwrap_err();
    assert!(
        errs.iter().any(|e| matches!(
            e,
            ConfigError::ValidationFailed(ctx)
                if ctx.reason.contains("same priority")
                   && ctx.entity.as_deref() == Some("devices.edo")
        )),
        "device-side membership conflict must be caught: {errs:?}"
    );
}

#[test]
fn ambiguous_priority_via_mixed_directions_rejected() {
    // One membership group-side, the other device-side — the union
    // must see both.
    let mut c = basic_config();
    c.profiles.insert("strict".into(), profile_default());
    c.profiles.insert("lenient".into(), profile_default());
    let mut d = device("edo", "10.0.0.1", None);
    d.groups = vec![Id::new("b").unwrap()];
    c.devices.push(d);
    c.groups.push(group("a", "strict", 10, &["edo"]));
    c.groups.push(group("b", "lenient", 10, &[]));
    let errs = validate(&c, now()).unwrap_err();
    assert!(
        errs.iter().any(|e| matches!(
            e,
            ConfigError::ValidationFailed(ctx) if ctx.reason.contains("same priority")
        )),
        "mixed-direction conflict must be caught: {errs:?}"
    );
}

#[test]
fn symmetric_membership_not_double_counted() {
    // A device listed in `g.devices` AND carrying the same group in
    // `d.groups` is ONE membership — no self-conflict, and a clean
    // config stays clean.
    let mut c = basic_config();
    c.profiles.insert("strict".into(), profile_default());
    let mut d = device("edo", "10.0.0.1", None);
    d.groups = vec![Id::new("a").unwrap()];
    c.devices.push(d);
    c.groups.push(group("a", "strict", 10, &["edo"]));
    assert!(validate(&c, now()).is_ok());
}

// ── rev-2606 schema-validator-07/-09 — WITHDRAWN at the plp cutover ──
//
// `typo_tagged_config_still_validates_ok` and its `slug()` helper lived
// here. The test built a config whose tags all missed and asserted
// `validate(...).is_ok()` — the WARN-only posture of the intersection
// diagnostics. Those diagnostics are gone, and `is_ok()` was true before
// they existed and stays true after: it never distinguished the emitting
// build from the silent one. Removed rather than left green, because a
// suite that keeps such a test reads as coverage of a rule nothing
// enforces.
//
// What the rule became is `PROFILE_FILTERS_NO_LISTS`, asserted
// positively — with a control arm — in
// `a_profile_that_ignores_every_list_is_warned_about`.

#[test]
fn dangling_device_side_group_ref_no_panic_in_conflict_check() {
    // A dangling gid in `d.groups` is a CrossRefMiss from
    // check_devices; the conflict check must skip it, not panic.
    let mut c = basic_config();
    let mut d = device("edo", "10.0.0.1", None);
    d.groups = vec![Id::new("ghost-group").unwrap()];
    c.devices.push(d);
    let errs = validate(&c, now()).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| matches!(e, ConfigError::CrossRefMiss(_))),
        "dangling group ref still reported: {errs:?}"
    );
}

// ── devices: identity + MAC ──────────────────────────

#[test]
fn device_with_no_identity_rejected() {
    let mut c = basic_config();
    c.devices.push(Device {
        id: Id::new("ghost").unwrap(),
        display_name: "ghost".into(),
        ip: None,
        mac: None,
        mac_aliases: vec![],
        profile: None,
        groups: vec![],
        owner: None,
        device_type: None,
        department: None,
        notes: None,
        allow_rules: vec![],
        deny_rules: vec![],
        override_profile_deny: false,
        unfiltered: false,
        network_name: None,
        network_name_wildcard: false,
    });
    let errs = validate(&c, now()).unwrap_err();
    assert!(errs.iter().any(
        |e| matches!(e, ConfigError::ValidationFailed(ctx) if ctx.reason.contains("no identity"))
    ));
}

#[test]
fn duplicate_ip_rejected() {
    let mut c = basic_config();
    c.devices.push(device("a", "10.0.0.1", Some("default")));
    c.devices.push(device("b", "10.0.0.1", Some("default")));
    let errs = validate(&c, now()).unwrap_err();
    assert!(errs.iter().any(
        |e| matches!(e, ConfigError::ValidationFailed(ctx) if ctx.reason.contains("reuses IP"))
    ));
}

#[test]
fn shared_mac_across_devices_rejected() {
    let mut c = basic_config();
    c.devices.push(Device {
        id: Id::new("a").unwrap(),
        display_name: "A".into(),
        ip: None,
        mac: Some("AA:BB:CC:DD:EE:01".into()),
        mac_aliases: vec![],
        profile: Some(Id::new("default").unwrap()),
        ..device("a", "10.0.0.1", Some("default"))
    });
    c.devices[0].ip = None;
    c.devices.push(Device {
        id: Id::new("b").unwrap(),
        display_name: "B".into(),
        ip: None,
        mac: Some("aa:bb:cc:dd:ee:01".into()),
        mac_aliases: vec![],
        profile: Some(Id::new("default").unwrap()),
        ..device("b", "10.0.0.2", Some("default"))
    });
    c.devices[1].ip = None;
    let errs = validate(&c, now()).unwrap_err();
    assert!(errs.iter().any(
        |e| matches!(e, ConfigError::ValidationFailed(ctx) if ctx.reason.contains("already owned"))
    ));
}

// ── server.default_blocked_ttl_secs sanity ────────────

#[test]
fn server_default_ttl_zero_rejected() {
    let mut c = basic_config();
    c.server.default_blocked_ttl_secs = 0;
    let errs = validate(&c, now()).unwrap_err();
    assert!(errs
        .iter()
        .any(|e| matches!(e, ConfigError::ValidationFailed(ctx) if ctx.reason.contains("default_blocked_ttl_secs"))));
}

// ── server.listen × server.allow_from open-resolver gate ──────
// rev-2606 init-01: the unspecified-bind + empty-ACL combination is
// an open resolver (the DNS handler accepts ALL sources on an empty
// ACL). These pins keep the three "the validator already refuses"
// comments (dns/handler.rs, start.rs ×2) true.

#[test]
fn unspecified_bind_with_empty_allow_from_rejected() {
    let mut c = basic_config();
    c.server.listen = "0.0.0.0:53".parse().unwrap();
    c.server.allow_from = vec![];
    let errs = validate(&c, now()).unwrap_err();
    assert!(errs.iter().any(
        |e| matches!(e, ConfigError::ValidationFailed(ctx) if ctx.reason.contains("open resolver"))
    ));
}

#[test]
fn unspecified_v6_bind_with_empty_allow_from_rejected() {
    let mut c = basic_config();
    c.server.listen = "[::]:53".parse().unwrap();
    c.server.allow_from = vec![];
    let errs = validate(&c, now()).unwrap_err();
    assert!(errs.iter().any(
        |e| matches!(e, ConfigError::ValidationFailed(ctx) if ctx.reason.contains("open resolver"))
    ));
}

/// rev-detect F1, adjacent consequence. `::ffff:0.0.0.0` is the
/// IPv4-mapped spelling of the wildcard. The kernel binds it as one
/// — proved by binding it and then receiving a datagram addressed to
/// a specific host address — but `Ipv6Addr::is_unspecified()` is
/// false for it, because its octets are not all zero.
///
/// So this exact config used to validate clean: warden answered on
/// every interface, from every source, with no ACL. An open resolver
/// is a DNS amplification vector, which makes this the more
/// dangerous half of the same root cause.
#[test]
fn ipv4_mapped_unspecified_bind_with_empty_allow_from_rejected() {
    let mut c = basic_config();
    c.server.listen = "[::ffff:0.0.0.0]:53".parse().unwrap();
    c.server.allow_from = vec![];
    let errs = validate(&c, now()).unwrap_err();
    assert!(errs
        .iter()
        .any(|e| matches!(e, ConfigError::ValidationFailed(ctx) if ctx.reason.contains("open resolver"))),
        "a mapped-form wildcard binds every interface exactly as 0.0.0.0 does; got {errs:?}");
}

/// Control arm: the mapped form of a SPECIFIC address is not a
/// wildcard and must stay legal with an empty ACL, exactly as its
/// plain form does. Without this the fix above could be "reject
/// anything IPv4-mapped", which would break a legitimate bind.
#[test]
fn ipv4_mapped_specific_bind_with_empty_allow_from_stays_legal() {
    let mut c = basic_config();
    c.server.listen = "[::ffff:192.0.2.53]:53".parse().unwrap();
    c.server.allow_from = vec![];
    let res = validate(&c, now());
    if let Err(errs) = res {
        assert!(
            !errs.iter().any(|e| matches!(
                e,
                ConfigError::ValidationFailed(ctx) if ctx.reason.contains("open resolver")
            )),
            "a pinned address is not an open resolver, mapped or not; got {errs:?}"
        );
    }
}

#[test]
fn unspecified_bind_with_allow_from_accepted() {
    let mut c = basic_config();
    c.server.listen = "0.0.0.0:53".parse().unwrap();
    c.server.allow_from = vec!["192.168.1.0/24".into(), "127.0.0.0/8".into()];
    assert!(validate(&c, now()).is_ok());
}

#[test]
fn unspecified_bind_with_explicit_allow_all_accepted() {
    // Answering everyone is a deliberate opt-in, not a refusal.
    let mut c = basic_config();
    c.server.listen = "0.0.0.0:53".parse().unwrap();
    c.server.allow_from = vec!["0.0.0.0/0".into(), "::/0".into()];
    assert!(validate(&c, now()).is_ok());
}

#[test]
fn loopback_bind_with_empty_allow_from_accepted() {
    let mut c = basic_config();
    c.server.listen = "127.0.0.1:15353".parse().unwrap();
    c.server.allow_from = vec![];
    assert!(validate(&c, now()).is_ok());
}

// ── blocklist sanity ──────────────────────────────────

#[test]
fn blocklist_missing_scheme_rejected() {
    let mut c = basic_config();
    c.blocklists[0].url = "lists.example.com/a.txt".into();
    let errs = validate(&c, now()).unwrap_err();
    assert!(errs.iter().any(
        |e| matches!(e, ConfigError::ValidationFailed(ctx) if ctx.reason.contains("http://"))
    ));
}

#[test]
fn blocklist_zero_update_interval_rejected() {
    let mut c = basic_config();
    c.blocklists[0].update_interval_hours = 0;
    let errs = validate(&c, now()).unwrap_err();
    assert!(errs
        .iter()
        .any(|e| matches!(e, ConfigError::ValidationFailed(ctx) if ctx.reason.contains("update_interval_hours"))));
}

// ── deny_unknown_fields walker ───────────────────────

#[test]
fn every_schema_struct_denies_unknown_fields() {
    // We probe each struct by deserialising a TOML payload that is
    // legal for the struct's required fields plus ONE extra field
    // that should not exist. If the struct forgot
    // `#[serde(deny_unknown_fields)]`, the probe succeeds and the
    // test fails with a clear message naming the offender.
    //
    // NOTE: when a new entity is added in a future sprint, remember
    // to extend this list. The cost of forgetting is a typo in a
    // real operator's config being silently ignored.
    let cases: &[(&str, &str)] = &[
        (
            "ConfigV1",
            "schema_version = 3\nextra = true\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        ),
        (
            "ServerGlobals (inside ConfigV1)",
            "schema_version = 3\n[server]\nextra_field = 1\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        ),
        (
            "Blocklist",
            "id = \"x\"\ndisplay_name = \"x\"\nurl = \"https://example.com/\"\nextra = 1\n",
        ),
        (
            "Profile",
            "display_name = \"x\"\nextra = 1\n",
        ),
        (
            "Device",
            "id = \"x\"\ndisplay_name = \"x\"\nextra = 1\n",
        ),
        (
            "Group",
            "id = \"x\"\ndisplay_name = \"x\"\nprofile = \"p\"\nextra = 1\n",
        ),
        (
            "Subnet",
            "id = \"x\"\ndisplay_name = \"x\"\ncidrs = [\"10.0.0.0/8\"]\nprofile = \"p\"\nextra = 1\n",
        ),
        (
            "Schedule",
            "id = \"x\"\ndisplay_name = \"x\"\ntarget_type = \"device\"\ntarget_id = \"d\"\nprofile = \"p\"\ndays = [\"all\"]\nhours = \"00:00-23:59\"\nextra = 1\n",
        ),
        (
            "AdminRule",
            "id = \"x\"\nrule = \"||x^\"\nextra = 1\n",
        ),
        (
            "RetiredEntry",
            "id = \"x\"\ntype = \"device\"\nretired_at = \"2026-04-01T00:00:00Z\"\nextra = 1\n",
        ),
    ];

    use super::super::admin_rule::AdminRule as AR;
    use super::super::blocklist::Blocklist as BL;
    use super::super::device::Device as DV;
    use super::super::group::Group as GR;
    use super::super::profile::Profile as PR;
    use super::super::retired::RetiredEntry as RT;
    use super::super::schedule::Schedule as SC;
    use super::super::subnet::Subnet as SN;

    let mut failures: Vec<String> = Vec::new();

    for (name, src) in cases {
        let accepts_unknown = match *name {
            "ConfigV1" => toml::from_str::<ConfigV1>(src).is_ok(),
            "ServerGlobals (inside ConfigV1)" => toml::from_str::<ConfigV1>(src).is_ok(),
            "Blocklist" => toml::from_str::<BL>(src).is_ok(),
            "Profile" => toml::from_str::<PR>(src).is_ok(),
            "Device" => toml::from_str::<DV>(src).is_ok(),
            "Group" => toml::from_str::<GR>(src).is_ok(),
            "Subnet" => toml::from_str::<SN>(src).is_ok(),
            "Schedule" => toml::from_str::<SC>(src).is_ok(),
            "AdminRule" => toml::from_str::<AR>(src).is_ok(),
            "RetiredEntry" => toml::from_str::<RT>(src).is_ok(),
            _ => unreachable!(),
        };
        if accepts_unknown {
            failures.push((*name).to_string());
        }
    }

    assert!(
        failures.is_empty(),
        "these schema structs accept unknown fields (missing #[serde(deny_unknown_fields)]?): {failures:?}"
    );
}

// ── Sprint 38 QLP3: [tracking] knobs ─────────────────────

fn has_entity(errs: &[ConfigError], entity: &str) -> bool {
    errs.iter().any(|e| match e {
        ConfigError::ValidationFailed(ctx) => ctx.entity.as_deref() == Some(entity),
        _ => false,
    })
}

#[test]
fn tracking_config_rejects_retention_days_out_of_range() {
    let mut c = basic_config();
    c.tracking.retention_days = 0;
    let errs = validate(&c, now()).unwrap_err();
    assert!(has_entity(&errs, "tracking.retention_days"));

    c.tracking.retention_days = 366;
    let errs = validate(&c, now()).unwrap_err();
    assert!(has_entity(&errs, "tracking.retention_days"));

    // Valid range endpoints pass.
    for ok in [1u32, 7, 365] {
        c.tracking.retention_days = ok;
        assert!(
            validate(&c, now()).is_ok(),
            "retention_days = {ok} should pass"
        );
    }
}

// ── rev-2606 settings-02 — zero intervals abort the daemon ───

#[test]
fn tracking_zero_intervals_rejected() {
    let mut c = basic_config();
    c.tracking.top_n_interval_secs = 0;
    let errs = validate(&c, now()).unwrap_err();
    assert!(has_entity(&errs, "tracking.top_n_interval_secs"));

    c.tracking.top_n_interval_secs = 1;
    c.tracking.snapshot_interval_secs = 0;
    let errs = validate(&c, now()).unwrap_err();
    assert!(has_entity(&errs, "tracking.snapshot_interval_secs"));

    c.tracking.snapshot_interval_secs = 1;
    assert!(validate(&c, now()).is_ok(), "1-second intervals are valid");
}

#[test]
fn lists_zero_update_interval_rejected() {
    let mut c = basic_config();
    c.lists.update_interval_secs = 0;
    let errs = validate(&c, now()).unwrap_err();
    assert!(has_entity(&errs, "lists.update_interval_secs"));

    c.lists.update_interval_secs = 1;
    assert!(
        validate(&c, now()).is_ok(),
        "update_interval_secs = 1 is valid"
    );
}

#[test]
fn lists_shrink_guard_pct_out_of_range_rejected() {
    // rev-2606 §06 manager-01: 0 and >100 are misconfigurations.
    let mut c = basic_config();
    for bad in [0u8, 101, 255] {
        c.lists.shrink_guard_max_drop_pct = bad;
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            has_entity(&errs, "lists.shrink_guard_max_drop_pct"),
            "shrink_guard_max_drop_pct = {bad} should be rejected"
        );
    }
    for ok in [1u8, 90, 100] {
        c.lists.shrink_guard_max_drop_pct = ok;
        assert!(
            validate(&c, now()).is_ok(),
            "shrink_guard_max_drop_pct = {ok} is valid"
        );
    }
}

// ── rev-2606 config-01 / settings-12 — [security] scalars ────

#[test]
fn security_rrl_zero_rps_rejected() {
    let mut c = basic_config();
    c.security.rrl.responses_per_second = 0;
    let errs = validate(&c, now()).unwrap_err();
    assert!(has_entity(&errs, "security.rrl.responses_per_second"));

    c.security.rrl.responses_per_second = 1;
    assert!(validate(&c, now()).is_ok());
}

#[test]
fn security_rrl_window_out_of_range_rejected() {
    let mut c = basic_config();
    for bad in [0u64, 86_401, (u32::MAX as u64) + 16] {
        c.security.rrl.window_secs = bad;
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            has_entity(&errs, "security.rrl.window_secs"),
            "window_secs = {bad} should be rejected"
        );
    }
    for ok in [1u64, 15, 86_400] {
        c.security.rrl.window_secs = ok;
        assert!(validate(&c, now()).is_ok(), "window_secs = {ok} is valid");
    }
}

#[test]
fn security_rate_limit_zeroes_rejected() {
    let mut c = basic_config();
    c.security.rate_limit.queries_per_second = 0;
    let errs = validate(&c, now()).unwrap_err();
    assert!(has_entity(&errs, "security.rate_limit.queries_per_second"));

    c.security.rate_limit.queries_per_second = 1;
    c.security.rate_limit.burst = 0;
    let errs = validate(&c, now()).unwrap_err();
    assert!(has_entity(&errs, "security.rate_limit.burst"));

    c.security.rate_limit.burst = 1;
    assert!(validate(&c, now()).is_ok());
}

#[test]
fn security_tunneling_invalid_entropy_rejected() {
    let mut c = basic_config();
    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, 0.0, -3.5] {
        c.security.tunneling.entropy_threshold = bad;
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            has_entity(&errs, "security.tunneling.entropy_threshold"),
            "entropy_threshold = {bad} should be rejected"
        );
    }
    // Large finite values are a legitimate way to soften the heuristic.
    for ok in [0.1, 3.5, 100.0] {
        c.security.tunneling.entropy_threshold = ok;
        assert!(
            validate(&c, now()).is_ok(),
            "entropy_threshold = {ok} is valid"
        );
    }
}

#[test]
fn security_tunneling_zero_integers_rejected() {
    let mut c = basic_config();
    c.security.tunneling.label_len_threshold = 0;
    let errs = validate(&c, now()).unwrap_err();
    assert!(has_entity(&errs, "security.tunneling.label_len_threshold"));

    c.security.tunneling.label_len_threshold = 1;
    c.security.tunneling.subdomain_rate = 0;
    let errs = validate(&c, now()).unwrap_err();
    assert!(has_entity(&errs, "security.tunneling.subdomain_rate"));

    c.security.tunneling.subdomain_rate = 1;
    c.security.tunneling.window_secs = 0;
    let errs = validate(&c, now()).unwrap_err();
    assert!(has_entity(&errs, "security.tunneling.window_secs"));

    c.security.tunneling.window_secs = 1;
    c.security.tunneling.max_unbroken_run = 0;
    let errs = validate(&c, now()).unwrap_err();
    assert!(has_entity(&errs, "security.tunneling.max_unbroken_run"));

    c.security.tunneling.max_unbroken_run = 1;
    c.security.tunneling.entropy_min_len = 0;
    let errs = validate(&c, now()).unwrap_err();
    assert!(has_entity(&errs, "security.tunneling.entropy_min_len"));

    c.security.tunneling.entropy_min_len = 1;
    assert!(validate(&c, now()).is_ok());
}

/// `exempt_domains` disarms checks that run before the filter engine,
/// so a bad entry cannot be narrowed downstream. Malformed and bare-TLD
/// entries are refused; a whole registrable domain is allowed but
/// warned. Both arms asserted — a test that only checks the rejections
/// would also pass against a validator that rejects everything.
#[test]
fn security_tunneling_exempt_domains_gated() {
    let mut c = basic_config();

    for bad in ["", "   ", ".", "..", "exam ple.com"] {
        c.security.tunneling.exempt_domains = vec![bad.to_string()];
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            has_entity(&errs, "security.tunneling.exempt_domains"),
            "malformed entry {bad:?} must be refused"
        );
    }

    // A bare TLD is `enabled = false` in disguise.
    c.security.tunneling.exempt_domains = vec!["com".to_string()];
    let errs = validate(&c, now()).unwrap_err();
    assert!(has_entity(&errs, "security.tunneling.exempt_domains"));

    // Two labels: legal, the operator's call, but warned every load.
    c.security.tunneling.exempt_domains = vec!["a2z.com".to_string()];
    assert!(validate(&c, now()).is_ok());

    // Deeper entries are the narrow, encouraged form — no warning.
    c.security.tunneling.exempt_domains = vec![
        "minerva.devices.a2z.com".to_string(),
        "x.y.example.org".to_string(),
    ];
    assert!(validate(&c, now()).is_ok());
}

/// The exemption gates ride the section's `enabled` flag like every
/// other tunneling gate — a stale entry in a disabled section must not
/// brick the config.
#[test]
fn security_tunneling_exempt_gates_scoped_to_enabled() {
    let mut c = basic_config();
    c.security.tunneling.enabled = false;
    c.security.tunneling.exempt_domains = vec!["com".to_string(), String::new()];
    assert!(validate(&c, now()).is_ok());
}

/// Disabled sections are inert: stale zero values in a section the
/// operator turned off must not brick the config (backward compat —
/// the gate fires when the value starts mattering).
#[test]
fn security_gates_scoped_to_enabled_flags() {
    let mut c = basic_config();
    c.security.rrl.responses_per_second = 0;
    c.security.rate_limit.burst = 0;
    c.security.tunneling.entropy_threshold = f64::NAN;

    c.security.rrl.enabled = false;
    c.security.rate_limit.enabled = false;
    c.security.tunneling.enabled = false;
    assert!(
        validate(&c, now()).is_ok(),
        "disabled sub-sections must not be validated"
    );

    // Master switch off ⇒ everything inert regardless of sub-flags.
    c.security.rrl.enabled = true;
    c.security.rate_limit.enabled = true;
    c.security.tunneling.enabled = true;
    c.security.enabled = false;
    assert!(
        validate(&c, now()).is_ok(),
        "security.enabled = false must skip every gate"
    );
}

// ── rev-2606 settings-11 / schema-validator-02 — [cache] ─────

#[test]
fn cache_inverted_ttl_pair_rejected() {
    let mut c = basic_config();
    c.cache.min_ttl_secs = 3601;
    c.cache.max_ttl_secs = 3600;
    let errs = validate(&c, now()).unwrap_err();
    assert!(has_entity(&errs, "cache.min_ttl_secs"));

    // min == max is a legitimate "pin every TTL" config.
    c.cache.min_ttl_secs = 3600;
    assert!(validate(&c, now()).is_ok(), "min == max is valid");
}

#[test]
fn dynamic_ttl_secs_zero_is_rejected() {
    let mut c = basic_config();
    c.local_dns.dynamic_ttl_secs = 0;
    let errs = validate(&c, now()).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.to_string().contains("dynamic_ttl_secs")),
        "expected a dynamic_ttl_secs error, got: {errs:?}"
    );
}

#[test]
fn cache_prefetch_threshold_out_of_range_rejected() {
    let mut c = basic_config();
    c.cache.prefetch = true;
    for bad in [f64::NAN, f64::INFINITY, 0.0, -0.1, 1.0, 1.5] {
        c.cache.prefetch_threshold = bad;
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            has_entity(&errs, "cache.prefetch_threshold"),
            "prefetch_threshold = {bad} should be rejected"
        );
    }
    for ok in [0.01, 0.1, 0.99] {
        c.cache.prefetch_threshold = ok;
        assert!(
            validate(&c, now()).is_ok(),
            "prefetch_threshold = {ok} is valid"
        );
    }
    // Scoped to the enabled flag: junk is inert when prefetch is off.
    c.cache.prefetch = false;
    c.cache.prefetch_threshold = f64::NAN;
    assert!(
        validate(&c, now()).is_ok(),
        "prefetch = false must skip the threshold gate"
    );
}

#[test]
fn cache_stale_buffer_over_cap_rejected() {
    let mut c = basic_config();
    // Unset ⇒ default 300 ⇒ valid (basic_config()); the 24 h cap boundary
    // is accepted; one second over is refused.
    assert!(
        validate(&c, now()).is_ok(),
        "default stale_buffer_secs is valid"
    );
    c.cache.stale_buffer_secs = 86_400;
    assert!(validate(&c, now()).is_ok(), "86400 (the 24 h cap) is valid");

    c.cache.stale_buffer_secs = 86_401;
    let errs = validate(&c, now()).unwrap_err();
    assert!(has_entity(&errs, "cache.stale_buffer_secs"));
}

/// `0` is refused; above the clamp is only warned about.
///
/// The asymmetry is the point. At `0` every CNAME'd name stops resolving,
/// so loading the config is worse than refusing it. Above the clamp the
/// walkers already behave as `16`, so refusing would take a daemon down
/// over a config that resolves perfectly well.
#[test]
fn cache_cname_max_depth_zero_rejected_above_cap_warned() {
    let mut c = basic_config();
    assert!(
        validate(&c, now()).is_ok(),
        "the default cname_max_depth is valid"
    );

    c.cache.cname_max_depth = 0;
    let errs = validate(&c, now()).unwrap_err();
    assert!(has_entity(&errs, "cache.cname_max_depth"));

    c.cache.cname_max_depth = crate::filter::cname::MAX_HOPS + 8;
    assert!(
        validate(&c, now()).is_ok(),
        "above the clamp the config still LOADS — the clamp makes it safe"
    );
    let warns = warns_for(&c);
    assert!(
        warns.iter().any(|w| w.contains("clamp to 16 hops")),
        "but the operator is told the extra depth is never followed: {warns:?}"
    );

    for ok in [1, crate::filter::cname::MAX_HOPS] {
        c.cache.cname_max_depth = ok;
        assert!(
            validate(&c, now()).is_ok(),
            "cname_max_depth = {ok} is inside the range"
        );
        assert!(
            !warns_for(&c).iter().any(|w| w.contains("cname_max_depth")),
            "an in-range value must be silent"
        );
    }
}

/// The message spells the cap as a literal because a frozen string cannot
/// interpolate a constant. This is what keeps the two from drifting.
#[test]
fn cache_cname_max_depth_message_states_the_real_cap() {
    let cap = crate::filter::cname::MAX_HOPS.to_string();
    assert!(
        CACHE_CNAME_MAX_DEPTH_ABOVE_CAP.contains(&format!("clamp to {cap} hops")),
        "message must state the real cap ({cap}): {CACHE_CNAME_MAX_DEPTH_ABOVE_CAP}"
    );
    let got = format_cache_cname_max_depth_above_cap(99);
    assert!(got.contains("is 99,"));
    assert!(!got.contains("{n}"));
}

/// `Device.ip` is an `IpAddr`, so `::ffff:10.0.0.5` deserialises as a
/// `V6` and a raw key makes it a different device from `10.0.0.5`. The
/// mapped pin is then dead config: `devices_by_ip` never matches it, the
/// operator sees the device listed, and its queries fall through.
#[test]
fn mapped_and_bare_v4_pins_collide() {
    let mut c = basic_config();
    c.devices = vec![
        device("bare", "10.0.0.5", None),
        device("mapped", "::ffff:10.0.0.5", None),
    ];
    let errs = validate(&c, now()).unwrap_err();
    assert!(
        errs.iter().any(
            |e| matches!(e, ConfigError::ValidationFailed(ctx) if ctx.reason.contains("reuses IP"))
        ),
        "the two spellings of one host must collide, got: {errs:?}"
    );

    // Control: two genuinely different hosts still validate, so the
    // assertion above is about normalisation and not about the check
    // firing on any pair of devices.
    c.devices = vec![
        device("bare", "10.0.0.5", None),
        device("other", "::ffff:10.0.0.6", None),
    ];
    assert!(
        validate(&c, now()).is_ok(),
        "distinct addresses must not collide"
    );
}

/// `check_display_text` used to return at its emptiness guard, so a
/// value made only of whitespace never reached the control-character
/// scan — and the two sets overlap, so "whitespace-only" is not
/// "harmless". Worst on the optional free-text fields, where the early
/// return produced no error at all.
#[test]
fn whitespace_only_control_chars_are_refused() {
    // U+0085 NEL and the LF/TAB pair are all White_Space AND control.
    for payload in ["\u{85}", "\n\t", "\u{0b}\u{0c}"] {
        let mut c = basic_config();
        let mut d = device("tv", "10.0.0.5", None);
        d.notes = Some(payload.to_string());
        c.devices = vec![d];
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e.to_string().contains("control character")),
            "{payload:?} trims to empty but is pure control bytes, got: {errs:?}"
        );
    }

    // Control: ordinary whitespace on an optional field is still fine.
    // Without this the check could reject every blank value and pass.
    let mut c = basic_config();
    let mut d = device("tv", "10.0.0.5", None);
    d.notes = Some("   ".to_string());
    c.devices = vec![d];
    assert!(
        validate(&c, now()).is_ok(),
        "a space-only optional field carries no control bytes"
    );
}

// ── rev-2606 blocklist-02 — max_consecutive_failures ─────────

#[test]
fn blocklist_zero_max_consecutive_failures_rejected() {
    let mut c = basic_config();
    let mut b = blocklist("zero-tolerance");
    b.max_consecutive_failures = 0;
    c.blocklists.push(b);
    let errs = validate(&c, now()).unwrap_err();
    assert!(
        errs.iter().any(|e| matches!(
            e,
            ConfigError::ValidationFailed(ctx)
                if ctx.reason.contains("max_consecutive_failures")
        )),
        "expected max_consecutive_failures rejection: {errs:?}"
    );

    c.blocklists.last_mut().unwrap().max_consecutive_failures = 1;
    assert!(validate(&c, now()).is_ok(), "1 is valid");
}

// ── rev-2606 schema-validator-02 — server/upstream/backup ────

#[test]
fn server_zero_tcp_timeout_rejected() {
    let mut c = basic_config();
    c.server.tcp_timeout_secs = 0;
    let errs = validate(&c, now()).unwrap_err();
    assert!(has_entity(&errs, "server.tcp_timeout_secs"));

    c.server.tcp_timeout_secs = 1;
    assert!(validate(&c, now()).is_ok());
}

#[test]
fn server_listen_port_zero_rejected() {
    let mut c = basic_config();
    c.server.listen = "127.0.0.1:0".parse().unwrap();
    let errs = validate(&c, now()).unwrap_err();
    assert!(has_entity(&errs, "server.listen"));

    c.server.listen = "127.0.0.1:15353".parse().unwrap();
    assert!(validate(&c, now()).is_ok());
}

#[test]
fn upstream_empty_servers_rejected() {
    let mut c = basic_config();
    c.upstream.servers.clear();
    let errs = validate(&c, now()).unwrap_err();
    assert!(has_entity(&errs, "upstream.servers"));

    // Non-empty AND shape-valid for the default (plain) mode. rev-2606
    // added per-entry shape validation, so a DoH URL here (the previous
    // placeholder) is now correctly rejected under `mode = "plain"`.
    c.upstream.servers = vec!["1.1.1.1:53".into()];
    assert!(validate(&c, now()).is_ok());
}

// ── rev-2606 rev2606-upstream-server-shape-lint ───────────

#[test]
fn upstream_malformed_plain_server_rejected() {
    let mut c = basic_config();
    // default mode = plain; a bare hostname (no IP:port) is malformed.
    c.upstream.servers = vec!["dns.google".into()];
    let errs = validate(&c, now()).unwrap_err();
    assert!(has_entity(&errs, "upstream.servers[0]"));
}

#[test]
fn upstream_doh_url_valid_under_doh_mode_http_rejected() {
    let mut c = basic_config();
    c.upstream.mode = UpstreamMode::Doh;
    c.upstream.servers = vec!["https://1.1.1.1/dns-query".into()];
    assert!(validate(&c, now()).is_ok());
    // ...but a cleartext http:// URL is rejected under the same mode.
    c.upstream.servers = vec!["http://1.1.1.1/dns-query".into()];
    assert!(has_entity(
        &validate(&c, now()).unwrap_err(),
        "upstream.servers[0]"
    ));
}

#[test]
fn upstream_fallback_empty_and_malformed_rejected() {
    use crate::config::settings::FallbackConfig;
    let mut c = basic_config();
    // empty fallback servers.
    c.upstream.fallback = Some(FallbackConfig {
        mode: UpstreamMode::Plain,
        servers: vec![],
    });
    assert!(has_entity(
        &validate(&c, now()).unwrap_err(),
        "upstream.fallback.servers"
    ));
    // malformed DoT fallback entry (no port).
    c.upstream.fallback = Some(FallbackConfig {
        mode: UpstreamMode::Dot,
        servers: vec!["dns.quad9.net".into()],
    });
    assert!(has_entity(
        &validate(&c, now()).unwrap_err(),
        "upstream.fallback.servers[0]"
    ));
    // valid DoT fallback entry passes.
    c.upstream.fallback = Some(FallbackConfig {
        mode: UpstreamMode::Dot,
        servers: vec!["dns.quad9.net:853".into()],
    });
    assert!(validate(&c, now()).is_ok());
}

#[test]
fn forwarding_malformed_and_valid_servers() {
    use crate::config::settings::ForwardingZoneConfig;
    let mut c = basic_config();
    // malformed (no port) — entity carries the zone suffix.
    c.forwarding = vec![ForwardingZoneConfig {
        suffix: "corp.example.com".into(),
        mode: UpstreamMode::Plain,
        servers: vec!["10.0.0.1".into()],
    }];
    assert!(has_entity(
        &validate(&c, now()).unwrap_err(),
        "forwarding[corp.example.com].servers[0]"
    ));
    // valid IP:port passes.
    c.forwarding = vec![ForwardingZoneConfig {
        suffix: "corp.example.com".into(),
        mode: UpstreamMode::Plain,
        servers: vec!["10.0.0.1:53".into()],
    }];
    assert!(validate(&c, now()).is_ok());
}

#[test]
fn backup_unparseable_auto_interval_rejected() {
    let mut c = basic_config();
    for bad in ["9999h", "24", "h", "1.5d", ""] {
        c.backup.auto_interval = Some(bad.into());
        let errs = validate(&c, now()).unwrap_err();
        assert!(
            has_entity(&errs, "backup.auto_interval"),
            "auto_interval = {bad:?} should be rejected"
        );
    }
    for ok in ["24h", "7d"] {
        c.backup.auto_interval = Some(ok.into());
        assert!(
            validate(&c, now()).is_ok(),
            "auto_interval = {ok:?} is valid"
        );
    }
    c.backup.auto_interval = None;
    assert!(validate(&c, now()).is_ok(), "unset auto_interval is valid");
}

// ── rev-2606 settings-13 — [dnssec] caps ─────────────────────

#[test]
fn dnssec_zero_caps_rejected_when_mode_active() {
    use crate::config::settings::DnssecMode;
    let mut c = basic_config();
    c.dnssec.mode = DnssecMode::Validate;

    c.dnssec.max_chain_depth = 0;
    let errs = validate(&c, now()).unwrap_err();
    assert!(has_entity(&errs, "dnssec.max_chain_depth"));
    c.dnssec.max_chain_depth = 1;

    c.dnssec.max_queries = 0;
    let errs = validate(&c, now()).unwrap_err();
    assert!(has_entity(&errs, "dnssec.max_queries"));
    c.dnssec.max_queries = 1;

    c.dnssec.max_nsec3_iterations = 0;
    let errs = validate(&c, now()).unwrap_err();
    assert!(has_entity(&errs, "dnssec.max_nsec3_iterations"));
    c.dnssec.max_nsec3_iterations = 1;

    c.dnssec.max_signature_verifications = 0;
    let errs = validate(&c, now()).unwrap_err();
    assert!(has_entity(&errs, "dnssec.max_signature_verifications"));
    c.dnssec.max_signature_verifications = 1;

    c.dnssec.cache_ttl_secs = 0;
    let errs = validate(&c, now()).unwrap_err();
    assert!(has_entity(&errs, "dnssec.cache_ttl_secs"));
    c.dnssec.cache_ttl_secs = 1;

    assert!(validate(&c, now()).is_ok(), "caps of 1 are valid");

    // log-only counts as active too.
    c.dnssec.mode = DnssecMode::LogOnly;
    c.dnssec.max_queries = 0;
    let errs = validate(&c, now()).unwrap_err();
    assert!(has_entity(&errs, "dnssec.max_queries"));
}

/// mode = "off" (the default) is inert: zero caps must not brick a
/// config on a binary that never validates (backward compat).
#[test]
fn dnssec_caps_inert_when_mode_off() {
    let mut c = basic_config();
    c.dnssec.max_chain_depth = 0;
    c.dnssec.cache_ttl_secs = 0;
    assert!(
        validate(&c, now()).is_ok(),
        "mode = off must skip the cap gates"
    );
}

// ── rev-2606 settings-03 — [lists] caps fail-open at 0 ───────

#[test]
fn lists_zero_caps_rejected() {
    let mut c = basic_config();
    c.lists.max_entries = 0;
    let errs = validate(&c, now()).unwrap_err();
    assert!(has_entity(&errs, "lists.max_entries"));

    c.lists.max_entries = 1;
    c.lists.max_body_bytes = 0;
    let errs = validate(&c, now()).unwrap_err();
    assert!(has_entity(&errs, "lists.max_body_bytes"));

    c.lists.max_body_bytes = 1;
    assert!(validate(&c, now()).is_ok(), "caps of 1 are valid");
}

// ── Sprint 43 T4 — DM1 / DM6 device overlay validation ───────

fn admin_rule(id: &str, rule: &str) -> super::super::admin_rule::AdminRule {
    super::super::admin_rule::AdminRule {
        id: Id::new(id).unwrap(),
        rule: rule.into(),
    }
}

#[test]
fn device_allow_rules_dangling_id_rejected() {
    let mut c = basic_config();
    let mut d = device("phone", "10.0.0.1", Some("default"));
    d.allow_rules = vec![Id::new("does-not-exist").unwrap()];
    c.devices.push(d);
    let errs = validate(&c, now()).unwrap_err();
    assert!(
        errs.iter().any(|e| matches!(
            e,
            ConfigError::CrossRefMiss(ctx)
                if ctx.reason.contains("does-not-exist")
                   && ctx.reason.contains("allow_rules")
        )),
        "expected dangling allow_rules ref error: {errs:?}"
    );
}

#[test]
fn device_deny_rules_dangling_id_rejected() {
    let mut c = basic_config();
    let mut d = device("phone", "10.0.0.1", Some("default"));
    d.deny_rules = vec![Id::new("ghost-rule").unwrap()];
    c.devices.push(d);
    let errs = validate(&c, now()).unwrap_err();
    assert!(
        errs.iter().any(|e| matches!(
            e,
            ConfigError::CrossRefMiss(ctx)
                if ctx.reason.contains("ghost-rule")
                   && ctx.reason.contains("deny_rules")
        )),
        "expected dangling deny_rules ref error: {errs:?}"
    );
}

#[test]
fn device_with_known_rule_ids_accepted() {
    let mut c = basic_config();
    c.admin_rules
        .push(admin_rule("dev-allow-bank", "@@||bank.example^"));
    c.admin_rules
        .push(admin_rule("dev-deny-tiktok", "||tiktok.com^"));
    let mut d = device("phone", "10.0.0.1", Some("default"));
    d.allow_rules = vec![Id::new("dev-allow-bank").unwrap()];
    d.deny_rules = vec![Id::new("dev-deny-tiktok").unwrap()];
    c.devices.push(d);
    assert!(validate(&c, now()).is_ok());
}

// ── rev-2606 schema-validator-05: admin rule text parse-validated ──

#[test]
fn admin_rule_broken_regex_rejected() {
    let mut c = basic_config();
    c.admin_rules.push(admin_rule("bad-re", "/broken(/"));
    let errs = validate(&c, now()).unwrap_err();
    let hits: Vec<_> = errs
        .iter()
        .filter(|e| {
            matches!(
                e,
                ConfigError::ValidationFailed(ctx)
                    if ctx.entity.as_deref() == Some("admin_rules.bad-re")
            )
        })
        .collect();
    assert_eq!(hits.len(), 1, "exactly one parse error: {errs:?}");
    let ConfigError::ValidationFailed(ctx) = hits[0] else {
        unreachable!()
    };
    assert!(
        ctx.reason.contains("failed to compile"),
        "reason carries the RuleParseError detail: {}",
        ctx.reason
    );
    assert!(
        ctx.suggestion.is_some(),
        "parse errors carry a next-step suggestion"
    );
}

#[test]
fn admin_rule_unknown_modifier_rejected() {
    let mut c = basic_config();
    c.admin_rules
        .push(admin_rule("aaaa-only", "||example.com^$dnstype=AAAA"));
    let errs = validate(&c, now()).unwrap_err();
    assert!(
        errs.iter().any(|e| matches!(
            e,
            ConfigError::ValidationFailed(ctx)
                if ctx.entity.as_deref() == Some("admin_rules.aaaa-only")
                   && ctx.reason.contains("unknown modifier '$dnstype=AAAA'")
        )),
        "unknown modifier surfaces at lint: {errs:?}"
    );
}

#[test]
fn admin_rule_empty_still_missing_required_only() {
    // The emptiness check stays first and short-circuits — an empty
    // rule must NOT also produce a parse error (double report).
    let mut c = basic_config();
    c.admin_rules.push(admin_rule("empty-rule", "   "));
    let errs = validate(&c, now()).unwrap_err();
    let mine: Vec<_> = errs
        .iter()
        .filter(|e| {
            let (ConfigError::MissingRequired(ctx) | ConfigError::ValidationFailed(ctx)) = e else {
                return false;
            };
            ctx.entity.as_deref() == Some("admin_rules.empty-rule")
        })
        .collect();
    assert_eq!(mine.len(), 1, "{errs:?}");
    assert!(
        matches!(mine[0], ConfigError::MissingRequired(_)),
        "empty rule keeps the MissingRequired shape: {:?}",
        mine[0]
    );
}

#[test]
fn admin_rule_two_broken_rules_two_errors() {
    // Complete-list contract: every broken rule is reported.
    let mut c = basic_config();
    c.admin_rules.push(admin_rule("bad-one", "/foo/bar"));
    c.admin_rules.push(admin_rule("bad-two", "||ads.*.com^"));
    let errs = validate(&c, now()).unwrap_err();
    for entity in ["admin_rules.bad-one", "admin_rules.bad-two"] {
        assert!(
            errs.iter().any(|e| matches!(
                e,
                ConfigError::ValidationFailed(ctx)
                    if ctx.entity.as_deref() == Some(entity)
            )),
            "missing error for {entity}: {errs:?}"
        );
    }
}

#[test]
fn admin_rule_valid_shapes_accepted() {
    let mut c = basic_config();
    for (id, rule) in [
        ("r1", "||tiktok.com^"),
        ("r2", "@@||wikipedia.org^"),
        ("r3", "||malware.example^$important"),
        ("r4", "||*.ads.example.com^"),
        ("r5", "||*.cdn.example.com^$noapex"),
        ("r6", "/ad[0-9]+\\.example\\.com/"),
        ("r7", "@@/safe-cdn[0-9]+/"),
        ("r8", "/DoubleClick/"),
        ("r9", "plain.example.com"),
        ("r10", "@@example.com"),
    ] {
        c.admin_rules.push(admin_rule(id, rule));
    }
    assert!(validate(&c, now()).is_ok());
}

#[test]
fn device_rules_hard_cap_129_rejected() {
    let mut c = basic_config();
    // Inject 129 admin rules so cross-refs all resolve, then point
    // every one of them from the device. The total count = 129
    // exceeds the hard cap of 128 by 1.
    for n in 0..129u32 {
        c.admin_rules.push(admin_rule(
            &format!("rule-{n}"),
            &format!("||t{n}.example^"),
        ));
    }
    let mut d = device("phone", "10.0.0.1", Some("default"));
    d.allow_rules = (0..129)
        .map(|n| Id::new(format!("rule-{n}")).unwrap())
        .collect();
    c.devices.push(d);
    let errs = validate(&c, now()).unwrap_err();
    assert!(
        errs.iter().any(|e| matches!(
            e,
            ConfigError::ValidationFailed(ctx)
                if ctx.reason.contains("hard cap") && ctx.reason.contains("128")
        )),
        "expected hard-cap rejection, got: {errs:?}"
    );
}

#[test]
fn device_rules_at_hard_cap_128_accepted() {
    // Exactly 128 entries (split allow + deny) is the boundary.
    // Validator must accept; only `> 128` rejects.
    let mut c = basic_config();
    for n in 0..128u32 {
        c.admin_rules.push(admin_rule(
            &format!("rule-{n}"),
            &format!("||t{n}.example^"),
        ));
    }
    let mut d = device("phone", "10.0.0.1", Some("default"));
    d.allow_rules = (0..64)
        .map(|n| Id::new(format!("rule-{n}")).unwrap())
        .collect();
    d.deny_rules = (64..128)
        .map(|n| Id::new(format!("rule-{n}")).unwrap())
        .collect();
    c.devices.push(d);
    assert!(
        validate(&c, now()).is_ok(),
        "128 entries (64+64) is exactly at the cap and must be accepted"
    );
}

#[test]
fn device_rules_soft_cap_warn_does_not_block() {
    // Soft cap = 64. Going from 65 to 128 emits LIST_PRUNE_WARN
    // via tracing::warn but does NOT push a ConfigError (operator
    // can still boot and prune later).
    let mut c = basic_config();
    for n in 0..70u32 {
        c.admin_rules.push(admin_rule(
            &format!("rule-{n}"),
            &format!("||t{n}.example^"),
        ));
    }
    let mut d = device("phone", "10.0.0.1", Some("default"));
    d.allow_rules = (0..70)
        .map(|n| Id::new(format!("rule-{n}")).unwrap())
        .collect();
    c.devices.push(d);
    assert!(validate(&c, now()).is_ok());
}

#[test]
fn list_prune_warn_const_is_pinned() {
    // T6 will turn this into a frozen-strings file; T4 pins the
    // const here so any unintentional rewording lights up before
    // the holistic pass.
    assert_eq!(
        LIST_PRUNE_WARN,
        "Device '{id}' has {n} rules (soft cap: 64). Run `warden device rules {id} prune` to clean up dead refs."
    );
}

#[test]
fn list_prune_warn_format_helper_substitutes() {
    let s = format_list_prune_warn("operator-iphone", 70);
    assert!(s.contains("'operator-iphone'"));
    assert!(s.contains("70 rules"));
    assert!(s.contains("warden device rules operator-iphone prune"));
}

#[test]
fn tracking_config_rejects_sampled_rate_out_of_range() {
    use crate::config::settings::LogMode;
    let mut c = basic_config();
    c.tracking.log_mode = LogMode::Sampled { allowed_rate: -0.1 };
    let errs = validate(&c, now()).unwrap_err();
    assert!(has_entity(&errs, "tracking.log_mode.sampled.allowed_rate"));

    c.tracking.log_mode = LogMode::Sampled { allowed_rate: 1.5 };
    let errs = validate(&c, now()).unwrap_err();
    assert!(has_entity(&errs, "tracking.log_mode.sampled.allowed_rate"));

    c.tracking.log_mode = LogMode::Sampled {
        allowed_rate: f32::NAN,
    };
    let errs = validate(&c, now()).unwrap_err();
    assert!(has_entity(&errs, "tracking.log_mode.sampled.allowed_rate"));

    // Valid rates at boundaries pass.
    for rate in [0.0_f32, 0.5, 1.0] {
        c.tracking.log_mode = LogMode::Sampled { allowed_rate: rate };
        assert!(validate(&c, now()).is_ok(), "rate = {rate} should pass");
    }
}

// ── kind/trust compatibility — the W2.1 gate, now consent-based ──
//
// `ALLOW_LIST_REQUIRES_LOCAL_TRUST` and its helper were deleted with
// the categorical gate: the sentence "Allow-direction lists require
// trust=local" became false the moment `accept_unsigned_allow`
// started admitting remote allow-lists. `tests/frozen_strings_s49.rs`
// is the tombstone; the replacements are pinned in
// `tests/frozen_strings_unsigned_allow.rs` and mirrored below.

/// Defence-in-depth mirror of
/// `tests/frozen_strings_unsigned_allow.rs` — lights up earlier than
/// the integration target when someone rewords the refusal.
#[test]
fn unsigned_allow_list_requires_ack_const_is_pinned() {
    assert_eq!(
        UNSIGNED_ALLOW_LIST_REQUIRES_ACK,
        "Blocklist '{id}' has kind=allow but trust='{got}'. A remote allow-list can unblock any domain it lists, and its content can change at every refresh with no review. Set accept_unsigned_allow = true on the list to accept that risk, or use `warden blocklist import-local` to import a local file."
    );
}

#[test]
fn unsigned_allow_list_requires_ack_format_helper_substitutes() {
    let s = format_unsigned_allow_list_requires_ack("trusted-internal", BlocklistTrust::Signed);
    assert!(s.contains("'trusted-internal'"));
    assert!(s.contains("trust='signed'"));
    assert!(s.contains("kind=allow"));
    assert!(s.contains("`warden blocklist import-local`"));

    // `RemoteUnsigned` must round-trip through the kebab-case spelling
    // (matches the on-wire form an operator typed in TOML).
    let s = format_unsigned_allow_list_requires_ack("x", BlocklistTrust::RemoteUnsigned);
    assert!(s.contains("trust='remote-unsigned'"));
}

#[test]
fn unsigned_allow_list_accepted_const_is_pinned() {
    assert_eq!(
        UNSIGNED_ALLOW_LIST_ACCEPTED,
        "allow-list \"{id}\" is remote and unsigned — whoever controls its URL can unblock any domain by adding it, at every refresh, with no review"
    );
}

#[test]
fn unsigned_allow_list_accepted_format_helper_substitutes() {
    let s = format_unsigned_allow_list_accepted("vendor-allow");
    assert!(s.contains("\"vendor-allow\""));
    assert!(!s.contains("{id}"), "placeholder left unsubstituted: {s}");
}

/// Sprint 50 T2: byte-for-byte pin for the new frozen string.
/// `tests/frozen_strings_s50.rs` (T5 deliverable) will mirror this
/// assertion into the dedicated frozen-strings file; pinning here as
/// well guards against accidental rewording during the inter-phase
/// window (same defence-in-depth pattern as
/// [`allow_list_requires_local_trust_const_is_pinned`]).
#[test]
fn trust_signed_not_yet_supported_const_is_pinned() {
    assert_eq!(
        TRUST_SIGNED_NOT_YET_SUPPORTED,
        "trust=signed is not supported in this version. Use trust=local for trusted allow-lists or trust=remote-unsigned for block-only lists."
    );
}

// ── Sprint A of lists_categories_v2: byte-pinned frozen strings ──
//
// Same defence-in-depth pattern as the S49 / S50 pins above. T3
// wires the validator emit paths; the byte-pin here lets a code
// reviewer catch a silent rename even if T3 has not landed yet.

#[test]
fn network_name_invalid_fqdn_const_is_pinned() {
    assert_eq!(
        NETWORK_NAME_INVALID_FQDN,
        "devices.{id}.network_name '{name}' is not a valid FQDN label (1-63 chars, alphanumeric + hyphen, no leading/trailing hyphen)."
    );
}

#[test]
fn network_name_invalid_fqdn_format_helper_substitutes() {
    let s = format_network_name_invalid_fqdn("desktop-1", "bad domain!");
    assert!(s.contains("devices.desktop-1.network_name"));
    assert!(s.contains("'bad domain!'"));
    assert!(!s.contains("{id}"));
    assert!(!s.contains("{name}"));
}

#[test]
fn network_name_wildcard_without_name_const_is_pinned() {
    assert_eq!(
        NETWORK_NAME_WILDCARD_WITHOUT_NAME,
        "devices.{id}.network_name_wildcard=true has no effect without network_name set."
    );
}

#[test]
fn network_name_wildcard_without_name_format_helper_substitutes() {
    let s = format_network_name_wildcard_without_name("desktop-1");
    assert!(s.contains("devices.desktop-1.network_name_wildcard"));
    assert!(!s.contains("{id}"));
}

// ── rev-2606 §05 schema-validator-03 ──────────────────────────────
//
// The lint and the fetcher must agree on which list URLs can ever be
// downloaded. They cannot share code — the fetcher owns `url`/`reqwest`
// and the config layer is deliberately free of both — so the guard
// against drift is this cross-check rather than a shared call.

/// What `check_blocklists` would accept without any diagnostic,
/// composed from the same predicates the emit sites use.
fn lint_accepts_silently(url: &str) -> bool {
    (url.starts_with("http://") || url.starts_with("https://"))
        && !url.starts_with("http://")
        && !url_has_embedded_userinfo(url)
        && !host_is_unfetchable(url_host_of(url))
}

#[test]
fn blocklist_url_policy_agrees_with_the_fetcher() {
    // Compared on the three axes this rule aligns: scheme, embedded
    // userinfo, and the host-address policy. URL *well-formedness* is
    // deliberately NOT compared — `Url::parse` owns that and the config
    // layer has no parser, so every case below is syntactically valid
    // for both sides.
    let cases = [
        "https://lists.purge.cc/privacy/ads.txt",
        "http://lists.purge.cc/privacy/ads.txt",
        "https://user:pass@lists.purge.cc/ads.txt",
        "https://192.0.2.10/ads.txt",
        "https://10.0.0.1/ads.txt",
        "https://192.168.1.1/ads.txt",
        "https://172.16.0.1/ads.txt",
        "https://127.0.0.1/ads.txt",
        "https://169.254.1.1/ads.txt",
        "https://192.0.2.1/ads.txt",
        "https://0.0.0.0/ads.txt",
        "https://[::1]/ads.txt",
        "https://[fc00::1]/ads.txt",
        "https://[fe80::1]/ads.txt",
        "https://[::ffff:127.0.0.1]/ads.txt",
        // RFC 3849 documentation prefix, not a real provider's address:
        // a public v6 literal is needed here and a vendor one would put a
        // named service into src/ for no reason (CLAUDE.md Rule 10).
        "https://[2001:db8::1]/ads.txt",
        "https://lists.purge.cc:8443/ads.txt",
        "https://192.0.2.10:8443/ads.txt",
    ];
    for url in cases {
        let fetcher_ok = crate::lists::http_client::validate_list_url(url).is_ok();
        let lint_ok = lint_accepts_silently(url);
        assert_eq!(
            lint_ok, fetcher_ok,
            "lint and fetcher disagree on {url}: lint_ok={lint_ok}, \
             fetcher_ok={fetcher_ok} — a config that lints clean and can \
             never download is exactly the split this rule closes"
        );
    }
}

/// The table above is only evidence if it contains both polarities.
/// Without this, a `lint_accepts_silently` hardwired to `false` (or a
/// fetcher that refused everything) would pass it.
#[test]
fn the_url_agreement_table_covers_both_verdicts() {
    assert!(
        lint_accepts_silently("https://lists.purge.cc/ads.txt"),
        "a plain https list on a public host must be accepted silently"
    );
    assert!(
        !lint_accepts_silently("http://lists.purge.cc/ads.txt"),
        "cleartext http must be diagnosed"
    );
    assert!(
        !lint_accepts_silently("https://10.0.0.1/ads.txt"),
        "an RFC1918 host must be diagnosed"
    );
}

#[test]
fn url_host_of_peels_userinfo_port_and_ipv6_brackets() {
    assert_eq!(
        url_host_of("https://lists.purge.cc/ads.txt"),
        "lists.purge.cc"
    );
    assert_eq!(
        url_host_of("https://u:p@lists.purge.cc/ads.txt"),
        "lists.purge.cc"
    );
    assert_eq!(
        url_host_of("https://lists.purge.cc:8443/ads.txt"),
        "lists.purge.cc"
    );
    // The inner colons of an IPv6 literal must not be read as a port.
    assert_eq!(url_host_of("https://[fe80::1]:8443/ads.txt"), "fe80::1");
    assert_eq!(url_host_of("https://192.0.2.10"), "192.0.2.10");
}

#[test]
fn blocklist_url_diagnostic_consts_are_pinned() {
    assert_eq!(
        BLOCKLIST_URL_CLEARTEXT_HTTP,
        "blocklist \"{id}\" uses a cleartext http:// URL — the downloader is https-only, so this list will never update"
    );
    assert_eq!(
        BLOCKLIST_URL_UNFETCHABLE_HOST,
        "blocklist \"{id}\" points at \"{host}\", an address the downloader refuses (private, loopback, link-local, CGNAT or unspecified) — so this list will never update"
    );
    let s = format_blocklist_url_unfetchable_host("corp-list", "10.0.0.1");
    assert!(s.contains("\"corp-list\"") && s.contains("\"10.0.0.1\""));
    assert!(!s.contains("{id}") && !s.contains("{host}"));
}

// ── Sprint B T3 — 3 new §5.4 frozen strings ────────────────────

// ── Sprint C T5 — Add-list pre-flight gate 3 ──────────────────

#[test]
fn list_url_not_reachable_const_is_pinned() {
    assert_eq!(
        LIST_URL_NOT_REACHABLE,
        "Cannot reach '{url}': {detail}. Verify the URL in a browser, then retry — or pass --skip-head-check to add the list anyway."
    );
}

#[test]
fn list_url_not_reachable_format_helper_substitutes() {
    let s = format_list_url_not_reachable("https://example.invalid/list.txt", "connection refused");
    assert!(s.contains("'https://example.invalid/list.txt'"));
    assert!(s.contains("connection refused"));
    assert!(!s.contains("{url}"));
    assert!(!s.contains("{detail}"));
}

// ── plp cutover — what replaced the §5.4 tag rows ──────────────
//
// Rows 0-3 of the `lists_categories_v2` §5.4 table were emit-path
// tests for four tag diagnostics. Three of them (rows 1-3) asserted
// only `validate(...).is_ok()`, which the validator returns whether
// the WARN fires or not — they were green against a validator that
// emitted nothing, and stayed green when the emit sites left at S3.
// A test that passes on the state the product preserves in failure is
// not evidence, so they are gone rather than kept as decoration.
//
// What replaced them:
//
// | withdrawn | replacement |
// |---|---|
// | row 0 `DEVICE_UNFILTERED_WITH_TAGS` (ERROR) | none — the contradiction it priced no longer exists; inverted below |
// | row 1 `DEVICE_NOT_FILTERED_NO_TAGS` | `PROFILE_FILTERS_NO_LISTS`, asserted below |
// | row 2 `PROFILE_CONTRIBUTES_NO_TAGS` | `PROFILE_FILTERS_NO_LISTS`, asserted below |
// | row 3 `ALLOW_LIST_NO_TAGS_NO_EFFECT` | premise inverted — an untagged allow-list now applies everywhere, and `ALLOW_DIRECTION_LIST_STANDING_EXPOSURE` is the honest signal (`f24_the_standing_exposure_warning_still_fires_on_the_allow_branch`) |
// | row 4 `UNCATEGORIZED_MISSING_AT_RELOAD` (ERROR) | none — the `uncategorized` sentinel is retired, so there is no registry left to miss it |
//
// **The constants themselves are gone as of `plp-s5f`**, along with the
// frozen-string tests that byte-pinned them. Until then they stood
// declared-and-unemitted, which is worse than absent: a byte-pin on a
// string the product cannot produce is green by construction, and reads
// to the next person as proof the diagnostic still exists. The
// replacements named above are pinned from outside the crate in
// `tests/frozen_strings_plp_profile_diagnostics.rs`.

/// The substitute for §5.4 rows 1 and 2, asserted rather than assumed:
/// a profile that ignores every enabled list is named in the warnings.
///
/// It asks one hop later than the tag rows did — a device inherits its
/// profile's policy, so the profile is where the answer is — and it
/// catches the case the tag version could not: a profile carrying tags
/// that no list matched still looked healthy to `PROFILE_CONTRIBUTES_NO_TAGS`.
#[test]
fn a_profile_that_ignores_every_list_is_warned_about() {
    let mut c = basic_config();
    let list_id = c.blocklists[0].id.clone();
    c.profiles
        .get_mut("default")
        .unwrap()
        .lists
        .insert(list_id, ListPolicy::Ignore);

    let mut warns = AuditWarnings::silent();
    assert!(validate_collect(&c, now(), &mut warns, None, None).is_ok());
    let msgs = warns.into_messages();
    let expected = format_profile_filters_no_lists("default");
    assert!(
        msgs.contains(&expected),
        "expected {expected:?}, got {msgs:?}"
    );
}

/// Control arm for the test above. Without it, the assertion there also
/// passes against a validator that warned about *every* profile — which
/// is the failure mode this whole class of WARN dies of, and the one
/// CLAUDE.md names twice for detectors.
#[test]
fn a_profile_that_filters_one_list_is_silent() {
    let c = basic_config();
    assert!(
        c.profiles["default"].lists.is_empty(),
        "fixture must inherit, or the control arm proves nothing"
    );
    let mut warns = AuditWarnings::silent();
    assert!(validate_collect(&c, now(), &mut warns, None, None).is_ok());
    let unexpected = format_profile_filters_no_lists("default");
    let msgs = warns.into_messages();
    assert!(
        !msgs.contains(&unexpected),
        "the profile inherits `base = deny` on an enabled list — it filters. \
         got {msgs:?}"
    );
}

// ── device.network_name — FQDN syntax + wildcard mutex ─────────

#[test]
fn device_network_name_bad_fqdn_syntax_is_rejected() {
    let mut c = basic_config();
    let mut d = device("desktop-1", "10.10.1.50", None);
    d.network_name = Some("bad domain!".to_string());
    c.devices.push(d);
    let errs = validate(&c, now()).unwrap_err();
    assert!(
        errs.iter().any(|e| e.to_string().contains("network_name")),
        "expected a network_name FQDN error, got: {errs:?}"
    );
}

#[test]
fn device_network_name_wildcard_without_name_is_rejected() {
    let mut c = basic_config();
    let mut d = device("desktop-1", "10.10.1.50", None);
    d.network_name_wildcard = true;
    c.devices.push(d);
    let errs = validate(&c, now()).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.to_string().contains("network_name_wildcard")),
        "expected a network_name_wildcard mutex error, got: {errs:?}"
    );
}

#[test]
fn device_network_name_valid_fqdn_is_accepted() {
    let mut c = basic_config();
    let mut d = device("desktop-1", "10.10.1.50", None);
    d.network_name = Some("desktop-1".to_string());
    c.devices.push(d);
    assert!(validate(&c, now()).is_ok());
}

#[test]
fn device_network_name_collides_with_another_device_is_rejected() {
    let mut c = basic_config();
    let mut d1 = device("desktop-1", "10.10.1.50", None);
    d1.network_name = Some("shared-name".to_string());
    let mut d2 = device("other-box", "10.10.1.51", None);
    d2.network_name = Some("shared-name".to_string());
    c.devices.push(d1);
    c.devices.push(d2);
    let errs = validate(&c, now()).unwrap_err();
    assert!(
        errs.iter().any(|e| e.to_string().contains("already used")),
        "expected a network_name collision error, got: {errs:?}"
    );
}

#[test]
fn device_network_name_collides_with_local_dns_record_is_rejected() {
    let mut c = basic_config();
    let mut d = device("desktop-1", "10.10.1.50", None);
    d.network_name = Some("nas".to_string());
    c.devices.push(d);
    c.local_dns
        .records
        .push(crate::config::settings::LocalDnsRecord {
            domain: "nas".to_string(),
            record_type: crate::config::settings::LocalDnsRecordType::A,
            value: "10.10.1.60".to_string(),
            match_subdomains: false,
            ttl_secs: None,
        });
    let errs = validate(&c, now()).unwrap_err();
    assert!(
        errs.iter().any(|e| e.to_string().contains("already used")),
        "expected a network_name/local_dns collision error, got: {errs:?}"
    );
}

/// The two collision messages above share the phrase "already used",
/// so a test keyed on it alone cannot tell which arm fired — swap
/// the device-vs-device and device-vs-local_dns branches and both
/// still pass. These two pin the discriminating half of each
/// message, and at the same time exercise the key normalisation
/// (case-fold + trailing dot) that nothing else covers: without it
/// `NAS.` and `nas` are two names claiming one record.
#[test]
fn device_network_name_device_collision_is_normalised_and_names_the_other_device() {
    let mut c = basic_config();
    let mut d1 = device("desktop-1", "10.10.1.50", None);
    d1.network_name = Some("NAS.".to_string());
    let mut d2 = device("other-box", "10.10.1.51", None);
    d2.network_name = Some("nas".to_string());
    c.devices.push(d1);
    c.devices.push(d2);
    let errs = validate(&c, now()).unwrap_err();
    assert!(
        errs.iter().any(|e| {
            let s = e.to_string();
            s.contains("already used by device") && s.contains("desktop-1")
        }),
        "expected a device-vs-device collision naming \"desktop-1\", got: {errs:?}"
    );
}

#[test]
fn device_network_name_local_dns_collision_is_normalised_and_names_local_dns() {
    let mut c = basic_config();
    let mut d = device("desktop-1", "10.10.1.50", None);
    d.network_name = Some("NAS.".to_string());
    c.devices.push(d);
    c.local_dns
        .records
        .push(crate::config::settings::LocalDnsRecord {
            domain: "nas".to_string(),
            record_type: crate::config::settings::LocalDnsRecordType::A,
            value: "10.10.1.60".to_string(),
            match_subdomains: false,
            ttl_secs: None,
        });
    let errs = validate(&c, now()).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.to_string().contains("already used by a local_dns record")),
        "expected a device-vs-local_dns collision, got: {errs:?}"
    );
}

/// The per-profile `local_records` scope is part of the same
/// collision universe as the global `[local_dns]` table — a device
/// name that shadows a profile-scoped record is just as broken.
#[test]
fn device_network_name_collides_with_profile_local_record_is_rejected() {
    let mut c = basic_config();
    let mut d = device("desktop-1", "10.10.1.50", None);
    d.network_name = Some("printer".to_string());
    c.devices.push(d);
    c.profiles.get_mut("default").unwrap().local_records.push(
        crate::config::settings::LocalDnsRecord {
            domain: "printer".to_string(),
            record_type: crate::config::settings::LocalDnsRecordType::A,
            value: "10.10.1.70".to_string(),
            match_subdomains: false,
            ttl_secs: None,
        },
    );
    let errs = validate(&c, now()).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.to_string().contains("already used by a local_dns record")),
        "expected a device-vs-profile-local_records collision, got: {errs:?}"
    );
}

// ── inert_blocklists — the plp predicate ────────────────────────

/// The one shape [`inert_blocklists`] reports: `base = "ignore"` with
/// every profile inheriting it. The message is the load-time WARN's own
/// frozen string, so `warden status` and `config lint` cannot drift.
#[test]
fn a_base_ignore_list_no_profile_overrides_is_inert() {
    let mut c = basic_config();
    c.blocklists[0].base = BlocklistBase::Ignore;
    let rows = inert_blocklists(&c);
    assert_eq!(rows.len(), 1, "got {rows:?}");
    assert_eq!(rows[0].0, "privacy-ads");
    assert_eq!(rows[0].1, InertListReason::BaseIgnore);
    assert_eq!(
        rows[0].1.message("privacy-ads"),
        format_base_ignore_list_is_inert("privacy-ads"),
        "the projection must reuse the WARN's string, not paraphrase it"
    );
}

/// The narrowing, asserted. A profile that overrides the list to `deny`
/// filters with it, so calling it inert in `warden status` would be F24's
/// false claim pointed the other way — and an operator acting on
/// "inert" removes a list that is doing work.
///
/// **Two profiles, and the second one is not decoration.** Written with
/// only `basic_config()`'s single profile, this test passed against
/// `any()` as happily as against `all()` — over a one-element iterator
/// they are the same function. The mutation caught it. The fixture now
/// has one profile that inherits `ignore` and one that overrides to
/// `deny`, which is the smallest shape where the two disagree.
#[test]
fn a_base_ignore_list_one_profile_overrides_is_not_inert() {
    let mut c = basic_config();
    c.blocklists[0].base = BlocklistBase::Ignore;
    let list_id = c.blocklists[0].id.clone();
    c.profiles.insert("kids".into(), profile_default());
    c.profiles
        .get_mut("kids")
        .unwrap()
        .lists
        .insert(list_id, ListPolicy::Deny);
    assert_eq!(c.profiles.len(), 2, "one profile makes all() == any()");
    assert!(
        inert_blocklists(&c).is_empty(),
        "`kids` denies with it — got {:?}",
        inert_blocklists(&c)
    );
}

/// Control arm for both tests above. An ordinary deny-direction list is
/// never inert, and without this a predicate that returned everything —
/// or nothing — would still satisfy one of the two.
#[test]
fn an_ordinary_deny_list_is_not_inert() {
    let c = basic_config();
    assert_eq!(c.blocklists[0].base, BlocklistBase::Deny);
    assert!(inert_blocklists(&c).is_empty());
}

/// **The vacuous-truth guard.** `all()` over an empty profile map is
/// true, so without the early return a config with no profiles would
/// report every ignore-direction list inert on the strength of a claim
/// no profile made. Reported for the record: with zero profiles nothing
/// resolves at all, and that is not a fact about any one list.
#[test]
fn a_config_with_no_profiles_reports_nothing_inert() {
    let mut c = basic_config();
    c.blocklists[0].base = BlocklistBase::Ignore;
    c.profiles.clear();
    assert!(
        inert_blocklists(&c).is_empty(),
        "vacuous truth is not a measurement — got {:?}",
        inert_blocklists(&c)
    );
}

/// The tag-keyed predicate this replaced is gone, and its variants must
/// never come back into production: an untagged `base = allow` list is
/// reached by every profile that inherits it, so `AllowListNoTags` was
/// F24's claim rendered in `warden status`.
#[test]
fn an_untagged_allow_list_is_not_reported_inert() {
    let mut c = basic_config();
    c.blocklists[0].base = BlocklistBase::Allow;
    c.blocklists[0].trust = BlocklistTrust::Local;
    assert!(
        inert_blocklists(&c).is_empty(),
        "an allow-direction list applies to every profile that inherits it \
         — got {:?}",
        inert_blocklists(&c)
    );
}

// ── `[lists].sources` entries that cannot filter ────────────────

/// The shape the diagnostic exists for: a source recorded in the
/// channel that downloads but cannot filter, with nothing to match
/// it.
#[test]
fn legacy_source_with_no_list_is_reported() {
    let mut c = basic_config();
    c.blocklists.clear();
    c.lists.sources = vec!["privacy/ads".to_string()];
    assert_eq!(orphan_legacy_sources(&c), vec!["privacy/ads".to_string()]);
}

/// Warning, not error. A config in the field that holds one of these
/// boots today; refusing to load would take a working resolver down
/// to fix a list that was already filtering nothing.
#[test]
fn legacy_source_with_no_list_still_loads() {
    let mut c = basic_config();
    c.blocklists.clear();
    c.lists.sources = vec!["privacy/ads".to_string()];

    let mut warns = AuditWarnings::silent();
    assert!(
        validate_collect(&c, now(), &mut warns, None, None).is_ok(),
        "an orphan source must never stop the daemon from starting"
    );
    let msgs = warns.into_messages();
    assert!(
        msgs.iter().any(|m| m.contains("filters nothing")),
        "expected the orphan-source warning, got: {msgs:?}"
    );
}

/// The shape every migrated config has. It must stay silent, or the
/// warning becomes noise operators learn to scroll past.
#[test]
fn no_legacy_sources_is_silent() {
    let c = basic_config();
    assert!(c.lists.sources.is_empty());
    assert!(orphan_legacy_sources(&c).is_empty());
}

/// A source that names a real list is not orphaned — the slug and
/// the list id are the same list spelled two ways.
#[test]
fn legacy_source_matching_a_list_by_id_is_silent() {
    let mut c = basic_config();
    let id = c.blocklists[0].id.as_str().to_string();
    c.lists.sources = vec![id.replace('-', "/")];
    assert!(
        orphan_legacy_sources(&c).is_empty(),
        "slug form and id form name one list; got {:?}",
        orphan_legacy_sources(&c)
    );
}

/// Matching by URL too, so a source written as a URL alongside the
/// list that fetches it is not reported twice.
#[test]
fn legacy_source_matching_a_list_by_url_is_silent() {
    let mut c = basic_config();
    c.lists.sources = vec![c.blocklists[0].url.clone()];
    assert!(orphan_legacy_sources(&c).is_empty());
}

/// **Inverted at the plp cutover — this test asserted the opposite,
/// and it was the pin holding F24 in place.** It read
/// `legacy_source_matching_an_untagged_list_is_reported`, on the
/// premise that a list with no tags could not be reached. Tags stopped
/// deciding reachability at S3, so an untagged list is reached by every
/// profile that inherits its `base` — and reporting it as unreachable
/// printed a `warden lists remove` at a working list.
///
/// Kept and inverted rather than deleted: a deletion sprint that leaves
/// its old pins standing is this repo's neutrality-#5 scar, and a test
/// that quietly disappears takes the record of the old rule with it.
#[test]
fn legacy_source_matching_an_untagged_list_is_silent() {
    let mut c = basic_config();
    c.lists.sources = vec![c.blocklists[0].url.clone()];
    assert!(
        orphan_legacy_sources(&c).is_empty(),
        "an untagged list is reachable through its base — got {:?}",
        orphan_legacy_sources(&c)
    );
}

/// A disabled list is never fetched, so a source pointing at one is
/// as inert as a source pointing at nothing.
#[test]
fn legacy_source_matching_a_disabled_list_is_reported() {
    let mut c = basic_config();
    c.blocklists[0].enabled = false;
    c.lists.sources = vec![c.blocklists[0].url.clone()];
    assert_eq!(orphan_legacy_sources(&c).len(), 1);
}

/// The message has to name the source and both halves of the fix —
/// it is the only place this failure is ever explained.
#[test]
fn legacy_source_warning_names_the_source_and_the_fix() {
    let msg = format_legacy_source_not_enforced("privacy/ads");
    assert!(msg.contains("privacy/ads"));
    assert!(msg.contains("warden lists remove privacy/ads"));
    assert!(msg.contains("warden lists add privacy/ads"));
    assert!(!msg.contains("{source}"), "placeholder left unsubstituted");
}

// ── F24 — the two contradictory warnings on one list ────────────
//
// Measured by lane 4a on two configs a single word apart, run
// through `warden config lint`. The `base = "allow"` branch emitted
// BOTH of these about the same list:
//
//   1. "downloaded but filters nothing — no profile, device, group
//      or subnet can reach it"          (LEGACY_SOURCE_NOT_ENFORCED)
//   2. "every profile that does not override it permits every domain
//      this list carries"   (ALLOW_DIRECTION_LIST_STANDING_EXPOSURE)
//
// They cannot both be true, and the false one is the first. The harm
// is not the wording: the repair it prints is `warden lists remove`
// then `warden lists add`, which destroys a working allow-list and
// the exemption the operator configured on purpose.
//
// The asymmetry was manufactured one layer up, in the LOADER:
// `auto_promote_blocklists` stamped `tags = ["uncategorized"]` on a
// `base = deny` list and deliberately not on a `base = allow` one
// (D2), and `orphan_legacy_sources` filtered on `!tags.is_empty()`.
// Past tense throughout: that pass no longer exists in `src/` — see
// the note on guard 3 in `check_device_metadata_vocabulary`.
// So these helpers run the same two steps `config lint` runs, in the
// same order. A test that called `validate_collect` alone would see
// `tags = []` on BOTH branches, fail before the patch for the wrong
// reason, and stop discriminating once the predicate is fixed.

/// The pipeline `warden config lint` runs.
///
/// **It used to run a loader-side promotion first** — the step that
/// stamped `tags = ["uncategorized"]` on every untagged `base = deny`
/// list, and deliberately not on a `base = allow` one, which is what
/// manufactured the F24 asymmetry described above. `plp-s5a` removed
/// the tag field, so there is nothing left to promote and the two
/// branches now differ only in the word under test.
fn lint_warnings(c: ConfigV1) -> Vec<String> {
    let mut warns = AuditWarnings::silent();
    let _ = validate_collect(&c, now(), &mut warns, None, None);
    warns.into_messages()
}

/// The two configs 4a compared. `trust = local` on both so the
/// allow branch is not short-circuited by the unsigned-allow ack
/// ERROR — the only difference that reaches the validator is the
/// one word under test.
fn f24_config(base: BlocklistBase) -> ConfigV1 {
    let mut c = basic_config();
    c.blocklists[0].base = base;
    c.blocklists[0].trust = BlocklistTrust::Local;
    c.lists.sources = vec![c.blocklists[0].url.clone()];
    c
}

#[test]
fn f24_a_list_source_backed_by_an_allow_list_is_not_called_unreachable() {
    let deny = lint_warnings(f24_config(BlocklistBase::Deny));
    let allow = lint_warnings(f24_config(BlocklistBase::Allow));

    // Control arm. The deny branch never made this claim — without
    // it, an assertion on the allow branch alone would also pass
    // against a validator that had simply stopped emitting the
    // warning for everyone.
    assert!(
        !deny.iter().any(|m| m.contains("filters nothing")),
        "control arm broken: the deny branch must never claim the \
         source filters nothing. got: {deny:?}"
    );

    assert!(
        !allow
            .iter()
            .any(|m| m.contains("downloaded but filters nothing")),
        "F24: the source is backed by an enabled allow-direction list \
         that every profile inherits — calling it unreachable is false, \
         and the repair it prints deletes the list. got: {allow:?}"
    );
}

/// The half of the pair that is TRUE must survive. Deleting the
/// false warning by silencing the whole check would pass the test
/// above and leave the operator with no signal at all.
#[test]
fn f24_the_standing_exposure_warning_still_fires_on_the_allow_branch() {
    let allow = lint_warnings(f24_config(BlocklistBase::Allow));
    let expected = format_allow_direction_list_standing_exposure("privacy-ads");
    assert!(
        allow.contains(&expected),
        "the true half of the F24 pair must still be emitted. \
         expected {expected:?}, got: {allow:?}"
    );
}

/// The destructive repair must not be printed about a list that
/// works. This is the operator-facing harm, asserted directly:
/// `warden lists remove` on a working allow-list drops the
/// exemption, and the next refresh does not bring it back.
#[test]
fn f24_no_remove_then_add_suggestion_for_a_working_allow_list() {
    let allow = lint_warnings(f24_config(BlocklistBase::Allow));
    assert!(
        !allow.iter().any(|m| m.contains("warden lists remove")),
        "a working allow-list must never be pointed at `lists remove`. \
         got: {allow:?}"
    );
}

// ── Sprint B T4 — auto-promote validator pass ─────────────────

// ── tag_model_consolidation §3.2 — duplicate source URL ────────

/// D3 as it exists on the live CT: two enabled lists pointing at
/// one source. They share a cache file and its ETag, so this must
/// be reported — and reported as a WARN, never an error.
#[test]
fn tmc_duplicate_url_groups_reports_both_ids() {
    let mut c = basic_config();
    c.blocklists = vec![blocklist("privacy-ads"), blocklist("ads")];
    c.blocklists[0].url = "https://lists.purge.cc/ads.txt".into();
    c.blocklists[1].url = "https://lists.purge.cc/ads.txt".into();
    let groups = duplicate_url_groups(&c);
    assert_eq!(groups.len(), 1, "one collision expected: {groups:?}");
    assert_eq!(groups[0].1, vec!["privacy-ads", "ads"]);
}

/// The point of the canonical key: a trailing slash / uppercase
/// host / default port are the SAME source, and the byte-exact
/// comparison this replaces missed all three.
#[test]
fn tmc_duplicate_url_groups_sees_through_cosmetic_url_differences() {
    let mut c = basic_config();
    c.blocklists = vec![blocklist("a"), blocklist("b"), blocklist("c")];
    c.blocklists[0].url = "https://lists.purge.cc/ads.txt".into();
    c.blocklists[1].url = "https://Lists.Purge.CC:443/ads.txt/".into();
    c.blocklists[2].url = "HTTPS://lists.purge.cc/ads.txt".into();
    let groups = duplicate_url_groups(&c);
    assert_eq!(groups.len(), 1, "{groups:?}");
    assert_eq!(groups[0].1, vec!["a", "b", "c"]);
}

/// Different paths are different sources — no false positive.
#[test]
fn tmc_duplicate_url_groups_silent_on_distinct_urls() {
    let mut c = basic_config();
    c.blocklists = vec![blocklist("ads"), blocklist("tracking")];
    c.blocklists[0].url = "https://lists.purge.cc/ads.txt".into();
    c.blocklists[1].url = "https://lists.purge.cc/tracking.txt".into();
    assert!(duplicate_url_groups(&c).is_empty());
}

/// A disabled twin downloads nothing, touches no cache file and
/// burns no bitmask slot — warning about a config the operator has
/// already neutralised is noise.
#[test]
fn tmc_duplicate_url_groups_ignores_disabled_lists() {
    let mut c = basic_config();
    c.blocklists = vec![blocklist("live"), blocklist("parked")];
    c.blocklists[0].url = "https://lists.purge.cc/ads.txt".into();
    c.blocklists[1].url = "https://lists.purge.cc/ads.txt".into();
    c.blocklists[1].enabled = false;
    assert!(duplicate_url_groups(&c).is_empty());
}

/// §2.1 hard constraint: the live config ALREADY contains a
/// duplicate. If this ever became an error, the daemon would refuse
/// to start and a household would lose DNS. Pin it as non-fatal.
#[test]
fn tmc_duplicate_url_is_warn_never_a_load_error() {
    let mut c = basic_config();
    c.blocklists = vec![blocklist("privacy-ads"), blocklist("ads")];
    c.blocklists[0].url = "https://lists.purge.cc/ads.txt".into();
    c.blocklists[1].url = "https://lists.purge.cc/ads.txt".into();
    let mut errs: Vec<ConfigError> = Vec::new();
    check_blocklists(&c, &mut errs, &mut AuditWarnings::emitting(), None);
    assert!(
        errs.is_empty(),
        "duplicate URLs must never be fatal at load: {errs:?}"
    );
}

// ── the W2.1 truth table, row by row ───────────────────────────
//
// | kind  | trust           | accept_unsigned_allow | outcome            |
// |-------|-----------------|-----------------------|--------------------|
// | deny  | any             | —                     | OK                 |
// | allow | local           | —                     | OK                 |
// | allow | remote-unsigned | false                 | ERROR (needs ack)  |
// | allow | remote-unsigned | true                  | WARN, loads        |
// | allow | signed          | any                   | ERROR (signed)     |
//
// Helper: run the full validator and hand back both channels, so a
// row can assert on what did NOT fire as well as what did. Several
// of these rows are about absence.
fn validate_rows(c: &ConfigV1) -> (Vec<ConfigError>, Vec<String>) {
    let mut warns = AuditWarnings::silent();
    let errs = validate_collect(c, now(), &mut warns, None, None)
        .err()
        .unwrap_or_default();
    (errs, warns.into_messages())
}

// ── §4.66 L1 — [[labels]] ──────────────────────────────────────

fn label(id: &str, kind: LabelKind, display_name: &str) -> Label {
    Label {
        id: Id::new(id).unwrap(),
        kind,
        display_name: display_name.into(),
        description: None,
    }
}

/// R1 — the pair is the identity, so the same id under two kinds is
/// legal. The differential against the duplicate test below.
#[test]
fn labels_same_id_under_two_kinds_is_legal() {
    let mut c = basic_config();
    c.labels = vec![
        label("personal", LabelKind::Department, "Personal"),
        label("personal", LabelKind::DeviceType, "Personal"),
    ];
    let (errs, _) = validate_rows(&c);
    assert!(errs.is_empty(), "got: {errs:?}");
}

/// R1 — the same id under the SAME kind is a duplicate.
#[test]
fn labels_duplicate_pair_is_an_error() {
    let mut c = basic_config();
    c.labels = vec![
        label("personal", LabelKind::Department, "Personal"),
        label("personal", LabelKind::Department, "Personale"),
    ];
    let (errs, _) = validate_rows(&c);
    assert!(
        errs.iter()
            .any(|e| matches!(e, ConfigError::DuplicateId(_))),
        "got: {errs:?}"
    );
}

/// R3 — the near-duplicate that motivated the whole entity.
/// `Personal` is declared, `Persona` is not, so only the second
/// device warns.
#[test]
fn labels_warn_on_a_value_outside_the_vocabulary() {
    let mut c = basic_config();
    c.labels = vec![label("personal", LabelKind::Department, "Personal")];
    let mut ok = device("good", "10.0.0.1", None);
    ok.department = Some("Personal".into());
    let mut typo = device("typo", "10.0.0.2", None);
    typo.department = Some("Persona".into());
    c.devices = vec![ok, typo];

    let (errs, warns) = validate_rows(&c);
    assert!(errs.is_empty(), "a stray value must never fail the load");
    let hits: Vec<&String> = warns
        .iter()
        .filter(|w| w.contains("not declared in the [[labels]] vocabulary"))
        .collect();
    assert_eq!(hits.len(), 1, "exactly the typo must warn. got: {warns:?}");
    assert!(hits[0].contains("Persona"), "got: {}", hits[0]);
    assert!(hits[0].contains("department"), "got: {}", hits[0]);
}

/// R3 — the id also satisfies the vocabulary, not just the display
/// name. Both spellings of the same label are inside.
#[test]
fn labels_accept_the_id_as_well_as_the_display_name() {
    let mut c = basic_config();
    c.labels = vec![label("operator", LabelKind::Owner, "Operator")];
    let mut by_id = device("a", "10.0.0.1", None);
    by_id.owner = Some("operator".into());
    let mut by_name = device("b", "10.0.0.2", None);
    by_name.owner = Some("Operator".into());
    c.devices = vec![by_id, by_name];

    let (_, warns) = validate_rows(&c);
    assert!(
        !warns
            .iter()
            .any(|w| w.contains("not declared in the [[labels]] vocabulary")),
        "got: {warns:?}"
    );
}

/// R3 — the guard that keeps this diagnostic readable. Every config
/// on disk today has zero labels and plenty of metadata; if an empty
/// vocabulary meant "nothing is legal", shipping the feature would
/// paint every existing deployment red at every load.
#[test]
fn labels_empty_vocabulary_warns_about_nothing() {
    let mut c = basic_config();
    let mut d = device("a", "10.0.0.1", None);
    d.owner = Some("Operator".into());
    d.device_type = Some("Apple TV".into());
    d.department = Some("Persona".into());
    c.devices = vec![d];
    assert!(c.labels.is_empty());

    let (errs, warns) = validate_rows(&c);
    assert!(errs.is_empty(), "got: {errs:?}");
    assert!(
        !warns
            .iter()
            .any(|w| w.contains("not declared in the [[labels]] vocabulary")),
        "got: {warns:?}"
    );
}

/// R3 — a vocabulary declared for one kind must not police another.
/// Declaring owners says nothing about which departments are legal.
#[test]
fn labels_one_kinds_vocabulary_does_not_police_another() {
    let mut c = basic_config();
    c.labels = vec![label("operator", LabelKind::Owner, "Operator")];
    let mut d = device("a", "10.0.0.1", None);
    d.owner = Some("Operator".into());
    d.department = Some("Persona".into()); // no department vocabulary
    c.devices = vec![d];

    let (_, warns) = validate_rows(&c);
    assert!(
        !warns
            .iter()
            .any(|w| w.contains("not declared in the [[labels]] vocabulary")),
        "got: {warns:?}"
    );
}

/// The WARN names the command that would adopt the value — warden
/// must never adopt it itself.
#[test]
fn device_metadata_unknown_label_string_is_actionable() {
    let s = format_device_metadata_unknown_label("iphone", "owner", "Operator", "owner");
    assert!(
        s.contains("device \"iphone\".owner = \"Operator\""),
        "got: {s}"
    );
    assert!(s.contains("warden label add"), "got: {s}");
    assert!(s.contains("--kind owner"), "got: {s}");
    assert!(!s.contains('{'), "every placeholder must be filled: {s}");
}

// ── §4.66 L5 — the `tag` kind ──────────────────────────────────

/// GUARD 1, the other half — the constraint belongs to the tag
/// namespace, not to the string. The very ids refused above are
/// ordinary owners.
#[test]
fn labels_the_slug_constraint_binds_only_the_tag_kind() {
    let over_long = "a".repeat(33);
    let mut c = basic_config();
    c.labels = vec![
        label("4chan", LabelKind::Owner, "4chan"),
        label(&over_long, LabelKind::Department, "Long"),
    ];
    let (errs, _) = validate_rows(&c);
    assert!(errs.is_empty(), "got: {errs:?}");
}

/// Row 3 — the default posture. An operator who flips a remote list
/// to allow-direction without saying anything is refused, and told
/// what the risk is rather than just that the combination is
/// forbidden.
#[test]
fn unsigned_allow_without_ack_is_refused() {
    let mut c = basic_config();
    // Default trust is RemoteUnsigned → flipping to Allow trips it.
    c.blocklists[0].base = BlocklistBase::Allow;
    let (errs, _) = validate_rows(&c);
    assert!(
        errs.iter().any(|e| matches!(
            e,
            ConfigError::UnsignedAllowListRequiresAck(ctx)
                if ctx.reason.contains("'privacy-ads'")
                   && ctx.reason.contains("'remote-unsigned'")
        )),
        "expected UnsignedAllowListRequiresAck, got: {errs:?}"
    );
}

// ── plp-s4b: the same consent property at OVERRIDE scope ────────

/// Put a `lists` override on the default profile naming blocklist 0.
fn with_override(policy: ListPolicy) -> ConfigV1 {
    let mut c = basic_config();
    let id: Id = "privacy-ads".try_into().expect("valid id");
    c.profiles
        .get_mut("default")
        .expect("default profile")
        .lists
        .insert(id, policy);
    c
}

/// `plp-s4b` — an `allow` override on a remote-unsigned list with no ack
/// is refused at load, naming BOTH the profile and the list.
///
/// The list's own `base` stays `deny`, so `UNSIGNED_ALLOW_LIST_REQUIRES_ACK`
/// at list scope does not fire: before this check the config loaded clean,
/// with a live allow-direction override and consent declared nowhere.
#[test]
fn plp_s4b_unconsented_allow_override_is_refused_at_load() {
    let c = with_override(ListPolicy::Allow);
    assert_eq!(
        c.blocklists[0].base,
        BlocklistBase::Deny,
        "the list-scope check must not be what fires here"
    );
    let (errs, _) = validate_rows(&c);
    let hit = errs
        .iter()
        .find(|e| matches!(e, ConfigError::UnsignedAllowListRequiresAck(_)))
        .unwrap_or_else(|| panic!("expected a refusal, got: {errs:?}"));
    let ConfigError::UnsignedAllowListRequiresAck(ctx) = hit else {
        unreachable!()
    };
    assert!(
        ctx.reason.contains("privacy-ads"),
        "must name the list: {}",
        ctx.reason
    );
    assert!(
        ctx.reason.contains("default"),
        "must name the PROFILE too — the ack lives on the list's row but \
         the offence lives in the profile, and an error naming only the \
         list sends the operator to stare at a row that looks fine: {}",
        ctx.reason
    );
    assert!(
        ctx.suggestion.is_some(),
        "a refusal must name the knob that unblocks it"
    );
}

/// The control arm. Same override, same list, the operator's declaration
/// on the row: it loads.
///
/// Without this the test above would stay green on a check that refused
/// every override of a remote list regardless of consent.
#[test]
fn plp_s4b_a_consented_allow_override_loads() {
    let mut c = with_override(ListPolicy::Allow);
    c.blocklists[0].accept_unsigned_allow = true;
    let (errs, _) = validate_rows(&c);
    assert!(
        !errs
            .iter()
            .any(|e| matches!(e, ConfigError::UnsignedAllowListRequiresAck(_))),
        "consent on the row must satisfy the override too, got: {errs:?}"
    );
}

/// `trust = local` is the operator's own file — no third party, nothing
/// to consent to. Pins that the gate keys on trust, not on the word
/// "allow".
#[test]
fn plp_s4b_an_allow_override_on_a_local_list_needs_no_ack() {
    let mut c = with_override(ListPolicy::Allow);
    c.blocklists[0].trust = BlocklistTrust::Local;
    let (errs, _) = validate_rows(&c);
    assert!(
        !errs
            .iter()
            .any(|e| matches!(e, ConfigError::UnsignedAllowListRequiresAck(_))),
        "got: {errs:?}"
    );
}

/// `Deny` and `Ignore` narrow what the profile permits, so they pay
/// nothing — on the very list whose `Allow` is refused.
///
/// Without this arm the refusal test would also pass on a check that
/// refused every override of an unconsented remote list, which is a
/// different bug wearing the same green.
#[test]
fn plp_s4b_deny_and_ignore_overrides_are_not_gated_at_load() {
    for policy in [ListPolicy::Deny, ListPolicy::Ignore] {
        let c = with_override(policy);
        let (errs, _) = validate_rows(&c);
        assert!(
            !errs
                .iter()
                .any(|e| matches!(e, ConfigError::UnsignedAllowListRequiresAck(_))),
            "{policy:?} must not be gated, got: {errs:?}"
        );
    }
}

/// A disabled list is still gated. It holds no source bit today, but
/// `warden blocklist set <id> --enabled true` flips that back with
/// nothing to re-run the gate — so the declaration is what is checked,
/// not its current reachability.
#[test]
fn plp_s4b_a_disabled_list_does_not_exempt_the_override() {
    let mut c = with_override(ListPolicy::Allow);
    c.blocklists[0].enabled = false;
    let (errs, _) = validate_rows(&c);
    assert!(
        errs.iter()
            .any(|e| matches!(e, ConfigError::UnsignedAllowListRequiresAck(_))),
        "a disabled list must not buy an exemption, got: {errs:?}"
    );
}

/// Row 3, the operator-facing half: the refusal carries the frozen
/// text and a suggestion naming the field that unblocks it. An
/// error that refuses without saying which knob to turn is how this
/// gate earned its reputation.
#[test]
fn unsigned_allow_refusal_carries_frozen_text_and_suggestion() {
    let mut c = basic_config();
    c.blocklists[0].base = BlocklistBase::Allow;
    let (errs, _) = validate_rows(&c);
    let ctx = errs
        .iter()
        .find_map(|e| match e {
            ConfigError::UnsignedAllowListRequiresAck(ctx) => Some(ctx),
            _ => None,
        })
        .expect("UnsignedAllowListRequiresAck present");
    assert_eq!(
        ctx.reason,
        format_unsigned_allow_list_requires_ack("privacy-ads", BlocklistTrust::RemoteUnsigned)
    );
    assert_eq!(ctx.entity.as_deref(), Some("blocklists.privacy-ads"));
    assert_eq!(
        ctx.suggestion.as_deref(),
        Some("set accept_unsigned_allow = true on this list if you trust its publisher, or set base = \"deny\" if this is a deny-direction list")
    );
}

// ── the sentinel is not an answer to "which tag?" ──────────────
//
// The CLI verbs and both TUI paths refuse this before writing. This
// pass is the backstop for the surface none of them can see: a
// hand-edited TOML, a file restored from a backup taken before the
// gates existed, or a bundle arriving on a cluster secondary. It
// lives in `check_blocklists`, which `validate_collect` runs, so the
// initial load, the daemon's reload and `cluster::apply_bundle` all
// inherit it rather than each needing to remember.

/// End to end through the real parse-promote-validate path, from
/// TOML an operator could have typed. The struct-level tests above
/// prove the predicate; this proves the file never becomes a running
/// config — which is the property the CLI and TUI gates cannot
/// deliver, because neither of them is in the room when someone
/// opens the file in an editor.
#[test]
fn a_hand_written_allow_list_tagged_with_the_sentinel_now_loads() {
    let src = r#"
schema_version = 3

[upstream]
servers = ["192.0.2.1:53"]

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[[blocklists]]
id = "guest-exemptions"
display_name = "Guest exemptions"
url = "https://example.com/guests.txt"
format = "domains"
base = "allow"
trust = "local"
tags = ["uncategorized"]
"#;
    // `plp-s3` §2.5: the hand-edited path was the ONLY one this ERROR
    // still guarded once the write verbs refused first. Both are retired
    // together — a load refusal for a reason the same binary's verbs no
    // longer apply is worse than no refusal, because the operator has no
    // way to see why the two disagree.
    super::super::load::load_from_str(src, None, now())
        .expect("the system-tag refusal is retired; this config must load");
}

/// The same file with the direction flipped loads. Together with the
/// test above this pins that the refusal is about the pairing, not
/// about the tag or the file.
#[test]
fn the_same_hand_written_list_loads_as_a_deny_list() {
    let src = r#"
schema_version = 3

[upstream]
servers = ["192.0.2.1:53"]

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[[blocklists]]
id = "guest-exemptions"
display_name = "Guest exemptions"
url = "https://example.com/guests.txt"
format = "domains"
base = "deny"
trust = "local"
tags = ["uncategorized"]
"#;
    super::super::load::load_from_str(src, None, now())
        .expect("a deny-list filed under the sentinel is the ordinary case");
}

/// Row 4 — the whole point of the change. Consent declared: the
/// config LOADS, and the warning fires anyway so the risk stays
/// visible at every single load rather than being acknowledged once
/// and forgotten.
#[test]
fn unsigned_allow_with_ack_loads_and_warns() {
    let mut c = basic_config();
    c.blocklists[0].base = BlocklistBase::Allow;
    c.blocklists[0].accept_unsigned_allow = true;
    let (errs, warns) = validate_rows(&c);
    assert!(
        errs.is_empty(),
        "declared consent must load, got errors: {errs:?}"
    );
    assert!(
        warns.contains(&format_unsigned_allow_list_accepted("privacy-ads")),
        "expected the acceptance WARN, got: {warns:?}"
    );
}

/// Row 2 — a local file is authored by the operator, so there is no
/// third party to trust and nothing to accept. It must stay silent:
/// warning here would train operators to ignore the warning that
/// matters.
#[test]
fn allow_with_local_trust_loads_without_the_unsigned_warn() {
    let mut c = basic_config();
    c.blocklists[0].base = BlocklistBase::Allow;
    c.blocklists[0].trust = BlocklistTrust::Local;
    let (errs, warns) = validate_rows(&c);
    assert!(
        errs.is_empty(),
        "kind=allow + trust=local must load: {errs:?}"
    );
    assert!(
        !warns.iter().any(|w| w.contains("is remote and unsigned")),
        "a local allow-list is not remote: {warns:?}"
    );
}

/// Row 2 again, with the ack set for good measure — a redundant
/// flag on a local list must not conjure a warning about a remote
/// risk that does not exist.
#[test]
fn ack_on_a_local_allow_list_is_inert() {
    let mut c = basic_config();
    c.blocklists[0].base = BlocklistBase::Allow;
    c.blocklists[0].trust = BlocklistTrust::Local;
    c.blocklists[0].accept_unsigned_allow = true;
    let (errs, warns) = validate_rows(&c);
    assert!(errs.is_empty(), "must still load: {errs:?}");
    assert!(
        !warns.iter().any(|w| w.contains("is remote and unsigned")),
        "ack must be inert on a local list: {warns:?}"
    );
}

/// Row 5 co-occurrence — unchanged behaviour. `allow` + `signed`
/// with no ack emits BOTH errors, exactly as it did before the gate
/// fell, so the operator sees the whole picture in one pass.
#[test]
fn allow_plus_signed_without_ack_emits_both_errors() {
    let mut c = basic_config();
    c.blocklists[0].base = BlocklistBase::Allow;
    c.blocklists[0].trust = BlocklistTrust::Signed;
    let (errs, _) = validate_rows(&c);
    assert!(
        errs.iter()
            .any(|e| matches!(e, ConfigError::UnsignedAllowListRequiresAck(_))),
        "expected the ack error alongside the signed one: {errs:?}"
    );
    assert!(
        errs.iter()
            .any(|e| matches!(e, ConfigError::TrustSignedNotYetSupported(_))),
        "expected TrustSignedNotYetSupported: {errs:?}"
    );
}

/// Row 5 with consent — a state the contract's table does not
/// cover, so it is pinned here rather than left to be discovered.
///
/// `signed` is still parked, so the config is still refused; that
/// part is settled. The open question was the WARN, and it must NOT
/// fire: its text says the list "is remote and unsigned", which of
/// a `trust = signed` list is simply false. A warning that lies is
/// worse than a missing one — it is the sentence an operator quotes
/// back when the audit asks why they ignored it.
#[test]
fn allow_plus_signed_with_ack_is_still_refused_and_never_warns_unsigned() {
    let mut c = basic_config();
    c.blocklists[0].base = BlocklistBase::Allow;
    c.blocklists[0].trust = BlocklistTrust::Signed;
    c.blocklists[0].accept_unsigned_allow = true;
    let (errs, warns) = validate_rows(&c);
    assert!(
        errs.iter()
            .any(|e| matches!(e, ConfigError::TrustSignedNotYetSupported(_))),
        "signed stays parked regardless of consent: {errs:?}"
    );
    assert!(
        !errs
            .iter()
            .any(|e| matches!(e, ConfigError::UnsignedAllowListRequiresAck(_))),
        "consent satisfies the ack gate even on signed: {errs:?}"
    );
    assert!(
        !warns.iter().any(|w| w.contains("is remote and unsigned")),
        "must not claim a signed list is unsigned: {warns:?}"
    );
}

/// Row 1 — the untouched majority. A deny-direction list is the
/// default and this whole pass must stay invisible to it, ack set
/// or not.
#[test]
fn deny_direction_never_touched_by_the_ack_gate() {
    for ack in [false, true] {
        let mut c = basic_config();
        c.blocklists[0].base = BlocklistBase::Deny;
        c.blocklists[0].accept_unsigned_allow = ack;
        let (errs, warns) = validate_rows(&c);
        assert!(errs.is_empty(), "deny must load (ack={ack}): {errs:?}");
        assert!(
            !warns.iter().any(|w| w.contains("is remote and unsigned")),
            "deny must not warn (ack={ack}): {warns:?}"
        );
    }
}

#[test]
fn trust_signed_alone_emits_only_signed_error() {
    // base = Deny + trust=Signed → only the parking-lot error fires;
    // the W2.1 (allow) check does NOT. S50 T2 also pins the
    // emitted `ErrorContext::reason` to the frozen
    // [`TRUST_SIGNED_NOT_YET_SUPPORTED`] string byte-for-byte; the
    // S49 T2 placeholder no longer leaks through.
    let mut c = basic_config();
    c.blocklists[0].trust = BlocklistTrust::Signed;
    let errs = validate(&c, now()).unwrap_err();
    let has_signed = errs
        .iter()
        .any(|e| matches!(e, ConfigError::TrustSignedNotYetSupported(_)));
    let has_allow = errs
        .iter()
        .any(|e| matches!(e, ConfigError::UnsignedAllowListRequiresAck(_)));
    assert!(
        has_signed,
        "expected TrustSignedNotYetSupported in: {errs:?}"
    );
    assert!(
        !has_allow,
        "UnsignedAllowListRequiresAck should NOT fire on kind=Deny: {errs:?}"
    );

    // Byte-for-byte: the offending error must carry the frozen
    // string verbatim (entity field localises which blocklist
    // tripped, but the reason text matches §9 row 5 exactly).
    let signed = errs
        .iter()
        .find_map(|e| match e {
            ConfigError::TrustSignedNotYetSupported(ctx) => Some(ctx),
            _ => None,
        })
        .expect("TrustSignedNotYetSupported variant present");
    assert_eq!(signed.reason, TRUST_SIGNED_NOT_YET_SUPPORTED);
    assert_eq!(signed.entity.as_deref(), Some("blocklists.privacy-ads"));
}

// ── §4.8 §2/2 T1: per-profile ECS validator ────────────────

fn profile_with_ecs(ecs: super::super::ProfileEcsConfig) -> Profile {
    Profile {
        ecs: Some(ecs),
        ..profile_default()
    }
}

#[test]
fn profile_ecs_subnet_prefix_v4_too_large_rejected() {
    let mut c = basic_config();
    c.profiles.insert(
        "tweaked".into(),
        profile_with_ecs(super::super::ProfileEcsConfig {
            mode: Some(super::super::super::settings::EcsMode::Subnet),
            source_prefix_v4: Some(33),
            source_prefix_v6: None,
        }),
    );
    let errs = validate(&c, now()).unwrap_err();
    assert!(
        errs.iter().any(|e| matches!(
            e,
            ConfigError::ValidationFailed(ctx)
                if ctx.reason.contains("source_prefix_v4") && ctx.reason.contains("33")
        )),
        "expected v4 prefix-range error, got: {errs:?}"
    );
}

#[test]
fn profile_ecs_subnet_prefix_v6_too_large_rejected() {
    let mut c = basic_config();
    c.profiles.insert(
        "tweaked".into(),
        profile_with_ecs(super::super::ProfileEcsConfig {
            mode: Some(super::super::super::settings::EcsMode::Subnet),
            source_prefix_v4: None,
            source_prefix_v6: Some(129),
        }),
    );
    let errs = validate(&c, now()).unwrap_err();
    assert!(
        errs.iter().any(|e| matches!(
            e,
            ConfigError::ValidationFailed(ctx)
                if ctx.reason.contains("source_prefix_v6") && ctx.reason.contains("129")
        )),
        "expected v6 prefix-range error, got: {errs:?}"
    );
}

/// cfg-validator-05 (rev-2606): a set-but-out-of-range prefix is
/// rejected even when `mode` is inherited (None) — pre-fix it loaded
/// clean and `EdnsClientSubnet::new(..).ok()` silently disabled ECS
/// for the profile at query time.
#[test]
fn profile_ecs_inherited_mode_out_of_range_prefix_rejected() {
    let mut c = basic_config();
    c.profiles.insert(
        "tweaked".into(),
        profile_with_ecs(super::super::ProfileEcsConfig {
            mode: None,
            source_prefix_v4: Some(200),
            source_prefix_v6: None,
        }),
    );
    let errs = validate(&c, now()).unwrap_err();
    assert!(
        errs.iter().any(|e| matches!(
            e,
            ConfigError::ValidationFailed(ctx)
                if ctx.reason.contains("source_prefix_v4") && ctx.reason.contains("200")
        )),
        "expected v4 prefix-range error with inherited mode, got: {errs:?}"
    );

    // In-range overrides with inherited mode stay valid.
    c.profiles.insert(
        "tweaked".into(),
        profile_with_ecs(super::super::ProfileEcsConfig {
            mode: None,
            source_prefix_v4: Some(24),
            source_prefix_v6: Some(56),
        }),
    );
    assert!(validate(&c, now()).is_ok());
}

#[test]
fn profile_ecs_subnet_valid_prefixes_pass() {
    let mut c = basic_config();
    c.profiles.insert(
        "ok".into(),
        profile_with_ecs(super::super::ProfileEcsConfig {
            mode: Some(super::super::super::settings::EcsMode::Subnet),
            source_prefix_v4: Some(24),
            source_prefix_v6: Some(56),
        }),
    );
    assert!(validate(&c, now()).is_ok());
}

#[test]
fn profile_ecs_coarse_rejects_out_of_range_prefixes() {
    // cfg-validator-05 (rev-2606): pre-fix, coarse ignored explicit
    // prefix values entirely (out-of-range accepted as inert). A set
    // value is now range-checked in every mode — coarse hardcodes
    // /24 + /56 at runtime, but a broken override would arm itself
    // the moment the operator switches the mode to subnet.
    let mut c = basic_config();
    c.profiles.insert(
        "coarse-anyway".into(),
        profile_with_ecs(super::super::ProfileEcsConfig {
            mode: Some(super::super::super::settings::EcsMode::Coarse),
            source_prefix_v4: Some(99),
            source_prefix_v6: Some(200),
        }),
    );
    let errs = validate(&c, now()).unwrap_err();
    assert!(
        errs.iter().any(|e| matches!(
            e,
            ConfigError::ValidationFailed(ctx) if ctx.reason.contains("source_prefix_v4")
        )),
        "coarse + out-of-range prefix must be rejected: {errs:?}"
    );

    // In-range overrides under coarse stay valid (inert but legal).
    c.profiles.insert(
        "coarse-anyway".into(),
        profile_with_ecs(super::super::ProfileEcsConfig {
            mode: Some(super::super::super::settings::EcsMode::Coarse),
            source_prefix_v4: Some(24),
            source_prefix_v6: Some(56),
        }),
    );
    assert!(validate(&c, now()).is_ok());
}

#[test]
fn profile_ecs_off_rejects_out_of_range_prefixes() {
    // cfg-validator-05 (rev-2606): same as coarse — `off` ignores the
    // fields at runtime, but a set-but-broken value is rejected at
    // lint so it cannot lie dormant.
    let mut c = basic_config();
    c.profiles.insert(
        "off".into(),
        profile_with_ecs(super::super::ProfileEcsConfig {
            mode: Some(super::super::super::settings::EcsMode::Off),
            source_prefix_v4: Some(99),
            source_prefix_v6: Some(200),
        }),
    );
    let errs = validate(&c, now()).unwrap_err();
    assert!(
        errs.iter().any(|e| matches!(
            e,
            ConfigError::ValidationFailed(ctx) if ctx.reason.contains("source_prefix_v6")
        )),
        "off + out-of-range prefix must be rejected: {errs:?}"
    );
}

#[test]
fn profile_ecs_absent_passes() {
    let mut c = basic_config();
    c.profiles
        .insert("none".into(), profile_with_ecs(Default::default()));
    // ecs subtable Some but every field None → no validation fires.
    assert!(validate(&c, now()).is_ok());
}

// ── §4.13 resource_budget ─────────────────────────────────

#[test]
fn resource_budget_tick_secs_zero_rejected() {
    let mut c = basic_config();
    c.resource_budget.tick_secs = 0;
    let errs = validate(&c, now()).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| matches!(e, ConfigError::ValidationFailed(ctx)
            if ctx.entity.as_deref() == Some("resource_budget.tick_secs"))),
        "expected ValidationFailed on resource_budget.tick_secs, got {errs:?}",
    );
}

#[test]
fn resource_budget_rss_warn_mb_zero_rejected() {
    let mut c = basic_config();
    c.resource_budget.rss_warn_mb = 0;
    let errs = validate(&c, now()).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| matches!(e, ConfigError::ValidationFailed(ctx)
            if ctx.entity.as_deref() == Some("resource_budget.rss_warn_mb"))),
        "expected ValidationFailed on resource_budget.rss_warn_mb, got {errs:?}",
    );
}

#[test]
fn resource_budget_defaults_pass() {
    // basic_config() inherits defaults via `..ConfigV1::test_scaffold()`,
    // which calls `ResourceBudgetConfig::default()` → tick_secs = 5,
    // rss_warn_mb derived. Validation must accept it.
    assert!(validate(&basic_config(), now()).is_ok());
}

// ── N1 — `[anti_bypass] enabled = true` with no domain source ──
//
// `AntiBypassConfig::default()` is `enabled = true, extra_domains =
// []`, and `warden init` never writes the section — so this is the
// state of essentially every install, including both live CTs. The
// set is empty, `SecurityLayer::from_config` drops the checker to
// `None`, and the operator's config asserts a protection that does
// not exist. Dropping it is correct (see the handler); being silent
// about it is not.

/// Collect the audit WARNs a config raises, without touching the
/// process-global tracing dispatcher (see [`AuditWarnings::silent`]).
fn warns_for(c: &ConfigV1) -> Vec<String> {
    let mut warns = AuditWarnings::silent();
    let _ = validate_collect(c, now(), &mut warns, None, None);
    warns.into_messages()
}

#[test]
fn n1_anti_bypass_enabled_with_no_domains_warns() {
    let c = basic_config();
    assert!(
        c.anti_bypass.enabled && c.anti_bypass.extra_domains.is_empty(),
        "precondition: the default shape is enabled-with-no-domains"
    );
    let warns = warns_for(&c);
    assert!(
        warns.iter().any(|w| w.contains("has no domains to block")),
        "expected ANTI_BYPASS_ENABLED_NO_DOMAINS, got: {warns:?}"
    );
}

// ── lint-warn-no-default-profile ──────────────────────────────────
//
// A config with no `default_profile` is VALID and the daemon then
// REFUSES every unmatched query. That is a legitimate posture, so the
// diagnostic is a WARN; the defect was that it was silent, and a fresh
// install linted clean while answering nothing.

#[test]
fn no_default_profile_warns_that_level5_refuses_everything() {
    let c = basic_config();
    assert!(
        c.server.default_profile.is_none() && c.subnets.is_empty(),
        "precondition: this is the fresh-install shape the footgun needs"
    );
    assert!(
        validate(&c, now()).is_ok(),
        "it must stay VALID — a refusal here would break every operator \
         who chose the restrictive posture on purpose"
    );
    let warns = warns_for(&c);
    assert!(
        warns
            .iter()
            .any(|w| w.contains("will get REFUSED for every query")),
        "expected NO_DEFAULT_PROFILE_REFUSES_UNMATCHED, got: {warns:?}"
    );
}

#[test]
fn a_set_default_profile_is_silent() {
    let mut c = basic_config();
    c.server.default_profile = Some(Id::new("default").unwrap());
    let warns = warns_for(&c);
    assert!(
        !warns.iter().any(|w| w.contains("will get REFUSED")),
        "level 5 resolves — nothing to warn about: {warns:?}"
    );
}

/// The suppression arm. Catch-alls in BOTH families answer level 4 for
/// every client, so level 5 is unreachable and the warning would be
/// noise.
///
/// Without this test the check could be `default_profile.is_none()`
/// alone and still pass the two above — i.e. the catch-all branch would
/// be unproven, which is how a diagnostic starts crying wolf.
#[test]
fn a_catch_all_subnet_suppresses_the_level5_warning() {
    let mut c = basic_config();
    c.subnets = vec![Subnet {
        id: Id::new("everything").unwrap(),
        display_name: "Everything".into(),
        cidrs: vec!["0.0.0.0/0".into(), "::/0".into()],
        profile: Id::new("default").unwrap(),
        priority: 0,
    }];
    let warns = warns_for(&c);
    assert!(
        !warns.iter().any(|w| w.contains("will get REFUSED")),
        "/0 in both families covers level 4, so level 5 never runs: {warns:?}"
    );
}

/// The defect this split exists for. A v4 default route says nothing
/// about IPv6 clients — `Cidr::contains` is family-strict — so they do
/// still fall through to level 5 and get REFUSED. Suppressing the
/// warning on the v4 entry alone is the diagnostic lying about the one
/// condition it exists to report, on the ordinary shape of a dual-stack
/// LAN handing out SLAAC addresses.
#[test]
fn v4_catch_all_alone_still_warns_for_v6() {
    let mut c = basic_config();
    c.subnets = vec![Subnet {
        id: Id::new("v4-only").unwrap(),
        display_name: "v4 only".into(),
        cidrs: vec!["0.0.0.0/0".into()],
        profile: Id::new("default").unwrap(),
        priority: 0,
    }];
    let warns = warns_for(&c);
    assert!(
        warns
            .iter()
            .any(|w| w.contains("will get REFUSED for every query")),
        "IPv6 is uncovered, so the warning must still fire: {warns:?}"
    );

    // And symmetrically: a v6-only default route leaves IPv4 on level 5.
    c.subnets[0].cidrs = vec!["::/0".into()];
    let warns = warns_for(&c);
    assert!(
        warns
            .iter()
            .any(|w| w.contains("will get REFUSED for every query")),
        "IPv4 is uncovered, so the warning must still fire: {warns:?}"
    );
}

#[test]
fn cidr_catch_all_detection_is_exact() {
    assert_eq!(catch_all_family("0.0.0.0/0"), Some(CatchAll::V4));
    assert_eq!(catch_all_family("::/0"), Some(CatchAll::V6));
    assert_eq!(catch_all_family(" 0.0.0.0/0 "), Some(CatchAll::V4));
    // A /0 is the only default route; nothing else may suppress the warn.
    assert_eq!(catch_all_family("10.0.0.0/8"), None);
    assert_eq!(catch_all_family("0.0.0.0/24"), None);
    assert_eq!(catch_all_family("fd00::/8"), None);
    // Unparseable entries are check_subnets' error, not a catch-all.
    assert_eq!(catch_all_family("not-a-cidr"), None);
}

/// `Cidr::parse` reads the prefix with `str::parse::<u8>`, which accepts
/// `00`. The textual `ends_with("/0")` test this replaced did not, so a
/// real default route was read as an ordinary subnet — a spurious WARN,
/// and `warden config lint` exits 2 on warnings.
#[test]
fn slash_double_zero_is_a_catch_all() {
    assert_eq!(catch_all_family("0.0.0.0/00"), Some(CatchAll::V4));
    assert_eq!(catch_all_family("::/00"), Some(CatchAll::V6));
}

#[test]
fn no_default_profile_const_is_pinned() {
    assert_eq!(
        NO_DEFAULT_PROFILE_REFUSES_UNMATCHED,
        "[server].default_profile is unset — every client that is not a configured device and not inside a configured subnet will get REFUSED for every query. Set default_profile to a profile id if that is not what you intended."
    );
}

#[test]
fn n1_anti_bypass_with_an_operator_domain_is_silent() {
    let mut c = basic_config();
    c.anti_bypass.extra_domains = vec!["doh.example.net".to_string()];
    let warns = warns_for(&c);
    assert!(
        !warns.iter().any(|w| w.contains("has no domains to block")),
        "a configured domain builds a real checker — no warning: {warns:?}"
    );
}

#[test]
fn n1_anti_bypass_disabled_is_silent() {
    // Off-and-empty is coherent: the operator asserts nothing.
    let mut c = basic_config();
    c.anti_bypass.enabled = false;
    let warns = warns_for(&c);
    assert!(
        !warns.iter().any(|w| w.contains("has no domains to block")),
        "a disabled section must not warn: {warns:?}"
    );
}

// ── the master switch silently kills `[anti_bypass]` ───────────
//
// `SecurityLayer::from_config` returns an all-`None` layer when
// `security.enabled` is false, short-circuiting before the branch
// that would honour `anti_bypass.enabled`. Reproduced during the
// neutrality-01 CT smoke, where a probe config disabled the security
// layer to stop RRL throttling and a listed resolver name resolved
// anyway — which read as "the change works" and proved nothing.

#[test]
fn master_switch_off_with_anti_bypass_on_warns() {
    let mut c = basic_config();
    c.security.enabled = false;
    c.anti_bypass.enabled = true;
    c.anti_bypass.extra_domains = vec!["doh.example.net".to_string()];
    let warns = warns_for(&c);
    assert!(
        warns
            .iter()
            .any(|w| w.contains("switches off every security sub-checker")),
        "expected SECURITY_DISABLED_DROPS_ANTI_BYPASS, got: {warns:?}"
    );
}

/// The predicate must key on `anti_bypass.enabled`, not on the
/// domain list being non-empty. A populated list is the *worse*
/// case — the operator did the work and gets nothing — but an empty
/// one is still a config claiming a protection that is not running.
#[test]
fn master_switch_warn_does_not_depend_on_a_populated_list() {
    let mut c = basic_config();
    c.security.enabled = false;
    assert!(
        c.anti_bypass.extra_domains.is_empty(),
        "precondition: default shape has no domains"
    );
    let warns = warns_for(&c);
    assert!(
        warns
            .iter()
            .any(|w| w.contains("switches off every security sub-checker")),
        "got: {warns:?}"
    );
    // Both diagnostics fire here, deliberately: two different reasons
    // the section enforces nothing, two different remedies. Fixing
    // one leaves the other true.
    assert!(
        warns.iter().any(|w| w.contains("has no domains to block")),
        "the N1 warning must still fire alongside it: {warns:?}"
    );
}

/// Control arm. Without it the assertions above would pass just as
/// well on a predicate that fired unconditionally.
#[test]
fn master_switch_on_is_silent() {
    let mut c = basic_config();
    assert!(
        c.security.enabled,
        "precondition: the master switch defaults on"
    );
    c.anti_bypass.enabled = true;
    let warns = warns_for(&c);
    assert!(
        !warns
            .iter()
            .any(|w| w.contains("switches off every security sub-checker")),
        "got: {warns:?}"
    );

    // …and an operator who stood the section down together with the
    // layer has a coherent config, so that is silent too.
    let mut c = basic_config();
    c.security.enabled = false;
    c.anti_bypass.enabled = false;
    let warns = warns_for(&c);
    assert!(
        !warns
            .iter()
            .any(|w| w.contains("switches off every security sub-checker")),
        "off-and-stood-down is coherent: {warns:?}"
    );
}

/// Same guard rail as N1's: WARN, never an error. A contradictory
/// config still loads — the daemon aborts on any `ConfigError`, and
/// refusing here would take DNS off the air over a contradiction the
/// operator may have meant.
#[test]
fn master_switch_contradiction_is_a_warning_never_an_error() {
    let mut c = basic_config();
    c.security.enabled = false;
    c.anti_bypass.enabled = true;
    assert!(validate(&c, now()).is_ok(), "must not block the load");
}

// ── neutrality-04 — `safe_search = true` selects nothing ────────

#[test]
fn neutrality04_safe_search_profile_warns_that_the_flag_is_inert() {
    let mut c = basic_config();
    let mut p = profile_default();
    p.safe_search = true;
    c.profiles.insert("kids".into(), p);
    let warns = warns_for(&c);
    assert!(
        warns
            .iter()
            .any(|w| w.contains("no longer selects any rewrite")),
        "expected SAFE_SEARCH_FLAG_SELECTS_NOTHING, got: {warns:?}"
    );
    assert!(
        warns
            .iter()
            .any(|w| w.contains("profiles.kids:") && w.contains("no longer selects")),
        "the warning must name the profile it belongs to: {warns:?}"
    );
}

/// Fires on the flag alone. An operator who has `[[rewrites]]` AND
/// the flag set still has an inert flag, so a warning that went
/// quiet once any rewrite existed would read as "fixed" while
/// nothing had changed.
#[test]
fn neutrality04_safe_search_warn_survives_authored_rewrites() {
    let mut c = basic_config();
    let mut p = profile_default();
    p.safe_search = true;
    p.rewrite_rules = vec![crate::config::settings::RewriteRule {
        from: "www.example-int".into(),
        to: "safe.example-int".into(),
        match_subdomains: false,
    }];
    c.profiles.insert("kids".into(), p);
    let warns = warns_for(&c);
    assert!(
        warns
            .iter()
            .any(|w| w.contains("no longer selects any rewrite")),
        "got: {warns:?}"
    );
}

/// Control arm: a profile that does not set the flag is silent.
#[test]
fn neutrality04_safe_search_off_is_silent() {
    let c = basic_config();
    assert!(
        !c.profiles["default"].safe_search,
        "precondition: the default profile does not set it"
    );
    let warns = warns_for(&c);
    assert!(
        !warns
            .iter()
            .any(|w| w.contains("no longer selects any rewrite")),
        "got: {warns:?}"
    );
}

/// The guard rail on the whole lane: this config is **valid**. Both
/// live CTs carry it, and the daemon load path aborts on any
/// `ConfigError` — turning this diagnostic fatal would take the
/// house off DNS at the next restart.
#[test]
fn n1_anti_bypass_toothless_config_is_a_warning_never_an_error() {
    let c = basic_config();
    assert!(
        validate(&c, now()).is_ok(),
        "enabled-with-no-domains must never block the load"
    );
}

/// The warning must not send the operator somewhere that cannot
/// work. Nothing joins a `[[blocklists]]` subscription to
/// `AntiBypassConfig` — no field, no `BlocklistBase` variant, no CLI
/// verb — so a list is a filter-engine path, not a checker source.
#[test]
fn n1_anti_bypass_warning_points_at_extra_domains_only() {
    let warns = warns_for(&basic_config());
    let w = warns
        .iter()
        .find(|w| w.contains("has no domains to block"))
        .expect("the warning must be present to check its remedy");
    assert!(
        w.contains("anti_bypass.extra_domains"),
        "the remedy must name the field that actually feeds the checker: {w}"
    );
}

fn custom_list_master(extra: &str) -> String {
    format!(
        r#"
schema_version = 3

[upstream]
servers = ["192.0.2.1:53"]

[server]
default_profile = "kids"

[[custom_lists]]
id = "minecraft"

[profiles.kids]
{extra}
"#
    )
}

#[test]
fn a_duplicate_custom_list_id_is_refused() {
    let src = custom_list_master("").replace(
        "[profiles.kids]",
        "[[custom_lists]]\nid = \"minecraft\"\n\n[profiles.kids]",
    );
    let cfg: ConfigV1 = toml::from_str(&src).unwrap();
    let errs = validate(&cfg, now()).unwrap_err();
    assert!(
        errs.iter().any(|e| matches!(e, ConfigError::DuplicateId(c)
            if c.reason.contains("minecraft"))),
        "expected DuplicateId naming the id, got {errs:?}"
    );
}

#[test]
fn a_custom_list_id_colliding_with_a_blocklist_id_is_refused() {
    // A NEW cross-kind rule. `labels` deliberately permits the same id
    // under two kinds; this does not, because the two entities are
    // adjacent in the operator's mental model and in the interface.
    let src = custom_list_master("").replace(
        "[[custom_lists]]",
        "[[blocklists]]\nid = \"minecraft\"\ndisplay_name = \"Minecraft\"\nurl = \"https://lists.example.invalid/a.txt\"\n\n[[custom_lists]]",
    );
    let cfg: ConfigV1 = toml::from_str(&src).unwrap();
    let errs = validate(&cfg, now()).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| matches!(e, ConfigError::DuplicateId(_))),
        "a custom list must not share an id with a blocklist, got {errs:?}"
    );
}

#[test]
fn a_profile_naming_an_undeclared_custom_list_is_refused() {
    let src = custom_list_master("custom_lists = [\"nope\"]");
    let cfg: ConfigV1 = toml::from_str(&src).unwrap();
    let errs = validate(&cfg, now()).unwrap_err();
    assert!(
        errs.iter().any(|e| matches!(e, ConfigError::CrossRefMiss(c)
            if c.reason.contains("nope"))),
        "expected CrossRefMiss naming the id, got {errs:?}"
    );
}

#[test]
fn a_profile_naming_a_declared_custom_list_validates() {
    // Negative control: without it, a validator that refuses every
    // mount would pass the test above.
    let src = custom_list_master("custom_lists = [\"minecraft\"]");
    let cfg: ConfigV1 = toml::from_str(&src).unwrap();
    assert!(
        validate(&cfg, now()).is_ok(),
        "a valid mount must be accepted"
    );
}

#[test]
fn a_custom_list_mounted_by_nobody_is_reported() {
    let src = custom_list_master("");
    let cfg: ConfigV1 = toml::from_str(&src).unwrap();
    let inert = inert_custom_lists(&cfg);
    assert!(
        inert
            .iter()
            .any(|(id, r)| id.as_str() == "minecraft"
                && *r == InertListReason::CustomListUnmounted),
        "an unmounted custom list must be reported: {inert:?}"
    );
}

#[test]
fn a_mounted_custom_list_is_not_reported_as_unmounted() {
    // Negative control. Without it, a predicate that reports every
    // custom list passes the test above.
    let src = custom_list_master("custom_lists = [\"minecraft\"]");
    let cfg: ConfigV1 = toml::from_str(&src).unwrap();
    assert!(inert_custom_lists(&cfg).is_empty());
}

#[test]
fn the_unmounted_report_reaches_the_lint_channel() {
    // `warden config lint` renders the messages the validator collects
    // in-band, so a diagnostic that only reached `tracing` would be
    // invisible there — the divergence that makes an operator stop
    // trusting the lint.
    let src = custom_list_master("");
    let cfg: ConfigV1 = toml::from_str(&src).unwrap();
    let mut warns = AuditWarnings::silent();
    validate_collect(&cfg, now(), &mut warns, None, None).expect("fixture must validate");
    let msgs = warns.into_messages();
    assert!(
        msgs.iter()
            .any(|m| m == &format_custom_list_unmounted("minecraft")),
        "the unmounted line must reach the lint channel: {msgs:?}"
    );
}

#[test]
fn a_zero_file_cap_is_refused() {
    let src = custom_list_master("").replace(
        "[[custom_lists]]",
        "[custom_list_limits]\nmax_file_bytes = 0\n\n[[custom_lists]]",
    );
    let cfg: ConfigV1 = toml::from_str(&src).unwrap();
    let errs = validate(&cfg, now()).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.to_string().contains("max_file_bytes")),
        "a zero cap makes every list unreadable at the next load, got {errs:?}"
    );
}
