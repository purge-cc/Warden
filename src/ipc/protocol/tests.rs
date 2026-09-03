use super::*;

#[test]
fn command_status_roundtrip() {
    let cmd = IpcCommand::Status;
    let json = serde_json::to_string(&cmd).unwrap();
    assert_eq!(json, r#"{"type":"status"}"#);
    let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, cmd);
}

#[test]
fn command_query_roundtrip() {
    let cmd = IpcCommand::Query {
        domain: "google.com".into(),
    };
    let json = serde_json::to_string(&cmd).unwrap();
    assert!(json.contains("\"domain\":\"google.com\""));
    let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, cmd);
}

#[test]
fn command_cache_flush_all_roundtrip() {
    let cmd = IpcCommand::CacheFlush {
        domain: None,
        token: None,
    };
    let json = serde_json::to_string(&cmd).unwrap();
    let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, cmd);
}

#[test]
fn command_cache_flush_domain_roundtrip() {
    let cmd = IpcCommand::CacheFlush {
        domain: Some("example.com".into()),
        token: None,
    };
    let json = serde_json::to_string(&cmd).unwrap();
    let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, cmd);
}

#[test]
fn response_status_roundtrip() {
    let resp = IpcResponse::Status {
        pid: 1234,
        listen: "127.0.0.1:15353".into(),
        upstream_mode: "plain".into(),
        upstream_count: 2,
        upstream_servers: Vec::new(),
        domain_count: 500_000,
        cache_entries: 1234,
        list_count: 3,
        uptime_secs: 3600,
        query_log_drops: None,
        version: String::new(),
        cache_cap: 0,
        lists_active: 0,
        lists_total: 0,
        lists_truncated: 0,
        lists_corpus_refusal: None,
        lists_cycle: None,
        lists_corpus_freeze: None,
        lc2_list_diagnostics: ListDiagnostics::default(),
        resource_budget: None,
        cache_weighted_size: 0,
    };
    let json = serde_json::to_string(&resp).unwrap();
    let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, resp);
}

/// T2.9 / H-20: a pre-T2.9 daemon's `Status` payload (without
/// `query_log_drops`) must still decode into the new struct shape
/// thanks to `#[serde(default)]`. Pins the wire-back-compat
/// guarantee for the freeze period before CLI/daemon are released
/// in lockstep.
#[test]
fn response_status_legacy_without_drop_counters_deserializes() {
    let legacy = r#"{"type":"status","pid":1,"listen":"127.0.0.1:53","upstream_mode":"plain","upstream_count":1,"domain_count":0,"cache_entries":0,"list_count":0,"uptime_secs":0}"#;
    let parsed: IpcResponse = serde_json::from_str(legacy).unwrap();
    match parsed {
        IpcResponse::Status {
            query_log_drops, ..
        } => assert!(query_log_drops.is_none()),
        other => panic!("expected Status, got {other:?}"),
    }
}

/// T2.9 / H-20: a fresh-daemon `Status` payload carries the new
/// `query_log_drops: Some(_)` field intact through round-trip.
#[test]
fn response_status_with_drop_counters_roundtrip() {
    use crate::tracking::query_log::QueryLogDropSnapshot;
    let resp = IpcResponse::Status {
        pid: 1234,
        listen: "127.0.0.1:15353".into(),
        upstream_mode: "plain".into(),
        upstream_count: 2,
        upstream_servers: Vec::new(),
        domain_count: 500_000,
        cache_entries: 1234,
        list_count: 3,
        uptime_secs: 3600,
        query_log_drops: Some(QueryLogDropSnapshot {
            channel_full: 7,
            flush_open_errors: 1,
            flush_write_errors: 42,
        }),
        version: String::new(),
        cache_cap: 0,
        lists_active: 0,
        lists_total: 0,
        lists_truncated: 0,
        lists_corpus_refusal: None,
        lists_cycle: None,
        lists_corpus_freeze: None,
        lc2_list_diagnostics: ListDiagnostics::default(),
        resource_budget: None,
        cache_weighted_size: 0,
    };
    let json = serde_json::to_string(&resp).unwrap();
    assert!(json.contains("\"channel_full\":7"));
    assert!(json.contains("\"flush_write_errors\":42"));
    let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, resp);
}

/// §4.19 — a pre-§4.19 daemon's Status payload (without `version`,
/// `cache_cap`, `lists_active`, `lists_total`) must still decode
/// thanks to `#[serde(default)]`. Pins back-compat for the freeze
/// period before CLI/daemon are released in lockstep.
#[test]
fn response_status_legacy_without_s419_fields_deserializes() {
    let legacy = r#"{"type":"status","pid":1,"listen":"127.0.0.1:53","upstream_mode":"plain","upstream_count":1,"domain_count":0,"cache_entries":0,"list_count":0,"uptime_secs":0}"#;
    let parsed: IpcResponse = serde_json::from_str(legacy).unwrap();
    match parsed {
        IpcResponse::Status {
            version,
            cache_cap,
            lists_active,
            lists_total,
            lists_truncated,
            ..
        } => {
            assert_eq!(version, "");
            assert_eq!(cache_cap, 0);
            assert_eq!(lists_active, 0);
            assert_eq!(lists_total, 0);
            // The truncation counter joins the same back-compat
            // contract: a CLI built with it must not fail to read a
            // daemon built without it.
            assert_eq!(lists_truncated, 0);
        }
        other => panic!("expected Status, got {other:?}"),
    }
}

/// §4.19 — a fresh-daemon Status payload carries the new fields
/// intact through round-trip with realistic values.
#[test]
fn response_status_s419_fields_roundtrip() {
    let resp = IpcResponse::Status {
        pid: 1234,
        listen: "127.0.0.1:15353".into(),
        upstream_mode: "plain".into(),
        upstream_count: 2,
        upstream_servers: Vec::new(),
        domain_count: 500_000,
        cache_entries: 1234,
        list_count: 8,
        uptime_secs: 3600,
        query_log_drops: None,
        version: "0.7.4".into(),
        cache_cap: 10_000,
        lists_active: 7,
        lists_total: 8,
        lists_truncated: 0,
        lists_corpus_refusal: None,
        lists_cycle: None,
        lists_corpus_freeze: None,
        lc2_list_diagnostics: ListDiagnostics::default(),
        resource_budget: None,
        cache_weighted_size: 4_120,
    };
    let json = serde_json::to_string(&resp).unwrap();
    assert!(json.contains("\"version\":\"0.7.4\""));
    assert!(json.contains("\"cache_cap\":10000"));
    assert!(json.contains("\"lists_active\":7"));
    assert!(json.contains("\"lists_total\":8"));
    assert!(json.contains("\"cache_weighted_size\":4120"));
    let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, resp);
}

/// mem2608-s3 — a pre-mem2608-s3 daemon's Status payload (without
/// `cache_weighted_size`) must still decode thanks to
/// `#[serde(default)]`. Same back-compat contract as `cache_cap`
/// itself: a CLI built with this field must not fail to read a
/// daemon built without it.
#[test]
fn response_status_legacy_without_cache_weighted_size_deserializes() {
    let legacy = r#"{"type":"status","pid":1,"listen":"127.0.0.1:53","upstream_mode":"plain","upstream_count":1,"domain_count":0,"cache_entries":0,"list_count":0,"uptime_secs":0}"#;
    let parsed: IpcResponse = serde_json::from_str(legacy).unwrap();
    match parsed {
        IpcResponse::Status {
            cache_weighted_size,
            ..
        } => assert_eq!(cache_weighted_size, 0),
        other => panic!("expected Status, got {other:?}"),
    }
}

/// §4.13 — pre-§4.13 daemon payload (no `resource_budget`) decodes
/// cleanly thanks to `#[serde(default)]`; the field is `None`.
#[test]
fn response_status_legacy_without_resource_budget_deserializes() {
    let legacy = r#"{"type":"status","pid":1,"listen":"127.0.0.1:53","upstream_mode":"plain","upstream_count":1,"domain_count":0,"cache_entries":0,"list_count":0,"uptime_secs":0}"#;
    let parsed: IpcResponse = serde_json::from_str(legacy).unwrap();
    match parsed {
        IpcResponse::Status {
            resource_budget, ..
        } => assert!(resource_budget.is_none()),
        other => panic!("expected Status, got {other:?}"),
    }
}

/// §4.13 — a fresh daemon Status payload carries a non-empty
/// resource_budget through round-trip.
#[test]
fn response_status_with_resource_budget_roundtrip() {
    use crate::resource_budget::ResourceBudgetSnapshot;
    let resp = IpcResponse::Status {
        pid: 1234,
        listen: "127.0.0.1:15353".into(),
        upstream_mode: "plain".into(),
        upstream_count: 1,
        upstream_servers: Vec::new(),
        domain_count: 1_000,
        cache_entries: 10,
        list_count: 1,
        uptime_secs: 60,
        query_log_drops: None,
        version: "0.13.0".into(),
        cache_cap: 5_000,
        lists_active: 1,
        lists_total: 1,
        lists_truncated: 0,
        lists_corpus_refusal: None,
        lists_cycle: None,
        lists_corpus_freeze: None,
        lc2_list_diagnostics: ListDiagnostics::default(),
        cache_weighted_size: 300,
        resource_budget: Some(ResourceBudgetSnapshot {
            rss_mb: 42,
            vsz_mb: 280,
            fd_count: 18,
            cpu_user_pct: 3,
            rss_warn_mb: 256,
        }),
    };
    let json = serde_json::to_string(&resp).unwrap();
    assert!(json.contains("\"rss_mb\":42"));
    assert!(json.contains("\"rss_warn_mb\":256"));
    let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, resp);
}

#[test]
fn response_query_result_roundtrip() {
    let resp = IpcResponse::QueryResult {
        domain: "ads.example.com".into(),
        blocked: true,
        blocked_by: Some("list:ads".into()),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, resp);
}

#[test]
fn response_ok_roundtrip() {
    let resp = IpcResponse::Ok {
        message: "cache flushed".into(),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, resp);
}

#[test]
fn response_error_roundtrip() {
    let resp = IpcResponse::Error {
        message: "unknown command".into(),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, resp);
}

/// §4.7 Phase 2 T1: `IpcCommand::ForgetList` and the matching
/// `IpcResponse::ListForgotten` round-trip cleanly across serde
/// AND `ForgetList` is classified `Mutating` so the auth gate
/// requires a token. Also covers `with_token` adding the token
/// after construction (the CLI client's flow).
#[test]
fn forget_list_command_and_response_serde_round_trip() {
    let cmd = IpcCommand::ForgetList {
        id: "privacy/ads".into(),
        token: Some("plaintext-token".into()),
    };
    assert_eq!(cmd.tier(), CommandTier::Mutating);
    assert_eq!(cmd.token(), Some("plaintext-token"));

    let json = serde_json::to_string(&cmd).unwrap();
    let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, cmd);

    let cmd_no_token = IpcCommand::ForgetList {
        id: "privacy/ads".into(),
        token: None,
    };
    let with_t = cmd_no_token.with_token(Some("tok".into()));
    assert_eq!(with_t.token(), Some("tok"));

    let resp = IpcResponse::ListForgotten {
        id: "privacy/ads".into(),
        was_cached: true,
    };
    let json = serde_json::to_string(&resp).unwrap();
    let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, resp);
}

#[test]
fn response_domain_count_roundtrip() {
    let resp = IpcResponse::DomainCount { count: 123456 };
    let json = serde_json::to_string(&resp).unwrap();
    let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, resp);
}

#[test]
fn all_command_variants_deserialize() {
    let cases = [
        r#"{"type":"status"}"#,
        r#"{"type":"query","domain":"test.com"}"#,
        r#"{"type":"cache_flush","domain":null}"#,
        r#"{"type":"reload"}"#,
        r#"{"type":"shutdown"}"#,
        r#"{"type":"domain_count"}"#,
        r#"{"type":"tracking_stats"}"#,
        r#"{"type":"client_stats"}"#,
        r#"{"type":"query_logs","limit":20}"#,
        r#"{"type":"query_logs","limit":10,"client":"laptop","blocked_only":true}"#,
        // Sprint 41: since_secs added with `#[serde(default)]` so
        // older callers (no field at all) still parse; newer callers
        // can set it to apply a rolling time cutoff.
        r#"{"type":"query_logs","limit":10,"since_secs":3600}"#,
    ];
    for json in cases {
        let _: IpcCommand = serde_json::from_str(json).unwrap();
    }
}

#[test]
fn tracking_stats_response_roundtrip() {
    let resp = IpcResponse::TrackingStats {
        queries_total: 1000,
        blocked_total: 200,
        blocked_pct: 20.0,
        cache_hit_rate: 85.5,
        cache_negative_hits: 42,
        uptime_secs: 3600,
        top_blocked: vec![DomainCount {
            domain: "ads.com".into(),
            count: 50,
            count_24h: 0,
            scope: Some("privacy".into()),
        }],
        top_queried: vec![DomainCount {
            domain: "google.com".into(),
            count: 200,
            count_24h: 0,
            scope: None,
        }],
        hourly: vec![TimeBucketDto {
            timestamp: 1000,
            queries: 100,
            blocked: 20,
            cache_hits: 80,
        }],
        daily: vec![],
        cache_hit_rate_24h: 80.0,
        blocked_pct_24h: 20.0,
        cache_hit_rate_delta_1h: 2.5,
        blocked_pct_delta_1h: -1.0,
        qtype_distribution: [700, 200, 5, 1, 0, 0, 0, 0, 80, 14],
        qtype_blocked_distribution: [50, 30, 1, 0, 0, 0, 0, 0, 4, 2],
        qtype_distribution_24h: [80, 22, 0, 0, 0, 0, 0, 0, 8, 1],
        qtype_blocked_distribution_24h: [5, 3, 0, 0, 0, 0, 0, 0, 0, 0],
        prefetch_pool_size: 7,
        prefetch_promotions_total: 12,
        prefetch_demotions_total: 5,
        top_blocked_lists: Vec::new(),
        top_blocked_24h: Vec::new(),
        top_queried_24h: Vec::new(),
        top_blocked_lists_24h: Vec::new(),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, resp);
}

/// Sprint §4.4 P1 — pre-§4.4 daemon emits TrackingStats without the
/// three `prefetch_*` fields. The post-upgrade CLI/TUI must still
/// deserialize that payload, defaulting all three to zero.
#[test]
fn tracking_stats_response_legacy_missing_prefetch_fields() {
    let legacy_json = serde_json::json!({
        "type": "tracking_stats",
        "queries_total": 500,
        "blocked_total": 50,
        "blocked_pct": 10.0,
        "cache_hit_rate": 60.0,
        "cache_negative_hits": 3,
        "uptime_secs": 120,
        "top_blocked": [],
        "top_queried": [],
        "hourly": [],
        "daily": [],
        "qtype_distribution": [400, 90, 0, 0, 0, 0, 0, 0, 0, 10]
    });
    let parsed: IpcResponse = serde_json::from_value(legacy_json).unwrap();
    match parsed {
        IpcResponse::TrackingStats {
            prefetch_pool_size,
            prefetch_promotions_total,
            prefetch_demotions_total,
            qtype_blocked_distribution,
            ..
        } => {
            assert_eq!(prefetch_pool_size, 0);
            assert_eq!(prefetch_promotions_total, 0);
            assert_eq!(prefetch_demotions_total, 0);
            // Sprint E — pre-Sprint-E daemons emit no
            // `qtype_blocked_distribution`; serde default fills in
            // the canonical 10-bucket all-zero array.
            assert_eq!(qtype_blocked_distribution, [0u64; 10]);
        }
        other => panic!("expected TrackingStats, got {other:?}"),
    }
}

/// Legacy migration: a pre-Sprint-25 daemon emits TrackingStats
/// without the new `cache_negative_hits` field. The TUI (post-upgrade)
/// must still deserialize that payload, defaulting the counter to 0.
#[test]
fn tracking_stats_response_legacy_missing_negative_hits() {
    let legacy_json = serde_json::json!({
        "type": "tracking_stats",
        "queries_total": 500,
        "blocked_total": 50,
        "blocked_pct": 10.0,
        "cache_hit_rate": 60.0,
        "uptime_secs": 120,
        "top_blocked": [],
        "top_queried": [],
        "hourly": [],
        "daily": []
    });
    let parsed: IpcResponse = serde_json::from_value(legacy_json).unwrap();
    match parsed {
        IpcResponse::TrackingStats {
            cache_negative_hits,
            ..
        } => assert_eq!(cache_negative_hits, 0),
        other => panic!("expected TrackingStats, got {other:?}"),
    }
}

/// Legacy migration (Sprint 27): a pre-scope daemon emits DomainCount
/// entries without the `scope` field. The TUI must default them to
/// `None` so the wire format is forward-compatible.
#[test]
fn domain_count_accepts_missing_scope_as_none() {
    let legacy = serde_json::json!({
        "domain": "ads.example",
        "count": 100,
    });
    let parsed: DomainCount = serde_json::from_value(legacy).unwrap();
    assert_eq!(parsed.scope, None);
    assert_eq!(parsed.domain, "ads.example");
    assert_eq!(parsed.count, 100);
}

/// And the new field round-trips when populated.
#[test]
fn domain_count_roundtrips_populated_scope() {
    let dc = DomainCount {
        domain: "tracker.example".into(),
        count: 42,
        count_24h: 0,
        scope: Some("privacy".into()),
    };
    let json = serde_json::to_string(&dc).unwrap();
    let parsed: DomainCount = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, dc);
}

#[test]
fn device_list_response_roundtrip() {
    let resp = IpcResponse::DeviceList {
        clients: vec![DeviceStatEntry {
            name: "laptop".into(),
            ip: "192.168.1.42".into(),
            queries: 500,
            blocked: 50,
            blocked_pct: 10.0,
            cache_hits: 400,
            profile: "default".into(),
            last_seen: 1704110000,
        }],
    };
    let json = serde_json::to_string(&resp).unwrap();
    let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, resp);
}

/// T5 decode-compat: a pre-T5 daemon (or CLI playback) sending the
/// legacy `client_list` variant tag must still decode into the T5
/// `DeviceList` variant. Pairs with the serde aliases on the
/// `IpcResponse` enum and satisfies §3 R1's IPC decode-compat
/// requirement for one release cycle.
#[test]
fn legacy_client_list_variant_decodes_into_device_list() {
    let legacy_json = r#"{"type":"client_list","clients":[{"name":"laptop","ip":"192.168.1.42","queries":1,"blocked":0,"blocked_pct":0.0,"cache_hits":0,"profile":"default","last_seen":1700000000}]}"#;
    let parsed: IpcResponse = serde_json::from_str(legacy_json).unwrap();
    match parsed {
        IpcResponse::DeviceList { clients } => {
            assert_eq!(clients.len(), 1);
            assert_eq!(clients[0].name, "laptop");
        }
        other => panic!("expected DeviceList, got {other:?}"),
    }
}

/// T5 decode-compat (command side): legacy `"client_stats"` tag must
/// deserialize into the renamed `DeviceStats` variant.
#[test]
fn legacy_client_stats_command_decodes_into_device_stats() {
    let legacy_json = r#"{"type":"client_stats"}"#;
    let parsed: IpcCommand = serde_json::from_str(legacy_json).unwrap();
    assert!(matches!(parsed, IpcCommand::DeviceStats { token: None }));
}

/// T5 decode-compat: legacy `"get_all_clients"` tag must deserialize
/// into the renamed `GetAllDevices` variant.
#[test]
fn legacy_get_all_clients_command_decodes_into_get_all_devices() {
    let legacy_json = r#"{"type":"get_all_clients"}"#;
    let parsed: IpcCommand = serde_json::from_str(legacy_json).unwrap();
    assert!(matches!(parsed, IpcCommand::GetAllDevices));
}

// --- P0-3: command tier classification ---

#[test]
fn readonly_commands_have_readonly_tier() {
    assert_eq!(IpcCommand::Status.tier(), CommandTier::ReadOnly);
    assert_eq!(IpcCommand::DomainCount.tier(), CommandTier::ReadOnly);
    assert_eq!(
        IpcCommand::Query {
            domain: "google.com".into()
        }
        .tier(),
        CommandTier::ReadOnly
    );
}

#[test]
fn mutating_commands_have_mutating_tier() {
    assert_eq!(
        IpcCommand::CacheFlush {
            domain: None,
            token: None
        }
        .tier(),
        CommandTier::Mutating
    );
    assert_eq!(
        IpcCommand::Reload { token: None }.tier(),
        CommandTier::Mutating
    );
}

#[test]
fn admin_commands_have_admin_tier() {
    assert_eq!(
        IpcCommand::Shutdown { token: None }.tier(),
        CommandTier::Admin
    );
    assert_eq!(
        IpcCommand::TrackingStats { token: None }.tier(),
        CommandTier::Admin
    );
    assert_eq!(
        IpcCommand::DeviceStats { token: None }.tier(),
        CommandTier::Admin
    );
    assert_eq!(
        IpcCommand::QueryLogs {
            limit: 10,
            client: None,
            blocked_only: false,
            domain: None,
            since_secs: None,
            cursor: None,
            advanced: None,
            token: None
        }
        .tier(),
        CommandTier::Admin
    );
}

#[test]
fn with_token_attaches_to_gated_commands() {
    let tok = Some("ps_abc123".to_string());
    let attached = IpcCommand::Reload { token: None }.with_token(tok.clone());
    assert_eq!(attached.token(), Some("ps_abc123"));

    let shutdown = IpcCommand::Shutdown { token: None }.with_token(tok.clone());
    assert_eq!(shutdown.token(), Some("ps_abc123"));

    let logs = IpcCommand::QueryLogs {
        limit: 10,
        client: None,
        blocked_only: false,
        domain: None,
        since_secs: None,
        cursor: None,
        advanced: None,
        token: None,
    }
    .with_token(tok.clone());
    assert_eq!(logs.token(), Some("ps_abc123"));
}

#[test]
fn with_token_is_noop_on_readonly() {
    let tok = Some("ps_abc123".to_string());
    let status = IpcCommand::Status.with_token(tok.clone());
    // ReadOnly commands have no token slot, so token() returns None.
    assert_eq!(status.token(), None);
    assert_eq!(status, IpcCommand::Status);
}

#[test]
fn old_clients_without_token_field_still_parse() {
    // Mutating commands with no `token` field in JSON must deserialize
    // (the field defaults to None). This covers CLI clients that pre-date
    // the P0-3 change, and the round-trip of an un-tokened command.
    let cases = [
        r#"{"type":"cache_flush","domain":null}"#,
        r#"{"type":"reload"}"#,
        r#"{"type":"shutdown"}"#,
        r#"{"type":"tracking_stats"}"#,
        r#"{"type":"device_stats"}"#,
    ];
    for json in cases {
        let cmd: IpcCommand = serde_json::from_str(json).unwrap();
        assert_eq!(cmd.token(), None);
    }
}

#[test]
fn token_serializes_only_when_set() {
    let no_tok = IpcCommand::Reload { token: None };
    let with_tok = IpcCommand::Reload {
        token: Some("ps_abc".into()),
    };
    let no_json = serde_json::to_string(&no_tok).unwrap();
    let with_json = serde_json::to_string(&with_tok).unwrap();
    // `skip_serializing_if = Option::is_none` should keep the wire format
    // minimal when no token is attached.
    assert!(!no_json.contains("token"), "got {no_json}");
    assert!(with_json.contains("\"token\":\"ps_abc\""));
}

/// **The trip-wire for the field-drop class.**
///
/// `socket_client::send_command` runs every token-bearing request
/// through `with_token` — so that arm is on the path of every real
/// `QueryLogs` request and on the path of no other test, because
/// tests build `IpcCommand` directly. When the arm destructured with
/// `..`, a field added to the variant was silently reset to whatever
/// the construct side wrote: paging would have been dead in
/// production with the whole suite green.
///
/// The `let … else` below destructures EXHAUSTIVELY. That is the
/// point: the next field added to `QueryLogs` fails to compile here
/// rather than vanishing on the wire. Do not replace it with `..`.
#[test]
fn with_token_preserves_every_query_logs_field() {
    let cursor = crate::tracking::query_log::QueryLogCursor {
        file: "/var/lib/purge-warden/query.log".into(),
        offset: 8192,
        inode: 4242,
    };
    let advanced = AdvancedClientFilterDto {
        name: Some("*ioel*".into()),
        name_exclude: true,
        subnet: Some("10.10.1.0/24".into()),
        ..Default::default()
    };
    let cmd = IpcCommand::QueryLogs {
        limit: 40,
        client: Some("laptop".into()),
        blocked_only: true,
        domain: Some("ads.example".into()),
        since_secs: Some(3600),
        cursor: Some(cursor.clone()),
        advanced: Some(advanced.clone()),
        token: None,
    };
    let IpcCommand::QueryLogs {
        limit,
        client,
        blocked_only,
        domain,
        since_secs,
        cursor: carried,
        advanced: carried_advanced,
        token,
    } = cmd.with_token(Some("tok".into()))
    else {
        panic!("with_token must not change the variant");
    };
    assert_eq!(limit, 40);
    assert_eq!(client.as_deref(), Some("laptop"));
    assert!(blocked_only);
    assert_eq!(domain.as_deref(), Some("ads.example"));
    assert_eq!(since_secs, Some(3600));
    assert_eq!(
        carried,
        Some(cursor),
        "the resume cursor must survive token attachment — without this \
         every paged request silently reads the live tail"
    );
    // Bound to a NAME, not matched against a literal. A pattern like
    // `advanced: None` would compile, satisfy the exhaustiveness the
    // doc comment above is asking for, and assert nothing about the
    // field — a trip-wire that fires on the build and then tests
    // nothing is the failure mode this test is guarding against.
    assert_eq!(
        carried_advanced,
        Some(advanced),
        "the advanced filter must survive token attachment — without \
         this every advanced search silently reads the whole log"
    );
    assert_eq!(token.as_deref(), Some("tok"));
}

/// A pre-paging caller sends no `cursor`; a pre-paging daemon sends
/// no `next_cursor` / `cursor_stale`. Both must still decode.
#[test]
fn query_logs_wire_is_compatible_in_both_directions() {
    let cmd: IpcCommand = serde_json::from_str(r#"{"type":"query_logs","limit":20}"#).unwrap();
    let IpcCommand::QueryLogs { cursor, .. } = cmd else {
        panic!("expected query_logs");
    };
    assert!(cursor.is_none(), "absent cursor decodes as live tail");

    let resp: IpcResponse = serde_json::from_str(
        r#"{"type":"query_logs","entries":[],"logging_enabled":true,"file_state":"Ok"}"#,
    )
    .unwrap();
    let IpcResponse::QueryLogs {
        next_cursor,
        cursor_stale,
        ..
    } = resp
    else {
        panic!("expected query_logs");
    };
    assert!(next_cursor.is_none());
    assert!(!cursor_stale);

    // And a cursor-bearing command survives the round trip.
    let with_cursor = IpcCommand::QueryLogs {
        limit: 40,
        client: None,
        blocked_only: false,
        domain: None,
        since_secs: None,
        cursor: Some(crate::tracking::query_log::QueryLogCursor {
            file: "/var/lib/purge-warden/query.log.2026-04-07".into(),
            offset: 123,
            inode: 9,
        }),
        advanced: Some(AdvancedClientFilterDto {
            ip: Some("10.10.1.*".into()),
            ip_exclude: true,
            ..Default::default()
        }),
        token: None,
    };
    let json = serde_json::to_string(&with_cursor).unwrap();
    let back: IpcCommand = serde_json::from_str(&json).unwrap();
    assert_eq!(back, with_cursor);
}

#[test]
fn query_logs_response_roundtrip() {
    let resp = IpcResponse::QueryLogs {
        entries: vec![QueryLogDto {
            timestamp: "2026-04-08T15:00:00Z".into(),
            client_ip: "192.168.1.1".into(),
            client_name: Some("laptop".into()),
            domain: "google.com".into(),
            query_type: "A".into(),
            result: "ALLOWED".into(),
            response_time_us: 500,
            cname_chain_via: None,
        }],
        logging_enabled: true,
        file_state: QueryLogFileState::Ok,
        next_cursor: None,
        cursor_stale: false,
    };
    let json = serde_json::to_string(&resp).unwrap();
    let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, resp);
}

#[test]
fn query_log_dto_with_cname_chain_via_round_trips() {
    // §4.5 Sprint 2/2: the IPC DTO mirrors `QueryLogEntry`'s new
    // `cname_chain_via` field so the TUI receives the offending hop
    // for the `[CNAME]` badge + `qname → offending` rendering.
    let dto = QueryLogDto {
        timestamp: "2026-05-08T12:00:00Z".into(),
        client_ip: "10.0.0.42".into(),
        client_name: Some("phone".into()),
        domain: "apex.example.com".into(),
        query_type: "A".into(),
        result: "BLOCKED".into(),
        response_time_us: 999,
        cname_chain_via: Some("offending.tracker.example".into()),
    };
    let json = serde_json::to_string(&dto).unwrap();
    assert!(json.contains("\"cname_chain_via\":\"offending.tracker.example\""));
    let parsed: QueryLogDto = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, dto);
}

#[test]
fn query_log_dto_without_cname_chain_via_skips_field() {
    // Non-CNAME outcomes must not surface a spurious
    // `cname_chain_via: null` on the IPC wire — keeps the byte
    // shape identical for older TUIs / tail consumers.
    let dto = QueryLogDto {
        timestamp: "2026-05-08T12:00:00Z".into(),
        client_ip: "10.0.0.1".into(),
        client_name: None,
        domain: "google.com".into(),
        query_type: "A".into(),
        result: "ALLOWED".into(),
        response_time_us: 100,
        cname_chain_via: None,
    };
    let json = serde_json::to_string(&dto).unwrap();
    assert!(!json.contains("cname_chain_via"));
}

#[test]
fn query_log_dto_legacy_payload_parses_with_cname_chain_via_none() {
    // Pre-S4.5-P2 daemons emit DTOs without the field. The
    // `#[serde(default)]` decoration lets a newer TUI parse them
    // back as `cname_chain_via: None` without erroring.
    let legacy_json = r#"{
        "timestamp":"2026-04-08T15:00:00Z",
        "client_ip":"10.0.0.1",
        "client_name":"laptop",
        "domain":"google.com",
        "query_type":"A",
        "result":"ALLOWED",
        "response_time_us":500
    }"#;
    let parsed: QueryLogDto = serde_json::from_str(legacy_json).unwrap();
    assert!(parsed.cname_chain_via.is_none());
}

// ── s23-mapped-dto-dedup wire-format pin ─────────────────────────
// Guards against accidental nesting or field renames from the
// MappedDeviceSnapshot/MappedDeviceDto collapse. The DTO is the
// single source of truth for mapped-device metadata shape, and the
// resolver's snapshot wraps it rather than duplicating fields — so
// if anyone (re)introduces `#[serde(flatten)] meta:` or moves a
// field out of the DTO, this test fails loudly. The TUI + every
// downstream consumer parses this exact flat shape.

#[test]
fn mapped_device_dto_roundtrip() {
    let dto = MappedDeviceDto {
        ip: "192.168.1.42".into(),
        name: "edo-laptop".into(),
        mac: Some("AA:BB:CC:DD:EE:FF".into()),
        mac_aliases: Vec::new(),
        profile: "default".into(),
        owner: Some("Operator".into()),
        device_type: Some("ThinkPad".into()),
        department: Some("home".into()),
        queries: 42,
        queries_today: 9,
        blocked: 7,
        blocked_24h: 0,
        cache_hits: 13,
        last_seen: 1_700_000_000,
        online: true,
        vendor: Some("Lenovo".into()),
        groups: Vec::new(),
        notes: None,
        network_name: None,
        network_name_wildcard: false,
        id: None,
        hourly_queries: Vec::new(),
        unfiltered: false,
    };
    let json = serde_json::to_string(&dto).unwrap();
    let parsed: MappedDeviceDto = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, dto);
}

/// The device view really does put operator-private metadata on the
/// wire, for a command that needs no token.
///
/// This exists because the variant's own rustdoc used to claim the
/// opposite — that the response "excludes `notes` and any field the
/// operator might treat as confidential" — while `notes`, `owner`
/// and `department` were all being serialized. A tier justified on
/// a false description of its own payload is worse than an
/// unjustified one, so the description is now pinned.
#[test]
fn device_view_carries_operator_private_fields() {
    let dto = MappedDeviceDto {
        ip: "192.168.1.42".into(),
        name: "edo-laptop".into(),
        mac: Some("AA:BB:CC:DD:EE:FF".into()),
        mac_aliases: vec!["11:22:33:44:55:66".into()],
        profile: "default".into(),
        owner: Some("Operator".into()),
        device_type: Some("ThinkPad".into()),
        department: Some("home".into()),
        queries: 0,
        queries_today: 0,
        blocked: 0,
        blocked_24h: 0,
        cache_hits: 0,
        last_seen: 0,
        online: false,
        vendor: None,
        groups: Vec::new(),
        notes: Some("spare key under the mat".into()),
        network_name: None,
        network_name_wildcard: false,
        id: None,
        hourly_queries: Vec::new(),
        unfiltered: false,
    };
    let json = serde_json::to_string(&dto).unwrap();
    for field in ["notes", "owner", "department", "mac", "mac_aliases"] {
        assert!(
            json.contains(&format!("\"{field}\"")),
            "{field} reaches the wire; any tier rationale has to account for it"
        );
    }
    assert!(json.contains("spare key under the mat"));
    assert_eq!(IpcCommand::GetAllDevices.tier(), CommandTier::ReadOnly);
}

#[test]
fn mapped_device_dto_wire_shape_is_flat() {
    // Every field is a top-level JSON key — NO nesting under
    // "meta" / "counters" / etc. If the test grows a nested object
    // after this comment, the dedup refactor has regressed and a
    // silently-shipping TUI breakage is one commit away.
    let dto = MappedDeviceDto {
        ip: "192.168.1.42".into(),
        name: "edo-laptop".into(),
        mac: None,
        mac_aliases: Vec::new(),
        profile: "default".into(),
        owner: None,
        device_type: None,
        department: None,
        queries: 0,
        queries_today: 0,
        blocked: 0,
        blocked_24h: 0,
        cache_hits: 0,
        last_seen: 0,
        online: false,
        vendor: Some("Lenovo".into()),
        groups: Vec::new(),
        notes: None,
        network_name: None,
        network_name_wildcard: false,
        id: None,
        hourly_queries: Vec::new(),
        unfiltered: false,
    };
    let json = serde_json::to_string(&dto).unwrap();

    for key in [
        "\"ip\":",
        "\"name\":",
        "\"mac\":",
        "\"profile\":",
        "\"owner\":",
        "\"device_type\":",
        "\"department\":",
        "\"queries\":",
        "\"queries_today\":",
        "\"blocked\":",
        "\"cache_hits\":",
        "\"last_seen\":",
        "\"online\":",
        "\"vendor\":",
    ] {
        assert!(json.contains(key), "missing top-level key {key} in {json}");
    }
    // Nothing nested — the wire format must stay flat for the TUI
    // and any third-party operator tooling that parses the JSON.
    assert!(!json.contains("\"meta\":"), "unexpected nesting: {json}");
    assert!(
        !json.contains("\"counters\":"),
        "unexpected nesting: {json}"
    );
}

// ── S43 T2: IpcNotification serde stability ─────────────────
// The publishing channel is wired in T2; the subscriber endpoint
// lands in T3. These tests pin the wire shape now so a future
// refactor cannot silently rename or restructure variants once
// subscribers exist.

#[test]
fn ipc_notification_list_stats_updated_roundtrip() {
    let n = IpcNotification::ListStatsUpdated {
        id: "privacy/ads".into(),
    };
    let json = serde_json::to_string(&n).unwrap();
    // Tag style matches IpcCommand / IpcResponse for consistency.
    assert_eq!(
        json, r#"{"type":"list_stats_updated","id":"privacy/ads"}"#,
        "wire shape must stay stable across releases — subscribers parse this verbatim"
    );
    let parsed: IpcNotification = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, n);
}

#[test]
fn ipc_notification_list_stats_updated_carries_raw_url_id() {
    // Source ids in `[lists].sources` may be raw URLs (not slugs).
    // The notification id field passes them through verbatim — no
    // canonicalisation, since the registry is keyed on the same
    // raw string.
    let n = IpcNotification::ListStatsUpdated {
        id: "https://example.com/blocklist.txt".into(),
    };
    let json = serde_json::to_string(&n).unwrap();
    let parsed: IpcNotification = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, n);
}

#[test]
fn device_view_dto_roundtrip_after_sn3_flag_removal() {
    // Post-SN3 the envelope carries only `mapped` + `unmapped`. This
    // test pins the wire shape against accidental field creep (e.g. a
    // future refactor re-adding `block_unmapped` would fail the
    // serialise→deserialise equality check and the absence-in-JSON
    // guard below).
    let view = DeviceViewDto {
        mapped: vec![MappedDeviceDto {
            ip: "10.0.0.5".into(),
            name: "kids-tablet".into(),
            mac: None,
            mac_aliases: Vec::new(),
            profile: "kids".into(),
            owner: None,
            device_type: None,
            department: None,
            queries: 1,
            queries_today: 1,
            blocked: 0,
            blocked_24h: 0,
            cache_hits: 0,
            last_seen: 0,
            online: false,
            vendor: None,
            groups: Vec::new(),
            notes: None,
            network_name: None,
            network_name_wildcard: false,
            id: None,
            hourly_queries: Vec::new(),
            unfiltered: false,
        }],
        unmapped: vec![UnmappedDeviceDto {
            ip: "10.0.0.99".into(),
            mac: None,
            queries: 3,
            queries_today: 2,
            blocked: 1,
            blocked_24h: 0,
            last_seen: 0,
            online: false,
            vendor: None,
            hourly_queries: Vec::new(),
        }],
    };
    let json = serde_json::to_string(&view).unwrap();
    let parsed: DeviceViewDto = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, view);
    assert!(
        !json.contains("block_unmapped"),
        "wire format must not carry legacy block_unmapped: {json}",
    );
}

/// Sprint B Dashboard v2 — `top_blocked_lists` round-trips intact
/// through serde_json. Pinning the wire shape so a future field
/// rename surfaces as a test failure rather than a silent break of
/// the TUI poller.
#[test]
fn tracking_stats_roundtrip_includes_top_blocked_lists() {
    use crate::tracking::TYPE_BUCKET_COUNT;
    let resp = IpcResponse::TrackingStats {
        queries_total: 100,
        blocked_total: 12,
        blocked_pct: 12.0,
        cache_hit_rate: 50.0,
        cache_negative_hits: 2,
        uptime_secs: 600,
        top_blocked: Vec::new(),
        top_queried: Vec::new(),
        hourly: Vec::new(),
        daily: Vec::new(),
        cache_hit_rate_24h: 50.0,
        blocked_pct_24h: 12.0,
        cache_hit_rate_delta_1h: 0.0,
        blocked_pct_delta_1h: 0.0,
        qtype_distribution: [0; TYPE_BUCKET_COUNT],
        qtype_blocked_distribution: [0; TYPE_BUCKET_COUNT],
        qtype_distribution_24h: [0; TYPE_BUCKET_COUNT],
        qtype_blocked_distribution_24h: [0; TYPE_BUCKET_COUNT],
        prefetch_pool_size: 0,
        prefetch_promotions_total: 0,
        prefetch_demotions_total: 0,
        top_blocked_lists: vec![
            ListBlockCount {
                label: "privacy/ads".into(),
                count: 42,
                count_24h: 0,
            },
            ListBlockCount {
                label: "security/malicious".into(),
                count: 7,
                count_24h: 0,
            },
        ],
        top_blocked_24h: Vec::new(),
        top_queried_24h: Vec::new(),
        top_blocked_lists_24h: Vec::new(),
    };
    let json = serde_json::to_string(&resp).unwrap();
    assert!(json.contains("\"top_blocked_lists\""));
    assert!(json.contains("\"label\":\"privacy/ads\""));
    let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
    match parsed {
        IpcResponse::TrackingStats {
            top_blocked_lists, ..
        } => {
            assert_eq!(top_blocked_lists.len(), 2);
            assert_eq!(top_blocked_lists[0].label, "privacy/ads");
            assert_eq!(top_blocked_lists[0].count, 42);
            assert_eq!(top_blocked_lists[1].label, "security/malicious");
            assert_eq!(top_blocked_lists[1].count, 7);
        }
        other => panic!("expected TrackingStats, got {other:?}"),
    }
}

/// Sprint B Dashboard v2 — JSON emitted by a pre-Sprint-B daemon
/// (no `top_blocked_lists` field) decodes into the new variant
/// with an empty vec, so a Sprint-B-aware CLI/TUI talking to an
/// older daemon degrades gracefully to the "collecting…"
/// placeholder rather than a parse error.
#[test]
fn tracking_stats_legacy_decodes_with_empty_top_blocked_lists() {
    // Hand-crafted JSON without `top_blocked_lists`. Mirrors the
    // shape of a pre-Sprint-B `IpcResponse::TrackingStats`.
    let legacy = r#"{
        "type": "tracking_stats",
        "queries_total": 1,
        "blocked_total": 0,
        "blocked_pct": 0.0,
        "cache_hit_rate": 0.0,
        "uptime_secs": 1,
        "top_blocked": [],
        "top_queried": [],
        "hourly": [],
        "daily": []
    }"#;
    let parsed: IpcResponse = serde_json::from_str(legacy).unwrap();
    match parsed {
        IpcResponse::TrackingStats {
            top_blocked_lists, ..
        } => {
            assert!(top_blocked_lists.is_empty());
        }
        other => panic!("expected TrackingStats, got {other:?}"),
    }
}

// ── custom-list mount delta: wire shape and version skew ──────────

/// An old client sends a `ProfileUpdate` that predates the mount field.
/// `serde(default)` is what keeps `profile update` working for every
/// other field on that patch; without it the whole request fails to
/// parse and an operator's rename stops landing.
#[test]
fn a_patch_without_the_mount_field_deserialises_to_none() {
    let legacy = r#"{"display_name":"Kids"}"#;
    let parsed: ProfileUpdatePatch = serde_json::from_str(legacy).unwrap();
    assert_eq!(parsed.display_name.as_deref(), Some("Kids"));
    assert!(parsed.custom_lists.is_none());
}

/// An absent mount patch puts no key on the wire.
///
/// `IpcCommand::ProfileUpdate` carries this patch by value, so a
/// `"custom_lists":null` would change the bytes of every profile
/// mutation the product sends, including the ones that mount nothing.
#[test]
fn an_absent_mount_patch_serialises_to_no_key_at_all() {
    let json = serde_json::to_string(&ProfileUpdatePatch::default()).unwrap();
    assert_eq!(json, "{}", "an empty patch must be an empty object");
}

/// **The skew that makes the deploy order load-bearing: daemon first.**
///
/// A daemon that predates the field parses the patch, ignores the mount
/// delta, applies everything else and answers OK — because
/// `ProfileUpdatePatch` carries no `deny_unknown_fields`, the same
/// property `retired_tags` exists to exploit in the other direction. The
/// caller has no way to tell that half its patch evaporated, so a TUI
/// talking to an old daemon would report a mount that never happened.
///
/// The old shape is reconstructed here rather than asserted about,
/// because the interesting fact is not what today's struct does — it is
/// what a struct WITHOUT the field does with today's bytes.
#[test]
fn an_old_daemon_drops_the_mount_delta_in_silence_and_keeps_the_rest() {
    #[derive(Debug, serde::Deserialize)]
    struct PreMountProfileUpdatePatch {
        #[serde(default)]
        display_name: Option<String>,
    }

    let patch = ProfileUpdatePatch {
        display_name: Some("Kids".into()),
        custom_lists: Some(CustomListMountPatch {
            mount: vec!["home-exceptions".into()],
            unmount: vec![],
        }),
        ..Default::default()
    };
    let wire = serde_json::to_string(&patch).unwrap();
    assert!(wire.contains("custom_lists"), "the field is on the wire");

    let old: PreMountProfileUpdatePatch =
        serde_json::from_str(&wire).expect("an old daemon parses it rather than refusing");
    assert_eq!(
        old.display_name.as_deref(),
        Some("Kids"),
        "the rest of the patch still applies — which is why the answer is OK",
    );
}

/// A patch carrying ONLY the mount delta round-trips. Nothing else on
/// `ProfileUpdatePatch` has to be populated for a surface whose single
/// job is mounting and unmounting.
#[test]
fn a_mount_only_patch_round_trips() {
    let patch = ProfileUpdatePatch {
        custom_lists: Some(CustomListMountPatch {
            mount: vec!["home-exceptions".into()],
            unmount: vec!["stale".into()],
        }),
        ..Default::default()
    };
    let wire = serde_json::to_string(&patch).unwrap();
    let back: ProfileUpdatePatch = serde_json::from_str(&wire).unwrap();
    assert_eq!(back, patch);
}

/// Both halves default, so a peer that sends `{"custom_lists":{}}` gets
/// a legal no-op rather than a parse error.
#[test]
fn both_halves_of_the_mount_patch_default_to_empty() {
    let parsed: CustomListMountPatch = serde_json::from_str("{}").unwrap();
    assert!(parsed.mount.is_empty());
    assert!(parsed.unmount.is_empty());
}

/// A fresh-daemon Status payload carries the per-server
/// `upstream_servers` list (here mixed-kind: 2 plain + 1 doh fallback)
/// intact through round-trip, addresses and kinds preserved.
#[test]
fn response_status_upstream_servers_roundtrip() {
    let resp = IpcResponse::Status {
        pid: 1234,
        listen: "127.0.0.1:15353".into(),
        upstream_mode: "plain".into(),
        upstream_count: 2,
        domain_count: 500_000,
        cache_entries: 1234,
        list_count: 3,
        uptime_secs: 3600,
        query_log_drops: None,
        version: "0.16.0".into(),
        cache_cap: 10_000,
        lists_active: 3,
        lists_total: 3,
        lists_truncated: 0,
        lists_corpus_refusal: None,
        lists_cycle: None,
        lists_corpus_freeze: None,
        lc2_list_diagnostics: ListDiagnostics::default(),
        cache_weighted_size: 0,
        resource_budget: None,
        upstream_servers: vec![
            UpstreamServerInfo {
                address: "192.0.2.1:53".into(),
                kind: "plain".into(),
            },
            UpstreamServerInfo {
                address: "192.0.2.2:53".into(),
                kind: "plain".into(),
            },
            UpstreamServerInfo {
                address: "https://dns.example/dns-query".into(),
                kind: "doh".into(),
            },
        ],
    };
    let json = serde_json::to_string(&resp).unwrap();
    assert!(json.contains("\"address\":\"192.0.2.1:53\""));
    assert!(json.contains("\"kind\":\"doh\""));
    let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, resp);
}

/// An older daemon's Status payload (without
/// `upstream_servers`) must still decode thanks to `#[serde(default)]`;
/// the field defaults to an empty Vec, which the TUI/CLI read as the
/// "fall back to legacy `upstream_mode (upstream_count)`" signal.
#[test]
fn response_status_legacy_without_upstream_servers_deserializes() {
    let legacy = r#"{"type":"status","pid":1,"listen":"127.0.0.1:53","upstream_mode":"plain","upstream_count":1,"domain_count":0,"cache_entries":0,"list_count":0,"uptime_secs":0}"#;
    let parsed: IpcResponse = serde_json::from_str(legacy).unwrap();
    match parsed {
        IpcResponse::Status {
            upstream_servers, ..
        } => assert!(upstream_servers.is_empty()),
        other => panic!("expected Status, got {other:?}"),
    }
}
