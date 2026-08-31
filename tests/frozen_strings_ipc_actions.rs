//! §4.39 (s-4.32-disc-8) — frozen-strings trip-wire for
//! [`purge_warden::ipc::protocol::IpcCommand::action_name`].
//!
//! `action_name()` is emitted by the IPC auth path (`auth_error_for`
//! in `src/ipc/socket_server.rs`) so a token-rejection audit line
//! names the *verb* that was attempted, not just its privilege tier.
//! Audit-log readers, SIEM rules, and incident-response greps key on
//! these strings — a drift silently breaks every
//! `action == "profile.delete"`-style filter.
//!
//! Pins every `IpcCommand` variant's action name byte-for-byte. The
//! `match` in `action_name()` is exhaustive (no wildcard), so adding
//! a variant is a compile error there — and a reviewer adding the new
//! arm must add its pin here in the same commit.
//!
//! Sibling: `frozen_strings_ipc_errors.rs` pins the `IpcError`
//! operator messages. Together they cover the IPC observability
//! surface.

use std::net::{IpAddr, Ipv4Addr};

use purge_warden::config::settings::ClientConfig;
use purge_warden::ipc::protocol::{DevicePatch, IpcCommand, ProfileUpdatePatch, TrackingPatch};

/// Minimal `ClientConfig` for `DeviceAdd` construction. `ClientConfig`
/// only derives `Default` under `#[cfg(test)]` in the lib crate, which
/// an integration test (separate crate) cannot see — so build one by
/// hand. The values are irrelevant; `action_name()` ignores the body.
fn minimal_client() -> ClientConfig {
    ClientConfig {
        name: String::new(),
        ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        mac: None,
        mac_aliases: Vec::new(),
        profile: String::new(),
        owner: None,
        device_type: None,
        department: None,
        group: None,
        notes: None,
    }
}

#[test]
fn ipc_command_action_names_are_frozen() {
    // (variant, canonical audit action name). One row per IpcCommand
    // variant — keep in sync with the `action_name()` match arms.
    let cases: Vec<(IpcCommand, &str)> = vec![
        (IpcCommand::Status, "status"),
        (
            IpcCommand::Query {
                domain: "example.test".into(),
            },
            "query",
        ),
        (
            IpcCommand::CacheFlush {
                domain: None,
                token: None,
            },
            "cache.flush",
        ),
        (IpcCommand::Reload { token: None }, "reload"),
        (
            IpcCommand::ForgetList {
                id: "privacy/ads".into(),
                token: None,
            },
            "list.forget",
        ),
        (IpcCommand::Shutdown { token: None }, "shutdown"),
        (IpcCommand::DomainCount, "domain.count"),
        (IpcCommand::TrackingStats { token: None }, "tracking.stats"),
        (IpcCommand::DeviceStats { token: None }, "device.stats"),
        (IpcCommand::GetAllDevices, "devices.get_all"),
        (
            IpcCommand::QueryLogs {
                limit: 0,
                client: None,
                blocked_only: false,
                domain: None,
                since_secs: None,
                cursor: None,
                advanced: None,
                token: None,
            },
            "query.logs",
        ),
        (
            IpcCommand::DeviceAdd {
                client: minimal_client(),
                token: None,
            },
            "device.add",
        ),
        (
            IpcCommand::DeviceUpdate {
                name: "laptop".into(),
                patch: DevicePatch::default(),
                token: None,
            },
            "device.update",
        ),
        (
            IpcCommand::DeviceRemove {
                name: "laptop".into(),
                token: None,
            },
            "device.remove",
        ),
        (
            IpcCommand::DevicePromote {
                ip: "10.0.0.1".parse().unwrap(),
                name: "laptop".into(),
                profile: "default".into(),
                owner: None,
                device_type: None,
                department: None,
                token: None,
            },
            "device.promote",
        ),
        (
            IpcCommand::TrackingConfigUpdate {
                patch: TrackingPatch::default(),
                token: None,
            },
            "tracking.config.update",
        ),
        (
            IpcCommand::BlocklistStats { source_id: None },
            "blocklist.stats",
        ),
        (IpcCommand::LocalRecordsHits, "local_records.hits"),
        (
            IpcCommand::ProfileCreate {
                id: "p1".into(),
                display_name: "P1".into(),
                token: None,
            },
            "profile.create",
        ),
        (
            IpcCommand::ProfileUpdate {
                id: "p1".into(),
                patch: ProfileUpdatePatch::default(),
                token: None,
            },
            "profile.update",
        ),
        (
            IpcCommand::ProfileDelete {
                id: "p1".into(),
                token: None,
            },
            "profile.delete",
        ),
        // `logs-tab`: the daemon's own tracing events. Admin tier — log
        // text carries client IPs and query names.
        (
            IpcCommand::DaemonLogs {
                limit: 100,
                level: None,
                contains: None,
                token: None,
            },
            "daemon.logs",
        ),
        // §4.11-4: ReadOnly cluster status verb; only exists under the
        // `cluster` feature (so its pin is feature-gated to match).
        #[cfg(feature = "cluster")]
        (IpcCommand::ClusterStatus, "cluster.status"),
    ];

    #[cfg(not(feature = "cluster"))]
    let expected_len = 22;
    #[cfg(feature = "cluster")]
    let expected_len = 23;
    assert_eq!(
        cases.len(),
        expected_len,
        "every IpcCommand variant must have a pinned action name"
    );
    for (cmd, expected) in cases {
        assert_eq!(
            cmd.action_name(),
            expected,
            "action_name() drift — expected {expected:?}"
        );
    }
}
