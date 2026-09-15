#![cfg(feature = "cluster")]

use purge_warden::cluster::membership::SecretString;
use purge_warden::cluster::node_control::NodeControlCommand;
use purge_warden::ipc::protocol::{CommandTier, IpcCommand};

#[test]
fn node_control_authorization_preserves_the_exact_request_and_redacts_association_secret() {
    let request = NodeControlCommand::PreviewAdd {
        name: "Office node".into(),
        endpoint: "192.0.2.8:8053".parse().unwrap(),
        token: SecretString("private-association-token".into()),
    };
    let command = IpcCommand::NodeControl {
        request: request.clone(),
        token: None,
    };
    assert_eq!(command.tier(), CommandTier::Admin);
    assert!(!format!("{command:?}").contains("private-association-token"));
    let authorized = command.with_token(Some("admin-credential".into()));
    assert_eq!(authorized.token(), Some("admin-credential"));
    let serialized = serde_json::to_vec(&authorized).unwrap();
    let decoded: IpcCommand = serde_json::from_slice(&serialized).unwrap();
    assert_eq!(decoded, authorized);
    assert!(
        matches!(decoded, IpcCommand::NodeControl { request: actual, .. } if actual == request)
    );
}

#[test]
fn node_control_audit_actions_and_tiers_are_stable() {
    let endpoint = "192.0.2.8:8053".parse().unwrap();
    let cases = [
        (
            NodeControlCommand::Status,
            "node.status",
            CommandTier::ReadOnly,
        ),
        (
            NodeControlCommand::TokenPrepare {
                listen: Some(endpoint),
            },
            "node.token.prepare",
            CommandTier::Admin,
        ),
        (
            NodeControlCommand::TokenRevoke,
            "node.token.revoke",
            CommandTier::Admin,
        ),
        (
            NodeControlCommand::PreviewAdd {
                name: "Desk".into(),
                endpoint,
                token: SecretString("secret".into()),
            },
            "node.add.preview",
            CommandTier::Admin,
        ),
        (
            NodeControlCommand::PreviewEdit {
                node_id: "id".into(),
                name: "Desk".into(),
                endpoint: Some(endpoint),
            },
            "node.edit.preview",
            CommandTier::Admin,
        ),
        (
            NodeControlCommand::PreviewRemove {
                node_id: "id".into(),
            },
            "node.remove.preview",
            CommandTier::Admin,
        ),
        (
            NodeControlCommand::Apply {
                preview_id: "id".into(),
            },
            "node.apply",
            CommandTier::Admin,
        ),
        (
            NodeControlCommand::Cancel {
                preview_id: "id".into(),
            },
            "node.cancel",
            CommandTier::Admin,
        ),
        (
            NodeControlCommand::Resume {
                operation_id: "id".into(),
            },
            "node.resume",
            CommandTier::Admin,
        ),
        (
            NodeControlCommand::AbandonPreparingAdd {
                operation_id: "id".into(),
            },
            "node.add.abandon_pending",
            CommandTier::Admin,
        ),
    ];
    for (request, action, tier) in cases {
        let command = IpcCommand::NodeControl {
            request,
            token: None,
        };
        assert_eq!(command.action_name(), action);
        assert_eq!(command.tier(), tier);
    }
}

#[test]
fn node_control_errors_use_frozen_operator_messages() {
    use purge_warden::cluster::node_control::NodeControlErrorCode as Code;
    use purge_warden::ipc::errors::IpcError;

    let cases = [
        (Code::InvalidInput, "the Nodes request is not valid for the current node, address, or membership state; review the fields and current status"),
        (Code::ListenRequired, "choose this node's reachable LAN address with warden node token --listen IP:8053"),
        (Code::CapabilityUpgradeRequired, "this peer needs a Warden upgrade before guided Nodes management is available; its existing policy sync is preserved"),
        (Code::AuthorizationExpired, "the association or review expired; issue a new token and review it again"),
        (Code::Conflict, "configuration or reviewed artifacts changed; prepare and review the operation again"),
        (Code::PeerUnavailable, "the managed node could not be reached through its pinned HTTPS endpoint; check its address and retry or resume"),
        (Code::SupervisorUnsupported, "managed restart is unavailable; run Warden as the supported systemd service with exit 75 configured, then resume the operation"),
        (Code::RecoveryRequired, "the operation remains durable and needs recovery; refresh Nodes and use Resume"),
        (Code::Internal, "the Nodes operation could not be completed; its durable status is still available"),
    ];
    for (code, expected) in cases {
        assert_eq!(IpcError::NodeControl(code).operator_message(), expected);
    }
}
