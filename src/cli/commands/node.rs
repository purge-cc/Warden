//! Local authorization and status for guided node management.

use std::path::Path;

use crate::cli::NodeAction;

#[cfg(feature = "cluster")]
pub async fn run_node(master: &Path, socket: &Path, action: NodeAction) -> anyhow::Result<()> {
    use crate::cluster::node_control::NodeControlCommand;
    use crate::ipc::protocol::{IpcCommand, IpcResponse};
    use crate::ipc::socket_client::send_command;

    let (request, json, issuing) = match action {
        NodeAction::Token { listen, revoke } => (
            if revoke {
                NodeControlCommand::TokenRevoke
            } else {
                NodeControlCommand::TokenPrepare { listen }
            },
            false,
            !revoke,
        ),
        NodeAction::Status { json } => (NodeControlCommand::Status, json, false),
        NodeAction::AbandonPendingAdd {
            operation_id,
            confirm,
        } => {
            anyhow::ensure!(
                confirm,
                "pass --confirm after checking `warden node status`"
            );
            (
                NodeControlCommand::AbandonPreparingAdd { operation_id },
                false,
                false,
            )
        }
        NodeAction::RecoverPrimary {
            listen,
            apply_preview,
            cancel_preview,
        } => {
            return run_primary_recovery(master, socket, listen, apply_preview, cancel_preview)
                .await;
        }
    };
    let response = send_command(
        socket,
        &IpcCommand::NodeControl {
            request,
            token: None,
        },
    )
    .await?;
    let reply = match response {
        IpcResponse::NodeControl { reply } => reply,
        IpcResponse::Error { message } => anyhow::bail!("{message}"),
        _ => anyhow::bail!("daemon does not support guided node management; upgrade the daemon"),
    };
    if issuing {
        let secret = reply
            .token
            .ok_or_else(|| anyhow::anyhow!("daemon did not issue an association token"))?;
        eprintln!("Paste this token into Add Node on the primary. It authorizes one association and expires in 15 minutes.");
        println!("{}", secret.0);
    } else if json {
        println!("{}", serde_json::to_string_pretty(&reply.status)?);
    } else {
        println!("{}", reply.message);
        println!("Node: {}", reply.status.membership.node_name);
        println!("Role: {:?}", reply.status.membership.saved_role);
        if let Some(endpoint) = reply.status.control_endpoint {
            println!("Nodes address: {endpoint}");
        }
        for peer in &reply.status.peers {
            println!(
                "{}  {}  {:?}  {:?}",
                peer.name, peer.endpoint, peer.role, peer.state
            );
        }
        for operation in &reply.status.operations {
            println!(
                "{}  {:?}: {}",
                operation.operation_id, operation.phase, operation.message
            );
        }
    }
    Ok(())
}

#[cfg(not(feature = "cluster"))]
pub async fn run_node(_master: &Path, _socket: &Path, _action: NodeAction) -> anyhow::Result<()> {
    anyhow::bail!("this build does not include Nodes; install a build with cluster support")
}

#[cfg(feature = "cluster")]
async fn run_primary_recovery(
    master: &Path,
    socket: &Path,
    listen: Option<std::net::SocketAddr>,
    apply_preview: Option<String>,
    cancel_preview: Option<String>,
) -> anyhow::Result<()> {
    use crate::cluster::lifecycle;
    match (listen, apply_preview, cancel_preview) {
        (Some(endpoint), None, None) => {
            let preview = lifecycle::preview_primary_activation_recovery(master, endpoint).await?;
            println!("{}", serde_json::to_string_pretty(&preview)?);
            eprintln!(
                "Review this recovery before applying it with: warden node recover-primary --apply-preview {}",
                preview.id
            );
        }
        (None, Some(id), None) => {
            let result = lifecycle::apply_primary_activation_recovery(master, &id).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            use super::ipc_reload::{attempt_reload, report_reload_outcome};
            report_reload_outcome(&attempt_reload(socket).await);
            eprintln!(
                "Recovery saved. Restart the service after checking its endpoint and certificate."
            );
        }
        (None, None, Some(id)) => {
            let result = lifecycle::cancel(master, &id).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        _ => anyhow::bail!("choose exactly one primary recovery action"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::NodeAction;
    use crate::cli::{Cli, Commands};

    #[test]
    fn token_authorization_has_no_secret_argument_and_revoke_excludes_listener() {
        let cli =
            Cli::try_parse_from(["warden", "node", "token", "--listen", "127.0.0.1:8053"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Node {
                action: NodeAction::Token {
                    listen: Some(_),
                    revoke: false
                }
            })
        ));
        assert!(Cli::try_parse_from([
            "warden",
            "node",
            "token",
            "--revoke",
            "--listen",
            "127.0.0.1:8053"
        ])
        .is_err());
        assert!(Cli::try_parse_from(["warden", "node", "token", "private-token"]).is_err());
        assert!(
            Cli::try_parse_from(["warden", "node", "token", "--token", "private-token"]).is_err()
        );
    }

    #[test]
    fn primary_recovery_requires_one_explicit_review_action() {
        for flags in [
            vec!["--listen", "192.0.2.10:8053"],
            vec!["--apply-preview", "review-id"],
            vec!["--cancel-preview", "review-id"],
        ] {
            let mut args = vec!["warden", "node", "recover-primary"];
            args.extend(flags);
            assert!(Cli::try_parse_from(args).is_ok());
        }
        assert!(Cli::try_parse_from(["warden", "node", "recover-primary"]).is_err());
        assert!(Cli::try_parse_from([
            "warden",
            "node",
            "recover-primary",
            "--listen",
            "192.0.2.10:8053",
            "--apply-preview",
            "review-id",
        ])
        .is_err());
    }

    #[test]
    fn target_pending_abandon_requires_an_explicit_confirmation_flag() {
        assert!(Cli::try_parse_from([
            "warden",
            "node",
            "abandon-pending-add",
            "--operation-id",
            "review-id",
            "--confirm"
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "warden",
            "node",
            "abandon-pending-add",
            "--operation-id",
            "review-id"
        ])
        .is_err());
    }
}
