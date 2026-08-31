//! Test if a domain would be blocked — via IPC (running daemon) or offline (local blocklist).
//!
//! # Exit codes
//!
//! - [`SUCCESS`] — the domain is ALLOWED.
//! - [`NEGATIVE`] — the domain is BLOCKED.
//! - [`FAILURE`](crate::cli::exit_codes::FAILURE) — no verdict could be obtained (daemon unreachable, the
//!   offline blocklist could not be read).
//!
//! BLOCKED is not a failure — the command did exactly its job — but a
//! script needs to branch on the answer. Before this the only way to ask
//! "is this domain blocked?" was to grep stdout for the word `BLOCKED`,
//! which made every wording change a breaking change. The distinction
//! that matters is [`NEGATIVE`] vs [`FAILURE`](crate::cli::exit_codes::FAILURE): "the daemon says this is
//! blocked" and "I could not reach the daemon" must never look alike, or
//! a filter-verification script reads an outage as a successful block.

use std::path::Path;

use anyhow::Context;

use crate::cli::exit_codes::{NEGATIVE, SUCCESS};
use crate::filter::engine::{parse_blocklist, FilterEngine};
use crate::ipc::protocol::{IpcCommand, IpcResponse};
use crate::ipc::socket_client;

/// Run query check. If a blocklist file is provided, check offline.
/// Otherwise, try the running daemon via IPC socket.
///
/// Returns the intended process exit code; `main.rs` translates it via
/// [`crate::cli::exit_codes::exit_with`]. Unreachable-daemon and
/// unreadable-file cases stay `Err` so `main` renders them as
/// [`FAILURE`](crate::cli::exit_codes::FAILURE) with the message attached.
pub async fn run_query(
    domain: &str,
    blocklist_path: Option<&str>,
    socket_path: &Path,
) -> anyhow::Result<i32> {
    if let Some(path) = blocklist_path {
        return run_offline_query(domain, path);
    }

    // Try IPC to the running daemon
    match socket_client::send_command(
        socket_path,
        &IpcCommand::Query {
            domain: domain.to_string(),
        },
    )
    .await
    {
        Ok(IpcResponse::QueryResult {
            domain,
            blocked,
            blocked_by,
        }) => {
            // §4.2 G1a — show what blocked it when the daemon attributed
            // the block (`list:<name>`, `rule:<pattern>`, `admin_block`…).
            match (blocked, blocked_by) {
                (true, Some(source)) => println!("BLOCKED  {domain}  ({source})"),
                (true, None) => println!("BLOCKED  {domain}"),
                (false, _) => println!("ALLOWED  {domain}"),
            }
            Ok(if blocked { NEGATIVE } else { SUCCESS })
        }
        Ok(IpcResponse::Error { message }) => {
            anyhow::bail!("daemon error: {message}");
        }
        Ok(_) => {
            anyhow::bail!("unexpected response from daemon");
        }
        Err(e) => {
            anyhow::bail!(
                "cannot determine block status: {e}\n\
                 hint: is purge-warden running? try `warden status`\n\
                 hint: to check a local blocklist, use --blocklist <path>"
            );
        }
    }
}

/// Offline query check using a local blocklist file.
///
/// Same verdict-to-code mapping as the IPC path — a script must not have
/// to know which one answered.
fn run_offline_query(domain: &str, blocklist_path: &str) -> anyhow::Result<i32> {
    let content = std::fs::read_to_string(Path::new(blocklist_path))
        .with_context(|| format!("reading offline blocklist file '{blocklist_path}'"))?;
    let set = parse_blocklist(&content);
    let engine = FilterEngine::with_domains(set);

    let normalized = domain.to_ascii_lowercase();
    let normalized = normalized.strip_suffix('.').unwrap_or(&normalized);

    if engine.is_blocked(normalized) {
        println!("BLOCKED  {normalized}");
        Ok(NEGATIVE)
    } else {
        println!("ALLOWED  {normalized}");
        Ok(SUCCESS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocklist_with(domains: &str) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deny.txt");
        std::fs::write(&path, domains).unwrap();
        let s = path.display().to_string();
        (dir, s)
    }

    /// The contract's reason for existing: a script asking "is this
    /// blocked?" branches on the code, never on stdout.
    #[test]
    fn offline_query_separates_blocked_from_allowed_by_exit_code() {
        let (_dir, path) = blocklist_with("tracker.example.com\n");

        assert_eq!(
            run_offline_query("tracker.example.com", &path).unwrap(),
            NEGATIVE,
            "a blocked domain must be distinguishable without parsing stdout"
        );
        assert_eq!(
            run_offline_query("example.org", &path).unwrap(),
            SUCCESS,
            "an allowed domain is a plain success"
        );
    }

    /// Case normalisation and the trailing dot are applied before the
    /// lookup, so the code must not depend on how the operator typed it.
    #[test]
    fn offline_query_code_survives_case_and_trailing_dot() {
        let (_dir, path) = blocklist_with("tracker.example.com\n");
        for spelling in [
            "TRACKER.example.com",
            "tracker.example.com.",
            "Tracker.Example.Com.",
        ] {
            assert_eq!(
                run_offline_query(spelling, &path).unwrap(),
                NEGATIVE,
                "{spelling} did not resolve to the same verdict"
            );
        }
    }

    /// The distinction that actually protects the operator: "I could not
    /// read the blocklist" must NOT look like "the domain is allowed".
    /// It stays an `Err`, which `main` renders as FAILURE.
    #[test]
    fn offline_query_unreadable_blocklist_is_an_error_not_a_verdict() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("no-such-list.txt").display().to_string();
        assert!(
            run_offline_query("example.com", &missing).is_err(),
            "an unreadable blocklist reported a verdict it could not have"
        );
    }
}
