//! §4.11 Cluster Sync — frozen-strings test.
//!
//! Pins every operator-facing recovery-hint const emitted by
//! `check_cluster` byte-for-byte. If a string drifts the test fails:
//! update both the literal here AND the design doc's §16.1 frozen-strings
//! note in the same commit.

use purge_warden::cli::commands::cluster::{LEAVE_UPSTREAM_NOT_NEEDED, LEAVE_WOULD_STRAND_NODE};
use std::path::PathBuf;

use purge_warden::config::schema::cluster::{
    format_cluster_enable_cert_already_exists, CLUSTER_ENABLE_CERT_ALREADY_EXISTS,
    CLUSTER_ENABLE_LISTEN_IS_LOOPBACK, CLUSTER_ENABLE_REQUIRES_API_TOKEN_HASH,
    CLUSTER_ENABLE_REQUIRES_SAN, CLUSTER_ENABLE_REQUIRES_TOKEN_HASH,
    CLUSTER_ENABLE_ROLE_SECONDARY_USE_JOIN, CLUSTER_ENABLE_SAN_WITH_EXISTING_CERT,
    CLUSTER_SECONDARY_REQUIRES_PEER_CERT,
};
use purge_warden::config::schema::validator::{
    CLUSTER_ALLOW_PEER_INVALID_CIDR, CLUSTER_ENABLED_REQUIRES_TOKEN_HASH,
    CLUSTER_POLL_INTERVAL_ZERO, CLUSTER_SECONDARY_MASTER_CARRIES_POLICY,
    CLUSTER_SECONDARY_NOT_YET_JOINED, CLUSTER_SECONDARY_PEER_INVALID,
    CLUSTER_SECONDARY_REQUIRES_PEER,
};

/// The other half of the `--upstream` pair: the flag replaces
/// `upstream.servers` wholesale, so on a node that already resolves one it can
/// only destroy. Frozen so the refusal cannot soften into a warning.
#[test]
fn leave_upstream_not_needed_byte_for_byte() {
    assert_eq!(
        LEAVE_UPSTREAM_NOT_NEEDED,
        "cluster: this node already resolves an upstream of its own, so `leave` does not need \
         `--upstream`."
    );
}

/// `cluster leave` on a joined-but-never-synced secondary. Frozen because it
/// is the only place the operator learns that the *verb* can supply the
/// resolver — the generic `UPSTREAM_SERVERS_EMPTY` remedy it replaces is a
/// deadlock here (it says to edit `upstream.servers`, which
/// `CLUSTER_SECONDARY_MASTER_CARRIES_POLICY` refuses while membership stands).
#[test]
fn leave_would_strand_node_byte_for_byte() {
    assert_eq!(
        LEAVE_WOULD_STRAND_NODE,
        "cluster: leaving would leave this node with no upstream resolver of its own. \
         It joined but has never synced, so no policy bundle has supplied `upstream.servers`, \
         and a secondary's own master is forbidden from carrying one."
    );
}

#[test]
fn enabled_requires_token_hash_byte_for_byte() {
    assert_eq!(
        CLUSTER_ENABLED_REQUIRES_TOKEN_HASH,
        "cluster: `token_hash` is required when `enabled = true`. \
         Run `warden cluster token` on the primary to generate one."
    );
}

#[test]
fn secondary_requires_peer_byte_for_byte() {
    assert_eq!(
        CLUSTER_SECONDARY_REQUIRES_PEER,
        "cluster: `peer` is required when `role = \"secondary\"`. \
         Set it to the primary's API base URL, e.g. peer = \"https://10.10.1.94:8053\"."
    );
}

/// §6 — the refusal an unpinned secondary's poll client emits.
///
/// Frozen because it is the operator's only account of why sync stopped, and
/// it must keep naming the flag that fixes it. It carries the whole recovery:
/// the reason a public CA cannot serve here, the verb, and the TOML key for
/// operators who edit the file directly.
///
/// Deliberately pinned from the UNGATED `config::schema::cluster` rather than
/// from the client that emits it — a const behind `--features cluster` would
/// go unpinned in the default build, which is the one almost everyone runs.
#[test]
fn secondary_requires_peer_cert_byte_for_byte() {
    assert_eq!(
        CLUSTER_SECONDARY_REQUIRES_PEER_CERT,
        "cluster: `peer_cert` is required for a secondary's poll client. Neither node has a \
         publicly-issued certificate, so the channel is authenticated by pinning the primary's. \
         Run `warden cluster join --peer <primary-url> --token-file <path> --peer-cert <pem>`, \
         or set peer_cert = \"/etc/purge-warden/primary-cert.pem\" in [cluster]."
    );
}

#[test]
fn allow_peer_invalid_cidr_byte_for_byte() {
    assert_eq!(
        CLUSTER_ALLOW_PEER_INVALID_CIDR,
        "cluster: `allow_peer` entry '{entry}' is not a valid CIDR ({reason}). \
         Use forms like 10.10.1.94/32 or 10.10.1.0/24."
    );
}

#[test]
fn secondary_peer_invalid_byte_for_byte() {
    assert_eq!(
        CLUSTER_SECONDARY_PEER_INVALID,
        "cluster: `peer` '{peer}' is not a valid URL ({reason}). \
         Use the primary's https:// API base URL, e.g. peer = \"https://10.10.1.94:8053\"."
    );
}

#[test]
fn poll_interval_zero_byte_for_byte() {
    assert_eq!(
        CLUSTER_POLL_INTERVAL_ZERO,
        "cluster: `poll_interval_secs` must be >= 1 when `enabled = true` \
         (0 stops the secondary from ever syncing). The default is 15."
    );
}

#[test]
fn secondary_master_carries_policy_byte_for_byte() {
    assert_eq!(
        CLUSTER_SECONDARY_MASTER_CARRIES_POLICY,
        "cluster: this node is a secondary, so its policy arrives from the \
         primary — but the master config carries policy of its own. The loader \
         would MERGE the two, concatenating lists silently, and this node would \
         filter more than the primary does. Move these sections out of the \
         master (the primary supplies them):"
    );
    // The offending sections are appended after this text, so it must end
    // ready for a list rather than as a closed sentence.
    assert!(
        CLUSTER_SECONDARY_MASTER_CARRIES_POLICY.ends_with(':'),
        "the message introduces the file:line list appended to it"
    );
}

#[test]
fn secondary_not_yet_joined_byte_for_byte() {
    assert_eq!(
        CLUSTER_SECONDARY_NOT_YET_JOINED,
        "cluster: this node is configured as a secondary but has not joined a \
         primary yet, so no policy has arrived and `upstream.servers` is empty. \
         Run `warden cluster join --peer <primary-url> --token-file <path>`. Do \
         NOT add an [upstream] here — a secondary's policy comes from its primary, \
         and a master carrying its own is refused."
    );
    // It exists to REPLACE the generic emptiness text, whose instruction is
    // wrong in this state. If it ever starts naming `init --upstream` it has
    // become the thing it replaced.
    assert!(CLUSTER_SECONDARY_NOT_YET_JOINED.contains("cluster join"));
    assert!(!CLUSTER_SECONDARY_NOT_YET_JOINED.contains("init --upstream"));
}

#[test]
fn cluster_consts_are_scoped_and_nonempty() {
    for s in [
        CLUSTER_ENABLED_REQUIRES_TOKEN_HASH,
        CLUSTER_SECONDARY_MASTER_CARRIES_POLICY,
        CLUSTER_SECONDARY_NOT_YET_JOINED,
        CLUSTER_SECONDARY_REQUIRES_PEER,
        CLUSTER_ALLOW_PEER_INVALID_CIDR,
        CLUSTER_SECONDARY_PEER_INVALID,
        CLUSTER_POLL_INTERVAL_ZERO,
    ] {
        assert!(!s.is_empty());
        assert!(s.starts_with("cluster:"), "must be scoped: {s}");
    }
    // The CIDR template keeps its substitution placeholders.
    assert!(CLUSTER_ALLOW_PEER_INVALID_CIDR.contains("{entry}"));
    assert!(CLUSTER_ALLOW_PEER_INVALID_CIDR.contains("{reason}"));
    // The peer-invalid template keeps its placeholders.
    assert!(CLUSTER_SECONDARY_PEER_INVALID.contains("{peer}"));
    assert!(CLUSTER_SECONDARY_PEER_INVALID.contains("{reason}"));
}

// ── S4 `warden cluster enable` ─────────────────────────────────
//
// Seven refusals, all frozen. They live in the UNGATED
// `config::schema::cluster` module, so this file pins them in the default
// build too — a const behind `--features cluster` is unpinned in the build
// almost everyone compiles, which is the same reasoning that put
// `CLUSTER_SECONDARY_REQUIRES_PEER_CERT` there.

#[test]
fn enable_role_secondary_use_join_byte_for_byte() {
    assert_eq!(
        CLUSTER_ENABLE_ROLE_SECONDARY_USE_JOIN,
        "cluster: `enable --role secondary` is not how a secondary is turned on. A secondary must \
         also record the primary it follows, the token it authenticates with, and the certificate \
         it pins — none of which this verb takes. \
         Run `warden cluster join --peer <primary-url> --token-file <path> --peer-cert <pem>`. \
         Nothing has been written."
    );
}

#[test]
fn enable_requires_token_hash_byte_for_byte() {
    assert_eq!(
        CLUSTER_ENABLE_REQUIRES_TOKEN_HASH,
        "cluster: `token_hash` is unset, so an enabled primary would reject every secondary's \
         poll. Run `warden cluster token` first — it mints the bearer credential and prints the \
         plaintext ONCE, to carry to the secondary. Nothing has been written."
    );
}

/// Frozen because it is the only place the operator learns that `--api-listen`
/// exists at all: no other verb sets `api.listen`, and the default is
/// loopback, so without this sentence a fresh node has no route to a working
/// primary short of hand-editing TOML.
#[test]
fn enable_listen_is_loopback_byte_for_byte() {
    assert_eq!(
        CLUSTER_ENABLE_LISTEN_IS_LOOPBACK,
        "cluster: a primary whose `api.listen` is a loopback address can serve no remote \
         secondary — the sync channel is the API server. Pass an address the secondary can \
         reach, e.g. `--api-listen 192.0.2.10:8053`. Nothing has been written."
    );
}

#[test]
fn enable_requires_api_token_hash_byte_for_byte() {
    assert_eq!(
        CLUSTER_ENABLE_REQUIRES_API_TOKEN_HASH,
        "api: `token_hash` is unset. Enabling clustering turns the API server on — the cluster \
         routes mount on it — and an API without a token hash is refused at every load. \
         Run `warden token generate` first. Nothing has been written."
    );
}

#[test]
fn enable_requires_san_byte_for_byte() {
    assert_eq!(
        CLUSTER_ENABLE_REQUIRES_SAN,
        "cluster: this node carries no `api.tls_cert`, so `enable` has to mint one — and a \
         certificate needs at least one subject alternative name. Pinning does not disable \
         hostname verification: rustls checks the SAN against the host the secondary dials, so a \
         certificate minted without it fails every poll while looking perfectly well-formed. \
         Pass `--san <ADDR>` once per address a secondary will use, e.g. `--san 192.0.2.10`. \
         Nothing has been written."
    );
}

#[test]
fn enable_cert_already_exists_byte_for_byte() {
    assert_eq!(
        CLUSTER_ENABLE_CERT_ALREADY_EXISTS,
        "cluster: TLS material already exists beside the master config, and minting over it \
         would invalidate the pin of every secondary that has already joined. There is no \
         `--force`: if replacing the certificate is what you mean to do, remove these files \
         yourself first, then re-run — {paths}. Nothing has been written."
    );
}

/// The const and the substitution are pinned together, for the same reason
/// `format_api_metrics_public_unauth` is: the literal alone stays green while
/// the formatter silently drops a path — and the paths ARE the remedy here,
/// because S4 ships no `--force`.
#[test]
fn enable_cert_already_exists_names_every_path_it_is_given() {
    let out = format_cluster_enable_cert_already_exists(&[
        PathBuf::from("/etc/purge-warden/api.crt"),
        PathBuf::from("/etc/purge-warden/api.key"),
    ]);
    assert!(out.contains("/etc/purge-warden/api.crt"), "{out}");
    assert!(out.contains("/etc/purge-warden/api.key"), "{out}");
    assert!(
        !out.contains("{paths}"),
        "the placeholder must be substituted, not printed: {out}"
    );
}

#[test]
fn enable_san_with_existing_cert_byte_for_byte() {
    assert_eq!(
        CLUSTER_ENABLE_SAN_WITH_EXISTING_CERT,
        "cluster: `--san` was passed, but this node already carries its own `api.tls_cert` — a \
         minted certificate would be written and never used. Drop `--san` to enable clustering \
         with the certificate you already have, or clear `api.tls_cert` and `api.tls_key` first. \
         Nothing has been written."
    );
}
