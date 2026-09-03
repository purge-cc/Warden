//! `[cluster]` — primary/secondary replication configuration.
//!
//! With the default `enabled = false` the daemon behaves byte-identically
//! to a standalone node.
//!
//! Decisions reflected at the schema level: pull model —
//! [`ClusterConfig::peer`] is the primary's API base URL that a secondary
//! polls; the cluster bearer token is stored as a SHA-256 hash in
//! [`ClusterConfig::token_hash`], never the plaintext; the whole
//! `[cluster]` section is node-local identity and is never replicated;
//! the [`ClusterRole`] enum distinguishes the read-only secondary from
//! the authoritative primary.

use serde::{Deserialize, Serialize};

/// This node's role in the cluster.
///
/// `role = "primary"` (the default) is the authoritative node that holds
/// policy and serves it; `role = "secondary"` is a read-only follower
/// that polls the primary. Serialises lowercase: `primary` /
/// `secondary`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClusterRole {
    /// Authoritative node — holds policy, downloads lists, serves the
    /// cluster endpoints (default).
    #[default]
    Primary,
    /// Read-only follower — polls the primary and mirrors its policy.
    Secondary,
}

/// The `[cluster]` config section.
///
/// Every field carries a `#[serde(default)]` (via the struct-level
/// attribute) so the whole section may be omitted — an omitted section is
/// identical to `enabled = false`. `schema_version` is **not** bumped:
/// this is a purely additive section.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClusterConfig {
    /// Opt-in master switch. `false` (default) ⇒ clustering is inert and
    /// the daemon is byte-identical to a standalone node.
    pub enabled: bool,

    /// This node's [`ClusterRole`]. Default [`ClusterRole::Primary`].
    pub role: ClusterRole,

    /// Optional human-readable label for this node, shown in the cluster
    /// roster / status views. A secondary advertises it on every
    /// heartbeat; the primary falls back to the peer's source IP when unset.
    /// Free-form (display only) — uniqueness is not enforced. `None` when
    /// unset.
    pub node_name: Option<String>,

    /// Split-brain tiebreak: the lower number wins on primary recovery.
    /// Operator-managed; distinctness from the peer is a
    /// warn-only concern, not enforced here.
    pub priority: u32,

    /// The primary's API base URL a secondary polls, e.g.
    /// `https://192.0.2.10:8053`. Required when `role = "secondary"`
    /// (validator-enforced); ignored on a primary. `None` when unset.
    pub peer: Option<String>,

    /// SHA-256 hex hash of the cluster bearer token. Set by
    /// `warden cluster token` (primary) or `warden cluster join`
    /// (secondary). Required when `enabled = true`. The plaintext is
    /// never stored here. `None` when unset.
    pub token_hash: Option<String>,

    /// Path to the PEM certificate the secondary pins for the primary's
    /// `[api]` TLS listener. Set by
    /// `warden cluster join --peer-cert <pem>`.
    ///
    /// The poll client trusts **this certificate and no public CA** — see
    /// `cluster::pinned::build_pinned_client`. Neither household box has a
    /// publicly-issued certificate, so without a pin the channel between two
    /// non-loopback nodes cannot complete a single poll.
    ///
    /// `None` on a primary, and on a secondary that has not been given one.
    /// **That case fails closed at client construction**, not at load: the
    /// poll loop refuses to start with
    /// [`CLUSTER_SECONDARY_REQUIRES_PEER_CERT`] rather than falling back to
    /// an unpinned client. Deliberate — an unpinned fallback is a sync that
    /// silently works against anyone holding a public certificate for the
    /// peer's name, which is worse than a loud refusal.
    pub peer_cert: Option<String>,

    /// Secondary heartbeat cadence, seconds — convergence target is
    /// one interval. Default 15.
    pub poll_interval_secs: u64,

    /// Consecutive-failure window before a secondary promotes itself,
    /// seconds. Default 45 (three missed 15 s beats).
    pub failover_after_secs: u64,

    /// Optional defence-in-depth: CIDRs allowed to reach `/api/cluster/*`
    /// on top of the bearer token. Each entry must be a valid CIDR.
    ///
    /// **Empty (the default) means no network restriction** — the bearer token
    /// is the gate that always applies, and this narrows it further only when
    /// the operator asks. Denying on empty would lock out every install that
    /// has not set the field.
    ///
    /// **The runtime gate is LIVE**, in `cluster::routes`'s auth middleware,
    /// ahead of both the lockout and the token check: a wrong CIDR here
    /// locks the secondary out of every poll, it is not inert.
    pub allow_peer: Vec<String>,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            role: ClusterRole::Primary,
            node_name: None,
            priority: 1,
            peer: None,
            token_hash: None,
            peer_cert: None,
            poll_interval_secs: 15,
            failover_after_secs: 45,
            allow_peer: Vec::new(),
        }
    }
}

/// An enabled secondary that polls without a pinned peer certificate.
///
/// Emitted when the poll client is built, **not** at config load: the pin is
/// consumed in one place, so refusing there keeps the check adjacent to the
/// thing it protects and cannot be bypassed by a code path that skips
/// validation. Frozen (pinned by `tests/frozen_strings_cluster.rs`).
///
/// Lives in this ungated module rather than beside the client so the frozen
/// string is pinned in **both** feature configs — a const behind
/// `--features cluster` is unpinned in the build almost everyone runs.
pub const CLUSTER_SECONDARY_REQUIRES_PEER_CERT: &str =
    "cluster: `peer_cert` is required for a secondary's poll client. Neither node has a \
     publicly-issued certificate, so the channel is authenticated by pinning the primary's. \
     Run `warden cluster join --peer <primary-url> --token-file <path> --peer-cert <pem>`, \
     or set peer_cert = \"/etc/purge-warden/primary-cert.pem\" in [cluster].";

// ── `warden cluster enable` refusals (S4) ──────────────────────
//
// All seven live in this UNGATED module for the reason spelled out on
// `CLUSTER_SECONDARY_REQUIRES_PEER_CERT` above: a const behind
// `--features cluster` is unpinned in the build almost everyone runs, so a
// drift in the operator-facing text would ship unnoticed. Pinned by
// `tests/frozen_strings_cluster.rs`.
//
// Every one of them is emitted BEFORE anything is written — the verb's tests
// assert the master is byte-identical after each, and assert on the const
// itself so a test cannot go green on the wrong refusal.

/// R1 — `enable --role secondary`. Frozen.
///
/// `EnableRole` deliberately carries a `Secondary` variant it refuses: with
/// only `primary`, clap's own "invalid value for --role" is what a mistaken
/// operator sees, and that error cannot name the verb they actually wanted.
pub const CLUSTER_ENABLE_ROLE_SECONDARY_USE_JOIN: &str =
    "cluster: `enable --role secondary` is not how a secondary is turned on. A secondary must \
     also record the primary it follows, the token it authenticates with, and the certificate \
     it pins — none of which this verb takes. \
     Run `warden cluster join --peer <primary-url> --token-file <path> --peer-cert <pem>`. \
     Nothing has been written.";

/// R2 — no `[cluster] token_hash`. Frozen.
pub const CLUSTER_ENABLE_REQUIRES_TOKEN_HASH: &str =
    "cluster: `token_hash` is unset, so an enabled primary would reject every secondary's poll. \
     Run `warden cluster token` first — it mints the bearer credential and prints the plaintext \
     ONCE, to carry to the secondary. Nothing has been written.";

/// R3 — the resulting `api.listen` is loopback. Frozen.
///
/// The default listen IS loopback, so this fires on a node that passed no
/// `--api-listen` and never set one by hand — which is every fresh node.
pub const CLUSTER_ENABLE_LISTEN_IS_LOOPBACK: &str =
    "cluster: a primary whose `api.listen` is a loopback address can serve no remote secondary — \
     the sync channel is the API server. Pass an address the secondary can reach, e.g. \
     `--api-listen 192.0.2.10:8053`. Nothing has been written.";

/// R4 — no `[api] token_hash`. Frozen.
///
/// Not a nicety: `api.enabled = true` without it is refused by the validator
/// (`API_ENABLED_REQUIRES_TOKEN_HASH`), so without this check the verb would
/// build a master the daemon cannot start from and fail late, in the staged
/// write, naming a temp path the operator can no longer look at.
pub const CLUSTER_ENABLE_REQUIRES_API_TOKEN_HASH: &str =
    "api: `token_hash` is unset. Enabling clustering turns the API server on — the cluster \
     routes mount on it — and an API without a token hash is refused at every load. \
     Run `warden token generate` first. Nothing has been written.";

/// R5 — minting, with no `--san`. Frozen.
pub const CLUSTER_ENABLE_REQUIRES_SAN: &str =
    "cluster: this node carries no `api.tls_cert`, so `enable` has to mint one — and a \
     certificate needs at least one subject alternative name. Pinning does not disable \
     hostname verification: rustls checks the SAN against the host the secondary dials, so a \
     certificate minted without it fails every poll while looking perfectly well-formed. \
     Pass `--san <ADDR>` once per address a secondary will use, e.g. `--san 192.0.2.10`. \
     Nothing has been written.";

/// R6 — `api.crt` / `api.key` already on disk. `{paths}` substituted by
/// [`format_cluster_enable_cert_already_exists`]. Frozen.
///
/// The paths are not decoration. There is no `--force` in S4, so an operator
/// who hits this and is not told exactly what to remove has no way forward at
/// all.
pub const CLUSTER_ENABLE_CERT_ALREADY_EXISTS: &str =
    "cluster: TLS material already exists beside the master config, and minting over it would \
     invalidate the pin of every secondary that has already joined. There is no `--force`: if \
     replacing the certificate is what you mean to do, remove these files yourself first, then \
     re-run — {paths}. Nothing has been written.";

/// Substitute `{paths}` into [`CLUSTER_ENABLE_CERT_ALREADY_EXISTS`]. Public so
/// the frozen-strings test exercises const and helper together — the const
/// alone would stay green while the substitution dropped a path.
pub fn format_cluster_enable_cert_already_exists(paths: &[std::path::PathBuf]) -> String {
    let joined = paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    CLUSTER_ENABLE_CERT_ALREADY_EXISTS.replace("{paths}", &joined)
}

/// R7 — `--san` passed while the config already carries operator TLS
/// material. Frozen.
///
/// Its mirror is deliberately NOT a refusal: an existing `tls_cert` and no
/// `--san` means "use what I already have", which is a supported way to run a
/// primary.
pub const CLUSTER_ENABLE_SAN_WITH_EXISTING_CERT: &str =
    "cluster: `--san` was passed, but this node already carries its own `api.tls_cert` — a \
     minted certificate would be written and never used. Drop `--san` to enable clustering \
     with the certificate you already have, or clear `api.tls_cert` and `api.tls_key` first. \
     Nothing has been written.";

/// Validate a cluster `peer_cert` path.
///
/// Path-shaped validation only — emptiness and absoluteness. Readability and
/// PEM well-formedness are deliberately **not** checked here: both are
/// time-of-check-to-time-of-use races against a file the operator may install
/// after writing the config, and both are caught for real when the client is
/// built.
pub fn validate_peer_cert_path(path: &str) -> Result<(), String> {
    let path = path.trim();
    if path.is_empty() {
        return Err("must not be empty".to_string());
    }
    if !std::path::Path::new(path).is_absolute() {
        return Err("must be an absolute path".to_string());
    }
    Ok(())
}

/// Is `peer` a loopback address — the case where pinning is not required?
///
/// Mirrors the exemption [`validate_peer_url`] already grants: a same-host peer
/// has no network segment on which to be intercepted, which is exactly why
/// plain `http://` is permitted there. A secondary polling
/// `http://127.0.0.1:8053` presents **no certificate at all**, so requiring a
/// pin would make a supported configuration unpollable rather than more
/// secure.
///
/// Accepts a bare host too, so a malformed peer that never reached
/// [`validate_peer_url`] cannot be mistaken for loopback by accident.
pub fn peer_is_loopback(peer: &str) -> bool {
    let peer = peer.trim();
    let rest = peer
        .strip_prefix("https://")
        .or_else(|| peer.strip_prefix("http://"))
        .unwrap_or(peer);
    is_loopback_host(host_of(rest))
}

/// Confirm a `peer_cert` file really contains at least one X.509 certificate.
///
/// **Necessary because `reqwest::Certificate::from_pem` does not parse under
/// this crate's feature set.** With `rustls-tls` (and no `default-tls`) it
/// only stores the bytes — `original: Cert::Pem(pem.to_owned())` — and the
/// parse is deferred to `add_to_rustls` at client-build time. There,
/// `read_pem_certs` maps a file containing **no PEM section at all** to an
/// empty vector and returns `Ok`, so the client is built with an **empty root
/// store** and no error is raised.
///
/// That fails closed, which is the right direction, but it is diagnostically
/// terrible: every poll then fails with an opaque TLS error and nothing points
/// at the certificate file. Measured — `b"not a certificate"` round-tripped
/// through `from_pem` without complaint.
///
/// It also matters for the pin's security story: an empty root store combined
/// with a *missing* `tls_built_in_root_certs(false)` is a client that trusts
/// every public CA and nothing else — the additive-trust defect at its worst.
pub fn validate_peer_cert_pem(pem: &[u8]) -> Result<(), String> {
    use rustls::pki_types::pem::PemObject;

    let mut found = 0usize;
    for item in rustls::pki_types::CertificateDer::pem_slice_iter(pem) {
        item.map_err(|e| format!("is not valid PEM ({e})"))?;
        found += 1;
    }
    if found == 0 {
        return Err(
            "contains no CERTIFICATE section — an empty file, a DER blob, or the primary's \
             PRIVATE KEY copied by mistake all look like this"
                .to_string(),
        );
    }
    Ok(())
}

/// Validate a cluster `peer` URL.
///
/// The secondary sends the plaintext cluster bearer token to this URL on every
/// poll, so a plaintext `http://` peer leaks the credential in cleartext and
/// makes the whole replicated channel (bundle + map) trivially MITM-able.
/// Require `https://` — with a **loopback exception** (`127.0.0.0/8`, `::1`,
/// `localhost`) so the ad-hoc/loopback CT-smoke and lab rigs keep working over
/// plain HTTP. Mirrors the DoH `https://`-only guard (`upstream/doh.rs`).
///
/// Used at `cluster join` time (fail fast) and in the config validator (defence
/// in depth — catches a hand-edited peer at lint/boot/reload).
pub fn validate_peer_url(peer: &str) -> Result<(), String> {
    let peer = peer.trim();
    if peer.is_empty() {
        return Err("must not be empty".to_string());
    }
    if let Some(rest) = peer.strip_prefix("https://") {
        if host_of(rest).is_empty() {
            return Err("missing host after https://".to_string());
        }
        return Ok(());
    }
    if let Some(rest) = peer.strip_prefix("http://") {
        let host = host_of(rest);
        if host.is_empty() {
            return Err("missing host after http://".to_string());
        }
        if is_loopback_host(host) {
            return Ok(());
        }
        return Err(
            "plaintext http:// is only allowed for a loopback peer (the cluster token is sent \
             on every poll); use https://"
                .to_string(),
        );
    }
    Err("must start with https:// (or http:// for a loopback peer)".to_string())
}

/// Host portion of a post-scheme URL remainder: drop the path (from the first
/// `/`), drop any `user:pass@` userinfo, then the `:port`. Keeps a bracketed
/// IPv6 literal (`[::1]:8053` → `[::1]`).
fn host_of(rest: &str) -> &str {
    let authority = rest.split('/').next().unwrap_or("");
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    if authority.starts_with('[') {
        if let Some(close) = authority.find(']') {
            return &authority[..=close];
        }
    }
    authority.split(':').next().unwrap_or(authority)
}

/// A loopback host literal we permit over plaintext `http://`.
fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "::1" | "[::1]") || host.starts_with("127.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_disabled_primary() {
        let c = ClusterConfig::default();
        assert!(!c.enabled);
        assert_eq!(c.role, ClusterRole::Primary);
        assert!(c.node_name.is_none());
        assert_eq!(c.priority, 1);
        assert!(c.peer.is_none());
        assert!(c.token_hash.is_none());
        assert!(c.peer_cert.is_none());
        assert_eq!(c.poll_interval_secs, 15);
        assert_eq!(c.failover_after_secs, 45);
        assert!(c.allow_peer.is_empty());
    }

    #[test]
    fn role_serialises_lowercase() {
        assert_eq!(
            toml::Value::try_from(ClusterRole::Primary).unwrap(),
            toml::Value::String("primary".into())
        );
        assert_eq!(
            toml::Value::try_from(ClusterRole::Secondary).unwrap(),
            toml::Value::String("secondary".into())
        );
    }

    #[test]
    fn omitted_section_equals_default() {
        // An empty table deserialises to the default thanks to the
        // struct-level `#[serde(default)]`.
        let from_empty: ClusterConfig = toml::from_str("").unwrap();
        assert_eq!(from_empty, ClusterConfig::default());
    }

    #[test]
    fn full_section_round_trips() {
        let cfg = ClusterConfig {
            enabled: true,
            role: ClusterRole::Secondary,
            node_name: Some("rpi-livingroom".into()),
            priority: 2,
            peer: Some("https://192.0.2.10:8053".into()),
            token_hash: Some("a".repeat(64)),
            peer_cert: Some("/etc/purge-warden/primary-cert.pem".into()),
            poll_interval_secs: 20,
            failover_after_secs: 60,
            allow_peer: vec!["192.0.2.10/32".into()],
        };
        let s = toml::to_string(&cfg).unwrap();
        let back: ClusterConfig = toml::from_str(&s).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn unknown_field_is_rejected() {
        // `deny_unknown_fields` guards against typos in the section.
        let err = toml::from_str::<ClusterConfig>("enabledd = true\n");
        assert!(err.is_err());
    }

    #[test]
    fn peer_url_accepts_https_and_loopback_http() {
        for ok in [
            "https://192.0.2.10:8053",
            "https://primary.lan",
            "http://127.0.0.1:18080",
            "http://[::1]:8053",
            "http://localhost:8053",
            "  https://10.0.0.1:8053  ", // trimmed
        ] {
            assert!(validate_peer_url(ok).is_ok(), "should accept: {ok}");
        }
    }

    #[test]
    fn peer_cert_path_accepts_absolute_and_rejects_the_rest() {
        assert!(validate_peer_cert_path("/etc/purge-warden/primary-cert.pem").is_ok());
        assert!(validate_peer_cert_path("  /etc/primary.pem  ").is_ok()); // trimmed
        for bad in ["", "   ", "primary-cert.pem", "./primary.pem", "../x.pem"] {
            assert!(
                validate_peer_cert_path(bad).is_err(),
                "should reject: {bad:?}"
            );
        }
    }

    /// The check that `reqwest::Certificate::from_pem` does NOT perform under
    /// this feature set. Every input here was accepted by `from_pem`.
    #[test]
    fn peer_cert_pem_rejects_anything_without_a_certificate_section() {
        for bad in [
            &b""[..],
            b"not a certificate",
            b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
            &[0x30, 0x82, 0x01, 0x0a], // DER bytes in a file named .pem
        ] {
            assert!(
                validate_peer_cert_pem(bad).is_err(),
                "should reject: {bad:?}"
            );
        }
    }

    #[test]
    fn peer_cert_pem_accepts_a_real_certificate() {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::ExplicitNoCa;
        params.subject_alt_names = vec![rcgen::SanType::IpAddress("192.0.2.1".parse().unwrap())];
        let cert = params.self_signed(&key).unwrap();
        assert!(validate_peer_cert_pem(cert.pem().as_bytes()).is_ok());
    }

    /// An omitted `peer_cert` must stay omitted on round-trip. A `Some("")`
    /// here would satisfy the schema and then fail at client construction,
    /// which is a worse diagnostic than the field simply being absent.
    #[test]
    fn omitted_peer_cert_round_trips_as_none() {
        let cfg: ClusterConfig = toml::from_str("role = \"secondary\"\n").unwrap();
        assert!(cfg.peer_cert.is_none());
        let back: ClusterConfig = toml::from_str(&toml::to_string(&cfg).unwrap()).unwrap();
        assert!(back.peer_cert.is_none());
    }

    #[test]
    fn peer_url_rejects_plaintext_offbox_and_garbage() {
        for bad in [
            "http://192.0.2.10:8053", // plaintext off-loopback — token disclosure
            "http://primary.lan",
            "ftp://192.0.2.10",
            "192.0.2.10:8053", // no scheme
            "not a url",
            "",
            "   ",
            "https://", // no host
        ] {
            assert!(validate_peer_url(bad).is_err(), "should reject: {bad:?}");
        }
    }
}
