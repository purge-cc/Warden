//! §6 — the secondary's pinned poll client.
//!
//! The cluster sync channel runs between two household boxes over a link the
//! design assumes may be hostile. Neither has a publicly-issued certificate,
//! so the default `reqwest` client — which trusts the webpki bundle and
//! nothing else — cannot complete a single poll against a non-loopback peer.
//! This module builds the client that can: one that trusts **exactly** the
//! primary's certificate.
//!
//! Extracted from the poll loop so the trust decision is testable without
//! spawning one.
//!
//! # Why two builder calls, not one
//!
//! `ClientBuilder::add_root_certificate` is **additive** — it pushes onto a
//! root store (reqwest 0.12.28 `client.rs:1854`) that is still seeded with the
//! webpki bundle, because `rustls-tls` pulls `rustls-tls-webpki-roots` and
//! `tls_built_in_certs_webpki` defaults to `true` (`client.rs:320`, consumed
//! at `:693`). With that call alone the client would trust the pinned
//! certificate **plus every public CA**, and a publicly-issued certificate for
//! the peer's hostname would validate. The pin would be no pin.
//!
//! `.tls_built_in_root_certs(false)` is therefore **mandatory**, and it does
//! reach the rustls path in this feature set (`client.rs:1919`).
//!
//! # What the tests in this module do and do not cover
//!
//! Recorded here because an untested mandatory call is a comment, and a
//! defence that is only prose cannot fail a build.
//!
//! | guard | catches a no-op client | catches `danger_accept_invalid_certs` | catches a deleted `tls_built_in_root_certs(false)` |
//! |---|---|---|---|
//! | `the_pinned_client_rejects_a_certificate_it_does_not_name` | no | **yes** | no |
//! | `the_pinned_client_accepts_the_certificate_it_names` | **yes** | no | no |
//! | `both_trust_calls_are_present_and_adjacent` | no | no | **yes** |
//!
//! Every row of that table is **measured by mutation**, not asserted: the two
//! calls were deleted one at a time and `danger_accept_invalid_certs(true)`
//! added, and the reds landed exactly where the table says.
//!
//! The remaining tests fence the boundary rather than the trust decision:
//! `a_loopback_peer_needs_no_pin` / `a_non_loopback_peer_still_requires_a_pin`
//! (a pin is required exactly where a certificate is actually presented),
//! `a_pem_with_no_certificate_refuses_to_build_a_client`, and
//! `a_blank_peer_cert_normalises_to_absent`.
//!
//! The negative test cannot catch the additive-trust defect offline: both
//! fixtures are self-signed, so neither chains to a public CA and re-adding
//! the webpki bundle changes nothing for either. The test that would catch it
//! directly needs a genuinely CA-issued certificate for the peer's hostname,
//! which cannot be minted in an offline harness. Hence the third guard, which
//! reads this file's own source — ugly, but it fails the build when someone
//! deletes one of the two calls, which is the whole requirement.

use std::time::Duration;

use anyhow::Context;

use crate::config::schema::cluster::CLUSTER_SECONDARY_REQUIRES_PEER_CERT;

/// Build the secondary's poll client, trusting **only** the PEM at
/// `peer_cert` and no public CA.
///
/// `peer_cert` is `None` when the operator has not run
/// `warden cluster join --peer-cert <pem>`. Against a **non-loopback** peer
/// that **fails closed**: a secondary with no pin has the authenticity of the
/// whole replicated channel resting on the bearer token alone, on a link §6
/// assumes may be hostile. Returning an unpinned client instead would be the
/// one outcome worse than an error — a sync that silently works, against
/// anyone holding a publicly-issued certificate for the peer's name.
///
/// A **loopback** peer is exempt and gets a plain client; see the branch
/// below for why that is the same argument, not a weakening of it.
pub fn build_pinned_client(
    peer: &str,
    peer_cert: Option<&str>,
    timeout: Duration,
) -> anyhow::Result<reqwest::Client> {
    let Some(path) = peer_cert.map(str::trim).filter(|p| !p.is_empty()) else {
        // A LOOPBACK peer is exempt, and this exemption is load-bearing rather
        // than a convenience. `validate_peer_url` accepts plain `http://` for
        // a loopback peer precisely because a same-host link has no segment to
        // intercept — and a plain-HTTP peer presents no certificate at all, so
        // demanding a pin would make an explicitly supported configuration
        // unpollable rather than more secure. Building the bare client here
        // reproduces the pre-pin behaviour exactly for that path and nothing
        // else.
        if crate::config::schema::cluster::peer_is_loopback(peer) {
            return reqwest::Client::builder()
                .timeout(timeout)
                .build()
                .context("build loopback cluster poll client");
        }
        anyhow::bail!(CLUSTER_SECONDARY_REQUIRES_PEER_CERT);
    };

    let pem =
        std::fs::read(path).with_context(|| format!("read pinned peer certificate {path}"))?;
    // BEFORE handing the bytes to reqwest: `Certificate::from_pem` does not
    // parse under `rustls-tls`, and a file with no CERTIFICATE section yields
    // an EMPTY root store with no error at all. Without this the operator gets
    // an opaque TLS failure on every poll and nothing naming the file.
    if let Err(reason) = crate::config::schema::cluster::validate_peer_cert_pem(&pem) {
        anyhow::bail!("pinned peer certificate {path} {reason}");
    }
    let cert = reqwest::Certificate::from_pem(&pem)
        .with_context(|| format!("parse pinned peer certificate {path}"))?;

    // BOTH calls are required, and deleting either silently un-pins the
    // channel. `add_root_certificate` is ADDITIVE: it pushes onto a store
    // still seeded with the webpki bundle (`rustls-tls` ->
    // rustls-tls-webpki-roots -> dep:webpki-roots), so without disabling the
    // built-ins the client would also trust every public CA and this would not
    // be a pin at all. `both_trust_calls_are_present_and_adjacent` below is
    // what fails the build if they drift apart.
    reqwest::Client::builder()
        .timeout(timeout)
        .add_root_certificate(cert)
        .tls_built_in_root_certs(false)
        .build()
        .context("build pinned cluster poll client")
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::sync::Arc;

    use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, SanType};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const TIMEOUT: Duration = Duration::from_secs(5);

    /// A NON-loopback peer, so the pin requirement applies. RFC 5737 TEST-NET-1
    /// (neutrality: never a real provider's address).
    const PEER: &str = "https://192.0.2.1:8053";

    /// rustls needs a process-wide crypto provider installed exactly once.
    fn install_ring_crypto_provider_once() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    /// A self-signed certificate + key, with its PEM written to a temp file so
    /// it can be pinned by path exactly as the operator's config does.
    struct Fixture {
        cert_der: CertificateDer<'static>,
        key_der: PrivatePkcs8KeyDer<'static>,
        pem_path: PathBuf,
        _dir: tempfile::TempDir,
    }

    /// Generate a self-signed certificate carrying `ip` as an **IP SAN** and
    /// `basicConstraints: CA:FALSE`.
    ///
    /// The SAN is load-bearing: rustls validates SAN, not CN.
    ///
    /// **`CA:FALSE` is load-bearing too, and it is the opposite of what the
    /// design doc says.** §6 asserts the pinned self-signed certificate "must
    /// carry `basicConstraints: CA:TRUE`, because `add_root_certificate`
    /// builds a chain to a trust anchor (openssl `-x509` does this by
    /// default)". Measured here, that produces a certificate the primary
    /// cannot serve: rustls rejects it with
    /// `InvalidCertificate(Other(CaUsedAsEndEntity))` before trust is even
    /// considered, because the same certificate is both the anchor and the
    /// leaf the server presents.
    ///
    /// A trust anchor is trusted by fiat — `RootCertStore::add` does not
    /// require `CA:TRUE` — so the working shape is a plain end-entity
    /// certificate that happens to be self-signed. `ExplicitNoCa` emits
    /// `CA:FALSE` rather than omitting basicConstraints, which is what an
    /// operator-facing recipe should produce.
    fn generate_self_signed(ip: &str) -> Fixture {
        let key_pair = KeyPair::generate().expect("generate key");
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::ExplicitNoCa;
        params.use_authority_key_identifier_extension = false;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.subject_alt_names = vec![SanType::IpAddress(ip.parse().expect("parse ip"))];
        let cert = params.self_signed(&key_pair).expect("self-sign");

        let dir = tempfile::tempdir().expect("tempdir");
        let pem_path = dir.path().join("peer-cert.pem");
        let mut f = std::fs::File::create(&pem_path).expect("create pem");
        f.write_all(cert.pem().as_bytes()).expect("write pem");

        Fixture {
            cert_der: cert.der().clone(),
            key_der: PrivatePkcs8KeyDer::from(key_pair.serialize_der()),
            pem_path,
            _dir: dir,
        }
    }

    /// A minimal HTTPS origin presenting `fixture`'s certificate. Speaks just
    /// enough HTTP/1.1 to let a successful handshake produce a 200 — the
    /// assertions are all about the handshake, not the body.
    async fn spawn_tls_server(fixture: &Fixture) -> SocketAddr {
        install_ring_crypto_provider_once();

        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![fixture.cert_der.clone()],
                PrivateKeyDer::Pkcs8(fixture.key_der.clone_key()),
            )
            .expect("server config");
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(stream).await else {
                        // A rejected handshake is the expected path in the
                        // negative test; drop the connection quietly.
                        return;
                    };
                    let mut buf = [0u8; 1024];
                    let _ = tls.read(&mut buf).await;
                    let _ = tls
                        .write_all(
                            b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                        )
                        .await;
                    let _ = tls.shutdown().await;
                });
            }
        });

        addr
    }

    /// The pin must REJECT a certificate it does not name.
    ///
    /// Same SAN, different key, is the point: it isolates **trust** from
    /// hostname matching. A fixture with a different SAN would be rejected for
    /// an unrelated reason and would pass against a broken build.
    #[tokio::test]
    async fn the_pinned_client_rejects_a_certificate_it_does_not_name() {
        let pinned = generate_self_signed("127.0.0.1");
        let other = generate_self_signed("127.0.0.1"); // same SAN, different key

        let addr = spawn_tls_server(&other).await; // presents `other`
        let client = build_pinned_client(PEER, Some(pinned.pem_path.to_str().unwrap()), TIMEOUT)
            .expect("builds");

        let err = client
            .get(format!("https://{addr}/api/cluster/policy"))
            .send()
            .await
            .expect_err("a certificate the pin does not name must be rejected");

        // NOT `err.is_connect()` alone: that is also true of connection-refused,
        // so a server that never started would satisfy it and the test would
        // pass for the wrong reason. `InvalidCertificate` is rustls rejecting a
        // certificate it was shown, which a dead socket cannot produce.
        //
        // The variant inside it is deliberately NOT pinned. Both fixtures also
        // share rcgen's default subject, so rustls matches the anchor by name
        // and fails the SIGNATURE (`BadSignature`) — the harder rejection, and
        // the one that shows the pin is checking keys rather than names. Two
        // certificates with different subjects would fail `UnknownIssuer`
        // instead. Both are correct; asserting on either would over-fit the
        // fixture.
        let rendered = format!("{err:?}");
        assert!(
            rendered.contains("InvalidCertificate"),
            "expected a TLS trust failure, got: {rendered}"
        );
    }

    /// …and ACCEPT the one it does. Paired with the rejection above: neither
    /// test alone states the pin's contract, and this one is the reachability
    /// control that stops the rejection passing vacuously.
    #[tokio::test]
    async fn the_pinned_client_accepts_the_certificate_it_names() {
        let pinned = generate_self_signed("127.0.0.1");
        let addr = spawn_tls_server(&pinned).await;
        let client = build_pinned_client(PEER, Some(pinned.pem_path.to_str().unwrap()), TIMEOUT)
            .expect("builds");

        let resp = client
            .get(format!("https://{addr}/api/cluster/policy"))
            .send()
            .await
            .expect("the pinned certificate must validate");
        assert!(resp.status().is_success());
    }

    /// A PEM with no certificate in it must REFUSE, not build a client with an
    /// empty root store.
    ///
    /// `reqwest::Certificate::from_pem` accepts these bytes silently under
    /// `rustls-tls` and `add_to_rustls` then adds zero anchors and returns
    /// `Ok`, so without the explicit parse this returned a perfectly good
    /// `Client` that could never connect to anything, and every poll failed
    /// with an opaque TLS error naming no file.
    #[test]
    fn a_pem_with_no_certificate_refuses_to_build_a_client() {
        let dir = tempfile::tempdir().expect("tempdir");
        for (name, body) in [
            ("garbage.pem", &b"not a certificate"[..]),
            ("empty.pem", b""),
            (
                "key.pem",
                b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
            ),
        ] {
            let path = dir.path().join(name);
            std::fs::write(&path, body).expect("write");
            let err = build_pinned_client(PEER, Some(path.to_str().unwrap()), TIMEOUT)
                .expect_err("a certificate-less PEM must not yield a client");
            assert!(
                format!("{err:#}").contains(name),
                "the refusal must name the file, got: {err:#}"
            );
        }
    }

    /// The compensating guard for the defect neither behavioural test can see.
    ///
    /// Deleting `.tls_built_in_root_certs(false)` leaves both tests above
    /// GREEN — measured, not assumed — because both fixtures are self-signed,
    /// so neither chains to a public CA and re-seeding the webpki bundle
    /// changes nothing for either. The defect only manifests against a
    /// genuinely CA-issued certificate for the peer's hostname, which an
    /// offline harness cannot mint and which a test must not reach for over
    /// the network (it would also put a third-party hostname in the tree,
    /// against the neutrality invariant).
    ///
    /// So this reads the module's own source instead. It is a poor test and a
    /// good trip-wire: it cannot tell you the client is correct, but it fails
    /// the build the moment someone removes one of the two calls, which is the
    /// requirement. `include_str!` resolves at compile time, so it does not
    /// depend on the working directory the test runs in.
    #[test]
    fn both_trust_calls_are_present_and_adjacent() {
        let src = include_str!("pinned.rs");
        // Skip this module's own test code, or the assertion matches the
        // string literals in this very function and passes vacuously.
        let impl_src = src.split("#[cfg(test)]").next().expect("source splits");
        // …and skip the module doc comment too. It *discusses* both calls, so
        // searching the whole file finds the prose before the code and reports
        // the calls in the wrong order. Measured: this guard failed against a
        // correct implementation for exactly that reason. Anchor on the
        // builder so only the real chain is read.
        let chain = &impl_src[impl_src
            .find("reqwest::Client::builder()")
            .expect("the pin must build a reqwest client")..];

        let add = chain
            .find(".add_root_certificate(cert)")
            .expect("the pin must call add_root_certificate");
        let disable = chain.find(".tls_built_in_root_certs(false)").expect(
            "the pin MUST disable the built-in webpki roots — without this \
                 add_root_certificate is additive and the client trusts every public CA",
        );

        assert!(
            disable > add,
            "tls_built_in_root_certs(false) must follow add_root_certificate on the same builder"
        );
        let between = &chain[add..disable];
        assert_eq!(
            between.matches('\n').count(),
            1,
            "the two trust calls must stay adjacent so neither is read in isolation; \
             found intervening lines: {between:?}"
        );
    }

    /// A LOOPBACK peer must still build a client without a pin.
    ///
    /// The regression this test exists for: making the pin unconditional broke
    /// `peer = "http://127.0.0.1:8053"`, which `validate_peer_url` explicitly
    /// permits "so the ad-hoc/loopback CT-smoke and lab rigs keep working over
    /// plain HTTP". A plain-HTTP peer presents no certificate, so demanding one
    /// makes a supported configuration unpollable rather than more secure —
    /// and nothing failed, because no test starts the poll loop.
    ///
    /// This is the `feedback_green_today_tests_catch_the_overreach` shape: with
    /// an exemption in play, the discriminating test is the one that is green
    /// **today**, not the one the new rule suggests.
    #[test]
    fn a_loopback_peer_needs_no_pin() {
        for peer in [
            "http://127.0.0.1:8053",
            "http://localhost:18080",
            "http://[::1]:8053",
            "https://127.0.0.1:8053",
        ] {
            assert!(
                build_pinned_client(peer, None, TIMEOUT).is_ok(),
                "a loopback peer must not require a pin: {peer}"
            );
        }
    }

    /// …and a non-loopback peer must NOT get that exemption. Paired with the
    /// test above: together they state where the boundary is, which neither
    /// states alone.
    #[test]
    fn a_non_loopback_peer_still_requires_a_pin() {
        for peer in [
            "https://192.0.2.1:8053",
            "https://primary.lan",
            // Not loopback despite the substring — the check is on the host,
            // not on whether "127.0.0.1" appears somewhere in the URL.
            "https://192.0.2.1:8053/127.0.0.1",
        ] {
            assert!(
                build_pinned_client(peer, None, TIMEOUT).is_err(),
                "a non-loopback peer must require a pin: {peer}"
            );
        }
    }

    /// An empty or whitespace-only `peer_cert` normalises to **absent**.
    ///
    /// Do not delete this as a duplicate of
    /// `a_non_loopback_peer_still_requires_a_pin`. That test covers `None`
    /// only; this one pins the `.map(str::trim).filter(|p| !p.is_empty())`
    /// normalisation, so `peer_cert = ""` in a hand-edited TOML refuses like a
    /// missing key instead of being passed to `std::fs::read` as a path.
    ///
    /// The "fails closed" half of the claim now belongs to the neighbour —
    /// once loopback became exempt, the refusal depends on the peer, and this
    /// test's `PEER` is non-loopback only so the branch is reachable.
    #[test]
    fn a_blank_peer_cert_normalises_to_absent() {
        for absent in [None, Some(""), Some("   ")] {
            let err = build_pinned_client(PEER, absent, TIMEOUT)
                .expect_err("no pin must not yield an unpinned client");
            assert!(
                err.to_string().contains("peer_cert"),
                "expected the frozen refusal, got: {err}"
            );
        }
    }
}
