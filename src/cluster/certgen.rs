//! Self-signed certificate minting for a cluster primary (§6 / S4).
//!
//! # Why a self-signed certificate is the right answer here, not a fallback
//!
//! [`super::pinned`] builds the secondary's poll client with
//! `add_root_certificate(pin)` **and** `tls_built_in_root_certs(false)`, so the
//! secondary trusts exactly one certificate and no public CA. With no CA in the
//! trust path there is nothing for a CA-issued certificate to buy: a
//! self-signed certificate is cryptographically sufficient, and it costs
//! neither a public DNS name nor a 90-day renewal on a link that already sits
//! inside WireGuard.
//!
//! # The SAN is the part that is easy to get wrong
//!
//! Pinning does **not** disable hostname verification. rustls still checks the
//! presented certificate's SAN against the host in `cluster.peer`, so a
//! certificate minted without the address the secondary actually dials fails
//! every poll while looking perfectly well-formed. That is why
//! [`classify_san`] exists and why it parses as an IP *first*: an address
//! carried as a DNS name does not match an IP host, and the failure surfaces
//! only on the wire.

use std::net::IpAddr;

use anyhow::Context;
use sha2::{Digest, Sha256};

/// How far `not_before` is backdated from the minting instant.
///
/// **The machine that validates this certificate is not the machine that
/// minted it.** The primary mints; the secondary's rustls checks the validity
/// window against the *secondary's* clock. A secondary whose clock trails —
/// a VM resumed from a snapshot, a box that has not reached its first NTP sync
/// — reads a certificate stamped `not_before = now` as not-yet-valid and fails
/// its first poll. The error surfaces as a TLS failure, which reads exactly
/// like a wrong pin, so the operator debugs the wrong thing.
///
/// An hour absorbs ordinary drift and costs nothing against a ten-year
/// validity. It is deliberately not larger: skew beyond an hour means the
/// clock is broken in ways that break TLS generally, and papering over that
/// here would hide it.
const CLOCK_SKEW_MARGIN: time::Duration = time::Duration::hours(1);

/// A freshly minted self-signed certificate and its private key, PEM-encoded.
pub struct GeneratedCert {
    /// PEM-encoded X.509 certificate. Public material — safe to copy to the
    /// secondary over any channel.
    pub cert_pem: String,
    /// PEM-encoded PKCS#8 private key. SECRET — mode `0600` on disk.
    pub key_pem: String,
    /// Lowercase hex SHA-256 over the **full DER encoding** of the
    /// certificate: the same bytes `openssl x509 -fingerprint -sha256`
    /// digests, minus the colons and the `SHA256 Fingerprint=` prefix.
    ///
    /// The operator compares this out-of-band to confirm the pin, so it MUST
    /// be reproducible with stock tooling. A digest over any other span — the
    /// TBS body, the PEM text — is a number nobody can check.
    pub fingerprint_sha256: String,
    /// Expiry, for the verb to print and for tests to assert on.
    pub not_after: time::OffsetDateTime,
}

/// A Subject Alternative Name, already classified.
///
/// The classification is the whole point — see the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum San {
    Ip(IpAddr),
    Dns(String),
}

/// Classify one operator-supplied `--san` value.
///
/// Parses as [`IpAddr`] first: `100.64.0.24` becomes [`San::Ip`], never
/// `San::Dns("100.64.0.24")`. Rejects the empty string and anything carrying a
/// scheme, a port, or a path — the operator passes a bare host, not a URL.
pub fn classify_san(raw: &str) -> Result<San, String> {
    let s = raw.trim();
    if s.is_empty() {
        return Err("must not be empty".to_string());
    }
    if s.contains("://") {
        return Err(format!("`{s}` looks like a URL; pass a bare host or IP"));
    }
    if s.contains('/') {
        return Err(format!("`{s}` must not contain a path"));
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(San::Ip(ip));
    }
    // A bare IPv6 would have parsed above; a colon left here is a port.
    if s.contains(':') {
        return Err(format!("`{s}` must not carry a port"));
    }
    Ok(San::Dns(s.to_ascii_lowercase()))
}

/// Mint a self-signed certificate carrying `sans`, valid for `validity_days`
/// from `now`.
///
/// Key algorithm is ECDSA P-256 — the widest-support choice rustls accepts,
/// and small.
///
/// Errors if `sans` is empty: a certificate with no SAN validates against no
/// host, so it would fail every poll while looking correctly generated.
///
/// # The certificate profile is MEASURED, not derived from the design doc
///
/// `basicConstraints` is `CA:FALSE` ([`rcgen::IsCa::ExplicitNoCa`]) and there
/// is no authority-key-identifier extension. `cluster_sync_policy_only.md` §6
/// says the opposite — that the pinned certificate "must carry
/// `basicConstraints: CA:TRUE`, because `add_root_certificate` builds a chain
/// to a trust anchor" — and that was tried and refuted in
/// [`super::pinned`]'s fixtures: the primary serves the *same* certificate it
/// asks the secondary to pin, so a `CA:TRUE` certificate is simultaneously the
/// anchor and the leaf, and rustls rejects it with
/// `InvalidCertificate(Other(CaUsedAsEndEntity))` before trust is even
/// considered. A trust anchor is trusted by fiat — `RootCertStore::add` does
/// not require `CA:TRUE` — so the shape that works on the wire is a plain
/// end-entity certificate that happens to be self-signed.
///
/// Do not "fix" this back to `CA:TRUE` from the design doc. The refutation is
/// in-repo and reproducible: `cargo test --features cluster cluster::pinned`.
pub fn generate_self_signed(
    sans: &[San],
    validity_days: u32,
    now: time::OffsetDateTime,
) -> anyhow::Result<GeneratedCert> {
    if sans.is_empty() {
        anyhow::bail!(
            "a certificate needs at least one subject alternative name: \
             without one it matches no host and every poll fails"
        );
    }

    // `checked_add` rather than `+`: `--validity-days` is operator input, and
    // an absurd one should be a refusal the operator can read, not a panic in
    // the middle of minting.
    let not_after = now
        .checked_add(time::Duration::days(i64::from(validity_days)))
        .with_context(|| {
            format!(
                "a validity of {validity_days} days from {now} runs past the \
                 representable date range"
            )
        })?;

    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .context("generating an ECDSA P-256 key pair")?;

    let mut params = rcgen::CertificateParams::default();
    // rcgen's default `not_before` is 1975-01-01. Harmless in practice, but it
    // makes the printed validity a lie, and no test that asserts only on
    // `not_after` would ever notice.
    //
    // Backdated by [`CLOCK_SKEW_MARGIN`]: the two ends of this channel are
    // different machines, and the one that validates is not the one that
    // minted.
    params.not_before = now - CLOCK_SKEW_MARGIN;
    params.not_after = not_after;
    params.is_ca = rcgen::IsCa::ExplicitNoCa;
    params.use_authority_key_identifier_extension = false;
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    params.distinguished_name = {
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "purge-warden cluster primary");
        dn
    };
    params.subject_alt_names = sans
        .iter()
        .map(to_rcgen_san)
        .collect::<anyhow::Result<Vec<_>>>()?;

    let cert = params
        .self_signed(&key_pair)
        .context("self-signing the cluster primary certificate")?;

    // Over `cert.der()` — the full DER, signature included — because that is
    // what `openssl x509 -fingerprint -sha256` digests. The PEM is base64 of
    // exactly these bytes; digesting the PEM text instead would give a number
    // no stock tool reproduces.
    let fingerprint_sha256 = hex::encode(Sha256::digest(cert.der()));

    Ok(GeneratedCert {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
        fingerprint_sha256,
        not_after,
    })
}

/// Map one classified SAN onto rcgen's own SAN type.
///
/// **The two arms are the defect this module exists to prevent.** An
/// [`San::Ip`] routed to [`rcgen::SanType::DnsName`] produces a certificate
/// that encodes `192.0.2.1` as a *name*, which matches no IP host — and
/// nothing about the file on disk looks wrong. Pinned by
/// `the_ip_san_is_encoded_as_an_ip_and_the_dns_san_as_a_name`, which reads the
/// emitted DER rather than this function's input.
fn to_rcgen_san(san: &San) -> anyhow::Result<rcgen::SanType> {
    Ok(match san {
        San::Ip(ip) => rcgen::SanType::IpAddress(*ip),
        San::Dns(name) => rcgen::SanType::DnsName(
            rcgen::Ia5String::try_from(name.as_str())
                .with_context(|| format!("`{name}` is not a valid DNS name for a certificate"))?,
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `192.0.2.1` is RFC 5737 TEST-NET-1 and `.invalid` is RFC 2606: neither
    /// belongs to anybody, which is what CLAUDE.md §Neutrality requires of a
    /// literal that lands in `src/`.
    const TEST_IP: &str = "192.0.2.1";
    const TEST_DNS: &str = "primary.invalid";

    fn mint(days: u32, now: time::OffsetDateTime) -> GeneratedCert {
        generate_self_signed(
            &[
                San::Ip(TEST_IP.parse().unwrap()),
                San::Dns(TEST_DNS.to_string()),
            ],
            days,
            now,
        )
        .expect("mint")
    }

    /// Decode the emitted PEM back to DER **independently of the mint**, which
    /// digests rcgen's DER directly. Two paths that have to agree; one path
    /// agreeing with itself would prove nothing.
    fn der_of(cert_pem: &str) -> Vec<u8> {
        let parsed = pem::parse(cert_pem).expect("the emitted certificate must be valid PEM");
        assert_eq!(parsed.tag(), "CERTIFICATE");
        parsed.contents().to_vec()
    }

    /// Read one DER TLV at `at`, returning `(tag, value_start, value_len)`.
    fn read_tlv(der: &[u8], at: usize) -> (u8, usize, usize) {
        let tag = der[at];
        let first = der[at + 1];
        let (len, header) = if first < 0x80 {
            (usize::from(first), 2)
        } else {
            let n = usize::from(first & 0x7f);
            assert!((1..=2).contains(&n), "unexpected {n}-byte DER length");
            let mut len = 0usize;
            for k in 0..n {
                len = (len << 8) | usize::from(der[at + 2 + k]);
            }
            (len, 2 + n)
        };
        (tag, at + header, len)
    }

    /// Every `GeneralName` in the certificate's subjectAltName extension, as
    /// `(context-specific tag, value bytes)`.
    ///
    /// Deliberately reads the **encoding**, not rcgen's input struct: the tag
    /// is the only thing that tells rustls an entry is an IP rather than a
    /// name, and it is the only thing a swapped mapping would change.
    fn subject_alt_names(der: &[u8]) -> Vec<(u8, Vec<u8>)> {
        // 06 03 55 1D 11 = OBJECT IDENTIFIER 2.5.29.17 (subjectAltName).
        const SAN_OID: [u8; 5] = [0x06, 0x03, 0x55, 0x1d, 0x11];
        let value = extension_value(der, &SAN_OID)
            .expect("the certificate must carry a subjectAltName extension");
        let (tag, mut cur, names_len) = read_tlv(&value, 0);
        assert_eq!(tag, 0x30, "GeneralNames must be a SEQUENCE");

        let end = cur + names_len;
        let mut out = Vec::new();
        while cur < end {
            let (tag, v, len) = read_tlv(&value, cur);
            out.push((tag, value[v..v + len].to_vec()));
            cur = v + len;
        }
        out
    }

    /// The `extnValue` octets of the extension identified by `oid_der`, or
    /// `None` if the certificate does not carry it.
    ///
    /// The optional `critical` BOOLEAN between the OID and the value is the
    /// part that is easy to miss: rcgen marks basicConstraints critical, so
    /// `01 01 FF` sits there — the *extension's* criticality, nothing to do
    /// with the `cA` flag inside. A window scan that does not skip it reads
    /// an explicit `CA:FALSE` certificate as `CA:TRUE`, which is exactly what
    /// the first draft of `the_certificate_is_an_end_entity_not_a_ca` did.
    fn extension_value(der: &[u8], oid_der: &[u8]) -> Option<Vec<u8>> {
        let at = der.windows(oid_der.len()).position(|w| w == oid_der)?;
        let mut i = at + oid_der.len();
        if der[i] == 0x01 {
            let (_, v, len) = read_tlv(der, i);
            i = v + len;
        }
        let (tag, v, len) = read_tlv(der, i);
        assert_eq!(tag, 0x04, "extnValue must be an OCTET STRING");
        Some(der[v..v + len].to_vec())
    }

    #[test]
    fn an_ip_san_is_classified_as_an_ip_not_a_dns_name() {
        // Asserting the VARIANT, not merely that it parsed: swapping the two
        // arms is the mutation that matters, and a test that only checks for
        // `Ok(_)` stays green through it.
        assert_eq!(
            classify_san("100.64.0.24").unwrap(),
            San::Ip("100.64.0.24".parse().unwrap())
        );
        assert_eq!(
            classify_san("home-warden").unwrap(),
            San::Dns("home-warden".to_string())
        );
    }

    #[test]
    fn a_san_carrying_a_scheme_port_or_path_is_refused() {
        for bad in [
            "https://example.invalid",
            "host:8053",
            "host/path",
            "",
            "  ",
        ] {
            assert!(classify_san(bad).is_err(), "must refuse {bad:?}");
        }
    }

    #[test]
    fn no_san_is_an_error_not_a_certificate() {
        let now = time::OffsetDateTime::UNIX_EPOCH;
        assert!(generate_self_signed(&[], 3650, now).is_err());
    }

    /// The one test the SAN mapping exists for. Reads the emitted DER, so it
    /// goes red if [`to_rcgen_san`] routes an [`San::Ip`] to a `dNSName`.
    #[test]
    fn the_ip_san_is_encoded_as_an_ip_and_the_dns_san_as_a_name() {
        let cert = mint(3650, time::OffsetDateTime::UNIX_EPOCH);
        let names = subject_alt_names(&der_of(&cert.cert_pem));

        // 0x87 = context-specific [7] primitive = iPAddress, four octets for
        // IPv4. 0x82 = [2] = dNSName, IA5 text.
        assert!(
            names.contains(&(0x87, vec![192, 0, 2, 1])),
            "the IP SAN must be encoded as an iPAddress GeneralName; got {names:?}"
        );
        assert!(
            names.contains(&(0x82, TEST_DNS.as_bytes().to_vec())),
            "the DNS SAN must be encoded as a dNSName GeneralName; got {names:?}"
        );
        // The swap, stated as a negative so the failure names the defect.
        assert!(
            !names
                .iter()
                .any(|(tag, v)| *tag == 0x82 && v == TEST_IP.as_bytes()),
            "the IP is carried as a dNSName — rustls matches that against no \
             IP host, and every poll fails while the file looks correct"
        );
        assert_eq!(names.len(), 2, "exactly the two SANs asked for: {names:?}");
    }

    /// The fingerprint spans the FULL DER — the bytes `openssl x509
    /// -fingerprint -sha256` digests — and not the TBS body or the PEM text.
    ///
    /// Hermetic: it decodes the emitted PEM itself rather than reusing the DER
    /// the mint hashed, and it is the assertion that must always be green.
    /// [`the_fingerprint_matches_stock_openssl`] is the cross-check against
    /// the tool the operator actually runs, and it skips when openssl is not
    /// installed.
    #[test]
    fn the_fingerprint_is_sha256_over_the_full_der() {
        let cert = mint(3650, time::OffsetDateTime::UNIX_EPOCH);
        let der = der_of(&cert.cert_pem);
        assert_eq!(cert.fingerprint_sha256, hex::encode(Sha256::digest(&der)));
        assert_eq!(cert.fingerprint_sha256.len(), 64);
        assert_eq!(
            cert.fingerprint_sha256,
            cert.fingerprint_sha256.to_lowercase(),
            "the operator compares this against openssl's output; case must be stable"
        );
        // A digest over the TBS body would also be 64 lowercase hex chars, so
        // state the difference: the full DER is strictly longer than its own
        // first element, and hashing that element gives a different number.
        let (_, tbs_start, _) = read_tlv(&der, 0);
        let (_, tbs_value, tbs_len) = read_tlv(&der, tbs_start);
        let tbs = &der[tbs_start..tbs_value + tbs_len];
        assert!(tbs.len() < der.len());
        assert_ne!(
            cert.fingerprint_sha256,
            hex::encode(Sha256::digest(tbs)),
            "the fingerprint must not be a digest of the TBS body"
        );
    }

    /// Cross-check against the tool named in [`GeneratedCert`]'s doc comment.
    ///
    /// **Fails, rather than skipping, when openssl is not runnable.** A skip
    /// would print through `eprintln!`, which libtest swallows on a passing
    /// test — so the cross-check would go dark and still report `ok`, which is
    /// the detector-death CLAUDE.md documents twice. The claim being tested is
    /// *"stock tooling reproduces this"*; an environment without the stock
    /// tool cannot answer it, and saying nothing is the wrong answer.
    /// [`the_fingerprint_is_sha256_over_the_full_der`] is the hermetic gate
    /// and stays green with or without openssl.
    #[test]
    fn the_fingerprint_matches_stock_openssl() {
        use std::io::Write;

        let cert = mint(3650, time::OffsetDateTime::UNIX_EPOCH);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("api.crt");
        std::fs::File::create(&path)
            .and_then(|mut f| f.write_all(cert.cert_pem.as_bytes()))
            .expect("write pem");

        let out = match std::process::Command::new("openssl")
            .args(["x509", "-in"])
            .arg(&path)
            .args([
                "-noout",
                "-fingerprint",
                "-sha256",
                "-ext",
                "subjectAltName",
            ])
            .output()
        {
            Ok(out) => out,
            Err(e) => panic!(
                "openssl is not runnable ({e}), so the claim that the operator \
                 can reproduce this fingerprint with stock tooling went \
                 unverified. Install openssl, or delete this test deliberately \
                 — do not let it pass in silence."
            ),
        };
        assert!(
            out.status.success(),
            "openssl failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let text = String::from_utf8_lossy(&out.stdout);
        let printed = text
            .lines()
            .find_map(|l| l.split_once("Fingerprint="))
            .expect("openssl must print a fingerprint")
            .1
            .replace(':', "")
            .to_lowercase();
        assert_eq!(cert.fingerprint_sha256, printed);
        // openssl renders the SAN types by name, so this is a second,
        // independent reading of the mapping the DER walk above checks.
        assert!(
            text.contains(&format!("IP Address:{TEST_IP}")),
            "openssl must see an IP SAN: {text}"
        );
        assert!(
            text.contains(&format!("DNS:{TEST_DNS}")),
            "openssl must see a DNS SAN: {text}"
        );
    }

    #[test]
    fn two_certificates_have_different_fingerprints() {
        let now = time::OffsetDateTime::UNIX_EPOCH;
        // Same inputs both times: the keys are fresh per mint, so the DER — and
        // therefore the pin — must differ anyway.
        assert_ne!(
            mint(3650, now).fingerprint_sha256,
            mint(3650, now).fingerprint_sha256
        );
    }

    #[test]
    fn not_after_is_validity_days_after_now() {
        let now = time::OffsetDateTime::UNIX_EPOCH + time::Duration::days(20_000);
        for days in [1_u32, 30, 3650] {
            let cert = mint(days, now);
            assert_eq!(cert.not_after, now + time::Duration::days(i64::from(days)));
        }
    }

    /// The struct field is what the verb prints; the DER is what a client
    /// enforces. Assert they are the same date, so the printed expiry cannot
    /// drift from the real one.
    #[test]
    fn the_der_carries_the_same_validity_window_as_the_struct() {
        let now = time::OffsetDateTime::UNIX_EPOCH + time::Duration::days(20_000);
        let cert = mint(365, now);
        let der = der_of(&cert.cert_pem);

        // RFC 5280: dates before 2050 are UTCTime (tag 0x17), `YYMMDDHHMMSSZ`.
        let fmt = time::macros::format_description!(
            "[year repr:last_two][month][day][hour][minute][second]Z"
        );
        // `not_before` is backdated by CLOCK_SKEW_MARGIN — asserted against the
        // constant rather than a literal, so the test states the RELATIONSHIP
        // and a future change to the margin does not need this test edited to
        // stay meaningful.
        let not_before = now - CLOCK_SKEW_MARGIN;
        let mut want = vec![0x30, 0x1e, 0x17, 0x0d];
        want.extend_from_slice(not_before.format(&fmt).unwrap().as_bytes());
        want.extend_from_slice(&[0x17, 0x0d]);
        want.extend_from_slice(cert.not_after.format(&fmt).unwrap().as_bytes());
        assert!(
            der.windows(want.len()).any(|w| w == want),
            "the DER validity window must be {} .. {}",
            not_before.format(&fmt).unwrap(),
            cert.not_after.format(&fmt).unwrap()
        );
    }

    /// A certificate is valid on a peer whose clock trails the minter's.
    ///
    /// The regression this guards is invisible to every other test here: they
    /// all read the DER with the same clock that minted it, so a
    /// `not_before = now` certificate looks perfectly valid to all of them and
    /// fails only on the second machine.
    #[test]
    fn the_validity_window_opens_before_the_minting_instant() {
        let now = time::OffsetDateTime::UNIX_EPOCH + time::Duration::days(20_000);
        let cert = mint(3650, now);
        let der = der_of(&cert.cert_pem);
        let fmt = time::macros::format_description!(
            "[year repr:last_two][month][day][hour][minute][second]Z"
        );

        // A peer 30 minutes behind must fall INSIDE the window.
        let trailing_peer_now = now - time::Duration::minutes(30);
        let mut opens_at = vec![0x17, 0x0d];
        opens_at.extend_from_slice((now - CLOCK_SKEW_MARGIN).format(&fmt).unwrap().as_bytes());
        assert!(
            der.windows(opens_at.len()).any(|w| w == opens_at),
            "the certificate must already be valid at {}, the clock of a peer that trails",
            trailing_peer_now.format(&fmt).unwrap()
        );
        assert!(
            now - CLOCK_SKEW_MARGIN < trailing_peer_now,
            "the margin must cover ordinary drift"
        );
    }

    #[test]
    fn a_one_day_certificate_is_expired_two_days_later() {
        let now = time::OffsetDateTime::UNIX_EPOCH + time::Duration::days(20_000);
        let cert = mint(1, now);
        assert!(cert.not_after < now + time::Duration::days(2));
        assert!(cert.not_after > now);
    }

    /// A certificate whose public key is not the emitted private key's is
    /// unusable, and nothing about either file looks wrong.
    #[test]
    fn the_emitted_key_is_the_one_the_certificate_carries() {
        let cert = mint(3650, time::OffsetDateTime::UNIX_EPOCH);
        let key = rcgen::KeyPair::from_pem(&cert.key_pem)
            .expect("the emitted key must be a loadable PKCS#8 key");
        let spki = key.public_key_der();
        let der = der_of(&cert.cert_pem);
        assert!(
            der.windows(spki.len()).any(|w| w == spki.as_slice()),
            "the certificate must carry the public key of the emitted private key"
        );
        assert!(cert.key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    }

    /// `CA:FALSE`, no AKI — the shape `cluster::pinned` measured as the only
    /// one rustls will serve when the leaf is also the pinned anchor. See the
    /// `generate_self_signed` doc comment.
    #[test]
    fn the_certificate_is_an_end_entity_not_a_ca() {
        let der = der_of(&mint(3650, time::OffsetDateTime::UNIX_EPOCH).cert_pem);
        // 06 03 55 1D 13 = basicConstraints. `IsCa::ExplicitNoCa` emits the
        // extension with `cA` spelled out FALSE (`30 03 01 01 00`); a future
        // rcgen omitting the DEFAULT-FALSE boolean would emit `30 00`. Both
        // say CA:FALSE. `30 03 01 01 FF` — CA:TRUE — fails either way.
        const BASIC_CONSTRAINTS: [u8; 5] = [0x06, 0x03, 0x55, 0x1d, 0x13];
        let bc = extension_value(&der, &BASIC_CONSTRAINTS)
            .expect("basicConstraints must be present and explicitly CA:FALSE");
        assert!(
            bc == [0x30, 0x00] || bc == [0x30, 0x03, 0x01, 0x01, 0x00],
            "CA:TRUE makes the pin unusable — rustls rejects the leaf with \
             CaUsedAsEndEntity when it is also the trust anchor; got {bc:02x?}"
        );
        // 06 03 55 1D 23 = authorityKeyIdentifier.
        const AKI: [u8; 5] = [0x06, 0x03, 0x55, 0x1d, 0x23];
        assert!(
            !der.windows(AKI.len()).any(|w| w == AKI),
            "a self-signed end-entity certificate needs no authority key identifier"
        );
    }

    #[test]
    fn an_unrepresentable_validity_is_an_error_not_a_panic() {
        let now = time::OffsetDateTime::UNIX_EPOCH;
        // Matched rather than `expect_err`: that needs `GeneratedCert: Debug`,
        // and a derived `Debug` would print `key_pem` — the private key — into
        // any `{:?}`. The struct stays undebuggable on purpose.
        let err = match generate_self_signed(&[San::Ip(TEST_IP.parse().unwrap())], u32::MAX, now) {
            Ok(_) => panic!("u32::MAX days runs past year 9999 and must not mint"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("representable date range"));
    }
}
