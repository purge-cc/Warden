//! Embedded IANA DNS root trust anchor(s).
//!
//! The root zone's Key-Signing-Key (KSK) is the apex of the DNSSEC chain of
//! trust: every validation ultimately terminates by matching a chained DNSKEY
//! against one of these anchors. IANA publishes them as DS records in
//! `root-anchors.xml`; we embed that canonical DS form (key tag, algorithm,
//! digest type, digest).
//!
//! ## RFC 5011 rollover-aware shape
//!
//! [`RootTrustAnchors`] holds a **set** of anchors rather than a single key,
//! because the root KSK is rolled over periodically (RFC 5011 / RFC 7958).
//! As of this writing two KSKs are simultaneously published and valid:
//! KSK-2017 (key tag 20326) and KSK-2024 (key tag 38696). Both are embedded.
//! The set shape, the [`RootTrustAnchors::push`] mutator, and the per-anchor
//! `valid_from` / `valid_until` metadata make future automated rollover
//! representable. Today only the representation exists: there is no add /
//! hold-down / revoke timing logic, so `valid_from` / `valid_until` are
//! informational only.

use hickory_proto::dnssec::rdata::DS;
use hickory_proto::dnssec::{Algorithm, DigestType};

/// One embedded root trust anchor, in IANA DS form plus its publication window.
#[derive(Debug, Clone)]
pub struct RootTrustAnchor {
    /// DNSKEY key tag (RFC 4034 Appendix B). 20326 = KSK-2017, 38696 = KSK-2024.
    pub key_tag: u16,
    /// Signing algorithm of the referenced DNSKEY (the root uses RSASHA256).
    pub algorithm: Algorithm,
    /// Digest algorithm used to build the DS digest (the root uses SHA-256).
    pub digest_type: DigestType,
    /// The DS digest bytes (32 bytes for SHA-256).
    pub digest: Vec<u8>,
    /// IANA `validFrom` (ISO-8601). Informational only — not enforced by any
    /// rollover timing logic.
    pub valid_from: &'static str,
    /// IANA `validUntil`; `None` = no scheduled retirement. Informational only.
    pub valid_until: Option<&'static str>,
}

impl RootTrustAnchor {
    /// This anchor as a hickory [`DS`] record, for DNSKEY matching
    /// (`DS::covers(name, &dnskey)`).
    pub fn to_ds(&self) -> DS {
        DS::new(
            self.key_tag,
            self.algorithm,
            self.digest_type,
            self.digest.clone(),
        )
    }
}

/// The set of trusted root KSK anchors. Rollover-aware: more than one anchor may
/// be valid simultaneously during a roll.
#[derive(Debug, Clone)]
pub struct RootTrustAnchors(Vec<RootTrustAnchor>);

impl RootTrustAnchors {
    /// The anchors currently published in IANA `root-anchors.xml`: KSK-2017
    /// (key tag 20326) and KSK-2024 (key tag 38696). The expired KSK-2010
    /// (key tag 19036, retired 2019-01-11) is deliberately excluded.
    pub fn iana() -> Self {
        Self(vec![
            RootTrustAnchor {
                key_tag: 20326,
                algorithm: Algorithm::RSASHA256,
                digest_type: DigestType::SHA256,
                digest: hex::decode(
                    "e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d",
                )
                .expect("embedded root anchor digest is valid hex"),
                valid_from: "2017-02-02T00:00:00+00:00",
                valid_until: None,
            },
            RootTrustAnchor {
                key_tag: 38696,
                algorithm: Algorithm::RSASHA256,
                digest_type: DigestType::SHA256,
                digest: hex::decode(
                    "683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16",
                )
                .expect("embedded root anchor digest is valid hex"),
                valid_from: "2024-07-18T00:00:00+00:00",
                valid_until: None,
            },
        ])
    }

    /// The embedded anchors.
    pub fn anchors(&self) -> &[RootTrustAnchor] {
        &self.0
    }

    /// Number of embedded anchors.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the anchor set is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Find an anchor by DNSKEY key tag.
    pub fn find_by_key_tag(&self, key_tag: u16) -> Option<&RootTrustAnchor> {
        self.0.iter().find(|a| a.key_tag == key_tag)
    }

    /// Add an anchor (e.g. a future rollover successor).
    pub fn push(&mut self, anchor: RootTrustAnchor) {
        self.0.push(anchor);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iana_root_anchors_load() {
        let anchors = RootTrustAnchors::iana();
        assert_eq!(
            anchors.len(),
            2,
            "both currently-published root KSKs embedded"
        );
        assert!(!anchors.is_empty());

        let ksk2017 = anchors.find_by_key_tag(20326).expect("KSK-2017 present");
        assert_eq!(ksk2017.algorithm, Algorithm::RSASHA256);
        assert_eq!(u8::from(ksk2017.digest_type), 2, "SHA-256");
        assert_eq!(ksk2017.digest.len(), 32);
        assert_eq!(ksk2017.valid_until, None);

        let ksk2024 = anchors.find_by_key_tag(38696).expect("KSK-2024 present");
        assert_eq!(ksk2024.algorithm, Algorithm::RSASHA256);
        assert_eq!(ksk2024.digest.len(), 32);

        // The expired KSK-2010 must NOT be embedded as a live anchor.
        assert!(anchors.find_by_key_tag(19036).is_none());
    }

    #[test]
    fn anchor_converts_to_ds_matching_wire_form() {
        let anchors = RootTrustAnchors::iana();
        let ds = anchors.find_by_key_tag(20326).unwrap().to_ds();
        assert_eq!(ds.key_tag(), 20326);
        assert_eq!(ds.algorithm(), Algorithm::RSASHA256);
        assert_eq!(ds.digest().len(), 32);

        // Cross-check the embedded digest against the same DS decoded from wire.
        let wire = crate::dnssec::parse::decode_ds_rdata(
            &hex::decode(
                "4f660802e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d",
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(ds.digest(), wire.digest());
    }

    #[test]
    fn set_is_rollover_extensible() {
        let mut anchors = RootTrustAnchors::iana();
        let before = anchors.len();
        anchors.push(RootTrustAnchor {
            key_tag: 12345,
            algorithm: Algorithm::RSASHA256,
            digest_type: DigestType::SHA256,
            digest: vec![0u8; 32],
            valid_from: "2030-01-01T00:00:00+00:00",
            valid_until: None,
        });
        assert_eq!(anchors.len(), before + 1);
        assert!(anchors.find_by_key_tag(12345).is_some());
    }
}
