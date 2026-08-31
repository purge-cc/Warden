//! DNSSEC algorithm identification — the subset this validator handles.
//!
//! This is intentionally distinct from hickory's [`Algorithm::is_supported`],
//! which reports whether hickory's *compiled crypto backend* can handle an
//! algorithm (seven algorithms). Here we model the narrower **validation
//! scope** of the §4.10 workstream, which targets RSASHA256 (IANA 8) and
//! ECDSAP256SHA256 (IANA 13) — the two algorithms covering the overwhelming
//! majority of signed zones, including the root KSK (RSASHA256). Other
//! algorithms are *recognised* but out of scope; a later sprint maps them to an
//! "insecure / cannot validate" verdict rather than a hard error.

use hickory_proto::dnssec::Algorithm;

/// A DNSSEC signing algorithm within this validator's §4.10 scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportedAlgorithm {
    /// RSA/SHA-256 — IANA algorithm number 8 (RFC 5702). The root zone KSK
    /// uses this algorithm.
    RsaSha256,
    /// ECDSA Curve P-256 with SHA-256 — IANA algorithm number 13 (RFC 6605).
    EcdsaP256Sha256,
}

impl SupportedAlgorithm {
    /// Identify a hickory [`Algorithm`] as one of the §4.10-supported set, or
    /// `None` if it is out of scope for validation.
    pub fn from_algorithm(algorithm: Algorithm) -> Option<Self> {
        match algorithm {
            Algorithm::RSASHA256 => Some(Self::RsaSha256),
            Algorithm::ECDSAP256SHA256 => Some(Self::EcdsaP256Sha256),
            _ => None,
        }
    }

    /// The hickory [`Algorithm`] this maps back to.
    pub fn algorithm(self) -> Algorithm {
        match self {
            Self::RsaSha256 => Algorithm::RSASHA256,
            Self::EcdsaP256Sha256 => Algorithm::ECDSAP256SHA256,
        }
    }

    /// The IANA algorithm number (RFC 4034 Appendix A.1): 8 or 13.
    pub fn number(self) -> u8 {
        u8::from(self.algorithm())
    }
}

/// Whether `algorithm` is within this validator's §4.10 scope (RSASHA256 or
/// ECDSAP256SHA256). Recognised-but-out-of-scope algorithms return `false`.
pub fn is_supported(algorithm: Algorithm) -> bool {
    SupportedAlgorithm::from_algorithm(algorithm).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_in_scope_algorithms() {
        assert_eq!(
            SupportedAlgorithm::from_algorithm(Algorithm::RSASHA256),
            Some(SupportedAlgorithm::RsaSha256)
        );
        assert_eq!(
            SupportedAlgorithm::from_algorithm(Algorithm::ECDSAP256SHA256),
            Some(SupportedAlgorithm::EcdsaP256Sha256)
        );
        assert!(is_supported(Algorithm::RSASHA256));
        assert!(is_supported(Algorithm::ECDSAP256SHA256));
    }

    #[test]
    fn rejects_out_of_scope_algorithms() {
        // Recognised by hickory but out of §4.10 validation scope. (Deprecated
        // variants such as RSASHA1 are deliberately omitted to avoid triggering
        // hickory's `#[deprecated]` lint.)
        for alg in [
            Algorithm::RSASHA512,
            Algorithm::ECDSAP384SHA384,
            Algorithm::ED25519,
            Algorithm::Unknown(99),
        ] {
            assert!(!is_supported(alg), "{alg:?} must be out of §4.10 scope");
            assert_eq!(SupportedAlgorithm::from_algorithm(alg), None);
        }
    }

    #[test]
    fn number_matches_iana() {
        assert_eq!(SupportedAlgorithm::RsaSha256.number(), 8);
        assert_eq!(SupportedAlgorithm::EcdsaP256Sha256.number(), 13);
    }
}
