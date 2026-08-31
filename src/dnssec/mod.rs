//! DNSSEC validation (RFC 4033-4035) — **opt-in, OFF by default**.
//!
//! Gated behind the `dnssec` cargo feature (default OFF) so the standard and
//! Raspberry Pi binaries stay byte-for-byte unchanged: DNSSEC pulls in
//! hickory-proto's ring-backed crypto primitives, which add binary size. This
//! mirrors the §4.9 DoQ feature gate. `ring` is already the rustls crypto
//! provider, so enabling `dnssec` adds no new crypto backend to the tree.
//!
//! ## Scope of this module today (§4.10-1 + §4.10-2 + §4.10-3a + §4.10-3b)
//!
//! - [`crate::dnssec::trust_anchor`] — the embedded IANA root KSK trust anchor(s), in an
//!   RFC 5011-rollover-aware set shape (§4.10-1).
//! - [`crate::dnssec::parse`] — wire-format decoding of DNSKEY, DS, and RRSIG resource
//!   records, via hickory-proto's `dnssec-ring` rdata types (§4.10-1 + -2).
//! - [`crate::dnssec::algorithm`] — identification of the signing algorithms this validator
//!   handles (RSASHA256, ECDSAP256SHA256) (§4.10-1).
//! - [`crate::dnssec::verify`] — RRSIG signature verification of one RRset against one DNSKEY,
//!   the RFC 4035 §5.3.1 gates wrapped around hickory's canonical-form
//!   verifier (§4.10-2).
//! - [`crate::dnssec::chain`] — the positive chain-of-trust walk from the root anchor down to a
//!   target zone, calling [`crate::dnssec::verify::verify_rrset`] per hop, with the
//!   `max_chain_depth` / `max_queries` DoS caps enforced (§4.10-3a). Produces a
//!   four-state [`crate::dnssec::chain::ChainResult`], and at a no-DS delegation consults
//!   [`crate::dnssec::denial`] to upgrade `Indeterminate(DenialProofRequired)` to a proven
//!   `Insecure(UnsignedDelegation)` / `Bogus` (§4.10-3b).
//! - [`crate::dnssec::denial`] — authenticated denial of existence: the pure NSEC (RFC 4034 §4)
//!   proof that a delegation is unsigned (§4.10-3b). NSEC3 (RFC 5155 —
//!   closest-encloser, opt-out, base32hex) and the `max_nsec3_iterations` cap are
//!   §4.10-3c.
//! - [`crate::dnssec::cache`] — a TTL-bounded cache of [`crate::dnssec::chain::ChainResult`] verdicts
//!   (§4.10-3a).
//! - [`crate::dnssec::fetcher`] — the production [`crate::dnssec::chain::ChainFetcher`] adapter over the live
//!   [`crate::upstream::Upstream`] (§4.10-4a). Issues DO-bit queries and reshapes
//!   the response into a [`crate::dnssec::chain::FetchedRrset`].
//!
//! The chain walk is a callable **engine**, and §4.10-4a adds the production
//! fetcher that can feed it from the live upstream — but it is **not yet wired
//! into the query path**: nothing reads the
//! [`crate::config::settings::DnssecConfig`] mode to act on a [`crate::dnssec::verify::Verdict`] /
//! [`crate::dnssec::chain::ChainResult`], and no AD/CD bit or SERVFAIL is emitted. That
//! response-path consumer is §4.10-4b.

pub mod algorithm;
pub mod cache;
pub mod chain;
pub mod denial;
pub mod fetcher;
pub mod parse;
pub mod trust_anchor;
pub mod verify;

pub use algorithm::{is_supported, SupportedAlgorithm};
pub use cache::VerdictCache;
pub use chain::{validate_chain, ChainBogus, ChainFetcher, ChainResult, FetchError, Indeterminate};
pub use denial::{nsec3_matching_proves_unsigned_delegation, nsec_proves_unsigned_delegation};
pub use fetcher::UpstreamChainFetcher;
pub use trust_anchor::{RootTrustAnchor, RootTrustAnchors};
pub use verify::{verify_rrset, BogusReason, InsecureReason, Verdict};
