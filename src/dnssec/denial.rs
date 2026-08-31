//! Authenticated denial of existence — proving a name/type is *absent* (§4.10-3b).
//!
//! When the chain walk ([`crate::dnssec::chain`]) reaches a delegation with no DS
//! RRset, it cannot tell a legitimately *unsigned* delegation from a stripped-DS
//! downgrade attack without an authenticated NSEC/NSEC3 proof from the parent that
//! no DS exists at the child. This module holds the **pure denial-proof logic**:
//! given an NSEC record the caller has *already authenticated* against the zone's
//! keys, does it prove the queried fact (here: no DS at a delegation)?
//!
//! Authentication is deliberately **not** done here — the caller
//! ([`crate::dnssec::chain::validate_chain`]) verifies the NSEC RRset's signature
//! first, so the "authenticate before trust" gate lives in exactly one place and
//! these functions stay crypto-free and exhaustively unit-testable. An unsigned or
//! forged NSEC never reaches this module's `true` arm.
//!
//! Scope: NSEC (RFC 4034 §4) and NSEC3 (RFC 5155). For NSEC3 the caller passes
//! records it has *already authenticated*; this module hashes the delegation name
//! (the only crypto-adjacent step — a name digest, not a signature) and decides
//! matching vs opt-out covering. The `max_nsec3_iterations` cap is enforced here,
//! before any hash, as the third DoS cap (§4.10-3c).

use data_encoding::BASE32_DNSSEC;
use hickory_proto::dnssec::rdata::{NSEC, NSEC3};
use hickory_proto::dnssec::Nsec3HashAlgorithm;
use hickory_proto::rr::{Name, RecordType};

/// Does this *authenticated* NSEC prove that its owner is an **unsigned
/// delegation** — a zone cut with no DS RRset (RFC 4035 §5.2, RFC 6840 §4.3)?
///
/// The proof requires all three bits of the owner's type bitmap:
/// - **DS absent** — the delegation is not signed (no secure entry point);
/// - **NS present** — the owner really is a delegation point (a zone cut), not an
///   in-zone name or empty non-terminal that merely lacks a DS;
/// - **SOA absent** — the NSEC is the *parent-side* delegation record, not the
///   child zone's own apex (an apex carries SOA), so "no DS" is the parent's
///   assertion about the child.
///
/// Dropping the NS-present check would let an empty-non-terminal or in-zone NSEC
/// masquerade as an unsigned delegation; dropping the SOA-absent check would let a
/// signed child's apex NSEC be mistaken for a parent's no-DS proof. Both are
/// downgrade vectors — hence all three bits are mandatory.
#[must_use]
pub fn nsec_proves_unsigned_delegation(nsec: &NSEC) -> bool {
    proves_unsigned_delegation(nsec.type_bit_maps())
}

/// The shared no-DS bitmap rule: **NS present ∧ DS absent ∧ SOA absent** over an
/// owner's type bitmap. Single source of truth for both the NSEC
/// ([`nsec_proves_unsigned_delegation`]) and NSEC3
/// ([`nsec3_matching_proves_unsigned_delegation`]) predicates — keeping the
/// three-bit downgrade rule (and any future change to it) in exactly one place.
fn proves_unsigned_delegation(types: impl Iterator<Item = RecordType>) -> bool {
    let (mut has_ns, mut has_ds, mut has_soa) = (false, false, false);
    for t in types {
        match t {
            RecordType::NS => has_ns = true,
            RecordType::DS => has_ds = true,
            RecordType::SOA => has_soa = true,
            _ => {}
        }
    }
    has_ns && !has_ds && !has_soa
}

/// Does this *authenticated* **matching** NSEC3 prove its owner is an unsigned
/// delegation — the NSEC3 analogue of [`nsec_proves_unsigned_delegation`]
/// (RFC 5155 §8.9): **NS present ∧ DS absent ∧ SOA absent**, a parent-side zone cut
/// with no secure entry point. Reads only the type bitmap; the same three-bit rule
/// (and the same downgrade reasoning) as the NSEC predicate.
#[must_use]
pub fn nsec3_matching_proves_unsigned_delegation(nsec3: &NSEC3) -> bool {
    proves_unsigned_delegation(nsec3.type_bit_maps())
}

/// Outcome of scanning *already-authenticated* NSEC3 records for a no-DS proof at a
/// delegation `child` — the [`crate::dnssec::chain`] no-DS hook (§4.10-3c).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Nsec3NoDsProof {
    /// A matching NSEC3 (NS∧!DS∧!SOA) or an opt-out NSEC3 covering `child`'s hash —
    /// a legitimately unsigned delegation.
    UnsignedDelegation,
    /// A matching NSEC3 *contradicts* a no-DS claim: it asserts a DS, or is not a
    /// parent-side zone cut (NS clear, or SOA set). The fingerprint of a stripped-DS
    /// downgrade.
    Contradiction,
    /// No matching and no opt-out-covering NSEC3 — nothing proves no-DS here.
    NoProof,
    /// A candidate's iteration count exceeds the cap; refused **before hashing**
    /// (RFC 5155 §10.3 — an attacker-chosen iteration count is a CPU-DoS vector).
    IterationsExceeded,
}

/// Decide whether a set of **already-authenticated** NSEC3 records proves that the
/// delegation `child` has no DS RRset (RFC 5155 §8.6 / §8.9).
///
/// `nsec3s` are `(owner name, rdata)` pairs the caller has verified against the
/// parent's keys — authentication is **not** done here; it lives in the single
/// auth-before-trust gate (`chain::verify_keyset`, private to that module so not linkable here). Scope is the
/// closest-encloser-free single-hop case the no-DS hook needs: a *matching* NSEC3
/// at the delegation hash, or an *opt-out covering* NSEC3 (delegation == next-closer
/// — the dominant deployment); the full closest-encloser proof for deep next-closers
/// is general negative-validation, deferred to §4.10-4 (see the §4.10-3c handoff).
///
/// `max_iterations` is enforced **before any hash**. Matching wins over opt-out
/// covering (RFC 5155 §8.6: consult a covering NSEC3 only when none matches).
pub(crate) fn nsec3_proves_no_ds(
    child: &Name,
    nsec3s: &[(Name, NSEC3)],
    max_iterations: u16,
) -> Nsec3NoDsProof {
    // Only SHA-1 (the sole defined NSEC3 hash algorithm, RFC 5155 §11) is usable;
    // an unknown hash makes a record unusable, not a proof.
    let usable: Vec<&(Name, NSEC3)> = nsec3s
        .iter()
        .filter(|(_, n)| n.hash_algorithm() == Nsec3HashAlgorithm::SHA1)
        .collect();
    let Some(first) = usable.first() else {
        return Nsec3NoDsProof::NoProof;
    };
    // Cap before hashing: refuse an absurd iteration count before any SHA-1 work.
    if usable.iter().any(|(_, n)| n.iterations() > max_iterations) {
        return Nsec3NoDsProof::IterationsExceeded;
    }

    // All NSEC3s in a response share hash params (RFC 5155 §8.2); hash `child` once.
    let target = match Nsec3HashAlgorithm::SHA1.hash(first.1.salt(), child, first.1.iterations()) {
        Ok(d) => d.as_ref().to_vec(),
        Err(_) => return Nsec3NoDsProof::NoProof,
    };

    // 1. A matching NSEC3 (owner hash == hash(child)) decides on its bitmap alone.
    for (owner, n) in &usable {
        if decode_owner_hash(owner).as_deref() == Some(target.as_slice()) {
            return if nsec3_matching_proves_unsigned_delegation(n) {
                Nsec3NoDsProof::UnsignedDelegation
            } else {
                Nsec3NoDsProof::Contradiction
            };
        }
    }

    // 2. No match: an opt-out NSEC3 covering hash(child) proves an insecure
    //    (unsigned) delegation directly. Sound because RFC 5155 §6 lets an opt-out
    //    NSEC3 cover only insecure delegations — a secure DS could not hide under it.
    for (owner, n) in &usable {
        if !n.opt_out() {
            continue;
        }
        if let Some(owner_hash) = decode_owner_hash(owner) {
            if hash_interval_covers(&owner_hash, n.next_hashed_owner_name(), &target) {
                return Nsec3NoDsProof::UnsignedDelegation;
            }
        }
    }

    Nsec3NoDsProof::NoProof
}

/// Decode an NSEC3 owner name's first label (base32hex text, RFC 5155 §1.3) to the
/// raw hash bytes it encodes. `None` if the name has no label or it is not valid
/// base32hex. Decoding is case-insensitive (`BASE32_DNSSEC` maps A-V → a-v).
fn decode_owner_hash(owner: &Name) -> Option<Vec<u8>> {
    let first_label = owner.iter().next()?;
    BASE32_DNSSEC.decode(first_label).ok()
}

/// Does the NSEC3 hash interval strictly **cover** `target` (RFC 5155 §1.3): the
/// open range `(owner, next)`, wrapping at the zone's last NSEC3 where `owner ≥
/// next`. Raw hash bytes; byte-lexicographic order is canonical hash order. Strict
/// at both ends — an exact equality is a *match*, handled separately.
fn hash_interval_covers(owner: &[u8], next: &[u8], target: &[u8]) -> bool {
    if owner < next {
        owner < target && target < next
    } else {
        // Wraparound: the last NSEC3 in the ring, whose `next` is the first owner.
        target > owner || target < next
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::Name;

    /// Build an NSEC carrying exactly `types` in its bitmap. The next domain name
    /// is irrelevant to the unsigned-delegation predicate (it reads only the
    /// bitmap), so any name serves.
    fn nsec(types: &[RecordType]) -> NSEC {
        NSEC::new(
            Name::from_ascii("z.example.").unwrap(),
            types.iter().copied(),
        )
    }

    #[test]
    fn unsigned_delegation_ns_set_ds_clear_soa_clear() {
        // The real unsigned-delegation case: a parent-side zone cut with no DS.
        let n = nsec(&[RecordType::NS, RecordType::RRSIG, RecordType::NSEC]);
        assert!(nsec_proves_unsigned_delegation(&n));
    }

    #[test]
    fn ds_present_is_not_unsigned() {
        // A signed delegation (DS present) is the opposite of unsigned.
        let n = nsec(&[
            RecordType::NS,
            RecordType::DS,
            RecordType::RRSIG,
            RecordType::NSEC,
        ]);
        assert!(!nsec_proves_unsigned_delegation(&n));
    }

    #[test]
    fn ns_absent_is_not_a_delegation() {
        // No NS bit ⇒ not a zone cut (e.g. an empty non-terminal). "No DS" here
        // says nothing about a child zone's signing status.
        let n = nsec(&[RecordType::RRSIG, RecordType::NSEC]);
        assert!(!nsec_proves_unsigned_delegation(&n));
    }

    #[test]
    fn soa_present_is_an_apex_not_a_parent_proof() {
        // SOA present ⇒ the child zone's own apex, not the parent's delegation
        // NSEC; cannot serve as a parent-side no-DS proof.
        let n = nsec(&[
            RecordType::SOA,
            RecordType::NS,
            RecordType::RRSIG,
            RecordType::NSEC,
        ]);
        assert!(!nsec_proves_unsigned_delegation(&n));
    }

    // ---- NSEC3 (§4.10-3c) --------------------------------------------------
    //
    // These exercise the *pure* logic over already-authenticated NSEC3 rdata (no
    // signing — `nsec3_proves_no_ds` does not authenticate). The auth dimension
    // (unsigned / forged / out-of-scope) is covered end-to-end in `chain.rs` via
    // `resolve_no_ds`, where the one auth gate lives.

    const SALT: &[u8] = b"\xaa\xbb";
    const ITERS: u16 = 1;

    fn child() -> Name {
        Name::from_ascii("org.").unwrap()
    }

    /// hash(name) with the fixture's salt/iterations — the raw NSEC3 owner hash.
    fn h(name_: &Name) -> Vec<u8> {
        Nsec3HashAlgorithm::SHA1
            .hash(SALT, name_, ITERS)
            .unwrap()
            .as_ref()
            .to_vec()
    }

    /// A single-label NSEC3 owner name `<base32hex(hash)>.` — only the first label
    /// is read by `decode_owner_hash`, so the zone suffix is irrelevant here.
    fn nsec3_owner(hash: &[u8]) -> Name {
        Name::from_ascii(BASE32_DNSSEC.encode(hash)).unwrap()
    }

    fn nsec3_rr(opt_out: bool, iters: u16, next: Vec<u8>, types: &[RecordType]) -> NSEC3 {
        NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            opt_out,
            iters,
            SALT.to_vec(),
            next,
            types.iter().copied(),
        )
    }

    fn nsec3_bitmap(types: &[RecordType]) -> NSEC3 {
        nsec3_rr(false, ITERS, vec![0xff; 20], types)
    }

    #[test]
    fn nsec3_unsigned_delegation_ns_set_ds_clear_soa_clear() {
        assert!(nsec3_matching_proves_unsigned_delegation(&nsec3_bitmap(&[
            RecordType::NS,
            RecordType::RRSIG,
        ])));
    }

    #[test]
    fn nsec3_ds_present_is_not_unsigned() {
        assert!(!nsec3_matching_proves_unsigned_delegation(&nsec3_bitmap(
            &[RecordType::NS, RecordType::DS, RecordType::RRSIG,]
        )));
    }

    #[test]
    fn nsec3_ns_absent_is_not_a_delegation() {
        assert!(!nsec3_matching_proves_unsigned_delegation(&nsec3_bitmap(
            &[RecordType::RRSIG]
        )));
    }

    #[test]
    fn nsec3_soa_present_is_an_apex() {
        assert!(!nsec3_matching_proves_unsigned_delegation(&nsec3_bitmap(
            &[RecordType::SOA, RecordType::NS, RecordType::RRSIG,]
        )));
    }

    #[test]
    fn nsec3_matching_unsigned_delegation_is_unsigned() {
        let child = child();
        let owner = nsec3_owner(&h(&child));
        let n = nsec3_rr(
            false,
            ITERS,
            vec![0xff; 20],
            &[RecordType::NS, RecordType::RRSIG],
        );
        assert_eq!(
            nsec3_proves_no_ds(&child, &[(owner, n)], 100),
            Nsec3NoDsProof::UnsignedDelegation
        );
    }

    #[test]
    fn nsec3_matching_with_ds_is_contradiction() {
        let child = child();
        let owner = nsec3_owner(&h(&child));
        let n = nsec3_rr(
            false,
            ITERS,
            vec![0xff; 20],
            &[RecordType::NS, RecordType::DS, RecordType::RRSIG],
        );
        assert_eq!(
            nsec3_proves_no_ds(&child, &[(owner, n)], 100),
            Nsec3NoDsProof::Contradiction
        );
    }

    #[test]
    fn nsec3_opt_out_covering_is_unsigned() {
        let child = child();
        let target = h(&child);
        // The bracket [00…, FF…] covers any non-extreme hash; a SHA-1 digest is
        // never all-zero/all-one (2^-159), so the bracket is valid.
        assert!(target != vec![0u8; 20] && target != vec![0xffu8; 20]);
        let owner = nsec3_owner(&[0u8; 20]); // owner hash = min, ≠ target
        let n = nsec3_rr(true, ITERS, vec![0xff; 20], &[RecordType::RRSIG]);
        assert_eq!(
            nsec3_proves_no_ds(&child, &[(owner, n)], 100),
            Nsec3NoDsProof::UnsignedDelegation
        );
    }

    #[test]
    fn nsec3_covering_without_opt_out_is_no_proof() {
        // Same covering interval, opt-out CLEAR: a covering NSEC3 without opt-out
        // proves nothing about a no-DS delegation (RFC 5155 §6).
        let child = child();
        let owner = nsec3_owner(&[0u8; 20]);
        let n = nsec3_rr(false, ITERS, vec![0xff; 20], &[RecordType::RRSIG]);
        assert_eq!(
            nsec3_proves_no_ds(&child, &[(owner, n)], 100),
            Nsec3NoDsProof::NoProof
        );
    }

    #[test]
    fn nsec3_non_covering_non_matching_is_no_proof() {
        let child = child();
        let target = h(&child);
        // An interval deterministically excluding `target` via its first byte's top
        // bit — robust regardless of the hash value.
        let (owner_hash, next_hash) = if target[0] < 0x80 {
            (vec![0x80u8; 20], vec![0xffu8; 20]) // target < owner ⇒ not covered
        } else {
            (vec![0x00u8; 20], vec![0x7fu8; 20]) // target > next  ⇒ not covered
        };
        let owner = nsec3_owner(&owner_hash);
        let n = nsec3_rr(true, ITERS, next_hash, &[RecordType::RRSIG]);
        assert_eq!(
            nsec3_proves_no_ds(&child, &[(owner, n)], 100),
            Nsec3NoDsProof::NoProof
        );
    }

    #[test]
    fn nsec3_iterations_over_cap_is_refused() {
        // iterations (200) > cap (150) ⇒ refused before any hash. The third DoS cap.
        let child = child();
        let owner = nsec3_owner(&[0u8; 20]);
        let n = nsec3_rr(
            false,
            200,
            vec![0xff; 20],
            &[RecordType::NS, RecordType::RRSIG],
        );
        assert_eq!(
            nsec3_proves_no_ds(&child, &[(owner, n)], 150),
            Nsec3NoDsProof::IterationsExceeded
        );
    }
}
