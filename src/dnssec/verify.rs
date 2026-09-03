//! RRSIG signature verification — authenticate one RRset against one DNSKEY.
//!
//! This is the verification *engine*. It is **not** wired into the live query
//! path; a chain walk invokes it per-RRset while walking from a trust anchor
//! and acts on the [`Verdict`] (set the AD bit, SERVFAIL on bogus, pass
//! through insecure).
//!
//! ## Canonicalization is delegated to hickory — by design
//!
//! Hand-rolling the RFC 4034 §6 canonical RRset form is the single highest
//! correctness hazard in DNSSEC. We do **not** do it. hickory-proto's
//! [`Verifier::verify_rrsig`] builds the to-be-signed serialization
//! (`TBS::from_sig`): it filters the RRset, sorts it into canonical order
//! (§6.3), reconstructs the wildcard owner name (RFC 4035 §5.3.2), lowercases
//! names (`set_canonical_names`, §6.2), emits the RRSIG_RDATA-minus-signature
//! prefix, and verifies the signature with the key's ring-backed primitive.
//!
//! `verify_rrsig` does the canonical form **and the crypto, only**. It does
//! *not* enforce the RRSIG validity period, nor the algorithm / key-tag / type
//! / label-count matches that RFC 4035 §5.3.1 requires of a validator. Those
//! gates are this module's job; [`verify_rrset`] is a thin §5.3.1 wrapper that
//! applies them before (and around) the delegated `verify_rrsig` call.

use hickory_proto::dnssec::rdata::{DNSKEY, RRSIG};
use hickory_proto::dnssec::{PublicKey, Verifier};
use hickory_proto::rr::{DNSClass, Name, Record};

use crate::dnssec::algorithm::SupportedAlgorithm;

/// The outcome of verifying an RRset against a DNSKEY, in the RFC 4035 §5
/// three-state model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The signature is cryptographically valid and currently within its
    /// validity period: the RRset is authenticated by this key.
    Secure,
    /// The signature could not be validated because the algorithm is outside
    /// this validator's scope — not a failure, just "cannot assert security".
    Insecure(InsecureReason),
    /// The signature is present but failed validation: the response is forged,
    /// stale, or otherwise must not be trusted.
    Bogus(BogusReason),
}

/// Why a [`Verdict::Insecure`] result could not be validated, or why a chain is
/// provably unsigned. [`verify_rrset`] only ever yields `OutOfScopeAlgorithm`;
/// the chain walk adds the denial-of-existence-proven cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsecureReason {
    /// The RRSIG's signing algorithm is recognised but outside this
    /// validator's scope (RSASHA256 / ECDSAP256SHA256).
    OutOfScopeAlgorithm,
    /// A delegation has no DS RRset and the parent served an *authenticated*
    /// NSEC/NSEC3 proof that no DS exists there (RFC 4035 §5.2) — the child zone
    /// is legitimately unsigned, not a stripped-DS downgrade. Produced only by
    /// the chain walk, never by [`verify_rrset`].
    UnsignedDelegation,
}

/// Why a [`Verdict::Bogus`] result failed validation. For diagnostics and
/// metrics; consumers branch on the [`Verdict`] category, not the reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BogusReason {
    /// The RRSIG algorithm does not match the DNSKEY's algorithm.
    AlgorithmMismatch,
    /// The RRSIG key tag does not match the DNSKEY's computed tag (or the key's
    /// tag could not be computed).
    KeyTagMismatch,
    /// The RRset is empty, or a record's type is not the type the RRSIG covers.
    TypeCoveredMismatch,
    /// The RRSIG Labels field exceeds the owner name's label count
    /// (RFC 4035 §5.3.1) — the RRSIG cannot authenticate this RRset.
    NameError,
    /// The RRSIG signer's name is not the zone that contains the RRset.
    SignerNameMismatch,
    /// The validator's clock is before the RRSIG inception time.
    NotYetValid,
    /// The validator's clock is after the RRSIG expiration time.
    Expired,
    /// The cryptographic signature check over the canonical RRset failed.
    SignatureInvalid,
}

/// Verify `rrsig` over the `records` RRset against `dnskey`, per RFC 4035 §5.3.
///
/// `name` / `dns_class` are the RRset's owner name and class. `now` is the
/// validator's notion of the current time, in Unix seconds — **injected** so
/// the cryptographic verdict is reproducible (the signature over a fixed RRset
/// is time-invariant; only the validity-period check reads `now`). The live
/// caller passes `OffsetDateTime::now_utc().unix_timestamp() as u32`.
///
/// Checks run cheap-to-expensive (RFC 4035 §5.3.1), short-circuiting on the
/// first failure, with the cryptographic check (§5.3.2/§5.3.3) last.
#[must_use]
pub fn verify_rrset(
    dnskey: &DNSKEY,
    rrsig: &RRSIG,
    name: &Name,
    dns_class: DNSClass,
    records: &[Record],
    now: u32,
) -> Verdict {
    // 1. The signing algorithm must be within this validator's scope.
    if SupportedAlgorithm::from_algorithm(rrsig.input().algorithm).is_none() {
        return Verdict::Insecure(InsecureReason::OutOfScopeAlgorithm);
    }

    // 2. RFC 4035 §5.3.1: the RRSIG algorithm must match the DNSKEY's.
    if rrsig.input().algorithm != dnskey.public_key().algorithm() {
        return Verdict::Bogus(BogusReason::AlgorithmMismatch);
    }

    // 3. RFC 4035 §5.3.1: the RRSIG key tag must match the DNSKEY's. A key whose
    //    tag cannot even be computed cannot be confirmed as the signer.
    match dnskey.calculate_key_tag() {
        Ok(tag) if tag == rrsig.input().key_tag => {}
        _ => return Verdict::Bogus(BogusReason::KeyTagMismatch),
    }

    // 4. The RRset must be non-empty and every record must be the covered type.
    //    hickory's verifier silently filters the iterator by (name, class,
    //    type); this guard stops a partial or empty RRset being hashed and
    //    spuriously matching a crafted signature.
    if records.is_empty()
        || records
            .iter()
            .any(|r| r.record_type() != rrsig.input().type_covered)
    {
        return Verdict::Bogus(BogusReason::TypeCoveredMismatch);
    }

    // 5. RFC 4035 §5.3.1: the owner's label count must be >= the RRSIG Labels
    //    field. (hickory's determine_name() also rejects this, but as a generic
    //    error; gating here keeps the verdict precise.)
    if usize::from(rrsig.input().num_labels) > usize::from(name.num_labels()) {
        return Verdict::Bogus(BogusReason::NameError);
    }

    // 6. RFC 4035 §5.3.1: the signer's name must be the zone containing the
    //    RRset. `zone_of` is reflexive, so an apex self-signature passes.
    if !rrsig.input().signer_name.zone_of(name) {
        return Verdict::Bogus(BogusReason::SignerNameMismatch);
    }

    // 7. RFC 4035 §5.3.1: now must lie within [inception, expiration]. The
    //    timestamps are RFC 1982 serial numbers (RFC 4034 §3.1.5); compare with
    //    wrap-aware mod-2^32 arithmetic. (`SerialNumber`'s field is private, so
    //    we cannot lean on its `PartialOrd` for `now` — reproduce it here.)
    let inception = rrsig.input().sig_inception.get();
    let expiration = rrsig.input().sig_expiration.get();
    if (now.wrapping_sub(inception) as i32) < 0 {
        return Verdict::Bogus(BogusReason::NotYetValid);
    }
    if (expiration.wrapping_sub(now) as i32) < 0 {
        return Verdict::Bogus(BogusReason::Expired);
    }

    // 8. Cryptographic verification over the canonical RRset (RFC 4034 §6 +
    //    RFC 4035 §5.3.2/§5.3.3) — delegated wholesale to hickory.
    match dnskey.verify_rrsig(name, dns_class, rrsig, records.iter()) {
        Ok(()) => Verdict::Secure,
        Err(_) => Verdict::Bogus(BogusReason::SignatureInvalid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::dnssec::rdata::DNSSECRData;
    use hickory_proto::dnssec::Algorithm;
    use hickory_proto::op::Message;
    use hickory_proto::rr::{RData, RecordType};

    /// 0.26 removed `RRSIG::new`; build a `SigInput` (u32 timestamps wrapped as
    /// `SerialNumber`) and pair it with the signature via `RRSIG::from_sig`.
    #[allow(clippy::too_many_arguments)]
    fn rrsig_new(
        type_covered: RecordType,
        algorithm: Algorithm,
        num_labels: u8,
        original_ttl: u32,
        sig_expiration: u32,
        sig_inception: u32,
        key_tag: u16,
        signer_name: Name,
        sig: Vec<u8>,
    ) -> RRSIG {
        use hickory_proto::dnssec::rdata::SigInput;
        use hickory_proto::rr::SerialNumber;
        RRSIG::from_sig(
            SigInput {
                type_covered,
                algorithm,
                num_labels,
                original_ttl,
                sig_expiration: SerialNumber::new(sig_expiration),
                sig_inception: SerialNumber::new(sig_inception),
                key_tag,
                signer_name,
            },
            sig,
        )
    }

    // Full `dig +dnssec . DNSKEY` response (wire format). Answer section: the
    // three root DNSKEYs (KSK-2017 tag 20326 + KSK-2024 tag 38696 + ZSK, all
    // RSASHA256) and the RRSIG over the RRset made by the KSK (tag 20326).
    const ROOT_DNSKEY_RESPONSE: &str = "1234818000010004000000010000300001000030000100028a7c01080101030803010001af7a8deba49d995a792aefc80263e991efdbc86138a931deb2c65d5682eab5d3b03738e3dfdc89d96da64c86c0224d9ce02514d285da3068b19054e5e787b2969058e98e12566c8c808c40c0b769e1db1a24a1bd9b31e303184a31fc7bb56b85bbba8abc02cd5040a444a36d47695969849e16ad856bb58e8fac8855224400319bdab224d83fc0e66aab32ff74bfeaf0f91c454e6850a1295207bbd4cdde8f6ffb08faa9755c2e3284efa01f99393e18786cb132f1e66ebc6517318e1ce8a3b7337ebb54d035ab57d9706ecd9350d4afacd825e43c8668eece89819caf6817af62dc4fbd82f0e33f6647b2b6bda175f14607f59f4635451e6b27df282ef73d87000030000100028a7c01080100030803010001be5d0d87dfa60009f155062f042d5973e5416b2320526d08cd34fd768a53ef259fea1f6a1dead8ac44223bf3420fa7a9dc518fef1e9ad3e77b59ad61c6c558fe10f44f839e23892cad3d474e45bb3bc66eb1bb0c37510d45ff71e745755ecef29144018a49a98351f4109320057def70ced9b89ab8a480df56fb23694aff0a31a11d6d7f972a27848c6c952f8ae1e2700128522d804ecc25a193567794f9b619841599f1171ec3e5480a098ee87e54bbf8653b74d27012d9859d66151131cdd241d7573e9a82ea2e680669ef4e985cd22847f893810866b11ed75fec0bd19f103362f1408c94eaf459d3a232b8930644c8b0912b861256ee9b206dd762596eb5000030000100028a7c01080101030803010001acffb409bcc939f831f7a1e5ec88f7a59255ec53040be432027390a4ce896d6f9086f3c5e177fbfe118163aaec7af1462c47945944c4e2c026be5e98bbcded25978272e1e3e079c5094d573f0e83c92f02b32d3513b1550b826929c80dd0f92cac966d17769fd5867b647c3f38029abdc48152eb8f207159ecc5d232c7c1537c79f4b7ac28ff11682f21681bf6d6aba555032bf6f9f036beb2aaa5b3778d6eebfba6bf9ea191be4ab0caea759e2f773a1f9029c73ecb8d5735b9321db085f1b8e2d8038fe2941992548cee0d67dd4547e11dd63af9c9fc1c5466fb684cf009d7197c2cf79e792ab501e6a8a1ca519af2cb9b5f6367e94c0d47502451357be1b500002e000100028a7c0113003008000002a3006a29fa806a0e4b004f66003eb63aef891c6aa08533d04c2e51d08c1a6834df2a30af63d3fec27ec4ac17dfc21384c03bc1c1df400af2f1c2ab80788e20f8383a3dfd8eb01f48b8d4430d191e58baddb7fcdeec2cf381d042d094535b7595071c082aa88794db2c0d56fda210a29df0b7f456699235921050261075ecb2ab6c63e716768c0b5db2def27eb62958808a5a2dddde98a2375e2bd9ed6e89f34fea1f222fb7fa70032c1e9357dafc378ab72207826c9d7674584679a743825e68146d759c0e886a2de996daf752aa5ae00f8297842aef9eac3bd27a698ec475719f22ac9ee8345e3b07a2a67aedee0a406309744bb7907ed1de6e266bad02f9e2caa297277e7715d77ce7d2772f00002904d0000080000000";

    // Full `dig +dnssec cloudflare.com DNSKEY` response. Answer section: the two
    // cloudflare DNSKEYs (KSK + ZSK, ECDSAP256SHA256 alg 13) and the RRSIG over
    // the RRset. The owner name carries DNS-0x20 mixed case ("ClouDFlaRe.com");
    // canonicalization lowercases it, so verification still succeeds.
    const CLOUDFLARE_DNSKEY_RESPONSE: &str = "1234818000010003000000010a636c6f7564666c61726503636f6d00003000010a436c6f5544466c615265c0170030000100000cdb00440101030d99db2cc14cabdc33d6d77da63a2f15f71112584f234e8d1dc428e39e8a4a97e1aa271a555dc90701e17e2a4c4b6f120b7c32d44f4ac02bd894cf2d4be7778a19c0200030000100000cdb00440100030da09311112cf9138818cd2feae970ebbd4d6a30f6088c25b325a39abbc5cd1197aa098283e5aaf421177c2aa5d714992a9957d1bcc18f98cd71f1f1806b65e148c020002e000100000cdb006200300d0200000e106a40a93b69f03dbb09430a636c6f7564666c61726503636f6d0041833bc43e79c963e23459aedb84560b5d7db65748724c7b4596bac27187731ba09a7b8f3c45edc71f77d120919cbee561f453f131e7064f1e1932d65a12200c00002904d0000080000000";

    /// Decode a captured response packet's answer section into records.
    fn answers(hex: &str) -> Vec<Record> {
        let bytes = hex::decode(hex).unwrap();
        Message::from_vec(&bytes).unwrap().answers.to_vec()
    }

    /// All DNSKEY records in an answer set.
    fn dnskey_records(answers: &[Record]) -> Vec<Record> {
        answers
            .iter()
            .filter(|r| r.record_type() == RecordType::DNSKEY)
            .cloned()
            .collect()
    }

    /// The RRSIG in an answer set whose key tag matches `want` (or the only one
    /// when `want` is `None`). Selecting by key tag avoids grabbing a ZSK-made
    /// RRSIG over a DNSKEY RRset that is also KSK-signed.
    fn rrsig(answers: &[Record], want: Option<u16>) -> RRSIG {
        answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::DNSSEC(DNSSECRData::RRSIG(s)) => Some(s.clone()),
                _ => None,
            })
            .find(|s| want.is_none_or(|kt| s.input().key_tag == kt))
            .expect("answer set has a matching RRSIG")
    }

    /// The DNSKEY in `records` whose computed key tag is `key_tag`.
    fn dnskey_with_tag(records: &[Record], key_tag: u16) -> DNSKEY {
        records
            .iter()
            .filter_map(|r| match &r.data {
                RData::DNSSEC(DNSSECRData::DNSKEY(k)) => Some(k.clone()),
                _ => None,
            })
            .find(|k| k.calculate_key_tag().ok() == Some(key_tag))
            .expect("a DNSKEY with the requested tag")
    }

    /// A DNSKEY in `records` whose tag is *not* `excluded` (for wrong-key tests).
    fn dnskey_other_than(records: &[Record], excluded: u16) -> DNSKEY {
        records
            .iter()
            .filter_map(|r| match &r.data {
                RData::DNSSEC(DNSSECRData::DNSKEY(k)) => Some(k.clone()),
                _ => None,
            })
            .find(|k| k.calculate_key_tag().ok() != Some(excluded))
            .expect("a second, different DNSKEY")
    }

    // ---- positive ----------------------------------------------------------

    #[test]
    fn verifies_root_dnskey_rrset_rsasha256() {
        let ans = answers(ROOT_DNSKEY_RESPONSE);
        let keys = dnskey_records(&ans);
        let sig = rrsig(&ans, Some(20326));
        let key = dnskey_with_tag(&keys, 20326);
        let now = sig.input().sig_inception.get() + 1; // inside the validity window
        assert_eq!(
            verify_rrset(&key, &sig, &keys[0].name, keys[0].dns_class, &keys, now),
            Verdict::Secure
        );
    }

    #[test]
    fn verifies_cloudflare_dnskey_rrset_ecdsap256() {
        let ans = answers(CLOUDFLARE_DNSKEY_RESPONSE);
        let keys = dnskey_records(&ans);
        let sig = rrsig(&ans, None);
        let key = dnskey_with_tag(&keys, sig.input().key_tag);
        assert_eq!(key.public_key().algorithm(), Algorithm::ECDSAP256SHA256);
        let now = sig.input().sig_inception.get() + 1;
        assert_eq!(
            verify_rrset(&key, &sig, &keys[0].name, keys[0].dns_class, &keys, now),
            Verdict::Secure
        );
    }

    // ---- negative: validity period ----------------------------------------

    #[test]
    fn rejects_expired_rrsig() {
        let ans = answers(ROOT_DNSKEY_RESPONSE);
        let keys = dnskey_records(&ans);
        let sig = rrsig(&ans, Some(20326));
        let key = dnskey_with_tag(&keys, 20326);
        let now = sig.input().sig_expiration.get() + 1; // just past expiration
        assert_eq!(
            verify_rrset(&key, &sig, &keys[0].name, keys[0].dns_class, &keys, now),
            Verdict::Bogus(BogusReason::Expired)
        );
    }

    #[test]
    fn rejects_not_yet_valid_rrsig() {
        let ans = answers(ROOT_DNSKEY_RESPONSE);
        let keys = dnskey_records(&ans);
        let sig = rrsig(&ans, Some(20326));
        let key = dnskey_with_tag(&keys, 20326);
        let now = sig.input().sig_inception.get() - 1; // just before inception
        assert_eq!(
            verify_rrset(&key, &sig, &keys[0].name, keys[0].dns_class, &keys, now),
            Verdict::Bogus(BogusReason::NotYetValid)
        );
    }

    // ---- negative: matching gates -----------------------------------------

    #[test]
    fn rejects_wrong_key_by_tag() {
        let ans = answers(ROOT_DNSKEY_RESPONSE);
        let keys = dnskey_records(&ans);
        let sig = rrsig(&ans, Some(20326));
        let wrong = dnskey_other_than(&keys, 20326); // a different root key
        let now = sig.input().sig_inception.get() + 1;
        assert_eq!(
            verify_rrset(&wrong, &sig, &keys[0].name, keys[0].dns_class, &keys, now),
            Verdict::Bogus(BogusReason::KeyTagMismatch)
        );
    }

    #[test]
    fn rejects_algorithm_mismatch() {
        // Root RRSIG (alg 8) verified against a cloudflare DNSKEY (alg 13):
        // both are in scope, so step 1 passes and step 2 catches the mismatch.
        let root = answers(ROOT_DNSKEY_RESPONSE);
        let root_keys = dnskey_records(&root);
        let sig = rrsig(&root, Some(20326));

        let cf = answers(CLOUDFLARE_DNSKEY_RESPONSE);
        let cf_keys = dnskey_records(&cf);
        let cf_key = dnskey_with_tag(&cf_keys, rrsig(&cf, None).input().key_tag);

        let now = sig.input().sig_inception.get() + 1;
        assert_eq!(
            verify_rrset(
                &cf_key,
                &sig,
                &root_keys[0].name,
                root_keys[0].dns_class,
                &root_keys,
                now
            ),
            Verdict::Bogus(BogusReason::AlgorithmMismatch)
        );
    }

    #[test]
    fn rejects_empty_rrset() {
        let ans = answers(ROOT_DNSKEY_RESPONSE);
        let keys = dnskey_records(&ans);
        let sig = rrsig(&ans, Some(20326));
        let key = dnskey_with_tag(&keys, 20326);
        let now = sig.input().sig_inception.get() + 1;
        assert_eq!(
            verify_rrset(&key, &sig, &keys[0].name, keys[0].dns_class, &[], now),
            Verdict::Bogus(BogusReason::TypeCoveredMismatch)
        );
    }

    #[test]
    fn rejects_signer_name_mismatch() {
        // Verify the cloudflare RRSIG (signer cloudflare.com) but claim the
        // RRset's owner is an unrelated zone: signer no longer zone_of(owner).
        let ans = answers(CLOUDFLARE_DNSKEY_RESPONSE);
        let keys = dnskey_records(&ans);
        let sig = rrsig(&ans, None);
        let key = dnskey_with_tag(&keys, sig.input().key_tag);
        let foreign = Name::from_ascii("unrelated.example.").unwrap();
        let now = sig.input().sig_inception.get() + 1;
        assert_eq!(
            verify_rrset(&key, &sig, &foreign, keys[0].dns_class, &keys, now),
            Verdict::Bogus(BogusReason::SignerNameMismatch)
        );
    }

    #[test]
    fn rejects_mutated_rrset() {
        // Flip one byte deep inside the first DNSKEY's public-key blob: the
        // record still decodes, but the canonical RRset no longer matches the
        // signature.
        let mut raw = hex::decode(ROOT_DNSKEY_RESPONSE).unwrap();
        raw[100] ^= 0x01;
        let mutated = Message::from_vec(&raw).unwrap().answers.to_vec();
        let keys = dnskey_records(&mutated);

        let ans = answers(ROOT_DNSKEY_RESPONSE);
        let sig = rrsig(&ans, Some(20326));
        let key = dnskey_with_tag(&dnskey_records(&ans), 20326);
        let now = sig.input().sig_inception.get() + 1;
        assert_eq!(
            verify_rrset(&key, &sig, &keys[0].name, keys[0].dns_class, &keys, now),
            Verdict::Bogus(BogusReason::SignatureInvalid)
        );
    }

    // ---- insecure: out-of-scope algorithm ----------------------------------

    #[test]
    fn out_of_scope_algorithm_is_insecure() {
        // A synthetic RRSIG with an in-the-wild-but-out-of-scope algorithm
        // (RSASHA512). Step 1 short-circuits before any key/record use.
        let ans = answers(ROOT_DNSKEY_RESPONSE);
        let keys = dnskey_records(&ans);
        let key = dnskey_with_tag(&keys, 20326);
        let sig = rrsig_new(
            RecordType::DNSKEY,
            Algorithm::RSASHA512,
            0,
            172_800,
            2_000_000_000,
            1_000_000_000,
            20326,
            Name::root(),
            vec![0u8; 256],
        );
        assert_eq!(
            verify_rrset(
                &key,
                &sig,
                &keys[0].name,
                keys[0].dns_class,
                &keys,
                1_500_000_000
            ),
            Verdict::Insecure(InsecureReason::OutOfScopeAlgorithm)
        );
    }
}
