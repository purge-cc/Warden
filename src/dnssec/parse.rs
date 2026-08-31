//! Wire-format parsing of DNSSEC resource records (DNSKEY, DS, RRSIG).
//!
//! Thin wrappers over hickory-proto's public [`RData::read`] so the rest of the
//! crate has one stable DNSSEC-parsing entry point — and one place to add
//! length / sanity caps in a later sprint. Parsing decodes the RDATA into typed
//! records only; signature *verification* lives in [`crate::dnssec::verify`].

use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY, DS, RRSIG};
use hickory_proto::rr::{RData, RecordType};
use hickory_proto::serialize::binary::{BinDecoder, Restrict};
use hickory_proto::ProtoError;

/// Decode the RDATA portion of a DNSKEY resource record (RFC 4034 §2.1).
///
/// `rdata` is the record's RDATA only (flags ‖ protocol ‖ algorithm ‖ public
/// key), not a full DNS message. hickory enforces the RFC 4034 §2.1.2 rule that
/// the protocol octet must be 3.
pub fn decode_dnskey_rdata(rdata: &[u8]) -> Result<DNSKEY, ProtoError> {
    let len = u16::try_from(rdata.len())
        .map_err(|_| ProtoError::from("DNSKEY rdata exceeds 65535 bytes"))?;
    let mut decoder = BinDecoder::new(rdata);
    match RData::read(&mut decoder, RecordType::DNSKEY, Restrict::new(len))? {
        RData::DNSSEC(DNSSECRData::DNSKEY(key)) => Ok(key),
        other => Err(ProtoError::from(format!(
            "expected DNSKEY rdata, decoded {other:?}"
        ))),
    }
}

/// Decode the RDATA portion of a DS resource record (RFC 4034 §5.1).
///
/// `rdata` is the record's RDATA only (key tag ‖ algorithm ‖ digest type ‖
/// digest).
pub fn decode_ds_rdata(rdata: &[u8]) -> Result<DS, ProtoError> {
    let len =
        u16::try_from(rdata.len()).map_err(|_| ProtoError::from("DS rdata exceeds 65535 bytes"))?;
    let mut decoder = BinDecoder::new(rdata);
    match RData::read(&mut decoder, RecordType::DS, Restrict::new(len))? {
        RData::DNSSEC(DNSSECRData::DS(ds)) => Ok(ds),
        other => Err(ProtoError::from(format!(
            "expected DS rdata, decoded {other:?}"
        ))),
    }
}

/// Decode the RDATA portion of an RRSIG resource record (RFC 4034 §3.1).
///
/// `rdata` is the record's RDATA only (type covered ‖ algorithm ‖ labels ‖
/// original TTL ‖ signature expiration ‖ signature inception ‖ key tag ‖
/// signer's name ‖ signature). The decoded [`RRSIG`] is what
/// [`crate::dnssec::verify::verify_rrset`] consumes to authenticate an RRset.
pub fn decode_rrsig_rdata(rdata: &[u8]) -> Result<RRSIG, ProtoError> {
    let len = u16::try_from(rdata.len())
        .map_err(|_| ProtoError::from("RRSIG rdata exceeds 65535 bytes"))?;
    let mut decoder = BinDecoder::new(rdata);
    match RData::read(&mut decoder, RecordType::RRSIG, Restrict::new(len))? {
        RData::DNSSEC(DNSSECRData::RRSIG(sig)) => Ok(sig),
        other => Err(ProtoError::from(format!(
            "expected RRSIG rdata, decoded {other:?}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnssec::algorithm::is_supported;
    use hickory_proto::dnssec::{Algorithm, PublicKey};

    // Root KSK-2017 (key tag 20326) DNSKEY RDATA: flags=257 (0x0101), protocol=3,
    // algorithm=8 (RSASHA256), then the live root KSK public key. Captured from
    // `dig . DNSKEY`; the key-tag assertion below (20326 is a checksum over the
    // entire RDATA) proves these bytes are exactly the IANA root KSK.
    const ROOT_KSK_2017_DNSKEY_RDATA: &str = "0101030803010001acffb409bcc939f831f7a1e5ec88f7a59255ec53040be432027390a4ce896d6f9086f3c5e177fbfe118163aaec7af1462c47945944c4e2c026be5e98bbcded25978272e1e3e079c5094d573f0e83c92f02b32d3513b1550b826929c80dd0f92cac966d17769fd5867b647c3f38029abdc48152eb8f207159ecc5d232c7c1537c79f4b7ac28ff11682f21681bf6d6aba555032bf6f9f036beb2aaa5b3778d6eebfba6bf9ea191be4ab0caea759e2f773a1f9029c73ecb8d5735b9321db085f1b8e2d8038fe2941992548cee0d67dd4547e11dd63af9c9fc1c5466fb684cf009d7197c2cf79e792ab501e6a8a1ca519af2cb9b5f6367e94c0d47502451357be1b5";

    // Root DS RDATA (key tag ‖ alg 8 ‖ digest-type 2 ‖ SHA-256 digest) for the two
    // currently-published IANA root anchors. Authoritative digests from
    // data.iana.org/root-anchors/root-anchors.xml.
    const ROOT_DS_20326_RDATA: &str =
        "4f660802e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d";
    const ROOT_DS_38696_RDATA: &str =
        "97280802683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16";

    #[test]
    fn parses_root_ksk_2017_dnskey() {
        let bytes = hex::decode(ROOT_KSK_2017_DNSKEY_RDATA).unwrap();
        let key = decode_dnskey_rdata(&bytes).expect("root KSK DNSKEY parses");

        assert_eq!(key.flags(), 257);
        assert!(key.zone_key());
        assert!(key.secure_entry_point());
        assert!(key.is_key_signing_key());
        assert!(!key.revoke());
        assert_eq!(key.public_key().algorithm(), Algorithm::RSASHA256);
        assert!(is_supported(key.public_key().algorithm()));
        assert!(!key.public_key().public_bytes().is_empty());
        // Strong known-good check: the key tag is a checksum over the full RDATA.
        assert_eq!(key.calculate_key_tag().unwrap(), 20326);
    }

    #[test]
    fn parses_root_ds_records() {
        for (rdata_hex, key_tag, digest_hex) in [
            (
                ROOT_DS_20326_RDATA,
                20326u16,
                "e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d",
            ),
            (
                ROOT_DS_38696_RDATA,
                38696u16,
                "683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16",
            ),
        ] {
            let ds = decode_ds_rdata(&hex::decode(rdata_hex).unwrap()).expect("root DS parses");
            assert_eq!(ds.key_tag(), key_tag);
            assert_eq!(ds.algorithm(), Algorithm::RSASHA256);
            assert_eq!(u8::from(ds.digest_type()), 2, "SHA-256");
            assert_eq!(ds.digest(), hex::decode(digest_hex).unwrap().as_slice());
        }
    }

    #[test]
    fn parses_ecdsa_p256_dnskey_algorithm() {
        // flags=256 (0x0100, ZSK), protocol=3, algorithm=13 (ECDSAP256SHA256),
        // then a 64-byte P-256 public key. Sprint 1 only identifies the
        // algorithm; it does not verify the key, so dummy key bytes suffice.
        let mut bytes = vec![0x01u8, 0x00, 0x03, 0x0d];
        bytes.extend_from_slice(&[0xABu8; 64]);
        let key = decode_dnskey_rdata(&bytes).expect("alg-13 DNSKEY parses");

        assert_eq!(key.public_key().algorithm(), Algorithm::ECDSAP256SHA256);
        assert!(is_supported(key.public_key().algorithm()));
        assert!(key.zone_key());
        assert!(!key.is_key_signing_key()); // ZSK: zone-key set, SEP clear
    }

    #[test]
    fn rejects_dnskey_with_invalid_protocol() {
        // RFC 4034 §2.1.2: the protocol octet MUST be 3. Flip it and parsing fails.
        let mut bytes = hex::decode(ROOT_KSK_2017_DNSKEY_RDATA).unwrap();
        bytes[2] = 4;
        assert!(decode_dnskey_rdata(&bytes).is_err());
    }

    // RRSIG RDATA over the root DNSKEY RRset, signed by the root KSK (key tag
    // 20326, alg 8 RSASHA256). Captured from `dig +dnssec . DNSKEY` — the RRSIG
    // RDATA slice only (type covered ‖ alg ‖ labels ‖ orig TTL ‖ expiration ‖
    // inception ‖ key tag ‖ root signer ‖ 256-byte RSA signature).
    const ROOT_DNSKEY_RRSIG_RDATA: &str = "003008000002a3006a29fa806a0e4b004f66003eb63aef891c6aa08533d04c2e51d08c1a6834df2a30af63d3fec27ec4ac17dfc21384c03bc1c1df400af2f1c2ab80788e20f8383a3dfd8eb01f48b8d4430d191e58baddb7fcdeec2cf381d042d094535b7595071c082aa88794db2c0d56fda210a29df0b7f456699235921050261075ecb2ab6c63e716768c0b5db2def27eb62958808a5a2dddde98a2375e2bd9ed6e89f34fea1f222fb7fa70032c1e9357dafc378ab72207826c9d7674584679a743825e68146d759c0e886a2de996daf752aa5ae00f8297842aef9eac3bd27a698ec475719f22ac9ee8345e3b07a2a67aedee0a406309744bb7907ed1de6e266bad02f9e2caa297277e7715d77ce7d2772f";

    #[test]
    fn parses_root_dnskey_rrsig() {
        let bytes = hex::decode(ROOT_DNSKEY_RRSIG_RDATA).unwrap();
        let sig = decode_rrsig_rdata(&bytes).expect("root DNSKEY RRSIG parses");

        assert_eq!(sig.input().type_covered, RecordType::DNSKEY);
        assert_eq!(sig.input().algorithm, Algorithm::RSASHA256);
        assert_eq!(sig.input().num_labels, 0, "root has zero labels");
        assert_eq!(sig.input().original_ttl, 172_800);
        assert_eq!(sig.input().key_tag, 20326, "signed by the root KSK");
        assert!(sig.input().signer_name.is_root());
        assert_eq!(sig.input().sig_inception.get(), 1_779_321_600);
        assert_eq!(sig.input().sig_expiration.get(), 1_781_136_000);
        assert_eq!(sig.sig().len(), 256, "2048-bit RSA signature");
    }

    #[test]
    fn rejects_truncated_rrsig() {
        // A SIG/RRSIG RDATA shorter than its fixed 18-byte preamble is malformed.
        let bytes = hex::decode(ROOT_DNSKEY_RRSIG_RDATA).unwrap();
        assert!(decode_rrsig_rdata(&bytes[..10]).is_err());
    }
}
