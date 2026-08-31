//! Production [`ChainFetcher`] over the daemon's upstream (§4.10-4a).
//!
//! [`crate::dnssec::fetcher::UpstreamChainFetcher`] adapts the live [`crate::upstream::Upstream`] into
//! the [`ChainFetcher`] seam the chain walk consumes. It issues DNSSEC OK (DO)
//! queries — the wrapped upstream MUST be built with `dnssec_ok = true`
//! (`build_upstream(.., true)` / `PlainUpstream::new(.., true)`), or the
//! responses won't carry the RRSIG / NSEC / NSEC3 material validation needs.
//!
//! It performs **no validation** — it only reshapes one upstream response into a
//! [`FetchedRrset`]: the answer section split into the records of the queried
//! type and the RRSIG(s) covering them, plus the authority section verbatim (the
//! NSEC/NSEC3 no-DS denial proofs the chain reads at a no-DS delegation).
//!
//! This adapter is built but **not yet wired into the response path** — that is
//! §4.10-4b (the `dnssec.mode` consumer + AD/CD/SERVFAIL). 4a ships the plumbing.

use std::sync::Arc;

use async_trait::async_trait;
use hickory_proto::dnssec::rdata::DNSSECRData;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Name, RData, RecordType};

use crate::dnssec::chain::{ChainFetcher, FetchError, FetchedRrset};
use crate::upstream::Upstream;

/// A [`ChainFetcher`] backed by the daemon's configured upstream.
///
/// The wrapped upstream must have the DO bit baked in (`dnssec_ok = true`); see
/// the module docs. Cheap to clone-share via `Arc`.
pub struct UpstreamChainFetcher {
    upstream: Arc<dyn Upstream>,
}

impl UpstreamChainFetcher {
    /// Wrap a DO-enabled upstream. The caller is responsible for having built
    /// `upstream` with `dnssec_ok = true`.
    #[must_use]
    pub fn new(upstream: Arc<dyn Upstream>) -> Self {
        Self { upstream }
    }
}

#[async_trait]
impl ChainFetcher for UpstreamChainFetcher {
    async fn fetch(&self, name: &Name, rtype: RecordType) -> Result<FetchedRrset, FetchError> {
        let resp = self
            .upstream
            .lookup(name, rtype, None)
            .await
            .map_err(|e| FetchError::Transport(e.to_string()))?;

        // A server failure is not a verdict — it makes the chain Indeterminate.
        // NXDOMAIN / NODATA are valid answers (empty `records` models an absent
        // RRset), so only ServFail / Refused map to a fetch failure.
        if matches!(
            resp.response_code,
            ResponseCode::ServFail | ResponseCode::Refused
        ) {
            return Err(FetchError::ServerFailure);
        }

        // The answer section carries the queried-type records mixed with the
        // RRSIG(s) covering them; split them apart. RRSIGs travel separately in
        // `FetchedRrset.rrsigs`, the records of the queried type in `records`.
        let rrsigs = resp
            .records
            .iter()
            .filter_map(|r| match &r.data {
                RData::DNSSEC(DNSSECRData::RRSIG(sig)) => Some(sig.clone()),
                _ => None,
            })
            .collect();
        let records = resp
            .records
            .iter()
            .filter(|r| r.record_type() == rtype)
            .cloned()
            .collect();

        Ok(FetchedRrset {
            records,
            rrsigs,
            authority: resp.authority,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::dnssec::rdata::{DNSSECRData, RRSIG};
    use hickory_proto::dnssec::Algorithm;
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{DNSClass, RData, Record};
    use std::net::Ipv4Addr;

    use crate::dns::edns::EdnsClientSubnet;
    use crate::dns::error::DnsError;
    use crate::upstream::UpstreamResponse;

    /// Canned upstream: returns a fixed response, or a transport error.
    struct MockUpstream {
        records: Vec<Record>,
        authority: Vec<Record>,
        response_code: ResponseCode,
        fail: bool,
    }

    #[async_trait]
    impl Upstream for MockUpstream {
        async fn lookup(
            &self,
            _name: &Name,
            _record_type: RecordType,
            _ecs: Option<EdnsClientSubnet>,
        ) -> Result<UpstreamResponse, DnsError> {
            if self.fail {
                return Err(DnsError::AllUpstreamsFailed);
            }
            Ok(UpstreamResponse {
                records: self.records.clone(),
                response_code: self.response_code,
                soa_minimum_ttl: None,
                authority: self.authority.clone(),
            })
        }
    }

    fn a_record(name: &str) -> Record {
        Record::from_rdata(
            name.parse().unwrap(),
            300,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
        )
    }

    /// A throwaway RRSIG record (the fetcher splits by type, never verifies, so
    /// the signature bytes are irrelevant here).
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

    fn rrsig_record(name: &str) -> Record {
        let rrsig = rrsig_new(
            RecordType::A,
            Algorithm::ECDSAP256SHA256,
            2,
            300,
            2_000_000_000,
            1_000_000_000,
            1234,
            "example.com.".parse().unwrap(),
            vec![0u8; 8],
        );
        Record::from_rdata(
            name.parse().unwrap(),
            300,
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig)),
        )
    }

    fn soa_record(name: &str) -> Record {
        use hickory_proto::rr::rdata::SOA;
        let soa = SOA::new(
            "ns1.example.com.".parse().unwrap(),
            "admin.example.com.".parse().unwrap(),
            2026052300,
            3600,
            600,
            86400,
            600,
        );
        Record::from_rdata(name.parse().unwrap(), 600, RData::SOA(soa))
    }

    #[tokio::test]
    async fn fetch_splits_records_rrsigs_and_authority() {
        let up = MockUpstream {
            records: vec![a_record("example.com."), rrsig_record("example.com.")],
            authority: vec![soa_record("example.com.")],
            response_code: ResponseCode::NoError,
            fail: false,
        };
        let fetcher = UpstreamChainFetcher::new(Arc::new(up));
        let name: Name = "example.com.".parse().unwrap();

        let got = fetcher.fetch(&name, RecordType::A).await.unwrap();
        assert_eq!(got.records.len(), 1, "only the A record in `records`");
        assert_eq!(got.records[0].record_type(), RecordType::A);
        assert_eq!(got.rrsigs.len(), 1, "the RRSIG split into `rrsigs`");
        assert_eq!(got.authority.len(), 1, "authority section carried verbatim");
        // sanity: the queried-type filter does not leak the RRSIG into `records`.
        assert!(got.records.iter().all(|r| r.record_type() == RecordType::A));
        let _ = DNSClass::IN;
    }

    #[tokio::test]
    async fn fetch_servfail_maps_to_server_failure() {
        let up = MockUpstream {
            records: vec![],
            authority: vec![],
            response_code: ResponseCode::ServFail,
            fail: false,
        };
        let fetcher = UpstreamChainFetcher::new(Arc::new(up));
        let name: Name = "example.com.".parse().unwrap();
        assert!(matches!(
            fetcher.fetch(&name, RecordType::DNSKEY).await,
            Err(FetchError::ServerFailure)
        ));
    }

    #[tokio::test]
    async fn fetch_refused_maps_to_server_failure() {
        let up = MockUpstream {
            records: vec![],
            authority: vec![],
            response_code: ResponseCode::Refused,
            fail: false,
        };
        let fetcher = UpstreamChainFetcher::new(Arc::new(up));
        let name: Name = "example.com.".parse().unwrap();
        assert!(matches!(
            fetcher.fetch(&name, RecordType::DS).await,
            Err(FetchError::ServerFailure)
        ));
    }

    #[tokio::test]
    async fn fetch_transport_error_maps_to_transport() {
        let up = MockUpstream {
            records: vec![],
            authority: vec![],
            response_code: ResponseCode::NoError,
            fail: true,
        };
        let fetcher = UpstreamChainFetcher::new(Arc::new(up));
        let name: Name = "example.com.".parse().unwrap();
        match fetcher.fetch(&name, RecordType::DS).await {
            Err(FetchError::Transport(_)) => {}
            other => panic!("expected Transport error, got {other:?}"),
        }
    }

    /// NODATA (NoError + empty answer) is a valid response, not a fetch failure:
    /// the no-DS hook relies on an empty `records` modelling an absent RRset.
    #[tokio::test]
    async fn fetch_nodata_is_not_a_failure() {
        let up = MockUpstream {
            records: vec![],
            authority: vec![soa_record("example.com.")],
            response_code: ResponseCode::NoError,
            fail: false,
        };
        let fetcher = UpstreamChainFetcher::new(Arc::new(up));
        let name: Name = "example.com.".parse().unwrap();
        let got = fetcher.fetch(&name, RecordType::DS).await.unwrap();
        assert!(got.records.is_empty(), "absent DS RRset");
        assert_eq!(got.authority.len(), 1, "denial proof retained in authority");
    }

    // ── Live engine proof (network; run ON the CT) ───────────────────────────
    //
    // The five-sprint payoff at the engine+fetcher level: the production fetcher
    // feeds the FROZEN `validate_chain` from a real DO-enabled upstream.
    // `#[ignore]`d (network, non-hermetic). The client-visible AD/SERVFAIL smokes
    // are §4.10-4b (there is no response hook yet).
    //
    //   cargo test --features dnssec -- --ignored dnssec_live
    #[tokio::test]
    #[ignore = "network: run on the CT — fetches real signed zones"]
    async fn dnssec_live_chain_proof() {
        use crate::config::settings::DnssecConfig;
        use crate::dnssec::{validate_chain, ChainResult, RootTrustAnchors};
        use crate::upstream::plain::PlainUpstream;
        use std::time::{SystemTime, UNIX_EPOCH};

        // A DO-enabled upstream pointed at a validating recursive resolver.
        // `dnssec_ok = true` forces PlainUpstream onto the raw-socket path so
        // the DO bit is actually set (ECS off).
        let upstream: Arc<dyn Upstream> = Arc::new(
            PlainUpstream::new(
                &["1.1.1.1:53".to_string()],
                std::time::Duration::from_secs(5),
                false, // ecs_enabled
                true,  // dnssec_ok
            )
            .unwrap(),
        );
        let fetcher = UpstreamChainFetcher::new(upstream);
        let anchors = RootTrustAnchors::iana();
        let caps = DnssecConfig::default();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        async fn verdict(
            fetcher: &UpstreamChainFetcher,
            anchors: &RootTrustAnchors,
            caps: &DnssecConfig,
            now: u32,
            zone: &str,
        ) -> ChainResult {
            let name: Name = zone.parse().unwrap();
            let ans = fetcher.fetch(&name, RecordType::A).await.unwrap();
            let answer = ans.rrsigs.first().map(|s| (ans.records.as_slice(), s));
            validate_chain(fetcher, anchors, &name, answer, now, caps).await
        }

        let signed = verdict(&fetcher, &anchors, &caps, now, "internetsociety.org.").await;
        let broken = verdict(&fetcher, &anchors, &caps, now, "dnssec-failed.org.").await;
        eprintln!("internetsociety.org => {signed:?}");
        eprintln!("dnssec-failed.org   => {broken:?}");

        assert!(
            matches!(signed, ChainResult::Secure),
            "internetsociety.org must validate Secure, got {signed:?}"
        );
        assert!(
            matches!(broken, ChainResult::Bogus(_)),
            "dnssec-failed.org must be Bogus, got {broken:?}"
        );
    }
}
