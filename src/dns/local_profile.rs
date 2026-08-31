//! Per-profile local DNS records (Sprint 44 — Local DNS Scoping v2).
//!
//! Static A / AAAA / CNAME records scoped to a single
//! [`ResolvedProfile`](crate::profiles::profile::ResolvedProfile).
//! Built once at resolver-map construction time from the profile's
//! `local_records` slice (already validated by `validate_local_records_v2`).
//! Lives behind the existing `ArcSwap<ResolverMap>`; no new lock, no new
//! synchronisation primitive — R5 (zero-alloc, zero-lock hot path).
//!
//! Lookup precedence inside this struct (per `_docs/features/local_dns_scoping.md` §5):
//!   1. exact match in `forward`,
//!   2. if `has_subdomain_records` is `false` → return `None` (fast-path skip),
//!   3. otherwise walk `q` label-by-label, scanning `suffix_index` (sorted
//!      depth-desc so the first contains-match is the longest matching suffix).
//!
//! Only A / AAAA / CNAME participate (DR4). Other qtypes return `None` so the
//! caller falls through to the global `LocalRecords` (which still owns PTR /
//! reverse DNS — DR13) and then to the upstream forward path.

use std::collections::HashMap;
use std::fmt::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use compact_str::CompactString;

use hickory_proto::rr::rdata::{A, AAAA, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use crate::config::settings::{LocalDnsRecord, LocalDnsRecordType};

type RecordMap = HashMap<CompactString, Vec<Record>, ahash::RandomState>;

/// Per-profile local DNS record table (DM4).
///
/// `forward` carries exact-match records keyed on the lowercased domain;
/// records with `match_subdomains: true` ALSO land here under their apex so
/// `domain == apex` queries hit the O(1) path before the suffix walk.
///
/// `suffix_index` carries `match_subdomains: true` records, **sorted by label
/// depth descending** so a linear scan returns the longest matching suffix
/// first. For the home-lab cap (≤256 records per profile, threat T9 §10) the
/// scan is single-digit microseconds; if profiling later shows it hot, the
/// vec can be replaced with a label-indexed map without touching the lookup
/// surface.
///
/// `has_subdomain_records` is the fast-path bool. When `false`, [`Self::lookup`]
/// short-circuits the suffix walk completely — typical Sprint-18-style configs
/// (exact-match only) pay one `HashMap::get` per query, exactly as before.
#[derive(Debug, Default)]
pub struct ProfileLocalRecords {
    forward: RecordMap,
    suffix_index: Vec<(CompactString, Vec<Record>)>,
    has_subdomain_records: bool,
}

/// A profile-scope local-records hit: the answer records plus the **matched
/// record's apex** — the exact forward key or the wildcard suffix key that
/// fired. The handler keys the per-record hit counter by `apex`, not the raw
/// QNAME, so a wildcard flood of distinct subdomains all count under the one
/// configured apex (perfmem T1 / TRK-01 — bounds `LocalRecordsHits`). Mirrors
/// the global `LocalLookup::Hit` variant on the decoupled-sibling table.
#[derive(Debug)]
pub struct ProfileLocalHit {
    pub records: Vec<Record>,
    pub apex: CompactString,
}

impl ProfileLocalRecords {
    /// Build from a validated slice of `LocalDnsRecord`s and the parent
    /// `[local_dns].ttl_secs` used as fallback when a record's own
    /// `ttl_secs` is `None` (DR5).
    ///
    /// **Caller contract:** the slice MUST have been through
    /// `crate::config::validator::validate_local_records_v2`. Parse failures
    /// (malformed IP, malformed FQDN) are silently dropped here — the
    /// validator catches them earlier and refuses the config; this is the
    /// belt-and-braces fallback that mirrors `LocalRecords::build_data`'s
    /// `let Ok(...) = ... else { continue }` posture.
    pub fn build(records: &[LocalDnsRecord], default_ttl: u32) -> Self {
        let mut forward: RecordMap = HashMap::with_hasher(ahash::RandomState::new());
        let mut subdomain_groups: HashMap<CompactString, Vec<Record>, ahash::RandomState> =
            HashMap::with_hasher(ahash::RandomState::new());

        for entry in records {
            // Shared canonical spelling (cfg-validator-03) — keys must
            // match the validator's bookkeeping and the handler's
            // lowercase dot-less query probe.
            let domain = crate::config::validator::canonicalize_domain(&entry.domain);
            let ttl = entry.ttl_secs.unwrap_or(default_ttl);
            let Ok(name) = Name::from_str(&format!("{domain}.")) else {
                continue;
            };

            let record = match entry.record_type {
                LocalDnsRecordType::A => {
                    let Ok(ip) = entry.value.parse::<Ipv4Addr>() else {
                        continue;
                    };
                    Record::from_rdata(name, ttl, RData::A(A(ip)))
                }
                LocalDnsRecordType::AAAA => {
                    let Ok(ip) = entry.value.parse::<Ipv6Addr>() else {
                        continue;
                    };
                    Record::from_rdata(name, ttl, RData::AAAA(AAAA(ip)))
                }
                LocalDnsRecordType::CNAME => {
                    let target = crate::config::validator::canonicalize_domain(&entry.value);
                    let Ok(target_name) = Name::from_str(&format!("{target}.")) else {
                        continue;
                    };
                    Record::from_rdata(name, ttl, RData::CNAME(CNAME(target_name)))
                }
            };

            // Apex always lands in `forward` so an exact-match query short-
            // circuits the suffix walk even when match_subdomains is true
            // (per §4 "exact-match wins, apex includes self").
            forward
                .entry(CompactString::new(&domain))
                .or_default()
                .push(record.clone());

            if entry.match_subdomains {
                subdomain_groups
                    .entry(CompactString::new(&domain))
                    .or_default()
                    .push(record);
            }
        }

        // Depth-desc sort (longest suffix / most labels first). On a tie we
        // keep insertion order — the validator forbids same-`(domain, type,
        // match_subdomains)` duplicates so ties only happen between
        // different types of the same domain (e.g. an A and a CNAME), which
        // share the same probe key and are returned together.
        let mut suffix_index: Vec<(CompactString, Vec<Record>)> =
            subdomain_groups.into_iter().collect();
        suffix_index.sort_by_key(|b| std::cmp::Reverse(label_count(b.0.as_str())));

        let has_subdomain_records = !suffix_index.is_empty();

        Self {
            forward,
            suffix_index,
            has_subdomain_records,
        }
    }

    /// Records-only view of [`Self::lookup_with_apex`] — the stable shape
    /// (`Option<Vec<Record>>`) every existing caller (unit + integration tests)
    /// depends on. The handler uses `lookup_with_apex` when it also needs the
    /// matched apex for hit-counting; everyone else keeps this signature.
    pub fn lookup(&self, domain: &str, qtype: RecordType) -> Option<Vec<Record>> {
        self.lookup_with_apex(domain, qtype).map(|hit| hit.records)
    }

    /// Hot-path lookup. Returns `Some(ProfileLocalHit)` — the answer records
    /// plus the matched record's apex (perfmem T1) — on hit, `None` otherwise.
    ///
    /// **DR4:** only `A` / `AAAA` / `CNAME` participate. Any other `qtype`
    /// (MX, TXT, SRV, NS, SOA, PTR, …) returns `None` immediately so the
    /// caller forwards the query upstream; profile-scope NEVER synthesises
    /// the missing types and NEVER produces PTR records (DR13).
    ///
    /// **CNAME follow:** when an exact-match hit is a single CNAME and the
    /// caller asked for `A` / `AAAA`, the target is probed in the local
    /// `forward` map exactly once. If the target is local, its A/AAAA
    /// records are appended; if not, only the CNAME is returned and the
    /// caller's resolver is expected to follow the chain externally.
    /// Same shape as `LocalRecords::lookup`.
    pub fn lookup_with_apex(&self, domain: &str, qtype: RecordType) -> Option<ProfileLocalHit> {
        if !matches!(qtype, RecordType::A | RecordType::AAAA | RecordType::CNAME) {
            return None;
        }

        // 1. Exact-match probe. `None` owner: an exact hit's record already
        //    owns the queried name. Apex = the matched forward key (`domain`).
        if let Some(records) = self.forward.get(domain) {
            if let Some(matched) = filter_or_cname_follow(records, qtype, &self.forward, None) {
                return Some(ProfileLocalHit {
                    records: matched,
                    apex: CompactString::new(domain),
                });
            }
        }

        // 2. Fast-path bypass when the profile has no subdomain records.
        if !self.has_subdomain_records {
            return None;
        }

        // Wildcard descendants are stored under their apex but must be
        // answered owned by the QNAME (wire invariant). The owner is
        // loop-invariant — the queried name regardless of which ancestor
        // suffix matches — so build it once here, past the fast-path bypass
        // (no-wildcard configs never reach this point).
        let owner = Name::from_str(&format!("{domain}.")).ok();

        // 3. Suffix walk: strip one leftmost label at a time, stop at the
        //    single-label suffix (TLD) — DR10 forbids root subdomain records
        //    so probing the empty string is wasted work.
        let mut current = domain;
        while let Some((_label, rest)) = current.split_once('.') {
            // Skip the apex itself (already probed exactly above).
            current = rest;
            if current.is_empty() || !current.contains('.') {
                // `current` is now the TLD ("it", "com", ...). Probe it once,
                // then stop — DR9 prevents subdomain records on TLDs anyway,
                // but the validator runs at config time and the lookup must
                // be defensive on drift.
                if let Some(records) = self.suffix_lookup(current) {
                    if let Some(matched) =
                        filter_or_cname_follow(records, qtype, &self.forward, owner.as_ref())
                    {
                        return Some(ProfileLocalHit {
                            records: matched,
                            apex: CompactString::new(current),
                        });
                    }
                }
                break;
            }
            if let Some(records) = self.suffix_lookup(current) {
                if let Some(matched) =
                    filter_or_cname_follow(records, qtype, &self.forward, owner.as_ref())
                {
                    return Some(ProfileLocalHit {
                        records: matched,
                        apex: CompactString::new(current),
                    });
                }
            }
        }

        None
    }

    /// True iff the profile owns at least one record (exact OR subdomain).
    /// Used by tests + future stats wiring; not on the hot path.
    pub fn is_empty(&self) -> bool {
        self.forward.is_empty()
    }

    /// Total exact-match record count. Test hook.
    #[cfg(test)]
    pub fn forward_count(&self) -> usize {
        self.forward.len()
    }

    /// Subdomain-records count. Test hook.
    #[cfg(test)]
    pub fn suffix_count(&self) -> usize {
        self.suffix_index.len()
    }

    /// Test hook: report the suffix-walk fast-path bit so unit tests can
    /// assert that an exact-only profile short-circuits.
    #[cfg(test)]
    pub fn has_subdomain_records(&self) -> bool {
        self.has_subdomain_records
    }

    /// Linear scan of [`Self::suffix_index`]. Sorted depth-desc at build
    /// time so the first match IS the longest matching suffix.
    fn suffix_lookup(&self, suffix: &str) -> Option<&Vec<Record>> {
        for (key, records) in &self.suffix_index {
            if key.as_str() == suffix {
                return Some(records);
            }
        }
        None
    }
}

/// Re-own a record to `owner` when set, otherwise return it unchanged.
/// Used only on the wildcard suffix-walk path: a record is stored under its
/// canonical apex, but a wire-correct answer to a descendant query must be
/// owned by the QNAME. Exact-match callers pass `None`. Duplicated in
/// `local` per the decoupled-siblings convention (see `label_count`).
fn reowned(mut record: Record, owner: Option<&Name>) -> Record {
    if let Some(name) = owner {
        record.name = name.clone();
    }
    record
}

/// Count the labels in a domain (`"app.example.test"` → 3, `"it"` → 1, `""` → 0).
/// Used at build time to sort the suffix index depth-desc; cheap enough that
/// inlining the byte scan beats pulling in `iter::Split::count`.
fn label_count(domain: &str) -> usize {
    if domain.is_empty() {
        return 0;
    }
    domain.bytes().filter(|&b| b == b'.').count() + 1
}

/// Shared filter + CNAME-follow logic between exact-match and suffix-match
/// paths. Mirrors `LocalRecords::lookup` so behaviour is consistent across
/// scopes — the only call-site difference is which `forward` map is consulted
/// for the CNAME target lookup.
fn filter_or_cname_follow(
    records: &[Record],
    qtype: RecordType,
    forward: &RecordMap,
    owner: Option<&Name>,
) -> Option<Vec<Record>> {
    // On the wildcard suffix-walk path `owner` is the QNAME; each matched
    // record is re-owned from its apex to it so the answer RR is owned by
    // the queried name (RFC 1035 §3.2.1), else RFC-conformant stub resolvers
    // (glibc `getanswer_r` `strcasecmp(qname, rr_owner)`) discard it. The
    // exact-match caller passes `None` — its records already own the QNAME.
    let direct: Vec<Record> = records
        .iter()
        .filter(|r| r.record_type() == qtype)
        .cloned()
        .map(|r| reowned(r, owner))
        .collect();
    if !direct.is_empty() {
        return Some(direct);
    }

    if !matches!(qtype, RecordType::A | RecordType::AAAA) {
        return None;
    }

    let cname_rec = records
        .iter()
        .find(|r| r.record_type() == RecordType::CNAME)?;
    let RData::CNAME(ref target) = cname_rec.data else {
        return None;
    };

    let mut target_str = CompactString::default();
    let _ = write!(target_str, "{}", &**target);
    if target_str.ends_with('.') {
        target_str.pop();
    }

    // The wildcard CNAME RR itself is re-owned by the QNAME; the followed
    // target's A/AAAA records keep their own concrete name (the target is a
    // real name, not the wildcard).
    let mut result = vec![reowned(cname_rec.clone(), owner)];
    if let Some(target_records) = forward.get(target_str.as_str()) {
        result.extend(
            target_records
                .iter()
                .filter(|r| r.record_type() == qtype)
                .cloned(),
        );
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::settings::{LocalDnsRecord, LocalDnsRecordType};

    fn rec(
        domain: &str,
        rt: LocalDnsRecordType,
        value: &str,
        match_subdomains: bool,
    ) -> LocalDnsRecord {
        LocalDnsRecord {
            domain: domain.into(),
            record_type: rt,
            value: value.into(),
            match_subdomains,
            ttl_secs: None,
        }
    }

    fn rec_ttl(
        domain: &str,
        rt: LocalDnsRecordType,
        value: &str,
        match_subdomains: bool,
        ttl: u32,
    ) -> LocalDnsRecord {
        let mut r = rec(domain, rt, value, match_subdomains);
        r.ttl_secs = Some(ttl);
        r
    }

    #[test]
    fn t2_label_count_basics() {
        assert_eq!(label_count(""), 0);
        assert_eq!(label_count("it"), 1);
        assert_eq!(label_count("example.test"), 2);
        assert_eq!(label_count("app.example.test"), 3);
        assert_eq!(label_count("a.b.c.d.e"), 5);
    }

    #[test]
    fn t2_empty_records_yields_empty_table() {
        let plr = ProfileLocalRecords::build(&[], 60);
        assert!(plr.is_empty());
        assert_eq!(plr.forward_count(), 0);
        assert_eq!(plr.suffix_count(), 0);
        assert!(!plr.has_subdomain_records());
    }

    #[test]
    fn t2_exact_match_a_record_wins() {
        let recs = vec![rec(
            "nas.home",
            LocalDnsRecordType::A,
            "192.168.1.50",
            false,
        )];
        let plr = ProfileLocalRecords::build(&recs, 60);
        let res = plr.lookup("nas.home", RecordType::A).unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].record_type(), RecordType::A);
    }

    #[test]
    fn t2_exact_match_aaaa_record_wins() {
        let recs = vec![rec(
            "server.home",
            LocalDnsRecordType::AAAA,
            "fd00::1",
            false,
        )];
        let plr = ProfileLocalRecords::build(&recs, 60);
        let res = plr.lookup("server.home", RecordType::AAAA).unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].record_type(), RecordType::AAAA);
    }

    #[test]
    fn t2_subdomain_match_apex() {
        // Record `example.test` with match_subdomains=true must match the apex
        // itself via the exact-path fast probe (forward map carries it).
        let recs = vec![rec(
            "example.test",
            LocalDnsRecordType::A,
            "192.0.2.50",
            true,
        )];
        let plr = ProfileLocalRecords::build(&recs, 60);
        assert!(plr.has_subdomain_records());
        let res = plr.lookup("example.test", RecordType::A).unwrap();
        assert_eq!(res.len(), 1);
        // Apex guard: exact/apex owner stays the apex (== queried name) —
        // unchanged by the wildcard owner-rewrite fix.
        assert_eq!(&res[0].name, &Name::from_str("example.test.").unwrap());
    }

    #[test]
    fn t2_subdomain_match_descendant() {
        let recs = vec![rec(
            "example.test",
            LocalDnsRecordType::A,
            "192.0.2.50",
            true,
        )];
        let plr = ProfileLocalRecords::build(&recs, 60);
        let res = plr.lookup("app.example.test", RecordType::A).unwrap();
        assert_eq!(res.len(), 1);
        match res[0].data {
            RData::A(ref a) => assert_eq!(a.0, Ipv4Addr::new(192, 0, 2, 50)),
            _ => panic!("expected A"),
        }
        // localdns-wildcard-owner: descendant answer owned by the QNAME,
        // not the configured apex (wire invariant).
        assert_eq!(&res[0].name, &Name::from_str("app.example.test.").unwrap());
    }

    #[test]
    fn t2_subdomain_match_deeper_descendant() {
        let recs = vec![rec(
            "example.test",
            LocalDnsRecordType::A,
            "192.0.2.50",
            true,
        )];
        let plr = ProfileLocalRecords::build(&recs, 60);
        let res = plr
            .lookup("api.v2.app.example.test", RecordType::A)
            .unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(
            &res[0].name,
            &Name::from_str("api.v2.app.example.test.").unwrap()
        );
    }

    #[test]
    fn t2_exact_wins_over_subdomain() {
        // `app.example.test` exact + `example.test` subdomain → query
        // `app.example.test` returns the EXACT record's IP, not the subdomain
        // wildcard. §4 truth table: exact > subdomain (longest match).
        let recs = vec![
            rec("example.test", LocalDnsRecordType::A, "10.0.0.1", true),
            rec("app.example.test", LocalDnsRecordType::A, "10.0.0.2", false),
        ];
        let plr = ProfileLocalRecords::build(&recs, 60);
        let res = plr.lookup("app.example.test", RecordType::A).unwrap();
        assert_eq!(res.len(), 1);
        match res[0].data {
            RData::A(ref a) => assert_eq!(a.0, Ipv4Addr::new(10, 0, 0, 2)),
            _ => panic!("expected A"),
        }
    }

    #[test]
    fn t2_longest_suffix_wins() {
        // Both `api.example.test` and `example.test` are subdomain records.
        // Query `something.api.example.test` must match `api.example.test` (the
        // longer / more-specific suffix).
        let recs = vec![
            rec("example.test", LocalDnsRecordType::A, "10.0.0.1", true),
            rec("api.example.test", LocalDnsRecordType::A, "10.0.0.2", true),
        ];
        let plr = ProfileLocalRecords::build(&recs, 60);
        let res = plr
            .lookup("something.api.example.test", RecordType::A)
            .unwrap();
        assert_eq!(res.len(), 1);
        match res[0].data {
            RData::A(ref a) => assert_eq!(a.0, Ipv4Addr::new(10, 0, 0, 2)),
            _ => panic!("expected A"),
        }
    }

    #[test]
    fn t2_subdomain_does_not_match_unrelated_domain() {
        let recs = vec![rec(
            "example.test",
            LocalDnsRecordType::A,
            "192.0.2.50",
            true,
        )];
        let plr = ProfileLocalRecords::build(&recs, 60);
        assert!(plr.lookup("google.com", RecordType::A).is_none());
        assert!(plr.lookup("evilexample.test", RecordType::A).is_none());
    }

    #[test]
    fn t2_exact_only_record_does_not_match_descendant() {
        // match_subdomains=false: `example.test` does NOT match `app.example.test`.
        let recs = vec![rec(
            "example.test",
            LocalDnsRecordType::A,
            "10.0.0.1",
            false,
        )];
        let plr = ProfileLocalRecords::build(&recs, 60);
        assert!(plr.lookup("example.test", RecordType::A).is_some());
        assert!(plr.lookup("app.example.test", RecordType::A).is_none());
        assert!(!plr.has_subdomain_records());
    }

    #[test]
    fn t2_fast_path_bypass_when_no_subdomain_records() {
        // When every record is exact-match, has_subdomain_records is false
        // and lookup must short-circuit the suffix walk entirely. We can't
        // observe the walk skip directly without instrumentation, but we
        // CAN observe the bool — and we can verify a non-matching query
        // returns None promptly.
        let recs = vec![
            rec("a.home", LocalDnsRecordType::A, "10.0.0.1", false),
            rec("b.home", LocalDnsRecordType::A, "10.0.0.2", false),
        ];
        let plr = ProfileLocalRecords::build(&recs, 60);
        assert!(!plr.has_subdomain_records());
        assert!(plr.lookup("c.home", RecordType::A).is_none());
        assert!(plr.lookup("nonexistent.example", RecordType::A).is_none());
    }

    #[test]
    fn t2_qtype_mx_bypassed_total() {
        // DR4: non A/AAAA/CNAME qtypes return None even when an A record
        // exists for the domain. The handler then forwards upstream.
        let recs = vec![rec(
            "example.test",
            LocalDnsRecordType::A,
            "192.0.2.50",
            false,
        )];
        let plr = ProfileLocalRecords::build(&recs, 60);
        assert!(plr.lookup("example.test", RecordType::MX).is_none());
        assert!(plr.lookup("example.test", RecordType::TXT).is_none());
        assert!(plr.lookup("example.test", RecordType::SRV).is_none());
        assert!(plr.lookup("example.test", RecordType::NS).is_none());
        assert!(plr.lookup("example.test", RecordType::SOA).is_none());
        assert!(plr.lookup("example.test", RecordType::PTR).is_none());
    }

    #[test]
    fn t2_qtype_aaaa_misses_when_only_a_present() {
        let recs = vec![rec(
            "example.test",
            LocalDnsRecordType::A,
            "192.0.2.50",
            false,
        )];
        let plr = ProfileLocalRecords::build(&recs, 60);
        assert!(plr.lookup("example.test", RecordType::AAAA).is_none());
    }

    #[test]
    fn t2_cname_record_returned_when_target_external() {
        let recs = vec![rec(
            "media.home",
            LocalDnsRecordType::CNAME,
            "external.cdn.com",
            false,
        )];
        let plr = ProfileLocalRecords::build(&recs, 60);
        let res = plr.lookup("media.home", RecordType::A).unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].record_type(), RecordType::CNAME);
    }

    #[test]
    fn t2_cname_follow_returns_cname_plus_target_a() {
        // CNAME → local A: lookup for A on the CNAME domain returns BOTH
        // the CNAME and the resolved target's A record. Same as Sprint 18.
        let recs = vec![
            rec("nas.home", LocalDnsRecordType::A, "192.168.1.50", false),
            rec("media.home", LocalDnsRecordType::CNAME, "nas.home", false),
        ];
        let plr = ProfileLocalRecords::build(&recs, 60);
        let res = plr.lookup("media.home", RecordType::A).unwrap();
        assert_eq!(res.len(), 2);
        assert_eq!(res[0].record_type(), RecordType::CNAME);
        assert_eq!(res[1].record_type(), RecordType::A);
        // Owner split — the same invariant
        // `t2_wildcard_cname_follow_local_target_owner_split` pins for the
        // wildcard path. Asserted here too because the exact-match case never
        // got the treatment when localdns-wildcard-owner was fixed: a
        // regression on this path would have been masked by its passing
        // wildcard sibling.
        assert_eq!(
            &res[0].name,
            &Name::from_str("media.home.").unwrap(),
            "the CNAME RR is owned by the queried name"
        );
        assert_eq!(
            &res[1].name,
            &Name::from_str("nas.home.").unwrap(),
            "followed target A RR keeps the target's own name — relabelling it to \
             the qname orphans it from the CNAME that points at it"
        );
    }

    #[test]
    fn t2_cname_query_for_cname_record_returns_cname_only() {
        let recs = vec![
            rec("nas.home", LocalDnsRecordType::A, "192.168.1.50", false),
            rec("media.home", LocalDnsRecordType::CNAME, "nas.home", false),
        ];
        let plr = ProfileLocalRecords::build(&recs, 60);
        // Asking for CNAME explicitly returns just the CNAME.
        let res = plr.lookup("media.home", RecordType::CNAME).unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].record_type(), RecordType::CNAME);
    }

    #[test]
    fn t2_case_insensitive_domain_lookup() {
        // Records are stored lowercased at build time; lookups arrive
        // already-lowercased from the handler (LowerName) but build-side
        // canonicalisation must be honoured even if a future call site
        // forgets.
        let recs = vec![rec(
            "NAS.Home",
            LocalDnsRecordType::A,
            "192.168.1.50",
            false,
        )];
        let plr = ProfileLocalRecords::build(&recs, 60);
        assert!(plr.lookup("nas.home", RecordType::A).is_some());
    }

    #[test]
    fn t2_ttl_per_record_overrides_default() {
        // ttl_secs=Some(7200) on the record → record carries 7200s, not the
        // 60s default passed to build().
        let recs = vec![rec_ttl(
            "nas.home",
            LocalDnsRecordType::A,
            "192.168.1.50",
            false,
            7200,
        )];
        let plr = ProfileLocalRecords::build(&recs, 60);
        let res = plr.lookup("nas.home", RecordType::A).unwrap();
        assert_eq!(res[0].ttl, 7200);
    }

    #[test]
    fn t2_ttl_falls_back_to_default_when_none() {
        // ttl_secs=None → fall back to the parent [local_dns].ttl_secs
        // value passed to build (DR5).
        let recs = vec![rec(
            "nas.home",
            LocalDnsRecordType::A,
            "192.168.1.50",
            false,
        )];
        let plr = ProfileLocalRecords::build(&recs, 1234);
        let res = plr.lookup("nas.home", RecordType::A).unwrap();
        assert_eq!(res[0].ttl, 1234);
    }

    #[test]
    fn t2_subdomain_apex_via_exact_path_skips_walk() {
        // When `example.test` (subdomain=true) is queried with the apex
        // exactly, the exact-match probe wins on the FIRST hash lookup —
        // the suffix walk never runs. Behavioural assertion only
        // (non-instrumented): the result is correct AND identical to a
        // pure exact-match-only profile would return.
        let recs = vec![rec(
            "example.test",
            LocalDnsRecordType::A,
            "192.0.2.50",
            true,
        )];
        let plr = ProfileLocalRecords::build(&recs, 60);
        let res = plr.lookup("example.test", RecordType::A).unwrap();
        assert_eq!(res.len(), 1);
    }

    #[test]
    fn t2_multiple_subdomain_records_sorted_depth_desc() {
        // Insertion order is `c.b.a`, `b.a`, `a` — but the index must end
        // up sorted depth-desc so the first hit on a deep query is the
        // longest suffix.
        let recs = vec![
            rec("a", LocalDnsRecordType::A, "10.0.0.1", true),
            rec("b.a", LocalDnsRecordType::A, "10.0.0.2", true),
            rec("c.b.a", LocalDnsRecordType::A, "10.0.0.3", true),
        ];
        let plr = ProfileLocalRecords::build(&recs, 60);
        // Query `x.c.b.a` walks: drop `x` → `c.b.a` (3-label) hits first.
        let res = plr.lookup("x.c.b.a", RecordType::A).unwrap();
        match res[0].data {
            RData::A(ref a) => assert_eq!(a.0, Ipv4Addr::new(10, 0, 0, 3)),
            _ => panic!("expected A"),
        }
        // Query `x.b.a` walks: drop `x` → `b.a` (2-label) hits.
        let res = plr.lookup("x.b.a", RecordType::A).unwrap();
        match res[0].data {
            RData::A(ref a) => assert_eq!(a.0, Ipv4Addr::new(10, 0, 0, 2)),
            _ => panic!("expected A"),
        }
    }

    #[test]
    fn t2_aaaa_subdomain_match() {
        let recs = vec![rec(
            "ipv6.home",
            LocalDnsRecordType::AAAA,
            "fd00::beef",
            true,
        )];
        let plr = ProfileLocalRecords::build(&recs, 60);
        let res = plr.lookup("api.ipv6.home", RecordType::AAAA).unwrap();
        assert_eq!(res[0].record_type(), RecordType::AAAA);
    }

    #[test]
    fn t2_walk_stops_at_tld() {
        // Query `app.example.test`, no records at all → walk runs through
        // `example.test` then `it` then stops. Verify by ensuring an unrelated
        // record on `it` (would not be allowed by validator anyway, but
        // belt-and-braces) doesn't accidentally match.
        let plr = ProfileLocalRecords::build(&[], 60);
        assert!(plr.lookup("app.example.test", RecordType::A).is_none());
    }

    #[test]
    fn t2_invalid_ipv4_silently_dropped() {
        // Validator catches this; build() defensive on drift.
        let recs = vec![rec(
            "bad.home",
            LocalDnsRecordType::A,
            "999.999.999.999",
            false,
        )];
        let plr = ProfileLocalRecords::build(&recs, 60);
        assert!(plr.is_empty());
    }

    #[test]
    fn t2_invalid_ipv6_silently_dropped() {
        let recs = vec![rec(
            "bad.home",
            LocalDnsRecordType::AAAA,
            "not-an-ipv6",
            false,
        )];
        let plr = ProfileLocalRecords::build(&recs, 60);
        assert!(plr.is_empty());
    }

    #[test]
    fn t2_multiple_types_same_domain_coexist() {
        // A + AAAA on the same domain: each query type hits its own record.
        // The validator's per-(domain,type) duplicate check would still
        // pass because the types differ.
        let recs = vec![
            rec("dual.home", LocalDnsRecordType::A, "10.0.0.5", false),
            rec("dual.home", LocalDnsRecordType::AAAA, "fd00::5", false),
        ];
        let plr = ProfileLocalRecords::build(&recs, 60);
        let a = plr.lookup("dual.home", RecordType::A).unwrap();
        assert_eq!(a[0].record_type(), RecordType::A);
        let aaaa = plr.lookup("dual.home", RecordType::AAAA).unwrap();
        assert_eq!(aaaa[0].record_type(), RecordType::AAAA);
    }

    #[test]
    fn t2_subdomain_with_match_subdomains_apex_lookup_returns_record() {
        // Apex MUST be reachable both via exact-match (forward) and via
        // suffix walk — but the exact-match path wins on the first hash
        // probe. Confirms the apex-also-in-forward storage choice.
        let recs = vec![rec("home.lan", LocalDnsRecordType::A, "10.0.0.1", true)];
        let plr = ProfileLocalRecords::build(&recs, 60);
        assert_eq!(plr.forward_count(), 1);
        assert_eq!(plr.suffix_count(), 1);
        let res = plr.lookup("home.lan", RecordType::A).unwrap();
        assert_eq!(res.len(), 1);
    }

    #[test]
    fn t2_query_for_tld_only_does_not_match_subdomain_record() {
        // A subdomain record on `home.lan` must NOT match a query for `lan`
        // alone — the walk strips labels but stops before the empty string,
        // and `lan` has no record.
        let recs = vec![rec("home.lan", LocalDnsRecordType::A, "10.0.0.1", true)];
        let plr = ProfileLocalRecords::build(&recs, 60);
        assert!(plr.lookup("lan", RecordType::A).is_none());
    }

    #[test]
    fn t2_cname_subdomain_match_returns_cname() {
        let recs = vec![rec(
            "example.test",
            LocalDnsRecordType::CNAME,
            "proxy.internal",
            true,
        )];
        let plr = ProfileLocalRecords::build(&recs, 60);
        let res = plr.lookup("api.example.test", RecordType::A).unwrap();
        // Query for A on a CNAME record + non-local target → CNAME only.
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].record_type(), RecordType::CNAME);
        // localdns-wildcard-owner: the wildcard CNAME RR is owned by the
        // QNAME, not the apex.
        assert_eq!(&res[0].name, &Name::from_str("api.example.test.").unwrap());
    }

    #[test]
    fn t2_wildcard_cname_follow_local_target_owner_split() {
        // localdns-wildcard-owner: wildcard CNAME on `example.test` → local
        // target `nas.home` (A). A descendant A query returns the CNAME RR
        // owned by the QNAME AND the followed target's A RR still owned by
        // the concrete target name (the target is not the wildcard).
        let recs = vec![
            rec("example.test", LocalDnsRecordType::CNAME, "nas.home", true),
            rec("nas.home", LocalDnsRecordType::A, "192.168.1.50", false),
        ];
        let plr = ProfileLocalRecords::build(&recs, 60);
        let res = plr.lookup("app.example.test", RecordType::A).unwrap();
        assert_eq!(res.len(), 2);
        assert_eq!(res[0].record_type(), RecordType::CNAME);
        assert_eq!(
            &res[0].name,
            &Name::from_str("app.example.test.").unwrap(),
            "wildcard CNAME RR must be re-owned by the QNAME"
        );
        assert_eq!(res[1].record_type(), RecordType::A);
        assert_eq!(
            &res[1].name,
            &Name::from_str("nas.home.").unwrap(),
            "followed target A RR keeps the target's own name"
        );
    }

    #[test]
    fn t2_zero_ttl_default_falls_through() {
        // Defensive: when the parent default_ttl is 0 (validator would
        // catch this), the per-record None still produces ttl=0. We don't
        // test the validator here — just that the field flows through.
        let recs = vec![rec("ttl.home", LocalDnsRecordType::A, "10.0.0.1", false)];
        let plr = ProfileLocalRecords::build(&recs, 0);
        let res = plr.lookup("ttl.home", RecordType::A).unwrap();
        assert_eq!(res[0].ttl, 0);
    }

    #[test]
    fn t2_two_subdomain_records_same_depth_both_kept() {
        // `siblings` at the same depth — both must be reachable. Tie-break
        // (depth equal) follows insertion order, but each lookup hits its
        // own apex.
        let recs = vec![
            rec("a.home.lan", LocalDnsRecordType::A, "10.0.0.1", true),
            rec("b.home.lan", LocalDnsRecordType::A, "10.0.0.2", true),
        ];
        let plr = ProfileLocalRecords::build(&recs, 60);
        let res_a = plr.lookup("foo.a.home.lan", RecordType::A).unwrap();
        match res_a[0].data {
            RData::A(ref a) => assert_eq!(a.0, Ipv4Addr::new(10, 0, 0, 1)),
            _ => panic!("expected A"),
        }
        let res_b = plr.lookup("foo.b.home.lan", RecordType::A).unwrap();
        match res_b[0].data {
            RData::A(ref a) => assert_eq!(a.0, Ipv4Addr::new(10, 0, 0, 2)),
            _ => panic!("expected A"),
        }
    }

    #[test]
    fn t2_default_yields_empty_table() {
        // Default impl is reached by ResolvedProfile::permissive_default
        // (and any test fixture that wants a no-op profile).
        let plr = ProfileLocalRecords::default();
        assert!(plr.is_empty());
        assert!(!plr.has_subdomain_records());
        assert!(plr.lookup("anything.test", RecordType::A).is_none());
    }

    #[test]
    fn hit_apex_is_matched_record_not_qname() {
        // The apex a hit surfaces is the record that FIRED: an exact hit's own
        // key, a wildcard descendant's configured suffix — never the raw QNAME.
        let recs = vec![
            rec("nas.home", LocalDnsRecordType::A, "192.168.1.50", false),
            rec("example.test", LocalDnsRecordType::A, "10.0.0.1", true),
        ];
        let plr = ProfileLocalRecords::build(&recs, 60);
        assert_eq!(
            plr.lookup_with_apex("nas.home", RecordType::A)
                .unwrap()
                .apex,
            "nas.home"
        );
        assert_eq!(
            plr.lookup_with_apex("deep.app.example.test", RecordType::A)
                .unwrap()
                .apex,
            "example.test"
        );
    }

    #[test]
    fn wildcard_flood_bounds_hit_table_to_apex_profile() {
        // TRK-01 / perfmem T1 (profile scope) — the load-bearing regression.
        // 1000 distinct subdomains of ONE match_subdomains record, driven
        // through the real lookup → record_hit path, must collapse to a single
        // apex key: a LAN wildcard flood can no longer grow `LocalRecordsHits`.
        use crate::tracking::{LocalRecordsHits, LocalRecordsScopeKey};

        let recs = vec![rec("example.test", LocalDnsRecordType::A, "10.0.0.1", true)];
        let plr = ProfileLocalRecords::build(&recs, 60);
        let hits = LocalRecordsHits::new();
        let scope = LocalRecordsScopeKey::Profile(CompactString::new("kids"));

        for i in 0..1000 {
            let qname = format!("host{i}.example.test");
            let hit = plr
                .lookup_with_apex(&qname, RecordType::A)
                .expect("wildcard descendant must hit");
            hits.record_hit(scope.clone(), &hit.apex);
        }

        assert_eq!(
            hits.key_count(),
            1,
            "1000 distinct subdomains must collapse to the single apex key"
        );
        assert_eq!(hits.count_for(&scope, "example.test"), 1000);
    }

    #[test]
    fn wildcard_flood_multi_record_bounded_by_config_count_profile() {
        // Multi-record variant: N wildcard records each flooded with distinct
        // subdomains → key_count == N (≤ configured record count), never the
        // (N × subdomains) raw-QNAME cardinality.
        use crate::tracking::{LocalRecordsHits, LocalRecordsScopeKey};

        let recs = vec![
            rec("a.lan", LocalDnsRecordType::A, "10.0.0.1", true),
            rec("b.lan", LocalDnsRecordType::A, "10.0.0.2", true),
            rec("c.lan", LocalDnsRecordType::A, "10.0.0.3", true),
        ];
        let plr = ProfileLocalRecords::build(&recs, 60);
        let hits = LocalRecordsHits::new();
        let scope = LocalRecordsScopeKey::Global;

        for apex in ["a.lan", "b.lan", "c.lan"] {
            for i in 0..500 {
                let qname = format!("h{i}.{apex}");
                let hit = plr
                    .lookup_with_apex(&qname, RecordType::A)
                    .expect("must hit");
                hits.record_hit(scope.clone(), &hit.apex);
            }
        }

        assert!(
            hits.key_count() <= recs.len(),
            "key_count {} must be ≤ {} configured records",
            hits.key_count(),
            recs.len()
        );
        assert_eq!(hits.key_count(), 3);
        assert_eq!(hits.count_for(&scope, "a.lan"), 500);
    }
}
