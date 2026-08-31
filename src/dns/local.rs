//! Local DNS records — static A/AAAA/CNAME records defined in config.
//!
//! Queries matching local records bypass the filter engine and upstream.
//! Auto-generates PTR records for reverse DNS lookups.

use std::collections::HashMap;
use std::fmt::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use compact_str::CompactString;

use hickory_proto::rr::rdata::{A, AAAA, CNAME, PTR};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use crate::config::settings::{LocalDnsConfig, LocalDnsRecordType};

type RecordMap = HashMap<CompactString, Vec<Record>, ahash::RandomState>;

/// Outcome of a global local-records probe (rev-2606 local-01).
pub enum LocalLookup {
    /// Records matching the qtype (possibly via one local CNAME hop),
    /// plus the **matched record's apex** — the configured record identity
    /// that fired (the exact forward key, the wildcard suffix key, or the
    /// PTR's owning forward name). The handler keys the per-record hit
    /// counter by this apex, not by the raw QNAME, so a wildcard flood of
    /// distinct subdomains all roll up under the one apex (perfmem T1 /
    /// TRK-01 — bounds `LocalRecordsHits` cardinality to the config).
    Hit {
        records: Vec<Record>,
        apex: CompactString,
    },
    /// The name is locally defined but holds no records of the queried
    /// type. The handler answers NODATA (NOERROR + SOA, RFC 2308 §2.1)
    /// instead of forwarding, so internal hostnames don't leak to the
    /// public resolver and an upstream NXDOMAIN for a private TLD can't
    /// negative-cache the *name* out from under the types we DO hold.
    /// Gated by `local_dns.nodata_for_missing_types` (default true) —
    /// when the flag is off the probe reports `Miss` instead.
    NodataSynthesis { ttl: u32 },
    /// Name not locally defined — fall through to filter/cache/upstream.
    Miss,
}

impl LocalLookup {
    /// Extract a `Hit` payload. Convenience for tests and callers that
    /// only care about served records.
    pub fn hit(self) -> Option<Vec<Record>> {
        match self {
            Self::Hit { records, .. } => Some(records),
            _ => None,
        }
    }
}

struct LocalData {
    forward: RecordMap,
    reverse: RecordMap,
    /// `match_subdomains = true` records, keyed on their canonical apex and
    /// sorted by label depth **descending** so a linear scan returns the
    /// longest matching suffix first. Mirrors
    /// [`crate::dns::local_profile::ProfileLocalRecords`]'s `suffix_index`; the
    /// global `LocalData` is its exact-only sibling, extended here for
    /// rev-2606 global-localdns-wildcard-dead.
    suffix_index: Vec<(CompactString, Vec<Record>)>,
    /// Fast-path bit. When `false` (no record sets `match_subdomains`),
    /// [`LocalRecords::lookup`] skips the suffix walk entirely and keeps its
    /// pre-wildcard exact-only cost — one `HashMap::get`, no per-query alloc.
    has_subdomain_records: bool,
    /// `[local_dns].ttl_secs` — reused as the NODATA negative TTL.
    ttl: u32,
    nodata_for_missing_types: bool,
}

impl LocalData {
    /// Linear scan of [`Self::suffix_index`]. Sorted depth-descending at build
    /// time so the first key match IS the longest matching suffix.
    fn suffix_lookup(&self, suffix: &str) -> Option<&Vec<Record>> {
        for (key, records) in &self.suffix_index {
            if key.as_str() == suffix {
                return Some(records);
            }
        }
        None
    }
}

/// Static local DNS records with atomic swap for hot reload.
pub struct LocalRecords {
    inner: ArcSwap<LocalData>,
}

impl LocalRecords {
    /// Build from config. Parses all records and auto-generates PTR entries.
    pub fn build(config: &LocalDnsConfig) -> Self {
        Self {
            inner: ArcSwap::new(Arc::new(build_data(config))),
        }
    }

    /// Atomically swap to new config (hot reload).
    pub fn swap(&self, config: &LocalDnsConfig) {
        self.inner.store(Arc::new(build_data(config)));
    }

    /// Look up local records for a domain and query type.
    ///
    /// Returns [`LocalLookup::Hit`] if the domain has local records matching
    /// the requested type. For CNAME domains queried for A/AAAA, follows one
    /// hop and includes the target's records if the target is also local.
    /// A locally-defined name with no records of the queried type yields
    /// [`LocalLookup::NodataSynthesis`] (unless the operator disabled
    /// `nodata_for_missing_types`); unknown names yield [`LocalLookup::Miss`].
    pub fn lookup(&self, domain: &str, qtype: RecordType) -> LocalLookup {
        let data = self.inner.load();

        // Exact forward match (Sprint 18 path — behaviour unchanged).
        // `None` owner: an exact hit's record already owns the queried name.
        if let Some(records) = data.forward.get(domain) {
            return resolve_forward(
                records,
                qtype,
                &data.forward,
                data.nodata_for_missing_types,
                data.ttl,
                None,
                domain,
            );
        }

        // rev-2606 global-localdns-wildcard-dead: walk ancestors for a
        // `match_subdomains = true` record. Gated two ways so nothing else
        // regresses:
        //   * `has_subdomain_records` — a config with no wildcards skips the
        //     walk entirely and keeps its exact-only cost (the common case, on
        //     the per-query hot path);
        //   * `A | AAAA | CNAME` — PTR and every other qtype keep the exact +
        //     NODATA + reverse path below byte-identical, and we never claim
        //     authority over an infinite MX/TXT namespace under a wildcard
        //     (matches profile-scope DR4).
        // A wildcard record's apex lives in `forward`, so the exact probe above
        // already served it; here we only match proper descendants. Longest
        // suffix wins (`suffix_index` is sorted depth-descending). Mirrors
        // `ProfileLocalRecords::lookup`.
        if data.has_subdomain_records
            && matches!(qtype, RecordType::A | RecordType::AAAA | RecordType::CNAME)
        {
            let mut current = domain;
            while let Some((_label, rest)) = current.split_once('.') {
                current = rest;
                if let Some(records) = data.suffix_lookup(current) {
                    // Wildcard-descendant hit: the stored record is owned by
                    // its apex, but the answer must be owned by the QNAME.
                    // Built once here, only on the descendant match — the
                    // no-wildcard fast path never enters this branch.
                    let owner = Name::from_str(&format!("{domain}.")).ok();
                    // Apex = the matched suffix key (`current`), NOT the raw
                    // QNAME `domain`: every distinct subdomain of one wildcard
                    // record counts under the single configured apex (TRK-01).
                    return resolve_forward(
                        records,
                        qtype,
                        &data.forward,
                        data.nodata_for_missing_types,
                        data.ttl,
                        owner.as_ref(),
                        current,
                    );
                }
                // Stop once the single-label TLD has been probed — DR9 forbids
                // wildcards on public suffixes, so nothing shorter can match.
                if current.is_empty() || !current.contains('.') {
                    break;
                }
            }
        }

        // PTR lookup (reverse DNS)
        if qtype == RecordType::PTR {
            if let Some(records) = data.reverse.get(domain) {
                // A PTR hit counts under the OWNING forward record's apex
                // (the PTR RDATA target), not the `*.in-addr.arpa` QNAME, so
                // a host's reverse + forward hits aggregate under one key.
                let apex = ptr_apex(records);
                return LocalLookup::Hit {
                    records: records.clone(),
                    apex,
                };
            }
        }

        LocalLookup::Miss
    }

    /// Check if a forward domain exists in local records.
    pub fn has_domain(&self, domain: &str) -> bool {
        self.inner.load().forward.contains_key(domain)
    }

    #[cfg(test)]
    pub fn forward_count(&self) -> usize {
        self.inner.load().forward.len()
    }

    #[cfg(test)]
    pub fn reverse_count(&self) -> usize {
        self.inner.load().reverse.len()
    }

    #[cfg(test)]
    pub fn suffix_count(&self) -> usize {
        self.inner.load().suffix_index.len()
    }

    #[cfg(test)]
    pub fn has_subdomain_records(&self) -> bool {
        self.inner.load().has_subdomain_records
    }
}

fn build_data(config: &LocalDnsConfig) -> LocalData {
    let mut forward: RecordMap = HashMap::with_hasher(ahash::RandomState::new());
    let mut reverse: RecordMap = HashMap::with_hasher(ahash::RandomState::new());
    let nodata_for_missing_types = config.nodata_for_missing_types;
    // rev-2606 global-localdns-wildcard-dead: wildcard (`match_subdomains`)
    // records accumulate here keyed on their apex, then become `suffix_index`.
    let mut subdomain_groups: RecordMap = HashMap::with_hasher(ahash::RandomState::new());

    for entry in &config.records {
        // rev-2606 cfg-validator-02: per-record TTL override wins; the
        // section value is the fallback — the same DR5 contract the
        // profile-scope builder has always implemented. Derived PTR
        // records inherit their parent record's effective TTL.
        let ttl = entry.ttl_secs.unwrap_or(config.ttl_secs);
        // Same canonicalization the validator keys its checks on
        // (cfg-validator-03): trim + strip trailing dots + lowercase, so a
        // validated spelling like "NAS.Home." builds the same table entry
        // the handler's lowercase dot-less query probe will hit.
        let domain = crate::config::validator::canonicalize_domain(&entry.domain);
        let Ok(name) = Name::from_str(&format!("{domain}.")) else {
            // Unreachable for validated configs (FQDN gate + shared
            // canonicalization); defensive skip against drift.
            continue;
        };

        // Build the forward A/AAAA/CNAME record (and, for address types, the
        // derived PTR — never wildcarded). The match evaluates to that forward
        // record so the `forward` push + optional wildcard insert happen once.
        let record = match entry.record_type {
            LocalDnsRecordType::A => {
                let Ok(ip) = entry.value.parse::<Ipv4Addr>() else {
                    continue;
                };
                let record = Record::from_rdata(name.clone(), ttl, RData::A(A(ip)));

                // Auto-generate PTR — reuse the already-parsed forward `name`
                // as the PTR target rather than re-parsing `{domain}.` (the
                // pre-fix `.unwrap()` was a latent panic on the build / hot-reload
                // path had the two strings ever drifted).
                let ptr_domain = ipv4_to_ptr(&ip);
                if let Ok(ptr_name) = Name::from_str(&format!("{ptr_domain}.")) {
                    let ptr_record = Record::from_rdata(ptr_name, ttl, RData::PTR(PTR(name)));
                    reverse
                        .entry(CompactString::new(&ptr_domain))
                        .or_default()
                        .push(ptr_record);
                }
                record
            }
            LocalDnsRecordType::AAAA => {
                let Ok(ip) = entry.value.parse::<Ipv6Addr>() else {
                    continue;
                };
                let record = Record::from_rdata(name.clone(), ttl, RData::AAAA(AAAA(ip)));

                // Auto-generate PTR — reuse the already-parsed forward `name`
                // as the PTR target rather than re-parsing `{domain}.` (the
                // pre-fix `.unwrap()` was a latent panic on the build / hot-reload
                // path had the two strings ever drifted).
                let ptr_domain = ipv6_to_ptr(&ip);
                if let Ok(ptr_name) = Name::from_str(&format!("{ptr_domain}.")) {
                    let ptr_record = Record::from_rdata(ptr_name, ttl, RData::PTR(PTR(name)));
                    reverse
                        .entry(CompactString::new(&ptr_domain))
                        .or_default()
                        .push(ptr_record);
                }
                record
            }
            LocalDnsRecordType::CNAME => {
                let target = crate::config::validator::canonicalize_domain(&entry.value);
                let Ok(target_name) = Name::from_str(&format!("{target}.")) else {
                    continue;
                };
                Record::from_rdata(name, ttl, RData::CNAME(CNAME(target_name)))
            }
        };

        // Apex always lands in `forward` so an exact-match query short-circuits
        // the suffix walk even when `match_subdomains` is true. A wildcard
        // record additionally joins `subdomain_groups` for the descendant walk
        // (the clone is build-time only, never on the query path).
        let key = CompactString::new(&domain);
        if entry.match_subdomains {
            subdomain_groups
                .entry(key.clone())
                .or_default()
                .push(record.clone());
        }
        forward.entry(key).or_default().push(record);
    }

    // Depth-descending sort (most labels first) so a linear suffix scan returns
    // the longest match first — mirrors `ProfileLocalRecords::build`.
    let mut suffix_index: Vec<(CompactString, Vec<Record>)> =
        subdomain_groups.into_iter().collect();
    suffix_index.sort_by_key(|b| std::cmp::Reverse(label_count(b.0.as_str())));
    let has_subdomain_records = !suffix_index.is_empty();

    LocalData {
        forward,
        reverse,
        suffix_index,
        has_subdomain_records,
        // NODATA negative TTL stays the section fallback — a per-record
        // override has no meaning for the absent-qtype answer.
        ttl: config.ttl_secs,
        nodata_for_missing_types,
    }
}

/// Shared exact-match resolution for the forward table — used by both the
/// exact probe and the wildcard suffix walk in [`LocalRecords::lookup`].
/// Direct qtype match → [`LocalLookup::Hit`]; for A/AAAA, one local CNAME hop
/// is followed; a locally-defined name with nothing for this qtype synthesises
/// [`LocalLookup::NodataSynthesis`] (anti-leak, local-01) unless the operator
/// disabled it, in which case it falls through to [`LocalLookup::Miss`].
fn resolve_forward(
    records: &[Record],
    qtype: RecordType,
    forward: &RecordMap,
    nodata_for_missing_types: bool,
    ttl: u32,
    owner: Option<&Name>,
    apex: &str,
) -> LocalLookup {
    // Direct type match. On the wildcard suffix-walk path `owner` is the
    // QNAME and each matched record is re-owned from its apex to it, so the
    // answer RR is owned by the queried name (RFC 1035 §3.2.1) and passes
    // the `strcasecmp(qname, rr_owner)` check RFC-conformant stub resolvers
    // (glibc `getanswer_r`, systemd-resolved) run before accepting it. The
    // exact-match caller passes `None` — its records already own the QNAME.
    let matched: Vec<Record> = records
        .iter()
        .filter(|r| r.record_type() == qtype)
        .cloned()
        .map(|r| reowned(r, owner))
        .collect();
    if !matched.is_empty() {
        return LocalLookup::Hit {
            records: matched,
            apex: CompactString::new(apex),
        };
    }

    // CNAME follow: return CNAME + resolved target if local.
    if matches!(qtype, RecordType::A | RecordType::AAAA) {
        if let Some(cname_rec) = records
            .iter()
            .find(|r| r.record_type() == RecordType::CNAME)
        {
            if let RData::CNAME(ref target) = cname_rec.data {
                let mut target_str = CompactString::default();
                let _ = write!(target_str, "{}", &**target);
                if target_str.ends_with('.') {
                    target_str.pop();
                }

                // The wildcard CNAME RR itself is re-owned by the QNAME; the
                // followed target's A/AAAA records keep their own concrete
                // name (the target is a real name, not the wildcard).
                let mut result = vec![reowned(cname_rec.clone(), owner)];
                if let Some(target_records) = forward.get(target_str.as_str()) {
                    result.extend(
                        target_records
                            .iter()
                            .filter(|r| r.record_type() == qtype)
                            .cloned(),
                    );
                }
                // Apex stays the matched record's key (the CNAME's own apex),
                // even though the followed target A/AAAA RRs are owned by the
                // target name — the record that *fired* is the CNAME.
                return LocalLookup::Hit {
                    records: result,
                    apex: CompactString::new(apex),
                };
            }
        }
    }

    // Name exists locally but holds nothing for this qtype: synthesise NODATA
    // instead of leaking the name upstream (local-01). Flag-off restores the
    // legacy fall-through.
    if nodata_for_missing_types {
        return LocalLookup::NodataSynthesis { ttl };
    }
    LocalLookup::Miss
}

/// Re-own a record to `owner` when set, otherwise return it unchanged.
/// Used only on the wildcard suffix-walk path: a record is stored under its
/// canonical apex, but a wire-correct answer to a descendant query must be
/// owned by the QNAME. Exact-match callers pass `None`. Duplicated in
/// `local_profile` per the decoupled-siblings convention (see `label_count`).
fn reowned(mut record: Record, owner: Option<&Name>) -> Record {
    if let Some(name) = owner {
        record.name = name.clone();
    }
    record
}

/// The apex under which a PTR hit is counted: the owning forward record's
/// name, read from the first PTR record's RDATA target and stripped of its
/// trailing dot (so it matches the lowercased, dot-less forward apex key an
/// A/AAAA hit for the same host uses). Panic-free (`panic="abort"` ⇒ any
/// panic is a full daemon outage): never indexes, and falls back to an empty
/// key if a future build ever stored a non-PTR record in the reverse map.
fn ptr_apex(records: &[Record]) -> CompactString {
    let Some(rec) = records.first() else {
        return CompactString::default();
    };
    let RData::PTR(ref target) = rec.data else {
        return CompactString::default();
    };
    let mut apex = CompactString::default();
    let _ = write!(apex, "{}", &**target);
    if apex.ends_with('.') {
        apex.pop();
    }
    apex
}

/// Count the labels in a domain (`"app.example.test"` → 3, `"it"` → 1, `""` → 0).
/// Used at build time to sort `suffix_index` depth-descending. Mirrors the
/// identical helper in `local_profile` — duplicated rather than shared to keep
/// the two sibling tables decoupled (as the `RecordMap` alias already is).
fn label_count(domain: &str) -> usize {
    if domain.is_empty() {
        return 0;
    }
    domain.bytes().filter(|&b| b == b'.').count() + 1
}

/// Convert IPv4 address to PTR domain name (reversed octets).
fn ipv4_to_ptr(ip: &Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
}

/// Convert IPv6 address to PTR domain name (reversed nibbles).
fn ipv6_to_ptr(ip: &Ipv6Addr) -> String {
    let segs = ip.segments();
    let mut nibbles = Vec::with_capacity(32);
    for seg in &segs {
        nibbles.push((seg >> 12) & 0xf);
        nibbles.push((seg >> 8) & 0xf);
        nibbles.push((seg >> 4) & 0xf);
        nibbles.push(seg & 0xf);
    }
    nibbles.reverse();
    // local-02: single-buffer write instead of a Vec<String> of 32 one-char
    // `format!`s + `join` + a final `format!` (~35 allocs). 32 nibbles × "x."
    // = 64 bytes + "ip6.arpa" = 72. Cold path (config build/reload), so this is
    // tidiness, not a hot-loop win — but the output is byte-identical.
    let mut out = String::with_capacity(72);
    for n in &nibbles {
        let _ = write!(out, "{n:x}.");
    }
    out.push_str("ip6.arpa");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with(records: Vec<(&str, LocalDnsRecordType, &str)>) -> LocalDnsConfig {
        LocalDnsConfig {
            ttl_secs: 3600,
            dynamic_ttl_secs: 30,
            nodata_for_missing_types: true,
            records: records
                .into_iter()
                .map(
                    |(domain, rt, value)| crate::config::settings::LocalDnsRecord {
                        domain: domain.into(),
                        record_type: rt,
                        value: value.into(),
                        match_subdomains: false,
                        ttl_secs: None,
                    },
                )
                .collect(),
        }
    }

    /// Like [`config_with`] but each tuple carries its `match_subdomains` flag
    /// — for the rev-2606 global-localdns-wildcard-dead suffix-walk tests.
    fn config_with_flags(records: Vec<(&str, LocalDnsRecordType, &str, bool)>) -> LocalDnsConfig {
        LocalDnsConfig {
            ttl_secs: 3600,
            dynamic_ttl_secs: 30,
            nodata_for_missing_types: true,
            records: records
                .into_iter()
                .map(|(domain, rt, value, match_subdomains)| {
                    crate::config::settings::LocalDnsRecord {
                        domain: domain.into(),
                        record_type: rt,
                        value: value.into(),
                        match_subdomains,
                        ttl_secs: None,
                    }
                })
                .collect(),
        }
    }

    #[test]
    fn lookup_a_record() {
        let cfg = config_with(vec![("nas.home", LocalDnsRecordType::A, "192.168.1.50")]);
        let local = LocalRecords::build(&cfg);

        let result = local.lookup("nas.home", RecordType::A).hit().unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].record_type(), RecordType::A);
        match result[0].data {
            RData::A(ref a) => assert_eq!(a.0, Ipv4Addr::new(192, 168, 1, 50)),
            _ => panic!("expected A record"),
        }
    }

    #[test]
    fn lookup_aaaa_record() {
        let cfg = config_with(vec![("server.home", LocalDnsRecordType::AAAA, "fd00::1")]);
        let local = LocalRecords::build(&cfg);

        let result = local.lookup("server.home", RecordType::AAAA).hit().unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].record_type(), RecordType::AAAA);
    }

    #[test]
    fn lookup_cname_returns_cname_only_when_target_external() {
        let cfg = config_with(vec![(
            "media.home",
            LocalDnsRecordType::CNAME,
            "external.cdn.com",
        )]);
        let local = LocalRecords::build(&cfg);

        let result = local.lookup("media.home", RecordType::A).hit().unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].record_type(), RecordType::CNAME);
    }

    #[test]
    fn lookup_cname_follows_local_target() {
        let cfg = config_with(vec![
            ("nas.home", LocalDnsRecordType::A, "192.168.1.50"),
            ("media.home", LocalDnsRecordType::CNAME, "nas.home"),
        ]);
        let local = LocalRecords::build(&cfg);

        let result = local.lookup("media.home", RecordType::A).hit().unwrap();
        // CNAME + target A record
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].record_type(), RecordType::CNAME);
        assert_eq!(result[1].record_type(), RecordType::A);
        // Owner split — the same invariant `wildcard_cname_follow_local_target_owner_split`
        // pins for the wildcard path. Asserted here too because the exact-match
        // case never got the treatment when localdns-wildcard-owner was fixed:
        // a regression on this path would have been masked by its passing
        // wildcard sibling sitting a few tests below.
        assert_eq!(
            &result[0].name,
            &Name::from_str("media.home.").unwrap(),
            "the CNAME RR is owned by the queried name"
        );
        assert_eq!(
            &result[1].name,
            &Name::from_str("nas.home.").unwrap(),
            "followed target A RR keeps the target's own name — relabelling it to \
             the qname orphans it from the CNAME that points at it"
        );
    }

    #[test]
    fn ptr_auto_generated_for_ipv4() {
        let cfg = config_with(vec![("nas.home", LocalDnsRecordType::A, "192.168.1.50")]);
        let local = LocalRecords::build(&cfg);

        let result = local
            .lookup("50.1.168.192.in-addr.arpa", RecordType::PTR)
            .hit()
            .unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].record_type(), RecordType::PTR);
    }

    #[test]
    fn ptr_auto_generated_for_ipv6() {
        let cfg = config_with(vec![("server.home", LocalDnsRecordType::AAAA, "fd00::1")]);
        let local = LocalRecords::build(&cfg);

        let expected_ptr = ipv6_to_ptr(&"fd00::1".parse().unwrap());
        let result = local.lookup(&expected_ptr, RecordType::PTR).hit().unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].record_type(), RecordType::PTR);
    }

    #[test]
    fn per_record_ttl_override_wins_fallback_elsewhere() {
        // rev-2606 cfg-validator-02: the validated per-record TTL is the
        // served TTL on the global path too (profile scope always did).
        let mut cfg = config_with(vec![
            ("nas.home", LocalDnsRecordType::A, "192.168.1.50"),
            ("printer.home", LocalDnsRecordType::A, "192.168.1.60"),
        ]);
        cfg.records[0].ttl_secs = Some(60);

        let local = LocalRecords::build(&cfg);
        let overridden = local.lookup("nas.home", RecordType::A).hit().unwrap();
        assert_eq!(overridden[0].ttl, 60, "override must be served");
        let fallback = local.lookup("printer.home", RecordType::A).hit().unwrap();
        assert_eq!(fallback[0].ttl, 3600, "no override → section fallback");

        // Derived PTR inherits the parent record's effective TTL.
        let ptr = local
            .lookup("50.1.168.192.in-addr.arpa", RecordType::PTR)
            .hit()
            .unwrap();
        assert_eq!(ptr[0].ttl, 60);

        // NODATA negative TTL stays the section fallback even for the
        // overridden name.
        assert!(matches!(
            local.lookup("nas.home", RecordType::AAAA),
            LocalLookup::NodataSynthesis { ttl: 3600 }
        ));
    }

    #[test]
    fn lookup_miss_returns_miss() {
        let cfg = config_with(vec![("nas.home", LocalDnsRecordType::A, "192.168.1.50")]);
        let local = LocalRecords::build(&cfg);

        assert!(matches!(
            local.lookup("unknown.home", RecordType::A),
            LocalLookup::Miss
        ));
    }

    #[test]
    fn lookup_wrong_type_synthesises_nodata() {
        // local-01: AAAA query for a domain that only has an A record must
        // NOT fall through to upstream — the name is locally authoritative.
        let cfg = config_with(vec![("nas.home", LocalDnsRecordType::A, "192.168.1.50")]);
        let local = LocalRecords::build(&cfg);

        assert!(matches!(
            local.lookup("nas.home", RecordType::AAAA),
            LocalLookup::NodataSynthesis { ttl: 3600 }
        ));
        // Non-address types too (MX, TXT, ...) — the leak vector is the same.
        assert!(matches!(
            local.lookup("nas.home", RecordType::MX),
            LocalLookup::NodataSynthesis { ttl: 3600 }
        ));
    }

    #[test]
    fn lookup_wrong_type_flag_off_falls_through() {
        // Operator opt-out restores the legacy split-horizon behaviour.
        let mut cfg = config_with(vec![("nas.home", LocalDnsRecordType::A, "192.168.1.50")]);
        cfg.nodata_for_missing_types = false;
        let local = LocalRecords::build(&cfg);

        assert!(matches!(
            local.lookup("nas.home", RecordType::AAAA),
            LocalLookup::Miss
        ));
    }

    #[test]
    fn case_insensitive_domain() {
        let cfg = config_with(vec![("NAS.Home", LocalDnsRecordType::A, "192.168.1.50")]);
        let local = LocalRecords::build(&cfg);

        assert!(local.lookup("nas.home", RecordType::A).hit().is_some());
    }

    #[test]
    fn swap_replaces_records() {
        let cfg1 = config_with(vec![("nas.home", LocalDnsRecordType::A, "192.168.1.50")]);
        let local = LocalRecords::build(&cfg1);
        assert_eq!(local.forward_count(), 1);

        let cfg2 = config_with(vec![
            ("nas.home", LocalDnsRecordType::A, "192.168.1.51"),
            ("server.home", LocalDnsRecordType::A, "192.168.1.100"),
        ]);
        local.swap(&cfg2);
        assert_eq!(local.forward_count(), 2);

        let result = local.lookup("nas.home", RecordType::A).hit().unwrap();
        match result[0].data {
            RData::A(ref a) => assert_eq!(a.0, Ipv4Addr::new(192, 168, 1, 51)),
            _ => panic!("expected updated A record"),
        }
    }

    #[test]
    fn empty_config_builds_empty() {
        let cfg = LocalDnsConfig::default();
        let local = LocalRecords::build(&cfg);
        assert_eq!(local.forward_count(), 0);
        assert_eq!(local.reverse_count(), 0);
    }

    #[test]
    fn has_domain_check() {
        let cfg = config_with(vec![("nas.home", LocalDnsRecordType::A, "192.168.1.50")]);
        let local = LocalRecords::build(&cfg);
        assert!(local.has_domain("nas.home"));
        assert!(!local.has_domain("unknown.home"));
    }

    #[test]
    fn ipv4_ptr_format() {
        assert_eq!(
            ipv4_to_ptr(&Ipv4Addr::new(192, 168, 1, 50)),
            "50.1.168.192.in-addr.arpa"
        );
    }

    #[test]
    fn ipv6_ptr_format() {
        let ip: Ipv6Addr = "fd00::1".parse().unwrap();
        let ptr = ipv6_to_ptr(&ip);
        // local-02: exact byte-for-byte pin so the single-buffer rewrite is
        // provably identical to the old Vec<String>+join form.
        // fd00::1 expanded = fd00:0000:0000:0000:0000:0000:0000:0001
        assert_eq!(
            ptr,
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa"
        );
    }

    // ── rev-2606 global-localdns-wildcard-dead: global match_subdomains ──
    // Mirrors the `local_profile` t2_* suffix-walk cases on the global table.

    fn a_ip(records: &[Record]) -> Ipv4Addr {
        match records[0].data {
            RData::A(ref a) => a.0,
            _ => panic!("expected A record, got {:?}", records[0].record_type()),
        }
    }

    #[test]
    fn wildcard_apex_served_via_exact_path() {
        // A `match_subdomains` record answers its own apex via the exact probe
        // (the apex is also in `forward`), no walk needed.
        let cfg = config_with_flags(vec![(
            "example.test",
            LocalDnsRecordType::A,
            "10.0.0.1",
            true,
        )]);
        let local = LocalRecords::build(&cfg);
        assert!(local.has_subdomain_records());
        assert_eq!(local.suffix_count(), 1);
        let hit = local.lookup("example.test", RecordType::A).hit().unwrap();
        assert_eq!(a_ip(&hit), Ipv4Addr::new(10, 0, 0, 1));
        // Apex guard: the exact/apex answer stays owned by the apex (which
        // equals the queried name here) — the owner-rewrite fix must NOT
        // touch this path. Passes both pre- and post-fix.
        assert_eq!(&hit[0].name, &Name::from_str("example.test.").unwrap());
    }

    #[test]
    fn wildcard_matches_descendant() {
        let cfg = config_with_flags(vec![(
            "example.test",
            LocalDnsRecordType::A,
            "10.0.0.1",
            true,
        )]);
        let local = LocalRecords::build(&cfg);
        let hit = local
            .lookup("app.example.test", RecordType::A)
            .hit()
            .unwrap();
        assert_eq!(a_ip(&hit), Ipv4Addr::new(10, 0, 0, 1));
        // localdns-wildcard-owner: the wire invariant — a wildcard-descendant
        // answer must be OWNED by the QNAME, not the configured apex, or
        // RFC-conformant stubs (glibc getanswer_r strcasecmp) discard it.
        assert_eq!(&hit[0].name, &Name::from_str("app.example.test.").unwrap());
        // ...and a deeper descendant too.
        let deep = local
            .lookup("api.v2.app.example.test", RecordType::A)
            .hit()
            .unwrap();
        assert_eq!(a_ip(&deep), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(
            &deep[0].name,
            &Name::from_str("api.v2.app.example.test.").unwrap()
        );
    }

    #[test]
    fn wildcard_longest_suffix_wins() {
        let cfg = config_with_flags(vec![
            ("example.test", LocalDnsRecordType::A, "10.0.0.1", true),
            ("api.example.test", LocalDnsRecordType::A, "10.0.0.2", true),
        ]);
        let local = LocalRecords::build(&cfg);
        let hit = local
            .lookup("x.api.example.test", RecordType::A)
            .hit()
            .unwrap();
        assert_eq!(a_ip(&hit), Ipv4Addr::new(10, 0, 0, 2));
    }

    #[test]
    fn wildcard_exact_record_beats_wildcard() {
        // `app.example.test` exact + `example.test` wildcard → the exact wins (it is
        // probed first), regardless of declaration order.
        let cfg = config_with_flags(vec![
            ("example.test", LocalDnsRecordType::A, "10.0.0.1", true),
            ("app.example.test", LocalDnsRecordType::A, "10.0.0.2", false),
        ]);
        let local = LocalRecords::build(&cfg);
        let hit = local
            .lookup("app.example.test", RecordType::A)
            .hit()
            .unwrap();
        assert_eq!(a_ip(&hit), Ipv4Addr::new(10, 0, 0, 2));
    }

    #[test]
    fn wildcard_does_not_match_unrelated_name() {
        let cfg = config_with_flags(vec![(
            "example.test",
            LocalDnsRecordType::A,
            "10.0.0.1",
            true,
        )]);
        let local = LocalRecords::build(&cfg);
        assert!(matches!(
            local.lookup("google.com", RecordType::A),
            LocalLookup::Miss
        ));
        // A sibling that merely ends with the same bytes (no label boundary)
        // must NOT match.
        assert!(matches!(
            local.lookup("evilexample.test", RecordType::A),
            LocalLookup::Miss
        ));
    }

    #[test]
    fn exact_only_record_does_not_match_descendant_and_short_circuits() {
        // match_subdomains=false: `example.test` does NOT cover `app.example.test`,
        // and the fast-path bit stays false (no walk built).
        let cfg = config_with_flags(vec![(
            "example.test",
            LocalDnsRecordType::A,
            "10.0.0.1",
            false,
        )]);
        let local = LocalRecords::build(&cfg);
        assert!(!local.has_subdomain_records());
        assert_eq!(local.suffix_count(), 0);
        assert!(local.lookup("example.test", RecordType::A).hit().is_some());
        assert!(matches!(
            local.lookup("app.example.test", RecordType::A),
            LocalLookup::Miss
        ));
    }

    #[test]
    fn wildcard_descendant_wrong_address_qtype_synthesises_nodata() {
        // Wildcard A-only → an AAAA query for a descendant is anti-leaked as
        // NODATA, same as the exact-match path does for the apex.
        let cfg = config_with_flags(vec![(
            "example.test",
            LocalDnsRecordType::A,
            "10.0.0.1",
            true,
        )]);
        let local = LocalRecords::build(&cfg);
        assert!(matches!(
            local.lookup("app.example.test", RecordType::AAAA),
            LocalLookup::NodataSynthesis { ttl: 3600 }
        ));
    }

    #[test]
    fn wildcard_descendant_non_address_qtype_misses() {
        // Non-A/AAAA/CNAME qtypes never enter the walk → the descendant falls
        // through to upstream (Miss), matching profile-scope DR4. The exact
        // apex still NODATAs every qtype (covered by the exact-path tests).
        let cfg = config_with_flags(vec![(
            "example.test",
            LocalDnsRecordType::A,
            "10.0.0.1",
            true,
        )]);
        let local = LocalRecords::build(&cfg);
        assert!(matches!(
            local.lookup("app.example.test", RecordType::MX),
            LocalLookup::Miss
        ));
    }

    #[test]
    fn wildcard_cname_descendant_returns_cname() {
        let cfg = config_with_flags(vec![(
            "example.test",
            LocalDnsRecordType::CNAME,
            "proxy.internal",
            true,
        )]);
        let local = LocalRecords::build(&cfg);
        // A query on a descendant → CNAME only (external target).
        let hit = local
            .lookup("api.example.test", RecordType::A)
            .hit()
            .unwrap();
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0].record_type(), RecordType::CNAME);
        // localdns-wildcard-owner: the wildcard CNAME RR is owned by the
        // QNAME, not the apex. (Its RDATA target is untouched.)
        assert_eq!(&hit[0].name, &Name::from_str("api.example.test.").unwrap());
    }

    #[test]
    fn wildcard_cname_follow_local_target_owner_split() {
        // localdns-wildcard-owner: wildcard CNAME on `example.test` → local
        // target `nas.home` (A). A descendant A query must return TWO RRs:
        //   * the CNAME RR owned by the QNAME (`app.example.test`), and
        //   * the followed target's A RR still owned by the concrete target
        //     name (`nas.home`) — the target is NOT the wildcard.
        let cfg = config_with_flags(vec![
            ("example.test", LocalDnsRecordType::CNAME, "nas.home", true),
            ("nas.home", LocalDnsRecordType::A, "192.168.1.50", false),
        ]);
        let local = LocalRecords::build(&cfg);
        let hit = local
            .lookup("app.example.test", RecordType::A)
            .hit()
            .unwrap();
        assert_eq!(hit.len(), 2);
        assert_eq!(hit[0].record_type(), RecordType::CNAME);
        assert_eq!(
            &hit[0].name,
            &Name::from_str("app.example.test.").unwrap(),
            "wildcard CNAME RR must be re-owned by the QNAME"
        );
        assert_eq!(hit[1].record_type(), RecordType::A);
        assert_eq!(
            &hit[1].name,
            &Name::from_str("nas.home.").unwrap(),
            "followed target A RR keeps the target's own name"
        );
    }

    #[test]
    fn exact_only_config_unchanged_nodata_and_ptr() {
        // No-regression: a zero-wildcard config keeps its exact-only posture —
        // the fast-path bit is false, wrong-qtype still NODATAs, PTR still
        // resolves. Nothing the suffix walk added changes this path.
        let cfg = config_with(vec![("nas.home", LocalDnsRecordType::A, "192.168.1.50")]);
        let local = LocalRecords::build(&cfg);
        assert!(!local.has_subdomain_records());
        assert_eq!(local.suffix_count(), 0);
        assert!(matches!(
            local.lookup("nas.home", RecordType::AAAA),
            LocalLookup::NodataSynthesis { ttl: 3600 }
        ));
        assert!(local
            .lookup("50.1.168.192.in-addr.arpa", RecordType::PTR)
            .hit()
            .is_some());
        // A descendant of an exact-only record must NOT resolve.
        assert!(matches!(
            local.lookup("sub.nas.home", RecordType::A),
            LocalLookup::Miss
        ));
    }

    #[test]
    fn wildcard_flood_bounds_hit_table_to_apex_global() {
        // TRK-01 / perfmem T1 — the load-bearing regression. A single
        // `match_subdomains` record answers an unbounded set of distinct
        // subdomains; every hit must key by the ONE configured apex the
        // lookup surfaces (`Hit.apex`), NOT the raw QNAME, so the
        // `LocalRecordsHits` table can't be grown by a LAN wildcard flood.
        use crate::tracking::{LocalRecordsHits, LocalRecordsScopeKey};

        let cfg = config_with_flags(vec![(
            "example.test",
            LocalDnsRecordType::A,
            "10.0.0.1",
            true,
        )]);
        let local = LocalRecords::build(&cfg);
        let hits = LocalRecordsHits::new();

        for i in 0..1000 {
            let qname = format!("host{i}.example.test");
            match local.lookup(&qname, RecordType::A) {
                LocalLookup::Hit { apex, .. } => {
                    hits.record_hit(LocalRecordsScopeKey::Global, &apex);
                }
                _ => panic!("expected wildcard Hit for {qname}"),
            }
        }

        assert_eq!(
            hits.key_count(),
            1,
            "1000 distinct subdomains must collapse to the single apex key"
        );
        assert_eq!(
            hits.count_for(&LocalRecordsScopeKey::Global, "example.test"),
            1000
        );
    }

    #[test]
    fn ptr_hit_apex_is_owning_forward_record() {
        // A PTR hit counts under the owning forward record's apex (from the
        // PTR RDATA target), so reverse + forward hits for one host share a
        // key rather than fragmenting the table.
        let cfg = config_with(vec![("nas.home", LocalDnsRecordType::A, "192.168.1.50")]);
        let local = LocalRecords::build(&cfg);
        match local.lookup("50.1.168.192.in-addr.arpa", RecordType::PTR) {
            LocalLookup::Hit { apex, .. } => assert_eq!(apex.as_str(), "nas.home"),
            _ => panic!("expected PTR Hit"),
        }
    }
}
