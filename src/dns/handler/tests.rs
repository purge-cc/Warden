use super::*;
use std::str::FromStr;

/// handler-07: `fwd_name_for` must forward the REWRITTEN qname when a
/// rewrite fired (the §4.12-leak guard — a client-response assertion can't
/// see a wrong name reach the wire) and reuse the original parsed name
/// verbatim when none did (the §4.30 disc-1 cheap branch). This is the
/// behavioural complement to the source-shape pin in
/// `tests/integration_fwd_name_branch_disc1.rs`.
#[test]
fn fwd_name_for_rewrite_vs_passthrough() {
    let original = LowerName::from(Name::from_ascii("api.old.example.").unwrap());

    // No rewrite: reuse the parsed name directly.
    let passthrough = fwd_name_for("api.old.example", false, &original);
    assert_eq!(passthrough, Name::from(original.clone()));

    // Rewrite fired: the upstream Name is rebuilt from the rewritten
    // `domain`, NOT the original — otherwise the engine would query the old
    // name (the §4.12 leak the shared helper exists to prevent).
    let rewritten = fwd_name_for("api.new.example", true, &original);
    assert_eq!(rewritten, Name::from_ascii("api.new.example.").unwrap());
    assert_ne!(rewritten, Name::from(original));
}

fn a_record(domain: &str, ttl: u32) -> Record {
    Record::from_rdata(
        Name::from_str(domain).unwrap(),
        ttl,
        RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
    )
}

fn cname_record(alias: &str, target: &str, ttl: u32) -> Record {
    Record::from_rdata(
        Name::from_str(alias).unwrap(),
        ttl,
        RData::CNAME(CNAME(Name::from_str(target).unwrap())),
    )
}

fn filter_with_blocked(domains: &[&str]) -> FilterEngine {
    let set: ahash::HashSet<CompactString> =
        domains.iter().map(|d| CompactString::from(*d)).collect();
    FilterEngine::with_domains(set)
}

#[test]
fn cname_to_blocked_domain_detected() {
    let filter = filter_with_blocked(&["tracker.evil.com"]);
    let records = vec![
        cname_record("alias.example.com.", "tracker.evil.com.", 300),
        a_record("tracker.evil.com.", 300),
    ];
    let result = cname_chain_blocked(&records, 16, |t| filter.is_blocked(t));
    assert_eq!(result.as_deref(), Some("tracker.evil.com"));
}

#[test]
fn cname_to_allowed_domain_passes() {
    let filter = filter_with_blocked(&["tracker.evil.com"]);
    let records = vec![
        cname_record("alias.example.com.", "cdn.cloudflare.net.", 300),
        a_record("cdn.cloudflare.net.", 300),
    ];
    assert!(cname_chain_blocked(&records, 16, |t| filter.is_blocked(t)).is_none());
}

#[test]
fn no_cname_records_returns_none() {
    let filter = filter_with_blocked(&["tracker.evil.com"]);
    let records = vec![a_record("example.com.", 300)];
    assert!(cname_chain_blocked(&records, 16, |t| filter.is_blocked(t)).is_none());
}

#[test]
fn empty_records_returns_none() {
    let filter = filter_with_blocked(&["tracker.evil.com"]);
    assert!(cname_chain_blocked(&[], 16, |t| filter.is_blocked(t)).is_none());
}

// --- check_pre_query qtype gate (query-validator-01, rev-2606) ---

fn default_security_layer() -> SecurityLayer {
    SecurityLayer::from_config(
        &SecurityConfig::default(),
        &crate::config::settings::AntiBypassConfig::default(),
    )
}

fn test_client() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
}

/// neutrality-01 — a default install builds NO anti-bypass checker.
///
/// `anti_bypass.enabled` still defaults to `true`, but with the
/// compiled-in provider list gone the resulting set is empty. Keeping
/// a `Some(_)` there would make every query walk its subdomains
/// against a set that can never match. `None` is both the honest
/// state and the free one.
#[test]
fn neutrality01_default_config_builds_no_anti_bypass_checker() {
    let layer = default_security_layer();
    assert!(
        layer.anti_bypass.is_none(),
        "an empty domain set must not become a per-query check"
    );
}

/// The converse: an operator who lists a domain still gets the check.
#[test]
fn neutrality01_operator_supplied_domain_still_builds_the_checker() {
    let layer = SecurityLayer::from_config(
        &SecurityConfig::default(),
        &crate::config::settings::AntiBypassConfig {
            enabled: true,
            extra_domains: vec!["doh.example.net".to_string()],
        },
    );
    let ab = layer
        .anti_bypass
        .as_ref()
        .expect("an operator-listed domain must produce a checker");
    assert!(ab.is_bypass_domain("foo.doh.example.net"));
}

/// Live-confirmed regression: every IPv4 PTR was REFUSED under default
/// config because four consecutive numeric labels matched the
/// rebinding heuristic (`dig -x` vs the CT returned REFUSED).
#[test]
fn ipv4_ptr_passes_pre_query_under_default_config() {
    let sec = default_security_layer();
    assert!(sec
        .check_pre_query(&test_client(), "94.1.10.10.in-addr.arpa", RecordType::PTR)
        .is_ok());
}

/// IPv6 PTR pin: random hex nibble labels concat to entropy ≥3.5,
/// which the tunneling shape check would flag — the PTR gate must
/// skip it. The same name as an A query trips it (gate is on qtype,
/// not on the threshold). 14 distinct nibbles (entropy log2(14)≈3.81)
/// keep the name at 16 labels, inside the shape check's stack-array
/// cap — a full 32-nibble name would fail open there and pin nothing.
#[test]
fn ipv6_ptr_nibbles_skip_tunneling_shape() {
    let sec = default_security_layer();
    let nibbles: Vec<String> = "0123456789abcd".chars().map(|c| c.to_string()).collect();
    let domain = format!("{}.ip6.arpa", nibbles.join("."));
    assert!(sec
        .check_pre_query(&test_client(), &domain, RecordType::PTR)
        .is_ok());
    // As a forward type the same name is still refused — digit nibbles
    // trip rebinding (4 consecutive u8 labels) ahead of the entropy
    // check; either way the heuristics stay armed for non-PTR.
    assert!(
        sec.check_pre_query(&test_client(), &domain, RecordType::A)
            .is_err(),
        "same name as a forward type must still be refused"
    );
    // The real-world full reverse name (32 nibbles + ip6 + arpa = 34
    // labels) must also pass as PTR end-to-end.
    let full: Vec<String> = "0123456789abcdef0123456789abcdef"
        .chars()
        .map(|c| c.to_string())
        .collect();
    let full_domain = format!("{}.ip6.arpa", full.join("."));
    assert!(sec
        .check_pre_query(&test_client(), &full_domain, RecordType::PTR)
        .is_ok());
}

/// Forward rebinding detection unchanged: address-bearing qtypes
/// still refuse IP-embedded names.
#[test]
fn rebinding_still_refused_for_address_types() {
    let sec = default_security_layer();
    for rt in [RecordType::A, RecordType::AAAA, RecordType::HTTPS] {
        assert_eq!(
            sec.check_pre_query(&test_client(), "192.168.1.1.evil.com", rt),
            Err("DNS rebinding pattern detected"),
            "qtype {rt:?}"
        );
    }
}

/// Non-address qtypes can't rebind (no address in the answer) — the
/// heuristic no longer fires for them.
#[test]
fn rebinding_not_checked_for_non_address_types() {
    let sec = default_security_layer();
    assert!(sec
        .check_pre_query(&test_client(), "192.168.1.1.evil.com", RecordType::TXT)
        .is_ok());
}

/// Tunneling shape stays armed for every non-PTR qtype — TXT is the
/// classic exfil carrier and must not ride the PTR exemption.
///
/// The payload used to be a 20-char base64-shaped label, caught by
/// the concatenated-entropy gate. That gate is now floored behind
/// `entropy_min_len`, so the fixture is a 63-char unbroken run —
/// the shape iodine and dnscat2 actually emit. **The property under
/// test is unchanged**: it is the qtype exemption, not the gate that
/// happens to fire.
///
/// Both arms are asserted deliberately. A one-armed version proves
/// only that *something* refused TXT; the PTR arm is what shows the
/// exemption is qtype-scoped rather than name-scoped.
#[test]
fn txt_payload_shape_still_trips_tunneling_but_ptr_rides_the_exemption() {
    let sec = default_security_layer();
    let name = format!("{}.tunnel.example.com", "0".repeat(63));

    assert_eq!(
        sec.check_pre_query(&test_client(), &name, RecordType::TXT),
        Err("tunneling detected"),
        "TXT must not inherit the PTR exemption"
    );
    assert!(
        sec.check_pre_query(&test_client(), &name, RecordType::PTR)
            .is_ok(),
        "PTR skips the shape gate — that is the exemption this test brackets"
    );
}

/// sec-ptr-skips-both-tunneling-gates: the **shape** exemption for PTR
/// is correct and stays (an IPv6 reverse name is 32 hex nibbles and
/// looks exactly like a payload), but nothing requires a PTR query to
/// sit under a reverse zone, and fan-out does not care about the
/// qtype. Pre-fix a payload carried as PTR got no shape check *and*
/// created no rate bucket: unbounded.
#[test]
fn ptr_outside_the_reverse_zones_counts_against_the_rate_gate() {
    // Genuine reverse lookups stay exempt — both families, and the
    // zone apex itself. These share one base domain per client
    // (`in-addr.arpa` is not an eTLD the detector splits), so counting
    // them re-creates the one-bucket-per-client footgun.
    for name in [
        "94.1.10.10.in-addr.arpa",
        "50.1.168.192.in-addr.arpa",
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa",
        "in-addr.arpa",
        "ip6.arpa",
    ] {
        assert!(
            !tunneling_rate_gate_applies(RecordType::PTR, name),
            "{name} is a genuine reverse lookup and must create no bucket"
        );
    }

    // A PTR query outside those zones is fan-out like any other.
    for name in [
        "aGVsbG8td29ybGQ.tun.example.com",
        "home.arpa",
        "example.com",
        // Label-boundary anchored: merely *ending with* the zone text
        // does not inherit the exemption, exactly as `is_exempt` in
        // the tunneling module refuses `evil-<exempt>`.
        "evil-in-addr.arpa",
        "notip6.arpa",
    ] {
        assert!(
            tunneling_rate_gate_applies(RecordType::PTR, name),
            "{name} is not a reverse zone — the rate gate must apply"
        );
    }

    // Unchanged for every other qtype, including under a reverse
    // zone: only PTR ever had the exemption, and only PTR keeps it.
    assert!(tunneling_rate_gate_applies(
        RecordType::A,
        "94.1.10.10.in-addr.arpa"
    ));
    assert!(tunneling_rate_gate_applies(
        RecordType::TXT,
        "x.tun.example.com"
    ));
}

/// The two gates now deliberately disagree on the same name, and that
/// split is the whole fix: shape stays exempt for PTR (nibble names
/// are indistinguishable from payloads), rate does not.
#[test]
fn ptr_payload_skips_the_shape_gate_but_not_the_rate_gate() {
    let sec = default_security_layer();
    let name = format!("{}.tunnel.example.com", "0".repeat(63));

    assert!(
        sec.check_pre_query(&test_client(), &name, RecordType::PTR)
            .is_ok(),
        "the shape gate's PTR exemption is unchanged"
    );
    assert!(
        tunneling_rate_gate_applies(RecordType::PTR, &name),
        "the same name is not in a reverse zone, so the rate gate applies"
    );
}

/// End to end on the detector: a PTR flood of unique names under an
/// attacker-controlled domain trips, and genuine reverse lookups
/// create no bucket at all — so there is nothing for them to be
/// refused from, no matter how many a scanner sends.
#[test]
fn ptr_flood_trips_the_rate_gate_while_reverse_lookups_never_create_a_bucket() {
    let sec = default_security_layer();
    let ip = test_client();
    let td = sec
        .tunneling
        .as_ref()
        .expect("default config builds the tunneling detector");

    // 400 distinct genuine reverse lookups — 8× the default budget.
    for i in 0..400u32 {
        let name = format!("{}.{}.168.192.in-addr.arpa", i % 256, i / 256);
        assert!(!tunneling_rate_gate_applies(RecordType::PTR, &name));
    }
    assert_eq!(
        td.entry_count(),
        0,
        "reverse lookups must never reach the detector, so no bucket exists"
    );

    // The same volume as PTR under an attacker's own domain does
    // reach it, and trips on the name after the budget is spent.
    let mut refused_at = None;
    for i in 0..200u32 {
        let name = format!("p{i}.tun.example.com");
        assert!(tunneling_rate_gate_applies(RecordType::PTR, &name));
        if sec.check_tunneling_rate(&ip, &name) {
            refused_at = Some(i);
            break;
        }
    }
    assert_eq!(
        refused_at,
        Some(50),
        "default subdomain_rate is 50: names 0..=49 fit, the 51st trips"
    );
}

#[test]
fn cname_chain_depth_exceeded_fails_closed() {
    // handler-02 (rev-2606): a chain longer than the cap counts as
    // BLOCKED — mirrors walk_response's CnameDepthExceeded on the
    // request path. Pre-fix the walker returned None here (fail
    // open) and the prefetch paths cached the over-long chain.
    let filter = filter_with_blocked(&["blocked.com"]);
    // Build 20 CNAME records — none of them blocked.
    let records: Vec<Record> = (0..20)
        .map(|i| {
            cname_record(
                &format!("hop{i}.example.com."),
                &format!("hop{}.example.com.", i + 1),
                300,
            )
        })
        .collect();

    // With depth=16, the 17th record trips the cap → treated as blocked
    // even though no target matches the filter.
    assert!(cname_chain_blocked(&records, 16, |t| filter.is_blocked(t)).is_some());
    // A chain within the cap and with no blocked target stays clean.
    assert!(cname_chain_blocked(&records[..10], 16, |t| filter.is_blocked(t)).is_none());

    // A blocked target sitting beyond the cap is still reported (the
    // cap-trip return carries the offending hop, not a filter match).
    let mut with_blocked = records;
    with_blocked[16] = cname_record("hop16.example.com.", "blocked.com.", 300);
    assert!(cname_chain_blocked(&with_blocked, 17, |t| filter.is_blocked(t)).is_some());
}

#[test]
fn cname_subdomain_walk_works() {
    // "sub.tracker.evil.com" is not in the blocklist directly,
    // but "tracker.evil.com" is — subdomain walk should catch it.
    let filter = filter_with_blocked(&["tracker.evil.com"]);
    let records = vec![cname_record(
        "alias.example.com.",
        "sub.tracker.evil.com.",
        300,
    )];
    let result = cname_chain_blocked(&records, 16, |t| filter.is_blocked(t));
    assert_eq!(result.as_deref(), Some("sub.tracker.evil.com"));
}

#[test]
fn cname_trailing_dot_stripped() {
    let filter = filter_with_blocked(&["tracker.evil.com"]);
    // hickory Name always includes trailing dot in Display
    let records = vec![cname_record("alias.example.com.", "tracker.evil.com.", 300)];
    let result = cname_chain_blocked(&records, 16, |t| filter.is_blocked(t));
    // Trailing dot should be stripped so it matches "tracker.evil.com"
    assert_eq!(result.as_deref(), Some("tracker.evil.com"));
}

#[test]
fn cname_mixed_case_target_is_lowercased_before_lookup() {
    // Regression: CNAME targets must be case-normalized before filter
    // lookup, otherwise a mixed-case target from upstream bypasses the
    // blocklist (which is always lowercase per ingestion rule).
    let filter = filter_with_blocked(&["tracker.evil.com"]);
    let records = vec![cname_record("alias.example.com.", "Tracker.Evil.COM.", 300)];
    let result = cname_chain_blocked(&records, 16, |t| filter.is_blocked(t));
    assert_eq!(result.as_deref(), Some("tracker.evil.com"));
}

#[test]
fn multiple_cnames_first_allowed_second_blocked() {
    let filter = filter_with_blocked(&["tracker.evil.com"]);
    let records = vec![
        cname_record("alias1.example.com.", "cdn.cloudflare.net.", 300),
        cname_record("alias2.example.com.", "tracker.evil.com.", 300),
        a_record("tracker.evil.com.", 300),
    ];
    let result = cname_chain_blocked(&records, 16, |t| filter.is_blocked(t));
    assert_eq!(result.as_deref(), Some("tracker.evil.com"));
}

// --- source_allowed (P0-5) ---

fn cidr(s: &str) -> Cidr {
    Cidr::parse(s).unwrap()
}

#[test]
fn source_allowed_none_acl_accepts_all() {
    assert!(source_allowed(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), None));
    assert!(source_allowed(IpAddr::V6(Ipv6Addr::LOCALHOST), None));
}

#[test]
fn source_allowed_empty_acl_accepts_all() {
    let empty: Vec<Cidr> = vec![];
    assert!(source_allowed(
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        Some(&empty)
    ));
}

#[test]
fn source_allowed_inside_cidr() {
    let acl = vec![cidr("10.0.0.0/8"), cidr("192.168.0.0/16")];
    assert!(source_allowed(
        IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
        Some(&acl)
    ));
    assert!(source_allowed(
        IpAddr::V4(Ipv4Addr::new(192, 168, 50, 1)),
        Some(&acl)
    ));
}

#[test]
fn source_allowed_outside_cidr_refused() {
    let acl = vec![cidr("10.0.0.0/8")];
    assert!(!source_allowed(
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        Some(&acl)
    ));
    assert!(!source_allowed(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        Some(&acl)
    ));
}

#[test]
fn source_allowed_v6_inside_cidr() {
    let acl = vec![cidr("fd00::/8")];
    assert!(source_allowed(
        IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
        Some(&acl)
    ));
}

/// On `listen = "[::]:53"` every IPv4 peer arrives as `::ffff:a.b.c.d`.
/// `Cidr::contains` is family-strict, so an IPv4 `allow_from` used to
/// refuse the whole LAN the moment the operator went dual-stack. Fails
/// closed, which is why it presents as "DNS stopped" rather than as a
/// breach. `cargo test` never opens a dual-stack socket, so this pins
/// the ACL decision rather than the socket behaviour.
#[test]
fn source_allowed_ipv4_mapped_source_matches_v4_acl() {
    let acl = vec![cidr("10.10.1.0/24")];
    assert!(source_allowed(
        "::ffff:10.10.1.5".parse().unwrap(),
        Some(&acl)
    ));
    assert!(
        !source_allowed("::ffff:10.10.2.5".parse().unwrap(), Some(&acl)),
        "a mapped address outside the ACL stays refused"
    );
}

#[test]
fn source_allowed_family_mismatch_refused() {
    // v4-only ACL should refuse a v6 source.
    let acl = vec![cidr("10.0.0.0/8")];
    assert!(!source_allowed(IpAddr::V6(Ipv6Addr::LOCALHOST), Some(&acl)));
}

// ── send_block_response dispatch (Sprint 23 s23-block-response-handler) ──

/// Capturing mock for the hickory `ResponseHandler` trait. Stores
/// the `ResponseCode` of the most recent `send_response` call so
/// the dispatcher tests can assert which DNS rcode landed on the
/// wire without spinning up a real socket. Drops every record set
/// — only the header response code matters here.
#[derive(Clone)]
struct CapturingHandler {
    captured_rcode: Arc<Mutex<Option<ResponseCode>>>,
    captured_answer_count: Arc<Mutex<u16>>,
    captured_aa: Arc<Mutex<Option<bool>>>,
    captured_name_server_count: Arc<Mutex<u16>>,
    /// The parsed answer section. The rcode + count fields above are
    /// enough for the dispatcher tests, but the device-network-name
    /// tests must assert the *contents* of the answer — its RDATA, its
    /// TTL, and its owner name. Kept on this handler rather than in a
    /// second recorder so every existing assertion keeps working.
    captured_answers: Arc<Mutex<Vec<Record>>>,
    /// §4.10-4b — the AD (authentic-data) bit, captured so the DNSSEC wire
    /// tests can assert it lands on (and only on) the answers we validated.
    #[cfg(feature = "dnssec")]
    captured_ad: Arc<Mutex<Option<bool>>>,
}

impl CapturingHandler {
    fn new() -> Self {
        Self {
            captured_rcode: Arc::new(Mutex::new(None)),
            captured_answer_count: Arc::new(Mutex::new(0)),
            captured_aa: Arc::new(Mutex::new(None)),
            captured_name_server_count: Arc::new(Mutex::new(0)),
            captured_answers: Arc::new(Mutex::new(Vec::new())),
            #[cfg(feature = "dnssec")]
            captured_ad: Arc::new(Mutex::new(None)),
        }
    }
    fn rcode(&self) -> Option<ResponseCode> {
        *self.captured_rcode.lock().unwrap()
    }
    fn answer_count(&self) -> u16 {
        *self.captured_answer_count.lock().unwrap()
    }
    fn aa(&self) -> Option<bool> {
        *self.captured_aa.lock().unwrap()
    }
    fn name_server_count(&self) -> u16 {
        *self.captured_name_server_count.lock().unwrap()
    }
    fn answers(&self) -> Vec<Record> {
        self.captured_answers.lock().unwrap().clone()
    }
    #[cfg(feature = "dnssec")]
    fn ad(&self) -> Option<bool> {
        *self.captured_ad.lock().unwrap()
    }
}

#[async_trait::async_trait]
impl ResponseHandler for CapturingHandler {
    async fn send_response<'a>(
        &mut self,
        response: hickory_server::zone_handler::MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> Result<ResponseInfo, hickory_net::NetError> {
        use hickory_proto::op::Message;
        use hickory_proto::serialize::binary::BinEncoder;
        // 0.26: MessageResponse no longer exposes a pre-emit Header/counts.
        // Emit to wire and parse back — reads flags + section counts off the
        // real bytes, which is a stronger check than the old pre-emit header.
        let mut buf = Vec::with_capacity(512);
        let info = {
            let mut encoder = BinEncoder::new(&mut buf);
            response
                .destructive_emit(&mut encoder)
                .expect("emit response")
        };
        let parsed = Message::from_vec(&buf).expect("parse emitted response");
        *self.captured_rcode.lock().unwrap() = Some(parsed.metadata.response_code);
        *self.captured_answer_count.lock().unwrap() = parsed.answers.len() as u16;
        *self.captured_answers.lock().unwrap() = parsed.answers.clone();
        *self.captured_aa.lock().unwrap() = Some(parsed.metadata.authoritative);
        *self.captured_name_server_count.lock().unwrap() = parsed.authorities.len() as u16;
        #[cfg(feature = "dnssec")]
        {
            *self.captured_ad.lock().unwrap() = Some(parsed.metadata.authentic_data);
        }
        Ok(info)
    }
}

use std::sync::Mutex;

/// Build a minimal `Request` for the dispatcher tests. The handler
/// helpers only read the request to clone the message header into
/// the response, so a default-constructed message is sufficient.
fn test_request() -> Request {
    use hickory_net::xfer::Protocol;
    use hickory_proto::op::Message;
    use std::net::SocketAddr;
    // 0.26: Request::from_message + MessageRequest ctors are `testing`-gated;
    // Request::from_bytes(Vec<u8>, ..) is the public ungated path.
    let bytes = Message::query().to_vec().unwrap();
    let src: SocketAddr = "127.0.0.1:53".parse().unwrap();
    Request::from_bytes(bytes, src, Protocol::Udp).unwrap()
}

/// Build a `Request` with the AA bit set in its header. Used by the
/// L-6 regression test to confirm we strip AA on the response side
/// regardless of what the request had.
fn test_request_with_aa_set() -> Request {
    use hickory_net::xfer::Protocol;
    use hickory_proto::op::Message;
    use std::net::SocketAddr;
    let mut msg = Message::query();
    msg.metadata.authoritative = true;
    let bytes = msg.to_vec().unwrap();
    let src: SocketAddr = "127.0.0.1:53".parse().unwrap();
    Request::from_bytes(bytes, src, Protocol::Udp).unwrap()
}

// ── §4.10-4b — DNSSEC AD-bit wiring on the cached response path ──────────
// The verdict→decision mapping is tested in `dns::dnssec_validator`; these
// pin the wire effect: `send_cached`'s `authentic` flag flips (and only
// flips) the AD bit. The default build clears the AD write entirely, so
// these only exist under `--features dnssec`.

#[cfg(feature = "dnssec")]
fn one_a_entry() -> crate::dns::cache::CacheEntry {
    let rec = Record::from_rdata(
        Name::from_str("a.example.com.").unwrap(),
        300,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
    );
    crate::dns::cache::CacheEntry::for_test(vec![rec], ResponseCode::NoError)
}

#[cfg(feature = "dnssec")]
#[tokio::test]
async fn send_cached_sets_ad_when_authentic() {
    let req = test_request();
    let entry = one_a_entry();
    let mut h = CapturingHandler::new();
    send_cached(&req, &entry, true, false, &mut h).await;
    assert_eq!(h.ad(), Some(true), "authentic=true must set the AD bit");
    assert_eq!(h.rcode(), Some(ResponseCode::NoError));
    assert_eq!(h.answer_count(), 1);
}

#[cfg(feature = "dnssec")]
#[tokio::test]
async fn send_cached_clears_ad_when_not_authentic() {
    let req = test_request();
    let entry = one_a_entry();
    let mut h = CapturingHandler::new();
    send_cached(&req, &entry, false, false, &mut h).await;
    assert_eq!(h.ad(), Some(false), "authentic=false must leave AD clear");
    assert_eq!(h.rcode(), Some(ResponseCode::NoError));
}

/// The rewrite suppression, at the one site that writes AD. A validator that
/// returned `SetAd` for the *original* name must still not raise AD on an
/// answer we fronted with an unsigned synthesized CNAME.
#[cfg(feature = "dnssec")]
#[tokio::test]
async fn send_cached_rewritten_never_sets_ad() {
    let req = test_request();
    let entry = one_a_entry();
    let mut h = CapturingHandler::new();
    send_cached(&req, &entry, true, true, &mut h).await;
    assert_eq!(
        h.ad(),
        Some(false),
        "a rewritten answer is fronted by an unsigned synthesized CNAME — \
         it must never carry AD, even when the validator said Secure"
    );
}

#[tokio::test]
async fn send_block_response_zero_returns_noerror_and_canned_record() {
    // Zero variant goes through send_blocked → NoError + canned
    // 0.0.0.0 record. This pins the retrocompat path so a future
    // refactor can't accidentally route Zero through NXDOMAIN.
    let req = test_request();
    let qname = Name::from_str("ads.example.com").unwrap();
    let mut handler = CapturingHandler::new();
    send_block_response(
        &req,
        &qname,
        RecordType::A,
        60,
        crate::config::schema::BlockResponseV1::Zero,
        &mut handler,
    )
    .await;
    assert_eq!(handler.rcode(), Some(ResponseCode::NoError));
}

#[tokio::test]
async fn send_block_response_zero_aaaa_returns_noerror_and_canned_record() {
    // AAAA branch of send_blocked — mirror of the A test. Pins the
    // explicit set_response_code(NoError) call so a refactor that
    // drops it leaves the test failing instead of silently
    // depending on hickory's default. Closes Sprint 9 audit bug #1
    // for the IPv6 path.
    let req = test_request();
    let qname = Name::from_str("ads.example.com").unwrap();
    let mut handler = CapturingHandler::new();
    send_block_response(
        &req,
        &qname,
        RecordType::AAAA,
        60,
        crate::config::schema::BlockResponseV1::Zero,
        &mut handler,
    )
    .await;
    assert_eq!(handler.rcode(), Some(ResponseCode::NoError));
}

#[tokio::test]
async fn send_block_response_zero_other_type_returns_nodata() {
    // Non-A/AAAA record types (TXT, MX, SRV, …) hit the NODATA
    // branch: NOERROR + zero answers + SOA in authority per RFC
    // 2308 §2.1. Critically NOT NXDOMAIN — that would tell caches
    // the domain doesn't exist at all and suppress future A/AAAA
    // queries for the same name, defeating the 0.0.0.0 sinkhole.
    // Pins the third branch of send_blocked against that regression.
    let req = test_request();
    let qname = Name::from_str("ads.example.com").unwrap();
    let mut handler = CapturingHandler::new();
    send_block_response(
        &req,
        &qname,
        RecordType::TXT,
        60,
        crate::config::schema::BlockResponseV1::Zero,
        &mut handler,
    )
    .await;
    assert_eq!(handler.rcode(), Some(ResponseCode::NoError));
}

#[tokio::test]
async fn send_block_response_nxdomain_returns_nxdomain_rcode() {
    let req = test_request();
    let qname = Name::from_str("ads.example.com").unwrap();
    let mut handler = CapturingHandler::new();
    send_block_response(
        &req,
        &qname,
        RecordType::A,
        60,
        crate::config::schema::BlockResponseV1::Nxdomain,
        &mut handler,
    )
    .await;
    assert_eq!(handler.rcode(), Some(ResponseCode::NXDomain));
}

#[tokio::test]
async fn send_block_response_refused_returns_refused_rcode() {
    let req = test_request();
    let qname = Name::from_str("ads.example.com").unwrap();
    let mut handler = CapturingHandler::new();
    send_block_response(
        &req,
        &qname,
        RecordType::A,
        60,
        crate::config::schema::BlockResponseV1::Refused,
        &mut handler,
    )
    .await;
    assert_eq!(handler.rcode(), Some(ResponseCode::Refused));
}

#[tokio::test]
async fn send_rfc8482_returns_noerror_with_single_hinfo_answer() {
    // RFC 8482 §6: ANY queries get a synthesised HINFO reply with
    // NOERROR + exactly one answer record. This pins the amplification
    // guard against a refactor that drops the answer_count=1 or flips
    // to NXDOMAIN (which would suppress subsequent A/AAAA queries at
    // client caches, same pitfall as the send_blocked NODATA path).
    let req = test_request();
    let qname = Name::from_str("example.com").unwrap();
    let mut handler = CapturingHandler::new();
    send_rfc8482(&req, &qname, 60, &mut handler).await;
    assert_eq!(handler.rcode(), Some(ResponseCode::NoError));
    assert_eq!(handler.answer_count(), 1);
}

#[tokio::test]
async fn send_nxdomain_helper_sets_nxdomain_directly() {
    // Regression guard: a future refactor that "simplifies"
    // send_nxdomain by removing the explicit set_response_code
    // call would silently leave the rcode as NoError. Pin the
    // contract.
    let req = test_request();
    let mut handler = CapturingHandler::new();
    send_nxdomain(&req, &mut handler).await;
    assert_eq!(handler.rcode(), Some(ResponseCode::NXDomain));
}

#[tokio::test]
async fn send_refused_emits_refused_rcode() {
    // L-3 (rev-2026-04-unreachable-profile) supporting pin: the fail-
    // closed fallback for the missing-profile-resolver branch in
    // handle_request_inner uses send_refused. Pin that send_refused
    // emits ResponseCode::Refused — if a future refactor turned this
    // into NoError or NXDomain, the L-3 fallback would silently allow
    // queries through during a broken construction invariant. The
    // integration-level pin (handle_request_inner with profiles=None
    // returns Refused) is out of scope here — it requires constructing
    // a 14-parameter mock handler stack — but this contract pin
    // catches the failure mode the L-3 fix depends on.
    let req = test_request();
    let mut handler = CapturingHandler::new();
    send_refused(&req, &mut handler).await;
    assert_eq!(handler.rcode(), Some(ResponseCode::Refused));
}

#[tokio::test]
async fn aa_bit_cleared_on_blocked_response_even_when_request_had_it_set() {
    // L-6 (rev-2026-04-aa-bit-clear) regression pin: hickory's
    // Header::response_from_request preserves the request's AA flag.
    // We're a recursive resolver — the AA bit on our responses must
    // always be 0. send_blocked is one of the canonical answer-path
    // sites; pin that even with AA=1 in the request, the response
    // emerges with AA=0.
    let req = test_request_with_aa_set();
    let qname = Name::from_str("ads.example.com").unwrap();
    let mut handler = CapturingHandler::new();
    send_block_response(
        &req,
        &qname,
        RecordType::A,
        60,
        crate::config::schema::BlockResponseV1::Zero,
        &mut handler,
    )
    .await;
    assert_eq!(handler.aa(), Some(false), "AA must be cleared on response");
}

#[tokio::test]
async fn aa_bit_cleared_on_nxdomain_response_even_when_request_had_it_set() {
    // L-6 regression pin sibling — covers the send_nxdomain path,
    // a separate Header::response_from_request site.
    let req = test_request_with_aa_set();
    let mut handler = CapturingHandler::new();
    send_nxdomain(&req, &mut handler).await;
    assert_eq!(handler.aa(), Some(false), "AA must be cleared on NXDOMAIN");
}

fn cache_test_config() -> crate::config::settings::CacheConfig {
    crate::config::settings::CacheConfig {
        max_entries: 100,
        max_ttl_secs: 3600,
        min_ttl_secs: 5,
        negative_ttl_secs: 60,
        stale_buffer_secs: 300,
        prefetch: false,
        prefetch_threshold: 0.1,
        prefetch_max_concurrent: 16,
        cname_max_depth: 16,
        prefetch_tracker_enabled: false,
        prefetch_tracker_window_secs: 300,
        prefetch_tracker_min_hits: 3,
        prefetch_tracker_max_pool_size: 1024,
        prefetch_tracker_tick_secs: 30,
        prefetch_tracker_lead_secs: 10,
    }
}

#[tokio::test]
async fn cached_nxdomain_response_includes_soa_in_authority() {
    // L-5 (rev-2026-04-cached-neg-soa) regression pin: cached NXDOMAIN
    // responses must include a SOA in the authority section per
    // RFC 2308 §3, mirroring the fresh-blocked NODATA path. Pre-fix
    // send_cached used build_no_records for the negative branch, which
    // sent the NXDOMAIN with an empty authority section — downstream
    // resolvers fell back to default negative-cache TTL instead of
    // honoring the operator's `negative_ttl` floor.
    use hickory_proto::rr::DNSClass;
    let cache = DnsCache::new(&cache_test_config());
    cache
        .insert(
            "nxdomain.example.com",
            RecordType::A,
            DNSClass::IN,
            Vec::new(),
            ResponseCode::NXDomain,
            None,
            None,
        )
        .await;
    let entry = cache
        .lookup("nxdomain.example.com", RecordType::A, DNSClass::IN, None)
        .await
        .fresh()
        .expect("freshly inserted entry must be Fresh");

    let req = test_request();
    let mut handler = CapturingHandler::new();
    send_cached(&req, &entry, false, false, &mut handler).await;

    assert_eq!(handler.rcode(), Some(ResponseCode::NXDomain));
    assert_eq!(
        handler.name_server_count(),
        1,
        "cached NXDOMAIN must carry SOA in authority section (RFC 2308 §3)"
    );
    assert_eq!(handler.answer_count(), 0);
}

#[test]
fn blocked_soa_static_names_match_from_ascii_parse() {
    // H-01 regression pin: the OnceLock'd cached `Name`s for the
    // blocked-NODATA SOA must be byte-for-byte equal to the
    // `Name::from_ascii(...)` output that the pre-fix code re-parsed
    // on every blocked response. Compare wire labels, not just
    // Display, so a future refactor that switches the literal can't
    // pass this test by coincidence.
    let zone_expected = Name::from_ascii("block.purge-warden.local.").unwrap();
    let mname_expected = Name::from_ascii("ns.purge-warden.local.").unwrap();
    let rname_expected = Name::from_ascii("admin.purge-warden.local.").unwrap();
    assert_eq!(blocked_soa_zone(), &zone_expected);
    assert_eq!(blocked_soa_mname(), &mname_expected);
    assert_eq!(blocked_soa_rname(), &rname_expected);

    // And the SOA record built from the cached names must carry
    // those names verbatim — covers `.clone()` returning a value
    // that compares equal, which is the contract the SOA depends on.
    let record = blocked_soa(60);
    assert_eq!(&record.name, &zone_expected);
    let RData::SOA(ref soa) = record.data else {
        panic!("blocked_soa must produce an SOA record");
    };
    assert_eq!(&soa.mname, &mname_expected);
    assert_eq!(&soa.rname, &rname_expected);
    assert_eq!(soa.minimum, 60);
}

#[test]
fn prefetch_helper_blocked_cname_short_chain() {
    let filter = filter_with_blocked(&["bad.example.com"]);
    let records = vec![cname_record("alias.example.com.", "bad.example.com.", 300)];
    let blocked = cname_chain_blocked(&records, 16, |t| filter.is_blocked(t));
    assert_eq!(blocked.as_deref(), Some("bad.example.com"));
}

#[test]
fn prefetch_helper_unblocked_cname_short_chain() {
    let filter = filter_with_blocked(&["bad.example.com"]);
    let records = vec![cname_record("alias.example.com.", "good.example.net.", 300)];
    assert!(cname_chain_blocked(&records, 16, |t| filter.is_blocked(t)).is_none());
}

#[test]
fn prefetch_helper_depth_capped_at_configured_limit() {
    // L-8 (rev-2026-04-cname-prefetch-cap) regression pin: the
    // pre-fix prefetch CNAME inspection used `iter().any(...)` and
    // walked the entire chain unbounded. The cap still stops the
    // scan at cname_max_depth — but per handler-02 (rev-2606) the
    // cap trip now FAILS CLOSED (returns the hop at the cap as
    // blocked) instead of returning None, mirroring walk_response's
    // CnameDepthExceeded. The filter probe count check below pins
    // that scanning genuinely stops at the cap.
    let filter = filter_with_blocked(&["blocked.example.com"]);
    let mut records: Vec<Record> = (0..20)
        .map(|i| {
            cname_record(
                &format!("hop{i}.example.com."),
                &format!("hop{}.example.com.", i + 1),
                300,
            )
        })
        .collect();
    records[16] = cname_record("hop16.example.com.", "blocked.example.com.", 300);
    // depth=16 → the 17th record trips the cap: fail-closed (blocked),
    // and the predicate ran at most 16 times (the cap bounds the scan).
    let mut probes = 0usize;
    let result = cname_chain_blocked(&records, 16, |t| {
        probes += 1;
        filter.is_blocked(t)
    });
    assert!(result.is_some());
    assert!(probes <= 16, "scan must stop at the cap, ran {probes}");
    // depth=17 → reaches the blocked record via a genuine filter match.
    assert_eq!(
        cname_chain_blocked(&records, 17, |t| filter.is_blocked(t)).as_deref(),
        Some("blocked.example.com")
    );
}

/// M-31 regression pin: the request-path walker hoists
/// `resolver.resolve(client_ip)` once before the chain walk. This test
/// confirms behaviour-equivalence with the pre-refactor per-iteration
/// resolution by exercising a profile-aware block in a 3-hop chain.
#[test]
fn check_cname_chain_blocks_via_resolved_profile() {
    let filter = filter_with_blocked(&["evil.example.com"]);
    let records = vec![
        cname_record("alias.example.com.", "hop1.example.com.", 300),
        cname_record("hop1.example.com.", "evil.example.com.", 300),
    ];
    // §4.5 Sprint 2/2: post wire-in the request-path uses
    // `walk_response` directly. The flat-filter fallback this test
    // pinned now lives in `cname_chain_blocked` (still pub(crate) for
    // the prefetch path).
    let blocked = cname_chain_blocked(&records, 16, |t| filter.is_blocked(t));
    assert_eq!(blocked.as_deref(), Some("evil.example.com"));
}

#[tokio::test]
async fn cached_nodata_response_includes_soa_in_authority() {
    // L-5 sibling: NODATA (NoError + empty records) is the second
    // negative-cache shape. Pin that it also receives the SOA fix —
    // is_negative() routes both NXDomain and NoError-with-empty
    // through the new SOA-bearing branch.
    use hickory_proto::rr::DNSClass;
    let cache = DnsCache::new(&cache_test_config());
    cache
        .insert(
            "nodata.example.com",
            RecordType::AAAA,
            DNSClass::IN,
            Vec::new(),
            ResponseCode::NoError,
            None,
            None,
        )
        .await;
    let entry = cache
        .lookup("nodata.example.com", RecordType::AAAA, DNSClass::IN, None)
        .await
        .fresh()
        .expect("freshly inserted entry must be Fresh");

    let req = test_request();
    let mut handler = CapturingHandler::new();
    send_cached(&req, &entry, false, false, &mut handler).await;

    assert_eq!(handler.rcode(), Some(ResponseCode::NoError));
    assert_eq!(
        handler.name_server_count(),
        1,
        "cached NODATA must carry SOA in authority section (RFC 2308 §3)"
    );
    assert_eq!(handler.answer_count(), 0);
}

// ── Sprint 43 T4: per-device overlay path ─────────────────

use ahash::RandomState;
use std::collections::HashSet;

fn empty_profile() -> Arc<ResolvedProfile> {
    Arc::new(ResolvedProfile::permissive_default())
}

fn overlay_with(allow: &[&str], deny: &[&str], override_flag: bool) -> Arc<DeviceOverlay> {
    let allow_set: HashSet<CompactString, RandomState> =
        allow.iter().map(|d| CompactString::from(*d)).collect();
    let deny_set: HashSet<CompactString, RandomState> =
        deny.iter().map(|d| CompactString::from(*d)).collect();
    Arc::new(DeviceOverlay {
        device_id: crate::config::schema::Id::new("dev-test").unwrap(),
        allow: Arc::new(allow_set),
        deny: Arc::new(deny_set),
        override_profile_deny: override_flag,
    })
}

/// Snapshot acceptance §8: device with empty overlay produces
/// byte-identical resolution to the pre-T4 baseline. We verify
/// this by calling `evaluate_with_overlay` with `overlay = None`
/// and asserting it agrees with `filter.evaluate(...) == Block`
/// across both block and forward outcomes.
#[test]
fn evaluate_with_overlay_none_overlay_is_byte_identical_baseline() {
    let filter = filter_with_blocked(&[]);
    // Use profile.deny_domains so the block path doesn't depend on
    // list-policy wiring: permissive_default subscribes to nothing, so
    // the generation's masks for it are inert. (Pre-`plp-s3` this was
    // spelled `list_bitmask = 0`, on a field that no longer exists.)
    let mut profile = ResolvedProfile::permissive_default();
    std::sync::Arc::make_mut(&mut profile.deny_domains).insert(CompactString::from("evil.com"));
    let profile = Arc::new(profile);

    let (blocked, _) = evaluate_with_overlay("evil.com", &profile, None, &filter);
    let baseline = filter.evaluate("evil.com", &profile) == FilterResult::Block;
    assert_eq!(blocked, baseline, "None overlay must match pre-T4 baseline");
    assert!(blocked, "evil.com is in profile.deny_domains");

    // Allowed domain — both must report Forward.
    let (blocked, _) = evaluate_with_overlay("good.com", &profile, None, &filter);
    let baseline = filter.evaluate("good.com", &profile) == FilterResult::Block;
    assert_eq!(blocked, baseline);
    assert!(!blocked);
}

/// Truth table row 4: device.deny alone blocks the query, no
/// profile rule matches.
#[test]
fn evaluate_with_overlay_device_deny_blocks() {
    let filter = filter_with_blocked(&[]); // empty list
    let profile = empty_profile();
    let overlay = overlay_with(&[], &["tiktok.com"], false);

    let (blocked, _) = evaluate_with_overlay("tiktok.com", &profile, Some(&overlay), &filter);
    assert!(blocked, "device.deny → BLOCK");
}

/// Sprint B Dashboard v2 — the overlay-Block path returns
/// `Some(BlockSource::AdminBlock)`. Per-device deny is admin-grade,
/// so the IPC `top_blocked_lists` aggregator must NOT pin a
/// Tier 1 list bit for this branch.
#[test]
fn evaluate_with_overlay_returns_admin_block_source() {
    let filter = filter_with_blocked(&[]);
    let profile = empty_profile();
    let overlay = overlay_with(&[], &["evil.com"], false);

    let (blocked, source) = evaluate_with_overlay("evil.com", &profile, Some(&overlay), &filter);
    assert!(blocked, "device.deny → BLOCK");
    assert_eq!(
        source,
        Some(BlockSource::AdminBlock),
        "overlay-deny is admin-grade, not a list bit"
    );
}

/// Truth table row 3: device.allow alone allows the query even
/// when the filter would default-forward (so this test is more
/// about exercising the FallThrough path with a hit).
#[test]
fn evaluate_with_overlay_device_allow_lets_through() {
    let filter = filter_with_blocked(&[]); // empty
    let profile = empty_profile();
    let overlay = overlay_with(&["bank.example"], &[], false);

    let (blocked, _) = evaluate_with_overlay("bank.example", &profile, Some(&overlay), &filter);
    assert!(!blocked, "device.allow → FORWARD");
}

/// Truth table row 5: profile.allow + device.deny → DENY
/// (Device, additive deny). The HashSet on profile.allow_domains
/// is populated; the device deny still wins.
#[test]
fn evaluate_with_overlay_device_deny_wins_over_profile_allow() {
    let filter = filter_with_blocked(&[]);
    let mut profile = ResolvedProfile::permissive_default();
    std::sync::Arc::make_mut(&mut profile.allow_domains)
        .insert(CompactString::from("bank.example"));
    let profile = Arc::new(profile);
    let overlay = overlay_with(&[], &["bank.example"], false);

    let (blocked, _) = evaluate_with_overlay("bank.example", &profile, Some(&overlay), &filter);
    assert!(blocked, "additive deny: device.deny over profile.allow");
}

/// Truth table row 7: profile.deny + device.allow + override=true
/// → ALLOW [OVERRIDE]. The most ergonomically important case for
/// the operator.
#[test]
fn evaluate_with_overlay_override_unblocks_profile_deny() {
    let filter = filter_with_blocked(&[]);
    let mut profile = ResolvedProfile::permissive_default();
    std::sync::Arc::make_mut(&mut profile.deny_domains).insert(CompactString::from("youtube.com"));
    let profile = Arc::new(profile);
    let overlay = overlay_with(&["youtube.com"], &[], true); // override = true

    let (blocked, _) = evaluate_with_overlay("youtube.com", &profile, Some(&overlay), &filter);
    assert!(!blocked, "override flag must allow past profile.deny");
}

/// Truth table row 6 (drift defensive): profile.deny +
/// device.allow + override=false → DENY (Profile). The CLI
/// refuses this combination at edit time, but if drift slips
/// through the daemon must default to profile-wins.
#[test]
fn evaluate_with_overlay_drift_falls_back_to_profile_deny() {
    let filter = filter_with_blocked(&[]);
    let mut profile = ResolvedProfile::permissive_default();
    std::sync::Arc::make_mut(&mut profile.deny_domains).insert(CompactString::from("youtube.com"));
    let profile = Arc::new(profile);
    let overlay = overlay_with(&["youtube.com"], &[], false); // no override

    let (blocked, _) = evaluate_with_overlay("youtube.com", &profile, Some(&overlay), &filter);
    assert!(blocked, "without override flag, profile.deny wins on drift");
}

/// Truth table row 8: both deny → BLOCK (Profile attribution).
/// The block result is the same as row 4; only the attribution
/// differs (covered by `apply_overlay` unit tests in resolver.rs).
#[test]
fn evaluate_with_overlay_both_deny_blocks() {
    let filter = filter_with_blocked(&[]);
    let mut profile = ResolvedProfile::permissive_default();
    std::sync::Arc::make_mut(&mut profile.deny_domains).insert(CompactString::from("evil.com"));
    let profile = Arc::new(profile);
    let overlay = overlay_with(&[], &["evil.com"], false);

    let (blocked, _) = evaluate_with_overlay("evil.com", &profile, Some(&overlay), &filter);
    assert!(blocked);
}

/// FallThrough rows (0/1/2): no device-side hit — the profile
/// evaluator decides. We pin via `profile.deny_domains` so the
/// block path doesn't depend on list-policy wiring: the permissive
/// default subscribes to nothing, so its masks are inert. (Pre-`plp-s3`:
/// `list_bitmask = 0`, a field that no longer exists.)
#[test]
fn evaluate_with_overlay_fall_through_uses_profile_evaluator() {
    let filter = filter_with_blocked(&[]);
    let mut profile = ResolvedProfile::permissive_default();
    std::sync::Arc::make_mut(&mut profile.deny_domains)
        .insert(CompactString::from("blocked.example"));
    let profile = Arc::new(profile);
    // Overlay exists but neither set matches the queried domain.
    let overlay = overlay_with(&["bank.example"], &["tiktok.com"], false);

    // Non-matching domain falls through to filter.evaluate which
    // hits profile.deny_domains.
    let (blocked, _) = evaluate_with_overlay("blocked.example", &profile, Some(&overlay), &filter);
    assert!(blocked, "profile.deny takes effect on FallThrough");
    let (blocked, _) = evaluate_with_overlay("nothing.example", &profile, Some(&overlay), &filter);
    assert!(!blocked, "domain not in any layer → forward");
}

/// N7 invariant on the full DNS-handler path: the overlay sets
/// are domain-only, and `apply_overlay` ignores qtype, so
/// `evaluate_with_overlay` produces an identical answer
/// regardless of whether the caller would later return A or AAAA.
/// We model the qtype-symmetric property as "two independent
/// invocations produce the same answer".
// s44-arch-cache-invalidate-on-block (M-12 follow-up):
// post-cache-hit re-check tests. The splice in `handle_inner`
// re-runs `check_cname_chain` + `IpFilter::check_response` against
// the cached `entry.records()` before serving. On trip, the cache
// tuple is invalidated and a canned block is sent. These tests
// exercise the wiring at the data-flow level (insert → lookup →
// re-check predicate → invalidate_key → re-lookup) without the
// full request/response_handle plumbing — sufficient because the
// splice composes three already-tested primitives.
fn cache_filter_test_config() -> crate::config::settings::CacheConfig {
    crate::config::settings::CacheConfig {
        max_entries: 100,
        max_ttl_secs: 3600,
        min_ttl_secs: 5,
        negative_ttl_secs: 60,
        stale_buffer_secs: 300,
        prefetch: false,
        prefetch_threshold: 0.1,
        prefetch_max_concurrent: 16,
        cname_max_depth: 16,
        prefetch_tracker_enabled: false,
        prefetch_tracker_window_secs: 300,
        prefetch_tracker_min_hits: 3,
        prefetch_tracker_max_pool_size: 1024,
        prefetch_tracker_tick_secs: 30,
        prefetch_tracker_lead_secs: 10,
    }
}

#[tokio::test]
async fn cache_hit_cname_chain_blocked_invalidates_entry() {
    // M-12 race scenario: cache stores `D CNAME → C` from an earlier
    // upstream fetch. Operator later adds `C` to a deny rule. Next
    // query for D: filter-evaluate(D) is allow, cache hit, but the
    // CNAME re-check now catches `C` and the entry must be evicted.
    use hickory_proto::rr::DNSClass;
    let cache = DnsCache::new(&cache_filter_test_config());
    let records = vec![
        cname_record("alias.example.com.", "tracker.evil.com.", 300),
        a_record("tracker.evil.com.", 300),
    ];
    cache
        .insert(
            "alias.example.com",
            RecordType::A,
            DNSClass::IN,
            records,
            ResponseCode::NoError,
            None,
            None,
        )
        .await;
    let entry = cache
        .lookup("alias.example.com", RecordType::A, DNSClass::IN, None)
        .await
        .fresh()
        .expect("populated entry must be fresh");
    let filter = filter_with_blocked(&["tracker.evil.com"]);
    let trip = cname_chain_blocked(entry.records(), 16, |t| filter.is_blocked(t));
    assert_eq!(
        trip.as_deref(),
        Some("tracker.evil.com"),
        "cache-hit re-check must catch the newly-blocked CNAME target"
    );
    cache
        .invalidate_key("alias.example.com", RecordType::A, DNSClass::IN, None)
        .await;
    assert!(
        matches!(
            cache
                .lookup("alias.example.com", RecordType::A, DNSClass::IN, None)
                .await,
            CacheLookup::Miss
        ),
        "M-12: post-trip invalidation must remove the cached entry"
    );
}

#[tokio::test]
async fn cache_hit_cname_chain_clean_passes_through() {
    // Negative case: the cached CNAME target is NOT in the filter's
    // blocklist, so the re-check returns None and the cache hit
    // would proceed to `send_cached` unchanged. Pins the no-op cost
    // of the splice on the happy path.
    use hickory_proto::rr::DNSClass;
    let cache = DnsCache::new(&cache_filter_test_config());
    let records = vec![
        cname_record("api.example.com.", "cdn.cloudflare.net.", 300),
        a_record("cdn.cloudflare.net.", 300),
    ];
    cache
        .insert(
            "api.example.com",
            RecordType::A,
            DNSClass::IN,
            records,
            ResponseCode::NoError,
            None,
            None,
        )
        .await;
    let entry = cache
        .lookup("api.example.com", RecordType::A, DNSClass::IN, None)
        .await
        .fresh()
        .unwrap();
    let filter = filter_with_blocked(&["tracker.evil.com"]);
    assert!(cname_chain_blocked(entry.records(), 16, |t| filter.is_blocked(t)).is_none());
    // Entry still present after the no-op re-check.
    assert!(cache
        .lookup("api.example.com", RecordType::A, DNSClass::IN, None)
        .await
        .fresh()
        .is_some());
}

#[tokio::test]
async fn cache_hit_ip_blocklist_match_invalidates_entry() {
    // M-12 race scenario, IP-blocklist variant: cache stores
    // `D A 1.2.3.4`. Operator later adds 1.2.3.4 to the IP
    // blocklist. Next query for D: filter-evaluate(D) is allow,
    // cache hit, but the IP re-check now catches 1.2.3.4 and the
    // entry must be evicted.
    use hickory_proto::rr::DNSClass;
    use std::collections::HashSet;
    let cache = DnsCache::new(&cache_filter_test_config());
    cache
        .insert(
            "fastflux.example.com",
            RecordType::A,
            DNSClass::IN,
            vec![a_record("fastflux.example.com.", 300)],
            ResponseCode::NoError,
            None,
            None,
        )
        .await;
    let entry = cache
        .lookup("fastflux.example.com", RecordType::A, DNSClass::IN, None)
        .await
        .fresh()
        .unwrap();
    let mut blocked_ips: HashSet<IpAddr, ahash::RandomState> = HashSet::default();
    blocked_ips.insert(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
    let ipf = IpFilter::with_ips(blocked_ips);
    let hit = ipf.check_response(entry.records(), NamePolicy::Neutral);
    assert_eq!(
        hit,
        Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
        "cache-hit IP re-check must catch the newly-blocked address"
    );
    cache
        .invalidate_key("fastflux.example.com", RecordType::A, DNSClass::IN, None)
        .await;
    assert!(matches!(
        cache
            .lookup("fastflux.example.com", RecordType::A, DNSClass::IN, None)
            .await,
        CacheLookup::Miss
    ));
}

#[tokio::test]
async fn cache_hit_ip_blocklist_clean_passes_through() {
    // Negative case for IP path: cached A record is not in the
    // blocklist, re-check returns None, entry stays.
    use hickory_proto::rr::DNSClass;
    use std::collections::HashSet;
    let cache = DnsCache::new(&cache_filter_test_config());
    cache
        .insert(
            "clean.example.com",
            RecordType::A,
            DNSClass::IN,
            vec![a_record("clean.example.com.", 300)],
            ResponseCode::NoError,
            None,
            None,
        )
        .await;
    let entry = cache
        .lookup("clean.example.com", RecordType::A, DNSClass::IN, None)
        .await
        .fresh()
        .unwrap();
    let mut other_ips: HashSet<IpAddr, ahash::RandomState> = HashSet::default();
    other_ips.insert(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)));
    let ipf = IpFilter::with_ips(other_ips);
    assert!(ipf
        .check_response(entry.records(), NamePolicy::Neutral)
        .is_none());
    assert!(cache
        .lookup("clean.example.com", RecordType::A, DNSClass::IN, None)
        .await
        .fresh()
        .is_some());
}

#[tokio::test]
async fn cache_hit_invalidate_key_targets_only_matched_qtype() {
    // The post-cache-hit splice invalidates the precise tuple it
    // looked up, NOT the whole domain. If the operator's deny rule
    // affects only the A-record CNAME chain, the cached AAAA tuple
    // (which has different records and a different CNAME chain or
    // none at all) stays put. This pins the precision of
    // `invalidate_key` against the broader `invalidate_domain`.
    use hickory_proto::rr::DNSClass;
    let cache = DnsCache::new(&cache_filter_test_config());
    cache
        .insert(
            "site.example.com",
            RecordType::A,
            DNSClass::IN,
            vec![cname_record("site.example.com.", "tracker.evil.com.", 300)],
            ResponseCode::NoError,
            None,
            None,
        )
        .await;
    cache
        .insert(
            "site.example.com",
            RecordType::AAAA,
            DNSClass::IN,
            vec![a_record("site.example.com.", 300)],
            ResponseCode::NoError,
            None,
            None,
        )
        .await;
    // Simulate the splice firing on the A-record cache hit only.
    cache
        .invalidate_key("site.example.com", RecordType::A, DNSClass::IN, None)
        .await;
    assert!(matches!(
        cache
            .lookup("site.example.com", RecordType::A, DNSClass::IN, None)
            .await,
        CacheLookup::Miss
    ));
    assert!(
        cache
            .lookup("site.example.com", RecordType::AAAA, DNSClass::IN, None)
            .await
            .fresh()
            .is_some(),
        "AAAA tuple must survive A-only invalidation"
    );
}

#[test]
fn evaluate_with_overlay_is_qtype_agnostic_n7() {
    let filter = filter_with_blocked(&["a.example", "b.example"]);
    let mut profile = ResolvedProfile::permissive_default();
    std::sync::Arc::make_mut(&mut profile.deny_domains).insert(CompactString::from("c.example"));
    let profile = Arc::new(profile);
    let overlay = overlay_with(&["x.example"], &["d.example"], false);

    for domain in [
        "a.example",
        "b.example",
        "c.example",
        "d.example",
        "x.example",
        "z.example",
    ] {
        let (r1, _) = evaluate_with_overlay(domain, &profile, Some(&overlay), &filter);
        let (r2, _) = evaluate_with_overlay(domain, &profile, Some(&overlay), &filter);
        assert_eq!(r1, r2, "N7: qtype-agnostic for {domain}");
    }
}

// §4.29 — ECS Cache Invalidation Hardening regression tests.
//
// Pre-§4.29, the four post-block invalidate sites in `handle_inner`
// (cache-hit CNAME, cache-hit IP, post-fetch CNAME, post-fetch IP)
// all passed literal `None` to `invalidate_key`, which targeted the
// non-ECS slot instead of the bucketed slot the lookup actually
// returned. The fix routes all four sites through
// `invalidate_current_bucket`, whose signature forces the call site
// to pass `ecs_cache_prefix` explicitly. These tests pin the helper's
// semantics on the bucketed path and confirm the non-ECS sentinel
// slot is not collateral-damaged.
fn ecs_test_prefix() -> EcsPrefix {
    EcsPrefix {
        addr: IpAddr::V4(Ipv4Addr::new(10, 10, 1, 0)),
        prefix: 24,
    }
}

/// h1 regression — cache-hit CNAME-block site (handler.rs:825).
#[tokio::test]
async fn ecs_bucketed_cache_hit_cname_block_invalidates_correct_bucket() {
    let cache = DnsCache::new(&cache_filter_test_config());
    let prefix = Some(ecs_test_prefix());
    let records = vec![
        cname_record("alias.example.com.", "tracker.evil.com.", 300),
        a_record("tracker.evil.com.", 300),
    ];
    cache
        .insert(
            "alias.example.com",
            RecordType::A,
            DNSClass::IN,
            records.clone(),
            ResponseCode::NoError,
            None,
            prefix,
        )
        .await;
    cache
        .insert(
            "alias.example.com",
            RecordType::A,
            DNSClass::IN,
            records,
            ResponseCode::NoError,
            None,
            None,
        )
        .await;
    let entry = cache
        .lookup("alias.example.com", RecordType::A, DNSClass::IN, prefix)
        .await
        .fresh()
        .expect("bucketed entry must be fresh");
    let filter = filter_with_blocked(&["tracker.evil.com"]);
    let trip = cname_chain_blocked(entry.records(), 16, |t| filter.is_blocked(t));
    assert_eq!(trip.as_deref(), Some("tracker.evil.com"));
    invalidate_current_bucket(
        &cache,
        "alias.example.com",
        RecordType::A,
        DNSClass::IN,
        prefix,
    )
    .await;
    assert!(
        matches!(
            cache
                .lookup("alias.example.com", RecordType::A, DNSClass::IN, prefix)
                .await,
            CacheLookup::Miss
        ),
        "§4.29 h1: ECS-bucketed slot must be evicted by helper"
    );
    assert!(
        cache
            .lookup("alias.example.com", RecordType::A, DNSClass::IN, None)
            .await
            .fresh()
            .is_some(),
        "§4.29 h1: non-ECS sentinel slot must NOT be collateral-damaged"
    );
}

/// h2 regression — cache-hit IP-block site (handler.rs:866).
#[tokio::test]
async fn ecs_bucketed_cache_hit_ip_block_invalidates_correct_bucket() {
    use std::collections::HashSet;
    let cache = DnsCache::new(&cache_filter_test_config());
    let prefix = Some(ecs_test_prefix());
    let records = vec![a_record("fastflux.example.com.", 300)];
    cache
        .insert(
            "fastflux.example.com",
            RecordType::A,
            DNSClass::IN,
            records.clone(),
            ResponseCode::NoError,
            None,
            prefix,
        )
        .await;
    cache
        .insert(
            "fastflux.example.com",
            RecordType::A,
            DNSClass::IN,
            records,
            ResponseCode::NoError,
            None,
            None,
        )
        .await;
    let entry = cache
        .lookup("fastflux.example.com", RecordType::A, DNSClass::IN, prefix)
        .await
        .fresh()
        .expect("bucketed entry must be fresh");
    let mut blocked_ips: HashSet<IpAddr, ahash::RandomState> = HashSet::default();
    blocked_ips.insert(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
    let ipf = IpFilter::with_ips(blocked_ips);
    assert_eq!(
        ipf.check_response(entry.records(), NamePolicy::Neutral),
        Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))
    );
    invalidate_current_bucket(
        &cache,
        "fastflux.example.com",
        RecordType::A,
        DNSClass::IN,
        prefix,
    )
    .await;
    assert!(
        matches!(
            cache
                .lookup("fastflux.example.com", RecordType::A, DNSClass::IN, prefix)
                .await,
            CacheLookup::Miss
        ),
        "§4.29 h2: ECS-bucketed slot must be evicted by helper"
    );
    assert!(
        cache
            .lookup("fastflux.example.com", RecordType::A, DNSClass::IN, None)
            .await
            .fresh()
            .is_some(),
        "§4.29 h2: non-ECS sentinel slot must NOT be collateral-damaged"
    );
}

/// h3 regression — post-fetch CNAME-block site (handler.rs:1181). Mirrors
/// h1 at the data-flow level; in production the entry was just inserted
/// by `lookup_or_fetch` rather than pre-existing. Helper behavior is
/// identical.
#[tokio::test]
async fn ecs_bucketed_post_fetch_cname_block_invalidates_correct_bucket() {
    let cache = DnsCache::new(&cache_filter_test_config());
    let prefix = Some(ecs_test_prefix());
    let records = vec![
        cname_record("freshly.example.com.", "tracker.evil.com.", 300),
        a_record("tracker.evil.com.", 300),
    ];
    cache
        .insert(
            "freshly.example.com",
            RecordType::A,
            DNSClass::IN,
            records.clone(),
            ResponseCode::NoError,
            None,
            prefix,
        )
        .await;
    cache
        .insert(
            "freshly.example.com",
            RecordType::A,
            DNSClass::IN,
            records,
            ResponseCode::NoError,
            None,
            None,
        )
        .await;
    invalidate_current_bucket(
        &cache,
        "freshly.example.com",
        RecordType::A,
        DNSClass::IN,
        prefix,
    )
    .await;
    assert!(
        matches!(
            cache
                .lookup("freshly.example.com", RecordType::A, DNSClass::IN, prefix)
                .await,
            CacheLookup::Miss
        ),
        "§4.29 h3: ECS-bucketed slot must be evicted by helper after post-fetch CNAME-block"
    );
    assert!(
        cache
            .lookup("freshly.example.com", RecordType::A, DNSClass::IN, None)
            .await
            .fresh()
            .is_some(),
        "§4.29 h3: non-ECS sentinel slot must NOT be collateral-damaged"
    );
}

/// h4 regression — post-fetch IP-block site (handler.rs:1222). Mirrors
/// h2 at the data-flow level.
#[tokio::test]
async fn ecs_bucketed_post_fetch_ip_block_invalidates_correct_bucket() {
    let cache = DnsCache::new(&cache_filter_test_config());
    let prefix = Some(ecs_test_prefix());
    let records = vec![a_record("freshly-ip.example.com.", 300)];
    cache
        .insert(
            "freshly-ip.example.com",
            RecordType::A,
            DNSClass::IN,
            records.clone(),
            ResponseCode::NoError,
            None,
            prefix,
        )
        .await;
    cache
        .insert(
            "freshly-ip.example.com",
            RecordType::A,
            DNSClass::IN,
            records,
            ResponseCode::NoError,
            None,
            None,
        )
        .await;
    invalidate_current_bucket(
        &cache,
        "freshly-ip.example.com",
        RecordType::A,
        DNSClass::IN,
        prefix,
    )
    .await;
    assert!(
        matches!(
            cache
                .lookup(
                    "freshly-ip.example.com",
                    RecordType::A,
                    DNSClass::IN,
                    prefix
                )
                .await,
            CacheLookup::Miss
        ),
        "§4.29 h4: ECS-bucketed slot must be evicted by helper after post-fetch IP-block"
    );
    assert!(
        cache
            .lookup("freshly-ip.example.com", RecordType::A, DNSClass::IN, None)
            .await
            .fresh()
            .is_some(),
        "§4.29 h4: non-ECS sentinel slot must NOT be collateral-damaged"
    );
}

/// Defensive: helper called with `None` (no-ECS-policy profile) targets
/// the non-ECS slot and leaves any concurrent `Some(prefix)` bucketed
/// slot intact. Mirror of h1-h4 from the other direction — pins backward
/// compatibility for non-ECS-routed profiles.
#[tokio::test]
async fn helper_with_none_does_not_touch_ecs_bucketed_slot() {
    let cache = DnsCache::new(&cache_filter_test_config());
    let prefix = Some(ecs_test_prefix());
    let records = vec![a_record("dual.example.com.", 300)];
    cache
        .insert(
            "dual.example.com",
            RecordType::A,
            DNSClass::IN,
            records.clone(),
            ResponseCode::NoError,
            None,
            prefix,
        )
        .await;
    cache
        .insert(
            "dual.example.com",
            RecordType::A,
            DNSClass::IN,
            records,
            ResponseCode::NoError,
            None,
            None,
        )
        .await;
    invalidate_current_bucket(
        &cache,
        "dual.example.com",
        RecordType::A,
        DNSClass::IN,
        None,
    )
    .await;
    assert!(
        matches!(
            cache
                .lookup("dual.example.com", RecordType::A, DNSClass::IN, None)
                .await,
            CacheLookup::Miss
        ),
        "helper with None must evict the non-ECS slot"
    );
    assert!(
        cache
            .lookup("dual.example.com", RecordType::A, DNSClass::IN, prefix)
            .await
            .fresh()
            .is_some(),
        "helper with None must NOT touch the bucketed slot"
    );
}

// ── device network names (2026-08-10 design spec, D1/D2/D5) ─────────────

/// Recording mock upstream.
///
/// **Records rather than traps.** Every test below turns on *whether the
/// query left this daemon*, and a `panic!` inside the handler's async
/// path can be swallowed instead of failing the test. What it answers is
/// irrelevant — the assertions read `calls()`.
#[derive(Default)]
struct RecordingUpstream {
    calls: std::sync::atomic::AtomicUsize,
    last_name: Mutex<Option<String>>,
}

impl RecordingUpstream {
    fn calls(&self) -> usize {
        self.calls.load(std::sync::atomic::Ordering::SeqCst)
    }
    fn last_name(&self) -> Option<String> {
        self.last_name.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl Upstream for RecordingUpstream {
    async fn lookup(
        &self,
        name: &Name,
        _record_type: RecordType,
        _ecs: Option<crate::dns::edns::EdnsClientSubnet>,
    ) -> Result<crate::upstream::UpstreamResponse, DnsError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        *self.last_name.lock().unwrap() = Some(name.to_string());
        Ok(crate::upstream::UpstreamResponse {
            records: vec![Record::from_rdata(
                name.clone(),
                60,
                RData::A(A(Ipv4Addr::new(203, 0, 113, 9))),
            )],
            response_code: ResponseCode::NoError,
            soa_minimum_ttl: None,
            #[cfg(feature = "dnssec")]
            authority: Vec::new(),
        })
    }
}

/// Query source for the network-name tests. Matches no device, so the
/// 5-level chain lands on `server.default_profile` — without that, a
/// fall-through would stop at the SN3 REFUSED sentinel and never reach
/// upstream, silently defeating the `calls()` assertions.
const NET_NAME_CLIENT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 7);

/// A resolver holding exactly one device with a `network_name`.
/// `device_ip = None` builds the offline case: no pinned IP and no MAC,
/// so `resolve_network_name` finds nothing to answer with while
/// `network_name_is_configured` still reports the name as ours.
fn resolver_with_network_name(
    network_name: &str,
    wildcard: bool,
    device_ip: Option<IpAddr>,
) -> Arc<ProfileResolver> {
    use crate::config::schema::{ConfigV1, Device, Id, Profile};
    use crate::lists::source_key::SourceBitMap;

    let mut config = ConfigV1 {
        schema_version: 1,
        ..Default::default()
    };
    config.server.default_profile = Some(Id::new("demo").unwrap());
    config.profiles.insert(
        "demo".to_string(),
        Profile {
            display_name: "demo".into(),
            ..Default::default()
        },
    );
    config.devices.push(Device {
        id: Id::new("named-dev").unwrap(),
        display_name: "named".into(),
        ip: device_ip,
        mac: None,
        mac_aliases: vec![],
        profile: Some(Id::new("demo").unwrap()),
        groups: vec![],
        owner: None,
        device_type: None,
        department: None,
        notes: None,
        allow_rules: vec![],
        deny_rules: vec![],
        override_profile_deny: false,
        unfiltered: false,
        network_name: Some(network_name.to_string()),
        network_name_wildcard: wildcard,
    });
    Arc::new(ProfileResolver::build(
        &config,
        &SourceBitMap::default(),
        &crate::config::custom_list::CustomListStore::new(),
    ))
}

/// `local_records = None` — a static-table miss is this branch's
/// precondition, so every test but the precedence pin wants it absent.
fn handler_with_resolver(
    resolver: Arc<ProfileResolver>,
    upstream: Arc<RecordingUpstream>,
    dynamic_ttl: u32,
) -> ForwardHandler {
    handler_with(resolver, upstream, dynamic_ttl, None)
}

fn handler_with(
    resolver: Arc<ProfileResolver>,
    upstream: Arc<RecordingUpstream>,
    dynamic_ttl: u32,
    local_records: Option<Arc<LocalRecords>>,
) -> ForwardHandler {
    ForwardHandler::new(
        upstream,
        Arc::new(FilterEngine::new()),
        DnsCache::new(&crate::config::settings::CacheConfig::default()),
        Some(resolver),
        None, // stats
        None, // security — no pre-query gate in the way
        local_records,
        None, // ip_filter
        None, // allow_from: accept every source
        60,
        None, // prefetch disabled
        0.0,
        16,
    )
    .with_dynamic_ttl_secs(dynamic_ttl)
}

fn net_name_request(qname: &str, record_type: RecordType) -> Request {
    use hickory_net::xfer::Protocol;
    use hickory_proto::op::{Message, Query};
    use std::net::SocketAddr;

    let mut msg = Message::new(0x2607, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(
        Name::from_ascii(format!("{qname}.")).unwrap(),
        record_type,
    ));
    let bytes = msg.to_vec().unwrap();
    let src = SocketAddr::new(IpAddr::V4(NET_NAME_CLIENT), 40000);
    Request::from_bytes(bytes, src, Protocol::Udp).unwrap()
}

async fn drive(handler: &ForwardHandler, request: &Request) -> CapturingHandler {
    let mut sink = CapturingHandler::new();
    handler
        .handle_inner(request, &mut sink)
        .await
        .expect("handler must not error");
    sink
}

/// The fallback the handler uses when the boot path never called
/// [`ForwardHandler::with_dynamic_ttl_secs`] must be the value the
/// config documents. Drift makes warden answer with a TTL no config
/// file mentions — invisible until an operator wonders why their name
/// went stale.
#[test]
fn default_dynamic_ttl_matches_config_default() {
    assert_eq!(
        DEFAULT_DYNAMIC_TTL_SECS,
        crate::config::settings::LocalDnsConfig::default().dynamic_ttl_secs,
    );
}

#[tokio::test]
async fn network_name_exact_hit_answers_a_record() {
    let upstream = Arc::new(RecordingUpstream::default());
    let handler = handler_with_resolver(
        resolver_with_network_name(
            "desktop-1",
            false,
            Some(IpAddr::V4(Ipv4Addr::new(10, 10, 1, 50))),
        ),
        Arc::clone(&upstream),
        // Deliberately NOT the default: a test asserting 30 would pass
        // whether or not the TTL plumbing works at all.
        77,
    );

    let sink = drive(&handler, &net_name_request("desktop-1", RecordType::A)).await;

    assert_eq!(sink.rcode(), Some(ResponseCode::NoError));
    let answers = sink.answers();
    assert_eq!(answers.len(), 1, "expected one A answer, got {answers:?}");
    assert_eq!(answers[0].data, RData::A(A(Ipv4Addr::new(10, 10, 1, 50))));
    assert_eq!(
        answers[0].ttl, 77,
        "the answer's TTL must come from local_dns.dynamic_ttl_secs"
    );
    assert_eq!(
        answers[0].name,
        Name::from_ascii("desktop-1.").unwrap(),
        "the answer must be owned by the QNAME"
    );
    assert_eq!(
        upstream.calls(),
        0,
        "a locally-answered name must never reach upstream"
    );
}

#[tokio::test]
async fn network_name_unknown_device_falls_through_to_nxdomain_path() {
    let upstream = Arc::new(RecordingUpstream::default());
    let handler = handler_with_resolver(
        resolver_with_network_name(
            "desktop-1",
            false,
            Some(IpAddr::V4(Ipv4Addr::new(10, 10, 1, 50))),
        ),
        Arc::clone(&upstream),
        77,
    );

    let sink = drive(&handler, &net_name_request("not-a-device", RecordType::A)).await;

    // The discriminating assertion. "No A for 10.10.1.50" would pass with
    // the whole branch deleted; "the query left the daemon" would not.
    assert_eq!(
        upstream.calls(),
        1,
        "an unrecognised name must fall through to the normal query path"
    );
    assert_eq!(upstream.last_name().as_deref(), Some("not-a-device."));
    assert_eq!(sink.rcode(), Some(ResponseCode::NoError));
}

#[tokio::test]
async fn network_name_configured_but_device_offline_answers_nxdomain() {
    let upstream = Arc::new(RecordingUpstream::default());
    // No configured IP and no MAC — nothing for the ARP walk to match.
    let handler = handler_with_resolver(
        resolver_with_network_name("offline-box", false, None),
        Arc::clone(&upstream),
        77,
    );

    let sink = drive(&handler, &net_name_request("offline-box", RecordType::A)).await;

    assert_eq!(sink.rcode(), Some(ResponseCode::NXDomain));
    assert_eq!(sink.answer_count(), 0);
    // Without this half, an upstream that happened to answer NXDOMAIN
    // would make the test pass with the branch deleted.
    assert_eq!(
        upstream.calls(),
        0,
        "a name warden owns must not leak upstream, even when unresolvable"
    );
}

/// Pins the `Some(IpAddr::V6(_))` arm: a device pinned to a v6-only
/// address must fall through on an A query rather than answer NXDOMAIN,
/// deliberately unlike the `None` (unresolvable) arm right above. Without
/// this test the only thing distinguishing the two arms was a comment.
#[tokio::test]
async fn network_name_v6_pinned_device_a_query_falls_through() {
    let upstream = Arc::new(RecordingUpstream::default());
    let handler = handler_with_resolver(
        resolver_with_network_name(
            "v6-only",
            false,
            Some(IpAddr::V6(std::net::Ipv6Addr::new(
                0xfd00, 0, 0, 0, 0, 0, 0, 1,
            ))),
        ),
        Arc::clone(&upstream),
        77,
    );

    let sink = drive(&handler, &net_name_request("v6-only", RecordType::A)).await;

    assert_eq!(
        upstream.calls(),
        1,
        "a v6-pinned device must fall through to the normal query path on an A query"
    );
    assert_eq!(upstream.last_name().as_deref(), Some("v6-only."));
    assert_ne!(
        sink.rcode(),
        Some(ResponseCode::NXDomain),
        "fall-through must not be mistaken for the offline NXDOMAIN case"
    );
}

/// The wildcard case is what justifies owning the answer with the parsed
/// QNAME rather than the device's apex: glibc's `getanswer()` silently
/// discards an answer whose owner is unreachable from the question.
#[tokio::test]
async fn network_name_wildcard_descendant_is_owned_by_the_qname() {
    let upstream = Arc::new(RecordingUpstream::default());
    let handler = handler_with_resolver(
        resolver_with_network_name(
            "casamia",
            true,
            Some(IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10))),
        ),
        Arc::clone(&upstream),
        77,
    );

    let sink = drive(&handler, &net_name_request("app.casamia", RecordType::A)).await;

    let answers = sink.answers();
    assert_eq!(answers.len(), 1, "expected one A answer, got {answers:?}");
    assert_eq!(answers[0].data, RData::A(A(Ipv4Addr::new(10, 10, 10, 10))));
    assert_eq!(
        answers[0].name,
        Name::from_ascii("app.casamia.").unwrap(),
        "a wildcard descendant must be owned by the queried name, not the apex"
    );
    assert_eq!(upstream.calls(), 0);
}

/// A-only for the actual *answer* (D5: no IPv6/NDP tracking exists), but
/// a configured name with no A must not leak upstream either — same
/// local-01 anti-leak rationale as the static `local_dns`
/// `NodataSynthesis` path immediately above this branch in
/// `handle_inner`. Default (`nodata_for_missing_types = true`, the
/// config default): NODATA, upstream never touched.
#[tokio::test]
async fn network_name_aaaa_query_answers_nodata_by_default() {
    let upstream = Arc::new(RecordingUpstream::default());
    let handler = handler_with_resolver(
        resolver_with_network_name(
            "desktop-1",
            false,
            Some(IpAddr::V4(Ipv4Addr::new(10, 10, 1, 50))),
        ),
        Arc::clone(&upstream),
        77,
    );

    let sink = drive(&handler, &net_name_request("desktop-1", RecordType::AAAA)).await;

    assert_eq!(
        upstream.calls(),
        0,
        "a configured network_name must never leak an AAAA query upstream"
    );
    assert_eq!(sink.rcode(), Some(ResponseCode::NoError));
    assert_eq!(sink.answer_count(), 0);
    assert!(
        sink.name_server_count() >= 1,
        "NODATA must carry a synthesized SOA in the authority section"
    );
}

/// The operator escape hatch: `nodata_for_missing_types = false` is the
/// same deliberate split-horizon opt-out the static `local_dns` table
/// already offers (its own doc comment: "Metti false solo se usi
/// deliberatamente split-horizon"). With it off, a device network_name
/// reverts to the old plain fall-through for a non-A qtype.
#[tokio::test]
async fn network_name_aaaa_query_falls_through_when_nodata_disabled() {
    let upstream = Arc::new(RecordingUpstream::default());
    let handler = ForwardHandler::new(
        Arc::clone(&upstream) as Arc<dyn Upstream>,
        Arc::new(FilterEngine::new()),
        DnsCache::new(&crate::config::settings::CacheConfig::default()),
        Some(resolver_with_network_name(
            "desktop-1",
            false,
            Some(IpAddr::V4(Ipv4Addr::new(10, 10, 1, 50))),
        )),
        None,
        None,
        None,
        None,
        None,
        60,
        None,
        0.0,
        16,
    )
    .with_dynamic_ttl_secs(77)
    .with_nodata_for_missing_types_network_name(false);

    let sink = drive(&handler, &net_name_request("desktop-1", RecordType::AAAA)).await;

    assert_eq!(
        upstream.calls(),
        1,
        "AAAA must fall through to the 5-level chain when the operator opted out"
    );
    assert_eq!(upstream.last_name().as_deref(), Some("desktop-1."));
    assert_ne!(sink.rcode(), Some(ResponseCode::NXDomain));
}

/// The ordering claim the inserted comment makes: a static `local_dns`
/// record wins an exact collision because this branch is probed only
/// after the static table misses.
///
/// Unpinned, that claim is a comment — a refactor hoisting the branch
/// above the `local_records` block would break it and stay green, since
/// every other test here passes `local_records = None`. Only a test can
/// reach this state at all: the validator refuses a config where a
/// device `network_name` collides with a `local_dns` record, so the
/// ordering is defence in depth and this is the only way to exercise it.
///
/// The two paths answer different addresses *and* different TTLs, so the
/// assertion names which one replied rather than merely that someone did.
#[tokio::test]
async fn static_local_dns_record_wins_over_a_colliding_network_name() {
    use crate::config::settings::{LocalDnsConfig, LocalDnsRecord, LocalDnsRecordType};

    let static_table = LocalRecords::build(&LocalDnsConfig {
        ttl_secs: 3600,
        dynamic_ttl_secs: 30,
        nodata_for_missing_types: true,
        records: vec![LocalDnsRecord {
            domain: "desktop-1".into(),
            record_type: LocalDnsRecordType::A,
            value: "192.0.2.1".into(),
            match_subdomains: false,
            ttl_secs: None,
        }],
    });
    let upstream = Arc::new(RecordingUpstream::default());
    let handler = handler_with(
        resolver_with_network_name(
            "desktop-1",
            false,
            Some(IpAddr::V4(Ipv4Addr::new(10, 10, 1, 50))),
        ),
        Arc::clone(&upstream),
        77,
        Some(Arc::new(static_table)),
    );

    let sink = drive(&handler, &net_name_request("desktop-1", RecordType::A)).await;

    let answers = sink.answers();
    assert_eq!(answers.len(), 1, "expected one A answer, got {answers:?}");
    assert_eq!(
        answers[0].data,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
        "the operator's explicit local_dns record must beat the device's \
         dynamic network_name"
    );
    assert_eq!(
        answers[0].ttl, 3600,
        "TTL must come from local_dns.ttl_secs, not dynamic_ttl_secs — \
         a matching address alone would not say which path answered"
    );
    assert_eq!(upstream.calls(), 0);
}

// ── boot list persistence — readiness gate backstop (Task 2, §2.4) ──────

/// A resolver with one `default_profile`, empty rules, no devices.
/// Every client falls through to it, so a query is neither blocked
/// nor caught by the `(None, _)` fail-closed arm in `handle_inner`
/// (L-3): passing `profiles: None` there REFUSES every query for a
/// reason unrelated to the readiness gate and would defeat these
/// tests regardless of gate state — the doc comment on
/// [`ForwardHandler::new`] claiming a `None`-profiles fallback to
/// legacy `is_blocked()` predates L-3 and is no longer accurate.
fn permissive_test_resolver() -> Arc<ProfileResolver> {
    use crate::config::schema::{ConfigV1, Id, Profile};
    use crate::lists::source_key::SourceBitMap;

    let mut config = ConfigV1 {
        schema_version: 1,
        ..Default::default()
    };
    config.server.default_profile = Some(Id::new("demo").unwrap());
    config.profiles.insert(
        "demo".to_string(),
        Profile {
            display_name: "demo".into(),
            ..Default::default()
        },
    );
    Arc::new(ProfileResolver::build(
        &config,
        &SourceBitMap::default(),
        &crate::config::custom_list::CustomListStore::new(),
    ))
}

/// A handler with security/stats/local-records/ACL disabled and a
/// permissive resolver (see [`permissive_test_resolver`]), backed by
/// `upstream` so an unblocked query resolves normally instead of
/// erroring. Takes the upstream by reference (mirrors
/// [`handler_with_resolver`]) rather than building its own, so a
/// test can keep its own handle and assert on `calls()` — the only
/// way to pin "never evaluates the filter", not just "answers
/// SERVFAIL", per `boot_list_persistence.md` §4 obligation 5.
fn build_test_handler(upstream: Arc<RecordingUpstream>) -> ForwardHandler {
    ForwardHandler::new(
        upstream,
        Arc::new(FilterEngine::new()),
        DnsCache::new(&crate::config::settings::CacheConfig::default()),
        Some(permissive_test_resolver()),
        None, // stats
        None, // security
        None, // local_records
        None, // ip_filter
        None, // allow_from: accept every source
        60,
        None, // prefetch disabled
        0.0,
        16,
    )
}

/// Drive a single query for `domain` through `handler` and return the
/// captured response. Reuses [`net_name_request`]'s message-building —
/// despite its name, that helper just builds a query for an arbitrary
/// qname/record type from a fixed private source address.
async fn query_handler(
    handler: &ForwardHandler,
    domain: &str,
    record_type: RecordType,
) -> CapturingHandler {
    drive(handler, &net_name_request(domain, record_type)).await
}

/// A closed gate refuses every query with SERVFAIL, before the
/// filter is consulted at all — pinned by `upstream.calls() == 0`,
/// not just the rcode. The rcode alone proves only that a later
/// SERVFAIL fired somewhere on the path; a refactor that hoists the
/// gate check below the point the query already leaked upstream
/// would still read SERVFAIL and pass a rcode-only assertion.
#[tokio::test]
async fn closed_readiness_gate_servfails_every_query() {
    let gate = ReadinessGate::new(false);
    let upstream = Arc::new(RecordingUpstream::default());
    // Build the handler exactly as the neighbouring tests do, then
    // attach the gate.
    let handler = build_test_handler(Arc::clone(&upstream)).with_filter_ready(gate.clone());

    let response = query_handler(&handler, "example.com", RecordType::A).await;

    assert_eq!(
        response.rcode(),
        Some(ResponseCode::ServFail),
        "a daemon with no installed generation must refuse, not answer"
    );
    assert_eq!(
        upstream.calls(),
        0,
        "a closed gate must refuse before the filter/upstream path is \
         ever reached — not merely end up SERVFAIL some other way"
    );
}

/// The default is OPEN, so every construction that does not opt in —
/// including every other test in this file — behaves exactly as
/// before. `start.rs` is the only place that seeds it closed.
///
/// Asserts the positive shape (`NoError` + one upstream call), not
/// just `!= ServFail`: a handler that returned `Ok` without ever
/// calling `send_response` would leave `rcode() == None`, which
/// also satisfies `!= Some(ServFail)` without proving anything
/// answered. `calls() == 1` is also the discriminator against the
/// closed-gate test above: if both read 0, the fixture never
/// reaches upstream at all and neither test means what it claims.
#[tokio::test]
async fn readiness_gate_defaults_open() {
    let upstream = Arc::new(RecordingUpstream::default());
    let handler = build_test_handler(Arc::clone(&upstream));

    let response = query_handler(&handler, "example.com", RecordType::A).await;

    assert_eq!(
        response.rcode(),
        Some(ResponseCode::NoError),
        "a handler with no gate attached must answer normally"
    );
    assert_eq!(upstream.calls(), 1);
}

/// handler-05 applies here too: an unconditional `warn!` per refused
/// query while the gate is closed is the same log-flood / journald
/// amplification vector the ACL path's comment (`handler.rs:952`)
/// already warns against — worse, here it fires for EVERY client,
/// not just non-allowed sources, at the worst possible
/// moment (boot, when the box is least able to absorb it).
///
/// This one asserts on the **latch**, not on the log level:
/// `gate_refusal_logged` is what the warn/debug branch reads, so
/// proving it is `false` before any refusal, `true` after the first
/// and still `true` after the second proves the branch was taken
/// once and only once.
///
/// That is necessary but NOT sufficient, and the gap is precisely
/// the mutation this repo has already named
/// (`feedback_mutation_swap_not_delete`): swap the two arms and the
/// latch behaves identically while every refusal *after* the first
/// warns — the same log-flood vector, delayed by one packet.
/// [`closed_gate_logs_warn_first_then_debug`] closes that by
/// capturing the levels; the two together are the whole property.
#[tokio::test]
async fn closed_gate_warns_once_then_stays_quiet() {
    let gate = ReadinessGate::new(false);
    let upstream = Arc::new(RecordingUpstream::default());
    let handler = build_test_handler(Arc::clone(&upstream)).with_filter_ready(gate.clone());

    assert!(
        !handler
            .gate_refusal_logged
            .load(std::sync::atomic::Ordering::Relaxed),
        "fixture sanity: nothing has refused yet"
    );

    let first = query_handler(&handler, "example.com", RecordType::A).await;
    assert_eq!(first.rcode(), Some(ResponseCode::ServFail));
    assert!(
        handler
            .gate_refusal_logged
            .load(std::sync::atomic::Ordering::Relaxed),
        "the first refusal must latch — this is what routes it to warn!"
    );

    let second = query_handler(&handler, "example.org", RecordType::A).await;
    assert_eq!(second.rcode(), Some(ResponseCode::ServFail));
    assert!(
        handler
            .gate_refusal_logged
            .load(std::sync::atomic::Ordering::Relaxed),
        "the latch must never reset — a second refusal must still take \
         the quiet debug! arm, not warn again"
    );
    assert_eq!(
        upstream.calls(),
        0,
        "both refusals must still refuse before reaching upstream — \
         this test is about log volume, not a regression on the gate \
         itself"
    );
}

/// Substring common to BOTH arms of the gate-refusal log — the
/// `warn!`'s "…no filter generation has been installed yet…" and the
/// `debug!`'s "…no filter generation installed yet". Filtering on it
/// rather than counting levels matters: the query path emits other
/// events, and a bare "one WARN, one DEBUG" count would be satisfied
/// by any two of them. Filtering on a substring unique to one arm
/// would be worse still — the filter would then decide the answer.
const GATE_REFUSAL_MARKER: &str = "no filter generation";

thread_local! {
    /// Levels of gate-refusal events seen on THIS thread, in order.
    /// `Some` only between [`arm_gate_refusal_capture`] and
    /// [`take_gate_refusal_levels`]; libtest gives each test its own
    /// thread and `#[tokio::test]` is a current-thread runtime, so
    /// no other test can write here.
    static GATE_REFUSAL_LEVELS: std::cell::RefCell<Option<Vec<tracing::Level>>> =
        const { std::cell::RefCell::new(None) };
}

/// Pulls the formatted `message` field out of an event. `tracing`
/// exposes it only through the visitor API — there is no
/// `event.message()`.
struct MessageVisitor(String);

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}

/// A minimal `tracing::Subscriber` that files gate-refusal events
/// into the armed thread's buffer and drops everything else.
///
/// **Installed GLOBALLY, and it has to be** — the obvious design is
/// a `tracing_subscriber::Layer` under
/// `tracing::subscriber::set_default`, thread-local so it cannot
/// disturb neighbours. That version is *flaky*: measured 8 failures
/// in 16 runs. `tracing` caches each callsite's `Interest` in a
/// process-global slot, so a neighbouring test that drives a refusal
/// with no subscriber on its thread (there are several) can get
/// `Interest::never()` cached for the `warn!` callsite, after which
/// this thread's subscriber is never consulted for it and the
/// capture silently loses the event. A global default is registered
/// in that cache, so every callsite resolves to `always` and the
/// capture is deterministic. Neighbours stay unaffected: their
/// thread has no buffer armed, so `event` returns after one
/// thread-local read.
struct GateRefusalCapture;

impl tracing::Subscriber for GateRefusalCapture {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn event(&self, event: &tracing::Event<'_>) {
        // `try_with` because this can run while a thread is being
        // torn down and its thread-locals are already destroyed.
        let _ = GATE_REFUSAL_LEVELS.try_with(|cell| {
            let Ok(mut slot) = cell.try_borrow_mut() else {
                return;
            };
            let Some(levels) = slot.as_mut() else {
                return; // not the capturing thread — the common case
            };
            let mut visitor = MessageVisitor(String::new());
            event.record(&mut visitor);
            if visitor.0.contains(GATE_REFUSAL_MARKER) {
                levels.push(*event.metadata().level());
            }
        });
    }

    // Spans are irrelevant here and deliberately not stored: this
    // subscriber is live for every test in the binary once armed.
    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
    fn enter(&self, _span: &tracing::span::Id) {}
    fn exit(&self, _span: &tracing::span::Id) {}
}

/// Install the capture (once per process) and start recording on
/// this thread.
fn arm_gate_refusal_capture() {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        tracing::subscriber::set_global_default(GateRefusalCapture)
            .expect("no other lib test may install a global tracing subscriber");
    });
    GATE_REFUSAL_LEVELS.with(|cell| *cell.borrow_mut() = Some(Vec::new()));
}

/// Stop recording on this thread and return what was seen, in order.
fn take_gate_refusal_levels() -> Vec<tracing::Level> {
    GATE_REFUSAL_LEVELS.with(|cell| {
        cell.borrow_mut()
            .take()
            .expect("capture was never armed on this thread")
    })
}

/// The first refusal logs at WARN, every one after at DEBUG —
/// asserted on the **levels themselves**, which is the half
/// [`closed_gate_warns_once_then_stays_quiet`] structurally cannot
/// reach.
///
/// The wrong implementation this kills is arms-swapped —
/// `if !flag.swap(true, ..) { debug! } else { warn! }` — which
/// leaves the latch behaving exactly as it does now and reintroduces
/// the per-packet `warn!` + journald write that `ce6f25e5` exists to
/// prevent, one packet later. Nothing else produces the sequence
/// `[WARN, DEBUG]`: both-warn, both-debug and swapped each yield a
/// different one, and a capture that silently caught nothing yields
/// an empty vec and fails rather than passing vacuously.
///
/// See [`GateRefusalCapture`] for why the subscriber is installed
/// globally rather than per-thread — the per-thread version was
/// measurably flaky, and a flaky log-capture test is worse than none.
#[tokio::test]
async fn closed_gate_logs_warn_first_then_debug() {
    arm_gate_refusal_capture();

    let upstream = Arc::new(RecordingUpstream::default());
    let handler =
        build_test_handler(Arc::clone(&upstream)).with_filter_ready(ReadinessGate::new(false));

    let first = query_handler(&handler, "example.com", RecordType::A).await;
    let second = query_handler(&handler, "example.org", RecordType::A).await;

    assert_eq!(first.rcode(), Some(ResponseCode::ServFail));
    assert_eq!(second.rcode(), Some(ResponseCode::ServFail));

    assert_eq!(
        take_gate_refusal_levels(),
        vec![tracing::Level::WARN, tracing::Level::DEBUG],
        "the FIRST refusal must warn and every one after must drop to \
         debug. Swapping the two arms keeps `gate_refusal_logged` \
         behaving identically while flooding the journal from the \
         second packet on"
    );
}
