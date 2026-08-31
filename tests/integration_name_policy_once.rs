//! F5 (incident 2026-07-27) — the queried name's policy is resolved once,
//! keeps its provenance, and reaches the sites that inspect the answer.
//!
//! ## Why these live at handler level and not next to `walk_response`
//!
//! `src/filter/cname.rs` and `src/filter/ip_filter.rs` pin the *consumption*
//! rule: given a `NamePolicy` and a `BlockSource`, which wins. They are handed
//! a policy directly, so they cannot say anything about where that policy came
//! from — and three of the four things this batch has to get right are
//! construction properties:
//!
//! 1. **The verdict is derived from allow-set hits, never from "was not
//!    blocked".** Site 1 forwards whenever a name is not blocked, which is the
//!    state nearly all traffic is in. An implementation that reused that
//!    output as the verdict would turn every forwarded query into a filter
//!    bypass, and no walker-level test can see it — patch
//!    `NamePolicy::resolve` to return `ProfileAllow` on the not-blocked path
//!    and every `cname.rs` unit test stays green while
//!    `unallowed_blocked_chain_is_still_blocked` below goes red.
//! 2. **A device-scoped allow reaches the response path at all.** That is the
//!    entire F5 defect: the allow the operator attached to `[[devices]]`
//!    landed in `DeviceOverlay.allow`, a set structurally distinct from
//!    `ResolvedProfile.allow_domains`, and nothing downstream of the
//!    pre-upstream check could see it.
//! 3. **The policy is keyed on the POST-rewrite name.** The §4.12 / §4.53
//!    rewrite hook `mem::replace`s the domain between the pre-upstream check
//!    and the response-path filters, so a policy resolved before it answers
//!    about a name no consumer will ever filter.
//!
//! The harness is the one from `tests/integration_rewrite_post_fetch_block.rs`
//! and `tests/rewrite_client_answer_shape.rs`: drive the real `ForwardHandler`
//! through `RequestHandler::handle_request`, serialize what it sends, re-parse
//! the bytes. Everything asserted is the actual wire.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use hickory_net::xfer::Protocol;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncoder};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponse;

use purge_warden::config::schema::{AdminRule, ConfigV1, Device, Id, Profile};
use purge_warden::config::settings::{CacheConfig, RewriteRule};
use purge_warden::dns::cache::DnsCache;
use purge_warden::dns::edns::EdnsClientSubnet;
use purge_warden::dns::error::DnsError;
use purge_warden::dns::handler::ForwardHandler;
use purge_warden::filter::ip_filter::IpFilter;
use purge_warden::filter::FilterEngine;
use purge_warden::lists::source_key::SourceBitMap;
use purge_warden::profiles::ProfileResolver;
use purge_warden::upstream::{Upstream, UpstreamResponse};

const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
/// The name the client queries, and the name the operator allow-lists.
const QUERIED: &str = "app.example.";
/// The CNAME target the operator denied at *profile* level.
const EVIL: &str = "evil.example.";
/// What `EVIL` resolves to — seeing this on the wire means "forwarded".
const CLEAN_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);
/// An address on the response-IP blocklist (F4 arm).
const EVIL_IP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 66);
/// Rewrite source / target for the ordering test.
const REWRITE_FROM: &str = "shop.example.";
const REWRITE_TO: &str = "tracker.example.";
/// The same target as an operator might actually spell it in TOML. The rewrite
/// builder canonicalises it, and the policy probe downstream depends on that —
/// see the `rewrite_rules` fixture below.
const REWRITE_TO_MIXED_CASE: &str = "Tracker.Example.";

// ── mock upstream ───────────────────────────────────────────────────────────

/// What the scripted upstream answers with.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// `asked CNAME evil.example` + `evil.example A 203.0.113.9` — trips the
    /// CNAME-chain walk against a profile-level deny on `evil.example`.
    ChainToEvil,
    /// `asked A 198.51.100.66` — trips the response-IP blocklist.
    BlockedIp,
}

struct ScriptedUpstream {
    calls: AtomicUsize,
    last_query_name: Mutex<Option<String>>,
    answer: Answer,
}

impl ScriptedUpstream {
    fn new(answer: Answer) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            last_query_name: Mutex::new(None),
            answer,
        }
    }
    fn last_query_name(&self) -> Option<String> {
        self.last_query_name.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl Upstream for ScriptedUpstream {
    async fn lookup(
        &self,
        name: &Name,
        _record_type: RecordType,
        _ecs: Option<EdnsClientSubnet>,
    ) -> Result<UpstreamResponse, DnsError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.last_query_name.lock().unwrap() = Some(name.to_string());

        let records = match self.answer {
            Answer::ChainToEvil => {
                let evil = Name::from_ascii(EVIL).unwrap();
                vec![
                    Record::from_rdata(name.clone(), 300, RData::CNAME(CNAME(evil.clone()))),
                    Record::from_rdata(evil, 300, RData::A(A(CLEAN_IP))),
                ]
            }
            Answer::BlockedIp => vec![Record::from_rdata(name.clone(), 300, RData::A(A(EVIL_IP)))],
        };

        Ok(UpstreamResponse {
            records,
            response_code: ResponseCode::NoError,
            soa_minimum_ttl: None,
            #[cfg(feature = "dnssec")]
            authority: Vec::new(),
        })
    }
}

// ── record-capturing response handler ───────────────────────────────────────

/// `MessageResponse`'s record iterators are private with no getters, so the
/// only way to inspect them is to emit into a `BinEncoder` and re-parse.
#[derive(Clone, Default)]
struct RecordingHandler {
    last: Arc<Mutex<Option<Message>>>,
}

impl RecordingHandler {
    fn response(&self) -> Message {
        self.last
            .lock()
            .unwrap()
            .clone()
            .expect("handler must have sent exactly one response")
    }
}

#[async_trait::async_trait]
impl ResponseHandler for RecordingHandler {
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> Result<ResponseInfo, hickory_net::NetError> {
        let mut buf = Vec::with_capacity(1024);
        let info = {
            let mut encoder = BinEncoder::new(&mut buf);
            response
                .destructive_emit(&mut encoder)
                .expect("response must serialize")
        };
        *self.last.lock().unwrap() = Some(Message::from_bytes(&buf).expect("response must parse"));
        Ok(info)
    }
}

// ── fixture ─────────────────────────────────────────────────────────────────

/// How the operator's allow (if any) is attached to the config.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Allow {
    /// No allow rule anywhere — the discriminating arm.
    None,
    /// `@@||<name>^` referenced from `[[devices]].allow_rules`. Lands in
    /// `DeviceOverlay.allow`. This is the incident's own shape.
    Device { override_profile_deny: bool },
    /// `@@||<name>^` referenced from the *profile*'s `admin_rules`. Lands in
    /// `ResolvedProfile.allow_domains`.
    Profile,
}

/// Build a resolver where:
/// - the client maps to profile `demo`,
/// - `demo` denies `evil.example` through an exact `||evil.example^` admin
///   rule (so the CNAME walker attributes the block to `BlockSource::AdminBlock`
///   — the operator's own word, the strictest input to the policy comparison),
/// - `allow` decides whether `allow_on` is allow-listed and at which layer,
/// - `rewrite` optionally installs a `REWRITE_FROM → REWRITE_TO` rule.
///
/// The `Allow::Device` arm deliberately puts the rule in the top-level
/// `[[admin_rules]]` table and references it ONLY from the device. Adding it to
/// `profile.admin_rules` would put it in `allow_domains` and the test would
/// silently stop exercising the overlay path.
fn resolver_with(allow: Allow, allow_on: &str, rewrite: bool) -> Arc<ProfileResolver> {
    let allow_name = allow_on.trim_end_matches('.');

    let mut profile = Profile {
        display_name: "demo".into(),
        admin_rules: vec![Id::new("deny-evil").unwrap()],
        ..Default::default()
    };
    if rewrite {
        profile.rewrite_rules = vec![RewriteRule {
            from: REWRITE_FROM.trim_end_matches('.').into(),
            // Deliberately MIXED CASE, while the allow rule below names the
            // lowercase form. `NamePolicy::resolve` runs on the post-rewrite
            // domain and feeds `domain_matches_set`, which `debug_assert!`s
            // lowercase-with-no-trailing-dot — so this fixture is what proves
            // the rewrite output actually satisfies that invariant rather than
            // happening to be lowercase in the config.
            //
            // `ProfileRewriteRules::build` canonicalises both `from` and `to`
            // via `config::validator::canonicalize_domain`
            // (`trim → strip trailing dot → to_ascii_lowercase`), so it does.
            // A future edit that drops that call panics this test in debug and
            // silently misses the allow in release.
            to: REWRITE_TO_MIXED_CASE.trim_end_matches('.').into(),
            match_subdomains: false,
        }];
    }
    if allow == Allow::Profile {
        profile.admin_rules.push(Id::new("allow-name").unwrap());
    }

    let mut config = ConfigV1 {
        schema_version: 1,
        ..Default::default()
    };
    config.server.allow_from = vec!["10.0.0.0/8".into()];
    config.server.default_profile = Some(Id::new("demo").unwrap());
    // `enforce_device_mac` defaults to TRUE, and under it a device pinned by
    // IP with no MAC is deliberately dropped from levels 1-3 (§4.39 /
    // s-review-2605-profiles-h1 — IP-only acceptance is ARP-spoofable). The
    // device below has no MAC, so leaving the default on makes it resolve at
    // level 5 with `device_id = None` and NO overlay — every device-scoped
    // test would then silently exercise the profile path instead. Turned off
    // the same way `profiles::resolver`'s own tests do.
    config.server.enforce_device_mac = false;
    config.admin_rules.push(AdminRule {
        id: Id::new("deny-evil").unwrap(),
        rule: format!("||{}^", EVIL.trim_end_matches('.')),
    });
    if allow != Allow::None {
        config.admin_rules.push(AdminRule {
            id: Id::new("allow-name").unwrap(),
            rule: format!("@@||{allow_name}^"),
        });
    }
    config.profiles.insert("demo".to_string(), profile);

    let (device_allow_rules, override_profile_deny) = match allow {
        Allow::Device {
            override_profile_deny,
        } => (vec![Id::new("allow-name").unwrap()], override_profile_deny),
        _ => (vec![], false),
    };
    config.devices.push(Device {
        id: Id::new("test-dev").unwrap(),
        display_name: "test".into(),
        ip: Some(IpAddr::V4(CLIENT_IP)),
        mac: None,
        mac_aliases: vec![],
        profile: Some(Id::new("demo").unwrap()),
        groups: vec![],
        owner: None,
        device_type: None,
        department: None,
        notes: None,
        allow_rules: device_allow_rules,
        deny_rules: vec![],
        override_profile_deny,
        unfiltered: false,
        network_name: None,
        network_name_wildcard: false,
    });

    Arc::new(ProfileResolver::build(
        &config,
        &SourceBitMap::default(),
        &purge_warden::config::custom_list::CustomListStore::new(),
    ))
}

fn handler_with(
    upstream: Arc<ScriptedUpstream>,
    resolver: Arc<ProfileResolver>,
    ip_filter: Option<Arc<IpFilter>>,
) -> ForwardHandler {
    ForwardHandler::new(
        upstream,
        Arc::new(FilterEngine::new()),
        DnsCache::new(&CacheConfig::default()),
        Some(resolver),
        None,
        None,
        None,
        ip_filter,
        None, // allow_from: accept every source
        60,
        None, // prefetch disabled — it would spawn a second upstream call
        0.0,
        16,
    )
}

fn ip_filter_blocking(ip: Ipv4Addr) -> Arc<IpFilter> {
    let mut set = std::collections::HashSet::with_hasher(ahash::RandomState::new());
    set.insert(IpAddr::V4(ip));
    Arc::new(IpFilter::with_ips(set))
}

fn request_for(qname: &str) -> Request {
    let mut msg = Message::new(0x1234, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(
        Name::from_ascii(qname).unwrap(),
        RecordType::A,
    ));
    let bytes = msg.to_vec().unwrap();
    let src = SocketAddr::new(IpAddr::V4(CLIENT_IP), 40000);
    Request::from_bytes(bytes, src, Protocol::Udp).unwrap()
}

async fn query(handler: &ForwardHandler, qname: &str) -> Message {
    let recorder = RecordingHandler::default();
    // 0.26 added the `T: Time` generic to handle_request; it's unused in the
    // arguments, so a direct call must name it. TokioTime is the only impl.
    handler
        .handle_request::<_, hickory_server::net::runtime::TokioTime>(
            &request_for(qname),
            recorder.clone(),
        )
        .await;
    recorder.response()
}

// ── assertions ──────────────────────────────────────────────────────────────

fn a_ips(response: &Message) -> Vec<Ipv4Addr> {
    response
        .answers
        .iter()
        .filter_map(|rr| match &rr.data {
            RData::A(A(ip)) => Some(*ip),
            _ => None,
        })
        .collect()
}

/// A canned block answers with the profile's `block_response` (default `zero`),
/// i.e. exactly one `A 0.0.0.0` owned by the question name.
///
/// Asserted on the address rather than on the answer count: when a rewrite
/// fires, the forwarded answer additionally carries the synthesized
/// `original CNAME target` bridge record (`prepend_rewrite_cname`), so counting
/// records would be brittle for reasons that have nothing to do with policy.
fn assert_blocked(response: &Message, why: &str) {
    assert_eq!(
        a_ips(response),
        vec![Ipv4Addr::UNSPECIFIED],
        "{why}: expected the canned 0.0.0.0 block, got answers {:?}",
        response.answers
    );
}

fn assert_forwarded(response: &Message, expect_ip: Ipv4Addr, why: &str) {
    assert_eq!(
        response.metadata.response_code,
        ResponseCode::NoError,
        "{why}: expected NOERROR"
    );
    let ips = a_ips(response);
    assert!(
        !ips.contains(&Ipv4Addr::UNSPECIFIED),
        "{why}: the answer carries the canned 0.0.0.0 block — the operator's \
         allow did not reach the response path. Answers: {:?}",
        response.answers
    );
    assert!(
        ips.contains(&expect_ip),
        "{why}: expected the upstream address {expect_ip} on the wire, got {ips:?}"
    );
}

// ── 0. fixture guards ───────────────────────────────────────────────────────

/// Without this, every `Allow::Device` test below could pass or fail for
/// reasons that have nothing to do with the policy plumbing — a rule shape the
/// overlay builder skips, an id that does not resolve, a device that never
/// matches. It asserts the fixture puts the allow in `DeviceOverlay.allow` and
/// **not** in `ResolvedProfile.allow_domains`, which is precisely the
/// structural split the incident turned on.
#[test]
fn fixture_guard_device_allow_lands_in_the_overlay_not_the_profile() {
    let resolver = resolver_with(
        Allow::Device {
            override_profile_deny: true,
        },
        QUERIED,
        false,
    );
    let resolution = resolver.resolve(&IpAddr::V4(CLIENT_IP));
    let name = QUERIED.trim_end_matches('.');

    let overlay = resolution
        .overlay
        .as_ref()
        .expect("the device references an allow rule, so it must carry an overlay");
    assert!(
        overlay.allow.contains(name),
        "the device's allow rule must land in DeviceOverlay.allow; got {:?}",
        overlay.allow
    );
    assert!(
        overlay.override_profile_deny,
        "the device's override_profile_deny must survive into the overlay"
    );

    let profile = resolution
        .profile
        .as_ref()
        .expect("the client must resolve to the demo profile");
    assert!(
        !profile.allow_domains.contains(name),
        "fixture guard: the allow must NOT also be profile-scoped, otherwise the \
         Allow::Device tests stop exercising the overlay path"
    );
}

/// The profile arm of the same guard.
#[test]
fn fixture_guard_profile_allow_lands_in_allow_domains() {
    let resolver = resolver_with(Allow::Profile, QUERIED, false);
    let resolution = resolver.resolve(&IpAddr::V4(CLIENT_IP));
    let profile = resolution.profile.as_ref().expect("profile must resolve");
    assert!(profile
        .allow_domains
        .contains(QUERIED.trim_end_matches('.')));
}

// ── 1. the discriminator ────────────────────────────────────────────────────

/// **Write this one first and keep it first.** No allow rule anywhere; the
/// chain terminates on a name the profile denies. Must block.
///
/// This is what fails against an implementation that derives the verdict from
/// "the pre-upstream check did not block" instead of from an allow-set hit —
/// `app.example` is not blocked pre-upstream (only `evil.example` is denied),
/// so such an implementation would report an allow here and forward a chain
/// the operator denied. Verified by construction: see NOTES-name-policy.md.
#[tokio::test]
async fn unallowed_blocked_chain_is_still_blocked() {
    let upstream = Arc::new(ScriptedUpstream::new(Answer::ChainToEvil));
    let handler = handler_with(
        upstream.clone(),
        resolver_with(Allow::None, QUERIED, false),
        None,
    );

    let response = query(&handler, QUERIED).await;

    assert_eq!(
        upstream.last_query_name().as_deref(),
        Some(QUERIED),
        "the query must have been forwarded — otherwise there is no chain to walk"
    );
    assert_blocked(
        &response,
        "no allow rule exists, so the CNAME chain into a profile-denied name must block",
    );
}

/// Same, IP-blocklist arm.
#[tokio::test]
async fn unallowed_blocked_ip_is_still_blocked() {
    let upstream = Arc::new(ScriptedUpstream::new(Answer::BlockedIp));
    let handler = handler_with(
        upstream.clone(),
        resolver_with(Allow::None, QUERIED, false),
        Some(ip_filter_blocking(EVIL_IP)),
    );

    let response = query(&handler, QUERIED).await;

    assert_blocked(
        &response,
        "no allow rule exists, so an answer inside a blocked IP range must block",
    );
}

// ── 2. the device-scoped allow reaches the response path ────────────────────

/// **The reported incident, end to end.** The operator attached the allow to
/// the device (`[[devices]].allow_rules`), which lands in
/// `DeviceOverlay.allow` — the set the CNAME walker could not see. With
/// `override_profile_deny = true` the device is entitled to beat the profile's
/// own deny, so the answer must be forwarded.
///
/// Pre-fix this returns the canned 0.0.0.0: the pre-upstream check honours the
/// device allow (which is why the query is forwarded at all), and the walker
/// then blocks on a set the allow never entered.
#[tokio::test]
async fn device_allow_with_override_survives_the_cname_walk() {
    let upstream = Arc::new(ScriptedUpstream::new(Answer::ChainToEvil));
    let handler = handler_with(
        upstream.clone(),
        resolver_with(
            Allow::Device {
                override_profile_deny: true,
            },
            QUERIED,
            false,
        ),
        None,
    );

    let response = query(&handler, QUERIED).await;

    assert_forwarded(
        &response,
        CLEAN_IP,
        "a device-scoped allow with override_profile_deny must reach the CNAME walker",
    );
}

/// **Trappola 1 at handler level.** Identical fixture, `override_profile_deny
/// = false`. `apply_overlay` row 6 refuses to let a device allow beat a
/// profile deny without that flag *for the queried name*; the response path
/// must give the same answer, or the weaker layer overrules the stronger one
/// hop later.
///
/// A two-state (`allowed` / `neutral`) verdict passes the test above and fails
/// this one.
#[tokio::test]
async fn device_allow_without_override_still_loses_to_a_profile_deny() {
    let upstream = Arc::new(ScriptedUpstream::new(Answer::ChainToEvil));
    let handler = handler_with(
        upstream.clone(),
        resolver_with(
            Allow::Device {
                override_profile_deny: false,
            },
            QUERIED,
            false,
        ),
        None,
    );

    let response = query(&handler, QUERIED).await;

    assert_blocked(
        &response,
        "apply_overlay row 6: a device allow must not sink a profile-level deny \
         without override_profile_deny",
    );
}

/// F4: the response-IP blocklist carries no attribution, so it ranks with an
/// external domain list — a device allow beats it even with
/// `override_profile_deny = false`, because there is no profile deny in play
/// for that flag to guard.
#[tokio::test]
async fn device_allow_survives_the_response_ip_blocklist() {
    let upstream = Arc::new(ScriptedUpstream::new(Answer::BlockedIp));
    let handler = handler_with(
        upstream.clone(),
        resolver_with(
            Allow::Device {
                override_profile_deny: false,
            },
            QUERIED,
            false,
        ),
        Some(ip_filter_blocking(EVIL_IP)),
    );

    let response = query(&handler, QUERIED).await;

    assert_forwarded(
        &response,
        EVIL_IP,
        "F4: an explicit allow on the queried name must suppress the IP blocklist",
    );
}

/// Lane A non-regression: a *profile*-scoped allow is same-layer with the
/// profile deny and wins without needing any flag.
#[tokio::test]
async fn profile_allow_survives_the_cname_walk() {
    let upstream = Arc::new(ScriptedUpstream::new(Answer::ChainToEvil));
    let handler = handler_with(
        upstream.clone(),
        resolver_with(Allow::Profile, QUERIED, false),
        None,
    );

    let response = query(&handler, QUERIED).await;

    assert_forwarded(
        &response,
        CLEAN_IP,
        "a profile-scoped allow on the queried name must win the chain (Lane A)",
    );
}

// ── 3. Trappola 2 — the policy is keyed on the POST-rewrite name ────────────

/// **The ordering pin.** The profile rewrites `shop.example → tracker.example`
/// and allows `tracker.example`. The client asks for `shop.example`.
///
/// `handle_inner` `mem::replace`s the domain at the rewrite hook, so the two
/// names in play differ: the pre-upstream filter check ran against
/// `shop.example`, while `walk_response` and the IP filter below run against
/// `tracker.example`. The policy must be resolved on the latter — the name its
/// consumers actually filter.
///
/// A verdict computed *before* the rewrite hook resolves `shop.example`, finds
/// no allow (the rule names `tracker.example`), and blocks. That is a live
/// regression on any deployment with a rewrite rule, and `safe_search = true`
/// alone populates eight of them.
#[tokio::test]
async fn policy_is_resolved_on_the_post_rewrite_name() {
    let upstream = Arc::new(ScriptedUpstream::new(Answer::ChainToEvil));
    let handler = handler_with(
        upstream.clone(),
        resolver_with(Allow::Profile, REWRITE_TO, true),
        None,
    );

    let response = query(&handler, REWRITE_FROM).await;

    assert_eq!(
        upstream.last_query_name().as_deref(),
        Some(REWRITE_TO),
        "the rewrite must have fired — otherwise the pre- and post-rewrite names \
         coincide and this test cannot observe the ordering it guards"
    );
    assert_forwarded(
        &response,
        CLEAN_IP,
        "the allow names the REWRITE TARGET, which is the name the response-path \
         filters see; a policy resolved before the rewrite hook keys on \
         `shop.example`, finds nothing, and blocks",
    );
}

/// The discriminating twin of the test above: same rewrite, allow moved onto
/// the *pre*-rewrite name. Nothing allows `tracker.example`, so the chain
/// blocks. Without this, `policy_is_resolved_on_the_post_rewrite_name` would
/// also pass against an implementation that consults BOTH names.
#[tokio::test]
async fn an_allow_on_the_pre_rewrite_name_does_not_carry_to_the_target() {
    let upstream = Arc::new(ScriptedUpstream::new(Answer::ChainToEvil));
    let handler = handler_with(
        upstream.clone(),
        resolver_with(Allow::Profile, REWRITE_FROM, true),
        None,
    );

    let response = query(&handler, REWRITE_FROM).await;

    assert_eq!(
        upstream.last_query_name().as_deref(),
        Some(REWRITE_TO),
        "the rewrite must have fired"
    );
    assert_blocked(
        &response,
        "the allow names the pre-rewrite name; the response path filters the \
         target, which nothing allows",
    );
}
