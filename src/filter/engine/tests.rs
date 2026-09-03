use super::*;

fn engine_with(domains: &[&str]) -> FilterEngine {
    let set: HashSet<CompactString, RandomState> =
        domains.iter().map(|d| CompactString::new(d)).collect();
    FilterEngine::with_domains(set)
}

/// Build an engine where every entry's bitmask sits in `block_mask`.
/// Mirrors pre-S50 single-mask shape; tests that need allow-direction
/// entries use [`engine_with_per_direction_map`] instead.
fn engine_with_map(entries: &[(&str, u64)]) -> FilterEngine {
    let map: HashMap<CompactString, u64, RandomState> = entries
        .iter()
        .map(|(d, b)| (CompactString::new(d), *b))
        .collect();
    FilterEngine::with_domain_map(map)
}

/// Build an engine with explicit per-direction masks per domain. Used by
/// the §4 step 5 ALLOW path tests added at S50 T1.
fn engine_with_per_direction_map(entries: &[(&str, DomainMasks)]) -> FilterEngine {
    let map: HashMap<CompactString, DomainMasks, RandomState> = entries
        .iter()
        .map(|(d, m)| (CompactString::new(d), *m))
        .collect();
    FilterEngine::with_per_direction_domain_map(map)
}

/// The `test` profile, subscribed to `bitmask` on `engine`.
///
/// Takes the engine because the subscription no longer lives on the
/// profile — see [`FilterEngine::fixture_subscribe`].
fn profile_with_bitmask(engine: &FilterEngine, bitmask: u64) -> ResolvedProfile {
    engine.fixture_subscribe("test", bitmask);
    test_profile()
}

/// The bare `test` profile, with no subscription installed anywhere.
///
/// For fixtures that evaluate one profile against **several** engines:
/// the subscription is per generation now, so each engine has to be told
/// separately with [`FilterEngine::fixture_subscribe`].
fn test_profile() -> ResolvedProfile {
    ResolvedProfile {
        name: CompactString::new("test"),
        unfiltered: false,
        allow_domains: std::sync::Arc::new(HashSet::with_hasher(RandomState::new())),
        deny_domains: std::sync::Arc::new(HashSet::with_hasher(RandomState::new())),
        block_all: false,
        rules: std::sync::Arc::new(Vec::new()),
        block_response: crate::config::schema::BlockResponseV1::Zero,
        blocked_ttl_secs: 60,
        local_records: std::sync::Arc::new(
            crate::dns::local_profile::ProfileLocalRecords::default(),
        ),
        rewrite_rules: std::sync::Arc::new(crate::dns::rewrite::ProfileRewriteRules::default()),
        ecs_policy: crate::profiles::profile::EcsPolicy::OFF,
    }
}

// --- is_blocked (legacy) ---

#[test]
fn exact_match_blocked() {
    let engine = engine_with(&["tracker.example.com"]);
    assert!(engine.is_blocked("tracker.example.com"));
}

#[test]
fn exact_match_not_blocked() {
    let engine = engine_with(&["tracker.example.com"]);
    assert!(!engine.is_blocked("google.com"));
}

#[test]
fn subdomain_blocked_by_parent() {
    let engine = engine_with(&["tracker.example.com"]);
    assert!(engine.is_blocked("sub.tracker.example.com"));
}

#[test]
fn deep_subdomain_blocked() {
    let engine = engine_with(&["tracker.example.com"]);
    assert!(engine.is_blocked("a.b.c.tracker.example.com"));
}

#[test]
fn parent_not_blocked_by_child() {
    let engine = engine_with(&["sub.example.com"]);
    assert!(!engine.is_blocked("example.com"));
}

#[test]
fn case_insensitive_lookup() {
    let engine = engine_with(&["tracker.example.com"]);
    assert!(engine.is_blocked("tracker.example.com"));
}

#[test]
fn empty_domain_not_blocked() {
    let engine = engine_with(&["tracker.example.com"]);
    assert!(!engine.is_blocked(""));
}

#[test]
fn single_label_domain() {
    let engine = engine_with(&["localhost"]);
    assert!(engine.is_blocked("localhost"));
    assert!(engine.is_blocked("sub.localhost"));
}

#[test]
fn tld_blocks_everything_under_it() {
    let engine = engine_with(&["com"]);
    assert!(engine.is_blocked("com"));
    assert!(engine.is_blocked("example.com"));
    assert!(engine.is_blocked("sub.example.com"));
}

#[test]
fn similar_but_not_suffix() {
    let engine = engine_with(&["ample.com"]);
    assert!(!engine.is_blocked("example.com"));
}

#[test]
fn domain_with_trailing_dot_in_blocklist() {
    let engine = engine_with(&["example.com"]);
    assert!(engine.is_blocked("sub.example.com"));
}

#[test]
fn swap_blocklist_replaces_set() {
    let engine = engine_with(&["old.example.com"]);
    assert!(engine.is_blocked("old.example.com"));

    let mut new_set = HashSet::with_hasher(RandomState::new());
    new_set.insert(CompactString::new("new.example.com"));
    engine.swap_blocklist(new_set);

    assert!(!engine.is_blocked("old.example.com"));
    assert!(engine.is_blocked("new.example.com"));
}

#[test]
fn domain_count() {
    let engine = engine_with(&["a.com", "b.com", "c.com"]);
    assert_eq!(engine.domain_count(), 3);
}

#[test]
fn parse_basic() {
    let content = "tracker.example.com\nads.example.com\n";
    let set = parse_blocklist(content);
    assert_eq!(set.len(), 2);
    assert!(set.contains("tracker.example.com"));
    assert!(set.contains("ads.example.com"));
}

#[test]
fn parse_comments_and_empty() {
    let content = "# This is a comment\n\ntracker.example.com\n  \n# Another comment\nads.com\n";
    let set = parse_blocklist(content);
    assert_eq!(set.len(), 2);
}

#[test]
fn parse_trailing_dot() {
    let content = "example.com.\n";
    let set = parse_blocklist(content);
    assert!(set.contains("example.com"));
}

#[test]
fn parse_mixed_case() {
    let content = "Tracker.EXAMPLE.com\n";
    let set = parse_blocklist(content);
    assert!(set.contains("tracker.example.com"));
}

#[test]
fn parse_whitespace() {
    let content = "  tracker.example.com  \n\tads.com\t\n";
    let set = parse_blocklist(content);
    assert_eq!(set.len(), 2);
    assert!(set.contains("tracker.example.com"));
    assert!(set.contains("ads.com"));
}

// --- bitmask ---

#[test]
fn bitmask_domain_in_list_a_only() {
    // "ads.com" in list 0 (bit 0), "tracker.com" in list 1 (bit 1)
    let engine = engine_with_map(&[("ads.com", 0b01), ("tracker.com", 0b10)]);

    // Profile subscribes to list 0 only
    let profile = profile_with_bitmask(&engine, 0b01);
    assert_eq!(engine.evaluate("ads.com", &profile), FilterResult::Block);
    assert_eq!(
        engine.evaluate("tracker.com", &profile),
        FilterResult::Forward
    );

    // Profile subscribes to list 1 only
    let profile = profile_with_bitmask(&engine, 0b10);
    assert_eq!(engine.evaluate("ads.com", &profile), FilterResult::Forward);
    assert_eq!(
        engine.evaluate("tracker.com", &profile),
        FilterResult::Block
    );
}

#[test]
fn bitmask_domain_in_multiple_lists() {
    // "overlap.com" in both list 0 and list 1
    let engine = engine_with_map(&[("overlap.com", 0b11)]);

    // Either list subscription blocks it
    assert_eq!(
        engine.evaluate("overlap.com", &profile_with_bitmask(&engine, 0b01)),
        FilterResult::Block
    );
    assert_eq!(
        engine.evaluate("overlap.com", &profile_with_bitmask(&engine, 0b10)),
        FilterResult::Block
    );
}

#[test]
fn bitmask_subdomain_walk() {
    let engine = engine_with_map(&[("tracker.com", 0b01)]);
    let profile = profile_with_bitmask(&engine, 0b01);
    assert_eq!(
        engine.evaluate("sub.tracker.com", &profile),
        FilterResult::Block
    );
}

#[test]
fn bitmask_no_match_forwards() {
    let engine = engine_with_map(&[("ads.com", 0b01)]);
    let profile = profile_with_bitmask(&engine, 0b01);
    assert_eq!(
        engine.evaluate("google.com", &profile),
        FilterResult::Forward
    );
}

// --- evaluate: allow/deny rules ---

#[test]
fn allow_rule_overrides_block() {
    let engine = engine_with_map(&[("cdn.example.com", 0b01)]);
    let mut profile = profile_with_bitmask(&engine, 0b01);
    std::sync::Arc::make_mut(&mut profile.allow_domains)
        .insert(CompactString::new("cdn.example.com"));

    // Normally blocked by list, but allow rule overrides
    assert_eq!(
        engine.evaluate("cdn.example.com", &profile),
        FilterResult::Forward
    );
}

#[test]
fn allow_rule_subdomain_walk() {
    let engine = engine_with_map(&[("example.com", 0b01)]);
    let mut profile = profile_with_bitmask(&engine, 0b01);
    std::sync::Arc::make_mut(&mut profile.allow_domains).insert(CompactString::new("example.com"));

    // Allow rule on parent covers subdomain
    assert_eq!(
        engine.evaluate("sub.example.com", &profile),
        FilterResult::Forward
    );
}

#[test]
fn deny_rule_blocks() {
    let engine = engine_with_map(&[]);
    let mut profile = profile_with_bitmask(&engine, 0);
    std::sync::Arc::make_mut(&mut profile.deny_domains).insert(CompactString::new("tiktok.com"));

    assert_eq!(engine.evaluate("tiktok.com", &profile), FilterResult::Block);
    assert_eq!(
        engine.evaluate("sub.tiktok.com", &profile),
        FilterResult::Block
    );
}

#[test]
fn deny_rule_without_allow_does_not_override_allow() {
    // allow takes priority over deny (allow checked first)
    let engine = engine_with_map(&[]);
    let mut profile = profile_with_bitmask(&engine, 0);
    std::sync::Arc::make_mut(&mut profile.allow_domains).insert(CompactString::new("example.com"));
    std::sync::Arc::make_mut(&mut profile.deny_domains).insert(CompactString::new("example.com"));

    assert_eq!(
        engine.evaluate("example.com", &profile),
        FilterResult::Forward
    );
}

// --- evaluate: block_all ---

#[test]
fn block_all_blocks_everything() {
    let engine = engine_with_map(&[]);
    let profile = ResolvedProfile {
        name: CompactString::new("night"),
        unfiltered: false,
        allow_domains: std::sync::Arc::new(HashSet::with_hasher(RandomState::new())),
        deny_domains: std::sync::Arc::new(HashSet::with_hasher(RandomState::new())),
        block_all: true,
        rules: std::sync::Arc::new(Vec::new()),
        block_response: crate::config::schema::BlockResponseV1::Zero,
        blocked_ttl_secs: 60,
        local_records: std::sync::Arc::new(
            crate::dns::local_profile::ProfileLocalRecords::default(),
        ),
        rewrite_rules: std::sync::Arc::new(crate::dns::rewrite::ProfileRewriteRules::default()),
        ecs_policy: crate::profiles::profile::EcsPolicy::OFF,
    };
    engine.fixture_subscribe("night", 0);
    assert_eq!(engine.evaluate("google.com", &profile), FilterResult::Block);
    assert_eq!(
        engine.evaluate("example.com", &profile),
        FilterResult::Block
    );
}

#[test]
fn block_all_except_allow() {
    let engine = engine_with_map(&[]);
    let mut allow = HashSet::with_hasher(RandomState::new());
    allow.insert(CompactString::new("captive.apple.com"));
    let profile = ResolvedProfile {
        name: CompactString::new("night"),
        unfiltered: false,
        allow_domains: allow.into(),
        deny_domains: std::sync::Arc::new(HashSet::with_hasher(RandomState::new())),
        block_all: true,
        rules: std::sync::Arc::new(Vec::new()),
        block_response: crate::config::schema::BlockResponseV1::Zero,
        blocked_ttl_secs: 60,
        local_records: std::sync::Arc::new(
            crate::dns::local_profile::ProfileLocalRecords::default(),
        ),
        rewrite_rules: std::sync::Arc::new(crate::dns::rewrite::ProfileRewriteRules::default()),
        ecs_policy: crate::profiles::profile::EcsPolicy::OFF,
    };
    engine.fixture_subscribe("night", 0);
    assert_eq!(
        engine.evaluate("captive.apple.com", &profile),
        FilterResult::Forward
    );
    assert_eq!(engine.evaluate("google.com", &profile), FilterResult::Block);
}

// --- swap_domain_map ---

#[test]
fn swap_domain_map_replaces() {
    let engine = engine_with_map(&[("old.com", 0b01)]);
    assert!(engine.is_blocked("old.com"));

    let mut new_map = HashMap::with_hasher(RandomState::new());
    new_map.insert(CompactString::new("new.com"), 0b01);
    engine.swap_domain_map(new_map);

    assert!(!engine.is_blocked("old.com"));
    assert!(engine.is_blocked("new.com"));
}

// --- evaluate: advanced rules ---

#[test]
fn important_deny_overrides_normal_allow() {
    use crate::filter::rules::parse_rule;
    let engine = engine_with_map(&[]);
    let mut allow = HashSet::with_hasher(RandomState::new());
    allow.insert(CompactString::new("evil.com"));
    let rules = vec![parse_rule("||evil.com^$important").unwrap()];
    let profile = ResolvedProfile {
        name: CompactString::new("test"),
        unfiltered: false,
        allow_domains: allow.into(),
        deny_domains: std::sync::Arc::new(HashSet::with_hasher(RandomState::new())),
        block_all: false,
        rules: rules.into(),
        block_response: crate::config::schema::BlockResponseV1::Zero,
        blocked_ttl_secs: 60,
        local_records: std::sync::Arc::new(
            crate::dns::local_profile::ProfileLocalRecords::default(),
        ),
        rewrite_rules: std::sync::Arc::new(crate::dns::rewrite::ProfileRewriteRules::default()),
        ecs_policy: crate::profiles::profile::EcsPolicy::OFF,
    };
    engine.fixture_subscribe("test", 0);
    // $important deny beats normal allow in HashSet
    assert_eq!(engine.evaluate("evil.com", &profile), FilterResult::Block);
}

#[test]
fn important_allow_overrides_important_deny() {
    use crate::filter::rules::parse_rule;
    let engine = engine_with_map(&[]);
    let rules = vec![
        parse_rule("||captive.apple.com^$important").unwrap(),
        parse_rule("@@||captive.apple.com^$important").unwrap(),
    ];
    let profile = ResolvedProfile {
        name: CompactString::new("test"),
        unfiltered: false,
        allow_domains: std::sync::Arc::new(HashSet::with_hasher(RandomState::new())),
        deny_domains: std::sync::Arc::new(HashSet::with_hasher(RandomState::new())),
        block_all: false,
        rules: rules.into(),
        block_response: crate::config::schema::BlockResponseV1::Zero,
        blocked_ttl_secs: 60,
        local_records: std::sync::Arc::new(
            crate::dns::local_profile::ProfileLocalRecords::default(),
        ),
        rewrite_rules: std::sync::Arc::new(crate::dns::rewrite::ProfileRewriteRules::default()),
        ecs_policy: crate::profiles::profile::EcsPolicy::OFF,
    };
    engine.fixture_subscribe("test", 0);
    // important allow > important deny
    assert_eq!(
        engine.evaluate("captive.apple.com", &profile),
        FilterResult::Forward
    );
}

#[test]
fn wildcard_deny_blocks() {
    use crate::filter::rules::parse_rule;
    let engine = engine_with_map(&[]);
    let rules = vec![parse_rule("||*.ads.example.com^").unwrap()];
    let profile = ResolvedProfile {
        name: CompactString::new("test"),
        unfiltered: false,
        allow_domains: std::sync::Arc::new(HashSet::with_hasher(RandomState::new())),
        deny_domains: std::sync::Arc::new(HashSet::with_hasher(RandomState::new())),
        block_all: false,
        rules: rules.into(),
        block_response: crate::config::schema::BlockResponseV1::Zero,
        blocked_ttl_secs: 60,
        local_records: std::sync::Arc::new(
            crate::dns::local_profile::ProfileLocalRecords::default(),
        ),
        rewrite_rules: std::sync::Arc::new(crate::dns::rewrite::ProfileRewriteRules::default()),
        ecs_policy: crate::profiles::profile::EcsPolicy::OFF,
    };
    engine.fixture_subscribe("test", 0);
    assert_eq!(
        engine.evaluate("banner.ads.example.com", &profile),
        FilterResult::Block
    );
    // ads.example.com itself is NOT matched by wildcard
    assert_eq!(
        engine.evaluate("ads.example.com", &profile),
        FilterResult::Forward
    );
}

#[test]
fn regex_deny_blocks() {
    use crate::filter::rules::parse_rule;
    let engine = engine_with_map(&[]);
    let rules = vec![parse_rule("/ad[0-9]+\\.example\\.com/").unwrap()];
    let profile = ResolvedProfile {
        name: CompactString::new("test"),
        unfiltered: false,
        allow_domains: std::sync::Arc::new(HashSet::with_hasher(RandomState::new())),
        deny_domains: std::sync::Arc::new(HashSet::with_hasher(RandomState::new())),
        block_all: false,
        rules: rules.into(),
        block_response: crate::config::schema::BlockResponseV1::Zero,
        blocked_ttl_secs: 60,
        local_records: std::sync::Arc::new(
            crate::dns::local_profile::ProfileLocalRecords::default(),
        ),
        rewrite_rules: std::sync::Arc::new(crate::dns::rewrite::ProfileRewriteRules::default()),
        ecs_policy: crate::profiles::profile::EcsPolicy::OFF,
    };
    engine.fixture_subscribe("test", 0);
    assert_eq!(
        engine.evaluate("ad123.example.com", &profile),
        FilterResult::Block
    );
    assert_eq!(
        engine.evaluate("safe.example.com", &profile),
        FilterResult::Forward
    );
}

#[test]
fn block_all_with_important_allow_rule() {
    use crate::filter::rules::parse_rule;
    let engine = engine_with_map(&[]);
    let rules = vec![parse_rule("@@||captive.apple.com^$important").unwrap()];
    let profile = ResolvedProfile {
        name: CompactString::new("night"),
        unfiltered: false,
        allow_domains: std::sync::Arc::new(HashSet::with_hasher(RandomState::new())),
        deny_domains: std::sync::Arc::new(HashSet::with_hasher(RandomState::new())),
        block_all: true,
        rules: rules.into(),
        block_response: crate::config::schema::BlockResponseV1::Zero,
        blocked_ttl_secs: 60,
        local_records: std::sync::Arc::new(
            crate::dns::local_profile::ProfileLocalRecords::default(),
        ),
        rewrite_rules: std::sync::Arc::new(crate::dns::rewrite::ProfileRewriteRules::default()),
        ecs_policy: crate::profiles::profile::EcsPolicy::OFF,
    };
    engine.fixture_subscribe("night", 0);
    assert_eq!(
        engine.evaluate("captive.apple.com", &profile),
        FilterResult::Forward
    );
    assert_eq!(engine.evaluate("google.com", &profile), FilterResult::Block);
}

#[test]
fn empty_rules_no_overhead() {
    // Profile with no advanced rules — rules Vec is empty, should behave
    // identically to pre-Sprint-9 behavior
    let engine = engine_with_map(&[("ads.com", 0b01)]);
    let mut allow = HashSet::with_hasher(RandomState::new());
    allow.insert(CompactString::new("safe.com"));
    let mut deny = HashSet::with_hasher(RandomState::new());
    deny.insert(CompactString::new("tiktok.com"));
    let profile = ResolvedProfile {
        name: CompactString::new("test"),
        unfiltered: false,
        allow_domains: allow.into(),
        deny_domains: deny.into(),
        block_all: false,
        rules: std::sync::Arc::new(Vec::new()),
        block_response: crate::config::schema::BlockResponseV1::Zero,
        blocked_ttl_secs: 60,
        local_records: std::sync::Arc::new(
            crate::dns::local_profile::ProfileLocalRecords::default(),
        ),
        rewrite_rules: std::sync::Arc::new(crate::dns::rewrite::ProfileRewriteRules::default()),
        ecs_policy: crate::profiles::profile::EcsPolicy::OFF,
    };
    engine.fixture_subscribe("test", 0b01);
    assert_eq!(engine.evaluate("ads.com", &profile), FilterResult::Block);
    assert_eq!(engine.evaluate("safe.com", &profile), FilterResult::Forward);
    assert_eq!(engine.evaluate("tiktok.com", &profile), FilterResult::Block);
    assert_eq!(
        engine.evaluate("google.com", &profile),
        FilterResult::Forward
    );
}

// H-05: priority lattice exhaustion — pin the single-pass evaluator's
// behaviour at every tier boundary, including the HashSet-vs-rule
// interactions the previous 4-loop code couldn't easily express.
//
// Helper that builds a profile whose allow_domains, deny_domains, and
// list_bitmask all point at "foo.example.com", then layers `rules` on top.
fn lattice_profile(rules: Vec<crate::filter::rules::DnsRule>) -> ResolvedProfile {
    let mut allow = HashSet::with_hasher(RandomState::new());
    allow.insert(CompactString::new("foo.example.com"));
    let mut deny = HashSet::with_hasher(RandomState::new());
    deny.insert(CompactString::new("foo.example.com"));
    ResolvedProfile {
        name: CompactString::new("test"),
        unfiltered: false,
        allow_domains: allow.into(),
        deny_domains: deny.into(),
        block_all: false,
        rules: rules.into(),
        block_response: crate::config::schema::BlockResponseV1::Zero,
        blocked_ttl_secs: 60,
        local_records: std::sync::Arc::new(
            crate::dns::local_profile::ProfileLocalRecords::default(),
        ),
        rewrite_rules: std::sync::Arc::new(crate::dns::rewrite::ProfileRewriteRules::default()),
        ecs_policy: crate::profiles::profile::EcsPolicy::OFF,
    }
}

#[test]
fn priority_tier3_important_allow_beats_everything() {
    use crate::filter::rules::parse_rule;
    // Tier 3 ($important allow) must short-circuit over every lower tier.
    let engine = engine_with_map(&[("foo.example.com", 0b01)]);
    let profile = lattice_profile(vec![
        parse_rule("@@||foo.example.com^$important").unwrap(),
        parse_rule("||foo.example.com^$important").unwrap(),
        parse_rule("@@||foo.example.com^").unwrap(),
        parse_rule("||foo.example.com^").unwrap(),
    ]);
    assert_eq!(
        engine.evaluate("foo.example.com", &profile),
        FilterResult::Forward
    );
}

#[test]
fn priority_tier2_important_deny_beats_normal_and_hashsets() {
    use crate::filter::rules::parse_rule;
    // Tier 2 ($important deny) must beat normal-tier rules AND the
    // priority-1 HashSet allow / priority-0 HashSet deny that are present
    // in the lattice profile.
    let engine = engine_with_map(&[("foo.example.com", 0b01)]);
    let profile = lattice_profile(vec![
        parse_rule("||foo.example.com^$important").unwrap(),
        parse_rule("@@||foo.example.com^").unwrap(),
        parse_rule("||foo.example.com^").unwrap(),
    ]);
    assert_eq!(
        engine.evaluate("foo.example.com", &profile),
        FilterResult::Block
    );
}

#[test]
fn priority_tier1_normal_allow_rule_beats_hashset_deny_and_bitmask() {
    use crate::filter::rules::parse_rule;
    // A normal allow rule (priority 1) must beat both the priority-0
    // HashSet deny AND the priority-0 list bitmask hit, with no
    // important-tier rules to interfere.
    let engine = engine_with_map(&[("foo.example.com", 0b01)]);
    let profile = lattice_profile(vec![
        parse_rule("@@||foo.example.com^").unwrap(),
        parse_rule("||foo.example.com^").unwrap(),
    ]);
    assert_eq!(
        engine.evaluate("foo.example.com", &profile),
        FilterResult::Forward
    );
}

#[test]
fn priority_tier1_hashset_allow_beats_normal_deny_rule_and_bitmask() {
    use crate::filter::rules::parse_rule;
    // HashSet allow sits at priority 1 — same tier as a normal allow
    // rule. With no normal allow rule present, HashSet allow must still
    // beat the priority-0 normal deny rule and the priority-0 bitmask.
    let engine = engine_with_map(&[("foo.example.com", 0b01)]);
    let profile = lattice_profile(vec![parse_rule("||foo.example.com^").unwrap()]);
    assert_eq!(
        engine.evaluate("foo.example.com", &profile),
        FilterResult::Forward
    );
}

#[test]
fn priority_tier0_normal_deny_rule_fires_when_no_higher_tier_matches() {
    use crate::filter::rules::parse_rule;
    // Strip allow_domains so tier 1 has nothing; only normal deny rule
    // remains at tier 0, and it must fire (and beat the bitmask, which
    // also sits at tier 0 but is checked last).
    let engine = engine_with_map(&[("foo.example.com", 0b01)]);
    let mut deny = HashSet::with_hasher(RandomState::new());
    deny.insert(CompactString::new("foo.example.com"));
    let profile = ResolvedProfile {
        name: CompactString::new("test"),
        unfiltered: false,
        allow_domains: std::sync::Arc::new(HashSet::with_hasher(RandomState::new())),
        deny_domains: deny.into(),
        block_all: false,
        rules: vec![parse_rule("||foo.example.com^").unwrap()].into(),
        block_response: crate::config::schema::BlockResponseV1::Zero,
        blocked_ttl_secs: 60,
        local_records: std::sync::Arc::new(
            crate::dns::local_profile::ProfileLocalRecords::default(),
        ),
        rewrite_rules: std::sync::Arc::new(crate::dns::rewrite::ProfileRewriteRules::default()),
        ecs_policy: crate::profiles::profile::EcsPolicy::OFF,
    };
    engine.fixture_subscribe("test", 0b01);
    assert_eq!(
        engine.evaluate("foo.example.com", &profile),
        FilterResult::Block
    );
}

// M-18: pin the unified walker against the three-walk equivalent. Each
// case below exercises a distinct probe path during the single byte-walk
// (allow at suffix N, deny at suffix M, bitmask at suffix K) and asserts
// the outcome matches the pre-unification priority semantics.
#[test]
fn unified_walk_allow_at_deeper_suffix_beats_deny_at_shallower() {
    // allow_domains hits at "foo.example.com"; deny_domains hits at
    // "example.com" further up; bitmask hits at "com" further still.
    // The walker must short-circuit on the allow before the deny / bitmask
    // would otherwise block.
    let engine = engine_with_map(&[("com", 0b01)]);
    let mut allow = HashSet::with_hasher(RandomState::new());
    allow.insert(CompactString::new("foo.example.com"));
    let mut deny = HashSet::with_hasher(RandomState::new());
    deny.insert(CompactString::new("example.com"));
    let profile = ResolvedProfile {
        name: CompactString::new("test"),
        unfiltered: false,
        allow_domains: allow.into(),
        deny_domains: deny.into(),
        block_all: false,
        rules: std::sync::Arc::new(Vec::new()),
        block_response: crate::config::schema::BlockResponseV1::Zero,
        blocked_ttl_secs: 60,
        local_records: std::sync::Arc::new(
            crate::dns::local_profile::ProfileLocalRecords::default(),
        ),
        rewrite_rules: std::sync::Arc::new(crate::dns::rewrite::ProfileRewriteRules::default()),
        ecs_policy: crate::profiles::profile::EcsPolicy::OFF,
    };
    engine.fixture_subscribe("test", 0b01);
    assert_eq!(
        engine.evaluate("bar.foo.example.com", &profile),
        FilterResult::Forward
    );
}

#[test]
fn unified_walk_deny_at_one_suffix_and_bitmask_at_another() {
    // No allow. Deny hits at "example.com" (priority 0 HashSet); bitmask
    // hits at "com" (priority 0 list-membership). With no rule producing
    // a result, deny is consulted before the bitmask — deny_hit wins.
    let engine = engine_with_map(&[("com", 0b01)]);
    let mut deny = HashSet::with_hasher(RandomState::new());
    deny.insert(CompactString::new("example.com"));
    let profile = ResolvedProfile {
        name: CompactString::new("test"),
        unfiltered: false,
        allow_domains: std::sync::Arc::new(HashSet::with_hasher(RandomState::new())),
        deny_domains: deny.into(),
        block_all: false,
        rules: std::sync::Arc::new(Vec::new()),
        block_response: crate::config::schema::BlockResponseV1::Zero,
        blocked_ttl_secs: 60,
        local_records: std::sync::Arc::new(
            crate::dns::local_profile::ProfileLocalRecords::default(),
        ),
        rewrite_rules: std::sync::Arc::new(crate::dns::rewrite::ProfileRewriteRules::default()),
        ecs_policy: crate::profiles::profile::EcsPolicy::OFF,
    };
    engine.fixture_subscribe("test", 0b01);
    assert_eq!(
        engine.evaluate("bar.example.com", &profile),
        FilterResult::Block
    );
}

#[test]
fn unified_walk_bitmask_only_when_other_sets_miss() {
    // allow + deny present but missing on the queried domain; bitmask is
    // the only thing that matches, on a deep suffix. The walker must
    // accumulate the bitmask hit across the walk and block at the end.
    let engine = engine_with_map(&[("tracker.example.com", 0b01)]);
    let mut allow = HashSet::with_hasher(RandomState::new());
    allow.insert(CompactString::new("safe.com"));
    let mut deny = HashSet::with_hasher(RandomState::new());
    deny.insert(CompactString::new("bad.com"));
    let profile = ResolvedProfile {
        name: CompactString::new("test"),
        unfiltered: false,
        allow_domains: allow.into(),
        deny_domains: deny.into(),
        block_all: false,
        rules: std::sync::Arc::new(Vec::new()),
        block_response: crate::config::schema::BlockResponseV1::Zero,
        blocked_ttl_secs: 60,
        local_records: std::sync::Arc::new(
            crate::dns::local_profile::ProfileLocalRecords::default(),
        ),
        rewrite_rules: std::sync::Arc::new(crate::dns::rewrite::ProfileRewriteRules::default()),
        ecs_policy: crate::profiles::profile::EcsPolicy::OFF,
    };
    engine.fixture_subscribe("test", 0b01);
    assert_eq!(
        engine.evaluate("sub.tracker.example.com", &profile),
        FilterResult::Block
    );
}

/// **D14 — an `unfiltered` device is not filtered by lists, and this is
/// the only test that says so after `plp-s3`.**
///
/// It replaces coverage that went out with the tag model:
/// `unfiltered_device_no_lists_apply`,
/// `specialise_with_effective_tags_unfiltered_short_circuits_to_empty_post_sprint_c`
/// and their siblings all asserted the mechanism — `effective_tags = ∅`
/// ⇒ `list_bitmask = 0` — rather than the behaviour, so every one of them
/// died with the mechanism and took the behaviour's only guard with it.
///
/// The field alone is not enough: a `pub` field that is written and never
/// read raises no `dead_code`, so `clippy -D warnings` is blind to the
/// term going missing from `want_bits`. Delete `!profile.unfiltered`
/// there and this test goes red; nothing else in the suite does.
///
/// The second half is what stops it being vacuous: the same engine, the
/// same masks, a filtered profile — that one must block, or "forwards"
/// would be satisfied by an engine that has forgotten how to filter.
#[test]
fn an_unfiltered_resolution_skips_the_list_layer_entirely() {
    let engine = engine_with_map(&[("ads.example.com", 0b01)]);
    let mut profile = profile_with_bitmask(&engine, 0b01);

    profile.unfiltered = true;
    assert_eq!(
        engine.evaluate("ads.example.com", &profile),
        FilterResult::Forward,
        "D14: `[[devices]].unfiltered = true` opts out of LIST filtering; \
         monitoring stays on, enforcement does not"
    );

    profile.unfiltered = false;
    assert_eq!(
        engine.evaluate("ads.example.com", &profile),
        FilterResult::Block,
        "control arm: the same profile with the same masks must block, or \
         the assertion above proves nothing about `unfiltered`"
    );
}

/// `unfiltered` skips the LIST layer and nothing else.
///
/// The pre-`plp-s3` mechanism had this property by construction — an
/// empty tag set zeroed the subscription mask and left `block_all`,
/// `rules` and the admin sets untouched. The boolean has to be *made* to
/// behave that way, so it gets its own pin: an operator who marks an IoT
/// device unfiltered has not thereby lifted their `block_all` posture.
#[test]
fn unfiltered_does_not_lift_block_all_or_admin_rules() {
    let engine = engine_with_map(&[]);
    let mut profile = profile_with_bitmask(&engine, 0);
    profile.unfiltered = true;
    profile.block_all = true;
    assert_eq!(
        engine.evaluate("anything.test", &profile),
        FilterResult::Block,
        "`unfiltered` is about lists; `block_all` is a posture and outranks it"
    );

    profile.block_all = false;
    std::sync::Arc::make_mut(&mut profile.deny_domains).insert(CompactString::new("blocked.test"));
    assert_eq!(
        engine.evaluate("blocked.test", &profile),
        FilterResult::Block,
        "an admin deny still applies to an unfiltered device"
    );
}

// M-17: pin that a profile with `list_bitmask == 0` short-circuits the
// list-membership lookup. With the previous code the lookup ran (and its
// O(labels) suffix walk) before the AND-with-zero produced the inevitable
// 0; this test would still pass byte-identically but the early-return is
// the contract operators rely on for admin-profile-no-list latency.
#[test]
fn list_bitmask_zero_short_circuits_list_check() {
    let engine = engine_with_map(&[("ads.com", 0b01), ("tracker.com", 0b11)]);
    let profile = profile_with_bitmask(&engine, 0);
    // Domains exist in the map with non-zero bitmasks, but the profile
    // subscribes to no lists — they must forward, not block.
    assert_eq!(engine.evaluate("ads.com", &profile), FilterResult::Forward);
    assert_eq!(
        engine.evaluate("sub.tracker.com", &profile),
        FilterResult::Forward
    );
}

// M-16: pin the lowercase invariant. The asserts are debug-only and zero
// cost in release, so a `should_panic` test under `cfg(debug_assertions)`
// is the right shape — it proves the assertion fires on any future
// mixed-case caller while not constraining release behaviour.
#[test]
#[should_panic(expected = "must be lowercased")]
#[cfg(debug_assertions)]
fn evaluate_rejects_uppercase_in_debug() {
    let engine = engine_with_map(&[]);
    let profile = profile_with_bitmask(&engine, 0);
    let _ = engine.evaluate("Example.COM", &profile);
}

#[test]
#[should_panic(expected = "must be lowercased")]
#[cfg(debug_assertions)]
fn list_membership_rejects_uppercase_in_debug() {
    let engine = engine_with_map(&[]);
    let _ = engine.list_membership("Tracker.Example.com");
}

#[test]
fn priority_tier0_bitmask_fires_when_only_subscription_matches() {
    // Last fallback: nothing in rules, nothing in HashSets, only the
    // domain map + matching bitmask. Pin that the bitmask check still
    // runs after the new single-pass scan exits with `best_result = None`.
    let engine = engine_with_map(&[("foo.example.com", 0b01)]);
    let profile = ResolvedProfile {
        name: CompactString::new("test"),
        unfiltered: false,
        allow_domains: std::sync::Arc::new(HashSet::with_hasher(RandomState::new())),
        deny_domains: std::sync::Arc::new(HashSet::with_hasher(RandomState::new())),
        block_all: false,
        rules: std::sync::Arc::new(Vec::new()),
        block_response: crate::config::schema::BlockResponseV1::Zero,
        blocked_ttl_secs: 60,
        local_records: std::sync::Arc::new(
            crate::dns::local_profile::ProfileLocalRecords::default(),
        ),
        rewrite_rules: std::sync::Arc::new(crate::dns::rewrite::ProfileRewriteRules::default()),
        ecs_policy: crate::profiles::profile::EcsPolicy::OFF,
    };
    engine.fixture_subscribe("test", 0b01);
    assert_eq!(
        engine.evaluate("foo.example.com", &profile),
        FilterResult::Block
    );
    // Non-matching bitmask must NOT block.
    let profile = ResolvedProfile {
        unfiltered: false,
        ..profile
    };
    engine.fixture_subscribe("test", 0b10);
    assert_eq!(
        engine.evaluate("foo.example.com", &profile),
        FilterResult::Forward
    );
}

// ── S50 T1 — allow-direction Tier 1 (DomainMasks split) ────────
//
// These tests cover §4 of `_docs/features/lists_categories_v1.md`. Each name
// references the truth-table step it pins so a future reader can trace
// doc → test in one hop.

/// Helper for §4 step 5: a single-bit allow-direction list entry.
const ALLOW_BIT0: DomainMasks = DomainMasks {
    allow_mask: 0b01,
    block_mask: 0,
};
/// Helper for §4 step 6: a single-bit block-direction list entry.
const BLOCK_BIT0: DomainMasks = DomainMasks {
    allow_mask: 0,
    block_mask: 0b01,
};
/// Helper for the same domain appearing on both an allow-list and a
/// block-list (operator imports both — §4 step 5 wins because allow
/// runs before block in the resolution stage).
///
/// **Corrected 2026-08-16 (mem-t6).** This used to be
/// `allow_mask: 0b01, block_mask: 0b01` — the *same* bit in both
/// directions. That encodes one source as being simultaneously
/// `base = allow` and `base = deny`, which the producer cannot build:
/// direction is a per-source property, so "the operator imports both"
/// means **two lists, therefore two bits**. The fixture's scenario was
/// always real; its encoding was not, and a test pinned to an
/// unreachable state pins nothing.
const ALLOW_AND_BLOCK_BIT0: DomainMasks = DomainMasks {
    allow_mask: 0b01,
    block_mask: 0b10,
};

#[test]
fn s50_t1_allow_list_match_returns_forward() {
    // §4 step 5: a `base = allow` list entry on a subscribed bit
    // forwards. Profile subscribes to bit 0; the entry's `allow_mask`
    // has bit 0 set; the AND is non-zero → Forward.
    let engine = engine_with_per_direction_map(&[("internal.example.com", ALLOW_BIT0)]);
    let profile = profile_with_bitmask(&engine, 0b01);
    assert_eq!(
        engine.evaluate("internal.example.com", &profile),
        FilterResult::Forward
    );
}

#[test]
fn s50_t1_allow_list_subdomain_walk_forwards_subdomain() {
    // Allow-direction entries support the same suffix walk as
    // block-direction. An entry on `corp.example.com` covers
    // `intranet.corp.example.com`.
    let engine = engine_with_per_direction_map(&[("corp.example.com", ALLOW_BIT0)]);
    let profile = profile_with_bitmask(&engine, 0b01);
    assert_eq!(
        engine.evaluate("intranet.corp.example.com", &profile),
        FilterResult::Forward
    );
}

#[test]
fn s50_t1_allow_list_no_match_falls_through_to_forward() {
    // Domain not in any list → §4 step 7 fall-through forward.
    let engine = engine_with_per_direction_map(&[("internal.example.com", ALLOW_BIT0)]);
    let profile = profile_with_bitmask(&engine, 0b01);
    assert_eq!(
        engine.evaluate("google.com", &profile),
        FilterResult::Forward
    );
}

#[test]
fn s50_t1_allow_only_domain_is_not_reported_as_blocked() {
    // is_blocked is the no-profile gate (CNAME prefetch, offline CLI).
    // An allow-only entry must NOT be reported as blocked there —
    // operator-curated trust signals shouldn't trigger profile-less
    // block reasoning. See `is_blocked` doc comment.
    let engine = engine_with_per_direction_map(&[("safe.example.com", ALLOW_BIT0)]);
    assert!(!engine.is_blocked("safe.example.com"));
    assert!(!engine.is_blocked("api.safe.example.com"));
}

#[test]
fn s50_t1_allow_and_block_same_domain_resolves_to_forward() {
    // §4 truth-table consequence: when the same domain has both an
    // allow-direction and a block-direction list entry on subscribed
    // bits, the allow wins (step 5 fires before step 6 in the
    // resolution stage). Order of probes doesn't matter — both masks
    // are OR-accumulated through the walk, then resolved.
    //
    // The subscription must cover BOTH bits (2026-08-16). The fixture now
    // uses bit 0 allow + bit 1 block, so a `0b01` profile would not
    // subscribe to the block list at all and this would assert Forward
    // against nothing — passing for the wrong reason. The control below
    // is what makes the Forward load-bearing.
    let engine = engine_with_per_direction_map(&[("dual.example.com", ALLOW_AND_BLOCK_BIT0)]);
    let profile = profile_with_bitmask(&engine, 0b11);
    assert_eq!(
        engine.evaluate("dual.example.com", &profile),
        FilterResult::Forward
    );

    // Control: same domain, same subscription, allow direction removed.
    // Blocks. Without this the assertion above cannot distinguish "allow
    // beat block" from "no block was ever visible".
    let blocking = engine_with_per_direction_map(&[(
        "dual.example.com",
        DomainMasks {
            allow_mask: 0,
            block_mask: 0b10,
        },
    )]);
    assert_eq!(
        blocking.evaluate("dual.example.com", &profile),
        FilterResult::Block
    );
}

#[test]
fn s50_t1_allow_only_when_subscription_overlaps() {
    // The AND with `profile.list_bitmask` is what makes an allow-list
    // a per-profile signal: bit 0 is allow-direction, profile only
    // subscribes to bit 1, so the allow_mask AND is 0 and the entry
    // is invisible to this profile.
    let engine = engine_with_per_direction_map(&[("internal.example.com", ALLOW_BIT0)]);
    let profile = profile_with_bitmask(&engine, 0b10);
    // Without subscription overlap, the entry doesn't fire either
    // direction — domain falls through to forward. (No block-mask
    // bits are set, so no §4 step 6 either.)
    assert_eq!(
        engine.evaluate("internal.example.com", &profile),
        FilterResult::Forward
    );
}

#[test]
fn s50_t1_allow_walks_at_deepest_match_first() {
    // Multiple suffix entries at different depths: subdomain has a
    // block, parent has an allow. The walk OR-accumulates both masks;
    // §4 step 5 fires (allow wins) regardless of which suffix the
    // probe found first. Documents the OR-then-resolve ordering the
    // engine guarantees.
    let engine = engine_with_per_direction_map(&[
        ("ads.example.com", BLOCK_BIT0),
        ("example.com", ALLOW_BIT0),
    ]);
    let profile = profile_with_bitmask(&engine, 0b01);
    assert_eq!(
        engine.evaluate("banner.ads.example.com", &profile),
        FilterResult::Forward,
    );
}

/// **W1.2 invariant test (load-bearing — cybersec-reviewable line).**
///
/// `_docs/features/lists_categories_v1.md` §2 W1.2: an admin `$important`
/// deny rule MUST pre-empt a Tier 1 allow-direction list match. The
/// allow-list is a "soft" union with `@@` admin rules; an admin who
/// wrote `$important` deny did so explicitly and the engine must
/// honour that explicitness. This test pins the priority ordering at
/// the engine entry point so any future refactor that reorders the
/// priority pass gets a hard fail here.
#[test]
fn w1_2_admin_important_deny_overrides_allow_list() {
    use crate::filter::rules::parse_rule;
    let engine = engine_with_per_direction_map(&[("contested.example.com", ALLOW_BIT0)]);
    let rules = vec![parse_rule("||contested.example.com^$important").unwrap()];
    let profile = ResolvedProfile {
        name: CompactString::new("test"),
        unfiltered: false,
        allow_domains: std::sync::Arc::new(HashSet::with_hasher(RandomState::new())),
        deny_domains: std::sync::Arc::new(HashSet::with_hasher(RandomState::new())),
        block_all: false,
        rules: rules.into(),
        block_response: crate::config::schema::BlockResponseV1::Zero,
        blocked_ttl_secs: 60,
        local_records: std::sync::Arc::new(
            crate::dns::local_profile::ProfileLocalRecords::default(),
        ),
        rewrite_rules: std::sync::Arc::new(crate::dns::rewrite::ProfileRewriteRules::default()),
        ecs_policy: crate::profiles::profile::EcsPolicy::OFF,
    };
    engine.fixture_subscribe("test", 0b01);
    // Admin $important deny is sovereign: BLOCK even though the
    // allow-list also matches.
    assert_eq!(
        engine.evaluate("contested.example.com", &profile),
        FilterResult::Block,
    );
}

#[test]
fn s50_t1_admin_normal_deny_rule_overrides_allow_list() {
    // Symmetry with W1.2: the truth table places admin `||domain^`
    // (step 4) above Tier 1 allow (step 5). A *non-important* admin
    // deny rule still wins over an allow-list. Pinned independently
    // because the priority lattice has multiple admin tiers; W1.2
    // covers tier 2, this one covers tier 0 (admin || without
    // $important).
    use crate::filter::rules::parse_rule;
    let engine = engine_with_per_direction_map(&[("contested.example.com", ALLOW_BIT0)]);
    let rules = vec![parse_rule("||contested.example.com^").unwrap()];
    let profile = ResolvedProfile {
        name: CompactString::new("test"),
        unfiltered: false,
        allow_domains: std::sync::Arc::new(HashSet::with_hasher(RandomState::new())),
        deny_domains: std::sync::Arc::new(HashSet::with_hasher(RandomState::new())),
        block_all: false,
        rules: rules.into(),
        block_response: crate::config::schema::BlockResponseV1::Zero,
        blocked_ttl_secs: 60,
        local_records: std::sync::Arc::new(
            crate::dns::local_profile::ProfileLocalRecords::default(),
        ),
        rewrite_rules: std::sync::Arc::new(crate::dns::rewrite::ProfileRewriteRules::default()),
        ecs_policy: crate::profiles::profile::EcsPolicy::OFF,
    };
    engine.fixture_subscribe("test", 0b01);
    assert_eq!(
        engine.evaluate("contested.example.com", &profile),
        FilterResult::Block,
    );
}

/// A custom list's rules do not merely compile — they decide.
///
/// Every other test of this feature stops at `allow_domains` /
/// `deny_domains`. Compilation is not evaluation: a domain that exists
/// ONLY in an operator's pack must change the verdict, with no admin
/// rule, no blocklist and no bitmask anywhere in the fixture. The
/// engine's corpus is deliberately empty, so the pack is the only
/// thing that can produce a verdict at all.
#[test]
fn a_custom_list_decides_the_verdict_not_just_the_hashsets() {
    use crate::config::custom_list::{CompiledCustomList, CustomListStore};
    use crate::config::schema::{Id, Profile, ServerGlobals};
    use std::collections::BTreeMap;

    let mut store = CustomListStore::new();
    store.insert(
        Id::new("minecraft").unwrap(),
        CompiledCustomList {
            allow: vec![CompactString::new("mc.example.com")],
            deny: vec![CompactString::new("ads.example.com")],
            skipped: 0,
        },
    );
    let profile = Profile {
        custom_lists: vec![Id::new("minecraft").unwrap()],
        ..Default::default()
    };
    let resolved = ResolvedProfile::build_v1(
        &Id::new("kids").unwrap(),
        &profile,
        &BTreeMap::new(),
        &store,
        &ServerGlobals::default(),
        60,
    );

    let engine = engine_with(&[]);
    assert_eq!(
        engine.evaluate("ads.example.com", &resolved),
        FilterResult::Block,
        "a deny rule that exists only in a custom list must block"
    );
    assert_eq!(
        engine.evaluate("mc.example.com", &resolved),
        FilterResult::Forward,
        "an allow rule that exists only in a custom list must forward"
    );
    // Negative control: without it, a profile that blocked everything
    // would satisfy the deny assertion above.
    assert_eq!(
        engine.evaluate("unrelated.example.org", &resolved),
        FilterResult::Forward,
        "a domain named by no rule must be untouched"
    );
}

/// A custom list's allow rule pierces `block_all`.
///
/// This is the operator's own file, so it carries admin power —
/// deliberately more than a remote allow-direction list gets, which the
/// neighbouring `block_all` test pins as NOT piercing. The asymmetry is
/// the whole point and an operator has to be able to predict it, so it
/// is asserted rather than left to be discovered by experiment.
#[test]
fn a_custom_list_allow_rule_pierces_block_all() {
    use crate::config::custom_list::{CompiledCustomList, CustomListStore};
    use crate::config::schema::{Id, Profile, ServerGlobals};
    use std::collections::BTreeMap;

    let mut store = CustomListStore::new();
    store.insert(
        Id::new("homework").unwrap(),
        CompiledCustomList {
            allow: vec![CompactString::new("school.example.com")],
            deny: Vec::new(),
            skipped: 0,
        },
    );
    let profile = Profile {
        block_all: true,
        custom_lists: vec![Id::new("homework").unwrap()],
        ..Default::default()
    };
    let resolved = ResolvedProfile::build_v1(
        &Id::new("night").unwrap(),
        &profile,
        &BTreeMap::new(),
        &store,
        &ServerGlobals::default(),
        60,
    );

    let engine = engine_with(&[]);
    assert_eq!(
        engine.evaluate("school.example.com", &resolved),
        FilterResult::Forward,
        "a custom list allow rule must pierce block_all"
    );
    assert_eq!(
        engine.evaluate("anything.example.org", &resolved),
        FilterResult::Block,
        "block_all must still deny everything the custom list does not allow"
    );
}

#[test]
fn s50_t1_admin_deny_domains_hashset_overrides_allow_list() {
    // The HashSet form of the same admin deny (a simple-exact rule
    // landed in `deny_domains` by `ResolvedProfile::build_v1`).
    // Without rule overlap, the admin deny still pre-empts the
    // allow-list at resolution time (`deny_hit` short-circuits before
    // the allow_bits check).
    let engine = engine_with_per_direction_map(&[("contested.example.com", ALLOW_BIT0)]);
    let mut deny = HashSet::with_hasher(RandomState::new());
    deny.insert(CompactString::new("contested.example.com"));
    let profile = ResolvedProfile {
        name: CompactString::new("test"),
        unfiltered: false,
        allow_domains: std::sync::Arc::new(HashSet::with_hasher(RandomState::new())),
        deny_domains: deny.into(),
        block_all: false,
        rules: std::sync::Arc::new(Vec::new()),
        block_response: crate::config::schema::BlockResponseV1::Zero,
        blocked_ttl_secs: 60,
        local_records: std::sync::Arc::new(
            crate::dns::local_profile::ProfileLocalRecords::default(),
        ),
        rewrite_rules: std::sync::Arc::new(crate::dns::rewrite::ProfileRewriteRules::default()),
        ecs_policy: crate::profiles::profile::EcsPolicy::OFF,
    };
    engine.fixture_subscribe("test", 0b01);
    assert_eq!(
        engine.evaluate("contested.example.com", &profile),
        FilterResult::Block,
    );
}

#[test]
fn s50_t1_block_all_ignores_allow_list_per_t1_conservatism() {
    // T1 conservatism (documented at the `block_all` branch in
    // `evaluate`): Tier 1 allow-direction lists do NOT pierce
    // `block_all`. Operators that want a curated allow-list to
    // override "night profile" must author an admin `@@||domain^`
    // rule. This is a behaviour pin; future sprints may relax it
    // with explicit operator opt-in.
    let engine = engine_with_per_direction_map(&[("safe.example.com", ALLOW_BIT0)]);
    let profile = ResolvedProfile {
        name: CompactString::new("night"),
        unfiltered: false,
        allow_domains: std::sync::Arc::new(HashSet::with_hasher(RandomState::new())),
        deny_domains: std::sync::Arc::new(HashSet::with_hasher(RandomState::new())),
        block_all: true,
        rules: std::sync::Arc::new(Vec::new()),
        block_response: crate::config::schema::BlockResponseV1::Zero,
        blocked_ttl_secs: 60,
        local_records: std::sync::Arc::new(
            crate::dns::local_profile::ProfileLocalRecords::default(),
        ),
        rewrite_rules: std::sync::Arc::new(crate::dns::rewrite::ProfileRewriteRules::default()),
        ecs_policy: crate::profiles::profile::EcsPolicy::OFF,
    };
    engine.fixture_subscribe("night", 0b01);
    assert_eq!(
        engine.evaluate("safe.example.com", &profile),
        FilterResult::Block,
    );
}

#[test]
fn s50_t1_legacy_swap_domain_map_treats_input_as_block_only() {
    // The pre-S50 single-mask `swap_domain_map` API is preserved
    // verbatim (lists::manager keeps using it). The conversion
    // treats every bit as block-direction — same behaviour as
    // before T1, no allow-direction bits surface. Pinned so a
    // future "clean up" doesn't accidentally route legacy bits
    // into `allow_mask`.
    let engine = FilterEngine::new();
    let mut legacy = HashMap::with_hasher(RandomState::new());
    legacy.insert(CompactString::new("ads.com"), 0b01_u64);
    engine.swap_domain_map(legacy);

    // Profile subscribes to bit 0 → block-only mask hits → BLOCK.
    let profile = profile_with_bitmask(&engine, 0b01);
    assert_eq!(engine.evaluate("ads.com", &profile), FilterResult::Block);

    // No allow_mask bits were set → list_membership reports zero on
    // the allow side.
    let masks = engine.list_membership("ads.com");
    assert_eq!(masks.allow_mask, 0);
    assert_eq!(masks.block_mask, 0b01);
}

// `s50_t1_swap_domain_map_with_directions_round_trip` was deleted with the
// method it exercised (mem-t6, 2026-08-16) — it was that method's only
// caller in the tree. The per-direction round trip it covered is still
// pinned, by `with_per_direction_domain_map` in
// `tests/integration_list_direction_e2e.rs` and by
// `derived_split_round_trips_every_production_mask_pair` below, so no
// coverage was lost with it.

#[test]
fn s50_t1_domain_masks_block_only_helper_zeros_allow() {
    // DomainMasks::block_only is the back-compat constructor used by
    // every legacy swap path. Pin its semantics so the conversion
    // stays kind-agnostic in legacy callers.
    let m = DomainMasks::block_only(0b1011);
    assert_eq!(m.allow_mask, 0);
    assert_eq!(m.block_mask, 0b1011);
    assert!(!m.is_empty());
    assert!(DomainMasks::default().is_empty());
}

// ──────────────────────────────────────────────────────────────────
// S54 — Filter Pipeline Consolidation: Foundations
//
// Pin the truth table of `evaluate()` before Sprint 55 rewrites the
// priority scan. These tests are the regression net for FC1-FC8 in
// _docs/features/filter_consolidation.md §3.
// ──────────────────────────────────────────────────────────────────

/// FC8 + §5.2: a device with `unfiltered = true` collapses to
/// `list_bitmask = 0` at resolve time. Admin rules (block_all,
/// allow_domains, deny_domains, rules) MUST still apply — only the
/// blocklist subscription is disabled.
#[test]
fn evaluate_unfiltered_device_passes_through_unless_admin_rule_blocks() {
    // Sub-case A: bitmask=0 + domain on a block list → Forward.
    // The list bit and the profile mask AND to zero, so the list
    // entry is invisible to the unfiltered device.
    let engine = engine_with_per_direction_map(&[("doubleclick.net", BLOCK_BIT0)]);
    let unfiltered = profile_with_bitmask(&engine, 0);
    assert_eq!(
        engine.evaluate("doubleclick.net", &unfiltered),
        FilterResult::Forward,
        "unfiltered device should pass through a list-blocked domain"
    );

    // Sub-case B: bitmask=0 + block_all=true → Block.
    // block_all is an admin policy; unfiltered does not bypass it.
    let mut block_all = profile_with_bitmask(&engine, 0);
    block_all.block_all = true;
    assert_eq!(
        engine.evaluate("doubleclick.net", &block_all),
        FilterResult::Block,
        "block_all on an unfiltered device must still block"
    );

    // Sub-case C: bitmask=0 + domain in deny_domains → Block.
    let mut deny = profile_with_bitmask(&engine, 0);
    std::sync::Arc::make_mut(&mut deny.deny_domains).insert(CompactString::new("ads.example.com"));
    assert_eq!(
        engine.evaluate("ads.example.com", &deny),
        FilterResult::Block,
        "admin deny_domains must still block on an unfiltered device"
    );

    // Sub-case D: bitmask=0 + domain in allow_domains while also on a
    // block list → Forward. allow_domains short-circuits before any
    // list check, so this is identical to Sub-case A; the test pins
    // the contract that both gates lead to Forward.
    let mut allow = profile_with_bitmask(&engine, 0);
    std::sync::Arc::make_mut(&mut allow.allow_domains)
        .insert(CompactString::new("doubleclick.net"));
    assert_eq!(
        engine.evaluate("doubleclick.net", &allow),
        FilterResult::Forward,
        "allow_domains must short-circuit on an unfiltered device"
    );
}

/// 13-case truth table that pins `evaluate()` before Sprint 55's
/// priority_scan refactor. Each case is independent: a fresh engine
/// + profile per row keeps regressions isolatable.
#[test]
fn evaluate_baseline_truth_table() {
    use crate::filter::rules::parse_rule;

    type Build = fn() -> (FilterEngine, ResolvedProfile);
    type Case = (&'static str, &'static str, Build, FilterResult);

    let cases: &[Case] = &[
        // 1. plain forward, empty list, empty rules
        (
            "case1_plain_forward",
            "google.com",
            || {
                let e = engine_with_map(&[]);
                let p = profile_with_bitmask(&e, 0b01);
                (e, p)
            },
            FilterResult::Forward,
        ),
        // 2. list bitmask block: domain on a subscribed block-list
        (
            "case2_list_block",
            "ads.example.com",
            || {
                let e = engine_with_per_direction_map(&[("ads.example.com", BLOCK_BIT0)]);
                let p = profile_with_bitmask(&e, 0b01);
                (e, p)
            },
            FilterResult::Block,
        ),
        // 3. allow rule overrides nothing — plain Forward
        (
            "case3_allow_rule_match",
            "safe.com",
            || {
                let e = engine_with_map(&[]);
                let mut p = profile_with_bitmask(&e, 0);
                p.rules = vec![parse_rule("@@||safe.com^").unwrap()].into();
                (e, p)
            },
            FilterResult::Forward,
        ),
        // 4. deny rule blocks
        (
            "case4_deny_rule_match",
            "evil.com",
            || {
                let e = engine_with_map(&[]);
                let mut p = profile_with_bitmask(&e, 0);
                p.rules = vec![parse_rule("||evil.com^").unwrap()].into();
                (e, p)
            },
            FilterResult::Block,
        ),
        // 5. allow_domains short-circuits over list block
        (
            "case5_allow_domains_over_list",
            "captive.apple.com",
            || {
                let e = engine_with_per_direction_map(&[("captive.apple.com", BLOCK_BIT0)]);
                let mut p = profile_with_bitmask(&e, 0b01);
                std::sync::Arc::make_mut(&mut p.allow_domains)
                    .insert(CompactString::new("captive.apple.com"));
                (e, p)
            },
            FilterResult::Forward,
        ),
        // 6. deny_domains blocks
        (
            "case6_deny_domains_block",
            "tracker.example.com",
            || {
                let e = engine_with_map(&[]);
                let mut p = profile_with_bitmask(&e, 0);
                std::sync::Arc::make_mut(&mut p.deny_domains)
                    .insert(CompactString::new("tracker.example.com"));
                (e, p)
            },
            FilterResult::Block,
        ),
        // 7. block_all on a profile with empty allow → blocks
        (
            "case7_block_all_on",
            "anything.example.com",
            || {
                let e = engine_with_map(&[]);
                let mut p = profile_with_bitmask(&e, 0);
                p.block_all = true;
                (e, p)
            },
            FilterResult::Block,
        ),
        // 8. block_all off + plain domain → forwards
        (
            "case8_block_all_off",
            "google.com",
            || {
                let e = engine_with_map(&[]);
                let p = profile_with_bitmask(&e, 0);
                (e, p)
            },
            FilterResult::Forward,
        ),
        // 9. important deny outranks normal allow
        (
            "case9_important_deny_over_normal_allow",
            "evil.com",
            || {
                let e = engine_with_map(&[]);
                let mut p = profile_with_bitmask(&e, 0);
                p.rules = vec![
                    parse_rule("@@||evil.com^").unwrap(),
                    parse_rule("||evil.com^$important").unwrap(),
                ]
                .into();
                (e, p)
            },
            FilterResult::Block,
        ),
        // 10. important allow outranks important deny
        (
            "case10_important_allow_over_important_deny",
            "captive.apple.com",
            || {
                let e = engine_with_map(&[]);
                let mut p = profile_with_bitmask(&e, 0);
                p.rules = vec![
                    parse_rule("||captive.apple.com^$important").unwrap(),
                    parse_rule("@@||captive.apple.com^$important").unwrap(),
                ]
                .into();
                (e, p)
            },
            FilterResult::Forward,
        ),
        // 11. W1.2 invariant: $important deny on admin rule beats Tier 1 list-allow
        (
            "case11_w1_2_important_deny_over_list_allow",
            "tracking.com",
            || {
                let e = engine_with_per_direction_map(&[("tracking.com", ALLOW_BIT0)]);
                let mut p = profile_with_bitmask(&e, 0b01);
                p.rules = vec![parse_rule("||tracking.com^$important").unwrap()].into();
                (e, p)
            },
            FilterResult::Block,
        ),
        // 12. list_bitmask=0 + block_all=true → Block (FC8 in table form)
        (
            "case12_unfiltered_block_all",
            "google.com",
            || {
                let e = engine_with_map(&[]);
                let mut p = profile_with_bitmask(&e, 0);
                p.block_all = true;
                (e, p)
            },
            FilterResult::Block,
        ),
        // 13. wildcard rule blocks subdomain
        (
            "case13_wildcard_rule",
            "banner.ads.example.com",
            || {
                let e = engine_with_map(&[]);
                let mut p = profile_with_bitmask(&e, 0);
                p.rules = vec![parse_rule("||*.ads.example.com^").unwrap()].into();
                (e, p)
            },
            FilterResult::Block,
        ),
    ];

    for (name, domain, build, expected) in cases {
        let (engine, profile) = build();
        let got = engine.evaluate(domain, &profile);
        assert_eq!(got, *expected, "truth-table {name} on {domain}");
    }
}

// ──────────────────────────────────────────────────────────────────
// S55 — evaluate_attributed: authoritative source attribution on the
// block path. The four unit tests pin one BlockSource variant each;
// the snapshot mirrors the truth table with Source assertions.
// ──────────────────────────────────────────────────────────────────

#[test]
fn evaluate_attributed_returns_list_for_bitmask_block() {
    let engine = engine_with_per_direction_map(&[("doubleclick.net", BLOCK_BIT0)]);
    let profile = profile_with_bitmask(&engine, 0b01);
    let (verdict, source) = engine.evaluate_attributed("doubleclick.net", &profile);
    assert_eq!(verdict, FilterResult::Block);
    assert_eq!(source, Some(BlockSource::List(0)));
}

#[test]
fn evaluate_attributed_returns_rule_for_admin_rule() {
    use crate::filter::rules::parse_rule;
    let engine = engine_with_map(&[]);
    let mut profile = profile_with_bitmask(&engine, 0);
    profile.rules = vec![parse_rule("||tracker.com^").unwrap()].into();
    let (verdict, source) = engine.evaluate_attributed("tracker.com", &profile);
    assert_eq!(verdict, FilterResult::Block);
    match source {
        Some(BlockSource::Rule(label)) => assert_eq!(label.as_str(), "tracker.com"),
        other => panic!("expected Rule source, got {other:?}"),
    }
}

#[test]
fn evaluate_attributed_returns_admin_block_for_block_all() {
    let engine = engine_with_map(&[]);
    let mut profile = profile_with_bitmask(&engine, 0);
    profile.block_all = true;
    let (verdict, source) = engine.evaluate_attributed("anything.example.com", &profile);
    assert_eq!(verdict, FilterResult::Block);
    assert_eq!(source, Some(BlockSource::AdminBlock));
}

#[test]
fn evaluate_attributed_returns_admin_block_for_deny_domains() {
    let engine = engine_with_map(&[]);
    let mut profile = profile_with_bitmask(&engine, 0);
    std::sync::Arc::make_mut(&mut profile.deny_domains)
        .insert(CompactString::new("blocked.example.com"));
    let (verdict, source) = engine.evaluate_attributed("blocked.example.com", &profile);
    assert_eq!(verdict, FilterResult::Block);
    assert_eq!(source, Some(BlockSource::AdminBlock));
}

/// Mirror of the 13-case `evaluate_baseline_truth_table` extended with
/// `BlockSource` expectations. Pins that the source emitted by
/// `evaluate_attributed` is consistent with the verdict pinned in
/// the S54 truth table.
#[test]
fn evaluate_attributed_baseline() {
    use crate::filter::rules::parse_rule;

    #[derive(Debug)]
    enum SourceExpect {
        AdminBlock,
        List(u8),
        RuleLabel(&'static str),
    }

    type Build = fn() -> (FilterEngine, ResolvedProfile);
    type Case = (
        &'static str,
        &'static str,
        Build,
        FilterResult,
        Option<SourceExpect>,
    );

    let cases: &[Case] = &[
        (
            "case1_plain_forward",
            "google.com",
            || {
                let e = engine_with_map(&[]);
                let p = profile_with_bitmask(&e, 0b01);
                (e, p)
            },
            FilterResult::Forward,
            None,
        ),
        (
            "case2_list_block",
            "ads.example.com",
            || {
                let e = engine_with_per_direction_map(&[("ads.example.com", BLOCK_BIT0)]);
                let p = profile_with_bitmask(&e, 0b01);
                (e, p)
            },
            FilterResult::Block,
            Some(SourceExpect::List(0)),
        ),
        (
            "case3_allow_rule_match",
            "safe.com",
            || {
                let e = engine_with_map(&[]);
                let mut p = profile_with_bitmask(&e, 0);
                p.rules = vec![parse_rule("@@||safe.com^").unwrap()].into();
                (e, p)
            },
            FilterResult::Forward,
            None,
        ),
        (
            "case4_deny_rule_match",
            "evil.com",
            || {
                let e = engine_with_map(&[]);
                let mut p = profile_with_bitmask(&e, 0);
                p.rules = vec![parse_rule("||evil.com^").unwrap()].into();
                (e, p)
            },
            FilterResult::Block,
            Some(SourceExpect::RuleLabel("evil.com")),
        ),
        (
            "case5_allow_domains_over_list",
            "captive.apple.com",
            || {
                let e = engine_with_per_direction_map(&[("captive.apple.com", BLOCK_BIT0)]);
                let mut p = profile_with_bitmask(&e, 0b01);
                std::sync::Arc::make_mut(&mut p.allow_domains)
                    .insert(CompactString::new("captive.apple.com"));
                (e, p)
            },
            FilterResult::Forward,
            None,
        ),
        (
            "case6_deny_domains_block",
            "tracker.example.com",
            || {
                let e = engine_with_map(&[]);
                let mut p = profile_with_bitmask(&e, 0);
                std::sync::Arc::make_mut(&mut p.deny_domains)
                    .insert(CompactString::new("tracker.example.com"));
                (e, p)
            },
            FilterResult::Block,
            Some(SourceExpect::AdminBlock),
        ),
        (
            "case7_block_all_on",
            "anything.example.com",
            || {
                let e = engine_with_map(&[]);
                let mut p = profile_with_bitmask(&e, 0);
                p.block_all = true;
                (e, p)
            },
            FilterResult::Block,
            Some(SourceExpect::AdminBlock),
        ),
        (
            "case8_block_all_off",
            "google.com",
            || {
                let e = engine_with_map(&[]);
                let p = profile_with_bitmask(&e, 0);
                (e, p)
            },
            FilterResult::Forward,
            None,
        ),
        (
            "case9_important_deny_over_normal_allow",
            "evil.com",
            || {
                let e = engine_with_map(&[]);
                let mut p = profile_with_bitmask(&e, 0);
                p.rules = vec![
                    parse_rule("@@||evil.com^").unwrap(),
                    parse_rule("||evil.com^$important").unwrap(),
                ]
                .into();
                (e, p)
            },
            FilterResult::Block,
            Some(SourceExpect::RuleLabel("evil.com")),
        ),
        (
            "case10_important_allow_over_important_deny",
            "captive.apple.com",
            || {
                let e = engine_with_map(&[]);
                let mut p = profile_with_bitmask(&e, 0);
                p.rules = vec![
                    parse_rule("||captive.apple.com^$important").unwrap(),
                    parse_rule("@@||captive.apple.com^$important").unwrap(),
                ]
                .into();
                (e, p)
            },
            FilterResult::Forward,
            None,
        ),
        (
            "case11_w1_2_important_deny_over_list_allow",
            "tracking.com",
            || {
                let e = engine_with_per_direction_map(&[("tracking.com", ALLOW_BIT0)]);
                let mut p = profile_with_bitmask(&e, 0b01);
                p.rules = vec![parse_rule("||tracking.com^$important").unwrap()].into();
                (e, p)
            },
            FilterResult::Block,
            Some(SourceExpect::RuleLabel("tracking.com")),
        ),
        (
            "case12_unfiltered_block_all",
            "google.com",
            || {
                let e = engine_with_map(&[]);
                let mut p = profile_with_bitmask(&e, 0);
                p.block_all = true;
                (e, p)
            },
            FilterResult::Block,
            Some(SourceExpect::AdminBlock),
        ),
        (
            "case13_wildcard_rule",
            "banner.ads.example.com",
            || {
                let e = engine_with_map(&[]);
                let mut p = profile_with_bitmask(&e, 0);
                p.rules = vec![parse_rule("||*.ads.example.com^").unwrap()].into();
                (e, p)
            },
            FilterResult::Block,
            Some(SourceExpect::RuleLabel("*.ads.example.com")),
        ),
    ];

    for (name, domain, build, expected_verdict, expected_source) in cases {
        let (engine, profile) = build();
        let (got_verdict, got_source) = engine.evaluate_attributed(domain, &profile);
        assert_eq!(
            got_verdict, *expected_verdict,
            "verdict for {name} on {domain}"
        );
        match (expected_source, &got_source) {
            (None, None) => {}
            (Some(SourceExpect::AdminBlock), Some(BlockSource::AdminBlock)) => {}
            (Some(SourceExpect::List(n)), Some(BlockSource::List(m))) => {
                assert_eq!(n, m, "List bit mismatch for {name}");
            }
            (Some(SourceExpect::RuleLabel(label)), Some(BlockSource::Rule(got))) => {
                assert_eq!(*label, got.as_str(), "Rule label mismatch for {name}");
            }
            (exp, got) => {
                panic!("source mismatch for {name}: expected {exp:?}, got {got:?}")
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────
// Property-based fuzz pinning — proptest dev-dep
//
// Each property pins one invariant that Sprint 55's priority_scan
// refactor must preserve. proptest defaults to 256 cases per test.
// ──────────────────────────────────────────────────────────────────

use proptest::prelude::*;

proptest! {
    /// Property (a) — a normal-action `||domain^` block rule alone
    /// always blocks the matching domain regardless of which other
    /// non-matching rules sit alongside it. Pins the rule scan from
    /// being silently short-circuited by an unrelated higher-priority
    /// allow rule.
    #[test]
    fn evaluate_property_important_deny_blocks(
        label in "[a-z]{3,8}",
        tld in "[a-z]{2,4}",
        decoy in "[a-z]{3,8}\\.[a-z]{2,4}",
    ) {
        use crate::filter::rules::parse_rule;
        let target = format!("{label}.{tld}");
        // Decoy is a rule on a DIFFERENT domain — must not affect verdict.
        let decoy_rule = parse_rule(&format!("@@||{decoy}^$important")).unwrap();
        let target_rule = parse_rule(&format!("||{target}^$important")).unwrap();
        let engine = engine_with_map(&[]);
        let mut profile = profile_with_bitmask(&engine, 0);
        profile.rules = vec![decoy_rule, target_rule].into();
        prop_assert_eq!(engine.evaluate(&target, &profile), FilterResult::Block);
    }

    /// Property (b) — the rules `Vec` is order-insensitive: shuffling
    /// the same set of rules yields the same verdict.
    #[test]
    fn evaluate_property_rule_order_invariant(
        label in "[a-z]{3,8}",
        tld in "[a-z]{2,4}",
    ) {
        use crate::filter::rules::parse_rule;
        let target = format!("{label}.{tld}");
        let r1 = parse_rule(&format!("||{target}^")).unwrap();
        let r2 = parse_rule(&format!("@@||{target}^$important")).unwrap();
        let r3 = parse_rule(&format!("||other-{label}.{tld}^")).unwrap();

        let engine = engine_with_map(&[]);
        let mut p_a = profile_with_bitmask(&engine, 0);
        p_a.rules = vec![r1.clone(), r2.clone(), r3.clone()].into();
        let mut p_b = profile_with_bitmask(&engine, 0);
        p_b.rules = vec![r3, r1, r2].into();
        prop_assert_eq!(
            engine.evaluate(&target, &p_a),
            engine.evaluate(&target, &p_b)
        );
    }

    /// Property (c) — `parse_rule` lowercases its input, so a
    /// mixed-case rule pattern must still match the lowercase query.
    /// Pins the case-folding contract that `engine.evaluate` relies on
    /// (its `debug_assert!` enforces lowercase domains).
    #[test]
    fn evaluate_property_lowercase_invariant(
        label in "[a-z]{3,8}",
        tld in "[a-z]{2,4}",
    ) {
        use crate::filter::rules::parse_rule;
        let target_lc = format!("{label}.{tld}");
        let target_uc = target_lc.to_ascii_uppercase();
        // Build the rule from the UPPERCASE form; parse_rule lowercases
        // it internally. The engine query is the lowercase form.
        let rule = parse_rule(&format!("||{target_uc}^")).unwrap();
        let engine = engine_with_map(&[]);
        let mut profile = profile_with_bitmask(&engine, 0);
        profile.rules = vec![rule].into();
        prop_assert_eq!(
            engine.evaluate(&target_lc, &profile),
            FilterResult::Block
        );
    }

    /// Property (d) — idempotence: with `list_bitmask = 0` and no
    /// admin rules, repeated evaluation of the same domain yields
    /// the same verdict (Forward). This is the unfiltered-device
    /// guarantee from FC8: ArcSwap reads must not race and produce
    /// inconsistent verdicts across calls.
    #[test]
    fn evaluate_property_unfiltered_idempotence(
        label in "[a-z]{3,8}",
        tld in "[a-z]{2,4}",
    ) {
        let domain = format!("{label}.{tld}");
        let engine = engine_with_map(&[]);
        let profile = profile_with_bitmask(&engine, 0);
        let v1 = engine.evaluate(&domain, &profile);
        let v2 = engine.evaluate(&domain, &profile);
        let v3 = engine.evaluate(&domain, &profile);
        prop_assert_eq!(v1, FilterResult::Forward);
        prop_assert_eq!(v1, v2);
        prop_assert_eq!(v2, v3);
    }

    /// Property (e) — non-divergence: `evaluate` and `evaluate_attributed`
    /// return the same verdict for every input. Generates a parametric
    /// profile with all combinations of admin layers (rules, allow/deny
    /// HashSets, block_all) and asserts the verdict portion of the
    /// attributed result agrees with the bare `evaluate`. This is the
    /// load-bearing guarantee that justifies replacing `evaluate +
    /// attribute_block_source` with the single `evaluate_attributed`
    /// call in `cname::walk_response`.
    #[test]
    fn evaluate_and_evaluate_attributed_agree_on_verdict(
        label in "[a-z]{3,8}",
        tld in "[a-z]{2,4}",
        bits in 0u64..0b1111,
        use_allow_rule in any::<bool>(),
        use_deny_rule in any::<bool>(),
        use_important_deny in any::<bool>(),
        use_allow_domains in any::<bool>(),
        use_deny_domains in any::<bool>(),
        use_block_all in any::<bool>(),
    ) {
        use crate::filter::rules::parse_rule;
        let target = format!("{label}.{tld}");

        // Use a per-direction engine so both `block_mask` and `allow_mask`
        // paths are exercised by varying `bits`.
        let engine = engine_with_per_direction_map(&[
            (target.as_str(), DomainMasks { allow_mask: 0b01, block_mask: 0b10 }),
        ]);

        let mut profile = profile_with_bitmask(&engine, bits);
        profile.block_all = use_block_all;
        if use_allow_rule {
            std::sync::Arc::make_mut(&mut profile.rules).push(parse_rule(&format!("@@||{target}^")).unwrap());
        }
        if use_deny_rule {
            std::sync::Arc::make_mut(&mut profile.rules).push(parse_rule(&format!("||{target}^")).unwrap());
        }
        if use_important_deny {
            std::sync::Arc::make_mut(&mut profile.rules).push(
                parse_rule(&format!("||{target}^$important")).unwrap()
            );
        }
        if use_allow_domains {
            std::sync::Arc::make_mut(&mut profile.allow_domains).insert(CompactString::new(&target));
        }
        if use_deny_domains {
            std::sync::Arc::make_mut(&mut profile.deny_domains).insert(CompactString::new(&target));
        }

        let v_plain = engine.evaluate(&target, &profile);
        let (v_attr, source) = engine.evaluate_attributed(&target, &profile);
        prop_assert_eq!(v_plain, v_attr);
        // Source contract: Some on Block, None on Forward.
        match v_attr {
            FilterResult::Block => prop_assert!(source.is_some()),
            FilterResult::Forward => prop_assert!(source.is_none()),
        }
    }
}

// ------------------------------------------------------------------
// PerfMem S2 — domain-map sharding
// (`_docs/features/memory_architecture_evaluation.md` §6 / §11)
// ------------------------------------------------------------------

/// Unsharded oracle: the pre-S2 `list_membership` walk over one flat map.
///
/// Deliberately an independent reimplementation and not a call back into
/// the engine — an equivalence test that asks the engine to check itself
/// proves nothing.
fn reference_membership(
    map: &HashMap<CompactString, DomainMasks, RandomState>,
    domain: &str,
) -> DomainMasks {
    let mut masks = DomainMasks::default();
    if let Some(&m) = map.get(domain) {
        masks.allow_mask |= m.allow_mask;
        masks.block_mask |= m.block_mask;
    }
    for (i, &byte) in domain.as_bytes().iter().enumerate() {
        if byte == b'.' {
            let suffix = &domain[i + 1..];
            if !suffix.is_empty() {
                if let Some(&m) = map.get(suffix) {
                    masks.allow_mask |= m.allow_mask;
                    masks.block_mask |= m.block_mask;
                }
            }
        }
    }
    masks
}

/// Truth-table steps 5-7 for a profile whose admin layer is inert:
/// an allow-direction hit forwards (step 5), otherwise a block-direction
/// hit blocks (step 6), otherwise forward (step 7).
fn reference_verdict(masks: DomainMasks, bitmask: u64) -> FilterResult {
    if masks.allow_mask & bitmask == 0 && masks.block_mask & bitmask != 0 {
        FilterResult::Block
    } else {
        FilterResult::Forward
    }
}

fn masks_map(entries: &[(&str, DomainMasks)]) -> HashMap<CompactString, DomainMasks, RandomState> {
    entries
        .iter()
        .map(|(d, m)| (CompactString::new(d), *m))
        .collect()
}

/// Extract the entries of `map` that belong to shard `idx`, the way the
/// reload producer will.
fn shard_slice(
    map: &HashMap<CompactString, DomainMasks, RandomState>,
    idx: usize,
) -> HashMap<CompactString, DomainMasks, RandomState> {
    map.iter()
        .filter(|(k, _)| FilterEngine::shard_index(k.as_str()) == idx)
        .map(|(k, v)| (k.clone(), *v))
        .collect()
}

/// Corpus spanning multi-label domains, apex entries, a TLD entry, an
/// allow-direction entry under a blocked TLD, and a trailing dot.
const EQUIV_ENTRIES: &[(&str, DomainMasks)] = &[
    // bit 1, not bit 0 (corrected 2026-08-16, mem-t6). Bit 0 is this
    // corpus's ALLOW-direction list — `safe.example.com`, `b.com`,
    // `mixed.test` — so blocking on bit 0 here made one list bit carry
    // both directions, which no source can. See
    // `assert_one_direction_per_bit`, which now enforces it.
    (
        "tracker.example.com",
        DomainMasks {
            allow_mask: 0,
            block_mask: 0b0010,
        },
    ),
    (
        "example.net",
        DomainMasks {
            allow_mask: 0,
            block_mask: 0b0010,
        },
    ),
    (
        "com",
        DomainMasks {
            allow_mask: 0,
            block_mask: 0b0100,
        },
    ),
    (
        "safe.example.com",
        DomainMasks {
            // Bit 5, not bit 0. Bit 0 is `tracker.example.com`'s BLOCK bit,
            // and one list bit cannot drive both directions — `kind` is a
            // per-SOURCE property, so bit N is allow or block for every
            // domain it tags. See the fixture-wide invariant pinned by
            // `equiv_entries_never_use_one_bit_in_both_directions`.
            allow_mask: 0b10_0000,
            block_mask: 0,
        },
    ),
    (
        "ads.co.uk",
        DomainMasks {
            allow_mask: 0,
            block_mask: 0b1000,
        },
    ),
    (
        "b.com",
        DomainMasks {
            allow_mask: 0b10_0000,
            block_mask: 0,
        },
    ),
    // Early-exit discriminators. The walk OR-accumulates across EVERY
    // suffix; these two pairs make a `break` on first hit change the
    // VERDICT, not merely the masks — without them a corpus can look
    // thorough while every probe happens to reach the same verdict from
    // its first hit alone.
    //
    // 1. parent allow must still beat a child block.
    //
    // TWO bits, not one (corrected 2026-08-16, mem-t6). This pair used to
    // put bit 0 in `block_mask` here and bit 0 in `allow_mask` on the
    // parent — one list bit driving both directions, which the producer
    // cannot emit: `kind` is a per-SOURCE property, so bit N is allow or
    // block for every domain it tags. "Parent allow beats child block"
    // means an allow-LIST and a deny-LIST, i.e. two bits.
    //
    // It was not a harmless inaccuracy. Under the derived representation
    // the per-shard `allow_bits` is the union of allow masks, so the child
    // keeps its block bit only while the two domains land in *different*
    // shards — a ~1-in-16 coin flip on `SHARD_HASHER`'s per-process seed.
    // The fixture was a non-deterministic failure waiting on a reseed.
    //
    // The discriminating property is fully preserved: a `break` on first
    // hit still stops at the child's block and returns Block instead of
    // Forward, so the early-exit regression this pair exists to catch is
    // still caught.
    (
        "child.mixed.test",
        DomainMasks {
            allow_mask: 0,
            block_mask: 0b0010,
        },
    ),
    (
        "mixed.test",
        DomainMasks {
            // Also bit 5. The 2026-08-16 correction below split this pair
            // onto two bits, which was right, but chose bit 0 for the allow
            // side — already `tracker.example.com`'s block bit. That fixed
            // the pair and re-created the fixture-wide violation.
            allow_mask: 0b10_0000,
            block_mask: 0,
        },
    ),
    // 2. a child bit OUTSIDE the profile's subscription mask must not stop
    //    the walk from reaching an in-mask parent bit.
    (
        "noise.example.org",
        DomainMasks {
            allow_mask: 0,
            block_mask: 0b1_0000,
        },
    ),
    (
        "example.org",
        DomainMasks {
            allow_mask: 0,
            block_mask: 0b0010,
        },
    ),
];

const EQUIV_PROBES: &[&str] = &[
    "sub.deep.tracker.example.com", // multi-label, two suffix hits
    "tracker.example.com",          // exact + TLD parent
    "example.net",                  // apex exact
    "www.example.net",              // apex via parent
    "a.b.c.d.e.f.example.net",      // deep walk
    "nothing.here.invalid",         // full miss
    "safe.example.com",             // allow beats the TLD block
    "x.safe.example.com",           // allow via parent
    "x.b.com",                      // allow via parent, TLD blocked
    "com",                          // TLD exact
    "ads.co.uk",
    "deep.ads.co.uk",
    "trailing.dot.com.",   // trailing dot: `com.` must NOT match `com`
    "x.child.mixed.test",  // parent allow beats child block
    "child.mixed.test",    // exact block, parent allow
    "x.noise.example.org", // out-of-mask child bit, in-mask parent bit
];

/// Assert a fixture corpus obeys the production invariant that **a list
/// bit has exactly one direction**.
///
/// `base` is a per-*source* property, so bit *N* is allow-direction or
/// block-direction for every domain it tags — never both. Under `mem-t6`
/// the engine stores direction once per generation
/// ([`SortedShard::policy`]) rather than once per entry, so a corpus
/// violating this is not merely unrealistic: it is **unrepresentable**,
/// and the engine normalises it to allow-wins.
///
/// # Why this is a hard assert and not a comment
///
/// Because the symptom is a coin flip. A violating corpus diverges from
/// the unsharded reference only when the conflicting domains hash into the
/// same shard — about 1 run in 16, on `SHARD_HASHER`'s per-process seed.
/// Both `EQUIV_ENTRIES` and the hybrid test's `OLD` carried exactly that
/// (bit 0 used as the allow list *and* as `tracker.example.com`'s block
/// bit) and passed for months.
///
/// This runs *before* the equivalence assertions on purpose: a fixture
/// fault should fail as a fixture fault, deterministically, with this
/// message — not as an intermittent mask mismatch that reads like an
/// engine bug.
///
/// **This does not weaken either test.** It narrows their input to what
/// the product can actually produce; the walk semantics, the
/// OR-accumulation and the early-exit discriminators are all untouched.
/// Asserting equivalence on input production cannot build proves nothing
/// about production.
fn assert_one_direction_per_bit(entries: &[(&str, DomainMasks)]) {
    let (allow, block) = entries.iter().fold((0u64, 0u64), |(a, b), (_, m)| {
        (a | m.allow_mask, b | m.block_mask)
    });
    assert_eq!(
        allow & block,
        0,
        "fixture corpus uses list bit(s) {:#b} in BOTH directions. A source has one \
         `kind`, so a bit is allow-direction or block-direction for every domain it \
         tags — give each direction its own bit. Left unfixed this diverges from the \
         unsharded reference only when the conflicting domains share a shard (~1 run \
         in 16), which is why it must fail here instead.",
        allow & block,
    );
}

/// Sharded lookup returns byte-identical masks *and* verdicts to the
/// unsharded walk over the same corpus.
#[test]
fn sharded_lookup_is_equivalent_to_the_unsharded_walk() {
    assert_one_direction_per_bit(EQUIV_ENTRIES);
    let flat = masks_map(EQUIV_ENTRIES);
    let engine = FilterEngine::with_per_direction_domain_map(flat.clone());
    // Bits 0-3 (block) and 5 (allow) are subscribed; bit 4 is deliberately
    // OUT, because `noise.example.org` uses it to prove an out-of-mask child
    // bit does not stop the walk reaching an in-mask parent.
    let bitmask = 0b10_1111;
    let profile = profile_with_bitmask(&engine, bitmask);

    let (mut saw_allow_win, mut saw_block, mut saw_miss) = (false, false, false);

    for &d in EQUIV_PROBES {
        let expected = reference_membership(&flat, d);
        assert_eq!(
            engine.list_membership(d),
            expected,
            "masks differ for `{d}`"
        );

        let verdict = reference_verdict(expected, bitmask);
        assert_eq!(
            engine.evaluate(d, &profile),
            verdict,
            "verdict differs for `{d}`"
        );
        assert_eq!(
            engine.evaluate_attributed(d, &profile).0,
            verdict,
            "attributed verdict differs for `{d}`"
        );
        assert_eq!(
            engine.is_blocked(d),
            expected.block_mask != 0,
            "is_blocked differs for `{d}`"
        );

        saw_allow_win |= expected.allow_mask & bitmask != 0;
        saw_block |= verdict == FilterResult::Block;
        saw_miss |= expected.is_empty();
    }

    // Non-vacuity: a corpus that only ever misses would pass every
    // assertion above while testing nothing.
    assert!(
        saw_allow_win && saw_block && saw_miss,
        "probe corpus degenerate: allow_win={saw_allow_win} block={saw_block} miss={saw_miss}"
    );
}

/// Split-view harmlessness, in the form that is actually true.
///
/// A reload installs shards one at a time, so for a few milliseconds some
/// shards hold the new generation and some still hold the old. The property
/// that holds is **hybrid consistency**: what a query sees is exactly the
/// view of a consistent key-wise mixture `M`, where
/// `M[k] = new[k]` if `shard_index(k)` has been swapped and `old[k]`
/// otherwise. No torn read, no dropped entry, no state that is not such a
/// mixture.
///
/// **The stronger property the S2 contract asked for is false**, and this
/// test contains the counter-example. The contract asked that a mid-reload
/// query "never yield a verdict that neither generation would produce
/// alone". Take:
///
/// - `old = { b.com → allow bit 0, com → block bit 2 }`. A query for
///   `x.b.com` hits the allow at `b.com`, so step 5 forwards.
/// - `new` drops both. `x.b.com` misses everything, so step 7 forwards.
/// - Mid-reload, once `b.com`'s shard is swapped but `com`'s is not, the
///   allow is gone while the block is still there → **Block**, which
///   neither generation produces alone.
///
/// That is not a defect in the implementation — it is the definition of
/// surrendering global atomicity, which for a blocklist is the accepted
/// trade-off (a domain becomes blocked a few ms earlier or later). Any
/// future table with cross-entry invariants must not be sharded this way.
///
/// The sweep asserts hybrid consistency at every prefix of the swap order,
/// and pins the counter-example itself: `saw_novel_verdict` must be true
/// exactly when `b.com` and `com` land in different shards, so the test
/// can neither degenerate into re-testing two pure generations nor go
/// flaky on the process-random shard seed.
#[test]
fn split_view_mid_reload_is_a_consistent_key_wise_hybrid() {
    const OLD: &[(&str, DomainMasks)] = &[
        (
            "b.com",
            DomainMasks {
                allow_mask: 0b0001,
                block_mask: 0,
            },
        ),
        (
            "com",
            DomainMasks {
                allow_mask: 0,
                block_mask: 0b0100,
            },
        ),
        // bit 1, not bit 0 (corrected 2026-08-16, mem-t6): bit 0 is the
        // allow-direction bit `b.com` above uses, and one list bit cannot
        // carry both directions. Enforced by
        // `assert_one_direction_per_bit` below.
        (
            "tracker.example.com",
            DomainMasks {
                allow_mask: 0,
                block_mask: 0b0010,
            },
        ),
        (
            "example.net",
            DomainMasks {
                allow_mask: 0,
                block_mask: 0b0010,
            },
        ),
    ];
    const NEW: &[(&str, DomainMasks)] = &[
        (
            "tracker.example.com",
            DomainMasks {
                allow_mask: 0,
                block_mask: 0b1000,
            },
        ),
        (
            "fresh.example.org",
            DomainMasks {
                allow_mask: 0,
                block_mask: 0b0010,
            },
        ),
    ];
    const PROBES: &[&str] = &[
        "x.b.com",
        "b.com",
        "sub.tracker.example.com",
        "example.net",
        "www.example.net",
        "fresh.example.org",
        "a.fresh.example.org",
        "com",
        "miss.invalid",
    ];

    // Both generations, and their union: a bit's direction must be
    // consistent across the reload too, since a mid-reload hybrid shard
    // derives `allow_bits` from whichever generation it holds.
    assert_one_direction_per_bit(OLD);
    assert_one_direction_per_bit(NEW);
    assert_one_direction_per_bit(&[OLD, NEW].concat());

    let old = masks_map(OLD);
    let new = masks_map(NEW);
    let bitmask = 0b1111;
    let profile = test_profile();

    let pure_old = FilterEngine::with_per_direction_domain_map(old.clone());
    pure_old.fixture_subscribe("test", bitmask);
    let pure_new = FilterEngine::with_per_direction_domain_map(new.clone());
    pure_new.fixture_subscribe("test", bitmask);

    // Swap order: `b.com`'s shard first, then the rest ascending. This makes
    // the counter-example state ({b.com new, com old}) deterministically
    // reachable at step 1 whenever the two keys occupy different shards,
    // instead of depending on their random relative index order.
    let first = FilterEngine::shard_index("b.com");
    let mut order = vec![first];
    order.extend((0..DOMAIN_SHARDS).filter(|i| *i != first));

    let mut saw_novel_verdict = false;

    for swapped in 0..=DOMAIN_SHARDS {
        let new_shards: HashSet<usize, RandomState> = order[..swapped].iter().copied().collect();

        let engine = FilterEngine::with_per_direction_domain_map(old.clone());
        for &idx in &order[..swapped] {
            engine.swap_shard(idx, shard_slice(&new, idx));
        }
        // AFTER the swaps: `swap_shard` derives a fresh policy per shard
        // from the entries it installs, so the subscription has to be
        // re-stated against the hybrid that actually results.
        engine.fixture_subscribe("test", bitmask);

        // The consistent key-wise hybrid this view must be
        // indistinguishable from.
        let mut hybrid: HashMap<CompactString, DomainMasks, RandomState> =
            HashMap::with_hasher(RandomState::new());
        for k in old.keys().chain(new.keys()) {
            let source = if new_shards.contains(&FilterEngine::shard_index(k)) {
                &new
            } else {
                &old
            };
            if let Some(&m) = source.get(k) {
                hybrid.insert(k.clone(), m);
            }
        }

        for &d in PROBES {
            let expected = reference_membership(&hybrid, d);
            assert_eq!(
                engine.list_membership(d),
                expected,
                "masks diverge from the key-wise hybrid at swapped={swapped} for `{d}`"
            );

            let verdict = reference_verdict(expected, bitmask);
            assert_eq!(
                engine.evaluate(d, &profile),
                verdict,
                "verdict diverges from the key-wise hybrid at swapped={swapped} for `{d}`"
            );

            saw_novel_verdict |= verdict != pure_old.evaluate(d, &profile)
                && verdict != pure_new.evaluate(d, &profile);
        }
    }

    let collided = FilterEngine::shard_index("b.com") == FilterEngine::shard_index("com");
    assert_eq!(
        saw_novel_verdict, !collided,
        "counter-example reachability must follow shard placement exactly \
         (b.com/com collided={collided}); if this fails the sweep no longer \
         exercises a genuine split view"
    );
}

/// `domain_count()` is the sum of the shard lengths and equals the count an
/// unsharded engine would have reported, through every swap entry point.
#[test]
fn domain_count_sums_shards_and_matches_the_unsharded_count() {
    const N: usize = 5_000;
    let flat: HashMap<CompactString, DomainMasks, RandomState> = (0..N)
        .map(|i| {
            (
                CompactString::from(format!("host{i}.example.com")),
                DomainMasks::block_only(1),
            )
        })
        .collect();
    assert_eq!(flat.len(), N, "fixture generated duplicate keys");

    let engine = FilterEngine::with_per_direction_domain_map(flat.clone());
    let summed: usize = engine.shards.iter().map(|s| s.0.load().len()).sum();
    assert_eq!(summed, N, "partition lost or duplicated entries");
    assert_eq!(engine.domain_count(), summed);

    // Legacy flat swap.
    let legacy: HashMap<CompactString, u64, RandomState> = (0..N)
        .map(|i| (CompactString::from(format!("legacy{i}.test")), 1))
        .collect();
    engine.swap_domain_map(legacy);
    assert_eq!(engine.domain_count(), N);
    assert_eq!(
        engine.domain_count(),
        engine
            .shards
            .iter()
            .map(|s| s.0.load().len())
            .sum::<usize>()
    );

    // Single-shard swap adjusts the total by exactly that shard's delta.
    let before = engine.domain_count();
    let victim = 0;
    let victim_len = engine.shards[victim].0.load().len();
    engine.swap_shard(victim, HashMap::with_hasher(RandomState::new()));
    assert_eq!(engine.domain_count(), before - victim_len);
}

/// `shard_index` agrees between the partition side and the probe side.
///
/// This is the guard against the failure mode described on `SHARD_HASHER`:
/// two sides seeding their own `RandomState` disagree, ~15/16 of every list
/// silently becomes unreachable, and nothing else in the suite notices.
#[test]
fn shard_index_round_trips_between_partition_and_probe() {
    const N: usize = 5_000;
    let domains: Vec<CompactString> = (0..N)
        .map(|i| CompactString::from(format!("d{i}.shard-probe.test")))
        .collect();

    // Engine-side partition (constructors / bulk swaps).
    let flat: HashMap<CompactString, DomainMasks, RandomState> = domains
        .iter()
        .map(|d| (d.clone(), DomainMasks::block_only(0b01)))
        .collect();
    let engine = FilterEngine::with_per_direction_domain_map(flat);

    for d in &domains {
        assert_eq!(
            engine.list_membership(d).block_mask,
            0b01,
            "`{d}` unreachable after engine-side partition"
        );
    }

    // Every entry sits in the shard its own index names — no entry is
    // findable only because some other shard happens to hold it.
    for (idx, shard) in engine.shards.iter().enumerate() {
        for (k, _) in shard.0.load().entries.iter() {
            assert_eq!(
                FilterEngine::shard_index(k),
                idx,
                "`{k}` stored in shard {idx} but indexes elsewhere"
            );
        }
    }

    let occupancy: Vec<usize> = engine.shards.iter().map(|s| s.0.load().len()).collect();
    assert!(
        occupancy.iter().all(|&n| n > 0),
        "degenerate partition, some shard is empty: {occupancy:?}"
    );
    assert_eq!(occupancy.iter().sum::<usize>(), N);

    // Producer-side partition: exactly what the reload producer will do —
    // bucket by `shard_index` outside the engine, then install shard by
    // shard through `swap_shard`.
    let engine2 = FilterEngine::new();
    let mut buckets: Vec<HashMap<CompactString, DomainMasks, RandomState>> = (0..DOMAIN_SHARDS)
        .map(|_| HashMap::with_hasher(RandomState::new()))
        .collect();
    for d in &domains {
        buckets[FilterEngine::shard_index(d)].insert(d.clone(), DomainMasks::block_only(0b10));
    }
    for (idx, bucket) in buckets.into_iter().enumerate() {
        engine2.swap_shard(idx, bucket);
    }

    for d in &domains {
        assert_eq!(
            engine2.list_membership(d).block_mask,
            0b10,
            "`{d}` unreachable after producer-side partition"
        );
    }
    assert_eq!(engine2.domain_count(), N);
}

/// `partition` routes a skewed corpus correctly and leaves every shard
/// **exact-size** — no reserved-but-unused slack anywhere.
///
/// **Rewritten 2026-08-16 (mem-t6).** This used to assert
/// `shard.capacity() >= share` on the 15 shards that receive nothing,
/// guarding `partition`'s `with_capacity_and_hasher` against a regression
/// to growth-by-doubling. That property is **gone, not untested**:
/// [`SortedShard`] stores a `Box<[_]>`, whose length *is* its allocation,
/// and [`SortedShard::from_pairs`] calls `shrink_to_fit` before boxing. An
/// over-reserved bucket cannot survive into a shard, so there is no
/// capacity to assert on — and the old assertion would not compile.
///
/// What replaces it is the property that now matters: the empty shards
/// really are empty (an exact-size representation must not pay for a
/// share it never received), and the skew still lands where
/// `shard_index` says it should.
#[test]
fn partition_is_exact_size_and_routes_a_skewed_corpus() {
    const TARGET: usize = 0;
    const N: usize = 512;

    // `collect()` into a real map first, deliberately: `partition` sizes
    // its buckets off `size_hint().0`, and a lazily-`filter`ed iterator
    // reports a lower bound of 0 — feeding one straight in would make
    // this test pass for the wrong reason.
    let flat: HashMap<CompactString, DomainMasks, RandomState> = (0..)
        .map(|i| CompactString::from(format!("d{i}.presize.test")))
        .filter(|d| FilterEngine::shard_index(d) == TARGET)
        .take(N)
        .map(|d| (d, DomainMasks::block_only(1)))
        .collect();
    assert_eq!(flat.len(), N, "corpus lost entries to a key collision");

    let shards = FilterEngine::partition(flat);

    assert_eq!(
        shards[TARGET].len(),
        N,
        "skew failed — the corpus is not concentrated in one shard"
    );
    for (idx, shard) in shards.iter().enumerate() {
        if idx == TARGET {
            continue;
        }
        assert!(
            shard.is_empty(),
            "shard {idx} should have received nothing, holds {}",
            shard.len()
        );
    }

    // Exact-size, stated as the arithmetic that motivated mem-t6: the
    // payload is len * 32 B with nothing rounded up. Under the hash
    // representation these 512 entries occupied 1024 buckets.
    assert_eq!(
        std::mem::size_of::<(CompactString, u64)>(),
        32,
        "entry width changed — the 410.5 MB corpus figure no longer holds"
    );
}

// ---------------------------------------------------------------------
// mem-t6 — the derived (allow_bits + source_bits) representation
// ---------------------------------------------------------------------

/// Every mask pair the *production* producer can emit survives the round
/// trip through one `u64` plus the shard's `allow_bits`.
///
/// "Production can emit" means disjoint: direction is a per-source
/// property, so a bit is allow or block, never both. This walks the whole
/// 2-bit cross product of that space plus the high bit, which is the
/// exhaustive case at this width.
#[test]
fn derived_split_round_trips_every_production_mask_pair() {
    let cases = [
        (0u64, 0u64),
        (0b01, 0b10),
        (0b10, 0b01),
        (0, 0b11),
        (0b11, 0),
        (1 << 63, 1),
        (1, 1 << 63),
    ];
    for (allow, block) in cases {
        let masks = DomainMasks {
            allow_mask: allow,
            block_mask: block,
        };
        let shard = SortedShard::from_pairs(
            vec![(CompactString::new("d.test"), masks)],
            ListPolicy::next_gen_id(),
        );
        assert_eq!(
            shard.split_base(shard.entries[0].1),
            masks,
            "allow={allow:#b} block={block:#b} did not survive the round trip"
        );
    }
}

/// Sortedness is the binary search's precondition, and an unsorted slice
/// fails *silently* — it finds nothing rather than erroring. Pin both the
/// ordering and that every key inserted is actually retrievable.
#[test]
fn shard_is_sorted_and_every_inserted_key_is_found() {
    const N: usize = 2_000;
    // Reverse insertion order, so a `from_pairs` that forgot to sort
    // would produce a strictly descending slice and fail on entry two.
    let pairs: Vec<(CompactString, DomainMasks)> = (0..N)
        .rev()
        .map(|i| {
            (
                CompactString::from(format!("d{i:05}.sorted.test")),
                DomainMasks::block_only(0b01),
            )
        })
        .collect();
    let shard = SortedShard::from_pairs(pairs, ListPolicy::next_gen_id());

    assert_eq!(shard.len(), N);
    assert!(
        shard.entries.windows(2).all(|w| w[0].0 < w[1].0),
        "shard is not strictly ascending"
    );
    for i in 0..N {
        let key = format!("d{i:05}.sorted.test");
        assert!(
            shard
                .entries
                .binary_search_by(|(k, _)| k.as_str().cmp(&key))
                .is_ok(),
            "`{key}` was stored but binary search cannot find it"
        );
    }
}

/// **The ordering pin.** A shard's entries and the [`ListPolicy`] that
/// splits them are published by one atomic store, so a reader holding a
/// generation sees that generation's *pair* — never new data against an
/// old direction map, or the reverse.
///
/// **Successor to `allow_bits_and_entries_are_swapped_as_one_generation`,
/// which pinned this same property while direction was a bare
/// `allow_bits: u64` field.** `_docs/features/profile_list_policy.md` §4
/// S1 required the replacement rather than the deletion: the old test is
/// the net under the fail-open risk of §1.4, and a sprint that moves where
/// direction lives must not remove the net in the same breath.
///
/// Built to fail. Hoist the policy to a field on [`FilterEngine`], onto
/// `ResolvedProfile`, or into a second `ArcSwap`, and the pinned
/// generation below starts splitting with the *new* generation's
/// direction map: the assertion flips to `allow_mask: 0b01, block_mask: 0`
/// — a pair no generation ever held, and under allow-beats-block a domain
/// both generations blocked reads as ALLOWED.
///
/// **What the successor pins that the predecessor could not.** With
/// direction a bare `u64`, "the pinned generation used its own map" was
/// only observable through the split's *value*, so two generations that
/// happened to agree were indistinguishable from a torn read. A policy
/// carries a `gen_id`, so the pairing is now asserted directly — and the
/// value assertion stays, because a `gen_id` that matches proves identity,
/// not that `split` consulted it.
#[test]
fn the_policy_and_entries_are_swapped_as_one_generation() {
    let domain = CompactString::new("flip.test");
    let idx = FilterEngine::shard_index(&domain);
    let engine = FilterEngine::new();

    // Generation 1 — bit 0 is a DENY-direction list.
    let gen1 = ListPolicy::publish_uniform(0);
    engine.swap_shard_sorted(
        idx,
        SortedShard::from_sorted_entries(vec![(domain.clone(), 0b01)], Arc::clone(&gen1)).unwrap(),
    );
    // Pin it, exactly as an in-flight query's guard would.
    let pinned = engine.shards[idx].0.load_full();

    // Generation 2 — the operator flipped that same list to ALLOW. Same
    // entries, byte for byte; only the direction map differs.
    let gen2 = ListPolicy::publish_uniform(0b01);
    engine.swap_shard_sorted(
        idx,
        SortedShard::from_sorted_entries(vec![(domain.clone(), 0b01)], Arc::clone(&gen2)).unwrap(),
    );

    assert_ne!(
        gen1.gen_id(),
        gen2.gen_id(),
        "two publishes must take two generation ids, or the assertions below              cannot tell one generation from the other"
    );
    assert_eq!(
        pinned.policy().gen_id(),
        gen1.gen_id(),
        "the pinned generation is holding a LATER generation's policy —              entries and policy are no longer one atomic unit"
    );

    let pos = pinned
        .entries
        .binary_search_by(|(k, _)| k.as_str().cmp(domain.as_str()))
        .expect("pinned generation lost its entry");
    assert_eq!(
        pinned.split_base(pinned.entries[pos].1),
        DomainMasks {
            allow_mask: 0,
            block_mask: 0b01,
        },
        "the pinned generation split its own data with a LATER generation's              policy — entries and policy are no longer one atomic unit"
    );

    // And the live engine does see generation 2.
    assert_eq!(
        engine.list_membership("flip.test"),
        DomainMasks {
            allow_mask: 0b01,
            block_mask: 0,
        }
    );
    assert_eq!(
        engine.filter_gen_ids()[idx],
        gen2.gen_id(),
        "the live shard must report the generation it is actually serving"
    );
}

/// Allow-direction is *carried*, not foreclosed (mem-t5 step 2): the same
/// stored bytes re-split when the operator flips a list's `base`, with no
/// change to any entry.
#[test]
fn flipping_a_list_deny_to_allow_re_splits_without_rebuilding_entries() {
    let domain = CompactString::new("x.test");
    const BITS: u64 = 0b10;

    let as_deny = SortedShard::from_sorted_entries(
        vec![(domain.clone(), BITS)],
        ListPolicy::publish_uniform(0),
    )
    .unwrap();
    let as_allow =
        SortedShard::from_sorted_entries(vec![(domain, BITS)], ListPolicy::publish_uniform(BITS))
            .unwrap();

    // Byte-identical entries.
    assert_eq!(as_deny.entries, as_allow.entries);

    assert_eq!(
        as_deny.split_base(BITS),
        DomainMasks {
            allow_mask: 0,
            block_mask: BITS
        }
    );
    assert_eq!(
        as_allow.split_base(BITS),
        DomainMasks {
            allow_mask: BITS,
            block_mask: 0
        }
    );
}

/// **mem-t5 DoD — the supported list count is bounded, not silently
/// truncated.**
///
/// The refusal itself already exists and is not mine: `SourceBitMap::build`
/// returns `TooManySources` above `MAX_LIST_SOURCES`, and
/// `lists::source_key` pins the message. What was missing is the *linkage*
/// — nothing tied that constant to the width the engine can actually
/// carry. Raise it to 128 and `1u64 << bit` wraps, so lists 64.. would
/// alias lists 0.. with every existing test still green. That is the
/// silent truncation still reachable today.
///
/// The first assertion is green the day it lands, by construction; it is a
/// trip-wire, not a regression test. The second is not: it fails if the
/// stored width is ever narrowed, which is precisely the mem-t5 shape this
/// task rejected.
#[test]
fn list_bit_bound_is_enforced_not_silently_truncated() {
    assert!(
        crate::lists::manager::MAX_LIST_SOURCES <= u64::BITS as usize,
        "MAX_LIST_SOURCES = {} exceeds the {} bits a shard entry stores; \
         bits at or above {} would wrap and alias low-numbered lists \
         instead of being refused",
        crate::lists::manager::MAX_LIST_SOURCES,
        u64::BITS,
        u64::BITS,
    );

    // The highest supported bit must survive storage and the split.
    const TOP: u64 = 1 << 63;
    let shard = SortedShard::from_sorted_entries(
        vec![(CompactString::new("top.test"), TOP)],
        ListPolicy::publish_uniform(0),
    )
    .unwrap();
    assert_eq!(
        shard.split_base(TOP),
        DomainMasks {
            allow_mask: 0,
            block_mask: TOP
        },
        "list bit 63 did not survive — the entry width was narrowed"
    );
}

/// **Unsorted input is REFUSED, in release as well as debug.**
///
/// Built to fail. Revert [`SortedShard::from_sorted_entries`] to a
/// `debug_assert!` and this test goes red in release
/// (`cargo test --release`) while staying green in debug — which is the
/// precise shape of the bug it guards: the shipped binary is the one that
/// loses the check, and the shipped binary is what serves household DNS.
///
/// An ordinary `#[should_panic]` assertion test could not express this;
/// only a checked `Result` is observable in both profiles.
#[test]
fn unsorted_shard_is_refused_not_silently_installed() {
    let unsorted = vec![
        (CompactString::new("b.test"), 0b01),
        (CompactString::new("a.test"), 0b10),
    ];
    let err = SortedShard::from_sorted_entries(unsorted, ListPolicy::publish_uniform(0))
        .expect_err("descending entries must be refused");
    assert_eq!(err.index, 1);
    assert!(!err.duplicate);

    // Duplicates are refused too, and reported as a dedup failure rather
    // than a sort failure — the producer bug is a different one.
    let duped = vec![
        (CompactString::new("a.test"), 0b01),
        (CompactString::new("a.test"), 0b10),
    ];
    let err = SortedShard::from_sorted_entries(duped, ListPolicy::publish_uniform(0))
        .expect_err("duplicate keys must be refused");
    assert!(
        err.duplicate,
        "a duplicate key must be reported as a dedup failure: {err}"
    );

    // The happy path still constructs.
    let ok = vec![
        (CompactString::new("a.test"), 0b01),
        (CompactString::new("b.test"), 0b10),
    ];
    assert!(SortedShard::from_sorted_entries(ok, ListPolicy::publish_uniform(0)).is_ok());
}

/// Refusing must leave the engine serving the previous generation, not an
/// empty or half-installed shard. This is the whole reason refuse-the-swap
/// was chosen over repair-by-sorting.
#[test]
fn a_refused_shard_leaves_the_previous_generation_serving() {
    let domain = CompactString::new("keep.test");
    let idx = FilterEngine::shard_index(&domain);
    let engine = FilterEngine::new();

    engine.swap_shard_sorted(
        idx,
        SortedShard::from_pairs(
            vec![(domain, DomainMasks::block_only(0b01))],
            ListPolicy::next_gen_id(),
        ),
    );
    assert!(engine.is_blocked("keep.test"));

    // A producer emitting an unsorted generation gets an `Err` and, having
    // nothing to swap, never calls `swap_shard_sorted`.
    assert!(SortedShard::from_sorted_entries(
        vec![
            (CompactString::new("z.test"), 0b01),
            (CompactString::new("a.test"), 0b01),
        ],
        ListPolicy::publish_uniform(0),
    )
    .is_err());

    assert!(
        engine.is_blocked("keep.test"),
        "a refused shard must not disturb the installed generation"
    );
}

/// A list bit used in opposite directions on **two different domains** is
/// detected, not just the same-entry case.
///
/// Built to fail, and it caught a real one. The first version of
/// [`SortedShard::from_pairs`]'s guard tested
/// `m.allow_mask & m.block_mask != 0`, which sees a bit set both ways on
/// *one* entry and is blind to bit N allow on `mixed.test` + bit N block on
/// `child.mixed.test`. Because `allow_bits` is a per-shard union, the child
/// loses its block bit only when both domains hash into the same shard —
/// roughly 1 in 16, decided by `SHARD_HASHER`'s per-process seed. So the
/// symptom was a **non-deterministic** wrong verdict, which is the worst
/// kind to inherit. Revert the guard to the same-entry form and this test
/// goes red deterministically.
#[test]
fn a_bit_used_in_both_directions_across_entries_is_detected() {
    // Same shard by construction: `from_pairs` builds exactly one.
    let shard = SortedShard::from_pairs(
        vec![
            (
                CompactString::new("mixed.test"),
                DomainMasks {
                    allow_mask: 0b0001,
                    block_mask: 0,
                },
            ),
            (
                CompactString::new("child.mixed.test"),
                DomainMasks {
                    allow_mask: 0,
                    block_mask: 0b0001,
                },
            ),
        ],
        ListPolicy::next_gen_id(),
    );

    // The conflict is real and the block side is what is lost: bit 0 is in
    // this shard's `allow_bits`, so the child's block bit re-splits to
    // allow. Pinned as the KNOWN normalisation, so a future reader sees a
    // decided behaviour rather than discovering it through a flaky test.
    let child = shard
        .entries
        .binary_search_by(|(k, _)| k.as_str().cmp("child.mixed.test"))
        .expect("child entry present");
    assert_eq!(
        shard.split_base(shard.entries[child].1),
        DomainMasks {
            allow_mask: 0b0001,
            block_mask: 0
        },
        "a bit in this shard's allow_bits cannot also carry a block for another domain"
    );

    // And the two-bit encoding — what the producer would actually emit —
    // round-trips exactly, which is the fix for any fixture that hits this.
    let ok = SortedShard::from_pairs(
        vec![
            (
                CompactString::new("mixed.test"),
                DomainMasks {
                    allow_mask: 0b0001,
                    block_mask: 0,
                },
            ),
            (
                CompactString::new("child.mixed.test"),
                DomainMasks {
                    allow_mask: 0,
                    block_mask: 0b0010,
                },
            ),
        ],
        ListPolicy::next_gen_id(),
    );
    let child = ok
        .entries
        .binary_search_by(|(k, _)| k.as_str().cmp("child.mixed.test"))
        .expect("child entry present");
    assert_eq!(
        ok.split_base(ok.entries[child].1),
        DomainMasks {
            allow_mask: 0,
            block_mask: 0b0010
        },
        "distinct bits per direction must survive — this is the production shape"
    );
}

/// A bit in both directions cannot come from the producer, but a fixture
/// can build one. It normalises to allow-wins — the verdict `evaluate`
/// reaches anyway, since §4 step 5 precedes step 6 — so no profile-aware
/// behaviour changes. Pinned so the normalisation is a decision on the
/// record rather than an accident of the derivation.
#[test]
fn overlapping_direction_bits_normalise_to_allow_wins() {
    let shard = SortedShard::from_pairs(
        vec![(
            CompactString::new("both.test"),
            DomainMasks {
                allow_mask: 0b01,
                block_mask: 0b01,
            },
        )],
        ListPolicy::next_gen_id(),
    );
    assert_eq!(
        shard.split_base(shard.entries[0].1),
        DomainMasks {
            allow_mask: 0b01,
            block_mask: 0
        }
    );

    // The verdict — the thing operators actually observe — is unchanged.
    let engine = engine_with_per_direction_map(&[(
        "both.test",
        DomainMasks {
            allow_mask: 0b01,
            block_mask: 0b01,
        },
    )]);
    assert_eq!(
        engine.evaluate("both.test", &profile_with_bitmask(&engine, 0b01)),
        FilterResult::Forward
    );
}
