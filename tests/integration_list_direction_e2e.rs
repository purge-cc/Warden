//! End-to-end characterisation of list **direction** at the engine's
//! crate-public surface.
//!
//! A blocklist the operator imports carries a direction: `base = deny`
//! blocks the domains it lists, `base = allow` re-opens them. The
//! machinery for that is built and live — `lists::manager` routes each
//! source's bit into [`DomainMasks::allow_mask`] or
//! [`DomainMasks::block_mask`], and `filter::engine::evaluate_inner`
//! consults the two in that order (§4 step 5 before step 6). What did
//! **not** exist before this file is a test that joins the two halves:
//! there were unit tests on the mask routing (`lists::manager`) and unit
//! tests on the evaluation (`filter::engine`), and nothing that asserted
//! the resulting verdict for a domain an allow-direction list covers.
//!
//! These are **characterisation** tests, not TDD: the behaviour they pin
//! already exists, so they passed the first time they ran. Each one was
//! therefore deliberately broken and observed red — see
//! `NOTES-direction-tests.md`. A test nobody has seen fail measures
//! nothing.
//!
//! # Every assertion here must discriminate
//!
//! The first draft of this file was **not** capable of failing, and
//! disabling the engine's allow path in a scratch build proved it: three
//! of the four tests still passed. The reason is worth stating, because
//! it is easy to reintroduce. A domain whose `block_mask` is empty (or
//! whose block bits the profile does not subscribe) **forwards anyway**,
//! by §4 step 7 "nothing matched". A test that allow-forwards such a
//! domain cannot tell "the allow list worked" from "no list matched at
//! all" — two empty arms reading as success.
//!
//! So every fixture below gives the domain a **subscribed block bit**.
//! Forward is then reachable only if the allow direction genuinely fires,
//! and every Block assertion additionally pins its
//! [`BlockSource`] so a block from the wrong layer cannot pass for the
//! right one.
//!
//! What this file pins:
//!
//! 1. A contested domain — allow bit *and* block bit, both subscribed —
//!    **forwards**. Allow beats block among lists.
//! 2. Moving those same bits from `allow_mask` into `block_mask` **flips
//!    the verdict to Block**, attributed to the list. The pair catches a
//!    routing regression in either direction: arm A goes red if
//!    everything lands in `block_mask`, arm B goes red if everything
//!    lands in `allow_mask`.
//! 3. An admin `$important` deny rule blocks the same domain **despite**
//!    the allow mask, attributed to the *rule* (invariant W1.2 — the
//!    operator's own config is sovereign over any list).
//! 4. A `block_all` profile blocks it too, attributed to `AdminBlock`.
//!    Allow-direction lists are deliberately *soft*: they do not pierce a
//!    deny-all posture.
//!
//! (3) and (4) are the product's threat model, not incidental detail. If
//! either regressed, a list fetched from a URL could punch a hole in a
//! deny-all profile — which is precisely the risk the `base = allow`
//! trust gate exists to govern.

use std::collections::HashMap;
use std::sync::Arc;

use ahash::RandomState;
use compact_str::CompactString;

use purge_warden::filter::cname::BlockSource;
use purge_warden::filter::engine::{DomainMasks, FilterEngine, FilterResult};
use purge_warden::filter::rules::{parse_rules, RuleAction};
use purge_warden::profiles::profile::ResolvedProfile;

/// Bit index 0 — the slot every test gives to the allow-direction list.
const ALLOW_BIT: u64 = 1 << 0;
/// Bit index 1 — the slot every test gives to the block-direction list.
const BLOCK_BIT: u64 = 1 << 1;
/// Every fixture profile subscribes to both slots, so a bit is never
/// inert merely because the profile ignores it.
const BOTH_BITS: u64 = ALLOW_BIT | BLOCK_BIT;

/// The single domain under test. Lowercase by construction: the engine
/// carries a `debug_assert` that lookups are pre-normalised.
const CONTESTED: &str = "contested.example";

/// Build an engine holding exactly one domain with the per-direction
/// masks already split — the shape `lists::manager` installs on the hot
/// path.
fn engine_with(domain: &str, masks: DomainMasks) -> FilterEngine {
    let mut map: HashMap<CompactString, DomainMasks, RandomState> =
        HashMap::with_hasher(RandomState::new());
    map.insert(CompactString::new(domain), masks);
    FilterEngine::with_per_direction_domain_map(map)
}

/// A profile subscribing to both list slots on `engine`.
///
/// The subscription is deliberately kind-agnostic — direction comes from the
/// published policy, never from the profile. `plp-s3` moved the subscription
/// out of `ResolvedProfile` for the same reason (a positional mask on the
/// profile can meet a corpus that re-assigned the bits it names), so the
/// fixture now states it to the engine.
fn profile_subscribing_both(engine: &FilterEngine) -> ResolvedProfile {
    let mut profile = ResolvedProfile::permissive_default();
    profile.unfiltered = false;
    engine.fixture_subscribe(&profile.name, BOTH_BITS);
    profile
}

/// The contested fixture: the domain is on an allow-direction list (bit 0)
/// *and* a block-direction list (bit 1), both subscribed. Absent the allow
/// direction this domain blocks, which is what makes every Forward
/// assertion below load-bearing.
fn contested_masks() -> DomainMasks {
    DomainMasks {
        allow_mask: ALLOW_BIT,
        block_mask: BLOCK_BIT,
    }
}

/// A domain carried by an allow-direction list and a block-direction list
/// at once, with the profile subscribed to both, forwards.
///
/// This is the "allow beats block among lists" half of the precedence
/// rule in `evaluate_inner`: §4 step 5 (allow) is consulted before §4
/// step 6 (block), so the allow hit short-circuits the block hit.
#[test]
fn contested_domain_forwards_when_allow_and_block_bits_are_both_subscribed() {
    let engine = engine_with(CONTESTED, contested_masks());
    let profile = profile_subscribing_both(&engine);

    assert_eq!(
        engine.evaluate(CONTESTED, &profile),
        FilterResult::Forward,
        "a domain on both an allow-direction and a block-direction list must \
         forward — allow wins among lists (§4 step 5 precedes step 6)"
    );
}

/// Move the same two bits from `allow_mask` into `block_mask` and the
/// verdict must flip Forward → Block.
///
/// **This is not a restatement of the test above.** It is the control that
/// gives it meaning, and the two arms fail on opposite regressions:
///
/// - Arm A (Forward) goes red if the producer stopped routing allow-
///   direction sources into `allow_mask` — the neutrality-06 defect, where
///   an allow list blocked what it was imported to permit.
/// - Arm B (Block) goes red if the producer routed *everything* into
///   `allow_mask`. Arm A alone cannot see that: it would still forward.
///
/// Note the literal "swap the two mask values" is not what arm B does, and
/// deliberately so: with both bits subscribed, swapping leaves `allow_mask`
/// non-empty, so allow still wins and the verdict does not flip. The
/// meaningful inversion is moving the bits *between directions*.
#[test]
fn moving_the_bits_between_the_two_masks_flips_the_verdict() {
    // Arm A — the allow bit is present, so the domain forwards despite the
    // subscribed block bit.
    let allowing = engine_with(CONTESTED, contested_masks());
    let profile = profile_subscribing_both(&allowing);
    assert_eq!(
        allowing.evaluate(CONTESTED, &profile),
        FilterResult::Forward,
        "with a bit in allow_mask the contested domain forwards"
    );

    // Arm B — the same two bits, both now block-direction. Nothing else
    // changed: same domain, same profile, same subscription.
    let blocking = engine_with(
        CONTESTED,
        DomainMasks {
            allow_mask: 0,
            block_mask: BOTH_BITS,
        },
    );
    blocking.fixture_subscribe(&profile.name, BOTH_BITS);
    let (verdict, source) = blocking.evaluate_attributed(CONTESTED, &profile);
    assert_eq!(
        verdict,
        FilterResult::Block,
        "with both bits in block_mask and none in allow_mask the same domain \
         under the same profile must block"
    );
    assert!(
        matches!(source, Some(BlockSource::List(_))),
        "the block must be attributed to the Tier 1 list layer, got {source:?}"
    );
}

/// An admin `$important` deny rule blocks a domain an allow-direction
/// list covers. Invariant W1.2: the operator's own config is sovereign.
///
/// In `evaluate_inner` the rule wins at `priority_scan` before the Tier 1
/// walk is even armed (`want_bits` requires `best_result.is_none()`), so
/// the allow mask is never consulted.
#[test]
fn admin_important_deny_overrides_an_allow_direction_list() {
    let engine = engine_with(CONTESTED, contested_masks());

    // Control: without the admin rule the allow direction really does
    // forward this domain, over a subscribed block bit. Without this the
    // Block below would prove nothing — it could just as well mean the
    // allow mask never worked at all.
    assert_eq!(
        engine.evaluate(CONTESTED, &profile_subscribing_both(&engine)),
        FilterResult::Forward,
        "control: the allow-direction list forwards this domain on its own"
    );

    let mut profile = profile_subscribing_both(&engine);
    let rules = parse_rules(&format!("||{CONTESTED}^$important"));
    assert_eq!(
        rules.len(),
        1,
        "the admin rule must parse to exactly one rule"
    );
    assert_eq!(
        rules[0].action,
        RuleAction::Block,
        "the admin rule must be a deny"
    );
    assert!(rules[0].important, "the admin rule must carry $important");
    profile.rules = Arc::new(rules);

    let (verdict, source) = engine.evaluate_attributed(CONTESTED, &profile);
    assert_eq!(
        verdict,
        FilterResult::Block,
        "an admin $important deny is sovereign over an allow-direction list \
         (W1.2) — a downloaded list must never unblock what the operator \
         explicitly denied"
    );
    // Pin the *reason*, not just the verdict: the fixture also carries a
    // subscribed block bit, so a Block alone would not prove the rule was
    // what stopped it.
    match source {
        Some(BlockSource::Rule(label)) => assert_eq!(
            label.as_str(),
            CONTESTED,
            "the block must be attributed to the admin rule for this domain"
        ),
        other => panic!("expected a rule-attributed block, got {other:?}"),
    }
}

/// A `block_all` profile blocks a domain an allow-direction list covers.
///
/// Allow-direction lists are deliberately *soft*: `block_all` is a
/// profile-level operator policy ("deny everything except what I allow")
/// and only an admin allow rule pierces it. If this regressed, importing
/// a remote allow-list would defeat a deny-all posture wholesale.
#[test]
fn block_all_is_not_pierced_by_an_allow_direction_list() {
    let engine = engine_with(CONTESTED, contested_masks());

    // Control: with block_all off, the allow direction forwards this
    // domain over its subscribed block bit.
    assert_eq!(
        engine.evaluate(CONTESTED, &profile_subscribing_both(&engine)),
        FilterResult::Forward,
        "control: with block_all off the allow-direction list forwards"
    );

    let mut profile = profile_subscribing_both(&engine);
    profile.block_all = true;

    let (verdict, source) = engine.evaluate_attributed(CONTESTED, &profile);
    assert_eq!(
        verdict,
        FilterResult::Block,
        "block_all must not be pierced by an allow-direction list — only an \
         admin allow rule may open a hole in a deny-all profile"
    );
    assert!(
        matches!(source, Some(BlockSource::AdminBlock)),
        "the block must be attributed to the block_all policy, not to a list; \
         got {source:?}"
    );
}
