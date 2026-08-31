//! **Adversarial bit remapping** — `_docs/features/profile_list_policy.md`
//! §2.4, "il modo di fallire da testare per primo", test 1.
//!
//! A list's bit is **positional, not identitary**: `source_key.rs` assigns
//! `bit = i` over the merged sources vector, so removing a list slides every
//! later list down one bit. The doc's scenario is `[L0, L1, L2]` → remove
//! `L1` → `L2` moves from bit 2 to bit 1, with a profile that permits *only*
//! `L2`.
//!
//! # What is actually at risk, stated precisely
//!
//! The danger is not a remap. It is a remap plus **two publishers**: a
//! direction map materialised against one bit assignment, read against
//! another. §1.4 records the asymmetry — a *subset* error over-blocks and
//! someone complains; a *superset* error puts a deny-list's bit on the allow
//! side, allow beats block, and every domain on that list silently stops
//! being blocked with no crash and no step in any counter.
//!
//! # Why this test is green at HEAD, and why that is the point
//!
//! At HEAD direction travels **inside the corpus** — `SortedShard` holds
//! `entries` and `allow_bits` in one `Arc` — so a stale profile mask can
//! only ever be read against the direction map of the generation whose
//! entries it is being ANDed with. The cross-pairing therefore *over*-blocks
//! and cannot fail open. This file pins that property in its current shape
//! so that S1, which moves where the direction lives, has to keep it.
//!
//! **A test that is green before the change it guards is worth nothing
//! unless the unsafe variant is shown to be red.** So every pairing also
//! computes the verdict the forbidden architecture would produce — direction
//! taken from the *profile's* generation instead of the corpus's — and
//! [`the_forbidden_pairing_really_does_fail_open`] asserts that variant
//! ALLOWS a domain that only a deny-list carries. Without that arm the green
//! assertions below would be satisfied by an engine that had stopped
//! consulting direction at all.

use compact_str::CompactString;
use std::sync::Arc;

use purge_warden::config::loader::load_config;
use purge_warden::config::schema::ConfigV1;
use purge_warden::filter::engine::{
    FilterEngine, FilterResult, ListPolicy, PolicyMasks, ProfileMasks, SortedShard,
};
use purge_warden::lists::manager::merge_sources_with_blocklists;
use purge_warden::lists::source_key::SourceBitMap;
use purge_warden::profiles::profile::ResolvedProfile;
use purge_warden::profiles::resolver::ProfileResolver;

/// Carried only by `l0`, a deny-list, in **both** generations.
const L0_ONLY: &str = "l0-only.test";
/// Carried only by `l1`, a deny-list, which generation B removes.
const L1_ONLY: &str = "l1-only.test";
/// Carried only by `l2`, the allow-direction list that slides bit 2 → bit 1.
const L2_ONLY: &str = "l2-only.test";

/// `l1` present (generation A) or absent (generation B).
fn config_toml(with_l1: bool) -> String {
    let l1 = if with_l1 {
        "[[blocklists]]\n\
         id = \"l1\"\n\
         display_name = \"L1\"\n\
         url = \"https://lists.test/l1.txt\"\n\
         format = \"domains\"\n\
         base = \"deny\"\n\
         tags = [\"t1\"]\n\n"
    } else {
        ""
    };
    format!(
        "schema_version = 3\n\n\
         [server]\n\
         default_profile = \"only-l2\"\n\n\
         # Subscribes to l2 and NOTHING else — the doc's \"un profilo che\n\
         # permetteva *solo* L2\".\n\
         [profiles.only-l2]\n\
         display_name = \"Only L2\"\n\
         tags = [\"t2\"]\n\n\
         [[blocklists]]\n\
         id = \"l0\"\n\
         display_name = \"L0\"\n\
         url = \"https://lists.test/l0.txt\"\n\
         format = \"domains\"\n\
         base = \"deny\"\n\
         tags = [\"t0\"]\n\n\
         {l1}\
         [[blocklists]]\n\
         id = \"l2\"\n\
         display_name = \"L2\"\n\
         url = \"https://lists.test/l2.txt\"\n\
         format = \"domains\"\n\
         base = \"allow\"\n\
         trust = \"remote-unsigned\"\n\
         accept_unsigned_allow = true\n\
         tags = [\"t2\"]\n\n\
         [upstream]\n\
         servers = [\"192.0.2.1:53\"]\n"
    )
}

/// One generation: its bit assignment, its direction map, and the profile
/// resolved against that same assignment.
struct Generation {
    label: &'static str,
    bits: SourceBitMap,
    /// The operator's policy projected onto **this** generation's bits.
    ///
    /// `plp-s3` replaced the bare `allow_bits: u64`: direction is per profile
    /// now, and it is materialised here, at publish time, against the
    /// assignment `bits` just made.
    policy: PolicyMasks,
    profile: Arc<ResolvedProfile>,
    /// The domains this generation's corpus carries, with the source bits
    /// **this** assignment gives them.
    corpus: Vec<(&'static str, u64)>,
}

fn build(label: &'static str, with_l1: bool) -> Generation {
    let dir = tempfile::tempdir().unwrap();
    let v2 = dir.path().join("config.toml");
    std::fs::write(&v2, config_toml(with_l1)).unwrap();
    // `plp-s3`: the fixture stays in its v2 shape and is put through the real
    // migration, so what this file exercises is the config an operator would
    // actually be running after the cutover — not a v3 twin written by hand
    // to produce the masks the assertions want.
    let path = dir.path().join("config.v3.toml");
    purge_warden::cli::commands::migrate::migrate_v2_to_v3(&v2, &path, false)
        .unwrap_or_else(|e| panic!("{label}: fixture must migrate: {e:#}"));
    let config: ConfigV1 = load_config(&path, time::OffsetDateTime::now_utc())
        .map(|l| l.config)
        .unwrap_or_else(|e| panic!("{label}: migrated fixture config must load: {e:?}"));

    let (merged, _trust) = merge_sources_with_blocklists(&config.lists.sources, &config.blocklists);
    let bits = SourceBitMap::build(&merged, &config.blocklists).unwrap();
    let policy = bits.project_policy(&config.blocklists, &config.profiles);
    let resolver_bits = SourceBitMap::build(&merged, &config.blocklists).unwrap();
    let profile = ProfileResolver::build(
        &config,
        &resolver_bits,
        &purge_warden::config::custom_list::CustomListStore::new(),
    )
    .default_profile()
    .unwrap_or_else(|| panic!("{label}: the config declares a default profile"));

    let bit_of = |id: &str| {
        let id = purge_warden::config::schema::Id::new(id.to_string()).unwrap();
        1u64 << bits
            .bit_for_v1_id(&id)
            .unwrap_or_else(|| panic!("{label}: no bit for `{id}`"))
    };
    let mut corpus = vec![(L0_ONLY, bit_of("l0")), (L2_ONLY, bit_of("l2"))];
    if with_l1 {
        corpus.push((L1_ONLY, bit_of("l1")));
    }

    Generation {
        label,
        bits,
        policy,
        profile,
        corpus,
    }
}

/// Install a generation's corpus through the **production** shard path:
/// partition with the engine's own hasher, then
/// `SortedShard::from_sorted_entries` + `swap_shard_sorted`. Not
/// `from_pairs` — see the module doc of `plp_s1_verdict_golden.rs`.
fn engine_for(gen: &Generation) -> FilterEngine {
    let engine = FilterEngine::new();
    let shards = purge_warden::filter::engine::DOMAIN_SHARDS;
    let mut buckets: Vec<Vec<(CompactString, u64)>> = vec![Vec::new(); shards];
    for (domain, bits) in &gen.corpus {
        buckets[FilterEngine::shard_index(domain)].push((CompactString::new(domain), *bits));
    }
    // One policy per generation, cloned into every shard — exactly what the
    // production refresh loop does. Minting one per shard would make each
    // shard its own generation and quietly destroy the scenario.
    let policy = ListPolicy::publish(gen.policy.clone());
    for (idx, mut entries) in buckets.into_iter().enumerate() {
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let shard = SortedShard::from_sorted_entries(entries, Arc::clone(&policy))
            .unwrap_or_else(|e| panic!("{}: shard {idx} refused: {e}", gen.label));
        engine.swap_shard_sorted(idx, shard);
    }
    engine
}

/// Is `domain` allowed **because an allow-direction list matched**?
/// `FilterResult` cannot say; the fail-open direction is exactly this state,
/// so it has to be reconstructed.
fn is_allow_hit(engine: &FilterEngine, profile: &ResolvedProfile, domain: &str) -> bool {
    engine.evaluate(domain, profile) == FilterResult::Forward
        && engine.list_membership_for(domain, &profile.name).allow_mask != 0
}

/// The masks the fixture's only profile gets from a generation's projection.
fn masks_of(gen: &Generation) -> ProfileMasks {
    gen.policy
        .per_profile
        .get("only-l2")
        .copied()
        .unwrap_or_else(|| panic!("{}: the projection covers every profile", gen.label))
}

/// The remap the whole file depends on. If `l2` did not move, every
/// assertion below is about a scenario that never happened.
#[test]
fn removing_a_list_really_does_slide_the_later_bits() {
    let a = build("gen-A", true);
    let b = build("gen-B", false);
    let l2 = purge_warden::config::schema::Id::new("l2".to_string()).unwrap();
    assert_eq!(
        a.bits.bit_for_v1_id(&l2),
        Some(2),
        "with l1 present, l2 must own bit 2"
    );
    assert_eq!(
        b.bits.bit_for_v1_id(&l2),
        Some(1),
        "removing l1 must slide l2 down to bit 1 — this is the positional \
         assignment §2.4 measured at source_key.rs, and the premise of this file"
    );
    assert_ne!(
        masks_of(&a),
        masks_of(&b),
        "the profile permits only l2, so its mask must move with l2's bit; if \
         the two masks were equal the cross-pairings below would be no-ops"
    );
}

/// **The property, restated for the architecture that now carries it.**
///
/// Under `plp-s1` the two axes were (corpus generation) × (profile
/// generation), because `ResolvedProfile` carried the subscription mask and
/// could therefore be stale against the corpus it met. `plp-s3` removed that
/// field: the profile carries an **identity**, and every mask is materialised
/// beside the corpus it interprets.
///
/// The sweep is unchanged — both corpora × both resolved profiles — but it is
/// now safe for a *structural* reason instead of an arithmetic one. That is
/// the whole of D-ARCH-1, and it is why
/// [`the_forbidden_pairing_really_does_fail_open`] and
/// [`publishing_a_foreign_generations_policy_is_observably_fail_open`] both
/// stay: without them this test would be green because the hazard has become
/// unreachable, which reads identically to green because the fixture is
/// toothless.
#[test]
fn a_deny_only_domain_is_never_allowed_under_any_cross_pairing() {
    let gens = [build("gen-A", true), build("gen-B", false)];
    for corpus in &gens {
        let engine = engine_for(corpus);
        for policy in &gens {
            for deny_only in [L0_ONLY, L1_ONLY] {
                // `l1-only` is not in generation B's corpus at all; absence
                // is not the property under test.
                if !corpus.corpus.iter().any(|(d, _)| *d == deny_only) {
                    continue;
                }
                assert!(
                    !is_allow_hit(&engine, &policy.profile, deny_only),
                    "corpus {} + policy {}: `{deny_only}` is carried only by a \
                     deny-direction list, and an allow-direction verdict for it \
                     is the fail-open of §1.4 — every domain on that list \
                     silently stops being blocked",
                    corpus.label,
                    policy.label,
                );
            }
        }
    }
}

/// The allow side still works when corpus and policy agree — otherwise the
/// test above is satisfied by an engine that allows nothing.
#[test]
fn the_allow_list_still_allows_when_the_generations_agree() {
    for gen in [build("gen-A", true), build("gen-B", false)] {
        let engine = engine_for(&gen);
        assert!(
            is_allow_hit(&engine, &gen.profile, L2_ONLY),
            "{}: `{L2_ONLY}` is carried by the allow-direction list this profile \
             subscribes to; if it is not an allow-hit, the allow side is dead and \
             the never-allowed assertions measure nothing",
            gen.label,
        );
    }
}

/// **The control arm that makes the green above non-vacuous.**
///
/// Recomputes the same pairing with direction taken from the *policy's*
/// generation instead of the corpus's — the architecture §2.4 forbids, where
/// the mask travels with the profile under a second `ArcSwap`. Under it,
/// `l1-only` — deny-only in generation A's corpus — is ALLOWED.
///
/// This is arithmetic on published values, not a claim about any code path
/// that exists: it exists to prove that the pairing the green tests exercise
/// is genuinely dangerous, so their passing is evidence about the
/// implementation rather than about the scenario being toothless.
#[test]
fn the_forbidden_pairing_really_does_fail_open() {
    let a = build("gen-A", true);
    let b = build("gen-B", false);

    let l1_bits_in_a = a
        .corpus
        .iter()
        .find(|(d, _)| *d == L1_ONLY)
        .map(|(_, bits)| *bits)
        .expect("generation A carries l1-only");

    // What the engine actually does: direction from the corpus the entries
    // came from.
    let honest_allow = l1_bits_in_a & masks_of(&a).allow;
    assert_eq!(
        honest_allow, 0,
        "direction read against the corpus's own generation must not put a \
         deny-list bit on the allow side"
    );

    // What the forbidden architecture would do: direction from the policy's
    // generation, entries from another.
    let forbidden_allow = l1_bits_in_a & masks_of(&b).allow;
    assert_ne!(
        forbidden_allow, 0,
        "the control arm is toothless: taking direction from the policy's \
         generation was supposed to allow a deny-only domain. If this is zero \
         the fixture no longer reproduces the remap hazard, and the green \
         assertions in this file stop being evidence"
    );
}

/// **The observed control arm.** Same claim as
/// [`the_forbidden_pairing_really_does_fail_open`], but read off the engine
/// instead of computed from published values.
///
/// `SortedShard::from_sorted_entries` *accepts* a policy rather than deriving
/// it — its own doc says the caller is responsible for the pairing — so the
/// forbidden state is still constructible by hand. This builds it: generation
/// A's corpus, generation B's policy, and then asks the engine.
///
/// `l1-only` is carried in generation A **only** by `l1`, a deny-direction
/// list, on bit 1. In generation B, bit 1 belongs to `l2`, which the profile
/// treats as allow. So the mismatched pair reports an ALLOW for a domain both
/// real generations block — the fail-open of §1.4, observed rather than
/// argued.
///
/// It asserts the DANGER, not the product: a green here means the hazard is
/// real, which is what makes the production path's structural avoidance of it
/// worth having. If this ever goes red, the fixture has stopped reproducing
/// the remap and every green assertion in this file needs re-examining.
#[test]
fn publishing_a_foreign_generations_policy_is_observably_fail_open() {
    let a = build("gen-A", true);
    let b = build("gen-B", false);

    let engine = FilterEngine::new();
    let shards = purge_warden::filter::engine::DOMAIN_SHARDS;
    let mut buckets: Vec<Vec<(CompactString, u64)>> = vec![Vec::new(); shards];
    for (domain, bits) in &a.corpus {
        buckets[FilterEngine::shard_index(domain)].push((CompactString::new(domain), *bits));
    }
    // A's entries, B's policy — the pairing D-ARCH-1 exists to make
    // unreachable through the production path.
    let foreign = ListPolicy::publish(b.policy.clone());
    for (idx, mut entries) in buckets.into_iter().enumerate() {
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        engine.swap_shard_sorted(
            idx,
            SortedShard::from_sorted_entries(entries, Arc::clone(&foreign)).unwrap(),
        );
    }

    assert!(
        is_allow_hit(&engine, &a.profile, L1_ONLY),
        "the control arm is toothless: `{L1_ONLY}` is deny-only in generation A \
         and its bit is the allow-list's bit in generation B, so a foreign \
         policy was supposed to allow it. If this is not an allow-hit the \
         fixture no longer reproduces the remap hazard"
    );
}
