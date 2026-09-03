//! Lock-free filter engine backed by [`DOMAIN_SHARDS`] independent
//! `ArcSwap<SortedShard>` cells with per-list bitmasks.
//!
//! Each domain is stored once, tagged with a `u64` of **source bits** — the
//! union of the list bits that contain it. Callers see that as a
//! [`DomainMasks`] pair (block-direction and allow-direction, `base = allow`),
//! recovered per probe from the shard's own [`ListPolicy`]; direction is a
//! per-*source* property, so storing it per domain was storing one global
//! fact 12.8 M times. Each profile has its own per-direction mask pair,
//! materialised on the generation's `ListPolicy` and reached by profile id —
//! **not** a field on `ResolvedProfile` (a `list_bitmask` field there did two
//! jobs, and it travelled under a different `ArcSwap` from the corpus that
//! gave its bits meaning). Filtering is a shard select plus a binary search
//! plus a handful of bitwise ANDs — zero allocation, zero lock.
//!
//! The hot path (`evaluate`) does: per-suffix shard select → `ArcSwap` load →
//! binary search with subdomain walk → admin layer (rules + `allow_domains`
//! / `deny_domains` HashSets) → Tier 1 allow-mask AND → Tier 1 block-mask AND.
//! Background list refresh calls [`FilterEngine::swap_shard_sorted`] to
//! replace one shard at a time, or
//! `swap_domain_map` (legacy, single-mask input treated as block-only) to
//! replace every shard at once.
//!
//! Each shard is an exact-size sorted slice ([`SortedShard`]), not a
//! `HashMap`. Lookup is O(log n) rather than O(1) — still zero-allocation and
//! zero-lock, which is what the hot-path rule requires. See [`SortedShard`]
//! for why one `u64` replaced two.
//!
//! # Sharding
//!
//! The map is split into [`DOMAIN_SHARDS`] cells keyed on
//! [`FilterEngine::shard_index`] of the full domain. This exists for **reload
//! peak memory**, not for throughput: with one `ArcSwap` a reader holding the
//! old `Arc` keeps it alive until it finishes, so old and new generations must
//! coexist — measured 780 MB steady against a 2.02 GB peak. Sharding does not
//! remove the coexistence, it *bounds* it to the shard in flight (measured
//! 43.0 MB at N = 16).
//!
//! The producer is `lists::manager::ListManager::refresh`
//! (`src/lists/manager.rs`): it builds each shard from spill records and
//! installs it one at a time via [`FilterEngine::swap_shard_sorted`], never
//! materialising a flat map. That path is reached from both
//! `cli::commands::start`'s boot/reload paths and
//! `cli::commands::update::run_update`'s foreground refresh — every caller
//! that goes through `ListManager::refresh`. The measured producer transient
//! on the integrated tree is 302.9 MB (flat) vs 60.1 MB (sharded) at
//! N = 2 000 000; the 43.0 MB figure above is a projection at a different N
//! and was not re-measured against the shipped producer.
//!
//! The flat path has no production caller left on the list-refresh side. Every
//! node — clustering or not — now installs shard-at-a-time via
//! [`FilterEngine::swap_shard_sorted`]; the clustering-primary branch that
//! rebuilt one full map to publish a sync artifact was deleted with the
//! artifact itself. The flat entry points remain for `init`'s one-shot load
//! and for tests, and still pay what `FilterEngine::partition`'s `# Memory`
//! section describes. The hot-path cost below, by contrast, is paid
//! unconditionally.
//!
//! Steady memory is unchanged by construction: 16 shards sum to exactly the
//! same 16 777 216 hashbrown buckets as one map. The cost is on the hot path
//! and is permanent, not confined to reload — each suffix of a query hashes to
//! a different shard, so the walk does one `ArcSwap` load *per probe*
//! (measured mean 2.76) instead of one per call. Measured +139 ns on a 236 ns
//! lookup, which is +0.11 % of a real 123 µs end-to-end query.
//!
//! **Deliberate trade-off:** during a reload the view is no longer *globally*
//! atomic — shard 3 may hold the new generation while shard 4 holds the old.
//! For a blocklist this is irrelevant (a domain becomes blocked 2 ms earlier or
//! later). For any table with cross-entry invariants it would be unacceptable.
//! See `tests::split_view_mid_reload_is_a_consistent_key_wise_hybrid` for the
//! exact property that does hold, and for the stronger property that does not.
//!
//! # Lowercase invariant
//!
//! Every public entry point (`evaluate`, `is_blocked`, `list_membership`, the free
//! `domain_matches_set`) assumes the `domain` argument is already lowercase ASCII.
//! Hash lookups against `domain_map` / `allow_domains` / `deny_domains` are
//! case-sensitive; mixed-case input would silently miss every probe.
//!
//! The invariant is enforced at ingestion: `lists::manager` stores domains
//! lowercase, and the DNS hot path lowercases at the call site (`dns::handler`
//! relies on `LowerName`; `cli::commands::query`, `ipc::socket_server`, and
//! `api::handlers` call `to_ascii_lowercase` before passing the domain in).
//!
//! Each entry point includes a `debug_assert!` that verifies the invariant in
//! debug builds and is compiled out in release. Adding a runtime lowercase
//! fallback would silently mask future regressions at the call site, defeating
//! the case-normalization design — do not add one.
//!
//! # Subdomain walk sites
//!
//! The byte-offset suffix scan — a `for` loop over the domain's bytes
//! filtering on `b'.'`, per the CLAUDE.md hot-path discipline (NOT
//! `find('.')` + substring) — appears in two places in this module:
//!
//! 1. [`FilterEngine::evaluate_inner`] — the profile-aware kernel
//!    behind the [`FilterEngine::evaluate`] and
//!    [`FilterEngine::evaluate_attributed`] thin wrappers. Probes
//!    `allow_domains`, `deny_domains`, and the Tier 1 `domain_map` in
//!    a single unified pass per dot-position, with per-set enable
//!    short-circuits.
//! 2. [`FilterEngine::list_membership`] — the profile-less Tier 1
//!    mask lookup used by IPC / CLI callers that need raw list
//!    membership without a profile (e.g. `warden query`, IPC
//!    introspection handlers). Probes `domain_map` only and
//!    OR-aggregates the per-suffix [`DomainMasks`] across every hit.
//!
//! The two sites are kept separate because they have different return
//! types (`(FilterResult, Option<BlockSource>)` vs [`DomainMasks`])
//! and different call contexts (no profile, no admin layer in the
//! second). They are NOT a pair of duplicates waiting to be merged.
//!
//! Both walks MUST stay byte-identical in their suffix-handling,
//! trailing-dot, and empty-label-skip semantics. Any change to walk
//! semantics — how trailing dots are handled, how empty labels are
//! skipped, how the exact-match probe relates to the suffix scan —
//! must be applied to every site in this list.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use ahash::RandomState;
use arc_swap::ArcSwap;
use compact_str::CompactString;

use super::cname::BlockSource;
use super::rules::{RuleAction, RulePattern};
use crate::profiles::profile::ResolvedProfile;

/// Number of independent `ArcSwap` cells the Tier 1 domain map is split across.
///
/// The knee below was measured against the **hash** representation (real
/// 12 287 120-domain corpus, 50 050 probes at 50 % hit):
///
/// | N | ns/query | reload transient |
/// |---|---|---|
/// | 1 (unsharded) | 236 | ~780 MB |
/// | **16** | **375** | **43.0 MB** |
/// | 64 | 409 | 10.7 MB |
/// | 256 | 586 | 2.7 MB |
///
/// Under hashing, sharding *cost* latency: loads/query is bounded by label
/// count (2.76 at every N), but each shard is a separate allocation and the
/// working set of shard cells, `Arc` control blocks and table headers stopped
/// fitting in cache.
///
/// # The sign of the latency term flipped, the value did not
///
/// Under [`SortedShard`] the table above no longer describes this parameter,
/// and it is kept only because it is the record of why N was ever 16.
/// Sharding now **reduces** work: binary search is O(log n) in *shard* size,
/// so 16 shards search log₂(801 692) ≈ 19.6 entries deep instead of the
/// log₂(12 827 071) ≈ 23.6 an unsharded slice would need — about 4 fewer
/// probes per lookup, each a potential cache miss.
///
/// So N = 16 is now favoured by **both** terms it used to trade off: it bounds
/// the reload transient *and* it shortens the search. Raising N further still
/// costs the per-shard working set the table measures, and buys progressively
/// less depth (log₂ of a sixteenth is only 4 less), so 16 stands.
///
/// **Do NOT change this value without re-running the benchmark** against the
/// sorted representation — the numbers above cannot be used to justify a new
/// N, because they measure a structure that no longer exists.
pub const DOMAIN_SHARDS: usize = 16;

/// Process-lifetime seed behind [`FilterEngine::shard_index`].
///
/// **This is the single most dangerous thing in this module.**
/// `ahash::RandomState::new()` seeds randomly *per instance*. The side that
/// partitions domains into shards and the side that probes them MUST use the
/// same seed; if each constructs its own `RandomState` they disagree and
/// roughly 15/16 of every list silently becomes unreachable — with the whole
/// test suite still green, because a suite that only ever uses one engine
/// instance never observes the disagreement. Every caller routes through
/// [`FilterEngine::shard_index`], which routes through here.
///
/// Seeded once per process rather than at compile time on purpose. A constant
/// seed would let a malicious external blocklist ship domains precomputed to
/// collide — external lists are an explicit supply-chain threat for this
/// product — and buys nothing, because the only cross-side agreement that has
/// to hold is within a single daemon process.
///
/// **Consequence for the reload producer:** anything that persists a partition
/// outside the process (the `.shard/` spill files) is valid only for the
/// process that wrote it. Spill files left by a crashed process must be deleted,
/// not resumed.
static SHARD_HASHER: OnceLock<RandomState> = OnceLock::new();

/// A shard was refused because its entries are not strictly ascending.
///
/// Returned by [`SortedShard::from_sorted_entries`]. Carries the offending
/// position so a producer bug is diagnosable from one log line rather than
/// requiring the corpus to be reproduced.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "domain shard entries are not strictly ascending at index {index}: \
     `{previous}` is followed by `{offending}`{}",
    if *.duplicate { " (duplicate key — the producer's dedup did not run)" } else { "" }
)]
pub struct ShardOrderError {
    /// Index of the first entry that breaks the ordering.
    pub index: usize,
    /// The entry before it.
    pub previous: String,
    /// The entry that breaks the ordering.
    pub offending: String,
    /// True when the two are equal — a dedup failure rather than a sort failure.
    pub duplicate: bool,
}

/// Monotonic counter behind [`ListPolicy::publish`].
///
/// Starts at 1 so `0` can mean "never published" — [`ListPolicy::inert`]
/// takes it, and a test asserting a generation actually moved cannot be
/// satisfied by the initial value.
static FILTER_GEN_ID: AtomicU64 = AtomicU64::new(1);
/// Direction masks one profile applies to the bits of **one** generation.
///
/// `allow` and `block` are disjoint by construction: the effective direction
/// of a `(profile, list)` pair is a single value — `profiles.<id>.lists[id]`
/// when present, the list's own `base` otherwise — so a bit lands on exactly
/// one side, or on neither, which is what `base = "ignore"` (or an `ignore`
/// override) means.
///
/// 16 bytes per profile per generation — 64 profiles × 16 B is noise beside
/// a 12.8 M-domain corpus, so nothing here is packed, interned, or shared,
/// and it should stay that way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProfileMasks {
    /// Bits of the lists this profile treats as allow-direction.
    pub allow: u64,
    /// Bits of the lists this profile treats as block-direction.
    pub block: u64,
}

impl ProfileMasks {
    /// What a profile **absent** from the published table gets.
    ///
    /// Never a permission: an unknown `ProfileId` in a generation gets the
    /// restrictive default, never an allow.
    ///
    /// A profile can only be absent when the resolver map and the corpus were
    /// published from different configs (a republish lag), and the two errors
    /// are not symmetric. Handing it the inherited [`PolicyMasks::base`] would
    /// give it every `base = "allow"` list, and an allow bit surviving into a
    /// generation that did not mint it is the **fail-open** direction — the
    /// fatal one: allow beats block, so a deny-list's domains would silently
    /// stop being blocked. Blocking every list instead over-blocks, which
    /// someone notices and reports.
    pub const RESTRICTIVE: Self = Self {
        allow: 0,
        block: u64::MAX,
    };

    /// A profile no list can produce a verdict for — every list ignored, or
    /// a config with no lists at all.
    pub const INERT: Self = Self { allow: 0, block: 0 };

    /// True when no list can produce a verdict for this profile.
    ///
    /// The Tier 1 probe short-circuits on this, which is what replaces the
    /// previous `profile.list_bitmask != 0` test. Same contract — an admin
    /// profile subscribed to nothing pays nothing — asked of the policy
    /// instead of of the profile.
    #[inline]
    #[must_use]
    pub const fn is_inert(self) -> bool {
        self.allow == 0 && self.block == 0
    }
}

/// The operator's whole list policy, projected onto **one** generation's bit
/// assignment.
///
/// Built by [`crate::lists::source_key::SourceBitMap::project_policy`] from
/// **stable list ids** and handed to [`ListPolicy::publish`]. The projection
/// happens inside that builder deliberately: a `u64` that crossed the
/// config→engine boundary would be a positional mask travelling on its own,
/// with nothing tying it to the assignment it was built from. The config
/// speaks ids; only the builder speaks bits. The default is **fail-closed**,
/// and it was fail-open for the length of one test run — worth keeping the
/// reason where the type is.
///
/// `#[derive(Default)]` gives `base = {allow: 0, block: 0}`, i.e. *no list
/// filters anything*. The scalar this replaced defaulted to `allow_bits = 0`,
/// which under `bits & !allow_bits` meant **every list is deny-direction** —
/// the opposite. Twelve `lists::manager` tests caught it by asserting
/// `is_blocked` on a manager that had never been handed a policy; the shape
/// in production is a construction site that forgets `set_list_policy` and
/// silently serves an unfiltered corpus, which is the failure direction
/// nobody notices.
///
/// So the manual impl: a list is deny-direction until something says
/// otherwise, exactly as before.
impl Default for PolicyMasks {
    fn default() -> Self {
        Self {
            base: ProfileMasks::RESTRICTIVE,
            per_profile: HashMap::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PolicyMasks {
    /// Direction implied by each list's own `base`, before any per-profile
    /// override.
    ///
    /// Answers "what does this list do by default", which is the only
    /// question the profile-less entry points ([`FilterEngine::is_blocked`],
    /// CNAME prefetch, offline `warden query`) can ask.
    pub base: ProfileMasks,
    /// One entry per profile in the config this generation was published
    /// from. Anything else gets [`ProfileMasks::RESTRICTIVE`].
    pub per_profile: HashMap<CompactString, ProfileMasks, RandomState>,
}

/// Everything that interprets a domain's membership bits, materialised
/// against **one** generation's bit assignment.
///
/// # Why this is a type and not the bare `u64` it replaces
///
/// A list's bit is **positional, not identitary**: `lists::source_key`
/// assigns `bit = i` over the merged sources vector, so removing a list
/// slides every later list down one bit. A direction map is therefore only
/// meaningful *against the assignment it was built from*, and the thing that
/// makes it safe is not that it is small — it is that it travels with the
/// entries it interprets. Naming it makes that pairing something the code
/// states rather than something a reader has to infer from a `u64` sitting
/// next to a slice.
///
/// # Why a per-profile table, not one global map
///
/// Direction is not one map for every reader: [`Self::masks_for`] answers
/// per profile, and the answer is materialised against **this** generation's
/// bits, inside the `Arc` that already publishes atomically with `entries`.
/// It is *not* a second `ArcSwap`, and it is *not* a field on
/// `ResolvedProfile` — see the [`SortedShard`] type docs for why both of
/// those fail open.
///
/// # `gen_id`
///
/// Identity of the publish that minted this policy. [`Self::next_gen_id`] is
/// the only site that advances the counter, so "did this mutation actually
/// reach the filter?" is answered by whether the served `gen_id` moved
/// rather than by reading the call graph — checkable instead of merely
/// asserted in prose: refresh-lists and reload-config share one publish
/// function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListPolicy {
    /// Per-profile projection. Keyed by `ResolvedProfile::name`, which is the
    /// profile id the config declares.
    per_profile: HashMap<CompactString, ProfileMasks, RandomState>,
    /// Direction from each list's own `base`. See [`PolicyMasks::base`].
    base: ProfileMasks,
    /// Answer for a profile missing from [`Self::per_profile`].
    ///
    /// [`ProfileMasks::RESTRICTIVE`] on every config-built policy. The field
    /// exists because the two-mask **adapters** ([`SortedShard::from_pairs`]
    /// and the `HashMap<_, DomainMasks>` entry points) carry direction per
    /// *entry* and know no profile names at all: they publish through
    /// [`Self::uniform`], where the derived split is the answer for every
    /// reader. Those adapters have no production caller that installs
    /// domains — see [`FilterEngine::swap_blocklist`].
    fallback: ProfileMasks,
    /// See the type docs.
    gen_id: u64,
}

impl ListPolicy {
    /// Mint a policy for publication from the config's projected masks.
    ///
    /// The production constructor: `lists::manager` calls it once per corpus
    /// install, and every shard of that install shares the returned `Arc`.
    #[must_use]
    pub fn publish(masks: PolicyMasks) -> Arc<Self> {
        Self::derived(masks, Self::next_gen_id())
    }

    /// Mint a policy for a generation id the caller already took.
    ///
    /// Exists for callers that must stamp several shards with one id. Taking
    /// the id per shard instead was a real defect for the ~2 minutes it
    /// existed: `swap_blocklist(Default::default())` is a production path
    /// (`cli/commands/start.rs`, the operator removed every list source), and
    /// it would have left [`FilterEngine::filter_gen_ids`] reporting 16
    /// different generations for one coherent clear — indistinguishable from
    /// a genuinely torn install.
    #[must_use]
    pub(crate) fn derived(masks: PolicyMasks, gen_id: u64) -> Arc<Self> {
        Arc::new(Self {
            per_profile: masks.per_profile,
            base: masks.base,
            fallback: ProfileMasks::RESTRICTIVE,
            gen_id,
        })
    }

    /// **Adapter constructor — every profile sees the same split.**
    ///
    /// For inputs that express direction per *entry* rather than per profile:
    /// [`SortedShard::from_pairs`] derives `allow_bits` as the union of the
    /// entries' `allow_mask`, and there are no profile names anywhere in that
    /// shape. `per_profile` is therefore empty and the derived split is the
    /// [`Self::fallback`], so every reader gets it.
    ///
    /// **Not a config path.** It cannot express `profiles.<id>.lists`, so a
    /// policy built here says nothing about the operator's per-profile
    /// intent. The production install path is [`Self::publish`] driven by
    /// `lists::manager::ListManager::refresh`; the only production caller of
    /// an adapter is `swap_blocklist(Default::default())`, whose corpus is
    /// empty and whose policy is therefore never consulted.
    #[must_use]
    pub fn uniform(allow_bits: u64, gen_id: u64) -> Arc<Self> {
        let split = ProfileMasks {
            allow: allow_bits,
            block: !allow_bits,
        };
        Arc::new(Self {
            per_profile: HashMap::default(),
            base: split,
            fallback: split,
            gen_id,
        })
    }

    /// [`Self::uniform`] taking a fresh generation id.
    #[must_use]
    pub fn publish_uniform(allow_bits: u64) -> Arc<Self> {
        Self::uniform(allow_bits, Self::next_gen_id())
    }

    /// Take the next generation id without minting a policy — for a caller
    /// that must stamp several shards with one id.
    ///
    /// **The only site that advances [`FILTER_GEN_ID`].** Pinned by
    /// `tests/plp_s1_write_path.rs`.
    #[must_use]
    pub(crate) fn next_gen_id() -> u64 {
        FILTER_GEN_ID.fetch_add(1, Ordering::Relaxed)
    }

    /// The policy of a shard that has never been published into: no profile
    /// has any mask, nothing is allow-direction, and `gen_id` is the
    /// reserved `0`.
    ///
    /// Deliberately **not** `publish(…)`: an empty engine has not published
    /// anything, and burning a generation id on `FilterEngine::new()` would
    /// make the counter count constructions instead of publishes.
    ///
    /// Both [`Self::base`] and [`Self::fallback`] are
    /// [`ProfileMasks::RESTRICTIVE`], and neither is reachable today — an
    /// inert shard has no entries, so no bits ever meet them. They are
    /// restrictive anyway because the cost of being wrong is not symmetric:
    /// if some future path ever installs entries against this policy, the
    /// choice is between over-blocking (visible, reported) and a corpus that
    /// silently filters nothing (see [`PolicyMasks::default`]).
    #[must_use]
    pub fn inert() -> Arc<Self> {
        Arc::new(Self {
            per_profile: HashMap::default(),
            base: ProfileMasks::RESTRICTIVE,
            fallback: ProfileMasks::RESTRICTIVE,
            gen_id: 0,
        })
    }

    /// The masks `profile` applies to this generation's bits.
    ///
    /// An unknown profile gets [`ProfileMasks::RESTRICTIVE`] — read that
    /// constant's doc before changing this, the asymmetry is the whole
    /// argument.
    #[inline]
    #[must_use]
    pub fn masks_for(&self, profile: &str) -> ProfileMasks {
        self.per_profile
            .get(profile)
            .copied()
            .unwrap_or(self.fallback)
    }

    /// Direction from each list's own `base`, before per-profile overrides.
    #[must_use]
    pub const fn base_masks(&self) -> ProfileMasks {
        self.base
    }

    /// Identity of the publish that minted this policy; `0` for
    /// [`Self::inert`].
    #[must_use]
    pub const fn gen_id(&self) -> u64 {
        self.gen_id
    }

    /// Split one entry's source bits using [`Self::base`] — the profile-less
    /// answer.
    #[inline]
    #[must_use]
    pub(crate) const fn split_base(&self, bits: u64) -> DomainMasks {
        DomainMasks {
            allow_mask: bits & self.base.allow,
            block_mask: bits & self.base.block,
        }
    }
}

/// One shard's domains: exact-size, sorted, no buckets and no empty slots.
///
/// # Why one `u64` and not two
///
/// This replaced `HashMap<CompactString, DomainMasks, RandomState>`. Two
/// separate wastes went with it:
///
/// 1. **Empty slots.** hashbrown holds ≤ 7/8 load and rounds to a power of two,
///    so 801 692 entries per shard occupied 1 048 576 buckets — 16 777 216
///    slots across 16 shards at 41 B each, of which ~158 MB was never
///    occupied. An exact-size boxed slice has no slots to leave empty.
/// 2. **A global fact stored 12.8 M times.** `DomainMasks` spends 128 bits
///    per domain to carry 64 bits of list membership *plus* the knowledge of
///    which lists are allow-direction — and that second part is identical for
///    every domain in the generation. So it is stored **once, here**, in
///    [`Self::policy`], and each entry keeps only its 64 membership bits.
///
/// Together: 41 B/slot → **32 B/entry**, 687.9 MB → 410.5 MB at the live
/// 12 827 071-domain corpus.
///
/// # The consistency property this buys — read before splitting these fields
///
/// `entries` and [`Self::policy`] live in the **same** `Arc`, so one atomic
/// `store` publishes both. A domain's membership bits and the direction map
/// that interprets them can never come from different generations: a torn
/// pair is *unrepresentable*, not merely unlikely.
///
/// That is strictly stronger than the `HashMap` it replaced, which guaranteed
/// only that the two masks came from one `get().copied()`. **Do not hoist
/// the policy to a field on [`FilterEngine`], onto `ResolvedProfile`, or into
/// a second `ArcSwap`.** Doing so recreates two independent loads of two
/// structures swapped at different instants, and the block-then-allow
/// interleaving then yields old-block + new-allow — a pair no generation held
/// — which under allow-beats-block reads as ALLOWED for a domain both
/// generations blocked.
///
/// **`ResolvedProfile` is named explicitly because it is the tempting one.**
/// The profile map is a *different* `ArcSwap` published by a *different*
/// path (config
/// reload), and list bits are positional, so a mask that travels with a
/// profile can meet a corpus that has since re-assigned the bits it names.
/// The subset error over-blocks and someone complains; the superset error
/// puts a deny-list's bit on the allow side and every domain on that list
/// silently stops being blocked.
///
/// Pinned by `tests::the_policy_and_entries_are_swapped_as_one_generation`,
/// which succeeded `allow_bits_and_entries_are_swapped_as_one_generation`
/// when the scalar became [`ListPolicy`] — same property, new shape.
/// `tests/plp_s1_bit_remap.rs` pins the end-to-end half: no domain carried
/// only by a deny-direction list is ever allowed, under any pairing of
/// corpus generation and policy generation.
///
/// Cross-*shard* generation mixing is untouched and remains deliberate — see
/// `FilterEngine::probe_shard`.
pub struct SortedShard {
    /// Sorted ascending by domain, exact capacity, no spare. Built from a
    /// `Vec` with the exact count so `into_boxed_slice` does not reallocate.
    ///
    /// The `u64` is the domain's **source bits** — the union of every list bit
    /// that contains it, direction-agnostic. [`Self::split_base`] recovers the
    /// per-direction masks.
    entries: Box<[(CompactString, u64)]>,
    /// The direction map that interprets [`Self::entries`], materialised
    /// against the **same** generation's bit assignment. Shared across the 16
    /// shards of a generation, so this costs one pointer per shard and one
    /// allocation per publish — the same 8 bytes the bare `u64` it replaced
    /// occupied.
    ///
    /// Was a bare `allow_bits: u64` previously. The pairing property
    /// described above is unchanged; what changed is that the thing being
    /// paired now has a name and a generation id, so the direction map can
    /// be extended in place instead of hoisting it somewhere that fails
    /// open.
    policy: Arc<ListPolicy>,
}

/// Reports shape, never contents.
///
/// **Deliberately hand-written rather than `#[derive(Debug)]`.** A production
/// shard holds ~801 692 domains; a derived impl would make one stray `{:?}` —
/// in a log line, an `assert_eq!` message, an `expect_err` — dump the entire
/// corpus. The fields that matter for diagnosis are the count and the
/// direction map, and both fit on one line.
///
/// Today the only reachable site is `expect_err` on
/// [`Self::from_sorted_entries`], where the useful information is "a shard was
/// built when it should have been refused" — which a derived impl would bury
/// under a megabyte of domain names. That reachability is *why the risk is
/// low today*, not why the impl exists: the impl exists so the next `{:?}`
/// added anywhere is safe by default.
impl std::fmt::Debug for SortedShard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SortedShard")
            .field("entries", &self.entries.len())
            // Zero-padded to a fixed 16 hex digits on purpose: these are
            // BITMASKS, so bit positions must line up when two shards' lines
            // are read side by side, and a leading-zero run must stay visible
            // rather than being absorbed by a variable-width `{:#x}`.
            .field(
                "base_allow",
                &format_args!("{:#018x}", self.policy.base.allow),
            )
            .field(
                "base_block",
                &format_args!("{:#018x}", self.policy.base.block),
            )
            .field("profiles", &self.policy.per_profile.len())
            .field("gen_id", &self.policy.gen_id)
            .finish()
    }
}

impl SortedShard {
    /// Empty shard, carrying [`ListPolicy::inert`] — nothing to split, and
    /// `gen_id == 0` so it is distinguishable from anything published.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            entries: Box::new([]),
            policy: ListPolicy::inert(),
        }
    }

    /// Pack records the producer has already sorted and deduplicated.
    ///
    /// The allocation-free path for `lists::manager`'s per-shard build loop:
    /// spill records go straight into `entries` with no intermediate map.
    ///
    /// `entries` must be sorted ascending by domain with no duplicate keys,
    /// and each `u64` must be the union of the list bits containing that
    /// domain. `policy` is the generation's direction map, minted once per
    /// publish by [`ListPolicy::publish`] and cloned into every shard of that
    /// cycle — the same `Arc` `build_shard` already receives.
    ///
    /// # Ordering is a hard precondition and is CHECKED, not asserted
    ///
    /// Binary search silently fails to find entries an unsorted slice
    /// contains. On a DNS filter that is not a wrong number in a status line —
    /// it is domains that should be blocked being resolved, for a whole
    /// generation, with no log line and no counter.
    ///
    /// So this returns [`ShardOrderError`] rather than trusting the caller,
    /// and **the check is a real runtime pass, deliberately not a
    /// `debug_assert!`**. It runs at reload — twice a day, off the query path —
    /// so an O(n) comparison sweep is free. Do not "optimise" it into a
    /// `debug_assert!`: release is exactly where a silent reclassification
    /// matters, and release is what ships to live household DNS. (An earlier
    /// revision of this function did use a `debug_assert!`, while
    /// [`Self::from_pairs`] two functions above already argued at length why
    /// that is the wrong guard. Same premise, opposite conclusions, in one
    /// file.)
    ///
    /// **Strictly ascending, so duplicates are refused too.** That is not
    /// pedantry: unsorted input almost certainly means the producer's dedup
    /// did not run either, and dedup is what OR-merges a domain's bits across
    /// sources. A duplicate key would leave `binary_search` returning an
    /// arbitrary one of them, i.e. a domain carrying *some* of its list bits.
    /// This is also why the failure is refused rather than repaired: sorting
    /// here would install plausible-looking data with bits missing. Rejecting
    /// leaves the previous generation serving — stale but internally
    /// consistent — which is exactly what `lists::manager` already does when a
    /// shard fails to build.
    ///
    /// A producer that pushes-then-sorts must use a **stable** sort
    /// (`sort_by`, never `sort_unstable_by`): `added_by_bit` credits a
    /// domain's *first occurrence in spill order*, and only a stable sort
    /// keeps that correspondence.
    ///
    /// # `policy` must come from the SAME generation as `entries`
    ///
    /// The read-time split is `allow_mask = source_bits & allow_bits`,
    /// `block_mask = source_bits & !allow_bits`. This constructor **accepts**
    /// the policy instead of deriving it, so it cannot check that pairing —
    /// and the two directions of error are not symmetric:
    ///
    /// - a **subset** (a bit that is allow in this generation, omitted here)
    ///   sends that bit to `block_mask`: **over-blocks**, visible, reported;
    /// - a **superset** (a bit that is *deny* in the generation `entries` came
    ///   from) sends it to `allow_mask`, and allow beats block — so **every
    ///   domain on that list silently stops being blocked**. This is the
    ///   fail-open direction.
    ///
    /// [`Self::from_pairs`] is exempt: it *derives* the policy from the
    /// entries it is given, so the pair cannot come from two generations.
    /// Once inside the `Arc` the pair cannot tear (see the type docs) — that
    /// guarantee says nothing about a caller assembling it from two
    /// generations before it gets there.
    ///
    /// # Errors
    ///
    /// [`ShardOrderError`] if `entries` is not strictly ascending by domain.
    pub fn from_sorted_entries(
        entries: Vec<(CompactString, u64)>,
        policy: Arc<ListPolicy>,
    ) -> Result<Self, ShardOrderError> {
        if let Some(pos) = entries.windows(2).position(|w| w[0].0 >= w[1].0) {
            let err = ShardOrderError {
                index: pos + 1,
                previous: entries[pos].0.to_string(),
                offending: entries[pos + 1].0.to_string(),
                duplicate: entries[pos].0 == entries[pos + 1].0,
            };
            // Loud by construction. Whatever the caller does with the `Err`,
            // this must never be a silent rejection.
            tracing::error!(
                index = err.index,
                previous = %err.previous,
                offending = %err.offending,
                duplicate = err.duplicate,
                "REFUSING a domain shard: entries are not strictly ascending. The \
                 previous generation keeps serving. Binary search would silently \
                 miss entries this shard contains — domains that should block \
                 would resolve.",
            );
            return Err(err);
        }
        Ok(Self {
            entries: entries.into_boxed_slice(),
            policy,
        })
    }

    /// Iterate `(domain, source_bits)` in sorted order.
    ///
    /// `source_bits` is direction-agnostic; use [`Self::split_base`] to recover the
    /// per-direction masks against this shard's own `allow_bits`.
    pub fn iter(&self) -> impl Iterator<Item = (&str, u64)> + '_ {
        self.entries.iter().map(|(d, b)| (d.as_str(), *b))
    }

    /// Number of domains in this shard.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when this shard holds no domains.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The profile-less split, from the lists' own `base` direction.
    ///
    /// Used by [`FilterEngine::is_blocked`] and the other entry points that
    /// have no client profile. See [`PolicyMasks::base`].
    #[inline]
    #[must_use]
    pub(crate) fn split_base(&self, bits: u64) -> DomainMasks {
        self.policy.split_base(bits)
    }

    /// The policy [`Self::entries`] are interpreted by.
    ///
    /// `pub(crate)` for the same reason as [`Self::split_base`]: a caller that
    /// rebuilt an equivalent policy from config would be asserting against
    /// its own arithmetic instead of against the pairing that was actually
    /// published.
    pub(crate) fn policy(&self) -> &Arc<ListPolicy> {
        &self.policy
    }

    /// Fold `(domain, DomainMasks)` pairs into the packed representation.
    ///
    /// `allow_bits` is derived as the union of every entry's `allow_mask`.
    /// **Per shard is sufficient, not an approximation:** if bit *b* appears
    /// in no `allow_mask` here, no entry here needs *b* on the allow side, so
    /// `bits & !allow_bits` restores every `block_mask` exactly.
    ///
    /// # The input shape that does not round-trip — BOTH forms of it
    ///
    /// **A list bit used in both directions.** Two forms, and an earlier
    /// revision of this doc named only the first, which is exactly why the
    /// guard below was written too narrow and shipped blind to the second:
    ///
    /// 1. **Same entry** — bit *N* in `allow_mask` *and* `block_mask` of one
    ///    domain. Verdict is **unchanged** by the normalisation: allow was
    ///    already set, so [`FilterEngine::evaluate`] forwards either way.
    /// 2. **Across entries** — bit *N* allow on `parent.test`, bit *N* block
    ///    on `child.parent.test`. **This one changes the verdict.** If the
    ///    blocked domain has no allow-direction ancestor, the reference answer
    ///    is `allow=0, block=N` → BLOCK and the normalised answer is
    ///    `allow=N, block=0` → **FORWARD**. It flips only when both domains
    ///    hash into the same shard, so it is *intermittent*, decided by
    ///    `SHARD_HASHER`'s per-process seed.
    ///
    /// Do not repeat the earlier claim that "no profile-aware verdict
    /// changes": it is true of form 1 and false of form 2.
    ///
    /// # It is NOT a production fail-open — the storage makes the class unrepresentable
    ///
    /// Say this accurately, because "fail-open in the filter engine" is the
    /// kind of sentence that gets acted on. **Production cannot reach either
    /// form**, and the reason is this representation working as designed:
    /// direction is stored **once per generation** in
    /// [`SortedShard::policy`], not once per entry, so there is no
    /// per-entry allow/block pair for the two sides to disagree about. The
    /// production install path is
    /// `build_shard` → [`Self::from_sorted_entries`] → `swap_shard_sorted`,
    /// which never builds a [`DomainMasks`] pair at all.
    ///
    /// This function is the **adapter from the old two-mask shape**, and that
    /// is the only place the conflict can be expressed.
    ///
    /// **Pin the immunity to the arithmetic, not to a caller count.** It is
    /// tempting to argue "the only non-test caller is `swap_shard`, which is
    /// `cfg(test)`" — but caller counts change (that one changed the day it
    /// was written), and an argument that decays silently is worth little. The
    /// durable form: `partition` also reaches here, from
    /// [`FilterEngine::with_domain_map`], [`FilterEngine::swap_domain_map`] and
    /// [`FilterEngine::swap_blocklist`] — and **all three build their masks with
    /// `DomainMasks::block_only`**, so every entry has `allow_mask == 0`, hence
    /// `allow_bits == 0`, hence `conflicting == block_mask & 0 == 0`.
    /// Arithmetically impossible, not merely unreached. The one entry point
    /// that can express arbitrary pairs,
    /// [`FilterEngine::with_per_direction_domain_map`], is fixture-only.
    ///
    /// # Why it still matters, and why it is still an error-level log
    ///
    /// **Because a fixture that hits it makes the TEST lie.** A test built
    /// through this adapter can report FORWARD where production would BLOCK —
    /// intermittently, on a seed the author never chose. A wrong test is worse
    /// than a missing one, and `sharded_lookup_is_equivalent_to_the_unsharded_walk`
    /// caught exactly that: `EQUIV_ENTRIES` encoded one list bit in both
    /// directions and failed roughly one run in sixteen.
    ///
    /// Normalised rather than refused because `partition` reaches here from
    /// constructors returning `Self`, not `Result`; making them fallible would
    /// change signatures in files this lane does not own, for a state
    /// production cannot enter. Pinned by
    /// `tests::a_bit_used_in_both_directions_across_entries_is_detected`.
    ///
    /// The normalisation is **allow-wins**, which for form 1 is the verdict
    /// [`FilterEngine::evaluate`] reaches anyway (the allow-direction check
    /// runs before the block-direction check); there only
    /// [`FilterEngine::is_blocked`], which reads `block_mask` alone, differs.
    ///
    /// A `debug_assert!` would be the obvious guard and is deliberately **not**
    /// used: it compiles out of the shipped binary, which is precisely where a
    /// silent reclassification would matter. This logs at build time instead,
    /// in release, once per affected shard.
    fn from_pairs(pairs: Vec<(CompactString, DomainMasks)>, gen_id: u64) -> Self {
        let mut allow_bits = 0u64;
        for (_, m) in &pairs {
            allow_bits |= m.allow_mask;
        }

        // Conflict detection is against `allow_bits`, NOT against each entry's
        // own `allow_mask`. Those are different checks and only this one is
        // sufficient.
        //
        // An earlier revision tested `m.allow_mask & m.block_mask != 0`, which
        // catches a bit set in both directions *on one entry* and misses the
        // case that actually bites: bit N allow on `parent.test` and bit N
        // block on `child.parent.test` — two entries, one bit, opposite
        // directions. `allow_bits` is a per-shard union, so the block loses
        // its bit **only when both domains hash to the same shard**, which
        // makes the divergence depend on `SHARD_HASHER`'s per-process seed.
        // That is a ~1-in-16 non-deterministic wrong answer, and it is exactly
        // how the equivalence test against the unsharded walk caught this.
        // `m.block_mask & allow_bits` subsumes the same-entry case, so one
        // check covers both.
        let conflicting: u64 = pairs
            .iter()
            .fold(0u64, |acc, (_, m)| acc | (m.block_mask & allow_bits));
        if conflicting != 0 {
            // ERROR, not WARN: across two entries this flips a BLOCK to a
            // FORWARD, and only when the two domains share a shard — so it is
            // intermittent, on a seed the author never chose. Production
            // cannot reach it (see the doc: every production path here has
            // allow_bits == 0), so in practice this fires only for a fixture,
            // where the cost is a test that lies.
            tracing::error!(
                conflicting = format_args!("{conflicting:#018x}"),
                "domain shard built with list bits used in BOTH directions; the \
                 block side of those bits is normalised away (allow-wins), turning \
                 a BLOCK into a FORWARD for any domain with no allow-direction \
                 ancestor. A source has one `kind`, so a bit is allow-direction or \
                 block-direction for every domain it tags — use one bit per \
                 direction. Reachable only through the two-mask adapter; if you \
                 are seeing this, a fixture built it."
            );
        }

        let mut entries: Vec<(CompactString, u64)> = pairs
            .into_iter()
            .map(|(d, m)| (d, m.allow_mask | m.block_mask))
            .collect();

        // STABLE sort: ties must retain input order so a dedup keeping the
        // first of each run keeps the *first* occurrence, which is what the
        // producer's `added_by_bit` accounting credits. `sort_unstable_by`
        // would be faster and would silently break that correspondence.
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        entries.dedup_by(|a, b| {
            if a.0 == b.0 {
                b.1 |= a.1;
                true
            } else {
                false
            }
        });
        entries.shrink_to_fit();

        Self {
            entries: entries.into_boxed_slice(),
            policy: ListPolicy::uniform(allow_bits, gen_id),
        }
    }
}

/// One shard cell.
///
/// `#[repr(align(64))]` is load-bearing: without it a reload storing into shard
/// 7 dirties the cache line that readers of shards 4-6 are sitting on. That
/// false sharing is invisible single-threaded — every test here would still
/// pass — and real under concurrent query load.
#[repr(align(64))]
struct DomainShard(ArcSwap<SortedShard>);

/// Result of profile-aware domain evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterResult {
    /// Forward query to upstream (allowed).
    Forward,
    /// Block the query (return canned response).
    Block,
}

/// Per-domain Tier 1 list-membership masks split by direction.
///
/// `block_mask` bit N is set when list with bit index N (a `base = deny`
/// list) contains this domain. `allow_mask` bit N is set when a
/// `base = allow` list with bit index N contains this domain.
///
/// Both masks live in a single 16-byte `Copy` struct. The walk accumulates
/// this profile's masks directly — the AND against a profile-side subscription
/// mask is gone with `ResolvedProfile.list_bitmask`; admin rules sit
/// above this layer in priority and override allow-list matches
/// (`$important deny` is sovereign).
///
/// # This is the interface, not the storage — and the invariant that follows
///
/// Shards no longer *store* this struct. They store one `u64` of source
/// bits per domain plus one [`ListPolicy`] per shard, and
/// [`FilterEngine::probe_shard`] reconstitutes the pair per probe. That is
/// lossless because of an invariant worth stating explicitly:
///
/// > **A list bit belongs to exactly one direction *per reader*.** This is
/// > "per reader" narrowed from "everyone" to "per profile": the effective
/// > direction of a `(profile, list)` pair is one value, so bit *N* is allow,
/// > block, or neither for that profile — never both. Hence
/// > `allow_mask & block_mask == 0` in every generation the production
/// > producer builds, for every profile.
///
/// Enforced structurally upstream:
/// `lists::source_key::SourceBitMap::project_policy` derives each profile's
/// partition from one `effective_direction` answer per pair, and asserts the
/// disjointness in debug. A fixture can still construct an overlapping pair
/// through the two-mask adapter; [`SortedShard::from_pairs`] normalises it and
/// warns. **Code that would make overlap meaningful — a bit that is allow for
/// one domain and block for another *within one profile* — must not be added
/// without changing the storage back.**
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DomainMasks {
    /// Bits set for allow-direction lists (`base = allow`) that contain this
    /// domain. Hits this mask short-circuit to [`FilterResult::Forward`]
    /// after the admin layer.
    pub allow_mask: u64,
    /// Bits set for block-direction lists (`base = deny`, the default) that
    /// contain this domain. Hits this mask trigger [`FilterResult::Block`]
    /// only when no allow-direction list also matched.
    pub block_mask: u64,
}

impl DomainMasks {
    /// Build masks where every bit lives in `block_mask` (back-compat with
    /// callers that produce a single `u64` bitmask). Used to convert
    /// inputs to [`FilterEngine::swap_domain_map`] / [`FilterEngine::with_domain_map`]
    /// — those entry points predate the per-direction split and still feed
    /// `lists::manager` via a single-mask `HashMap<CompactString, u64>`.
    #[inline]
    #[must_use]
    pub const fn block_only(block_mask: u64) -> Self {
        Self {
            allow_mask: 0,
            block_mask,
        }
    }

    /// True iff at least one direction has any bit set.
    #[inline]
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.allow_mask == 0 && self.block_mask == 0
    }
}

/// Lock-free filter engine backed by [`DOMAIN_SHARDS`] `ArcSwap<SortedShard>`
/// cells with per-list bitmasks.
///
/// Hot path: `evaluate()` does, per probed suffix, a shard select + atomic
/// pointer load + binary search over the shard's sorted slice, then bitmask
/// AND + allow/deny rule check. Background: `swap_domain_map()` replaces every
/// shard; [`Self::swap_shard_sorted`] replaces exactly one.
pub struct FilterEngine {
    shards: [DomainShard; DOMAIN_SHARDS],
}

impl Default for FilterEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl FilterEngine {
    /// Map a domain (or any suffix of one) to its shard.
    ///
    /// **THE single source of truth for partitioning.** The reload producer
    /// calls this to decide which shard a domain belongs to; the engine calls
    /// it to decide which shard to probe. Both sides must agree or lookups
    /// silently miss — see [`SHARD_HASHER`] for why that failure mode is
    /// invisible to tests.
    ///
    /// `key` is expected lowercase ASCII, like every other lookup path in this
    /// module: the shard of `Example.com` is not the shard of `example.com`.
    #[inline]
    #[must_use]
    pub fn shard_index(key: &str) -> usize {
        let hash = SHARD_HASHER.get_or_init(RandomState::new).hash_one(key);
        // Bits 32..35 — deliberately NOT the low bits and NOT the top 7.
        // hashbrown takes its bucket index from the LOW bits (`hash &
        // bucket_mask`) and its control byte from the TOP 7. A shard selector
        // overlapping either would correlate shard membership with in-shard
        // bucket placement the moment a caller builds a shard map with this
        // same hasher: every key in shard `i` would land on buckets ≡ i
        // (mod 16), i.e. 1/16 of the table. Independent per-map seeds make
        // that moot today; this keeps it moot if that ever changes.
        // Do NOT "simplify" this to `hash as usize % DOMAIN_SHARDS`.
        (hash >> 32) as usize % DOMAIN_SHARDS
    }

    /// Partition entries into per-shard maps.
    ///
    /// **The only place in this module that decides which map an entry lands
    /// in.** Every constructor and every bulk swap funnels through here, so
    /// there is exactly one site to audit against [`Self::shard_index`]. A
    /// stray direct insert into `shards[n]` elsewhere is precisely the
    /// 15/16-invisible bug described on [`SHARD_HASHER`].
    ///
    /// Takes an iterator rather than a built map so a caller can feed one
    /// straight through without building a `DomainMasks` map first
    /// That removes one *conversion* table, not the duplication below — see
    /// `# Memory`.
    ///
    /// # Memory — this IS the reload peak. Read before adding a caller.
    ///
    /// **Partitioning a flat input duplicates it.** Every entry is moved into
    /// one of 16 fresh buffers while the source collection stays allocated
    /// until its `IntoIter` is exhausted, so a constructor peaks at ~2× the
    /// corpus and a bulk swap, which also holds the outgoing generation until
    /// [`Self::store_shard_maps`] replaces it, peaks at ~3×.
    ///
    /// This is **inherent to a by-value flat input**, not an oversight: a shard
    /// cannot be known complete until the whole input has been seen, so no
    /// reordering of the work avoids materialising a second full generation.
    ///
    /// **The reload-peak win is reached through [`Self::swap_shard_sorted`],**
    /// driven by `lists::manager::ListManager::refresh`'s per-shard build loop,
    /// which builds shard `i` straight from spill records and never
    /// materialises a flat map. Every *other* entry point on this type still
    /// pays the duplication above — each takes a flat input by value.
    ///
    /// The sorted representation has no buckets and no load factor, so none
    /// of the hashbrown-era pre-sizing rationale (power-of-two bucket
    /// counts, 7/8 load, never add headroom because it could push a shard
    /// across a power-of-two boundary and double its table) applies here.
    /// `Vec::with_capacity` here is an exact reservation, not a rounded one,
    /// and over-reserving now costs only the slack itself — which
    /// [`SortedShard::from_pairs`] returns with `shrink_to_fit`.
    fn partition<I>(entries: I) -> [SortedShard; DOMAIN_SHARDS]
    where
        I: IntoIterator<Item = (CompactString, DomainMasks)>,
    {
        let entries = entries.into_iter();

        // `size_hint().0` rather than an `ExactSizeIterator` bound: every
        // caller today feeds a `HashMap`/`HashSet` iterator (possibly through
        // `.map()`, which forwards the bound), so the lower bound is exact; a
        // future producer with an unknown length degrades to plain `Vec`
        // growth instead of failing to compile.
        let per_shard = entries.size_hint().0.div_ceil(DOMAIN_SHARDS);
        let mut buckets: [Vec<(CompactString, DomainMasks)>; DOMAIN_SHARDS] =
            std::array::from_fn(|_| Vec::with_capacity(per_shard));
        for (domain, masks) in entries {
            buckets[Self::shard_index(&domain)].push((domain, masks));
        }
        // ONE generation id for all 16 shards: this is one install, however
        // many shards it lands in. `from_pairs` still derives `allow_bits` per
        // shard (see its docs — per-shard is sufficient, not an
        // approximation), but the identity of the publish is shared.
        let gen_id = ListPolicy::next_gen_id();
        buckets.map(|b| SortedShard::from_pairs(b, gen_id))
    }

    /// Build an engine from already-partitioned shards.
    fn from_shard_maps(maps: [SortedShard; DOMAIN_SHARDS]) -> Self {
        Self {
            shards: maps.map(|m| DomainShard(ArcSwap::from_pointee(m))),
        }
    }

    /// Store already-partitioned shards into a live engine.
    ///
    /// Shards are installed one at a time, so each displaced old shard is
    /// released as soon as its last reader lets go rather than the whole old
    /// generation being pinned until the end.
    fn store_shard_maps(&self, maps: [SortedShard; DOMAIN_SHARDS]) {
        for (idx, map) in maps.into_iter().enumerate() {
            self.shards[idx].0.store(Arc::new(map));
        }
    }

    /// Replace exactly one shard, from a `HashMap` the producer already built.
    ///
    /// This is the entry point the reload producer drives a low-peak refresh
    /// with: build shard `idx`, swap it, let the displaced shard drop when its
    /// last reader releases it, then move to the next. A full new generation
    /// never exists, which is the entire point of sharding — see the module
    /// docs.
    ///
    /// `map` must contain only domains for which
    /// [`Self::shard_index`]` == idx`. Entries that violate that are stored but
    /// never found, because the probe side consults `shard_index` alone.
    ///
    /// # Memory — this signature is a compatibility shim, not the fast path
    ///
    /// The stored representation changed to [`SortedShard`], but this
    /// signature is **preserved deliberately** so `lists::manager` keeps
    /// compiling unchanged. The conversion costs one transient sorted slice
    /// (~26 MB) alongside the caller's `HashMap` (~43 MB) for **one shard at a
    /// time**, so the reload peak rises by the smaller of the two while steady
    /// state falls by 277 MB. The one-shard-at-a-time bound is preserved, not
    /// spent.
    ///
    /// [`Self::swap_shard_sorted`] is the allocation-free path that removes
    /// even that transient. A producer that can emit sorted records should
    /// call it instead.
    ///
    /// # Panics
    ///
    /// Panics if `idx >= DOMAIN_SHARDS`.
    ///
    /// # Test-only since the producer bridge
    ///
    /// `ListManager::refresh` now installs through
    /// [`Self::swap_shard_sorted`], so this `HashMap`-taking form has **no
    /// production caller** — only the three fixtures in this file's `mod
    /// tests`. It is gated rather than deleted because those fixtures build
    /// their input as a map and reading them is easier than rewriting them.
    ///
    /// Do not remove the gate to "make it available": an ungated dead swap
    /// function silently piles up cost that nothing then measures — exactly
    /// what happened to `swap_domain_map_with_directions`, which sat dead
    /// while stale comments priced it at +1 GB.
    #[cfg(test)]
    pub fn swap_shard(&self, idx: usize, map: HashMap<CompactString, DomainMasks, RandomState>) {
        self.swap_shard_sorted(
            idx,
            SortedShard::from_pairs(map.into_iter().collect(), ListPolicy::next_gen_id()),
        );
    }

    /// Replace exactly one shard with an already-packed [`SortedShard`].
    ///
    /// The low-peak entry point: no intermediate `HashMap`, no conversion. The
    /// producer builds the sorted slice straight from spill records and hands
    /// it over.
    ///
    /// `shard` must contain only domains for which
    /// [`Self::shard_index`]` == idx`. Entries that violate that are stored but
    /// never found, because the probe side consults `shard_index` alone.
    ///
    /// # Sortedness needs no check here — the type is the proof
    ///
    /// A [`SortedShard`] cannot be constructed unsorted: the only two routes
    /// are [`SortedShard::from_pairs`], which sorts, and
    /// [`SortedShard::from_sorted_entries`], which *refuses* unsorted input at
    /// runtime and returns [`ShardOrderError`]. So there is deliberately no
    /// re-validation on this path — not because it is cheap to skip, but
    /// because the invariant is established at construction and re-checking it
    /// here would suggest it might not be.
    ///
    /// A caller holding an `Err` from `from_sorted_entries` must **not** swap:
    /// leaving the previous generation installed is the correct response, and
    /// mirrors what `lists::manager` already does when a shard fails to build.
    ///
    /// # Panics
    ///
    /// Panics if `idx >= DOMAIN_SHARDS`.
    pub fn swap_shard_sorted(&self, idx: usize, shard: SortedShard) {
        let count = shard.entries.len();
        self.shards[idx].0.store(Arc::new(shard));
        tracing::debug!(shard = idx, count, "domain shard swapped");
    }

    /// Create empty filter engine.
    #[must_use]
    pub fn new() -> Self {
        Self::from_shard_maps(std::array::from_fn(|_| SortedShard::empty()))
    }

    /// Create filter engine pre-loaded with a single-mask domain map.
    ///
    /// Each entry's `u64` is treated as the [`DomainMasks::block_mask`] —
    /// no allow-direction bits are set. This signature predates the
    /// per-direction split and is preserved verbatim so `lists::manager`
    /// keeps compiling unchanged. New callers that want allow-direction
    /// lists must use [`Self::with_per_direction_domain_map`].
    ///
    /// **Memory:** partitions a flat input, so it costs a full extra copy of
    /// the corpus — see `partition`'s `# Memory`.
    #[must_use]
    pub fn with_domain_map(map: HashMap<CompactString, u64, RandomState>) -> Self {
        Self::from_shard_maps(Self::partition(
            map.into_iter()
                .map(|(d, b)| (d, DomainMasks::block_only(b))),
        ))
    }

    /// Create filter engine pre-loaded with a per-direction domain map.
    ///
    /// The primary constructor for a per-direction map — each entry already
    /// carries split allow / block masks. Used by tests that exercise the
    /// Tier 1 allow-direction path. Production reaches the engine by
    /// swapping an already-constructed one, never through this constructor:
    /// it always builds the engine empty ([`Self::new`]) and populates it by
    /// swap, so this is a fixture-only entry point.
    ///
    /// **Do not write the current installer's name here.** The production
    /// install path is whichever `swap_shard*` the list manager calls —
    /// `grep -n 'swap_shard' src/lists/manager.rs`. A pointer that names a
    /// version goes stale in silence; a pointer that names how to look does not.
    ///
    /// # Invariant
    ///
    /// A list bit must not appear in both `allow_mask` and `block_mask` of the
    /// same entry. Direction is a per-**source** property, so production
    /// cannot produce that; a fixture can. [`SortedShard::from_pairs`]
    /// normalises such a bit to allow-wins — which is the verdict
    /// [`Self::evaluate`] would reach anyway — and warns.
    ///
    /// **Memory:** partitions a flat input, so it costs a full extra copy of
    /// the corpus — measured +169.1 MB at N = 2 000 000 where the pre-sharding
    /// move cost +0.0 MB. See `partition`'s `# Memory`.
    #[must_use]
    pub fn with_per_direction_domain_map(
        map: HashMap<CompactString, DomainMasks, RandomState>,
    ) -> Self {
        Self::from_shard_maps(Self::partition(map))
    }

    /// Create filter engine from a flat set (all domains get block_mask = 1).
    ///
    /// Used by the offline `query` CLI command (`cli/commands/query.rs`) and
    /// by hot-path test fixtures (`dns/handler.rs`). Profiles resolved against
    /// this engine see every domain as belonging to block-direction "list 0",
    /// so any profile whose policy carries bit 0 on the block side will match
    /// them. (Previously this read `list_bitmask & 1 != 0`, on a profile
    /// field that no longer exists.)
    ///
    /// **Memory:** partitions a flat input, so it costs a full extra copy of
    /// the corpus — see `partition`'s `# Memory`.
    #[must_use]
    pub fn with_domains(domains: HashSet<CompactString, RandomState>) -> Self {
        let count = domains.len();
        tracing::info!(count, "filter engine loaded");
        Self::from_shard_maps(Self::partition(
            domains.into_iter().map(|d| (d, DomainMasks::block_only(1))),
        ))
    }

    /// Atomically swap the entire domain map (legacy single-mask input).
    ///
    /// Each `u64` is interpreted as the [`DomainMasks::block_mask`]; no
    /// allow-direction bits are set. Preserved verbatim for `lists::manager`
    /// — the per-direction split keeps the manager API back-compat.
    /// Kind-aware production wiring and the CLI verbs that set list
    /// direction (`warden blocklist import-local --kind allow`, `set-kind`)
    /// already exist, but neither routes through this method, which stays
    /// deliberately block-only.
    ///
    /// **Its cluster caller is gone.** A secondary used to install a primary's
    /// synced flat snapshot through here, and that transfer was deleted — a
    /// secondary now builds its own per-direction table from the replicated
    /// policy, exactly as the primary does. The remaining callers are
    /// `cli::commands::init`'s one-shot load and tests.
    ///
    /// This targets the 16 destination shards directly instead of collecting
    /// into an intermediate full-size `DomainMasks` map first. Measured at
    /// N = 2 000 000: +164.0 MB before, +169.1 MB after — that removes no
    /// memory; the intermediate *was* the incoming generation, so there was
    /// never a third table to delete, and the shards replace it one-for-one.
    /// What it does buy is structural: the destination is per-shard, which is
    /// the precondition for `swap_shard` to exist at all.
    ///
    /// **Memory:** partitions a flat input, so it costs a full extra copy of
    /// the corpus on top of the outgoing generation — see `partition`'s
    /// `# Memory`.
    ///
    /// This flat entry point still costs the caller's map plus a complete new
    /// generation, because a flat input cannot be partitioned before it is
    /// fully built. Reaching a lower reload peak needs the producer to build
    /// and install one shard at a time via [`Self::swap_shard_sorted`]; this
    /// shim exists so the callers that do not do that keep working
    /// unchanged.
    pub fn swap_domain_map(&self, map: HashMap<CompactString, u64, RandomState>) {
        let count = map.len();
        self.store_shard_maps(Self::partition(
            map.into_iter()
                .map(|(d, b)| (d, DomainMasks::block_only(b))),
        ));
        tracing::info!(count, "domain map swapped");
    }

    // `swap_domain_map_with_directions` was DELETED here.
    //
    // It was dead production code, and three doc comments in this file
    // asserted the opposite — that a clustering primary reached it "on every
    // reload via `ListManager::refresh`'s `cluster_primary` branch", pricing
    // it at ~+1 GB at the 12.3 M corpus, complete with the log line that node
    // supposedly emitted. **There is no `cluster_primary` branch.**
    // `grep -rn cluster_primary --include='*.rs' src/` matched only those
    // comments, in this file, describing themselves. The function's only
    // caller in the entire tree was its own test.
    //
    // It is deleted rather than kept because of what the sorted-shard
    // representation made of it. The derived representation
    // ([`SortedShard`]) needs each list bit to have one
    // direction, which the production producer guarantees structurally; this
    // function was a `pub` way to hand the engine an overlapping pair, and the
    // natural guard — a `debug_assert!` — compiles out of the shipped binary.
    // That is a correctness hole with no user: reachable only in release,
    // where the check is gone, through an API nothing calls. Keeping it would
    // have meant a `Result` and a real refusal path — error handling for a
    // caller that does not exist.
    //
    // The remaining fixture constructor, [`Self::with_per_direction_domain_map`],
    // can still express an overlapping pair; [`SortedShard::from_pairs`]
    // normalises it to allow-wins and WARNs at build time, in release.

    /// Atomically swap a flat blocklist into the engine.
    ///
    /// Legacy entry point — superseded by `swap_domain_map`, which carries
    /// per-list bitmasks. Kept only for the in-file tests; production callers
    /// should not use this.
    ///
    /// **Memory:** partitions a flat input, so it costs a full extra copy of
    /// the corpus on top of the outgoing generation — see `partition`'s
    /// `# Memory`.
    pub fn swap_blocklist(&self, domains: HashSet<CompactString, RandomState>) {
        let count = domains.len();
        self.store_shard_maps(Self::partition(
            domains.into_iter().map(|d| (d, DomainMasks::block_only(1))),
        ));
        tracing::info!(count, "blocklist swapped");
    }

    /// Probe one key against its shard.
    ///
    /// The `ArcSwap` guard is created and dropped inside this call, per probe.
    /// That is the measured design, not an oversight: hoisting the guards —
    /// caching a `[Guard; DOMAIN_SHARDS]`, or reusing one guard across the
    /// exact-match probe and the suffix probes — would pin those shards for the
    /// whole call and reintroduce exactly the generation coexistence sharding
    /// exists to bound. Every test in this file would still pass.
    /// # Cost — O(1) became O(log n)
    ///
    /// A binary search over one shard's ~801 692 entries is ~19.6 probes
    /// against ~23.6 for an unsharded slice, so **sharding now *reduces*
    /// search depth** — under hashing it was a measured latency cost, under
    /// binary search it is a win. Still zero-allocation and zero-lock, which
    /// is what CLAUDE.md's hot-path rule requires; O(1) was never the rule.
    ///
    /// # The `list_bitmask` short-circuit moved in here
    ///
    /// The caller used to skip the whole Tier 1 layer on
    /// `profile.list_bitmask != 0`. That field is gone: direction and
    /// subscription are now one per-profile pair held beside the corpus, so
    /// the question "does this profile subscribe to anything" can only be
    /// asked of the shard's own policy. It is asked here, **before** the
    /// binary search, so an admin profile subscribed to nothing still pays no
    /// search — it pays one `ArcSwap` load and one hash lookup per suffix
    /// instead of nothing at all. That is the honest price of moving the
    /// answer to where it cannot be stale.
    #[inline]
    fn probe_shard(&self, key: &str, profile: &str) -> Option<DomainMasks> {
        let guard = self.shards[Self::shard_index(key)].0.load();
        let shard: &SortedShard = &guard;
        let masks = shard.policy.masks_for(profile);
        if masks.is_inert() {
            return None;
        }
        shard
            .entries
            .binary_search_by(|(k, _)| k.as_str().cmp(key))
            .ok()
            .map(|pos| {
                let bits = shard.entries[pos].1;
                DomainMasks {
                    allow_mask: bits & masks.allow,
                    block_mask: bits & masks.block,
                }
            })
    }

    /// [`Self::probe_shard`] with no profile context — the lists' own `base`
    /// direction. See [`PolicyMasks::base`].
    #[inline]
    fn probe_shard_base(&self, key: &str) -> Option<DomainMasks> {
        let guard = self.shards[Self::shard_index(key)].0.load();
        let shard: &SortedShard = &guard;
        shard
            .entries
            .binary_search_by(|(k, _)| k.as_str().cmp(key))
            .ok()
            .map(|pos| shard.split_base(shard.entries[pos].1))
    }

    /// Profile-less block check: returns `true` if `domain` (or any parent
    /// domain) appears in any block-direction list, regardless of
    /// subscription bitmask.
    ///
    /// This is the deliberate "no profile context" entry point used by:
    /// - CNAME prefetch (`dns/handler.rs`) — shared cache has no client
    ///   profile, so per-profile filtering would be misleading.
    /// - CNAME chain no-profile branch (`dns/handler.rs`).
    /// - CLI / IPC / HTTP `query` commands when the caller has no client IP.
    /// - Offline blocklist mode (`cli/commands/query.rs`).
    ///
    /// Allow-direction (`base = allow`) hits are not reported by
    /// this method. An operator-curated allow-list domain is *not* "blocked"
    /// in the absence of a profile; the caller can rely on `is_blocked` to
    /// answer "would any block-direction list match" without false positives
    /// from allow-only entries.
    ///
    /// **Not** legacy — do not delete or `#[deprecated]` without auditing the
    /// callers above.
    ///
    /// `domain` must be lowercase ASCII; see the module-level lowercase invariant.
    pub fn is_blocked(&self, domain: &str) -> bool {
        debug_assert!(
            !domain.bytes().any(|b| b.is_ascii_uppercase()),
            "filter::is_blocked: domain must be lowercased before lookup (got `{domain}`)",
        );
        self.list_membership(domain).block_mask != 0
    }

    /// Profile-aware domain evaluation.
    ///
    /// Evaluation order:
    ///   1. `block_all` → BLOCK unless an admin allow matches
    ///   2. `$important` allow rule → FORWARD (short-circuits)
    ///   3. `$important` deny rule → BLOCK
    ///   4. normal allow rule OR `allow_domains` `HashSet` → FORWARD
    ///   5. normal deny rule OR `deny_domains` `HashSet` → BLOCK
    ///   6. **Tier 1 allow-direction list match → FORWARD**
    ///   7. **Tier 1 block-direction list match → BLOCK**
    ///   8. no match → FORWARD
    ///
    /// **Invariant (security-reviewable):** the admin layer (steps 2–5)
    /// runs strictly before the Tier 1 allow check. Any rule or HashSet
    /// match places `best_result`/`deny_hit` at a priority that fires *before*
    /// `allow_bits` is consulted, so an admin `$important deny` (step 3) on
    /// an allow-listed domain returns BLOCK — the allow-list cannot pierce
    /// the admin deny. Pinned by
    /// `tests::w1_2_admin_important_deny_overrides_allow_list`.
    ///
    /// Steps 2–5 are implemented as a single priority-tracking pass over
    /// `profile.rules` mirroring `evaluator::evaluate_rules`, with the
    /// `HashSet` checks interleaved at the matching priority tier.
    ///
    /// Thin wrapper over [`Self::evaluate_inner`]`::<false>`. The
    /// `ATTR = false` monomorphisation deletes every `BlockSource`
    /// construction site at codegen, so this path stays alloc-free and
    /// branch-equivalent to the previous standalone `evaluate` body.
    ///
    /// `#[inline(always)]` is intentional: with the plain `#[inline]` hint
    /// the bench harness (`benches/filter_bench.rs`) recorded a +3 % wall-
    /// clock regression on `evaluate/blocked` and +4.5 % on `evaluate/allowed`
    /// vs the pre-merge standalone body — LLVM kept the
    /// `(FilterResult, Option<BlockSource>)` tuple return ABI across the
    /// wrapper boundary instead of folding it into a 1-byte enum return.
    /// Forcing the inline drops both numbers back into the ±2 % noise floor.
    /// Same workaround documented on
    /// [`super::evaluator::priority_scan`].
    ///
    /// `domain` must be lowercase ASCII; see the module-level lowercase invariant.
    #[inline(always)]
    pub fn evaluate(&self, domain: &str, profile: &ResolvedProfile) -> FilterResult {
        let (verdict, _) = self.evaluate_inner::<false>(domain, profile);
        verdict
    }

    /// Profile-aware evaluation that also reports the source of any block.
    ///
    /// Mirrors [`Self::evaluate`] for verdict semantics — every input that
    /// produces `Forward` from `evaluate` produces `(Forward, None)` here,
    /// and every `Block` produces `(Block, Some(source))` where `source`
    /// names the layer responsible (Tier 1 list bit, admin rule, or admin
    /// block). Verdict + walk-shape agreement is now structural — both
    /// methods are thin wrappers over the same
    /// [`Self::evaluate_inner`] kernel; the
    /// `evaluate_and_evaluate_attributed_agree_on_verdict` proptest is
    /// retained as the regression guard against accidental drift inside
    /// the kernel.
    ///
    /// When the Tier 1 list layer fires on a domain that matches
    /// multiple block-direction lists, the [`BlockSource::List`] payload
    /// reports only the lowest set bit of the matching mask — see
    /// [`BlockSource::List`] for the rationale and the contract with the
    /// Dashboard v2 `block_list_bit` shape. Multi-list attribution
    /// requires a new variant, not a wider `List(u8)` payload.
    ///
    /// Used by the CNAME walker (`cname::walk_response`) to populate the
    /// `cname_block` audit log event in a single pass — replacing the
    /// previous second pass via `cname::attribute_block_source` that
    /// re-walked the same domain after `evaluate` had already decided.
    /// One walk on the block path; attribution is authoritative, not
    /// heuristic (no defensive fallback).
    ///
    /// Hot path callers that don't need attribution should use
    /// [`Self::evaluate`] — `evaluate_attributed` allocates a `CompactString`
    /// for the rule label on the rule-attributed Block branch (rare in
    /// practice; Tier 1 list bits and admin block are alloc-free).
    ///
    /// `domain` must be lowercase ASCII; see the module-level lowercase invariant.
    #[inline(always)]
    pub fn evaluate_attributed(
        &self,
        domain: &str,
        profile: &ResolvedProfile,
    ) -> (FilterResult, Option<BlockSource>) {
        self.evaluate_inner::<true>(domain, profile)
    }

    /// Shared evaluation kernel for [`Self::evaluate`] and
    /// [`Self::evaluate_attributed`].
    ///
    /// The const-generic `ATTR` controls attribution emission. At
    /// `ATTR = false`, every `if ATTR { ... } else { None }` is constant-
    /// folded to `None` at monomorphisation, the `best_rule` local is
    /// dead-store-eliminated by LLVM, and `rule_pattern_label` is never
    /// reached — so the non-attribution path stays alloc-free and
    /// branch-equivalent to the previous standalone `evaluate` body.
    /// At `ATTR = true`, every `Block` return carries a `Some(source)`;
    /// the only allocation is `rule_pattern_label` on the rule-attributed
    /// Block branch (`Wildcard` / `Regex` patterns format!-allocate; the
    /// `Exact` variant clones the inline `CompactString` and stays on the
    /// stack for domains ≤ 24 bytes).
    ///
    /// One source of truth for the walk + resolution stages. Previously
    /// the engine carried two parallel ~270 LOC bodies with verdict
    /// agreement pinned only by a proptest — which did not pin walk shape,
    /// so a change applied to one method but not the other would silently
    /// drift attribution while still satisfying the verdict check. Merging
    /// removes the drift surface entirely; the proptest now guards against
    /// accidental kernel-side drift rather than cross-method drift.
    ///
    /// `#[inline(always)]` matches the wrappers — see [`Self::evaluate`]
    /// for the rationale (LLVM kept the tuple ABI across the wrapper
    /// boundary at plain `#[inline]`, producing a +3-4 % wall-clock
    /// regression in the engine bench).
    #[inline(always)]
    fn evaluate_inner<const ATTR: bool>(
        &self,
        domain: &str,
        profile: &ResolvedProfile,
    ) -> (FilterResult, Option<BlockSource>) {
        debug_assert!(
            !domain.bytes().any(|b| b.is_ascii_uppercase()),
            "filter::evaluate_inner: domain must be lowercased before lookup (got `{domain}`)",
        );

        // 1. block_all: deny everything except admin-allow-listed domains.
        //
        // Tier 1 allow-direction lists do NOT pierce `block_all` by design.
        // The truth table describes non-`block_all` profiles; `block_all`
        // is a profile-level operator policy that
        // says "deny everything except what I, the admin, explicitly
        // allow." Honouring a sandboxed external (or even local) allow-list
        // here would weaken that policy without an explicit operator
        // signal. Operators that want a curated allow-list to bypass a
        // "night" profile can author an admin `@@||domain^` rule instead.
        //
        // Verdict-equivalent to the previous `evaluate`'s
        // `evaluate_rules(...) == Some(Forward)` check: `priority_scan`
        // returns the highest-priority match; only a winning Allow forwards.
        // Any other match (Block, `$important deny`) or no-match falls
        // through to the block_all default Block. One scan serves both
        // ATTR variants.
        if profile.block_all {
            if domain_matches_set(domain, &profile.allow_domains) {
                return (FilterResult::Forward, None);
            }
            if let Some((_, rule)) = super::evaluator::priority_scan(&profile.rules, domain) {
                if matches!(rule.action, RuleAction::Allow) {
                    return (FilterResult::Forward, None);
                }
            }
            // Attribution coarsens to AdminBlock here by design: even when a
            // specific `$important` deny rule was the
            // proximate match, under `block_all` the operator's profile-level
            // "deny everything" policy IS the reason, so the audit log / CNAME
            // `cname_source` records the policy, not the incidental rule.
            // `evaluate_attributed` is precise everywhere else; this is the one
            // deliberate coarsening.
            return (
                FilterResult::Block,
                if ATTR {
                    Some(BlockSource::AdminBlock)
                } else {
                    None
                },
            );
        }

        // 2-5. Priority scan over `profile.rules`: pick the single
        // highest-priority rule match. The shared `priority_scan` helper in
        // `evaluator.rs` is the canonical scanner — used here and in the
        // standalone `evaluate_rules` shim. The HashSet checks (priority 1
        // allow, priority 0 deny) are interleaved below in the unified walk;
        // `priority_scan` does not model them because it operates on rules
        // alone.
        let mut best_priority: i8 = -1;
        let mut best_result: Option<FilterResult> = None;
        // `best_rule` is dead-stored on the `ATTR = false` monomorphisation;
        // LLVM elides the local plus the `if ATTR { ... }` assign-site at
        // codegen for the non-attribution path.
        let mut best_rule: Option<&super::rules::DnsRule> = None;
        if let Some((priority, rule)) = super::evaluator::priority_scan(&profile.rules, domain) {
            best_priority = priority;
            best_result = Some(match rule.action {
                RuleAction::Allow => FilterResult::Forward,
                RuleAction::Block => FilterResult::Block,
            });
            if ATTR {
                best_rule = Some(rule);
            }
            // Important allow can't be beaten — short-circuit.
            if priority == 3 {
                return (FilterResult::Forward, None);
            }
        }

        // Unified subdomain walk. Previously the engine ran three independent
        // suffix scans (allow_domains, deny_domains, list_membership) — same
        // byte slice, three passes, three times the L1 traffic. Now one pass
        // probes every enabled set per dot-position. Set-empty /
        // bitmask-zero short circuits keep the walk completely off the hot path
        // when no probe is needed.
        //
        // The Tier 1 hit is a `DomainMasks { allow_mask, block_mask }`; the
        // walk OR-accumulates each direction separately so the resolution
        // stage can fire the allow path before the block path.
        //
        // Priority semantics preserved byte-identically with the previous
        // `domain_matches_set` chain for the block-only case:
        //   - `allow_domains` hit at any suffix → Forward (priority 1, beats
        //     a tier-0 normal-deny rule that may already have set best_result).
        //   - `deny_domains` hit at any suffix → Block (priority 0, only
        //     consulted when no rule produced a result).
        //   - Tier 1 `allow_mask` hit → Forward (only fires when the admin
        //     layer produced no result).
        //   - Tier 1 `block_mask` hit → Block (last).
        let want_allow = best_priority < 1 && !profile.allow_domains.is_empty();
        let want_deny = best_result.is_none() && !profile.deny_domains.is_empty();
        // The second half of this test used to be
        // `profile.list_bitmask != 0`, and that one field was doing two jobs.
        // They separate here.
        //
        // - *"does this profile subscribe to anything"* is no longer a
        //   property of the profile — it is one half of the per-profile pair
        //   held beside the corpus — so it moved into `probe_shard`, where it
        //   is answered against the generation that will actually serve the
        //   query. See that method's docs for what the move costs.
        // - *"this device opted out of list filtering"* (D14,
        //   `[[devices]].unfiltered`) is still a property of the resolution
        //   and has to be asked HERE. It used to be expressed by an empty tag
        //   set zeroing the mask, which is exactly why it vanished when the
        //   masks left: an `unfiltered` device now carries its profile's real
        //   masks, so `probe_shard` finds them non-inert and would filter a
        //   device the operator told warden not to filter.
        //
        // Only the list layer is skipped. `block_all`, admin rules and the
        // `allow_domains` / `deny_domains` sets still apply — exactly as they
        // did when `unfiltered` worked by emptying the tag set. Pinned by
        // `an_unfiltered_resolution_skips_the_list_layer_entirely` and
        // `unfiltered_does_not_lift_block_all_or_admin_rules`.
        let want_bits = best_result.is_none() && !profile.unfiltered;

        if !(want_allow || want_deny || want_bits) {
            // Nothing to probe — either a rule already won at priority ≥ 1, or
            // a tier-0 rule won and the only thing the walk could do is be
            // beaten by an allow we know is empty.
            //
            // On `ATTR = true` a `Some(Block)` here is the `$important deny`
            // path (or any rule-wins-no-walk path) and must carry a
            // `BlockSource::Rule(label)` so the CNAME walker / proptest see
            // the same source they got from the resolution stage. The
            // attribution build is monomorphised out on `ATTR = false`,
            // preserving the alloc-free fast path.
            let verdict = best_result.unwrap_or(FilterResult::Forward);
            let source = if ATTR {
                match verdict {
                    FilterResult::Forward => None,
                    FilterResult::Block => {
                        let label = best_rule
                            .map(|rule| rule_pattern_label(&rule.pattern))
                            .unwrap_or_default();
                        Some(BlockSource::Rule(label))
                    }
                }
            } else {
                None
            };
            return (verdict, source);
        }

        // Single byte-walk: probe enabled sets at exact match + each suffix
        // after a '.'.
        //
        // The Tier 1 probe used to hoist ONE `ArcSwap` guard here for the
        // whole call ("at most one load per call, ATTR-independent").
        // Sharding breaks that invariant by construction — every suffix of a
        // domain hashes to a different shard, so each probe loads its own
        // shard: measured mean 2.76 loads per query, still ATTR-independent,
        // still zero-alloc and zero-lock. Restoring a single hoisted guard is
        // not possible without a single map, and hoisting the *shards* instead
        // (see `probe_shard`) would defeat the reload-peak bound the whole
        // change exists for. The `want_bits` short-circuit still keeps the
        // Tier 1 layer entirely off the path when no bits are needed.
        let mut deny_hit = false;
        let mut allow_bits: u64 = 0;
        let mut block_bits: u64 = 0;

        // Exact match.
        if want_allow && profile.allow_domains.contains(domain) {
            return (FilterResult::Forward, None);
        }
        if want_deny && profile.deny_domains.contains(domain) {
            deny_hit = true;
        }
        if want_bits {
            if let Some(m) = self.probe_shard(domain, &profile.name) {
                allow_bits |= m.allow_mask;
                block_bits |= m.block_mask;
            }
        }

        // Subdomain walk: byte-offset scan for '.' (NOT find('.') + substring
        // per CLAUDE.md hot-path discipline).
        let bytes = domain.as_bytes();
        for (i, &byte) in bytes.iter().enumerate() {
            if byte != b'.' {
                continue;
            }
            let suffix = &domain[i + 1..];
            if suffix.is_empty() {
                continue;
            }
            if want_allow && profile.allow_domains.contains(suffix) {
                return (FilterResult::Forward, None);
            }
            if want_deny && !deny_hit && profile.deny_domains.contains(suffix) {
                deny_hit = true;
            }
            // NOTE: no early exit. The walk probes EVERY suffix and
            // OR-accumulates both masks across all of them — it is not
            // first-match-wins. A `break` on the first hit here would change
            // verdicts (an allow-direction hit on a parent must still be able
            // to beat a block-direction hit on a child).
            if want_bits {
                if let Some(m) = self.probe_shard(suffix, &profile.name) {
                    allow_bits |= m.allow_mask;
                    block_bits |= m.block_mask;
                }
            }
        }

        // Walk completed without an admin-allow hit. Resolve in priority order.
        // Invariant: a populated `best_result` (admin rule, including
        // `$important deny`) wins before Tier 1 allow is even consulted.
        if let Some(r) = best_result {
            return match r {
                FilterResult::Forward => (FilterResult::Forward, None),
                FilterResult::Block => {
                    let source = if ATTR {
                        // `best_rule` is `Some` whenever `best_result` is `Some`
                        // — they are written together under the same
                        // `priority_scan` branch above.
                        let label = best_rule
                            .map(|rule| rule_pattern_label(&rule.pattern))
                            .unwrap_or_default();
                        Some(BlockSource::Rule(label))
                    } else {
                        None
                    };
                    (FilterResult::Block, source)
                }
            };
        }
        // Admin priority-0 deny via deny_domains beats Tier 1 allow (the
        // Tier 1 allow check sits below admin rules in evaluation order).
        if deny_hit {
            return (
                FilterResult::Block,
                if ATTR {
                    Some(BlockSource::AdminBlock)
                } else {
                    None
                },
            );
        }
        // Allow-direction Tier 1 hit forwards.
        //
        // No AND with a profile subscription mask any more. The masks the
        // walk accumulated were already this profile's — projected onto
        // this generation's bits at publish time — so a second AND here
        // would either be a no-op or a second, staler opinion about the
        // same question. That is the defect the per-profile projection
        // exists to remove.
        if allow_bits != 0 {
            return (FilterResult::Forward, None);
        }
        // Block-direction Tier 1 hit blocks.
        let effective = block_bits;
        if effective != 0 {
            let source = if ATTR {
                Some(BlockSource::List(effective.trailing_zeros() as u8))
            } else {
                None
            };
            return (FilterResult::Block, source);
        }

        // No match → forward
        (FilterResult::Forward, None)
    }

    /// Get the combined per-direction list-membership masks for a domain,
    /// walking subdomains.
    ///
    /// For `sub.tracker.example.com`, checks and ORs masks for:
    ///   1. `sub.tracker.example.com` (exact)
    ///   2. `tracker.example.com` (parent)
    ///   3. `example.com` (grandparent)
    ///   4. `com` (TLD)
    ///
    /// Returns the OR-aggregated [`DomainMasks`] across every suffix hit,
    /// split by the lists' own `base` direction — **no profile context**.
    /// [`Self::is_blocked`] reads only `block_mask`;
    /// [`Self::list_membership_for`] is the per-profile sibling.
    ///
    /// The profile-aware [`Self::evaluate`] walks the same shards inline so
    /// it never invokes this method on the hot path.
    ///
    /// `domain` must be lowercase ASCII; see the module-level lowercase invariant.
    pub fn list_membership(&self, domain: &str) -> DomainMasks {
        debug_assert!(
            !domain.bytes().any(|b| b.is_ascii_uppercase()),
            "filter::list_membership: domain must be lowercased before lookup (got `{domain}`)",
        );
        self.walk_membership(domain, |eng, key| eng.probe_shard_base(key))
    }

    /// [`Self::list_membership`] answered for one profile.
    ///
    /// The masks are this generation's projection of `profiles.<id>.lists` +
    /// each list's `base`, so a bit the profile ignores appears in neither
    /// half — do **not** reconstruct membership by OR-ing them.
    ///
    /// Exists for callers that need to tell an allow-direction FORWARD from a
    /// no-match FORWARD, a distinction [`FilterResult`] cannot carry.
    /// `tests/plp_s1_verdict_golden.rs` is the one that matters: without it
    /// the golden collapses to two values and a refactor that dropped the
    /// allow side entirely would leave every row unchanged.
    ///
    /// `domain` must be lowercase ASCII; see the module-level lowercase invariant.
    pub fn list_membership_for(&self, domain: &str, profile: &str) -> DomainMasks {
        debug_assert!(
            !domain.bytes().any(|b| b.is_ascii_uppercase()),
            "filter::list_membership_for: domain must be lowercased before lookup (got `{domain}`)",
        );
        self.walk_membership(domain, |eng, key| eng.probe_shard(key, profile))
    }

    /// Exact match plus the subdomain walk, OR-accumulating whatever `probe`
    /// returns.
    ///
    /// Like the `evaluate_inner` walk this must not gain an early exit: an
    /// allow-direction hit on a parent has to be able to beat a
    /// block-direction hit on a child. PerfMem S2 made each probe select and
    /// load its own shard.
    #[inline]
    fn walk_membership(
        &self,
        domain: &str,
        probe: impl Fn(&Self, &str) -> Option<DomainMasks>,
    ) -> DomainMasks {
        let mut masks = DomainMasks::default();

        if let Some(m) = probe(self, domain) {
            masks.allow_mask |= m.allow_mask;
            masks.block_mask |= m.block_mask;
        }

        let bytes = domain.as_bytes();
        for (i, &byte) in bytes.iter().enumerate() {
            if byte == b'.' {
                let suffix = &domain[i + 1..];
                if !suffix.is_empty() {
                    if let Some(m) = probe(self, suffix) {
                        masks.allow_mask |= m.allow_mask;
                        masks.block_mask |= m.block_mask;
                    }
                }
            }
        }

        masks
    }

    /// **Fixture-only.** Give `profile` the subscription `bits` against the
    /// generation currently installed, splitting them by that generation's
    /// own direction.
    ///
    /// # Why this exists and why production must never call it
    ///
    /// Previously a fixture said "this profile subscribes to bits N" by
    /// setting `ResolvedProfile.list_bitmask`, and the hot path AND-ed it
    /// against the entry's direction masks. Both halves of that pair now live
    /// beside the corpus, so a fixture has to say the same
    /// thing to the **engine**. That is the change working, not an
    /// inconvenience of it: a test can no longer express a subscription the
    /// published generation never agreed to, which is exactly the state a
    /// stale positional mask used to be able to reach in production.
    ///
    /// The split is taken from each shard's own [`ListPolicy::base_masks`],
    /// per shard, so this reproduces the old `allow_mask & list_bitmask` /
    /// `block_mask & list_bitmask` arithmetic exactly — including the
    /// deliberate cross-shard independence of [`Self::probe_shard`].
    ///
    /// Entries are carried over into the new shard untouched and republished
    /// in the same `Arc` as the policy, so the pairing invariant holds. What
    /// makes it fixture-only is **semantic**: it republishes a policy the
    /// config never produced. A production caller would be re-introducing a
    /// write-path bug — policy and corpus from two different configs. There
    /// is none, and there must not be one; the production
    /// install path is `ListManager::refresh` → [`ListPolicy::publish`].
    ///
    /// `pub` rather than `#[cfg(test)]` because the integration tests in
    /// `tests/` link the library compiled *without* `cfg(test)`.
    #[doc(hidden)]
    pub fn fixture_subscribe(&self, profile: &str, bits: u64) {
        let gen_id = ListPolicy::next_gen_id();
        for shard in &self.shards {
            let cur = shard.0.load();
            let base = cur.policy.base;
            let mut per_profile: HashMap<CompactString, ProfileMasks, RandomState> =
                cur.policy.per_profile.clone();
            per_profile.insert(
                CompactString::new(profile),
                ProfileMasks {
                    allow: base.allow & bits,
                    block: base.block & bits,
                },
            );
            shard.0.store(Arc::new(SortedShard {
                entries: cur.entries.clone(),
                policy: Arc::new(ListPolicy {
                    per_profile,
                    base,
                    fallback: cur.policy.fallback,
                    gen_id,
                }),
            }));
        }
    }

    /// Number of domains currently loaded, summed across every shard.
    ///
    /// The sum is not a snapshot of one instant — shards are loaded one after
    /// another, so a count taken during a reload may straddle two generations.
    /// Consumers (IPC / API status, `lists::manager` capacity hint) only ever
    /// use it as a magnitude, never as an invariant.
    pub fn domain_count(&self) -> usize {
        self.shards.iter().map(|s| s.0.load().len()).sum()
    }

    /// The [`ListPolicy::gen_id`] each shard is currently serving, in shard
    /// order.
    ///
    /// **One id per shard, deliberately not one for the engine.** Shards are
    /// installed one at a time and a shard that fails to build keeps its
    /// previous generation, so "the generation the engine is serving" is not
    /// always a single value — the type says so rather than papering over it
    /// with a first-shard read that is right most of the time.
    ///
    /// Cold path: used to verify every write path actually reaches the
    /// publish function, and for status reporting. Never consulted per
    /// query.
    #[must_use]
    pub fn filter_gen_ids(&self) -> Vec<u64> {
        self.shards
            .iter()
            .map(|s| s.0.load().policy().gen_id())
            .collect()
    }
}

/// Stable audit-log label for a [`RulePattern`].
///
/// Used by [`FilterEngine::evaluate_attributed`] to populate
/// `BlockSource::Rule(label)` in one pass. Moved here from `cname.rs`
/// alongside the `evaluate_attributed` consolidation — the previous home
/// was the heuristic second-pass `attribute_block_source` (now removed).
///
/// Allocation: `Exact` clones the inline-friendly `CompactString` (≤24
/// bytes inline). `Wildcard` and `Regex` go through `format!` so they
/// always allocate; in practice both are rare and only the rule-attributed
/// Block path pays this cost.
#[must_use]
pub(crate) fn rule_pattern_label(pattern: &RulePattern) -> CompactString {
    match pattern {
        RulePattern::Exact(d) => d.clone(),
        RulePattern::Wildcard(s) => CompactString::from(format!("*.{s}")),
        RulePattern::Regex { source, .. } => CompactString::from(format!("/{source}/")),
    }
}

/// Check if a domain (or any of its parent domains) matches a set.
/// Same subdomain walk as `list_membership` but against a `HashSet`.
///
/// `pub(crate)` so the per-device overlay layer
/// (`crate::profiles::resolver::overlay_decision_for`) can run the same
/// subdomain-walk semantics against `DeviceOverlay.allow` /
/// `DeviceOverlay.deny` without duplicating the byte-scan loop.
/// Zero-allocation, two probes per query against the overlay sets.
///
/// `domain` must be lowercase ASCII; see the module-level lowercase invariant.
pub(crate) fn domain_matches_set(domain: &str, set: &HashSet<CompactString, RandomState>) -> bool {
    debug_assert!(
        !domain.bytes().any(|b| b.is_ascii_uppercase()),
        "filter::domain_matches_set: domain must be lowercased before lookup (got `{domain}`)",
    );
    if set.is_empty() {
        return false;
    }
    if set.contains(domain) {
        return true;
    }
    let bytes = domain.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'.' {
            let suffix = &domain[i + 1..];
            if !suffix.is_empty() && set.contains(suffix) {
                return true;
            }
        }
    }
    false
}

/// Parse a blocklist text file into a set of `CompactString` domains.
///
/// Delegates to the canonical parser in `lists::parser`.
#[must_use]
pub fn parse_blocklist(content: &str) -> HashSet<CompactString, RandomState> {
    crate::lists::parser::parse_domain_list(content)
}

#[cfg(test)]
mod tests;
