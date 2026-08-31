//! Lock-free filter engine backed by [`DOMAIN_SHARDS`] independent
//! `ArcSwap<SortedShard>` cells with per-list bitmasks.
//!
//! Each domain is stored once, tagged with a `u64` of **source bits** — the
//! union of the list bits that contain it. Callers see that as a
//! [`DomainMasks`] pair (block-direction and allow-direction, `base = allow`,
//! S50 T1 / `_docs/features/lists_categories_v1.md` §4 step 5), recovered per
//! probe from the shard's own [`ListPolicy`]; direction is a per-*source*
//! property, so storing it per domain was storing one global fact 12.8 M
//! times. Each profile has its own per-direction mask pair, materialised on
//! the generation's `ListPolicy` and reached by profile id — **not** a field
//! on `ResolvedProfile`, which `plp-s3` removed (`list_bitmask` there was one
//! field doing two jobs, and it travelled under a different `ArcSwap` from the
//! corpus that gave its bits meaning). Filtering is a shard select plus a
//! binary search plus a handful of bitwise ANDs — zero allocation, zero lock.
//!
//! The hot path (`evaluate`) does: per-suffix shard select → `ArcSwap` load →
//! binary search with subdomain walk → admin layer (rules + `allow_domains`
//! / `deny_domains` HashSets) → Tier 1 allow-mask AND → Tier 1 block-mask AND.
//! Background list refresh calls [`FilterEngine::swap_shard_sorted`] to
//! replace one shard at a time, or
//! `swap_domain_map` (legacy, single-mask input treated as block-only) to
//! replace every shard at once.
//!
//! **`mem-t6`, 2026-08-16:** each shard is an exact-size sorted slice
//! ([`SortedShard`]), not a `HashMap`. Lookup is O(log n) rather than O(1) —
//! still zero-allocation and zero-lock, which is what the hot-path rule
//! requires. See [`SortedShard`] for why one `u64` replaced two.
//!
//! # Sharding (PerfMem S2, `_docs/features/memory_architecture_evaluation.md` §6/§11)
//!
//! The map is split into [`DOMAIN_SHARDS`] cells keyed on
//! [`FilterEngine::shard_index`] of the full domain. This exists for **reload
//! peak memory**, not for throughput: with one `ArcSwap` a reader holding the
//! old `Arc` keeps it alive until it finishes, so old and new generations must
//! coexist — measured 780 MB steady against a 2.02 GB peak. Sharding does not
//! remove the coexistence, it *bounds* it to the shard in flight (measured
//! 43.0 MB at N = 16).
//!
//! **Corrected 2026-08-01 — the producer landed; retargeted 2026-08-16 by
//! `mem-t6`.** The producer is `lists::manager::ListManager::refresh`
//! (`src/lists/manager.rs`): it builds each shard from spill records and
//! installs it one at a time — since `mem-t6` via
//! [`FilterEngine::swap_shard_sorted`] — never materialising a
//! flat map. That path is reached from both `cli::commands::start`'s
//! boot/reload paths and `cli::commands::update::run_update`'s foreground
//! refresh — every caller that goes through `ListManager::refresh` (landed
//! 2026-07-30, neutrality-06, commit 9119d98). See
//! `_docs/features/memory_architecture_evaluation.md` §11 for the measured
//! producer transient on the integrated tree — 302.9 MB (flat) vs 60.1 MB
//! (sharded) at N = 2 000 000; the 43.0 MB figure above is a projection at a
//! different N and was not re-measured against the shipped producer.
//!
//! The flat path has no production caller left on the list-refresh side. Every
//! node — clustering or not — now installs shard-at-a-time via
//! [`FilterEngine::swap_shard_sorted`]; the clustering-primary branch that rebuilt one
//! full map to publish a sync artifact was deleted with the artifact itself
//! (cluster sync S1, `_docs/features/cluster_sync_policy_only.md` §3). The flat
//! entry points remain for `init`'s one-shot load and for tests, and still pay
//! what `FilterEngine::partition`'s `# Memory` section describes. The hot-path
//! cost below, by contrast, is paid unconditionally.
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
//! the Sprint 15 case-normalization design — do not add one.
//!
//! # Subdomain walk sites
//!
//! The byte-offset suffix scan — a `for` loop over the domain's bytes
//! filtering on `b'.'`, per the project rules hot-path discipline (NOT
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
/// The knee below was measured against the **hash** representation
/// (`_docs/features/memory_architecture_evaluation.md` §6, real 12 287 120-domain
/// corpus, 50 050 probes at 50 % hit):
///
/// | N | ns/query | reload transient |
/// |---|---|---|
/// | 1 (pre-S2) | 236 | ~780 MB |
/// | **16** | **375** | **43.0 MB** |
/// | 64 | 409 | 10.7 MB |
/// | 256 | 586 | 2.7 MB |
///
/// Under hashing, sharding *cost* latency: loads/query is bounded by label
/// count (2.76 at every N), but each shard is a separate allocation and the
/// working set of shard cells, `Arc` control blocks and table headers stopped
/// fitting in cache.
///
/// # `mem-t6` — the sign of the latency term flipped, the value did not
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
/// outside the process (the §11 T3 `.shard/` spill files) is valid only for the
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
/// 16 bytes per profile per generation.
/// `_docs/features/profile_list_policy.md` §7 prices the whole table at
/// 64 profiles × 16 B, which is noise beside a 12.8 M-domain corpus — so
/// nothing here is packed, interned, or shared, and it should stay that way.
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
    /// Never a permission — `_docs/features/profile_list_policy.md` §2.4:
    /// *"Un `ProfileId` sconosciuto in questa generazione → profilo di
    /// default restrittivo, mai un permesso."*
    ///
    /// A profile can only be absent when the resolver map and the corpus were
    /// published from different configs (a republish lag), and the two errors
    /// are not symmetric. Handing it the inherited [`PolicyMasks::base`] would
    /// give it every `base = "allow"` list, and an allow bit surviving into a
    /// generation that did not mint it is the **fail-open** direction §1.4
    /// names as the fatal one: allow beats block, so a deny-list's domains
    /// would silently stop being blocked. Blocking every list instead
    /// over-blocks, which someone notices and reports.
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
    /// pre-`plp-s3` `profile.list_bitmask != 0` test (M-17). Same contract —
    /// an admin profile subscribed to nothing pays nothing — asked of the
    /// policy instead of of the profile.
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
/// which is precisely the shape `_docs/features/profile_list_policy.md` §2.4
/// forbids. The config speaks ids; only the builder speaks bits.
/// The default is **fail-closed**, and it was fail-open for the length of one
/// test run — worth keeping the reason where the type is.
///
/// `#[derive(Default)]` gives `base = {allow: 0, block: 0}`, i.e. *no list
/// filters anything*. The scalar this replaced defaulted to `allow_bits = 0`,
/// which under `bits & !allow_bits` meant **every list is deny-direction** —
/// the opposite. Twelve `lists::manager` tests caught it by asserting
/// `is_blocked` on a manager that had never been handed a policy; the shape
/// in production is a construction site that forgets `set_list_policy` and
/// silently serves an unfiltered corpus, which is the failure direction §1.4
/// names as the one nobody notices.
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
/// # What `plp-s3` put inside it
///
/// `plp-s1` created the seat with one global `allow_bits`; `plp-s3` filled it
/// with the per-profile table §2.4 (D-ARCH-1) requires. Direction is no
/// longer one map for every reader: [`Self::masks_for`] answers per profile,
/// and the answer is materialised against **this** generation's bits, inside
/// the `Arc` that already publishes atomically with `entries`. It is *not* a
/// second `ArcSwap`, and it is *not* a field on `ResolvedProfile` — see the
/// [`SortedShard`] type docs for why both of those fail open.
///
/// # `gen_id`
///
/// Identity of the publish that minted this policy. [`Self::next_gen_id`] is
/// the only site that advances the counter, so "did this mutation actually
/// reach the filter?" is answered by whether the served `gen_id` moved rather
/// than by reading the call graph — which is what makes §2.4's write-path
/// requirement ("refresh liste e reload config condividono una sola funzione
/// di publish") checkable instead of merely asserted in prose.
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
/// # Why one `u64` and not two (`mem-t6`, 2026-08-16)
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
/// `_docs/features/profile_list_policy.md` §2.4 records why: the profile map
/// is a *different* `ArcSwap` published by a *different* path (config
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
///
/// **Relocated 2026-08-16 at integration.** This block was written attached to
/// [`ShardOrderError`] — concatenated onto that type's own doc with no item
/// between them — so the design rationale for this sprint's headline change
/// documented an error type while `SortedShard` itself had no doc at all. The
/// broken `Self::allow_bits` link was the symptom that exposed it: the prose
/// was right, `Self` was not.
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
    /// Was a bare `allow_bits: u64` until `plp-s1`. The pairing property
    /// described above is unchanged; what changed is that the thing being
    /// paired now has a name and a generation id, so
    /// `_docs/features/profile_list_policy.md` S2 can extend it in place
    /// instead of hoisting it somewhere that fails open.
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
            // Zero-padded to a fixed 16 hex digits on purpose: this is a
            // BITMASK, so bit positions must line up when two shards' lines
            // are read side by side, and a leading-zero run must stay visible
            // rather than being absorbed by a variable-width `{:#x}`.
            // Zero-padded to a fixed 16 hex digits on purpose: these are
            // BITMASKS, so bit positions must line up when two shards' lines
            // are read side by side.
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
    /// # It is NOT a production fail-open — mem-t6 made the class unrepresentable
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
    /// [`FilterEngine::evaluate`] reaches anyway (§4 step 5 is consulted
    /// before step 6); there only [`FilterEngine::is_blocked`], which reads
    /// `block_mask` alone, differs.
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
/// list per `_docs/features/lists_categories_v1.md` §2 W1.1) contains this domain.
/// `allow_mask` bit N is set when a `base = allow` list with bit index N
/// contains this domain.
///
/// Both masks live in a single 16-byte `Copy` struct. The walk accumulates
/// this profile's masks directly — the AND against a profile-side subscription
/// mask is gone with `ResolvedProfile.list_bitmask` (`plp-s3`); admin rules sit
/// above this layer in priority and override allow-list matches per W1.2
/// (`$important deny` is sovereign).
///
/// # This is the interface, not the storage — and the invariant that follows
///
/// **`mem-t6`, 2026-08-16:** shards no longer *store* this struct. They store
/// one `u64` of source bits per domain plus one [`ListPolicy`] per shard, and
/// [`FilterEngine::probe_shard`] reconstitutes the pair per probe. That is
/// lossless because of an invariant worth stating explicitly:
///
/// > **A list bit belongs to exactly one direction *per reader*.** `plp-s3`
/// > widened "per reader" from "everyone" to "per profile": the effective
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
    /// after the admin layer per §4 step 5.
    pub allow_mask: u64,
    /// Bits set for block-direction lists (`base = deny`, the default) that
    /// contain this domain. Hits this mask trigger [`FilterResult::Block`]
    /// only when no allow-direction list also matched (§4 step 6).
    pub block_mask: u64,
}

impl DomainMasks {
    /// Build masks where every bit lives in `block_mask` (back-compat with
    /// pre-S50 callers that produce a single `u64` bitmask). Used to convert
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
    /// (`pm2607-t3` / §6 row 2). That removes one *conversion* table, not the
    /// duplication below — see `# Memory`.
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
    /// **`mem-t6` note.** The pre-sizing rationale that used to fill this
    /// section was entirely about hashbrown — power-of-two bucket counts, 7/8
    /// load, the "16 shards sum to exactly 16 777 216 buckets" identity, and a
    /// warning never to add headroom because it could push a shard across a
    /// power-of-two boundary and double its table. **None of it survives the
    /// sorted representation, which has no buckets and no load factor**, so it
    /// is deleted rather than left to read as still-true. `Vec::with_capacity`
    /// here is an exact reservation, not a rounded one, and over-reserving now
    /// costs only the slack itself — which [`SortedShard::from_pairs`] returns
    /// with `shrink_to_fit`.
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
    /// `mem-t6` changed the stored representation to [`SortedShard`], but this
    /// signature is **preserved deliberately** so `lists::manager` keeps
    /// compiling unchanged. The conversion costs one transient sorted slice
    /// (~26 MB) alongside the caller's `HashMap` (~43 MB) for **one shard at a
    /// time**, so the reload peak rises by the smaller of the two while steady
    /// state falls by 277 MB. The PerfMem S2 one-shard-at-a-time bound is
    /// preserved, not spent.
    ///
    /// [`Self::swap_shard_sorted`] is the allocation-free path that removes
    /// even that transient. A producer that can emit sorted records should
    /// call it instead.
    ///
    /// # Panics
    ///
    /// Panics if `idx >= DOMAIN_SHARDS`.
    ///
    /// # Test-only since the producer bridge (2026-08-16)
    ///
    /// `ListManager::refresh` now installs through
    /// [`Self::swap_shard_sorted`], so this `HashMap`-taking form has **no
    /// production caller** — only the three fixtures in this file's `mod
    /// tests`. It is gated rather than deleted because those fixtures build
    /// their input as a map and reading them is easier than rewriting them.
    ///
    /// Do not remove the gate to "make it available": an ungated dead swap
    /// function is precisely finding F-O of this sprint, where
    /// `swap_domain_map_with_directions` sat dead while three comments priced
    /// it at +1 GB.
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
    /// no allow-direction bits are set. This signature predates the S50 T1
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
    /// Primary S50 T1 constructor — each entry already carries split allow /
    /// block masks. Used by tests that exercise the §4 step 5 ALLOW path.
    /// Production reaches the engine by swapping an already-constructed one,
    /// never through this constructor: it always builds the engine empty
    /// ([`Self::new`]) and populates it by swap, so this is a fixture-only
    /// entry point.
    ///
    /// **Corrected twice on 2026-08-16 — first by `mem-t6`, then by the
    /// producer bridge hours later.** This paragraph first named
    /// `swap_domain_map_with_directions` as the clustering-primary route; that
    /// method was dead and is deleted. It then named `swap_shard` as the only
    /// production install path, which the bridge falsified the same day by
    /// moving the producer to [`Self::swap_shard_sorted`].
    ///
    /// Three revisions, each true when written, is the signal: **do not write
    /// the current installer's name here.** The production install path is
    /// whichever `swap_shard*` the list manager calls —
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
    /// them. (Pre-`plp-s3` this read `list_bitmask & 1 != 0`, on a profile
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
    /// — the S50 T1 split keeps the manager API back-compat. **Corrected
    /// 2026-08-01:** kind-aware production wiring landed in S50 T3 on
    /// 2026-07-30 (neutrality-06, commit 9119d98) and the CLI verbs already
    /// exist (`warden blocklist import-local --kind allow`, `set-kind`) —
    /// but neither routes through this method, which stays deliberately
    /// block-only.
    ///
    /// **Its cluster caller is gone.** A secondary used to install a primary's
    /// synced flat snapshot through here, and that transfer was deleted in
    /// cluster sync S1 — a secondary now builds its own per-direction table
    /// from the replicated policy, exactly as the primary does. The remaining
    /// callers are `cli::commands::init`'s one-shot load and tests.
    ///
    /// **`pm2607-t3` (T0) — what it did, and what it did not.** This used to
    /// `collect()` the whole input into a second full-size `DomainMasks` map
    /// and only then store it; that collect now targets the 16 destination
    /// shards directly. **It removed no memory.** The "intermediate" *was* the
    /// incoming generation — there was never a third table to delete — and the
    /// shards replace it one-for-one. Measured at N = 2 000 000: +164.0 MB
    /// before, +169.1 MB after; no reduction. What t3 actually bought is
    /// structural — the destination is per-shard, which is the precondition
    /// for `swap_shard` to exist at all. An earlier revision of this
    /// paragraph claimed a ~780 MB saving; it was false, and the paragraph
    /// below it already said so. Do not restate t3 as a saving.
    ///
    /// **Memory:** partitions a flat input, so it costs a full extra copy of
    /// the corpus on top of the outgoing generation — see `partition`'s
    /// `# Memory`.
    ///
    /// This flat entry point still costs the caller's map plus a complete new
    /// generation, because a flat input cannot be partitioned before it is
    /// fully built. Reaching the §6 target peak needs the producer to build and
    /// install one shard at a time via [`Self::swap_shard_sorted`]; this shim exists so
    /// the callers that do not do that keep working unchanged.
    pub fn swap_domain_map(&self, map: HashMap<CompactString, u64, RandomState>) {
        let count = map.len();
        self.store_shard_maps(Self::partition(
            map.into_iter()
                .map(|(d, b)| (d, DomainMasks::block_only(b))),
        ));
        tracing::info!(count, "domain map swapped");
    }

    // `swap_domain_map_with_directions` was DELETED here (mem-t6, 2026-08-16).
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
    // It is deleted rather than kept because of what `mem-t6` made of it. The
    // derived representation ([`SortedShard`]) needs each list bit to have one
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
    /// # Cost — `mem-t6` changed this from O(1) to O(log n)
    ///
    /// A binary search over one shard's ~801 692 entries is ~19.6 probes
    /// against ~23.6 for an unsharded slice, so **sharding now *reduces*
    /// search depth** — under hashing it was a measured latency cost, under
    /// binary search it is a win. Still zero-allocation and zero-lock, which
    /// is what project rules's hot-path rule requires; O(1) was never the rule.
    ///
    /// # The `list_bitmask` short-circuit moved in here (`plp-s3`)
    ///
    /// The caller used to skip the whole Tier 1 layer on
    /// `profile.list_bitmask != 0` (M-17). That field is gone: direction and
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
    /// **S50 T1:** allow-direction (`base = allow`) hits are not reported by
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
    /// Evaluation order, post-S50 T1 (mirrors
    /// `_docs/features/lists_categories_v1.md` §4 truth table verbatim):
    ///   1. `block_all` → BLOCK unless an admin allow matches
    ///   2. `$important` allow rule → FORWARD (short-circuits)
    ///   3. `$important` deny rule → BLOCK
    ///   4. normal allow rule OR `allow_domains` `HashSet` → FORWARD
    ///   5. normal deny rule OR `deny_domains` `HashSet` → BLOCK
    ///   6. **Tier 1 allow-direction list match → FORWARD** (S50 T1, §4 step 5)
    ///   7. **Tier 1 block-direction list match → BLOCK** (§4 step 6)
    ///   8. no match → FORWARD
    ///
    /// **W1.2 invariant (cybersec-reviewable):** the admin layer (steps 2–5)
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
    /// branch-equivalent to the pre-§4.43 standalone `evaluate` body.
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
    /// pre-Sprint-55 second pass via `cname::attribute_block_source` that
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
    /// branch-equivalent to the pre-§4.43 standalone `evaluate` body.
    /// At `ATTR = true`, every `Block` return carries a `Some(source)`;
    /// the only allocation is `rule_pattern_label` on the rule-attributed
    /// Block branch (`Wildcard` / `Regex` patterns format!-allocate; the
    /// `Exact` variant clones the inline `CompactString` and stays on the
    /// stack for domains ≤ 24 bytes).
    ///
    /// One source of truth for the walk + resolution stages. Pre-§4.43
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
        // S50 T1 conservatism: Tier 1 allow-direction lists do NOT pierce
        // `block_all`. The truth table (§4) describes non-`block_all`
        // profiles; `block_all` is a profile-level operator policy that
        // says "deny everything except what I, the admin, explicitly
        // allow." Honouring a sandboxed external (or even local) allow-list
        // here would weaken that policy without an explicit operator
        // signal. Operators that want a curated allow-list to bypass a
        // "night" profile can author an admin `@@||domain^` rule instead.
        //
        // Verdict-equivalent to the pre-§4.43 `evaluate`'s
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
            // Attribution coarsens to AdminBlock here by design (rev-2606
            // engine-02): even when a specific `$important` deny rule was the
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
        // allow, priority 0 deny) are interleaved below in the M-18 walk;
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

        // M-18 + S50 T1: unified subdomain walk. Pre-fix the engine ran three
        // independent suffix scans (allow_domains, deny_domains, list_membership)
        // — same byte slice, three passes, three times the L1 traffic. Now one
        // pass probes every enabled set per dot-position. Set-empty /
        // bitmask-zero short circuits keep the walk completely off the hot path
        // when no probe is needed.
        //
        // S50 T1 split: the Tier 1 hit is now a `DomainMasks { allow_mask,
        // block_mask }`; the walk OR-accumulates each direction separately so
        // the resolution stage can fire the §4 step 5 ALLOW path before the
        // step 6 BLOCK path.
        //
        // Priority semantics preserved byte-identically with the pre-S50
        // `domain_matches_set` chain for the block-only case:
        //   - `allow_domains` hit at any suffix → Forward (priority 1, beats
        //     a tier-0 normal-deny rule that may already have set best_result).
        //   - `deny_domains` hit at any suffix → Block (priority 0, only
        //     consulted when no rule produced a result).
        //   - Tier 1 `allow_mask` hit → Forward (NEW §4 step 5; only fires
        //     when the admin layer produced no result).
        //   - Tier 1 `block_mask` hit → Block (§4 step 6, last).
        let want_allow = best_priority < 1 && !profile.allow_domains.is_empty();
        let want_deny = best_result.is_none() && !profile.deny_domains.is_empty();
        // `plp-s3`: the second half of this test used to be
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
        // PerfMem S2: the Tier 1 probe used to hoist ONE `ArcSwap` guard here
        // for the whole call ("at most one load per call, ATTR-independent").
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
        // per project rules hot-path discipline).
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
        // W1.2 invariant: a populated `best_result` (admin rule, including
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
        // Admin priority-0 deny via deny_domains beats Tier 1 allow (§4 step 5
        // sits below admin || rules in the truth table).
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
        // §4 step 5: allow-direction Tier 1 hit forwards.
        //
        // `plp-s3`: no AND with a profile subscription mask any more. The
        // masks the walk accumulated were already this profile's — projected
        // onto this generation's bits at publish time — so a second AND here
        // would either be a no-op or a second, staler opinion about the same
        // question. That is the defect `_docs/features/profile_list_policy.md`
        // §2.4 exists to remove.
        if allow_bits != 0 {
            return (FilterResult::Forward, None);
        }
        // §4 step 6: block-direction Tier 1 hit blocks.
        let effective = block_bits;
        if effective != 0 {
            let source = if ATTR {
                Some(BlockSource::List(effective.trailing_zeros() as u8))
            } else {
                None
            };
            return (FilterResult::Block, source);
        }

        // §4 step 7: no match → forward
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
    /// Before `plp-s3` a fixture said "this profile subscribes to bits N" by
    /// setting `ResolvedProfile.list_bitmask`, and the hot path AND-ed it
    /// against the entry's direction masks. Both halves of that pair now live
    /// beside the corpus (§2.4 D-ARCH-1), so a fixture has to say the same
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
    /// config never produced. A production caller would be re-introducing the
    /// write-path bug §2.4 names — policy and corpus from two different
    /// configs. There is none, and there must not be one; the production
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
    /// Cold path: `_docs/features/profile_list_policy.md` §2.4 test 4 (does
    /// every write path actually reach the publish function?) and status
    /// reporting. Never consulted per query.
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
/// `BlockSource::Rule(label)` in one pass. Moved here from `cname.rs` in
/// Sprint 55 alongside the `evaluate_attributed` consolidation — the
/// previous home was the heuristic second-pass `attribute_block_source`
/// (now removed).
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
/// Sprint 43 T4 promoted to `pub(crate)` so the per-device overlay layer
/// (`crate::profiles::resolver::overlay_decision_for`) can run the same
/// subdomain-walk semantics against `DeviceOverlay.allow` /
/// `DeviceOverlay.deny` without duplicating the byte-scan loop. R5
/// guarantee preserved: zero-allocation, two probes per query against
/// the overlay sets.
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
mod tests {
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
        let content =
            "# This is a comment\n\ntracker.example.com\n  \n# Another comment\nads.com\n";
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
        std::sync::Arc::make_mut(&mut profile.allow_domains)
            .insert(CompactString::new("example.com"));

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
        std::sync::Arc::make_mut(&mut profile.deny_domains)
            .insert(CompactString::new("tiktok.com"));

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
        std::sync::Arc::make_mut(&mut profile.allow_domains)
            .insert(CompactString::new("example.com"));
        std::sync::Arc::make_mut(&mut profile.deny_domains)
            .insert(CompactString::new("example.com"));

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
        std::sync::Arc::make_mut(&mut profile.deny_domains)
            .insert(CompactString::new("blocked.test"));
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
        std::sync::Arc::make_mut(&mut deny.deny_domains)
            .insert(CompactString::new("ads.example.com"));
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

    fn masks_map(
        entries: &[(&str, DomainMasks)],
    ) -> HashMap<CompactString, DomainMasks, RandomState> {
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
            let new_shards: HashSet<usize, RandomState> =
                order[..swapped].iter().copied().collect();

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
            SortedShard::from_sorted_entries(vec![(domain.clone(), 0b01)], Arc::clone(&gen1))
                .unwrap(),
        );
        // Pin it, exactly as an in-flight query's guard would.
        let pinned = engine.shards[idx].0.load_full();

        // Generation 2 — the operator flipped that same list to ALLOW. Same
        // entries, byte for byte; only the direction map differs.
        let gen2 = ListPolicy::publish_uniform(0b01);
        engine.swap_shard_sorted(
            idx,
            SortedShard::from_sorted_entries(vec![(domain.clone(), 0b01)], Arc::clone(&gen2))
                .unwrap(),
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
        let as_allow = SortedShard::from_sorted_entries(
            vec![(domain, BITS)],
            ListPolicy::publish_uniform(BITS),
        )
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
}
