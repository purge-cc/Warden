//! CNAME chain inspection — §4.5 Sprint 1/2 foundation.
//!
//! [`walk_response`] follows the CNAME chain returned by upstream and
//! decides whether any hop in the chain matches the active profile's
//! filter (admin allow/deny, advanced rules, Tier 1 list bitmask). The
//! function is profile-aware and stack-only for loop detection up to a
//! 16-hop cap. Each hop materialises its target into a `CompactString`:
//! inline (no heap) for targets ≤24 bytes, but heap-allocating for longer
//! names — long CDN-flatten chains routinely exceed 24 bytes (rev-2606
//! cname-02) — so the happy path is allocation-light, not allocation-free.
//!
//! Sprint 1/2 ships the pure function + tests in isolation. Sprint 2/2
//! wires it into [`crate::dns::handler`] post-upstream-response, adds
//! the audit log `cname_block` event, the TUI Query Log badge, and a
//! CT smoke test against a live CNAME-cloaked tracker.

use std::fmt::Write as _;

use compact_str::CompactString;
use hickory_proto::rr::{Name, RData, Record, RecordType};

use super::engine::{domain_matches_set, FilterEngine, FilterResult};
use crate::profiles::profile::{DeviceOverlay, ResolvedProfile};

/// Why a CNAME hop in the chain caused a block.
///
/// The dynamic variants ([`BlockSource::List`], [`BlockSource::Rule`])
/// carry just enough payload to populate the §4.5 Sprint 2 audit log
/// and TUI badge without a second filter probe at log time. The
/// built-in variants ([`BlockSource::CnameLoop`],
/// [`BlockSource::CnameDepthExceeded`]) are emitted by the walker
/// itself when the chain shape is the threat — neither hop sits in any
/// blocklist, but the chain is malformed (cycle) or unbounded
/// (depth cap exceeded).
///
/// Attribution is **authoritative** as of Sprint 55: the engine emits
/// the `BlockSource` in the same pass that decides the verdict, via
/// [`FilterEngine::evaluate_attributed`]. The walker passes the source
/// through unchanged. The pre-Sprint-55 heuristic that re-walked the
/// domain in a second pass (`attribute_block_source`, with a "defensive
/// AdminBlock" fallback when no layer claimed responsibility) is gone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockSource {
    /// Tier 1 blocklist (per-list bitmask) hit. The `u8` is the bit
    /// index of the list in the generation's bit assignment
    /// (`lists::source_key::SourceBitMap`).
    ///
    /// When a domain appears in more than one block-direction list, the
    /// engine reports **only the lowest set bit** of the matching mask
    /// (selected via `effective.trailing_zeros() as u8` inside
    /// [`super::engine::FilterEngine::evaluate_attributed`]). Other
    /// matching lists are dropped from attribution by design — the
    /// payload mirrors the Dashboard v2 `block_list_bit: Option<u8>`
    /// field shape, which carries a single bit. Future multi-list
    /// tracking would require a new variant that carries the full
    /// mask, NOT a wider payload on this variant.
    List(u8),
    /// Admin advanced rule (`||domain^`, `||*.suffix^`, `/regex/`,
    /// optionally `$important`) matched and chose to block. The string
    /// carries the rule pattern label (e.g. `"tracker.com"`,
    /// `"*.evil.com"`, `"/ad[0-9]+/"`).
    Rule(CompactString),
    /// Admin profile-level deny: either `block_all` engaged with no
    /// allow override, or a `||domain^`-form rule that landed in
    /// `deny_domains`.
    AdminBlock,
    /// CNAME chain contains a cycle (a target already visited in the
    /// same chain).
    CnameLoop,
    /// CNAME chain exceeded `max_depth` (typically
    /// `cache.cname_max_depth`, default 16).
    CnameDepthExceeded,
}

impl BlockSource {
    /// Stable string label for audit logs and TUI badges.
    ///
    /// Only the static label is returned (no payload). Pinned in
    /// `tests/frozen_strings_s45_p1.rs` so a future variant rename
    /// cannot silently rewrite a downstream log schema.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            BlockSource::List(_) => "list",
            BlockSource::Rule(_) => "rule",
            BlockSource::AdminBlock => "admin_block",
            BlockSource::CnameLoop => "cname_loop",
            BlockSource::CnameDepthExceeded => "cname_depth_exceeded",
        }
    }

    /// Operator-facing attribution string for the on-demand query path
    /// (`warden query`, `GET /api/query`). Built on top of the
    /// schema-frozen [`BlockSource::label`]: the two payload-carrying
    /// variants append their detail (`list:<name>`, `rule:<pattern>`),
    /// the payload-less variants return the bare label (`admin_block`,
    /// `cname_loop`, `cname_depth_exceeded`). `labels` maps a Tier-1
    /// list bit to its catalog id; an unknown bit falls back to the
    /// bare index (`list:<bit>`). Off the hot path — allocates a
    /// `String`.
    #[must_use]
    pub fn describe(&self, labels: &[Option<String>]) -> String {
        match self {
            BlockSource::List(bit) => {
                let name = labels
                    .get(*bit as usize)
                    .and_then(|slot| slot.clone())
                    .unwrap_or_else(|| bit.to_string());
                format!("{}:{name}", self.label())
            }
            BlockSource::Rule(pattern) => format!("{}:{pattern}", self.label()),
            BlockSource::AdminBlock | BlockSource::CnameLoop | BlockSource::CnameDepthExceeded => {
                self.label().to_string()
            }
        }
    }
}

/// Outcome of a CNAME chain walk against a resolved profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Every CNAME hop forwarded; the upstream answer is safe to
    /// return to the client unchanged.
    Allow,
    /// One CNAME hop caused a block. `offending` is the case-normalised
    /// target name that triggered it (or, for
    /// [`BlockSource::CnameDepthExceeded`], the name of the hop that
    /// could not be followed). `source` records why.
    Block {
        offending: CompactString,
        source: BlockSource,
    },
}

/// The operator's allow verdict for the **queried name**, resolved once
/// before the query is forwarded and consumed by every site that
/// inspects the answer.
///
/// # Why this is not a `bool`
///
/// F5 (incident 2026-07-27): four sites decide "is this allowed?" and
/// each sees less of the operator's policy than the one before it —
/// site 1 ([`crate::dns::handler`]'s `evaluate_with_overlay`) sees both
/// the profile's and the device's allow sets, the CNAME walker used to
/// see only the profile's, the response-IP filter neither. Handing the
/// response path a two-state "explicitly allowed / not" verdict closes
/// the reported incident but opens a worse one: it erases *which layer*
/// granted the allow, and the layers are not interchangeable.
///
/// `profiles::resolver::apply_overlay` row 6 refuses to let a
/// device-scoped allow beat a profile-scoped deny unless the device
/// carries `override_profile_deny`. A boolean verdict reintroduces
/// exactly that beaten path one hop later:
///
/// > `profile.deny_domains = {cdn.evil.example}`, device allow on
/// > `app.example`, `override_profile_deny = false`. Upstream answers
/// > `app.example CNAME cdn.evil.example`. Site 1 never sees a profile
/// > deny on `app.example`, so it forwards. A boolean verdict would then
/// > tell the walker "allowed" and the *device* allow would sink a
/// > *profile* deny — the weaker layer overruling the stronger.
///
/// So the verdict carries its provenance, and the consumption rule
/// ([`NamePolicy::outranks`]) is `policy × BlockSource → bool`.
///
/// # Derived from allow hits, never from "was not blocked"
///
/// [`NamePolicy::resolve`] probes the allow sets and nothing else. Site
/// 1 forwards whenever a name is *not blocked*, which is the state the
/// overwhelming majority of traffic is in and which must stay fully
/// filterable on the response path. Deriving the verdict from site 1's
/// `(false, None)` "not blocked" output — rather than from an actual
/// allow-set hit — would turn every forwarded query into a
/// filter-bypass. That is the one fatal mistake this type exists to
/// prevent; the default is [`NamePolicy::Neutral`] so drift degrades
/// toward filtering, never toward passing everything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NamePolicy {
    /// No operator allow matched the queried name. The response path
    /// filters in full. Default: a future field/variant added without
    /// updating a construction site fails closed.
    #[default]
    Neutral,
    /// A profile-scoped `@@||domain^` matched the queried name —
    /// `ResolvedProfile::allow_domains`, built solely from the
    /// operator's own `[[admin_rules]]`. The strongest allow the
    /// response path recognises.
    ProfileAllow,
    /// A device-scoped `@@||domain^` matched the queried name —
    /// `DeviceOverlay::allow`, i.e. a rule referenced from
    /// `[[devices]].allow_rules`. Carries the device's D3
    /// `override_profile_deny` flag because that flag is what decides
    /// whether this allow may beat a profile-level deny.
    DeviceAllow { override_profile_deny: bool },
}

impl NamePolicy {
    /// Resolve the operator's allow verdict for `name`.
    ///
    /// `name` is the name the *client* asked for, after any §4.12 /
    /// §4.53 rewrite — it must be the same string the response-path
    /// consumers will filter against, lowercase and without the
    /// trailing dot (the invariant [`domain_matches_set`]
    /// `debug_assert!`s).
    ///
    /// # `name` comes from the caller, never from the response
    ///
    /// This is where the anti-spoof property lives now that
    /// [`walk_response`] no longer takes a queried name of its own.
    /// The walker's `visited[0]` holds the first CNAME record's owner,
    /// which is upstream-supplied and therefore attacker-influenced: a
    /// hostile or compromised resolver could lead its answer with a
    /// record owned by an allow-listed name and launder an arbitrary
    /// chain past the filter. `visited[0]` exists for cycle detection
    /// only. Pinned by `walk_response_ignores_spoofed_first_record_owner`.
    ///
    /// # Scope
    ///
    /// Only the two exact-match allow sets participate. Rule-level
    /// allows (wildcard, `$important`, regex) are not in either set;
    /// they manifest as `FilterEngine::evaluate() == Forward` and
    /// continue the walk organically, unchanged from before. Design
    /// rule 4: both sets are built exclusively from parsed
    /// `[[admin_rules]]`, so an external blocklist can never grant an
    /// allow through this path.
    ///
    /// `ProfileAllow` wins when both layers hit — it is never weaker
    /// than `DeviceAllow` on any input.
    #[must_use]
    pub fn resolve(name: &str, profile: &ResolvedProfile, overlay: Option<&DeviceOverlay>) -> Self {
        if domain_matches_set(name, &profile.allow_domains) {
            return NamePolicy::ProfileAllow;
        }
        if let Some(ov) = overlay {
            if domain_matches_set(name, &ov.allow) {
                return NamePolicy::DeviceAllow {
                    override_profile_deny: ov.override_profile_deny,
                };
            }
        }
        NamePolicy::Neutral
    }

    /// Does the operator's allow on the queried name outrank a block
    /// attributed to `source` somewhere in the answer?
    ///
    /// | policy | `List` | `Rule` / `AdminBlock` | `CnameLoop` / `CnameDepthExceeded` |
    /// |---|---|---|---|
    /// | `Neutral` | no | no | no |
    /// | `ProfileAllow` | yes | yes | **no** |
    /// | `DeviceAllow { override_profile_deny: false }` | yes | **no** | **no** |
    /// | `DeviceAllow { override_profile_deny: true }` | yes | yes | **no** |
    ///
    /// - **`List`** is an external blocklist hit — the incident's actual
    ///   shape (`fts.rbxcdn.com` flattening onto a CDN target that sits
    ///   on a subscribed list). Design rule 4 forbids external lists
    ///   from granting an allow; nothing forbids an operator allow from
    ///   beating one. Both allow layers win.
    /// - **`Rule` / `AdminBlock`** is the operator's own profile-level
    ///   deny. `ProfileAllow` is same-layer, so it wins (the semantics
    ///   frozen by the Lane A fix). `DeviceAllow` is the weaker layer
    ///   and loses unless the device carries `override_profile_deny` —
    ///   the same answer `apply_overlay` rows 6/7 give for the queried
    ///   name, so the two cannot disagree.
    /// - **`CnameLoop` / `CnameDepthExceeded`** are defences against a
    ///   malformed answer, not policy. No allow switches them off. In
    ///   [`walk_response`] they are already unreachable here (both
    ///   `return` earlier in the loop body); saying so in the type too
    ///   means a future consumer that reaches for this method from a
    ///   different site inherits the guarantee instead of having to
    ///   remember it.
    #[must_use]
    pub fn outranks(self, source: &BlockSource) -> bool {
        match source {
            // Malformation guards: never. Matched first so no allow arm
            // below can reach them.
            BlockSource::CnameLoop | BlockSource::CnameDepthExceeded => false,
            // External blocklist: any explicit allow on the queried name.
            BlockSource::List(_) => !matches!(self, NamePolicy::Neutral),
            // The operator's own profile-level deny.
            BlockSource::Rule(_) | BlockSource::AdminBlock => match self {
                NamePolicy::Neutral => false,
                NamePolicy::ProfileAllow => true,
                NamePolicy::DeviceAllow {
                    override_profile_deny,
                } => override_profile_deny,
            },
        }
    }

    /// Does the operator's allow outrank an external-blocklist-grade
    /// block that carries no attribution at all?
    ///
    /// The response-IP blocklist ([`super::ip_filter::IpFilter`]) is a
    /// flat `HashSet<IpAddr>` loaded from a list file — there is no
    /// per-entry provenance to compare layers against, and no operator
    /// rule involved. It ranks with [`BlockSource::List`]: any explicit
    /// allow on the queried name beats it, including a `DeviceAllow`
    /// whose `override_profile_deny` is `false`, because there is no
    /// profile deny in play for that flag to guard.
    #[must_use]
    pub fn outranks_external(self) -> bool {
        !matches!(self, NamePolicy::Neutral)
    }
}

/// Hard ceiling on the number of CNAME hops a chain walker will follow.
///
/// Callers may pass a smaller `max_depth`; every walker clamps to this
/// so the stack array stays bounded regardless of operator config
/// drift. RFC 1034 §5.2.2 recommends a much smaller chain limit
/// (typically 8); 16 is the project default in `cache.cname_max_depth`.
///
/// Crate-visible because the prefetch-path walker
/// ([`crate::dns::handler::cname_chain_blocked`]) must clamp to the
/// same number: the two paths disagreeing on the bound means the
/// prefetch path caches entries the serve path then refuses.
pub(crate) const MAX_HOPS: usize = 16;

/// Slots in the visited stack: one for the starting alias (the
/// queried name, recorded at the first CNAME record's `record.name()`)
/// plus one per hop target. The +1 is what lets cycle detection catch
/// `A → B → A` — without recording the starting alias, "A" never
/// appears in visited, so the second hop's target=A is treated as a
/// fresh name.
const VISITED_CAPACITY: usize = MAX_HOPS + 1;

/// The head of a CNAME chain: the index of the CNAME record whose owner is not
/// the target of any *other* CNAME in the answer.
///
/// **M3** A DNS answer's answer-section is a *set*; nothing in RFC 1034 §3.6.2
/// obliges a server to emit a CNAME chain in traversal order, and resolvers do
/// reorder. Picking the head explicitly is what lets [`walk_response`] thread
/// `a → b → c` out of the wire order `[b → c, a → b]`.
///
/// Returns `None` when there is no CNAME at all (the overwhelmingly common
/// case — a plain A/AAAA answer) **or** when every owner is also some record's
/// target, which means the records form a cycle with no entry point. The caller
/// distinguishes those two.
///
/// O(n²) in the number of CNAME records, which the depth cap bounds at
/// [`MAX_HOPS`]; zero allocation — [`Name`] comparison is case-insensitive by
/// contract, so no lowercased copy is materialised.
fn chain_head(records: &[Record]) -> Option<usize> {
    records.iter().position(|rec| {
        // Type AND rdata, via `is_cname_link`. Deliberately belt-and-braces:
        // in hickory 0.26 `Record::record_type()` is `self.data.record_type()`
        // (`rr/record.rs:600`), so the two cannot disagree and no such record
        // is constructible today. It is checked anyway because the *walk* now
        // enters at a single chosen record instead of iterating all of them —
        // if that invariant ever changed, a type-only match could select a
        // record with no followable target, and the walk would return `Allow`
        // while a real chain sat unexamined in the same answer. The pre-[M3]
        // loop `continue`d past such records; this preserves that, and no test
        // pins it because the case cannot be constructed to fail.
        if !is_cname_link(rec) {
            return false;
        }
        !records.iter().any(|other| {
            // `eq_ignore_root` rather than `==`: case-insensitive like `==`,
            // but also tolerant of a relative-vs-FQDN mismatch, so a chain is
            // never silently left unwalked over a trailing dot.
            matches!(&other.data, RData::CNAME(t) if rec.name.eq_ignore_root(t))
        })
    })
}

/// A record that is a usable CNAME link: CNAME by type **and** by rdata.
fn is_cname_link(rec: &Record) -> bool {
    rec.record_type() == RecordType::CNAME && matches!(rec.data, RData::CNAME(_))
}

/// Walk a CNAME chain in `records` against `profile` and return
/// whether the chain is safe to return to the client.
///
/// The walker:
/// 1. Finds the chain head via [`chain_head`], then follows each hop by
///    matching the **owner** of the next CNAME record against the current
///    hop's target — *not* by taking records in wire order. Non-CNAME records
///    and CNAMEs that are not links in this chain pass through unchanged.
/// 2. For each hop: case-normalises the target, strips trailing dot,
///    checks for a cycle against the visited set, checks depth, then
///    short-circuits on an admin `allow_domains` hit, and finally
///    calls [`FilterEngine::evaluate_attributed`] for the verdict
///    paired with its `BlockSource`.
/// 3. On the first block, asks the pre-resolved [`NamePolicy`] whether
///    the operator's allow on the *queried* name outranks that
///    particular `BlockSource` and returns [`Verdict::Allow`] if so;
///    otherwise returns [`Verdict::Block`] with the offending name and
///    the source emitted by `evaluate_attributed` — single pass,
///    authoritative attribution (no heuristic second walk).
///
/// # `policy` — consumed, never derived here
///
/// The walker does **not** compute the queried name's allow verdict.
/// It receives one that [`NamePolicy::resolve`] built at the single
/// point where the whole of the operator's policy is in scope: the
/// profile's allow set *and* the resolved device's overlay, keyed on
/// the name the client asked for after any rewrite. F5 (incident
/// 2026-07-27) is what happens when each response-path site re-derives
/// this from whatever data it happens to hold — the walker only ever
/// had the profile's set, so an allow the operator had attached to a
/// device could not take effect here.
///
/// The consumption rule and the reason it is layer-aware rather than
/// boolean live on [`NamePolicy::outranks`]; the anti-spoof reason the
/// key must come from the caller and never from `visited[0]` lives on
/// [`NamePolicy::resolve`].
///
/// The separate short-circuit on a CNAME *target* (below) remains
/// scoped to `profile.allow_domains` and is unchanged: a device-scoped
/// allow grants passage for the name the operator named, not for
/// arbitrary intermediate hops it happens to flatten onto.
///
/// `max_depth` is clamped to [`MAX_HOPS`] (16) so the loop
/// detector's stack array cannot overflow regardless of operator
/// config.
#[must_use]
pub fn walk_response(
    records: &[Record],
    engine: &FilterEngine,
    profile: &ResolvedProfile,
    policy: NamePolicy,
    max_depth: usize,
) -> Verdict {
    let cap = max_depth.min(MAX_HOPS);
    let mut visited: [Option<CompactString>; VISITED_CAPACITY] = std::array::from_fn(|_| None);
    // `slots_used` counts every name in `visited`: starting alias
    // (slot 0, populated on the first CNAME record we see) + targets
    // (slots 1..). `hops` counts only CNAME records actually walked,
    // which is what `cap` (= `max_depth` clamped to MAX_HOPS) bounds.
    let mut slots_used = 0usize;
    let mut hops = 0usize;

    // [M3] Enter the chain at its head, not at whichever CNAME the server
    // happened to serialise first. `chain_head` returns `None` both for "no
    // CNAMEs" (return Allow — nothing to walk) and for "every owner is also a
    // target", which is a closed cycle; for the cycle we deliberately fall back
    // to the first CNAME so the walk still runs and reports `CnameLoop` through
    // the normal visited-set check below, rather than short-circuiting to Allow.
    let Some(start) = chain_head(records).or_else(|| records.iter().position(is_cname_link)) else {
        return Verdict::Allow;
    };

    let mut next_record = Some(&records[start]);

    while let Some(record) = next_record {
        let RData::CNAME(ref cname) = record.data else {
            break;
        };

        let mut target = CompactString::default();
        let _ = write!(target, "{}", &**cname);
        if target.ends_with('.') {
            target.pop();
        }
        target.make_ascii_lowercase();

        // Depth check fires when about to walk hop #(cap+1).
        if hops >= cap {
            return Verdict::Block {
                offending: target,
                source: BlockSource::CnameDepthExceeded,
            };
        }

        // On the head record, record the alias (the chain's starting name)
        // at slot 0 so cycle detection can catch `A → B → A` — without
        // this, the starting "A" never appears in visited.
        if slots_used == 0 {
            let mut alias = CompactString::default();
            let _ = write!(alias, "{}", record.name);
            if alias.ends_with('.') {
                alias.pop();
            }
            alias.make_ascii_lowercase();
            visited[0] = Some(alias);
            slots_used = 1;
        }

        // Loop detection: same target seen earlier in this chain
        // (`A → B → A`, or any cycle) is a malformed answer. O(slots)
        // scan, slots ≤ 17.
        for seen in visited.iter().take(slots_used).flatten() {
            if seen.as_str() == target.as_str() {
                return Verdict::Block {
                    offending: target,
                    source: BlockSource::CnameLoop,
                };
            }
        }

        // Admin allow short-circuit: operator-explicit `@@||domain^`
        // (HashSet fast path). Even if the remainder of the chain
        // would block, admin trust wins. Rule-level allows
        // (priority 1, `$important`) manifest as
        // `engine.evaluate() == Forward` and continue the walk
        // organically.
        if domain_matches_set(&target, &profile.allow_domains) {
            return Verdict::Allow;
        }

        let (verdict, source) = engine.evaluate_attributed(&target, profile);
        match verdict {
            FilterResult::Forward => {}
            FilterResult::Block => {
                // F1 / F5 (incident 2026-07-27): the operator's own
                // `@@||domain^` on the *queried* name wins the chain when
                // it outranks the block's attribution. Before this check
                // the walker only ever tested the CNAME *target* against
                // `allow_domains`, so an operator who whitelisted the name
                // they actually query (`fts.rbxcdn.com`) could never take
                // effect — the only name consulted was a CDN target they
                // never see.
                //
                // Two properties this placement buys, both load-bearing:
                //
                // 1. Sitting in the `Block` arm means the two
                //    anti-malformation guards — `CnameLoop` and
                //    `CnameDepthExceeded` — are unreachable from here:
                //    both `return` earlier in the loop body. They are
                //    defences against a malformed answer, not policy, so
                //    an operator allow must not switch them off. The
                //    control flow enforces that, and `outranks` refuses
                //    them a second time so a future caller reaching this
                //    rule from elsewhere inherits the guarantee.
                // 2. Resolving the source BEFORE consulting the policy is
                //    what keeps the layers ordered: a device-scoped allow
                //    beats an external list but not the operator's own
                //    profile-level deny (unless the device carries
                //    `override_profile_deny`). See `NamePolicy::outranks`.
                //
                // Cost is on the block path only; a forwarded chain never
                // reaches this arm, so the hot path is unchanged.
                //
                // `evaluate_attributed` always emits a source on `Block` —
                // pinned by `evaluate_and_evaluate_attributed_agree_on_verdict`
                // proptest plus the four `evaluate_attributed_returns_*` unit
                // tests — so this `unwrap_or_else` is unreachable today. The
                // `debug_assert!` keeps Sprint 55's drift-surfacing intent (a
                // future kernel edit that drops a source trips every test /
                // proptest run); release builds fail closed — block as
                // AdminBlock — rather than abort the query's task with a panic
                // on a network-driven path (rev-2606 cname-01). This is NOT the
                // pre-Sprint-55 "defensive AdminBlock" heuristic that masked
                // drift silently: drift still fails the suite. `AdminBlock` is
                // also the least permissive input to the policy comparison
                // below, so failing closed here fails closed there too.
                let source = source.unwrap_or_else(|| {
                    debug_assert!(false, "evaluate_attributed must emit a source on Block");
                    BlockSource::AdminBlock
                });
                if policy.outranks(&source) {
                    return Verdict::Allow;
                }
                return Verdict::Block {
                    offending: target,
                    source,
                };
            }
        }

        visited[slots_used] = Some(target);
        slots_used += 1;
        hops += 1;

        // [M3] The next hop is the CNAME whose OWNER is this hop's target.
        // Wire position is irrelevant — that assumption is the whole defect
        // this replaces. `None` ends the chain (the target resolved to an
        // address, or the answer is truncated), which is `Allow`.
        //
        // The `visited` borrow lives only for the `find`; `next_record`
        // borrows `records`, so the next iteration is free to write `visited`.
        let current = visited[slots_used - 1]
            .as_deref()
            .expect("the slot written immediately above is populated");
        next_record = records
            .iter()
            .find(|r| is_cname_link(r) && owner_matches(&r.name, current));
    }

    Verdict::Allow
}

/// Case-insensitive comparison of a record owner against an already-normalised
/// domain (lowercase, no trailing dot) — **without allocating**.
///
/// [`walk_response`] runs on every cache hit, so materialising a `String` per
/// record per hop to compare owners would put an allocation on the hot path for
/// the sake of a comparison. Walking a [`Name`]'s label slices against the
/// string's dot-separated segments costs nothing.
fn owner_matches(name: &Name, domain: &str) -> bool {
    let mut rest = domain;
    for label in name.iter() {
        let (head, tail) = rest.split_once('.').unwrap_or((rest, ""));
        if head.len() != label.len() || !head.as_bytes().eq_ignore_ascii_case(label) {
            return false;
        }
        rest = tail;
    }
    // Every label consumed exactly one segment, and nothing is left over —
    // otherwise `a.b` would match the owner `a`.
    rest.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::Id;
    use crate::filter::rules::parse_rules;
    use ahash::RandomState;
    use hickory_proto::rr::rdata::{A, CNAME};
    use hickory_proto::rr::Name;
    use std::collections::HashSet;
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use std::sync::Arc;

    // ── §4.2 G1a: BlockSource::describe (on-demand query attribution) ──

    #[test]
    fn describe_list_resolves_label_name() {
        let labels = vec![Some("privacy/ads".to_string()), None];
        assert_eq!(BlockSource::List(0).describe(&labels), "list:privacy/ads");
    }

    #[test]
    fn describe_list_unknown_bit_falls_back_to_index() {
        let labels: Vec<Option<String>> = vec![None; 64];
        assert_eq!(BlockSource::List(7).describe(&labels), "list:7");
    }

    #[test]
    fn describe_rule_carries_pattern() {
        let src = BlockSource::Rule(CompactString::new("*.evil.com"));
        assert_eq!(src.describe(&[]), "rule:*.evil.com");
    }

    #[test]
    fn describe_payloadless_variants_use_bare_label() {
        assert_eq!(BlockSource::AdminBlock.describe(&[]), "admin_block");
        assert_eq!(BlockSource::CnameLoop.describe(&[]), "cname_loop");
        assert_eq!(
            BlockSource::CnameDepthExceeded.describe(&[]),
            "cname_depth_exceeded"
        );
    }

    fn cname_record(alias: &str, target: &str) -> Record {
        Record::from_rdata(
            Name::from_str(alias).unwrap(),
            300,
            RData::CNAME(CNAME(Name::from_str(target).unwrap())),
        )
    }

    fn a_record(domain: &str) -> Record {
        Record::from_rdata(
            Name::from_str(domain).unwrap(),
            300,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        )
    }

    fn engine_blocking(domains: &[&str]) -> FilterEngine {
        let engine = FilterEngine::new();
        let set: HashSet<CompactString, RandomState> = domains
            .iter()
            .map(|d| {
                let mut cs = CompactString::new(*d);
                cs.make_ascii_lowercase();
                cs
            })
            .collect();
        engine.swap_blocklist(set);
        engine
    }

    /// A profile that filters on list bit 0, subscribed on `engine`.
    ///
    /// `plp-s3`: the subscription lives beside the corpus now, so the
    /// fixture has to tell the engine — and `permissive_default()` is
    /// `unfiltered`, which skips the list layer outright, so that has to be
    /// cleared too. Both were one `list_bitmask = 1` before.
    /// [`ResolvedProfile::permissive_default`] with the `unfiltered` opt-out
    /// cleared, and no subscription anywhere.
    ///
    /// For the `NamePolicy::resolve` fixtures, which never touch a
    /// [`FilterEngine`] — the `list_bitmask = 1` they used to set was inert
    /// for them even before `plp-s3`.
    fn permissive_filtered() -> ResolvedProfile {
        let mut p = ResolvedProfile::permissive_default();
        p.unfiltered = false;
        p
    }

    fn permissive_with_bit0(engine: &FilterEngine) -> ResolvedProfile {
        let mut p = ResolvedProfile::permissive_default();
        p.unfiltered = false;
        engine.fixture_subscribe(&p.name, 1);
        p
    }

    #[test]
    fn walk_response_allows_clean_chain() {
        let records = [
            cname_record("a.example.com", "b.example.com"),
            cname_record("b.example.com", "c.example.com"),
        ];
        let engine = FilterEngine::new();
        let profile = ResolvedProfile::permissive_default();
        assert_eq!(
            walk_response(&records, &engine, &profile, NamePolicy::Neutral, 16),
            Verdict::Allow
        );
    }

    /// M3 The defect this fix exists for.
    ///
    /// Wire order `[b→c, a→b]` is a legitimate serialisation of the chain
    /// `a → b → c`; nothing obliges a server to emit CNAMEs in traversal
    /// order. The old walker seeded `visited[0]` from the *first record's*
    /// owner — `b` — then reached hop 2 whose target is also `b`, and reported
    /// `CnameLoop`. A clean chain came back BLOCKED.
    ///
    /// The in-order arm below is the control: identical records, identical
    /// expectation, only the wire order differs. If the two ever disagree
    /// again, ordering has crept back into the walk.
    #[test]
    fn walk_response_tolerates_out_of_order_cname_records() {
        let engine = FilterEngine::new();
        let profile = ResolvedProfile::permissive_default();

        let in_order = [
            cname_record("a.example.com", "b.example.com"),
            cname_record("b.example.com", "c.example.com"),
        ];
        let reversed = [
            cname_record("b.example.com", "c.example.com"),
            cname_record("a.example.com", "b.example.com"),
        ];

        assert_eq!(
            walk_response(&in_order, &engine, &profile, NamePolicy::Neutral, 16),
            Verdict::Allow,
            "control arm: the in-order chain must be clean"
        );
        assert_eq!(
            walk_response(&reversed, &engine, &profile, NamePolicy::Neutral, 16),
            Verdict::Allow,
            "same chain, reversed on the wire — a false CnameLoop here is the M3 defect"
        );
    }

    /// M3 Out-of-order records must still reach a block at the tail, so the
    /// fix cannot be mistaken for "stop walking on reorder".
    ///
    /// Wire order is `[b→evil, a→b]`; the walker must enter at `a`, thread to
    /// `b`, then to `evil.com`, and block there.
    #[test]
    fn walk_response_out_of_order_still_blocks_at_tail() {
        let records = [
            cname_record("b.example.com", "evil.com"),
            cname_record("a.example.com", "b.example.com"),
        ];
        let engine = engine_blocking(&["evil.com"]);
        let profile = permissive_with_bit0(&engine);
        assert_eq!(
            walk_response(&records, &engine, &profile, NamePolicy::Neutral, 16),
            Verdict::Block {
                offending: CompactString::new("evil.com"),
                source: BlockSource::List(0),
            },
            "reordering the wire must not let a blocked tail escape the walk"
        );
    }

    /// M3 A genuine cycle must still be caught after the rewrite — the
    /// head-detection fallback exists precisely so a closed cycle (where every
    /// owner is also a target, so there is no head) still enters the walk and
    /// trips the visited-set check instead of short-circuiting to `Allow`.
    #[test]
    fn walk_response_still_detects_a_closed_cycle_with_no_head() {
        let records = [
            cname_record("a.example.com", "b.example.com"),
            cname_record("b.example.com", "a.example.com"),
        ];
        let engine = FilterEngine::new();
        let profile = ResolvedProfile::permissive_default();
        match walk_response(&records, &engine, &profile, NamePolicy::Neutral, 16) {
            Verdict::Block { source, .. } => {
                assert!(
                    matches!(source, BlockSource::CnameLoop),
                    "a closed cycle must still be CnameLoop, got {source:?}"
                );
            }
            other => panic!("expected Block (loop) on a closed cycle, got {other:?}"),
        }
    }

    /// M3 `owner_matches` is the zero-alloc comparison the threading rests
    /// on. It must be case-insensitive (DNS-0x20 randomises owner case) and
    /// must not accept a prefix — `a` is not `a.b`.
    #[test]
    fn owner_matches_is_case_insensitive_and_not_a_prefix_match() {
        let owner = Name::from_str("A.ExAmPle.CoM.").unwrap();
        assert!(
            owner_matches(&owner, "a.example.com"),
            "DNS-0x20 case must not defeat the match"
        );
        assert!(
            !owner_matches(&owner, "a.example"),
            "a suffix-short domain must not match"
        );
        assert!(
            !owner_matches(&owner, "a.example.com.uk"),
            "a longer domain must not match"
        );
        assert!(
            !owner_matches(&owner, "b.example.com"),
            "a different label must not match"
        );
        assert!(
            !owner_matches(&owner, ""),
            "the empty domain must not match a 3-label owner"
        );
    }

    #[test]
    fn walk_response_blocks_at_tail() {
        let records = [
            cname_record("a.example.com", "b.example.com"),
            cname_record("b.example.com", "evil.com"),
        ];
        let engine = engine_blocking(&["evil.com"]);
        let profile = permissive_with_bit0(&engine);
        let v = walk_response(&records, &engine, &profile, NamePolicy::Neutral, 16);
        assert_eq!(
            v,
            Verdict::Block {
                offending: CompactString::new("evil.com"),
                source: BlockSource::List(0),
            }
        );
    }

    #[test]
    fn walk_response_blocks_at_mid() {
        let records = [
            cname_record("a.example.com", "evil.com"),
            cname_record("evil.com", "c.example.com"),
        ];
        let engine = engine_blocking(&["evil.com"]);
        let profile = permissive_with_bit0(&engine);
        let v = walk_response(&records, &engine, &profile, NamePolicy::Neutral, 16);
        match v {
            Verdict::Block { offending, source } => {
                assert_eq!(offending.as_str(), "evil.com");
                assert!(matches!(source, BlockSource::List(0)));
            }
            other => panic!("expected Block at mid, got {other:?}"),
        }
    }

    #[test]
    fn walk_response_blocks_loop() {
        let records = [
            cname_record("a.example.com", "b.example.com"),
            cname_record("b.example.com", "a.example.com"),
        ];
        let engine = FilterEngine::new();
        let profile = ResolvedProfile::permissive_default();
        let v = walk_response(&records, &engine, &profile, NamePolicy::Neutral, 16);
        match v {
            Verdict::Block { offending, source } => {
                assert_eq!(offending.as_str(), "a.example.com");
                assert!(matches!(source, BlockSource::CnameLoop));
            }
            other => panic!("expected Block (loop), got {other:?}"),
        }
    }

    #[test]
    fn walk_response_blocks_depth_exceeded() {
        // 17 chained CNAMEs: depth cap is 16, so the 17th hop trips.
        let mut records = Vec::with_capacity(17);
        for i in 0..17 {
            records.push(cname_record(
                &format!("h{i}.example.com"),
                &format!("h{}.example.com", i + 1),
            ));
        }
        let engine = FilterEngine::new();
        let profile = ResolvedProfile::permissive_default();
        let v = walk_response(&records, &engine, &profile, NamePolicy::Neutral, 16);
        match v {
            Verdict::Block { source, .. } => {
                assert!(matches!(source, BlockSource::CnameDepthExceeded));
            }
            other => panic!("expected Block (depth exceeded), got {other:?}"),
        }
    }

    /// The prefetch walker and the serve walker must stop at the same depth.
    ///
    /// With an operator value above [`MAX_HOPS`] they once did not: the serve
    /// path clamped and blocked, the prefetch path ran to the operator's
    /// number, saw nothing, and cached an entry the serve path then refused.
    /// The mirroring used to be asserted only in a comment.
    ///
    /// `is_blocked` answers `false` for everything and the engine holds no
    /// corpus, so depth is the only thing either walker can be reacting to;
    /// the short-chain arm is the control that keeps "both blocked" from
    /// passing on a walker that blocks unconditionally.
    #[test]
    fn both_walkers_stop_at_the_same_depth_above_max_hops() {
        fn chain(hops: usize) -> Vec<Record> {
            (0..hops)
                .map(|i| {
                    cname_record(
                        &format!("h{i}.example.com"),
                        &format!("h{}.example.com", i + 1),
                    )
                })
                .collect()
        }

        let configured = MAX_HOPS + 8;
        let engine = FilterEngine::new();
        let profile = ResolvedProfile::permissive_default();

        let long = chain(MAX_HOPS + 4);
        let serve = walk_response(&long, &engine, &profile, NamePolicy::Neutral, configured);
        assert!(
            matches!(
                serve,
                Verdict::Block {
                    source: BlockSource::CnameDepthExceeded,
                    ..
                }
            ),
            "serve path must refuse a chain longer than MAX_HOPS, got {serve:?}"
        );
        assert!(
            crate::dns::handler::cname_chain_blocked(&long, configured, |_| false).is_some(),
            "prefetch path must refuse the same chain the serve path refuses"
        );

        let short = chain(4);
        assert_eq!(
            walk_response(&short, &engine, &profile, NamePolicy::Neutral, configured),
            Verdict::Allow,
            "control: a chain inside the cap is not refused by the serve path"
        );
        assert!(
            crate::dns::handler::cname_chain_blocked(&short, configured, |_| false).is_none(),
            "control: a chain inside the cap is not refused by the prefetch path"
        );
    }

    #[test]
    fn walk_response_admin_allow_short_circuits() {
        let records = [
            cname_record("a.example.com", "safe.com"),
            cname_record("safe.com", "evil.com"),
        ];
        let engine = engine_blocking(&["evil.com"]);
        let mut profile = permissive_with_bit0(&engine);
        profile.allow_domains = ["safe.com"]
            .iter()
            .map(|d| CompactString::new(*d))
            .collect::<std::collections::HashSet<_, _>>()
            .into();
        assert_eq!(
            walk_response(&records, &engine, &profile, NamePolicy::Neutral, 16),
            Verdict::Allow
        );
    }

    #[test]
    fn walk_response_returns_offending_name_byte_identical() {
        // Upstream returns a mixed-case target; the walker must
        // case-normalise before lookup AND in the `offending` field
        // (Sprint 2 audit log + TUI badge consume this directly).
        let records = [cname_record("a.example.com", "EVIL.COM")];
        let engine = engine_blocking(&["evil.com"]);
        let profile = permissive_with_bit0(&engine);
        let v = walk_response(&records, &engine, &profile, NamePolicy::Neutral, 16);
        match v {
            Verdict::Block { offending, .. } => {
                assert_eq!(offending.as_str(), "evil.com");
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn walk_response_handles_empty_records() {
        let engine = engine_blocking(&["evil.com"]);
        let profile = permissive_with_bit0(&engine);
        assert_eq!(
            walk_response(&[], &engine, &profile, NamePolicy::Neutral, 16),
            Verdict::Allow
        );
    }

    #[test]
    fn walk_response_skips_non_cname_records() {
        // A and AAAA records in the answer must not interfere with
        // CNAME chain walking. The blocked CNAME still trips Block.
        let records = [
            a_record("a.example.com"),
            cname_record("a.example.com", "evil.com"),
            a_record("evil.com"),
        ];
        let engine = engine_blocking(&["evil.com"]);
        let profile = permissive_with_bit0(&engine);
        let v = walk_response(&records, &engine, &profile, NamePolicy::Neutral, 16);
        assert!(matches!(v, Verdict::Block { .. }));
    }

    #[test]
    fn walk_response_lowercases_targets_before_lookup() {
        // Mixed-case CNAME target; the engine has the lowercase form
        // only. Without the case-norm in the walker, this would miss
        // the block.
        let records = [cname_record("a.example.com", "TrAcKeR.evil.com")];
        let engine = engine_blocking(&["tracker.evil.com"]);
        let profile = permissive_with_bit0(&engine);
        let v = walk_response(&records, &engine, &profile, NamePolicy::Neutral, 16);
        assert!(matches!(v, Verdict::Block { .. }));
    }

    #[test]
    fn walk_response_blocks_via_admin_deny_domains() {
        let records = [cname_record("a.example.com", "blocked.example.com")];
        let engine = FilterEngine::new();
        let mut profile = ResolvedProfile::permissive_default();
        profile.deny_domains = ["blocked.example.com"]
            .iter()
            .map(|d| CompactString::new(*d))
            .collect::<std::collections::HashSet<_, _>>()
            .into();
        let v = walk_response(&records, &engine, &profile, NamePolicy::Neutral, 16);
        match v {
            Verdict::Block { offending, source } => {
                assert_eq!(offending.as_str(), "blocked.example.com");
                assert!(matches!(source, BlockSource::AdminBlock));
            }
            other => panic!("expected Block (admin), got {other:?}"),
        }
    }

    #[test]
    fn walk_response_blocks_via_admin_rule_attribution() {
        let records = [cname_record("a.example.com", "tracker.com")];
        let engine = FilterEngine::new();
        let mut profile = ResolvedProfile::permissive_default();
        profile.rules = parse_rules("||tracker.com^").into();
        let v = walk_response(&records, &engine, &profile, NamePolicy::Neutral, 16);
        match v {
            Verdict::Block { offending, source } => {
                assert_eq!(offending.as_str(), "tracker.com");
                match source {
                    BlockSource::Rule(pattern) => {
                        assert_eq!(pattern.as_str(), "tracker.com");
                    }
                    other => panic!("expected Rule source, got {other:?}"),
                }
            }
            other => panic!("expected Block (rule), got {other:?}"),
        }
    }

    #[test]
    fn walk_response_blocks_via_block_all() {
        let records = [cname_record("a.example.com", "anything.com")];
        let engine = FilterEngine::new();
        let mut profile = ResolvedProfile::permissive_default();
        profile.block_all = true;
        let v = walk_response(&records, &engine, &profile, NamePolicy::Neutral, 16);
        match v {
            Verdict::Block { offending, source } => {
                assert_eq!(offending.as_str(), "anything.com");
                assert!(matches!(source, BlockSource::AdminBlock));
            }
            other => panic!("expected Block (block_all), got {other:?}"),
        }
    }

    // ── F1 / F5 (incident 2026-07-27): the pre-resolved NamePolicy ──
    //
    // These pin "`@@||fts.rbxcdn.com^` is in the operator's admin rules,
    // the device references it, and the name is blocked anyway". Pre-fix
    // the walker only ever tested the CNAME *target* against
    // `allow_domains`, so the only name that could win the chain was a CDN
    // target the operator never sees — and even after the Lane A fix, an
    // allow attached to a *device* could not reach this site at all.
    //
    // Every test below leaves `profile.allow_domains` EMPTY unless it is
    // specifically exercising the target short-circuit. That is deliberate:
    // with the set empty, the ONLY thing that can turn a blocked chain into
    // `Allow` is the `NamePolicy` the caller handed in, so each test names
    // exactly one mechanism.

    fn overlay_allowing(domains: &[&str], override_profile_deny: bool) -> DeviceOverlay {
        let allow: HashSet<CompactString, RandomState> = domains
            .iter()
            .map(|d| {
                let mut cs = CompactString::new(*d);
                cs.make_ascii_lowercase();
                cs
            })
            .collect();
        DeviceOverlay {
            device_id: Id::new("pc-test").unwrap(),
            allow: Arc::new(allow),
            deny: Arc::new(HashSet::with_hasher(RandomState::new())),
            override_profile_deny,
        }
    }

    fn profile_denying(engine: &FilterEngine, domains: &[&str]) -> ResolvedProfile {
        let mut p = permissive_with_bit0(engine);
        p.deny_domains = domains
            .iter()
            .map(|d| CompactString::new(*d))
            .collect::<std::collections::HashSet<_, _>>()
            .into();
        p
    }

    // ── NamePolicy::resolve — construction ──────────────────────────────

    #[test]
    fn resolve_returns_neutral_when_no_allow_set_matches() {
        let profile = permissive_filtered();
        let overlay = overlay_allowing(&["other.example.com"], false);
        assert_eq!(
            NamePolicy::resolve("fts.rbxcdn.com", &profile, Some(&overlay)),
            NamePolicy::Neutral
        );
        assert_eq!(
            NamePolicy::resolve("fts.rbxcdn.com", &profile, None),
            NamePolicy::Neutral
        );
    }

    #[test]
    fn resolve_returns_profile_allow_on_profile_allow_domains_hit() {
        let mut profile = permissive_filtered();
        profile.allow_domains = ["fts.rbxcdn.com"]
            .iter()
            .map(|d| CompactString::new(*d))
            .collect::<std::collections::HashSet<_, _>>()
            .into();
        assert_eq!(
            NamePolicy::resolve("fts.rbxcdn.com", &profile, None),
            NamePolicy::ProfileAllow
        );
    }

    /// The incident's actual shape: the operator attached the rule to the
    /// **device** (`[[devices]].allow_rules`), which lands in
    /// `DeviceOverlay.allow` — a set structurally distinct from
    /// `ResolvedProfile.allow_domains`.
    #[test]
    fn resolve_returns_device_allow_carrying_the_override_flag() {
        let profile = permissive_filtered();
        for flag in [false, true] {
            let overlay = overlay_allowing(&["fts.rbxcdn.com"], flag);
            assert_eq!(
                NamePolicy::resolve("fts.rbxcdn.com", &profile, Some(&overlay)),
                NamePolicy::DeviceAllow {
                    override_profile_deny: flag
                },
                "the device's override_profile_deny must survive into the verdict — \
                 it is the only thing that decides row 6 vs row 7 downstream"
            );
        }
    }

    /// `ProfileAllow` is never weaker than `DeviceAllow` on any
    /// `BlockSource`, so when both layers hit, reporting the stronger one
    /// cannot lose an allow the operator was entitled to.
    #[test]
    fn resolve_prefers_profile_allow_when_both_layers_hit() {
        let mut profile = permissive_filtered();
        profile.allow_domains = ["fts.rbxcdn.com"]
            .iter()
            .map(|d| CompactString::new(*d))
            .collect::<std::collections::HashSet<_, _>>()
            .into();
        let overlay = overlay_allowing(&["fts.rbxcdn.com"], false);
        assert_eq!(
            NamePolicy::resolve("fts.rbxcdn.com", &profile, Some(&overlay)),
            NamePolicy::ProfileAllow
        );
    }

    /// Both allow sets carry `domain_matches_set` subdomain-walk
    /// semantics — allowing `rbxcdn.com` allows `fts.rbxcdn.com`.
    #[test]
    fn resolve_honours_the_subdomain_walk_on_both_layers() {
        let mut profile = permissive_filtered();
        profile.allow_domains = ["rbxcdn.com"]
            .iter()
            .map(|d| CompactString::new(*d))
            .collect::<std::collections::HashSet<_, _>>()
            .into();
        assert_eq!(
            NamePolicy::resolve("fts.rbxcdn.com", &profile, None),
            NamePolicy::ProfileAllow
        );

        let bare = permissive_filtered();
        let overlay = overlay_allowing(&["rbxcdn.com"], false);
        assert_eq!(
            NamePolicy::resolve("fts.rbxcdn.com", &bare, Some(&overlay)),
            NamePolicy::DeviceAllow {
                override_profile_deny: false
            }
        );
    }

    // ── NamePolicy::outranks — the consumption matrix ───────────────────

    /// The whole truth table in one place. A change to any cell has to
    /// come here first.
    #[test]
    fn outranks_matrix_is_layer_aware() {
        let dev_no = NamePolicy::DeviceAllow {
            override_profile_deny: false,
        };
        let dev_yes = NamePolicy::DeviceAllow {
            override_profile_deny: true,
        };
        let rule = BlockSource::Rule(CompactString::new("tracker.com"));

        // Neutral never outranks anything.
        for src in [
            BlockSource::List(0),
            rule.clone(),
            BlockSource::AdminBlock,
            BlockSource::CnameLoop,
            BlockSource::CnameDepthExceeded,
        ] {
            assert!(
                !NamePolicy::Neutral.outranks(&src),
                "Neutral must never outrank {src:?} — the response path filters in full"
            );
        }

        // External list: every explicit allow wins.
        assert!(NamePolicy::ProfileAllow.outranks(&BlockSource::List(0)));
        assert!(dev_no.outranks(&BlockSource::List(0)));
        assert!(dev_yes.outranks(&BlockSource::List(0)));

        // Operator's own profile-level deny: same-layer wins, weaker layer
        // needs the override flag.
        for src in [rule.clone(), BlockSource::AdminBlock] {
            assert!(
                NamePolicy::ProfileAllow.outranks(&src),
                "a profile allow is same-layer with {src:?}"
            );
            assert!(
                !dev_no.outranks(&src),
                "apply_overlay row 6: a device allow must NOT sink {src:?} without \
                 override_profile_deny"
            );
            assert!(
                dev_yes.outranks(&src),
                "apply_overlay row 7: override_profile_deny lets the device allow win"
            );
        }

        // Malformation guards are not policy — no allow switches them off.
        for src in [BlockSource::CnameLoop, BlockSource::CnameDepthExceeded] {
            for policy in [NamePolicy::ProfileAllow, dev_no, dev_yes] {
                assert!(
                    !policy.outranks(&src),
                    "{policy:?} must not outrank {src:?}: a malformed answer is not a \
                     policy decision"
                );
            }
        }
    }

    /// The response-IP blocklist has no per-entry attribution, so it ranks
    /// with `BlockSource::List` for every allow layer — including a device
    /// allow with `override_profile_deny = false`, because no profile deny
    /// is in play for that flag to guard.
    #[test]
    fn outranks_external_accepts_any_explicit_allow() {
        assert!(!NamePolicy::Neutral.outranks_external());
        assert!(NamePolicy::ProfileAllow.outranks_external());
        assert!(NamePolicy::DeviceAllow {
            override_profile_deny: false
        }
        .outranks_external());
        assert!(NamePolicy::DeviceAllow {
            override_profile_deny: true
        }
        .outranks_external());
    }

    // ── walk_response consuming the verdict ─────────────────────────────

    /// **Walker-arm discriminator.** Same chain as the two allow tests
    /// below, `NamePolicy::Neutral`. Without it those tests would pass
    /// against a walker that allows everything.
    ///
    /// The *construction*-side discriminator (a `resolve` that derives the
    /// verdict from "was not blocked" rather than from an allow-set hit)
    /// cannot be caught here — this test hands the walker a policy
    /// directly. It lives in `tests/integration_name_policy_once.rs`,
    /// which drives the real handler.
    #[test]
    fn walk_response_blocks_a_blocked_chain_under_a_neutral_policy() {
        let records = [cname_record(
            "fts.rbxcdn.com",
            "ftsak.rbxcdn.com.akamaized.net",
        )];
        let engine = engine_blocking(&["ftsak.rbxcdn.com.akamaized.net"]);
        let profile = permissive_with_bit0(&engine);
        let v = walk_response(&records, &engine, &profile, NamePolicy::Neutral, 16);
        match v {
            Verdict::Block { offending, source } => {
                assert_eq!(offending.as_str(), "ftsak.rbxcdn.com.akamaized.net");
                assert!(matches!(source, BlockSource::List(0)));
            }
            other => panic!("expected Block without an allow, got {other:?}"),
        }
    }

    /// Lane A non-regression: a *profile*-scoped allow on the queried name
    /// wins a chain that flattens onto a subscribed list.
    #[test]
    fn walk_response_profile_allow_wins_an_external_list_block() {
        let records = [cname_record(
            "fts.rbxcdn.com",
            "ftsak.rbxcdn.com.akamaized.net",
        )];
        let engine = engine_blocking(&["ftsak.rbxcdn.com.akamaized.net"]);
        let profile = permissive_with_bit0(&engine);
        assert_eq!(
            walk_response(&records, &engine, &profile, NamePolicy::ProfileAllow, 16),
            Verdict::Allow
        );
    }

    /// **The reported incident.** Operator allow attached to the device;
    /// the chain flattens onto a CDN target sitting on a subscribed list.
    /// Design rule 4 forbids an external list from granting an allow — it
    /// says nothing about an operator allow beating one.
    #[test]
    fn walk_response_device_allow_wins_an_external_list_block() {
        let records = [cname_record(
            "fts.rbxcdn.com",
            "ftsak.rbxcdn.com.akamaized.net",
        )];
        let engine = engine_blocking(&["ftsak.rbxcdn.com.akamaized.net"]);
        let profile = permissive_with_bit0(&engine);
        assert_eq!(
            walk_response(
                &records,
                &engine,
                &profile,
                NamePolicy::DeviceAllow {
                    override_profile_deny: false
                },
                16
            ),
            Verdict::Allow,
            "the incident case: a device-scoped allow must beat an external blocklist"
        );
    }

    /// **The trap a boolean verdict falls into.** The queried name carries
    /// a *device* allow; the chain terminates on a name the operator
    /// denied at *profile* level. `override_profile_deny = false`, so
    /// `apply_overlay` row 6 would refuse this pairing for the queried
    /// name — the response path must refuse it too, or the weaker layer
    /// overrules the stronger one hop later.
    #[test]
    fn walk_response_device_allow_loses_to_a_profile_deny_without_override() {
        let records = [cname_record("app.example", "cdn.evil.example")];
        let engine = FilterEngine::new();
        let profile = profile_denying(&engine, &["cdn.evil.example"]);
        let v = walk_response(
            &records,
            &engine,
            &profile,
            NamePolicy::DeviceAllow {
                override_profile_deny: false,
            },
            16,
        );
        match v {
            Verdict::Block { offending, source } => {
                assert_eq!(offending.as_str(), "cdn.evil.example");
                assert!(matches!(source, BlockSource::AdminBlock));
            }
            other => panic!(
                "a device allow must not sink a profile deny without \
                 override_profile_deny (apply_overlay row 6); got {other:?}"
            ),
        }
    }

    /// Row 7: with `override_profile_deny` the same pairing allows.
    #[test]
    fn walk_response_device_allow_beats_a_profile_deny_with_override() {
        let records = [cname_record("app.example", "cdn.evil.example")];
        let engine = FilterEngine::new();
        let profile = profile_denying(&engine, &["cdn.evil.example"]);
        assert_eq!(
            walk_response(
                &records,
                &engine,
                &profile,
                NamePolicy::DeviceAllow {
                    override_profile_deny: true
                },
                16
            ),
            Verdict::Allow
        );
    }

    /// The `BlockSource::Rule` arm of the same rule — an advanced
    /// `||tracker.com^` is the operator's word just as much as
    /// `deny_domains` is.
    #[test]
    fn walk_response_device_allow_loses_to_a_profile_rule_without_override() {
        let records = [cname_record("app.example", "tracker.com")];
        let engine = FilterEngine::new();
        let mut profile = permissive_with_bit0(&engine);
        profile.rules = parse_rules("||tracker.com^").into();
        let v = walk_response(
            &records,
            &engine,
            &profile,
            NamePolicy::DeviceAllow {
                override_profile_deny: false,
            },
            16,
        );
        match v {
            Verdict::Block { source, .. } => match source {
                BlockSource::Rule(pattern) => assert_eq!(pattern.as_str(), "tracker.com"),
                other => panic!("expected Rule source, got {other:?}"),
            },
            other => panic!("device allow must not sink an admin rule, got {other:?}"),
        }
    }

    /// A *profile* allow and a profile deny are the same layer, so the
    /// allow wins — the semantics frozen by the Lane A fix.
    #[test]
    fn walk_response_profile_allow_wins_a_profile_deny() {
        let records = [cname_record("app.example", "cdn.evil.example")];
        let engine = FilterEngine::new();
        let profile = profile_denying(&engine, &["cdn.evil.example"]);
        assert_eq!(
            walk_response(&records, &engine, &profile, NamePolicy::ProfileAllow, 16),
            Verdict::Allow
        );
    }

    /// **Anti-spoof — the test that justifies keying the policy on the
    /// caller's name instead of on `visited[0]`.**
    ///
    /// `record.name` of the first CNAME comes from the *upstream*, so it
    /// is attacker-influenced: a hostile or compromised resolver can emit
    /// an answer whose first CNAME is owned by a name the operator
    /// allow-listed, and thereby launder an arbitrary chain. Here the
    /// forged record owner (`allowed.example.com`) IS in `allow_domains`
    /// while the policy handed in is `Neutral` — i.e. the client asked
    /// for something else entirely. The walk must still block.
    ///
    /// An implementation that probes `visited[0]` against `allow_domains`
    /// returns `Allow` here.
    #[test]
    fn walk_response_ignores_spoofed_first_record_owner() {
        let records = [cname_record("allowed.example.com", "evil.com")];
        let engine = engine_blocking(&["evil.com"]);
        let mut profile = permissive_with_bit0(&engine);
        profile.allow_domains = ["allowed.example.com"]
            .iter()
            .map(|d| CompactString::new(*d))
            .collect::<std::collections::HashSet<_, _>>()
            .into();
        let v = walk_response(&records, &engine, &profile, NamePolicy::Neutral, 16);
        match v {
            Verdict::Block { offending, source } => {
                assert_eq!(offending.as_str(), "evil.com");
                assert!(matches!(source, BlockSource::List(0)));
            }
            other => panic!(
                "spoofed first-record owner must not grant the allow; got {other:?}. \
                 The allow key is the caller-resolved NamePolicy, never visited[0]."
            ),
        }
    }

    /// `CnameLoop` is not policy, it is a defence against a malformed
    /// answer. No allow switches it off.
    #[test]
    fn walk_response_allow_does_not_bypass_cname_loop() {
        let records = [
            cname_record("a.example.com", "b.example.com"),
            cname_record("b.example.com", "a.example.com"),
        ];
        let engine = FilterEngine::new();
        let profile = ResolvedProfile::permissive_default();
        for policy in [
            NamePolicy::ProfileAllow,
            NamePolicy::DeviceAllow {
                override_profile_deny: true,
            },
        ] {
            match walk_response(&records, &engine, &profile, policy, 16) {
                Verdict::Block { source, .. } => {
                    assert!(matches!(source, BlockSource::CnameLoop));
                }
                other => panic!("{policy:?} must not bypass the loop guard, got {other:?}"),
            }
        }
    }

    /// Depth arm: an unbounded chain stays blocked under any allow.
    #[test]
    fn walk_response_allow_does_not_bypass_depth_cap() {
        let mut records = Vec::with_capacity(17);
        for i in 0..17 {
            records.push(cname_record(
                &format!("h{i}.example.com"),
                &format!("h{}.example.com", i + 1),
            ));
        }
        let engine = FilterEngine::new();
        let profile = ResolvedProfile::permissive_default();
        for policy in [
            NamePolicy::ProfileAllow,
            NamePolicy::DeviceAllow {
                override_profile_deny: true,
            },
        ] {
            match walk_response(&records, &engine, &profile, policy, 16) {
                Verdict::Block { source, .. } => {
                    assert!(matches!(source, BlockSource::CnameDepthExceeded));
                }
                other => panic!("{policy:?} must not bypass the depth cap, got {other:?}"),
            }
        }
    }

    /// Non-regression for the pre-existing *target* short-circuit (the
    /// `domain_matches_set(&target, …)` probe): the policy check is
    /// additive, it does not replace it. The policy here is `Neutral`, so
    /// only the target probe can produce the `Allow`.
    #[test]
    fn walk_response_target_short_circuit_still_applies() {
        let records = [
            cname_record("a.example.com", "safe.com"),
            cname_record("safe.com", "evil.com"),
        ];
        let engine = engine_blocking(&["evil.com"]);
        let mut profile = permissive_with_bit0(&engine);
        profile.allow_domains = ["safe.com"]
            .iter()
            .map(|d| CompactString::new(*d))
            .collect::<std::collections::HashSet<_, _>>()
            .into();
        assert_eq!(
            walk_response(&records, &engine, &profile, NamePolicy::Neutral, 16),
            Verdict::Allow
        );
    }

    /// The target short-circuit stays **profile**-scoped: a device allow
    /// grants passage for the name the operator named, not for arbitrary
    /// intermediate hops the chain happens to flatten onto. Here the
    /// blocked tail is reached through `safe.com`, which only the DEVICE
    /// allows — and the chain still blocks.
    #[test]
    fn walk_response_device_allow_does_not_extend_to_cname_targets() {
        let records = [
            cname_record("a.example.com", "safe.com"),
            cname_record("safe.com", "evil.com"),
        ];
        let engine = engine_blocking(&["evil.com"]);
        let profile = permissive_with_bit0(&engine);
        assert!(
            profile.allow_domains.is_empty(),
            "fixture guard: only the device may allow `safe.com` here"
        );
        // The device allows `safe.com`, but the queried name is
        // `a.example.com`, so the resolved policy is Neutral.
        let overlay = overlay_allowing(&["safe.com"], false);
        assert_eq!(
            NamePolicy::resolve("a.example.com", &profile, Some(&overlay)),
            NamePolicy::Neutral
        );
        assert!(matches!(
            walk_response(&records, &engine, &profile, NamePolicy::Neutral, 16),
            Verdict::Block { .. }
        ));
    }

    #[test]
    fn walk_response_clamps_max_depth_to_ceiling() {
        // Operator passes max_depth=99; walker must clamp to 16.
        // Build a 17-hop chain to verify the clamp engages.
        let mut records = Vec::with_capacity(17);
        for i in 0..17 {
            records.push(cname_record(
                &format!("h{i}.example.com"),
                &format!("h{}.example.com", i + 1),
            ));
        }
        let engine = FilterEngine::new();
        let profile = ResolvedProfile::permissive_default();
        let v = walk_response(&records, &engine, &profile, NamePolicy::Neutral, 99);
        assert!(matches!(
            v,
            Verdict::Block {
                source: BlockSource::CnameDepthExceeded,
                ..
            }
        ));
    }
}
