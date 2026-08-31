//! Chain-of-trust walk — authenticate a name from the root anchor down (§4.10-3a).
//!
//! [`verify::verify_rrset`](crate::dnssec::verify::verify_rrset) authenticates
//! *one* RRset against *one* DNSKEY. This module sequences those calls into a
//! full RFC 4035 §5 chain of trust: start from an embedded root trust anchor and
//! descend the delegation hierarchy `.` → TLD → … → target zone, at each hop
//!
//! 1. fetching the child's DS RRset from the parent and authenticating it with
//!    the parent's already-trusted DNSKEYs,
//! 2. fetching the child's DNSKEY RRset, confirming a key it contains is the one
//!    the DS commits to (`DS::covers`), and authenticating the RRset's
//!    self-signature,
//!
//! then optionally authenticating the queried answer RRset against the target
//! zone's keys. The result is a single [`ChainResult`] for the name.
//!
//! ## Scope (§4.10-3a + §4.10-3b)
//!
//! - The **positive** chain (§4.10-3a): `Secure` when every hop authenticates,
//!   `Bogus` when a link is broken, `Indeterminate` when a DoS cap trips or a
//!   fetch fails.
//! - The **no-DS delegation** (§4.10-3b): a delegation with no DS could be a
//!   legitimately *unsigned* zone or a stripped-DS downgrade. [`resolve_no_ds`]
//!   consults the parent's authenticated NSEC denial proof ([`crate::dnssec::denial`])
//!   to decide: a proof of no-DS ⇒ `Insecure(UnsignedDelegation)`; a missing or
//!   contradictory proof ⇒ `Bogus`; no proof material at all ⇒
//!   [`crate::dnssec::chain::Indeterminate::DenialProofRequired`]. NSEC3 denial and the
//!   `max_nsec3_iterations` cap are §4.10-3c.
//! - The `max_chain_depth` and `max_queries` DoS caps (§4.10-3a).
//!
//! Like the rest of [`crate::dnssec`], this is an **engine** — it produces a
//! verdict but is not wired into the live response path (no AD/CD bit, no
//! SERVFAIL). That is §4.10-4. Chain material is fetched through the injectable
//! [`ChainFetcher`] trait so the walk is hermetically testable offline; the
//! production adapter over the daemon's upstream (which must set the DO bit and
//! retain the authority section) lands with the §4.10-4 wiring.

use async_trait::async_trait;
use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY, DS, NSEC3, RRSIG};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

use crate::config::settings::DnssecConfig;
use crate::dnssec::denial::{nsec3_proves_no_ds, nsec_proves_unsigned_delegation, Nsec3NoDsProof};
use crate::dnssec::trust_anchor::RootTrustAnchors;
use crate::dnssec::verify::{verify_rrset, BogusReason, InsecureReason, Verdict};

/// One RRset fetched for the chain walk: the records of the queried type plus the
/// RRSIG(s) covering them. An empty `records` models an absent RRset (NODATA /
/// NXDOMAIN) — for a DS query that means "no secure delegation here".
#[derive(Debug, Clone, Default)]
pub struct FetchedRrset {
    /// The records of the queried type (e.g. all the zone's DNSKEYs, or the
    /// child's DS records). Empty = the RRset does not exist.
    pub records: Vec<Record>,
    /// The RRSIG records covering `records`.
    pub rrsigs: Vec<RRSIG>,
    /// The response's authority section, verbatim and heterogeneous (NSEC/NSEC3 +
    /// their RRSIGs + SOA, as they arrived on the wire). For a DS query that
    /// returned NODATA this carries the parent's authenticated denial-of-existence
    /// proof that no DS exists at the child (§4.10-3b consumes it); empty for an
    /// answer that needs no denial proof.
    pub authority: Vec<Record>,
}

/// Why fetching chain material failed at the transport level (distinct from a
/// cryptographic verdict — a fetch failure makes the chain `Indeterminate`, not
/// `Bogus`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
    /// The upstream could not be reached, timed out, or returned a transport
    /// error. Carries a short diagnostic.
    Transport(String),
    /// The upstream answered with a server failure (SERVFAIL / REFUSED).
    ServerFailure,
}

/// Fetches DNSSEC chain material (DNSKEY / DS RRsets) for the walk.
///
/// Production implementations issue DO-bit queries to the configured upstream;
/// tests inject a canned implementation backed by captured responses, so the
/// walk runs offline and deterministically. The `name`/`rtype` pair identifies
/// the RRset to fetch (e.g. `(org., DS)` or `(., DNSKEY)`).
#[async_trait]
pub trait ChainFetcher: Send + Sync {
    /// Fetch the `rtype` RRset at `name`, with the DNSSEC OK (DO) bit set.
    async fn fetch(&self, name: &Name, rtype: RecordType) -> Result<FetchedRrset, FetchError>;
}

/// The outcome of walking the chain of trust for a name — RFC 4035 §5's four
/// validator states. ([`Verdict`](crate::dnssec::verify::Verdict) is the
/// three-state per-RRset subset; a chain additionally has the `Indeterminate`
/// state, for "could not complete validation".)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainResult {
    /// Every hop from the root anchor to the target authenticated.
    Secure,
    /// The chain is provably unsigned from some point down — today only via a
    /// hop whose algorithm is out of scope (the denial-of-existence-based
    /// unsigned-delegation proof arrives in §4.10-3b). Reuses the engine's
    /// [`InsecureReason`] unchanged.
    Insecure(InsecureReason),
    /// A link in the chain is broken: the response must not be trusted.
    Bogus(ChainBogus),
    /// Validation could not be completed (a DoS cap tripped, a fetch failed, no
    /// trust anchor matched, or a no-DS delegation needs denial-of-existence
    /// proof). Not an assertion that the answer is forged.
    Indeterminate(Indeterminate),
}

/// Why a [`ChainResult::Bogus`] chain failed. Wraps a per-RRset
/// [`BogusReason`] for a failed hop, or names a chain-structural break that has
/// no single-RRset analogue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainBogus {
    /// A per-hop [`verify_rrset`] call returned `Bogus`, propagated as-is.
    Hop(BogusReason),
    /// The delegation is signed (a DS exists) but no DNSKEY in the child's RRset
    /// is the key the DS commits to — the chain cannot continue.
    DsCoversNoKey,
    /// The delegation is signed (a DS exists) but the child returned no DNSKEY
    /// RRset at all.
    DnskeyMissing,
    /// A no-DS delegation offered a denial proof, but no *authenticated* NSEC
    /// matching the child's name was present to prove the DS absent (§4.10-3b) —
    /// the absence of a proof for a stripped DS must not be trusted.
    DenialProofMissing,
    /// A no-DS delegation's authenticated NSEC *contradicts* an unsigned-delegation
    /// claim: it asserts a DS, or is not a parent-side zone cut (no NS bit, or a
    /// SOA bit). The denial proves the opposite of what a downgrade would need.
    DenialProofInvalid,
    /// The answer RRset carried records under more than one owner name, so it is
    /// not a single authenticatable RRset. [`verify_keyset`] (via hickory's
    /// `verify_rrsig`) authenticates only the subset whose owner equals the first
    /// record's name, yet a `Secure` verdict is read by the consumer as covering
    /// the whole slice (AD bit) — which would vouch for unverified sibling
    /// records. Fail closed: a correct positive answer is single-owner after the
    /// queried-type filter, so a multi-owner answer is a downgrade/injection
    /// fingerprint.
    AnswerOwnerMismatch,
}

/// Why a [`ChainResult::Indeterminate`] chain could not be completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Indeterminate {
    /// The walk would descend past `max_chain_depth` delegations.
    MaxChainDepthExceeded,
    /// The walk would issue more than `max_queries` upstream queries.
    MaxQueriesExceeded,
    /// A no-DS delegation's NSEC3 denial proof declares more hash iterations than
    /// `max_nsec3_iterations`; refused before hashing (RFC 5155 §10.3, §4.10-3c).
    /// The third DoS cap — an attacker-chosen iteration count is a CPU-DoS vector.
    MaxNsec3IterationsExceeded,
    /// A delegation has no DS RRset. Proving this is a legitimately unsigned
    /// delegation (rather than a stripped-DS downgrade) needs authenticated
    /// denial of existence — §4.10-3b upgrades this to `Insecure`/`Bogus`.
    DenialProofRequired,
    /// Fetching chain material failed at the transport level.
    FetchFailed,
    /// The root DNSKEY RRset contains no key committed to by an embedded trust
    /// anchor — there is no basis to validate anything.
    NoAnchorMatch,
    /// The walk performed more than `max_signature_verifications` RRSIG crypto
    /// checks — a KeyTrap (CVE-2023-50387) colliding-key-tag flood forcing
    /// O(keys × sigs) verifications. The fourth DoS cap, counted globally across
    /// the whole walk. Structural: fail closed (SERVFAIL under validate), never
    /// serve — a verification blowup is an attack signal, not a transient glitch.
    MaxSignatureVerificationsExceeded,
}

/// Walk the chain of trust for `target_zone`, optionally authenticating a queried
/// `answer` RRset against the target zone's keys.
///
/// `target_zone` is the apex of the signed zone whose DNSKEYs terminate the walk
/// (e.g. `internetsociety.org.`); the walk authenticates `.` → each label-suffix
/// of `target_zone`. `answer`, if given, is the queried RRset plus the RRSIG over
/// it, authenticated last against the target zone's keys. `now` is the
/// validator's clock in Unix seconds (injected, as in [`verify_rrset`]). `caps`
/// supplies the DoS limits.
pub async fn validate_chain(
    fetcher: &dyn ChainFetcher,
    anchors: &RootTrustAnchors,
    target_zone: &Name,
    answer: Option<(&[Record], &RRSIG)>,
    now: u32,
    caps: &DnssecConfig,
) -> ChainResult {
    let mut queries: u32 = 0;
    // Global RRSIG-verification budget for the whole walk (KeyTrap guard). Charged
    // in `verify_keyset` at every hop, the denial proofs, and the answer — so the
    // per-hop crypto cost cannot be multiplied across `max_chain_depth` hops.
    let mut verifications: u32 = 0;

    // ---- Hop 0: the root DNSKEY RRset, anchored in an embedded trust anchor. --
    let root = Name::root();
    let root_set = match guarded_fetch(fetcher, &root, RecordType::DNSKEY, &mut queries, caps).await
    {
        Ok(set) => set,
        Err(cr) => return cr,
    };
    let root_keys = extract_dnskeys(&root_set.records);

    // The keys an embedded anchor's DS commits to — the basis for trust.
    let anchored: Vec<DNSKEY> = root_keys
        .iter()
        .filter(|k| {
            anchors
                .anchors()
                .iter()
                .any(|a| a.to_ds().covers(&root, k).unwrap_or(false))
        })
        .cloned()
        .collect();
    if anchored.is_empty() {
        return ChainResult::Indeterminate(Indeterminate::NoAnchorMatch);
    }
    // Authenticate the root DNSKEY RRset's self-signature with an anchored key.
    let verdict = match verify_keyset(
        &root_set.records,
        &root_set.rrsigs,
        &root,
        &anchored,
        now,
        &mut verifications,
        caps,
    ) {
        Ok(v) => v,
        Err(cr) => return cr,
    };
    match verdict {
        Verdict::Secure => {}
        Verdict::Insecure(r) => return ChainResult::Insecure(r),
        Verdict::Bogus(r) => return ChainResult::Bogus(ChainBogus::Hop(r)),
    }
    // The whole authenticated root DNSKEY RRset signs the next hop's DS.
    let mut current_keys = root_keys;

    // ---- Descend each delegation: `.` → label-suffixes of the target zone. ----
    let depth = usize::from(target_zone.num_labels());
    for i in 1..=depth {
        if i > usize::from(caps.max_chain_depth) {
            return ChainResult::Indeterminate(Indeterminate::MaxChainDepthExceeded);
        }
        let child = target_zone.trim_to(i);

        // (a) The child's DS RRset, signed by the parent. No DS ⇒ needs a denial
        //     proof to tell an unsigned delegation from a downgrade (§4.10-3b).
        let ds_set = match guarded_fetch(fetcher, &child, RecordType::DS, &mut queries, caps).await
        {
            Ok(set) => set,
            Err(cr) => return cr,
        };
        if ds_set.records.is_empty() {
            // No DS: a legitimately unsigned delegation, or a stripped-DS
            // downgrade. The parent's authenticated NSEC denial proof decides
            // (§4.10-3b); the parent's keys (`current_keys`) sign that proof.
            return resolve_no_ds(
                &child,
                &ds_set.authority,
                &current_keys,
                now,
                &mut verifications,
                caps,
            );
        }
        let verdict = match verify_keyset(
            &ds_set.records,
            &ds_set.rrsigs,
            &child,
            &current_keys,
            now,
            &mut verifications,
            caps,
        ) {
            Ok(v) => v,
            Err(cr) => return cr,
        };
        match verdict {
            Verdict::Secure => {}
            Verdict::Insecure(r) => return ChainResult::Insecure(r),
            Verdict::Bogus(r) => return ChainResult::Bogus(ChainBogus::Hop(r)),
        }
        let ds_records = extract_ds(&ds_set.records);

        // (b) The child's DNSKEY RRset. A DS must commit to one of its keys, and
        //     that key must authenticate the RRset's self-signature.
        let key_set =
            match guarded_fetch(fetcher, &child, RecordType::DNSKEY, &mut queries, caps).await {
                Ok(set) => set,
                Err(cr) => return cr,
            };
        let child_keys = extract_dnskeys(&key_set.records);
        if child_keys.is_empty() {
            return ChainResult::Bogus(ChainBogus::DnskeyMissing);
        }
        let committed: Vec<DNSKEY> = child_keys
            .iter()
            .filter(|k| {
                ds_records
                    .iter()
                    .any(|ds| ds.covers(&child, k).unwrap_or(false))
            })
            .cloned()
            .collect();
        if committed.is_empty() {
            return ChainResult::Bogus(ChainBogus::DsCoversNoKey);
        }
        let verdict = match verify_keyset(
            &key_set.records,
            &key_set.rrsigs,
            &child,
            &committed,
            now,
            &mut verifications,
            caps,
        ) {
            Ok(v) => v,
            Err(cr) => return cr,
        };
        match verdict {
            Verdict::Secure => {}
            Verdict::Insecure(r) => return ChainResult::Insecure(r),
            Verdict::Bogus(r) => return ChainResult::Bogus(ChainBogus::Hop(r)),
        }
        current_keys = child_keys;
    }

    // ---- Optionally authenticate the queried answer against the zone's keys. --
    if let Some((records, rrsig)) = answer {
        // The leaf answer is authenticated under its OWN owner name (e.g.
        // `www.example.com.`), NOT the zone apex `target_zone` — the apex only
        // selected the keys. Using the apex would trip the RFC 4035 §5.3.1
        // label-count gate in `verify_rrset` for every name below the apex.
        // hickory still reconstructs the wildcard owner from the RRSIG Labels
        // field, so wildcard answers stay correct. Empty records (degenerate)
        // fall back to the apex and fail closed.
        let answer_owner = records.first().map_or(target_zone, |r| &r.name);
        // Owner-uniformity guard: `verify_keyset` only authenticates the records
        // whose owner == `answer_owner` (hickory's `verify_rrsig` filters by
        // `(name, class, type)`), but a `Secure` verdict is read by the consumer
        // as authenticating the whole slice. If a second owner name is present,
        // the slice is not one authenticatable RRset — fail closed rather than
        // vouch for the unverified subset. (`Name`'s `==` is the DNS-correct
        // case-insensitive comparison; empty `records` trivially passes and falls
        // through to the existing degenerate handling.)
        if records.iter().any(|r| &r.name != answer_owner) {
            return ChainResult::Bogus(ChainBogus::AnswerOwnerMismatch);
        }
        let verdict = match verify_keyset(
            records,
            std::slice::from_ref(rrsig),
            answer_owner,
            &current_keys,
            now,
            &mut verifications,
            caps,
        ) {
            Ok(v) => v,
            Err(cr) => return cr,
        };
        match verdict {
            Verdict::Secure => {}
            Verdict::Insecure(r) => return ChainResult::Insecure(r),
            Verdict::Bogus(r) => return ChainResult::Bogus(ChainBogus::Hop(r)),
        }
    }

    ChainResult::Secure
}

/// Resolve a delegation that has **no DS RRset** (RFC 4035 §5.2): decide whether
/// the parent served an *authenticated* NSEC/NSEC3 proof that no DS exists at
/// `child` (a legitimately unsigned delegation) versus a stripped-DS downgrade.
///
/// `authority` is the DS response's authority section (NSEC/NSEC3 + RRSIGs + SOA,
/// …); `parent_keys` are the parent zone's already-authenticated DNSKEYs, which
/// must sign the denial proof. **Authenticate before trust** is the central
/// security property: an unsigned or forged proof yields `Bogus`, never `Insecure`
/// — otherwise an attacker strips the real DS and injects a fabricated "no-DS"
/// proof to force a downgrade.
///
/// - empty authority ⇒ `Indeterminate(DenialProofRequired)` — no proof material,
///   validation cannot be completed (distinct from a proof that failed).
/// - a matching NSEC for `child` ⇒ the §4.10-3b NSEC path (below).
/// - otherwise ⇒ the §4.10-3c NSEC3 path ([`resolve_no_ds_nsec3`]).
///
/// NSEC path verdicts: authenticated NSEC with DS-absent ∧ NS-present ∧ SOA-absent
/// ⇒ `Insecure(UnsignedDelegation)`; authenticated NSEC contradicting that ⇒
/// `Bogus(DenialProofInvalid)`; NSEC present but unauthenticatable ⇒ `Bogus(Hop)`,
/// out-of-scope algorithm ⇒ `Insecure(OutOfScopeAlgorithm)`.
fn resolve_no_ds(
    child: &Name,
    authority: &[Record],
    parent_keys: &[DNSKEY],
    now: u32,
    verifications: &mut u32,
    caps: &DnssecConfig,
) -> ChainResult {
    if authority.is_empty() {
        return ChainResult::Indeterminate(Indeterminate::DenialProofRequired);
    }

    // The matching NSEC RRset: NSEC record(s) owned by `child` (case-insensitive
    // `Name` equality) and the RRSIG(s) covering an NSEC at that owner.
    let nsec_records: Vec<Record> = authority
        .iter()
        .filter(|r| r.record_type() == RecordType::NSEC && &r.name == child)
        .cloned()
        .collect();
    // No plain NSEC matches `child`: the proof is NSEC3 (or absent) — §4.10-3c.
    if nsec_records.is_empty() {
        return resolve_no_ds_nsec3(child, authority, parent_keys, now, verifications, caps);
    }
    let nsec_rrsigs: Vec<RRSIG> = authority
        .iter()
        .filter_map(|r| match &r.data {
            RData::DNSSEC(DNSSECRData::RRSIG(s))
                if s.input().type_covered == RecordType::NSEC && &r.name == child =>
            {
                Some(s.clone())
            }
            _ => None,
        })
        .collect();

    // Authenticate the matching NSEC RRset against the parent's keys, reusing the
    // one keyset verifier (Bogus>Insecure precedence + key-tag selection) every
    // other hop uses — the gate lives in exactly one place.
    let verdict = match verify_keyset(
        &nsec_records,
        &nsec_rrsigs,
        child,
        parent_keys,
        now,
        verifications,
        caps,
    ) {
        Ok(v) => v,
        Err(cr) => return cr,
    };
    match verdict {
        Verdict::Secure => {}
        Verdict::Bogus(r) => return ChainResult::Bogus(ChainBogus::Hop(r)),
        Verdict::Insecure(r) => return ChainResult::Insecure(r),
    }

    // Authenticated. Does any matching NSEC prove an unsigned delegation
    // (DS absent ∧ NS present ∧ SOA absent — a parent-side zone cut)?
    let proven = nsec_records.iter().any(|r| match &r.data {
        RData::DNSSEC(DNSSECRData::NSEC(n)) => nsec_proves_unsigned_delegation(n),
        _ => false,
    });
    if proven {
        ChainResult::Insecure(InsecureReason::UnsignedDelegation)
    } else {
        ChainResult::Bogus(ChainBogus::DenialProofInvalid)
    }
}

/// The NSEC3 arm of the no-DS hook (RFC 5155 §8.6 / §8.9, §4.10-3c). Same
/// auth-before-trust gate and same verdicts as the NSEC path: authenticate every
/// NSEC3 RRset against the parent's keys *first*, then decide no-DS over the
/// authenticated set only — a forged or unsigned NSEC3 is `Bogus` before any hash
/// or bitmap is trusted.
///
/// Scope is the closest-encloser-free single-hop case (a matching NSEC3, or an
/// opt-out NSEC3 covering the delegation hash); see [`nsec3_proves_no_ds`] and the
/// §4.10-3c handoff. The `max_nsec3_iterations` cap is charged *before* auth and
/// hashing — the cheapest refusal of an attacker-chosen iteration count.
fn resolve_no_ds_nsec3(
    child: &Name,
    authority: &[Record],
    parent_keys: &[DNSKEY],
    now: u32,
    verifications: &mut u32,
    caps: &DnssecConfig,
) -> ChainResult {
    let nsec3_records: Vec<&Record> = authority
        .iter()
        .filter(|r| r.record_type() == RecordType::NSEC3)
        .collect();
    if nsec3_records.is_empty() {
        // Neither NSEC nor NSEC3: a signed parent owes a denial proof for a
        // stripped DS, and none is present — do not trust the absence.
        return ChainResult::Bogus(ChainBogus::DenialProofMissing);
    }

    // Authenticate first, then apply the iteration cap over authenticated records
    // only (inside `nsec3_proves_no_ds`). RRSIG verification performs no NSEC3
    // hashing, so authenticating an over-cap record is cheap (and bounded by the
    // KeyTrap verification cap); the expensive owner-name hashing stays gated by
    // the cap for the records that actually drive the proof. A pre-auth scan that
    // refused on *any* record's declared count let one injected over-cap NSEC3 (a
    // different owner, unsigned) SERVFAIL a resolvable domain — RFC 5155 §10.3:
    // discard the unusable record, do not fail the walk (§4.10-5c).

    // Authenticate each NSEC3 RRset (grouped by owner) against the parent's keys;
    // only `Secure` groups' rdata may prove anything. Track a failed group for the
    // no-proof fallback so a forged/unsigned NSEC3 surfaces as `Bogus`/`Insecure`.
    let mut owners: Vec<Name> = Vec::new();
    for r in &nsec3_records {
        if !owners.iter().any(|o| o == &r.name) {
            owners.push(r.name.clone());
        }
    }
    let mut authed: Vec<(Name, NSEC3)> = Vec::new();
    let mut failed_bogus: Option<BogusReason> = None;
    let mut failed_insecure: Option<InsecureReason> = None;
    for owner in &owners {
        let recs: Vec<Record> = authority
            .iter()
            .filter(|r| r.record_type() == RecordType::NSEC3 && &r.name == owner)
            .cloned()
            .collect();
        let sigs: Vec<RRSIG> = authority
            .iter()
            .filter_map(|r| match &r.data {
                RData::DNSSEC(DNSSECRData::RRSIG(s))
                    if s.input().type_covered == RecordType::NSEC3 && &r.name == owner =>
                {
                    Some(s.clone())
                }
                _ => None,
            })
            .collect();
        let verdict =
            match verify_keyset(&recs, &sigs, owner, parent_keys, now, verifications, caps) {
                Ok(v) => v,
                Err(cr) => return cr,
            };
        match verdict {
            Verdict::Secure => {
                for r in &recs {
                    if let RData::DNSSEC(DNSSECRData::NSEC3(n)) = &r.data {
                        authed.push((owner.clone(), n.clone()));
                    }
                }
            }
            Verdict::Bogus(r) => failed_bogus = Some(r),
            Verdict::Insecure(r) => failed_insecure = Some(r),
        }
    }

    match nsec3_proves_no_ds(child, &authed, caps.max_nsec3_iterations) {
        Nsec3NoDsProof::UnsignedDelegation => {
            ChainResult::Insecure(InsecureReason::UnsignedDelegation)
        }
        Nsec3NoDsProof::Contradiction => ChainResult::Bogus(ChainBogus::DenialProofInvalid),
        Nsec3NoDsProof::IterationsExceeded => {
            ChainResult::Indeterminate(Indeterminate::MaxNsec3IterationsExceeded)
        }
        // No authenticated NSEC3 proved no-DS. A group that failed authentication
        // surfaces as `Bogus`/`Insecure` (Bogus > Insecure); otherwise the proof is
        // simply missing.
        Nsec3NoDsProof::NoProof => {
            if let Some(r) = failed_bogus {
                ChainResult::Bogus(ChainBogus::Hop(r))
            } else if let Some(r) = failed_insecure {
                ChainResult::Insecure(r)
            } else {
                ChainResult::Bogus(ChainBogus::DenialProofMissing)
            }
        }
    }
}

/// Authenticate `records` (an RRset at `name`) against a set of candidate `keys`,
/// trying each RRSIG paired with the key whose tag it names. Returns `Secure` if
/// any pair validates.
///
/// On failure, precedence is **Bogus over Insecure**: a determinable
/// cryptographic failure on a supported algorithm must never be masked by an
/// unrelated out-of-scope signature on the same RRset (an attacker could
/// otherwise attach a junk out-of-scope RRSIG to downgrade a real `Bogus` to
/// `Insecure`). If no RRSIG names a key we hold, the RRset cannot be tied to the
/// chain — `Bogus(KeyTagMismatch)`.
///
/// Selecting the key by the RRSIG's key tag matters: an RRset may carry RRSIGs
/// from several keys (e.g. a DNSKEY RRset signed by both KSK and ZSK), and pairing
/// a signature with the wrong key would spuriously fail.
///
/// **Invariant:** every record in `records` must share one `RecordType`, equal to
/// the RRSIGs' `type_covered`. Callers pass a single, homogeneous RRset. The
/// production fetcher (`UpstreamChainFetcher::fetch`) filters by `record_type()`
/// before building a [`FetchedRrset`], so this holds on the live path; for any
/// future caller that assembles a `FetchedRrset` by hand, `verify_rrset` step 4 is
/// the safety net — a mixed-type or empty RRset yields `Bogus(TypeCoveredMismatch)`
/// rather than being hashed against a crafted signature.
fn verify_keyset(
    records: &[Record],
    rrsigs: &[RRSIG],
    name: &Name,
    keys: &[DNSKEY],
    now: u32,
    verifications: &mut u32,
    caps: &DnssecConfig,
) -> Result<Verdict, ChainResult> {
    let mut bogus: Option<BogusReason> = None;
    let mut insecure: Option<InsecureReason> = None;
    // Precompute each key's RFC 4034 App-B tag once (a cheap checksum) instead of
    // recomputing it for every RRSIG — the prefilter was O(keys × sigs) tag
    // computations. A key whose tag cannot be computed can never be named by an
    // RRSIG, so it is dropped here.
    let tagged_keys: Vec<(u16, &DNSKEY)> = keys
        .iter()
        .filter_map(|key| key.calculate_key_tag().ok().map(|tag| (tag, key)))
        .collect();
    for sig in rrsigs {
        for &(tag, key) in &tagged_keys {
            if tag != sig.input().key_tag {
                continue;
            }
            // KeyTrap guard: charge the global verification budget *before* the
            // crypto. Colliding 16-bit key tags let an attacker pass the gate above
            // with many (sig, key) pairs; without this, one RRset could force
            // O(keys × sigs) verifications, and the walk O(that × hops).
            if *verifications >= u32::from(caps.max_signature_verifications) {
                return Err(ChainResult::Indeterminate(
                    Indeterminate::MaxSignatureVerificationsExceeded,
                ));
            }
            *verifications += 1;
            match verify_rrset(key, sig, name, DNSClass::IN, records, now) {
                Verdict::Secure => return Ok(Verdict::Secure),
                Verdict::Bogus(r) => bogus = Some(r),
                Verdict::Insecure(r) => insecure = Some(r),
            }
        }
    }
    if let Some(r) = bogus {
        return Ok(Verdict::Bogus(r));
    }
    if let Some(r) = insecure {
        return Ok(Verdict::Insecure(r));
    }
    // No RRSIG named a key we hold ⇒ we cannot tie this RRset to the chain.
    Ok(Verdict::Bogus(BogusReason::KeyTagMismatch))
}

/// Fetch chain material, charging the `max_queries` cap first and mapping a
/// transport failure to `Indeterminate(FetchFailed)`. Returns the
/// `Indeterminate` chain result to short-circuit with on either failure.
async fn guarded_fetch(
    fetcher: &dyn ChainFetcher,
    name: &Name,
    rtype: RecordType,
    queries: &mut u32,
    caps: &DnssecConfig,
) -> Result<FetchedRrset, ChainResult> {
    if *queries >= u32::from(caps.max_queries) {
        return Err(ChainResult::Indeterminate(
            Indeterminate::MaxQueriesExceeded,
        ));
    }
    *queries += 1;
    fetcher
        .fetch(name, rtype)
        .await
        .map_err(|_| ChainResult::Indeterminate(Indeterminate::FetchFailed))
}

/// Extract the typed DNSKEYs from a record slice (ignoring other types).
fn extract_dnskeys(records: &[Record]) -> Vec<DNSKEY> {
    records
        .iter()
        .filter_map(|r| match &r.data {
            RData::DNSSEC(DNSSECRData::DNSKEY(k)) => Some(k.clone()),
            _ => None,
        })
        .collect()
}

/// Extract the typed DS records from a record slice (ignoring other types).
fn extract_ds(records: &[Record]) -> Vec<DS> {
    records
        .iter()
        .filter_map(|r| match &r.data {
            RData::DNSSEC(DNSSECRData::DS(ds)) => Some(ds.clone()),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Message;
    use std::collections::HashMap;

    // Real `.` → `org.` → `internetsociety.org.` chain, captured (DO bit set)
    // within one moment so every RRSIG validity window overlaps. `now` is derived
    // from the signatures themselves (see `chain_now`), so expiry never makes
    // these tests flaky — exactly the §4.10-2 vector discipline, extended to a
    // multi-zone chain.
    const ROOT_DNSKEY: &str = "1234818000010004000000010000300001000030000100029bf401080101030803010001acffb409bcc939f831f7a1e5ec88f7a59255ec53040be432027390a4ce896d6f9086f3c5e177fbfe118163aaec7af1462c47945944c4e2c026be5e98bbcded25978272e1e3e079c5094d573f0e83c92f02b32d3513b1550b826929c80dd0f92cac966d17769fd5867b647c3f38029abdc48152eb8f207159ecc5d232c7c1537c79f4b7ac28ff11682f21681bf6d6aba555032bf6f9f036beb2aaa5b3778d6eebfba6bf9ea191be4ab0caea759e2f773a1f9029c73ecb8d5735b9321db085f1b8e2d8038fe2941992548cee0d67dd4547e11dd63af9c9fc1c5466fb684cf009d7197c2cf79e792ab501e6a8a1ca519af2cb9b5f6367e94c0d47502451357be1b5000030000100029bf401080101030803010001af7a8deba49d995a792aefc80263e991efdbc86138a931deb2c65d5682eab5d3b03738e3dfdc89d96da64c86c0224d9ce02514d285da3068b19054e5e787b2969058e98e12566c8c808c40c0b769e1db1a24a1bd9b31e303184a31fc7bb56b85bbba8abc02cd5040a444a36d47695969849e16ad856bb58e8fac8855224400319bdab224d83fc0e66aab32ff74bfeaf0f91c454e6850a1295207bbd4cdde8f6ffb08faa9755c2e3284efa01f99393e18786cb132f1e66ebc6517318e1ce8a3b7337ebb54d035ab57d9706ecd9350d4afacd825e43c8668eece89819caf6817af62dc4fbd82f0e33f6647b2b6bda175f14607f59f4635451e6b27df282ef73d87000030000100029bf401080100030803010001be5d0d87dfa60009f155062f042d5973e5416b2320526d08cd34fd768a53ef259fea1f6a1dead8ac44223bf3420fa7a9dc518fef1e9ad3e77b59ad61c6c558fe10f44f839e23892cad3d474e45bb3bc66eb1bb0c37510d45ff71e745755ecef29144018a49a98351f4109320057def70ced9b89ab8a480df56fb23694aff0a31a11d6d7f972a27848c6c952f8ae1e2700128522d804ecc25a193567794f9b619841599f1171ec3e5480a098ee87e54bbf8653b74d27012d9859d66151131cdd241d7573e9a82ea2e680669ef4e985cd22847f893810866b11ed75fec0bd19f103362f1408c94eaf459d3a232b8930644c8b0912b861256ee9b206dd762596eb500002e000100029bf40113003008000002a3006a29fa806a0e4b004f66003eb63aef891c6aa08533d04c2e51d08c1a6834df2a30af63d3fec27ec4ac17dfc21384c03bc1c1df400af2f1c2ab80788e20f8383a3dfd8eb01f48b8d4430d191e58baddb7fcdeec2cf381d042d094535b7595071c082aa88794db2c0d56fda210a29df0b7f456699235921050261075ecb2ab6c63e716768c0b5db2def27eb62958808a5a2dddde98a2375e2bd9ed6e89f34fea1f222fb7fa70032c1e9357dafc378ab72207826c9d7674584679a743825e68146d759c0e886a2de996daf752aa5ae00f8297842aef9eac3bd27a698ec475719f22ac9ee8345e3b07a2a67aedee0a406309744bb7907ed1de6e266bad02f9e2caa297277e7715d77ce7d2772f00002904d0000080000000";
    const ORG_DS: &str = "123481800001000200000001036f726700002b0001c00c002b000100000f0e0024695e08024fede294c53f438a158c41d39489cd78a86beb0d8a0aeaff14745c0d16e1de32c00c002e000100000f0e0113002b0801000151806a2106506a0fd4c0d479000ee24aeff015289131f7ea9f51f73c998e08828382a7233c6abb7b64b827aa86d27854568abd6e0428f3dbf79facebcb8ca0fc70b1f84bb9d2125f9e3d704a4ed0e10f6002b2ec806f289b2e824272715a00aa7f4a5e07a283c9aba0aa9bad98df875b4b6abf240ec9ee7d71e1bd8f51ea7f5fd1d22e1a38d93d8a792765cdf7527868dfa393f4cb42c1c497bd431d31fceea82331a859139a2af9f177bc09d4bfd4ff7a00fe02817864328dc8d9e4863cb04aa7c69edf9524157a27a5d3a3836def2950c7751ad5aa5e406079bc718a358c7785d1b5533209571e435e4da79d375733c8271d8b0a3c2e3703cb24b126d008dd34322b03df4cb1b0feecd93b0e00002904d0000080000000";
    const ORG_DNSKEY: &str = "123481800001000400000001036f72670000300001c00c003000010000086400880100030803010001d737ce87b2f7a67133bcf13a4c21b78ea38fa07bf278dbd919161afcaeafca081b1e1e01bcfe237f0dd929f7c695dea6c5e19853935224f6034b52c9eeb255a0b797304b771bf466d28f38b0e039276e90c673d7901a3937e9a3294e4d78ce1f9c26ff722e1b68b735bc680b405221ef6cd6a4da982778ee42d0db2bfd8031f1c00c003000010000086401080101030803010001ec5927fd707f2342c4d3eb4d98b3686ed49626c684ff80ca8811e9baa3a6d2b0784804e200fc1b1450264b7e167e690a836ace69b56671282aabe6f77b8e62d6ca918403187f96ebd27ae8c48aa602324be993ff889a5e7fa5a5be68f7d97fb1fee51cc6bdef93bf7ea37a68f5259788546cdd93d4b1efe87cd0b900ad351240f231c6c17e6ad0d32687667ec9a1ba07d70849eae37bd9792fe203db2749eb35eab98b5ea0852f5f6c73aa75c27473d2bc3fa82fa47fc1e5beb73b5d152d61a24ff5cf7b67e4dce671a38b965f675e7882a331292c51063ecc32beda615a0098848f1b053aa152c2307c8c0b481413120da8097eec4b909b5e0e383aac21216fc00c003000010000086400880100030803010001b1ac5fd2e78ca6b3eeb87e59ae4826bbdbaaddc35318f337942d3f207026d95c135d8e35863309bcd365a5c46223c90a6305467dfd6c3a874eb952ae11c7a9e5f177ae31ce9c0f6eeff1b331fcad3e32683cc254f38de0d92ef8188669ea9b7f30d78e82e8e6961dd390673941d67f397df95bd00859ec2306924eee737ec62bc00c002e00010000086401170030080100000e106a258d3e6a09cfae695e036f726700831ed0c4fcc15125bfdd584858c72a88c4f837d8c15e7e276976417a3de45fe6ed14418035accd04081facdc0a0091bde55164a4e820514b49857155c2163b7ab07bf6d7d41003cd7971154bbf345f10ef04e9aa88e861c727c63d3f0ac2c484916360a1efa3ebef5cead2092b7c61ed8ebfccb40a79bce9d0082892d097cbd5541256ccaa09c96117e45ccdbd4d45b46145f902a81d660441f6e28ce6ec2cc83e773508947a7892cd2b1c91f8de73ed13f4199e7f3c097cb979c97bd97a34cfd0011647037c2c23da4a865960aa0f55a1d7a1c3817f0fb2f1bb7d6380eb5da578898fb0aebd5a9383ac5a1b76d6013a1a20832c53ea46ae5c6d35a06e6cc50300002904d0000080000000";
    const ISOC_DS: &str = "1234818000010002000000010f696e7465726e6574736f6369657479036f726700002b0001c00c002b000100000b54002409430d0239fdc63793db261f978f59086a5d1d17bde3b5a32e2a4d55c8ece6027d969c33c00c002e000100000b540097002b080200000e106a258d3e6a09cfae9b04036f7267001177fc511bc55c6cbab432c69108d64d524ed9ecf9924835fd2d5d8d70b86176119c7eacdb9de2d46dfc5dd7317924bd92ffca81600a8cf666fe95f2ee1556bb79dde72ac024ddfa2b64d91bfff590d16c318ae66b0ffa2d9c49c5ac0ed9d203ca2cf668e5e5b2a91e1b431b7b46d6f9d9e1767ce2cfed47ca4ca14804dc18d700002904d0000080000000";
    const ISOC_DNSKEY: &str = "1234818000010003000000010f696e7465726e6574736f6369657479036f72670000300001c00c0030000100000b5700440101030d99db2cc14cabdc33d6d77da63a2f15f71112584f234e8d1dc428e39e8a4a97e1aa271a555dc90701e17e2a4c4b6f120b7c32d44f4ac02bd894cf2d4be7778a19c00c0030000100000b5700440100030da09311112cf9138818cd2feae970ebbd4d6a30f6088c25b325a39abbc5cd1197aa098283e5aaf421177c2aa5d714992a9957d1bcc18f98cd71f1f1806b65e148c00c002e000100000b57006700300d0200000e106a5e405c6a0dd4dc09430f696e7465726e6574736f6369657479036f7267002ee6e88422f5e124a5ff9ac29ea231e254ee8ee2aefd30b30da49eb669ba8066e3dfa82834585812b031b7a39028bdd8d1aac699addaeb6295ec27e7b2a7a0bb00002904d0000080000000";

    fn answers(hex: &str) -> Vec<Record> {
        Message::from_vec(&hex::decode(hex).unwrap())
            .unwrap()
            .answers
            .to_vec()
    }

    fn records_of(ans: &[Record], rt: RecordType) -> Vec<Record> {
        ans.iter()
            .filter(|r| r.record_type() == rt)
            .cloned()
            .collect()
    }

    fn rrsigs_over(ans: &[Record], rt: RecordType) -> Vec<RRSIG> {
        ans.iter()
            .filter_map(|r| match &r.data {
                RData::DNSSEC(DNSSECRData::RRSIG(s)) if s.input().type_covered == rt => {
                    Some(s.clone())
                }
                _ => None,
            })
            .collect()
    }

    fn set_of(hex: &str, rt: RecordType) -> FetchedRrset {
        let ans = answers(hex);
        FetchedRrset {
            records: records_of(&ans, rt),
            rrsigs: rrsigs_over(&ans, rt),
            ..Default::default()
        }
    }

    fn name(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    /// `now` = the latest inception across all the chain's RRSIGs. Every RRSIG was
    /// captured while valid, so this instant lies inside *every* validity window
    /// (max-inception ≤ capture-time ≤ min-expiration), making the verdict
    /// deterministic and immune to the signatures eventually expiring.
    fn chain_now() -> u32 {
        let mut max = 0u32;
        for hex in [ROOT_DNSKEY, ORG_DS, ORG_DNSKEY, ISOC_DS, ISOC_DNSKEY] {
            let ans = answers(hex);
            for r in &ans {
                if let RData::DNSSEC(DNSSECRData::RRSIG(s)) = &r.data {
                    max = max.max(s.input().sig_inception.get());
                }
            }
        }
        max
    }

    /// A `ChainFetcher` backed by a `(name, rtype) -> FetchedRrset` map. Missing
    /// keys return `Transport` errors; insert an empty `FetchedRrset` to model a
    /// NODATA / absent RRset.
    #[derive(Default)]
    struct CannedFetcher {
        map: HashMap<(Name, RecordType), FetchedRrset>,
        err: HashMap<(Name, RecordType), FetchError>,
    }

    impl CannedFetcher {
        fn with(mut self, n: &str, rt: RecordType, set: FetchedRrset) -> Self {
            self.map.insert((name(n), rt), set);
            self
        }
        fn fail(mut self, n: &str, rt: RecordType, e: FetchError) -> Self {
            self.err.insert((name(n), rt), e);
            self
        }
    }

    #[async_trait]
    impl ChainFetcher for CannedFetcher {
        async fn fetch(&self, n: &Name, rt: RecordType) -> Result<FetchedRrset, FetchError> {
            if let Some(e) = self.err.get(&(n.clone(), rt)) {
                return Err(e.clone());
            }
            self.map
                .get(&(n.clone(), rt))
                .cloned()
                .ok_or_else(|| FetchError::Transport(format!("no canned {rt} for {n}")))
        }
    }

    /// The full, valid 3-cut chain.
    fn good_chain() -> CannedFetcher {
        CannedFetcher::default()
            .with(
                ".",
                RecordType::DNSKEY,
                set_of(ROOT_DNSKEY, RecordType::DNSKEY),
            )
            .with("org.", RecordType::DS, set_of(ORG_DS, RecordType::DS))
            .with(
                "org.",
                RecordType::DNSKEY,
                set_of(ORG_DNSKEY, RecordType::DNSKEY),
            )
            .with(
                "internetsociety.org.",
                RecordType::DS,
                set_of(ISOC_DS, RecordType::DS),
            )
            .with(
                "internetsociety.org.",
                RecordType::DNSKEY,
                set_of(ISOC_DNSKEY, RecordType::DNSKEY),
            )
    }

    #[tokio::test]
    async fn secure_chain_root_to_isoc() {
        let r = validate_chain(
            &good_chain(),
            &RootTrustAnchors::iana(),
            &name("internetsociety.org."),
            None,
            chain_now(),
            &DnssecConfig::default(),
        )
        .await;
        assert_eq!(r, ChainResult::Secure, "valid 3-cut chain must be Secure");
    }

    #[tokio::test]
    async fn secure_chain_root_to_org() {
        // A shorter chain (one delegation) terminates Secure at the TLD apex.
        let r = validate_chain(
            &good_chain(),
            &RootTrustAnchors::iana(),
            &name("org."),
            None,
            chain_now(),
            &DnssecConfig::default(),
        )
        .await;
        assert_eq!(r, ChainResult::Secure);
    }

    #[tokio::test]
    async fn no_anchor_match_is_indeterminate() {
        // Serve org's DNSKEYs as the "root" set: none is committed to by an
        // embedded IANA anchor.
        let fetcher = CannedFetcher::default().with(
            ".",
            RecordType::DNSKEY,
            set_of(ORG_DNSKEY, RecordType::DNSKEY),
        );
        let r = validate_chain(
            &fetcher,
            &RootTrustAnchors::iana(),
            &name("org."),
            None,
            chain_now(),
            &DnssecConfig::default(),
        )
        .await;
        assert_eq!(r, ChainResult::Indeterminate(Indeterminate::NoAnchorMatch));
    }

    #[tokio::test]
    async fn broken_hop_signature_is_bogus() {
        // Flip a byte inside the RRSIG signature blob (the last answer record,
        // just before the trailing 11-byte OPT). The DNSKEYs and the RRSIG key
        // tag are untouched, so the key-tag gate passes and the crypto check is
        // what fails — Bogus(SignatureInvalid), not KeyTagMismatch.
        let mut raw = hex::decode(ROOT_DNSKEY).unwrap();
        let n = raw.len();
        raw[n - 40] ^= 0x01;
        let mutated = Message::from_vec(&raw).unwrap().answers.to_vec();
        let fetcher = CannedFetcher::default().with(
            ".",
            RecordType::DNSKEY,
            FetchedRrset {
                records: records_of(&mutated, RecordType::DNSKEY),
                rrsigs: rrsigs_over(&mutated, RecordType::DNSKEY),
                ..Default::default()
            },
        );
        let r = validate_chain(
            &fetcher,
            &RootTrustAnchors::iana(),
            &name("org."),
            None,
            chain_now(),
            &DnssecConfig::default(),
        )
        .await;
        assert_eq!(
            r,
            ChainResult::Bogus(ChainBogus::Hop(BogusReason::SignatureInvalid))
        );
    }

    #[tokio::test]
    async fn no_ds_delegation_needs_denial_proof() {
        // Root authenticates, but org's DS RRset is absent (empty) *and* the
        // response carried no authority section — no denial proof was offered, so
        // validation cannot be completed. (A proof that is offered but fails is
        // `Bogus`; see the §4.10-3b `resolve_no_ds` tests below.)
        let fetcher = good_chain().with("org.", RecordType::DS, FetchedRrset::default());
        let r = validate_chain(
            &fetcher,
            &RootTrustAnchors::iana(),
            &name("org."),
            None,
            chain_now(),
            &DnssecConfig::default(),
        )
        .await;
        assert_eq!(
            r,
            ChainResult::Indeterminate(Indeterminate::DenialProofRequired)
        );
    }

    #[tokio::test]
    async fn ds_covers_no_key_is_bogus() {
        // A valid org DS, but the child DNSKEY RRset is unrelated (root's keys),
        // so no DNSKEY is the one the DS commits to.
        let fetcher = good_chain().with(
            "org.",
            RecordType::DNSKEY,
            set_of(ROOT_DNSKEY, RecordType::DNSKEY),
        );
        let r = validate_chain(
            &fetcher,
            &RootTrustAnchors::iana(),
            &name("org."),
            None,
            chain_now(),
            &DnssecConfig::default(),
        )
        .await;
        assert_eq!(r, ChainResult::Bogus(ChainBogus::DsCoversNoKey));
    }

    #[tokio::test]
    async fn dnskey_missing_under_signed_delegation_is_bogus() {
        let fetcher = good_chain().with("org.", RecordType::DNSKEY, FetchedRrset::default());
        let r = validate_chain(
            &fetcher,
            &RootTrustAnchors::iana(),
            &name("org."),
            None,
            chain_now(),
            &DnssecConfig::default(),
        )
        .await;
        assert_eq!(r, ChainResult::Bogus(ChainBogus::DnskeyMissing));
    }

    #[tokio::test]
    async fn fetch_failure_is_indeterminate() {
        let fetcher = good_chain().fail("org.", RecordType::DS, FetchError::ServerFailure);
        let r = validate_chain(
            &fetcher,
            &RootTrustAnchors::iana(),
            &name("org."),
            None,
            chain_now(),
            &DnssecConfig::default(),
        )
        .await;
        assert_eq!(r, ChainResult::Indeterminate(Indeterminate::FetchFailed));
    }

    #[tokio::test]
    async fn max_chain_depth_cap_trips() {
        // depth 2 (org, internetsociety.org) exceeds a cap of 1.
        let caps = DnssecConfig {
            max_chain_depth: 1,
            ..DnssecConfig::default()
        };
        let r = validate_chain(
            &good_chain(),
            &RootTrustAnchors::iana(),
            &name("internetsociety.org."),
            None,
            chain_now(),
            &caps,
        )
        .await;
        assert_eq!(
            r,
            ChainResult::Indeterminate(Indeterminate::MaxChainDepthExceeded)
        );
    }

    #[tokio::test]
    async fn max_queries_cap_trips() {
        // The 3-cut walk needs 5 fetches; cap at 2 trips before the chain
        // completes. (Root DNSKEY = 1, org DS = 2, org DNSKEY = 3 > 2.)
        let caps = DnssecConfig {
            max_queries: 2,
            ..DnssecConfig::default()
        };
        let r = validate_chain(
            &good_chain(),
            &RootTrustAnchors::iana(),
            &name("internetsociety.org."),
            None,
            chain_now(),
            &caps,
        )
        .await;
        assert_eq!(
            r,
            ChainResult::Indeterminate(Indeterminate::MaxQueriesExceeded)
        );
    }

    // ---- §4.10-3b: authenticated denial of existence (NSEC no-DS) ----------
    //
    // Real NSEC-no-DS vectors are rare (most delegations use NSEC3), and the
    // spoof cases (a *signed* NSEC with the wrong bits) are unservable by any real
    // zone. So these synthesise the parent's denial proof in-test: a throwaway
    // P-256 zone key signs an NSEC with a controlled type bitmap. Fully hermetic
    // and deterministic — `now` is injected inside a fixed validity window.

    use crate::dnssec::trust_anchor::RootTrustAnchor;
    use data_encoding::BASE32_DNSSEC;
    use hickory_proto::dnssec::crypto::EcdsaSigningKey;
    use hickory_proto::dnssec::rdata::NSEC;
    use hickory_proto::dnssec::{
        Algorithm, DigestType, DnssecSigner, Nsec3HashAlgorithm, SigningKey, TBS,
    };
    use hickory_proto::rr::rdata::A;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    const INC: u32 = 1_700_000_000;
    const EXP: u32 = 2_000_000_000;
    const NOW: u32 = 1_800_000_000; // inside [INC, EXP]

    /// 0.26 removed `RRSIG::new` (getters/setters gave way to public fields).
    /// This shim preserves the helpers' positional construction by assembling a
    /// `SigInput` (u32 timestamps wrapped as `SerialNumber`) and pairing it with
    /// the signature via `RRSIG::from_sig`.
    #[allow(clippy::too_many_arguments)]
    fn rrsig_new(
        type_covered: RecordType,
        algorithm: Algorithm,
        num_labels: u8,
        original_ttl: u32,
        sig_expiration: u32,
        sig_inception: u32,
        key_tag: u16,
        signer_name: Name,
        sig: Vec<u8>,
    ) -> RRSIG {
        use hickory_proto::dnssec::rdata::SigInput;
        use hickory_proto::rr::SerialNumber;
        RRSIG::from_sig(
            SigInput {
                type_covered,
                algorithm,
                num_labels,
                original_ttl,
                sig_expiration: SerialNumber::new(sig_expiration),
                sig_inception: SerialNumber::new(sig_inception),
                key_tag,
                signer_name,
            },
            sig,
        )
    }

    /// 0.26 renamed `TBS::from_sig` → `TBS::from_input`, which takes the
    /// `&SigInput` rather than the whole `&RRSIG`. Shim keeps the call sites.
    fn tbs_from_sig<'a>(
        name: &Name,
        dns_class: DNSClass,
        sig: &RRSIG,
        records: impl Iterator<Item = &'a Record>,
    ) -> Result<TBS, hickory_proto::ProtoError> {
        TBS::from_input(name, dns_class, sig.input(), records)
    }

    /// A throwaway P-256 zone key for synthesising *authenticated* NSEC proofs.
    /// Returns the signer (holding the private key) plus the matching DNSKEY to
    /// seed the chain's parent-key set.
    fn test_zone_key(signer_name: &Name) -> (DnssecSigner, DNSKEY) {
        let der = EcdsaSigningKey::generate_pkcs8(Algorithm::ECDSAP256SHA256).unwrap();
        let key = EcdsaSigningKey::from_pkcs8(&der, Algorithm::ECDSAP256SHA256).unwrap();
        let dnskey = DNSKEY::from_key(&key.to_public_key().unwrap());
        let signer = DnssecSigner::new(
            dnskey.clone(),
            Box::new(key),
            signer_name.clone(),
            Duration::from_secs(3600),
        );
        (signer, dnskey)
    }

    /// Build an `(NSEC, RRSIG)` record pair at `owner` carrying exactly `types`,
    /// signed by `signer`. `TBS::from_sig` derives the to-be-signed bytes from the
    /// exact RRSIG parameters, so the verifier reconstructs an identical TBS.
    fn signed_nsec(signer: &DnssecSigner, owner: &Name, types: &[RecordType]) -> (Record, Record) {
        const TTL: u32 = 3600;
        let nsec = NSEC::new(name("zzz.example."), types.iter().copied());
        let nsec_record =
            Record::from_rdata(owner.clone(), TTL, RData::DNSSEC(DNSSECRData::NSEC(nsec)));
        let key_tag = signer.calculate_key_tag().unwrap();
        let mk_rrsig = |sig: Vec<u8>| {
            rrsig_new(
                RecordType::NSEC,
                Algorithm::ECDSAP256SHA256,
                owner.num_labels(),
                TTL,
                EXP,
                INC,
                key_tag,
                signer.signer_name().clone(),
                sig,
            )
        };
        let tbs = tbs_from_sig(
            owner,
            DNSClass::IN,
            &mk_rrsig(Vec::new()),
            std::iter::once(&nsec_record),
        )
        .unwrap();
        let sig = signer.sign(&tbs).unwrap();
        let rrsig_record = Record::from_rdata(
            owner.clone(),
            TTL,
            RData::DNSSEC(DNSSECRData::RRSIG(mk_rrsig(sig))),
        );
        (nsec_record, rrsig_record)
    }

    /// Flip a byte inside an RRSIG record's signature blob, keeping every other
    /// field (so the key-tag gate passes and the crypto check is what fails).
    fn corrupt_sig(rec: &Record) -> Record {
        let RData::DNSSEC(DNSSECRData::RRSIG(s)) = &rec.data else {
            panic!("not an RRSIG record");
        };
        let mut sig = s.sig().to_vec();
        sig[0] ^= 0x01;
        // 0.26 removed RRSIG::new; rebuild from the (unchanged) SigInput + the
        // corrupted signature bytes via from_sig.
        let bad = RRSIG::from_sig(s.input().clone(), sig);
        Record::from_rdata(
            rec.name.clone(),
            rec.ttl,
            RData::DNSSEC(DNSSECRData::RRSIG(bad)),
        )
    }

    // Delegation tested throughout: parent `.` proves no DS at child `org.`.
    fn delegation() -> (Name, Name) {
        (name("."), name("org."))
    }

    #[test]
    fn no_ds_authenticated_unsigned_delegation_is_insecure() {
        // The real case: a parent-side zone cut, DS-clear ∧ NS-set ∧ SOA-clear.
        let (parent, child) = delegation();
        let (signer, dnskey) = test_zone_key(&parent);
        let (nsec, rrsig) = signed_nsec(
            &signer,
            &child,
            &[RecordType::NS, RecordType::RRSIG, RecordType::NSEC],
        );
        let r = resolve_no_ds(
            &child,
            &[nsec, rrsig],
            &[dnskey],
            NOW,
            &mut 0,
            &DnssecConfig::default(),
        );
        assert_eq!(r, ChainResult::Insecure(InsecureReason::UnsignedDelegation));
    }

    #[test]
    fn no_ds_authenticated_nsec_asserting_ds_is_bogus() {
        // Authenticated, but the bitmap includes DS — contradicts a no-DS claim.
        let (parent, child) = delegation();
        let (signer, dnskey) = test_zone_key(&parent);
        let (nsec, rrsig) = signed_nsec(
            &signer,
            &child,
            &[
                RecordType::NS,
                RecordType::DS,
                RecordType::RRSIG,
                RecordType::NSEC,
            ],
        );
        let r = resolve_no_ds(
            &child,
            &[nsec, rrsig],
            &[dnskey],
            NOW,
            &mut 0,
            &DnssecConfig::default(),
        );
        assert_eq!(r, ChainResult::Bogus(ChainBogus::DenialProofInvalid));
    }

    #[test]
    fn no_ds_authenticated_nsec_without_ns_is_bogus() {
        // DS-clear but NS-clear: an empty non-terminal, not a delegation. "No DS"
        // here proves nothing about a child zone's signing status.
        let (parent, child) = delegation();
        let (signer, dnskey) = test_zone_key(&parent);
        let (nsec, rrsig) = signed_nsec(&signer, &child, &[RecordType::RRSIG, RecordType::NSEC]);
        let r = resolve_no_ds(
            &child,
            &[nsec, rrsig],
            &[dnskey],
            NOW,
            &mut 0,
            &DnssecConfig::default(),
        );
        assert_eq!(r, ChainResult::Bogus(ChainBogus::DenialProofInvalid));
    }

    #[test]
    fn no_ds_authenticated_apex_nsec_with_soa_is_bogus() {
        // SOA-set: the child's own apex NSEC, not the parent's delegation record.
        let (parent, child) = delegation();
        let (signer, dnskey) = test_zone_key(&parent);
        let (nsec, rrsig) = signed_nsec(
            &signer,
            &child,
            &[
                RecordType::SOA,
                RecordType::NS,
                RecordType::RRSIG,
                RecordType::NSEC,
            ],
        );
        let r = resolve_no_ds(
            &child,
            &[nsec, rrsig],
            &[dnskey],
            NOW,
            &mut 0,
            &DnssecConfig::default(),
        );
        assert_eq!(r, ChainResult::Bogus(ChainBogus::DenialProofInvalid));
    }

    #[test]
    fn no_ds_unsigned_nsec_is_bogus_not_insecure() {
        // The central security property: a matching NSEC with no signature proves
        // nothing — it must be Bogus, never Insecure(UnsignedDelegation).
        let (parent, child) = delegation();
        let (signer, dnskey) = test_zone_key(&parent);
        let (nsec, _rrsig) = signed_nsec(
            &signer,
            &child,
            &[RecordType::NS, RecordType::RRSIG, RecordType::NSEC],
        );
        // Authority carries the NSEC but NOT its RRSIG.
        let r = resolve_no_ds(
            &child,
            &[nsec],
            &[dnskey],
            NOW,
            &mut 0,
            &DnssecConfig::default(),
        );
        assert_eq!(
            r,
            ChainResult::Bogus(ChainBogus::Hop(BogusReason::KeyTagMismatch))
        );
    }

    #[test]
    fn no_ds_forged_nsec_is_bogus_not_insecure() {
        // A valid-looking NSEC whose signature byte is flipped: the key-tag gate
        // passes, the crypto check fails ⇒ Bogus(SignatureInvalid), never Insecure.
        let (parent, child) = delegation();
        let (signer, dnskey) = test_zone_key(&parent);
        let (nsec, rrsig) = signed_nsec(
            &signer,
            &child,
            &[RecordType::NS, RecordType::RRSIG, RecordType::NSEC],
        );
        let r = resolve_no_ds(
            &child,
            &[nsec, corrupt_sig(&rrsig)],
            &[dnskey],
            NOW,
            &mut 0,
            &DnssecConfig::default(),
        );
        assert_eq!(
            r,
            ChainResult::Bogus(ChainBogus::Hop(BogusReason::SignatureInvalid))
        );
    }

    #[test]
    fn no_ds_out_of_scope_algorithm_nsec_is_insecure_not_unsigned() {
        // The NSEC bitmap looks like a clean unsigned delegation, but its RRSIG
        // uses an out-of-scope algorithm: we cannot assert security, so the
        // verdict is Insecure(OutOfScopeAlgorithm) — NOT an UnsignedDelegation
        // claim synthesised from a signature we never checked.
        let (parent, child) = delegation();
        let (_signer, dnskey) = test_zone_key(&parent);
        let nsec = Record::from_rdata(
            child.clone(),
            3600,
            RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                name("zzz.example."),
                [RecordType::NS, RecordType::RRSIG, RecordType::NSEC],
            ))),
        );
        // No real signature needed: verify_rrset short-circuits on the
        // out-of-scope algorithm before any crypto. The key tag must match a
        // parent key so the RRSIG is actually evaluated.
        let rrsig = Record::from_rdata(
            child.clone(),
            3600,
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig_new(
                RecordType::NSEC,
                Algorithm::RSASHA512,
                child.num_labels(),
                3600,
                EXP,
                INC,
                dnskey.calculate_key_tag().unwrap(),
                parent.clone(),
                vec![0u8; 256],
            ))),
        );
        let r = resolve_no_ds(
            &child,
            &[nsec, rrsig],
            &[dnskey],
            NOW,
            &mut 0,
            &DnssecConfig::default(),
        );
        assert_eq!(
            r,
            ChainResult::Insecure(InsecureReason::OutOfScopeAlgorithm)
        );
    }

    #[test]
    fn no_ds_no_matching_nsec_is_bogus() {
        // Authority carries an authenticated NSEC for a *different* owner: nothing
        // proves no-DS at `child`.
        let (parent, child) = delegation();
        let (signer, dnskey) = test_zone_key(&parent);
        let (nsec, rrsig) = signed_nsec(
            &signer,
            &name("sibling."),
            &[RecordType::NS, RecordType::RRSIG, RecordType::NSEC],
        );
        let r = resolve_no_ds(
            &child,
            &[nsec, rrsig],
            &[dnskey],
            NOW,
            &mut 0,
            &DnssecConfig::default(),
        );
        assert_eq!(r, ChainResult::Bogus(ChainBogus::DenialProofMissing));
    }

    #[test]
    fn no_ds_empty_authority_is_indeterminate() {
        // No proof material at all ⇒ validation cannot be completed (distinct from
        // a proof that was offered and failed).
        let (_parent, child) = delegation();
        let r = resolve_no_ds(&child, &[], &[], NOW, &mut 0, &DnssecConfig::default());
        assert_eq!(
            r,
            ChainResult::Indeterminate(Indeterminate::DenialProofRequired)
        );
    }

    // ---- §4.10-3c: NSEC3 authenticated denial of existence (NSEC3 no-DS) ----
    //
    // Same hermetic, synthetic-signing strategy as the §4.10-3b NSEC tests: a
    // throwaway P-256 zone key signs an NSEC3 with a controlled owner hash, opt-out
    // flag, iteration count, and type bitmap. Real zones never serve the spoof
    // cases (a *signed* NSEC3 asserting a DS, an out-of-scope NSEC3, …).

    const NSEC3_SALT: &[u8] = b"\xde\xad";
    const NSEC3_ITERS: u16 = 1;

    /// hash(name) with the fixture salt — the raw NSEC3 owner hash.
    fn nsec3_hash(name_: &Name, iters: u16) -> Vec<u8> {
        Nsec3HashAlgorithm::SHA1
            .hash(NSEC3_SALT, name_, iters)
            .unwrap()
            .as_ref()
            .to_vec()
    }

    /// The hashed-owner name `<base32hex(hash)>.<zone>` a parent zone serves.
    fn nsec3_owner(hash: &[u8], zone: &Name) -> Name {
        Name::from_ascii(BASE32_DNSSEC.encode(hash))
            .unwrap()
            .append_name(zone)
            .unwrap()
    }

    /// Build a signed `(NSEC3, RRSIG)` pair at `owner` with the given opt-out flag,
    /// iterations, next-hash, and bitmap. `TBS::from_sig` derives the exact TBS the
    /// verifier reconstructs (mirrors `signed_nsec`).
    fn signed_nsec3(
        signer: &DnssecSigner,
        owner: &Name,
        opt_out: bool,
        iterations: u16,
        next_hash: Vec<u8>,
        types: &[RecordType],
    ) -> (Record, Record) {
        const TTL: u32 = 3600;
        let nsec3 = NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            opt_out,
            iterations,
            NSEC3_SALT.to_vec(),
            next_hash,
            types.iter().copied(),
        );
        let nsec3_record =
            Record::from_rdata(owner.clone(), TTL, RData::DNSSEC(DNSSECRData::NSEC3(nsec3)));
        let key_tag = signer.calculate_key_tag().unwrap();
        let mk_rrsig = |sig: Vec<u8>| {
            rrsig_new(
                RecordType::NSEC3,
                Algorithm::ECDSAP256SHA256,
                owner.num_labels(),
                TTL,
                EXP,
                INC,
                key_tag,
                signer.signer_name().clone(),
                sig,
            )
        };
        let tbs = tbs_from_sig(
            owner,
            DNSClass::IN,
            &mk_rrsig(Vec::new()),
            std::iter::once(&nsec3_record),
        )
        .unwrap();
        let sig = signer.sign(&tbs).unwrap();
        let rrsig_record = Record::from_rdata(
            owner.clone(),
            TTL,
            RData::DNSSEC(DNSSECRData::RRSIG(mk_rrsig(sig))),
        );
        (nsec3_record, rrsig_record)
    }

    #[test]
    fn no_ds_nsec3_matching_unsigned_delegation_is_insecure() {
        // The real case: a matching NSEC3 with NS-set ∧ DS-clear ∧ SOA-clear.
        let (parent, child) = delegation();
        let (signer, dnskey) = test_zone_key(&parent);
        let owner = nsec3_owner(&nsec3_hash(&child, NSEC3_ITERS), &parent);
        let (nsec3, rrsig) = signed_nsec3(
            &signer,
            &owner,
            false,
            NSEC3_ITERS,
            vec![0xff; 20],
            &[RecordType::NS, RecordType::RRSIG],
        );
        let r = resolve_no_ds(
            &child,
            &[nsec3, rrsig],
            &[dnskey],
            NOW,
            &mut 0,
            &DnssecConfig::default(),
        );
        assert_eq!(r, ChainResult::Insecure(InsecureReason::UnsignedDelegation));
    }

    #[test]
    fn no_ds_nsec3_opt_out_covering_is_insecure() {
        // No matching NSEC3, but an opt-out NSEC3 covers hash(child) — RFC 5155 §6.
        let (parent, child) = delegation();
        let (signer, dnskey) = test_zone_key(&parent);
        let target = nsec3_hash(&child, NSEC3_ITERS);
        assert!(target != vec![0u8; 20] && target != vec![0xffu8; 20]);
        let owner = nsec3_owner(&[0u8; 20], &parent); // owner hash = min ≠ target
        let (nsec3, rrsig) = signed_nsec3(
            &signer,
            &owner,
            true,
            NSEC3_ITERS,
            vec![0xff; 20],
            &[RecordType::RRSIG],
        );
        let r = resolve_no_ds(
            &child,
            &[nsec3, rrsig],
            &[dnskey],
            NOW,
            &mut 0,
            &DnssecConfig::default(),
        );
        assert_eq!(r, ChainResult::Insecure(InsecureReason::UnsignedDelegation));
    }

    #[test]
    fn no_ds_nsec3_asserting_ds_is_bogus() {
        // Authenticated matching NSEC3 whose bitmap includes DS — contradicts no-DS.
        let (parent, child) = delegation();
        let (signer, dnskey) = test_zone_key(&parent);
        let owner = nsec3_owner(&nsec3_hash(&child, NSEC3_ITERS), &parent);
        let (nsec3, rrsig) = signed_nsec3(
            &signer,
            &owner,
            false,
            NSEC3_ITERS,
            vec![0xff; 20],
            &[RecordType::NS, RecordType::DS, RecordType::RRSIG],
        );
        let r = resolve_no_ds(
            &child,
            &[nsec3, rrsig],
            &[dnskey],
            NOW,
            &mut 0,
            &DnssecConfig::default(),
        );
        assert_eq!(r, ChainResult::Bogus(ChainBogus::DenialProofInvalid));
    }

    #[test]
    fn no_ds_nsec3_unsigned_is_bogus_not_insecure() {
        // The central security property for NSEC3: a matching NSEC3 with no
        // signature proves nothing — Bogus, never Insecure(UnsignedDelegation).
        let (parent, child) = delegation();
        let (signer, dnskey) = test_zone_key(&parent);
        let owner = nsec3_owner(&nsec3_hash(&child, NSEC3_ITERS), &parent);
        let (nsec3, _rrsig) = signed_nsec3(
            &signer,
            &owner,
            false,
            NSEC3_ITERS,
            vec![0xff; 20],
            &[RecordType::NS, RecordType::RRSIG],
        );
        // Authority carries the NSEC3 but NOT its RRSIG.
        let r = resolve_no_ds(
            &child,
            &[nsec3],
            &[dnskey],
            NOW,
            &mut 0,
            &DnssecConfig::default(),
        );
        assert_eq!(
            r,
            ChainResult::Bogus(ChainBogus::Hop(BogusReason::KeyTagMismatch))
        );
    }

    #[test]
    fn no_ds_nsec3_forged_is_bogus_not_insecure() {
        // Signature byte flipped: key-tag gate passes, crypto fails ⇒ Bogus.
        let (parent, child) = delegation();
        let (signer, dnskey) = test_zone_key(&parent);
        let owner = nsec3_owner(&nsec3_hash(&child, NSEC3_ITERS), &parent);
        let (nsec3, rrsig) = signed_nsec3(
            &signer,
            &owner,
            false,
            NSEC3_ITERS,
            vec![0xff; 20],
            &[RecordType::NS, RecordType::RRSIG],
        );
        let r = resolve_no_ds(
            &child,
            &[nsec3, corrupt_sig(&rrsig)],
            &[dnskey],
            NOW,
            &mut 0,
            &DnssecConfig::default(),
        );
        assert_eq!(
            r,
            ChainResult::Bogus(ChainBogus::Hop(BogusReason::SignatureInvalid))
        );
    }

    #[test]
    fn no_ds_nsec3_out_of_scope_algorithm_is_insecure_not_unsigned() {
        // A clean unsigned-delegation NSEC3 bitmap, but its RRSIG uses an
        // out-of-scope algorithm: cannot assert ⇒ Insecure(OutOfScopeAlgorithm),
        // never an UnsignedDelegation synthesised from an unchecked signature.
        let (parent, child) = delegation();
        let (_signer, dnskey) = test_zone_key(&parent);
        let owner = nsec3_owner(&nsec3_hash(&child, NSEC3_ITERS), &parent);
        let nsec3 = Record::from_rdata(
            owner.clone(),
            3600,
            RData::DNSSEC(DNSSECRData::NSEC3(NSEC3::new(
                Nsec3HashAlgorithm::SHA1,
                false,
                NSEC3_ITERS,
                NSEC3_SALT.to_vec(),
                vec![0xff; 20],
                [RecordType::NS, RecordType::RRSIG],
            ))),
        );
        let rrsig = Record::from_rdata(
            owner.clone(),
            3600,
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig_new(
                RecordType::NSEC3,
                Algorithm::RSASHA512,
                owner.num_labels(),
                3600,
                EXP,
                INC,
                dnskey.calculate_key_tag().unwrap(),
                parent.clone(),
                vec![0u8; 256],
            ))),
        );
        let r = resolve_no_ds(
            &child,
            &[nsec3, rrsig],
            &[dnskey],
            NOW,
            &mut 0,
            &DnssecConfig::default(),
        );
        assert_eq!(
            r,
            ChainResult::Insecure(InsecureReason::OutOfScopeAlgorithm)
        );
    }

    #[test]
    fn no_ds_nsec3_iterations_over_cap_is_indeterminate() {
        // iterations (200) > cap (150) ⇒ refused before hashing. The signed,
        // otherwise-provable proof is pre-empted by the cap. The third DoS cap.
        let (parent, child) = delegation();
        let (signer, dnskey) = test_zone_key(&parent);
        let owner = nsec3_owner(&nsec3_hash(&child, 200), &parent);
        let (nsec3, rrsig) = signed_nsec3(
            &signer,
            &owner,
            false,
            200,
            vec![0xff; 20],
            &[RecordType::NS, RecordType::RRSIG],
        );
        let caps = DnssecConfig {
            max_nsec3_iterations: 150,
            ..DnssecConfig::default()
        };
        let r = resolve_no_ds(&child, &[nsec3, rrsig], &[dnskey], NOW, &mut 0, &caps);
        assert_eq!(
            r,
            ChainResult::Indeterminate(Indeterminate::MaxNsec3IterationsExceeded)
        );
    }

    #[test]
    fn no_ds_nsec3_injected_over_cap_record_does_not_fail_walk() {
        // §4.10-5c: a valid signed NSEC3 no-DS proof PLUS an injected, unauthenticated
        // over-cap NSEC3 (different owner, no RRSIG — an in-path append). The junk must
        // be discarded (it authenticates to nothing), not fail the walk.
        // Pre-fix: the pre-auth scan saw iterations=200 > cap and returned
        // Indeterminate(MaxNsec3IterationsExceeded) — a SERVFAIL of a resolvable domain.
        // Post-fix: same verdict as the clean proof.
        let (parent, child) = delegation();
        let (signer, dnskey) = test_zone_key(&parent);

        // Legitimate signed under-cap matching proof (== the clean case in
        // `no_ds_nsec3_matching_unsigned_delegation_is_insecure`).
        let owner = nsec3_owner(&nsec3_hash(&child, NSEC3_ITERS), &parent);
        let (nsec3, rrsig) = signed_nsec3(
            &signer,
            &owner,
            false,
            NSEC3_ITERS,
            vec![0xff; 20],
            &[RecordType::NS, RecordType::RRSIG],
        );

        // Injected junk: unsigned NSEC3 at a different owner, iterations over cap.
        let junk = Record::from_rdata(
            nsec3_owner(&[0x11u8; 20], &parent),
            3600,
            RData::DNSSEC(DNSSECRData::NSEC3(NSEC3::new(
                Nsec3HashAlgorithm::SHA1,
                false,
                200,
                NSEC3_SALT.to_vec(),
                vec![0xff; 20],
                [RecordType::NS, RecordType::RRSIG],
            ))),
        );

        let caps = DnssecConfig {
            max_nsec3_iterations: 150,
            ..DnssecConfig::default()
        };
        let r = resolve_no_ds(&child, &[nsec3, rrsig, junk], &[dnskey], NOW, &mut 0, &caps);
        assert_eq!(r, ChainResult::Insecure(InsecureReason::UnsignedDelegation));
    }

    #[test]
    fn no_ds_nsec3_covering_without_opt_out_is_bogus() {
        // A covering NSEC3 with opt-out CLEAR proves nothing for no-DS (RFC 5155 §6).
        let (parent, child) = delegation();
        let (signer, dnskey) = test_zone_key(&parent);
        let owner = nsec3_owner(&[0u8; 20], &parent);
        let (nsec3, rrsig) = signed_nsec3(
            &signer,
            &owner,
            false, // opt-out CLEAR
            NSEC3_ITERS,
            vec![0xff; 20],
            &[RecordType::RRSIG],
        );
        let r = resolve_no_ds(
            &child,
            &[nsec3, rrsig],
            &[dnskey],
            NOW,
            &mut 0,
            &DnssecConfig::default(),
        );
        assert_eq!(r, ChainResult::Bogus(ChainBogus::DenialProofMissing));
    }

    #[test]
    fn no_ds_nsec3_non_covering_is_bogus() {
        // An authenticated NSEC3 whose interval excludes hash(child), no match,
        // even with opt-out set: nothing proves no-DS here.
        let (parent, child) = delegation();
        let (signer, dnskey) = test_zone_key(&parent);
        let target = nsec3_hash(&child, NSEC3_ITERS);
        let (owner_hash, next_hash) = if target[0] < 0x80 {
            (vec![0x80u8; 20], vec![0xffu8; 20]) // target < owner ⇒ not covered
        } else {
            (vec![0x00u8; 20], vec![0x7fu8; 20]) // target > next  ⇒ not covered
        };
        let owner = nsec3_owner(&owner_hash, &parent);
        let (nsec3, rrsig) = signed_nsec3(
            &signer,
            &owner,
            true,
            NSEC3_ITERS,
            next_hash,
            &[RecordType::RRSIG],
        );
        let r = resolve_no_ds(
            &child,
            &[nsec3, rrsig],
            &[dnskey],
            NOW,
            &mut 0,
            &DnssecConfig::default(),
        );
        assert_eq!(r, ChainResult::Bogus(ChainBogus::DenialProofMissing));
    }

    // ===== §4.10-5a: non-apex leaf answer authentication ====================
    // The §4.10-3a `validate_chain` tests use real captured chains and always
    // pass `answer = None`, so the answer branch was never exercised with a
    // non-apex owner. These build a fully synthetic, in-test-signed chain so the
    // answer branch can be driven at a name below the zone apex. A throwaway root
    // key is covered by a pushed trust anchor, making the whole chain forgeable
    // and deterministic (`now` fixed inside the validity window).

    const TTL: u32 = 3600;

    /// SHA-256 DS digest of `dnskey` under `owner`, as DS-record digest bytes.
    fn digest_of(dnskey: &DNSKEY, owner: &Name) -> Vec<u8> {
        dnskey
            .to_digest(owner, DigestType::SHA256)
            .unwrap()
            .as_ref()
            .to_vec()
    }

    /// A trust anchor whose DS commits to `dnskey` at `owner` — lets a synthetic
    /// root key stand in for the IANA KSK so `validate_chain` anchors in-test.
    fn anchor_covering(dnskey: &DNSKEY, owner: &Name) -> RootTrustAnchor {
        RootTrustAnchor {
            key_tag: dnskey.calculate_key_tag().unwrap(),
            algorithm: Algorithm::ECDSAP256SHA256,
            digest_type: DigestType::SHA256,
            digest: digest_of(dnskey, owner),
            valid_from: "2017-02-02T00:00:00+00:00",
            valid_until: None,
        }
    }

    /// Sign `records` (the RRset at `owner`, type `rtype`) under `signer` and
    /// return them as a `FetchedRrset`. RRSIG `labels` = `owner.num_labels()`,
    /// mirroring a real signer — so the answer branch's owner choice is exactly
    /// what the RFC 4035 §5.3.1 label-count gate keys on.
    fn signed_set(
        signer: &DnssecSigner,
        owner: &Name,
        rtype: RecordType,
        records: Vec<Record>,
    ) -> FetchedRrset {
        signed_set_with_labels(signer, owner, rtype, owner.num_labels(), records)
    }

    /// Like [`signed_set`] but with an explicit RRSIG `labels` field, to model a
    /// wildcard-expanded answer: served at a deeper wire `owner` (e.g.
    /// `foo.example.`) while `labels` counts only the wildcard's labels
    /// (1 = `*.example.`). `TBS::from_sig` reconstructs the `*.example.` owner
    /// from `labels` for the signed bytes (RFC 4035 §5.3.2), exactly as the
    /// verifier does — so the signature lines up only when both sides agree on
    /// the wire owner.
    fn signed_set_with_labels(
        signer: &DnssecSigner,
        owner: &Name,
        rtype: RecordType,
        labels: u8,
        records: Vec<Record>,
    ) -> FetchedRrset {
        let key_tag = signer.calculate_key_tag().unwrap();
        let mk = |sig: Vec<u8>| {
            rrsig_new(
                rtype,
                Algorithm::ECDSAP256SHA256,
                labels,
                TTL,
                EXP,
                INC,
                key_tag,
                signer.signer_name().clone(),
                sig,
            )
        };
        let tbs = tbs_from_sig(owner, DNSClass::IN, &mk(Vec::new()), records.iter()).unwrap();
        let sig = signer.sign(&tbs).unwrap();
        FetchedRrset {
            records,
            rrsigs: vec![mk(sig)],
            authority: Vec::new(),
        }
    }

    /// A synthetic, in-test-signed chain `.` → `example.`: a self-generated root
    /// key (covered by a pushed anchor) signs `example.`'s DS; `example.`'s key
    /// self-signs and is committed by that DS. Returns the anchors, a fetcher
    /// serving the root + `example.` DNSKEY/DS RRsets, and `example.`'s signer +
    /// name so a caller can sign an answer under the zone and validate it with
    /// `target_zone = example.`.
    fn synthetic_chain() -> (RootTrustAnchors, CannedFetcher, DnssecSigner, Name) {
        let root = Name::root();
        let zone = name("example.");
        let (root_signer, root_dnskey) = test_zone_key(&root);
        let (zone_signer, zone_dnskey) = test_zone_key(&zone);

        // Root DNSKEY RRset, self-signed; anchored by a matching pushed anchor.
        let root_key_rec = Record::from_rdata(
            root.clone(),
            TTL,
            RData::DNSSEC(DNSSECRData::DNSKEY(root_dnskey.clone())),
        );
        let root_set = signed_set(&root_signer, &root, RecordType::DNSKEY, vec![root_key_rec]);

        // `example.` DS, signed by the root key, committing to the zone key.
        let ds = DS::new(
            zone_dnskey.calculate_key_tag().unwrap(),
            Algorithm::ECDSAP256SHA256,
            DigestType::SHA256,
            digest_of(&zone_dnskey, &zone),
        );
        let ds_rec = Record::from_rdata(zone.clone(), TTL, RData::DNSSEC(DNSSECRData::DS(ds)));
        let ds_set = signed_set(&root_signer, &zone, RecordType::DS, vec![ds_rec]);

        // `example.` DNSKEY RRset, self-signed.
        let zone_key_rec = Record::from_rdata(
            zone.clone(),
            TTL,
            RData::DNSSEC(DNSSECRData::DNSKEY(zone_dnskey.clone())),
        );
        let key_set = signed_set(&zone_signer, &zone, RecordType::DNSKEY, vec![zone_key_rec]);

        let mut anchors = RootTrustAnchors::iana();
        anchors.push(anchor_covering(&root_dnskey, &root));

        let fetcher = CannedFetcher::default()
            .with(".", RecordType::DNSKEY, root_set)
            .with("example.", RecordType::DS, ds_set)
            .with("example.", RecordType::DNSKEY, key_set);

        (anchors, fetcher, zone_signer, zone)
    }

    #[tokio::test]
    async fn answer_below_apex_validates_secure() {
        // The crux: a correctly-signed leaf BELOW the apex must validate Secure.
        // Pre-fix the answer branch authenticated it under the apex owner
        // (`example.`), tripping the RFC 4035 §5.3.1 label-count gate
        // (`rrsig.labels = 2 > example.labels = 1`) → Bogus(NameError) → SERVFAIL.
        let (anchors, fetcher, zone_signer, zone) = synthetic_chain();
        let leaf = name("www.example.");
        let a_rec = Record::from_rdata(leaf.clone(), TTL, RData::A(A(Ipv4Addr::new(192, 0, 2, 1))));
        let answer = signed_set(&zone_signer, &leaf, RecordType::A, vec![a_rec]);

        let r = validate_chain(
            &fetcher,
            &anchors,
            &zone,
            Some((&answer.records, &answer.rrsigs[0])),
            NOW,
            &DnssecConfig::default(),
        )
        .await;
        assert_eq!(
            r,
            ChainResult::Secure,
            "a correctly-signed non-apex leaf (www.example.) must validate Secure, not SERVFAIL"
        );
    }

    #[tokio::test]
    async fn answer_wildcard_validates_secure() {
        // A wildcard answer: served at `foo.example.` (2 wire labels) but signed
        // with RRSIG labels = 1, so the verifier reconstructs the canonical
        // `*.example.` owner (RFC 4035 §5.3.2). The 5a fix authenticates under
        // the real wire owner `foo.example.`, which is what makes that
        // reconstruction line up → Secure. Pre-fix, authenticating under the apex
        // `example.` skips the reconstruction (labels 1 == example.labels 1), so
        // the TBS is built over `example.` not `*.example.` → SignatureInvalid.
        let (anchors, fetcher, zone_signer, zone) = synthetic_chain();
        let wild = name("foo.example.");
        let a_rec = Record::from_rdata(wild.clone(), TTL, RData::A(A(Ipv4Addr::new(192, 0, 2, 1))));
        let answer = signed_set_with_labels(&zone_signer, &wild, RecordType::A, 1, vec![a_rec]);

        let r = validate_chain(
            &fetcher,
            &anchors,
            &zone,
            Some((&answer.records, &answer.rrsigs[0])),
            NOW,
            &DnssecConfig::default(),
        )
        .await;
        assert_eq!(
            r,
            ChainResult::Secure,
            "a wildcard-expanded answer (foo.example. signed as *.example.) must validate Secure"
        );
    }

    #[tokio::test]
    async fn answer_with_mixed_owners_is_bogus() {
        // s3-01: the answer slice carries two same-type (A) records under
        // DIFFERENT owners. `verify_keyset` would authenticate only the first
        // owner's subset, yet a Secure verdict is read by the consumer as
        // covering the whole slice (AD bit) — so the owner-uniformity guard must
        // fail closed rather than vouch for the unverified sibling.
        let (anchors, fetcher, zone_signer, zone) = synthetic_chain();
        let leaf = name("www.example.");
        let a1 = Record::from_rdata(leaf.clone(), TTL, RData::A(A(Ipv4Addr::new(192, 0, 2, 1))));
        let signed = signed_set(&zone_signer, &leaf, RecordType::A, vec![a1]);

        // Inject a same-type record under a sibling owner into the answer slice.
        let sibling = name("evil.example.");
        let a2 = Record::from_rdata(sibling, TTL, RData::A(A(Ipv4Addr::new(192, 0, 2, 2))));
        let mut records = signed.records.clone();
        records.push(a2);

        let r = validate_chain(
            &fetcher,
            &anchors,
            &zone,
            Some((&records, &signed.rrsigs[0])),
            NOW,
            &DnssecConfig::default(),
        )
        .await;
        assert_eq!(
            r,
            ChainResult::Bogus(ChainBogus::AnswerOwnerMismatch),
            "a multi-owner answer slice must fail closed, not be vouched for as Secure"
        );
    }

    #[tokio::test]
    async fn answer_at_apex_validates_secure() {
        // Regression guard: the apex answer (owner == apex == target_zone) must
        // keep validating after the fix.
        let (anchors, fetcher, zone_signer, zone) = synthetic_chain();
        let a_rec = Record::from_rdata(zone.clone(), TTL, RData::A(A(Ipv4Addr::new(192, 0, 2, 1))));
        let answer = signed_set(&zone_signer, &zone, RecordType::A, vec![a_rec]);

        let r = validate_chain(
            &fetcher,
            &anchors,
            &zone,
            Some((&answer.records, &answer.rrsigs[0])),
            NOW,
            &DnssecConfig::default(),
        )
        .await;
        assert_eq!(
            r,
            ChainResult::Secure,
            "an apex answer must keep validating"
        );
    }

    // ---- §4.10-5b: KeyTrap — global RRSIG-verification cap (CVE-2023-50387) ----

    #[test]
    fn sig_cap_trips_on_keyset_flood() {
        // The KeyTrap vector: many RRSIGs sharing one 16-bit key tag force a crypto
        // verification per (sig, key) pair. The global cap must stop the walk and
        // fail closed. Exercised on the NSEC denial path — proof the budget covers
        // the denial branches, not only the DS/DNSKEY hops.
        let (parent, child) = delegation();
        let (signer, dnskey) = test_zone_key(&parent);
        // One real NSEC owned by `child`; its valid RRSIG is dropped — the authority
        // instead carries a flood of same-tag, non-verifying decoy RRSIGs.
        let (nsec, _rrsig) = signed_nsec(
            &signer,
            &child,
            &[RecordType::NS, RecordType::RRSIG, RecordType::NSEC],
        );
        let key_tag = dnskey.calculate_key_tag().unwrap();
        let mut authority = vec![nsec];
        for _ in 0..50 {
            authority.push(Record::from_rdata(
                child.clone(),
                3600,
                RData::DNSSEC(DNSSECRData::RRSIG(rrsig_new(
                    RecordType::NSEC,
                    Algorithm::ECDSAP256SHA256,
                    child.num_labels(),
                    3600,
                    EXP,
                    INC,
                    key_tag, // collide on the parent key's tag ⇒ gate passes
                    parent.clone(),
                    vec![0u8; 64], // non-verifying ⇒ the keyset loop never short-circuits
                ))),
            ));
        }
        let caps = DnssecConfig {
            max_signature_verifications: 8,
            ..DnssecConfig::default()
        };
        let r = resolve_no_ds(&child, &authority, &[dnskey], NOW, &mut 0, &caps);
        assert_eq!(
            r,
            ChainResult::Indeterminate(Indeterminate::MaxSignatureVerificationsExceeded),
            "a 50-deep colliding-key-tag RRSIG flood must trip the cap (8), not verify all 50"
        );
    }

    #[tokio::test]
    async fn sig_cap_is_global_across_hops() {
        // The cap is GLOBAL to the walk, not per-RRset: a budget of 2 is spent by
        // the root and DS verifications, so the DNSKEY-hop verification is refused
        // even though no single RRset is itself oversized.
        let (anchors, fetcher, _zone_signer, zone) = synthetic_chain();
        let caps = DnssecConfig {
            max_signature_verifications: 2,
            ..DnssecConfig::default()
        };
        let r = validate_chain(&fetcher, &anchors, &zone, None, NOW, &caps).await;
        assert_eq!(
            r,
            ChainResult::Indeterminate(Indeterminate::MaxSignatureVerificationsExceeded),
            "a 2-verification budget must be exhausted across hops (root + DS) before the DNSKEY hop"
        );
    }

    #[tokio::test]
    async fn legit_chain_secure_under_default_sig_cap() {
        // Regression: the default cap (256) must clear a real chain with wide
        // margin — a legitimate walk spends only a handful of verifications, so the
        // KeyTrap guard must never choke valid validation.
        let (anchors, fetcher, zone_signer, zone) = synthetic_chain();
        let leaf = name("www.example.");
        let a_rec = Record::from_rdata(leaf.clone(), TTL, RData::A(A(Ipv4Addr::new(192, 0, 2, 1))));
        let answer = signed_set(&zone_signer, &leaf, RecordType::A, vec![a_rec]);

        let r = validate_chain(
            &fetcher,
            &anchors,
            &zone,
            Some((&answer.records, &answer.rrsigs[0])),
            NOW,
            &DnssecConfig::default(),
        )
        .await;
        assert_eq!(
            r,
            ChainResult::Secure,
            "the default max_signature_verifications (256) must not break a legitimate chain"
        );
    }
}
