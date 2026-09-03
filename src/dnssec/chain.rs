//! Chain-of-trust walk — authenticate a name from the root anchor down.
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
//! ## Scope
//!
//! - The **positive** chain: `Secure` when every hop authenticates, `Bogus`
//!   when a link is broken, `Indeterminate` when a DoS cap trips or a fetch
//!   fails.
//! - The **no-DS delegation**: a delegation with no DS could be a
//!   legitimately *unsigned* zone or a stripped-DS downgrade. [`resolve_no_ds`]
//!   consults the parent's authenticated NSEC denial proof ([`crate::dnssec::denial`])
//!   to decide: a proof of no-DS ⇒ `Insecure(UnsignedDelegation)`; a missing or
//!   contradictory proof ⇒ `Bogus`; no proof material at all ⇒
//!   [`crate::dnssec::chain::Indeterminate::DenialProofRequired`].
//! - The `max_chain_depth` and `max_queries` DoS caps.
//!
//! Like the rest of [`crate::dnssec`], this is an **engine** — it produces a
//! verdict but is not wired into the live response path (no AD/CD bit, no
//! SERVFAIL). Chain material is fetched through the injectable
//! [`ChainFetcher`] trait so the walk is hermetically testable offline; the
//! production adapter over the daemon's upstream (which must set the DO bit and
//! retain the authority section) is separate from this walk.

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
    /// proof that no DS exists at the child; empty for an answer that needs no
    /// denial proof.
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
    /// hop whose algorithm is out of scope, or a denial-of-existence-based
    /// unsigned-delegation proof. Reuses the engine's [`InsecureReason`]
    /// unchanged.
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
    /// matching the child's name was present to prove the DS absent — the
    /// absence of a proof for a stripped DS must not be trusted.
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
    /// `max_nsec3_iterations`; refused before hashing (RFC 5155 §10.3). The
    /// third DoS cap — an attacker-chosen iteration count is a CPU-DoS vector.
    MaxNsec3IterationsExceeded,
    /// A delegation has no DS RRset. Proving this is a legitimately unsigned
    /// delegation (rather than a stripped-DS downgrade) needs authenticated
    /// denial of existence, which upgrades this to `Insecure`/`Bogus`.
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
        //     proof to tell an unsigned delegation from a downgrade.
        let ds_set = match guarded_fetch(fetcher, &child, RecordType::DS, &mut queries, caps).await
        {
            Ok(set) => set,
            Err(cr) => return cr,
        };
        if ds_set.records.is_empty() {
            // No DS: a legitimately unsigned delegation, or a stripped-DS
            // downgrade. The parent's authenticated NSEC denial proof decides;
            // the parent's keys (`current_keys`) sign that proof.
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
/// - a matching NSEC for `child` ⇒ the NSEC path (below).
/// - otherwise ⇒ the NSEC3 path ([`resolve_no_ds_nsec3`]).
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
    // No plain NSEC matches `child`: the proof is NSEC3 (or absent).
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

/// The NSEC3 arm of the no-DS hook (RFC 5155 §8.6 / §8.9). Same
/// auth-before-trust gate and same verdicts as the NSEC path: authenticate every
/// NSEC3 RRset against the parent's keys *first*, then decide no-DS over the
/// authenticated set only — a forged or unsigned NSEC3 is `Bogus` before any hash
/// or bitmap is trusted.
///
/// Scope is the closest-encloser-free single-hop case (a matching NSEC3, or an
/// opt-out NSEC3 covering the delegation hash); see [`nsec3_proves_no_ds`]. The
/// `max_nsec3_iterations` cap is charged *before* auth and hashing — the
/// cheapest refusal of an attacker-chosen iteration count.
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
    // discard the unusable record, do not fail the walk.

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
mod tests;
