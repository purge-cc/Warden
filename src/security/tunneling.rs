//! DNS tunneling detection via label shape and subdomain rate analysis.
//!
//! Tunneling tools encode data in DNS labels, producing long unbroken
//! payload runs and high rates of never-before-seen names under one base
//! domain. Two independent surfaces:
//!
//! - [`TunnelingDetector::check`] — stateless shape heuristics (per-label
//!   length, longest `-`-free run, and a length-gated entropy backstop).
//!   Runs pre-query on every request.
//! - [`TunnelingDetector::check_rate`] — stateful query-rate heuristic,
//!   keyed per `(client, base domain)` and bumped by the handler on the
//!   cache-MISS path only. Tunneling fan-out is inherently cache-missing
//!   (every exfil name is unique); cache hits prove repetition, so counting
//!   them — or sharing one bucket LAN-wide — only manufactured false
//!   positives on popular bases (googlevideo.com, amazonaws.com).
//!   It counts **distinct names** in the window rather than calls: a
//!   cache-missing name can repeat too — a short TTL is enough — and one
//!   such name spending a whole base's budget is what REFUSED its
//!   innocent siblings for 8 days. See
//!   `RecentNames` for the ring that does the de-duplication and the
//!   four-part cost justification behind its size.
//!
//! # Why entropy stopped being the primary signal
//!
//! Shannon entropy *per character* is bounded by `log2(len)` and by
//! `log2(alphabet)`. An encoder using 11 or fewer distinct symbols never
//! reaches a 3.5 threshold **at any length**, so the gate could not see a
//! competent tunnel; meanwhile a legitimate 38-char AWS ELB hostname
//! scores 4.572 against a hex tunnel's `log2(16) = 4.0` ceiling. The
//! distributions are inverted, not merely overlapping — no threshold
//! separates them.
//!
//! Measured on 8 days of live traffic (942 distinct analysable names):
//! the shape gate produced 4358 of 4717 refusals, essentially all
//! legitimate. The replacement — longest `-`-free run — is a strict
//! *subset* of the old predicate: it detects nothing the old one missed,
//! it just stops refusing what was never a tunnel. Entropy survives as a
//! configurable backstop behind
//! [`TunnelingConfig::entropy_min_len`](crate::config::settings::TunnelingConfig::entropy_min_len).
//!
//! The primary defence is now [`TunnelingDetector::check_rate`]: a tunnel
//! is by definition a stream of unique cache-missing names.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use compact_str::CompactString;

use super::atomic_window::AtomicWindowCounter;
use super::bounded_map::BoundedMap;
use super::MAX_LABELS;
use crate::config::settings::TunnelingConfig;

/// Hard cap on the number of tracked base domains.
///
/// Without this cap, an attacker flooding unique eTLD+1s (or unique
/// attacker-owned subdomains under different 2LDs) pins one tracker
/// entry per source, unbounded. The cap triggers approximate-LRU
/// eviction on over-cap insert.
const MAX_TRACKED_BASE_DOMAINS: usize = 100_000;

/// Known 2-label public suffixes (eTLD+1 has 3 labels under these).
///
/// **ICANN entries only.** These are structural DNS facts: registries
/// that sell at the third level, so `evil.co.uk` is one registrant's
/// name and `co.uk` is not. Naming them favours nobody, which is why
/// CLAUDE.md §Neutrality lists this table as a *legal* site.
///
/// # `neutrality-05`: the twelve private-section entries are gone
///
/// This table used to carry twelve more under a comment reading
/// "Common as-if-TLD hosting platforms" — vendor-submitted names from
/// the PSL's **private** section. Those are not structural facts about
/// DNS; they are eleven companies' hosting products, compiled into the
/// binary, changing how warden grouped traffic to named providers. That
/// is Key Design Rule 10, and the ICANN/private split is exactly the
/// line between the two halves of this table.
///
/// Loading the real PSL as data was the other option and was rejected:
/// it needs a file path this module has no way to resolve, and it would
/// import the private section too unless filtered — reintroducing the
/// same names through a different door.
///
/// # What that changes, derived rather than assumed
///
/// The buckets in [`TunnelingDetector::check_rate`] are keyed
/// `(client_ip, base_domain)`, so dropping an entry **widens** its
/// bucket: every `*.<dropped-suffix>` name a client looks up now shares
/// one budget instead of getting one budget per site. Two consequences,
/// both in the strict direction:
///
/// 1. Fan-out under such a name is detected *sooner*, because unrelated
///    traffic to the same platform now counts toward the same budget.
/// 2. A client legitimately touching many sites on one platform can
///    trip the gate, and tripping it REFUSEs further misses under that
///    base for the rest of the window.
///
/// Note this is the opposite of what this comment claimed before the
/// change — it described the last-two-labels fallback as "safe (possibly
/// too permissive)". For a per-base *fan-out* counter a coarser base is
/// not more permissive, it is less. The remedy for a false positive is
/// the operator's own `tunneling.exempt_domains`, which is consulted
/// before the bump so an exempt name does not consume the budget either.
const TWO_LABEL_SUFFIXES: &[&str] = &[
    // Country-code 2LDs
    "co.uk", "co.jp", "co.kr", "co.nz", "co.za", "co.in", "co.il", "co.th", "com.au", "com.br",
    "com.cn", "com.mx", "com.tw", "com.tr", "com.sg", "com.hk", "ac.uk", "ac.jp", "ac.nz",
    "gov.uk", "gov.au", "gov.br", "org.uk", "org.au", "org.nz", "net.au", "net.nz", "net.br",
    "edu.au", "edu.br",
];

/// Longest entry in [`TWO_LABEL_SUFFIXES`] (`com.au` and friends = 6 B).
/// Used by [`compute_base_domain`] to skip the suffix probe when the
/// joined last-two labels are too long to match any entry — keeping the
/// throwaway probe `CompactString` inline (no adversary-forced heap
/// alloc).
///
/// Was 16 while the table carried `s3.amazonaws.com`; re-derived when
/// `neutrality-05` removed the twelve private-section entries. Pinned by
/// `two_label_suffix_len_bound`, which asserts **equality** rather than
/// an upper bound: too large only wastes a few bytes of probe, but too
/// small makes every longer entry silently unreachable — the table would
/// still list it and `compute_base_domain` would never look.
const MAX_TWO_LABEL_SUFFIX_LEN: usize = 6;

/// Compute the eTLD+1 of a label sequence, using [`TWO_LABEL_SUFFIXES`] to
/// decide whether the last 2 or last 3 labels form the base.
///
/// Returns `None` if there are fewer than 2 labels. Returned value is the
/// base domain joined with `.`.
///
/// Returns `CompactString` (inline ≤24 bytes, no heap alloc for the
/// common case) and uses `write!` into a single stackbuf rather than two
/// `format!` heap allocations.
fn compute_base_domain(labels: &[&str]) -> Option<CompactString> {
    use std::fmt::Write;
    let n = labels.len();
    if n < 2 {
        return None;
    }
    // If we have at least 3 labels and the final two match a known 2LD
    // suffix, the base is the last 3 labels (foo.co.uk, bar.github.io).
    if n >= 3 {
        // Probe the last-two-joined form against TWO_LABEL_SUFFIXES via
        // a small stackbuf — common eTLDs like co.uk / github.io are
        // well under 24 bytes so this never spills to heap. Bail before
        // building the probe when the joined length exceeds the longest
        // known suffix: it cannot match, and two adversary-controlled
        // labels (up to ~127 B) would otherwise spill the throwaway probe
        // to the heap on the pre-query hot path.
        let joined_len = labels[n - 2].len() + 1 + labels[n - 1].len();
        if joined_len <= MAX_TWO_LABEL_SUFFIX_LEN {
            let mut probe = CompactString::default();
            let _ = write!(probe, "{}.{}", labels[n - 2], labels[n - 1]);
            if TWO_LABEL_SUFFIXES.contains(&probe.as_str()) {
                let mut out = CompactString::default();
                let _ = write!(out, "{}.{}", labels[n - 3], probe);
                return Some(out);
            }
        }
    }
    let mut out = CompactString::default();
    let _ = write!(out, "{}.{}", labels[n - 2], labels[n - 1]);
    Some(out)
}

/// Extract window_start for [`BoundedMap`] eviction ordering.
fn tracker_age(t: &SubdomainTracker) -> u64 {
    t.counter.window_start_secs()
}

/// Result of tunneling analysis for a single query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelingVerdict {
    /// No tunneling indicators detected.
    Clean,
    /// Suspicious: one or more heuristics triggered.
    Suspicious,
}

/// Slots in each bucket's [`RecentNames`] ring. Power of two — the index
/// is `hash & (RECENT_NAME_SLOTS - 1)`.
const RECENT_NAME_SLOTS: usize = 8;

const _: () = assert!(
    RECENT_NAME_SLOTS.is_power_of_two(),
    "RECENT_NAME_SLOTS indexes by mask, so it must be a power of two"
);

/// Fixed-size ring of the name hashes most recently counted in one
/// `(client, base domain)` bucket. Lets [`TunnelingDetector::check_rate`]
/// count **distinct names** in the window instead of every cache-missing
/// call.
///
/// Copied in shape — not imported — from `MacMismatchRing`
/// (`profiles/resolver.rs`), which is not generic and lives in another
/// module: an `[AtomicU64; N]` indexed by `hash & (N-1)`, each slot
/// packing `[hash_high:u32 | last_secs:u32]`, deliberately **without
/// CAS**. Same four-part justification the precedent carries:
///
/// 1. **Worst case before.** `check_rate` bumped on every cache-missing
///    call, with no per-name state of any kind. Measured on 8 days of
///    live traffic: `ephemeralcounters.api.roblox.com` alone spent 954
///    bumps of a 50-per-minute budget and its siblings
///    (`groups.` 41, `metrics.` 15) were REFUSED — 65 refusals, none of
///    them a tunnel. The obvious exact fix, a `HashSet` of seen names per
///    bucket, is up to [`MAX_TRACKED_BASE_DOMAINS`] independent jemalloc
///    allocations reached from the DNS cache-miss path — the thing
///    `CLAUDE.md` §Hot path exists to forbid.
/// 2. **Structural bound after.** 8 × `AtomicU64` = 64 B inline per
///    bucket, zero heap allocations, `size_of::<SubdomainTracker>()` =
///    72 B. At the 100 000-entry cap the map goes from ~7.5 MB (48 B key
///    plus 8 B value) to ~15.9 MB — the whole cost is in the value, none
///    of it in the allocator. Pinned by
///    `subdomain_tracker_is_structurally_bounded`.
/// 3. **Accuracy cost.** Direct-mapped, no CAS, no LRU. Two names sharing
///    a slot displace each other, so a repeat can be counted a second
///    time: ~12.5 % for a random pair, and for K names cycling inside one
///    bucket the suppression rate is ≈ `(7/8)^(K-1)`. A lost store under
///    contention has the same effect as a displacement.
/// 4. **Why that cost is bounded.** A displacement can only *fail to
///    suppress* a repeat — never suppress a name the bucket has not seen.
///    The error floor is therefore exactly the count-every-call behaviour
///    this ring replaces, so it can never make a false refusal more
///    likely — only less likely. The converse error, two
///    *distinct* names collapsing into one, needs the low 3 index bits
///    **and** the high 32 hash bits to match (~2^-35) and costs one
///    uncounted name out of the budget — the false-negative direction
///    this gate is required to fail in.
struct RecentNames {
    slots: [AtomicU64; RECENT_NAME_SLOTS],
}

impl RecentNames {
    fn new() -> Self {
        // Every slot starts at the all-zero sentinel (`hash_high == 0`,
        // `last_secs == 0`). A name whose `hash_high` is itself 0 and
        // whose first sighting lands inside the detector's first
        // `window_secs` of life is therefore wrongly treated as a repeat
        // once — a ~1-in-2^32 hash against a one-window startup slice,
        // costing a single uncounted name. Failing that way round is the
        // requirement, not a compromise.
        Self {
            slots: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
        }
    }

    /// Has this name already been counted in the current window? On a
    /// miss, record it (displacing whatever shared the slot) and return
    /// `false` so the caller bumps.
    ///
    /// Lock-free and alloc-free: one atomic load plus, on a miss, one
    /// atomic store. No retry — see justification part 4 on the ring
    /// type for why a lost store is safe here.
    ///
    /// Freshness is measured from the name's own last sighting rather
    /// than from the counter's window start, so the two can skew by up
    /// to `window_secs`. The skew resolves in the suppress direction (a
    /// name may stay suppressed into the first seconds of a new window),
    /// which is again the direction this gate must err in.
    fn seen_or_record(&self, hash: u64, now_secs: u64, window_secs: u64) -> bool {
        let idx = (hash & (RECENT_NAME_SLOTS as u64 - 1)) as usize;
        let hash_high = (hash >> 32) as u32;
        let now = now_secs as u32;

        let prev = self.slots[idx].load(Ordering::Relaxed);
        let prev_hash = (prev >> 32) as u32;
        let prev_secs = prev as u32;
        if prev_hash == hash_high && u64::from(now.saturating_sub(prev_secs)) < window_secs {
            return true;
        }

        self.slots[idx].store(
            (u64::from(hash_high) << 32) | u64::from(now),
            Ordering::Relaxed,
        );
        false
    }
}

/// Hash a query name for [`RecentNames`]. `DefaultHasher::new()` is
/// SipHash-1-3 with fixed keys, so the ring behaves identically across
/// runs — the collision budget above is a property of the slot count, not
/// of a per-process seed. Not reachable as an oracle by a client (the ring
/// is invisible in the response), so collision-forcing is not in scope.
fn name_hash(domain: &str) -> u64 {
    let mut h = DefaultHasher::new();
    domain.hash(&mut h);
    h.finish()
}

/// Per-base-domain subdomain rate tracker.
struct SubdomainTracker {
    /// Packed `[count:u32 | window_start_secs:u32]` — atomic window reset
    /// closes the TOCTOU a two-store reset pattern would have between the
    /// window-start write and the count write. Preserves the invariant
    /// that the first responder sees prior count = 0, so a single
    /// `check_and_bump` covers first-responder and subsequent-responder
    /// paths uniformly.
    counter: AtomicWindowCounter,
    /// Names already counted in this bucket's window. Deliberately
    /// **beside** [`Self::counter`] and not inside it: the packed counter
    /// has no spare bits (`[count:u32 | ws:u32]`, both halves load-bearing),
    /// and the inverse layout that would free some was rejected because a
    /// count overflow bleeding into `window_start` sticks the window in a
    /// never-expiring state — a hard prefix DoS, pinned by
    /// `count_overflow_wraps_within_upper_bits` in
    /// [`super::atomic_window`].
    recent: RecentNames,
}

impl SubdomainTracker {
    fn new(now_secs: u64) -> Self {
        Self {
            counter: AtomicWindowCounter::new(now_secs),
            recent: RecentNames::new(),
        }
    }
}

/// DNS tunneling detector. Stateful — tracks subdomain rates over time.
///
/// Backed by a [`BoundedMap`] capped at [`MAX_TRACKED_BASE_DOMAINS`] to
/// prevent memory DoS from a flood of unique base domains. When the
/// cap is hit, the oldest tracker is evicted via sample-8 approximate LRU.
pub struct TunnelingDetector {
    /// Per-`(client, base domain)` cache-miss rate tracking — keyed per
    /// client so one device's fan-out can't exhaust a base's budget for
    /// the whole LAN.
    subdomain_rates: BoundedMap<(IpAddr, CompactString), SubdomainTracker>,
    /// Live-swappable thresholds + exemption list. See [`TunnelingParams`].
    params: ArcSwap<TunnelingParams>,
    /// Monotonic epoch for every rate window. Deliberately **outside**
    /// [`Self::params`]: it is the origin every `window_start_secs` is
    /// measured against, so swapping it on reload would silently
    /// corrupt every live window rather than retune anything.
    created_at: Instant,
}

/// The reload-swappable half of the detector.
///
/// Split out of [`TunnelingDetector`] so `warden security tunneling
/// exempt …` takes effect without a daemon restart. The stateful
/// `subdomain_rates` map is *not* in here on purpose: rebuilding the
/// whole detector on reload would zero the rate counters, and the rate
/// gate is the primary tunneling defence — a reload must not hand an
/// attacker a fresh budget.
#[derive(Debug, Clone)]
pub struct TunnelingParams {
    entropy_threshold: f64,
    label_len_threshold: usize,
    max_unbroken_run: usize,
    entropy_min_len: usize,
    subdomain_rate_limit: u32,
    window_secs: u64,
    /// Lowercased exempt suffixes. Empty in the overwhelmingly common
    /// case, which is why every consult is guarded by `is_empty()`.
    exempt_domains: Vec<CompactString>,
}

impl TunnelingParams {
    fn from_config(config: &TunnelingConfig) -> Self {
        Self {
            entropy_threshold: config.entropy_threshold,
            label_len_threshold: config.label_len_threshold,
            max_unbroken_run: config.max_unbroken_run,
            entropy_min_len: config.entropy_min_len,
            subdomain_rate_limit: config.subdomain_rate,
            window_secs: config.window_secs,
            exempt_domains: config
                .exempt_domains
                .iter()
                .map(|d| CompactString::from(d.trim_matches('.').to_ascii_lowercase()))
                .collect(),
        }
    }
}

/// Does `domain` fall under one of the operator's exempt suffixes?
///
/// Label-boundary anchored: `a2z.com` covers `x.y.a2z.com` and the apex
/// itself, but **not** `evil-a2z.com` — the byte preceding the matched
/// suffix must be a `.`. Without that check an attacker registers
/// `evil-<exempt>` and inherits the exemption.
///
/// `domain` is already lowercased by the caller (the handler normalises
/// at ingestion); entries are lowercased at [`TunnelingParams::from_config`].
fn is_exempt(domain: &str, exempt: &[CompactString]) -> bool {
    exempt.iter().any(|suffix| {
        let s = suffix.as_str();
        if s.is_empty() {
            return false;
        }
        if domain == s {
            return true;
        }
        domain.len() > s.len()
            && domain.as_bytes()[domain.len() - s.len() - 1] == b'.'
            && domain.ends_with(s)
    })
}

/// Is `domain` inside one of the two IANA reverse-mapping zones?
///
/// `in-addr.arpa` (RFC 1035 §3.5) and `ip6.arpa` (RFC 3596 §2.5) are
/// protocol structure, not third-party knowledge — the same class as
/// `RESERVED_TLDS` in the config validator and `HOSTS_SKIP` in the list
/// parser, and outside what `CLAUDE.md` §Neutrality forbids: that rule
/// governs named *services*, and these two names belong to DNS itself.
///
/// Written from scratch because no reusable predicate existed —
/// `dns/local.rs` *builds* reverse names, `dns/validation.rs` only names
/// the zones in comments and tests.
///
/// **Lives here, not in `dns/handler.rs`,** for a mechanical reason worth
/// keeping: the handler is one of the four files `CLAUDE.md` §Neutrality
/// pins at *zero* domain literals outside tests, and its check is a plain
/// `grep -cE '"[a-z0-9-]+\.[a-z]{2,}"'` that cannot tell an RFC zone from
/// a vendor name. A legal literal there would still read as a violation
/// and cost the next reader the triage.
///
/// Label-boundary anchored, mirroring [`is_exempt`]: a bare suffix match
/// would hand `evil-in-addr.arpa` the exemption. `domain` is already
/// lowercased and trailing-dot-free by the time a caller sees it.
pub(crate) fn is_reverse_zone(domain: &str) -> bool {
    const REVERSE_ZONES: [&str; 2] = ["in-addr.arpa", "ip6.arpa"];
    REVERSE_ZONES.iter().any(|zone| {
        domain == *zone
            || (domain.len() > zone.len()
                && domain.as_bytes()[domain.len() - zone.len() - 1] == b'.'
                && domain.ends_with(zone))
    })
}

/// Longest substring of `label` containing no `-`.
///
/// Deliberately *not* "longest alphanumeric run": `_` is a legal and
/// deliberate label character here (see
/// [`query_validator`](super::query_validator), which permits it for
/// DKIM/SRV names), so an `is_ascii_alphanumeric` scan would break the
/// run at underscores and flag `_dmarc`-style names differently from
/// how the offline threshold derivation modelled them.
fn longest_unbroken_run(label: &str) -> usize {
    label.split('-').map(str::len).max().unwrap_or(0)
}

impl TunnelingDetector {
    pub fn new(config: &TunnelingConfig) -> Self {
        Self {
            subdomain_rates: BoundedMap::new(MAX_TRACKED_BASE_DOMAINS, tracker_age),
            params: ArcSwap::from_pointee(TunnelingParams::from_config(config)),
            created_at: Instant::now(),
        }
    }

    /// Swap thresholds + exemptions in place, preserving every rate
    /// bucket. Called from the daemon's config-reload path.
    pub fn set_params(&self, config: &TunnelingConfig) {
        self.params
            .store(Arc::new(TunnelingParams::from_config(config)));
    }

    /// Current number of tracked `(client, base domain)` rate buckets.
    #[allow(dead_code)] // not yet wired to stats/metrics
    pub fn entry_count(&self) -> usize {
        self.subdomain_rates.len()
    }

    /// Analyze a domain's *shape* for tunneling indicators (per-label
    /// length, longest `-`-free run, length-gated entropy backstop).
    /// Stateless — the query-rate heuristic lives in [`Self::check_rate`]
    /// and is bumped on cache misses only.
    ///
    /// `domain` should be the full domain name (already lowercased).
    /// Returns `Suspicious` if any heuristic triggers and the name is not
    /// covered by an operator exemption.
    ///
    /// **Exactly one `params.load()` per call.** A second load could pair
    /// pre-reload thresholds with a post-reload exemption list, producing
    /// a verdict that matches neither configuration.
    ///
    /// **Stateless is load-bearing**, not incidental:
    /// `shape_check_never_trips_on_volume` asserts `entry_count() == 0`
    /// after 100 calls, so any future heuristic that memoises per base
    /// domain breaks that test by design.
    ///
    /// Hot-path is allocation-free in the common case. Labels live in a
    /// stack array sized at MAX_LABELS,
    /// the eTLD+1 lives in a `CompactString` (inline ≤24 bytes), and the
    /// entropy backstop streams bytes from a chained iterator instead of
    /// materializing a `String::concat`.
    pub fn check(&self, domain: &str) -> TunnelingVerdict {
        // An input deeper than the validator admits is treated as Clean.
        // Fail-open costs one heuristic rather than opening a bypass, and
        // the buffer is sized from that same ceiling, so nothing reaching
        // the handler lands here.
        let mut label_buf: [&str; MAX_LABELS] = [""; MAX_LABELS];
        let mut n = 0usize;
        for label in domain.split('.').filter(|l| !l.is_empty()) {
            if n >= MAX_LABELS {
                return TunnelingVerdict::Clean;
            }
            label_buf[n] = label;
            n += 1;
        }
        if n < 2 {
            return TunnelingVerdict::Clean;
        }
        let labels: &[&str] = &label_buf[..n];

        // Compute the eTLD+1 via the embedded 2LD list so that hostnames
        // under `co.uk`, `github.io`, etc. share a base domain and roll
        // into the same per-base rate-limit bucket.
        let base_domain = match compute_base_domain(labels) {
            Some(b) => b,
            None => return TunnelingVerdict::Clean,
        };
        let base_label_count = base_domain.split('.').count();

        // Analyze only labels that are *not* part of the base — they are the
        // attacker-controllable portion of the name. For `foo.bar.example.co.uk`
        // with base `example.co.uk`, the analyzed labels are `foo` and `bar`.
        if labels.len() <= base_label_count {
            return TunnelingVerdict::Clean;
        }
        let check_labels = &labels[..labels.len() - base_label_count];

        let p = self.params.load();

        // Two shape gates, OR'd, both per-label:
        //
        //  - length catches payloads padded with `-` to keep every run
        //    short (worst legitimate observed: 43 chars),
        //  - longest `-`-free run catches the unbroken base32/hex labels
        //    iodine and dnscat2 emit (40-63 chars).
        //
        // Neither is a scoring system; a single gate is sufficient to
        // flag. `flagged` rather than an early `return` because the
        // operator's exemption is consulted below — and only for names
        // that actually tripped something, so clean traffic never pays
        // for the list.
        let mut flagged = check_labels.iter().any(|label| {
            label.len() >= p.label_len_threshold
                || longest_unbroken_run(label) >= p.max_unbroken_run
        });

        // Entropy backstop. Gated behind `entropy_min_len` because on
        // short strings Shannon entropy per character measures alphabet
        // size, not randomness — below the gate it flagged ordinary
        // hyphenated CDN hostnames by construction. Streams bytes from
        // the chained iterator without materializing the joined string.
        if !flagged {
            let total_len: usize = check_labels.iter().map(|l| l.len()).sum();
            if total_len >= p.entropy_min_len {
                let entropy =
                    shannon_entropy_bytes(check_labels.iter().flat_map(|l| l.bytes()), total_len);
                flagged = entropy >= p.entropy_threshold;
            }
        }

        if flagged && !p.exempt_domains.is_empty() && is_exempt(domain, &p.exempt_domains) {
            return TunnelingVerdict::Clean;
        }
        if flagged {
            return TunnelingVerdict::Suspicious;
        }

        TunnelingVerdict::Clean
    }

    /// Track and check the per-`(client, base domain)` query rate.
    /// Returns true if the rate exceeds the limit.
    ///
    /// The handler calls this on the cache-MISS path only. If the bump
    /// instead lived inside [`Self::check`] (pre-cache, so cache hits
    /// counted) and the bucket were keyed on base domain alone (one
    /// budget shared by every client on the LAN), any base whose
    /// aggregate exceeds `limit` queries/window would flip to REFUSED
    /// for the whole network. Repeat lookups of a cached name prove
    /// repetition, not fan-out; only names the resolver actually has to
    /// go upstream count against the budget.
    ///
    /// Names with no labels beyond the base (e.g. `example.com`) never
    /// count — same guard as the shape check.
    ///
    /// Atomic get-or-insert via
    /// [`super::bounded_map::BoundedMap::entry_or_insert_with`] closes a
    /// get-then-insert race a naive check-then-insert would have (two
    /// concurrent fresh-key queries both inserting, the second overwrite
    /// restarting the counter at 1). Mirrors the same fix in
    /// `rate_limiter.rs`.
    ///
    /// Window reset uses the packed [`AtomicWindowCounter`] so a
    /// two-store reset (ws then count) is a single CAS — no torn
    /// intermediate state.
    pub fn check_rate(&self, client_ip: &IpAddr, domain: &str) -> bool {
        let mut label_buf: [&str; MAX_LABELS] = [""; MAX_LABELS];
        let mut n = 0usize;
        for label in domain.split('.').filter(|l| !l.is_empty()) {
            if n >= MAX_LABELS {
                // Over-cap input fails open, same as `check` — validation
                // upstream rejects these before they reach the handler.
                return false;
            }
            label_buf[n] = label;
            n += 1;
        }
        let labels: &[&str] = &label_buf[..n];

        let base_domain = match compute_base_domain(labels) {
            Some(b) => b,
            None => return false,
        };
        let base_label_count = base_domain.split('.').count();
        if labels.len() <= base_label_count {
            return false;
        }

        let p = self.params.load();

        // The exemption covers this gate too, not just the shape gates.
        // `exempt_domains` exists because a refusal here is unreachable
        // by any allow rule — and that is true of the rate gate for the
        // same reason it is true of `check`. An exemption honoured in
        // only one of the two would leave the operator with a dead end
        // they were told they had a remedy for.
        //
        // Checked before the bump, so an exempt name does not consume
        // its base domain's budget either.
        if !p.exempt_domains.is_empty() && is_exempt(domain, &p.exempt_domains) {
            return false;
        }

        let now_secs = self.created_at.elapsed().as_secs();
        let key = (*client_ip, base_domain);

        // Hashed *before* the shard guard is taken. `entry_or_insert_with`
        // hands back a DashMap shard WRITE guard held until this function
        // returns, so everything under it is a lock on the cache-miss
        // path; SipHash over the name has no business being there.
        let name = name_hash(domain);

        let tracker = self
            .subdomain_rates
            .entry_or_insert_with(key, || SubdomainTracker::new(now_secs));

        // Count distinct names, not calls. A name this bucket already
        // counted in the window is repetition — the exact opposite of
        // the unique-name fan-out this gate exists to detect — so it
        // neither bumps nor trips.
        //
        // Not tripping (rather than bumping-nothing-and-comparing) is a
        // decision, not an oversight: once a bucket is over budget, a
        // count-every-call gate REFUSEs every later miss under that base
        // for the rest of the window, repeats included, and that
        // collateral is half of what makes the defect visible. A
        // ring-resident name was
        // already answered in this window by construction, so letting it
        // be answered again grants no query the client has not already
        // made. Fan-out is untouched: every *new* name still bumps, and
        // still trips once the budget is spent.
        if tracker.recent.seen_or_record(name, now_secs, p.window_secs) {
            return false;
        }

        let prev_count = tracker.counter.check_and_bump(now_secs, p.window_secs);
        prev_count >= p.subdomain_rate_limit
    }

    /// Remove stale entries. Call periodically from a background task.
    pub fn cleanup(&self) {
        let now_secs = self.created_at.elapsed().as_secs();
        let stale = self.params.load().window_secs * 2;

        self.subdomain_rates.retain(|_, tracker| {
            let ws = tracker.counter.window_start_secs();
            now_secs.saturating_sub(ws) < stale
        });
    }
}

/// Compute Shannon entropy of a string in bits per character.
///
/// Higher entropy = more random-looking. Normal English text ~2.5-3.0,
/// base64/hex data ~3.5-4.5, fully random ~5.0+.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    shannon_entropy_bytes(s.bytes(), s.len())
}

/// Shannon entropy from a byte iterator. `total_len` must equal the
/// iterator's byte count (callers know this without re-traversing).
///
/// Lets the tunneling detector compute concatenated-label entropy
/// without materializing the joined string — saves one heap allocation
/// per query when entropy is checked.
pub fn shannon_entropy_bytes(bytes: impl Iterator<Item = u8>, total_len: usize) -> f64 {
    if total_len == 0 {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for b in bytes {
        freq[b as usize] += 1;
    }
    let len = total_len as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shipped defaults, with only `subdomain_rate` lowered so rate
    /// tests trip in a handful of calls instead of 50.
    ///
    /// Deliberately an **exhaustive struct literal, not
    /// `..Default::default()`** — it is the trip-wire that forces a new
    /// `TunnelingConfig` field to be considered here rather than
    /// silently inheriting a default in every test. (It earned its keep:
    /// it broke the build the moment `max_unbroken_run`,
    /// `entropy_min_len` and `exempt_domains` were added.) Keep it the
    /// *only* such literal in the module; a second one is maintenance
    /// with no extra signal.
    fn test_config() -> TunnelingConfig {
        TunnelingConfig {
            enabled: true,
            entropy_threshold: 3.5,
            label_len_threshold: 48,
            max_unbroken_run: 40,
            entropy_min_len: 64,
            subdomain_rate: 10,
            window_secs: 60,
            exempt_domains: Vec::new(),
        }
    }

    // --- shannon_entropy ---

    #[test]
    fn entropy_empty_string() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn entropy_single_char_repeated() {
        assert_eq!(shannon_entropy("aaaa"), 0.0);
    }

    #[test]
    fn entropy_normal_domain_label() {
        // "google" — low entropy, few unique chars
        let e = shannon_entropy("google");
        assert!(e < 2.5, "expected <2.5, got {e}");
    }

    #[test]
    fn entropy_base64_like() {
        // Simulated base64 tunneling label
        let e = shannon_entropy("aHR0cHM6Ly9leGFtcGxlLmNv");
        assert!(e > 3.5, "expected >3.5, got {e}");
    }

    #[test]
    fn entropy_hex_string() {
        let e = shannon_entropy("4a6f686e446f65313233");
        assert!(e > 3.0, "expected >3.0, got {e}");
    }

    // --- tunneling detection ---

    #[test]
    fn clean_normal_domain() {
        let d = TunnelingDetector::new(&test_config());
        assert_eq!(d.check("www.google.com"), TunnelingVerdict::Clean);
    }

    #[test]
    fn clean_short_domain() {
        let d = TunnelingDetector::new(&test_config());
        assert_eq!(d.check("example.com"), TunnelingVerdict::Clean);
    }

    #[test]
    fn suspicious_long_label() {
        let d = TunnelingDetector::new(&test_config());
        let long_label = "a".repeat(48);
        let domain = format!("{long_label}.tunnel.example.com");
        assert_eq!(d.check(&domain), TunnelingVerdict::Suspicious);
    }

    /// The length gate is inclusive (`>=`), and the boundary is the whole
    /// point of raising it from 30 to 48: the 43-char AWS ELB name
    /// `apiproxy-device-prod-nlb-4-1f9e6a56738a49ec` is legitimate and
    /// must clear it. Pins both sides so a future "tighten it a bit"
    /// has to break a test to happen.
    #[test]
    fn length_gate_boundary_is_inclusive_and_clears_real_elb_names() {
        let d = TunnelingDetector::new(&test_config());
        // Runs of 10 so only the LENGTH gate can fire — a plain "a"*47
        // would trip the run gate instead and prove nothing about length.
        let hyphenated = |total: usize| -> String {
            (0..total)
                .map(|i| if i % 11 == 10 { '-' } else { 'a' })
                .collect()
        };
        assert_eq!(
            d.check(&format!("{}.tunnel.example.com", hyphenated(48))),
            TunnelingVerdict::Suspicious
        );
        assert_eq!(
            d.check(&format!("{}.tunnel.example.com", hyphenated(47))),
            TunnelingVerdict::Clean
        );
        // 43 chars, measured on live traffic, not invented.
        assert_eq!(
            d.check("apiproxy-device-prod-nlb-4-1f9e6a56738a49ec.elb.us-east-1.amazonaws.com"),
            TunnelingVerdict::Clean,
            "a real AWS ELB hostname must not be refused"
        );
    }

    /// **Deliberate posture reduction — do not "fix" this test.**
    ///
    /// This name (`aHR0cHM6Ly9leGFtcGxl`, base64-shaped, 20 chars) used
    /// to be `Suspicious` via the concatenated-entropy gate. It is now
    /// `Clean` on shape, because that gate is what refused 92% of one
    /// live server's traffic — including ordinary Apple, PlayStation and
    /// AWS hostnames — while being blind to any tunnel encoding with 11
    /// or fewer distinct symbols (`H <= log2(alphabet)`).
    ///
    /// A short high-entropy label is now the rate gate's problem:
    /// exfiltration needs a *stream* of such names, and
    /// `seven_byte_chunk_flood_caught_by_rate_limit` pins that path.
    #[test]
    fn short_high_entropy_label_is_clean_on_shape() {
        let d = TunnelingDetector::new(&test_config());
        assert_eq!(
            d.check("aHR0cHM6Ly9leGFtcGxl.tunnel.example.com"),
            TunnelingVerdict::Clean,
            "entropy must not fire below entropy_min_len"
        );
    }

    /// The entropy backstop is *not* dead — it still fires once the
    /// concatenation is long enough that entropy stops being a proxy for
    /// length. Guards against a future edit that removes the gate
    /// entirely rather than raising its floor.
    #[test]
    fn entropy_backstop_still_fires_above_min_len() {
        let mut cfg = test_config();
        // Neutralise the two shape gates so only entropy can flag.
        cfg.label_len_threshold = 64;
        cfg.max_unbroken_run = 64;
        let d = TunnelingDetector::new(&cfg);
        // 7 x 10 base32-ish chars, plus the `tun` label = 73 concatenated,
        // above entropy_min_len (64). Every label is 10 chars, so neither
        // shape gate can fire even at their real defaults.
        let payload = [
            "mfrggzdfmz",
            "twq2lknnwg",
            "23tpobyxg4",
            "3uobzgk5df",
            "nzscaylsmv",
            "zxg43tpoby",
            "wq4dbnfxg2",
        ]
        .join(".");
        let domain = format!("{payload}.tun.example.com");
        assert_eq!(d.check(&domain), TunnelingVerdict::Suspicious);
    }

    #[test]
    fn clean_short_high_entropy_label() {
        // Well below entropy_min_len — entropy is never even computed.
        let d = TunnelingDetector::new(&test_config());
        assert_eq!(d.check("abcd.example.com"), TunnelingVerdict::Clean);
    }

    fn client(last: u8) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, last))
    }

    #[test]
    fn subdomain_rate_triggers() {
        let mut config = test_config();
        config.subdomain_rate = 5;
        let d = TunnelingDetector::new(&config);
        let ip = client(10);

        // First 5 unique subdomains should be fine
        for i in 0..5 {
            let domain = format!("sub{i}.tunnel.example.com");
            assert!(!d.check_rate(&ip, &domain), "query {i}");
        }

        // 6th should trigger
        assert!(d.check_rate(&ip, "sub5.tunnel.example.com"));
    }

    #[test]
    fn subdomain_rate_per_base_domain() {
        let mut config = test_config();
        config.subdomain_rate = 3;
        let d = TunnelingDetector::new(&config);
        let ip = client(10);

        // Exhaust rate for example.com
        for i in 0..3 {
            d.check_rate(&ip, &format!("s{i}.sub.example.com"));
        }
        assert!(d.check_rate(&ip, "s99.sub.example.com"));

        // other.com should still be clean
        assert!(!d.check_rate(&ip, "s0.sub.other.com"));
    }

    /// Regression: the rate bucket is keyed per `(client, base)` — one
    /// client exhausting a base's budget must not REFUSE the same base
    /// for every other device on the LAN. If the key were the base
    /// alone, >limit aggregate queries to a popular base would flip it
    /// to Suspicious network-wide.
    #[test]
    fn subdomain_rate_isolated_per_client() {
        let mut config = test_config();
        config.subdomain_rate = 3;
        let d = TunnelingDetector::new(&config);

        // Client A exhausts the budget for example.com.
        for i in 0..4 {
            d.check_rate(&client(10), &format!("a{i}.cdn.example.com"));
        }
        assert!(d.check_rate(&client(10), "a9.cdn.example.com"));

        // Client B on the same base still has a full budget.
        assert!(!d.check_rate(&client(20), "b0.cdn.example.com"));
    }

    /// `check` is shape-only — arbitrary repeat volume through it must
    /// never flip a low-entropy name to Suspicious (the rate heuristic
    /// lives in `check_rate`, bumped on cache misses only).
    #[test]
    fn shape_check_never_trips_on_volume() {
        let mut config = test_config();
        config.subdomain_rate = 5;
        let d = TunnelingDetector::new(&config);

        for _ in 0..100 {
            assert_eq!(d.check("www.tunnel.example.com"), TunnelingVerdict::Clean);
        }
        assert_eq!(
            d.entry_count(),
            0,
            "shape check must not touch the rate map"
        );
    }

    // --- eTLD+1 base-domain computation ---

    /// ICANN two-label suffixes must be treated as suffixes, so `foo.co.uk`
    /// is the base domain rather than `co.uk` itself. Without this each
    /// attacker subdomain would bucket under its own 2LD and per-base rate
    /// limiting would be defeated.
    ///
    /// **`github.io` is deliberately no longer in that set** — see
    /// `a_private_section_suffix_is_no_longer_a_suffix` for the behaviour
    /// change and what it costs. This test now covers only the ICANN entries,
    /// which are structural facts about DNS rather than a vendor's statement
    /// about its own product.
    #[test]
    fn compute_base_domain_handles_two_label_public_suffixes() {
        assert_eq!(
            compute_base_domain(&["www", "example", "co", "uk"]),
            Some(CompactString::from("example.co.uk"))
        );
        assert_eq!(
            compute_base_domain(&["sub", "foo", "com", "au"]),
            Some(CompactString::from("foo.com.au"))
        );
        assert_eq!(
            compute_base_domain(&["a", "b", "ac", "jp"]),
            Some(CompactString::from("b.ac.jp"))
        );
    }

    /// `neutrality-05` removed the 12 PSL *private*-section entries. This pins
    /// what that changed, rather than letting it be discovered in production.
    ///
    /// A private-section entry is a vendor's submission about its own product,
    /// not a fact about DNS. Compiled into the binary it is stale by
    /// construction — the platform list churns, and an operator cannot correct
    /// it without a new build. So warden no longer knows `github.io` is a
    /// multi-tenant host, and `victim.github.io` is an ordinary subdomain of
    /// the eTLD+1 `github.io`.
    ///
    /// # What this costs, stated plainly
    ///
    /// Every tenant on such a platform now shares **one** rate-limit bucket,
    /// so one abusive tenant can consume the budget for all of them. That is a
    /// real availability trade-off, accepted because the alternative is warden
    /// carrying an opinion about named companies that only a release can
    /// update.
    ///
    /// **The remedy is the operator's, which is the point:**
    /// `tunneling.exempt_domains` takes the platforms that particular
    /// household actually uses. Config beats a compiled-in list — visible,
    /// overridable, and correct for that operator rather than for the average
    /// of all of them.
    #[test]
    fn a_private_section_suffix_is_no_longer_a_suffix() {
        assert_eq!(
            compute_base_domain(&["victim", "github", "io"]),
            Some(CompactString::from("github.io")),
            "github.io is an ordinary eTLD+1 now; if this reads victim.github.io \
             a private-section entry has been reintroduced"
        );
        // The ICANN neighbour in the same table is unaffected — the two
        // classes stay distinguishable, which is the whole basis of the split.
        assert_eq!(
            compute_base_domain(&["victim", "example", "co", "uk"]),
            Some(CompactString::from("example.co.uk"))
        );
    }

    #[test]
    fn compute_base_domain_falls_back_to_two_labels_for_standard_tlds() {
        assert_eq!(
            compute_base_domain(&["sub", "example", "com"]),
            Some(CompactString::from("example.com"))
        );
        assert_eq!(
            compute_base_domain(&["example", "com"]),
            Some(CompactString::from("example.com"))
        );
    }

    #[test]
    fn compute_base_domain_none_for_too_few_labels() {
        assert_eq!(compute_base_domain(&["example"]), None);
        assert_eq!(compute_base_domain(&[]), None);
    }

    /// `MAX_TWO_LABEL_SUFFIX_LEN` must bound every entry, or the
    /// length-bail in `compute_base_domain` would skip the suffix probe
    /// for a legitimately-matching (longer) suffix. Adding a longer entry
    /// to `TWO_LABEL_SUFFIXES` without bumping the const trips this.
    #[test]
    fn two_label_suffix_len_bound() {
        let max = TWO_LABEL_SUFFIXES
            .iter()
            .map(|s| s.len())
            .max()
            .unwrap_or(0);
        // EQUALITY, not `<=`. The old one-sided assertion stayed green
        // when `neutrality-05` cut the longest entry from 16 B to 6 B,
        // leaving the probe guard three times looser than the table
        // needs — a bound that can only rot in silence is not a pin.
        // Equality also catches the dangerous direction: a constant set
        // below the longest entry makes that entry unreachable, and
        // `compute_base_domain` would skip the probe rather than fail.
        assert_eq!(
            max, MAX_TWO_LABEL_SUFFIX_LEN,
            "longest TWO_LABEL_SUFFIXES entry is {max} B but \
             MAX_TWO_LABEL_SUFFIX_LEN is {MAX_TWO_LABEL_SUFFIX_LEN} — \
             update the constant in the same commit as the table"
        );
    }

    /// `neutrality-05` — the twelve PSL *private*-section entries must
    /// not come back. Named here, in a test, which per CLAUDE.md
    /// §Neutrality is the right place for a vendor name: proving warden
    /// holds no opinion about them.
    #[test]
    fn neutrality05_no_private_section_suffix_in_the_table() {
        for retired in [
            "github.io",
            "gitlab.io",
            "herokuapp.com",
            "blogspot.com",
            "wordpress.com",
            "netlify.app",
            "vercel.app",
            "pages.dev",
            "web.app",
            "firebaseapp.com",
            "s3.amazonaws.com",
            "cloudfront.net",
        ] {
            assert!(
                !TWO_LABEL_SUFFIXES.contains(&retired),
                "{retired} is a PSL private-section entry — vendor-submitted, \
                 not a structural DNS fact"
            );
        }
    }

    /// The other half of the invariant, and the one that keeps the test
    /// above from being satisfied by deleting the whole table: the 30
    /// ICANN entries are legal and load-bearing, and must stay.
    #[test]
    fn neutrality05_icann_suffixes_survive() {
        for keep in ["co.uk", "ac.jp", "com.au", "gov.br", "org.nz", "edu.br"] {
            assert!(
                TWO_LABEL_SUFFIXES.contains(&keep),
                "{keep} is a genuine ICANN eTLD — removing it regresses \
                 eTLD+1 grouping and is not what neutrality-05 asked for"
            );
        }
        assert_eq!(
            TWO_LABEL_SUFFIXES.len(),
            30,
            "the table should hold exactly the 30 ICANN entries"
        );
    }

    /// The behaviour change, asserted rather than described: a name
    /// under a retired suffix now groups by its last two labels, so
    /// every site on that platform shares one bucket per client.
    ///
    /// This is the *stricter* direction — the module comment used to
    /// call the fallback "possibly too permissive", which is backwards
    /// for a per-base fan-out counter. Pinning it here means a future
    /// reader gets the real semantics from a test rather than from
    /// prose that drifted.
    #[test]
    fn neutrality05_retired_suffix_now_groups_by_last_two_labels() {
        let base = compute_base_domain(&["payload", "victim", "github", "io"]).unwrap();
        assert_eq!(
            base, "github.io",
            "with the private-section entry gone the base is the last two labels"
        );
        // Two different sites on the same platform now share a bucket.
        let other = compute_base_domain(&["payload", "other", "github", "io"]).unwrap();
        assert_eq!(base, other, "same bucket — this is the collateral");

        // Control arm: an ICANN entry still gets per-registrant grouping,
        // so the assertion above reflects the removal and not a broken
        // `compute_base_domain`.
        let uk = compute_base_domain(&["payload", "victim", "co", "uk"]).unwrap();
        assert_eq!(uk, "victim.co.uk");
    }

    /// Regression: adversarial last-two labels longer than any 2LD
    /// suffix must still fall back to the last-two-labels base (the
    /// length-bail skips the probe, never the fallback). Pins that the
    /// bail did not change base computation.
    #[test]
    fn compute_base_domain_long_last_two_labels_uses_two_label_base() {
        let long_a = "a".repeat(40);
        let long_b = "b".repeat(40);
        let labels = ["sub", long_a.as_str(), long_b.as_str()];
        let expected = CompactString::from(format!("{long_a}.{long_b}"));
        assert_eq!(compute_base_domain(&labels), Some(expected));
    }

    #[test]
    fn shannon_entropy_bytes_matches_string_form() {
        // Regression pin: the iterator-based shannon_entropy_bytes must
        // produce the same result as shannon_entropy(&str) for the same
        // byte sequence. The detector relies on this equivalence to swap
        // concat-then-entropy for stream-bytes-to-entropy without
        // changing detection semantics.
        let cases: &[&str] = &[
            "",
            "aaaa",
            "abcdef",
            "the quick brown fox",
            "ZGVhZGJlZWZkZWFkYmVlZg",
            "1234567890",
        ];
        for s in cases {
            let str_form = shannon_entropy(s);
            let bytes_form = shannon_entropy_bytes(s.bytes(), s.len());
            assert!(
                (str_form - bytes_form).abs() < 1e-12,
                "entropy mismatch for {s:?}: str={str_form}, bytes={bytes_form}"
            );
        }
    }

    #[test]
    fn shannon_entropy_bytes_chained_iterator_matches_concat_form() {
        // The concrete callsite chains label.bytes() across multiple
        // labels via flat_map. Verify the result equals the entropy of
        // the concatenated string. This guarantees the
        // detector's "concat → entropy" swap in the hot path is
        // semantically lossless.
        let labels: &[&str] = &["abcd", "efgh", "ijkl"];
        let total: usize = labels.iter().map(|l| l.len()).sum();
        let chained = shannon_entropy_bytes(labels.iter().flat_map(|l| l.bytes()), total);
        let concat = shannon_entropy(&labels.concat());
        assert!((chained - concat).abs() < 1e-12);
    }

    #[test]
    fn check_with_pathological_label_count_is_clean() {
        // Stack-array bound: a domain crafted with more labels than the
        // buffer holds must fail open (Clean) rather than panic on the
        // array index. Real traffic is filtered by validation::validate_query
        // first, so this is purely a defensive guard.
        let mut cfg = test_config();
        cfg.subdomain_rate = 100;
        let d = TunnelingDetector::new(&cfg);
        let huge = (0..MAX_LABELS + 5)
            .map(|i| format!("l{i}"))
            .collect::<Vec<_>>()
            .join(".");
        assert_eq!(d.check(&huge), TunnelingVerdict::Clean);
    }

    /// A name at the validator's deepest ceiling must still be *analysed*,
    /// not skipped. One label here is over `label_len_threshold`, so a
    /// buffer that fits the name returns Suspicious while a buffer that
    /// overflows returns Clean — the two are distinguishable, which a bare
    /// "is Clean" assertion would not be.
    ///
    /// At the old fixed buffer of 16 this name was never looked at, so
    /// padding a payload past 15 labels walked through the shape gate.
    #[test]
    fn name_at_the_validator_ceiling_is_still_analysed() {
        let mut cfg = test_config();
        cfg.subdomain_rate = 100;
        let d = TunnelingDetector::new(&cfg);
        let mut labels: Vec<String> = (0..31).map(|i| format!("l{i}")).collect();
        labels.push("a".repeat(60));
        labels.push("example".into());
        labels.push("com".into());
        let name = labels.join(".");
        assert_eq!(
            name.split('.').count(),
            crate::dns::validation::MAX_LABEL_COUNT_ARPA
        );
        assert_eq!(d.check(&name), TunnelingVerdict::Suspicious);
    }

    /// The other half of raising the buffer: a full IPv6 reverse name is the
    /// deepest legitimate name that exists, and it must not start being
    /// refused now that it fits. Its 32 nibbles concatenate to 32 bytes,
    /// under `entropy_min_len`, so the entropy backstop stays inert.
    #[test]
    fn full_ipv6_reverse_name_is_clean() {
        let mut cfg = test_config();
        cfg.subdomain_rate = 100;
        let d = TunnelingDetector::new(&cfg);
        let name = format!("{}ip6.arpa", "f.".repeat(32));
        assert_eq!(
            name.split('.').count(),
            crate::dns::validation::MAX_LABEL_COUNT_ARPA
        );
        assert_eq!(d.check(&name), TunnelingVerdict::Clean);
    }

    /// The rate-bucket half of the `neutrality-05` trade-off documented
    /// on [`TWO_LABEL_SUFFIXES`], kept as a test because it is the
    /// consequence an operator will actually feel.
    ///
    /// This test asserted the **opposite** while `github.io` was a
    /// compiled-in suffix: back then each tenant got its own bucket. It
    /// is not a suffix now, so every tenant on the platform shares one —
    /// three queries under `victim.github.io` exhaust the budget for
    /// `other.github.io` too.
    ///
    /// The ICANN case immediately below is the control: `co.uk` **is** still a
    /// suffix, so two registrants under it keep separate buckets. If both
    /// halves ever agree, either the private entries came back or the ICANN
    /// ones were lost, and the assertion messages say which.
    ///
    /// An operator who hosts on such a platform sets
    /// `tunneling.exempt_domains`. That is the neutral remedy, and it is
    /// better than the compiled list it replaces: it names the platforms that
    /// household uses, and it can be changed without a release.
    #[test]
    fn tenants_of_a_private_section_platform_now_share_one_bucket() {
        let mut config = test_config();
        config.subdomain_rate = 3;
        let d = TunnelingDetector::new(&config);
        let ip = client(10);

        // Three queries under victim.github.io eat the 3-query budget for the
        // whole of github.io, because that is now the base domain.
        d.check_rate(&ip, "a.victim.github.io");
        d.check_rate(&ip, "b.victim.github.io");
        d.check_rate(&ip, "c.victim.github.io");

        assert!(
            d.check_rate(&ip, "d.victim.github.io"),
            "the base-domain bucket must still fill and trip at all"
        );
        assert!(
            d.check_rate(&ip, "x.other.github.io"),
            "a DIFFERENT tenant on the same platform is now caught by the first \
             tenant's traffic — this is the neutrality-05 trade-off. If this is \
             clean, github.io has been reintroduced as a compiled-in suffix"
        );

        // Control: a genuine ICANN two-label suffix still separates
        // registrants, so the two classes have not been collapsed together.
        let d2 = TunnelingDetector::new(&config);
        let ip2 = client(11);
        d2.check_rate(&ip2, "a.victim.co.uk");
        d2.check_rate(&ip2, "b.victim.co.uk");
        d2.check_rate(&ip2, "c.victim.co.uk");
        assert!(d2.check_rate(&ip2, "d.victim.co.uk"), "budget must fill");
        assert!(
            !d2.check_rate(&ip2, "x.other.co.uk"),
            "a different registrant under an ICANN suffix must keep its own \
             bucket — losing this would be a real regression, not a trade-off"
        );
    }

    /// **Deliberate posture reduction — successor to the old
    /// `seven_byte_chunks_caught_by_concatenated_entropy`.**
    ///
    /// Chunked payloads whose concatenation stays under
    /// `entropy_min_len` are no longer caught by *shape*. The gate that
    /// used to catch them is the same one that refused
    /// `configuration.ls.apple.com` (entropy 3.507) and 4356 other
    /// legitimate queries in 8 days — it did not survive measurement.
    ///
    /// Kept as an explicit assertion rather than deleted, so the change
    /// is visible to whoever reads this module next: the defence for
    /// this shape is `seven_byte_chunk_flood_caught_by_rate_limit`,
    /// which pins that the *flood* still trips the per-`(client, base)`
    /// counter.
    #[test]
    fn seven_byte_chunks_are_clean_on_shape_and_left_to_the_rate_gate() {
        let d = TunnelingDetector::new(&test_config());
        assert_eq!(
            d.check("a1b2c3d.e4f5g6h.i7j8k9l.tunnel.example.com"),
            TunnelingVerdict::Clean,
            "21 concatenated chars is far below entropy_min_len"
        );
    }

    #[test]
    fn concurrent_first_subdomains_capped_at_subdomain_rate_limit() {
        // Regression pin: a naive get-then-insert would let two or more
        // concurrent fresh-base queries each pass the `get(...) = None`
        // check and each insert a fresh SubdomainTracker — the last
        // writer wins, but the per-base counter restarts at 1 on every
        // overwrite, lifting the effective per-base subdomain budget.
        // Mirrors `concurrent_first_queries_share_one_burst_budget` in
        // `rate_limiter.rs`.
        //
        // The rate path is `check_rate(client, domain)`: 8 distinct
        // fresh subdomains under the same (client, base) key, racing in
        // parallel. With `subdomain_rate = 2` exactly 2 should pass and
        // the rest trip.
        use std::sync::{Arc, Barrier};
        use std::thread;

        let mut config = test_config();
        config.subdomain_rate = 2;
        // Long window so the race never crosses a reset boundary.
        config.window_secs = 60;
        let detector = Arc::new(TunnelingDetector::new(&config));

        let threads = 8usize;
        let barrier = Arc::new(Barrier::new(threads));

        let handles: Vec<_> = (0..threads)
            .map(|i| {
                let detector = Arc::clone(&detector);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    // Distinct subdomain per thread, same client + base.
                    let domain = format!("h{i}.victim.example.com");
                    detector.check_rate(&client(10), &domain)
                })
            })
            .collect();

        let clean = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|tripped| !tripped)
            .count();

        assert_eq!(
            clean, 2,
            "TOCTOU regression: exactly subdomain_rate=2 concurrent fresh-base queries should pass, got {clean}"
        );
        assert_eq!(detector.entry_count(), 1);
    }

    /// Rate limit still catches volume even without high entropy.
    #[test]
    fn seven_byte_chunk_flood_caught_by_rate_limit() {
        let mut config = test_config();
        config.subdomain_rate = 5;
        let d = TunnelingDetector::new(&config);
        let ip = client(10);

        // Use labels 7 bytes each (low entropy, passes the shape check).
        for i in 0..5 {
            assert_eq!(
                d.check(&format!("abcdef{i}.tunnel.example.com")),
                TunnelingVerdict::Clean
            );
            d.check_rate(&ip, &format!("abcdef{i}.tunnel.example.com"));
        }
        // 6th unique (cache-missing) query should be caught by the rate limit.
        assert!(d.check_rate(&ip, "abcdef6.tunnel.example.com"));
    }

    // ── distinct-name counting ───────────────────────────────────────

    /// The gate counts **distinct names** in the window, not calls.
    ///
    /// This closes a real failure mode: a single legitimate name that
    /// polls frequently (short TTL, cache-missing every time) can drain
    /// a `(client, base)` bucket by itself and take its siblings down
    /// with it — REFUSED traffic that was never a tunnel.
    ///
    /// Counting calls instead of distinct names would trip this test on
    /// call 6. No prior test called `check_rate` twice with the same
    /// name, so the repeat-name semantics were pinned in neither
    /// direction — this is the first.
    #[test]
    fn repeated_name_never_trips_the_rate_gate() {
        let mut config = test_config();
        config.subdomain_rate = 5;
        let d = TunnelingDetector::new(&config);
        let ip = client(10);

        // Far past the budget: 200 calls against a limit of 5.
        for i in 0..200 {
            assert!(
                !d.check_rate(&ip, "ephemeralcounters.api.example.com"),
                "one name repeated is repetition, not fan-out — tripped on call {i}"
            );
        }
    }

    /// The other half of the same defect: a repeated name must not spend
    /// the budget its *siblings* need. This is the shape of the live
    /// incident — the flood was one name, the refusals landed on two
    /// others under the same base.
    ///
    /// Counting calls instead of distinct names, the 200 repeats alone
    /// would exhaust a budget of 5, so every sibling would be REFUSED
    /// on arrival.
    #[test]
    fn a_repeated_name_does_not_drain_its_siblings_budget() {
        let mut config = test_config();
        config.subdomain_rate = 5;
        let d = TunnelingDetector::new(&config);
        let ip = client(10);

        for _ in 0..200 {
            d.check_rate(&ip, "ephemeralcounters.api.example.com");
        }

        // The flood spent exactly one of the five slots. Four more
        // distinct names still fit.
        for sibling in ["groups", "metrics", "presence", "avatar"] {
            assert!(
                !d.check_rate(&ip, &format!("{sibling}.api.example.com")),
                "{sibling} must survive a sibling's repeat flood"
            );
        }

        // And the gate is still a gate: the 6th distinct name trips.
        assert!(
            d.check_rate(&ip, "thumbnails.api.example.com"),
            "distinct-name fan-out past the budget must still trip"
        );
    }

    /// The ring de-duplicates **within the window**, not forever. The
    /// counter resets every `window_secs`, so a name that repeats for
    /// hours must contribute roughly one bump per window — otherwise the
    /// first name a bucket ever sees would be permanently free.
    ///
    /// Exercised directly because `check_rate` reads the clock from
    /// `created_at.elapsed()` and cannot be moved through a window from a
    /// test.
    #[test]
    fn recent_names_ring_forgets_after_the_window() {
        let ring = RecentNames::new();
        let h = name_hash("ephemeralcounters.api.example.com");

        assert!(
            !ring.seen_or_record(h, 100, 60),
            "first sighting is counted"
        );
        assert!(
            ring.seen_or_record(h, 159, 60),
            "still inside the window — repetition"
        );
        assert!(
            !ring.seen_or_record(h, 160, 60),
            "window elapsed — the name counts again"
        );
    }

    /// Pins justification part 4: a slot collision can only *fail to
    /// suppress* a repeat (degrading to counting it as a fresh call),
    /// never suppress a name the ring has not seen. If this inverts, the
    /// ring starts hiding fan-out instead of hiding repetition.
    #[test]
    fn ring_displacement_fails_toward_counting_never_toward_suppressing() {
        let ring = RecentNames::new();
        // Same slot (low 3 bits = 0), different high bits.
        let a = 0x0000_0001_0000_0000u64;
        let b = 0x0000_0002_0000_0000u64;

        assert!(!ring.seen_or_record(a, 10, 60), "a is new");
        assert!(ring.seen_or_record(a, 10, 60), "a repeats — suppressed");
        assert!(!ring.seen_or_record(b, 10, 60), "b is new and displaces a");
        assert!(
            !ring.seen_or_record(a, 10, 60),
            "a was displaced, so it is counted again — the safe direction"
        );
    }

    /// Structural memory bound on the per-bucket state, modelled on
    /// `h_14_mac_mismatch_ring_is_structurally_bounded` in
    /// `profiles/resolver.rs`.
    ///
    /// `AtomicWindowCounter` (8 B) + `RECENT_NAME_SLOTS` × `AtomicU64`
    /// (64 B) = 72 B, inline, zero heap allocations. The bound is tight
    /// on purpose: the alternative design — a `HashSet` of seen names per
    /// bucket — would be up to [`MAX_TRACKED_BASE_DOMAINS`] independent
    /// jemalloc allocations reached from the DNS cache-miss path, and a
    /// loose bound here would not notice one arriving.
    #[test]
    fn subdomain_tracker_is_structurally_bounded() {
        assert!(
            std::mem::size_of::<SubdomainTracker>() <= 72,
            "SubdomainTracker must stay an inline counter + fixed ring \
             (8 B + 8 × 8 B), not a heap collection — got {} bytes",
            std::mem::size_of::<SubdomainTracker>(),
        );
    }

    // ── the `-`-free run gate ────────────────────────────────────────

    /// **Conservation, not gain.** The new predicate is a strict subset
    /// of the old one — everything below was already refused before this
    /// change. The point of these assertions is that retiring entropy
    /// did not cost the tool shapes it genuinely detected.
    #[test]
    fn run_gate_still_catches_real_tunnel_shapes() {
        let d = TunnelingDetector::new(&test_config());
        for (name, payload) in [
            (
                "iodine 3x63 base32",
                ["a".repeat(63), "b".repeat(63), "c".repeat(63)].join("."),
            ),
            (
                "dnscat2 2x60 hex",
                ["d".repeat(60), "e".repeat(60)].join("."),
            ),
            ("dns2tcp 1x40 hex", "f".repeat(40)),
        ] {
            let domain = format!("{payload}.tun.example.com");
            assert_eq!(
                d.check(&domain),
                TunnelingVerdict::Suspicious,
                "{name} must still be refused"
            );
        }
    }

    /// The run gate is inclusive at 40, and `-` breaks a run — that is
    /// the whole mechanism. `longest_unbroken_run` deliberately splits
    /// on `-` only, so an underscore (legal in DKIM/SRV names) does NOT
    /// break the run; pinned here because an `is_ascii_alphanumeric`
    /// implementation would silently disagree.
    #[test]
    fn run_gate_boundary_and_separators() {
        let d = TunnelingDetector::new(&test_config());
        assert_eq!(
            d.check(&format!("{}.tun.example.com", "a".repeat(40))),
            TunnelingVerdict::Suspicious
        );
        assert_eq!(
            d.check(&format!("{}.tun.example.com", "a".repeat(39))),
            TunnelingVerdict::Clean
        );
        // 44 chars total but every run is 10 — under the gate.
        let hyphenated = [
            "a".repeat(10),
            "b".repeat(10),
            "c".repeat(10),
            "d".repeat(10),
        ]
        .join("-");
        assert_eq!(
            d.check(&format!("{hyphenated}.tun.example.com")),
            TunnelingVerdict::Clean
        );
        assert_eq!(
            longest_unbroken_run("_dmarc_key_selector_padding_to_forty_ab"),
            39
        );
    }

    /// The user-facing regression: this exact name was REFUSED in
    /// production and no allow rule could reach it.
    #[test]
    fn the_name_that_started_this_resolves() {
        let d = TunnelingDetector::new(&test_config());
        assert_eq!(
            d.check("launcher-public-service-prod06.ol.epicgames.com"),
            TunnelingVerdict::Clean
        );
    }

    // ── exempt_domains ───────────────────────────────────────────────

    fn exempt_config(entries: &[&str]) -> TunnelingConfig {
        let mut c = test_config();
        c.exempt_domains = entries.iter().map(|s| s.to_string()).collect();
        c
    }

    /// The irreducible false positive: a 63-char hex label at the DNS
    /// ceiling, indistinguishable from a payload by shape alone. An
    /// exemption is the only remedy, which is why the key exists.
    #[test]
    fn exemption_clears_the_shape_gate() {
        let name = format!("{}.us-east-1.prod.minerva.devices.a2z.com", "0".repeat(63));
        assert_eq!(
            TunnelingDetector::new(&test_config()).check(&name),
            TunnelingVerdict::Suspicious
        );
        assert_eq!(
            TunnelingDetector::new(&exempt_config(&["minerva.devices.a2z.com"])).check(&name),
            TunnelingVerdict::Clean
        );
    }

    /// **The arm that must not match.** A suffix test without label
    /// anchoring lets an attacker register `evil-<exempt>` and inherit
    /// the operator's exemption. A probe whose every arm comes back
    /// exempt proves nothing.
    #[test]
    fn exemption_is_label_anchored() {
        let d = TunnelingDetector::new(&exempt_config(&["a2z.com"]));
        let payload = "0".repeat(63);

        assert_eq!(
            d.check(&format!("{payload}.x.a2z.com")),
            TunnelingVerdict::Clean,
            "a real subdomain of the exempt suffix is covered"
        );
        assert_eq!(
            d.check(&format!("{payload}.x.evil-a2z.com")),
            TunnelingVerdict::Suspicious,
            "a hyphen is not a label boundary — must NOT inherit the exemption"
        );
        assert_eq!(
            d.check(&format!("{payload}.a2z.com.attacker.net")),
            TunnelingVerdict::Suspicious,
            "the exempt string appearing mid-name must NOT match"
        );
        assert_eq!(
            d.check(&format!("{payload}.xa2z.com")),
            TunnelingVerdict::Suspicious,
            "a longer label ending in the exempt suffix must NOT match"
        );
    }

    /// The rate gate refuses names no allow rule can reach, exactly like
    /// the shape gate. An exemption honoured in only one of the two
    /// would hand the operator a remedy that half-works.
    #[test]
    fn exemption_covers_the_rate_gate_too() {
        let mut cfg = exempt_config(&["exempt.example.com"]);
        cfg.subdomain_rate = 3;
        let d = TunnelingDetector::new(&cfg);
        let ip = client(11);

        for i in 0..12 {
            assert!(
                !d.check_rate(&ip, &format!("n{i}.sub.exempt.example.com")),
                "exempt names must never trip the rate gate, even past the budget"
            );
        }
        // Control arm: the same volume under a non-exempt base does trip.
        for i in 0..3 {
            d.check_rate(&ip, &format!("n{i}.sub.other.example.com"));
        }
        assert!(d.check_rate(&ip, "n99.sub.other.example.com"));
    }

    // ── hot reload ───────────────────────────────────────────────────

    /// `warden security tunneling exempt …` must apply without a daemon
    /// restart — a restart costs ~30 s of downed DNS, which would make
    /// the escape hatch cost more than the false positive it fixes.
    ///
    /// Also pins that the swap preserves rate state: rebuilding the
    /// whole detector on reload would zero every counter and hand an
    /// attacker a fresh budget on each config edit.
    #[test]
    fn set_params_applies_without_restart_and_preserves_rate_buckets() {
        let mut cfg = test_config();
        cfg.subdomain_rate = 3;
        let d = TunnelingDetector::new(&cfg);
        let ip = client(12);
        let name = format!("{}.x.late.example.com", "0".repeat(63));

        assert_eq!(d.check(&name), TunnelingVerdict::Suspicious);
        for i in 0..3 {
            d.check_rate(&ip, &format!("n{i}.x.other.example.com"));
        }
        let buckets_before = d.entry_count();

        let mut updated = cfg.clone();
        updated.exempt_domains = vec!["late.example.com".to_string()];
        d.set_params(&updated);

        assert_eq!(
            d.check(&name),
            TunnelingVerdict::Clean,
            "the exemption must be live immediately after the swap"
        );
        assert_eq!(
            d.entry_count(),
            buckets_before,
            "a params swap must not drop rate buckets"
        );
        assert!(
            d.check_rate(&ip, "n99.x.other.example.com"),
            "the pre-swap budget must still be spent — no free reset on reload"
        );
    }

    // ── live-traffic corpus ──────────────────────────────────────────

    /// Replays every domain the *previous* predicate refused over 8 days
    /// of production traffic. 229 of 230 must now resolve.
    ///
    /// The fixture is generated from the measured log, not hand-picked:
    /// the design doc that preceded this change derived its thresholds
    /// from a 16-domain excerpt and landed on a run threshold of 28-32,
    /// which refuses `firebaseremoteconfigrealtime.googleapis.com`.
    /// A curated excerpt is how that happens.
    #[test]
    fn live_traffic_corpus_is_no_longer_refused() {
        let d = TunnelingDetector::new(&test_config());
        let raw = include_str!("../../tests/fixtures/tunneling_live_corpus.tsv");

        let mut checked = 0usize;
        let mut suspicious = 0usize;
        let mut wrong: Vec<String> = Vec::new();

        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (expected, domain) = line
                .split_once('\t')
                .unwrap_or_else(|| panic!("malformed fixture row: {line:?}"));
            let want = match expected {
                "CLEAN" => TunnelingVerdict::Clean,
                "SUSPICIOUS" => TunnelingVerdict::Suspicious,
                other => panic!("unknown expectation {other:?}"),
            };
            if want == TunnelingVerdict::Suspicious {
                suspicious += 1;
            }
            let got = d.check(domain);
            if got != want {
                wrong.push(format!("{domain}: want {want:?}, got {got:?}"));
            }
            checked += 1;
        }

        assert_eq!(checked, 230, "fixture size changed — re-derive, don't edit");
        assert!(
            suspicious >= 1,
            "a corpus with no Suspicious row would pass against a stub returning Clean"
        );
        assert!(
            wrong.is_empty(),
            "{} regressions:\n{}",
            wrong.len(),
            wrong.join("\n")
        );
    }
}
