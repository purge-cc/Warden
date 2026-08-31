//! Per-list runtime telemetry (Sprint 43 T1, DM3).
//!
//! Every blocklist source tracked by [`super::manager::ListManager`] gets a
//! [`ListStatus`] handle held behind an [`ArcSwap`]. On each refresh the
//! manager builds a fresh [`ListStatus`] from the parser's [`ParsedCounts`]
//! and the merged-map count delta, then atomically swaps it in. The IPC
//! layer reads the same registry to answer `IpcCommand::BlocklistStats`
//! without touching the manager itself — the registry is the single
//! authoritative seat for "what does the daemon think about list X right
//! now".
//!
//! `prev_entries` is the supply-chain canary anchor: it is persisted to
//! `data/list_stats.json` (atomic write, same pattern as `stats.json`) so
//! a daemon restart still has the previous-cycle entry count for the
//! delta calculation. Without persistence the first refresh after every
//! restart would emit `delta_pct_vs_prev = None` and a list that
//! suddenly grew 1000x would slip through unnoticed for one cycle.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::config::schema::id::Id;
use crate::config::schema::Blocklist;

/// Hard cap on the number of skipped-line samples retained per list.
///
/// The counter [`ListStatus::parsed_skipped`] itself is unbounded — only
/// the sample strings are capped. 32 lines is enough to surface a pattern
/// (e.g. "every line in this list starts with `||`, parser is wrong
/// format") without unbounded memory growth on a malicious or
/// misconfigured upstream.
pub const MAX_SKIPPED_SAMPLES: usize = 32;

/// Hard cap on the byte length of each retained skipped-line sample.
///
/// [`MAX_SKIPPED_SAMPLES`] bounds the *number* of samples; this bounds
/// each sample's *length*. Without it, a hostile list body with no `\n`
/// makes `str::lines()` yield the entire body (up to `max_body_bytes`,
/// default 200 MB) as a single "line", and `push_skipped` would park
/// that whole blob in the `ArcSwap` status registry — re-cloned in full
/// on every IPC stats read. A sample is only a diagnostic hint ("every
/// line starts with `||`, wrong format detected"), so the first ~256
/// bytes carry all the signal.
pub const MAX_SKIPPED_SAMPLE_BYTES: usize = 256;

/// Truncate a skipped-line sample to [`MAX_SKIPPED_SAMPLE_BYTES`] on a
/// UTF-8 char boundary, appending `…` when the line was clipped. Bounds
/// the per-sample memory cost of attacker-controlled list content.
fn truncate_sample(line: &str) -> String {
    if line.len() <= MAX_SKIPPED_SAMPLE_BYTES {
        return line.to_string();
    }
    // Walk back to the largest char boundary at or below the cap so the
    // slice stays valid UTF-8 (a fixed byte cut could land mid-character).
    let mut end = MAX_SKIPPED_SAMPLE_BYTES;
    while end > 0 && !line.is_char_boundary(end) {
        end -= 1;
    }
    let mut sample = String::with_capacity(end + '…'.len_utf8());
    sample.push_str(&line[..end]);
    sample.push('…');
    sample
}

/// Counts produced by a parser pass over a single list body.
///
/// The manager merges these into a [`ListStatus`] post-refresh. Kept
/// separate from `ListStatus` because a parser doesn't know `entries`
/// (the merged-map count delta) — that's a manager-side concern.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedCounts {
    /// Lines successfully parsed and forwarded to the merged map. Pre-dedup —
    /// the merged map drops collisions, so `parsed_ok` may exceed the actual
    /// entry-count contribution to the merged map.
    pub parsed_ok: u64,
    /// Distinct domains in this source's own body, per this source's bit —
    /// i.e. `parsed_ok` minus this source's in-list duplicates and minus the
    /// lines whose domain already carried this source's bit. Order- and
    /// duplicate-independent, unlike both `parsed_ok` (pre-dedup, inflatable)
    /// and the manager's `entries` (net-new merged-map delta, sensitive to
    /// source iteration order). The retention guard
    /// ([`super::manager::ListManager::refresh`]) trips on a catastrophic
    /// drop in this value versus the prior cycle.
    pub unique_domains: u64,
    /// Lines rejected by the parser: invalid domain shape, sandboxed rule
    /// kind (allow / regex / wildcard for AdGuard external lists), comment
    /// lines do NOT count here.
    pub parsed_skipped: u64,
    /// Up to [`MAX_SKIPPED_SAMPLES`] verbatim sample lines that were
    /// skipped, in encounter order. Useful for the operator to spot the
    /// "wrong format detected" failure mode. Counter is unbounded; this
    /// vec is hard-capped.
    pub parsed_skipped_samples: Vec<String>,
    /// Entries this source offered *after* `max_entries` was already
    /// reached, i.e. domains the cap dropped on the floor.
    ///
    /// Non-zero means the operator is under-covered by exactly this much
    /// and every other counter still looks healthy: the source fetched,
    /// parsed and reported `Ok`. Before this existed the live daemon
    /// dropped 2,370,261 domains (19% of the corpus) while printing
    /// `lists: 8/8 sources active`.
    ///
    /// **Counts validated domains, never candidate lines.** The cap test
    /// sits after the format extractor and after `is_valid_domain`, so
    /// structural noise a format discards — a hosts row with no
    /// `0.0.0.0`/`127.0.0.1` prefix, a loopback alias, a non-`||` AdGuard
    /// line — is never charged here. That bound is load-bearing now that
    /// the cap fails closed: a source whose *domains* stay under the cap
    /// must not lose its entire body because its *lines* ran past it.
    /// Until S2 the spill producer ran a private copy of the parse
    /// skeleton whose check sat ahead of extraction and counted candidate
    /// lines; that copy is gone and this is the one definition.
    ///
    /// Still pre-dedup, symmetric with [`Self::parsed_ok`]: a domain
    /// repeated past the cap counts once per occurrence.
    pub parsed_truncated: u64,
}

impl ParsedCounts {
    /// Record a skipped line. Always increments the counter; pushes the
    /// sample text only while the cap allows.
    pub fn push_skipped(&mut self, line: &str) {
        self.parsed_skipped += 1;
        if self.parsed_skipped_samples.len() < MAX_SKIPPED_SAMPLES {
            self.parsed_skipped_samples.push(truncate_sample(line));
        }
    }
}

/// Outcome of the most recent refresh attempt for a list.
///
/// `Failed` carries the reason as a String so the operator can read it
/// directly in `warden blocklist show` (T2) or the TUI Lists tab (T2).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LastOutcome {
    /// Boot state: no refresh has run yet for this source.
    #[default]
    NeverFetched,
    /// Latest refresh succeeded (200 OK or 304 Not Modified).
    Ok,
    /// Latest refresh failed; `reason` is a one-line operator-readable error.
    Failed { reason: String },
}

/// Per-list runtime telemetry — DM3 in `_docs/features/lists_management.md`.
///
/// Held behind an `ArcSwap` per source, replaced atomically on every
/// refresh. The IPC layer takes a `load_full()` snapshot to build the
/// `BlocklistStatusDto` returned to clients.
///
/// `entries` is the primary metric (D1). `parsed_ok` and `parsed_skipped`
/// surface why a list might have a lower-than-expected entry count.
/// `delta_pct_vs_prev` is the supply-chain canary; the retention guard's
/// accept path now alarms on it via [`BLOCKLIST_DELTA_WARN`] (rev-2606 §06
/// `status-01` — the doc-promised wiring that S43 T6 never delivered).
///
/// No `Eq` derive: `delta_pct_vs_prev: Option<f32>` is intentionally a
/// float for percentage arithmetic; tests use field-by-field comparisons
/// or the `PartialEq` derive when a strict equality is needed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ListStatus {
    /// Domains this source was the **first** to put into the merged
    /// blocklist map — its net-new contribution, not its size. Counted in
    /// the `Vacant` arm of the shard build, so a domain an earlier source
    /// already contributed is charged to that source and not to this one:
    /// two sources with identical bodies report the full count and zero,
    /// in iteration order. Primary D1 metric. Contrast
    /// [`Self::unique_domains`], which ignores every other source.
    pub entries: u64,
    /// Lines successfully parsed (pre-dedup, see [`ParsedCounts::parsed_ok`]).
    pub parsed_ok: u64,
    /// Distinct domains in **this source's own body**, whatever any other
    /// source carries (see [`ParsedCounts::unique_domains`]) — so unlike
    /// [`Self::entries`] it does not shrink when a list earlier in
    /// iteration order happens to hold the same domains. The
    /// retention-guard
    /// baseline: a successful refresh records the fresh value, a failed
    /// or guard-tripped refresh carries forward the last-good value via
    /// [`Self::from_failure`]. `#[serde(default)]` so a `list_stats.json`
    /// or IPC payload written by a pre-guard binary deserialises with
    /// this at `0` (treated as "no baseline" → first-fetch-accept).
    #[serde(default)]
    pub unique_domains: u64,
    /// Lines skipped by the parser.
    pub parsed_skipped: u64,
    /// Up to [`MAX_SKIPPED_SAMPLES`] sample skipped lines.
    pub parsed_skipped_samples: Vec<String>,
    /// Domains this source offered past `max_entries` and the cap threw
    /// away (see [`ParsedCounts::parsed_truncated`]). `> 0` means the
    /// operator is silently under-covered by that many entries.
    ///
    /// `#[serde(default)]` for the same reason as `unique_domains`: the
    /// live daemon's `data/list_stats.json` was written by a binary that
    /// predates this field, and a missing key must deserialise to `0`
    /// ("nothing known to be truncated") rather than fail the whole
    /// stats load on the first restart after deploy.
    #[serde(default)]
    pub parsed_truncated: u64,
    /// RFC 3339 timestamp of the most recent refresh attempt — set on both
    /// success AND failure so the operator can see "the daemon tried at
    /// 14:02 but it failed". `None` until the first attempt completes.
    #[serde(default, with = "rfc3339_option")]
    pub fetched_at: Option<OffsetDateTime>,
    /// Outcome of the most recent refresh.
    pub last_outcome: LastOutcome,
    /// `(entries - prev_entries) / prev_entries * 100`. `None` on the first
    /// successful refresh after boot, or when `prev_entries` is zero
    /// (delta is undefined; pretend "no comparison").
    pub delta_pct_vs_prev: Option<f32>,
    /// Entry count from the previous successful refresh. Persisted to
    /// `data/list_stats.json` so the delta survives daemon restart.
    pub prev_entries: Option<u64>,
    /// §4.7 Phase 2 T2: RFC 3339 timestamp of the most recent
    /// **successful** refresh — distinct from [`Self::fetched_at`]
    /// which records the most recent *attempt* (success or failure).
    /// `None` until the first successful refresh completes;
    /// preserved across subsequent failures so the TUI stale badge
    /// can compare against "last-known-good", not "last tried".
    ///
    /// `#[serde(default)]` for back-compat: a pre-Phase-2 daemon's
    /// `ListStatus` payload deserialises with this field at `None`,
    /// which makes the TUI suppress the badge (correct degradation).
    #[serde(default, with = "rfc3339_option")]
    pub last_refresh_at: Option<OffsetDateTime>,
}

mod rfc3339_option {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(t: &Option<OffsetDateTime>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match t {
            Some(ts) => {
                let formatted = ts
                    .format(&Rfc3339)
                    .map_err(|e| serde::ser::Error::custom(e.to_string()))?;
                s.serialize_str(&formatted)
            }
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Option<OffsetDateTime>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(d)?;
        match opt {
            Some(s) => OffsetDateTime::parse(&s, &Rfc3339)
                .map(Some)
                .map_err(|e| serde::de::Error::custom(e.to_string())),
            None => Ok(None),
        }
    }
}

impl ListStatus {
    /// Build a fresh status from a successful refresh.
    ///
    /// `prev` is the prior status (or `None` on boot before persistence
    /// loaded). `prev_entries` is read from `prev` so a chain of refreshes
    /// always reports the delta against the *immediately* prior cycle, not
    /// some ancestor cycle.
    pub fn from_refresh(
        entries: u64,
        counts: ParsedCounts,
        prev: Option<&ListStatus>,
        fetched_at: OffsetDateTime,
    ) -> Self {
        let prev_entries = prev.and_then(|p| {
            // Prefer the prior cycle's `entries`. Fall back to the prior
            // `prev_entries` only if the prior cycle has not yet had a
            // successful refresh (entries == 0 + NeverFetched). This
            // covers the path where persistence loaded a `prev_entries`
            // before any refresh ran.
            match (&p.last_outcome, p.entries) {
                (LastOutcome::Ok, n) if n > 0 => Some(n),
                _ => p.prev_entries,
            }
        });
        let delta_pct_vs_prev = prev_entries.and_then(|pe| compute_delta_pct(entries, pe));
        Self {
            entries,
            parsed_ok: counts.parsed_ok,
            unique_domains: counts.unique_domains,
            parsed_skipped: counts.parsed_skipped,
            parsed_skipped_samples: counts.parsed_skipped_samples,
            parsed_truncated: counts.parsed_truncated,
            fetched_at: Some(fetched_at),
            last_outcome: LastOutcome::Ok,
            delta_pct_vs_prev,
            prev_entries,
            // §4.7 Phase 2 T2: success path stamps "last good" alongside
            // the attempt timestamp. `from_failure` carries this forward.
            last_refresh_at: Some(fetched_at),
        }
    }

    /// Build a status for a failed refresh.
    ///
    /// Carries forward `entries`, `parsed_ok`, `parsed_skipped`, and
    /// `prev_entries` from the previous successful refresh so the operator
    /// can still see "last good" data. Only `last_outcome` and
    /// `fetched_at` reflect the failure. `delta_pct_vs_prev` is cleared
    /// because the cycle didn't produce a fresh entry count to compare.
    pub fn from_failure(
        prev: Option<&ListStatus>,
        reason: String,
        fetched_at: OffsetDateTime,
    ) -> Self {
        let mut next = prev.cloned().unwrap_or_default();
        next.last_outcome = LastOutcome::Failed { reason };
        next.fetched_at = Some(fetched_at);
        next.delta_pct_vs_prev = None;
        next
    }
}

/// rev-2606 §06 `status-01`: the supply-chain delta canary warning.
///
/// The [`ListStatus`] doc-comment long promised "T6 wires the
/// `BLOCKLIST_DELTA_WARN` frozen string against this", but the symbol was
/// never created — the canary was computed and surfaced pull-only (in
/// `warden blocklist show` / the TUI), so no daemon-side alarm ever fired.
/// This is that string. The retention guard's accept path emits it at
/// `warn!(target: "audit")` whenever a refresh is accepted but the
/// unique-domain count still swung by more than [`DELTA_WARN_THRESHOLD_PCT`]
/// versus the prior cycle — loud-but-allowed movement the operator should
/// see even though it stayed under the guard's refusal threshold.
pub const BLOCKLIST_DELTA_WARN: &str = "blocklist size changed sharply versus the previous refresh";

/// Absolute percentage swing in a source's unique-domain count past which
/// an *accepted* refresh still emits [`BLOCKLIST_DELTA_WARN`]. Strictly
/// below the guard's refusal threshold — this surfaces a large but
/// non-catastrophic change, not a refusal.
pub const DELTA_WARN_THRESHOLD_PCT: f32 = 50.0;

/// rev-2606 §06 `manager-01`: operator-facing `last_outcome` reason
/// stamped when the retention guard refuses a catastrophic shrink. Frozen
/// template — the live string substitutes the measured numbers. Surfaces
/// in `warden blocklist show` (`failed: …`) and the TUI Lists tab.
pub const BLOCKLIST_SHRINK_REFUSED: &str =
    "refresh refused: list shrank by {drop}% to {got} domains (was {kept}); \
     keeping the previous list — run `warden lists forget <source>` to accept";

/// Operator-facing `last_outcome` reason stamped when a source is refused
/// for exceeding its `max_entries` cap (step 3 of
/// `lists-truncation-silent-19pct`). Frozen template — the live string
/// substitutes the measured numbers.
///
/// Fail-closed is the point. A truncated list passes every sanity check
/// the daemon has — it fetched, it parsed, its entry count is plausible —
/// while the guarantee it exists to provide is already broken, and broken
/// *deterministically*: the sources are roughly alphabetical, so the cut
/// is a cliff, not a sample. Anyone who knows the cap can pick a
/// late-alphabet domain and be guaranteed through. Half a blocklist is
/// not a degraded blocklist, it is a blocklist with a published bypass.
pub const BLOCKLIST_TRUNCATION_REFUSED: &str =
    "refresh refused: list exceeded max_entries ({cap}) and would have dropped {dropped} \
     entries; keeping the previous list — raise `max_entries` for this source";

/// Substitute the measured numbers into [`BLOCKLIST_TRUNCATION_REFUSED`].
pub fn format_blocklist_truncation_refused(cap: usize, dropped: u64) -> String {
    BLOCKLIST_TRUNCATION_REFUSED
        .replace("{cap}", &cap.to_string())
        .replace("{dropped}", &dropped.to_string())
}

/// Substitute the measured drop into [`BLOCKLIST_SHRINK_REFUSED`].
pub fn format_blocklist_shrink_refused(drop_pct: u32, got: u64, kept: u64) -> String {
    BLOCKLIST_SHRINK_REFUSED
        .replace("{drop}", &drop_pct.to_string())
        .replace("{got}", &got.to_string())
        .replace("{kept}", &kept.to_string())
}

/// Compute `(entries - prev_entries) / prev_entries * 100`.
///
/// Returns `None` when `prev_entries == 0` to avoid the division-by-zero
/// trap. The semantic interpretation: "we have nothing to compare
/// against, don't show a delta" — which is what the TUI / CLI surface
/// in T2 is going to render as `—`.
pub fn compute_delta_pct(entries: u64, prev_entries: u64) -> Option<f32> {
    if prev_entries == 0 {
        return None;
    }
    let cur = entries as f64;
    let prev = prev_entries as f64;
    Some(((cur - prev) / prev * 100.0) as f32)
}

/// IPC wire shape for [`ListStatus`].
///
/// Bridges the in-memory struct to a stable Serialize/Deserialize form.
/// Serializes `fetched_at` as an RFC 3339 string for human readability
/// (matches the `.meta` sidecar files). `id` is filled in by the IPC
/// handler from `slug_to_id` so the operator can correlate the source
/// string (legacy slug like `"privacy/ads"` or raw URL) with the v1
/// `[[blocklists]].id`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct BlocklistStatusDto {
    /// Source string as it appears in `[lists].sources` — legacy
    /// slug-form (`"privacy/ads"`) or raw URL.
    pub source: String,
    /// Canonical `[[blocklists]].id` resolved via `slug_to_id`. `None`
    /// when the source has no v1 entry (raw URL, or the slug isn't in
    /// the map yet).
    pub id: Option<String>,
    pub entries: u64,
    pub parsed_ok: u64,
    pub parsed_skipped: u64,
    pub parsed_skipped_samples: Vec<String>,
    /// Entries the `max_entries` cap discarded on the last refresh (see
    /// [`ListStatus::parsed_truncated`]). `> 0` means this source is
    /// loaded only in part while still reporting `ok`.
    ///
    /// `#[serde(default)]` so a new CLI reading a pre-truncation-counter
    /// daemon's response decodes `0` rather than failing the whole
    /// `blocklist show` — same contract as every other added field here.
    #[serde(default)]
    pub parsed_truncated: u64,
    /// RFC 3339 timestamp; `None` until first refresh.
    pub fetched_at: Option<String>,
    /// `LastOutcome` rendered as one of `"never_fetched"`, `"ok"`, or
    /// `"failed: <reason>"` for direct CLI / TUI display.
    pub last_outcome: String,
    pub delta_pct_vs_prev: Option<f32>,
    pub prev_entries: Option<u64>,
    /// §4.7 Phase 2 T2: RFC 3339 timestamp of the most recent
    /// *successful* refresh. `None` until the first success;
    /// preserved across subsequent failures (so the TUI stale badge
    /// reflects last-good, not last-attempted). `#[serde(default)]`
    /// keeps pre-Phase-2 payloads decodable — old daemons emit no
    /// field, new readers see `None`, badge suppressed.
    #[serde(default)]
    pub last_refresh_at: Option<String>,
}

impl BlocklistStatusDto {
    /// Build a DTO from a (source, status, optional canonical id) triple.
    pub fn from_status(source: String, id: Option<String>, status: &ListStatus) -> Self {
        let last_outcome = match &status.last_outcome {
            LastOutcome::NeverFetched => "never_fetched".to_string(),
            LastOutcome::Ok => "ok".to_string(),
            LastOutcome::Failed { reason } => format!("failed: {reason}"),
        };
        let fetched_at = status.fetched_at.and_then(|ts| ts.format(&Rfc3339).ok());
        let last_refresh_at = status
            .last_refresh_at
            .and_then(|ts| ts.format(&Rfc3339).ok());
        Self {
            source,
            id,
            entries: status.entries,
            parsed_ok: status.parsed_ok,
            parsed_skipped: status.parsed_skipped,
            parsed_skipped_samples: status.parsed_skipped_samples.clone(),
            parsed_truncated: status.parsed_truncated,
            fetched_at,
            last_outcome,
            delta_pct_vs_prev: status.delta_pct_vs_prev,
            prev_entries: status.prev_entries,
            last_refresh_at,
        }
    }
}

/// Per-source registry of [`ListStatus`] handles.
///
/// Seeded at boot from the configured `[lists].sources` and grown on
/// demand when the reload pipeline introduces a new source through the
/// merge bridge. Keys are the verbatim source strings the
/// [`super::manager::ListManager`] uses internally — legacy slugs
/// (`"privacy/ads"`) and raw URLs.
///
/// The outer `inner` map is wrapped in `ArcSwap<HashMap<...>>` so it can
/// grow without blocking readers: writers do a copy-on-write `rcu`
/// insert, readers go through `inner.load()` and walk the snapshot. Each
/// source slot is itself an `ArcSwap` so per-list status updates remain
/// lock-free even when the outer map is being grown.
///
/// Closes the §14.1 pitfall: pre-S53.2 the registry was a `HashMap`
/// fixed at boot, so reloads that added a new `[[blocklists]].url`
/// silently failed to surface stats for the new source until daemon
/// restart. Now `update()` self-heals — first write to an unknown
/// source materialises the slot.
/// A whole refresh cycle was refused because the merged **deduplicated**
/// corpus exceeded `[lists] max_total_domains`.
///
/// Cycle-level, and that is the entire point of it existing separately.
/// Every source in a refused cycle downloaded, parsed and reported `Ok`,
/// so no per-source field can express this state: `active/total` reads
/// `N/N sources active` while the daemon is serving the *previous*
/// generation. That is the same conflation of *downloaded and parsed*
/// with *installed and serving* that let `8/8 sources active` print while
/// 2,370,261 domains were being dropped, and an operator must not be able
/// to read a status line in this state and conclude they are covered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusRefusal {
    /// Deduplicated domains the refused corpus would have installed.
    pub unique: u64,
    /// The operator's configured ceiling it exceeded.
    pub ceiling: u64,
    /// Per source, domains whose first occurrence in merge order belonged
    /// to it — "which list would free the most room" — descending.
    ///
    /// **Order-dependent**, and said so wherever it is rendered: a domain
    /// shared by two sources is attributed wholly to whichever merged
    /// first. Sound as a diagnostic, and never an input to the refusal
    /// decision itself, which is taken on the order-independent union.
    pub novel_by_source: Vec<(String, u64)>,
}

/// What a completed reload cycle did to the corpus.
///
/// Exists because [`CorpusRefusal`] cannot answer the question a caller
/// actually has after triggering a refresh. It is an `Option`, so it has
/// two values, but there are **four** states after a SIGHUP:
///
/// | state | `corpus_refusal()` |
/// |---|---|
/// | finished, installed | `None` |
/// | finished, refused | `Some(..)` |
/// | not finished yet | `None` |
/// | skipped — inputs unchanged, live blocklist reused | `None` |
///
/// Three of the four read `None`, so polling that field is a verdict built
/// on absence: it cannot tell "installed" from "still running" from
/// "there was nothing to do". This type makes the distinction explicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CycleOutcome {
    /// A new generation was built and installed.
    Installed,
    /// The merged corpus exceeded the ceiling; the previous generation is
    /// still being served, and it will keep being served until the corpus
    /// shrinks or the ceiling rises. Filtering is not absent — it is FROZEN.
    Refused,
    /// The pipeline inputs were byte-identical, so no rebuild happened and
    /// the live blocklist was reused. A success, and information the caller
    /// wants: "nothing changed" and "a new corpus installed" are different
    /// answers to "what did my refresh do?".
    SkippedUnchanged,
    /// The config carried no list sources, so the blocklist was CLEARED.
    ///
    /// Its own variant rather than an `Installed` of size zero, because the
    /// two call for opposite reactions: one is a routine success, the other
    /// means this host is now filtering nothing. An operator who triggered a
    /// refresh and got "installed" would have no reason to look further.
    ClearedNoSources,
    /// The daemon read the new config and REFUSED it, so nothing was
    /// reloaded and the previous config is still in force.
    ///
    /// Recorded for the same reason the rest are: without it the reload ends
    /// with the counter untouched, and a caller waiting for it to advance
    /// waits out its whole timeout before reporting that it does not know —
    /// about a cycle the daemon closed, deliberately, and could describe.
    ConfigRejected,
}

/// A completed cycle: what it did, plus a monotonic sequence number.
///
/// The sequence number is the part that makes polling sound. A caller reads
/// it before signalling and waits for it to change; only then is the
/// outcome the outcome of *their* cycle rather than of whatever ran last.
/// A completed cycle: what it did, plus a monotonic sequence number.
///
/// The sequence number is the part that makes polling sound. A caller reads
/// it before signalling and waits for it to change; only then is the
/// outcome the outcome of *their* cycle rather than of whatever ran last.
///
/// **`outcome` is optional and `seq` starts at 0 for a reason.** A caller
/// has to separate three states that a bare `Option<CycleMark>` collapses
/// into one `None`:
///
/// - the daemon is too old to report cycles → the IPC field is `None`
/// - the daemon reports them, none has finished yet → `seq: 0, outcome: None`
/// - a cycle finished → `seq: n > 0, outcome: Some(..)`
///
/// Collapse the first two and a new CLI against an old daemon waits for a
/// counter that will never move, burning its whole timeout on every single
/// refresh — which is exactly the failure this type exists to prevent
/// elsewhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CycleMark {
    /// Cycles completed since this daemon started. `0` means none has.
    pub seq: u64,
    /// `None` iff `seq == 0`.
    pub outcome: Option<CycleOutcome>,
}

pub struct ListStatusRegistry {
    inner: ArcSwap<HashMap<String, Arc<ArcSwap<ListStatus>>>>,
    /// Set when the last refresh cycle was refused by the global corpus
    /// guard, cleared whenever a cycle installs.
    ///
    /// Lives here because this is the handle the daemon already shares
    /// with the IPC server and the metrics exporter — a cycle-level fact
    /// reaches every reporting surface off one write, with no new
    /// plumbing.
    corpus_refusal: ArcSwap<Option<CorpusRefusal>>,
    /// The last completed cycle, or `None` before the first one ends.
    ///
    /// Sits beside `corpus_refusal` rather than replacing it: that field
    /// carries the refusal's *payload* (counts, worst contributor) which
    /// every existing renderer reads. This one answers the orthogonal
    /// question of whether a cycle happened at all, and which.
    ///
    /// Bumping the sequence is a read-modify-write, and it is sound because
    /// reload cycles are serialised **structurally**, not by convention:
    /// every reload request funnels through the single `ipc_reload_rx`
    /// receiver that `signal_loop` borrows mutably, so exactly one runs at a
    /// time. Signal-driven reloads bypass the coalescer but land in the same
    /// channel.
    ///
    /// Do not soften that into "concurrent cycles are merely unlikely". If
    /// two ever did run, one would read the other's `seq` before it stored,
    /// an outcome would be lost, and a poller could pair a `seq` with the
    /// WRONG cycle's outcome — a wrong verdict, not just a slow one. The
    /// safety comes from the single receiver; keep it there.
    cycle: ArcSwap<CycleMark>,
    /// §4.24 Phase 2 P2-C: secondary lookup-only index mapping a v1
    /// canonical [`Id`] to the slot key stored in `inner`. Lets
    /// future id-keyed consumers (TUI Lists tab v2, audit attribution,
    /// IPC handlers that pre-resolve `Id`) reach the slot without
    /// monkey-patching a reverse lookup through the URL.
    ///
    /// Seeded automatically at construction from slash-form sources
    /// (`"privacy/ads"` → `Id::new("privacy-ads")`). For pure-v1
    /// configs (`[lists].sources = []` with rows in `[[blocklists]]`),
    /// callers must invoke
    /// [`populate_v1_id_index`](Self::populate_v1_id_index) once the
    /// `[[blocklists]]` catalogue is available — typically right after
    /// the daemon clones the registry handle out of the manager.
    ///
    /// Wrapped in [`ArcSwap`] for lock-free atomic replacement (mirror
    /// of `inner`'s concurrency invariant). Writes happen on the
    /// daemon-reload path only (single mutator); reads are wait-free.
    by_v1_id_index: ArcSwap<HashMap<Id, String>>,
}

/// On-disk shape of a `list_stats.json` per-source baseline.
///
/// **v2** (current) serialises an object carrying both the merged-map
/// `entries` baseline (the delta-canary anchor) and the `unique_domains`
/// baseline the retention guard compares against. **v1** wrote a bare
/// integer (entries only); the untagged fallback still decodes it so an
/// in-place upgrade keeps the operator's existing canary anchor — the v1
/// value seeds `entries` and the guard falls back to it when no
/// `unique_domains` baseline is present.
///
/// A v1 (pre-guard) daemon reading a v2 file fails to parse the object
/// and starts with no baselines (logged, non-fatal — `load_persisted`
/// treats a parse error as boot-from-nothing). That one-cycle downgrade
/// cost is called out in the release notes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(untagged)]
enum PersistedEntry {
    V2 { entries: u64, unique_domains: u64 },
    Legacy(u64),
}

impl ListStatusRegistry {
    /// Build a registry covering every entry in `sources`. Each slot
    /// starts as `ListStatus::default()` (entries=0, NeverFetched).
    ///
    /// The Phase 2 [`by_v1_id_index`](Self) is seeded with slash-form
    /// translations from `sources` (`"privacy/ads"` →
    /// `Id::new("privacy-ads")`); v1-row aliases get added by a
    /// subsequent [`populate_v1_id_index`](Self::populate_v1_id_index)
    /// call from the daemon, which has the `[[blocklists]]` catalogue
    /// in scope.
    pub fn new(sources: &[String]) -> Self {
        let inner: HashMap<String, Arc<ArcSwap<ListStatus>>> = sources
            .iter()
            .map(|s| {
                (
                    s.clone(),
                    Arc::new(ArcSwap::from_pointee(ListStatus::default())),
                )
            })
            .collect();
        let by_v1_id_index = Self::seed_v1_id_index_from_sources(sources);
        Self {
            inner: ArcSwap::from_pointee(inner),
            by_v1_id_index: ArcSwap::from_pointee(by_v1_id_index),
            corpus_refusal: ArcSwap::from_pointee(None),
            cycle: ArcSwap::from_pointee(CycleMark {
                seq: 0,
                outcome: None,
            }),
        }
    }

    /// Record — or clear, with `None` — the global corpus guard's verdict
    /// for the cycle that just ended.
    ///
    /// Called on **every** completed cycle, not only on refusals: leaving
    /// a stale refusal set after a later cycle installs successfully would
    /// be the same class of lie in the opposite direction.
    pub fn set_corpus_refusal(&self, refusal: Option<CorpusRefusal>) {
        self.corpus_refusal.store(Arc::new(refusal));
    }

    /// The last cycle's corpus refusal, if it was refused.
    pub fn corpus_refusal(&self) -> Option<CorpusRefusal> {
        self.corpus_refusal.load().as_ref().clone()
    }

    /// Record a completed cycle, advancing the sequence number.
    ///
    /// **Must be called from every path that ends a cycle**, including the
    /// ones that do no work. The rebuild-skip in `start.rs` returns before
    /// it ever reaches the manager's install path, so a counter bumped only
    /// there would sit still through a perfectly successful reload and leave
    /// a poller reporting "still running" forever.
    pub fn record_cycle(&self, outcome: CycleOutcome) {
        let seq = self.cycle.load().seq + 1;
        self.cycle.store(Arc::new(CycleMark {
            seq,
            outcome: Some(outcome),
        }));
    }

    /// The cycle counter. `seq == 0` means none has completed yet — which
    /// is NOT the same as a daemon that cannot report cycles at all; that
    /// distinction lives in the IPC field's own `Option`.
    pub fn cycle(&self) -> CycleMark {
        **self.cycle.load()
    }

    /// Seed-time helper: translate legacy slash-form source strings to
    /// canonical [`Id`]s. Shares the [`is_url_source`](super::source_key::is_url_source) heuristic with
    /// [`super::source_key::SourceBitMap::build`] so the rule cannot
    /// drift (Phase 1 §11 Pitfall 1).
    fn seed_v1_id_index_from_sources(sources: &[String]) -> HashMap<Id, String> {
        let mut out: HashMap<Id, String> = HashMap::new();
        for s in sources {
            if super::source_key::is_url_source(s) {
                continue;
            }
            if let Ok(id) = Id::new(s.replace('/', "-")) {
                out.insert(id, s.clone());
            }
        }
        out
    }

    /// §4.24 Phase 2 P2-C: rebuild the
    /// [`by_v1_id_index`](Self) from the current `inner` slot keys
    /// plus the v1 `[[blocklists]]` catalogue. Idempotent — atomically
    /// replaces the whole index, so the post-call state is purely a
    /// function of `(self.inner_keys, blocklists)`.
    ///
    /// The seeding mirrors
    /// [`super::source_key::SourceBitMap::build`] for the v1-id
    /// channel:
    /// - Slash-form slot keys translate to ids (`"privacy/ads"` →
    ///   `Id::new("privacy-ads")`) — preserved across rebuild for
    ///   legacy `[lists].sources` configs.
    /// - Enabled blocklist rows whose URL matches a slot key alias
    ///   `Id → slot_key`. The blocklist pass runs after the slash-form
    ///   pass and wins on collision (matches Phase 1 §11.4 overwrite
    ///   discipline) — a typed lookup test pins this explicitly.
    pub fn populate_v1_id_index(&self, blocklists: &[Blocklist]) {
        let snapshot = self.inner.load();
        let mut next: HashMap<Id, String> = HashMap::new();
        for key in snapshot.keys() {
            if super::source_key::is_url_source(key) {
                continue;
            }
            if let Ok(id) = Id::new(key.replace('/', "-")) {
                next.insert(id, key.clone());
            }
        }
        for b in blocklists {
            if !b.enabled {
                continue;
            }
            if snapshot.contains_key(b.url.as_str()) {
                next.insert(b.id.clone(), b.url.clone());
            }
        }
        self.by_v1_id_index.store(Arc::new(next));
    }

    /// Ensure a slot exists for `source`. Fast path: read-only check
    /// against the current snapshot. Slow path: COW insert via `rcu` so
    /// concurrent writers don't lose updates. Idempotent — a second
    /// caller racing on the same key sees the slot already present and
    /// returns without further work.
    fn ensure_slot(&self, source: &str) {
        if self.inner.load().contains_key(source) {
            return;
        }
        self.inner.rcu(|current| {
            if current.contains_key(source) {
                return (**current).clone();
            }
            let mut next = (**current).clone();
            next.insert(
                source.to_string(),
                Arc::new(ArcSwap::from_pointee(ListStatus::default())),
            );
            next
        });
    }

    /// Atomically replace the status for `source` (keyed by the
    /// manager's source string — URL for v1 rows, slash-form for
    /// legacy `[lists].sources`). Materialises the slot if it doesn't
    /// exist yet — first write from a reload-time-added source
    /// self-heals the registry instead of being silently dropped
    /// (pre-S53.2 behaviour). The materialised slot starts at
    /// `ListStatus::default()` and is immediately replaced with the
    /// new status, so readers never observe a stale "NeverFetched"
    /// transient between materialise and update.
    ///
    /// Renamed from `update` in §4.24 Phase 2 P2-C to make the URL-vs-id
    /// contract explicit at the call line. Future v1-id-keyed
    /// consumers will reach for a parallel `update_for_v1_id` method
    /// — out of scope until a concrete consumer surfaces.
    pub fn update_for_url(&self, source: &str, new_status: ListStatus) {
        self.ensure_slot(source);
        if let Some(slot) = self.inner.load().get(source) {
            slot.store(Arc::new(new_status));
        }
    }

    /// Ensure registry slots exist for every source in `sources`. Called
    /// from the reload pipeline right after `merge_sources_with_blocklists`
    /// so the IPC `snapshot()` returns a row for newly-added sources
    /// immediately — operators see the new list with `last_outcome =
    /// "never_fetched"` while the daemon is still downloading, which
    /// transitions to `"ok"` after the first refresh completes.
    /// Without this pre-seed, the row would only appear after the
    /// download landed, leaving the TUI showing nothing for ~1-3s
    /// post-subscribe.
    pub fn ensure_slots(&self, sources: &[String]) {
        for s in sources {
            self.ensure_slot(s);
        }
    }

    /// Drop every slot whose source string is NOT in `keep`. Symmetric
    /// to [`Self::ensure_slots`] and called right after it in the
    /// reload pipeline so the registry tracks exactly the current
    /// merged source set.
    ///
    /// Closes the S53.7 leak: deleting a `[[blocklists]]` entry caused
    /// `merge_sources_with_blocklists` to drop its URL from the next
    /// reload's source list, but the registry slot lived on forever
    /// (the post-S53.2 grow path adds slots, never removes them). The
    /// TUI then rendered a permanent orphan row keyed on the dead URL
    /// because the IPC `snapshot()` still returned that slot.
    pub fn retain_only(&self, keep: &[String]) {
        // Fast-path read: see if anything would actually be removed.
        // Skip the expensive rcu COW when the current map already
        // matches keep (common case during steady-state refreshes).
        let snapshot = self.inner.load();
        let keep_set: std::collections::HashSet<&str> = keep.iter().map(String::as_str).collect();
        let any_stale = snapshot.keys().any(|k| !keep_set.contains(k.as_str()));
        if !any_stale {
            return;
        }
        drop(snapshot);

        self.inner.rcu(|current| {
            let keep_set: std::collections::HashSet<&str> =
                keep.iter().map(String::as_str).collect();
            let mut next: HashMap<String, Arc<ArcSwap<ListStatus>>> =
                HashMap::with_capacity(current.len());
            for (k, v) in current.iter() {
                if keep_set.contains(k.as_str()) {
                    next.insert(k.clone(), v.clone());
                }
            }
            next
        });

        // §4.24 Phase 2 P2-C: retire stale `by_v1_id_index` entries
        // pointing at slots we just dropped. Without this, a typed
        // `status_for_v1_id` lookup would return `None` (because the
        // chained inner lookup misses), but the index would still
        // carry the dead id — leaking memory and confusing diagnostics.
        // The rcu is cheap (the index is tiny vs `inner`).
        self.by_v1_id_index.rcu(|current| {
            let keep_set: std::collections::HashSet<&str> =
                keep.iter().map(String::as_str).collect();
            let mut next: HashMap<Id, String> = HashMap::with_capacity(current.len());
            for (id, slot_key) in current.iter() {
                if keep_set.contains(slot_key.as_str()) {
                    next.insert(id.clone(), slot_key.clone());
                }
            }
            next
        });
    }

    /// Snapshot the current status for one source (keyed by the
    /// manager's source string — URL for v1 rows, slash-form for
    /// legacy `[lists].sources` entries). Renamed from `get` in
    /// §4.24 Phase 2 P2-C — see [`update_for_url`](Self::update_for_url)
    /// rationale.
    pub fn status_for_url(&self, source: &str) -> Option<Arc<ListStatus>> {
        self.inner.load().get(source).map(|s| s.load_full())
    }

    /// §4.24 Phase 2 P2-C: snapshot the current status by canonical
    /// v1 entity [`Id`]. Chains through the
    /// [`by_v1_id_index`](Self) → slot key → slot lookup. Returns
    /// `None` either when the id is unknown to the registry OR when
    /// the slot it points at has been retired by
    /// [`retain_only`](Self::retain_only) since the index was last
    /// populated (defensive — `retain_only` already prunes the
    /// index, but a race window could in theory leave a dangling
    /// entry, which a typed consumer must not observe as a stale
    /// hit).
    pub fn status_for_v1_id(&self, id: &Id) -> Option<Arc<ListStatus>> {
        let slot_key = self.by_v1_id_index.load().get(id)?.clone();
        self.inner.load().get(&slot_key).map(|s| s.load_full())
    }

    /// Snapshot every (source, status) pair. Order is not guaranteed.
    pub fn snapshot(&self) -> Vec<(String, Arc<ListStatus>)> {
        self.inner
            .load()
            .iter()
            .map(|(k, v)| (k.clone(), v.load_full()))
            .collect()
    }

    /// Number of source slots in the registry.
    pub fn len(&self) -> usize {
        self.inner.load().len()
    }

    /// True when the registry has no slots (empty `[lists].sources`).
    pub fn is_empty(&self) -> bool {
        self.inner.load().is_empty()
    }

    /// rev-2606 §06 `manager-01`: reset a source's slot to the boot
    /// default (clearing the retention-guard baseline) **iff the slot
    /// already exists**. Used by `forget_source` so `warden lists forget`
    /// disarms a guard-refused list — the next fetch is then treated as a
    /// first fetch and accepted. Returns whether a slot was reset. Does
    /// NOT materialise a slot for an unknown / typo'd source, so it can't
    /// leave a phantom `NeverFetched` row the TUI would render.
    pub fn reset_baseline(&self, source: &str) -> bool {
        if let Some(slot) = self.inner.load().get(source) {
            slot.store(Arc::new(ListStatus::default()));
            true
        } else {
            false
        }
    }

    /// Persist `prev_entries` for every known source to `path` as a JSON
    /// document. Atomic write (tmp + rename) so a crash mid-write leaves a
    /// stray `.tmp` file rather than a half-written `list_stats.json` the
    /// next boot would refuse to parse.
    ///
    /// Two baselines are persisted per source: the merged-map `entries`
    /// count (delta-canary anchor) and the `unique_domains` count (the
    /// retention-guard baseline). The rest of [`ListStatus`] is freshly
    /// populated on the first refresh after boot, so persisting the full
    /// struct would be redundant and would invite stale
    /// `parsed_skipped_samples` lingering forever.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let mut payload: BTreeMap<String, PersistedEntry> = BTreeMap::new();
        let snapshot = self.inner.load();
        for (source, slot) in snapshot.iter() {
            let status = slot.load();
            // entries baseline: prefer the live count, fall back to the
            // seeded `prev_entries` during the loaded-but-not-yet-
            // refreshed window (a restart before the first scheduled
            // refresh).
            let entries = if status.entries > 0 {
                status.entries
            } else {
                status.prev_entries.unwrap_or(0)
            };
            // unique-domains baseline: `from_refresh` stamps it on success
            // and `from_failure` carries it forward (clone), so the live
            // field already IS the last-good value — `0` means the source
            // has never had a successful refresh. Persisting this is what
            // closes the fully-shadowed-source hole: a list whose every
            // domain overlaps an earlier source reports `entries == 0`
            // forever, but its `unique_domains` is non-zero, so the guard
            // still has a baseline after a restart.
            let unique_domains = status.unique_domains;
            if entries == 0 && unique_domains == 0 {
                // Nothing useful to remember for this source yet.
                continue;
            }
            payload.insert(
                source.clone(),
                PersistedEntry::V2 {
                    entries,
                    unique_domains,
                },
            );
        }
        let body = serde_json::to_vec_pretty(&payload).map_err(std::io::Error::other)?;
        atomic_write(path, &body)
    }

    /// Load persisted baselines from disk and seed each source's status
    /// accordingly. Missing file is a silent no-op (boot-from-nothing
    /// path). Malformed file is a logged warning, not an error — a
    /// corrupted persistence file MUST NOT prevent the daemon from
    /// starting.
    ///
    /// `max_entries` is the configured per-list cap. Both persisted
    /// baselines are clamped to it on load (clamp-to-cap, not discard):
    /// a planted `list_stats.json` cannot inject an arbitrarily large
    /// baseline to weaponise the retention guard (a huge baseline would
    /// make any honest refresh look like a catastrophic shrink and brick
    /// the list), and an operator who *lowers* `max_entries` across a
    /// restart keeps a usable — if capped — baseline rather than losing
    /// it. The §4.28-era `s-review-2605-lists-low` carryover.
    ///
    /// **Merge-don't-clobber.** Only slots the live daemon has not yet
    /// populated this run are seeded. On a config reload the registry is
    /// reused (the boot-time `Arc` is shared with the IPC layer), so an
    /// unconditional overwrite would wipe live `entries`/`last_outcome`
    /// back to `NeverFetched` and disarm the guard for one cycle right
    /// when a reload-triggered refresh is about to fire.
    pub fn load_persisted(&self, path: &Path, max_entries: u64) {
        let body = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "list_stats.json read failed");
                return;
            }
        };
        let payload: BTreeMap<String, PersistedEntry> = match serde_json::from_slice(&body) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "list_stats.json parse failed — starting with no baselines"
                );
                return;
            }
        };
        for (source, entry) in payload {
            let (entries, unique_domains) = match entry {
                PersistedEntry::V2 {
                    entries,
                    unique_domains,
                } => (entries, unique_domains),
                // v1 file: bare entries count, no unique baseline. The
                // guard falls back to `prev_entries` when `unique_domains`
                // is zero, so a v1→v2 upgrade still has a usable baseline
                // for the first post-upgrade cycle.
                PersistedEntry::Legacy(entries) => (entries, 0),
            };
            let entries = entries.min(max_entries);
            let unique_domains = unique_domains.min(max_entries);
            if let Some(slot) = self.inner.load().get(&source) {
                let current = slot.load();
                // Only seed a slot the live daemon has not already
                // populated this run (see "Merge-don't-clobber" above).
                if matches!(current.last_outcome, LastOutcome::NeverFetched) && current.entries == 0
                {
                    let seeded = ListStatus {
                        prev_entries: Some(entries),
                        unique_domains,
                        ..ListStatus::default()
                    };
                    slot.store(Arc::new(seeded));
                }
            }
        }
    }
}

/// §4.31: thin adapter over [`hardened_atomic_write`](crate::config::atomic_write::hardened_atomic_write) so the
/// `list_stats.json` write here gets the same fsync + mode
/// preservation as every config-mutation path.
fn atomic_write(path: &Path, content: &[u8]) -> std::io::Result<()> {
    crate::config::atomic_write::hardened_atomic_write(
        path,
        content,
        crate::config::atomic_write::AtomicWriteOpts::default(),
    )
    .map_err(std::io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parsed_counts_default_is_zero() {
        let c = ParsedCounts::default();
        assert_eq!(c.parsed_ok, 0);
        assert_eq!(c.parsed_skipped, 0);
        assert!(c.parsed_skipped_samples.is_empty());
    }

    #[test]
    fn push_skipped_caps_samples_at_32_but_counter_unbounded() {
        let mut c = ParsedCounts::default();
        for i in 0..100 {
            c.push_skipped(&format!("line {i}"));
        }
        // Counter counts every push, capped vec keeps only the first 32.
        assert_eq!(c.parsed_skipped, 100);
        assert_eq!(c.parsed_skipped_samples.len(), MAX_SKIPPED_SAMPLES);
        assert_eq!(c.parsed_skipped_samples[0], "line 0");
        assert_eq!(c.parsed_skipped_samples[31], "line 31");
    }

    #[test]
    fn push_skipped_truncates_long_lines_to_bounded_width() {
        // Hostile input: a list body with no '\n' makes str::lines() yield
        // the whole blob as one multi-megabyte "line". The retained sample
        // must be byte-bounded, not the full blob (P1 memory amplification).
        let mut c = ParsedCounts::default();
        let huge = "a".repeat(1024 * 1024); // 1 MiB single line
        c.push_skipped(&huge);
        assert_eq!(c.parsed_skipped, 1);
        let sample = &c.parsed_skipped_samples[0];
        assert!(
            sample.len() <= MAX_SKIPPED_SAMPLE_BYTES + '…'.len_utf8(),
            "sample len {} exceeds bound {}",
            sample.len(),
            MAX_SKIPPED_SAMPLE_BYTES + '…'.len_utf8()
        );
        assert!(sample.ends_with('…'), "clipped sample should be marked");
    }

    #[test]
    fn push_skipped_truncates_on_char_boundary_no_panic() {
        // A long multi-byte line must clip on a char boundary (no panic,
        // result stays valid UTF-8). '€' is 3 bytes, so the 256-byte cap is
        // NOT a char boundary (255 = 85×3) — the is_char_boundary walk must
        // back up. The string existing as valid UTF-8 proves it worked.
        let mut c = ParsedCounts::default();
        let huge = "€".repeat(4096); // 12 KiB of 3-byte chars
        c.push_skipped(&huge);
        let sample = &c.parsed_skipped_samples[0];
        assert!(sample.len() <= MAX_SKIPPED_SAMPLE_BYTES + '…'.len_utf8());
        assert!(sample.ends_with('…'));
        // Every char before the marker is the intact 3-byte '€'.
        assert!(sample.trim_end_matches('…').chars().all(|ch| ch == '€'));
    }

    #[test]
    fn push_skipped_keeps_short_lines_verbatim() {
        let mut c = ParsedCounts::default();
        c.push_skipped("||short.example.com^");
        assert_eq!(c.parsed_skipped_samples[0], "||short.example.com^");
    }

    #[test]
    fn list_status_default_is_empty() {
        let s = ListStatus::default();
        assert_eq!(s.entries, 0);
        assert_eq!(s.parsed_ok, 0);
        assert_eq!(s.parsed_skipped, 0);
        assert!(s.parsed_skipped_samples.is_empty());
        assert!(s.fetched_at.is_none());
        assert_eq!(s.last_outcome, LastOutcome::NeverFetched);
        assert!(s.delta_pct_vs_prev.is_none());
        assert!(s.prev_entries.is_none());
    }

    #[test]
    fn from_refresh_first_time_has_no_delta() {
        // No prior status → delta is None even if entries > 0.
        let now = OffsetDateTime::now_utc();
        let counts = ParsedCounts {
            parsed_ok: 100,
            unique_domains: 100,
            parsed_skipped: 5,
            parsed_skipped_samples: vec!["bad-line".into()],
            parsed_truncated: 0,
        };
        let s = ListStatus::from_refresh(100, counts, None, now);
        assert_eq!(s.entries, 100);
        assert_eq!(s.parsed_ok, 100);
        assert_eq!(s.parsed_skipped, 5);
        assert_eq!(s.fetched_at, Some(now));
        assert_eq!(s.last_outcome, LastOutcome::Ok);
        assert!(s.delta_pct_vs_prev.is_none());
        assert!(s.prev_entries.is_none());
    }

    #[test]
    fn from_refresh_with_prior_computes_delta() {
        let now = OffsetDateTime::now_utc();
        let prior = ListStatus {
            entries: 1000,
            last_outcome: LastOutcome::Ok,
            ..Default::default()
        };
        let s = ListStatus::from_refresh(1100, ParsedCounts::default(), Some(&prior), now);
        assert_eq!(s.entries, 1100);
        assert_eq!(s.prev_entries, Some(1000));
        // (1100 - 1000) / 1000 * 100 = 10.0
        assert_eq!(s.delta_pct_vs_prev, Some(10.0));
    }

    #[test]
    fn from_refresh_with_prev_entries_only() {
        // Boot path: persistence seeded `prev_entries` but the prior
        // cycle has not had a successful refresh yet. The new refresh
        // should still compute a delta against that seeded value.
        let now = OffsetDateTime::now_utc();
        let prior = ListStatus {
            entries: 0,
            last_outcome: LastOutcome::NeverFetched,
            prev_entries: Some(2000),
            ..Default::default()
        };
        let s = ListStatus::from_refresh(2200, ParsedCounts::default(), Some(&prior), now);
        assert_eq!(s.prev_entries, Some(2000));
        // (2200 - 2000) / 2000 * 100 = 10.0
        assert_eq!(s.delta_pct_vs_prev, Some(10.0));
    }

    #[test]
    fn from_failure_carries_forward_last_good() {
        let now = OffsetDateTime::now_utc();
        let prior = ListStatus {
            entries: 5000,
            parsed_ok: 5000,
            unique_domains: 4800,
            parsed_skipped: 2,
            parsed_skipped_samples: vec!["x".into()],
            parsed_truncated: 0,
            fetched_at: Some(now - time::Duration::hours(2)),
            last_outcome: LastOutcome::Ok,
            delta_pct_vs_prev: Some(1.5),
            prev_entries: Some(4925),
            last_refresh_at: Some(now - time::Duration::hours(2)),
        };
        let s = ListStatus::from_failure(Some(&prior), "HTTP 502".into(), now);
        // Counts carried over so the operator still sees "last good" data.
        assert_eq!(s.entries, 5000);
        assert_eq!(s.parsed_ok, 5000);
        // The retention-guard baseline survives a failure cycle so a
        // recovered list is measured against its last-good unique count.
        assert_eq!(s.unique_domains, 4800);
        assert_eq!(s.parsed_skipped, 2);
        assert_eq!(s.parsed_skipped_samples, vec!["x".to_string()]);
        // Timestamp is the failure attempt, NOT the prior success.
        assert_eq!(s.fetched_at, Some(now));
        // Outcome flipped to Failed.
        assert!(matches!(
            s.last_outcome,
            LastOutcome::Failed { ref reason } if reason == "HTTP 502"
        ));
        // Delta cleared — no fresh count to compare.
        assert!(s.delta_pct_vs_prev.is_none());
        // prev_entries kept — survives the failure cycle.
        assert_eq!(s.prev_entries, Some(4925));
    }

    #[test]
    fn from_failure_with_no_prior_is_default_plus_outcome() {
        let now = OffsetDateTime::now_utc();
        let s = ListStatus::from_failure(None, "DNS lookup failed".into(), now);
        assert_eq!(s.entries, 0);
        assert_eq!(s.fetched_at, Some(now));
        assert!(matches!(
            s.last_outcome,
            LastOutcome::Failed { ref reason } if reason == "DNS lookup failed"
        ));
    }

    #[test]
    fn delta_pct_growth() {
        assert_eq!(compute_delta_pct(150, 100), Some(50.0));
    }

    #[test]
    fn delta_pct_shrinkage() {
        assert_eq!(compute_delta_pct(80, 100), Some(-20.0));
    }

    #[test]
    fn delta_pct_zero_prev_is_none() {
        // Avoid division by zero — operator gets `None` rendered as `—`.
        assert!(compute_delta_pct(100, 0).is_none());
    }

    #[test]
    fn delta_pct_unchanged_is_zero() {
        assert_eq!(compute_delta_pct(1000, 1000), Some(0.0));
    }

    #[test]
    fn registry_new_pre_populates_default_for_each_source() {
        let sources: Vec<String> = vec!["privacy/ads".into(), "security/malicious".into()];
        let reg = ListStatusRegistry::new(&sources);
        assert_eq!(reg.len(), 2);
        let s = reg.status_for_url("privacy/ads").unwrap();
        assert_eq!(s.entries, 0);
        assert_eq!(s.last_outcome, LastOutcome::NeverFetched);
    }

    #[test]
    fn registry_update_atomic_swap() {
        let sources = vec!["privacy/ads".into()];
        let reg = ListStatusRegistry::new(&sources);
        let now = OffsetDateTime::now_utc();
        let new_status = ListStatus::from_refresh(42, ParsedCounts::default(), None, now);
        reg.update_for_url("privacy/ads", new_status);
        let snap = reg.status_for_url("privacy/ads").unwrap();
        assert_eq!(snap.entries, 42);
        assert_eq!(snap.last_outcome, LastOutcome::Ok);
    }

    /// The cycle counter has to separate FOUR states that `corpus_refusal()`
    /// collapses into two. Three of them read `None` there — installed,
    /// still-running and skipped — so a caller polling that field cannot
    /// tell a successful reload from one that has not started.
    ///
    /// Asserted as a sequence rather than as four isolated cases because
    /// the monotonicity is the property: a poller waits for `seq` to CHANGE,
    /// so a counter that resets, repeats, or fails to advance on one of the
    /// outcomes is exactly the bug that makes the wait meaningless.
    #[test]
    fn cycle_counter_advances_on_every_outcome() {
        let reg = ListStatusRegistry::new(&["a".into()]);

        // Before anything runs: seq 0 and NO outcome. The `None` here is
        // load-bearing — it is what lets a caller tell "no cycle yet" from
        // "a cycle happened", and it must not be forgeable as an outcome.
        let start = reg.cycle();
        assert_eq!(start.seq, 0);
        assert_eq!(start.outcome, None);

        for (n, outcome) in [
            CycleOutcome::Installed,
            CycleOutcome::Refused,
            // The one no naive implementation records: this path returns
            // early in start.rs and never reaches the manager, so a counter
            // wired only into the install path sits still through it.
            CycleOutcome::SkippedUnchanged,
            CycleOutcome::Installed,
        ]
        .into_iter()
        .enumerate()
        {
            reg.record_cycle(outcome);
            let mark = reg.cycle();
            assert_eq!(
                mark.seq,
                n as u64 + 1,
                "seq must advance once per cycle, including for {outcome:?}"
            );
            assert_eq!(mark.outcome, Some(outcome));
        }
    }

    /// A refusal and a cycle mark are written together but answer different
    /// questions, and the pairing is what a caller reads. Pinned because the
    /// tempting simplification — derive the outcome from `corpus_refusal()`
    /// — reintroduces the exact ambiguity the mark exists to remove.
    #[test]
    fn skipped_cycle_does_not_clear_a_standing_refusal() {
        let reg = ListStatusRegistry::new(&["a".into()]);
        reg.set_corpus_refusal(Some(CorpusRefusal {
            unique: 14_540_036,
            ceiling: 14_000_000,
            novel_by_source: vec![],
        }));
        reg.record_cycle(CycleOutcome::Refused);

        // A later cycle that does no work must not announce a recovery: no
        // corpus was built, so what is installed is still the refused-era
        // generation and the refusal is still the truth about it.
        reg.record_cycle(CycleOutcome::SkippedUnchanged);
        assert_eq!(
            reg.cycle().outcome,
            Some(CycleOutcome::SkippedUnchanged),
            "the skip is the latest cycle"
        );
        assert!(
            reg.corpus_refusal().is_some(),
            "a skip must not clear a standing refusal — nothing was rebuilt"
        );
    }

    #[test]
    fn registry_update_unknown_source_grows_on_demand() {
        // S53.2 — pre-S53.2 this was a silent no-op (§14.1 pitfall:
        // reload-time-added sources never surfaced in IPC stats until
        // daemon restart). Now `update()` self-heals: writing to an
        // unknown source materialises a slot for it on the spot.
        let reg = ListStatusRegistry::new(&["a".into()]);
        let now = OffsetDateTime::now_utc();
        reg.update_for_url(
            "https://example.com/new-list.txt",
            ListStatus::from_refresh(99, ParsedCounts::default(), None, now),
        );
        let materialised = reg
            .status_for_url("https://example.com/new-list.txt")
            .expect("update on unknown source must materialise a slot");
        assert_eq!(materialised.entries, 99);
        assert_eq!(materialised.last_outcome, LastOutcome::Ok);
        // The pre-existing source is untouched.
        let known = reg.status_for_url("a").unwrap();
        assert_eq!(known.entries, 0);
        // Length reflects the materialised slot — the IPC `snapshot()`
        // will now include the new row.
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn registry_retain_only_drops_stale_slots() {
        // Pin the S53.7 leak fix: deleting a [[blocklists]] entry drops
        // its URL from the next merged_sources, and the reload
        // pipeline calls retain_only(merged_sources) to evict the
        // matching registry slot. Without this the TUI would render a
        // permanent orphan row keyed on the dead URL.
        let reg = ListStatusRegistry::new(&["a".into(), "b".into(), "c".into()]);
        // Simulate a refresh that wrote to all three.
        let now = OffsetDateTime::now_utc();
        for src in ["a", "b", "c"] {
            reg.update_for_url(
                src,
                ListStatus::from_refresh(10, ParsedCounts::default(), None, now),
            );
        }
        assert_eq!(reg.len(), 3);

        // Operator deletes "b" — reload's merged_sources drops it.
        reg.retain_only(&["a".into(), "c".into()]);
        assert_eq!(reg.len(), 2);
        assert!(reg.status_for_url("a").is_some());
        assert!(
            reg.status_for_url("b").is_none(),
            "stale slot must be evicted"
        );
        assert!(reg.status_for_url("c").is_some());
    }

    #[test]
    fn registry_retain_only_is_no_op_when_keep_matches_current_set() {
        // Steady-state refreshes hit the fast path and avoid the
        // expensive COW rcu.
        let reg = ListStatusRegistry::new(&["a".into(), "b".into()]);
        let snapshot_before: Vec<String> = reg.snapshot().into_iter().map(|(k, _)| k).collect();
        reg.retain_only(&["a".into(), "b".into()]);
        let snapshot_after: Vec<String> = reg.snapshot().into_iter().map(|(k, _)| k).collect();
        let mut a = snapshot_before.clone();
        let mut b = snapshot_after.clone();
        a.sort();
        b.sort();
        assert_eq!(a, b);
    }

    #[test]
    fn registry_retain_only_with_empty_keep_clears_all() {
        let reg = ListStatusRegistry::new(&["a".into(), "b".into()]);
        reg.retain_only(&[]);
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn registry_grow_idempotent_under_repeated_updates() {
        // Two updates to the same previously-unknown source must end
        // with one slot, not two — the rcu fast-path check + slow-path
        // re-check keep growth idempotent.
        let reg = ListStatusRegistry::new(&[]);
        let now = OffsetDateTime::now_utc();
        reg.update_for_url(
            "https://x/list.txt",
            ListStatus::from_refresh(1, ParsedCounts::default(), None, now),
        );
        reg.update_for_url(
            "https://x/list.txt",
            ListStatus::from_refresh(2, ParsedCounts::default(), None, now),
        );
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.status_for_url("https://x/list.txt").unwrap().entries, 2);
    }

    #[test]
    fn registry_snapshot_returns_all_sources() {
        let reg = ListStatusRegistry::new(&["a".into(), "b".into(), "c".into()]);
        let snap = reg.snapshot();
        assert_eq!(snap.len(), 3);
        let mut keys: Vec<String> = snap.into_iter().map(|(k, _)| k).collect();
        keys.sort();
        assert_eq!(keys, vec!["a", "b", "c"]);
    }

    #[test]
    fn registry_persistence_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("list_stats.json");

        // Save: one source with entries, one with only prev_entries
        // (carried over from a previous run), one untouched.
        let reg = ListStatusRegistry::new(&["live".into(), "carried".into(), "untouched".into()]);
        let now = OffsetDateTime::now_utc();
        reg.update_for_url(
            "live",
            ListStatus::from_refresh(123, ParsedCounts::default(), None, now),
        );
        // Simulate a prior persistence load that seeded `carried`.
        let carried = ListStatus {
            prev_entries: Some(456),
            ..ListStatus::default()
        };
        reg.update_for_url("carried", carried);
        reg.save(&path).expect("save must succeed");
        // The untouched source is omitted (no useful prev_entries to remember).

        // Load into a fresh registry — must seed both `live` (from
        // entries) and `carried` (from prev_entries).
        let fresh = ListStatusRegistry::new(&["live".into(), "carried".into(), "untouched".into()]);
        fresh.load_persisted(&path, u64::MAX);
        assert_eq!(
            fresh.status_for_url("live").unwrap().prev_entries,
            Some(123)
        );
        assert_eq!(
            fresh.status_for_url("carried").unwrap().prev_entries,
            Some(456),
        );
        // Untouched source has no prev_entries seeded.
        assert!(fresh
            .status_for_url("untouched")
            .unwrap()
            .prev_entries
            .is_none());
    }

    #[test]
    fn registry_persistence_missing_file_is_silent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonexistent.json");
        let reg = ListStatusRegistry::new(&["x".into()]);
        // Must not panic, must not log error — boot-from-nothing path.
        reg.load_persisted(&path, u64::MAX);
        assert!(reg.status_for_url("x").unwrap().prev_entries.is_none());
    }

    #[test]
    fn registry_persistence_malformed_file_is_silent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("malformed.json");
        std::fs::write(&path, b"not valid json").unwrap();
        let reg = ListStatusRegistry::new(&["x".into()]);
        // Must not panic; corrupted persistence MUST NOT block boot.
        reg.load_persisted(&path, u64::MAX);
        assert!(reg.status_for_url("x").unwrap().prev_entries.is_none());
    }

    #[test]
    fn load_persisted_decodes_v1_legacy_bare_integer() {
        // A `list_stats.json` written by a pre-guard binary holds bare
        // integers. The untagged fallback must still seed `prev_entries`
        // so an in-place upgrade keeps the delta-canary anchor.
        let dir = tempdir().unwrap();
        let path = dir.path().join("list_stats.json");
        std::fs::write(&path, br#"{"privacy/ads": 4242}"#).unwrap();
        let reg = ListStatusRegistry::new(&["privacy/ads".into()]);
        reg.load_persisted(&path, u64::MAX);
        let s = reg.status_for_url("privacy/ads").unwrap();
        assert_eq!(s.prev_entries, Some(4242));
        // No unique baseline in v1 — guard falls back to prev_entries.
        assert_eq!(s.unique_domains, 0);
    }

    #[test]
    fn persistence_v2_round_trips_unique_domains() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("list_stats.json");
        let now = OffsetDateTime::now_utc();
        let reg = ListStatusRegistry::new(&["src".into()]);
        let counts = ParsedCounts {
            parsed_ok: 1000,
            unique_domains: 950,
            ..Default::default()
        };
        reg.update_for_url("src", ListStatus::from_refresh(900, counts, None, now));
        reg.save(&path).unwrap();

        let fresh = ListStatusRegistry::new(&["src".into()]);
        fresh.load_persisted(&path, u64::MAX);
        let s = fresh.status_for_url("src").unwrap();
        assert_eq!(s.prev_entries, Some(900), "entries baseline round-trips");
        assert_eq!(s.unique_domains, 950, "unique baseline round-trips");
    }

    #[test]
    fn load_persisted_clamps_to_cap() {
        // A planted baseline larger than the configured per-list cap must
        // be clamped, not trusted — otherwise an attacker who can write
        // list_stats.json could weaponise the retention guard, making any
        // honest refresh look like a catastrophic shrink.
        let dir = tempdir().unwrap();
        let path = dir.path().join("list_stats.json");
        std::fs::write(
            &path,
            br#"{"src": {"entries": 999999999, "unique_domains": 999999999}}"#,
        )
        .unwrap();
        let reg = ListStatusRegistry::new(&["src".into()]);
        reg.load_persisted(&path, 5000);
        let s = reg.status_for_url("src").unwrap();
        assert_eq!(s.prev_entries, Some(5000));
        assert_eq!(s.unique_domains, 5000);
    }

    #[test]
    fn load_persisted_does_not_clobber_live_slot() {
        // Merge-don't-clobber: on a config reload the registry is reused,
        // so loading persisted baselines must NOT overwrite a slot the
        // live daemon already refreshed this run (which would reset
        // last_outcome to NeverFetched and disarm the guard).
        let dir = tempdir().unwrap();
        let path = dir.path().join("list_stats.json");
        std::fs::write(&path, br#"{"src": {"entries": 10, "unique_domains": 10}}"#).unwrap();
        let now = OffsetDateTime::now_utc();
        let reg = ListStatusRegistry::new(&["src".into()]);
        // Live refresh populated the slot.
        let counts = ParsedCounts {
            unique_domains: 5000,
            ..Default::default()
        };
        reg.update_for_url("src", ListStatus::from_refresh(5000, counts, None, now));
        reg.load_persisted(&path, u64::MAX);
        let s = reg.status_for_url("src").unwrap();
        // Live data survives — NOT replaced by the stale disk baseline.
        assert!(matches!(s.last_outcome, LastOutcome::Ok));
        assert_eq!(s.unique_domains, 5000);
    }

    #[test]
    fn dto_renders_outcomes_consistently() {
        let now = OffsetDateTime::now_utc();
        let mut status = ListStatus::default();
        let dto = BlocklistStatusDto::from_status(
            "privacy/ads".into(),
            Some("privacy-ads".into()),
            &status,
        );
        assert_eq!(dto.last_outcome, "never_fetched");
        assert!(dto.fetched_at.is_none());

        status = ListStatus::from_refresh(10, ParsedCounts::default(), None, now);
        let dto = BlocklistStatusDto::from_status(
            "privacy/ads".into(),
            Some("privacy-ads".into()),
            &status,
        );
        assert_eq!(dto.last_outcome, "ok");
        assert!(dto.fetched_at.is_some());

        status = ListStatus::from_failure(None, "HTTP 502".into(), now);
        let dto = BlocklistStatusDto::from_status("raw-url".into(), None, &status);
        assert_eq!(dto.last_outcome, "failed: HTTP 502");
        assert_eq!(dto.id, None);
    }

    #[test]
    fn dto_serialises_to_stable_json() {
        // T2 / API consumers depend on this JSON shape.
        let status = ListStatus {
            entries: 100,
            parsed_ok: 100,
            unique_domains: 100,
            parsed_skipped: 0,
            parsed_skipped_samples: vec![],
            parsed_truncated: 0,
            fetched_at: None,
            last_outcome: LastOutcome::Ok,
            delta_pct_vs_prev: Some(5.0),
            prev_entries: Some(95),
            last_refresh_at: None,
        };
        let dto = BlocklistStatusDto::from_status("a".into(), Some("a".into()), &status);
        let json = serde_json::to_string(&dto).unwrap();
        // Field names are stable across versions.
        assert!(json.contains("\"entries\":100"));
        assert!(json.contains("\"prev_entries\":95"));
        assert!(json.contains("\"delta_pct_vs_prev\":5.0"));
    }

    /// A `list_stats.json` written before `parsed_truncated` existed must
    /// still load.
    ///
    /// This is not a theoretical back-compat nicety: the live daemon has a
    /// populated `data/list_stats.json` on disk right now, and the first
    /// restart after this ships reads it. Without `#[serde(default)]` the
    /// whole stats load fails, the retention guard loses every
    /// `prev_entries` baseline, and it does so on a box serving household
    /// DNS. The control arm proves the field still decodes when present,
    /// so a green result here can't come from the field being ignored.
    #[test]
    fn list_status_without_parsed_truncated_decodes_as_zero() {
        let legacy = r#"{"entries":100,"parsed_ok":100,"parsed_skipped":0,
            "parsed_skipped_samples":[],"last_outcome":{"kind":"ok"},
            "delta_pct_vs_prev":null,"prev_entries":95}"#;
        let parsed: ListStatus = serde_json::from_str(legacy).expect("legacy stats must load");
        assert_eq!(parsed.parsed_truncated, 0);
        assert_eq!(parsed.prev_entries, Some(95), "baseline must survive");

        let current = r#"{"entries":100,"parsed_ok":100,"parsed_skipped":0,
            "parsed_skipped_samples":[],"parsed_truncated":4242,
            "last_outcome":{"kind":"ok"},"delta_pct_vs_prev":null,"prev_entries":95}"#;
        let parsed: ListStatus = serde_json::from_str(current).expect("current stats must load");
        assert_eq!(
            parsed.parsed_truncated, 4242,
            "the field must actually round-trip, not just default"
        );
    }

    /// §4.7 Phase 2 T2: `ListStatus.last_refresh_at` survives the
    /// round-trip through `BlocklistStatusDto::from_status` (the
    /// IPC encoder) — set on success via `from_refresh`, carried
    /// forward across a subsequent `from_failure`, suppressed when
    /// `None`. Also confirms back-compat: a payload from a pre-T2
    /// daemon (no `last_refresh_at` field in JSON) decodes with the
    /// field at `None` thanks to `#[serde(default)]`.
    #[test]
    fn list_status_carries_last_refresh_at() {
        let now = OffsetDateTime::now_utc();

        // Success path stamps both fetched_at and last_refresh_at.
        let s_ok = ListStatus::from_refresh(1000, ParsedCounts::default(), None, now);
        assert_eq!(s_ok.last_refresh_at, Some(now));
        let dto_ok = BlocklistStatusDto::from_status("privacy/ads".into(), None, &s_ok);
        let expected = now.format(&Rfc3339).unwrap();
        assert_eq!(dto_ok.last_refresh_at.as_deref(), Some(expected.as_str()));

        // Failure carries forward the prior last_refresh_at — operator
        // still sees "last good" in the stale-badge calculation.
        let later = now + time::Duration::hours(1);
        let s_fail = ListStatus::from_failure(Some(&s_ok), "HTTP 502".into(), later);
        assert_eq!(
            s_fail.last_refresh_at,
            Some(now),
            "carry-forward on failure"
        );
        // fetched_at moves to the failure moment but last_refresh_at stays.
        assert_eq!(s_fail.fetched_at, Some(later));

        // Default + None: badge suppressed.
        let s_default = ListStatus::default();
        assert_eq!(s_default.last_refresh_at, None);
        let dto_default = BlocklistStatusDto::from_status("x".into(), None, &s_default);
        assert!(dto_default.last_refresh_at.is_none());

        // Back-compat: legacy JSON without the field decodes cleanly.
        let legacy_json = r#"{
            "source": "privacy/ads",
            "id": null,
            "entries": 100,
            "parsed_ok": 100,
            "parsed_skipped": 0,
            "parsed_skipped_samples": [],
            "fetched_at": null,
            "last_outcome": "ok",
            "delta_pct_vs_prev": null,
            "prev_entries": null
        }"#;
        let decoded: BlocklistStatusDto = serde_json::from_str(legacy_json).unwrap();
        assert_eq!(decoded.last_refresh_at, None);
    }

    fn mk_v1_blocklist(id: &str, url: &str, enabled: bool) -> Blocklist {
        use crate::config::schema::{BlocklistBase, BlocklistFormat, BlocklistTrust};
        Blocklist {
            id: Id::new(id).unwrap(),
            display_name: id.to_string(),
            url: url.to_string(),
            format: BlocklistFormat::Domains,
            update_interval_hours: 12,
            max_entries: 5_000_000,
            enabled,
            auth_token_ref: None,
            base: BlocklistBase::Deny,
            trust: BlocklistTrust::RemoteUnsigned,
            accept_unsigned_allow: false,
            max_consecutive_failures: 5,
        }
    }

    #[test]
    fn status_for_v1_id_resolves_v1_row_via_url_alias() {
        // §4.24 Phase 2 P2-C: a pure-v1 row in `[[blocklists]]` (URL
        // in the source list, id known) — after
        // `populate_v1_id_index`, the typed v1-id lookup must hit the
        // same slot the URL lookup hits.
        let url = "https://lists.purge.cc/ads.txt";
        let reg = ListStatusRegistry::new(&[url.to_string()]);
        reg.populate_v1_id_index(&[mk_v1_blocklist("privacy-ads", url, true)]);

        let now = OffsetDateTime::now_utc();
        reg.update_for_url(
            url,
            ListStatus::from_refresh(42, ParsedCounts::default(), None, now),
        );

        let by_url = reg
            .status_for_url(url)
            .expect("URL lookup hits the freshly-updated slot");
        let by_id = reg
            .status_for_v1_id(&Id::new("privacy-ads").unwrap())
            .expect("v1-id lookup hits the same slot through by_v1_id_index");
        assert_eq!(by_url.entries, 42);
        assert_eq!(by_id.entries, 42);
    }

    #[test]
    fn status_for_v1_id_resolves_legacy_slash_form_source_via_translation() {
        // The constructor seeds slash-form slot keys into
        // `by_v1_id_index` via `Id::new(s.replace('/','-'))` directly,
        // so this works WITHOUT calling `populate_v1_id_index`.
        let reg = ListStatusRegistry::new(&["privacy/ads".to_string()]);
        let now = OffsetDateTime::now_utc();
        reg.update_for_url(
            "privacy/ads",
            ListStatus::from_refresh(7, ParsedCounts::default(), None, now),
        );

        let by_id = reg
            .status_for_v1_id(&Id::new("privacy-ads").unwrap())
            .expect("legacy slash-form auto-translates to v1 id at construction");
        assert_eq!(by_id.entries, 7);
    }

    #[test]
    fn status_for_v1_id_returns_none_for_unknown_id() {
        let reg = ListStatusRegistry::new(&["https://lists.purge.cc/ads.txt".to_string()]);
        reg.populate_v1_id_index(&[mk_v1_blocklist(
            "privacy-ads",
            "https://lists.purge.cc/ads.txt",
            true,
        )]);
        assert!(reg
            .status_for_v1_id(&Id::new("not-configured").unwrap())
            .is_none());
    }

    #[test]
    fn populate_v1_id_index_skips_disabled_blocklists() {
        // §4.24 Phase 2 P2-C parity with `SourceBitMap::build` —
        // disabled rows don't get a `by_v1_id_index` alias because
        // their URL doesn't surface in `merge_sources_with_blocklists`
        // (so the slot wouldn't exist anyway). Pinning this prevents
        // a dangling id-alias when a row is disabled at reload time.
        let url = "https://lists.purge.cc/ads.txt";
        let reg = ListStatusRegistry::new(&[url.to_string()]);
        // The row is in the catalogue but disabled — `populate` skips
        // it. Slot exists (constructor created it from sources), but
        // the v1-id lookup does NOT resolve.
        reg.populate_v1_id_index(&[mk_v1_blocklist("privacy-ads", url, false)]);
        assert!(reg
            .status_for_v1_id(&Id::new("privacy-ads").unwrap())
            .is_none());
        // URL lookup still works (slot is present).
        assert!(reg.status_for_url(url).is_some());
    }

    #[test]
    fn retain_only_retires_v1_id_index_entries_pointing_at_dropped_slots() {
        // §4.24 Phase 2 P2-C: when a [[blocklists]] entry is removed
        // at reload time, both the URL slot AND the v1-id alias must
        // be retired. Otherwise `status_for_v1_id` would return
        // `None` (correct outcome via the inner-lookup miss) but the
        // index would leak the dead id forever. The doc-comment on
        // `retain_only` calls this out — this test pins it.
        let live = "https://lists.purge.cc/ads.txt";
        let stale = "https://lists.purge.cc/dead.txt";
        let reg = ListStatusRegistry::new(&[live.to_string(), stale.to_string()]);
        reg.populate_v1_id_index(&[
            mk_v1_blocklist("privacy-ads", live, true),
            mk_v1_blocklist("dead-list", stale, true),
        ]);

        // Pre-retain: both v1-id lookups hit.
        assert!(reg
            .status_for_v1_id(&Id::new("privacy-ads").unwrap())
            .is_some());
        assert!(reg
            .status_for_v1_id(&Id::new("dead-list").unwrap())
            .is_some());

        reg.retain_only(&[live.to_string()]);

        // Post-retain: only the live id resolves; the stale entry is
        // gone from the typed index, not just from `inner`.
        assert!(reg
            .status_for_v1_id(&Id::new("privacy-ads").unwrap())
            .is_some());
        assert!(reg
            .status_for_v1_id(&Id::new("dead-list").unwrap())
            .is_none());
    }
}
