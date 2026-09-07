//! Per-list runtime telemetry.
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
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::config::schema::id::Id;
use crate::config::schema::Blocklist;
use crate::lists::source_key::ResolvedSourcePlan;

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
/// default [`crate::config::settings::DEFAULT_MAX_LIST_BODY_BYTES`]) as a
/// single "line", and `push_skipped` would park
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
    /// Entries this parse offered after `max_entries` was reached.
    ///
    /// The manager rejects a source whole when this is non-zero.
    ///
    /// **Counts validated domains, never candidate lines.** The cap test
    /// sits after the format extractor and after `is_valid_domain`, so
    /// structural noise a format discards — a hosts row with no
    /// `0.0.0.0`/`127.0.0.1` prefix, a loopback alias, a non-`||` AdGuard
    /// line — is never charged here. That bound is load-bearing now that
    /// the cap fails closed: a source whose *domains* stay under the cap
    /// must not lose its entire body because its *lines* ran past it.
    /// The spill producer used to run a private copy of the parse
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
/// directly in `warden blocklist show` or the TUI Lists tab.
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

/// Per-list runtime telemetry.
///
/// Held behind an `ArcSwap` per source, replaced atomically on every
/// refresh. The IPC layer takes a `load_full()` snapshot to build the
/// `BlocklistStatusDto` returned to clients.
///
/// `entries` is the primary metric. `parsed_ok` and `parsed_skipped`
/// surface why a list might have a lower-than-expected entry count.
/// `delta_pct_vs_prev` is the supply-chain canary; the retention guard's
/// accept path alarms on it via [`BLOCKLIST_DELTA_WARN`].
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
    /// in iteration order. Primary metric. Contrast
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
    /// Domains the last uncleared cap-refusal since this daemon started
    /// offered past `max_entries` (see [`ParsedCounts::parsed_truncated`]).
    /// `> 0` names that exact overshoot; later non-cap failures retain it
    /// until a success clears it. It is runtime telemetry, not persisted
    /// across a daemon restart.
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
    /// RFC 3339 timestamp of the most recent **successful** refresh —
    /// distinct from [`Self::fetched_at`]
    /// which records the most recent *attempt* (success or failure).
    /// `None` until the first successful refresh completes;
    /// preserved across subsequent failures so the TUI stale badge
    /// can compare against "last-known-good", not "last tried".
    ///
    /// `#[serde(default)]` for back-compat: an older daemon's
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
            // Success path stamps "last good" alongside the attempt
            // timestamp. `from_failure` carries this forward.
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

    /// Build a failure status for a global entry-cap refusal.
    ///
    /// Last-good measurements remain visible, while `parsed_truncated`
    /// reports the rejected candidate's exact overshoot.
    pub fn from_cap_refusal(
        prev: Option<&ListStatus>,
        max_entries: usize,
        dropped: u64,
        fetched_at: OffsetDateTime,
    ) -> Self {
        let mut next = Self::from_failure(
            prev,
            format_blocklist_truncation_refused(max_entries, dropped),
            fetched_at,
        );
        next.parsed_truncated = dropped;
        next
    }
}

/// The supply-chain delta canary warning.
///
/// The retention guard's accept path emits it at
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

/// Operator-facing `last_outcome` reason stamped when the retention
/// guard refuses a catastrophic shrink. Frozen
/// template — the live string substitutes the measured numbers. Surfaces
/// in `warden blocklist show` (`failed: …`) and the TUI Lists tab.
pub const BLOCKLIST_SHRINK_REFUSED: &str =
    "refresh refused: list shrank by {drop}% to {got} domains (was {kept}); \
     candidate not installed — run `warden lists forget <source>` to accept";

/// Operator-facing `last_outcome` reason stamped when a candidate is
/// refused for exceeding its `max_entries` cap. Frozen template — the
/// live string substitutes the measured numbers.
///
/// Fail-closed is the point. A truncated list passes every sanity check
/// the daemon has — it fetched, it parsed, its entry count is plausible —
/// while the guarantee it exists to provide is already broken, and broken
/// *deterministically*: the sources are roughly alphabetical, so the cut
/// is a cliff, not a sample. Anyone who knows the cap can pick a
/// late-alphabet domain and be guaranteed through. Half a blocklist is
/// not a degraded blocklist, it is a blocklist with a published bypass.
pub const BLOCKLIST_TRUNCATION_REFUSED: &str =
    "refresh refused: candidate not installed; max_entries ({cap}) would drop {dropped} \
     entries — inspect effective_max_entries with `warden blocklist show <id>` and raise the limiting configured cap";

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
/// renders as `—`.
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
/// handler from the registry routing snapshot so the operator can correlate
/// a source spelling with its deterministic v1 `[[blocklists]].id`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct BlocklistStatusDto {
    /// Source string as it appears in `[lists].sources` — legacy
    /// slug-form (`"privacy/ads"`) or raw URL.
    pub source: String,
    /// Deterministic canonical `[[blocklists]].id`, when this source has an
    /// owning row.
    pub id: Option<String>,
    pub entries: u64,
    pub parsed_ok: u64,
    pub parsed_skipped: u64,
    pub parsed_skipped_samples: Vec<String>,
    /// Entries the `max_entries` cap found past the limit on the last
    /// uncleared cap refusal (see [`ListStatus::parsed_truncated`]). A later
    /// non-cap failure retains the value until a success clears it.
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
    /// RFC 3339 timestamp of the most recent *successful* refresh.
    /// `None` until the first success; preserved across subsequent
    /// failures (so the TUI stale badge reflects last-good, not
    /// last-attempted). `#[serde(default)]` keeps older payloads
    /// decodable — old daemons emit no field, new readers see `None`,
    /// badge suppressed.
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

/// How long the corpus has been frozen, and across how many cycles.
///
/// [`CorpusRefusal`] is rebuilt from scratch by every refused cycle, so
/// it can only ever say *this refresh was refused* — the operator reading
/// it cannot tell a refusal that started ten minutes ago from one that
/// has been standing for a fortnight. Those are different incidents: the
/// first may clear on its own when a list shrinks, the second is a host
/// that has silently stopped tracking upstream. proxmox ran the second
/// for two weeks and nine cycles with every per-source row green.
///
/// So the streak lives on the registry instead of in the payload, and
/// survives the payload being replaced.
///
/// The count is honest about its own horizon: the registry is built at
/// boot, so a restart resets it, and a restart takes the cold-start arm
/// of the guard anyway. Every surface that renders this says "since this
/// daemon started" rather than implying an all-time total.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusFreeze {
    /// When the current streak's first refusal landed. `Some` for every
    /// value this daemon publishes — the `Option` exists so the
    /// `rfc3339_option` serde helper is reused verbatim rather than
    /// duplicated for a non-optional timestamp.
    #[serde(with = "rfc3339_option")]
    pub since: Option<OffsetDateTime>,
    /// Refused cycles in the current streak, `1` on the first.
    pub consecutive: u32,
}

/// What a completed reload cycle did to the corpus.
///
/// Exists because [`CorpusRefusal`] cannot answer the question a caller
/// actually has after triggering a refresh. It is an `Option`, so it has
/// two values, but there are **seven** states after a SIGHUP: six completed
/// outcomes plus the unfinished state.
///
/// | state | `corpus_refusal()` |
/// |---|---|
/// | finished, installed | `None` |
/// | finished, refused | `Some(..)` |
/// | finished, no complete generation installed | `None` |
/// | skipped — unchanged input or retained fallback, live blocklist reused | `None` |
/// | finished, no configured sources (blocklist cleared) | `None` |
/// | finished, config rejected | `None` |
/// | not finished yet | `None` |
///
/// Six of the seven read `None`, so polling that field is a verdict built
/// on absence: it cannot tell an install from a degraded generation, a running
/// refresh, or an unchanged skip. This type makes the distinction explicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CycleOutcome {
    /// A new generation was built and installed.
    Installed,
    /// Hot retention refused a candidate and keeps the prior generation, or
    /// a cold refusal left no corpus installed.
    Refused,
    /// No complete generation was installed. The engine may serve the prior
    /// corpus, a shard hybrid, or nothing on a cold start; current readers use
    /// `generation_degraded` to identify this conservative wire value.
    SpillRollbackFailed,
    /// Byte-identical inputs reused the live blocklist, or a failed candidate
    /// had a usable retained fallback. No rebuild was installed.
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

/// What the filter is serving after the most recently completed cycle.
///
/// This is separate from [`CycleOutcome`]: an attempted refresh can fail
/// while the prior complete corpus remains live.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServedState {
    /// The daemon did not report enough state to classify what it serves.
    #[default]
    Unknown,
    /// No complete list generation has been installed since this daemon started.
    Uninitialized,
    /// Every configured source reached one complete installed generation.
    Complete,
    /// Only part of a generation is serving.
    Partial,
    /// Configured sources completed with an accepted empty corpus.
    IntentionalEmpty,
    /// The operator removed all configured sources.
    Cleared,
}

impl ServedState {
    /// A configured source set has produced a generation safe to serve.
    #[must_use]
    pub const fn is_ready_for_bind(self) -> bool {
        matches!(
            self,
            Self::Complete | Self::Partial | Self::IntentionalEmpty
        )
    }
}

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
    /// The standing coverage result from the most recent manager list
    /// attempt. It is retained across config rejection and fingerprint-only
    /// cycles, then replaced by the next manager attempt or an intentional
    /// no-sources clear.
    ///
    /// This is a qualifier, rather than a new [`CycleOutcome`] variant, so
    /// old clients with a closed outcome enum ignore this unknown struct
    /// field. It supplements the current outcome; it does not say that a
    /// `ConfigRejected` cycle itself had incomplete coverage.
    #[serde(default)]
    pub source_coverage_incomplete: bool,
    /// The most recent manager attempt did not complete a whole-generation
    /// install. The engine may therefore still serve the prior generation,
    /// a shard hybrid, or nothing on a cold start; readers must use the
    /// current domain count to distinguish those states.
    ///
    /// Kept as a defaulted qualifier so the closed serialized outcome enum
    /// remains compatible with older clients.
    #[serde(default)]
    pub generation_degraded: bool,
    /// The corpus state actually serving after this completed cycle.
    ///
    /// Defaulting preserves decoding of payloads emitted before this
    /// qualifier existed without guessing from the domain count.
    #[serde(default)]
    pub served_state: ServedState,
}

/// One immutable completed-cycle status view.
///
/// The manager may update individual status slots while a refresh is running,
/// but IPC and HTTP readers use this value rather than assembling those
/// independent atomics. It is replaced only after the cycle mark and every
/// row/payload/freeze mutation for that cycle are complete, so readers never
/// spin or pair a new sequence number with stale state.
#[derive(Clone)]
pub struct RegistrySnapshot {
    pub rows: Vec<(String, Arc<ListStatus>)>,
    pub corpus_refusal: Option<CorpusRefusal>,
    pub corpus_freeze: Option<CorpusFreeze>,
    /// Domains in the generation represented by these completed rows.
    pub domain_count: usize,
    pub cycle: CycleMark,
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum CompletedPublicationHookPoint {
    BeforeLock { manager: bool },
    AfterSnapshotLoad { manager: bool },
    AfterStore { manager: bool },
}

#[cfg(test)]
type CompletedPublicationHook =
    Arc<dyn Fn(CompletedPublicationHookPoint, &Mutex<()>) + Send + Sync>;

/// Per-source status registry shared by the manager and IPC.
///
/// Slots and routing live in one immutable generation so a routed read or
/// write never pairs aliases from one reload with slots from another. Slot
/// values remain individually swappable: publishing a source plan is atomic,
/// while a refresh does not need to clone the whole generation.
pub struct ListStatusRegistry {
    generation: ArcSwap<RegistryGeneration>,
    /// Set when the last refresh cycle was refused by the global corpus
    /// guard, cleared whenever a cycle installs.
    ///
    /// Lives here because this is the handle the daemon already shares
    /// with the IPC server and the metrics exporter — a cycle-level fact
    /// reaches every reporting surface off one write, with no new
    /// plumbing.
    corpus_refusal: ArcSwap<Option<CorpusRefusal>>,
    /// How long the standing refusal has stood, cleared by any cycle that
    /// installs.
    ///
    /// Separate from `corpus_refusal` because that field is *replaced*
    /// wholesale every cycle from values the cycle just measured — there
    /// is nowhere in it for a fact that outlives the cycle. This is the
    /// only state in the reload path that deliberately accumulates.
    corpus_freeze: ArcSwap<Option<CorpusFreeze>>,
    /// Complete IPC/API view. Kept separately from the live slots because a
    /// refresh can take minutes; a seqlock held for that whole interval would
    /// make status reads spin instead of returning the last completed view.
    completed_snapshot: ArcSwap<RegistrySnapshot>,
    /// Serializes short, synchronous completed-snapshot publications.
    /// Live manager work runs outside this lock.
    completed_publication: Mutex<()>,
    /// Precise test-only publication interleaving control. It is per-registry
    /// so parallel tests cannot affect one another.
    #[cfg(test)]
    completed_publication_hook: Mutex<Option<CompletedPublicationHook>>,
}

/// A status resolved through one registry generation.
///
/// The representative, primary Id, and slot value come from the same loaded
/// routing snapshot, so a reload cannot combine old slots with new aliases.
#[derive(Clone)]
pub struct ResolvedListStatus {
    pub representative: String,
    pub primary_id: Option<Id>,
    pub status: Arc<ListStatus>,
}

#[derive(Clone)]
struct RegistryGeneration {
    slots: HashMap<String, Arc<ArcSwap<ListStatus>>>,
    routing: RoutingSnapshot,
}

#[derive(Debug, Clone, Default)]
struct RoutingSnapshot {
    source_aliases: HashMap<String, String>,
    canonical_url_aliases: HashMap<String, String>,
    id_aliases: HashMap<Id, String>,
    primary_ids: HashMap<String, Id>,
    /// Plan-backed managers must not recreate a retired slot from a late write.
    strict: bool,
}

impl RoutingSnapshot {
    fn representative_for_source(&self, source: &str) -> Option<&str> {
        self.source_aliases
            .get(source)
            .or_else(|| {
                self.canonical_url_aliases
                    .get(&crate::lists::source_key::canonical_url_key(source))
            })
            .or_else(|| Id::new(source).ok().and_then(|id| self.id_aliases.get(&id)))
            .map(String::as_str)
    }
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
    /// This compatibility constructor permits unknown writes. Plan-backed
    /// construction uses [`Self::from_plan`] and strict immutable routing.
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
        let mut routing = RoutingSnapshot::default();
        for source in sources {
            routing
                .source_aliases
                .insert(source.clone(), source.clone());
            routing.canonical_url_aliases.insert(
                crate::lists::source_key::canonical_url_key(source),
                source.clone(),
            );
            if !super::source_key::is_url_source(source) {
                if let Ok(id) = Id::new(source.replace('/', "-")) {
                    routing.id_aliases.insert(id.clone(), source.clone());
                    routing.primary_ids.insert(source.clone(), id);
                }
            }
        }
        let initial_cycle = CycleMark {
            seq: 0,
            outcome: None,
            source_coverage_incomplete: false,
            generation_degraded: false,
            served_state: ServedState::Uninitialized,
        };
        let initial_rows = inner
            .iter()
            .map(|(source, slot)| (source.clone(), slot.load_full()))
            .collect();
        Self {
            generation: ArcSwap::from_pointee(RegistryGeneration {
                slots: inner,
                routing,
            }),
            corpus_refusal: ArcSwap::from_pointee(None),
            corpus_freeze: ArcSwap::from_pointee(None),
            completed_snapshot: ArcSwap::from_pointee(RegistrySnapshot {
                rows: initial_rows,
                corpus_refusal: None,
                corpus_freeze: None,
                domain_count: 0,
                cycle: initial_cycle,
            }),
            completed_publication: Mutex::new(()),
            #[cfg(test)]
            completed_publication_hook: Mutex::new(None),
        }
    }

    /// Build a registry whose slots and aliases come from one source plan.
    pub fn from_plan(plan: &ResolvedSourcePlan) -> Self {
        let registry = Self::new(&[]);
        registry.sync_plan(plan);
        registry
    }

    /// Atomically publish one plan-backed status generation.
    ///
    /// Existing representatives retain their slot handles so prior status
    /// survives a reload. Retired slots are omitted before publication: an old
    /// writer may still update its detached handle, but cannot make it visible
    /// in the newly routed generation.
    pub fn sync_plan(&self, plan: &ResolvedSourcePlan) {
        let representatives = plan.representatives();
        self.generation.rcu(|current| RegistryGeneration {
            slots: representatives
                .iter()
                .map(|source| {
                    let slot =
                        current.slots.get(source).cloned().unwrap_or_else(|| {
                            Arc::new(ArcSwap::from_pointee(ListStatus::default()))
                        });
                    (source.clone(), slot)
                })
                .collect(),
            routing: RoutingSnapshot {
                source_aliases: plan.source_aliases().clone(),
                canonical_url_aliases: plan.canonical_url_aliases().clone(),
                id_aliases: plan.id_aliases().clone(),
                primary_ids: plan.primary_ids().clone(),
                strict: true,
            },
        });
    }

    /// Record — or clear, with `None` — the global corpus guard's verdict
    /// for the cycle that just ended.
    ///
    /// Called on every completed manager cycle. Leaving a stale refusal set
    /// after a later manager install would be the same lie in reverse.
    pub fn set_corpus_refusal(&self, refusal: Option<CorpusRefusal>) {
        self.corpus_refusal.store(Arc::new(refusal));
    }

    /// The last cycle's corpus refusal, if it was refused.
    pub fn corpus_refusal(&self) -> Option<CorpusRefusal> {
        self.corpus_refusal.load().as_ref().clone()
    }

    /// Extend the freeze streak with one more refused cycle and return
    /// the updated value, so the caller can log it without re-reading.
    ///
    /// `now` is the cycle's own timestamp, not a fresh clock read: the
    /// refusal, the ERROR line and this stamp must all name the same
    /// instant, or an operator correlating the log against `warden
    /// status` sees two times for one event.
    ///
    /// Manager-owned state is copied into the completed snapshot only when
    /// its cycle finishes; readers never assemble it from these live cells.
    pub fn note_refused_cycle(&self, now: OffsetDateTime) -> CorpusFreeze {
        let next = match self.corpus_freeze.load().as_ref() {
            Some(prev) => CorpusFreeze {
                since: prev.since,
                consecutive: prev.consecutive.saturating_add(1),
            },
            None => CorpusFreeze {
                since: Some(now),
                consecutive: 1,
            },
        };
        self.corpus_freeze.store(Arc::new(Some(next.clone())));
        next
    }

    /// End the streak: a cycle installed, so nothing is frozen.
    ///
    /// Only an install clears it. The other non-installing arms
    /// (flush failure, degraded shard build, an empty spill) leave the
    /// previous generation serving too — the corpus is still frozen, and
    /// zeroing the streak there would report a fresh incident on the next
    /// refusal of an outage that never ended.
    pub fn note_installed_cycle(&self) {
        self.corpus_freeze.store(Arc::new(None));
    }

    /// Clear a standing freeze after an intentional corpus clear. This is not
    /// an install, but it deliberately replaces the previously frozen
    /// generation with the operator-requested empty corpus.
    pub fn clear_corpus_freeze(&self) {
        self.corpus_freeze.store(Arc::new(None));
    }

    /// The standing freeze, or `None` when the corpus is current.
    pub fn corpus_freeze(&self) -> Option<CorpusFreeze> {
        self.corpus_freeze.load().as_ref().clone()
    }

    /// Record a non-manager completed cycle, advancing the sequence number.
    ///
    /// Config rejection and fingerprint skips never own live manager slots,
    /// so they retain the prior completed rows and corpus payloads. The
    /// rebuild-skip in `start.rs` still must publish one, or a poller waits
    /// forever for a cycle that already ended.
    pub fn record_cycle(&self, outcome: CycleOutcome) {
        #[cfg(test)]
        self.run_completed_publication_hook_for_test(CompletedPublicationHookPoint::BeforeLock {
            manager: false,
        });
        let _publication = self
            .completed_publication
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = self.completed_snapshot.load_full();
        #[cfg(test)]
        self.run_completed_publication_hook_for_test(
            CompletedPublicationHookPoint::AfterSnapshotLoad { manager: false },
        );
        let cycle = CycleMark {
            seq: previous.cycle.seq.saturating_add(1),
            outcome: Some(outcome),
            source_coverage_incomplete: previous.cycle.source_coverage_incomplete,
            generation_degraded: previous.cycle.generation_degraded,
            served_state: previous.cycle.served_state,
        };
        // Config rejection and fingerprint skips do not own manager payloads.
        // Preserve the last completed generation even while a refresh mutates
        // its live slots.
        self.completed_snapshot.store(Arc::new(RegistrySnapshot {
            rows: previous.rows.clone(),
            corpus_refusal: previous.corpus_refusal.clone(),
            corpus_freeze: previous.corpus_freeze.clone(),
            domain_count: previous.domain_count,
            cycle,
        }));
        #[cfg(test)]
        self.run_completed_publication_hook_for_test(CompletedPublicationHookPoint::AfterStore {
            manager: false,
        });
    }

    /// Record a manager cycle with its final installed-domain count.
    pub fn record_cycle_with_source_coverage(
        &self,
        outcome: CycleOutcome,
        source_coverage_incomplete: bool,
        domain_count: usize,
    ) {
        self.record_cycle_with_qualifiers(outcome, source_coverage_incomplete, false, domain_count);
    }

    /// Record a manager cycle with its coverage and install-completeness
    /// qualifiers and final installed-domain count. Call this only after all
    /// rows, refusal payload, and freeze state for the cycle have been written.
    pub fn record_cycle_with_qualifiers(
        &self,
        outcome: CycleOutcome,
        source_coverage_incomplete: bool,
        generation_degraded: bool,
        domain_count: usize,
    ) {
        self.record_cycle_with_qualifiers_and_served_state(
            outcome,
            source_coverage_incomplete,
            generation_degraded,
            domain_count,
            None,
        );
    }

    /// Record a manager cycle with the state of the corpus that remains live.
    pub fn record_cycle_with_qualifiers_and_served_state(
        &self,
        outcome: CycleOutcome,
        source_coverage_incomplete: bool,
        generation_degraded: bool,
        domain_count: usize,
        served_state: Option<ServedState>,
    ) -> RegistrySnapshot {
        #[cfg(test)]
        self.run_completed_publication_hook_for_test(CompletedPublicationHookPoint::BeforeLock {
            manager: true,
        });
        let _publication = self
            .completed_publication
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = self.completed_snapshot.load_full();
        #[cfg(test)]
        self.run_completed_publication_hook_for_test(
            CompletedPublicationHookPoint::AfterSnapshotLoad { manager: true },
        );
        let served_state = served_state.unwrap_or_else(|| match outcome {
            CycleOutcome::Installed => ServedState::Complete,
            CycleOutcome::ClearedNoSources => ServedState::Cleared,
            CycleOutcome::Refused
            | CycleOutcome::SpillRollbackFailed
            | CycleOutcome::SkippedUnchanged
            | CycleOutcome::ConfigRejected => previous.cycle.served_state,
        });
        let cycle = CycleMark {
            seq: previous.cycle.seq.saturating_add(1),
            outcome: Some(outcome),
            source_coverage_incomplete,
            generation_degraded,
            served_state,
        };
        // This is the external publication point. All manager mutations
        // precede it; readers take this single immutable value rather than
        // relying on an ordering between separate atomics.
        let snapshot = self.publish_manager_snapshot(cycle, domain_count);
        #[cfg(test)]
        self.run_completed_publication_hook_for_test(CompletedPublicationHookPoint::AfterStore {
            manager: true,
        });
        snapshot
    }

    /// The cycle counter. `seq == 0` means none has completed yet — which
    /// is NOT the same as a daemon that cannot report cycles at all; that
    /// distinction lives in the IPC field's own `Option`.
    pub fn cycle(&self) -> CycleMark {
        self.completed_snapshot.load().cycle
    }

    /// Compatibility helper rebuilding Id aliases from existing slots.
    /// Plan-backed callers use [`Self::sync_plan`] for one routing snapshot.
    pub fn populate_v1_id_index(&self, blocklists: &[Blocklist]) {
        self.generation.rcu(|current| {
            let mut next = (**current).clone();
            next.routing.id_aliases.clear();
            next.routing.primary_ids.clear();
            for key in next.slots.keys() {
                if super::source_key::is_url_source(key) {
                    continue;
                }
                if let Ok(id) = Id::new(key.replace('/', "-")) {
                    next.routing.id_aliases.insert(id.clone(), key.clone());
                    next.routing.primary_ids.insert(key.clone(), id);
                }
            }
            for b in blocklists {
                if b.enabled && next.slots.contains_key(b.url.as_str()) {
                    next.routing.id_aliases.insert(b.id.clone(), b.url.clone());
                    next.routing.primary_ids.insert(b.url.clone(), b.id.clone());
                }
            }
            next
        });
    }

    /// Ensure a slot exists for `source`. Fast path: read-only check
    /// against the current snapshot. Slow path: COW insert via `rcu` so
    /// concurrent writers don't lose updates. Idempotent — a second
    /// caller racing on the same key sees the slot already present and
    /// returns without further work.
    fn ensure_slot(&self, source: &str) {
        if self.generation.load().slots.contains_key(source) {
            return;
        }
        self.generation.rcu(|current| {
            if current.slots.contains_key(source) {
                return (**current).clone();
            }
            let mut next = (**current).clone();
            next.slots.insert(
                source.to_string(),
                Arc::new(ArcSwap::from_pointee(ListStatus::default())),
            );
            next
        });
    }

    /// Replace a status through this generation's routing snapshot.
    /// Compatibility mode may materialise unknown slots; planned mode drops
    /// them so late writers cannot recreate retired sources.
    pub fn update_for_url(&self, source: &str, new_status: ListStatus) {
        let generation = self.generation.load_full();
        self.update_with_generation(&generation, source, new_status);
    }

    fn update_with_generation(
        &self,
        generation: &RegistryGeneration,
        source: &str,
        new_status: ListStatus,
    ) {
        let representative = generation
            .routing
            .representative_for_source(source)
            .map(str::to_string)
            .or_else(|| (!generation.routing.strict).then(|| source.to_string()));
        let Some(representative) = representative else {
            return;
        };
        if !generation.routing.strict {
            self.ensure_slot(&representative);
            // Compatibility construction promises on-demand slots. Reload
            // after publication only for that permissive legacy behavior.
            if let Some(slot) = self.generation.load().slots.get(&representative) {
                slot.store(Arc::new(new_status));
            }
            return;
        }
        // Use the captured generation for the write. A later `sync_plan`
        // cannot redirect this status into a different source's slot.
        if let Some(slot) = generation.slots.get(&representative) {
            slot.store(Arc::new(new_status));
        }
    }

    /// Ensure registry slots exist for every source in `sources`.
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
    /// representative source set.
    pub fn retain_only(&self, keep: &[String]) {
        // Fast-path read: see if anything would actually be removed.
        // Skip the expensive rcu COW when the current map already
        // matches keep (common case during steady-state refreshes).
        let snapshot = self.generation.load();
        let keep_set: std::collections::HashSet<&str> = keep.iter().map(String::as_str).collect();
        let any_stale = snapshot
            .slots
            .keys()
            .any(|k| !keep_set.contains(k.as_str()));
        if !any_stale {
            return;
        }
        drop(snapshot);

        self.generation.rcu(|current| {
            let keep_set: std::collections::HashSet<&str> =
                keep.iter().map(String::as_str).collect();
            let mut next = (**current).clone();
            next.slots.retain(|key, _| keep_set.contains(key.as_str()));
            next.routing
                .source_aliases
                .retain(|_, representative| keep_set.contains(representative.as_str()));
            next.routing
                .canonical_url_aliases
                .retain(|_, representative| keep_set.contains(representative.as_str()));
            next.routing
                .id_aliases
                .retain(|_, representative| keep_set.contains(representative.as_str()));
            next.routing
                .primary_ids
                .retain(|representative, _| keep_set.contains(representative.as_str()));
            next
        });
    }

    /// Snapshot the current status for one source (keyed by the
    /// manager's source string — URL for v1 rows, slash-form for
    /// legacy `[lists].sources` entries). See
    /// [`update_for_url`](Self::update_for_url) for the naming rationale.
    pub fn status_for_url(&self, source: &str) -> Option<Arc<ListStatus>> {
        let generation = self.generation.load();
        let representative = generation
            .routing
            .representative_for_source(source)
            .or_else(|| (!generation.routing.strict).then_some(source))?;
        generation.slots.get(representative).map(|s| s.load_full())
    }

    /// Snapshot status by canonical v1 entity [`Id`]. A missing or retired
    /// representative returns `None`.
    pub fn status_for_v1_id(&self, id: &Id) -> Option<Arc<ListStatus>> {
        let generation = self.generation.load();
        let slot_key = generation.routing.id_aliases.get(id)?;
        generation.slots.get(slot_key).map(|s| s.load_full())
    }

    /// Resolve a configured URL, slug, or Id spelling to its representative.
    pub fn representative_for_source(&self, source: &str) -> Option<String> {
        self.generation
            .load()
            .routing
            .representative_for_source(source)
            .map(str::to_string)
    }

    /// Resolve a URL, slug, or Id alias and load its status from one
    /// generation.
    pub fn resolve_alias(&self, source: &str) -> Option<ResolvedListStatus> {
        let generation = self.generation.load();
        Self::resolve_alias_from_generation(&generation, source)
    }

    fn resolve_alias_from_generation(
        generation: &RegistryGeneration,
        source: &str,
    ) -> Option<ResolvedListStatus> {
        let representative = generation.routing.representative_for_source(source)?;
        let slot = generation.slots.get(representative)?;
        Some(ResolvedListStatus {
            representative: representative.to_string(),
            primary_id: generation.routing.primary_ids.get(representative).cloned(),
            status: slot.load_full(),
        })
    }

    /// Return the deterministic primary Id for a source alias.
    pub fn primary_id_for_source(&self, source: &str) -> Option<Id> {
        let generation = self.generation.load();
        let representative = generation.routing.representative_for_source(source)?;
        generation.routing.primary_ids.get(representative).cloned()
    }

    /// Snapshot slots with their primary IDs from one loaded generation.
    pub fn snapshot_with_ids(&self) -> Vec<(String, Option<Id>, Arc<ListStatus>)> {
        let generation = self.generation.load();
        generation
            .slots
            .iter()
            .map(|(source, slot)| {
                (
                    source.clone(),
                    generation.routing.primary_ids.get(source).cloned(),
                    slot.load_full(),
                )
            })
            .collect()
    }

    /// Compatibility snapshot without routing metadata. Order is not
    /// guaranteed; routed IPC rendering uses [`Self::snapshot_with_ids`].
    pub fn snapshot(&self) -> Vec<(String, Arc<ListStatus>)> {
        self.snapshot_with_ids()
            .into_iter()
            .map(|(source, _, status)| (source, status))
            .collect()
    }

    /// Return the last fully published status view for IPC, HTTP, and metrics.
    /// It never waits for an in-progress refresh.
    pub fn consistent_snapshot(&self) -> RegistrySnapshot {
        (*self.completed_snapshot.load_full()).clone()
    }

    #[cfg(test)]
    fn set_completed_publication_hook_for_test(&self, hook: CompletedPublicationHook) {
        let mut slot = self
            .completed_publication_hook
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(
            slot.is_none(),
            "completed-publication test hook already armed"
        );
        *slot = Some(hook);
    }

    #[cfg(test)]
    fn run_completed_publication_hook_for_test(&self, point: CompletedPublicationHookPoint) {
        let hook = self
            .completed_publication_hook
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if let Some(hook) = hook {
            hook(point, &self.completed_publication);
        }
    }

    fn publish_manager_snapshot(&self, cycle: CycleMark, domain_count: usize) -> RegistrySnapshot {
        let snapshot = RegistrySnapshot {
            rows: self.snapshot(),
            corpus_refusal: self.corpus_refusal(),
            corpus_freeze: self.corpus_freeze(),
            domain_count,
            cycle,
        };
        self.completed_snapshot.store(Arc::new(snapshot.clone()));
        snapshot
    }

    /// Number of source slots in the registry.
    pub fn len(&self) -> usize {
        self.generation.load().slots.len()
    }

    /// True when the current source plan has no status slots.
    pub fn is_empty(&self) -> bool {
        self.generation.load().slots.is_empty()
    }

    /// Reset a source's slot to the boot default (clearing the
    /// retention-guard baseline) **iff the slot
    /// already exists**. Used by `forget_source` so `warden lists forget`
    /// disarms a guard-refused list — the next fetch is then treated as a
    /// first fetch and accepted. Returns whether a slot was reset. Does
    /// NOT materialise a slot for an unknown / typo'd source, so it can't
    /// leave a phantom `NeverFetched` row the TUI would render.
    pub fn reset_baseline(&self, source: &str) -> bool {
        let generation = self.generation.load();
        let representative = generation
            .routing
            .representative_for_source(source)
            .or_else(|| (!generation.routing.strict).then_some(source));
        if let Some(slot) = representative.and_then(|key| generation.slots.get(key).cloned()) {
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
        let snapshot = self.generation.load();
        for (source, slot) in &snapshot.slots {
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
    /// `default_max_entries` is the global safety ceiling; a plan-derived
    /// source cap narrows it when the persisted row names that source. Both
    /// persisted baselines are clamped to it on load (clamp-to-cap, not
    /// discard):
    /// a planted `list_stats.json` cannot inject an arbitrarily large
    /// baseline to weaponise the retention guard (a huge baseline would
    /// make any honest refresh look like a catastrophic shrink and brick
    /// the list), and an operator who *lowers* `max_entries` across a
    /// restart keeps a usable — if capped — baseline rather than losing
    /// it.
    ///
    /// **Merge-don't-clobber.** Only slots the live daemon has not yet
    /// populated this run are seeded. On a config reload the registry is
    /// reused (the boot-time `Arc` is shared with the IPC layer), so an
    /// unconditional overwrite would wipe live `entries`/`last_outcome`
    /// back to `NeverFetched` and disarm the guard for one cycle right
    /// when a reload-triggered refresh is about to fire.
    pub fn load_persisted(
        &self,
        path: &Path,
        default_max_entries: usize,
        source_max_entries: &std::collections::HashMap<String, usize>,
    ) {
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
            let max_entries = source_max_entries
                .get(&source)
                .copied()
                .unwrap_or(default_max_entries) as u64;
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
            let generation = self.generation.load();
            if let Some(slot) = generation.slots.get(&source) {
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

/// Thin adapter over [`hardened_atomic_write`](crate::config::atomic_write::hardened_atomic_write) so the
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
    use time::macros::datetime;
    use time::Duration;

    #[derive(Default)]
    struct PublicationRaceState {
        manager_loaded: bool,
        shared_lock_honored: Option<bool>,
        non_manager_loaded: bool,
        manager_stored: bool,
    }

    struct PublicationRace {
        state: Mutex<PublicationRaceState>,
        changed: std::sync::Condvar,
    }

    impl PublicationRace {
        fn new() -> Self {
            Self {
                state: Mutex::new(PublicationRaceState::default()),
                changed: std::sync::Condvar::new(),
            }
        }

        fn hook(&self, point: CompletedPublicationHookPoint, publication_lock: &Mutex<()>) {
            match point {
                CompletedPublicationHookPoint::BeforeLock { manager: false } => {
                    let mut state = self.state.lock().unwrap();
                    while !state.manager_loaded {
                        state = self.changed.wait(state).unwrap();
                    }
                    // The manager is paused after loading its prior snapshot.
                    // This succeeds only if the two record paths do not share
                    // the same publication lock.
                    state.shared_lock_honored = Some(matches!(
                        publication_lock.try_lock(),
                        Err(std::sync::TryLockError::WouldBlock)
                    ));
                    self.changed.notify_all();
                }
                CompletedPublicationHookPoint::AfterSnapshotLoad { manager: true } => {
                    let mut state = self.state.lock().unwrap();
                    state.manager_loaded = true;
                    self.changed.notify_all();
                    while state.shared_lock_honored.is_none() {
                        state = self.changed.wait(state).unwrap();
                    }
                    // With no shared lock, force both paths to derive from the
                    // same old snapshot before either stores it.
                    if state.shared_lock_honored == Some(false) {
                        while !state.non_manager_loaded {
                            state = self.changed.wait(state).unwrap();
                        }
                    }
                }
                CompletedPublicationHookPoint::AfterSnapshotLoad { manager: false } => {
                    let mut state = self.state.lock().unwrap();
                    if state.shared_lock_honored == Some(false) {
                        state.non_manager_loaded = true;
                        self.changed.notify_all();
                        while !state.manager_stored {
                            state = self.changed.wait(state).unwrap();
                        }
                    }
                }
                CompletedPublicationHookPoint::AfterStore { manager: true } => {
                    let mut state = self.state.lock().unwrap();
                    state.manager_stored = true;
                    self.changed.notify_all();
                }
                _ => {}
            }
        }

        fn shared_lock_honored(&self) -> Option<bool> {
            self.state.lock().unwrap().shared_lock_honored
        }
    }

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
        // must be byte-bounded, not the full blob.
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

    /// The cycle counter has to separate the six completed outcomes from
    /// the unfinished state. Installed, rollback-failed, skipped, cleared,
    /// rejected, and still-running all read `None` through
    /// `corpus_refusal()`, so polling that field cannot identify a cycle.
    ///
    /// Asserted as a sequence rather than as isolated cases because
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
        assert_eq!(start.served_state, ServedState::Uninitialized);

        for (n, outcome) in [
            CycleOutcome::Installed,
            CycleOutcome::Refused,
            CycleOutcome::SpillRollbackFailed,
            CycleOutcome::SkippedUnchanged,
            CycleOutcome::ClearedNoSources,
            CycleOutcome::ConfigRejected,
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

    #[test]
    fn cycle_mark_qualifier_keeps_existing_outcome_values_stable() {
        let installed: CycleMark = serde_json::from_str(r#"{"seq":7,"outcome":"installed"}"#)
            .expect("existing cycle mark must remain readable");
        assert_eq!(installed.outcome, Some(CycleOutcome::Installed));
        assert!(!installed.source_coverage_incomplete);
        assert_eq!(installed.served_state, ServedState::Unknown);
        assert!(!installed.generation_degraded);

        let mark = CycleMark {
            seq: 8,
            outcome: Some(CycleOutcome::SpillRollbackFailed),
            source_coverage_incomplete: false,
            generation_degraded: false,
            served_state: ServedState::Uninitialized,
        };
        assert_eq!(
            serde_json::to_string(&mark).expect("serialise new cycle mark"),
            r#"{"seq":8,"outcome":"spill_rollback_failed","source_coverage_incomplete":false,"generation_degraded":false,"served_state":"uninitialized"}"#
        );

        let coverage = CycleMark {
            seq: 9,
            outcome: Some(CycleOutcome::SpillRollbackFailed),
            source_coverage_incomplete: true,
            generation_degraded: true,
            served_state: ServedState::Uninitialized,
        };
        assert_eq!(
            serde_json::to_string(&coverage).expect("serialise coverage mark"),
            r#"{"seq":9,"outcome":"spill_rollback_failed","source_coverage_incomplete":true,"generation_degraded":true,"served_state":"uninitialized"}"#
        );
    }

    #[test]
    fn only_installed_generations_are_ready_for_bind() {
        for state in [
            ServedState::Complete,
            ServedState::Partial,
            ServedState::IntentionalEmpty,
        ] {
            assert!(state.is_ready_for_bind(), "{state:?} must bind");
        }
        for state in [
            ServedState::Unknown,
            ServedState::Uninitialized,
            ServedState::Cleared,
        ] {
            assert!(!state.is_ready_for_bind(), "{state:?} must not bind");
        }
    }

    #[test]
    fn old_shaped_cycle_mark_ignores_the_coverage_qualifier() {
        #[derive(Deserialize)]
        struct LegacyCycleMark {
            seq: u64,
            outcome: Option<CycleOutcome>,
        }

        let legacy: LegacyCycleMark = serde_json::from_str(
            r#"{"seq":9,"outcome":"spill_rollback_failed","source_coverage_incomplete":true}"#,
        )
        .expect("an old serde struct must ignore a newly added field");
        assert_eq!(legacy.seq, 9);
        assert_eq!(legacy.outcome, Some(CycleOutcome::SpillRollbackFailed));
    }

    #[test]
    fn cycle_coverage_qualifier_has_the_documented_lifecycle() {
        let reg = ListStatusRegistry::new(&["a".into()]);

        // A degraded partial install sets both qualifiers. A config
        // fingerprint skip and a config rejection keep describing the
        // corpus they leave live.
        reg.record_cycle_with_qualifiers_and_served_state(
            CycleOutcome::Installed,
            true,
            true,
            0,
            Some(ServedState::Partial),
        );
        assert!(reg.cycle().source_coverage_incomplete);
        assert!(reg.cycle().generation_degraded);
        assert_eq!(reg.cycle().served_state, ServedState::Partial);
        reg.record_cycle(CycleOutcome::SkippedUnchanged);
        assert!(reg.cycle().source_coverage_incomplete);
        assert!(reg.cycle().generation_degraded);
        assert_eq!(reg.cycle().served_state, ServedState::Partial);
        reg.record_cycle(CycleOutcome::ConfigRejected);
        assert!(reg.cycle().source_coverage_incomplete);
        assert!(reg.cycle().generation_degraded);
        assert_eq!(reg.cycle().served_state, ServedState::Partial);

        // A complete manager cycle clears it. Removing every source clears
        // both qualifiers without becoming a configured empty generation.
        reg.record_cycle_with_qualifiers(CycleOutcome::Installed, false, false, 0);
        assert!(!reg.cycle().source_coverage_incomplete);
        assert!(!reg.cycle().generation_degraded);
        assert_eq!(reg.cycle().served_state, ServedState::Complete);
        reg.record_cycle_with_qualifiers(CycleOutcome::Installed, true, true, 0);
        reg.record_cycle_with_qualifiers(CycleOutcome::ClearedNoSources, false, false, 0);
        assert!(!reg.cycle().source_coverage_incomplete);
        assert!(!reg.cycle().generation_degraded);
        assert_eq!(reg.cycle().served_state, ServedState::Cleared);
    }

    #[test]
    fn completed_snapshot_never_exposes_unpublished_rows_or_payloads() {
        let reg = ListStatusRegistry::new(&["a".into()]);
        let now = OffsetDateTime::now_utc();
        reg.update_for_url(
            "a",
            ListStatus::from_refresh(42, ParsedCounts::default(), None, now),
        );
        reg.set_corpus_refusal(Some(CorpusRefusal {
            unique: 42,
            ceiling: 10,
            novel_by_source: vec![],
        }));

        // These are in-progress writes. A status reader receives the prior
        // immutable view rather than mixing them with seq 0.
        let before = reg.consistent_snapshot();
        assert_eq!(before.cycle.seq, 0);
        assert_eq!(before.rows[0].1.entries, 0);
        assert!(before.corpus_refusal.is_none());

        reg.record_cycle_with_qualifiers(CycleOutcome::Refused, false, false, 42);
        let after = reg.consistent_snapshot();
        assert_eq!(after.cycle.outcome, Some(CycleOutcome::Refused));
        assert_eq!(after.rows[0].1.entries, 42);
        assert_eq!(after.corpus_refusal.unwrap().unique, 42);
        assert_eq!(after.domain_count, 42);
    }

    #[test]
    fn non_manager_publication_keeps_the_last_completed_manager_view() {
        let reg = ListStatusRegistry::new(&["a".into()]);
        let now = OffsetDateTime::now_utc();
        reg.update_for_url(
            "a",
            ListStatus::from_refresh(10, ParsedCounts::default(), None, now),
        );
        reg.note_refused_cycle(now);
        reg.set_corpus_refusal(Some(CorpusRefusal {
            unique: 10,
            ceiling: 5,
            novel_by_source: vec![],
        }));
        reg.record_cycle_with_qualifiers(CycleOutcome::Refused, true, false, 10);

        // Simulate a manager refresh after it has changed live slots but
        // before it reaches its completed publication point.
        reg.update_for_url(
            "a",
            ListStatus::from_refresh(20, ParsedCounts::default(), None, now),
        );
        reg.note_refused_cycle(now + Duration::seconds(1));
        reg.set_corpus_refusal(Some(CorpusRefusal {
            unique: 20,
            ceiling: 5,
            novel_by_source: vec![],
        }));
        reg.record_cycle(CycleOutcome::ConfigRejected);

        let during = reg.consistent_snapshot();
        assert_eq!(during.cycle.outcome, Some(CycleOutcome::ConfigRejected));
        assert!(during.cycle.source_coverage_incomplete);
        assert_eq!(during.rows[0].1.entries, 10);
        assert_eq!(during.domain_count, 10);
        assert_eq!(during.corpus_refusal.unwrap().unique, 10);
        assert_eq!(during.corpus_freeze.unwrap().consecutive, 1);

        reg.record_cycle_with_qualifiers(CycleOutcome::Refused, false, false, 20);
        let finished = reg.consistent_snapshot();
        assert_eq!(finished.rows[0].1.entries, 20);
        assert_eq!(finished.domain_count, 20);
        assert_eq!(finished.corpus_refusal.unwrap().unique, 20);
        assert_eq!(finished.corpus_freeze.unwrap().consecutive, 2);
    }

    #[test]
    fn concurrent_manager_and_non_manager_publications_are_serialized() {
        let reg = Arc::new(ListStatusRegistry::new(&["a".into()]));
        let now = OffsetDateTime::now_utc();
        reg.update_for_url(
            "a",
            ListStatus::from_refresh(10, ParsedCounts::default(), None, now),
        );
        reg.note_refused_cycle(now);
        reg.set_corpus_refusal(Some(CorpusRefusal {
            unique: 10,
            ceiling: 5,
            novel_by_source: vec![],
        }));
        reg.record_cycle_with_qualifiers(CycleOutcome::Refused, true, false, 10);

        // These are live manager writes awaiting the manager publication.
        reg.update_for_url(
            "a",
            ListStatus::from_refresh(20, ParsedCounts::default(), None, now),
        );
        reg.note_refused_cycle(now + Duration::seconds(1));
        reg.set_corpus_refusal(Some(CorpusRefusal {
            unique: 20,
            ceiling: 5,
            novel_by_source: vec![],
        }));

        let race = Arc::new(PublicationRace::new());
        let hook_race = Arc::clone(&race);
        reg.set_completed_publication_hook_for_test(Arc::new(move |point, lock| {
            hook_race.hook(point, lock);
        }));
        let start = Arc::new(std::sync::Barrier::new(3));
        let manager_reg = Arc::clone(&reg);
        let manager_start = Arc::clone(&start);
        let manager = std::thread::spawn(move || {
            manager_start.wait();
            manager_reg.record_cycle_with_qualifiers(CycleOutcome::Refused, false, true, 20);
        });
        let non_manager_reg = Arc::clone(&reg);
        let non_manager_start = Arc::clone(&start);
        let non_manager = std::thread::spawn(move || {
            non_manager_start.wait();
            non_manager_reg.record_cycle(CycleOutcome::ConfigRejected);
        });

        start.wait();
        manager.join().expect("manager publication thread panicked");
        non_manager
            .join()
            .expect("non-manager publication thread panicked");

        assert_eq!(race.shared_lock_honored(), Some(true));
        let snapshot = reg.consistent_snapshot();
        assert_eq!(snapshot.cycle.seq, 3, "no publication increment was lost");
        assert_eq!(snapshot.cycle.outcome, Some(CycleOutcome::ConfigRejected));
        assert!(!snapshot.cycle.source_coverage_incomplete);
        assert!(snapshot.cycle.generation_degraded);
        assert_eq!(snapshot.rows[0].1.entries, 20);
        assert_eq!(snapshot.corpus_refusal.unwrap().unique, 20);
        assert_eq!(snapshot.corpus_freeze.unwrap().consecutive, 2);
        assert_eq!(snapshot.domain_count, 20);
    }

    #[test]
    fn intentional_clear_publishes_no_refusal_or_freeze() {
        let reg = ListStatusRegistry::new(&[]);
        reg.note_refused_cycle(OffsetDateTime::now_utc());
        reg.set_corpus_refusal(Some(CorpusRefusal {
            unique: 42,
            ceiling: 10,
            novel_by_source: vec![],
        }));
        reg.set_corpus_refusal(None);
        reg.clear_corpus_freeze();
        reg.record_cycle_with_source_coverage(CycleOutcome::ClearedNoSources, false, 0);

        let snapshot = reg.consistent_snapshot();
        assert_eq!(snapshot.cycle.outcome, Some(CycleOutcome::ClearedNoSources));
        assert_eq!(snapshot.cycle.served_state, ServedState::Cleared);
        assert!(snapshot.rows.is_empty());
        assert_eq!(snapshot.domain_count, 0);
        assert!(snapshot.corpus_refusal.is_none());
        assert!(snapshot.corpus_freeze.is_none());
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
        reg.record_cycle_with_qualifiers(CycleOutcome::Refused, false, false, 0);

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

    /// The whole point of the type: one refusal is an incident, nine in a
    /// row is a host that stopped tracking upstream a fortnight ago. The
    /// refusal payload cannot tell them apart — it is rebuilt from
    /// scratch by every cycle — so the streak is pinned here.
    #[test]
    fn a_freeze_streak_keeps_its_start_and_counts_its_cycles() {
        let reg = ListStatusRegistry::new(&["a".into()]);
        assert!(
            reg.corpus_freeze().is_none(),
            "a fresh registry is not frozen"
        );

        let first = datetime!(2026-08-04 03:00:00 UTC);
        let f1 = reg.note_refused_cycle(first);
        assert_eq!(f1.since, Some(first));
        assert_eq!(f1.consecutive, 1);
        assert_eq!(reg.corpus_freeze(), Some(f1));

        // The mutation this is built to catch is not a missing call — that
        // leaves `consecutive` at 1 and is caught below. It is a
        // `note_refused_cycle` that restamps `since` every cycle, which
        // counts correctly and reports a fortnight-old freeze as minutes
        // old: the one number an operator would act on.
        let second = datetime!(2026-08-18 03:00:00 UTC);
        let f2 = reg.note_refused_cycle(second);
        assert_eq!(
            f2.since,
            Some(first),
            "the streak must date from its FIRST refusal, not its latest"
        );
        assert_eq!(f2.consecutive, 2);
        assert_eq!(reg.corpus_freeze(), Some(f2));

        // An install is the only thing that ends it.
        reg.note_installed_cycle();
        assert!(reg.corpus_freeze().is_none());

        // ...and the next refusal is a new incident, not a resumption.
        let third = datetime!(2026-08-19 03:00:00 UTC);
        let f3 = reg.note_refused_cycle(third);
        assert_eq!(f3.since, Some(third));
        assert_eq!(f3.consecutive, 1);
    }

    /// The end-to-end shape the manager drives: refuse, refuse, install.
    ///
    /// Lives here rather than beside the manager because the streak is
    /// registry state and the manager owns only the three call sites; a
    /// manager-level test would re-measure the download pipeline to assert
    /// on two integers.
    #[test]
    fn two_refusals_then_an_install_leaves_nothing_frozen() {
        let reg = ListStatusRegistry::new(&["a".into()]);
        let t0 = datetime!(2026-08-04 03:00:00 UTC);
        reg.note_refused_cycle(t0);
        reg.set_corpus_refusal(Some(CorpusRefusal {
            unique: 15_012_024,
            ceiling: 14_000_000,
            novel_by_source: vec![],
        }));
        reg.record_cycle_with_qualifiers(CycleOutcome::Refused, false, false, 0);

        reg.note_refused_cycle(t0 + Duration::hours(24));
        reg.record_cycle_with_qualifiers(CycleOutcome::Refused, false, false, 0);
        let frozen = reg.corpus_freeze().expect("still frozen");
        assert_eq!(frozen.since, Some(t0));
        assert_eq!(frozen.consecutive, 2);

        // The install clears the freeze. The refusal record is not this
        // method's to clear — the manager republishes it (as `None`) on
        // every cycle that installs — so only the freeze is asserted here.
        reg.note_installed_cycle();
        reg.set_corpus_refusal(None);
        reg.record_cycle_with_qualifiers(CycleOutcome::Installed, false, false, 0);
        assert!(reg.corpus_freeze().is_none());
    }

    /// `since` is an `Option` only so the RFC3339 serde helper is reused.
    /// Nothing this daemon publishes may leave it `None`, and a renderer
    /// that has to print "unknown" for a live freeze is a worse line than
    /// no line — so the invariant is a test, not a sentence.
    #[test]
    fn a_published_freeze_always_names_its_start() {
        let reg = ListStatusRegistry::new(&["a".into()]);
        for i in 0..3 {
            let f = reg.note_refused_cycle(datetime!(2026-08-04 03:00:00 UTC) + Duration::hours(i));
            assert!(
                f.since.is_some(),
                "cycle {i} published a freeze with no start"
            );
        }
    }

    #[test]
    fn a_freeze_round_trips_through_json() {
        let f = CorpusFreeze {
            since: Some(datetime!(2026-08-04 03:00:00 UTC)),
            consecutive: 9,
        };
        let json = serde_json::to_string(&f).expect("serialise");
        assert!(
            json.contains("2026-08-04T03:00:00Z"),
            "the timestamp must go over the wire as RFC3339, got: {json}"
        );
        let back: CorpusFreeze = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(back, f);
    }

    #[test]
    fn registry_update_unknown_source_grows_on_demand() {
        // This used to be a silent no-op: reload-time-added sources
        // never surfaced in IPC stats until daemon restart. Now
        // `update()` self-heals: writing to an unknown source
        // materialises a slot for it on the spot.
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
        // Compatibility callers retire removed slots explicitly.
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

        // Simulate a removed source.
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
        fresh.load_persisted(&path, usize::MAX, &HashMap::new());
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
        reg.load_persisted(&path, usize::MAX, &HashMap::new());
        assert!(reg.status_for_url("x").unwrap().prev_entries.is_none());
    }

    #[test]
    fn registry_persistence_malformed_file_is_silent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("malformed.json");
        std::fs::write(&path, b"not valid json").unwrap();
        let reg = ListStatusRegistry::new(&["x".into()]);
        // Must not panic; corrupted persistence MUST NOT block boot.
        reg.load_persisted(&path, usize::MAX, &HashMap::new());
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
        reg.load_persisted(&path, usize::MAX, &HashMap::new());
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
        fresh.load_persisted(&path, usize::MAX, &HashMap::new());
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
        reg.load_persisted(&path, 5000, &HashMap::new());
        let s = reg.status_for_url("src").unwrap();
        assert_eq!(s.prev_entries, Some(5000));
        assert_eq!(s.unique_domains, 5000);
    }

    #[test]
    fn load_persisted_clamps_each_source_to_its_effective_cap() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("list_stats.json");
        std::fs::write(
            &path,
            br#"{"narrow": {"entries": 9, "unique_domains": 9}, "wide": {"entries": 9, "unique_domains": 9}}"#,
        )
        .unwrap();
        let reg = ListStatusRegistry::new(&["narrow".into(), "wide".into()]);
        let caps = HashMap::from([("narrow".to_string(), 2usize), ("wide".to_string(), 7usize)]);
        reg.load_persisted(&path, 10, &caps);
        let narrow = reg.status_for_url("narrow").unwrap();
        assert_eq!(narrow.prev_entries, Some(2));
        assert_eq!(narrow.unique_domains, 2);
        let wide = reg.status_for_url("wide").unwrap();
        assert_eq!(wide.prev_entries, Some(7));
        assert_eq!(wide.unique_domains, 7);
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
        reg.load_persisted(&path, usize::MAX, &HashMap::new());
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

    /// `ListStatus.last_refresh_at` survives the round-trip through
    /// `BlocklistStatusDto::from_status` (the IPC encoder) — set on
    /// success via `from_refresh`, carried forward across a
    /// subsequent `from_failure`, suppressed when `None`. Also
    /// confirms back-compat: a payload from an older daemon (no
    /// `last_refresh_at` field in JSON) decodes with the field at
    /// `None` thanks to `#[serde(default)]`.
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
            update_interval_hours: None,
            max_entries: None,
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
        // Compatibility Id routing maps the row and URL to one slot.
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
            .expect("v1-id lookup hits the same slot through compatibility routing");
        assert_eq!(by_url.entries, 42);
        assert_eq!(by_id.entries, 42);
    }

    #[test]
    fn registry_plan_routes_url_slug_and_id_aliases_to_one_status() {
        let legacy = vec!["privacy/ads".to_string()];
        let rows = vec![mk_v1_blocklist(
            "privacy-ads",
            "https://lists.purge.cc/ads.txt",
            true,
        )];
        let plan = crate::lists::source_key::ResolvedSourcePlan::build(
            &crate::lists::catalog::Catalog::fallback(),
            &legacy,
            &rows,
            &std::collections::BTreeMap::new(),
        )
        .unwrap();
        let reg = ListStatusRegistry::from_plan(&plan);
        let now = OffsetDateTime::now_utc();
        reg.update_for_url(
            "privacy/ads",
            ListStatus::from_refresh(42, ParsedCounts::default(), None, now),
        );
        let by_slug = reg.status_for_url("privacy/ads").unwrap();
        let by_url = reg
            .status_for_url("https://LISTS.PURGE.CC:443/ads.txt/")
            .unwrap();
        let by_id_alias = reg.status_for_url("privacy-ads").unwrap();
        let by_id = reg
            .status_for_v1_id(&Id::new("privacy-ads").unwrap())
            .unwrap();
        assert_eq!(reg.len(), 1);
        assert_eq!(by_slug.entries, 42);
        assert_eq!(by_url.entries, 42);
        assert_eq!(by_id_alias.entries, 42);
        assert_eq!(by_id.entries, 42);
    }

    #[test]
    fn resolve_alias_keeps_routing_identity_and_slot_in_one_generation() {
        let old_row = mk_v1_blocklist("team-ads", "https://lists.test/old.txt", true);
        let old_plan = crate::lists::source_key::ResolvedSourcePlan::build(
            &crate::lists::catalog::Catalog::fallback(),
            &[],
            &[old_row],
            &std::collections::BTreeMap::new(),
        )
        .unwrap();
        let reg = ListStatusRegistry::from_plan(&old_plan);
        reg.update_for_url(
            "team-ads",
            ListStatus::from_refresh(1, ParsedCounts::default(), None, OffsetDateTime::now_utc()),
        );
        let old_generation = reg.generation.load_full();

        let new_row = mk_v1_blocklist("team-ads", "https://lists.test/new.txt", true);
        let new_plan = crate::lists::source_key::ResolvedSourcePlan::build(
            &crate::lists::catalog::Catalog::fallback(),
            &[],
            &[new_row],
            &std::collections::BTreeMap::new(),
        )
        .unwrap();
        reg.sync_plan(&new_plan);
        reg.update_for_url(
            "team-ads",
            ListStatus::from_refresh(2, ParsedCounts::default(), None, OffsetDateTime::now_utc()),
        );

        let old = ListStatusRegistry::resolve_alias_from_generation(&old_generation, "team-ads")
            .expect("captured generation retains its alias and slot");
        let current = reg
            .resolve_alias("team-ads")
            .expect("current generation resolves the same Id alias");
        assert_eq!(old.representative, "https://lists.test/old.txt");
        assert_eq!(old.primary_id.unwrap().as_str(), "team-ads");
        assert_eq!(old.status.entries, 1);
        assert_eq!(current.representative, "https://lists.test/new.txt");
        assert_eq!(current.primary_id.unwrap().as_str(), "team-ads");
        assert_eq!(current.status.entries, 2);
    }

    #[test]
    fn planned_registry_does_not_recreate_a_retired_slot_from_a_late_writer() {
        let rows = vec![mk_v1_blocklist(
            "privacy-ads",
            "https://lists.purge.cc/ads.txt",
            true,
        )];
        let plan = crate::lists::source_key::ResolvedSourcePlan::build(
            &crate::lists::catalog::Catalog::fallback(),
            &["privacy/ads".to_string()],
            &rows,
            &std::collections::BTreeMap::new(),
        )
        .unwrap();
        let empty = crate::lists::source_key::ResolvedSourcePlan::default();
        let reg = ListStatusRegistry::from_plan(&plan);

        let old_generation = reg.generation.load_full();
        reg.sync_plan(&empty);
        reg.update_with_generation(
            &old_generation,
            "privacy/ads",
            ListStatus::from_refresh(1, ParsedCounts::default(), None, OffsetDateTime::now_utc()),
        );

        assert!(reg.is_empty());
        assert!(reg.status_for_url("privacy/ads").is_none());
    }

    #[test]
    fn sync_plan_publishes_slots_and_aliases_as_one_generation() {
        let rows = vec![mk_v1_blocklist(
            "privacy-ads",
            "https://lists.purge.cc/ads.txt",
            true,
        )];
        let plan = crate::lists::source_key::ResolvedSourcePlan::build(
            &crate::lists::catalog::Catalog::fallback(),
            &["privacy/ads".to_string()],
            &rows,
            &std::collections::BTreeMap::new(),
        )
        .unwrap();
        let reg = ListStatusRegistry::from_plan(&ResolvedSourcePlan::default());
        reg.sync_plan(&plan);

        let generation = reg.generation.load();
        let representative = generation
            .routing
            .representative_for_source("privacy-ads")
            .expect("the Id alias is part of the published generation");
        assert!(
            generation.slots.contains_key(representative),
            "the same loaded generation must carry the routed status slot"
        );
    }

    #[test]
    fn status_for_v1_id_resolves_legacy_slash_form_source_via_translation() {
        // Compatibility construction translates slash-form keys directly.
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
        // Disabled rows must not create compatibility Id aliases.
        let url = "https://lists.purge.cc/ads.txt";
        let reg = ListStatusRegistry::new(&[url.to_string()]);
        // The URL slot remains, but the disabled row has no Id route.
        reg.populate_v1_id_index(&[mk_v1_blocklist("privacy-ads", url, false)]);
        assert!(reg
            .status_for_v1_id(&Id::new("privacy-ads").unwrap())
            .is_none());
        // The existing URL slot remains reachable.
        assert!(reg.status_for_url(url).is_some());
    }

    #[test]
    fn retain_only_retires_v1_id_index_entries_pointing_at_dropped_slots() {
        // Removing a slot must also remove its compatibility Id route.
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
