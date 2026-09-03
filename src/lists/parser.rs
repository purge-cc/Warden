//! Multi-format blocklist parser.
//!
//! Supports three list formats:
//! - **Domain-only**: purge.cc native format (one domain per line)
//! - **Hosts file**: `0.0.0.0 domain` or `127.0.0.1 domain` (Steven Black, etc.)
//! - **AdGuard DNS**: `||domain^` syntax (rules.purge.cc, AdGuard DNS lists)
//!
//! Format is auto-detected via [`super::detector::detect_format`].
//! All parsers lowercase at ingestion, validate domain characters,
//! and insert into the caller's bitmask-tagged HashMap.
//!
//! **Security**: The AdGuard list parser is sandboxed for external sources —
//! `@@` allow rules, `$important`, and `/regex/` are stripped. Only admin
//! rules in config.toml get full AdGuard syntax (via `filter::rules`).

use std::collections::{HashMap, HashSet};
use std::io::{self, BufRead, Read};

use ahash::RandomState;
use compact_str::CompactString;

use super::detector::{detect_format, ListFormat};
use super::status::ParsedCounts;
use crate::common::domain::is_valid_domain;

/// Default maximum entries per list when no config value is provided.
/// Used by the HashSet convenience functions (CLI `warden query
/// --blocklist`, tests). The configurable path (ListManager) uses
/// `settings.lists.max_entries`.
///
/// # Why 20M, and why a cap at all
///
/// The cap is a supply-chain defence (CLAUDE.md rule 4: external lists
/// are hostile by assumption) and is **not** to be removed. A list past
/// the cap is refused for the cycle, not truncated.
///
/// 20M is roughly 2.2x the largest real list (9.03M entries), which grows
/// by roughly 12k/day — headroom sized against measured growth, not
/// picked by feel. Each shard of the filter engine's domain map is an
/// exact-size sorted slice, so memory grows linearly with the entry
/// count: there is no allocation step this cap needs to sit under.
///
/// A per-list cap still does not bound the aggregate — eight lists at 20M
/// is 160M on paper. Only dedup keeps the real union far below that; the
/// budget that actually constrains the merged corpus is
/// `settings::default_max_total_domains`, a separate knob. This cap is a
/// per-source sanity bound, not a memory guarantee.
pub const DEFAULT_MAX_LIST_ENTRIES: usize = 20_000_000;

/// Parse a domain-only blocklist into a new `HashSet`.
///
/// Convenience wrapper around [`parse_domain_list_into`] that creates and
/// returns a fresh set. Prefer `parse_domain_list_into` when merging
/// multiple lists to avoid intermediate allocations.
pub fn parse_domain_list(content: &str) -> HashSet<CompactString, RandomState> {
    let mut set = HashSet::with_hasher(RandomState::new());
    parse_domain_list_into(content, &mut set);
    set
}

/// Parse a domain-only blocklist directly into an existing `HashSet`.
///
/// This avoids creating an intermediate set when merging multiple lists —
/// domains are inserted (and deduplicated) in-place. With 12M raw domains
/// across multiple lists deduplicating to ~7M, this saves significant
/// memory and ~3M redundant hash+probe operations.
///
/// Handles:
/// - `#` comments and `!` comments (AdGuard-style)
/// - Empty lines and whitespace-only lines
/// - Leading/trailing whitespace trimming
/// - Trailing root dots (`example.com.` → `example.com`)
/// - Case normalization (in-place, zero extra allocation for ≤24-byte domains)
pub fn parse_domain_list_into(content: &str, set: &mut HashSet<CompactString, RandomState>) {
    let max = DEFAULT_MAX_LIST_ENTRIES;
    let mut count = 0usize;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }
        // Strip trailing root dot (e.g. "example.com." → "example.com")
        let domain = line.strip_suffix('.').unwrap_or(line);
        if !domain.is_empty() && is_valid_domain(domain) {
            if count >= max {
                tracing::warn!(max, "list entry limit reached, truncating");
                break;
            }
            // Zero-copy lowercase: CompactString inlines domains ≤24 bytes
            // (most domains). make_ascii_lowercase() mutates in-place,
            // avoiding the extra String allocation from to_ascii_lowercase().
            let mut cs = CompactString::new(domain);
            cs.make_ascii_lowercase();
            set.insert(cs);
            count += 1;
        }
    }
}

// ── Domain sink abstraction (PerfMem S2, wave 2) ───────────────
//
// `apply_line` below used to write straight into a `&mut HashMap`,
// hardcoding every parse path to building one flat, fully-resident map —
// exactly what a sharded reload (`filter::engine`, PerfMem S2 lane A)
// needs to stop doing: the producer must route parsed domains to
// per-shard spill files instead. `DomainSink` is the seam that lets it:
// `apply_line` writes through the trait, and `MapSink` below is the one
// implementation that reproduces the legacy in-memory behaviour
// exactly, so `parse_list_into_map` and `parse_list_into_map_reader`
// keep working unchanged. See `CONTRACT-wave2.md` for the frozen shape
// both this file and the manager's own sink code against.

/// Destination for accepted domains. [`parse_list_streaming`] calls
/// `accept` once per accepted line, in file order — including
/// duplicates; deduplication is the sink's business, not the parser's (a
/// spill-file sink deliberately doesn't dedup — see [`MapSink`] for the
/// one that does).
pub trait DomainSink {
    /// `domain` is already lowercased, trailing-dot-stripped and validated.
    /// `bit` is the source's list bit.
    fn accept(&mut self, domain: &str, bit: u64) -> std::io::Result<()>;
}

/// [`DomainSink`] that writes into the bitmask-tagged `HashMap` the
/// legacy `parse_*_into_map` / `parse_list_into_map[_reader]` entry
/// points expose. This is the only sink able to compute
/// `ParsedCounts::unique_domains` — that count means "does this key
/// already carry this bit", which needs visibility into prior state a
/// spill-style sink does not have (and, per `CONTRACT-wave2.md`, must
/// not try to fake — dedup there is pass-2's job). `unique_domains`
/// therefore lives here as a private counter, and every map-backed
/// wrapper below copies it into the `ParsedCounts` it returns once the
/// parse completes.
struct MapSink<'a> {
    map: &'a mut HashMap<CompactString, u64, RandomState>,
    unique_domains: u64,
}

impl<'a> MapSink<'a> {
    fn new(map: &'a mut HashMap<CompactString, u64, RandomState>) -> Self {
        Self {
            map,
            unique_domains: 0,
        }
    }
}

impl DomainSink for MapSink<'_> {
    fn accept(&mut self, domain: &str, bit: u64) -> io::Result<()> {
        // Same entry/OR/count logic `apply_line` used to run inline —
        // moved here so any sink, not just this one, can sit behind it.
        let entry = self.map.entry(CompactString::new(domain)).or_insert(0);
        if *entry & bit == 0 {
            self.unique_domains += 1;
        }
        *entry |= bit;
        Ok(())
    }
}

// ── Shared map-parser skeleton (S56 FPC X.3) ──────────────────
//
// The three `parse_*_into_map` parsers below share ~70% boilerplate
// (line iteration, comment skip, `is_valid_domain` gate, `max_entries`
// cap, lowercase, OR-into-map, `ParsedCounts` accounting). Factor that
// into one helper parameterised by a per-format extractor closure that
// returns a `LineDecision`. Each format's quirks (hosts IP prefix +
// loopback aliases, AdGuard sandbox rules) live entirely in the
// extractor.

/// Per-line outcome from a format-specific extractor.
///
/// `Domain(&str)` borrows from the input line — the helper applies
/// trailing-dot strip, `is_valid_domain`, lowercase, and OR-into-map.
enum LineDecision<'a> {
    /// Structural noise — silent skip (no counter, no sample). Used for
    /// hosts lines without a `0.0.0.0`/`127.0.0.1` prefix, hosts
    /// loopback aliases (`localhost`, etc.), and AdGuard lines without
    /// a `||` prefix.
    Skip,
    /// Sandbox supply-chain signal — counted via `ParsedCounts::push_skipped`
    /// on the original trimmed line so the operator sees how many
    /// entries an external list tried to allow / mark important / regex
    /// / wildcard. AdGuard-only.
    SkipCounted,
    /// Valid extracted domain candidate — still subject to the
    /// `is_valid_domain` gate inside the helper.
    Domain(&'a str),
}

/// One line's worth of the `parse_*_into_map` body: comment/blank skip,
/// format-specific extraction (via `line_extractor`), validation,
/// lowercase, OR-into-map, `ParsedCounts` accounting. Shared by the
/// `&str` skeleton ([`parse_lines_into_sink`]) and the streaming skeleton
/// ([`parse_lines_into_sink_reader`]) so the two paths cannot drift apart
/// — each just supplies trimmed lines from a different source.
///
/// Past `max_entries` this keeps scanning and records each dropped domain
/// in [`ParsedCounts::parsed_truncated`] rather than stopping. The old
/// bare `break` reported `Ok` on a half-loaded list, so a source could be
/// silently truncated while every counter and the status line still looked
/// healthy. Callers no longer need a stop signal, hence `io::Result<()>` —
/// a cap hit was the only condition that ever asked them to stop, and
/// returning unit makes it impossible to reintroduce the early exit
/// without deleting this contract first.
///
/// The cap test sits *after* the extractor and `is_valid_domain`, where it
/// is free, so what it counts is validated domains — never candidate
/// lines. This is the **only** definition of that counter: the spill
/// producer in `lists::manager` used to carry a second one that tested the
/// cap ahead of extraction, and it could refuse a whole source over rows
/// that hold no domain at all. See [`ParsedCounts::parsed_truncated`].
#[allow(clippy::too_many_arguments)] // shared skeleton internals — see callers
fn apply_line(
    trimmed: &str,
    bit: u64,
    sink: &mut impl DomainSink,
    max_entries: usize,
    count: &mut usize,
    counts: &mut ParsedCounts,
    line_extractor: &impl Fn(&str) -> LineDecision,
) -> io::Result<()> {
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
        return Ok(());
    }
    match line_extractor(trimmed) {
        LineDecision::Skip => {}
        LineDecision::SkipCounted => counts.push_skipped(trimmed),
        LineDecision::Domain(raw) => {
            let domain = raw.strip_suffix('.').unwrap_or(raw);
            if !domain.is_empty() && is_valid_domain(domain) {
                if *count >= max_entries {
                    counts.parsed_truncated += 1;
                    return Ok(());
                }
                let mut cs = CompactString::new(domain);
                cs.make_ascii_lowercase();
                // Dedup + `unique_domains` accounting now live inside the
                // sink (see `MapSink::accept`) — a spill-style sink
                // legitimately can't answer "does this key already carry
                // this bit", so that responsibility can't stay here.
                sink.accept(&cs, bit)?;
                *count += 1;
                counts.parsed_ok += 1;
            } else {
                counts.push_skipped(trimmed);
            }
        }
    }
    Ok(())
}

/// Emit the one-per-source truncation warning shared by both skeleton
/// entry points. Logged once with the measured total after the body is
/// fully scanned — the pre-existing warn fired at the `break` and could
/// only say "truncating", never how many entries had been lost.
fn warn_if_truncated(counts: &ParsedCounts, max_entries: usize, source: &str) {
    if counts.parsed_truncated > 0 {
        tracing::warn!(
            source,
            max_entries,
            dropped = counts.parsed_truncated,
            "list entry limit reached; entries past the cap were dropped"
        );
    }
}

/// Shared parse skeleton consumed by the three `parse_*_into_map`
/// parsers, generic over [`DomainSink`] so the `&str` path and the
/// streaming path ([`parse_lines_into_sink_reader`]) run the exact same
/// per-line logic (`apply_line`) and cannot drift apart. The closure
/// carries each format's per-line specifics.
fn parse_lines_into_sink(
    content: &str,
    bit: u64,
    sink: &mut impl DomainSink,
    max_entries: usize,
    source: &str,
    line_extractor: impl Fn(&str) -> LineDecision,
) -> io::Result<ParsedCounts> {
    let mut counts = ParsedCounts::default();
    let mut count = 0usize;
    for line in content.lines() {
        let trimmed = line.trim();
        apply_line(
            trimmed,
            bit,
            sink,
            max_entries,
            &mut count,
            &mut counts,
            &line_extractor,
        )?;
    }
    warn_if_truncated(&counts, max_entries, source);
    Ok(counts)
}

/// Domain-only line extractor: every non-comment, non-blank line is a
/// domain candidate, subject to [`apply_line`]'s validation. Shared by
/// the `&str` and streaming entry points.
fn domain_extract(line: &str) -> LineDecision<'_> {
    LineDecision::Domain(line)
}

/// Parse a domain-only blocklist into a bitmask-tagged `HashMap`.
///
/// For each parsed domain, ORs `bit` into its existing bitmask entry.
/// This supports multi-list tagging: if "ads.com" appears in list 0 (bit=1)
/// and list 2 (bit=4), its final bitmask is 5 (0b101).
pub fn parse_domain_list_into_map(
    content: &str,
    bit: u64,
    map: &mut HashMap<CompactString, u64, RandomState>,
    max_entries: usize,
    source: &str,
) -> ParsedCounts {
    let mut sink = MapSink::new(map);
    let mut counts =
        parse_lines_into_sink(content, bit, &mut sink, max_entries, source, domain_extract)
            .expect("MapSink::accept never fails");
    counts.unique_domains = sink.unique_domains;
    counts
}

// ── Hosts file parser ──────────────────────────────────────────

/// Hosts entries to skip (loopback aliases, not real blocklist entries).
const HOSTS_SKIP: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
];

/// Hosts-format line extractor: `0.0.0.0`/`127.0.0.1` prefix required,
/// inline `#` comments and tab-separated extra fields stripped, loopback
/// aliases silently skipped. Shared by the `&str` and streaming entry
/// points.
fn hosts_extract(trimmed: &str) -> LineDecision<'_> {
    // Strip inline comment: "0.0.0.0 ads.com # block ads" → "0.0.0.0 ads.com"
    let stripped = trimmed.split('#').next().unwrap_or(trimmed).trim_end();

    // Lines without a hosts-format IP prefix are structural noise
    // (header lines, blank-after-trim, etc.) — silent skip.
    let domain = if let Some(rest) = stripped.strip_prefix("0.0.0.0") {
        rest.trim_start()
    } else if let Some(rest) = stripped.strip_prefix("127.0.0.1") {
        rest.trim_start()
    } else {
        return LineDecision::Skip;
    };

    // Some hosts files have tab-separated fields; take only the first.
    let domain = domain.split_whitespace().next().unwrap_or(domain);

    // Loopback aliases (`localhost`, etc.) are expected boilerplate,
    // not malformed entries — silent skip, not counted.
    if domain.is_empty() || HOSTS_SKIP.iter().any(|&s| domain.eq_ignore_ascii_case(s)) {
        return LineDecision::Skip;
    }

    LineDecision::Domain(domain)
}

/// Parse a hosts-format blocklist into a bitmask-tagged `HashMap`.
///
/// Recognizes lines in the form:
///   `0.0.0.0 domain`  or  `127.0.0.1 domain`
///
/// Handles inline `# comments`, skips loopback aliases (localhost, etc.),
/// and enforces the `max_entries` cap (default [`DEFAULT_MAX_LIST_ENTRIES`]).
pub fn parse_hosts_list_into_map(
    content: &str,
    bit: u64,
    map: &mut HashMap<CompactString, u64, RandomState>,
    max_entries: usize,
    source: &str,
) -> ParsedCounts {
    let mut sink = MapSink::new(map);
    let mut counts =
        parse_lines_into_sink(content, bit, &mut sink, max_entries, source, hosts_extract)
            .expect("MapSink::accept never fails");
    counts.unique_domains = sink.unique_domains;
    counts
}

// ── AdGuard DNS list parser (sandboxed) ────────────────────────

/// AdGuard line extractor. Sandbox order (matches pre-S56 behaviour
/// byte-identically): `@@` → `/regex/` → strip `||` → `$important` in
/// modifiers → strip `^` → wildcard `*`. Each sandbox arm returns
/// `SkipCounted` so the operator gets a supply-chain signal; non-`||`
/// lines return `Skip` (silent — would dominate the counter for
/// mixed-format files).
fn adguard_extract(line: &str) -> LineDecision<'_> {
    // Sandbox: skip allow rules — counted so the operator can see
    // "N% of upstream were @@ allow rules we ignored" (supply-chain
    // signal: an external list trying to silently allow domains).
    if line.starts_with("@@") {
        return LineDecision::SkipCounted;
    }

    // Sandbox: skip regex rules.
    if line.starts_with('/') {
        return LineDecision::SkipCounted;
    }

    // Must start with || for a domain block rule. Lines without `||`
    // are silent (structural noise: cosmetic filters, hosts entries,
    // etc. that would dominate the counter for mixed-format files).
    let rest = match line.strip_prefix("||") {
        Some(r) => r,
        None => return LineDecision::Skip,
    };

    // Split off modifiers: "domain^$third-party" → "domain^" + "third-party"
    let (before_mod, modifiers) = match rest.split_once('$') {
        Some((b, m)) => (b, Some(m)),
        None => (rest, None),
    };

    // Sandbox: skip $important — same supply-chain signal as `@@`.
    // Compare case-insensitively: AdGuard modifiers are case-insensitive,
    // so `$Important` / `$IMPORTANT` are the same override; a
    // case-sensitive check would let `$Important` slip past the sandbox
    // counter (and, worse, fall through to be ingested as a plain block —
    // fail-safe, but it would evade the supply-chain signal).
    if let Some(mods) = modifiers {
        if mods
            .split(',')
            .any(|m| m.trim().eq_ignore_ascii_case("important"))
        {
            return LineDecision::SkipCounted;
        }
    }

    // Strip trailing ^ anchor.
    let domain = before_mod.strip_suffix('^').unwrap_or(before_mod);

    // Sandbox: skip wildcards.
    if domain.contains('*') {
        return LineDecision::SkipCounted;
    }

    LineDecision::Domain(domain)
}

/// Parse an AdGuard DNS-format blocklist into a bitmask-tagged `HashMap`.
///
/// Extracts blocking domains from `||domain^` lines. This parser is
/// **sandboxed** for external (untrusted) list sources:
///
/// - `@@` allow rules → **skipped** (supply-chain attack vector)
/// - `$important` modifier → **skipped**
/// - `/regex/` rules → **skipped**
/// - Wildcard `*` rules → **skipped**
///
/// Only simple `||domain^` blocking entries are extracted.
pub fn parse_adguard_list_into_map(
    content: &str,
    bit: u64,
    map: &mut HashMap<CompactString, u64, RandomState>,
    max_entries: usize,
    source: &str,
) -> ParsedCounts {
    let mut sink = MapSink::new(map);
    let mut counts = parse_lines_into_sink(
        content,
        bit,
        &mut sink,
        max_entries,
        source,
        adguard_extract,
    )
    .expect("MapSink::accept never fails");
    counts.unique_domains = sink.unique_domains;
    counts
}

// ── Unified dispatcher ─────────────────────────────────────────

/// Parse a blocklist of any supported format into a bitmask-tagged `HashMap`.
///
/// `declared` is the operator-declared wire format: when `Some`, it
/// **forces** the parser; when `None`, the format is
/// auto-detected via [`detect_format`]. The manager passes `Some` only for
/// sources whose `[[blocklists]]` row declares `hosts`/`adguard` — a declared
/// (or omitted) `domains` resolves to `None` and defers to detection, so an
/// operator gains a working remedy for misdetection without regressing the
/// auto-detect default. This is the primary entry point for
/// [`super::manager::ListManager`].
///
/// Forcing `AdGuard` routes through [`parse_adguard_list_into_map`], so the
/// external-list sandbox (`@@`/`$important`/regex/`*` stripped) is preserved
/// regardless of the dispatch path.
pub fn parse_list_into_map(
    content: &str,
    bit: u64,
    map: &mut HashMap<CompactString, u64, RandomState>,
    max_entries: usize,
    source: &str,
    declared: Option<ListFormat>,
) -> ParsedCounts {
    let format = declared.unwrap_or_else(|| detect_format(content));
    match format {
        ListFormat::DomainOnly => {
            parse_domain_list_into_map(content, bit, map, max_entries, source)
        }
        ListFormat::Hosts => parse_hosts_list_into_map(content, bit, map, max_entries, source),
        ListFormat::AdGuard => parse_adguard_list_into_map(content, bit, map, max_entries, source),
    }
}

// ── Streaming entry point ──────────────────────────────────────
//
// `parse_list_into_map` above requires the whole body as a `&str`.
// `ListManager` currently gets there via `std::fs::read_to_string`,
// which holds an entire list body (up to ~200 MB for the largest cached
// source) resident for the duration of the parse — on top of the merged
// map(s) already live at reload time. The functions below parse straight
// off a `BufRead` — a file, a chained buffer, anything — one line at a
// time, so that body is never fully resident.
//
// `detect_format` needs a `&str` prefix to sniff from, and a stream has
// no such thing without buffering. [`sniff_format_reader`] buffers a
// *bounded* prefix — capped at [`DETECT_PREFIX_MAX_LINES`] raw lines
// AND at [`DETECT_PREFIX_MAX_BYTES`], since a line has no length limit
// and one crafted line is otherwise the whole body — detects on it, and
// the prefix is then replayed ahead of whatever is left on the reader
// via `Read::chain` — one continuous pass, so `max_entries`/dedup state
// is identical to parsing the same bytes as one `&str`.
//
// Wave 2 (`CONTRACT-wave2.md`) generalises the destination too: the
// skeleton below no longer hardcodes a `HashMap`. It writes through
// [`DomainSink`], so a caller can plug in a `HashMap` (via [`MapSink`],
// what the compatibility wrappers use) or, for the reload producer,
// per-shard spill files — without this skeleton knowing which.

/// Hard cap on how many *raw* lines (blank/comment/content combined)
/// [`sniff_format_reader`] will buffer while sniffing the format.
/// `detect_format` itself only ever examines the first 10 *non-comment*
/// lines of whatever string it is handed — this only needs to
/// comfortably outlast the blank/comment lines that can precede them in
/// a real list header (a handful of `#`/`!` lines in every source seen
/// in this repo's fixtures and live lists). It exists so a pathological
/// source (an unbroken run of comment lines, say) cannot push the
/// streaming parser back toward buffering the whole body — see
/// `sniff_format_reader_buffers_at_most_the_documented_cap` and
/// `reader_format_detection_prefix_is_bounded` in the test module for
/// what happens at the boundary.
///
/// **A line cap alone does not bound memory** — see the companion
/// [`DETECT_PREFIX_MAX_BYTES`], which does. Both are enforced and both
/// are pinned by their own test; neither subsumes the other.
const DETECT_PREFIX_MAX_LINES: usize = 256;

/// Hard cap on how many *bytes* [`sniff_format_reader`] will buffer
/// while sniffing the format. The real bound — [`DETECT_PREFIX_MAX_LINES`]
/// counts lines, and a line has no length limit.
///
/// Without this, one crafted line is the whole body: `read_until` has no
/// length cap, so a body with no `\n` anywhere makes the sniff loop
/// buffer all of it into `prefix`, which is then handed to
/// `Cursor::new(prefix).chain(reader)` and stays resident for the entire
/// parse *while* `parse_lines_into_sink_reader`'s own buffer re-reads the
/// same bytes. Demonstrated at 2.00× the non-streaming path's peak on a
/// 32 MB single-line body, i.e. 400 MB against 200 MB at the
/// `lists.max_body_bytes` default — the difference between a refresh and
/// an OOM on the 1 GB-class hardware this product targets.
///
/// This is not a hypothetical input class. External blocklists are an
/// explicit supply-chain threat (`CLAUDE.md` rule 4), and
/// [`super::status::MAX_SKIPPED_SAMPLE_BYTES`] exists in this very module
/// tree for the same hostile-body shape one layer down. 64 KiB is ~256 B
/// per line at the line cap, comfortably past any real list header, and
/// 3200× below `max_body_bytes`.
const DETECT_PREFIX_MAX_BYTES: usize = 64 * 1024;

/// Buffer a bounded prefix off `reader` and run [`detect_format`] on it.
/// Reading to sniff the format is destructive — there is no "unread" on
/// a stream — so the returned prefix must be replayed through the
/// chosen parser ahead of whatever is left on `reader`; see
/// [`parse_list_into_map_reader`].
///
/// Bounded by [`DETECT_PREFIX_MAX_LINES`] **and** by
/// [`DETECT_PREFIX_MAX_BYTES`], whichever binds first. The byte cap is
/// applied via `Read::take` rather than by checking `prefix.len()` after
/// each read: a post-hoc check is worthless here, because the read that
/// blows the budget has already swallowed the whole line.
///
/// Returns raw bytes, not a `String`, on purpose. The byte cap can fall
/// mid-line and therefore mid-UTF-8-sequence; `read_line` would reject
/// that as `InvalidData` and fail an otherwise valid list. Detection runs
/// on a lossy view (a diagnostic read, never replayed), while the bytes
/// handed back are byte-exact so the chain replays the original body.
/// Genuinely invalid UTF-8 still surfaces as an error — just from the
/// parse loop downstream rather than from here.
///
/// A mid-line cut is invisible to the parser: `Chain::fill_buf` only
/// reports EOF once *both* readers are drained, so `read_until` walks
/// straight across the seam and reassembles the split line. Pinned by
/// `reader_matches_str_path_across_a_byte_capped_mid_line_cut`.
fn sniff_format_reader<R: BufRead>(reader: &mut R) -> io::Result<(ListFormat, Vec<u8>)> {
    let mut prefix = Vec::new();
    let mut limited = reader.take(DETECT_PREFIX_MAX_BYTES as u64);
    for _ in 0..DETECT_PREFIX_MAX_LINES {
        if limited.read_until(b'\n', &mut prefix)? == 0 {
            break;
        }
    }
    Ok((detect_format(&String::from_utf8_lossy(&prefix)), prefix))
}

/// Streaming counterpart to [`parse_lines_into_sink`]: reads lines off a
/// `BufRead` one at a time via `read_line` into a reused buffer, so peak
/// memory is bounded by one line, never the whole body. Generic over
/// [`DomainSink`] for the same reason `parse_lines_into_sink` is — see
/// its doc comment.
///
/// `read_line` keeps the line terminator, but `trim()` removes it same
/// as everything else at the edges — `\n` and `\r` are both ASCII
/// whitespace, so a trailing `\r\n` (or even a stray doubled `\r\r\n`)
/// disappears into the same `.trim()` call the `&str` path already
/// makes on each `str::lines()` segment. No terminator-specific
/// stripping needed for the two paths to agree byte-for-byte.
fn parse_lines_into_sink_reader<R: BufRead>(
    mut reader: R,
    bit: u64,
    sink: &mut impl DomainSink,
    max_entries: usize,
    source: &str,
    line_extractor: impl Fn(&str) -> LineDecision,
) -> io::Result<ParsedCounts> {
    let mut counts = ParsedCounts::default();
    let mut count = 0usize;
    let mut buf = String::new();
    loop {
        buf.clear();
        if reader.read_line(&mut buf)? == 0 {
            break;
        }
        let trimmed = buf.trim();
        apply_line(
            trimmed,
            bit,
            sink,
            max_entries,
            &mut count,
            &mut counts,
            &line_extractor,
        )?;
    }
    warn_if_truncated(&counts, max_entries, source);
    Ok(counts)
}

/// The one streaming skeleton (PerfMem S2, wave 2 — frozen shape, see
/// `CONTRACT-wave2.md`). Sniffs or accepts a declared [`ListFormat`],
/// then runs [`parse_lines_into_sink_reader`] with the matching
/// extractor. Generic over [`DomainSink`], so a caller can route parsed
/// domains anywhere — a `HashMap` (see [`parse_list_into_map_reader`]
/// below, now a thin wrapper over this), per-shard spill files, or
/// anything else — without this function, or `apply_line` underneath
/// it, needing to know which.
///
/// Byte-identical results to the `&str` path for the same bytes — same
/// entries delivered to the sink, same `parsed_ok` / `parsed_skipped` /
/// samples — for any input whose format marker sits inside the bounded
/// sniff window, so that detection agrees either way (see
/// [`DETECT_PREFIX_MAX_LINES`] and [`DETECT_PREFIX_MAX_BYTES`]). Past
/// that window the two paths can pick different formats; the *parse* of
/// a given format is byte-identical regardless.
///
/// `declared` has the same meaning as in [`parse_list_into_map`]: `Some`
/// forces the format and skips sniffing entirely (no prefix buffering);
/// `None` sniffs via [`sniff_format_reader`] first.
///
/// # `unique_domains` is always zero here
///
/// This function cannot compute `ParsedCounts::unique_domains` for an
/// arbitrary sink — that count means "does this domain already carry
/// this bit", which needs visibility into state only the sink owns.
/// Tracking it here regardless (a local dedup set) would re-materialize
/// the very full-corpus map wave 2 exists to stop building, so it isn't
/// attempted: the returned `ParsedCounts::unique_domains` is always 0.
///
/// **A caller that needs this count must derive it from its own sink**
/// — see [`parse_list_into_map_reader`] below, which does exactly that
/// with [`MapSink`]. Do not feed this function's `unique_domains`
/// straight into a retention guard; a real corpus reads 0 and a
/// same-or-growing list looks like a 100% collapse.
///
/// # Errors
///
/// On an I/O or UTF-8 decode error from `reader`, or an error from
/// `sink.accept`, `sink` may already have accepted entries from lines
/// processed before the failure — unlike the `&str` path, where the
/// caller's own `read_to_string` fails closed before any parsing starts.
/// A caller needing all-or-nothing semantics must snapshot state
/// beforehand and roll back on `Err`.
pub fn parse_list_streaming<R: std::io::BufRead, S: DomainSink>(
    mut reader: R,
    bit: u64,
    sink: &mut S,
    max_entries: usize,
    source: &str,
    declared: Option<ListFormat>,
) -> std::io::Result<ParsedCounts> {
    let (format, prefix) = match declared {
        Some(format) => (format, Vec::new()),
        None => sniff_format_reader(&mut reader)?,
    };

    // Splice the sniffed prefix back ahead of whatever is left on
    // `reader` — one continuous pass through the chosen parser, so the
    // seam between "sniffed" and "streamed" bytes is invisible to it.
    let chained = io::Cursor::new(prefix).chain(reader);

    match format {
        ListFormat::DomainOnly => {
            parse_lines_into_sink_reader(chained, bit, sink, max_entries, source, domain_extract)
        }
        ListFormat::Hosts => {
            parse_lines_into_sink_reader(chained, bit, sink, max_entries, source, hosts_extract)
        }
        ListFormat::AdGuard => {
            parse_lines_into_sink_reader(chained, bit, sink, max_entries, source, adguard_extract)
        }
    }
}

/// Streaming variant of [`parse_list_into_map`]: parses a blocklist body
/// off a [`std::io::BufRead`] without ever holding the whole thing in
/// memory. Now a thin wrapper over [`parse_list_streaming`] with a
/// [`MapSink`] — see that function's doc comment for the streaming and
/// equivalence guarantees; this one only adds back the `unique_domains`
/// accounting `MapSink` tracks, so callers of this function keep seeing
/// exactly the numbers they always have.
///
/// This is the entry point [`super::manager::ListManager`] streams a
/// cached list body through instead of `std::fs::read_to_string` +
/// [`parse_list_into_map`].
///
/// # Errors
///
/// See [`parse_list_streaming`] — `map` may already contain entries from
/// lines processed before an `Err`.
pub fn parse_list_into_map_reader<R: std::io::BufRead>(
    reader: R,
    bit: u64,
    map: &mut HashMap<CompactString, u64, RandomState>,
    max_entries: usize,
    source: &str,
    declared: Option<ListFormat>,
) -> std::io::Result<ParsedCounts> {
    let mut sink = MapSink::new(map);
    let mut counts = parse_list_streaming(reader, bit, &mut sink, max_entries, source, declared)?;
    counts.unique_domains = sink.unique_domains;
    Ok(counts)
}

#[cfg(test)]
/// Parse a blocklist of any supported format into a `HashSet`.
///
/// Convenience wrapper for tests.
pub fn parse_list(content: &str) -> HashSet<CompactString, RandomState> {
    let mut map = HashMap::with_hasher(RandomState::new());
    parse_list_into_map(content, 1, &mut map, DEFAULT_MAX_LIST_ENTRIES, "test", None);
    map.into_keys().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: usize = DEFAULT_MAX_LIST_ENTRIES;
    const S: &str = "test";

    #[test]
    fn parse_basic_domains() {
        let content = "tracker.example.com\nads.example.com\n";
        let set = parse_domain_list(content);
        assert_eq!(set.len(), 2);
        assert!(set.contains("tracker.example.com"));
        assert!(set.contains("ads.example.com"));
    }

    #[test]
    fn parse_comments_and_empty_lines() {
        let content =
            "# This is a comment\n\ntracker.example.com\n  \n# Another comment\nads.com\n";
        let set = parse_domain_list(content);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn parse_purge_cc_header() {
        let content = "# PURGE.CC - Ads blocklist\n# Generated: 2026-04-01\n# Entries: 2\nads.example.com\ntracker.example.com\n";
        let set = parse_domain_list(content);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn parse_bang_comments() {
        let content = "! AdGuard-style comment\nads.example.com\n";
        let set = parse_domain_list(content);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn parse_trailing_dot() {
        let content = "example.com.\n";
        let set = parse_domain_list(content);
        assert!(set.contains("example.com"));
    }

    #[test]
    fn parse_mixed_case() {
        let content = "Tracker.EXAMPLE.com\n";
        let set = parse_domain_list(content);
        assert!(set.contains("tracker.example.com"));
    }

    #[test]
    fn parse_whitespace_trimming() {
        let content = "  tracker.example.com  \n\tads.com\t\n";
        let set = parse_domain_list(content);
        assert_eq!(set.len(), 2);
        assert!(set.contains("tracker.example.com"));
        assert!(set.contains("ads.com"));
    }

    #[test]
    fn parse_rejects_invalid_lines() {
        let content = "good.com\n<script>alert(1)</script>\n||bad.syntax^\nalso-good.com\n";
        let set = parse_domain_list(content);
        assert_eq!(set.len(), 2);
        assert!(set.contains("good.com"));
        assert!(set.contains("also-good.com"));
    }

    #[test]
    fn parse_empty_content() {
        let set = parse_domain_list("");
        assert!(set.is_empty());
    }

    #[test]
    fn parse_only_comments() {
        let content = "# comment 1\n# comment 2\n";
        let set = parse_domain_list(content);
        assert!(set.is_empty());
    }

    #[test]
    fn parse_rejects_empty_labels() {
        let content = "example..com\n.leading-dot.com\n";
        let set = parse_domain_list(content);
        assert!(set.is_empty());
    }

    #[test]
    fn parse_rejects_leading_hyphen_label() {
        let content = "-bad.example.com\ngood.example.com\n";
        let set = parse_domain_list(content);
        assert_eq!(set.len(), 1);
        assert!(set.contains("good.example.com"));
    }

    #[test]
    fn parse_into_deduplicates() {
        let mut set = HashSet::with_hasher(RandomState::new());
        parse_domain_list_into("ads.example.com\ntracker.com\n", &mut set);
        parse_domain_list_into("ads.example.com\nother.com\n", &mut set);
        // ads.example.com appears in both lists, but should only be in set once
        assert_eq!(set.len(), 3);
    }

    // --- bitmask map ---

    #[test]
    fn parse_into_map_basic() {
        let mut map = HashMap::with_hasher(RandomState::new());
        parse_domain_list_into_map("ads.com\ntracker.com\n", 0b01, &mut map, T, S);
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("ads.com").copied(), Some(0b01));
        assert_eq!(map.get("tracker.com").copied(), Some(0b01));
    }

    #[test]
    fn parse_into_map_multi_list_or() {
        let mut map = HashMap::with_hasher(RandomState::new());
        parse_domain_list_into_map("ads.com\nunique-a.com\n", 0b01, &mut map, T, S);
        parse_domain_list_into_map("ads.com\nunique-b.com\n", 0b10, &mut map, T, S);
        // ads.com is in both lists → bitmask = 0b11
        assert_eq!(map.get("ads.com").copied(), Some(0b11));
        assert_eq!(map.get("unique-a.com").copied(), Some(0b01));
        assert_eq!(map.get("unique-b.com").copied(), Some(0b10));
    }

    #[test]
    fn parse_into_map_skips_comments() {
        let mut map = HashMap::with_hasher(RandomState::new());
        parse_domain_list_into_map("# comment\nads.com\n", 1, &mut map, T, S);
        assert_eq!(map.len(), 1);
    }

    // --- hosts format ---

    #[test]
    fn hosts_basic_0000() {
        let content = "0.0.0.0 tracker.example.com\n0.0.0.0 ads.example.com\n";
        let mut map = HashMap::with_hasher(RandomState::new());
        parse_hosts_list_into_map(content, 1, &mut map, T, S);
        assert_eq!(map.len(), 2);
        assert!(map.contains_key("tracker.example.com"));
        assert!(map.contains_key("ads.example.com"));
    }

    #[test]
    fn hosts_basic_127() {
        let content = "127.0.0.1 tracker.example.com\n";
        let mut map = HashMap::with_hasher(RandomState::new());
        parse_hosts_list_into_map(content, 1, &mut map, T, S);
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("tracker.example.com"));
    }

    #[test]
    fn hosts_skips_localhost() {
        let content = "0.0.0.0 localhost\n127.0.0.1 localhost.localdomain\n0.0.0.0 local\n0.0.0.0 broadcasthost\n0.0.0.0 ads.com\n";
        let mut map = HashMap::with_hasher(RandomState::new());
        parse_hosts_list_into_map(content, 1, &mut map, T, S);
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("ads.com"));
    }

    #[test]
    fn hosts_inline_comment() {
        let content = "0.0.0.0 ads.com # block ads\n";
        let mut map = HashMap::with_hasher(RandomState::new());
        parse_hosts_list_into_map(content, 1, &mut map, T, S);
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("ads.com"));
    }

    #[test]
    fn hosts_comments_and_blank() {
        let content = "# Steven Black hosts\n# Updated 2026-04-01\n\n0.0.0.0 ads.com\n";
        let mut map = HashMap::with_hasher(RandomState::new());
        parse_hosts_list_into_map(content, 1, &mut map, T, S);
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn hosts_case_normalize() {
        let content = "0.0.0.0 Tracker.EXAMPLE.COM\n";
        let mut map = HashMap::with_hasher(RandomState::new());
        parse_hosts_list_into_map(content, 1, &mut map, T, S);
        assert!(map.contains_key("tracker.example.com"));
    }

    #[test]
    fn hosts_trailing_dot() {
        let content = "0.0.0.0 example.com.\n";
        let mut map = HashMap::with_hasher(RandomState::new());
        parse_hosts_list_into_map(content, 1, &mut map, T, S);
        assert!(map.contains_key("example.com"));
    }

    #[test]
    fn hosts_tab_separated() {
        let content = "0.0.0.0\tads.com\textra-field\n";
        let mut map = HashMap::with_hasher(RandomState::new());
        parse_hosts_list_into_map(content, 1, &mut map, T, S);
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("ads.com"));
    }

    #[test]
    fn hosts_skips_non_hosts_lines() {
        let content = "just-a-domain.com\n0.0.0.0 ads.com\n";
        let mut map = HashMap::with_hasher(RandomState::new());
        parse_hosts_list_into_map(content, 1, &mut map, T, S);
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("ads.com"));
    }

    #[test]
    fn hosts_bitmask_or() {
        let mut map = HashMap::with_hasher(RandomState::new());
        parse_hosts_list_into_map("0.0.0.0 ads.com\n", 0b01, &mut map, T, S);
        parse_hosts_list_into_map("0.0.0.0 ads.com\n", 0b10, &mut map, T, S);
        assert_eq!(map.get("ads.com").copied(), Some(0b11));
    }

    // --- AdGuard format (sandboxed) ---

    #[test]
    fn adguard_basic_block() {
        let content = "||tracker.example.com^\n||ads.example.com^\n";
        let mut map = HashMap::with_hasher(RandomState::new());
        parse_adguard_list_into_map(content, 1, &mut map, T, S);
        assert_eq!(map.len(), 2);
        assert!(map.contains_key("tracker.example.com"));
        assert!(map.contains_key("ads.example.com"));
    }

    #[test]
    fn adguard_with_modifiers_extracted() {
        let content = "||tracker.com^$third-party\n||ads.com^$popup,document\n";
        let mut map = HashMap::with_hasher(RandomState::new());
        parse_adguard_list_into_map(content, 1, &mut map, T, S);
        assert_eq!(map.len(), 2);
        assert!(map.contains_key("tracker.com"));
        assert!(map.contains_key("ads.com"));
    }

    #[test]
    fn adguard_sandbox_skips_allow() {
        let content = "||block.com^\n@@||allowed.com^\n";
        let mut map = HashMap::with_hasher(RandomState::new());
        parse_adguard_list_into_map(content, 1, &mut map, T, S);
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("block.com"));
        assert!(!map.contains_key("allowed.com"));
    }

    #[test]
    fn adguard_sandbox_skips_important() {
        let content = "||normal.com^\n||important.com^$important\n";
        let mut map = HashMap::with_hasher(RandomState::new());
        parse_adguard_list_into_map(content, 1, &mut map, T, S);
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("normal.com"));
        assert!(!map.contains_key("important.com"));
    }

    #[test]
    fn adguard_sandbox_skips_important_case_insensitively() {
        // `$Important` / `$IMPORTANT` are the same override and must be
        // sandboxed (SkipCounted), not slip through to be ingested as a
        // plain block.
        let content = "||a.com^$Important\n||b.com^$IMPORTANT\n||c.com^$ImPoRtAnT\n";
        let mut map = HashMap::with_hasher(RandomState::new());
        let counts = parse_adguard_list_into_map(content, 1, &mut map, T, S);
        assert!(
            map.is_empty(),
            "all three importance variants must be skipped"
        );
        assert_eq!(counts.parsed_skipped, 3, "each counts as a sandbox skip");
    }

    #[test]
    fn adguard_sandbox_skips_regex() {
        let content = "||block.com^\n/ads[0-9]+\\.example\\.com/\n";
        let mut map = HashMap::with_hasher(RandomState::new());
        parse_adguard_list_into_map(content, 1, &mut map, T, S);
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("block.com"));
    }

    #[test]
    fn adguard_sandbox_skips_wildcard() {
        let content = "||block.com^\n||*.wild.com^\n";
        let mut map = HashMap::with_hasher(RandomState::new());
        parse_adguard_list_into_map(content, 1, &mut map, T, S);
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("block.com"));
    }

    #[test]
    fn adguard_comments() {
        let content = "! AdGuard DNS filter\n! Updated: 2026-04-01\n||ads.com^\n";
        let mut map = HashMap::with_hasher(RandomState::new());
        parse_adguard_list_into_map(content, 1, &mut map, T, S);
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn adguard_case_normalize() {
        let content = "||Tracker.EXAMPLE.COM^\n";
        let mut map = HashMap::with_hasher(RandomState::new());
        parse_adguard_list_into_map(content, 1, &mut map, T, S);
        assert!(map.contains_key("tracker.example.com"));
    }

    #[test]
    fn adguard_no_caret() {
        // Some lists omit the trailing ^ — should still extract domain
        let content = "||ads.com\n";
        let mut map = HashMap::with_hasher(RandomState::new());
        parse_adguard_list_into_map(content, 1, &mut map, T, S);
        assert!(map.contains_key("ads.com"));
    }

    #[test]
    fn adguard_important_with_other_modifiers() {
        // $important mixed with other modifiers → still skipped
        let content = "||ads.com^$third-party,important\n";
        let mut map = HashMap::with_hasher(RandomState::new());
        parse_adguard_list_into_map(content, 1, &mut map, T, S);
        assert!(map.is_empty());
    }

    #[test]
    fn adguard_bitmask_or() {
        let mut map = HashMap::with_hasher(RandomState::new());
        parse_adguard_list_into_map("||ads.com^\n", 0b01, &mut map, T, S);
        parse_adguard_list_into_map("||ads.com^\n", 0b10, &mut map, T, S);
        assert_eq!(map.get("ads.com").copied(), Some(0b11));
    }

    // --- unified dispatcher ---

    #[test]
    fn parse_list_domain_format() {
        let content = "# purge.cc list\nads.com\ntracker.com\n";
        let set = parse_list(content);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn parse_list_hosts_format() {
        let content = "# Steven Black hosts\n0.0.0.0 ads.com\n0.0.0.0 tracker.com\n";
        let set = parse_list(content);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn parse_list_adguard_format() {
        let content = "! AdGuard DNS filter\n||ads.com^\n||tracker.com^\n";
        let set = parse_list(content);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn parse_list_into_map_auto_detects() {
        let mut map = HashMap::with_hasher(RandomState::new());
        parse_list_into_map(
            "0.0.0.0 ads.com\n0.0.0.0 tracker.com\n",
            0b01,
            &mut map,
            T,
            S,
            None,
        );
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("ads.com").copied(), Some(0b01));
    }

    // --- max_entries truncation ---

    #[test]
    fn domain_list_truncates_at_max_entries() {
        let content = "a.com\nb.com\nc.com\nd.com\ne.com\n";
        let mut map = HashMap::with_hasher(RandomState::new());
        parse_domain_list_into_map(content, 1, &mut map, 3, "truncation-test");
        assert_eq!(map.len(), 3);
    }

    #[test]
    fn hosts_list_truncates_at_max_entries() {
        let content = "0.0.0.0 a.com\n0.0.0.0 b.com\n0.0.0.0 c.com\n0.0.0.0 d.com\n";
        let mut map = HashMap::with_hasher(RandomState::new());
        parse_hosts_list_into_map(content, 1, &mut map, 2, "truncation-test");
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn adguard_list_truncates_at_max_entries() {
        let content = "||a.com^\n||b.com^\n||c.com^\n||d.com^\n";
        let mut map = HashMap::with_hasher(RandomState::new());
        parse_adguard_list_into_map(content, 1, &mut map, 2, "truncation-test");
        assert_eq!(map.len(), 2);
    }

    // ── ParsedCounts return values (s43-t1) ─────────────────────

    #[test]
    fn domain_parser_reports_parsed_ok_count() {
        let content = "good.com\nalso-good.com\n";
        let mut map = HashMap::with_hasher(RandomState::new());
        let counts = parse_domain_list_into_map(content, 1, &mut map, T, S);
        assert_eq!(counts.parsed_ok, 2);
        assert_eq!(counts.parsed_skipped, 0);
        assert!(counts.parsed_skipped_samples.is_empty());
    }

    #[test]
    fn domain_parser_counts_invalid_lines_as_skipped() {
        // The validator rejects two of these — they get counted.
        // Comments and blanks do NOT count.
        let content = "# comment\n\ngood.com\n<bad>\n.also-bad\n";
        let mut map = HashMap::with_hasher(RandomState::new());
        let counts = parse_domain_list_into_map(content, 1, &mut map, T, S);
        assert_eq!(counts.parsed_ok, 1);
        assert_eq!(counts.parsed_skipped, 2);
        // Samples preserve verbatim (post-trim) the rejected lines.
        assert_eq!(counts.parsed_skipped_samples.len(), 2);
        assert!(counts.parsed_skipped_samples.contains(&"<bad>".to_string()));
    }

    #[test]
    fn hosts_parser_does_not_count_localhost_aliases_as_skipped() {
        // The localhost-alias filter is expected boilerplate.
        let content = "0.0.0.0 localhost\n0.0.0.0 ads.com\n";
        let mut map = HashMap::with_hasher(RandomState::new());
        let counts = parse_hosts_list_into_map(content, 1, &mut map, T, S);
        assert_eq!(counts.parsed_ok, 1);
        assert_eq!(counts.parsed_skipped, 0);
    }

    #[test]
    fn adguard_parser_counts_sandboxed_rules_as_skipped() {
        // @@ allow / regex / $important all count — operator wants
        // visibility into "external list tried to allow X" supply-chain
        // signals.
        let content = "||good.com^\n@@||allow.com^\n||imp.com^$important\n/regex/\n";
        let mut map = HashMap::with_hasher(RandomState::new());
        let counts = parse_adguard_list_into_map(content, 1, &mut map, T, S);
        assert_eq!(counts.parsed_ok, 1);
        assert_eq!(counts.parsed_skipped, 3);
        assert_eq!(counts.parsed_skipped_samples.len(), 3);
    }

    #[test]
    fn parse_list_into_map_returns_parsed_counts() {
        // The unified dispatcher must propagate the inner parser's counts.
        let content = "good.com\n<bad>\n";
        let mut map = HashMap::with_hasher(RandomState::new());
        let counts = parse_list_into_map(content, 1, &mut map, T, S, None);
        assert_eq!(counts.parsed_ok, 1);
        assert_eq!(counts.parsed_skipped, 1);
    }

    // --- declared format forces the dispatch ---

    #[test]
    fn declared_hosts_forces_parser_on_tab_separated_body() {
        // A tab-separated hosts body misdetects as DomainOnly (the detector
        // requires a literal space after the IP), so auto-detect yields 0
        // entries. A declared `Hosts` format forces the hosts parser, which
        // strips the IP prefix and trims whitespace, recovering the domains.
        let content = "0.0.0.0\tads.com\n0.0.0.0\ttracker.com\n";

        let mut detected = HashMap::with_hasher(RandomState::new());
        parse_list_into_map(content, 1, &mut detected, T, S, None);
        assert_eq!(detected.len(), 0, "auto-detect misses tab-separated hosts");

        let mut forced = HashMap::with_hasher(RandomState::new());
        let counts = parse_list_into_map(content, 1, &mut forced, T, S, Some(ListFormat::Hosts));
        assert_eq!(forced.len(), 2, "declared hosts yields nonzero entries");
        assert!(forced.contains_key("ads.com"));
        assert_eq!(counts.parsed_ok, 2);
    }

    #[test]
    fn declared_adguard_forces_parser_when_head_looks_domain_only() {
        // The first ten content lines are bare domains, so the detector returns
        // DomainOnly; the adguard rules sit below the detection window. A
        // declared `AdGuard` format forces the sandboxed adguard parser so the
        // `||domain^` rules are extracted instead of being silently skipped.
        let mut content = String::new();
        for i in 0..10 {
            content.push_str("domain");
            content.push_str(&i.to_string());
            content.push_str(".example.com\n");
        }
        content.push_str("||ads.example.com^\n");
        assert_eq!(detect_format(&content), ListFormat::DomainOnly);

        let mut forced = HashMap::with_hasher(RandomState::new());
        parse_list_into_map(&content, 1, &mut forced, T, S, Some(ListFormat::AdGuard));
        assert!(
            forced.contains_key("ads.example.com"),
            "declared adguard extracts the rule the detector window missed"
        );
        assert!(
            !forced.contains_key("domain0.example.com"),
            "bare-domain lines are not adguard blocking rules"
        );
    }

    #[test]
    fn declared_none_auto_detects() {
        // `None` preserves the legacy behaviour for slash-form sources with no
        // `[[blocklists]]` row: detection runs and an adguard head parses as
        // adguard.
        let content = "||ads.com^\n||tracker.com^\n";
        let mut map = HashMap::with_hasher(RandomState::new());
        parse_list_into_map(content, 1, &mut map, T, S, None);
        assert_eq!(map.len(), 2);
        assert!(map.contains_key("ads.com"));
    }

    #[test]
    fn parsed_skipped_samples_capped_at_32() {
        // Generate 50 invalid lines — counter grows to 50 but the
        // sample vec stops at 32.
        use std::fmt::Write as _;
        let mut content = String::new();
        for i in 0..50 {
            writeln!(content, "<bad-{i}>").unwrap();
        }
        let mut map = HashMap::with_hasher(RandomState::new());
        let counts = parse_domain_list_into_map(&content, 1, &mut map, T, S);
        assert_eq!(counts.parsed_skipped, 50);
        assert_eq!(counts.parsed_skipped_samples.len(), 32);
    }

    #[test]
    fn unique_domains_ignores_in_list_duplicates() {
        // parsed_ok counts every valid line (pre-dedup); unique_domains
        // counts each domain once. The retention guard relies on the
        // latter so a body padded with repeats of one domain cannot
        // inflate the metric and slip a catastrophic shrink past the
        // guard.
        let content = "a.com\na.com\na.com\nb.com\n";
        let mut map = HashMap::with_hasher(RandomState::new());
        let counts = parse_domain_list_into_map(content, 1, &mut map, T, S);
        assert_eq!(counts.parsed_ok, 4, "every valid line counts pre-dedup");
        assert_eq!(counts.unique_domains, 2, "a.com + b.com");
    }

    #[test]
    fn unique_domains_counts_overlap_with_other_source() {
        // A domain already in the merged map under a DIFFERENT source's
        // bit still counts toward THIS source's unique_domains — the
        // metric is the source's own deduped contribution, independent of
        // cross-source overlap (a fully-shadowed list still reports its
        // real size, unlike the manager's net-new `entries` delta).
        let mut map = HashMap::with_hasher(RandomState::new());
        // Source on bit 0 inserts a.com + b.com.
        parse_domain_list_into_map("a.com\nb.com\n", 1, &mut map, T, S);
        // Source on bit 1 sees a.com (overlap) + c.com (new).
        let counts = parse_domain_list_into_map("a.com\nc.com\n", 1 << 1, &mut map, T, S);
        assert_eq!(
            counts.unique_domains, 2,
            "a.com counts for bit-1 even though the key pre-existed"
        );
        // Map now has a.com (bits 0+1), b.com (bit 0), c.com (bit 1).
        assert_eq!(map.len(), 3);
        assert_eq!(*map.get(&CompactString::new("a.com")).unwrap(), 0b11);
    }

    // ── streaming reader entry point (PerfMem S2, lane B) ───────

    /// Run both the `&str` and streaming paths over the same content and
    /// assert byte-identical results — map contents AND `ParsedCounts`.
    ///
    /// Wraps the reader in a 4-byte `BufReader` rather than handing
    /// `Cursor` straight to `parse_list_into_map_reader`: `Cursor::fill_buf`
    /// returns its whole remaining slice in one call, so a bare `Cursor`
    /// never exercises `read_line`'s own loop-until-`\n`-or-EOF behaviour
    /// over multiple underlying reads. Lane C's real caller is
    /// `BufReader<File>`, where a line routinely spans more than one
    /// `fill_buf` — a 4-byte cap forces every non-trivial line in these
    /// fixtures to cross at least one such boundary.
    fn assert_reader_matches_str(content: &str, declared: Option<ListFormat>) {
        let mut map_str = HashMap::with_hasher(RandomState::new());
        let counts_str = parse_list_into_map(content, 0b01, &mut map_str, T, S, declared);

        let mut map_reader = HashMap::with_hasher(RandomState::new());
        let counts_reader = parse_list_into_map_reader(
            std::io::BufReader::with_capacity(4, std::io::Cursor::new(content.as_bytes())),
            0b01,
            &mut map_reader,
            T,
            S,
            declared,
        )
        .unwrap();

        assert_eq!(map_reader, map_str, "map contents diverge for: {content:?}");
        assert_eq!(
            counts_reader, counts_str,
            "ParsedCounts diverge for: {content:?}"
        );
    }

    #[test]
    fn reader_equivalence_domain_only() {
        let content = "# purge.cc list header\n! bang comment\n\nTracker.EXAMPLE.com.\nads.example.com\n\n<bad-line>\nalso-good.example.com.\n";
        assert_eq!(detect_format(content), ListFormat::DomainOnly);
        assert_reader_matches_str(content, None);
    }

    #[test]
    fn reader_equivalence_hosts() {
        let content = "# Steven Black hosts\n# Updated 2026-04-01\n\n0.0.0.0 Tracker.EXAMPLE.com.\n127.0.0.1 ads.example.com\n0.0.0.0 localhost\n0.0.0.0 broadcasthost\njust-a-domain.com\n0.0.0.0 also-good.example.com # inline comment\n";
        assert_eq!(detect_format(content), ListFormat::Hosts);
        assert_reader_matches_str(content, None);
    }

    #[test]
    fn reader_equivalence_adguard() {
        let content = "! AdGuard DNS filter\n! Updated: 2026-04-01\n\n||Tracker.EXAMPLE.com.^\n\n@@||allowed.example.com^\n||ads.example.com^$third-party\n||important.example.com^$important\n||*.wild.example.com^\n/regex-rule/\n||also-good.example.com\n";
        assert_eq!(detect_format(content), ListFormat::AdGuard);
        assert_reader_matches_str(content, None);
    }

    #[test]
    fn reader_equivalence_empty_content() {
        assert_reader_matches_str("", None);
    }

    #[test]
    fn reader_equivalence_crlf_line_endings() {
        // \r is ASCII whitespace, so `.trim()` erases it on both paths
        // regardless of how `str::lines()` vs. `read_line` each handle
        // the terminator — see `parse_lines_into_sink_reader`'s doc
        // comment. Assert it, don't just reason about it.
        let content = "Tracker.EXAMPLE.com.\r\nads.example.com\r\n\r\n<bad-line>\r\n";
        assert_reader_matches_str(content, None);
    }

    #[test]
    fn reader_read_line_reassembles_across_a_chained_seam() {
        // A line's bytes split across two chained readers must still be
        // read as one line. Exercises `read_line`'s own loop-until-`\n`-
        // or-EOF over a seam directly, in isolation from the sniff. The
        // sniff/replay chain in `parse_list_into_map_reader` can now
        // split mid-line too, once the byte cap in `sniff_format_reader`
        // binds — that case is covered end-to-end by
        // `reader_matches_str_path_across_a_byte_capped_mid_line_cut`.
        let chained =
            std::io::Cursor::new(&b"a.co"[..]).chain(std::io::Cursor::new(&b"m\nb.com\n"[..]));
        let mut map = HashMap::with_hasher(RandomState::new());
        parse_list_into_map_reader(chained, 1, &mut map, T, S, Some(ListFormat::DomainOnly))
            .unwrap();
        assert_eq!(map.len(), 2);
        assert!(map.contains_key("a.com"));
        assert!(map.contains_key("b.com"));
    }

    #[test]
    fn reader_declared_format_skips_sniff_like_str_path() {
        // Mirrors `declared_hosts_forces_parser_on_tab_separated_body`:
        // a tab-separated hosts body misdetects (the detector wants a
        // literal space after the IP); a declared format forces the
        // right parser on the reader path too, and still matches the
        // `&str` path bit-for-bit.
        let content = "0.0.0.0\tads.com\n0.0.0.0\ttracker.com\n";
        assert_reader_matches_str(content, None);
        assert_reader_matches_str(content, Some(ListFormat::Hosts));

        let mut forced = HashMap::with_hasher(RandomState::new());
        let counts = parse_list_into_map_reader(
            std::io::Cursor::new(content.as_bytes()),
            1,
            &mut forced,
            T,
            S,
            Some(ListFormat::Hosts),
        )
        .unwrap();
        assert_eq!(forced.len(), 2, "declared hosts yields nonzero entries");
        assert!(forced.contains_key("ads.com"));
        assert_eq!(counts.parsed_ok, 2);
    }

    #[test]
    fn reader_truncates_at_max_entries_same_as_str_path() {
        // The cap still binds at exactly `max_entries` — that is the
        // supply-chain defence and it must not move. What changed is what
        // happens to the overflow: the parser now keeps scanning and
        // reports the dropped entries in `parsed_truncated` instead of
        // breaking and reporting a healthy-looking `Ok`.
        //
        // Both halves matter. `map.len() == 3` fails if the cap stops
        // binding; `parsed_truncated == 2` fails if the scan goes back to
        // breaking early (it would report 0, or 1, not 2).
        let content = "a.com\nb.com\nc.com\nd.com\ne.com\n";

        let mut map_str = HashMap::with_hasher(RandomState::new());
        let counts_str = parse_domain_list_into_map(content, 1, &mut map_str, 3, "truncation-test");

        let mut map_reader = HashMap::with_hasher(RandomState::new());
        let counts_reader = parse_list_into_map_reader(
            std::io::Cursor::new(content.as_bytes()),
            1,
            &mut map_reader,
            3,
            "truncation-test",
            Some(ListFormat::DomainOnly),
        )
        .unwrap();

        assert_eq!(map_reader.len(), 3);
        assert_eq!(map_reader, map_str);

        assert_eq!(
            counts_str.parsed_truncated, 2,
            "d.com and e.com were dropped by the cap and must be counted, not silently skipped"
        );
        assert_eq!(
            counts_reader.parsed_truncated, counts_str.parsed_truncated,
            "the streaming and &str paths must agree on the truncation count"
        );
        assert_eq!(counts_str.parsed_ok, 3, "parsed_ok counts accepted only");
    }

    #[test]
    fn sniff_format_reader_buffers_at_most_the_documented_cap() {
        // Ten times the cap in all-blank lines: proves the sniff loop
        // stops at exactly DETECT_PREFIX_MAX_LINES regardless of how
        // much more input is available — the bound is real, not just
        // "smaller than this particular input".
        //
        // This pins the LINE cap specifically, and must keep doing so:
        // 2560 one-byte lines sit far under DETECT_PREFIX_MAX_BYTES, so
        // the byte cap cannot bind here and the equality below is a
        // statement about the line cap alone. Its sibling
        // `sniff_prefix_is_bounded_in_bytes_not_only_lines` pins the
        // other bound with the mirror-image input (one long line, where
        // the line cap cannot bind). Do not relax this to `<=` — that
        // would let the byte cap satisfy it and silently retire the
        // line-bound test.
        let huge = "\n".repeat(DETECT_PREFIX_MAX_LINES * 10);
        let mut cursor = std::io::Cursor::new(huge.as_bytes());
        let (format, prefix) = sniff_format_reader(&mut cursor).unwrap();
        assert_eq!(
            format,
            ListFormat::DomainOnly,
            "no content line ever appears"
        );
        assert!(
            prefix.len() < DETECT_PREFIX_MAX_BYTES,
            "fixture must stay under the byte cap or this stops testing the line cap"
        );
        assert_eq!(
            String::from_utf8(prefix).unwrap().lines().count(),
            DETECT_PREFIX_MAX_LINES,
            "sniff buffer must stop at exactly the documented cap"
        );
    }

    #[test]
    fn sniff_prefix_is_bounded_in_bytes_not_only_lines() {
        // Audit F3. ONE line, no `\n` anywhere, four times the byte cap:
        // DETECT_PREFIX_MAX_LINES cannot bind — the loop's very first
        // read would swallow the entire body — so only the byte cap can
        // stop it. Mirror image of
        // `sniff_format_reader_buffers_at_most_the_documented_cap`,
        // which pins the line cap with input the byte cap cannot bind.
        //
        // Built to fail: drop the `take` in `sniff_format_reader` and
        // `prefix` comes back at 4x the cap.
        let body = "a".repeat(DETECT_PREFIX_MAX_BYTES * 4);
        let mut cursor = std::io::Cursor::new(body.as_bytes());
        let (_, prefix) = sniff_format_reader(&mut cursor).unwrap();
        assert!(
            prefix.len() <= DETECT_PREFIX_MAX_BYTES,
            "one line amplified the sniff prefix to {} bytes against a \
             {DETECT_PREFIX_MAX_BYTES}-byte cap",
            prefix.len()
        );
    }

    #[test]
    fn reader_matches_str_path_across_a_byte_capped_mid_line_cut() {
        // The byte cap can fall mid-line, which the line cap never
        // could. The remainder of that line must be spliced back through
        // the `Cursor::chain(reader)` seam and reassembled, or the cap
        // silently corrupts every list carrying one long header line.
        //
        // Also covers the UTF-8 hazard the cap introduces: a multi-byte
        // character straddling the cut would make a `read_line`-based
        // sniff return InvalidData on a perfectly valid list. `€` is
        // 3 bytes and the cap is a power of two, so the cut is
        // guaranteed to land mid-character — asserted below rather than
        // assumed, since a 2-byte filler would align with the cap and
        // quietly stop testing this at all.
        let mut content = String::from("# ");
        content.push_str(&"\u{20ac}".repeat(DETECT_PREFIX_MAX_BYTES / 2));
        content.push_str("\ngood.example.com\nads.example.com\n");
        assert!(
            content.len() > DETECT_PREFIX_MAX_BYTES,
            "fixture must actually exceed the byte cap"
        );

        let (_, prefix) =
            sniff_format_reader(&mut std::io::Cursor::new(content.as_bytes())).unwrap();
        assert_eq!(prefix.len(), DETECT_PREFIX_MAX_BYTES, "byte cap must bind");
        assert!(
            String::from_utf8(prefix).is_err(),
            "cut must land mid-character — otherwise this test says nothing \
             about the UTF-8 hazard, and a read_line-based sniff would pass it"
        );

        assert_reader_matches_str(&content, None);

        // Non-vacuity: the body's real entries survive the cut, so the
        // equality above is not two empty maps agreeing.
        let mut map = HashMap::with_hasher(RandomState::new());
        parse_list_into_map_reader(
            std::io::Cursor::new(content.as_bytes()),
            1,
            &mut map,
            T,
            S,
            None,
        )
        .unwrap();
        assert_eq!(map.len(), 2, "entries past the mid-line cut were lost");
        assert!(map.contains_key("good.example.com"));
    }

    #[test]
    fn reader_format_detection_prefix_is_bounded() {
        // More leading comment lines than DETECT_PREFIX_MAX_LINES, so
        // the hosts marker sits past the streaming sniff window. The
        // &str path (unbounded — `detect_format` sees the whole body)
        // still finds it; the streaming path must not, proving the
        // prefix buffer really is capped and not silently reading the
        // whole body to get a "correct" answer.
        let mut content = String::new();
        for _ in 0..(DETECT_PREFIX_MAX_LINES + 10) {
            content.push_str("# noise\n");
        }
        content.push_str("0.0.0.0 marker.example.com\n");

        assert_eq!(
            detect_format(&content),
            ListFormat::Hosts,
            "unbounded &str detection finds the marker"
        );

        let mut map = HashMap::with_hasher(RandomState::new());
        parse_list_into_map_reader(
            std::io::Cursor::new(content.as_bytes()),
            1,
            &mut map,
            T,
            S,
            None,
        )
        .unwrap();
        assert!(
            !map.contains_key("marker.example.com"),
            "streaming detection must not see past the bounded prefix"
        );
    }

    #[test]
    fn str_path_format_detection_is_not_bounded_unlike_streaming() {
        // Sibling of `reader_format_detection_prefix_is_bounded`, pinning
        // the other half: `parse_list_into_map` (the `&str` entry point)
        // deliberately does NOT route through the bounded streaming
        // sniff — it already holds the whole body resident (it's a
        // `&str`), so capping its detection window would be a pure
        // regression bought with nothing in return. If a future
        // refactor collapses this onto `parse_list_streaming` via a
        // `Cursor`, this test starts failing — that is its job.
        let mut content = String::new();
        for _ in 0..(DETECT_PREFIX_MAX_LINES + 10) {
            content.push_str("# noise\n");
        }
        content.push_str("0.0.0.0 marker.example.com\n");

        let mut map = HashMap::with_hasher(RandomState::new());
        parse_list_into_map(&content, 1, &mut map, T, S, None);
        assert!(
            map.contains_key("marker.example.com"),
            "the &str path already holds the whole body — its detection must not be bounded"
        );
    }

    // ── DomainSink (PerfMem S2, wave 2) ─────────────────────────

    /// Independent `DomainSink` impl, authored here rather than reusing
    /// `MapSink` — proves the frozen trait is sufficient for an
    /// *outside* implementor (mirrors what lane D writes in
    /// `manager.rs`) to reach parity with the legacy map path, not just
    /// that this file's own internal wiring is self-consistent.
    struct TestHashMapSink<'a> {
        map: &'a mut HashMap<CompactString, u64, RandomState>,
        unique_domains: u64,
    }

    impl DomainSink for TestHashMapSink<'_> {
        fn accept(&mut self, domain: &str, bit: u64) -> io::Result<()> {
            let entry = self.map.entry(CompactString::new(domain)).or_insert(0);
            if *entry & bit == 0 {
                self.unique_domains += 1;
            }
            *entry |= bit;
            Ok(())
        }
    }

    fn assert_streaming_sink_matches_legacy_map_path(content: &str, declared: Option<ListFormat>) {
        let mut map_str = HashMap::with_hasher(RandomState::new());
        let counts_str = parse_list_into_map(content, 0b01, &mut map_str, T, S, declared);

        let mut map_via_sink = HashMap::with_hasher(RandomState::new());
        let mut sink = TestHashMapSink {
            map: &mut map_via_sink,
            unique_domains: 0,
        };
        let mut counts_sink = parse_list_streaming(
            std::io::Cursor::new(content.as_bytes()),
            0b01,
            &mut sink,
            T,
            S,
            declared,
        )
        .unwrap();
        // `parse_list_streaming` itself never populates `unique_domains`
        // (see its doc comment) — an outside caller patches it in from
        // its own sink, exactly as `parse_list_into_map_reader` does
        // internally with `MapSink`.
        counts_sink.unique_domains = sink.unique_domains;

        assert_eq!(map_via_sink, map_str, "map mismatch for: {content:?}");
        assert_eq!(
            counts_sink, counts_str,
            "ParsedCounts mismatch for: {content:?}"
        );
    }

    #[test]
    fn streaming_sink_matches_legacy_map_path_domain_only() {
        let content = "# purge.cc list header\n! bang comment\n\nTracker.EXAMPLE.com.\nads.example.com\n\n<bad-line>\nalso-good.example.com.\n";
        assert_streaming_sink_matches_legacy_map_path(content, None);
    }

    #[test]
    fn streaming_sink_matches_legacy_map_path_hosts() {
        let content = "# Steven Black hosts\n0.0.0.0 Tracker.EXAMPLE.com.\n127.0.0.1 ads.example.com\n0.0.0.0 localhost\njust-a-domain.com\n0.0.0.0 also-good.example.com # inline comment\n";
        assert_streaming_sink_matches_legacy_map_path(content, None);
    }

    #[test]
    fn streaming_sink_matches_legacy_map_path_adguard() {
        let content = "! AdGuard DNS filter\n||Tracker.EXAMPLE.com.^\n@@||allowed.example.com^\n||ads.example.com^$third-party\n||important.example.com^$important\n||*.wild.example.com^\n/regex-rule/\n||also-good.example.com\n";
        assert_streaming_sink_matches_legacy_map_path(content, None);
    }

    /// `DomainSink` that just records every accepted `(domain, bit)`
    /// call, duplicates included, in order — proves the trait works for
    /// a sink with no map underneath it at all (CONTRACT-wave2.md's
    /// spill-file case).
    struct RecordingSink {
        events: Vec<(String, u64)>,
    }

    impl DomainSink for RecordingSink {
        fn accept(&mut self, domain: &str, bit: u64) -> io::Result<()> {
            self.events.push((domain.to_string(), bit));
            Ok(())
        }
    }

    #[test]
    fn non_map_sink_receives_every_accepted_line_with_duplicates_in_order() {
        // CONTRACT-wave2.md: "a spill sink does not dedup ... every copy
        // of a domain hashes to the same shard, so the pass-2 HashMap
        // per shard dedups them". Assert `accept` fires once per
        // accepted line, in file order, duplicates included — dedup is
        // not this layer's job.
        let content = "a.com\na.com\nb.com\n<bad>\nc.com\n";
        let mut sink = RecordingSink { events: Vec::new() };
        let counts = parse_list_streaming(
            std::io::Cursor::new(content.as_bytes()),
            0b01,
            &mut sink,
            T,
            S,
            Some(ListFormat::DomainOnly),
        )
        .unwrap();

        assert_eq!(
            sink.events,
            vec![
                ("a.com".to_string(), 0b01),
                ("a.com".to_string(), 0b01),
                ("b.com".to_string(), 0b01),
                ("c.com".to_string(), 0b01),
            ],
            "accept must fire once per accepted line, in order, duplicates included"
        );
        assert_eq!(
            counts.parsed_ok, 4,
            "parsed_ok matches the accept call count exactly"
        );
        assert_eq!(
            counts.parsed_skipped, 1,
            "<bad> is rejected, never reaches the sink"
        );
    }

    #[test]
    fn non_map_sink_sees_max_entries_truncation_including_duplicates() {
        // Pins the interaction CONTRACT-wave2.md calls out twice:
        // `max_entries` counts accepted lines INCLUDING duplicates, and
        // stops with a bare break. Three copies of "a.com" precede
        // "b.com"; a cap of 2 must truncate inside that duplicate run,
        // so "b.com" never reaches the sink — proven at the sink layer,
        // not just the map layer the `*_truncates_at_max_entries` tests
        // already cover.
        let content = "a.com\na.com\na.com\nb.com\n";
        let mut sink = RecordingSink { events: Vec::new() };
        let counts = parse_list_streaming(
            std::io::Cursor::new(content.as_bytes()),
            1,
            &mut sink,
            2,
            "truncation-test",
            Some(ListFormat::DomainOnly),
        )
        .unwrap();

        assert_eq!(
            sink.events,
            vec![("a.com".to_string(), 1), ("a.com".to_string(), 1)],
            "cap hits mid-duplicate-run; b.com must never arrive"
        );
        assert_eq!(counts.parsed_ok, 2);
    }
}
