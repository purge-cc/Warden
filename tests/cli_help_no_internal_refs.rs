//! The help fence: no rendered help page may carry an internal
//! engineering reference.
//!
//! # What this protects
//!
//! `warden --help` is the first surface every operator reads, and it was
//! quoting things only this repository knows about: sprint numbers
//! (`Sprint 43 T5`), design-doc section marks (`§4.12`), decision ids
//! (`D14`, `SN1`, `DR9`), internal document names
//! (`tag_model_consolidation`), and Rust symbol paths
//! (`Cidr::parse_friendly`). `project rules` enforces exactly this
//! internal/public boundary between `CONFIG_GUIDE.md` and its `.public`
//! sibling; it was unenforced in the surface operators actually meet
//! first.
//!
//! None of those tokens are wrong — they are *true*, and they are how the
//! feature is discussed internally. They are simply unreadable to the
//! person the text is addressed to, who has no way to look any of them up.
//!
//! # Why a tree walk and not a grep
//!
//! Two reasons, and the second is the load-bearing one.
//!
//! 1. A grep over `///` lines cannot distinguish a clap doc comment (which
//!    clap-derive promotes into `about` / `long_about`) from an ordinary
//!    rustdoc comment on a helper, or from a `//!` module doc, which never
//!    renders as help at all. It would report leaks that no operator can
//!    see and miss help set through `#[arg(help = …)]`.
//! 2. This walks [`purge_warden::cli::Cli::command()`] — the same tree the
//!    binary dispatches from — so it reads the bytes clap will actually
//!    print. A page added tomorrow is fenced tonight, with nobody
//!    remembering to extend a list.
//!
//! # Both halves of every page
//!
//! `-h` renders `about` (clap-derive: the doc comment's first line);
//! `--help` renders `long_about` (the whole comment). Scanning one and not
//! the other would leave half the surface unfenced — and that split is
//! precisely why some paths render differently under the two flags.
//! Argument `help` / `long_help` are scanned for the same reason.

use std::collections::BTreeSet;

use clap::CommandFactory;
use purge_warden::cli::Cli;

/// One class of internal reference, its detector, and a human-readable
/// name used in the failure report.
///
/// Detectors are hand-rolled rather than regex-driven: the crate has no
/// regex dependency in its dev-dependencies, and each rule below is
/// narrow enough that a scanner states its intent more clearly than a
/// pattern would.
struct Rule {
    name: &'static str,
    /// Returns the matched substring, if any.
    find: fn(&str) -> Option<String>,
}

/// `§` is unambiguous: it only ever appears here as a design-doc section
/// mark. No operator-facing sentence needs it.
fn find_section_mark(s: &str) -> Option<String> {
    let idx = s.find('§')?;
    // Report the mark plus the reference that follows it, so the failure
    // message names `§4.12` rather than a bare glyph.
    let tail: String = s[idx..]
        .chars()
        .take_while(|c| *c == '§' || c.is_ascii_digit() || *c == '.')
        .collect();
    Some(tail)
}

/// True when the byte before `i` is not alphanumeric — i.e. `i` starts a
/// fresh token. `i` must be a char boundary.
///
/// Looking at the preceding *byte* is safe even next to a multi-byte
/// character: a UTF-8 continuation or lead byte is never in the ASCII
/// alphanumeric range, so a non-ASCII neighbour correctly reads as a
/// boundary.
fn starts_token(s: &str, i: usize) -> bool {
    i == 0 || !s.as_bytes()[i - 1].is_ascii_alphanumeric()
}

/// Count ASCII digits starting at byte offset `from`.
fn digit_run(s: &str, from: usize) -> usize {
    s.as_bytes()[from..]
        .iter()
        .take_while(|c| c.is_ascii_digit())
        .count()
}

/// `Sprint 43`, `Sprint C`, `Sprint 43 T5`, `pre-S34`, `S51+`.
///
/// Returns `Sprint ` plus the following whitespace-delimited token, so
/// the report names a stable, meaningful string rather than a fixed
/// number of characters cut mid-word.
fn find_sprint_ref(s: &str) -> Option<String> {
    if let Some(i) = s.find("Sprint ") {
        let rest = &s[i + "Sprint ".len()..];
        let token: String = rest.chars().take_while(|c| !c.is_whitespace()).collect();
        return Some(format!("Sprint {token}"));
    }
    // A bare `S` + two digits as a whole token: `S34`, `S51`. Guarded on
    // both sides so `AS34` or `S345` do not match — the first is a word,
    // the second is not a sprint number this project has ever used.
    //
    // `char_indices`, not `0..len`: see the note on `find_decision_id`.
    for (i, ch) in s.char_indices() {
        if ch != 'S' || !starts_token(s, i) {
            continue;
        }
        let digits = digit_run(s, i + 1);
        if digits != 2 {
            continue;
        }
        let end = i + 1 + digits;
        if s.as_bytes()
            .get(end)
            .is_some_and(|c| c.is_ascii_alphanumeric())
        {
            continue;
        }
        return Some(s[i..end].to_string());
    }
    None
}

/// Decision ids as whole tokens: `D14`, `DR9`, `SN1`, `DM6`.
///
/// Deliberately NOT extended to bare `A1` / `N1`: those are generic enough
/// to appear in a legitimate operator example (a DNS record type, a
/// placeholder id), and a fence with a false-positive class is a fence
/// people learn to suppress.
///
/// # Why `char_indices` and not `0..len`
///
/// The first cut of this function walked byte offsets from
/// `s.as_bytes()` and then sliced `s[i..]`. A byte offset taken from the
/// `[u8]` view is not necessarily a `str` boundary, so the very first
/// help page containing an em-dash — and this help surface is full of
/// them — panicked with *"start byte index 24 is not a char boundary"*.
///
/// That is the identical defect as review item P3-6, where `audit tail`
/// truncated a hash with `&h[..12]` and crashed on a multi-byte
/// character. Worth the paragraph: a fence that panics reports nothing
/// at all, which is strictly worse than one that reports wrongly.
/// `char_indices` yields offsets that are always boundaries.
fn find_decision_id(s: &str) -> Option<String> {
    const PREFIXES: &[&str] = &["DR", "SN", "DM", "D"];
    for (i, _) in s.char_indices() {
        if !starts_token(s, i) {
            continue;
        }
        for p in PREFIXES {
            if !s[i..].starts_with(p) {
                continue;
            }
            let after_prefix = i + p.len();
            let digits = digit_run(s, after_prefix);
            if digits == 0 || digits > 2 {
                continue;
            }
            let end = after_prefix + digits;
            if s.as_bytes()
                .get(end)
                .is_some_and(|c| c.is_ascii_alphanumeric())
            {
                continue;
            }
            return Some(s[i..end].to_string());
        }
    }
    None
}

/// Internal document references: a `_docs/` path, or a bare snake_case
/// design-doc name. Both send the operator somewhere they cannot go.
fn find_internal_doc(s: &str) -> Option<String> {
    if let Some(i) = s.find("_docs/") {
        let tail: String = s[i..].chars().take_while(|c| !c.is_whitespace()).collect();
        return Some(tail);
    }
    for name in [
        "tag_model_consolidation",
        "lists_categories_v2",
        "config_architecture",
        "sprint_roadmap",
        "public_launch",
        "DEVPLAN",
        "PROJECT.md",
        "project rules",
    ] {
        if s.contains(name) {
            return Some(name.to_string());
        }
    }
    None
}

/// A Rust symbol path: `Identifier::function_name`.
///
/// The right-hand side must start with a lowercase letter or `_`, which is
/// what keeps IPv6 literals out: in `2001:db8::1` and `fe80::1` the text
/// after `::` starts with a digit, and `::1` has no identifier before it.
/// That distinction is why this is not a bare search for `::`.
fn find_rust_path(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let ident_char = |c: u8| (c as char).is_ascii_alphanumeric() || c == b'_';
    let mut i = 0;
    while i + 2 < b.len() {
        if b[i] != b':' || b[i + 1] != b':' {
            i += 1;
            continue;
        }
        let rhs = b[i + 2];
        if !((rhs as char).is_ascii_lowercase() || rhs == b'_') {
            i += 1;
            continue;
        }
        // Walk back over the left-hand identifier.
        let mut start = i;
        while start > 0 && ident_char(b[start - 1]) {
            start -= 1;
        }
        if start == i {
            i += 1;
            continue;
        }
        let mut end = i + 2;
        while end < b.len() && ident_char(b[end]) {
            end += 1;
        }
        return Some(s[start..end].to_string());
    }
    None
}

const RULES: &[Rule] = &[
    Rule {
        name: "design-doc section mark",
        find: find_section_mark,
    },
    Rule {
        name: "sprint number",
        find: find_sprint_ref,
    },
    Rule {
        name: "decision id",
        find: find_decision_id,
    },
    Rule {
        name: "internal document",
        find: find_internal_doc,
    },
    Rule {
        name: "Rust symbol path",
        find: find_rust_path,
    },
];

/// One leaked token, located precisely enough to fix without searching.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Leak {
    /// Space-joined command path, e.g. `device tag add`.
    page: String,
    /// Which rendered field carried it: `about`, `long_about`,
    /// `--flag help`, …
    field: String,
    rule: &'static str,
    matched: String,
}

/// Scan one string against every rule, appending any hits.
fn scan(page: &str, field: &str, text: Option<&str>, out: &mut Vec<Leak>) {
    let Some(text) = text else { return };
    for rule in RULES {
        if let Some(matched) = (rule.find)(text) {
            out.push(Leak {
                page: page.to_string(),
                field: field.to_string(),
                rule: rule.name,
                matched,
            });
        }
    }
}

/// Walk every command node, scanning both help renderings and every
/// argument's help on the way down.
fn walk(cmd: &clap::Command, prefix: &str, out: &mut Vec<Leak>) {
    let page = if prefix.is_empty() {
        cmd.get_name().to_string()
    } else {
        format!("{prefix} {}", cmd.get_name())
    };

    scan(
        &page,
        "about",
        cmd.get_about().map(|s| s.to_string()).as_deref(),
        out,
    );
    scan(
        &page,
        "long_about",
        cmd.get_long_about().map(|s| s.to_string()).as_deref(),
        out,
    );

    for arg in cmd.get_arguments() {
        let field = format!("arg `{}`", arg.get_id());
        scan(
            &page,
            &format!("{field} help"),
            arg.get_help().map(|s| s.to_string()).as_deref(),
            out,
        );
        scan(
            &page,
            &format!("{field} long_help"),
            arg.get_long_help().map(|s| s.to_string()).as_deref(),
            out,
        );
    }

    for sub in cmd.get_subcommands() {
        // clap injects a `help` node with no content of its own.
        if sub.get_name() == "help" {
            continue;
        }
        walk(sub, &page, out);
    }
}

fn collect_leaks() -> Vec<Leak> {
    let cmd = Cli::command();
    let mut out = Vec::new();
    walk(&cmd, "", &mut out);
    out.sort();
    out
}

#[test]
fn no_help_page_carries_an_internal_engineering_reference() {
    let leaks = collect_leaks();
    if leaks.is_empty() {
        return;
    }

    let pages: BTreeSet<&str> = leaks.iter().map(|l| l.page.as_str()).collect();
    let mut report = String::new();
    for l in &leaks {
        report.push_str(&format!(
            "  warden {} · {} · {} · `{}`\n",
            l.page, l.field, l.rule, l.matched
        ));
    }

    panic!(
        "{} internal reference(s) leak into {} rendered help page(s):\n{}\n\
         These are printed to operators who cannot look any of them up. \
         Rewrite the doc comment to say what the verb DOES; the sprint \
         number, section mark or decision id belongs in the design doc, \
         the commit message, or a `//` comment — none of which clap \
         renders.\n\n\
         If a token here is a genuine false positive, narrow the rule in \
         this file rather than deleting the assertion: a fence with a \
         known false-positive class is one people learn to route around.",
        leaks.len(),
        pages.len(),
        report
    );
}

/// The detectors must actually detect. Without this, a refactor that
/// broke `find_*` into always returning `None` would leave the fence
/// above permanently, silently green — the exact failure mode a
/// zero-findings assertion cannot distinguish from success.
#[test]
fn the_detectors_fire_on_known_internal_references() {
    // (text, the rule that must catch it, the token it must report).
    //
    // Keyed by RULE, not by "whichever rule fires first". Real leaked
    // text often trips two rules at once — `tag_model_consolidation §3.5`
    // is both an internal document and a section mark — so asserting on
    // the first match makes the test depend on the order of `RULES`,
    // which is an implementation detail nobody should have to preserve.
    let cases: &[(&str, &str, &str)] = &[
        (
            "§4.12 — Manage per-profile domain rewrite rules",
            "design-doc section mark",
            "§4.12",
        ),
        ("Sprint 43 T5: allow a domain", "sprint number", "Sprint 43"),
        ("legacy subcommand retired in S34.", "sprint number", "S34"),
        ("D14 mutual exclusion applies", "decision id", "D14"),
        (
            "Validator refuses public suffixes (DR9)",
            "decision id",
            "DR9",
        ),
        ("SN1 still uses longest-prefix match.", "decision id", "SN1"),
        (
            "see `_docs/features/lists_categories_v2.md`",
            "internal document",
            "_docs/features/lists_categories_v2.md`",
        ),
        (
            "`tag_model_consolidation` §3.5",
            "internal document",
            "tag_model_consolidation",
        ),
        (
            "parsed by Cidr::parse_friendly",
            "Rust symbol path",
            "Cidr::parse_friendly",
        ),
    ];

    for (text, rule_name, expected) in cases {
        let rule = RULES
            .iter()
            .find(|r| r.name == *rule_name)
            .unwrap_or_else(|| panic!("no rule named `{rule_name}` — did a rule get renamed?"));
        assert_eq!(
            (rule.find)(text).as_deref(),
            Some(*expected),
            "the `{rule_name}` rule did not match `{text}` — the fence \
             would pass this leak"
        );
    }
}

/// Every detector must survive multi-byte characters anywhere in the
/// input, including immediately before a candidate match.
///
/// This is a regression test, not a hypothetical. The first cut of
/// `find_decision_id` walked raw byte offsets and sliced `s[i..]`, so it
/// panicked — *"start byte index 24 is not a char boundary; it is inside
/// '—'"* — on the very first real help page it met. This help surface
/// uses em-dashes constantly, so the fence crashed instead of reporting,
/// which reads as "the fence is broken", not "the help is dirty".
///
/// The strings below put a multi-byte character directly before, inside
/// and after the region each detector scans.
#[test]
fn the_detectors_survive_multi_byte_characters() {
    let inputs: &[&str] = &[
        "Upstream DNS server(s) — format depends on mode (overrides config)",
        "— D14 — a decision id right after an em-dash",
        "tags — (`device.tags` ∪ `profile.tags`) ∩ `blocklist.tags` — intersection",
        "naïve · façade · résumé — accented prose with no reference at all",
        "—",
        "∪∩§",
        "",
    ];
    for text in inputs {
        // The assertion is that this does not panic; the verdict itself
        // is checked by the two tests around this one.
        for rule in RULES {
            let _ = (rule.find)(text);
        }
    }
}

/// …and must NOT fire on legitimate operator prose. A fence that flags
/// correct text gets suppressed, which is worse than no fence.
///
/// The IPv6 cases are the ones that earn their keep: `::` is the obvious
/// way to write the Rust-path detector and it would flag every IPv6
/// literal in the help surface.
#[test]
fn the_detectors_do_not_fire_on_operator_prose() {
    let clean: &[&str] = &[
        "Listen address (overrides config)",
        "Bind to [::1]:53 for loopback-only IPv6",
        "Upstream DNS server, e.g. 2001:db8::1:53",
        "Link-local addresses such as fe80::1 are refused",
        "Comma-separated upstream resolvers (addr:port, plain DNS)",
        "Remove a device by id. Use `warden device list` to see them.",
        "Set the DNS-over-TLS server name",
        "Path to a local blocklist file (one domain per line)",
        "Refuse queries from sources with no mapping",
        "A1 and AAAA records are both supported",
        "Retention in days, 1-365",
    ];

    for text in clean {
        let hit = RULES
            .iter()
            .find_map(|r| (r.find)(text).map(|m| (r.name, m)));
        assert!(
            hit.is_none(),
            "false positive: `{text}` was flagged as {:?} — narrow the rule, \
             legitimate operator prose must never trip this fence",
            hit
        );
    }
}
