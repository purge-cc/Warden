//! The `#[cfg(test)]` walk shared by the production-source stripper and by
//! every "no inline test module" pin.
//!
//! Does NOT parse Rust. It recognises the shapes rustfmt actually emits for a
//! cfg-gated item and skips them; anything it cannot classify it refuses
//! loudly rather than guessing, because both consumers read the surviving
//! text as production code and a silent mis-skip makes their scans blind
//! exactly where they claim to look.
//!
//! Not for use outside tests: it exists so the two scans, and the seven pins,
//! share one definition of "this item only exists in test builds" instead of
//! each carrying a copy that drifts.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum StripState {
    Normal,
    Classifying,
    SkippingBlock,
}

/// Splits a line that opens with `#[` into the attribute's own text
/// (everything between the brackets) and whatever follows the closing `]` on
/// the same physical line — `#[cfg(test)]` -> `("cfg(test)", "")`,
/// `#[cfg(test)] mod tests;` -> `("cfg(test)", "mod tests;")`.
///
/// Matches `[`/`]` depth with string literals masked and backslash escapes
/// honoured, so neither a bracket in a string value nor a `\"` inside one can
/// be mistaken for the attribute's own close. Returns `None` when the line
/// does not start with `#[`, or when the brackets never close on this
/// physical line — the caller decides what that means.
pub(crate) fn split_leading_attr(line: &str) -> Option<(&str, &str)> {
    let rest = line.strip_prefix('#')?.strip_prefix('[')?;
    let mut depth: i32 = 1;
    let mut in_string = false;
    let mut escaped = false;
    for (i, &b) in rest.as_bytes().iter().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match b {
            b'\\' if in_string => escaped = true,
            b'"' => in_string = !in_string,
            b'[' if !in_string => depth += 1,
            b']' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    return Some((&rest[..i], rest[i + 1..].trim_start()));
                }
            }
            _ => {}
        }
    }
    None
}

/// `line` with a trailing `//` comment removed, and trailing space trimmed.
/// Only a `//` outside a string literal counts, so a URL in a literal is not
/// mistaken for one.
pub(crate) fn without_line_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_string = false;
    let mut escaped = false;
    for i in 0..bytes.len() {
        if escaped {
            escaped = false;
            continue;
        }
        match bytes[i] {
            b'\\' if in_string => escaped = true,
            b'"' => in_string = !in_string,
            b'/' if !in_string && bytes.get(i + 1) == Some(&b'/') => {
                return line[..i].trim_end();
            }
            _ => {}
        }
    }
    line.trim_end()
}

/// `{` minus `}` over `s`, ignoring both inside string literals. Blind to a
/// brace in a character literal; no such line exists at column 0 in the files
/// these scans read, and the failure is a refusal, not a silent mis-skip.
fn brace_delta(s: &str) -> i32 {
    let mut delta = 0;
    let mut in_string = false;
    let mut escaped = false;
    for &b in s.as_bytes() {
        if escaped {
            escaped = false;
            continue;
        }
        match b {
            b'\\' if in_string => escaped = true,
            b'"' => in_string = !in_string,
            b'{' if !in_string => delta += 1,
            b'}' if !in_string => delta -= 1,
            _ => {}
        }
    }
    delta
}

/// `cfg(PREDICATE)` -> `Some("PREDICATE")`; anything else (a non-`cfg`
/// attribute such as `allow(dead_code)`, or `cfg_attr(..)`, which decorates an
/// item that exists in every build) -> `None`.
fn cfg_inner_predicate(attr: &str) -> Option<&str> {
    attr.strip_prefix("cfg(")?.strip_suffix(')')
}

/// `name(INNER)` -> `Some("INNER")`, for a predicate combinator.
fn strip_combinator<'a>(predicate: &'a str, name: &str) -> Option<&'a str> {
    predicate
        .strip_prefix(name)?
        .trim_start()
        .strip_prefix('(')?
        .strip_suffix(')')
}

/// Top-level comma split of a combinator's operands, blind to commas nested in
/// parentheses or in string literals.
fn split_operands(inner: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escaped = false;
    let mut start = 0usize;
    for (i, &b) in inner.as_bytes().iter().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match b {
            b'\\' if in_string => escaped = true,
            b'"' => in_string = !in_string,
            b'(' if !in_string => depth += 1,
            b')' if !in_string => depth -= 1,
            b',' if !in_string && depth == 0 => {
                out.push(inner[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    let last = inner[start..].trim();
    if !last.is_empty() {
        out.push(last);
    }
    out.retain(|o| !o.is_empty());
    out
}

/// True when *every* build that compiles the marked item is a test build —
/// the only condition under which dropping the item leaves production source
/// intact.
///
/// `all(..)` qualifies as soon as one operand does; `any(..)` needs all of
/// them, because `any(test, feature = "x")` still compiles with that feature
/// on and the item is therefore production source. Everything else, `not(..)`
/// included, counts as production.
///
/// The bias is deliberate and one-directional: keeping test code shows up in
/// the consumers as an extra match they report, while dropping production
/// code makes them silently blind over the region they claim to cover.
fn predicate_is_test_only(predicate: &str) -> bool {
    let predicate = predicate.trim();
    if predicate == "test" {
        return true;
    }
    if let Some(inner) = strip_combinator(predicate, "all") {
        return split_operands(inner)
            .into_iter()
            .any(predicate_is_test_only);
    }
    if let Some(inner) = strip_combinator(predicate, "any") {
        let operands = split_operands(inner);
        return !operands.is_empty() && operands.into_iter().all(predicate_is_test_only);
    }
    false
}

/// True when `line` is a column-0 marker opening a `#[cfg(..)]` attribute
/// whose predicate makes the item test-only. Indented lines are never markers
/// — an indented `#[cfg(test)]` decorates one item inside a block that is
/// itself production code, and removing it would take the block's braces with
/// it. Returns the marker's own tail, so the caller can tell a bare
/// declaration (`mod tests;`) from a block opener (`mod tests {`).
pub(crate) fn is_test_cfg_marker(line: &str) -> Option<&str> {
    if line.starts_with(char::is_whitespace) {
        return None;
    }
    let (attr, tail) = split_leading_attr(line)?;
    let predicate = cfg_inner_predicate(attr)?;
    predicate_is_test_only(predicate).then_some(tail)
}

/// Same predicate as `is_test_cfg_marker` without the column-0 gate, so a
/// consumer counting surviving markers and the walk that removes them share
/// one definition instead of two that can drift apart.
pub(crate) fn looks_like_test_cfg_attr(trimmed_line: &str) -> bool {
    split_leading_attr(trimmed_line)
        .and_then(|(attr, _tail)| cfg_inner_predicate(attr))
        .map(predicate_is_test_only)
        .unwrap_or(false)
}

/// What the text following a marker says about the shape of the item it
/// introduces: nothing yet, a bare declaration that ends here, or a brace
/// block whose close must still be found.
pub(crate) fn classify_tail(tail: &str) -> StripState {
    let tail = without_line_comment(tail);
    if tail.is_empty() {
        return StripState::Classifying;
    }
    if tail.ends_with(';') {
        return StripState::Normal;
    }
    let delta = brace_delta(tail);
    if delta > 0 {
        return StripState::SkippingBlock;
    }
    if delta == 0 && tail.ends_with('}') {
        // The whole item fits on one line — `fn h() -> i32 { 1 }`.
        return StripState::Normal;
    }
    StripState::Classifying
}

/// `src` with every test-only item removed.
///
/// A 3-state walk. `Normal` looks for the next marker; `Classifying` reads
/// forward through stacked attributes and a multi-line signature until the
/// item's shape is known; `SkippingBlock` runs to the item's column-0 close.
///
/// Column-0 delimiters, not brace depth: rustfmt closes a top-level item with
/// a `}` in column 0, whereas brace counting over a whole file is fooled by
/// braces inside string literals.
///
/// Panics rather than mis-stripping when an attribute's brackets do not close
/// on one physical line, or when a marked item's close never arrives before
/// EOF.
pub(crate) fn strip_test_items(src: &str) -> String {
    let mut out = String::new();
    let mut state = StripState::Normal;
    for line in src.lines() {
        state = match state {
            StripState::Normal => {
                if line.starts_with("#[") && split_leading_attr(line).is_none() {
                    panic!(
                        "attribute at {line:?} did not close its brackets on one \
                         physical line; strip_test_items cannot tell whether it \
                         marks a test item, and keeping it would leak a whole \
                         test module into the output — reformat to one line or \
                         extend split_leading_attr for multi-line attributes"
                    );
                }
                if let Some(tail) = is_test_cfg_marker(line) {
                    classify_tail(tail)
                } else {
                    out.push_str(line);
                    out.push('\n');
                    StripState::Normal
                }
            }
            StripState::Classifying => {
                if line.starts_with("#[") {
                    match split_leading_attr(line) {
                        Some((_, tail)) => classify_tail(tail),
                        None => panic!(
                            "attribute at {line:?} did not close its brackets on \
                             one physical line; strip_test_items cannot classify \
                             what follows it — reformat to one line or extend \
                             split_leading_attr for multi-line attributes"
                        ),
                    }
                } else {
                    classify_tail(line)
                }
            }
            StripState::SkippingBlock => {
                if without_line_comment(line) == "}" {
                    StripState::Normal
                } else {
                    StripState::SkippingBlock
                }
            }
        };
    }
    assert_eq!(
        state,
        StripState::Normal,
        "strip_test_items ended in {state:?} at EOF — a test item's closing \
         brace or semicolon was never found; the walk ran off the end of the \
         file and silently dropped every line after the last marker"
    );
    out
}

/// The header text of the item a marker introduces: the marker's own tail
/// plus the lines that follow it, comments and stacked attributes dropped, up
/// to and including the `{` that opens its body or the `;` that ends it.
/// `None` at EOF — `strip_test_items` is what reports that as a failure.
fn item_header(lines: &[&str], marker: usize, tail: &str) -> Option<String> {
    let mut header = String::new();
    let mut text = without_line_comment(tail).to_string();
    let mut i = marker;
    loop {
        if !text.is_empty() {
            if !header.is_empty() {
                header.push(' ');
            }
            header.push_str(&text);
            if header.contains('{') || header.ends_with(';') {
                return Some(header);
            }
        }
        i += 1;
        let next = without_line_comment(lines.get(i)?);
        text = match split_leading_attr(next) {
            Some((_, attr_tail)) => without_line_comment(attr_tail).to_string(),
            None => next.to_string(),
        };
    }
}

/// True when `header` declares a `mod`, past any visibility qualifier: a
/// `pub mod` / `pub(crate) mod` block is the same offender as a bare one.
fn declares_a_mod(header: &str) -> bool {
    let mut rest = header.trim_start();
    if let Some(after_pub) = rest.strip_prefix("pub") {
        rest = after_pub.trim_start();
        if let Some(open) = rest.strip_prefix('(') {
            match open.find(')') {
                Some(close) => rest = open[close + 1..].trim_start(),
                None => return false,
            }
        }
    }
    rest.strip_prefix("mod")
        .is_some_and(|r| r.starts_with(char::is_whitespace))
}

/// Every line of `src` that opens a brace-form `#[cfg(test)] mod { .. }`
/// block, labelled `label:LINE`.
///
/// Deliberately blind to a `#[cfg(test)] fn` opener: a standalone test helper
/// at column 0 is a kept exception, not a regression. It is *not* blind to a
/// visibility qualifier, to attributes stacked between the marker and the
/// `mod`, or to a brace on the following line — each of those is an inline
/// test module by any reading, and each defeated an earlier form of this scan.
pub(crate) fn brace_form_test_mod_offenders(label: &str, src: &str) -> Vec<String> {
    let lines: Vec<&str> = src.lines().collect();
    let mut offenders = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let Some(tail) = is_test_cfg_marker(line) else {
            continue;
        };
        let Some(header) = item_header(&lines, i, tail) else {
            continue;
        };
        if header.contains('{') && declares_a_mod(&header) {
            offenders.push(format!("{label}:{}: {line}", i + 1));
        }
    }
    offenders
}

/// Fails when `src`, the text of the file named `label`, still carries an
/// inline brace-form `#[cfg(test)] mod { .. }` block.
///
/// Every relocated file's pin is this one call. The detection is proved once,
/// by this module's fixtures, instead of once per pin — six pins previously
/// carried four different hand-rolled spellings of it, and the weakest was a
/// bare `contains("mod tests {")` that a rename or a `pub` defeated.
pub(crate) fn assert_no_inline_test_module(label: &str, src: &str) {
    let offenders = brace_form_test_mod_offenders(label, src);
    assert!(
        offenders.is_empty(),
        "an inline #[cfg(test)] mod block is back in {label} — its tests \
         belong in src/tui/tests/<name>.rs, reached via #[path]:\n{}",
        offenders.join("\n")
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixtures are single-line escaped strings, never `r#"..."#` blocks: a raw
    // multi-line string puts its own content at real column 0 inside this
    // file, which the pins' recursive walk would then read as real code.

    fn stripped(src: &str) -> String {
        strip_test_items(src)
    }

    fn offenders(src: &str) -> Vec<String> {
        brace_form_test_mod_offenders("f.rs", src)
    }

    // ── an `any(...)` predicate is not test-only ───────────────────────────

    #[test]
    fn keeps_a_cfg_any_test_or_feature_item() {
        // `any(test, feature = "x")` compiles in a production build with that
        // feature on, so the item is production source and must survive.
        let src =
            "PROD_BEFORE\n#[cfg(any(test, feature = \"x\"))]\nfn real() {\nBODY\n}\nPROD_AFTER\n";
        let out = stripped(src);
        assert!(out.contains("fn real") && out.contains("BODY"), "{out:?}");
    }

    #[test]
    fn strips_a_cfg_any_whose_every_operand_is_test() {
        let src =
            "PROD_BEFORE\n#[cfg(any(test, all(test, unix)))]\nmod t {\nTEST_BODY\n}\nPROD_AFTER\n";
        let out = stripped(src);
        assert!(!out.contains("TEST_BODY"), "{out:?}");
    }

    #[test]
    fn keeps_a_compound_not_test_instead_of_panicking() {
        for src in [
            "PROD\n#[cfg(all(not(test), unix))]\nfn real() {\nBODY\n}\n",
            "PROD\n#[cfg(all(unix, not(test)))]\nfn real() {\nBODY\n}\n",
        ] {
            let out = stripped(src);
            assert!(out.contains("fn real"), "{src:?} -> {out:?}");
        }
    }

    // ── comments are trivia, not item syntax ───────────────────────────────

    #[test]
    fn a_trailing_comment_on_a_bare_declaration_does_not_swallow_the_next_item() {
        // Every relocated test module is declared in this `mod name;` form, so
        // this is one keystroke away from live code.
        let src =
            "PROD_BEFORE\n#[cfg(test)]\nmod t; // relocated\nfn real() {\nBODY\n}\nPROD_AFTER\n";
        let out = stripped(src);
        assert!(out.contains("fn real") && out.contains("BODY"), "{out:?}");
        assert!(!out.contains("mod t;"), "{out:?}");
    }

    #[test]
    fn a_trailing_comment_on_a_block_opener_is_still_a_block() {
        let src = "PROD_BEFORE\n#[cfg(test)]\nmod t { // helpers\nTEST_BODY\n}\nPROD_AFTER\n";
        let out = stripped(src);
        assert!(
            out.contains("PROD_BEFORE") && out.contains("PROD_AFTER"),
            "{out:?}"
        );
        assert!(!out.contains("TEST_BODY"), "{out:?}");
        assert_eq!(offenders(src).len(), 1, "{:?}", offenders(src));
    }

    #[test]
    fn a_trailing_comment_on_the_closing_brace_still_closes_the_block() {
        let src = "PROD_BEFORE\n#[cfg(test)]\nmod t {\nTEST_BODY\n} // tests\nPROD_AFTER\n";
        let out = stripped(src);
        assert!(out.contains("PROD_AFTER"), "{out:?}");
        assert!(!out.contains("TEST_BODY"), "{out:?}");
    }

    #[test]
    fn a_whole_line_comment_between_marker_and_item_is_trivia() {
        // Both halves matter: a comment ending in `;` must not look like a
        // bare declaration, and one ending in `{` must not open a block.
        for src in [
            "PROD_BEFORE\n#[cfg(test)]\n// note; not an item\nmod t {\nTEST_BODY\n}\nPROD_AFTER\n",
            "PROD_BEFORE\n#[cfg(test)]\n/// example: fn foo() {\nmod t;\nPROD_AFTER\nfn real() {\nBODY\n}\n",
        ] {
            let out = stripped(src);
            assert!(out.contains("PROD_AFTER"), "{src:?} -> {out:?}");
            assert!(!out.contains("TEST_BODY"), "{src:?} -> {out:?}");
        }
    }

    #[test]
    fn a_comment_inside_a_cfg_predicate_is_not_a_token() {
        let src = "PROD\n#[cfg(unix /* test builds differ */)]\nfn real() {\nBODY\n}\n";
        assert!(stripped(src).contains("fn real"), "{:?}", stripped(src));
    }

    // ── items complete on one line ─────────────────────────────────────────

    #[test]
    fn a_one_line_item_body_does_not_consume_the_next_item() {
        for src in [
            "PROD_BEFORE\n#[cfg(test)]\nfn h() -> i32 { 1 }\nfn real() {\nBODY\n}\nPROD_AFTER\n",
            "PROD_BEFORE\n#[cfg(test)]\nfn helper() {}\nfn real() {\nBODY\n}\nPROD_AFTER\n",
        ] {
            let out = stripped(src);
            assert!(
                out.contains("fn real") && out.contains("BODY"),
                "{src:?} -> {out:?}"
            );
            assert!(
                !out.contains("fn h(") && !out.contains("fn helper"),
                "{src:?} -> {out:?}"
            );
        }
    }

    #[test]
    fn a_one_line_mod_block_is_an_offender() {
        let src = "#[cfg(test)] mod t {}\n";
        assert_eq!(offenders(src).len(), 1, "{:?}", offenders(src));
    }

    // ── the pin cannot be walked around ────────────────────────────────────

    #[test]
    fn offenders_sees_through_a_visibility_qualifier() {
        for src in [
            "#[cfg(test)]\npub mod t {\nTEST\n}\n",
            "#[cfg(test)]\npub(crate) mod t {\nTEST\n}\n",
            "#[cfg(test)]\npub(super) mod t {\nTEST\n}\n",
        ] {
            assert_eq!(offenders(src).len(), 1, "{src:?} -> {:?}", offenders(src));
        }
    }

    #[test]
    fn offenders_sees_through_a_stacked_attribute() {
        let src = "#[cfg(test)]\n#[allow(dead_code)]\nmod t {\nTEST\n}\n";
        assert_eq!(offenders(src).len(), 1, "{:?}", offenders(src));
    }

    #[test]
    fn offenders_sees_a_brace_on_the_following_line() {
        let src = "#[cfg(test)]\nmod t\n{\nTEST\n}\n";
        assert_eq!(offenders(src).len(), 1, "{:?}", offenders(src));
    }

    #[test]
    fn offenders_names_the_offending_line_not_merely_a_count() {
        // A count-only assertion passes for a function that flags an arbitrary
        // line, so the pin's own self-test must read the hit.
        let src = "PROD\n#[cfg(test)]\nmod sneaky {\nTEST\n}\nPROD\n";
        let hits = offenders(src);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(hits[0].starts_with("f.rs:2: "), "{hits:?}");
    }

    #[test]
    fn offenders_ignores_a_standalone_fn() {
        let src = "PROD\n#[cfg(test)]\nfn h(x: i32) -> i32 {\n    x\n}\nPROD\n";
        assert!(offenders(src).is_empty(), "{:?}", offenders(src));
    }

    #[test]
    fn offenders_ignores_a_bare_relocated_declaration() {
        // The shape every relocated module uses. Nothing pins that this is not
        // an offender except this test.
        let src = "#[cfg(test)]\n#[path = \"tests/t.rs\"]\nmod t;\n";
        assert!(offenders(src).is_empty(), "{:?}", offenders(src));
    }

    #[test]
    fn offenders_recognises_more_than_the_literal_cfg_test_spelling() {
        // Reverting recognition to `line == "#[cfg(test)]"` must go red.
        let src = "#[cfg(all(test, unix))]\nmod t {\nTEST\n}\n";
        assert_eq!(offenders(src).len(), 1, "{:?}", offenders(src));
    }

    // ── a marker the walk cannot classify is refused, never ignored ────────

    #[test]
    #[should_panic(expected = "did not close its brackets")]
    fn a_multiline_marker_is_refused_rather_than_silently_kept() {
        strip_test_items("PROD\n#[cfg(\n    test\n)]\nmod t {\nTEST_BODY\n}\nPROD\n");
    }

    #[test]
    #[should_panic(expected = "did not close its brackets")]
    fn a_multiline_attribute_after_a_marker_is_refused() {
        strip_test_items("#[cfg(test)]\n#[cfg(\n    unix\n)]\nmod t {\n}\n");
    }

    #[test]
    #[should_panic(expected = "ended in")]
    fn an_unclosed_marker_at_eof_is_refused() {
        strip_test_items("#[cfg(test)]\nmod t {\nTEST_BODY\n");
    }

    // ── shapes that must survive verbatim ──────────────────────────────────

    #[test]
    fn keeps_a_cfg_not_test() {
        let src = "#[cfg(not(test))]\nfn real() {\nBODY\n}\n";
        assert_eq!(stripped(src), src);
    }

    #[test]
    fn keeps_a_cfg_attr_test() {
        let src = "#[cfg_attr(test, allow(dead_code))]\nfn real() {\nBODY\n}\n";
        assert_eq!(stripped(src), src);
    }

    #[test]
    fn keeps_a_cfg_feature_named_test() {
        let src = "#[cfg(feature = \"test\")]\nfn real() {\nBODY\n}\n";
        assert_eq!(stripped(src), src);
    }

    #[test]
    fn keeps_an_indented_marker() {
        let src = "impl X {\n    #[cfg(test)]\n    fn with_restore() {}\n}\n";
        assert_eq!(stripped(src), src);
    }

    // ── shapes that must not survive ───────────────────────────────────────

    #[test]
    fn strips_the_block_bare_and_same_line_forms() {
        for src in [
            "PROD_BEFORE\n#[cfg(test)]\nmod t {\nTEST_BODY\n}\nPROD_AFTER\n",
            "PROD_BEFORE\n#[cfg(test)]\nmod t;\nPROD_AFTER\n",
            "PROD_BEFORE\n#[cfg(test)] mod t;\nPROD_AFTER\n",
            "PROD_BEFORE\n#[cfg(all(test, unix))]\nmod t {\nTEST_BODY\n}\nPROD_AFTER\n",
        ] {
            let out = stripped(src);
            assert!(
                out.contains("PROD_BEFORE") && out.contains("PROD_AFTER"),
                "{src:?} -> {out:?}"
            );
            assert!(
                !out.contains("TEST_BODY") && !out.contains("mod t"),
                "{src:?} -> {out:?}"
            );
        }
    }

    #[test]
    fn is_not_fooled_by_a_brace_inside_a_string_literal() {
        let src = "PROD_BEFORE\n#[cfg(test)]\nmod t {\n    let s = \"a}b\";\n}\nPROD_AFTER\n";
        let out = stripped(src);
        assert!(
            out.contains("PROD_BEFORE") && out.contains("PROD_AFTER"),
            "{out:?}"
        );
        assert!(!out.contains("a}b"), "{out:?}");
    }

    #[test]
    fn strips_a_column_zero_standalone_test_fn() {
        let src =
            "PROD_BEFORE\n#[cfg(test)]\npub(crate) fn h(x: i32) -> i32 {\n    x\n}\nPROD_AFTER\n";
        let out = stripped(src);
        assert!(
            out.contains("PROD_BEFORE") && out.contains("PROD_AFTER"),
            "{out:?}"
        );
        assert!(!out.contains("pub(crate) fn h"), "{out:?}");
    }
}
