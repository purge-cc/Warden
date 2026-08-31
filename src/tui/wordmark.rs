//! ASCII-art wordmark glyphs for the dashboard header.
//!
//! Split out from `tui/ui.rs` because the raw strings were escape-noisy
//! (`\u{2588}\u{2580}\u{2580}\u{2588}...`) and iterative tweaks —
//! "P looks too long", "I reads as T" — were painful to edit with
//! escape sequences. Here they're direct Unicode block glyphs, so
//! editing is "open in a monospace-font editor and adjust the
//! shapes." Row widths are pinned by unit tests below.
//!
//! Built from `█ ▀ ▄` plus spaces only. Half-width block glyphs
//! (`▌ ▍ ▘`) from the original design bundle are deliberately avoided
//! because they carry East-Asian-Width "Ambiguous" in Unicode and
//! render with cell-drift on many terminals.

/// PURGE in 3-cell letters — 19 cells wide. Used at every terminal
/// width (the wide variant was retired 2026-04-29 because the 4-cell
/// glyphs rendered malformed on certain font/terminal combinations).
///
/// The "P" originally closed its bowl with `▘` (QUADRANT UPPER LEFT),
/// but that glyph carries East-Asian-Width "Ambiguous" — exactly what
/// the safe-glyph rule above forbids. Replaced with `▀` on
/// 2026-04-29, which closes the bowl with a clean horizontal bar at
/// the middle row and drops the cell-drift risk.
pub const PURGE_COMPACT: [&str; 3] = [
    "█▀█ █ █ █▀█ █▀▀ █▀▀",
    "█▀▀ █ █ █▀▄ █ █ █▀▀",
    "▀   ▀▀▀ ▀ ▀ ▀▀▀ ▀▀▀",
];

/// WARDEN — W in 5 cells, A/R/D/E/N in 3 — 25 cells wide. W and N are
/// the new glyphs; R/D reuse the prior wordmark's letter shapes and A/E
/// mirror PURGE's E. The 5-cell W renders an unmistakable double-V (the 3-cell
/// forms read as U). Width feeds `ui::render_header`'s `wm_width`
/// constant (1 + 19 PURGE + 3 gap + 25 WARDEN = 48).
pub const WARDEN_COMPACT: [&str; 3] = [
    "█   █ █▀█ █▀█ █▀▄ █▀▀ █▄█",
    "█ ▄ █ █▀█ █▀▄ █ █ █▀▀ █ █",
    "▀▀ ▀▀ ▀ ▀ ▀ ▀ ▀▀  ▀▀▀ ▀ ▀",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn row_widths(rows: &[&str; 3]) -> [usize; 3] {
        [
            rows[0].chars().count(),
            rows[1].chars().count(),
            rows[2].chars().count(),
        ]
    }

    /// Every row of every variant must be the same width — otherwise
    /// the layout's left-column constraint is computed against one
    /// row and the other rows spill. This catches the kind of typo
    /// where a space gets dropped after a glyph sequence.
    ///
    /// Note: `chars().count()` counts Unicode code points, not
    /// terminal cells. The two coincide here only because
    /// `glyphs_restricted_to_safe_set` guarantees every glyph is a
    /// single code point that displays as exactly one cell — if you
    /// loosen that allowlist, this test stops being a cell-width
    /// check and you need a different invariant.
    #[test]
    fn every_variant_has_equal_row_widths() {
        for (label, rows) in [
            ("PURGE_COMPACT", &PURGE_COMPACT),
            ("WARDEN_COMPACT", &WARDEN_COMPACT),
        ] {
            let widths = row_widths(rows);
            assert!(
                widths[0] == widths[1] && widths[1] == widths[2],
                "{label}: rows have unequal widths {widths:?} — \
                 the wordmark will misalign in the header",
            );
        }
    }

    /// Pin the exact known widths so a glyph swap that accidentally
    /// resizes the wordmark gets caught before the left-column width
    /// in `ui::render_header` drifts out of sync.
    #[test]
    fn widths_match_header_layout_constants() {
        assert_eq!(row_widths(&PURGE_COMPACT), [19, 19, 19]);
        assert_eq!(row_widths(&WARDEN_COMPACT), [25, 25, 25]);
    }

    /// Only `█ ▀ ▄` + ASCII space are allowed. `▌ ▍ ▐ ▘` and similar
    /// quarter/half-width forms fail this check — they render
    /// inconsistently across terminals due to East-Asian-Width
    /// ambiguity, and the whole point of this module is to stay clear
    /// of them.
    #[test]
    fn glyphs_restricted_to_safe_set() {
        let allowed: &[char] = &['█', '▀', '▄', ' '];
        for (label, rows) in [
            ("PURGE_COMPACT", &PURGE_COMPACT),
            ("WARDEN_COMPACT", &WARDEN_COMPACT),
        ] {
            for (i, row) in rows.iter().enumerate() {
                for ch in row.chars() {
                    assert!(
                        allowed.contains(&ch),
                        "{label}[{i}] contains disallowed glyph {ch:?} \
                         (U+{:04X}) — stick to █ ▀ ▄ + space",
                        ch as u32,
                    );
                }
            }
        }
    }
}
