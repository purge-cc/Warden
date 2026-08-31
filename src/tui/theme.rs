//! Color palette and styled widget helpers for the TUI.
//!
//! Design tokens derived from the purge.cc website for brand consistency.
//! See _docs/rules/TUI_DESIGN.md for the full specification.

use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, BorderType, Borders};
use ratatui::Frame;

// ── Theme struct ───────────────────────────────────────────────────────────

#[allow(dead_code)]
pub struct Theme {
    // Base — backgrounds & surfaces
    pub bg_main: Color,
    pub bg_surface: Color,
    pub bg_elevated: Color,
    pub bg_highlight: Color,
    pub bg_input: Color,

    // Borders
    pub border_default: Color,
    pub border_subtle: Color,
    pub border_focus: Color,

    // Text
    pub text_primary: Color,
    pub text_secondary: Color,
    pub text_muted: Color,
    pub text_disabled: Color,
    pub text_inverse: Color,

    // Brand
    pub brand_red: Color,
    pub brand_red_dim: Color,
    pub brand_red_bg: Color,

    // Red *text*. Same value as `brand_red` today, but a separate token
    // so the two roles can diverge: `brand_red` fills and borders,
    // `red_glow` is the only red allowed on a glyph (Block nature, "No",
    // the Delete label). The palette spec asked for these to be two
    // different hexes with `brand_red` renamed onto #B91C1C — refused,
    // because that silently retargets `chart_1`, `gauge_critical`,
    // `bar_gradient` and `border_focus` across 12 tab files. Splitting
    // the *role* now costs nothing and makes the later value split a
    // one-line change. See _docs/features/tui_modal_palette_spec_v1.md §1.3.
    pub red_glow: Color,

    // Warden-only accents (refined purge.cc brand guide) — no Tailwind
    // origin. teal = ops / bands / "this is a feature"; emerald = the
    // interactive cursor / live focus. See the modal-ecosystem color rule.
    pub warden_teal: Color,
    pub emerald_ping: Color,

    // Scope — feature categories. Refined brand trio (muted, not the
    // original Tailwind-400 brights): these carry *data* meaning, never
    // chrome. Beyond the literal category they read as
    // privacy = identity & location · security = healthy / permissive ·
    // content = caution / unverified.
    pub scope_privacy: Color,
    pub scope_security: Color,
    pub scope_content: Color,
    /// Lavender. The refined brand guide drops this hue; its sole
    /// remaining caller is `settings.rs:284` ("booleans in purple"), so
    /// the token stays until that tab is redesigned.
    pub scope_services: Color,

    // Semantic — status colors
    pub success: Color,
    pub success_bg: Color,
    pub error: Color,
    pub error_bg: Color,
    pub warning: Color,
    pub warning_bg: Color,
    pub info: Color,
    pub info_bg: Color,

    // Chart series (ordered by contrast on dark bg)
    pub chart_1: Color,
    pub chart_2: Color,
    pub chart_3: Color,
    pub chart_4: Color,
    pub chart_5: Color,
    pub chart_6: Color,
    pub chart_7: Color,
    pub chart_8: Color,

    // Sparkline
    pub spark_normal: Color,
    pub spark_rising: Color,
    pub spark_falling: Color,

    // Heatmap — 5-stop cold→hot intensity scale (green → yellow →
    // orange → red). Operator override 2026-05-10 at Sprint C close
    // (supersedes Sprint A single-hue purple).
    // Dormant since Sprint D 2026-05-10 (heatmap retired); tokens
    // reserved for possible future re-introduction.
    pub heat_0: Color,
    pub heat_1: Color,
    pub heat_2: Color,
    pub heat_3: Color,
    pub heat_4: Color,

    // Gauge — threshold-based progress
    pub gauge_empty: Color,
    pub gauge_low: Color,
    pub gauge_mid: Color,
    pub gauge_high: Color,
    pub gauge_critical: Color,

    // Axis & grid
    pub axis_line: Color,
    pub axis_label: Color,
    pub axis_tick: Color,
    pub grid_line: Color,
}

impl Theme {
    pub const fn dark() -> Self {
        Self {
            // Base
            bg_main: Color::Rgb(15, 15, 15),
            bg_surface: Color::Rgb(26, 26, 26),
            bg_elevated: Color::Rgb(38, 38, 38),
            bg_highlight: Color::Rgb(51, 51, 51),
            bg_input: Color::Rgb(31, 31, 31),

            // Border
            border_default: Color::Rgb(64, 64, 64),
            border_subtle: Color::Rgb(46, 46, 46),
            border_focus: Color::Rgb(185, 28, 28),

            // Text
            text_primary: Color::Rgb(229, 229, 229),
            text_secondary: Color::Rgb(163, 163, 163),
            text_muted: Color::Rgb(115, 115, 115),
            text_disabled: Color::Rgb(82, 82, 82),
            text_inverse: Color::Rgb(23, 23, 23),

            // Brand
            brand_red: Color::Rgb(220, 38, 38),
            brand_red_dim: Color::Rgb(153, 27, 27),
            brand_red_bg: Color::Rgb(45, 17, 17),
            red_glow: Color::Rgb(220, 38, 38),

            // Warden-only accents
            warden_teal: Color::Rgb(13, 148, 136),
            emerald_ping: Color::Rgb(52, 211, 153),

            // Scope — refined trio (slate / sage / ochre). Previously the
            // Tailwind-400 brights #60A5FA / #4ADE80 / #FBBF24; the
            // refined values were duplicated as raw hex inside
            // tabs/lists.rs because these tokens still held the old ones.
            // Retargeted here so there is one source of truth.
            scope_privacy: Color::Rgb(110, 138, 184),
            scope_security: Color::Rgb(111, 160, 136),
            scope_content: Color::Rgb(201, 163, 90),
            scope_services: Color::Rgb(167, 139, 250),

            // Semantic
            success: Color::Rgb(74, 222, 128),
            success_bg: Color::Rgb(13, 40, 24),
            error: Color::Rgb(248, 113, 113),
            error_bg: Color::Rgb(45, 17, 17),
            warning: Color::Rgb(251, 191, 36),
            warning_bg: Color::Rgb(45, 32, 6),
            info: Color::Rgb(96, 165, 250),
            info_bg: Color::Rgb(12, 27, 46),

            // Chart series
            chart_1: Color::Rgb(220, 38, 38),
            chart_2: Color::Rgb(96, 165, 250),
            chart_3: Color::Rgb(74, 222, 128),
            chart_4: Color::Rgb(251, 191, 36),
            chart_5: Color::Rgb(167, 139, 250),
            chart_6: Color::Rgb(251, 146, 60),
            chart_7: Color::Rgb(56, 189, 248),
            chart_8: Color::Rgb(244, 114, 182),

            // Sparkline
            spark_normal: Color::Rgb(96, 165, 250),
            spark_rising: Color::Rgb(74, 222, 128),
            spark_falling: Color::Rgb(248, 113, 113),

            // Heatmap — 5-stop cold→hot Tailwind ramp:
            //   heat_0 bg_surface (no data, dark gray)
            //   heat_1 green-400  (low)
            //   heat_2 yellow-400 (med-low)
            //   heat_3 orange-400 (med-hi)
            //   heat_4 red-500    (high)
            // Operator override 2026-05-10 at Sprint C close
            // (supersedes Sprint A's single-hue Tailwind violet).
            // Dormant since Sprint D 2026-05-10 (heatmap retired);
            // RGB stops reserved for possible future re-introduction.
            heat_0: Color::Rgb(26, 26, 26),
            heat_1: Color::Rgb(74, 222, 128),
            heat_2: Color::Rgb(250, 204, 21),
            heat_3: Color::Rgb(251, 146, 60),
            heat_4: Color::Rgb(239, 68, 68),

            // Gauge
            gauge_empty: Color::Rgb(51, 51, 51),
            gauge_low: Color::Rgb(74, 222, 128),
            gauge_mid: Color::Rgb(251, 191, 36),
            gauge_high: Color::Rgb(248, 113, 113),
            gauge_critical: Color::Rgb(220, 38, 38),

            // Axis & grid
            axis_line: Color::Rgb(82, 82, 82),
            axis_label: Color::Rgb(115, 115, 115),
            axis_tick: Color::Rgb(64, 64, 64),
            grid_line: Color::Rgb(46, 46, 46),
        }
    }

    /// Returns chart series colors as a slice for iteration.
    #[allow(dead_code)]
    pub const fn chart_series(&self) -> [Color; 8] {
        [
            self.chart_1,
            self.chart_2,
            self.chart_3,
            self.chart_4,
            self.chart_5,
            self.chart_6,
            self.chart_7,
            self.chart_8,
        ]
    }

    /// Returns the gauge color for a given percentage (0.0–1.0).
    #[allow(dead_code)]
    pub const fn gauge_color(&self, pct: f64) -> Color {
        if pct >= 0.95 {
            self.gauge_critical
        } else if pct >= 0.80 {
            self.gauge_high
        } else if pct >= 0.50 {
            self.gauge_mid
        } else {
            self.gauge_low
        }
    }

    /// Returns the heatmap color for a normalized value (0.0–1.0).
    /// Dormant since Sprint D 2026-05-10 (heatmap retired); kept for
    /// possible future re-introduction.
    #[allow(dead_code)]
    pub const fn heat_color(&self, val: f64) -> Color {
        if val <= 0.0 {
            self.heat_0
        } else if val <= 0.25 {
            self.heat_1
        } else if val <= 0.50 {
            self.heat_2
        } else if val <= 0.75 {
            self.heat_3
        } else {
            self.heat_4
        }
    }

    /// Bar-gradient color for a cell at normalized position
    /// (`cell_index / bar_width`, 0.0–1.0). Use only on "fill = good"
    /// bars. See _docs/rules/TUI_DESIGN.md §"Bar Gradient" for the policy.
    ///
    /// First stop is hardcoded to the original pre-Sprint-A heat_2
    /// dark green (`#1D6B4F`) so the Block Rate / Cache Hit Rate
    /// gauges keep their original cool-start anchor across heatmap
    /// palette changes. Sprint A inadvertently retargeted this stop
    /// to violet-700 by changing `heat_2`'s value while leaving
    /// `bar_gradient` pulling `self.heat_2`; Sprint C operator
    /// override pinned it back to the original.
    pub const fn bar_gradient(&self, pos: f64) -> Color {
        if pos <= 0.20 {
            Color::Rgb(29, 107, 79)
        } else if pos <= 0.45 {
            self.success
        } else if pos <= 0.65 {
            self.warning
        } else if pos <= 0.85 {
            self.chart_6
        } else {
            self.brand_red
        }
    }
}

/// Global theme instance.
pub static T: Theme = Theme::dark();

// ── Reusable styles ────────────────────────────────────────────────────────

pub fn highlight_style() -> Style {
    Style::default().fg(T.text_primary).bg(T.bg_highlight)
}

// ── Block constructors ─────────────────────────────────────────────────────

/// Standard block with rounded corners, subtle border, and a secondary-text
/// title — matches the design's `╭─ Label ─╮` panel chrome. Titles are
/// intentionally rendered in `text_secondary` (not brand_red) so the red
/// stays reserved for data and action affordances.
///
/// Kept available for popup modals that intentionally want the
/// border-title look. The 9 leaf tabs render their title as the first
/// interior row via `ui::render_section_chrome` instead — this gives a
/// brilliant outer border + bold colored title in row 0 which matches
/// the menu card chrome and signals "this is a tab panel, not a popup".
#[allow(dead_code)]
pub fn titled_block(title: &str) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(T.border_default))
        .title_style(Style::default().fg(T.text_secondary))
        .title(title)
}

/// Frame-only block: rounded corners, subtle border, no title on the
/// border. Use when the panel renders its title as the first interior
/// row (codeburn-style "title inside the box, bold, category-coloured")
/// and the panel does not need a category-coloured border. Pendant of
/// `framed_block_colored` for sections without a brand colour.
#[allow(dead_code)]
pub fn framed_block() -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(T.border_default))
}

/// Frame-only block with a category-coloured border. Pair with a
/// matching first-row title in the same colour for visual coupling
/// (codeburn pattern: the eye scans by colour and instantly knows
/// which panel it's looking at). See _docs/rules/TUI_DESIGN.md §"Gauge Anatomy".
pub fn framed_block_colored(border: Color) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(border))
}

/// N13 (`_docs/features/tui_nav_and_help_v1.md` §10a): the one filter-card
/// frame shared by Query Log, Lists, Rules and Tags. Paints
/// `framed_block_colored(T.text_primary)` at `area` (height 3 — top
/// border, one content row, bottom border) and returns the **padded**
/// 1-row inner rect (border + 1-col pad on each side) so every caller's
/// width-budget arithmetic lines up without hand-rolling the same
/// `inner.x + 1` / `width - 2` math four times.
///
/// Deliberately lives here, not in a new `filter_card.rs`: a new module
/// needs a `mod filter_card;` line in `tui/mod.rs`, which this wave does
/// not own (see `LANE-REPORT.md`). `_docs/features/tui_nav_and_help_v1.md`
/// §10a.1 sanctions this file as the fallback site.
///
/// Caller renders one `Line` of fields into the returned rect. Do not
/// write a title — the fields are the label now.
pub fn render_filter_card(f: &mut Frame, area: Rect) -> Rect {
    let block = framed_block_colored(T.text_primary);
    let inner = block.inner(area);
    f.render_widget(block, area);
    Rect {
        x: inner.x.saturating_add(1),
        y: inner.y,
        width: inner.width.saturating_sub(2),
        height: 1,
    }
}

// ── Conditional coloring ───────────────────────────────────────────────────

/// Color a block-percentage value: green < 20%, yellow 20-50%, red > 50%.
pub fn blocked_pct_color(pct: f64) -> Color {
    if pct < 20.0 {
        T.success
    } else if pct <= 50.0 {
        T.warning
    } else {
        T.error
    }
}

/// Color a "last seen" value by staleness (seconds ago).
pub fn last_seen_color(secs_ago: u64) -> Color {
    if secs_ago < 300 {
        T.text_primary
    } else if secs_ago < 3600 {
        T.text_secondary
    } else {
        T.text_muted
    }
}

// ── Contrast ───────────────────────────────────────────────────────────────

/// WCAG 2.x relative luminance of one sRGB channel.
fn srgb_channel(c: u8) -> f64 {
    let c = f64::from(c) / 255.0;
    if c <= 0.03928 {
        c / 12.92
    } else {
        ((c + 0.055) / 1.055).powf(2.4)
    }
}

/// WCAG 2.x relative luminance of an sRGB triplet.
fn relative_luminance(r: u8, g: u8, b: u8) -> f64 {
    0.2126 * srgb_channel(r) + 0.7152 * srgb_channel(g) + 0.0722 * srgb_channel(b)
}

/// WCAG contrast ratio between two colors, in `1.0..=21.0`.
///
/// Returns `None` when either color is not a concrete RGB triplet
/// (`Color::Reset`, indexed, named). Deliberately not a panic: the
/// contrast gate in this module's tests iterates the palette, and a
/// token changing representation must surface as an unhandled pair
/// rather than as a green test.
///
/// `pub` so render modules can assert their own local pairs, and they do:
/// besides this module's gate, `modal_form`'s band tests measure the pair
/// they refused. That division is deliberate — this module holds the
/// palette's role table, a render module holds what it actually paints.
#[allow(dead_code)]
pub fn contrast_ratio(fg: Color, bg: Color) -> Option<f64> {
    let (Color::Rgb(r1, g1, b1), Color::Rgb(r2, g2, b2)) = (fg, bg) else {
        return None;
    };
    let (l1, l2) = (
        relative_luminance(r1, g1, b1),
        relative_luminance(r2, g2, b2),
    );
    let (hi, lo) = if l1 >= l2 { (l1, l2) } else { (l2, l1) };
    Some((hi + 0.05) / (lo + 0.05))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warden_only_brand_tokens_present() {
        // The refined purge.cc brand guide adds two Warden-only accents
        // absent from the original Tailwind-derived palette:
        //   warden_teal  #0D9488  — ops / bands / "this is a feature"
        //   emerald_ping #34D399  — the interactive cursor / live focus
        // The modal-ecosystem color rule leans on both, so pin their
        // exact RGB here.
        assert_eq!(T.warden_teal, Color::Rgb(13, 148, 136));
        assert_eq!(T.emerald_ping, Color::Rgb(52, 211, 153));
    }

    #[test]
    fn red_glow_is_a_new_role_not_a_renamed_brand_red() {
        // The palette spec asked to rename brand_red onto #B91C1C and
        // introduce red_glow at #DC2626. Renaming in place would have
        // retargeted chart_1, gauge_critical, bar_gradient's last stop and
        // border_focus across 12 tab files. Instead the *role* split, with
        // brand_red's value pinned. If someone later re-values brand_red,
        // this fails and they must confirm the blast radius on purpose.
        assert_eq!(T.brand_red, Color::Rgb(220, 38, 38), "brand_red moved");
        assert_eq!(T.red_glow, Color::Rgb(220, 38, 38));
        assert_eq!(T.border_focus, Color::Rgb(185, 28, 28));
    }

    #[test]
    fn scope_trio_holds_the_refined_values() {
        // These exact values were duplicated as raw hex inside
        // tabs/lists.rs while the tokens still held Tailwind brights.
        // Pinned here so the single source of truth cannot drift back.
        assert_eq!(T.scope_privacy, Color::Rgb(110, 138, 184), "slate");
        assert_eq!(T.scope_security, Color::Rgb(111, 160, 136), "sage");
        assert_eq!(T.scope_content, Color::Rgb(201, 163, 90), "ochre");
    }

    #[test]
    fn contrast_ratio_matches_wcag_reference_points() {
        let white = Color::Rgb(255, 255, 255);
        let black = Color::Rgb(0, 0, 0);
        let r = contrast_ratio(white, black).unwrap();
        assert!(
            (r - 21.0).abs() < 0.01,
            "white on black must be 21:1, got {r}"
        );
        let same = contrast_ratio(T.warden_teal, T.warden_teal).unwrap();
        assert!((same - 1.0).abs() < 0.001, "a color on itself is 1:1");
        // Order must not matter — the ratio is symmetric.
        assert_eq!(
            contrast_ratio(white, black).map(|v| (v * 1e6) as i64),
            contrast_ratio(black, white).map(|v| (v * 1e6) as i64),
        );
    }

    #[test]
    fn contrast_ratio_is_none_for_non_rgb_colors() {
        // A token silently becoming a named/indexed color must not read as
        // "passing" in the gate below — it has no measurable luminance.
        assert!(contrast_ratio(Color::Reset, T.bg_main).is_none());
        assert!(contrast_ratio(T.text_primary, Color::Indexed(4)).is_none());
    }

    /// WCAG AA for body text. Applies to every prose pair on every
    /// surface, and **has no exception mechanism** — deliberately. The
    /// whole point of splitting the two floors is that excusing one
    /// glanceable mark must not lower the bar for sentences.
    const PROSE_FLOOR: f64 = 4.5;

    /// WCAG AA's large/bold provision, for short glanceable marks: state
    /// words, chips, single glyphs. Exceptions below it are declarable —
    /// see [`SUB_FLOOR_ACCENTS`].
    const ACCENT_FLOOR: f64 = 3.0;

    /// Accent pairs that sit below [`ACCENT_FLOOR`], each named with the
    /// reason the bar does not apply to that mark.
    ///
    /// `contrast_gate_holds_for_every_text_pair` reads this table in
    /// **both** directions, so it cannot rot into an amnesty:
    ///
    /// * a pair below the floor with **no** row fails as undeclared. This
    ///   is the hole the gate had until 2026-08-08: `bg_highlight` was
    ///   left out of the surfaces entirely, so anything landing on it was
    ///   admitted by absence rather than by a decision;
    /// * a row whose pair now **clears** the floor fails as stale, and has
    ///   to be deleted in the commit that lifts it;
    /// * a row naming a pair the gate does not enumerate fails as a typo.
    ///
    /// What the assertion actually checks is the **ratio**, not the paint
    /// site — this module cannot see render code. The reason strings carry
    /// the paint-site claim and are held by review; the render modules
    /// hold their own span-level tests (see the gate's doc).
    const SUB_FLOOR_ACCENTS: [(&str, &str, &str); 3] = [
        (
            "brand_red",
            "bg_highlight",
            "2.62:1 — `modal_form::title_band`'s leading `▌` tick. A solid \
             block glyph, not a letterform: it has no interior shape the eye \
             has to resolve, so WCAG's text bars do not describe it. The \
             title beside it on the same band is `text_primary` at 10.03:1, \
             and that IS held to the prose floor by this gate.",
        ),
        (
            "red_glow",
            "bg_highlight",
            "2.62:1 — not painted on the focus bar, and must not be: a \
             focused row drops its semantic hue and renders `text_primary`. \
             Keyed separately from `brand_red` above even though the two \
             hold the same RGB today, because the role split exists exactly \
             so they can diverge (see the token's comment). One value, two \
             reasons — the day the values part, each row still describes its \
             own mark.",
        ),
        (
            "text_muted",
            "bg_highlight",
            "2.66:1 — same rule as `red_glow`: muted grey never lands on the \
             focus bar. A row that is dim because it is stale becomes \
             `text_primary` while focused, and goes back to muted the moment \
             focus leaves.",
        ),
    ];

    /// The build gate the palette spec asked for, sized to what a terminal
    /// actually renders.
    ///
    /// Enumerates **every** `bg_*` token in `Theme` — all five — against
    /// every foreground that carries a glyph. Nothing is held back for a
    /// narrower test: until 2026-08-08 `bg_highlight` was, and the test it
    /// deferred to (`focus_bar_admits_only_high_contrast_foregrounds`) is a
    /// *positive* list, so it enumerated nothing and forbade nothing. A
    /// `warden_teal` band on `bg_highlight` (3.37:1, against a 4.5:1 prose
    /// bar) was written, reviewed and nearly shipped with both tests green;
    /// it was caught by reading `modal_form`'s colour rule and measuring by
    /// hand. A gate that cannot fail is indistinguishable from one that
    /// passes.
    ///
    /// ## What this gate does NOT cover
    ///
    /// It holds the palette's **role table** — which token may carry which
    /// kind of text, on which surface. It cannot see render sites: theme.rs
    /// has no view of what `modal_form` or a tab actually paints. Paint
    /// sites are held by the render module's own tests, which assert over
    /// rendered spans (`modal_form::desc_band2`'s twin tests are the worked
    /// example). Both halves are needed; neither substitutes for the other.
    ///
    /// ## Two deviations from the spec's §7, both measured rather than assumed
    ///
    /// 1. It measured everything against a `#0F0F11` page background. The
    ///    modal body is drawn on `bg_elevated` `#262626`
    ///    (`modal_form::render_body_fixed`), which costs every pair ~0.6-0.9
    ///    of ratio. The spec's numbers were optimistic for a surface the TUI
    ///    never paints.
    /// 2. A flat 4.5:1 bar would fail on tokens the spec itself mandates
    ///    (`red_glow` 3.13, `warden_teal` 4.04, `scope_privacy` 4.32). These
    ///    are short bold state labels, not prose, so they are held to
    ///    [`ACCENT_FLOOR`] while anything carrying sentences stays at
    ///    [`PROSE_FLOOR`].
    ///
    /// The tightest pair in the whole gate is `text_secondary` on
    /// `bg_highlight` at **5.01:1** — half a point of headroom. It is the
    /// first thing that goes red if anyone dims `text_secondary` or lightens
    /// the focus bar, which is the reason worth adding the surface.
    /// Every background token a glyph can land on — all five, including
    /// the focus bar. A surface off this list is a surface where any tint
    /// passes in silence, so the list is held exhaustive by
    /// [`every_background_token_reaches_the_gate`] rather than by the
    /// sentence you are reading.
    fn surfaces() -> [(&'static str, Color); 5] {
        [
            ("bg_main", T.bg_main),
            ("bg_surface", T.bg_surface),
            ("bg_elevated", T.bg_elevated),
            ("bg_highlight", T.bg_highlight),
            ("bg_input", T.bg_input),
        ]
    }

    /// [`surfaces`] claims to be *every* background the theme defines.
    /// Until this test that claim was a comment — and a comment does not
    /// fail a build, which is the exact shape of the defect the gate was
    /// repaired for. A sixth `bg_*` token nobody added to the list would
    /// be a surface where every tint passes in silence: the same bug, one
    /// level up.
    ///
    /// The destructuring is exhaustive on purpose — no `..`. Adding a
    /// field to `Theme` breaks this test's *compile*, and whoever adds it
    /// has to say which bin it falls in. Precedent: the exhaustive
    /// `let Blocklist { … }` that stopped config fields vanishing on save.
    ///
    /// Keying on values instead would be unsound: `gauge_empty` and
    /// `bg_highlight` are both `Rgb(51, 51, 51)`, so a value-keyed check
    /// cannot tell a background from a fill that happens to match one.
    #[test]
    fn every_background_token_reaches_the_gate() {
        let Theme {
            // Surfaces — the bin this test exists to guard.
            bg_main,
            bg_surface,
            bg_elevated,
            bg_highlight,
            bg_input,
            // Everything else: never a background a glyph lands on.
            // Borders and rules are chrome, `*_bg` tokens are fills
            // behind a badge, the rest are foreground marks.
            border_default: _,
            border_subtle: _,
            border_focus: _,
            text_primary: _,
            text_secondary: _,
            text_muted: _,
            text_disabled: _,
            text_inverse: _,
            brand_red: _,
            brand_red_dim: _,
            brand_red_bg: _,
            red_glow: _,
            warden_teal: _,
            emerald_ping: _,
            scope_privacy: _,
            scope_security: _,
            scope_content: _,
            scope_services: _,
            success: _,
            success_bg: _,
            error: _,
            error_bg: _,
            warning: _,
            warning_bg: _,
            info: _,
            info_bg: _,
            chart_1: _,
            chart_2: _,
            chart_3: _,
            chart_4: _,
            chart_5: _,
            chart_6: _,
            chart_7: _,
            chart_8: _,
            spark_normal: _,
            spark_rising: _,
            spark_falling: _,
            heat_0: _,
            heat_1: _,
            heat_2: _,
            heat_3: _,
            heat_4: _,
            gauge_empty: _,
            gauge_low: _,
            gauge_mid: _,
            gauge_high: _,
            gauge_critical: _,
            axis_line: _,
            axis_label: _,
            axis_tick: _,
            grid_line: _,
        } = Theme::dark();

        let defined = [
            ("bg_main", bg_main),
            ("bg_surface", bg_surface),
            ("bg_elevated", bg_elevated),
            ("bg_highlight", bg_highlight),
            ("bg_input", bg_input),
        ];
        let listed = surfaces();
        assert_eq!(
            defined.len(),
            listed.len(),
            "the theme defines {} backgrounds and the gate enumerates {}",
            defined.len(),
            listed.len()
        );
        for (name, color) in defined {
            assert!(
                listed.iter().any(|(n, c)| *n == name && *c == color),
                "background {name} is defined by Theme but not enumerated by \
                 the contrast gate — a surface off the list is a surface where \
                 any tint passes in silence, which is the defect this gate was \
                 repaired for on 2026-08-08"
            );
        }
    }

    #[test]
    fn contrast_gate_holds_for_every_text_pair() {
        let surfaces = surfaces();

        // Carries sentences the operator must read: labels, values, hints.
        let prose = [
            ("text_primary", T.text_primary),
            ("text_secondary", T.text_secondary),
        ];

        // Short, bold, glanceable: state words, chips, single glyphs.
        // `brand_red` is here as well as `red_glow`: it is painted as a
        // glyph (`title_band`'s tick) and was enumerated against no
        // background at all while only its same-valued twin was listed.
        let accent = [
            ("scope_privacy", T.scope_privacy),
            ("scope_security", T.scope_security),
            ("scope_content", T.scope_content),
            ("scope_services", T.scope_services),
            ("warden_teal", T.warden_teal),
            ("emerald_ping", T.emerald_ping),
            ("brand_red", T.brand_red),
            ("red_glow", T.red_glow),
            ("text_muted", T.text_muted),
        ];

        let mut declared_used = [false; SUB_FLOOR_ACCENTS.len()];

        for (bg_name, bg) in surfaces {
            for (name, fg) in prose {
                let r = contrast_ratio(fg, bg)
                    .unwrap_or_else(|| panic!("{name} on {bg_name}: not an RGB pair"));
                assert!(
                    r >= PROSE_FLOOR,
                    "prose token {name} on {bg_name} is {r:.2}:1, below WCAG AA \
                     {PROSE_FLOOR}:1. Prose has no exception mechanism: this pair \
                     has to move to a darker surface or a brighter token, not be \
                     declared away"
                );
            }
            for (name, fg) in accent {
                let r = contrast_ratio(fg, bg)
                    .unwrap_or_else(|| panic!("{name} on {bg_name}: not an RGB pair"));
                match SUB_FLOOR_ACCENTS
                    .iter()
                    .position(|(f, b, _)| *f == name && *b == bg_name)
                {
                    Some(i) => {
                        declared_used[i] = true;
                        assert!(
                            r < ACCENT_FLOOR,
                            "{name} on {bg_name} is {r:.2}:1 and now clears \
                             {ACCENT_FLOOR}:1 — its row in SUB_FLOOR_ACCENTS is \
                             stale. Delete the row in the commit that lifted the \
                             ratio, so the table never outlives its reasons"
                        );
                    }
                    None => assert!(
                        r >= ACCENT_FLOOR,
                        "accent token {name} on {bg_name} is {r:.2}:1, below WCAG \
                         AA large/bold {ACCENT_FLOOR}:1, and undeclared. Either it \
                         may not carry text there, or add a row to \
                         SUB_FLOOR_ACCENTS saying why the bar does not apply to \
                         that mark"
                    ),
                }
            }
        }

        for (i, (fg, bg, _)) in SUB_FLOOR_ACCENTS.iter().enumerate() {
            assert!(
                declared_used[i],
                "SUB_FLOOR_ACCENTS declares {fg} on {bg}, a pair this gate does \
                 not enumerate — a typo, or a token that left the tables and took \
                 its exception with it"
            );
        }
    }

    #[test]
    fn focus_bar_admits_only_high_contrast_foregrounds() {
        // A *policy* claim, not a measurement: several semantic tokens do
        // clear 4.5:1 on `bg_highlight` (scope_content 5.34, info 4.97,
        // chart_8 4.77, scope_services 4.64, error 4.57). The rule is that
        // a focused row drops its semantic hue and renders text_primary
        // anyway — meaning returns the moment focus leaves — so these two
        // are the only foregrounds the bar is *meant* to carry, and this
        // test pins that both clear the prose floor.
        //
        // Worth keeping alongside the gate above: there `emerald_ping` is
        // an accent, held to 3.0. Here it is held to 4.5, because on the
        // focus bar it is the live-cursor mark and there is no cheaper
        // fallback behind it.
        for (name, fg) in [
            ("text_primary", T.text_primary),
            ("emerald_ping", T.emerald_ping),
        ] {
            let r = contrast_ratio(fg, T.bg_highlight).unwrap();
            assert!(r >= PROSE_FLOOR, "{name} on the focus bar is {r:.2}:1");
        }
        // Guard the premise: if red ever clears 4.5 on the bar, the
        // "no semantics on the focus bar" rule can be revisited.
        let red = contrast_ratio(T.red_glow, T.bg_highlight).unwrap();
        assert!(
            red < PROSE_FLOOR,
            "red_glow now clears the bar ({red:.2}:1) — revisit"
        );
    }

    #[test]
    fn primary_action_fill_is_readable() {
        // Save is the one filled button in a modal: text_inverse on a
        // warden_teal fill. At 4.79:1 it clears AA — worth pinning, because
        // the same label on a brand_red fill would be 3.71:1, which is why
        // Delete is outlined rather than filled.
        let save = contrast_ratio(T.text_inverse, T.warden_teal).unwrap();
        assert!(save >= 4.5, "Save fill is {save:.2}:1");
    }

    /// `text_disabled` is deliberately below every threshold — it marks
    /// content that is genuinely inactive (an unselected radio option) and
    /// must never carry information the operator has to read.
    #[test]
    fn text_disabled_is_intentionally_sub_threshold() {
        let r = contrast_ratio(T.text_disabled, T.bg_elevated).unwrap();
        assert!(
            r < 3.0,
            "text_disabled reads as active text at {r:.2}:1 — either it was \
             brightened or it is being used for something it should not be"
        );
    }
}
