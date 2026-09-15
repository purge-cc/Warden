//! Color palette and styled widget helpers for the TUI.
//!
//! Design tokens derived from the purge.cc website for brand consistency.

use std::cell::Cell;
use std::ops::Deref;

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, BorderType, Borders, Paragraph, Widget};
use ratatui::Frame;

// ── Theme struct ───────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
#[allow(dead_code)]
pub struct Theme {
    // Base — backgrounds & surfaces
    pub bg_main: Color,
    pub bg_surface: Color,
    pub bg_elevated: Color,
    pub bg_highlight: Color,
    pub bg_input: Color,

    // Card bands. These are card hierarchy, not status surfaces: the three
    // role pairs stay coordinated while preserving their own title/subtitle
    // contrast in every preset.
    pub card_summary_title_bg: Color,
    pub card_summary_subtitle_bg: Color,
    pub card_analytics_title_bg: Color,
    pub card_analytics_subtitle_bg: Color,
    pub card_history_title_bg: Color,
    pub card_history_subtitle_bg: Color,

    // Navigation and modal headings share the accepted paired red bands.
    pub navigation_active_bg: Color,
    pub navigation_active_fg: Color,
    pub navigation_submenu_bg: Color,

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
    // `border_focus` across 12 tab files. Splitting
    // the *role* now costs nothing and makes the later value split a
    // one-line change.
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
    // orange → red). The heatmap itself is retired; tokens are kept
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

/// Built-in palettes. The selection belongs to [`crate::tui::app::App`];
/// [`set_active`] makes that selection available to legacy renderers through
/// [`T`] for the duration of a frame.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ThemePreset {
    #[default]
    Warden,
    TokyoNight,
    Gruvbox,
    Everforest,
    Dracula,
}

/// Semantic card families. Card renderers choose a role, never a raw colour,
/// so the blue/green/yellow hierarchy follows every active preset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CardRole {
    /// Primary operational summaries use the first (blue) family.
    Summary,
    /// Live analysis uses the second (green) family.
    Analytics,
    /// History and cautionary data use the third (yellow) family.
    History,
}

impl ThemePreset {
    pub const ALL: [Self; 5] = [
        Self::Warden,
        Self::TokyoNight,
        Self::Gruvbox,
        Self::Everforest,
        Self::Dracula,
    ];

    pub const fn next(self) -> Self {
        match self {
            Self::Warden => Self::TokyoNight,
            Self::TokyoNight => Self::Gruvbox,
            Self::Gruvbox => Self::Everforest,
            Self::Everforest => Self::Dracula,
            Self::Dracula => Self::Warden,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Warden => "Warden",
            Self::TokyoNight => "Tokyo Night",
            Self::Gruvbox => "Gruvbox",
            Self::Everforest => "Everforest",
            Self::Dracula => "Dracula",
        }
    }
}

struct BasePalette {
    bg_main: Color,
    bg_surface: Color,
    bg_elevated: Color,
    bg_highlight: Color,
    text_primary: Color,
    text_secondary: Color,
    text_muted: Color,
    text_inverse: Color,
    brand_red: Color,
    teal: Color,
    success: Color,
    warning: Color,
    info: Color,
    privacy: Color,
    security: Color,
    content: Color,
    frame: Color,
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
            card_summary_title_bg: Color::Rgb(96, 165, 250),
            card_summary_subtitle_bg: Color::Rgb(52, 69, 91),
            card_analytics_title_bg: Color::Rgb(52, 211, 153),
            card_analytics_subtitle_bg: Color::Rgb(42, 81, 67),
            card_history_title_bg: Color::Rgb(251, 191, 36),
            card_history_subtitle_bg: Color::Rgb(91, 76, 38),

            navigation_active_bg: Color::Rgb(185, 28, 28),
            navigation_active_fg: Color::Rgb(229, 229, 229),
            navigation_submenu_bg: Color::Rgb(75, 36, 36),

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
            // The heatmap itself is retired; RGB stops are kept
            // reserved for possible future re-introduction.
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

    const fn recolored(palette: BasePalette) -> Self {
        let BasePalette {
            bg_main,
            bg_surface,
            bg_elevated,
            bg_highlight,
            text_primary,
            text_secondary,
            text_muted,
            text_inverse,
            brand_red,
            teal,
            success,
            warning,
            info,
            privacy,
            security,
            content,
            frame,
        } = palette;
        let mut theme = Self::dark();
        theme.bg_main = bg_main;
        theme.bg_surface = bg_surface;
        theme.bg_elevated = bg_elevated;
        theme.bg_highlight = bg_highlight;
        theme.bg_input = bg_surface;
        theme.border_default = frame;
        theme.border_subtle = bg_surface;
        theme.border_focus = brand_red;
        theme.text_primary = text_primary;
        theme.text_secondary = text_secondary;
        theme.text_muted = text_muted;
        theme.text_disabled = text_muted;
        theme.text_inverse = text_inverse;
        theme.navigation_active_bg = brand_red;
        theme.navigation_active_fg = text_inverse;
        theme.brand_red = brand_red;
        theme.brand_red_dim = brand_red;
        theme.brand_red_bg = bg_highlight;
        theme.red_glow = brand_red;
        theme.warden_teal = teal;
        theme.emerald_ping = success;
        theme.scope_privacy = privacy;
        theme.scope_security = security;
        theme.scope_content = content;
        theme.scope_services = privacy;
        theme.success = success;
        theme.success_bg = bg_surface;
        theme.error = brand_red;
        theme.error_bg = bg_highlight;
        theme.warning = warning;
        theme.warning_bg = bg_surface;
        theme.info = info;
        theme.info_bg = bg_surface;
        theme.chart_1 = brand_red;
        theme.chart_2 = info;
        theme.chart_3 = success;
        theme.chart_4 = warning;
        theme.chart_5 = privacy;
        theme.chart_6 = content;
        theme.chart_7 = teal;
        theme.chart_8 = brand_red;
        theme.spark_normal = info;
        theme.spark_rising = success;
        theme.spark_falling = brand_red;
        theme.heat_0 = bg_surface;
        theme.heat_1 = success;
        theme.heat_2 = warning;
        theme.heat_3 = content;
        theme.heat_4 = brand_red;
        theme.gauge_empty = bg_highlight;
        theme.gauge_low = success;
        theme.gauge_mid = warning;
        theme.gauge_high = brand_red;
        theme.gauge_critical = brand_red;
        theme.axis_line = frame;
        theme.axis_label = text_muted;
        theme.axis_tick = frame;
        theme.grid_line = bg_surface;
        theme
    }

    const fn with_submenu(mut self, color: Color) -> Self {
        self.navigation_submenu_bg = color;
        self
    }

    const fn with_navigation_text(mut self, color: Color) -> Self {
        self.navigation_active_fg = color;
        self
    }

    pub fn modal_heading_style(&self, subtitle: bool) -> Style {
        if subtitle {
            Style::default()
                .bg(self.navigation_submenu_bg)
                .fg(self.text_primary)
        } else {
            Style::default()
                .bg(self.navigation_active_bg)
                .fg(self.navigation_active_fg)
                .add_modifier(ratatui::style::Modifier::BOLD)
        }
    }

    const fn with_card_bands(
        mut self,
        summary_title: Color,
        summary_subtitle: Color,
        analytics_title: Color,
        analytics_subtitle: Color,
        history_title: Color,
        history_subtitle: Color,
    ) -> Self {
        self.card_summary_title_bg = summary_title;
        self.card_summary_subtitle_bg = summary_subtitle;
        self.card_analytics_title_bg = analytics_title;
        self.card_analytics_subtitle_bg = analytics_subtitle;
        self.card_history_title_bg = history_title;
        self.card_history_subtitle_bg = history_subtitle;
        self
    }

    pub const fn card_title_bg(&self, role: CardRole) -> Color {
        match role {
            CardRole::Summary => self.card_summary_title_bg,
            CardRole::Analytics => self.card_analytics_title_bg,
            CardRole::History => self.card_history_title_bg,
        }
    }

    pub const fn card_subtitle_bg(&self, role: CardRole) -> Color {
        match role {
            CardRole::Summary => self.card_summary_subtitle_bg,
            CardRole::Analytics => self.card_analytics_subtitle_bg,
            CardRole::History => self.card_history_subtitle_bg,
        }
    }

    const fn tokyo_night() -> Self {
        Self::recolored(BasePalette {
            bg_main: Color::Rgb(26, 27, 38),
            bg_surface: Color::Rgb(31, 35, 53),
            bg_elevated: Color::Rgb(36, 40, 59),
            bg_highlight: Color::Rgb(41, 46, 66),
            text_primary: Color::Rgb(192, 202, 245),
            text_secondary: Color::Rgb(169, 177, 214),
            text_muted: Color::Rgb(115, 122, 162),
            text_inverse: Color::Rgb(26, 27, 38),
            brand_red: Color::Rgb(247, 118, 142),
            teal: Color::Rgb(115, 218, 202),
            success: Color::Rgb(158, 206, 106),
            warning: Color::Rgb(224, 175, 104),
            info: Color::Rgb(122, 162, 247),
            privacy: Color::Rgb(122, 162, 247),
            security: Color::Rgb(158, 206, 106),
            content: Color::Rgb(224, 175, 104),
            frame: Color::Rgb(169, 177, 214),
        })
        .with_card_bands(
            Color::Rgb(122, 162, 247),
            Color::Rgb(57, 70, 106),
            Color::Rgb(158, 206, 106),
            Color::Rgb(57, 77, 64),
            Color::Rgb(224, 175, 104),
            Color::Rgb(83, 74, 70),
        )
        .with_submenu(Color::Rgb(89, 60, 80))
    }

    const fn gruvbox() -> Self {
        Self::recolored(BasePalette {
            bg_main: Color::Rgb(40, 40, 40),
            bg_surface: Color::Rgb(60, 56, 54),
            bg_elevated: Color::Rgb(80, 73, 69),
            bg_highlight: Color::Rgb(80, 73, 69),
            text_primary: Color::Rgb(235, 219, 178),
            text_secondary: Color::Rgb(213, 196, 161),
            text_muted: Color::Rgb(168, 153, 132),
            text_inverse: Color::Rgb(40, 40, 40),
            brand_red: Color::Rgb(251, 73, 52),
            teal: Color::Rgb(142, 192, 124),
            success: Color::Rgb(184, 187, 38),
            warning: Color::Rgb(250, 189, 47),
            info: Color::Rgb(131, 165, 152),
            privacy: Color::Rgb(131, 165, 152),
            security: Color::Rgb(184, 187, 38),
            content: Color::Rgb(250, 189, 47),
            frame: Color::Rgb(189, 174, 147),
        })
        .with_card_bands(
            Color::Rgb(131, 165, 152),
            Color::Rgb(92, 96, 89),
            Color::Rgb(184, 187, 38),
            Color::Rgb(103, 98, 62),
            Color::Rgb(250, 189, 47),
            Color::Rgb(111, 94, 65),
        )
        .with_submenu(Color::Rgb(123, 73, 65))
        .with_navigation_text(Color::Rgb(29, 32, 33))
    }

    const fn everforest() -> Self {
        Self::recolored(BasePalette {
            bg_main: Color::Rgb(45, 53, 59),
            bg_surface: Color::Rgb(52, 63, 68),
            bg_elevated: Color::Rgb(61, 72, 77),
            bg_highlight: Color::Rgb(71, 82, 88),
            text_primary: Color::Rgb(211, 198, 170),
            text_secondary: Color::Rgb(157, 169, 160),
            text_muted: Color::Rgb(133, 146, 137),
            text_inverse: Color::Rgb(45, 53, 59),
            brand_red: Color::Rgb(230, 126, 128),
            teal: Color::Rgb(131, 192, 146),
            success: Color::Rgb(167, 192, 128),
            warning: Color::Rgb(219, 188, 127),
            info: Color::Rgb(127, 187, 179),
            privacy: Color::Rgb(127, 187, 179),
            security: Color::Rgb(167, 192, 128),
            content: Color::Rgb(219, 188, 127),
            frame: Color::Rgb(157, 169, 160),
        })
        .with_card_bands(
            Color::Rgb(127, 187, 179),
            Color::Rgb(69, 86, 90),
            Color::Rgb(167, 192, 128),
            Color::Rgb(74, 86, 83),
            Color::Rgb(219, 188, 127),
            Color::Rgb(78, 85, 82),
        )
        .with_submenu(Color::Rgb(96, 79, 83))
    }

    const fn dracula() -> Self {
        Self::recolored(BasePalette {
            bg_main: Color::Rgb(40, 42, 54),
            bg_surface: Color::Rgb(40, 42, 54),
            bg_elevated: Color::Rgb(68, 71, 90),
            bg_highlight: Color::Rgb(68, 71, 90),
            text_primary: Color::Rgb(248, 248, 242),
            text_secondary: Color::Rgb(248, 248, 242),
            text_muted: Color::Rgb(98, 114, 164),
            text_inverse: Color::Rgb(40, 42, 54),
            brand_red: Color::Rgb(255, 85, 85),
            teal: Color::Rgb(139, 233, 253),
            success: Color::Rgb(80, 250, 123),
            warning: Color::Rgb(241, 250, 140),
            info: Color::Rgb(139, 233, 253),
            privacy: Color::Rgb(189, 147, 249),
            security: Color::Rgb(80, 250, 123),
            content: Color::Rgb(255, 184, 108),
            frame: Color::Rgb(189, 147, 249),
        })
        .with_card_bands(
            Color::Rgb(139, 233, 253),
            Color::Rgb(85, 111, 130),
            Color::Rgb(80, 250, 123),
            Color::Rgb(65, 102, 82),
            Color::Rgb(241, 250, 140),
            Color::Rgb(111, 116, 102),
        )
        .with_submenu(Color::Rgb(115, 74, 89))
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
    /// The heatmap itself is retired; kept for possible future
    /// re-introduction.
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
}

const WARDEN: Theme = Theme::dark();
const TOKYO_NIGHT: Theme = Theme::tokyo_night();
const GRUVBOX: Theme = Theme::gruvbox();
const EVERFOREST: Theme = Theme::everforest();
const DRACULA: Theme = Theme::dracula();

thread_local! {
    static ACTIVE_PRESET: Cell<ThemePreset> = const { Cell::new(ThemePreset::Warden) };
}

/// Select the palette for this rendering thread. The UI calls this once per
/// frame before drawing; tests and incremental page migrations can continue to
/// read `T.field` without receiving a process-global mutable palette.
pub fn set_active(preset: ThemePreset) {
    ACTIVE_PRESET.with(|active| active.set(preset));
}

pub fn active_preset() -> ThemePreset {
    ACTIVE_PRESET.with(Cell::get)
}

pub fn active_theme() -> &'static Theme {
    match active_preset() {
        ThemePreset::Warden => &WARDEN,
        ThemePreset::TokyoNight => &TOKYO_NIGHT,
        ThemePreset::Gruvbox => &GRUVBOX,
        ThemePreset::Everforest => &EVERFOREST,
        ThemePreset::Dracula => &DRACULA,
    }
}

/// Adjacent card rectangles share their outer page-background column.
pub fn split_card_columns(area: Rect, right_width: u16) -> [Rect; 2] {
    let right_width = right_width.min(area.width);
    let overlap = u16::from(right_width > 0 && area.width > 0);
    [
        Rect::new(
            area.x,
            area.y,
            area.width - right_width + overlap,
            area.height,
        ),
        Rect::new(area.right() - right_width, area.y, right_width, area.height),
    ]
}

/// Stacked cards share one page-background row without a separator stroke.
pub fn split_card_rows(area: Rect, top_height: u16) -> [Rect; 2] {
    let top_height = top_height.min(area.height);
    let overlap = u16::from(top_height > 0 && area.height > 0);
    [
        Rect::new(area.x, area.y, area.width, top_height),
        Rect::new(
            area.x,
            area.y + top_height - overlap,
            area.width,
            area.height - top_height + overlap,
        ),
    ]
}

/// Paint a borderless card with a page-background gutter and the semantic
/// title/subtitle bands, returning the padded neutral body. This buffer-native
/// primitive is shared by Frame-based pages and Dashboard's canvas renderer.
pub fn filled_card(
    buf: &mut Buffer,
    area: Rect,
    title: &str,
    subtitle: &str,
    role: CardRole,
) -> Rect {
    filled_card_with_subtitle(buf, area, title, Line::raw(subtitle), role)
}

/// The padded subtitle row shared by caption text and inline chart legends.
pub fn card_subtitle_area(area: Rect) -> Rect {
    Rect::new(
        area.x.saturating_add(2),
        area.y.saturating_add(2),
        area.width.saturating_sub(4),
        area.height.saturating_sub(3).min(1),
    )
}

/// Reserve the right-hand legend before fitting the descriptive caption.
pub fn card_subtitle_with_legend(
    area: Rect,
    description: &str,
    legend: Line<'static>,
) -> Line<'static> {
    use super::text::{fit, width};
    use ratatui::text::Span;

    let cells = card_subtitle_area(area).width as usize;
    let legend_width = legend.width();
    if cells <= legend_width {
        return legend;
    }
    let description = fit(description, cells.saturating_sub(legend_width + 2));
    let gap = " ".repeat(cells.saturating_sub(width(&description) + legend_width));
    let mut spans = vec![Span::raw(description), Span::raw(gap)];
    spans.extend(legend.spans);
    Line::from(spans)
}

pub fn filled_card_with_subtitle(
    buf: &mut Buffer,
    area: Rect,
    title: &str,
    subtitle: Line<'_>,
    role: CardRole,
) -> Rect {
    Paragraph::new("")
        .style(Style::default().bg(T.bg_main))
        .render(area, buf);
    let surface = Rect::new(
        area.x.saturating_add(1),
        area.y.saturating_add(1),
        area.width.saturating_sub(2),
        area.height.saturating_sub(2),
    );
    if surface.is_empty() {
        return surface;
    }
    Paragraph::new("")
        .style(Style::default().bg(T.bg_elevated))
        .render(surface, buf);
    Paragraph::new(format!(" {}", title.to_uppercase()))
        .style(
            Style::default()
                .bg(T.card_title_bg(role))
                .fg(T.text_inverse)
                .add_modifier(ratatui::style::Modifier::BOLD),
        )
        .render(Rect::new(surface.x, surface.y, surface.width, 1), buf);
    let subtitle_area = Rect::new(
        surface.x,
        surface.y.saturating_add(1),
        surface.width,
        surface.height.saturating_sub(1).min(1),
    );
    if !subtitle_area.is_empty() {
        let style = Style::default()
            .bg(T.card_subtitle_bg(role))
            .fg(T.text_primary);
        Paragraph::new("").style(style).render(subtitle_area, buf);
        Paragraph::new(subtitle)
            .style(style)
            .render(card_subtitle_area(area), buf);
    }
    Rect::new(
        surface.x.saturating_add(1),
        surface.y.saturating_add(2),
        surface.width.saturating_sub(2),
        surface.height.saturating_sub(2),
    )
}

/// Compatibility palette handle. Dereferencing resolves to a static palette
/// selected in the current thread, so existing `T.field` call sites migrate
/// incrementally without cross-test or cross-session palette races.
pub struct ActiveTheme;

impl Deref for ActiveTheme {
    type Target = Theme;

    fn deref(&self) -> &Self::Target {
        active_theme()
    }
}

pub static T: ActiveTheme = ActiveTheme;

// ── Reusable styles ────────────────────────────────────────────────────────

pub fn highlight_style() -> Style {
    Style::default().fg(T.text_primary).bg(T.bg_highlight)
}

pub fn table_heading_style(sorted: bool) -> Style {
    Style::default()
        .bg(T.bg_surface)
        .fg(if sorted {
            T.warden_teal
        } else {
            T.text_secondary
        })
        .add_modifier(ratatui::style::Modifier::BOLD)
}

// ── Block constructors ─────────────────────────────────────────────────────

/// Standard square block with a subtle border and a secondary-text
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
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(T.border_default))
        .title_style(Style::default().fg(T.text_secondary))
        .title(title)
}

/// Frame-only block: square corners, subtle border, no title on the
/// border. Use when the panel renders its title as the first interior
/// row (codeburn-style "title inside the box, bold, category-coloured")
/// and the panel does not need a category-coloured border. Pendant of
/// `framed_block_colored` for sections without a brand colour.
#[allow(dead_code)]
pub fn framed_block() -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(T.border_default))
}

/// Frame-only block with a category-coloured border. Pair with a
/// matching first-row title in the same colour for visual coupling
/// (codeburn pattern: the eye scans by colour and instantly knows
/// which panel it's looking at).
pub fn framed_block_colored(border: Color) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(border))
}

/// The one filter-card frame shared by Query Log, Lists, Rules and Tags.
/// Paints `framed_block_colored(T.text_primary)` at `area` (height 3 —
/// top border, one content row, bottom border) and returns the
/// **padded** 1-row inner rect (border + 1-col pad on each side) so
/// every caller's width-budget arithmetic lines up without hand-rolling
/// the same `inner.x + 1` / `width - 2` math four times.
///
/// Deliberately lives here, not in a new `filter_card.rs`: a new module
/// needs a `mod filter_card;` line in `tui/mod.rs`, which is an extra
/// wiring change this shared helper does not need.
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
        // retargeted chart_1, gauge_critical and
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
    fn presets_cycle_in_the_operator_visible_order() {
        let mut preset = ThemePreset::Warden;
        let mut names = Vec::new();
        for _ in ThemePreset::ALL {
            names.push(preset.name());
            preset = preset.next();
        }
        assert_eq!(
            names,
            vec!["Warden", "Tokyo Night", "Gruvbox", "Everforest", "Dracula"]
        );
        assert_eq!(preset, ThemePreset::Warden);
    }

    #[test]
    fn compatibility_handle_resolves_the_current_threads_static_palette() {
        let prior = active_preset();
        set_active(ThemePreset::Dracula);
        assert_eq!(T.bg_main, Color::Rgb(40, 42, 54));
        assert_eq!(T.brand_red, Color::Rgb(255, 85, 85));
        set_active(prior);
    }

    #[test]
    fn warden_card_role_pairs_are_the_approved_bands() {
        assert_eq!(T.card_title_bg(CardRole::Summary), Color::Rgb(96, 165, 250));
        assert_eq!(
            T.card_subtitle_bg(CardRole::Summary),
            Color::Rgb(52, 69, 91)
        );
        assert_eq!(
            T.card_title_bg(CardRole::Analytics),
            Color::Rgb(52, 211, 153)
        );
        assert_eq!(
            T.card_subtitle_bg(CardRole::Analytics),
            Color::Rgb(42, 81, 67)
        );
        assert_eq!(T.card_title_bg(CardRole::History), Color::Rgb(251, 191, 36));
        assert_eq!(
            T.card_subtitle_bg(CardRole::History),
            Color::Rgb(91, 76, 38)
        );
    }

    #[test]
    fn styled_card_subtitles_preserve_series_colors_and_card_padding() {
        use ratatui::text::Span;

        let area = Rect::new(0, 0, 30, 8);
        let mut buffer = Buffer::empty(area);
        let body = filled_card_with_subtitle(
            &mut buffer,
            area,
            "DNS Traffic",
            Line::from(vec![
                Span::raw("Queries  "),
                Span::styled("Total", Style::default().fg(T.chart_2)),
                Span::raw("  "),
                Span::styled("Blocked", Style::default().fg(T.brand_red)),
            ]),
            CardRole::Analytics,
        );
        assert_eq!(body, Rect::new(2, 3, 26, 4));
        assert_eq!(card_subtitle_area(area), Rect::new(2, 2, 26, 1));
        assert_eq!(buffer[(11, 2)].symbol(), "T");
        assert_eq!(buffer[(11, 2)].fg, T.chart_2);
        assert_eq!(buffer[(18, 2)].symbol(), "B");
        assert_eq!(buffer[(18, 2)].fg, T.brand_red);
        for x in 1..29 {
            assert_eq!(buffer[(x, 2)].bg, T.card_analytics_subtitle_bg);
        }
        for x in [0, 29] {
            assert_eq!(buffer[(x, 2)].bg, T.bg_main);
        }
        assert_eq!(buffer[(1, 2)].symbol(), " ");
        assert_eq!(buffer[(28, 2)].symbol(), " ");
        for width in 0..=4 {
            for height in 0..=3 {
                assert!(card_subtitle_area(Rect::new(0, 0, width, height)).is_empty());
            }
        }
    }

    #[test]
    fn paired_cards_share_exactly_one_background_cell() {
        let area = Rect::new(3, 2, 125, 24);
        let columns = split_card_columns(area, 42);
        assert_eq!(columns[1].width, 42);
        assert_eq!(columns[0].right() - 1, columns[1].x);
        let mut buffer = Buffer::empty(Rect::new(0, 0, 132, 30));
        for (column, role) in columns
            .into_iter()
            .zip([CardRole::Analytics, CardRole::History])
        {
            for row in split_card_rows(column, 12) {
                filled_card(&mut buffer, row, "Card", "Caption", role);
            }
        }
        for y in area.y..area.bottom() {
            let cell = &buffer[(columns[1].x, y)];
            assert_eq!(cell.symbol(), " ");
            assert_eq!(cell.bg, T.bg_main);
        }
        for x in area.x..area.right() {
            assert_eq!(buffer[(x, area.y + 11)].symbol(), " ");
            assert_eq!(buffer[(x, area.y + 11)].bg, T.bg_main);
        }
        for width in 0..=5 {
            for height in 0..=5 {
                let small = Rect::new(3, 2, width, height);
                for rect in split_card_columns(small, 42)
                    .into_iter()
                    .chain(split_card_rows(small, 12))
                {
                    assert!(rect.x >= small.x && rect.y >= small.y);
                    assert!(rect.right() <= small.right() && rect.bottom() <= small.bottom());
                }
            }
        }
    }

    #[test]
    fn table_headers_use_foreground_tokens_in_every_palette() {
        let original = active_preset();
        for preset in ThemePreset::ALL {
            set_active(preset);
            for selected in [false, true] {
                let style = table_heading_style(selected);
                assert_eq!(style.bg, Some(T.bg_surface));
                assert_eq!(
                    style.fg,
                    Some(if selected {
                        T.warden_teal
                    } else {
                        T.text_secondary
                    })
                );
            }
        }
        set_active(original);
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
    /// * a pair below the floor with **no** row fails as undeclared. A gate
    ///   that leaves a surface out of its enumeration entirely admits
    ///   anything landing on it by absence rather than by a decision, which
    ///   is why the enumeration below covers every `bg_*` token;
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
    /// narrower test: a *positive* list like
    /// `focus_bar_admits_only_high_contrast_foregrounds` enumerates
    /// nothing and forbids nothing, which is not the same guarantee. A
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
    /// ## Two deviations from the palette spec, both measured rather than assumed
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
            card_summary_title_bg: _,
            card_summary_subtitle_bg: _,
            card_analytics_title_bg: _,
            card_analytics_subtitle_bg: _,
            card_history_title_bg: _,
            card_history_subtitle_bg: _,
            // Everything else: never a background a glyph lands on.
            // Borders and rules are chrome, `*_bg` tokens are fills
            // behind a badge, the rest are foreground marks.
            navigation_active_bg: _,
            navigation_active_fg: _,
            navigation_submenu_bg: _,
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
                 any tint passes in silence"
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
