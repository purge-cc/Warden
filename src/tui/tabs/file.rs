//! File tab — the master config file as a *document*: read-only,
//! syntax-coloured TOML with an on-demand `/` section jump.
//!
//! §4.67-b MN3 split this out of `tabs/settings.rs`, which had been
//! rendering **either** the Tracking form **or** this viewer from one
//! 854-line module. The two are different jobs and the split says so:
//!
//! - **Settings** administers the configuration — tracking knobs, backup,
//!   restore, and the auto-backup status those verbs produce.
//! - **File** shows the bytes on disk. It never writes, and it holds no
//!   knob.
//!
//! The `/` section-jump popup lives here rather than on Settings because
//! it jumps to an offset *within this text*: it is navigation inside the
//! document, not a setting.
//!
//! ```text
//! FILE
//!   [server]
//!   listen = "0.0.0.0:53"
//!   ...
//!   [/] jump to section
//! ```

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use crate::tui::app::App;
use crate::tui::modal_form::{self, ChoiceRow, NoticeSpec, ProseRow, ValueKind};
use crate::tui::theme::T;
use crate::tui::ui::render_section_chrome;

// tui-wave1/settings-sidebar: frozen strings for the `/` section-jump
// popup that replaced the permanent left "Sections" sidebar. Pinned by
// `tests/frozen_strings_tui_file_viewer.rs`.
//
// §4.67-b MN3: carried here verbatim with the popup they belong to. The
// strings did NOT change — only the module that owns them — so the
// frozen-string test moved its `include_str!` target rather than its
// expectations.
pub const SECTION_JUMP_TITLE: &str = " Jump to section ";
pub const SECTION_JUMP_HINT: &str = "Enter: jump · Esc: cancel";

/// Ecosystem modal width (§4.61 Archetype C). The popup used to be 50,
/// which is precisely the "looks wrong next to twelve migrated siblings"
/// this sweep exists to fix.
const SECTION_JUMP_W: u16 = 64;

/// The filter row's prompt. `prose_row` prepends a 2-cell indent, so the
/// caret starts `2 + prompt` columns in — ASCII, so bytes and columns
/// agree.
const FILTER_PROMPT: &str = "/ ";
const FILTER_COL: usize = 2 + FILTER_PROMPT.len();

/// Shown in place of the document when nothing could be read from disk.
pub const NO_CONFIG_LOADED: &str = "  (no config loaded)";

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    // §4.67-b MN3: the card is titled after its LEAF, which is what every
    // other tab does (Devices → "Devices", Lists → "Lists", …). The module
    // this was split from was the single exception — it titled its card
    // "Configuration" while its leaf said "Settings" — and that outlier is
    // fixed in the same commit rather than inherited.
    let content = render_section_chrome(f, area, "File", T.text_secondary);
    render_document(f, content, app);

    if let Some(filter) = app.file.section_jump.as_ref() {
        render_section_jump_popup(f, area, app, filter);
    }
}

/// The document body: syntax-coloured TOML from `scroll_offset` down, or
/// the empty-state line when nothing was read.
fn render_document(f: &mut Frame, content: Rect, app: &App) {
    if app.file.config_text.is_empty() {
        f.render_widget(
            Paragraph::new(Span::styled(
                NO_CONFIG_LOADED,
                Style::default().fg(T.text_muted),
            )),
            content,
        );
        return;
    }

    // Clamp the scroll offset to the current line count first: the `e`-key
    // $EDITOR round-trip can reload a SHORTER config without resetting
    // `scroll_offset`, and a stale offset past the new length makes
    // `.skip()` consume every line → a blank viewer that reads as "no
    // config loaded". (set-01)
    let line_count = app.file.config_text.lines().count();
    let offset = (app.file.scroll_offset as usize).min(line_count.saturating_sub(1));
    let lines: Vec<Line> = app
        .file
        .config_text
        .lines()
        .skip(offset)
        .map(colorize_toml_line)
        .collect();

    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), content);
}

/// tui-wave1/settings-sidebar: the `/` section-jump popup. Lists the
/// TOML section names, filtered by substring (case-insensitive) as the
/// operator types; the first match is highlighted — that is the row
/// `Enter` jumps to (see [`filter_and_jump_target`]).
///
/// §4.63 S2b migrated it to **Archetype C**. `area` is the tab content
/// rect, so **D18** holds: the popup anchors over the tab, not the frame.
fn render_section_jump_popup(f: &mut Frame, area: Rect, app: &App, filter: &str) {
    let (filtered, _) = filter_and_jump_target(&app.file.config_text, &app.file.sections, filter);
    let spec = section_jump_notice(filter, &filtered);
    let render = modal_form::render_modal(f, area, SECTION_JUMP_W, |w| {
        (modal_form::notice_body(&spec, w), ())
    });

    // The filter is field-region row 0, so the caret target is
    // unconditional; `place_cursor` no-ops if that row is ever scrolled
    // out of view. This is a real terminal cursor — the pre-migration
    // popup drew none, so the operator could not see their own insertion
    // point.
    let caret = u16::try_from(FILTER_COL + filter.chars().count()).unwrap_or(u16::MAX);
    render.place_cursor(f, 0, caret);
}

/// The popup as one Archetype-C spec.
///
/// The matches are [`ChoiceRow`]s rather than prose for two reasons: the
/// first match wears the ecosystem focus bar, which is exactly what
/// "`Enter` jumps here" needs to say; and `choices` is what makes
/// `ScrollBody::scrollable` true, so a match list longer than the field
/// region gets a scrollbar instead of being cut in silence.
///
/// Row count depends only on the spec, never on the width: `render_modal`
/// builds twice, and a count that differed between the passes would
/// mis-size the frame.
fn section_jump_notice(filter: &str, filtered: &[String]) -> NoticeSpec {
    let mut prose = vec![ProseRow::emphasis(
        format!("{FILTER_PROMPT}{filter}"),
        ValueKind::Editable,
    )];
    if filtered.is_empty() {
        prose.push(ProseRow::plain(String::new()));
        prose.push(ProseRow::plain("(no match)"));
    }

    NoticeSpec {
        // The frozen string carries the border-title padding it needed as
        // a `Block` title; the title band supplies its own lead.
        title: SECTION_JUMP_TITLE.trim().to_string(),
        desc: "filter as you type \u{2014} Enter jumps to the first match".to_string(),
        prose,
        choices: filtered
            .iter()
            .enumerate()
            .map(|(i, s)| ChoiceRow {
                label: s.clone(),
                detail: None,
                // A section name is an identifier, not a decision.
                kind: ValueKind::Identity,
                focused: i == 0,
                note: None,
            })
            .collect(),
        error: None,
        hint: String::new(),
        hint_rows: None,
        // The frozen hint IS the whole key contract for this surface, so
        // it rides the key legend. An action row would repeat it verbatim
        // and cost a row the match list wants.
        keys: SECTION_JUMP_HINT.to_string(),
        actions: Vec::new(),
    }
}

/// Pure filter + jump-target resolver for the section-jump popup. Filters
/// `sections` by case-insensitive substring match on `filter` (preserving
/// original order), and resolves the `scroll_offset` `Enter` should jump
/// to — the first filtered match, or `None` when nothing matches (Enter is
/// then a no-op in the caller).
pub fn filter_and_jump_target(
    config_text: &str,
    sections: &[String],
    filter: &str,
) -> (Vec<String>, Option<u16>) {
    let needle = filter.to_lowercase();
    let filtered: Vec<String> = sections
        .iter()
        .filter(|s| s.to_lowercase().contains(&needle))
        .cloned()
        .collect();
    let target = filtered.first().map(|s| section_offset(config_text, s));
    (filtered, target)
}

/// Simple TOML syntax coloring for a single line.
fn colorize_toml_line(line: &str) -> Line<'static> {
    let trimmed = line.trim();

    // Section headers: [server], [[clients]]
    if trimmed.starts_with('[') {
        return Line::from(Span::styled(
            line.to_string(),
            Style::default()
                .fg(T.brand_red)
                .add_modifier(Modifier::BOLD),
        ));
    }

    // Comments
    if trimmed.starts_with('#') {
        return Line::from(Span::styled(
            line.to_string(),
            Style::default().fg(T.text_muted),
        ));
    }

    // Key = value lines
    if let Some(eq_pos) = trimmed.find(" = ") {
        let indent_len = line.len() - line.trim_start().len();
        let indent = &line[..indent_len];
        let key = &trimmed[..eq_pos];
        let val = &trimmed[eq_pos + 3..];

        let val_color = if val.starts_with('"') || val.starts_with('\'') {
            T.success // strings in green
        } else if val == "true" || val == "false" {
            T.scope_services // booleans in purple
        } else if val.parse::<f64>().is_ok() {
            T.warning // numbers in amber
        } else {
            T.text_primary
        };

        return Line::from(vec![
            Span::raw(indent.to_string()),
            Span::styled(key.to_string(), Style::default().fg(T.text_primary)),
            Span::styled(" = ".to_string(), Style::default().fg(T.text_secondary)),
            Span::styled(val.to_string(), Style::default().fg(val_color)),
        ]);
    }

    // Fallback
    Line::from(Span::raw(line.to_string()))
}

/// Load config sections and full text from a TOML file.
pub fn load_config(path: &std::path::Path) -> (Vec<String>, String) {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => return (vec![], format!("error reading config: {e}")),
    };

    let mut sections = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && !trimmed.starts_with("[[") {
            let name = trimmed
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_string();
            sections.push(name);
        }
    }

    (sections, text)
}

/// Get the line offset for a given section name within the config text.
///
/// Saturates at `u16::MAX` rather than truncating: `scroll_offset` is a
/// `u16` (ratatui's own type), and a bare `as` on a config past 65 535 lines
/// would wrap the jump to a line near the top — the operator would press
/// Enter on a section and land somewhere arbitrary, with nothing to
/// indicate why. Saturating lands at the end instead, which is wrong in a
/// way the operator can see.
pub fn section_offset(config_text: &str, section: &str) -> u16 {
    let target = format!("[{section}]");
    for (i, line) in config_text.lines().enumerate() {
        if line.trim() == target {
            return u16::try_from(i).unwrap_or(u16::MAX);
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_is_case_insensitive_and_preserves_order() {
        let sections = vec!["server".into(), "Tracking".into(), "upstream".into()];
        let (filtered, _) = filter_and_jump_target("", &sections, "TRACK");
        assert_eq!(filtered, vec!["Tracking".to_string()]);
    }

    #[test]
    fn jump_target_is_none_when_nothing_matches() {
        let sections = vec!["server".into()];
        let (filtered, target) = filter_and_jump_target("[server]\n", &sections, "zzz");
        assert!(filtered.is_empty());
        assert!(target.is_none(), "Enter must be a no-op with no match");
    }

    #[test]
    fn section_offset_finds_the_header_line() {
        let text = "[a]\nx = 1\n[b]\ny = 2\n";
        assert_eq!(section_offset(text, "b"), 2);
    }

    #[test]
    fn section_offset_saturates_instead_of_wrapping_on_a_huge_config() {
        // `scroll_offset` is a u16, so a bare `as` past 65 535 lines would
        // wrap the jump to a line near the top: the operator picks a section
        // and lands somewhere arbitrary, with nothing saying why. Saturating
        // lands at the end — wrong in a way that is visible.
        let mut text = String::with_capacity(70_000 * 2);
        for _ in 0..70_000 {
            text.push_str("x\n");
        }
        text.push_str("[deep]\n");
        assert_eq!(
            section_offset(&text, "deep"),
            u16::MAX,
            "must saturate, not wrap"
        );
    }

    #[test]
    fn section_offset_falls_back_to_zero_for_an_unknown_section() {
        assert_eq!(section_offset("[a]\n", "nope"), 0);
    }

    /// The empty document must render the empty-state line, not a blank
    /// pane — a blank pane and "the file is empty" look identical, and
    /// only one of them is true.
    #[test]
    fn empty_config_text_renders_the_empty_state() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut app = App::default();
        app.file.config_text = String::new();
        let mut term = Terminal::new(TestBackend::new(60, 6)).unwrap();
        term.draw(|f| render_document(f, f.area(), &app)).unwrap();
        let dump = term.backend().to_string();
        assert!(
            dump.contains("(no config loaded)"),
            "empty document must say so; got:\n{dump}"
        );
    }

    /// A `scroll_offset` past the end of a reloaded-shorter config must
    /// clamp, not consume every line. Regression guard for set-01: an
    /// unclamped offset makes `.skip()` eat the document and the viewer
    /// reads as "no config loaded" while a config is very much loaded.
    #[test]
    fn a_stale_scroll_offset_clamps_instead_of_blanking_the_document() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut app = App::default();
        app.file.config_text = "[a]\nx = 1\n".to_string();
        app.file.scroll_offset = 9_999;
        let mut term = Terminal::new(TestBackend::new(60, 6)).unwrap();
        term.draw(|f| render_document(f, f.area(), &app)).unwrap();
        let dump = term.backend().to_string();
        assert!(
            dump.contains("x = 1"),
            "a stale offset must clamp to the last line, not blank the view; got:\n{dump}"
        );
    }
    // tui-wave1/settings-sidebar: section-jump popup pure fn.
    const FIXTURE_CONFIG: &str = "[server]\nx = 1\n\n[filter]\ny = 2\n\n[api]\nz = 3\n";

    fn fixture_sections() -> Vec<String> {
        vec![
            "server".to_string(),
            "filter".to_string(),
            "api".to_string(),
        ]
    }

    #[test]
    fn filter_and_jump_target_substring_match() {
        let (filtered, target) = filter_and_jump_target(FIXTURE_CONFIG, &fixture_sections(), "fil");
        assert_eq!(filtered, vec!["filter".to_string()]);
        assert_eq!(target, Some(3), "[filter] starts at line 3");
    }

    #[test]
    fn filter_and_jump_target_is_case_insensitive() {
        let (filtered, target) = filter_and_jump_target(FIXTURE_CONFIG, &fixture_sections(), "API");
        assert_eq!(filtered, vec!["api".to_string()]);
        assert_eq!(target, Some(6), "[api] starts at line 6");
    }

    #[test]
    fn filter_and_jump_target_empty_filter_matches_all_in_order() {
        let (filtered, target) = filter_and_jump_target(FIXTURE_CONFIG, &fixture_sections(), "");
        assert_eq!(filtered, fixture_sections());
        assert_eq!(
            target,
            Some(0),
            "first section (server) wins on empty filter"
        );
    }

    #[test]
    fn filter_and_jump_target_no_match_returns_empty_and_none() {
        let (filtered, target) = filter_and_jump_target(FIXTURE_CONFIG, &fixture_sections(), "zzz");
        assert!(filtered.is_empty());
        assert_eq!(target, None);
    }

    // ---- §4.63 S2b — the section-jump popup as Archetype C -------------
    //
    // The anchor a Settings overlay actually receives at the declared
    // 80×24 floor: `ui::layout_chunks` hands the content region
    // 24 − 4 header − 3 menu card − 1 footer = **16** rows (Settings is a
    // singleton section, so its card is 3 rows, not 5), leaving a 14-row
    // modal interior.
    //
    // Rendering against a full 24-row frame would prove nothing:
    // `overlay::centered_rect` CLAMPS, so an oversized popup is silently
    // **cut**, not rejected.
    const FLOOR_W: u16 = 80;
    const FLOOR_H: u16 = 16;

    /// The focus bar `modal_form` paints in front of the focused row.
    /// Asserting on `FOCUS + label` is what makes the needle
    /// discriminating — the bare label also occurs on unfocused rows, and
    /// a filter substring occurs inside every match it selected.
    const FOCUS: &str = "\u{258c} ";

    fn dump_buffer(buf: &ratatui::buffer::Buffer) -> String {
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    fn app_with_sections(sections: Vec<String>) -> App {
        let mut app = App::new();
        app.active_leaf = crate::tui::app::Leaf::File;
        app.file.config_text = sections
            .iter()
            .map(|s| format!("[{s}]\nk = 1\n\n"))
            .collect::<String>();
        app.file.sections = sections;
        app
    }

    fn popup_dump(app: &App, filter: &str) -> String {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut term = Terminal::new(TestBackend::new(FLOOR_W, FLOOR_H)).unwrap();
        term.draw(|f| render_section_jump_popup(f, f.area(), app, filter))
            .unwrap();
        dump_buffer(term.backend().buffer())
    }

    #[test]
    fn floor_section_jump_keeps_the_typed_filter_the_first_match_and_the_legend() {
        let app = app_with_sections(vec![
            "server".to_string(),
            "filtering".to_string(),
            "zz_unique_section".to_string(),
        ]);
        let dump = popup_dump(&app, "zz_u");

        // The prompt lead is what discriminates: `zz_u` on its own also
        // matches the section name it selected, one row below.
        assert!(
            dump.contains("/ zz_u"),
            "the typed filter and its prompt must be on screen:\n{dump}"
        );
        assert!(
            dump.contains(&format!("{FOCUS}zz_unique_section")),
            "the first match must wear the focus bar — that is the row Enter \
             jumps to:\n{dump}"
        );
        assert!(
            dump.contains(SECTION_JUMP_HINT),
            "the key legend is this surface's action row and was cut:\n{dump}"
        );
    }

    /// The clip test. 40 sections asks `render_modal` for a 47-row frame
    /// against a 16-row anchor; `centered_rect` clamps rather than
    /// scrolls, so only `scroll_layout` serving the tail first keeps the
    /// legend on screen.
    #[test]
    fn floor_section_jump_survives_a_list_far_longer_than_the_anchor() {
        let sections: Vec<String> = (0..40).map(|i| format!("sec{i:02}")).collect();
        let app = app_with_sections(sections);
        let dump = popup_dump(&app, "");

        assert!(
            dump.contains(&format!("{FOCUS}sec00")),
            "the jump target must be on screen:\n{dump}"
        );
        assert!(
            dump.contains(SECTION_JUMP_HINT),
            "the key legend was cut by the long list:\n{dump}"
        );
        assert!(
            !dump.contains("sec39"),
            "sanity: a 40-entry list cannot fit a 14-row interior, so this \
             test is not accidentally proving something easier:\n{dump}"
        );
    }

    #[test]
    fn section_jump_says_so_when_nothing_matches() {
        let app = app_with_sections(fixture_sections());
        let dump = popup_dump(&app, "zzz");
        assert!(
            dump.contains("(no match)"),
            "an empty result must say so rather than render a blank card:\n{dump}"
        );
        assert!(
            dump.contains("/ zzz"),
            "the filter that matched nothing must stay visible so the \
             operator can correct it:\n{dump}"
        );
    }

    /// Eyeball it: `cargo test --lib section_jump_visual_dump -- --ignored --nocapture`.
    #[test]
    #[ignore = "visual aid, not an assertion"]
    fn section_jump_visual_dump() {
        let short = app_with_sections(vec![
            "server".to_string(),
            "filtering".to_string(),
            "query_log".to_string(),
            "zz_unique_section".to_string(),
        ]);
        println!(
            "\n=== filtered to one match ===\n{}",
            popup_dump(&short, "zz_u")
        );
        println!("\n=== unfiltered ===\n{}", popup_dump(&short, ""));
        println!("\n=== no match ===\n{}", popup_dump(&short, "zzz"));
        let long = app_with_sections((0..40).map(|i| format!("sec{i:02}")).collect());
        println!(
            "\n=== 40 sections, overflowing ===\n{}",
            popup_dump(&long, "")
        );
    }

    /// D15 / D13, as a test rather than a claim in a commit message.
    /// Needles are split with `concat!` so this assertion cannot match
    /// itself — the house pattern, see `scope_modal`.
    ///
    /// Scoped to *chrome*: the two surviving `T.brand_red` spans in this
    /// file style the TOML section-header syntax highlight and the
    /// Tracking form's focused value. Both are copy, not borders, and
    /// D15 governs borders. With no border built here at all, the popup's
    /// red frame is structurally gone.
    #[test]
    fn section_jump_popup_builds_no_chrome_of_its_own() {
        let src = include_str!("settings.rs");
        for needle in [
            concat!("Borders", "::ALL"),
            concat!("border", "_style("),
            concat!("Color", "::Rgb("),
        ] {
            assert!(
                !src.contains(needle),
                "{needle} in settings.rs — the chrome belongs to modal_form"
            );
        }
    }

    // ---- D18 / §4.62 N1 -------------------------------------------------
    //
    // Header 4 (rows 0..=3) · menu card 3 (rows 4..=6) · content 16
    // (rows 7..=22) · footer 1 (row 23) at the 80×24 floor.
    const CONTENT_ROWS: std::ops::RangeInclusive<usize> = 7..=22;

    /// The popup already anchored on the content rect before the
    /// migration, so unlike the backup/restore overlays this one has no
    /// fail-before. It is pinned anyway: the sweep's whole premise is
    /// that an unpinned property drifts back.
    ///
    /// Diffing the frame with and without the popup, rather than grepping
    /// for a legend needle, is deliberate — a needle that also occurs
    /// inside the modal gives a false green.
    #[test]
    fn section_jump_popup_never_occludes_the_menu_card_or_the_footer_legend() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut app = app_with_sections(fixture_sections());

        let frame = |app: &App| {
            let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
            term.draw(|f| crate::tui::ui::render(f, app)).unwrap();
            dump_buffer(term.backend().buffer())
        };

        let before = frame(&app);
        app.file.section_jump = Some("se".to_string());
        let after = frame(&app);

        let (b, a): (Vec<&str>, Vec<&str>) = (before.lines().collect(), after.lines().collect());
        for (y, (bl, al)) in b.iter().zip(a.iter()).enumerate() {
            if !CONTENT_ROWS.contains(&y) {
                assert_eq!(
                    bl, al,
                    "the section-jump popup repainted row {y}, which is header / \
                     menu card / footer\n--- without ---\n{before}\n--- with ---\n{after}"
                );
            }
        }
        // Control arm: without this the loop above passes vacuously if the
        // popup failed to render at all.
        assert_ne!(
            before, after,
            "the popup changed nothing — it did not render, so the assertion \
             above proved nothing"
        );
    }
}
