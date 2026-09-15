//! Scroll state and rendering for the read-only half of master/detail tabs.
//!
//! The cards deliberately keep their existing styled `Line` vocabulary.  This
//! module owns only the viewport: it measures the wrapped paragraph, clamps a
//! per-leaf offset, and lets a narrow terminal replace the master with the
//! selected detail card.

use crossterm::event::KeyCode;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::widgets::Paragraph;
use ratatui::Frame;
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

use super::app::{App, Leaf};
use super::mouse::{self, MouseAction};

#[derive(Debug, Clone)]
pub struct Information {
    pub title: String,
    pub subtitle: String,
    pub lines: Vec<Line<'static>>,
    pub scroll: usize,
}

impl Information {
    pub fn new(
        title: impl Into<String>,
        subtitle: impl Into<String>,
        lines: Vec<Line<'static>>,
    ) -> Self {
        Self {
            title: title.into(),
            subtitle: subtitle.into(),
            lines,
            scroll: 0,
        }
    }
}

/// Labels, Settings and Nodes share one responsive list/detail composition.
pub fn columns(area: Rect) -> Option<[Rect; 2]> {
    if area.width < 108 {
        return None;
    }
    let left = (u32::from(area.width) * 42 / 100) as u16;
    Some([
        Rect::new(area.x, area.y, left, area.height),
        Rect::new(
            area.x + left.saturating_sub(1),
            area.y,
            area.width - left + 1,
            area.height,
        ),
    ])
}

pub fn handle_information(app: &mut App, code: KeyCode) -> bool {
    let Some(info) = app.information.as_mut() else {
        return false;
    };
    match code {
        KeyCode::Esc | KeyCode::Enter => app.information = None,
        KeyCode::Down => info.scroll = info.scroll.saturating_add(1),
        KeyCode::Up => info.scroll = info.scroll.saturating_sub(1),
        KeyCode::PageDown => info.scroll = info.scroll.saturating_add(8),
        KeyCode::PageUp => info.scroll = info.scroll.saturating_sub(8),
        KeyCode::Home => info.scroll = 0,
        KeyCode::End => info.scroll = usize::MAX,
        _ => {}
    }
    true
}

pub fn render_information(f: &mut Frame, area: Rect, app: &mut App) {
    use super::modal_form::{self, ScrollBody};
    let Some(info) = app.information.as_mut() else {
        return;
    };
    let rendered = modal_form::render_modal(f, area, 76, |width| {
        let fields = wrap_styled_lines(info.lines.clone(), width as usize);
        let (_, view, _) =
            modal_form::scroll_layout(area.height.saturating_sub(2) as usize, 3, fields.len(), 2);
        let offset = info.scroll.min(fields.len().saturating_sub(view));
        (
            ScrollBody {
                head: vec![
                    modal_form::title_band(&info.title, width),
                    modal_form::desc_band(&info.subtitle, width),
                    Line::default(),
                ],
                fields,
                tail: vec![
                    Line::default(),
                    modal_form::nav_keys_line("↑↓ Scroll · Enter / Esc Close"),
                ],
                focus_row: view.checked_sub(1).map(|last| offset + last),
                scrollable: true,
                action_hits: Vec::new(),
                field_hits: Vec::new(),
            },
            (),
        )
    });
    info.scroll = rendered.view.offset;
    if rendered.inner.height > 0 {
        mouse::register_overlay(
            Rect::new(
                rendered.inner.x,
                rendered.inner.bottom() - 1,
                rendered.inner.width,
                1,
            ),
            KeyCode::Enter.into(),
        );
    }
}

const PAGE_ROWS: usize = 8;

/// Remember the selected entity before a card is painted.  A new entity is a
/// new document, so it always starts at its first line.
pub fn prepare(app: &App, leaf: Leaf, selection_key: &str) {
    app.mouse.prepare_detail(leaf, selection_key);
}

/// True when this leaf's detail card owns directional scrolling.
pub fn focused(app: &App, leaf: Leaf) -> bool {
    app.mouse.detail_focused(leaf)
}

/// Give the selected detail card focus.  Returns false when the leaf has not
/// rendered a detail card in the current frame.
pub fn focus(app: &App, leaf: Leaf) -> bool {
    app.mouse.focus_detail(leaf)
}

/// Route a wheel event to the detail body.  Unlike keyboard scrolling, a
/// wheel directly over a detail card also focuses it.
pub fn scroll(app: &App, leaf: Leaf, key: KeyCode) -> bool {
    app.mouse.scroll_detail(leaf, key, true, PAGE_ROWS)
}

/// Render an already-built, styled detail body through its shared viewport.
///
/// Ratatui 0.29 keeps `Paragraph::line_count` behind an unstable feature.
/// Prewrapping here makes the measured vector and painted paragraph exactly
/// the same rows without enabling that feature or estimating from width.
pub fn render(
    f: &mut Frame,
    area: Rect,
    app: &App,
    leaf: Leaf,
    selection_key: &str,
    lines: Vec<Line<'static>>,
) {
    prepare(app, leaf, selection_key);
    let lines = wrap_styled_lines(lines, area.width as usize);
    let total = lines.len();
    let max = total.saturating_sub(area.height as usize);
    let offset = app.mouse.sync_detail(leaf, selection_key, max);
    f.render_widget(
        Paragraph::new(lines).scroll((offset.min(u16::MAX as usize) as u16, 0)),
        area,
    );
    mouse::register(app, area, MouseAction::DetailPanel(leaf));
}

#[derive(Clone)]
struct StyledGrapheme {
    text: String,
    style: Style,
}

/// Hard-wrap a line without splitting graphemes or discarding whitespace.
/// Every wrapped output line retains the source line and span styles.  A hard
/// break is deliberate: it makes a long domain or backend value reachable
/// instead of relying on a word boundary that may not exist.
fn wrap_styled_lines(lines: Vec<Line<'static>>, width: usize) -> Vec<Line<'static>> {
    if width == 0 {
        return Vec::new();
    }

    let mut wrapped = Vec::new();
    for line in lines {
        let style = line.style;
        let alignment = line.alignment;
        let mut graphemes = Vec::new();
        for span in line.spans {
            let span_style = span.style;
            let content = span.content.into_owned();
            for (index, source) in content.split('\n').enumerate() {
                if index > 0 {
                    graphemes.push(StyledGrapheme {
                        text: "\n".to_string(),
                        style: span_style,
                    });
                }
                graphemes.extend(source.graphemes(true).map(|text| StyledGrapheme {
                    text: text.to_string(),
                    style: span_style,
                }));
            }
        }
        wrapped.extend(wrap_one_line(graphemes, width, style, alignment));
    }
    wrapped
}

fn wrap_one_line(
    graphemes: Vec<StyledGrapheme>,
    width: usize,
    style: Style,
    alignment: Option<ratatui::layout::Alignment>,
) -> Vec<Line<'static>> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut used: usize = 0;

    for grapheme in graphemes {
        if grapheme.text == "\n" {
            rows.push(styled_line(std::mem::take(&mut row), style, alignment));
            used = 0;
            continue;
        }
        let cells = UnicodeWidthStr::width(grapheme.text.as_str());
        if !row.is_empty() && used.saturating_add(cells) > width {
            rows.push(styled_line(std::mem::take(&mut row), style, alignment));
            used = 0;
        }
        used = used.saturating_add(cells);
        row.push(grapheme);
    }
    rows.push(styled_line(row, style, alignment));
    rows
}

fn styled_line(
    graphemes: Vec<StyledGrapheme>,
    style: Style,
    alignment: Option<ratatui::layout::Alignment>,
) -> Line<'static> {
    let mut line = Line::from(
        graphemes
            .into_iter()
            .map(|grapheme| ratatui::text::Span::styled(grapheme.text, grapheme.style))
            .collect::<Vec<_>>(),
    )
    .style(style);
    if let Some(alignment) = alignment {
        line = line.alignment(alignment);
    }
    line
}

/// Consume only detail-navigation keys for the active read-only detail card.
/// Edit-opening keys intentionally fall through to the existing leaf handler.
pub fn handle_detail_key(app: &mut App, key: KeyCode) -> bool {
    let leaf = app.active_leaf;

    match key {
        KeyCode::Right => focus(app, leaf),
        KeyCode::Left | KeyCode::Esc if focused(app, leaf) => {
            app.mouse.blur_detail(leaf);
            true
        }
        KeyCode::Up
        | KeyCode::Down
        | KeyCode::PageUp
        | KeyCode::PageDown
        | KeyCode::Home
        | KeyCode::End
            if focused(app, leaf) =>
        {
            app.mouse.scroll_detail(leaf, key, false, PAGE_ROWS)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use ratatui::backend::TestBackend;
    use ratatui::style::{Color, Style};
    use ratatui::Terminal;

    use super::*;

    #[test]
    fn wrapped_body_reaches_its_last_line_and_home_returns_to_start() {
        let mut app = App::new();
        app.active_leaf = Leaf::Profiles;
        let lines = || {
            let mut lines = vec![Line::styled(
                "first detail value",
                Style::default().fg(Color::Blue),
            )];
            lines.extend((0..24).map(|index| {
                Line::styled(
                    format!(
                        "long detail value {index:02}: this must be reachable in an 80 by 24 terminal"
                    ),
                    Style::default().fg(Color::Yellow),
                )
            }));
            lines.push(Line::styled(
                "final reachable value",
                Style::default().fg(Color::Green),
            ));
            lines
        };
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| render(frame, frame.area(), &app, Leaf::Profiles, "kids", lines()))
            .unwrap();
        assert!(focus(&app, Leaf::Profiles));
        assert!(handle_detail_key(&mut app, KeyCode::End));
        assert!(app.mouse.detail_offset(Leaf::Profiles) > 0);
        terminal
            .draw(|frame| render(frame, frame.area(), &app, Leaf::Profiles, "kids", lines()))
            .unwrap();
        let buffer = terminal.backend().buffer();
        let visible = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            visible.contains("final reachable value"),
            "End must render the full final detail value:\n{visible}"
        );
        let end = app.mouse.detail_offset(Leaf::Profiles);
        assert!(handle_detail_key(&mut app, KeyCode::Up));
        assert_eq!(app.mouse.detail_offset(Leaf::Profiles), end - 1);
        assert!(handle_detail_key(&mut app, KeyCode::Home));
        assert_eq!(app.mouse.detail_offset(Leaf::Profiles), 0);
    }

    #[test]
    fn changing_the_selection_resets_the_viewport() {
        let app = App::new();
        prepare(&app, Leaf::Groups, "alpha");
        app.mouse.sync_detail(Leaf::Groups, "alpha", 12);
        assert!(focus(&app, Leaf::Groups));
        assert!(scroll(&app, Leaf::Groups, KeyCode::End));
        assert!(app.mouse.detail_offset(Leaf::Groups) > 0);
        prepare(&app, Leaf::Groups, "beta");
        assert_eq!(app.mouse.detail_offset(Leaf::Groups), 0);
    }
}
