//! Read-only Query Log entry detail. Enter remains reserved for rule actions.

use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::Frame;

use crate::ipc::protocol::QueryLogDto;
use crate::tui::modal_form::{self, Action, ActionKind, ScrollBody};
use crate::tui::text;
use crate::tui::theme::T;

const W: u16 = 68;
const TITLE: &str = "Query detail";
const DESC: &str = "Request, Client & Response";
// A fixed wrap width keeps row counts stable when the scrollbar reserves a cell.
const DETAIL_ROW_WIDTH: usize = 61;

#[derive(Debug, Clone)]
pub(crate) struct QueryLogDetail {
    pub(crate) entry: QueryLogDto,
    pub(crate) scroll: u16,
    /// Rendered viewport and content limit make page keys match the actual
    /// popup instead of an arbitrary fixed number of rows.
    pub(crate) visible_rows: u16,
    pub(crate) max_scroll: u16,
}

impl QueryLogDetail {
    pub(crate) fn open(entry: QueryLogDto) -> Self {
        Self {
            entry,
            scroll: 0,
            visible_rows: 1,
            max_scroll: 0,
        }
    }

    pub(crate) fn scroll_down(&mut self, rows: u16) {
        self.scroll = self.scroll.saturating_add(rows).min(self.max_scroll);
    }

    pub(crate) fn scroll_up(&mut self, rows: u16) {
        self.scroll = self.scroll.saturating_sub(rows);
    }

    fn clamp_scroll(&mut self, content_rows: usize, viewport_rows: u16) {
        self.visible_rows = viewport_rows.max(1);
        self.max_scroll = content_rows
            .saturating_sub(usize::from(self.visible_rows))
            .min(usize::from(u16::MAX)) as u16;
        self.scroll = self.scroll.min(self.max_scroll);
    }
}

/// Materialize every display row before rendering. The wrapper breaks an
/// overlong unbroken domain at grapheme boundaries, unlike whitespace-only
/// wrapping which can leave an audit-critical name clipped forever.
#[cfg(test)]
pub(crate) fn wrapped_lines(entry: &QueryLogDto, width: usize) -> Vec<Line<'static>> {
    detail_values(entry)
        .into_iter()
        .flat_map(|line| wrapped_value_rows(&line, width))
        .collect()
}

#[cfg(test)]
fn detail_values(entry: &QueryLogDto) -> [String; 8] {
    let (request, response) = detail_sections(entry);
    [
        request[0].clone(),
        request[1].clone(),
        request[2].clone(),
        request[3].clone(),
        request[4].clone(),
        response[0].clone(),
        response[1].clone(),
        response[2].clone(),
    ]
}

fn detail_sections(entry: &QueryLogDto) -> ([String; 5], [String; 3]) {
    let client = entry
        .client_name
        .as_deref()
        .unwrap_or("(unmapped / no current name)");
    let cname = entry.cname_chain_via.as_deref().unwrap_or("—");
    (
        [
            format!("Time (UTC): {}", entry.timestamp),
            format!("Client: {client}"),
            format!("Client IP: {}", entry.client_ip),
            format!("Domain: {}", entry.domain),
            format!("Type: {}", entry.query_type),
        ],
        [
            format!("Result: {}", entry.result),
            format!("Response Time: {} µs", entry.response_time_us),
            format!("CNAME Chain: {cname}"),
        ],
    )
}

pub(crate) fn render(f: &mut Frame, anchor: Rect, detail: &mut QueryLogDetail) {
    // Detail rows use a fixed wrap width, so measuring once gives the same
    // row count as the scrollbar pass. This lets page keys follow the real
    // clamped viewport immediately, including on the first frame after resize.
    let (measured, ()) = detail_body(detail, W.saturating_sub(2), 0, 1);
    let requested_h = measured
        .head
        .len()
        .saturating_add(measured.fields.len())
        .saturating_add(measured.tail.len())
        .saturating_add(2);
    let inner_h = requested_h
        .min(usize::from(anchor.height))
        .saturating_sub(2);
    let (_, viewport, _) = modal_form::scroll_layout(
        inner_h,
        measured.head.len(),
        measured.fields.len(),
        measured.tail.len(),
    );
    detail.clamp_scroll(
        measured.fields.len(),
        u16::try_from(viewport).unwrap_or(u16::MAX),
    );

    let scroll = detail.scroll;
    let visible_rows = detail.visible_rows;
    let rendered = modal_form::render_modal(f, anchor, W, |width| {
        detail_body(detail, width, scroll, visible_rows)
    });
    detail.visible_rows = u16::try_from(rendered.view.view_h.max(1)).unwrap_or(u16::MAX);
}

fn detail_body(
    detail: &QueryLogDetail,
    width: u16,
    scroll: u16,
    visible_rows: u16,
) -> (ScrollBody, ()) {
    let mut rows = modal_form::FormRows::new(TITLE, DESC, width);
    let (request, response) = detail_sections(&detail.entry);
    rows.line(section_line("REQUEST", T.card_summary_title_bg, width));
    for line in request
        .into_iter()
        .flat_map(|value| wrapped_value_rows(&value, DETAIL_ROW_WIDTH))
    {
        rows.line(line);
    }
    rows.line(Line::from(""));
    rows.line(section_line("RESPONSE", T.card_analytics_title_bg, width));
    for line in response
        .into_iter()
        .flat_map(|value| wrapped_value_rows(&value, DETAIL_ROW_WIDTH))
    {
        rows.line(line);
    }

    let actions =
        [Action::new("Close", true, ActionKind::Neutral, "")
            .on_key(crossterm::event::KeyCode::Esc)];
    let tail = modal_form::form_tail_with_note(
        &rows,
        modal_form::TailNote {
            rows: 0,
            banded: false,
        },
        None,
        "",
        "",
        &actions,
    );
    let (mut body, _) = rows.finish(tail);
    let last_visible = usize::from(scroll)
        .saturating_add(usize::from(visible_rows))
        .saturating_sub(1)
        .min(body.fields.len().saturating_sub(1));
    body.focus_row = Some(last_visible);
    (body, ())
}

fn section_line(title: &str, background: ratatui::style::Color, width: u16) -> Line<'static> {
    Line::styled(
        text::pad(&format!(" {title}"), usize::from(width)),
        Style::default()
            .fg(T.text_inverse)
            .bg(background)
            .add_modifier(ratatui::style::Modifier::BOLD),
    )
}

fn wrapped_value_rows(row: &str, width: usize) -> Vec<Line<'static>> {
    let (label, value) = row.split_once(": ").unwrap_or(("", row));
    let label_width = 15.min(width.saturating_sub(2) / 2);
    let usable = width.saturating_sub(label_width + 2).max(1);
    text::wrap(value, usable)
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            Line::from(vec![
                Span::styled(
                    format!(
                        "  {}",
                        text::pad(
                            &text::fit(if index == 0 { label } else { "" }, label_width),
                            label_width
                        )
                    ),
                    Style::default().fg(T.text_secondary),
                ),
                Span::styled(value, Style::default().fg(T.text_primary)),
            ])
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(domain: &str) -> QueryLogDto {
        QueryLogDto {
            timestamp: "2026-09-08T10:00:00Z".into(),
            client_ip: "192.0.2.1".into(),
            client_name: None,
            domain: domain.into(),
            query_type: "AAAA".into(),
            result: "ALLOWED".into(),
            response_time_us: 12,
            cname_chain_via: None,
        }
    }

    #[test]
    fn unbroken_domains_wrap_without_losing_any_grapheme() {
        let domain = "averylongunbrokenname.example.test";
        let rows = wrapped_lines(&entry(domain), 12);
        let rendered = rows
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .filter(|span| span.style.fg == Some(T.text_primary))
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect::<String>();
        assert!(rendered.contains(domain));
    }

    #[test]
    fn scroll_is_clamped_to_the_last_visible_detail_row() {
        let mut detail = QueryLogDetail::open(entry("longlonglonglonglonglonglong.example"));
        detail.scroll = u16::MAX;
        let rows = wrapped_lines(&detail.entry, 10);
        detail.clamp_scroll(rows.len(), 3);
        assert_eq!(
            detail.scroll as usize,
            rows.len().saturating_sub(usize::from(detail.visible_rows))
        );
    }

    #[test]
    fn detail_renders_shared_structure_and_keeps_the_record_read_only() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut detail = QueryLogDetail::open(entry(
            "a-very-long-domain-that-needs-more-than-one-detail-row.example.test",
        ));
        detail.entry.client_name = Some("living-room display".into());
        detail.entry.cname_chain_via = Some("blocked-hop.example.test".into());
        let original = detail.entry.clone();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| render(frame, frame.area(), &mut detail))
            .unwrap();
        let buffer = terminal.backend().buffer();
        let mut rendered = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                rendered.push_str(buffer[(x, y)].symbol());
            }
            rendered.push('\n');
        }
        assert!(rendered.contains(&TITLE.to_uppercase()), "title missing");
        for expected in ["REQUEST", "RESPONSE", "Result", "Close"] {
            assert!(
                rendered.contains(expected),
                "missing common modal row: {expected}"
            );
        }
        assert_eq!(
            detail.entry, original,
            "rendering may update only viewport state"
        );
        assert!(detail.visible_rows > 0);
    }

    #[test]
    fn full_record_rows_keep_every_value_across_wrapping() {
        let mut source = entry("δοκιμή.averylongunbrokenname.example.test");
        source.client_name = Some("café display".into());
        source.cname_chain_via = Some("hop.example.test".into());
        let rendered = wrapped_lines(&source, 12)
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .filter(|span| span.style.fg == Some(T.text_primary))
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect::<String>();
        for value in [
            source.timestamp.as_str(),
            source.client_ip.as_str(),
            source.domain.as_str(),
            source.query_type.as_str(),
            source.result.as_str(),
            source.cname_chain_via.as_deref().unwrap(),
            "café",
            "display",
            "12",
        ] {
            assert!(rendered.contains(value), "wrapped detail lost {value}");
        }
    }
}
