//! §4.62 S1 — transient action feedback as an auto-expiring overlay.
//!
//! Before this module the outcome of every action rendered into the
//! footer's left slot, which is also where `tab_hints_for` paints the
//! tab keyboard legend (`[a] add [e] edit [d] delete …`). The two shared
//! one `cols[1]`, so the moment an action reported anything the operator
//! lost the discovery surface for the screen they were working on — and
//! got it back only when some *poll* happened to clear the message,
//! which on six of eleven leaves is never. See
//! `_docs/features/tui_notification_surface_v1.md` §1 (B1, B2).
//!
//! The fix is to move the message, not to shorten it. The toast is an
//! overlay inside the tab-content rect — the same `Clear`-over-a-small-
//! rect mechanism every modal already uses — so it costs **zero layout
//! rows**. A dedicated footer row would have taken a permanent
//! `Constraint::Length(1)` out of a content area that is only 14 rows at
//! the 80×24 floor, and a *conditional* row would reflow the content on
//! every action.
//!
//! N6: nothing here takes focus or reads a key. The toast is drawn from
//! `&StatusLine` and is structurally incapable of gating a keystroke.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Paragraph};
use ratatui::Frame;

use crate::tui::app::{StatusLine, StatusSeverity};
use crate::tui::theme::{framed_block_colored, T};

/// Gap between the toast and the edges of the content rect (N1).
pub const INSET: u16 = 1;

/// Total toast height: a one-line body plus the top and bottom frame
/// rows. Deterministic by design (N5) — a fixed height is what lets the
/// overlay float over a table without ever growing into it. Wrapping is
/// therefore not an option, and the body truncates with `…` instead.
pub const TOAST_HEIGHT: u16 = 3;

/// Columns of tab content that must stay readable beside the toast (N5).
pub const MIN_CONTENT_COLS: u16 = 40;

/// Below this the toast could not show a severity glyph plus a
/// meaningful slice of text, so it is not drawn at all. A missing toast
/// is better than an unreadable one — the message is transient and the
/// legend it no longer displaces is not.
const MIN_TOAST_WIDTH: u16 = 12;

/// Frame (2) + leading `" ✓ "` glyph (3) + trailing pad (1).
const CHROME_COLS: u16 = 6;

/// Severity → (glyph, colour). Carried over verbatim from the footer
/// slot this replaces (ui-01): success and neutral outcomes used to
/// render through the same red `✕` as errors, so a successful mutation
/// read as a failure.
fn severity_style(severity: StatusSeverity) -> (&'static str, ratatui::style::Color) {
    match severity {
        StatusSeverity::Ok => (" \u{2713} ", T.success),
        StatusSeverity::Error => (" \u{2715} ", T.error),
        StatusSeverity::Info => (" \u{2022} ", T.text_secondary),
    }
}

/// Columns the toast would like, given the message length.
pub fn desired_width(text: &str) -> u16 {
    let cols = text.chars().count().min(u16::MAX as usize) as u16;
    cols.saturating_add(CHROME_COLS)
}

/// Truncate `text` to `cols` display columns, marking the cut with `…`
/// (N5 — the toast never wraps, because a wrapping toast has a
/// data-dependent height and could grow over the rows it floats above).
pub fn truncate_to(text: &str, cols: u16) -> String {
    let cols = cols as usize;
    if cols == 0 {
        return String::new();
    }
    if text.chars().count() <= cols {
        return text.to_string();
    }
    let mut out: String = text.chars().take(cols.saturating_sub(1)).collect();
    out.push('\u{2026}');
    out
}

/// The band of rows inside `content` currently painted with the focus
/// bar background.
///
/// Every table leaf highlights its selected row with
/// `theme::highlight_style()` (bg `T.bg_highlight`), and the Lists cards
/// paint the same bar, so reading it back off the rendered buffer finds
/// the operator's cursor for *any* tab. The alternative — recomputing
/// each tab's table origin, header offset and scroll position here —
/// would duplicate eleven separate layouts in a file that does not own
/// any of them, and would silently drift the first time one changed.
///
/// The band is returned full-width because the row highlight is
/// full-width; a partial match still yields the whole row, which is the
/// conservative answer.
pub fn focus_band(buf: &Buffer, content: Rect) -> Option<Rect> {
    let mut top: Option<u16> = None;
    let mut bottom = content.y;
    for y in content.y..content.bottom() {
        let hit = (content.x..content.right())
            .any(|x| buf.cell((x, y)).is_some_and(|c| c.bg == T.bg_highlight));
        if hit {
            top.get_or_insert(y);
            bottom = y;
        }
    }
    top.map(|t| Rect {
        x: content.x,
        y: t,
        width: content.width,
        height: bottom - t + 1,
    })
}

/// Where the toast goes inside `content`, or `None` when there is no
/// room for one.
///
/// N1: top-right, inset one cell, always strictly inside `content` — so
/// it can never touch the footer or the menu card, which are siblings of
/// `content` in the vertical layout, not children.
///
/// N1′: if that would sit on the focused row, it drops to bottom-right
/// instead. Anchoring top-right over a table whose selection sits at the
/// top would hide the operator's own cursor under the success message —
/// B1 relocated one surface over, not fixed.
pub fn toast_rect(content: Rect, desired: u16, focus: Option<Rect>) -> Option<Rect> {
    // Both anchors must fit inside the same rect with their insets, or
    // the N1′ fallback has nowhere to fall back to.
    if content.height < TOAST_HEIGHT + 2 * INSET {
        return None;
    }
    // N5: whatever is left of the toast must still be readable. The
    // inset column is counted against the toast, not against the
    // content, so the guarantee holds at exactly 40 on an 80-col frame.
    let max_w = content
        .width
        .saturating_sub(MIN_CONTENT_COLS.saturating_add(INSET));
    if max_w < MIN_TOAST_WIDTH {
        return None;
    }
    let w = desired.clamp(MIN_TOAST_WIDTH, max_w);

    let x = content.right() - INSET - w;
    let top = Rect {
        x,
        y: content.y + INSET,
        width: w,
        height: TOAST_HEIGHT,
    };
    if focus.is_some_and(|f| f.intersects(top)) {
        // Bottom-right. If the focused band covers this too (a Lists
        // card tall enough to span both ends of a 14-row content area)
        // there is no non-occluding anchor left; bottom-right is the
        // deterministic answer rather than a third position nobody can
        // predict.
        return Some(Rect {
            x,
            y: content.bottom() - INSET - TOAST_HEIGHT,
            width: w,
            height: TOAST_HEIGHT,
        });
    }
    Some(top)
}

/// Draw the toast over the tab content.
///
/// Call *after* the active tab has rendered — [`focus_band`] reads the
/// tab's own highlight back out of the frame buffer — and *before* the
/// modal overlays, which must draw on top of it.
pub fn render(f: &mut Frame, content: Rect, status: &StatusLine) {
    let band = focus_band(f.buffer_mut(), content);
    let Some(rect) = toast_rect(content, desired_width(&status.text), band) else {
        return;
    };

    let (glyph, color) = severity_style(status.severity);
    // Body budget: the frame's two columns plus the glyph and the
    // trailing pad. Guaranteed non-negative — `MIN_TOAST_WIDTH` is
    // wider than `CHROME_COLS`.
    let body = truncate_to(&status.text, rect.width - CHROME_COLS);

    f.render_widget(Clear, rect);
    let block = framed_block_colored(T.border_subtle).style(Style::default().bg(T.bg_elevated));
    let line = Line::from(vec![
        Span::styled(glyph, Style::default().fg(color)),
        Span::styled(body, Style::default().fg(color)),
    ]);
    f.render_widget(Paragraph::new(line).block(block), rect);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    /// The content rect the real layout hands us at the declared 80×24
    /// floor with a 5-row menu card: 4 header + 5 menu + 14 content + 1
    /// footer.
    fn floor_content() -> Rect {
        Rect::new(0, 9, 80, 14)
    }

    // N5 — the toast must leave at least 40 usable content columns at
    // the 80×24 floor, however long the message is.
    #[test]
    fn toast_leaves_forty_content_columns_at_the_floor() {
        let content = floor_content();
        let long = "a".repeat(200);
        let r = toast_rect(content, desired_width(&long), None).expect("toast must fit at 80x24");
        assert!(
            r.x - content.x >= MIN_CONTENT_COLS,
            "only {} content columns left of the toast (need {MIN_CONTENT_COLS})",
            r.x - content.x
        );
        assert!(
            r.right() <= content.right(),
            "toast escaped the content rect"
        );
        assert_eq!(r.height, TOAST_HEIGHT, "toast height must be deterministic");
    }

    // N5 — the body truncates with `…`; it never wraps into a second
    // row, which would make the height data-dependent.
    #[test]
    fn long_message_truncates_with_ellipsis() {
        let long = "blocklist privacy/ads failed to refresh: connection timed out after 30s";
        let content = floor_content();
        let r = toast_rect(content, desired_width(long), None).unwrap();
        let body = truncate_to(long, r.width - CHROME_COLS);
        assert_eq!(body.chars().count(), (r.width - CHROME_COLS) as usize);
        assert!(
            body.ends_with('\u{2026}'),
            "truncated body must be marked: {body}"
        );
    }

    #[test]
    fn short_message_is_not_truncated() {
        assert_eq!(truncate_to("list saved", 30), "list saved");
        assert_eq!(truncate_to("", 30), "");
        assert_eq!(truncate_to("abcdef", 0), "");
    }

    // N1′ — cursor on the first row of the table: the toast must not sit
    // on it. This is the regression that would otherwise reintroduce B1
    // one surface over.
    #[test]
    fn toast_avoids_a_focused_row_at_the_top() {
        let content = floor_content();
        // A table header at content.y + 1, first data row at + 2 — well
        // inside the band the top-right anchor would claim.
        let focused = Rect::new(content.x, content.y + 2, content.width, 1);
        let r = toast_rect(content, 20, Some(focused)).unwrap();
        assert!(
            !r.intersects(focused),
            "toast {r:?} sits on the focused row {focused:?}"
        );
        assert!(
            r.y > content.y + content.height / 2,
            "toast must drop to the bottom half, got {r:?}"
        );
    }

    // …and when the cursor is far down, the toast keeps its top-right
    // home rather than always fleeing to the bottom.
    #[test]
    fn toast_stays_top_right_when_the_cursor_is_low() {
        let content = floor_content();
        let focused = Rect::new(content.x, content.bottom() - 2, content.width, 1);
        let r = toast_rect(content, 20, Some(focused)).unwrap();
        assert_eq!(r.y, content.y + INSET);
        assert!(!r.intersects(focused));
    }

    // A degenerate content rect yields no toast rather than a rect that
    // overflows into the footer.
    #[test]
    fn no_toast_when_there_is_no_room() {
        assert!(toast_rect(Rect::new(0, 0, 80, 4), 20, None).is_none());
        assert!(toast_rect(Rect::new(0, 0, 50, 14), 20, None).is_none());
    }

    // The focus-band scan reads the tab's own highlight back out of the
    // buffer — the mechanism N1′ depends on for every tab without
    // duplicating any tab's layout here.
    #[test]
    fn focus_band_finds_the_highlight_row() {
        let mut term = Terminal::new(TestBackend::new(20, 6)).unwrap();
        term.draw(|f| {
            let row = Rect::new(0, 2, 20, 1);
            f.render_widget(
                Paragraph::new("selected").style(Style::default().bg(T.bg_highlight)),
                row,
            );
        })
        .unwrap();
        let buf = term.backend().buffer().clone();
        let band = focus_band(&buf, Rect::new(0, 0, 20, 6)).expect("highlight row must be found");
        assert_eq!(band.y, 2);
        assert_eq!(band.height, 1);
    }

    #[test]
    fn focus_band_is_none_without_a_highlight() {
        let mut term = Terminal::new(TestBackend::new(20, 6)).unwrap();
        term.draw(|f| f.render_widget(Paragraph::new("plain"), f.area()))
            .unwrap();
        let buf = term.backend().buffer().clone();
        assert!(focus_band(&buf, Rect::new(0, 0, 20, 6)).is_none());
    }

    // ui-01 moves with the message: the severity glyph and colour are
    // now the toast's contract, not the footer's. A success must paint
    // the green `✓`, an error the red `✕`.
    #[test]
    fn toast_styles_success_green_and_error_red() {
        use crate::tui::app::App;

        for (set, glyph, want) in [
            (0u8, '\u{2713}', T.success),
            (1u8, '\u{2715}', T.error),
            (2u8, '\u{2022}', T.text_secondary),
        ] {
            let mut app = App::new();
            match set {
                0 => app.status_ok("list saved".into()),
                1 => app.status_err("boom".into()),
                _ => app.status_info("nothing to do".into()),
            }
            let content = floor_content();
            let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
            term.draw(|f| render(f, content, app.last_status.as_ref().unwrap()))
                .unwrap();
            let buf = term.backend().buffer().clone();
            let cell = buf
                .content()
                .iter()
                .find(|c| c.symbol().starts_with(glyph))
                .unwrap_or_else(|| panic!("toast must render the {glyph} glyph"));
            assert_eq!(cell.fg, want, "{glyph} rendered in the wrong colour");
        }
    }

    // N1 — the drawn toast stays inside the content rect. The footer and
    // the menu card are siblings of that rect, so containment is the
    // property that proves non-intersection with both.
    #[test]
    fn rendered_toast_never_leaves_the_content_rect() {
        use crate::tui::app::App;

        let mut app = App::new();
        app.status_ok("x".repeat(120));
        let content = floor_content();
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| render(f, content, app.last_status.as_ref().unwrap()))
            .unwrap();
        let buf = term.backend().buffer().clone();
        // Any cell painted with the toast's elevated background must be
        // inside `content`.
        for y in 0..24u16 {
            for x in 0..80u16 {
                if buf.cell((x, y)).is_some_and(|c| c.bg == T.bg_elevated) {
                    assert!(
                        content.contains(ratatui::layout::Position { x, y }),
                        "toast cell ({x},{y}) escaped the content rect {content:?}"
                    );
                }
            }
        }
    }
}
