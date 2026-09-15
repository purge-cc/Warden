//! Shared building blocks for every operator-facing modal overlay in the
//! dashboard: the chrome, the row vocabulary, the scrolling body, the
//! action row, and the palette decisions — so twelve surfaces look and
//! behave like one system instead of twelve.
//!
//! ## Archetypes — pick one, they are the whole contract
//!
//! There are exactly **two** shapes. Which one a
//! surface is decides which functions it calls; there is no third option
//! and no "mostly a form".
//!
//! ### F — form (banded, sectioned, always scrolling)
//!
//! An entity add/edit surface. Build it with:
//!
//! 1. [`FormRows::new`] — opens the body with the banded title,
//!    description and spacer.
//! 2. [`FormRows::section`] / [`FormRows::field`] /
//!    [`FormRows::text_field`] / [`FormRows::line`] / [`FormRows::spacer`],
//!    with rows from [`value_row`], [`selector_row`], [`radio_row`],
//!    [`collapse_row`], [`state_row`].
//! 3. [`form_tail`] then [`FormRows::finish`].
//! 4. [`render_modal`] with that builder as its closure.
//!
//! **Every** form is built on [`ScrollBody`], including the four-field
//! ones. [`scroll_layout`] returns `view_h == fields.len()` whenever the
//! rows fit and the scrollbar only draws on overflow, so on a terminal
//! with room the output is identical to a fixed body — what scrolling adds
//! is that the **tail is allocated first**, so the action row survives even
//! when the space does not. Choosing a fixed body buys nothing and
//! re-opens the min-height clipping defect this repo has paid for
//! more than once.
//!
//! Reference implementation: `tabs/lists.rs::render_edit_modal` — the
//! operator-validated surface every other form is measured against.
//!
//! ### C — not-a-form (confirm / picker / read-only)
//!
//! A question, a list of options, or a rendered result. Same frame, same
//! title band, same surface, **no field grid**. Build it with
//! [`NoticeSpec`] + [`notice_body`], rows from [`prose_row`] and
//! [`choice_rows`], then the same [`render_modal`].
//!
//! Its row budget is the tightest in the ecosystem — **12** interior rows
//! at the minimum-terminal floor, of which the head takes 2 and the tail
//! `hint_rows + keys + actions`. Three things follow, and a new consumer
//! that gets them wrong fails silently:
//!
//! - An option's explanation is never dropped. A choosable option's
//!   [`ChoiceRow::detail`] is ellipsised into its row; a disabled one's
//!   [`ChoiceRow::note`] gets an indented row of its own,
//!   unconditionally, because no consumer's cursor can land on a disabled
//!   entry and the tail's hint only ever shows the focused one's copy.
//! - The row count of a body is a function of the **spec**, never of the
//!   width. [`render_modal`] measures at `w` and renders at `w - 1`.
//! - A body with no [`NoticeSpec::choices`] has no focus target, so it
//!   cannot scroll and draws no scrollbar
//!   ([`ScrollBody::scrollable`]) — such a body must be sized to fit,
//!   because overflow is cut with no affordance saying so.
//!
//!
//! ## Color roles
//!
//! Modal titles reuse the red navigation bands. Section rules use their
//! semantic card colors. Editable values have a neutral resting surface and
//! a blue focus surface with inverse text. Buttons use compact neutral fills;
//! the focused button uses its action color. Labels stay outside the focus fill.
//!
//! ## Input contract
//!
//! A surface keeps its **own keying** across migration: real
//! terminal cursor, `Ctrl+S`, `Enter`-submits, popup pickers. Only chrome,
//! layout and colour are shared. Muscle memory is not part of the
//! redesign, which is why [`nav_keys_line`] takes the caller's copy rather
//! than advertising a fixed legend.
//!
//! ## Legacy layering — gone
//!
//! An older grey `Field │ Value` grid survived here for as long as
//! `tabs/devices` was unmigrated. Migrating it to Archetype F
//! orphaned the layer outright, and it was **deleted**: `FieldKind`,
//! `FieldRow` (+ its constructors), `Button`, `button_row`, `button_span`,
//! `section_lines`, `grid_row`, `grid_rule`, `decorate`, `value_color` and
//! `GRID_RULE_COL` — about 430 lines with their tests.
//!
//! Two things survived the sweep and are worth knowing why:
//!
//! - [`GRID_LABEL_W`] is a **genuine** external dependency — `subnet_modal`,
//!   `profile_modal` and `tabs/lists` use it for cursor arithmetic.
//! - [`render_chrome_in`], [`render_body_fixed`] and [`hint_or_error_rows`]
//!   are called only from inside this module now ([`render_modal`],
//!   [`render_scroll_body`], [`note_rows`]/[`notice_body`]). Their `pub` is
//!   therefore unnecessary; demoting it is an optional tidy, not a fix.
//!
//! The attribution was measured, not assumed: with `allow(dead_code)` on
//! this file alone, `clippy --all-targets -D warnings` went from 13 errors
//! to 0, so every one of them originated here. Note also that a
//! `cfg(test)`-only consumer does **not** rescue a `pub` item from
//! `dead_code` — clippy builds the lib target separately, without
//! `cfg(test)`, and that is the target that fails.

use std::cell::RefCell;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Alignment, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph};
use ratatui::Frame;

use crate::tui::overlay::centered_rect;
use crate::tui::theme::{self, T};

/// Fixed width (chars) of the left "Field" label column in the grid.
pub const GRID_LABEL_W: usize = 18;

/// Clear a `w`×`h` rect centred on `anchor`, draw the square modal frame
/// on the elevated surface, and return the inner rect for the body.
///
/// `anchor` bounds the modal and supplies its horizontal center. Vertically
/// the modal centers on the terminal, clamped inside the content anchor so
/// narrow terminals retain navigation and footer access. Devices supplies the
/// list column as its anchor to keep the detail card visible.
///
/// `title_in_band` suppresses the border title: the caller renders
/// [`title_band`] as the first body line instead.
pub fn render_chrome_in(
    f: &mut Frame,
    anchor: Rect,
    w: u16,
    h: u16,
    title: &str,
    accent: Color,
    title_in_band: bool,
) -> Rect {
    crate::tui::mouse::begin_overlay();
    let mut area = centered_rect(anchor, w, h);
    let centered_y = f.area().y + f.area().height.saturating_sub(area.height) / 2;
    area.y = centered_y.clamp(anchor.y, anchor.bottom().saturating_sub(area.height));
    f.render_widget(Clear, area);
    let mut block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(accent))
        // Raised surface so the modal reads as floating above the tab.
        .style(Style::default().bg(T.bg_elevated));
    if !title_in_band {
        block = block.title(Span::styled(
            title.to_string(),
            Style::default().fg(accent).add_modifier(Modifier::BOLD),
        ));
    }
    let inner = block.inner(area);
    f.render_widget(block, area);
    inner
}

/// Content shares one cell of horizontal breathing room inside the frame.
pub fn content_rect(surface: Rect) -> Rect {
    Rect::new(
        surface.x.saturating_add(surface.width.min(1)),
        surface.y,
        surface.width.saturating_sub(2),
        surface.height,
    )
}

/// Paint full surface heading bands and return the padded body below them.
pub fn render_header(f: &mut Frame, surface: Rect, title: &str, description: &str) -> Rect {
    let inner = content_rect(surface);
    for (row, (text, subtitle)) in [(title, false), (description, true)]
        .into_iter()
        .enumerate()
    {
        if row >= surface.height as usize {
            break;
        }
        let band = Rect::new(surface.x, surface.y + row as u16, surface.width, 1);
        let text_area = Rect::new(inner.x, band.y, inner.width, 1);
        f.render_widget(
            Block::default().style(T.modal_heading_style(subtitle)),
            band,
        );
        f.render_widget(
            Paragraph::new(heading_line(text, inner.width, subtitle)),
            text_area,
        );
    }
    Rect::new(
        inner.x,
        inner.y.saturating_add(3.min(inner.height)),
        inner.width,
        inner.height.saturating_sub(3),
    )
}

/// Reserve an actionable Close control beneath a read-only modal body.
pub fn close_footer(f: &mut Frame, content: Rect) -> Rect {
    if content.is_empty() {
        return content;
    }
    let actions = [Action::new("Close", true, ActionKind::Neutral, "").on_key(KeyCode::Esc)];
    let footer = Rect::new(content.x, content.bottom() - 1, content.width, 1);
    f.render_widget(Paragraph::new(action_row(&actions, content.width)), footer);
    for hit in action_hits(&actions, content.width) {
        crate::tui::mouse::register_overlay(
            Rect::new(footer.x + hit.x, footer.y, hit.width, 1),
            hit.key,
        );
    }
    Rect::new(
        content.x,
        content.y,
        content.width,
        content.height.saturating_sub(2),
    )
}

/// Render a body whose rows are already laid out to exactly fill the
/// modal — no wrapping. The only body renderer; the wrapping one is
/// retired.
///
/// Wrapping is actively harmful for such a body. Under `Wrap { trim: false }`
/// a line costs a second rendered row when it is **over-width** or
/// **whitespace-only** — a line of exactly the target width is fine, which is
/// why this went unnoticed. The Devices client form's validation row renders
/// `"  "` whenever there is no error and the focused field has no hint, and
/// that one row pushed its entire `Cancel`/`Save` row off the bottom.
///
/// Every unit assertion on the line vector passed while this was broken,
/// because the vector was correct — the defect lived only in how the widget
/// rendered it. A real-terminal smoke found it. See the regression test
/// `wrap_costs_a_row_for_overwidth_and_whitespace_only_lines`.
pub fn render_body_fixed(f: &mut Frame, inner: Rect, lines: Vec<Line<'static>>) {
    let paragraph = Paragraph::new(lines)
        .style(Style::default().bg(T.bg_elevated))
        .alignment(Alignment::Left);
    f.render_widget(paragraph, inner);
}

/// A modal body split into three regions so it can survive a terminal
/// shorter than its content.
///
/// The problem this solves: [`render_body_fixed`] draws a flat line list,
/// and `overlay::centered_rect` clamps the modal to its anchor. When the
/// anchor is short — at the declared floor of 80×24 a leaf tab's content
/// area is only ~14 rows — the tail of the list is simply cut off. The
/// Lists edit modal lost its `Save`/`Cancel` row that way, and focus could
/// still Tab onto rows below the cut, so the operator was editing blind.
///
/// Splitting it means the two things that must never disappear — what am I
/// editing, and how do I commit or escape — are pinned, and only the field
/// region scrolls.
pub struct ScrollBody {
    /// Explicit keyboard actions and the exact button cells that activate them.
    pub action_hits: Vec<ActionHit>,
    pub field_hits: Vec<FieldHit>,
    /// Pinned to the top: title band, description, spacer.
    pub head: Vec<Line<'static>>,
    /// The scrolling region: one entry per field row.
    pub fields: Vec<Line<'static>>,
    /// Pinned to the bottom, **least important first** — when there is not
    /// enough room the front of this vector is dropped, so put hints and
    /// key legends before the button row.
    pub tail: Vec<Line<'static>>,
    /// Index into `fields` of the focused row. The viewport scrolls to keep
    /// it visible; there is no scroll keybinding, because following focus
    /// is what the operator already expects from Tab.
    pub focus_row: Option<usize>,
    /// Whether any keystroke can move the field region at all.
    ///
    /// `false` means nothing in `fields` can ever take focus — an
    /// Archetype-C body of pure prose. There is no scroll keybinding
    /// anywhere in this module (following focus is the whole mechanism),
    /// so a body with no focus target has a viewport pinned at offset 0
    /// forever. [`render_scroll_body`] then suppresses the scrollbar:
    /// a bar advertises "there is more, and you can reach it", and the
    /// second half of that would be a lie.
    ///
    /// It is deliberately NOT `focus_row.is_none()`. A form whose focus
    /// currently sits on an action row has no focused *field* yet still
    /// scrolls the moment focus returns to one, and blinking the bar in
    /// and out as the operator tabs onto Save would be its own defect.
    ///
    /// A `false` body that overflows is silently cut — so a surface that
    /// sets it must size its content to the anchor. See
    /// `a_prose_only_notice_draws_no_scrollbar`.
    pub scrollable: bool,
}

/// Where [`render_scroll_body`] put the viewport, so the caller can place
/// the hardware cursor in the same coordinate space.
pub struct ScrollView {
    /// First `fields` index rendered.
    pub offset: usize,
    /// How many `fields` rows are visible.
    pub view_h: usize,
    /// Rows consumed by `head` — the y offset of the field region.
    pub head_h: usize,
}

/// Split `avail` rows between the three regions of a [`ScrollBody`],
/// returning `(head_h, view_h, tail_h)`.
///
/// Height is allocated by necessity, not by order: the tail is served
/// first (its last row is the button row, the whole point of the modal),
/// then the head, and the field region gets what remains. If the space is
/// so tight that even the tail must be cut, the **last** rows survive — a
/// modal with no visible hint is workable, one with no visible Save is not.
///
/// Pure and public so the scrollbar-column question can be answered before
/// any row is built. Both [`will_scroll`] and [`render_scroll_body`] go
/// through here, so there is exactly one definition of the allocation.
pub fn scroll_layout(
    avail: usize,
    head: usize,
    fields: usize,
    tail: usize,
) -> (usize, usize, usize) {
    if avail == 0 {
        return (0, 0, 0);
    }
    // Tail first: its last row is the button row, which is the whole point
    // of the modal. Then the head. Fields take what is left.
    let tail_h = tail.min(avail);
    let head_h = head.min(avail - tail_h);
    let view_h = (avail - tail_h - head_h).min(fields);
    (head_h, view_h, tail_h)
}

/// Whether a body of these dimensions will scroll in `avail` rows — i.e.
/// whether a scrollbar column will be claimed.
///
/// **Not a consumer-facing entry point.** A surface that asks this by hand
/// then has to remember to rebuild its rows one column narrower, and every
/// surface each remembering that is exactly the drift this ecosystem
/// exists to end.
/// Call [`render_modal`], which resolves the width internally. This
/// stays public only so the allocation rule can be asserted directly.
pub fn will_scroll(avail: usize, head: usize, fields: usize, tail: usize) -> bool {
    let (_, view_h, _) = scroll_layout(avail, head, fields, tail);
    view_h > 0 && fields > view_h
}

/// Draw a [`ScrollBody`] into `inner`, scrolling the field region to keep
/// `focus_row` visible and drawing a scrollbar in the last column when it
/// does not all fit. Height is allocated per [`scroll_layout`].
///
/// Prefer [`render_modal`], which owns the chrome, the two-pass width
/// resolution and the scrollbar column on top of this.
pub fn render_scroll_body(f: &mut Frame, inner: Rect, body: &ScrollBody) -> ScrollView {
    let avail = inner.height as usize;
    if avail == 0 {
        return ScrollView {
            offset: 0,
            view_h: 0,
            head_h: 0,
        };
    }

    let (head_h, view_h, tail_h) =
        scroll_layout(avail, body.head.len(), body.fields.len(), body.tail.len());
    let tail_skip = body.tail.len() - tail_h;

    // Scroll so the focused row sits inside the window. Clamped to the end
    // of the list so the last page never shows blank rows below content.
    let total = body.fields.len();
    let mut offset = 0usize;
    if view_h > 0 && total > view_h {
        if let Some(focus) = body.focus_row {
            if focus >= view_h {
                offset = focus + 1 - view_h;
            }
        }
        offset = offset.min(total - view_h);
    }
    let scrolled = body.scrollable && view_h > 0 && total > view_h;

    let mut lines: Vec<Line<'static>> = Vec::with_capacity(avail);
    lines.extend(body.head.iter().take(head_h).cloned());
    lines.extend(body.fields.iter().skip(offset).take(view_h).cloned());
    let gap = avail.saturating_sub(head_h + view_h + tail_h);
    lines.extend(std::iter::repeat_with(Line::default).take(gap));
    lines.extend(body.tail.iter().skip(tail_skip).cloned());
    for (row, line) in lines.iter().enumerate() {
        if line.style.bg == T.modal_heading_style(false).bg
            || line.style.bg == T.modal_heading_style(true).bg
        {
            let band = Rect::new(
                inner.x.saturating_sub(1),
                inner.y + row as u16,
                inner.width.saturating_add(2),
                1,
            )
            .intersection(f.area());
            f.render_widget(Block::default().style(line.style), band);
        }
    }
    render_body_fixed(f, inner, lines);

    for hit in &body.field_hits {
        if hit.row >= offset && hit.row < offset + view_h {
            let area = Rect::new(
                inner.x.saturating_add(hit.x),
                inner.y + (head_h + hit.row - offset) as u16,
                hit.width,
                1,
            )
            .intersection(inner);
            crate::tui::mouse::register_overlay_action(area, hit.action);
        }
    }

    if tail_h > 0 {
        let y = inner.y + (avail - 1) as u16;
        for hit in &body.action_hits {
            let area =
                Rect::new(inner.x.saturating_add(hit.x), y, hit.width, 1).intersection(inner);
            crate::tui::mouse::register_overlay(area, hit.key);
        }
    }

    if scrolled {
        render_scrollbar(f, inner, head_h as u16, view_h, offset, total);
    }

    ScrollView {
        offset,
        view_h,
        head_h,
    }
}

/// Vertical scrollbar in the last column of the field region: a
/// `text_secondary` thumb on a `border_subtle` track, both chrome greys —
/// no semantic colour, since position is not a state.
fn render_scrollbar(
    f: &mut Frame,
    inner: Rect,
    y_start: u16,
    view_h: usize,
    offset: usize,
    total: usize,
) {
    if inner.width == 0 || view_h == 0 {
        return;
    }
    // Proportional thumb, never shorter than one cell, never past the end.
    let thumb_h = ((view_h * view_h) / total).max(1).min(view_h);
    let span = view_h - thumb_h;
    let scroll_span = total - view_h;
    let thumb_at = (offset * span + scroll_span / 2)
        .checked_div(scroll_span)
        .unwrap_or(0);

    let x = inner.right() - 1;
    for row in 0..view_h {
        let in_thumb = row >= thumb_at && row < thumb_at + thumb_h;
        let (glyph, color) = if in_thumb {
            ("\u{2588}", T.text_secondary)
        } else {
            ("\u{2502}", T.border_subtle)
        };
        let cell = Rect {
            x,
            y: inner.y + y_start + row as u16,
            width: 1,
            height: 1,
        };
        if cell.y < inner.bottom() {
            f.render_widget(
                Paragraph::new(Span::styled(glyph, Style::default().fg(color)))
                    .style(Style::default().bg(T.bg_elevated)),
                cell,
            );
        }
    }
}

/// Fit complete graphemes into a display-cell budget, marking omitted text.
pub fn fit(text: &str, max: usize) -> String {
    crate::tui::text::fit(text, max)
}

#[derive(Clone, Copy)]
pub enum TextTone {
    Primary,
    Secondary,
    Muted,
    Success,
    Warning,
    Error,
}

pub fn text_style(tone: TextTone) -> Style {
    Style::default().fg(match tone {
        TextTone::Primary => T.text_primary,
        TextTone::Secondary => T.text_secondary,
        TextTone::Muted => T.text_muted,
        TextTone::Success => T.success,
        TextTone::Warning => T.warning,
        TextTone::Error => T.error,
    })
}

fn padded_line(text: &str, width: u16, style: Style) -> Line<'static> {
    let shown = fit(text, width as usize);
    let padding = (width as usize).saturating_sub(crate::tui::text::width(&shown));
    Line::styled(format!("{shown}{}", " ".repeat(padding)), style)
}

pub fn heading_band(text: &str, width: u16, subtitle: bool) -> Line<'static> {
    padded_line(&format!(" {text}"), width, T.modal_heading_style(subtitle))
}

pub fn filled_section_band(label: &str, width: u16, role: theme::CardRole) -> Line<'static> {
    padded_line(
        label,
        width,
        Style::default()
            .bg(T.card_title_bg(role))
            .fg(T.text_inverse)
            .add_modifier(Modifier::BOLD),
    )
}

pub fn list_choice_row(label: &str, width: u16, focused: bool, selected: bool) -> Line<'static> {
    let style = if focused {
        Style::default()
            .bg(T.warden_teal)
            .fg(T.text_inverse)
            .add_modifier(Modifier::BOLD)
    } else if selected {
        Style::default()
            .bg(T.bg_highlight)
            .fg(T.warden_teal)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().bg(T.bg_surface).fg(T.text_secondary)
    };
    padded_line(label, width, style)
}

/// [`fit`]'s mirror: keep the **tail**, mark the cut on the left.
///
/// [`fit`] is right for a value the operator is *reading* — the head is
/// where a domain, an id or a path identifies itself. It is wrong for one
/// they are *typing*, because typing happens at the end: keeping the head
/// shows them the part they have finished with and hides the part their
/// fingers are on.
///
/// The ellipsis leads for the same reason it trails in [`fit`] — it marks
/// which side was cut, and here that side is the left.
fn fit_tail(text: &str, max: usize) -> String {
    crate::tui::text::fit_tail(text, max)
}

/// Full-width paired heading bands shared with the main navigation.
/// The form retains a single blank row after its subtitle.
pub fn title_band(title: &str, width: u16) -> Line<'static> {
    heading_line(&title.to_uppercase(), width, false)
}

fn heading_line(text: &str, width: u16, subtitle: bool) -> Line<'static> {
    let body = fit(text, width as usize);
    let pad = (width as usize).saturating_sub(crate::tui::text::width(&body));
    Line::from(format!("{body}{}", " ".repeat(pad))).style(T.modal_heading_style(subtitle))
}

/// A coordinated darker subtitle band; long copy is fitted to the viewport.
pub fn desc_band(text: &str, width: u16) -> Line<'static> {
    heading_line(text, width, true)
}

/// A fixed two-row subtitle for forms whose description needs two lines.
pub fn desc_band2(desc: [&str; 2], width: u16) -> [Line<'static>; 2] {
    desc.map(|text| desc_band(text, width))
}

/// Buffer assertions shared by the four surfaces that carry a
/// [`desc_band2`] heading, so each pins the property the same way instead
/// of four hand-rolled approximations of it.
#[cfg(test)]
pub(crate) mod desc_band2_assert {
    use ratatui::buffer::Buffer;
    use ratatui::style::Color;

    /// The frozen colours, as literals rather than as `T.bg_main` /
    /// `T.warden_teal`. The contract froze the *colours*; reading them back
    /// out of the same constants the renderer used would make the test pass
    /// on any theme edit that moved both together.
    ///
    /// `BAND_BG` is `bg_main`, **not** the title's `bg_highlight`: teal on
    /// the latter is 3.37:1 against a 4.5:1 prose bar and no gate catches
    /// it. See [`super::desc_band2`]'s doc. Asserting the literal here is
    /// what makes a re-alignment to the title's background fail the build
    /// instead of shipping green.
    const BAND_BG: Color = Color::Rgb(75, 36, 36);
    const TITLE_BG: Color = Color::Rgb(185, 28, 28);
    const COPY_FG: Color = Color::Rgb(229, 229, 229);

    /// Cell-accurate substring search — returns the **column** of the
    /// match, not a byte offset.
    ///
    /// `str::find` on a row string would return bytes, and these rows sit
    /// directly under a title band whose first cell is `▌` (3 bytes), so
    /// the two diverge for every column after it.
    fn find_cells(buf: &Buffer, needle: &str) -> Option<(u16, u16)> {
        let n: Vec<String> = needle.chars().map(|c| c.to_string()).collect();
        for y in 0..buf.area.height {
            let row: Vec<&str> = (0..buf.area.width).map(|x| buf[(x, y)].symbol()).collect();
            if row.len() < n.len() {
                continue;
            }
            for start in 0..=(row.len() - n.len()) {
                if (0..n.len()).all(|k| row[start + k] == n[k]) {
                    return Some((start as u16, y));
                }
            }
        }
        None
    }

    /// Columns on row `y` painted with background `bg`.
    fn run_of(buf: &Buffer, y: u16, bg: Color) -> Vec<u16> {
        (0..buf.area.width)
            .filter(|&x| buf[(x, y)].bg == bg)
            .collect()
    }

    /// Assert `desc` renders as two adjacent full-width rows on `bg_main`
    /// under the title band, in teal, with the modal's actions still on
    /// screen.
    ///
    /// The band's **extent** is derived from the title row rather than from
    /// a geometry constant: `title_band` fills the modal interior with
    /// `bg_highlight`, so the columns it occupies ARE the interior, and no
    /// surface's `MODAL_W` has to be duplicated here.
    ///
    /// The two strips are deliberately different colours — same width,
    /// distinct background — so this asserts extent *across* them rather
    /// than equality of the runs, and additionally that the description
    /// carries **no** `bg_highlight`. That second check is what fails if
    /// someone re-aligns the band to the title's background for looks: it
    /// would be a 3.37:1 prose regression that no contrast gate can see
    /// (see [`super::desc_band2`]).
    ///
    /// Full-width matters on its own. A `Span`'s background paints only its
    /// own characters, so a band built without a styled pad span stops
    /// where the sentence does — passing any check that samples the copy.
    pub(crate) fn assert_two_row_band(buf: &Buffer, desc: [&str; 2], actions: &[&str]) {
        let dump: String = (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");

        let (x0, y0) = find_cells(buf, desc[0])
            .unwrap_or_else(|| panic!("description row 0 is off screen: {:?}\n{dump}", desc[0]));
        let (x1, y1) = find_cells(buf, desc[1])
            .unwrap_or_else(|| panic!("description row 1 is off screen: {:?}\n{dump}", desc[1]));
        assert_eq!(y1, y0 + 1, "the two description rows must be adjacent");
        assert_eq!(x1, x0, "both rows share one indent");
        assert!(y0 > 0, "a description row cannot be the buffer's first row");

        // `title_band` fills the interior with `bg_highlight`, so its run of
        // columns IS the modal interior — the band under it must cover the
        // same span, in its own colour.
        let interior = run_of(buf, y0 - 1, TITLE_BG);
        assert!(
            !interior.is_empty(),
            "no title band above the description — the heading is what this \
             band sits under\n{dump}"
        );
        for (i, y) in [y0, y1].into_iter().enumerate() {
            assert_eq!(
                run_of(buf, y, BAND_BG),
                interior,
                "description row {i} does not carry the bg_main band across \
                 the modal's full interior — a band that stops at the end of \
                 its text is the defect `band_line` documents\n{dump}"
            );
            // Every cell of the copy, not just its first: a style applied to
            // one span and not its neighbours passes a single-cell sample.
            //
            // The range stops at the end of the sentence ON PURPOSE. The pad
            // span carries the background but deliberately NO foreground, so
            // widening this to the whole row would fail on correct output —
            // if you are here because it did, that is the reason.
            for dx in 0..crate::tui::text::width(desc[i]) as u16 {
                assert_eq!(
                    buf[(x0 + dx, y)].fg,
                    COPY_FG,
                    "description row {i} is not red at column {}\n{dump}",
                    x0 + dx
                );
            }
        }

        // A form can lose its action row to a head that grew
        // and still look complete, while the focus ring keeps reaching the
        // buttons that are no longer drawn.
        for a in actions {
            assert!(
                dump.contains(a),
                "the {a} action was pushed off screen by the description \
                 band\n{dump}"
            );
        }
    }
}

// ── Ecosystem layer (Archetype F rows) ────────────────────────────────
//
// The operator-validated Lists edit modal's row vocabulary, lifted out of
// `tabs/lists.rs` so every Archetype-F surface inherits one implementation
// of the colour rule instead of re-deriving it. Chrome stays grey;
// `warden_teal` marks static info; `emerald_ping` marks the single live
// focus; category colour appears only on tag chips; `brand_red` is the
// title tick and destructive copy, never a border.

/// Value column (chars from the modal's inner-left edge) for the banded
/// ecosystem rows: [`GRID_LABEL_W`] label + a 2-cell gap.
/// Every value span and the real terminal cursor share it, so the column
/// is dead straight and [`ModalRender::place_cursor`] can be told a plain
/// character offset.
///
/// Distinct from `GRID_RULE_COL`, which belonged to the older `│`-ruled
/// grid (`section_lines`): the ecosystem rows carry no vertical rule,
/// so their gap is two cells of whitespace, not `│ `.
pub const VALUE_COL: usize = GRID_LABEL_W + 2;

/// What a row's value *is* — the sole input to its colour, per the palette
/// spec. No caller passes a `Color`, so a value's meaning can never be
/// decided by where the widget sits or how deeply it nests.
///
/// Colours here are resting colours. On the focus bar every kind renders
/// `text_primary` instead: `bg_highlight` is the lightest surface the theme
/// paints and it sinks every semantic hue below WCAG's 3:1 large-text floor
/// (red_glow 2.62, warden_teal 3.37, slate 3.60). The meaning returns the
/// moment focus leaves. See
/// `theme::tests::focus_bar_admits_only_high_contrast_foregrounds`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ValueKind {
    /// Free text the operator types.
    Editable,
    /// Identity & location: ids, URLs, paths, hostnames.
    Identity,
    /// Permissive / healthy / verified: allow, active, signed, reachable.
    Healthy,
    /// Caution, not error: unsigned, stale, unverified.
    Caution,
    /// Blocking or destructive.
    Blocking,
}

impl ValueKind {
    pub fn color(self) -> Color {
        match self {
            // Editable text recedes at rest and comes to full strength
            // under focus (`text_muted_hi` → `text`), so the
            // value itself carries a focus signal beyond the bar.
            ValueKind::Editable => T.text_secondary,
            ValueKind::Identity => T.scope_privacy,
            ValueKind::Healthy => T.scope_security,
            ValueKind::Caution => T.scope_content,
            ValueKind::Blocking => T.red_glow,
        }
    }
}

/// A coloured section label followed by a trailing hairline rule. The text
/// has no background: section identity is conveyed by foreground and rule,
/// never by a second selection-like band.
pub fn section_rule(label: &str, width: u16, role: theme::CardRole) -> Line<'static> {
    let label = fit(&label.to_uppercase(), width as usize);
    let remaining = (width as usize).saturating_sub(crate::tui::text::width(&label));
    let rule = if remaining > 0 {
        format!(" {}", "─".repeat(remaining - 1))
    } else {
        String::new()
    };
    let color = T.card_title_bg(role);
    Line::from(vec![
        Span::styled(
            label,
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ),
        Span::styled(rule, Style::default().fg(color)),
    ])
}

pub fn section_band(label: &str, width: u16) -> [Line<'static>; 2] {
    section_band_with_role(label, width, theme::CardRole::Summary)
}

pub fn section_band_with_role(
    label: &str,
    width: u16,
    role: theme::CardRole,
) -> [Line<'static>; 2] {
    [section_rule(label, width, role), Line::default()]
}

/// Label width and neutral spacing before the value surface.
#[derive(Clone, Copy)]
pub struct ValueLayout {
    pub label_width: usize,
    pub gap: usize,
}

impl Default for ValueLayout {
    fn default() -> Self {
        Self {
            label_width: GRID_LABEL_W,
            gap: 1,
        }
    }
}

impl ValueLayout {
    /// Text starts after the value surface's leading padding cell.
    pub fn value_column(self) -> usize {
        self.label_width + self.gap + 1
    }

    fn budget(self, width: u16) -> usize {
        (width as usize).saturating_sub(self.value_column() + 1)
    }
}

/// Editable value surface with a stable label and cursor column.
pub fn value_row(
    label: &str,
    value: &str,
    focused: bool,
    kind: ValueKind,
    placeholder: Option<&str>,
    width: u16,
) -> Line<'static> {
    value_row_with_layout(
        label,
        value,
        focused,
        kind,
        placeholder,
        width,
        ValueLayout::default(),
    )
}

/// Editable row with explicit label geometry, shared by its cursor budget.
pub fn value_row_with_layout(
    label: &str,
    value: &str,
    focused: bool,
    kind: ValueKind,
    placeholder: Option<&str>,
    width: u16,
    layout: ValueLayout,
) -> Line<'static> {
    let label_style = Style::default().fg(if focused {
        T.text_primary
    } else {
        T.text_secondary
    });
    let surface = if focused { T.info } else { T.bg_highlight };
    let (value, color) = if value.is_empty() && !focused {
        (placeholder.unwrap_or(""), T.text_muted)
    } else {
        (
            value,
            if focused {
                T.text_inverse
            } else {
                kind.color()
            },
        )
    };
    let budget = layout.budget(width);
    let shown = if focused {
        fit_tail(value, budget)
    } else {
        fit(value, budget)
    };
    let mut value_style = Style::default().fg(color).bg(surface);
    if focused {
        value_style = value_style.add_modifier(Modifier::BOLD);
    }
    let lead = format!(
        "{}{}",
        crate::tui::text::pad(&fit(label, layout.label_width), layout.label_width),
        " ".repeat(layout.gap)
    );
    let lead = fit(&lead, width as usize);
    let mut spans = vec![Span::styled(lead, label_style)];
    if width as usize >= layout.value_column() {
        spans.push(Span::styled(" ", value_style));
        let padding = (width as usize)
            .saturating_sub(layout.value_column() + crate::tui::text::width(&shown));
        spans.push(Span::styled(shown, value_style));
        spans.push(Span::styled(" ".repeat(padding), value_style));
    }
    Line::from(spans)
}

/// Reserve one trailing cell for the cursor at the end of a full input.
pub fn value_budget(width: u16, _focused: bool) -> usize {
    (width as usize).saturating_sub(VALUE_COL + 1)
}

/// A cyclable value row (format, refresh interval). Focused wraps the value
/// in `‹ … ›` to signal that a key cycles it.
pub fn selector_row(label: &str, value: &str, focused: bool, width: u16) -> FormLine {
    let shown = if focused {
        // Fit the value FIRST so [`value_row`]'s own fit is a no-op here.
        // Ellipsising the composed string would eat the closing `›` — the
        // marker that says a key cycles this row would be what got cut,
        // rather than the value that overran.
        let inner = fit(value, value_budget(width, true).saturating_sub(4));
        format!("\u{2039} {inner} \u{203a}")
    } else {
        value.to_string()
    };
    let mut line = FormLine::from(value_row(
        label,
        &shown,
        focused,
        ValueKind::Editable,
        None,
        width,
    ));
    if focused && value_budget(width, true) >= 4 {
        line.keys.push((VALUE_COL as u16, 1, KeyCode::Left));
        line.keys.push((
            (VALUE_COL + crate::tui::text::width(&shown) - 1) as u16,
            1,
            KeyCode::Right,
        ));
    }
    line
}

/// A rendered field and its explicitly declared keyboard controls.
/// Geometry follows the same fitted value as the glyphs, including Unicode.
pub struct FormLine {
    line: Line<'static>,
    keys: Vec<(u16, u16, KeyCode)>,
}

impl From<Line<'static>> for FormLine {
    fn from(line: Line<'static>) -> Self {
        Self {
            line,
            keys: Vec::new(),
        }
    }
}

impl From<FormLine> for Line<'static> {
    fn from(line: FormLine) -> Self {
        line.line
    }
}

impl std::ops::Deref for FormLine {
    type Target = Line<'static>;
    fn deref(&self) -> &Self::Target {
        &self.line
    }
}

pub struct FieldHit {
    row: usize,
    x: u16,
    width: u16,
    action: crate::tui::mouse::MouseAction,
}

/// A two-option radio row (Block/Allow, Yes/No). Each side declares what it
/// *means* via its [`ValueKind`], so `nature` reads red on Block and sage on
/// Allow without the renderer knowing either word.
///
/// A glyph alone is too weak at terminal sizes, so the selected
/// side carries both the filled `●` and full-strength colour while the
/// unselected side drops to `text_disabled` — genuinely inactive content,
/// the one place the sub-threshold grey belongs.
pub fn radio_row(
    label: &str,
    left: (&str, ValueKind),
    right: (&str, ValueKind),
    left_selected: bool,
    focused: bool,
    width: u16,
) -> Line<'static> {
    let bar = |s: Style| {
        if focused {
            s.bg(T.info).fg(T.text_inverse)
        } else {
            s.bg(T.bg_highlight)
        }
    };
    let (left_label, left_kind) = left;
    let (right_label, right_kind) = right;
    let selected_text = |kind: ValueKind| {
        if focused {
            T.text_primary
        } else {
            kind.color()
        }
    };
    let dot_sel = if focused {
        T.emerald_ping
    } else {
        T.text_primary
    };
    let (lmark, lcol, ltext) = if left_selected {
        ("\u{25cf}", dot_sel, selected_text(left_kind))
    } else {
        ("\u{25cb}", T.text_disabled, T.text_disabled)
    };
    let (rmark, rcol, rtext) = if left_selected {
        ("\u{25cb}", T.text_disabled, T.text_disabled)
    } else {
        ("\u{25cf}", dot_sel, selected_text(right_kind))
    };
    let label_style = Style::default().fg(if focused {
        T.text_primary
    } else {
        T.text_secondary
    });
    let mut spans = Vec::with_capacity(6);
    push_row_lead(&mut spans, focused, label, label_style);
    spans.extend([
        Span::styled(lmark.to_string(), bar(Style::default().fg(lcol))),
        Span::styled(
            format!(" {left_label}    "),
            bar(Style::default().fg(ltext)),
        ),
        Span::styled(rmark.to_string(), bar(Style::default().fg(rcol))),
        Span::styled(format!(" {right_label}"), bar(Style::default().fg(rtext))),
    ]);
    if focused {
        let used = VALUE_COL
            + 2
            + crate::tui::text::width(left_label)
            + 5
            + crate::tui::text::width(right_label);
        let pad = (width as usize).saturating_sub(used);
        if pad > 0 {
            spans.push(Span::styled(" ".repeat(pad), Style::default().bg(T.info)));
        }
    }
    Line::from(spans)
}

/// A collapse toggle that hides a group of secondary fields (the Lists
/// SOURCE section's "▸ Advanced"). Collapsed, it trails a muted `preview`
/// naming what it hides; focused, the arrow glows emerald.
///
/// `preview` is rendered verbatim, so a caller that wants a gap before it
/// includes the leading spaces.
pub fn collapse_row(
    label: &str,
    preview: &str,
    expanded: bool,
    focused: bool,
    width: u16,
) -> Line<'static> {
    let bar = |s: Style| if focused { s.bg(T.bg_highlight) } else { s };
    let arrow = if expanded { "\u{25be}" } else { "\u{25b8}" };
    let arrow_col = if focused {
        T.emerald_ping
    } else {
        T.warden_teal
    };
    let mut spans = vec![
        Span::styled(format!("{arrow} "), bar(Style::default().fg(arrow_col))),
        Span::styled(
            label.to_string(),
            bar(if focused {
                Style::default()
                    .fg(T.text_primary)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(T.text_secondary)
            }),
        ),
    ];
    let mut used = 2 + crate::tui::text::width(label);
    if !expanded {
        spans.push(Span::styled(
            preview.to_string(),
            bar(Style::default().fg(T.text_muted)),
        ));
        used += crate::tui::text::width(preview);
    }
    if focused {
        let pad = (width as usize).saturating_sub(used);
        if pad > 0 {
            spans.push(Span::styled(
                " ".repeat(pad),
                Style::default().bg(T.bg_highlight),
            ));
        }
    }
    Line::from(spans)
}

/// A read-only state row: a `◆` chip in the state's own colour, plus an
/// optional plain-language `note` explaining it. Never focusable — this is
/// something the operator can see but not change from here.
///
/// Colour *and* copy change together: pass a
/// `note` for the states that need explaining and `""` for the ones that do
/// not. Colour alone would leave an operator who does not know the palette
/// none the wiser.
///
/// The note is dropped, never clipped, when it does not fit: the body does
/// not wrap, so an over-wide line would be cut mid-word instead of
/// reflowing, and half an explanation is worth less than a clean row.
pub fn state_row(
    label: &str,
    state: &str,
    kind: ValueKind,
    note: &str,
    width: u16,
) -> Line<'static> {
    let value = format!("\u{25c6} {state}");
    let mut spans = vec![
        Span::styled(
            format!("{}  ", crate::tui::text::pad(label, GRID_LABEL_W)),
            Style::default().fg(T.text_secondary),
        ),
        Span::styled(value.clone(), Style::default().fg(kind.color())),
    ];
    if !note.is_empty() {
        let used = VALUE_COL + crate::tui::text::width(&value) + crate::tui::text::width(note);
        if used <= width as usize {
            spans.push(Span::styled(
                note.to_string(),
                Style::default()
                    .fg(T.text_muted)
                    .add_modifier(Modifier::ITALIC),
            ));
        }
    }
    Line::from(spans)
}

/// Nav-key legend with caller-supplied copy. Every surface keeps its own
/// input contract across migration (D7′), so the keys it advertises are
/// its own. The retired grid advertised one fixed `←/→` legend for every
/// surface, which is exactly what D7′ makes wrong.
pub fn nav_keys_line(keys: &str) -> Line<'static> {
    Line::from(Span::styled(
        keys.to_string(),
        Style::default().fg(T.text_secondary),
    ))
}

/// What an action does, which decides how it is painted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ActionKind {
    /// The one filled action in the modal.
    Primary,
    /// Destructive. Outlined by colour, never filled.
    Destructive,
    /// Everything else.
    Neutral,
}

/// One action on an Archetype-F / Archetype-C button row.
#[derive(Clone, Debug)]
pub struct Action {
    pub label: String,
    pub focused: bool,
    pub kind: ActionKind,
    /// Contextual one-line help shown while this action holds focus. An
    /// action is a focus target like any row, so it carries its own hint
    /// rather than leaving the tail builder to look it up — see
    /// [`form_tail`].
    pub hint: String,
    /// Activation is declared by the caller; labels never determine behavior.
    pub key: Option<KeyEvent>,
}

impl Action {
    pub fn new(
        label: impl Into<String>,
        focused: bool,
        kind: ActionKind,
        hint: impl Into<String>,
    ) -> Self {
        Self {
            label: label.into(),
            focused,
            kind,
            hint: hint.into(),
            key: None,
        }
    }

    pub fn on_key(mut self, code: KeyCode) -> Self {
        self.key = Some(KeyEvent::new(code, KeyModifiers::NONE));
        self
    }

    pub fn on_save(mut self) -> Self {
        self.key = Some(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL));
        self
    }
}

#[derive(Clone, Debug)]
pub struct ActionHit {
    x: u16,
    width: u16,
    key: KeyEvent,
}

fn action_leading_pad(actions: &[Action], width: u16) -> usize {
    let labels: usize = actions
        .iter()
        .map(|a| crate::tui::text::width(action_label(a)) + 2)
        .sum();
    (width as usize).saturating_sub(labels + actions.len().saturating_sub(1) * 2)
}

fn action_label(action: &Action) -> &str {
    let label = action.label.trim();
    label
        .strip_prefix('[')
        .and_then(|s| s.split_once("] "))
        .map_or(label, |(_, name)| name.trim_start())
}

pub(crate) fn action_hits(actions: &[Action], width: u16) -> Vec<ActionHit> {
    let mut x = action_leading_pad(actions, width);
    let mut hits = Vec::new();
    for action in actions {
        let cells = crate::tui::text::width(action_label(action)) + 2;
        if let Some(key) = action.key {
            if x < width as usize {
                hits.push(ActionHit {
                    x: x as u16,
                    width: cells.min(width as usize - x) as u16,
                    key,
                });
            }
        }
        x += cells + 2;
    }
    hits
}

/// The same clipped button cells used by the painter, in frame coordinates.
pub fn action_regions(actions: &[Action], row: Rect) -> Vec<(Rect, KeyEvent)> {
    action_hits(actions, row.width)
        .into_iter()
        .map(|hit| {
            (
                Rect::new(
                    row.x.saturating_add(hit.x),
                    row.y,
                    hit.width,
                    row.height.min(1),
                )
                .intersection(row),
                hit.key,
            )
        })
        .collect()
}

/// Compact right-aligned buttons. Focus fills the selected button with its
/// action color; resting buttons retain a neutral surface.
pub fn action_row(actions: &[Action], width: u16) -> Line<'static> {
    // The content rectangle already reserves the right gutter.
    let pad = action_leading_pad(actions, width);

    let mut spans: Vec<Span<'static>> = Vec::with_capacity(actions.len() * 3 + 2);
    spans.push(Span::raw(" ".repeat(pad)));
    for (i, a) in actions.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("  "));
        }
        let color = match a.kind {
            ActionKind::Primary => T.warden_teal,
            ActionKind::Destructive => T.red_glow,
            ActionKind::Neutral => T.text_secondary,
        };
        let style = if a.focused {
            Style::default()
                .bg(color)
                .fg(T.text_inverse)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().bg(T.bg_highlight).fg(color)
        };
        spans.push(Span::styled(format!(" {} ", action_label(a)), style));
    }
    Line::from(spans)
}

/// Rows the hint/error region of an Archetype-F tail always occupies.
///
/// Fixed, never content-derived: validation errors routinely run past one
/// row, and a variable count means the whole body shifts the moment an
/// error appears.
pub const HINT_ROWS: usize = 2;

/// Accumulator for an Archetype-F field region.
///
/// Every hand-rolled form in this tree repeats the same four pieces of
/// bookkeeping alongside its rows: push the line, remember *which* index
/// holds focus so the viewport can follow it, remember the focused row's
/// one-line hint so the tail can show it, and remember where the hardware
/// cursor goes. Four parallel `if focused { … }` blocks per field, one
/// chance each to fall out of step.
///
/// [`FormRows`] makes them one call. A row cannot be marked focused
/// without supplying its hint, which is what "per-field guidance is a
/// first-class capability, not a per-consumer convention" means in
/// practice: there is no longer a second `match focus { … }` table to keep
/// in sync with the field list.
pub struct FormRows {
    action_hits: RefCell<Vec<ActionHit>>,
    field_hits: Vec<FieldHit>,
    field_count: usize,
    width: u16,
    value_layout: ValueLayout,
    head: Vec<Line<'static>>,
    lines: Vec<Line<'static>>,
    focus_row: Option<usize>,
    hint: Option<String>,
    cursor: Option<(usize, u16)>,
}

impl FormRows {
    /// Open a form whose head is the standard banded title + description +
    /// spacer. `width` is the *inner* width the rows must fill.
    pub fn new(title: &str, desc: &str, width: u16) -> Self {
        Self {
            action_hits: RefCell::default(),
            field_hits: Vec::new(),
            field_count: 0,
            width,
            value_layout: ValueLayout::default(),
            head: vec![
                title_band(title, width),
                desc_band(desc, width),
                Line::from(""),
            ],
            lines: Vec::with_capacity(32),
            focus_row: None,
            hint: None,
            cursor: None,
        }
    }

    /// [`FormRows::new`] with a two-row description band ([`desc_band2`]) —
    /// the heading carries the explanation, and no section under it does.
    ///
    /// **A separate constructor, not a widened [`FormRows::new`].** Eleven
    /// call sites build a form, and seven of them are surfaces this change
    /// does not own (`group_modal`, `local_dns_modal`, `subnet_modal`,
    /// `tabs/devices`, `tabs/tags` ×3). Changing `new`'s signature would
    /// have made every one of them re-derive its own row-budget floor to
    /// stay honest — the same blast radius that once cost the Devices form
    /// its `Save`, `Cancel` and 9 of 13 fields when its head grew without
    /// re-deriving that budget, and the
    /// same reasoning that made [`TailNote`] a per-call value instead of an
    /// edit to [`HINT_ROWS`].
    ///
    /// ## The row it costs, and where it comes from
    ///
    /// The head goes from 3 rows to **4**. [`scroll_layout`] serves the
    /// tail first and the head second, so at the minimum-terminal floor's
    /// 12 interior rows that row comes straight out of the **field viewport**:
    /// a default-tail surface goes 4 visible field rows → 3, and one
    /// declaring `TailNote { rows: 3, .. }` goes 3 → 2.
    ///
    /// Deleting per-section blurbs does **not** pay this back. Blurbs live
    /// in `fields`, which is the region that scrolls; `view_h` is fixed by
    /// head + tail alone. Dropping them means less scrolling, never a taller
    /// viewport. Re-derive the floor for each surface that adopts this,
    /// from its own `form_tail*` call — a sibling's number does not
    /// transfer.
    pub fn new_desc2(title: &str, desc: [&str; 2], width: u16) -> Self {
        let [d1, d2] = desc_band2(desc, width);
        Self {
            action_hits: RefCell::default(),
            field_hits: Vec::new(),
            field_count: 0,
            width,
            value_layout: ValueLayout::default(),
            head: vec![title_band(title, width), d1, d2, Line::from("")],
            lines: Vec::with_capacity(32),
            focus_row: None,
            hint: None,
            cursor: None,
        }
    }

    /// Match the caret window to rows using explicit value geometry.
    pub fn with_value_layout(mut self, layout: ValueLayout) -> Self {
        self.value_layout = layout;
        self
    }

    /// The inner width rows must be built at — already net of the
    /// scrollbar column when [`render_modal`] decided one is needed.
    pub fn width(&self) -> u16 {
        self.width
    }

    /// The focused row's hint, if a focused row has been pushed.
    pub fn hint(&self) -> Option<&str> {
        self.hint.as_deref()
    }

    /// A labelled section header + its hairline rule.
    pub fn section(&mut self, label: &str) {
        self.lines.extend(section_band(label, self.width));
    }

    pub fn section_with_role(&mut self, label: &str, role: theme::CardRole) {
        self.lines
            .extend(section_band_with_role(label, self.width, role));
    }

    // `section_with_blurb` used to live here:
    // `section()` plus two `text_secondary` rows of per-section prose. It
    // is **deleted**, not deprecated — `profile_modal` was its only
    // consumer, and a `pub` item with no non-test caller fails
    // `clippy --all-targets -D warnings` in this crate (a `cfg(test)`-only
    // consumer does not rescue it; clippy builds the lib target without
    // `cfg(test)`).
    //
    // What replaced it is [`FormRows::new_desc2`]: the same explanatory job
    // done **once, in the heading**, instead of once per section. The
    // operator's report after using the old approach was that five two-row
    // blurbs read as five interruptions of a form they had already understood.
    // The trade in rows is worth stating, because it is not the obvious
    // direction: the blurbs cost 10 rows of `fields` (scrolling, cheap),
    // the band costs 1 row of `head` (pinned, and taken straight out of the
    // floor's field viewport — see [`FormRows::new_desc2`]).

    /// A blank separator row. Truly empty, never whitespace — see
    /// [`render_body_fixed`] for why that distinction is load-bearing.
    pub fn spacer(&mut self) {
        self.lines.push(Line::from(""));
    }

    /// A row that cannot take focus (a state row, a suggestion row).
    pub fn line(&mut self, line: impl Into<Line<'static>>) {
        self.lines.push(line.into());
    }

    /// A focusable row. When `focused`, it becomes the viewport's anchor
    /// and `hint` becomes the tail's guidance.
    pub fn field(&mut self, line: impl Into<FormLine>, focused: bool, hint: &str) {
        let line = line.into();
        self.field_hits.push(FieldHit {
            row: self.lines.len(),
            x: 0,
            width: self.width,
            action: crate::tui::mouse::MouseAction::OverlayField(self.field_count),
        });
        self.field_count += 1;
        if focused {
            self.field_hits
                .extend(line.keys.into_iter().map(|(x, width, code)| FieldHit {
                    row: self.lines.len(),
                    x,
                    width,
                    action: crate::tui::mouse::MouseAction::OverlayKey(KeyEvent::new(
                        code,
                        KeyModifiers::NONE,
                    )),
                }));
        }
        self.lines.push(line.line);
        if focused {
            self.focus_row = Some(self.lines.len() - 1);
            self.hint = Some(hint.to_string());
        }
    }

    pub fn choice_field(&mut self, line: impl Into<FormLine>, focused: bool, hint: &str) {
        let hit = self.field_hits.len();
        let index = self.field_count;
        self.field(line, focused, hint);
        self.field_hits[hit].action = crate::tui::mouse::MouseAction::OverlayChoice(index);
    }

    /// [`FormRows::field`] for a row that hosts the real terminal cursor.
    /// `caret` is the caret's cell offset from the configured value column —
    /// i.e. the visible length of the value being typed.
    pub fn text_field(&mut self, line: Line<'static>, focused: bool, hint: &str, caret: u16) {
        self.field(line, focused, hint);
        if focused {
            // Callers pass the value's full character count — the caret's
            // LOGICAL position. Once [`value_row`] windows an overlong
            // value to its tail, the caret's VISIBLE column stops tracking
            // that: the row shows exactly `value_budget` cells however long
            // the value grows, so the caret belongs at the budget, not at
            // the length.
            //
            // Without the clamp the column keeps climbing past the modal
            // edge and [`ModalRender::place_cursor`] silently declines to
            // set it (`x < self.inner.right()`), so the cursor VANISHES
            // mid-typing — which is the defect, not the truncation. The
            // ellipsis at least announces itself; a missing caret does not.
            let budget = u16::try_from(self.value_layout.budget(self.width)).unwrap_or(u16::MAX);
            self.cursor = Some((self.lines.len() - 1, caret.min(budget)));
        }
    }

    /// Close the form: hand back the [`ScrollBody`] and the cursor target
    /// (field-region row index + caret offset), if any.
    ///
    /// Build `tail` with [`form_tail`] — it needs `&self` for the hint, so
    /// call it before this.
    pub fn finish(self, tail: Vec<Line<'static>>) -> (ScrollBody, Option<(usize, u16)>) {
        (
            ScrollBody {
                action_hits: self.action_hits.into_inner(),
                field_hits: self.field_hits,
                head: self.head,
                fields: self.lines,
                tail,
                focus_row: self.focus_row,
                // Every form has focusable rows by construction, and the
                // ones that momentarily do not (focus parked on an
                // action) get it back on the next Tab.
                scrollable: true,
            },
            self.cursor,
        )
    }
}

/// The standard Archetype-F tail: spacer · [`HINT_ROWS`] of hint-or-error ·
/// nav-key legend · [`action_row`].
///
/// Ordered least-important-first because [`render_scroll_body`] drops the
/// tail from the front when the terminal is short — so guidance goes before
/// controls, and the action row is last and therefore never cut.
///
/// The hint resolves in three steps: the focused **row**'s hint, else the
/// focused **action**'s (an action is a focus target too, and a row-only
/// lookup silently loses Delete / Cancel / Save), else `fallback` — which a
/// surface can use to cover a focus state that renders no row at all, and
/// can otherwise leave `""`.
pub fn form_tail(
    rows: &FormRows,
    error: Option<&str>,
    fallback: &str,
    keys: &str,
    actions: &[Action],
) -> Vec<Line<'static>> {
    form_tail_with_status(rows, None, error, fallback, keys, actions)
}

/// How a surface wants its tail's note region drawn.
///
/// This exists as a **per-call** value rather than as an edit to
/// [`HINT_ROWS`]. Bumping the constant to give one modal a taller help
/// region resizes the region on every Archetype-F modal in `src/tui/` at
/// once, each of which then needs its own row-budget floor re-verified —
/// the exact blast radius that once cost the Devices form its `Save`,
/// `Cancel` and 9 of 13 fields when its head grew without re-deriving
/// that budget. `Default` reproduces the shared
/// behaviour byte for byte, so a surface that says nothing keeps it.
#[derive(Clone, Copy, Debug)]
pub struct TailNote {
    /// Rows the hint / error region occupies. Fixed per surface, never
    /// derived from the current text — see [`HINT_ROWS`].
    pub rows: usize,
    /// Paint the region on `bg_surface` so it reads as its own band, the
    /// way [`section_band`] does. Off by default: a band is worth a
    /// surface's attention budget only where the region is large enough
    /// to be a help *area* rather than a single guidance line.
    pub banded: bool,
}

impl Default for TailNote {
    fn default() -> Self {
        Self {
            rows: HINT_ROWS,
            banded: false,
        }
    }
}

/// [`form_tail`] with the note region's shape spelled out — see
/// [`TailNote`].
pub fn form_tail_with_note(
    rows: &FormRows,
    note: TailNote,
    error: Option<&str>,
    fallback: &str,
    keys: &str,
    actions: &[Action],
) -> Vec<Line<'static>> {
    build_form_tail(rows, note, None, error, fallback, keys, actions)
}

/// [`form_tail`] plus the **transient status slot**: the neutral "we are
/// talking to the config right now" message a submit puts up.
///
/// Archetype F's tail used to offer exactly two states — `error`
/// (`⚠` + error colour) and `hint` (muted italic) — so both Rules modals
/// shipped their `adding…` / `saving…` through the hint, by handing the
/// status to *every* row in place of its own guidance.
/// Two silent losses: the status
/// wore the hint's muted italic instead of a status colour, and the
/// guidance for the field the operator is standing on vanished for the
/// duration of the submit.
///
/// The three states share the [`HINT_ROWS`] region by precedence, and only
/// the first is exclusive:
///
/// | state | rows |
/// |---|---|
/// | `error` | all of them — a validation message routinely runs past one row |
/// | `status` | one row, in `info`; the hint keeps what is left |
/// | neither | the hint, as before |
///
/// An error outranks a status because the two are mutually exclusive in
/// every consumer's submit path anyway, and a stale "saving…" over a
/// failure would be the worse lie.
pub fn form_tail_with_status(
    rows: &FormRows,
    status: Option<&str>,
    error: Option<&str>,
    fallback: &str,
    keys: &str,
    actions: &[Action],
) -> Vec<Line<'static>> {
    build_form_tail(
        rows,
        TailNote::default(),
        status,
        error,
        fallback,
        keys,
        actions,
    )
}

#[allow(clippy::too_many_arguments)] // the three public entry points above
                                     // each drop a parameter; this is the
                                     // union of them, deliberately private.
fn build_form_tail(
    rows: &FormRows,
    note: TailNote,
    status: Option<&str>,
    error: Option<&str>,
    fallback: &str,
    keys: &str,
    actions: &[Action],
) -> Vec<Line<'static>> {
    let width = rows.width();
    *rows.action_hits.borrow_mut() = action_hits(actions, width);
    let hint = rows
        .hint()
        .or_else(|| {
            actions
                .iter()
                .find(|a| a.focused)
                .map(|a| a.hint.as_str())
                .filter(|h| !h.is_empty())
        })
        .unwrap_or(fallback);

    let mut tail: Vec<Line<'static>> = Vec::with_capacity(note.rows + 3);
    tail.push(Line::from(""));
    let mut region = note_rows(width, status, error, hint, note.rows);
    if note.banded {
        region = region.into_iter().map(|l| band_line(l, width)).collect();
    }
    tail.extend(region);
    if !keys.is_empty() {
        tail.push(nav_keys_line(keys));
    }
    tail.push(action_row(actions, width));
    tail
}

/// Lay `line` on a `bg_surface` band, padded out to `width`.
///
/// The padding is the whole job: a `Span`'s background paints only its own
/// characters, so a half-width row bands half a row — the defect
/// `section_band` already pads around, and the reason
/// `a_banded_help_region_paints_the_full_width` measures cells rather than
/// styles.
fn band_line(line: Line<'static>, width: u16) -> Line<'static> {
    let band = Style::default().bg(T.bg_surface);
    let used: usize = line
        .spans
        .iter()
        .map(|s| crate::tui::text::width(&s.content))
        .sum();
    let mut spans: Vec<Span<'static>> = line
        .spans
        .into_iter()
        .map(|s| {
            let style = s.style.bg(T.bg_surface);
            Span::styled(s.content, style)
        })
        .collect();
    let pad = (width as usize).saturating_sub(used);
    if pad > 0 {
        spans.push(Span::styled(" ".repeat(pad), band));
    }
    Line::from(spans)
}

/// The `error` / `status` / `hint` precedence, laid into `max_rows` rows.
/// Always returns exactly `max_rows` lines, so the body above it never
/// shifts as the three states swap.
fn note_rows(
    width: u16,
    status: Option<&str>,
    error: Option<&str>,
    hint: &str,
    max_rows: usize,
) -> Vec<Line<'static>> {
    match status.filter(|s| !s.is_empty()) {
        Some(s) if error.is_none() && max_rows > 0 => {
            let mut rows = vec![Line::from(Span::styled(
                fit(s, width as usize),
                // Its own colour, not the hint's: `info` is the theme's
                // neutral "something is happening" and it is the one
                // affordance that told the operator a submit was in
                // flight before the migration. No italic — that is the
                // hint's signature, and the two now share the region.
                Style::default().fg(T.info),
            ))];
            rows.extend(hint_or_error_rows(None, hint, width, max_rows - 1));
            rows
        }
        _ => hint_or_error_rows(error, hint, width, max_rows),
    }
}

// ── Archetype C (confirm / picker / read-only) ────────────────────────
//
// The gap that kept the Tier-0 overlays bespoke: there had never been a
// shared shape for "not a form", so every confirm and every picker drew
// its own `Borders::ALL` in `brand_red`. Same frame, same title band, same
// surface as Archetype F — no field grid.
//
// Shipped consumers: `scope_modal` (menu + all four confirm stages),
// `resolver_modal`, and the remove-confirm / outcome stages of
// `subnet_modal`, `local_dns_modal`, `profile_modal` and `tabs/rules`.

/// A paragraph row aligned to the modal content edge.
///
/// `kind` is `None` for ordinary prose and `Some(_)` for a line that
/// carries state — the entity being deleted, the count that is about to
/// change — which then renders bold in that state's colour.
///
/// `verbatim` marks the row as a **transcription target**: a string the
/// operator has to reproduce keystroke for keystroke. It wraps instead of
/// being cut. See [`ProseRow::verbatim`].
#[derive(Clone, Debug)]
pub struct ProseRow {
    pub text: String,
    pub kind: Option<ValueKind>,
    /// Wrap rather than ellipsise. Set only by [`ProseRow::verbatim`].
    pub verbatim: bool,
}

impl ProseRow {
    pub fn plain(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            kind: None,
            verbatim: false,
        }
    }

    pub fn emphasis(text: impl Into<String>, kind: ValueKind) -> Self {
        Self {
            text: text.into(),
            kind: Some(kind),
            verbatim: false,
        }
    }

    /// A row whose text must reach the operator **whole** — the id or the
    /// domain a typed-confirm gate compares against.
    ///
    /// Ellipsising such a row does not degrade the screen, it breaks the
    /// gate: `Id::MAX_LEN` is 64 and [`prose_row`] leaves 60 usable cells
    /// at the ecosystem's 64-column modal, so a maximum-length id was cut
    /// to 59 characters plus a `…`. The gate still compared against all
    /// 64, the missing characters were not recoverable from the display,
    /// and nothing on screen said why the confirm would not take. **No
    /// keystroke sequence could satisfy it.**
    ///
    /// So the wrap is not one option among several — 64 > 60 forces it.
    /// The row is never shortened and never marked; it costs whatever
    /// number of lines it costs, and a surface that cannot afford them
    /// must shorten its *other* rows.
    pub fn verbatim(text: impl Into<String>, kind: ValueKind) -> Self {
        Self {
            text: text.into(),
            kind: Some(kind),
            verbatim: true,
        }
    }
}

/// Cells a verbatim row may put on one line.
///
/// A fixed column, deliberately not derived from the passed `width`:
/// [`render_modal`] builds the body at `w` and again at `w - 1` when the
/// scrollbar claims a column, so a width-derived wrap would yield a
/// different row count between the two passes and silently mis-size the
/// modal. Same invariant [`choice_rows`] carries, same reason — pinned by
/// `prose_rows_row_count_never_varies_with_width`.
///
/// 59 is the narrowest interior the ecosystem can hand a [`ProseRow`]: its
/// consumers are all 64 columns or wider: borders and gutters leave 60
/// content cells, then the scrollbar takes one. A notice
/// narrower than 64 would clip — [`render_body_fixed`] does not wrap — so
/// that is the floor this constant encodes.
const VERBATIM_WRAP: usize = 59;

/// How many lines a [`ProseRow`] renders as. A function of the **spec**,
/// never of the width — see [`VERBATIM_WRAP`].
pub fn prose_row_count(row: &ProseRow) -> usize {
    if !row.verbatim {
        return 1;
    }
    row.text
        .chars()
        .count()
        .div_ceil(VERBATIM_WRAP)
        // An empty verbatim row is still a row.
        .max(1)
}

/// Field-region row index of `prose[idx]`, i.e. how many lines the rows
/// before it occupy.
///
/// Callers place the hardware cursor on the row the operator types into,
/// and that index is *not* the prose ordinal once any earlier row wraps.
/// Both typed-id gates used to hardcode it (`TYPED_PROSE_ROW = 2`) or
/// derive it from `prose.len()`, which is the same bug written twice.
/// Width-free by construction, so the index and the render cannot diverge.
pub fn prose_field_row(prose: &[ProseRow], idx: usize) -> usize {
    prose.iter().take(idx).map(prose_row_count).sum()
}

/// Render a [`ProseRow`] as a single line, ellipsised to `width`.
///
/// The fit is why this exists: a deterministic row count, the same reason
/// [`desc_band`] does not wrap. **A verbatim row cannot go through here** —
/// use [`prose_rows`], which is what [`notice_body`] calls.
pub fn prose_row(row: &ProseRow, width: u16) -> Line<'static> {
    Line::from(Span::styled(
        fit(&row.text, width as usize),
        prose_style(row),
    ))
}

/// Render a [`ProseRow`] as **one or more** lines: one ellipsised line for
/// ordinary prose, and for a verbatim row as many wrapped lines as its text
/// needs — never cut, never marked.
///
/// The line count is a function of the spec alone; see [`VERBATIM_WRAP`].
pub fn prose_rows(row: &ProseRow, width: u16) -> Vec<Line<'static>> {
    if !row.verbatim {
        return vec![prose_row(row, width)];
    }
    let style = prose_style(row);
    let chars: Vec<char> = row.text.chars().collect();
    if chars.is_empty() {
        return vec![Line::from(Span::styled(String::new(), style))];
    }
    // A hard character wrap, not a word wrap: a transcription target is
    // reproduced keystroke for keystroke, and breaking on a space would
    // leave the operator guessing whether the space is part of the string.
    chars
        .chunks(VERBATIM_WRAP)
        .map(|chunk| Line::from(Span::styled(chunk.iter().collect::<String>(), style)))
        .collect()
}

fn prose_style(row: &ProseRow) -> Style {
    match row.kind {
        Some(kind) => Style::default()
            .fg(kind.color())
            .add_modifier(Modifier::BOLD),
        None => Style::default().fg(T.text_secondary),
    }
}

/// One option in an Archetype-C list.
///
/// `detail` is the per-option explanation — Archetype C's answer to
/// Archetype F's focus hint, except it is visible for every option at
/// once, which is what a picker needs. It rides the option's own row and
/// is **ellipsised, never dropped**, when the row cannot hold it whole.
///
/// That inverts the original rule ("half an explanation is worth less
/// than a clean row"):
/// at the real 62-column interior a label plus any useful sentence runs
/// past the width, so *every* detail was silently discarded and nothing on
/// screen distinguished "this option has no explanation" from "its
/// explanation did not fit". Every other row vocabulary in this module
/// ellipsises ([`fit`], [`desc_band`], [`hint_or_error_rows`]) precisely
/// because a `…` is self-announcing.
///
/// `note` is the other half: text that gets **an indented row of its
/// own**, unconditionally — see [`choice_rows`] and [`ChoiceNote`].
#[derive(Clone, Debug)]
pub struct ChoiceRow {
    pub label: String,
    pub detail: Option<String>,
    /// What choosing this option *means* — drives its resting colour.
    pub kind: ValueKind,
    pub focused: bool,
    /// The option's own explanation row, if it has one. `None` is a bare
    /// option carrying nothing but its label and whatever inline `detail`
    /// fits.
    ///
    /// The variant decides whether the option is also **unselectable** —
    /// one field rather than a `disabled: bool` beside a reason string,
    /// because "disabled and silent about it" is exactly the state
    /// this type should not be able to express.
    ///
    /// Named `note`, not `reason`, because it holds **two different things**
    /// and only one of them is a reason: [`ChoiceNote::Blocked`] says *why
    /// the option cannot be chosen*, while [`ChoiceNote::Detail`] — which
    /// choosable options also carry — says *what the option does*.
    /// The field was named for the disabled case it started as; once
    /// choosable entries took the same row, "reason" described the minority
    /// of its contents.
    pub note: Option<ChoiceNote>,
}

/// The text under a [`ChoiceRow`], and what it says about the option.
///
/// This widened from a bare reason string to a two-variant
/// note. The **mechanism** — a guaranteed, indented row that never has to
/// win a fight with the label for the width — is unchanged and is the whole
/// point of reusing it: it closed the
/// "detail silently dropped" failure mode by ellipsising inline instead,
/// and shipped the remainder the operator hit next — at a 62-column
/// interior a real label plus a real sentence leaves the sentence about 27
/// cells, so every non-focused option showed a stub. The tail's hint row
/// covered the focused one only.
///
/// So a choosable option now takes the same row a disabled one always had.
/// What it must **not** take is a row whose presence depends on whether the
/// text happened to fit — that is the width-dependent row count
/// [`choice_rows`]'s doc forbids.
#[derive(Clone, Debug)]
pub enum ChoiceNote {
    /// What this option *means*. The option stays choosable.
    Detail(String),
    /// Why this option **cannot** be chosen. Also recesses the label.
    ///
    /// No consumer builds one today. Kept because it is half of the
    /// mechanism [`choice_rows`] documents — a reason is the only thing
    /// on screen that explains an option the operator can see but cannot
    /// pick — and dropping it would take `blocks()` and the label
    /// recession with it, leaving the next picker with an unselectable
    /// option to express and nothing to express it with.
    #[allow(dead_code)]
    Blocked(String),
}

impl ChoiceNote {
    pub fn text(&self) -> &str {
        match self {
            ChoiceNote::Detail(t) | ChoiceNote::Blocked(t) => t,
        }
    }

    /// Whether this note makes its option unselectable.
    pub fn blocks(&self) -> bool {
        matches!(self, ChoiceNote::Blocked(_))
    }
}

/// Cells a [`ChoiceNote`] row may put on one line, after its 2-cell
/// indent.
///
/// A fixed column for the same reason [`VERBATIM_WRAP`] is one, and derived
/// the same way: [`render_modal`] builds the body at `w` and again at
/// `w - 1` once the scrollbar claims a column, so a width-derived wrap
/// would change the row count between the two passes and silently mis-size
/// the modal. A 64-column modal leaves 60 content cells, 59 with a
/// scrollbar, then 57 after the note indent.
const NOTE_WRAP: usize = 57;

/// How many lines a [`ChoiceRow`] renders as. A function of the **spec**
/// alone; pinned by `choice_rows_row_count_never_varies_with_width`.
///
/// `#[cfg(test)]` on purpose: [`choice_rows`] is the only production
/// consumer of the count and it produces the rows themselves, so a second
/// live implementation of the same arithmetic is a second thing to keep in
/// step. The test wants the *independent* statement of the rule.
#[cfg(test)]
fn choice_row_count(row: &ChoiceRow) -> usize {
    1 + row
        .note
        .as_ref()
        .map(|n| crate::tui::text::width(n.text()).div_ceil(NOTE_WRAP).max(1))
        .unwrap_or(0)
}

/// Render a [`ChoiceRow`] as **one or more** lines, with the same focus
/// grammar every ecosystem row uses: inverse text on a blue focus surface.
///
/// The row count is a function of the **spec**, never of `width`: one line
/// for a bare option, plus however many [`NOTE_WRAP`] chunks its `note`
/// costs. [`render_modal`] sizes the modal from a first build pass at
/// `width` and renders a second at `width - 1`, so a count that varied with
/// the width would silently mis-size the modal — see `render_modal`'s doc
/// and `choice_rows_row_count_never_varies_with_width`.
///
/// ## Why an option's explanation gets a whole row
///
/// It started as the disabled case: a
/// reason is the only thing on screen that explains an entry the operator
/// can see but cannot pick, and both affordances that cover a *choosable*
/// option structurally miss it — an inline detail is ellipsised at the
/// interior width (the scope modal's subnet reason wants 77 columns against
/// 62), and the tail's hint row only ever shows the FOCUSED option's copy,
/// while every consumer's cursor skips disabled entries.
///
/// The second half of the same argument: the hint row
/// covers exactly *one* choosable option, so every other one is reading a
/// stub. A picker's whole job is to let the operator compare options they
/// are **not** standing on. So a `ChoiceNote::Detail` buys the same row —
/// same mechanism, same guarantee, one more case (see [`ChoiceNote`]).
///
/// A wider modal is not available: at the declared 80-column floor the
/// modal is already full-bleed. The rows are paid for out of the
/// Archetype-C tail budget (see [`notice_body`]).
pub fn choice_rows(row: &ChoiceRow, width: u16) -> Vec<Line<'static>> {
    let disabled = row.note.as_ref().is_some_and(ChoiceNote::blocks);
    let bar = |s: Style| if row.focused { s.bg(T.info) } else { s };
    // Semantic colour steps aside on the focus bar — see [`ValueKind`].
    // A disabled option recedes to `text_muted`: its kind describes what
    // choosing it would mean, and it cannot be chosen.
    //
    // Deliberately NOT `text_disabled`, which `theme.rs` pins below every
    // contrast threshold on the explicit condition that it "must never
    // carry information the operator has to read" — and the label of an
    // option whose reason references it is exactly that.
    let label_style = bar(if row.focused {
        Style::default()
            .fg(T.text_inverse)
            .add_modifier(Modifier::BOLD)
    } else if disabled {
        Style::default().fg(T.text_muted)
    } else {
        Style::default().fg(row.kind.color())
    });

    let mut spans: Vec<Span<'static>> = Vec::with_capacity(5);
    spans.push(Span::styled(row.label.clone(), label_style));
    let mut used = crate::tui::text::width(&row.label);

    // Focus must not change the detail budget and reflow adjacent choices.
    let detail_budget = (width as usize).saturating_sub(used + 2 + 2);
    if let Some(detail) = row.detail.as_deref().filter(|d| !d.is_empty()) {
        if detail_budget >= MIN_DETAIL_CELLS {
            let shown = fit(detail, detail_budget);
            used += 2 + crate::tui::text::width(&shown);
            spans.push(Span::styled(
                format!("  {shown}"),
                bar(Style::default()
                    .fg(if row.focused {
                        T.text_inverse
                    } else {
                        T.text_muted
                    })
                    .add_modifier(Modifier::ITALIC)),
            ));
        }
    }

    if row.focused {
        let pad = (width as usize).saturating_sub(used);
        if pad > 0 {
            spans.push(Span::styled(" ".repeat(pad), Style::default().bg(T.info)));
        }
    }

    let mut lines = vec![Line::from(spans)];
    if let Some(note) = row.note.as_ref() {
        // Indented one step past the option's own lead so it reads as
        // belonging to the row above rather than as a sibling option.
        //
        // Hard-chunked at a fixed column rather than fitted to `width`:
        // the text is the whole reason this row exists, so it is never
        // cut, and the count must not move between the two build passes.
        let style = Style::default()
            .fg(T.text_muted)
            .add_modifier(Modifier::ITALIC);
        let chars: Vec<char> = note.text().chars().collect();
        if chars.is_empty() {
            lines.push(Line::from(Span::styled(String::new(), style)));
        } else {
            lines.extend(chars.chunks(NOTE_WRAP).map(|chunk| {
                Line::from(Span::styled(
                    format!("  {}", chunk.iter().collect::<String>()),
                    style,
                ))
            }));
        }
    }
    lines
}

/// Below this many cells an inline detail is more ellipsis than text, so
/// [`choice_rows`] omits it rather than rendering `e…`. Not a row-count
/// decision — the option still occupies exactly one line either way.
const MIN_DETAIL_CELLS: usize = 8;

/// An Archetype-C overlay: a question, a list of options, or a rendered
/// result. Feed it to [`notice_body`], then [`render_modal`].
#[derive(Clone, Debug, Default)]
pub struct NoticeSpec {
    pub title: String,
    pub desc: String,
    /// Prose above the options — or the entire body, when there are none.
    pub prose: Vec<ProseRow>,
    pub choices: Vec<ChoiceRow>,
    pub error: Option<String>,
    /// Guidance row. Falls back to the focused action's hint when empty,
    /// same precedence [`form_tail`] uses.
    pub hint: String,
    /// Rows the tail reserves for the hint / error note.
    ///
    /// `None` — the default and the right answer for almost every surface
    /// — reserves [`HINT_ROWS`] whenever the spec has *anything* to say
    /// and **zero** when it has nothing. All-or-nothing on purpose: a
    /// region that resized itself to the current text would move the body
    /// under the operator's cursor the moment a validation error replaced
    /// a one-line hint, which is the defect [`HINT_ROWS`] exists to
    /// prevent on Archetype F.
    ///
    /// `Some(n)` pins it to exactly `n`. Reach for it when a surface knows
    /// its note is one line and needs the other row for content — the
    /// scope menu buys its disabled-reason rows this way. Do **not** pin
    /// `Some(1)` on a surface that can raise a validation error: an error
    /// is routinely longer than one row and would be ellipsised.
    pub hint_rows: Option<usize>,
    /// Nav-key legend copy. The surface keeps its own keying (D7′), so it
    /// states its own keys.
    pub keys: String,
    pub actions: Vec<Action>,
}

/// Build an Archetype-C body: title band, description band, prose, option
/// list, pinned tail. No field grid, no sections.
///
/// **Only the title band, the description and the tail are pinned.** Prose
/// and options share the scrolling region, prose first.
///
/// Prose is caller-controlled and unbounded, so pinning it would let it
/// compete with the options for the 12 interior rows the anchor leaves
/// at the 80×24 floor — and [`scroll_layout`] serves the head before the
/// fields, so three prose rows would render **zero** options while
/// `focus_row` still pointed at one. That failure is silent by
/// construction: nothing panics, and [`will_scroll`] reports `false`
/// because it requires `view_h > 0`, so not even a scrollbar appears. A
/// delete confirm with a two-sentence warning and a blank line is three
/// prose rows. See `notice_body_never_starves_the_option_list_at_the_floor`.
///
/// ## The row budget
///
/// At the minimum-terminal floor the interior is **12 rows**, and
/// Archetype C used to spend **8** of them on chrome: a 3-row head and a
/// 5-row tail whose hint
/// region was fixed at [`HINT_ROWS`] whether or not the surface had
/// anything to put in it. Two structurally blank rows and a spacer, on the
/// tightest budget in the ecosystem.
///
/// It now costs **2 + tail**:
///
/// - **head = 2** — title band, description band. The blank third row is
///   Archetype F's: there it separates the bands from the first
///   [`section_band`], and C has no sections. `scroll_layout` serves the
///   head before the fields, so this is a row back at every size.
/// - **tail = `hint_rows` + 1 + 1** — note region, key legend, action row,
///   each of the last two dropped when its copy is empty. No leading
///   spacer: the tail is dropped front-first under pressure, so a spacer
///   there is the first thing sacrificed anyway, and paying for it costs a
///   row of content at every size that is *not* under pressure.
///
/// A five-option menu with a one-line hint therefore gets **7** field rows
/// where it used to get 4, and **8** when it declines the hint region
/// altogether. That is what pays for the [`ChoiceNote`] rows
/// [`choice_rows`] emits.
pub fn notice_body(spec: &NoticeSpec, width: u16) -> ScrollBody {
    let head = vec![title_band(&spec.title, width), desc_band(&spec.desc, width)];

    let mut fields: Vec<Line<'static>> = spec
        .prose
        .iter()
        .flat_map(|p| prose_rows(p, width))
        .collect();
    let mut field_hits = Vec::new();
    let focus_row = if spec.choices.is_empty() {
        None
    } else {
        if !fields.is_empty() {
            fields.push(Line::from(""));
        }
        // Resolve the focus index by accumulating as rows are pushed, NOT
        // by the choice's ordinal: a disabled option emits two lines, so
        // the two indices diverge and the viewport would follow the wrong
        // row — silently, since nothing panics and the marker still draws.
        let mut focus = None;
        for (index, choice) in spec.choices.iter().enumerate() {
            if !choice.note.as_ref().is_some_and(ChoiceNote::blocks) {
                field_hits.push(FieldHit {
                    row: fields.len(),
                    x: 0,
                    width,
                    action: crate::tui::mouse::MouseAction::OverlayChoice(index),
                });
            }
            if choice.focused {
                focus = Some(fields.len());
            }
            fields.extend(choice_rows(choice, width));
        }
        focus
    };

    let hint = if spec.hint.is_empty() {
        spec.actions
            .iter()
            .find(|a| a.focused)
            .map(|a| a.hint.as_str())
            .unwrap_or("")
    } else {
        spec.hint.as_str()
    };
    let note_rows = spec.hint_rows.unwrap_or({
        if hint.is_empty() && spec.error.is_none() {
            0
        } else {
            HINT_ROWS
        }
    });
    let mut tail = hint_or_error_rows(spec.error.as_deref(), hint, width, note_rows);
    if !spec.keys.is_empty() {
        tail.push(nav_keys_line(&spec.keys));
    }
    if !spec.actions.is_empty() {
        tail.push(action_row(&spec.actions, width));
    }

    ScrollBody {
        action_hits: action_hits(&spec.actions, width),
        field_hits,
        head,
        fields,
        tail,
        focus_row,
        // Prose carries no focus. With no choices there is no focus
        // target in the field region at all, so no keystroke can move the
        // viewport and a scrollbar would be a control nothing operates.
        scrollable: !spec.choices.is_empty(),
    }
}

/// What [`render_modal`] drew, so the caller can finish the job —
/// place a hardware cursor, or measure what landed on screen in a test.
pub struct ModalRender<C> {
    /// The horizontally padded content rect, including heading rows.
    pub inner: Rect,
    /// Where the field viewport ended up.
    pub view: ScrollView,
    /// Whatever the body builder returned alongside its rows — for a form
    /// with a real terminal cursor, `Option<(row, caret)>`.
    pub cursor: C,
}

impl<C> ModalRender<C> {
    /// Put the hardware cursor on field-region row `row`, `col` characters
    /// in from the inner-left edge.
    ///
    /// Silently does nothing when that row is scrolled out of view: left to
    /// itself the cursor would sit on whatever row happens to occupy that
    /// line, which reads as "you are typing here" on a field that is not
    /// even on screen.
    pub fn place_cursor(&self, f: &mut Frame, row: usize, col: u16) {
        if row < self.view.offset || row >= self.view.offset + self.view.view_h {
            return;
        }
        let x = self.inner.x.saturating_add(col);
        let y = self
            .inner
            .y
            .saturating_add((self.view.head_h + row - self.view.offset) as u16);
        if x < self.inner.right() && y < self.inner.bottom() {
            f.set_cursor_position(Position { x, y });
        }
    }
}

/// Render a complete Archetype-F modal: chrome, body, scrollbar, viewport.
/// **This is the entry point for a form** — nothing else in this module
/// needs to be sequenced by hand.
///
/// `build` is called with the inner width and returns the body plus any
/// per-surface payload (typically the cursor target from
/// [`FormRows::finish`]). It may be called **twice**, which is the whole
/// reason this function exists:
///
/// 1. once at the nominal inner width, to measure how tall the body wants
///    to be — the modal asks the anchor for exactly that, and
///    `overlay::centered_rect` clamps it down if the anchor is shorter;
/// 2. again one column narrower **iff** the clamped height means the field
///    region scrolls, because the scrollbar claims the last column and rows
///    built at the full width would collide with it.
///
/// That bookkeeping used to live in [`will_scroll`]'s doc as an instruction
/// to the caller. Twelve callers each remembering it is twelve chances to
/// get it wrong, silently, in a way only a real terminal shows.
///
/// The border accent is not a parameter: chrome stays neutral grey under
/// the ecosystem colour rule, and `brand_red` never becomes a modal border.
pub fn render_modal<C>(
    f: &mut Frame,
    anchor: Rect,
    width: u16,
    build: impl Fn(u16) -> (ScrollBody, C),
) -> ModalRender<C> {
    let nominal_w = width.min(anchor.width).saturating_sub(4);
    let (body, payload) = build(nominal_w);
    let total = body.head.len() + body.fields.len() + body.tail.len();
    let h = (total as u16).saturating_add(2);
    let surface = render_chrome_in(f, anchor, width, h, "", T.text_primary, true);
    let inner = content_rect(surface);

    let scrolls = body.scrollable
        && will_scroll(
            inner.height as usize,
            body.head.len(),
            body.fields.len(),
            body.tail.len(),
        );
    let target_w = if scrolls {
        inner.width.saturating_sub(1)
    } else {
        inner.width
    };
    let (body, payload) = if target_w == nominal_w {
        (body, payload)
    } else {
        build(target_w)
    };

    let view = render_scroll_body(f, inner, &body);
    ModalRender {
        inner,
        view,
        cursor: payload,
    }
}

fn push_row_lead(spans: &mut Vec<Span<'static>>, _focused: bool, label: &str, label_style: Style) {
    spans.push(Span::styled(
        format!(
            "{}  ",
            crate::tui::text::pad(&fit(label, GRID_LABEL_W), GRID_LABEL_W)
        ),
        label_style,
    ));
}

/// Validation row for a fixed-height body: the pending error (`⚠ …`) if
/// any, else a muted hint, hard-wrapped to at most `max_rows` lines of
/// `width` cells and padded out to exactly that many rows.
///
/// Two properties a single-line validation row cannot give a non-wrapping
/// body — and the reason the single-line variant is retired: an error
/// longer than one row stays readable instead of being
/// silently cut mid-word, and the row count is constant, so the rest of
/// the modal never shifts when an error appears.
///
/// A refusal's own way out, as opposed to prose that merely mentions a
/// verb.
///
/// Narrow on purpose. `TAG_RENAME_BOTH_DECLARED`'s closing sentence —
/// "warden label remove refuses while any entity still carries that
/// tag…" — also starts with "warden ", so `starts_with` alone would
/// promote description ahead of the very commands it describes. Every
/// recovery command in this convention carries a flag (`--kind`, `--url`,
/// …); closing prose never does, so requiring both is what tells the two
/// apart.
fn is_recovery_command(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("warden ") && t.contains(" --")
}

/// Move a refusal's own recovery commands directly after its lead
/// sentence, ahead of supporting detail the operator does not need to
/// act on — `tui-modal-truncates-multiline-refusal`.
///
/// A fixed row budget and an unbounded refusal cannot both be honoured,
/// so something is always cut; this decides WHAT survives instead of
/// leaving it to source order. `TAG_RENAME_BOTH_DECLARED` is the case
/// that forced it: its two `warden label remove …` commands are the only
/// way out of the collision, and source order put them last — behind two
/// declaration rows and a closing sentence — so at any budget short of
/// the full 13 wrapped rows the operator got prose, never the exit.
///
/// Identity when nothing looks like a command, so every other caller of
/// [`hint_or_error_rows`] keeps its exact existing behaviour — this is
/// reached only by a refusal already shaped like one.
fn prioritize_recovery_commands(lines: Vec<&str>) -> Vec<&str> {
    let mut commands = Vec::new();
    let mut rest = Vec::new();
    for line in lines {
        if is_recovery_command(line) {
            commands.push(line);
        } else {
            rest.push(line);
        }
    }
    if commands.is_empty() {
        return rest;
    }
    let mut out = Vec::with_capacity(rest.len() + commands.len());
    if let Some((lead, tail)) = rest.split_first() {
        out.push(*lead);
        out.extend(commands);
        out.extend(tail);
    } else {
        out.extend(commands);
    }
    out
}

/// The last kept row is ellipsised if the text still does not fit, so a
/// truncated message always *looks* truncated.
pub fn hint_or_error_rows(
    error: Option<&str>,
    hint: &str,
    width: u16,
    max_rows: usize,
) -> Vec<Line<'static>> {
    let (text, style) = match error {
        Some(err) => (format!("\u{26a0} {err}"), Style::default().fg(T.error)),
        None => (
            hint.to_string(),
            Style::default()
                .fg(T.text_muted)
                .add_modifier(Modifier::ITALIC),
        ),
    };

    let usable = (width as usize).max(1);

    // `tui-modal-truncates-multiline-refusal`: a fixed row budget and an
    // unbounded refusal can never both be honoured, so cutting is a given.
    // What used to decide WHAT survives was source order — the same order
    // a CLI verb picks for a reader who can scroll a whole terminal, not
    // for a fixed N-row region. Only an ERROR gets re-keyed: a hint is
    // guidance, never a multi-command refusal, and re-keying it would risk
    // the very regression this fix is for — see `hint_or_error_rows`'s
    // sibling paths below for why hints and errors already diverge.
    let logical: Vec<&str> = text.split('\n').collect();
    let logical = if error.is_some() {
        prioritize_recovery_commands(logical)
    } else {
        logical
    };

    // wrap each SOURCE LINE, not the message as one run.
    //
    // A refusal composed by a CLI verb carries `\n` — `TAG_RENAME_BOTH_DECLARED`
    // is seven lines, two of them the recovery commands. To ratatui those
    // are ordinary characters inside a `Span`, not breaks, so the whole
    // thing arrived as one long run and its structure was lost before the
    // truncation even got to it. Splitting first means an indented command
    // line stays its own row.
    let wrapped: Vec<String> = logical
        .into_iter()
        .flat_map(|line| crate::tui::text::wrap(line, usable))
        .collect();

    let mut rows: Vec<Line<'static>> = Vec::with_capacity(max_rows);
    // Only an ERROR names its residual. A hint is guidance the operator
    // can already act without, and its abbreviation is not a loss worth a
    // sentence — whereas the sentence itself is long enough to displace
    // the very guidance it would be describing, which is how it broke
    // `transient_status_has_its_own_slot_and_the_focus_guidance_survives`
    // on the first attempt. "Run it in the CLI" is also simply false
    // advice for a focus hint.
    let truncated = wrapped.len() > max_rows;
    let overflows = error.is_some() && truncated;
    for (i, chunk) in wrapped.iter().enumerate() {
        if rows.len() >= max_rows {
            break;
        }
        let last_row = rows.len() + 1 == max_rows;
        let text = if last_row && truncated && !overflows {
            // A hint keeps the bare marker it always had: something was
            // cut, and for guidance that is all the operator needs.
            let keep = usable.saturating_sub(1);
            let head = crate::tui::text::fit(chunk, keep);
            format!("{head}\u{2026}")
        } else if last_row && overflows {
            // STATE the residual, do not merely mark it. A bare `…` says
            // "something was cut" and leaves the operator with no way to
            // judge whether the part they need is in the missing piece —
            // for this refusal the missing piece is both recovery
            // commands. A fixed region with
            // the remainder named rather than hidden.
            let dropped = wrapped.len() - i;
            // Names a way OUT, not just a fact. An operator who cannot see
            // the recovery commands needs to know where they are, and the
            // CLI prints this same refusal in full.
            let tail = format!("\u{2026} +{dropped} more \u{2014} run in the CLI to read it all");
            if crate::tui::text::width(&tail) >= usable {
                tail
            } else {
                let keep = usable - crate::tui::text::width(&tail);
                let head = crate::tui::text::fit(chunk, keep);
                format!("{head}{tail}")
            }
        } else {
            chunk.clone()
        };
        rows.push(Line::from(Span::styled(text, style)));
    }

    // Pad with EMPTY lines, never whitespace-only ones — see
    // `render_body_fixed`'s doc for why that distinction matters.
    while rows.len() < max_rows {
        rows.push(Line::from(String::new()));
    }
    rows
}

/// Wrap a complete error for a scrollable modal body without truncating it.
pub fn scrollable_error_rows(error: &str, width: u16) -> Vec<Line<'static>> {
    let usable = usize::from(width).max(1);
    error
        .split('\n')
        .flat_map(|line| crate::tui::text::wrap(line, usable))
        .map(|line| Line::styled(line, Style::default().fg(T.error)))
        .collect()
}

// ── internals ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_recovery_command_requires_both_the_verb_and_a_flag() {
        assert!(is_recovery_command(
            "  warden label remove adverts --kind tag   # keep it"
        ));
        // `TAG_RENAME_BOTH_DECLARED`'s own closing sentence: starts with
        // "warden " too, but carries no flag. Promoting this ahead of the
        // declaration detail would be wrong — it is not a way out, it is
        // a fact about the verb the operator has not typed yet.
        assert!(!is_recovery_command(
            "warden label remove refuses while any entity still carries that tag."
        ));
        assert!(!is_recovery_command("some other prose entirely"));
    }

    #[test]
    fn prioritize_recovery_commands_moves_the_command_after_the_lead_line_only() {
        let lines = vec![
            "lead sentence",
            "declaration row one",
            "declaration row two",
            "  warden label remove x --kind tag   # do it",
            "closing prose",
        ];
        let out = prioritize_recovery_commands(lines);
        assert_eq!(
            out,
            vec![
                "lead sentence",
                "  warden label remove x --kind tag   # do it",
                "declaration row one",
                "declaration row two",
                "closing prose",
            ]
        );
    }

    #[test]
    fn prioritize_recovery_commands_is_identity_when_nothing_looks_like_a_command() {
        let lines = vec!["one", "two", "three"];
        assert_eq!(prioritize_recovery_commands(lines.clone()), lines);
    }

    fn flatten(lines: &[Line<'static>]) -> String {
        lines
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Total cells a row's spans occupy. A `Span`'s background paints only
    /// its own characters, so a band whose spans sum to fewer than the
    /// inner width leaves its tail on the modal surface instead.
    fn row_cells(line: &Line<'static>) -> usize {
        line.spans
            .iter()
            .map(|s| crate::tui::text::width(&s.content))
            .sum()
    }

    #[test]
    fn title_band_fills_the_width_with_the_navigation_red_background() {
        let line = title_band("Edit client", 60);
        assert_eq!(row_cells(&line), 60);
        assert_eq!(
            line.style.bg,
            Some(T.modal_heading_style(false).bg.unwrap())
        );
        assert_eq!(line.style.fg, Some(T.navigation_active_fg));
        let text = flatten(std::slice::from_ref(&line));
        assert!(text.starts_with("EDIT CLIENT"));
        assert!(!text.contains('▌'));
    }

    #[test]
    fn desc_band_truncates_an_overlong_description() {
        let line = desc_band(&"d".repeat(200), 40);
        assert_eq!(row_cells(&line), 40);
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(
            text.contains('\u{2026}'),
            "overlong description gets an ellipsis"
        );
    }

    /// A modal narrower than a band's fixed prefix must not make the band
    /// *wider* than the width it was given — over-filling shifts or clips
    /// the rest of the body.
    #[test]
    fn bands_never_exceed_a_degenerate_width() {
        for w in 0u16..6 {
            assert!(
                row_cells(&title_band("EDIT CLIENT", w)) <= w as usize,
                "title_band overflows at width {w}"
            );
            assert!(
                row_cells(&desc_band("some description", w)) <= w as usize,
                "desc_band overflows at width {w}"
            );
        }
    }

    #[test]
    fn title_band_truncates_an_overlong_title() {
        let line = title_band("A".repeat(200).as_str(), 30);
        assert_eq!(row_cells(&line), 30);
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains('\u{2026}'), "overlong title gets an ellipsis");
    }

    #[test]
    fn subtitle_band_fills_the_width_in_the_coordinated_red_tone() {
        let line = desc_band("Change the profile and metadata.", 60);
        assert_eq!(row_cells(&line), 60);
        assert_eq!(line.style.bg, Some(T.navigation_submenu_bg));
        assert_eq!(line.style.fg, Some(T.text_primary));
    }

    #[test]
    fn section_rule_uses_coloured_text_without_a_background_band() {
        let [section, spacer] = section_band("Identity", 40);
        let text = flatten(std::slice::from_ref(&section));
        assert!(text.contains("IDENTITY") && text.contains('─'));
        assert!(section.spans.iter().all(|span| span.style.bg.is_none()));
        assert!(
            spacer.spans.is_empty(),
            "the section leaves one compact spacer row"
        );
    }

    #[test]
    fn selected_actions_are_compact_background_buttons_without_arrows() {
        let line = action_row(
            &[
                Action::new("Cancel", false, ActionKind::Neutral, "discard"),
                Action::new("Save", true, ActionKind::Primary, "write"),
            ],
            40,
        );
        let text = flatten(std::slice::from_ref(&line));
        assert!(!text.contains('▌') && !text.contains('◀'));
        let save = line
            .spans
            .iter()
            .find(|span| span.content.contains("Save"))
            .expect("Save action is rendered");
        assert_eq!(save.style.bg, Some(T.warden_teal));
    }

    #[test]
    fn editable_value_focus_uses_blue_without_coloring_the_label() {
        use ratatui::{buffer::Buffer, widgets::Widget};
        let area = Rect::new(0, 0, 50, 1);
        let mut buffer = Buffer::empty(area);
        value_row("Name", "Device", true, ValueKind::Editable, None, 50).render(area, &mut buffer);
        assert_eq!(buffer[(2, 0)].bg, ratatui::style::Color::Reset);
        assert_eq!(buffer[(VALUE_COL as u16, 0)].bg, T.info);
        assert_eq!(buffer[(VALUE_COL as u16, 0)].fg, T.text_inverse);
        value_row("Name", "Device", false, ValueKind::Editable, None, 50).render(area, &mut buffer);
        assert_eq!(buffer[(VALUE_COL as u16, 0)].bg, T.bg_highlight);
    }

    #[test]
    fn short_inline_forms_keep_their_actions_at_the_bottom() {
        use ratatui::{backend::TestBackend, Terminal};
        let mut rows = FormRows::new("EDIT", "Details", 50);
        rows.field(
            value_row("Name", "Device", true, ValueKind::Editable, None, 50),
            true,
            "",
        );
        let tail = form_tail(
            &rows,
            None,
            "",
            "",
            &[
                Action::new("[Esc] Discard", false, ActionKind::Neutral, "").on_key(KeyCode::Esc),
                Action::new("[Enter] Save", false, ActionKind::Primary, "").on_save(),
            ],
        );
        let (body, _) = rows.finish(tail);
        let mut terminal = Terminal::new(TestBackend::new(50, 24)).unwrap();
        terminal
            .draw(|frame| {
                render_scroll_body(frame, frame.area(), &body);
            })
            .unwrap();
        let last: String = (0..50)
            .map(|x| terminal.backend().buffer()[(x, 23)].symbol())
            .collect();
        assert!(last.contains("Discard") && last.contains("Save"), "{last}");
        assert!(!last.contains("[Esc]") && !last.contains("[Enter]"));
    }

    #[test]
    fn both_subtitle_rows_fill_the_same_heading_band() {
        for line in desc_band2(["First line", "Second"], 60) {
            assert_eq!(row_cells(&line), 60);
            assert_eq!(line.style.bg, Some(T.navigation_submenu_bg));
            assert_eq!(line.style.fg, Some(T.text_primary));
        }
    }

    #[test]
    fn all_palette_heading_pairs_meet_text_contrast() {
        use crate::tui::theme::{self, CardRole, ThemePreset};
        struct RestorePreset(ThemePreset);
        impl Drop for RestorePreset {
            fn drop(&mut self) {
                theme::set_active(self.0);
            }
        }
        let _restore = RestorePreset(theme::active_preset());
        for preset in ThemePreset::ALL {
            theme::set_active(preset);
            for (fg, bg) in [
                (
                    T.navigation_active_fg,
                    T.modal_heading_style(false).bg.unwrap(),
                ),
                (T.text_primary, T.navigation_submenu_bg),
            ] {
                assert!(
                    theme::contrast_ratio(fg, bg).unwrap() >= 4.5,
                    "{} modal heading contrast",
                    preset.name()
                );
            }
            for role in [CardRole::Summary, CardRole::Analytics, CardRole::History] {
                assert!(
                    theme::contrast_ratio(T.text_inverse, T.card_title_bg(role)).unwrap() >= 4.5,
                    "{} {:?} title contrast",
                    preset.name(),
                    role
                );
                assert!(
                    theme::contrast_ratio(T.text_primary, T.card_subtitle_bg(role)).unwrap() >= 4.5,
                    "{} {:?} subtitle contrast",
                    preset.name(),
                    role
                );
            }
        }
    }

    /// The row count comes from the spec, never from the width — the same
    /// invariant `choice_rows_row_count_never_varies_with_width` holds for
    /// choices. An empty second line still costs its row.
    #[test]
    fn desc_band2_is_always_two_rows_at_every_width() {
        for w in [0u16, 1, 5, 40, 200] {
            let lines = desc_band2(["a description that is fairly long", ""], w);
            assert_eq!(lines.len(), 2, "row count varied at width {w}");
            for line in &lines {
                assert!(
                    row_cells(line) <= w as usize,
                    "desc_band2 overflows at width {w}"
                );
            }
        }
    }

    #[test]
    fn desc_band2_truncates_an_overlong_row() {
        let lines = desc_band2([&"d".repeat(200), "short"], 40);
        assert_eq!(row_cells(&lines[0]), 40);
        let text: String = lines[0].spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(
            text.contains('\u{2026}'),
            "an overlong row gets an ellipsis"
        );
    }

    /// The one row this costs, pinned where it is spent. `scroll_layout`
    /// serves the head before the fields, so a fourth head row comes
    /// straight out of the field viewport at the minimum-terminal floor.
    #[test]
    fn new_desc2_head_is_one_row_taller_than_new() {
        let plain = FormRows::new("EDIT", "d", 60).finish(vec![]).0;
        let two = FormRows::new_desc2("EDIT", ["d1", "d2"], 60)
            .finish(vec![])
            .0;
        assert_eq!(plain.head.len(), 3, "title band + desc band + spacer");
        assert_eq!(
            two.head.len(),
            4,
            "title band + TWO desc rows + spacer — if this is 3 the second \
             description row is being dropped, not rendered"
        );
        // The trailing spacer separates the head from the first section
        // band; losing it would butt the copy against the section header.
        assert_eq!(
            two.head[3].spans.len(),
            0,
            "the head still ends in a spacer"
        );
    }

    /// A modal over the list column keeps the adjacent detail visible.
    #[test]
    fn modal_horizontal_center_uses_the_anchor_column() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut term = Terminal::new(TestBackend::new(100, 30)).unwrap();
        let mut inner = Rect::default();
        term.draw(|f| {
            let anchor = Rect::new(0, 0, 60, 30);
            inner = render_chrome_in(f, anchor, 40, 10, " T ", T.text_primary, false);
        })
        .unwrap();
        // Centred in the 60-wide anchor → box x = (60-40)/2 = 10, so the
        // inner rect starts at 11. Centred on the 100-wide frame it would
        // have been (100-40)/2 = 30.
        assert_eq!(inner.x, 11, "anchor, not frame, decides the centring");
        assert_eq!(inner.width, 38);
    }

    #[test]
    fn modal_centers_vertically_on_the_terminal_within_content_bounds() {
        use ratatui::{backend::TestBackend, Terminal};
        let mut terminal = Terminal::new(TestBackend::new(164, 46)).unwrap();
        terminal
            .draw(|frame| {
                let inner = render_chrome_in(
                    frame,
                    Rect::new(0, 7, 164, 37),
                    68,
                    26,
                    "",
                    T.text_primary,
                    true,
                );
                assert_eq!(inner.y, 11);
            })
            .unwrap();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| {
                let inner = render_chrome_in(
                    frame,
                    Rect::new(0, 4, 80, 18),
                    68,
                    26,
                    "",
                    T.text_primary,
                    true,
                );
                assert!(inner.y >= 5 && inner.bottom() <= 21);
            })
            .unwrap();
    }

    /// With `title_in_band` the border must carry no title — the caller
    /// draws it as the first body row instead.
    #[test]
    fn render_chrome_in_omits_the_border_title_when_banded() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut term = Terminal::new(TestBackend::new(60, 20)).unwrap();
        term.draw(|f| {
            let a = f.area();
            render_chrome_in(f, a, 40, 10, " EDIT CLIENT ", T.text_primary, true);
        })
        .unwrap();
        let dump: String = term
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(
            !dump.contains("EDIT CLIENT"),
            "banded chrome draws no border title"
        );
    }

    /// The banded and unbanded paths must agree on geometry — only the
    /// border title differs, so a caller can switch modes without the
    /// body silently shifting.
    #[test]
    fn render_chrome_in_geometry_is_identical_with_and_without_the_band() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut term = Terminal::new(TestBackend::new(80, 30)).unwrap();
        let (mut banded, mut titled) = (Rect::default(), Rect::default());
        term.draw(|f| {
            let a = f.area();
            banded = render_chrome_in(f, a, 60, 27, " X ", T.text_primary, true);
        })
        .unwrap();
        term.draw(|f| {
            let a = f.area();
            titled = render_chrome_in(f, a, 60, 27, " X ", T.text_primary, false);
        })
        .unwrap();
        assert_eq!(banded, titled);
    }

    // ── The form builder ─────────────────────────────────────────────

    /// The load-bearing invariant: a scrolling body must be REBUILT one
    /// column narrower, because the scrollbar paints over the last column
    /// either way. This used to be an instruction in `will_scroll`'s doc
    /// that every caller had to remember.
    #[test]
    fn modal_padding_aligns_headings_sections_labels_and_pointer_targets() {
        use crate::tui::mouse::{self, MouseAction};
        use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};
        use ratatui::{backend::TestBackend, Terminal};

        for height in [12, 32] {
            let mut app = crate::tui::app::App::new();
            app.devices.inspect_open = true;
            let mut terminal = Terminal::new(TestBackend::new(80, height)).unwrap();
            let mut content = Rect::default();
            let mut field_y = 0;
            terminal
                .draw(|f| {
                    let rendered = render_modal(f, f.area(), 64, |width| {
                        let mut rows = FormRows::new("TITLE", "Description", width);
                        rows.section("SECTION");
                        rows.text_field(
                            value_row("Name", "typed", true, ValueKind::Editable, None, width),
                            true,
                            "",
                            5,
                        );
                        let actions =
                            [Action::new("Save", true, ActionKind::Primary, "").on_save()];
                        let tail = form_tail(&rows, None, "", "", &actions);
                        rows.finish(tail)
                    });
                    content = rendered.inner;
                    if let Some((row, caret)) = rendered.cursor {
                        field_y =
                            content.y + (rendered.view.head_h + row - rendered.view.offset) as u16;
                        rendered.place_cursor(f, row, VALUE_COL as u16 + caret);
                    }
                })
                .unwrap();
            let buffer = terminal.backend().buffer();
            assert_eq!(content.x, 10);
            assert_eq!(content.width, 60);
            assert_eq!(buffer[(content.x, content.y)].symbol(), "T");
            assert_eq!(buffer[(content.x - 1, content.y)].symbol(), " ");
            assert_eq!(
                buffer[(content.x - 1, content.y)].bg,
                T.modal_heading_style(false).bg.unwrap()
            );
            assert_eq!(
                buffer[(content.right(), content.y)].bg,
                T.modal_heading_style(false).bg.unwrap()
            );
            assert_eq!(buffer[(content.x, field_y)].symbol(), "N");
            assert_eq!(buffer[(content.x - 1, field_y)].bg, T.bg_elevated);
            assert_eq!(buffer[(content.x + VALUE_COL as u16, field_y)].bg, T.info);
            assert_eq!(
                terminal.get_cursor_position().unwrap().x,
                content.x + VALUE_COL as u16 + 5
            );
            let click = |x, y| MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: x,
                row: y,
                modifiers: KeyModifiers::NONE,
            };
            assert_eq!(
                mouse::action(&app, click(content.x, field_y)),
                Some(MouseAction::OverlayField(0))
            );
            assert_eq!(mouse::action(&app, click(content.x - 1, field_y)), None);
        }
    }

    #[test]
    fn close_footer_only_activates_its_painted_button() {
        use crate::tui::mouse::{self, MouseAction};
        use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};
        use ratatui::{backend::TestBackend, Terminal};
        let mut app = crate::tui::app::App::new();
        app.devices.inspect_open = true;
        let mut terminal = Terminal::new(TestBackend::new(40, 14)).unwrap();
        let mut footer = Rect::default();
        terminal
            .draw(|f| {
                let surface = render_chrome_in(f, f.area(), 32, 12, "", T.text_primary, true);
                let content = render_header(f, surface, "DETAILS", "Description");
                footer = Rect::new(content.x, content.bottom() - 1, content.width, 1);
                close_footer(f, content);
            })
            .unwrap();
        let click = |x| MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: x,
            row: footer.y,
            modifiers: KeyModifiers::NONE,
        };
        let close = KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE);
        assert_eq!(
            mouse::action(&app, click(footer.right() - 2)),
            Some(MouseAction::OverlayKey(close))
        );
        assert_eq!(mouse::action(&app, click(footer.right())), None);
        assert_eq!(mouse::action(&app, click(footer.x)), None);
    }

    #[test]
    fn render_modal_rebuilds_narrower_only_when_the_field_region_scrolls() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        use std::cell::RefCell;

        let widths: RefCell<Vec<u16>> = RefCell::new(Vec::new());
        let build = |w: u16| {
            widths.borrow_mut().push(w);
            (
                ScrollBody {
                    action_hits: Vec::new(),
                    field_hits: Vec::new(),
                    head: vec![Line::from("HEAD")],
                    fields: (0..20).map(|i| Line::from(format!("F{i}"))).collect(),
                    tail: vec![Line::from("BUTTONS")],
                    focus_row: Some(0),
                    scrollable: true,
                },
                (),
            )
        };

        // Room for all 22 rows → no scrollbar → built once, at full width.
        let mut term = Terminal::new(TestBackend::new(80, 40)).unwrap();
        term.draw(|f| {
            render_modal(f, f.area(), 64, build);
        })
        .unwrap();
        assert_eq!(*widths.borrow(), vec![60], "no scroll → one pass");

        // Clamped to a short anchor → scrolls → rebuilt one narrower.
        widths.borrow_mut().clear();
        let mut term = Terminal::new(TestBackend::new(80, 10)).unwrap();
        term.draw(|f| {
            render_modal(f, f.area(), 64, build);
        })
        .unwrap();
        assert_eq!(
            *widths.borrow(),
            vec![60, 59],
            "scroll → second pass reserves the scrollbar column"
        );
    }

    #[test]
    fn form_rows_records_the_focused_row_its_hint_and_the_caret() {
        let mut rows = FormRows::new("EDIT", "a description", 60);
        rows.section("Identity");
        rows.line(value_row("id", "x1", false, ValueKind::Identity, None, 60));
        rows.text_field(
            value_row("name", "abc", true, ValueKind::Editable, None, 60),
            true,
            "the name shown in dashboards",
            3,
        );
        assert_eq!(rows.hint(), Some("the name shown in dashboards"));
        let (body, cursor) = rows.finish(Vec::new());
        // section header + rule + id + name
        assert_eq!(body.fields.len(), 4);
        assert_eq!(body.focus_row, Some(3), "focus follows the pushed row");
        assert_eq!(cursor, Some((3, 3)));
        assert_eq!(body.head.len(), 3, "title band + desc band + spacer");
    }

    /// An action is a focus target like any row. A row-only hint lookup
    /// silently loses Delete / Cancel / Save — and nothing renders the
    /// hint text into an assertable buffer, so that would ship green.
    #[test]
    fn form_tail_falls_back_to_the_focused_actions_hint() {
        let mut rows = FormRows::new("EDIT", "d", 60);
        rows.line(value_row("id", "x1", false, ValueKind::Identity, None, 60));
        let actions = [
            Action::new(
                "  Cancel  ",
                false,
                ActionKind::Neutral,
                "discard and close",
            ),
            Action::new("  Save  ", true, ActionKind::Primary, "write the changes"),
        ];
        let tail = form_tail(&rows, None, "", "Esc cancel", &actions);
        assert!(
            flatten(&tail).contains("write the changes"),
            "focused action's hint must reach the tail: {}",
            flatten(&tail)
        );
        // The action row is last, so a squeezed tail loses guidance first.
        let last: String = tail
            .last()
            .unwrap()
            .spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect();
        assert!(last.contains("Save") && last.contains("Cancel"));
    }

    #[test]
    fn form_tail_prefers_the_focused_row_over_the_focused_action() {
        let mut rows = FormRows::new("EDIT", "d", 60);
        rows.field(
            value_row("name", "abc", true, ValueKind::Editable, None, 60),
            true,
            "row hint wins",
        );
        let actions = [Action::new(
            "  Save  ",
            true,
            ActionKind::Primary,
            "action hint",
        )];
        let tail = form_tail(&rows, None, "fallback", "Esc", &actions);
        let text = flatten(&tail);
        assert!(text.contains("row hint wins"), "{text}");
        assert!(!text.contains("action hint"), "{text}");
        assert!(!text.contains("fallback"), "{text}");
    }

    // ── Archetype C ──────────────────────────────────────────────────

    fn choice(label: &str, detail: Option<&str>, focused: bool) -> ChoiceRow {
        ChoiceRow {
            label: label.to_string(),
            detail: detail.map(str::to_string),
            kind: ValueKind::Identity,
            focused,
            note: None,
        }
    }

    /// A choosable option is one line, so this is the honest reading of
    /// `choice_rows` in the tests that only care about the first.
    fn choice_line(row: &ChoiceRow, width: u16) -> Line<'static> {
        let lines = choice_rows(row, width);
        assert_eq!(lines.len(), 1, "expected a choosable, single-line option");
        lines.into_iter().next().unwrap()
    }

    /// The defining property of Archetype C: no field grid. The `│` column
    /// separator and the `┬`/`┴` rules that Archetype-F's legacy grid draws
    /// must be absent, and the title band + action row must still be there.
    #[test]
    fn notice_body_draws_no_field_grid() {
        let spec = NoticeSpec {
            title: "Delete list".into(),
            desc: "This cannot be undone.".into(),
            prose: vec![ProseRow::emphasis("privacy-ads", ValueKind::Blocking)],
            choices: vec![choice("Delete", None, true), choice("Keep", None, false)],
            keys: "↑↓ move · Enter confirm".into(),
            actions: vec![Action::new(
                "  Cancel  ",
                false,
                ActionKind::Neutral,
                "close",
            )],
            ..NoticeSpec::default()
        };
        let body = notice_body(&spec, 60);
        let all = flatten(&[body.head.clone(), body.fields.clone(), body.tail.clone()].concat());
        assert!(!all.contains('\u{2502}'), "no grid separator:\n{all}");
        assert!(!all.contains('\u{252c}') && !all.contains('\u{2534}'));
        assert!(all.contains("DELETE LIST") && all.contains("privacy-ads"));
        assert!(all.contains("Cancel"), "action row present");
    }

    /// Prose and options share the scrolling region, prose first; only the
    /// title band, description and tail are pinned.
    #[test]
    fn notice_body_scrolls_the_prose_and_the_options_but_never_the_title() {
        let base = NoticeSpec {
            title: "Pick one".into(),
            desc: "d".into(),
            prose: vec![ProseRow::plain("some context")],
            ..NoticeSpec::default()
        };

        let picker = NoticeSpec {
            choices: vec![choice("A", None, false), choice("B", None, true)],
            ..base.clone()
        };
        let body = notice_body(&picker, 60);
        // 1 prose + 1 separator + 2 options — all in the scrolling region.
        assert_eq!(body.fields.len(), 4, "prose and options scroll together");
        assert_eq!(
            body.focus_row,
            Some(3),
            "focus index is resolved against the prose in front of it"
        );
        assert!(
            flatten(&body.fields).contains("some context"),
            "prose leads the scrolling region, it is not pinned"
        );
        // Two, not three: the blank row belongs to Archetype F, where it
        // separates the bands from the first section band, and C has no
        // sections.
        assert_eq!(body.head.len(), 2, "only title + desc are pinned");

        let read_only = notice_body(&base, 60);
        assert_eq!(
            read_only.fields.len(),
            1,
            "prose scrolls when nothing else does"
        );
        assert_eq!(read_only.focus_row, None);
        assert!(flatten(&read_only.head).contains("PICK ONE"));
    }

    #[test]
    fn choice_row_carries_the_ecosystem_focus_grammar() {
        let focused = choice_line(&choice("Delete", None, true), 60);
        let cells: usize = focused
            .spans
            .iter()
            .map(|s| crate::tui::text::width(&s.content))
            .sum();
        assert_eq!(cells, 60, "a focused row fills the width");
        let text = flatten(std::slice::from_ref(&focused));
        assert!(!text.contains('▌') && !text.contains('◀'));
        assert!(focused
            .spans
            .iter()
            .all(|span| span.style.bg == Some(T.info)));

        let at_rest = choice_line(&choice("Delete", None, false), 60);
        assert!(
            at_rest.spans.iter().all(|s| s.style.bg.is_none()),
            "an unfocused option carries no focus bar"
        );
        assert_eq!(at_rest.spans[0].style.fg, Some(T.scope_privacy));
    }

    /// Was `choice_detail_is_dropped_not_clipped_when_it_does_not_fit`,
    /// pinning the opposite behaviour. The body still does not wrap — the detail is
    /// ellipsised into the row instead, which is what every other row
    /// vocabulary in this module does and the only variant that tells the
    /// operator something was cut.
    #[test]
    fn choice_detail_is_ellipsised_not_dropped_when_it_does_not_fit() {
        let long = "a".repeat(80);
        let narrow = choice_line(&choice("Delete", Some(&long), false), 30);
        let text = flatten(&[narrow]);
        assert!(text.contains("aaaa"), "detail must survive, cut: {text}");
        assert!(text.ends_with('\u{2026}'), "the cut is announced: {text}");
        assert!(
            crate::tui::text::width(&text) <= 30,
            "the row still fits its width: {text}"
        );
        assert!(
            text.contains("Delete"),
            "the option itself survives: {text}"
        );

        // Below `MIN_DETAIL_CELLS` there is no room for text, only for an
        // ellipsis — the option keeps its single row and drops the stub.
        // The needle is `z`, absent from the label, so this cannot pass by
        // matching the option's own text.
        let stub = "z".repeat(80);
        let cramped = choice_line(&choice("Delete every list here", Some(&stub), false), 30);
        let text = flatten(&[cramped]);
        assert!(
            !text.contains('z'),
            "a stub detail is worse than none: {text}"
        );
        assert_eq!(
            choice_rows(&choice("Delete every list here", Some(&stub), false), 30).len(),
            1,
            "dropping the stub must not change the row count"
        );
    }

    fn render_notice_in(spec: &NoticeSpec, w: u16, h: u16) -> String {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| {
            render_modal(f, f.area(), 64, |width| (notice_body(spec, width), ()));
        })
        .unwrap();
        let buf = term.backend().buffer();
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    /// Prose is caller-controlled and unbounded. Pinned in the head it
    /// would compete with the options for the same 12 interior rows the
    /// anchor leaves at 80x24 — and `scroll_layout` serves head before
    /// fields, so three prose rows render ZERO options while `focus_row`
    /// still points at one. No panic, and `will_scroll` reports false
    /// (it needs `view_h > 0`), so not even a scrollbar hints at it.
    ///
    /// A delete confirm with a two-sentence warning and a blank line is
    /// three prose rows. Hence: prose leads the SCROLLING region, it is
    /// not pinned.
    #[test]
    fn notice_body_never_starves_the_option_list_at_the_floor() {
        let spec = NoticeSpec {
            title: "Delete list".into(),
            desc: "This cannot be undone.".into(),
            prose: vec![
                ProseRow::plain("privacy-ads is used by 3 profiles."),
                ProseRow::emphasis("They stop filtering its domains.", ValueKind::Blocking),
                ProseRow::plain(""),
            ],
            choices: vec![
                choice("Delete it", None, true),
                choice("Delete and detach", None, false),
                choice("Keep it", None, false),
            ],
            keys: "\u{2191}\u{2193} move \u{b7} Enter confirm".into(),
            actions: vec![Action::new(
                "  Cancel  ",
                false,
                ActionKind::Neutral,
                "close",
            )],
            ..NoticeSpec::default()
        };
        let out = render_notice_in(&spec, 80, 14);
        assert!(
            out.contains("Delete it"),
            "the focused option was starved off screen:\n{out}"
        );
        assert!(
            out.contains("Cancel"),
            "action row must stay pinned:\n{out}"
        );
        assert!(
            out.contains("DELETE LIST"),
            "title must stay pinned:\n{out}"
        );
    }

    // ── The Archetype-C row budget ──────────────────────────────────────

    /// A five-option picker with a one-line hint, the shape
    /// `scope_modal::menu_notice` actually builds — including its
    /// `hint_rows: Some(1)`, which is how it buys the row back.
    fn picker_spec(hint: &str) -> NoticeSpec {
        NoticeSpec {
            title: "Add to allowlist".into(),
            desc: "how widely should the rule apply?".into(),
            choices: (0..5)
                .map(|i| choice(&format!("Option number {i}"), None, i == 0))
                .collect(),
            hint: hint.into(),
            hint_rows: Some(1),
            keys: "[\u{2191}/\u{2193}] move   [Enter] select".into(),
            actions: vec![
                Action::new("  Cancel  ", false, ActionKind::Neutral, ""),
                Action::new("  Continue  ", false, ActionKind::Primary, ""),
            ],
            ..NoticeSpec::default()
        }
    }

    /// Archetype C's tail used to be Archetype F's: a spacer, a FIXED
    /// two-row hint region and the two control rows — five of the twelve
    /// interior rows the anchor leaves at the 80×24 floor, two of them
    /// structurally blank. F pins that region because a form must not
    /// shift under the operator's cursor when an error appears; C has no
    /// such body, so it pays for what it writes and nothing else.
    #[test]
    fn c_tail_costs_three_rows_when_the_surface_wrote_one_hint() {
        let body = notice_body(&picker_spec("affects only this device"), 60);
        assert_eq!(
            body.head.len(),
            2,
            "C's head is the title band + the description; the blank row \
             after it belongs to Archetype F, where it separates the bands \
             from the first SECTION band. C has no sections. Got:\n{}",
            flatten(&body.head)
        );
        assert_eq!(
            body.tail.len(),
            3,
            "one hint row + the key legend + the action row. Got:\n{}",
            flatten(&body.tail)
        );
    }

    /// The same budget, spent: five options and a hint on screen together
    /// at the minimum-terminal floor. Asserted on the rendered buffer,
    /// because the line vector can be correct while the render is wrong.
    #[test]
    fn c_option_list_keeps_every_option_on_screen_at_the_d18_floor() {
        let spec = picker_spec("affects only this device");
        let out = render_notice_in(&spec, 80, 14);
        for i in 0..5 {
            assert!(
                out.contains(&format!("Option number {i}")),
                "option {i} of 5 was pushed off a 12-row interior by the \
                 tail's blank rows:\n{out}"
            );
        }
        assert!(
            out.contains("affects only this device"),
            "the hint row is the one tail row C actually writes:\n{out}"
        );
        assert!(
            out.contains("Continue"),
            "action row must stay pinned:\n{out}"
        );
    }

    /// A surface that wrote no hint and has no error must not be charged
    /// for the region: two blank rows is the whole of the defect above.
    ///
    /// Also pins the *default* — `hint_rows: None` reserves the full
    /// [`HINT_ROWS`] the moment there is anything to say, all-or-nothing,
    /// so a validation error never shifts the body under the operator's
    /// cursor. Only a surface that knows better pins `Some(1)`.
    #[test]
    fn c_tail_spends_nothing_on_a_note_the_surface_never_wrote() {
        let silent = NoticeSpec {
            hint_rows: None,
            ..picker_spec("")
        };
        assert_eq!(
            notice_body(&silent, 60).tail.len(),
            2,
            "key legend + action row only. Got:\n{}",
            flatten(&notice_body(&silent, 60).tail)
        );

        let speaking = NoticeSpec {
            hint_rows: None,
            ..picker_spec("mind the gap")
        };
        assert_eq!(
            notice_body(&speaking, 60).tail.len(),
            2 + HINT_ROWS,
            "the default reserves the whole region once there is a note"
        );
        let erroring = NoticeSpec {
            hint_rows: None,
            error: Some("that id does not match".into()),
            ..picker_spec("")
        };
        assert_eq!(
            notice_body(&erroring, 60).tail.len(),
            2 + HINT_ROWS,
            "an error alone is enough to claim the region"
        );
    }

    /// Column just inside the right border — where [`render_scrollbar`]
    /// paints. Read off the buffer rather than computed, so it cannot
    /// drift from the chrome.
    fn scrollbar_glyphs(out: &str) -> String {
        out.lines()
            .filter_map(|row| {
                let chars: Vec<char> = row.chars().collect();
                // The modal is centred; find its right border on this row.
                let right = chars
                    .iter()
                    .rposition(|c| *c == '\u{2502}' || *c == '\u{256f}')?;
                chars.get(right.checked_sub(1)?).copied()
            })
            .filter(|c| *c == '\u{2588}' || *c == '\u{2502}')
            .collect()
    }

    /// A prose-only C body used to draw a scrollbar nothing could move.
    ///
    /// Prose carries no focus, so `focus_row` is `None`, so
    /// `render_scroll_body`'s offset is pinned at 0 — but the bar still
    /// painted whenever the prose overflowed, advertising a control the
    /// operator cannot operate and content no keystroke can reach.
    #[test]
    fn a_prose_only_notice_draws_no_scrollbar() {
        let spec = NoticeSpec {
            title: "Resolver".into(),
            desc: "what this name resolves to".into(),
            prose: (0..12)
                .map(|i| ProseRow::plain(format!("attribution line {i}")))
                .collect(),
            hint: "nothing here can take focus".into(),
            keys: "[Esc] close".into(),
            actions: vec![Action::new("  Close  ", false, ActionKind::Neutral, "")],
            ..NoticeSpec::default()
        };
        let out = render_notice_in(&spec, 80, 14);
        assert_eq!(
            scrollbar_glyphs(&out),
            "",
            "a scrollbar was drawn beside a body no keystroke can scroll:\n{out}"
        );
    }

    // ── An option's explanation must survive ────────────────────────────

    /// `choice_row` used to drop a detail it could not fit whole. At the real
    /// 62-column interior that is every non-trivial one — all five of the
    /// scope modal's descriptions vanished, and nothing on screen said so.
    /// Everything else in this module ellipsises (`fit`, `desc_band`,
    /// `hint_or_error_rows`), which is self-announcing; a dropped detail
    /// is indistinguishable from an option that never had one.
    #[test]
    fn an_enabled_options_detail_is_ellipsised_never_dropped() {
        let spec = NoticeSpec {
            title: "Pick one".into(),
            desc: "d".into(),
            choices: vec![
                choice(
                    "All devices on profile 'default'",
                    Some("every device currently using this profile."),
                    true,
                ),
                choice(
                    "All devices in group 'famiglia'",
                    Some("every device that belongs to this group."),
                    false,
                ),
            ],
            keys: "[Esc] close".into(),
            actions: vec![Action::new("  Cancel  ", false, ActionKind::Neutral, "")],
            ..NoticeSpec::default()
        };
        // Roomy anchor: this is a question about WIDTH, not the budget.
        let out = render_notice_in(&spec, 80, 40);
        // Short needles on purpose: the point is that the detail is CUT
        // rather than dropped, so asserting the whole sentence would fail
        // for the right behaviour.
        for needle in ["every device currently", "every device that bel"] {
            assert!(
                out.contains(needle),
                "detail {needle:?} was dropped whole at a 62-column \
                 interior:\n{out}"
            );
        }
    }

    // ── S3: a verbatim row is wrapped, never ellipsised ───────────────

    /// Strip the modal chrome and the row indents, so a string that had to
    /// wrap across two rows reads back contiguous.
    ///
    /// Deliberately keeps `…`: an ellipsis is exactly what a verbatim row
    /// must never produce, so leaving it in is what makes the assertion
    /// discriminating rather than a formality.
    fn dechrome(dump: &str) -> String {
        dump.chars()
            .filter(|c| {
                !matches!(
                    c,
                    ' ' | '\n'
                        | '\u{2502}'
                        | '\u{2500}'
                        | '\u{256d}'
                        | '\u{256e}'
                        | '\u{2570}'
                        | '\u{256f}'
                        | '\u{258c}'
                        | '\u{2588}'
                        | '\u{25c0}'
                )
            })
            .collect()
    }

    /// A non-uniform id of exactly `n` characters whose **tail** is unique
    /// in the frame.
    ///
    /// `"a".repeat(64)` would be a needle that matches a truncated render
    /// too — 59 of the same character still `contains` any shorter run of
    /// them. Truncation always eats the tail, so the tail is the only part
    /// worth asserting on.
    fn id_of_len(n: usize) -> String {
        const HEAD: &str = "delete-me-";
        const TAIL: &str = "-endsentinel";
        format!("{HEAD}{}{TAIL}", "x".repeat(n - HEAD.len() - TAIL.len()))
    }

    /// The row count of a verbatim row is a function of the **spec**, not
    /// of `width` — the same invariant [`choice_rows`] carries, and for the
    /// same reason: [`render_modal`] builds the body at `w` and again at
    /// `w - 1` when the scrollbar claims a column, so a width-derived wrap
    /// would silently mis-size the modal.
    #[test]
    fn prose_rows_row_count_never_varies_with_width() {
        let row = ProseRow::verbatim(id_of_len(64), ValueKind::Blocking);
        let baseline = prose_rows(&row, 62).len();
        assert_eq!(baseline, 2, "a 64-char id needs two rows at a 59-cell wrap");
        for w in 40u16..=120 {
            assert_eq!(
                prose_rows(&row, w).len(),
                baseline,
                "verbatim row count changed at width {w}"
            );
            assert_eq!(
                prose_row_count(&row),
                baseline,
                "the width-free count disagrees with the render at {w}"
            );
        }
    }

    /// `prose_field_row` is what puts the hardware cursor on the row the
    /// operator types into. It has to count *rendered* lines, not prose
    /// ordinals, or a wrapped id silently moves the caret one row up.
    #[test]
    fn prose_field_row_counts_wrapped_lines_not_ordinals() {
        let prose = vec![
            ProseRow::verbatim(id_of_len(64), ValueKind::Blocking),
            ProseRow::plain("type the id above verbatim, then Enter:"),
            ProseRow::plain("> "),
        ];
        assert_eq!(prose_field_row(&prose, 0), 0);
        assert_eq!(prose_field_row(&prose, 1), 2, "the id took two lines");
        assert_eq!(prose_field_row(&prose, 2), 3);

        let short = vec![
            ProseRow::verbatim("tiny-id".to_string(), ValueKind::Blocking),
            ProseRow::plain("> "),
        ];
        assert_eq!(prose_field_row(&short, 1), 1, "one line when it fits");
    }

    /// A verbatim row never emits `…` and never drops a character, at any
    /// width the ecosystem can hand it — including the `w - 1` scrollbar
    /// pass.
    #[test]
    fn a_verbatim_row_is_never_ellipsised() {
        for n in 55..=64usize {
            let id = id_of_len(n);
            let row = ProseRow::verbatim(id.clone(), ValueKind::Blocking);
            for w in [61u16, 62] {
                let joined: String = prose_rows(&row, w)
                    .iter()
                    .flat_map(|l| l.spans.iter().map(|s| s.content.to_string()))
                    .collect::<String>()
                    .replace(' ', "");
                assert!(
                    !joined.contains('\u{2026}'),
                    "verbatim row ellipsised a {n}-char id at width {w}: {joined:?}"
                );
                assert!(
                    joined.contains(&id),
                    "a {n}-char id did not survive width {w}: {joined:?}"
                );
            }
        }
    }

    /// Every rendered line of a verbatim row stays inside the interior.
    ///
    /// [`render_body_fixed`] does **not** wrap — it clips at the modal edge
    /// with no marker — so an over-wide verbatim line would lose exactly
    /// the characters this feature exists to preserve, and lose them
    /// silently.
    #[test]
    fn a_verbatim_row_never_overruns_the_interior() {
        let row = ProseRow::verbatim("z".repeat(253), ValueKind::Identity);
        for w in [61u16, 62] {
            for line in prose_rows(&row, w) {
                let cells: usize = line
                    .spans
                    .iter()
                    .map(|s| crate::tui::text::width(&s.content))
                    .sum();
                assert!(
                    cells <= w as usize,
                    "verbatim line is {cells} cells against an interior of {w}"
                );
            }
        }
    }

    /// Contract item 3: an ordinary prose row is unchanged — it still
    /// ellipsises, because a deterministic row count is why `fit` is there.
    #[test]
    fn a_plain_prose_row_still_ellipsises() {
        let row = ProseRow::plain("y".repeat(200));
        let lines = prose_rows(&row, 62);
        assert_eq!(lines.len(), 1, "a plain prose row is always one line");
        let text: String = lines[0]
            .spans
            .iter()
            .map(|s| s.content.to_string())
            .collect();
        assert!(
            text.ends_with('\u{2026}'),
            "a plain prose row must announce its own cut: {text:?}"
        );
    }

    /// The sibling invariant on [`choice_rows`]. Its doc has long named
    /// this test; only now does it exist.
    #[test]
    fn choice_rows_row_count_never_varies_with_width() {
        // Both `ChoiceNote` variants, and a note long
        // enough to spill past one `NOTE_WRAP` chunk. Exercising only the
        // one-chunk case would leave the spill path — the only part of
        // this function that computes a count at all — unpinned, and the
        // invariant would read green over the defect it exists to catch.
        let long = "e".repeat(NOTE_WRAP * 2 + 3);
        let notes = [
            None,
            Some(ChoiceNote::Blocked("in use by two profiles".to_string())),
            Some(ChoiceNote::Detail(
                "every device currently using this profile.".to_string(),
            )),
            Some(ChoiceNote::Detail(long)),
        ];
        for note in notes {
            let row = ChoiceRow {
                label: "All devices on profile 'default'".to_string(),
                detail: Some("every device currently using this profile.".to_string()),
                kind: ValueKind::Identity,
                focused: true,
                note,
            };
            // The independent statement of the rule, not a self-comparison
            // at some reference width: a renderer that derived its count
            // from `width` identically on every pass would still satisfy
            // the loop below.
            let baseline = choice_row_count(&row);
            for w in 20u16..=120 {
                assert_eq!(
                    choice_rows(&row, w).len(),
                    baseline,
                    "choice row count changed at width {w}"
                );
            }
        }
    }

    // The four suggestion-window tests
    // (`the_suggestions_row_fits_its_width_at_every_focus`,
    // `the_focused_suggestion_is_always_inside_the_window`,
    // `the_overflow_markers_account_for_every_hidden_suggestion`,
    // `a_suggestion_list_that_fits_carries_no_overflow_marker`) are gone,
    // along with
    // `suggestion_window` / `chip_suggestions_row` / `chip_picker_row` /
    // `chip_cells` / `tag_chip_color`, the primitives they tested.
    //
    // No substitute: these were guarantees about the tag chip
    // picker's scrolling suggestion row, and no surviving modal_form widget
    // has a windowed row. The guarantees leave with the widget.
    // `the_suggestions_label_names_its_navigation_key` went with them.

    /// A [`ChoiceNote`] is never cut — that is the whole reason it takes a
    /// row instead of riding the label's leftovers.
    #[test]
    fn a_choice_note_is_wrapped_never_ellipsised() {
        let text = "This device's IP doesn't match any defined subnet, and \
                    nothing else on screen would say so.";
        let row = ChoiceRow {
            label: "All devices on subnet".to_string(),
            detail: None,
            kind: ValueKind::Caution,
            focused: false,
            note: Some(ChoiceNote::Blocked(text.to_string())),
        };
        let lines = choice_rows(&row, 62);
        let rendered = flatten(&lines);
        assert!(
            !rendered.contains('\u{2026}'),
            "a note must wrap, not ellipsise: {rendered:?}"
        );
        // Undo the wrap by stripping each note row's 2-cell indent — a
        // chunk boundary can fall mid-word, so re-splitting on whitespace
        // would not reconstruct the original.
        let joined: String = rendered
            .lines()
            .skip(1)
            .map(|l| l.strip_prefix("  ").unwrap_or(l))
            .collect();
        assert_eq!(
            joined, text,
            "the note lost text across the wrap: {joined:?}"
        );
    }

    /// The whole point, end to end: a maximum-length id renders in full on
    /// an Archetype-C gate at the 80×24 floor.
    #[test]
    fn a_max_length_id_renders_in_full_at_the_floor() {
        for n in 55..=64usize {
            let id = id_of_len(n);
            let spec = NoticeSpec {
                title: "Delete admin rule".into(),
                desc: "removes the row and every reference to it".into(),
                prose: vec![
                    ProseRow::verbatim(id.clone(), ValueKind::Blocking),
                    ProseRow::plain("type the id above verbatim, then Enter:"),
                    ProseRow::plain("> "),
                ],
                error: None,
                hint: "nothing is written unless what you type matches exactly".into(),
                keys: "Enter confirm \u{b7} Esc back to edit".into(),
                actions: vec![Action::new(
                    "  Enter Delete  ",
                    false,
                    ActionKind::Destructive,
                    "",
                )],
                ..NoticeSpec::default()
            };
            // 14 rows is the anchor's content rect at the declared 80×24 floor.
            let out = render_notice_in(&spec, 80, 14);
            // Nothing else in this fixture is long enough to ellipsise, so
            // a `…` anywhere in the frame is the id being cut.
            assert!(
                !out.contains('\u{2026}'),
                "a {n}-char id was ellipsised:\n{out}"
            );
            assert!(
                dechrome(&out).contains(&id),
                "a {n}-char id is not recoverable from the screen:\n{out}"
            );
        }
    }

    // ── S3: `value_row` announces its own cut ─────────────────────────

    fn flat_line(line: &Line<'static>) -> String {
        line.spans.iter().map(|s| s.content.to_string()).collect()
    }

    /// A value wider than the interior used to be pushed raw and clipped
    /// by the widget at the modal edge — with **no** marker, so the
    /// operator read a truncated string as a complete one.
    #[test]
    fn an_overlong_value_row_announces_its_cut() {
        for focused in [false, true] {
            let line = value_row(
                "references",
                &"w".repeat(120),
                focused,
                ValueKind::Identity,
                None,
                62,
            );
            let text = flat_line(&line);
            assert!(
                text.contains('\u{2026}'),
                "value_row clipped without a tell (focused={focused}): {text:?}"
            );
            assert!(
                crate::tui::text::width(&text) <= 62,
                "value_row overran the interior (focused={focused}): \
                 {} cells",
                crate::tui::text::width(&text)
            );
        }
    }

    /// A focused selector wraps its value in `‹ … ›` to say a key cycles
    /// it. Fitting the composed string would eat the closing `›` — the
    /// marker, not the value, would be what got cut.
    #[test]
    fn a_fitted_selector_row_keeps_its_closing_marker() {
        let line = selector_row("format", &"v".repeat(120), true, 62);
        let text = flat_line(&line);
        assert!(
            text.contains('\u{2039}') && text.contains('\u{203a}'),
            "the cycle markers did not both survive the fit: {text:?}"
        );
        assert!(
            text.contains('\u{2026}'),
            "the value was cut without a tell: {text:?}"
        );
    }

    // ── F1: a focused editable is windowed to the caret, not the head ──
    //
    // `an_overlong_value_row_announces_its_cut` above passes on BOTH the
    // broken and the fixed builds, and that is not a criticism of it — it
    // was written to prove the cut is *announced*, and it does. But its
    // fixture is `"w".repeat(120)`, so head and tail are indistinguishable
    // and it cannot see which end survived. Every test below is built so
    // that reversing the windowing direction turns it red.

    /// The value an operator types is worked on at the END. Keeping the
    /// head shows them the part they have finished with.
    #[test]
    fn a_focused_editable_keeps_the_tail_the_operator_is_typing() {
        let value = "HEADWORD followed by plenty of filler text ending in TAILWORD";
        let text = flat_line(&value_row(
            "description",
            value,
            true,
            ValueKind::Editable,
            None,
            62,
        ));
        assert!(
            text.contains("TAILWORD"),
            "the operator cannot see what they are typing: {text:?}"
        );
        assert!(
            !text.contains("HEADWORD"),
            "the row kept the head, so the tail is what was cut: {text:?}"
        );
        assert!(
            text.contains('\u{2026}'),
            "the cut was not announced: {text:?}"
        );
    }

    /// The read-only direction must NOT change. `fit` keeps the head
    /// because an id, a domain or a path identifies itself there, and
    /// `rules.rs` documents that choice. A fix that reversed both
    /// directions would pass the test above and still be wrong.
    #[test]
    fn an_unfocused_value_still_keeps_its_head() {
        let value = "HEADWORD followed by plenty of filler text ending in TAILWORD";
        let text = flat_line(&value_row(
            "references",
            value,
            false,
            ValueKind::Identity,
            None,
            62,
        ));
        assert!(
            text.contains("HEADWORD"),
            "the read-only path lost the head it exists to show: {text:?}"
        );
        assert!(
            !text.contains("TAILWORD"),
            "the read-only path was flipped to keep the tail: {text:?}"
        );
    }

    /// Windowing the text without clamping the caret fixes nothing: the
    /// column keeps climbing and `place_cursor` declines to set it.
    #[test]
    fn the_caret_stops_at_the_budget_instead_of_walking_off_the_row() {
        let long = "x".repeat(200);
        let mut rows = FormRows::new("Describe tag", "a note", 62);
        rows.text_field(
            value_row("description", &long, true, ValueKind::Editable, None, 62),
            true,
            "type a sentence",
            u16::try_from(long.chars().count()).unwrap(),
        );
        let (_, cursor) = rows.finish(Vec::new());
        let (_, caret) = cursor.expect("a focused text field records a caret");
        let budget = u16::try_from(value_budget(62, true)).unwrap();
        assert_eq!(
            caret, budget,
            "caret sat at the value's length, not at the last visible column"
        );
    }

    /// A short value must NOT be clamped — the caret still has to follow
    /// the text. A fix that pinned every caret to the budget would pass
    /// the test above and put the cursor in empty space here.
    #[test]
    fn a_short_value_leaves_its_caret_exactly_where_the_text_ends() {
        let mut rows = FormRows::new("Describe tag", "a note", 62);
        rows.text_field(
            value_row("description", "kids", true, ValueKind::Editable, None, 62),
            true,
            "type a sentence",
            4,
        );
        let (_, cursor) = rows.finish(Vec::new());
        assert_eq!(cursor.map(|(_, c)| c), Some(4));
    }

    /// The one that matters, and the one no handler test can see: at the
    /// declared 80×24 floor, with a value past the budget, the hardware
    /// cursor is actually PLACED. Before the clamp `place_cursor` fell
    /// through its `x < inner.right()` guard and set nothing — the caret
    /// did not move, it disappeared.
    #[test]
    fn at_eighty_by_twentyfour_an_overlong_field_still_shows_a_cursor() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let long = "a sentence that comfortably outgrows the value column budget";
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| {
            let out = render_modal(f, f.area(), 64, |w| {
                let mut rows = FormRows::new("Describe tag", "a note", w);
                rows.text_field(
                    value_row("description", long, true, ValueKind::Editable, None, w),
                    true,
                    "type a sentence",
                    u16::try_from(long.chars().count()).unwrap(),
                );
                let tail = form_tail(&rows, None, "type a sentence", "Ctrl+S save", &[]);
                rows.finish(tail)
            });
            if let Some((row, caret)) = out.cursor {
                out.place_cursor(f, row, VALUE_COL as u16 + caret);
            }
        })
        .unwrap();

        let pos = term.get_cursor_position().unwrap();
        assert!(
            pos.x > 0 && pos.y > 0,
            "no cursor was placed — the operator types blind: {pos:?}"
        );
        assert!(
            pos.x < 80,
            "the cursor was placed off the 80-column screen: {pos:?}"
        );
    }
}
