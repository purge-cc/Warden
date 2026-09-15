//! Query Log filter bar and the small forms sharing the Advanced modal style.

use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use super::app::SincePreset;
use super::mouse::{self, MouseAction};
use super::theme::T;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum FilterFocus {
    #[default]
    Value,
    Discard,
    Apply,
}

impl FilterFocus {
    pub(crate) fn next(self) -> Self {
        match self {
            Self::Value => Self::Discard,
            Self::Discard => Self::Apply,
            Self::Apply => Self::Value,
        }
    }

    pub(crate) fn prev(self) -> Self {
        match self {
            Self::Value => Self::Apply,
            Self::Discard => Self::Value,
            Self::Apply => Self::Discard,
        }
    }
}

pub(crate) fn render_domain(
    f: &mut Frame,
    bounds: Rect,
    anchor: Rect,
    draft: &str,
    focus: FilterFocus,
) {
    let inner = super::filter_chips::popup(f, bounds, anchor, (44, 6), "Domain");
    let focused = focus == FilterFocus::Value;
    let shown = if focused {
        super::filter_chips::input_text(draft, inner.width)
    } else {
        super::text::fit(draft, inner.width as usize)
    };
    let field = Rect::new(inner.x, inner.y, inner.width, 1);
    f.render_widget(
        Paragraph::new(shown.as_str())
            .style(super::filter_chips::chip_style(!draft.is_empty(), focused)),
        field,
    );
    mouse::register_overlay_action(field, MouseAction::OverlayField(0));
    f.render_widget(
        Paragraph::new("Case-insensitive domain fragment").style(Style::default().fg(T.text_muted)),
        Rect::new(inner.x, inner.y.saturating_add(1), inner.width, 1),
    );
    super::filter_chips::render_actions(
        f,
        Rect::new(inner.x, inner.bottom().saturating_sub(1), inner.width, 1),
        focus,
    );
    if focused {
        f.set_cursor_position((
            inner.x + super::text::width(&shown).saturating_sub(1) as u16,
            inner.y,
        ));
    }
}

pub(crate) fn render_period(
    f: &mut Frame,
    bounds: Rect,
    anchor: Rect,
    selected: SincePreset,
    focus: FilterFocus,
) {
    let inner = super::filter_chips::popup(
        f,
        bounds,
        anchor,
        (28, SincePreset::ALL.len() as u16 + 4),
        "Period",
    );
    for (index, preset) in SincePreset::ALL.into_iter().enumerate() {
        let active = selected == preset;
        let row = Rect::new(inner.x, inner.y + index as u16, inner.width, 1);
        f.render_widget(
            Paragraph::new(format!(
                "({}) {}",
                if active { "x" } else { " " },
                preset.long_label()
            ))
            .style(super::filter_chips::chip_style(
                active,
                active && focus == FilterFocus::Value,
            )),
            row,
        );
        mouse::register_overlay_action(row, MouseAction::OverlayField(index));
    }
    super::filter_chips::render_actions(
        f,
        Rect::new(inner.x, inner.bottom().saturating_sub(1), inner.width, 1),
        focus,
    );
}
