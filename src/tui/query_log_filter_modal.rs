//! Query Log advanced client search (`qlog-advanced-filter-form`).
//!
//! **Additive, and that is a design constraint rather than a courtesy.**
//! The Query Log's `/` domain, `c` client, `b` blocked-only and `t` time
//! controls keep exactly the behaviour they had; this form ANDs three more
//! predicates on top. An operator who never presses `f` cannot tell it
//! exists, and the daemon pays nothing for it — an empty form compiles to
//! no predicate at all.
//!
//! ## Why three dimensions and not five
//!
//! Client **name**, client **IP** and **subnet** are Tier 1: every one is a
//! property of the log row itself, so the walker answers them without
//! knowing anything about the operator's configuration. Owner, department
//! and device-type are Tier 2 — they live in Labels, not in the row, and
//! reaching them means a join that must happen *before* the walk and
//! arrive as a resolved set of client IPs. `AdvancedFilter` already carries
//! that seam. **MAC was dropped by operator decision**: it needs the same
//! join and yields no dimension owner/device-type does not already give.
//!
//! ## Why glob and not regex
//!
//! The pattern is matched once per line of a file that can be hundreds of
//! megabytes, against text the operator typed. A regex there owns
//! catastrophic backtracking. `*` is the only metacharacter, and a pattern
//! without one is a plain substring — the semantics `c` has always had, so
//! the form does not quietly redefine what the operator already knows.
//!
//! ## Why INCLUDE / EXCLUDE and not AND / OR
//!
//! Predicates are ANDed, each with its own polarity. OR would cost
//! precedence, grouping, and a way to render the live expression in a
//! footer already short of cells; AND-with-polarity already covers the
//! case that motivated the feature ("everything except the IoT devices").

use ratatui::layout::Rect;
use ratatui::Frame;

use crate::ipc::protocol::AdvancedClientFilterDto;
use crate::tui::modal_form::{self, Action, ActionKind, ScrollBody, ValueKind};

/// Modal width, matching the ecosystem's form modals.
const W: u16 = 66;

const TITLE: &str = "Advanced search";
const DESC: &str = "narrow the log by client \u{b7} ANDed with Domain / Client / Time";
const KEYS: &str = "\u{21b9}/\u{2191}\u{2193} move \u{b7} \u{2190}/\u{2192} flip include/exclude";

/// Refused save because the subnet did not parse. Frozen — the operator
/// reads this to tell a typo from an empty result set.
pub const QLOG_FILTER_BAD_CIDR: &str = "subnet must be a CIDR like 10.10.1.0/24";

/// Focus targets, in Tab order. Each dimension owns a text row and a
/// polarity row, so the polarity is reachable by the same key that reaches
/// everything else rather than by a modifier the operator has to be told
/// about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    NamePattern,
    NamePolarity,
    IpPattern,
    IpPolarity,
    SubnetPattern,
    SubnetPolarity,
    Cancel,
    Apply,
}

impl Field {
    const ORDER: [Field; 8] = [
        Field::NamePattern,
        Field::NamePolarity,
        Field::IpPattern,
        Field::IpPolarity,
        Field::SubnetPattern,
        Field::SubnetPolarity,
        Field::Cancel,
        Field::Apply,
    ];

    pub fn next(self) -> Self {
        let i = Self::ORDER.iter().position(|f| *f == self).unwrap_or(0);
        Self::ORDER[(i + 1) % Self::ORDER.len()]
    }

    pub fn prev(self) -> Self {
        let i = Self::ORDER.iter().position(|f| *f == self).unwrap_or(0);
        Self::ORDER[(i + Self::ORDER.len() - 1) % Self::ORDER.len()]
    }

    /// The text buffer this field edits, if it edits one.
    fn text_of(self, d: &mut AdvancedClientFilterDto) -> Option<&mut Option<String>> {
        match self {
            Field::NamePattern => Some(&mut d.name),
            Field::IpPattern => Some(&mut d.ip),
            Field::SubnetPattern => Some(&mut d.subnet),
            _ => None,
        }
    }

    /// The polarity flag this field toggles, if it toggles one.
    fn polarity_of(self, d: &mut AdvancedClientFilterDto) -> Option<&mut bool> {
        match self {
            Field::NamePolarity => Some(&mut d.name_exclude),
            Field::IpPolarity => Some(&mut d.ip_exclude),
            Field::SubnetPolarity => Some(&mut d.subnet_exclude),
            _ => None,
        }
    }
}

/// The open form. `draft` is edited in place and only copied onto
/// `QueryLogState.advanced` on Apply, so Esc genuinely discards.
#[derive(Debug, Clone)]
pub struct QueryLogFilterModal {
    pub draft: AdvancedClientFilterDto,
    pub focus: Field,
    pub error: Option<String>,
}

impl QueryLogFilterModal {
    /// Open seeded from what is currently applied, so re-opening shows the
    /// live filter rather than a blank form the operator must retype.
    pub fn open(current: &AdvancedClientFilterDto) -> Self {
        Self {
            draft: current.clone(),
            focus: Field::NamePattern,
            error: None,
        }
    }

    pub fn focus_next(&mut self) {
        self.focus = self.focus.next();
    }

    pub fn focus_prev(&mut self) {
        self.focus = self.focus.prev();
    }

    /// Append one character to the focused text row. No-op on a polarity
    /// or action row — a keystroke that lands nowhere is better than one
    /// that silently edits a field the operator is not looking at.
    pub fn push_char(&mut self, c: char) {
        if let Some(slot) = self.focus.text_of(&mut self.draft) {
            slot.get_or_insert_with(String::new).push(c);
            self.error = None;
        }
    }

    pub fn backspace(&mut self) {
        if let Some(slot) = self.focus.text_of(&mut self.draft) {
            if let Some(s) = slot.as_mut() {
                s.pop();
                if s.is_empty() {
                    *slot = None;
                }
            }
            self.error = None;
        }
    }

    /// Flip the focused row's polarity. A no-op on a text or action row —
    /// Left/Right is consumed by the handler either way, so there is
    /// nothing for a caller to branch on.
    pub fn toggle_polarity(&mut self) {
        if let Some(flag) = self.focus.polarity_of(&mut self.draft) {
            *flag = !*flag;
        }
    }

    /// Validate and hand back the filter to apply, or set `error`.
    ///
    /// Only the subnet can be malformed: a glob has no syntax to get
    /// wrong, which is a second reason it beats a regex here. A bad CIDR
    /// is refused rather than dropped, because a silently-dropped subnet
    /// predicate looks exactly like "no traffic from that subnet".
    pub fn try_apply(&mut self) -> Option<AdvancedClientFilterDto> {
        if let Some(sn) = self
            .draft
            .subnet
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if crate::config::cidr::Cidr::parse(sn).is_err() {
                self.error = Some(QLOG_FILTER_BAD_CIDR.to_string());
                self.focus = Field::SubnetPattern;
                return None;
            }
        }
        self.error = None;
        Some(self.draft.clone())
    }
}

/// Draw the form as an overlay anchored on the tab content rect.
pub fn render_overlay(f: &mut Frame, anchor: Rect, modal: &QueryLogFilterModal) {
    let render = modal_form::render_modal(f, anchor, W, |w| form_body(modal, w));
    if let Some((row, caret)) = render.cursor {
        render.place_cursor(f, row, modal_form::VALUE_COL as u16 + caret);
    }
}

fn chars(s: Option<&String>) -> u16 {
    u16::try_from(s.map_or(0, |v| v.chars().count())).unwrap_or(u16::MAX)
}

fn form_body(modal: &QueryLogFilterModal, width: u16) -> (ScrollBody, Option<(usize, u16)>) {
    let d = &modal.draft;
    let focus = modal.focus;
    let mut rows = modal_form::FormRows::new(TITLE, DESC, width);

    let dimension = |rows: &mut modal_form::FormRows,
                     section: &str,
                     label: &str,
                     value: Option<&String>,
                     placeholder: &str,
                     text_field: Field,
                     polarity_field: Field,
                     exclude: bool| {
        rows.section(section);
        let tf = focus == text_field;
        rows.text_field(
            modal_form::value_row(
                label,
                value.map(String::as_str).unwrap_or(""),
                tf,
                ValueKind::Editable,
                Some(placeholder),
                width,
            ),
            tf,
            field_hint(text_field),
            chars(value),
        );
        let pf = focus == polarity_field;
        rows.field(
            modal_form::radio_row(
                "match",
                ("include", ValueKind::Editable),
                ("exclude", ValueKind::Identity),
                !exclude,
                pf,
                width,
            ),
            pf,
            field_hint(polarity_field),
        );
    };

    dimension(
        &mut rows,
        "Client name",
        "name",
        d.name.as_ref(),
        "e.g. *ioel* or laptop",
        Field::NamePattern,
        Field::NamePolarity,
        d.name_exclude,
    );
    dimension(
        &mut rows,
        "Client IP",
        "ip",
        d.ip.as_ref(),
        "e.g. 10.10.1.* or 1.84",
        Field::IpPattern,
        Field::IpPolarity,
        d.ip_exclude,
    );
    dimension(
        &mut rows,
        "Subnet",
        "cidr",
        d.subnet.as_ref(),
        "e.g. 10.10.1.0/24",
        Field::SubnetPattern,
        Field::SubnetPolarity,
        d.subnet_exclude,
    );

    // Neutral Discard, primary Apply — one filled button per form.
    // Nothing here destroys saved state, so no red.
    let actions = [
        Action::new(
            "  [Esc] Discard  ",
            focus == Field::Cancel,
            ActionKind::Neutral,
            field_hint(Field::Cancel),
        ),
        Action::new(
            "  [Enter] Apply  ",
            focus == Field::Apply,
            ActionKind::Primary,
            field_hint(Field::Apply),
        ),
    ];

    let tail = modal_form::form_tail(
        &rows,
        modal.error.as_deref(),
        field_hint(focus),
        KEYS,
        &actions,
    );
    // The payload IS the caret: `render_modal` hands it back so
    // `render_overlay` can place the real terminal cursor on the focused
    // text row, the same contract `subnet_modal` uses.
    rows.finish(tail)
}

/// One-line guidance for the focused row.
fn field_hint(f: Field) -> &'static str {
    match f {
        Field::NamePattern => "glob over the device name \u{b7} `*` wildcard, no regex",
        Field::IpPattern => "glob over the client address \u{b7} `*` wildcard",
        Field::SubnetPattern => {
            "CIDR tested against the row's client IP \u{b7} reaches unmapped devices too"
        }
        Field::NamePolarity | Field::IpPolarity | Field::SubnetPolarity => {
            "\u{2190}/\u{2192} flips this predicate \u{b7} all predicates are ANDed"
        }
        Field::Cancel => "close without changing the applied filter",
        Field::Apply => "apply \u{b7} returns to the newest page",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft(
        name: Option<&str>,
        ip: Option<&str>,
        subnet: Option<&str>,
    ) -> AdvancedClientFilterDto {
        AdvancedClientFilterDto {
            name: name.map(str::to_string),
            ip: ip.map(str::to_string),
            subnet: subnet.map(str::to_string),
            ..Default::default()
        }
    }

    /// Esc must not be able to half-apply. The draft is a copy; only a
    /// successful `try_apply` hands anything back.
    #[test]
    fn the_draft_is_a_copy_of_what_is_applied() {
        let applied = draft(Some("laptop"), None, None);
        let mut modal = QueryLogFilterModal::open(&applied);
        modal.push_char('X');
        assert_eq!(modal.draft.name.as_deref(), Some("laptopX"));
        assert_eq!(
            applied.name.as_deref(),
            Some("laptop"),
            "editing the draft must not reach the applied filter"
        );
    }

    /// A malformed CIDR is REFUSED, not dropped. A dropped subnet
    /// predicate renders as a full log the operator reads as "no traffic
    /// from that subnet" — the failure has to be visible as a failure.
    #[test]
    fn a_malformed_subnet_is_refused_and_focuses_the_offending_row() {
        let mut modal = QueryLogFilterModal::open(&draft(None, None, Some("10.10.1.0/99")));
        modal.focus = Field::Apply;
        assert!(modal.try_apply().is_none());
        assert_eq!(modal.error.as_deref(), Some(QLOG_FILTER_BAD_CIDR));
        assert_eq!(
            modal.focus,
            Field::SubnetPattern,
            "the refusal must land the operator on the row that caused it"
        );

        let mut ok = QueryLogFilterModal::open(&draft(None, None, Some("10.10.1.0/24")));
        assert!(ok.try_apply().is_some());
        assert!(ok.error.is_none());
    }

    /// A blank subnet is not a malformed one.
    #[test]
    fn a_blank_subnet_applies_cleanly() {
        let mut modal = QueryLogFilterModal::open(&draft(Some("*ioel*"), None, Some("   ")));
        assert!(modal.try_apply().is_some());
    }

    /// Tab order must reach every row AND both actions, and wrap. A
    /// polarity row that Tab cannot reach is a control the operator can
    /// see and not use.
    #[test]
    fn tab_order_reaches_every_field_and_wraps() {
        let mut modal = QueryLogFilterModal::open(&AdvancedClientFilterDto::default());
        let mut seen = vec![modal.focus];
        for _ in 0..Field::ORDER.len() - 1 {
            modal.focus_next();
            seen.push(modal.focus);
        }
        assert_eq!(seen, Field::ORDER.to_vec());
        modal.focus_next();
        assert_eq!(modal.focus, Field::NamePattern, "Tab wraps");
        modal.focus_prev();
        assert_eq!(modal.focus, Field::Apply, "Shift-Tab wraps the other way");
    }

    /// Typing goes to the focused row and nowhere else; polarity keys
    /// only fire on polarity rows.
    #[test]
    fn edits_land_only_on_the_focused_row() {
        let mut modal = QueryLogFilterModal::open(&AdvancedClientFilterDto::default());
        modal.focus = Field::IpPattern;
        modal.push_char('1');
        modal.push_char('0');
        assert_eq!(modal.draft.ip.as_deref(), Some("10"));
        assert!(modal.draft.name.is_none());
        assert!(modal.draft.subnet.is_none());

        modal.toggle_polarity();
        assert!(
            !modal.draft.ip_exclude,
            "a text row must not consume the polarity key"
        );

        modal.focus = Field::IpPolarity;
        modal.toggle_polarity();
        assert!(modal.draft.ip_exclude);
        modal.push_char('z');
        assert_eq!(
            modal.draft.ip.as_deref(),
            Some("10"),
            "typing on a polarity row must not edit the neighbouring text"
        );
    }

    /// Backspacing a field empty returns it to `None`, so a field the
    /// operator cleared stops counting as an applied predicate.
    #[test]
    fn clearing_a_field_makes_it_absent_not_empty() {
        let mut modal = QueryLogFilterModal::open(&draft(Some("ab"), None, None));
        modal.focus = Field::NamePattern;
        modal.backspace();
        assert_eq!(modal.draft.name.as_deref(), Some("a"));
        modal.backspace();
        assert!(modal.draft.name.is_none());
        assert!(modal.draft.is_empty());
    }
}
