//! Local DNS tab — **one** list of every local record, global and
//! per-profile, with non-selectable group headers, plus in-tab Add /
//! Edit / Delete modals and an audit-history side-card.
//!
//! This replaces a master/detail pair of stacked tables. That shape put
//! every profile record two keys away from being seen: `o` to move
//! focus to the lower panel, then `n`/`N` to cycle to the right
//! profile, with `Tab` unavailable for either because it is the global
//! leaf cycle (`ldns_04_tab_still_cycles_leaf`). One list with headers is
//! the shape Devices already uses, and `↑`/`↓` now walk the lot.
//!
//! Data source is [`App::loaded_config`] (the v1 master + includes,
//! refreshed on `r`) — same offline source as Subnets / Devices /
//! Profiles. The daemon is NOT consulted for the records list; that
//! avoids a stale view when the operator is staging edits that haven't
//! been hot-reloaded yet. The Add / Remove modals submit through
//! `cli::commands::local_dns::add_inner` / `remove_inner` — the same
//! single-seat code path the CLI verbs use.
//!
//! Hits column: reads the per-record
//! [`LocalRecordsHits`](crate::tracking::LocalRecordsHits) counter
//! snapshot fetched via `IpcCommand::LocalRecordsHits` on a slow IPC
//! tick into
//! [`LocalDnsState::hits_snapshot`](crate::tui::app::LocalDnsState::hits_snapshot).
//! A `None` snapshot (boot-fresh TUI, IPC not yet polled) renders `—`; a populated
//! snapshot resolves `(scope, domain) → count`.
//!
//! Keybindings (handled in `tui/mod.rs`):
//!   ↑/↓             walk every record, skipping group headers
//!   Home/End        first / last record
//!   PgUp/PgDn       page, clamped at both ends
//!   a / e / d       open the Add / Edit / Remove modal on the focused row
//!   Enter / Esc     open / close the audit side-card on the focused row
//!
//! `o`, `n` and `N` are **unbound** — retired with the stacked panels.
//! `Tab` is untouched and still cycles leaves; that is never negotiable
//! (`ldns_04_tab_still_cycles_leaf`).
//!
//! Empty groups are omitted, headers included: a profile with no records
//! contributes no rows. When the whole list is empty the tab shows
//! [`LOCAL_RECORDS_TAB_EMPTY_GLOBAL`]. One consequence worth knowing:
//! `format_local_records_tab_empty_profile` no longer has a TUI caller —
//! there is no per-profile panel left to be empty. The constant is
//! untouched and the CLI still prints it.
//!
//! ## Not here
//! - Keys:  `mod.rs::handle_local_dns_key` (bindings listed above)
//! - Form:  `tui::local_dns_modal` (the Add/Edit/Remove modal named above)
//! - State: `app::LocalDnsState` (`selected_id`, `modal`, `hits_snapshot`)
//! - Tests: render + pure fns here; key handling in `tui/tests/`, declared from `mod.rs`

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, Wrap};
use ratatui::Frame;

// `format_local_records_tab_empty_profile` is not imported here — with
// empty profile groups omitted there is no per-profile panel left to be
// empty, so the TUI has no caller for it. The constant itself stays
// byte-identical, the CLI still prints it, and the in-file test below
// still pins it through its full path.
use crate::cli::commands::local_dns::LocalRecordScope;
use crate::cli::commands::local_dns::LOCAL_RECORDS_TAB_EMPTY_GLOBAL;
use crate::config::audit::AuditRecord;
use crate::config::loader::LoadedConfig;
use crate::config::settings::{LocalDnsRecord, LocalDnsRecordType};
use crate::tui::app::{App, LocalDnsAuditView};
use crate::tui::theme::{self, T};
use crate::tui::ui::render_section_chrome;

/// Side-card empty-state copy for a record with no `local_records.add`
/// or `local_records.remove` audit history yet (`s44-tui-modal-audit-history`).
pub const LOCAL_RECORDS_SIDE_CARD_AUDIT_EMPTY: &str = "no audit history for this record yet";

/// Width (cells) of the drill-down side-card. Matches the Devices
/// side-card (38 cells — enough for the longest KV row without
/// truncation).
const SIDE_CARD_WIDTH: u16 = 38;

// ── The unified row model ─────────────────────────────────────────────

/// One row of the Local DNS table.
///
/// Deliberately the same shape as `tabs::devices::DeviceRow`: a flat
/// vector interleaving non-selectable headers with selectable records, so
/// one cursor walks both scopes and the skip logic has one definition.
#[derive(Debug, Clone)]
pub enum LocalDnsRow<'a> {
    /// `── Global ──` / `── Profile: kids ──`. Never selectable.
    Header(String),
    /// A record and the scope it lives in.
    Record {
        scope: LocalRecordScope,
        record: &'a LocalDnsRecord,
    },
}

impl LocalDnsRow<'_> {
    pub fn is_selectable(&self) -> bool {
        matches!(self, LocalDnsRow::Record { .. })
    }
}

/// The audit-log spelling of a scope: `"global"` or `"profile:<id>"`.
///
/// One vocabulary for the cursor key, the hits lookup and the side-card,
/// so a record cannot be addressed one way here and another way there —
/// a mismatch here is exactly how the hits column can disagree with the
/// side-card about the same row.
pub fn scope_key(scope: &LocalRecordScope) -> String {
    match scope {
        LocalRecordScope::Global => "global".to_string(),
        LocalRecordScope::Profile(id) => format!("profile:{id}"),
    }
}

/// The operator-stable key for a row: `(scope_key, lowercased domain)`.
/// `None` for a header — the same contract `devices::row_key` has.
pub fn row_key(row: &LocalDnsRow) -> Option<(String, String)> {
    match row {
        LocalDnsRow::Header(_) => None,
        LocalDnsRow::Record { scope, record } => {
            Some((scope_key(scope), record.domain.to_ascii_lowercase()))
        }
    }
}

/// Build the unified row vector: Global first, then each profile in
/// config (`BTreeMap`) order.
///
/// **Empty groups are omitted entirely, headers included.** A header with
/// no rows under it is a claim that something is there. The spec offered
/// "omit the header, or show the header and no rows" and named omission
/// as the cheaper one; it is also the honest one, and applying it to
/// Global as well as to profiles keeps one rule instead of two.
///
/// An all-empty result is how the caller knows to paint
/// [`LOCAL_RECORDS_TAB_EMPTY_GLOBAL`].
pub fn build_rows(loaded: &LoadedConfig) -> Vec<LocalDnsRow<'_>> {
    let mut out = Vec::new();
    let globals = &loaded.config.local_dns.records;
    if !globals.is_empty() {
        out.push(LocalDnsRow::Header("Global".to_string()));
        for record in globals {
            out.push(LocalDnsRow::Record {
                scope: LocalRecordScope::Global,
                record,
            });
        }
    }
    for (id, profile) in loaded.config.profiles.iter() {
        if profile.local_records.is_empty() {
            continue;
        }
        out.push(LocalDnsRow::Header(format!("Profile: {}", id.as_str())));
        for record in &profile.local_records {
            out.push(LocalDnsRow::Record {
                scope: LocalRecordScope::Profile(id.as_str().to_string()),
                record,
            });
        }
    }
    out
}

/// Step the cursor to the next selectable row, skipping headers.
///
/// **Clamps**, does not wrap. Written here rather than reused from
/// `devices::next_selectable_index` because that one still wraps, and
/// a new list shipping with a wrap would be a regression on arrival.
pub fn next_selectable_index(
    rows: &[LocalDnsRow],
    current: Option<usize>,
    forward: bool,
) -> Option<usize> {
    match current {
        Some(i) if i < rows.len() => {
            if forward {
                rows.iter()
                    .enumerate()
                    .skip(i + 1)
                    .find(|(_, r)| r.is_selectable())
                    .map(|(n, _)| n)
                    // Clamp: walking off the end stays put, it does not
                    // teleport to the other end.
                    .or(Some(i))
                    .filter(|n| rows.get(*n).is_some_and(LocalDnsRow::is_selectable))
            } else {
                rows[..i]
                    .iter()
                    .rposition(LocalDnsRow::is_selectable)
                    .or(Some(i))
                    .filter(|n| rows.get(*n).is_some_and(LocalDnsRow::is_selectable))
            }
        }
        // Nothing focused yet (or a stale index): seed at the near end.
        _ => {
            if forward {
                rows.iter().position(LocalDnsRow::is_selectable)
            } else {
                rows.iter().rposition(LocalDnsRow::is_selectable)
            }
        }
    }
}

/// Resolve the stable `(scope, domain)` key to its current index.
pub fn index_of_key(rows: &[LocalDnsRow], want: Option<&(String, String)>) -> Option<usize> {
    let want = want?;
    rows.iter().position(|r| row_key(r).as_ref() == Some(want))
}

pub fn render(f: &mut Frame, area: Rect, app: &mut App) {
    let Some(loaded) = app.loaded_config.as_ref() else {
        render_no_config(f, area);
        return;
    };

    // Side-card split: when the audit view is open and the terminal is
    // wide enough, the list takes the left column and the card the
    // right. The left column is one table, not a 50/50 vertical stack
    // of two.
    let (list_area, side_card) = match app.local_dns.audit_view.as_ref() {
        Some(view) if area.width >= 60 + SIDE_CARD_WIDTH => {
            let cols = Layout::horizontal([
                Constraint::Min(60),
                Constraint::Length(1),
                Constraint::Length(SIDE_CARD_WIDTH),
            ])
            .split(area);
            (cols[0], Some((cols[2], view)))
        }
        _ => (area, None),
    };

    let rows = build_rows(loaded);
    let record_count = rows.iter().filter(|r| r.is_selectable()).count();
    let title = format!("Local DNS ({record_count})");
    let content = render_section_chrome(f, list_area, &title, T.text_secondary);

    if rows.is_empty() {
        // Byte-identical to the CLI's empty state.
        render_empty_state(f, content, LOCAL_RECORDS_TAB_EMPTY_GLOBAL);
    } else {
        // Resolve the anchor here rather than trusting `table_state`: a
        // reload / add / delete reshuffles the rows, and an index-only
        // cursor silently re-points at whatever slid into that slot.
        // Falls back to the first selectable row so the tab never renders
        // with nothing highlighted while records exist.
        let selected = index_of_key(&rows, app.local_dns.selected_id.as_ref())
            .or_else(|| rows.iter().position(LocalDnsRow::is_selectable));
        render_records_table(
            f,
            content,
            &rows,
            selected,
            &mut app.local_dns.table_state,
            app.local_dns.hits_snapshot.as_deref(),
        );
    }

    if let Some((card_area, view)) = side_card {
        render_side_card(f, card_area, app, loaded, view);
    }
}

/// Paint the unified table: group headers as non-selectable divider
/// rows, records as data rows.
///
/// Takes the cursor and the hits snapshot explicitly rather than an
/// `&App`. The coupling was incidental — those three values are all it
/// ever read — and taking them by argument is what lets the render tests
/// exercise real row vectors without standing up a whole `LoadedConfig`.
fn render_records_table(
    f: &mut Frame,
    area: Rect,
    rows: &[LocalDnsRow],
    selected: Option<usize>,
    state: &mut ratatui::widgets::TableState,
    hits_snapshot: Option<&[(String, String, u64)]>,
) {
    let header = Row::new(vec![
        Cell::from("DOMAIN"),
        Cell::from("TYPE"),
        Cell::from("VALUE"),
        Cell::from("SUBDOMAIN"),
        Cell::from("TTL"),
        Cell::from("HITS"),
    ])
    .style(
        Style::default()
            .fg(T.brand_red)
            .add_modifier(Modifier::BOLD),
    );

    let table_rows: Vec<Row> = rows
        .iter()
        .map(|row| match row {
            LocalDnsRow::Header(label) => render_group_header_row(label, area.width),
            LocalDnsRow::Record { scope, record } => {
                render_record_row(record, &scope_key(scope), hits_snapshot)
            }
        })
        .collect();

    let table = Table::new(
        table_rows,
        [
            Constraint::Min(20),    // domain
            Constraint::Length(5),  // type
            Constraint::Min(20),    // value
            Constraint::Length(10), // subdomain
            Constraint::Length(8),  // ttl
            Constraint::Length(8),  // hits
        ],
    )
    .header(header)
    .row_highlight_style(theme::highlight_style());

    super::render_table(f, area, table, state, selected);
}

/// A group divider, styled like the Devices one: em-dash rule, muted,
/// italic — visually not a row you can land on, which is what it is.
fn render_group_header_row<'a>(label: &str, width: u16) -> Row<'a> {
    let used = label.chars().count() + 4;
    let dashes = "\u{2500}".repeat((width as usize).saturating_sub(used).min(60));
    Row::new(vec![Cell::from(Span::styled(
        format!("\u{2500}\u{2500} {label} {dashes}"),
        Style::default()
            .fg(T.text_muted)
            .add_modifier(Modifier::ITALIC),
    ))])
    .style(
        Style::default()
            .fg(T.text_muted)
            .add_modifier(Modifier::ITALIC),
    )
}

fn render_record_row<'a>(
    r: &LocalDnsRecord,
    scope_tag: &str,
    hits_snapshot: Option<&[(String, String, u64)]>,
) -> Row<'a> {
    let subdomain_label = if r.match_subdomains {
        Cell::from(Span::styled(
            "true",
            Style::default()
                .fg(T.brand_red)
                .add_modifier(Modifier::BOLD),
        ))
    } else {
        Cell::from(Span::styled("false", Style::default().fg(T.text_muted)))
    };
    let ttl = match r.ttl_secs {
        Some(n) => Cell::from(n.to_string()),
        None => Cell::from(Span::styled("default", Style::default().fg(T.text_muted))),
    };
    // Hits reads through the daemon snapshot. `None` snapshot
    // (boot-fresh TUI, IPC not yet polled) renders `—`; a populated
    // snapshot resolves `(scope_tag, domain)` and renders 0 for a
    // record that exists but has never been hit. Resolution is shared
    // with the side-card via `hits_for` so both match
    // case-insensitively.
    //
    // `scope_tag` comes from `scope_key`, the same function that
    // builds the cursor key — one spelling for all three consumers.
    let hits = match hits_for(hits_snapshot, scope_tag, r.domain.as_str()) {
        None => Cell::from(Span::styled("\u{2014}", Style::default().fg(T.text_muted))),
        Some(count) => Cell::from(count.to_string()),
    };
    Row::new(vec![
        Cell::from(r.domain.clone()),
        Cell::from(record_type_to_str(r.record_type)),
        Cell::from(r.value.clone()),
        subdomain_label,
        ttl,
        hits,
    ])
}

fn render_empty_state(f: &mut Frame, area: Rect, msg: &str) {
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            format!("  {msg}"),
            Style::default().fg(T.text_secondary),
        )),
    ];
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
}

fn render_no_config(f: &mut Frame, area: Rect) {
    let content = render_section_chrome(f, area, "Local DNS", T.text_secondary);
    f.render_widget(
        Paragraph::new(Span::styled(
            "  could not load config — fix it and press r to retry",
            Style::default().fg(T.text_muted),
        )),
        content,
    );
}

/// Render the audit-history side-card. The card always shows the loaded
/// `LocalDnsAuditView` regardless of whether the focused row still
/// matches — keeping the panel stable lets the operator scroll the
/// underlying list without losing the audit slice they were reading.
/// Refreshes happen in the key handler: navigation re-loads the slice
/// for the new focused row before the next render.
fn render_side_card(
    f: &mut Frame,
    area: Rect,
    app: &App,
    loaded: &LoadedConfig,
    view: &LocalDnsAuditView,
) {
    let title = format!("Local DNS \u{00b7} {}", view.domain);
    let content = render_section_chrome(f, area, &title, T.brand_red);

    let mut lines: Vec<Line<'static>> = Vec::with_capacity(20);

    // Detail block — pulled from the focused row when it still matches
    // the loaded view. If focus moved to an unrelated row (rare; key
    // handler refreshes on ↑/↓/o/n/N) we fall back to a stub that
    // surfaces just the scope + domain so the panel still tells the
    // operator what the audit slice belongs to.
    match focused_record_matching(app, loaded, view) {
        Some(rec) => {
            lines.push(kv_str("Domain", rec.domain.as_str(), T.text_primary));
            lines.push(kv_str(
                "Type",
                record_type_to_str(rec.record_type),
                T.text_primary,
            ));
            lines.push(kv_str("Value", rec.value.as_str(), T.text_primary));
            lines.push(kv_str(
                "Subdomain",
                if rec.match_subdomains {
                    "true"
                } else {
                    "false"
                },
                if rec.match_subdomains {
                    T.brand_red
                } else {
                    T.text_muted
                },
            ));
            let ttl_label = match rec.ttl_secs {
                Some(n) => n.to_string(),
                None => "default".to_string(),
            };
            lines.push(kv(
                "TTL",
                Span::styled(ttl_label, Style::default().fg(T.text_primary)),
            ));
        }
        None => {
            lines.push(kv_str("Domain", view.domain.as_str(), T.text_primary));
        }
    }
    lines.push(kv_str("Scope", scope_label(view).as_str(), T.text_primary));
    lines.push(kv("Hits", hits_span(app, view)));

    lines.push(divider_line());
    lines.push(Line::from(Span::styled(
        " Audit history (last 10)",
        Style::default()
            .fg(T.text_secondary)
            .add_modifier(Modifier::BOLD),
    )));

    if view.entries.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!(" {LOCAL_RECORDS_SIDE_CARD_AUDIT_EMPTY}"),
            Style::default()
                .fg(T.text_muted)
                .add_modifier(Modifier::ITALIC),
        )));
    } else {
        for entry in &view.entries {
            lines.push(audit_entry_line(entry));
        }
    }

    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), content);
}

/// Resolve the currently-focused record only when its `(scope, domain)`
/// matches the loaded audit view. Anything else returns `None` so the
/// renderer falls back to the stub detail block.
fn focused_record_matching<'a>(
    app: &App,
    loaded: &'a LoadedConfig,
    view: &LocalDnsAuditView,
) -> Option<&'a LocalDnsRecord> {
    // One lookup instead of a per-panel branch. The view's
    // `(scope_tag, target_id)` pair is the audit-log spelling, which
    // `scope_key` also produces — so the comparison is one string
    // equality rather than two shapes that have to be kept agreeing.
    let want_scope = if view.scope_tag == "global" {
        "global".to_string()
    } else {
        format!("profile:{}", view.target_id)
    };
    let rows = build_rows(loaded);
    let idx = index_of_key(&rows, app.local_dns.selected_id.as_ref())?;
    match rows.get(idx)? {
        LocalDnsRow::Record { scope, record } => (scope_key(scope) == want_scope
            && record.domain.eq_ignore_ascii_case(&view.domain))
        .then_some(*record),
        LocalDnsRow::Header(_) => None,
    }
}

/// Human-readable scope label rendered on the side-card. Mirrors the
/// audit log shape: `"global"` or `"profile:<id>"`.
fn scope_label(view: &LocalDnsAuditView) -> String {
    if view.scope_tag == "profile" {
        format!("profile:{}", view.target_id)
    } else {
        view.scope_tag.clone()
    }
}

/// Hit count for `(scope_tag, domain)` in the daemon snapshot, matched
/// **case-insensitively**. Single source of truth for both the
/// records table and the audit side-card: an exact `==` in one and
/// `eq_ignore_ascii_case` in the other lets a record whose snapshot
/// casing differs from its TOML casing show HITS `0` in the table but
/// the real count in the side-card. Domains are lowercased at
/// ingestion and lookup elsewhere, but the snapshot and the on-disk
/// record can still disagree on case, so the insensitive compare here
/// is the robust one. `None` snapshot → `None`
/// (boot-fresh, render `—`); present snapshot with no match → `Some(0)`.
fn hits_for(
    snapshot: Option<&[(String, String, u64)]>,
    scope_tag: &str,
    domain: &str,
) -> Option<u64> {
    let snap = snapshot?;
    Some(
        snap.iter()
            .find(|(s, d, _)| s.eq_ignore_ascii_case(scope_tag) && d.eq_ignore_ascii_case(domain))
            .map(|(_, _, c)| *c)
            .unwrap_or(0),
    )
}

/// Hit-count span for the side-card. Reads from the same daemon snapshot
/// the table column already consults (`s44-hits-ipc-verb`) and applies
/// the same `—` boot-fresh / `0` daemon-said-zero semantics.
fn hits_span(app: &App, view: &LocalDnsAuditView) -> Span<'static> {
    let scope_tag = scope_label(view);
    match hits_for(
        app.local_dns.hits_snapshot.as_deref(),
        &scope_tag,
        &view.domain,
    ) {
        None => Span::styled("\u{2014}", Style::default().fg(T.text_muted)),
        Some(count) => Span::styled(count.to_string(), Style::default().fg(T.text_primary)),
    }
}

/// Render one audit entry as a single line: timestamp + verb + uid.
fn audit_entry_line(entry: &AuditRecord) -> Line<'static> {
    let ts = trim_audit_ts(&entry.ts);
    let (verb, color) = match entry.action.as_deref() {
        Some("local_records.add") => ("+ added  ", T.brand_red),
        Some("local_records.remove") => ("\u{2212} removed", T.text_secondary),
        _ => ("? unknown", T.text_muted),
    };
    let uid = entry.uid.map(|u| format!(" uid={u}")).unwrap_or_default();
    Line::from(vec![
        Span::raw(" "),
        Span::styled(ts, Style::default().fg(T.text_muted)),
        Span::raw("  "),
        Span::styled(verb.to_string(), Style::default().fg(color)),
        Span::styled(uid, Style::default().fg(T.text_muted)),
    ])
}

/// Trim the RFC 3339 audit timestamp to `MM-dd HH:mm` for the narrow
/// side-card. Falls back to the raw string if the slice doesn't fit.
fn trim_audit_ts(ts: &str) -> String {
    // Expected shape: "2026-05-04T12:34:56Z" → "05-04 12:34". `.get()`
    // yields None when a slice boundary isn't a char boundary (a non-ASCII
    // byte in a malformed timestamp), so a bad input falls back to the raw
    // string instead of panicking mid-codepoint. (ldns-02)
    match (ts.get(5..10), ts.get(11..16)) {
        (Some(date), Some(time)) if ts.as_bytes().get(10) == Some(&b'T') => {
            format!("{date} {time}")
        }
        _ => ts.to_string(),
    }
}

fn kv(label: &'static str, value: Span<'static>) -> Line<'static> {
    Line::from(vec![
        Span::raw(" "),
        Span::styled(format!("{label:<10}"), Style::default().fg(T.text_muted)),
        value,
    ])
}

fn kv_str(label: &'static str, value: &str, color: Color) -> Line<'static> {
    kv(
        label,
        Span::styled(value.to_string(), Style::default().fg(color)),
    )
}

fn divider_line() -> Line<'static> {
    Line::from(Span::styled(
        "\u{2500}".repeat(SIDE_CARD_WIDTH.saturating_sub(2) as usize),
        Style::default().fg(T.text_muted),
    ))
}

fn record_type_to_str(rt: LocalDnsRecordType) -> &'static str {
    match rt {
        LocalDnsRecordType::A => "A",
        LocalDnsRecordType::AAAA => "AAAA",
        LocalDnsRecordType::CNAME => "CNAME",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::app::App;

    /// Build a row vector from owned records without a `LoadedConfig`.
    /// The renderer only needs the vector; `build_rows` is exercised
    /// separately against a real config below.
    fn rows_of<'a>(
        globals: &'a [LocalDnsRecord],
        profile: Option<(&str, &'a [LocalDnsRecord])>,
    ) -> Vec<LocalDnsRow<'a>> {
        let mut out = Vec::new();
        if !globals.is_empty() {
            out.push(LocalDnsRow::Header("Global".to_string()));
            for r in globals {
                out.push(LocalDnsRow::Record {
                    scope: LocalRecordScope::Global,
                    record: r,
                });
            }
        }
        if let Some((id, recs)) = profile {
            if !recs.is_empty() {
                out.push(LocalDnsRow::Header(format!("Profile: {id}")));
                for r in recs {
                    out.push(LocalDnsRow::Record {
                        scope: LocalRecordScope::Profile(id.to_string()),
                        record: r,
                    });
                }
            }
        }
        out
    }

    fn rec(domain: &str, value: &str) -> LocalDnsRecord {
        LocalDnsRecord {
            domain: domain.into(),
            record_type: LocalDnsRecordType::A,
            value: value.into(),
            match_subdomains: false,
            ttl_secs: None,
        }
    }

    /// One cursor, not `focused_panel` / `focused_profile_idx`. A fresh
    /// tab has no anchor until the first keystroke seeds it — same
    /// contract as Subnets / Profiles.
    #[test]
    fn n6_fresh_local_dns_state_has_no_selection() {
        let app = App::new();
        assert!(app.local_dns.selected_id.is_none());
        assert!(app.local_dns.table_state.selected().is_none());
        assert!(app.local_dns.hits_snapshot.is_none());
    }

    // The hits lookup must match the daemon snapshot case-insensitively
    // — an exact `==` silently reports 0 when the snapshot casing
    // differs from the TOML record, while `eq_ignore_ascii_case` finds
    // the count. Both go through `hits_for`.
    #[test]
    fn hits_for_matches_case_insensitively() {
        let snap = vec![("profile:Kids".to_string(), "Example.COM".to_string(), 7u64)];
        assert_eq!(
            hits_for(Some(&snap), "profile:kids", "example.com"),
            Some(7)
        );
        assert_eq!(
            hits_for(Some(&snap), "PROFILE:KIDS", "EXAMPLE.COM"),
            Some(7)
        );
        // Present snapshot, no such record → daemon-said-zero.
        assert_eq!(hits_for(Some(&snap), "profile:kids", "other.test"), Some(0));
        // Boot-fresh: no snapshot yet → `—` sentinel.
        assert_eq!(hits_for(None, "profile:kids", "example.com"), None);
    }

    // `t3_local_dns_panel_next_cycles_global_to_profile_to_global`
    // and `t3_focus_marker_returns_visible_indicator_when_focused` are
    // GONE, not retargeted. Both tested a member of the panel model
    // itself — `LocalDnsPanel::next` and the `[focus]` marker that said
    // which panel had it — and there is no panel model left to assert
    // about. That is different from `ldns_04_panel_switch_flips_panel_not_leaf`
    // in `mod.rs`, which pinned a BEHAVIOUR (`o` must not change leaf)
    // and is rewritten rather than dropped.

    #[test]
    fn t3_record_type_to_str_covers_all_variants() {
        assert_eq!(record_type_to_str(LocalDnsRecordType::A), "A");
        assert_eq!(record_type_to_str(LocalDnsRecordType::AAAA), "AAAA");
        assert_eq!(record_type_to_str(LocalDnsRecordType::CNAME), "CNAME");
    }

    #[test]
    fn t3_render_empty_state_does_not_panic_on_zero_height() {
        // ratatui rejects zero-height areas internally, so we use a
        // 1×1 minimum which still exercises the render code path.
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let backend = TestBackend::new(40, 4);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            let area = Rect::new(0, 0, 40, 4);
            render_empty_state(f, area, "test message");
        })
        .unwrap();
    }

    #[test]
    fn t3_render_no_config_renders_friendly_message() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let backend = TestBackend::new(60, 6);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            let area = Rect::new(0, 0, 60, 6);
            render_no_config(f, area);
        })
        .unwrap();
        let buffer = term.backend().buffer().clone();
        let mut content = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                content.push_str(buffer[(x, y)].symbol());
            }
        }
        assert!(
            content.contains("could not load config"),
            "no-config message must mention load failure"
        );
    }

    #[test]
    fn t3_render_runs_with_no_records_in_app() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let backend = TestBackend::new(80, 20);
        let mut term = Terminal::new(backend).unwrap();
        let mut app = App::new();
        term.draw(|f| {
            let area = Rect::new(0, 0, 80, 20);
            render(f, area, &mut app);
        })
        .unwrap();
        // Without a loaded config we hit the no-config branch.
        let buffer = term.backend().buffer().clone();
        let mut content = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                content.push_str(buffer[(x, y)].symbol());
            }
        }
        assert!(content.contains("Local DNS"));
    }

    #[test]
    fn t3_global_empty_state_string_byte_pinned() {
        // Bridge to the frozen const T1/T3 frozen-strings table — T4
        // pins these byte-for-byte; this test just asserts the
        // crate-public string matches.
        assert!(LOCAL_RECORDS_TAB_EMPTY_GLOBAL.starts_with("No global"));
        assert!(LOCAL_RECORDS_TAB_EMPTY_GLOBAL.contains("warden local-dns add"));
    }

    /// Kept even though the TUI no longer calls this — the constant is
    /// byte-frozen and the CLI still prints it, so the pin has to
    /// survive the caller. Full path, since the module no longer
    /// imports it.
    #[test]
    fn t3_profile_empty_state_substitutes_profile_id() {
        let s = crate::cli::commands::local_dns::format_local_records_tab_empty_profile("kids");
        assert!(s.contains("'kids'"));
        assert!(s.contains("--profile 'kids'"));
        assert!(s.starts_with("No local"));
    }

    #[test]
    fn t3_render_records_table_displays_subdomain_flag_and_ttl() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let backend = TestBackend::new(120, 10);
        let mut term = Terminal::new(backend).unwrap();
        let records = vec![
            rec("nas.home", "192.168.1.50"),
            LocalDnsRecord {
                domain: "example.test".into(),
                record_type: LocalDnsRecordType::A,
                value: "10.10.1.50".into(),
                match_subdomains: true,
                ttl_secs: Some(7200),
            },
        ];
        let rows = rows_of(&records, None);
        let mut state = ratatui::widgets::TableState::default();
        term.draw(|f| {
            let area = Rect::new(0, 0, 120, 10);
            // No snapshot in this test — `None` triggers the boot-fresh
            // `—` rendering, which the assertion below pins.
            render_records_table(f, area, &rows, Some(1), &mut state, None);
        })
        .unwrap();
        let buffer = term.backend().buffer().clone();
        let mut content = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                content.push_str(buffer[(x, y)].symbol());
            }
        }
        assert!(content.contains("nas.home"));
        assert!(content.contains("example.test"));
        assert!(content.contains("192.168.1.50"));
        assert!(content.contains("10.10.1.50"));
        assert!(content.contains("true")); // match_subdomains badge
        assert!(content.contains("7200")); // explicit TTL
        assert!(content.contains("default")); // ttl_secs=None fallback label
        assert!(content.contains("—")); // hits dash for boot-fresh snapshot
    }

    #[test]
    fn s44_hits_column_shows_count_from_snapshot() {
        // Populated snapshot must replace the boot-fresh `—` with the
        // resolved count. Two records: one with a hit, one without —
        // the second renders `0`, not `—`, because `Some(snap)` means
        // "the daemon has spoken" and a missing key means "never hit".
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let backend = TestBackend::new(120, 10);
        let mut term = Terminal::new(backend).unwrap();
        let records = vec![
            rec("nas.home", "192.168.1.50"),
            rec("intranet.home", "192.168.1.51"),
        ];
        let rows = rows_of(&records, None);
        let snap = vec![("global".to_string(), "nas.home".to_string(), 42_u64)];
        let mut state = ratatui::widgets::TableState::default();
        term.draw(|f| {
            let area = Rect::new(0, 0, 120, 10);
            render_records_table(f, area, &rows, Some(1), &mut state, Some(&snap));
        })
        .unwrap();
        let buffer = term.backend().buffer().clone();
        let mut content = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                content.push_str(buffer[(x, y)].symbol());
            }
        }
        assert!(content.contains("nas.home"));
        assert!(content.contains("intranet.home"));
        assert!(content.contains("42"), "live hit count must render");
        assert!(
            !content.contains("—"),
            "with a populated snapshot the dash must not appear",
        );
    }

    #[test]
    fn s44_hits_column_lookup_keys_on_scope_tag() {
        // A record tagged `profile:kids` in the snapshot must NOT show
        // up under the `global` panel — the scope-tag arm prevents
        // cross-scope leakage. The global cell renders `0` because
        // there's no `global` row for `example.test` in the snapshot.
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let backend = TestBackend::new(120, 6);
        let mut term = Terminal::new(backend).unwrap();
        let records = vec![rec("example.test", "10.10.1.50")];
        let rows = rows_of(&records, None);
        let snap = vec![("profile:kids".to_string(), "example.test".to_string(), 99_u64)];
        let mut state = ratatui::widgets::TableState::default();
        term.draw(|f| {
            let area = Rect::new(0, 0, 120, 6);
            render_records_table(f, area, &rows, Some(1), &mut state, Some(&snap));
        })
        .unwrap();
        let buffer = term.backend().buffer().clone();
        let mut content = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                content.push_str(buffer[(x, y)].symbol());
            }
        }
        assert!(content.contains("example.test"));
        assert!(
            !content.contains("99"),
            "profile-scoped count must not bleed into the global panel",
        );
        assert!(
            !content.contains("—"),
            "with a populated snapshot the dash must not appear, even on miss",
        );
    }

    #[test]
    fn s44_side_card_renders_record_detail_and_audit_history() {
        // Side-card with a populated audit view must surface every KV
        // line + each audit entry's verb. Two entries (one add, one
        // remove) prove the verb-color split path doesn't crash.
        use crate::config::audit::{AuditEvent, AuditRecord, AuditResult};
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let backend = TestBackend::new(120, 30);
        let mut term = Terminal::new(backend).unwrap();

        let mut app = App::new();
        // Synthesise the loaded_config so render() takes the populated
        // path (a None loaded_config short-circuits to render_no_config).
        let toml_src = r#"
schema_version = 3

[upstream]
servers = ["1.1.1.1"]

[[local_dns.records]]
domain = "nas.home"
type = "A"
value = "192.168.1.50"
"#;
        let cfg = toml::from_str::<crate::config::schema::ConfigV1>(toml_src).unwrap();
        app.loaded_config = Some(crate::config::loader::LoadedConfig {
            config: cfg,
            master_path: std::path::PathBuf::from("/tmp/dummy.toml"),
            files_loaded: Vec::new(),
            total_bytes: 0,
            provenance: Default::default(),
            custom_lists: Default::default(),
        });
        // One cursor, anchored by (scope, domain) rather than by a
        // per-panel index.
        app.local_dns.selected_id = Some(("global".to_string(), "nas.home".to_string()));
        app.local_dns.audit_view = Some(crate::tui::app::LocalDnsAuditView {
            scope_tag: "global".to_string(),
            target_id: "global".to_string(),
            domain: "nas.home".to_string(),
            entries: vec![
                AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
                    .with_uid(Some(1000))
                    .with_action("local_records.add")
                    .with_scope("global")
                    .with_target_id("global")
                    .with_domain("nas.home"),
                AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
                    .with_uid(Some(1000))
                    .with_action("local_records.remove")
                    .with_scope("global")
                    .with_target_id("global")
                    .with_domain("nas.home"),
            ],
        });

        term.draw(|f| {
            let area = Rect::new(0, 0, 120, 30);
            render(f, area, &mut app);
        })
        .unwrap();

        let buffer = term.backend().buffer().clone();
        let mut content = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                content.push_str(buffer[(x, y)].symbol());
            }
        }
        // Side-card title + KV lines for the focused record.
        assert!(content.contains("Local DNS"), "side-card title missing");
        assert!(content.contains("nas.home"));
        assert!(content.contains("192.168.1.50"));
        // Audit history header + verbs.
        assert!(content.contains("Audit history"));
        assert!(content.contains("added"));
        assert!(content.contains("removed"));
        assert!(content.contains("uid=1000"));
    }

    #[test]
    fn s44_side_card_empty_audit_renders_friendly_state() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let backend = TestBackend::new(120, 40);
        let mut term = Terminal::new(backend).unwrap();
        let mut app = App::new();
        let toml_src = r#"
schema_version = 3

[upstream]
servers = ["1.1.1.1"]

[[local_dns.records]]
domain = "intranet.home"
type = "A"
value = "192.168.1.51"
"#;
        let cfg = toml::from_str::<crate::config::schema::ConfigV1>(toml_src).unwrap();
        app.loaded_config = Some(crate::config::loader::LoadedConfig {
            config: cfg,
            master_path: std::path::PathBuf::from("/tmp/dummy.toml"),
            files_loaded: Vec::new(),
            total_bytes: 0,
            provenance: Default::default(),
            custom_lists: Default::default(),
        });
        // One cursor, anchored by (scope, domain) rather than by a
        // per-panel index.
        app.local_dns.selected_id = Some(("global".to_string(), "nas.home".to_string()));
        app.local_dns.audit_view = Some(crate::tui::app::LocalDnsAuditView {
            scope_tag: "global".to_string(),
            target_id: "global".to_string(),
            domain: "intranet.home".to_string(),
            entries: Vec::new(),
        });

        term.draw(|f| {
            let area = Rect::new(0, 0, 120, 40);
            render(f, area, &mut app);
        })
        .unwrap();
        let buffer = term.backend().buffer().clone();
        let mut content = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                content.push_str(buffer[(x, y)].symbol());
            }
        }
        // The card's content rect is ~34 cells wide (38 - 4 for chrome
        // padding); ratatui's Wrap{trim:false} can split the empty-state
        // copy across two scanlines, so we match a non-wrapping prefix
        // of the frozen const rather than the full byte sequence.
        assert!(
            content.contains("no audit history"),
            "frozen empty-state copy missing from side-card render",
        );
    }

    #[test]
    fn s44_side_card_collapses_on_narrow_terminal() {
        // <60+38 cells: side-card must collapse so the table still
        // renders. Asserts the layout switch by drawing into a
        // 50-cell-wide buffer and verifying nothing panics + the audit
        // header line does NOT appear (because the card is hidden).
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let backend = TestBackend::new(50, 20);
        let mut term = Terminal::new(backend).unwrap();
        let mut app = App::new();
        let toml_src = r#"
schema_version = 3

[upstream]
servers = ["1.1.1.1"]

[[local_dns.records]]
domain = "nas.home"
type = "A"
value = "192.168.1.50"
"#;
        let cfg = toml::from_str::<crate::config::schema::ConfigV1>(toml_src).unwrap();
        app.loaded_config = Some(crate::config::loader::LoadedConfig {
            config: cfg,
            master_path: std::path::PathBuf::from("/tmp/dummy.toml"),
            files_loaded: Vec::new(),
            total_bytes: 0,
            provenance: Default::default(),
            custom_lists: Default::default(),
        });
        // One cursor, anchored by (scope, domain) rather than by a
        // per-panel index.
        app.local_dns.selected_id = Some(("global".to_string(), "nas.home".to_string()));
        app.local_dns.audit_view = Some(crate::tui::app::LocalDnsAuditView {
            scope_tag: "global".to_string(),
            target_id: "global".to_string(),
            domain: "nas.home".to_string(),
            entries: Vec::new(),
        });

        term.draw(|f| {
            let area = Rect::new(0, 0, 50, 20);
            render(f, area, &mut app);
        })
        .unwrap();
        let buffer = term.backend().buffer().clone();
        let mut content = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                content.push_str(buffer[(x, y)].symbol());
            }
        }
        // Audit header should NOT appear on the collapsed layout.
        assert!(
            !content.contains("Audit history"),
            "side-card must collapse on narrow terminals"
        );
    }

    #[test]
    fn s44_trim_audit_ts_strips_to_month_day_time() {
        assert_eq!(trim_audit_ts("2026-05-04T12:34:56Z"), "05-04 12:34");
        // Malformed input falls back to raw.
        assert_eq!(trim_audit_ts("garbage"), "garbage");
    }

    #[test]
    fn s44_scope_label_renders_profile_qualified() {
        let v = crate::tui::app::LocalDnsAuditView {
            scope_tag: "profile".into(),
            target_id: "kids".into(),
            domain: "x.example".into(),
            entries: Vec::new(),
        };
        assert_eq!(scope_label(&v), "profile:kids");

        let g = crate::tui::app::LocalDnsAuditView {
            scope_tag: "global".into(),
            target_id: "global".into(),
            domain: "x.example".into(),
            entries: Vec::new(),
        };
        assert_eq!(scope_label(&g), "global");
    }

    // ── The unified row model ─────────────────────────────────────────

    fn loaded_from(toml_src: &str) -> crate::config::loader::LoadedConfig {
        let cfg = toml::from_str::<crate::config::schema::ConfigV1>(toml_src).unwrap();
        crate::config::loader::LoadedConfig {
            config: cfg,
            master_path: std::path::PathBuf::from("/tmp/dummy.toml"),
            files_loaded: Vec::new(),
            total_bytes: 0,
            provenance: Default::default(),
            custom_lists: Default::default(),
        }
    }

    const MIXED: &str = r#"
schema_version = 3

[upstream]
servers = ["1.1.1.1"]

[[local_dns.records]]
domain = "nas.home"
type = "A"
value = "192.168.1.50"

[[local_dns.records]]
domain = "printer.home"
type = "A"
value = "192.168.1.60"

[profiles.empty]
display_name = "Empty"

[profiles.kids]
display_name = "Kids"
local_records = [{ domain = "youtube.local", type = "A", value = "10.10.1.9" }]
"#;

    /// The unified row model: both scopes in one vector, headers between
    /// them, and **the empty profile contributes nothing** — not even a
    /// header. A header with no rows under it claims something is there.
    #[test]
    fn n6_build_rows_interleaves_headers_and_omits_empty_groups() {
        let loaded = loaded_from(MIXED);
        let rows = build_rows(&loaded);

        let labels: Vec<String> = rows
            .iter()
            .map(|r| match r {
                LocalDnsRow::Header(h) => format!("H:{h}"),
                LocalDnsRow::Record { record, .. } => format!("R:{}", record.domain),
            })
            .collect();
        assert_eq!(
            labels,
            vec![
                "H:Global",
                "R:nas.home",
                "R:printer.home",
                "H:Profile: kids",
                "R:youtube.local",
            ],
            "empty profile `empty` must contribute no header and no rows"
        );
        assert!(!rows[0].is_selectable(), "a header is never selectable");
        assert!(rows[1].is_selectable());
    }

    /// **The DoD case**: `↓` from the last global record must land on the
    /// first profile record, stepping over the header rather than onto
    /// it. This is the whole point of merging the panels.
    #[test]
    fn n6_down_from_the_last_global_record_reaches_the_first_profile_record() {
        let loaded = loaded_from(MIXED);
        let rows = build_rows(&loaded);
        // index 2 = printer.home, the last Global record.
        let next = next_selectable_index(&rows, Some(2), true).unwrap();
        assert!(
            matches!(&rows[next], LocalDnsRow::Record { record, .. } if record.domain == "youtube.local"),
            "Down must skip the `Profile: kids` header, not land on it"
        );
    }

    /// This list ships clamping from the start; it does not inherit a
    /// wrap to be fixed later.
    #[test]
    fn n6_the_cursor_clamps_at_both_ends() {
        let loaded = loaded_from(MIXED);
        let rows = build_rows(&loaded);
        let last = rows.len() - 1;

        assert_eq!(
            next_selectable_index(&rows, Some(last), true),
            Some(last),
            "Down on the last record stays put, it does not wrap to the first"
        );
        assert_eq!(
            next_selectable_index(&rows, Some(1), false),
            Some(1),
            "Up on the first record stays put — and must NOT land on the \
             header at index 0"
        );
        // Nothing focused seeds at the near end for either direction.
        assert_eq!(next_selectable_index(&rows, None, true), Some(1));
        assert_eq!(next_selectable_index(&rows, None, false), Some(last));
        // An empty vector has nowhere to go.
        assert_eq!(next_selectable_index(&[], None, true), None);
    }

    /// The cursor is a `(scope, domain)` key, not an index — so deleting
    /// a record ABOVE the focused one keeps the highlight on the same
    /// record instead of sliding it onto a neighbour.
    #[test]
    fn n6_the_anchor_survives_a_reshuffle_that_an_index_would_not() {
        let loaded = loaded_from(MIXED);
        let rows = build_rows(&loaded);
        let want = row_key(&rows[2]).unwrap();
        assert_eq!(want, ("global".to_string(), "printer.home".to_string()));
        assert_eq!(index_of_key(&rows, Some(&want)), Some(2));

        // Same config minus the first global record: `printer.home` is
        // now at index 1, and an index-based cursor would have kept
        // pointing at 2 — which is the profile header.
        let shrunk = loaded_from(
            r#"
schema_version = 3

[upstream]
servers = ["1.1.1.1"]

[[local_dns.records]]
domain = "printer.home"
type = "A"
value = "192.168.1.60"

[profiles.kids]
display_name = "Kids"
local_records = [{ domain = "youtube.local", type = "A", value = "10.10.1.9" }]
"#,
        );
        let rows2 = build_rows(&shrunk);
        assert_eq!(index_of_key(&rows2, Some(&want)), Some(1));
        assert!(
            matches!(&rows2[2], LocalDnsRow::Header(_)),
            "fixture check: an index-based cursor really would have been \
             stranded on a header here"
        );
    }

    /// A scope key must not collide across scopes. The same domain in
    /// Global and in a profile are two different records.
    #[test]
    fn n6_row_key_separates_the_same_domain_in_two_scopes() {
        let g = rec("shared.home", "10.0.0.1");
        let p = rec("SHARED.home", "10.0.0.2");
        let rows = rows_of(
            std::slice::from_ref(&g),
            Some(("kids", std::slice::from_ref(&p))),
        );
        let keys: Vec<_> = rows.iter().filter_map(row_key).collect();
        assert_eq!(
            keys,
            vec![
                ("global".to_string(), "shared.home".to_string()),
                ("profile:kids".to_string(), "shared.home".to_string()),
            ],
            "scope disambiguates, and the domain half is lowercased so a \
             casing difference on disk cannot lose the cursor"
        );
    }

    /// Whole list empty → the frozen global empty string, byte-identical.
    #[test]
    fn n6_an_all_empty_config_shows_the_frozen_global_empty_state() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut app = App::new();
        app.loaded_config = Some(loaded_from(
            "schema_version = 3\n\n[upstream]\nservers = [\"1.1.1.1\"]\n\n\
             [profiles.kids]\ndisplay_name = \"Kids\"\n",
        ));
        assert!(build_rows(app.loaded_config.as_ref().unwrap()).is_empty());

        let mut term = Terminal::new(TestBackend::new(120, 12)).unwrap();
        term.draw(|f| render(f, Rect::new(0, 0, 120, 12), &mut app))
            .unwrap();
        let buffer = term.backend().buffer().clone();
        let mut content = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                content.push_str(buffer[(x, y)].symbol());
            }
        }
        // The const wraps across the 120-cell rows, so pin a distinctive
        // fragment rather than the whole line.
        assert!(
            content.contains("No global"),
            "the frozen empty-state string must still paint: {content}"
        );
    }

    /// Both scopes render in one table, and the group headers are
    /// visible — the operator can tell which records are which.
    #[test]
    fn n6_render_paints_one_table_with_both_scopes_and_their_headers() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut app = App::new();
        app.loaded_config = Some(loaded_from(MIXED));

        let mut term = Terminal::new(TestBackend::new(120, 16)).unwrap();
        term.draw(|f| render(f, Rect::new(0, 0, 120, 16), &mut app))
            .unwrap();
        let buffer = term.backend().buffer().clone();
        let mut content = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                content.push_str(buffer[(x, y)].symbol());
            }
        }
        assert!(content.contains("nas.home"), "global record missing");
        assert!(
            content.contains("youtube.local"),
            "profile record must be visible WITHOUT a panel switch"
        );
        assert!(content.contains("Global"), "global header missing");
        assert!(content.contains("Profile: kids"), "profile header missing");
        assert!(
            !content.contains("Empty"),
            "the empty profile must not appear at all"
        );
    }
}
