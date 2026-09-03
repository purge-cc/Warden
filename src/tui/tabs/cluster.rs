//! Cluster tab — the operator-facing view of cluster sync.
//!
//! Role-adaptive, read-only:
//! - **Primary** → a roster table (self-row first; NODE / ROLE / STATUS / QPS
//!   / BLOCK% / SHARE%, `—` for STALE rows) with the live generations in the
//!   card title, over a per-node detail card that follows the `j`/`k` cursor.
//! - **Secondary** → a single sync-state card (peer / sync age / converged /
//!   applied hashes / last poll).
//!
//! Data is `app.cluster_status` (an [`ClusterStatusDto`] polled on the
//! heartbeat cadence — see `ipc_poller::fetch_cluster_status`). The whole tab
//! is gated at the nav layer behind `cluster` + `[cluster].enabled`, so
//! `render` is only ever reached when the tab is visible. Detail fields are
//! exactly what `RosterEntryDto` carries — no per-node generations/cache-hit
//! (those are cluster-wide and live in the titles / secondary card).
//!
//! ## Not here
//! - Keys:  `mod.rs::handle_cluster_key` (`j`/`k` move the roster cursor)
//! - Form:  none — read-only, no modal
//! - State: `app::ClusterState` (`selected_name`, `table_state`)
//! - Tests: render + pure fns here; key handling in `tui/tests/`, declared from `mod.rs`

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, TableState};
use ratatui::Frame;

use crate::cluster::observe::SyncHealth;
use crate::ipc::protocol::{ClusterStatusDto, RosterEntryDto};
use crate::tui::app::App;
use crate::tui::theme::{self, T};
use crate::tui::ui::render_section_chrome;

const GLYPH_SOLID: &str = "\u{25cf}"; // ● healthy / error
const GLYPH_HOLLOW: &str = "\u{25cc}"; // ◌ transient / degraded

/// View-layer parse of the DTO's stringly `role` field. A value other than
/// the two known roles (a future role, casing drift) maps to `Unknown` so the
/// tab renders an explicit "unknown role" card instead of silently falling
/// into the primary roster — which on a non-primary node shows the misleading
/// "no nodes yet" (clu-02). Distinct from the daemon-side
/// `config::schema::ClusterRole` (which has no Unknown — the daemon's own role
/// is always valid; the untrusted boundary is the wire string the TUI reads).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClusterRoleView {
    Primary,
    Secondary,
    Unknown,
}

impl ClusterRoleView {
    pub(crate) fn parse(role: &str) -> Self {
        match role {
            "primary" => ClusterRoleView::Primary,
            "secondary" => ClusterRoleView::Secondary,
            _ => ClusterRoleView::Unknown,
        }
    }
}

pub fn render(f: &mut Frame, area: Rect, app: &mut App) {
    let Some(status) = app.cluster_status.as_ref() else {
        render_no_view(f, area);
        return;
    };

    // A daemon that answers with `enabled = false` is not clustering at all
    // (`[cluster] enabled = false`, or a daemon with no observe handle —
    // `socket_server::handle_cluster_status`). It answers `role: "primary"` with
    // everything else defaulted, which the primary branch below used to draw as
    // a healthy primary with "no nodes yet". A standalone node must not read as
    // a converged cluster.
    if !status.enabled {
        render_not_active(f, area);
        return;
    }

    match ClusterRoleView::parse(&status.role) {
        ClusterRoleView::Secondary => {
            // Secondary carries no roster — one full-height sync-state card.
            render_secondary_card(f, area, status);
        }
        ClusterRoleView::Primary => {
            // Primary: roster table on top, per-node detail below.
            let rows = Layout::vertical([Constraint::Min(6), Constraint::Length(8)]).split(area);
            render_roster(
                f,
                rows[0],
                status,
                app.cluster.selected_name.as_deref(),
                &mut app.cluster.table_state,
            );
            render_node_detail(f, rows[1], app, status);
        }
        ClusterRoleView::Unknown => render_unknown_role(f, area, status),
    }
}

/// No DTO in hand. This is the first-poll case **and** the poll-stopped case,
/// and the wording has to serve both: the TUI cannot tell "the answer has not
/// arrived yet" from "the answers stopped arriving".
///
/// It used to read *"waiting for first cluster poll…"*, which after the first
/// answer is simply false. Saying "waiting for the first poll" in a state that
/// is also "the answers stopped arriving" would move the lie rather than
/// remove it.
///
/// **A failing poll does not reach this state.** The poll site keeps the
/// previous DTO on error — `if let Ok(..)`, "on error keep the last-known
/// view" — so a broken TUI-to-daemon link shows stale data, not this. The
/// wording above is kept because it is the right wording for when the drop
/// does land; dropping the DTO on the first error would blank the tab on a
/// transient IPC hiccup, so it needs a sustained-failure threshold.
fn render_no_view(f: &mut Frame, area: Rect) {
    let content = render_section_chrome(f, area, "Cluster", T.info);
    f.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(
                " no live cluster view",
                Style::default().fg(T.warning).add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                " the local daemon has not answered a cluster status",
                Style::default().fg(T.text_muted),
            )),
            Line::from(Span::styled(
                " poll yet, or has stopped answering.",
                Style::default().fg(T.text_muted),
            )),
        ]),
        content,
    );
}

/// The daemon answered, and said it is not clustering.
fn render_not_active(f: &mut Frame, area: Rect) {
    let content = render_section_chrome(f, area, "Cluster \u{00b7} not active", T.text_secondary);
    f.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(
                " this daemon reports clustering disabled",
                Style::default().fg(T.text_primary),
            )),
            Line::from(Span::styled(
                " ([cluster] enabled = false).",
                Style::default().fg(T.text_muted),
            )),
        ]),
        content,
    );
}

/// The daemon reported a role this TUI build doesn't recognise. Show it
/// plainly rather than guessing a layout (clu-02).
fn render_unknown_role(f: &mut Frame, area: Rect, status: &ClusterStatusDto) {
    let content = render_section_chrome(f, area, "Cluster", T.warning);
    f.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(
                format!(" unknown cluster role: {:?}", status.role),
                Style::default().fg(T.warning).add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                " the daemon reported a role this build does not recognise.",
                Style::default().fg(T.text_muted),
            )),
        ]),
        content,
    );
}

// ── Primary: roster table ───────────────────────────────────────────────────

fn render_roster(
    f: &mut Frame,
    area: Rect,
    status: &ClusterStatusDto,
    selected_name: Option<&str>,
    table_state: &mut TableState,
) {
    let title = format!(
        "Cluster \u{00b7} primary \u{00b7} cfg gen {}",
        status.config_generation,
    );
    let content = render_section_chrome(f, area, &title, T.brand_red);

    if status.roster.is_empty() {
        f.render_widget(
            Paragraph::new(Span::styled(
                " no nodes yet (no heartbeats received).",
                Style::default().fg(T.text_muted),
            )),
            content,
        );
        return;
    }

    let header = Row::new(vec![
        Cell::from("NODE"),
        Cell::from("ROLE"),
        Cell::from("STATUS"),
        Cell::from("QPS"),
        Cell::from("BLOCK%"),
        Cell::from("SHARE%"),
    ])
    .style(
        Style::default()
            .fg(T.brand_red)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = status.roster.iter().map(roster_row).collect();
    let selected = Some(resolve_idx(status, selected_name));

    let table = Table::new(
        rows,
        [
            Constraint::Min(14),
            Constraint::Length(5),
            Constraint::Length(7),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(8),
        ],
    )
    .header(header)
    .row_highlight_style(theme::highlight_style());

    super::render_table(f, content, table, table_state, selected);
}

fn roster_row(r: &RosterEntryDto) -> Row<'static> {
    let role = if r.is_self { "self" } else { "peer" };
    if r.online {
        Row::new(vec![
            Cell::from(truncate(&r.name, 16)),
            Cell::from(role),
            Cell::from(Span::styled("online", Style::default().fg(T.success))),
            Cell::from(format!("{:.1}", r.qps)),
            Cell::from(format!("{:.1}", r.blocked_pct)),
            Cell::from(format!("{:.1}", r.share_pct)),
        ])
    } else {
        // Offline: cached rates are stale — dashes, not stale numbers.
        Row::new(vec![
            Cell::from(truncate(&r.name, 16)),
            Cell::from(role),
            Cell::from(Span::styled("STALE", Style::default().fg(T.warning))),
            Cell::from(Span::styled("\u{2014}", Style::default().fg(T.text_muted))),
            Cell::from(Span::styled("\u{2014}", Style::default().fg(T.text_muted))),
            Cell::from(Span::styled("\u{2014}", Style::default().fg(T.text_muted))),
        ])
    }
}

// ── Primary: per-node detail card ───────────────────────────────────────────

fn render_node_detail(f: &mut Frame, area: Rect, app: &App, status: &ClusterStatusDto) {
    let Some(r) = status
        .roster
        .get(resolve_idx(status, app.cluster.selected_name.as_deref()))
    else {
        let content = render_section_chrome(f, area, "Node", T.text_secondary);
        f.render_widget(
            Paragraph::new(Span::styled(" \u{2014}", Style::default().fg(T.text_muted))),
            content,
        );
        return;
    };

    let content = render_section_chrome(
        f,
        area,
        &format!("Node \u{00b7} {}", r.name),
        T.text_secondary,
    );
    let scope = if r.is_self { "self" } else { "peer" };

    let mut lines: Vec<Line<'static>> = Vec::with_capacity(5);
    if r.online {
        lines.push(kv(
            "Status",
            Span::styled(
                format!("{GLYPH_SOLID} online ({scope})"),
                Style::default().fg(T.success).add_modifier(Modifier::BOLD),
            ),
        ));
        lines.push(kv(
            "Queries",
            Span::styled(
                format!(
                    "{} total \u{00b7} {:.1}/s",
                    fmt_count(r.total_queries),
                    r.qps
                ),
                Style::default().fg(T.text_primary),
            ),
        ));
        lines.push(kv(
            "Blocked",
            Span::styled(
                format!("{:.1}%", r.blocked_pct),
                Style::default().fg(theme::blocked_pct_color(r.blocked_pct)),
            ),
        ));
        lines.push(kv(
            "Share",
            Span::styled(
                format!("{:.1}% of cluster qps", r.share_pct),
                Style::default().fg(T.text_primary),
            ),
        ));
    } else {
        lines.push(kv(
            "Status",
            Span::styled(
                format!("{GLYPH_HOLLOW} STALE ({scope})"),
                Style::default().fg(T.warning).add_modifier(Modifier::BOLD),
            ),
        ));
        lines.push(kv(
            "Queries",
            Span::styled(
                format!("{} total \u{00b7} \u{2014}/s", fmt_count(r.total_queries)),
                Style::default().fg(T.text_muted),
            ),
        ));
        lines.push(kv(
            "Blocked",
            Span::styled("\u{2014}", Style::default().fg(T.text_muted)),
        ));
        lines.push(kv(
            "Share",
            Span::styled("\u{2014}", Style::default().fg(T.text_muted)),
        ));
    }
    lines.push(kv(
        "Address",
        Span::styled(r.addr.clone(), Style::default().fg(T.text_primary)),
    ));

    f.render_widget(Paragraph::new(lines), content);
}

// ── Secondary: single sync-state card ───────────────────────────────────────

fn render_secondary_card(f: &mut Frame, area: Rect, status: &ClusterStatusDto) {
    let content = render_section_chrome(
        f,
        area,
        "Cluster \u{00b7} this node (secondary)",
        T.brand_red,
    );

    let mut lines: Vec<Line<'static>> = Vec::with_capacity(4);

    lines.push(kv(
        "Peer",
        Span::styled(
            status.peer.clone().unwrap_or_else(|| "(none)".to_string()),
            Style::default().fg(T.text_primary),
        ),
    ));

    // Sync — the headline health signal: a secondary must be able to state
    // which policy it is applying and how old that answer is, and degrade
    // audibly when it cannot.
    //
    // Classified by the SHARED classifier, not by `converged`. `converged` is
    // `synced_at_least_once && last_poll_ok`, which collapses "has never synced
    // since boot" into "synced, currently erroring" — two states with different
    // remedies (a join/token vs. the primary coming back).
    //
    // `last_sync_secs.is_some()` IS `synced_at_least_once`: the poll loop writes
    // `last_sync` and the flag on the same success branch, so nothing has to be
    // added to the wire DTO to tell the three states apart.
    let health = SyncHealth::of_secondary(status.last_sync_secs.is_some(), status.last_poll_ok);
    let (glyph, text, colour) = match health {
        SyncHealth::Current => (
            GLYPH_SOLID,
            format!(
                "current \u{00b7} confirmed {}",
                confirmed_age(status.last_sync_secs)
            ),
            T.success,
        ),
        // Hollow glyph: degraded, not a settled state. The policy still stands
        // and DNS is unaffected — the card says so on the Applied line.
        SyncHealth::Stale => (
            GLYPH_HOLLOW,
            format!(
                "STALE \u{00b7} last confirmed {}",
                confirmed_age(status.last_sync_secs)
            ),
            T.warning,
        ),
        SyncHealth::NeverSynced => (GLYPH_SOLID, "NEVER SYNCED since boot".to_string(), T.error),
    };
    lines.push(kv(
        "Sync",
        Span::styled(
            format!("{glyph} {text}"),
            Style::default().fg(colour).add_modifier(Modifier::BOLD),
        ),
    ));

    // Applied — the hash, plus what an operator most needs to know in each
    // degraded state. "still filtering" is not decoration: the rule is
    // *degrade audibly, never refuse*, and an operator who reads STALE
    // without it will assume DNS is down and start restarting things.
    let applied = match health {
        SyncHealth::Current => format!("policy {}", short_hash(&status.config_hash)),
        SyncHealth::Stale => format!(
            "policy {} \u{00b7} still filtering",
            short_hash(&status.config_hash)
        ),
        SyncHealth::NeverSynced => {
            "policy \u{2014} \u{00b7} last-good bundle on disk, if any".to_string()
        }
    };
    lines.push(kv(
        "Applied",
        Span::styled(applied, Style::default().fg(T.text_secondary)),
    ));

    let last_poll = match (status.last_poll_ok, &status.last_error) {
        (true, _) => Span::styled("ok", Style::default().fg(T.success)),
        (false, Some(e)) => {
            Span::styled(format!("FAILED \u{2014} {e}"), Style::default().fg(T.error))
        }
        (false, None) => Span::styled("FAILED", Style::default().fg(T.error)),
    };
    lines.push(kv("Last poll", last_poll));

    f.render_widget(Paragraph::new(lines), content);
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Resolve the operator's stable `selected_name` back to a roster index for
/// the current frame; default to the top row (self) when unset or the node
/// dropped out of the roster.
fn resolve_idx(status: &ClusterStatusDto, selected_name: Option<&str>) -> usize {
    selected_name
        .and_then(|name| status.roster.iter().position(|r| r.name == name))
        .unwrap_or(0)
}

/// KV row: ` Label    value`, label padded to 10 so even the longest label
/// here — "Last poll" (9 chars) — keeps a ≥1-space gap before the value (the
/// System-card kv pads to 9 because its longest label is "Upstream" = 8).
fn kv(label: &'static str, value: Span<'static>) -> Line<'static> {
    Line::from(vec![
        Span::raw(" "),
        Span::styled(format!("{label:<10}"), Style::default().fg(T.text_muted)),
        value,
    ])
}

/// `last_sync_secs` → a compact age (`"12s ago"`, `"6m ago"`, `"3h ago"`,
/// `"2d ago"`), or `"never"`.
///
/// **This is the age of the last *confirmation*, not of the policy**, which is
/// why the callers say "confirmed" and never "synced Ns ago". A poll that gets
/// a 304 (bundle unchanged) is a success and refreshes `last_sync`, so a policy
/// authored three days ago and re-confirmed twelve seconds ago reports twelve —
/// true of the confirmation, false of the policy.
fn confirmed_age(last_sync_secs: Option<u64>) -> String {
    let Some(s) = last_sync_secs else {
        return "never".to_string();
    };
    if s < 60 {
        format!("{s}s ago")
    } else if s < 3600 {
        format!("{}m ago", s / 60)
    } else if s < 86_400 {
        format!("{}h ago", s / 3600)
    } else {
        format!("{}d ago", s / 86_400)
    }
}

/// First 10 hex chars + `…`, or `—` for an empty hash (mirrors the CLI's
/// `short_hash`). Keeps the applied-hash line scannable in a narrow card.
fn short_hash(h: &str) -> String {
    if h.is_empty() {
        "\u{2014}".to_string()
    } else if h.len() <= 10 {
        h.to_string()
    } else {
        // `h.get(..10)` is None when byte 10 isn't a char boundary (a
        // non-ASCII / malformed hash) — fall back to the raw string instead
        // of panicking mid-codepoint, mirroring local_dns::trim_audit_ts
        // (clu-01 / ldns-02).
        match h.get(..10) {
            Some(head) => format!("{head}\u{2026}"),
            None => h.to_string(),
        }
    }
}

/// Truncate a display name to `max` chars with an ellipsis (byte-safe for the
/// ASCII node names / IPs the roster carries).
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let head: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{head}\u{2026}")
    }
}

/// Thousands-separated count (e.g. `1,284,003`). Local to keep the tab
/// self-contained — the subnets/dashboard formatters are module-private.
fn fmt_count(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    let len = bytes.len();
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (len - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(*b as char);
    }
    out
}

#[cfg(test)]
mod tests {
    // The whole module is `#[cfg(feature = "cluster")]`, so these tests build
    // only under `cargo test --features cluster` (clu-03 — the tab's first
    // coverage; the helpers below are where clu-01/clu-02 lived).
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn secondary_status(config_hash: &str) -> ClusterStatusDto {
        ClusterStatusDto {
            enabled: true,
            role: "secondary".to_string(),
            peer: Some("10.10.1.94:53".to_string()),
            config_generation: 0,
            config_hash: config_hash.to_string(),
            last_sync_secs: Some(12),
            last_poll_ok: true,
            last_error: None,
            converged: true,
            roster: Vec::new(),
        }
    }

    #[test]
    fn short_hash_buckets() {
        assert_eq!(short_hash(""), "\u{2014}");
        assert_eq!(short_hash("abcdef"), "abcdef");
        assert_eq!(short_hash("0123456789ab"), "0123456789\u{2026}");
    }

    #[test]
    fn short_hash_does_not_panic_on_multibyte_boundary() {
        // clu-01: a hash whose byte 10 falls mid-codepoint must not panic
        // (the old `&h[..10]` did) — fall back to the raw string.
        let s = "\u{1f600}".repeat(4); // 16 bytes; byte 10 is mid-emoji
        assert_eq!(short_hash(&s), s);
    }

    #[test]
    fn truncate_is_char_safe() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world", 5), "hell\u{2026}");
        // Multibyte: keep whole codepoints, never panic.
        assert_eq!(
            truncate(&"\u{1f600}".repeat(5), 3),
            "\u{1f600}\u{1f600}\u{2026}"
        );
    }

    #[test]
    fn fmt_count_groups_thousands() {
        assert_eq!(fmt_count(0), "0");
        assert_eq!(fmt_count(1_000), "1,000");
        assert_eq!(fmt_count(1_284_003), "1,284,003");
    }

    #[test]
    fn confirmed_age_formats() {
        assert_eq!(confirmed_age(None), "never");
        assert_eq!(confirmed_age(Some(5)), "5s ago");
        assert_eq!(confirmed_age(Some(59)), "59s ago");
        assert_eq!(confirmed_age(Some(60)), "1m ago");
        assert_eq!(confirmed_age(Some(372)), "6m ago");
        assert_eq!(confirmed_age(Some(7_200)), "2h ago");
        assert_eq!(confirmed_age(Some(172_800)), "2d ago");
    }

    /// Render a widget and read the cells back as text lines. A handler-level
    /// or helper-level assertion cannot see truncation: the card's `Paragraph`
    /// clips silently, so the only way to know a line survived at this width is
    /// to read the painted cells (`feedback_render_tests_see_what_handler_tests_cannot`).
    fn painted(w: u16, h: u16, draw: impl FnOnce(&mut Frame)) -> Vec<String> {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(draw).unwrap();
        let buf = term.backend().buffer().clone();
        (0..h)
            .map(|y| {
                (0..w)
                    .map(|x| buf[(x, y)].symbol())
                    .collect::<String>()
                    .trim_end()
                    .to_string()
            })
            .collect()
    }

    fn card_lines(status: &ClusterStatusDto) -> Vec<String> {
        painted(60, 10, |f| {
            render_secondary_card(f, Rect::new(0, 0, 60, 10), status)
        })
    }

    fn joined(lines: &[String]) -> String {
        lines.join("\n")
    }

    /// The three states must not read alike. The assertions are on the words an
    /// operator reads, and on the **tail** of each line — a mid-line fragment
    /// passes against a clipped line, which is how a render test goes green
    /// against a broken card.
    #[test]
    fn a_current_secondary_says_current_and_when_it_was_confirmed() {
        let out = joined(&card_lines(&secondary_status("0123456789abcdef")));
        assert!(
            out.contains("current \u{00b7} confirmed 12s ago"),
            "expected the confirmed age, got:\n{out}"
        );
        assert!(
            !out.contains("converged"),
            "`converged` collapses never-synced into erroring; it must not come back:\n{out}"
        );
    }

    #[test]
    fn a_stale_secondary_says_stale_and_that_it_is_still_filtering() {
        let mut s = secondary_status("0123456789abcdef");
        s.last_poll_ok = false;
        s.converged = false;
        s.last_error = Some("heartbeat HTTP 502".into());
        s.last_sync_secs = Some(372);
        let out = joined(&card_lines(&s));
        assert!(
            out.contains("STALE \u{00b7} last confirmed 6m ago"),
            "the stale card must carry the age of the last confirmation:\n{out}"
        );
        // Degrade audibly, never refuse. Without this the operator reads
        // STALE and assumes DNS is down.
        assert!(
            out.contains("still filtering"),
            "a stale secondary is still serving, and the card must say so:\n{out}"
        );
        assert!(
            out.contains("FAILED \u{2014} heartbeat HTTP 502"),
            "the poll error is the operator's only clue to the cause:\n{out}"
        );
    }

    /// The state that reads identically to "synced long ago" if you only have
    /// an age — and the one the old card labelled with the transient
    /// "syncing…".
    #[test]
    fn a_never_synced_secondary_says_so_and_does_not_claim_a_policy() {
        let mut s = secondary_status("");
        s.last_sync_secs = None;
        s.last_poll_ok = false;
        s.converged = false;
        s.last_error = Some("connection refused".into());
        let out = joined(&card_lines(&s));
        assert!(
            out.contains("NEVER SYNCED since boot"),
            "never-synced must be distinguishable from stale:\n{out}"
        );
        assert!(
            !out.contains("syncing"),
            "'syncing…' understates a node that has never synced:\n{out}"
        );
        // The tail of the line, not a fragment of it: this is the longest line
        // the card draws, so it is the one that clips first.
        assert!(
            out.contains("last-good bundle on disk, if any"),
            "the never-synced card must not claim there is no policy at all:\n{out}"
        );
    }

    /// A stale card and a current card must differ in the cells, not only in
    /// the struct — the pair is the point: an implementation that renders one
    /// text for both passes either single test on its own.
    #[test]
    fn the_three_states_paint_differently() {
        let current = card_lines(&secondary_status("0123456789abcdef"));
        let mut s = secondary_status("0123456789abcdef");
        s.last_poll_ok = false;
        let stale = card_lines(&s);
        let mut n = secondary_status("");
        n.last_sync_secs = None;
        n.last_poll_ok = false;
        let never = card_lines(&n);
        assert_ne!(current, stale);
        assert_ne!(stale, never);
        assert_ne!(current, never);
    }

    /// `enabled = false` is what a daemon with `[cluster] enabled = false`
    /// answers — with `role: "primary"` and everything else defaulted. It used
    /// to fall through to the primary branch and paint a healthy-looking
    /// cluster card on a standalone node.
    #[test]
    fn a_disabled_daemon_is_not_drawn_as_a_cluster() {
        let out = joined(&painted(60, 10, |f| {
            render_not_active(f, Rect::new(0, 0, 60, 10))
        }));
        assert!(out.contains("clustering disabled"), "got:\n{out}");
        assert!(out.contains("enabled = false"), "got:\n{out}");
    }

    /// The no-DTO state has to serve both "not yet" and "not any more" — it is
    /// where a failed status fetch lands once the `Err` arm drops the cached
    /// view.
    #[test]
    fn the_empty_view_does_not_claim_it_is_only_the_first_poll() {
        let out = joined(&painted(60, 10, |f| {
            render_no_view(f, Rect::new(0, 0, 60, 10))
        }));
        assert!(out.contains("no live cluster view"), "got:\n{out}");
        assert!(
            out.contains("or has stopped answering."),
            "the tail of the sentence is the half that covers a broken poll:\n{out}"
        );
    }

    #[test]
    fn role_view_parse_tolerates_unknown() {
        assert_eq!(ClusterRoleView::parse("primary"), ClusterRoleView::Primary);
        assert_eq!(
            ClusterRoleView::parse("secondary"),
            ClusterRoleView::Secondary
        );
        assert_eq!(ClusterRoleView::parse(""), ClusterRoleView::Unknown);
        assert_eq!(ClusterRoleView::parse("PRIMARY"), ClusterRoleView::Unknown);
        assert_eq!(ClusterRoleView::parse("observer"), ClusterRoleView::Unknown);
    }

    #[test]
    fn render_secondary_card_does_not_panic_with_multibyte_hash() {
        // Drives short_hash through the real render path with a multibyte hash.
        let backend = TestBackend::new(60, 10);
        let mut term = Terminal::new(backend).unwrap();
        let status = secondary_status(&"\u{1f600}".repeat(6));
        term.draw(|f| render_secondary_card(f, Rect::new(0, 0, 60, 10), &status))
            .unwrap();
    }

    #[test]
    fn render_unknown_role_does_not_panic() {
        let backend = TestBackend::new(60, 10);
        let mut term = Terminal::new(backend).unwrap();
        let mut status = secondary_status("a");
        status.role = "observer".to_string();
        term.draw(|f| render_unknown_role(f, Rect::new(0, 0, 60, 10), &status))
            .unwrap();
    }
}
