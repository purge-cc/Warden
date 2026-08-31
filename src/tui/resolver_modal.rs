//! Source-IP resolver as a global modal overlay.
//!
//! Replaces the former `tabs/resolver.rs` leaf. Opened with the global
//! hotkey `s` from any leaf; pre-fills the input from the focused row
//! when invoked on Query Log or Devices. Owns its own input buffer +
//! last-result + error so the modal-priority gate in `tui::mod` can
//! claim every keystroke until `Esc` (no leading `i` ceremony).
//!
//! The 5-level attribution body of [`resolve_for_tui`] is a lift from
//! the pre-S52 leaf — same `ProfileResolver::build` invocation, same
//! strings. Only the input source moved (modal buffer instead of leaf
//! state) and, in §4.61 Wave 4b, the order the strings come back in:
//! see that function for why the answer now leads.

use std::net::IpAddr;

use ratatui::layout::Rect;
use ratatui::Frame;

use crate::lists::manager::merge_sources_with_blocklists;
use crate::lists::source_key::SourceBitMap;
use crate::profiles::{resolver::ResolveLevel, ProfileResolver};
use crate::tui::app::{App, Leaf};
use crate::tui::modal_form::{self, Action, ActionKind, NoticeSpec, ProseRow, ValueKind};

/// State for the open modal. Cleared (`= None`) when the modal closes.
#[derive(Debug, Clone, Default)]
pub struct ResolverModal {
    pub input: String,
    pub last_result: Option<Vec<String>>,
    pub error: Option<String>,
    /// Telemetry tag for the pre-fill source. Not user-visible; kept so
    /// a future debugging session can tell the QueryLog vs Devices vs
    /// manual-typed cases apart without re-reading the dispatch site.
    pub prefilled_from: Option<&'static str>,
}

impl ResolverModal {
    /// Open with no pre-fill — operator types from scratch.
    pub fn open_blank() -> Self {
        Self {
            prefilled_from: Some("manual"),
            ..Self::default()
        }
    }

    /// Open with the input buffer pre-filled. `source` is a short
    /// telemetry tag (`"queries"`, `"devices"`).
    pub fn open_with(prefill: String, source: &'static str) -> Self {
        Self {
            input: prefill,
            prefilled_from: Some(source),
            ..Self::default()
        }
    }

    /// Resolve the current input against `app.loaded_config`. On
    /// success `last_result` carries the 5-level attribution lines and
    /// `error` is cleared; on failure the inverse.
    pub fn submit(&mut self, app: &App) {
        match resolve_for_tui(app, &self.input) {
            Ok(lines) => {
                self.last_result = Some(lines);
                self.error = None;
            }
            Err(msg) => {
                self.error = Some(msg);
                self.last_result = None;
            }
        }
    }

    /// `Ctrl-U` clear: empty the buffer + drop any prior result. The
    /// modal stays open so the operator can type a new IP without a
    /// re-open round-trip.
    pub fn clear_input(&mut self) {
        self.input.clear();
        self.last_result = None;
        self.error = None;
    }

    /// rev-2607 (#12): paste is delivered through the crossterm
    /// `Event::Paste` path (`handle_paste` in `tui::mod`), which never
    /// goes through `handle_resolver_modal_key` — so it cannot rely on
    /// that handler's dispatch to keep `input` and the displayed result
    /// in sync. Append the pasted text here, in the one place both
    /// sides of that split are visible, and drop the previous
    /// result/error along with it: it described the pre-paste query,
    /// not the one now in the buffer.
    pub fn paste_into_input(&mut self, text: &str) {
        self.input.push_str(text);
        self.invalidate_result();
    }

    /// Typing and backspacing mutate `input` exactly as a paste does, so
    /// they invalidate the displayed result for the same reason. Fixing
    /// only the paste path would have left the commoner route — typing —
    /// still showing a result for a query the buffer no longer holds.
    /// Routing every mutation through these keeps the invariant in one
    /// place instead of relying on each call site to remember it.
    pub fn push_char(&mut self, c: char) {
        self.input.push(c);
        self.invalidate_result();
    }

    pub fn pop_char(&mut self) {
        self.input.pop();
        self.invalidate_result();
    }

    /// The rendered result/error describes the query that produced it. The
    /// moment `input` changes it no longer does, so it must go.
    fn invalidate_result(&mut self) {
        self.last_result = None;
        self.error = None;
    }
}

/// Capture-at-open helper: reads the focused row's IP off the in-memory
/// snapshot at the moment `s` is pressed. Returns the (ip, source) pair
/// when a useful pre-fill exists, `None` otherwise (modal opens blank).
///
/// Pre-fill is a quality-of-life shortcut, not a contract — the modal
/// owns its buffer from the moment it opens, so subsequent scrolling
/// of the underlying leaf cannot retroactively change the resolved IP.
pub fn prefill_from_active_leaf(app: &App) -> Option<(String, &'static str)> {
    match app.active_leaf {
        Leaf::QueryLog => {
            let idx = app.query_log.table_state.selected()?;
            let entry = app.query_log.entries.get(idx)?;
            let ip = entry.client_ip.trim();
            if ip.is_empty() {
                None
            } else {
                Some((ip.to_string(), "queries"))
            }
        }
        Leaf::Devices => {
            let view = app.device_view.as_ref()?;
            let rows = crate::tui::tabs::devices::build_rows(view, app.devices.group_by);
            let idx =
                crate::tui::tabs::devices::current_selection(&app.devices.table_state, &rows)?;
            match rows.get(idx)? {
                crate::tui::tabs::devices::DeviceRow::Mapped(m) if !m.ip.trim().is_empty() => {
                    Some((m.ip.trim().to_string(), "devices"))
                }
                crate::tui::tabs::devices::DeviceRow::Unmapped(u) if !u.ip.trim().is_empty() => {
                    Some((u.ip.trim().to_string(), "devices"))
                }
                _ => None,
            }
        }
        _ => None,
    }
}

// ── render (§4.61 Wave 4b — Archetype C via `modal_form`) ─────────────
//
// Not one colour is chosen in this module; every span comes out of
// `modal_form`. That is the wave's acceptance criterion rather than an
// aesthetic preference — R1 is twelve surfaces each re-deriving the
// ecosystem colour rule locally until they drift apart. Pinned by
// `no_hand_rolled_colour_or_chrome_in_this_module`.
//
// This is a *not-a-form*: nothing is edited, nothing is saved, there is no
// focus ring to Tab around. One live query row and the attribution it
// produced, which is Archetype C exactly.

/// Modal width, wider than the 64 the Wave-2 forms use — and the reason
/// is measured, not aesthetic.
///
/// An Archetype-F row splits its label and value into separate spans, so
/// the width it needs is the value's. These rows instead arrive from
/// [`resolve_for_tui`] as single pre-padded strings carrying a 17-column
/// label field, and the longest of them — the `Overrides:` placeholder —
/// is 67 characters, 69 once [`modal_form::prose_row`] adds its 2-cell
/// indent. `prose_row` truncates where the pre-migration body wrapped
/// (style-01.1), so anything narrower would silently eat that tail
/// instead of costing it a second row. At 74 the inner rect is 72, 71
/// once the scrollbar claims its column. Pinned by
/// `widest_attribution_line_is_not_ellipsized_at_the_modal_width`.
const W: u16 = 74;

/// Label of the live query row. Its width sets the caret column.
const QUERY_LABEL: &str = "Source IP   ";

/// Where the caret sits when the buffer is empty: `prose_row`'s 2-cell
/// indent plus the label. ASCII, so bytes and columns agree.
const QUERY_COL: usize = 2 + QUERY_LABEL.len();

/// Nav-key legend — the same three keys the pre-migration footer
/// advertised, in the same order. D7′ changes chrome, layout and colour
/// and leaves the keying alone, so the legend must not move either.
const KEYS: &str = "Enter resolve \u{b7} Ctrl-U clear \u{b7} Esc close";

/// Draw the modal as an Archetype-C overlay anchored on the tab content
/// rect.
///
/// `anchor` is the tab content area (§4.61 D18), never `f.area()`. This
/// modal answers the global `s` from every page, so it is the one most
/// likely to be opened over an arbitrary tab — and the header, the menu
/// card and the footer legend have to survive it (§4.62 N1). Before this
/// wave the parameter was accepted and discarded (`let _ = anchor;`) and
/// the overlay centred on the whole frame, painting over all three.
///
/// Honouring it costs rows. At the declared 80×24 floor the content rect
/// is 14 tall, so the interior is 12: three for the pinned head, five for
/// the pinned tail, **four** for content. `overlay::centered_rect` clamps
/// rather than scrolls, so a flat body would simply lose its bottom —
/// which is why the body is a [`modal_form::ScrollBody`] and the
/// attribution leads with its answer (see [`resolve_for_tui`]).
/// [`modal_form::render_modal`] owns the chrome, the height request, the
/// two-pass width resolution and the viewport; what it guarantees is that
/// the tail is allocated first, so the action row is on screen whatever
/// the terminal does.
pub fn render_overlay(f: &mut Frame, anchor: Rect, modal: &ResolverModal) {
    let spec = notice(modal);
    let render =
        modal_form::render_modal(f, anchor, W, |w| (modal_form::notice_body(&spec, w), ()));

    // The query row is field-region row 0 and nothing else can take
    // focus, so the caret target is unconditional; `place_cursor` no-ops
    // if that row is ever scrolled out of view. This replaces the `_` the
    // pre-migration body appended to the buffer — a real terminal cursor
    // is what the operator-validated Lists modal uses.
    let caret = u16::try_from(QUERY_COL + modal.input.chars().count()).unwrap_or(u16::MAX);
    render.place_cursor(f, 0, caret);
}

/// The whole modal as one Archetype-C spec.
fn notice(modal: &ResolverModal) -> NoticeSpec {
    NoticeSpec {
        hint_rows: None,
        title: "Resolver".to_string(),
        desc: "which profile a client IP resolves to, and why".to_string(),
        prose: prose_rows(modal),
        choices: Vec::new(),
        error: modal.error.clone(),
        hint: hint(modal).to_string(),
        keys: KEYS.to_string(),
        // Both actions carry their key in the label because neither is a
        // Tab target — this modal has no focus ring (D7′), so they
        // orient rather than receive focus, the same reason the Subnets
        // remove-confirm labels its `[y]` / `[n]`. `Resolve` is the one
        // filled action; `Close` is colour-only.
        actions: vec![
            Action::new("  [Esc] Close  ", false, ActionKind::Neutral, ""),
            Action::new("  [Enter] Resolve  ", false, ActionKind::Primary, ""),
        ],
    }
}

/// Guidance for the tail, by state.
///
/// Empty while an error is pending: `hint_or_error_rows` prefers the
/// error and would drop this anyway, and saying so here keeps the two
/// from reading as if they stack.
fn hint(modal: &ResolverModal) -> &'static str {
    if modal.error.is_some() {
        ""
    } else if modal.input.trim().is_empty() {
        "type a client IP — resolution is offline, against the loaded config"
    } else if modal.last_result.is_some() {
        "editing the address clears the result: it described the previous query"
    } else {
        "press Enter to resolve this address"
    }
}

/// The scrolling region: the live query row, then the attribution.
///
/// The query row is first because it is first that must survive — the
/// viewport shows the top of this vector, and at the floor only four of
/// its rows are on screen. That makes the order load-bearing rather than
/// cosmetic; [`resolve_for_tui`] carries the other half of the argument.
fn prose_rows(modal: &ResolverModal) -> Vec<ProseRow> {
    let mut rows = vec![ProseRow::emphasis(
        format!("{QUERY_LABEL}{}", modal.input),
        ValueKind::Identity,
    )];
    if let Some(result) = modal.last_result.as_deref() {
        rows.extend(result.iter().map(|l| attribution_row(l)));
    }
    rows
}

/// Colour one attribution line by what it says.
///
/// Prefix matching decides **decoration only** — the ordering that keeps
/// the answer on screen is structural, built by [`resolve_for_tui`]. A
/// label this misses renders plain, which is a dull row, not a lost one.
fn attribution_row(line: &str) -> ProseRow {
    if line.contains("<REFUSED") {
        ProseRow::emphasis(line.to_string(), ValueKind::Blocking)
    } else if line.starts_with("Active profile:") {
        ProseRow::emphasis(line.to_string(), ValueKind::Healthy)
    } else {
        ProseRow::plain(line.to_string())
    }
}

// ── core ──────────────────────────────────────────────────────────────

/// Build a [`ProfileResolver`] on demand and compute the attribution
/// lines for `input`. Same offline computation as `warden resolve`, and
/// every line is byte-identical to the string that command prints.
///
/// **The order is presentation order, not `warden resolve`'s order**
/// (§4.61 Wave 4b). The D18 anchor leaves four content rows at the 80×24
/// floor and `overlay::centered_rect` clamps rather than scrolls, so
/// whatever sits at the bottom of this vector is what the operator does
/// not get to read — and with the old order that was `Active profile`,
/// the answer to the only question the modal is asked. So the answer
/// leads, its `Match level` and the provenance that explains it follow,
/// and the rows that merely restate the query the operator just typed go
/// last. Only the order moved; no string changed, which is why the
/// `submit_*` tests above still assert the same text.
///
/// This function has no caller outside the TUI, so the reordering is a
/// presentation decision about this surface and does not reach the CLI.
/// Pinned by `floor_keeps_the_answer_on_screen_for_every_resolve_level`.
pub fn resolve_for_tui(app: &App, input: &str) -> Result<Vec<String>, String> {
    let loaded = app
        .loaded_config
        .as_ref()
        .ok_or_else(|| "config is not loaded — fix it and press r to retry".to_string())?;
    let ip: IpAddr = input
        .trim()
        .parse()
        .map_err(|_| format!("\"{}\" is not a valid IP address", input.trim()))?;

    let (merged_sources, _trust) =
        merge_sources_with_blocklists(&loaded.config.lists.sources, &loaded.config.blocklists);
    let source_bits = SourceBitMap::build(&merged_sources, &loaded.config.blocklists)
        .map_err(|e| format!("lists.sources: {e}"))?;
    let resolver = ProfileResolver::build(&loaded.config, &source_bits, &loaded.custom_lists);
    let res = resolver.resolve(&ip);

    let mut lines: Vec<String> = Vec::new();

    // 1 — the answer.
    match res.profile.as_ref() {
        Some(p) => lines.push(format!("Active profile:  {}", p.name)),
        None => lines.push("Active profile:  <REFUSED>".to_string()),
    }

    // 2 — why, and via what. `ProfileResolver::resolve` nulls the other
    // two `matched_*` fields in every branch it returns from, so the
    // provenance below contributes exactly one row, never three.
    match res.level {
        Some(level) => {
            let label = match level {
                ResolveLevel::DeviceDirect => "1 (direct device profile)",
                ResolveLevel::Schedule => "2 (active schedule override)",
                ResolveLevel::Group => "3 (group membership)",
                ResolveLevel::Subnet => "4 (subnet longest-prefix)",
                ResolveLevel::GlobalDefault => "5 (global default_profile)",
            };
            lines.push(format!("Match level:     {label}"));
            if let Some(s) = res.matched_schedule.as_ref() {
                lines.push(format!("Active schedule: {}", s.as_str()));
            }
            if let Some(g) = res.matched_group.as_ref() {
                lines.push(format!("Via group:       {}", g.as_str()));
            }
            if let Some(sb) = res.matched_subnet.as_ref() {
                lines.push(format!("Via subnet:      {}", sb.as_str()));
            }
        }
        None => {
            lines.push("Match level:     <REFUSED — no level matched>".to_string());
        }
    }

    // 3 — who. Still worth a row: an IP that resolved through an
    // unexpected device row is the commonest surprise this modal exists
    // to explain.
    match res.device_id.as_ref() {
        Some(id) => {
            let display = res.device_name.as_deref().unwrap_or(id.as_str());
            lines.push(format!("Matched device:  {} ({})", id.as_str(), display));
        }
        None => lines.push("Matched device:  <none>".to_string()),
    }

    // 4 — an echo of the query row the operator is looking at, and a
    // placeholder for a feature that does not exist yet. Last because
    // they are the two rows worth losing first.
    lines.push(format!("Source IP:       {ip}"));
    lines.extend(render_overlay_badge(res.device_id.as_ref()));

    Ok(lines)
}

/// Sprint 43 T2 placeholder for the per-device overlay badge — kept as
/// a one-function swap point so T4 (when `[[devices]]` gains
/// `allow_rules` / `deny_rules` / `override_profile_deny`) can wire the
/// real `+N override(s)` count without scattered edits.
fn render_overlay_badge(_device_id: Option<&crate::config::schema::Id>) -> Vec<String> {
    vec!["Overrides:       <none yet — populated in the device-overlay phase>".to_string()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::loader::{LoadedConfig, ProvenanceMap};
    use crate::config::schema::{ConfigV1, Device, Id, Profile};
    use crate::ipc::protocol::QueryLogDto;
    use crate::tui::app::App;
    use std::path::PathBuf;

    fn mk_id(s: &str) -> Id {
        Id::new(s).unwrap()
    }

    fn empty_loaded() -> LoadedConfig {
        let c = ConfigV1 {
            schema_version: 1,
            ..ConfigV1::default()
        };
        LoadedConfig {
            config: c,
            master_path: PathBuf::new(),
            files_loaded: Vec::new(),
            total_bytes: 0,
            provenance: ProvenanceMap::new(),
            custom_lists: Default::default(),
        }
    }

    fn loaded_with_default_profile() -> LoadedConfig {
        let mut cfg = ConfigV1 {
            schema_version: 1,
            ..ConfigV1::default()
        };
        cfg.profiles.insert(
            "default".into(),
            Profile {
                display_name: "Default".into(),
                ..Default::default()
            },
        );
        cfg.server.default_profile = Some(mk_id("default"));
        LoadedConfig {
            config: cfg,
            master_path: PathBuf::new(),
            files_loaded: Vec::new(),
            total_bytes: 0,
            provenance: ProvenanceMap::new(),
            custom_lists: Default::default(),
        }
    }

    fn loaded_with_device_match() -> LoadedConfig {
        let mut cfg = ConfigV1 {
            schema_version: 1,
            ..ConfigV1::default()
        };
        cfg.profiles.insert(
            "default".into(),
            Profile {
                display_name: "Default".into(),
                ..Default::default()
            },
        );
        cfg.devices.push(Device {
            id: mk_id("laptop"),
            display_name: "Laptop".into(),
            ip: Some("10.0.0.42".parse().unwrap()),
            mac: None,
            mac_aliases: vec![],
            profile: Some(mk_id("default")),
            groups: vec![],
            owner: None,
            device_type: None,
            department: None,
            notes: None,
            allow_rules: vec![],
            deny_rules: vec![],
            override_profile_deny: false,
            unfiltered: false,
            network_name: None,
            network_name_wildcard: false,
        });
        cfg.server.default_profile = Some(mk_id("default"));
        // §4.39 / profiles-h1: `laptop` is pin-less (mac: None); keep
        // MAC enforcement off so it still resolves device-direct.
        cfg.server.enforce_device_mac = false;
        LoadedConfig {
            config: cfg,
            master_path: PathBuf::new(),
            files_loaded: Vec::new(),
            total_bytes: 0,
            provenance: ProvenanceMap::new(),
            custom_lists: Default::default(),
        }
    }

    #[test]
    fn open_blank_starts_empty_with_no_result() {
        let m = ResolverModal::open_blank();
        assert!(m.input.is_empty());
        assert!(m.last_result.is_none());
        assert!(m.error.is_none());
        assert_eq!(m.prefilled_from, Some("manual"));
    }

    #[test]
    fn submit_with_invalid_ip_sets_error_not_result() {
        let mut app = App::new();
        app.loaded_config = Some(empty_loaded());
        let mut m = ResolverModal::open_with("not-an-ip".into(), "manual");
        m.submit(&app);
        assert!(m.last_result.is_none());
        let err = m
            .error
            .as_deref()
            .expect("invalid IP must produce an error");
        assert!(
            err.contains("not a valid IP address"),
            "error must explain the parse failure; got: {err}"
        );
    }

    #[test]
    fn submit_with_valid_ip_against_default_config_returns_global_default() {
        let mut app = App::new();
        app.loaded_config = Some(loaded_with_default_profile());
        let mut m = ResolverModal::open_with("203.0.113.7".into(), "manual");
        m.submit(&app);
        assert!(m.error.is_none(), "valid IP must not error");
        let lines = m.last_result.as_deref().expect("result lines");
        let blob = lines.join("\n");
        assert!(blob.contains("Source IP:       203.0.113.7"));
        assert!(
            blob.contains("Match level:     5 (global default_profile)"),
            "level-5 fallback expected; got:\n{blob}"
        );
        assert!(blob.contains("Active profile:  default"));
    }

    #[test]
    fn submit_with_device_match_includes_matched_device_line() {
        let mut app = App::new();
        app.loaded_config = Some(loaded_with_device_match());
        let mut m = ResolverModal::open_with("10.0.0.42".into(), "manual");
        m.submit(&app);
        let lines = m.last_result.as_deref().expect("result lines");
        let blob = lines.join("\n");
        assert!(
            blob.contains("Matched device:  laptop (Laptop)"),
            "device-direct match must surface the matched device id + display name; got:\n{blob}"
        );
        assert!(
            blob.contains("Match level:     1 (direct device profile)"),
            "level-1 device-direct match expected; got:\n{blob}"
        );
    }

    #[test]
    fn clear_input_zeroes_buffer_but_keeps_open() {
        let mut m = ResolverModal::open_with("10.0.0.1".into(), "manual");
        m.last_result = Some(vec!["dummy".into()]);
        m.error = Some("dummy".into());
        m.clear_input();
        assert!(m.input.is_empty());
        assert!(m.last_result.is_none());
        assert!(m.error.is_none());
    }

    #[test]
    fn prefill_helper_returns_query_log_client_when_focused() {
        use ratatui::widgets::TableState;

        let mut app = App::new();
        app.active_leaf = Leaf::QueryLog;
        app.query_log.entries.push(QueryLogDto {
            timestamp: "2026-05-03T12:00:00Z".into(),
            client_ip: "10.0.0.42".into(),
            client_name: None,
            domain: "example.com".into(),
            query_type: "A".into(),
            result: "ALLOWED".into(),
            response_time_us: 0,
            cname_chain_via: None,
        });
        let mut ts = TableState::default();
        ts.select(Some(0));
        app.query_log.table_state = ts;

        let prefill = prefill_from_active_leaf(&app).expect("query log row must seed pre-fill");
        assert_eq!(prefill.0, "10.0.0.42");
        assert_eq!(prefill.1, "queries");
    }

    // ── §4.61 Wave 4b: render, the anchor, and the 80×24 floor ───────
    //
    // `ui.rs` declares MIN_WIDTH 80 × MIN_HEIGHT 24. At that size the tab
    // content rect this overlay anchors on (D18) is
    // `24 − 4 header − 5 menu card − 1 footer = 14` rows, leaving a
    // 12-row interior: 3 for the pinned head, 5 for the pinned tail, 4
    // for content. `overlay::centered_rect` CLAMPS rather than scrolls,
    // so anything past that budget is silently cut. Every assertion
    // below reads the RENDERED BUFFER, never the line vector — in every
    // past instance of this defect (`lists-modal-min-height-clip`) the
    // vector was correct and only the render was wrong.

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

    /// Render the real [`render_overlay`] into a `w`×`h` backend, handing
    /// the whole frame in as the anchor — so `h` **is** the tab content
    /// rect's height, which is the number that matters (D18).
    fn render_overlay_in(modal: &ResolverModal, w: u16, h: u16) -> String {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| render_overlay(f, f.area(), modal)).unwrap();
        dump_buffer(term.backend().buffer())
    }

    /// Drive a real resolution through [`ResolverModal::submit`] rather
    /// than hand-building `last_result`. A hand-built fixture drifts from
    /// what [`resolve_for_tui`] actually emits, and the whole point of
    /// the floor tests is what the operator sees.
    fn resolved(loaded: LoadedConfig, ip: &str) -> ResolverModal {
        let mut app = App::new();
        app.loaded_config = Some(loaded);
        let mut m = ResolverModal::open_with(ip.to_string(), "manual");
        m.submit(&app);
        assert!(m.error.is_none(), "fixture must resolve: {:?}", m.error);
        m
    }

    fn mk_device(id: &str, ip: &str, profile: Option<&str>, groups: Vec<&str>) -> Device {
        Device {
            id: mk_id(id),
            display_name: id.to_uppercase(),
            ip: Some(ip.parse().unwrap()),
            mac: None,
            mac_aliases: vec![],
            profile: profile.map(mk_id),
            groups: groups.into_iter().map(mk_id).collect(),
            owner: None,
            device_type: None,
            department: None,
            notes: None,
            allow_rules: vec![],
            deny_rules: vec![],
            override_profile_deny: false,
            unfiltered: false,
            network_name: None,
            network_name_wildcard: false,
        }
    }

    fn mk_profile(name: &str) -> Profile {
        Profile {
            display_name: name.to_string(),
            ..Default::default()
        }
    }

    fn wrap(cfg: ConfigV1) -> LoadedConfig {
        LoadedConfig {
            config: cfg,
            master_path: PathBuf::new(),
            files_loaded: Vec::new(),
            total_bytes: 0,
            provenance: ProvenanceMap::new(),
            custom_lists: Default::default(),
        }
    }

    /// Level 2 — an always-open schedule (`days = ["all"]`,
    /// `hours = "00:00-00:00"`) so the fixture is wall-clock independent;
    /// a window with real edges would make this test flaky by the hour.
    fn loaded_with_schedule_match() -> LoadedConfig {
        use crate::config::schema::{Schedule, ScheduleTargetType};
        let mut cfg = ConfigV1 {
            schema_version: 1,
            ..ConfigV1::default()
        };
        cfg.profiles.insert("default".into(), mk_profile("Default"));
        cfg.profiles
            .insert("sched-prof".into(), mk_profile("Sched"));
        cfg.devices
            .push(mk_device("tablet", "10.0.0.44", Some("default"), vec![]));
        cfg.schedules.push(Schedule {
            id: mk_id("bedtime"),
            display_name: "Bedtime".into(),
            target_type: ScheduleTargetType::Device,
            target_id: mk_id("tablet"),
            profile: mk_id("sched-prof"),
            days: vec!["all".into()],
            hours: "00:00-00:00".into(),
            expires_at: None,
        });
        cfg.server.default_profile = Some(mk_id("default"));
        cfg.server.enforce_device_mac = false;
        wrap(cfg)
    }

    /// Level 3 — device with no direct profile, resolved via its group.
    fn loaded_with_group_match() -> LoadedConfig {
        use crate::config::schema::Group;
        let mut cfg = ConfigV1 {
            schema_version: 1,
            ..ConfigV1::default()
        };
        cfg.profiles.insert("default".into(), mk_profile("Default"));
        cfg.profiles
            .insert("group-prof".into(), mk_profile("Group"));
        cfg.devices
            .push(mk_device("printer", "10.0.0.45", None, vec!["iot"]));
        cfg.groups.push(Group {
            id: mk_id("iot"),
            display_name: "IoT".into(),
            profile: mk_id("group-prof"),
            priority: 0,
            devices: vec![mk_id("printer")],
        });
        cfg.server.default_profile = Some(mk_id("default"));
        cfg.server.enforce_device_mac = false;
        wrap(cfg)
    }

    /// Level 4 — no device row at all; longest-prefix subnet wins.
    fn loaded_with_subnet_match() -> LoadedConfig {
        use crate::config::schema::Subnet;
        let mut cfg = ConfigV1 {
            schema_version: 1,
            ..ConfigV1::default()
        };
        cfg.profiles.insert("default".into(), mk_profile("Default"));
        cfg.profiles
            .insert("subnet-prof".into(), mk_profile("Subnet"));
        cfg.subnets.push(Subnet {
            id: mk_id("guest-wifi"),
            display_name: "Guest WiFi".into(),
            cidrs: vec!["10.9.0.0/24".into()],
            profile: mk_id("subnet-prof"),
            priority: 0,
        });
        cfg.server.default_profile = Some(mk_id("default"));
        wrap(cfg)
    }

    /// §4.61 D18 — the anchor is the tab content rect, and the overlay
    /// has to stay inside it.
    ///
    /// **Fail-before:** `HEAD` accepted `anchor` and threw it away
    /// (`let _ = anchor;`), centring on `f.area()` instead. On the 80×24
    /// floor that puts the modal's top rows over the header and the menu
    /// card — which §4.62 N1 forbids outright, and which is the same
    /// full-bleed occlusion §4.2.1 measured on Profiles.
    #[test]
    fn overlay_stays_inside_the_anchor_and_never_covers_the_header() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        // The 80×24 floor split the way `ui.rs` splits it: 4 header rows,
        // a 5-row menu card, 14 rows of content, 1 footer row.
        const CONTENT_Y: u16 = 9;
        const CONTENT_H: u16 = 14;

        let modal = resolved(loaded_with_device_match(), "10.0.0.42");
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| {
            let anchor = Rect {
                x: 0,
                y: CONTENT_Y,
                width: 80,
                height: CONTENT_H,
            };
            render_overlay(f, anchor, &modal);
        })
        .unwrap();
        let dump = dump_buffer(term.backend().buffer());

        for (y, row) in dump.lines().enumerate() {
            let y = y as u16;
            if (CONTENT_Y..CONTENT_Y + CONTENT_H).contains(&y) {
                continue;
            }
            assert!(
                row.trim().is_empty(),
                "row {y} lies outside the tab content rect ({CONTENT_Y}..{}) but the \
                 overlay painted it — header, menu card or footer legend occluded:\n{dump}",
                CONTENT_Y + CONTENT_H
            );
        }
    }

    /// The two things a clip silently takes away, asserted together.
    ///
    /// Needles are chosen so each can only match the row it names: the
    /// live query row is `Source IP` + three spaces, while the
    /// attribution's own line is `Source IP:` **with a colon** — a Wave-2
    /// floor test went green on a needle that also matched a band one row
    /// above, so "it passed" and "the row is on screen" are not the same
    /// claim unless the needle is unique.
    #[test]
    fn floor_keeps_the_action_row_and_the_query_row_on_screen_together() {
        let modal = resolved(loaded_with_device_match(), "10.0.0.42");
        let dump = render_overlay_in(&modal, 80, 14);

        assert!(
            dump.contains("Source IP   10.0.0.42"),
            "the live query row is off screen at the 80x24 floor:\n{dump}"
        );
        assert!(
            dump.contains("[Enter] Resolve"),
            "the action row is off screen at the 80x24 floor — nothing tells the \
             operator how to commit:\n{dump}"
        );
    }

    /// The answer survives the floor for **every** resolve level.
    ///
    /// This is the test that decides whether the presentation order in
    /// [`resolve_for_tui`] is right. Levels 2/3/4 each insert one
    /// provenance row (`Active schedule:` / `Via group:` / `Via subnet:`)
    /// that levels 1 and 5 do not have, and with four content rows at the
    /// floor one extra row is the difference between reading the answer
    /// and reading only the provenance. Asserting a single level would
    /// pass with a wrong order.
    #[test]
    fn floor_keeps_the_answer_on_screen_for_every_resolve_level() {
        let cases: Vec<(&str, LoadedConfig, &str, &str)> = vec![
            (
                "1 device-direct",
                loaded_with_device_match(),
                "10.0.0.42",
                "Active profile:  default",
            ),
            (
                "2 schedule",
                loaded_with_schedule_match(),
                "10.0.0.44",
                "Active profile:  sched-prof",
            ),
            (
                "3 group",
                loaded_with_group_match(),
                "10.0.0.45",
                "Active profile:  group-prof",
            ),
            (
                "4 subnet",
                loaded_with_subnet_match(),
                "10.9.0.7",
                "Active profile:  subnet-prof",
            ),
            (
                "5 global default",
                loaded_with_default_profile(),
                "203.0.113.7",
                "Active profile:  default",
            ),
        ];

        for (label, loaded, ip, needle) in cases {
            let modal = resolved(loaded, ip);
            let dump = render_overlay_in(&modal, 80, 14);
            assert!(
                dump.contains(needle),
                "level {label}: `{needle}` is off screen at the 80x24 floor — the \
                 operator sees the provenance but not the answer:\n{dump}"
            );
        }
    }

    /// The caret lands one cell past the typed address, on the query row.
    ///
    /// Every other assertion here reads buffer *symbols*, and the caret is
    /// not one — it is backend state, so a dump cannot show it and the
    /// migration replaced a `_` that WAS a symbol with a cursor that is
    /// not. Without this the whole caret would be untested.
    ///
    /// Asserted relationally against the rendered query row rather than
    /// against literal coordinates, so it pins three things at once:
    /// that `place_cursor` is called at all, that [`QUERY_COL`] still
    /// tracks [`QUERY_LABEL`], and — the durable one — that field-region
    /// row 0 is inside the viewport. That last currently holds because
    /// `notice_body` derives `focus_row` solely from `choices` and this
    /// surface has none, so `offset` is pinned at 0. Give this modal
    /// choices and the field region can scroll; `place_cursor` would then
    /// early-return and the caret would vanish silently. Nothing else
    /// records that dependency.
    #[test]
    fn caret_sits_one_cell_past_the_typed_address_on_the_query_row() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let modal = resolved(loaded_with_device_match(), "10.0.0.42");
        let mut term = Terminal::new(TestBackend::new(80, 14)).unwrap();
        term.draw(|f| render_overlay(f, f.area(), &modal)).unwrap();
        let cursor = term.get_cursor_position().unwrap();
        let dump = dump_buffer(term.backend().buffer());

        const NEEDLE: &str = "Source IP   10.0.0.42";
        let (row, line) = dump
            .lines()
            .enumerate()
            .find(|(_, l)| l.contains(NEEDLE))
            .unwrap_or_else(|| panic!("query row is not on screen at all:\n{dump}"));

        assert_eq!(
            cursor.y as usize, row,
            "caret is on row {} but the query row rendered on row {row} — it is \
             sitting on some other row's text:\n{dump}",
            cursor.y
        );
        // Byte offset → column: the border glyphs are multi-byte, so
        // `find` cannot be used as a column directly.
        let byte_at = line.find(NEEDLE).expect("just matched");
        let expected_x = line[..byte_at].chars().count() + NEEDLE.chars().count();
        assert_eq!(
            cursor.x as usize, expected_x,
            "caret is at column {} but the address ends at {expected_x} — QUERY_COL \
             has drifted from QUERY_LABEL:\n{dump}",
            cursor.x
        );
    }

    /// The widest line this modal can emit must survive its width.
    ///
    /// The pre-migration body wrapped (`Wrap { trim: false }`, style-01.1)
    /// so a long attribution line cost a second row rather than its tail;
    /// `prose_row` truncates instead, to keep the row count deterministic.
    /// That trade is only safe while the modal is wide enough for the
    /// longest line, so the width is pinned here rather than left as a
    /// comment.
    #[test]
    fn widest_attribution_line_is_not_ellipsized_at_the_modal_width() {
        // Roomy anchor: this is a question about width, not about the
        // vertical budget.
        let modal = resolved(loaded_with_device_match(), "10.0.0.42");
        let dump = render_overlay_in(&modal, 100, 40);
        assert!(
            dump.contains("device-overlay phase>"),
            "the longest attribution line lost its tail to an ellipsis — W is too \
             narrow, and truncating where the pre-migration body wrapped is a \
             regression, not a cosmetic:\n{dump}"
        );
    }

    /// §4.61 R1, as a test rather than a claim in a commit message: a
    /// surface that reaches for the theme directly is a surface that will
    /// drift from the other eleven. Needles are split so this assertion
    /// cannot match itself.
    #[test]
    fn no_hand_rolled_colour_or_chrome_in_this_module() {
        let src = include_str!("resolver_modal.rs");
        for needle in [
            concat!("Style::default()", ".fg("),
            concat!("Color", "::Rgb("),
            concat!("T", ".brand_red"),
            concat!("Borders", "::ALL"),
        ] {
            assert!(
                !src.contains(needle),
                "{needle} in resolver_modal.rs — chrome and colour belong in modal_form"
            );
        }
    }

    #[test]
    #[ignore = "visual aid: cargo test resolver_visual_dump -- --ignored --nocapture"]
    fn resolver_visual_dump() {
        let modal = resolved(loaded_with_group_match(), "10.0.0.45");
        println!(
            "--- roomy anchor ---\n{}",
            render_overlay_in(&modal, 100, 40)
        );
        println!(
            "--- the 80x24 floor (14-row content rect) ---\n{}",
            render_overlay_in(&modal, 80, 14)
        );
        let typing = ResolverModal::open_with("10.0.0.".into(), "manual");
        println!(
            "--- mid-type, no result ---\n{}",
            render_overlay_in(&typing, 80, 14)
        );
        let mut app = App::new();
        app.loaded_config = Some(empty_loaded());
        let mut bad = ResolverModal::open_with("nope".into(), "manual");
        bad.submit(&app);
        println!("--- error ---\n{}", render_overlay_in(&bad, 80, 14));
    }
}
