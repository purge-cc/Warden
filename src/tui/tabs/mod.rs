#[cfg(feature = "cluster")]
pub mod cluster;
pub mod custom_lists;
pub mod dashboard;
pub mod devices;
pub mod file;
pub mod groups;
pub mod labels;
pub mod lists;
pub mod local_dns;
pub mod logs;
pub mod profiles;
pub mod query_log;
pub mod rules;
pub mod settings;
pub mod subnets;

/// Select `selected` on `state`, then paint `table` against it.
///
/// `state` must be the tab's real, persisted `TableState` — never a
/// clone. Ratatui reads `state.offset` on entry and only nudges it far
/// enough to keep the selected row visible (see `Table::render_ref` /
/// `get_row_bounds` in ratatui); it also clamps both `offset` and
/// `selected` to the current row count before doing so, so a value
/// carried over from a frame with a different row count can never point
/// at content that doesn't exist. A `TableState` rebuilt fresh every
/// frame throws that carried offset away, so ratatui has nothing to
/// nudge from and instead jumps straight to whatever offset keeps the
/// selected row on-screen — for a row past the first page, that lands
/// the selection at the very edge of the viewport on every single
/// render.
pub(super) fn render_table(
    f: &mut ratatui::Frame,
    area: ratatui::layout::Rect,
    table: ratatui::widgets::Table<'_>,
    state: &mut ratatui::widgets::TableState,
    selected: Option<usize>,
) {
    state.select(selected);
    f.render_stateful_widget(table, area, state);
}

/// Runtime-enumerated coverage: every scrollable table in `tabs/` must
/// keep ratatui's own scroll offset
/// across renders instead of resetting it from a fresh `TableState` every
/// frame. One assertion loop over a table of cases, not one `#[test]` per
/// tab — same shape as `tests/tui_modal_colour_coverage.rs`.
///
/// Lives here rather than under the top-level `tests/` directory that
/// sibling file uses: `tui::app` and `tui::tabs` are private modules
/// (`mod app;` / `mod tabs;` in `tui/mod.rs`), visible only to `tui`'s own
/// descendants, so an external integration test cannot name `App` or any
/// tab's `render`. This module is a descendant of `tui` (`tui::tabs::
/// scroll_persistence_tests`) and can.
#[cfg(test)]
mod scroll_persistence_tests {
    use crate::tui::app::App;
    use ratatui::backend::TestBackend;
    use ratatui::layout::Rect;
    use ratatui::Terminal;

    /// Rows per fixture — comfortably more than two screens at the area
    /// below, so the deep/shallow indices are never near a page edge.
    const ROWS: usize = 60;
    /// Wide enough to clear every tab's narrow-layout threshold (the
    /// widest is `custom_lists::SPLIT_THRESHOLD` at 86) and tall enough
    /// that `ROWS` still needs several pages.
    fn area() -> Rect {
        Rect::new(0, 0, 120, 30)
    }
    /// Selected row for the first render — deep enough that no tab's
    /// viewport can show it without scrolling.
    const DEEP: usize = 40;
    /// One row up from `DEEP`, still off the first page. The
    /// discriminating step: a monotonic walk in one direction converges
    /// to the same offset whether or not the previous frame's offset was
    /// kept (see `render_table`'s doc comment), so the harness must move
    /// the cursor *up* from a deep position, not just select a deep row
    /// once.
    const SHALLOW: usize = DEEP - 1;

    /// Generates `ROWS` entries for every entity kind `render()` might
    /// read off `app.loaded_config`, so one parse serves every
    /// config-backed case. Ids are zero-padded so lexicographic order
    /// (what a `BTreeMap<String, Profile>` iterates in) agrees with
    /// declaration order (what a `Vec` iterates in) — the fixture must
    /// not care which one a given tab happens to use.
    fn big_config_toml() -> String {
        let mut s =
            String::from("schema_version = 3\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n\n");
        for i in 0..ROWS {
            s += &format!("[profiles.prof-{i:02}]\ndisplay_name = \"Prof {i:02}\"\n\n");
        }
        for i in 0..ROWS {
            s += &format!(
                "[[subnets]]\nid = \"sub-{i:02}\"\ndisplay_name = \"Sub {i:02}\"\n\
                 cidrs = [\"10.{i}.0.0/24\"]\nprofile = \"prof-00\"\n\n"
            );
        }
        for i in 0..ROWS {
            s += &format!("[[devices]]\nid = \"dev-{i:02}\"\ndisplay_name = \"Dev {i:02}\"\n\n");
        }
        for i in 0..ROWS {
            s += &format!(
                "[[groups]]\nid = \"grp-{i:02}\"\ndisplay_name = \"Grp {i:02}\"\n\
                 profile = \"prof-00\"\n\n"
            );
        }
        for i in 0..ROWS {
            s += &format!(
                "[[labels]]\nid = \"lbl-{i:02}\"\nkind = \"owner\"\n\
                 display_name = \"Lbl {i:02}\"\n\n"
            );
        }
        for i in 0..ROWS {
            s += &format!("[[custom_lists]]\nid = \"cl-{i:02}\"\ndisplay_name = \"CL {i:02}\"\n\n");
        }
        for i in 0..ROWS {
            s += &format!(
                "[[admin_rules]]\nid = \"rule-{i:02}\"\nrule = \"||d{i:02}.example^\"\n\n"
            );
        }
        for i in 0..ROWS {
            s += &format!(
                "[[local_dns.records]]\ndomain = \"rec{i:02}.home\"\ntype = \"A\"\n\
                 value = \"10.9.{i}.1\"\n\n"
            );
        }
        s
    }

    fn big_loaded_config() -> crate::config::loader::LoadedConfig {
        let cfg: crate::config::schema::ConfigV1 =
            toml::from_str(&big_config_toml()).expect("generated fixture config must parse");
        crate::config::loader::LoadedConfig {
            config: cfg,
            master_path: std::path::PathBuf::from("/tmp/scroll-persist-fixture.toml"),
            files_loaded: Vec::new(),
            total_bytes: 0,
            provenance: Default::default(),
            custom_lists: Default::default(),
        }
    }

    fn mapped_device(i: usize) -> crate::ipc::protocol::MappedDeviceDto {
        crate::ipc::protocol::MappedDeviceDto {
            ip: format!("10.9.{i}.2"),
            name: format!("device-{i:02}"),
            mac: None,
            mac_aliases: Vec::new(),
            profile: "default".to_string(),
            owner: None,
            device_type: None,
            department: None,
            queries: 0,
            queries_today: 0,
            blocked: 0,
            blocked_24h: 0,
            cache_hits: 0,
            last_seen: 0,
            online: false,
            vendor: None,
            groups: Vec::new(),
            notes: None,
            network_name: None,
            network_name_wildcard: false,
            id: Some(format!("dev-{i:02}")),
            hourly_queries: Vec::new(),
            unfiltered: false,
        }
    }

    fn query_log_entry(i: usize) -> crate::ipc::protocol::QueryLogDto {
        crate::ipc::protocol::QueryLogDto {
            timestamp: format!("2026-01-01T00:{i:02}:00Z"),
            client_ip: "10.0.0.9".to_string(),
            client_name: None,
            domain: format!("q{i:02}.example"),
            query_type: "A".to_string(),
            result: "OK".to_string(),
            response_time_us: 1000,
            cname_chain_via: None,
        }
    }

    /// One scrollable table: how to build a fixture, how to move the
    /// cursor up one row from `DEEP`, how to render, and where to read
    /// the offset ratatui wrote back.
    struct ScrollCase {
        name: &'static str,
        build: fn() -> App,
        advance: fn(&mut App),
        render: fn(&mut ratatui::Frame, Rect, &mut App),
        offset: fn(&App) -> usize,
    }

    fn scroll_cases() -> Vec<ScrollCase> {
        vec![
            ScrollCase {
                name: "custom_lists (list pane)",
                build: || {
                    let mut app = App::new();
                    app.loaded_config = Some(big_loaded_config());
                    app.custom_lists.selected_id = Some(format!("cl-{DEEP:02}"));
                    app
                },
                advance: |app| app.custom_lists.selected_id = Some(format!("cl-{SHALLOW:02}")),
                render: super::custom_lists::render,
                offset: |app| app.custom_lists.table_state.offset(),
            },
            ScrollCase {
                name: "custom_lists (rules/pack pane)",
                build: || {
                    let mut app = App::new();
                    // The pack pane only paints once the list pane has at
                    // least one row (`render`'s own early-empty-state
                    // gate), so this reuses the shared config too.
                    app.loaded_config = Some(big_loaded_config());
                    let rows = (0..ROWS)
                        .map(|i| crate::tui::app::PackRow {
                            number: i + 1,
                            raw: format!("||d{i:02}.example^"),
                            domain: Some(format!("d{i:02}.example")),
                            action: crate::tui::app::PackRowAction::Deny,
                        })
                        .collect();
                    app.custom_lists.pack = Some(crate::tui::app::PackView {
                        id: "cl-00".to_string(),
                        rows,
                        error: None,
                    });
                    app.custom_lists.selected_line = Some(DEEP + 1); // 1-based line
                    app
                },
                advance: |app| app.custom_lists.selected_line = Some(SHALLOW + 1),
                render: super::custom_lists::render,
                offset: |app| app.custom_lists.rules_table_state.offset(),
            },
            ScrollCase {
                name: "local_dns",
                build: || {
                    let mut app = App::new();
                    app.loaded_config = Some(big_loaded_config());
                    app.local_dns.selected_id =
                        Some(("global".to_string(), format!("rec{DEEP:02}.home")));
                    app
                },
                advance: |app| {
                    app.local_dns.selected_id =
                        Some(("global".to_string(), format!("rec{SHALLOW:02}.home")))
                },
                render: super::local_dns::render,
                offset: |app| app.local_dns.table_state.offset(),
            },
            ScrollCase {
                name: "query_log",
                build: || {
                    let mut app = App::new();
                    app.query_log.entries = (0..ROWS).map(query_log_entry).collect();
                    app.query_log.selected_key =
                        Some(super::query_log::entry_key(&query_log_entry(DEEP)));
                    app
                },
                advance: |app| {
                    app.query_log.selected_key =
                        Some(super::query_log::entry_key(&query_log_entry(SHALLOW)))
                },
                render: super::query_log::render,
                offset: |app| app.query_log.table_state.offset(),
            },
            ScrollCase {
                name: "devices",
                build: || {
                    let mut app = App::new();
                    app.device_view = Some(crate::ipc::protocol::DeviceViewDto {
                        mapped: (0..ROWS).map(mapped_device).collect(),
                        unmapped: Vec::new(),
                    });
                    app.devices.selected_id = Some(format!("dev-{DEEP:02}"));
                    app
                },
                advance: |app| app.devices.selected_id = Some(format!("dev-{SHALLOW:02}")),
                render: super::devices::render,
                offset: |app| app.devices.table_state.offset(),
            },
            ScrollCase {
                name: "rules",
                build: || {
                    let mut app = App::new();
                    app.loaded_config = Some(big_loaded_config());
                    app.rules.table_state.select(Some(DEEP));
                    app
                },
                advance: |app| app.rules.table_state.select(Some(SHALLOW)),
                render: super::rules::render,
                offset: |app| app.rules.table_state.offset(),
            },
            ScrollCase {
                name: "lists",
                build: || {
                    let mut app = App::new();
                    app.lists.entries = (0..ROWS)
                        .map(|i| crate::lists::status::BlocklistStatusDto {
                            id: Some(format!("bl-{i:02}")),
                            source: format!("bl-{i:02}"),
                            last_outcome: "ok".to_string(),
                            ..Default::default()
                        })
                        .collect();
                    app.lists.table_state.select(Some(DEEP));
                    app
                },
                advance: |app| app.lists.table_state.select(Some(SHALLOW)),
                render: super::lists::render,
                offset: |app| app.lists.table_state.offset(),
            },
            ScrollCase {
                name: "subnets",
                build: || {
                    let mut app = App::new();
                    app.loaded_config = Some(big_loaded_config());
                    app.subnets.selected_id = Some(format!("sub-{DEEP:02}"));
                    app
                },
                advance: |app| app.subnets.selected_id = Some(format!("sub-{SHALLOW:02}")),
                render: super::subnets::render,
                offset: |app| app.subnets.table_state.offset(),
            },
            ScrollCase {
                name: "profiles",
                build: || {
                    let mut app = App::new();
                    app.loaded_config = Some(big_loaded_config());
                    app.profiles.selected_id = Some(format!("prof-{DEEP:02}"));
                    app
                },
                advance: |app| app.profiles.selected_id = Some(format!("prof-{SHALLOW:02}")),
                render: super::profiles::render,
                offset: |app| app.profiles.table_state.offset(),
            },
            ScrollCase {
                name: "groups",
                build: || {
                    let mut app = App::new();
                    app.loaded_config = Some(big_loaded_config());
                    app.groups.selected_id = Some(format!("grp-{DEEP:02}"));
                    app
                },
                advance: |app| app.groups.selected_id = Some(format!("grp-{SHALLOW:02}")),
                render: super::groups::render,
                offset: |app| app.groups.table_state.offset(),
            },
            ScrollCase {
                name: "labels",
                build: || {
                    let mut app = App::new();
                    app.loaded_config = Some(big_loaded_config());
                    app.labels.selected_kind = crate::config::schema::LabelKind::Owner;
                    app.labels.selected_id = Some(format!("lbl-{DEEP:02}"));
                    app
                },
                advance: |app| app.labels.selected_id = Some(format!("lbl-{SHALLOW:02}")),
                render: super::labels::render,
                offset: |app| app.labels.table_state.offset(),
            },
        ]
    }

    /// **Control arm.** Without it, an empty `scroll_cases()` (a typo
    /// that drops every `ScrollCase`, or a refactor that stops
    /// constructing the `Vec`) would make the assertion loop below pass
    /// vacuously — the same failure mode `tui_modal_colour_coverage.rs`'s
    /// `the_modal_set_is_not_empty` exists to catch.
    #[test]
    fn the_case_set_is_not_empty() {
        let cases = scroll_cases();
        assert!(
            cases.len() >= 10,
            "expected at least 10 scrollable-table cases, found {}: {:?} — \
             did a case get dropped from `scroll_cases`?",
            cases.len(),
            cases.iter().map(|c| c.name).collect::<Vec<_>>()
        );
    }

    /// **Second control arm.** Proves the harness itself can fail — that
    /// the assertion in the main test is actually checking something,
    /// not vacuously true for every input. Reproduces the exact defect
    /// `render_table` fixes: an offset thrown away and recomputed from
    /// zero. `TableState::offset_mut` is ratatui's own public accessor
    /// (its rustdoc example uses it the same way), not a private field
    /// reach-around.
    #[test]
    fn the_harness_detects_a_reset_offset() {
        let case = scroll_cases()
            .into_iter()
            .find(|c| c.name == "local_dns")
            .expect("local_dns case must exist");
        let mut app = (case.build)();
        let mut term = Terminal::new(TestBackend::new(area().width, area().height)).unwrap();

        term.draw(|f| (case.render)(f, area(), &mut app)).unwrap();
        let offset_before = (case.offset)(&app);
        assert!(
            offset_before > 0,
            "fixture never scrolled — the control arm needs a genuinely deep selection"
        );

        // Simulate the bug this test exists to catch: throw the offset
        // away, exactly as a fresh `TableState::default()` or a discarded
        // clone would every frame.
        *app.local_dns.table_state.offset_mut() = 0;
        (case.advance)(&mut app);
        term.draw(|f| (case.render)(f, area(), &mut app)).unwrap();
        let offset_after = (case.offset)(&app);

        assert_ne!(
            offset_before, offset_after,
            "corrupting the offset between renders must change the result — if it \
             doesn't, this harness cannot tell a persisted offset from a reset one"
        );
    }

    /// The guard itself: every enumerated table keeps ratatui's offset
    /// across a render where the selection moves up by one row from deep
    /// in the list. A monotonic walk down converges to the same offset
    /// whether or not the previous frame's state was kept (see
    /// `render_table`'s doc comment) — only a step *up* from a deep
    /// position tells persisted and reset apart, because a reset always
    /// re-pins the selection to the bottom of the viewport regardless of
    /// which direction the cursor just moved.
    #[test]
    fn every_scrollable_table_keeps_its_offset_across_a_render() {
        for case in scroll_cases() {
            let mut app = (case.build)();
            let mut term = Terminal::new(TestBackend::new(area().width, area().height)).unwrap();

            term.draw(|f| (case.render)(f, area(), &mut app)).unwrap();
            let offset_first = (case.offset)(&app);
            assert!(
                offset_first > 0,
                "{}: fixture never scrolled at DEEP={DEEP} — this case proves \
                 nothing until it does",
                case.name
            );

            (case.advance)(&mut app);
            term.draw(|f| (case.render)(f, area(), &mut app)).unwrap();
            let offset_second = (case.offset)(&app);

            assert_eq!(
                offset_second, offset_first,
                "{}: offset changed from {offset_first} to {offset_second} after \
                 moving the cursor up one row from a deep position — the viewport \
                 reset instead of persisting, which pins the cursor to the bottom \
                 of the screen on every render past the first page",
                case.name
            );
        }
    }
}
