use super::*;
use crate::config::schema::{ConfigV1, CustomList, Id};

fn app_with_one_list() -> App {
    let mut app = App::new();
    app.active_leaf = Leaf::CustomLists;
    app.loaded_config = Some(crate::config::loader::LoadedConfig {
        config: ConfigV1 {
            custom_lists: vec![CustomList {
                id: Id::new("videogames").unwrap(),
                display_name: String::new(),
                description: String::new(),
            }],
            ..Default::default()
        },
        master_path: std::path::PathBuf::from("/tmp/dummy.toml"),
        files_loaded: Vec::new(),
        total_bytes: 0,
        provenance: Default::default(),
        custom_lists: Default::default(),
    });
    app
}

/// Translate one advertised key token into the event it promises.
///
/// Returns `None` for a token this test cannot model; the caller
/// counts what it did map, so an unrecognised spelling shrinks the
/// test's reach visibly instead of silently.
fn key_for(token: &str) -> Option<KeyCode> {
    Some(match token.trim() {
        "Up" => KeyCode::Up,
        "Down" => KeyCode::Down,
        // The arrow GLYPHS are mapped too: the footer draws an arrow
        // key cell, and a scan that skipped it would leave the leaf's
        // only motion affordances unguarded.
        "Left" | "\u{2190}" => KeyCode::Left,
        "Right" | "\u{2192}" => KeyCode::Right,
        "Enter" => KeyCode::Enter,
        "Esc" => KeyCode::Esc,
        "Delete" => KeyCode::Delete,
        "Space" => KeyCode::Char(' '),
        t if t.chars().count() == 1 => KeyCode::Char(t.chars().next().unwrap()),
        _ => return None,
    })
}

/// Is `code` handled in EITHER pane?
///
/// Both have to be tried, because several keys are honoured in exactly
/// one: `Left` returns from the rule pane and means nothing on the list
/// pane, and the reverse for `Right`. Requiring a key to work in
/// whichever pane happens to be the default would make the guard reject
/// correct pane-scoped bindings; requiring it in both would too. *Does
/// something somewhere on this leaf* is the property a legend promises.
fn handled_in_either_pane(code: KeyCode) -> bool {
    [CustomListsFocus::Lists, CustomListsFocus::Rules]
        .into_iter()
        .any(|focus| {
            let mut app = app_with_one_list();
            app.custom_lists.focus = focus;
            handle_custom_lists_key(&mut app, KeyEvent::new(code, KeyModifiers::NONE));
            !app.leaf_key_unhandled
        })
}

/// **Every key this leaf advertises must actually be bound.**
///
/// The rule is not stylistic. Shipped once as three phantom
/// affordances — the empty state offered `[a] create one`, the footer
/// promised `[a] add [e] edit [d] delete`, and the `?` overlay listed
/// the same three, while the only handler was scrolling. An operator
/// on a live box pressed them, nothing happened, and the reasonable
/// conclusion is that the product is broken. An UNADVERTISED key costs
/// nothing by comparison: it is simply not reached for.
///
/// So the legend, the overlay and the empty state land in the same
/// commit as the handler they announce — and this is what enforces it
/// for the rows that remain to be added.
#[test]
fn every_key_the_custom_lists_leaf_advertises_is_bound() {
    let rows = crate::tui::help::per_leaf_rows(Leaf::CustomLists);
    let mut checked = 0usize;
    for row in &rows {
        for token in row.key.split('/') {
            let Some(code) = key_for(token) else { continue };
            assert!(
                handled_in_either_pane(code),
                "the `?` overlay advertises {:?} ({}), but neither pane \
                     binds it — remove the row or bind the key",
                row.key,
                row.desc
            );
            checked += 1;
        }
    }
    // Without this the test passes on a parser that maps nothing.
    assert!(
        checked >= 3,
        "expected to exercise at least the motion keys plus one verb; \
             mapped only {checked} of {} rows",
        rows.len()
    );
}

/// The footer is a second hand-maintained legend over the same keys,
/// so it gets the same guard — read back off the rendered buffer,
/// because that is the only place its spans become text.
#[test]
fn every_key_the_custom_lists_footer_advertises_is_bound() {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    // BOTH focus states, because the footer is contextual: rendering
    // only the default one would leave the rule pane's legend
    // unguarded, which is the half a reader is least likely to check
    // by hand.
    let mut checked = 0usize;
    for focus in [CustomListsFocus::Lists, CustomListsFocus::Rules] {
        let mut app = App::new();
        app.active_leaf = Leaf::CustomLists;
        app.custom_lists.focus = focus;
        let mut term = Terminal::new(TestBackend::new(120, 1)).unwrap();
        term.draw(|f| crate::tui::ui::render_footer_for_test(f, f.area(), &app))
            .unwrap();
        let buf = term.backend().buffer().clone();
        let mut line = String::new();
        for x in 0..buf.area.width {
            line.push_str(buf[(x, 0)].symbol());
        }

        // `[k] label` is the footer's only key vocabulary (`key_span`).
        // The token is read WHOLE rather than as one character: a
        // single-char scan silently skips `[Esc]`, and skipping is how
        // a guard develops a blind spot exactly where a longer key name
        // lives.
        for token in line
            .split('[')
            .skip(1)
            .filter_map(|rest| rest.split_once(']').map(|(k, _)| k))
        {
            // The global cluster (r/p/s/?/q) is handled outside the
            // leaf, so it is out of scope here.
            if token.len() == 1 && "rps?q".contains(token) {
                continue;
            }
            let Some(code) = key_for(token) else { continue };
            assert!(
                handled_in_either_pane(code),
                "the footer advertises [{token}] but neither pane binds it; \
                     footer was:\n{line}"
            );
            checked += 1;
        }
    }
    assert!(
        checked >= 2,
        "expected leaf keys in both footers — the scan is broken, not \
             the footer"
    );
}

/// **The rule pane's legend has to FIT.**
///
/// Advertising a key is only half the promise: a token clipped by the
/// right edge is a key the operator cannot read, and 80 columns is the
/// narrowest terminal this TUI supports. The rule pane's cluster runs
/// closest to that edge, and it grew by one key.
#[test]
fn the_rule_pane_legend_fits_eighty_columns() {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    let mut app = App::new();
    app.active_leaf = Leaf::CustomLists;
    app.custom_lists.focus = CustomListsFocus::Rules;
    let mut term = Terminal::new(TestBackend::new(80, 1)).unwrap();
    term.draw(|f| crate::tui::ui::render_footer_for_test(f, f.area(), &app))
        .unwrap();
    let buf = term.backend().buffer().clone();
    let mut line = String::new();
    for x in 0..buf.area.width {
        line.push_str(buf[(x, 0)].symbol());
    }

    for token in [
        "[a] add rule",
        "[e] edit rule",
        "[d] remove rule",
        "[Esc] lists",
    ] {
        assert!(
            line.contains(token),
            "{token} is clipped or missing at 80 columns:\n{line}"
        );
    }
}
