use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::path::Path;

fn key_char(ch: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE)
}

/// Build an `IpcPoller` pointed at a guaranteed-nonexistent socket.
/// The mnemonic + numeric tests trigger `poll_active_leaf` on every
/// leaf change; the IPC call fails fast (ENOENT) and lands an error
/// in `app.last_error` we don't assert on. The state machine
/// transitions (active_leaf, pending_goto) happen synchronously
/// before the poll, so we can pin them deterministically.
fn dummy_poller() -> IpcPoller {
    IpcPoller::new(Path::new(
        "/tmp/purge-warden-t3-test-nonexistent-socket.sock",
    ))
}

#[tokio::test]
async fn numeric_1_jumps_to_dashboard() {
    let mut app = App::new();
    app.active_leaf = Leaf::Settings;
    let poller = dummy_poller();
    handle_key(&mut app, key_char('1'), &poller, Path::new("/dev/null")).await;
    assert_eq!(
        app.active_leaf,
        Leaf::Dashboard,
        "S46 T1: 1 -> Section::Dashboard.default_leaf() = Dashboard"
    );
}

#[tokio::test]
async fn numeric_2_jumps_to_query_log() {
    let mut app = App::new();
    let poller = dummy_poller();
    handle_key(&mut app, key_char('2'), &poller, Path::new("/dev/null")).await;
    assert_eq!(
        app.active_leaf,
        Leaf::QueryLog,
        "S46 T1: 2 -> Section::QueryLog.default_leaf() = QueryLog"
    );
}

#[tokio::test]
async fn numeric_3_jumps_to_network_default_leaf() {
    let mut app = App::new();
    let poller = dummy_poller();
    handle_key(&mut app, key_char('3'), &poller, Path::new("/dev/null")).await;
    assert_eq!(
        app.active_leaf,
        Leaf::Devices,
        "S46 T1: 3 -> Network default = Devices"
    );
}

#[tokio::test]
async fn numeric_4_jumps_to_filters_default_leaf() {
    let mut app = App::new();
    let poller = dummy_poller();
    handle_key(&mut app, key_char('4'), &poller, Path::new("/dev/null")).await;
    assert_eq!(
        app.active_leaf,
        Leaf::Profiles,
        "2026-07-24 (IA Option B): Filters default = Profiles, the policy hub"
    );
}

#[tokio::test]
async fn numeric_5_jumps_to_configuration_leftmost_leaf() {
    let mut app = App::new();
    let poller = dummy_poller();
    handle_key(&mut app, key_char('5'), &poller, Path::new("/dev/null")).await;
    assert_eq!(
        app.active_leaf,
        Leaf::Labels,
        "2026-08-24 operator rule: every section lands on its LEFTMOST leaf. \
             This asserted Leaf::Settings until then, on the ground that `5` had \
             meant Settings for the life of the product — an inference about the \
             operator's muscle memory, which the operator has now overridden \
             directly. Asserted against Leaf::Labels rather than against \
             `Section::Configuration.default_leaf()`: a test that recomputes the \
             value it checks would pass on any future drift, which is the whole \
             failure this rule exists to prevent."
    );
}

/// S46 T1 retired numerics 6..=9 (S45 T3 had retired 5..=9; the S46
/// reshape promoted Settings from `4` to `5`, so only 6-9 remain
/// orphaned). They no longer have a global handler and must NOT
/// change the active leaf. The Dashboard tab binds none of those
/// digits per-tab, so the leaf stays put if the handler genuinely
/// fell through. Pins the regression: a future edit that re-binds
/// one of them, or a per-tab handler that silently catches a digit,
/// would flip this test red.
#[tokio::test]
async fn numeric_6_through_9_are_no_ops() {
    let poller = dummy_poller();
    for ch in ['6', '7', '8', '9'] {
        let mut app = App::new();
        app.active_leaf = Leaf::Dashboard;
        handle_key(&mut app, key_char(ch), &poller, Path::new("/dev/null")).await;
        assert_eq!(
            app.active_leaf,
            Leaf::Dashboard,
            "numeric {ch} must not change active_leaf after S46 T1 retired 6-9"
        );
        assert!(!app.pending_goto, "numeric {ch} must not arm pending_goto");
    }
}

#[tokio::test]
async fn g_arms_pending_goto_without_changing_leaf() {
    let mut app = App::new();
    app.active_leaf = Leaf::Lists;
    let poller = dummy_poller();
    handle_key(&mut app, key_char('g'), &poller, Path::new("/dev/null")).await;
    assert!(app.pending_goto, "first g arms the mnemonic prefix");
    assert_eq!(
        app.active_leaf,
        Leaf::Lists,
        "g alone does not move the leaf — that's the second key's job"
    );
}

#[tokio::test]
async fn g_then_d_jumps_to_dashboard_from_settings() {
    let mut app = App::new();
    app.active_leaf = Leaf::Settings;
    let poller = dummy_poller();
    handle_key(&mut app, key_char('g'), &poller, Path::new("/dev/null")).await;
    assert!(app.pending_goto);
    handle_key(&mut app, key_char('d'), &poller, Path::new("/dev/null")).await;
    assert_eq!(app.active_leaf, Leaf::Dashboard, "g d -> Dashboard");
    assert!(
        !app.pending_goto,
        "pending_goto cleared after a successful mnemonic dispatch"
    );
}

#[tokio::test]
async fn g_then_unknown_letter_clears_flag_and_keeps_leaf() {
    let mut app = App::new();
    app.active_leaf = Leaf::Lists;
    let poller = dummy_poller();
    handle_key(&mut app, key_char('g'), &poller, Path::new("/dev/null")).await;
    assert!(app.pending_goto);
    handle_key(&mut app, key_char('x'), &poller, Path::new("/dev/null")).await;
    assert!(
        !app.pending_goto,
        "pending_goto must clear even on an unknown second key"
    );
    assert_eq!(
        app.active_leaf,
        Leaf::Lists,
        "unknown second key falls through silently — leaf does not move"
    );
}

/// Bonus: `g g` — the first `g` arms; the second `g` is not a
/// mnemonic letter (no leaf has the `g` initial), so it drains
/// `pending_goto` and falls through to the normal match where it
/// re-arms the flag. The third keystroke completes the jump. Pins
/// the design doc §4 "g g re-arms" decision.
#[tokio::test]
async fn double_g_re_arms_pending_goto() {
    let mut app = App::new();
    let poller = dummy_poller();
    handle_key(&mut app, key_char('g'), &poller, Path::new("/dev/null")).await;
    assert!(app.pending_goto, "first g arms");
    handle_key(&mut app, key_char('g'), &poller, Path::new("/dev/null")).await;
    assert!(
        app.pending_goto,
        "second g re-arms — operator can complete with one more letter"
    );
}

/// Round-trip every mnemonic in the §4 table through the live
/// `handle_key` path. Confirms the table is consistent end-to-end:
/// the `Leaf::from_mnemonic` lookup, the `pending_goto` state
/// machine, and the post-dispatch flag clear all line up.
#[tokio::test]
async fn all_eight_mnemonics_dispatch_correctly() {
    let poller = dummy_poller();
    let pairs: [(char, Leaf); 8] = [
        ('d', Leaf::Dashboard),
        ('q', Leaf::QueryLog),
        ('v', Leaf::Devices),
        ('s', Leaf::Subnets),
        ('l', Leaf::LocalDns),
        ('i', Leaf::Lists),
        ('u', Leaf::Rules),
        ('e', Leaf::Settings),
    ];
    for (ch, expected) in pairs {
        let mut app = App::new();
        // Start from a leaf different from `expected` so the
        // transition is observable. Settings is a safe parking
        // spot for every other target except itself; jump to
        // Dashboard for the Settings case.
        app.active_leaf = if expected == Leaf::Settings {
            Leaf::Dashboard
        } else {
            Leaf::Settings
        };
        handle_key(&mut app, key_char('g'), &poller, Path::new("/dev/null")).await;
        handle_key(&mut app, key_char(ch), &poller, Path::new("/dev/null")).await;
        assert_eq!(app.active_leaf, expected, "g{ch} -> {expected:?}");
        assert!(
            !app.pending_goto,
            "pending_goto cleared after successful g{ch} dispatch"
        );
    }
}
