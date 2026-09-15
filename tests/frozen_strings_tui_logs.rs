//! Frozen strings for the Log Messages tab (`Leaf::Logs`).
//!
//! Pins the shared filter labels and the distinct empty states.
//! "Nothing was captured" and "nothing matched your filter"
//! are different facts about the daemon, and an operator who reads the
//! wrong one concludes the tab is broken when it is merely filtered. A
//! reword that collapses them into one sentence is the regression this
//! file exists to stop.
//!
//! `include_str!` + literal-contains, the same idiom as
//! `frozen_strings_tui_file_viewer.rs`. `crate::tui::tabs` is private, so
//! an integration test cannot import the constants — and widening a
//! module's visibility to suit a test is a worse trade than reading the
//! source.

const SEARCH_LABEL: &str = "Search";
const LEVEL_LABEL: &str = "Level";
const CLEAR_LABEL: &str = "Clear";
const NO_MESSAGES: &str = "  (no messages captured yet)";
const NO_MATCHES: &str = "  (no messages match the current filters — use Clear)";
const WAITING: &str = "  (waiting for the daemon…)";
const UNREADABLE: &str = "  (could not read the daemon's log buffer — see the footer)";

fn logs_src() -> &'static str {
    include_str!("../src/tui/tabs/logs.rs")
}

fn pinned(name: &str, value: &str) {
    let needle = format!("= \"{value}\";");
    assert!(
        logs_src().contains(&needle),
        "tabs/logs.rs must spell {name} exactly as `{value}` \
         (looked for literal `{needle}`)"
    );
}

#[test]
fn filter_chip_labels_and_shortcuts_are_frozen() {
    let chips = include_str!("../src/tui/filter_chips.rs")
        .split_once("Leaf::Logs => vec![")
        .expect("Logs must use the shared filter chip model")
        .1
        .split_once("],")
        .expect("Logs chip model must be a complete list")
        .0;
    for label in [SEARCH_LABEL, LEVEL_LABEL, CLEAR_LABEL] {
        assert!(chips.contains(&format!("\"{label}\"")));
    }
    assert!(logs_src().contains("crate::tui::filter_chips::render_card("));

    let help = include_str!("../src/tui/help.rs")
        .split_once("Leaf::Logs => vec![")
        .expect("Logs must have contextual filter help")
        .1
        .split_once("],")
        .expect("Logs help must be a complete list")
        .0;
    assert!(help.contains("key: \"f\""));
    assert!(help.contains("Focus filters; Tab/arrows move, Enter opens, Delete clears"));
    for retired in ["key: \"/\"", "key: \"R\""] {
        assert!(
            !help.contains(retired),
            "Logs help must not restore the retired shortcut {retired}"
        );
    }
}

#[test]
fn the_four_empty_states_are_frozen_and_mutually_distinct() {
    // One empty list has four readings: not fetched yet, fetched and the
    // daemon is quiet, fetched and nothing matched, and the fetch failed.
    // Three are claims about the DAEMON and one is a claim about the
    // CONNECTION. A reword that collapses any two of them tells an
    // operator something untrue about a live daemon — which is the exact
    // dishonesty the source scout rejected a cheaper data source over.
    let all = [NO_MESSAGES, NO_MATCHES, WAITING, UNREADABLE];
    pinned("NO_MESSAGES", NO_MESSAGES);
    pinned("NO_MATCHES", NO_MATCHES);
    pinned("WAITING", WAITING);
    pinned("UNREADABLE", UNREADABLE);
    for (i, a) in all.iter().enumerate() {
        for b in all.iter().skip(i + 1) {
            assert_ne!(a, b, "the empty states must stay distinguishable");
        }
    }
    assert!(
        NO_MATCHES.contains("use Clear"),
        "the filtered empty state must name the visible action that clears the filters"
    );
    assert!(
        !WAITING.contains("no messages") && !UNREADABLE.contains("no messages"),
        "neither the pre-fetch nor the failed state may claim the daemon said nothing"
    );
}

#[test]
fn the_leaf_label_and_mnemonic_are_frozen() {
    // Not "Logs": every letter of that word is already a mnemonic (`l`
    // LocalDns, `o` Groups, `s` Subnets) or the `g` prefix itself, so a
    // leaf labelled "Logs" could carry no underlined letter. The label
    // also has to stay distinguishable from "Query Log", which answers a
    // different question — what clients asked for, not what the daemon
    // said.
    let app_src = include_str!("../src/tui/app.rs");
    assert!(
        app_src.contains(r#"Leaf::Logs => "Log Messages","#),
        "the Logs leaf must be labelled `Log Messages`"
    );
    assert!(
        app_src.contains("'m' => Some(Leaf::Logs),"),
        "`g m` must jump to the Logs leaf"
    );
    assert!(
        app_src.contains("Leaf::Logs => 'm',"),
        "the Logs mnemonic must round-trip as `m`"
    );
}
