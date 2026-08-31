//! Runtime coverage guard for the hand-rolled-colour/chrome rule across every
//! `src/tui/*_modal.rs` file.
//!
//! The rule is already enforced per-file, individually, in 7 of the 11 modal
//! files (each does its own `include_str!` self-scan). Because each copy only
//! sees itself, a new modal that forgets to add the test ships unguarded and
//! nothing notices — that happened four times. This test closes the gap by
//! enumerating the file set at runtime instead of by a hand-written list (a
//! hand-written list is exactly the failure mode that produced the gap), so
//! the next forgotten modal fails loud instead of silently.
//!
//! Scope is deliberately `*_modal.rs` only, not `src/tui/tabs/`: the
//! `Style::default().fg(` / `T.brand_red` rule applies to modal surfaces
//! only, not to tab bodies, which legitimately set their own foreground.
//! Widening this scan to tabs would falsely flag files that were never in
//! violation. Tab files keep their own, separately-scoped tests.
//!
//! `modal_form.rs` is not a violator and is not scanned: it is the shared
//! chrome/colour implementation every modal delegates to (same role as
//! `theme.rs`), not a policed consumer — and it does not match the
//! `*_modal.rs` filename pattern this test enumerates.

use std::path::{Path, PathBuf};

/// Same needle set the per-file scans use, reunited: `Borders::ALL` /
/// `border_style(` (chrome), `Color::Rgb(` (raw rgb), `Style::default().fg(`
/// / `T.brand_red` (direct foreground). Split with `concat!` so this file's
/// own source can never match its own needles.
const FORBIDDEN_NEEDLES: &[&str] = &[
    concat!("Borders", "::ALL"),
    concat!("border", "_style("),
    concat!("Color", "::Rgb("),
    concat!("Style::default()", ".fg("),
    concat!("T", ".brand_red"),
];

/// Every needle present in `body`. Pulled out as its own function so the
/// detector itself can be exercised against a fixture, independent of
/// whether any real file currently violates the rule.
fn forbidden_hits(body: &str) -> Vec<&'static str> {
    FORBIDDEN_NEEDLES
        .iter()
        .copied()
        .filter(|needle| body.contains(needle))
        .collect()
}

/// `src/tui/*_modal.rs`, enumerated at runtime — not named by hand.
fn modal_files() -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tui");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .expect("src/tui must be readable")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.ends_with("_modal.rs"))
                .unwrap_or(false)
        })
        .collect();
    files.sort();
    files
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("modal file {} must be readable: {e}", path.display()))
}

/// **The control arm.** Without it, `no_hand_rolled_colour_or_chrome_in_any_modal_file`
/// passing would be indistinguishable from `forbidden_hits` being broken and
/// never matching anything.
#[test]
fn the_detector_fires_on_a_known_bad_fixture() {
    let bad = r#"
        fn render(f: &mut Frame) {
            let block = Block::default().borders(Borders::ALL);
            let style = Style::default().fg(Color::Rgb(255, 0, 0));
        }
    "#;
    let hits = forbidden_hits(bad);
    assert!(
        !hits.is_empty(),
        "the detector found nothing in a fixture that hand-rolls Borders::ALL, \
         Color::Rgb(, and Style::default().fg( — it is not actually checking anything"
    );
}

/// **The other control arm.** Without it, an empty `read_dir` result (wrong
/// path, permissions, a moved directory) would make every assertion below
/// pass vacuously — a detector that sees nothing and a tree that contains
/// nothing are indistinguishable from the outside.
#[test]
fn the_modal_set_is_not_empty() {
    let files = modal_files();
    assert!(
        files.len() >= 11,
        "expected at least 11 *_modal.rs files under src/tui, found {}: {:?} — \
         did `src/tui` move, or did the enumeration break?",
        files.len(),
        files
    );
}

/// Positive control per file: proves each enumerated path is a real modal
/// file with a render path, not an artifact of a `read_dir` scoped to the
/// wrong directory.
#[test]
fn every_enumerated_file_actually_renders() {
    for file in modal_files() {
        let src = read(&file);
        assert!(
            src.contains("fn render"),
            "{} has no `fn render` — is this really a modal file, or did the \
             `_modal.rs` filename filter catch something it shouldn't have?",
            file.display()
        );
    }
}

/// The guard itself: every `*_modal.rs` file, present and future, checked
/// against the full colour/chrome needle set — whole file text, test code
/// included, so there is no `#[cfg(test)]` region to strip and nothing here
/// shares the stripper's brace-depth fragility.
#[test]
fn no_hand_rolled_colour_or_chrome_in_any_modal_file() {
    for file in modal_files() {
        let src = read(&file);
        let hits = forbidden_hits(&src);
        assert!(
            hits.is_empty(),
            "{} hand-rolls colour/chrome directly — {hits:?} present, but this \
             belongs in modal_form",
            file.display()
        );
    }
}
