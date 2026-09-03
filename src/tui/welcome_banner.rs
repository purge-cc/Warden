//! The startup overlay: first-run welcome, or a config-discovery diagnosis.
//!
//! One surface, two states ([`BannerKind`]). On a healthy launch it is a
//! one-shot greeting: shown the first time an operator opens the dashboard,
//! dismissable on any keypress, and recorded in
//! `~/.config/purge-warden/seen_versions` (one key per line) so it does NOT
//! reappear. When config discovery could not hand the dashboard a usable
//! config it is a diagnosis instead — same chrome, opposite persistence:
//! shown on **every** launch while that holds, recorded nowhere.
//!
//! The module keeps its `welcome_banner` name for the greeting it started
//! as; the diagnosis is the state that actually matters, because it is the
//! one an operator sees when nothing else on screen is theirs.
//!
//! # Storage
//!
//! Path resolution mirrors [`crate::ipc::auth_token::default_token_path`]:
//! `$XDG_CONFIG_HOME/purge-warden/seen_versions` if the env var is set,
//! otherwise `$HOME/.config/purge-warden/seen_versions`. The file is
//! plaintext (one version literal per line) — no JSON, no schema. Lines
//! are trimmed and lowercased before comparison so a stray newline or
//! casing drift doesn't keep re-showing the banner.
//!
//! # Why a separate file from `token`
//!
//! The banner state is operator-scoped UX context, not a credential.
//! Token rotation must not erase banner history; banner dismissal must
//! not touch the token. Two files keep the lifecycles independent.
//!
//! # Banner copy
//!
//! [`welcome_copy`] is the evergreen first-run copy. It answers the three
//! questions a fresh install actually raises — *where do upstreams come
//! from, why is nothing being blocked, and why is warden seeing no
//! traffic* — and for each one names the leaf and the key that satisfies
//! it. Every `g <letter>` in it is **generated from
//! [`crate::tui::app::Leaf::mnemonic`]**, so a remapped mnemonic moves the
//! copy with it instead of leaving a hint that points at the wrong tab —
//! a frozen const naming a literal key survives the rebinding it once
//! described, and a mnemonic can be rebound. The build version is no
//! longer in the body at all:
//! [`notice_spec`] puts it in the title band, where it costs no row of the
//! tightest budget in the TUI, and
//! `welcome_shows_the_running_build_version_on_screen` pins it at the
//! *render*, which is stronger than pinning the string.
//!
//! ## The copy IS rationed, and the ration is 19 rows
//!
//! This section used to say the opposite — *"the overlay is now built by
//! [`modal_form::render_modal`], which derives its height from the row
//! count, so length is no longer a hazard and copy no longer has to be
//! rationed. Write what the operator needs."* **That claim is false, and
//! it is the more dangerous of the two this module carried.**
//! `render_modal` does derive the height from the row count,
//! but `overlay::centered_rect` then clamps that height to the anchor —
//! and [`notice_spec`] passes no choices, so
//! [`modal_form::notice_body`] returns `scrollable: false` and
//! `modal_form::render_scroll_body` cuts the overflow **with no scrollbar
//! and no `…`**. `ScrollBody::scrollable`'s own doc says it: *"a `false`
//! body that overflows is silently cut."*
//!
//! The anchor is the whole frame (`ui::render` passes `area`, not
//! `chunks[2]`) and `ui::render` refuses to draw below 80×24, so the floor
//! is a 22-row interior: `head` 2 + `tail` 1 leaves **19 prose rows**.
//! `welcome_copy_fits_the_floor_row_budget` asserts that through
//! [`modal_form::scroll_layout`] itself rather than against a hardcoded
//! 19, so it follows the allocator if the allocation rule changes.
//!
//! **The horizontal axis is the one that cannot bite.** A project note
//! records that modal bodies do not wrap but truncate silently, and
//! [`wrap_prose`] in this file implies the reverse; both are locally
//! accurate and neither describes the widget. `ProseRow::plain` really
//! does ellipsise (`modal_form::prose_row` → `fit`) at 60 usable cells,
//! and this module pre-wraps to [`PROSE_WRAP`] = 59 before handing the
//! rows over, so the ellipsis is unreachable — and the width cannot shrink
//! underneath it, because `centered_rect` yields the full 64 at every
//! width `ui::render` will draw at.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use ratatui::layout::Rect;
use ratatui::Frame;

use crate::tui::app::Leaf;
use crate::tui::modal_form;

/// Stable dedup key written to `seen_versions` on dismissal. Fixed (not the
/// build version) so the banner shows **once per operator** and does not
/// reappear on every upgrade — the copy is an evergreen welcome, not a
/// per-release "what's new". Versioned the suffix so a future content
/// revision can intentionally re-surface by bumping it.
///
/// A bump earns its cost when what the box is FOR changes — e.g. moving
/// from advertising one feature to a setup checklist covering upstreams,
/// lists and client pointing — not when only the wording changes. An
/// operator who dismissed the earlier body would otherwise never see the
/// content that replaced it.
///
/// **The cost is real and is the reason this is not free to do:** every
/// operator who has already dismissed the banner sees it once more. Priced
/// deliberately — a one-off re-show is cheaper than a fresh install that
/// never learns why nothing is being blocked. Do NOT bump this for a
/// reword; a suffix spent on cosmetics is one that cannot be spent when the
/// content actually changes.
pub const WELCOME_SEEN_KEY: &str = "welcome-setup-v3";

/// What the overlay is currently showing.
///
/// The two variants exist as one enum because they share a surface and a
/// dismissal key — but their **persistence rules are opposite**, and that
/// is the part worth stating:
///
/// * [`BannerKind::Welcome`] is shown **once per operator**, gated by
///   [`WELCOME_SEEN_KEY`] in `seen_versions`. A greeting repeated is noise.
/// * [`BannerKind::NotReady`] is shown on **every launch while the state
///   holds**, and never touches `seen_versions`. A diagnosis is not a
///   greeting: it is true until the cause is fixed, and suppressing it after
///   one viewing would mean an operator who dismissed the welcome months ago
///   gets a dashboard full of empty panels with no explanation on screen.
///
/// Putting them under one key was the tempting simplification and it is the
/// exact failure this shape prevents.
#[derive(Debug, Clone)]
pub enum BannerKind {
    /// Evergreen first-run greeting.
    Welcome,
    /// Config discovery could not hand this dashboard a usable config, so
    /// nothing it shows will be the operator's real configuration. Carries
    /// the two halves of the discovery warning: `headline` rides the
    /// description band, `detail` becomes the wrapped body.
    NotReady { headline: String, detail: String },
}

/// Description band for [`BannerKind::Welcome`].
///
/// A `const` and not an inline literal so
/// `welcome_desc_band_is_not_truncated` can measure it: `desc_band` does
/// **not** wrap — it `fit`s to one line and ellipsises — so unlike the body
/// this string is not protected by [`wrap_prose`] and has to be checked
/// against the band's own budget directly.
pub const WELCOME_DESC: &str = "First launch — three things to set up";

/// Evergreen first-run welcome copy: the three things standing between a
/// fresh install and a filtered network, each naming the leaf and key that
/// satisfies it.
///
/// **Why this is not per-profile local DNS records.** That is a feature
/// with no bearing on minute one. Two of the three things below are load
/// bearing on a fresh install and one of them is a *product decision*:
/// warden carries no baked-in default resolver, so it names no provider
/// for the operator and `warden init` refuses without `--upstream`. A
/// first screen that pointed at local DNS records instead would point
/// away from the only thing that could be blocking the box.
///
/// **Every `g <letter>` is derived from [`Leaf::mnemonic`], never typed.**
/// A hint typed by hand is a hint that survives the binding it describes —
/// which is exactly how `[5]` outlived the `5` key. The leaf-local keys
/// (`B` and `a` on Lists, `e` on File) have no such table and are pinned by
/// test instead; see `welcome_copy_advertises_only_live_leaf_local_keys`.
///
/// **State-independent by construction.** This runs before the config is
/// loaded — `run_app` builds the banner from `startup_warning` alone, and
/// `App::loaded_config` is still `None` — so the copy may not claim that
/// *this* box has no upstream or no lists. Every sentence below is a
/// statement about warden or a conditional, never a reading of the current
/// configuration. A future edit tempted to say "you have no lists" needs a
/// data source this constructor does not have.
///
/// Length is capped: see the module-level "The copy IS rationed" note.
pub fn welcome_copy() -> String {
    format!(
        "Three things turn this into a filtering resolver.\n\
         \n\
         1  Upstreams — where warden forwards what it does not block. It \
         ships with none and names no provider for you: without one, \
         nothing resolves. {dash} (g {d}) shows what is set, on the \
         \"Upstream\" row. {file} (g {f}), then  e  opens the config in \
         $EDITOR to change it.\n\
         \n\
         2  Lists — until one is subscribed warden resolves normally and \
         blocks nothing. {lists} (g {i}), then  B  to browse the purge.cc \
         catalog or  a  to add one by URL.\n\
         \n\
         3  Point your clients here — warden sees no query until your \
         router's DHCP, or each machine, names this box as its DNS server. \
         {dash} (g {d}) shows the \"Listen\" address; {qlog} (g {q}) fills \
         as queries arrive.",
        dash = Leaf::Dashboard.label(),
        d = Leaf::Dashboard.mnemonic(),
        file = Leaf::File.label(),
        f = Leaf::File.mnemonic(),
        lists = Leaf::Lists.label(),
        i = Leaf::Lists.mnemonic(),
        qlog = Leaf::QueryLog.label(),
        q = Leaf::QueryLog.mnemonic(),
    )
}

/// Resolve the default `seen_versions` path from the environment.
/// Returns `None` only if neither `$XDG_CONFIG_HOME` nor `$HOME` is
/// set — a very broken environment in which case the banner silently
/// does not persist (but still shows on every launch). This is a UX
/// degradation, not a failure mode worth bubbling to the operator.
pub fn default_seen_versions_path() -> Option<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return Some(
                PathBuf::from(xdg)
                    .join("purge-warden")
                    .join("seen_versions"),
            );
        }
    }
    let home = std::env::var("HOME").ok()?;
    if home.is_empty() {
        return None;
    }
    Some(
        PathBuf::from(home)
            .join(".config")
            .join("purge-warden")
            .join("seen_versions"),
    )
}

/// In-memory state for the welcome banner overlay. Owned by the TUI
/// app; `None` means "do not render".
#[derive(Debug, Clone)]
pub struct WelcomeBanner {
    /// Dedup key recorded on dismissal — a stable banner identity (e.g.
    /// [`WELCOME_SEEN_KEY`]), not necessarily the build version, so a
    /// version bump doesn't re-show an already-dismissed banner.
    pub version: String,
    /// Which of the two surfaces this is. See [`BannerKind`] — the variants
    /// differ in whether dismissal persists at all.
    pub kind: BannerKind,
    /// Frozen banner copy to display. Body text for
    /// [`BannerKind::Welcome`]; unused by [`BannerKind::NotReady`], which
    /// carries its own two halves.
    pub copy: String,
    /// File path the dismissal will append to. `None` when the
    /// environment is too broken to resolve a config dir; the banner
    /// still renders, but dismissal is in-memory only.
    pub persist_path: Option<PathBuf>,
}

impl WelcomeBanner {
    /// Build the evergreen welcome banner with the default `seen_versions`
    /// path resolved from the environment. The dedup key is fixed
    /// ([`WELCOME_SEEN_KEY`]) so it shows once per operator; the copy is
    /// version- and key-accurate ([`welcome_copy`]). Production callers go
    /// through this constructor.
    pub fn welcome() -> Self {
        Self {
            version: WELCOME_SEEN_KEY.to_string(),
            kind: BannerKind::Welcome,
            copy: welcome_copy(),
            persist_path: default_seen_versions_path(),
        }
    }

    /// Build the diagnosis variant from a config-discovery warning.
    ///
    /// `persist_path` is deliberately `None`: this variant must re-show on
    /// every launch while the condition holds, so there is nothing to
    /// record. Leaving the field empty makes [`WelcomeBanner::dismiss`] a
    /// no-op by the same code path that handles a broken `$HOME`, rather
    /// than by a second branch that could drift from it.
    pub fn not_ready(headline: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            version: WELCOME_SEEN_KEY.to_string(),
            kind: BannerKind::NotReady {
                headline: headline.into(),
                detail: detail.into(),
            },
            copy: String::new(),
            persist_path: None,
        }
    }

    /// Build a banner with an explicit `seen_versions` path. Used by
    /// tests so the tempdir layout doesn't pollute the real
    /// `~/.config/purge-warden/`. Marked `dead_code` because production
    /// callers always go through [`WelcomeBanner::welcome`]; the
    /// constructor exists for tempdir-driven test fixtures only.
    #[allow(dead_code)]
    pub fn with_path(version: impl Into<String>, copy: impl Into<String>, path: PathBuf) -> Self {
        Self {
            version: version.into(),
            kind: BannerKind::Welcome,
            copy: copy.into(),
            persist_path: Some(path),
        }
    }

    /// Dismiss the banner by writing its version to the persist path.
    /// Best-effort: filesystem failures (no parent, EROFS, EPERM) are
    /// swallowed because the banner has already done its job (operator
    /// saw it). The next launch may re-show it; that's acceptable.
    pub fn dismiss(&self) {
        let Some(path) = self.persist_path.as_deref() else {
            return;
        };
        let _ = append_version_line(path, &self.version);
    }
}

/// Read the `seen_versions` file and return whether `version` is
/// already present (case-insensitive, trim-tolerant). Missing file →
/// `false` (i.e. show the banner). Read errors → `false` so a transient
/// IO hiccup never silences a banner the operator hasn't seen.
pub fn version_already_seen(path: &Path, version: &str) -> bool {
    let needle = version.trim().to_ascii_lowercase();
    let Ok(content) = fs::read_to_string(path) else {
        return false;
    };
    content
        .lines()
        .map(|l| l.trim().to_ascii_lowercase())
        .any(|l| l == needle)
}

/// Append one version line to the seen_versions file. Creates parent
/// directories with mode 0700 (matching the auth_token convention),
/// the file itself in append mode. Idempotency is the caller's
/// responsibility — duplicate lines are harmless because
/// [`version_already_seen`] handles them.
fn append_version_line(path: &Path, version: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perm = fs::metadata(parent)?.permissions();
                perm.set_mode(0o700);
                let _ = fs::set_permissions(parent, perm);
            }
        }
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{version}")?;
    Ok(())
}

/// Column at which [`wrap_prose`] breaks, **before** the 2-cell indent
/// [`modal_form::prose_rows`] adds.
///
/// A constant, not a function of the passed width, for the reason
/// `modal_form::VERBATIM_WRAP` documents: [`modal_form::render_modal`]
/// builds the body once at `w` and again at `w - 1` when a scrollbar claims
/// a column, so a width-derived wrap yields a different row count between
/// the two passes and silently mis-sizes the modal. 59 is the same floor
/// that constant encodes for a 64-column notice.
const PROSE_WRAP: usize = 59;

/// Greedy word wrap into lines of at most [`PROSE_WRAP`] characters.
///
/// **Why this exists rather than [`modal_form::ProseRow::verbatim`].** The
/// ecosystem's two prose shapes are both wrong for sentences:
/// `ProseRow::plain` is one line and ellipsises the rest, and `verbatim`
/// wraps by **character** in bold `ValueKind` colour — correct for an id or
/// a domain the operator must transcribe exactly, wrong for English, which
/// it would break mid-word and paint as a value.
///
/// So the text is wrapped here and handed over one `plain` row per line:
/// each row then fits on its line, nothing ellipsises, and the row count
/// stays a function of the spec rather than of the width. A word longer
/// than the budget is emitted on its own overlong line and clipped rather
/// than split — a URL or a path is worth more whole-ish than halved, and
/// the alternative is the character wrap this function exists to avoid.
/// Wrap a multi-paragraph body: [`wrap_prose`] per `\n`-separated
/// paragraph, with each blank paragraph kept as one blank row.
///
/// [`wrap_prose`] alone cannot do this — it calls `split_whitespace`, which
/// treats `\n` as an ordinary space, so a three-item checklist collapses
/// into one undifferentiated block. The blank rows are the only thing
/// separating the three items in [`welcome_copy`]: `prose_row` renders each
/// line with a flat 2-cell indent, so a wrapped continuation line is
/// indistinguishable from the start of the next item without them.
///
/// A blank row costs a row of the 19 the floor allows, which is why they
/// are counted by `welcome_copy_fits_the_floor_row_budget` like any other.
///
/// Identity on a body with no `\n`, so [`BannerKind::NotReady`] — whose
/// detail is one paragraph — goes through this unchanged.
fn wrap_paragraphs(text: &str, cols: usize) -> Vec<String> {
    let mut out = Vec::new();
    for para in text.split('\n') {
        if para.trim().is_empty() {
            out.push(String::new());
        } else {
            out.extend(wrap_prose(para, cols));
        }
    }
    out
}

fn wrap_prose(text: &str, cols: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if line.is_empty() {
            line.push_str(word);
        } else if line.chars().count() + 1 + word.chars().count() <= cols {
            line.push(' ');
            line.push_str(word);
        } else {
            out.push(std::mem::take(&mut line));
            line.push_str(word);
        }
    }
    if !line.is_empty() {
        out.push(line);
    }
    out
}

/// Build the Archetype-C spec for whichever state the banner is in.
///
/// The two states share the chrome and differ in every word, which is the
/// point: an operator whose dashboard cannot read a config is not greeted,
/// they are told what is wrong.
fn notice_spec(banner: &WelcomeBanner) -> modal_form::NoticeSpec {
    let (title, desc, body) = match &banner.kind {
        BannerKind::Welcome => (
            // The version rides the title band, not the body: it is one
            // row of the 19 the floor allows (see the module note), and a
            // title band is where an operator already looks for "what am I
            // running". Pinned at the render by
            // `welcome_shows_the_running_build_version_on_screen`.
            format!("Welcome to purge-warden v{}", env!("CARGO_PKG_VERSION")),
            WELCOME_DESC.to_string(),
            banner.copy.clone(),
        ),
        BannerKind::NotReady { headline, detail } => (
            "Dashboard is not reading your configuration".to_string(),
            headline.clone(),
            format!(
                "{detail} Until then this dashboard shows built-in defaults, not your \
                 setup — the daemon itself may be running perfectly."
            ),
        ),
    };

    modal_form::NoticeSpec {
        title,
        desc,
        prose: wrap_paragraphs(&body, PROSE_WRAP)
            .into_iter()
            .map(modal_form::ProseRow::plain)
            .collect(),
        choices: Vec::new(),
        error: None,
        hint: "press any key to dismiss".to_string(),
        hint_rows: Some(1),
        keys: String::new(),
        actions: Vec::new(),
    }
}

/// Render the banner as a centred overlay on top of `frame`.
///
/// **Archetype C, not hand-rolled chrome.** This used to be a bare `Block`
/// with a centre-aligned `Paragraph` at a fixed 64×7 — the only overlay in
/// the TUI outside the modal ecosystem, and it read as foreign next to
/// every other surface: centred where the rest is left-aligned at a 2-cell
/// indent, and with no title band or description band at all.
///
/// The fixed height was the worse half. Seven rows held the one-sentence
/// copy it shipped with and nothing longer, so any revision that said more
/// would have been clipped by the box — silently, the way
/// `feedback_modal_form_wrap_clips_full_width_rows` records for the form
/// rows. [`modal_form::render_modal`] derives the height from the row count
/// instead, so the surface now grows with its content and the clipping
/// failure mode is gone by construction rather than by choosing shorter
/// words.
pub fn render_overlay(f: &mut Frame, banner: &WelcomeBanner, area: Rect) {
    const W: u16 = 64;
    let spec = notice_spec(banner);
    modal_form::render_modal(f, area, W, |w| (modal_form::notice_body(&spec, w), ()));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_seen_versions_path() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seen_versions");
        (dir, path)
    }

    /// The deliverable itself: the three things a fresh install needs,
    /// **in the operator's order** — upstreams, lists, point the clients
    /// here. Order is asserted by byte offset, not by presence: a copy
    /// that mentions all three but leads with lists sends someone to
    /// subscribe a blocklist on a box that cannot resolve anything.
    #[test]
    fn welcome_copy_names_the_three_first_run_steps_in_order() {
        let copy = welcome_copy();
        let up = copy
            .find("Upstreams")
            .unwrap_or_else(|| panic!("no upstreams step:\n{copy}"));
        let lists = copy
            .find("2  Lists")
            .unwrap_or_else(|| panic!("no lists step:\n{copy}"));
        let point = copy
            .find("Point your clients")
            .unwrap_or_else(|| panic!("no client-DNS step:\n{copy}"));
        assert!(up < lists && lists < point, "wrong order:\n{copy}");

        // Each step has to say what goes wrong without it, or it is a
        // chore list rather than an explanation.
        for why in [
            "names no provider for you",
            "blocks nothing",
            "warden sees no query",
        ] {
            assert!(copy.contains(why), "missing the {why:?} reason:\n{copy}");
        }
    }

    /// The `g <letter>` hints are **derived** from [`Leaf::mnemonic`], so
    /// this asserts the derivation actually happened rather than that
    /// some letter is present: it
    /// rebuilds each hint from the live table and requires it in the copy.
    /// A hand-typed `g i` would pass today and rot the day `i` moves; a
    /// derived one cannot.
    #[test]
    fn welcome_copy_uses_the_live_leaf_mnemonics() {
        let copy = welcome_copy();
        for leaf in [Leaf::Dashboard, Leaf::File, Leaf::Lists, Leaf::QueryLog] {
            let hint = format!("(g {})", leaf.mnemonic());
            assert!(
                copy.contains(&hint),
                "copy must advertise {hint} for {leaf:?}:\n{copy}"
            );
            assert!(
                copy.contains(leaf.label()),
                "a bare key is unfindable — copy must name the {leaf:?} leaf too:\n{copy}"
            );
        }
        // The retired advert must not creep back: it is the exact copy this
        // rewrite replaced, and the `[5]` / 0.4.7 pair is the staleness this
        // module has already shipped once.
        for dead in ["local DNS records", "[5]", "What's new in 0.4.7"] {
            assert!(!copy.contains(dead), "retired copy resurfaced: {dead:?}");
        }
    }

    /// Every leaf-local key the copy advertises must still be a binding of
    /// the leaf it is advertised on.
    ///
    /// **This one is weaker than it looks, and the weakness is the point of
    /// saying so.** It reads `help::per_leaf_rows`, which is the `?`
    /// overlay's table, not the `handle_*_key` match — a rebind that
    /// forgets to update help passes here. It is a paper pin, kept because
    /// the table is the operator-facing contract and `Leaf::Logs`'s own
    /// help block already declares the invariant that makes it meaningful
    /// ("every binding `handle_logs_key` answers to has a row here.
    /// Non-negotiable"). The real pin for `a` and `B` drives the live
    /// handler and lives in `tui::mod`'s
    /// `welcome_banner_lists_keys_are_live_bindings`, because
    /// `handle_lists_key` is private, async, and needs a poller.
    #[test]
    fn welcome_copy_advertises_only_live_leaf_local_keys() {
        let copy = welcome_copy();
        for (leaf, key) in [(Leaf::Lists, "B"), (Leaf::Lists, "a"), (Leaf::File, "e")] {
            assert!(
                crate::tui::help::per_leaf_rows(leaf)
                    .iter()
                    .any(|r| r.key == key),
                "copy advertises {key:?} on {leaf:?}, which is not one of its bindings"
            );
            // Two spaces each side: that is the copy's deliberate key
            // highlight, and it occurs nowhere else. A single-space ` a `
            // would also match the indefinite article — a needle that
            // cannot tell a hit from a coincidence.
            assert!(
                copy.contains(&format!("  {key}  ")),
                "the pin lists {key:?} but the copy no longer advertises it:\n{copy}"
            );
        }
    }

    /// The body has to FIT, and the failure it guards is silent.
    ///
    /// [`notice_spec`] passes no choices, so `notice_body` returns
    /// `scrollable: false` and `render_scroll_body` cuts the overflow with
    /// no scrollbar and no `…`. The budget is computed through the real
    /// allocator rather than against a hardcoded 19, so it follows
    /// `scroll_layout` if the allocation rule ever changes.
    #[test]
    fn welcome_copy_fits_the_floor_row_budget() {
        // 80×24 is the floor `ui::render` will draw at (MIN_WIDTH /
        // MIN_HEIGHT); the banner anchors to the whole frame, so a 64-wide
        // modal clamped to 24 rows leaves a 22-row interior.
        const FLOOR_INTERIOR: usize = 22;
        // What `notice_spec` builds: title band + desc band, and a tail of
        // exactly `hint_rows: Some(1)` with no keys row and no actions.
        const HEAD: usize = 2;
        const TAIL: usize = 1;

        let rows = wrap_paragraphs(&welcome_copy(), PROSE_WRAP).len();
        let (head_h, view_h, tail_h) = modal_form::scroll_layout(FLOOR_INTERIOR, HEAD, rows, TAIL);
        assert_eq!(head_h, HEAD, "the head was cut — the copy is far too long");
        assert_eq!(tail_h, TAIL, "the tail was cut — the copy is far too long");
        assert_eq!(
            view_h, rows,
            "{rows} prose rows do not fit the {FLOOR_INTERIOR}-row floor \
             interior ({view_h} visible). The overflow is cut SILENTLY — no \
             scrollbar, no ellipsis. Shorten the copy."
        );
    }

    /// `desc_band` does not wrap: it `fit`s to one line and ellipsises. The
    /// body is protected by [`wrap_prose`]; this string is not, so it needs
    /// its own measurement against the band's own budget.
    #[test]
    fn welcome_desc_band_is_not_truncated() {
        // `desc_band` renders `fit("  {text}", width)` at the 62-cell inner
        // width of the 64-column modal, so the indent leaves 60 usable.
        const DESC_BUDGET: usize = 60;
        assert!(
            WELCOME_DESC.chars().count() <= DESC_BUDGET,
            "desc band is {} cells, over the {DESC_BUDGET}-cell budget — it \
             will be ellipsised: {WELCOME_DESC:?}",
            WELCOME_DESC.chars().count()
        );
        // A tempdir, not `/dev/null`: these tests never call `dismiss()`,
        // but a banner holding that path is one method call away from
        // `create_dir_all("/")`. A test that is safe only because of what it
        // does NOT call is a test waiting for its next edit.
        let (_dir, path) = tmp_seen_versions_path();
        let banner = WelcomeBanner::with_path(WELCOME_SEEN_KEY, welcome_copy(), path);
        let dump = render_to_lines(&banner).join("\n");
        assert!(
            dump.contains(WELCOME_DESC),
            "the description band was cut on screen:\n{dump}"
        );
    }

    #[test]
    fn welcome_uses_a_fixed_seen_key_not_the_build_version() {
        let dir = tempfile::tempdir().unwrap();
        let prev = std::env::var("XDG_CONFIG_HOME").ok();
        std::env::set_var("XDG_CONFIG_HOME", dir.path());
        let banner = WelcomeBanner::welcome();
        assert_eq!(
            banner.version, WELCOME_SEEN_KEY,
            "dedup key must be stable so the banner shows once, not per upgrade"
        );
        assert_ne!(
            banner.version,
            env!("CARGO_PKG_VERSION"),
            "the seen key must not track the build version"
        );
        assert_eq!(banner.copy, welcome_copy());
        assert!(banner.persist_path.is_some());
        match prev {
            Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
    }

    #[test]
    fn welcome_resolves_persist_path_when_xdg_or_home_is_set() {
        // Force XDG_CONFIG_HOME so we don't depend on ambient $HOME.
        let dir = tempfile::tempdir().unwrap();
        let prev_xdg = std::env::var("XDG_CONFIG_HOME").ok();
        std::env::set_var("XDG_CONFIG_HOME", dir.path());
        let banner = WelcomeBanner::welcome();
        assert!(banner.persist_path.is_some());
        let p = banner.persist_path.unwrap();
        assert!(p.ends_with("purge-warden/seen_versions"), "{}", p.display());
        match prev_xdg {
            Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
    }

    #[test]
    fn dismiss_marks_the_key_seen() {
        let (_dir, path) = tmp_seen_versions_path();
        let banner = WelcomeBanner::with_path(WELCOME_SEEN_KEY, welcome_copy(), path.clone());
        assert!(!version_already_seen(&path, WELCOME_SEEN_KEY));
        banner.dismiss();
        assert!(
            version_already_seen(&path, WELCOME_SEEN_KEY),
            "after dismiss the key must be marked seen"
        );
        let body = fs::read_to_string(&path).unwrap();
        assert!(body.contains(WELCOME_SEEN_KEY), "body: {body}");
    }

    /// Render the overlay at 80×24 (the D18 floor) and return the buffer as
    /// one string per row, so assertions read like the screen does.
    fn render_to_lines(banner: &WelcomeBanner) -> Vec<String> {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| {
            let area = f.area();
            render_overlay(f, banner, area);
        })
        .unwrap();
        let buf = term.backend().buffer();
        (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect()
    }

    /// The diagnosis must not be recorded as seen. If it were, an operator
    /// who dismissed it once would get a dashboard full of built-in defaults
    /// with nothing on screen saying why — for every launch after.
    #[test]
    fn not_ready_never_persists_its_dismissal() {
        let (_dir, path) = tmp_seen_versions_path();
        let banner = WelcomeBanner::not_ready("headline", "detail");
        assert!(
            banner.persist_path.is_none(),
            "a diagnosis has nothing to record — it is true until fixed"
        );
        banner.dismiss();
        assert!(
            !path.exists(),
            "dismissing a diagnosis must not write seen_versions"
        );
    }

    /// The welcome keeps the opposite rule, so the two cannot be collapsed
    /// into one persistence policy by a later simplification.
    #[test]
    fn welcome_still_persists_its_dismissal() {
        let (_dir, path) = tmp_seen_versions_path();
        let banner = WelcomeBanner::with_path(WELCOME_SEEN_KEY, welcome_copy(), path.clone());
        banner.dismiss();
        assert!(version_already_seen(&path, WELCOME_SEEN_KEY));
    }

    /// The defect that started this: a fixed 64×7 box silently clipped copy
    /// longer than its two body rows. The detail is now ~380 characters, so
    /// this fails on any return to a fixed-height overlay.
    #[test]
    fn not_ready_renders_its_whole_detail() {
        let detail = "Blocked: /var/lib/purge-warden/config.toml. warden's config is owned \
                      by the system user the daemon runs as, so this is a permissions \
                      problem, NOT a missing install. Re-run as that user. Do NOT run \
                      warden init — it would write a second config beside the existing one.";
        let banner = WelcomeBanner::not_ready("config found but not readable by this user", detail);
        let dump = render_to_lines(&banner).join("\n");

        // Every word of the detail must be on screen somewhere. Checking the
        // last sentence alone would pass on a box that clipped the middle.
        for word in detail.split_whitespace() {
            assert!(
                dump.contains(word),
                "detail word {word:?} was clipped off the overlay:\n{dump}"
            );
        }
        assert!(
            dump.contains("config found but not readable by this user"),
            "the headline must ride the description band:\n{dump}"
        );
    }

    /// The whole deliverable is text, so a row the operator cannot read is
    /// the failure of this task specifically. Renders the REAL overlay at
    /// the 80×24 floor and requires every word of the copy on screen.
    ///
    /// Secondary to `welcome_copy_fits_the_floor_row_budget`, deliberately.
    /// Word-presence is weaker than it looks: a common word ("press", "the")
    /// can be satisfied by the title band or the dismiss hint even when its
    /// row was cut. The row-count assertion is the real pin; this one
    /// catches whatever the arithmetic gets wrong about the render.
    #[test]
    fn welcome_renders_every_word_at_the_floor() {
        let copy = welcome_copy();
        // A tempdir, not `/dev/null`: these tests never call `dismiss()`,
        // but a banner holding that path is one method call away from
        // `create_dir_all("/")`. A test that is safe only because of what it
        // does NOT call is a test waiting for its next edit.
        let (_dir, path) = tmp_seen_versions_path();
        let banner = WelcomeBanner::with_path(WELCOME_SEEN_KEY, copy.clone(), path);
        let dump = render_to_lines(&banner).join("\n");
        for word in copy.split_whitespace() {
            assert!(
                dump.contains(word),
                "copy word {word:?} is not on screen at 80×24:\n{dump}"
            );
        }
        // Line-level, not word-level: every wrapped row must survive whole.
        // A row cut mid-way still passes the word check above for every word
        // before the cut.
        for row in wrap_paragraphs(&copy, PROSE_WRAP) {
            if row.is_empty() {
                continue;
            }
            assert!(
                dump.contains(&row),
                "wrapped row {row:?} was clipped or ellipsised:\n{dump}"
            );
        }
        assert!(
            !dump.contains('\u{2026}'),
            "something was ellipsised on the welcome overlay:\n{dump}"
        );
    }

    /// Pinned at the render rather than at the string. The version left
    /// the body (it costs a row of the 19 the floor allows) and rides
    /// the title band instead, so the invariant that
    /// matters — the operator sees the version they are running — has to be
    /// asserted against the buffer.
    #[test]
    fn welcome_shows_the_running_build_version_on_screen() {
        // A tempdir, not `/dev/null`: these tests never call `dismiss()`,
        // but a banner holding that path is one method call away from
        // `create_dir_all("/")`. A test that is safe only because of what it
        // does NOT call is a test waiting for its next edit.
        let (_dir, path) = tmp_seen_versions_path();
        let banner = WelcomeBanner::with_path(WELCOME_SEEN_KEY, welcome_copy(), path);
        let dump = render_to_lines(&banner).join("\n");
        assert!(
            dump.contains(env!("CARGO_PKG_VERSION")),
            "the running build version must be on screen:\n{dump}"
        );
        assert!(
            !dump.contains("0.4.7") || env!("CARGO_PKG_VERSION") == "0.4.7",
            "a frozen version literal resurfaced:\n{dump}"
        );
    }

    /// Archetype C, not the hand-rolled block it used to be. The red `▌`
    /// tick is `modal_form::title_band`'s first cell and nothing else in the
    /// ecosystem draws it, so its presence is the cheap structural proof
    /// that the shared chrome is what rendered.
    #[test]
    fn overlay_uses_the_ecosystem_title_band() {
        let banner = WelcomeBanner::not_ready("headline here", "detail here");
        let dump = render_to_lines(&banner).join("\n");
        assert!(
            dump.contains('\u{258c}'),
            "no title-band tick — the overlay is not Archetype C:\n{dump}"
        );
    }

    #[test]
    fn wrap_prose_never_exceeds_the_budget_and_loses_no_words() {
        let text = "one two three four five six seven eight nine ten eleven twelve \
                    thirteen fourteen fifteen sixteen seventeen eighteen nineteen";
        let lines = wrap_prose(text, PROSE_WRAP);
        for line in &lines {
            assert!(
                line.chars().count() <= PROSE_WRAP,
                "line over budget ({}): {line:?}",
                line.chars().count()
            );
        }
        assert_eq!(
            lines.join(" ").split_whitespace().collect::<Vec<_>>(),
            text.split_whitespace().collect::<Vec<_>>(),
            "wrapping must not drop or reorder words"
        );
    }

    /// A word longer than the budget goes out whole on its own line rather
    /// than being split mid-character. Paths and URLs are the real case.
    #[test]
    fn wrap_prose_keeps_an_overlong_word_intact() {
        let long = "/var/lib/purge-warden/an/extremely/deeply/nested/path/that/exceeds/the/budget";
        assert!(long.chars().count() > PROSE_WRAP);
        let lines = wrap_prose(&format!("prefix {long} suffix"), PROSE_WRAP);
        assert!(
            lines.iter().any(|l| l.contains(long)),
            "the long token was split: {lines:?}"
        );
    }

    #[test]
    fn version_already_seen_returns_false_when_file_missing() {
        let (_dir, path) = tmp_seen_versions_path();
        assert!(!version_already_seen(&path, WELCOME_SEEN_KEY));
    }

    #[test]
    fn version_already_seen_is_case_insensitive_and_trim_tolerant() {
        let (_dir, path) = tmp_seen_versions_path();
        // The literal deliberately mis-cases and pads the CURRENT key — it
        // pins the comparison's tolerance, not the key's value. It broke on
        // the v1→v2 bump and again on v2→v3, which is the right kind of
        // break: a version bump that left this green would be a bump that
        // changed nothing.
        fs::write(&path, "  Welcome-Setup-V3  \nother-key\n").unwrap();
        assert!(version_already_seen(&path, WELCOME_SEEN_KEY));
        assert!(version_already_seen(&path, "other-key"));
        assert!(!version_already_seen(&path, "unseen-key"));
    }

    #[test]
    fn dismiss_appends_without_overwriting_prior_keys() {
        let (_dir, path) = tmp_seen_versions_path();
        fs::write(&path, "0.4.6\n").unwrap();
        let banner = WelcomeBanner::with_path(WELCOME_SEEN_KEY, welcome_copy(), path.clone());
        banner.dismiss();
        let body = fs::read_to_string(&path).unwrap();
        assert!(body.contains("0.4.6"), "prior key must survive: {body}");
        assert!(
            body.contains(WELCOME_SEEN_KEY),
            "new key must be appended: {body}"
        );
    }

    #[test]
    fn dismiss_with_no_persist_path_is_a_no_op() {
        let banner = WelcomeBanner {
            version: WELCOME_SEEN_KEY.into(),
            kind: BannerKind::Welcome,
            copy: welcome_copy(),
            persist_path: None,
        };
        // Must not panic; the banner has already done its UX job.
        banner.dismiss();
    }
}
