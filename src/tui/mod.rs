//! Interactive TUI dashboard for purge-warden.
//!
//! Launched via `warden dashboard`. Connects to the running daemon over IPC
//! and displays live stats, query logs, device activity, and configuration.

mod app;
mod backup_restore_modal;
mod custom_list_modal;
mod event;
mod format;
// The Groups Add / Edit / Delete modal. Private, unlike
// `subnet_modal` — that one was promoted so a frozen-string integration
// test could reach `SUBNET_SUGGESTED_TAG` through it; this module exports
// no frozen string, and `app::GroupsState` reaches it as a sibling
// descendant of `crate::tui`.
mod group_modal;
mod help;
mod ipc_poller;
mod label_modal;
mod local_dns_modal;
mod modal_form;
mod overlay;
// Profiles tab modal (Add / Edit / Delete).
//
// Promoted to `pub mod` on the same
// `subnet_modal` / `rule_add_modal` precedent: the per-list override
// panel's vocabulary is operator-facing and
// `tests/frozen_strings_plp_list_override_panel.rs` pins it BY VALUE.
// The `include_str!` source-grep idiom the Phase 2 file still uses passes
// just as happily on a const that nothing renders — see the note on the
// `tabs::lists` re-export below, which was promoted for the same reason.
//
// `main` carried this as a private `mod` with a note saying no promotion
// was needed, which was true of the `include_str!` test and is not true of
// the by-value one. The stricter of the two requirements wins.
pub mod profile_modal;
pub mod query_log_filter_modal;
mod query_log_rule_modal;
// Promoted to `pub mod` so the integration test
// `tests/resolver_modal_global_hotkey.rs` can reach `ResolverModal` to
// pin the open/close lifecycle that the global `s` hotkey relies on.
pub mod resolver_modal;
// Promoted to `pub mod` (same precedent as
// `subnet_modal` / `resolver_modal` below) so `app::RulesState::add_modal`
// can hold the public `RuleAddModal` type and
// `tests/frozen_strings_tui_rules_add.rs` can reach its consts.
pub mod rule_add_modal;
// Promoted to `pub mod` so `app::SubnetsState::modal` can hold
// the public type and the frozen-string integration test can reach
// `SUBNET_SUGGESTED_TAG` from `tabs::subnets`.
pub mod subnet_modal;
mod tabs;
// Re-export the pure stale predicate so the
// `tests/tui_stale_badge_fixture.rs` integration test can pin it
// without promoting the whole `tabs` private module — keeps the
// internal cargo of `tabs::lists` (render fns, modal builders)
// hidden from external crate consumers.
pub use tabs::lists::is_stale_for_dto;
// Same narrow-re-export precedent, for the unsigned-allow consent copy.
// `tests/frozen_strings_tui_allow_consent.rs` pins these byte-for-byte;
// they are the operator's entire view of a decision with no undo and no
// lasting mark on the Lists tab, so the pin has to be on the VALUES.
// The `include_str!` source-grep idiom the other TUI string tests use
// would pin the source text instead, which passes just as happily on a
// const that nothing renders.
pub use tabs::lists::{
    format_kind_toggle_ok, format_list_allow_consent_saved, KIND_TOGGLE_OK_ALLOW,
    KIND_TOGGLE_OK_BLOCK, LIST_ALLOW_CONSENT_SAVED, UNSIGNED_ALLOW_CONFIRM_DESC,
    UNSIGNED_ALLOW_CONFIRM_HINT, UNSIGNED_ALLOW_CONFIRM_MISMATCH, UNSIGNED_ALLOW_CONFIRM_PROMPT,
    UNSIGNED_ALLOW_CONFIRM_RISK_1, UNSIGNED_ALLOW_CONFIRM_RISK_2, UNSIGNED_ALLOW_CONFIRM_TITLE,
};
mod theme;
// The transient action-feedback overlay. Lives beside `ui`
// rather than inside it — `ui` owns the four-chunk frame layout, the
// toast owns a rect it floats *inside* one of those chunks.
mod toast;
mod ui;
// Promoted from `mod` to `pub mod` so an integration test
// `tests/frozen_strings_local_dns_v2.rs` can reach the banner copy
// (`welcome_copy`). Other items in the module (constructors, fs helpers)
// are not used externally; promoting the module is cleaner than threading
// individual re-exports.
pub mod welcome_banner;
mod wordmark;

// Frozen-strings reach: the integration test
// `tests/frozen_strings_s43.rs` pins these strings byte-for-byte. The
// const lives in the private `tabs::lists` module; this re-export
// makes it reachable as `purge_warden::tui::LISTS_TAB_EMPTY` without
// promoting the rest of the `tabs` module surface.
pub use tabs::lists::LISTS_TAB_EMPTY;

// Frozen-strings reach: the integration test
// `tests/frozen_strings_s47.rs` pins the three Query Log neutral-status
// footer messages byte-for-byte. Same pattern as `LISTS_TAB_EMPTY`
// above — selective re-export keeps the rest of `tabs::query_log`
// private.
pub use tabs::query_log::{
    QUERY_NOT_ACTIONABLE_LOCAL, QUERY_NOT_ACTIONABLE_REFUSED, QUERY_NOT_ACTIONABLE_UNKNOWN,
};

// Frozen-strings reach: the integration test
// `tests/frozen_strings_s45_p2.rs` pins the CNAME chain block badge
// rendered in the Query Log RESULT column when `cname_chain_via` is
// populated. Same pattern as the other re-exports here.
pub use tabs::query_log::CNAME_CHAIN_BLOCK_BADGE;

// Frozen-strings reach: the integration test
// `tests/frozen_strings_s51.rs` pins the auto-discovery suggestion
// marker byte-for-byte. Same selective re-export idiom.
pub use tabs::subnets::SUBNET_SUGGESTED_TAG;

// Frozen-strings reach: the integration test
// `tests/frozen_strings_tui_t1.rs` pins the Profiles detail-pane "What it
// blocks" summary literals byte-for-byte. The consts live in the private
// `tabs::profiles` module; this selective re-export makes them reachable as
// `purge_warden::tui::PROFILE_*` without promoting the rest of the module.
pub use tabs::profiles::{
    PROFILE_BLOCKS_ALL_QUERIES, PROFILE_BLOCKS_LOADING, PROFILE_BLOCKS_NONE,
    PROFILE_BLOCKS_PARTIAL, PROFILE_CUSTOM_LISTS_NONE, PROFILE_LABEL_ALSO,
    PROFILE_LABEL_BLOCKLISTS, PROFILE_LABEL_CUSTOM_LISTS, PROFILE_LABEL_WHAT_IT_BLOCKS,
};

// Reach for the integration test
// `tests/resolver_modal_global_hotkey.rs`, which pins the resolver-modal
// open/close lifecycle that the global `s` hotkey relies on. Selective
// re-export of `App` + `Leaf` keeps the rest of the `app` module
// private — only the two types the lifecycle pin needs surface.
pub use app::{App, Leaf};

use std::path::{Path, PathBuf};
use std::sync::Once;
use std::time::{Duration, Instant};

use crossterm::event::{
    DisableBracketedPaste, EnableBracketedPaste, KeyCode, KeyEvent, KeyModifiers,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use crate::cli::config_discovery::DiscoveryWarning;

use app::{
    CustomListsFocus, DeviceFormField, DeviceFormFocus, DeviceFormMode, DeviceFormState,
    DeviceModal, FieldPicker, InputMode, LabelsFocus, Section,
};
use event::Event;
use ipc_poller::IpcPoller;
use tabs::file;

use crate::config::settings::ClientConfig;
use crate::ipc::protocol::DevicePatch;

/// Tick rate for the event reader (controls render frequency).
const TICK_RATE: Duration = Duration::from_millis(33); // ~30 FPS

/// How often to poll the active tab's data.
const POLL_DASHBOARD: Duration = Duration::from_secs(2);
const POLL_QUERY_LOG: Duration = Duration::from_secs(3);
const POLL_DEVICES: Duration = Duration::from_secs(5);
/// Lists poll slower than the dashboard: lists change on operator action.
const POLL_LISTS: Duration = Duration::from_secs(30);
/// Poll cadence for the
/// `Leaf::LocalDns` hits column. Records change rarely (operator-driven
/// via `warden local-dns add/remove`) and the counter is a stats read,
/// so a 5 s tick is plenty — operators reading "is this firing?" see a
/// fresh number on every focus shift without the daemon paying the
/// dashboard-grade 2 s rate.
const POLL_LOCAL_DNS: Duration = Duration::from_secs(5);
/// `logs-tab`: poll cadence for the Log Messages leaf. See the arm in the
/// `poll_interval` match for why 5 s.
const POLL_LOGS: Duration = Duration::from_secs(5);
/// `logs-tab`: rows requested per poll. Half the ring — deep enough that
/// scrolling rarely hits the end, small enough that a 5 s cadence is not
/// re-serialising 1000 strings a minute. The title says "of ≤capacity" so
/// the operator can see this is a page, not the whole buffer.
const LOGS_PAGE_LIMIT: usize = 500;
const POLL_HEARTBEAT: Duration = Duration::from_secs(5);

/// Entry point for the TUI. Called from main.rs.
///
/// `startup_warning` is plumbed through from the config-discovery step so
/// messages like "no config file found" land in the TUI instead of being
/// swallowed by the alternate screen buffer. It arrives as a
/// [`DiscoveryWarning`] rather than a string because the two surfaces that
/// consume it have different width budgets: the footer takes the headline,
/// the first-run notice overlay takes the detail.
pub async fn run(
    socket_path: &Path,
    config_path: &Path,
    startup_warning: Option<DiscoveryWarning>,
) -> anyhow::Result<()> {
    use std::io::IsTerminal;

    // Refuse to start without an interactive terminal. Entering raw mode on a
    // pipe / `nohup` / non-tty (e.g. a root shell with no controlling tty)
    // gives a dashboard that can never receive input and whose reader thread
    // would immediately hit the dead-tty path. Bail with a clear message
    // instead. The `su … -c 'exec warden dashboard'` operator wrapper inherits
    // a real pts, so it is unaffected.
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        anyhow::bail!(
            "warden dashboard requires an interactive terminal (stdin/stdout are not a TTY)"
        );
    }

    // Install the terminal-restore panic hook BEFORE entering raw mode. It
    // covers the *panic* exit; `TerminalGuard` below covers every *return*
    // exit. Both are load-bearing — see `restore_terminal`.
    install_terminal_restore_panic_hook();

    // Setup terminal. Raw mode goes on first because if IT fails there is
    // nothing to restore; from the very next statement the guard is armed and
    // every path out of this function runs the restore.
    enable_raw_mode()?;
    // tui-06: ARM THE RESTORE. Must be a *named* binding — `let _ = ` would
    // drop the guard immediately and restore the terminal while the TUI is
    // still running. Before this existed, the three fallible setup calls below
    // returned through `?` straight past the manual cleanup block, stranding
    // the operator's shell in raw + alt-screen mode (no echo, garbled cursor,
    // unrecoverable without `reset`). The guard makes that unreachable by
    // construction rather than by remembering to call cleanup.
    let _restore_guard = TerminalGuard::new();

    let mut stdout = std::io::stdout();
    // EnableBracketedPaste so a terminal paste arrives as one atomic
    // `Event::Paste` instead of a synthetic key storm. PAIRED
    // with DisableBracketedPaste in `restore_terminal`, which both the guard
    // and the panic hook run — a half-pair would leave the operator's terminal
    // in bracketed mode after exit.
    execute!(stdout, EnterAlternateScreen, EnableBracketedPaste)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    // `_restore_guard` drops on the way out of this scope — whichever way we
    // leave, including the `?` above and any `Err` from `run_app`.
    run_app(&mut terminal, socket_path, config_path, startup_warning).await
}

/// RAII terminal-state guard (tui-06). Armed immediately after
/// `enable_raw_mode` in [`run`]; its `Drop` runs [`restore_terminal`], so the
/// operator's shell is handed back cooked on **every** return path — the clean
/// one, and the `?` early-returns from the fallible setup calls that used to
/// jump over the old hand-written cleanup block.
///
/// The restore action is a field rather than a hard-coded call so the
/// arm-then-early-return contract is unit-testable without a real tty (see
/// `terminal_guard_restores_on_early_question_mark_return`).
struct TerminalGuard {
    restore: fn(),
}

impl TerminalGuard {
    fn new() -> Self {
        Self {
            restore: restore_terminal,
        }
    }

    /// Test seam: swap the restore action for an observable one.
    #[cfg(test)]
    fn with_restore(restore: fn()) -> Self {
        Self { restore }
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        (self.restore)();
    }
}

/// The single terminal-restore sequence: leave raw mode, leave the alternate
/// screen, disable bracketed paste, show the cursor. Best-effort — each step is
/// `let _ =` so a failure in one still runs the rest and the terminal lands as
/// close to cooked mode as it can. Never blocks: these are ioctls and short
/// writes on the tty, and their errors are discarded, so a dead pty cannot
/// wedge the teardown.
///
/// Two callers, and NEITHER is redundant:
///
/// * [`TerminalGuard::drop`] — covers every **return** out of [`run`]
///   (clean, and the `?` early-returns from terminal setup: tui-06).
/// * [`install_terminal_restore_panic_hook`] — covers every **panic**.
///
/// The guard does **not** subsume the hook, despite what the shape of the code
/// suggests. `[profile.release] panic = "abort"` (Cargo.toml) means the shipped
/// binary does not unwind: on a panic, `Drop` never runs and the hook is the
/// only thing standing between the operator and a stranded shell. The hook also
/// catches panics on the event-reader and hangup-watchdog threads, whose unwind
/// never touches `run`'s frame at all. Do not delete it as "now redundant".
fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(
        std::io::stdout(),
        LeaveAlternateScreen,
        DisableBracketedPaste,
        crossterm::cursor::Show
    );
}

async fn run_app(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    socket_path: &Path,
    config_path: &Path,
    startup_warning: Option<DiscoveryWarning>,
) -> anyhow::Result<()> {
    let mut app = App::new();
    app.startup_warning = startup_warning;

    // Surface the welcome banner on the first launch
    // since upgrade. `version_already_seen` reads
    // `~/.config/purge-warden/seen_versions`; missing file → show.
    // Dismissal in `handle_key` appends the banner's dedup key to the file
    // so subsequent launches do NOT re-show. The key is fixed (not the build
    // version), so the welcome shows once per operator and survives version
    // bumps; the copy itself is version-accurate at render.
    //
    // The decision consults `startup_warning` first. It was
    // already at this call site — `main.rs` passes it in — and the banner
    // ignored it, so a dashboard that could not read the operator's config
    // covered four correct stderr diagnostics with a cheerful advert for
    // Local DNS records. A greeting on top of a broken state is worse than
    // no greeting.
    //
    // The two branches differ in more than copy: the diagnosis is NOT gated
    // on `seen_versions`. See `BannerKind` for why suppressing it after one
    // viewing is the failure this shape prevents.
    app.welcome_banner = match app.startup_warning.as_ref() {
        Some(warn) => Some(welcome_banner::WelcomeBanner::not_ready(
            warn.headline.clone(),
            warn.detail.clone(),
        )),
        None => {
            let banner = welcome_banner::WelcomeBanner::welcome();
            let already_seen = banner
                .persist_path
                .as_deref()
                .map(|p| welcome_banner::version_already_seen(p, &banner.version))
                .unwrap_or(false);
            (!already_seen).then_some(banner)
        }
    };

    let poller = IpcPoller::new(socket_path);
    // Clone the editor-handoff flags into the reader thread: the `e`
    // handler sets `reader_suspended` and waits on `reader_parked` around the
    // blocking $EDITOR spawn so two readers never race the same tty.
    let mut events = event::spawn_event_reader(
        TICK_RATE,
        app.reader_suspended.clone(),
        app.reader_parked.clone(),
    );

    // Channel for background-job results (the catalog fetch). The
    // loop drains it in the select! below and applies each result via
    // `apply_job_result`, so remote HTTP runs off-thread and never blocks
    // the render/input path. The sender lives on `app` so `handle_key`
    // can spawn jobs without threading it through every handler.
    let (job_tx, mut job_rx) = tokio::sync::mpsc::unbounded_channel::<app::UiJob>();
    app.job_tx = Some(job_tx);

    // SIGHUP/SIGTERM/SIGINT → exit. Defense-in-depth alongside the reader
    // thread's dead-tty detection: if the kernel delivers a terminating signal
    // to this process (an attached session dropping, `systemctl stop`, a bare
    // `kill`, an orphan-cleanup sweep, a `timeout(1)` wrapper), tear down
    // cleanly through the terminal-restore path in `run` rather than dying by
    // default disposition mid-render — which would strand the operator's shell
    // in raw + alt-screen mode (the orphaned-dashboard incident
    // class, reachable one signal over). Reuses the daemon's *full* signal
    // pattern (src/cli/commands/start.rs), which installs terminate() as well
    // as hangup(); the TUI previously copied only the hangup half.
    //
    // Every signal handled here is exit-desired. tokio's process-wide signal
    // delivery can land EINTR on the hangup watchdog thread's `poll()` (which
    // `event::spawn_event_reader` does not auto-restart — a known deferred
    // issue), but because an EINTR-induced
    // early `Event::Eof` only triggers teardown — the very outcome TERM/INT/HUP
    // ask for — widening the handler set here stays benign. Do NOT add a
    // *non-exit* handler (e.g. a SIGUSR1 stats dump) without first fixing that
    // EINTR conflation, or a stray signal would become a spurious dashboard exit.
    //
    // Keyboard Ctrl+C is unaffected: raw mode disables ISIG, so ^C arrives as a
    // key event (handled below), not a signal. The interrupt() arm catches only
    // an *external* `kill -INT` from another shell.
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;

    // Load config for settings tab
    let (sections, config_text) = file::load_config(config_path);
    app.file.sections = sections;
    app.file.config_text = config_text;
    if !app.file.sections.is_empty() {
        app.file.sections_state.select(Some(0));
    }

    // Load the full v1 config once at startup for the Subnets,
    // Resolver tabs and the Devices source-annotation. Silent failure is
    // fine: each consuming tab renders a "config unreadable — press r"
    // hint when `loaded_config` is None.
    app.loaded_config = load_v1_config(config_path);

    // Prime the Settings-tab auto-backup snapshot so the
    // status line / failure banner are correct on first render.
    refresh_auto_backup_view(&mut app, config_path);

    // Tracking poll timestamps
    let mut last_poll = Instant::now() - Duration::from_secs(10); // force immediate poll
    let mut last_heartbeat = Instant::now() - Duration::from_secs(10);
    let mut dirty = true;

    loop {
        // Render if dirty
        if dirty {
            // Re-anchor the active tab's cursor to the rows it is
            // about to paint. A poll or a config reload can rebuild those
            // rows with no keypress involved, so this — not the key handler
            // — is the only place guaranteed to run between "the data
            // changed" and "the operator sees it".
            // The focus must not rest on a pane this width
            // does not paint. Here rather than in the renderer because the
            // key handler needs the clamped value too, before the next
            // frame ever draws.
            if let Ok(size) = terminal.size() {
                clamp_labels_focus_to_layout(&mut app, size.width);
                clamp_custom_lists_focus_to_layout(&mut app, size.width);
            }
            reconcile_active_leaf_selection(&mut app);
            terminal.draw(|f| ui::render(f, &mut app))?;
            dirty = false;
        }

        // Wait for the next event, or a terminating signal. All three signal
        // arms break into the normal-return teardown in `run` so the terminal
        // is restored on the way out (raw mode off, alt screen left) instead of
        // the kernel killing us mid-render.
        let event = tokio::select! {
            maybe = events.recv() => match maybe {
                Some(ev) => ev,
                None => break, // channel closed — reader thread gone
            },
            // A background job finished — apply its result and
            // redraw. Additive arm beside the signal/reader machinery;
            // it never blocks because the work already ran
            // off-thread.
            Some(job) = job_rx.recv() => {
                apply_job_result(&mut app, job);
                dirty = true;
                continue;
            }
            _ = sighup.recv() => break,  // controlling terminal hung up
            _ = sigterm.recv() => break, // systemctl stop / kill / orphan sweep
            _ = sigint.recv() => break,  // external kill -INT (keyboard ^C is a key event)
        };

        match event {
            // Reader thread detected a dead controlling terminal — exit so an
            // orphaned dashboard tears down instead of busy-looping.
            Event::Eof => break,
            Event::Key(key) => {
                dirty = true;
                if handle_key(&mut app, key, &poller, config_path).await {
                    break; // quit
                }
            }
            Event::Paste(pasted) => {
                // Atomic paste — append to the focused text buffer only, inert
                // in confirm/menu/nav contexts. Sync, no await:
                // it only mutates a buffer, so it stays out of the select!.
                dirty = true;
                handle_paste(&mut app, pasted);
            }
            Event::Tick => {
                // TTL expiry rides the tick, not the poll.
                // Before this, a status was cleared only in the success
                // arms of `poll_active_leaf`, so its lifetime was an
                // accident of which leaf happened to poll — 2s on
                // Dashboard, 30s on Lists, *never* on the six leaves
                // with no poll of their own. Outside the `paused` gate
                // on purpose: pausing suspends data polls, not the
                // clock, and a toast frozen on screen by `[p]` would be
                // the same defect wearing a different hat.
                //
                // Gated on the return value — this arm fires every
                // 33ms, and repainting unconditionally would pin the
                // render loop at ~30 FPS on a box also serving DNS.
                if app.expire_status() {
                    dirty = true;
                }
                // An explicit fetch request from a key
                // handler, honoured ahead of — and outside — the pause gate.
                // `[p]` suspends the *automatic* refresh; `PgDn` is the
                // operator asking for a specific page, and advancing
                // `page_index` without fetching would paint page N-1's rows
                // under the label "page N". Refusing instead would need a
                // second explanation surface for a state `p` already exits.
                if app.force_poll {
                    app.force_poll = false;
                    poll_active_leaf(&mut app, &poller).await;
                    last_poll = Instant::now();
                    dirty = true;
                }
                if !app.paused {
                    let now = Instant::now();

                    // Active-tab polling
                    let poll_interval = match app.active_leaf {
                        Leaf::Dashboard => POLL_DASHBOARD,
                        Leaf::QueryLog => POLL_QUERY_LOG,
                        Leaf::Devices => POLL_DEVICES,
                        // Lists polls every 30s as the fallback
                        // path when no `IpcNotification` subscriber pushes
                        // mid-cycle; 30s is the upper bound on stale data.
                        Leaf::Lists => POLL_LISTS,
                        // Records
                        // are still offline-config-driven, but the hits
                        // column needs a slow IPC tick to fetch the
                        // counter snapshot. Joining the offline cohort
                        // would freeze the column at boot-fresh `—`.
                        Leaf::LocalDns => POLL_LOCAL_DNS,
                        // `logs-tab`: the ring only changes when the
                        // daemon says something, and the operator is
                        // usually reading rather than watching a live
                        // tail. 5 s keeps a fresh error visible within one
                        // breath without re-serialising up to 500 rows
                        // every couple of seconds.
                        Leaf::Logs => POLL_LOGS,
                        // Subnets renders live per-subnet traffic — the
                        // 24h chart, block-rate gauge and stats all read
                        // `device_view` over IPC (same GetAllDevices call
                        // the Devices tab uses), so it joins the Devices
                        // poll cohort. `poll_active_leaf` only polls the
                        // focused leaf, so this adds no cost when Subnets
                        // is unfocused; a 1h interval would freeze the
                        // gauge/chart at heartbeat cadence.
                        Leaf::Subnets => POLL_DEVICES,
                        // Resolver/Settings read from the cached
                        // on-disk config, not IPC. An hour interval means
                        // the tick loop only wakes for heartbeat, not
                        // per-tab. Rules and Profiles are offline-config-
                        // driven too — both join the cohort.
                        Leaf::Rules
                        | Leaf::Settings
                        | Leaf::Profiles
                        | Leaf::File
                        | Leaf::Groups
                        | Leaf::Labels
                        | Leaf::CustomLists => Duration::from_secs(3600),
                        // The Cluster tab reads `app.cluster_status`,
                        // which the always-on heartbeat refreshes; no active-leaf
                        // poll of its own. Joins the offline 3600s cohort.
                        #[cfg(feature = "cluster")]
                        Leaf::Cluster => Duration::from_secs(3600),
                    };

                    if now.duration_since(last_poll) >= poll_interval {
                        poll_active_leaf(&mut app, &poller).await;
                        last_poll = now;
                        dirty = true;
                    }

                    // Background heartbeat (status only)
                    if now.duration_since(last_heartbeat) >= POLL_HEARTBEAT {
                        poll_heartbeat(&mut app, &poller).await;
                        last_heartbeat = now;
                        dirty = true;
                    }
                }
            }
            Event::Resize => {
                dirty = true;
            }
        }
    }

    Ok(())
}

/// Returns true if the app should quit.
async fn handle_key(app: &mut App, key: KeyEvent, poller: &IpcPoller, config_path: &Path) -> bool {
    // Welcome banner has the absolute highest priority.
    // Any keypress dismisses it AND records the version on disk so it
    // does NOT re-show on subsequent launches. The keystroke is
    // consumed by the banner — it does NOT fall through to tab
    // navigation, scope modal, etc. This matches the "any key to
    // dismiss" UX hint rendered in the overlay footer.
    if let Some(banner) = app.welcome_banner.take() {
        let _ = key; // consume the key

        // tui-11: `dismiss` is create_dir_all + metadata + set_permissions +
        // open + writeln. Microseconds on a local filesystem — but this is the
        // event-loop thread, and on a hung network `$HOME` those syscalls block
        // it for the full I/O timeout: no repaint, no key, no signal. Off to the
        // blocking pool. Fire-and-forget is enough: the banner has already done
        // its job the moment we `take()` it, and `dismiss` swallows its own
        // errors by design (a missed line just re-shows the banner next launch).
        spawn_fs_side_effect(move || banner.dismiss());
        return false;
    }

    // An `Error` toast is sticky — it has no TTL, because an
    // error the operator never read is a lost error. It is dismissed by
    // the next key that acts on the tab, which is any key at all once
    // the welcome banner (which consumes its own) is out of the way.
    //
    // This is a side effect, NOT a gate. The key is not consumed and
    // dispatch continues below, so the toast surface is structurally
    // incapable of swallowing a keystroke.
    app.dismiss_sticky_status();

    // Modal overlay on the Devices tab takes absolute priority — every
    // key while a form or confirmation dialog is open must reach the
    // modal handler, NOT fall through to tab navigation. Without this
    // gate, typing "1" inside the form's name field would jump to
    // Dashboard.
    if app.active_leaf == Leaf::Devices && app.devices.modal.is_some() {
        handle_modal_key(app, key, poller).await;
        return false;
    }

    // The edit modal absorbs every keystroke so
    // Tab/Shift-Tab cycle fields, ↑↓ cycle picker values, Ctrl+S saves,
    // and the Delete confirm screen does not leak digits to navigation.
    if app.active_leaf == Leaf::Lists && app.lists.edit_modal.is_some() {
        handle_lists_edit_modal_key(app, key, poller, config_path).await;
        return false;
    }
    // Same gate for the `K`-hotkey consent notice. It is a typed input,
    // so without this every character the operator types to accept would
    // also be a Lists-tab hotkey — `d` would open a delete, `a` an add.
    if app.active_leaf == Leaf::Lists && app.lists.kind_confirm.is_some() {
        handle_kind_confirm_key(app, key, poller, config_path).await;
        return false;
    }
    // Same gate for the catalog picker so ↑/↓ + Enter +
    // Esc all stay in the modal.
    if app.active_leaf == Leaf::Lists && app.lists.catalog_picker.is_some() {
        handle_lists_catalog_picker_key(app, key, poller, config_path).await;
        return false;
    }
    // Gate the Rules-tab edit modal — same priority pattern.
    // While the modal is open every keystroke routes through the
    // dedicated handler so digit jumps / tab cycling don't leak past.
    if app.active_leaf == Leaf::Rules && app.rules.edit_modal.is_some() {
        handle_rules_edit_modal_key(app, key, poller, config_path).await;
        return false;
    }
    // Same gate pattern as the edit_modal gate just
    // above — the add-rule modal (opened with `[a]` in `handle_rules_key`)
    // captures a typed domain, so every keystroke must route here while
    // it's open rather than falling into the global keybindings below
    // (`q`, `1`-`5`, `Tab`, …). Key handling itself lives in
    // `rule_add_modal::handle_key`, not in this function.
    if app.active_leaf == Leaf::Rules && app.rules.add_modal.is_some() {
        rule_add_modal::handle_key(app, key, poller, config_path).await;
        return false;
    }
    // Query Log rule picker opened from the Query
    // Log tab via `Enter`. Same priority pattern — every keystroke
    // goes through the modal handler, not the navigation dispatcher.
    if app.query_log_rule_modal.is_some() {
        handle_query_log_rule_modal_key(app, key, poller, config_path).await;
        return false;
    }

    // Local DNS modal (Add / Remove / Edit) opened
    // from Leaf::LocalDns via `a` / `d`|`Delete` / `e`. Same gate pattern
    // as the Devices / Lists / rule-picker modals — once open, the modal
    // owns every keystroke until submit lands or Esc closes.
    if app.active_leaf == Leaf::LocalDns && app.local_dns.modal.is_some() {
        handle_local_dns_modal_key(app, key, poller, config_path).await;
        return false;
    }

    // Settings restore picker modal (opened from Leaf::Settings via `R`).
    // Same gate pattern — once open, the modal owns every keystroke until
    // the restore lands, the operator cancels, or the outcome is dismissed.
    if app.active_leaf == Leaf::Settings && app.settings.restore_modal.is_some() {
        handle_restore_modal_key(app, key, poller, config_path).await;
        return false;
    }

    // Settings backup confirm modal (opened from Leaf::Settings via `b`).
    // Parallel gate to the restore picker — the two modals are mutually
    // exclusive in practice because only one field is `Some` at a time.
    if app.active_leaf == Leaf::Settings && app.settings.backup_modal.is_some() {
        handle_backup_modal_key(app, key, config_path).await;
        return false;
    }

    // The Tracking form is modal in
    // behaviour — it binds digits (retention), `s` (submit) and Tab
    // (field cycle), every one of which the global match below would
    // otherwise consume first (digit → section nav, `s` → resolver
    // modal, Tab → next leaf), leaving the only TUI path that mutates
    // tracking config unreachable. Hoist the gate here, beside the
    // backup/restore modals, so the form owns every keystroke. The
    // inner gate in `handle_settings_key` is kept as defence-in-depth
    // for direct-handler callers (unit tests).
    if app.active_leaf == Leaf::Settings && app.settings.tracking_panel.is_some() {
        handle_tracking_panel_key(app, key, poller).await;
        return false;
    }

    // Subnets modal (Add / Edit / Delete) opened from
    // Leaf::Subnets via `a` / `e` / `d`. Same gate pattern as the
    // Local DNS modal.
    if app.active_leaf == Leaf::Subnets && app.subnets.modal.is_some() {
        handle_subnet_modal_key(app, key, poller, config_path).await;
        return false;
    }

    // Groups modal (Add / Edit / Delete) opened from
    // Leaf::Groups via `a` / `e` / `d`. Same gate pattern as Subnets.
    if app.active_leaf == Leaf::Groups && app.groups.modal.is_some() {
        handle_group_modal_key(app, key, poller, config_path).await;
        return false;
    }

    // Labels modal (Add / Edit / Delete) opened from
    // Leaf::Labels via `a` / `e` / `d`. Same gate pattern as Groups.
    if app.active_leaf == Leaf::Labels && app.labels.modal.is_some() {
        handle_label_modal_key(app, key, poller, config_path).await;
        return false;
    }

    // Custom Lists Add / Edit / Remove modal opened via `a` / `e` / `d`.
    if app.active_leaf == Leaf::CustomLists && app.custom_lists.modal.is_some() {
        handle_custom_list_modal_key(app, key, poller, config_path).await;
        return false;
    }

    // Custom Lists mount picker opened from Leaf::CustomLists via `m`.
    // Same gate pattern: while it is open it owns every keystroke, so
    // Space and the arrows reach the picker instead of the global cluster.
    if app.active_leaf == Leaf::CustomLists && app.custom_lists.mount_picker.is_some() {
        handle_custom_list_mount_key(app, key, poller, config_path).await;
        return false;
    }

    // Profiles modal (Add / Edit / Delete) opened from
    // Leaf::Profiles via `a` / `e` / `d`. Same gate pattern as the
    // Subnets modal — once open, the modal owns every keystroke until
    // submit lands or Esc closes.
    if app.active_leaf == Leaf::Profiles && app.profiles.modal.is_some() {
        handle_profile_modal_key(app, key, poller, config_path).await;
        return false;
    }

    // The Query Log advanced-search form owns every keystroke while open,
    // for the same reason the resolver modal below does: `b`, `t`, `c` and
    // `R` are Query Log verbs, and a form with three text fields must be
    // able to type all four letters.
    if app.query_log.advanced_modal.is_some() {
        handle_query_log_filter_modal_key(app, key);
        return false;
    }

    // Source-IP resolver modal opened from any leaf via the
    // global hotkey `s`. The gate is global (not leaf-scoped) because
    // the modal is reachable from anywhere; once open the modal owns
    // every keystroke — digits flow into the input buffer instead of
    // triggering the section hotkeys.
    if app.resolver_modal.is_some() {
        handle_resolver_modal_key(app, key);
        return false;
    }

    // Text input mode takes priority. Both filter prompts share the
    // same edit contract — `drive_text_input` routes the keystroke and
    // returns where the buffer ended up so each caller decides which
    // `app.query_log` slot the committed string lands in.
    match &mut app.input_mode {
        InputMode::FilterDomain(buf) => {
            match drive_text_input(buf, key) {
                TextInputOutcome::Submit(val) => {
                    app.query_log.filter_domain = if val.is_empty() { None } else { Some(val) };
                    app.input_mode = InputMode::Normal;
                    // Filters run DURING the walk, so a cursor minted
                    // under the previous predicate set names a boundary
                    // that no longer exists. `reset_paging` on every
                    // commit, not just on `R`.
                    app.query_log.reset_paging();
                }
                TextInputOutcome::Cancel => {
                    app.input_mode = InputMode::Normal;
                }
                TextInputOutcome::Continue => {}
            }
            return false;
        }
        InputMode::FilterClient(buf) => {
            match drive_text_input(buf, key) {
                TextInputOutcome::Submit(val) => {
                    app.query_log.filter_client = if val.is_empty() { None } else { Some(val) };
                    app.input_mode = InputMode::Normal;
                    app.query_log.reset_paging();
                }
                TextInputOutcome::Cancel => {
                    app.input_mode = InputMode::Normal;
                }
                TextInputOutcome::Continue => {}
            }
            return false;
        }
        InputMode::FilterLists(buf) => {
            match drive_text_input(buf, key) {
                TextInputOutcome::Submit(val) => {
                    app.lists.filter_text = if val.is_empty() { None } else { Some(val) };
                    app.input_mode = InputMode::Normal;
                    reconcile_lists_selection(app);
                }
                TextInputOutcome::Cancel => {
                    app.input_mode = InputMode::Normal;
                }
                TextInputOutcome::Continue => {}
            }
            return false;
        }
        InputMode::FilterLogs(buf) => {
            match drive_text_input(buf, key) {
                TextInputOutcome::Submit(val) => {
                    app.logs.filter_text = if val.is_empty() { None } else { Some(val) };
                    app.input_mode = InputMode::Normal;
                    // The daemon applies this during its walk, so the page
                    // that comes back is a different set of rows — an old
                    // offset would point into a page that no longer exists.
                    app.logs.scroll_offset = 0;
                }
                TextInputOutcome::Cancel => {
                    app.input_mode = InputMode::Normal;
                }
                TextInputOutcome::Continue => {}
            }
            return false;
        }
        InputMode::FilterDevicesSubnet(buf) => {
            match drive_text_input(buf, key) {
                TextInputOutcome::Submit(val) => {
                    app.devices.filter_subnet = if val.is_empty() { None } else { Some(val) };
                    app.input_mode = InputMode::Normal;
                }
                TextInputOutcome::Cancel => {
                    app.input_mode = InputMode::Normal;
                }
                TextInputOutcome::Continue => {}
            }
            return false;
        }
        InputMode::FilterRules(buf) => {
            match drive_text_input(buf, key) {
                TextInputOutcome::Submit(val) => {
                    app.rules.filter_text = if val.is_empty() { None } else { Some(val) };
                    app.input_mode = InputMode::Normal;
                    reconcile_rules_selection(app);
                }
                TextInputOutcome::Cancel => {
                    app.input_mode = InputMode::Normal;
                }
                TextInputOutcome::Continue => {}
            }
            return false;
        }
        InputMode::Normal => {}
    }

    // ── `?` is a menu you can press ───────────────────────────────────────
    //
    // The overlay used to swallow every key but `?` / `Esc` / `q` / Ctrl+C.
    // It now dispatches: a key that is bound in Normal mode on this leaf
    // runs its action and the overlay closes behind it, as if help had
    // never been open.
    //
    // The mechanism is minimal by design — clear
    // `show_help` and **fall through** into the same global match and
    // `handle_tab_key` a Normal-mode keystroke walks. There is deliberately
    // NO second dispatch table: the live match arms stay the only place a
    // binding is written down. A parallel table is how `?` once advertised a
    // dead Tags verb for a long stretch.
    //
    // What falling through cannot answer on its own is whether the key
    // meant anything, and an unbound key must leave the overlay
    // OPEN so a typo does not silently mutate the tab underneath. The leaf
    // handlers' `_` arms report that via `App::leaf_key_unhandled` (see its
    // doc for why a boundness predicate would be the forbidden second
    // table); if the dispatch came back untouched, the overlay is restored.
    //
    // Falling through rather than re-entering `handle_key` also keeps the
    // `prev_leaf` poll-on-change below working: `2` from help lands on
    // Query Log AND triggers its first poll, which a recursive call would
    // have done against a leaf that had already changed.
    //
    // A modal open underneath cannot reach here at all — every modal gate
    // above returns first — so "do not execute keys while a modal is
    // open" holds structurally, not by a check that could rot.
    let dispatched_from_help = if app.show_help {
        match key.code {
            // Close, and do nothing else. `?` is special-cased so the
            // fall-through below cannot toggle it straight back on, and `q`
            // closes help rather than quitting.
            KeyCode::Char('?') | KeyCode::Esc | KeyCode::Char('q') => {
                app.show_help = false;
                return false;
            }
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
            _ => {
                app.show_help = false;
                true
            }
        }
    } else {
        false
    };

    // Global keybindings
    let prev_leaf = app.active_leaf;
    // Reset before dispatch: the flag describes THIS keystroke only.
    app.leaf_key_unhandled = false;

    // `g <letter>` one-shot mnemonic dispatch. The flag
    // was set by the previous keystroke; the current event is the
    // second half of the chord. On a known mnemonic we jump to the
    // matching leaf and skip the normal match (the second key has been
    // consumed). On an unknown letter we fall through silently — the
    // flag is already cleared, so the second key still gets a chance
    // to fire its tab-local binding (e.g. `g j` scrolls down on the
    // Query Log tab). Snapshot of `prev_leaf` is taken above so the
    // post-match poll-on-change check fires for the mnemonic path too.
    let mnemonic_dispatched = if app.pending_goto {
        app.pending_goto = false;
        match key.code {
            KeyCode::Char(ch) => match Leaf::from_mnemonic(ch) {
                // Ignore a mnemonic targeting a runtime-hidden leaf
                // (`g c` when clustering is off); the jump no-ops and the key
                // falls through.
                Some(leaf) if leaf_visible(leaf, app) => {
                    app.active_leaf = leaf;
                    true
                }
                _ => false,
            },
            _ => false,
        }
    } else {
        false
    };

    if !mnemonic_dispatched {
        match key.code {
            KeyCode::Char('q') => return true,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
            // Numeric 1-5 jumps to the
            // section's default leaf. 6-9 are dropped (no handler).
            // Dashboard and Query Log are their own
            // top-level sections (1 and 2); Network/Filters/Configuration
            // follow. 4 and 5 are Filters /
            // Configuration; both LAND on the same leaf as before
            // (Profiles / Settings) so no muscle memory moves. The
            // `g <letter>` mnemonic above is the escape hatch for direct
            // leaf-level jumps.
            KeyCode::Char('1') => app.active_leaf = Section::Dashboard.default_leaf(),
            KeyCode::Char('2') => app.active_leaf = Section::QueryLog.default_leaf(),
            KeyCode::Char('3') => app.active_leaf = Section::Network.default_leaf(),
            KeyCode::Char('4') => app.active_leaf = Section::Filters.default_leaf(),
            KeyCode::Char('5') => app.active_leaf = Section::Configuration.default_leaf(),
            // `6` jumps to the Cluster section, but only when it is
            // visible (built with `cluster` + `[cluster].enabled`). Otherwise
            // it falls through as an unbound key, matching the 7-9 drop.
            #[cfg(feature = "cluster")]
            KeyCode::Char('6') if app.cluster_visible() => {
                app.active_leaf = Section::Cluster.default_leaf()
            }
            // `[` / `]` cycle the leaves of the active
            // section (wraps within the section). `Tab` / `Shift-Tab`
            // keep cycling ALL leaves linearly so the existing operator
            // muscle memory of "press Tab to walk through everything"
            // survives the grouped chrome. The linear cycle skips
            // a runtime-hidden cluster leaf via `next_visible`/`prev_visible`.
            KeyCode::Char('[') => app.active_leaf = app.active_leaf.prev_in_section(),
            KeyCode::Char(']') => app.active_leaf = app.active_leaf.next_in_section(),
            // `Tab` was once asked to switch the Labels leaf's two
            // panes, and it was built that way and then **reverted**.
            // Kept as a comment because it is the decision a future
            // session would otherwise re-take from scratch:
            //
            // The complaint that opened that batch was "Labels does not
            // behave like the other tabs". Making Labels the one leaf
            // where `Tab` means something else recreates that defect in
            // a new place. Local DNS already faced the identical choice
            // and went the other way — it picked `o` and pinned the
            // decision with `ldns_04_tab_still_cycles_leaf`.
            //
            // "Which key switches pane in a two-card layout" is a
            // TUI-wide question, to be answered once for every leaf
            // rather than per leaf. `←`/`→` already carry the whole
            // focus model, so Labels degrades rather than breaks.
            // `ux8_tab_still_cycles_leaves_on_labels` pins it. (This
            // line read "`←`/`→` (and `h`/`l`)" until the `h`/`l` aliases
            // were deleted; the arrows were always the real
            // binding, so the argument is unchanged.)
            KeyCode::Tab => app.active_leaf = next_visible_leaf(app),
            KeyCode::BackTab => app.active_leaf = prev_visible_leaf(app),
            // `g` arms the mnemonic prefix. The next
            // event reads the table; `g g` re-arms (second `g` is an
            // unknown second-key, falls through here, re-sets the flag).
            KeyCode::Char('g') => app.pending_goto = true,
            KeyCode::Char('?') => {
                app.show_help = !app.show_help;
            }
            KeyCode::Char('r') => {
                // Global refresh re-reads the on-disk config so the
                // Subnets / Resolver / Devices-annotation tabs pick up
                // operator edits without a full TUI restart.
                app.loaded_config = load_v1_config(config_path);
                refresh_auto_backup_view(app, config_path);
                poll_active_leaf(app, poller).await;
                poll_heartbeat(app, poller).await;
                // Also tell the daemon to reload. Without this, the TUI
                // would show the new on-disk config while the daemon kept
                // serving DNS with the old in-memory one — a misleading
                // split that surprised operators who expected `r` to mean
                // "apply my edits". Outcome goes to the footer status line.
                match poller.send_reload().await {
                    Ok(msg) => app.status_ok(format!("reload: {msg}")),
                    Err(e) => app.status_err(format!("reload failed: {e}")),
                }
            }
            KeyCode::Char('p') => {
                app.paused = !app.paused;
            }
            // Open the global resolver modal. Pre-fills the
            // input from QueryLog/Devices when the active leaf has a
            // focused row (`prefill_from_active_leaf`); otherwise opens
            // blank. Distinct from the two-key `g s` (Subnets) — the
            // mnemonic prefix is consumed before this match runs.
            KeyCode::Char('s') => {
                let modal = match resolver_modal::prefill_from_active_leaf(app) {
                    Some((ip, source)) => resolver_modal::ResolverModal::open_with(ip, source),
                    None => resolver_modal::ResolverModal::open_blank(),
                };
                app.resolver_modal = Some(modal);
            }
            _ => {
                // Tab-specific keybindings
                handle_tab_key(app, key, poller, config_path).await;
            }
        }
    }

    // The key turned out to mean nothing on this leaf. Nothing ran,
    // so put the overlay back: the operator mistyped while reading it, and
    // losing their place is the cost the swallow was always paying for.
    if dispatched_from_help && app.leaf_key_unhandled {
        app.show_help = true;
    }

    // On tab change, trigger an immediate poll so the freshly-visible
    // tab shows current data instead of whatever was last loaded. This
    // is especially important for Dashboard and Clients which both
    // consume `app.device_view` — without this, the operator flipping
    // from QueryLog to Dashboard sees counts that might be minutes old.
    if app.active_leaf != prev_leaf {
        poll_active_leaf(app, poller).await;
        // Entering Settings re-reads the auto-backup snapshot
        // (mirrors the Tags/Dashboard on-tab-entry refresh idiom) so the
        // status line / banner reflect on-disk `.auto_state` + archives.
        if app.active_leaf == Leaf::Settings {
            refresh_auto_backup_view(app, config_path);
        }
    }

    false
}

/// Dispatch a non-global keystroke to the per-tab handler. Each tab
/// owns its own key contract; this match is intentionally a 9-line
/// router so adding a new tab requires touching one place, not
/// chasing through a 400-line dispatcher.
/// A leaf is nav-visible iff its owning section is shown. The only
/// hideable section is `Section::Cluster` (hidden unless `cluster_visible()`);
/// every other leaf is always visible. On a default build there is no cluster
/// leaf, so this is unconditionally `true`.
fn leaf_visible(leaf: Leaf, app: &App) -> bool {
    #[cfg(feature = "cluster")]
    if matches!(leaf, Leaf::Cluster) {
        return app.cluster_visible();
    }
    #[cfg(not(feature = "cluster"))]
    let _ = (leaf, app);
    true
}

/// `Tab` cycle that skips any runtime-hidden leaf. On a default build no leaf
/// is hidden, so the first hop returns `active_leaf.next()` — identical to the
/// behaviour before section visibility existed. Bounded by `Leaf::ALL.len()` so an all-hidden set
/// (impossible today) can't spin.
fn next_visible_leaf(app: &App) -> Leaf {
    let mut leaf = app.active_leaf.next();
    for _ in 0..Leaf::ALL.len() {
        if leaf_visible(leaf, app) {
            return leaf;
        }
        leaf = leaf.next();
    }
    app.active_leaf
}

/// `Shift+Tab` mirror of [`next_visible_leaf`].
fn prev_visible_leaf(app: &App) -> Leaf {
    let mut leaf = app.active_leaf.prev();
    for _ in 0..Leaf::ALL.len() {
        if leaf_visible(leaf, app) {
            return leaf;
        }
        leaf = leaf.prev();
    }
    app.active_leaf
}

async fn handle_tab_key(app: &mut App, key: KeyEvent, poller: &IpcPoller, config_path: &Path) {
    match app.active_leaf {
        Leaf::Subnets => handle_subnets_key(app, key),
        Leaf::LocalDns => handle_local_dns_key(app, key),
        Leaf::Profiles => handle_profiles_key(app, key),
        Leaf::Dashboard => handle_dashboard_key(app, key),
        Leaf::QueryLog => handle_query_log_key(app, key),
        Leaf::Devices => handle_devices_key(app, key),
        Leaf::Lists => handle_lists_key(app, key, poller, config_path).await,
        Leaf::Rules => handle_rules_key(app, key),
        Leaf::Settings => handle_settings_key(app, key, poller, config_path).await,
        Leaf::File => handle_file_key(app, key, poller, config_path).await,
        // Takes no `IpcPoller`: the leaf's keys only move the cursor and
        // set filters; the fetch happens on the poll tick.
        Leaf::Logs => handle_logs_key(app, key),
        Leaf::Groups => handle_groups_key(app, key),
        Leaf::Labels => handle_labels_key(app, key),
        Leaf::CustomLists => handle_custom_lists_key(app, key),
        #[cfg(feature = "cluster")]
        Leaf::Cluster => handle_cluster_key(app, key),
    }
}

/// Cluster tab key handling: `↑`/`↓` move the roster cursor
/// (primary only; the secondary view is a single non-navigable card). The
/// cursor is `selected_name` — resolve it to the current row index, step, and
/// write the new node's name back, so the selection survives a roster reorder.
#[cfg(feature = "cluster")]
fn handle_cluster_key(app: &mut App, key: KeyEvent) {
    let Some(status) = app.cluster_status.as_ref() else {
        app.leaf_key_unhandled = true;
        return;
    };
    let roster = &status.roster;
    if roster.is_empty() {
        // Secondary / no nodes yet — nothing to move, so nothing this
        // key could have meant.
        app.leaf_key_unhandled = true;
        return;
    }
    // Current index from the stable name key; default to the top row.
    let cur = app
        .cluster
        .selected_name
        .as_ref()
        .and_then(|name| roster.iter().position(|r| &r.name == name))
        .unwrap_or(0);
    let last = roster.len() - 1;
    let next = match key.code {
        KeyCode::Down => (cur + 1).min(last),
        KeyCode::Up => cur.saturating_sub(1),
        // Jump / page. Already clamped above; these just travel further.
        KeyCode::Home => 0,
        KeyCode::End => last,
        KeyCode::PageDown => (cur + NAV_PAGE).min(last),
        KeyCode::PageUp => cur.saturating_sub(NAV_PAGE),
        _ => {
            app.leaf_key_unhandled = true;
            return;
        }
    };
    app.cluster.selected_name = Some(roster[next].name.clone());
}

// Subnets is master/detail with modal-driven CRUD. ↑/↓
// scrolls the master list (configured subnets + auto-discovered
// candidate buckets); `a` opens an Add modal; `e` opens an Edit modal
// pre-filled from the focused row; `d` opens a Delete confirm; Enter
// on a discovered candidate opens the Add modal pre-filled with the
// candidate's CIDR + a synthesised display name (promote-from-
// suggestion). `selected_id` is updated alongside the cursor so the
// right card re-renders the just-selected subnet on the next frame.
fn handle_subnets_key(app: &mut App, key: KeyEvent) {
    // Seed the selection on first keystroke. The renderer auto-places
    // the visual cursor on row 0 when `selected_id` is None, but the
    // modal openers (`e`/`d`/`Enter`) consult `selected_id` directly.
    // Without this seed the first `e`/`d` press after opening the tab
    // would silently no-op because the cursor and the selection key
    // are out of sync. Fixes review subnets-01.
    ensure_subnet_selection_seeded(app);
    match key.code {
        KeyCode::Down => {
            let len = subnets_master_len(app);
            scroll_table_down(&mut app.subnets.table_state, len);
            sync_subnet_selection(app);
        }
        KeyCode::Up => {
            scroll_table_up(&mut app.subnets.table_state);
            sync_subnet_selection(app);
        }
        // Jump / page.
        KeyCode::Home => {
            let len = subnets_master_len(app);
            jump_table_home(&mut app.subnets.table_state, len);
            sync_subnet_selection(app);
        }
        KeyCode::End => {
            let len = subnets_master_len(app);
            jump_table_end(&mut app.subnets.table_state, len);
            sync_subnet_selection(app);
        }
        KeyCode::PageDown => {
            let len = subnets_master_len(app);
            page_table_down(&mut app.subnets.table_state, len);
            sync_subnet_selection(app);
        }
        KeyCode::PageUp => {
            page_table_up(&mut app.subnets.table_state);
            sync_subnet_selection(app);
        }
        KeyCode::Char('a') => {
            app.subnets.modal = Some(build_subnet_add_modal(app));
        }
        KeyCode::Char('e') => {
            if let Some(modal) = build_subnet_edit_modal(app) {
                app.subnets.modal = Some(modal);
            }
        }
        KeyCode::Char('d') | KeyCode::Delete => {
            if let Some(modal) = build_subnet_remove_modal(app) {
                app.subnets.modal = Some(modal);
            }
        }
        KeyCode::Enter => {
            // Promote-from-suggestion: open Add pre-filled with the
            // candidate's CIDR. Only fires when the focused row is a
            // discovered candidate (configured subnets handle Edit
            // via `e` instead — Enter on a configured row is a no-op
            // for now; per-subnet rule shortcuts are parked future work).
            if let Some(cidr) = focused_candidate_cidr(app) {
                app.subnets.modal = Some(build_subnet_promote_modal(app, &cidr));
            }
        }
        _ => app.leaf_key_unhandled = true,
    }
}

/// Seed `app.subnets.selected_id` to the first master-row's stable
/// key when it's still `None`. Called on every keystroke so the tab
/// is operable from the very first interaction (the operator
/// shouldn't have to press ↑/↓ once just to "wake up" the cursor).
///
/// Configured subnets take priority over candidates (so `e`/`d` land
/// on a real entity if one exists), and the cursor anchors at row 0
/// to match the renderer's auto-placement.
/// The Subnets master row set, computed once: configured subnet ids
/// first, then auto-discovered candidate CIDRs — the renderer's own row
/// order. `ensure_subnet_selection_seeded`, `subnets_master_len` and
/// `sync_subnet_selection` each recomputed `discover_candidates` and
/// cloned its inputs to get this; one `↓` on the Subnets leaf ran it
/// three times (a fourth in `reconcile_active_leaf_selection` before the
/// frame), cloning the full `unmapped` device list — unbounded by
/// config — every time. Borrows rather than clones: the
/// clones the three call sites carried existed only to satisfy the
/// borrow checker against `&mut App`, and disappear once the read
/// happens here, against `&App`.
fn subnet_master_keys(app: &App) -> (usize, Vec<String>) {
    let configured = app
        .loaded_config
        .as_ref()
        .map(|l| l.config.subnets.as_slice())
        .unwrap_or(&[]);
    let unmapped = app
        .device_view
        .as_ref()
        .map(|dv| dv.unmapped.as_slice())
        .unwrap_or(&[]);
    let candidates = crate::tui::tabs::subnets::discover_candidates(unmapped, configured);
    let mut keys: Vec<String> = configured
        .iter()
        .map(|s| s.id.as_str().to_string())
        .collect();
    keys.extend(candidates.into_iter().map(|c| c.cidr));
    (configured.len(), keys)
}

fn ensure_subnet_selection_seeded(app: &mut App) {
    let (_, keys) = subnet_master_keys(app);

    // Repair a *dangling* id, not just an unset one —
    // see `ensure_profile_selection_seeded` for the master/detail desync
    // this closes. The key is either a configured subnet id or a candidate
    // CIDR, since `keys` is configured rows first, then candidates.
    if let Some(key) = app.subnets.selected_id.as_deref() {
        if keys.iter().any(|k| k == key) {
            return;
        }
    }

    // Row 0 — the row the renderer falls back to.
    match keys.first().cloned() {
        Some(id) => {
            app.subnets.selected_id = Some(id);
            app.subnets.table_state.select(Some(0));
        }
        None => {
            app.subnets.selected_id = None;
            app.subnets.table_state.select(None);
        }
    }
}

/// Combined length of the master row list: configured subnets first,
/// then auto-discovered candidates. Both counts are derived from
/// `app.loaded_config` + `app.device_view`, so the math here mirrors
/// what `tabs::subnets::render` actually paints.
fn subnets_master_len(app: &App) -> usize {
    subnet_master_keys(app).1.len()
}

/// Recompute `selected_id` from the cursor position so the right
/// detail card stays in sync with ↑/↓ scrolling.
fn sync_subnet_selection(app: &mut App) {
    let (_, keys) = subnet_master_keys(app);
    let Some(idx) = app.subnets.table_state.selected() else {
        app.subnets.selected_id = None;
        return;
    };
    app.subnets.selected_id = keys.get(idx).cloned();
}

// ── Subnet modal openers + key handler + submit ──────────────────────

/// The currently-focused configured subnet, if any. Returns `None`
/// when the cursor is on a discovered candidate row, on the empty
/// state, or out of range.
fn focused_configured_subnet(app: &App) -> Option<crate::config::schema::Subnet> {
    let configured = app.loaded_config.as_ref().map(|l| &l.config.subnets)?;
    let key = app.subnets.selected_id.as_deref()?;
    configured.iter().find(|s| s.id.as_str() == key).cloned()
}

/// The currently-focused candidate CIDR string, if the cursor is on
/// a discovered candidate row. Returns `None` for configured rows.
fn focused_candidate_cidr(app: &App) -> Option<String> {
    let key = app.subnets.selected_id.as_deref()?;
    let configured = app
        .loaded_config
        .as_ref()
        .map(|l| l.config.subnets.as_slice())
        .unwrap_or(&[]);
    if configured.iter().any(|s| s.id.as_str() == key) {
        return None;
    }
    let unmapped = app
        .device_view
        .as_ref()
        .map(|dv| dv.unmapped.as_slice())
        .unwrap_or(&[]);
    let candidates = crate::tui::tabs::subnets::discover_candidates(unmapped, configured);
    candidates
        .iter()
        .find(|c| c.cidr == key)
        .map(|c| c.cidr.clone())
}

/// Snapshot the configured profile ids at modal-open time. Reuses
/// the same shape as Local DNS — the dropdown reads from the snapshot,
/// not from the live `loaded_config`, so a refresh during the form's
/// lifetime cannot surprise the operator with a profile that
/// disappeared mid-edit.
fn snapshot_subnet_profile_ids(app: &App) -> Vec<String> {
    app.loaded_config
        .as_ref()
        .map(|loaded| {
            loaded
                .config
                .profiles
                .keys()
                .map(|id| id.as_str().to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn build_subnet_add_modal(app: &App) -> subnet_modal::SubnetModal {
    let profiles = snapshot_subnet_profile_ids(app);
    subnet_modal::SubnetModal::open_add(profiles, 0)
}

fn build_subnet_promote_modal(app: &App, cidr: &str) -> subnet_modal::SubnetModal {
    let profiles = snapshot_subnet_profile_ids(app);
    subnet_modal::SubnetModal::open_promote(cidr, profiles, 0)
}

fn build_subnet_edit_modal(app: &App) -> Option<subnet_modal::SubnetModal> {
    let s = focused_configured_subnet(app)?;
    let profiles = snapshot_subnet_profile_ids(app);
    Some(subnet_modal::SubnetModal::open_edit(&s, profiles))
}

fn build_subnet_remove_modal(app: &App) -> Option<subnet_modal::SubnetModal> {
    let s = focused_configured_subnet(app)?;
    Some(subnet_modal::SubnetModal::open_remove(&s))
}

/// Drive the Subnets modal's state machine on each keypress. On
/// submit fires the single-seat helpers — `add_inner` for Add,
/// `set_inner` (per changed field) for Edit, `remove_inner` for
/// Remove — then triggers `attempt_reload`. Mirrors
/// `handle_local_dns_modal_key`.
async fn handle_subnet_modal_key(
    app: &mut App,
    key: KeyEvent,
    poller: &IpcPoller,
    config_path: &Path,
) {
    let Some(mut modal) = app.subnets.modal.take() else {
        return;
    };

    use subnet_modal::{FormField, Stage};

    if modal.is_submitted() {
        // Any keypress in the submitted stage closes the modal.
        return;
    }

    // `Ctrl+s` saves from anywhere on an Archetype-F form.
    //
    // Checked BEFORE the field dispatch, not as a guarded `Char('s')` arm:
    // the `KeyCode::Char(c)` catch-all at the bottom of the form match is
    // what used to append a literal `s` to the focused buffer, so an arm
    // placed after it would be dead. "From anywhere" means ahead of the
    // field dispatch entirely. Mirrors the check in
    // `handle_edit_mode_key`, including the `S` spelling some terminals
    // send.
    //
    // Confirm stages are Archetype C and keep `[y]` / `[n]` — the chord
    // must not reach them, hence the stage guard.
    if matches!(key.code, KeyCode::Char('s') | KeyCode::Char('S'))
        && key.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(modal.stage, Stage::EditingForm(_))
    {
        submit_subnet_modal(app, modal, poller, config_path).await;
        return;
    }

    match &mut modal.stage {
        Stage::EditingForm(form) => {
            match key.code {
                KeyCode::Esc => {
                    // Drop the modal — handler returned without re-stashing
                    // closes it.
                    return;
                }
                KeyCode::Tab | KeyCode::Down => {
                    form.focused = next_editable_field(form.focused, form.mode);
                    form.error_message = None;
                }
                KeyCode::BackTab | KeyCode::Up => {
                    form.focused = prev_editable_field(form.focused, form.mode);
                    form.error_message = None;
                }
                KeyCode::Enter => {
                    if form.focused == FormField::Cancel {
                        // Discard button → close without saving (same as Esc).
                        return;
                    } else {
                        // Otherwise Enter submits from any field. A
                        // pre-flight or apply error keeps the form open
                        // with an inline message (see
                        // `submit_subnet_modal`) instead of dropping the
                        // operator's input, so a stray Enter is
                        // recoverable.
                        submit_subnet_modal(app, modal, poller, config_path).await;
                        return;
                    }
                }
                // These were `if Profile {...} else if Tags {...}`.
                // With the Tags branch gone the lone `if` trips
                // `collapsible_if` under `-D warnings`, so the condition
                // moves onto the arm. Behaviour is unchanged: a Left/Right
                // on any other field fell through the empty `if` before and
                // falls through to the `_ => {}` arm now — both no-ops.
                KeyCode::Right
                    if form.focused == FormField::Profile && !form.profiles_snapshot.is_empty() =>
                {
                    let n = form.profiles_snapshot.len();
                    form.profile_idx = (form.profile_idx + 1) % n;
                }
                KeyCode::Left
                    if form.focused == FormField::Profile && !form.profiles_snapshot.is_empty() =>
                {
                    let n = form.profiles_snapshot.len();
                    form.profile_idx = (form.profile_idx + n - 1) % n;
                }
                KeyCode::Char(' ') => match form.focused {
                    // Profile is the only selector — Space cycles it forward.
                    FormField::Profile => {
                        if !form.profiles_snapshot.is_empty() {
                            let n = form.profiles_snapshot.len();
                            form.profile_idx = (form.profile_idx + 1) % n;
                        }
                    }
                    FormField::Submit => {
                        submit_subnet_modal(app, modal, poller, config_path).await;
                        return;
                    }
                    FormField::Cancel => {
                        // Discard button → close without saving.
                        return;
                    }
                    // For text fields, treat space as a literal char.
                    _ => {
                        if let Some(buf) = subnet_text_field_buf(form) {
                            buf.push(' ');
                            form.error_message = None;
                        }
                    }
                },
                KeyCode::Backspace => {
                    if let Some(buf) = subnet_text_field_buf(form) {
                        buf.pop();
                        form.error_message = None;
                    }
                }
                KeyCode::Char(c) => {
                    if let Some(buf) = subnet_text_field_buf(form) {
                        buf.push(c);
                        form.error_message = None;
                    }
                }
                _ => {}
            }
            app.subnets.modal = Some(modal);
        }
        Stage::ConfirmingRemove(_) => match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                submit_subnet_modal(app, modal, poller, config_path).await;
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                // Drop the modal — handler returned without re-stashing.
            }
            _ => {
                app.subnets.modal = Some(modal);
            }
        },
        Stage::Submitted(_) => {
            // Already handled above.
        }
    }
}

/// Skip the Id field on Edit — id is read-only after creation, so focus
/// must not land on a field the operator cannot change.
///
/// The second skip is gone: `FormField::Tags` was Edit-only and
/// was stepped over in Add mode; with the picker gone there is no
/// mode-dependent row left, and both modes walk the same ring bar `Id`.
fn next_editable_field(
    f: subnet_modal::FormField,
    mode: subnet_modal::FormMode,
) -> subnet_modal::FormField {
    let mut next = f.next();
    if mode == subnet_modal::FormMode::Edit && next == subnet_modal::FormField::Id {
        next = next.next();
    }
    next
}

fn prev_editable_field(
    f: subnet_modal::FormField,
    mode: subnet_modal::FormMode,
) -> subnet_modal::FormField {
    let mut prev = f.prev();
    if mode == subnet_modal::FormMode::Edit && prev == subnet_modal::FormField::Id {
        prev = prev.prev();
    }
    prev
}

/// Mutable reference to the buffer behind the focused text-input
/// field. `None` for non-text fields (Profile dropdown, Submit/Cancel).
fn subnet_text_field_buf(form: &mut subnet_modal::AddForm) -> Option<&mut String> {
    use subnet_modal::{FormField, FormMode};
    match form.focused {
        FormField::Id if form.mode == FormMode::Add => Some(&mut form.id),
        FormField::Id => None, // read-only on Edit
        FormField::DisplayName => Some(&mut form.display_name),
        FormField::Cidrs => Some(&mut form.cidrs),
        FormField::Priority => Some(&mut form.priority_input),
        FormField::Profile | FormField::Submit | FormField::Cancel => None,
    }
}

/// Submit path for all three Subnet modals. Branches on the stage:
///
/// - Add → `add_inner` once.
/// - Edit → walk every field that diverges from the original
///   snapshot and call `set_inner` per change. Non-atomic; the
///   modal reports the first failure and stops.
/// - Remove → `remove_inner` once.
///
/// On a real Apply, fires the shared `attempt_reload` and reloads the
/// cached config so the next render reflects the mutation. Audit
/// emissions go through the standard `tracing::info!(target: "audit",
/// ...)` cabling on the Apply path. Mirrors `submit_local_dns_modal`.
async fn submit_subnet_modal(
    app: &mut App,
    mut modal: subnet_modal::SubnetModal,
    poller: &IpcPoller,
    config_path: &Path,
) {
    use crate::cli::commands::ipc_reload::{attempt_reload, ReloadOutcome};
    use crate::cli::commands::subnets::{add_inner, remove_inner, RemoveOutcome};
    use subnet_modal::{Stage, SubmitOutcome};

    // The armed tag valve, captured before the form is consumed.
    let outcome: SubmitOutcome = match &modal.stage {
        Stage::EditingForm(form) => match form.try_resolve() {
            Err(msg) => SubmitOutcome::Failed(msg),
            Ok(resolved) => match form.mode {
                subnet_modal::FormMode::Add => {
                    match add_inner(
                        config_path,
                        &resolved.id,
                        Some(&resolved.display_name),
                        &resolved.cidrs,
                        &resolved.profile,
                        Some(resolved.priority),
                        None,
                    ) {
                        Ok(report) => {
                            tracing::info!(
                                target: "audit",
                                action = "subnet.add",
                                surface = "tui",
                                id = %resolved.id,
                                profile = %resolved.profile,
                                source_file = %report.target_path.display(),
                                "TUI mutation"
                            );
                            SubmitOutcome::Ok(format!("added subnet {}", resolved.id))
                        }
                        Err(e) => SubmitOutcome::Failed(e.to_string()),
                    }
                }
                subnet_modal::FormMode::Edit => match form.original.as_ref() {
                    Some(original) => submit_subnet_edit(config_path, original, &resolved),
                    // The Add/Edit constructors keep `mode == Edit` and
                    // `original.is_some()` in lock-step; degrade a broken
                    // invariant to a footer error instead of a panic that
                    // would unwind out of the dashboard's main task.
                    None => SubmitOutcome::Failed(
                        "internal error: edit modal lost its original snapshot".into(),
                    ),
                },
            },
        },
        Stage::ConfirmingRemove(rc) => match remove_inner(config_path, &rc.id, None) {
            Ok(RemoveOutcome::Removed(report)) => {
                tracing::info!(
                    target: "audit",
                    action = "subnet.delete",
                    surface = "tui",
                    id = %rc.id,
                    source_file = %report.target_path.display(),
                    "TUI mutation"
                );
                SubmitOutcome::Ok(format!("removed subnet {}", rc.id))
            }
            Ok(RemoveOutcome::NotFound { .. }) => {
                SubmitOutcome::Failed(format!("subnet '{}' not found — already removed?", rc.id))
            }
            Err(e) => SubmitOutcome::Failed(e.to_string()),
        },
        Stage::Submitted(_) => return,
    };

    // A form (Add/Edit) failure — pre-flight validation (empty field, bad
    // priority) or an apply/validator rejection — keeps the modal open
    // with the message on the grid's inline validation line instead of
    // dropping to the terminal "failed" screen. The operator fixes the
    // offending field and re-submits without retyping the rest. Remove
    // failures still finish (their confirm screen has no form to keep).
    // Mirrors `submit_local_dns_modal`.
    if let SubmitOutcome::Failed(msg) = &outcome {
        if let Stage::EditingForm(form) = &mut modal.stage {
            app.status_err(format!("subnet modal: {msg}"));
            form.error_message = Some(msg.clone());
            app.subnets.modal = Some(modal);
            return;
        }
    }

    let was_ok = matches!(outcome, SubmitOutcome::Ok(_));
    match &outcome {
        SubmitOutcome::Ok(msg) => app.status_ok(msg.clone()),
        SubmitOutcome::Failed(msg) => {
            app.status_err(format!("subnet modal: {msg}"));
        }
    }
    modal.finish(outcome);
    app.subnets.modal = Some(modal);

    if was_ok {
        let outcome = attempt_reload(poller.socket_path()).await;
        // The reload arms REPLACE the status set above. `Reloaded` is the
        // one arm that stays silent and therefore keeps it.
        match outcome {
            ReloadOutcome::Reloaded => {}
            ReloadOutcome::DaemonUnreachable => {
                app.status_err(
                    "subnet saved on disk — daemon not running, will activate on next start".into(),
                );
            }
            ReloadOutcome::NoToken { .. } => {
                app.status_err(
                    "subnet saved on disk but no admin token is available to request a reload"
                        .into(),
                );
            }
            ReloadOutcome::ReloadFailed(msg) => {
                app.status_err(format!("subnet saved but daemon rejected reload: {msg}"));
            }
        }
        app.loaded_config = load_v1_config(config_path);
        poll_active_leaf(app, poller).await;
    }
}

/// Apply the diff between `original` and `resolved`. The scalar fields
/// (display_name/cidrs/profile/priority) stay **atomic** exactly as
/// before: every changed one lands in a single `set_fields_inner` write,
/// or none do (the partial-apply trap where an
/// earlier field persisted while a later one failed and Discard then
/// implied nothing was saved).
///
/// **This is a single write, and the atomicity above is
/// the whole story.** `tags` used to be a second, independent write
/// through `apply_tags_inner`, so a Save could half-land: scalars written,
/// tag delta refused, and an outcome that had to say so. An earlier change had
/// already turned that second write into an unconditional refusal
/// (`TAGS_RETIRED`) taken BEFORE the scalar write — which meant an
/// operator who edited a display name and also touched the tag picker lost
/// the rename too, for a field that had stopped deciding anything.
///
/// Both are gone: `ResolvedForm` has no `tags`, so there is no delta to
/// diff, refuse, or half-apply. The runtime refusal is replaced by the
/// stronger guarantee that the type cannot carry the value.
fn submit_subnet_edit(
    config_path: &Path,
    original: &subnet_modal::OriginalSnapshot,
    resolved: &subnet_modal::ResolvedForm,
) -> subnet_modal::SubmitOutcome {
    use crate::cli::commands::subnets::set_fields_inner;
    use subnet_modal::SubmitOutcome;

    let mut changes: Vec<(&str, String)> = Vec::new();
    if original.display_name != resolved.display_name {
        changes.push(("display_name", resolved.display_name.clone()));
    }
    if original.cidrs != resolved.cidrs {
        changes.push(("cidrs", resolved.cidrs.join(",")));
    }
    if original.profile != resolved.profile {
        changes.push(("profile", resolved.profile.clone()));
    }
    if original.priority != resolved.priority {
        changes.push(("priority", resolved.priority.to_string()));
    }

    let mut messages: Vec<String> = Vec::new();

    if !changes.is_empty() {
        let fields: Vec<(&str, &str)> = changes.iter().map(|(f, v)| (*f, v.as_str())).collect();
        match set_fields_inner(config_path, &resolved.id, &fields, None) {
            Ok(report) => {
                tracing::info!(
                    target: "audit",
                    action = "subnet.update",
                    surface = "tui",
                    id = %resolved.id,
                    fields = %report.fields.join(","),
                    source_file = %report.target_path.display(),
                    "TUI mutation"
                );
                let n = report.fields.len();
                messages.push(format!(
                    "{n} field{} updated",
                    if n == 1 { "" } else { "s" }
                ));
            }
            // A single write, so nothing landed — Discard genuinely
            // discards, with no partial-apply caveat needed.
            Err(e) => return SubmitOutcome::Failed(format!("edit failed: {e}")),
        }
    }

    if messages.is_empty() {
        return SubmitOutcome::Ok(format!("subnet {} unchanged", resolved.id));
    }
    SubmitOutcome::Ok(format!(
        "edited subnet {}: {}",
        resolved.id,
        messages.join(", ")
    ))
}

#[cfg(test)]
#[path = "tests/subnet_edit_tests.rs"]
mod subnet_edit_tests;

#[cfg(test)]
#[path = "tests/group_edit_tests.rs"]
mod group_edit_tests;

// ── Profiles tab key handler + modal openers + submit ────────────────
//
// Offline-backed master/detail tab (mirrors Subnets minus the
// candidate-promote path — profiles have no auto-discovery). ↑/↓ scrolls
// the master list; `a` / `e` / `d` open the Add / Edit / Delete modals
// which drive the IPC verbs directly (`ProfileCreate` /
// `ProfileUpdate` / `ProfileDelete`). `selected_id` tracks the cursor so
// the side-card re-renders the focused profile on the next frame.

fn handle_profiles_key(app: &mut App, key: KeyEvent) {
    // Seed the selection on first keystroke so `e` / `d` land on a real
    // profile from the very first interaction (mirrors the Subnets seed).
    ensure_profile_selection_seeded(app);
    match key.code {
        KeyCode::Down => {
            let len = profiles_len(app);
            scroll_table_down(&mut app.profiles.table_state, len);
            sync_profile_selection(app);
        }
        KeyCode::Up => {
            scroll_table_up(&mut app.profiles.table_state);
            sync_profile_selection(app);
        }
        // Jump / page.
        KeyCode::Home => {
            let len = profiles_len(app);
            jump_table_home(&mut app.profiles.table_state, len);
            sync_profile_selection(app);
        }
        KeyCode::End => {
            let len = profiles_len(app);
            jump_table_end(&mut app.profiles.table_state, len);
            sync_profile_selection(app);
        }
        KeyCode::PageDown => {
            let len = profiles_len(app);
            page_table_down(&mut app.profiles.table_state, len);
            sync_profile_selection(app);
        }
        KeyCode::PageUp => {
            page_table_up(&mut app.profiles.table_state);
            sync_profile_selection(app);
        }
        KeyCode::Char('a') => {
            app.profiles.modal = Some(profile_modal::ProfileModal::open_add());
        }
        // Enter is the primary action on the focused row, and on
        // Profiles the primary action is edit. Same branch as `e`, not a
        // new modal: Lists / Rules / mapped Devices already read this way,
        // and Profiles / Groups / Labels were the three leaves where Enter
        // did nothing at all.
        KeyCode::Enter | KeyCode::Char('e') => {
            if let Some(modal) = build_profile_edit_modal(app) {
                app.profiles.modal = Some(modal);
            }
        }
        KeyCode::Char('d') | KeyCode::Delete => {
            if let Some(modal) = build_profile_remove_modal(app) {
                app.profiles.modal = Some(modal);
            }
        }
        _ => app.leaf_key_unhandled = true,
    }
}

/// Master row count = the configured profile count.
fn profiles_len(app: &App) -> usize {
    app.loaded_config
        .as_ref()
        .map(|l| l.config.profiles.len())
        .unwrap_or(0)
}

/// Seed `app.profiles.selected_id` to the first profile's id when it is
/// still `None`. Mirrors `ensure_subnet_selection_seeded`: the renderer
/// auto-places the visual cursor on row 0, but the modal openers
/// (`e` / `d`) consult `selected_id` directly.
fn ensure_profile_selection_seeded(app: &mut App) {
    let ids: Vec<String> = app
        .loaded_config
        .as_ref()
        .map(|l| l.config.profiles.keys().cloned().collect())
        .unwrap_or_default();

    // Repair a *dangling* id, not just an unset one.
    // The old guard returned early whenever the id was `Some`, so an id
    // whose profile had been deleted (a second operator, an external edit
    // + `r`) survived — and master and detail then disagreed:
    // `render_master` falls back to highlighting row 0 on a *local*
    // `TableState`, while `render_detail` re-reads that same dead id,
    // matches nothing, and paints "select a profile on the left". Both
    // sides resolve the id, so re-anchoring it here — the `&mut App` the
    // renderer doesn't have — is what makes them agree.
    if app
        .profiles
        .selected_id
        .as_deref()
        .is_some_and(|id| ids.iter().any(|k| k == id))
    {
        return;
    }

    match ids.first() {
        // Row 0 — the same row `render_master` falls back to, and the
        // first key of the `BTreeMap` the master rows are built from.
        Some(id) => {
            app.profiles.selected_id = Some(id.clone());
            app.profiles.table_state.select(Some(0));
        }
        None => {
            app.profiles.selected_id = None;
            app.profiles.table_state.select(None);
        }
    }
}

/// Recompute `selected_id` from the cursor position after ↑/↓ scroll so
/// the side-card stays in sync. The master list is the `BTreeMap` key
/// order — same order `tabs::profiles::master_rows` paints.
fn sync_profile_selection(app: &mut App) {
    let ids: Vec<String> = app
        .loaded_config
        .as_ref()
        .map(|l| l.config.profiles.keys().cloned().collect())
        .unwrap_or_default();
    match app.profiles.table_state.selected() {
        Some(idx) => app.profiles.selected_id = ids.get(idx).cloned(),
        None => app.profiles.selected_id = None,
    }
}

/// The currently-focused profile `(id, Profile)`, captured by value so
/// the modal opener holds an owned snapshot rather than borrowing
/// `loaded_config` for the modal's lifetime.
fn focused_profile(app: &App) -> Option<(String, crate::config::schema::Profile)> {
    let key = app.profiles.selected_id.as_deref()?;
    let profiles = app.loaded_config.as_ref().map(|l| &l.config.profiles)?;
    profiles.get(key).map(|p| (key.to_string(), p.clone()))
}

fn build_profile_edit_modal(app: &App) -> Option<profile_modal::ProfileModal> {
    let (id, profile) = focused_profile(app)?;
    // The per-list override panel's rows, captured at open time.
    //
    // Sorted by id rather than left in `[[blocklists]]` file order: the
    // panel is a focus ring indexed by position, and a reload that
    // re-ordered the vector under an open modal would move the operator's
    // cursor onto a different list than the one they were looking at. Id
    // order is stable across reloads and across which `*.d/*.toml` file an
    // entry happens to live in.
    //
    // NOT filtered on `enabled`, deliberately, and for the reason the
    // daemon's own gate gives: a disabled list holds no source bit today,
    // but `warden blocklist set <id> --enabled true` flips that back with
    // no gate to re-run. The override is a declaration about the list, not
    // about its current reachability.
    let mut lists: Vec<crate::config::schema::blocklist::Blocklist> = app
        .loaded_config
        .as_ref()
        .map(|l| l.config.blocklists.clone())
        .unwrap_or_default();
    lists.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
    // The mount panel's rows. Sorted by id for the same reason the
    // override panel's are: the panel is a focus ring indexed by position,
    // and file order is neither stable across reloads nor meaningful to
    // the operator.
    //
    // The DECLARED entities, not the compiled store: a pack the reader
    // could not open is still a list the operator declared and may want to
    // unmount, and a panel that dropped it would offer no way to.
    let mut custom_lists: Vec<crate::config::schema::custom_list::CustomList> = app
        .loaded_config
        .as_ref()
        .map(|l| l.config.custom_lists.clone())
        .unwrap_or_default();
    custom_lists.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
    Some(profile_modal::ProfileModal::open_edit(
        &id,
        &profile,
        lists,
        custom_lists,
    ))
}

fn build_profile_remove_modal(app: &App) -> Option<profile_modal::ProfileModal> {
    let (id, profile) = focused_profile(app)?;
    // Client-side blast-radius pre-check — informational only; the
    // daemon validator is still the authority that blocks the delete.
    let summary = app
        .loaded_config
        .as_ref()
        .map(|l| crate::tui::tabs::profiles::reference_summary(l, &id))
        .unwrap_or_else(|| "unknown".to_string());
    Some(profile_modal::ProfileModal::open_remove(
        &id,
        &profile.display_name,
        summary,
    ))
}

/// Drive the Profiles modal state machine on each keypress. On submit
/// fires the Phase 1 IPC verbs via `IpcPoller::send_profile_*`. Mirrors
/// `handle_subnet_modal_key`, adapted for the dropdown / toggle / text
/// field mix of the profile Edit form.
async fn handle_profile_modal_key(
    app: &mut App,
    key: KeyEvent,
    poller: &IpcPoller,
    config_path: &Path,
) {
    let Some(mut modal) = app.profiles.modal.take() else {
        return;
    };

    use profile_modal::{FormField, Stage};

    if modal.is_submitted() {
        // Any keypress in the submitted stage closes the modal — handler
        // returned without re-stashing.
        return;
    }

    // `Ctrl+s` saves from anywhere on an Archetype-F form.
    //
    // Checked BEFORE the field dispatch, not as a guarded `Char('s')` arm:
    // the `KeyCode::Char(c)` catch-all at the bottom of the form match is
    // what used to append a literal `s` to the focused buffer, so an arm
    // placed after it would be dead. "From anywhere" means ahead of the
    // field dispatch entirely. Mirrors the check in
    // `handle_edit_mode_key`, including the `S` spelling some terminals
    // send.
    //
    // Confirm stages are Archetype C and keep `[y]` / `[n]` — the chord
    // must not reach them, hence the stage guard.
    if matches!(key.code, KeyCode::Char('s') | KeyCode::Char('S'))
        && key.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(modal.stage, Stage::EditingForm(_))
    {
        submit_profile_modal(app, modal, poller, config_path).await;
        return;
    }

    match &mut modal.stage {
        Stage::EditingForm(form) => {
            match key.code {
                KeyCode::Esc => {
                    return;
                }
                // Merged with Down/Up so this matches the
                // shared modal legend (`keys_line()`: "↹/↑↓ move"), and the
                // Subnet / Local-DNS handlers, which already bind both.
                KeyCode::Tab | KeyCode::Down => {
                    // Leaving a row spends the `ignore` valve, so the next
                    // visit starts unarmed. Same reason the tag picker
                    // dropped its type-ahead here: a confirmation left
                    // live under a row the operator has navigated away
                    // from is one they would spend without meaning to.
                    form.ignore_armed = None;
                    form.focus_next();
                    form.error_message = None;
                }
                KeyCode::BackTab | KeyCode::Up => {
                    form.ignore_armed = None;
                    form.focus_prev();
                    form.error_message = None;
                }
                KeyCode::Enter => {
                    // A panel row does NOT carve Enter out the way the tag
                    // picker did. The picker had to: it held a half-typed
                    // slug that a form-wide submit would have dropped on
                    // the floor. A panel row holds no buffer — the `i`
                    // valve is armed state, not typed state, and an
                    // unspent one leaves the row displaying exactly the
                    // value that gets saved. So Enter keeps meaning
                    // "save", as it does on every other row here.
                    if form.focused == FormField::Cancel {
                        // Discard button → close without saving (same as Esc).
                        return;
                    } else {
                        // Enter submits from any other field; a pre-flight or
                        // apply error keeps the form open with an inline
                        // message (see `submit_profile_modal`), so a stray
                        // Enter is recoverable. Honors the shared "Enter
                        // save" legend.
                        submit_profile_modal(app, modal, poller, config_path).await;
                        return;
                    }
                }
                KeyCode::Right => match form.focused {
                    // Toggles read as 2-state selectors — ←/→ flips them,
                    // matching the shared "←/→ change" legend.
                    FormField::BlockAll | FormField::EcsClear => form.toggle(),
                    // A panel row walks `inherit → Block → Allow`. Named
                    // explicitly rather than left to the `_` arm below:
                    // `cycle_dropdown` would silently do nothing here, so
                    // the arrow key would appear dead on the one field the
                    // legend advertises it hardest for.
                    FormField::ListOverride(_) => form.cycle_list_policy(true),
                    // A mount row is two-state, so both arrows flip it —
                    // there is no cycle to walk in a direction. Named
                    // explicitly for the reason the row above is: the `_`
                    // arm would send the arrow into `cycle_dropdown`,
                    // which is a no-op here and would make the key look
                    // dead on a row the legend advertises it for.
                    FormField::CustomListMount(_) => form.toggle_custom_list_mount(),
                    _ => form.cycle_dropdown(true),
                },
                KeyCode::Left => match form.focused {
                    FormField::BlockAll | FormField::EcsClear => form.toggle(),
                    FormField::ListOverride(_) => form.cycle_list_policy(false),
                    FormField::CustomListMount(_) => form.toggle_custom_list_mount(),
                    _ => form.cycle_dropdown(false),
                },
                KeyCode::Char(' ') => {
                    // Space flips a toggle, steps a panel row, fires the
                    // focused button, or is a literal space inside a text
                    // field (display names may contain spaces).
                    match form.focused {
                        FormField::BlockAll | FormField::EcsClear => form.toggle(),
                        // Same step `→` takes, and safe for the same
                        // reason: `POLICY_CYCLE` cannot produce `Ignore`,
                        // so the casual keypress cannot make a list inert.
                        // `i` is the only route to that, and it asks twice.
                        FormField::ListOverride(_) => form.cycle_list_policy(true),
                        // Same flip both arrows take. Safe as a casual
                        // keypress for the same reason as the row above:
                        // the reachable states are "applies here" and
                        // "does not", and the row shows which one gets
                        // saved.
                        FormField::CustomListMount(_) => form.toggle_custom_list_mount(),
                        FormField::Submit => {
                            submit_profile_modal(app, modal, poller, config_path).await;
                            return;
                        }
                        FormField::Cancel => return,
                        _ => {
                            if let Some(buf) = form.text_field_buf() {
                                buf.push(' ');
                            }
                        }
                    }
                    form.error_message = None;
                }
                KeyCode::Backspace => {
                    if let Some(buf) = form.text_field_buf() {
                        buf.pop();
                        form.error_message = None;
                    }
                }
                KeyCode::Char(c) => {
                    // `i` on a panel row is the `ignore` declaration, and
                    // it takes two presses. It sits here rather than on a
                    // key of its own because `text_field_buf` returns
                    // `None` for a panel row, so every other letter is
                    // already inert there — this is the one that is not.
                    //
                    // Any OTHER letter disarms. An armed confirmation that
                    // survives arbitrary keystrokes is one the operator can
                    // spend without having meant to; the two presses have
                    // to be consecutive to be a deliberation.
                    if matches!(form.focused, FormField::ListOverride(_)) {
                        if c == 'i' || c == 'I' {
                            form.press_ignore();
                        } else {
                            form.ignore_armed = None;
                        }
                        form.error_message = None;
                    } else if let Some(buf) = form.text_field_buf() {
                        buf.push(c);
                        form.error_message = None;
                    }
                }
                _ => {}
            }
            app.profiles.modal = Some(modal);
        }
        Stage::ConfirmingRemove(_) => match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                submit_profile_modal(app, modal, poller, config_path).await;
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                // Drop the modal — handler returned without re-stashing.
            }
            _ => {
                app.profiles.modal = Some(modal);
            }
        },
        Stage::Submitted(_) => {
            // Already handled above.
        }
    }
}

/// Submit path for all three Profile modals. Branches on the stage:
///
/// - Add → `send_profile_create` once.
/// - Edit → `resolve_edit_patch` diffs the form against the captured
///   snapshot, then ONE atomic `send_profile_update`. An all-`None`
///   patch short-circuits with an "unchanged" outcome.
/// - Remove → `send_profile_delete` once.
///
/// Unlike `submit_subnet_modal`, there is NO `attempt_reload` here: the
/// daemon's `handle_profile_*` IPC handlers self-reload via
/// `notify_reload`. The TUI only refreshes its offline `loaded_config`
/// cache so the next render reflects the mutation.
async fn submit_profile_modal(
    app: &mut App,
    mut modal: profile_modal::ProfileModal,
    poller: &IpcPoller,
    config_path: &Path,
) {
    use crate::ipc::protocol::ProfileUpdatePatch;
    use profile_modal::{FormMode, Stage, SubmitOutcome};

    // The tag valve this path used to capture is gone with the picker it
    // guarded. Its notice was earned: a slug awaiting its second `Enter`
    // was typed state, so a save that dropped it lost work the operator
    // could see themselves doing, and saying nothing would have been a
    // silent loss.
    //
    // The `ignore` valve that replaced it is NOT typed state. An unspent
    // one leaves the panel row displaying exactly the policy that gets
    // saved, so there is nothing to lose and nothing to report — a notice
    // here would announce a non-event on every save, which is how a real
    // notice stops being read. The subnet and group modals still capture
    // their own valve; only this form's picker went away.
    let outcome: SubmitOutcome = match &modal.stage {
        Stage::EditingForm(form) => match form.mode {
            FormMode::Add => match form.try_resolve_add() {
                Err(msg) => SubmitOutcome::Failed(msg),
                Ok((id, display_name)) => {
                    match poller.send_profile_create(id.clone(), display_name).await {
                        Ok(_) => SubmitOutcome::Ok(format!("created profile {id}")),
                        Err(e) => SubmitOutcome::Failed(e.to_string()),
                    }
                }
            },
            FormMode::Edit => match form.original.as_ref() {
                // The Add/Edit constructors keep `mode == Edit` and
                // `original.is_some()` in lock-step; degrade a broken
                // invariant to a footer error instead of a panic that
                // would unwind out of the dashboard's main task.
                None => SubmitOutcome::Failed(
                    "internal error: edit modal lost its original snapshot".into(),
                ),
                Some(original) => match profile_modal::resolve_edit_patch(form, original) {
                    Err(msg) => SubmitOutcome::Failed(msg),
                    Ok(patch) if patch == ProfileUpdatePatch::default() => {
                        SubmitOutcome::Ok(format!("profile {} unchanged", original.id))
                    }
                    Ok(patch) => {
                        match poller.send_profile_update(original.id.clone(), patch).await {
                            Ok(_) => SubmitOutcome::Ok(format!("updated profile {}", original.id)),
                            Err(e) => SubmitOutcome::Failed(e.to_string()),
                        }
                    }
                },
            },
        },
        Stage::ConfirmingRemove(rc) => match poller.send_profile_delete(rc.id.clone()).await {
            Ok(_) => SubmitOutcome::Ok(format!("removed profile {}", rc.id)),
            Err(e) => SubmitOutcome::Failed(e.to_string()),
        },
        Stage::Submitted(_) => return,
    };

    // A form (Add/Edit) failure — pre-flight validation or an apply/
    // validator rejection — keeps the modal open with the message on the
    // form's own error line instead of dropping to the terminal "failed"
    // screen. The operator fixes the offending field and re-submits
    // without retyping the rest (this form especially: 9 head fields plus
    // one row per configured blocklist override). Remove failures still
    // finish — their confirm screen has no form to keep. Mirrors
    // `submit_subnet_modal` / `submit_local_dns_modal` (`profile-01`).
    if let SubmitOutcome::Failed(msg) = &outcome {
        if let Stage::EditingForm(form) = &mut modal.stage {
            app.status_err(format!("profile modal: {msg}"));
            form.error_message = Some(msg.clone());
            app.profiles.modal = Some(modal);
            return;
        }
    }

    let was_ok = matches!(outcome, SubmitOutcome::Ok(_));
    match &outcome {
        SubmitOutcome::Ok(msg) => app.status_ok(msg.clone()),
        SubmitOutcome::Failed(msg) => {
            app.status_err(format!("profile modal: {msg}"));
        }
    }
    modal.finish(outcome);
    app.profiles.modal = Some(modal);

    if was_ok {
        app.loaded_config = load_v1_config(config_path);
        // A delete leaves `selected_id` dangling (the id is gone). Clear
        // + re-seed so the side-card and the next e/d keypress land on a
        // real profile instead of an empty "select a profile" card.
        let still_valid = app
            .loaded_config
            .as_ref()
            .zip(app.profiles.selected_id.as_deref())
            .map(|(l, id)| l.config.profiles.contains_key(id))
            .unwrap_or(false);
        if !still_valid {
            app.profiles.selected_id = None;
            app.profiles.table_state.select(None);
            ensure_profile_selection_seeded(app);
        }
        poll_active_leaf(app, poller).await;
    }
}

// Local DNS tab. `a` / `d`|`Delete` / `e` open
// modals that submit through `cli::commands::local_dns::add_inner` /
// `remove_inner` (single-seat — same code path as the CLI verbs).
//
// Keybindings:
//   ↑/↓         scroll the focused panel's table.
//   Tab         switch focus Global ⇄ Profile.
//   p / n       previous / next profile (when Profile panel focused).
//   a           open Add modal (form: domain, type, value, subdomain,
//               TTL, profile dropdown).
//   d / Delete  open Remove modal with a tiered confirm on the
//               focused row.
//   e           open Edit modal pre-filled from the focused row.
/// Keys of the Local DNS leaf.
///
/// **One list, one cursor.** `o` (panel switch) and `n` / `N`
/// (profile cycle) are gone with the panels they served — `↑`/`↓` walk
/// every record in every scope, skipping the group headers. `Tab` is
/// untouched and still cycles leaves (`ldns_04_tab_still_cycles_leaf`).
fn handle_local_dns_key(app: &mut App, key: KeyEvent) {
    let Some(loaded) = app.loaded_config.as_ref() else {
        app.leaf_key_unhandled = true;
        return;
    };
    let rows = tabs::local_dns::build_rows(loaded);

    // Seed the anchor on the first keystroke, before the openers run.
    //
    // Mirrors `ensure_subnet_selection_seeded` / the Labels seed, and it
    // is load-bearing here for a reason beyond symmetry: the renderer
    // highlights the first selectable row when the anchor is `None`, so
    // an unseeded `a` / `e` / `d` would act on a row the operator can see
    // is highlighted while the state says nothing is selected. For `a`
    // that is not a missed convenience — it is a record written to the
    // wrong SCOPE, silently.
    if app.local_dns.selected_id.is_none() {
        if let Some(idx) = rows
            .iter()
            .position(tabs::local_dns::LocalDnsRow::is_selectable)
        {
            app.local_dns.selected_id = tabs::local_dns::row_key(&rows[idx]);
            app.local_dns.table_state.select(Some(idx));
        }
    }
    let current = tabs::local_dns::index_of_key(&rows, app.local_dns.selected_id.as_ref());

    // `focus` moves the cursor and re-anchors the stable key together —
    // separating them is how the two drift.
    macro_rules! focus {
        ($idx:expr) => {
            if let Some(i) = $idx {
                app.local_dns.table_state.select(Some(i));
                app.local_dns.selected_id = tabs::local_dns::row_key(&rows[i]);
            }
        };
    }

    match key.code {
        KeyCode::Down => focus!(tabs::local_dns::next_selectable_index(&rows, current, true)),
        KeyCode::Up => focus!(tabs::local_dns::next_selectable_index(
            &rows, current, false
        )),
        // Jump / page, headers skipped and clamped at both ends.
        KeyCode::Home => {
            focus!(first_selectable_idx(
                &rows,
                tabs::local_dns::LocalDnsRow::is_selectable
            ))
        }
        KeyCode::End => {
            focus!(last_selectable_idx(
                &rows,
                tabs::local_dns::LocalDnsRow::is_selectable
            ))
        }
        KeyCode::PageDown => focus!(page_selectable_idx(
            &rows,
            current,
            true,
            tabs::local_dns::LocalDnsRow::is_selectable
        )),
        KeyCode::PageUp => focus!(page_selectable_idx(
            &rows,
            current,
            false,
            tabs::local_dns::LocalDnsRow::is_selectable
        )),
        // s44-tui-modals: open Add modal, scoped to the focused row.
        KeyCode::Char('a') => {
            let (modal, note) = build_local_dns_add_modal(app);
            app.local_dns.modal = Some(modal);
            if let Some(note) = note {
                app.status_info(note);
            }
        }
        // s44-tui-modals: open Remove modal on the focused row. The
        // tier (single-keypress vs typed-phrase) is decided by
        // `ConfirmTier::for_remove` from (scope, match_subdomains).
        KeyCode::Char('d') | KeyCode::Delete => {
            if let Some(modal) = build_local_dns_remove_modal(app) {
                app.local_dns.modal = Some(modal);
            } else {
                app.status_err(
                    "no local DNS row selected — ↑/↓ to pick one before pressing d".into(),
                );
            }
        }
        // s44-tui-modals: open Edit modal pre-filled from the focused row.
        KeyCode::Char('e') => {
            if let Some(modal) = build_local_dns_edit_modal(app) {
                app.local_dns.modal = Some(modal);
            } else {
                app.status_err(
                    "no local DNS row selected — ↑/↓ to pick one before pressing e".into(),
                );
            }
        }
        // Enter toggles the side-card. When
        // closed and the focused row is valid → load + open. When open →
        // close. The audit log is read off the master config path stored
        // in `loaded_config` so we don't need to thread `config_path`
        // through the per-tab dispatch signature.
        KeyCode::Enter => {
            if app.local_dns.audit_view.is_some() {
                app.local_dns.audit_view = None;
            } else if let Some(view) = build_local_dns_audit_view(app) {
                app.local_dns.audit_view = Some(view);
            } else {
                app.status_err(
                    "no local DNS row selected — ↑/↓ to pick one before pressing Enter".into(),
                );
            }
        }
        // Esc closes the side-card without affecting cursor state. Only
        // consumes the key when the side-card was open; otherwise the
        // global Esc handler keeps the existing semantics.
        KeyCode::Esc if app.local_dns.audit_view.is_some() => {
            app.local_dns.audit_view = None;
        }
        _ => app.leaf_key_unhandled = true,
    }

    // Side-card follows the cursor: any navigation that moved the focused
    // row while the panel is open re-loads the audit slice for the new
    // row before the next render. Cheap because reads are bounded by
    // `LOCAL_DNS_HISTORY_SCAN_LIMIT` and only fire on key events, not
    // every frame. If the new focus has no resolvable row the previous
    // view is preserved so the side-card never silently vanishes —
    // operator closes it explicitly with Esc.
    if app.local_dns.audit_view.is_some() {
        match key.code {
            // The follow set is exactly the cursor keys. It used
            // to include `o` / `n` / `N`, which no longer exist.
            KeyCode::Up
            | KeyCode::Down
            | KeyCode::Home
            | KeyCode::End
            | KeyCode::PageUp
            | KeyCode::PageDown => {
                if let Some(view) = build_local_dns_audit_view(app) {
                    app.local_dns.audit_view = Some(view);
                }
            }
            _ => {}
        }
    }
}

/// Build a `LocalDnsAuditView` for the currently-focused Local DNS row.
/// Returns `None` when no row is focused, the cursor is out of range, or
/// no master config path is loaded.
fn build_local_dns_audit_view(app: &App) -> Option<crate::tui::app::LocalDnsAuditView> {
    use crate::cli::commands::audit::local_dns_history_for;
    use crate::cli::commands::local_dns::LocalRecordScope;

    let loaded = app.loaded_config.as_ref()?;
    let (scope, record) = focused_local_dns_row(app)?;
    let (scope_tag, target_id): (String, String) = match &scope {
        LocalRecordScope::Global => ("global".to_string(), "global".to_string()),
        LocalRecordScope::Profile(id) => ("profile".to_string(), id.clone()),
    };
    let domain = record.domain.to_ascii_lowercase();
    let entries = local_dns_history_for(&loaded.master_path, &scope_tag, &target_id, &domain, 10);
    Some(crate::tui::app::LocalDnsAuditView {
        scope_tag,
        target_id,
        domain,
        entries,
    })
}

// Resolver modal: input is always live while the modal is
// open, no leading `i` ceremony. Enter resolves; Ctrl-U clears; Esc
// closes. The modal-priority gate above ensures every keystroke lands
// here while open, so digits flow into the input buffer instead of
// firing the section hotkeys.
fn handle_resolver_modal_key(app: &mut App, key: KeyEvent) {
    if app.resolver_modal.is_none() {
        return;
    }
    match key.code {
        KeyCode::Esc => {
            app.resolver_modal = None;
        }
        KeyCode::Enter => {
            // Lift the modal out of the Option so `submit` can take
            // `&App` (it consults `loaded_config`) without aliasing
            // the mutable borrow on `app.resolver_modal`.
            let mut modal = app.resolver_modal.take().expect("guarded above");
            modal.submit(app);
            app.resolver_modal = Some(modal);
        }
        KeyCode::Backspace => {
            if let Some(modal) = app.resolver_modal.as_mut() {
                modal.pop_char();
            }
        }
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            if let Some(modal) = app.resolver_modal.as_mut() {
                modal.clear_input();
            }
        }
        KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            if let Some(modal) = app.resolver_modal.as_mut() {
                modal.push_char(c);
            }
        }
        _ => {}
    }
}

fn handle_dashboard_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('d') => app.dashboard.show_daily = !app.dashboard.show_daily,
        // An `if let` cannot report the miss, and Dashboard is the
        // leaf an operator is most likely to be standing on when they open
        // `?`. Widened to a match for the one arm that matters.
        _ => app.leaf_key_unhandled = true,
    }
}

/// Resolve the captured entry key to its current index and
/// move the cursor there. The Query Log is a sliding tail refreshed
/// every 3s, so the row the operator selected drifts to a new index when
/// the window shifts; re-anchoring keeps the cursor on it. No-op when the
/// key is unset or the entry has scrolled off the tail (the cursor then
/// stays put, and `clamp_query_log_cursor` keeps it in range).
fn anchor_query_log_cursor(app: &mut App) {
    if let Some(idx) = crate::tui::app::resolve_row_index(
        &app.query_log.entries,
        app.query_log.selected_key.as_ref(),
        |e| Some(tabs::query_log::entry_key(e)),
    ) {
        app.query_log.table_state.select(Some(idx));
    }
}

/// Capture the stable key of the row now under the cursor, so
/// the next poll can re-anchor to it. Called after every cursor move.
fn sync_query_log_selection(app: &mut App) {
    app.query_log.selected_key = app
        .query_log
        .table_state
        .selected()
        .and_then(|i| app.query_log.entries.get(i))
        .map(tabs::query_log::entry_key);
}

/// Drive the Query Log advanced-search form.
///
/// Esc discards the draft outright — `QueryLogState::advanced` is only
/// written on a successful Apply, so backing out cannot half-change the
/// applied filter. Enter validates first: a malformed CIDR keeps the form
/// open with the error on the tail rather than dropping the predicate,
/// because a silently-dropped subnet looks exactly like "no traffic from
/// that subnet".
fn handle_query_log_filter_modal_key(app: &mut App, key: KeyEvent) {
    use crate::tui::query_log_filter_modal::Field;
    let Some(modal) = app.query_log.advanced_modal.as_mut() else {
        return;
    };
    match key.code {
        KeyCode::Esc => {
            app.query_log.advanced_modal = None;
        }
        KeyCode::Tab | KeyCode::Down => modal.focus_next(),
        KeyCode::BackTab | KeyCode::Up => modal.focus_prev(),
        KeyCode::Left | KeyCode::Right => {
            // Only polarity rows consume it; on a text row the key is a
            // no-op rather than silently flipping a neighbour's polarity.
            modal.toggle_polarity();
        }
        KeyCode::Backspace => modal.backspace(),
        KeyCode::Enter => {
            if modal.focus == Field::Cancel {
                app.query_log.advanced_modal = None;
                return;
            }
            if let Some(applied) = modal.try_apply() {
                app.query_log.advanced = applied;
                app.query_log.advanced_modal = None;
                // A filter mutation like any other: cursors minted under
                // the previous predicate set name boundaries that no
                // longer exist. Same reason `b` / `t` / `R` / `/` / `c`
                // all reset — see `QueryLogState::reset_paging`.
                app.query_log.reset_paging();
                app.force_poll = true;
                app.status_info(QUERY_LOG_ADVANCED_APPLIED.to_string());
            }
        }
        // Bare characters only. Six sibling modals submit on `Ctrl+S`, so
        // an operator with that muscle memory WILL press it here — and
        // without this guard it types an `s` into whichever field has
        // focus. Ctrl+C is the quit chord and must reach its own handler
        // rather than being swallowed as text.
        KeyCode::Char(c)
            if !key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
        {
            modal.push_char(c)
        }
        _ => {}
    }
}

fn handle_query_log_key(app: &mut App, key: KeyEvent) {
    // Re-anchor the cursor to the captured entry key before
    // handling the key — a 3s poll may have slid the tail window, moving
    // the row out from under the bare TableState index.
    anchor_query_log_cursor(app);
    match key.code {
        KeyCode::Down => {
            scroll_table_down(&mut app.query_log.table_state, app.query_log.entries.len());
            sync_query_log_selection(app);
        }
        KeyCode::Up => {
            scroll_table_up(&mut app.query_log.table_state);
            sync_query_log_selection(app);
        }
        // Jump / page. **Query Log is a documented exception and it
        // must say so.** Its rows are not a list in memory: they are
        // whatever the last `read_log_entries_with_state` call returned.
        // `End` lands on the oldest *loaded* row, which an operator reads
        // as the oldest *query*. It is not. Shipping `End` /
        // `PgDn` here without a boundary marker would make a limit
        // visible for the first time while declining to explain it,
        // which is worse than the silent version it replaces.
        //
        // The marker is a row annotation, which lives in
        // `tabs/query_log.rs`. The status line carries it instead: same
        // information, same keystroke, in a file this module owns.
        // Real backward paging stays out of scope.
        KeyCode::End | KeyCode::PageDown => {
            let len = app.query_log.entries.len();
            let was_at_end = app.query_log.table_state.selected() == len.checked_sub(1);
            // `PgDn` pressed *while already on the last row* is the fetch
            // gesture; anywhere else it is ordinary within-page travel.
            // Two keystrokes to cross a page boundary is deliberate — a
            // single one would make an IPC round-trip out of a scroll.
            // `End` never fetches: it means "oldest loaded row", and
            // silently turning it into a fetch would make the one key
            // that promises a bounded jump unbounded.
            if matches!(key.code, KeyCode::PageDown) && was_at_end && len > 0 {
                if app.query_log.page_older() {
                    // Land on the newest row of the page about to arrive.
                    // The rows on screen are still the previous page for
                    // one tick, so this reads as travel, not a jump.
                    //
                    // `selected_key` is dropped rather than re-synced: it
                    // is the anchor for a *sliding tail*, and the
                    // row it names belongs to the page being left. Keeping
                    // it would let a coincidentally identical row on the
                    // incoming page yank the cursor off row 0.
                    app.query_log.selected_key = None;
                    app.query_log.table_state.select(Some(0));
                    app.force_poll = true;
                    app.status_info(query_log_page_label(app.query_log.page_index));
                } else {
                    app.status_info(QUERY_LOG_OLDEST.to_string());
                }
                return;
            }
            if matches!(key.code, KeyCode::End) {
                jump_table_end(&mut app.query_log.table_state, len);
            } else {
                page_table_down(&mut app.query_log.table_state, len);
            }
            sync_query_log_selection(app);
            if len > 0 && app.query_log.table_state.selected() == Some(len - 1) && !was_at_end {
                // Gated on the resume point: "older entries not loaded"
                // is only true when there are none to load.
                if app.query_log.next_cursor.is_some() {
                    app.status_info(QUERY_LOG_MORE_BELOW.to_string());
                } else {
                    app.status_info(QUERY_LOG_END_OF_PAGE.to_string());
                }
            }
        }
        KeyCode::Home => {
            jump_table_home(&mut app.query_log.table_state, app.query_log.entries.len());
            sync_query_log_selection(app);
        }
        KeyCode::PageUp => {
            // Mirror of `PgDn`: at the top of a paged-back view the key
            // returns to the newer page, which re-requests a cursor the
            // operator already used. That is why the daemon needs no
            // forward walker at all.
            let at_top = matches!(app.query_log.table_state.selected(), None | Some(0));
            if at_top && app.query_log.page_newer() {
                app.query_log.selected_key = None;
                app.query_log.table_state.select(Some(0));
                app.force_poll = true;
                if app.query_log.page_index == 0 {
                    app.status_info(QUERY_LOG_LIVE_TAIL.to_string());
                } else {
                    app.status_info(query_log_page_label(app.query_log.page_index));
                }
                return;
            }
            page_table_up(&mut app.query_log.table_state);
            sync_query_log_selection(app);
        }
        KeyCode::Char('G') => {
            let len = app.query_log.entries.len();
            if len > 0 {
                app.query_log.table_state.select(Some(len - 1));
                sync_query_log_selection(app);
            }
        }
        // `g` is a global mnemonic prefix that arms
        // `pending_goto` BEFORE per-tab dispatch — the previous
        // `g`-jumps-to-top handler is unreachable now and was removed;
        // jump-to-top is uncovered (operator scrolls with
        // `Up`). The help overlay no longer cites `g` for Query Log.
        KeyCode::Char('/') => {
            app.input_mode = InputMode::FilterDomain(String::new());
        }
        KeyCode::Char('c') => {
            app.input_mode = InputMode::FilterClient(String::new());
        }
        // `f` opens the advanced client search. Additive by construction:
        // `c` above is untouched and keeps its substring-over-name-or-IP
        // meaning, and an operator who never presses `f` sees no change.
        // Seeded from what is applied, so re-opening shows the live filter
        // instead of a blank form to retype.
        KeyCode::Char('f') => {
            app.query_log.advanced_modal = Some(
                crate::tui::query_log_filter_modal::QueryLogFilterModal::open(
                    &app.query_log.advanced,
                ),
            );
        }
        // Both toggles change the predicate set immediately, so both
        // must drop the cursor stack — see `reset_paging`.
        KeyCode::Char('b') => {
            app.query_log.blocked_only = !app.query_log.blocked_only;
            app.query_log.reset_paging();
        }
        // Cycle the time preset on `t`. One keystroke,
        // no text entry mode.
        KeyCode::Char('t') => {
            app.query_log.since = app.query_log.since.next();
            app.query_log.reset_paging();
        }
        // `R` resets all four filters. `Esc` no longer resets
        // here — it now cancels an in-progress filter *edit* only (handled
        // in the `InputMode::Filter*` arms of `handle_key`, which discard
        // the edit buffer and keep the committed filters). Dropping `Esc`
        // from this arm fixes the footgun where one stray Esc in Normal
        // mode nuked every filter; a Normal-mode Esc now falls through to
        // the `_ => {}` no-op below.
        KeyCode::Char('R') => {
            app.query_log.filter_domain = None;
            app.query_log.filter_client = None;
            app.query_log.blocked_only = false;
            app.query_log.since = crate::tui::app::SincePreset::Off;
            // `R` is documented as "reset all filters". Leaving the
            // advanced form applied would make it the one filter the
            // reset key does not reach — invisible on the card's single
            // chip and impossible to clear without reopening the form.
            app.query_log.advanced = Default::default();
            app.query_log.reset_paging();
        }
        // Single Enter opens the custom-list picker with the
        // highlighted row's domain + client captured at this moment
        // (NOT a file-tail re-read — the row may scroll out before the
        // operator finishes choosing). The action is
        // auto-flipped via `inferred_action` based on the row's status:
        // BLOCKED → Allow (whitelist), ALLOWED/CACHED/STALE → Deny
        // (blocklist). Non-actionable statuses (LOCAL / REFUSED /
        // HINFO / unknown) skip the modal and surface a footer message
        // explaining why.
        KeyCode::Enter => {
            if let Some(modal) = build_query_log_rule_modal(app) {
                app.query_log_rule_modal = Some(modal);
            } else {
                app.status_info(footer_message_for_neutral_row(app).to_string());
            }
        }
        _ => app.leaf_key_unhandled = true,
    }
}

fn handle_devices_key(app: &mut App, key: KeyEvent) {
    // Unified-list navigation. `↑` / `↓` move the cursor through the
    // merged mapped + unmapped list, skipping group-header rows
    // (`devices::next_selectable_index` does the heavy lifting). Enter
    // / e / d / p dispatch on the row variant: mapped rows go to
    // edit-or-delete, unmapped rows go to promote.
    let rows = match &app.device_view {
        // `build_filtered_rows`, NOT `build_rows`: this is the row set
        // Enter / e / d act on, and it must be the row set on screen. If
        // the two diverge a stale index opens the edit or delete modal on
        // a device that is not visible. Lane C's note on
        // `build_filtered_rows` names this hazard, and it is why the
        // keybinding below could not land in a commit without this line.
        Some(view) => {
            tabs::devices::build_filtered_rows(
                view,
                app.devices.group_by,
                app.devices.filter_subnet.as_deref(),
            )
            .0
        }
        None => Vec::new(),
    };
    // Resolve the operator's stable key to the current index so
    // navigation and the modal openers act on the device the highlight
    // is on — even after a background poll reshuffled the rows. Seed the
    // key and sync the visual cursor from the resolved row.
    let current = crate::tui::app::resolve_row_index(
        &rows,
        app.devices.selected_id.as_ref(),
        tabs::devices::row_key,
    )
    .or_else(|| tabs::devices::current_selection(&app.devices.table_state, &rows));
    if let Some(idx) = current {
        app.devices.table_state.select(Some(idx));
        if app.devices.selected_id.is_none() {
            app.devices.selected_id = tabs::devices::row_key(&rows[idx]);
        }
    }

    match key.code {
        KeyCode::Down => {
            if let Some(idx) = tabs::devices::next_selectable_index(&rows, current, 1) {
                app.devices.table_state.select(Some(idx));
                app.devices.selected_id = tabs::devices::row_key(&rows[idx]);
            }
        }
        KeyCode::Up => {
            if let Some(idx) = tabs::devices::next_selectable_index(&rows, current, -1) {
                app.devices.table_state.select(Some(idx));
                app.devices.selected_id = tabs::devices::row_key(&rows[idx]);
            }
        }
        // Jump / page over a row vector that interleaves group
        // headers. Built on `is_selectable`, not on a loop over
        // `next_selectable_index`: that helper wraps, and a paging key
        // that wraps is exactly the defect this exists to avoid.
        KeyCode::Home | KeyCode::End | KeyCode::PageUp | KeyCode::PageDown => {
            let sel = |r: &tabs::devices::DeviceRow| r.is_selectable();
            let idx = match key.code {
                KeyCode::Home => first_selectable_idx(&rows, sel),
                KeyCode::End => last_selectable_idx(&rows, sel),
                KeyCode::PageDown => page_selectable_idx(&rows, current, true, sel),
                _ => page_selectable_idx(&rows, current, false, sel),
            };
            if let Some(idx) = idx {
                app.devices.table_state.select(Some(idx));
                app.devices.selected_id = tabs::devices::row_key(&rows[idx]);
            }
        }
        // Remapped from `g` to `G` because
        // the global mnemonic prefix swallows lowercase `g` before
        // per-tab dispatch. Capital `G` is free on Devices (no
        // jump-to-bottom collision) and is mnemonic for "Group".
        // Subnet filter card. `/` focuses the CIDR buffer seeded with the
        // committed value so re-pressing edits rather than retypes; `R`
        // clears. Mirrors the Lists card exactly — an operator who learned
        // the filter there must not have to relearn it here.
        KeyCode::Char('/') => {
            app.input_mode = InputMode::FilterDevicesSubnet(
                app.devices.filter_subnet.clone().unwrap_or_default(),
            );
        }
        KeyCode::Char('R') => {
            app.devices.filter_subnet = None;
        }
        KeyCode::Char('G') => {
            app.devices.group_by = app.devices.group_by.next();
            // After re-grouping the row positions shift — clear the
            // visual cursor so the next render re-resolves `selected_id`
            // into the new layout (the device keeps its anchor).
            app.devices.table_state.select(None);
        }
        KeyCode::Enter | KeyCode::Char('e') => {
            // Enter behaves contextually: mapped → edit, unmapped → promote.
            // `e` is the explicit shortcut and is mapped-only.
            match selected_row(&rows, current) {
                Some(tabs::devices::DeviceRow::Mapped(m)) => {
                    let (profiles, groups) = device_form_option_lists(app);
                    let (owners, types, depts) = device_form_label_vocab(app);
                    app.devices.modal = Some(DeviceModal::Form(
                        edit_form_from(m)
                            .with_options(profiles, groups)
                            .with_label_vocab(owners, types, depts),
                    ));
                }
                Some(tabs::devices::DeviceRow::Unmapped(u))
                    if matches!(key.code, KeyCode::Enter) =>
                {
                    let (profiles, groups) = device_form_option_lists(app);
                    let (owners, types, depts) = device_form_label_vocab(app);
                    match promote_form_from(u) {
                        Ok(form) => {
                            app.devices.modal = Some(DeviceModal::Form(
                                form.with_options(profiles, groups)
                                    .with_label_vocab(owners, types, depts),
                            ))
                        }
                        Err(msg) => app.status_err(msg),
                    }
                }
                Some(tabs::devices::DeviceRow::Unmapped(_)) => {
                    app.status_err(
                        "edit (e) only works on mapped rows — press Enter to promote instead"
                            .into(),
                    );
                }
                _ => {
                    app.status_err("no device selected — ↑/↓ to pick one first".into());
                }
            }
        }
        KeyCode::Char('a') => {
            let (profiles, groups) = device_form_option_lists(app);
            let (owners, types, depts) = device_form_label_vocab(app);
            app.devices.modal = Some(DeviceModal::Form(
                DeviceFormState::new_add()
                    .with_options(profiles, groups)
                    .with_label_vocab(owners, types, depts),
            ));
        }
        KeyCode::Char('d') => match selected_row(&rows, current) {
            Some(tabs::devices::DeviceRow::Mapped(m)) => {
                let id =
                    m.id.clone()
                        .filter(|s| !s.is_empty())
                        .or_else(|| crate::cli::commands::target::slug_id(&m.name).ok())
                        .unwrap_or_else(|| m.name.clone());
                app.devices.modal = Some(DeviceModal::DeleteConfirm {
                    id,
                    display_name: m.name.clone(),
                });
            }
            Some(tabs::devices::DeviceRow::Unmapped(_)) => {
                app.status_err("delete (d) only works on mapped rows".into());
            }
            _ => {
                app.status_err("no mapped client selected — ↑/↓ to pick one first".into());
            }
        },
        // No dedicated `p` (Promote) shortcut on this tab — it
        // collided with the global `[p] pause` and the Enter handler
        // above already opens the Promote modal contextually when the
        // focused row is Unmapped. Pressing `p` on Devices now falls
        // through to the global pause toggle, restoring symmetry with
        // every other tab.
        _ => app.leaf_key_unhandled = true,
    }
}

fn selected_row(
    rows: &[tabs::devices::DeviceRow],
    current: Option<usize>,
) -> Option<&tabs::devices::DeviceRow> {
    current.and_then(|i| rows.get(i))
}

// Lists tab — ↑/↓ scroll, Enter toggles drill-down, `p` opens the
// per-list assignment modal, `[K]` direct-toggles kind (BLOCK ↔ ALLOW)
// on the focused list, dispatched through
// `blocklists::run_set_kind_with_ack` so the
// verb stays the sole authority on the write while the TUI owns the
// asking (`toggle_focused_list_kind`). The
// category-grouping ↑/↓ skip + `[c]`/`[m]` modals are gone — the
// Category entity is retired and the Lists tab now renders a flat table.
async fn handle_lists_key(app: &mut App, key: KeyEvent, poller: &IpcPoller, config_path: &Path) {
    // Seed the cursor on the first selectable row so the very first
    // Enter / m / K press lands on a list — without this, an operator
    // who tabs into Lists and presses Enter sees only a footer hint
    // because `focused_list` returns None on a None TableState. Mirrors
    // the Subnets seed pattern at `ensure_subnet_selection_seeded`.
    if app.lists.table_state.selected().is_none() {
        let rows = tabs::lists::build_grouped_rows(app);
        if let Some(idx) = tabs::lists::next_selectable_index(&rows, None, 1) {
            app.lists.table_state.select(Some(idx));
            // Anchor the stable id alongside the visual cursor —
            // `focused_list` resolves the id, not the index.
            app.lists.selected_id = tabs::lists::row_key(&rows[idx]);
        }
    }
    match key.code {
        KeyCode::Down => {
            move_lists_cursor(app, 1);
        }
        KeyCode::Up => {
            move_lists_cursor(app, -1);
        }
        // Jump / page. Same argument as Devices: `is_selectable`,
        // not a loop over the wrapping `next_selectable_index`.
        KeyCode::Home | KeyCode::End | KeyCode::PageUp | KeyCode::PageDown => {
            jump_lists_cursor(app, key.code);
        }
        // Query-Log-style filter card. `/` focuses the text search
        // (seeded with the current committed value so re-pressing edits
        // rather than retypes); `f` cycles the all/block/allow kind chip
        // (`k` was the scroll-up alias, deleted and NOT rebound); `R` clears both.
        KeyCode::Char('/') => {
            app.input_mode =
                InputMode::FilterLists(app.lists.filter_text.clone().unwrap_or_default());
        }
        KeyCode::Char('f') => {
            app.lists.kind_filter = app.lists.kind_filter.next();
            reconcile_lists_selection(app);
        }
        KeyCode::Char('R') => {
            app.lists.filter_text = None;
            app.lists.kind_filter = app::ListsKindFilter::All;
            reconcile_lists_selection(app);
        }
        KeyCode::Enter => {
            // ENTER opens the edit modal in
            // place of the retired drill-down split-pane.
            //
            // Orphan-source promote: when the focused
            // row is a List but has no matching `[[blocklists]]` entry
            // (raw URL or unmapped slug in `[lists].sources`),
            // `build_edit_modal_for` returns None. Fall through to
            // `build_promote_modal_for` which opens the same modal in
            // Promote mode so the operator can promote the orphan to a
            // managed v1 entry (Ctrl+S) or discard it from
            // `[lists].sources` (Tab → Discard → Enter).
            match tabs::lists::build_edit_modal_for(app, config_path) {
                Ok(Some(modal)) => app.lists.edit_modal = Some(modal),
                Ok(None) => {
                    if let Some(modal) = tabs::lists::build_promote_modal_for(app) {
                        app.lists.edit_modal = Some(modal);
                    } else {
                        app.status_err(
                            "focus a list row first (↑/↓) — then Enter opens the editor".into(),
                        );
                    }
                }
                // Unreadable entity file. NOT the Promote fall-through:
                // the entry exists, and offering to create it would be a
                // second wrong thing on top of the first.
                Err(msg) => app.status_err(msg),
            }
        }
        KeyCode::Char('a') => {
            // Open the form modal in Add mode. No focused
            // row required — adding a brand-new list is independent of
            // the cursor position. Operator types id + URL +
            // display_name (+ optional fields) and Ctrl+S persists via
            // the same `run_add` path the Promote flow uses.
            app.lists.edit_modal = Some(tabs::lists::build_add_modal());
        }
        KeyCode::Char('B') => {
            // Open the purge.cc
            // catalog picker. The first open per 5-min TTL fetches both
            // lists.purge.cc and rules.purge.cc; the fetch runs
            // OFF the render loop (it used to await inline here, freezing
            // input for up to ~4s with no feedback). A fresh cache builds
            // the picker synchronously; a stale cache shows a responsive
            // "Loading…" placeholder and fetches on a background task.
            open_catalog_picker(app).await;
        }
        KeyCode::Char('K') => {
            // `[K]` not `[k]`: lowercase `k` was the vim-style scroll-up
            // alias shared by every navigable tab in this TUI. That alias
            // is deleted now, but the toggle stays on `K` anyway — moving
            // a live hotkey costs muscle memory for nothing. Same
            // precedent as `[G] group-by` on Devices: uppercase for
            // actions, lowercase for navigation. The footer hint surfaces
            // `[K] kind` so the case is explicit.
            toggle_focused_list_kind(app, poller, config_path).await;
        }
        _ => app.leaf_key_unhandled = true,
    }
}

/// Step the Lists cursor to the next selectable row (skipping category
/// headers), keeping the stable `selected_id` anchor in step with the
/// visual cursor — `focused_list` resolves the id, not the index, so a
/// cursor move that forgot to re-anchor would leave `Enter` acting on the
/// previously-selected list.
fn move_lists_cursor(app: &mut App, dir: i32) {
    let rows = tabs::lists::build_grouped_rows(app);
    let next = tabs::lists::next_selectable_index(&rows, app.lists.table_state.selected(), dir);
    app.lists.table_state.select(next);
    app.lists.selected_id = next.and_then(|i| tabs::lists::row_key(&rows[i]));
}

/// `Home` / `End` / `PgUp` / `PgDn` for the Lists cursor. Keeps the
/// stable `selected_id` anchor in step with the visual cursor, exactly as
/// [`move_lists_cursor`] does — `focused_list` resolves the id, not the
/// index, so a jump that moved only the cursor would leave `e` / `Enter`
/// acting on the row the operator was standing on before.
fn jump_lists_cursor(app: &mut App, code: KeyCode) {
    let rows = tabs::lists::build_grouped_rows(app);
    let cur = app.lists.table_state.selected();
    let sel = |r: &tabs::lists::ListRowMeta| r.is_selectable();
    let next = match code {
        KeyCode::Home => first_selectable_idx(&rows, sel),
        KeyCode::End => last_selectable_idx(&rows, sel),
        KeyCode::PageDown => page_selectable_idx(&rows, cur, true, sel),
        _ => page_selectable_idx(&rows, cur, false, sel),
    };
    if next.is_some() {
        app.lists.table_state.select(next);
        app.lists.selected_id = next.and_then(|i| tabs::lists::row_key(&rows[i]));
    }
}

/// Open the purge.cc catalog picker without blocking the render
/// loop. A fresh cache builds the picker synchronously; a stale cache
/// opens a "Loading…" placeholder and spawns the two HTTP fetches as a
/// background job whose result (`UiJob::CatalogFetched`) the loop applies
/// on arrival. Falls back to the inline await when no job channel is
/// wired (tests / non-loop callers), preserving the old behaviour there.
async fn open_catalog_picker(app: &mut App) {
    const CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(300);
    let cache_fresh = app
        .catalog_cache
        .as_ref()
        .map(|c| c.fetched_at.elapsed() < CACHE_TTL)
        .unwrap_or(false);
    if cache_fresh {
        let catalog = app.catalog_cache.as_ref().unwrap().catalog.clone();
        let modal = tabs::lists::build_catalog_picker_modal_from(app, &catalog);
        app.lists.catalog_picker = Some(modal);
        return;
    }
    match app.job_tx.clone() {
        Some(tx) => {
            app.lists.catalog_picker = Some(tabs::lists::loading_catalog_picker_modal());
            tokio::spawn(async move {
                let catalog = fetch_catalog().await;
                let _ = tx.send(app::UiJob::CatalogFetched(catalog));
            });
        }
        None => {
            app.lists.catalog_picker =
                Some(tabs::lists::build_catalog_picker_modal_async(app).await);
        }
    }
}

/// Build a reqwest client and fetch the unified purge.cc catalog,
/// falling back to the embedded catalog when the client can't be built.
/// Pure (touches no `App`) so it runs on a spawned task off the UI thread.
async fn fetch_catalog() -> crate::lists::catalog::Catalog {
    use crate::lists::catalog::Catalog;
    match reqwest::Client::builder()
        .user_agent(concat!("purge-warden/", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(client) => Catalog::fetch_unified(&client).await,
        Err(e) => {
            tracing::warn!(error = %e, "could not build reqwest client; using embedded catalog");
            Catalog::fallback()
        }
    }
}

/// Apply a background-job result on the UI thread, then the loop
/// redraws. Keeps every mutation of `App` on the single render thread.
fn apply_job_result(app: &mut App, job: app::UiJob) {
    use backup_restore_modal::{RestoreStage, SubmitOutcome};

    match job {
        app::UiJob::CatalogFetched(catalog) => {
            app.catalog_cache = Some(app::CatalogCache {
                fetched_at: Instant::now(),
                catalog,
            });
            // Rebuild the picker only if it's still open — the operator
            // may have pressed Esc while the fetch was in flight. The
            // rebuild carries their staged ticks across: the fetch is
            // slow enough to toggle rows under, and dropping them would
            // be silent, keystroke-less data loss.
            if let Some(previous) = app.lists.catalog_picker.take() {
                let catalog = app.catalog_cache.as_ref().unwrap().catalog.clone();
                let mut modal = tabs::lists::build_catalog_picker_modal_from(app, &catalog);
                tabs::lists::merge_catalog_picker_state(&mut modal, &previous);
                app.lists.catalog_picker = Some(modal);
            }
        }
        // tui-02: the restore finished. Land it on the card the operator is
        // watching; if that card is somehow gone, fall back to the footer rather
        // than dropping the outcome of a live-config swap on the floor.
        app::UiJob::RestoreFinished(outcome) => match app.settings.restore_modal.as_mut() {
            Some(modal) if matches!(modal.stage, RestoreStage::Restoring { .. }) => {
                modal.stage = RestoreStage::Submitted(outcome);
            }
            _ => match outcome {
                SubmitOutcome::Ok(msg) => app.status_ok(msg),
                SubmitOutcome::Failed(msg) => app.status_err(msg),
            },
        },
        // tui-14: the backup finished — the mirror of the arm above.
        app::UiJob::BackupFinished {
            outcome,
            auto_backup,
        } => {
            match app.settings.backup_modal {
                Some(backup_restore_modal::BackupModal::Running { .. }) => {
                    app.settings.backup_modal = Some(backup_submitted_card(outcome));
                }
                _ => match outcome {
                    SubmitOutcome::Ok(msg) => app.status_ok(msg),
                    SubmitOutcome::Failed(msg) => app.status_err(msg),
                },
            }
            // The refreshed snapshot was taken on the blocking thread after the
            // archive landed, so the "Last auto-backup" line updates
            // immediately, not at the next tab-entry. `None` ⇒ the blocking
            // task died before it could look; keep the view we already have.
            if let Some(view) = auto_backup {
                app.settings.auto_backup = view;
            }
        }
    }
}

/// Run a best-effort, result-free filesystem side effect off the event loop
/// (tui-11).
///
/// The loop is a tokio worker: a synchronous `fs` call inside a key handler
/// stalls rendering, input and signal handling for the whole syscall — and
/// unlike an inline `.await`, it does not even yield the worker to another task.
/// The blocking pool exists for exactly this. Use it for side effects whose
/// result the UI does not need; anything the UI must *react* to goes through
/// `UiJob` / `apply_job_result` instead, so the mutation still happens on the
/// render thread.
///
/// Runs `f` inline when there is no tokio runtime — a direct handler call from
/// a unit test, where there is no event loop to protect and `spawn_blocking`
/// would panic.
fn spawn_fs_side_effect<F: FnOnce() + Send + 'static>(f: F) {
    match tokio::runtime::Handle::try_current() {
        Ok(_) => {
            tokio::task::spawn_blocking(f);
        }
        Err(_) => f(),
    }
}

/// The `K` path's half of the allow-direction decision.
///
/// Split out of [`toggle_focused_list_kind`] so the rule it carries can
/// be asserted without an async runtime and an IPC socket. That rule is
/// the one most likely to be undone by a well-meant optimisation, and
/// until this existed the only thing defending it was three comments —
/// prose does not fail a build.
///
/// It used to read the list's `tags` off the **raw TOML**, never off
/// `app.lists.entries` or `blist.tags`, because the loaded config carries
/// the `uncategorized` the loader synthesised and a pre-check against it
/// passed on exactly the lists that had to fail. The `tags` field is
/// gone, so what survives of that read is the existence probe: an id the
/// running config knows about but no file declares.
///
/// The consent DOES come from the loaded config — nothing synthesises it,
/// so the two agree by construction.
///
/// `Err` is an unreadable entity file, which must NOT be quietly read as
/// "absent": that is the distinction the probe returns a `Result` for.
fn kind_toggle_gate(
    app: &App,
    config_path: &Path,
    list_id: &str,
    trust: crate::config::schema::BlocklistTrust,
) -> Result<AllowGateOutcome, String> {
    match crate::cli::commands::blocklists::blocklist_entry_exists(config_path, list_id, None) {
        Ok(true) => {}
        Ok(false) => {
            return Err(format!(
                "list '{list_id}' is in the running config but not in any config file"
            ))
        }
        Err(e) => return Err(format!("cannot read the config file for '{list_id}': {e}")),
    }
    let consent_in_file = app
        .loaded_config
        .as_ref()
        .and_then(|l| {
            l.config
                .blocklists
                .iter()
                .find(|b| b.id.as_str() == list_id)
        })
        .is_some_and(|b| b.accept_unsigned_allow);
    let gates =
        crate::cli::commands::blocklists::allow_direction_gates(trust, consent_in_file, false);
    Ok(if gates.needs_consent {
        AllowGateOutcome::NeedsConsent
    } else {
        AllowGateOutcome::Proceed
    })
}

/// Toggle BLOCK ↔ ALLOW on the focused list. Refuses (with a toast) when
/// the cursor is on a header or the list has no canonical id.
///
/// `Deny → Allow` runs the two allow-direction gates before committing
/// anything, and reports them in the editor's order rather than the
/// CLI's: a missing tag is a refusal pointing at the editor, a missing
/// consent opens the typed-id notice. `Allow → Deny` asks nothing —
/// withdrawing an exemption carries no risk to price.
///
/// It used to call `run_set_kind` and let the validator's
/// reload-or-rollback path surface the refusal. That was honest and
/// unusable: the operator was told to set a TOML field the interface
/// gave them no way to set.
async fn toggle_focused_list_kind(app: &mut App, poller: &IpcPoller, config_path: &Path) {
    use crate::config::schema::BlocklistBase;
    let Some(meta) = tabs::lists::focused_list(app) else {
        app.status_err(
            "focus a list row first (↑/↓) — then press K to toggle BLOCK ↔ ALLOW".into(),
        );
        return;
    };
    let Some(canonical_id) = meta.canonical_id.clone() else {
        app.status_err(
            "this list has no [[blocklists]] id — kind toggle requires a canonical entry".into(),
        );
        return;
    };
    // Second casualty of the `Block` → `Deny` wire rename: this map used
    // to send `"block"` for the Allow→Deny direction, which `parse_kind`
    // refuses outright ("unknown kind 'block'. Valid: deny, allow"), so
    // `k` could flip a list one way and never back. Flip the variant and
    // let the enum spell its own token.
    let target = match meta.base {
        BlocklistBase::Deny => BlocklistBase::Allow,
        BlocklistBase::Allow => BlocklistBase::Deny,
        // `[K]` is a ONE-WAY exit out of `base = "ignore"`, and deny is
        // the exit it takes. Two alternatives were weighed:
        //
        // - cycling three ways would let one keypress make a list inert
        //   with no gate, which is the silent-inertness this exists to
        //   remove. A 3-state picker with its own affordance would still
        //   need that gate;
        // - refusing outright would tell the operator to go and edit a
        //   TOML field the interface gives them no way to set — the exact
        //   shape of the unsatisfiable refusal this repo already paid for
        //   with the TUI consent gate (CLAUDE.md §Neutrality).
        //
        // So it moves, and it moves toward MORE filtering, never less:
        // deny needs no consent gate, allow does. The toast names the new
        // direction; the way back to `ignore` is the config
        // file or `warden migrate`.
        BlocklistBase::Ignore => BlocklistBase::Deny,
    };
    let trust = meta.trust;

    if target == BlocklistBase::Allow {
        match kind_toggle_gate(app, config_path, &canonical_id, trust) {
            Ok(AllowGateOutcome::Proceed) => {}
            Ok(AllowGateOutcome::NeedsConsent) => {
                app.lists.kind_confirm = Some(app::KindConfirm {
                    list_id: canonical_id,
                    typed: String::new(),
                    error: None,
                });
                return;
            }
            Err(msg) => {
                app.status_err(msg);
                return;
            }
        }
    }

    apply_kind_change(app, poller, config_path, &canonical_id, target, false).await;
}

/// Commit a direction change through the verb, and report it.
///
/// Split out because the `K` path reaches it twice — directly when no
/// consent is needed, and again from the notice once the operator has
/// typed the id. `accept_unsigned_allow` is the consent this invocation
/// carries; the verb re-runs both gates against the file regardless, so
/// this cannot talk it into a write the CLI would refuse.
async fn apply_kind_change(
    app: &mut App,
    poller: &IpcPoller,
    config_path: &Path,
    list_id: &str,
    target: crate::config::schema::BlocklistBase,
    accept_unsigned_allow: bool,
) {
    let new_kind = target.wire_str();
    match crate::cli::commands::blocklists::run_set_kind_with_ack(
        config_path,
        poller.socket_path(),
        list_id,
        new_kind,
        accept_unsigned_allow,
        None,
    )
    .await
    {
        Ok(()) => {
            // Was `status_err` — success painted red, with the `✕`
            // glyph, left over from the `last_error` → `last_status`
            // migration where both outcomes shared one red footer.
            app.status_ok(if accept_unsigned_allow {
                tabs::lists::format_list_allow_consent_saved(list_id)
            } else {
                tabs::lists::format_kind_toggle_ok(list_id, target)
            });
            app.loaded_config = load_v1_config(config_path);
            poll_active_leaf(app, poller).await;
        }
        Err(e) => {
            app.status_err(format!("kind toggle refused: {e}"));
        }
    }
}

/// Keys for the `K`-hotkey consent notice. Same gate as the editor's
/// stage, same strings; the difference is only where the accepted
/// decision goes — straight to the verb, since there is no form holding
/// pending edits.
async fn handle_kind_confirm_key(
    app: &mut App,
    key: KeyEvent,
    poller: &IpcPoller,
    config_path: &Path,
) {
    let Some(mut confirm) = app.lists.kind_confirm.take() else {
        return;
    };
    match key.code {
        KeyCode::Esc => {}
        KeyCode::Backspace => {
            confirm.typed.pop();
            confirm.error = None;
            app.lists.kind_confirm = Some(confirm);
        }
        KeyCode::Char(c) => {
            confirm.typed.push(c);
            confirm.error = None;
            app.lists.kind_confirm = Some(confirm);
        }
        KeyCode::Enter => {
            if confirm.typed != confirm.list_id {
                confirm.error = Some(tabs::lists::UNSIGNED_ALLOW_CONFIRM_MISMATCH.to_string());
                app.lists.kind_confirm = Some(confirm);
                return;
            }
            let list_id = confirm.list_id.clone();
            apply_kind_change(
                app,
                poller,
                config_path,
                &list_id,
                crate::config::schema::BlocklistBase::Allow,
                true,
            )
            .await;
        }
        _ => {
            app.lists.kind_confirm = Some(confirm);
        }
    }
}

// Rules tab — ↑/↓ scroll the populated table (filtered
// by the chip), `f` cycles the filter chip, `Enter` opens the edit
// modal on the focused row, `d` short-circuits straight to the
// delete-confirm screen.
/// Re-anchor the stable rule id from the cursor position after a ↑/↓
/// move, so the anchor tracks the operator's intent. Mirrors
/// `sync_query_log_selection`; the modal openers resolve the id, not the
/// index.
fn sync_rules_selection(app: &mut App) {
    let rows = tabs::rules::visible_rule_rows(app);
    app.rules.selected_id = app
        .rules
        .table_state
        .selected()
        .and_then(|i| rows.get(i))
        .map(|r| r.id.clone());
}

fn handle_rules_key(app: &mut App, key: KeyEvent) {
    let visible_len = visible_rule_rows_count(app);
    match key.code {
        KeyCode::Down => {
            scroll_table_down(&mut app.rules.table_state, visible_len);
            sync_rules_selection(app);
        }
        KeyCode::Up => {
            scroll_table_up(&mut app.rules.table_state);
            sync_rules_selection(app);
        }
        // Jump / page.
        KeyCode::Home => {
            jump_table_home(&mut app.rules.table_state, visible_len);
            sync_rules_selection(app);
        }
        KeyCode::End => {
            jump_table_end(&mut app.rules.table_state, visible_len);
            sync_rules_selection(app);
        }
        KeyCode::PageDown => {
            page_table_down(&mut app.rules.table_state, visible_len);
            sync_rules_selection(app);
        }
        KeyCode::PageUp => {
            page_table_up(&mut app.rules.table_state);
            sync_rules_selection(app);
        }
        KeyCode::Char('f') => {
            app.rules.filter = app.rules.filter.next();
            reconcile_rules_selection(app);
        }
        // Query-Log-style text search, combined (AND) with the chip.
        // `/` focuses (seeded with the current value); `R` clears both
        // the search text and the action chip.
        KeyCode::Char('/') => {
            app.input_mode =
                InputMode::FilterRules(app.rules.filter_text.clone().unwrap_or_default());
        }
        KeyCode::Char('R') => {
            app.rules.filter_text = None;
            app.rules.filter = app::RulesFilter::All;
            reconcile_rules_selection(app);
        }
        KeyCode::Enter => {
            if let Some(modal) = tabs::rules::build_rule_edit_modal_for(app) {
                app.rules.edit_modal = Some(modal);
            } else {
                app.status_err("focus a rule row first (↑/↓) — then Enter opens the editor".into());
            }
        }
        KeyCode::Char('d') | KeyCode::Delete => {
            // Shortcut: open the modal AND immediately swap to the
            // delete-confirm screen so the operator skips the form.
            if let Some(mut modal) = tabs::rules::build_rule_edit_modal_for(app) {
                modal.mode = app::RuleEditMode::ConfirmDelete {
                    typed: String::new(),
                };
                app.rules.edit_modal = Some(modal);
            } else {
                app.status_err(
                    "focus a rule row first (↑/↓) — then [d] opens delete confirm".into(),
                );
            }
        }
        // `[a]` opens the add-rule modal — no row
        // focus needed (unlike `Enter`/`d` above, which edit/delete the
        // row under the cursor). Blocked while another Rules modal is
        // already open; the top-level gates route keys away from this
        // fn in that case, so `edit_modal` is always `None` here.
        KeyCode::Char('a') => {
            app.rules.add_modal = Some(rule_add_modal::RuleAddModal::open(app));
        }
        _ => app.leaf_key_unhandled = true,
    }
}

/// Count of rule rows currently visible (post-filter). Used by the
/// ↑/↓ handlers so cursor scroll stops at the visible bottom.
fn visible_rule_rows_count(app: &App) -> usize {
    tabs::rules::visible_rule_rows(app).len()
}

/// Reconcile the active tab's selection with the rows that are
/// about to be painted. Called once per frame, immediately before the
/// draw.
///
/// **Why here, and not on the data-mutation paths.** These row sets are
/// *derived*. The Lists rows come from an IPC poll written at two sites —
/// one of them the *Dashboard's* poll arm, so they can move while the
/// operator is looking at another tab — and the Rules rows are rebuilt
/// from `loaded_config`, which a dozen call sites rewrite (this tab's own
/// delete, `r`, the post-`$EDITOR` reload, …). Hooking every producer is
/// whack-a-mole: the next reload site somebody adds silently reintroduces
/// the bug. Reconciling at the one point where the rows are *consumed* is
/// correct for every producer, including producers that don't exist yet.
///
/// **Why not in the renderer.** `ui::render` takes `&App`, so a fallback
/// computed there can only be written to a throwaway local `TableState` —
/// which is precisely how Profiles/Subnets came to highlight row 0 in the
/// master while the detail card, re-reading the same dead id, painted its
/// empty "select a profile" stub. The write-back needs a `&mut App`, and
/// this is the last one before the frame.
///
/// Every mutation path sets `dirty`, so this runs after any data change
/// and before the operator can see — or act on — the new rows.
fn reconcile_active_leaf_selection(app: &mut App) {
    match app.active_leaf {
        Leaf::Lists => reconcile_lists_selection(app),
        Leaf::Rules => reconcile_rules_selection(app),
        // Already identity-keyed and re-resolved every frame; they only
        // need the dangling-id repair so the master's row-0 fallback and
        // the detail card agree on which row is selected.
        Leaf::Profiles => ensure_profile_selection_seeded(app),
        Leaf::Subnets => ensure_subnet_selection_seeded(app),
        // Same contract: the renderer falls back to row 0,
        // so the anchor must agree before the operator can act on it.
        Leaf::Labels => ensure_labels_selection_seeded(app),
        // Same contract: the renderer falls back to row 0, so the anchor
        // must agree before the operator can act on it.
        Leaf::CustomLists => {
            ensure_custom_list_selection_seeded(app);
            // The rule pane follows the list cursor without a keystroke,
            // so the load belongs on the render reconcile rather than on a
            // key: entering the leaf already has to show the file.
            refresh_custom_list_pack(app, false);
        }
        _ => {}
    }
}

/// Reconcile the Rules cursor with the current visible row set.
///
/// Anchors on the operator's stable rule id and re-resolves it to an
/// index, so the highlight follows the rule they chose even when rows
/// above it disappear. A clamp cannot do that: when a rule above the
/// cursor is deleted the index stays *in range* and quietly addresses a
/// different rule, so `Enter` would edit — and `d` would delete — the
/// wrong one.
///
/// When the id no longer resolves, the rule itself is gone: degrade to
/// the old slot clamped into range and re-anchor the id to the row we
/// land on, so the cursor stays live and keeps telling the truth.
/// Shared by the `f` chip-cycle, the `/` search commit and `R` clear —
/// each of which can also shrink the visible set under the cursor.
fn reconcile_rules_selection(app: &mut App) {
    // Nothing focused and nothing anchored — the operator has not touched
    // this tab yet. Leave it alone: auto-selecting a row here would change
    // the tab-entry behaviour (the first ↑/↓ is what seeds the cursor).
    if app.rules.selected_id.is_none() && app.rules.table_state.selected().is_none() {
        return;
    }

    let rows = tabs::rules::visible_rule_rows(app);
    if let Some(idx) =
        crate::tui::app::resolve_row_index(&rows, app.rules.selected_id.as_ref(), |r| {
            Some(r.id.clone())
        })
    {
        app.rules.table_state.select(Some(idx));
        return;
    }

    let Some(last) = rows.len().checked_sub(1) else {
        app.rules.table_state.select(None);
        app.rules.selected_id = None;
        return;
    };
    let idx = app.rules.table_state.selected().unwrap_or(0).min(last);
    app.rules.table_state.select(Some(idx));
    app.rules.selected_id = Some(rows[idx].id.clone());
}

/// Reconcile the Lists cursor with the current visible row set.
///
/// Same contract as [`reconcile_rules_selection`], with one extra care:
/// the grouped vec interleaves non-selectable category headers, so the
/// degrade path walks to the nearest *selectable* row rather than
/// clamping to a raw index that might land on a header.
///
/// The trigger here needs no keypress at all — `app.lists.entries` is
/// rewritten by a 30 s poll, so a blocklist removed by an external
/// `warden list remove` (or by a config reload, or by this tab's own
/// delete) shrinks the row set while the operator sits perfectly still.
fn reconcile_lists_selection(app: &mut App) {
    if app.lists.selected_id.is_none() && app.lists.table_state.selected().is_none() {
        return;
    }

    let rows = tabs::lists::build_grouped_rows(app);
    if let Some(idx) = crate::tui::app::resolve_row_index(
        &rows,
        app.lists.selected_id.as_ref(),
        tabs::lists::row_key,
    ) {
        app.lists.table_state.select(Some(idx));
        return;
    }

    // The list is gone (or nothing was anchored yet). Clamp the old slot
    // into range, keep it if it still holds a live list row, and otherwise
    // walk back to the nearest selectable one — `next_selectable_index`
    // never inspects its own start index, so the `filter` below is what
    // lets a deleted *last* row leave the cursor on the new last row
    // rather than skipping one further back.
    let clamped = app
        .lists
        .table_state
        .selected()
        .map(|i| i.min(rows.len().saturating_sub(1)));
    let landing = clamped
        .filter(|i| rows.get(*i).is_some_and(|r| r.is_selectable()))
        .or_else(|| tabs::lists::next_selectable_index(&rows, clamped, -1));
    match landing {
        Some(idx) => {
            app.lists.table_state.select(Some(idx));
            app.lists.selected_id = tabs::lists::row_key(&rows[idx]);
        }
        None => {
            app.lists.table_state.select(None);
            app.lists.selected_id = None;
        }
    }
}

/// Clamp the Query-Log cursor after a fetch — if the selected row fell
/// out of the now-shorter entry set (a text/blocked filter narrowed the
/// server-side result, or the periodic poll returned fewer rows), snap
/// back to the last row, or clear the selection when the log is empty.
/// The Query-Log filter is applied server-side, so the only place
/// `entries` changes is the fetch result — clamp there. Without this the
/// cursor silently points past the end and the rule picker
/// (`build_query_log_rule_modal`) reads `None`, so Enter becomes a
/// no-op on a row the operator can still see highlighted.
///
/// Lists and Rules are not safe merely because their client-side filters
/// are "clamped on the filter keypress" — their row sets change on a
/// *data refresh* too, no keypress involved. Both now
/// re-resolve a stable id before every draw (`reconcile_lists_selection`,
/// `reconcile_rules_selection`); anchoring beats clamping, because a clamp
/// still lets an in-range index drift onto a *different* entity. The
/// Query-Log pairs this clamp with its own anchor (`anchor_query_log_cursor`),
/// so it is covered on both halves.
/// Fold one successful Query Log poll into the tab state.
///
/// **Extracted from the poll arm so it is reachable from a test.** All
/// three branches below are behavioural decisions about cursor validity,
/// and a test that re-implements them inline asserts on its own copy: it
/// stays green when the branch is deleted from the caller, which makes it
/// a comment with an `assert!` around it. Reaching the arm in situ needs
/// a live daemon; reaching this function needs a `QueryLogPollResult`.
fn apply_query_log_page(app: &mut App, result: crate::tui::ipc_poller::QueryLogPollResult) {
    app.query_log.logging_enabled = result.logging_enabled;
    app.query_log.file_state = result.file_state;
    if result.cursor_stale {
        // The file the cursor named rotated under it. The daemon served
        // the live tail rather than whatever now sits at that offset, so
        // the view really is page 0 and the stack must agree.
        app.query_log.reset_paging();
        app.status_info(QUERY_LOG_CURSOR_STALE.to_string());
        app.query_log.entries = result.entries;
        app.query_log.next_cursor = result.next_cursor;
        clamp_query_log_cursor(app);
    } else if result.entries.is_empty() && app.query_log.page_index > 0 {
        // A cursor is minted whenever a page fills, so the last page of a
        // log whose size is an exact multiple of the limit hands back one
        // that yields nothing. Step back rather than blank the table:
        // `entries` still holds the page the operator was reading, and
        // dropping the dead cursor makes `PgDn` refuse instead of
        // offering the same empty page again.
        app.query_log
            .page_cursors
            .truncate(app.query_log.page_index + 1);
        app.query_log.page_newer();
        app.query_log.next_cursor = None;
        app.status_info(QUERY_LOG_OLDEST.to_string());
    } else {
        // On the live tail, DROP every stored cursor. Page 0's boundary
        // moves on every append, so a cursor minted against an older
        // boundary now names a position with freshly-written rows above
        // it: paging down would silently skip them. Same reasoning as the
        // filter reset — a cursor is only valid against the boundary that
        // produced it — except the invalidating event is the log growing
        // rather than the operator typing.
        if app.query_log.page_index == 0 {
            app.query_log.page_cursors.truncate(1);
        }
        app.query_log.entries = result.entries;
        app.query_log.next_cursor = result.next_cursor;
        clamp_query_log_cursor(app);
    }
}

fn clamp_query_log_cursor(app: &mut App) {
    let len = app.query_log.entries.len();
    match app.query_log.table_state.selected() {
        Some(_) if len == 0 => app.query_log.table_state.select(None),
        Some(idx) if idx >= len => app.query_log.table_state.select(Some(len - 1)),
        _ => {}
    }
}

/// Drive the Rules-tab edit modal state machine.
///
/// Routes by `mode`: `Edit` handles Tab cycling + arrow-key picker
/// changes on Action/Scope + `Ctrl+S` submit + `Enter` on Delete
/// (swap to `ConfirmDelete`); `ConfirmDelete` handles char + backspace
/// edits + `Enter` (typed-id confirm). `Esc` from either mode aborts
/// back one level.
async fn handle_rules_edit_modal_key(
    app: &mut App,
    key: KeyEvent,
    poller: &IpcPoller,
    config_path: &Path,
) {
    let Some(mut modal) = app.rules.edit_modal.take() else {
        return;
    };
    if modal.submitting && !matches!(key.code, KeyCode::Esc) {
        // Block re-entrant submits — only Esc escapes the in-flight
        // state. Mirrors the list-edit-modal pattern.
        app.rules.edit_modal = Some(modal);
        return;
    }
    match modal.mode.clone() {
        app::RuleEditMode::Edit => {
            handle_rule_edit_form_key(app, &mut modal, key, poller, config_path).await
        }
        app::RuleEditMode::ConfirmDelete { typed } => {
            handle_rule_delete_confirm_key(app, &mut modal, typed, key, poller, config_path).await
        }
    }
}

async fn handle_rule_edit_form_key(
    app: &mut App,
    modal: &mut app::RuleEditModal,
    key: KeyEvent,
    poller: &IpcPoller,
    config_path: &Path,
) {
    use crate::filter::rules::RuleAction;
    use app::RuleEditFocus;

    // Ctrl+S → submit before any other dispatch.
    if matches!(key.code, KeyCode::Char('s') | KeyCode::Char('S'))
        && key.modifiers.contains(KeyModifiers::CONTROL)
    {
        submit_rule_edit_modal(app, modal.clone(), poller, config_path).await;
        return;
    }

    match key.code {
        KeyCode::Esc => {
            app.rules.edit_modal = None;
            return;
        }
        // Down/Up alias Tab/BackTab so focus moves
        // with the arrows here exactly as it already did in the Subnets /
        // Profiles / Local DNS / Devices forms. Tab and BackTab keep
        // working — this is an addition, not a swap, so the old muscle
        // memory survives.
        KeyCode::Tab | KeyCode::Down => {
            modal.focus = modal.focus.next();
            modal.error_message = None;
        }
        KeyCode::BackTab | KeyCode::Up => {
            modal.focus = modal.focus.prev();
            modal.error_message = None;
        }
        // Value-cycling vacates Up/Down for Left/Right — the same house
        // convention the four conformant forms already use. Left/Right
        // were unbound in this handler, so nothing collides. `RuleEditFocus`
        // carries no text field (Action / Scope / DeleteButton only), so
        // there is no intra-field cursor for the arrows to compete with.
        KeyCode::Left | KeyCode::Right => match modal.focus {
            RuleEditFocus::Action => {
                modal.current_action = match modal.current_action {
                    RuleAction::Block => RuleAction::Allow,
                    RuleAction::Allow => RuleAction::Block,
                };
                modal.error_message = None;
            }
            RuleEditFocus::Scope => {
                let dir = if matches!(key.code, KeyCode::Right) {
                    1
                } else {
                    -1
                };
                tabs::rules::cycle_scope_choice(modal, dir);
            }
            RuleEditFocus::DeleteButton | RuleEditFocus::SaveButton => {}
        },
        KeyCode::Enter if modal.focus == RuleEditFocus::DeleteButton => {
            modal.mode = app::RuleEditMode::ConfirmDelete {
                typed: String::new(),
            };
            modal.error_message = None;
            modal.status_message = None;
        }
        // Save is Tab-reachable — Enter on it takes
        // the same path as Ctrl+S. Ctrl+S-from-anywhere is
        // untouched above; this is an addition, not a replacement.
        KeyCode::Enter if modal.focus == RuleEditFocus::SaveButton => {
            submit_rule_edit_modal(app, modal.clone(), poller, config_path).await;
            return;
        }
        _ => {}
    }
    app.rules.edit_modal = Some(modal.clone());
}

async fn handle_rule_delete_confirm_key(
    app: &mut app::App,
    modal: &mut app::RuleEditModal,
    mut typed: String,
    key: KeyEvent,
    poller: &IpcPoller,
    config_path: &Path,
) {
    match key.code {
        KeyCode::Esc => {
            // Back to edit mode — no destructive op.
            modal.mode = app::RuleEditMode::Edit;
            modal.error_message = None;
            app.rules.edit_modal = Some(modal.clone());
        }
        KeyCode::Backspace => {
            typed.pop();
            modal.error_message = None;
            modal.mode = app::RuleEditMode::ConfirmDelete { typed };
            app.rules.edit_modal = Some(modal.clone());
        }
        KeyCode::Char(c) => {
            typed.push(c);
            modal.error_message = None;
            modal.mode = app::RuleEditMode::ConfirmDelete { typed };
            app.rules.edit_modal = Some(modal.clone());
        }
        KeyCode::Enter => {
            if typed != modal.rule_id {
                modal.mode = app::RuleEditMode::Edit;
                modal.error_message = Some(format!(
                    "typed '{typed}' \u{2260} '{}' — delete aborted",
                    modal.rule_id
                ));
                app.rules.edit_modal = Some(modal.clone());
                return;
            }
            modal.submitting = true;
            modal.status_message = Some("removing\u{2026}".into());
            app.rules.edit_modal = Some(modal.clone());
            let result = crate::cli::commands::rules::remove_admin_rule_by_id(
                config_path,
                poller.socket_path(),
                &modal.rule_id,
            )
            .await;
            match result {
                Ok(_) => {
                    app.rules.edit_modal = None;
                    app.status_ok(format!("rule '{}' deleted", modal.rule_id));
                    app.loaded_config = load_v1_config(config_path);
                    poll_active_leaf(app, poller).await;
                }
                Err(e) => {
                    if let Some(m) = app.rules.edit_modal.as_mut() {
                        m.submitting = false;
                        m.status_message = None;
                        m.mode = app::RuleEditMode::Edit;
                        m.error_message = Some(format!("delete failed: {e}"));
                    }
                }
            }
        }
        _ => {
            app.rules.edit_modal = Some(modal.clone());
        }
    }
}

/// Submit the Edit-mode form: diff (action, scope) against the
/// originals and call `move_admin_rule`. No-op closes the modal
/// silently; success closes + posts a footer hint; failure keeps the
/// modal open with the error.
async fn submit_rule_edit_modal(
    app: &mut App,
    mut modal: app::RuleEditModal,
    poller: &IpcPoller,
    config_path: &Path,
) {
    use crate::cli::commands::rules::Action as CliAction;
    use crate::cli::commands::rules::{move_admin_rule, MoveOutcome, Scope};
    use crate::filter::rules::RuleAction;

    modal.submitting = true;
    modal.error_message = None;
    modal.status_message = Some("saving\u{2026}".into());
    app.rules.edit_modal = Some(modal.clone());

    let to_cli_action = |a: RuleAction| match a {
        RuleAction::Allow => CliAction::Allow,
        RuleAction::Block => CliAction::Deny,
    };
    let old_action = to_cli_action(modal.original_action);
    let new_action = to_cli_action(modal.current_action);

    // Resolve the original scope in a single match that borrows `modal`
    // directly. Orphan rules can't be edited — short-circuit here so
    // there is exactly one match over `original_scope` and no second,
    // refactor-fragile `unreachable!` arm. (`&modal.rule_id` is already
    // borrowed across the await below, so borrowing `original_scope` for
    // `old_scope` too is consistent.)
    let old_scope = match &modal.original_scope {
        app::RuleScope::Default => Scope::Default,
        app::RuleScope::Profile(id) => Scope::Profile(id.as_str()),
        app::RuleScope::Device(id) => Scope::Device(id.as_str()),
        app::RuleScope::Orphan => {
            if let Some(m) = app.rules.edit_modal.as_mut() {
                m.submitting = false;
                m.status_message = None;
                m.error_message = Some("cannot edit an orphan rule — delete it instead".into());
            }
            return;
        }
    };
    let new_scope_id: String = match &modal.current_scope_choice {
        app::ScopeChoice::Default => String::new(),
        app::ScopeChoice::Profile(id) => id.clone(),
        app::ScopeChoice::Device(id) => id.clone(),
    };
    let new_scope = match &modal.current_scope_choice {
        app::ScopeChoice::Default => Scope::Default,
        app::ScopeChoice::Profile(_) => Scope::Profile(new_scope_id.as_str()),
        app::ScopeChoice::Device(_) => Scope::Device(new_scope_id.as_str()),
    };

    let outcome = move_admin_rule(
        config_path,
        poller.socket_path(),
        &modal.rule_id,
        old_scope,
        old_action,
        new_scope,
        new_action,
    )
    .await;

    match outcome {
        Ok(MoveOutcome::NoOp) => {
            app.rules.edit_modal = None;
            app.status_info(format!("rule '{}' unchanged", modal.rule_id));
        }
        Ok(MoveOutcome::Applied {
            master_rewritten, ..
        }) => {
            app.rules.edit_modal = None;
            app.status_ok(format!(
                "rule '{}' updated{}",
                modal.rule_id,
                if master_rewritten {
                    " (action flipped)"
                } else {
                    ""
                }
            ));
            app.loaded_config = load_v1_config(config_path);
            poll_active_leaf(app, poller).await;
        }
        Err(e) => {
            if let Some(m) = app.rules.edit_modal.as_mut() {
                m.submitting = false;
                m.status_message = None;
                m.error_message = Some(format!("save failed: {e}"));
            }
        }
    }
}

// The Tags-tab handlers that once stood here — the table
// keys, the filter chip, the `/` search, and the six modals (Members,
// Check, Declare, Describe, Rename, Delete) — are gone along with the
// `Leaf::Tags` tab itself. The CRUD surface administered the implicit
// tag registry, and after the per-list-policy cutover a tag decides
// nothing, so there was nothing left for it to administer.

/// `/` search buffer. Sync (unlike the Create/Rename/
/// Delete siblings) — there's no IPC round-trip, just a text commit.
/// Enter commits `buf` into `TagsState::filter_text` (trimmed, `None`
/// if empty) and reconciles the cursor against the new filtered view;
/// Esc discards the buffer and leaves `filter_text` untouched.
async fn handle_settings_key(app: &mut App, key: KeyEvent, poller: &IpcPoller, config_path: &Path) {
    // When the Tracking form is active, route keys to the
    // form handler FIRST and only fall through when it returns "pass
    // through" (currently never — the form owns its keys).
    if app.settings.tracking_panel.is_some() {
        handle_tracking_panel_key(app, key, poller).await;
        return;
    }

    match key.code {
        KeyCode::Char('t') => {
            // Enter the Tracking form. Load the current
            // tracking config fresh from disk so a prior `e`-edit is
            // picked up; fall back to a default TrackingConfig when
            // the loader fails (operator can still make edits; submit
            // will surface the real load error from the daemon).
            let tracking = load_v1_config(config_path)
                .map(|lc| lc.config.tracking.clone())
                .unwrap_or_default();
            app.settings.tracking_panel =
                Some(crate::tui::app::TrackingPanelState::from_config(&tracking));
        }
        KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            match poller.send_reload().await {
                Ok(msg) => app.status_ok(format!("reload: {msg}")),
                Err(e) => app.status_err(format!("reload failed: {e}")),
            }
        }
        KeyCode::Char('b') => {
            // Open the backup confirm modal. The actual backup runs in
            // `handle_backup_modal_key` on `y`, so a stray `b` keystroke
            // no longer writes an archive without acknowledgement. The
            // result lands in a styled modal card (green/red via
            // `T.success`/`T.error`) instead of the red `last_error`
            // footer that swallowed the success styling before.
            let dir = crate::cli::commands::config::resolved_backup_dir(config_path);
            app.settings.backup_modal = Some(backup_restore_modal::BackupModal::Confirm { dir });
        }
        KeyCode::Char('R') => {
            // Open the restore picker. No backups → footer hint instead
            // of an empty modal.
            match backup_restore_modal::RestoreModal::from_config(config_path) {
                Some(modal) => app.settings.restore_modal = Some(modal),
                None => {
                    let dir = crate::cli::commands::config::resolved_backup_dir(config_path);
                    app.status_err(format!("no backups in {}", dir.display()));
                }
            }
        }
        _ => app.leaf_key_unhandled = true,
    }
}

/// Move the Labels entries cursor. **Clamps**: `%` used to teleport
/// the operator from the last label to the first.
///
/// Extracted from the `↑`/`↓` arm so the jump and page keys share one
/// definition of "where the cursor may land" — two copies of index maths is
/// how one of them keeps a `%` nobody notices.
fn step_labels_entry(app: &mut App, code: KeyCode) {
    let ids = labels_ids_of_kind(app, app.labels.selected_kind);
    if ids.is_empty() {
        return;
    }
    let last = ids.len() - 1;
    let cur = app
        .labels
        .selected_id
        .as_deref()
        .and_then(|want| ids.iter().position(|i| i == want))
        .unwrap_or(0);
    let next = match code {
        KeyCode::Down => (cur + 1).min(last),
        KeyCode::Up => cur.saturating_sub(1),
        KeyCode::Home => 0,
        KeyCode::End => last,
        KeyCode::PageDown => (cur + NAV_PAGE).min(last),
        KeyCode::PageUp => cur.saturating_sub(NAV_PAGE),
        _ => return,
    };
    app.labels.selected_id = Some(ids[next].clone());
}

/// Force the Labels focus onto a pane the layout actually paints.
///
/// Below `tabs::labels::NARROW_THRESHOLD` the leaf collapses to the
/// entry table alone, so a `KindMenu` focus is unhonourable: `↑`/`↓`
/// would swap the whole table's contents while the operator, seeing only
/// a table, expects its rows to move. At the minimum-terminal floor of
/// 80×24 that is the *default* state, not an edge case.
///
/// Clamped in state rather than derived at draw time so the **key
/// handler** is correct too — it has no idea how wide the terminal is,
/// and a renderer-only fix would leave the keys behaving as if a menu
/// nobody can see still had the cursor.
///
/// Runs in the render loop because that is the only place the viewport
/// width is known. Widening the terminal again does not restore the
/// previous focus: `←` does, and inventing a remembered focus would be
/// state nobody asked for.
fn clamp_labels_focus_to_layout(app: &mut App, viewport_width: u16) {
    if app.active_leaf != Leaf::Labels {
        return;
    }
    // Record it as well as act on it. The key handler has no viewport
    // width and this is the only place that does; see
    // `LabelsState::menu_painted` for what went wrong when the handler
    // was left to assume two panes on a one-pane screen.
    let painted = crate::tui::tabs::labels::menu_is_painted(viewport_width);
    app.labels.menu_painted = painted;
    if !painted {
        app.labels.focus = LabelsFocus::Entries;
    }
}

/// Step the focused vocabulary one place, and re-anchor the row.
///
/// Extracted so the two callers cannot drift: `↑`/`↓` drive it when the
/// kind menu has focus, and `←`/`→` drive it when the menu is not painted
/// at all and there is no focus to move. A second copy would be a second
/// place for the tag filter or the re-seed to be forgotten.
fn cycle_labels_kind(app: &mut App, forward: bool) {
    // The menu's own list — never `LabelKind::ALL`, which still carries
    // `Tag`. Cycling into a kind the menu does not paint would blank the
    // highlight and empty the table with nothing on screen to explain it.
    let kinds = crate::tui::tabs::labels::menu_kinds();
    if kinds.is_empty() {
        return;
    }
    let cur = kinds
        .iter()
        .position(|k| *k == app.labels.selected_kind)
        .unwrap_or(0);
    let next = if forward {
        (cur + 1) % kinds.len()
    } else {
        (cur + kinds.len() - 1) % kinds.len()
    };
    app.labels.selected_kind = kinds[next];
    // An id from the previous vocabulary means nothing here; re-seed
    // rather than leave the gap open.
    app.labels.selected_id = None;
    ensure_labels_selection_seeded(app);
}

/// The ids of every label of `kind`, in config order.
///
/// Returns owned `String`s deliberately: the caller mutates `app.labels`
/// straight afterwards, and handing back a borrow of `app.loaded_config`
/// would keep the immutable borrow alive across that write.
fn labels_ids_of_kind(app: &App, kind: crate::config::schema::LabelKind) -> Vec<String> {
    app.loaded_config
        .as_ref()
        .map(|l| {
            l.config
                .labels
                .iter()
                .filter(|x| x.kind == kind)
                .map(|x| x.id.as_str().to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// Seed `app.labels.selected_id` to the first entry of the focused kind
/// when it is unset — or repair it when it points at a label that the
/// current kind does not contain.
///
/// The desync this closes is the one
/// [`ensure_subnet_selection_seeded`] was written for: the renderer
/// falls back to highlighting row 0 when the anchor is `None`
/// (`tabs/labels.rs`, `state.select(Some(0))`), so the operator sees a
/// cursor while the state says `None`. Load-bearing now that the leaf
/// has CRUD: an opener reading `selected_id` would no-op
/// on exactly the row the operator can see is selected.
///
/// Called on every keystroke *and* on leaf entry, and again right after
/// a kind change: the kind change clears the anchor by design (an id
/// from one vocabulary means nothing in another), which would otherwise
/// re-open the same gap for one frame.
fn ensure_labels_selection_seeded(app: &mut App) {
    // **"No config" is not "a config with no labels".** The guard lives
    // here rather than only in the key handler because this function has
    // three callers, and the one that matters is not a keystroke:
    // `reconcile_active_leaf_selection` runs on *every dirty render*. A
    // failed load would otherwise find zero labels, write `None`, and
    // discard the operator's place without anyone pressing a key —
    // guarding the handler alone would have been cosmetic.
    if app.loaded_config.is_none() {
        return;
    }
    let ids = labels_ids_of_kind(app, app.labels.selected_kind);
    if let Some(want) = app.labels.selected_id.as_deref() {
        if ids.iter().any(|i| i == want) {
            return;
        }
    }
    // `None` when the kind is empty — the table has no row to anchor.
    app.labels.selected_id = ids.into_iter().next();
}

/// Labels navigation on the axis the
/// leaf is drawn, plus `a` / `e` / `d` to author the vocabulary.
///
/// **This leaf shipped as a view first, and that was never the design.**
/// Groups' read-only phase was *structural* — its handler took neither
/// `config_path` nor `IpcPoller`, so a write could not arrive unannounced.
/// Labels never had that bar: writing was inside the leaf's own scope and
/// simply did not land at first. This signature stays `(&mut App, KeyEvent)` for
/// the same reason Groups' did: the openers only need the app, and every
/// write lives in `handle_label_modal_key` / `submit_label_modal`, which
/// take both.
///
/// **The axis was the defect, not the key names.** `←`/`→` already
/// worked, aliased to `h`/`l` — but they *cycled the kind menu*, which is
/// painted as stacked rows, one per kind. A vertical list walked by a horizontal
/// key is what an operator reported as "VIM navigation"; `h`/`l` was the
/// only such pair in the TUI. Now the horizontal keys move between the
/// two cards and the vertical keys move inside the focused one, which is
/// how the leaf looks.
///
/// **`←`/`→` are absolute, not toggles.** `Left` always means the left
/// card, which is what the operator sees. That is also what makes an
/// omitted arm detectable: with a two-variant focus, toggling keys are
/// behaviourally identical, so no test could distinguish a missing
/// `Left` arm from a present one — nor a build with the `Left` and
/// `Right` bodies swapped. Verified by mutation, both ways.
///
/// **`Tab` is deliberately NOT bound here.** It stays the global leaf
/// cycle; see the arm in `handle_key` for why the shadow was built and
/// then reverted.
///
/// **`h`/`l` were remapped once and then DELETED.** The paragraph above
/// is kept because it is the
/// argument, not the state: they used to cycle the kind, then that
/// job moved to `↑`/`↓` while the menu has focus, and the two could not both
/// hold. The four vim aliases were then removed TUI-wide — bound but
/// undocumented is the one state that is wrong in both directions. The
/// arrows are unchanged; `h`/`l`/`j`/`k` are unbound here and are
/// deliberately NOT rebound. Pinned by
/// `ux8_h_and_l_are_no_longer_bound_on_labels`.
fn handle_labels_key(app: &mut App, key: KeyEvent) {
    // The guard comes FIRST. Seeding against a failed load would find no
    // labels and write `selected_id = None`, so a single keystroke while
    // the config is broken would wipe an anchor that had survived it —
    // and the operator's next `r` would land them on row 0 of a table
    // they had already navigated away from.
    if app.loaded_config.is_none() {
        return;
    }
    // Every keystroke, like Subnets: the leaf must be operable from the
    // first interaction rather than after a wake-up press.
    //
    // This leans on it harder now than the read-only view did. It is what makes
    // `selected_id` name the row the table highlights, and `focused_label`
    // — which `e` and `d` resolve through — reads that anchor. Seeding
    // after the openers would let the first `e` on a freshly entered tab
    // act on a row the operator has not seen highlighted.
    ensure_labels_selection_seeded(app);

    // Add first, and above every emptiness check: it is the one verb whose
    // whole purpose is to work when the vocabulary is empty. **Zero**
    // `[[labels]]` rows is measured on live boxes, so "empty" is
    // not the corner case here — it is the state the operator meets. The
    // kind comes from the focused pane and is not a form field; see the
    // `label_modal` module doc for the context-desync argument that
    // settled it.
    if key.code == KeyCode::Char('a') {
        app.labels.modal = Some(build_label_add_modal(app));
        return;
    }

    match key.code {
        // `e` / `d` resolve a row first: there is nothing to edit or
        // remove when the focused kind has no entries, and
        // `build_label_*_modal` returns `None` in exactly that case.
        // Enter is the primary action on the focused row; on Labels
        // that is edit. Same branch as `e`, no new modal.
        KeyCode::Enter | KeyCode::Char('e') => {
            if let Some(modal) = build_label_edit_modal(app) {
                app.labels.modal = Some(modal);
            }
        }
        KeyCode::Char('d') | KeyCode::Delete => {
            if let Some(modal) = build_label_remove_modal(app) {
                app.labels.modal = Some(modal);
            }
        }
        // **`←`/`→` mean one of two things, and which one is a property of
        // the layout rather than a mode the operator chose.**
        //
        // Wide: they move focus between the two cards — a vertically drawn
        // menu must not be walked by a horizontal
        // key.
        //
        // Narrow: there is no second card. `menu_is_painted` is false below
        // `NARROW_THRESHOLD`, the clamp pins focus to the table every frame,
        // and a `←` that sets `KindMenu` is undone before the next keystroke
        // is read — so the kind was **unreachable**, and with it two of the
        // three vocabularies at the declared 80×24 floor. The axis argument
        // does not apply to a menu that is not drawn: there is no vertical
        // list to walk, so the horizontal keys are free to carry the kind,
        // which is exactly what they did before the axis fix.
        KeyCode::Left => {
            if app.labels.menu_painted {
                app.labels.focus = LabelsFocus::KindMenu;
            } else {
                cycle_labels_kind(app, false);
            }
        }
        KeyCode::Right => {
            if app.labels.menu_painted {
                app.labels.focus = LabelsFocus::Entries;
            } else {
                cycle_labels_kind(app, true);
            }
        }
        KeyCode::Down | KeyCode::Up => {
            let forward = matches!(key.code, KeyCode::Down);
            match app.labels.focus {
                // The kind menu is a three-item value cycler, not a list —
                // one of a small set of `rem_euclid` sites where wrap is
                // load-bearing. It keeps
                // wrapping; only the ENTRIES table is a list.
                LabelsFocus::KindMenu => cycle_labels_kind(app, forward),
                LabelsFocus::Entries => step_labels_entry(app, key.code),
            }
        }
        // Jump / page, entries only. `Home` / `End` on the kind menu
        // would be a jump within a three-item cycler; there is nothing to
        // jump past, so they stay unbound there rather than aliasing
        // `↑`/`↓`.
        KeyCode::Home | KeyCode::End | KeyCode::PageUp | KeyCode::PageDown
            if app.labels.focus == LabelsFocus::Entries =>
        {
            step_labels_entry(app, key.code);
        }
        _ => app.leaf_key_unhandled = true,
    }
}

// ── Custom Lists ─────────────────────────────────────────────────────

/// The ids of every declared custom list, in config order.
///
/// Owned `String`s deliberately: the caller writes to `app.custom_lists`
/// straight afterwards, and handing back a borrow of `app.loaded_config`
/// would keep the immutable borrow alive across that write.
fn custom_list_ids(app: &App) -> Vec<String> {
    app.loaded_config
        .as_ref()
        .map(|l| {
            l.config
                .custom_lists
                .iter()
                .map(|c| c.id.as_str().to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// Seed the list cursor to the first row when it is unset, or repair it
/// when it names a list the config no longer declares.
///
/// The renderer falls back to highlighting row 0 when the anchor does not
/// resolve, so without this the operator sees a cursor while the state says
/// `None` — and the openers, which read the anchor, would no-op on exactly
/// the row that looks selected.
///
/// **"No config" is not "a config with no custom lists".** This runs on
/// every dirty render, not only on a keystroke, so a failed load would
/// otherwise find zero lists, write `None`, and discard the operator's
/// place without anyone pressing a key.
fn ensure_custom_list_selection_seeded(app: &mut App) {
    if app.loaded_config.is_none() {
        return;
    }
    let ids = custom_list_ids(app);
    if let Some(want) = app.custom_lists.selected_id.as_deref() {
        if ids.iter().any(|i| i == want) {
            return;
        }
    }
    app.custom_lists.selected_id = ids.into_iter().next();
}

/// Reload the rule pane's lines when the selection has moved.
///
/// Runs on every dirty render, but reads the file only when the loaded
/// pack does not match the anchor — otherwise the draw path would do I/O
/// at the frame rate. `force` re-reads the same list after a write.
fn refresh_custom_list_pack(app: &mut App, force: bool) {
    use crate::config::custom_list::{pack_path, read_pack_lines};
    use crate::tui::app::PackView;

    let Some(loaded) = app.loaded_config.as_ref() else {
        app.custom_lists.pack = None;
        return;
    };
    let Some(want) = app.custom_lists.selected_id.clone() else {
        app.custom_lists.pack = None;
        return;
    };
    if !force && app.custom_lists.pack.as_ref().is_some_and(|p| p.id == want) {
        return;
    }
    let Ok(id) = crate::config::schema::Id::new(want.as_str()) else {
        app.custom_lists.pack = None;
        return;
    };
    let Some(root) = loaded.master_path.parent() else {
        app.custom_lists.pack = None;
        return;
    };
    let max = loaded.config.custom_list_limits.max_file_bytes;
    let view = match read_pack_lines(&pack_path(root, &id), max) {
        Ok(views) => PackView {
            id: want,
            rows: crate::tui::tabs::custom_lists::rows_from_views(&views),
            error: None,
        },
        // An unreadable FILE is an error the pane states; an unparseable
        // LINE is a row. Collapsing the two would hide the difference
        // between "no rules" and "cannot be read".
        Err(e) => PackView {
            id: want,
            rows: Vec::new(),
            error: Some(e.to_string()),
        },
    };
    app.custom_lists.pack = Some(view);
}

/// Step the rule cursor, clamped at both ends.
///
/// Anchored on the 1-based FILE LINE, not on a row index: a reload that
/// adds or removes lines above the cursor would otherwise silently move
/// what the next action operates on.
fn step_custom_list_rule(app: &mut App, code: KeyCode) {
    let Some(pack) = app.custom_lists.pack.as_ref() else {
        return;
    };
    if pack.rows.is_empty() {
        return;
    }
    let last = pack.rows.len() - 1;
    let cur = app
        .custom_lists
        .selected_line
        .and_then(|n| pack.rows.iter().position(|r| r.number == n))
        .unwrap_or(0);
    let next = match code {
        KeyCode::Down => (cur + 1).min(last),
        KeyCode::Up => cur.saturating_sub(1),
        KeyCode::Home => 0,
        KeyCode::End => last,
        KeyCode::PageDown => (cur + NAV_PAGE).min(last),
        KeyCode::PageUp => cur.saturating_sub(NAV_PAGE),
        _ => return,
    };
    app.custom_lists.selected_line = Some(pack.rows[next].number);
}

/// Force the Custom Lists focus onto a pane the layout actually paints.
///
/// Below the split threshold the leaf collapses to the list pane alone, so
/// a `Rules` focus is unhonourable: the operator would be moving a cursor
/// on a table that is not on screen. At the 80x24 floor that is the
/// DEFAULT state, not an edge case.
///
/// Clamped in state rather than derived at draw time so the **key handler**
/// is correct too — it has no idea how wide the terminal is, and a
/// renderer-only fix would leave the keys behaving as if a pane nobody can
/// see still had the cursor.
fn clamp_custom_lists_focus_to_layout(app: &mut App, viewport_width: u16) {
    if app.active_leaf != Leaf::CustomLists {
        return;
    }
    let painted = crate::tui::tabs::custom_lists::rules_pane_is_painted(viewport_width);
    app.custom_lists.rules_pane_painted = painted;
    if !painted {
        app.custom_lists.focus = CustomListsFocus::Lists;
    }
}

/// Step the list cursor, clamped at both ends.
///
/// A clamp, not a wrap: this is a list of rows the operator scrolls, not a
/// small value cycler.
fn step_custom_list(app: &mut App, code: KeyCode) {
    let ids = custom_list_ids(app);
    if ids.is_empty() {
        return;
    }
    let last = ids.len() - 1;
    let cur = app
        .custom_lists
        .selected_id
        .as_deref()
        .and_then(|want| ids.iter().position(|i| i == want))
        .unwrap_or(0);
    let next = match code {
        KeyCode::Down => (cur + 1).min(last),
        KeyCode::Up => cur.saturating_sub(1),
        KeyCode::Home => 0,
        KeyCode::End => last,
        KeyCode::PageDown => (cur + NAV_PAGE).min(last),
        KeyCode::PageUp => cur.saturating_sub(NAV_PAGE),
        _ => return,
    };
    app.custom_lists.selected_id = Some(ids[next].clone());
}

/// Custom Lists navigation.
///
/// **`h`/`j`/`k`/`l` are deliberately not bound**, here or anywhere: the
/// four vim aliases were deleted TUI-wide, and a leaf that reinstated them
/// would be the only one that answers to them. The arrows are the motion
/// keys.
fn handle_custom_lists_key(app: &mut App, key: KeyEvent) {
    // The guard comes FIRST, as on Labels: seeding against a failed load
    // would find no lists and wipe an anchor that had survived it.
    if app.loaded_config.is_none() {
        return;
    }
    ensure_custom_list_selection_seeded(app);

    // **`a`, `e` and `d` mean different things per pane, and the focused
    // pane is what says which.** The rule pane's cursor glyph and the
    // footer both change with focus, which is what keeps them from
    // reading as ambiguous. Every arm here must stay INSIDE this guard:
    // on the list pane the same letters act on the list, which is what
    // the operator expects there.
    if app.custom_lists.focus == CustomListsFocus::Rules {
        match key.code {
            KeyCode::Char('a') => {
                if let Some(id) = app.custom_lists.selected_id.clone() {
                    app.custom_lists.modal =
                        Some(custom_list_modal::CustomListModal::open_add_rule(id));
                }
                return;
            }
            KeyCode::Char('e') => {
                if let Some(modal) = build_rule_edit_modal(app) {
                    app.custom_lists.modal = Some(modal);
                }
                return;
            }
            KeyCode::Char('d') | KeyCode::Delete => {
                if let Some(modal) = build_rule_remove_modal(app) {
                    app.custom_lists.modal = Some(modal);
                }
                return;
            }
            _ => {}
        }
    }

    match key.code {
        KeyCode::Char('a') => {
            app.custom_lists.modal = Some(custom_list_modal::CustomListModal::open_add(
                packs_dir_display(app),
            ));
            return;
        }
        KeyCode::Char('e') => {
            if let Some(entity) = focused_custom_list(app) {
                app.custom_lists.modal = Some(custom_list_modal::CustomListModal::open_edit(
                    &entity,
                    packs_dir_display(app),
                ));
            }
            return;
        }
        KeyCode::Char('d') | KeyCode::Delete => {
            if let Some(entity) = focused_custom_list(app) {
                let mounted = profiles_mounting(app, entity.id.as_str());
                let rules = app
                    .loaded_config
                    .as_ref()
                    .and_then(|l| l.custom_lists.get(&entity.id))
                    .map(|c| c.allow.len() + c.deny.len())
                    .unwrap_or(0);
                app.custom_lists.modal = Some(custom_list_modal::CustomListModal::open_remove(
                    &entity, mounted, rules,
                ));
            }
            return;
        }
        _ => {}
    }

    if key.code == KeyCode::Char('m') {
        if let Some(entity) = focused_custom_list(app) {
            let profiles = profiles_with_mount_state(app, entity.id.as_str());
            app.custom_lists.mount_picker =
                Some(custom_list_modal::MountPicker::open(&entity, profiles));
        }
        return;
    }

    // **The horizontal axis exists on this leaf**, which is the condition
    // the navigation rule attaches to `←`/`→`: there are two panes, so the
    // keys have somewhere to go. `h`/`l` ride alongside them here by the
    // operator's decision; they are bound on no other leaf.
    match key.code {
        KeyCode::Enter | KeyCode::Right | KeyCode::Char('l')
            if app.custom_lists.focus == CustomListsFocus::Lists =>
        {
            // Never hand focus to a pane the layout does not paint.
            if app.custom_lists.rules_pane_painted {
                app.custom_lists.focus = CustomListsFocus::Rules;
                ensure_custom_list_rule_seeded(app);
            } else {
                app.leaf_key_unhandled = true;
            }
        }
        KeyCode::Left | KeyCode::Char('h') | KeyCode::Esc
            if app.custom_lists.focus == CustomListsFocus::Rules =>
        {
            app.custom_lists.focus = CustomListsFocus::Lists;
        }
        KeyCode::Down
        | KeyCode::Up
        | KeyCode::Home
        | KeyCode::End
        | KeyCode::PageUp
        | KeyCode::PageDown => match app.custom_lists.focus {
            CustomListsFocus::Lists => {
                step_custom_list(app, key.code);
                // The rule pane FOLLOWS the list cursor with no keystroke:
                // that is what makes the selection legible at a glance,
                // and it is the answer to "which list holds this domain".
                refresh_custom_list_pack(app, false);
                app.custom_lists.selected_line = None;
            }
            CustomListsFocus::Rules => step_custom_list_rule(app, key.code),
        },
        _ => app.leaf_key_unhandled = true,
    }
}

/// The removal confirm for the rule under the cursor, if there is one.
///
/// Returns `None` on a comment, a blank or a refused line: those carry no
/// domain, so there is nothing for `remove_rule` to match. Silently doing
/// nothing there is right — the alternative is a confirm that offers to
/// remove a comment and then removes something else.
fn build_rule_remove_modal(app: &App) -> Option<custom_list_modal::CustomListModal> {
    let list_id = app.custom_lists.selected_id.clone()?;
    let pack = app.custom_lists.pack.as_ref()?;
    let line = app.custom_lists.selected_line?;
    let row = pack.rows.iter().find(|r| r.number == line)?;
    let domain = row.domain.clone()?;
    let affected = rule_lines_naming(app, &domain);
    Some(custom_list_modal::CustomListModal::open_remove_rule(
        list_id, domain, affected,
    ))
}

/// The edit form for the rule under the cursor, if there is one.
///
/// `None` on a comment, a blank, or a line the grammar refused. The first
/// two are unreachable — the pane does not draw them — but a REFUSED line
/// is drawn, and it carries no domain: it cannot state what the operator
/// saw, so there is nothing the writer could check the file against. A key
/// that opens nothing beats a form that can never save.
fn build_rule_edit_modal(app: &App) -> Option<custom_list_modal::CustomListModal> {
    use crate::tui::app::PackRowAction;
    let list_id = app.custom_lists.selected_id.clone()?;
    let pack = app.custom_lists.pack.as_ref()?;
    let line = app.custom_lists.selected_line?;
    let row = pack.rows.iter().find(|r| r.number == line)?;
    let domain = row.domain.clone()?;
    Some(custom_list_modal::CustomListModal::open_edit_rule(
        list_id,
        line,
        domain,
        matches!(row.action, PackRowAction::Allow),
    ))
}

/// Seed the rule cursor to the first line when it is unset or dangling.
///
/// The renderer falls back to row 0, so without this the operator sees a
/// cursor while the state says `None` — and any verb reading the anchor
/// would no-op on exactly the row that looks selected.
fn ensure_custom_list_rule_seeded(app: &mut App) {
    let Some(pack) = app.custom_lists.pack.as_ref() else {
        return;
    };
    let resolves = app
        .custom_lists
        .selected_line
        .is_some_and(|n| pack.rows.iter().any(|r| r.number == n));
    if !resolves {
        app.custom_lists.selected_line = pack.rows.first().map(|r| r.number);
    }
}

/// The list the openers act on: the anchored selection, else the first row.
///
/// **The fallback is the correctness argument, not a convenience.** The
/// list pane highlights `resolve_selected_index(..)` and falls back to row
/// 0 when the anchor does not resolve. If this resolved differently, `m`
/// would mount a list other than the highlighted one and nothing on screen
/// would say so.
fn focused_custom_list(app: &App) -> Option<crate::config::schema::CustomList> {
    let loaded = app.loaded_config.as_ref()?;
    let lists = &loaded.config.custom_lists;
    let want = app.custom_lists.selected_id.as_deref();
    lists
        .iter()
        .find(|c| Some(c.id.as_str()) == want)
        .or_else(|| lists.first())
        .cloned()
}

/// Profiles that mount `id`, in config order.
fn profiles_mounting(app: &App, id: &str) -> Vec<String> {
    app.loaded_config
        .as_ref()
        .map(|l| {
            l.config
                .profiles
                .iter()
                .filter(|(_, p)| p.custom_lists.iter().any(|c| c.as_str() == id))
                .map(|(name, _)| name.clone())
                .collect()
        })
        .unwrap_or_default()
}

/// The `packs/` directory, for the modal's read-only path row.
fn packs_dir_display(app: &App) -> String {
    app.loaded_config
        .as_ref()
        .and_then(|l| l.master_path.parent().map(|p| p.join("packs")))
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "packs".to_string())
}

/// Every declared profile in config order, each with whether it already
/// mounts `list_id`.
fn profiles_with_mount_state(app: &App, list_id: &str) -> Vec<(String, bool)> {
    app.loaded_config
        .as_ref()
        .map(|l| {
            l.config
                .profiles
                .iter()
                .map(|(name, p)| {
                    (
                        name.clone(),
                        p.custom_lists.iter().any(|c| c.as_str() == list_id),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
#[path = "tests/custom_lists_nav_tests.rs"]
mod custom_lists_nav_tests;

/// Which text buffer the Add / Edit form is typing into, if any.
fn custom_list_form_buf(form: &mut custom_list_modal::Form) -> Option<&mut String> {
    use custom_list_modal::{FormField, FormMode};
    match form.focused {
        // The id names the file and is immutable once created; the
        // renderer draws it as a plain row on Edit, so there is no buffer
        // to reach even when focus somehow lands there.
        FormField::Id if form.mode == FormMode::Add => Some(&mut form.id),
        FormField::Id => None,
        FormField::DisplayName => Some(&mut form.display_name),
        FormField::Description => Some(&mut form.description),
        FormField::Submit | FormField::Cancel => None,
    }
}

/// Skip the Id field on Edit — immutable after creation, and the renderer
/// draws it as a plain row that can never take focus.
fn next_editable_custom_list_field(
    f: custom_list_modal::FormField,
    mode: custom_list_modal::FormMode,
    forward: bool,
) -> custom_list_modal::FormField {
    use custom_list_modal::{FormField, FormMode};
    let mut next = if forward { f.next() } else { f.prev() };
    if mode == FormMode::Edit && next == FormField::Id {
        next = if forward { next.next() } else { next.prev() };
    }
    next
}

/// Add / Edit / Remove modal keys.
async fn handle_custom_list_modal_key(
    app: &mut App,
    key: KeyEvent,
    poller: &IpcPoller,
    config_path: &Path,
) {
    use custom_list_modal::{FormField, Stage};

    let Some(mut modal) = app.custom_lists.modal.take() else {
        return;
    };
    if modal.is_submitted() {
        // Any keypress on the outcome card closes it.
        return;
    }

    match &mut modal.stage {
        Stage::EditingForm(form) => {
            match key.code {
                // Returning without re-stashing closes the modal.
                KeyCode::Esc => return,
                KeyCode::Tab | KeyCode::Down => {
                    form.focused = next_editable_custom_list_field(form.focused, form.mode, true);
                    form.error_message = None;
                }
                KeyCode::BackTab | KeyCode::Up => {
                    form.focused = next_editable_custom_list_field(form.focused, form.mode, false);
                    form.error_message = None;
                }
                KeyCode::Enter => {
                    if form.focused == FormField::Cancel {
                        return;
                    }
                    submit_custom_list_modal(app, modal, poller, config_path).await;
                    return;
                }
                KeyCode::Backspace => {
                    if let Some(buf) = custom_list_form_buf(form) {
                        buf.pop();
                        form.error_message = None;
                    }
                }
                // **The CONTROL guard is not decoration.** The footer, while
                // this form is open, advertises the shared modal grammar,
                // which names `Ctrl+s`. This modal saves on Enter, so
                // `Ctrl+s` does nothing — and without the mask it would do
                // something worse than nothing and type an `s` into
                // whichever field had focus.
                KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    if let Some(buf) = custom_list_form_buf(form) {
                        buf.push(c);
                        form.error_message = None;
                    }
                }
                _ => {}
            }
            app.custom_lists.modal = Some(modal);
        }
        Stage::ConfirmingRemove(rc) => {
            if rc.is_refused() {
                // No amount of typing authorises a mounted list, so the
                // gate takes no input at all — only a way out.
                if !matches!(key.code, KeyCode::Esc) {
                    app.custom_lists.modal = Some(modal);
                }
                return;
            }
            match key.code {
                // Falling out without re-stashing is what closes the
                // modal; every other arm here puts it back explicitly.
                KeyCode::Esc => {}
                KeyCode::Enter => {
                    if rc.confirmed() {
                        submit_custom_list_modal(app, modal, poller, config_path).await;
                        return;
                    }
                    // A mismatch is not a silent no-op: the operator gets
                    // told what they typed did not match.
                    app.status_err("typed id does not match — nothing removed".into());
                    app.custom_lists.modal = Some(modal);
                }
                KeyCode::Backspace => {
                    rc.typed.pop();
                    app.custom_lists.modal = Some(modal);
                }
                KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    rc.typed.push(c);
                    app.custom_lists.modal = Some(modal);
                }
                _ => app.custom_lists.modal = Some(modal),
            }
        }
        Stage::AddingRule(form) => {
            use custom_list_modal::RuleField;
            match key.code {
                KeyCode::Esc => return,
                KeyCode::Tab | KeyCode::Down => {
                    form.focused = form.focused.next();
                    form.error_message = None;
                }
                KeyCode::BackTab | KeyCode::Up => {
                    form.focused = form.focused.prev();
                    form.error_message = None;
                }
                // The shared modal grammar: Left/Right change the value on
                // a toggle. Absolute rather than a flip, so an omitted arm
                // is detectable — with two values a toggling pair is
                // behaviourally identical either way.
                KeyCode::Left if form.focused == RuleField::Direction => {
                    form.allow = false;
                    form.error_message = None;
                }
                KeyCode::Right if form.focused == RuleField::Direction => {
                    form.allow = true;
                    form.error_message = None;
                }
                KeyCode::Enter => {
                    if form.focused == RuleField::Cancel {
                        return;
                    }
                    submit_custom_list_modal(app, modal, poller, config_path).await;
                    return;
                }
                // The focus check rides the guard rather than an inner
                // `if`: a keystroke aimed at a non-text field then falls to
                // the catch-all, which is where it already ended up.
                KeyCode::Backspace if form.focused == RuleField::Domain => {
                    form.domain.pop();
                    form.error_message = None;
                }
                // **The CONTROL mask is not decoration.** The footer, while
                // this form is open, advertises the shared modal grammar,
                // which names `Ctrl+s`. This modal saves on Enter, so
                // `Ctrl+s` does nothing here — and without the mask it
                // would do something worse than nothing and type an `s`
                // into the domain.
                KeyCode::Char(c)
                    if form.focused == RuleField::Domain
                        && !key.modifiers.contains(KeyModifiers::CONTROL) =>
                {
                    form.domain.push(c);
                    form.error_message = None;
                }
                _ => {}
            }
            app.custom_lists.modal = Some(modal);
        }
        Stage::ConfirmingRuleRemove(_) => match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                submit_custom_list_modal(app, modal, poller, config_path).await;
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                // Drop the modal — returning without re-stashing.
            }
            _ => app.custom_lists.modal = Some(modal),
        },
        Stage::Submitted(_) => {}
    }
}

/// Apply the modal, then ask the daemon to reload.
///
/// **The reload is not optional.** Nothing watches the config files, so a
/// write reaches the daemon only through SIGHUP or the IPC reload; without
/// it the operator creates a list and the DNS does not change.
async fn submit_custom_list_modal(
    app: &mut App,
    mut modal: custom_list_modal::CustomListModal,
    poller: &IpcPoller,
    config_path: &Path,
) {
    use crate::cli::commands::ipc_reload::{attempt_reload, ReloadOutcome};
    use custom_list_modal::{FormMode, Stage, SubmitOutcome};

    // An Edit that changes nothing must not write. Rewriting the
    // operator's TOML and reloading the daemon for a no-op is the same
    // waste the mount picker refuses when nothing is staged — and here it
    // would also churn the file's mtime, which is what the leaf's UPDATED
    // column reports.
    let mut wrote = true;
    let outcome: SubmitOutcome = match &modal.stage {
        Stage::EditingForm(form) => match form.try_resolve() {
            Err(msg) => SubmitOutcome::Failed(msg),
            Ok(resolved) => {
                let unchanged = form.original.as_ref().is_some_and(|o| {
                    o.id == resolved.id
                        && o.display_name == resolved.display_name
                        && o.description == resolved.description
                });
                if form.mode == FormMode::Edit && unchanged {
                    wrote = false;
                    SubmitOutcome::Ok(format!("custom list {} unchanged", resolved.id))
                } else {
                    let r = match form.mode {
                        FormMode::Add => create_custom_list(config_path, &resolved),
                        FormMode::Edit => update_custom_list_meta(config_path, &resolved),
                    };
                    match r {
                        Ok(msg) => SubmitOutcome::Ok(msg),
                        Err(msg) => SubmitOutcome::Failed(msg),
                    }
                }
            }
        },
        Stage::ConfirmingRemove(rc) => match remove_custom_list(config_path, &rc.id) {
            Ok(msg) => SubmitOutcome::Ok(msg),
            Err(msg) => SubmitOutcome::Failed(msg),
        },
        Stage::AddingRule(form) => {
            // An edit that changes nothing must not write, for the reason
            // the list form gives one arm up: it would churn the file's
            // mtime, which the leaf's UPDATED column reports, and spend a
            // daemon reload on a no-op.
            let written = match form.replacing() {
                None => add_rule_to_pack(app, &form.list_id, form.domain.trim(), form.allow),
                Some((line, ..)) if form.is_unchanged() => {
                    wrote = false;
                    Ok(format!("line {line} of {} unchanged", form.list_id))
                }
                Some((line, was_domain, was_allow)) => replace_rule_in_pack(
                    app,
                    &form.list_id,
                    line,
                    (was_domain, was_allow),
                    form.domain.trim(),
                    form.allow,
                ),
            };
            match written {
                Ok(msg) => SubmitOutcome::Ok(msg),
                Err(msg) => SubmitOutcome::Failed(msg),
            }
        }
        Stage::ConfirmingRuleRemove(rc) => {
            match remove_rule_from_pack(app, &rc.list_id, &rc.domain) {
                Ok(msg) => SubmitOutcome::Ok(msg),
                Err(msg) => SubmitOutcome::Failed(msg),
            }
        }
        Stage::Submitted(_) => return,
    };

    // A form failure keeps the modal OPEN with the message inline, so the
    // operator fixes the offending field instead of retyping the rest. A
    // remove failure has no form to keep, so it finishes.
    if let SubmitOutcome::Failed(msg) = &outcome {
        match &mut modal.stage {
            Stage::EditingForm(form) => {
                app.status_err(format!("custom list: {msg}"));
                form.error_message = Some(msg.clone());
                app.custom_lists.modal = Some(modal);
                return;
            }
            // A rejected domain keeps the form and its typing: the
            // grammar refuses wildcards and paths, and retyping the whole
            // domain to fix one character is the cost of dropping it.
            Stage::AddingRule(form) => {
                app.status_err(format!("rule: {msg}"));
                form.error_message = Some(msg.clone());
                app.custom_lists.modal = Some(modal);
                return;
            }
            _ => {}
        }
    }

    let was_ok = wrote && matches!(outcome, SubmitOutcome::Ok(_));
    match &outcome {
        SubmitOutcome::Ok(msg) => app.status_ok(msg.clone()),
        SubmitOutcome::Failed(msg) => app.status_err(format!("custom list: {msg}")),
    }
    modal.finish(outcome);
    app.custom_lists.modal = Some(modal);

    if was_ok {
        let reload = attempt_reload(poller.socket_path()).await;
        // The reload arms REPLACE the status set above. `Reloaded` is the
        // one arm that stays silent and therefore keeps it.
        match reload {
            ReloadOutcome::Reloaded => {}
            ReloadOutcome::DaemonUnreachable => {
                app.status_err(
                    "saved on disk — daemon not running, will activate on next start".into(),
                );
            }
            ReloadOutcome::NoToken { .. } => {
                app.status_err(
                    "saved on disk but no admin token is available to request a reload".into(),
                );
            }
            ReloadOutcome::ReloadFailed(msg) => {
                app.status_err(format!("saved but daemon rejected reload: {msg}"));
            }
        }
        app.loaded_config = load_v1_config(config_path);
        // The anchor may name a list that no longer exists after a remove.
        ensure_custom_list_selection_seeded(app);
        // FORCED: a rule write changes the file under an unchanged
        // selection, so the "same id, already loaded" fast path would
        // leave the pane showing the file as it was before the write.
        refresh_custom_list_pack(app, true);
        ensure_custom_list_rule_seeded(app);
        poll_active_leaf(app, poller).await;
    }
}

/// Append one rule to the selected list's pack.
///
/// **`add_rule` and `remove_rule` are the only two writers this leaf may
/// reach for.** Reading a pack is permissive — an unparseable line is
/// skipped and counted, and the file loads — while `write_pack` refuses the
/// whole write at the first invalid line. So a save that rebuilt the file
/// from the rows this pane drew would either fail on a file that had loaded
/// cleanly, or "repair" it by deleting every comment and every line the
/// reader had skipped. A pack in the field carries more comment lines than
/// rules.
fn add_rule_to_pack(app: &App, list_id: &str, domain: &str, allow: bool) -> Result<String, String> {
    use crate::config::custom_list::AddOutcome;

    if domain.is_empty() {
        return Err("a domain is required".into());
    }
    let loaded = app
        .loaded_config
        .as_ref()
        .ok_or_else(|| "the configuration could not be read".to_string())?;
    let id = crate::config::schema::Id::new(list_id).map_err(|e| format!("list id: {e}"))?;
    match crate::tui::tabs::custom_lists::append_rule(loaded, &id, domain, allow)
        .map_err(|e| e.to_string())?
    {
        AddOutcome::Added => Ok(format!(
            "added {} rule for {domain}",
            if allow { "allow" } else { "deny" }
        )),
        // Idempotent, and saying so beats reporting a no-op as a success:
        // the operator would otherwise look for a second line that is not
        // there.
        AddOutcome::AlreadyPresent => Ok(format!("{domain} is already in {list_id}")),
    }
}

/// Replace the rule on one file line of the selected list's pack.
///
/// **Not remove-then-add, and the difference is data loss.**
/// `remove_rule` matches the domain and ignores the direction, so a flip
/// composed from the two primitives takes the opposite direction of the
/// same domain with it — a rule the operator never touched, in a file
/// they diff.
///
/// `expect` is what the pane RENDERED on that line, and it is what makes
/// the file line number safe to key on: the pack view is only re-read
/// when the selection changes or a write lands here, so a write from
/// anywhere else moves the numbering under it.
fn replace_rule_in_pack(
    app: &App,
    list_id: &str,
    line: usize,
    expect: (&str, bool),
    domain: &str,
    allow: bool,
) -> Result<String, String> {
    if domain.is_empty() {
        return Err("a domain is required".into());
    }
    let loaded = app
        .loaded_config
        .as_ref()
        .ok_or_else(|| "the configuration could not be read".to_string())?;
    let id = crate::config::schema::Id::new(list_id).map_err(|e| format!("list id: {e}"))?;
    crate::tui::tabs::custom_lists::replace_rule(loaded, &id, line, expect, domain, allow)
        .map_err(|e| e.to_string())?;
    Ok(format!("replaced line {line} of {list_id}"))
}

/// Drop every rule naming `domain`, **in both directions**.
fn remove_rule_from_pack(app: &App, list_id: &str, domain: &str) -> Result<String, String> {
    let loaded = app
        .loaded_config
        .as_ref()
        .ok_or_else(|| "the configuration could not be read".to_string())?;
    let id = crate::config::schema::Id::new(list_id).map_err(|e| format!("list id: {e}"))?;
    let removed = crate::tui::tabs::custom_lists::delete_rule(loaded, &id, domain)
        .map_err(|e| e.to_string())?;
    if removed {
        Ok(format!("removed {domain} from {list_id}"))
    } else {
        Err(format!("{domain} is not in {list_id}"))
    }
}

/// Every rendered line naming `domain`, in file order.
///
/// Feeds the removal confirm so it can state what a single `y` actually
/// takes. `remove_rule` matches the domain and ignores the direction, so
/// this is where an allow and a deny for one domain become visible as two
/// lines rather than one.
fn rule_lines_naming(app: &App, domain: &str) -> Vec<(usize, String)> {
    app.custom_lists
        .pack
        .as_ref()
        .map(|p| {
            p.rows
                .iter()
                .filter(|r| r.domain.as_deref() == Some(domain))
                .map(|r| (r.number, r.raw.clone()))
                .collect()
        })
        .unwrap_or_default()
}

/// The `[[custom_lists]]` table an entity saves as.
///
/// **`upsert_id_keyed` REPLACES the entry it finds**, so every field this
/// omits is reset to its serde default on the next save — of anything, not
/// of that field. `every_custom_list_field_is_written` pins that by
/// exhaustive destructuring, so a fourth field on `CustomList` breaks the
/// build instead of vanishing on the next save.
fn custom_list_value(resolved: &custom_list_modal::ResolvedForm) -> toml::Value {
    let mut tbl = toml::map::Map::new();
    tbl.insert("id".into(), toml::Value::String(resolved.id.clone()));
    tbl.insert(
        "display_name".into(),
        toml::Value::String(resolved.display_name.clone()),
    );
    tbl.insert(
        "description".into(),
        toml::Value::String(resolved.description.clone()),
    );
    toml::Value::Table(tbl)
}

/// The file that declares `[[custom_lists]]` with this id.
///
/// The array is merged by concatenation across the include graph, so an
/// entry may legitimately live in a fragment. A removal aimed at the master
/// would no-op while reporting success, and the list would still be there
/// after the reload.
///
/// `Err` is a file in `files_loaded` — the loader's own record of files it
/// successfully read — that can no longer be read or parsed: a permission
/// change or a truncated write since load. It must not collapse into
/// `Ok(None)`: the entity IS declared, and "no file declares it" sends the
/// operator to look for the wrong thing; `kind_toggle_gate`
/// already draws exactly this line elsewhere in this same
/// file.
fn custom_list_owner_file(
    loaded: &crate::config::loader::LoadedConfig,
    id: &str,
) -> Result<Option<PathBuf>, String> {
    for path in &loaded.files_loaded {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let value = text
            .parse::<toml::Value>()
            .map_err(|e| format!("cannot parse {}: {e}", path.display()))?;
        let declares_id = value
            .get("custom_lists")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .any(|item| item.get("id").and_then(|v| v.as_str()) == Some(id))
            })
            .unwrap_or(false);
        if declares_id {
            return Ok(Some(path.clone()));
        }
    }
    Ok(None)
}

/// Create a custom list: **the file first, then the declaration.**
///
/// `write_value_validated` runs the whole loader, and `build_store` fails
/// the entire config on one unreadable pack — so declaring a list whose
/// file does not exist yet would be refused, and on a daemon reload it
/// would take every other list down with it.
///
/// The id is checked before either step because both are destructive on a
/// collision: `create_pack` goes through `hardened_atomic_write`, which
/// OVERWRITES, and `upsert_id_keyed` REPLACES. An `a` on a taken id would
/// delete that list's rules before the config write was even attempted.
///
/// # Why the guard is scoped rather than held across both steps
///
/// `write_value_validated` takes the tree lock itself, and `claim_tree`
/// records why a guard still live here would stall against it. The scope
/// buys exactly one thing: every pack write in this tree happens under the
/// lock. It does **not** make the two steps one transaction, and it does
/// not close the id collision — the existence check above runs unlocked,
/// so two concurrent creates for one id still both pass it.
fn create_custom_list(
    config_path: &Path,
    resolved: &custom_list_modal::ResolvedForm,
) -> Result<String, String> {
    use crate::cli::commands::target::{read_or_empty, upsert_id_keyed, write_value_validated};
    use crate::config::custom_list::{create_pack, pack_dir, pack_path};
    use crate::config::schema::Id;
    use crate::tui::tabs::custom_lists;

    let id = Id::new(resolved.id.as_str()).map_err(|e| format!("id: {e}"))?;
    let loaded = load_v1_config(config_path)
        .ok_or_else(|| "the configuration could not be read".to_string())?;
    if loaded.config.custom_lists.iter().any(|c| c.id == id) {
        return Err(format!(
            "a custom list named {} already exists",
            resolved.id
        ));
    }
    let root = loaded
        .master_path
        .parent()
        .ok_or_else(|| "the configuration has no parent directory".to_string())?;

    std::fs::create_dir_all(pack_dir(root))
        .map_err(|e| format!("creating the packs directory: {e}"))?;
    let path = pack_path(root, &id);
    {
        let lock = custom_lists::claim_tree(&loaded).map_err(|e| e.to_string())?;
        create_pack(
            &lock,
            &path,
            &resolved.display_name,
            custom_lists::max_pack_bytes(&loaded),
        )
        .map_err(|e| e.to_string())?;
    }

    let (mut doc, _) = read_or_empty(&loaded.master_path).map_err(|e| e.to_string())?;
    upsert_id_keyed(
        &mut doc,
        "custom_lists",
        &resolved.id,
        custom_list_value(resolved),
    )
    .map_err(|e| e.to_string())?;
    write_value_validated(config_path, &loaded.master_path, &doc).map_err(|e| {
        // The file is already down. Say so rather than leaving an orphan
        // the operator cannot account for.
        format!(
            "validator: {e} — {} was created and is not declared; remove it or retry",
            path.display()
        )
    })?;
    Ok(format!("created custom list {}", resolved.id))
}

/// Rewrite an entity's metadata. The pack file is not touched.
fn update_custom_list_meta(
    config_path: &Path,
    resolved: &custom_list_modal::ResolvedForm,
) -> Result<String, String> {
    use crate::cli::commands::target::{read_or_empty, upsert_id_keyed, write_value_validated};

    let loaded = load_v1_config(config_path)
        .ok_or_else(|| "the configuration could not be read".to_string())?;
    let owner = custom_list_owner_file(&loaded, &resolved.id)?
        .ok_or_else(|| format!("no file declares custom list '{}'", resolved.id))?;
    let (mut doc, _) = read_or_empty(&owner).map_err(|e| e.to_string())?;
    upsert_id_keyed(
        &mut doc,
        "custom_lists",
        &resolved.id,
        custom_list_value(resolved),
    )
    .map_err(|e| e.to_string())?;
    write_value_validated(config_path, &owner, &doc).map_err(|e| format!("validator: {e}"))?;
    Ok(format!("updated custom list {}", resolved.id))
}

/// Remove the declaration. **The pack file is left on disk.**
///
/// Unlinking first and then failing the config write would leave the config
/// naming a file that is gone, and `build_store` fails the whole config on
/// one missing pack — so the next reload would drop every other list too.
/// Leaving the file costs a stale `packs/<id>.txt`; the confirm says so,
/// and `create_custom_list` refuses a taken id rather than adopting it.
fn remove_custom_list(config_path: &Path, id: &str) -> Result<String, String> {
    use crate::cli::commands::target::{read_or_empty, remove_id_keyed, write_value_validated};

    let loaded = load_v1_config(config_path)
        .ok_or_else(|| "the configuration could not be read".to_string())?;
    let owner = custom_list_owner_file(&loaded, id)?
        .ok_or_else(|| format!("no file declares custom list '{id}'"))?;
    let (mut doc, _) = read_or_empty(&owner).map_err(|e| e.to_string())?;
    if !remove_id_keyed(&mut doc, "custom_lists", id).map_err(|e| e.to_string())? {
        return Err(format!("custom list '{id}' not found — already removed?"));
    }
    write_value_validated(config_path, &owner, &doc).map_err(|e| format!("validator: {e}"))?;
    Ok(format!("removed custom list {id}"))
}

/// Mount-picker keys. `Space` toggles, `Enter` saves, `Esc` discards.
///
/// `Esc` discards and that is only meaningful because the toggles stage:
/// a picker that wrote on each keypress would leave nothing to discard.
async fn handle_custom_list_mount_key(
    app: &mut App,
    key: KeyEvent,
    poller: &IpcPoller,
    config_path: &Path,
) {
    let Some(picker) = app.custom_lists.mount_picker.as_mut() else {
        return;
    };
    // The outcome card is read-only: any key closes it.
    if picker.is_done() {
        app.custom_lists.mount_picker = None;
        return;
    }
    match key.code {
        KeyCode::Esc => app.custom_lists.mount_picker = None,
        KeyCode::Down => picker.step(true),
        KeyCode::Up => picker.step(false),
        KeyCode::Char(' ') => picker.toggle(),
        KeyCode::Enter => submit_custom_list_mount(app, poller, config_path).await,
        _ => {}
    }
}

/// Apply the staged mounts, then ask the daemon to reload.
///
/// **The reload is not optional.** Nothing watches the config files —
/// `notify` is not a dependency and no polling watcher exists — so a write
/// reaches the daemon only through SIGHUP or the IPC reload. Without this
/// the operator mounts a list, sees the row change, and the DNS does not.
async fn submit_custom_list_mount(app: &mut App, poller: &IpcPoller, config_path: &Path) {
    use crate::cli::commands::ipc_reload::{attempt_reload, ReloadOutcome};

    let Some(picker) = app.custom_lists.mount_picker.as_mut() else {
        return;
    };
    let changes: Vec<(String, bool)> = picker
        .changes()
        .into_iter()
        .map(|(p, on)| (p.to_string(), on))
        .collect();
    if changes.is_empty() {
        // Nothing staged is not a failure, and it must not write: a
        // no-op save that still promoted a file would rewrite the
        // operator's TOML for nothing.
        app.custom_lists.mount_picker = None;
        app.status_info("nothing to mount".into());
        return;
    }
    let list_id = picker.list_id.clone();

    match apply_custom_list_mounts(config_path, &list_id, &changes) {
        Err(msg) => {
            if let Some(p) = app.custom_lists.mount_picker.as_mut() {
                p.error = Some(msg.clone());
            }
            app.status_err(format!("mount: {msg}"));
            return;
        }
        Ok(summary) => {
            if let Some(p) = app.custom_lists.mount_picker.as_mut() {
                p.outcome = Some(summary.clone());
                p.failed = false;
            }
            app.status_ok(summary);
        }
    }

    let outcome = attempt_reload(poller.socket_path()).await;
    // The reload arms REPLACE the status set above. `Reloaded` is the one
    // arm that stays silent and therefore keeps it.
    match outcome {
        ReloadOutcome::Reloaded => {}
        ReloadOutcome::DaemonUnreachable => {
            app.status_err(
                "mount saved on disk — daemon not running, will activate on next start".into(),
            );
        }
        ReloadOutcome::NoToken { .. } => {
            app.status_err(
                "mount saved on disk but no admin token is available to request a reload".into(),
            );
        }
        ReloadOutcome::ReloadFailed(msg) => {
            app.status_err(format!("mount saved but daemon rejected reload: {msg}"));
        }
    }
    app.loaded_config = load_v1_config(config_path);
    poll_active_leaf(app, poller).await;
}

/// The file that declares `[profiles.<id>]`.
///
/// `profiles` is a named map merged across the include graph, so an entry
/// may legitimately live in a fragment. A write aimed at the master would
/// then create a SECOND declaration of the same profile, which the loader
/// refuses as a duplicate key — the whole config, not just this write.
///
/// Walks `files_loaded`, the loader's own record of what it read.
/// `Err` is a file in `files_loaded` that can no longer be read or parsed —
/// see [`custom_list_owner_file`], which carries the same rule and the
/// same reason.
fn profile_owner_file(
    loaded: &crate::config::loader::LoadedConfig,
    profile: &str,
) -> Result<Option<PathBuf>, String> {
    for path in &loaded.files_loaded {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let value = text
            .parse::<toml::Value>()
            .map_err(|e| format!("cannot parse {}: {e}", path.display()))?;
        let declares_profile = value
            .get("profiles")
            .and_then(|v| v.as_table())
            .map(|t| t.contains_key(profile))
            .unwrap_or(false);
        if declares_profile {
            return Ok(Some(path.clone()));
        }
    }
    Ok(None)
}

/// Set `[profiles.<id>].custom_lists`, **touching nothing else on that
/// table**.
///
/// This is the whole point of the function and the reason `upsert_profile`
/// is not called here: it does `profiles.insert(id, entry)`, and inserting
/// into a TOML table REPLACES the value whole. Every caller of it today is
/// a *create*, which is why the semantics have never bitten; a mount is an
/// *update*, and building a profile value from scratch would silently drop
/// that profile's `display_name`, its `lists` map and its `admin_rules`.
/// On a live box the `kids` profile carries a display name and fourteen
/// blocklist mounts.
///
/// The key is REMOVED rather than written as `[]` when nothing is mounted,
/// because `Profile::custom_lists` carries `skip_serializing_if` for
/// exactly that reason: an empty mount list declares nothing, and writing
/// it would grow `custom_lists = []` into profiles that never opted in.
fn set_profile_custom_lists(
    doc: &mut toml::Value,
    profile: &str,
    ids: &[String],
) -> Result<(), String> {
    let table = doc
        .as_table_mut()
        .ok_or_else(|| "config root is not a TOML table".to_string())?;
    let profiles = table
        .get_mut("profiles")
        .and_then(|v| v.as_table_mut())
        .ok_or_else(|| "no [profiles] table in this file".to_string())?;
    let entry = profiles
        .get_mut(profile)
        .ok_or_else(|| format!("profile '{profile}' is not declared in this file"))?;
    let t = entry
        .as_table_mut()
        .ok_or_else(|| format!("[profiles.{profile}] is not a table"))?;
    if ids.is_empty() {
        t.remove("custom_lists");
    } else {
        t.insert(
            "custom_lists".to_string(),
            toml::Value::Array(ids.iter().cloned().map(toml::Value::String).collect()),
        );
    }
    Ok(())
}

/// Apply every staged mount in ONE validated promotion.
///
/// Grouped by owning file and promoted together rather than one profile at
/// a time: `write_value_validated` per profile would run one full
/// validation and one rename each, so a refusal half-way would leave the
/// operator's intent partly applied with nothing saying which half landed.
///
/// **This is the second of two writers of `[profiles.<id>].custom_lists`,
/// and the file path is chosen here rather than inherited.** The profile
/// modal mounts through
/// [`ProfileUpdatePatch::custom_lists`](crate::ipc::protocol::ProfileUpdatePatch::custom_lists),
/// which is right for its gesture — one profile, N lists, one atomic patch
/// alongside that profile's other edits. This gesture is the transpose: one
/// list, N profiles, and those profiles need not share a file. Routing it
/// through the per-profile seat would trade the guarantee above for N
/// independent round-trips, so it writes the documents itself and reloads.
fn apply_custom_list_mounts(
    config_path: &Path,
    list_id: &str,
    changes: &[(String, bool)],
) -> Result<String, String> {
    use crate::cli::commands::target::{read_or_empty, write_values_validated, StagedWrite};
    use crate::cli::commands::toml_write::render_preserving;

    let loaded = load_v1_config(config_path)
        .ok_or_else(|| "the configuration could not be read".to_string())?;

    // path -> (original text, edited doc)
    let mut edits: Vec<(PathBuf, String, toml::Value)> = Vec::new();
    for (profile, mount) in changes {
        let owner = profile_owner_file(&loaded, profile)?
            .ok_or_else(|| format!("no file declares profile '{profile}'"))?;

        let slot = match edits.iter().position(|(p, _, _)| *p == owner) {
            Some(i) => i,
            None => {
                let original = std::fs::read_to_string(&owner).unwrap_or_default();
                let (doc, _) = read_or_empty(&owner).map_err(|e| e.to_string())?;
                edits.push((owner, original, doc));
                edits.len() - 1
            }
        };

        // Read the CURRENT list off the doc being edited, not off
        // `loaded.config`: two profiles in one file are two edits to the
        // same document, and the merged view would not carry the first.
        let mut ids = current_custom_lists(&edits[slot].2, profile);
        ids.retain(|id| id != list_id);
        if *mount {
            ids.push(list_id.to_string());
        }
        let doc = &mut edits[slot].2;
        set_profile_custom_lists(doc, profile, &ids)?;
    }

    let writes: Vec<StagedWrite> = edits
        .iter()
        .map(|(path, original, doc)| {
            render_preserving(original, doc)
                .map(|content| StagedWrite {
                    final_path: path.clone(),
                    content,
                })
                .map_err(|e| format!("serialise {}: {e}", path.display()))
        })
        .collect::<Result<_, String>>()?;

    write_values_validated(&loaded.master_path, &writes).map_err(|e| format!("validator: {e}"))?;

    let mounted = changes.iter().filter(|(_, on)| *on).count();
    let unmounted = changes.len() - mounted;
    Ok(match (mounted, unmounted) {
        (m, 0) => format!("{list_id} mounted on {m} profile(s)"),
        (0, u) => format!("{list_id} unmounted from {u} profile(s)"),
        (m, u) => format!("{list_id}: {m} mounted, {u} unmounted"),
    })
}

/// The `custom_lists` array currently on `[profiles.<id>]` in this doc.
fn current_custom_lists(doc: &toml::Value, profile: &str) -> Vec<String> {
    doc.get("profiles")
        .and_then(|v| v.as_table())
        .and_then(|t| t.get(profile))
        .and_then(|v| v.get("custom_lists"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
#[path = "tests/custom_lists_advertised_keys_tests.rs"]
mod custom_lists_advertised_keys_tests;

#[cfg(test)]
#[path = "tests/custom_list_write_tests.rs"]
mod custom_list_write_tests;

// ── Labels modal openers, key handler and submit path ────────────────
//
// No new IPC verb. The submit path drives the
// **sync inner writers** of `cli::commands::labels` and fires a single
// `attempt_reload` afterwards. `run_add` / `run_set` / `run_remove` are
// forbidden — they `println!`, and a `println!` on the alternate screen in
// raw mode staircases one column per line.

/// The label the openers act on: the anchored selection, else the first
/// row.
///
/// **The fallback is not a convenience — it is the whole correctness
/// argument.** `render_entries` highlights `resolve_selected_index(..)`
/// and falls back to row 0 when the anchor does not resolve. If this
/// resolved differently, `e` and `d` would act on a row other than the one
/// under the highlight, and nothing on screen would say so. Both sides
/// derive their row set from the same `tabs::labels::rows_for_kind`, so
/// the filter and the ordering cannot drift apart either.
fn focused_label(app: &App) -> Option<crate::config::schema::Label> {
    let loaded = app.loaded_config.as_ref()?;
    let rows = tabs::labels::rows_for_kind(&loaded.config.labels, app.labels.selected_kind);
    let idx =
        tabs::labels::resolve_selected_index(&rows, app.labels.selected_id.as_deref()).unwrap_or(0);
    rows.get(idx).map(|l| (*l).clone())
}

/// Usage count of the focused label, by the same collector the table's
/// USED column prints — so the confirm screen and the row behind it can
/// never disagree about the number.
fn focused_label_usage(app: &App, label: &crate::config::schema::Label) -> usize {
    app.loaded_config
        .as_ref()
        .map(|loaded| tabs::labels::usage_count(loaded, label))
        .unwrap_or(0)
}

fn build_label_add_modal(app: &App) -> label_modal::LabelModal {
    label_modal::LabelModal::open_add(app.labels.selected_kind)
}

fn build_label_edit_modal(app: &App) -> Option<label_modal::LabelModal> {
    let label = focused_label(app)?;
    Some(label_modal::LabelModal::open_edit(&label))
}

fn build_label_remove_modal(app: &App) -> Option<label_modal::LabelModal> {
    let label = focused_label(app)?;
    let usage = focused_label_usage(app, &label);
    Some(label_modal::LabelModal::open_remove(&label, usage))
}

/// Every keystroke while a Labels modal is open. Mirrors
/// `handle_group_modal_key`, minus the two selector fields Groups has
/// (profile dropdown, tags chip picker) — a label has no such field, so
/// `←`/`→` and `Space` carry no special meaning and Space is a literal
/// character everywhere it lands in a text field.
async fn handle_label_modal_key(
    app: &mut App,
    key: KeyEvent,
    poller: &IpcPoller,
    config_path: &Path,
) {
    let Some(mut modal) = app.labels.modal.take() else {
        return;
    };

    use label_modal::{FormField, Stage};

    if modal.is_submitted() {
        // Any keypress in the submitted stage closes the modal.
        return;
    }

    // `Ctrl+s` saves from anywhere on an Archetype-F form.
    //
    // Checked BEFORE the field dispatch, not as a guarded `Char('s')` arm:
    // the `KeyCode::Char(c)` catch-all at the bottom of the form match is
    // what used to append a literal `s` to the focused buffer, so an arm
    // placed after it would be dead. "From anywhere" means ahead of the
    // field dispatch entirely. Mirrors the check in
    // `handle_edit_mode_key`, including the `S` spelling some terminals
    // send.
    //
    // Confirm stages are Archetype C and keep `[y]` / `[n]` — the chord
    // must not reach them, hence the stage guard.
    //
    // No tag valve to carry here: `label_modal` has no
    // `tags_pending_new` (grep returns zero), unlike the subnet / group /
    // profile forms. Same for `local_dns_modal`.
    if matches!(key.code, KeyCode::Char('s') | KeyCode::Char('S'))
        && key.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(modal.stage, Stage::EditingForm(_))
    {
        submit_label_modal(app, modal, poller, config_path).await;
        return;
    }

    match &mut modal.stage {
        Stage::EditingForm(form) => {
            match key.code {
                KeyCode::Esc => {
                    // Drop the modal — returning without re-stashing closes it.
                    return;
                }
                KeyCode::Tab | KeyCode::Down => {
                    form.focused = next_editable_label_field(form.focused, form.mode);
                    form.error_message = None;
                }
                KeyCode::BackTab | KeyCode::Up => {
                    form.focused = prev_editable_label_field(form.focused, form.mode);
                    form.error_message = None;
                }
                KeyCode::Enter => {
                    if form.focused == FormField::Cancel {
                        // Discard button → close without saving (same as Esc).
                        return;
                    }
                    // Enter submits from any other field. A pre-flight or
                    // apply error keeps the form open with an inline
                    // message instead of dropping the operator's input, so
                    // a stray Enter is recoverable.
                    submit_label_modal(app, modal, poller, config_path).await;
                    return;
                }
                KeyCode::Char(' ') => match form.focused {
                    FormField::Submit => {
                        submit_label_modal(app, modal, poller, config_path).await;
                        return;
                    }
                    FormField::Cancel => {
                        return;
                    }
                    // A label has no selector field, so space is only ever
                    // a literal character. `display_name` in particular
                    // NEEDS it: the live values this vocabulary exists to
                    // adopt include "Apple TV".
                    _ => {
                        if let Some(buf) = label_text_field_buf(form) {
                            buf.push(' ');
                            form.error_message = None;
                        }
                    }
                },
                KeyCode::Backspace => {
                    if let Some(buf) = label_text_field_buf(form) {
                        buf.pop();
                        form.error_message = None;
                    }
                }
                // **The CONTROL guard is not decoration.** The footer, while
                // this form is open, advertises the shared modal grammar —
                // which names `Ctrl+s`. This modal saves on Enter, so
                // `Ctrl+s` does nothing; without the mask it would do
                // something worse than nothing and type an `s` into
                // whichever field had focus. Groups carries the same
                // advertised key and pins that it does not save, but not
                // that it does not corrupt the buffer.
                KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    if let Some(buf) = label_text_field_buf(form) {
                        buf.push(c);
                        form.error_message = None;
                    }
                }
                _ => {}
            }
            app.labels.modal = Some(modal);
        }
        Stage::ConfirmingRemove(_) => match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                submit_label_modal(app, modal, poller, config_path).await;
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                // Drop the modal — returning without re-stashing.
            }
            _ => {
                app.labels.modal = Some(modal);
            }
        },
        Stage::Submitted(_) => {
            // Already handled above.
        }
    }
}

/// Skip the Id field on Edit — immutable after creation, and the renderer
/// draws it as a plain row that can never take focus. There is no Add-mode
/// skip here: unlike Groups, every field a label has is available in both
/// modes.
fn next_editable_label_field(
    f: label_modal::FormField,
    mode: label_modal::FormMode,
) -> label_modal::FormField {
    let mut next = f.next();
    if mode == label_modal::FormMode::Edit && next == label_modal::FormField::Id {
        next = next.next();
    }
    next
}

fn prev_editable_label_field(
    f: label_modal::FormField,
    mode: label_modal::FormMode,
) -> label_modal::FormField {
    let mut prev = f.prev();
    if mode == label_modal::FormMode::Edit && prev == label_modal::FormField::Id {
        prev = prev.prev();
    }
    prev
}

/// Mutable reference to the buffer behind the focused text-input field.
/// `None` for the two actions and for `Id` on Edit.
fn label_text_field_buf(form: &mut label_modal::AddForm) -> Option<&mut String> {
    use label_modal::{FormField, FormMode};
    match form.focused {
        FormField::Id if form.mode == FormMode::Add => Some(&mut form.id),
        FormField::Id => None, // read-only on Edit
        FormField::DisplayName => Some(&mut form.display_name),
        FormField::Description => Some(&mut form.description),
        FormField::Submit | FormField::Cancel => None,
    }
}

/// Submit path for all three Label modals. Branches on the stage:
///
/// - Add → `add_inner` once.
/// - Edit → `submit_label_edit`: one `set_inner` per changed field.
/// - Remove → `remove_inner` once.
///
/// On a real write, fires `attempt_reload` **once** and re-reads the cached
/// config. That re-read is not decoration: Labels is in the offline cohort
/// (`poll_active_leaf` is a no-op for this leaf) and `tabs::labels::render`
/// reads `loaded_config` every frame, so without it a successful save
/// renders an unchanged table and reads to the operator as a failed write.
///
/// **The reload is keyed on "the disk changed", not on "the submit
/// succeeded", and the difference is a real state.** An Edit is one
/// `set_inner` per changed field, so `display_name` can land and
/// `description` be refused in the same Save. Keying the reload on success
/// left the table showing the old name while the file held the new one —
/// and the operator who trusts the table then reopens Edit onto a stale
/// snapshot. Partial writes therefore reload **and** re-anchor
/// `form.original` to what landed, so a retry diffs against the file
/// rather than against history.
async fn submit_label_modal(
    app: &mut App,
    mut modal: label_modal::LabelModal,
    poller: &IpcPoller,
    config_path: &Path,
) {
    use crate::cli::commands::labels::{add_inner, remove_inner};
    use label_modal::{Stage, SubmitOutcome};

    // `landed` names the fields that actually reached disk. Empty means the
    // file is untouched; **non-empty alongside a `Failed` outcome is the
    // partial write** this function exists to handle honestly.
    let (outcome, landed): (SubmitOutcome, Vec<String>) = match &modal.stage {
        Stage::EditingForm(form) => match form.try_resolve() {
            Err(msg) => (SubmitOutcome::Failed(msg), Vec::new()),
            Ok(resolved) => match form.mode {
                label_modal::FormMode::Add => {
                    match add_inner(
                        config_path,
                        &resolved.id,
                        form.kind,
                        Some(&resolved.display_name),
                        // Empty means "no description" on Add — passing
                        // `Some("")` would write an empty key instead of
                        // omitting it.
                        Some(resolved.description.as_str()).filter(|d| !d.is_empty()),
                        None,
                    ) {
                        // Report the id the writer says it wrote, not the
                        // one the form holds. They agree today; a toast
                        // that echoes the operator's own input back is
                        // reporting the request, not the outcome.
                        Ok(report) => {
                            tracing::info!(
                                target: "audit",
                                action = "label.add",
                                surface = "tui",
                                id = %report.id,
                                kind = %form.kind,
                                source_file = %report.target_path.display(),
                                "TUI mutation"
                            );
                            (
                                SubmitOutcome::Ok(format!(
                                    "added {} {}",
                                    form.kind.as_str(),
                                    report.id
                                )),
                                vec!["id".to_string()],
                            )
                        }
                        Err(e) => (SubmitOutcome::Failed(e.to_string()), Vec::new()),
                    }
                }
                label_modal::FormMode::Edit => match form.original.as_ref() {
                    Some(original) => {
                        submit_label_edit(config_path, form.kind, original, &resolved)
                    }
                    // The Add/Edit constructors keep `mode == Edit` and
                    // `original.is_some()` in lock-step; degrade a broken
                    // invariant to a footer error instead of a panic that
                    // would unwind out of the dashboard's main task.
                    None => (
                        SubmitOutcome::Failed(
                            "internal error: edit modal lost its original snapshot".into(),
                        ),
                        Vec::new(),
                    ),
                },
            },
        },
        Stage::ConfirmingRemove(rc) => {
            // `kind` is passed, never `None`: the pane the operator is
            // looking at IS the disambiguation, and letting `select_label`
            // resolve a bare id would refuse an id that legally exists
            // under two kinds — a refusal the operator could not act on
            // from here.
            match remove_inner(config_path, &rc.id, Some(rc.kind), None) {
                Ok(report) => {
                    tracing::info!(
                        target: "audit",
                        action = "label.delete",
                        surface = "tui",
                        id = %report.id,
                        kind = %rc.kind,
                        source_file = %report.target_path.display(),
                        "TUI mutation"
                    );
                    (
                        SubmitOutcome::Ok(format!("removed {} {}", rc.kind.as_str(), report.id)),
                        vec!["id".to_string()],
                    )
                }
                // **`labels::remove_inner` is NOT `groups::remove_inner`.**
                // Groups returns `Ok(None)` for an absent id and the caller
                // turns that into a message; labels has no such variant —
                // its own doc calls an already-absent label an error "so a
                // caller holding a row that has since vanished learns it
                // instead of being told the removal succeeded". That is the
                // right answer for a TUI and it arrives here as `Err`,
                // together with every other refusal. Recognise the
                // not-found spelling so the operator gets the reason rather
                // than a bare repeat of the verb's words.
                Err(e) => {
                    let msg = e.to_string();
                    let text = if msg.starts_with("label not found") {
                        format!(
                            "{} \"{}\" is already gone — the table was stale",
                            rc.kind.as_str(),
                            rc.id
                        )
                    } else {
                        msg
                    };
                    // A refused remove writes nothing — `remove_if_present`
                    // bails before touching the file — so the disk is
                    // untouched and there is nothing to reload.
                    (SubmitOutcome::Failed(text), Vec::new())
                }
            }
        }
        Stage::Submitted(_) => return,
    };

    // **The disk changed, so refresh — whatever the verdict was.** This runs
    // before the form-failure branch below on purpose: a partial Edit is a
    // `Failed` outcome over a file that really did change, and keying the
    // refresh on success left the table rendering the old row.
    let wrote = !landed.is_empty();
    if wrote {
        // Re-anchor the form to what landed, so a retry diffs against the
        // file rather than against a snapshot the file no longer matches —
        // otherwise the operator's second Save re-writes a field that is
        // already correct and audits it as a change.
        if let Stage::EditingForm(form) = &mut modal.stage {
            // Resolve first, then take the mutable borrow: `try_resolve`
            // reads the whole form.
            if let Ok(resolved) = form.try_resolve() {
                if let Some(original) = form.original.as_mut() {
                    for field in &landed {
                        match field.as_str() {
                            "display_name" => original.display_name = resolved.display_name.clone(),
                            "description" => original.description = resolved.description.clone(),
                            _ => {}
                        }
                    }
                }
            }
        }
        refresh_after_label_write(app, poller, config_path).await;
    }

    // A form (Add/Edit) failure — pre-flight validation or a validator
    // rejection — keeps the modal open with the message on the inline
    // validation line instead of dropping to the terminal "failed" screen.
    // The operator fixes the offending field and re-submits without
    // retyping the rest. Remove failures still finish (their confirm
    // screen has no form to keep).
    if let SubmitOutcome::Failed(msg) = &outcome {
        if let Stage::EditingForm(form) = &mut modal.stage {
            app.status_err(format!("label modal: {msg}"));
            form.error_message = Some(msg.clone());
            app.labels.modal = Some(modal);
            return;
        }
    }

    match &outcome {
        SubmitOutcome::Ok(msg) => app.status_ok(msg.clone()),
        SubmitOutcome::Failed(msg) => app.status_err(format!("label modal: {msg}")),
    }
    modal.finish(outcome);
    app.labels.modal = Some(modal);
}

/// Tell the daemon, then re-read the cached config.
///
/// Split out because it is reached from two places that used to be one: a
/// clean save and a **partially applied** one. Labels is in the offline
/// cohort — `poll_active_leaf` is a no-op for this leaf and
/// `tabs::labels::render` reads `loaded_config` every frame — so this
/// assignment IS how the table learns the file moved.
async fn refresh_after_label_write(app: &mut App, poller: &IpcPoller, config_path: &Path) {
    use crate::cli::commands::ipc_reload::{attempt_reload, ReloadOutcome};
    match attempt_reload(poller.socket_path()).await {
        ReloadOutcome::Reloaded => {}
        ReloadOutcome::DaemonUnreachable => {
            app.status_err(
                "label saved on disk — daemon not running, will activate on next start".into(),
            );
        }
        ReloadOutcome::NoToken { .. } => {
            app.status_err(
                "label saved on disk but no admin token is available to request a reload".into(),
            );
        }
        ReloadOutcome::ReloadFailed(msg) => {
            app.status_err(format!("label saved but daemon rejected reload: {msg}"));
        }
    }
    app.loaded_config = load_v1_config(config_path);
    // A no-op for Leaf::Labels today (see the offline cohort in
    // `poll_active_leaf`), kept so a future leaf that does poll cannot
    // acquire a stale-until-next-tick bug by inheriting this path.
    poll_active_leaf(app, poller).await;
}

/// Apply the diff between `original` and `resolved` in one validated write.
///
/// **Was per-field, non-atomic, and that was the last surviving instance
/// of the same partial-apply shape already closed for Subnets:**
/// `labels::set_inner` per changed field meant a
/// validator refusal on the second field left the first one written, so
/// Discard stopped discarding. `labels::set_fields_inner` — new,
/// mirroring `groups::set_fields_inner` / `subnets::set_fields_inner` —
/// diffs the whole field vector into one `write_value_validated` call, so
/// this is now the `submit_subnet_edit` / `submit_group_edit` shape: a
/// single write, so nothing landed — Discard genuinely discards, with no
/// partial-apply caveat needed.
///
/// Field order (display_name, then description) is no longer
/// load-bearing — it was pinned only because a partial apply needed one
/// field to have landed before the other could fail, and one write has no
/// "before" to land in.
fn submit_label_edit(
    config_path: &Path,
    kind: crate::config::schema::LabelKind,
    original: &label_modal::OriginalSnapshot,
    resolved: &label_modal::ResolvedForm,
) -> (label_modal::SubmitOutcome, Vec<String>) {
    use crate::cli::commands::labels::set_fields_inner;
    use label_modal::SubmitOutcome;

    let mut pending: Vec<(&str, &str)> = Vec::new();
    if original.display_name != resolved.display_name {
        pending.push(("display_name", resolved.display_name.as_str()));
    }
    if original.description != resolved.description {
        pending.push(("description", resolved.description.as_str()));
    }

    if pending.is_empty() {
        return (
            SubmitOutcome::Ok(format!("{} {} unchanged", kind.as_str(), original.id)),
            Vec::new(),
        );
    }

    match set_fields_inner(config_path, &original.id, Some(kind), &pending, None) {
        Ok(report) => {
            tracing::info!(
                target: "audit",
                action = "label.set",
                surface = "tui",
                id = %report.id,
                kind = %kind,
                fields = %report.fields.join(","),
                source_file = %report.target_path.display(),
                "TUI mutation"
            );
            // **The target file goes in the audit line, not on the
            // screen**, and that was decided by looking at the screen.
            // `prose_row` truncates at the modal's 62-column body, and
            // "updated device-type apple-tv (display_name, description)"
            // already spends 52 of them — so an appended path was
            // ellipsed away on a real terminal every time, taking the
            // trailing words of the field list with it. `tracing` keeps
            // the path in a record that does not have 62 columns.
            let msg = format!(
                "updated {} {} ({})",
                kind.as_str(),
                original.id,
                report.fields.join(", ")
            );
            (SubmitOutcome::Ok(msg), report.fields)
        }
        Err(e) => (
            SubmitOutcome::Failed(format!("edit failed: {e}")),
            Vec::new(),
        ),
    }
}

/// Keys of the Groups leaf: `↑`/`↓` move the cursor and
/// `a`/`e`/`d` open the Add / Edit / Delete modal.
///
/// **The leaf's earlier structural read-only is deliberately over.** That
/// property was stated as *"the signature takes neither `config_path` nor
/// `IpcPoller`, so adding a write path would be a visible change rather
/// than a quiet one"* — and the signature is still exactly that, because
/// the openers only need `&mut App`. Every write lives in
/// `handle_group_modal_key` / `submit_group_modal`, which do take both.
/// The claim was never "this leaf will not write"; it was "a write cannot
/// arrive here unannounced", and this is the announcement.
///
/// **`a` is reachable with zero groups, and the ordering here is the
/// whole point.** The empty-list guard used to sit above the key match,
/// so bolting the openers on below it would have left Add dead on exactly
/// the config where it matters — a config with no groups is the one an
/// operator most needs to create the first one on. That is the same shape
/// as `open_field_picker`'s empty-list no-op, which is *why* no TUI path
/// used to be able to create a group. `e` / `d`
/// still require a resolved selection: there is nothing to edit or
/// remove.
fn handle_groups_key(app: &mut App, key: KeyEvent) {
    // **"No config" is not "a config with no groups", and conflating them
    // makes the modal lie.** A config that failed to parse yields no
    // profile snapshot, so an Add form opened over it resolves to
    // "no profiles defined — create one first" — which is false: the
    // operator's profiles exist, the file did not load, and `add_inner`
    // would fail on `load_config` no matter what they typed. The leaf is
    // already painting "could not load config — fix it and press r to
    // retry"; every key stays inert until it does.
    //
    // This guard is therefore ABOVE `a`, while the zero-groups guard
    // below it is not. They are different predicates.
    let Some(loaded) = app.loaded_config.as_ref() else {
        app.leaf_key_unhandled = true;
        return;
    };
    let ids: Vec<String> = loaded
        .config
        .groups
        .iter()
        .map(|g| g.id.as_str().to_string())
        .collect();

    // Add next, and before the empty-list guard: it is the one verb whose
    // whole purpose is to work when the list is empty.
    if key.code == KeyCode::Char('a') {
        app.groups.modal = Some(build_group_add_modal(app));
        return;
    }

    if ids.is_empty() {
        app.leaf_key_unhandled = true;
        return;
    }

    match key.code {
        // Enter is the primary action on the focused row; on Groups
        // that is edit. Same branch as `e`, no new modal.
        KeyCode::Enter | KeyCode::Char('e') => {
            if let Some(modal) = build_group_edit_modal(app) {
                app.groups.modal = Some(modal);
            }
            return;
        }
        KeyCode::Char('d') | KeyCode::Delete => {
            if let Some(modal) = build_group_remove_modal(app) {
                app.groups.modal = Some(modal);
            }
            return;
        }
        _ => {}
    }

    let cur = app
        .groups
        .selected_id
        .as_deref()
        .and_then(|want| ids.iter().position(|i| i == want))
        .unwrap_or(0);
    // Clamp, not wrap. `%` used to teleport the operator from the
    // last group to the first, which reads as a lost cursor rather than as
    // navigation. Walking off the end is now a no-op.
    let last = ids.len() - 1;
    let next = match key.code {
        KeyCode::Down => (cur + 1).min(last),
        KeyCode::Up => cur.saturating_sub(1),
        KeyCode::Home => 0,
        KeyCode::End => last,
        KeyCode::PageDown => (cur + NAV_PAGE).min(last),
        KeyCode::PageUp => cur.saturating_sub(NAV_PAGE),
        _ => {
            app.leaf_key_unhandled = true;
            return;
        }
    };
    app.groups.selected_id = Some(ids[next].clone());
}

// ── Groups modal openers, key handler and submit path ─────────────────
//
// No new IPC verb. The submit path replicates the
// `groups.rs` pipeline through the **sync inner writers** and fires a
// single `attempt_reload` afterwards. `run_add` / `run_set` /
// `run_remove` are forbidden — they `println!`, and a `println!` on the alternate
// screen in raw mode staircases one column per line.

/// The group the modal openers act on: the anchored selection, else the
/// first row — matching what `tabs::groups::render_master` highlights, so
/// `e` and `d` always land on the row the operator can see is selected.
fn focused_group(app: &App) -> Option<crate::config::schema::Group> {
    let groups = app.loaded_config.as_ref().map(|l| &l.config.groups)?;
    tabs::groups::resolve_selected_index(groups, app.groups.selected_id.as_deref())
        .and_then(|i| groups.get(i))
        .or_else(|| groups.first())
        .cloned()
}

/// Snapshot of profile ids at modal-open time (capture-at-open
/// invariant). `Group.profile` is mandatory, so an empty snapshot means
/// the form cannot resolve at all — `try_resolve` says so by name rather
/// than letting `add_inner` fail on an empty string.
fn snapshot_group_profile_ids(app: &App) -> Vec<String> {
    app.loaded_config
        .as_ref()
        .map(|loaded| {
            loaded
                .config
                .profiles
                .keys()
                .map(|id| id.as_str().to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn build_group_add_modal(app: &App) -> group_modal::GroupModal {
    group_modal::GroupModal::open_add(snapshot_group_profile_ids(app), 0)
}

fn build_group_edit_modal(app: &App) -> Option<group_modal::GroupModal> {
    let g = focused_group(app)?;
    let profiles = snapshot_group_profile_ids(app);
    Some(group_modal::GroupModal::open_edit(&g, profiles))
}

fn build_group_remove_modal(app: &App) -> Option<group_modal::GroupModal> {
    let g = focused_group(app)?;
    Some(group_modal::GroupModal::open_remove(&g))
}

/// Drive the Groups modal's state machine on each keypress. Mirrors
/// `handle_subnet_modal_key` field for field; the only divergence is the
/// text-buffer table, since a group's membership field is `devices`
/// rather than `cidrs`.
async fn handle_group_modal_key(
    app: &mut App,
    key: KeyEvent,
    poller: &IpcPoller,
    config_path: &Path,
) {
    let Some(mut modal) = app.groups.modal.take() else {
        return;
    };

    use group_modal::{FormField, Stage};

    if modal.is_submitted() {
        // Any keypress in the submitted stage closes the modal.
        return;
    }

    // `Ctrl+s` saves from anywhere on an Archetype-F form.
    //
    // Checked BEFORE the field dispatch, not as a guarded `Char('s')` arm:
    // the `KeyCode::Char(c)` catch-all at the bottom of the form match is
    // what used to append a literal `s` to the focused buffer, so an arm
    // placed after it would be dead. "From anywhere" means ahead of the
    // field dispatch entirely. Mirrors the check in
    // `handle_edit_mode_key`, including the `S` spelling some terminals
    // send.
    //
    // Confirm stages are Archetype C and keep `[y]` / `[n]` — the chord
    // must not reach them, hence the stage guard.
    if matches!(key.code, KeyCode::Char('s') | KeyCode::Char('S'))
        && key.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(modal.stage, Stage::EditingForm(_))
    {
        submit_group_modal(app, modal, poller, config_path).await;
        return;
    }

    match &mut modal.stage {
        Stage::EditingForm(form) => {
            match key.code {
                KeyCode::Esc => {
                    // Drop the modal — returning without re-stashing closes it.
                    return;
                }
                KeyCode::Tab | KeyCode::Down => {
                    form.focused = next_editable_group_field(form.focused, form.mode);
                    form.error_message = None;
                }
                KeyCode::BackTab | KeyCode::Up => {
                    form.focused = prev_editable_group_field(form.focused, form.mode);
                    form.error_message = None;
                }
                KeyCode::Enter => {
                    if form.focused == FormField::Cancel {
                        // Discard button → close without saving (same as Esc).
                        return;
                    } else {
                        // Otherwise Enter submits from any field. A pre-flight
                        // or apply error keeps the form open with an inline
                        // message instead of dropping the operator's input, so
                        // a stray Enter is recoverable.
                        submit_group_modal(app, modal, poller, config_path).await;
                        return;
                    }
                }
                // These were `if Profile {...} else if Tags {...}`.
                // With the Tags branch gone the lone `if` trips
                // `collapsible_if` under `-D warnings`, so the condition
                // moves onto the arm. Behaviour is unchanged: a Left/Right
                // on any other field fell through the empty `if` before and
                // falls through to the `_ => {}` arm now — both no-ops.
                KeyCode::Right
                    if form.focused == FormField::Profile && !form.profiles_snapshot.is_empty() =>
                {
                    let n = form.profiles_snapshot.len();
                    form.profile_idx = (form.profile_idx + 1) % n;
                }
                KeyCode::Left
                    if form.focused == FormField::Profile && !form.profiles_snapshot.is_empty() =>
                {
                    let n = form.profiles_snapshot.len();
                    form.profile_idx = (form.profile_idx + n - 1) % n;
                }
                KeyCode::Char(' ') => match form.focused {
                    // Profile is the only selector — Space cycles it forward.
                    FormField::Profile => {
                        if !form.profiles_snapshot.is_empty() {
                            let n = form.profiles_snapshot.len();
                            form.profile_idx = (form.profile_idx + 1) % n;
                        }
                    }
                    FormField::Submit => {
                        submit_group_modal(app, modal, poller, config_path).await;
                        return;
                    }
                    FormField::Cancel => {
                        return;
                    }
                    // For text fields, treat space as a literal char.
                    _ => {
                        if let Some(buf) = group_text_field_buf(form) {
                            buf.push(' ');
                            form.error_message = None;
                        }
                    }
                },
                KeyCode::Backspace => {
                    if let Some(buf) = group_text_field_buf(form) {
                        buf.pop();
                        form.error_message = None;
                    }
                }
                KeyCode::Char(c) => {
                    if let Some(buf) = group_text_field_buf(form) {
                        buf.push(c);
                        form.error_message = None;
                    }
                }
                _ => {}
            }
            app.groups.modal = Some(modal);
        }
        Stage::ConfirmingRemove(_) => match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                submit_group_modal(app, modal, poller, config_path).await;
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                // Drop the modal — returning without re-stashing.
            }
            _ => {
                app.groups.modal = Some(modal);
            }
        },
        Stage::Submitted(_) => {
            // Already handled above.
        }
    }
}

/// Skip the Id field on Edit — immutable after creation, so focus must
/// not land on a field the operator cannot change.
///
/// The second skip is gone: `FormField::Tags` was Edit-only and
/// stepped over in Add, and with the picker gone both modes walk the same
/// ring bar `Id`.
fn next_editable_group_field(
    f: group_modal::FormField,
    mode: group_modal::FormMode,
) -> group_modal::FormField {
    let mut next = f.next();
    if mode == group_modal::FormMode::Edit && next == group_modal::FormField::Id {
        next = next.next();
    }
    next
}

fn prev_editable_group_field(
    f: group_modal::FormField,
    mode: group_modal::FormMode,
) -> group_modal::FormField {
    let mut prev = f.prev();
    if mode == group_modal::FormMode::Edit && prev == group_modal::FormField::Id {
        prev = prev.prev();
    }
    prev
}

/// Mutable reference to the buffer behind the focused text-input field.
/// `None` for non-text fields (Profile dropdown and the two actions).
fn group_text_field_buf(form: &mut group_modal::AddForm) -> Option<&mut String> {
    use group_modal::{FormField, FormMode};
    match form.focused {
        FormField::Id if form.mode == FormMode::Add => Some(&mut form.id),
        FormField::Id => None, // read-only on Edit
        FormField::DisplayName => Some(&mut form.display_name),
        FormField::Devices => Some(&mut form.devices),
        FormField::Priority => Some(&mut form.priority_input),
        FormField::Profile | FormField::Submit | FormField::Cancel => None,
    }
}

/// Submit path for all three Group modals. Branches on the stage:
///
/// - Add → `add_inner` once.
/// - Edit → `submit_group_edit`: one atomic scalar batch, then the tag
///   delta.
/// - Remove → `remove_inner` once.
///
/// On a real write, fires the shared `attempt_reload` **once** and re-reads the
/// cached config. That re-read is not decoration: Groups is in the
/// offline cohort (`poll_active_leaf` is a no-op for this leaf), so
/// without it a successful save renders an unchanged table and reads to
/// the operator as a failed write.
async fn submit_group_modal(
    app: &mut App,
    mut modal: group_modal::GroupModal,
    poller: &IpcPoller,
    config_path: &Path,
) {
    use crate::cli::commands::groups::add_inner;
    use crate::cli::commands::ipc_reload::{attempt_reload, ReloadOutcome};
    use group_modal::{Stage, SubmitOutcome};

    let outcome: SubmitOutcome = match &modal.stage {
        Stage::EditingForm(form) => match form.try_resolve() {
            Err(msg) => SubmitOutcome::Failed(msg),
            Ok(resolved) => match form.mode {
                group_modal::FormMode::Add => {
                    match add_inner(
                        config_path,
                        &resolved.id,
                        Some(&resolved.display_name),
                        &resolved.profile,
                        Some(resolved.priority),
                        &resolved.devices,
                        None,
                    ) {
                        // Report the id the writer says it wrote, not the
                        // one the form holds. They agree today; a toast
                        // that echoes the operator's own input back is
                        // reporting the request, not the outcome.
                        Ok(report) => {
                            tracing::info!(
                                target: "audit",
                                action = "group.add",
                                surface = "tui",
                                id = %report.id,
                                profile = %resolved.profile,
                                source_file = %report.target_path.display(),
                                "TUI mutation"
                            );
                            SubmitOutcome::Ok(format!("added group {}", report.id))
                        }
                        Err(e) => SubmitOutcome::Failed(e.to_string()),
                    }
                }
                group_modal::FormMode::Edit => match form.original.as_ref() {
                    Some(original) => submit_group_edit(config_path, original, &resolved),
                    // The Add/Edit constructors keep `mode == Edit` and
                    // `original.is_some()` in lock-step; degrade a broken
                    // invariant to a footer error instead of a panic that
                    // would unwind out of the dashboard's main task.
                    None => SubmitOutcome::Failed(
                        "internal error: edit modal lost its original snapshot".into(),
                    ),
                },
            },
        },
        Stage::ConfirmingRemove(rc) => {
            match crate::cli::commands::groups::remove_inner(config_path, &rc.id, None) {
                Ok(Some(report)) => {
                    tracing::info!(
                        target: "audit",
                        action = "group.delete",
                        surface = "tui",
                        id = %report.id,
                        source_file = %report.target_path.display(),
                        "TUI mutation"
                    );
                    SubmitOutcome::Ok(format!("removed group {}", report.id))
                }
                // `remove_inner` returns `Ok(None)` for an absent id —
                // idempotent by verbs-02. From the TUI that means the row
                // the operator was looking at is already gone, which is
                // worth saying rather than reporting a success that wrote
                // nothing.
                Ok(None) => {
                    SubmitOutcome::Failed(format!("group '{}' not found — already removed?", rc.id))
                }
                Err(e) => SubmitOutcome::Failed(e.to_string()),
            }
        }
        Stage::Submitted(_) => return,
    };

    // A form (Add/Edit) failure — pre-flight validation or an
    // apply/validator rejection — keeps the modal open with the message on
    // the inline validation line instead of dropping to the terminal
    // "failed" screen. The operator fixes the offending field and
    // re-submits without retyping the rest. Remove failures still finish
    // (their confirm screen has no form to keep).
    if let SubmitOutcome::Failed(msg) = &outcome {
        if let Stage::EditingForm(form) = &mut modal.stage {
            app.status_err(format!("group modal: {msg}"));
            form.error_message = Some(msg.clone());
            app.groups.modal = Some(modal);
            return;
        }
    }

    let was_ok = matches!(outcome, SubmitOutcome::Ok(_));
    match &outcome {
        SubmitOutcome::Ok(msg) => app.status_ok(msg.clone()),
        SubmitOutcome::Failed(msg) => app.status_err(format!("group modal: {msg}")),
    }
    modal.finish(outcome);
    app.groups.modal = Some(modal);

    if was_ok {
        let outcome = attempt_reload(poller.socket_path()).await;
        // The reload arms REPLACE the status set above. `Reloaded` is the
        // one arm that stays silent and therefore keeps it.
        match outcome {
            ReloadOutcome::Reloaded => {}
            ReloadOutcome::DaemonUnreachable => {
                app.status_err(
                    "group saved on disk — daemon not running, will activate on next start".into(),
                );
            }
            ReloadOutcome::NoToken { .. } => {
                app.status_err(
                    "group saved on disk but no admin token is available to request a reload"
                        .into(),
                );
            }
            ReloadOutcome::ReloadFailed(msg) => {
                app.status_err(format!("group saved but daemon rejected reload: {msg}"));
            }
        }
        // Mandatory, not symmetry with Subnets: this leaf renders from
        // `loaded_config` and never polls, so this assignment IS how the
        // table learns the write happened.
        app.loaded_config = load_v1_config(config_path);
        // A no-op for Leaf::Groups today (see the offline cohort in
        // `poll_active_leaf`), kept so a future leaf that does poll cannot
        // acquire a stale-until-next-tick bug by inheriting this path.
        poll_active_leaf(app, poller).await;
    }
}

/// Apply the diff between `original` and `resolved`.
///
/// Every changed scalar field (display_name / profile / priority /
/// devices) lands in a single `set_fields_inner` write, or none do.
///
/// **That is the whole story again.** A Save used to be TWO
/// writes: the scalar batch, then a `tags` delta through
/// `apply_tags_inner`, which could not join the batch because it was a
/// different primitive (add-set / remove-set, not a replace). That path
/// could half-land, so the outcome had to distinguish "nothing was
/// written" from "the rename landed and the tags did not".
///
/// An earlier change had already replaced the second write with an unconditional
/// `TAGS_RETIRED` refusal taken BEFORE the scalar one — which turned the
/// picker into a trap: an operator who renamed a group and also touched
/// the tag field lost the rename, for a field that decided nothing.
///
/// Both are gone. `ResolvedForm` has no `tags`, so there is no delta to
/// diff, refuse, or half-apply, and the atomicity is structural.
///
/// Structurally identical to `submit_subnet_edit`, deliberately: the same
/// hazard was already solved once and a second shape would be a second
/// thing to keep right.
fn submit_group_edit(
    config_path: &Path,
    original: &group_modal::OriginalSnapshot,
    resolved: &group_modal::ResolvedForm,
) -> group_modal::SubmitOutcome {
    use crate::cli::commands::groups::set_fields_inner;
    use group_modal::SubmitOutcome;

    let mut changes: Vec<(&str, String)> = Vec::new();
    if original.display_name != resolved.display_name {
        changes.push(("display_name", resolved.display_name.clone()));
    }
    if original.devices != resolved.devices {
        changes.push(("devices", resolved.devices.join(",")));
    }
    if original.profile != resolved.profile {
        changes.push(("profile", resolved.profile.clone()));
    }
    if original.priority != resolved.priority {
        changes.push(("priority", resolved.priority.to_string()));
    }

    let mut messages: Vec<String> = Vec::new();

    if !changes.is_empty() {
        let fields: Vec<(&str, &str)> = changes.iter().map(|(f, v)| (*f, v.as_str())).collect();
        match set_fields_inner(config_path, &resolved.id, &fields, None) {
            Ok(report) => {
                tracing::info!(
                    target: "audit",
                    action = "group.update",
                    surface = "tui",
                    id = %report.id,
                    fields = %report.fields.join(","),
                    source_file = %report.target_path.display(),
                    "TUI mutation"
                );
                let n = report.fields.len();
                messages.push(format!(
                    "{n} field{} updated",
                    if n == 1 { "" } else { "s" }
                ));
            }
            // A single write, so nothing landed — Discard genuinely
            // discards, with no partial-apply caveat needed.
            Err(e) => return SubmitOutcome::Failed(format!("edit failed: {e}")),
        }
    }

    if messages.is_empty() {
        return SubmitOutcome::Ok(format!("group {} unchanged", resolved.id));
    }
    SubmitOutcome::Ok(format!(
        "edited group {}: {}",
        resolved.id,
        messages.join(", ")
    ))
}

/// `logs-tab`: keys of the [`Leaf::Logs`] viewer.
///
/// Scrolling is `tabs::file`'s convention verbatim — one line on the
/// arrows, [`NAV_PAGE`] on the page keys, `Home`/`End` to the ends, every
/// bound through the same saturating `u16` conversion. The filters are
/// the shared filter card's: `/` opens the search buffer, `f` cycles the
/// severity chip, `R` clears both.
///
/// Every filter change resets `scroll_offset`. The daemon applies the
/// filters during its own walk, so the next poll returns a **different
/// set of rows** — an offset minted against the previous set points into
/// a page that no longer exists.
fn handle_logs_key(app: &mut App, key: KeyEvent) {
    let last = tabs::logs::last_row(app);
    let page = tabs::logs::page_step();
    match key.code {
        KeyCode::Char('/') => {
            app.input_mode =
                InputMode::FilterLogs(app.logs.filter_text.clone().unwrap_or_default());
        }
        KeyCode::Char('f') => {
            app.logs.level_filter = app.logs.level_filter.next();
            app.logs.scroll_offset = 0;
        }
        KeyCode::Char('R') => {
            app.logs.level_filter = crate::tui::app::LogsLevelFilter::All;
            app.logs.filter_text = None;
            app.logs.scroll_offset = 0;
        }
        KeyCode::Down => {
            app.logs.scroll_offset = app.logs.scroll_offset.saturating_add(1).min(last);
        }
        KeyCode::Up => {
            app.logs.scroll_offset = app.logs.scroll_offset.saturating_sub(1);
        }
        KeyCode::Home => app.logs.scroll_offset = 0,
        KeyCode::End => app.logs.scroll_offset = last,
        KeyCode::PageDown => {
            app.logs.scroll_offset = app.logs.scroll_offset.saturating_add(page).min(last);
        }
        KeyCode::PageUp => {
            app.logs.scroll_offset = app.logs.scroll_offset.saturating_sub(page);
        }
        _ => {}
    }
}

/// Keys of the [`Leaf::File`] document viewer, split out of
/// `handle_settings_key`. Navigation inside the text (`/` jump, `↑`/`↓`
/// scroll) and the `$EDITOR` hand-off live here; the administration keys
/// (`t` / `b` / `R` / `Ctrl+r`) stayed on Settings.
///
/// `async` and takes an `IpcPoller` for exactly one reason: the `[e]` arm
/// writes the master config, and nothing watches config files
/// — a write reaches the daemon only through SIGHUP or an IPC reload this
/// handler requests itself.
async fn handle_file_key(app: &mut App, key: KeyEvent, poller: &IpcPoller, config_path: &Path) {
    // backup/restore modals above.
    if app.file.section_jump.is_some() {
        match key.code {
            KeyCode::Esc => {
                app.file.section_jump = None;
            }
            KeyCode::Enter => {
                let filter = app.file.section_jump.clone().unwrap_or_default();
                let (_, target) = file::filter_and_jump_target(
                    &app.file.config_text,
                    &app.file.sections,
                    &filter,
                );
                if let Some(offset) = target {
                    app.file.scroll_offset = offset;
                }
                app.file.section_jump = None;
            }
            KeyCode::Backspace => {
                if let Some(filter) = app.file.section_jump.as_mut() {
                    filter.pop();
                }
            }
            KeyCode::Char(c) => {
                if let Some(filter) = app.file.section_jump.as_mut() {
                    filter.push(c);
                }
            }
            _ => {}
        }
        return;
    }

    match key.code {
        KeyCode::Char('/') => {
            app.file.section_jump = Some(String::new());
        }
        KeyCode::Down => {
            // tui-wave1/settings-sidebar: no sidebar to navigate anymore —
            // scroll the config viewer by one line, clamped to content.
            let line_count = app.file.config_text.lines().count();
            app.file.scroll_offset = (app.file.scroll_offset + 1).min(
                // Saturating, not truncating: a bare `as` on a config
                // past 65 535 lines wraps the clamp to a small number
                // and pins scrolling near the top of the file.
                u16::try_from(line_count.saturating_sub(1)).unwrap_or(u16::MAX),
            );
        }
        KeyCode::Up => {
            app.file.scroll_offset = app.file.scroll_offset.saturating_sub(1);
        }
        // Jump / page. The File leaf scrolls text lines rather than
        // table rows, so it clamps against the same `line_count - 1` the
        // `↓` arm above uses, via the same saturating `u16` conversion (a
        // bare `as` on a >65 535-line config wraps the clamp to a small
        // number and pins scrolling near the top).
        KeyCode::Home | KeyCode::End | KeyCode::PageUp | KeyCode::PageDown => {
            let last = u16::try_from(app.file.config_text.lines().count().saturating_sub(1))
                .unwrap_or(u16::MAX);
            let page = u16::try_from(NAV_PAGE).unwrap_or(u16::MAX);
            app.file.scroll_offset = match key.code {
                KeyCode::Home => 0,
                KeyCode::End => last,
                KeyCode::PageDown => app.file.scroll_offset.saturating_add(page).min(last),
                _ => app.file.scroll_offset.saturating_sub(page),
            };
        }
        KeyCode::Char('e') => {
            // Open config in $EDITOR — we need to temporarily leave the
            // TUI. Capture step-by-step failures into the footer hint
            // instead of silently swallowing them: when something goes
            // wrong, the operator needs the exact next command. The first failure
            // in the chain wins so the operator sees the earliest break;
            // subsequent steps still run best-effort so the terminal
            // lands as close to a usable TUI as possible.
            let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());
            let mut step_error: Option<String> = None;

            // Pause the event-reader thread before handing the tty to
            // $EDITOR. Otherwise it keeps calling event::read() on the same
            // terminal — racing the editor per byte (dropped chars while editing
            // the master config) and queuing the bytes it steals as keys that
            // replay against the TUI on return (a swallowed `q` quits). Wait
            // (bounded, ~200ms) for the reader to ack `parked` before leaving raw
            // mode so no in-flight read consumes a byte; proceed best-effort if it
            // does not park in time (worst case degrades to the old race, no hang).
            // Resumed after the screen is restored below.
            app.reader_suspended
                .store(true, std::sync::atomic::Ordering::Release);
            for _ in 0..40 {
                if app.reader_parked.load(std::sync::atomic::Ordering::Acquire) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }

            if let Err(e) = disable_raw_mode() {
                step_error.get_or_insert(format!(
                    "could not leave raw mode before launching $EDITOR ({editor}): {e}. \
                     Editor output may be garbled. Press 'q' to exit and re-launch the dashboard."
                ));
            }
            if let Err(e) = execute!(std::io::stdout(), LeaveAlternateScreen) {
                step_error.get_or_insert(format!(
                    "could not leave alternate screen before launching $EDITOR ({editor}): {e}. \
                     Press 'q' to exit and re-launch the dashboard."
                ));
            }

            // Word-split $EDITOR so multi-token values (`code -w`,
            // `emacsclient -t`) spawn — first token is the program, the rest
            // are leading args before the config path. Reuses the CLI
            // `config edit` splitter so both $EDITOR shell-outs parse alike.
            // The full `editor` string is kept verbatim for the error messages.
            let (program, args) =
                crate::cli::commands::config::edit::split_editor_invocation(&editor);
            let editor_status = if program.is_empty() {
                // EDITOR was empty/all-whitespace (the `unwrap_or` above only
                // covers *unset*) — fall back to vi so `e` still does something.
                std::process::Command::new("vi").arg(config_path).status()
            } else {
                std::process::Command::new(&program)
                    .args(&args)
                    .arg(config_path)
                    .status()
            };
            if let Some(msg) = format_editor_failure(&editor, editor_status) {
                step_error.get_or_insert(msg);
            }

            if let Err(e) = enable_raw_mode() {
                step_error.get_or_insert(format!(
                    "could not re-enter raw mode after $EDITOR ({editor}): {e}. \
                     TUI input may be unreliable. Press 'q' to exit cleanly."
                ));
            }
            if let Err(e) = execute!(std::io::stdout(), EnterAlternateScreen) {
                step_error.get_or_insert(format!(
                    "could not re-enter alternate screen after $EDITOR ({editor}): {e}. \
                     TUI may render in scrollback. Press 'q' to exit cleanly."
                ));
            }

            // The screen is restored — let the reader resume reading the
            // tty. Any tick it owes for the elapsed editor session fires once on
            // resume (harmless — it just refreshes the just-edited config view).
            app.reader_suspended
                .store(false, std::sync::atomic::Ordering::Release);

            // Always reload config — last-write-wins. Even on a non-zero
            // editor exit the operator may have saved partial edits, and
            // the in-memory view must match the on-disk state.
            let (sections, text) = file::load_config(config_path);
            app.file.sections = sections;
            app.file.config_text = text;

            // The edit landed on the master config. Nothing watches it, so
            // this reload is what makes the operator's edit real; every
            // other leaf reads `loaded_config`, so that has to move too
            // — otherwise Subnets/Profiles/Rules/Local DNS/
            // Labels/Groups/Custom Lists keep rendering, and their modal
            // openers keep snapshotting, the pre-edit config until a
            // manual `[r]`/SIGHUP/restart. Invalid TOML makes
            // `load_v1_config` return `None`, same as `[r]` on a bad edit
            // today — every consuming tab then shows its own
            // "config unreadable" hint, which is correct.
            app.loaded_config = load_v1_config(config_path);
            refresh_auto_backup_view(app, config_path);

            use crate::cli::commands::ipc_reload::{attempt_reload, ReloadOutcome};

            // The editor's own failure outranks a reload message: it is
            // why there may be nothing new to reload.
            if let Some(msg) = step_error {
                app.status_err(msg);
                return;
            }
            match attempt_reload(poller.socket_path()).await {
                ReloadOutcome::Reloaded => app.status_ok("config reloaded".into()),
                ReloadOutcome::DaemonUnreachable => app
                    .status_err("edit saved — daemon not running, will apply on next start".into()),
                ReloadOutcome::NoToken { .. } => app.status_err(
                    "edit saved but no admin token is available to request a reload".into(),
                ),
                ReloadOutcome::ReloadFailed(msg) => {
                    app.status_err(format!("edit saved but daemon rejected reload: {msg}"))
                }
            }
        }
        _ => app.leaf_key_unhandled = true,
    }
}

/// Keyboard handler for the Settings → restore picker modal. Gated in
/// `handle_key` while `app.settings.restore_modal.is_some()`. Picking
/// moves the selection or advances to the confirm prompt; Confirming hands the
/// restore to a background task on `y` and parks the modal in `Restoring`;
/// Submitted closes on any key. Mirrors `handle_local_dns_modal_key`.
async fn handle_restore_modal_key(
    app: &mut App,
    key: KeyEvent,
    poller: &IpcPoller,
    config_path: &Path,
) {
    use backup_restore_modal::RestoreStage;

    let Some(mut modal) = app.settings.restore_modal.take() else {
        return;
    };

    // Submitted — any key closes (drop by not re-stashing).
    if modal.is_submitted() {
        return;
    }

    // Restoring — the background task owns this modal. Swallow every key and
    // re-stash: a second `y` would race a second extraction against the same
    // live config tree, and letting the operator close the card would orphan an
    // outcome that is still coming (`apply_job_result` would have nowhere to
    // land it). The card says "please wait" and means it.
    if matches!(modal.stage, RestoreStage::Restoring { .. }) {
        app.settings.restore_modal = Some(modal);
        return;
    }

    // Confirming handled first so the stage transition happens before any
    // `&mut modal.stage` borrow is taken.
    if let RestoreStage::Confirming { point } = &modal.stage {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                let point = point.clone();
                start_restore(app, modal, point, poller, config_path).await;
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {} // cancel: drop the modal
            _ => app.settings.restore_modal = Some(modal),
        }
        return;
    }

    // Picking — pure in-place navigation, no await.
    if let RestoreStage::Picking { entries, selected } = &mut modal.stage {
        match key.code {
            KeyCode::Esc => return, // cancel: drop the modal
            KeyCode::Down if *selected + 1 < entries.len() => {
                *selected += 1;
            }
            KeyCode::Up => {
                *selected = selected.saturating_sub(1);
            }
            KeyCode::Enter => {
                let point = entries[*selected].clone();
                modal.stage = RestoreStage::Confirming { point };
            }
            _ => {}
        }
    }
    app.settings.restore_modal = Some(modal);
}

/// Keyboard handler for the Settings → backup confirm modal. Gated in
/// `handle_key` while `app.settings.backup_modal.is_some()`. Confirm hands the
/// backup to a background task on `y` and parks the modal in `Running`;
/// `n`/`Esc` drops the modal without writing; Submitted closes on any key.
/// Mirrors `handle_restore_modal_key` but does not need an `IpcPoller` — backup
/// is a pure filesystem op, no daemon reload involved.
async fn handle_backup_modal_key(app: &mut App, key: KeyEvent, config_path: &Path) {
    use backup_restore_modal::BackupModal;

    let Some(modal) = app.settings.backup_modal.take() else {
        return;
    };

    // Submitted — any key closes (drop by not re-stashing).
    if matches!(modal, BackupModal::Submitted { .. }) {
        return;
    }

    // Running — the background task owns this modal. Swallow every key and
    // re-stash: a second `y` would race a second `create_backup` against the
    // same backup dir (and unlike the `run_backup_managed` CLI path, the TUI
    // call takes no lock, so two archives could collide on the same
    // second-granularity filename), and letting the operator close the card
    // would orphan an outcome that is still coming. Mirrors `Restoring`.
    if matches!(modal, BackupModal::Running { .. }) {
        app.settings.backup_modal = Some(modal);
        return;
    }

    let BackupModal::Confirm { dir } = modal else {
        return; // unreachable: Submitted + Running handled above
    };

    match key.code {
        KeyCode::Char('y') | KeyCode::Char('Y') => {
            start_backup(app, dir, config_path).await;
        }
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
            // cancel: drop the modal (don't re-stash)
        }
        _ => {
            // Unrecognized key — keep the confirm card open.
            app.settings.backup_modal = Some(BackupModal::Confirm { dir });
        }
    }
}

/// tui-14: hand a confirmed backup to a background task and park the modal in
/// `Running` so the loop is free to paint the progress card. The exact mirror of
/// [`start_restore`].
///
/// Why a task rather than an inline call: `create_backup` is a synchronous
/// tar+gzip of the whole config tree. It ran right here, on the tokio worker
/// that drives the event loop — and being sync rather than an `.await`, it did
/// not even yield that worker. No repaint, no key, no signal, for the length of
/// the archive. `tokio::spawn` alone would not fix it either; it would only
/// relocate the stall to another worker thread, or on a single-core box back
/// onto the event loop's own. Hence the blocking pool — see [`execute_backup`].
///
/// Falls back to running inline when no job channel is wired (unit tests /
/// non-loop callers), the same escape hatch [`start_restore`] uses.
async fn start_backup(app: &mut App, dir: PathBuf, config_path: &Path) {
    use backup_restore_modal::BackupModal;

    let config_path = config_path.to_path_buf();

    match app.job_tx.clone() {
        Some(tx) => {
            app.settings.backup_modal = Some(BackupModal::Running { dir: dir.clone() });
            tokio::spawn(async move {
                let (outcome, auto_backup) = execute_backup(config_path, dir).await;
                // Send on EVERY path (`execute_backup` maps a panicked or
                // cancelled archive to a `Failed` outcome rather than returning
                // nothing): the `Running` stage swallows keys, so an outcome that
                // never arrives would leave the card unclosable.
                let _ = tx.send(app::UiJob::BackupFinished {
                    outcome,
                    auto_backup,
                });
            });
        }
        None => {
            let (outcome, auto_backup) = execute_backup(config_path, dir).await;
            app.settings.backup_modal = Some(backup_submitted_card(outcome));
            if let Some(view) = auto_backup {
                app.settings.auto_backup = view;
            }
        }
    }
}

/// Run a backup and take the post-backup Settings snapshot, both on the blocking
/// pool. Owned paths so the future is `'static` and can be spawned.
///
/// The snapshot is taken *inside* the blocking closure, right after the archive
/// lands, for two reasons: it must observe the new archive (the
/// "Last auto-backup" line updates immediately rather than at the next
/// tab-entry), and it is itself sync filesystem work — a readdir plus a small
/// JSON read. Recomputing it on the render thread would hand the loop back
/// exactly the kind of stall this whole change exists to remove.
async fn execute_backup(
    config_path: PathBuf,
    dir: PathBuf,
) -> (
    backup_restore_modal::SubmitOutcome,
    Option<crate::tui::app::AutoBackupView>,
) {
    use backup_restore_modal::SubmitOutcome;

    let archived = tokio::task::spawn_blocking(move || {
        let report = crate::cli::commands::config::create_backup(&config_path, Some(&dir));
        // Snapshot AFTER the archive so the refreshed view sees it.
        let view = auto_backup_view(&config_path);
        (report, view)
    })
    .await;

    match archived {
        Ok((Ok(report), view)) => {
            let n = report.entries.len();
            let msg = format!(
                "backup saved: {} ({n} entr{})",
                report.archive.display(),
                if n == 1 { "y" } else { "ies" }
            );
            (SubmitOutcome::Ok(msg), Some(view))
        }
        Ok((Err(e), view)) => (
            SubmitOutcome::Failed(format!("backup failed: {e}")),
            Some(view),
        ),
        // The blocking task panicked or was cancelled at runtime shutdown.
        // Surface it as an outcome: the caller MUST get one, or the `Running`
        // card (which eats every key) never closes. No snapshot was taken, so
        // leave the existing view alone rather than fabricating a default.
        Err(e) => (SubmitOutcome::Failed(format!("backup failed: {e}")), None),
    }
}

/// Map a finished-backup outcome onto the terminal card. Shared by the spawned
/// path (`apply_job_result`) and the inline fallback so both agree on the
/// message and the success colour.
fn backup_submitted_card(
    outcome: backup_restore_modal::SubmitOutcome,
) -> backup_restore_modal::BackupModal {
    use backup_restore_modal::{BackupModal, SubmitOutcome};

    match outcome {
        SubmitOutcome::Ok(msg) => BackupModal::Submitted { msg, ok: true },
        SubmitOutcome::Failed(msg) => BackupModal::Submitted { msg, ok: false },
    }
}

/// Refresh the cached Settings-tab auto-backup snapshot from
/// `<backup_dir>/.auto_state` + the newest archive. Cheap (one readdir +
/// one small JSON read) and deliberately event-driven — called on
/// startup, global `r`, Settings tab-entry, and after a manual backup,
/// never per-frame (the render fn has no `config_path`).
fn refresh_auto_backup_view(app: &mut App, config_path: &Path) {
    app.settings.auto_backup = auto_backup_view(config_path);
}

/// Compute the auto-backup snapshot. Pure (no `App`), so it can run either on
/// the render thread — the startup / global-`r` / tab-entry callers above go
/// through [`refresh_auto_backup_view`] — or on the blocking pool, which is
/// where the post-backup refresh runs now (tui-14): it is one readdir plus a
/// small JSON read, and that is sync filesystem work the event loop should not
/// be doing.
fn auto_backup_view(config_path: &Path) -> crate::tui::app::AutoBackupView {
    use crate::cli::commands::config::backup::{load_auto_state, AutoOutcome};
    use crate::cli::commands::config::{list_backups, resolved_backup_dir};

    let dir = resolved_backup_dir(config_path);
    let last_archive = list_backups(&dir).first().map(|e| e.timestamp);
    let state = load_auto_state(&dir);
    let last_error = match state.last_outcome {
        Some(AutoOutcome::Err { message }) => Some(message),
        _ => None,
    };
    crate::tui::app::AutoBackupView {
        last_archive,
        consecutive_failures: state.consecutive_failures,
        last_error,
        disabled: state.disabled,
    }
}

/// tui-02: hand a confirmed restore to a background task and park the modal in
/// `Restoring` so the loop is free to paint the progress card.
///
/// Why a task rather than an inline `.await`: the whole event loop — render,
/// input, signals — is one future. Awaiting the restore inside a key handler
/// suspends it for the length of the extraction plus the reload round-trip. And
/// the extraction is not even an await that yields the worker: `restore_archive`
/// is a synchronous syscall storm (untar → copy → validate → atomic rename), so
/// it pins the thread it lands on. `#[tokio::main]` sizes the worker pool to the
/// core count, so on a small box (the Pi class) that thread is *the* event loop.
/// Hence a spawned task, and inside it the blocking pool — see `execute_restore`.
///
/// Falls back to running inline when no job channel is wired (unit tests /
/// non-loop callers), the same escape hatch `open_catalog_picker` uses.
async fn start_restore(
    app: &mut App,
    mut modal: backup_restore_modal::RestoreModal,
    point: backup_restore_modal::RestorePoint,
    poller: &IpcPoller,
    config_path: &Path,
) {
    use backup_restore_modal::RestoreStage;

    let archive = point.path.clone();
    let config_path = config_path.to_path_buf();
    // Own the socket path rather than the `&IpcPoller`: the task must be
    // 'static, and `send_reload` needs nothing but the path.
    let socket_path = poller.socket_path().to_path_buf();

    match app.job_tx.clone() {
        Some(tx) => {
            modal.stage = RestoreStage::Restoring { point };
            app.settings.restore_modal = Some(modal);
            tokio::spawn(async move {
                let outcome = execute_restore(archive, config_path, socket_path).await;
                // Send on EVERY path (`execute_restore` maps a panicked or
                // cancelled extraction to a `Failed` outcome rather than
                // returning nothing): the `Restoring` stage swallows keys, so an
                // outcome that never arrives would leave the card unclosable.
                let _ = tx.send(app::UiJob::RestoreFinished(outcome));
            });
        }
        None => {
            let outcome = execute_restore(archive, config_path, socket_path).await;
            modal.stage = RestoreStage::Submitted(outcome);
            app.settings.restore_modal = Some(modal);
        }
    }
}

/// Run a restore from `archive` and reload the daemon. The engine core
/// does the staged-validate + atomic swap; on success we trigger the same
/// IPC `Reload` the `Ctrl+r` path uses so the live daemon picks up the
/// restored tree. A reload failure is reported but does NOT mark the
/// restore failed — the config is already swapped on disk.
///
/// Owned paths, and it builds its own `IpcPoller`, so the future is `'static`
/// and can be spawned. The synchronous `restore_archive` goes to the blocking
/// pool: `tokio::spawn` alone would only relocate the stall to another worker
/// thread — or, on a single-core box, back onto the event loop's own.
async fn execute_restore(
    archive: PathBuf,
    config_path: PathBuf,
    socket_path: PathBuf,
) -> backup_restore_modal::SubmitOutcome {
    use crate::cli::commands::config::{restore_archive, RestoreOutcome};
    use backup_restore_modal::SubmitOutcome;

    let name = archive
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| archive.display().to_string());

    let extracted =
        tokio::task::spawn_blocking(move || restore_archive(&config_path, &archive)).await;

    match extracted {
        Ok(Ok(RestoreOutcome::Restored { .. })) => {
            match IpcPoller::new(&socket_path).send_reload().await {
                Ok(_) => SubmitOutcome::Ok(format!("restored {name} and reloaded the daemon")),
                Err(e) => SubmitOutcome::Ok(format!(
                    "restored {name}; reload failed ({e}) — run `systemctl reload purge-warden`"
                )),
            }
        }
        Ok(Ok(RestoreOutcome::ValidationFailed(errs))) => SubmitOutcome::Failed(format!(
            "{name} failed validation ({} error(s)); live config untouched",
            errs.len()
        )),
        Ok(Err(e)) => SubmitOutcome::Failed(format!("restore failed: {e}")),
        // The blocking task panicked or was cancelled at runtime shutdown.
        // Surface it as an outcome: the caller MUST get one, or the `Restoring`
        // card (which eats every key) never closes. The live tree is whatever
        // `restore_archive`'s own rollback left behind.
        Err(e) => SubmitOutcome::Failed(format!("restore failed: {e}")),
    }
}

// ── Tracking form handler ────────────────────────────────────────────────────

/// Keyboard handler for the Settings → Tracking form.
/// Called only when `app.settings.tracking_panel.is_some()`. All keys
/// are consumed by the form; Esc exits back to the TOML viewer.
///
/// Submits via `IpcCommand::TrackingConfigUpdate` on `s`; surfaces
/// the daemon's response (success message or verbatim error) in the
/// panel's footer so the operator sees the frozen validation string
/// (e.g. "retention_days must be between 1 and 365.") inline.
async fn handle_tracking_panel_key(app: &mut App, key: KeyEvent, poller: &IpcPoller) {
    // Esc exits the form — handled outside the mut-borrow scope so
    // the borrow checker lets us reset the Option.
    if matches!(key.code, KeyCode::Esc) {
        app.settings.tracking_panel = None;
        return;
    }
    let Some(panel) = app.settings.tracking_panel.as_mut() else {
        return;
    };
    use crate::tui::app::TrackingFocus;

    // Any input clears the previous submit message so the footer
    // doesn't stale against a mid-edit view.
    let clear_message_on_edit = |p: &mut crate::tui::app::TrackingPanelState| {
        p.submit_message = None;
    };

    match key.code {
        KeyCode::Tab | KeyCode::Down => {
            panel.focus = panel.focus.next();
            clear_message_on_edit(panel);
        }
        KeyCode::BackTab | KeyCode::Up => {
            panel.focus = panel.focus.prev();
            clear_message_on_edit(panel);
        }
        KeyCode::Char(' ') | KeyCode::Enter if panel.focus == TrackingFocus::Enabled => {
            panel.query_log_enabled = !panel.query_log_enabled;
            clear_message_on_edit(panel);
        }
        KeyCode::Left if panel.focus == TrackingFocus::Mode => {
            panel.log_mode = cycle_log_mode_prev(&panel.log_mode);
            clear_message_on_edit(panel);
        }
        KeyCode::Right if panel.focus == TrackingFocus::Mode => {
            panel.log_mode = cycle_log_mode_next(&panel.log_mode);
            clear_message_on_edit(panel);
        }
        KeyCode::Char(c) if panel.focus == TrackingFocus::Retention && c.is_ascii_digit() => {
            if panel.retention_input.len() < 3 {
                panel.retention_input.push(c);
            }
            commit_retention_from_input(panel);
            clear_message_on_edit(panel);
        }
        KeyCode::Backspace if panel.focus == TrackingFocus::Retention => {
            panel.retention_input.pop();
            commit_retention_from_input(panel);
            clear_message_on_edit(panel);
        }
        KeyCode::Char('s') => {
            // Commit retention buffer first (user may have Tab'd
            // away but still typed).
            commit_retention_from_input(panel);
            // Pre-flight clamp mirrors the daemon-side validator so
            // the frozen string shows before the IPC roundtrip.
            if !(1..=365).contains(&panel.retention_days) {
                panel.submit_message = Some(format!(
                    "error: {}",
                    crate::tui::tabs::settings::TRACKING_VALIDATION_RETENTION_OUT_OF_RANGE
                ));
                return;
            }
            let patch = panel.to_patch();
            match poller.send_tracking_update(patch).await {
                Ok(msg) => {
                    panel.submit_message = Some(msg);
                }
                Err(e) => {
                    panel.submit_message = Some(format!("error: {e}"));
                }
            }
        }
        _ => {}
    }
}

fn cycle_log_mode_next(
    mode: &crate::config::settings::LogMode,
) -> crate::config::settings::LogMode {
    use crate::config::settings::LogMode;
    match mode {
        LogMode::All => LogMode::BlockedOnly,
        LogMode::BlockedOnly => LogMode::Sampled { allowed_rate: 0.1 },
        LogMode::Sampled { .. } => LogMode::All,
    }
}

fn cycle_log_mode_prev(
    mode: &crate::config::settings::LogMode,
) -> crate::config::settings::LogMode {
    use crate::config::settings::LogMode;
    match mode {
        LogMode::All => LogMode::Sampled { allowed_rate: 0.1 },
        LogMode::BlockedOnly => LogMode::All,
        LogMode::Sampled { .. } => LogMode::BlockedOnly,
    }
}

fn commit_retention_from_input(panel: &mut crate::tui::app::TrackingPanelState) {
    if panel.retention_input.is_empty() {
        // Leave the previous value — empty buffer just means the
        // operator is mid-edit. Submit-time validation catches the
        // 0 case if they actually clear and commit.
        return;
    }
    if let Ok(v) = panel.retention_input.parse::<u32>() {
        panel.retention_days = v;
    }
}

// ── Text-input helper (Query Log filter prompts) ───────────────────────────

/// Outcome from a single keystroke routed into a text input buffer.
/// The Query Log filter prompts (`/` for domain, `c` for client) share
/// this contract; the caller decides where a committed value lands.
enum TextInputOutcome {
    /// Operator pressed Enter — caller takes ownership of the buffer.
    Submit(String),
    /// Operator pressed Esc — caller exits input mode without saving.
    Cancel,
    /// Buffer was edited (or key was ignored); stay in input mode.
    Continue,
}

/// Maximum characters appended from a single paste — bounds a giant paste from
/// blowing a field.
const MAX_PASTE: usize = 256;

/// Append a bracketed-paste payload to the focused text buffer, or drop it when
/// no text field has focus (confirm prompts, menus, pickers, navigation).
///
/// Control characters (newlines, tabs, ESC) are stripped so a multi-line paste
/// collapses to one line and cannot synthesize an Enter/submit, and the chunk is
/// capped at [`MAX_PASTE`]. Dropping the paste in non-text contexts is the safety
/// property: a pasted `y` can never confirm a destructive Remove, a pasted `q`
/// can never quit.
fn handle_paste(app: &mut App, pasted: String) {
    let cleaned: String = pasted
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_PASTE)
        .collect();
    if cleaned.is_empty() {
        return;
    }

    // The Lists edit modal edits through a closure (chip type-ahead buffer or a
    // focused URL/name field), not a borrowable accessor — handle it here.
    if app.active_leaf == Leaf::Lists {
        if let Some(modal) = app.lists.edit_modal.as_mut() {
            paste_into_edit_list_modal(modal, &cleaned);
            return;
        }
    }

    // The Groups form carries the same chip-picker/text-field
    // split as the Lists modal above, and for the same reason cannot be
    // reached through `focused_text_buffer` — see `paste_into_group_modal`.
    // Ordered here, above the resolver, because `handle_key` gates the
    // Groups modal above the resolver too.
    if app.active_leaf == Leaf::Groups {
        if let Some(modal) = app.groups.modal.as_mut() {
            paste_into_group_modal(modal, &cleaned);
            return;
        }
    }

    // The resolver modal's input mutation carries a
    // side effect (drop the now-stale prior result) that a bare
    // `&mut String` from `focused_text_buffer` can't express — handle
    // it here, same shape as the Lists case above.
    if let Some(modal) = app.resolver_modal.as_mut() {
        modal.paste_into_input(&cleaned);
        return;
    }

    if let Some(buf) = focused_text_buffer(app) {
        buf.push_str(&cleaned);
    }
}

/// Lists edit modal paste: append to the chip type-ahead buffer when the Tags
/// field has focus, otherwise to the focused text field (URL / name). Inert in
/// both typed-id confirms.
///
/// The gates ask for the id verbatim to buy deliberation, not to test
/// transcription. A paste satisfies the string comparison without the
/// operator having read what they are agreeing to, which is the whole
/// thing being bought — so paste stays inert in both.
fn paste_into_edit_list_modal(modal: &mut app::EditListModal, cleaned: &str) {
    use app::EditModalMode;
    if matches!(
        modal.mode,
        EditModalMode::ConfirmDelete { .. } | EditModalMode::ConfirmUnsignedAllow { .. }
    ) {
        return;
    }
    edit_text_field(modal, |buf| buf.push_str(cleaned));
}

/// Groups form paste: append to the chip type-ahead buffer when
/// the Tags field has focus, otherwise to the focused text field (Id /
/// Display name / Devices / Priority). Inert in the `y`/`n` remove confirm and
/// on the submitted card — neither owns a buffer.
///
/// The field this exists for is **Devices**: a comma-separated id list is
/// exactly the content an operator copies from the Devices tab rather than
/// retypes. Before this, a paste with the Groups modal open reached no field
/// and said nothing.
///
/// **Paste on Tags lands in the type-ahead buffer — decided, not inherited.**
/// The same widget in the Lists edit modal already takes paste
/// ([`paste_into_edit_list_modal`]), and two identically-rendered chip
/// pickers that disagree about paste would be an incoherence worth
/// removing. Nothing is committed by pasting: the buffer only filters
/// suggestions until `Enter`, so an unusable paste costs a `Backspace`, not a
/// wrong tag.
///
/// **Why this is a `handle_paste` interceptor and not a `focused_text_buffer`
/// arm.** Appending to `tags_input_buf` carries two side effects a borrowed
/// `&mut String` cannot express — the same reason the Lists and resolver
/// modals are handled there. They are not cosmetic. `tags_picker_focus` is an
/// index into `filter_tag_suggestions(known, selected, buf)`, a list
/// re-derived from the buffer on every keystroke; the filter preserves order,
/// so the narrowed list is a *subsequence*, and once any earlier entry drops
/// out, index `i` names a **different tag**. `commit_tag_picker` catches only
/// the out-of-bounds case ("suggestion focus is stale"); an index still in
/// bounds silently attaches the wrong tag to the group. The typing arm in
/// `handle_group_modal_key` clears both fields for exactly this reason, and a
/// paste is a burst of typing.
fn paste_into_group_modal(modal: &mut group_modal::GroupModal, cleaned: &str) {
    use group_modal::Stage;
    let Stage::EditingForm(form) = &mut modal.stage else {
        // ConfirmingRemove is a single-key y/n gate and Submitted is a
        // read-only outcome card: no buffer to land in, so paste is inert.
        return;
    };
    if let Some(buf) = group_text_field_buf(form) {
        buf.push_str(cleaned);
        form.error_message = None;
    }
}

/// The single text buffer that currently has input focus, or `None` when the
/// active context does not accept free text (confirm prompts, menus, pickers,
/// toggles, plain navigation). Mirrors `handle_key`'s gate order so a paste
/// lands exactly where a typed character would — and nowhere a typed character
/// would trigger an action.
///
/// The Lists edit modal is handled in [`handle_paste`] directly (it edits
/// through a closure, not a borrowable buffer), so it is absent here.
/// `custom_list_modal::Form`'s id is immutable once created — it names
/// the file — mirroring `label_text_field_buf`'s / `subnet_text_field_buf`'s
/// treatment of the same Add-only-id shape.
fn custom_list_form_paste_buf(form: &mut custom_list_modal::Form) -> Option<&mut String> {
    use custom_list_modal::{FormField, FormMode};
    match form.focused {
        FormField::Id if form.mode == FormMode::Add => Some(&mut form.id),
        FormField::Id => None, // immutable on Edit
        FormField::DisplayName => Some(&mut form.display_name),
        FormField::Description => Some(&mut form.description),
        FormField::Submit | FormField::Cancel => None,
    }
}

fn custom_list_rule_paste_buf(form: &mut custom_list_modal::RuleForm) -> Option<&mut String> {
    use custom_list_modal::RuleField;
    match form.focused {
        RuleField::Domain => Some(&mut form.domain),
        RuleField::Direction | RuleField::Submit | RuleField::Cancel => None,
    }
}

/// The typed-id remove gate and the rule-remove confirm take no paste —
/// same rule as the Lists gates: they ask for the id to buy
/// deliberation, not transcription.
fn custom_list_paste_buf(modal: &mut custom_list_modal::CustomListModal) -> Option<&mut String> {
    use custom_list_modal::Stage;
    match &mut modal.stage {
        Stage::EditingForm(form) => custom_list_form_paste_buf(form),
        Stage::AddingRule(form) => custom_list_rule_paste_buf(form),
        Stage::ConfirmingRemove(_) | Stage::ConfirmingRuleRemove(_) | Stage::Submitted(_) => None,
    }
}

/// Mirrors `query_log_filter_modal::Field::text_of`, which is private to
/// that module — this free function is the same shape as
/// `label_text_field_buf` / `subnet_text_field_buf` for exactly the same
/// reason: reaching a sibling-owned modal's pub fields from here rather
/// than adding a method to a file this function does not own.
fn query_log_filter_paste_buf(
    modal: &mut query_log_filter_modal::QueryLogFilterModal,
) -> Option<&mut String> {
    use query_log_filter_modal::Field;
    match modal.focus {
        Field::NamePattern => Some(modal.draft.name.get_or_insert_with(String::new)),
        Field::IpPattern => Some(modal.draft.ip.get_or_insert_with(String::new)),
        Field::SubnetPattern => Some(modal.draft.subnet.get_or_insert_with(String::new)),
        Field::NamePolarity
        | Field::IpPolarity
        | Field::SubnetPolarity
        | Field::Cancel
        | Field::Apply => None,
    }
}

fn focused_text_buffer(app: &mut App) -> Option<&mut String> {
    // Welcome banner consumes everything until a key dismisses it — paste inert.
    if app.welcome_banner.is_some() {
        return None;
    }

    // Devices form. Text only when not submitting, no picker is open, and the
    // focused field accepts typing (Profile / Group are select-only).
    if app.active_leaf == Leaf::Devices && app.devices.modal.is_some() {
        if let Some(DeviceModal::Form(form)) = app.devices.modal.as_mut() {
            // Focus on Cancel / Save has no buffer to paste into.
            if let Some(focused) = form.focused.field() {
                if !form.submitting && form.picker.is_none() && field_accepts_typing(form, focused)
                {
                    return Some(form.field_buf(focused));
                }
            }
        }
        return None; // a devices modal is open (non-text field, or delete confirm)
    }

    // Lists: the edit modal is handled in `handle_paste`; the catalog
    // picker is a picker; the consent gate is a typed confirm and takes
    // no paste, for the same reason the delete gate does not — it asks
    // for the id to buy deliberation, not transcription.
    if app.active_leaf == Leaf::Lists
        && (app.lists.edit_modal.is_some()
            || app.lists.catalog_picker.is_some()
            || app.lists.kind_confirm.is_some())
    {
        return None;
    }

    // Rules add/edit forms, in `handle_key`'s gate order (edit_modal
    // before add_modal). The domain is copied off a Query Log row more
    // often than it is typed, so an inert paste is felt here first —
    // `modals-01`.
    if app.active_leaf == Leaf::Rules {
        if app.rules.edit_modal.is_some() {
            return None; // picker/confirm only — inert, but STOP here
        }
        if let Some(m) = app.rules.add_modal.as_mut() {
            return (m.focus == rule_add_modal::AddFocus::Domain).then_some(&mut m.domain);
        }
    }

    // Groups: the whole modal is handled in `handle_paste` (the Tags chip
    // picker needs side effects a borrowed `&mut String` cannot carry — see
    // `paste_into_group_modal`), so nothing here is borrowable.
    //
    // **The arm still has to exist.** `handle_key` gates the Groups modal
    // above the `/`-filter arms; without a stop here, a paste with the modal
    // open falls past every arm below and lands in the `input_mode` match at
    // the bottom — i.e. in a filter buffer hidden behind the modal, which is
    // worse than inert. That is unreachable today (an armed filter returns
    // early from `handle_key` on every key, so the modal cannot be opened
    // while one is live), but it is unreachable because the gate order holds,
    // and this function's contract is to mirror that order rather than to
    // depend on it.
    if app.active_leaf == Leaf::Groups && app.groups.modal.is_some() {
        return None;
    }

    // Labels add/edit text fields; the y/n remove confirm → inert.
    //
    // **Paste matters more here than on most forms.** The values this
    // vocabulary exists to adopt are the ones already on the operator's
    // devices — `Apple TV`, `Dweller` — and the way you get them exactly
    // right is to copy them from the Devices tab rather than retype them
    // and introduce the very near-duplicate the vocabulary is meant to
    // prevent. Without this arm the paste was inert **and silent**.
    if app.active_leaf == Leaf::Labels && app.labels.modal.is_some() {
        if let Some(modal) = app.labels.modal.as_mut() {
            if let label_modal::Stage::EditingForm(form) = &mut modal.stage {
                return label_text_field_buf(form);
            }
        }
        return None;
    }

    // Subnet add/edit text fields; confirm → inert.
    if app.active_leaf == Leaf::Subnets && app.subnets.modal.is_some() {
        if let Some(modal) = app.subnets.modal.as_mut() {
            if let subnet_modal::Stage::EditingForm(form) = &mut modal.stage {
                return subnet_text_field_buf(form);
            }
        }
        return None;
    }

    // Custom Lists, in `handle_key`'s gate order (modal before
    // mount_picker). The add/edit form and the add-rule form take text;
    // the typed-id remove gate and the rule-remove confirm do NOT — they
    // ask for the id to buy deliberation, not transcription, same rule as
    // the Lists gates above.
    if app.active_leaf == Leaf::CustomLists {
        if let Some(modal) = app.custom_lists.modal.as_mut() {
            return custom_list_paste_buf(modal);
        }
        if app.custom_lists.mount_picker.is_some() {
            return None; // multi-select picker — inert
        }
    }

    // Profile add/edit text fields; confirm → inert.
    if app.active_leaf == Leaf::Profiles && app.profiles.modal.is_some() {
        if let Some(modal) = app.profiles.modal.as_mut() {
            if let profile_modal::Stage::EditingForm(form) = &mut modal.stage {
                return form.text_field_buf();
            }
        }
        return None;
    }

    // Source-IP resolver modal (global) is handled directly in
    // `handle_paste` (its input mutation carries a side effect that a bare
    // `&mut String` can't express), so it
    // never reaches this generic path. No arm needed here.

    // Query Log rule picker (global). The marker list and the report
    // take no text; the create form is the Custom Lists add form, so it
    // pastes through the same buffer that leaf uses rather than a copy.
    if let Some(modal) = app.query_log_rule_modal.as_mut() {
        return match &mut modal.stage {
            query_log_rule_modal::Stage::NewList(inner) => custom_list_paste_buf(inner),
            _ => None,
        };
    }

    // Query Log advanced search (global, not leaf-gated — mirrors
    // `handle_key`'s placement after the rule-picker gate). Three
    // predicates whose values are read off other tabs; polarity and
    // action rows have no buffer.
    if let Some(m) = app.query_log.advanced_modal.as_mut() {
        return query_log_filter_paste_buf(m);
    }

    // `/`-filter prompts.
    match &mut app.input_mode {
        InputMode::FilterDomain(buf)
        | InputMode::FilterClient(buf)
        | InputMode::FilterLists(buf)
        | InputMode::FilterRules(buf)
        | InputMode::FilterDevicesSubnet(buf)
        | InputMode::FilterLogs(buf) => Some(buf),
        InputMode::Normal => None,
    }
}

/// Apply a key event to a `String` buffer and return what the caller
/// should do next. Typing inserts characters, Backspace pops, Enter
/// submits, Esc cancels, every other key is a no-op.
fn drive_text_input(buf: &mut String, key: KeyEvent) -> TextInputOutcome {
    match key.code {
        KeyCode::Enter => TextInputOutcome::Submit(std::mem::take(buf)),
        KeyCode::Esc => TextInputOutcome::Cancel,
        KeyCode::Backspace => {
            buf.pop();
            TextInputOutcome::Continue
        }
        // Only insert a literal when no CONTROL/ALT modifier is held —
        // mirrors the resolver modal's guard (`handle_resolver_modal_key`).
        // Without it, Ctrl+C in a `/`-filter buffer pushes a literal 'c'
        // instead of being a no-op; the modified chord falls through to
        // the `_` arm below. SHIFT is intentionally not masked so capitals
        // still type.
        KeyCode::Char(c)
            if !key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
        {
            buf.push(c);
            TextInputOutcome::Continue
        }
        _ => TextInputOutcome::Continue,
    }
}

#[cfg(test)]
#[path = "tests/drive_text_input_tests.rs"]
mod drive_text_input_tests;

#[cfg(test)]
#[path = "tests/paste_tests.rs"]
mod paste_tests;

// ── Settings → 'e' editor failure formatting ───────────────────────────────

/// Format a failure from the Settings 'e' editor invocation into a
/// plain-English footer hint. Returns `None` on a clean exit so the
/// caller can leave `app.last_error` untouched.
///
/// Two realistic failure modes:
/// - `Ok(non-zero)`: $EDITOR ran but exited with an error (operator
///   used `:cq` in vim, save permission denied, post-edit validator
///   rejected the write). The caller has already reloaded from disk,
///   so the TUI view matches whatever made it through; the message
///   tells the operator how to retry if their edits are missing.
/// - `Err(_)`: $EDITOR could not be spawned at all (binary not found,
///   permission denied). Operator has to fix $EDITOR before retrying.
fn format_editor_failure(
    editor: &str,
    status: std::io::Result<std::process::ExitStatus>,
) -> Option<String> {
    match status {
        Ok(s) if s.success() => None,
        Ok(s) => Some(format!(
            "$EDITOR ({editor}) exited with {s} — config reloaded from disk. \
             If your edits aren't visible, the editor likely didn't save. Press 'e' to retry."
        )),
        Err(e) => Some(format!(
            "could not launch $EDITOR ({editor}): {e}. Set $EDITOR to a known-good \
             binary (e.g. nano, vim). Press 'e' to retry."
        )),
    }
}

// ── Scroll helpers ──────────────────────────────────────────────────────────

fn scroll_table_down(state: &mut ratatui::widgets::TableState, len: usize) {
    if len == 0 {
        return;
    }
    let i = state.selected().map(|i| (i + 1).min(len - 1)).unwrap_or(0);
    state.select(Some(i));
}

fn scroll_table_up(state: &mut ratatui::widgets::TableState) {
    let i = state.selected().map(|i| i.saturating_sub(1)).unwrap_or(0);
    state.select(Some(i));
}

// ── Home / End / PgUp / PgDn ─────────────────────────────────────────────────
//
// `scroll_table_down` / `scroll_table_up` above already CLAMP. What was
// missing is the jump and the page, on every
// leaf that has `↑`/`↓`. Two families, because the TUI has two row shapes:
// flat tables (Subnets, Profiles, Query Log, Rules, Tags, Cluster) and
// grouped vectors that interleave non-selectable headers (Devices, Lists).

/// The Query Log boundary notice raised by `End` / `PgDn`.
///
/// Makes the loaded-window edge reachable in one keystroke. Without this
/// line the operator lands on the oldest *loaded* row and
/// reads it as the oldest *query*, which it is not — see the
/// `KeyCode::End` arm in `handle_query_log_key` for why it is a status line
/// and not a row annotation.
/// Shown on reaching the last loaded row when the daemon reported **no**
/// resume point — the page really is the oldest retained data.
///
/// It used to fire on reaching the last row unconditionally, because
/// before paging could fetch there was nothing older to load and the
/// message was always true. Now that `PgDn` can fetch, firing it while a
/// `next_cursor` exists would be a lie, so the trigger is gated and
/// `QUERY_LOG_MORE_BELOW` covers the other half. The text is unchanged.
const QUERY_LOG_END_OF_PAGE: &str = "end of page \u{00b7} older entries not loaded";

/// Reaching the last loaded row with a resume point in hand.
const QUERY_LOG_MORE_BELOW: &str = "end of page \u{00b7} PgDn again for older entries";

/// `PgDn` at the bottom of the oldest retained page.
const QUERY_LOG_OLDEST: &str = "oldest retained entry \u{00b7} nothing older on disk";

/// Confirmation that the advanced form was applied.
const QUERY_LOG_ADVANCED_APPLIED: &str = "advanced search applied \u{00b7} [R] clears every filter";

/// `PgUp` back onto page 0.
const QUERY_LOG_LIVE_TAIL: &str = "live tail \u{00b7} newest entries";

/// The cursor's file rotated mid-session; this view is the live tail.
const QUERY_LOG_CURSOR_STALE: &str =
    "query log rotated \u{00b7} paging reset to the newest entries";

/// How many rows one Query Log page holds. Was an inline `100` at the
/// single poll call site; named because the paging handler and the page
/// label now have to agree with it.
const QUERY_LOG_PAGE_LIMIT: usize = 100;

/// Footer label for a paged-back view. `page 1` is the live tail, so the
/// operator's count starts where their intuition does.
fn query_log_page_label(page_index: usize) -> String {
    format!(
        "page {} \u{00b7} PgUp for newer",
        page_index.saturating_add(1)
    )
}

/// How many rows `PgUp` / `PgDn` travel.
///
/// The leaf handlers never see the viewport height — the renderer owns the
/// layout and the handler owns the key — so the spec's stated fallback
/// applies rather than threading a height through fourteen signatures for a
/// paging convenience. Ten rows.
const NAV_PAGE: usize = 10;

/// `Home` — first row. No-op on an empty table.
fn jump_table_home(state: &mut ratatui::widgets::TableState, len: usize) {
    if len == 0 {
        return;
    }
    state.select(Some(0));
}

/// `End` — last row. No-op on an empty table.
fn jump_table_end(state: &mut ratatui::widgets::TableState, len: usize) {
    if len == 0 {
        return;
    }
    state.select(Some(len - 1));
}

/// `PgDn` — forward one page, clamped at the last row.
fn page_table_down(state: &mut ratatui::widgets::TableState, len: usize) {
    if len == 0 {
        return;
    }
    let i = state
        .selected()
        .map(|i| (i + NAV_PAGE).min(len - 1))
        .unwrap_or(0);
    state.select(Some(i));
}

/// `PgUp` — back one page, clamped at row 0.
fn page_table_up(state: &mut ratatui::widgets::TableState) {
    let i = state
        .selected()
        .map(|i| i.saturating_sub(NAV_PAGE))
        .unwrap_or(0);
    state.select(Some(i));
}

// The three below serve the grouped leaves, whose row vectors interleave
// non-selectable group headers.
//
// They live here rather than beside `next_selectable_index` in
// `tabs/devices.rs` / `tabs/lists.rs` to keep one owner per file.
// Nothing is duplicated by that: both row types already expose
// `is_selectable()` publicly, single-step motion still routes through each
// leaf's own helper, and these three read only that predicate. This code
// never depended on `next_selectable_index`'s wrap behaviour, which is
// exactly why the paging was NOT built by calling it in
// a loop.

/// First selectable row index, skipping headers.
fn first_selectable_idx<T>(rows: &[T], selectable: impl Fn(&T) -> bool) -> Option<usize> {
    rows.iter().position(selectable)
}

/// Last selectable row index, skipping headers.
fn last_selectable_idx<T>(rows: &[T], selectable: impl Fn(&T) -> bool) -> Option<usize> {
    rows.iter().rposition(selectable)
}

/// Step [`NAV_PAGE`] selectable rows from `from`, clamping at whichever end
/// is reached first. `None` (nothing focused yet) seeds at the first / last
/// selectable row, matching what a first `↓` / `↑` press does.
fn page_selectable_idx<T>(
    rows: &[T],
    from: Option<usize>,
    forward: bool,
    selectable: impl Fn(&T) -> bool,
) -> Option<usize> {
    let mut cur = match from {
        Some(i) if i < rows.len() && selectable(&rows[i]) => i,
        _ => {
            return if forward {
                first_selectable_idx(rows, selectable)
            } else {
                last_selectable_idx(rows, selectable)
            }
        }
    };
    for _ in 0..NAV_PAGE {
        let next = if forward {
            rows.iter()
                .enumerate()
                .skip(cur + 1)
                .find(|(_, r)| selectable(r))
                .map(|(i, _)| i)
        } else {
            rows[..cur].iter().rposition(&selectable)
        };
        match next {
            Some(i) => cur = i,
            // Clamp: the page stops at the end rather than wrapping.
            None => break,
        }
    }
    Some(cur)
}

// ── IPC polling ─────────────────────────────────────────────────────────────

/// The success arms of this function used to call
/// `app.clear_status()`, which made the *poll cadence* the de-facto
/// lifetime of every action message — 2s on Dashboard, 30s on Lists, and
/// never at all on the six leaves that have no poll. Expiry now belongs
/// to the tick (`App::expire_status`), so those calls are gone. They
/// could not simply be left in place either: an `Error` is sticky,
/// and a 2s poll would have wiped it before the operator read it.
///
/// What replaces them is narrower. The failure arms below raise
/// `status_err_poll`, marking the message as *poll-origin*, and the one
/// `clear_poll_status()` at the top of the pass retires the previous
/// one. A failure that persists is re-raised by its arm before anything
/// renders; a failure that recovered is simply not re-raised and is
/// gone. An action's error — a Save the operator watched fail — carries
/// `StatusOrigin::Action` and is untouched by any of this.
async fn poll_active_leaf(app: &mut App, poller: &IpcPoller) {
    // Poll errors describe a condition, not an event. Drop last pass's
    // before re-testing it; the arms below re-raise if it still holds.
    app.clear_poll_status();

    match app.active_leaf {
        Leaf::Dashboard => {
            // Fire the four independent
            // ReadOnly fetches concurrently — one round-trip window
            // instead of four sequential connect/read cycles. Each future
            // borrows only `poller` (shared `&self`) and returns owned
            // data; the per-result match arms below write `app` after the
            // join, so there is no `&mut app` aliasing and the
            // last-error-wins ordering is unchanged. Also bounds the
            // worst-case freeze when the daemon stalls mid-poll to one
            // timeout window instead of four (partial mitigation of a
            // known deferred event-loop-blocking issue).
            let (status_res, tracking_res, view_res, stats_res) = tokio::join!(
                poller.fetch_status(),
                poller.fetch_tracking_stats(),
                poller.fetch_device_view(),
                poller.fetch_blocklist_stats(),
            );
            match status_res {
                Ok(status) => {
                    app.daemon_status = Some(status);
                    app.connected = true;
                }
                Err(e) => {
                    app.connected = false;
                    app.status_err_poll(e.to_string());
                }
            }
            match tracking_res {
                Ok(data) => {
                    app.tracking = data;
                }
                Err(e) => {
                    // Mirror the pattern already used for device_view /
                    // lists.entries in this arm. Reset to
                    // default → render fns paint "collecting..." placeholders
                    // instead of stale KPI gauges + trend charts that may
                    // be minutes stale during a transient daemon hiccup.
                    app.tracking = Default::default();
                    app.status_err_poll(e.to_string());
                }
            }
            // Device view feeds the Pulse's `Active` counter (online
            // / total) on Dashboard. Surface errors the same way as
            // status/tracking — silently keeping a stale `device_view`
            // would let a schema mismatch rot for hours with zero
            // feedback.
            match view_res {
                Ok(view) => {
                    app.device_view = Some(view);
                }
                Err(e) => {
                    // Clear the view so the widget renders its
                    // "waiting for daemon..." state instead of
                    // stale data + a small error banner.
                    app.device_view = None;
                    app.status_err_poll(e.to_string());
                }
            }
            // Blocklist stats feed the Pulse's `Lists` freshness row.
            // Without this fetch the row would stay at "not configured"
            // until the operator visited the Lists tab once. IPC failure
            // clears the cached entries so the Pulse degrades to "no
            // fetch yet" rather than carrying stale ages forward.
            match stats_res {
                Ok(stats) => {
                    app.lists.entries = stats;
                }
                Err(e) => {
                    app.lists.entries.clear();
                    app.status_err_poll(e.to_string());
                }
            }
        }
        Leaf::QueryLog => match poller
            .fetch_query_logs(crate::ipc::protocol::QueryLogRequest {
                limit: QUERY_LOG_PAGE_LIMIT,
                client: app.query_log.filter_client.clone(),
                blocked_only: app.query_log.blocked_only,
                domain: app.query_log.filter_domain.clone(),
                since_secs: app.query_log.since.as_secs(),
                cursor: app.query_log.current_cursor(),
                advanced: app.query_log.advanced_for_request(),
            })
            .await
        {
            Ok(result) => apply_query_log_page(app, result),
            Err(e) => {
                // Clear entries on Err → engage empty-state
                // picker (same pattern as Devices/Lists). Without this,
                // operator pressing Enter→allow/blocklist on a stale row
                // makes decisions on outdated data with only footer
                // last_error as cue.
                app.query_log.entries.clear();
                app.status_err_poll(e.to_string());
            }
        },
        Leaf::Devices => match poller.fetch_device_view().await {
            Ok(view) => {
                app.device_view = Some(view);
            }
            Err(e) => {
                // Same rationale as Dashboard — clear on error so the
                // operator sees "waiting..." instead of stale rows
                // with a mismatched error banner underneath.
                app.device_view = None;
                app.status_err_poll(e.to_string());
            }
        },
        // Lists pulls per-blocklist runtime telemetry. Empty
        // list on success means "daemon has zero sources"; an IPC
        // failure clears the cached entries so the empty-state
        // message tells the operator to wait rather than mislead
        // them with stale rows.
        Leaf::Lists => match poller.fetch_blocklist_stats().await {
            Ok(stats) => {
                app.lists.entries = stats;
            }
            Err(e) => {
                app.lists.entries.clear();
                app.status_err_poll(e.to_string());
            }
        },
        // Records list still comes
        // from the cached `LoadedConfig` (refreshed on `r`); the IPC
        // fetch only feeds the `hits` column snapshot. On error keep the
        // last good snapshot so a transient daemon hiccup doesn't blank
        // counts the operator was just reading — the surface degrades
        // gracefully rather than flickering between live and dash.
        Leaf::LocalDns => match poller.fetch_local_records_hits().await {
            Ok(entries) => {
                app.local_dns.hits_snapshot = Some(
                    entries
                        .into_iter()
                        .map(|e| (e.scope, e.domain, e.count))
                        .collect(),
                );
            }
            Err(e) => {
                app.status_err_poll(e.to_string());
            }
        },
        // Subnets / Resolver tabs read from the cached
        // LoadedConfig. No IPC call, so nothing to poll here. The `r`
        // keybinding in handle_key re-reads the config file. Rules
        // is also data-source-less — kept here to preserve the no-poll
        // invariant for offline-backed tabs. Profiles reads
        // `[profiles]` from the same cached LoadedConfig — joins the
        // no-poll cohort.
        // File joins the no-poll cohort by construction — it
        // reads the config off disk at load and on `r`, and its key handler
        // takes no `IpcPoller` at all.
        // `logs-tab`: both filters go DOWN with the request — the daemon
        // applies them while walking its ring, so a page filtered to
        // `errors` reaches the bottom of the buffer. Filtering the
        // returned page here instead would search only the newest
        // `LOGS_PAGE_LIMIT` rows and present that as "the errors".
        Leaf::Logs => match poller
            .fetch_daemon_logs(
                LOGS_PAGE_LIMIT,
                app.logs.level_filter.as_wire(),
                app.logs.filter_text.clone(),
            )
            .await
        {
            Ok(page) => {
                app.logs.entries = page.entries;
                app.logs.dropped = page.dropped;
                app.logs.capacity = page.capacity;
                app.logs.fetch = crate::tui::app::LogsFetch::Ok;
            }
            Err(e) => {
                // Clear on error, the gold standard the other leaves
                // follow: stale log lines under a fresh error banner read
                // as "the daemon is still saying this". Recording the
                // FAILURE alongside is what stops the now-empty pane from
                // claiming the daemon has said nothing.
                app.logs.entries.clear();
                app.logs.fetch = crate::tui::app::LogsFetch::Failed;
                app.status_err_poll(e.to_string());
            }
        },
        Leaf::Subnets
        | Leaf::Rules
        | Leaf::Settings
        | Leaf::Profiles
        | Leaf::File
        | Leaf::Groups
        | Leaf::Labels
        | Leaf::CustomLists => {} // no polling
        // The Cluster tab is fed by `poll_heartbeat`; no
        // active-leaf poll of its own.
        #[cfg(feature = "cluster")]
        Leaf::Cluster => {}
    }
}

/// Read the v1 config once for the TUI's offline-backed tabs (Subnets,
/// Resolver, Devices source annotation). Errors are swallowed and
/// translated to `None` — the consuming tabs render a "could not load"
/// state rather than bubbling up into the footer error slot (which is
/// reserved for daemon / IPC failures).
fn load_v1_config(config_path: &Path) -> Option<crate::config::loader::LoadedConfig> {
    crate::config::loader::load_config(config_path, time::OffsetDateTime::now_utc()).ok()
}

async fn poll_heartbeat(app: &mut App, poller: &IpcPoller) {
    match poller.fetch_status().await {
        Ok(status) => {
            app.daemon_status = Some(status);
            app.connected = true;
        }
        Err(_) => {
            app.connected = false;
        }
    }

    // The always-on heartbeat is the single cadence feeding BOTH
    // the dashboard dot and the Cluster tab — no second polling loop in
    // the TUI. Only fetch when clustering is enabled. On error keep the
    // last-known view, exactly like `daemon_status` above — `connected`
    // drives the dot's stale / red state.
    #[cfg(feature = "cluster")]
    if app.cluster_visible() {
        if let Ok(status) = poller.fetch_cluster_status().await {
            app.cluster_status = Some(status);
        }
    }
}

// ── Modal key handling ───────────────────────────────────────────────

/// Key handler for the active client modal. Routed from `handle_key`
/// before any global navigation so typing inside the form doesn't
/// trip tab-switch shortcuts. Splits on `DeviceModal` variant so the
/// form and the delete confirmation each get their own minimal
/// state machine.
async fn handle_modal_key(app: &mut App, key: KeyEvent, poller: &IpcPoller) {
    // Take the modal out so we can mutate the form without holding
    // a borrow on `app.devices`. Put it back at the end unless the
    // submit succeeded (which closes the modal).
    let Some(modal) = app.devices.modal.take() else {
        return;
    };

    match modal {
        DeviceModal::Form(mut form) => {
            // While a submit is in flight, only allow Esc to cancel —
            // every other key is dropped so a double-Enter can't
            // submit twice. (`submitting` is set to true by submit_form
            // before the await; reset on response.)
            if form.submitting && !matches!(key.code, KeyCode::Esc) {
                app.devices.modal = Some(DeviceModal::Form(form));
                return;
            }
            // Ctrl+s → save from anywhere, before any other dispatch —
            // same contract as the Rules and Lists edit modals. The
            // footer already advertises "[Ctrl+s] save" for this form;
            // before this guard the chord had no handler at all, so
            // `KeyCode::Char(c)` below caught it and typed a literal
            // `s` into whichever field held focus — measured
            // on the CT via pty-smoke — the field silently corrupted,
            // it did not simply ignore the chord.
            if matches!(key.code, KeyCode::Char('s') | KeyCode::Char('S'))
                && key.modifiers.contains(KeyModifiers::CONTROL)
            {
                submit_form(app, form, poller).await;
                return;
            }
            // Popup picker open → route keys to it (Profile / Group are
            // select-only). The form stays open underneath; Esc/Enter in
            // the picker close only the picker, not the form.
            if form.picker.is_some() {
                handle_form_picker_key(&mut form, key.code);
                app.devices.modal = Some(DeviceModal::Form(form));
                return;
            }
            match key.code {
                KeyCode::Esc => {
                    // Close the form without submitting. Don't restore
                    // — drop on the floor, modal closed.
                }
                // Arrows alias Tab / Shift-Tab. Safe to bind: the text
                // fields consume only `KeyCode::Char`, so before this the
                // arrows fell through to the catch-all and did nothing.
                KeyCode::Tab | KeyCode::Down => {
                    form.focus_next();
                    app.devices.modal = Some(DeviceModal::Form(form));
                }
                KeyCode::BackTab | KeyCode::Up => {
                    form.focus_prev();
                    app.devices.modal = Some(DeviceModal::Form(form));
                }
                KeyCode::Backspace => {
                    // Buttons hold no buffer — only a focused field takes
                    // the keystroke.
                    if let Some(focused) = form.focused.field() {
                        if field_accepts_typing(&form, focused) {
                            form.field_buf(focused).pop();
                            form.error_message = None; // clear on edit
                        }
                    }
                    app.devices.modal = Some(DeviceModal::Form(form));
                }
                KeyCode::Char(c) => {
                    // Profile / Group are select-only — typing does nothing;
                    // Enter opens their picker instead. Buttons ignore it.
                    if let Some(focused) = form.focused.field() {
                        if field_accepts_typing(&form, focused) {
                            form.field_buf(focused).push(c);
                            form.error_message = None;
                        }
                    }
                    app.devices.modal = Some(DeviceModal::Form(form));
                }
                KeyCode::Enter => match form.focused {
                    // Cancel → drop the modal on the floor, same as Esc.
                    DeviceFormFocus::Cancel => {}
                    // Save → submit. submit_form takes ownership, calls IPC,
                    // and decides whether to put the modal back (with an
                    // error message) or close it (success).
                    DeviceFormFocus::Save => submit_form(app, form, poller).await,
                    // Profile / Group → open the popup picker instead of
                    // submitting.
                    DeviceFormFocus::Field(f) if is_select_only_field(&form, f) => {
                        open_field_picker(&mut form);
                        app.devices.modal = Some(DeviceModal::Form(form));
                    }
                    // Enter from any typed field still submits — the
                    // pre-existing muscle memory survives the buttons.
                    DeviceFormFocus::Field(_) => submit_form(app, form, poller).await,
                },
                _ => {
                    app.devices.modal = Some(DeviceModal::Form(form));
                }
            }
        }
        DeviceModal::DeleteConfirm { id, display_name } => match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                match poller.send_device_remove(id.clone()).await {
                    Ok(_) => {
                        // Modal closes; force a re-poll so the row
                        // disappears from the table immediately.
                        app.clear_status();
                        poll_active_leaf(app, poller).await;
                    }
                    Err(e) => {
                        app.status_err(format!("delete failed: {e}"));
                        // Re-open the confirm so the operator can
                        // retry or cancel after seeing the error.
                        app.devices.modal = Some(DeviceModal::DeleteConfirm { id, display_name });
                    }
                }
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                // Cancelled — drop the modal.
            }
            _ => {
                app.devices.modal = Some(DeviceModal::DeleteConfirm { id, display_name });
            }
        },
    }
}

// ── Lists edit modal key handler + save / delete flows ────────────────

/// Drive the catalog picker's state machine.
///
/// `↑`/`↓` move the cursor, `Space` toggles the focused row's ON column,
/// `Tab` walks focus Table → Cancel → Save → Table, `Enter` fires the
/// focused footer action, `Ctrl+S` saves from anywhere, `Esc` discards.
/// Any keystroke during an in-flight save is dropped except `Esc`.
///
/// Nothing here mutates `staged_kind`: the KIND column is read-only until
/// the upstream trust story changes (see `CatalogPickerRow::staged_kind`).
/// A key that cycled a cell the operator cannot commit would read as a
/// broken modal.
async fn handle_lists_catalog_picker_key(
    app: &mut App,
    key: KeyEvent,
    poller: &IpcPoller,
    config_path: &Path,
) {
    use app::CatalogPickerFocus;

    let Some(mut modal) = app.lists.catalog_picker.take() else {
        return;
    };
    if modal.submitting && !matches!(key.code, KeyCode::Esc) {
        app.lists.catalog_picker = Some(modal);
        return;
    }

    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    match key.code {
        KeyCode::Esc => {
            app.lists.catalog_picker = None;
            return;
        }
        KeyCode::Char('s') | KeyCode::Char('S') if ctrl => {
            app.lists.catalog_picker = Some(modal);
            submit_catalog_picker(app, poller, config_path).await;
            return;
        }
        KeyCode::Tab => {
            modal.focus = match modal.focus {
                CatalogPickerFocus::Table => CatalogPickerFocus::Cancel,
                CatalogPickerFocus::Cancel => CatalogPickerFocus::Save,
                CatalogPickerFocus::Save => CatalogPickerFocus::Table,
            };
        }
        KeyCode::BackTab => {
            modal.focus = match modal.focus {
                CatalogPickerFocus::Table => CatalogPickerFocus::Save,
                CatalogPickerFocus::Save => CatalogPickerFocus::Cancel,
                CatalogPickerFocus::Cancel => CatalogPickerFocus::Table,
            };
        }
        KeyCode::Down => {
            // Arrowing while the footer has focus returns to the table
            // rather than doing nothing — the rows are what `↓` means on
            // this surface.
            modal.focus = CatalogPickerFocus::Table;
            tabs::lists::cycle_catalog_picker(&mut modal, 1);
        }
        KeyCode::Up => {
            modal.focus = CatalogPickerFocus::Table;
            tabs::lists::cycle_catalog_picker(&mut modal, -1);
        }
        // Space over the footer falls through to the catch-all: a button
        // is activated with Enter, and toggling a row the operator cannot
        // see the cursor on would be a blind write.
        KeyCode::Char(' ') if modal.focus == CatalogPickerFocus::Table => {
            toggle_focused_catalog_row(&mut modal);
        }
        KeyCode::Enter => match modal.focus {
            CatalogPickerFocus::Cancel => {
                app.lists.catalog_picker = None;
                return;
            }
            CatalogPickerFocus::Save => {
                app.lists.catalog_picker = Some(modal);
                submit_catalog_picker(app, poller, config_path).await;
                return;
            }
            // Enter acts on the focused THING, and on the table that is a
            // row — so it toggles, exactly as Space does. Making it save
            // instead would close the picker on an operator who pressed
            // Enter over a row expecting the predecessor's
            // subscribe-this-one, having staged nothing: no write, no
            // modal, no explanation. Committing is Ctrl+S and the Save
            // button, both one keystroke away and both labelled.
            CatalogPickerFocus::Table => toggle_focused_catalog_row(&mut modal),
        },
        _ => {}
    }
    app.lists.catalog_picker = Some(modal);
}

/// Flip the focused row's ON column. Shared by `Space` and by `Enter`
/// over the table so the two can never drift apart.
fn toggle_focused_catalog_row(modal: &mut app::CatalogPickerModal) {
    match modal
        .table_state
        .selected()
        .and_then(|i| modal.rows.get_mut(i))
    {
        Some(row) => {
            row.staged_enabled = !row.staged_enabled;
            modal.error_message = None;
        }
        None => {
            modal.error_message = Some("no row selected — ↑/↓ to pick one".into());
        }
    }
}

/// Commit every staged catalog row in **one** write and **one** reload.
///
/// Shape mirrors [`submit_edit_modal`]: one `read_or_empty`, an
/// `upsert_id_keyed` per dirty row, a single `write_value_validated`
/// (which validates the whole would-be-merged tree before promoting
/// anything, so a bad row leaves the config untouched), then one
/// `attempt_reload`. N separate `run_add_silent` calls would mean N
/// reloads for what the operator experienced as one action.
///
/// Three things `run_add_silent` does that this path must not lose:
///
/// 1. **the audit record** — a blocklist add is supply-chain-relevant, so
///    each added row emits its own audit line with the URL;
/// 2. **URL dedup on the canonical key** — `upsert_id_keyed` keys on the
///    *id*, and `original` was computed at modal-open, so a list added
///    from another surface since then is re-checked against the config we
///    just read;
/// 3. `run_add_silent`'s **HEAD probe is deliberately skipped** — catalog
///    URLs are pre-validated by the publisher, as the old subscribe path
///    also assumed.
///
/// Nothing is ever removed: unticking a subscribed row writes
/// `enabled = false`, keeping the operator's tags, interval and display
/// name. Deletion lives in the Lists edit modal behind its typed-id gate.
async fn submit_catalog_picker(app: &mut App, poller: &IpcPoller, config_path: &Path) {
    use crate::cli::commands::ipc_reload::{attempt_reload, ReloadOutcome};
    use crate::cli::commands::target::{
        read_or_empty, resolve_target_file, upsert_id_keyed, write_value_validated, EntityClass,
    };
    use crate::lists::source_key::canonical_url_key;

    let Some(mut modal) = app.lists.catalog_picker.take() else {
        return;
    };

    let dirty: Vec<app::CatalogPickerRow> = modal.dirty_rows().cloned().collect();
    if dirty.is_empty() {
        app.lists.catalog_picker = None;
        app.status_ok("no pending changes — nothing written".to_string());
        return;
    }

    modal.submitting = true;
    modal.error_message = None;
    modal.status_message = Some(format!("saving {} change(s)…", dirty.len()));
    app.lists.catalog_picker = Some(modal);

    macro_rules! fail {
        ($msg:expr) => {{
            if let Some(m) = app.lists.catalog_picker.as_mut() {
                m.submitting = false;
                m.status_message = None;
                m.error_message = Some($msg);
            }
            return;
        }};
    }

    let target_path = match resolve_target_file(config_path, EntityClass::Blocklists, None) {
        Ok(p) => p,
        Err(e) => fail!(e.to_string()),
    };
    let (mut doc, _) = match read_or_empty(&target_path) {
        Ok(v) => v,
        Err(e) => fail!(e.to_string()),
    };

    // Re-read the config from DISK, not from `app.loaded_config`: that is
    // the same modal-open snapshot `original` came from, so validating a
    // stale snapshot against itself would always agree. The two pre-flight
    // gates below need what is on disk right now.
    let on_disk = load_v1_config(config_path);
    let live: Vec<(&str, &str)> = on_disk
        .as_ref()
        .map(|lc| {
            lc.config
                .blocklists
                .iter()
                .map(|b| (b.id.as_str(), b.url.as_str()))
                .collect()
        })
        .unwrap_or_default();

    let mut added = 0usize;
    let mut updated = 0usize;
    for row in &dirty {
        if !row.original.is_subscribed() {
            // Gate 2 — dedup on the CANONICAL url key: a list subscribed
            // from another surface since the modal opened would otherwise
            // land as a second entry pointing at the same file, i.e. two
            // registry slots downloading one URL.
            let key = canonical_url_key(&row.url);
            if let Some((owner, _)) = live.iter().find(|(_, u)| canonical_url_key(u) == key) {
                fail!(format!(
                    "'{}' is already subscribed as \"{owner}\" — reopen the picker",
                    row.catalog_id
                ));
            }
            // `upsert_id_keyed` keys on the ID and REPLACES what it finds.
            // A catalog id deriving onto an id the operator already used
            // for a different URL would silently overwrite that list.
            if let Some((_, url)) = live.iter().find(|(id, _)| *id == row.canonical_id) {
                fail!(format!(
                    "id \"{}\" is already taken by {url} — rename that list first",
                    row.canonical_id
                ));
            }
        }
        let value = build_catalog_blocklist_value(row, on_disk.as_ref());
        if let Err(e) = upsert_id_keyed(
            &mut doc,
            EntityClass::Blocklists.toml_key(),
            &row.canonical_id,
            value,
        ) {
            fail!(e.to_string());
        }
        if row.original.is_subscribed() {
            updated += 1;
        } else {
            added += 1;
        }
    }

    if let Err(e) = write_value_validated(config_path, &target_path, &doc) {
        fail!(format!("validator: {e}"));
    }

    for row in &dirty {
        tracing::info!(
            target: "audit",
            action = if row.original.is_subscribed() { "blocklist.tui_catalog_set_enabled" } else { "blocklist.tui_catalog_add" },
            source = %row.canonical_id,
            url = %row.url,
            enabled = row.staged_enabled,
            surface = "tui",
            "TUI mutation"
        );
    }

    let reload = attempt_reload(poller.socket_path()).await;
    app.lists.catalog_picker = None;
    app.loaded_config = load_v1_config(config_path);

    let summary = match (added, updated) {
        (0, u) => format!("{u} list(s) updated"),
        (a, 0) => format!("{a} list(s) subscribed"),
        (a, u) => format!("{a} subscribed, {u} updated"),
    };
    match reload {
        ReloadOutcome::Reloaded => app.status_ok(format!("{summary} — daemon reloaded")),
        _ => app.status_ok(format!("{summary} — config written, daemon not reachable")),
    }
    poll_active_leaf(app, poller).await;
}

/// The `[[blocklists]]` table a catalog row saves as.
///
/// An already-subscribed row is **patched, not rebuilt**: only `enabled`
/// changes, and every other key is copied from the live entry so the
/// operator's tags, interval, display name and `auth_token_ref` survive a
/// tick in this modal. A fresh subscription gets the catalog's metadata
/// and the schema defaults for the rest — no tags, which lets the
/// validator's auto-promote pass pin `base = deny` to `["uncategorized"]`
/// at reload, exactly as the old subscribe path did.
/// Every enum token comes from `wire_str()`, never a local `match`. The
/// TUI already shipped its own copy of this mapping once, missed the
/// `Block` → `Deny` rename, and wrote `kind = "block"` — which the loader
/// refused as `unknown variant`, so the Lists modal could not save at all.
fn build_catalog_blocklist_value(
    row: &app::CatalogPickerRow,
    on_disk: Option<&crate::config::loader::LoadedConfig>,
) -> toml::Value {
    use toml::Value;

    let existing = on_disk.and_then(|lc| {
        lc.config
            .blocklists
            .iter()
            .find(|b| b.id.as_str() == row.canonical_id)
    });

    let mut tbl = toml::map::Map::new();
    tbl.insert("id".into(), Value::String(row.canonical_id.clone()));
    tbl.insert(
        "display_name".into(),
        Value::String(
            existing
                .map(|b| b.display_name.clone())
                .unwrap_or_else(|| row.display_name.clone()),
        ),
    );
    tbl.insert(
        "url".into(),
        Value::String(
            existing
                .map(|b| b.url.clone())
                .unwrap_or_else(|| row.url.clone()),
        ),
    );
    tbl.insert(
        "format".into(),
        Value::String(
            existing
                .map(|b| b.format)
                .unwrap_or(row.format)
                .wire_str()
                .to_string(),
        ),
    );
    tbl.insert("enabled".into(), Value::Boolean(row.staged_enabled));
    tbl.insert(
        "base".into(),
        Value::String(row.staged_kind.wire_str().to_string()),
    );
    if let Some(b) = existing {
        // `upsert_id_keyed` REPLACES the entry, so every key the operator
        // set has to be carried forward explicitly — `trust` above all:
        // dropping it would silently reset a `local` list to the
        // `remote-unsigned` default, which for a `base = allow` list is
        // the exact combination the validator refuses.
        tbl.insert(
            "trust".into(),
            Value::String(b.trust.wire_str().to_string()),
        );
        tbl.insert(
            "update_interval_hours".into(),
            Value::Integer(b.update_interval_hours as i64),
        );
        tbl.insert("max_entries".into(), Value::Integer(b.max_entries as i64));
        tbl.insert(
            "max_consecutive_failures".into(),
            Value::Integer(b.max_consecutive_failures as i64),
        );
        // Same contract as the four fields above, and the one that is
        // load-bearing: dropping it either refuses the whole apply (a
        // `base = allow`, `trust = remote-unsigned` row loses the consent
        // that made it legal) or silently erases a security declaration
        // the operator cannot see to redo. This picker has no consent
        // affordance — unlike the edit modal's `consent_declared` — so the
        // only legitimate value is the one the file already carried. Never
        // defaulted to `true` for a new row: a first-time add through this
        // picker correctly gets the schema default and lets the validator
        // refuse if the staged direction needs consent nobody gave.
        tbl.insert(
            "accept_unsigned_allow".into(),
            Value::Boolean(b.accept_unsigned_allow),
        );
        if let Some(r) = b.auth_token_ref.as_deref() {
            tbl.insert("auth_token_ref".into(), Value::String(r.to_string()));
        }
    }
    Value::Table(tbl)
}

/// Handle keys for the list edit modal. Routes by `mode`:
///
/// - `Edit` — Tab / Shift-Tab cycle fields, arrow keys cycle picker
///   and toggle values, text fields accept char / backspace, `Ctrl+S`
///   commits via the shared write pipeline, `Esc` discards. Pressing
///   `Enter` while focus is on the Delete button swaps the modal body
///   to `ConfirmDelete`.
/// - `ConfirmDelete { typed }` — char / backspace edit the typed
///   buffer, `Enter` proceeds with the delete only when
///   `typed == blocklist_id`, `Esc` falls back to `Edit` (no
///   destructive action).
/// - `ConfirmUnsignedAllow { typed }` — the same typed-id gate, reached
///   from `Ctrl+S` when the save would make this an allow-list on a
///   source warden cannot verify. `Enter` on a match records the
///   consent and re-enters `submit_edit_modal`, so the declaration and
///   the write it authorises are one operator action. A mismatch keeps
///   the stage (unlike the delete gate — see
///   `handle_confirm_unsigned_allow_key`); `Esc` returns to `Edit` with
///   nothing declared.
/// - `Promote` / `Add` — share the `Edit` state machine for buffer
///   editing; the `Enter` on Delete branch and the `Ctrl+S` submit
///   path branch on mode (see `handle_edit_mode_key` and
///   `submit_edit_modal`).
async fn handle_lists_edit_modal_key(
    app: &mut App,
    key: KeyEvent,
    poller: &IpcPoller,
    config_path: &Path,
) {
    let Some(mut modal) = app.lists.edit_modal.take() else {
        return;
    };

    if modal.submitting && !matches!(key.code, KeyCode::Esc) {
        // Block re-entrant submits — only Esc escapes the in-flight
        // state. Mirrors the assignment-modal pattern.
        app.lists.edit_modal = Some(modal);
        return;
    }

    match modal.mode.clone() {
        app::EditModalMode::Edit | app::EditModalMode::Promote { .. } | app::EditModalMode::Add => {
            // Promote and Add share the same edit-state machine as
            // Edit (text inputs, picker cycling, Tab/Shift-Tab focus
            // motion); the per-mode branches live inside
            // `handle_edit_mode_key` (Enter on Delete/Cancel) and
            // `submit_edit_modal` (id validation, orphan-source removal).
            handle_edit_mode_key(app, &mut modal, key, poller, config_path).await
        }
        app::EditModalMode::ConfirmDelete { typed } => {
            handle_confirm_delete_key(app, &mut modal, typed, key, poller, config_path).await
        }
        app::EditModalMode::ConfirmUnsignedAllow { typed } => {
            if handle_confirm_unsigned_allow_key(app, &mut modal, typed, key) {
                submit_edit_modal(app, modal, poller, config_path).await;
            }
        }
    }
}

async fn handle_edit_mode_key(
    app: &mut App,
    modal: &mut app::EditListModal,
    key: KeyEvent,
    poller: &IpcPoller,
    config_path: &Path,
) {
    use app::{EditField, IntervalChoice};

    // Ctrl+S → save before any other handling so it can fire from any
    // field. ASCII 0x13 = Ctrl+S in some terminals (Char('s') + CONTROL
    // is the canonical event though).
    if matches!(key.code, KeyCode::Char('s') | KeyCode::Char('S'))
        && key.modifiers.contains(KeyModifiers::CONTROL)
    {
        submit_edit_modal(app, modal.clone(), poller, config_path).await;
        return;
    }

    match key.code {
        KeyCode::Esc => {
            // Drop the modal — discard buffers.
            app.lists.edit_modal = None;
            return;
        }
        // Down/Up alias Tab/BackTab. They share the
        // arm, so arrow-driven focus movement clears the chip picker's
        // type-ahead state exactly like Tab does — a separate arm would
        // have leaked it.
        KeyCode::Tab | KeyCode::Down => {
            modal.focus = modal.focus.next_in(&modal.mode, modal.advanced_expanded);
            modal.error_message = None;
        }
        KeyCode::BackTab | KeyCode::Up => {
            modal.focus = modal.focus.prev_in(&modal.mode, modal.advanced_expanded);
            modal.error_message = None;
        }
        // Value-cycling moves off Up/Down onto Left/Right (unbound here
        // before this change). Text fields have no values to cycle and no
        // intra-field cursor to move — `place_cursor` is always fed
        // `VALUE_COL + value_len`, i.e. pinned to end-of-buffer — so Left
        // on a text field is a deliberate no-op, not a lost gesture.
        // One caveat, recorded here rather than by reference: on
        // `Interval`, cycling off `Custom` clears `interval_custom_buf`,
        // and that buffer is typed into. The clear predates this change
        // and is left as-is. (This cited a NOTES-s3b.md that was never
        // committed and no longer exists — the substance was already
        // inline, so only the dangling pointer is gone.)
        KeyCode::Left => match modal.focus {
            EditField::Nature => {
                modal.nature = match modal.nature {
                    crate::config::schema::BlocklistBase::Deny => {
                        crate::config::schema::BlocklistBase::Allow
                    }
                    crate::config::schema::BlocklistBase::Allow => {
                        crate::config::schema::BlocklistBase::Deny
                    }
                    // Same one-way exit as `[K]`, same reasoning — see the
                    // `[K]` handler. The seed (`nature: blist.base`) keeps
                    // `Ignore` intact, so a save that never touches this
                    // field preserves the operator's declaration; only an
                    // explicit arrow leaves it, and only toward deny.
                    crate::config::schema::BlocklistBase::Ignore => {
                        crate::config::schema::BlocklistBase::Deny
                    }
                };
            }
            EditField::Enabled => {
                modal.enabled = !modal.enabled;
            }
            EditField::Interval => {
                modal.interval = modal.interval.prev();
                if !matches!(modal.interval, IntervalChoice::Custom) {
                    modal.interval_custom_buf.clear();
                }
            }
            EditField::Format => {
                modal.format = match modal.format {
                    crate::config::schema::BlocklistFormat::Domains => {
                        crate::config::schema::BlocklistFormat::Hosts
                    }
                    crate::config::schema::BlocklistFormat::Adguard => {
                        crate::config::schema::BlocklistFormat::Domains
                    }
                    crate::config::schema::BlocklistFormat::Hosts => {
                        crate::config::schema::BlocklistFormat::Adguard
                    }
                };
            }
            _ => {}
        },
        KeyCode::Right => match modal.focus {
            EditField::Nature => {
                modal.nature = match modal.nature {
                    crate::config::schema::BlocklistBase::Deny => {
                        crate::config::schema::BlocklistBase::Allow
                    }
                    crate::config::schema::BlocklistBase::Allow => {
                        crate::config::schema::BlocklistBase::Deny
                    }
                    // Same one-way exit as `[K]`, same reasoning — see the
                    // `[K]` handler. The seed (`nature: blist.base`) keeps
                    // `Ignore` intact, so a save that never touches this
                    // field preserves the operator's declaration; only an
                    // explicit arrow leaves it, and only toward deny.
                    crate::config::schema::BlocklistBase::Ignore => {
                        crate::config::schema::BlocklistBase::Deny
                    }
                };
            }
            EditField::Enabled => {
                modal.enabled = !modal.enabled;
            }
            EditField::Interval => {
                modal.interval = modal.interval.next();
                if !matches!(modal.interval, IntervalChoice::Custom) {
                    modal.interval_custom_buf.clear();
                }
            }
            EditField::Format => {
                modal.format = match modal.format {
                    crate::config::schema::BlocklistFormat::Domains => {
                        crate::config::schema::BlocklistFormat::Adguard
                    }
                    crate::config::schema::BlocklistFormat::Adguard => {
                        crate::config::schema::BlocklistFormat::Hosts
                    }
                    crate::config::schema::BlocklistFormat::Hosts => {
                        crate::config::schema::BlocklistFormat::Domains
                    }
                };
            }
            _ => {}
        },
        KeyCode::Enter => {
            if modal.focus == EditField::DeleteButton {
                match &modal.mode {
                    app::EditModalMode::Add => {
                        // Bottom-row focus in Add mode is a "Cancel"
                        // affordance — same effect as Esc, but reachable
                        // by Tab so the operator who lives in the form
                        // can back out without remembering Esc.
                        app.lists.edit_modal = None;
                        return;
                    }
                    app::EditModalMode::Promote { source } => {
                        // Promote-mode "Discard source" — drop the
                        // orphan from [lists].sources and close the
                        // modal. No v1 entry exists yet so there is
                        // nothing to validator-check; the source string
                        // removal is a one-line legacy mutation.
                        let source = source.clone();
                        match remove_source_from_master(config_path, &source) {
                            Ok(()) => {
                                app.lists.edit_modal = None;
                                app.loaded_config = load_v1_config(config_path);
                                let outcome = crate::cli::commands::ipc_reload::attempt_reload(
                                    poller.socket_path(),
                                )
                                .await;
                                let _ = outcome;
                                poll_active_leaf(app, poller).await;
                                app.status_ok(format!("removed orphan source: {source}"));
                                return;
                            }
                            Err(e) => {
                                modal.error_message = Some(format!("could not remove source: {e}"));
                            }
                        }
                    }
                    _ => {
                        modal.mode = app::EditModalMode::ConfirmDelete {
                            typed: String::new(),
                        };
                        modal.error_message = None;
                        modal.status_message = None;
                    }
                }
            } else if modal.focus == EditField::Advanced {
                // Variant-A SOURCE collapse toggle: reveal / hide Format,
                // Interval and AuthTokenRef. The three governed fields
                // leave the Tab cycle when hidden (see EditField::cycle).
                modal.advanced_expanded = !modal.advanced_expanded;
                modal.error_message = None;
            } else if modal.focus == EditField::Cancel {
                // Button-row Cancel — same effect as Esc, reachable by Tab.
                app.lists.edit_modal = None;
                return;
            } else if modal.focus == EditField::Save {
                // Button-row Save — same effect as Ctrl+S.
                submit_edit_modal(app, modal.clone(), poller, config_path).await;
                return;
            }
        }
        KeyCode::Backspace => {
            edit_text_field(modal, |s| {
                s.pop();
            });
        }
        KeyCode::Char(c) => {
            edit_text_field(modal, |s| {
                s.push(c);
            });
        }
        _ => {}
    }
    app.lists.edit_modal = Some(modal.clone());
}

/// Apply a text-buffer edit only when the focused field is a text
/// input. Picker / toggle / read-only / Delete-button focuses ignore
/// raw chars + backspace. `ListId` only accepts edits in Promote mode —
/// in Edit mode it's not even in the focus cycle (id is immutable).
fn edit_text_field(modal: &mut app::EditListModal, edit: impl FnOnce(&mut String)) {
    use app::{EditField, EditModalMode, IntervalChoice};
    let target: Option<&mut String> = match modal.focus {
        EditField::ListId
            if matches!(
                modal.mode,
                EditModalMode::Promote { .. } | EditModalMode::Add
            ) =>
        {
            Some(&mut modal.blocklist_id)
        }
        EditField::DisplayName => Some(&mut modal.display_name),
        EditField::Url => Some(&mut modal.url),
        EditField::AuthTokenRef => Some(&mut modal.auth_token_ref),
        EditField::Interval if matches!(modal.interval, IntervalChoice::Custom) => {
            Some(&mut modal.interval_custom_buf)
        }
        _ => None,
    };
    if let Some(buf) = target {
        edit(buf);
        modal.error_message = None;
    }
}

async fn handle_confirm_delete_key(
    app: &mut App,
    modal: &mut app::EditListModal,
    mut typed: String,
    key: KeyEvent,
    poller: &IpcPoller,
    config_path: &Path,
) {
    match key.code {
        KeyCode::Esc => {
            // Back to edit mode — no destructive action.
            modal.mode = app::EditModalMode::Edit;
            modal.error_message = None;
            app.lists.edit_modal = Some(modal.clone());
        }
        KeyCode::Backspace => {
            typed.pop();
            modal.error_message = None;
            modal.mode = app::EditModalMode::ConfirmDelete { typed };
            app.lists.edit_modal = Some(modal.clone());
        }
        KeyCode::Char(c) => {
            typed.push(c);
            modal.error_message = None;
            modal.mode = app::EditModalMode::ConfirmDelete { typed };
            app.lists.edit_modal = Some(modal.clone());
        }
        KeyCode::Enter => {
            if typed != modal.blocklist_id {
                // Two changes, and they are one decision.
                //
                // **Stay in ConfirmDelete.** Bouncing to `Edit` discarded
                // the typed buffer, and — worse — made the error row this
                // stage reserves unreachable for the only path that can
                // populate it: the stage that would have drawn it is no
                // longer the stage being rendered. The Archetype-C
                // migration made staying strictly cheaper: the message wraps
                // across the two rows `hint_rows: None` already reserves,
                // so it costs ZERO extra rows and the input row survives
                // beside it.
                //
                // **Name what was expected.** Lists was the last typed-
                // confirm gate that refused without saying what it
                // wanted. Rules and Tags both name the expected value;
                // this now matches that wording.
                //
                // The frozen const stays the lede rather than being
                // replaced: it lives in `cli/commands/blocklists.rs`,
                // owned separately, and keeping it means
                // its byte-for-byte pin still guards a string that is
                // really on screen.
                modal.error_message = Some(tabs::lists::delete_confirm_mismatch_message(
                    &typed,
                    &modal.blocklist_id,
                ));
                modal.status_message = None;
                // The buffer survives, so a one-character typo costs one
                // Backspace rather than the whole gate.
                modal.mode = app::EditModalMode::ConfirmDelete { typed };
                app.lists.edit_modal = Some(modal.clone());
                return;
            }
            // Match — proceed with the delete pipeline.
            submit_delete_modal(app, modal.clone(), poller, config_path).await;
        }
        _ => {
            modal.mode = app::EditModalMode::ConfirmDelete { typed };
            app.lists.edit_modal = Some(modal.clone());
        }
    }
}

/// Keys for the typed-id consent gate.
///
/// Deliberately **not** a copy of [`handle_confirm_delete_key`] in one
/// respect: a mismatched buffer keeps the stage instead of bouncing to
/// `Edit`. The delete gate can bounce because its trigger is one Enter
/// on a button; this one is reached from `Ctrl+S`, so a bounce would
/// make a typo cost the operator a re-submit and re-read of the whole
/// notice. Refusing in place, with the reason in the error slot, is also
/// what the scope modal settled on — a refused keypress that re-stashes
/// the state untouched is indistinguishable from a dead key.
fn handle_confirm_unsigned_allow_key(
    app: &mut App,
    modal: &mut app::EditListModal,
    mut typed: String,
    key: KeyEvent,
) -> bool {
    match key.code {
        KeyCode::Esc => {
            // Back to the form with `consent_declared` untouched. A list
            // whose file already consents must come out of here exactly
            // as it went in — this stage grants, it never revokes.
            modal.mode = app::EditModalMode::Edit;
            modal.error_message = None;
            app.lists.edit_modal = Some(modal.clone());
            false
        }
        KeyCode::Backspace => {
            typed.pop();
            modal.error_message = None;
            modal.mode = app::EditModalMode::ConfirmUnsignedAllow { typed };
            app.lists.edit_modal = Some(modal.clone());
            false
        }
        KeyCode::Char(c) => {
            typed.push(c);
            modal.error_message = None;
            modal.mode = app::EditModalMode::ConfirmUnsignedAllow { typed };
            app.lists.edit_modal = Some(modal.clone());
            false
        }
        KeyCode::Enter => {
            if typed != modal.blocklist_id {
                modal.error_message =
                    Some(tabs::lists::UNSIGNED_ALLOW_CONFIRM_MISMATCH.to_string());
                modal.mode = app::EditModalMode::ConfirmUnsignedAllow { typed };
                app.lists.edit_modal = Some(modal.clone());
                return false;
            }
            // Declared. Back to `Edit` and straight into the save the
            // operator already asked for — the consent and the write it
            // authorises belong to one action, exactly as
            // `run_set_kind_with_ack` writes both in one document
            // mutation.
            modal.consent_declared = true;
            modal.mode = app::EditModalMode::Edit;
            modal.error_message = None;
            true
        }
        _ => {
            modal.mode = app::EditModalMode::ConfirmUnsignedAllow { typed };
            app.lists.edit_modal = Some(modal.clone());
            false
        }
    }
}

/// Build a `toml::Value::Table` representing the v1 `[[blocklists]]` row
/// the operator's modal buffers should produce. `trust` and `id` are
/// preserved verbatim from `modal.original` (read-only fields).
/// Returns an `Err` with an operator-friendly message when the
/// numeric buffers don't parse — caller surfaces it in the modal footer.
fn build_blocklist_value(modal: &app::EditListModal) -> Result<toml::Value, String> {
    use toml::Value;

    let display_name = modal.display_name.trim();
    if display_name.is_empty() {
        return Err("display name cannot be empty".to_string());
    }
    let url = modal.url.trim();
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(format!(
            "URL must start with http:// or https:// (got '{url}')"
        ));
    }

    let interval_hours: u32 = match modal.interval.hours() {
        Some(h) => h,
        None => modal
            .interval_custom_buf
            .trim()
            .parse::<u32>()
            .map_err(|_| {
                format!(
                    "custom interval hours must be a positive integer (got '{}')",
                    modal.interval_custom_buf
                )
            })?,
    };
    if interval_hours == 0 {
        return Err("update interval must be ≥ 1 hour".to_string());
    }

    // `max_entries` is no longer operator-editable from the modal
    // (no meaningful way to choose which entries get truncated). The
    // schema field is preserved at its pre-edit value so existing TOML
    // is not silently rewritten.
    let max_entries: u64 = modal.original.max_entries;

    // Wire tokens come from the schema enums themselves, never from a
    // local `match`. A previous hand-rolled map here once still said
    // `Deny => "block"` after the schema renamed
    // the token to `"deny"` (no serde alias), so every save of a
    // deny-kind list — which is nearly every list — was refused at load
    // with `unknown variant` and the modal could not write at all.
    let format_label = modal.format.wire_str();
    let kind_label = modal.nature.wire_str();
    let trust_label = modal.original.trust.wire_str();

    let mut tbl = toml::map::Map::new();
    tbl.insert("id".into(), Value::String(modal.blocklist_id.clone()));
    tbl.insert(
        "display_name".into(),
        Value::String(display_name.to_string()),
    );
    tbl.insert("url".into(), Value::String(url.to_string()));
    tbl.insert("format".into(), Value::String(format_label.to_string()));
    tbl.insert(
        "update_interval_hours".into(),
        Value::Integer(interval_hours as i64),
    );
    tbl.insert("max_entries".into(), Value::Integer(max_entries as i64));
    // Same contract as `max_entries`: the modal does not edit this field,
    // and this row REPLACES the whole entry, so omitting it would silently
    // reset an operator-tuned `max_consecutive_failures` to the schema
    // default (5) on the next save.
    tbl.insert(
        "max_consecutive_failures".into(),
        Value::Integer(modal.original.max_consecutive_failures as i64),
    );
    tbl.insert("enabled".into(), Value::Boolean(modal.enabled));
    tbl.insert("base".into(), Value::String(kind_label.to_string()));
    tbl.insert("trust".into(), Value::String(trust_label.to_string()));
    // Same contract as `max_entries` and `max_consecutive_failures` above:
    // the modal does not edit this field, and this row REPLACES the whole
    // entry, so omitting it resets a declared consent to `false`.
    //
    // That is not a cosmetic loss. An operator who set up a remote
    // allow-list from the CLI — the documented path — and then changed
    // anything at all here (the display name, the interval) had the
    // consent stripped from the file, and the validator refused the very
    // save the TUI had just built: the list became uneditable from the
    // TUI, for a field the modal never showed them.
    //
    // Preserved, and now also declarable — but never synthesised. The two
    // sources are kept apart on purpose: `modal.original` is what the file
    // already said, `modal.consent_declared` is what the operator typed
    // into `ConfirmUnsignedAllow` during this session. Writing a bare
    // `true` here, or seeding `consent_declared` from `original`, would
    // both be warden fabricating a declaration nobody made — the first
    // for every list, the second for the list the operator then backed
    // out of with Esc.
    tbl.insert(
        "accept_unsigned_allow".into(),
        Value::Boolean(modal.original.accept_unsigned_allow || modal.consent_declared),
    );
    if !modal.auth_token_ref.trim().is_empty() {
        tbl.insert(
            "auth_token_ref".into(),
            Value::String(modal.auth_token_ref.trim().to_string()),
        );
    }
    // **Writing `tags` stopped, and that is a deliberate
    // exception to the preservation rule stated three times above.**
    //
    // Every other unedited field is carried across because this row
    // REPLACES the whole entry (`upsert_id_keyed` does `*item = entry`),
    // so an omission silently resets an operator's value. `tags` is the
    // one field where writing it is the harmful direction:
    //
    //   - Nothing reads it any more. `effective_direction` is
    //     `profile.lists[list]` falling back to `list.base`; the only
    //     surviving readers are validator WARNs, since retired.
    //   - `Blocklist` is `#[serde(deny_unknown_fields)]`, so once
    //     the field is removed from the schema, a row still carrying
    //     `tags = [...]`
    //     does not merely look stale — it FAILS TO LOAD with `unknown
    //     field`. Preserving it here would be writing a landmine onto
    //     configs that run household DNS.
    //   - `migrate.rs` deliberately does NOT strip tags
    //     (`apply_v2_to_v3_transformations`: "`tags`, anywhere. They stay
    //     exactly as the file had them"), so
    //     nothing else is going to clean up after this writer.
    //
    // A list edited from the TUI therefore sheds its `tags` array, which
    // narrows the blast radius of the `deny_unknown_fields` problem rather
    // than widening it. It does NOT solve that problem — nothing yet
    // strips `tags` from files already on disk.
    Ok(Value::Table(tbl))
}

/// What `Ctrl+S` has to do about direction before anything is written.
///
/// **Two variants, not four — and the two that left were unreachable
/// rather than unused.** `NeedsTag` and `NeedsNonSystemTag` dispatched on
/// `AllowDirectionGates::needs_tag` / `needs_non_system_tag`, which became
/// permanently `false`: both tag gates lost
/// their premise when tag intersection stopped deciding which lists reach
/// which clients, and the same change stopped `warden blocklist tag add`
/// from writing tags at all — so an operator refused by them would have
/// been told to do a thing the next verb also refuses.
///
/// They were removed rather than left in place because a runtime `bool`
/// that is always `false` fails **no** gate: not `dead_code`, not
/// `unreachable_patterns`, not `-D warnings`. Four branches that read as
/// live defences and are not is prose that cannot fail a build. Deleting
/// the variants turns the
/// same guarantee into a compile error the day anything tries to raise
/// them again.
///
/// The **signature** of `allow_direction_gates` is untouched: its two tag
/// parameters are due to retire, and pulling them here would break the CLI
/// mid-change. Every caller still reads them out of the file and hands
/// them over, so the day they leave is a compile error and not a
/// behaviour change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AllowGateOutcome {
    /// Not an allow-list, or the consent door already open.
    Proceed,
    /// Swap the body to the typed-id consent notice.
    NeedsConsent,
}

/// Run the allow-direction gates against the modal's own state.
///
/// Split out of [`submit_edit_modal`] purely so the decision is testable
/// without an async runtime and an IPC socket — the save path around it
/// needs both, and a rule nobody can assert cheaply is a rule that
/// drifts.
///
/// The last two arguments used to be a real reading of the file's tags —
/// `modal.tags`, seeded from disk by
/// [`tabs::lists::build_edit_modal_for`] precisely so this question had
/// an honest input rather than the loaded config's promoted
/// `["uncategorized"]`. The picker is gone, so there is no
/// reading left to take.
///
/// **The two placeholder parameters are gone.** They were
/// passed as a named constant rather than a bare `true`, because a bare
/// `true` here READ like "the file has no tags" — a measurement nobody
/// took. Keeping them in the signature until the field itself went was
/// deliberate: the arity change is a compile error in every caller at
/// once, which is how this call site was found rather than missed.
fn allow_gate_for_modal(modal: &app::EditListModal) -> AllowGateOutcome {
    if modal.nature != crate::config::schema::BlocklistBase::Allow {
        return AllowGateOutcome::Proceed;
    }
    let gates = crate::cli::commands::blocklists::allow_direction_gates(
        modal.original.trust,
        modal.original.accept_unsigned_allow,
        modal.consent_declared,
    );
    // Consent is the only door left, so there is nothing to order it
    // against — the tag gates that used to be read first are gone.
    if gates.needs_consent {
        AllowGateOutcome::NeedsConsent
    } else {
        AllowGateOutcome::Proceed
    }
}

/// The `Reloaded` arm's message: the promote warning if there is one,
/// otherwise the plain success line.
///
/// **This is reduced to a two-way choice.** It used to interleave
/// a third element — the dropped-pending-tag notice — and the whole point
/// of the function was RANKING those three: a partial write outranks a
/// lost slug, because the legacy source is still in `[lists].sources` and
/// the daemon fetches the same URL twice until the operator repairs it,
/// where a lost slug costs a retype. Only one of the two fitted in the
/// toast's 33 columns.
///
/// With the tag picker gone there is no slug to drop and nothing to rank
/// the warning against. It stays a named function rather than being
/// inlined because the arm that holds it is unreachable from a test — it
/// needs `Promote` + a failed orphan removal + a daemon that answers the
/// reload — so this is the only place the choice can be asserted.
fn reloaded_status_text(promote_warning: Option<String>, base: String) -> String {
    promote_warning.unwrap_or(base)
}

async fn submit_edit_modal(
    app: &mut App,
    mut modal: app::EditListModal,
    poller: &IpcPoller,
    config_path: &Path,
) {
    use crate::cli::commands::blocklists::{format_list_edit_ok, LIST_EDIT_DAEMON_UNREACHABLE};
    use crate::cli::commands::ipc_reload::{attempt_reload, ReloadOutcome};
    use crate::cli::commands::target::{
        read_or_empty, resolve_target_file, upsert_id_keyed, write_value_validated, EntityClass,
    };
    use crate::config::schema::Id;

    // Promote- and Add-mode pre-flight: id is operator-typed so it has
    // to clear schema validation + uniqueness before we touch any file.
    // Edit mode skips this because the id was captured at modal-open
    // from an already-validated `[[blocklists]]` entry (id is
    // read-only).
    if matches!(
        &modal.mode,
        app::EditModalMode::Promote { .. } | app::EditModalMode::Add
    ) {
        let trimmed = modal.blocklist_id.trim().to_string();
        if let Err(e) = Id::new(&trimmed) {
            modal.error_message = Some(format!("invalid id: {e}"));
            modal.submitting = false;
            app.lists.edit_modal = Some(modal);
            return;
        }
        if let Some(loaded) = app.loaded_config.as_ref() {
            if loaded
                .config
                .blocklists
                .iter()
                .any(|b| b.id.as_str() == trimmed)
            {
                modal.error_message = Some(format!(
                    "id '{trimmed}' is already used by another [[blocklists]] entry"
                ));
                modal.submitting = false;
                app.lists.edit_modal = Some(modal);
                return;
            }
        }
        modal.blocklist_id = trimmed;
    }

    // Add-list pre-flight
    // gates 2 (dedup by URL) + 3 (HEAD reachability probe). Gate 1
    // (URL parses to http/https) lives inside `build_blocklist_value`
    // below; surfacing it here AS WELL would double the error surface
    // for no benefit. Promote mode also runs these gates so the orphan
    // doesn't promote into a dead URL.
    if matches!(
        &modal.mode,
        app::EditModalMode::Add | app::EditModalMode::Promote { .. }
    ) {
        let candidate_url = modal.url.trim().to_string();
        if let Some(loaded) = app.loaded_config.as_ref() {
            if let Some(existing) = loaded
                .config
                .blocklists
                .iter()
                .find(|b| b.url == candidate_url)
            {
                modal.error_message = Some(format!(
                    "list URL already added as \"{}\" — use that id or remove it first",
                    existing.id.as_str()
                ));
                modal.submitting = false;
                app.lists.edit_modal = Some(modal);
                return;
            }
        }
        if !modal.skip_head_check
            && (candidate_url.starts_with("http://") || candidate_url.starts_with("https://"))
        {
            if let Err(e) =
                crate::cli::commands::blocklists::probe_url_for_tui(&candidate_url).await
            {
                modal.error_message = Some(e.to_string());
                modal.submitting = false;
                app.lists.edit_modal = Some(modal);
                return;
            }
        }
    }

    // The one remaining door to `base = allow`. Reached on every save
    // whose Nature reads Allow, not only on the save that flipped it: a
    // list that already permits can have its trust moved under it here
    // just as easily.
    //
    // It used to be "the two doors" — the tag refusals were the other one,
    // and they are gone with their premise (see
    // [`AllowGateOutcome`]).
    match allow_gate_for_modal(&modal) {
        AllowGateOutcome::Proceed => {}
        AllowGateOutcome::NeedsConsent => {
            // Not an error — a question. The stage owns the copy; this
            // clears any stale error so the notice opens clean.
            modal.error_message = None;
            modal.mode = app::EditModalMode::ConfirmUnsignedAllow {
                typed: String::new(),
            };
            modal.submitting = false;
            app.lists.edit_modal = Some(modal);
            return;
        }
    }

    let value = match build_blocklist_value(&modal) {
        Ok(v) => v,
        Err(msg) => {
            modal.error_message = Some(msg);
            modal.submitting = false;
            app.lists.edit_modal = Some(modal);
            return;
        }
    };

    modal.submitting = true;
    modal.error_message = None;
    modal.status_message = None;
    let blocklist_id = modal.blocklist_id.clone();
    // Captured here because `modal` is moved into `app.lists.edit_modal`
    // below, and the success arm needs to know whether this save was the
    // one that granted the consent — `LIST_EDIT_OK` says nothing about a
    // standing exposure the operator just accepted.
    let consent_granted_now = modal.consent_declared;
    let promote_source: Option<String> = match &modal.mode {
        app::EditModalMode::Promote { source } => Some(source.clone()),
        _ => None,
    };
    app.lists.edit_modal = Some(modal.clone());

    let target_path = match resolve_target_file(config_path, EntityClass::Blocklists, None) {
        Ok(p) => p,
        Err(e) => {
            if let Some(m) = app.lists.edit_modal.as_mut() {
                m.submitting = false;
                m.error_message = Some(e.to_string());
            }
            return;
        }
    };
    let (mut doc, _) = match read_or_empty(&target_path) {
        Ok(v) => v,
        Err(e) => {
            if let Some(m) = app.lists.edit_modal.as_mut() {
                m.submitting = false;
                m.error_message = Some(e.to_string());
            }
            return;
        }
    };
    if let Err(e) = upsert_id_keyed(
        &mut doc,
        EntityClass::Blocklists.toml_key(),
        &blocklist_id,
        value,
    ) {
        if let Some(m) = app.lists.edit_modal.as_mut() {
            m.submitting = false;
            m.error_message = Some(e.to_string());
        }
        return;
    }
    if let Err(e) = write_value_validated(config_path, &target_path, &doc) {
        if let Some(m) = app.lists.edit_modal.as_mut() {
            m.submitting = false;
            m.error_message = Some(format!("validator: {e}"));
        }
        return;
    }

    tracing::info!(
        target: "audit",
        action = "blocklist.tui_edit",
        source = %blocklist_id,
        surface = "tui",
        "TUI mutation"
    );

    // Promote-mode follow-up: the v1 entry has landed and validated, so
    // now drop the orphan source line from `[lists].sources` to avoid
    // the daemon downloading the same URL twice (once per registry slot
    // — the legacy slug/URL source AND the new [[blocklists]] entry).
    // Removal failure is non-fatal: the v1 entry is already valid, so
    // we surface the partial state and continue to the reload.
    let mut promote_warning: Option<String> = None;
    if let Some(source) = promote_source.as_deref() {
        if let Err(e) = remove_source_from_master(config_path, source) {
            promote_warning = Some(format!(
                "list saved but could not remove orphan source '{source}': {e}"
            ));
        }
    }

    // Refresh schema cache + reload daemon.
    app.loaded_config = load_v1_config(config_path);
    let outcome = attempt_reload(poller.socket_path()).await;
    match outcome {
        ReloadOutcome::Reloaded => {
            app.status_ok(reloaded_status_text(
                promote_warning.clone(),
                if consent_granted_now {
                    tabs::lists::format_list_allow_consent_saved(&blocklist_id)
                } else {
                    format_list_edit_ok(&blocklist_id)
                },
            ));
            app.lists.edit_modal = None;
        }
        ReloadOutcome::DaemonUnreachable => {
            app.status_err(LIST_EDIT_DAEMON_UNREACHABLE.to_string());
            app.lists.edit_modal = None;
        }
        ReloadOutcome::NoToken { .. } => {
            app.status_err(
                "list saved on disk but no admin token is available to request a reload"
                    .to_string(),
            );
            app.lists.edit_modal = None;
        }
        ReloadOutcome::ReloadFailed(msg) => {
            app.status_err(format!("list saved but daemon rejected reload: {msg}"));
            app.lists.edit_modal = None;
        }
    }
    poll_active_leaf(app, poller).await;
}

/// Strip a single source string out of the master config's
/// `[lists].sources` array. Used by the Promote-orphan flow (after the
/// v1 entry has landed) and by the modal's "Discard source" Tab focus
/// (no v1 entry created). Atomic write + validate_or_revert mirrors the
/// rest of the v1 mutation pipeline; missing array → bail with a clear
/// error so the caller can surface it in the modal footer.
fn remove_source_from_master(master_path: &Path, source: &str) -> anyhow::Result<()> {
    use crate::cli::commands::target::{read_or_empty, write_value_validated};
    let (mut doc, _) = read_or_empty(master_path)?;
    {
        let table = match &mut doc {
            toml::Value::Table(t) => t,
            _ => anyhow::bail!("master config root is not a TOML table"),
        };
        let lists = table
            .get_mut("lists")
            .and_then(|v| v.as_table_mut())
            .ok_or_else(|| anyhow::anyhow!("master config has no [lists] section"))?;
        let sources = lists
            .get_mut("sources")
            .and_then(|v| v.as_array_mut())
            .ok_or_else(|| anyhow::anyhow!("master config has no [lists].sources array"))?;
        let before = sources.len();
        sources.retain(|s| s.as_str().map(|x| x != source).unwrap_or(true));
        if sources.len() == before {
            anyhow::bail!("source not in [lists].sources: {source}");
        }
    }
    write_value_validated(master_path, master_path, &doc)?;
    Ok(())
}

/// Delete flow: the typed-id ConfirmDelete already passed in the caller.
/// Here we route through `run_remove_silent`, which drops the
/// `[[blocklists]]` row AND every `profiles.<id>.lists` override naming
/// it, in one compound mutation. The typed-id confirm is THE safety gate;
/// the operator has already been shown which profiles lose the list
/// (`tabs::lists::compute_cascade_targets`, rendered in the ConfirmDelete
/// prompt), so the cascade is the natural follow-through. Returning to
/// the dangling-ref refusal would force the operator to drop to the CLI,
/// defeating the purpose of the TUI flow.
///
/// **Two claims in this comment were false until `plp-s4c` and one of
/// them is worth keeping as a marker.** It said the cascade removed
/// references from `[profiles.X].blocklists` — a field
/// `lists_categories_v2` deleted — and the `cascade` argument below
/// described itself as the thing that turns the behaviour on. Neither
/// survived contact with the code: `run_remove_silent` enumerates
/// `p.lists.keys()`, and since the `listref` lane its cascade is
/// **unconditional** — the flag reaches the audit row and nothing else,
/// deliberately, because the CLI passes `false` and honouring it there
/// would have left the CLI broken while looking repaired.
///
/// The consequence for this function is that the `else` arm of
/// `cascade_summary` below was unreachable while the cascade was a no-op
/// and now fires for the first time. It is covered by
/// `s53_delete_cascades_a_real_override_and_reports_it`.
/// The clause appended to the delete's success footer when the removal
/// also dropped `profiles.<id>.lists` overrides naming the list.
///
/// Split out of [`submit_delete_modal`] on the `allow_gate_for_modal`
/// precedent — so the decision is assertable without an async runtime, a
/// socket and a temp config. **Its non-empty arm had never executed.**
/// The cascade was a structural no-op from `lists_categories_v2` until
/// the `listref` lane made it real, so `cascade_log` was always empty and
/// this branch was unreachable text: a string that reads fine and had
/// never been rendered once.
///
/// Says "refs", not "profiles that lose the list", and the distinction is
/// load-bearing. This counts the profiles whose OVERRIDE row was
/// rewritten (`run_remove_silent` enumerates `p.lists.keys()`); the
/// confirm prompt the operator saw beforehand counts the profiles that
/// ENFORCED the list, override or inherited `base`
/// (`tabs::lists::compute_cascade_targets`). The second is normally the
/// larger, and the two numbers differing is correct rather than a bug —
/// which is exactly why they must not use the same words.
fn cascade_summary(n: usize) -> String {
    if n == 0 {
        return String::new();
    }
    format!(
        " (cascaded refs from {n} profile{})",
        if n == 1 { "" } else { "s" }
    )
}

async fn submit_delete_modal(
    app: &mut App,
    mut modal: app::EditListModal,
    poller: &IpcPoller,
    config_path: &Path,
) {
    use crate::cli::commands::blocklists::{
        format_list_delete_ok, run_remove_silent, LIST_EDIT_DAEMON_UNREACHABLE,
    };
    use crate::cli::commands::ipc_reload::ReloadOutcome;

    modal.submitting = true;
    modal.error_message = None;
    modal.status_message = None;
    let blocklist_id = modal.blocklist_id.clone();
    app.lists.edit_modal = Some(modal.clone());

    let result = run_remove_silent(
        config_path,
        poller.socket_path(),
        &blocklist_id,
        None,
        // `cascade` reaches the callee's AUDIT ROW only — its removal of
        // dangling overrides is unconditional (see `run_remove_silent`).
        // `true` is still the honest value to pass from here: the typed-id
        // confirm plus the affected-profile list in the prompt are the
        // safety gates, and the operator has explicitly opted into the
        // destructive path. A `false` here would understate that in the
        // audit trail without changing what happens on disk.
        true,
    )
    .await;

    let outcome = match result {
        Ok(o) => o,
        Err(e) => {
            if let Some(m) = app.lists.edit_modal.as_mut() {
                m.submitting = false;
                m.error_message = Some(format!("delete failed: {e}"));
                m.mode = app::EditModalMode::Edit;
            }
            return;
        }
    };

    tracing::info!(
        target: "audit",
        action = "blocklist.tui_delete",
        source = %blocklist_id,
        surface = "tui",
        cascade_count = outcome.cascade_log.len(),
        "TUI mutation"
    );

    app.loaded_config = load_v1_config(config_path);
    let cascade_summary = cascade_summary(outcome.cascade_log.len());
    match outcome.reload_outcome {
        ReloadOutcome::Reloaded => {
            app.status_ok(format!(
                "{}{cascade_summary}",
                format_list_delete_ok(&blocklist_id)
            ));
            app.lists.edit_modal = None;
        }
        ReloadOutcome::DaemonUnreachable => {
            app.status_err(LIST_EDIT_DAEMON_UNREACHABLE.to_string());
            app.lists.edit_modal = None;
        }
        ReloadOutcome::NoToken { .. } => {
            app.status_err(
                "list deleted on disk but no admin token is available to request a reload"
                    .to_string(),
            );
            app.lists.edit_modal = None;
        }
        ReloadOutcome::ReloadFailed(msg) => {
            app.status_err(format!("list deleted but daemon rejected reload: {msg}"));
            app.lists.edit_modal = None;
        }
    }
    poll_active_leaf(app, poller).await;
}

// ── Lists edit modal key handler ends here ────────────────────────────

// ── Query Log rule picker: opener + key handler ───────────────────────

/// Build a [`query_log_rule_modal::QueryLogRuleModal`] from the focused
/// row in the Query Log table. Returns `None` when no row is focused, the
/// row's domain is empty, or the row's `result` status is not actionable
/// (`LOCAL` / `REFUSED` / `HINFO` / unknown future status — see
/// [`query_log_rule_modal::inferred_action`]). Captures the data once at
/// this moment so later scrolls do not invalidate the modal's state.
///
/// There is no `action` parameter — auto-flip via
/// [`query_log_rule_modal::QueryLogRuleModal::open_for_query_row`] is the
/// single source of truth, so no caller can request the wrong action.
fn build_query_log_rule_modal(app: &App) -> Option<query_log_rule_modal::QueryLogRuleModal> {
    // Resolve the operator's stable entry key to the current
    // index so the captured row is the one they highlighted, not whatever
    // slid under the cursor on the last 3s poll. Fall back to the raw
    // cursor before the key is seeded.
    let cursor = crate::tui::app::resolve_row_index(
        &app.query_log.entries,
        app.query_log.selected_key.as_ref(),
        |e| Some(tabs::query_log::entry_key(e)),
    )
    .or_else(|| app.query_log.table_state.selected())?;
    let entry = app.query_log.entries.get(cursor)?;
    if entry.domain.is_empty() {
        return None;
    }

    let display_client = entry
        .client_name
        .clone()
        .unwrap_or_else(|| entry.client_ip.clone());

    query_log_rule_modal::QueryLogRuleModal::open_for_query_row(
        entry,
        display_client,
        custom_list_rows(app),
    )
}

/// Every declared custom list, in config order, with the profiles that
/// mount it.
///
/// The mount state is a snapshot: the picker states it on the row the
/// operator is about to write into, so a list nobody mounts announces
/// itself at the moment it would silently swallow a rule.
fn custom_list_rows(app: &App) -> Vec<query_log_rule_modal::ListRow> {
    let Some(loaded) = app.loaded_config.as_ref() else {
        return Vec::new();
    };
    loaded
        .config
        .custom_lists
        .iter()
        .map(|c| {
            let id = c.id.as_str().to_string();
            let display = if c.display_name.is_empty() {
                id.clone()
            } else {
                format!("{} ({id})", c.display_name)
            };
            let mounted = profiles_mounting(app, &id);
            query_log_rule_modal::ListRow::new(id, display, mounted)
        })
        .collect()
}

/// Pick the footer message to surface when Enter is
/// pressed on a Query Log row whose status maps to no rule action.
/// Reads `app.query_log.entries[selected].result` and returns one of
/// the three `QUERY_NOT_ACTIONABLE_*` frozen strings. An empty
/// selection (or out-of-range index) falls through to `_UNKNOWN` so
/// the footer never goes silent.
fn footer_message_for_neutral_row(app: &App) -> &'static str {
    // Same resolution `build_query_log_rule_modal` uses, right above
    // it in the `KeyCode::Enter` arm. The two agree only because
    // `anchor_query_log_cursor` writes the resolved index back into the
    // `TableState` before either runs — real, but undocumented coupling
    // on a tab whose row set slides every 3 seconds. Resolving the key
    // directly here makes the two agree by construction.
    let result = crate::tui::app::resolve_row_index(
        &app.query_log.entries,
        app.query_log.selected_key.as_ref(),
        |e| Some(tabs::query_log::entry_key(e)),
    )
    .or_else(|| app.query_log.table_state.selected())
    .and_then(|idx| app.query_log.entries.get(idx))
    .map(|entry| entry.result.as_str())
    .unwrap_or("");
    match result {
        "LOCAL" => tabs::query_log::QUERY_NOT_ACTIONABLE_LOCAL,
        "REFUSED" | "HINFO" => tabs::query_log::QUERY_NOT_ACTIONABLE_REFUSED,
        _ => tabs::query_log::QUERY_NOT_ACTIONABLE_UNKNOWN,
    }
}

/// Drive the picker's state machine on each keypress. On confirm writes
/// every marked pack, then `attempt_reload` to push the change live.
async fn handle_query_log_rule_modal_key(
    app: &mut App,
    key: KeyEvent,
    poller: &IpcPoller,
    config_path: &Path,
) {
    let Some(mut modal) = app.query_log_rule_modal.take() else {
        return;
    };

    use query_log_rule_modal::Stage;

    match &modal.stage {
        // Report state — any keypress closes the modal.
        Stage::Done(_) => {}
        Stage::NewList(_) => {
            handle_query_log_new_list_key(app, modal, key, poller, config_path).await;
        }
        Stage::Picking => match key.code {
            KeyCode::Esc => {}
            KeyCode::Down | KeyCode::Char('j') => {
                modal.move_cursor(1);
                app.query_log_rule_modal = Some(modal);
            }
            KeyCode::Up | KeyCode::Char('k') => {
                modal.move_cursor(-1);
                app.query_log_rule_modal = Some(modal);
            }
            KeyCode::Char(' ') => {
                modal.toggle();
                app.query_log_rule_modal = Some(modal);
            }
            // Both cases, like every other single-key binding in the
            // ecosystem: an operator with CapsLock must not press a key
            // that does nothing and says nothing.
            KeyCode::Char('n') | KeyCode::Char('N') => {
                modal.begin_new_list(packs_dir_display(app));
                app.query_log_rule_modal = Some(modal);
            }
            KeyCode::Enter => {
                if modal.selected_ids().is_empty() {
                    // Say why rather than re-stashing untouched: a picker
                    // that opens at zero selections makes an empty Enter
                    // routine, and a silent one reads as a dead key.
                    modal.note_no_selection();
                    app.query_log_rule_modal = Some(modal);
                } else {
                    submit_query_log_rule_modal(app, modal, poller, config_path).await;
                }
            }
            _ => {
                app.query_log_rule_modal = Some(modal);
            }
        },
    }
}

/// Keys for the create-a-list form reached with `n`.
///
/// Delegates to the Custom Lists leaf's own form helpers and its create
/// path, so the two routes to the same form cannot drift apart. The
/// create is a *config* write and takes the tree lock itself, so it must
/// complete and return here before any pack write starts — a guard still
/// live in this process stalls the promotion for the whole lock deadline.
async fn handle_query_log_new_list_key(
    app: &mut App,
    mut modal: query_log_rule_modal::QueryLogRuleModal,
    key: KeyEvent,
    poller: &IpcPoller,
    config_path: &Path,
) {
    use custom_list_modal::FormField;

    let Some(focused) = new_list_form(&modal).map(|f| f.focused) else {
        app.query_log_rule_modal = Some(modal);
        return;
    };

    match key.code {
        KeyCode::Esc => {
            modal.cancel_new_list();
            app.query_log_rule_modal = Some(modal);
        }
        KeyCode::Enter if focused == FormField::Cancel => {
            modal.cancel_new_list();
            app.query_log_rule_modal = Some(modal);
        }
        KeyCode::Enter => {
            submit_query_log_new_list(app, modal, poller, config_path).await;
        }
        _ => {
            if let Some(form) = new_list_form_mut(&mut modal) {
                match key.code {
                    KeyCode::Tab | KeyCode::Down => {
                        form.focused =
                            next_editable_custom_list_field(form.focused, form.mode, true)
                    }
                    KeyCode::BackTab | KeyCode::Up => {
                        form.focused =
                            next_editable_custom_list_field(form.focused, form.mode, false)
                    }
                    KeyCode::Backspace => {
                        if let Some(buf) = custom_list_form_buf(form) {
                            buf.pop();
                        }
                    }
                    KeyCode::Char(c) => {
                        if custom_list_form_buf(form).is_some() {
                            // Split from the push so the error can be
                            // cleared without holding the buffer borrow.
                            form.error_message = None;
                        }
                        if let Some(buf) = custom_list_form_buf(form) {
                            buf.push(c);
                        }
                    }
                    _ => {}
                }
            }
            app.query_log_rule_modal = Some(modal);
        }
    }
}

/// The add-list form inside the picker, when the picker is showing one.
fn new_list_form(
    modal: &query_log_rule_modal::QueryLogRuleModal,
) -> Option<&custom_list_modal::Form> {
    match &modal.stage {
        query_log_rule_modal::Stage::NewList(inner) => match &inner.stage {
            custom_list_modal::Stage::EditingForm(form) => Some(form),
            _ => None,
        },
        _ => None,
    }
}

fn new_list_form_mut(
    modal: &mut query_log_rule_modal::QueryLogRuleModal,
) -> Option<&mut custom_list_modal::Form> {
    match &mut modal.stage {
        query_log_rule_modal::Stage::NewList(inner) => match &mut inner.stage {
            custom_list_modal::Stage::EditingForm(form) => Some(form),
            _ => None,
        },
        _ => None,
    }
}

/// Create the list the form describes, then return to the picker with it
/// marked.
///
/// `create_custom_list` writes the pack file **before** the declaration —
/// a `[[custom_lists]]` entry naming a file that does not exist fails the
/// whole config on the next load, taking every other list with it. The
/// reload is this surface's own: nothing watches the config files, and a
/// list the daemon never sees is a list that filters nothing.
async fn submit_query_log_new_list(
    app: &mut App,
    mut modal: query_log_rule_modal::QueryLogRuleModal,
    poller: &IpcPoller,
    config_path: &Path,
) {
    let resolved = {
        let Some(form) = new_list_form_mut(&mut modal) else {
            app.query_log_rule_modal = Some(modal);
            return;
        };
        match form.try_resolve() {
            Ok(r) => r,
            Err(msg) => {
                // The form keeps the operator's typing: retyping the rest
                // to fix one field is the cost of dropping it.
                form.error_message = Some(msg.clone());
                app.status_err(format!("custom list: {msg}"));
                app.query_log_rule_modal = Some(modal);
                return;
            }
        }
    };

    match create_custom_list(config_path, &resolved) {
        Err(msg) => {
            if let Some(form) = new_list_form_mut(&mut modal) {
                form.error_message = Some(msg.clone());
            }
            app.status_err(format!("custom list: {msg}"));
            app.query_log_rule_modal = Some(modal);
        }
        Ok(msg) => {
            app.status_ok(msg);
            report_reload_to_status(app, poller, "custom list").await;
            app.loaded_config = load_v1_config(config_path);
            modal.adopt_lists(custom_list_rows(app), Some(resolved.id.as_str()));
            app.query_log_rule_modal = Some(modal);
        }
    }
}

/// Write the rule into every marked pack, then reload once.
///
/// **One lock, N appends, one reload.** Each append is a
/// read-modify-write, and taking the guard per list would let another
/// surface interleave between two of them — leaving a reload able to see
/// a multi-list write half done. The guard is scoped closed before the
/// reload for the same reason `create_custom_list` scopes its own: a live
/// guard in this process stalls a config promotion for the whole lock
/// deadline.
///
/// Failure is reported **per list**. Three writes out of five do not
/// collapse into one toast: the modal stays open and names which list
/// took the rule and which did not.
async fn submit_query_log_rule_modal(
    app: &mut App,
    mut modal: query_log_rule_modal::QueryLogRuleModal,
    poller: &IpcPoller,
    config_path: &Path,
) {
    use crate::cli::commands::rules::Action;
    use crate::config::custom_list::{add_rule, pack_path, AddOutcome};
    use crate::config::schema::Id;
    use crate::tui::tabs::custom_lists;
    use query_log_rule_modal::{RuleOutcome, RuleReport};

    let allow = matches!(modal.action, Action::Allow);
    let domain = modal.domain.clone();
    let ids = modal.selected_ids();

    let reports: Vec<RuleReport> = {
        let Some(loaded) = app.loaded_config.as_ref() else {
            app.status_err("the configuration could not be read".into());
            app.query_log_rule_modal = Some(modal);
            return;
        };
        let Some(root) = loaded.master_path.parent() else {
            app.status_err("the configuration has no parent directory".into());
            app.query_log_rule_modal = Some(modal);
            return;
        };
        let max = custom_lists::max_pack_bytes(loaded);
        let lock = match custom_lists::claim_tree(loaded) {
            Ok(l) => l,
            Err(e) => {
                app.status_err(format!("rule: {e}"));
                app.query_log_rule_modal = Some(modal);
                return;
            }
        };
        ids.iter()
            .map(|id| {
                let outcome = match Id::new(id.as_str()) {
                    Err(e) => RuleOutcome::Failed(format!("id: {e}")),
                    // A list dropped between open and confirm would
                    // otherwise take a pack write with no declaration
                    // behind it — an orphan file that filters nothing.
                    Ok(pid) if !loaded.config.custom_lists.iter().any(|c| c.id == pid) => {
                        RuleOutcome::Failed("no longer declared".into())
                    }
                    Ok(pid) => match add_rule(&lock, &pack_path(root, &pid), &domain, allow, max) {
                        Ok(AddOutcome::Added) => RuleOutcome::Added,
                        Ok(AddOutcome::AlreadyPresent) => RuleOutcome::AlreadyPresent,
                        Err(e) => RuleOutcome::Failed(e.to_string()),
                    },
                };
                RuleReport {
                    id: id.clone(),
                    outcome,
                }
            })
            .collect()
    };

    let added = reports
        .iter()
        .filter(|r| r.outcome == RuleOutcome::Added)
        .count();
    let failed = reports
        .iter()
        .filter(|r| matches!(r.outcome, RuleOutcome::Failed(_)))
        .count();

    for report in &reports {
        if let RuleOutcome::Failed(msg) = &report.outcome {
            tracing::warn!(
                target: "audit",
                action = "custom_list.rule.add",
                surface = "tui",
                list = %report.id,
                rule_action = modal.action.slug(),
                domain = %domain,
                error = %msg,
                "TUI mutation refused"
            );
        } else {
            tracing::info!(
                target: "audit",
                action = "custom_list.rule.add",
                surface = "tui",
                list = %report.id,
                rule_action = modal.action.slug(),
                domain = %domain,
                already_present = report.outcome == RuleOutcome::AlreadyPresent,
                "TUI mutation"
            );
        }
    }

    // The footer carries the headline while the modal carries the detail:
    // the renderer draws both on the same frame, so the operator sees the
    // status without dismissing the report first.
    if failed > 0 {
        app.status_err(format!(
            "{failed} of {} lists did not accept it",
            reports.len()
        ));
    } else {
        app.status_ok(format!(
            "{}: {domain} written to {} list(s)",
            modal.action.slug(),
            reports.len()
        ));
    }
    modal.finish(reports);
    app.query_log_rule_modal = Some(modal);

    // Nothing changed on disk when every list already carried the rule,
    // so there is nothing for the daemon to reload.
    if added > 0 {
        report_reload_to_status(app, poller, "rule").await;
        // Refresh cached config so subsequent renders pick up the
        // mutation without waiting for the next 30s poll.
        app.loaded_config = load_v1_config(config_path);
        poll_active_leaf(app, poller).await;
    }
}

/// Ask the daemon to reload and route the outcome to the footer.
///
/// The alt-screen swallows `report_reload_outcome`'s stdout, so every
/// arm has to reach the operator through `app`. `Reloaded` is the one
/// arm that stays silent and therefore keeps whatever status the caller
/// already set.
///
/// `noun` names what was written, because the two callers here write
/// different things: a fixed "rule" would tell an operator who created a
/// list against a stopped daemon that a rule was saved.
async fn report_reload_to_status(app: &mut App, poller: &IpcPoller, noun: &str) {
    use crate::cli::commands::ipc_reload::{attempt_reload, ReloadOutcome};

    match attempt_reload(poller.socket_path()).await {
        ReloadOutcome::Reloaded => {}
        ReloadOutcome::DaemonUnreachable => {
            app.status_err(format!(
                "{noun} saved on disk — daemon not running, will activate on next start"
            ));
        }
        ReloadOutcome::NoToken { .. } => {
            app.status_err(format!(
                "{noun} saved on disk but no admin token is available to request a reload"
            ));
        }
        ReloadOutcome::ReloadFailed(msg) => {
            app.status_err(format!("{noun} saved but daemon rejected reload: {msg}"));
        }
    }
}

// ── s44-tui-modals — Local DNS modal openers + key handler + submit ──

/// Snapshot the configured profile ids at modal-open time. The
/// dropdown reads from this snapshot, not from the live `loaded_config`,
/// so a config refresh during the form's lifetime cannot surprise the
/// operator with a profile that disappeared mid-edit. Mirrors the
/// rule picker's capture-at-render-time invariant.
fn snapshot_profile_ids(app: &App) -> Vec<String> {
    app.loaded_config
        .as_ref()
        .map(|loaded| {
            loaded
                .config
                .profiles
                .keys()
                .map(|id| id.as_str().to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// Resolve the focused row on the Local DNS tab into (scope, record)
/// for Edit / Remove modals. `None` when no record is focused.
///
/// One lookup through the unified row vector, resolved from the
/// stable `(scope, domain)` anchor rather than from a visual index — an
/// index is not an identity once a reload or a delete reshuffles the
/// list.
fn focused_local_dns_row(
    app: &App,
) -> Option<(
    crate::cli::commands::local_dns::LocalRecordScope,
    crate::config::settings::LocalDnsRecord,
)> {
    let loaded = app.loaded_config.as_ref()?;
    let rows = tabs::local_dns::build_rows(loaded);
    let idx = tabs::local_dns::index_of_key(&rows, app.local_dns.selected_id.as_ref())?;
    match rows.get(idx)? {
        tabs::local_dns::LocalDnsRow::Record { scope, record } => {
            Some((scope.clone(), (*record).clone()))
        }
        tabs::local_dns::LocalDnsRow::Header(_) => None,
    }
}

/// Build an Add modal, scoped to the focused row.
///
/// **`a` must not guess the scope.** Writing a record to Global when the
/// operator meant a profile — or the reverse — is a silent policy error,
/// not a missed convenience: nothing on screen afterwards says the record
/// went somewhere else, and the fix is a delete plus a re-add in the
/// right place. So there are exactly two cases and no third:
///
/// - **A record is focused.** Its scope IS the answer, and with the unified
///   row vector that is one field read rather than a panel/profile-index reconstruction.
///   Prefill it exactly. (The spec offered "skip the prefill if it costs
///   more than a few lines"; one list made it cheaper than the code it
///   replaces, so the escape hatch is unused.)
/// - **Nothing is focused** — the list is genuinely empty, since the
///   handler seeds the anchor before this runs. There is no row to infer
///   from, so the form does not pretend: it opens with the **Profile
///   field focused** and returns a note naming the scope it opened on, so
///   the operator reads the scope before typing a domain instead of
///   discovering it afterwards.
///
/// Returns the modal plus an optional status note for the caller to
/// raise.
fn build_local_dns_add_modal(app: &App) -> (local_dns_modal::LocalDnsModal, Option<String>) {
    use crate::cli::commands::local_dns::LocalRecordScope;

    let profiles = snapshot_profile_ids(app);
    match focused_local_dns_row(app) {
        Some((LocalRecordScope::Global, _)) => {
            (local_dns_modal::LocalDnsModal::open_add(profiles, 0), None)
        }
        Some((LocalRecordScope::Profile(id), _)) => {
            // `+1` for the leading Global slot in the selector.
            let idx = profiles
                .iter()
                .position(|p| *p == id)
                .map(|i| i + 1)
                .unwrap_or(0);
            (
                local_dns_modal::LocalDnsModal::open_add(profiles, idx),
                None,
            )
        }
        None => {
            let mut modal = local_dns_modal::LocalDnsModal::open_add(profiles, 0);
            if let local_dns_modal::Stage::EditingForm(form) = &mut modal.stage {
                form.focused = local_dns_modal::FormField::Profile;
            }
            (
                modal,
                Some(
                    "no record focused — Add opened on scope Global. ←/→ changes it \
                     before you type a domain."
                        .into(),
                ),
            )
        }
    }
}

/// Build a Remove modal targeting the focused row. Returns `None` if
/// no row is focused.
fn build_local_dns_remove_modal(app: &App) -> Option<local_dns_modal::LocalDnsModal> {
    let (scope, record) = focused_local_dns_row(app)?;
    Some(local_dns_modal::LocalDnsModal::open_remove(scope, &record))
}

/// Build an Edit modal pre-filled from the focused row. Returns `None`
/// if no row is focused.
fn build_local_dns_edit_modal(app: &App) -> Option<local_dns_modal::LocalDnsModal> {
    let (scope, record) = focused_local_dns_row(app)?;
    let profiles = snapshot_profile_ids(app);
    Some(local_dns_modal::LocalDnsModal::open_edit(
        scope, &record, profiles,
    ))
}

/// Drive the Local DNS modal's state machine on each keypress. On
/// submit fires the single-seat helpers — `add_inner` for Add /
/// Edit, `remove_inner` for Remove / Edit — then triggers
/// `attempt_reload`. Mirrors `handle_query_log_rule_modal_key`.
async fn handle_local_dns_modal_key(
    app: &mut App,
    key: KeyEvent,
    poller: &IpcPoller,
    config_path: &Path,
) {
    let Some(mut modal) = app.local_dns.modal.take() else {
        return;
    };

    use local_dns_modal::{ConfirmTier, FormField, Stage};

    // Submitted state — any keypress closes the modal (drop it on the
    // floor by NOT putting it back into `app.local_dns.modal`).
    if modal.is_submitted() {
        return;
    }

    // `Ctrl+s` saves from anywhere on an Archetype-F form.
    //
    // Checked BEFORE the field dispatch, not as a guarded `Char('s')` arm:
    // the `KeyCode::Char(c)` catch-all at the bottom of the form match is
    // what used to append a literal `s` to the focused buffer, so an arm
    // placed after it would be dead. "From anywhere" means ahead of the
    // field dispatch entirely. Mirrors the check in
    // `handle_edit_mode_key`, including the `S` spelling some terminals
    // send.
    //
    // Confirm stages are Archetype C and keep `[y]` / `[n]` — the chord
    // must not reach them, hence the stage guard.
    //
    // No tag valve here — see the note in `handle_label_modal_key`.
    if matches!(key.code, KeyCode::Char('s') | KeyCode::Char('S'))
        && key.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(modal.stage, Stage::EditingForm(_))
    {
        submit_local_dns_modal(app, modal, poller, config_path).await;
        return;
    }

    match &mut modal.stage {
        Stage::EditingForm(form) => {
            match key.code {
                KeyCode::Esc => {
                    // Drop the modal — handler returned without
                    // re-stashing closes it.
                    return;
                }
                KeyCode::Tab | KeyCode::Down => {
                    form.focused = form.focused.next();
                    form.error_message = None;
                }
                KeyCode::BackTab | KeyCode::Up => {
                    form.focused = form.focused.prev();
                    form.error_message = None;
                }
                KeyCode::Enter => {
                    // Discard button → close without saving (same as Esc).
                    if form.focused == FormField::Cancel {
                        return;
                    }
                    // Otherwise Enter submits from any field. A pre-flight
                    // or apply error keeps the form open with an inline
                    // message (see `submit_local_dns_modal`) instead of
                    // dropping the operator's input, so a stray Enter is
                    // recoverable.
                    submit_local_dns_modal(app, modal, poller, config_path).await;
                    return;
                }
                KeyCode::Right => match form.focused {
                    FormField::RecordType => {
                        form.record_type =
                            local_dns_modal::cycle_record_type_next(form.record_type);
                    }
                    FormField::MatchSubdomains => {
                        form.match_subdomains = !form.match_subdomains;
                    }
                    FormField::Profile if form.profile_options_len() > 0 => {
                        form.profile_idx = (form.profile_idx + 1) % form.profile_options_len();
                    }
                    _ => {}
                },
                KeyCode::Left => match form.focused {
                    FormField::RecordType => {
                        form.record_type =
                            local_dns_modal::cycle_record_type_prev(form.record_type);
                    }
                    FormField::MatchSubdomains => {
                        form.match_subdomains = !form.match_subdomains;
                    }
                    FormField::Profile => {
                        let n = form.profile_options_len();
                        if n > 0 {
                            form.profile_idx = (form.profile_idx + n - 1) % n;
                        }
                    }
                    _ => {}
                },
                KeyCode::Char(' ') => match form.focused {
                    FormField::MatchSubdomains => {
                        form.match_subdomains = !form.match_subdomains;
                    }
                    FormField::RecordType => {
                        form.record_type =
                            local_dns_modal::cycle_record_type_next(form.record_type);
                    }
                    FormField::Profile => {
                        if form.profile_options_len() > 0 {
                            form.profile_idx = (form.profile_idx + 1) % form.profile_options_len();
                        }
                    }
                    // For text fields, treat space as a literal char.
                    FormField::Domain | FormField::Value | FormField::Ttl => {
                        text_field_buf(form).push(' ');
                        form.error_message = None;
                    }
                    FormField::Submit => {
                        submit_local_dns_modal(app, modal, poller, config_path).await;
                        return;
                    }
                    FormField::Cancel => {
                        // Discard button → close without saving.
                        return;
                    }
                },
                KeyCode::Backspace => {
                    if matches!(
                        form.focused,
                        FormField::Domain | FormField::Value | FormField::Ttl
                    ) {
                        text_field_buf(form).pop();
                        form.error_message = None;
                    }
                }
                KeyCode::Char(c) => {
                    if matches!(
                        form.focused,
                        FormField::Domain | FormField::Value | FormField::Ttl
                    ) {
                        text_field_buf(form).push(c);
                        form.error_message = None;
                    }
                }
                _ => {}
            }
            app.local_dns.modal = Some(modal);
        }
        Stage::ConfirmingRemove(rc) => {
            match (rc.tier, key.code) {
                // Single-keypress tier: y submits, n/Esc cancels.
                (ConfirmTier::SingleKeypress, KeyCode::Char('y') | KeyCode::Char('Y')) => {
                    submit_local_dns_modal(app, modal, poller, config_path).await;
                }
                (ConfirmTier::SingleKeypress, KeyCode::Char('n') | KeyCode::Char('N'))
                | (_, KeyCode::Esc) => {
                    // Drop the modal — handler returned without
                    // re-stashing closes it.
                }
                // Typed-phrase tier: collect chars; Enter submits when
                // the buffer matches the domain.
                (ConfirmTier::TypedPhrase, KeyCode::Char(c)) => {
                    rc.push_char(c);
                    app.local_dns.modal = Some(modal);
                }
                (ConfirmTier::TypedPhrase, KeyCode::Backspace) => {
                    rc.backspace();
                    app.local_dns.modal = Some(modal);
                }
                (ConfirmTier::TypedPhrase, KeyCode::Enter) => {
                    // `confirm_or_refuse` records why it said no, so the
                    // modal that goes back into `app` carries a refusal on
                    // the notice's error line. It used to be re-stashed
                    // untouched, which made Enter a dead key here.
                    if rc.confirm_or_refuse() {
                        submit_local_dns_modal(app, modal, poller, config_path).await;
                        return;
                    }
                    app.local_dns.modal = Some(modal);
                }
                _ => {
                    app.local_dns.modal = Some(modal);
                }
            }
        }
        Stage::Submitted(_) => {
            // Already handled by the early-return above; unreachable.
        }
    }
}

/// Mutable reference to the buffer behind a text-input field.
fn text_field_buf(form: &mut local_dns_modal::AddForm) -> &mut String {
    use local_dns_modal::FormField;
    match form.focused {
        FormField::Domain => &mut form.domain,
        FormField::Value => &mut form.value,
        FormField::Ttl => &mut form.ttl_input,
        // Other fields are not text inputs — return the value buffer as
        // a harmless default. Caller checks `focused` before using.
        _ => &mut form.value,
    }
}

/// Submit path for all three Local DNS modals. Branches on the stage:
///
/// - Add → `add_inner(scope, spec)` once.
/// - Edit → `remove_inner(original_scope, original_domain, ...)` then
///   `add_inner(new_scope, new_spec)`. Non-atomic — if the second call
///   fails, attempts a best-effort restore by re-adding the original.
/// - Remove → `remove_inner(scope, domain, ...)` once.
///
/// Outcomes flow through `LocalDnsModal::finish` so the renderer
/// shows the success / error message; the modal closes on the next
/// keypress. On a real Apply, fires the shared `attempt_reload` and reloads
/// the cached config so the next render reflects the mutation.
async fn submit_local_dns_modal(
    app: &mut App,
    mut modal: local_dns_modal::LocalDnsModal,
    poller: &IpcPoller,
    config_path: &Path,
) {
    use crate::cli::commands::ipc_reload::{attempt_reload, ReloadOutcome};
    use crate::cli::commands::local_dns::{
        add_inner, format_local_records_added_global, format_local_records_added_profile,
        format_local_records_removed, remove_inner, AddOutcome, LocalRecordScope, RemoveOutcome,
    };
    use local_dns_modal::{Stage, SubmitOutcome};

    let outcome: SubmitOutcome = match &modal.stage {
        Stage::EditingForm(form) => match form.try_resolve() {
            Err(msg) => SubmitOutcome::Failed(msg),
            Ok((scope, spec)) => match form.mode {
                local_dns_modal::FormMode::Add => submit_add(config_path, &scope, &spec),
                local_dns_modal::FormMode::Edit => match form.original.as_ref() {
                    Some(original) => {
                        submit_edit(config_path, &original.scope, &original.spec, &scope, &spec)
                    }
                    // The Add/Edit constructors keep `mode == Edit` and
                    // `original.is_some()` in lock-step; degrade a broken
                    // invariant to a footer error instead of a panic that
                    // would unwind out of the dashboard's main task.
                    None => SubmitOutcome::Failed(
                        "internal error: edit modal lost its original snapshot".into(),
                    ),
                },
            },
        },
        Stage::ConfirmingRemove(rc) => {
            match remove_inner(
                config_path,
                &rc.scope,
                &rc.spec.domain,
                Some(rc.spec.record_type),
                None,
            ) {
                Ok(RemoveOutcome::Removed { .. }) => {
                    let scope_label = match &rc.scope {
                        LocalRecordScope::Global => "global".to_string(),
                        LocalRecordScope::Profile(id) => format!("profile '{id}'"),
                    };
                    SubmitOutcome::Ok(format_local_records_removed(&rc.spec.domain, &scope_label))
                }
                Ok(RemoveOutcome::NotFound) => SubmitOutcome::Failed(format!(
                    "record '{}' not found in scope — already removed?",
                    rc.spec.domain
                )),
                Err(e) => SubmitOutcome::Failed(e.to_string()),
            }
        }
        Stage::Submitted(_) => return,
    };

    // A form (Add/Edit) failure — pre-flight validation (empty field,
    // bad TTL) or an apply/validator rejection — keeps the modal open
    // with the message on the grid's inline validation line instead of
    // dropping to the terminal "failed" screen. The operator fixes the
    // offending field and re-submits without retyping the rest. Remove
    // failures still finish (their confirm screen has no form to keep).
    if let SubmitOutcome::Failed(msg) = &outcome {
        if let Stage::EditingForm(form) = &mut modal.stage {
            app.status_err(format!("local DNS modal: {msg}"));
            form.error_message = Some(msg.clone());
            app.local_dns.modal = Some(modal);
            return;
        }
    }

    let was_ok = matches!(outcome, SubmitOutcome::Ok(_));
    match &outcome {
        SubmitOutcome::Ok(msg) => app.status_ok(msg.clone()),
        SubmitOutcome::Failed(msg) => {
            app.status_err(format!("local DNS modal: {msg}"));
        }
    }
    modal.finish(outcome);
    app.local_dns.modal = Some(modal);

    // Reload + cache invalidation only on a real Apply. Same shape
    // as `submit_query_log_rule_modal`. Errors land on `last_error` so the
    // operator sees them in the footer alongside the modal.
    if was_ok {
        let outcome = attempt_reload(poller.socket_path()).await;
        match outcome {
            ReloadOutcome::Reloaded => {}
            ReloadOutcome::DaemonUnreachable => {
                app.status_err(
                    "local DNS record saved — daemon not running, will activate on next start"
                        .into(),
                );
            }
            ReloadOutcome::NoToken { .. } => {
                app.status_err(
                    "local DNS record saved on disk but no admin token is available to request a reload"
                        .into(),
                );
            }
            ReloadOutcome::ReloadFailed(msg) => {
                app.status_err(format!(
                    "local DNS record saved but daemon rejected reload: {msg}"
                ));
            }
        }
        // Refresh cached config so the table reflects the mutation
        // without waiting for the next refresh.
        app.loaded_config = load_v1_config(config_path);
        poll_active_leaf(app, poller).await;
    }

    // Local helpers — kept inside the submit fn so they share the
    // `add_inner`/`remove_inner` import scope. They return a
    // SubmitOutcome the caller threads into `modal.finish`.
    use local_dns_modal::SubmitOutcome as So;

    fn submit_add(
        config_path: &std::path::Path,
        scope: &LocalRecordScope,
        spec: &crate::cli::commands::local_dns::LocalRecordSpec,
    ) -> So {
        match add_inner(config_path, scope, spec, None) {
            Ok(AddOutcome::Applied {
                devices_affected, ..
            }) => {
                let rt = match spec.record_type {
                    crate::config::settings::LocalDnsRecordType::A => "A",
                    crate::config::settings::LocalDnsRecordType::AAAA => "AAAA",
                    crate::config::settings::LocalDnsRecordType::CNAME => "CNAME",
                };
                let msg = match scope {
                    LocalRecordScope::Global => {
                        format_local_records_added_global(&spec.domain, rt, &spec.value)
                    }
                    LocalRecordScope::Profile(id) => format_local_records_added_profile(
                        &spec.domain,
                        rt,
                        &spec.value,
                        id,
                        devices_affected,
                    ),
                };
                So::Ok(msg)
            }
            Ok(AddOutcome::NoOp) => {
                So::Ok(format!("record '{}' already present — no-op", spec.domain))
            }
            Err(e) => So::Failed(e.to_string()),
        }
    }

    fn submit_edit(
        config_path: &std::path::Path,
        old_scope: &LocalRecordScope,
        old_spec: &crate::cli::commands::local_dns::LocalRecordSpec,
        new_scope: &LocalRecordScope,
        new_spec: &crate::cli::commands::local_dns::LocalRecordSpec,
    ) -> So {
        // Two-phase: drop the original first so the duplicate-check on
        // the validator pre-flight does not refuse the new record on
        // an unchanged (domain, type, match_subdomains) tuple. The
        // window between the two writes is small thanks to valid-
        // ation pre-flight + filesystem atomic-rename + ipc reload
        // coalescing, but the two operations are NOT atomic — if the
        // second write fails the modal reports both errors and
        // attempts a best-effort restore.
        match remove_inner(
            config_path,
            old_scope,
            &old_spec.domain,
            Some(old_spec.record_type),
            None,
        ) {
            Err(e) => So::Failed(format!("edit failed during remove: {e}")),
            Ok(RemoveOutcome::NotFound) => {
                // Original already gone (concurrent edit?). Try to add
                // the new record anyway — it may be the operator's
                // intended state.
                submit_add(config_path, new_scope, new_spec)
            }
            Ok(RemoveOutcome::Removed { .. }) => {
                match add_inner(config_path, new_scope, new_spec, None) {
                    Ok(AddOutcome::Applied { .. }) | Ok(AddOutcome::NoOp) => So::Ok(format!(
                        "edited local DNS record '{}' (removed old, added new)",
                        new_spec.domain
                    )),
                    Err(e) => {
                        // Best-effort restore — re-add the original.
                        let restore = add_inner(config_path, old_scope, old_spec, None);
                        let restored = restore.is_ok();
                        let restore_note = if restored {
                            "; restored the original record"
                        } else {
                            "; FAILED to restore original — config may be missing the row"
                        };
                        So::Failed(format!("edit failed during add: {e}{restore_note}"))
                    }
                }
            }
        }
    }
}

/// Apply a form submit by dispatching the right IPC mutation for the
/// form's mode. On success the modal is closed and the active tab
/// is re-polled so the table reflects the new state immediately. On
/// validation or IPC failure the modal stays open with the error
/// message in `form.error_message`, and `submitting` is reset.
async fn submit_form(app: &mut App, mut form: DeviceFormState, poller: &IpcPoller) {
    // Parse the per-field user input into typed values up front so
    // syntax errors (bad IP, bad tag charset) surface as friendly
    // in-modal messages, not as a daemon error 5 seconds later.
    let parsed = match parse_form(&form) {
        Ok(p) => p,
        Err(msg) => {
            form.error_message = Some(msg);
            app.devices.modal = Some(DeviceModal::Form(form));
            return;
        }
    };

    form.submitting = true;
    form.error_message = None;

    let result = match form.mode {
        DeviceFormMode::Add => {
            let client = ClientConfig {
                name: parsed.name.clone(),
                ip: parsed.ip,
                mac: parsed.mac.clone(),
                mac_aliases: parsed.mac_aliases.clone(),
                profile: parsed.profile.clone(),
                // Singular by wire shape, not by choice — see the
                // len() > 1 refusal in `parse_form`. `first()` is safe
                // only because that gate ran.
                group: parsed.groups.first().cloned(),
                owner: parsed.owner.clone(),
                device_type: parsed.device_type.clone(),
                department: parsed.department.clone(),
                notes: parsed.notes.clone(),
            };
            poller.send_device_add(client).await
        }
        DeviceFormMode::Promote => {
            poller
                .send_device_promote(crate::tui::ipc_poller::PromoteFields {
                    ip: parsed.ip,
                    name: parsed.name.clone(),
                    profile: parsed.profile.clone(),
                    owner: parsed.owner.clone(),
                    device_type: parsed.device_type.clone(),
                    department: parsed.department.clone(),
                })
                .await
        }
        DeviceFormMode::Edit => {
            let patch = edit_patch_from(&parsed);
            // The IPC key for Update is the device's STABLE v1 id
            // CAPTURED AT MODAL-OPEN (`form.original_id`), NOT a
            // re-resolution from the live cursor. A 5s poll can reshuffle
            // the row set under the open modal, so re-deriving the target
            // here could patch a different device than the one the form
            // was opened on. Fall back to slug(parsed.name) only for a
            // form with no captured id (Add-converted-to-Edit edge; the
            // id-less case is already handled at capture time).
            let original_id = form.original_id.clone().unwrap_or_else(|| {
                crate::cli::commands::target::slug_id(&parsed.name).unwrap_or(parsed.name.clone())
            });
            poller.send_device_update(original_id, patch).await
        }
    };

    match result {
        Ok(_) => {
            app.clear_status();
            // Modal closes (form is owned, drops here), poll fresh.
            poll_active_leaf(app, poller).await;
        }
        Err(e) => {
            form.submitting = false;
            form.error_message = Some(e.to_string());
            app.devices.modal = Some(DeviceModal::Form(form));
        }
    }
}

/// Build the `Edit` mode patch from a parsed form.
///
/// Patches every editable field. The daemon's validator catches
/// duplicate name/IP/(owner, device); the partial semantics let the
/// operator clear nullable fields by emptying them in the form (empty
/// string → `Some(None)`).
///
/// `groups` carries the form's **whole** membership list. It used to
/// carry `vec![first]`, and since `DevicePatch.groups` is a full-list
/// replacement, a Save that only renamed the device deleted every extra
/// membership from the file. The list is passed through in
/// buffer order, so a Save the operator did not mean as a reorder never
/// emits one.
fn edit_patch_from(parsed: &ParsedForm) -> DevicePatch {
    DevicePatch {
        new_name: Some(parsed.name.clone()),
        ip: Some(parsed.ip),
        profile: Some(parsed.profile.clone()),
        mac: Some(parsed.mac.clone()),
        mac_aliases: Some(parsed.mac_aliases.clone()),
        owner: Some(parsed.owner.clone()),
        device_type: Some(parsed.device_type.clone()),
        department: Some(parsed.department.clone()),
        groups: Some(parsed.groups.clone()),
        notes: Some(parsed.notes.clone()),
        // Unconditionally `Some(...)`: the Edit form always holds the
        // field's whole intended value, so an empty buffer means "clear
        // it", never "leave it alone". The leave-alone arm of
        // `Option<Option<_>>` exists for the wire's other callers.
        network_name: Some(parsed.network_name.clone()),
        // Already `Option<bool>` on `DevicePatch` — it has no
        // clear state — so this passes straight through with no wrapper.
        network_name_wildcard: parsed.network_name_wildcard,
        // ALWAYS `None`, and it is not a placeholder. `retired_tags` is a
        // capture slot for a key only a legacy client sends; the daemon
        // WARNs when it arrives. This binary is not that client, so a
        // `Some(...)` here would make warden accuse itself of running an
        // outdated CLI.
        retired_tags: None,
    }
}

/// Parse an `Edit` form and build the `DevicePatch` its Save would send.
///
/// The seam the submit path itself goes through — `submit_form` calls
/// exactly these two steps for [`DeviceFormMode::Edit`] and then hands the
/// result to the IPC poller. Exposed so a test can drive the **real**
/// builder against the **real** daemon write path and then assert on the
/// resulting file, instead of re-deriving what the TUI "would" send.
///
/// Test-only, like `selected_device_row` above: the live path already
/// holds a parsed form at this point and must not parse it twice.
#[cfg(test)]
pub(crate) fn device_update_patch(form: &DeviceFormState) -> Result<DevicePatch, String> {
    Ok(edit_patch_from(&parse_form(form)?))
}

/// Parsed-and-typed form values, ready for IPC dispatch. Parsing
/// happens in one pass at submit time so all the syntax errors
/// surface together and the operator can fix them in one edit cycle.
#[derive(Debug)]
struct ParsedForm {
    name: String,
    ip: std::net::IpAddr,
    mac: Option<String>,
    /// Parsed from the comma-separated `Aliases` field. Each entry is
    /// a validated MAC (XX:XX:XX:XX:XX:XX) — daemon re-validates, but
    /// catching the format here gives the operator an in-modal error.
    mac_aliases: Vec<String>,
    profile: String,
    /// Group memberships, in the order the form buffer carried them
    /// (file order, then anything the operator appended in the picker).
    /// Empty means "no direct group membership".
    groups: Vec<String>,
    owner: Option<String>,
    device_type: Option<String>,
    department: Option<String>,
    notes: Option<String>,
    /// Bare network name, or `None` for "no resolvable name". On an Edit
    /// form `None` is an explicit clear, not a leave-alone — the form
    /// always carries the field's whole intended value.
    network_name: Option<String>,
    /// `None` only on an untouched Add / Promote form. An Edit form's
    /// buffer is seeded concrete and `parse_form` REFUSES it empty —
    /// `None` reaches the daemon as leave-alone, so accepting a deleted
    /// buffer here would turn "clear the wildcard" into a Save that
    /// reports success and changes nothing. Anything other than
    /// `true` / `false` is refused rather than coerced.
    network_name_wildcard: Option<bool>,
}

/// Split a comma-separated form buffer into trimmed, non-empty items,
/// **in buffer order**, dropping later duplicates.
///
/// Order-preserving on purpose: for `groups` the buffer order is the
/// file's order, and rewriting it would produce a diff in the operator's
/// config that no operator action asked for.
fn csv_items(buf: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for raw in buf.split(',') {
        let item = raw.trim();
        if item.is_empty() || out.iter().any(|existing| existing == item) {
            continue;
        }
        out.push(item.to_string());
    }
    out
}

fn parse_form(form: &DeviceFormState) -> Result<ParsedForm, String> {
    let name = form.name.trim();
    if name.is_empty() {
        return Err("name is required".into());
    }
    let ip_str = form.ip.trim();
    let ip: std::net::IpAddr = ip_str
        .parse()
        .map_err(|_| format!("ip \"{ip_str}\" is not a valid address"))?;
    let profile = form.profile.trim();
    if profile.is_empty() {
        return Err("profile is required".into());
    }

    let opt = |s: &str| {
        let t = s.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        }
    };

    // MAC aliases: comma-separated, shape-checked locally so typos
    // surface before the IPC round trip. Empty entries are skipped
    // (so trailing commas are forgiven), whitespace is trimmed, case
    // is preserved as-typed — the daemon validator uppercases before
    // dedup anyway.
    let mut mac_aliases: Vec<String> = Vec::new();
    for raw in form.mac_aliases.split(',') {
        let r = raw.trim();
        if r.is_empty() {
            continue;
        }
        if !is_macish(r) {
            return Err(format!(
                "mac alias \"{r}\" doesn't look like a MAC — expected XX:XX:XX:XX:XX:XX"
            ));
        }
        mac_aliases.push(r.to_string());
    }

    // Groups: comma-separated, same shape as `tags` above. Order is the
    // buffer's order, which is the file's order plus whatever the
    // operator appended in the picker — preserved rather than
    // normalised, so a Save that touched nothing else produces no diff
    // here. There is no CSV refusal any more: the buffer is written by
    // the picker, never typed, and a refusal would now reject the very
    // state the picker produces.
    let groups = csv_items(&form.groups);

    // The Add / Promote wire is singular (`ClientConfig.group:
    // Option<String>`), so a form in those modes must never carry more
    // than one id. The picker enforces this at the other end by refusing
    // to open multi-select off an Edit form; this is the second gate, on
    // the write side, because a silent truncation here would be exactly
    // the defect already fixed once, re-opened in another mode.
    if form.mode != DeviceFormMode::Edit && groups.len() > 1 {
        return Err("a new device takes one group; save it, then edit it to add the others".into());
    }

    // Same shape as the group refusal above, and for the same reason: the
    // Add wire is `ClientConfig` and the Promote wire is `PromoteFields`,
    // and neither carries a network name. Without this the operator types
    // one on an Add form, Save succeeds, and the name is silently gone —
    // the failure mode is indistinguishable from success.
    //
    // Gated on the BUFFERS, not on the parsed values: an untouched Add form
    // holds `String::new()` for both and must pass in silence.
    if form.mode != DeviceFormMode::Edit
        && !(form.network_name.trim().is_empty() && form.network_name_wildcard.trim().is_empty())
    {
        return Err("a network name is set on an existing device; save it, then edit it".into());
    }

    let network_name = opt(&form.network_name);
    let wildcard_token = form.network_name_wildcard.trim().to_ascii_lowercase();
    let network_name_wildcard = match wildcard_token.as_str() {
        // On Add / Promote an empty buffer is the untouched form the guard
        // above just cleared, and `None` is the honest answer.
        //
        // On Edit it is the operator having DELETED a buffer that
        // `edit_form_from` seeded concrete — the field is free-text, so
        // Backspace reaches it. `None` would travel to the daemon as
        // leave-alone: a Save that reports success and changes nothing.
        // Refuse, so the two fields agree about what empty means (an
        // emptied Network Name clears it; an emptied wildcard would
        // otherwise silently keep it).
        "" if form.mode != DeviceFormMode::Edit => None,
        "" => {
            return Err(
                "network_name_wildcard: expected true/false, the field cannot be left empty".into(),
            )
        }
        "true" => Some(true),
        "false" => Some(false),
        _ => {
            let typed = form.network_name_wildcard.trim();
            return Err(format!(
                "network_name_wildcard: expected true/false, got \"{typed}\""
            ));
        }
    };

    Ok(ParsedForm {
        name: name.to_string(),
        ip,
        mac: opt(&form.mac),
        mac_aliases,
        profile: profile.to_string(),
        groups,
        owner: opt(&form.owner),
        device_type: opt(&form.device_type),
        department: opt(&form.department),
        notes: opt(&form.notes),
        network_name,
        network_name_wildcard,
    })
}

/// Rough MAC shape check: 6 colon-separated 2-char hex groups.
/// The daemon re-validates with the canonical `is_valid_mac`; this
/// just keeps obvious typos out of the IPC payload.
fn is_macish(s: &str) -> bool {
    let parts: Vec<&str> = s.split(':').collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

// ── Modal pre-fill helpers ───────────────────────────────────────────

/// Resolve the currently-highlighted device row in the unified list.
/// Test-only — the live keybinding handler resolves the row inline via
/// `selected_row` to keep the production path branchless; the
/// test-facing wrappers (`build_edit_form` / `build_promote_form` /
/// `focused_mapped_name`) share this single selection pipeline.
#[cfg(test)]
fn selected_device_row(app: &App) -> Option<tabs::devices::DeviceRow> {
    let view = app.device_view.as_ref()?;
    // Same reason as `handle_devices_key`: the selection must resolve
    // against the VISIBLE rows, not the full list.
    let rows = tabs::devices::build_filtered_rows(
        view,
        app.devices.group_by,
        app.devices.filter_subnet.as_deref(),
    )
    .0;
    // Resolve by the operator's stable key first so the focused
    // row tracks the device across poll reshuffles; fall back to the
    // positional cursor before the key is seeded.
    let idx = crate::tui::app::resolve_row_index(
        &rows,
        app.devices.selected_id.as_ref(),
        tabs::devices::row_key,
    )
    .or_else(|| tabs::devices::current_selection(&app.devices.table_state, &rows))?;
    rows.get(idx).cloned()
}

/// Build an Edit form pre-filled from the focused mapped row in the
/// unified list. Returns `None` when no row is selected, the view
/// hasn't loaded yet, or the focused row is unmapped. Test-only —
/// the keybinding handler dispatches inline via `selected_row` to
/// keep the live path branchless on the row variant.
#[cfg(test)]
fn build_edit_form(app: &App) -> Option<DeviceFormState> {
    match selected_device_row(app)? {
        tabs::devices::DeviceRow::Mapped(m) => Some(edit_form_from(&m)),
        _ => None,
    }
}

/// Build a Promote form from the focused unmapped row. Test-only;
/// the live keybinding path goes through `selected_row` directly.
#[cfg(test)]
fn build_promote_form(app: &App) -> Result<DeviceFormState, String> {
    match selected_device_row(app) {
        Some(tabs::devices::DeviceRow::Unmapped(u)) => promote_form_from(&u),
        Some(_) => Err("focused row is not an unmapped device".to_string()),
        None => Err("no unmapped row selected — ↑/↓ to pick one first".to_string()),
    }
}

/// Friendly display name of the focused mapped row. Test-only —
/// the production path captures the device id at modal-open
/// (`DeviceFormState::original_id`) for IPC keys and reads the
/// display name straight off the DTO when needed.
#[cfg(test)]
fn focused_mapped_name(app: &App) -> Option<String> {
    match selected_device_row(app)? {
        tabs::devices::DeviceRow::Mapped(m) => Some(m.name),
        _ => None,
    }
}

/// Build an Edit form pre-filled from a mapped device. Tags are joined
/// with commas to match the on-screen format the user sees.
///
/// Groups: joined the same way, ALL of them, in the DTO's order — which
/// is the file's order (`DeviceIndex.groups` is `dev.groups.clone()`,
/// never sorted). Seeding from `groups[0]` was a real defect: the
/// form could only hold one, so the Save that replaced the whole array
/// dropped the rest.
/// Configured profile + group id snapshots for the device-form pickers,
/// read from `app.loaded_config`. Empty vecs when no config is loaded.
/// Profile ids come out sorted (BTreeMap key order); group ids in config
/// order.
/// The `[[labels]]` vocabulary for the three metadata fields,
/// as **display names**, sorted, one list per kind.
///
/// Display names and not ids because `Device.{owner,device_type,department}`
/// are free text while `Label.id` is an `Id` — the two sets never intersect.
/// `Label::matches_value` accepts either, so
/// the display name is the one that both reads well in the Devices table and
/// silences the unknown-value WARN.
fn device_form_label_vocab(app: &App) -> (Vec<String>, Vec<String>, Vec<String>) {
    let Some(loaded) = app.loaded_config.as_ref() else {
        return (Vec::new(), Vec::new(), Vec::new());
    };
    let pick = |want: crate::config::schema::LabelKind| -> Vec<String> {
        let mut v: Vec<String> = loaded
            .config
            .labels
            .iter()
            .filter(|l| l.kind == want)
            .map(|l| l.display_name.clone())
            .collect();
        v.sort();
        v.dedup();
        v
    };
    use crate::config::schema::LabelKind;
    (
        pick(LabelKind::Owner),
        pick(LabelKind::DeviceType),
        pick(LabelKind::Department),
    )
}

fn device_form_option_lists(app: &App) -> (Vec<String>, Vec<String>) {
    match app.loaded_config.as_ref() {
        Some(loaded) => {
            let profiles = loaded.config.profiles.keys().cloned().collect();
            let groups = loaded
                .config
                .groups
                .iter()
                .map(|g| g.id.as_str().to_owned())
                .collect();
            (profiles, groups)
        }
        None => (Vec::new(), Vec::new()),
    }
}

/// True for the device-form fields chosen from a popup picker rather than
/// typed (Profile / Group). Selection-only fields ignore Char / Backspace
/// and open the picker on Enter.
fn is_select_only_field(form: &DeviceFormState, field: DeviceFormField) -> bool {
    match field {
        // Always picker-driven: their option lists come from entities that
        // must already exist for the value to be legal.
        DeviceFormField::Profile | DeviceFormField::Group => true,
        // The three metadata fields are picker-driven **only when
        // a vocabulary exists for that kind**.
        //
        // This condition is load-bearing, not a nicety. `field_accepts_typing`
        // is the negation of this predicate, so marking them select-only
        // unconditionally makes Char and Backspace no-ops — and
        // `open_field_picker` also no-ops on an empty list, to avoid trapping
        // the operator in an empty popup. The two guards together would leave
        // the field with **no way to enter a value at all**, on every config
        // that has not declared labels yet, which today is all of them.
        DeviceFormField::Owner => !form.owners_snapshot.is_empty(),
        DeviceFormField::Device => !form.device_types_snapshot.is_empty(),
        DeviceFormField::Department => !form.departments_snapshot.is_empty(),
        _ => false,
    }
}

/// Whether the focused field accepts typed characters (Backspace / Char).
/// False for select-only fields (Profile / Group) and for a Promote form's
/// ARP-locked IP.
fn field_accepts_typing(form: &DeviceFormState, field: DeviceFormField) -> bool {
    !(is_select_only_field(form, field) || (form.ip_locked && field == DeviceFormField::Ip))
}

/// Open the popup picker for the focused select-only field, seeding the
/// cursor on the current value. No-op when the option snapshot is empty so
/// the operator can't get trapped in an empty popup.
/// Prepend the clear option to a metadata vocabulary. Returns the
/// list unchanged when empty — an empty vocabulary means the field is not
/// picker-driven at all, and offering a popup with only "clear" in it would
/// be a worse affordance than plain typing.
fn with_clear_option(vocab: &[String]) -> Vec<String> {
    if vocab.is_empty() {
        return Vec::new();
    }
    let mut v = Vec::with_capacity(vocab.len() + 1);
    v.push(String::new());
    v.extend(vocab.iter().cloned());
    v
}

fn open_field_picker(form: &mut DeviceFormState) {
    // Buttons have no picker; only a focused field can open one.
    let Some(target) = form.focused.field() else {
        return;
    };
    // A locked row cannot be written, and the picker writes. `focus_ring`
    // already keeps focus off it, so this is the second gate rather than
    // the first — but the two guards answer different questions ("can the
    // operator get here" vs "may this write"), and the picker is the one
    // that touches the buffer.
    if form.is_locked(target) {
        return;
    }
    let (options, current, multi, selected) = match target {
        DeviceFormField::Profile => (
            form.profiles_snapshot.clone(),
            form.profile.clone(),
            false,
            Vec::new(),
        ),
        DeviceFormField::Group => {
            let selected = csv_items(&form.groups);
            // Options are the configured groups in config order, plus any
            // membership the config does not declare — a group deleted
            // out from under the device, or a snapshot taken before a
            // reload. Appending them keeps a stale reference **visible
            // and removable** instead of invisible-but-preserved: the
            // submit would carry it either way, so hiding it would mean
            // the operator cannot see what they are about to re-save.
            let mut options = form.groups_snapshot.clone();
            for id in &selected {
                if !options.iter().any(|o| o == id) {
                    options.push(id.clone());
                }
            }
            (
                options,
                selected.first().cloned().unwrap_or_default(),
                // Multi-select on Edit only — the Add / Promote wire
                // carries one id (see the `parse_form` refusal).
                form.mode == DeviceFormMode::Edit,
                selected,
            )
        }
        // The three metadata fields are optional, so their picker
        // leads with an explicit clear. Without it a value set once could
        // never be removed from the TUI — the field is select-only while a
        // vocabulary exists, so Backspace is a no-op, and every other option
        // writes a value. The empty string IS the cleared state
        // (`Option<String>` → `None` at save), so no sentinel is needed.
        DeviceFormField::Owner => (
            with_clear_option(&form.owners_snapshot),
            form.owner.clone(),
            false,
            Vec::new(),
        ),
        DeviceFormField::Device => (
            with_clear_option(&form.device_types_snapshot),
            form.device_type.clone(),
            false,
            Vec::new(),
        ),
        DeviceFormField::Department => (
            with_clear_option(&form.departments_snapshot),
            form.department.clone(),
            false,
            Vec::new(),
        ),
        _ => return,
    };
    if options.is_empty() {
        return;
    }
    let cursor = options.iter().position(|o| *o == current).unwrap_or(0);
    form.picker = Some(FieldPicker {
        target,
        options,
        cursor,
        multi,
        selected,
    });
}

/// Drive the open device-form popup picker. `↑`/`↓` move the cursor
/// (wrapping); Enter writes the chosen value into the target field and
/// closes the picker; Esc closes it without change.
///
/// In `multi` mode (the Group picker on an Edit form) Space toggles the
/// row under the cursor and Enter commits the whole selection. A toggle
/// **appends**, so the memberships the file already carried keep their
/// positions and a Save that added one group emits a one-element diff
/// rather than a reordered array. Group membership resolves by priority, so the
/// order is semantically inert — which is exactly why churning it would
/// be pure noise in the operator's config.
fn handle_form_picker_key(form: &mut DeviceFormState, code: KeyCode) {
    let Some(picker) = form.picker.as_mut() else {
        return;
    };
    let n = picker.options.len();
    match code {
        KeyCode::Down if n > 0 => {
            picker.cursor = (picker.cursor + 1) % n;
        }
        KeyCode::Up if n > 0 => {
            picker.cursor = (picker.cursor + n - 1) % n;
        }
        KeyCode::Char(' ') if picker.multi => {
            let Some(opt) = picker.options.get(picker.cursor).cloned() else {
                return;
            };
            match picker.selected.iter().position(|s| *s == opt) {
                Some(i) => {
                    picker.selected.remove(i);
                }
                None => picker.selected.push(opt),
            }
        }
        KeyCode::Enter if picker.multi => {
            let value = picker.selected.join(",");
            let target = picker.target;
            form.picker = None;
            *form.field_buf(target) = value;
            form.error_message = None;
        }
        KeyCode::Enter => {
            let choice = picker.options.get(picker.cursor).cloned();
            let target = picker.target;
            form.picker = None;
            if let Some(choice) = choice {
                *form.field_buf(target) = choice;
                form.error_message = None;
            }
        }
        KeyCode::Esc => {
            form.picker = None;
        }
        _ => {}
    }
}

pub(crate) fn edit_form_from(row: &crate::ipc::protocol::MappedDeviceDto) -> DeviceFormState {
    // Capture the stable IPC id NOW, at modal-open, from the DTO
    // in hand. The submit uses it verbatim so a poll that reshuffles the
    // row set under the open modal can't redirect the patch onto another
    // device. Fall back to the slug of the ORIGINAL name (not the
    // post-edit name) for an id-less DTO.
    let original_id = row
        .id
        .clone()
        .filter(|s| !s.is_empty())
        .or_else(|| crate::cli::commands::target::slug_id(&row.name).ok())
        .unwrap_or_else(|| row.name.clone());
    DeviceFormState::new_edit(
        row.name.clone(),
        row.ip.clone(),
        row.mac.clone().unwrap_or_default(),
        row.mac_aliases.join(","),
        row.profile.clone(),
        row.groups.join(","),
        row.owner.clone().unwrap_or_default(),
        row.device_type.clone().unwrap_or_default(),
        row.department.clone().unwrap_or_default(),
        row.notes.clone().unwrap_or_default(),
        row.network_name.clone().unwrap_or_default(),
        // Always concrete, never empty — the Edit submit sends whatever
        // this shows, so a blank here would read as "leave alone" on a
        // field the operator can see a definite state for.
        row.network_name_wildcard.to_string(),
    )
    .with_original_id(Some(original_id))
}

/// Build a Promote form from an unmapped device. Returns an error
/// string when the row's MAC is empty (stale ARP) — IP-only
/// identification is bypassable per CLAUDE.md, so promotion requires
/// a MAC pin so DHCP can't move the IP to a different device.
fn promote_form_from(
    row: &crate::ipc::protocol::UnmappedDeviceDto,
) -> Result<DeviceFormState, String> {
    let mac = row.mac.clone().filter(|m| !m.is_empty()).ok_or_else(|| {
        format!(
            "no MAC for {} in ARP yet. Try `ping {}` from this host to refresh ARP, \
             then press Enter again. Promotion requires a MAC pin so DHCP can't \
             move the IP to a different device behind the operator's back.",
            row.ip, row.ip
        )
    })?;
    Ok(DeviceFormState::new_promote(row.ip.clone(), mac))
}

/// Install a panic hook that restores the terminal (cooked mode +
/// leave alternate screen + show cursor) before chaining to the
/// previous hook (typically the default that prints the panic
/// message to stderr). Order matters: the terminal must be restored
/// FIRST so the panic message lands on a sane terminal instead of
/// being mangled by raw-mode escape sequences.
///
/// `Once`-guarded for idempotency: repeated `run()` calls within the
/// same process do not stack hooks (each `take_hook` + `set_hook`
/// pair would otherwise grow the chain by one).
///
/// Direct unit-testing of this function is impractical because the
/// hook it installs is process-global — it would persist for every
/// subsequent panic in the test binary. The chain-and-cleanup pattern
/// it embodies is pinned by `panic_hook_tests::panic_hook_runs_cleanup_then_chains_previous`.
///
/// Still required alongside [`TerminalGuard`]: under the release profile's
/// `panic = "abort"` a panic does not unwind, so no `Drop` runs — this hook is
/// the whole of the panic-path restore in the shipped binary. See
/// [`restore_terminal`].
fn install_terminal_restore_panic_hook() {
    static INSTALLED: Once = Once::new();
    INSTALLED.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore_terminal();
            previous(info);
        }));
    });
}

#[cfg(test)]
#[path = "tests/cfg_scan.rs"]
mod cfg_scan;

#[cfg(test)]
#[path = "tests/modal_keybinding_tests.rs"]
mod modal_keybinding_tests;

// ── Settings 'e' editor failure formatting tests ────────────────

#[cfg(all(test, unix))]
#[path = "tests/editor_failure_tests.rs"]
mod editor_failure_tests;

// ── Tracking panel tests ─────────────────────────────────────────

#[cfg(test)]
#[path = "tests/tracking_panel_tests.rs"]
mod tracking_panel_tests;

// ── Dispatch-level key-routing harness ───────────────────────────
//
// Every other tab test calls `handle_<tab>_key` DIRECTLY, so it never
// exercises the global modal gates + global key match that run first in
// `handle_key`. That is exactly the layer where global-hotkey shadowing
// lives — the Settings Tracking-form gate, the Local DNS modal gate,
// and Devices `p` before them all shadowed a per-tab binding at one
// point. These tests drive `handle_key` END-TO-END so the next global hotkey
// that shadows a tab contract trips here instead of shipping silently.
#[cfg(test)]
#[path = "tests/dispatch_routing_tests.rs"]
mod dispatch_routing_tests;

// ── No synchronous filesystem work on the loop ────────────────────

#[cfg(test)]
#[path = "tests/event_loop_offload_tests.rs"]
mod event_loop_offload_tests;

// ── RAII terminal restore on every return path ────────────────────

#[cfg(test)]
#[path = "tests/terminal_guard_tests.rs"]
mod terminal_guard_tests;

// ── Panic hook chain-and-cleanup pattern ──────────────────────────

#[cfg(test)]
#[path = "tests/panic_hook_tests.rs"]
mod panic_hook_tests;

// ── Numeric remap + g<letter> mnemonic dispatch ───────────────────

#[cfg(test)]
#[path = "tests/hotkey_t3_tests.rs"]
mod hotkey_t3_tests;

/// The global `g` mnemonic prefix swallows
/// every lowercase `g` BEFORE per-tab dispatch. That made two existing
/// per-tab handlers unreachable: `KeyCode::Char('g')` on Devices
/// (group-by cycle) and `KeyCode::Char('g')` on Query Log (jump-to-top).
/// The dead Query Log handler was removed outright (cursor
/// jump-to-top is now uncovered — operator scrolls with `Up`) and
/// the Devices group-by binding remapped from `g` to `G`. These tests
/// pin the contract end-to-end so a future revert can't silently
/// re-break it.
#[cfg(test)]
#[path = "tests/mini_patch_devices_groupby_tests.rs"]
mod mini_patch_devices_groupby_tests;

// ── Enter rewire on Query Log + a/d retired ──────────────────────────
//
// These tests pin the Enter-driven entry surface and the absence of the
// legacy `a` / `d` keybindings. Status mapping is owned by
// `query_log_rule_modal::inferred_action` (covered by its own unit tests
// in `query_log_rule_modal.rs`) — these tests cover the wiring: that
// pressing Enter on a Query Log row goes through
// `build_query_log_rule_modal` and lands the right `Action` on the modal,
// that non-actionable statuses surface a footer message instead of
// opening the modal, and that `a` / `d` are inert on the Query Log tab.
//
// IPC poller policy mirrors `hotkey_t3_tests`: the dummy poller points
// at a nonexistent socket; the tab-change poll fires on first dispatch
// to QueryLog and lands an error in `app.last_error`. We park the leaf
// on QueryLog BEFORE the call we care about so no tab-change poll runs
// for that keypress, leaving `last_error` clean for the neutral-row
// assertion.
#[cfg(test)]
#[path = "tests/s47_t2_tests.rs"]
mod s47_t2_tests;

// ── List edit modal save / delete pipeline tests ──────────────────

#[cfg(test)]
#[path = "tests/s53_tests.rs"]
mod s53_tests;

#[cfg(test)]
#[path = "tests/stale_data_indicator_tests.rs"]
mod stale_data_indicator_tests;

// ── Settings backup confirm modal dispatch tests ─────────────────────
//
// Covers `b` on Settings → BackupModal::Confirm → y/n/Esc transitions.
// Self-contained: own helpers (master + poller) so this module doesn't
// depend on the helpers in s47/s53 test modules above.
#[cfg(test)]
#[path = "tests/backup_modal_tests.rs"]
mod backup_modal_tests;

/// The operator's table selection must survive a data refresh.
///
/// Lists and Rules keyed their cursor on a bare positional index that was
/// clamped only on a *filter keypress*. Both row sets also change on a
/// **data refresh** that involves no keypress at all — Lists on a 30 s IPC
/// poll, Rules on any `loaded_config` reload (including the Rules tab's own
/// delete). That left two distinct defects, and a clamp only closes the
/// first:
///
///   1. the cursor dangles past the end → `Enter`/`d` are silent no-ops on
///      a row the operator can still see highlighted;
///   2. an entity vanishing from *above* the cursor keeps the index in
///      range but slides a **different** entity under it → `Enter` edits,
///      and `d` deletes, the wrong one.
///
/// Both tabs now anchor on a stable id and re-resolve it to an index, the
/// way Subnets/Profiles/Cluster/Devices/Query-Log already do.
#[cfg(test)]
#[path = "tests/rev2607_cursor_refresh_tests.rs"]
mod rev2607_cursor_refresh_tests;

/// Regression cover for the Lists edit/add modal's **save payload**.
///
/// `build_blocklist_value` hand-rolls the TOML row the modal writes, and
/// for every enum field it hand-rolled the wire string too. When the schema
/// renamed `BlocklistBase::Block` to `Deny` — and
/// with it the wire token `"block"` → `"deny"`, deliberately without a
/// serde alias — the modal's copy of that map was missed. Every save
/// of a `base = deny` list (i.e. nearly every list) therefore wrote
/// `kind = "block"`, which the loader refused with `unknown variant`, so
/// the modal could never write anything.
///
/// The map is gone: the wire token now comes from the enums themselves
/// ([`crate::config::schema::BlocklistBase::wire_str`] and siblings). These
/// tests are the fence that keeps it gone — they drive the real payload
/// builder over **every** variant of all three enums and prove the bytes
/// deserialise back to the variant they came from, so a future rename
/// cannot silently re-open the hole.
#[cfg(test)]
#[path = "tests/lists_save_payload_wire_format_tests.rs"]
mod lists_save_payload_wire_format_tests;

// ── One navigation grammar for every modal form ───────────────────────
//
// Up/Down move focus, Left/Right cycle the focused field's value, in
// EVERY form modal. Before this, four handlers did that and three
// inverted it (arrows changed the value, only Tab moved focus).
//
// These tests drive real `KeyCode`s through the production handlers
// rather than reading the match arms, because the match arms are exactly
// what a refactor rewrites. Each focus test asserts Down moves *and* Up
// comes back — a handler that swallowed both keys, or that moved forward
// on both, fails it.
#[cfg(test)]
#[path = "tests/nav_grammar_tests.rs"]
mod nav_grammar_tests;

/// End-to-end cover for the Local DNS typed-phrase confirm: keys go
/// through the **real** key handler and the assertion is made on the
/// **rendered buffer**.
///
/// Both halves are deliberate. The precedent for this fix — the
/// scope modal — put every test next to the modal's own state, leaving the
/// one-line `mod.rs` wiring uncovered — so the arm could be reverted to
/// its silent form and the suite would stay green. And a refusal that
/// only reaches `RemoveConfirm::error` is exactly the defect: the whole
/// complaint is that state never reaches the screen.
#[cfg(test)]
#[path = "tests/local_dns_typed_confirm_tests.rs"]
mod local_dns_typed_confirm_tests;

// `mod tags_verb_status_tests` is gone along with the Tags tab.
//
// It pinned that the Rename and Delete verbs did not report success on a
// failure — `run_rename` / `run_delete` returned `Ok(())` for a refusal,
// and the TUI rendered the operator's REQUEST rather than the outcome.
// **The technique is worth keeping even though the tests are not:** each
// asserted `modal.is_none()` FIRST, because both verbs start at
// `load_config` and an unloadable fixture takes the `Err` arm, which
// leaves the modal open and never touches the status line — so a bare
// "the status does not claim a deletion" passes on a build with no fix in
// it. Assert the state only reachable through the success arm, then assert
// what it said.

// ── The tag valve loss tests, RETIRED ───────────────────────────────
//
// `mod armed_tag_valve_loss_tests` stood here: five tests over the Lists
// edit modal's attach-only tag valve. The valve armed on the first
// `Enter` and attached on the second; between the two, `Ctrl+S` saved and
// closed, dropping the slug — correctly, because attaching there would
// have made the save itself the second `Enter` — and the tests pinned
// that the drop was ANNOUNCED rather than silent.
//
// **They were unusually well built, which is why they are named rather
// than just deleted.** The core one asserted on PAINTED CELLS, not on
// `app.status_text()`: a string assertion passes with the clause appended
// to the tail, where `toast::truncate_to` cuts it at 33 columns on the
// declared 80x24 floor. The in-house precedent for that mistake is the
// `ui.rs` test that asserts the footer *contains* the chord string — i.e.
// that the chord is advertised, not that it works — which stayed green
// through a `Ctrl+S` that was broken in the Devices form.
//
// All five drove the tag picker and the `dropped_tag_leads` notice, both
// of which are now gone; there is no slug to drop and no notice to
// paint. The retired tests:
//
//   `ctrl_s_with_the_valve_armed_names_the_slug_it_dropped`
//   `the_notice_rides_the_error_arms_too_not_just_the_success_arm`
//   `the_promote_warning_outranks_the_dropped_tag_notice`
//   `a_save_with_no_armed_slug_says_nothing_about_tags`
//   `a_confirmed_slug_attaches_and_is_not_reported_as_dropped`
//
// **That `Ctrl+S` reaches the submit path at all — is a separate
// guarantee and is NOT retired.** It keeps its own coverage: the Lists
// modal's chord is exercised by the consent-stage tests above, and the
// Subnets / Groups / Profiles twins are asserted in
// `armed_tag_valve_other_modals_tests` below, retargeted onto surviving
// fields.
//
// The painted-cells lesson above outlives the tests: any future assertion
// about toast content must read the buffer, not the status string.

// ── The same valve, the other three modals that carry it ─────────────
//
// **The trip-wire fired, and this is the far side of it.**
//
// What stood here — kept, because it is the record and not merely an
// outdated paragraph — was a measurement: `tags_pending_new` also lives
// on the Subnet, Group and Profile forms, but **none of the three bound
// `Ctrl+S`**; their legends advertised "Enter save"; and every
// focus-moving arm cleared the valve on the way out of Tags. So every
// route to a save disarmed it first, and wiring the notice into their
// submit paths would have been a branch no key could reach — coverage in
// appearance only.
//
// What was built instead was a trip-wire, on the stated expectation that
// "the keying-preserved contract and the Devices form both invite someone
// to wire `Ctrl+S` here
// next. The day they do, these go red at the exact line that would
// reintroduce the silent loss, and whoever wired it has to carry the
// notice across."
//
// That day came: `Ctrl+s` saves from anywhere on **every**
// Archetype-F form. The chord is bound on all five form modals, so the
// three tests below were **inverted, not deleted** — the property they
// defend is unchanged, only its precondition moved. Each now asserts the
// chord DOES save AND that the dropped slug is announced. An inverted
// test that checked only "the modal closed" would pass against a save
// that silently ate the slug, which is the exact defect the originals
// guarded.
//
// `submit_{subnet,group,profile}_modal` capture `tags_pending_new` before
// the form is consumed and lead the status line with
// `format_dropped_pending_tag` via `dropped_tag_leads`.
//
// Two asymmetries worth knowing, both deliberate:
//
//  - `label_modal` and `local_dns_modal` also gained the chord but carry
//    **no** `tags_pending_new` at all (grep: zero sites), so there is no
//    valve to lose and no trip-wire to write for them. Not an omission.
//  - Subnets and Groups KEEP the form open on a failed submit, so the
//    slug survives and no drop is announced; Profiles finishes either
//    way and announces on both arms. The notice sits past their
//    early-return for exactly that reason — the existing control flow
//    already encodes "was the form destroyed?".
//
// Also settled by that change: `Ctrl+S` used to fall through to the
// `KeyCode::Char(c)` arm and append a literal `s` to the tag buffer.
#[cfg(test)]
#[path = "tests/armed_tag_valve_other_modals_tests.rs"]
mod armed_tag_valve_other_modals_tests;

// ── Paste reach and one confirm convention ────────────────────────────
//
// Self-contained (own master + poller + key helpers) so it does not
// depend on the helper sets in the test modules above.
//
// **Every test drives `handle_key`, never `handle_group_modal_key`.**
// A test that calls the leaf/modal handler directly passes on a
// dispatcher that never routes the key to it, and the Groups modal sits
// behind two hops: the modal gate ahead of the leaf match, then the
// leaf match itself.
#[cfg(test)]
#[path = "tests/confirm_and_paste_tests.rs"]
mod confirm_and_paste_tests;

/// Clamp / `Home` / `End` / `PgUp` / `PgDn`, and Enter as the
/// focused row's primary action, on the leaves this module owns.
///
/// Devices and Lists single-step clamping is NOT here: it lives in
/// `tabs::{devices,lists}::next_selectable_index`, owned separately. What
/// IS here for those two is the
/// jump / page path, built on `is_selectable` precisely so
/// it does not inherit the wrap those helpers still have.
#[cfg(test)]
#[path = "tests/n4_n5_nav_tests.rs"]
mod n4_n5_nav_tests;

/// The `?` overlay is executable.
///
/// Driven through the full `handle_key` dispatcher (not a leaf handler)
/// because that IS the property: the overlay must reach the same match a
/// Normal-mode keystroke reaches. A leaf-handler test would pass against a
/// parallel dispatch table, which is exactly what this forbids.
#[cfg(test)]
#[path = "tests/n8_executable_help_tests.rs"]
mod n8_executable_help_tests;

/// Tags `/` onto `InputMode`, and the Ctrl+S keying on the two form
/// modals that carry no tag valve.
///
/// The three that DO carry one are covered by
/// `armed_tag_valve_other_modals_tests`, which had to be inverted for
/// that change; these two have no valve to lose (`label_modal` and
/// `local_dns_modal` have zero `tags_pending_new` sites), so they need a
/// plain "the chord saves" pin rather than a trip-wire.
#[cfg(test)]
#[path = "tests/n9_n14_key_tests.rs"]
mod n9_n14_key_tests;

/// Local DNS is one list.
///
/// Driven through `handle_key`, never `handle_local_dns_key`: the modal
/// gate sits ahead of the leaf match, and the reachability claims here
/// are about the dispatcher as much as about the leaf.
#[cfg(test)]
#[path = "tests/n6_local_dns_one_list_tests.rs"]
mod n6_local_dns_one_list_tests;

#[cfg(test)]
#[path = "tests/logs_tab_key_tests.rs"]
mod logs_tab_key_tests;

#[cfg(test)]
#[path = "tests/file_editor_reload_tests.rs"]
mod file_editor_reload_tests;
