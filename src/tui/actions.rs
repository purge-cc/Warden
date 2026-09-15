//! A single admitted mutation; workers return effects, never a copied App.
use std::future::Future;
use std::path::PathBuf;

use super::{app, App};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Surface {
    Global,
    Device,
    Profile,
    Subnet,
    Group,
    Label,
    LocalDns,
    Catalog,
    ListEdit,
    RuleEdit,
    RuleAdd,
    Tracking,
    Restore,
    Backup,
    #[cfg(feature = "cluster")]
    Nodes,
}

pub(crate) struct PendingAction {
    pub id: u64,
    pub surface: Surface,
    pub label: String,
    pub detached: bool,
    pub written: Option<String>,
}

type ApplyAction = Box<dyn FnOnce(&mut App, bool) + Send>;

pub struct ActionCompletion {
    id: u64,
    apply: Result<ApplyAction, String>,
}

pub struct ActionProgress {
    id: u64,
    summary: String,
}

pub(super) fn progress(app: &mut App, result: ActionProgress) {
    if let Some(pending) = app.pending_action.as_mut().filter(|p| p.id == result.id) {
        pending.written = Some(result.summary);
    }
}

/// Existing backup/restore result variants keep their public test seam. Their
/// single worker holds this slot until its result is consumed by the UI loop.
pub(super) fn reserve_external(app: &mut App, surface: Surface, label: &str) -> bool {
    if app.pending_action.is_some() {
        return false;
    }
    app.action_serial += 1;
    app.pending_action = Some(PendingAction {
        id: app.action_serial,
        surface,
        label: label.into(),
        detached: false,
        written: None,
    });
    super::reads::invalidate_all(app);
    true
}

pub(super) fn finish_external(app: &mut App, surface: Surface) {
    if app
        .pending_action
        .as_ref()
        .is_some_and(|pending| pending.surface == surface)
    {
        app.pending_action = None;
        super::reads::invalidate_all(app);
        app.force_poll = true;
    }
}

pub(super) fn start<R, F, A>(
    app: &mut App,
    surface: Surface,
    label: &str,
    work: F,
    apply: A,
) -> bool
where
    R: Send + 'static,
    F: Future<Output = R> + Send + 'static,
    A: FnOnce(&mut App, bool, R) + Send + 'static,
{
    if app.pending_action.is_some() {
        return false;
    }
    let Some(tx) = app.job_tx.clone() else {
        return false;
    };
    app.action_serial += 1;
    let id = app.action_serial;
    app.pending_action = Some(PendingAction {
        id,
        surface,
        label: label.into(),
        detached: false,
        written: None,
    });
    super::reads::invalidate_all(app);
    let worker = tokio::spawn(work);
    tokio::spawn(async move {
        let apply: Result<ApplyAction, String> = match worker.await {
            Ok(result) => Ok(Box::new(move |app, attached| apply(app, attached, result))),
            Err(error) => Err(format!(
                "operation interrupted; outcome may be incomplete: {error}"
            )),
        };
        let _ = tx.send(app::UiJob::ActionFinished(ActionCompletion { id, apply }));
    });
    true
}

pub(super) fn apply(app: &mut App, result: ActionCompletion) {
    if app
        .pending_action
        .as_ref()
        .is_none_or(|pending| pending.id != result.id)
    {
        return;
    }
    let pending = app.pending_action.take().unwrap();
    reset_submitting(app);
    super::reads::invalidate_all(app);
    match result.apply {
        Ok(apply) => apply(app, !pending.detached),
        Err(error) => app.status_err(match pending.written {
            Some(written) => format!("{written}; {error}"),
            None => error,
        }),
    }
    app.force_poll = true;
    super::reads::request_heartbeat(app, super::jobs::ReadReason::Explicit);
}

/// Tests without a job channel execute the identical work and application.
/// Production always has a sender and never awaits the operation here.
pub(super) async fn dispatch<R, F, A>(
    app: &mut App,
    surface: Surface,
    label: &str,
    work: F,
    apply: A,
) -> bool
where
    R: Send + 'static,
    F: Future<Output = R> + Send + 'static,
    A: FnOnce(&mut App, bool, R) + Send + 'static,
{
    if app.pending_action.is_some() {
        return false;
    }
    if app.job_tx.is_some() {
        start(app, surface, label, work, apply)
    } else {
        let result = work.await;
        reset_submitting(app);
        apply(app, true, result);
        true
    }
}

fn reset_submitting(app: &mut App) {
    if let Some(app::DeviceModal::Form(form)) = app.devices.modal.as_mut() {
        form.submitting = false;
    }
    if let Some(form) = app.lists.edit_modal.as_mut() {
        form.submitting = false;
    }
    if let Some(form) = app.lists.catalog_picker.as_mut() {
        form.submitting = false;
    }
    if let Some(form) = app.rules.edit_modal.as_mut() {
        form.submitting = false;
    }
}

/// Close only the accepted action's presentation. Its slot and owned work
/// remain alive, and completion reports the outcome without restoring a form.
pub(super) fn detach_presentation(app: &mut App) {
    let Some(pending) = app.pending_action.as_mut() else {
        return;
    };
    pending.detached = true;
    let surface = pending.surface;
    match surface {
        Surface::Device => app.devices.modal = None,
        Surface::Profile => app.profiles.modal = None,
        Surface::Subnet => app.subnets.modal = None,
        Surface::Group => app.groups.modal = None,
        Surface::Label => app.labels.modal = None,
        Surface::LocalDns => app.local_dns.modal = None,
        Surface::Catalog => app.lists.catalog_picker = None,
        Surface::ListEdit => app.lists.edit_modal = None,
        Surface::RuleEdit => app.rules.edit_modal = None,
        Surface::RuleAdd => app.rules.add_modal = None,
        Surface::Tracking => app.settings.tracking_panel = None,
        Surface::Restore => app.settings.restore_modal = None,
        Surface::Backup => app.settings.backup_modal = None,
        #[cfg(feature = "cluster")]
        Surface::Nodes => app.nodes.dialog = None,
        Surface::Global => {}
    }
}

/// Navigate between visible screens without dispatching a key to an open form.
pub(super) fn navigate_screen(app: &mut App, key: KeyCode) -> bool {
    let leaf = match key {
        KeyCode::Tab => super::next_visible_leaf(app),
        KeyCode::BackTab => super::prev_visible_leaf(app),
        KeyCode::Char('[') => super::visible_leaf_in_section(app, false),
        KeyCode::Char(']') => super::visible_leaf_in_section(app, true),
        KeyCode::Char(digit @ '1'..='5') => {
            app::Section::ALL[(digit as u8 - b'1') as usize].default_leaf()
        }
        _ => return false,
    };
    app.active_leaf = leaf;
    app.force_poll = true;
    true
}

/// The busy input gate prevents modal replacement as well as duplicate writes.
/// Esc detaches the presentation, not the accepted operation. Tab navigation
/// and quit do not wait for IPC. No form snapshot is restored on completion.
pub(super) fn handle_busy_key(app: &mut App, key: KeyEvent) -> Option<bool> {
    app.pending_action.as_ref()?;
    let previous_leaf = app.active_leaf;
    if (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL))
        || key.code == KeyCode::Char('q')
    {
        return Some(true);
    }
    match key.code {
        KeyCode::Esc => detach_presentation(app),
        KeyCode::Char('?') => app.show_help = !app.show_help,
        _ => {
            navigate_screen(app, key.code);
        }
    }
    if app.active_leaf != previous_leaf {
        detach_presentation(app);
    }
    Some(false)
}

pub(super) fn render_saving(frame: &mut ratatui::Frame, app: &App) {
    let Some(pending) = &app.pending_action else {
        return;
    };
    let area = frame.area();
    if area.height == 0 {
        return;
    }
    let area = ratatui::layout::Rect::new(area.x, area.bottom() - 1, area.width, 1);
    frame.render_widget(ratatui::widgets::Clear, area);
    let label = pending.written.as_deref().unwrap_or(&pending.label);
    let version = concat!(" v", env!("CARGO_PKG_VERSION"), " ");
    let version_width = version.len() as u16;
    let mut hints = Vec::new();
    for (key, description) in [("Esc", "close"), ("Tab", "screen"), ("q", "quit")] {
        hints.extend(super::ui::key_span(key, description));
        hints.push(ratatui::text::Span::raw(" "));
    }
    let hints_width = ratatui::text::Line::from(hints.clone()).width() as u16;
    let cols = ratatui::layout::Layout::horizontal([
        ratatui::layout::Constraint::Min(0),
        ratatui::layout::Constraint::Length(hints_width),
        ratatui::layout::Constraint::Length(version_width),
    ])
    .split(area);
    frame.render_widget(
        ratatui::widgets::Paragraph::new(crate::tui::text::fit(
            &format!("{label}…"),
            cols[0].width as usize,
        )),
        cols[0],
    );
    frame.render_widget(
        ratatui::widgets::Paragraph::new(ratatui::text::Line::from(hints)),
        cols[1],
    );
    frame.render_widget(
        ratatui::widgets::Paragraph::new(version)
            .style(ratatui::style::Style::default().fg(super::theme::T.text_muted)),
        cols[2],
    );
}

pub(super) struct WriteResult<D = ()> {
    pub details: Option<D>,
    pub result: Result<String, String>,
    pub config: Option<Box<app::ConfigSnapshot>>,
    pub reload: Option<crate::cli::commands::ipc_reload::ReloadOutcome>,
}

/// The guarded writer runs on the blocking pool; its guard is gone before
/// reload. A failed reload never turns a completed disk write into a retry.
pub(super) async fn write<D, F>(
    path: PathBuf,
    socket: PathBuf,
    work: F,
    progress: Option<(u64, tokio::sync::mpsc::UnboundedSender<app::UiJob>)>,
) -> WriteResult<D>
where
    D: Send + 'static,
    F: FnOnce(&std::path::Path) -> (Result<String, String>, bool, D) + Send + 'static,
{
    write_with_reload(
        path,
        async move { crate::cli::commands::ipc_reload::attempt_reload(&socket).await },
        work,
        progress,
    )
    .await
}

pub(super) async fn start_disk<F, A>(
    app: &mut App,
    surface: Surface,
    label: &str,
    path: &std::path::Path,
    poller: &super::IpcPoller,
    work: F,
    apply: A,
) -> bool
where
    F: FnOnce(&std::path::Path) -> (Result<String, String>, bool) + Send + 'static,
    A: FnOnce(&mut App, bool, WriteResult) + Send + 'static,
{
    start_disk_details(
        app,
        surface,
        label,
        path,
        poller,
        move |path| {
            let (result, changed) = work(path);
            (result, changed, ())
        },
        apply,
    )
    .await
}

pub(super) fn report<D>(app: &mut App, result: WriteResult<D>, noun: &str) {
    if let Some(config) = result.config {
        super::apply_config_snapshot(app, *config);
    }
    use crate::cli::commands::ipc_reload::ReloadOutcome;
    let failed = result.result.is_err();
    let mut message = match result.result {
        Ok(message) | Err(message) => message,
    };
    let reload_error = match result.reload {
        None | Some(ReloadOutcome::Reloaded) => None,
        Some(ReloadOutcome::DaemonUnreachable) => {
            Some("daemon not running, will activate on next start".to_owned())
        }
        Some(ReloadOutcome::NoToken { .. }) => {
            Some("no admin token is available to request a reload".to_owned())
        }
        Some(ReloadOutcome::ReloadFailed(error)) => {
            Some(format!("daemon rejected reload: {error}"))
        }
    };
    if let Some(error) = &reload_error {
        // An unsuccessful batch can still have durable writes. Its primary
        // error and target details must survive the post-write reload failure.
        if failed {
            message.push_str(&format!("; reload of disk changes: {error}"));
        } else {
            message.push_str(&format!("; {noun} saved on disk; {error}"));
        }
    }
    if failed || reload_error.is_some() {
        app.status_err(message);
    } else {
        app.status_ok(message);
    }
}

pub(super) async fn start_disk_details<D, F, A>(
    app: &mut App,
    surface: Surface,
    label: &str,
    path: &std::path::Path,
    poller: &super::IpcPoller,
    work: F,
    apply: A,
) -> bool
where
    D: Send + 'static,
    F: FnOnce(&std::path::Path) -> (Result<String, String>, bool, D) + Send + 'static,
    A: FnOnce(&mut App, bool, WriteResult<D>) + Send + 'static,
{
    let progress = app.job_tx.clone().map(|tx| (app.action_serial + 1, tx));
    dispatch(
        app,
        surface,
        label,
        write(
            path.to_owned(),
            poller.socket_path().to_owned(),
            work,
            progress,
        ),
        apply,
    )
    .await
}

pub(super) async fn write_with_reload<D, F, R>(
    path: PathBuf,
    reload: R,
    work: F,
    progress: Option<(u64, tokio::sync::mpsc::UnboundedSender<app::UiJob>)>,
) -> WriteResult<D>
where
    D: Send + 'static,
    R: Future<Output = crate::cli::commands::ipc_reload::ReloadOutcome> + Send + 'static,
    F: FnOnce(&std::path::Path) -> (Result<String, String>, bool, D) + Send + 'static,
{
    let written = tokio::task::spawn_blocking(move || {
        let (result, changed, details) = work(&path);
        if changed {
            if let Some((id, tx)) = progress {
                let summary = match &result {
                    Ok(msg) => format!("{msg}; reloading"),
                    Err(error) => format!("partially saved: {error}; reloading"),
                };
                let _ = tx.send(app::UiJob::ActionProgress(ActionProgress { id, summary }));
            }
        }
        let config = Some(Box::new(super::load_config_snapshot(&path)));
        (result, config, changed, details)
    })
    .await;
    match written {
        Ok((result, config, changed, details)) => {
            let reload = if changed { Some(reload.await) } else { None };
            WriteResult {
                details: Some(details),
                result,
                config,
                reload,
            }
        }
        Err(error) => WriteResult {
            details: None,
            result: Err(format!(
                "write interrupted; inspect configuration before retrying: {error}"
            )),
            config: None,
            reload: None,
        },
    }
}
