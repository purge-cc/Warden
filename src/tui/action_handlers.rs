//! Owned action inputs and application of typed results to live forms.
use super::actions::Surface;
use super::*;

fn write_subnets(stage: subnet_modal::Stage, config_path: &Path) -> (Result<String, String>, bool) {
    use crate::cli::commands::subnets::{add_inner, remove_inner, RemoveOutcome};
    use subnet_modal::{Stage, SubmitOutcome};

    // The armed tag valve, captured before the form is consumed.
    let outcome: SubmitOutcome = match &stage {
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
        Stage::Submitted(_) => return (Err("already submitted".into()), false),
    };

    let result = match outcome {
        SubmitOutcome::Ok(msg) => Ok(msg),
        SubmitOutcome::Failed(msg) => Err(msg),
    };
    let changed = result.is_ok();
    (result, changed)
}

pub(super) async fn subnets(
    app: &mut App,
    modal: subnet_modal::SubnetModal,
    poller: &IpcPoller,
    path: &Path,
) {
    let stage = modal.stage.clone();
    app.subnets.modal = Some(modal);
    actions::start_disk(
        app,
        Surface::Subnet,
        "Saving subnets",
        path,
        poller,
        move |path| write_subnets(stage, path),
        |app, attached, result| {
            if attached {
                if let Some(modal) = app.subnets.modal.as_mut() {
                    match &result.result {
                        Err(error) => match &mut modal.stage {
                            subnet_modal::Stage::EditingForm(form) => {
                                form.error_message = Some(error.clone())
                            }
                            _ => modal.finish(subnet_modal::SubmitOutcome::Failed(error.clone())),
                        },
                        Ok(msg) => modal.finish(subnet_modal::SubmitOutcome::Ok(msg.clone())),
                    }
                }
            }
            actions::report(app, result, "subnets");
        },
    )
    .await;
}
fn write_groups(stage: group_modal::Stage, config_path: &Path) -> (Result<String, String>, bool) {
    use crate::cli::commands::groups::add_inner;
    use group_modal::{Stage, SubmitOutcome};

    let outcome: SubmitOutcome = match &stage {
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
        Stage::Submitted(_) => return (Err("already submitted".into()), false),
    };

    let result = match outcome {
        SubmitOutcome::Ok(msg) => Ok(msg),
        SubmitOutcome::Failed(msg) => Err(msg),
    };
    let changed = result.is_ok();
    (result, changed)
}

pub(super) async fn groups(
    app: &mut App,
    modal: group_modal::GroupModal,
    poller: &IpcPoller,
    path: &Path,
) {
    let stage = modal.stage.clone();
    app.groups.modal = Some(modal);
    actions::start_disk(
        app,
        Surface::Group,
        "Saving groups",
        path,
        poller,
        move |path| write_groups(stage, path),
        |app, attached, result| {
            if attached {
                if let Some(modal) = app.groups.modal.as_mut() {
                    match &result.result {
                        Err(error) => match &mut modal.stage {
                            group_modal::Stage::EditingForm(form) => {
                                form.error_message = Some(error.clone())
                            }
                            _ => modal.finish(group_modal::SubmitOutcome::Failed(error.clone())),
                        },
                        Ok(msg) => modal.finish(group_modal::SubmitOutcome::Ok(msg.clone())),
                    }
                }
            }
            actions::report(app, result, "groups");
        },
    )
    .await;
}
enum CustomListPolicyAction {
    Unchanged(String),
    Change(crate::tui::operator_policy::PolicyChange),
}

fn custom_list_policy_action(
    stage: &custom_list_modal::Stage,
    rules: Option<&crate::tui::operator_policy::PolicyRules>,
) -> Result<CustomListPolicyAction, String> {
    use crate::tui::operator_policy::PolicyChange;
    use custom_list_modal::{FormMode, Stage};

    match stage {
        Stage::EditingForm(form) => {
            let resolved = form.try_resolve()?;
            let unchanged = form.original.as_ref().is_some_and(|original| {
                original.id == resolved.id
                    && original.display_name == resolved.display_name
                    && original.description == resolved.description
            });
            if form.mode == FormMode::Edit && unchanged {
                return Ok(CustomListPolicyAction::Unchanged(format!(
                    "custom list {} unchanged",
                    resolved.id
                )));
            }
            let operation = match form.mode {
                FormMode::Add => crate::operator_rules::Operation::CreateList {
                    id: resolved.id,
                    display_name: resolved.display_name,
                    description: resolved.description,
                    into: None,
                },
                FormMode::Edit => match form.original.as_ref() {
                    Some(original) if original.id == resolved.id => {
                        crate::operator_rules::Operation::SetMetadata {
                            id: original.id.clone(),
                            display_name: (original.display_name != resolved.display_name)
                                .then_some(resolved.display_name),
                            description: (original.description != resolved.description)
                                .then_some(resolved.description),
                        }
                    }
                    Some(_) => return Err("custom list identity changed — reopen the list".into()),
                    None => return Err("custom-list edit lost its original snapshot".into()),
                },
            };
            Ok(CustomListPolicyAction::Change(PolicyChange::Operations(
                vec![operation],
            )))
        }
        Stage::ConfirmingRemove(confirm) => Ok(CustomListPolicyAction::Change(
            PolicyChange::Operations(vec![crate::operator_rules::Operation::DeleteList {
                id: confirm.id.clone(),
                cascade_unmount: false,
            }]),
        )),
        Stage::AddingRule(form) => match form.replacing() {
            None => Ok(CustomListPolicyAction::Change(PolicyChange::Operations(
                vec![crate::operator_rules::Operation::AddDomainRule {
                    id: form.list_id.clone(),
                    domain: form.domain.trim().to_string(),
                    action: if form.allow {
                        crate::operator_rules::RuleAction::Allow
                    } else {
                        crate::operator_rules::RuleAction::Deny
                    },
                }],
            ))),
            Some((line, ..)) if form.is_unchanged() => Ok(CustomListPolicyAction::Unchanged(
                format!("line {line} of {} unchanged", form.list_id),
            )),
            Some(_) => {
                let row_ref = form
                    .row_ref()
                    .ok_or_else(|| "custom-list edit lost its original row".to_string())?;
                let (expected_config_revision, expected_pack_revision) =
                    captured_rule_fence(rules, &form.list_id, std::slice::from_ref(&row_ref))?;
                Ok(CustomListPolicyAction::Change(PolicyChange::ReplaceRule {
                    id: form.list_id.clone(),
                    expected_config_revision,
                    expected_pack_revision,
                    row_ref: row_ref.to_string(),
                    replacement: form.replacement_rule()?,
                }))
            }
        },
        Stage::ConfirmingRuleRemove(confirm) => {
            let row_refs: Vec<&str> = confirm
                .affected
                .iter()
                .map(|target| target.row_ref.as_str())
                .collect();
            let (expected_config_revision, expected_pack_revision) =
                captured_rule_fence(rules, &confirm.list_id, &row_refs)?;
            Ok(CustomListPolicyAction::Change(PolicyChange::RemoveRules {
                id: confirm.list_id.clone(),
                expected_config_revision,
                expected_pack_revision,
                row_refs: row_refs.into_iter().map(str::to_owned).collect(),
            }))
        }
        Stage::Submitted(_) => Err("already submitted".into()),
    }
}

fn captured_rule_fence(
    rules: Option<&crate::tui::operator_policy::PolicyRules>,
    list_id: &str,
    row_refs: &[&str],
) -> Result<(String, String), String> {
    let rules = rules.filter(|rules| rules.id == list_id).ok_or_else(|| {
        "the captured backend rule snapshot is unavailable; reopen the rule".to_string()
    })?;
    if row_refs.iter().any(|row_ref| {
        !rules
            .rows
            .iter()
            .any(|row| row.row_ref.as_str() == *row_ref)
    }) {
        return Err("the captured backend rule snapshot is stale; reopen the rule".into());
    }
    Ok((rules.config_revision.clone(), rules.pack_revision.clone()))
}

pub(super) async fn custom_lists(
    app: &mut App,
    modal: custom_list_modal::CustomListModal,
    poller: &IpcPoller,
    _path: &Path,
) {
    app.custom_lists.modal = Some(modal);
    let rules = app.operator_rules.clone();
    let action = app
        .custom_lists
        .modal
        .as_ref()
        .map(|modal| custom_list_policy_action(&modal.stage, rules.as_ref()));
    match action {
        Some(Ok(CustomListPolicyAction::Unchanged(message))) => {
            if let Some(modal) = app.custom_lists.modal.as_mut() {
                modal.finish(custom_list_modal::SubmitOutcome::Ok(message.clone()));
            }
            app.status_info(message);
        }
        Some(Ok(CustomListPolicyAction::Change(change))) => {
            crate::tui::operator_policy::open(
                app,
                poller,
                crate::tui::operator_policy::PolicyOrigin::CustomList,
                change,
            )
            .await;
        }
        Some(Err(error)) => {
            if let Some(modal) = app.custom_lists.modal.as_mut() {
                match &mut modal.stage {
                    custom_list_modal::Stage::EditingForm(form) => {
                        form.error_message = Some(error.clone())
                    }
                    custom_list_modal::Stage::AddingRule(form) => {
                        form.error_message = Some(error.clone())
                    }
                    _ => modal.finish(custom_list_modal::SubmitOutcome::Failed(error.clone())),
                }
            }
            app.status_err(error);
        }
        None => {}
    }
}
fn write_local_dns(stage: local_dns_modal::Stage, path: &Path) -> (Result<String, String>, bool) {
    use crate::cli::commands::local_dns::{
        add_inner, format_local_records_removed, remove_inner, LocalRecordScope, RemoveOutcome,
    };
    use local_dns_modal::{Stage, SubmitOutcome};
    let unchanged = |message| LocalDnsWriteOutcome {
        outcome: SubmitOutcome::Failed(message),
        changed: false,
    };
    let write = match stage {
        Stage::EditingForm(form) => match form.try_resolve() {
            Err(error) => unchanged(error),
            Ok((scope, spec)) => match form.mode {
                local_dns_modal::FormMode::Add => {
                    local_dns_add_write_result(&scope, &spec, add_inner(path, &scope, &spec, None))
                }
                local_dns_modal::FormMode::Edit => match form.original {
                    Some(original) => submit_local_dns_edit_write(
                        path,
                        &original.scope,
                        &original.spec,
                        &scope,
                        &spec,
                    ),
                    None => {
                        unchanged("internal error: edit modal lost its original snapshot".into())
                    }
                },
            },
        },
        Stage::ConfirmingRemove(rc) => match remove_inner(
            path,
            &rc.scope,
            &rc.spec.domain,
            Some(rc.spec.record_type),
            None,
        ) {
            Ok(RemoveOutcome::Removed { .. }) => {
                let scope = match &rc.scope {
                    LocalRecordScope::Global => "global".to_owned(),
                    LocalRecordScope::Profile(id) => format!("profile '{id}'"),
                };
                LocalDnsWriteOutcome {
                    outcome: SubmitOutcome::Ok(format_local_records_removed(
                        &rc.spec.domain,
                        &scope,
                    )),
                    changed: true,
                }
            }
            Ok(RemoveOutcome::NotFound) => unchanged(format!(
                "record '{}' not found in scope — already removed?",
                rc.spec.domain
            )),
            Err(error) => unchanged(error.to_string()),
        },
        Stage::Submitted(_) => unchanged("already submitted".into()),
    };
    let result = match write.outcome {
        SubmitOutcome::Ok(msg) => Ok(msg),
        SubmitOutcome::Failed(msg) => Err(msg),
    };
    (result, write.changed)
}

pub(super) async fn local_dns(
    app: &mut App,
    modal: local_dns_modal::LocalDnsModal,
    poller: &IpcPoller,
    path: &Path,
) {
    let stage = modal.stage.clone();
    app.local_dns.modal = Some(modal);
    actions::start_disk(
        app,
        Surface::LocalDns,
        "Saving local_dns",
        path,
        poller,
        move |path| write_local_dns(stage, path),
        |app, attached, result| {
            if attached {
                if let Some(modal) = app.local_dns.modal.as_mut() {
                    match &result.result {
                        Err(error) => match &mut modal.stage {
                            local_dns_modal::Stage::EditingForm(form) => {
                                form.error_message = Some(error.clone())
                            }
                            _ => {
                                modal.finish(local_dns_modal::SubmitOutcome::Failed(error.clone()))
                            }
                        },
                        Ok(msg) => modal.finish(local_dns_modal::SubmitOutcome::Ok(msg.clone())),
                    }
                }
            }
            actions::report(app, result, "local_dns");
        },
    )
    .await;
}

async fn write_profile(stage: profile_modal::Stage, poller: &IpcPoller) -> Result<String, String> {
    use crate::ipc::protocol::ProfileUpdatePatch;
    use profile_modal::{FormMode, Stage, SubmitOutcome};

    let outcome: SubmitOutcome = match &stage {
        Stage::EditingForm(form) => match form.mode {
            FormMode::Add => {
                SubmitOutcome::Failed("profile creation requires reconciliation".into())
            }
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
        Stage::ReviewingError(_) | Stage::Submitted(_) => {
            return Err("profile form is not ready to submit".into());
        }
    };

    match outcome {
        SubmitOutcome::Ok(msg) => Ok(msg),
        SubmitOutcome::Failed(msg) => Err(msg),
    }
}

type ProfilePolicyChange = (
    String,
    crate::ipc::protocol::ProfileUpdatePatch,
    Vec<crate::operator_rules::Operation>,
);

fn profile_policy_change(
    stage: &profile_modal::Stage,
) -> Result<Option<ProfilePolicyChange>, String> {
    let profile_modal::Stage::EditingForm(form) = stage else {
        return Ok(None);
    };
    if form.mode != profile_modal::FormMode::Edit {
        return Ok(None);
    }
    let original = form
        .original
        .as_ref()
        .ok_or_else(|| "internal error: edit modal lost its original snapshot".to_string())?;
    let mut patch = profile_modal::resolve_edit_patch(form, original)?;
    let Some(mounts) = patch.custom_lists.take() else {
        return Ok(None);
    };
    let profile_id = original.id.clone();
    let mut operations = Vec::with_capacity(mounts.mount.len() + mounts.unmount.len());
    operations.extend(
        mounts
            .mount
            .into_iter()
            .map(|id| crate::operator_rules::Operation::Mount {
                id,
                profile_id: profile_id.clone(),
            }),
    );
    operations.extend(mounts.unmount.into_iter().map(|id| {
        crate::operator_rules::Operation::Unmount {
            id,
            profile_id: profile_id.clone(),
        }
    }));
    Ok(Some((profile_id, patch, operations)))
}

async fn create_profile(
    app: &mut App,
    mut modal: profile_modal::ProfileModal,
    poller: &IpcPoller,
    path: &Path,
) {
    let profile_modal::Stage::EditingForm(form) = &mut modal.stage else {
        return;
    };
    let (id, display_name) = match form.try_resolve_add().and_then(|(id, name)| {
        profile_modal::resolve_add_patch(form, &id, &name)?;
        Ok((id, name))
    }) {
        Ok(values) => values,
        Err(error) => {
            modal.fail(error);
            app.profiles.modal = Some(modal);
            return;
        }
    };
    if form.creation_attempted && !form.creation_confirmed {
        modal.fail("Creation was already attempted. Verify the profile in the list before reopening Add; this draft will not send a duplicate creation.".into());
        app.profiles.modal = Some(modal);
        return;
    }
    let readback_only = form.creation_confirmed;
    form.creation_attempted = true;
    app.profiles.modal = Some(modal);
    let socket = poller.socket_path().to_owned();
    let path = path.to_owned();
    actions::dispatch(
        app,
        Surface::Profile,
        "Creating profile",
        async move {
            let outcome = if readback_only {
                Ok(format!("created profile {id}"))
            } else {
                IpcPoller::new(&socket).send_profile_create(id, display_name).await
            };
            let refused = matches!(&outcome, Err(ipc_poller::ProfileCreateFailure::Refused(_)));
            let result = outcome.map_err(|error| error.to_string());
            let config = tokio::task::spawn_blocking(move || Box::new(load_config_snapshot(&path))).await.ok();
            actions::WriteResult { details: Some(refused), result, config, reload: None }
        },
        |app, attached, mut result| {
            if attached {
                if let Some(modal) = app.profiles.modal.as_mut() {
                    if let profile_modal::Stage::EditingForm(form) = &mut modal.stage {
                        if let Ok(message) = &result.result {
                            form.creation_confirmed = true;
                            let persisted = result.config.as_ref()
                                .and_then(|snapshot| snapshot.loaded_config.as_ref())
                                .and_then(|loaded| loaded.config.profiles.get(form.id.as_str()));
                            if let Some(profile) = persisted {
                                form.reconcile_created(profile);
                                let remaining = profile_modal::resolve_edit_patch(form, form.original.as_ref().unwrap());
                                if remaining.as_ref().is_ok_and(|patch| *patch == crate::ipc::protocol::ProfileUpdatePatch::default()) {
                                    modal.finish(profile_modal::SubmitOutcome::Ok(message.clone()));
                                } else {
                                    let message = "Profile created. Review the remaining settings and Save; custom-list mounts require Apply in the preview.".to_string();
                                    form.error_message = Some(message.clone());
                                    result.result = Ok(message);
                                }
                            } else {
                                let message = "Profile created, but its configuration could not be read back. Save retries the read without creating it again.".to_string();
                                form.error_message = Some(message.clone());
                                result.result = Err(message);
                            }
                        } else if let Err(error) = &result.result {
                            if result.details == Some(true) { form.creation_attempted = false; }
                            modal.fail(error.clone());
                        }
                    }
                }
            }
            actions::report(app, result, "profile");
        },
    ).await;
}

pub(super) async fn profile(
    app: &mut App,
    modal: profile_modal::ProfileModal,
    poller: &IpcPoller,
    path: &Path,
) {
    if matches!(&modal.stage, profile_modal::Stage::EditingForm(form) if form.mode == profile_modal::FormMode::Add)
    {
        create_profile(app, modal, poller, path).await;
        return;
    }
    let policy_change = match profile_policy_change(&modal.stage) {
        Ok(change) => change,
        Err(error) => {
            let mut modal = modal;
            if let profile_modal::Stage::EditingForm(form) = &mut modal.stage {
                form.error_message = Some(error);
            }
            app.profiles.modal = Some(modal);
            return;
        }
    };
    if let Some((profile_id, patch, operations)) = policy_change {
        let properties_changed = patch != crate::ipc::protocol::ProfileUpdatePatch::default();
        app.profiles.modal = Some(modal);
        let origin = crate::tui::operator_policy::PolicyOrigin::ProfileMounts {
            profile_id: profile_id.clone(),
            properties_committed: false,
        };
        let change = crate::tui::operator_policy::PolicyChange::Operations(operations);
        if properties_changed {
            crate::tui::operator_policy::open_profile_after(
                app,
                poller,
                origin,
                change,
                path.to_owned(),
                crate::tui::operator_policy::ProfilePrefix { profile_id, patch },
            )
            .await;
        } else {
            crate::tui::operator_policy::open(app, poller, origin, change).await;
        }
        return;
    }
    let stage = modal.stage.clone();
    app.profiles.modal = Some(modal);
    let socket = poller.socket_path().to_owned();
    let path = path.to_owned();
    actions::dispatch(
        app,
        Surface::Profile,
        "Saving profile",
        async move {
            let result = write_profile(stage, &IpcPoller::new(&socket)).await;
            let config = tokio::task::spawn_blocking(move || Box::new(load_config_snapshot(&path)))
                .await
                .ok();
            actions::WriteResult {
                details: Some(()),
                result,
                config,
                reload: None,
            }
        },
        |app, attached, result| {
            if attached {
                if let Some(modal) = app.profiles.modal.as_mut() {
                    match &result.result {
                        Err(error) => modal.fail(error.clone()),
                        Ok(msg) => modal.finish(profile_modal::SubmitOutcome::Ok(msg.clone())),
                    }
                }
            }
            actions::report(app, result, "profile");
        },
    )
    .await;
}

pub(super) async fn device(app: &mut App, mut form: DeviceFormState, poller: &IpcPoller) {
    let parsed = match parse_form(&form) {
        Ok(parsed) => parsed,
        Err(error) => {
            form.error_message = Some(error);
            app.devices.modal = Some(DeviceModal::Form(form));
            return;
        }
    };
    let mode = form.mode;
    let original_id = form.original_id.clone();
    form.submitting = true;
    form.error_message = None;
    app.devices.modal = Some(DeviceModal::Form(form));
    let socket = poller.socket_path().to_owned();
    actions::dispatch(
        app,
        Surface::Device,
        "Saving device",
        async move {
            let poller = IpcPoller::new(&socket);
            let result = match mode {
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
                    // CAPTURED AT MODAL-OPEN (`original_id`), NOT a
                    // re-resolution from the live cursor. A 5s poll can reshuffle
                    // the row set under the open modal, so re-deriving the target
                    // here could patch a different device than the one the form
                    // was opened on. Fall back to slug(parsed.name) only for a
                    // form with no captured id (Add-converted-to-Edit edge; the
                    // id-less case is already handled at capture time).
                    let original_id = original_id.clone().unwrap_or_else(|| {
                        crate::cli::commands::target::slug_id(&parsed.name)
                            .unwrap_or(parsed.name.clone())
                    });
                    poller.send_device_update(original_id, patch).await
                }
            };

            result.map_err(|error| {
                format!("{error}; if transport failed, inspect device state before retrying")
            })
        },
        |app, attached, result| match result {
            Ok(message) => {
                if attached {
                    app.devices.modal = None;
                }
                app.status_ok(message);
                app.force_poll = true;
            }
            Err(error) => {
                if attached {
                    if let Some(DeviceModal::Form(form)) = app.devices.modal.as_mut() {
                        form.submitting = false;
                        form.error_message = Some(error.clone());
                    }
                }
                app.status_err(error);
            }
        },
    )
    .await;
    if app.job_tx.is_none() && app.devices.modal.is_none() {
        poll_active_leaf(app, poller).await;
    }
}

pub(super) async fn device_remove(
    app: &mut App,
    id: String,
    display_name: String,
    poller: &IpcPoller,
) {
    app.devices.modal = Some(DeviceModal::DeleteConfirm {
        id: id.clone(),
        display_name,
    });
    let socket = poller.socket_path().to_owned();
    actions::dispatch(
        app,
        Surface::Device,
        "Deleting device",
        async move {
            IpcPoller::new(&socket)
                .send_device_remove(id)
                .await
                .map_err(|e| e.to_string())
        },
        |app, attached, result| match result {
            Ok(msg) => {
                if attached {
                    app.devices.modal = None;
                }
                app.status_ok(msg);
                app.force_poll = true;
            }
            Err(error) => app.status_err(format!(
                "delete failed; check current device state before retrying: {error}"
            )),
        },
    )
    .await;
    if app.job_tx.is_none() && app.devices.modal.is_none() {
        poll_active_leaf(app, poller).await;
    }
}

pub(super) async fn tracking(
    app: &mut App,
    patch: crate::ipc::protocol::TrackingPatch,
    poller: &IpcPoller,
) {
    let socket = poller.socket_path().to_owned();
    let path = app
        .loaded_config
        .as_ref()
        .map(|loaded| loaded.master_path.clone());
    actions::dispatch(
        app,
        Surface::Tracking,
        "Saving tracking",
        async move {
            let result = IpcPoller::new(&socket)
                .send_tracking_update(patch)
                .await
                .map_err(|error| error.to_string());
            let config = match path {
                Some(path) if result.is_ok() => {
                    tokio::task::spawn_blocking(move || Box::new(load_config_snapshot(&path)))
                        .await
                        .ok()
                }
                _ => None,
            };
            actions::WriteResult {
                details: Some(()),
                result,
                config,
                reload: None,
            }
        },
        |app, attached, result| {
            if attached {
                match &result.result {
                    Ok(_) => app.settings.tracking_panel = None,
                    Err(error) => {
                        if let Some(panel) = app.settings.tracking_panel.as_mut() {
                            panel.submit_message = Some(format!("error: {error}"));
                        }
                    }
                }
            }
            actions::report(app, result, "tracking");
        },
    )
    .await;
}

pub(super) async fn reload<F>(app: &mut App, path: Option<PathBuf>, reload: F)
where
    F: std::future::Future<Output = anyhow::Result<String>> + Send + 'static,
{
    actions::dispatch(
        app,
        Surface::Global,
        "Reloading configuration",
        async move {
            let config = match path {
                Some(path) => {
                    tokio::task::spawn_blocking(move || Box::new(load_config_snapshot(&path)))
                        .await
                        .ok()
                }
                None => None,
            };
            (config, reload.await.map_err(|e| e.to_string()))
        },
        |app, _, (config, result)| {
            if let Some(config) = config {
                apply_config_snapshot(app, *config);
            }
            match result {
                Ok(msg) => app.status_ok(format!("reload: {msg}")),
                Err(error) => app.status_err(format!("reload failed: {error}")),
            }
            app.force_poll = true;
        },
    )
    .await;
}

pub(super) async fn mount(app: &mut App, poller: &IpcPoller, _path: &Path) {
    let Some(picker) = app.custom_lists.mount_picker.as_ref() else {
        return;
    };
    let changes: Vec<(String, bool)> = picker
        .changes()
        .into_iter()
        .map(|(p, on)| (p.to_owned(), on))
        .collect();
    if changes.is_empty() {
        app.custom_lists.mount_picker = None;
        app.status_info("nothing to mount".into());
        return;
    }
    let id = picker.list_id.clone();
    let operations = changes
        .into_iter()
        .map(|(profile_id, mounted)| {
            if mounted {
                crate::operator_rules::Operation::Mount {
                    id: id.clone(),
                    profile_id,
                }
            } else {
                crate::operator_rules::Operation::Unmount {
                    id: id.clone(),
                    profile_id,
                }
            }
        })
        .collect();
    crate::tui::operator_policy::open(
        app,
        poller,
        crate::tui::operator_policy::PolicyOrigin::Mount,
        crate::tui::operator_policy::PolicyChange::Operations(operations),
    )
    .await;
}

pub(super) async fn catalog(app: &mut App, poller: &IpcPoller, path: &Path) {
    let Some(modal) = app.lists.catalog_picker.as_mut() else {
        return;
    };
    let dirty: Vec<app::CatalogPickerRow> = modal.dirty_rows().cloned().collect();
    if dirty.is_empty() {
        app.lists.catalog_picker = None;
        app.status_ok("no pending changes — nothing written".into());
        return;
    }
    modal.submitting = true;
    modal.error_message = None;
    actions::start_disk(app, Surface::Catalog, "Saving catalog selection", path, poller, move |path| {
        let result = apply_catalog_picker_changes(path, &dirty).map(|(added, updated)| {
            for row in &dirty {
                tracing::info!(target: "audit", action = if row.original.is_subscribed() { "blocklist.tui_catalog_set_enabled" } else { "blocklist.tui_catalog_add" }, source = %row.canonical_id, url = %row.url, enabled = row.staged_enabled, surface = "tui", "TUI mutation");
            }
            format!("catalog: {added} added, {updated} updated")
        });
        let changed = result.is_ok(); (result, changed)
    }, |app, attached, result| {
        if attached { match &result.result {
            Ok(_) => app.lists.catalog_picker = None,
            Err(error) => if let Some(modal) = app.lists.catalog_picker.as_mut() { modal.submitting = false; modal.error_message = Some(error.clone()); },
        } }
        actions::report(app, result, "lists");
    }).await;
}

fn write_label(
    stage: label_modal::Stage,
    config_path: &Path,
) -> (Result<String, String>, bool, Vec<String>) {
    use crate::cli::commands::labels::{add_inner, remove_inner};
    use label_modal::{Stage, SubmitOutcome};

    // `landed` names the fields that actually reached disk. Empty means the
    // file is untouched; **non-empty alongside a `Failed` outcome is the
    // partial write** this function exists to handle honestly.
    let (outcome, landed): (SubmitOutcome, Vec<String>) = match &stage {
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
        Stage::Submitted(_) => return (Err("already submitted".into()), false, Vec::new()),
    };

    let result = match outcome {
        SubmitOutcome::Ok(msg) => Ok(msg),
        SubmitOutcome::Failed(msg) => Err(msg),
    };
    let changed = !landed.is_empty();
    (result, changed, landed)
}

pub(super) async fn label(
    app: &mut App,
    modal: label_modal::LabelModal,
    poller: &IpcPoller,
    path: &Path,
) {
    let stage = modal.stage.clone();
    app.labels.modal = Some(modal);
    actions::start_disk_details(
        app,
        Surface::Label,
        "Saving label",
        path,
        poller,
        move |path| write_label(stage, path),
        |app, attached, result| {
            if attached {
                if let Some(modal) = app.labels.modal.as_mut() {
                    if let label_modal::Stage::EditingForm(form) = &mut modal.stage {
                        if let (Some(landed), Ok(resolved)) = (&result.details, form.try_resolve())
                        {
                            if let Some(original) = form.original.as_mut() {
                                for field in landed {
                                    match field.as_str() {
                                        "display_name" => {
                                            original.display_name = resolved.display_name.clone()
                                        }
                                        "description" => {
                                            original.description = resolved.description.clone()
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                    match &result.result {
                        Err(error) => match &mut modal.stage {
                            label_modal::Stage::EditingForm(form) => {
                                form.error_message = Some(error.clone())
                            }
                            _ => modal.finish(label_modal::SubmitOutcome::Failed(error.clone())),
                        },
                        Ok(msg) => modal.finish(label_modal::SubmitOutcome::Ok(msg.clone())),
                    }
                }
            }
            actions::report(app, result, "label");
        },
    )
    .await;
}

pub(super) async fn kind(
    app: &mut App,
    poller: &IpcPoller,
    path: &Path,
    id: &str,
    target: crate::config::schema::BlocklistBase,
    consent: bool,
) {
    let id = id.to_owned();
    actions::start_disk(
        app,
        Surface::Global,
        "Saving list direction",
        path,
        poller,
        move |path| {
            let result = crate::cli::commands::blocklists::set_kind_without_reload(
                path,
                &id,
                target.wire_str(),
                consent,
                None,
            )
            .map(|_| {
                if consent {
                    tabs::lists::format_list_allow_consent_saved(&id)
                } else {
                    tabs::lists::format_kind_toggle_ok(&id, target)
                }
            })
            .map_err(|e| format!("kind toggle refused: {e}"));
            let changed = result.is_ok();
            (result, changed)
        },
        |app, _, result| actions::report(app, result, "list"),
    )
    .await;
}

pub(super) async fn rule_edit(
    app: &mut App,
    mut modal: app::RuleEditModal,
    poller: &IpcPoller,
    path: &Path,
) {
    if matches!(modal.original_scope, app::RuleScope::Orphan) {
        modal.error_message = Some("cannot edit an orphan rule — delete it instead".into());
        app.rules.edit_modal = Some(modal);
        return;
    }
    let id = modal.rule_id.clone();
    let old_scope = modal.original_scope.clone();
    let new_scope = modal.current_scope_choice.clone();
    let to_cli = |action| match action {
        crate::filter::rules::RuleAction::Allow => crate::cli::commands::rules::Action::Allow,
        crate::filter::rules::RuleAction::Block => crate::cli::commands::rules::Action::Deny,
    };
    let old_action = to_cli(modal.original_action);
    let new_action = to_cli(modal.current_action);
    modal.submitting = true;
    modal.error_message = None;
    app.rules.edit_modal = Some(modal);
    actions::start_disk(
        app,
        Surface::RuleEdit,
        "Saving rule",
        path,
        poller,
        move |path| {
            use crate::cli::commands::rules::{
                move_admin_rule_without_reload, MoveWriteOutcome, Scope,
            };
            let old = match &old_scope {
                app::RuleScope::Default => Scope::Default,
                app::RuleScope::Profile(id) => Scope::Profile(id),
                app::RuleScope::Device(id) => Scope::Device(id),
                app::RuleScope::Orphan => unreachable!("validated before dispatch"),
            };
            let new = match &new_scope {
                app::ScopeChoice::Default => Scope::Default,
                app::ScopeChoice::Profile(id) => Scope::Profile(id),
                app::ScopeChoice::Device(id) => Scope::Device(id),
            };
            match move_admin_rule_without_reload(path, &id, old, old_action, new, new_action) {
                Ok(MoveWriteOutcome::NoOp) => (Ok(format!("rule '{id}' unchanged")), false),
                Ok(MoveWriteOutcome::Applied { master_rewritten }) => (
                    Ok(format!(
                        "rule '{id}' updated{}",
                        if master_rewritten {
                            " (action flipped)"
                        } else {
                            ""
                        }
                    )),
                    true,
                ),
                Err(e) => (Err(format!("save failed: {e}")), false),
            }
        },
        apply_rule_edit,
    )
    .await;
}

fn apply_rule_edit(app: &mut App, attached: bool, result: actions::WriteResult) {
    if attached {
        match &result.result {
            Ok(_) => app.rules.edit_modal = None,
            Err(error) => {
                if let Some(modal) = app.rules.edit_modal.as_mut() {
                    modal.submitting = false;
                    modal.status_message = None;
                    modal.error_message = Some(error.clone());
                }
            }
        }
    }
    actions::report(app, result, "rule");
}

pub(super) async fn rule_delete(
    app: &mut App,
    mut modal: app::RuleEditModal,
    poller: &IpcPoller,
    path: &Path,
) {
    let id = modal.rule_id.clone();
    modal.submitting = true;
    app.rules.edit_modal = Some(modal);
    actions::start_disk(
        app,
        Surface::RuleEdit,
        "Deleting rule",
        path,
        poller,
        move |path| {
            use crate::cli::commands::rules::{
                remove_admin_rule_by_id_without_reload, RemoveByIdWriteOutcome,
            };
            match remove_admin_rule_by_id_without_reload(path, &id) {
                Ok(RemoveByIdWriteOutcome::NotFound) => {
                    (Ok(format!("rule '{id}' already absent")), false)
                }
                Ok(RemoveByIdWriteOutcome::Removed { n_refs }) => (
                    Ok(format!("rule '{id}' deleted ({n_refs} references removed)")),
                    true,
                ),
                Err(e) => (Err(format!("delete failed: {e}")), false),
            }
        },
        apply_rule_edit,
    )
    .await;
}

pub(super) async fn list_edit(
    app: &mut App,
    mut modal: app::EditListModal,
    poller: &IpcPoller,
    path: &Path,
) {
    let creates = matches!(
        modal.mode,
        app::EditModalMode::Add | app::EditModalMode::Promote { .. }
    );
    let url = modal.url.trim().to_owned();
    let probe =
        creates && !modal.skip_head_check && modal.head_probe_passed_for.as_deref() != Some(&url);
    modal.submitting = true;
    modal.error_message = None;
    app.lists.edit_modal = Some(modal.clone());
    let path = path.to_owned();
    let socket = poller.socket_path().to_owned();
    let progress = app.job_tx.clone().map(|tx| (app.action_serial + 1, tx));
    actions::dispatch(app, Surface::ListEdit, "Saving list", async move {
        if probe {
            if let Err(error) = crate::cli::commands::blocklists::probe_url_for_tui(&url).await {
                return (actions::WriteResult { result: Err(error.to_string()), config: None, reload: None, details: Some(()) }, None);
            }
        }
        let passed = probe.then_some(url);
        let result = actions::write(path, socket, move |path| {
            let source = match &modal.mode { app::EditModalMode::Promote { source } => Some(source.as_str()), _ => None };
            let result = apply_list_edit(path, &modal, &modal.blocklist_id, creates, source).map(|warning| {
                tracing::info!(target: "audit", action = "blocklist.tui_edit", source = %modal.blocklist_id, surface = "tui", "TUI mutation");
                reloaded_status_text(warning, if modal.consent_declared {
                    tabs::lists::format_list_allow_consent_saved(&modal.blocklist_id)
                } else { crate::cli::commands::blocklists::format_list_edit_ok(&modal.blocklist_id) })
            });
            let changed = result.is_ok(); (result, changed, ())
        }, progress).await;
        (result, passed)
    }, |app, attached, (result, passed)| {
        if attached { if let Some(modal) = app.lists.edit_modal.as_mut() {
            if let Some(url) = passed { if modal.url.trim() == url { modal.head_probe_passed_for = Some(url); } }
        } }
        apply_list_edit_result(app, attached, result);
    }).await;
}

fn apply_list_edit_result(app: &mut App, attached: bool, result: actions::WriteResult) {
    if attached {
        match &result.result {
            Ok(_) => app.lists.edit_modal = None,
            Err(error) => {
                if let Some(modal) = app.lists.edit_modal.as_mut() {
                    modal.submitting = false;
                    modal.status_message = None;
                    modal.error_message = Some(error.clone());
                    // Backend validation can name format, refresh, trust or
                    // authentication fields. Keep those fields visible while
                    // the blocking message is on screen.
                    modal.advanced_expanded = true;
                }
            }
        }
    }
    actions::report(app, result, "list");
}

pub(super) async fn list_delete(
    app: &mut App,
    mut modal: app::EditListModal,
    poller: &IpcPoller,
    path: &Path,
) {
    let id = modal.blocklist_id.clone();
    modal.submitting = true;
    app.lists.edit_modal = Some(modal);
    actions::start_disk(app, Surface::ListEdit, "Deleting list", path, poller, move |path| {
        let result = (|| {
            let guard = crate::config::write_lock::acquire_for_write(path).map_err(|e| e.to_string())?;
            let cascade = crate::cli::commands::blocklists::run_remove_silent_locked(&guard, path, &id, None, true).map_err(|e| e.to_string())?;
            tracing::info!(target: "audit", action = "blocklist.tui_delete", source = %id, surface = "tui", cascade_count = cascade.len(), "TUI mutation");
            Ok(format!("{}{}", crate::cli::commands::blocklists::format_list_delete_ok(&id), cascade_summary(cascade.len())))
        })();
        let changed = result.is_ok(); (result, changed)
    }, apply_list_edit_result).await;
}

pub(super) async fn orphan_remove(app: &mut App, source: String, poller: &IpcPoller, path: &Path) {
    actions::start_disk(
        app,
        Surface::ListEdit,
        "Removing orphan source",
        path,
        poller,
        move |path| {
            let result = remove_source_from_master(path, &source)
                .map(|_| format!("removed orphan source: {source}"))
                .map_err(|e| e.to_string());
            let changed = result.is_ok();
            (result, changed)
        },
        apply_list_edit_result,
    )
    .await;
}

pub(super) async fn query_rules(
    app: &mut App,
    modal: query_log_rule_modal::QueryLogRuleModal,
    poller: &IpcPoller,
    _path: &Path,
) {
    let domain = modal.domain.clone();
    let action = if matches!(modal.action, crate::cli::commands::rules::Action::Allow) {
        crate::operator_rules::RuleAction::Allow
    } else {
        crate::operator_rules::RuleAction::Deny
    };
    let ids = modal.selected_ids();
    app.query_log_rule_modal = Some(modal);
    crate::tui::operator_policy::open(
        app,
        poller,
        crate::tui::operator_policy::PolicyOrigin::QueryRules {
            ids: ids.clone(),
            already_present: Vec::new(),
        },
        crate::tui::operator_policy::PolicyChange::QueryRules {
            ids,
            domain,
            action,
        },
    )
    .await;
}

pub(super) async fn query_new_list(
    app: &mut App,
    resolved: custom_list_modal::ResolvedForm,
    poller: &IpcPoller,
    _path: &Path,
) {
    let id = resolved.id.clone();
    let display_name = resolved.display_name.clone();
    crate::tui::operator_policy::open(
        app,
        poller,
        crate::tui::operator_policy::PolicyOrigin::QueryNewList { id, display_name },
        crate::tui::operator_policy::PolicyChange::Operations(vec![
            crate::operator_rules::Operation::CreateList {
                id: resolved.id,
                display_name: resolved.display_name,
                description: resolved.description,
                into: None,
            },
        ]),
    )
    .await;
}
