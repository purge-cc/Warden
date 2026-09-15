//! Pointer focus uses the same visible field order as keyboard navigation.

use crossterm::event::KeyCode;

use super::app::{
    App, DeviceFormFocus, DeviceFormState, DeviceModal, InputMode, Leaf, TrackingFocus,
};
use super::{
    custom_list_modal, group_modal, label_modal, local_dns_modal, profile_modal, subnet_modal,
};

fn assign<T: Copy>(target: &mut T, fields: impl IntoIterator<Item = T>, index: usize) {
    if let Some(field) = fields.into_iter().nth(index) {
        *target = field;
    }
}

fn custom_field(modal: &mut custom_list_modal::CustomListModal, index: usize) {
    use custom_list_modal::{FormField, FormMode, RuleField, Stage};
    match &mut modal.stage {
        Stage::EditingForm(form) => {
            let skip = usize::from(matches!(form.mode, FormMode::Edit));
            assign(
                &mut form.focused,
                FormField::ALL.into_iter().take(3).skip(skip),
                index,
            );
        }
        Stage::AddingRule(form) => {
            let fields = if form.is_raw_edit() {
                vec![RuleField::Raw]
            } else {
                RuleField::ALL.into_iter().take(2).collect()
            };
            assign(&mut form.focused, fields, index)
        }
        _ => {}
    }
}

pub(super) fn field(app: &mut App, index: usize) {
    if let Some(modal) = app.query_log_rule_modal.as_mut() {
        if let super::query_log_rule_modal::Stage::NewList(inner) = &mut modal.stage {
            custom_field(inner, index);
        }
        return;
    }
    if super::filter_chips::text_editor_open(app) {
        app.filter_editor_focus = super::query_log_controls::FilterFocus::Value;
        return;
    }
    if app.resolver_modal.is_some() {
        // Resolver has one editable query row; its result is a read-only
        // snapshot and must not become a second focus target.
        let _ = index;
        return;
    }
    match app.active_leaf {
        Leaf::QueryLog => {
            if matches!(app.input_mode, InputMode::FilterDomain(_)) {
                app.query_log.domain_focus = super::query_log_controls::FilterFocus::Value;
            } else if let Some(picker) = app.query_log.client_picker.as_mut() {
                let options = super::query_log_client_picker::QueryLogClientPicker::options(
                    app.device_view.as_ref(),
                    &picker.selected,
                );
                picker.click_field(index, &options);
            } else if app.query_log.period_menu {
                if let Some(preset) = super::app::SincePreset::ALL.get(index) {
                    app.query_log.period_draft = *preset;
                    app.query_log.period_focus = super::query_log_controls::FilterFocus::Value;
                }
            } else if let Some(form) = app.query_log.advanced_modal.as_mut() {
                assign(
                    &mut form.focus,
                    super::query_log_filter_modal::Field::ORDER
                        .into_iter()
                        .take(6),
                    index,
                );
            }
        }
        Leaf::Devices => {
            if let Some(DeviceModal::Form(form)) = app.devices.modal.as_mut() {
                if form.picker.is_none() {
                    let fields: Vec<_> = DeviceFormState::FIELDS
                        .into_iter()
                        .filter(|field| !form.is_locked(*field))
                        .map(DeviceFormFocus::Field)
                        .collect();
                    assign(&mut form.focused, fields, index);
                }
            }
        }
        Leaf::Subnets => {
            if let Some(subnet_modal::SubnetModal {
                stage: subnet_modal::Stage::EditingForm(form),
            }) = app.subnets.modal.as_mut()
            {
                let skip = usize::from(matches!(form.mode, subnet_modal::FormMode::Edit));
                assign(
                    &mut form.focused,
                    subnet_modal::FormField::ALL.into_iter().take(5).skip(skip),
                    index,
                );
            }
        }
        Leaf::Groups => {
            if let Some(group_modal::GroupModal {
                stage: group_modal::Stage::EditingForm(form),
            }) = app.groups.modal.as_mut()
            {
                let skip = usize::from(matches!(form.mode, group_modal::FormMode::Edit));
                assign(
                    &mut form.focused,
                    group_modal::FormField::ALL.into_iter().take(5).skip(skip),
                    index,
                );
            }
        }
        Leaf::LocalDns => {
            if let Some(local_dns_modal::LocalDnsModal {
                stage: local_dns_modal::Stage::EditingForm(form),
            }) = app.local_dns.modal.as_mut()
            {
                assign(
                    &mut form.focused,
                    local_dns_modal::FormField::ALL.into_iter().take(6),
                    index,
                );
            }
        }
        Leaf::Profiles => {
            if let Some(profile_modal::ProfileModal {
                stage: profile_modal::Stage::EditingForm(form),
            }) = app.profiles.modal.as_mut()
            {
                let fields = form.visible_fields();
                assign(
                    &mut form.focused,
                    fields.into_iter().filter(|field| {
                        !matches!(
                            field,
                            profile_modal::FormField::Submit | profile_modal::FormField::Cancel
                        )
                    }),
                    index,
                );
            }
        }
        Leaf::Labels => {
            if let Some(label_modal::LabelModal {
                stage: label_modal::Stage::EditingForm(form),
            }) = app.labels.modal.as_mut()
            {
                let skip = usize::from(matches!(form.mode, label_modal::FormMode::Edit));
                assign(
                    &mut form.focused,
                    label_modal::FormField::ALL.into_iter().take(3).skip(skip),
                    index,
                );
            }
        }
        Leaf::Settings => {
            if let Some(panel) = app.settings.tracking_panel.as_mut() {
                assign(
                    &mut panel.focus,
                    [
                        TrackingFocus::Enabled,
                        TrackingFocus::Mode,
                        TrackingFocus::Retention,
                    ],
                    index,
                );
            }
        }
        Leaf::Lists => {
            if let Some(form) = app.lists.edit_modal.as_mut() {
                if matches!(
                    form.mode,
                    super::app::EditModalMode::Edit
                        | super::app::EditModalMode::Add
                        | super::app::EditModalMode::Promote { .. }
                ) {
                    let fields = super::app::EditField::cycle(&form.mode, form.advanced_expanded);
                    assign(
                        &mut form.focus,
                        fields.into_iter().take_while(|field| {
                            !matches!(
                                field,
                                super::app::EditField::DeleteButton
                                    | super::app::EditField::Cancel
                                    | super::app::EditField::Save
                            )
                        }),
                        index,
                    );
                }
            }
        }
        Leaf::Rules => {
            if let Some(modal) = app.rules.add_modal.as_mut() {
                assign(
                    &mut modal.focus,
                    [
                        super::rule_add_modal::AddFocus::Domain,
                        super::rule_add_modal::AddFocus::Action,
                        super::rule_add_modal::AddFocus::Scope,
                    ],
                    index,
                );
            } else if let Some(modal) = app.rules.edit_modal.as_mut() {
                assign(
                    &mut modal.focus,
                    [
                        super::app::RuleEditFocus::Action,
                        super::app::RuleEditFocus::Scope,
                    ],
                    index,
                );
            }
        }
        Leaf::CustomLists => {
            if let Some(modal) = app.custom_lists.modal.as_mut() {
                custom_field(modal, index);
            }
        }
        #[cfg(feature = "cluster")]
        Leaf::Nodes => {
            if let Some(super::nodes::NodesDialog::Form(draft)) = app.nodes.dialog.as_mut() {
                if index < draft.visible_fields() {
                    draft.focus = index;
                }
            }
        }
        _ => {}
    }
}

/// Pickers act on their captured option snapshots. A click selects/toggles an
/// option; destructive workflows still pass through their existing confirmation.
pub(super) fn choice(app: &mut App, index: usize) -> Option<KeyCode> {
    if super::filter_chips::click_choice(app, index) {
        return None;
    }
    if app.lists.import_source.is_some() {
        if index < 2 {
            app.lists.import_source = Some(index);
            app.lists.import_source_focus = 0;
        }
        return None;
    }
    if let Some(modal) = app.lists.catalog_picker.as_mut() {
        if index < modal.rows.len() {
            modal.table_state.select(Some(index));
            return Some(KeyCode::Char(' '));
        }
        return None;
    }
    if let Some(DeviceModal::Form(form)) = app.devices.modal.as_mut() {
        if let Some(picker) = form.picker.as_mut() {
            if index < picker.options.len() {
                picker.cursor = index;
                return Some(if picker.multi {
                    KeyCode::Char(' ')
                } else {
                    KeyCode::Enter
                });
            }
        }
        return None;
    }
    if let Some(modal) = app.query_log_rule_modal.as_mut() {
        if matches!(modal.stage, super::query_log_rule_modal::Stage::Picking)
            && index < modal.rows.len()
        {
            modal.cursor = index;
            modal.focus = 0;
            return Some(KeyCode::Char(' '));
        }
        return None;
    }
    if let Some(picker) = app.custom_lists.mount_picker.as_mut() {
        if index < picker.rows.len() {
            picker.cursor = index;
            return Some(KeyCode::Char(' '));
        }
        return None;
    }
    if let Some(modal) = app.settings.restore_modal.as_mut() {
        if let super::backup_restore_modal::RestoreStage::Picking { entries, selected } =
            &mut modal.stage
        {
            if index < entries.len() {
                *selected = index;
                return None;
            }
        }
    }
    if let Some(panel) = app.settings.tracking_panel.as_mut() {
        match index {
            0 => {
                panel.focus = TrackingFocus::Enabled;
                return Some(KeyCode::Char(' '));
            }
            1 => {
                panel.focus = TrackingFocus::Mode;
                return Some(KeyCode::Right);
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracking_pointer_choices_focus_and_apply_the_same_keyboard_action() {
        let config = crate::config::settings::TrackingConfig::default();
        let mut app = App::new();
        app.settings.tracking_panel =
            Some(super::super::app::TrackingPanelState::from_config(&config));

        assert_eq!(choice(&mut app, 0), Some(KeyCode::Char(' ')));
        assert_eq!(
            app.settings.tracking_panel.as_ref().unwrap().focus,
            TrackingFocus::Enabled
        );
        assert_eq!(choice(&mut app, 1), Some(KeyCode::Right));
        assert_eq!(
            app.settings.tracking_panel.as_ref().unwrap().focus,
            TrackingFocus::Mode
        );
    }
}
