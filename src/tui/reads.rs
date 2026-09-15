//! Event-loop side of background IPC reads. Only this side edits live UI data.
use super::jobs::{ReadCompletion, ReadReason, ReadRequest, ReadResource, ReadValue};
use super::{app, App, Leaf};

pub(super) fn active_requests(app: &App) -> Vec<ReadRequest> {
    match app.active_leaf {
        Leaf::Dashboard => vec![
            ReadRequest::Status,
            ReadRequest::Tracking,
            ReadRequest::Devices,
            ReadRequest::Blocklists,
        ],
        Leaf::Devices | Leaf::Subnets => vec![ReadRequest::Devices],
        Leaf::Lists => vec![ReadRequest::Blocklists],
        Leaf::LocalDns => vec![ReadRequest::LocalDnsHits],
        Leaf::QueryLog => vec![query_request(app), ReadRequest::OperatorCatalog],
        Leaf::Profiles => vec![ReadRequest::OperatorCatalog],
        Leaf::CustomLists => {
            let mut requests = vec![ReadRequest::OperatorCatalog];
            if let Some(rules) = operator_rules_request(app) {
                requests.push(rules);
            }
            if let Some(counts) = operator_rule_counts_request(app) {
                requests.push(counts);
            }
            requests
        }
        Leaf::Logs => vec![logs_request(app)],
        #[cfg(feature = "cluster")]
        Leaf::Nodes => vec![
            ReadRequest::NodesStatus,
            ReadRequest::NodeControlStatus,
            ReadRequest::ClusterStatus,
        ],
        _ => Vec::new(),
    }
}

pub(super) fn request_active(app: &mut App, reason: ReadReason) {
    if matches!(reason, ReadReason::Explicit) {
        app.custom_lists
            .counts
            .retain(|_, counts| matches!(counts, app::CustomListCounts::Ready { .. }));
    }
    let requests = active_requests(app);
    if let Some(jobs) = app.read_jobs.as_mut() {
        for request in requests {
            jobs.request(request, reason);
        }
    }
}

/// The client picker needs a device catalogue and the exact-IP capability,
/// but opening it is not a Query Log filter mutation. Keep this direct so a
/// paused operator cannot accidentally replace the page they were reading.
pub(super) fn request_query_log_picker_metadata(app: &mut App) {
    if let Some(jobs) = app.read_jobs.as_mut() {
        jobs.request(ReadRequest::Devices, ReadReason::Explicit);
        jobs.request(ReadRequest::Status, ReadReason::Explicit);
        jobs.request(ReadRequest::OperatorCatalog, ReadReason::Explicit);
    }
}

pub(super) fn request_heartbeat(app: &mut App, reason: ReadReason) {
    #[cfg(feature = "cluster")]
    let cluster = app.cluster_visible();
    if let Some(jobs) = app.read_jobs.as_mut() {
        jobs.request(ReadRequest::Status, reason);
        #[cfg(feature = "cluster")]
        jobs.request(ReadRequest::NodesStatus, reason);
        #[cfg(feature = "cluster")]
        jobs.request(ReadRequest::NodeControlStatus, reason);
        #[cfg(feature = "cluster")]
        if cluster {
            jobs.request(ReadRequest::ClusterStatus, reason);
        }
    }
}

pub(super) fn invalidate_all(app: &mut App) {
    if let Some(jobs) = app.read_jobs.as_mut() {
        for &resource in ReadResource::ALL {
            jobs.invalidate(resource);
        }
    }
}

pub(super) fn spawn_ready(app: &mut App) {
    let Some(tx) = app.job_tx.clone() else { return };
    if let Some(jobs) = app.read_jobs.as_mut() {
        if app.paused {
            jobs.pause_automatic();
        }
        for task in jobs.take_ready() {
            task.spawn(tx.clone(), app::UiJob::ReadFinished);
        }
    }
}

pub(super) fn apply(app: &mut App, completion: ReadCompletion) {
    let query = query_request(app);
    let logs = logs_request(app);
    let operator_rules = operator_rules_request(app);
    let operator_rule_counts = operator_rule_counts_request(app);
    let Some(reply) = app.read_jobs.as_mut().and_then(|jobs| {
        jobs.finish_if(completion, |request| match request.resource() {
            ReadResource::QueryLog => request.same_selection(&query),
            ReadResource::Logs => request.same_selection(&logs),
            ReadResource::OperatorRules => operator_rules
                .as_ref()
                .is_some_and(|current| request.same_selection(current)),
            ReadResource::OperatorRuleCounts => operator_rule_counts
                .as_ref()
                .is_some_and(|current| request.same_selection(current)),
            _ => true,
        })
    }) else {
        return;
    };
    match reply.result {
        Ok(ReadValue::Status(status)) => {
            app.daemon_status = Some(*status);
            app.connected = true;
            app.last_status_read = Some(std::time::Instant::now());
        }
        Ok(ReadValue::Tracking(data)) => {
            app.tracking = *data;
            app.last_tracking_read = Some(std::time::Instant::now());
            crate::tui::tabs::dashboard::observe_tracking(app);
        }
        Ok(ReadValue::Devices(view)) => {
            app.device_view = Some(*view);
            app.last_devices_read = Some(std::time::Instant::now());
        }
        Ok(ReadValue::Blocklists(stats)) => {
            app.lists.entries = stats;
            app.last_lists_read = Some(std::time::Instant::now());
        }
        Ok(ReadValue::QueryLog(page)) => super::apply_query_log_page(app, page),
        Ok(ReadValue::LocalDnsHits(entries)) => {
            app.local_dns.hits_snapshot = Some(
                entries
                    .into_iter()
                    .map(|e| (e.scope, e.domain, e.count))
                    .collect(),
            )
        }
        Ok(ReadValue::Logs(page)) => {
            app.logs.entries = page.entries;
            app.logs.dropped = page.dropped;
            app.logs.capacity = page.capacity;
            app.logs.fetch = app::LogsFetch::Ok;
        }
        Ok(ReadValue::OperatorCatalog(catalog)) => {
            let catalog = *catalog;
            app.custom_lists.counts.retain(|id, counts| {
                catalog
                    .lists
                    .iter()
                    .find(|list| &list.id == id)
                    .is_some_and(|list| count_matches_list(counts, list))
            });
            let selected = app
                .custom_lists
                .selected_id
                .as_ref()
                .filter(|id| catalog.lists.iter().any(|list| &list.id == *id))
                .cloned()
                .or_else(|| catalog.lists.first().map(|list| list.id.clone()));
            app.custom_lists.selected_id = selected;
            let rules_still_current = app.operator_rules.as_ref().is_some_and(|rules| {
                catalog.lists.iter().any(|list| {
                    list.id == rules.id
                        && list.config_revision == rules.config_revision
                        && list.pack_revision == rules.pack_revision
                })
            });
            if !rules_still_current {
                app.operator_rules = None;
                app.custom_lists.selected_row_ref = None;
            }
            app.operator_catalog = Some(catalog);
            app.operator_catalog_error = None;
            app.operator_rules_error = None;
            if app.active_leaf == Leaf::CustomLists {
                if let Some(request) = operator_rules_request(app) {
                    if let Some(jobs) = app.read_jobs.as_mut() {
                        jobs.request(request, ReadReason::Explicit);
                    }
                }
                if let Some(request) = operator_rule_counts_request(app) {
                    if let Some(jobs) = app.read_jobs.as_mut() {
                        jobs.request(request, ReadReason::Dependent);
                    }
                }
            }
        }
        Ok(ReadValue::OperatorRules(rules)) => {
            let selected = app
                .custom_lists
                .selected_row_ref
                .as_ref()
                .filter(|(id, row_ref)| {
                    id == &rules.id && rules.rows.iter().any(|row| &row.row_ref == row_ref)
                })
                .cloned()
                .or_else(|| {
                    rules
                        .rows
                        .first()
                        .map(|row| (rules.id.clone(), row.row_ref.clone()))
                });
            app.custom_lists.selected_row_ref = selected;
            app.operator_rules = Some(rules);
            app.operator_rules_error = None;
        }
        Ok(ReadValue::OperatorRuleCounts(counts)) => {
            merge_rule_counts(app, counts);
        }
        #[cfg(feature = "cluster")]
        Ok(ReadValue::ClusterStatus(status)) => app.apply_cluster_poll_result(Ok(*status)),
        #[cfg(feature = "cluster")]
        Ok(ReadValue::NodesStatus(status)) => app.apply_nodes_poll_result(Ok(*status)),
        #[cfg(feature = "cluster")]
        Ok(ReadValue::NodeControlStatus(status)) => app.apply_node_control_poll_result(Ok(*status)),
        Err(_error) => match reply.request.resource() {
            ReadResource::Status => app.connected = false,
            ReadResource::Tracking => app.tracking = Default::default(),
            ReadResource::Devices => app.device_view = None,
            ReadResource::Blocklists => app.lists.entries.clear(),
            ReadResource::QueryLog => {
                app.query_log.entries.clear();
                app.query_log.read_failed = true;
            }
            ReadResource::Logs => {
                app.logs.entries.clear();
                app.logs.fetch = app::LogsFetch::Failed;
            }
            ReadResource::LocalDnsHits => {}
            ReadResource::OperatorCatalog => {
                app.operator_catalog = None;
                app.operator_rules = None;
                app.custom_lists.selected_row_ref = None;
                app.operator_catalog_error = Some(_error);
            }
            ReadResource::OperatorRules => {
                app.operator_rules = None;
                app.custom_lists.selected_row_ref = None;
                app.operator_rules_error = Some(_error);
            }
            ReadResource::OperatorRuleCounts => {
                if let ReadRequest::OperatorRuleCounts { lists } = &reply.request {
                    cache_count_failures(app, lists, &_error);
                }
            }
            #[cfg(feature = "cluster")]
            ReadResource::ClusterStatus => app.apply_cluster_poll_result(Err(_error)),
            #[cfg(feature = "cluster")]
            ReadResource::NodesStatus => app.apply_nodes_poll_result(Err(_error)),
            #[cfg(feature = "cluster")]
            ReadResource::NodeControlStatus => app.apply_node_control_poll_result(Err(_error)),
        },
    }
    refresh_status(app);
}

fn query_request(app: &App) -> ReadRequest {
    ReadRequest::QueryLog {
        query: Box::new(crate::ipc::protocol::QueryLogRequest {
            limit: super::QUERY_LOG_PAGE_LIMIT,
            client: app.query_log.filter_client.clone(),
            blocked_only: app.query_log.blocked_only,
            domain: app.query_log.filter_domain.clone(),
            since_secs: app.query_log.since.as_secs(),
            cursor: app.query_log.current_cursor(),
            advanced: app.query_log.advanced_for_request(),
            client_ips: if app.query_log.client_mode == app::ClientFilterMode::Selected {
                app.query_log.client_ips.clone()
            } else {
                Vec::new()
            },
        }),
        page_index: app.query_log.page_index,
    }
}
fn logs_request(app: &App) -> ReadRequest {
    ReadRequest::Logs {
        limit: super::LOGS_PAGE_LIMIT,
        level: app.logs.level_filter.as_wire(),
        contains: app.logs.filter_text.clone(),
    }
}

fn operator_rules_request(app: &App) -> Option<ReadRequest> {
    let catalog = app.operator_catalog.as_ref()?;
    let id = app
        .custom_lists
        .selected_id
        .as_deref()
        .or_else(|| catalog.lists.first().map(|list| list.id.as_str()))?;
    let list = catalog.lists.iter().find(|list| list.id == id)?;
    Some(ReadRequest::OperatorRules {
        id: list.id.clone(),
        expected_config_revision: list.config_revision.clone(),
        expected_pack_revision: list.pack_revision.clone(),
    })
}

fn operator_rule_counts_request(app: &App) -> Option<ReadRequest> {
    let catalog = app.operator_catalog.as_ref()?;
    let mut lists = catalog
        .lists
        .iter()
        .filter(|list| {
            !app.custom_lists
                .counts
                .get(&list.id)
                .is_some_and(|counts| count_matches_list(counts, list))
        })
        .map(|list| {
            (
                list.id.clone(),
                list.config_revision.clone(),
                list.pack_revision.clone(),
            )
        })
        .collect::<Vec<_>>();
    lists.sort_unstable();
    (!lists.is_empty()).then_some(ReadRequest::OperatorRuleCounts { lists })
}

fn count_matches_list(
    counts: &app::CustomListCounts,
    list: &crate::operator_rules::ListDetail,
) -> bool {
    let (config_revision, pack_revision) = match counts {
        app::CustomListCounts::Ready {
            config_revision,
            pack_revision,
            ..
        }
        | app::CustomListCounts::Unavailable {
            config_revision,
            pack_revision,
            ..
        } => (config_revision, pack_revision),
    };
    config_revision == &list.config_revision && pack_revision == &list.pack_revision
}

fn cache_count_failures(app: &mut App, lists: &[(String, String, String)], error: &str) {
    let Some(catalog) = app.operator_catalog.as_ref() else {
        return;
    };
    for (id, config_revision, pack_revision) in lists {
        let current = catalog.lists.iter().any(|list| {
            list.id == *id
                && list.config_revision == *config_revision
                && list.pack_revision == *pack_revision
        });
        if current {
            app.custom_lists.counts.insert(
                id.clone(),
                app::CustomListCounts::Unavailable {
                    config_revision: config_revision.clone(),
                    pack_revision: pack_revision.clone(),
                    error: error.to_string(),
                },
            );
        }
    }
}

fn merge_rule_counts(app: &mut App, counts: Vec<super::operator_policy::PolicyRuleCounts>) {
    let Some(catalog) = app.operator_catalog.as_ref() else {
        return;
    };
    for count in counts {
        let current = catalog.lists.iter().any(|list| {
            list.id == count.id
                && list.config_revision == count.config_revision
                && list.pack_revision == count.pack_revision
        });
        if !current {
            continue;
        }
        let state = match count.result {
            Ok((allow, deny, skipped)) => app::CustomListCounts::Ready {
                config_revision: count.config_revision,
                pack_revision: count.pack_revision,
                allow,
                deny,
                skipped,
            },
            Err(error) => app::CustomListCounts::Unavailable {
                config_revision: count.config_revision,
                pack_revision: count.pack_revision,
                error,
            },
        };
        app.custom_lists.counts.insert(count.id, state);
    }
}

pub(super) fn refresh_status(app: &mut App) {
    let mut resources: Vec<_> = active_requests(app)
        .iter()
        .map(ReadRequest::resource)
        .collect();
    if !resources.contains(&ReadResource::Status) {
        resources.push(ReadResource::Status);
    }
    #[cfg(feature = "cluster")]
    if app.cluster_visible() {
        resources.push(ReadResource::ClusterStatus);
    }
    #[cfg(feature = "cluster")]
    if !resources.contains(&ReadResource::NodesStatus) {
        resources.push(ReadResource::NodesStatus);
    }
    #[cfg(feature = "cluster")]
    if !resources.contains(&ReadResource::NodeControlStatus) {
        resources.push(ReadResource::NodeControlStatus);
    }
    let error = app.read_jobs.as_ref().and_then(|jobs| {
        resources
            .into_iter()
            .find_map(|resource| jobs.error(resource).map(str::to_owned))
    });
    if app.last_status.as_ref().is_some_and(|status| {
        status.origin == app::StatusOrigin::Poll && Some(status.text.as_str()) == error.as_deref()
    }) {
        return;
    }
    app.clear_poll_status();
    if let Some(error) = error {
        app.status_err_poll(error);
    }
}

pub(super) fn flush_explicit(app: &mut App) -> bool {
    if !app.force_poll {
        return false;
    }
    app.force_poll = false;
    request_active(app, ReadReason::Explicit);
    true
}

pub(super) fn render_loading(frame: &mut ratatui::Frame, app: &App) {
    if !matches!(app.active_leaf, Leaf::QueryLog | Leaf::Logs) {
        return;
    }
    // This renders after the tab body. Query Log overlays own the footer for
    // their actions, so do not cover Apply, Cancel, or detail navigation.
    if app.active_leaf == Leaf::QueryLog && crate::tui::tabs::query_log::overlay_open(app) {
        return;
    }
    let loading = app.read_jobs.as_ref().is_some_and(|jobs| {
        active_requests(app)
            .iter()
            .any(|request| jobs.is_loading(request.resource()))
    });
    if loading && frame.area().height > 0 {
        let area = frame.area();
        let area = ratatui::layout::Rect::new(area.x, area.bottom() - 1, area.width, 1);
        frame.render_widget(ratatui::widgets::Clear, area);
        frame.render_widget(
            ratatui::widgets::Paragraph::new("Loading requested page…"),
            area,
        );
    }
}

#[cfg(test)]
mod rule_count_cache_tests {
    use super::*;
    use crate::operator_rules::{Capabilities, ListDetail, Metadata, TransportLimits};
    use crate::tui::operator_policy::{PolicyCatalog, PolicyRuleCounts};

    fn list(id: &str, pack_revision: &str) -> ListDetail {
        ListDetail {
            id: id.to_string(),
            display_name: id.to_string(),
            description: String::new(),
            config_revision: "config-r1".into(),
            pack_revision: pack_revision.into(),
            bytes: 0,
            rule_count: 0,
            invalid_rows: 0,
            profiles: Vec::new(),
        }
    }

    fn catalog(lists: Vec<ListDetail>) -> PolicyCatalog {
        PolicyCatalog {
            capabilities: Capabilities {
                contract_version: crate::operator_rules::CONTRACT_VERSION,
                schema_version: 5,
                operator_rule_grammar: 1,
                operations: Vec::new(),
                semantic_hash: true,
                activation_ack: true,
                cluster_artifact: false,
                limits: TransportLimits::IPC,
            },
            metadata: Metadata {
                contract_version: crate::operator_rules::CONTRACT_VERSION,
                schema_version: 5,
                config_revision: "config-r1".into(),
                desired_operator_policy_hash: String::new(),
                active_policy: None,
                activation_in_sync: true,
                lists: lists.len(),
                mounted_lists: 0,
                orphan_packs: 0,
            },
            lists,
            orphan_packs: Vec::new(),
        }
    }

    fn ready(pack_revision: &str, allow: usize) -> app::CustomListCounts {
        app::CustomListCounts::Ready {
            config_revision: "config-r1".into(),
            pack_revision: pack_revision.into(),
            allow,
            deny: 0,
            skipped: 0,
        }
    }

    fn unavailable(pack_revision: &str) -> app::CustomListCounts {
        app::CustomListCounts::Unavailable {
            config_revision: "config-r1".into(),
            pack_revision: pack_revision.into(),
            error: "unavailable".into(),
        }
    }

    fn requested_lists(app: &App) -> Vec<(String, String, String)> {
        match operator_rule_counts_request(app) {
            Some(ReadRequest::OperatorRuleCounts { lists }) => lists,
            None => Vec::new(),
            Some(other) => panic!("unexpected request: {other:?}"),
        }
    }

    #[test]
    fn matching_ready_and_unavailable_entries_are_not_refetched() {
        let mut app = App::new();
        app.operator_catalog = Some(catalog(vec![list("alpha", "a-r1"), list("beta", "b-r1")]));
        app.custom_lists
            .counts
            .insert("alpha".into(), ready("a-r1", 3));
        app.custom_lists
            .counts
            .insert("beta".into(), unavailable("b-r1"));

        assert!(operator_rule_counts_request(&app).is_none());
    }

    #[test]
    fn explicit_refresh_retries_failed_counts_without_refetching_valid_counts() {
        let mut app = App::new();
        app.active_leaf = Leaf::CustomLists;
        app.operator_catalog = Some(catalog(vec![list("alpha", "a-r1"), list("beta", "b-r1")]));
        app.custom_lists
            .counts
            .insert("alpha".into(), ready("a-r1", 3));
        app.custom_lists
            .counts
            .insert("beta".into(), unavailable("b-r1"));
        assert!(requested_lists(&app).is_empty());
        request_active(&mut app, ReadReason::Explicit);
        assert_eq!(
            requested_lists(&app),
            vec![("beta".into(), "config-r1".into(), "b-r1".into())]
        );
        merge_rule_counts(
            &mut app,
            vec![PolicyRuleCounts {
                id: "beta".into(),
                config_revision: "config-r1".into(),
                pack_revision: "b-r1".into(),
                result: Ok((2, 3, 4)),
            }],
        );
        assert!(requested_lists(&app).is_empty());
        assert_eq!(
            app.custom_lists.counts.get("alpha"),
            Some(&ready("a-r1", 3))
        );
        assert!(matches!(
            app.custom_lists.counts.get("beta"),
            Some(app::CustomListCounts::Ready {
                allow: 2,
                deny: 3,
                skipped: 4,
                ..
            })
        ));
    }

    #[test]
    fn revision_change_requests_only_the_invalidated_pack() {
        let mut app = App::new();
        app.operator_catalog = Some(catalog(vec![list("alpha", "a-r1"), list("beta", "b-r2")]));
        app.custom_lists
            .counts
            .insert("alpha".into(), ready("a-r1", 3));
        app.custom_lists
            .counts
            .insert("beta".into(), unavailable("b-r1"));

        assert_eq!(
            requested_lists(&app),
            vec![("beta".into(), "config-r1".into(), "b-r2".into())]
        );
    }

    #[test]
    fn metadata_revision_change_invalidates_the_old_count_tuple() {
        let mut current = list("alpha", "a-r1");
        current.config_revision = "config-r2".into();
        let mut current_catalog = catalog(vec![current]);
        current_catalog.metadata.config_revision = "config-r2".into();
        let mut app = App::new();
        app.operator_catalog = Some(current_catalog);
        app.custom_lists
            .counts
            .insert("alpha".into(), ready("a-r1", 3));

        assert_eq!(
            requested_lists(&app),
            vec![("alpha".into(), "config-r2".into(), "a-r1".into())]
        );
    }

    #[test]
    fn completion_merges_current_counts_and_ignores_stale_tuples() {
        let mut app = App::new();
        app.operator_catalog = Some(catalog(vec![list("alpha", "a-r1"), list("beta", "b-r2")]));
        app.custom_lists
            .counts
            .insert("alpha".into(), ready("a-r1", 3));

        merge_rule_counts(
            &mut app,
            vec![
                PolicyRuleCounts {
                    id: "beta".into(),
                    config_revision: "config-r1".into(),
                    pack_revision: "b-r1".into(),
                    result: Ok((99, 0, 0)),
                },
                PolicyRuleCounts {
                    id: "beta".into(),
                    config_revision: "config-r1".into(),
                    pack_revision: "b-r2".into(),
                    result: Ok((4, 5, 6)),
                },
            ],
        );

        assert_eq!(
            app.custom_lists.counts.get("alpha"),
            Some(&ready("a-r1", 3))
        );
        assert_eq!(
            app.custom_lists.counts.get("beta"),
            Some(&app::CustomListCounts::Ready {
                config_revision: "config-r1".into(),
                pack_revision: "b-r2".into(),
                allow: 4,
                deny: 5,
                skipped: 6,
            })
        );
    }

    #[test]
    fn transport_failure_only_marks_still_current_requested_entries() {
        let mut app = App::new();
        app.operator_catalog = Some(catalog(vec![list("alpha", "a-r1"), list("beta", "b-r2")]));
        app.custom_lists
            .counts
            .insert("alpha".into(), ready("a-r1", 3));

        cache_count_failures(
            &mut app,
            &[
                ("beta".into(), "config-r1".into(), "b-r1".into()),
                ("beta".into(), "config-r1".into(), "b-r2".into()),
            ],
            "transport unavailable",
        );

        assert_eq!(
            app.custom_lists.counts.get("alpha"),
            Some(&ready("a-r1", 3))
        );
        assert_eq!(
            app.custom_lists.counts.get("beta"),
            Some(&app::CustomListCounts::Unavailable {
                config_revision: "config-r1".into(),
                pack_revision: "b-r2".into(),
                error: "transport unavailable".into(),
            })
        );
    }
}

#[cfg(all(test, feature = "cluster"))]
mod cluster_poll_tests {
    use super::*;
    use crate::ipc::protocol::ClusterStatusDto;
    use crate::tui::ipc_poller::IpcPoller;
    use crate::tui::jobs::ReadScheduler;
    use std::path::Path;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    fn app() -> App {
        let mut app = App::new();
        app.read_jobs = Some(ReadScheduler::new(Arc::new(IpcPoller::new(Path::new(
            "unused.sock",
        )))));
        app
    }

    fn status(role: &str) -> ClusterStatusDto {
        ClusterStatusDto {
            enabled: true,
            role: role.to_string(),
            peer: Some("https://192.0.2.1:8443".to_string()),
            config_generation: 1,
            config_hash: "0123456789abcdef".to_string(),
            last_sync_secs: Some(12),
            last_poll_ok: true,
            last_error: None,
            converged: true,
            roster: Vec::new(),
        }
    }

    fn accept(app: &mut App, request: ReadRequest, result: Result<ReadValue, String>) {
        let jobs = app.read_jobs.as_mut().unwrap();
        jobs.request(request, ReadReason::Explicit);
        let completion = jobs.take_ready().pop().unwrap().complete_for_test(result);
        apply(app, completion);
    }

    #[test]
    fn failed_cluster_poll_invalidates_both_roles_while_daemon_remains_connected() {
        for role in ["primary", "secondary"] {
            let mut app = app();
            let previous = status(role);
            accept(
                &mut app,
                ReadRequest::Status,
                Ok(ReadValue::Status(Box::default())),
            );
            accept(
                &mut app,
                ReadRequest::ClusterStatus,
                Ok(ReadValue::ClusterStatus(Box::new(previous.clone()))),
            );
            let observed = Instant::now() - Duration::from_secs(372);
            app.cluster.last_observed_at = Some(observed);

            accept(
                &mut app,
                ReadRequest::ClusterStatus,
                Err("cluster IPC timeout".to_string()),
            );
            assert!(app.connected);
            assert!(app.cluster_status.is_none());
            assert_eq!(app.cluster.last_observation.as_ref(), Some(&previous));
            assert_eq!(app.cluster.last_observed_at, Some(observed));

            accept(
                &mut app,
                ReadRequest::ClusterStatus,
                Err("cluster IPC still unavailable".to_string()),
            );
            assert_eq!(app.cluster.last_observation.as_ref(), Some(&previous));
            assert_eq!(app.cluster.last_observed_at, Some(observed));

            let mut recovered = status(role);
            recovered.config_hash = "fedcba9876543210".to_string();
            accept(
                &mut app,
                ReadRequest::ClusterStatus,
                Ok(ReadValue::ClusterStatus(Box::new(recovered.clone()))),
            );
            assert_eq!(app.cluster_status.as_ref(), Some(&recovered));
            assert!(app.cluster.last_observation.is_none());
            assert!(app.cluster.last_poll_error.is_none());
            assert!(app.cluster.last_observed_at.unwrap() > observed);
        }
    }

    #[test]
    fn first_cluster_poll_failure_reports_unknown_without_inventing_an_observation() {
        let mut app = app();
        accept(
            &mut app,
            ReadRequest::ClusterStatus,
            Err("cluster response rejected".to_string()),
        );
        assert!(app.cluster_status.is_none());
        assert!(app.cluster.last_observation.is_none());
        assert!(app.cluster.last_observed_at.is_none());
        assert_eq!(
            app.cluster.last_poll_error.as_deref(),
            Some("cluster response rejected")
        );
    }

    #[test]
    fn rejected_old_cluster_failure_does_not_invalidate_current_observation() {
        let mut app = app();
        let current = status("secondary");
        accept(
            &mut app,
            ReadRequest::ClusterStatus,
            Ok(ReadValue::ClusterStatus(Box::new(current.clone()))),
        );
        let observed = app.cluster.last_observed_at;
        let jobs = app.read_jobs.as_mut().unwrap();
        jobs.request(ReadRequest::ClusterStatus, ReadReason::Explicit);
        let old = jobs.take_ready().pop().unwrap();
        jobs.request(ReadRequest::ClusterStatus, ReadReason::Explicit);
        apply(
            &mut app,
            old.complete_for_test(Err("obsolete failure".to_string())),
        );
        assert_eq!(app.cluster_status.as_ref(), Some(&current));
        assert_eq!(app.cluster.last_observed_at, observed);
        assert!(app.cluster.last_poll_error.is_none());
        assert!(app.cluster.last_observation.is_none());
    }
}
