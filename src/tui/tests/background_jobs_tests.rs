use super::*;

fn scheduler() -> ReadScheduler {
    // Pure scheduler tests never start these tasks or contact this path.
    ReadScheduler::new(Arc::new(IpcPoller::new(std::path::Path::new(
        "unused.sock",
    ))))
}

fn query(domain: &str) -> ReadRequest {
    ReadRequest::QueryLog {
        query: Box::new(QueryLogRequest {
            limit: 100,
            domain: Some(domain.into()),
            ..Default::default()
        }),
        page_index: 0,
    }
}

fn complete(task: ReadTask, result: Result<ReadValue, String>) -> ReadCompletion {
    ReadCompletion {
        ticket: task.ticket,
        request: task.request,
        result,
    }
}

fn empty_page() -> ReadValue {
    ReadValue::QueryLog(QueryLogPollResult {
        entries: Vec::new(),
        logging_enabled: true,
        file_state: crate::ipc::protocol::QueryLogFileState::Ok,
        next_cursor: None,
        cursor_stale: false,
    })
}

fn all_requests() -> Vec<ReadRequest> {
    vec![
        ReadRequest::Status,
        ReadRequest::Tracking,
        ReadRequest::Devices,
        ReadRequest::Blocklists,
        query("example.test"),
        ReadRequest::LocalDnsHits,
        ReadRequest::Logs {
            limit: 100,
            level: None,
            contains: None,
        },
        ReadRequest::OperatorCatalog,
        ReadRequest::OperatorRuleCounts {
            lists: vec![("local".into(), "config-r1".into(), "pack-r1".into())],
        },
        ReadRequest::OperatorRules {
            id: "local".into(),
            expected_config_revision: "config-r1".into(),
            expected_pack_revision: "pack-r1".into(),
        },
        #[cfg(feature = "cluster")]
        ReadRequest::ClusterStatus,
        #[cfg(feature = "cluster")]
        ReadRequest::NodesStatus,
        #[cfg(feature = "cluster")]
        ReadRequest::NodeControlStatus,
    ]
}

#[test]
fn resource_bound_holds_while_responses_are_withheld() {
    let mut jobs = scheduler();
    for request in all_requests() {
        jobs.request(request, ReadReason::Automatic);
    }
    let running = jobs.take_ready();
    assert_eq!(running.len(), ReadResource::ALL.len());
    for _ in 0..100 {
        for request in all_requests() {
            jobs.request(request, ReadReason::Explicit);
        }
        assert!(jobs.take_ready().is_empty());
    }
    for task in running {
        assert!(jobs
            .finish(complete(task, Err("old response".into())))
            .is_none());
    }
    assert_eq!(jobs.take_ready().len(), ReadResource::ALL.len());
    assert!(jobs.take_ready().is_empty());
}

#[test]
fn stale_success_and_error_are_both_rejected_and_latest_selection_runs() {
    for old_result in [Ok(empty_page()), Err("old failure".into())] {
        let mut jobs = scheduler();
        jobs.request(query("first.test"), ReadReason::Explicit);
        let first = jobs.take_ready().pop().unwrap();
        jobs.request(query("second.test"), ReadReason::Explicit);
        jobs.request(query("latest.test"), ReadReason::Explicit);
        assert!(jobs.take_ready().is_empty());
        assert!(jobs.finish(complete(first, old_result)).is_none());
        let latest = jobs.take_ready().pop().unwrap();
        assert!(latest.request.same_selection(&query("latest.test")));
        let accepted = jobs.finish(complete(latest, Ok(empty_page()))).unwrap();
        assert!(accepted.result.is_ok());
        assert!(accepted.request.same_selection(&query("latest.test")));
        assert!(!jobs.is_loading(ReadResource::QueryLog));
    }
}

#[test]
fn returning_to_same_filter_does_not_accept_the_first_visit() {
    let mut jobs = scheduler();
    jobs.request(query("a.test"), ReadReason::Automatic);
    let old = jobs.take_ready().pop().unwrap();
    jobs.request(query("b.test"), ReadReason::Automatic);
    jobs.request(query("a.test"), ReadReason::Automatic);
    assert!(jobs.finish(complete(old, Ok(empty_page()))).is_none());
    assert_eq!(jobs.take_ready().len(), 1);
}

#[test]
fn ticks_neither_starve_a_running_read_nor_queue_an_old_cursor() {
    let mut jobs = scheduler();
    jobs.request(query("a.test"), ReadReason::Automatic);
    let task = jobs.take_ready().pop().unwrap();
    let generation = task.ticket.generation;
    for _ in 0..100 {
        jobs.request(query("a.test"), ReadReason::Automatic);
        assert!(jobs.take_ready().is_empty());
    }
    let accepted = jobs.finish(complete(task, Ok(empty_page()))).unwrap();
    assert_eq!(accepted.ticket.generation, generation);
    assert!(jobs.take_ready().is_empty());
    // The next cadence request uses the cursor AFTER application of this page.
    jobs.request(query("a.test"), ReadReason::Automatic);
    assert_eq!(jobs.take_ready().len(), 1);
}

#[test]
fn pause_removes_automatic_pending_work_but_preserves_explicit_work() {
    let mut jobs = scheduler();
    jobs.request(ReadRequest::Status, ReadReason::Automatic);
    jobs.request(query("a.test"), ReadReason::Explicit);
    jobs.request(query("a.test"), ReadReason::Automatic);
    jobs.pause_automatic();
    let tasks = jobs.take_ready();
    assert_eq!(tasks.len(), 1);
    assert_eq!(tasks[0].ticket.resource, ReadResource::QueryLog);
}

#[test]
fn explicit_refresh_of_same_selection_invalidates_a_queued_completion() {
    let mut jobs = scheduler();
    jobs.request(ReadRequest::Status, ReadReason::Automatic);
    let task = jobs.take_ready().pop().unwrap();
    let reply = complete(task, Ok(ReadValue::Status(Box::default())));
    // Fetch finished, but the UI has not consumed its UiJob yet.
    jobs.request(ReadRequest::Status, ReadReason::Explicit);
    assert!(jobs.take_ready().is_empty());
    assert!(jobs.finish(reply).is_none());
    assert_eq!(jobs.take_ready().len(), 1);
}

#[test]
fn mutation_invalidation_does_not_free_running_slots_or_apply_old_errors() {
    let mut jobs = scheduler();
    jobs.request(ReadRequest::Devices, ReadReason::Automatic);
    let old = jobs.take_ready().pop().unwrap();
    jobs.invalidate(ReadResource::Devices);
    assert!(!jobs.is_loading(ReadResource::Devices));
    jobs.request(ReadRequest::Devices, ReadReason::Explicit);
    assert!(jobs.is_loading(ReadResource::Devices));
    assert!(jobs.take_ready().is_empty());
    assert!(jobs
        .finish(complete(old, Err("before save".into())))
        .is_none());
    let fresh = jobs.take_ready().pop().unwrap();
    let accepted = jobs
        .finish(complete(fresh, Err("current failure".into())))
        .unwrap();
    assert_eq!(accepted.result.unwrap_err(), "current failure");
}

#[test]
fn duplicate_completion_cannot_release_a_newer_request() {
    let mut jobs = scheduler();
    jobs.request(ReadRequest::Status, ReadReason::Automatic);
    let old = jobs.take_ready().pop().unwrap();
    let duplicate = ReadCompletion {
        ticket: old.ticket,
        request: old.request.clone(),
        result: Err("duplicate".into()),
    };
    assert!(jobs.finish(complete(old, Err("first".into()))).is_some());
    jobs.request(ReadRequest::Status, ReadReason::Automatic);
    let fresh = jobs.take_ready().pop().unwrap();
    assert!(jobs.finish(duplicate).is_none());
    assert!(jobs.is_loading(ReadResource::Status));
    assert!(jobs.finish(complete(fresh, Err("second".into()))).is_some());
}

#[test]
fn all_query_dimensions_invalidate_even_if_mistakenly_requested_as_automatic() {
    let changes: Vec<ReadRequest> = (0..8)
        .map(|dimension| {
            let mut request = query("a.test");
            let ReadRequest::QueryLog { query, page_index } = &mut request else {
                unreachable!()
            };
            match dimension {
                0 => query.limit += 1,
                1 => query.client = Some("192.0.2.1".into()),
                2 => query.blocked_only = true,
                3 => query.domain = Some("b.test".into()),
                4 => query.since_secs = Some(60),
                5 => {
                    query.cursor = Some(crate::tracking::query_log::QueryLogCursor {
                        file: "query.log".into(),
                        offset: 42,
                        inode: 1,
                    })
                }
                6 => {
                    query.advanced = Some(crate::ipc::protocol::AdvancedClientFilterDto {
                        name: Some("laptop*".into()),
                        ..Default::default()
                    })
                }
                7 => *page_index = 1,
                _ => unreachable!(),
            }
            request
        })
        .collect();
    for changed in changes {
        let mut jobs = scheduler();
        jobs.request(query("a.test"), ReadReason::Automatic);
        let old = jobs.take_ready().pop().unwrap();
        jobs.request(changed, ReadReason::Automatic);
        assert!(jobs.finish(complete(old, Ok(empty_page()))).is_none());
        assert_eq!(jobs.take_ready().len(), 1);
    }
}

#[test]
fn log_filters_are_part_of_request_identity() {
    let original = ReadRequest::Logs {
        limit: 100,
        level: None,
        contains: None,
    };
    let changes = [
        ReadRequest::Logs {
            limit: 50,
            level: None,
            contains: None,
        },
        ReadRequest::Logs {
            limit: 100,
            level: Some(LogLevel::Error),
            contains: None,
        },
        ReadRequest::Logs {
            limit: 100,
            level: None,
            contains: Some("resolver".into()),
        },
    ];
    for changed in changes {
        let mut jobs = scheduler();
        jobs.request(original.clone(), ReadReason::Automatic);
        let old = jobs.take_ready().pop().unwrap();
        jobs.request(changed, ReadReason::Automatic);
        assert!(jobs
            .finish(complete(old, Err("old log error".into())))
            .is_none());
    }
}

#[test]
fn tasks_share_the_persistent_poller_across_resources_and_rounds() {
    let mut jobs = scheduler();
    for request in all_requests() {
        jobs.request(request, ReadReason::Automatic);
    }
    for task in jobs.take_ready() {
        assert!(Arc::ptr_eq(&jobs.poller, &task.poller));
        assert!(jobs
            .finish(complete(task, Err("synthetic reply".into())))
            .is_some());
    }
    jobs.request(ReadRequest::Tracking, ReadReason::Automatic);
    let next = jobs.take_ready().pop().unwrap();
    assert!(Arc::ptr_eq(&jobs.poller, &next.poller));
}

#[tokio::test]
async fn withheld_socket_reply_leaves_the_caller_free_and_uses_completion_channel() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::time::{timeout, Duration};

    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("mock.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let mut jobs = ReadScheduler::new(Arc::new(IpcPoller::new(&socket)));
    jobs.request(ReadRequest::Status, ReadReason::Automatic);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let worker = jobs
        .take_ready()
        .pop()
        .unwrap()
        .spawn(tx, std::convert::identity);
    let (stream, _) = timeout(Duration::from_secs(1), listener.accept())
        .await
        .unwrap()
        .unwrap();
    let mut stream = BufReader::new(stream);
    let mut command = String::new();
    timeout(Duration::from_secs(1), stream.read_line(&mut command))
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        serde_json::from_str::<crate::ipc::protocol::IpcCommand>(&command).unwrap(),
        crate::ipc::protocol::IpcCommand::Status
    ));
    // Peer has the request and withholds its response. The caller still owns
    // the scheduler and can process invalidation/other resources immediately.
    assert!(rx.try_recv().is_err());
    jobs.invalidate(ReadResource::Status);
    jobs.request(ReadRequest::Devices, ReadReason::Explicit);
    let other = jobs.take_ready().pop().unwrap();
    assert_eq!(other.ticket.resource, ReadResource::Devices);
    assert!(jobs
        .finish(complete(
            other,
            Err("synthetic unrelated completion".into()),
        ))
        .is_some());

    let response = serde_json::to_string(&crate::ipc::protocol::IpcResponse::Error {
        message: "released fixture".into(),
    })
    .unwrap()
        + "\n";
    stream
        .get_mut()
        .write_all(response.as_bytes())
        .await
        .unwrap();
    let completion = timeout(Duration::from_secs(1), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(
        jobs.finish(completion).is_none(),
        "invalidated IPC error is stale"
    );
    worker.await.unwrap();
}
