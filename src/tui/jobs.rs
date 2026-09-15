//! Bounded background reads for the TUI event loop.
//!
//! Integration contract:
//! - Keep one `ReadScheduler` for the lifetime of the UI (and thus one poller).
//! - Request reads synchronously when filters/pages change, including while
//!   paused. `invalidate` immediately rejects old replies when no replacement
//!   request can be built yet (for example, after a configuration mutation).
//! - Spawn `take_ready()` tasks through the existing UiJob sender. A slot stays
//!   occupied until `finish`, even when its result is already in the channel.
//! - Apply only `finish`'s accepted reply, synchronously on the event-loop task.
//!   Reconcile any changed cursor/filter before requesting another page.
//! - Never use these discardable reads for mutations or their outcomes.

use std::sync::Arc;

use crate::ipc::protocol::{DeviceViewDto, LocalRecordsHitEntry, QueryLogRequest};
use crate::lists::status::BlocklistStatusDto;
use crate::tracking::log_ring::LogLevel;

use super::app::{DaemonStatus, TrackingData};
use super::ipc_poller::{DaemonLogPage, IpcPoller, QueryLogPollResult};

/// Resources, rather than leaves: Dashboard and heartbeat share Status;
/// Dashboard, Devices and Subnets share Devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadResource {
    Status,
    Tracking,
    Devices,
    Blocklists,
    QueryLog,
    LocalDnsHits,
    Logs,
    OperatorCatalog,
    OperatorRules,
    OperatorRuleCounts,
    #[cfg(feature = "cluster")]
    ClusterStatus,
    #[cfg(feature = "cluster")]
    NodesStatus,
    #[cfg(feature = "cluster")]
    NodeControlStatus,
}

impl ReadResource {
    pub(crate) const ALL: &'static [Self] = &[
        Self::Status,
        Self::Tracking,
        Self::Devices,
        Self::Blocklists,
        Self::QueryLog,
        Self::LocalDnsHits,
        Self::Logs,
        Self::OperatorCatalog,
        Self::OperatorRules,
        Self::OperatorRuleCounts,
        #[cfg(feature = "cluster")]
        Self::ClusterStatus,
        #[cfg(feature = "cluster")]
        Self::NodesStatus,
        #[cfg(feature = "cluster")]
        Self::NodeControlStatus,
    ];

    fn index(self) -> usize {
        self as usize
    }
}

/// Everything determining the returned rows is captured before spawning.
#[derive(Debug, Clone)]
pub(crate) enum ReadRequest {
    Status,
    Tracking,
    Devices,
    Blocklists,
    QueryLog {
        query: Box<QueryLogRequest>,
        /// UI identity in addition to the wire cursor, including page zero.
        page_index: usize,
    },
    LocalDnsHits,
    Logs {
        limit: usize,
        level: Option<LogLevel>,
        contains: Option<String>,
    },
    OperatorCatalog,
    OperatorRules {
        id: String,
        expected_config_revision: String,
        expected_pack_revision: String,
    },
    OperatorRuleCounts {
        /// `(id, config revision, pack revision)` captured from one complete
        /// inventory snapshot.
        lists: Vec<(String, String, String)>,
    },
    #[cfg(feature = "cluster")]
    ClusterStatus,
    #[cfg(feature = "cluster")]
    NodesStatus,
    #[cfg(feature = "cluster")]
    NodeControlStatus,
}

impl ReadRequest {
    pub(crate) fn resource(&self) -> ReadResource {
        match self {
            Self::Status => ReadResource::Status,
            Self::Tracking => ReadResource::Tracking,
            Self::Devices => ReadResource::Devices,
            Self::Blocklists => ReadResource::Blocklists,
            Self::QueryLog { .. } => ReadResource::QueryLog,
            Self::LocalDnsHits => ReadResource::LocalDnsHits,
            Self::Logs { .. } => ReadResource::Logs,
            Self::OperatorCatalog => ReadResource::OperatorCatalog,
            Self::OperatorRules { .. } => ReadResource::OperatorRules,
            Self::OperatorRuleCounts { .. } => ReadResource::OperatorRuleCounts,
            #[cfg(feature = "cluster")]
            Self::ClusterStatus => ReadResource::ClusterStatus,
            #[cfg(feature = "cluster")]
            Self::NodesStatus => ReadResource::NodesStatus,
            #[cfg(feature = "cluster")]
            Self::NodeControlStatus => ReadResource::NodeControlStatus,
        }
    }

    pub(crate) fn same_selection(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::QueryLog {
                    query: a,
                    page_index: ap,
                },
                Self::QueryLog {
                    query: b,
                    page_index: bp,
                },
            ) => {
                // QueryLogRequest has no PartialEq. Destructure exhaustively
                // so adding a wire filter requires extending this comparison.
                let QueryLogRequest {
                    limit,
                    client,
                    client_ips,
                    blocked_only,
                    domain,
                    since_secs,
                    cursor,
                    advanced,
                } = a.as_ref();
                ap == bp
                    && *limit == b.limit
                    && *client == b.client
                    && *client_ips == b.client_ips
                    && *blocked_only == b.blocked_only
                    && *domain == b.domain
                    && *since_secs == b.since_secs
                    && *cursor == b.cursor
                    && *advanced == b.advanced
            }
            (
                Self::Logs {
                    limit: al,
                    level: av,
                    contains: ac,
                },
                Self::Logs {
                    limit: bl,
                    level: bv,
                    contains: bc,
                },
            ) => al == bl && av == bv && ac == bc,
            (
                Self::OperatorRules {
                    id: ai,
                    expected_config_revision: ac,
                    expected_pack_revision: ap,
                },
                Self::OperatorRules {
                    id: bi,
                    expected_config_revision: bc,
                    expected_pack_revision: bp,
                },
            ) => ai == bi && ac == bc && ap == bp,
            (Self::OperatorRuleCounts { lists: a }, Self::OperatorRuleCounts { lists: b }) => {
                a == b
            }
            _ => self.resource() == other.resource(),
        }
    }

    async fn execute(self, poller: &IpcPoller) -> Result<ReadValue, String> {
        let result = match self {
            Self::Status => poller
                .fetch_status()
                .await
                .map(Box::new)
                .map(ReadValue::Status),
            Self::Tracking => poller
                .fetch_tracking_stats()
                .await
                .map(Box::new)
                .map(ReadValue::Tracking),
            Self::Devices => poller
                .fetch_device_view()
                .await
                .map(Box::new)
                .map(ReadValue::Devices),
            Self::Blocklists => poller
                .fetch_blocklist_stats()
                .await
                .map(ReadValue::Blocklists),
            Self::QueryLog { query, .. } => poller
                .fetch_query_logs(*query)
                .await
                .map(ReadValue::QueryLog),
            Self::LocalDnsHits => poller
                .fetch_local_records_hits()
                .await
                .map(ReadValue::LocalDnsHits),
            Self::Logs {
                limit,
                level,
                contains,
            } => poller
                .fetch_daemon_logs(limit, level, contains)
                .await
                .map(ReadValue::Logs),
            Self::OperatorCatalog => {
                return super::operator_policy::read_catalog(poller.socket_path().to_owned())
                    .await
                    .map(Box::new)
                    .map(ReadValue::OperatorCatalog)
                    .map_err(|error| error.to_string());
            }
            Self::OperatorRules {
                id,
                expected_config_revision,
                expected_pack_revision,
            } => {
                return super::operator_policy::read_rules(
                    poller.socket_path().to_owned(),
                    id,
                    expected_config_revision,
                    expected_pack_revision,
                )
                .await
                .map(ReadValue::OperatorRules)
                .map_err(|error| error.to_string());
            }
            Self::OperatorRuleCounts { lists } => {
                return super::operator_policy::read_rule_counts(
                    poller.socket_path().to_owned(),
                    lists,
                )
                .await
                .map(ReadValue::OperatorRuleCounts)
                .map_err(|error| error.to_string());
            }
            #[cfg(feature = "cluster")]
            Self::ClusterStatus => poller
                .fetch_cluster_status()
                .await
                .map(Box::new)
                .map(ReadValue::ClusterStatus),
            #[cfg(feature = "cluster")]
            Self::NodesStatus => poller
                .fetch_nodes_status()
                .await
                .map(Box::new)
                .map(ReadValue::NodesStatus),
            #[cfg(feature = "cluster")]
            Self::NodeControlStatus => poller
                .fetch_node_control_status()
                .await
                .map(Box::new)
                .map(ReadValue::NodeControlStatus),
        };
        result.map_err(|error| error.to_string())
    }
}

#[derive(Debug)]
pub(crate) enum ReadValue {
    Status(Box<DaemonStatus>),
    Tracking(Box<TrackingData>),
    Devices(Box<DeviceViewDto>),
    Blocklists(Vec<BlocklistStatusDto>),
    QueryLog(QueryLogPollResult),
    LocalDnsHits(Vec<LocalRecordsHitEntry>),
    Logs(DaemonLogPage),
    OperatorCatalog(Box<super::operator_policy::PolicyCatalog>),
    OperatorRules(super::operator_policy::PolicyRules),
    OperatorRuleCounts(Vec<super::operator_policy::PolicyRuleCounts>),
    #[cfg(feature = "cluster")]
    ClusterStatus(Box<crate::ipc::protocol::ClusterStatusDto>),
    #[cfg(feature = "cluster")]
    NodesStatus(Box<crate::cluster::lifecycle::LifecycleStatus>),
    #[cfg(feature = "cluster")]
    NodeControlStatus(Box<crate::cluster::node_control::NodeControlStatus>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadReason {
    /// A cadence tick: never invalidates an identical in-flight request.
    Automatic,
    /// Follow-up work discovered by an accepted parent read. It must not
    /// supersede an identical in-flight request and remains eligible after
    /// that parent completed, including while the UI is paused.
    Dependent,
    /// A committed filter, page, tab entry or manual refresh. Survives pause
    /// and supersedes even a running read for the same selection.
    Explicit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReadTicket {
    pub(crate) resource: ReadResource,
    pub(crate) generation: u64,
    id: u64,
}

/// Opaque until the scheduler validates it; callers cannot accidentally apply
/// a stale error via a separate error-handling path.
#[derive(Debug)]
pub struct ReadCompletion {
    ticket: ReadTicket,
    request: ReadRequest,
    result: Result<ReadValue, String>,
}

#[derive(Debug)]
pub(crate) struct AcceptedRead {
    #[cfg(test)]
    pub(crate) ticket: ReadTicket,
    pub(crate) request: ReadRequest,
    pub(crate) result: Result<ReadValue, String>,
}

#[derive(Default)]
struct ReadSlot {
    generation: u64,
    desired: Option<ReadRequest>,
    pending: Option<ReadReason>,
    in_flight: Option<ReadTicket>,
    error: Option<String>,
}

pub(crate) struct ReadScheduler {
    poller: Arc<IpcPoller>,
    slots: [ReadSlot; ReadResource::ALL.len()],
    next_id: u64,
}

impl ReadScheduler {
    pub(crate) fn new(poller: Arc<IpcPoller>) -> Self {
        Self {
            poller,
            slots: std::array::from_fn(|_| ReadSlot::default()),
            next_id: 0,
        }
    }

    /// Request immediately on a semantic change, not on the following Tick:
    /// a completion may be selected before that Tick arrives.
    pub(crate) fn request(&mut self, request: ReadRequest, reason: ReadReason) {
        let slot = &mut self.slots[request.resource().index()];
        let changed = slot
            .desired
            .as_ref()
            .is_none_or(|old| !old.same_selection(&request));
        if changed || reason == ReadReason::Explicit {
            slot.generation = slot
                .generation
                .checked_add(1)
                .expect("read generation exhausted");
        } else if slot.in_flight.is_some() && slot.pending.is_none() {
            // Do not queue a trailing automatic refresh on every tick of a
            // slow request. This also avoids queuing an obsolete query cursor
            // before the accepted page has reconciled the UI's cursor stack.
            return;
        }
        slot.desired = Some(request);
        // Automatic ticks cannot downgrade a pending explicit fetch; pausing
        // must still leave that explicit request scheduled.
        slot.pending = Some(match (slot.pending, reason) {
            (Some(ReadReason::Explicit), _) | (_, ReadReason::Explicit) => ReadReason::Explicit,
            (Some(ReadReason::Dependent), _) | (_, ReadReason::Dependent) => ReadReason::Dependent,
            _ => ReadReason::Automatic,
        });
    }

    /// Reject running replies and remove queued work. Does not free a running
    /// slot: letting a replacement start now would exceed the IPC bound.
    pub(crate) fn invalidate(&mut self, resource: ReadResource) {
        let slot = &mut self.slots[resource.index()];
        slot.generation = slot
            .generation
            .checked_add(1)
            .expect("read generation exhausted");
        slot.desired = None;
        slot.pending = None;
    }

    /// Pause prevents automatic starts, rather than cancelling a read already
    /// sent to the daemon. Explicit pending requests remain eligible.
    pub(crate) fn pause_automatic(&mut self) {
        for slot in &mut self.slots {
            if slot.pending == Some(ReadReason::Automatic) {
                slot.pending = None;
            }
        }
    }

    pub(crate) fn is_loading(&self, resource: ReadResource) -> bool {
        let slot = &self.slots[resource.index()];
        slot.pending.is_some()
            || slot
                .in_flight
                .is_some_and(|ticket| ticket.generation == slot.generation)
    }

    pub(crate) fn error(&self, resource: ReadResource) -> Option<&str> {
        self.slots[resource.index()].error.as_deref()
    }

    /// At most one task per resource; callers must spawn every returned task.
    /// Keep timer deadlines in the event loop, not inside these workers.
    pub(crate) fn take_ready(&mut self) -> Vec<ReadTask> {
        let mut ready = Vec::new();
        for &resource in ReadResource::ALL {
            let slot = &mut self.slots[resource.index()];
            if slot.in_flight.is_some() || slot.pending.is_none() {
                continue;
            }
            let Some(request) = slot.desired.clone() else {
                continue;
            };
            self.next_id = self
                .next_id
                .checked_add(1)
                .expect("read request ID exhausted");
            let ticket = ReadTicket {
                resource,
                generation: slot.generation,
                id: self.next_id,
            };
            slot.pending = None;
            slot.in_flight = Some(ticket);
            ready.push(ReadTask {
                poller: Arc::clone(&self.poller),
                ticket,
                request,
            });
        }
        ready
    }

    /// Releases exactly the completing task's slot. A duplicate/foreign
    /// completion cannot release a newer task. Validate before exposing either
    /// Ok or Err; stale errors must not clear current rows or connection state.
    #[cfg(test)]
    pub(crate) fn finish(&mut self, completion: ReadCompletion) -> Option<AcceptedRead> {
        self.finish_if(completion, |_| true)
    }

    pub(crate) fn finish_if(
        &mut self,
        completion: ReadCompletion,
        accept: impl FnOnce(&ReadRequest) -> bool,
    ) -> Option<AcceptedRead> {
        let slot = &mut self.slots[completion.ticket.resource.index()];
        if slot.in_flight != Some(completion.ticket) {
            return None;
        }
        slot.in_flight = None;
        if completion.ticket.generation != slot.generation || !accept(&completion.request) {
            return None;
        }
        slot.error = completion.result.as_ref().err().cloned();
        Some(AcceptedRead {
            #[cfg(test)]
            ticket: completion.ticket,
            request: completion.request,
            result: completion.result,
        })
    }
}

/// Owned worker input. No App reference, UI lock or full-state snapshot crosses
/// the task boundary. Cloning the Arc preserves the tracking-rate baseline.
#[must_use = "spawn the returned read task so its scheduler slot can complete"]
pub(crate) struct ReadTask {
    poller: Arc<IpcPoller>,
    ticket: ReadTicket,
    request: ReadRequest,
}

impl ReadTask {
    #[cfg(test)]
    pub(crate) fn resource(&self) -> ReadResource {
        self.ticket.resource
    }

    #[cfg(test)]
    pub(crate) fn complete_for_test(self, result: Result<ReadValue, String>) -> ReadCompletion {
        ReadCompletion {
            ticket: self.ticket,
            request: self.request,
            result,
        }
    }
    /// `wrap` is normally `UiJob::ReadFinished`. Supervise the fetch so a panic
    /// becomes a completion and cannot permanently occupy a resource slot.
    /// There are at most ALL.len() fetches plus ALL.len() small supervisors.
    pub(crate) fn spawn<J: Send + 'static>(
        self,
        tx: tokio::sync::mpsc::UnboundedSender<J>,
        wrap: fn(ReadCompletion) -> J,
    ) -> tokio::task::JoinHandle<()> {
        let request = self.request.clone();
        let poller = self.poller;
        let worker = tokio::spawn(async move { request.execute(&poller).await });
        tokio::spawn(async move {
            let result = match worker.await {
                Ok(result) => result,
                Err(error) => Err(format!("background read failed: {error}")),
            };
            let _ = tx.send(wrap(ReadCompletion {
                ticket: self.ticket,
                request: self.request,
                result,
            }));
        })
    }
}

#[cfg(test)]
#[path = "tests/background_jobs_tests.rs"]
mod tests;
