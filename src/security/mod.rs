//! Per-query security gates: rate limiting, response rate limiting,
//! tunneling detection, query-shape validation, anti-bypass.
//!
//! Hot path — every gate here runs per packet. Nothing in this module takes
//! an `RwLock` or `Mutex`: shared counters are atomics, and the per-source
//! trackers hold only the sharded map locks their reads and inserts need.
//!
//! These gates decide one thing: whether to REFUSE a query outright. They do
//! **not** decide whether a domain is blocked — that is
//! [`crate::filter::FilterEngine`], which runs once a query is past here —
//! and they do not resolve profiles. Every checker is optional, and a `None`
//! means the operator turned that sub-feature off, never that the query
//! passed it.

pub mod anti_bypass;
pub mod atomic_window;
pub mod bounded_map;
pub mod query_validator;
pub mod rate_limiter;
pub mod rrl;
pub mod tunneling;

use crate::dns::validation::{MAX_LABEL_COUNT, MAX_LABEL_COUNT_ARPA};

/// Upper bound on the labels a heuristic in this module holds on the stack,
/// sized from the deepest name `dns::validation` admits plus one slot of
/// slack — so a name that passed validation always fits, and the over-cap
/// arm stays unreachable for real traffic.
///
/// Deriving it is the enforcement. A literal drifts silently when either
/// validation ceiling moves, and a heuristic reading a truncated prefix of
/// the name fails open: padding a name past the buffer would be enough to
/// walk through the gate.
pub(crate) const MAX_LABELS: usize = {
    let deepest = if MAX_LABEL_COUNT_ARPA > MAX_LABEL_COUNT {
        MAX_LABEL_COUNT_ARPA
    } else {
        MAX_LABEL_COUNT
    };
    deepest + 1
};
