// Stats tracking: per-client counters, top-N, query log, snapshots

pub mod engine;
pub mod local_records_hits;
pub mod log_ring;
pub mod prefetch;
pub mod prefetch_worker;
pub mod query_log;
pub mod query_type;
pub mod rule_source;
pub mod snapshot;
pub mod time_series;
pub mod top_n;

pub use engine::StatsEngine;
pub use local_records_hits::{LocalRecordsHits, LocalRecordsScopeKey};
pub use log_ring::{LogEntry, LogLevel, LogRing};
pub use prefetch::{HitTracker, PrefetchTrackerConfig};
pub use query_type::{TypeBucket, TYPE_BUCKET_COUNT};
pub use rule_source::RuleSource;
