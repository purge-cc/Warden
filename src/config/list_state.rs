//! `data/list_state.toml` — refresh-state persistence for blocklists.
//!
//! The retry state machine (Pending → Active → Failed) needs a
//! durable side-channel so a daemon restart does not reset every
//! list's `consecutive_failures` counter or its `last_success`
//! timestamp. The state lives in `data/list_state.toml` (alongside
//! the existing stats snapshots) so the master `config.toml`
//! stays operator-authored.
//!
//! This module supplies:
//!
//! - The struct surface ([`ListState`], [`ListStatusEntry`],
//!   [`ListStatus`]) that the resolver and the refresh task read/write.
//! - [`ListState::read_or_default`] — load from disk, return
//!   `ListState::default()` when the file is missing.
//! - [`ListState::write_atomic`] — write through
//!   [`crate::config::atomic_write::atomic_write_and_validate`] so a
//!   crash mid-write leaves the previous state intact.
//! - The state-machine transitions themselves
//!   ([`ListStatusEntry::record_success`],
//!   [`ListStatusEntry::record_failure`]).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

use super::atomic_write::{atomic_write_and_validate, AtomicWriteError};
use super::schema::Id;

/// Where each blocklist sits in the refresh state machine. Strings
/// kebab-case so the on-disk form is readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ListStatus {
    /// Initial state. The first download has not yet succeeded.
    #[default]
    Pending,
    /// Cache is fresh and the filter engine is using it.
    Active,
    /// `max_consecutive_failures` exhausted. A list with a prior
    /// success keeps its stale cache; a list that never
    /// succeeded has `cache_path = None` and contributes nothing.
    Failed,
}

/// Per-list refresh state row. Every field except `status` carries
/// `#[serde(default)]` so a partial v2 state file (or a fresh
/// install) deserialises cleanly.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
pub struct ListStatusEntry {
    /// Current state-machine position.
    #[serde(default)]
    pub status: ListStatus,
    /// Wall-clock at the most recent successful refresh, RFC 3339.
    /// The stale-badge logic reads this.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_success: Option<OffsetDateTime>,
    /// Wall-clock at the most recent refresh attempt (success or
    /// failure). Used to decide when to schedule the
    /// next attempt.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_attempt: Option<OffsetDateTime>,
    /// Number of refresh attempts that have failed in a row since
    /// the last success. Reset to 0 on success. Checked
    /// against `Blocklist.max_consecutive_failures` (default 5,
    /// configurable per list).
    #[serde(default)]
    pub consecutive_failures: u32,
    /// On-disk path of the cached list bytes, when one exists. The
    /// file may be stale — the resolver applies it anyway as
    /// long as `status != Failed without prior success`.
    #[serde(default)]
    pub cache_path: Option<PathBuf>,
}

/// Top-level shape of `list_state.toml`. The TOML form is a
/// `[lists]` map keyed by [`Id`], one entry per blocklist.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListState {
    /// Map keyed by blocklist [`Id`]. The map type is `BTreeMap` so
    /// `toml::to_string` emits entries in deterministic order
    /// (frozen-test friendly).
    #[serde(default)]
    pub lists: BTreeMap<Id, ListStatusEntry>,
}

/// Errors surfaced while reading or writing `list_state.toml`.
#[derive(Debug, Error)]
pub enum ListStateError {
    #[error("cannot read list-state file {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot parse list-state file {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("cannot serialise list-state to TOML: {source}")]
    Serialise {
        #[source]
        source: toml::ser::Error,
    },
    #[error("cannot persist list-state to {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: AtomicWriteError,
    },
}

impl ListStatusEntry {
    /// Record a successful
    /// refresh. Resets [`Self::consecutive_failures`] to 0, transitions
    /// any prior `Pending` / `Failed` status back to `Active`, and
    /// stamps the success / attempt timestamps.
    ///
    /// `cache_path` is the path the manager just wrote the cached
    /// bytes to. Always `Some(_)` after a success — the stale-cache
    /// fallback depends on it.
    pub fn record_success(&mut self, now: OffsetDateTime, cache_path: PathBuf) {
        self.status = ListStatus::Active;
        self.consecutive_failures = 0;
        self.last_success = Some(now);
        self.last_attempt = Some(now);
        self.cache_path = Some(cache_path);
    }

    /// Record a failed refresh.
    /// Increments [`Self::consecutive_failures`]; when the new count
    /// reaches `max_consecutive_failures`, transitions the entry to
    /// [`ListStatus::Failed`].
    ///
    /// **Stale-cache fallback.** If the entry has succeeded at least
    /// once before (`last_success.is_some()`), [`Self::cache_path`] is
    /// preserved across the transition — the resolver continues to
    /// apply the stale bytes (badge red but filtering active). For an
    /// entry that has never succeeded, `cache_path` stays `None` and
    /// the list contributes nothing once Failed.
    ///
    /// Returns `true` when the call flipped the status to `Failed`
    /// (i.e. the threshold was crossed in this call). Useful for the
    /// caller's audit log.
    pub fn record_failure(&mut self, now: OffsetDateTime, max_consecutive_failures: u32) -> bool {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.last_attempt = Some(now);
        let should_fail = self.consecutive_failures >= max_consecutive_failures
            && self.status != ListStatus::Failed;
        if should_fail {
            self.status = ListStatus::Failed;
            // cache_path stays as-is: if a prior success populated it,
            // the resolver keeps using it; otherwise
            // it remains None and the list is inactive.
        }
        should_fail
    }
}

impl ListState {
    /// Read the state file at `path`. Missing file returns
    /// [`ListState::default`] (no entries) so a fresh install never
    /// errors here. A malformed file is a hard error — the daemon
    /// should refuse to boot rather than silently zero the counters.
    pub fn read_or_default(path: &Path) -> Result<Self, ListStateError> {
        let bytes = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(source) => {
                return Err(ListStateError::Read {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        toml::from_str(&bytes).map_err(|source| ListStateError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }

    /// Serialise to TOML and write atomically through
    /// [`atomic_write_and_validate`]. The validator step round-trips
    /// the staged bytes through `toml::from_str::<ListState>` so a
    /// serialiser regression cannot land a state file the daemon
    /// will later refuse to load.
    pub fn write_atomic(&self, path: &Path) -> Result<(), ListStateError> {
        let serialised =
            toml::to_string_pretty(self).map_err(|source| ListStateError::Serialise { source })?;
        atomic_write_and_validate(path, &serialised, |p: &Path| {
            let bytes = std::fs::read_to_string(p).map_err(|e| e.to_string())?;
            toml::from_str::<ListState>(&bytes).map_err(|e| e.to_string())?;
            Ok::<(), String>(())
        })
        .map_err(|source| ListStateError::Write {
            path: path.to_path_buf(),
            source,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn id(s: &str) -> Id {
        Id::new(s).unwrap()
    }

    #[test]
    fn read_or_default_returns_empty_when_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("list_state.toml");
        let state = ListState::read_or_default(&path).unwrap();
        assert!(state.lists.is_empty());
    }

    #[test]
    fn write_then_read_round_trips_one_entry_per_status() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("list_state.toml");

        let mut original = ListState::default();
        original.lists.insert(
            id("priv-ads"),
            ListStatusEntry {
                status: ListStatus::Active,
                last_success: Some(datetime!(2026-05-08 19:30:00 UTC)),
                last_attempt: Some(datetime!(2026-05-08 19:30:00 UTC)),
                consecutive_failures: 0,
                cache_path: Some(PathBuf::from("lists/https___lists.purge.cc_ads.txt.cache")),
            },
        );
        original.lists.insert(
            id("broken-source"),
            ListStatusEntry {
                status: ListStatus::Pending,
                last_success: None,
                last_attempt: Some(datetime!(2026-05-08 18:00:00 UTC)),
                consecutive_failures: 3,
                cache_path: None,
            },
        );
        original.lists.insert(
            id("dead-feed"),
            ListStatusEntry {
                status: ListStatus::Failed,
                last_success: Some(datetime!(2026-04-30 12:00:00 UTC)),
                last_attempt: Some(datetime!(2026-05-08 19:00:00 UTC)),
                consecutive_failures: 5,
                cache_path: Some(PathBuf::from("lists/https___example.invalid_d.txt.cache")),
            },
        );

        original.write_atomic(&path).unwrap();
        let back = ListState::read_or_default(&path).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn parse_pinned_toml_layout() {
        // Frozen-shape pin for the on-disk format. Future serialiser
        // upgrades that change spacing, key ordering, or default
        // omission would surface here before they hit a deployed
        // state file.
        let pinned = r##"
[lists.priv-ads]
status = "active"
last_success = "2026-05-08T19:30:00Z"
last_attempt = "2026-05-08T19:30:00Z"
consecutive_failures = 0
cache_path = "lists/priv-ads.cache"

[lists.broken-source]
status = "pending"
consecutive_failures = 3
"##;
        let state: ListState = toml::from_str(pinned).unwrap();
        assert_eq!(state.lists.len(), 2);
        let priv_ads = state.lists.get(&id("priv-ads")).unwrap();
        assert_eq!(priv_ads.status, ListStatus::Active);
        assert_eq!(priv_ads.consecutive_failures, 0);
        assert_eq!(
            priv_ads.cache_path.as_deref().unwrap().to_str().unwrap(),
            "lists/priv-ads.cache"
        );
        let broken = state.lists.get(&id("broken-source")).unwrap();
        assert_eq!(broken.status, ListStatus::Pending);
        assert!(broken.last_success.is_none());
        assert_eq!(broken.consecutive_failures, 3);
    }

    #[test]
    fn unknown_top_level_field_rejected() {
        // `deny_unknown_fields` on the root keeps typos loud at load
        // time — the operator gets a directed parse error rather
        // than a silently dropped section.
        let toml = r#"made_up = 7"#;
        let err = toml::from_str::<ListState>(toml).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn write_atomic_creates_parent_directory_if_needed() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("data").join("list_state.toml");
        let state = ListState::default();
        state.write_atomic(&nested).unwrap();
        assert!(nested.exists());
    }

    #[test]
    fn write_atomic_replaces_existing_file_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("list_state.toml");

        let mut a = ListState::default();
        a.lists.insert(
            id("a"),
            ListStatusEntry {
                status: ListStatus::Active,
                ..Default::default()
            },
        );
        a.write_atomic(&path).unwrap();

        let mut b = ListState::default();
        b.lists.insert(
            id("b"),
            ListStatusEntry {
                status: ListStatus::Failed,
                consecutive_failures: 7,
                ..Default::default()
            },
        );
        b.write_atomic(&path).unwrap();

        let back = ListState::read_or_default(&path).unwrap();
        assert_eq!(back.lists.len(), 1);
        assert!(back.lists.contains_key(&id("b")));
    }

    #[test]
    fn list_status_default_is_pending() {
        // Pending is the safe default — a list whose entry is
        // synthesised on first observation has not yet succeeded.
        assert_eq!(ListStatus::default(), ListStatus::Pending);
    }

    #[test]
    fn list_status_kebab_wire_form() {
        // Pin the on-wire spelling so a future rename surfaces here
        // rather than silently breaking deployed state files.
        let s = toml::to_string(&ListStatusEntry {
            status: ListStatus::Active,
            ..Default::default()
        })
        .unwrap();
        assert!(s.contains("status = \"active\""), "got: {s}");
    }

    // ── state-machine transitions ────────────────────

    /// Pending → Active on first success.
    #[test]
    fn pending_to_active_on_first_success() {
        let mut e = ListStatusEntry::default();
        assert_eq!(e.status, ListStatus::Pending);
        e.record_success(
            datetime!(2026-05-08 10:00:00 UTC),
            PathBuf::from("lists/x.cache"),
        );
        assert_eq!(e.status, ListStatus::Active);
        assert_eq!(e.consecutive_failures, 0);
        assert!(e.last_success.is_some());
        assert!(e.cache_path.is_some());
    }

    /// Active → Failed once consecutive_failures hits the
    /// max threshold. cache_path is preserved across the transition
    /// (stale-cache fallback) when a prior success populated it.
    #[test]
    fn active_to_failed_after_max_consecutive_failures() {
        let mut e = ListStatusEntry::default();
        // Bring it Active first with a populated cache_path.
        e.record_success(
            datetime!(2026-05-08 10:00:00 UTC),
            PathBuf::from("lists/x.cache"),
        );
        assert_eq!(e.status, ListStatus::Active);
        // Three failures with max=5 → still Active, counter increments.
        for _ in 0..4 {
            assert!(!e.record_failure(datetime!(2026-05-08 11:00:00 UTC), 5));
        }
        assert_eq!(e.status, ListStatus::Active);
        assert_eq!(e.consecutive_failures, 4);
        // Fifth failure → flips to Failed, returns true.
        assert!(e.record_failure(datetime!(2026-05-08 12:00:00 UTC), 5));
        assert_eq!(e.status, ListStatus::Failed);
        assert_eq!(e.consecutive_failures, 5);
        // Stale-cache fallback — cache_path preserved.
        assert_eq!(
            e.cache_path.as_deref().unwrap().to_str().unwrap(),
            "lists/x.cache"
        );
    }

    /// Failed → Active on recovery, counter resets.
    #[test]
    fn failed_to_active_on_recovery_resets_counter() {
        let mut e = ListStatusEntry {
            status: ListStatus::Failed,
            consecutive_failures: 7,
            last_attempt: Some(datetime!(2026-05-08 09:00:00 UTC)),
            last_success: Some(datetime!(2026-05-01 09:00:00 UTC)),
            cache_path: Some(PathBuf::from("lists/old.cache")),
        };
        e.record_success(
            datetime!(2026-05-08 10:00:00 UTC),
            PathBuf::from("lists/new.cache"),
        );
        assert_eq!(e.status, ListStatus::Active);
        assert_eq!(e.consecutive_failures, 0);
        assert_eq!(
            e.last_success.unwrap(),
            datetime!(2026-05-08 10:00:00 UTC),
            "last_success bumped on recovery"
        );
        assert_eq!(
            e.cache_path.as_deref().unwrap().to_str().unwrap(),
            "lists/new.cache",
            "cache_path bumped on recovery"
        );
    }

    /// Pending → Failed without prior success. cache_path
    /// stays `None`; the resolver excludes the list entirely.
    #[test]
    fn pending_to_failed_no_cache_after_max_failures() {
        let mut e = ListStatusEntry::default();
        for _ in 0..5 {
            e.record_failure(datetime!(2026-05-08 12:00:00 UTC), 5);
        }
        assert_eq!(e.status, ListStatus::Failed);
        assert_eq!(e.consecutive_failures, 5);
        assert!(
            e.cache_path.is_none(),
            "Pending→Failed without prior success keeps cache_path=None"
        );
        assert!(e.last_success.is_none());
    }

    /// Once Failed, additional failures keep the status
    /// pinned (does not flip to Failed twice). Counter still ticks
    /// up so the operator can see how long the list has been broken.
    #[test]
    fn failed_state_is_idempotent_on_continued_failure() {
        let mut e = ListStatusEntry::default();
        for _ in 0..5 {
            e.record_failure(datetime!(2026-05-08 12:00:00 UTC), 5);
        }
        assert_eq!(e.status, ListStatus::Failed);
        // Subsequent failures don't return `true` again.
        assert!(!e.record_failure(datetime!(2026-05-08 13:00:00 UTC), 5));
        assert_eq!(e.status, ListStatus::Failed);
        assert_eq!(e.consecutive_failures, 6);
    }
}
