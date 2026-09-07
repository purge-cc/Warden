//! `data/list_schedule_state.toml` — durable canonical-source scheduling.
//!
//! This sidecar is intentionally separate from `list_state.toml`: an older
//! binary ignores an unknown file, so rolling back remains safe.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

use super::atomic_write::{atomic_write_and_validate, AtomicWriteError};
use crate::lists::source_key::CanonicalSourceScheduleKey;

/// Result of the attempt anchored at [`CanonicalScheduleEntry::last_attempt`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CanonicalScheduleOutcome {
    Success,
    Failure,
}

/// One canonical source's durable scheduling anchor.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalScheduleEntry {
    /// Cycle-start time for the attempt that produced [`Self::outcome`].
    #[serde(with = "time::serde::rfc3339")]
    pub last_attempt: OffsetDateTime,
    /// Determines whether the next slice applies normal or retry cadence.
    pub outcome: CanonicalScheduleOutcome,
}

/// Strict sidecar persisted separately from legacy list health state.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListScheduleState {
    /// BTreeMap keeps the on-disk ledger deterministic.
    pub schedules: BTreeMap<CanonicalSourceScheduleKey, CanonicalScheduleEntry>,
}

/// Errors surfaced while reading or writing the scheduling sidecar.
#[derive(Debug, Error)]
pub enum ListScheduleStateError {
    #[error("cannot read list-schedule-state file {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot parse list-schedule-state file {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("cannot serialise list-schedule-state: {source}")]
    Serialise {
        #[source]
        source: toml::ser::Error,
    },
    #[error("cannot persist list-schedule-state to {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: AtomicWriteError,
    },
}

impl ListScheduleState {
    /// Missing sidecars are normal until the runtime scheduler first persists one.
    pub fn read_or_default(path: &Path) -> Result<Self, ListScheduleStateError> {
        let bytes = match std::fs::read_to_string(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default())
            }
            Err(source) => {
                return Err(ListScheduleStateError::Read {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        toml::from_str(&bytes).map_err(|source| ListScheduleStateError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }

    /// Atomically persist only a fully deserializable strict sidecar.
    pub fn write_atomic(&self, path: &Path) -> Result<(), ListScheduleStateError> {
        let serialised = toml::to_string_pretty(self)
            .map_err(|source| ListScheduleStateError::Serialise { source })?;
        atomic_write_and_validate(path, &serialised, |staged| {
            let bytes = std::fs::read_to_string(staged).map_err(|error| error.to_string())?;
            toml::from_str::<Self>(&bytes).map_err(|error| error.to_string())?;
            Ok::<(), String>(())
        })
        .map_err(|source| ListScheduleStateError::Write {
            path: path.to_path_buf(),
            source,
        })
    }

    /// Look up a canonical source's persisted scheduling anchor.
    pub fn lookup(&self, key: &CanonicalSourceScheduleKey) -> Option<&CanonicalScheduleEntry> {
        self.schedules.get(key)
    }

    /// Record a successful attempt anchored at this cycle's start time.
    pub fn record_success(&mut self, key: CanonicalSourceScheduleKey, cycle_start: OffsetDateTime) {
        self.record(key, cycle_start, CanonicalScheduleOutcome::Success);
    }

    /// Record a failed attempt anchored at this cycle's start time.
    pub fn record_failure(&mut self, key: CanonicalSourceScheduleKey, cycle_start: OffsetDateTime) {
        self.record(key, cycle_start, CanonicalScheduleOutcome::Failure);
    }

    fn record(
        &mut self,
        key: CanonicalSourceScheduleKey,
        cycle_start: OffsetDateTime,
        outcome: CanonicalScheduleOutcome,
    ) {
        self.schedules.insert(
            key,
            CanonicalScheduleEntry {
                last_attempt: cycle_start,
                outcome,
            },
        );
    }

    /// Seed selected legacy metadata without replacing a canonical ledger row.
    pub fn seed_if_absent(
        &mut self,
        key: CanonicalSourceScheduleKey,
        cycle_start: OffsetDateTime,
        outcome: CanonicalScheduleOutcome,
    ) -> bool {
        match self.schedules.entry(key) {
            Entry::Occupied(_) => false,
            Entry::Vacant(entry) => {
                entry.insert(CanonicalScheduleEntry {
                    last_attempt: cycle_start,
                    outcome,
                });
                true
            }
        }
    }

    /// Discard canonical rows no longer present in the active source plan.
    pub fn prune(&mut self, current_keys: &BTreeSet<CanonicalSourceScheduleKey>) {
        self.schedules.retain(|key, _| current_keys.contains(key));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    use time::macros::datetime;

    const ADS_KEY: &str =
        "canonical-url-v1-sha256-5f96be98e676eb9d356654baaff1e8f8e02de9e32dc8cbaf27fda1599ffbb5e1";
    const PATH_KEY: &str =
        "canonical-url-v1-sha256-4e597e623d4112f2872d16b23fdc91d5f7f38102bf6fcf204c8b41911e5da6f8";
    const TOML_FIXTURE: &str = "[schedules.canonical-url-v1-sha256-4e597e623d4112f2872d16b23fdc91d5f7f38102bf6fcf204c8b41911e5da6f8]\nlast_attempt = \"2026-09-05T10:01:00Z\"\noutcome = \"failure\"\n\n[schedules.canonical-url-v1-sha256-5f96be98e676eb9d356654baaff1e8f8e02de9e32dc8cbaf27fda1599ffbb5e1]\nlast_attempt = \"2026-09-05T10:00:00Z\"\noutcome = \"success\"\n";

    fn ads_key() -> CanonicalSourceScheduleKey {
        CanonicalSourceScheduleKey::from_str(ADS_KEY).unwrap()
    }

    fn path_key() -> CanonicalSourceScheduleKey {
        CanonicalSourceScheduleKey::from_str(PATH_KEY).unwrap()
    }

    #[test]
    fn missing_sidecar_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let state = ListScheduleState::read_or_default(&dir.path().join("missing.toml")).unwrap();
        assert!(state.schedules.is_empty());
    }

    #[test]
    fn explicit_empty_schedules_table_is_valid() {
        let state: ListScheduleState = toml::from_str("[schedules]\n").unwrap();
        assert!(state.schedules.is_empty());
    }

    #[test]
    fn empty_or_comment_only_sidecar_is_corrupt() {
        for invalid in ["", "# no schedule state yet\n"] {
            assert!(
                toml::from_str::<ListScheduleState>(invalid).is_err(),
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn exact_toml_fixture_round_trips() {
        let state: ListScheduleState = toml::from_str(TOML_FIXTURE).unwrap();

        assert_eq!(ads_key().as_str(), ADS_KEY);
        assert_eq!(path_key().as_str(), PATH_KEY);
        assert_eq!(
            state.lookup(&ads_key()).unwrap().outcome,
            CanonicalScheduleOutcome::Success
        );
        assert_eq!(
            state.lookup(&path_key()).unwrap().outcome,
            CanonicalScheduleOutcome::Failure
        );
        assert_eq!(toml::to_string_pretty(&state).unwrap(), TOML_FIXTURE);
    }

    #[test]
    fn atomic_write_then_read_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data/list_schedule_state.toml");
        let mut state = ListScheduleState::default();
        state.record_success(ads_key(), datetime!(2026-09-05 10:00:00 UTC));

        assert!(!path.parent().unwrap().exists());
        state.write_atomic(&path).unwrap();
        assert!(path.parent().unwrap().exists());
        assert_eq!(ListScheduleState::read_or_default(&path).unwrap(), state);
    }

    #[test]
    fn strict_sidecar_rejects_unknown_or_malformed_data() {
        let invalid = [
            "unexpected = true\n".to_string(),
            "[schedules.not-a-key]\nlast_attempt = \"2026-09-05T10:00:00Z\"\noutcome = \"success\"\n".to_string(),
            "[schedules.canonical-url-v1-sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA]\nlast_attempt = \"2026-09-05T10:00:00Z\"\noutcome = \"success\"\n".to_string(),
            format!(
                "[schedules.{ADS_KEY}]\nlast_attempt = \"2026-09-05T10:00:00Z\"\noutcome = \"success\"\nextra = true\n"
            ),
            format!(
                "[schedules.{ADS_KEY}]\nlast_attempt = \"2026-09-05T10:00:00Z\"\noutcome = \"unknown\"\n"
            ),
        ];
        for invalid in invalid {
            assert!(
                toml::from_str::<ListScheduleState>(&invalid).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn seed_and_prune_preserve_existing_canonical_rows() {
        let mut state = ListScheduleState::default();
        let first = datetime!(2026-09-05 10:00:00 UTC);
        let later = datetime!(2026-09-05 11:00:00 UTC);
        let ads = ads_key();
        let path = path_key();
        state.record_success(ads.clone(), first);

        assert!(!state.seed_if_absent(ads.clone(), later, CanonicalScheduleOutcome::Failure));
        assert!(state.seed_if_absent(path.clone(), later, CanonicalScheduleOutcome::Failure));
        assert_eq!(state.lookup(&ads).unwrap().last_attempt, first);

        state.prune(&BTreeSet::from([ads.clone()]));
        assert!(state.lookup(&ads).is_some());
        assert!(state.lookup(&path).is_none());
    }

    #[test]
    fn future_attempt_timestamp_is_retained_without_policy() {
        let mut state = ListScheduleState::default();
        let future = datetime!(2030-01-01 00:00:00 UTC);
        let key = ads_key();
        state.record_failure(key.clone(), future);

        assert_eq!(state.lookup(&key).unwrap().last_attempt, future);
    }
}
