//! Append-only audit log.
//!
//! Every reload / boot / shutdown event writes one JSON object on a single
//! line to `/var/lib/purge-warden/audit/audit.log`. The file is never
//! truncated, only appended, so the log is a permanent integrity record of
//! every change the daemon saw at runtime.
//!
//! # Schema
//!
//! ```json
//! {
//!   "ts": "2026-04-22T16:09:55Z",
//!   "event": "reload",
//!   "uid": 1000,
//!   "files": ["/var/lib/purge-warden/config.toml"],
//!   "pre_hash": "abc…",
//!   "post_hash": "def…",
//!   "result": "ok",
//!   "errors": []
//! }
//! ```
//!
//! - `ts` — RFC 3339 UTC timestamp of when the event was written.
//! - `event` — one of `"boot"`, `"reload"`, `"shutdown"`, `"restore"`.
//! - `uid` — invoker uid from `SO_PEERCRED` on the IPC socket, or `null`
//!   for signal-triggered reloads (SIGHUP from systemd / kill) and boot.
//! - `files` — absolute paths of every config file loaded / attempted.
//!   Sorted for determinism.
//! - `pre_hash` / `post_hash` — config-tree SHA-256 before / after the
//!   event. `null` when the side is not meaningful (no config before boot;
//!   no config after shutdown).
//! - `result` — `"ok"` or `"rejected"`.
//! - `errors` — empty on `ok`, one string per validator error on `rejected`.
//!
//! Schema changes are breaking: downstream tooling parses a fixed shape.
//!
//! # Concurrency & atomicity
//!
//! The writer opens the file with `O_APPEND | O_CREATE` and holds an exclusive
//! file lock through boundary repair, append, and synchronization. Short writes
//! cannot interleave with another writer. If an append fails midway, the next
//! append preserves the incomplete bytes and adds a newline before its record.
//! The per-record `errors` list is capped at [`MAX_AUDIT_RECORD_ERRORS`].
//!
//! # Permissions
//!
//! The audit directory is created with mode `0750`, the file with mode
//! `0640`. Group `purge-warden` can read without being able to write — which
//! matches the systemd service user/group deployed on the CT. If those bits
//! need tightening further the daemon can re-apply on every open.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Mode bits applied to the audit directory on first create. `0o750` =
/// `rwxr-x---`: owner full control, group read, other none.
pub const AUDIT_DIR_MODE: u32 = 0o750;

/// Mode bits applied to the audit log file on first create. `0o640` =
/// `rw-r-----`: owner write, group read, other none.
pub const AUDIT_FILE_MODE: u32 = 0o640;

/// Default audit log filename under the audit directory.
pub const AUDIT_FILE_NAME: &str = "audit.log";

/// Max validator-error strings kept inline in one audit record. A
/// `Rejected` reload over a badly broken multi-file config could otherwise
/// emit one string per error and grow the record past a safe single-write
/// size (risking a torn `O_APPEND`) and bloat the log. Beyond this we keep
/// the first N and append a synthetic "… and M more" marker.
pub const MAX_AUDIT_RECORD_ERRORS: usize = 32;

/// Default audit directory name. Paired with the daemon's `/var/lib`
/// parent to produce `/var/lib/purge-warden/audit/audit.log`.
pub const AUDIT_DIR_NAME: &str = "audit";

/// Maximum serialized size of one operator-rules audit event.
pub const MAX_UOR_AUDIT_EVENT_BYTES: usize = 64 * 1024;

/// Maximum number of list or profile identifiers retained in one event.
pub const MAX_UOR_AUDIT_ENTITY_IDS: usize = 256;

/// Maximum number of operation identities retained by the restart-safe
/// deduplication index before old recorded entries become eligible for expiry.
pub const MAX_UOR_AUDIT_DEDUP_ENTRIES: usize = 4_096;

const UOR_AUDIT_DEDUP_RETENTION_SECS: u64 = 24 * 60 * 60;
const UOR_AUDIT_INDEX_FORMAT: u32 = 2;
const MAX_UOR_AUDIT_ID_BYTES: usize = 128;
const MAX_UOR_AUDIT_ACTOR_BYTES: usize = 256;
const MAX_UOR_AUDIT_OPERATION_BYTES: usize = 128;

/// Classification of what triggered an audit record. The daemon emits one
/// per lifecycle transition; `warden audit tail` reads them back verbatim.
///
/// [`AuditEvent::CliMutation`] covers CLI-issued rule writes (`warden
/// {profile,device,group,subnet,default} {allow,deny}`, `warden rule
/// undo`, `warden device rules prune`, `warden profile blocklists ...`).
/// [`AuditWriter::append_cli_mutation`] writes it to the same JSON file
/// the daemon writes to, with the optional fields below carrying the
/// mutation context, so `journalctl -u purge-warden` and `warden audit
/// tail` both see it. The schema is additive: audit lines written before
/// this variant existed still deserialise unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEvent {
    /// Daemon startup. No `pre_hash`; `post_hash` reflects the initial
    /// loaded tree.
    Boot,
    /// Config reload: either SIGHUP (uid = None) or IPC `Reload` (uid set
    /// from `SO_PEERCRED`). `pre_hash` and `post_hash` bracket the attempt.
    Reload,
    /// Daemon shutdown. `post_hash` is None.
    Shutdown,
    /// Out-of-band config replacement via `warden config restore`. Recorded
    /// from the CLI path, not the daemon runtime — uid = invoker.
    Restore,
    /// CLI rule/blocklist mutation issued from `warden <verb>`. `action`
    /// carries the verb tag (`rule.add` / `rule.remove` / `rule.undo` /
    /// `device.rules.prune`); `scope` / `target_id` / `domain` /
    /// `rule_id` / `rule_action` / `override_used` carry the mutation
    /// detail. `pre_hash` / `post_hash` not used (the row is short-lived
    /// CLI state, not daemon state); `files` may carry the touched
    /// master/entity paths.
    CliMutation,
    /// Runtime CNAME chain block. Emitted when
    /// `filter::cname::walk_response` returns `Verdict::Block` on a
    /// CNAME chain post-upstream-fetch or on cache-hit re-check. `action`
    /// carries the static `"cname_block"` verb; `domain` carries the
    /// original qname; `cname_target` carries the offending hop; and
    /// `cname_source` carries `BlockSource::label()`.
    CnameBlock,
    /// One durable operator-rules transaction outcome. The structured
    /// `uor_operation` field carries bounded metadata and state; raw rules,
    /// pack bodies, tokens and secrets have no representation in this event.
    OperatorRulesOperation,
}

impl AuditEvent {
    /// Short tag for human tools (`warden audit tail`).
    pub fn as_tag(self) -> &'static str {
        match self {
            Self::Boot => "boot",
            Self::Reload => "reload",
            Self::Shutdown => "shutdown",
            Self::Restore => "restore",
            Self::CliMutation => "cli_mutation",
            Self::CnameBlock => "cname_block",
            Self::OperatorRulesOperation => "operator_rules_operation",
        }
    }
}

/// Outcome tag: did the event succeed, or was it rejected by the validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditResult {
    Ok,
    Rejected,
}

impl AuditResult {
    pub fn as_tag(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Rejected => "rejected",
        }
    }
}

/// Authenticated source of an operator-rules transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UorAuditOrigin {
    Cli,
    Ipc,
    Rest,
    Replica,
    Migration,
    External,
    Unknown,
}

/// Identity fields copied from durable transaction intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UorAuditIdentity {
    pub operation_id: String,
    pub request_id: String,
    pub actor: String,
    pub origin: UorAuditOrigin,
    pub operation: String,
}

/// Byte revision and optional semantic hash on both sides of a transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UorAuditRevisions {
    pub before_config_revision: String,
    pub after_config_revision: String,
    pub before_operator_policy_hash: Option<String>,
    pub after_operator_policy_hash: Option<String>,
}

/// Bounded entity identities involved in a transaction.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UorAuditEntities {
    pub list_ids: Vec<String>,
    pub profile_ids: Vec<String>,
}

/// Aggregate mutation counts. Scalars keep the audit useful without storing
/// rule text, pack bodies or a full semantic diff.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UorAuditCounts {
    pub operations: u32,
    pub changed_members: u32,
    pub rules_added: u32,
    pub rules_removed: u32,
    pub rules_replaced: u32,
    pub mounts_added: u32,
    pub mounts_removed: u32,
}

/// Aggregate reachability impact known when the receipt is audited.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UorAuditImpact {
    pub affected_profiles: u32,
    pub affected_destinations: u32,
    pub potential_destinations: u32,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UorAuditPersistence {
    Prepared,
    Committed,
    Aborted,
    DurabilityUncertain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UorAuditActivation {
    NotRequested,
    Pending,
    Active,
    Failed,
    Unknown,
    Superseded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UorAuditReplication {
    NotConfigured,
    Pending,
    Converged,
    Degraded,
    Failed,
    Unknown,
}

/// Durable receipt states captured by the audit attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UorAuditOutcome {
    pub persistence: UorAuditPersistence,
    pub activation: UorAuditActivation,
    pub replication: UorAuditReplication,
}

/// Redacted, bounded audit projection of one durable operator-rules intent and
/// receipt. This type deliberately has no token, secret, raw-rule, domain,
/// pattern, diff-body or pack-body field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UorOperationAuditEvent {
    pub identity: UorAuditIdentity,
    pub revisions: UorAuditRevisions,
    pub entities: UorAuditEntities,
    pub counts: UorAuditCounts,
    pub impact: UorAuditImpact,
    pub outcome: UorAuditOutcome,
    pub changed: bool,
}

/// Serialisable single-line record. Matches the frozen schema comment at
/// the top of this module one-to-one; renaming a field here is a breaking
/// change for parsers.
///
/// Every field beyond the original lifecycle quartet (`event`, `uid`,
/// `files`, `pre_hash`/`post_hash`, `result`, `errors`) carries the
/// CLI-mutation or feature-specific detail below, is
/// `#[serde(default, skip_serializing_if = ...)]`, and defaults to
/// `None` on lifecycle records (Boot/Reload/Shutdown/Restore). That
/// keeps two things true at once: older lines on disk without a given
/// field still deserialise, and a record that doesn't populate a field
/// doesn't grow a spurious `null` in the JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub ts: String,
    pub event: AuditEvent,
    pub uid: Option<u32>,
    pub files: Vec<String>,
    pub pre_hash: Option<String>,
    pub post_hash: Option<String>,
    pub result: AuditResult,
    pub errors: Vec<String>,

    // CLI mutation detail. All optional + skip-if-none so lifecycle
    // records on disk keep their original shape.
    /// CLI mutation verb tag, e.g. `rule.add` / `rule.remove` /
    /// `rule.undo` / `device.rules.prune` / `blocklist.tag_add` /
    /// `device.tag_add` / `profile.tag_add` / `tags.rename`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Scope tag: `profile` / `device` / `group` / `subnet` /
    /// `default`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Operator-typed scope target id (profile id, device id, group id,
    /// subnet id-or-cidr, or `default`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
    /// `[[admin_rules]]` row id touched by the mutation, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// `allow` / `deny` (the rule action, distinct from `action` above
    /// which names the CLI verb).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_action: Option<String>,
    /// Canonical domain (post-`validate_domain`) for rule mutations;
    /// `None` for prune.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// `true` when the device-allow path landed because
    /// `override_profile_deny = true` was set on the device entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub override_used: Option<bool>,

    /// Value of the mutated field BEFORE the CLI mutation landed.
    /// Carried for `blocklist.set_kind` / `blocklist.set_trust` (e.g.
    /// `"block"` flipping to `"allow"`). Stored as the wire-form string
    /// the operator typed in TOML so audit-log readers don't have to
    /// know the Rust enum spelling. `None` for any record where the
    /// action is not a single-field mutation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields_before: Option<String>,
    /// Value of the mutated field AFTER the CLI mutation landed.
    /// Symmetric counterpart to [`AuditRecord::fields_before`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields_after: Option<String>,

    /// The resolved IP/CNAME target stored on a `local_records.add`
    /// mutation. `None` for any non-Local-DNS audit record and for
    /// `local_records.remove` (the value is implied by the matched
    /// row, not part of the operator-typed mutation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_value: Option<String>,
    /// The `match_subdomains` flag on a `local_records.add` mutation.
    /// `None` outside Local DNS adds. Lets the audit panel show
    /// "wildcard" mutations distinct from exact-match adds without
    /// having to cross-reference the master TOML.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_subdomains: Option<bool>,
    /// Explicit per-record TTL on a `local_records.add` mutation.
    /// `None` when the operator did not override the global default;
    /// the daemon falls back to `[local_dns].ttl_secs`. `None` outside
    /// Local DNS adds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u32>,

    /// Offending hop in a CNAME chain block. Set when
    /// [`AuditRecord::event`] is [`AuditEvent::CnameBlock`]; carries the
    /// fully-qualified domain that triggered the block in the chain
    /// reached from [`AuditRecord::domain`] (the original qname).
    /// `None` outside CNAME-block records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cname_target: Option<String>,
    /// Block-source classifier. One of `"list"` / `"rule"` /
    /// `"admin_block"` / `"cname_loop"` / `"cname_depth_exceeded"`
    /// (frozen via `BlockSource::label()` in
    /// `tests/frozen_strings_s45_p1.rs`). `None` outside CNAME-block
    /// records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cname_source: Option<String>,

    /// `from` side of a `rewrite.add` / `rewrite.remove` mutation (the
    /// operator-typed source FQDN). `None` outside rewrite-rule
    /// mutations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewrite_from: Option<String>,
    /// `to` side of a `rewrite.add` / `rewrite.remove` mutation (the
    /// operator-typed target FQDN). `None` outside rewrite-rule
    /// mutations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewrite_to: Option<String>,

    /// Original (pre-rewrite) qname when a per-profile domain rewrite
    /// fired on the *resolved query* that produced this CNAME-block
    /// audit record. [`AuditRecord::domain`] carries the effective
    /// (rewritten) name that was actually filtered; this carries what
    /// the client typed. `None` when no rewrite fired (the common
    /// case) and on every non-CNAME-block record.
    ///
    /// Distinct from [`AuditRecord::rewrite_from`] above: that is the
    /// operator-typed `from` side of a `rewrite.add` / `rewrite.remove`
    /// *CLI mutation*; this is the runtime original qname of a query
    /// the resolver rewrote. The tense difference (`rewrite_` vs
    /// `rewrote_`) is the naming cue.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewrote_from: Option<String>,

    /// Redacted operator-rules transaction metadata. Kept as one optional
    /// additive object so legacy lifecycle and mutation records retain their
    /// original JSON shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uor_operation: Option<UorOperationAuditEvent>,
    /// Versioned digest of the normalized `uor_operation` object. The durable
    /// side index uses it to distinguish an exact retry from reuse of an
    /// operation id with different audit data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uor_event_hash: Option<String>,
    /// Durable index timestamp, at least the original receipt's creation time.
    /// Kept outside the event digest so delivery timing never changes identity.
    /// Absent when the caller did not supply a trusted receipt creation time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uor_index_time_floor_unix_seconds: Option<u64>,
}

impl AuditRecord {
    /// Build a fresh record for `event` with the current UTC timestamp.
    /// Callers chain `.with_*` mutators to decorate.
    pub fn new(event: AuditEvent, result: AuditResult) -> Self {
        Self {
            ts: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                // Practically unreachable for a valid `now_utc()`, but the
                // fallback must itself be parseable RFC 3339 — the old
                // "0000-00-00T00:00:00Z" has month/day 00 (invalid) and
                // would carry a date no downstream parser accepts.
                .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into()),
            event,
            uid: None,
            files: Vec::new(),
            pre_hash: None,
            post_hash: None,
            result,
            errors: Vec::new(),
            action: None,
            scope: None,
            target_id: None,
            rule_id: None,
            rule_action: None,
            domain: None,
            override_used: None,
            fields_before: None,
            fields_after: None,
            record_value: None,
            match_subdomains: None,
            ttl_secs: None,
            cname_target: None,
            cname_source: None,
            rewrite_from: None,
            rewrite_to: None,
            rewrote_from: None,
            uor_operation: None,
            uor_event_hash: None,
            uor_index_time_floor_unix_seconds: None,
        }
    }

    pub fn with_uid(mut self, uid: Option<u32>) -> Self {
        self.uid = uid;
        self
    }

    pub fn with_files<I, P>(mut self, files: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let mut out: Vec<String> = files
            .into_iter()
            .map(|p| p.as_ref().display().to_string())
            .collect();
        out.sort();
        out.dedup();
        self.files = out;
        self
    }

    pub fn with_pre_hash(mut self, h: Option<String>) -> Self {
        self.pre_hash = h;
        self
    }

    pub fn with_post_hash(mut self, h: Option<String>) -> Self {
        self.post_hash = h;
        self
    }

    pub fn with_errors<I: IntoIterator<Item = String>>(mut self, errs: I) -> Self {
        self.errors = errs.into_iter().collect();
        self
    }

    // ── CLI-mutation builders ────────────────────────────────────────

    pub fn with_action(mut self, action: impl Into<String>) -> Self {
        self.action = Some(action.into());
        self
    }

    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    pub fn with_target_id(mut self, target_id: impl Into<String>) -> Self {
        self.target_id = Some(target_id.into());
        self
    }

    pub fn with_rule_id(mut self, rule_id: impl Into<String>) -> Self {
        self.rule_id = Some(rule_id.into());
        self
    }

    pub fn with_rule_action(mut self, rule_action: impl Into<String>) -> Self {
        self.rule_action = Some(rule_action.into());
        self
    }

    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    pub fn with_override_used(mut self, override_used: bool) -> Self {
        self.override_used = Some(override_used);
        self
    }

    // ── single-field-mutation builders ───────────────────────────────

    pub fn with_fields_before(mut self, before: impl Into<String>) -> Self {
        self.fields_before = Some(before.into());
        self
    }

    pub fn with_fields_after(mut self, after: impl Into<String>) -> Self {
        self.fields_after = Some(after.into());
        self
    }

    // ── Local-DNS-mutation builders ──────────────────────────────────

    pub fn with_record_value(mut self, value: impl Into<String>) -> Self {
        self.record_value = Some(value.into());
        self
    }

    pub fn with_match_subdomains(mut self, match_subdomains: bool) -> Self {
        self.match_subdomains = Some(match_subdomains);
        self
    }

    pub fn with_ttl_secs(mut self, ttl_secs: u32) -> Self {
        self.ttl_secs = Some(ttl_secs);
        self
    }

    // ── domain-rewrite-rule builders ─────────────────────────────────

    pub fn with_rewrite_from(mut self, from: impl Into<String>) -> Self {
        self.rewrite_from = Some(from.into());
        self
    }

    pub fn with_rewrite_to(mut self, to: impl Into<String>) -> Self {
        self.rewrite_to = Some(to.into());
        self
    }

    // ── CNAME-chain-block builders ───────────────────────────────────

    pub fn with_cname_target(mut self, target: impl Into<String>) -> Self {
        self.cname_target = Some(target.into());
        self
    }

    pub fn with_cname_source(mut self, source: impl Into<String>) -> Self {
        self.cname_source = Some(source.into());
        self
    }

    /// Attach the original (pre-rewrite) qname when a per-profile
    /// rewrite fired on the query being audited. `None` is a no-op so
    /// call sites can pass `decision.rewrote_from` straight through
    /// without branching.
    pub fn with_rewrote_from(mut self, original: Option<&str>) -> Self {
        if let Some(orig) = original {
            self.rewrote_from = Some(orig.to_string());
        }
        self
    }
}

/// Handle for appending audit records. Cheap to clone — the underlying
/// file is reopened per write to keep the inode consistent across log
/// rotations (`logrotate copytruncate` or similar).
#[derive(Debug, Clone)]
pub struct AuditWriter {
    path: PathBuf,
    #[cfg(test)]
    fail_after_bytes: Arc<Mutex<Option<usize>>>,
}

impl AuditWriter {
    /// Open (and create if absent) the audit file at `path`. Ensures the
    /// parent directory exists with mode `0750` and the file with mode
    /// `0640`. Returns a handle that is safe to clone + share across
    /// threads; each `append` opens fresh so rotations don't orphan the
    /// writer.
    pub fn open(path: PathBuf) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                // Chmod the parent ONLY when we created it — the rule
                // `ipc::auth_token::save_token_at` and
                // `ipc::socket_server` both honour. A dir we create would
                // otherwise land at `0o777 & !umask` (umask-dependent), so
                // it still needs the explicit mode; a dir that was already
                // there is the operator's, and re-moding it is warden
                // overriding a choice nobody asked it to review.
                //
                // Conformance, not a bug fix: today `path` is always
                // derived (`audit_log_path` / `audit_log_path_for`), so the
                // pre-existing parent is the state dir and 0750 is what it
                // already carries. Deliberately no migration for a parent
                // found at some other mode.
                let pre_existed = parent.exists();
                fs::create_dir_all(parent)?;
                if !pre_existed {
                    let mut perm = fs::metadata(parent)?.permissions();
                    perm.set_mode(AUDIT_DIR_MODE);
                    fs::set_permissions(parent, perm)?;
                }
            }
        }

        if !path.exists() {
            // Create with the desired mode up front — avoids the race where
            // `fs::write` then `set_permissions` leaves a 0644 window.
            // `OpenOptions::mode` is still subject to the process umask, so
            // we force the exact mode with an explicit `set_permissions`
            // right after create. Either call alone leaves a short window
            // where the file is either missing or has the wrong bits;
            // running both closes the race.
            let f = OpenOptions::new()
                .create(true)
                .append(true)
                .mode(AUDIT_FILE_MODE)
                .open(&path)?;
            drop(f);
            let mut perm = fs::metadata(&path)?.permissions();
            perm.set_mode(AUDIT_FILE_MODE);
            fs::set_permissions(&path, perm)?;
        } else {
            // Best-effort re-apply mode so a previous 0644 mistake gets
            // tightened on upgrade. Ignore failure — operator can fix by
            // hand, daemon must not refuse to boot over this.
            if let Ok(meta) = fs::metadata(&path) {
                let mode = meta.permissions().mode() & 0o777;
                if mode != AUDIT_FILE_MODE {
                    let mut perm = meta.permissions();
                    perm.set_mode(AUDIT_FILE_MODE);
                    let _ = fs::set_permissions(&path, perm);
                }
            }
        }

        Ok(Self {
            path,
            #[cfg(test)]
            fail_after_bytes: Arc::new(Mutex::new(None)),
        })
    }

    /// Path the writer appends to. Used by `warden audit tail` to find the
    /// same file and by tests to pin the write location.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Serialise + append one record. Fails only on IO errors (disk full,
    /// permissions revoked). A serialisation error is effectively
    /// impossible for this struct (every field is a primitive or typed
    /// enum), but the (unreachable) case is folded into the returned
    /// `io::Result` rather than panicking — a panic on the append-only
    /// integrity-log path is a strictly worse failure mode.
    pub fn append(&self, record: &AuditRecord) -> std::io::Result<()> {
        // Cap the per-record error list so a `Rejected` reload over
        // a badly broken multi-file config can't produce a record large
        // enough to risk a torn O_APPEND write (or bloat the log). Keep the
        // first N + a synthetic marker. Clone only on the rare overflow path.
        let capped;
        let record = if record.errors.len() > MAX_AUDIT_RECORD_ERRORS {
            let extra = record.errors.len() - MAX_AUDIT_RECORD_ERRORS;
            let mut r = record.clone();
            r.errors.truncate(MAX_AUDIT_RECORD_ERRORS);
            r.errors
                .push(format!("… and {extra} more error(s) (truncated)"));
            capped = r;
            &capped
        } else {
            record
        };
        let mut line = serde_json::to_string(record).map_err(std::io::Error::other)?;
        line.push('\n');
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .mode(AUDIT_FILE_MODE)
            .open(&self.path)?;
        let _advisory = AdvisoryFileLock::exclusive(&file)?;
        restore_audit_line_boundary(&file)?;
        #[cfg(test)]
        if let Some(bytes) = lock_unpoisoned(&self.fail_after_bytes).take() {
            (&file).write_all(&line.as_bytes()[..bytes.min(line.len() - 1)])?;
            return Err(std::io::Error::other("injected partial audit write"));
        }
        (&file).write_all(line.as_bytes())?;
        file.sync_data()?;
        Ok(())
    }

    /// Append a CLI-mutation record. Same on-disk
    /// shape as [`AuditWriter::append`], but the [`AuditEvent`] is
    /// [`AuditEvent::CliMutation`] and the new optional fields carry
    /// the mutation context. Called by every `warden <verb>` rule
    /// write before the IPC reload fires, so the trail survives even
    /// when the daemon never sees the write (offline writes).
    pub fn append_cli_mutation(&self, record: &AuditRecord) -> std::io::Result<()> {
        debug_assert_eq!(record.event, AuditEvent::CliMutation);
        self.append(record)
    }

    /// Build a restart-safe, deduplicating sink over this audit log.
    pub fn operator_rules_sink(&self) -> std::io::Result<UorAuditSink> {
        UorAuditSink::open(self.clone())
    }
}

/// Successful delivery status for one operator-rules audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UorAuditDelivery {
    Recorded,
    AlreadyRecorded,
}

/// A post-commit audit failure is pending work, never evidence that the
/// transaction itself failed or should be rolled back.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UorAuditSinkError {
    #[error("operator-rules audit is pending for {operation_id}: {detail}")]
    Pending {
        operation_id: String,
        detail: String,
    },
    #[error("operator-rules audit operation id {operation_id} has different event data")]
    Conflict { operation_id: String },
    #[error("invalid operator-rules audit field: {field}")]
    Invalid { field: &'static str },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum UorAuditIndexState {
    Pending,
    Recorded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UorAuditIndexEntry {
    event_hash: String,
    state: UorAuditIndexState,
    updated_unix_seconds: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UorAuditIndex {
    format_version: u32,
    entries: BTreeMap<String, UorAuditIndexEntry>,
    /// Receipt creation times at or below this watermark may have been pruned,
    /// even if the wall clock subsequently moved backwards. Missing means legacy.
    /// `u64::MAX` preserves recovery for legacy evidence with an unknown age floor.
    #[serde(default)]
    pruned_through_unix_seconds: Option<u64>,
}

impl Default for UorAuditIndex {
    fn default() -> Self {
        Self {
            format_version: UOR_AUDIT_INDEX_FORMAT,
            entries: BTreeMap::new(),
            pruned_through_unix_seconds: Some(0),
        }
    }
}

#[derive(Deserialize)]
struct UorAuditProbe {
    #[serde(default)]
    ts: Option<String>,
    #[serde(default)]
    event: Option<String>,
    #[serde(default)]
    uor_operation: Option<UorOperationAuditEvent>,
    #[serde(default)]
    uor_event_hash: Option<String>,
    #[serde(default)]
    uor_index_time_floor_unix_seconds: Option<u64>,
}

enum ExistingAuditEvent {
    Absent,
    Matching,
    Conflicting,
}

struct AdvisoryFileLock<'a> {
    file: &'a File,
}

impl<'a> AdvisoryFileLock<'a> {
    fn exclusive(file: &'a File) -> std::io::Result<Self> {
        // SAFETY: flock only reads the live descriptor value and retains no
        // userspace pointer. `file` is borrowed for the guard's full lifetime.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if result == 0 {
            Ok(Self { file })
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

impl Drop for AdvisoryFileLock<'_> {
    fn drop(&mut self) {
        // SAFETY: the borrowed file remains live until after this guard drops.
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// Append-only operator-rules audit sink with a durable idempotency index.
///
/// A small process mutex handles cloned sinks; an advisory side lock handles
/// independently opened sinks. Neither is used by DNS queries. All audit appends
/// also lock the log file to protect line boundaries. The index records `pending`
/// before the JSON append and `recorded` afterwards. Recovery checks the log for
/// pending or expired entries; receipt delivery can outlive index retention.
#[derive(Debug, Clone)]
pub struct UorAuditSink {
    writer: AuditWriter,
    index_path: PathBuf,
    lock_file: Arc<File>,
    process_lock: Arc<Mutex<()>>,
}

impl UorAuditSink {
    fn open(writer: AuditWriter) -> std::io::Result<Self> {
        let index_path = suffixed_path(writer.path(), ".uor-index");
        let lock_path = suffixed_path(writer.path(), ".uor-lock");
        let index_exists = index_path.exists();
        let lock_file = open_sidecar(&lock_path)?;
        let sink = Self {
            writer,
            index_path,
            lock_file: Arc::new(lock_file),
            process_lock: Arc::new(Mutex::new(())),
        };
        if !index_exists {
            let _process = lock_unpoisoned(&sink.process_lock);
            let _advisory = AdvisoryFileLock::exclusive(&sink.lock_file)?;
            if !sink.index_path.exists() {
                let index = sink.rebuild_index()?;
                sink.write_index(&index)?;
            }
        }
        Ok(sink)
    }

    pub fn record(
        &self,
        event: &UorOperationAuditEvent,
    ) -> Result<UorAuditDelivery, UorAuditSinkError> {
        self.record_at(event, unix_seconds(), None)
    }

    /// Deliver a persisted receipt's event. Its trusted creation time keeps
    /// fresh operations off the historical recovery scan: their index entries
    /// cannot yet have expired, unless the persisted pruning watermark says
    /// otherwise. Callers must use the original receipt timestamp.
    pub(crate) fn record_for_receipt(
        &self,
        event: &UorOperationAuditEvent,
        created_unix_seconds: u64,
    ) -> Result<UorAuditDelivery, UorAuditSinkError> {
        self.record_at(event, unix_seconds(), Some(created_unix_seconds))
    }

    fn record_at(
        &self,
        event: &UorOperationAuditEvent,
        now: u64,
        created_unix_seconds: Option<u64>,
    ) -> Result<UorAuditDelivery, UorAuditSinkError> {
        // A backward clock step must not age the index before its receipt.
        let updated = now.max(created_unix_seconds.unwrap_or(now));
        let event = normalize_uor_event(event.clone())?;
        let event_bytes = serde_json::to_vec(&event).map_err(|_| UorAuditSinkError::Invalid {
            field: "event encoding",
        })?;
        if event_bytes.len() > MAX_UOR_AUDIT_EVENT_BYTES {
            return Err(UorAuditSinkError::Invalid {
                field: "event size",
            });
        }
        let event_hash = uor_event_hash(&event_bytes);
        let operation_id = event.identity.operation_id.clone();
        let pending = |detail: String| UorAuditSinkError::Pending {
            operation_id: operation_id.clone(),
            detail,
        };

        let _process = lock_unpoisoned(&self.process_lock);
        let _advisory = AdvisoryFileLock::exclusive(&self.lock_file)
            .map_err(|error| pending(error.to_string()))?;
        let mut index = self
            .read_index()
            .map_err(|error| pending(error.to_string()))?;

        if let Some(entry) = index.entries.get(&operation_id) {
            if entry.event_hash != event_hash {
                return Err(UorAuditSinkError::Conflict { operation_id });
            }
            if entry.state == UorAuditIndexState::Recorded {
                return Ok(UorAuditDelivery::AlreadyRecorded);
            }
        }
        // The receipt's pending marker has an independent lifetime, so expiry
        // of this bounded index cannot authorize another logical event.
        let needs_recovery = index.entries.contains_key(&operation_id)
            || created_unix_seconds.is_none_or(|created| {
                created <= index.pruned_through_unix_seconds.unwrap_or(u64::MAX)
                    || now.saturating_sub(created) > UOR_AUDIT_DEDUP_RETENTION_SECS
            });
        if needs_recovery {
            match self
                .find_existing_event(&operation_id, &event_hash)
                .map_err(|error| pending(error.to_string()))?
            {
                ExistingAuditEvent::Matching => {
                    if let Some(entry) = index.entries.get_mut(&operation_id) {
                        entry.state = UorAuditIndexState::Recorded;
                        entry.updated_unix_seconds = updated;
                        self.write_index(&index)
                            .map_err(|error| pending(error.to_string()))?;
                    }
                    return Ok(UorAuditDelivery::AlreadyRecorded);
                }
                ExistingAuditEvent::Conflicting => {
                    return Err(UorAuditSinkError::Conflict { operation_id });
                }
                ExistingAuditEvent::Absent => {}
            }
        }
        if !index.entries.contains_key(&operation_id) {
            let mut pruned_through = index.pruned_through_unix_seconds.unwrap_or(u64::MAX);
            index.entries.retain(|_, entry| {
                let retain = entry.state == UorAuditIndexState::Pending
                    || now.saturating_sub(entry.updated_unix_seconds)
                        <= UOR_AUDIT_DEDUP_RETENTION_SECS;
                if !retain {
                    pruned_through = pruned_through.max(entry.updated_unix_seconds);
                }
                retain
            });
            index.pruned_through_unix_seconds = Some(pruned_through);
            if index.entries.len() >= MAX_UOR_AUDIT_DEDUP_ENTRIES {
                return Err(pending("deduplication index is at capacity".into()));
            }
            index.entries.insert(
                operation_id.clone(),
                UorAuditIndexEntry {
                    event_hash: event_hash.clone(),
                    state: UorAuditIndexState::Pending,
                    updated_unix_seconds: updated,
                },
            );
            self.write_index(&index)
                .map_err(|error| pending(error.to_string()))?;
        }

        let result = if event.outcome.persistence == UorAuditPersistence::Committed {
            AuditResult::Ok
        } else {
            AuditResult::Rejected
        };
        let mut record = AuditRecord::new(AuditEvent::OperatorRulesOperation, result);
        record.ts = OffsetDateTime::from_unix_timestamp(
            i64::try_from(now).map_err(|error| pending(error.to_string()))?,
        )
        .map_err(|error| pending(error.to_string()))?
        .format(&Rfc3339)
        .map_err(|error| pending(error.to_string()))?;
        record.uor_operation = Some(event);
        record.uor_event_hash = Some(event_hash);
        record.uor_index_time_floor_unix_seconds = created_unix_seconds.map(|_| updated);
        self.writer
            .append(&record)
            .map_err(|error| pending(error.to_string()))?;

        let entry = index
            .entries
            .get_mut(&operation_id)
            .expect("new audit entry remains indexed");
        entry.state = UorAuditIndexState::Recorded;
        entry.updated_unix_seconds = updated;
        self.write_index(&index)
            .map_err(|error| pending(error.to_string()))?;
        Ok(UorAuditDelivery::Recorded)
    }

    fn read_index(&self) -> std::io::Result<UorAuditIndex> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.index_path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let index = self.rebuild_index()?;
                self.write_index(&index)?;
                return Ok(index);
            }
            Err(error) => return Err(error),
        };
        let limit = MAX_UOR_AUDIT_EVENT_BYTES
            .saturating_mul(MAX_UOR_AUDIT_DEDUP_ENTRIES)
            .min(8 * 1024 * 1024);
        if file.metadata()?.len() > limit as u64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "operator-rules audit index exceeds its size limit",
            ));
        }
        let mut bytes = Vec::new();
        file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "operator-rules audit index exceeds its size limit",
            ));
        }
        let mut index: UorAuditIndex =
            serde_json::from_slice(&bytes).map_err(std::io::Error::other)?;
        if !matches!(index.format_version, 1 | UOR_AUDIT_INDEX_FORMAT)
            || index.entries.len() > MAX_UOR_AUDIT_DEDUP_ENTRIES
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unsupported or oversized operator-rules audit index",
            ));
        }
        if index.format_version != UOR_AUDIT_INDEX_FORMAT
            || index.pruned_through_unix_seconds.is_none()
        {
            // Older indices may derive ages from wall-clock log timestamps,
            // which do not bound receipt creation after a backwards clock step.
            index.format_version = UOR_AUDIT_INDEX_FORMAT;
            index.pruned_through_unix_seconds = Some(u64::MAX);
            self.write_index(&index)?;
        }
        Ok(index)
    }

    fn write_index(&self, index: &UorAuditIndex) -> std::io::Result<()> {
        let bytes = serde_json::to_vec(index).map_err(std::io::Error::other)?;
        super::atomic_write::hardened_atomic_write(
            &self.index_path,
            &bytes,
            super::atomic_write::AtomicWriteOpts {
                mode: Some(AUDIT_FILE_MODE),
                ..Default::default()
            },
        )
        .map_err(std::io::Error::other)
    }

    fn rebuild_index(&self) -> std::io::Result<UorAuditIndex> {
        self.rebuild_index_at(unix_seconds())
    }

    fn rebuild_index_at(&self, now: u64) -> std::io::Result<UorAuditIndex> {
        let mut index = UorAuditIndex::default();
        scan_uor_audit_lines(self.writer.path(), |probe, event, event_hash| {
            let updated = match probe.uor_index_time_floor_unix_seconds {
                Some(floor) => floor,
                None => {
                    // A legacy timestamp cannot bound receipt creation. Keep
                    // missing identities recoverable regardless of clock age.
                    index.pruned_through_unix_seconds = Some(u64::MAX);
                    probe
                        .ts
                        .as_deref()
                        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
                        .and_then(|value| u64::try_from(value.unix_timestamp()).ok())
                        .unwrap_or(now)
                }
            };
            if now.saturating_sub(updated) > UOR_AUDIT_DEDUP_RETENTION_SECS {
                index.pruned_through_unix_seconds =
                    Some(index.pruned_through_unix_seconds.unwrap_or(0).max(updated));
                return Ok(());
            }
            let operation_id = event.identity.operation_id.clone();
            match index.entries.get(&operation_id) {
                Some(existing) if existing.event_hash != event_hash => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "conflicting operator-rules events in audit log",
                )),
                Some(_) => Ok(()),
                None if index.entries.len() >= MAX_UOR_AUDIT_DEDUP_ENTRIES => {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "operator-rules audit index is at capacity",
                    ))
                }
                None => {
                    index.entries.insert(
                        operation_id,
                        UorAuditIndexEntry {
                            event_hash: event_hash.to_string(),
                            state: UorAuditIndexState::Recorded,
                            updated_unix_seconds: updated,
                        },
                    );
                    Ok(())
                }
            }
        })?;
        Ok(index)
    }

    fn find_existing_event(
        &self,
        operation_id: &str,
        expected_hash: &str,
    ) -> std::io::Result<ExistingAuditEvent> {
        let mut found = ExistingAuditEvent::Absent;
        scan_uor_audit_lines(self.writer.path(), |_, event, event_hash| {
            if event.identity.operation_id == operation_id {
                if event_hash != expected_hash {
                    found = ExistingAuditEvent::Conflicting;
                } else if !matches!(found, ExistingAuditEvent::Conflicting) {
                    found = ExistingAuditEvent::Matching;
                }
            }
            Ok(())
        })?;
        if matches!(found, ExistingAuditEvent::Matching) {
            let file = OpenOptions::new()
                .read(true)
                .append(true)
                .open(self.writer.path())?;
            let _advisory = AdvisoryFileLock::exclusive(&file)?;
            restore_audit_line_boundary(&file)?;
            // A prior append may have written all JSON bytes but failed its
            // final newline or sync. Recovery acknowledges only durable data.
            file.sync_data()?;
        }
        Ok(found)
    }
}

fn normalize_uor_event(
    mut event: UorOperationAuditEvent,
) -> Result<UorOperationAuditEvent, UorAuditSinkError> {
    validate_bounded_text(
        &event.identity.operation_id,
        MAX_UOR_AUDIT_ID_BYTES,
        "identity.operation_id",
    )?;
    validate_bounded_text(
        &event.identity.request_id,
        MAX_UOR_AUDIT_ID_BYTES,
        "identity.request_id",
    )?;
    validate_bounded_text(
        &event.identity.actor,
        MAX_UOR_AUDIT_ACTOR_BYTES,
        "identity.actor",
    )?;
    validate_bounded_text(
        &event.identity.operation,
        MAX_UOR_AUDIT_OPERATION_BYTES,
        "identity.operation",
    )?;
    validate_digest(
        &event.revisions.before_config_revision,
        "revisions.before_config_revision",
    )?;
    validate_digest(
        &event.revisions.after_config_revision,
        "revisions.after_config_revision",
    )?;
    for (value, field) in [
        (
            event.revisions.before_operator_policy_hash.as_deref(),
            "revisions.before_operator_policy_hash",
        ),
        (
            event.revisions.after_operator_policy_hash.as_deref(),
            "revisions.after_operator_policy_hash",
        ),
    ] {
        if let Some(value) = value {
            validate_digest(value, field)?;
        }
    }

    event.entities.list_ids.sort();
    event.entities.list_ids.dedup();
    event.entities.profile_ids.sort();
    event.entities.profile_ids.dedup();
    if event.entities.list_ids.len() > MAX_UOR_AUDIT_ENTITY_IDS {
        return Err(UorAuditSinkError::Invalid {
            field: "entities.list_ids",
        });
    }
    if event.entities.profile_ids.len() > MAX_UOR_AUDIT_ENTITY_IDS {
        return Err(UorAuditSinkError::Invalid {
            field: "entities.profile_ids",
        });
    }
    for id in &event.entities.list_ids {
        validate_entity_id(id, "entities.list_ids")?;
    }
    for id in &event.entities.profile_ids {
        validate_entity_id(id, "entities.profile_ids")?;
    }
    Ok(event)
}

fn validate_bounded_text(
    value: &str,
    max_bytes: usize,
    field: &'static str,
) -> Result<(), UorAuditSinkError> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(|ch| ch.is_control()) {
        Err(UorAuditSinkError::Invalid { field })
    } else {
        Ok(())
    }
}

fn validate_entity_id(value: &str, field: &'static str) -> Result<(), UorAuditSinkError> {
    if value.is_empty()
        || value.len() > 64
        || value.starts_with('-')
        || value.ends_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        Err(UorAuditSinkError::Invalid { field })
    } else {
        Ok(())
    }
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), UorAuditSinkError> {
    let digest = value.strip_prefix("sha256:").unwrap_or(value);
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Err(UorAuditSinkError::Invalid { field })
    } else {
        Ok(())
    }
}

fn uor_event_hash(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"purge-warden/uor-audit-event/v1\0");
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn scan_uor_audit_lines(
    path: &Path,
    mut visit: impl FnMut(&UorAuditProbe, &UorOperationAuditEvent, &str) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let _advisory = AdvisoryFileLock::exclusive(&file)?;
    // Bound memory per line and scan only the file length seen on entry.
    // Oversized evidence fails closed instead of silently losing an identity.
    let mut reader = BufReader::new((&file).take(file.metadata()?.len()));
    let mut line = Vec::new();
    const MAX_LINE_BYTES: usize = MAX_UOR_AUDIT_EVENT_BYTES * 2;
    loop {
        line.clear();
        let read = reader
            .by_ref()
            .take(MAX_LINE_BYTES as u64 + 1)
            .read_until(b'\n', &mut line)?;
        if read == 0 {
            break;
        }
        if read > MAX_LINE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "audit line exceeds operator-rules recovery limit",
            ));
        }
        let Ok(probe) = serde_json::from_slice::<UorAuditProbe>(&line) else {
            continue;
        };
        if probe.event.as_deref() != Some("operator_rules_operation") {
            continue;
        }
        let event = probe.uor_operation.as_ref().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "operator-rules audit line is missing its event data",
            )
        })?;
        let stored_hash = probe.uor_event_hash.as_deref().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "operator-rules audit line is missing its event hash",
            )
        })?;
        let normalized = normalize_uor_event(event.clone())
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        let bytes = serde_json::to_vec(&normalized).map_err(std::io::Error::other)?;
        let calculated_hash = uor_event_hash(&bytes);
        if calculated_hash != stored_hash {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "operator-rules audit event hash mismatch",
            ));
        }
        visit(&probe, &normalized, &calculated_hash)?;
    }
    Ok(())
}

fn restore_audit_line_boundary(mut file: &File) -> std::io::Result<()> {
    if file.metadata()?.len() != 0 {
        file.seek(SeekFrom::End(-1))?;
        let mut last = [0];
        file.read_exact(&mut last)?;
        if last[0] != b'\n' {
            file.write_all(b"\n")?;
        }
    }
    Ok(())
}

fn suffixed_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn open_sidecar(path: &Path) -> std::io::Result<File> {
    let existed = path.exists();
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(AUDIT_FILE_MODE)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    if !existed {
        fs::set_permissions(path, fs::Permissions::from_mode(AUDIT_FILE_MODE))?;
    }
    Ok(file)
}

fn lock_unpoisoned<T>(lock: &Mutex<T>) -> MutexGuard<'_, T> {
    lock.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn unix_seconds() -> u64 {
    u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).unwrap_or(0)
}

/// SHA-256 of a single file, lowercase hex. Used to form the per-file
/// contribution to a tree hash.
pub fn hash_file(path: &Path) -> std::io::Result<String> {
    let bytes = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

/// Aggregate content hash of every file in `files`. Inputs are sorted +
/// deduplicated first so two callers with different iteration orders
/// produce the same hash. *Missing* files (ENOENT) are skipped silently —
/// the hash reflects what was actually present. An *unreadable* file (it
/// exists but EACCES / EIO / ELOOP) instead folds a distinct sentinel, so
/// a member becoming unreadable perturbs the digest differently from both
/// "present with bytes" and "absent" — otherwise an integrity-relevant
/// "file became unreadable" change would be invisible to anyone diffing
/// `pre_hash`/`post_hash`. Returns `None` when nothing was hashed (empty
/// input or every path missing).
pub fn tree_hash<I, P>(files: I) -> Option<String>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    let mut paths: Vec<String> = files
        .into_iter()
        .map(|p| p.as_ref().display().to_string())
        .collect();
    paths.sort();
    paths.dedup();

    let mut aggregator = Sha256::new();
    let mut seen_any = false;
    for path_str in paths {
        match hash_file(Path::new(&path_str)) {
            Ok(h) => {
                aggregator.update(path_str.as_bytes());
                aggregator.update(b":");
                aggregator.update(h.as_bytes());
                aggregator.update(b"\n");
                seen_any = true;
            }
            // Absent (never existed / deleted): skipped silently so a file
            // that was never part of the tree does not perturb the digest.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            // Exists but unreadable: fold the path plus a sentinel that can
            // never collide with a real lowercase-hex digest, so it is
            // distinct from both "present with bytes" and "absent".
            Err(_) => {
                aggregator.update(path_str.as_bytes());
                aggregator.update(b":");
                aggregator.update(b"<unreadable>");
                aggregator.update(b"\n");
                seen_any = true;
            }
        }
    }
    if seen_any {
        Some(hex::encode(aggregator.finalize()))
    } else {
        None
    }
}

/// Read the last `n` records from an audit log. Used by `warden audit tail`.
/// Returns each record as `(raw_json_line, parsed)`; raw is kept so the CLI
/// can display the exact bytes on disk even if the parser struct has drifted.
/// Errors on IO failure; malformed lines are reported as `Err` inside the
/// parsed side.
pub fn tail(path: &Path, n: usize) -> std::io::Result<Vec<(String, Result<AuditRecord, String>)>> {
    // Bounded back-scan. Read the file's tail in chunks from the
    // END until we've seen enough lines (or reached the start), rather than
    // slurping a possibly-large audit.log whole for a small `tail`. Bytes
    // are reassembled before decoding so a UTF-8 char split across a chunk
    // boundary still decodes; per-line `from_utf8_lossy` then keeps the old
    // graceful-degradation contract — a single non-UTF-8 byte (torn write,
    // corruption) degrades to ONE parse `Err` row, never hides the rest.
    let mut file = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut pos = file.metadata()?.len();
    const CHUNK: u64 = 64 * 1024;
    let mut bytes: Vec<u8> = Vec::new();
    let mut newlines = 0usize;
    while pos > 0 && newlines <= n {
        let read_size = CHUNK.min(pos);
        pos -= read_size;
        file.seek(SeekFrom::Start(pos))?;
        let mut chunk = vec![0u8; read_size as usize];
        file.read_exact(&mut chunk)?;
        newlines += chunk.iter().filter(|&&b| b == b'\n').count();
        chunk.extend_from_slice(&bytes);
        bytes = chunk;
    }

    let lines: Vec<String> = bytes
        .split(|&b| b == b'\n')
        .map(|l| String::from_utf8_lossy(l).into_owned())
        .filter(|l| !l.trim().is_empty())
        .collect();
    let start = lines.len().saturating_sub(n);
    let tail = &lines[start..];

    let mut out = Vec::with_capacity(tail.len());
    for raw in tail {
        let parsed: Result<AuditRecord, String> =
            serde_json::from_str::<AuditRecord>(raw).map_err(|e| e.to_string());
        out.push((raw.clone(), parsed));
    }
    Ok(out)
}

// serde Deserialize wiring for replay. Kept as a separate impl block so
// the write-path module above stays focused on the producer side.
impl<'de> serde::Deserialize<'de> for AuditEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "boot" => Ok(Self::Boot),
            "reload" => Ok(Self::Reload),
            "shutdown" => Ok(Self::Shutdown),
            "restore" => Ok(Self::Restore),
            "cli_mutation" => Ok(Self::CliMutation),
            "cname_block" => Ok(Self::CnameBlock),
            "operator_rules_operation" => Ok(Self::OperatorRulesOperation),
            other => Err(serde::de::Error::custom(format!(
                "unknown audit event: {other}"
            ))),
        }
    }
}

impl<'de> serde::Deserialize<'de> for AuditResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "ok" => Ok(Self::Ok),
            "rejected" => Ok(Self::Rejected),
            other => Err(serde::de::Error::custom(format!(
                "unknown audit result: {other}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmp_dir(tag: &str) -> PathBuf {
        static CTR: AtomicU64 = AtomicU64::new(0);
        let pid = std::process::id();
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("purge-audit-{pid}-{n}-{tag}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn uor_event(operation_id: &str) -> UorOperationAuditEvent {
        UorOperationAuditEvent {
            identity: UorAuditIdentity {
                operation_id: operation_id.into(),
                request_id: "request-1".into(),
                actor: "uid:1000".into(),
                origin: UorAuditOrigin::Ipc,
                operation: "operator_rules.batch.v1".into(),
            },
            revisions: UorAuditRevisions {
                before_config_revision: "1".repeat(64),
                after_config_revision: "2".repeat(64),
                before_operator_policy_hash: Some("3".repeat(64)),
                after_operator_policy_hash: Some("4".repeat(64)),
            },
            entities: UorAuditEntities {
                list_ids: vec!["household-rules".into()],
                profile_ids: vec!["household".into()],
            },
            counts: UorAuditCounts {
                operations: 2,
                changed_members: 2,
                rules_added: 1,
                mounts_added: 1,
                ..Default::default()
            },
            impact: UorAuditImpact {
                affected_profiles: 1,
                affected_destinations: 4,
                potential_destinations: 7,
                truncated: false,
            },
            outcome: UorAuditOutcome {
                persistence: UorAuditPersistence::Committed,
                activation: UorAuditActivation::Pending,
                replication: UorAuditReplication::NotConfigured,
            },
            changed: true,
        }
    }

    fn uor_line_count(path: &Path) -> usize {
        tail(path, usize::MAX)
            .unwrap()
            .into_iter()
            .filter(|(_, parsed)| {
                parsed
                    .as_ref()
                    .is_ok_and(|record| record.event == AuditEvent::OperatorRulesOperation)
            })
            .count()
    }

    #[test]
    fn uor_retry_is_one_logical_event_across_reopen() {
        let root = tmp_dir("uor-reopen");
        let path = root.join("audit.log");
        let writer = AuditWriter::open(path.clone()).unwrap();
        let sink = writer.operator_rules_sink().unwrap();
        let event = uor_event("operation-reopen");

        assert_eq!(sink.record(&event).unwrap(), UorAuditDelivery::Recorded);
        assert_eq!(
            sink.record(&event).unwrap(),
            UorAuditDelivery::AlreadyRecorded
        );
        drop(sink);

        let reopened = AuditWriter::open(path.clone())
            .unwrap()
            .operator_rules_sink()
            .unwrap();
        assert_eq!(
            reopened.record(&event).unwrap(),
            UorAuditDelivery::AlreadyRecorded
        );
        assert_eq!(uor_line_count(&path), 1);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn uor_pending_index_recovers_append_without_duplicate() {
        let root = tmp_dir("uor-pending-recovery");
        let path = root.join("audit.log");
        let sink = AuditWriter::open(path.clone())
            .unwrap()
            .operator_rules_sink()
            .unwrap();
        let event = uor_event("operation-pending-recovery");
        sink.record(&event).unwrap();

        let mut index = sink.read_index().unwrap();
        index
            .entries
            .get_mut(&event.identity.operation_id)
            .unwrap()
            .state = UorAuditIndexState::Pending;
        sink.write_index(&index).unwrap();
        drop(sink);

        let reopened = AuditWriter::open(path.clone())
            .unwrap()
            .operator_rules_sink()
            .unwrap();
        assert_eq!(
            reopened.record(&event).unwrap(),
            UorAuditDelivery::AlreadyRecorded
        );
        assert_eq!(uor_line_count(&path), 1);
        assert_eq!(
            reopened
                .read_index()
                .unwrap()
                .entries
                .get(&event.identity.operation_id)
                .unwrap()
                .state,
            UorAuditIndexState::Recorded
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn uor_partial_append_preserves_evidence_and_retries_in_process() {
        for cut in [37, usize::MAX] {
            let root = tmp_dir("uor-partial-append");
            let path = root.join("audit.log");
            let writer = AuditWriter::open(path.clone()).unwrap();
            let sink = writer.operator_rules_sink().unwrap();
            let event = uor_event("operation-partial-append");
            *lock_unpoisoned(&writer.fail_after_bytes) = Some(cut);

            assert!(matches!(
                sink.record(&event),
                Err(UorAuditSinkError::Pending { .. })
            ));
            let fragment = fs::read(&path).unwrap();
            assert!(!fragment.is_empty());
            assert_ne!(fragment.last(), Some(&b'\n'));
            assert_eq!(
                sink.read_index().unwrap().entries[&event.identity.operation_id].state,
                UorAuditIndexState::Pending
            );

            let delivery = sink.record(&event).unwrap();
            assert_eq!(
                delivery,
                if cut == usize::MAX {
                    UorAuditDelivery::AlreadyRecorded
                } else {
                    UorAuditDelivery::Recorded
                }
            );
            let repaired = fs::read(&path).unwrap();
            assert!(repaired.starts_with(&fragment));
            assert_eq!(repaired[fragment.len()], b'\n');
            assert_eq!(repaired.last(), Some(&b'\n'));
            assert_eq!(uor_line_count(&path), 1);
            assert_eq!(
                sink.read_index().unwrap().entries[&event.identity.operation_id].state,
                UorAuditIndexState::Recorded
            );
            assert_eq!(
                sink.record(&event).unwrap(),
                UorAuditDelivery::AlreadyRecorded
            );
            let reopened = AuditWriter::open(path.clone())
                .unwrap()
                .operator_rules_sink()
                .unwrap();
            assert_eq!(
                reopened.record(&event).unwrap(),
                UorAuditDelivery::AlreadyRecorded
            );
            assert_eq!(fs::read(&path).unwrap(), repaired);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn uor_partial_append_coordinates_independent_retries_and_lifecycle_writes() {
        let root = tmp_dir("uor-partial-concurrent");
        let path = root.join("audit.log");
        let writer = AuditWriter::open(path.clone()).unwrap();
        let sink = writer.operator_rules_sink().unwrap();
        let event = uor_event("operation-partial-concurrent");
        *lock_unpoisoned(&writer.fail_after_bytes) = Some(37);
        assert!(matches!(
            sink.record(&event),
            Err(UorAuditSinkError::Pending { .. })
        ));
        let fragment = fs::read(&path).unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(3));
        std::thread::scope(|scope| {
            for _ in 0..2 {
                let sink = AuditWriter::open(path.clone())
                    .unwrap()
                    .operator_rules_sink()
                    .unwrap();
                let barrier = barrier.clone();
                let event = &event;
                scope.spawn(move || {
                    barrier.wait();
                    sink.record(event).unwrap();
                });
            }
            scope.spawn(|| {
                barrier.wait();
                writer
                    .append(&AuditRecord::new(AuditEvent::Reload, AuditResult::Ok))
                    .unwrap();
            });
        });
        assert!(fs::read(&path).unwrap().starts_with(&fragment));
        let rows = tail(&path, 10).unwrap();
        assert_eq!(rows.len(), 3);
        assert!(rows[0].1.is_err());
        assert!(rows[1..].iter().all(|(_, record)| record.is_ok()));
        assert_eq!(uor_line_count(&path), 1);
        assert_eq!(
            sink.record(&event).unwrap(),
            UorAuditDelivery::AlreadyRecorded
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn uor_pending_receipt_replay_survives_recorded_index_pruning() {
        let root = tmp_dir("uor-expired-index");
        let path = root.join("audit.log");
        let sink = AuditWriter::open(path.clone())
            .unwrap()
            .operator_rules_sink()
            .unwrap();
        let event = uor_event("operation-pending-receipt");
        let created = 100;
        sink.record_at(&event, created, Some(created)).unwrap();
        let later = created + UOR_AUDIT_DEDUP_RETENTION_SECS + 1;
        sink.record_at(&uor_event("operation-pruning-trigger"), later, Some(later))
            .unwrap();
        assert!(!sink
            .read_index()
            .unwrap()
            .entries
            .contains_key(&event.identity.operation_id));
        let before = fs::read(&path).unwrap();
        assert_eq!(
            sink.record_at(&event, later, Some(created)).unwrap(),
            UorAuditDelivery::AlreadyRecorded
        );
        let mut conflicting = event.clone();
        conflicting.counts.rules_added += 1;
        assert!(matches!(
            sink.record_at(&conflicting, later, Some(created)),
            Err(UorAuditSinkError::Conflict { .. })
        ));
        let reopened = AuditWriter::open(path.clone())
            .unwrap()
            .operator_rules_sink()
            .unwrap();
        assert_eq!(
            reopened.record_at(&event, later, Some(created)).unwrap(),
            UorAuditDelivery::AlreadyRecorded
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(uor_line_count(&path), 2);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn uor_pruning_watermark_survives_clock_rollback_and_reopen() {
        let root = tmp_dir("uor-prune-rollback");
        let path = root.join("audit.log");
        let sink = AuditWriter::open(path.clone())
            .unwrap()
            .operator_rules_sink()
            .unwrap();
        let event = uor_event("operation-before-rollback");
        sink.record_at(&event, 100, Some(100)).unwrap();
        sink.record_at(&uor_event("operation-prune"), 86_501, Some(86_501))
            .unwrap();
        let index = sink.read_index().unwrap();
        assert_eq!(index.pruned_through_unix_seconds, Some(100));
        assert!(!index.entries.contains_key(&event.identity.operation_id));
        drop(sink);

        let reopened = AuditWriter::open(path.clone())
            .unwrap()
            .operator_rules_sink()
            .unwrap();
        let before = fs::read(&path).unwrap();
        assert_eq!(
            reopened.record_at(&event, 150, Some(100)).unwrap(),
            UorAuditDelivery::AlreadyRecorded
        );
        let mut conflicting = event.clone();
        conflicting.counts.rules_added += 1;
        assert!(matches!(
            reopened.record_at(&conflicting, 150, Some(100)),
            Err(UorAuditSinkError::Conflict { .. })
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(uor_line_count(&path), 2);

        // A genuinely new operation beyond the watermark still skips history.
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&vec![b'x'; MAX_UOR_AUDIT_EVENT_BYTES * 2 + 1])
            .unwrap();
        file.write_all(b"\n").unwrap();
        assert_eq!(
            reopened
                .record_at(&uor_event("operation-after-rollback"), 150, Some(150))
                .unwrap(),
            UorAuditDelivery::Recorded
        );
        assert_eq!(
            reopened.read_index().unwrap().pruned_through_unix_seconds,
            Some(100)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn uor_rebuilt_index_preserves_pruning_watermark_after_clock_rollback() {
        let root = tmp_dir("uor-rebuild-rollback");
        let path = root.join("audit.log");
        let sink = AuditWriter::open(path.clone())
            .unwrap()
            .operator_rules_sink()
            .unwrap();
        let event = uor_event("operation-before-rebuild");
        // Receipt creation predates a backward clock step during first delivery.
        sink.record_at(&event, 50, Some(100)).unwrap();
        let row = tail(&path, 1).unwrap().pop().unwrap().1.unwrap();
        assert_eq!(row.ts, "1970-01-01T00:00:50Z");
        assert_eq!(row.uor_index_time_floor_unix_seconds, Some(100));
        assert_eq!(
            row.uor_event_hash.unwrap(),
            uor_event_hash(
                &serde_json::to_vec(&normalize_uor_event(event.clone()).unwrap()).unwrap()
            )
        );
        sink.record_at(
            &uor_event("operation-rebuild-trigger"),
            86_501,
            Some(86_501),
        )
        .unwrap();
        let rebuilt = sink.rebuild_index_at(86_501).unwrap();
        assert_eq!(rebuilt.pruned_through_unix_seconds, Some(100));
        assert!(!rebuilt.entries.contains_key(&event.identity.operation_id));
        sink.write_index(&rebuilt).unwrap();
        drop(sink);
        let reopened = AuditWriter::open(path.clone())
            .unwrap()
            .operator_rules_sink()
            .unwrap();
        let before = fs::read(&path).unwrap();
        assert_eq!(
            reopened.record_at(&event, 150, Some(100)).unwrap(),
            UorAuditDelivery::AlreadyRecorded
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(uor_line_count(&path), 2);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn uor_legacy_log_without_receipt_floor_recovers_after_rebuild_and_rollback() {
        let root = tmp_dir("uor-legacy-log-floor");
        let path = root.join("audit.log");
        let writer = AuditWriter::open(path.clone()).unwrap();
        let sink = writer.operator_rules_sink().unwrap();
        let event = normalize_uor_event(uor_event("operation-legacy-clock")).unwrap();
        let mut legacy = AuditRecord::new(AuditEvent::OperatorRulesOperation, AuditResult::Ok);
        legacy.ts = "1970-01-01T00:00:50Z".into();
        legacy.uor_event_hash = Some(uor_event_hash(&serde_json::to_vec(&event).unwrap()));
        legacy.uor_operation = Some(event.clone());
        assert!(!serde_json::to_value(&legacy)
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("uor_index_time_floor_unix_seconds"));
        writer.append(&legacy).unwrap();
        fs::remove_file(&sink.index_path).unwrap();

        let rebuilt = sink.rebuild_index_at(86_501).unwrap();
        assert!(rebuilt.entries.is_empty());
        assert_eq!(rebuilt.pruned_through_unix_seconds, Some(u64::MAX));
        sink.write_index(&rebuilt).unwrap();
        drop(sink);
        let reopened = writer.operator_rules_sink().unwrap();
        let before = fs::read(&path).unwrap();
        for created in [100, u64::MAX] {
            assert_eq!(
                reopened.record_at(&event, 150, Some(created)).unwrap(),
                UorAuditDelivery::AlreadyRecorded
            );
            let mut conflicting = event.clone();
            conflicting.counts.rules_added += 1;
            assert!(matches!(
                reopened.record_at(&conflicting, 150, Some(created)),
                Err(UorAuditSinkError::Conflict { .. })
            ));
        }
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(uor_line_count(&path), 1);
        assert_eq!(
            reopened.read_index().unwrap().pruned_through_unix_seconds,
            Some(u64::MAX)
        );

        // An older rebuild may already have persisted an unsafe finite watermark.
        let mut old_index = reopened.read_index().unwrap();
        old_index.format_version = 1;
        old_index.pruned_through_unix_seconds = Some(50);
        reopened.write_index(&old_index).unwrap();
        drop(reopened);
        let migrated = writer.operator_rules_sink().unwrap();
        assert_eq!(
            migrated.record_at(&event, 150, Some(u64::MAX)).unwrap(),
            UorAuditDelivery::AlreadyRecorded
        );
        let index = migrated.read_index().unwrap();
        assert_eq!(index.format_version, UOR_AUDIT_INDEX_FORMAT);
        assert_eq!(index.pruned_through_unix_seconds, Some(u64::MAX));
        assert_eq!(fs::read(&path).unwrap(), before);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn uor_legacy_index_migrates_watermark_durably_without_duplicate() {
        let root = tmp_dir("uor-legacy-watermark");
        let path = root.join("audit.log");
        let sink = AuditWriter::open(path.clone())
            .unwrap()
            .operator_rules_sink()
            .unwrap();
        let event = uor_event("operation-legacy-pruned");
        sink.record_at(&event, 100, Some(100)).unwrap();
        sink.record_at(&uor_event("operation-legacy-trigger"), 86_501, Some(86_501))
            .unwrap();
        let mut legacy = serde_json::to_value(sink.read_index().unwrap()).unwrap();
        legacy
            .as_object_mut()
            .unwrap()
            .remove("pruned_through_unix_seconds");
        super::super::atomic_write::hardened_atomic_write(
            &sink.index_path,
            &serde_json::to_vec(&legacy).unwrap(),
            Default::default(),
        )
        .unwrap();
        drop(sink);
        let reopened = AuditWriter::open(path.clone())
            .unwrap()
            .operator_rules_sink()
            .unwrap();
        assert_eq!(
            reopened.record_at(&event, 150, Some(100)).unwrap(),
            UorAuditDelivery::AlreadyRecorded
        );
        let migrated: UorAuditIndex =
            serde_json::from_slice(&fs::read(&reopened.index_path).unwrap()).unwrap();
        assert!(migrated.pruned_through_unix_seconds.unwrap() >= 86_501);
        assert_eq!(uor_line_count(&path), 2);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn uor_fresh_receipt_skips_history_and_retention_tolerates_clock_rollback() {
        let root = tmp_dir("uor-fresh-no-scan");
        let path = root.join("audit.log");
        let sink = AuditWriter::open(path.clone())
            .unwrap()
            .operator_rules_sink()
            .unwrap();
        // This oversized line makes recovery fail closed if history is scanned.
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&vec![b'x'; MAX_UOR_AUDIT_EVENT_BYTES * 2 + 1])
            .unwrap();
        file.write_all(b"\n").unwrap();
        let event = uor_event("operation-clock-rollback");
        let created = 100;
        assert_eq!(
            sink.record_at(&event, 50, Some(created)).unwrap(),
            UorAuditDelivery::Recorded
        );
        let later = created + UOR_AUDIT_DEDUP_RETENTION_SECS;
        sink.record_at(&uor_event("operation-fresh-trigger"), later, Some(later))
            .unwrap();
        assert!(sink
            .read_index()
            .unwrap()
            .entries
            .contains_key(&event.identity.operation_id));
        assert_eq!(
            sink.record_at(&event, later, Some(created)).unwrap(),
            UorAuditDelivery::AlreadyRecorded
        );
        assert!(matches!(
            sink.record_at(&uor_event("operation-old"), later, Some(0)),
            Err(UorAuditSinkError::Pending { .. })
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn uor_changed_retry_is_a_conflict_and_does_not_append() {
        let root = tmp_dir("uor-conflict");
        let path = root.join("audit.log");
        let sink = AuditWriter::open(path.clone())
            .unwrap()
            .operator_rules_sink()
            .unwrap();
        let event = uor_event("operation-conflict");
        sink.record(&event).unwrap();

        let mut changed = event.clone();
        changed.counts.rules_added += 1;
        assert!(matches!(
            sink.record(&changed),
            Err(UorAuditSinkError::Conflict { operation_id })
                if operation_id == "operation-conflict"
        ));
        assert_eq!(uor_line_count(&path), 1);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn uor_io_failure_is_pending_and_retryable_after_reopen() {
        let root = tmp_dir("uor-io-retry");
        let path = root.join("audit.log");
        let sink = AuditWriter::open(path.clone())
            .unwrap()
            .operator_rules_sink()
            .unwrap();
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        let event = uor_event("operation-io-retry");

        assert!(matches!(
            sink.record(&event),
            Err(UorAuditSinkError::Pending { operation_id, .. })
                if operation_id == "operation-io-retry"
        ));
        drop(sink);
        fs::remove_dir(&path).unwrap();

        let reopened = AuditWriter::open(path.clone())
            .unwrap()
            .operator_rules_sink()
            .unwrap();
        assert_eq!(reopened.record(&event).unwrap(), UorAuditDelivery::Recorded);
        assert_eq!(uor_line_count(&path), 1);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn uor_model_rejects_sensitive_extensions_and_bounds_entity_ids() {
        let event = uor_event("operation-redaction");
        let mut encoded = serde_json::to_value(&event).unwrap();
        let root = encoded.as_object_mut().unwrap();
        root.insert("pack_body".into(), serde_json::json!("||private.invalid^"));
        root.insert("token".into(), serde_json::json!("secret-bearer"));
        assert!(serde_json::from_value::<UorOperationAuditEvent>(encoded).is_err());

        let root = tmp_dir("uor-bounds");
        let path = root.join("audit.log");
        let sink = AuditWriter::open(path.clone())
            .unwrap()
            .operator_rules_sink()
            .unwrap();
        let mut oversized = event;
        oversized.entities.list_ids = (0..=MAX_UOR_AUDIT_ENTITY_IDS)
            .map(|index| format!("list-{index}"))
            .collect();
        assert!(matches!(
            sink.record(&oversized),
            Err(UorAuditSinkError::Invalid {
                field: "entities.list_ids"
            })
        ));
        assert_eq!(uor_line_count(&path), 0);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn legacy_and_uor_records_parse_together_through_tail() {
        let root = tmp_dir("uor-legacy-tail");
        let path = root.join("audit.log");
        let legacy = r#"{"ts":"2026-04-22T16:09:55Z","event":"reload","uid":1000,"files":[],"pre_hash":"aaa","post_hash":"bbb","result":"ok","errors":[]}"#;
        fs::write(&path, format!("{legacy}\n")).unwrap();
        let sink = AuditWriter::open(path.clone())
            .unwrap()
            .operator_rules_sink()
            .unwrap();
        sink.record(&uor_event("operation-mixed-tail")).unwrap();

        let rows = tail(&path, 2).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].1.as_ref().unwrap().event, AuditEvent::Reload);
        let uor = rows[1].1.as_ref().unwrap();
        assert_eq!(uor.event, AuditEvent::OperatorRulesOperation);
        assert_eq!(
            uor.uor_operation.as_ref().unwrap().identity.operation_id,
            "operation-mixed-tail"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn open_creates_dir_and_file_with_correct_modes() {
        let root = tmp_dir("create");
        let path = root.join("audit/audit.log");
        let w = AuditWriter::open(path.clone()).unwrap();
        assert_eq!(w.path(), path);
        let dir_mode = fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let file_mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, AUDIT_DIR_MODE);
        assert_eq!(file_mode, AUDIT_FILE_MODE);
        let _ = fs::remove_dir_all(root);
    }

    /// A parent directory that was ALREADY there belongs to
    /// the operator, and `open` must leave its mode alone. Only a directory
    /// warden itself creates gets [`AUDIT_DIR_MODE`] — the rule
    /// `ipc::auth_token::save_token_at` and `ipc::socket_server` honour.
    ///
    /// This is the other half of `open_creates_dir_and_file_with_correct_modes`
    /// above, whose parent (`root/audit`) does not pre-exist. The two arms
    /// pin opposite sides of the same branch, so inverting the condition
    /// turns both red rather than trading one green for another.
    #[test]
    fn open_leaves_a_pre_existing_parent_dir_alone() {
        let root = tmp_dir("preexisting-parent");
        let parent = root.join("audit");
        fs::create_dir(&parent).unwrap();
        // Not AUDIT_DIR_MODE, and one bit away from it (other-execute), so
        // an unwanted re-mode shows up instead of coinciding with the
        // operator's value.
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();

        let path = parent.join("audit.log");
        AuditWriter::open(path.clone()).unwrap();

        let dir_mode = fs::metadata(&parent).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            dir_mode, 0o755,
            "open must not chmod a parent it did not create (§4.40 DISC-3); \
             got {dir_mode:o}"
        );
        // The FILE is warden's to mode either way — that half must not
        // regress while the directory half is being tightened.
        let file_mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, AUDIT_FILE_MODE);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn append_writes_one_json_line_per_record() {
        let root = tmp_dir("one-line");
        let path = root.join("audit.log");
        let w = AuditWriter::open(path.clone()).unwrap();

        let rec = AuditRecord::new(AuditEvent::Reload, AuditResult::Ok)
            .with_uid(Some(1000))
            .with_files([Path::new("/etc/purge-warden/config.toml")])
            .with_pre_hash(Some("aaa".into()))
            .with_post_hash(Some("bbb".into()));
        w.append(&rec).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content.lines().count(), 1);
        let first = content.lines().next().unwrap();
        let parsed: AuditRecord = serde_json::from_str(first).unwrap();
        assert_eq!(parsed.event, AuditEvent::Reload);
        assert_eq!(parsed.result, AuditResult::Ok);
        assert_eq!(parsed.uid, Some(1000));
        assert_eq!(parsed.files.len(), 1);
        assert_eq!(parsed.pre_hash.as_deref(), Some("aaa"));
        assert_eq!(parsed.post_hash.as_deref(), Some("bbb"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cname_block_record_round_trips_via_writer() {
        // A chain block writes one JSON line with
        // `event=cname_block`, `action=cname_block`, the original qname
        // in `domain`, the offending hop in `cname_target`, and the
        // BlockSource label in `cname_source`.
        let root = tmp_dir("cname-block");
        let path = root.join("audit.log");
        let w = AuditWriter::open(path.clone()).unwrap();

        let rec = AuditRecord::new(AuditEvent::CnameBlock, AuditResult::Ok)
            .with_action("cname_block")
            .with_domain("apex.example.com")
            .with_cname_target("offending.tracker.example")
            .with_cname_source("rule");
        w.append(&rec).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        let parsed: AuditRecord = serde_json::from_str(content.lines().next().unwrap()).unwrap();
        assert_eq!(parsed.event, AuditEvent::CnameBlock);
        assert_eq!(parsed.action.as_deref(), Some("cname_block"));
        assert_eq!(parsed.domain.as_deref(), Some("apex.example.com"));
        assert_eq!(
            parsed.cname_target.as_deref(),
            Some("offending.tracker.example")
        );
        assert_eq!(parsed.cname_source.as_deref(), Some("rule"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn pre_s4_5_p2_lifecycle_record_deserialises_with_new_fields_none() {
        // Backward compat: an older Reload record on disk has no
        // `cname_target` / `cname_source` fields. The
        // `#[serde(default)]` decorations on the manual Deserialize
        // impl read them back as `None` without erroring.
        let legacy = r#"{
            "ts":"2026-04-22T16:09:55Z",
            "event":"reload",
            "uid":1000,
            "files":["/etc/purge-warden/config.toml"],
            "pre_hash":"aaa",
            "post_hash":"bbb",
            "result":"ok",
            "errors":[]
        }"#;
        let parsed: AuditRecord = serde_json::from_str(legacy).unwrap();
        assert_eq!(parsed.event, AuditEvent::Reload);
        assert!(parsed.cname_target.is_none());
        assert!(parsed.cname_source.is_none());
    }

    #[test]
    fn cname_block_event_tag_round_trips() {
        // The event tag string must survive serialise + deserialise
        // unchanged so `warden audit tail` filtering on
        // `event == "cname_block"` keeps working across upgrades.
        let rec = AuditRecord::new(AuditEvent::CnameBlock, AuditResult::Ok);
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("\"event\":\"cname_block\""));
        let parsed: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.event.as_tag(), "cname_block");
    }

    #[test]
    fn cname_block_record_carries_all_five_block_source_labels() {
        // The `cname_source` field is the BlockSource::label() string
        // pinned by `tests/frozen_strings_s45_p1.rs`. Exhaustive pin:
        // every variant must round-trip through the audit log.
        let labels = [
            "list",
            "rule",
            "admin_block",
            "cname_loop",
            "cname_depth_exceeded",
        ];
        for label in &labels {
            let rec =
                AuditRecord::new(AuditEvent::CnameBlock, AuditResult::Ok).with_cname_source(*label);
            let json = serde_json::to_string(&rec).unwrap();
            let needle = format!("\"cname_source\":\"{label}\"");
            assert!(
                json.contains(&needle),
                "label `{label}` did not surface in audit JSON: {json}"
            );
            let parsed: AuditRecord = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed.cname_source.as_deref(), Some(*label));
        }
    }

    #[test]
    fn multiple_appends_accumulate() {
        let root = tmp_dir("multi");
        let path = root.join("audit.log");
        let w = AuditWriter::open(path.clone()).unwrap();
        for i in 0..5 {
            let rec = AuditRecord::new(AuditEvent::Boot, AuditResult::Ok).with_uid(Some(i));
            w.append(&rec).unwrap();
        }
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content.lines().count(), 5);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn tail_returns_last_n_lines() {
        let root = tmp_dir("tail");
        let path = root.join("audit.log");
        let w = AuditWriter::open(path.clone()).unwrap();
        for i in 0..10 {
            let rec = AuditRecord::new(AuditEvent::Reload, AuditResult::Ok).with_uid(Some(i));
            w.append(&rec).unwrap();
        }
        let got = tail(&path, 3).unwrap();
        assert_eq!(got.len(), 3);
        let uids: Vec<_> = got
            .iter()
            .map(|(_, parsed)| parsed.as_ref().unwrap().uid.unwrap())
            .collect();
        assert_eq!(uids, vec![7, 8, 9]);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn tail_caps_at_file_length() {
        let root = tmp_dir("tail-cap");
        let path = root.join("audit.log");
        let w = AuditWriter::open(path.clone()).unwrap();
        w.append(&AuditRecord::new(AuditEvent::Boot, AuditResult::Ok))
            .unwrap();
        let got = tail(&path, 100).unwrap();
        assert_eq!(got.len(), 1);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn append_caps_oversized_error_list() {
        // A Rejected reload with a huge validator-error list is
        // capped to N + a marker on disk, bounding the record size.
        let root = tmp_dir("err-cap");
        let path = root.join("audit.log");
        let w = AuditWriter::open(path.clone()).unwrap();
        let mut rec = AuditRecord::new(AuditEvent::Reload, AuditResult::Rejected);
        rec.errors = (0..100).map(|i| format!("validator error {i}")).collect();
        w.append(&rec).unwrap();

        let got = tail(&path, 1).unwrap();
        let parsed = got[0].1.as_ref().expect("record parses");
        assert_eq!(
            parsed.errors.len(),
            MAX_AUDIT_RECORD_ERRORS + 1,
            "errors capped to N + marker"
        );
        assert!(parsed.errors.last().unwrap().contains("more error(s)"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn tail_on_missing_file_returns_empty() {
        let root = tmp_dir("tail-missing");
        let path = root.join("audit.log");
        let got = tail(&path, 5).unwrap();
        assert!(got.is_empty());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn tail_reports_malformed_lines() {
        let root = tmp_dir("tail-bad");
        let path = root.join("audit.log");
        fs::write(&path, "not valid json\n").unwrap();
        let got = tail(&path, 1).unwrap();
        assert_eq!(got.len(), 1);
        assert!(got[0].1.is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn tree_hash_is_stable_across_iteration_orders() {
        let root = tmp_dir("tree");
        let a = root.join("a.toml");
        let b = root.join("b.toml");
        fs::write(&a, "a contents").unwrap();
        fs::write(&b, "b contents").unwrap();

        let h1 = tree_hash([a.as_path(), b.as_path()]).unwrap();
        let h2 = tree_hash([b.as_path(), a.as_path()]).unwrap();
        assert_eq!(h1, h2);

        fs::write(&a, "a changed").unwrap();
        let h3 = tree_hash([a.as_path(), b.as_path()]).unwrap();
        assert_ne!(h1, h3);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn tree_hash_missing_returns_none() {
        let root = tmp_dir("tree-missing");
        let missing = root.join("none.toml");
        assert!(tree_hash([missing.as_path()]).is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn event_and_result_serialise_to_stable_strings() {
        let rec = AuditRecord::new(AuditEvent::Boot, AuditResult::Rejected)
            .with_errors(["broken".into()]);
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("\"event\":\"boot\""));
        assert!(json.contains("\"result\":\"rejected\""));
        assert!(json.contains("\"errors\":[\"broken\"]"));
    }

    #[test]
    fn files_sorted_and_deduped() {
        let rec = AuditRecord::new(AuditEvent::Reload, AuditResult::Ok).with_files([
            Path::new("/b"),
            Path::new("/a"),
            Path::new("/a"),
        ]);
        assert_eq!(rec.files, vec!["/a".to_string(), "/b".to_string()]);
    }

    #[test]
    fn event_tag_roundtrip() {
        assert_eq!(AuditEvent::Boot.as_tag(), "boot");
        assert_eq!(AuditEvent::Reload.as_tag(), "reload");
        assert_eq!(AuditEvent::Shutdown.as_tag(), "shutdown");
        assert_eq!(AuditEvent::Restore.as_tag(), "restore");
        assert_eq!(AuditEvent::CliMutation.as_tag(), "cli_mutation");
    }

    #[test]
    fn cli_mutation_record_roundtrips_via_writer() {
        let root = tmp_dir("cli-mutation");
        let path = root.join("audit.log");
        let w = AuditWriter::open(path.clone()).unwrap();

        let rec = AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
            .with_uid(Some(1000))
            .with_action("rule.add")
            .with_scope("device")
            .with_target_id("pc-gioele")
            .with_rule_id("auto-allow-deadbeef")
            .with_rule_action("allow")
            .with_domain("example.com")
            .with_override_used(false);
        w.append_cli_mutation(&rec).unwrap();

        let got = tail(&path, 5).unwrap();
        assert_eq!(got.len(), 1);
        let parsed = got[0].1.as_ref().unwrap();
        assert_eq!(parsed.event, AuditEvent::CliMutation);
        assert_eq!(parsed.action.as_deref(), Some("rule.add"));
        assert_eq!(parsed.scope.as_deref(), Some("device"));
        assert_eq!(parsed.target_id.as_deref(), Some("pc-gioele"));
        assert_eq!(parsed.rule_id.as_deref(), Some("auto-allow-deadbeef"));
        assert_eq!(parsed.rule_action.as_deref(), Some("allow"));
        assert_eq!(parsed.domain.as_deref(), Some("example.com"));
        assert_eq!(parsed.override_used, Some(false));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn lifecycle_record_serialises_without_cli_mutation_fields() {
        let rec = AuditRecord::new(AuditEvent::Reload, AuditResult::Ok).with_uid(Some(0));
        let json = serde_json::to_string(&rec).unwrap();
        // Lifecycle records have no action / scope / etc, and no
        // fields_before / fields_after — the skip_serializing_if guard
        // on every optional field keeps the on-disk shape identical.
        assert!(!json.contains("\"action\""));
        assert!(!json.contains("\"scope\""));
        assert!(!json.contains("\"target_id\""));
        assert!(!json.contains("\"rule_id\""));
        assert!(!json.contains("\"domain\""));
        assert!(!json.contains("\"override_used\""));
        assert!(!json.contains("\"fields_before\""));
        assert!(!json.contains("\"fields_after\""));
    }

    /// Every CLI mutation that flips a blocklist's `kind` field must
    /// emit one append-only audit line carrying `ts`, `uid`,
    /// `action = "blocklist.set_kind"`, `target_id`, `fields_before` /
    /// `fields_after` (the wire-form values the operator typed), and
    /// `pre_hash` / `post_hash`. Pinning here exercises the
    /// audit-emission helper end-to-end (build → append → tail →
    /// parse) so CLI dispatch call sites can rely on a locked JSON
    /// shape.
    #[test]
    fn s50_t2_blocklist_set_kind_round_trips_via_writer() {
        let root = tmp_dir("s50-t2-set-kind");
        let path = root.join("audit.log");
        let w = AuditWriter::open(path.clone()).unwrap();

        let rec = AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
            .with_uid(Some(1000))
            .with_action("blocklist.set_kind")
            .with_target_id("trusted-internal")
            .with_fields_before("block")
            .with_fields_after("allow")
            .with_pre_hash(Some("aaa".into()))
            .with_post_hash(Some("bbb".into()))
            .with_files([Path::new("/etc/purge-warden/config.toml")]);
        w.append_cli_mutation(&rec).unwrap();

        // Round-trip via the on-disk path so the assertion exercises
        // the same code path operators read with `warden audit tail`.
        let got = tail(&path, 5).unwrap();
        assert_eq!(got.len(), 1);
        let parsed = got[0].1.as_ref().unwrap();
        assert_eq!(parsed.event, AuditEvent::CliMutation);
        assert_eq!(parsed.result, AuditResult::Ok);
        assert_eq!(parsed.uid, Some(1000));
        assert_eq!(parsed.action.as_deref(), Some("blocklist.set_kind"));
        assert_eq!(parsed.target_id.as_deref(), Some("trusted-internal"));
        assert_eq!(parsed.fields_before.as_deref(), Some("block"));
        assert_eq!(parsed.fields_after.as_deref(), Some("allow"));
        assert_eq!(parsed.pre_hash.as_deref(), Some("aaa"));
        assert_eq!(parsed.post_hash.as_deref(), Some("bbb"));
        assert!(!parsed.ts.is_empty(), "ts must be populated");

        // The on-disk JSON must spell out every field for downstream
        // tooling, even fields that happen to be empty strings.
        let raw = &got[0].0;
        for needle in [
            "\"action\":\"blocklist.set_kind\"",
            "\"target_id\":\"trusted-internal\"",
            "\"fields_before\":\"block\"",
            "\"fields_after\":\"allow\"",
            "\"pre_hash\":\"aaa\"",
            "\"post_hash\":\"bbb\"",
            "\"uid\":1000",
        ] {
            assert!(
                raw.contains(needle),
                "audit JSON line missing R4 field {needle:?}: {raw}"
            );
        }

        let _ = fs::remove_dir_all(root);
    }

    /// Symmetric to the kind test, but for the `blocklist.set_trust`
    /// action. Pins the per-action tag so CLI dispatch can copy this
    /// pattern verbatim. The test also covers a `Rejected` outcome
    /// (e.g. operator tries to set `trust = signed`) so the audit row
    /// records the refusal — every mutation, successful or not, must
    /// leave a trail.
    #[test]
    fn s50_t2_blocklist_set_trust_records_rejection_with_errors() {
        let root = tmp_dir("s50-t2-set-trust");
        let path = root.join("audit.log");
        let w = AuditWriter::open(path.clone()).unwrap();

        let rec = AuditRecord::new(AuditEvent::CliMutation, AuditResult::Rejected)
            .with_uid(Some(0))
            .with_action("blocklist.set_trust")
            .with_target_id("priv-ads")
            .with_fields_before("remote-unsigned")
            .with_fields_after("signed")
            .with_pre_hash(Some("hhh".into()))
            .with_post_hash(Some("hhh".into()))
            .with_errors([
                "trust=signed is not supported in this version. Use trust=local for trusted allow-lists or trust=remote-unsigned for block-only lists."
                    .to_string(),
            ]);
        w.append_cli_mutation(&rec).unwrap();

        let got = tail(&path, 5).unwrap();
        assert_eq!(got.len(), 1);
        let parsed = got[0].1.as_ref().unwrap();
        assert_eq!(parsed.event, AuditEvent::CliMutation);
        assert_eq!(parsed.result, AuditResult::Rejected);
        assert_eq!(parsed.action.as_deref(), Some("blocklist.set_trust"));
        assert_eq!(parsed.target_id.as_deref(), Some("priv-ads"));
        assert_eq!(parsed.fields_before.as_deref(), Some("remote-unsigned"));
        assert_eq!(parsed.fields_after.as_deref(), Some("signed"));
        assert_eq!(parsed.pre_hash, parsed.post_hash);
        assert_eq!(parsed.errors.len(), 1);
        assert!(parsed.errors[0].contains("trust=signed is not supported"));

        let _ = fs::remove_dir_all(root);
    }

    /// Older audit lines on disk must still deserialise even though
    /// these fields don't exist there. Companion to
    /// `pre_t6_lifecycle_lines_still_deserialise`.
    #[test]
    fn pre_s50_t2_cli_mutation_lines_still_deserialise() {
        let raw = r#"{"ts":"2026-04-25T12:00:00Z","event":"cli_mutation","uid":1000,"files":[],"pre_hash":null,"post_hash":null,"result":"ok","errors":[],"action":"rule.add","scope":"device","target_id":"pc-gioele","rule_id":"r1","rule_action":"allow","domain":"example.com","override_used":false}"#;
        let parsed: AuditRecord = serde_json::from_str(raw).unwrap();
        assert_eq!(parsed.event, AuditEvent::CliMutation);
        assert_eq!(parsed.fields_before, None);
        assert_eq!(parsed.fields_after, None);
    }

    /// Older audit lines (no `record_value` / `match_subdomains` /
    /// `ttl_secs` columns) must continue to deserialise. The new
    /// fields default to `None`.
    #[test]
    fn pre_s44_followup_local_dns_audit_lines_still_deserialise() {
        let raw = r#"{"ts":"2026-05-01T10:11:00Z","event":"cli_mutation","uid":1000,"files":[],"pre_hash":null,"post_hash":null,"result":"ok","errors":[],"action":"local_records.add","scope":"global","target_id":"global","rule_action":"A","domain":"nas.home"}"#;
        let parsed: AuditRecord = serde_json::from_str(raw).unwrap();
        assert_eq!(parsed.event, AuditEvent::CliMutation);
        assert_eq!(parsed.action.as_deref(), Some("local_records.add"));
        assert_eq!(parsed.domain.as_deref(), Some("nas.home"));
        // The three new fields land as `None` on legacy lines.
        assert_eq!(parsed.record_value, None);
        assert_eq!(parsed.match_subdomains, None);
        assert_eq!(parsed.ttl_secs, None);
    }

    /// An audit line carrying the three Local-DNS fields must
    /// round-trip through the writer + tail + parse pipeline
    /// byte-stable, including the wire-form spelling of every column.
    #[test]
    fn s44_followup_local_dns_audit_line_round_trips_through_writer() {
        let root = tmp_dir("s44-roundtrip");
        let path = root.join("audit.log");
        let w = AuditWriter::open(path.clone()).unwrap();

        let rec = AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
            .with_uid(Some(1000))
            .with_action("local_records.add")
            .with_scope("profile")
            .with_target_id("kids")
            .with_domain("blocked.example")
            .with_rule_action("A")
            .with_record_value("10.10.1.99")
            .with_match_subdomains(true)
            .with_ttl_secs(7200);
        w.append_cli_mutation(&rec).unwrap();

        let got = tail(&path, 5).unwrap();
        assert_eq!(got.len(), 1);
        let parsed = got[0].1.as_ref().unwrap();
        assert_eq!(parsed.action.as_deref(), Some("local_records.add"));
        assert_eq!(parsed.scope.as_deref(), Some("profile"));
        assert_eq!(parsed.target_id.as_deref(), Some("kids"));
        assert_eq!(parsed.record_value.as_deref(), Some("10.10.1.99"));
        assert_eq!(parsed.match_subdomains, Some(true));
        assert_eq!(parsed.ttl_secs, Some(7200));

        // Wire-form spelling sanity: the JSON line must carry the new
        // field names exactly so external readers (jq scripts, log
        // shippers) can grep for them.
        let raw = &got[0].0;
        assert!(raw.contains("\"record_value\":\"10.10.1.99\""));
        assert!(raw.contains("\"match_subdomains\":true"));
        assert!(raw.contains("\"ttl_secs\":7200"));

        let _ = fs::remove_dir_all(root);
    }

    /// An audit line that omits the Local-DNS fields (e.g. a
    /// `local_records.remove` against multiple matching rows) keeps
    /// the on-disk shape compact. `skip_serializing_if` must drop the
    /// `null`s so log readers don't see columns until they actually
    /// carry data.
    #[test]
    fn s44_followup_audit_line_without_new_fields_serialises_compactly() {
        let rec = AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
            .with_action("local_records.remove")
            .with_scope("global")
            .with_target_id("global")
            .with_domain("multi.example");
        let json = serde_json::to_string(&rec).unwrap();
        assert!(!json.contains("\"record_value\""));
        assert!(!json.contains("\"match_subdomains\""));
        assert!(!json.contains("\"ttl_secs\""));
    }

    #[test]
    fn pre_t6_lifecycle_lines_still_deserialise() {
        // Hand-crafted JSON in the original lifecycle shape: no
        // action/scope/etc fields. The deserialiser must accept it.
        let raw = r#"{"ts":"2026-04-22T16:09:55Z","event":"reload","uid":1000,"files":["/etc/purge-warden/config.toml"],"pre_hash":"aaa","post_hash":"bbb","result":"ok","errors":[]}"#;
        let parsed: AuditRecord = serde_json::from_str(raw).unwrap();
        assert_eq!(parsed.event, AuditEvent::Reload);
        assert_eq!(parsed.action, None);
        assert_eq!(parsed.scope, None);
        assert_eq!(parsed.override_used, None);
    }

    #[test]
    fn reload_rejected_record_matches_schema() {
        let rec = AuditRecord::new(AuditEvent::Reload, AuditResult::Rejected)
            .with_uid(Some(0))
            .with_files([Path::new("/etc/purge-warden/config.toml")])
            .with_pre_hash(Some("hhh".into()))
            .with_post_hash(Some("hhh".into()))
            .with_errors(["cross-reference miss: missing profile".into()]);
        let json = serde_json::to_string(&rec).unwrap();
        let roundtrip: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.event, AuditEvent::Reload);
        assert_eq!(roundtrip.result, AuditResult::Rejected);
        assert_eq!(roundtrip.errors.len(), 1);
        assert_eq!(roundtrip.pre_hash, roundtrip.post_hash);
    }
}
