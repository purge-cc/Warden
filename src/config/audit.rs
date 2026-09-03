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
//! The writer opens the file with `O_APPEND | O_CREATE` and issues one
//! `write(2)` per record (trailing newline included). On Linux the kernel
//! serialises concurrent `O_APPEND` writes so two writers don't interleave
//! within a line, as long as each record fits in a single `write(2)` of a
//! practical size. (Not a `PIPE_BUF` guarantee — that 4 KB atomicity bound
//! governs pipes / FIFOs, not regular files.) Records
//! are kept small on purpose — the per-record `errors` list is capped at
//! [`MAX_AUDIT_RECORD_ERRORS`] — so a `Rejected` reload over a badly broken
//! multi-file config can't grow a line large enough to risk a torn write.
//!
//! # Permissions
//!
//! The audit directory is created with mode `0750`, the file with mode
//! `0640`. Group `purge-warden` can read without being able to write — which
//! matches the systemd service user/group deployed on the CT. If those bits
//! need tightening further the daemon can re-apply on every open.

use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

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

        Ok(Self { path })
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
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(AUDIT_FILE_MODE)
            .open(&self.path)?;
        file.write_all(line.as_bytes())?;
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
            .with_record_value("192.0.2.99")
            .with_match_subdomains(true)
            .with_ttl_secs(7200);
        w.append_cli_mutation(&rec).unwrap();

        let got = tail(&path, 5).unwrap();
        assert_eq!(got.len(), 1);
        let parsed = got[0].1.as_ref().unwrap();
        assert_eq!(parsed.action.as_deref(), Some("local_records.add"));
        assert_eq!(parsed.scope.as_deref(), Some("profile"));
        assert_eq!(parsed.target_id.as_deref(), Some("kids"));
        assert_eq!(parsed.record_value.as_deref(), Some("192.0.2.99"));
        assert_eq!(parsed.match_subdomains, Some(true));
        assert_eq!(parsed.ttl_secs, Some(7200));

        // Wire-form spelling sanity: the JSON line must carry the new
        // field names exactly so external readers (jq scripts, log
        // shippers) can grep for them.
        let raw = &got[0].0;
        assert!(raw.contains("\"record_value\":\"192.0.2.99\""));
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
