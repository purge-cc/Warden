//! The single CLI-mutation audit seam.
//!
//! Every `warden <verb>` that writes config routes its per-mutation
//! [`AuditEvent::CliMutation`](crate::config::audit::AuditEvent::CliMutation)
//! record through [`persist_cli_mutation_audit`] — one emit path, one
//! failure policy — so audit coverage cannot silently drift per-verb
//! (rev-2606 audit-01 / audit-02). The companion coverage guard
//! `tests/cli_audit_coverage_guard.rs` fails the build if a config-writing
//! verb forgets to call this.
//!
//! Failure policy (audit-02): the config write has already landed on disk
//! by the time this runs — verbs emit AFTER `validate_or_revert`. A failed
//! audit append is therefore an observability gap, not a write failure to
//! propagate: surfacing it as a non-zero exit would falsely tell the
//! operator the change failed and invite a re-run. So we warn LOUD
//! (`tracing::warn` + stderr) and return — the mutation stands, the
//! operator is told it went unrecorded. This is the "visibility fix, not a
//! new trust boundary" stance previously local to the local-dns verbs,
//! now applied uniformly.

use std::path::Path;

use crate::config::audit::{AuditRecord, AuditWriter};

use super::audit::audit_log_path_for;

/// Emit one CLI-mutation audit record for a config write rooted at
/// `config_path`. `build` is invoked only once the writer opens, so callers
/// may move the mutation context into it freely.
///
/// Never propagates: on any audit I/O error the change (already on disk) is
/// kept and the operator is warned on stderr that it went unrecorded. See
/// the module doc for the rationale.
pub fn persist_cli_mutation_audit(config_path: &Path, build: impl FnOnce() -> AuditRecord) {
    let path = audit_log_path_for(config_path);
    let writer = match AuditWriter::open(path.clone()) {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!(
                error = %e,
                path = %path.display(),
                "cli mutation audit: cannot open writer (change is applied but UNAUDITED)"
            );
            eprintln!(
                "warning: config change applied but NOT recorded in the audit log ({}): {e}",
                path.display()
            );
            return;
        }
    };
    let record = build();
    if let Err(e) = writer.append_cli_mutation(&record) {
        tracing::warn!(
            error = %e,
            path = %path.display(),
            "cli mutation audit: append failed (change is applied but UNAUDITED)"
        );
        eprintln!(
            "warning: config change applied but NOT recorded in the audit log ({}): {e}",
            path.display()
        );
    }
}

/// uid of the invoking operator, for the audit `uid` field. The CLI process
/// is short-lived and runs as the operator, so this reflects who ran the
/// verb (not the daemon runtime uid).
pub fn current_uid() -> Option<u32> {
    // SAFETY: getuid() takes no arguments, cannot fail, and cannot alias.
    Some(unsafe { libc::getuid() })
}
