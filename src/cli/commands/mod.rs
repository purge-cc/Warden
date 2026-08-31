use std::path::{Path, PathBuf};

pub mod audit;
pub mod audit_emit;
pub mod blocklists;
pub mod cache;
pub mod cluster;
pub mod completion;
pub mod config;
pub mod devices;
pub mod entity_tags;
pub mod firewall_rules;
pub mod groups;
pub mod init;
pub mod ipc_reload;
pub mod labels;
pub mod lists;
pub mod lists_knobs;
pub mod local_dns;

#[cfg(test)]
pub(crate) mod hr2_test_support;
pub mod logs;
pub mod manpages;
pub mod migrate;
pub mod pid;
pub mod profiles_v1;
pub mod query;
pub mod reload;
pub mod resolve;
pub mod rewrite;
pub mod rules;
pub mod schedules;
pub mod security;
pub mod start;
pub mod stats;
pub mod status;
pub mod stop;
pub mod subnets;
pub mod target;
pub mod token;
pub mod toml_write;
pub mod update;

/// Return `desired` if nothing exists at that path, otherwise the first free
/// `<desired>-N` (N = 1, 2, …).
///
/// Used for one-shot rollback asides (`*.pre-restore-<ts>`,
/// `pre-migration-<ts>.toml`, `*.pre-init-<ts>`). Their second-granularity UTC
/// timestamp collides on a same-second retry, and the bare `rename`/`copy` that
/// follows would silently clobber a just-written recovery copy — losing the
/// only rollback point. These aside names are never parsed back, so a numeric
/// suffix is safe. (The `config-<ts>.tar.gz` backup *archive* name is parsed by
/// [`config::backup::list_backups`], so it is deliberately NOT routed through
/// here — same-second archives are same-content and retention manages them.)
///
/// Probe-and-bump carries an inherent check-then-create race, acceptable here
/// because these asides are operator-paced, not a security boundary (the
/// restore staging dir, which IS a boundary, uses exclusive `O_EXCL` create).
pub(crate) fn make_unique_path(desired: PathBuf) -> PathBuf {
    if !desired.exists() {
        return desired;
    }
    let name = desired
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("backup");
    let parent = desired.parent().unwrap_or_else(|| Path::new("."));
    for n in 1..=10_000u32 {
        let candidate = parent.join(format!("{name}-{n}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    // 10k same-named asides in one second is not a real operating condition;
    // fall back to the original rather than loop unbounded.
    desired
}

/// Collapse the loader's `Vec<ConfigError>` into a bulleted `anyhow::Error`.
///
/// Every CLI read path needs this because `Vec<ConfigError>` is not
/// `std::error::Error`, so `?` cannot convert it. Living in one seat is the
/// point: the wording is operator-facing, and a per-file copy drifts —
/// `warden schedule list` once reported a broken config in different words
/// than every other read verb, and nobody decided that.
///
/// Decides neither exit codes nor printing; callers own both.
pub(crate) fn format_config_errors(errs: Vec<crate::config::error::ConfigError>) -> anyhow::Error {
    let mut msg = format!("cannot load config ({} error(s)):", errs.len());
    for e in &errs {
        msg.push_str("\n  - ");
        msg.push_str(&e.to_string());
    }
    anyhow::anyhow!(msg)
}

/// The same errors joined with `"; "`, for embedding in a one-line context
/// such as a staging validator's `Result<(), String>`.
pub(crate) fn format_config_errors_flat(errs: &[crate::config::error::ConfigError]) -> String {
    let mut s = String::new();
    for (i, e) in errs.iter().enumerate() {
        if i > 0 {
            s.push_str("; ");
        }
        s.push_str(&e.to_string());
    }
    s
}
