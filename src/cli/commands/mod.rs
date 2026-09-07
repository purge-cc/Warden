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
