//! `warden audit …` subcommands (Sprint 32, N1).
//!
//! Read-only surface on top of the append-only audit log written by the
//! daemon. Operator does not need bulk read rights on
//! `/var/lib/purge-warden/audit/audit.log` — the CLI opens the file in
//! user mode and pretty-prints the last N records so a support pair can
//! answer "who reloaded the config at X o'clock" without greenflagging
//! the whole daemon state.

use std::path::{Path, PathBuf};

use crate::config::audit::{self, AuditEvent, AuditResult};

/// Resolve the audit log path relative to a master config file. Mirrors
/// [`crate::cli::commands::start::audit_log_path`] so `warden audit tail`
/// reads from the same path the daemon writes to — including the FHS v1
/// redirection that sends `/etc/<pkg>/config.toml` to
/// `/var/lib/<pkg>/audit/audit.log`.
pub fn audit_log_path_for(config_path: &Path) -> PathBuf {
    let dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    crate::cli::commands::start::state_dir_for(dir)
        .join(audit::AUDIT_DIR_NAME)
        .join(audit::AUDIT_FILE_NAME)
}

/// Cap on the most recent audit lines scanned by
/// [`local_dns_history_for`]. The TUI side-card asks for the last 10
/// hits on a (scope, target_id, domain) tuple; reading the trailing 5000
/// lines covers months of typical home/SMB activity without paying for a
/// full-file walk on every Enter keypress.
pub const LOCAL_DNS_HISTORY_SCAN_LIMIT: usize = 5000;

/// Filter the audit log for `local_records.add` / `local_records.remove`
/// entries matching the given `(scope_tag, target_id, domain)` tuple and
/// return the most recent `max` matches in reverse-chronological order
/// (newest first). Used by the Local DNS tab side-card to render the
/// drill-down audit panel without inventing a new IPC verb — the audit
/// log is the source of truth for who/when.
///
/// `domain` is matched case-insensitively. Malformed lines on disk are
/// silently skipped so an operator manually editing the log can never
/// brick the side-card. IO failures (file missing, unreadable) return an
/// empty vector — callers render the friendly empty-state copy.
pub fn local_dns_history_for(
    config_path: &Path,
    scope_tag: &str,
    target_id: &str,
    domain: &str,
    max: usize,
) -> Vec<audit::AuditRecord> {
    let path = audit_log_path_for(config_path);
    let domain_lower = domain.to_ascii_lowercase();
    let records = match audit::tail(&path, LOCAL_DNS_HISTORY_SCAN_LIMIT) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let mut matches: Vec<audit::AuditRecord> = records
        .into_iter()
        .filter_map(|(_, parsed)| parsed.ok())
        .filter(|rec| rec.event == AuditEvent::CliMutation)
        .filter(|rec| {
            matches!(
                rec.action.as_deref(),
                Some("local_records.add") | Some("local_records.remove")
            )
        })
        .filter(|rec| rec.scope.as_deref() == Some(scope_tag))
        .filter(|rec| rec.target_id.as_deref() == Some(target_id))
        .filter(|rec| {
            rec.domain
                .as_deref()
                .map(|d| d.eq_ignore_ascii_case(&domain_lower))
                .unwrap_or(false)
        })
        .collect();
    // tail returns oldest-first within the window; reverse for
    // newest-first display, then truncate to `max`.
    matches.reverse();
    matches.truncate(max);
    matches
}

/// `warden audit tail [-n N]` — print the last `n` records from the
/// audit log as human-friendly rows (not the raw JSON). Returns exit code
/// 0 on success, 1 on IO failure, 2 on malformed records (the line is
/// surfaced as-is so the operator can read it by hand).
pub fn run_tail(config_path: &Path, n: usize) -> anyhow::Result<i32> {
    let path = audit_log_path_for(config_path);
    let records = match audit::tail(&path, n) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("cannot read audit log at {}: {e}", path.display());
            return Ok(1);
        }
    };
    if records.is_empty() {
        println!("# {} (empty)", path.display());
        return Ok(0);
    }

    println!("# {} (last {} record(s))", path.display(), records.len());
    println!(
        "{:<20}  {:<9}  {:<5}  {:<9}  detail",
        "timestamp", "event", "uid", "result"
    );
    let mut any_bad = false;
    for (raw, parsed) in &records {
        match parsed {
            Ok(rec) => {
                let uid = rec.uid.map(|u| u.to_string()).unwrap_or_else(|| "-".into());
                let event = rec.event.as_tag();
                let result = rec.result.as_tag();
                let detail = format_detail(rec);
                println!(
                    "{:<20}  {:<9}  {:<5}  {:<9}  {}",
                    rec.ts, event, uid, result, detail
                );
            }
            Err(err) => {
                any_bad = true;
                println!("# malformed record: {err}");
                println!("  raw: {raw}");
            }
        }
    }
    Ok(if any_bad { 2 } else { 0 })
}

fn format_detail(rec: &audit::AuditRecord) -> String {
    // T6: CLI mutations carry the action / scope / target_id / domain
    // / rule_id / rule_action / override_used fields instead of the
    // lifecycle file/hash/errors trio.
    if rec.event == AuditEvent::CliMutation {
        return format_cli_mutation_detail(rec);
    }

    let files = if rec.files.is_empty() {
        "-".to_string()
    } else if rec.files.len() == 1 {
        rec.files[0].clone()
    } else {
        format!("{} ({} files)", rec.files[0], rec.files.len())
    };
    // `post_hash` is deserialised from the on-disk audit log, so its
    // contents are whatever is in the file — not necessarily the hex
    // `tree_hash` wrote. Truncating by BYTE (`&h[..12]`) panics when byte
    // 12 lands inside a multi-byte character, which turns a corrupted or
    // hand-edited log into a crashed `warden audit tail` instead of a
    // readable one. Count characters instead: the display is a
    // human-facing prefix, so 12 characters is as correct as 12 bytes and
    // cannot panic.
    let post = rec
        .post_hash
        .as_deref()
        .map(|h| format!(" hash={}", h.chars().take(12).collect::<String>()))
        .unwrap_or_default();
    let err_msg = if rec.errors.is_empty() {
        String::new()
    } else {
        format!(" errors=[{}]", rec.errors.join("; "))
    };
    let _ = AuditEvent::Boot; // keep import stable
    let _ = AuditResult::Ok;
    format!("{files}{post}{err_msg}")
}

fn format_cli_mutation_detail(rec: &audit::AuditRecord) -> String {
    let action = rec.action.as_deref().unwrap_or("?");
    let mut parts: Vec<String> = vec![action.to_string()];
    if let Some(scope) = rec.scope.as_deref() {
        let target = rec.target_id.as_deref().unwrap_or("-");
        parts.push(format!("scope={scope}:{target}"));
    } else if let Some(target) = rec.target_id.as_deref() {
        parts.push(format!("target={target}"));
    }
    if let Some(rule_action) = rec.rule_action.as_deref() {
        parts.push(rule_action.to_string());
    }
    if let Some(domain) = rec.domain.as_deref() {
        parts.push(domain.to_string());
    }
    // S44 follow-up — Local-DNS-only fields. The arrow form mirrors
    // operator muscle memory ("domain → value") and stays compact for
    // narrow terminals reading `warden audit tail`.
    if let Some(value) = rec.record_value.as_deref() {
        parts.push(format!("\u{2192} {value}"));
    }
    if rec.match_subdomains == Some(true) {
        parts.push("match_subdomains".to_string());
    }
    if let Some(ttl) = rec.ttl_secs {
        parts.push(format!("ttl={ttl}"));
    }
    if let Some(id) = rec.rule_id.as_deref() {
        parts.push(format!("id={id}"));
    }
    if rec.override_used == Some(true) {
        parts.push("override".to_string());
    }
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::audit::{AuditRecord, AuditWriter};
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmp_config(tag: &str) -> PathBuf {
        static CTR: AtomicU64 = AtomicU64::new(0);
        let pid = std::process::id();
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("purge-audit-cli-{pid}-{n}-{tag}"));
        fs::create_dir_all(&root).unwrap();
        root.join("config.toml")
    }

    #[test]
    fn audit_log_path_resolves_next_to_config() {
        let config = Path::new("/var/lib/purge-warden/config.toml");
        let path = audit_log_path_for(config);
        assert_eq!(path, Path::new("/var/lib/purge-warden/audit/audit.log"));
    }

    #[test]
    fn tail_returns_zero_when_file_missing() {
        let config = tmp_config("missing");
        let rc = run_tail(&config, 5).unwrap();
        assert_eq!(rc, 0);
        let _ = fs::remove_dir_all(config.parent().unwrap());
    }

    #[test]
    fn tail_reads_written_records() {
        let config = tmp_config("populated");
        let path = audit_log_path_for(&config);
        let w = AuditWriter::open(path.clone()).unwrap();
        for i in 0..3 {
            let rec = AuditRecord::new(AuditEvent::Reload, AuditResult::Ok).with_uid(Some(i));
            w.append(&rec).unwrap();
        }
        let rc = run_tail(&config, 5).unwrap();
        assert_eq!(rc, 0);
        let _ = fs::remove_dir_all(config.parent().unwrap());
    }

    #[test]
    fn format_detail_renders_cli_mutation_record() {
        let rec = AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
            .with_uid(Some(1000))
            .with_action("rule.add")
            .with_scope("device")
            .with_target_id("pc-gioele")
            .with_rule_id("auto-allow-deadbeef")
            .with_rule_action("allow")
            .with_domain("example.com")
            .with_override_used(false);
        let detail = format_detail(&rec);
        // The detail line must surface the verb + scope:target + action
        // + domain + id so an operator scanning `warden audit tail`
        // sees what changed without having to grep the JSON.
        assert!(detail.contains("rule.add"), "detail: {detail}");
        assert!(
            detail.contains("scope=device:pc-gioele"),
            "detail: {detail}"
        );
        assert!(detail.contains("allow"), "detail: {detail}");
        assert!(detail.contains("example.com"), "detail: {detail}");
        assert!(
            detail.contains("id=auto-allow-deadbeef"),
            "detail: {detail}"
        );
        // Override was false → no `override` token in the output.
        assert!(!detail.contains("override"), "detail: {detail}");
    }

    /// `post_hash` comes off disk, so it can hold anything — and the
    /// display used to truncate it by BYTE. This fixture is 12 characters
    /// but 13 bytes: `é` occupies bytes 11-12, so a cut at byte 12 lands
    /// mid-character and panics.
    ///
    /// Control arm: replacing the body of the `post` mapping with the old
    /// `&h[..h.len().min(12)]` makes this test abort with
    /// `byte index 12 is not a char boundary`. A test asserting only
    /// "the output contains hash=" would pass on both, since the panic
    /// happens before any comparison — the assertion has to be that the
    /// call RETURNS.
    #[test]
    fn format_detail_truncates_post_hash_without_splitting_a_character() {
        let hash = "0123456789aé";
        assert_eq!(hash.chars().count(), 12, "fixture must be 12 characters");
        assert_eq!(hash.len(), 13, "fixture must be 13 bytes to bite");

        // `Reload`, not `CliMutation`: `format_detail` returns early for
        // CLI mutations into a renderer that never touches `post_hash`, so
        // a CliMutation fixture exercises a path where the bug cannot
        // fire. `Reload` (10 call sites) and `Boot` (1) are the events
        // that actually carry a hash into this branch.
        let rec = AuditRecord::new(AuditEvent::Reload, AuditResult::Ok)
            .with_post_hash(Some(hash.to_string()));

        let detail = format_detail(&rec);
        assert!(
            detail.contains(&format!("hash={hash}")),
            "all 12 characters must survive: {detail}"
        );
    }

    /// The prefix is twelve CHARACTERS, not twelve bytes — pinned without
    /// relying on a panic, because byte-truncation can also be silently
    /// *short*.
    ///
    /// This fixture is 13 two-byte characters (26 bytes) and every byte
    /// offset in it is a valid boundary, so the old code did not crash on
    /// it: it cut at byte 12 and rendered **six** characters. The first
    /// version of this test used `"0123456789abé"`, where byte 12 happens
    /// to be a boundary AND the twelve-character prefix is the same twelve
    /// bytes — so it passed on the bug and proved nothing. Byte-truncation
    /// fails in two directions and only one of them is loud.
    #[test]
    fn format_detail_post_hash_prefix_stops_at_twelve_characters() {
        let hash = "ééééééééééééé";
        assert_eq!(hash.chars().count(), 13, "fixture must be 13 characters");
        assert_eq!(hash.len(), 26, "fixture must be 26 bytes");
        // `Reload`, not `CliMutation`: `format_detail` returns early for
        // CLI mutations into a renderer that never touches `post_hash`, so
        // a CliMutation fixture exercises a path where the bug cannot
        // fire. `Reload` (10 call sites) and `Boot` (1) are the events
        // that actually carry a hash into this branch.
        let rec = AuditRecord::new(AuditEvent::Reload, AuditResult::Ok)
            .with_post_hash(Some(hash.to_string()));

        let detail = format_detail(&rec);
        let expected = "é".repeat(12);
        assert!(
            detail.contains(&format!("hash={expected}")),
            "prefix must be 12 characters, not 12 bytes: {detail}"
        );
        assert!(
            !detail.contains(&format!("hash={hash}")),
            "the 13th character must be dropped: {detail}"
        );
    }

    #[test]
    fn s44_format_detail_renders_local_records_extra_fields() {
        // S44 follow-up — `warden audit tail` must surface the
        // record_value (with arrow), match_subdomains badge, and
        // explicit TTL on a `local_records.add` line so the operator
        // sees full mutation context without reaching for the JSON.
        let rec = AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
            .with_uid(Some(1000))
            .with_action("local_records.add")
            .with_scope("profile")
            .with_target_id("kids")
            .with_rule_action("A")
            .with_domain("blocked.example")
            .with_record_value("10.10.1.99")
            .with_match_subdomains(true)
            .with_ttl_secs(7200);
        let detail = format_detail(&rec);
        assert!(detail.contains("local_records.add"), "detail: {detail}");
        assert!(detail.contains("scope=profile:kids"), "detail: {detail}");
        assert!(detail.contains("\u{2192} 10.10.1.99"), "detail: {detail}");
        assert!(detail.contains("match_subdomains"), "detail: {detail}");
        assert!(detail.contains("ttl=7200"), "detail: {detail}");
    }

    #[test]
    fn s44_format_detail_omits_extra_fields_when_unset() {
        // A pre-S44-followup CLI mutation row (or a `remove` against
        // multiple records) must render exactly as before — the new
        // tokens must NOT appear. Mirrors the
        // `s44_followup_audit_line_without_new_fields_serialises_compactly`
        // wire-form test on the render side.
        let rec = AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
            .with_action("local_records.remove")
            .with_scope("global")
            .with_target_id("global")
            .with_domain("multi.example");
        let detail = format_detail(&rec);
        assert!(!detail.contains("\u{2192}"));
        assert!(!detail.contains("match_subdomains"));
        assert!(!detail.contains("ttl="));
    }

    #[test]
    fn format_detail_marks_override_when_set() {
        let rec = AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
            .with_action("rule.add")
            .with_scope("device")
            .with_target_id("pc")
            .with_rule_action("allow")
            .with_domain("x.example")
            .with_override_used(true);
        let detail = format_detail(&rec);
        assert!(
            detail.contains("override"),
            "override token missing from: {detail}"
        );
    }

    #[test]
    fn run_tail_renders_mixed_lifecycle_and_cli_mutations() {
        let config = tmp_config("mixed");
        let path = audit_log_path_for(&config);
        let w = AuditWriter::open(path.clone()).unwrap();
        w.append(&AuditRecord::new(AuditEvent::Boot, AuditResult::Ok))
            .unwrap();
        w.append_cli_mutation(
            &AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
                .with_action("rule.add")
                .with_scope("profile")
                .with_target_id("default")
                .with_domain("smoke.example"),
        )
        .unwrap();
        w.append(&AuditRecord::new(AuditEvent::Reload, AuditResult::Ok))
            .unwrap();
        // run_tail prints to stdout — we can't capture it easily here.
        // Just assert exit code is OK and the file shape is valid.
        let rc = run_tail(&config, 10).unwrap();
        assert_eq!(rc, 0);
        let recs = audit::tail(&path, 10).unwrap();
        assert_eq!(recs.len(), 3);
        assert_eq!(recs[0].1.as_ref().unwrap().event, AuditEvent::Boot);
        assert_eq!(recs[1].1.as_ref().unwrap().event, AuditEvent::CliMutation);
        assert_eq!(recs[2].1.as_ref().unwrap().event, AuditEvent::Reload);
        let _ = fs::remove_dir_all(config.parent().unwrap());
    }

    #[test]
    fn local_dns_history_returns_empty_when_log_missing() {
        let config = tmp_config("ldns-missing");
        let got = local_dns_history_for(&config, "global", "global", "nas.home", 10);
        assert!(got.is_empty());
        let _ = fs::remove_dir_all(config.parent().unwrap());
    }

    #[test]
    fn local_dns_history_filters_by_scope_target_and_domain() {
        let config = tmp_config("ldns-filter");
        let path = audit_log_path_for(&config);
        let w = AuditWriter::open(path.clone()).unwrap();

        // Same domain on global vs profile:default — the filter must not
        // bleed across scopes.
        w.append_cli_mutation(
            &AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
                .with_action("local_records.add")
                .with_scope("global")
                .with_target_id("global")
                .with_domain("nas.home"),
        )
        .unwrap();
        w.append_cli_mutation(
            &AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
                .with_action("local_records.add")
                .with_scope("profile")
                .with_target_id("default")
                .with_domain("nas.home"),
        )
        .unwrap();
        // A non-Local-DNS verb on the same domain — must be excluded.
        w.append_cli_mutation(
            &AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
                .with_action("rule.add")
                .with_scope("global")
                .with_target_id("global")
                .with_domain("nas.home"),
        )
        .unwrap();
        // A lifecycle event — must be excluded.
        w.append(&AuditRecord::new(AuditEvent::Reload, AuditResult::Ok))
            .unwrap();

        let global = local_dns_history_for(&config, "global", "global", "nas.home", 10);
        assert_eq!(global.len(), 1);
        assert_eq!(global[0].action.as_deref(), Some("local_records.add"));
        assert_eq!(global[0].scope.as_deref(), Some("global"));

        let profile = local_dns_history_for(&config, "profile", "default", "nas.home", 10);
        assert_eq!(profile.len(), 1);
        assert_eq!(profile[0].scope.as_deref(), Some("profile"));
        assert_eq!(profile[0].target_id.as_deref(), Some("default"));

        let other_domain = local_dns_history_for(&config, "global", "global", "elsewhere", 10);
        assert!(other_domain.is_empty());

        let _ = fs::remove_dir_all(config.parent().unwrap());
    }

    #[test]
    fn local_dns_history_returns_newest_first_and_truncates_to_max() {
        let config = tmp_config("ldns-30entry");
        let path = audit_log_path_for(&config);
        let w = AuditWriter::open(path.clone()).unwrap();

        // 30 add-then-remove pairs on the same record — the side-card
        // wants the last 10 newest-first. Synthesised ts markers via the
        // uid field so we can pin ordering without poking ts strings.
        for i in 0..30u32 {
            let action = if i % 2 == 0 {
                "local_records.add"
            } else {
                "local_records.remove"
            };
            w.append_cli_mutation(
                &AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
                    .with_uid(Some(i))
                    .with_action(action)
                    .with_scope("global")
                    .with_target_id("global")
                    .with_domain("churn.example"),
            )
            .unwrap();
        }

        let got = local_dns_history_for(&config, "global", "global", "churn.example", 10);
        assert_eq!(got.len(), 10, "must truncate to max");

        // Newest-first: uid=29 (the 30th = last write) should be first.
        assert_eq!(got[0].uid, Some(29));
        assert_eq!(got[9].uid, Some(20));

        let _ = fs::remove_dir_all(config.parent().unwrap());
    }

    #[test]
    fn local_dns_history_matches_domain_case_insensitively() {
        let config = tmp_config("ldns-case");
        let path = audit_log_path_for(&config);
        let w = AuditWriter::open(path.clone()).unwrap();
        w.append_cli_mutation(
            &AuditRecord::new(AuditEvent::CliMutation, AuditResult::Ok)
                .with_action("local_records.add")
                .with_scope("global")
                .with_target_id("global")
                .with_domain("Mixed.Case.Example"),
        )
        .unwrap();

        let got = local_dns_history_for(&config, "global", "global", "mixed.case.example", 10);
        assert_eq!(got.len(), 1);

        let _ = fs::remove_dir_all(config.parent().unwrap());
    }
}
