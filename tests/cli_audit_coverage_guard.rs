//! Coverage guard (rev-2606 audit-01 / audit-02): every CLI verb that
//! writes config must route through the single audit seam
//! [`persist_cli_mutation_audit`] (or the blocklists `persist_audit`
//! signature-adapter, which forwards to it). Source-scan trip-wire — a
//! sibling of the `tests/frozen_strings_*` suite — so a future
//! `warden <verb>` that mutates config but forgets the audit line fails the
//! build instead of silently shrinking coverage. The guard *is* the
//! regression backstop the per-verb spot-adds could otherwise lose.
//!
//! Mechanism: per-function scan. A function is a WRITER if its body calls
//! `write_value(` or `atomic_write_and_validate`; an AUDITOR if it mentions
//! `persist_cli_mutation_audit` / `persist_audit`. Every WRITER must be an
//! AUDITOR unless it is exempt for one of two documented reasons:
//!
//! - [`REVERT_HELPERS`]: writes only to roll back to prior bytes on a
//!   validation failure (a rollback, not a mutation to record).
//! - [`AUDIT_DELEGATED`]: a compound-write inner core whose audit record is
//!   emitted by its public `run_*` caller (the single-seat `*_inner`
//!   pattern).
//!
//! Both lists are explicit so each exemption is a reviewed, documented
//! decision rather than a silent gap.

/// Entity / read-verb command modules that can mutate config.
const SOURCES: &[(&str, &str)] = &[
    ("rules.rs", include_str!("../src/cli/commands/rules.rs")),
    ("rewrite.rs", include_str!("../src/cli/commands/rewrite.rs")),
    (
        "local_dns.rs",
        include_str!("../src/cli/commands/local_dns.rs"),
    ),
    (
        "blocklists.rs",
        include_str!("../src/cli/commands/blocklists.rs"),
    ),
    ("devices.rs", include_str!("../src/cli/commands/devices.rs")),
    ("groups.rs", include_str!("../src/cli/commands/groups.rs")),
    ("labels.rs", include_str!("../src/cli/commands/labels.rs")),
    ("subnets.rs", include_str!("../src/cli/commands/subnets.rs")),
    ("lists.rs", include_str!("../src/cli/commands/lists.rs")),
];

/// Writers that only restore prior bytes on a validation failure — a
/// rollback, never a mutation to audit.
const REVERT_HELPERS: &[&str] = &[
    "rules.rs::revert_master",
    "rules.rs::revert_file",
    "subnets.rs::revert_target",
];

/// Compound-write inner cores whose audit record is emitted by their
/// public `run_*` caller (the single-seat `*_inner` pattern). The trailing
/// comment names the verb that audits on each one's behalf.
const AUDIT_DELEGATED: &[&str] = &[
    "rules.rs::add_inner",                  // audited by run_apply
    "rules.rs::remove_inner",               // audited by run_apply
    "rules.rs::undo_inner",                 // audited by run_undo
    "rules.rs::prune_inner",                // audited by run_prune
    "rules.rs::move_admin_rule",            // rule action-flip; audited at the run_apply seam
    "rules.rs::rewrite_master_rule_action", // sub-step of move_admin_rule
    "rules.rs::remove_admin_rule_by_id",    // sub-step of move_admin_rule
    "devices.rs::apply_set_inline",         // audited by run_set / run_block / run_unblock
];

/// Split a source file into `(fn_name, fn_body)` pairs, scanning only
/// non-test code (everything before the `#[cfg(test)] mod tests` block).
/// Body is captured by brace-balancing from the signature's opening brace.
fn functions(src: &str) -> Vec<(String, String)> {
    let scan = match src.find("#[cfg(test)]\nmod tests") {
        Some(i) => &src[..i],
        None => src,
    };
    let bytes = scan.as_bytes();
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel) = scan[cursor..].find("fn ") {
        let fn_kw = cursor + rel;
        cursor = fn_kw + 3;
        // Word-boundary before `fn` so we skip `fn` inside identifiers.
        let boundary_ok = fn_kw == 0
            || !scan[..fn_kw]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || c == '_');
        if !boundary_ok {
            continue;
        }
        let after = &scan[cursor..];
        let name: String = after
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            continue;
        }
        // Real definitions are followed by `(` (args) or `<` (generics);
        // this filters the word "fn" appearing in comments / prose.
        let next = after[name.len()..].trim_start().chars().next();
        if !matches!(next, Some('(') | Some('<')) {
            continue;
        }
        let Some(brace_off) = scan[fn_kw..].find('{') else {
            continue;
        };
        let body_start = fn_kw + brace_off;
        let mut depth = 0i32;
        let mut end = body_start;
        for (k, &b) in bytes[body_start..].iter().enumerate() {
            if b == b'{' {
                depth += 1;
            } else if b == b'}' {
                depth -= 1;
                if depth == 0 {
                    end = body_start + k + 1;
                    break;
                }
            }
        }
        out.push((name, scan[body_start..end].to_string()));
    }
    out
}

#[test]
fn every_config_writer_routes_through_the_audit_seam() {
    let mut offenders = Vec::new();
    for (file, src) in SOURCES {
        for (name, body) in functions(src) {
            let writes =
                body.contains("write_value(") || body.contains("atomic_write_and_validate");
            if !writes {
                continue;
            }
            let audits =
                body.contains("persist_cli_mutation_audit") || body.contains("persist_audit");
            let key = format!("{file}::{name}");
            if audits
                || REVERT_HELPERS.contains(&key.as_str())
                || AUDIT_DELEGATED.contains(&key.as_str())
            {
                continue;
            }
            offenders.push(key);
        }
    }
    assert!(
        offenders.is_empty(),
        "these CLI fns write config but do not route through the audit seam.\n\
         Fix one of three ways: add a `persist_cli_mutation_audit` emit; or, if a \
         public `run_*` caller audits on their behalf, add the key to \
         AUDIT_DELEGATED with a justification; or, for a rollback-only helper, \
         add it to REVERT_HELPERS:\n  {}",
        offenders.join("\n  ")
    );
}

#[test]
fn audit_seam_defined_once_outside_command_modules() {
    // The policy seam lives in exactly one place (audit_emit.rs). A command
    // module re-defining `fn persist_cli_mutation_audit` would reintroduce
    // the per-verb failure-handling drift this guard exists to prevent
    // (audit-02).
    for (file, src) in SOURCES {
        assert!(
            !src.contains("fn persist_cli_mutation_audit"),
            "{file} defines its own persist_cli_mutation_audit — the seam must \
             live only in cli/commands/audit_emit.rs"
        );
    }
    let seam = include_str!("../src/cli/commands/audit_emit.rs");
    assert_eq!(
        seam.matches("pub fn persist_cli_mutation_audit").count(),
        1,
        "audit_emit.rs must define the audit seam exactly once"
    );
}
