//! `warden security` — read and edit `[security.rrl]` and
//! `[security.rate_limit]` without hand-editing TOML.
//!
//! Part B of `security-rrl-cli-and-prefix-scope`. Both sections existed in
//! config and were validated, but no verb touched them: `warden config
//! edit` opening `$EDITOR` was the only path, which is a poor answer for
//! settings an operator tunes in response to a live incident.
//!
//! Follows CLAUDE.md design rule 6 — the config file stays the single
//! source of truth. `set` edits the TOML through
//! [`write_value_validated`] (which validates the COMBINED master +
//! includes state before promoting anything) and then asks the daemon to
//! reload, exactly like `local-dns` and `rewrite` do. There is no separate
//! runtime state to keep in step.

use std::path::Path;

use anyhow::{bail, Context};
use toml::Value;

use crate::config::loader::load_config;

use super::target::{read_or_empty, write_value_validated};

/// One tunable, its config path, and how to parse an operator's string.
///
/// A table rather than a `match` arm per key so `show`, `set` and the
/// error message that lists valid keys all read the SAME source. When
/// they drifted apart in other subsystems the result was a verb that
/// accepted a key `show` never printed.
struct Knob {
    /// Dotted key as the operator types it, e.g. `rrl.slip_rate`.
    key: &'static str,
    /// TOML section under `[security]`.
    section: &'static str,
    /// Leaf field name inside that section.
    field: &'static str,
    /// What the value means, printed by `show`.
    help: &'static str,
    kind: KnobKind,
    /// `true` only for `rrl.enabled` / `rate_limit.enabled`: each
    /// sub-checker is an `Option` decided once, when `SecurityLayer` is
    /// built (`dns::handler::SecurityLayer::from_config`), so no reload
    /// can flip a checker on or off — `handle_reload` only ever swaps
    /// *parameters* inside an already-built checker (see
    /// `cli::commands::start::handle_reload`). `set` still writes the
    /// value — an operator staging a change ahead of a planned restart
    /// needs that — but must not claim the running daemon changed.
    restart_required: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum KnobKind {
    Bool,
    /// Non-negative integer. The config validator enforces the real
    /// ranges (e.g. `window_secs` 1..=86400); this only rejects input
    /// that is not an integer at all, so the operator gets "not a
    /// number" rather than a validator error about a field they typed
    /// correctly.
    Uint,
    /// Finite float. Same division of labour as [`Self::Uint`]: this
    /// rejects "not a number", the validator rejects NaN/inf/<= 0.
    Float,
}

const KNOBS: &[Knob] = &[
    // rrl.enabled / rate_limit.enabled are the two knobs a reload cannot
    // reach — see `Knob::restart_required`. Kept in the table (unlike
    // `tunneling.enabled`, which is omitted below) so `set` can still
    // stage the value; `run_set` reports the restart requirement instead
    // of silently pretending the write took effect immediately.
    Knob {
        key: "rrl.enabled",
        section: "rrl",
        field: "enabled",
        help: "response rate limiting on/off",
        kind: KnobKind::Bool,
        restart_required: true,
    },
    Knob {
        key: "rrl.responses_per_second",
        section: "rrl",
        field: "responses_per_second",
        help: "per-bucket response budget rate (budget = this x window_secs)",
        kind: KnobKind::Uint,
        restart_required: false,
    },
    Knob {
        key: "rrl.window_secs",
        section: "rrl",
        field: "window_secs",
        help: "sliding window length in seconds",
        kind: KnobKind::Uint,
        restart_required: false,
    },
    Knob {
        key: "rrl.slip_rate",
        section: "rrl",
        field: "slip_rate",
        help: "1-in-N throttled responses get TC=1 instead of a drop (0 = always drop)",
        kind: KnobKind::Uint,
        restart_required: false,
    },
    Knob {
        key: "rate_limit.enabled",
        section: "rate_limit",
        field: "enabled",
        help: "per-client query rate limiting on/off",
        kind: KnobKind::Bool,
        restart_required: true,
    },
    Knob {
        key: "rate_limit.queries_per_second",
        section: "rate_limit",
        field: "queries_per_second",
        help: "sustained queries per second per client IP",
        kind: KnobKind::Uint,
        restart_required: false,
    },
    Knob {
        key: "rate_limit.burst",
        section: "rate_limit",
        field: "burst",
        help: "queries allowed instantly before throttling begins",
        kind: KnobKind::Uint,
        restart_required: false,
    },
    // `[security.tunneling]`. Deliberately WITHOUT `tunneling.enabled`:
    // the detector is an `Option` decided when the handler is built, so
    // the flag cannot be reached by a reload. Exposing it here would make
    // `set` print success for a change that silently does nothing until
    // the next restart — the same shape of defect `rrl.enabled` and
    // `rate_limit.enabled` have, handled above by `restart_required`
    // instead of by omission (both were already CLI-reachable before
    // this table grew a way to say so).
    Knob {
        key: "tunneling.label_len_threshold",
        section: "tunneling",
        field: "label_len_threshold",
        help: "label length that flags a name (longest legitimate seen: 43)",
        kind: KnobKind::Uint,
        restart_required: false,
    },
    Knob {
        key: "tunneling.max_unbroken_run",
        section: "tunneling",
        field: "max_unbroken_run",
        help: "longest hyphen-free run that flags a name (primary signal)",
        kind: KnobKind::Uint,
        restart_required: false,
    },
    Knob {
        key: "tunneling.entropy_min_len",
        section: "tunneling",
        field: "entropy_min_len",
        help: "length below which the entropy heuristic never fires",
        kind: KnobKind::Uint,
        restart_required: false,
    },
    Knob {
        key: "tunneling.entropy_threshold",
        section: "tunneling",
        field: "entropy_threshold",
        help: "entropy that flags a name, once past entropy_min_len",
        kind: KnobKind::Float,
        restart_required: false,
    },
    Knob {
        key: "tunneling.subdomain_rate",
        section: "tunneling",
        field: "subdomain_rate",
        help: "cache-missing queries per (client, base domain) per window",
        kind: KnobKind::Uint,
        restart_required: false,
    },
    Knob {
        key: "tunneling.window_secs",
        section: "tunneling",
        field: "window_secs",
        help: "window for the subdomain rate counter",
        kind: KnobKind::Uint,
        restart_required: false,
    },
];

/// Keys with their meanings, for `show` and for the unknown-key error.
///
/// One renderer for both: an operator who mistypes a key gets the same
/// annotated list they would have got from `show`, instead of a bare
/// name list that makes them run a second command to find out what the
/// right key does.
fn knob_list() -> String {
    KNOBS
        .iter()
        .map(|k| format!("{:<30} {}", k.key, k.help))
        .collect::<Vec<_>>()
        .join("\n  ")
}

/// `warden security show` — print the effective RRL and rate-limit
/// settings, reading the same resolved config the daemon loads.
pub fn run_show(config_path: &Path) -> anyhow::Result<()> {
    let now = time::OffsetDateTime::now_utc();
    let loaded = load_config(config_path, now).map_err(|errs| {
        anyhow::anyhow!(
            "cannot read config: {}",
            errs.iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("; ")
        )
    })?;
    let sec = &loaded.config.security;

    println!("[security.rrl]");
    println!("  enabled:               {}", sec.rrl.enabled);
    println!("  responses_per_second:  {}", sec.rrl.responses_per_second);
    println!("  window_secs:           {}", sec.rrl.window_secs);
    println!("  slip_rate:             {}", sec.rrl.slip_rate);
    // The budget is the product, and operators consistently read
    // `responses_per_second` as a per-second cap. Spelling it out here is
    // the difference between "5 looks small" and "5 means 75 per window".
    println!(
        "  → effective budget:    {} responses per {}s window, per bucket",
        u64::from(sec.rrl.responses_per_second) * sec.rrl.window_secs,
        sec.rrl.window_secs
    );
    // Which bucket, because this changed and is not guessable from config.
    println!(
        "  → bucket:              per client address inside `server.allow_from`, \
         per /24 (IPv4) or /48 (IPv6) outside it"
    );

    println!();
    println!("[security.rate_limit]");
    println!("  enabled:               {}", sec.rate_limit.enabled);
    println!(
        "  queries_per_second:    {}",
        sec.rate_limit.queries_per_second
    );
    println!("  burst:                 {}", sec.rate_limit.burst);

    println!();
    println!("[security.tunneling]");
    println!("  enabled:               {}", sec.tunneling.enabled);
    println!(
        "  label_len_threshold:   {}",
        sec.tunneling.label_len_threshold
    );
    println!(
        "  max_unbroken_run:      {}",
        sec.tunneling.max_unbroken_run
    );
    println!("  entropy_min_len:       {}", sec.tunneling.entropy_min_len);
    println!(
        "  entropy_threshold:     {}",
        sec.tunneling.entropy_threshold
    );
    println!("  subdomain_rate:        {}", sec.tunneling.subdomain_rate);
    println!("  window_secs:           {}", sec.tunneling.window_secs);
    // Spelled out because it is the least guessable part: these gates run
    // before the filter engine, so an operator who finds a legitimate name
    // refused cannot fix it with an allow rule. This list is the remedy.
    if sec.tunneling.exempt_domains.is_empty() {
        println!("  exempt_domains:        (none)");
    } else {
        println!("  exempt_domains:");
        for d in &sec.tunneling.exempt_domains {
            println!("      {d}");
        }
    }
    println!(
        "  → exemptions skip BOTH the shape gates and the subdomain rate \
         counter, for every name under the suffix"
    );

    println!();
    println!("Change one with: warden security set <key> <value>");
    println!("Keys:\n  {}", knob_list());
    println!();
    println!("Exempt a name from tunneling detection (applies without a restart):");
    println!("  warden security tunneling exempt <domain>");
    println!("  warden security tunneling unexempt <domain>");
    Ok(())
}

/// `warden security tunneling exempt|unexempt <domain>` — edit
/// `[security.tunneling] exempt_domains`, then reload.
///
/// A list, so it cannot ride [`run_set`], which takes a scalar. Kept a
/// distinct verb rather than overloading `set` with list semantics: an
/// operator reaching for this is recovering from a refused query and
/// should not have to reason about whether `set` appends or replaces.
pub async fn run_tunneling_exempt(
    config_path: &Path,
    socket_path: &Path,
    domain: &str,
    remove: bool,
) -> anyhow::Result<()> {
    let normalized = domain.trim().trim_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        bail!("domain is empty");
    }
    // Refused here as well as in the validator so the operator gets the
    // reason at the point of typing, rather than a validation failure on
    // a file that was already written.
    if normalized.split('.').filter(|l| !l.is_empty()).count() < 2 {
        bail!(
            "'{normalized}' is a single label — exempting a whole TLD disables \
             tunneling detection for most of the namespace. Use \
             `warden security set tunneling.enabled false` if that is the intent."
        );
    }

    let (mut doc, _orig) = read_or_empty(config_path)?;
    let table = doc
        .as_table_mut()
        .context("config root is not a TOML table")?;
    let security = table
        .entry("security")
        .or_insert_with(|| Value::Table(Default::default()))
        .as_table_mut()
        .context("[security] exists but is not a table")?;
    let tunneling = security
        .entry("tunneling")
        .or_insert_with(|| Value::Table(Default::default()))
        .as_table_mut()
        .context("[security.tunneling] exists but is not a table")?;

    let mut entries: Vec<String> = tunneling
        .get("exempt_domains")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    // Read from the FILE, not from the loaded config: a value the loader
    // synthesised is not something the operator declared, and writing it
    // back would turn a runtime default into a config statement.
    let present = entries.iter().any(|e| e == &normalized);
    if remove {
        if !present {
            println!("'{normalized}' is not exempt — no change");
            return Ok(());
        }
        entries.retain(|e| e != &normalized);
    } else {
        if present {
            println!("'{normalized}' is already exempt — no change");
            return Ok(());
        }
        entries.push(normalized.clone());
    }
    entries.sort();

    tunneling.insert(
        "exempt_domains".to_string(),
        Value::Array(entries.iter().map(|e| Value::String(e.clone())).collect()),
    );

    write_value_validated(config_path, config_path, &doc)?;

    if remove {
        println!("security.tunneling.exempt_domains: removed '{normalized}'");
    } else {
        println!("security.tunneling.exempt_domains: added '{normalized}'");
        if normalized.split('.').filter(|l| !l.is_empty()).count() == 2 {
            println!(
                "  note: this covers every name under '{normalized}', including \
                 ones you have not seen. Narrow it to the specific hostname if \
                 you can."
            );
        }
        // The trap worth naming up front: operators copy the exact name
        // out of the query log, and if it embeds a rotating token the
        // exemption matches once and never again.
        println!(
            "  note: if the refused name embeds a rotating token, exempt its \
             parent instead — an exact name will stop matching."
        );
    }

    let outcome = super::ipc_reload::attempt_reload(socket_path).await;
    super::ipc_reload::report_reload_outcome(&outcome);
    Ok(())
}

/// `warden security set <key> <value>` — edit the TOML, then reload.
pub async fn run_set(
    config_path: &Path,
    socket_path: &Path,
    key: &str,
    value: &str,
) -> anyhow::Result<()> {
    let knob = KNOBS
        .iter()
        .find(|k| k.key == key)
        .with_context(|| format!("unknown key '{key}'\nvalid keys:\n  {}", knob_list()))?;

    let parsed = parse_value(knob, value)?;

    // `[security]` lives in the master, not an include — same shape as
    // `lists.rs` / `devices.rs`, which pass the master as both the
    // validation root and the write target.
    let (mut doc, _orig) = read_or_empty(config_path)?;
    let table = doc
        .as_table_mut()
        .context("config root is not a TOML table")?;

    let security = table
        .entry("security")
        .or_insert_with(|| Value::Table(Default::default()))
        .as_table_mut()
        .context("[security] exists but is not a table")?;
    let section = security
        .entry(knob.section)
        .or_insert_with(|| Value::Table(Default::default()))
        .as_table_mut()
        .with_context(|| format!("[security.{}] exists but is not a table", knob.section))?;

    let previous = section.get(knob.field).cloned();
    if previous.as_ref() == Some(&parsed) {
        // No-op writes still cost a reload, and a reload on a live
        // resolver is not free. Mirrors `local-dns`'s NoOp path.
        println!("security.{key} is already {value} — no change");
        return Ok(());
    }
    section.insert(knob.field.to_string(), parsed);

    // Validates master + every include as one combined state BEFORE any
    // file is promoted, so an out-of-range value is refused with the
    // config untouched rather than written and then rejected at load.
    write_value_validated(config_path, config_path, &doc)?;

    match previous {
        Some(p) => println!("security.{key}: {p} → {value}"),
        None => println!("security.{key} = {value} (was unset, using the built-in default)"),
    }

    let outcome = super::ipc_reload::attempt_reload(socket_path).await;
    super::ipc_reload::report_reload_outcome(&outcome);

    // Printed AFTER the reload outcome on purpose: `report_reload_outcome`
    // may say "daemon reloaded — change is live" (a frozen string, see
    // `tests/frozen_strings_*.rs`), which is false for these two keys.
    // This note is the qualifying last word rather than a contradiction
    // baked into the frozen text itself.
    if let Some(note) = restart_required_note(knob) {
        println!("  note: {note}");
    }
    Ok(())
}

/// The restart caveat for `rrl.enabled` / `rate_limit.enabled` — the two
/// knobs `handle_reload` cannot reach (see `Knob::restart_required`).
///
/// A free function returning the string, rather than a `println!` inlined
/// into [`run_set`], so the decision "write the value, but say plainly it
/// needs a restart" is unit-testable without stubbing the IPC socket.
fn restart_required_note(knob: &Knob) -> Option<&'static str> {
    knob.restart_required.then_some(
        "this checker's presence is decided once, when the daemon starts — \
         the value is saved but the running daemon keeps its old behaviour \
         until you restart it",
    )
}

/// Parse the operator's string per the knob's declared type.
fn parse_value(knob: &Knob, raw: &str) -> anyhow::Result<Value> {
    match knob.kind {
        KnobKind::Bool => match raw {
            "true" | "on" | "yes" | "1" => Ok(Value::Boolean(true)),
            "false" | "off" | "no" | "0" => Ok(Value::Boolean(false)),
            other => bail!("'{other}' is not a boolean — use true/false (also on/off, yes/no)"),
        },
        KnobKind::Uint => {
            let n: i64 = raw
                .parse()
                .with_context(|| format!("'{raw}' is not a whole number"))?;
            if n < 0 {
                bail!("'{raw}' is negative; {} must be >= 0", knob.key);
            }
            Ok(Value::Integer(n))
        }
        KnobKind::Float => {
            let f: f64 = raw
                .parse()
                .with_context(|| format!("'{raw}' is not a number"))?;
            if !f.is_finite() {
                bail!(
                    "'{raw}' is not a finite number; {} must be finite",
                    knob.key
                );
            }
            Ok(Value::Float(f))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every knob's dotted key must be exactly `section.field`. `show`
    /// prints from the struct fields while `set` writes via
    /// `section`/`field`, so a mismatch would let `set` silently write a
    /// key that `show` never reads back.
    #[test]
    fn knob_keys_match_their_section_and_field() {
        for k in KNOBS {
            assert_eq!(
                k.key,
                format!("{}.{}", k.section, k.field),
                "knob '{}' would write to security.{}.{}",
                k.key,
                k.section,
                k.field
            );
        }
    }

    /// `handle_reload` (`cli::commands::start`) only ever swaps
    /// *parameters* inside an already-built checker — it cannot flip a
    /// checker between `Some`/`None`. That is true of exactly these two
    /// knobs; every other knob's field is read fresh by `set_params` on
    /// every reload, so a `restart_required` drift here would either
    /// under-warn (operator thinks a change is live when it is not) or
    /// over-warn (operator restarts for nothing).
    #[test]
    fn restart_required_flags_only_the_two_unreachable_enabled_knobs() {
        for k in KNOBS {
            let expected = k.key == "rrl.enabled" || k.key == "rate_limit.enabled";
            assert_eq!(
                k.restart_required, expected,
                "knob '{}' restart_required should be {expected}",
                k.key
            );
        }
    }

    #[test]
    fn restart_required_note_present_only_for_flagged_knobs() {
        for k in KNOBS {
            assert_eq!(
                restart_required_note(k).is_some(),
                k.restart_required,
                "knob '{}': note presence must track restart_required",
                k.key
            );
        }
    }

    #[test]
    fn knob_keys_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for k in KNOBS {
            assert!(seen.insert(k.key), "duplicate knob key '{}'", k.key);
        }
    }

    #[test]
    fn bool_parsing_accepts_the_documented_spellings_and_rejects_others() {
        let knob = KNOBS.iter().find(|k| k.key == "rrl.enabled").unwrap();
        for yes in ["true", "on", "yes", "1"] {
            assert_eq!(parse_value(knob, yes).unwrap(), Value::Boolean(true));
        }
        for no in ["false", "off", "no", "0"] {
            assert_eq!(parse_value(knob, no).unwrap(), Value::Boolean(false));
        }
        // A number is NOT silently coerced — `rrl.enabled 5` is a typo,
        // and accepting it as `true` would hide the mistake.
        assert!(parse_value(knob, "5").is_err());
        assert!(parse_value(knob, "").is_err());
    }

    #[test]
    fn uint_parsing_rejects_negatives_and_non_numbers() {
        let knob = KNOBS
            .iter()
            .find(|k| k.key == "rrl.responses_per_second")
            .unwrap();
        assert_eq!(parse_value(knob, "100").unwrap(), Value::Integer(100));
        assert_eq!(parse_value(knob, "0").unwrap(), Value::Integer(0));
        assert!(
            parse_value(knob, "-1").is_err(),
            "a negative budget must not reach the validator as a huge unsigned"
        );
        assert!(parse_value(knob, "many").is_err());
        assert!(parse_value(knob, "1.5").is_err());
    }
}
