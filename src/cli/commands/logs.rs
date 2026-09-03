//! Query log CLI command — tail/filter/export the query log via IPC.

use std::path::Path;

use clap::ValueEnum;

use crate::ipc::protocol::{IpcCommand, IpcResponse, QueryLogDto};
use crate::ipc::socket_client;

/// Output format for `warden logs`. `Text` is the human-readable default
/// used for quick tail viewing; `Json` and `Csv` are structured exports.
/// `Csv` lets operators pipe into spreadsheets without round-tripping
/// through `jq`; `Json` stays pretty-printed to match the legacy
/// `--json` flag behaviour byte-for-byte (that flag is now an alias for
/// `--format json`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    Text,
    Json,
    Csv,
}

/// Parse a humantime duration string into seconds. Thin wrapper so clap
/// can use it as a `value_parser` and surface a plain-English error
/// message on failure. Matches the `feedback_usability_first` bar: when
/// something goes wrong, show the operator exactly what to type instead.
pub fn parse_duration_to_secs(s: &str) -> Result<u64, String> {
    humantime::parse_duration(s)
        .map(|d| d.as_secs())
        .map_err(|_| format!("invalid duration '{s}' — examples: 30m, 6h, 2d"))
}

// Eight args is over the clippy default of seven, but every one is a
// distinct clap-surface flag with no natural grouping — bundling them
// into a struct would only move the noise. Single call site (main.rs).
#[allow(clippy::too_many_arguments)]
pub async fn run_logs(
    socket_path: &Path,
    limit: usize,
    client: Option<&str>,
    blocked_only: bool,
    domain: Option<&str>,
    since_secs: Option<u64>,
    format: LogFormat,
    legacy_json: bool,
) -> anyhow::Result<()> {
    let cmd = IpcCommand::QueryLogs {
        limit,
        client: client.map(|s| s.to_string()),
        blocked_only,
        domain: domain.map(|s| s.to_string()),
        since_secs,
        // `warden logs` is a one-shot dump, not a paged surface: it always
        // reads the live tail. Paging belongs to the TUI, which is the only
        // caller with somewhere to keep the cursor between requests.
        cursor: None,
        // The advanced client filter is a TUI form; `warden logs` keeps
        // its existing flags.
        advanced: None,
        token: None,
    };

    let resp = socket_client::send_command(socket_path, &cmd).await?;
    let entries = match resp {
        IpcResponse::QueryLogs {
            entries,
            logging_enabled: _,
            file_state: _,
            next_cursor: _,
            cursor_stale: _,
        } => entries,
        IpcResponse::Error { message } => anyhow::bail!("{message}"),
        _ => anyhow::bail!("unexpected response"),
    };

    // Legacy `--json` collapses to Json; otherwise honour `--format`.
    let effective = if legacy_json { LogFormat::Json } else { format };
    match effective {
        LogFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&entries)?);
        }
        LogFormat::Csv => {
            print_csv(&entries);
        }
        LogFormat::Text => {
            if entries.is_empty() {
                println!("(no log entries)");
            } else {
                for e in &entries {
                    let name = e.client_name.as_deref().unwrap_or(&e.client_ip);
                    println!(
                        "{} {:<16} {:<40} {:<8} {}",
                        e.timestamp,
                        name,
                        e.domain,
                        e.result,
                        format_time(e.response_time_us),
                    );
                }
            }
        }
    }
    Ok(())
}

fn print_csv(entries: &[QueryLogDto]) {
    // Header row. Pin the column order — operators who build sheets on
    // top of `warden logs --format csv` depend on it.
    println!("timestamp,client,domain,type,result,response_time_us");
    for e in entries {
        let client = e.client_name.as_deref().unwrap_or(&e.client_ip);
        println!(
            "{},{},{},{},{},{}",
            csv_escape(&e.timestamp),
            csv_escape(client),
            csv_escape(&e.domain),
            csv_escape(&e.query_type),
            csv_escape(&e.result),
            e.response_time_us,
        );
    }
}

/// RFC 4180 field escaping + spreadsheet formula-injection guard.
/// Quote if the field contains `,`, `"`, `\n` or `\r`
/// and double any embedded `"`. Additionally, a field that *begins* with a
/// formula trigger (`=`, `+`, `-`, `@`, or a leading tab/CR a spreadsheet
/// folds into one) is prefixed with a single quote and quoted, so a
/// config-sourced `client_name` / `display_name` like `=HYPERLINK(...)`
/// cannot execute when the export is opened in Excel / Sheets / LibreOffice.
fn csv_escape(s: &str) -> String {
    let formula_trigger = s
        .chars()
        .next()
        .is_some_and(|c| matches!(c, '=' | '+' | '-' | '@' | '\t' | '\r'));
    let needs_quote = formula_trigger
        || s.contains(',')
        || s.contains('"')
        || s.contains('\n')
        || s.contains('\r');
    if !needs_quote {
        return s.to_string();
    }
    let escaped = s.replace('"', "\"\"");
    if formula_trigger {
        // Leading apostrophe neutralises the formula; the cell stays quoted.
        format!("\"'{escaped}\"")
    } else {
        format!("\"{escaped}\"")
    }
}

fn format_time(us: u64) -> String {
    if us < 1000 {
        format!("{}us", us)
    } else {
        format!("{:.1}ms", us as f64 / 1000.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_accepts_humantime_examples() {
        assert_eq!(parse_duration_to_secs("30m").unwrap(), 1800);
        assert_eq!(parse_duration_to_secs("6h").unwrap(), 6 * 3600);
        assert_eq!(parse_duration_to_secs("2d").unwrap(), 2 * 86_400);
        assert_eq!(parse_duration_to_secs("90s").unwrap(), 90);
    }

    #[test]
    fn parse_duration_rejects_garbage_with_helpful_message() {
        let err = parse_duration_to_secs("foo").unwrap_err();
        assert!(err.contains("invalid duration"));
        assert!(err.contains("'foo'"));
        // Suggest the exact next command to try — usability-first rule.
        assert!(err.contains("30m"));
    }

    #[test]
    fn csv_escape_leaves_plain_fields_untouched() {
        assert_eq!(csv_escape("google.com"), "google.com");
        assert_eq!(csv_escape("ALLOWED"), "ALLOWED");
    }

    #[test]
    fn csv_escape_quotes_field_containing_comma() {
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
    }

    #[test]
    fn csv_escape_doubles_embedded_quotes() {
        // `he said "hi"` → `"he said ""hi"""`
        assert_eq!(csv_escape(r#"he said "hi""#), r#""he said ""hi""""#);
    }

    #[test]
    fn csv_escape_handles_embedded_newline() {
        assert_eq!(csv_escape("a\nb"), "\"a\nb\"");
    }

    #[test]
    fn csv_escape_neutralises_formula_injection() {
        // A cell beginning with =/+/-/@ is prefixed with `'` and
        // quoted so it imports as text, not an executable formula.
        assert_eq!(
            csv_escape(r#"=HYPERLINK("http://evil")"#),
            r#""'=HYPERLINK(""http://evil"")""#
        );
        assert_eq!(csv_escape("+SUM(1)"), "\"'+SUM(1)\"");
        assert_eq!(csv_escape("-1+1"), "\"'-1+1\"");
        assert_eq!(csv_escape("@cmd"), "\"'@cmd\"");
        // A formula trigger only in the MIDDLE is harmless → untouched.
        assert_eq!(csv_escape("a=b"), "a=b");
    }
}
