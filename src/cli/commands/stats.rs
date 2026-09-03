//! Stats CLI command — top-blocked, top-queried, hourly, daily trends.

use std::path::Path;

use crate::ipc::protocol::{IpcCommand, IpcResponse};
use crate::ipc::socket_client;

/// Warn when `--limit` asked for more rows than the daemon sent.
///
/// The daemon truncates its top-N lists to `tracking.top_n_limit`
/// (default 20) before they ever reach the socket, and `--limit` is
/// applied client-side over what arrived. So `--limit 100` printed 20
/// rows and said nothing — indistinguishable from "there are only 20
/// domains", which is a different and much more reassuring fact.
///
/// The CLI cannot raise the ceiling; the value is daemon-side config.
/// The honest thing is to name it, so the operator knows the list is
/// short because of a setting and not because of their traffic.
fn warn_if_truncated(requested: usize, received: usize) {
    if requested > received {
        eprintln!(
            "note: showing {received} row(s); the daemon caps its top-N lists at \
             tracking.top_n_limit, so --limit {requested} cannot return more. \
             Raise tracking.top_n_limit in the config to widen it."
        );
    }
}

pub async fn run_top_blocked(socket_path: &Path, limit: usize, json: bool) -> anyhow::Result<()> {
    let resp = socket_client::send_command(socket_path, &IpcCommand::TrackingStats { token: None })
        .await?;
    match resp {
        IpcResponse::TrackingStats { top_blocked, .. } => {
            warn_if_truncated(limit, top_blocked.len());
            if json {
                let limited: Vec<_> = top_blocked.into_iter().take(limit).collect();
                println!("{}", serde_json::to_string_pretty(&limited)?);
            } else {
                println!("Top blocked domains:");
                for (i, entry) in top_blocked.iter().take(limit).enumerate() {
                    println!("  {:>2}. {:<40} {} hits", i + 1, entry.domain, entry.count);
                }
                if top_blocked.is_empty() {
                    println!("  (no data yet)");
                }
            }
            Ok(())
        }
        IpcResponse::Error { message } => anyhow::bail!("{message}"),
        _ => anyhow::bail!("unexpected response"),
    }
}

pub async fn run_top_queried(socket_path: &Path, limit: usize, json: bool) -> anyhow::Result<()> {
    let resp = socket_client::send_command(socket_path, &IpcCommand::TrackingStats { token: None })
        .await?;
    match resp {
        IpcResponse::TrackingStats { top_queried, .. } => {
            warn_if_truncated(limit, top_queried.len());
            if json {
                let limited: Vec<_> = top_queried.into_iter().take(limit).collect();
                println!("{}", serde_json::to_string_pretty(&limited)?);
            } else {
                println!("Top queried domains:");
                for (i, entry) in top_queried.iter().take(limit).enumerate() {
                    println!("  {:>2}. {:<40} {} hits", i + 1, entry.domain, entry.count);
                }
                if top_queried.is_empty() {
                    println!("  (no data yet)");
                }
            }
            Ok(())
        }
        IpcResponse::Error { message } => anyhow::bail!("{message}"),
        _ => anyhow::bail!("unexpected response"),
    }
}

pub async fn run_hourly(socket_path: &Path, json: bool) -> anyhow::Result<()> {
    let resp = socket_client::send_command(socket_path, &IpcCommand::TrackingStats { token: None })
        .await?;
    match resp {
        IpcResponse::TrackingStats { hourly, .. } => {
            if json {
                println!("{}", serde_json::to_string_pretty(&hourly)?);
            } else {
                // "HOUR (UTC)", not "HOUR". `format_timestamp` formats
                // in UTC unconditionally; under a bare header a CET/CEST
                // operator misreads every bucket by one or two hours, and
                // nothing in the output tells them so.
                println!(
                    "{:<20} {:>8} {:>8} {:>14}",
                    "HOUR (UTC)", "QUERIES", "BLOCKED", "CACHE HIT RATE"
                );
                for bucket in &hourly {
                    let rate = if bucket.queries > 0 {
                        (bucket.cache_hits as f64 / bucket.queries as f64) * 100.0
                    } else {
                        0.0
                    };
                    println!(
                        "  {:<18} {:>8} {:>8} {:>12.1}%",
                        format_timestamp(bucket.timestamp),
                        bucket.queries,
                        bucket.blocked,
                        rate,
                    );
                }
                if hourly.is_empty() {
                    println!("  (no data yet)");
                }
            }
            Ok(())
        }
        IpcResponse::Error { message } => anyhow::bail!("{message}"),
        _ => anyhow::bail!("unexpected response"),
    }
}

pub async fn run_daily(socket_path: &Path, json: bool) -> anyhow::Result<()> {
    let resp = socket_client::send_command(socket_path, &IpcCommand::TrackingStats { token: None })
        .await?;
    match resp {
        IpcResponse::TrackingStats { daily, .. } => {
            if json {
                println!("{}", serde_json::to_string_pretty(&daily)?);
            } else {
                // See the note in `run_hourly`: these buckets are UTC
                // days, which for an operator east of Greenwich do not
                // line up with their calendar days.
                println!(
                    "{:<14} {:>8} {:>8} {:>14}",
                    "DATE (UTC)", "QUERIES", "BLOCKED", "CACHE HIT RATE"
                );
                for bucket in &daily {
                    let rate = if bucket.queries > 0 {
                        (bucket.cache_hits as f64 / bucket.queries as f64) * 100.0
                    } else {
                        0.0
                    };
                    println!(
                        "  {:<12} {:>8} {:>8} {:>12.1}%",
                        format_date(bucket.timestamp),
                        bucket.queries,
                        bucket.blocked,
                        rate,
                    );
                }
                if daily.is_empty() {
                    println!("  (no data yet)");
                }
            }
            Ok(())
        }
        IpcResponse::Error { message } => anyhow::bail!("{message}"),
        _ => anyhow::bail!("unexpected response"),
    }
}

/// Format a Unix timestamp as "YYYY-MM-DD HH:MM", **in UTC**.
///
/// Not the operator's local time, and the column headers say so. There
/// is no timezone in the daemon's bucket data to convert from, so
/// rendering local time here would mean guessing.
fn format_timestamp(secs: u64) -> String {
    // Simple UTC formatting without external crate
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hour = time_secs / 3600;
    let minute = (time_secs % 3600) / 60;

    let (year, month, day) = days_to_date(days);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}")
}

/// Format a Unix timestamp as "YYYY-MM-DD", **in UTC**. See
/// [`format_timestamp`].
fn format_date(secs: u64) -> String {
    let days = secs / 86400;
    let (year, month, day) = days_to_date(days);
    format!("{year:04}-{month:02}-{day:02}")
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_date(days: u64) -> (u64, u64, u64) {
    // Civil calendar algorithm from Howard Hinnant
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn days_to_date_matches_time_crate_across_boundaries() {
        // Validate the hand-rolled Hinnant civil-calendar algorithm against
        // the `time` crate oracle across epoch, leap days, a div-400 leap
        // century (2000), and a non-leap century (2100).
        let cases: [i64; 6] = [
            0,             // 1970-01-01 (epoch)
            946_684_800,   // 2000-01-01
            951_782_400,   // 2000-02-29 (leap, divisible by 400)
            1_582_934_400, // 2020-02-29 (leap)
            4_107_542_400, // ~2100 (non-leap century: 2100 % 100 == 0, % 400 != 0)
            1_609_459_200, // 2021-01-01
        ];
        for secs in cases {
            let want = time::OffsetDateTime::from_unix_timestamp(secs).unwrap();
            let expect = format!(
                "{:04}-{:02}-{:02}",
                want.year(),
                u8::from(want.month()),
                want.day()
            );
            assert_eq!(format_date(secs as u64), expect, "secs={secs}");
        }
    }

    #[test]
    fn format_timestamp_matches_time_crate() {
        let secs: i64 = 1_623_761_115;
        let want = time::OffsetDateTime::from_unix_timestamp(secs).unwrap();
        let expect = format!(
            "{:04}-{:02}-{:02} {:02}:{:02}",
            want.year(),
            u8::from(want.month()),
            want.day(),
            want.hour(),
            want.minute()
        );
        assert_eq!(format_timestamp(secs as u64), expect);
    }
}
