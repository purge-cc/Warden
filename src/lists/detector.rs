//! List format auto-detection.
//!
//! Examines the first non-comment, non-empty lines of a list to determine
//! whether it uses domain-per-line, hosts file, or AdGuard DNS syntax.

/// Supported blocklist formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListFormat {
    /// One domain per line (purge.cc native format).
    DomainOnly,
    /// Hosts file: `0.0.0.0 domain` or `127.0.0.1 domain`.
    Hosts,
    /// AdGuard DNS filter syntax: `||domain^`, `@@||domain^`, etc.
    AdGuard,
}

/// Maximum number of content lines to examine for format detection.
const DETECT_LINES: usize = 10;

/// Detect the list format from file content.
///
/// Scans the first [`DETECT_LINES`] non-comment, non-empty lines. If any
/// line matches a format-specific marker, that format wins immediately.
/// Priority: AdGuard > Hosts > DomainOnly (fallback).
pub fn detect_format(content: &str) -> ListFormat {
    let mut checked = 0;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
            continue;
        }
        if checked >= DETECT_LINES {
            break;
        }
        checked += 1;

        // AdGuard markers: ||domain^ or @@||domain^
        if trimmed.starts_with("||") || trimmed.starts_with("@@||") {
            return ListFormat::AdGuard;
        }

        // Hosts markers: 0.0.0.0 or 127.0.0.1 prefix
        if trimmed.starts_with("0.0.0.0 ") || trimmed.starts_with("127.0.0.1 ") {
            return ListFormat::Hosts;
        }
    }

    ListFormat::DomainOnly
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_domain_only() {
        let content = "# purge.cc ads list\ntracker.example.com\nads.example.com\n";
        assert_eq!(detect_format(content), ListFormat::DomainOnly);
    }

    #[test]
    fn detect_hosts_0000() {
        let content = "# hosts file\n0.0.0.0 tracker.example.com\n0.0.0.0 ads.example.com\n";
        assert_eq!(detect_format(content), ListFormat::Hosts);
    }

    #[test]
    fn detect_hosts_127() {
        let content = "127.0.0.1 tracker.example.com\n127.0.0.1 ads.example.com\n";
        assert_eq!(detect_format(content), ListFormat::Hosts);
    }

    #[test]
    fn detect_adguard_block() {
        let content = "! AdGuard list\n||tracker.example.com^\n||ads.example.com^\n";
        assert_eq!(detect_format(content), ListFormat::AdGuard);
    }

    #[test]
    fn detect_adguard_allow_prefix() {
        let content = "@@||safe.example.com^\n||tracker.com^\n";
        assert_eq!(detect_format(content), ListFormat::AdGuard);
    }

    #[test]
    fn detect_empty_content() {
        assert_eq!(detect_format(""), ListFormat::DomainOnly);
    }

    #[test]
    fn detect_comments_only() {
        let content = "# comment 1\n! comment 2\n# comment 3\n";
        assert_eq!(detect_format(content), ListFormat::DomainOnly);
    }

    #[test]
    fn detect_skips_comments_to_find_format() {
        let content = "# Steven Black hosts\n# Updated 2026-04-01\n\n0.0.0.0 ads.example.com\n";
        assert_eq!(detect_format(content), ListFormat::Hosts);
    }

    #[test]
    fn detect_adguard_with_modifiers() {
        let content = "||tracker.com^$third-party\n||ads.com^\n";
        assert_eq!(detect_format(content), ListFormat::AdGuard);
    }

    #[test]
    fn detect_within_10_lines() {
        // 9 plain domains then a hosts line — should still detect as DomainOnly
        // because the first format match wins, and line 1 is a plain domain
        // Actually: plain domains don't trigger DomainOnly early — it's the fallback.
        // So the hosts line at position 10 should still be checked.
        let mut content = String::new();
        for i in 0..9 {
            content.push_str(&format!("domain{i}.com\n"));
        }
        content.push_str("0.0.0.0 ads.com\n");
        assert_eq!(detect_format(&content), ListFormat::Hosts);
    }

    #[test]
    fn detect_stops_after_10_lines() {
        // 11 plain domains then a hosts line — hosts line is past the limit
        let mut content = String::new();
        for i in 0..11 {
            content.push_str(&format!("domain{i}.com\n"));
        }
        content.push_str("0.0.0.0 ads.com\n");
        assert_eq!(detect_format(&content), ListFormat::DomainOnly);
    }
}
