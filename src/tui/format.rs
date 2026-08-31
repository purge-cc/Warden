//! Display formatters shared across TUI tabs.
//!
//! Single source of truth so the same number renders identically on
//! every tab. Before this module each tab carried its own `format_count`
//! with drifted precision (Dashboard rendered `1.23M` while Devices and
//! Lists rendered `1.2M` for the same value).

/// Render a count with K / M suffix. Used by Dashboard, Devices, and
/// Lists for query / blocked / cache / domain counters.
pub fn count(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 10_000 {
        format!("{:.0}K", n as f64 / 1_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_under_thousand_is_plain() {
        assert_eq!(count(0), "0");
        assert_eq!(count(42), "42");
        assert_eq!(count(999), "999");
    }

    #[test]
    fn count_thousands_render_with_one_decimal() {
        assert_eq!(count(1_000), "1.0K");
        assert_eq!(count(1_234), "1.2K");
        assert_eq!(count(9_999), "10.0K");
    }

    #[test]
    fn count_ten_thousands_drop_decimal() {
        assert_eq!(count(10_000), "10K");
        assert_eq!(count(123_456), "123K");
        assert_eq!(count(999_999), "1000K");
    }

    #[test]
    fn count_millions_render_with_one_decimal() {
        assert_eq!(count(1_000_000), "1.0M");
        assert_eq!(count(1_234_000), "1.2M");
        assert_eq!(count(12_345_678), "12.3M");
    }
}
