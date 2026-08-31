//! Hand-written parsers for the `/proc` files this sampler consumes.
//!
//! Each parser is a pure `&str → Option<…>` function so unit tests feed
//! canned input without touching the real `/proc`. The real-`/proc` I/O
//! is funnelled through [`read_proc_file`] / [`count_directory_entries`]
//! which the sampler calls; the parsers themselves never touch the
//! filesystem.
//!
//! Linux-specific formats. The module compiles on every target; the
//! sampler only invokes it under `#[cfg(target_os = "linux")]`, so
//! parsing a non-Linux `/proc` stub would be a configuration error
//! rather than a soft failure.

use std::path::Path;

/// Extract a `VmRSS:` / `VmSize:` style kilobyte value from a
/// `/proc/self/status` blob. Returns `None` when the key is absent or
/// the value column can't be parsed as a `u64`.
///
/// The line format is `<key>:<whitespace><value><whitespace>kB`. We
/// match by exact `<key>:` prefix so a future `VmRSSPeak:` (or similar)
/// can't get picked up by a naive substring match.
pub fn parse_vm_kb(status_text: &str, key: &str) -> Option<u64> {
    let prefix = format!("{key}:");
    for line in status_text.lines() {
        if let Some(rest) = line.strip_prefix(&prefix) {
            return rest
                .split_whitespace()
                .next()
                .and_then(|tok| tok.parse::<u64>().ok());
        }
    }
    None
}

/// Pull field 14 (utime, the cumulative user-mode CPU ticks) from a
/// `/proc/self/stat` blob.
///
/// The `comm` field (field 2) is parenthesised and may itself contain
/// spaces or close-parens (e.g. `(weird (proc name))`). We split on the
/// **last** `)` to skip past it before tokenising on whitespace, so a
/// command name like `(my (proc) name)` is handled correctly. After
/// that split, field 14 in `proc(5)` indexing becomes index 11 in the
/// trailing whitespace-split list (state, ppid, pgrp, session, tty_nr,
/// tpgid, flags, minflt, cminflt, majflt, cmajflt, utime → 12 tokens,
/// index 11).
pub fn parse_utime_ticks(stat_text: &str) -> Option<u64> {
    let last_close = stat_text.rfind(')')?;
    let tail = &stat_text[last_close + 1..];
    tail.split_whitespace().nth(11).and_then(|t| t.parse().ok())
}

/// Extract `MemTotal:` kilobytes from a `/proc/meminfo` blob. Same
/// idiom as [`parse_vm_kb`]; factored separately because the key set is
/// fixed and the call site is unambiguous about what it wants.
pub fn parse_meminfo_total_kb(meminfo_text: &str) -> Option<u64> {
    parse_vm_kb(meminfo_text, "MemTotal")
}

/// Read a file at `path` into a `String`. Thin wrapper so test code can
/// substitute a TempDir-rooted path while the sampler passes
/// `/proc/self/status`.
pub fn read_proc_file(path: &Path) -> std::io::Result<String> {
    std::fs::read_to_string(path)
}

/// Count the entries inside a directory. The sampler uses this against
/// `/proc/self/fd`; tests use it against a populated `TempDir`. Errors
/// propagate (e.g. `EACCES`) so the caller can surface a `None` sample
/// rather than guessing at a zero count.
pub fn count_directory_entries(path: &Path) -> std::io::Result<u32> {
    let mut n: u32 = 0;
    for entry in std::fs::read_dir(path)? {
        let _ = entry?;
        n = n.saturating_add(1);
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_STATUS: &str = "\
Name:\twarden
Umask:\t0022
State:\tS (sleeping)
Tgid:\t12345
VmPeak:\t   72180 kB
VmSize:\t   60000 kB
VmLck:\t       0 kB
VmRSS:\t   42500 kB
VmHWM:\t   42500 kB
VmData:\t   12345 kB
";

    const SAMPLE_STAT_SIMPLE: &str =
        "12345 (warden) S 1 12345 12345 0 -1 4194560 1234 0 0 0 178 23 0 0 20 0 5 0 9876 100000000 1000 18446744073709551615";

    /// `comm` field intentionally contains spaces AND a nested close-paren.
    const SAMPLE_STAT_WEIRD: &str =
        "12345 (my (proc) name) S 1 12345 12345 0 -1 4194560 1234 0 0 0 314 11 0 0 20 0 5 0 9876 100000000 1000 18446744073709551615";

    const SAMPLE_MEMINFO: &str = "\
MemTotal:        4012345 kB
MemFree:         1234567 kB
MemAvailable:    2345678 kB
Buffers:           45678 kB
";

    #[test]
    fn parse_vm_kb_extracts_vmrss() {
        assert_eq!(parse_vm_kb(SAMPLE_STATUS, "VmRSS"), Some(42500));
    }

    #[test]
    fn parse_vm_kb_extracts_vmsize() {
        assert_eq!(parse_vm_kb(SAMPLE_STATUS, "VmSize"), Some(60000));
    }

    #[test]
    fn parse_vm_kb_missing_key_returns_none() {
        // VmRSSPeak doesn't exist in SAMPLE_STATUS; VmPeak does but
        // shouldn't be matched by a "VmRSSPeak" prefix.
        assert_eq!(parse_vm_kb(SAMPLE_STATUS, "VmRSSPeak"), None);
    }

    #[test]
    fn parse_vm_kb_rejects_prefix_match() {
        // "Vm" is a prefix of many keys; we require the trailing `:`,
        // so this must not silently latch onto VmPeak.
        assert_eq!(parse_vm_kb(SAMPLE_STATUS, "Vm"), None);
    }

    #[test]
    fn parse_utime_handles_simple_comm() {
        assert_eq!(parse_utime_ticks(SAMPLE_STAT_SIMPLE), Some(178));
    }

    #[test]
    fn parse_utime_handles_paren_in_comm() {
        assert_eq!(parse_utime_ticks(SAMPLE_STAT_WEIRD), Some(314));
    }

    #[test]
    fn parse_utime_malformed_returns_none() {
        assert_eq!(parse_utime_ticks("not actually proc stat output"), None);
        // Truncated before field 14.
        assert_eq!(parse_utime_ticks("12345 (warden) S 1"), None);
    }

    #[test]
    fn parse_meminfo_total_extracts_kb() {
        assert_eq!(parse_meminfo_total_kb(SAMPLE_MEMINFO), Some(4012345));
    }

    #[test]
    fn parse_meminfo_missing_total_returns_none() {
        assert_eq!(parse_meminfo_total_kb("MemFree: 100 kB"), None);
    }

    #[test]
    fn count_directory_entries_returns_n() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..7 {
            std::fs::write(dir.path().join(format!("f{i}")), b"x").unwrap();
        }
        assert_eq!(count_directory_entries(dir.path()).unwrap(), 7);
    }

    #[test]
    fn count_directory_entries_zero_for_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(count_directory_entries(dir.path()).unwrap(), 0);
    }
}
