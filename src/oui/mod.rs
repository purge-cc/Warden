//! Disk-resident MAC OUI vendor lookup.
//!
//! Loads two `mmap`'d files: `oui.bin` (sorted prefix index) and
//! `oui.strings` (concatenated vendor names). Lookup runs a binary
//! search on the prefix slot of each fixed-width record, reading
//! directly from the mapping — no allocation in the daemon's RSS for
//! the OUI data itself. Kernel page cache serves hot pages and evicts
//! under memory pressure (Pi-friendly).
//!
//! Files are produced by the `oui-pack` build helper from the IEEE
//! OUI registry CSV (`https://standards-oui.ieee.org/oui/oui.csv`).
//! At install time they live at `/var/lib/purge-warden/data/`.

use memmap2::Mmap;
use std::fs::File;
use std::io;
use std::path::Path;

/// File magic written by `oui-pack`. Bumping this is how we'd
/// version-gate a future format change.
pub const MAGIC: &[u8; 4] = b"OUI1";

/// `[magic: 4][record_count: u32 LE]`
pub const HEADER_SIZE: usize = 8;

/// `[prefix: 3][string_offset: u32 LE]`
pub const RECORD_SIZE: usize = 7;

/// MAC OUI lookup table backed by two `mmap`'d files. Not `Clone` — a `Mmap`
/// owns its mapping and is not itself `Clone`; share a single instance behind
/// an `Arc<OuiTable>` so the mapping stays resident once and lookups borrow it.
pub struct OuiTable {
    bin: Mmap,
    strings: Mmap,
    record_count: usize,
}

impl std::fmt::Debug for OuiTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OuiTable")
            .field("record_count", &self.record_count)
            .field("strings_len", &self.strings.len())
            .finish()
    }
}

impl OuiTable {
    /// Open `dir/oui.bin` and `dir/oui.strings`. Returns `Err` if either
    /// file is missing, the magic doesn't match, or the size doesn't
    /// agree with the embedded record count. Daemon should log the
    /// error and store `None`; lookups will return `None` and the TUI
    /// hides the vendor row.
    pub fn open(dir: &Path) -> io::Result<Self> {
        let bin = mmap_file(&dir.join("oui.bin"))?;
        let strings = mmap_file(&dir.join("oui.strings"))?;

        if bin.len() < HEADER_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("oui.bin too short: {} bytes", bin.len()),
            ));
        }
        if &bin[0..4] != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "oui.bin: wrong magic (expected OUI1)",
            ));
        }
        let record_count = u32::from_le_bytes(bin[4..8].try_into().unwrap()) as usize;
        // `record_count` is attacker-controlled (read straight from the file
        // header). `* RECORD_SIZE` cannot overflow `usize` on the project's
        // 64-bit targets (max ≈ 30 GB), but `checked_mul` keeps it sound if a
        // 32-bit target ever appears: a corrupt count surfaces as the
        // InvalidData error below instead of a wrapped length.
        let expected_len = record_count
            .checked_mul(RECORD_SIZE)
            .and_then(|body| body.checked_add(HEADER_SIZE));
        if expected_len != Some(bin.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                match expected_len {
                    Some(exp) => {
                        format!("oui.bin size mismatch: {} bytes, expected {exp}", bin.len())
                    }
                    None => format!(
                        "oui.bin header record_count {record_count} is implausibly large \
                         (size overflow)"
                    ),
                },
            ));
        }

        Ok(OuiTable {
            bin,
            strings,
            record_count,
        })
    }

    /// Vendor name for a MAC's first three bytes. Returns `None` for
    /// unknown OUIs and malformed MACs. Locally-administered MACs
    /// (iOS / Android randomization) are NOT filtered here — the
    /// caller decides whether to call `is_randomized` first.
    pub fn lookup(&self, mac: &str) -> Option<&str> {
        let prefix = parse_prefix(mac)?;
        let offset = self.find_offset(&prefix)?;
        read_string(&self.strings, offset)
    }

    /// Whether the MAC's first byte has the locally-administered bit
    /// set (mask `0x02`). Modern device randomization sets this; no
    /// real OUI will ever match.
    pub fn is_randomized(mac: &str) -> bool {
        parse_prefix(mac).is_some_and(|p| (p[0] & 0x02) != 0)
    }

    fn find_offset(&self, prefix: &[u8; 3]) -> Option<u32> {
        let records = &self.bin[HEADER_SIZE..];
        let mut lo = 0usize;
        let mut hi = self.record_count;
        while lo < hi {
            let mid = (lo + hi) / 2;
            let r = &records[mid * RECORD_SIZE..(mid + 1) * RECORD_SIZE];
            let mid_prefix: &[u8; 3] = r[0..3].try_into().unwrap();
            match mid_prefix.cmp(prefix) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => {
                    return Some(u32::from_le_bytes(r[3..7].try_into().unwrap()));
                }
            }
        }
        None
    }
}

fn mmap_file(path: &Path) -> io::Result<Mmap> {
    let file = File::open(path)?;
    // SAFETY: we only read from the mapping. The asset files are
    // installed read-only by the deploy step and never written at
    // runtime. The `Mmap` keeps the underlying file open until
    // dropped. Note: if the mapped asset were ever TRUNCATED in place
    // (a careless re-deploy), reads past the new end SIGBUS — uncatchable.
    // Deploys must rename-replace the asset (atomic swap), never
    // truncate-and-rewrite; the install flow already does this.
    unsafe { Mmap::map(&file) }
}

fn parse_prefix(mac: &str) -> Option<[u8; 3]> {
    let mut bytes = [0u8; 3];
    let mut written = 0;
    let mut nibble: Option<u8> = None;
    for ch in mac.chars() {
        match ch {
            ':' | '-' | ' ' => continue,
            c => {
                let v = c.to_digit(16)? as u8;
                match nibble.take() {
                    None => nibble = Some(v),
                    Some(hi) => {
                        if written == 3 {
                            return Some(bytes);
                        }
                        bytes[written] = (hi << 4) | v;
                        written += 1;
                        if written == 3 {
                            return Some(bytes);
                        }
                    }
                }
            }
        }
    }
    if written == 3 {
        Some(bytes)
    } else {
        None
    }
}

fn read_string(blob: &[u8], offset: u32) -> Option<&str> {
    let off = offset as usize;
    if off >= blob.len() {
        return None;
    }
    let len = blob[off] as usize;
    let start = off + 1;
    let end = start.checked_add(len)?;
    if end > blob.len() {
        return None;
    }
    std::str::from_utf8(&blob[start..end]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Build a fixture pair of files inside a tempdir using the
    /// `oui-pack` layout, then open it and exercise lookups.
    fn write_fixture(records: &[([u8; 3], &str)]) -> (tempfile::TempDir, std::path::PathBuf) {
        // Sort defensively — the format requires sorted prefixes.
        let mut sorted: Vec<([u8; 3], &str)> = records.to_vec();
        sorted.sort_by_key(|(p, _)| *p);

        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();

        let mut strings: Vec<u8> = Vec::new();
        let mut offsets: Vec<u32> = Vec::with_capacity(sorted.len());
        for (_, name) in &sorted {
            let bytes = name.as_bytes();
            assert!(bytes.len() <= 255);
            offsets.push(strings.len() as u32);
            strings.push(bytes.len() as u8);
            strings.extend_from_slice(bytes);
        }
        std::fs::write(dir.join("oui.strings"), &strings).unwrap();

        let mut bin: Vec<u8> = Vec::with_capacity(HEADER_SIZE + sorted.len() * RECORD_SIZE);
        bin.extend_from_slice(MAGIC);
        bin.extend_from_slice(&(sorted.len() as u32).to_le_bytes());
        for ((prefix, _), off) in sorted.iter().zip(offsets.iter()) {
            bin.extend_from_slice(prefix);
            bin.extend_from_slice(&off.to_le_bytes());
        }
        std::fs::write(dir.join("oui.bin"), &bin).unwrap();

        (tmp, dir)
    }

    #[test]
    fn parse_prefix_accepts_colon_dash_and_no_separator() {
        assert_eq!(parse_prefix("AC:DE:48:00:11:22"), Some([0xAC, 0xDE, 0x48]));
        assert_eq!(parse_prefix("ac-de-48-00-11-22"), Some([0xAC, 0xDE, 0x48]));
        assert_eq!(parse_prefix("ACDE48001122"), Some([0xAC, 0xDE, 0x48]));
    }

    #[test]
    fn parse_prefix_rejects_truncated_or_invalid_input() {
        assert_eq!(parse_prefix("AC:DE"), None);
        assert_eq!(parse_prefix(""), None);
        assert_eq!(parse_prefix("ZZ:ZZ:ZZ"), None);
    }

    #[test]
    fn is_randomized_reads_locally_administered_bit() {
        assert!(OuiTable::is_randomized("02:00:00:00:00:00"));
        assert!(OuiTable::is_randomized("AA:BB:CC:DD:EE:FF")); // 0xAA bit1=1
        assert!(!OuiTable::is_randomized("AC:DE:48:00:11:22")); // 0xAC bit1=0
        assert!(!OuiTable::is_randomized("not a mac"));
    }

    #[test]
    fn lookup_returns_vendor_for_known_prefix() {
        let (_keep, dir) = write_fixture(&[
            ([0xAC, 0xDE, 0x48], "Apple, Inc."),
            ([0xB8, 0x27, 0xEB], "Raspberry Pi Foundation"),
            ([0x00, 0x50, 0x56], "VMware, Inc."),
        ]);
        let table = OuiTable::open(&dir).unwrap();
        assert_eq!(table.lookup("AC:DE:48:00:11:22"), Some("Apple, Inc."));
        assert_eq!(
            table.lookup("b8:27:eb:de:ad:be"),
            Some("Raspberry Pi Foundation"),
        );
        assert_eq!(table.lookup("00-50-56-00-00-01"), Some("VMware, Inc."));
    }

    #[test]
    fn lookup_returns_none_for_unknown_prefix() {
        let (_keep, dir) = write_fixture(&[([0xAC, 0xDE, 0x48], "Apple, Inc.")]);
        let table = OuiTable::open(&dir).unwrap();
        assert_eq!(table.lookup("FF:FF:FF:00:00:00"), None);
    }

    #[test]
    fn open_rejects_bad_magic() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        // Header with bad magic; strings file empty but present.
        let mut bin = Vec::new();
        bin.extend_from_slice(b"NOPE");
        bin.extend_from_slice(&0u32.to_le_bytes());
        std::fs::write(dir.join("oui.bin"), &bin).unwrap();
        std::fs::write(dir.join("oui.strings"), b"").unwrap();
        let err = OuiTable::open(dir).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn open_rejects_implausible_record_count_without_overflow() {
        // oui-01: a header claiming u32::MAX records makes
        // `record_count * RECORD_SIZE` huge — it must be rejected as
        // InvalidData, never panic or wrap (the `checked_mul` guard).
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let mut bin = Vec::new();
        bin.extend_from_slice(MAGIC);
        bin.extend_from_slice(&u32::MAX.to_le_bytes());
        std::fs::write(dir.join("oui.bin"), &bin).unwrap();
        std::fs::write(dir.join("oui.strings"), b"").unwrap();
        let err = OuiTable::open(dir).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn open_rejects_size_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        // Header claims 5 records but file is only the header.
        let mut bin = Vec::new();
        bin.extend_from_slice(MAGIC);
        bin.extend_from_slice(&5u32.to_le_bytes());
        std::fs::write(dir.join("oui.bin"), &bin).unwrap();
        std::fs::write(dir.join("oui.strings"), b"").unwrap();
        let err = OuiTable::open(dir).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn open_returns_not_found_when_files_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let err = OuiTable::open(tmp.path()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    /// Side-effect test used to keep `Write` imported when the doctest
    /// path is otherwise unused — silences the unused-import warning
    /// without `#[allow]` on the import itself.
    #[test]
    fn _io_write_is_in_scope() {
        let mut v: Vec<u8> = Vec::new();
        v.write_all(b"x").unwrap();
        assert_eq!(v, b"x");
    }
}
