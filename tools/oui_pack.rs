//! `oui-pack` — convert the IEEE OUI registry CSV into the binary
//! layout consumed by `src/oui/`.
//!
//! Run once at release packaging:
//!
//! ```text
//! cargo run --bin oui-pack -- /tmp/oui.csv assets/oui/
//! ```
//!
//! Produces `assets/oui/oui.bin` (sorted prefix index, magic `OUI1`,
//! 7-byte fixed-width records) and `assets/oui/oui.strings`
//! (length-prefixed UTF-8 names). Commit both files; the deploy step
//! ships them to `/var/lib/purge-warden/data/`.
//!
//! IEEE CSV columns: `Registry,Assignment,Organization Name,Organization Address`.
//! Only the second and third are read here; commas inside quoted
//! Organization Name fields are honored.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

const MAGIC: &[u8; 4] = b"OUI1";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: oui-pack <ieee-oui.csv> <output-dir>");
        return ExitCode::from(64);
    }
    let csv_path = PathBuf::from(&args[1]);
    let out_dir = PathBuf::from(&args[2]);

    let csv = match fs::read_to_string(&csv_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("read {}: {e}", csv_path.display());
            return ExitCode::from(66);
        }
    };

    let mut records = parse_csv(&csv);
    records.sort_by_key(|(p, _)| *p);
    records.dedup_by_key(|(p, _)| *p);

    if records.is_empty() {
        eprintln!("no records parsed from {}", csv_path.display());
        return ExitCode::from(65);
    }

    if let Err(e) = fs::create_dir_all(&out_dir) {
        eprintln!("mkdir -p {}: {e}", out_dir.display());
        return ExitCode::from(73);
    }

    let mut strings: Vec<u8> = Vec::with_capacity(records.len() * 32);
    let mut offsets: Vec<u32> = Vec::with_capacity(records.len());
    for (_, name) in &records {
        let bytes = clamp_name(name);
        offsets.push(strings.len() as u32);
        strings.push(bytes.len() as u8);
        strings.extend_from_slice(bytes);
    }

    let mut bin: Vec<u8> = Vec::with_capacity(8 + records.len() * 7);
    bin.extend_from_slice(MAGIC);
    bin.extend_from_slice(&(records.len() as u32).to_le_bytes());
    for ((prefix, _), off) in records.iter().zip(offsets.iter()) {
        bin.extend_from_slice(prefix);
        bin.extend_from_slice(&off.to_le_bytes());
    }

    let bin_path = out_dir.join("oui.bin");
    let strings_path = out_dir.join("oui.strings");
    if let Err(e) = fs::write(&bin_path, &bin) {
        eprintln!("write {}: {e}", bin_path.display());
        return ExitCode::from(73);
    }
    if let Err(e) = fs::write(&strings_path, &strings) {
        eprintln!("write {}: {e}", strings_path.display());
        return ExitCode::from(73);
    }

    println!(
        "wrote {} records ({} bytes index + {} bytes strings)",
        records.len(),
        bin.len(),
        strings.len(),
    );
    ExitCode::SUCCESS
}

/// Pull `(prefix, organization_name)` pairs out of an IEEE OUI CSV.
/// Skips the header row and any malformed records silently — the
/// IEEE registry is large and a single broken line shouldn't fail
/// the whole repackaging.
fn parse_csv(input: &str) -> Vec<([u8; 3], String)> {
    let mut out = Vec::with_capacity(40_000);
    for (idx, line) in input.lines().enumerate() {
        if idx == 0 && line.starts_with("Registry,") {
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        let fields = split_csv(line);
        if fields.len() < 3 {
            continue;
        }
        // Field layout: Registry,Assignment,Organization Name,Organization Address.
        // Filter out non-MA-L entries (MA-S, MA-M assignments are
        // smaller-than-/24 blocks; we don't honor those because our
        // index is keyed on the full 24-bit OUI).
        if fields[0] != "MA-L" {
            continue;
        }
        let Some(prefix) = parse_assignment(&fields[1]) else {
            continue;
        };
        let name = fields[2].trim();
        if name.is_empty() {
            continue;
        }
        out.push((prefix, name.to_string()));
    }
    out
}

/// Minimal CSV row splitter that honors double-quoted fields. Doubled
/// quotes inside a quoted field collapse to a single quote, matching
/// the IEEE export's escape style.
fn split_csv(line: &str) -> Vec<String> {
    let mut fields: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, in_quotes) {
            ('"', false) => in_quotes = true,
            ('"', true) => {
                if matches!(chars.peek(), Some('"')) {
                    chars.next();
                    current.push('"');
                } else {
                    in_quotes = false;
                }
            }
            (',', false) => {
                fields.push(std::mem::take(&mut current));
            }
            (other, _) => current.push(other),
        }
    }
    fields.push(current);
    fields
}

fn parse_assignment(s: &str) -> Option<[u8; 3]> {
    let trimmed = s.trim();
    if trimmed.len() < 6 {
        return None;
    }
    let mut bytes = [0u8; 3];
    for (i, byte) in bytes.iter_mut().enumerate() {
        let pair = trimmed.get(i * 2..i * 2 + 2)?;
        *byte = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(bytes)
}

/// Clamp organization names to 255 bytes so they fit a `u8` length
/// prefix. IEEE entries are typically <80 bytes; the few that exceed
/// 255 get truncated at a UTF-8 boundary so we never write split
/// codepoints.
fn clamp_name(name: &str) -> &[u8] {
    let bytes = name.as_bytes();
    if bytes.len() <= 255 {
        return bytes;
    }
    let mut end = 255;
    while end > 0 && (bytes[end] & 0b1100_0000) == 0b1000_0000 {
        end -= 1;
    }
    &bytes[..end]
}
