//! Reading and writing pack files.
//!
//! The only module in this feature that touches the filesystem.

use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use compact_str::CompactString;

use crate::config::atomic_write::{hardened_atomic_write, AtomicWriteOpts};

use super::grammar::{compose_line, normalise_domain, parse_pack_line, GrammarError, PackLine};

/// One pack file, parsed.
///
/// `skipped` is part of the value, not only a log line: a rule that fails to
/// parse stops filtering silently, and a list that has lost fifty of them
/// must not look identical to an intact one on every surface.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompiledCustomList {
    pub allow: Vec<CompactString>,
    pub deny: Vec<CompactString>,
    pub skipped: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum PackReadError {
    #[error("custom list file {path} does not exist")]
    Missing { path: PathBuf },
    #[error("custom list file {path} cannot be read (permission denied)")]
    Permission { path: PathBuf },
    #[error("custom list file {path} is {size} bytes, over the {cap}-byte limit")]
    TooLarge { path: PathBuf, size: u64, cap: u64 },
    #[error("custom list file {path} is not valid UTF-8")]
    NotUtf8 { path: PathBuf },
    #[error("custom list file {path} is a symlink; refusing to follow it")]
    Symlink { path: PathBuf },
    #[error("custom list file {path} could not be read: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl PackReadError {
    /// The operator-facing remedy. A daemon that refuses to start has to say
    /// what to run, not only what it found.
    pub fn remedy(&self) -> &'static str {
        match self {
            Self::Missing { .. } => {
                "restore the file, or drop the [[custom_lists]] entry that names it"
            }
            Self::Permission { .. } => {
                "make the file readable by the warden user, or drop the entry that names it"
            }
            Self::TooLarge { .. } => "split the file, or raise [custom_list_limits] max_file_bytes",
            Self::Symlink { .. } => {
                "replace the symlink with a plain file, or drop the entry that names it"
            }
            Self::NotUtf8 { .. } | Self::Io { .. } => {
                "repair the file, or drop the [[custom_lists]] entry that names it"
            }
        }
    }
}

/// Read and parse one pack file.
///
/// An unreadable **file** is an error; an unparseable **line** is skipped and
/// counted. Treating an unreadable file as empty would drop its allow rules
/// and its deny rules together — the allows fail loudly, the denies fail
/// silently, and a daemon serving a silently degraded policy is worse than
/// one that refuses to start. Discarding two hundred good lines because one
/// has a typo is the same fail-open with the sign reversed.
pub fn read_pack(path: &Path, max_bytes: u64) -> Result<CompiledCustomList, PackReadError> {
    let text = read_text(path, max_bytes)?;

    let mut out = CompiledCustomList::default();
    for (n, line) in text.lines().enumerate() {
        match parse_pack_line(line) {
            Ok(PackLine::Blank) => {}
            Ok(PackLine::Allow(d)) => out.allow.push(d),
            Ok(PackLine::Deny(d)) => out.deny.push(d),
            Err(e) => {
                out.skipped += 1;
                tracing::warn!(
                    file = %path.display(),
                    line = n + 1,
                    error = %e,
                    "custom list rule skipped — it enforces nothing"
                );
            }
        }
    }
    Ok(out)
}

/// One line of the pack, as it sits on the file.
///
/// `read_pack` returns compiled rules and discards comments, order and raw
/// text. This view is for surfaces that must show the file to the operator
/// as it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackLineView {
    /// 1-based — the number a skipped-line WARN cites.
    pub number: usize,
    /// The exact line, untrimmed.
    pub raw: String,
    /// `Ok(PackLine::Blank)` for blank lines and comments.
    pub parsed: Result<PackLine, GrammarError>,
}

/// Read the pack, keeping order, comments and unparsed lines.
///
/// Same file errors as `read_pack` (missing, permission, too large,
/// not-UTF-8, symlink): an unparseable line is not a file error, an
/// unreadable file is.
pub fn read_pack_lines(path: &Path, max_bytes: u64) -> Result<Vec<PackLineView>, PackReadError> {
    let text = read_text(path, max_bytes)?;
    Ok(text
        .lines()
        .enumerate()
        .map(|(n, line)| PackLineView {
            number: n + 1,
            raw: line.to_string(),
            parsed: parse_pack_line(line),
        })
        .collect())
}

/// Opened once with `O_NOFOLLOW`, then fstat-ed and read on that same
/// descriptor.
///
/// The path is derived from the list id, but the INODE at that path is not:
/// a symlink planted there would otherwise be read from wherever it points
/// and rendered to the operator as their own file. The write side already
/// takes this posture. Working from a single descriptor also closes the
/// window between the size check and the read.
fn read_text(path: &Path, max_bytes: u64) -> Result<String, PackReadError> {
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return Err(PackReadError::Symlink {
                path: path.to_path_buf(),
            })
        }
        Err(e) => return Err(classify(path, e)),
    };
    let meta = file.metadata().map_err(|e| classify(path, e))?;
    if !meta.is_file() {
        return Err(PackReadError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a regular file"),
        });
    }
    if meta.len() > max_bytes {
        return Err(PackReadError::TooLarge {
            path: path.to_path_buf(),
            size: meta.len(),
            cap: max_bytes,
        });
    }
    // Bounded one byte past the cap. The fstat above measured a size that can
    // still change, so the read itself is what must not exceed the ceiling.
    let mut bytes = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| classify(path, e))?;
    if bytes.len() as u64 > max_bytes {
        return Err(PackReadError::TooLarge {
            path: path.to_path_buf(),
            size: bytes.len() as u64,
            cap: max_bytes,
        });
    }
    String::from_utf8(bytes).map_err(|_| PackReadError::NotUtf8 {
        path: path.to_path_buf(),
    })
}

fn classify(path: &Path, e: std::io::Error) -> PackReadError {
    match e.kind() {
        std::io::ErrorKind::NotFound => PackReadError::Missing {
            path: path.to_path_buf(),
        },
        std::io::ErrorKind::PermissionDenied => PackReadError::Permission {
            path: path.to_path_buf(),
        },
        _ => PackReadError::Io {
            path: path.to_path_buf(),
            source: e,
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddOutcome {
    Added,
    AlreadyPresent,
}

#[derive(Debug, thiserror::Error)]
pub enum PackWriteError {
    #[error("line {line}: {source}")]
    InvalidLine {
        line: usize,
        #[source]
        source: GrammarError,
    },
    #[error("{0}")]
    Grammar(#[from] GrammarError),
    #[error("reading {0} before the write failed: {1}")]
    Read(PathBuf, #[source] PackReadError),
    #[error("writing {0} failed: {1}")]
    Write(
        PathBuf,
        #[source] crate::config::atomic_write::AtomicWriteError,
    ),
    #[error(
        "writing {path} would leave it {size} bytes, over the {cap}-byte \
         [custom_list_limits] max_file_bytes limit"
    )]
    TooLarge { path: PathBuf, size: u64, cap: u64 },
}

/// Replace a pack file's whole content, atomically, after validating every
/// line.
///
/// The first invalid line rejects the entire write. This is not the list
/// parser's skip-and-count: that discipline is a supply-chain signal for a
/// body nobody in this house wrote, and this is the operator's own file.
pub fn write_pack(path: &Path, lines: &[String], max_bytes: u64) -> Result<(), PackWriteError> {
    for (n, l) in lines.iter().enumerate() {
        if let Err(e) = parse_pack_line(l) {
            return Err(PackWriteError::InvalidLine {
                line: n + 1,
                source: e,
            });
        }
    }
    write_all_raw(path, lines, max_bytes)
}

/// Create the file for a new custom list.
///
/// Written immediately, so a mounted list always has a file and "missing"
/// is unambiguously a fault rather than possibly just an empty list.
pub fn create_pack(path: &Path, display_name: &str) -> Result<(), PackWriteError> {
    let header = if display_name.is_empty() {
        "# purge-warden custom list\n".to_string()
    } else {
        // The name goes in a comment, so a newline in it would produce a
        // line the operator never approved.
        let safe = display_name.replace(['\n', '\r'], " ");
        format!("# purge-warden custom list: {safe}\n")
    };
    hardened_atomic_write(path, header.as_bytes(), AtomicWriteOpts::default())
        .map_err(|e| PackWriteError::Write(path.to_path_buf(), e))
}

/// Append one rule, unless an identical one is already there.
///
/// Idempotent and order-preserving: the operator diffs these files, and a
/// verb that reshuffles them makes the diff useless.
pub fn add_rule(
    path: &Path,
    domain: &str,
    allow: bool,
    max_bytes: u64,
) -> Result<AddOutcome, PackWriteError> {
    let line = compose_line(domain, allow)?;
    let target = normalise_domain(domain)?;
    let text = read_raw(path, max_bytes)?;
    // Compared as parsed rules rather than as text: `normalise_domain`
    // lowercases, so a file already carrying `||EXAMPLE.COM^` carries THIS
    // rule, and a text compare appended a duplicate the operator never typed.
    // Direction is part of the match — an allow for a domain must not suppress
    // adding its deny. `remove_rule` compares the same way; the asymmetry
    // between the two is what made this visible.
    let already = text.lines().any(|l| match parse_pack_line(l) {
        Ok(PackLine::Allow(d)) => allow && d == target,
        Ok(PackLine::Deny(d)) => !allow && d == target,
        _ => false,
    });
    if already {
        return Ok(AddOutcome::AlreadyPresent);
    }
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    lines.push(line);
    write_all_raw(path, &lines, max_bytes).map(|()| AddOutcome::Added)
}

/// Drop every rule naming `domain`, in either direction.
///
/// Returns whether anything was removed, so the caller can say "not there"
/// instead of reporting a no-op as a success.
pub fn remove_rule(path: &Path, domain: &str, max_bytes: u64) -> Result<bool, PackWriteError> {
    let target = normalise_domain(domain)?;
    let text = read_raw(path, max_bytes)?;
    let kept: Vec<String> = text
        .lines()
        .filter(|l| match parse_pack_line(l) {
            Ok(PackLine::Allow(d)) | Ok(PackLine::Deny(d)) => d != target,
            _ => true, // blanks, comments and unparseable lines survive
        })
        .map(str::to_string)
        .collect();
    let removed = kept.len() != text.lines().count();
    if removed {
        write_all_raw(path, &kept, max_bytes)?;
    }
    Ok(removed)
}

/// The read half of a read-modify-write, through the reader's own open.
///
/// Shares `read_text` rather than reopening by path, so a rule append cannot
/// be talked into copying a symlink target's body into the operator's pack —
/// and so the two paths cannot drift into disagreeing about what this file
/// is.
fn read_raw(path: &Path, max_bytes: u64) -> Result<String, PackWriteError> {
    read_text(path, max_bytes).map_err(|e| PackWriteError::Read(path.to_path_buf(), e))
}

/// Write the file without re-judging lines this call did not author.
///
/// The reader survives an unparseable line — skipped, counted, file loads —
/// so a writer that refused the whole file over one would make a single
/// hand-typed typo freeze the list against every verb. A caller that means
/// to judge every line calls `write_pack`, which validates first and then
/// delegates here.
///
/// `max_bytes` is the ceiling the reader enforces, applied here so a write can
/// never produce a file `read_pack` refuses. `build_store` is all-or-nothing,
/// so such a file fails the WHOLE config on the next load — and every surface
/// that could repair it loads the config first, leaving the operator no route
/// back in through warden at all. Checked in this function rather than at each
/// caller because all three writers route through it.
fn write_all_raw(path: &Path, lines: &[String], max_bytes: u64) -> Result<(), PackWriteError> {
    let mut body = lines.join("\n");
    if !body.is_empty() {
        body.push('\n');
    }
    if body.len() as u64 > max_bytes {
        return Err(PackWriteError::TooLarge {
            path: path.to_path_buf(),
            size: body.len() as u64,
            cap: max_bytes,
        });
    }
    hardened_atomic_write(path, body.as_bytes(), AtomicWriteOpts::default())
        .map_err(|e| PackWriteError::Write(path.to_path_buf(), e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn a_readable_file_compiles_into_two_sets() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(
            dir.path(),
            "a.txt",
            "# header\n@@||cdn.example.com^\n@@||assets.example.com^\n||ads.example.com^\n\n",
        );
        let c = read_pack(&p, 1024 * 1024).unwrap();
        assert_eq!(c.allow.len(), 2);
        assert_eq!(c.deny.len(), 1);
        assert_eq!(c.skipped, 0);
        assert!(c.allow.iter().any(|d| d == "cdn.example.com"));
        assert!(c.deny.iter().any(|d| d == "ads.example.com"));
    }

    #[test]
    fn a_readable_file_with_zero_rules_is_legal() {
        // The negative control for the failure tests below: without it, a
        // reader that refused every empty list would still pass them.
        let dir = tempfile::tempdir().unwrap();
        let p = write(dir.path(), "a.txt", "# just a header\n\n");
        let c = read_pack(&p, 1024 * 1024).unwrap();
        assert!(c.allow.is_empty() && c.deny.is_empty());
        assert_eq!(c.skipped, 0);
    }

    #[test]
    fn broken_lines_are_skipped_and_counted() {
        // Two good, three broken. The count is state, not a log line: a
        // list with 50 skipped rules out of 200 must not be indistinguishable
        // from an intact one.
        let dir = tempfile::tempdir().unwrap();
        let p = write(
            dir.path(),
            "a.txt",
            "||ads.example.com^\n||*.example.com^\nnonsense\n@@||cdn.example.com^\n||bad_domain.example^\n",
        );
        let c = read_pack(&p, 1024 * 1024).unwrap();
        assert_eq!(c.allow.len(), 1);
        assert_eq!(c.deny.len(), 1);
        assert_eq!(c.skipped, 3, "skipped count must be state on the result");
    }

    #[test]
    fn a_missing_file_is_an_error_not_an_empty_list() {
        let dir = tempfile::tempdir().unwrap();
        let err = read_pack(&dir.path().join("nope.txt"), 1024 * 1024).unwrap_err();
        assert!(matches!(err, PackReadError::Missing { .. }));
        assert!(
            err.to_string().contains("nope.txt"),
            "the error must name the path: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_file_is_an_error_not_an_empty_list() {
        // EACCES is not hypothetical here: the pack dir is 0750 and files
        // are 0640. `Path::exists()` returning false on EACCES has already
        // produced a "file is missing" diagnosis on a present file in this
        // repo, so the reader must distinguish the two.
        use std::os::unix::fs::PermissionsExt;
        if nix_running_as_root() {
            return; // root ignores the mode bits; the assertion would be vacuous
        }
        let dir = tempfile::tempdir().unwrap();
        let p = write(dir.path(), "a.txt", "||ads.example.com^\n");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();
        let err = read_pack(&p, 1024 * 1024).unwrap_err();
        assert!(
            matches!(err, PackReadError::Permission { .. }),
            "expected a permission error, got {err:?}"
        );
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
    }

    #[cfg(unix)]
    fn nix_running_as_root() -> bool {
        // SAFETY: getuid is always safe and never fails.
        unsafe { libc::getuid() == 0 }
    }

    #[test]
    fn a_file_over_the_cap_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let body = "||ads.example.com^\n".repeat(100);
        let p = write(dir.path(), "a.txt", &body);
        let err = read_pack(&p, 64).unwrap_err();
        assert!(matches!(err, PackReadError::TooLarge { .. }));
    }

    /// Path derivation constrains the path, not the inode at it. Both
    /// readers go through the same open, so both refuse.
    #[test]
    fn a_symlinked_pack_is_refused_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let real = write(dir.path(), "elsewhere.txt", "||ads.example.com^\n");
        let link = dir.path().join("a.txt");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let err = read_pack(&link, 1024 * 1024).expect_err("a symlink must not be read through");
        assert!(
            matches!(err, PackReadError::Symlink { .. }),
            "expected a symlink refusal, got {err:?}"
        );
        assert!(
            err.to_string().contains("a.txt"),
            "must name the path: {err}"
        );
        assert!(
            err.remedy().contains("symlink"),
            "the remedy must say what to do: {}",
            err.remedy()
        );
        assert!(matches!(
            read_pack_lines(&link, 1024 * 1024).unwrap_err(),
            PackReadError::Symlink { .. }
        ));
    }

    /// The write path reads through the same open, so an append cannot be
    /// talked into copying a symlink target's body into the operator's pack.
    #[test]
    fn a_symlinked_pack_is_refused_by_the_write_path_too() {
        let dir = tempfile::tempdir().unwrap();
        let real = write(dir.path(), "elsewhere.txt", "||smuggled.example.com^\n");
        let link = dir.path().join("a.txt");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let err = add_rule(&link, "new.example.com", false, 1024 * 1024)
            .expect_err("an append through a symlink must be refused");
        assert!(
            matches!(err, PackWriteError::Read(_, PackReadError::Symlink { .. })),
            "expected a symlink refusal, got {err:?}"
        );
        assert!(
            remove_rule(&link, "smuggled.example.com", 1024 * 1024).is_err(),
            "the remove path must refuse it too"
        );
        assert_eq!(
            std::fs::read_to_string(&real).unwrap(),
            "||smuggled.example.com^\n",
            "the symlink target must be untouched"
        );
    }

    /// The negative control: a plain file at the same path still reads.
    /// Without it a reader that refused everything would pass the test above.
    #[test]
    fn a_plain_file_where_a_symlink_would_have_been_still_reads() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(dir.path(), "a.txt", "||ads.example.com^\n");
        assert_eq!(read_pack(&p, 1024 * 1024).unwrap().deny.len(), 1);
    }

    #[test]
    fn a_directory_at_the_pack_path_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.txt");
        std::fs::create_dir(&p).unwrap();
        assert!(read_pack(&p, 1024 * 1024).is_err());
    }

    #[test]
    fn create_writes_a_readable_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("packs").join("a.txt");
        create_pack(&p, "Minecraft").unwrap();
        let c = read_pack(&p, 1024 * 1024).unwrap();
        assert!(c.allow.is_empty() && c.deny.is_empty() && c.skipped == 0);
    }

    #[cfg(unix)]
    #[test]
    fn create_leaves_the_dir_at_0750_and_the_file_at_0640() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("packs").join("a.txt");
        create_pack(&p, "A").unwrap();
        let dmode = std::fs::metadata(p.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let fmode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(dmode, 0o750, "pack dir mode");
        assert_eq!(fmode, 0o640, "pack file mode");
    }

    #[test]
    fn adding_the_same_rule_twice_is_byte_identical() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("packs").join("a.txt");
        create_pack(&p, "A").unwrap();
        assert_eq!(
            add_rule(&p, "ads.example.com", false, 1024 * 1024).unwrap(),
            AddOutcome::Added
        );
        let once = std::fs::read(&p).unwrap();
        assert_eq!(
            add_rule(&p, "ads.example.com", false, 1024 * 1024).unwrap(),
            AddOutcome::AlreadyPresent
        );
        assert_eq!(
            std::fs::read(&p).unwrap(),
            once,
            "second add must not change the file"
        );
    }

    /// The same rule spelled in another case is the same rule: the grammar
    /// lowercases at ingestion, so both compile to one domain. The byte
    /// comparison is the assertion that matters — an implementation that
    /// appended and then reported `AlreadyPresent` would pass on the outcome
    /// alone.
    #[test]
    fn a_rule_already_present_in_another_case_is_not_appended_again() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(dir.path(), "a.txt", "||EXAMPLE.COM^\n");
        let before = std::fs::read(&p).unwrap();
        assert_eq!(
            add_rule(&p, "example.com", false, 1024 * 1024).unwrap(),
            AddOutcome::AlreadyPresent
        );
        assert_eq!(
            std::fs::read(&p).unwrap(),
            before,
            "the file must be untouched"
        );
        assert_eq!(read_pack(&p, 1024 * 1024).unwrap().deny.len(), 1);
    }

    /// Whitespace and case are both noise to the grammar, and the check has
    /// to agree with it in both.
    #[test]
    fn an_indented_rule_already_present_is_not_appended_again() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(dir.path(), "a.txt", "   @@||CDN.Example.Com^\t\n");
        let before = std::fs::read(&p).unwrap();
        assert_eq!(
            add_rule(&p, "cdn.example.com", true, 1024 * 1024).unwrap(),
            AddOutcome::AlreadyPresent
        );
        assert_eq!(std::fs::read(&p).unwrap(), before);
    }

    /// Direction is half the rule. An existing allow must not swallow the
    /// deny for the same domain — that would be a filter the operator asked
    /// for and never got.
    #[test]
    fn an_allow_for_a_domain_does_not_suppress_adding_its_deny() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(dir.path(), "a.txt", "@@||example.com^\n");
        assert_eq!(
            add_rule(&p, "example.com", false, 1024 * 1024).unwrap(),
            AddOutcome::Added
        );
        let c = read_pack(&p, 1024 * 1024).unwrap();
        assert_eq!(c.allow.len(), 1);
        assert_eq!(c.deny.len(), 1);
    }

    /// A comment that quotes a rule is not that rule. The parse of a comment
    /// line is `Blank`, so it can never satisfy the check.
    #[test]
    fn a_commented_out_rule_does_not_count_as_present() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(dir.path(), "a.txt", "# ||ads.example.com^ under review\n");
        assert_eq!(
            add_rule(&p, "ads.example.com", false, 1024 * 1024).unwrap(),
            AddOutcome::Added
        );
        assert_eq!(read_pack(&p, 1024 * 1024).unwrap().deny.len(), 1);
    }

    #[test]
    fn adding_preserves_the_existing_order() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("packs").join("a.txt");
        create_pack(&p, "A").unwrap();
        for d in ["c.example.com", "a.example.com", "b.example.com"] {
            add_rule(&p, d, false, 1024 * 1024).unwrap();
        }
        let text = std::fs::read_to_string(&p).unwrap();
        let ci = text.find("c.example.com").unwrap();
        let ai = text.find("a.example.com").unwrap();
        let bi = text.find("b.example.com").unwrap();
        assert!(ci < ai && ai < bi, "the file must not be reordered: {text}");
    }

    #[test]
    fn a_hostile_domain_is_refused_and_the_file_is_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("packs").join("a.txt");
        create_pack(&p, "A").unwrap();
        add_rule(&p, "ads.example.com", false, 1024 * 1024).unwrap();
        let before = std::fs::read(&p).unwrap();
        assert!(add_rule(
            &p,
            "evil.example.com\n@@||x.example.com",
            false,
            1024 * 1024
        )
        .is_err());
        assert!(add_rule(&p, "evil.example.com^", true, 1024 * 1024).is_err());
        assert_eq!(
            std::fs::read(&p).unwrap(),
            before,
            "the file must be untouched"
        );
    }

    #[test]
    fn a_full_replacement_rejects_the_whole_write_on_one_invalid_line() {
        // Not skip-and-count. That discipline is for untrusted remote
        // bodies; this is the operator's own file, and lines supplied
        // wholesale are the caller's to get right.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("packs").join("a.txt");
        create_pack(&p, "A").unwrap();
        let before = std::fs::read(&p).unwrap();
        let err = write_pack(
            &p,
            &[
                "||good.example.com^".to_string(),
                "||*.example.com^".to_string(),
                "||also-good.example.com^".to_string(),
            ],
            1024 * 1024,
        )
        .expect_err("an invalid line must reject the whole write");
        assert!(
            err.to_string().contains("2"),
            "the error must name the line: {err}"
        );
        assert_eq!(std::fs::read(&p).unwrap(), before, "nothing may be written");
    }

    #[test]
    fn a_pre_existing_bad_line_does_not_freeze_the_file() {
        // The reader survives a bad line (skipped and counted); the writer
        // must too, or one hand-typed typo makes the file permanently
        // un-editable through the verbs — the "became uneditable from
        // there" class. A write judges only the line it authors.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("packs").join("a.txt");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, "# header\n||*.example.com^\n||good.example.com^\n").unwrap();

        assert_eq!(
            add_rule(&p, "new.example.com", false, 1024 * 1024).unwrap(),
            AddOutcome::Added,
            "a pre-existing bad line must not block an add"
        );
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(
            text.contains("||*.example.com^"),
            "the untouched bad line must survive byte-identically: {text}"
        );
        assert!(text.contains("||new.example.com^"));

        // And it is still reported as degraded, not silently repaired.
        let c = read_pack(&p, 1024 * 1024).unwrap();
        assert_eq!(c.skipped, 1, "the bad line must still count as skipped");
        assert_eq!(c.deny.len(), 2);
    }

    #[test]
    fn a_pre_existing_bad_line_does_not_block_a_remove() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("packs").join("a.txt");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, "||*.example.com^\n||good.example.com^\n").unwrap();
        assert!(remove_rule(&p, "good.example.com", 1024 * 1024).unwrap());
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(
            text.contains("||*.example.com^"),
            "bad line must survive: {text}"
        );
        assert!(!text.contains("good.example.com"));
    }

    #[test]
    fn remove_reports_whether_it_removed_anything() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("packs").join("a.txt");
        create_pack(&p, "A").unwrap();
        add_rule(&p, "ads.example.com", false, 1024 * 1024).unwrap();
        assert!(remove_rule(&p, "ads.example.com", 1024 * 1024).unwrap());
        assert!(!remove_rule(&p, "ads.example.com", 1024 * 1024).unwrap());
        let c = read_pack(&p, 1024 * 1024).unwrap();
        assert!(c.deny.is_empty());
    }

    #[test]
    fn read_pack_lines_gives_one_contiguous_1_based_view_per_line() {
        let dir = tempfile::tempdir().unwrap();
        let body = "# header\n||ads.example.com^\n\n@@||cdn.example.com^\nnonsense\n";
        let p = write(dir.path(), "a.txt", body);
        let views = read_pack_lines(&p, 1024 * 1024).unwrap();
        let want_len = body.lines().count();
        assert_eq!(views.len(), want_len, "one view per line of the file");
        let numbers: Vec<usize> = views.iter().map(|v| v.number).collect();
        assert_eq!(numbers, (1..=want_len).collect::<Vec<_>>());
    }

    #[test]
    fn blank_lines_and_comments_parse_as_blank_with_raw_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let body = "  # indented comment  \n\n\t\n";
        let p = write(dir.path(), "a.txt", body);
        let views = read_pack_lines(&p, 1024 * 1024).unwrap();
        let raw: Vec<&str> = body.lines().collect();
        assert_eq!(views.len(), raw.len());
        for (v, r) in views.iter().zip(raw.iter()) {
            assert_eq!(v.parsed, Ok(PackLine::Blank));
            assert_eq!(&v.raw, r, "raw must be untrimmed");
        }
    }

    #[test]
    fn an_invalid_line_is_err_with_raw_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let body = "  nonsense line  \n";
        let p = write(dir.path(), "a.txt", body);
        let views = read_pack_lines(&p, 1024 * 1024).unwrap();
        assert_eq!(views.len(), 1);
        assert!(matches!(&views[0].parsed, Err(GrammarError::NotARule)));
        assert_eq!(views[0].raw, "  nonsense line  ");
    }

    #[test]
    fn read_pack_lines_preserves_file_order_not_allow_then_deny() {
        let dir = tempfile::tempdir().unwrap();
        let body =
            "||deny-first.example.com^\n@@||allow-second.example.com^\n||deny-third.example.com^\n";
        let p = write(dir.path(), "a.txt", body);
        let views = read_pack_lines(&p, 1024 * 1024).unwrap();
        let parsed: Vec<PackLine> = views.into_iter().map(|v| v.parsed.unwrap()).collect();
        assert_eq!(
            parsed,
            vec![
                PackLine::Deny("deny-first.example.com".into()),
                PackLine::Allow("allow-second.example.com".into()),
                PackLine::Deny("deny-third.example.com".into()),
            ]
        );
    }

    #[test]
    fn read_pack_lines_matches_read_pack_on_the_same_file() {
        // The property that matters most: if the two readers ever disagree
        // on what a line means, this is what catches it. Counts alone do
        // not — an allow/deny swap would keep totals equal — so this
        // compares the actual domains, in file order. The fixture is
        // deliberately asymmetric (2 allow, 3 deny) so a swap cannot pass
        // by coincidence, and includes a commented-out rule to prove it
        // reads as Blank on both sides, not as a rule.
        let dir = tempfile::tempdir().unwrap();
        let body = concat!(
            "# section: vendor A\n",
            "@@||cdn-a.example.com^\n",
            "||ads-a.example.com^\n",
            "\n",
            "# section: vendor B — @@||b.example.org^ still under review\n",
            "@@||cdn-b.example.com^\n",
            "||ads-b.example.com^\n",
            "||ads-c.example.com^\n",
            "nonsense\n",
        );
        let p = write(dir.path(), "a.txt", body);

        let compiled = read_pack(&p, 1024 * 1024).unwrap();
        let views = read_pack_lines(&p, 1024 * 1024).unwrap();

        let allow: Vec<CompactString> = views
            .iter()
            .filter_map(|v| match &v.parsed {
                Ok(PackLine::Allow(d)) => Some(d.clone()),
                _ => None,
            })
            .collect();
        let deny: Vec<CompactString> = views
            .iter()
            .filter_map(|v| match &v.parsed {
                Ok(PackLine::Deny(d)) => Some(d.clone()),
                _ => None,
            })
            .collect();
        let skipped = views.iter().filter(|v| v.parsed.is_err()).count();

        assert_eq!(allow, compiled.allow, "allow domains must match, in order");
        assert_eq!(deny, compiled.deny, "deny domains must match, in order");
        assert_eq!(skipped, compiled.skipped);
        assert_eq!(allow.len(), 2);
        assert_eq!(deny.len(), 3);
        assert_eq!(skipped, 1);
    }

    #[test]
    fn read_pack_lines_reports_a_missing_file_like_read_pack() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("nope.txt");
        assert!(matches!(
            read_pack_lines(&p, 1024 * 1024).unwrap_err(),
            PackReadError::Missing { .. }
        ));
    }

    /// A pack at the operator's ceiling must not be pushed over it by an
    /// append. The assertion is on the READER: a writer that refused with
    /// its own, drifted, ceiling would still pass an assertion on the error.
    #[test]
    fn an_append_that_would_breach_the_cap_leaves_a_file_the_reader_still_loads() {
        let dir = tempfile::tempdir().unwrap();
        let mut body = String::new();
        for i in 0..10 {
            body.push_str(&format!("||d{i}.example.com^\n"));
        }
        // Room for part of a line, never a whole one.
        let cap = body.len() as u64 + 5;
        let p = write(dir.path(), "a.txt", &body);
        assert!(
            read_pack(&p, cap).is_ok(),
            "the fixture must start inside the cap"
        );
        let before = std::fs::read(&p).unwrap();

        let err = add_rule(&p, "new.example.com", false, cap)
            .expect_err("an append over the cap must be refused");
        assert!(
            matches!(err, PackWriteError::TooLarge { .. }),
            "expected a cap refusal, got {err:?}"
        );
        assert!(
            err.to_string().contains("max_file_bytes"),
            "the refusal must name the config key: {err}"
        );

        assert_eq!(std::fs::read(&p).unwrap(), before, "nothing may be written");
        read_pack(&p, cap).expect("the file on disk must still load at the same cap");
    }

    /// The negative control for the test above: a writer that refused every
    /// append would pass it.
    #[test]
    fn an_append_inside_the_cap_still_lands() {
        let dir = tempfile::tempdir().unwrap();
        let body = "||d0.example.com^\n";
        let p = write(dir.path(), "a.txt", body);
        assert_eq!(
            add_rule(&p, "new.example.com", false, 1024 * 1024).unwrap(),
            AddOutcome::Added
        );
        assert_eq!(read_pack(&p, 1024 * 1024).unwrap().deny.len(), 2);
    }

    /// `write_pack` inherits the ceiling from the same choke point, so a
    /// wholesale replacement cannot brick the config either.
    #[test]
    fn a_full_replacement_over_the_cap_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("packs").join("a.txt");
        create_pack(&p, "A").unwrap();
        let before = std::fs::read(&p).unwrap();
        let lines: Vec<String> = (0..10).map(|i| format!("||d{i}.example.com^")).collect();
        let err =
            write_pack(&p, &lines, 32).expect_err("a replacement over the cap must be refused");
        assert!(matches!(err, PackWriteError::TooLarge { .. }));
        assert_eq!(std::fs::read(&p).unwrap(), before, "nothing may be written");
    }

    /// A shrinking write is judged by the same ceiling, which can only ever
    /// refuse a file `read_raw` has already refused — so a pack that somehow
    /// went over the cap can still be emptied back under it.
    #[test]
    fn a_removal_that_shrinks_the_file_is_not_blocked_by_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let mut body = String::new();
        for i in 0..10 {
            body.push_str(&format!("||d{i}.example.com^\n"));
        }
        let cap = body.len() as u64;
        let p = write(dir.path(), "a.txt", &body);
        assert!(remove_rule(&p, "d3.example.com", cap).unwrap());
        read_pack(&p, cap).expect("the shrunk file must still load");
    }

    #[test]
    fn read_pack_lines_reports_a_too_large_file_like_read_pack() {
        let dir = tempfile::tempdir().unwrap();
        let body = "||ads.example.com^\n".repeat(100);
        let p = write(dir.path(), "a.txt", &body);
        assert!(matches!(
            read_pack_lines(&p, 64).unwrap_err(),
            PackReadError::TooLarge { .. }
        ));
    }
}
