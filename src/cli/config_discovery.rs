//! Config file path discovery for the `warden` binary.
//!
//! When the user runs `warden` without `--config`, we search a fixed list of
//! standard locations and pick the first one whose file exists. This lets the
//! same binary work from the dev repo (`./config.toml`), a user install
//! (`~/.config/purge-warden/config.toml`), or the v1 FHS system install
//! (`/etc/purge-warden/config.toml`) without the operator having to pass
//! `--config` every time. The legacy pre-S34 location
//! (`/var/lib/purge-warden/config.toml`) is kept as a last-resort fallback
//! so boxes that still hold a monolithic config from before the FHS split
//! keep working.
//!
//! If none of the candidates exist, we fall back to `./config.toml` and return
//! a warning the caller can surface to the user (TUI footer, stderr, …) so the
//! silent-fallback footgun doesn't strike again.
//!
//! **A candidate can fail in two different ways, and they get two different
//! warnings** ([`CandidateProbe`]). "Absent" is what `warden init` is for;
//! "present but unreadable" is a permissions problem on a host that already
//! has a working install, and recommending `init` there would put a second
//! config beside a live one. The probe opens each candidate rather than
//! stat-ing it, so the two never collapse into one answer.
//!
//! **Security — privileged discovery (rev-2606 `config_discovery-01`).** A
//! *root* invocation without `--config` must never auto-load a config from a
//! path a non-root user can write. The CWD (`./config.toml`) is frequently a
//! shared/scratch dir under `sudo`, and `$HOME` may still belong to the
//! non-root caller — a planted file there could repoint `upstream.servers` at
//! an attacker resolver, widen `server.allow_from`, or aim list fetches at
//! attacker URLs. So when `geteuid()==0` we search ONLY the root-owned system
//! roots (`/etc/`, `/var/lib/`) and skip both the CWD and the per-user path; a
//! present `./config.toml` is ignored with a loud notice. Non-root keeps the
//! full dev search order unchanged, and an explicit `--config` always wins.
//!
//! [`resolve_pid_file`] mirrors the same "system vs dev" decision for the
//! daemon PID file so `warden status` / `stop` / `cache` find the daemon
//! without a flag once `--config` has been resolved.

use std::path::{Path, PathBuf};

/// Outcome of probing one candidate config path.
///
/// **Why three variants and not a `bool`.** Discovery used to probe with
/// `Path::exists()`, which is `metadata().is_ok()` — it collapses `ENOENT`
/// and `EACCES` into a single `false`. On a systemd install
/// `/var/lib/purge-warden/` is `0750` owned by the daemon user, so the
/// master config that *does* exist there is indistinguishable from absent
/// to any other shell. Discovery then reported "no config file found" and
/// the advice attached to that message is **`Run \`warden init\``** — which
/// on such a host would write a SECOND config beside a live one. A
/// misdiagnosis that recommends a destructive action is worse than no
/// diagnosis, and on a box serving household DNS it is the only failure
/// mode here that can cause damage rather than confusion.
///
/// The probe therefore opens the file rather than stat-ing it: a `0640`
/// config inside a world-traversable directory passes `exists()` and then
/// fails at load time, which is the same defect one layer later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateProbe {
    /// The file is there and the caller can open it for reading.
    Present,
    /// The file is definitively not there (`ENOENT`).
    Absent,
    /// Something is in the way — most often a `0750` parent directory owned
    /// by the daemon user, or a `0640` config owned by it. The file may or
    /// may not exist; the caller is not permitted to find out.
    Unreadable,
}

/// A discovery warning, split into the two shapes its consumers need.
///
/// **Why a struct and not the single string this used to be.** The full
/// text is ~260 characters. stderr wants all of it. The TUI footer renders
/// it into a `Constraint::Min(20)` column with no `.wrap()`, so ratatui
/// clips at the column edge — with no ellipsis, so the operator cannot even
/// tell text is missing. Measured on a 210-column terminal: 142 of 258
/// characters survive, and the 116 that are cut contain **the entire
/// remedy**. What is left is the list of paths that were searched, which is
/// the half that helps least.
///
/// Truncating more cleverly does not fix that — no prefix of one sentence
/// is both short enough for a narrow footer and complete enough to act on.
/// So the warning states itself twice, at two lengths, and each surface
/// takes the one it can render:
///
/// * [`DiscoveryWarning::headline`] — one clause, no paths, no remedy.
///   Sized to survive a narrow footer intact.
/// * [`DiscoveryWarning::detail`] — paths, cause and remedy. Needs a
///   surface that wraps: stderr, or the TUI's Archetype-C notice overlay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryWarning {
    /// Glanceable clause. Safe to render in a fixed-width slot.
    pub headline: String,
    /// The full explanation, including every path and the remedy.
    pub detail: String,
}

impl DiscoveryWarning {
    /// stderr rendering: both halves, one line. This is the only consumer
    /// with unlimited width, and the original single-string text is what it
    /// printed before the split — so it keeps printing exactly that.
    pub fn one_line(&self) -> String {
        format!("{} {}", self.headline, self.detail)
    }
}

/// Probe one candidate by attempting to open it.
///
/// `File::open` and not `try_exists`: the latter answers "is there a
/// directory entry", which is a strictly weaker question than "can this
/// process load this config" and leaves the `0640`-in-a-`0755`-directory
/// case reported as `Present`. Opening for read is side-effect-free.
fn probe_path(p: &Path) -> CandidateProbe {
    match std::fs::File::open(p) {
        Ok(_) => CandidateProbe::Present,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => CandidateProbe::Absent,
        // PermissionDenied is the case this whole enum exists for; every
        // other errno (ELOOP, ENAMETOOLONG, EIO…) is also "present enough
        // that we must not tell the operator to run `init`".
        Err(_) => CandidateProbe::Unreadable,
    }
}

/// System-install root for the v1 master config (A2 in
/// `_docs/features/config_architecture.md`).
const ETC_ROOT: &str = "/etc/purge-warden/";

/// Legacy monolithic-config root kept for backward compatibility with
/// pre-S34 installs.
const VAR_LIB_ROOT: &str = "/var/lib/purge-warden/";

/// Runtime PID file path used when the resolved config lives under a
/// system root ([`ETC_ROOT`] or [`VAR_LIB_ROOT`]).
const SYSTEM_PID_FILE: &str = "/run/purge-warden/purge-warden.pid";

/// Fallback PID file path used for the dev workflow (repo-local config).
const DEV_PID_FILE: &str = "purge-warden.pid";

/// Build the ordered list of candidate config paths.
///
/// Order matters: the first existing candidate wins, and the first candidate
/// overall is used as the placeholder path when none exist.
///
/// Non-root (`is_root == false`) — full dev search order:
/// 1. `./config.toml` — dev workflow (running from the repo root).
/// 2. `$XDG_CONFIG_HOME/purge-warden/config.toml` (or `$HOME/.config/...`)
///    — per-user install.
/// 3. `/etc/purge-warden/config.toml` — v1 FHS system install (A2).
/// 4. `/var/lib/purge-warden/config.toml` — legacy pre-S34 monolithic
///    layout.
///
/// Root (`is_root == true`) — system roots ONLY (`config_discovery-01`): the
/// CWD and per-user candidates are dropped because a root process must not
/// auto-load a config from a user-writable path. Only `/etc/` then `/var/lib/`
/// remain.
fn default_search_paths(is_root: bool) -> Vec<PathBuf> {
    let mut paths = Vec::with_capacity(4);

    // config_discovery-01: skip the user-writable dev candidates entirely when
    // running as root. `./config.toml` (CWD) and the XDG/`$HOME` path are dev
    // conveniences; as root we trust only the root-owned system roots below.
    if !is_root {
        paths.push(PathBuf::from("./config.toml"));

        let user_base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")));
        if let Some(base) = user_base {
            paths.push(base.join("purge-warden").join("config.toml"));
        }
    }

    paths.push(PathBuf::from("/etc/purge-warden/config.toml"));
    paths.push(PathBuf::from("/var/lib/purge-warden/config.toml"));

    paths
}

/// Resolve which config path the binary should load.
///
/// - `explicit = Some(p)` — the user passed `--config`. Return `p` unchanged;
///   we never second-guess an explicit flag.
/// - `explicit = None` — walk the default search paths and return the first
///   file that exists. If none exist, return the first candidate plus a
///   warning string listing where we looked.
pub fn resolve_config_path(explicit: Option<PathBuf>) -> (PathBuf, Option<DiscoveryWarning>) {
    let is_root = running_as_root();
    resolve_with(explicit, default_search_paths(is_root), is_root, probe_path)
}

/// True when the effective uid is 0. `geteuid()` is always-safe (no arguments,
/// cannot fail, permitted under the daemon seccomp filter); mirrors
/// `cli::commands::init::is_root`.
fn running_as_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn resolve_with(
    explicit: Option<PathBuf>,
    candidates: Vec<PathBuf>,
    is_root: bool,
    probe: impl Fn(&Path) -> CandidateProbe,
) -> (PathBuf, Option<DiscoveryWarning>) {
    if let Some(p) = explicit {
        return (p, None);
    }
    let exists = |p: &Path| probe(p) == CandidateProbe::Present;

    // config_discovery-01: as root the CWD candidate was dropped from the
    // search list. If a `./config.toml` a non-root run WOULD have loaded is
    // sitting in the CWD, say so loudly — otherwise the operator is left
    // wondering why their local file was ignored, and a planted file's
    // shadowing would pass silently.
    let root_skip_notice = if is_root && exists(Path::new("./config.toml")) {
        Some(DiscoveryWarning {
            headline: "running as root: ignoring ./config.toml in the current directory"
                .to_string(),
            detail: "A root invocation auto-loads only the system config under \
                     /etc/purge-warden/ or /var/lib/purge-warden/. Pass \
                     `--config ./config.toml` to load it explicitly."
                .to_string(),
        })
    } else {
        None
    };

    // One probe per candidate: the loop both selects the winner and records
    // the blocked ones, so the diagnosis below is built from what was
    // actually observed rather than re-derived afterwards.
    let mut blocked: Vec<&PathBuf> = Vec::new();
    for candidate in &candidates {
        match probe(candidate) {
            CandidateProbe::Present => return (candidate.clone(), root_skip_notice),
            CandidateProbe::Unreadable => blocked.push(candidate),
            CandidateProbe::Absent => {}
        }
    }

    let searched = candidates
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    // A blocked candidate is a DIFFERENT fact from an absent one, and gets a
    // different instruction. Saying "no config file found" here would be
    // false, and the `warden init` it recommends would put a second config
    // beside a live one — see [`CandidateProbe`].
    //
    // Each headline is written to stand alone: no path list, no trailing
    // clause that a narrow footer would cut mid-word. The paths live in the
    // detail, where there is room to wrap them.
    let warning = if blocked.is_empty() {
        // The remedy is spelled out as a sequence, not as one verb. The
        // question this answers is the one a first-run operator actually
        // asks — "do I need an upstream? a list?" — and `warden init` alone
        // does not answer it. Naming no resolver is deliberate: there is no
        // default upstream (neutrality-03), so the operator must choose one
        // and warden must not choose for them.
        DiscoveryWarning {
            headline: "no config file found — using built-in defaults".to_string(),
            detail: format!(
                "Searched: {searched}. This looks like a fresh install. Three steps: \
                 (1) `warden init --upstream <resolver>` — there is no default, warden \
                 does not pick a provider for you; (2) subscribe to at least one \
                 blocklist, with `warden blocklist add` or from the Lists tab, or the \
                 daemon runs and filters nothing; (3) start it — `systemctl start \
                 purge-warden`, or `warden start` for a foreground run. Already have a \
                 config elsewhere? Pass `--config <path>`."
            ),
        }
    } else {
        let list = blocked
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        DiscoveryWarning {
            headline: "config found but not readable by this user".to_string(),
            detail: format!(
                "Blocked: {list}. warden's config is owned by the system user the daemon \
                 runs as, so this is a permissions problem, NOT a missing install. Re-run \
                 as that user — a login shell sources \
                 /etc/profile.d/purge-warden-wrapper.sh, which routes for you, and \
                 `sudo -u purge-warden warden status` always works. Do NOT run \
                 `warden init` — it would write a second config beside the existing one."
            ),
        }
    };
    // Surface both facts when we ALSO skipped a CWD config because we're root.
    // The discovery headline is kept — it describes what warden is actually
    // doing — and the root skip leads the detail, because an ignored file the
    // operator can see in `ls` is the more surprising of the two.
    let warning = match root_skip_notice {
        Some(notice) => DiscoveryWarning {
            headline: warning.headline,
            detail: format!("{} {} {}", notice.headline, notice.detail, warning.detail),
        },
        None => warning,
    };

    let fallback = candidates
        .into_iter()
        .next()
        .unwrap_or_else(|| PathBuf::from("./config.toml"));
    (fallback, Some(warning))
}

/// Resolve the PID file path the CLI should talk to.
///
/// - `explicit = Some(p)` — the user passed `--pid-file`. Return it
///   unchanged (never second-guess an explicit flag).
/// - `explicit = None` — derive the default from `config_path`:
///   * config under `/etc/purge-warden/` or `/var/lib/purge-warden/`
///     → `/run/purge-warden/purge-warden.pid` (systemd install).
///   * anywhere else → `./purge-warden.pid` (dev workflow; matches the
///     pre-S34 clap default).
///
/// This keeps `warden status` / `stop` / `cache` working without a flag
/// on a systemd install where the daemon writes its PID under `/run/`,
/// and leaves `cargo run -- start` untouched in the repo.
pub fn resolve_pid_file(explicit: Option<PathBuf>, config_path: &Path) -> PathBuf {
    if let Some(p) = explicit {
        return p;
    }
    if config_is_under_system_root(config_path) {
        PathBuf::from(SYSTEM_PID_FILE)
    } else {
        PathBuf::from(DEV_PID_FILE)
    }
}

fn config_is_under_system_root(config_path: &Path) -> bool {
    let s = config_path.to_string_lossy();
    s.starts_with(ETC_ROOT) || s.starts_with(VAR_LIB_ROOT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Adapt the old "this set of paths is present, everything else is not"
    /// fixture shape to the three-way probe. Absent is the right default
    /// here: the blocked case is the exception these tests are contrasted
    /// against, so it is always spelled out explicitly by the test that
    /// wants it.
    fn present_set(set: HashSet<PathBuf>) -> impl Fn(&Path) -> CandidateProbe {
        move |p| {
            if set.contains(&p.to_path_buf()) {
                CandidateProbe::Present
            } else {
                CandidateProbe::Absent
            }
        }
    }

    #[test]
    fn explicit_path_passes_through_even_if_missing() {
        let (path, warning) =
            resolve_config_path(Some(PathBuf::from("/definitely/not/there.toml")));
        assert_eq!(path, PathBuf::from("/definitely/not/there.toml"));
        assert!(warning.is_none());
    }

    #[test]
    fn explicit_beats_existing_candidates() {
        // Even if `./config.toml` exists on disk (it may in the dev repo),
        // an explicit path must win without any warning.
        let explicit = PathBuf::from("/explicit/override.toml");
        let candidates = vec![PathBuf::from("/etc/should_be_ignored.toml")];
        let (path, warning) = resolve_with(Some(explicit.clone()), candidates, false, |_| {
            CandidateProbe::Present
        });
        assert_eq!(path, explicit);
        assert!(warning.is_none());
    }

    #[test]
    fn first_existing_candidate_wins() {
        let candidates = vec![
            PathBuf::from("/a/missing.toml"),
            PathBuf::from("/b/present.toml"),
            PathBuf::from("/c/also_present.toml"),
        ];
        let present: HashSet<PathBuf> = [
            PathBuf::from("/b/present.toml"),
            PathBuf::from("/c/also_present.toml"),
        ]
        .into_iter()
        .collect();

        let (path, warning) = resolve_with(None, candidates, false, present_set(present));
        assert_eq!(path, PathBuf::from("/b/present.toml"));
        assert!(warning.is_none());
    }

    #[test]
    fn no_candidates_exist_returns_first_with_warning() {
        let candidates = vec![
            PathBuf::from("./config.toml"),
            PathBuf::from("/home/x/.config/purge-warden/config.toml"),
            PathBuf::from("/etc/purge-warden/config.toml"),
            PathBuf::from("/var/lib/purge-warden/config.toml"),
        ];

        let (path, warning) = resolve_with(None, candidates, false, |_| CandidateProbe::Absent);
        assert_eq!(path, PathBuf::from("./config.toml"));
        let w = warning
            .expect("warning should be present when nothing exists")
            .one_line();
        assert!(w.contains("no config file found"));
        assert!(w.contains("./config.toml"));
        assert!(w.contains("/etc/purge-warden/config.toml"));
        assert!(w.contains("/var/lib/purge-warden/config.toml"));
        // The genuinely-absent case is the ONE case where `init` is right.
        assert!(
            w.contains("warden init"),
            "an absent config is what `init` is for: {w}"
        );
    }

    /// The measured home-warden failure: the master exists at
    /// `/var/lib/purge-warden/config.toml` behind a `0750` directory owned by
    /// the daemon user, and every other candidate is genuinely absent.
    #[test]
    fn blocked_candidate_is_not_reported_as_missing() {
        let candidates = vec![
            PathBuf::from("./config.toml"),
            PathBuf::from("/home/x/.config/purge-warden/config.toml"),
            PathBuf::from("/etc/purge-warden/config.toml"),
            PathBuf::from("/var/lib/purge-warden/config.toml"),
        ];
        let blocked = PathBuf::from("/var/lib/purge-warden/config.toml");
        let (path, warning) = resolve_with(None, candidates, false, |p| {
            if p == blocked {
                CandidateProbe::Unreadable
            } else {
                CandidateProbe::Absent
            }
        });

        // The fallback path is deliberately unchanged — only the diagnosis moves.
        assert_eq!(path, PathBuf::from("./config.toml"));
        let w = warning
            .expect("a blocked candidate must still warn")
            .one_line();
        assert!(
            !w.contains("no config file found"),
            "the config was found — saying otherwise is the bug: {w}"
        );
        assert!(
            w.contains("/var/lib/purge-warden/config.toml"),
            "the warning must name the path it could not read: {w}"
        );
    }

    /// The damage-preventing property, pinned on its own: on this host
    /// `warden init` would write a second config beside a live one that is
    /// serving DNS. The warning must never recommend it.
    #[test]
    fn blocked_candidate_warning_never_recommends_init() {
        let candidates = vec![
            PathBuf::from("./config.toml"),
            PathBuf::from("/var/lib/purge-warden/config.toml"),
        ];
        let blocked = PathBuf::from("/var/lib/purge-warden/config.toml");
        let (_, warning) = resolve_with(None, candidates, false, |p| {
            if p == blocked {
                CandidateProbe::Unreadable
            } else {
                CandidateProbe::Absent
            }
        });
        let w = warning.expect("warning expected").one_line();
        assert!(
            !w.contains("Run `warden init`"),
            "recommending init here creates a second config: {w}"
        );
        assert!(
            w.contains("Do NOT run `warden init`"),
            "the refusal must be explicit, not merely omitted: {w}"
        );
    }

    /// A readable candidate wins outright — a blocked one earlier in the
    /// order must not shadow it, and must not produce a warning either.
    #[test]
    fn readable_candidate_beats_a_blocked_one() {
        let candidates = vec![
            PathBuf::from("/etc/purge-warden/config.toml"),
            PathBuf::from("/var/lib/purge-warden/config.toml"),
        ];
        let (path, warning) = resolve_with(None, candidates, false, |p| {
            if p == Path::new("/etc/purge-warden/config.toml") {
                CandidateProbe::Unreadable
            } else {
                CandidateProbe::Present
            }
        });
        assert_eq!(path, PathBuf::from("/var/lib/purge-warden/config.toml"));
        assert!(
            warning.is_none(),
            "a successful load needs no warning about the paths it skipped"
        );
    }

    /// `File::open`, not `try_exists`: a config that a stat can see but the
    /// process cannot read must land in `Unreadable`, or the defect simply
    /// moves one layer down to the loader.
    #[test]
    fn probe_reports_unreadable_for_a_mode_000_file() {
        use std::os::unix::fs::PermissionsExt;

        // Running as root defeats the mode bits entirely, so there is nothing
        // to assert — skip rather than fail. (`cargo test` as root is
        // unusual but happens inside containers.)
        if unsafe { libc::geteuid() } == 0 {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("config.toml");
        std::fs::write(&f, "x = 1\n").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o000)).unwrap();

        assert_eq!(probe_path(&f), CandidateProbe::Unreadable);
        assert_eq!(
            probe_path(&dir.path().join("nope.toml")),
            CandidateProbe::Absent
        );

        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(probe_path(&f), CandidateProbe::Present);
    }

    #[test]
    fn root_skips_planted_cwd_and_picks_system_with_notice() {
        // config_discovery-01: a root run has system-only candidates. With a
        // planted ./config.toml AND a real /etc master, the /etc master wins
        // and the operator is told the CWD file was ignored.
        let candidates = vec![
            PathBuf::from("/etc/purge-warden/config.toml"),
            PathBuf::from("/var/lib/purge-warden/config.toml"),
        ];
        let present: HashSet<PathBuf> = [
            PathBuf::from("/etc/purge-warden/config.toml"),
            PathBuf::from("./config.toml"),
        ]
        .into_iter()
        .collect();

        let (path, warning) = resolve_with(None, candidates, true, present_set(present));
        assert_eq!(path, PathBuf::from("/etc/purge-warden/config.toml"));
        let w = warning
            .expect("root must be told its CWD config was ignored")
            .one_line();
        assert!(w.contains("ignoring ./config.toml"), "notice text: {w}");
    }

    #[test]
    fn root_with_cwd_only_falls_back_and_combines_warnings() {
        // Root, a ./config.toml present but no system master: discovery skips
        // the CWD file, falls back to the /etc placeholder, and the warning
        // names BOTH the ignored CWD file and the no-config fallback.
        let candidates = vec![
            PathBuf::from("/etc/purge-warden/config.toml"),
            PathBuf::from("/var/lib/purge-warden/config.toml"),
        ];
        let present: HashSet<PathBuf> = [PathBuf::from("./config.toml")].into_iter().collect();

        let (path, warning) = resolve_with(None, candidates, true, present_set(present));
        assert_eq!(path, PathBuf::from("/etc/purge-warden/config.toml"));
        let w = warning.expect("warning expected").one_line();
        assert!(w.contains("ignoring ./config.toml"), "notice text: {w}");
        assert!(w.contains("no config file found"), "fallback text: {w}");
    }

    #[test]
    fn non_root_still_loads_cwd_config_unaffected() {
        // The dev workflow must be byte-for-byte unchanged: a non-root run
        // loads ./config.toml first, no warning, no notice.
        let candidates = vec![
            PathBuf::from("./config.toml"),
            PathBuf::from("/etc/purge-warden/config.toml"),
        ];
        let present: HashSet<PathBuf> = [PathBuf::from("./config.toml")].into_iter().collect();

        let (path, warning) = resolve_with(None, candidates, false, present_set(present));
        assert_eq!(path, PathBuf::from("./config.toml"));
        assert!(warning.is_none(), "non-root CWD load must be silent");
    }

    #[test]
    fn default_search_paths_are_non_empty_and_start_with_cwd() {
        // Non-root dev search order: CWD first.
        let paths = default_search_paths(false);
        assert!(!paths.is_empty());
        assert_eq!(paths[0], PathBuf::from("./config.toml"));
        // Both system install paths must be present, regardless of
        // whether $HOME is set in the test environment.
        assert!(paths.contains(&PathBuf::from("/etc/purge-warden/config.toml")));
        assert!(paths.contains(&PathBuf::from("/var/lib/purge-warden/config.toml")));
    }

    #[test]
    fn root_search_paths_are_system_only() {
        // config_discovery-01: as root the CWD and per-user candidates are
        // dropped — only the root-owned system roots remain, /etc first.
        let paths = default_search_paths(true);
        assert_eq!(
            paths,
            vec![
                PathBuf::from("/etc/purge-warden/config.toml"),
                PathBuf::from("/var/lib/purge-warden/config.toml"),
            ]
        );
        assert!(!paths.contains(&PathBuf::from("./config.toml")));
        // No per-user path leaks in, whatever $HOME/$XDG_CONFIG_HOME hold.
        assert!(!paths
            .iter()
            .any(|p| p.to_string_lossy().contains(".config")));
    }

    #[test]
    fn default_search_paths_prefer_etc_over_var_lib() {
        // v1 FHS layout puts the master at /etc/. Both candidates must
        // appear, but /etc/ must come first so a machine still carrying
        // a pre-S34 /var/lib/...config.toml does not shadow the new
        // master once it is created under /etc/.
        let paths = default_search_paths(false);
        let etc_idx = paths
            .iter()
            .position(|p| p == Path::new("/etc/purge-warden/config.toml"))
            .expect("/etc/ candidate must be present");
        let var_idx = paths
            .iter()
            .position(|p| p == Path::new("/var/lib/purge-warden/config.toml"))
            .expect("/var/lib/ candidate must be present");
        assert!(
            etc_idx < var_idx,
            "/etc/ must come before /var/lib/ (got etc@{etc_idx}, var@{var_idx})"
        );
    }

    #[test]
    fn resolve_pid_file_honours_explicit_flag() {
        let explicit = PathBuf::from("/custom/pid.file");
        let resolved = resolve_pid_file(
            Some(explicit.clone()),
            Path::new("/etc/purge-warden/config.toml"),
        );
        assert_eq!(resolved, explicit);
    }

    #[test]
    fn resolve_pid_file_defaults_to_run_for_etc_master() {
        let resolved = resolve_pid_file(None, Path::new("/etc/purge-warden/config.toml"));
        assert_eq!(
            resolved,
            PathBuf::from("/run/purge-warden/purge-warden.pid")
        );
    }

    #[test]
    fn resolve_pid_file_defaults_to_run_for_legacy_var_lib_master() {
        let resolved = resolve_pid_file(None, Path::new("/var/lib/purge-warden/config.toml"));
        assert_eq!(
            resolved,
            PathBuf::from("/run/purge-warden/purge-warden.pid")
        );
    }

    #[test]
    fn resolve_pid_file_defaults_to_cwd_for_dev_repo() {
        let resolved = resolve_pid_file(None, Path::new("./config.toml"));
        assert_eq!(resolved, PathBuf::from("purge-warden.pid"));
    }

    #[test]
    fn resolve_pid_file_defaults_to_cwd_for_home_config() {
        let resolved = resolve_pid_file(
            None,
            Path::new("/home/alice/.config/purge-warden/config.toml"),
        );
        assert_eq!(resolved, PathBuf::from("purge-warden.pid"));
    }

    #[test]
    fn resolve_pid_file_does_not_match_prefix_substring() {
        // /etc/purge-warden-backup/... must NOT be treated as a system
        // install just because its path starts with /etc/purge-warden.
        // The trailing slash in ETC_ROOT guards against this.
        let resolved = resolve_pid_file(None, Path::new("/etc/purge-warden-backup/config.toml"));
        assert_eq!(resolved, PathBuf::from("purge-warden.pid"));
    }
}
