//! `warden lists show` / `warden lists set` — read and edit the `[lists]`
//! tunables without hand-editing TOML.
//!
//! `[lists]` carried seven knobs and no verb: `warden config edit`
//! opening `$EDITOR` was the only way to turn any of them. That is a poor
//! answer for `max_total_domains` in particular, which is a ceiling with
//! three distinct behaviours either side of it — an operator setting it
//! blind cannot tell which one they are in.
//!
//! Follows the same shape as `warden security show` / `set`, deliberately:
//! one declarative `KNOBS` table feeding `show`, the valid-key list, the
//! unknown-key error and the value parser, so none of the four can drift
//! from the others.
//!
//! `set` edits the TOML through [`write_value_validated`] (which validates
//! the COMBINED master + includes state before promoting anything) and
//! then asks the daemon to reload. Nothing on the daemon side needs
//! rewiring: the reload path re-reads the corpus ceiling and the shrink
//! guard from config on every reload.
//!
//! `[lists]` is a *singleton* section, so the loader refuses it appearing
//! in more than one file. `set` therefore writes the master
//! unconditionally: if an operator moved the section into an include, the
//! combined validation refuses the write and names both files, rather
//! than writing a value the merged config would never use.

use std::path::Path;

use anyhow::{bail, Context};
use toml::Value;

use crate::config::loader::load_config;
use crate::ipc::protocol::{IpcCommand, IpcResponse};
use crate::ipc::socket_client::send_command;
use crate::lists::status::{CorpusRefusal, CycleMark};

use super::target::{read_or_empty, write_value_validated};

/// One tunable, its field name under `[lists]`, and how to parse an
/// operator's string.
///
/// A table rather than a `match` arm per key so `show`, `set` and the
/// error message that lists valid keys all read the SAME source. When
/// those drifted apart elsewhere the result was a verb that accepted a
/// key `show` never printed.
///
/// Unlike `[security]`, which nests its knobs under `rrl` and
/// `rate_limit`, `[lists]` is flat — the key IS the field name, so there
/// is no separate section to carry.
struct Knob {
    /// Key as the operator types it, and the field name under `[lists]`.
    key: &'static str,
    /// What the value means, printed by `show`.
    help: &'static str,
    kind: KnobKind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum KnobKind {
    Bool,
    /// Non-negative integer. The config validator enforces the real
    /// ranges (e.g. `shrink_guard_max_drop_pct` 1..=100); this only
    /// rejects input that is not an integer at all, so the operator gets
    /// "not a number" rather than a validator error about a field they
    /// typed correctly.
    Uint,
    /// Filesystem path, stored verbatim. Relative paths resolve against
    /// the config file's own directory, which is why no canonicalisation
    /// happens here — the string the operator typed is the string the
    /// loader must see.
    Path,
}

const KNOBS: &[Knob] = &[
    Knob {
        key: "max_total_domains",
        help: "ceiling on the merged, deduplicated corpus (0 disables the check)",
        kind: KnobKind::Uint,
    },
    Knob {
        key: "max_entries",
        help: "default cap on domains loaded from any single list",
        kind: KnobKind::Uint,
    },
    Knob {
        key: "max_body_bytes",
        help: "cap on the download size of any single list, in bytes",
        kind: KnobKind::Uint,
    },
    Knob {
        key: "cache_dir",
        help: "directory holding cached list bodies (relative to the config file)",
        kind: KnobKind::Path,
    },
    Knob {
        key: "staleness_threshold_secs",
        help: "age past which a list is shown as stale",
        kind: KnobKind::Uint,
    },
    Knob {
        key: "shrink_guard_enabled",
        help: "refuse a refresh that shrinks a list too far, keeping the last good copy",
        kind: KnobKind::Bool,
    },
    Knob {
        key: "shrink_guard_max_drop_pct",
        help: "percent a list may shrink in one refresh before the guard refuses it (1-100)",
        kind: KnobKind::Uint,
    },
];

/// Keys with their meanings, for `show` and for the unknown-key error.
///
/// One renderer for both: an operator who mistypes a key gets the same
/// annotated list they would have got from `show`, instead of a bare name
/// list that makes them run a second command to find out what the right
/// key does.
fn knob_list() -> String {
    KNOBS
        .iter()
        .map(|k| format!("{:<26} {}", k.key, k.help))
        .collect::<Vec<_>>()
        .join("\n  ")
}

/// `warden lists show` — print the effective `[lists]` settings, plus the
/// live corpus size measured against the ceiling.
pub async fn run_show(config_path: &Path, socket_path: &Path) -> anyhow::Result<()> {
    // Ahead of the config, and on stderr: an operator who pipes this
    // command's output somewhere still sees the freeze, and one whose
    // config no longer loads sees it instead of only a parse error.
    warn_if_frozen(socket_path).await;

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
    let l = &loaded.config.lists;

    println!("[lists]");
    // `0` is not "no ceiling of note" — it turns the whole guard off,
    // including the counting pass. Say so inline; an operator reading a
    // bare `0` would reasonably read it as "unset".
    if l.max_total_domains == 0 {
        println!("  max_total_domains:         0 (the corpus ceiling is disabled)");
    } else {
        println!("  max_total_domains:         {}", l.max_total_domains);
    }
    println!("  max_entries:               {}", l.max_entries);
    println!("  max_body_bytes:            {}", l.max_body_bytes);
    println!("  cache_dir:                 {}", l.cache_dir.display());
    println!(
        "  staleness_threshold_secs:  {}",
        l.staleness_threshold_secs
    );
    println!("  shrink_guard_enabled:      {}", l.shrink_guard_enabled);
    println!(
        "  shrink_guard_max_drop_pct: {}",
        l.shrink_guard_max_drop_pct
    );

    println!();
    let live = fetch_live_corpus(socket_path).await;
    for line in format_corpus_lines(l.max_total_domains as u64, live.as_ref().map_err(|e| *e)) {
        println!("{line}");
    }

    println!();
    println!("Change one with: warden lists set <key> <value>");
    println!("Keys:\n  {}", knob_list());
    Ok(())
}

/// What the running daemon knows about the installed corpus.
///
/// Every field here is a *live measurement*: none of it can be derived
/// from the config file, which is the whole reason `show` makes an IPC
/// call rather than printing config back at the operator.
pub(crate) struct LiveCorpus {
    /// Deduplicated domains in the filter map right now, across shards.
    pub(crate) unique_installed: u64,
    /// Sources whose last refresh hit `max_entries` and dropped the rest.
    pub(crate) truncated: u32,
    /// Configured sources, for the `n of m` denominator.
    pub(crate) total_sources: u32,
    /// Set when the last refresh cycle was refused by the corpus guard.
    pub(crate) refusal: Option<CorpusRefusal>,
    /// When the standing refusal streak began and how many cycles it has
    /// refused, from the same daemon. `None` from a daemon that predates
    /// the field, or when nothing has been refused since the last install.
    pub(crate) freeze: Option<crate::lists::status::CorpusFreeze>,
    /// The last completed reload cycle, for callers that need to wait for
    /// one. `None` from a daemon too old to report it — which is NOT the
    /// same as "no cycle has run", and callers must not conflate them.
    pub(crate) cycle: Option<CycleMark>,
}

/// Why the live measurement could not be taken.
///
/// A bare `None` rendered as *"the daemon is not running"* is misleading
/// when the daemon is up and serving DNS but the IPC connection was
/// refused — e.g. `warden` run as root while the peer-uid gate accepts
/// only the daemon's own uid. "Not running" and "running but refusing
/// you" call for opposite actions — start the service, versus re-run as
/// the right user — so a diagnostic that cannot tell them apart sends
/// the operator the wrong way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unreachable {
    /// No socket file at the path. Nothing has bound it, so the daemon
    /// really is not running.
    NoSocket,
    /// The socket file exists but nothing is listening — `ECONNREFUSED`,
    /// the signature of a daemon that died without unlinking it.
    StaleSocket,
    /// The socket accepted a connection, so a daemon **is** listening; it
    /// then closed without answering. That is precisely what the peer-uid
    /// gate does: it drops the stream and writes no response, so as not
    /// to leak the uid it expects.
    ConnectionRefused,
    /// `EACCES` on connect: the socket is `0o600` and owned by the daemon
    /// user, and this process is neither.
    PermissionDenied,
    /// Connected and answered, but not with a `Status` — version skew, or
    /// an error response.
    UnexpectedResponse,
}

/// One best-effort `Status` round-trip. An `Err` means we could not
/// measure — never a zero, which would read as "the corpus is empty".
pub(crate) async fn fetch_live_corpus(socket_path: &Path) -> Result<LiveCorpus, Unreachable> {
    match send_command(socket_path, &IpcCommand::Status).await {
        Ok(IpcResponse::Status {
            domain_count,
            lists_total,
            lists_truncated,
            lists_corpus_refusal,
            lists_corpus_freeze,
            lists_cycle,
            ..
        }) => Ok(LiveCorpus {
            unique_installed: domain_count as u64,
            truncated: lists_truncated,
            total_sources: lists_total,
            refusal: lists_corpus_refusal,
            freeze: lists_corpus_freeze,
            cycle: lists_cycle,
        }),
        Ok(_) => Err(Unreachable::UnexpectedResponse),
        Err(_) => Err(classify_unreachable(socket_path).await),
    }
}

/// Work out *why* the round-trip failed, by probing rather than by
/// reading the error text.
///
/// `send_command` returns an `anyhow::Error` whose message is the only
/// thing distinguishing a peer-uid drop (`daemon closed connection
/// without response`) from the rest, and matching on that string across
/// a module boundary would break silently the first time it is reworded.
/// So this re-probes the socket and classifies from what the kernel says,
/// which is typed. It costs one extra `connect` on a path that has
/// already failed, and nothing on the happy path.
///
/// Best-effort by construction: the daemon can stop between the two
/// attempts. Every outcome is still one of the states below, so a race
/// downgrades the precision of the advice, never its truthfulness.
async fn classify_unreachable(socket_path: &Path) -> Unreachable {
    if !socket_path.exists() {
        return Unreachable::NoSocket;
    }
    match tokio::net::UnixStream::connect(socket_path).await {
        // Something is listening and accepted us. The request failing
        // after that is a refusal by the daemon, not an absence of one.
        Ok(_) => Unreachable::ConnectionRefused,
        Err(e) => match e.kind() {
            std::io::ErrorKind::ConnectionRefused => Unreachable::StaleSocket,
            std::io::ErrorKind::PermissionDenied => Unreachable::PermissionDenied,
            // The file existed a moment ago and does not now.
            std::io::ErrorKind::NotFound => Unreachable::NoSocket,
            _ => Unreachable::StaleSocket,
        },
    }
}

/// Which of the corpus guard's three behaviours the current corpus falls in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Band {
    /// `max_total_domains = 0` — no measurement is taken at all.
    Disabled,
    /// Below 90 % of the ceiling: a refresh cycle installs quietly.
    Quiet,
    /// At or above 90 %: a refresh cycle installs, and warns.
    Warn,
    /// Past the ceiling: a refresh cycle is refused outright.
    Over,
}

/// Classify `unique` against `ceiling`.
///
/// Mirrors the daemon's own guard, which is private to the list manager
/// and cannot be called from here. The cross-multiplication is copied
/// deliberately rather than simplified to `unique >= ceiling / 10 * 9`:
/// integer division would distort small ceilings, and the multiplication
/// is done in `u128` so no configured ceiling can overflow it. The
/// boundary cases are pinned in the tests below against the same numbers
/// the manager's own tests use, so the duplication stays auditable.
fn corpus_band(unique: u64, ceiling: u64) -> Band {
    if ceiling == 0 {
        return Band::Disabled;
    }
    if unique > ceiling {
        return Band::Over;
    }
    if u128::from(unique) * 10 >= u128::from(ceiling) * 9 {
        Band::Warn
    } else {
        Band::Quiet
    }
}

/// Render the `Corpus:` block.
///
/// Split out as a pure function so the three bands, the refused-cycle
/// state and the daemon-down state are all testable without a daemon.
///
/// `ceiling` is the value in the config file. `live` is `None` when the
/// daemon could not be reached — in which case this prints that it could
/// not measure, and prints no number at all. A fabricated or stale count
/// here would be worse than no count: the operator is running this
/// command precisely because they cannot see the number any other way.
pub(crate) fn format_corpus_lines(
    ceiling: u64,
    live: Result<&LiveCorpus, Unreachable>,
) -> Vec<String> {
    let mut out = vec!["Corpus:".to_string()];

    let live = match live {
        Ok(l) => l,
        Err(why) => {
            // Each arm names the cause and the action it implies. They
            // are different actions, which is the entire point of the
            // split — see `Unreachable`.
            let (cause, fix) = match why {
                Unreachable::NoSocket => (
                    "the daemon is not running; there is no IPC socket at that path",
                    "Start it, or pass --socket if it listens elsewhere.",
                ),
                Unreachable::StaleSocket => (
                    "the IPC socket exists but nothing is listening; the daemon died \
                     without removing it",
                    "Start it; check `journalctl -u purge-warden` for why it stopped.",
                ),
                Unreachable::ConnectionRefused => (
                    "the daemon IS running and REFUSED the connection — it accepts IPC only \
                     from its own uid",
                    "Re-run as the daemon user, e.g. `runuser -u purge-warden -- warden \
                     lists show`. Running as root does not bypass this gate.",
                ),
                Unreachable::PermissionDenied => (
                    "permission denied on the IPC socket — it is mode 0600 and owned by the \
                     daemon user",
                    "Re-run as the daemon user, e.g. `runuser -u purge-warden -- warden \
                     lists show`.",
                ),
                Unreachable::UnexpectedResponse => (
                    "the daemon answered, but not with a status — likely a version mismatch \
                     between this binary and the running one",
                    "Check `warden --version` against the running unit.",
                ),
            };
            // Cause and remedy each get their own line rather than being
            // folded into the `<unknown …>` slot. That slot was written
            // for one short cause ("the daemon is not running") and turned
            // into a run-on the moment the causes below became specific
            // enough to be useful — with a nested em-dash inside a clause
            // the brackets had already opened.
            out.push(
                "  installed unique domains:  <unknown — no live measurement could be taken>"
                    .to_string(),
            );
            out.push(
                "  band:                      <unknown without a live measurement>".to_string(),
            );
            out.push(format!("  Why: {cause}."));
            out.push(format!("  Fix: {fix}"));
            return out;
        }
    };

    let unique = live.unique_installed;
    // Every band line is a claim about what the NEXT cycle does, derived
    // from the corpus that is currently installed. On a refused cycle that
    // corpus is the *previous* generation, so the claim is a prediction the
    // refusal record directly contradicts — "a refresh cycle installs
    // quietly" printed two lines above "the last cycle was refused". The
    // refusal block below already states what happens next, authoritatively
    // and from the daemon's own measurement, so the band stands down and
    // lets it speak. Same reason `warden status` drops the word "active"
    // on a refusal: a statement that is true about one thing and false
    // about the thing the operator is actually asking is worse than silence.
    let predict = live.refusal.is_none();
    match corpus_band(unique, ceiling) {
        Band::Disabled => {
            out.push(format!("  installed unique domains:  {unique}"));
            if predict {
                out.push(
                    "  band:                      n/a — max_total_domains is 0, so no ceiling \
                     is enforced"
                        .to_string(),
                );
            }
        }
        band => {
            out.push(format!(
                "  installed unique domains:  {unique} ({}% of max_total_domains {ceiling})",
                unique.saturating_mul(100) / ceiling.max(1),
            ));
            if predict {
                out.push(match band {
                    Band::Quiet => "  band:                      below 90% — a refresh cycle \
                         installs quietly"
                        .to_string(),
                    Band::Warn => "  band:                      at or above 90% — a refresh \
                         cycle installs, and warns"
                        .to_string(),
                    // Reachable without any refusal on record: lowering the
                    // ceiling below what is already installed does not evict
                    // anything, it arms the guard for the NEXT cycle. That
                    // state is invisible everywhere else, and it is the one
                    // an operator most needs to be told about after an edit.
                    Band::Over => "  band:                      ABOVE the ceiling — the next \
                         refresh cycle will be REFUSED and the currently installed corpus kept"
                        .to_string(),
                    Band::Disabled => unreachable!("handled above"),
                });
            }
        }
    }

    if live.total_sources > 0 {
        // Printed even at zero, unlike the per-list `blocklist show`
        // block which stays silent to avoid reading as reassurance. Here
        // the operator ran a command about `max_entries` — "nothing is
        // truncated" is the answer to their question, not noise.
        let mut line = format!(
            "  truncated sources:         {} of {} hit max_entries",
            live.truncated, live.total_sources
        );
        if live.truncated > 0 {
            line.push_str(" (run `warden blocklist show <id>` for per-list counts)");
        }
        out.push(line);
    }

    if let Some(r) = &live.refusal {
        out.push(String::new());
        out.push(format!(
            "  CORPUS REFUSED: the last cycle measured {} unique domains against a ceiling \
             of {}, and installed nothing.",
            r.unique, r.ceiling
        ));
        out.push(
            "  Every source downloaded and parsed correctly; the daemon is serving the \
             previous generation."
                .to_string(),
        );
        // The line that separates a blip from an outage; same wording as
        // `warden status`, so the two surfaces cannot disagree about it.
        if let Some((f, since)) = live
            .freeze
            .as_ref()
            .and_then(|f| Some((f, super::status::format_frozen_since(f)?)))
        {
            out.push(format!(
                "  FROZEN since {since} ({} refused cycles, counted since this daemon started).",
                f.consecutive
            ));
        }
        if let Some((source, novel)) = r.novel_by_source.first() {
            out.push(format!(
                "  Largest contributor: {source} (+{novel} domains no other list supplies; \
                 order-dependent)."
            ));
        }
        // The daemon enforces the ceiling it loaded, not the one on disk.
        // An edit that has not been reloaded makes every band above a
        // statement about a number the daemon is not using.
        if r.ceiling != ceiling {
            out.push(format!(
                "  Note: the daemon enforced max_total_domains = {}, but the config file now \
                 says {ceiling} — it has not reloaded since that edit.",
                r.ceiling
            ));
        }
    }

    out
}

/// What subscribing to one more list would do to the corpus ceiling.
///
/// An upper bound, never a measurement. The catalog records each list's
/// own size, and warden installs the *union* of every list — overlap
/// between lists is large in practice, so a list this says "may cross"
/// the ceiling often does not. The asymmetry is deliberate: a false
/// warning costs a line of output, a missed one costs a corpus that
/// silently stops updating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Projection {
    /// Even the no-overlap upper bound stays inside the ceiling.
    Fits,
    /// The upper bound crosses it; `upper_bound` is `installed + entries`.
    MayCross { upper_bound: u64 },
    /// No bound can be computed; `reason` names the input that was missing.
    Unknown { reason: &'static str },
    /// `max_total_domains = 0` — no ceiling is enforced, so nothing to project.
    Disabled,
}

/// Project `installed + entries` against `ceiling`.
///
/// `ceiling` is tested first: with the guard disabled there is no
/// question to answer, so a missing catalog entry is not worth reporting.
///
/// `Some(0)` is the catalog's *unknown*, not a list of no domains — the
/// field is `#[serde(default)]` and an index that omits it deserializes
/// to zero — so it collapses into the same `Unknown` as an absent entry.
/// Reading it as a real count would report `Fits` for every list whose
/// size nobody knows, which is the one answer that cannot be justified.
pub(crate) fn corpus_projection(installed: u64, ceiling: u64, entries: Option<u64>) -> Projection {
    if ceiling == 0 {
        return Projection::Disabled;
    }
    let Some(entries) = entries.filter(|n| *n > 0) else {
        return Projection::Unknown {
            reason: "no catalog metadata for this list yet",
        };
    };
    // Saturating because both operands are operator-controlled and the
    // sum is only ever compared against the ceiling, never counted with.
    let upper_bound = installed.saturating_add(entries);
    if upper_bound > ceiling {
        Projection::MayCross { upper_bound }
    } else {
        Projection::Fits
    }
}

/// The banner for a corpus the daemon has stopped updating, or `None`
/// when the last cycle installed.
///
/// Pure so the wording is pinned without a daemon. On every verb but
/// `show` this line is the *only* notice a refusal gets, and a refusal
/// that goes unread is indistinguishable to the operator from a corpus
/// that is up to date — which is exactly how one survives for weeks.
///
/// `<n>` is literal. The operator chooses the new ceiling; any number
/// warden named here would be a guess at their memory budget.
pub(crate) fn frozen_banner(live: &LiveCorpus) -> Option<String> {
    let r = live.refusal.as_ref()?;
    Some(format!(
        "warning: CORPUS FROZEN — the last refresh was refused (merged corpus {} > \
         max_total_domains {}); domains published upstream since then are NOT being \
         blocked. Run: warden status. Raise with: warden lists set max_total_domains \
         <n>, or drop a list.",
        r.unique, r.ceiling
    ))
}

/// Print [`frozen_banner`] on stderr when the daemon reports a refusal.
///
/// Best-effort, and silent on every failure: the verbs that call this are
/// doing something else, and an operator who cannot reach the daemon has
/// already been told so by whatever they ran.
///
/// Silence is also the answer when the probe is slow. `send_command`
/// bounds each phase at five seconds and the unreachability classifier
/// adds an unbounded `connect`, so a daemon that accepts the connection
/// and then stops answering could hold a fast verb for far longer than
/// the verb itself takes. A banner is worth two seconds, not fifteen.
pub(crate) async fn warn_if_frozen(socket_path: &Path) {
    let probe = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        fetch_live_corpus(socket_path),
    );
    if let Ok(Ok(live)) = probe.await {
        if let Some(banner) = frozen_banner(&live) {
            eprintln!("{banner}");
        }
    }
}

/// `warden lists set <key> <value>` — edit the TOML, then reload.
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

    let (mut doc, _orig) = read_or_empty(config_path)?;
    let table = doc
        .as_table_mut()
        .context("config root is not a TOML table")?;
    let lists = table
        .entry("lists")
        .or_insert_with(|| Value::Table(Default::default()))
        .as_table_mut()
        .context("[lists] exists but is not a table")?;

    let previous = lists.get(knob.key).cloned();
    if previous.as_ref() == Some(&parsed) {
        // No-op writes still cost a reload, and a reload on a live
        // resolver is not free.
        println!("lists.{key} is already {value} — no change");
        return Ok(());
    }
    lists.insert(knob.key.to_string(), parsed);

    // Validates master + every include as one combined state BEFORE any
    // file is promoted, so an out-of-range value is refused with the
    // config untouched rather than written and then rejected at load.
    write_value_validated(config_path, config_path, &doc)?;

    match previous {
        Some(p) => println!("lists.{key}: {p} → {value}"),
        None => println!("lists.{key} = {value} (was unset, using the built-in default)"),
    }

    let outcome = super::ipc_reload::attempt_reload(socket_path).await;
    super::ipc_reload::report_reload_outcome(&outcome);
    Ok(())
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
        KnobKind::Path => {
            if raw.trim().is_empty() {
                bail!("{} cannot be empty — give a directory path", knob.key);
            }
            Ok(Value::String(raw.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Projection::{Disabled, Fits, MayCross, Unknown};
    use super::*;

    #[test]
    fn knob_keys_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for k in KNOBS {
            assert!(seen.insert(k.key), "duplicate knob key '{}'", k.key);
        }
    }

    /// Every knob key must name a real field of `ListsConfig`.
    ///
    /// `set` writes `lists.<key>` verbatim, so a typo'd key would write a
    /// field the schema does not have. This compares against the
    /// serialised default rather than a hand-written list of names, so it
    /// stays true when the struct changes.
    #[test]
    fn every_knob_key_is_a_real_lists_field() {
        let defaults = crate::config::settings::ListsConfig::default();
        let table = Value::try_from(&defaults).expect("ListsConfig serialises to TOML");
        let table = table.as_table().expect("ListsConfig is a table");
        for k in KNOBS {
            assert!(
                table.contains_key(k.key),
                "knob '{}' is not a field of [lists]; `set` would write a key the schema rejects",
                k.key
            );
        }
    }

    #[test]
    fn bool_parsing_accepts_the_documented_spellings_and_rejects_others() {
        let knob = KNOBS
            .iter()
            .find(|k| k.key == "shrink_guard_enabled")
            .unwrap();
        for yes in ["true", "on", "yes", "1"] {
            assert_eq!(parse_value(knob, yes).unwrap(), Value::Boolean(true));
        }
        for no in ["false", "off", "no", "0"] {
            assert_eq!(parse_value(knob, no).unwrap(), Value::Boolean(false));
        }
        // A number is NOT silently coerced — `shrink_guard_enabled 5` is a
        // typo, and accepting it as `true` would hide the mistake.
        assert!(parse_value(knob, "5").is_err());
        assert!(parse_value(knob, "").is_err());
    }

    #[test]
    fn uint_parsing_rejects_negatives_and_non_numbers() {
        let knob = KNOBS.iter().find(|k| k.key == "max_total_domains").unwrap();
        assert_eq!(
            parse_value(knob, "15000000").unwrap(),
            Value::Integer(15_000_000)
        );
        // 0 is meaningful here (it disables the ceiling), so it must parse.
        assert_eq!(parse_value(knob, "0").unwrap(), Value::Integer(0));
        assert!(
            parse_value(knob, "-1").is_err(),
            "a negative ceiling must not reach the validator as a huge unsigned"
        );
        assert!(parse_value(knob, "many").is_err());
        assert!(parse_value(knob, "1.5").is_err());
    }

    #[test]
    fn path_parsing_rejects_empty_and_keeps_the_string_verbatim() {
        let knob = KNOBS.iter().find(|k| k.key == "cache_dir").unwrap();
        assert_eq!(
            parse_value(knob, "lists").unwrap(),
            Value::String("lists".into())
        );
        // Relative paths resolve against the config file's directory, so
        // the string must survive untouched.
        assert_eq!(
            parse_value(knob, "/var/lib/purge-warden/lists").unwrap(),
            Value::String("/var/lib/purge-warden/lists".into())
        );
        assert!(parse_value(knob, "").is_err());
        assert!(parse_value(knob, "   ").is_err());
    }

    /// The three bands, at their exact boundaries.
    ///
    /// `corpus_band` re-implements a guard that is private to the list
    /// manager, so these numbers mirror the manager's own band tests
    /// (ceiling 10 with 8 / 9 / 11 unique). If the daemon's thresholds
    /// ever move, this test is the tripwire that says the copy went stale.
    #[test]
    fn corpus_band_matches_the_daemon_thresholds() {
        assert_eq!(corpus_band(8, 10), Band::Quiet, "8/10 = 80% is below 90%");
        assert_eq!(corpus_band(9, 10), Band::Warn, "9/10 = exactly 90%");
        assert_eq!(corpus_band(10, 10), Band::Warn, "at the ceiling still fits");
        assert_eq!(corpus_band(11, 10), Band::Over, "past the ceiling");
        // 0 disables the guard entirely, including the counting pass —
        // it is not "a ceiling of zero that everything exceeds".
        assert_eq!(corpus_band(12_000_000, 0), Band::Disabled);
        assert_eq!(corpus_band(0, 0), Band::Disabled);
    }

    /// A ceiling large enough to overflow `u64` multiplication must not
    /// wrap into a wrong band. The daemon does this arithmetic in `u128`
    /// for the same reason.
    #[test]
    fn corpus_band_does_not_overflow_on_a_huge_ceiling() {
        assert_eq!(corpus_band(1, u64::MAX), Band::Quiet);
        assert_eq!(corpus_band(u64::MAX, u64::MAX), Band::Warn);
    }

    fn live(unique: u64, truncated: u32, total: u32, refusal: Option<CorpusRefusal>) -> LiveCorpus {
        LiveCorpus {
            unique_installed: unique,
            truncated,
            total_sources: total,
            refusal,
            freeze: None,
            // These tests are about the corpus RENDERER, which never reads
            // the cycle mark — that field exists for `lists refresh`, which
            // has to wait for a cycle to end.
            cycle: None,
        }
    }

    /// The freeze line rides the refusal block, worded exactly as
    /// `warden status` words it — one wording per fact, on both surfaces.
    #[test]
    fn the_refusal_block_says_since_when_the_corpus_is_frozen() {
        let refusal = CorpusRefusal {
            unique: 14_582_846,
            ceiling: 14_000_000,
            novel_by_source: vec![],
        };
        let mut l = live(14_564_865, 0, 14, Some(refusal));
        l.freeze = Some(crate::lists::status::CorpusFreeze {
            since: Some(time::macros::datetime!(2026-08-04 03:00:00 UTC)),
            consecutive: 9,
        });
        let lines = format_corpus_lines(14_000_000, Ok(&l)).join("\n");
        assert!(
            lines.contains(
                "  FROZEN since 2026-08-04T03:00:00Z (9 refused cycles, counted since this \
                 daemon started)."
            ),
            "{lines}"
        );
        // Without a freeze record the block is unchanged — no "since unknown".
        l.freeze = None;
        let lines = format_corpus_lines(14_000_000, Ok(&l)).join("\n");
        assert!(!lines.contains("FROZEN since"), "{lines}");
    }

    /// The daemon-down path must print no number at all.
    ///
    /// A `0` here would be indistinguishable from a real measurement of
    /// an empty corpus, which is the exact conflation this command exists
    /// to end.
    #[test]
    fn corpus_lines_without_a_daemon_state_the_gap_and_print_no_count() {
        let lines = format_corpus_lines(14_000_000, Err(Unreachable::NoSocket)).join("\n");
        assert!(lines.contains("daemon is not running"), "{lines}");
        assert!(lines.contains("<unknown"), "{lines}");
        assert!(
            !lines.contains(" 0 "),
            "a fabricated zero count must never be printed: {lines}"
        );
    }

    /// A refused connection must NOT be reported as an absent daemon:
    /// a live daemon whose peer-uid gate drops the connection (e.g.
    /// `warden` run as root) is not the same state as no daemon running,
    /// and the two need opposite actions. The assertion is on the
    /// *contradiction*, not merely on the new wording being present.
    #[test]
    fn a_refused_connection_is_not_reported_as_a_missing_daemon() {
        let lines = format_corpus_lines(14_000_000, Err(Unreachable::ConnectionRefused)).join("\n");
        assert!(
            !lines.contains("is not running"),
            "a refusal by a live daemon was reported as the daemon being down: {lines}"
        );
        assert!(lines.contains("REFUSED"), "{lines}");
        assert!(
            lines.contains("uid"),
            "the cause must be named, not just the symptom: {lines}"
        );
        assert!(
            lines.contains("runuser"),
            "an operator needs the command that works, not only the diagnosis: {lines}"
        );
        assert!(lines.contains("<unknown"), "{lines}");
    }

    /// Every state prints a cause and an action, and no two states print
    /// the same advice.
    ///
    /// Distinct text is the whole product of this split: if two arms
    /// converged the enum would be decoration, and the caller would be
    /// back to guessing.
    #[test]
    fn each_unreachable_state_gives_its_own_advice() {
        let all = [
            Unreachable::NoSocket,
            Unreachable::StaleSocket,
            Unreachable::ConnectionRefused,
            Unreachable::PermissionDenied,
            Unreachable::UnexpectedResponse,
        ];
        let mut seen: Vec<String> = Vec::new();
        for why in all {
            let lines = format_corpus_lines(14_000_000, Err(why)).join("\n");
            assert!(
                lines.contains("<unknown"),
                "{why:?} fabricated a measurement: {lines}"
            );
            assert!(
                !lines.contains(" 0 "),
                "{why:?} printed a fabricated zero: {lines}"
            );
            assert!(
                !seen.contains(&lines),
                "{why:?} renders identically to another state, so the split tells the \
                 operator nothing: {lines}"
            );
            seen.push(lines);
        }
    }

    /// The classifier reads the socket, not an error string.
    ///
    /// `NoSocket` is the one state reachable without a daemon, and it is
    /// also the default the old code applied to everything.
    #[tokio::test]
    async fn an_absent_socket_classifies_as_no_socket() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nothing-here.sock");
        assert_eq!(
            classify_unreachable(&missing).await,
            Unreachable::NoSocket,
            "a path with no socket file must be the not-running state"
        );
    }

    /// A bound, listening socket must classify as a refusal — the daemon
    /// is there. This is the peer-uid shape: connect succeeds, the
    /// request does not.
    #[tokio::test]
    async fn a_listening_socket_classifies_as_refused_not_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("live.sock");
        let _listener = tokio::net::UnixListener::bind(&path).unwrap();
        assert_eq!(
            classify_unreachable(&path).await,
            Unreachable::ConnectionRefused,
            "something accepted the connection, so the daemon is not absent"
        );
    }

    #[test]
    fn corpus_lines_name_the_band_and_the_truncation_tally() {
        let l = live(12_600_000, 3, 8, None);
        let lines = format_corpus_lines(14_000_000, Ok(&l)).join("\n");
        assert!(lines.contains("12600000"), "{lines}");
        assert!(lines.contains("at or above 90%"), "{lines}");
        assert!(lines.contains("3 of 8 hit max_entries"), "{lines}");
        assert!(lines.contains("warden blocklist show"), "{lines}");
    }

    #[test]
    fn corpus_lines_report_a_clean_truncation_tally_too() {
        let l = live(1_000_000, 0, 8, None);
        let lines = format_corpus_lines(14_000_000, Ok(&l)).join("\n");
        assert!(lines.contains("below 90%"), "{lines}");
        assert!(lines.contains("0 of 8 hit max_entries"), "{lines}");
        // The per-list remedy is noise when nothing is truncated.
        assert!(!lines.contains("warden blocklist show"), "{lines}");
    }

    /// Lowering the ceiling under an already-installed corpus arms the
    /// guard for the next cycle without any refusal on record yet.
    #[test]
    fn corpus_lines_warn_when_the_installed_corpus_already_exceeds_the_ceiling() {
        let l = live(12_000_000, 0, 8, None);
        let lines = format_corpus_lines(1_000_000, Ok(&l)).join("\n");
        assert!(lines.contains("ABOVE the ceiling"), "{lines}");
        assert!(lines.contains("will be REFUSED"), "{lines}");
    }

    #[test]
    fn corpus_lines_render_a_refused_cycle_with_its_largest_contributor() {
        let l = live(
            12_000_000,
            0,
            8,
            Some(CorpusRefusal {
                unique: 15_000_000,
                ceiling: 14_000_000,
                novel_by_source: vec![
                    ("https://lists.purge.cc/malicious.txt".into(), 4_000_000),
                    ("https://lists.purge.cc/ads.txt".into(), 100),
                ],
            }),
        );
        let lines = format_corpus_lines(14_000_000, Ok(&l)).join("\n");
        assert!(lines.contains("CORPUS REFUSED"), "{lines}");
        assert!(lines.contains("15000000"), "{lines}");
        assert!(lines.contains("previous generation"), "{lines}");
        assert!(lines.contains("malicious.txt"), "{lines}");
        assert!(lines.contains("order-dependent"), "{lines}");
        // Config and daemon agree, so no divergence note.
        assert!(!lines.contains("has not reloaded"), "{lines}");
        // The installed corpus is the PREVIOUS generation here, so its
        // band would predict what the next cycle does — and the refusal
        // on record says that prediction is already wrong. No band line
        // may appear alongside a refusal.
        assert!(
            !lines.contains("installs quietly"),
            "a band prediction must not contradict the refusal: {lines}"
        );
        assert!(!lines.contains("  band:"), "{lines}");
    }

    /// The bands above are computed from the config file's ceiling, but
    /// the daemon enforces the one it loaded. When a refusal proves those
    /// differ, say so — otherwise every band line is a statement about a
    /// number the daemon is not using.
    #[test]
    fn corpus_lines_flag_a_ceiling_the_daemon_has_not_reloaded() {
        let l = live(
            12_000_000,
            0,
            8,
            Some(CorpusRefusal {
                unique: 15_000_000,
                ceiling: 14_000_000,
                novel_by_source: vec![],
            }),
        );
        // Config was edited up to 20 M; the daemon still enforces 14 M.
        let lines = format_corpus_lines(20_000_000, Ok(&l)).join("\n");
        assert!(lines.contains("has not reloaded"), "{lines}");
        assert!(lines.contains("14000000"), "{lines}");
        assert!(lines.contains("20000000"), "{lines}");
        assert!(
            !lines.contains("  band:"),
            "no band prediction may accompany a refusal: {lines}"
        );
    }

    /// A list whose no-overlap upper bound still fits says nothing. The
    /// bound is deliberately the worst case, so `Fits` is the only arm
    /// that can promise anything, and it must not be reached by rounding.
    #[test]
    fn a_list_whose_worst_case_still_fits_is_silent() {
        assert_eq!(corpus_projection(12_000_000, 14_000_000, Some(1)), Fits);
        // Exactly at the ceiling fits: the guard refuses on `>`, not `>=`.
        assert_eq!(
            corpus_projection(13_000_000, 14_000_000, Some(1_000_000)),
            Fits
        );
    }

    /// The bound reported is `installed + entries` — the sum with no
    /// overlap assumed, which is what makes it an upper bound and not a
    /// prediction. An operator comparing it against the ceiling must get
    /// the same number the note prints.
    #[test]
    fn a_crossing_list_reports_the_no_overlap_upper_bound() {
        assert_eq!(
            corpus_projection(12_000_000, 14_000_000, Some(3_000_000)),
            MayCross {
                upper_bound: 15_000_000
            }
        );
        // One domain over is still over.
        assert_eq!(
            corpus_projection(14_000_000, 14_000_000, Some(1)),
            MayCross {
                upper_bound: 14_000_001
            }
        );
    }

    /// Both catalog spellings of "we do not know" must reach `Unknown`.
    ///
    /// `Some(0)` is the `#[serde(default)]` for an index that omits the
    /// field, not a list of no domains. Read as a count it would make
    /// every unmeasured list report `Fits` — a promise from data that
    /// does not exist. The ceiling here is non-zero on purpose: a zero
    /// one is checked first and would make both cases pass as `Disabled`.
    #[test]
    fn a_list_of_unknown_size_is_not_reported_as_fitting() {
        let reason = "no catalog metadata for this list yet";
        assert_eq!(
            corpus_projection(12_000_000, 14_000_000, None),
            Unknown { reason }
        );
        assert_eq!(
            corpus_projection(12_000_000, 14_000_000, Some(0)),
            Unknown { reason }
        );
    }

    /// `max_total_domains = 0` turns the guard off, so there is nothing
    /// to project — including when the list's size is unknown, which is
    /// why the ceiling is tested before the catalog metadata.
    #[test]
    fn a_disabled_ceiling_projects_nothing() {
        assert_eq!(corpus_projection(12_000_000, 0, Some(9_000_000)), Disabled);
        assert_eq!(corpus_projection(12_000_000, 0, None), Disabled);
    }

    /// A ceiling and a list large enough to overflow `u64` addition must
    /// report the crossing, not wrap into `Fits`. Both operands come
    /// from operator-editable inputs, and the sibling band tests already
    /// probe this file at `u64::MAX`.
    #[test]
    fn the_upper_bound_does_not_wrap() {
        assert_eq!(
            corpus_projection(u64::MAX, u64::MAX - 1, Some(u64::MAX)),
            MayCross {
                upper_bound: u64::MAX
            }
        );
    }

    /// The exact line an operator reads on a frozen corpus.
    ///
    /// Frozen deliberately: this is the only notice a refusal gets on
    /// every verb but `show`, so it must say what stopped, what the
    /// consequence is, and both ways out. `<n>` stays literal — warden
    /// does not know the operator's memory budget and must not appear to.
    #[test]
    fn the_frozen_banner_says_what_stopped_and_both_ways_out() {
        let l = live(
            12_000_000,
            0,
            8,
            Some(CorpusRefusal {
                unique: 15_012_024,
                ceiling: 14_000_000,
                novel_by_source: vec![],
            }),
        );
        assert_eq!(
            frozen_banner(&l).expect("a refusal on record must produce a banner"),
            "warning: CORPUS FROZEN — the last refresh was refused (merged corpus 15012024 \
             > max_total_domains 14000000); domains published upstream since then are NOT \
             being blocked. Run: warden status. Raise with: warden lists set \
             max_total_domains <n>, or drop a list."
        );
    }

    /// No refusal, no banner. The banner is printed by verbs that are
    /// doing something else entirely, so a healthy daemon must leave
    /// their output untouched.
    #[test]
    fn a_daemon_that_installed_its_last_cycle_prints_no_banner() {
        assert_eq!(frozen_banner(&live(12_000_000, 0, 8, None)), None);
    }

    /// The unknown-key error must hand back the valid keys, annotated.
    #[test]
    fn knob_list_is_shared_by_show_and_the_unknown_key_error() {
        let listing = knob_list();
        for k in KNOBS {
            assert!(
                listing.contains(k.key),
                "'{}' missing from knob_list",
                k.key
            );
            assert!(listing.contains(k.help), "'{}' help missing", k.key);
        }
    }
}
