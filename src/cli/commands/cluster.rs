//! `warden cluster …` — primary/secondary replication CLI.
//!
//! `token` mints the primary's bearer credential; `status` prints local
//! cluster state. `join` makes a node a working secondary: it persists
//! the `[cluster]` section AND — on a `cluster`-feature build — adds
//! the `cluster.d/*.toml` include and saves the PLAINTEXT token
//! (`crate::cluster::secret`) the poll loop sends on every heartbeat.
//! The serve endpoints and the secondary poll loop live in
//! `crate::cluster` (only built under the `cluster` feature, so it is
//! absent from a default doc build); there is still no live handshake
//! at `join` time.
//!
//! Config writes mirror the hardened path proven by `token.rs`: read the
//! master as a format-preserving document, mutate only the `[cluster]`
//! table (and, for `join`, the top-level `includes`), then
//! [`atomic_write_and_validate`] with the full v1 loader as the staging
//! validator. Every other section survives with its comments and key
//! order, and a mutation that would not load never reaches disk.
//!
//! The phrase here used to be "survives byte-for-byte" while both
//! writers went through `toml::to_string_pretty`, which deletes every
//! comment and re-sorts the file. Corrected together with the same
//! claim in `token.rs`, which this module copied it from -- one wrong
//! sentence propagated by being cited as precedent.

use std::path::Path;

use anyhow::Context;

use super::{format_config_errors, format_config_errors_flat};
use crate::auth::token::{generate_token, hash_token};
use crate::config::atomic_write::atomic_write_and_validate;
use crate::config::loader;
use crate::config::schema::ClusterRole;

/// `warden cluster token` — primary: mint the cluster bearer token.
///
/// Reuses [`generate_token`] (OsRng + SHA-256, `ps_` prefix). The
/// plaintext is printed ONCE and never persisted (the primary only
/// *verifies* incoming tokens; it never sends one). Only the SHA-256 hash
/// is written, into `[cluster] token_hash`. Does not flip `enabled`/`role`
/// — minting a credential is distinct from turning clustering on.
pub fn run_token(config_path: &Path) -> anyhow::Result<()> {
    let now = time::OffsetDateTime::now_utc();
    let _loaded = loader::load_config(config_path, now).map_err(format_config_errors)?;

    let (plaintext, hash) = generate_token();

    write_cluster_fields_to_master(
        config_path,
        &[("token_hash", Some(toml::Value::String(hash)))],
        now,
    )?;

    println!("Cluster token: {plaintext}");
    println!();
    println!("Shown once — it will NOT be displayed again. Treat it like the API token.");
    println!("Carry it to each secondary, keeping it OFF the command line. Either write it");
    println!("to a 0600 file and run there:");
    println!("  warden cluster join --peer <this-primary-api-url> --token-file <path>");
    println!("or pipe it on stdin:");
    println!("  printf %s '<token>' | warden cluster join --peer <this-primary-api-url>");
    println!();
    println!("Only its SHA-256 hash was stored in [cluster] token_hash on this node.");
    Ok(())
}

/// Resolve `--peer-cert` into the absolute path recorded in `[cluster]`.
///
/// Validated **eagerly** — existence, PEM well-formedness, absoluteness —
/// unlike the loader-side [`crate::config::schema::cluster::validate_peer_cert_path`],
/// which deliberately checks shape only. The difference is who is standing
/// there: at join time the operator can fix a typo immediately, and a config
/// written now with an unreadable pin produces a secondary that refuses every
/// poll later, with the cause hours behind the symptom.
///
/// Relative paths are made absolute against the CWD before storing. The daemon
/// reads this path with a different working directory (and often a different
/// user), so a relative entry would resolve to nothing at poll time.
///
/// `None` — the flag was omitted — is passed through, NOT an error. `join`
/// stays usable for token rotation on a node that is already pinned; the
/// missing-pin refusal belongs to the poll client, which is the one place that
/// can tell a never-pinned node from a re-join.
fn resolve_join_peer_cert(peer_cert: Option<&Path>) -> anyhow::Result<Option<String>> {
    let Some(path) = peer_cert else {
        eprintln!(
            "note: no --peer-cert given. The sync channel is authenticated by pinning the \
             primary's certificate; without one in [cluster] peer_cert this node's poll \
             loop will refuse to start. Ignore this if the pin is already set."
        );
        return Ok(None);
    };

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("resolve --peer-cert against the current directory")?
            .join(path)
    };

    let pem = std::fs::read(&absolute)
        .with_context(|| format!("--peer-cert {} cannot be read", absolute.display()))?;
    // Parse now rather than trusting the extension: an empty file, a DER blob
    // named .pem, or the primary's KEY copied by mistake all fail here instead
    // of at the first poll.
    //
    // NOT `reqwest::Certificate::from_pem` — under `rustls-tls` that stores the
    // bytes WITHOUT parsing, so it accepts literal garbage. Measured: this test
    // failed against that call before the check moved here.
    if let Err(reason) = crate::config::schema::cluster::validate_peer_cert_pem(&pem) {
        anyhow::bail!("--peer-cert {} {reason}", absolute.display());
    }

    let stored = absolute.to_string_lossy().into_owned();
    if let Err(reason) = crate::config::schema::cluster::validate_peer_cert_path(&stored) {
        anyhow::bail!("--peer-cert {reason}");
    }
    Ok(Some(stored))
}

/// Resolve the cluster bearer token off the command line:
/// `--token-file` (preferred) → stdin (piped or interactive prompt) →
/// the discouraged inline `--token`. Command-line arguments are world-readable
/// via `ps`/`/proc/<pid>/cmdline` and persist in shell history, so the inline
/// form warns; the file/stdin paths keep the secret out of argv entirely.
fn resolve_join_token(token: Option<&str>, token_file: Option<&Path>) -> anyhow::Result<String> {
    if let Some(path) = token_file {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read --token-file {}", path.display()))?;
        // Warn, never refuse: the operator may be reading from a ramdisk or a
        // deliberately shared provisioning path, and this is the route the
        // steering text calls preferred — breaking it would push them back onto
        // argv, which is worse.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(md) = std::fs::metadata(path) {
                let mode = md.permissions().mode() & 0o777;
                if mode_exposes_secret(mode) {
                    eprintln!(
                        "warning: --token-file {} is readable by other users (mode {mode:o}); \
                         chmod 600 it — the bearer token grants policy sync.",
                        path.display()
                    );
                }
            }
        }
        let t = raw.trim().to_string();
        if t.is_empty() {
            anyhow::bail!("--token-file {} is empty", path.display());
        }
        return Ok(t);
    }
    if let Some(t) = token {
        let t = t.trim();
        if t.is_empty() {
            anyhow::bail!("--token must not be empty");
        }
        eprintln!(
            "warning: --token on the command line is exposed via `ps` / /proc/<pid>/cmdline and \
             saved to shell history; prefer --token-file <path> or piping the token on stdin."
        );
        return Ok(t.to_string());
    }
    read_token_from_stdin()
}

/// Any group or other permission bit on a file holding a bearer secret. The
/// only safe mode is owner-only; `0o640` already exposes the token to a group
/// the operator may not have thought about.
#[cfg(unix)]
fn mode_exposes_secret(mode: u32) -> bool {
    mode & 0o077 != 0
}

/// Read the token from stdin — a single line, piped or typed at an interactive
/// prompt. Trimmed; empty input is an error.
fn read_token_from_stdin() -> anyhow::Result<String> {
    use std::io::{BufRead, IsTerminal, Write};
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        eprint!("Cluster token: ");
        let _ = std::io::stderr().flush();
    }
    let mut line = String::new();
    stdin
        .lock()
        .read_line(&mut line)
        .context("reading the cluster token from stdin")?;
    let t = line.trim().to_string();
    if t.is_empty() {
        anyhow::bail!(
            "no cluster token provided — pass --token-file <path>, pipe the token on stdin, \
             or use --token <t>"
        );
    }
    Ok(t)
}

/// `warden cluster join --peer <url> --token <t>` — secondary: follow a
/// primary.
///
/// Writes the `[cluster]` section (`enabled = true`, `role = "secondary"`,
/// `peer`, `token_hash`); on a `cluster`-feature build it also adds the
/// `cluster.d/*.toml` include and saves the plaintext token. The token is
/// hashed with [`hash_token`] before storage. There is no live handshake
/// against the primary at join time — `join` only persists config (the
/// staging validator confirms it loads); the poll loop performs the
/// first real contact once the daemon (re)starts.
///
/// The bearer token is resolved off the command line: from
/// `--token-file` (preferred), else stdin (piped or an interactive prompt),
/// else the discouraged inline `--token` (with a `ps`/history-exposure warning).
/// `cluster join` with no pin supplied — delegates to [`run_join_pinned`].
///
/// Kept as the four-argument form deliberately. Sixteen call sites use it,
/// one of them in `init`'s scaffold test, and none of them are expressing
/// "clear the pin" — they are expressing "this join is not about the pin".
/// Passing `None` through preserves whatever `peer_cert` the master already
/// carries; it never clears one.
pub fn run_join(
    config_path: &Path,
    peer: &str,
    token: Option<&str>,
    token_file: Option<&Path>,
) -> anyhow::Result<()> {
    run_join_pinned(config_path, peer, token, token_file, None)
}

/// [`run_join`] plus `--peer-cert`, the certificate this secondary pins for
/// the primary's API listener.
pub fn run_join_pinned(
    config_path: &Path,
    peer: &str,
    token: Option<&str>,
    token_file: Option<&Path>,
    peer_cert: Option<&Path>,
) -> anyhow::Result<()> {
    // Refuse before anything is persisted. See `ensure_can_join`.
    ensure_can_join()?;

    let now = time::OffsetDateTime::now_utc();
    // No pre-load: a policy-free secondary master does not validate
    // until `enabled = true` is written, and writing it is what `join`
    // does — a pre-load guard here would deadlock a node that could not
    // join because it had not joined.
    //
    // Nothing is lost. `write_cluster_fields_to_master` parses the raw master
    // itself, and `atomic_write_and_validate` validates the POST state with
    // the full loader, so any pre-existing defect survives into that state and
    // fails there. The only errors the post state does NOT inherit are exactly
    // the ones joining fixes — which is the semantics wanted, for free and
    // without an error-string allowlist. `run_leave` has always worked this
    // way (raw read, no pre-load); this makes the two siblings consistent
    // rather than adding a third pattern.
    //
    // `run_token` keeps its pre-load on purpose: minting is a PRIMARY
    // operation, and failing it on an unjoined secondary is correct.

    // Refuse a policy-carrying master HERE, before anything is
    // written. The permanent guard in the validator would catch it too, but
    // only on the staged-write path, where the provenance map names the
    // STAGING TEMP FILE: a remedy pointing at a path that no longer exists
    // when the operator reads it. This reads the real master and names it.
    ensure_master_carries_no_policy(config_path)?;

    let peer = peer.trim();
    // A secondary sends the plaintext cluster token to `peer` on every
    // poll, so reject a non-https (or non-loopback-http) peer at join time —
    // before it is persisted — mirroring the config validator's defence in depth.
    if let Err(reason) = crate::config::schema::cluster::validate_peer_url(peer) {
        anyhow::bail!("--peer {reason}");
    }
    // The pin is what authenticates the channel. Resolve it BEFORE the
    // token prompt so a bad path fails without the operator having typed a
    // secret, and before anything is persisted.
    let peer_cert = resolve_join_peer_cert(peer_cert)?;

    let token = resolve_join_token(token, token_file)?;
    let token = token.as_str();
    let hash = hash_token(token);

    let mut fields: Vec<(&str, Option<toml::Value>)> = vec![
        ("enabled", Some(toml::Value::Boolean(true))),
        ("role", Some(toml::Value::String("secondary".into()))),
        ("peer", Some(toml::Value::String(peer.to_string()))),
        ("token_hash", Some(toml::Value::String(hash))),
    ];
    // Only written when the operator supplied one. `None` in this vector means
    // REMOVE (`write_cluster_fields_to_master`'s match arm), so passing the
    // flag's absence through would silently DELETE an existing pin — an
    // operator re-running `join` to rotate the token would un-pin the node and
    // the next poll would refuse. Absence preserves; only an explicit
    // `--peer-cert` writes.
    if let Some(path) = peer_cert {
        fields.push(("peer_cert", Some(toml::Value::String(path))));
    }

    write_cluster_fields_to_master(config_path, &fields, now)?;

    // Make this node a working secondary. Both steps are gated on the
    // `cluster` feature — a feature-less build refuses upstream in
    // `ensure_can_join`, so these fields are never written there.
    //   (a) include the sync-owned `cluster.d/` drop-in so the loader picks up
    //       applied policy bundles (wildcard zero-match is allowed, so it loads
    //       cleanly before the first bundle lands);
    //   (b) persist the PLAINTEXT token so the poll loop can authenticate
    //       against the primary's stored hash.
    #[cfg(feature = "cluster")]
    {
        ensure_cluster_include(config_path, now)?;
        let token_path = crate::cluster::secret::save_cluster_token(config_path, token)
            .context("persisting the plaintext cluster token")?;
        tracing::debug!(path = %token_path.display(), "cluster: saved plaintext token for poll loop");
    }

    println!("Joined cluster as a secondary.");
    println!("  peer: {peer}");
    println!("  role: secondary");
    println!();
    #[cfg(feature = "cluster")]
    {
        // NOT "policy + domain map": the secondary downloads its own
        // lists from the replicated policy and derives the Tier-1 bits
        // itself.
        println!("(Re)start the daemon to begin syncing: it will poll the primary every");
        println!("poll_interval_secs, converge on its policy, and download its own lists");
        println!("from it. `warden cluster status`.");
    }
    Ok(())
}

/// Refuse `warden cluster join` on a build that cannot act as a secondary.
///
/// Two cfg'd definitions rather than a `#[cfg]` block inside [`run_join`]: an
/// unconditional `bail!` in the body would make the rest of the function
/// unreachable on a feature-less build, and `unreachable_code` is denied here.
///
/// **Why this has to run before the write.** Persisting
/// `cluster.enabled = true` before checking the `cluster` feature is
/// destructive on a feature-less binary: [`super::start::check_cluster_build`]
/// refuses to start the daemon while `cluster.enabled`, and there is no
/// `warden cluster leave` to undo it. On a stock build (`[features]` has
/// no `default` key, so `cluster` is off) that ordering would take DNS
/// down and leave hand-editing TOML as the only way back.
#[cfg(not(feature = "cluster"))]
fn ensure_can_join() -> anyhow::Result<()> {
    anyhow::bail!(
        "this binary was built without the `cluster` feature, so it cannot run as a secondary.\n\
         Joining would set cluster.enabled = true, after which the daemon refuses to start — \
         and there is no `warden cluster leave` to undo it.\n\
         Nothing has been written. Rebuild with `--features cluster` to join a cluster."
    )
}

/// Feature-enabled counterpart of [`ensure_can_join`] — this build can be a secondary.
#[cfg(feature = "cluster")]
fn ensure_can_join() -> anyhow::Result<()> {
    Ok(())
}

/// Refuse to join when the master carries policy of its own, before any
/// write.
///
/// The permanent enforcement is the validator's
/// `CLUSTER_SECONDARY_MASTER_CARRIES_POLICY`, which fires at every load and is
/// the rule that actually holds; a join-time check does not stop an operator
/// adding a device a month later. This is the *early, readable* half —
/// one does not replace the other.
///
/// It exists as its own check rather than as "the staged write will catch it"
/// for one concrete reason: on the staged-write path the provenance map names
/// the **staging temp file**, so the remedy — "move these sections out of" —
/// points at a path that has already been unlinked by the time the operator
/// reads it. Reading the raw master here makes the instruction executable.
///
/// Scans with `replicated_policy_outside_the_drop_in`, the same function the
/// validator uses. Deliberately NOT a second implementation of the rule.
///
/// A master that will not parse is left to the writer below, which reports
/// TOML errors with more context than this check could.
fn ensure_master_carries_no_policy(config_path: &Path) -> anyhow::Result<()> {
    let Ok(raw) = std::fs::read_to_string(config_path) else {
        return Ok(());
    };
    let Ok(provenance) = loader::provenance_of_file(config_path, &raw) else {
        return Ok(());
    };
    let offenders =
        crate::config::schema::validator::replicated_policy_outside_the_drop_in(&provenance);
    if offenders.is_empty() {
        return Ok(());
    }
    // Listed as `section (line N)`, not through `describe_policy_origins`:
    // that helper repeats the file on every entry, which is right for the
    // validator (offenders can come from different included files) and pure
    // noise here, where the header has already named the single file they all
    // came from.
    let listed = offenders
        .iter()
        .map(|o| format!("  {} (line {})", o.section, o.line))
        .collect::<Vec<_>>()
        .join("\n");
    anyhow::bail!(
        "cannot join: this node's config carries policy of its own, and a secondary's \
         policy comes from the primary. The loader would MERGE the two — concatenating \
         lists SILENTLY — leaving this node filtering more than the primary does while \
         sync reports success.\n\
         \n\
         Move these sections out of {}:\n{}\n\
         \n\
         Nothing has been written.",
        config_path.display(),
        listed,
    )
}

/// The `[cluster]` keys that make a node a cluster member — exactly the
/// membership fields [`run_join`] writes, and exactly what [`run_leave`]
/// removes. `token_hash` is deliberately absent: it is a credential, and
/// leaving a cluster does not revoke one.
const MEMBERSHIP_FIELDS: [&str; 3] = ["enabled", "role", "peer"];

/// The sync-owned drop-in glob `join` adds to the master's `includes` on a
/// `cluster` build. Named here (ungated) because [`run_leave`] must be able to
/// SPOT it on any build — a config carrying it can be copied onto a stock box.
const CLUSTER_INCLUDE: &str = "cluster.d/*.toml";

/// Refusal when `leave` would clear membership on a node that has no resolver
/// of its own — a joined-but-never-synced secondary. Frozen.
pub const LEAVE_WOULD_STRAND_NODE: &str =
    "cluster: leaving would leave this node with no upstream resolver of its own. \
     It joined but has never synced, so no policy bundle has supplied `upstream.servers`, \
     and a secondary's own master is forbidden from carrying one.";

/// Refusal when `--upstream` is passed to `leave` on a node that already
/// resolves one. Frozen.
///
/// The flag replaces `upstream.servers` wholesale, so on a node that is fine it
/// can only destroy — and a multi-server list would lose every entry but the
/// one typed. Refusing is the difference between a flag that repairs a
/// stranded node and a flag that quietly rewrites a working one.
pub const LEAVE_UPSTREAM_NOT_NEEDED: &str =
    "cluster: this node already resolves an upstream of its own, so `leave` does not need \
     `--upstream`.";

/// What `leave` can tell about this node's own resolver, before writing.
///
/// **Three states, not two, and the third is why.** An earlier version of this
/// returned `bool`, which conflated *"it loads and has an upstream"* with
/// *"it does not load, so I cannot tell"* — and those want opposite treatment
/// for `--upstream`: refuse the flag in the first (it would silently replace a
/// working resolver list), allow it in the second (it may be the repair).
#[derive(Debug, PartialEq, Eq)]
enum OwnUpstream {
    /// Loads, and `upstream.servers` is empty — the joined-but-never-synced
    /// shape. Clearing membership drops the exemption a cluster secondary
    /// gets from the empty-upstream check, and that same emptiness
    /// becomes a hard `UPSTREAM_SERVERS_EMPTY`.
    WouldStrand,
    /// Loads and already resolves a non-empty `upstream.servers`, whether from
    /// the master or from a synced bundle the include keeps.
    Present,
    /// Does not load, so nothing can be concluded. `run_leave` must rescue
    /// configs that do NOT load — that is the verb's reason to exist —
    /// and `leave_clears_membership_on_a_stock_build` pins it. This arm
    /// therefore changes no behaviour: the staged write decides, exactly
    /// as before.
    Unknown,
}

/// Probe the node's own resolver. The load is deliberately **non-fatal** — see
/// [`OwnUpstream::Unknown`].
fn own_upstream(config_path: &Path) -> OwnUpstream {
    let now = time::OffsetDateTime::now_utc();
    match loader::load_config(config_path, now) {
        Ok(loaded) if loaded.config.upstream.servers.is_empty() => OwnUpstream::WouldStrand,
        Ok(_) => OwnUpstream::Present,
        Err(_) => OwnUpstream::Unknown,
    }
}

/// `warden cluster leave` — undo a join; make this node standalone again.
///
/// Removes `MEMBERSHIP_FIELDS` from `[cluster]`, the exact inverse of what
/// [`run_join`] inserts. Removal rather than `enabled = false`: every
/// [`crate::config::schema::ClusterConfig`] field carries a serde default, so
/// an absent key IS the inert default, and the master ends up as it was
/// before the join instead of carrying settings-looking cruft.
///
/// **Deliberately NOT feature-gated** (unlike [`run_join`], see
/// `ensure_can_join`). The operator this verb exists for is holding a STOCK
/// binary and a config that says `enabled = true` — the combination
/// `start::check_cluster_build` refuses to boot. Gating `leave` on the
/// `cluster` feature would leave exactly that operator with no way back,
/// which is the hole this closes. A stock box reaches the joined state by a
/// hand-edit, by a config copied off another machine, or from a binary older
/// than that guard.
///
/// **Deliberately does not pre-load the config**, unlike every other verb in
/// this file. Its inputs are by definition configs that may FAIL validation —
/// `enabled = true` without a `token_hash`, or `role = "secondary"` without a
/// `peer`, both hard errors from the validator's `check_cluster`. A
/// `load_config` guard up front would make `leave` refuse precisely the
/// configs it is meant to repair. Nothing is lost: the staging validator
/// inside `write_cluster_fields_to_master` proves the RESULT loads, so a
/// mutation that is still broken never reaches disk and the file is left
/// byte-identical.
///
/// A no-op when the node is not a member: prints so and returns without
/// rewriting the file.
pub fn run_leave(config_path: &Path, upstream: Option<&str>) -> anyhow::Result<()> {
    let raw = std::fs::read_to_string(config_path)
        .with_context(|| format!("cannot read {}", config_path.display()))?;
    let value: toml::Value = raw
        .parse()
        .with_context(|| format!("cannot parse {} as TOML", config_path.display()))?;

    // Read membership off the RAW master, not a loaded config: the master is
    // the file we would rewrite, and a broken config never loads at all.
    let cluster = value.get("cluster").and_then(toml::Value::as_table);

    if !cluster.is_some_and(asserts_membership) {
        bail_if_an_include_holds_membership(config_path)?;
        println!("cluster: not a member — nothing to leave.");
        println!("{} was not modified.", config_path.display());
        return Ok(());
    }

    match (upstream, own_upstream(config_path)) {
        (None, OwnUpstream::WouldStrand) => {
            anyhow::bail!(
                "{LEAVE_WOULD_STRAND_NODE}\n\
                 Re-run as `warden cluster leave --upstream <addr:port>` to clear membership \
                 and set this node's own resolver in the same write.\n\
                 Nothing has been written; {} is unchanged.",
                config_path.display()
            );
        }
        // The flag REPLACES `upstream.servers` wholesale. On a node that
        // already resolves one — a synced secondary whose bundle supplies it,
        // or a primary — that silently discards a working list, and a
        // multi-server list loses every entry but the one typed. It exists for
        // the stranding case; refuse it where it can only destroy.
        (Some(u), OwnUpstream::Present) => {
            anyhow::bail!(
                "{LEAVE_UPSTREAM_NOT_NEEDED}\n\
                 Passing --upstream {u} would REPLACE that list, not add to it.\n\
                 Re-run `warden cluster leave` without the flag.\n\
                 Nothing has been written; {} is unchanged.",
                config_path.display()
            );
        }
        // `Unknown` takes the unchanged path in BOTH columns: the config does
        // not load, so neither refusal can be justified, and `leave`'s rescue
        // role outranks a guess. With the flag it may even be the repair.
        _ => {}
    }

    // Report only the keys that were really there; clear all three regardless,
    // so a half-written section can't survive as `enabled = false` + a stale peer.
    let cleared: Vec<&str> = MEMBERSHIP_FIELDS
        .iter()
        .copied()
        .filter(|k| cluster.is_some_and(|t| t.contains_key(*k)))
        .collect();
    let kept_token = cluster.is_some_and(|t| t.contains_key("token_hash"));
    let kept_include = value
        .get("includes")
        .and_then(toml::Value::as_array)
        .is_some_and(|a| a.iter().any(|v| v.as_str() == Some(CLUSTER_INCLUDE)));

    // On failure with no flag, point at the flag. The probe above answers
    // `Unknown` for a config that does not load, and that is exactly the
    // operator whose post-leave state may ALSO lack an upstream — they would
    // otherwise get a bare `UPSTREAM_SERVERS_EMPTY` from a verb they ran about
    // cluster membership, with no hint that `leave` can fix it in one write.
    //
    // Worded as a possibility, not a diagnosis: we genuinely do not know why
    // the staged write failed, and classifying it by matching the validator's
    // error text is the error-string allowlist this module has twice refused
    // to grow.
    write_cluster_fields_to_master_with_upstream(
        config_path,
        &MEMBERSHIP_FIELDS.map(|k| (k, None::<toml::Value>)),
        upstream,
        time::OffsetDateTime::now_utc(),
    )
    .map_err(|e| {
        if upstream.is_some() {
            return e;
        }
        anyhow::anyhow!(
            "{e}\n\n\
             If this node has no upstream resolver of its own, \
             `warden cluster leave --upstream <addr:port>` clears membership and sets one \
             in the same write — neither order works alone."
        )
    })?;

    println!("Left the cluster — this node is standalone again.");
    println!("  cleared: {}", cleared.join(", "));
    if let Some(u) = upstream {
        println!("  upstream.servers set to: {u}");
    }
    println!();
    println!("(Re)start the daemon for this to take effect.");
    if kept_token {
        println!();
        println!("The stored cluster token hash was kept — leaving does not revoke a");
        println!("credential. Mint a fresh one with `warden cluster token` if this node");
        println!("is not rejoining.");
    }
    if kept_include {
        println!();
        println!("Note: `includes` still lists {CLUSTER_INCLUDE}, so policy synced from the");
        println!("primary is still applied. Remove that entry, and the directory it points");
        println!("at, once you have restored this node's own settings — doing it here could");
        println!("strip the only definition of a profile the config still references.");
    }
    Ok(())
}

/// Refuse the no-op when the master is clean but an INCLUDE turns clustering
/// on, instead of reporting a false all-clear.
///
/// `[cluster]` is a singleton section, so a hand-edit or a copied drop-in can
/// put it in an included file rather than the master. `run_leave` only ever
/// rewrites the master, so it would print "not a member" and exit 0 while the
/// daemon still refuses to boot — the same shape of dead end this verb exists
/// to remove. Name the offending file instead, and write nothing.
///
/// Read-only, and only conclusive on a config that LOADS: when it does not, we
/// cannot see the merged view, so fall through to the plain no-op rather than
/// guess. A master that has its OWN `[cluster]` never reaches here — this runs
/// only after the master was found clean, and a second definition of a
/// singleton is a hard duplicate error anyway.
fn bail_if_an_include_holds_membership(config_path: &Path) -> anyhow::Result<()> {
    let Ok(loaded) = loader::load_config(config_path, time::OffsetDateTime::now_utc()) else {
        return Ok(());
    };
    let c = &loaded.config.cluster;
    if !c.enabled && c.role != ClusterRole::Secondary {
        return Ok(());
    }
    let source = loaded
        .provenance
        .get("cluster")
        .map(|(file, line)| format!("{}:{line}", file.display()))
        .unwrap_or_else(|| "one of the included files".to_string());
    anyhow::bail!(
        "clustering is on, but `[cluster]` is not in {} — it comes from {source}.\n\
         `cluster leave` only rewrites the master config, so it has changed nothing. \
         Remove the `[cluster]` section from that file by hand.",
        config_path.display()
    )
}

/// Does this raw `[cluster]` table claim membership of a cluster?
///
/// Any one of: clustering switched on, the secondary role, or a leftover peer.
/// `role`/`peer` count on their own because the validator rejects
/// `role = "secondary"` without a valid `peer` *regardless of `enabled`* — so a
/// node can be unbootable on role alone, and `leave` has to reach that state.
fn asserts_membership(cluster: &toml::value::Table) -> bool {
    let enabled = cluster.get("enabled").and_then(toml::Value::as_bool) == Some(true);
    let secondary = cluster.get("role").and_then(toml::Value::as_str) == Some("secondary");
    let peer = cluster
        .get("peer")
        .and_then(toml::Value::as_str)
        .is_some_and(|p| !p.trim().is_empty());
    enabled || secondary || peer
}

/// `warden cluster status` — print this node's cluster state.
///
/// On a `cluster`-feature build it first asks the RUNNING daemon for
/// the live view (peer roster + sync telemetry) over IPC; if the daemon is
/// unreachable or clustering is off it falls back to the on-disk config
/// summary. A feature-less binary can never run a live cluster, so it always
/// prints the config summary. The token hash value is never printed — only
/// whether one is configured.
pub async fn run_status(socket_path: &Path, config_path: &Path) -> anyhow::Result<()> {
    #[cfg(feature = "cluster")]
    {
        match fetch_cluster_status(socket_path).await {
            Ok(dto) if dto.enabled => return print_live_status(&dto),
            // Daemon reachable but clustering off → on-disk summary.
            Ok(_) => {}
            // Daemon unreachable / IPC error → fall back, but say why.
            Err(e) => {
                eprintln!("(live cluster status unavailable: {e}; showing on-disk config)");
            }
        }
    }
    let _ = socket_path;
    print_config_status(config_path)
}

/// Print the on-disk `[cluster]` config summary — no daemon contact. The
/// always-available fallback, and the only output on a feature-less build.
fn print_config_status(config_path: &Path) -> anyhow::Result<()> {
    let now = time::OffsetDateTime::now_utc();
    let loaded = loader::load_config(config_path, now).map_err(format_config_errors)?;
    let c = &loaded.config.cluster;

    if !c.enabled {
        println!("cluster: disabled");
        println!();
        println!("This node is standalone. To form a cluster:");
        println!("  • primary:   warden cluster token   (then enable [cluster])");
        println!("  • secondary: warden cluster join --peer <url> --token <t>");
        return Ok(());
    }

    let role = match c.role {
        ClusterRole::Primary => "primary",
        ClusterRole::Secondary => "secondary",
    };
    let token_state = if c
        .token_hash
        .as_deref()
        .is_some_and(|h| !h.trim().is_empty())
    {
        "configured"
    } else {
        "MISSING"
    };

    println!("cluster: enabled");
    println!("  role:     {role}");
    if let Some(name) = &c.node_name {
        println!("  name:     {name}");
    }
    match &c.peer {
        Some(p) => println!("  peer:     {p}"),
        None => println!("  peer:     (none)"),
    }
    println!("  priority: {}", c.priority);
    println!("  token:    {token_state}");
    println!("  poll:     {}s", c.poll_interval_secs);
    if !c.allow_peer.is_empty() {
        println!("  allow_peer: {}", c.allow_peer.join(", "));
    }
    println!();
    println!("Live status unavailable (daemon not running, or built without --features cluster).");
    Ok(())
}

/// Ask the running daemon for the live cluster view over IPC.
#[cfg(feature = "cluster")]
async fn fetch_cluster_status(
    socket_path: &Path,
) -> anyhow::Result<crate::ipc::protocol::ClusterStatusDto> {
    use crate::ipc::protocol::{IpcCommand, IpcResponse};
    match crate::ipc::socket_client::send_command(socket_path, &IpcCommand::ClusterStatus).await? {
        IpcResponse::ClusterStatus { status } => Ok(status),
        IpcResponse::Error { message } => anyhow::bail!("{message}"),
        other => anyhow::bail!("unexpected response {other:?}"),
    }
}

/// Render the live view: a roster table on a primary, a sync-state block on a
/// secondary.
#[cfg(feature = "cluster")]
fn print_live_status(dto: &crate::ipc::protocol::ClusterStatusDto) -> anyhow::Result<()> {
    if dto.role == "secondary" {
        println!("cluster: secondary");
        match &dto.peer {
            Some(p) => println!("  peer:       {p}"),
            None => println!("  peer:       (none)"),
        }
        let sync = match dto.last_sync_secs {
            Some(s) => format!("{s}s ago"),
            None => "never".into(),
        };
        println!("  last sync:  {sync}");
        println!("  converged:  {}", if dto.converged { "yes" } else { "no" });
        println!("  applied:    config {}", short_hash(&dto.config_hash));
        match (dto.last_poll_ok, &dto.last_error) {
            (true, _) => println!("  last poll:  ok"),
            (false, Some(e)) => println!("  last poll:  FAILED — {e}"),
            (false, None) => println!("  last poll:  FAILED"),
        }
        return Ok(());
    }

    // Primary: generations + a roster table (self-row first, then peers).
    println!("cluster: primary");
    println!(
        "  config gen {} ({})",
        dto.config_generation,
        short_hash(&dto.config_hash),
    );
    println!();
    if dto.roster.is_empty() {
        println!("  no nodes yet (no heartbeats received).");
        return Ok(());
    }
    println!(
        "  {:<16} {:<5} {:<7} {:>7} {:>7} {:>7}",
        "NODE", "ROLE", "STATUS", "QPS", "BLOCK%", "SHARE%"
    );
    for r in &dto.roster {
        let role = if r.is_self { "self" } else { "peer" };
        if r.online {
            println!(
                "  {:<16} {:<5} {:<7} {:>7.1} {:>7.1} {:>7.1}",
                truncate(&r.name, 16),
                role,
                "online",
                r.qps,
                r.blocked_pct,
                r.share_pct,
            );
        } else {
            // Offline: the cached rates are stale — show dashes, not numbers.
            println!(
                "  {:<16} {:<5} {:<7} {:>7} {:>7} {:>7}",
                truncate(&r.name, 16),
                role,
                "STALE",
                "—",
                "—",
                "—",
            );
        }
    }
    Ok(())
}

/// First 10 chars of a content hash + ellipsis; `—` when empty.
#[cfg(feature = "cluster")]
fn short_hash(h: &str) -> String {
    if h.is_empty() {
        "—".into()
    } else if h.len() > 10 {
        format!("{}…", &h[..10])
    } else {
        h.to_string()
    }
}

/// Clip a roster label to `max` display chars (node names + IPs are ASCII in
/// practice; char-based so a stray multibyte name can't panic).
#[cfg(feature = "cluster")]
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() > max {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    } else {
        s.to_string()
    }
}

/// Apply `fields` to the `[cluster]` table of the master file and write it
/// back atomically, validating the whole tree through the v1 loader.
/// Mirrors `token.rs::write_token_hash_to_master`.
///
/// `Some(v)` inserts (or overwrites) the key; `None` REMOVES it. Removal is
/// what [`run_leave`] needs: every `[cluster]` field carries a serde default,
/// so deleting a key restores its inert default exactly — without leaving
/// `enabled = false` cruft behind that reads like a deliberate setting.
fn write_cluster_fields_to_master(
    config_path: &Path,
    fields: &[(&str, Option<toml::Value>)],
    now: time::OffsetDateTime,
) -> anyhow::Result<()> {
    write_cluster_fields_to_master_with_upstream(config_path, fields, None, now)
}

/// [`write_cluster_fields_to_master`] plus, optionally, this node's own
/// `upstream.servers`, mutated into the SAME staged write.
///
/// The two cannot be separate writes and that is the whole point. On a
/// never-synced secondary, clearing membership drops the cluster
/// secondary's exemption from the empty-upstream check while no
/// `[upstream]` exists yet — and adding `[upstream]` first is refused by
/// `CLUSTER_SECONDARY_MASTER_CARRIES_POLICY` while membership still stands.
/// Either order fails; only the simultaneous one is representable, because
/// `atomic_write_and_validate` validates the post state and nothing in
/// between.
fn write_cluster_fields_to_master_with_upstream(
    config_path: &Path,
    fields: &[(&str, Option<toml::Value>)],
    upstream: Option<&str>,
    now: time::OffsetDateTime,
) -> anyhow::Result<()> {
    write_master_sections(config_path, fields, &[], upstream, now)
}

/// [`write_cluster_fields_to_master`] plus `[api]` fields, mutated into the
/// SAME staged write (S4).
///
/// Third instance of the same argument, and the sharpest one.
/// `check_api` turns on **four** rules the instant `api.enabled = true`:
/// a non-blank `token_hash`, both halves of the TLS pair on a non-loopback
/// `listen`, and never a half pair. `atomic_write_and_validate` validates the
/// POST state and nothing in between, so `[cluster]` first and `[api]` second
/// — or the reverse — passes through a document the loader rejects, and the
/// verb fails half-applied. Only the simultaneous write is representable.
fn write_cluster_and_api_fields_to_master(
    config_path: &Path,
    cluster_fields: &[(&str, Option<toml::Value>)],
    api_fields: &[(&str, Option<toml::Value>)],
    now: time::OffsetDateTime,
) -> anyhow::Result<()> {
    write_master_sections(config_path, cluster_fields, api_fields, None, now)
}

/// The one staged, validated master write the three wrappers above share.
///
/// Kept private and reached only through them: every caller expresses its
/// intent in its own name, and none of them has to restate why the sections
/// travel together.
fn write_master_sections(
    config_path: &Path,
    cluster_fields: &[(&str, Option<toml::Value>)],
    api_fields: &[(&str, Option<toml::Value>)],
    upstream: Option<&str>,
    now: time::OffsetDateTime,
) -> anyhow::Result<()> {
    let content = super::toml_write::edit_document(config_path, |doc| {
        if let Some(u) = upstream {
            let mut servers = toml_edit::Array::new();
            servers.push(u);
            super::toml_write::table_mut(doc, "upstream")?
                .insert("servers", toml_edit::value(servers));
        }
        for (section, fields) in [("cluster", cluster_fields), ("api", api_fields)] {
            if fields.is_empty() {
                // Not a micro-optimisation: `table_mut` CREATES the table, so
                // an unconditional pass would add an empty `[api]` header to
                // every `join` and `leave` write.
                continue;
            }
            let table = super::toml_write::table_mut(doc, section)?;
            for (k, v) in fields {
                match v {
                    Some(v) => {
                        table.insert(k, super::toml_write::value_to_item(v)?);
                    }
                    None => {
                        table.remove(k);
                    }
                }
            }
        }
        Ok(())
    })?;

    atomic_write_and_validate(
        config_path,
        &content,
        |staged: &Path| -> Result<(), String> {
            loader::load_config(staged, now)
                .map(|_| ())
                .map_err(|e| format_config_errors_flat(&e))
        },
    )
    .map_err(|e| anyhow::anyhow!("{e}"))
}

/// `warden cluster enable --role primary` — S4: turn a standalone node into a
/// cluster primary and mint the TLS material the secondary will pin.
///
/// # Why this writes `[api]` too, and why it is ONE write
///
/// The sync channel IS the API server: the cluster routes mount on it. So a
/// primary needs `api.enabled = true` on an address its secondary can reach,
/// and `check_api` makes four rules bite the instant that flips — a non-blank
/// `token_hash`, both halves of the TLS pair on a non-loopback `listen`, and
/// never a half pair. `atomic_write_and_validate` validates the POST state and
/// nothing in between, so any split write passes through a document the loader
/// rejects. See [`write_cluster_and_api_fields_to_master`].
///
/// # Why the pre-state is necessarily `api.enabled = false`
///
/// Worth stating because the S3 plan got it backwards and had this verb
/// *require* the API already on. It cannot be: `enabled = true` on a
/// non-loopback listen does not load without a cert, and nothing else mints
/// one — so "already enabled" describes no node that needs this verb. The
/// verb sets it.
///
/// # Refusals write NOTHING
///
/// Seven of them (R1-R7), all evaluated before the first byte reaches disk,
/// each pinned by a frozen const in [`crate::config::schema::cluster`]. The
/// tests assert both that the master is byte-identical afterwards *and* which
/// const came back — byte-identity alone is satisfied by any refusal, so on
/// its own it cannot tell a test that pinned its rule from one that went green
/// on an earlier check.
pub fn run_enable(
    config_path: &Path,
    role: crate::cli::EnableRole,
    sans: &[String],
    api_listen: Option<std::net::SocketAddr>,
    validity_days: u32,
) -> anyhow::Result<()> {
    use crate::config::schema::cluster as cluster_schema;

    // R1 first, and deliberately ahead of the build guard: `--role secondary`
    // is the same mistake on every build, and the answer to it (`cluster
    // join`) is more useful than "rebuild with --features cluster".
    if role == crate::cli::EnableRole::Secondary {
        anyhow::bail!(cluster_schema::CLUSTER_ENABLE_ROLE_SECONDARY_USE_JOIN);
    }
    // Not one of R1-R7 — see `ensure_can_enable`. It has to run before the
    // write for the cli-h1 reason, and here the trap is worse than it was for
    // `join`: a retry after rebuilding hits R6, and there is no `--force`.
    ensure_can_enable()?;

    let now = time::OffsetDateTime::now_utc();
    // Pre-load, unlike `run_join`. A would-be PRIMARY's master is an ordinary
    // standalone config that already loads — the §5.3 deadlock that forced
    // `join` to read raw is a SECONDARY-only condition. Same reasoning keeps
    // `run_token`'s pre-load. It also buys the parsed `api.listen`, defaults
    // applied, which R3 needs and a raw TOML read cannot give.
    let loaded = loader::load_config(config_path, now).map_err(format_load_errs)?;
    let cluster = &loaded.config.cluster;
    let api = &loaded.config.api;

    // R2 — the credential must exist before the door opens.
    if !is_set(cluster.token_hash.as_deref()) {
        anyhow::bail!(cluster_schema::CLUSTER_ENABLE_REQUIRES_TOKEN_HASH);
    }

    // R3 — the RESULTING listen, not the configured one: `--api-listen` is
    // what makes a fresh node (default `127.0.0.1:8053`) reachable at all.
    let listen = api_listen.unwrap_or(api.listen);
    if listen.ip().is_loopback() {
        anyhow::bail!(cluster_schema::CLUSTER_ENABLE_LISTEN_IS_LOOPBACK);
    }

    // R4 — without it the post state is refused by
    // `API_ENABLED_REQUIRES_TOKEN_HASH`, i.e. the verb would build a master
    // the daemon cannot start from and fail late, in the staged write, naming
    // a temp path that is unlinked by the time the operator reads the error.
    if !is_set(api.token_hash.as_deref()) {
        anyhow::bail!(cluster_schema::CLUSTER_ENABLE_REQUIRES_API_TOKEN_HASH);
    }

    // Either half counts as "the operator brought their own". A lone
    // `tls_cert` is loadable today only because `check_api` is inert while
    // `api.enabled = false`; treating it as absent would mint over half a
    // pair the operator configured on purpose.
    let has_own_cert = api.tls_cert.is_some() || api.tls_key.is_some();

    if has_own_cert && !sans.is_empty() {
        // R7 — the certificate would be written and never used.
        anyhow::bail!(cluster_schema::CLUSTER_ENABLE_SAN_WITH_EXISTING_CERT);
    }
    if !has_own_cert && sans.is_empty() {
        // R5.
        anyhow::bail!(cluster_schema::CLUSTER_ENABLE_REQUIRES_SAN);
    }

    let dir = config_dir(config_path)?;
    let crt = dir.join("api.crt");
    let key = dir.join("api.key");

    let minted = if has_own_cert {
        // R7's mirror, and NOT a refusal: existing material plus no `--san`
        // means "use what I already have", a supported way to run a primary.
        // Nothing is generated and `api.tls_cert` is left exactly as it is.
        None
    } else {
        // R6 — checked here so the message can name both paths before
        // anything is minted. `create_new(true)` below re-checks it
        // atomically; this one exists for the diagnostic, not the guarantee.
        if crt.exists() || key.exists() {
            anyhow::bail!(cluster_schema::format_cluster_enable_cert_already_exists(
                &[crt.clone(), key.clone()]
            ));
        }
        Some(mint_primary_cert(sans, validity_days, now)?)
    };

    let cluster_fields: [(&str, Option<toml::Value>); 2] = [
        ("enabled", Some(toml::Value::Boolean(true))),
        ("role", Some(toml::Value::String("primary".into()))),
    ];
    let mut api_fields: Vec<(&str, Option<toml::Value>)> =
        vec![("enabled", Some(toml::Value::Boolean(true)))];
    if api_listen.is_some() {
        // Only when the operator asked. Absence must preserve whatever the
        // master already carries — the same rule `join` follows for
        // `peer_cert`, and for the same reason: a flag's absence is not an
        // instruction to overwrite.
        api_fields.push(("listen", Some(toml::Value::String(listen.to_string()))));
    }
    if minted.is_some() {
        api_fields.push((
            "tls_cert",
            Some(toml::Value::String(crt.display().to_string())),
        ));
        api_fields.push((
            "tls_key",
            Some(toml::Value::String(key.display().to_string())),
        ));
    }
    // Certificate first, then the config, and the order is not arbitrary.
    // `check_api` only checks `is_some()` on the TLS pair — nothing in the
    // loader stats the file — so a config-first order can leave a node whose
    // master says `api.enabled = true` pointing at a certificate that does
    // not exist. That node cannot bind, and no verb undoes it. Orphaned files
    // are the recoverable failure; a non-bootable master is not.
    let mut created: Vec<std::path::PathBuf> = Vec::new();
    let outcome = (|| -> anyhow::Result<()> {
        if let Some(m) = &minted {
            // The master is the ownership reference: it is what the daemon
            // loads, so its owner is the identity that has to be able to read
            // the key sitting next to it. See `create_exclusive`.
            create_exclusive(&crt, m.cert_pem.as_bytes(), 0o644, &crt, &key, config_path)?;
            created.push(crt.clone());
            // 0600 AT CREATION, never write-then-`set_permissions`: that
            // leaves a world-readable window on a private key, which is the
            // exact race `hardened_atomic_write` exists to close for config.
            create_exclusive(&key, m.key_pem.as_bytes(), 0o600, &crt, &key, config_path)?;
            created.push(key.clone());
        }
        write_cluster_and_api_fields_to_master(config_path, &cluster_fields, &api_fields, now)
    })();

    if let Err(e) = outcome {
        // Undo only what THIS call created. Without it a validator refusal on
        // the staged write leaves the pair on disk, and the operator's retry
        // hits R6 — with no `--force`, a dead end produced by our own
        // half-finished attempt.
        return Err(match unwind_created(&created) {
            Ok(()) => e,
            Err(paths) => e.context(format!(
                "could not remove the certificate material this attempt created — \
                 remove it by hand before re-running: {paths}"
            )),
        });
    }

    println!("Cluster enabled — this node is now a primary.");
    println!("  role:       primary");
    println!("  api.listen: {listen}");
    if let Some(m) = &minted {
        println!("  certificate: {}", crt.display());
        println!("  private key: {} (mode 0600)", key.display());
        println!("  expires:     {}", m.not_after);
        println!();
        println!("  SHA-256 fingerprint:");
        println!("    {}", m.fingerprint_sha256);
        println!();
        println!("Copy {} to the secondary and run there:", crt.display());
        println!(
            "  warden cluster join --peer https://<this node>:{} \\",
            listen.port()
        );
        println!("      --token-file <path> --peer-cert <copy of api.crt>");
        println!();
        println!("Compare the fingerprint out-of-band before trusting the copy — on the");
        println!("secondary, `openssl x509 -in <copy> -noout -fingerprint -sha256` must");
        println!("print the same digest. The pin is the only thing authenticating the");
        println!("channel; a certificate that arrived over a channel you have not checked");
        println!("pins whatever an interceptor substituted.");
    } else if let Some(own) = api.tls_cert.as_ref() {
        // No trailing `else`: the only way here with `tls_cert` unset is a
        // half pair (`tls_key` alone), and that post state is refused by
        // `API_TLS_PAIR_INCOMPLETE` in the staged write above — so this
        // branch is not reached with nothing to print.
        println!("  certificate: {} (unchanged — your own)", own.display());
        println!();
        println!("Nothing was generated: this node already carries its own TLS material.");
        println!("The secondary still has to pin it — copy that certificate across and");
        println!("pass it to `warden cluster join --peer-cert`.");
    }
    println!();
    println!("Restart the daemon for the change to take effect.");
    Ok(())
}

/// Non-blank, the way `check_api` and `check_cluster` both read a hash.
fn is_set(v: Option<&str>) -> bool {
    v.is_some_and(|h| !h.trim().is_empty())
}

/// The directory the master config lives in, absolute.
///
/// `Path::new("config.toml").parent()` is `Some("")`, not `None` — and
/// CLAUDE.md documents `./config.toml` as the development path, so the empty
/// parent is reachable, not theoretical. Left relative it would put
/// `tls_cert = "api.crt"` in the master, which the daemon then resolves
/// against ITS working directory rather than the config's. A test suite built
/// on `tempfile::tempdir()` cannot see this: every path there is already
/// absolute.
fn config_dir(config_path: &Path) -> anyhow::Result<std::path::PathBuf> {
    let parent = config_path.parent().unwrap_or_else(|| Path::new(""));
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    parent
        .canonicalize()
        .with_context(|| format!("cannot resolve the config directory {}", parent.display()))
}

/// The uid/gid owning `path`, or `None` if it cannot be stat'd.
///
/// The reference for the TLS pair's ownership is the **config master**: the
/// process that has to read the key is the daemon, and the daemon runs as the
/// user that owns the config it loads. Deriving the owner from anything else
/// (the caller's uid, a hardcoded name) re-opens exactly the hole this closes.
#[cfg(unix)]
fn owner_of(path: &Path) -> Option<(u32, u32)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|m| (m.uid(), m.gid()))
}

/// Create `path` with `mode` **at creation**, refusing if it already exists.
///
/// `create_new(true)` is what makes R6 a guarantee rather than a check: an
/// existence test followed by a write is a TOCTOU window, and the thing on the
/// other side of it is a private key. `r6_crt`/`r6_key` are carried only so
/// the collision reports the same frozen message the pre-check does — the
/// operator must not get two different stories for one condition.
///
/// `owner_ref` is the file whose uid/gid the created file must inherit — the
/// **config master**. It is taken as a path, not as an `Option<(uid, gid)>`, on
/// purpose: with the tuple there is a spelling (`None`) that silently restores
/// the bug, and nothing in the type system objects to it. A required path has
/// no such spelling, and the effect this guards is invisible to any test that
/// does not run as root — so the defence has to be structural, not asserted.
///
/// **What it guards.** Run as root without it, `enable` mints `api.key` as
/// `0600 root:root` while the daemon runs as `purge-warden`: the key the master
/// now points at is one the daemon cannot open, `api.enabled = true` is already
/// written, and the node no longer starts. The config writer learned this
/// already — `atomic_write.rs` captures and re-applies the owner — and this is
/// the same lesson on the sibling path.
///
/// **Why `geteuid() == 0` is the right gate, not a lazy one.** `lchown` needs
/// CAP_CHOWN when the target differs from the caller, and the daemon's seccomp
/// filter excludes `@chown`, so an unconditional call dies on SIGSYS. The
/// non-root case cannot go wrong regardless: the config directory is
/// `drwxr-x---` owned by the daemon user, so a caller who is neither root nor
/// that user cannot create anything here at all — either the owner already
/// matches, or the open fails long before this.
fn create_exclusive(
    path: &Path,
    bytes: &[u8],
    mode: u32,
    r6_crt: &Path,
    r6_key: &Path,
    owner_ref: &Path,
) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut f = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            anyhow::bail!(
                crate::config::schema::cluster::format_cluster_enable_cert_already_exists(&[
                    r6_crt.to_path_buf(),
                    r6_key.to_path_buf()
                ])
            );
        }
        Err(e) => {
            return Err(anyhow::Error::new(e).context(format!("cannot create {}", path.display())))
        }
    };
    f.write_all(bytes)
        .with_context(|| format!("cannot write {}", path.display()))?;

    // Owner BEFORE the fsync below, so the metadata is made durable with the
    // bytes rather than in a second, unsynced step — same ordering, and same
    // reason, as `atomic_write`'s chmod/lchown-then-fsync.
    #[cfg(unix)]
    if let Some((uid, gid)) = owner_of(owner_ref) {
        // SAFETY: geteuid takes no arguments, cannot fail, and is
        // async-signal-safe.
        if unsafe { libc::geteuid() } == 0 {
            if let Err(e) = std::os::unix::fs::lchown(path, Some(uid), Some(gid)) {
                // Leave nothing behind: a key the daemon cannot read is the
                // failure this whole function exists to prevent, so a
                // half-applied one must not survive to be picked up by R6 on
                // the operator's retry.
                drop(f);
                let _ = std::fs::remove_file(path);
                return Err(anyhow::Error::new(e).context(format!(
                    "cannot set ownership {uid}:{gid} on {}",
                    path.display()
                )));
            }
        }
    }

    // Durability matters here for the same reason it does for config: the pin
    // is copied off this file, and a truncated certificate that survives a
    // crash is a node that cannot be joined.
    f.sync_all()
        .with_context(|| format!("cannot flush {}", path.display()))?;
    Ok(())
}

/// Best-effort removal of the files this invocation created. Returns the
/// paths it could NOT remove, so the caller can name them — a cleanup that
/// fails silently reproduces exactly the dead end it exists to prevent.
fn unwind_created(created: &[std::path::PathBuf]) -> Result<(), String> {
    let left: Vec<String> = created
        .iter()
        .filter(|p| std::fs::remove_file(p).is_err() && p.exists())
        .map(|p| p.display().to_string())
        .collect();
    if left.is_empty() {
        Ok(())
    } else {
        Err(left.join(", "))
    }
}

/// What [`run_enable`] needs from a minted certificate, in a shape that exists
/// in **both** feature configurations.
///
/// `crate::cluster` is `#[cfg(feature = "cluster")]`, so `GeneratedCert`
/// simply is not a type on a default build — and `run_enable` is compiled
/// there regardless, because the verb has to exist in order to refuse.
struct MintedPair {
    cert_pem: String,
    key_pem: String,
    fingerprint_sha256: String,
    not_after: time::OffsetDateTime,
}

/// Classify the operator's `--san` values and mint the primary's certificate.
#[cfg(feature = "cluster")]
fn mint_primary_cert(
    sans: &[String],
    validity_days: u32,
    now: time::OffsetDateTime,
) -> anyhow::Result<MintedPair> {
    use crate::cluster::certgen;

    let classified = sans
        .iter()
        .map(|raw| {
            certgen::classify_san(raw).map_err(|reason| anyhow::anyhow!("--san `{raw}` {reason}"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let g = certgen::generate_self_signed(&classified, validity_days, now)?;
    Ok(MintedPair {
        cert_pem: g.cert_pem,
        key_pem: g.key_pem,
        fingerprint_sha256: g.fingerprint_sha256,
        not_after: g.not_after,
    })
}

/// Unreachable in practice — [`ensure_can_enable`] bails first on this build —
/// but it has to *compile*, because `run_enable` does.
#[cfg(not(feature = "cluster"))]
fn mint_primary_cert(
    sans: &[String],
    validity_days: u32,
    now: time::OffsetDateTime,
) -> anyhow::Result<MintedPair> {
    let _ = (sans, validity_days, now);
    anyhow::bail!(
        "this binary was built without the `cluster` feature, so it cannot mint a cluster \
         certificate. Nothing has been written."
    )
}

/// Refuse `warden cluster enable` on a build that cannot run as a primary.
///
/// The same guard, and the same reasoning, as [`ensure_can_join`] — see its
/// doc comment for cli-h1. It is NOT one of the contract's R1-R7; it is the
/// build-gating every `cluster.enabled = true` writer in this module owes,
/// because `super::start::check_cluster_build` refuses to start the daemon
/// while that flag is set on a feature-less binary.
///
/// The trap is strictly worse here than for `join`. `enable` also mints a
/// certificate pair, so an operator who ran it on a stock build, rebuilt with
/// `--features cluster`, and re-ran would hit R6 on their own leftovers — and
/// S4 ships no `--force`.
#[cfg(not(feature = "cluster"))]
fn ensure_can_enable() -> anyhow::Result<()> {
    anyhow::bail!(
        "this binary was built without the `cluster` feature, so it cannot run as a primary.\n\
         Enabling would set cluster.enabled = true, after which the daemon refuses to start.\n\
         Nothing has been written. Rebuild with `--features cluster` to enable clustering."
    )
}

/// Feature-enabled counterpart of [`ensure_can_enable`] — this build can be a primary.
#[cfg(feature = "cluster")]
fn ensure_can_enable() -> anyhow::Result<()> {
    Ok(())
}

/// Ensure the master's top-level `includes` contains the sync-owned
/// `cluster.d/*.toml` drop-in glob, then atomically re-write the
/// master. Idempotent — a re-join does not duplicate the entry. The glob's
/// zero-match-is-allowed rule means the master still loads before any bundle
/// has been synced into `cluster.d/`.
#[cfg(feature = "cluster")]
fn ensure_cluster_include(config_path: &Path, now: time::OffsetDateTime) -> anyhow::Result<()> {
    const PATTERN: &str = CLUSTER_INCLUDE;

    let mut already_present = false;
    let content = super::toml_write::edit_document(config_path, |doc| {
        let includes = doc
            .entry("includes")
            .or_insert(toml_edit::value(toml_edit::Array::new()));
        let arr = includes
            .as_array_mut()
            .ok_or_else(|| anyhow::anyhow!("`includes` must be a TOML array of strings"))?;
        if arr.iter().any(|v| v.as_str() == Some(PATTERN)) {
            already_present = true; // idempotent re-join
            return Ok(());
        }
        arr.push(PATTERN);
        Ok(())
    })?;
    if already_present {
        return Ok(());
    }
    atomic_write_and_validate(
        config_path,
        &content,
        |staged: &Path| -> Result<(), String> {
            loader::load_config(staged, now)
                .map(|_| ())
                .map_err(|e| format_config_errors_flat(&e))
        },
    )
    .map_err(|e| anyhow::anyhow!("{e}"))
}

/// Flatten loader errors into one operator-facing message.
///
/// The wrapper is per-verb because the text names the operation; the
/// flattener underneath is shared with `token`.
fn format_load_errs(errs: Vec<crate::config::error::ConfigError>) -> anyhow::Error {
    anyhow::anyhow!(
        "cannot load config for cluster operation: {}",
        crate::cli::commands::token::format_errs_flat(errs)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Owner-only is the only safe mode for a file holding a bearer secret:
    /// whoever can read it can sync policy. `0o640` is already an exposure —
    /// the group is one the operator may not have thought about.
    #[test]
    fn mode_exposes_secret_flags_any_group_or_other_bit() {
        assert!(!mode_exposes_secret(0o600));
        assert!(!mode_exposes_secret(0o400));
        assert!(mode_exposes_secret(0o640));
        assert!(mode_exposes_secret(0o604));
        assert!(mode_exposes_secret(0o644));
        assert!(mode_exposes_secret(0o777));
    }

    /// The check warns; it must never refuse. `--token-file` is the route
    /// the steering text calls preferred, and an operator reading from a
    /// ramdisk or a shared provisioning path would otherwise be pushed back
    /// onto argv, which is the exposure this whole seam exists to avoid.
    #[test]
    fn resolve_join_token_still_accepts_a_world_readable_token_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        for (name, mode) in [("open.tok", 0o644u32), ("tight.tok", 0o600u32)] {
            let path = dir.path().join(name);
            std::fs::write(&path, "sekrit\n").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            let t = resolve_join_token(None, Some(&path)).unwrap();
            assert_eq!(t, "sekrit", "mode {mode:o} must not change the token");
        }
    }

    const MASTER: &str = r#"schema_version = 3

[server]
default_profile = "default"
default_blocked_ttl_secs = 60

[api]
token_hash = ""

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#;

    fn write_master(dir: &tempfile::TempDir) -> std::path::PathBuf {
        let path = dir.path().join("config.toml");
        std::fs::write(&path, MASTER).unwrap();
        path
    }

    /// A master shaped the way a cluster secondary requires: the
    /// node-local keep-list and nothing else. No `[profiles.*]`, no
    /// `[upstream]` — those arrive in the primary's bundle, and a secondary
    /// keeping its own copies is refused by
    /// `CLUSTER_SECONDARY_MASTER_CARRIES_POLICY` because the loader would
    /// silently CONCATENATE them with the bundle's.
    ///
    /// Deliberately NOT loadable until `enabled = true` has been written:
    /// only a node that is actually syncing earns the missing-`[upstream]`
    /// exemption. An unvalidated `std::fs::write` followed by a validating
    /// cluster write is exactly the sequence a real join performs.
    const SECONDARY_MASTER: &str = r#"schema_version = 3

[server]
default_blocked_ttl_secs = 60

[api]
token_hash = ""
"#;

    fn write_secondary_master(dir: &tempfile::TempDir) -> std::path::PathBuf {
        let path = dir.path().join("config.toml");
        std::fs::write(&path, SECONDARY_MASTER).unwrap();
        path
    }

    /// A policy bundle as the poll loop would have installed it.
    ///
    /// `[upstream]` is the load-bearing part, not decoration: `leave`
    /// deliberately KEEPS the `cluster.d/*.toml` include (see `run_leave`'s
    /// closing note), so on a synced node the bundle still supplies the
    /// policy after leaving and the post-leave master validates. Without a
    /// bundle the node is joined-but-never-synced, and there `leave` cannot
    /// write — a real residue of the missing-`[upstream]` exemption.
    ///
    /// Gated: only the `cluster`-feature tests reach a synced node, and an
    /// ungated helper would be dead code in the default build. `#[expect(dead_code)]`
    /// is not an option here — it is itself always red under `--all-targets`.
    #[cfg(feature = "cluster")]
    fn write_synced_bundle(dir: &tempfile::TempDir) {
        let dropin = dir.path().join("cluster.d");
        std::fs::create_dir_all(&dropin).unwrap();
        std::fs::write(
            dropin.join("bundle.toml"),
            "[upstream]\nservers = [\"192.0.2.1:53\"]\n\n\
             [profiles.synced]\ndisplay_name = \"Synced\"\n",
        )
        .unwrap();
    }

    fn reload(path: &Path) -> crate::config::schema::ClusterConfig {
        let now = time::OffsetDateTime::now_utc();
        loader::load_config(path, now).unwrap().config.cluster
    }

    #[test]
    fn token_writes_hash_without_enabling() {
        let dir = tempfile::tempdir().unwrap();
        let master = write_master(&dir);
        run_token(&master).unwrap();

        let c = reload(&master);
        // hash landed (64 hex chars), but clustering stays off and role
        // stays the default primary.
        assert_eq!(c.token_hash.as_deref().unwrap().len(), 64);
        assert!(!c.enabled);
        assert_eq!(c.role, ClusterRole::Primary);
    }

    // The four `run_join` tests below exercise paths that only exist on a
    // `cluster` build: a feature-less binary refuses the verb before peer
    // validation or any write. Left ungated, the two `rejects`
    // tests would still pass on a default build — but for the wrong reason,
    // green on the early refusal while never reaching the peer check they
    // claim to pin. The refusal itself is covered by `join_refused_*` below.
    #[test]
    #[cfg(feature = "cluster")]
    fn join_writes_enabled_secondary() {
        let dir = tempfile::tempdir().unwrap();
        let master = write_secondary_master(&dir);
        run_join(
            &master,
            "https://192.0.2.1:8053",
            Some("ps_exampletoken"),
            None,
        )
        .unwrap();

        let c = reload(&master);
        assert!(c.enabled);
        assert_eq!(c.role, ClusterRole::Secondary);
        assert_eq!(c.peer.as_deref(), Some("https://192.0.2.1:8053"));
        // token_hash is the SHA-256 of the supplied plaintext, never the
        // plaintext itself.
        let h = c.token_hash.as_deref().unwrap();
        assert_eq!(h.len(), 64);
        assert_eq!(h, &hash_token("ps_exampletoken"));
    }

    /// A joined-but-NEVER-SYNCED secondary has no `[upstream]` anywhere: not
    /// in its own master (a cluster secondary may not carry policy) and not
    /// in `cluster.d/` (no bundle has landed). Clearing membership drops
    /// the missing-`[upstream]` exemption, so the
    /// post-leave config fails `UPSTREAM_SERVERS_EMPTY` and the write is
    /// refused — leaving the operator joined, told about `upstream.servers`
    /// by a verb they ran about cluster membership.
    ///
    /// The generic remedy that error prints is a DEADLOCK here: it says to
    /// edit `upstream.servers`, and doing that on a still-joined secondary is
    /// refused by `CLUSTER_SECONDARY_MASTER_CARRIES_POLICY`. There is no
    /// `warden upstream` verb. So `leave` must be able to supply it itself.
    #[test]
    #[cfg(feature = "cluster")]
    fn leave_refuses_a_never_synced_secondary_and_names_the_flag() {
        let dir = tempfile::tempdir().unwrap();
        let master = write_secondary_master(&dir);
        run_join(
            &master,
            "https://192.0.2.1:8053",
            Some("ps_exampletoken"),
            None,
        )
        .unwrap();
        let before = std::fs::read_to_string(&master).unwrap();

        let err = run_leave(&master, None).expect_err("must refuse, not strand the node");
        let msg = err.to_string();

        assert!(
            msg.contains(LEAVE_WOULD_STRAND_NODE),
            "must use the frozen refusal, got: {msg}"
        );
        assert!(
            msg.contains("--upstream"),
            "the refusal must name the flag that resolves it, got: {msg}"
        );
        assert!(
            !msg.contains(".tmp-"),
            "must not name the staging temp file — it is unlinked by the time \
             the operator reads this. Got: {msg}"
        );
        assert_eq!(
            before,
            std::fs::read_to_string(&master).unwrap(),
            "a refusal must leave the master byte-identical"
        );
    }

    /// …and with the flag it completes, in ONE write: membership cleared and
    /// the node's own upstream installed together. Two writes cannot work —
    /// the intermediate state is exactly the one the validator refuses.
    #[test]
    #[cfg(feature = "cluster")]
    fn leave_with_an_upstream_completes_on_a_never_synced_secondary() {
        let dir = tempfile::tempdir().unwrap();
        let master = write_secondary_master(&dir);
        run_join(
            &master,
            "https://192.0.2.1:8053",
            Some("ps_exampletoken"),
            None,
        )
        .unwrap();

        run_leave(&master, Some("192.0.2.53:53")).expect("leave completes with an upstream");

        let now = time::OffsetDateTime::now_utc();
        let loaded = loader::load_config(&master, now).expect("post-leave config loads");
        assert!(!loaded.config.cluster.enabled);
        assert_eq!(loaded.config.cluster.role, ClusterRole::Primary);
        assert!(loaded.config.cluster.peer.is_none());
        assert_eq!(loaded.config.upstream.servers, vec!["192.0.2.53:53"]);
    }

    /// `--upstream` on a node that already resolves one is REFUSED, because
    /// the flag replaces `upstream.servers` wholesale rather than adding to
    /// it. Found by an adversarial review of the first implementation, which
    /// accepted the flag on any successful leave: an operator with three
    /// upstreams who passed it casually would have kept one.
    #[test]
    #[cfg(feature = "cluster")]
    fn leave_refuses_an_upstream_flag_the_node_does_not_need() {
        let dir = tempfile::tempdir().unwrap();
        let master = write_secondary_master(&dir);
        write_synced_bundle(&dir);
        run_join(
            &master,
            "https://192.0.2.1:8053",
            Some("ps_exampletoken"),
            None,
        )
        .unwrap();
        let before = std::fs::read_to_string(&master).unwrap();

        let err = run_leave(&master, Some("192.0.2.53:53"))
            .expect_err("the flag must be refused where it can only destroy");
        assert!(
            err.to_string().contains(LEAVE_UPSTREAM_NOT_NEEDED),
            "must use the frozen refusal, got: {err}"
        );
        assert_eq!(before, std::fs::read_to_string(&master).unwrap());
    }

    /// GREEN TODAY — the boundary the new branch must not cross. A SYNCED
    /// secondary needs no `--upstream`: `leave` keeps the `cluster.d/*.toml`
    /// include on purpose, so the bundle still supplies `[upstream]` after
    /// membership is cleared. An implementation that demands the flag from
    /// every secondary reds this and nothing else.
    #[test]
    #[cfg(feature = "cluster")]
    fn leave_on_a_synced_secondary_needs_no_upstream_flag() {
        let dir = tempfile::tempdir().unwrap();
        let master = write_secondary_master(&dir);
        write_synced_bundle(&dir);
        run_join(
            &master,
            "https://192.0.2.1:8053",
            Some("ps_exampletoken"),
            None,
        )
        .unwrap();

        run_leave(&master, None).expect("a synced node leaves without a flag");
        assert!(!reload(&master).enabled);
    }

    /// On a stock build `cluster join` must refuse and persist NOTHING:
    /// writing `cluster.enabled = true` first would make the daemon
    /// refuse to start with no `cluster leave` to undo it.
    ///
    /// Asserts the file is byte-identical, not merely that `enabled` is false:
    /// a partial write that landed `role`/`peer`/`token_hash` without `enabled`
    /// would satisfy the weaker check while still mutating the operator's
    /// master config.
    #[test]
    #[cfg(not(feature = "cluster"))]
    fn join_refused_without_cluster_feature_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let master = write_master(&dir);
        let before = std::fs::read_to_string(&master).unwrap();

        let err = run_join(
            &master,
            "https://192.0.2.1:8053",
            Some("ps_exampletoken"),
            None,
        )
        .unwrap_err();

        // The message must send the operator to the build, not to their config.
        let msg = err.to_string();
        assert!(
            msg.contains("`cluster` feature"),
            "refusal must name the missing feature, got: {msg}"
        );
        assert!(
            msg.contains("Nothing has been written"),
            "refusal must state that no write happened, got: {msg}"
        );

        assert_eq!(
            before,
            std::fs::read_to_string(&master).unwrap(),
            "cluster join must not touch the master on a feature-less build"
        );
        assert!(!reload(&master).enabled);
    }

    #[test]
    #[cfg(feature = "cluster")]
    fn join_rejects_empty_peer() {
        let dir = tempfile::tempdir().unwrap();
        let master = write_master(&dir);
        assert!(run_join(&master, "  ", Some("ps_tok"), None).is_err());
        // Nothing was written — still disabled default.
        assert!(!reload(&master).enabled);
    }

    #[test]
    #[cfg(feature = "cluster")]
    fn join_rejects_plaintext_offbox_peer() {
        // A non-loopback http:// peer is refused before any write.
        let dir = tempfile::tempdir().unwrap();
        let master = write_master(&dir);
        assert!(run_join(&master, "http://192.0.2.1:8053", Some("ps_tok"), None).is_err());
        assert!(!reload(&master).enabled);
    }

    #[test]
    fn resolve_token_prefers_file_then_arg() {
        // --token-file wins and is trimmed; --token works and is trimmed;
        // empty file / empty arg both error.
        let dir = tempfile::tempdir().unwrap();
        let tf = dir.path().join("tok");
        std::fs::write(&tf, "  ps_fromfile\n").unwrap();
        assert_eq!(
            resolve_join_token(Some("ps_fromarg"), Some(&tf)).unwrap(),
            "ps_fromfile"
        );
        assert_eq!(
            resolve_join_token(Some(" ps_fromarg "), None).unwrap(),
            "ps_fromarg"
        );
        std::fs::write(&tf, "   \n").unwrap();
        assert!(resolve_join_token(None, Some(&tf)).is_err());
        assert!(resolve_join_token(Some("   "), None).is_err());
    }

    #[test]
    #[cfg(feature = "cluster")]
    fn join_reads_token_from_file() {
        // The secret never touches argv — the hash matches the file's
        // plaintext.
        let dir = tempfile::tempdir().unwrap();
        let master = write_secondary_master(&dir);
        let tf = dir.path().join("tok");
        std::fs::write(&tf, "ps_filesecret\n").unwrap();
        run_join(&master, "https://192.0.2.1:8053", None, Some(&tf)).unwrap();
        let c = reload(&master);
        assert!(c.enabled);
        assert_eq!(
            c.token_hash.as_deref().unwrap(),
            &hash_token("ps_filesecret")
        );
    }

    /// A self-signed PEM good enough for `resolve_join_peer_cert` to accept.
    #[cfg(feature = "cluster")]
    fn write_pem(dir: &tempfile::TempDir, name: &str) -> std::path::PathBuf {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::ExplicitNoCa;
        params.subject_alt_names = vec![rcgen::SanType::IpAddress("192.0.2.1".parse().unwrap())];
        let cert = params.self_signed(&key).unwrap();
        let path = dir.path().join(name);
        std::fs::write(&path, cert.pem()).unwrap();
        path
    }

    #[test]
    #[cfg(feature = "cluster")]
    fn join_records_the_peer_cert_as_an_absolute_path() {
        let dir = tempfile::tempdir().unwrap();
        let master = write_secondary_master(&dir);
        let pem = write_pem(&dir, "primary.pem");
        run_join_pinned(
            &master,
            "https://192.0.2.1:8053",
            Some("ps_tok"),
            None,
            Some(&pem),
        )
        .unwrap();
        let c = reload(&master);
        assert_eq!(c.peer_cert.as_deref(), Some(pem.to_str().unwrap()));
        assert!(
            std::path::Path::new(c.peer_cert.as_deref().unwrap()).is_absolute(),
            "the daemon runs with a different CWD; a relative pin resolves to nothing"
        );
    }

    /// Re-joining WITHOUT `--peer-cert` must not clear an existing pin.
    ///
    /// `write_cluster_fields_to_master` maps a `None` field to
    /// `cluster_table.remove(k)`, so threading the flag's absence straight
    /// through would delete the pin — an operator rotating the token would
    /// silently un-pin the node and every later poll would refuse. Same class
    /// as the `build_blocklist_value` field-loss bug.
    #[test]
    #[cfg(feature = "cluster")]
    fn a_rejoin_without_the_flag_preserves_the_existing_pin() {
        let dir = tempfile::tempdir().unwrap();
        let master = write_secondary_master(&dir);
        let pem = write_pem(&dir, "primary.pem");
        run_join_pinned(
            &master,
            "https://192.0.2.1:8053",
            Some("ps_first"),
            None,
            Some(&pem),
        )
        .unwrap();

        // Rotate the token only — no --peer-cert this time.
        run_join(&master, "https://192.0.2.1:8053", Some("ps_second"), None).unwrap();

        let c = reload(&master);
        assert_eq!(c.token_hash.as_deref().unwrap(), &hash_token("ps_second"));
        assert_eq!(
            c.peer_cert.as_deref(),
            Some(pem.to_str().unwrap()),
            "a re-join must not un-pin the node"
        );
    }

    /// A pin that cannot be read or parsed is refused at join time, while the
    /// operator is present to fix it — not hours later at the first poll.
    #[test]
    #[cfg(feature = "cluster")]
    fn join_refuses_an_unreadable_or_non_pem_peer_cert() {
        let dir = tempfile::tempdir().unwrap();
        let master = write_secondary_master(&dir);
        // Byte-identity, NOT `reload()`: an unjoined secondary master does not
        // validate (`CLUSTER_SECONDARY_NOT_YET_JOINED` — its upstream has not
        // arrived yet), so loading it to prove nothing changed panics for an
        // unrelated reason. The bytes are also the stronger claim.
        let before = std::fs::read(&master).unwrap();

        let missing = dir.path().join("nope.pem");
        assert!(run_join_pinned(
            &master,
            "https://192.0.2.1:8053",
            Some("ps_tok"),
            None,
            Some(&missing)
        )
        .is_err());

        let garbage = dir.path().join("garbage.pem");
        std::fs::write(&garbage, b"not a certificate").unwrap();
        assert!(run_join_pinned(
            &master,
            "https://192.0.2.1:8053",
            Some("ps_tok"),
            None,
            Some(&garbage)
        )
        .is_err());

        assert_eq!(
            std::fs::read(&master).unwrap(),
            before,
            "a refused join must leave the master byte-identical"
        );
    }

    #[test]
    fn status_runs_for_disabled_and_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let master = write_master(&dir);
        // The on-disk summary is the daemon-less fallback `run_status` prints
        // when IPC is unavailable; exercise it directly (sync, no runtime).
        // disabled default
        print_config_status(&master).unwrap();

        // Enabled arm. Writes the secondary state directly rather than via
        // `run_join`: `join` refuses on a feature-less build, and routing
        // through it would make this test cluster-only for a reason that
        // has nothing to do with `status`.
        //
        // A SEPARATE, policy-free master: reusing the one above would
        // flip a master that carries `[profiles.*]` and `[upstream]` to
        // `role = secondary`, which is exactly the illegal state where
        // the primary's bundle would silently union with the node's own
        // policy.
        let sec_dir = tempfile::tempdir().unwrap();
        let master = write_secondary_master(&sec_dir);
        write_cluster_fields_to_master(
            &master,
            &[
                ("enabled", Some(toml::Value::Boolean(true))),
                ("role", Some(toml::Value::String("secondary".into()))),
                (
                    "peer",
                    Some(toml::Value::String("https://192.0.2.1:8053".into())),
                ),
                (
                    "token_hash",
                    Some(toml::Value::String(hash_token("ps_tok"))),
                ),
            ],
            time::OffsetDateTime::now_utc(),
        )
        .unwrap();
        print_config_status(&master).unwrap();
    }

    #[test]
    fn other_sections_survive_cluster_write() {
        let dir = tempfile::tempdir().unwrap();
        let master = write_master(&dir);
        run_token(&master).unwrap();
        let now = time::OffsetDateTime::now_utc();
        let cfg = loader::load_config(&master, now).unwrap().config;
        // the [api] and [profiles.default] sections are untouched.
        assert!(cfg.profiles.contains_key("default"));
        assert_eq!(cfg.schema_version, 3);
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn join_adds_cluster_include_and_persists_plaintext_token() {
        let dir = tempfile::tempdir().unwrap();
        let master = write_secondary_master(&dir);
        run_join(
            &master,
            "http://127.0.0.1:18080",
            Some("ps_plainsecret"),
            None,
        )
        .unwrap();

        // (a) the sync drop-in glob was added to the master's includes.
        let now = time::OffsetDateTime::now_utc();
        let loaded = loader::load_config(&master, now).unwrap();
        assert!(
            loaded
                .config
                .includes
                .iter()
                .any(|p| p == "cluster.d/*.toml"),
            "join must add the cluster.d include: {:?}",
            loaded.config.includes
        );

        // (b) the plaintext token landed where the poll loop reads it.
        assert_eq!(
            crate::cluster::secret::load_cluster_token(&master)
                .unwrap()
                .as_deref(),
            Some("ps_plainsecret"),
        );
    }

    // ── `cluster leave` ────────────────────────────────────────────
    //
    // Only the round-trip test below is `cluster`-gated. Every other `leave`
    // test is UNGATED on purpose: `[features]` has no `default` key, so the
    // default `cargo test` leg is the stock build — the one an operator is
    // actually holding when this verb is needed. A `leave` suite that only
    // ran under `--features cluster` would prove nothing about it.

    /// A master hand-edited into the joined state.
    ///
    /// Deliberately NOT produced by `run_join`: on a stock build `join`
    /// refuses before writing anything (correctly — see `ensure_can_join`), so
    /// the state has to be written directly. That is also how a real stock box
    /// gets here: a hand-edit, a config copied off another machine, or a
    /// binary older than that guard.
    fn write_joined_master(dir: &tempfile::TempDir, name: &str) -> std::path::PathBuf {
        let path = dir.path().join(name);
        std::fs::write(
            &path,
            format!(
                "{MASTER}\n[cluster]\nenabled = true\nrole = \"secondary\"\n\
                 peer = \"https://192.0.2.1:8053\"\ntoken_hash = \"{}\"\n",
                hash_token("ps_tok")
            ),
        )
        .unwrap();
        path
    }

    /// The point of the whole verb: clearing cluster state must work on a
    /// STOCK build, since that is the build whose daemon refuses to boot on
    /// `cluster.enabled = true` and which cannot reach the joined state
    /// through `join` at all.
    ///
    /// The fixture is the minimal hand-edit — `enabled = true` and nothing
    /// else — which the validator REJECTS (`token_hash` is required when
    /// enabled). That makes this the discriminating test for the pre-load
    /// trap: give `run_leave` a `load_config` guard like its siblings have and
    /// this goes red, because the verb would refuse the very config it exists
    /// to repair. If it does go red, the fix is dropping the guard — never
    /// adding `token_hash` to the fixture, which would quietly narrow the test
    /// to the already-loadable case and leave the recovery path broken.
    #[test]
    fn leave_clears_membership_on_a_stock_build() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, format!("{MASTER}\n[cluster]\nenabled = true\n")).unwrap();

        let now = time::OffsetDateTime::now_utc();
        assert!(
            loader::load_config(&path, now).is_err(),
            "fixture must be the stuck, unloadable state or this test proves nothing"
        );

        run_leave(&path, None).unwrap();

        // `reload` unwraps `load_config`, so this also proves the config that
        // would not load now does.
        let c = reload(&path);
        assert!(!c.enabled);
        assert_eq!(c.role, ClusterRole::Primary);
        assert!(c.peer.is_none());
    }

    /// `role = "secondary"` without a `peer` is rejected by the validator with
    /// no `enabled` guard, so a node is unbootable on the role alone. `leave`
    /// has to reach that state too — hence `role` counts as membership on its
    /// own in `asserts_membership`.
    #[test]
    fn leave_rescues_secondary_role_without_peer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            format!("{MASTER}\n[cluster]\nrole = \"secondary\"\n"),
        )
        .unwrap();

        let now = time::OffsetDateTime::now_utc();
        assert!(loader::load_config(&path, now).is_err());

        run_leave(&path, None).unwrap();
        assert_eq!(reload(&path).role, ClusterRole::Primary);
    }

    /// Not a member ⇒ say so and leave the file byte-identical. Byte equality
    /// subsumes a sha256 comparison and pins it without a hash round-trip.
    #[test]
    fn leave_is_a_noop_when_not_a_member() {
        let dir = tempfile::tempdir().unwrap();

        // (a) no `[cluster]` section at all.
        let master = write_master(&dir);
        let before = std::fs::read_to_string(&master).unwrap();
        run_leave(&master, None).unwrap();
        assert_eq!(
            before,
            std::fs::read_to_string(&master).unwrap(),
            "leave must not rewrite a master with no [cluster] section"
        );

        // (b) an explicit but inert section — still not membership, and the
        // operator's unrelated tuning must not be reformatted away.
        let off = dir.path().join("off.toml");
        std::fs::write(
            &off,
            format!("{MASTER}\n[cluster]\nenabled = false\npoll_interval_secs = 30\n"),
        )
        .unwrap();
        let before = std::fs::read_to_string(&off).unwrap();
        run_leave(&off, None).unwrap();
        assert_eq!(
            before,
            std::fs::read_to_string(&off).unwrap(),
            "leave must not rewrite an already-disabled master"
        );
    }

    /// A clean master plus an INCLUDE that switches clustering on must NOT
    /// report "nothing to leave" — that is a false all-clear for an operator
    /// whose daemon is still refusing to boot. `leave` only rewrites the
    /// master, so it names the real source and writes nothing.
    #[test]
    fn leave_refuses_when_an_include_holds_membership() {
        let dir = tempfile::tempdir().unwrap();
        // `includes` is a top-level key, so it must precede every table header
        // or TOML would nest it inside the preceding table.
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "schema_version = 3\nincludes = [\"cluster.d/*.toml\"]\n\n\
             [server]\ndefault_profile = \"default\"\n\n\
             [profiles.default]\ndisplay_name = \"D\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        )
        .unwrap();
        std::fs::create_dir(dir.path().join("cluster.d")).unwrap();
        std::fs::write(
            dir.path().join("cluster.d").join("node.toml"),
            format!(
                "[cluster]\nenabled = true\ntoken_hash = \"{}\"\n",
                hash_token("ps_tok")
            ),
        )
        .unwrap();

        let before = std::fs::read_to_string(&path).unwrap();
        let err = run_leave(&path, None).unwrap_err();
        let msg = err.to_string();

        // Both needles: the filename alone could be echoed by an unrelated
        // load error, which would make this pass for the wrong reason.
        assert!(
            msg.contains("node.toml"),
            "the refusal must name the file that actually holds the section, got: {msg}"
        );
        assert!(
            msg.contains("only rewrites the master"),
            "the refusal must be THIS guard, not an incidental load error, got: {msg}"
        );
        assert_eq!(
            before,
            std::fs::read_to_string(&path).unwrap(),
            "leave must not rewrite the master when the state is not in it"
        );
    }

    /// The second `leave` finds no membership and must not touch the file.
    #[test]
    fn leave_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let master = write_joined_master(&dir, "config.toml");

        run_leave(&master, None).unwrap();
        let after_first = std::fs::read_to_string(&master).unwrap();
        run_leave(&master, None).unwrap();

        assert_eq!(
            after_first,
            std::fs::read_to_string(&master).unwrap(),
            "a second leave must be a byte-identical no-op"
        );
    }

    /// Membership goes; nothing else does. The credential in particular
    /// survives — leaving a cluster is not revoking a token.
    #[test]
    fn leave_preserves_token_hash_and_every_other_section() {
        let dir = tempfile::tempdir().unwrap();
        let master = write_joined_master(&dir, "config.toml");
        run_leave(&master, None).unwrap();

        let now = time::OffsetDateTime::now_utc();
        let cfg = loader::load_config(&master, now).unwrap().config;
        assert!(cfg.profiles.contains_key("default"));
        assert_eq!(cfg.schema_version, 3);
        assert_eq!(
            cfg.cluster.token_hash.as_deref(),
            Some(hash_token("ps_tok").as_str())
        );
    }

    /// The staging validator is what replaces the pre-load `leave` cannot
    /// have: if clearing cluster state is NOT enough to make the config load,
    /// the write is refused and the file is left byte-identical. Here the
    /// master also names a profile that does not exist.
    #[test]
    fn leave_refuses_when_the_result_would_still_not_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "schema_version = 3\n\n[server]\ndefault_profile = \"ghost\"\n\n\
             [profiles.default]\ndisplay_name = \"D\"\n\n[cluster]\nenabled = true\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        )
        .unwrap();
        let before = std::fs::read_to_string(&path).unwrap();

        assert!(run_leave(&path, None).is_err());
        assert_eq!(
            before,
            std::fs::read_to_string(&path).unwrap(),
            "a refused leave must leave the master byte-identical"
        );
    }

    /// The shape `leave` ITSELF produces on a real secondary: `join` leaves a
    /// `cluster.d/*.toml` include behind and `leave` keeps it by design, so a
    /// second `leave` runs against a master that still carries the include and
    /// an emptied `[cluster]`. It must stay a clean no-op.
    ///
    /// Guards the include check from misfiring on its own output — a recovery
    /// verb that exits non-zero AFTER successfully recovering is worse than
    /// the false all-clear that check replaces, because the operator's next
    /// move is to hand-edit a config that was already correct.
    ///
    /// Second case is the adversarial one: a synced bundle that itself carries
    /// `[cluster]`. The master always keeps a `[cluster]` table after `leave`
    /// (`token_hash` is retained, and even an emptied table is still emitted),
    /// so a second definition is a duplicate-singleton load error — the guard
    /// cannot see a merged view, falls through, and still does not bail.
    #[cfg(feature = "cluster")]
    #[test]
    fn leave_twice_on_a_real_secondary_stays_a_clean_noop() {
        let dir = tempfile::tempdir().unwrap();
        let master = write_secondary_master(&dir);
        run_join(&master, "https://192.0.2.1:8053", Some("ps_tok"), None).unwrap();

        // A policy bundle synced by the poll loop into the sync-owned drop-in.
        write_synced_bundle(&dir);

        run_leave(&master, None).unwrap();
        let after_first = std::fs::read_to_string(&master).unwrap();

        run_leave(&master, None).expect("a second leave must not bail on leave's own output");
        assert_eq!(
            after_first,
            std::fs::read_to_string(&master).unwrap(),
            "the second leave must be byte-identical"
        );

        // Adversarial: the bundle also carries a [cluster] section.
        std::fs::write(
            dir.path().join("cluster.d/bundle.toml"),
            "[upstream]\nservers = [\"192.0.2.1:53\"]\n\n\
             [profiles.synced]\ndisplay_name = \"Synced\"\n\n[cluster]\nenabled = true\n",
        )
        .unwrap();
        run_leave(&master, None).expect("must not bail when the merged view is unreadable");
        assert_eq!(
            after_first,
            std::fs::read_to_string(&master).unwrap(),
            "still byte-identical"
        );
    }

    /// The round trip. `cluster`-gated because reaching the joined state
    /// through `run_join` is only possible on this build.
    ///
    /// Scoped on `token_hash`, which `leave` deliberately keeps — and for the
    /// same reason on the `cluster.d` include and the plaintext token file,
    /// which `join` also writes here and `leave` also leaves alone. "Pre-join
    /// state" is already a scoped comparison because of the credential
    /// carve-out; scoping it on those two is the same rule, not a dodge.
    #[cfg(feature = "cluster")]
    #[test]
    fn join_then_leave_round_trips_to_pre_join_state() {
        let dir = tempfile::tempdir().unwrap();
        let master = write_secondary_master(&dir);
        write_synced_bundle(&dir);
        // Pre-join the master lists no `includes`, so the bundle is not
        // merged and the config does NOT load: a policy-free master is not a
        // bootable node until it has joined. Assert non-membership off the
        // RAW file, the way `run_leave` reads it, rather than through a load
        // this state is not supposed to survive.
        let raw: toml::Value = std::fs::read_to_string(&master).unwrap().parse().unwrap();
        assert!(
            raw.get("cluster").is_none(),
            "the round trip must start from a non-member"
        );

        run_join(&master, "https://192.0.2.1:8053", Some("ps_rt"), None).unwrap();
        assert!(reload(&master).enabled);

        run_leave(&master, None).unwrap();

        assert_eq!(
            reload(&master),
            crate::config::schema::ClusterConfig {
                token_hash: Some(hash_token("ps_rt")),
                ..Default::default()
            },
            "every membership field must be back to its pre-join default"
        );
    }

    /// `join` refuses a policy-carrying master AND writes nothing. The
    /// byte-identity assertion is the point: a refusal that
    /// half-wrote `[cluster]` leaves the node in a state neither `join` nor
    /// `leave` describes.
    #[cfg(feature = "cluster")]
    #[test]
    fn join_refuses_a_policy_carrying_master_and_leaves_it_byte_identical() {
        let dir = tempfile::tempdir().unwrap();
        // MASTER carries [profiles.default] and [upstream] — an ordinary
        // standalone config, and exactly what a second box looks like when
        // someone runs `warden init` on it before joining.
        let master = write_master(&dir);
        let before = std::fs::read(&master).unwrap();

        let err = run_join(&master, "https://192.0.2.1:8053", Some("ps_tok"), None)
            .expect_err("join must refuse a master carrying policy");

        let after = std::fs::read(&master).unwrap();
        assert_eq!(before, after, "a refused join must write NOTHING");

        let text = err.to_string();
        assert!(
            text.contains("profiles") && text.contains("upstream"),
            "every offending section must be listed, not just the first: {text}"
        );
        // The remedy must name the REAL master. On the staged-write path the
        // provenance file is the staging temp file, and an instruction that
        // names a path which no longer exists cannot be followed.
        assert!(
            text.contains(&master.display().to_string()),
            "the refusal must name the operator's own config: {text}"
        );
        assert!(
            !text.contains(".tmp-"),
            "must not name a staging temp file: {text}"
        );
    }

    /// The refusal is scoped to policy. A master carrying only its node-local
    /// keep-list joins fine — otherwise the guard would block every join.
    #[cfg(feature = "cluster")]
    #[test]
    fn join_accepts_a_policy_free_master() {
        let dir = tempfile::tempdir().unwrap();
        let master = write_secondary_master(&dir);
        run_join(&master, "https://192.0.2.1:8053", Some("ps_tok"), None)
            .expect("a §5.3-shaped master is exactly what join is for");
        assert!(reload(&master).enabled);
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn join_is_idempotent_on_includes() {
        let dir = tempfile::tempdir().unwrap();
        let master = write_secondary_master(&dir);
        run_join(&master, "http://127.0.0.1:18080", Some("ps_a"), None).unwrap();
        run_join(&master, "http://127.0.0.1:18080", Some("ps_b"), None).unwrap();

        let now = time::OffsetDateTime::now_utc();
        let loaded = loader::load_config(&master, now).unwrap();
        let n = loaded
            .config
            .includes
            .iter()
            .filter(|p| p.as_str() == "cluster.d/*.toml")
            .count();
        assert_eq!(n, 1, "re-join must not duplicate the include");
    }

    // ── S4 `cluster enable` ────────────────────────────────────
    //
    // Every refusal test asserts TWO things: the master is byte-identical
    // afterwards, AND the specific frozen const came back. Byte-identity
    // alone does not discriminate — it is satisfied by any refusal, so seven
    // tests could all be green on R2 and the suite would read clean. That is
    // this module's own documented failure mode; see the note above the
    // `run_join` tests.
    //
    // Gated on `cluster` for the second half of the same reason: on a
    // feature-less build `ensure_can_enable` bails before every one of them,
    // so they would pass without reaching the rule they claim to pin.

    /// A 64-hex-char hash, the shape `hash_token` produces. The value is
    /// never verified by anything under test — only its non-blankness is.
    #[cfg(feature = "cluster")]
    const HASH64: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    /// Knobs for a would-be primary's master. `Default` is the node that
    /// SHOULD succeed: both token hashes present, no TLS material, and no
    /// `[api] listen` — i.e. the loopback default, which is the state of
    /// every fresh install and the reason `--api-listen` exists.
    #[cfg(feature = "cluster")]
    #[derive(Default)]
    struct PrimaryFixture {
        no_cluster_token: bool,
        no_api_token: bool,
        listen: Option<&'static str>,
        tls: Option<(&'static str, &'static str)>,
    }

    #[cfg(feature = "cluster")]
    fn write_primary_master(dir: &tempfile::TempDir, f: &PrimaryFixture) -> std::path::PathBuf {
        let mut s = String::from(
            "schema_version = 3\n\n\
             [server]\ndefault_profile = \"default\"\n\n\
             [profiles.default]\ndisplay_name = \"Default\"\n\n\
             [upstream]\nservers = [\"192.0.2.1:53\"]\n\n\
             [cluster]\n",
        );
        if !f.no_cluster_token {
            s.push_str(&format!("token_hash = \"{HASH64}\"\n"));
        }
        s.push_str("\n[api]\n");
        if !f.no_api_token {
            s.push_str(&format!("token_hash = \"{HASH64}\"\n"));
        }
        if let Some(l) = f.listen {
            s.push_str(&format!("listen = \"{l}\"\n"));
        }
        if let Some((c, k)) = f.tls {
            s.push_str(&format!("tls_cert = \"{c}\"\ntls_key = \"{k}\"\n"));
        }
        let path = dir.path().join("config.toml");
        std::fs::write(&path, s).unwrap();
        path
    }

    /// The arguments of a call that would otherwise succeed, so a refusal
    /// test isolates exactly the one condition its fixture breaks.
    #[cfg(feature = "cluster")]
    fn good_sans() -> Vec<String> {
        vec!["192.0.2.10".to_string()]
    }

    #[cfg(feature = "cluster")]
    fn reachable() -> Option<std::net::SocketAddr> {
        Some("192.0.2.10:8053".parse().unwrap())
    }

    #[cfg(feature = "cluster")]
    fn assert_refused(
        master: &Path,
        before: &str,
        err: &anyhow::Error,
        expected: &str,
        which: &str,
    ) {
        let text = format!("{err:#}");
        assert!(
            text.contains(expected),
            "{which} must refuse with its own frozen string, got: {text}"
        );
        assert_eq!(
            before,
            std::fs::read_to_string(master).unwrap(),
            "{which}: a refusal must leave the master byte-identical"
        );
    }

    #[cfg(feature = "cluster")]
    fn material(dir: &tempfile::TempDir) -> (std::path::PathBuf, std::path::PathBuf) {
        (dir.path().join("api.crt"), dir.path().join("api.key"))
    }

    #[cfg(feature = "cluster")]
    fn mode_of(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn owner_of_reports_the_files_real_uid_gid() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("master.toml");
        std::fs::write(&f, b"x").unwrap();

        // Whatever uid the suite runs under — asserting against `getuid()`
        // rather than a literal keeps this true as root and as anyone else.
        let expected = unsafe { (libc::getuid(), libc::getgid()) };
        assert_eq!(owner_of(&f), Some(expected));
    }

    #[test]
    fn owner_of_is_none_when_the_reference_cannot_be_stat_d() {
        // The degradation path: an unstattable master must not abort the mint.
        // `create_exclusive` then simply skips the lchown, which is the old
        // behaviour — strictly no worse than before this guard existed.
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(owner_of(&dir.path().join("absent.toml")), None);
    }

    /// The mutation guard for the lchown, and it can only run as root.
    ///
    /// Delete the `lchown` block in `create_exclusive` and this goes red — but
    /// **only** in a root session, because the block is gated on
    /// `geteuid() == 0` for the seccomp reason documented there. Under an
    /// ordinary user there is nothing to observe: the created file is already
    /// owned by the caller, so a correct implementation and a gutted one are
    /// byte-identical on disk. That is why the primary defence is the required
    /// `owner_ref: &Path` parameter and not this assertion — a test that skips
    /// is not a test that protects.
    ///
    /// Feature-gated because `mode_of` above is: `create_exclusive` is only
    /// *reachable* through `run_enable`, which is `#[cfg(feature = "cluster")]`,
    /// so under the default build there is no live path to guard. Leaving this
    /// ungated broke the default config of `make test` with E0425 while
    /// `cargo test --features cluster` stayed green — the gate the other one
    /// cannot see.
    #[cfg(feature = "cluster")]
    #[test]
    fn a_file_created_as_root_inherits_the_reference_files_owner() {
        // SAFETY: geteuid takes no arguments and cannot fail.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!(
                "SKIPPED a_file_created_as_root_inherits_the_reference_files_owner: \
                 needs root; the lchown it checks is gated on geteuid() == 0"
            );
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        std::fs::write(&master, b"# master").unwrap();

        // `nobody` on Linux. Any uid that is NOT root's works — the point is
        // that the created file must follow the REFERENCE, not the caller.
        const NOBODY: u32 = 65534;
        std::os::unix::fs::lchown(&master, Some(NOBODY), Some(NOBODY)).unwrap();

        let crt = dir.path().join("api.crt");
        let key = dir.path().join("api.key");
        create_exclusive(&key, b"-----BEGIN-----\n", 0o600, &crt, &key, &master).unwrap();

        assert_eq!(
            owner_of(&key),
            Some((NOBODY, NOBODY)),
            "the key must be owned by the master's owner, not by root — \
             otherwise the daemon cannot open the key it is told to load"
        );
        assert_eq!(mode_of(&key), 0o600, "the private key must stay 0600");
    }

    /// R1 — `--role secondary` is refused by NAME, pointing at `cluster
    /// join`. The variant exists in `EnableRole` only so this refusal is
    /// reachable at all: with a single-variant enum the operator gets clap's
    /// "invalid value", which cannot name the verb they wanted.
    #[test]
    #[cfg(feature = "cluster")]
    fn enable_refuses_role_secondary() {
        let dir = tempfile::tempdir().unwrap();
        let master = write_primary_master(&dir, &PrimaryFixture::default());
        let before = std::fs::read_to_string(&master).unwrap();

        let err = run_enable(
            &master,
            crate::cli::EnableRole::Secondary,
            &good_sans(),
            reachable(),
            3650,
        )
        .unwrap_err();

        assert_refused(
            &master,
            &before,
            &err,
            crate::config::schema::cluster::CLUSTER_ENABLE_ROLE_SECONDARY_USE_JOIN,
            "R1",
        );
        let (crt, key) = material(&dir);
        assert!(!crt.exists() && !key.exists(), "R1 must mint nothing");
    }

    /// R2 — no `[cluster] token_hash`. Every other input is the one that
    /// would succeed, so nothing but the missing hash can be what refuses.
    #[test]
    #[cfg(feature = "cluster")]
    fn enable_refuses_without_a_cluster_token_hash() {
        let dir = tempfile::tempdir().unwrap();
        let master = write_primary_master(
            &dir,
            &PrimaryFixture {
                no_cluster_token: true,
                ..Default::default()
            },
        );
        let before = std::fs::read_to_string(&master).unwrap();

        let err = run_enable(
            &master,
            crate::cli::EnableRole::Primary,
            &good_sans(),
            reachable(),
            3650,
        )
        .unwrap_err();

        assert_refused(
            &master,
            &before,
            &err,
            crate::config::schema::cluster::CLUSTER_ENABLE_REQUIRES_TOKEN_HASH,
            "R2",
        );
    }

    /// R3 — no `--api-listen` on a node whose configured listen is the
    /// loopback default. This is the state of every fresh install, which is
    /// why the refusal names the flag rather than the TOML key.
    #[test]
    #[cfg(feature = "cluster")]
    fn enable_refuses_a_loopback_listen() {
        let dir = tempfile::tempdir().unwrap();
        let master = write_primary_master(&dir, &PrimaryFixture::default());
        let before = std::fs::read_to_string(&master).unwrap();

        let err = run_enable(
            &master,
            crate::cli::EnableRole::Primary,
            &good_sans(),
            None,
            3650,
        )
        .unwrap_err();

        assert_refused(
            &master,
            &before,
            &err,
            crate::config::schema::cluster::CLUSTER_ENABLE_LISTEN_IS_LOOPBACK,
            "R3",
        );
    }

    /// R3 again, via an explicitly loopback `--api-listen`. The check is on
    /// the RESULTING address, so passing the flag must not launder it.
    #[test]
    #[cfg(feature = "cluster")]
    fn enable_refuses_an_explicitly_loopback_api_listen() {
        let dir = tempfile::tempdir().unwrap();
        let master = write_primary_master(
            &dir,
            &PrimaryFixture {
                listen: Some("192.0.2.10:8053"),
                ..Default::default()
            },
        );
        let before = std::fs::read_to_string(&master).unwrap();

        let err = run_enable(
            &master,
            crate::cli::EnableRole::Primary,
            &good_sans(),
            Some("127.0.0.1:8053".parse().unwrap()),
            3650,
        )
        .unwrap_err();

        assert_refused(
            &master,
            &before,
            &err,
            crate::config::schema::cluster::CLUSTER_ENABLE_LISTEN_IS_LOOPBACK,
            "R3 (explicit)",
        );
    }

    /// R4 — no `[api] token_hash`. Without this check the verb would build a
    /// master `API_ENABLED_REQUIRES_TOKEN_HASH` refuses, failing late in the
    /// staged write and naming a temp path that no longer exists.
    #[test]
    #[cfg(feature = "cluster")]
    fn enable_refuses_without_an_api_token_hash() {
        let dir = tempfile::tempdir().unwrap();
        let master = write_primary_master(
            &dir,
            &PrimaryFixture {
                no_api_token: true,
                ..Default::default()
            },
        );
        let before = std::fs::read_to_string(&master).unwrap();

        let err = run_enable(
            &master,
            crate::cli::EnableRole::Primary,
            &good_sans(),
            reachable(),
            3650,
        )
        .unwrap_err();

        assert_refused(
            &master,
            &before,
            &err,
            crate::config::schema::cluster::CLUSTER_ENABLE_REQUIRES_API_TOKEN_HASH,
            "R4",
        );
    }

    /// R5 — minting with no `--san`. A SAN-less certificate matches no host,
    /// so it would fail every poll while looking perfectly well-formed.
    #[test]
    #[cfg(feature = "cluster")]
    fn enable_refuses_to_mint_without_a_san() {
        let dir = tempfile::tempdir().unwrap();
        let master = write_primary_master(&dir, &PrimaryFixture::default());
        let before = std::fs::read_to_string(&master).unwrap();

        let err = run_enable(
            &master,
            crate::cli::EnableRole::Primary,
            &[],
            reachable(),
            3650,
        )
        .unwrap_err();

        assert_refused(
            &master,
            &before,
            &err,
            crate::config::schema::cluster::CLUSTER_ENABLE_REQUIRES_SAN,
            "R5",
        );
        let (crt, key) = material(&dir);
        assert!(!crt.exists() && !key.exists(), "R5 must mint nothing");
    }

    /// R6 — existing material is never overwritten, and the message names
    /// BOTH absolute paths. The paths are the whole remedy: S4 ships no
    /// `--force`, so an operator not told what to remove has no way forward.
    #[test]
    #[cfg(feature = "cluster")]
    fn enable_refuses_to_overwrite_existing_material_and_names_both_paths() {
        let dir = tempfile::tempdir().unwrap();
        let master = write_primary_master(&dir, &PrimaryFixture::default());
        let (crt, key) = material(&dir);
        std::fs::write(&crt, "an already-pinned certificate").unwrap();
        let before = std::fs::read_to_string(&master).unwrap();

        let err = run_enable(
            &master,
            crate::cli::EnableRole::Primary,
            &good_sans(),
            reachable(),
            3650,
        )
        .unwrap_err();

        assert_refused(
            &master,
            &before,
            &err,
            // Only the prefix: the const carries a `{paths}` placeholder the
            // formatter substitutes, so the full literal never appears.
            "TLS material already exists beside the master config",
            "R6",
        );
        let text = format!("{err:#}");
        for p in [&crt, &key] {
            assert!(
                text.contains(&p.display().to_string()),
                "R6 must name {} — there is no --force, so the paths ARE the remedy: {text}",
                p.display()
            );
        }
        assert_eq!(
            std::fs::read_to_string(&crt).unwrap(),
            "an already-pinned certificate",
            "R6 must not have touched the existing certificate"
        );
        assert!(!key.exists(), "R6 must not have created the missing half");
    }

    /// R7 — `--san` with operator-supplied TLS material already configured:
    /// the minted certificate would be written and never used.
    #[test]
    #[cfg(feature = "cluster")]
    fn enable_refuses_a_san_when_the_config_already_carries_a_cert() {
        let dir = tempfile::tempdir().unwrap();
        let master = write_primary_master(
            &dir,
            &PrimaryFixture {
                tls: Some((
                    "/etc/purge-warden/operator.crt",
                    "/etc/purge-warden/operator.key",
                )),
                ..Default::default()
            },
        );
        let before = std::fs::read_to_string(&master).unwrap();

        let err = run_enable(
            &master,
            crate::cli::EnableRole::Primary,
            &good_sans(),
            reachable(),
            3650,
        )
        .unwrap_err();

        assert_refused(
            &master,
            &before,
            &err,
            crate::config::schema::cluster::CLUSTER_ENABLE_SAN_WITH_EXISTING_CERT,
            "R7",
        );
        let (crt, key) = material(&dir);
        assert!(!crt.exists() && !key.exists(), "R7 must mint nothing");
    }

    /// The happy path. Asserts the post state LOADS, not merely that the keys
    /// are present: a diff of the TOML proves the write happened, it does not
    /// prove the daemon could start from the result — which is the property
    /// `[cluster]` and `[api]` travelling in one staged write exists to buy.
    #[test]
    #[cfg(feature = "cluster")]
    fn enable_writes_cluster_and_api_together_and_the_result_loads() {
        let dir = tempfile::tempdir().unwrap();
        let master = write_primary_master(&dir, &PrimaryFixture::default());
        let (crt, key) = material(&dir);

        run_enable(
            &master,
            crate::cli::EnableRole::Primary,
            &good_sans(),
            reachable(),
            3650,
        )
        .unwrap();

        let now = time::OffsetDateTime::now_utc();
        let loaded = loader::load_config(&master, now).unwrap_or_else(|e| {
            panic!(
                "the post state must load: {}",
                crate::cli::commands::token::format_errs_flat(e)
            )
        });

        assert!(loaded.config.cluster.enabled);
        assert_eq!(loaded.config.cluster.role, ClusterRole::Primary);
        assert!(loaded.config.api.enabled);
        assert_eq!(
            loaded.config.api.listen,
            "192.0.2.10:8053".parse::<std::net::SocketAddr>().unwrap()
        );
        assert_eq!(loaded.config.api.tls_cert.as_deref(), Some(crt.as_path()));
        assert_eq!(loaded.config.api.tls_key.as_deref(), Some(key.as_path()));
        assert!(crt.exists() && key.exists());
        // The certificate path written into the config must be absolute, or
        // the daemon resolves it against ITS working directory.
        assert!(loaded.config.api.tls_cert.as_ref().unwrap().is_absolute());
    }

    /// The private key is `0600` **at creation** — never written first and
    /// chmod'd after, which would leave a world-readable window on a key.
    ///
    /// Exact equality is safe for `0600` specifically: `umask` can only clear
    /// bits, and `0600` has no group or other bits to clear. The certificate
    /// is asserted loosely for the mirror-image reason — `0644` under a
    /// `077` umask lands as `0600`, so `== 0o644` would be a fixture-
    /// dependent failure.
    #[test]
    #[cfg(feature = "cluster")]
    fn the_minted_private_key_is_0600_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let master = write_primary_master(&dir, &PrimaryFixture::default());
        let (crt, key) = material(&dir);

        run_enable(
            &master,
            crate::cli::EnableRole::Primary,
            &good_sans(),
            reachable(),
            3650,
        )
        .unwrap();

        assert_eq!(mode_of(&key), 0o600, "the private key must be 0600");
        assert_eq!(
            mode_of(&crt) & 0o022,
            0,
            "the certificate must not be group- or world-writable"
        );
    }

    /// R7's mirror, and NOT a refusal: operator TLS material already
    /// configured, no `--san` ⇒ generate nothing, write only `[cluster]` plus
    /// `api.enabled` / `listen`, and leave the operator's paths alone.
    #[test]
    #[cfg(feature = "cluster")]
    fn enable_with_an_existing_cert_and_no_san_generates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let master = write_primary_master(
            &dir,
            &PrimaryFixture {
                tls: Some((
                    "/etc/purge-warden/operator.crt",
                    "/etc/purge-warden/operator.key",
                )),
                ..Default::default()
            },
        );
        let (crt, key) = material(&dir);

        run_enable(
            &master,
            crate::cli::EnableRole::Primary,
            &[],
            reachable(),
            3650,
        )
        .unwrap();

        assert!(
            !crt.exists() && !key.exists(),
            "the mirror path must mint nothing"
        );
        let now = time::OffsetDateTime::now_utc();
        let loaded = loader::load_config(&master, now).unwrap_or_else(|e| {
            panic!(
                "the post state must load: {}",
                crate::cli::commands::token::format_errs_flat(e)
            )
        });
        assert!(loaded.config.cluster.enabled);
        assert!(loaded.config.api.enabled);
        assert_eq!(
            loaded.config.api.tls_cert.as_deref(),
            Some(Path::new("/etc/purge-warden/operator.crt")),
            "the operator's own certificate path must survive untouched"
        );
    }

    /// Absence of `--api-listen` preserves whatever the master carries — the
    /// same rule `join` follows for `peer_cert`. A flag's absence is not an
    /// instruction to overwrite.
    #[test]
    #[cfg(feature = "cluster")]
    fn enable_without_api_listen_keeps_a_reachable_configured_listen() {
        let dir = tempfile::tempdir().unwrap();
        let master = write_primary_master(
            &dir,
            &PrimaryFixture {
                listen: Some("192.0.2.11:9053"),
                ..Default::default()
            },
        );

        run_enable(
            &master,
            crate::cli::EnableRole::Primary,
            &good_sans(),
            None,
            3650,
        )
        .unwrap();

        let now = time::OffsetDateTime::now_utc();
        let loaded = loader::load_config(&master, now).unwrap();
        assert_eq!(
            loaded.config.api.listen,
            "192.0.2.11:9053".parse::<std::net::SocketAddr>().unwrap()
        );
    }

    /// `Path::new("config.toml").parent()` is `Some("")`, not `None`, and
    /// CLAUDE.md documents `./config.toml` as the dev path — so the empty
    /// parent is reachable. Left relative it would write `tls_cert =
    /// "api.crt"`, which the daemon resolves against its own working
    /// directory.
    ///
    /// Tested on the helper rather than through the verb on purpose: the only
    /// way to reach the branch end-to-end is to change the process working
    /// directory, which is global state and would race every other test in
    /// this binary. Ungated — the helper is not feature-dependent.
    #[test]
    fn a_bare_config_filename_still_yields_an_absolute_directory() {
        let d = config_dir(Path::new("config.toml")).unwrap();
        assert!(d.is_absolute(), "{} must be absolute", d.display());
        assert_eq!(d, std::env::current_dir().unwrap().canonicalize().unwrap());
    }
}
