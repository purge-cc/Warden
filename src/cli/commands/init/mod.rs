//! `warden init` — create system user, directories, default config.
//!
//! Requires root (euid 0). Every path it touches is derived from ONE
//! input — the config path — through `InitLayout`. With no `--config`
//! that input is `DEFAULT_CONFIG_PATH` and the layout is the historical
//! one:
//!
//! - System user `purge-warden` (no login shell, no home directory)
//! - /var/lib/purge-warden/            (config, lists, data)
//! - /var/lib/purge-warden/lists/      (downloaded blocklists)
//! - /var/lib/purge-warden/data/       (stats snapshots)
//! - /run/purge-warden/                (control socket, PID file)
//! - /var/lib/purge-warden/config.toml (default config, only if missing)
//!
//! With `--config <path>` every one of those moves with it. Before
//! cli-h9 the flag was parsed, accepted, and discarded: `run_init` took
//! no path at all and wrote to the constant regardless, so
//! `warden --config /tmp/x/config.toml init` provisioned
//! `/var/lib/purge-warden` and reported success.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::lists::catalog::{Catalog, DEFAULT_SOURCES};

pub(crate) mod upstream;

const USER: &str = "purge-warden";

/// Config master `warden init` provisions when no `--config` is given.
///
/// **Deliberately NOT `config_discovery::resolve_config_path`.** That
/// helper's no-config fallback is `/etc/purge-warden/config.toml` under
/// root, and `scripts/install.sh` hardcodes
/// `CONFIG_PATH="/var/lib/purge-warden/config.toml"`, calls `init --yes`
/// with no `--config`, and then dies if that exact file is absent.
/// Routing the unflagged path through discovery would relocate the master
/// out from under every existing provisioning script. So: an explicit
/// `--config` is honoured, and the unflagged default stays put.
pub(crate) const DEFAULT_CONFIG_PATH: &str = "/var/lib/purge-warden/config.toml";

/// neutrality-03: the whole message an operator sees when they run
/// `warden init` without `--upstream`. It is the ONLY thing standing
/// between them and a dead-end, because there is no compiled-in default
/// to fall back on any more — so it must name the flag, show the shape,
/// and give an example that is not a real provider (RFC 5737 TEST-NET-1).
///
/// A `const` rather than an inline literal so a test can read it. The
/// first version was inline and shipped with the source indentation
/// baked into the text; nothing asserted on it, so nothing caught it.
pub(crate) const UPSTREAM_MISSING: &str =
    "no upstream resolver configured. warden does not pick one for you \u{2014} \
     pass --upstream <addr:port>, comma-separated for several. \
     Example: --upstream 192.0.2.53:53";

/// Scaffold client ACL: RFC 1918 + loopback. An unspecified bind
/// (`0.0.0.0`/`::`)
/// with an EMPTY `allow_from` is an open resolver and the validator
/// refuses it — the scaffold must never ship that combination.
const DEFAULT_ALLOW_FROM: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
];
const DEFAULT_LISTEN: &str = "0.0.0.0:53";
/// neutrality-03: there is deliberately **no** default upstream.
///
/// This used to be Cloudflare, so every fresh install routed the whole
/// household's DNS to one named company that warden — not the operator —
/// chose. No non-empty value is neutral: any address favours someone. The
/// scaffold therefore ships an empty `upstream.servers`, which the
/// validator already rejects with the frozen `UPSTREAM_SERVERS_EMPTY`
/// message, so the operator is told exactly what to supply instead of
/// silently inheriting our preference. See project rules §Neutrality.
const NO_DEFAULT_UPSTREAMS: &[&str] = &[];

/// The config body `warden init --yes` writes with no overrides.
///
/// Delegates to [`render_default_config`] so there is exactly ONE
/// template in the tree — the former `DEFAULT_CONFIG` const drifted
/// from the render path (rev-2606: the const shipped dual-channel
/// list wiring with 404 entity URLs while tests exercised the const,
/// not the render). Consumers: `config edit`'s missing-file seed and
/// the tests below.
pub(crate) fn default_config() -> String {
    let sources: Vec<String> = DEFAULT_SOURCES.iter().map(|s| s.to_string()).collect();
    let lists = resolve_scaffold_lists(&sources)
        .expect("DEFAULT_SOURCES must resolve in the fallback catalog");
    let upstreams: Vec<String> = NO_DEFAULT_UPSTREAMS.iter().map(|s| s.to_string()).collect();
    let allow_from: Vec<String> = DEFAULT_ALLOW_FROM.iter().map(|s| s.to_string()).collect();
    render_default_config(
        "default",
        &lists,
        DEFAULT_LISTEN,
        &upstreams,
        &allow_from,
        &InitLayout::for_config(Path::new(DEFAULT_CONFIG_PATH)).socket_path,
    )
}

/// Every directory and file `warden init` provisions, derived from one
/// config path.
///
/// One derivation, one owner. The pre-cli-h9 code carried four unrelated
/// constants (`BASE_DIR`, `RUN_DIR`, `CONFIG_PATH`, and a socket path
/// baked into the render), which is why `--config` could move none of
/// them.
///
/// The `/etc` → `/var/lib` step is [`state_dir_for`] rather than a second
/// copy of that rule: `/etc/` is read-only under the daemon's
/// `ProtectSystem=strict` hardening, so mutable state has to live
/// elsewhere, and the audit log, lists cache, stats snapshot and query
/// log already agree on where.
///
/// [`state_dir_for`]: crate::cli::commands::start::state_dir_for
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InitLayout {
    /// The master config file to write.
    pub config_path: PathBuf,
    /// Directory holding the master. Equals `state_dir` on every layout
    /// except the FHS one, where the master is under `/etc/`.
    pub config_dir: PathBuf,
    /// Mutable-state root: `lists/`, `data/`, and on a dev layout the
    /// control socket too.
    pub state_dir: PathBuf,
    /// Runtime directory for the control socket. `Some` only for a system
    /// layout — a dev or temp install has no business creating `/run/…`.
    pub run_dir: Option<PathBuf>,
    /// Control socket path rendered into `[socket]`.
    pub socket_path: PathBuf,
}

impl InitLayout {
    /// Derive the full layout from the config master's path.
    pub fn for_config(config_path: &Path) -> Self {
        let config_dir = match config_path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let state_dir = crate::cli::commands::start::state_dir_for(&config_dir);

        // A system layout is one whose mutable state lands under
        // `/var/lib/<pkg>/` — either because the master is already there
        // (the legacy monolithic layout) or because `state_dir_for`
        // redirected it out of `/etc/<pkg>/`. Only those get a `/run/`
        // directory, because only those have systemd creating one.
        let run_dir = state_dir
            .strip_prefix("/var/lib")
            .ok()
            .and_then(|rest| rest.components().next())
            .map(|pkg| Path::new("/run").join(pkg.as_os_str()));

        // Dev/temp installs keep the socket beside their state, so an
        // operator who pointed `--config` at a directory they own does not
        // end up with a config demanding a `/run/` path they cannot write.
        let socket_path = match &run_dir {
            Some(run) => run.join("control.sock"),
            None => state_dir.join("control.sock"),
        };

        Self {
            config_path: config_path.to_path_buf(),
            config_dir,
            state_dir,
            run_dir,
            socket_path,
        }
    }

    /// Directories to create, in creation order, with their modes.
    fn dirs_to_create(&self) -> Vec<(PathBuf, u32)> {
        let mut dirs = vec![
            (self.state_dir.clone(), 0o750),
            (self.state_dir.join("lists"), 0o750),
            (self.state_dir.join("data"), 0o750),
        ];
        // Only the FHS layout splits these; elsewhere it is already in the
        // list above and `create_dir` would just report "directory exists".
        if self.config_dir != self.state_dir {
            dirs.push((self.config_dir.clone(), 0o750));
        }
        if let Some(run) = &self.run_dir {
            dirs.push((run.clone(), 0o755));
        }
        dirs
    }

    /// Roots to hand to the daemon user, recursively.
    fn chown_roots(&self) -> Vec<PathBuf> {
        let mut roots = vec![self.state_dir.clone()];
        if self.config_dir != self.state_dir {
            roots.push(self.config_dir.clone());
        }
        if let Some(run) = &self.run_dir {
            roots.push(run.clone());
        }
        roots
    }
}

/// CLI override values for `warden init` (rev-2606 P0-2: these back
/// the `--listen` / `--upstream` / `--allow-from` / `--lists` flags so
/// provisioning scripts — install.sh first among them — can drive a
/// fully non-interactive, fully specified scaffold). `None` falls back
/// to the interactive prompt where one exists, or the baked-in default
/// under `--yes`.
#[derive(Debug, Default)]
pub struct InitOverrides {
    /// `[server].listen` bind address (`addr:port`).
    pub listen: Option<String>,
    /// Comma-separated upstream resolvers (`addr:port`, plain mode).
    pub upstream: Option<String>,
    /// Comma-separated CIDRs for `[server].allow_from`.
    pub allow_from: Option<String>,
    /// Comma-separated catalog list ids to subscribe.
    pub lists: Option<String>,
    /// Path to the `upstreams.toml` menu catalog. Defaults to
    /// `<config_dir>/upstreams.toml`; absent is a supported state.
    pub upstream_catalog: Option<PathBuf>,
    /// `--cluster-secondary --peer <url>`: scaffold a §5.3 secondary
    /// master — node-local sections only, no policy at all. `None` is the
    /// ordinary standalone scaffold.
    pub cluster_secondary_peer: Option<String>,
}

/// Run `warden init`.
///
/// `explicit_config` — the operator's `--config <path>`, if they passed
///   one. Every directory init creates is derived from it via
///   `InitLayout`. `None` keeps the historical
///   `DEFAULT_CONFIG_PATH` layout byte-for-byte, which
///   `scripts/install.sh` depends on.
///
/// `force` — overwrite the target config if it already exists (the
///   existing file is renamed aside with a `.pre-init-<ts>` suffix so
///   the operator can recover from a mistaken overwrite).
///
/// `yes` — non-interactive mode: skip every prompt, use the baked-in
///   defaults (default profile = `default`, three pre-configured
///   blocklists, RFC 1918 + loopback `allow_from`). Intended for
///   provisioning scripts.
///
/// `overrides` — per-knob flag values; each one wins over both the
///   prompt and the `--yes` default for that knob.
pub fn run_init(
    explicit_config: Option<&Path>,
    force: bool,
    yes: bool,
    overrides: &InitOverrides,
) -> anyhow::Result<()> {
    // Must be root
    if !is_root() {
        anyhow::bail!("warden init requires root. Run with sudo.");
    }

    let layout =
        InitLayout::for_config(explicit_config.unwrap_or_else(|| Path::new(DEFAULT_CONFIG_PATH)));

    // Gather + validate every answer BEFORE mutating the system, so a
    // bad flag value or a typo'd list id fails fast with nothing
    // half-created. Flag values are typed-parsed here (SocketAddr /
    // Cidr / slug charset) — that is also what makes their later
    // interpolation into the TOML body injection-safe.
    let listen = match &overrides.listen {
        Some(v) => validated_listen(v)?,
        None => DEFAULT_LISTEN.to_string(),
    };
    // §5.3 — a cluster secondary's scaffold. Branches BEFORE upstream
    // resolution and before every prompt, because each of the three things
    // the standalone path gathers next (`[upstream]`, `[profiles.*]`,
    // `[[blocklists]]`) is policy the primary supplies, and a secondary's
    // master carrying its own is refused at load and at `join`.
    if let Some(peer) = overrides.cluster_secondary_peer.as_deref() {
        return run_init_cluster_secondary(&layout, force, &listen, peer, overrides);
    }

    // neutrality-03/-09: no vendor fallback, and warden still picks
    // nobody. The operator's flag wins; otherwise `init` proposes the
    // resolver THIS MACHINE already uses (its network chose it, we did
    // not) plus whatever the operator put in `upstreams.toml`.
    // `UPSTREAM_MISSING` survives as the refusal for the genuinely
    // undecidable case.
    let upstreams = upstream::resolve_upstreams(
        overrides.upstream.as_deref(),
        yes,
        &listen,
        &overrides
            .upstream_catalog
            .clone()
            .unwrap_or_else(|| layout.config_dir.join("upstreams.toml")),
    )?;

    let default_profile = if yes {
        "default".to_string()
    } else {
        prompt_default_profile()?
    };
    validated_default_profile(&default_profile)?;

    let list_inputs: Vec<String> = match &overrides.lists {
        Some(csv) => split_csv(csv),
        None if yes => DEFAULT_SOURCES.iter().map(|s| s.to_string()).collect(),
        None => prompt_lists()?,
    };
    let scaffold_lists = resolve_scaffold_lists(&list_inputs)?;

    let allow_from_inputs: Vec<String> = match &overrides.allow_from {
        Some(csv) => split_csv(csv),
        None if yes => DEFAULT_ALLOW_FROM.iter().map(|s| s.to_string()).collect(),
        None => prompt_allow_from()?,
    };
    let allow_from = validated_allow_from(&allow_from_inputs)?;

    let config_path = layout.config_path.as_path();
    let config_display = config_path.display();

    // Everything above either reads or prompts. Everything below mutates,
    // and `provision` cannot be called without the receipt this returns.
    let precondition = check_preconditions(config_path, force)?;
    provision(&layout, &precondition)?;

    let body = render_default_config(
        &default_profile,
        &scaffold_lists,
        &listen,
        &upstreams,
        &allow_from,
        &layout.socket_path,
    );

    // Honour `--force`: rename any existing config aside before writing.
    // `replacing_existing` is what the precondition check already
    // observed, so this does not re-`stat` the path and cannot disagree
    // with the decision that let us get this far.
    if precondition.replacing_existing {
        let ts = time::OffsetDateTime::now_utc()
            .format(&time::macros::format_description!(
                "[year][month][day]T[hour][minute][second]Z"
            ))
            .map_err(|e| anyhow::anyhow!("failed to format timestamp: {}", e))?;
        // Bump the name on a same-second collision so a rapid `--force`
        // re-run can't silently clobber the pre-init rollback copy (cli §9 #8).
        let backup = crate::cli::commands::make_unique_path(
            config_path.with_extension(format!("toml.pre-init-{ts}")),
        );
        std::fs::rename(config_path, &backup)?;
        println!("renamed previous config to {}", backup.display());
    }

    // §4.31 DISC-2: route the first-boot master through the hardened
    // atomic-write helper. Explicit mode 0o640 closes the 0o644 race
    // window the previous `fs::write` + `set_permissions` pair left
    // open (same antipattern documented at `src/config/audit.rs:476`).
    // The owner-preservation branch of the helper only fires when the
    // target already existed; we are on the first-write path so the
    // explicit `chown` call afterwards keeps the daemon-owned semantics.
    crate::config::atomic_write::hardened_atomic_write(
        config_path,
        body.as_bytes(),
        crate::config::atomic_write::AtomicWriteOpts {
            mode: Some(0o640),
            ..Default::default()
        },
    )?;
    chown(config_path)?;
    println!("created {config_display}");

    println!();
    println!("purge-warden initialized successfully");
    println!();
    if scaffold_lists.is_empty() {
        println!("WARNING: no blocklists subscribed — filtering is OFF until you add lists.");
    } else {
        println!("pre-configured lists:");
        for l in &scaffold_lists {
            println!("  - {}", l.slug);
        }
    }
    println!();
    println!("allowed client networks:");
    for cidr in &allow_from {
        println!("  - {cidr}");
    }
    println!();
    // The binary the operator just invoked is the one `setcap` must target,
    // so name it rather than guessing an install prefix.
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/usr/local/bin/warden"));
    print!("{}", next_steps(config_path, &listen, &exe));
    println!();
    println!("browse all available lists: warden lists catalog");
    println!("add another list:           warden blocklist add <id> --url <url>");
    println!("validate your config:       warden config lint");

    Ok(())
}

/// `warden init --cluster-secondary --peer <url>` (§5.3).
///
/// Writes the keep-list and nothing else: `schema_version`, `[server]`
/// (node-local fields only), `[api]`, `[socket]`, `[tracking]`, `[backup]`,
/// `[resource_budget]`, `[cluster]`. **No `[upstream]`, no `[[blocklists]]`,
/// no `[profiles.*]`** — those are policy, they arrive in the primary's
/// bundle, and a secondary master carrying its own copies is refused both at
/// load and by `cluster join`.
///
/// Two deliberate properties of the result:
///
/// - **`enabled = false`.** `join` turns it on, because `join` is what
///   supplies the `token_hash` the validator demands of any enabled cluster
///   node. A self-enabling scaffold would be refused for a missing credential
///   it has no way to have.
/// - **It does not load.** Only a node that is actually syncing earns the
///   missing-`[upstream]` exemption, so this state is refused — with
///   `CLUSTER_SECONDARY_NOT_YET_JOINED`, which names `cluster join` rather
///   than sending the operator to write the `[upstream]` that would then be
///   refused. A config that loaded here would produce a daemon answering
///   nothing, i.e. a failure at query time instead of at load time.
///
/// `--upstream`, `--lists` and `--upstream-catalog` are rejected by clap
/// before this runs; there is no path where a resolver address reaches this
/// scaffold.
fn run_init_cluster_secondary(
    layout: &InitLayout,
    force: bool,
    listen: &str,
    peer: &str,
    overrides: &InitOverrides,
) -> anyhow::Result<()> {
    if let Err(reason) = crate::config::schema::cluster::validate_peer_url(peer.trim()) {
        anyhow::bail!("--peer {reason}");
    }

    // Same ACL rules as the standalone scaffold: an unspecified bind with an
    // empty allow_from is an open resolver, on a secondary exactly as much as
    // on a primary.
    let allow_from_inputs: Vec<String> = match &overrides.allow_from {
        Some(csv) => split_csv(csv),
        None => DEFAULT_ALLOW_FROM.iter().map(|s| s.to_string()).collect(),
    };
    let allow_from = validated_allow_from(&allow_from_inputs)?;

    let config_path = layout.config_path.as_path();
    let precondition = check_preconditions(config_path, force)?;
    provision(layout, &precondition)?;

    let body = render_cluster_secondary_config(listen, &allow_from, &layout.socket_path, peer);

    write_cluster_secondary_scaffold(config_path, &body)?;
    chown(config_path)?;

    println!("created {} (cluster secondary)", config_path.display());
    println!();
    println!("This node carries NO policy of its own — lists, profiles, devices and");
    println!("the upstream all arrive from the primary. It will not start until it has");
    println!("joined, which is intended: a node with no resolver and no sync answers");
    println!("nothing, and failing now beats failing on the first query.");
    println!();
    println!("Next, on the PRIMARY:");
    println!("  warden cluster token          # prints the token once");
    println!();
    println!("then back here, keeping the token off the command line:");
    println!("  warden cluster join --peer {peer} --token-file <path>");
    println!();
    println!("after that: warden config lint   # should report a valid config");
    Ok(())
}

/// Write the §5.3 scaffold at `0o640`.
///
/// A seam, not decoration. [`run_init_cluster_secondary`] is unreachable from a
/// test — [`run_init`] bails on [`is_root`], and the two steps that need root
/// ([`provision`], which runs `useradd`, and [`chown`]) mutate the machine
/// running the suite. So the mode this config is created with — a security
/// property, since the file will carry `cluster.token_hash` — was asserted by
/// nothing at all.
///
/// Splitting the write out makes exactly that testable without pretending the
/// root-only steps are.
fn write_cluster_secondary_scaffold(config_path: &Path, body: &str) -> anyhow::Result<()> {
    crate::config::atomic_write::hardened_atomic_write(
        config_path,
        body.as_bytes(),
        crate::config::atomic_write::AtomicWriteOpts {
            mode: Some(0o640),
            ..Default::default()
        },
    )?;
    Ok(())
}

/// Render the §5.3 keep-list body for [`run_init_cluster_secondary`].
///
/// Built from typed parts, like [`render_default_config`], so the result is
/// valid TOML regardless of the answers. The absences are the point: any
/// section added here that the primary also replicates turns the scaffold
/// into a config `cluster join` refuses.
fn render_cluster_secondary_config(
    listen: &str,
    allow_from: &[String],
    socket_path: &Path,
    peer: &str,
) -> String {
    let quoted = allow_from
        .iter()
        .map(|s| format!("\"{s}\""))
        .collect::<Vec<_>>()
        .join(", ");

    let mut out = String::new();
    out.push_str("# purge-warden configuration — CLUSTER SECONDARY (schema v2)\n");
    out.push_str("# Generated by `warden init --cluster-secondary`.\n");
    out.push_str(
        "#\n\
         # This node's POLICY comes from its primary and is installed into\n\
         # cluster.d/ by the sync. Do not add [upstream], [[blocklists]],\n\
         # [profiles.*], [[devices]], [[groups]], [[subnets]], [[schedules]],\n\
         # [[admin_rules]] or [[labels]] here: the loader would MERGE them with\n\
         # the primary's bundle — concatenating lists silently — and this node\n\
         # would filter more than the primary does while sync reported success.\n\
         # The validator refuses such a master, and so does `cluster join`.\n",
    );
    out.push_str("\nschema_version = 3\n");

    out.push_str("\n[server]\n");
    out.push_str(&format!("listen = \"{listen}\"\n"));
    out.push_str(
        "# Node-local. The bundle supplies the POLICY half of [server]\n\
         # (default_profile and the block-response fallbacks); these fields\n\
         # are this box's own identity and never cross the wire.\n",
    );
    out.push_str(&format!("allow_from = [{quoted}]\n"));
    out.push_str("log_level = \"info\"\n");

    out.push_str("\n[cluster]\n");
    out.push_str(
        "# `enabled` stays false until `warden cluster join` runs: joining is\n\
         # what supplies the token_hash an enabled cluster node must have.\n",
    );
    out.push_str("enabled = false\n");
    out.push_str("role = \"secondary\"\n");
    out.push_str(&format!("peer = \"{peer}\"\n"));

    out.push_str("\n[socket]\n");
    out.push_str(&format!("path = \"{}\"\n", socket_path.display()));

    out.push_str("\n[api]\n");
    out.push_str("enabled = false\n");

    out.push_str("\n[tracking]\n");
    out.push_str("enabled = true\n");

    out.push_str("\n[backup]\n");
    out.push_str("# auto_interval = \"24h\"\n");

    out
}

/// The "next steps" block printed after a successful `warden init`.
///
/// Split out so the first words a new operator reads are testable.
///
/// **The token step is the one that was missing.** `init` does not create
/// an IPC token, and without one every Mutating/Admin-tier command refuses
/// up-front — `stop`, `reload`, and every config-editing verb — so an
/// operator who followed the old two-step list hit a wall on their next
/// command with nothing here having mentioned it.
///
/// `init` prints the command instead of generating a token itself, on
/// purpose:
///
/// - `token generate` writes `[api].token_hash` into the master through
///   the atomic write-and-revalidate path and prints the plaintext once.
///   Duplicating that inside `init` would give the scaffold a second
///   owner of the same field.
/// - The plaintext would land in the output of every provisioning script
///   that runs `init --yes`, which is a change to where secrets end up.
/// - `default_token_path()` is an FHS constant and does not follow
///   `--config`, so a token minted here for a non-default layout would be
///   saved somewhere that layout's daemon does not read.
///
/// **The start command needed a caveat.** It tells the operator to run the
/// daemon as the unprivileged `purge-warden` user, and the scaffold binds
/// port 53. Binding a port below [`FIRST_UNPRIVILEGED_PORT`] needs
/// `CAP_NET_BIND_SERVICE`, which `sudo -u` does not confer and which the
/// binary does not carry as a file capability — the packaged systemd unit
/// grants it with `AmbientCapabilities=`, and `init` neither installs nor
/// can see that unit. So the very first command a new operator was told to
/// run failed with EACCES, on a line printed by the tool itself.
fn next_steps(config_path: &Path, listen: &str, exe: &Path) -> String {
    let cfg = config_path.display();
    let mut out = String::from("next steps:\n");
    out.push_str(&format!("  1. (optional) edit {cfg} to customize lists\n"));
    // `--config` is a root-level clap flag (not `global = true`): it must
    // precede the subcommand or clap rejects it — container-smoke-proven.
    out.push_str("  2. create the admin token — every mutating command needs one:\n");
    out.push_str(&format!("       warden --config {cfg} token generate\n"));
    out.push_str("  3. start the daemon:\n");
    out.push_str(&format!(
        "       sudo -u {USER} warden --config {cfg} start --daemon\n"
    ));

    if let Some(port) = privileged_port(listen) {
        out.push_str(&format!(
            "\n     Port {port} is privileged: running as {USER} is not enough to bind\n\
             \x20    it. Grant the capability once —\n\
             \x20      setcap cap_net_bind_service=+ep {}\n\
             \x20    — or run the daemon from the packaged systemd unit, which grants\n\
             \x20    the same capability via AmbientCapabilities.\n",
            exe.display()
        ));
    }
    out
}

/// Ports below this need `CAP_NET_BIND_SERVICE` on Linux. (The
/// `net.ipv4.ip_unprivileged_port_start` sysctl can lower it, but the
/// default is what an operator meets on a fresh box.)
const FIRST_UNPRIVILEGED_PORT: u16 = 1024;

/// The port `listen` binds, if binding it needs a capability.
///
/// `listen` reached here through [`validated_listen`] or [`DEFAULT_LISTEN`],
/// so it parses; an unparseable value simply produces no caveat rather than
/// a wrong one.
fn privileged_port(listen: &str) -> Option<u16> {
    listen
        .parse::<std::net::SocketAddr>()
        .ok()
        .map(|a| a.port())
        .filter(|p| *p < FIRST_UNPRIVILEGED_PORT)
}

/// Receipt proving every `warden init` precondition passed.
///
/// Only [`check_preconditions`] can mint one and [`provision`] demands one,
/// so the compiler — not a comment, and not the order two blocks happen to
/// sit in — is what keeps the existence check ahead of the first mutation.
/// That ordering is the whole defect: the check used to run *after* a
/// `useradd`, four `create_dir` calls and two `chown -R` calls.
#[must_use]
#[derive(Debug)]
struct PreconditionsPassed {
    /// A config is already present AND `--force` authorised replacing it.
    /// Carried forward so the write phase does not re-`stat` the path and
    /// reach a different conclusion than the one that let it run.
    replacing_existing: bool,
}

/// Decide whether `warden init` may proceed. Reads only — no mutation.
///
/// Refusing here rather than after provisioning is the point: on an
/// existing install, `warden init` without `--force` used to create the
/// system user, create four directories and recursively re-own a live
/// deployment's config, lists and data, and only then decline to do the
/// thing the operator actually asked for.
fn check_preconditions(config_path: &Path, force: bool) -> anyhow::Result<PreconditionsPassed> {
    let exists = config_path.exists();
    if exists && !force {
        anyhow::bail!(
            "config already exists: {}. Pass --force to overwrite \
             (the existing file will be renamed with a .pre-init-<ts> suffix).",
            config_path.display()
        );
    }
    Ok(PreconditionsPassed {
        replacing_existing: exists,
    })
}

/// Create the directories, the system user, and hand ownership over.
///
/// Requires a [`PreconditionsPassed`] receipt, which is what makes the
/// ordering un-regressable rather than merely correct today.
///
/// Directories come before the user deliberately: an unwanted directory is
/// undone with `rmdir`, whereas a system user outlives any failure and
/// needs `userdel`. Least-reversible last.
fn provision(layout: &InitLayout, _precondition: &PreconditionsPassed) -> anyhow::Result<()> {
    for (dir, mode) in layout.dirs_to_create() {
        create_dir(&dir, mode)?;
    }

    // Idempotent — skips if the user already exists.
    create_system_user()?;

    for root in layout.chown_roots() {
        chown_recursive(&root)?;
    }
    Ok(())
}

/// Operator-facing refusal when a prompt hits end-of-stdin.
///
/// `warden init` without `--yes` is an interview. If stdin is closed
/// there is nobody to interview, and the honest answer is to say so
/// rather than to invent one.
pub const INIT_STDIN_CLOSED: &str = "stdin closed before this question was answered. Re-run `warden init --yes` to accept the defaults non-interactively.";

/// Prompt on stdout, read one line from stdin, and distinguish "the
/// operator pressed Enter" from "there is no operator".
///
/// The three prompts each did `stdin.read_line(&mut buf)?` and then
/// tested `buf.trim().is_empty()`. `read_line` returns `Ok(0)` at
/// end-of-stream and leaves the buffer empty, so EOF was indistinguishable
/// from Enter and `warden init < /dev/null` silently took every default.
///
/// That is benign *today* — the defaults happen to match `--yes`. It
/// stops being benign the first time a question has no safe default, and
/// at that point the failure is a config scaffolded from answers nobody
/// gave. Cheaper to separate the two cases now, while they still agree.
fn prompt_line(question: &str) -> anyhow::Result<String> {
    use std::io::Write;
    let mut stdout = std::io::stdout();
    print!("{question}");
    stdout.flush().ok();

    let mut buf = String::new();
    let read = std::io::stdin().read_line(&mut buf)?;
    if read == 0 {
        anyhow::bail!("{INIT_STDIN_CLOSED}");
    }
    Ok(buf.trim().to_string())
}

/// Q1 — default profile. We ship with `default` because every scaffold
/// already defines a matching profile section; naming a different id
/// would leave the config referencing a non-existent profile.
fn prompt_default_profile() -> anyhow::Result<String> {
    let answer = prompt_line(
        "default_profile for unmapped sources (press Enter for \"default\", or type \"none\" to REFUSE): ",
    )?;
    let answer = answer.as_str();
    Ok(if answer.is_empty() {
        "default".to_string()
    } else if answer.eq_ignore_ascii_case("none") {
        // Represented as an empty string in the render — the output
        // leaves `default_profile` commented out, meaning "REFUSED".
        String::new()
    } else {
        answer.to_string()
    })
}

/// Q2 — blocklist subscriptions. Default keeps the canonical three
/// (security/malicious + privacy/ads + privacy/tracking).
fn prompt_lists() -> anyhow::Result<Vec<String>> {
    let answer = prompt_line(&format!(
        "blocklist subscriptions (comma-separated; press Enter for all three defaults: {}): ",
        DEFAULT_SOURCES.join(", ")
    ))?;
    let answer = answer.as_str();
    Ok(if answer.is_empty() {
        DEFAULT_SOURCES.iter().map(|s| s.to_string()).collect()
    } else {
        split_csv(answer)
    })
}

/// Q3 — client ACL (rev-2606 P0-2 / init-01). The scaffold binds
/// 0.0.0.0, and an unspecified bind with an empty `allow_from` is an
/// open resolver the validator refuses — so init must collect a
/// non-empty ACL on every path.
fn prompt_allow_from() -> anyhow::Result<Vec<String>> {
    let answer = prompt_line(&format!(
        "allowed client networks (comma-separated CIDRs; press Enter for RFC1918 + loopback: {}): ",
        DEFAULT_ALLOW_FROM.join(", ")
    ))?;
    let answer = answer.as_str();
    Ok(if answer.is_empty() {
        DEFAULT_ALLOW_FROM.iter().map(|s| s.to_string()).collect()
    } else {
        split_csv(answer)
    })
}

fn split_csv(csv: &str) -> Vec<String> {
    csv.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Typed-parse gate for `--listen`. Returns the input unchanged on
/// success — the parse is the validation (and the injection guard:
/// a `SocketAddr` cannot contain quotes or newlines).
fn validated_listen(value: &str) -> anyhow::Result<String> {
    value.parse::<std::net::SocketAddr>().map_err(|e| {
        anyhow::anyhow!("--listen \"{value}\" is not a valid addr:port (e.g. 0.0.0.0:53): {e}")
    })?;
    Ok(value.to_string())
}

/// Typed-parse gate for `--upstream` (comma-separated `addr:port`,
/// plain mode — DoH/DoT upstreams are a post-init config edit).
fn validated_upstreams(csv: &str) -> anyhow::Result<Vec<String>> {
    let items = split_csv(csv);
    if items.is_empty() {
        anyhow::bail!("--upstream needs at least one addr:port (e.g. 192.0.2.53:53)");
    }
    for item in &items {
        item.parse::<std::net::SocketAddr>().map_err(|e| {
            anyhow::anyhow!(
                "--upstream entry \"{item}\" is not a valid addr:port (e.g. 192.0.2.53:53): {e}"
            )
        })?;
    }
    Ok(items)
}

/// Typed-parse gate for `default_profile` (init render escape, roundup-01).
///
/// `default_profile` is interpolated raw into the generated TOML
/// (`default_profile = "{x}"`, `[profiles.{x}]`). The other scaffold inputs are
/// typed-gated, so validate this one against the same id charset
/// (`config::schema::Id`) — a hostile or typo'd answer then fails fast with a
/// clear error instead of producing un-loadable TOML. An empty value means
/// REFUSED (the field is rendered commented-out) and is allowed.
fn validated_default_profile(value: &str) -> anyhow::Result<()> {
    if value.is_empty() {
        return Ok(());
    }
    crate::config::schema::Id::new(value)
        .map_err(|e| anyhow::anyhow!("default_profile \"{value}\" is not a valid id: {e}"))?;
    Ok(())
}

/// Typed-parse gate for the client ACL. Refuses an empty set: every
/// scaffold binds 0.0.0.0 by default and the validator refuses the
/// unspecified-bind + empty-allow_from combination.
fn validated_allow_from(items: &[String]) -> anyhow::Result<Vec<String>> {
    if items.is_empty() {
        anyhow::bail!(
            "allow_from cannot be empty: with the default 0.0.0.0 bind that would be an \
             open resolver. Pass CIDRs (e.g. --allow-from 192.168.1.0/24,127.0.0.0/8) or \
             [\"0.0.0.0/0\", \"::/0\"] to deliberately answer everyone."
        );
    }
    for item in items {
        crate::config::cidr::Cidr::parse(item).map_err(|e| {
            anyhow::anyhow!(
                "allow_from entry \"{item}\" is not a valid CIDR (e.g. 192.168.1.0/24): {e}"
            )
        })?;
    }
    Ok(items.to_vec())
}

/// A subscribed list resolved against the purge.cc catalog: the
/// `[[blocklists]]` entity row the scaffold will emit for it.
#[derive(Debug)]
struct ScaffoldList {
    slug: String,
    id: String,
    display_name: String,
    url: String,
}

/// Resolve subscription inputs (catalog slugs) into entity rows.
///
/// The scaffold is single-channel by design: every subscribed list
/// becomes a `[[blocklists]]` entity with the URL the catalog's
/// offline fallback table maps the slug to — the SAME table the
/// daemon's fetcher falls back to, so the scaffold can never invent a
/// URL shape the CDN doesn't serve (rev-2606 discovery: the previous
/// hand-rolled `https://lists.purge.cc/<scope>/<topic>.txt` form was
/// 404 fiction; the catalog serves flat `<topic>.txt`).
///
/// Raw URLs are refused: an entity row needs a stable kebab id and
/// there is no honest way to derive one from an arbitrary URL —
/// `warden blocklist add <id> --url <url>` is the post-init verb for
/// that. Unknown slugs are refused too (fail-fast beats a scaffold
/// that silently subscribes fewer lists than asked).
fn resolve_scaffold_lists(inputs: &[String]) -> anyhow::Result<Vec<ScaffoldList>> {
    let catalog = Catalog::fallback();
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(inputs.len());
    for raw in inputs {
        if !seen.insert(raw.clone()) {
            continue;
        }
        if raw.starts_with("http://") || raw.starts_with("https://") {
            anyhow::bail!(
                "\"{raw}\": raw URLs are not accepted by warden init — subscribe catalog ids \
                 here (see `warden lists catalog`), then add custom sources after init with: \
                 warden blocklist add <id> --url <url>"
            );
        }
        if !is_valid_slug(raw) {
            anyhow::bail!(
                "\"{raw}\" is not a valid list id (lowercase a-z, digits, '-', '/'); \
                 run `warden lists catalog` to see available lists"
            );
        }
        let url = catalog.resolve(raw).ok_or_else(|| {
            anyhow::anyhow!(
                "unknown list id \"{raw}\" — run `warden lists catalog` to see available lists"
            )
        })?;
        out.push(ScaffoldList {
            slug: raw.clone(),
            id: raw.replace('/', "-"),
            display_name: pretty_display_name(raw),
            url,
        });
    }
    Ok(out)
}

/// Charset gate for catalog slugs. Doubles as the TOML-injection guard
/// for every slug-derived string the render interpolates (id,
/// display_name): no quotes, no backslashes, no control characters.
fn is_valid_slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '/')
}

/// Render the v2 config body with the operator's choices substituted
/// in. Builds the scaffold from typed parts rather than string-patching
/// a static template so the result stays syntactically valid TOML
/// regardless of the answers.
fn render_default_config(
    default_profile: &str,
    lists: &[ScaffoldList],
    listen: &str,
    upstreams: &[String],
    allow_from: &[String],
    socket_path: &Path,
) -> String {
    let quote_join = |items: &[String]| -> String {
        items
            .iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(", ")
    };

    let mut out = String::new();
    out.push_str("# purge-warden configuration (schema v2 — lists & categories v2)\n");
    out.push_str("# Generated by `warden init`. See PROJECT.md for full reference.\n");
    out.push_str("\nschema_version = 3\n");

    out.push_str("\n[server]\n");
    out.push_str(&format!("listen = \"{listen}\"\n"));
    out.push_str(
        "# Source networks allowed to query. With an unspecified bind\n\
         # (0.0.0.0 / ::) a NON-EMPTY allow_from is required — the validator\n\
         # refuses the open-resolver combination. Answering the whole\n\
         # internet is an explicit opt-in: [\"0.0.0.0/0\", \"::/0\"].\n",
    );
    out.push_str(&format!("allow_from = [{}]\n", quote_join(allow_from)));
    out.push_str("log_level = \"info\"\n");
    if default_profile.is_empty() {
        out.push_str(
            "# SN2: leaving default_profile commented out means REFUSED for every\n\
             # source IP that doesn't match a [[devices]], [[groups]] or [[subnets]] row.\n\
             # default_profile = \"default\"\n",
        );
    } else {
        out.push_str(&format!("default_profile = \"{default_profile}\"\n"));
    }

    out.push_str("\n[upstream]\n");
    out.push_str("mode = \"plain\"\n");
    out.push_str(&format!("servers = [{}]\n", quote_join(upstreams)));
    out.push_str("timeout_ms = 5000\n");

    out.push_str("\n[lists]\n");
    out.push_str(
        "# Subscriptions live as [[blocklists]] entities below. This legacy\n\
         # slug channel stays empty on purpose; do NOT mirror the entities\n\
         # here as slugs (the two channels get separate filter bits and the\n\
         # profile ends up masking bits the downloads never populate —\n\
         # silent no-blocking).\n",
    );
    out.push_str("sources = []\n");
    out.push_str("update_interval_secs = 43200\n");

    out.push_str(
        "\n# What a profile does with a list is the list's own `base`\n\
         # (`deny` by default, so filtering is ON out of the box), unless\n\
         # that profile overrides it:\n\
         #\n\
         #   [profiles.kids]\n\
         #   lists = { social = \"allow\", gambling = \"deny\" }\n\
         #\n\
         # `deny` blocks the domains the list carries, `allow` permits\n\
         # them, `ignore` loads the list and applies it nowhere. Set one\n\
         # with `warden profile list-policy set <profile> <list> <policy>`;\n\
         # `warden profile list-policy show <profile>` prints what is in\n\
         # force and whether it was set there or inherited.\n",
    );

    // [[blocklists]] entity rows resolved from the subscribed slugs —
    // URLs come from the catalog fallback table (the same table the
    // fetcher uses), never hand-assembled.
    for l in lists {
        out.push_str(&format!("\n[[blocklists]]\nid = \"{}\"\n", l.id));
        out.push_str(&format!(
            "display_name = \"{}\"\nurl = \"{}\"\n",
            l.display_name, l.url,
        ));
    }

    // No `tags` key on the profile, and none on the blocklists above.
    //
    // `warden init` used to stamp `tags = ["uncategorized"]` on both,
    // because tag intersection was what made the bundled lists apply. It
    // has not been since the `plp-s3` cutover: `effective_direction` is
    // `profile.lists[list]` if present, else `list.base`, and `base`
    // defaults to `deny`. Filtering is ON out of the box for exactly the
    // same configs, by a mechanism that reads the key the operator can
    // see and change.
    //
    // Writing it anyway would be warden putting a value into the
    // operator's file that they never asked for and that decides nothing
    // — and the validator auto-promotes an untagged deny-list to the
    // sentinel at LOAD, so a writer emitting it is round-tripping a value
    // the loader synthesises. Both are named hazards in this repo.
    if !default_profile.is_empty() {
        out.push_str(&format!("\n[profiles.{default_profile}]\n"));
        out.push_str(&format!(
            "display_name = \"{}\"\n",
            pretty_profile_name(default_profile)
        ));
    }

    out.push_str("\n[cache]\n");
    out.push_str("max_entries = 10000\n");
    out.push_str("max_ttl_secs = 3600\n");
    out.push_str("min_ttl_secs = 60\n");
    out.push_str("negative_ttl_secs = 300\n");

    // Must match the directory init actually created. A hardcoded
    // `/run/purge-warden/control.sock` here meant an init at any other
    // location emitted a config pointing into a directory it had not
    // provisioned and the operator could not write — so the daemon that
    // config describes could never bind its control socket, and every IPC
    // verb would report "daemon not running".
    out.push_str("\n[socket]\n");
    out.push_str(&format!("path = \"{}\"\n", socket_path.display()));

    out.push_str(
        "\n# [api]\n\
         # enabled = false\n\
         # listen = \"127.0.0.1:8053\"\n\
         # tls_cert = \"\"\n\
         # tls_key = \"\"\n\
         # token_hash = \"\"  # set by: warden token generate\n\
         # rate_limit_per_minute = 60  # per client IP; 0 = disabled\n",
    );

    out.push_str(
        "\n# Example [[devices]] / [[groups]] / [[subnets]] entries (commented out)\n\
         # — uncomment and adapt to bind specific sources to specific profiles.\n\
         # See `_docs/features/config_architecture.md` §8 for the full schema.\n\
         #\n\
         # Field order below matches the Device struct. Any field left out\n\
         # (not just commented) is simply treated as \"not set\" — the file\n\
         # stays clean. Only `id` and `display_name` are required; everything\n\
         # else is optional.\n\
         #\n\
         # [[devices]]\n\
         # id           = \"alex-iphone-01\"        # stable key, lowercase-ascii-dashes; never rename\n\
         # display_name = \"Alex's phone\"        # human label shown in TUI / logs\n\
         # ip           = \"192.0.2.107\"              # optional static IP pin\n\
         # mac          = \"AA:BB:CC:DD:EE:FF\"        # optional primary MAC (uppercase)\n\
         # mac_aliases  = [\"22:33:44:55:66:77\"]      # optional extra MACs (iOS/Android randomisation)\n\
         # profile      = \"default\"                  # optional; wins over group/subnet\n\
         # groups       = [\"famiglia\"]               # optional group memberships (see [[groups]])\n\
         # tags         = [\"mobile\", \"personal\"]     # optional free-form labels (UI filter only)\n\
         # owner        = \"Alex\"                  # optional; purely descriptive\n\
         # device       = \"iPhone personale\"         # optional model/type description\n\
         # department   = \"famiglia\"                 # optional zone / department label\n\
         # notes        = \"compleanno gennaio\"       # optional free text\n\
         #\n\
         # [[subnets]]\n\
         # id = \"lan-guest\"\n\
         # display_name = \"Guest VLAN\"\n\
         # cidrs = [\"10.10.2.0/24\"]\n\
         # profile = \"default\"\n",
    );

    out
}

fn pretty_display_name(source: &str) -> String {
    // "privacy/ads" → "Privacy: ads". Good enough for the scaffold —
    // operators edit to taste.
    let (scope, name) = source.split_once('/').unwrap_or(("", source));
    if scope.is_empty() {
        name.to_string()
    } else {
        let mut s = scope.chars().next().unwrap().to_uppercase().to_string();
        s.push_str(&scope[1..]);
        format!("{s}: {name}")
    }
}

fn pretty_profile_name(id: &str) -> String {
    match id {
        "default" => "Default household profile".to_string(),
        other => format!("Profile {other}"),
    }
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn create_system_user() -> anyhow::Result<()> {
    // Check if user already exists
    let status = Command::new("id").arg(USER).output()?;
    if status.status.success() {
        println!("user '{USER}' already exists");
        return Ok(());
    }

    let output = Command::new("useradd")
        .args([
            "--system",
            "--no-create-home",
            "--shell",
            "/usr/sbin/nologin",
            USER,
        ])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("failed to create user '{USER}': {stderr}");
    }

    println!("created system user '{USER}'");
    Ok(())
}

fn create_dir(path: &Path, mode: u32) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use std::os::unix::fs::DirBuilderExt;

    let existed = path.exists();
    // `mkdir(2)` takes the mode itself, so a directory created here is never
    // briefly readable at the umask default the way a create-then-chmod pair
    // leaves it.
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(mode)
        .create(path)
        .with_context(|| format!("cannot create {} (mode {mode:o})", path.display()))?;
    // Unconditional, and each half covers what the other cannot. `mkdir` masks
    // the mode with umask, so it can only ever REMOVE bits — under a tight
    // umask the run dir would land at 0o700 and the socket would be
    // unreachable for non-root clients. And a directory that already existed,
    // from an older init or a bare `mkdir -p`, keeps whatever mode it had
    // until this reasserts the one declared here: init is the seat that
    // declares these modes, so a re-init that leaves the state dir
    // world-listable has not done its job.
    set_permissions(path, mode)?;
    if existed {
        println!("directory exists: {} (mode {mode:o})", path.display());
    } else {
        println!("created {} (mode {mode:o})", path.display());
    }
    Ok(())
}

fn set_permissions(path: &Path, mode: u32) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

fn chown(path: &Path) -> anyhow::Result<()> {
    let output = Command::new("chown")
        .args([Path::new(&format!("{USER}:{USER}")), path])
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("chown failed for {}: {stderr}", path.display());
    }
    Ok(())
}

fn chown_recursive(path: &Path) -> anyhow::Result<()> {
    // roundup-01: `-h` (`--no-dereference`) so a symlink encountered during the
    // recursive walk has ITS OWN ownership changed, never the target's. On a
    // first `init` the tree is freshly created and symlink-free, but a `--force`
    // re-init walks `/var/lib/purge-warden` which already holds daemon-written
    // `lists/` + `data/` — a symlink planted there by a compromised daemon user
    // must not let `chown -R` follow it to an arbitrary file. GNU coreutils
    // already defaults to no-follow (`-P`), but busybox/BSD differ and musl is
    // the prod target, so we force it explicitly.
    let output = Command::new("chown")
        .args([
            Path::new("-R"),
            Path::new("-h"),
            Path::new(&format!("{USER}:{USER}")),
            path,
        ])
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("chown -R failed for {}: {stderr}", path.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::ConfigV1;

    /// `dirs_to_create` declares a security-relevant mode per directory, and
    /// `init` is the seat that declares them — so a directory that already
    /// exists at a wider mode must be narrowed, not reported as fine. A
    /// pre-existing `0o755` state dir is what an older init, a package, or a
    /// bare `mkdir -p` leaves; it holds the device inventory and the admin
    /// token file.
    #[test]
    fn create_dir_converges_an_existing_directory_to_the_declared_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("state");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();

        create_dir(&target, 0o750).unwrap();

        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o750, "an existing directory kept its wider mode");
    }

    /// The other half: a directory this call creates lands at exactly the
    /// declared mode. `mkdir(2)` masks with umask and can only remove bits,
    /// so the mode is reasserted afterwards — under a tight umask a
    /// `mode()`-only create would land the run dir at 0o700 and make the
    /// socket unreachable for non-root clients.
    #[test]
    fn create_dir_creates_at_the_declared_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        for (name, mode) in [("state", 0o750u32), ("run", 0o755u32)] {
            let target = dir.path().join(name);
            create_dir(&target, mode).unwrap();
            let got = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
            assert_eq!(got, mode, "{name} landed at {got:o}, declared {mode:o}");
        }
    }

    /// Parents are created too, and re-running is a no-op that still
    /// converges — `init --force` walks this path for every declared dir.
    #[test]
    fn create_dir_is_idempotent_and_creates_parents() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("state").join("lists");
        create_dir(&nested, 0o750).unwrap();
        std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o777)).unwrap();
        create_dir(&nested, 0o750).unwrap();
        let mode = std::fs::metadata(&nested).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o750);
    }

    // ── cli-h9 defect 1: `--config` was accepted and discarded ──────────

    /// **The highest-value test in this sprint.** `scripts/install.sh:28`
    /// hardcodes `CONFIG_PATH="/var/lib/purge-warden/config.toml"`, runs
    /// `init --yes` with no `--config` (line 550), and then dies if that
    /// exact file is missing. The installer is not ours to edit, so the
    /// unflagged layout must stay byte-for-byte what it was before this
    /// sprint — every field, not just the config path.
    #[test]
    fn unflagged_layout_is_unchanged_from_the_pre_h9_constants() {
        let l = InitLayout::for_config(Path::new(DEFAULT_CONFIG_PATH));

        // The four pre-h9 constants, verbatim.
        assert_eq!(
            l.config_path,
            Path::new("/var/lib/purge-warden/config.toml"),
            "install.sh dies if init stops writing exactly here"
        );
        assert_eq!(l.state_dir, Path::new("/var/lib/purge-warden"), "BASE_DIR");
        assert_eq!(l.config_dir, Path::new("/var/lib/purge-warden"));
        assert_eq!(l.run_dir.as_deref(), Some(Path::new("/run/purge-warden")));
        assert_eq!(
            l.socket_path,
            Path::new("/run/purge-warden/control.sock"),
            "the socket the rendered config points at"
        );

        // And the exact directory set, in the pre-h9 creation order.
        let dirs: Vec<_> = l.dirs_to_create().into_iter().collect();
        assert_eq!(
            dirs,
            vec![
                (PathBuf::from("/var/lib/purge-warden"), 0o750),
                (PathBuf::from("/var/lib/purge-warden/lists"), 0o750),
                (PathBuf::from("/var/lib/purge-warden/data"), 0o750),
                (PathBuf::from("/run/purge-warden"), 0o755),
            ],
        );
        assert_eq!(
            l.chown_roots(),
            vec![
                PathBuf::from("/var/lib/purge-warden"),
                PathBuf::from("/run/purge-warden"),
            ],
        );
    }

    /// An explicit `--config` under a temp dir must move EVERYTHING. The
    /// discriminating assertions are the negative ones: pre-h9 the layout
    /// was the constants regardless of what was passed, so a test that
    /// only checked `config_path` would have passed on the bug the moment
    /// the field existed.
    #[test]
    fn explicit_config_moves_every_path_off_the_system_roots() {
        let l = InitLayout::for_config(Path::new("/tmp/h9-scratch/config.toml"));

        assert_eq!(l.config_path, Path::new("/tmp/h9-scratch/config.toml"));
        assert_eq!(l.config_dir, Path::new("/tmp/h9-scratch"));
        assert_eq!(l.state_dir, Path::new("/tmp/h9-scratch"));
        assert_eq!(
            l.run_dir, None,
            "a temp install must not provision /run/purge-warden"
        );
        assert_eq!(l.socket_path, Path::new("/tmp/h9-scratch/control.sock"));

        // Nothing anywhere in the layout may reference a system root.
        let mut touched: Vec<PathBuf> = l.dirs_to_create().into_iter().map(|(p, _)| p).collect();
        touched.extend(l.chown_roots());
        touched.push(l.socket_path.clone());
        touched.push(l.config_path.clone());
        for p in &touched {
            let s = p.to_string_lossy();
            assert!(
                !s.starts_with("/var/lib") && !s.starts_with("/run") && !s.starts_with("/etc"),
                "explicit --config still reaches a system root: {s}"
            );
        }
    }

    /// The FHS layout: master under `/etc/`, mutable state under
    /// `/var/lib/`. `/etc/` is read-only under `ProtectSystem=strict`, so
    /// `lists/` and `data/` must not land beside the master — and the
    /// `/etc/` directory itself still has to be created and handed over.
    #[test]
    fn etc_master_splits_config_dir_from_state_dir() {
        let l = InitLayout::for_config(Path::new("/etc/purge-warden/config.toml"));

        assert_eq!(l.config_dir, Path::new("/etc/purge-warden"));
        assert_eq!(l.state_dir, Path::new("/var/lib/purge-warden"));
        assert_eq!(l.run_dir.as_deref(), Some(Path::new("/run/purge-warden")));
        assert_eq!(l.socket_path, Path::new("/run/purge-warden/control.sock"));

        let dirs: Vec<PathBuf> = l.dirs_to_create().into_iter().map(|(p, _)| p).collect();
        assert!(
            dirs.contains(&PathBuf::from("/etc/purge-warden")),
            "the /etc master's own directory must be created: {dirs:?}"
        );
        assert!(
            dirs.contains(&PathBuf::from("/var/lib/purge-warden/lists")),
            "lists must live under /var/lib, not /etc: {dirs:?}"
        );
        assert!(
            !dirs.contains(&PathBuf::from("/etc/purge-warden/lists")),
            "a writable dir under ProtectSystem=strict /etc is unusable: {dirs:?}"
        );
        assert!(l
            .chown_roots()
            .contains(&PathBuf::from("/etc/purge-warden")));
    }

    /// cli-h9: the rendered `[socket] path` must name a directory init
    /// actually created. It was a hardcoded `/run/purge-warden/control.sock`
    /// regardless of layout, so an init anywhere else produced a config
    /// describing a socket the daemon could never bind — and every IPC verb
    /// would then report "daemon not running" against a live daemon.
    ///
    /// Entailed by the layout commit: reverting one requires reverting both,
    /// or `--config` moves the directories while the socket stays behind.
    #[test]
    fn rendered_socket_path_follows_the_layout() {
        let lists = resolve_scaffold_lists(&["privacy/ads".to_string()]).unwrap();
        let upstreams = vec!["1.1.1.1:53".to_string()];
        let allow_from = vec!["127.0.0.0/8".to_string()];

        let temp = InitLayout::for_config(Path::new("/tmp/h9-scratch/config.toml"));
        let body = render_default_config(
            "default",
            &lists,
            "127.0.0.1:15353",
            &upstreams,
            &allow_from,
            &temp.socket_path,
        );
        assert!(
            body.contains("path = \"/tmp/h9-scratch/control.sock\""),
            "socket must sit in the directory init created: {body}"
        );
        assert!(
            !body.contains("/run/purge-warden"),
            "a temp install's config must not reference /run/purge-warden: {body}"
        );

        // It still has to be a config the daemon can load.
        let cfg: ConfigV1 = toml::from_str(&body).expect("temp-layout render parses");
        assert_eq!(
            cfg.socket.path,
            Path::new("/tmp/h9-scratch/control.sock"),
            "the parsed socket is what the daemon will bind"
        );
    }

    // ── §5.3: the cluster-secondary scaffold ────────────────────────────
    //
    // WHAT IS AND IS NOT COVERED HERE — declared, not implied.
    //
    // Covered: the rendered body, the file mode, and the two refusals that
    // fire before anything is created (`--peer`, `allow_from`). Those reach
    // `run_init_cluster_secondary` itself, not merely the renderer.
    //
    // NOT covered, and not coverable in this suite: `provision` and `chown`.
    // `provision` runs `useradd` and `chown -R` against real system paths, so
    // exercising it would create a `purge-warden` account on whatever machine
    // runs `cargo test` — a test that mutates the developer's box is worse
    // than a gap. `run_init` bails on `is_root` for the same reason, which is
    // why the seam is drawn at `write_cluster_secondary_scaffold` rather than
    // by faking root.
    //
    // The consequence is real, and writing it down is the point: the ORDER of
    // provision → write → chown, and the ownership those two steps establish,
    // are proven only by the live host smoke. Do not read the green tests
    // below as covering them.

    fn secondary_scaffold(dir: &Path) -> String {
        render_cluster_secondary_config(
            "0.0.0.0:53",
            &["192.0.2.0/24".to_string()],
            &dir.join("control.sock"),
            "https://192.0.2.10:8053",
        )
    }

    /// The scaffold is created `0o640`, not the umask default.
    ///
    /// It will hold `cluster.token_hash` after `join`, and it names the peer.
    /// Nothing asserted this before: `run_init` bails on `is_root`, so the
    /// whole secondary branch — mode included — ran under no test.
    ///
    /// `0o640` and not `0o600`: the daemon reads this config as the
    /// `purge-warden` group, which `chown` sets on the next line.
    #[test]
    fn the_cluster_secondary_scaffold_is_written_group_readable_not_world() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_cluster_secondary_scaffold(&path, &secondary_scaffold(dir.path())).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "got {mode:o}, want 640");
    }

    /// `--peer` is validated BEFORE `provision` runs, so the refusal is
    /// reachable without root and this covers the real entry point rather
    /// than the renderer.
    ///
    /// A plaintext off-box peer is the discriminating input: the cluster
    /// token is sent on every poll, so `http://` off loopback would leak the
    /// credential in cleartext.
    #[test]
    fn the_cluster_secondary_init_refuses_a_plaintext_offbox_peer() {
        let dir = tempfile::tempdir().unwrap();
        let layout = InitLayout::for_config(&dir.path().join("config.toml"));
        let overrides = InitOverrides {
            cluster_secondary_peer: Some("http://192.0.2.10:8053".to_string()),
            ..Default::default()
        };

        let err = run_init_cluster_secondary(
            &layout,
            false,
            "0.0.0.0:53",
            "http://192.0.2.10:8053",
            &overrides,
        )
        .expect_err("a plaintext off-box peer must be refused");

        assert!(
            err.to_string().contains("--peer"),
            "the refusal must name the flag, got: {err}"
        );
        assert!(
            !layout.config_path.exists(),
            "a refused init must not create the config"
        );
    }

    /// …and so is the ACL, on BOTH of `validated_allow_from`'s refusals.
    ///
    /// The two are different guards and a test that hits only one is
    /// mis-named. `allow_from = []` is the **open-resolver** guard: with the
    /// default `0.0.0.0` bind an empty ACL answers the whole internet. A
    /// malformed entry is a **parse** guard. An implementation that dropped
    /// the open-resolver check while keeping the CIDR parser would leave a
    /// parse-only test green — which is exactly what this test used to be, and
    /// it was named for the guard it did not exercise.
    ///
    /// A secondary does not get a pass on either because its policy arrives
    /// from elsewhere: the bind is node-local and so is the exposure.
    #[test]
    fn the_cluster_secondary_init_refuses_both_open_and_malformed_acls() {
        for (allow_from, want_in_msg) in [
            (Some(String::new()), "open resolver"),
            (Some("not-a-cidr".to_string()), "not a valid CIDR"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let layout = InitLayout::for_config(&dir.path().join("config.toml"));
            let overrides = InitOverrides {
                cluster_secondary_peer: Some("https://192.0.2.10:8053".to_string()),
                allow_from,
                ..Default::default()
            };

            let err = run_init_cluster_secondary(
                &layout,
                false,
                "0.0.0.0:53",
                "https://192.0.2.10:8053",
                &overrides,
            )
            .expect_err("this ACL must be refused");

            assert!(
                err.to_string().contains(want_in_msg),
                "wrong guard fired — wanted {want_in_msg:?}, got: {err}"
            );
            assert!(
                !layout.config_path.exists(),
                "a refused init must not create the config"
            );
        }
    }

    /// The scaffold must carry NO policy. Every section listed here is one
    /// the primary replicates, so writing it would produce a master that
    /// `cluster join` refuses and the loader refuses after that.
    #[test]
    fn the_cluster_secondary_scaffold_carries_no_policy() {
        let dir = tempfile::tempdir().unwrap();
        let body = secondary_scaffold(dir.path());
        // Scan the TOML, not the prose. The scaffold's header comment NAMES
        // the forbidden sections in order to warn about them, and a naive
        // substring scan over the whole file reads that warning as the
        // violation it warns against.
        let toml_only: String = body
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n");

        for section in [
            "[upstream]",
            "[[blocklists]]",
            "[profiles.",
            "[[devices]]",
            "[[groups]]",
            "[[subnets]]",
            "[[schedules]]",
            "[[admin_rules]]",
            "[[labels]]",
        ] {
            assert!(
                !toml_only.contains(section),
                "scaffold must not write {section}: {body}"
            );
        }
        // And no resolver address may appear anywhere — warden does not
        // choose one for anyone, least of all where the primary will.
        // The resolver-literal check DOES scan the whole file, comments
        // included: an address in a comment is still warden naming a
        // provider, and an operator uncommenting it is the likeliest
        // outcome of putting one there.
        assert!(
            !body.contains("1.1.1.1") && !body.contains("dns-query") && !body.contains("9.9.9.9"),
            "warden does not choose a resolver for anyone: {body}"
        );
        // It is still a config, not a fragment.
        let cfg: ConfigV1 = toml::from_str(&body).expect("the scaffold parses as v1");
        assert_eq!(
            cfg.cluster.role,
            crate::config::schema::ClusterRole::Secondary
        );
        assert!(
            !cfg.cluster.enabled,
            "join turns clustering on -- it is what supplies the token_hash"
        );
        assert!(cfg.upstream.servers.is_empty(), "no resolver, by design");
    }

    /// Pre-join the scaffold does NOT load, and the refusal must name
    /// `cluster join`. The generic emptiness error sends the operator to
    /// `init --upstream`, i.e. to hand-write the one section a secondary's
    /// master may not carry -- an instruction whose only outcome is a
    /// second refusal.
    #[test]
    fn the_unjoined_cluster_secondary_scaffold_is_refused_and_names_join() {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        std::fs::write(&master, secondary_scaffold(dir.path())).unwrap();

        let errs = crate::config::loader::load_config(&master, time::OffsetDateTime::now_utc())
            .expect_err("an unjoined secondary is not a bootable node");
        let text = errs
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            text.contains("cluster join"),
            "the refusal must point at join: {text}"
        );
        assert!(
            !text.contains("init --upstream"),
            "must not send the operator to hand-write [upstream]: {text}"
        );
    }

    /// The end-to-end claim S2 exists to make: the documented path to a
    /// second node produces a master that `join` ACCEPTS and that LOADS
    /// once joined. Before S2 the scaffold had to be hand-edited, and the
    /// hand-edit was itself refused.
    #[cfg(feature = "cluster")]
    #[test]
    fn the_cluster_secondary_scaffold_is_joinable_and_loads_after() {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        std::fs::write(&master, secondary_scaffold(dir.path())).unwrap();

        let tok = dir.path().join("tok");
        std::fs::write(&tok, "ps_scaffoldsecret\n").unwrap();
        crate::cli::commands::cluster::run_join(
            &master,
            "https://192.0.2.10:8053",
            None,
            Some(&tok),
        )
        .expect("the scaffold is exactly what join is for");

        let loaded = crate::config::loader::load_config(&master, time::OffsetDateTime::now_utc())
            .expect("a joined, policy-free secondary master loads");
        assert!(loaded.config.cluster.enabled);
        assert!(
            loaded.config.upstream.servers.is_empty(),
            "still no policy of its own -- the bundle brings it"
        );
    }

    // ── cli-h9 defect 3: init left the operator without a token ─────────

    /// `init` creates no IPC token, and every Mutating/Admin command
    /// refuses without one. The old block listed two steps — edit, start —
    /// and never mentioned it, so the operator's next command failed with
    /// nothing in the first-hour path having warned them.
    ///
    /// Asserting the block is non-empty would pass on the bug; the
    /// assertion is that it names the verb, and names it before `start`.
    #[test]
    fn next_steps_tells_the_operator_to_create_a_token() {
        let steps = next_steps(
            Path::new("/var/lib/purge-warden/config.toml"),
            DEFAULT_LISTEN,
            Path::new("/usr/local/bin/warden"),
        );

        assert!(
            steps.contains("token generate"),
            "the token step is what was missing: {steps}"
        );
        let token_at = steps.find("token generate").unwrap();
        let start_at = steps.find("start --daemon").unwrap();
        assert!(
            token_at < start_at,
            "the daemon must learn the hash at boot, so the token comes first: {steps}"
        );
    }

    /// Every command in the block must carry `--config <the path init just
    /// wrote>`. `--config` is a root-level flag, so it also has to sit
    /// before the subcommand or clap rejects it.
    #[test]
    fn next_steps_point_every_command_at_the_config_init_wrote() {
        let steps = next_steps(
            Path::new("/tmp/h9-scratch/config.toml"),
            DEFAULT_LISTEN,
            Path::new("/usr/local/bin/warden"),
        );

        assert!(
            steps.contains("warden --config /tmp/h9-scratch/config.toml token generate"),
            "token step must target the config init wrote: {steps}"
        );
        assert!(
            steps.contains("warden --config /tmp/h9-scratch/config.toml start --daemon"),
            "start step must target the config init wrote: {steps}"
        );
        assert!(
            !steps.contains("/var/lib/purge-warden"),
            "a --config init must not send the operator to the default layout: {steps}"
        );
    }

    // ── cli-h9 defect 7: the printed start command could not work ───────

    /// The scaffold binds :53 and the block tells the operator to run as
    /// the unprivileged `purge-warden` user. `sudo -u` confers no
    /// capability and the binary carries no file capability (the systemd
    /// unit grants `CAP_NET_BIND_SERVICE` via `AmbientCapabilities=`, and
    /// `init` neither installs nor can see that unit), so the command the
    /// tool printed failed with EACCES.
    ///
    /// Measured on the dev box: `net.ipv4.ip_unprivileged_port_start=1024`
    /// and binding a privileged port as uid 1000 returns EACCES.
    #[test]
    fn privileged_listen_port_gets_a_capability_caveat() {
        let steps = next_steps(
            Path::new("/var/lib/purge-warden/config.toml"),
            "0.0.0.0:53",
            Path::new("/usr/local/bin/warden"),
        );

        assert!(
            steps.contains("CAP_NET_BIND_SERVICE") || steps.contains("cap_net_bind_service"),
            "must name the capability that is actually missing: {steps}"
        );
        assert!(
            steps.contains("setcap cap_net_bind_service=+ep /usr/local/bin/warden"),
            "must give a runnable remedy naming the binary: {steps}"
        );
        assert!(
            steps.contains("Port 53 is privileged"),
            "must say which port and why: {steps}"
        );
    }

    /// …and an unprivileged port gets no caveat. Printing the capability
    /// note unconditionally would be its own species of the same defect:
    /// telling the operator to fix something that is not broken.
    #[test]
    fn unprivileged_listen_port_gets_no_caveat() {
        let steps = next_steps(
            Path::new("/tmp/h9-scratch/config.toml"),
            "127.0.0.1:15353",
            Path::new("/usr/local/bin/warden"),
        );
        assert!(
            !steps.contains("setcap"),
            "port 15353 needs no capability: {steps}"
        );
        assert!(!steps.contains("privileged"), "{steps}");
    }

    /// The boundary, and the guard against a malformed value inventing a
    /// caveat.
    #[test]
    fn privileged_port_detection_boundaries() {
        assert_eq!(privileged_port("0.0.0.0:53"), Some(53));
        assert_eq!(privileged_port("[::]:80"), Some(80));
        assert_eq!(privileged_port("0.0.0.0:1023"), Some(1023));
        assert_eq!(privileged_port("0.0.0.0:1024"), None);
        assert_eq!(privileged_port("127.0.0.1:15353"), None);
        assert_eq!(
            privileged_port("not-an-addr"),
            None,
            "an unparseable listen must produce no caveat rather than a wrong one"
        );
    }

    // ── cli-h9 defect 2: init mutated before checking ───────────────────

    /// An existing config without `--force` is refused, and the refusal is
    /// a *read-only* outcome: `check_preconditions` performs no mutation,
    /// and `provision` — the only thing that does — cannot be called
    /// without the receipt this fails to produce.
    #[test]
    fn existing_config_without_force_is_refused_before_any_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            "schema_version = 3\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        )
        .unwrap();

        let err = check_preconditions(&config, false)
            .expect_err("an existing config without --force must refuse")
            .to_string();
        assert!(err.contains("already exists"), "{err}");
        assert!(err.contains("--force"), "must name the way forward: {err}");

        // The refusal touched nothing: still exactly the file we wrote.
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "the check must not create anything: {entries:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&config).unwrap(),
            "schema_version = 3\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
            "the check must not rewrite the config it refused"
        );
    }

    /// `--force` authorises the overwrite, and the receipt remembers that a
    /// file was there so the write phase renames it aside instead of
    /// re-`stat`ing and possibly disagreeing.
    #[test]
    fn force_authorises_replacement_and_records_it() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            "schema_version = 3\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        )
        .unwrap();

        let pre = check_preconditions(&config, true).expect("--force must be allowed");
        assert!(
            pre.replacing_existing,
            "the rename-aside step keys off this flag"
        );
    }

    /// A fresh install passes with nothing to replace.
    #[test]
    fn absent_config_passes_with_nothing_to_replace() {
        let dir = tempfile::tempdir().unwrap();
        let pre = check_preconditions(&dir.path().join("config.toml"), false)
            .expect("a fresh install must proceed");
        assert!(!pre.replacing_existing);
    }

    /// A relative `--config` must not produce an empty parent that
    /// `create_dir_all("")` would fail on.
    #[test]
    fn bare_filename_config_falls_back_to_the_cwd() {
        let l = InitLayout::for_config(Path::new("config.toml"));
        assert_eq!(l.config_dir, Path::new("."));
        assert_eq!(l.state_dir, Path::new("."));
        assert_eq!(l.run_dir, None);
        assert_eq!(l.socket_path, Path::new("./control.sock"));
    }

    #[test]
    fn validated_default_profile_accepts_empty_and_clean_ids() {
        // Empty == REFUSED sentinel (rendered commented out).
        assert!(validated_default_profile("").is_ok());
        assert!(validated_default_profile("default").is_ok());
        assert!(validated_default_profile("kids-safe").is_ok());
    }

    #[test]
    fn validated_default_profile_rejects_hostile_or_typod_ids() {
        // roundup-01: a TOML-breaking / injection attempt or any non-charset
        // value must be refused before it reaches `render_default_config`.
        assert!(validated_default_profile("a\"]\nevil = true").is_err());
        assert!(validated_default_profile("Has Spaces").is_err());
        assert!(validated_default_profile("../etc").is_err());
        assert!(validated_default_profile("UPPER").is_err());
    }

    /// neutrality-03 — the scaffold must not route a fresh install's
    /// entire DNS traffic to a provider warden picked.
    ///
    /// `DEFAULT_UPSTREAMS` used to be Cloudflare (`1.1.1.1:53`,
    /// `1.0.0.1:53`), so every `warden init` handed one named company the
    /// household's full query stream by default. There is no neutral
    /// non-empty default — any address favours someone — so the scaffold
    /// ships none and the operator states one. See project rules §Neutrality.
    #[test]
    fn neutrality03_scaffold_ships_no_vendor_upstream() {
        let body = default_config();
        for probe in [
            "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "208.67.", "94.140.",
        ] {
            assert!(
                !body.contains(probe),
                "the init scaffold must not name a third-party resolver; found {probe}"
            );
        }
        let cfg: ConfigV1 = toml::from_str(&body).unwrap();
        assert!(
            cfg.upstream.servers.is_empty(),
            "the scaffold must leave upstream.servers for the operator to fill"
        );
    }

    /// neutrality-03: the dead-end message is the only recovery surface a
    /// fresh operator gets, so it has to READ like prose in a terminal.
    /// The first version was an inline multi-line literal whose source
    /// indentation ended up inside the string — on the CT it printed as
    /// `for you \u{2014}                  pass --upstream`. Every gate was
    /// green: no test asserted on the text at all.
    #[test]
    fn neutrality03_upstream_missing_message_reads_as_prose() {
        assert!(
            !UPSTREAM_MISSING.contains("  "),
            "run of spaces from source indentation leaked into an \
             operator-facing message: {UPSTREAM_MISSING:?}"
        );
        assert!(
            !UPSTREAM_MISSING.contains('\n'),
            "the message is printed by anyhow on one line; embedded newlines \
             break the terminal layout: {UPSTREAM_MISSING:?}"
        );
        // It must still do its job: name the flag and carry a
        // documentation-range example rather than a real resolver.
        assert!(UPSTREAM_MISSING.contains("--upstream"));
        assert!(UPSTREAM_MISSING.contains("192.0.2.53:53"));
    }

    #[test]
    fn default_config_is_valid_toml() {
        let body = default_config();
        let parsed: Result<ConfigV1, _> = toml::from_str(&body);
        assert!(
            parsed.is_ok(),
            "default config should be valid v2 TOML: {parsed:?}"
        );
    }

    // rev-2606 P0-2 (init-scaffold-silent-no-blocking): replaces the
    // pre-rework `default_config_sources_match_catalog_defaults`, which
    // pinned the dual-channel shape (DEFAULT_SOURCES mirrored into
    // `[lists].sources`). The scaffold is single-channel now: slugs
    // become `[[blocklists]]` entities with catalog-resolved URLs, the
    // legacy slug channel stays empty.
    #[test]
    fn default_config_ships_entities_resolved_from_catalog() {
        let cfg: ConfigV1 = toml::from_str(&default_config()).unwrap();

        assert!(
            cfg.lists.sources.is_empty(),
            "scaffold must not populate the legacy [lists].sources slug channel \
             (dual-channel wiring splits filter bits — silent no-blocking)"
        );

        let catalog = Catalog::fallback();
        assert_eq!(cfg.blocklists.len(), DEFAULT_SOURCES.len());
        for (slug, b) in DEFAULT_SOURCES.iter().zip(cfg.blocklists.iter()) {
            assert_eq!(b.id.as_str(), slug.replace('/', "-"));
            assert_eq!(
                b.url.as_str(),
                catalog
                    .resolve(slug)
                    .expect("DEFAULT_SOURCES resolve in fallback catalog"),
                "scaffold entity URL for {slug} must be the catalog's URL, \
                 never hand-assembled (the path-form was 404 fiction)"
            );
        }

        assert!(
            !cfg.server.allow_from.is_empty(),
            "scaffold must ship a non-empty allow_from — 0.0.0.0 with an empty \
             ACL is an open resolver"
        );
    }

    #[test]
    fn default_config_default_profile_blocks_known_bad_domain() {
        // End-to-end: parse the scaffold, stand up a FilterEngine with
        // a known-bad domain mapped to the bit the profile mask uses,
        // build a v1 ResolvedProfile via the same path start.rs uses,
        // and confirm the hot-path evaluator blocks. §4.24: the bit map
        // is the typed [`SourceBitMap`] — the post-§4.24 production
        // path — so `bit_for_v1_id` is the only consumer lookup.
        use crate::filter::engine::{FilterEngine, FilterResult};
        use crate::lists::manager::merge_sources_with_blocklists;
        use crate::lists::source_key::SourceBitMap;
        use crate::profiles::profile::ResolvedProfile;
        use ahash::RandomState;
        use compact_str::CompactString;
        use std::collections::{BTreeMap, HashMap};

        let cfg: ConfigV1 = toml::from_str(&default_config()).unwrap();
        let (merged_sources, _trust) =
            merge_sources_with_blocklists(&cfg.lists.sources, &cfg.blocklists);
        let list_bit_map =
            SourceBitMap::build(&merged_sources, &cfg.blocklists).expect("at-cap accept");
        let default_profile = cfg.profiles.get("default").unwrap();
        let admin_rules: BTreeMap<&crate::config::schema::Id, &crate::config::schema::AdminRule> =
            cfg.admin_rules.iter().map(|r| (&r.id, r)).collect();
        let resolved = ResolvedProfile::build_v1(
            &crate::config::schema::Id::new("default").unwrap(),
            default_profile,
            &admin_rules,
            &crate::config::custom_list::CustomListStore::new(),
            &cfg.server,
            cfg.local_dns.ttl_secs,
        );

        // `plp-s3`: the subscription is no longer a field on the resolved
        // profile — it is the publish-time projection of the operator's
        // policy onto this generation's bits. Same claim, asked where the
        // answer now lives.
        let policy = list_bit_map.project_policy(&cfg.blocklists, &cfg.profiles);
        let default_masks = policy
            .per_profile
            .get("default")
            .copied()
            .expect("scaffold ships [profiles.default]");
        assert_ne!(
            default_masks.block, 0,
            "default profile should filter on at least one list"
        );

        // Tag the test domain with the SAME bit `SourceBitMap` assigned
        // to the first profile-subscribed list (`security-malicious`).
        let security_bit = list_bit_map
            .bit_for_v1_id(&crate::config::schema::Id::new("security-malicious").unwrap())
            .expect("scaffold bundles security-malicious blocklist");
        let mut domain_map: HashMap<CompactString, u64, RandomState> =
            HashMap::with_hasher(RandomState::new());
        domain_map.insert(CompactString::new("doubleclick.net"), 1u64 << security_bit);
        let engine = FilterEngine::new();
        engine.swap_domain_map(domain_map);
        engine.fixture_subscribe("default", default_masks.block);

        assert!(matches!(
            engine.evaluate("doubleclick.net", &resolved),
            FilterResult::Block
        ));
    }

    #[test]
    fn default_config_uses_production_paths() {
        let cfg: ConfigV1 = toml::from_str(&default_config()).unwrap();
        assert_eq!(
            cfg.socket.path,
            std::path::Path::new("/run/purge-warden/control.sock")
        );
        assert_eq!(cfg.server.listen, "0.0.0.0:53".parse().unwrap());
    }

    /// Helper shared by the template round-trip tests: render the
    /// scaffold exactly as `warden init --yes` (no overrides) would.
    fn render_yes_defaults() -> String {
        default_config()
    }

    #[test]
    fn rendered_template_round_trips_through_validator_and_resolver() {
        // Integration proof that the runtime template stays consistent
        // with the schema, validator, and resolver. Generates the
        // template `warden init --yes` writes to disk, parses it, runs
        // the full schema validator pass, and builds the resolver map
        // for the default profile. Any of the three steps failing means
        // a fresh install would refuse to boot.
        //
        // rev-2606 P0-2 extension — BIT IDENTITY: a non-zero mask is
        // not enough (the dual-channel scaffold had a non-zero mask
        // pointing at bits the downloads never populated). The pin is
        // now: merged sources == exactly the catalog URLs of
        // DEFAULT_SOURCES (each fetched once), and the profile mask ==
        // exactly the bits of those fetched sources.
        use crate::config::schema::validator::validate as schema_validate;
        use crate::lists::manager::merge_sources_with_blocklists;
        use crate::lists::source_key::SourceBitMap;
        use crate::profiles::profile::ResolvedProfile;
        use std::collections::BTreeMap;
        use time::OffsetDateTime;

        let body = render_yes_defaults();

        let mut cfg: ConfigV1 =
            toml::from_str(&body).expect("rendered template parses as ConfigV1");

        // neutrality-03: the scaffold deliberately ships NO upstream, so it
        // must fail validation on exactly that and nothing else. `warden
        // init` refuses without `--upstream` rather than writing this body,
        // so the "a fresh install boots" invariant is preserved by failing
        // at init time with a clear message instead of at boot.
        let errs = schema_validate(&cfg, OffsetDateTime::now_utc())
            .expect_err("the scaffold must not validate until the operator picks an upstream");
        let msgs: Vec<String> = errs.iter().map(|e| e.to_string()).collect();
        assert_eq!(
            msgs.len(),
            1,
            "the missing upstream must be the ONLY thing wrong with the scaffold, got: {msgs:?}"
        );
        assert!(
            msgs[0].contains("must list at least one resolver"),
            "expected the upstream-empty error, got: {msgs:?}"
        );

        // Supply the one decision the operator has to make (RFC 5737
        // documentation address), then the rest of the invariant below is
        // exactly what it was before.
        cfg.upstream.servers = vec!["192.0.2.53:53".to_string()];
        schema_validate(&cfg, OffsetDateTime::now_utc())
            .expect("with an upstream supplied, the template passes the full validator pass");

        let (merged_sources, _trust) =
            merge_sources_with_blocklists(&cfg.lists.sources, &cfg.blocklists);
        let list_bit_map =
            SourceBitMap::build(&merged_sources, &cfg.blocklists).expect("at-cap accept");
        let default_profile = cfg
            .profiles
            .get("default")
            .expect("rendered template ships [profiles.default]");
        let admin_rules: BTreeMap<&crate::config::schema::Id, &crate::config::schema::AdminRule> =
            cfg.admin_rules.iter().map(|r| (&r.id, r)).collect();
        let _resolved = ResolvedProfile::build_v1(
            &crate::config::schema::Id::new("default").unwrap(),
            default_profile,
            &admin_rules,
            &crate::config::custom_list::CustomListStore::new(),
            &cfg.server,
            cfg.local_dns.ttl_secs,
        );

        // Single channel: one merged source per subscribed list, each
        // one a real catalog URL (the strings the fetcher will GET).
        let catalog = Catalog::fallback();
        let expected_urls: Vec<String> = DEFAULT_SOURCES
            .iter()
            .map(|s| catalog.resolve(s).expect("default slug resolves"))
            .collect();
        assert_eq!(
            merged_sources, expected_urls,
            "merged sources must be exactly the catalog URLs — no slug \
             duplicates, no invented URL shapes"
        );

        // Bit identity: the profile mask covers exactly the bits the
        // fetch loop populates (bit i ↔ merged_sources[i]).
        let fetched_bits: u64 = (0..merged_sources.len()).fold(0, |acc, i| acc | (1u64 << i));
        let policy = list_bit_map.project_policy(&cfg.blocklists, &cfg.profiles);
        let default_masks = policy
            .per_profile
            .get("default")
            .copied()
            .expect("rendered template ships [profiles.default]");
        assert_eq!(
            default_masks.block, fetched_bits,
            "profile mask bits must equal fetched-source bits \
             (mask ∩ populated = ∅ was the silent-no-blocking shape)"
        );
        assert_eq!(
            default_masks.allow, 0,
            "the scaffold bundles no allow-direction list"
        );
    }

    /// The scaffold writes no association key the operator did not ask
    /// for — not the v1 `[[categories]]` entity, and since `plp-s5c` not
    /// a `tags` array either.
    ///
    /// **This test was INVERTED, and the previous claim is the record.**
    /// It required `tags = ["uncategorized"]` on every bundled blocklist
    /// and on the default profile, "so a fresh install boots with
    /// filtering ON for every device that inherits the system-reserved
    /// sentinel". That was the mechanism until `plp-s3`; it has not been
    /// since. `effective_direction` is `profile.lists[list]` if present,
    /// else `list.base`, and `base` defaults to `deny`.
    ///
    /// So the tags were doing nothing, and writing them was warden
    /// putting a value into the operator's file that they never asked
    /// for — while the validator auto-promotes an untagged deny-list to
    /// the same sentinel at LOAD, making the writer a round-trip of a
    /// loader-synthesised value.
    ///
    /// **"Filtering is ON out of the box" did not become unpinned; it
    /// moved to where it was always better measured.**
    /// `rendered_template_is_a_single_channel_with_matching_bits` above
    /// asserts the default profile's block mask equals exactly the bits
    /// the fetch loop populates — the real property, through the real
    /// projection, rather than through the presence of a string that
    /// used to imply it.
    #[test]
    fn rendered_template_writes_no_association_key_the_operator_did_not_ask_for() {
        let body = render_yes_defaults();

        // The v1 entity is gone — pinning the absence so a regression
        // here surfaces immediately.
        assert!(
            !body.contains("[[categories]]"),
            "rendered template must NOT contain a [[categories]] block (Sprint A of lc2_v2 removed the entity)"
        );
        assert!(
            !body.contains("category ="),
            "rendered template must NOT contain a `category =` field on blocklists"
        );
        assert!(
            !body.contains("blocklists ="),
            "rendered template must NOT contain a `blocklists = [...]` field on profiles"
        );

        // Neither a tags array nor the sentinel, anywhere.
        assert!(
            !body.contains("tags = ["),
            "the scaffold must not write a `tags` array: it decides nothing \
             since plp-s3, and the loader synthesises the sentinel itself. \
             Rendered:\n{body}"
        );
        assert!(
            !body.contains("uncategorized"),
            "not even in prose — the scaffold's comments used to teach the \
             retired tag-intersection model to every fresh install"
        );

        // The scaffold must still TELL the operator how association works,
        // or removing the old explanation would leave a fresh config with
        // no account of why it filters. Fail-before: this fires on a
        // template that simply drops the comment block.
        assert!(
            body.contains("list-policy"),
            "the scaffold must name the verb that sets a per-profile \
             direction, since the tag prose it replaced is gone"
        );
    }

    // rev-2606 P0-2: flag-value gates. Typed parses double as the
    // TOML-injection guard for everything init interpolates.
    #[test]
    fn flag_gates_accept_valid_and_reject_garbage() {
        assert!(validated_listen("0.0.0.0:53").is_ok());
        assert!(validated_listen("[::]:53").is_ok());
        assert!(validated_listen("not-an-addr").is_err());
        assert!(validated_listen("1.2.3.4").is_err()); // port required
        assert!(validated_listen("0.0.0.0:53\"\ninjected = true").is_err());

        assert!(validated_upstreams("1.1.1.1:53,9.9.9.9:53").is_ok());
        assert!(validated_upstreams("").is_err());
        assert!(validated_upstreams("dns.example.com:53").is_err()); // plain mode = IPs

        assert!(validated_allow_from(&["192.168.1.0/24".into(), "127.0.0.0/8".into()]).is_ok());
        assert!(validated_allow_from(&[]).is_err());
        assert!(validated_allow_from(&["999.0.0.0/8".into()]).is_err());
    }

    #[test]
    fn resolve_scaffold_lists_refuses_urls_and_unknown_slugs() {
        let err = resolve_scaffold_lists(&["https://evil.example/x.txt".into()])
            .expect_err("raw URLs refused");
        assert!(err.to_string().contains("warden blocklist add"));

        let err =
            resolve_scaffold_lists(&["privacy/nonexistent".into()]).expect_err("unknown slug");
        assert!(err.to_string().contains("warden lists catalog"));

        let err = resolve_scaffold_lists(&["privacy/ads\"".into()]).expect_err("charset gate");
        assert!(err.to_string().contains("not a valid list id"));

        // Duplicates collapse instead of producing duplicate entity ids.
        let lists = resolve_scaffold_lists(&["privacy/ads".into(), "privacy/ads".into()]).unwrap();
        assert_eq!(lists.len(), 1);
    }
}
