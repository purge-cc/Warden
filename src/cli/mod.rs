pub mod commands;
pub mod config_discovery;
pub mod exit_codes;

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use clap::{Parser, Subcommand};

pub use commands::completion::CompletionShell;

// Top-level clap parser. Exposed at `crate::cli::Cli` so the completion
// and manpage generators can read the subcommand tree without
// duplicating the definition.
//
// Deliberately a `//` comment, not `///`. clap-derive promotes a doc
// comment on this struct into the ROOT help page — the first thing every
// operator reads — where a note about which internal generators consume
// the tree means nothing to them. The `about` below is what they should
// see. Same reasoning applies to any implementation note on a derived
// type or field: if it is for the next engineer, `//` keeps it out of
// the operator's terminal, and `tests/cli_help_no_internal_refs.rs`
// enforces that.
#[derive(Parser)]
#[command(name = "warden", version, about = "purge-warden DNS filtering server")]
pub struct Cli {
    /// Path to configuration file. If omitted, searched in:
    /// ./config.toml, ~/.config/purge-warden/config.toml,
    /// /etc/purge-warden/config.toml (v1 FHS master),
    /// /var/lib/purge-warden/config.toml (legacy layout).
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Path to PID file (used by `start`, `stop`, `status`, `lists
    /// refresh`, and `config restore`). If omitted, defaults to
    /// /run/purge-warden/purge-warden.pid when the resolved config lives
    /// under /etc/ or /var/lib/, else ./purge-warden.pid.
    ///
    /// Not used by `cache flush`: cache flushing goes through the
    /// authenticated IPC socket only. The SIGUSR1-to-PID fallback this
    /// line used to describe was removed as a local auth bypass.
    #[arg(long)]
    pub pid_file: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start the DNS filtering server
    Start {
        /// Listen address (overrides config)
        #[arg(short, long)]
        listen: Option<SocketAddr>,
        /// Upstream DNS server(s), comma-separated — format depends on
        /// mode (overrides config)
        ///
        /// Comma-separated to match `--lists` on this same command and
        /// `warden init --upstream`. Without the delimiter,
        /// `--upstream 1.1.1.1:53,9.9.9.9:53` parsed as ONE server whose
        /// name contained a comma; plain mode then failed at boot on a
        /// string the operator had every reason to think was two entries.
        #[arg(short, long, value_delimiter = ',')]
        upstream: Vec<String>,
        /// Path to a local blocklist file (one domain per line)
        #[arg(short, long)]
        blocklist: Option<String>,
        /// List IDs or URLs to subscribe to (overrides config)
        #[arg(long, value_delimiter = ',')]
        lists: Vec<String>,
        /// List update interval in seconds (overrides config)
        #[arg(long)]
        update_interval: Option<u64>,
        /// Run as background daemon
        #[arg(long)]
        daemon: bool,
        /// Boot with a hardcoded safe config (127.0.0.1:5335, no
        /// filtering, IPC enabled) — used to recover control of a daemon
        /// whose on-disk config is broken. Every query is REFUSED, so no
        /// upstream is ever contacted.
        /// Ignores every file under the config directory.
        #[arg(long)]
        safe_mode: bool,
    },
    /// Stop a running daemon.
    ///
    /// Default: goes through the authenticated IPC socket — needs a
    /// token (run `warden token generate` first if you haven't).
    /// Use `--force` for emergency recovery when IPC is broken: it
    /// sends SIGTERM directly to the PID, skipping the auth gate.
    ///
    /// Exit code: 0 only when the process actually exited · 1 otherwise,
    /// including when the shutdown was accepted but the daemon was still
    /// alive 2 s later. Do not treat a non-zero exit as "the port is free".
    Stop {
        /// Skip the IPC auth gate and send SIGTERM directly to the
        /// daemon. Only use this if the daemon is hung or you have
        /// no valid token — it bypasses authorization entirely.
        #[arg(long)]
        force: bool,
    },
    /// Show server status — live stats from the running daemon, or the
    /// on-disk config when it is down.
    ///
    /// Exit code: 0 the daemon answered · 1 it is not reachable · 2 it is
    /// not reachable and the config does not load either. Safe to use as a
    /// liveness probe.
    Status {
        /// Output as JSON. Both the running and the not-running case emit
        /// a JSON object carrying a `running` boolean, so one parser
        /// covers both.
        #[arg(long)]
        json: bool,
    },
    /// Test if a domain would be blocked.
    ///
    /// Exit code: 0 ALLOWED · 3 BLOCKED · 1 no verdict could be obtained
    /// (daemon unreachable, or `--blocklist` unreadable). Branch on the
    /// code rather than grepping stdout — "blocked" and "could not ask"
    /// are deliberately different codes.
    Query {
        /// Domain name to test
        domain: String,
        /// Path to a blocklist file (one domain per line)
        #[arg(short, long)]
        blocklist: Option<String>,
    },
    /// Initialize system: create user, dirs, default config (requires root).
    /// Prompts for the default profile and initial blocklist subscriptions.
    Init {
        /// Overwrite an existing config file at the target path. By
        /// default `warden init` refuses to run if the target already
        /// exists so a hand-tuned config is never silently replaced.
        #[arg(long)]
        force: bool,
        /// Non-interactive mode — skip every prompt and accept the
        /// baked-in defaults (default profile = "default", the three
        /// pre-configured blocklists, RFC 1918 + loopback allow_from).
        /// Useful for provisioning scripts.
        #[arg(long)]
        yes: bool,
        /// Bind address for `[server].listen` (addr:port, e.g.
        /// `0.0.0.0:53`). Defaults to `0.0.0.0:53`.
        #[arg(long)]
        listen: Option<String>,
        /// Comma-separated upstream resolvers (addr:port, plain DNS).
        /// No default: warden does not pick a resolver for you. Omit it
        /// and `init` offers the resolver detected on this machine plus
        /// any entries in `upstreams.toml`; omit it with `--yes` and
        /// `init` adopts the detected one, or refuses if there is none.
        #[arg(long)]
        upstream: Option<String>,
        /// Path to the `upstreams.toml` menu catalog offered when
        /// `--upstream` is omitted. Defaults to `upstreams.toml` beside
        /// the config; an absent file simply shortens the menu.
        #[arg(long)]
        upstream_catalog: Option<PathBuf>,
        /// Comma-separated CIDRs allowed to query (`[server].allow_from`).
        /// Defaults to RFC 1918 + loopback. Required to be non-empty:
        /// an unspecified bind with an empty ACL is an open resolver.
        #[arg(long)]
        allow_from: Option<String>,
        /// Comma-separated catalog list ids to subscribe (e.g.
        /// `security/malicious,privacy/ads`). Overrides the
        /// subscription prompt; see `warden lists catalog`.
        #[arg(long)]
        lists: Option<String>,
        /// Scaffold this node as a cluster SECONDARY: write only the
        /// node-local sections and no policy at all — no
        /// `[upstream]`, no `[[blocklists]]`, no `[profiles.*]`. Those
        /// arrive from the primary, and a secondary's master carrying its
        /// own copies is refused. Requires `--peer <primary-api-url>`.
        ///
        /// The result is deliberately NOT bootable until `warden cluster
        /// join` runs: a node that is not syncing and names no resolver
        /// would answer nothing, and failing at load beats failing at
        /// query time.
        #[arg(
            long,
            requires = "peer",
            conflicts_with_all = ["upstream", "lists", "upstream_catalog"]
        )]
        cluster_secondary: bool,
        /// The primary's API base URL, e.g. `https://10.10.1.94:8053`.
        /// Only meaningful with `--cluster-secondary`.
        #[arg(long, requires = "cluster_secondary")]
        peer: Option<String>,
        /// Also generate manpages into `/usr/local/share/man/man1/` via
        /// [`clap_mangen`]. Operator can override the target directory
        /// with `--man-dir <path>`.
        #[arg(long)]
        install_manpages: bool,
        /// Directory for manpage generation. Defaults to
        /// `/usr/local/share/man/man1` (Debian convention for
        /// third-party binaries).
        #[arg(long, requires = "install_manpages")]
        man_dir: Option<PathBuf>,
    },
    /// Show how the 5-level resolver chain would resolve a given source IP
    /// against the current on-disk config (offline — does not require a
    /// running daemon). Prints the matched device, match level, and
    /// effective profile.
    ///
    /// Exit code: 0 resolved at some level 1-5 · 3 the IP would be REFUSED
    /// · 1 the resolver could not be built · 2 the config does not load.
    /// REFUSED is an answer, not an error — it no longer shares a code
    /// with "could not compute an answer".
    Resolve {
        /// Source IP address to resolve (e.g. `10.10.1.107`).
        ip: std::net::IpAddr,
    },
    /// Manage list subscriptions
    Lists {
        #[command(subcommand)]
        action: ListsAction,
    },
    /// Manage configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Manage DNS cache
    Cache {
        #[command(subcommand)]
        action: CacheAction,
    },
    /// Manage filtering profiles
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },
    /// Manage devices — the leaf entities of the resolver chain (id,
    /// ip, optional mac, profile, group memberships). Replaces the
    /// legacy `warden client` subcommand, which has been retired.
    Device {
        #[command(subcommand)]
        action: DeviceAction,
    },
    /// Manage groups — named sets of device ids with a shared profile.
    Group {
        #[command(subcommand)]
        action: GroupAction,
    },
    /// Manage labels — the controlled vocabulary for device owner /
    /// type / department metadata, and for tag names. Advisory
    /// throughout: declaring attaches nothing, and a device value
    /// outside the vocabulary still loads, with a warning.
    Label {
        #[command(subcommand)]
        action: LabelAction,
    },
    /// Manage subnets — CIDR-range default profiles resolved via
    /// longest-prefix match.
    Subnet {
        #[command(subcommand)]
        action: SubnetAction,
    },
    /// Inspect and remove `[[schedules]]` entries — time-window profile
    /// overrides for a device or group. Authoring stays with
    /// `warden device quiet` (one-shot) or the config file (recurring);
    /// this verb is the recovery path: list what exists, remove a
    /// leftover or cancel a quiet early. Expired entries are pruned
    /// automatically.
    Schedule {
        #[command(subcommand)]
        action: ScheduleAction,
    },
    /// Manage blocklists — external domain / rule subscriptions.
    Blocklist {
        #[command(subcommand)]
        action: BlocklistAction,
    },
    // NOTE — maintainer rationale, deliberately NOT a doc comment.
    //
    // Everything below `Tags {` that starts with `///` is promoted by
    // clap-derive into `long_about` and printed to whoever types
    // `warden tags`. The first draft of this variant explained the design
    // there — why a catch-all beats a subcommand enum, which frozen-string
    // test exercises it — and that text rendered verbatim into the help
    // page: a maintainer's argument with itself, shown to an operator who
    // just wants to know where their command went. Caught by rendering the
    // help, not by reading the source, which is the only way this class of
    // defect is visible.
    //
    // The design note, kept here where it belongs: a
    // `#[command(subcommand)]` enum would quarantine only the four slugs
    // that existed on the day tags were retired (`list`, `check`,
    // `rename`, `remove`). Muscle memory also reaches for `add` and
    // `create` — `warden tags create work` is a real argv this repo's
    // frozen-string suite has exercised since long before the retirement.
    // Both must land on the same signpost, so the argument list is opaque
    // by construction and `refuse_retired_tags_verb` never inspects it.
    //
    // Scope is the PLURAL verb only. This note first claimed the singular
    // `warden tag …` too, and the test written from it went red on the
    // gate: there has never been a top-level `warden tag`, only the
    // sub-verb form (`warden device tag add`). Quarantining a spelling
    // that never existed would be inventing surface, not retiring it.
    /// RETIRED — every `warden tags …` verb refuses.
    ///
    /// Tags used to decide which blocklists reached which clients. They
    /// decide nothing now: what a profile enforces is its own
    /// `profiles.<id>.lists` table plus each list's `base`. Set a
    /// direction with `warden profile list-policy set`.
    ///
    /// The command is kept, and accepts anything, so that typing a
    /// retired sub-verb tells you where the capability went rather than
    /// reporting an unrecognized subcommand.
    Tags {
        /// Accepted and ignored. Present only so that
        /// `warden tags <anything>` parses and reaches the refusal.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
        args: Vec<String>,
    },
    /// Add or remove a rule scoped to the **default** profile (the one
    /// `[server].default_profile` points at).
    Default {
        #[command(subcommand)]
        action: DefaultAction,
    },
    /// Manage admin rules. Currently exposes the `undo`
    /// verb that pops the last `[[admin_rules]]` row + cascades the
    /// reference drop across every profile / device / group it
    /// touched.
    Rule {
        #[command(subcommand)]
        action: RuleVerb,
    },
    /// View statistics (top blocked/queried domains, hourly/daily trends)
    Stats {
        #[command(subcommand)]
        action: StatsAction,
    },
    /// Manage REST API authentication token
    Token {
        #[command(subcommand)]
        action: TokenAction,
    },
    /// Manage primary/secondary cluster replication.
    Cluster {
        #[command(subcommand)]
        action: ClusterAction,
    },
    /// Print iptables/nftables rules for DNS enforcement
    FirewallRules,
    /// Launch the interactive terminal dashboard
    Dashboard,
    /// Inspect the security audit log
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },
    /// Emit a shell-completion script to stdout. Pipe to your shell's
    /// completion directory (see `warden completion --help`).
    Completion {
        /// Shell to generate completion for (bash, zsh, fish, elvish,
        /// powershell).
        shell: CompletionShell,
    },
    /// View query log entries
    Logs {
        /// Number of entries to show
        #[arg(long, default_value = "20")]
        limit: usize,
        /// Filter by client name or IP (substring match)
        #[arg(long)]
        client: Option<String>,
        /// Show only blocked queries
        #[arg(long)]
        blocked: bool,
        /// Filter by domain (substring match)
        #[arg(long)]
        domain: Option<String>,
        /// Only entries within the last DUR. humantime syntax:
        /// `30m`, `6h`, `2d`, `90s`.
        #[arg(long, value_parser = commands::logs::parse_duration_to_secs)]
        since: Option<u64>,
        /// Output format: `text` (default, tab-aligned), `json` (pretty
        /// array), or `csv` (RFC 4180 header row + rows).
        #[arg(long, value_enum, default_value_t = commands::logs::LogFormat::Text)]
        format: commands::logs::LogFormat,
    },
    /// One-shot migration from the pre-v1 single-file config layout to
    /// the v1 multi-file FHS tree under `/etc/purge-warden/`. Accepts v0,
    /// v1, and mixed configs; writes a backup of the source file to
    /// `<source-parent>/backups/pre-migration-<ts>.toml` before touching
    /// anything. The produced tree is validated through the v1 loader
    /// before the command returns.
    Migrate {
        #[command(subcommand)]
        action: MigrateAction,
    },
    /// Ask the running daemon to reload its configuration and lists via
    /// the authenticated IPC socket.
    ///
    /// Exit code: 0 the daemon reloaded · 1 it did not (not running, no
    /// token, or the reload was refused). Unlike the reload that follows
    /// an entity edit, here the reload IS the operation, so a daemon that
    /// is down is a failure and not a "takes effect on next start".
    Reload,
    /// Manage static local DNS records (A / AAAA / CNAME) — global table
    /// or scoped to a single profile.
    LocalDns {
        #[command(subcommand)]
        action: LocalDnsAction,
    },
    /// Manage per-profile domain rewrite rules
    /// (`api.old.com → api.new.com`). The rewrite happens AFTER the
    /// filter and BEFORE the upstream query, so blocklists still apply
    /// to the name the client actually asked for.
    Rewrite {
        #[command(subcommand)]
        action: RewriteAction,
    },
    /// Read and tune response rate limiting (`[security.rrl]`) and
    /// per-client query rate limiting (`[security.rate_limit]`).
    ///
    /// Both sections were validated by the daemon but had no verb, so
    /// `warden config edit` in `$EDITOR` was the only way to change
    /// settings an operator most wants to touch during an incident.
    Security {
        #[command(subcommand)]
        action: SecurityAction,
    },
}

#[derive(Subcommand)]
pub enum SecurityAction {
    /// Print the effective RRL and rate-limit settings, including the
    /// derived per-window budget and which bucket the budget applies to
    /// (per client address inside `server.allow_from`, per /24 or /48
    /// outside) — neither is readable off the raw config.
    Show,
    /// Set one key and trigger a hot reload. The config file remains the
    /// single source of truth; the whole config (master + includes) is
    /// validated before anything is written, so an out-of-range value is
    /// refused with the file untouched.
    Set {
        /// Dotted key, e.g. `rrl.responses_per_second` or
        /// `rate_limit.burst`. Run `warden security show` for the list.
        key: String,
        /// New value. Integers for budgets/windows; booleans accept
        /// true/false, on/off, yes/no.
        value: String,
    },
    /// Manage `[security.tunneling] exempt_domains`.
    ///
    /// The tunneling gates run before profile resolution and before the
    /// filter engine, so a name they refuse cannot be rescued by any
    /// allow rule — this list is the only remedy. Exemptions cover the
    /// shape gates AND the per-client subdomain rate counter, and apply
    /// without a daemon restart.
    Tunneling {
        #[command(subcommand)]
        action: TunnelingAction,
    },
}

#[derive(Subcommand)]
pub enum TunnelingAction {
    /// Stop refusing this name (and everything under it) as a tunnel.
    ///
    /// Matching is by label boundary: `a2z.com` covers `x.a2z.com` but
    /// not `evil-a2z.com`. A single-label entry is refused — exempting a
    /// whole TLD is `enabled = false` wearing a disguise.
    Exempt {
        /// Domain suffix to exempt, e.g. `minerva.devices.a2z.com`.
        domain: String,
    },
    /// Remove a suffix from the exemption list.
    Unexempt {
        /// Domain suffix to stop exempting.
        domain: String,
    },
}

#[derive(Subcommand)]
pub enum MigrateAction {
    /// Translate the legacy single-file config into the v1 multi-file
    /// layout. Default output: split under `<target>/<entity>.d/` files.
    /// Use `--single-file` to emit one monolithic master instead.
    V0ToV1 {
        /// Path to the existing config.toml (v0 or v1 or mixed).
        #[arg(long)]
        legacy_config: PathBuf,
        /// Directory that will hold the produced v1 tree. Created if
        /// missing; must be an empty or not-yet-existing directory for
        /// safety.
        #[arg(long)]
        target: PathBuf,
        /// Emit a single monolithic `<target>/config.toml` instead of
        /// the `.d/` split. Useful for environments that prefer
        /// one-file-per-host packaging.
        #[arg(long)]
        single_file: bool,
        /// Overwrite an existing migration tree under `<target>`. By
        /// default `warden migrate v0-to-v1` refuses to run if
        /// `<target>/config.toml` exists or any `<target>/<entity>.d/`
        /// directory is non-empty, so hand-tuned files are never
        /// silently clobbered. A one-line warning summary is printed
        /// before any overwrite.
        #[arg(long)]
        force: bool,
    },
    /// Snapshot the tag-based list association into explicit per-profile
    /// overrides (`profiles.<id>.lists`), so the same config keeps filtering
    /// exactly as it does today once tags stop deciding anything. Output is
    /// a single-file master at `<target>`.
    ///
    /// Mechanical, not corrective: if two profiles filter identically because
    /// every list carries `uncategorized`, the migrated config says so.
    ///
    /// REFUSES a config whose devices, groups or subnets carry their own
    /// `tags` — v3 has no policy axis below the profile, so flattening them
    /// would silently change what those clients filter. The message names
    /// them.
    V2ToV3 {
        /// Path to the existing v2 config.toml.
        #[arg(long)]
        from_config: PathBuf,
        /// Path where the v3 master will be written. Parent directory
        /// must exist.
        #[arg(long)]
        target: PathBuf,
        /// Overwrite `<target>` if it already exists. A re-run is
        /// byte-stable for targets that have not been edited, but
        /// `--force` is still required to proceed.
        #[arg(long)]
        force: bool,
    },
    // WHY IT IS DIRECT and not `v1-to-v2` chained with `v2-to-v3`: that
    // chain deletes `profiles.<id>.blocklists` (which IS the v3 model),
    // then stamps `tags = ["uncategorized"]` on every device, which
    // `tagged_sub_profile_entities` refuses — so it rejects every v1
    // config that has a device, on tags it wrote itself. Suppress the
    // refusal and every pair lands on `ignore`. Full trace on
    // `migrate::migrate_v1_to_v3`. `//` and not `///` because clap renders
    // doc comments into the operator's help page.
    /// Convert a config from the oldest supported layout to the current
    /// one, in a single step.
    ///
    /// Drops the retired `[[categories]]` blocks and the per-list
    /// `category` field, renames each list's `kind` to `base`, and writes
    /// out `profiles.<id>.lists` so every profile states, list by list,
    /// exactly what it enforces today. Nothing changes what the server
    /// blocks: a profile that filtered on three of five lists comes out
    /// naming those three and ignoring the other two.
    ///
    /// Use this on a config the current server refuses to load. If it
    /// already loads, you do not need it.
    V1ToV3 {
        /// Path to the existing v1 config.toml.
        #[arg(long)]
        from_config: PathBuf,
        /// Path where the v3 master will be written. Parent directory
        /// must exist.
        #[arg(long)]
        target: PathBuf,
        /// Overwrite `<target>` if it already exists. A re-run is
        /// byte-stable for targets that have not been edited, but
        /// `--force` is still required to proceed.
        #[arg(long)]
        force: bool,
    },
    /// DEPRECATED alias for `v1-to-v3`, which it runs instead.
    ///
    /// The intermediate format this verb used to produce is no longer one
    /// this server can read, so there is nothing for it to write. Kept so
    /// an older runbook still works instead of failing with "unrecognized
    /// subcommand".
    V1ToV2 {
        /// Path to the existing v1 config.toml.
        #[arg(long)]
        from_config: PathBuf,
        /// Path where the migrated master will be written. Parent
        /// directory must exist.
        #[arg(long)]
        target: PathBuf,
        /// Overwrite `<target>` if it already exists. By default the
        /// migrator refuses to overwrite an existing file so an
        /// operator who has post-edited the output is not silently
        /// clobbered on a re-run. A re-run is byte-stable for targets
        /// that have not been edited, but `--force` is still required
        /// to proceed.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
pub enum ListsAction {
    /// Add a list source to configuration
    Add {
        /// List ID (e.g. "privacy/ads") or URL
        source: String,
    },
    /// Remove a list source from configuration
    Remove {
        /// List ID or URL to remove
        source: String,
    },
    /// Show all configured list sources
    List,
    /// Show the `[lists]` settings — download caps, cache directory,
    /// retention guard — alongside the live corpus size measured
    /// against the ceiling. Use `list` for the sources themselves.
    Show,
    /// Change one `[lists]` setting and reload the daemon. Run `show`
    /// for the list of keys and what each one does.
    Set {
        /// Setting to change, e.g. `max_total_domains`
        key: String,
        /// New value
        value: String,
    },
    /// Re-download every subscribed list now and rebuild the filter.
    /// Signals a running daemon over SIGHUP; with no daemon up, runs
    /// the download in the foreground.
    ///
    /// Exit code: 0 the refresh was triggered or completed (a foreground
    /// download with no daemon running is still success) · 2 the config
    /// could not be loaded.
    Refresh,
    /// Browse available purge.cc lists
    Catalog {
        /// Filter by scope (privacy, security, content, services)
        #[arg(long)]
        scope: Option<String>,
    },
    /// Forget a list source's cached data (in-memory + disk). Forces
    /// re-download on the next refresh cycle. Surgical escape hatch
    /// from cache-poisoned-by-maintainer scenarios — does NOT touch
    /// the configuration, only the cached body + headers.
    Forget {
        /// List ID (e.g. "privacy/ads") or URL whose cache to drop
        source: String,
    },
}

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Print the current configuration as merged TOML.
    Show {
        /// Materialise the resolver output per-device and per-subnet
        /// (what the 5-level chain would pick for every configured
        /// source).
        #[arg(long)]
        resolved: bool,
        /// Annotate each entity with its source file:line from the
        /// include-merge provenance map.
        #[arg(long)]
        annotate: bool,
        /// Filter to a single top-level section (e.g. `devices`,
        /// `profiles`, `subnets`, `server`, `upstream`, `cache`).
        /// Under `--resolved` only `devices`, `subnets`, and `server`
        /// have a rendering; any other name is refused.
        #[arg(long)]
        section: Option<String>,
    },
    /// Open config in $EDITOR, then validate what was saved.
    ///
    /// Exit code: 0 the saved config is valid · 1 the editor could not be
    /// launched or exited non-zero · 2 the saved config does not validate
    /// (the errors are printed). Safe to chain: `warden config edit &&
    /// systemctl reload purge-warden`.
    Edit,
    /// Load + validate the v1 config without touching the running daemon.
    ///
    /// Exit code: 0 the config is valid (any warnings are printed to
    /// stderr but do not fail the command) · 2 the config has errors or
    /// could not be loaded. Safe to gate a deploy on: `warden config lint
    /// && systemctl reload purge-warden`.
    Lint {
        /// Treat warnings as failure: exit 2 on a config that is valid
        /// but carries warnings.
        ///
        /// Off by default, because a warning means the daemon boots and
        /// serves — failing on one would block an upgrade over a
        /// cosmetic nit. Turn it on when you would rather stop and look:
        /// `warden config lint --strict && systemctl reload
        /// purge-warden`.
        #[arg(long)]
        strict: bool,
    },
    /// Structured diff between two v1 config files.
    ///
    /// Exit code: 0 the two configs are identical · 3 they differ · 2 one
    /// of them could not be loaded. "They differ" is a successful answer,
    /// not a failure, so it does not share a code with one.
    Diff {
        /// Path to the other config to compare the current one against.
        other: PathBuf,
    },
    /// Create a timestamped tar.gz backup of the config file(s).
    Backup {
        /// Output directory for the archive. Defaults to
        /// `<config-parent>/backups/`.
        #[arg(long, conflicts_with = "auto")]
        out: Option<PathBuf>,
        /// Scheduled-backup mode used by the `purge-warden-backup.timer`
        /// systemd unit. Honours `[backup] auto_interval`,
        /// `disable_after_failures`, and the `.auto_state` file; exits
        /// 0 if not due / disabled / `auto_interval` is unset.
        #[arg(long, conflicts_with = "out")]
        auto: bool,
        /// Clear the auto-disable latch + failure counter in
        /// `.auto_state` after fixing the failure cause (Q5 recovery).
        /// Re-enables scheduled backups. Does NOT run a backup or write
        /// an archive.
        #[arg(long, conflicts_with_all = ["auto", "out"])]
        reset_auto_failure: bool,
    },
    /// Restore a config from a tar.gz backup archive. Validates the
    /// staged copy before replacing the live config.
    Restore {
        /// Path to the backup archive (.tar.gz). Required unless
        /// `--list` or `--latest`.
        #[arg(required_unless_present_any = ["list", "latest"])]
        archive: Option<PathBuf>,
        /// List the restore points in the configured backup dir and exit
        /// (does not restore anything).
        #[arg(long, conflicts_with_all = ["archive", "latest"])]
        list: bool,
        /// Restore the newest archive in the configured backup dir
        /// without naming it — skips the `--list` + copy-paste two-step.
        /// Mutually exclusive with an explicit archive path and `--list`.
        #[arg(long, conflicts_with_all = ["archive", "list"])]
        latest: bool,
    },
    /// Render the built-in default (scaffold) config to stdout as TOML.
    /// Pure: no root, no file writes, ignores the resolved config path.
    /// Used by the packaging build to freeze the seed config; also handy
    /// for diffing a live config against the shipped default.
    RenderDefault,
}

#[derive(Subcommand)]
pub enum CacheAction {
    /// Flush cache entries
    Flush {
        /// Domain to flush (omit to clear all)
        domain: Option<String>,
    },
}

/// `warden profile <verb>` operates on the v1 profile schema.
/// Mutating verbs dispatch over IPC to the running daemon; read verbs
/// (`list`, `show`) read the merged config tree locally.
///
/// Surface coverage (6 mutating verbs, 3 read-only):
/// - MUTATE: `display_name`, `block_response`, `blocked_ttl_secs`,
///   `block_all`, `admin_rules` (add/remove refs), `ecs` subtree.
/// - READ-only count + drill-out: `lists` (the per-list direction
///   override, written by `list-policy set` / `clear`), `tags` (inert —
///   every write verb refuses), `local_records` (TUI Local DNS tab),
///   `rewrite_rules` (`warden rewrite`).
///
/// `Allow` / `Deny` are carried from v0 — they synth an admin_rule
/// entry + cross-ref add. The dedicated `admin-rule add` /
/// `admin-rule remove` verbs work on existing `[[admin_rules]]` ids.
///
/// The six scalar fields take one generic `set <field> <value>`, as
/// every other entity does. `admin_rules` is a list of references and
/// `lists` is a three-state map, so neither folds into `set`: they keep
/// their own sub-verbs. `tags` keeps its sub-verb too, but only so the
/// refusal has somewhere to land.
#[derive(Subcommand)]
pub enum ProfileAction {
    /// List all v1 profiles with summary stats.
    List,
    /// Show full v1 details for one profile.
    Show {
        /// Profile id (the map key in `[profiles.<id>]`).
        id: String,
    },
    /// Add a new v1 profile.
    Add {
        /// Profile id (the map key in `[profiles.<id>]`). Charset
        /// `[a-z0-9-]`, 1..=64 bytes.
        id: String,
        /// Human-readable label.
        #[arg(long)]
        display_name: String,
    },
    /// Set one field on an existing profile.
    ///
    /// Fields:
    ///   display_name    human-readable label
    ///   block_response  shape of a blocked answer: zero, nxdomain,
    ///                   refused, soa_nodata, or clear to inherit the
    ///                   server default
    ///   blocked_ttl     seconds to live on a blocked answer; 0 inherits
    ///                   the server default
    ///   block_all       block every query unless an allow rule matches:
    ///                   true or false
    ///   ecs.mode        EDNS Client Subnet policy: off, coarse, subnet
    ///   ecs.prefix_v4   IPv4 prefix length sent upstream, 0-32
    ///   ecs.prefix_v6   IPv6 prefix length sent upstream, 0-128
    ///   ecs             the literal none — drop the whole subtree so the
    ///                   profile inherits the upstream defaults
    ///
    /// The ecs settings are one subtree rather than one scalar, so they
    /// take dotted keys. Setting one leaves the other two as they were.
    ///
    /// Which blocklists this profile applies is not a field either:
    /// use `warden profile list-policy`. Admin rules are a list of
    /// references: use `warden profile admin-rule`.
    #[command(verbatim_doc_comment)]
    Set {
        /// Profile id (the map key in `[profiles.<id>]`).
        id: String,
        /// Field name (see above).
        field: String,
        /// New value.
        value: String,
    },
    /// Manage which existing `[[admin_rules]]` rows this profile
    /// enforces. Rows are not created here — they are synthesised as a
    /// side effect of `warden profile allow` / `warden profile deny`
    /// (and the device / group / subnet / default equivalents), which
    /// write the row and reference it in one step. `warden profile
    /// show` lists the ids this profile currently names.
    AdminRule {
        #[command(subcommand)]
        action: commands::profiles_v1::ProfileAdminRuleAction,
    },
    /// Remove a v1 profile. Refuses if any device, subnet, or
    /// schedule still references the id — resolve the dangling
    /// references first.
    Remove { id: String },
    /// Allow a domain on this profile — synthesises an
    /// `@@||domain^` admin rule and references it. Use `--remove` to
    /// undo a previous allow on the same domain.
    Allow {
        /// Profile id (the map key in `[profiles.<id>]`).
        profile_id: String,
        /// Domain (LDH ASCII; for IDN use the Punycode `xn--…` form).
        domain: String,
        /// Optional explicit rule id. On add, the id given to the new
        /// `[[admin_rules]]` row (default: auto-generated
        /// `auto-<action>-<8hex>` via OsRng). With `--remove`, selects the
        /// rule carrying this id instead of the first one matching the
        /// domain — several rules may share an (action, domain).
        #[arg(long)]
        id: Option<String>,
        /// Invert: drop a previous allow on the same domain (or the
        /// rule named by `--id`), cascading the `[[admin_rules]]` row
        /// drop when no other entity references the id.
        #[arg(long)]
        remove: bool,
        /// Optional `profiles.d/*.toml` slice to edit.
        #[arg(long)]
        into: Option<PathBuf>,
    },
    /// Block a domain on this profile — synthesises a `||domain^`
    /// admin rule. Use `--remove` to undo a previous block.
    Deny {
        profile_id: String,
        domain: String,
        /// Optional explicit rule id. On add, the id given to the new
        /// `[[admin_rules]]` row (default: auto-generated
        /// `auto-<action>-<8hex>` via OsRng). With `--remove`, selects the
        /// rule carrying this id instead of the first one matching the
        /// domain — several rules may share an (action, domain).
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        remove: bool,
        #[arg(long)]
        into: Option<PathBuf>,
    },
    /// Set or clear what this profile does with one blocklist — the
    /// three-state direction override.
    ///
    /// A profile either declares a direction for a list, or inherits the
    /// one the list declares for itself in its own `base`. `set` writes
    /// the declaration; `clear` removes it so the pair follows `base`
    /// again; `show` prints what is in force for every list and which of
    /// the two it came from.
    ///
    /// `clear` and `set … ignore` are different: `ignore` is a standing
    /// declaration that this profile applies nothing from the list, and
    /// keeps saying so when `base` changes; a cleared pair follows `base`
    /// wherever it goes.
    ListPolicy {
        #[command(subcommand)]
        action: commands::profiles_v1::ProfileListPolicyAction,
    },
}

// `ProfileBlocklistsAction` was removed in Sprint A of
// `lists_categories_v2` (Q2-A), when tags took over list applicability.
// The plp workstream took it back off them: `profiles.<id>.lists` is the
// association now, and `Profile.blocklists` is NOT what returned — the new
// field is a three-state map, not a subscription array.

#[derive(Subcommand)]
pub enum DeviceAction {
    /// List all devices (from config or live stats via IPC)
    List {
        /// Show live stats from running daemon
        #[arg(long)]
        live: bool,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Add a new device. `id` is the stable cross-reference key; at
    /// least one of `--ip` / `--mac` is required so the resolver can
    /// identify the device.
    Add {
        /// Stable identifier (`[a-z0-9-]`, 1..=64 bytes). Used as the
        /// display name if `--display-name` is not supplied.
        id: String,
        /// Human-friendly label. Defaults to `id` when omitted.
        #[arg(long)]
        display_name: Option<String>,
        /// IPv4 or IPv6 address that pins this device.
        #[arg(long)]
        ip: Option<IpAddr>,
        /// Primary MAC address (AA:BB:CC:DD:EE:FF).
        #[arg(long)]
        mac: Option<String>,
        /// Direct profile assignment (wins over group / subnet).
        #[arg(long)]
        profile: Option<String>,
        /// Group memberships (comma-separated ids).
        #[arg(long, value_delimiter = ',')]
        groups: Vec<String>,
        /// Optional human owner ("Dweller", "User2")
        #[arg(long)]
        owner: Option<String>,
        /// Optional device label ("iPad personale")
        #[arg(long)]
        device_type: Option<String>,
        /// Optional logical group ("famiglia")
        #[arg(long)]
        department: Option<String>,
        /// Free-form notes
        #[arg(long)]
        notes: Option<String>,
        /// Target file to write into. Defaults to auto-selected
        /// `devices.d/*.toml` (if unique) or the master config.
        #[arg(long)]
        into: Option<PathBuf>,
    },
    /// Set a single field on an existing device. Supported fields: ip,
    /// mac, profile, display_name, owner, device, department, notes,
    /// groups, network_name, network_name_wildcard.
    ///
    /// `tags` is NOT settable: a device tag no longer decides which lists
    /// reach it, so the field is accepted by the loader and refused by
    /// this verb rather than written and ignored.
    Set {
        /// Device id.
        id: String,
        /// Field name (see above).
        field: String,
        /// New value. Use "none" to clear a nullable field.
        value: String,
        #[arg(long)]
        into: Option<PathBuf>,
    },
    /// Remove a device.
    Remove {
        id: String,
        #[arg(long)]
        into: Option<PathBuf>,
    },
    /// Show full details for a single device.
    Show { id: String },
    /// Block a device — set its profile to `blocked` (auto-created if
    /// missing).
    Block {
        id: String,
        #[arg(long)]
        into: Option<PathBuf>,
    },
    /// Restore a device's profile after `warden device block`.
    Unblock {
        id: String,
        #[arg(long, default_value = "default")]
        profile: String,
        #[arg(long)]
        into: Option<PathBuf>,
    },
    /// Quiet a device temporarily via a one-shot `[[schedules]]` entry
    /// that expires automatically.
    Quiet {
        id: String,
        /// Duration like `15m`, `2h`, `1h30m`.
        #[arg(long, conflicts_with = "until")]
        r#for: Option<String>,
        /// Absolute end time as RFC 3339.
        #[arg(long)]
        until: Option<String>,
        #[arg(long)]
        into: Option<PathBuf>,
    },
    /// Allow a domain ONLY for this device. Refused when the device's
    /// profile explicitly denies the same domain, unless the device
    /// entry sets `override_profile_deny = true`.
    Allow {
        device_id: String,
        domain: String,
        /// Optional explicit rule id. On add, the id given to the new
        /// `[[admin_rules]]` row (default: auto-generated
        /// `auto-<action>-<8hex>` via OsRng). With `--remove`, selects the
        /// rule carrying this id instead of the first one matching the
        /// domain — several rules may share an (action, domain).
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        remove: bool,
        #[arg(long)]
        into: Option<PathBuf>,
    },
    /// Block a domain ONLY for this device.
    Deny {
        device_id: String,
        domain: String,
        /// Optional explicit rule id. On add, the id given to the new
        /// `[[admin_rules]]` row (default: auto-generated
        /// `auto-<action>-<8hex>` via OsRng). With `--remove`, selects the
        /// rule carrying this id instead of the first one matching the
        /// domain — several rules may share an (action, domain).
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        remove: bool,
        #[arg(long)]
        into: Option<PathBuf>,
    },
    /// Manage the per-device rule references. Currently exposes
    /// `prune`, which drops rule ids that no longer resolve to an
    /// `[[admin_rules]]` row — the ones `warden config lint` warns
    /// about.
    Rules {
        device_id: String,
        #[command(subcommand)]
        action: DeviceRulesAction,
    },
    /// Toggle the device's `unfiltered` flag. Setting it to `true`
    /// also clears the `tags` array in the same write, because the two
    /// are mutually exclusive. Monitoring (DNS resolution + query log
    /// + stats) stays active either way.
    SetUnfiltered {
        /// Device id.
        id: String,
        /// `true` skips filtering, `false` re-enables it.
        value: String,
        #[arg(long)]
        into: Option<PathBuf>,
    },
}

/// Every selector verb takes an optional `--kind` because a label's
/// identity is the pair `(kind, id)`. One id is deliberately allowed
/// under two kinds, so guessing which row the operator meant would be
/// worse than asking.
#[derive(Subcommand)]
pub enum LabelAction {
    /// List the vocabulary, grouped by kind.
    List,
    /// Show full details for a single label.
    Show {
        /// Label id.
        id: String,
        /// Disambiguate when the id exists under several kinds.
        #[arg(long)]
        kind: Option<String>,
    },
    /// Declare a new vocabulary value.
    Add {
        /// Stable identifier, unique within its kind.
        id: String,
        /// Vocabulary dimension: owner, device-type, department, or tag.
        /// A `tag` id must also be a valid tag slug (letter-led, max 32
        /// bytes) and cannot be the system-reserved `uncategorized`.
        #[arg(long)]
        kind: String,
        /// The value as a human writes it. Device metadata is matched
        /// against this as well as against the id, so declaring a
        /// vocabulary never forces a rewrite of existing devices.
        /// Defaults to the id.
        #[arg(long)]
        display_name: Option<String>,
        /// Free-form note. Inert — stored and echoed by `label show`,
        /// read by nothing at runtime.
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        into: Option<PathBuf>,
    },
    /// Set a label field (display_name, description, kind).
    Set {
        id: String,
        field: String,
        value: String,
        /// Disambiguate when the id exists under several kinds.
        #[arg(long)]
        kind: Option<String>,
        #[arg(long)]
        into: Option<PathBuf>,
    },
    /// Remove a label (refused while any entity still uses its value).
    Remove {
        id: String,
        /// Disambiguate when the id exists under several kinds.
        #[arg(long)]
        kind: Option<String>,
        #[arg(long)]
        into: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub enum GroupAction {
    /// List all groups.
    List,
    /// Show full details for a single group.
    Show { id: String },
    /// Add a new group.
    Add {
        /// Stable identifier.
        id: String,
        #[arg(long)]
        display_name: Option<String>,
        /// Profile applied to group members (required).
        #[arg(long)]
        profile: String,
        /// Priority resolving conflicting memberships (higher wins).
        #[arg(long)]
        priority: Option<i32>,
        /// Device ids to include (comma-separated).
        #[arg(long, value_delimiter = ',')]
        devices: Vec<String>,
        #[arg(long)]
        into: Option<PathBuf>,
    },
    /// Set a group field (display_name, profile, priority, devices).
    Set {
        id: String,
        field: String,
        value: String,
        #[arg(long)]
        into: Option<PathBuf>,
    },
    /// Remove a group (must not be referenced by any device).
    Remove {
        id: String,
        #[arg(long)]
        into: Option<PathBuf>,
    },
    /// Allow a domain across every device in this group.
    /// The rule lands on the Profile this group references, so it also
    /// applies to every other group, subnet, or device pointing at that
    /// same profile — the scope is the profile, not the group.
    ProfileAllow {
        group_id: String,
        domain: String,
        /// Optional explicit rule id. On add, the id given to the new
        /// `[[admin_rules]]` row (default: auto-generated
        /// `auto-<action>-<8hex>` via OsRng). With `--remove`, selects the
        /// rule carrying this id instead of the first one matching the
        /// domain — several rules may share an (action, domain).
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        remove: bool,
        #[arg(long)]
        into: Option<PathBuf>,
    },
    /// Block a domain across every device in this group.
    /// Same profile-wide scope as `profile-allow`.
    ProfileDeny {
        group_id: String,
        domain: String,
        /// Optional explicit rule id. On add, the id given to the new
        /// `[[admin_rules]]` row (default: auto-generated
        /// `auto-<action>-<8hex>` via OsRng). With `--remove`, selects the
        /// rule carrying this id instead of the first one matching the
        /// domain — several rules may share an (action, domain).
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        remove: bool,
        #[arg(long)]
        into: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub enum ScheduleAction {
    /// List all schedules with target, window, expiry, and current state
    /// (active / inactive / expired).
    List,
    /// Remove a schedule by id. Works on active entries too — removing a
    /// live quiet schedule un-quiets the device early. Find the id with
    /// `warden schedule list`.
    Remove { id: String },
}

#[derive(Subcommand)]
pub enum SubnetAction {
    List,
    Show {
        id: String,
    },
    Add {
        id: String,
        #[arg(long)]
        display_name: Option<String>,
        /// One or more CIDR ranges (comma-separated). Each entry
        /// accepts canonical CIDR (`10.14.0.0/24`), bare addresses
        /// (`10.14.0.5` → `/32`), wildcard suffixes (`10.14.0.*` →
        /// `/24`, `10.14.*.*` → `/16`, `10.*.*.*` → `/8`), and
        /// CIDR-aligned ranges (`10.14.0.0-10.14.0.255` → `/24`).
        /// IPv6 still requires canonical CIDR. Rejected forms
        /// include non-contiguous wildcards (`10.*.0.*`), mixed
        /// range+wildcard, and misaligned ranges.
        #[arg(long, value_delimiter = ',')]
        cidrs: Vec<String>,
        /// Profile for unmapped devices in this range (required).
        #[arg(long)]
        profile: String,
        /// Informational only — matching still uses longest prefix.
        #[arg(long)]
        priority: Option<i32>,
        #[arg(long)]
        into: Option<PathBuf>,
    },
    Set {
        id: String,
        field: String,
        value: String,
        #[arg(long)]
        into: Option<PathBuf>,
    },
    Remove {
        id: String,
        #[arg(long)]
        into: Option<PathBuf>,
    },
    /// Allow a domain across every device on this subnet.
    /// The rule lands on the Profile this subnet references, so it also
    /// applies to every other subnet, group, or device pointing at that
    /// same profile — the scope is the profile, not the subnet. The
    /// `subnet_or_cidr` arg accepts either the subnet id or any CIDR
    /// in its `cidrs` list.
    ProfileAllow {
        subnet_or_cidr: String,
        domain: String,
        /// Optional explicit rule id. On add, the id given to the new
        /// `[[admin_rules]]` row (default: auto-generated
        /// `auto-<action>-<8hex>` via OsRng). With `--remove`, selects the
        /// rule carrying this id instead of the first one matching the
        /// domain — several rules may share an (action, domain).
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        remove: bool,
        #[arg(long)]
        into: Option<PathBuf>,
    },
    /// Block a domain across every device on this subnet.
    /// Same profile-wide scope as `profile-allow`.
    ProfileDeny {
        subnet_or_cidr: String,
        domain: String,
        /// Optional explicit rule id. On add, the id given to the new
        /// `[[admin_rules]]` row (default: auto-generated
        /// `auto-<action>-<8hex>` via OsRng). With `--remove`, selects the
        /// rule carrying this id instead of the first one matching the
        /// domain — several rules may share an (action, domain).
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        remove: bool,
        #[arg(long)]
        into: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub enum BlocklistAction {
    List,
    Show {
        id: String,
    },
    Add {
        id: String,
        #[arg(long)]
        display_name: Option<String>,
        /// Source URL (http:// or https://).
        #[arg(long)]
        url: String,
        /// Parser format (domains, adguard, hosts). Defaults to
        /// `domains`.
        #[arg(long)]
        format: Option<String>,
        /// Update interval in hours. Default: 12.
        #[arg(long)]
        update_interval_hours: Option<u32>,
        /// Entry cap recorded on this list. The daemon enforces the global
        /// `[lists] max_entries` (default 20_000_000), not this value.
        #[arg(long)]
        max_entries: Option<u64>,
        /// Whether this list is active.
        #[arg(long)]
        enabled: Option<bool>,
        /// Name of the secret in `secrets.toml` that holds the bearer
        /// token for authenticated fetches.
        #[arg(long)]
        auth_token_ref: Option<String>,
        /// Skip the synchronous HEAD reachability probe run before
        /// the list is registered. Use only when the URL is trusted but
        /// transiently unreachable, or behind auth that rejects HEAD.
        #[arg(long, default_value_t = false)]
        skip_head_check: bool,
        /// Direction this list applies in for every profile that does
        /// not override it: `deny` (default) blocks the domains it
        /// lists, `allow` permits them, `ignore` loads it and applies it
        /// nowhere. An allow-list on a URL source is remote and
        /// unsigned, so it needs `--accept-unsigned-allow`.
        ///
        /// A list's direction reaches every profile that does not
        /// override it. To exempt one profile, or to apply the list to
        /// only some, set the override: `warden profile list-policy set
        /// <profile> <list> deny|allow|ignore`.
        #[arg(long)]
        kind: Option<String>,
        /// Declare that you accept a remote, unsigned source deciding
        /// which domains stop being blocked. Required with
        /// `--kind allow`: whoever controls the URL can add a domain at
        /// any refresh, with no signature and no review. Prefer
        /// `warden blocklist import-local` if you would rather own the
        /// content than subscribe to it.
        #[arg(long, action = clap::ArgAction::SetTrue)]
        accept_unsigned_allow: bool,
        #[arg(long)]
        into: Option<PathBuf>,
    },
    Set {
        id: String,
        field: String,
        value: String,
        #[arg(long)]
        into: Option<PathBuf>,
    },
    // `--cascade` was declared here until cli-h5 and did nothing. It
    // existed to unlock a refusal that fired when a profile still
    // enumerated the blocklist being removed — a shape the v2 tag model
    // deleted: the profile↔list join is tags now, so no profile
    // references a blocklist id and the refusal had no production
    // emitter. The flag parsed, set an audit field, and returned success
    // without cascading anything.
    //
    // The refusal's wording (`RULE_DANGLING_REF`) outlived the flag by one
    // sprint — a frozen string recommending an argument the binary
    // rejected — and was retired with its formatter and both pins.
    Remove {
        id: String,
        #[arg(long)]
        into: Option<PathBuf>,
    },
    /// Flip a blocklist's direction. `base = allow` on a
    /// remote-unsigned source needs `--accept-unsigned-allow`, checked
    /// before anything is written.
    ///
    /// The two accepted values are `deny` and `allow`.
    SetKind {
        list_id: String,
        /// `deny` or `allow`.
        kind: String,
        /// Declare that you accept a remote, unsigned source deciding
        /// which domains stop being blocked. Needed when flipping a
        /// `trust = remote-unsigned` list to `allow`, unless the list
        /// already carries the declaration.
        #[arg(long, action = clap::ArgAction::SetTrue)]
        accept_unsigned_allow: bool,
        #[arg(long)]
        into: Option<PathBuf>,
    },
    /// Flip a blocklist's trust level. `local` and `remote-unsigned`
    /// are accepted; `signed` is not yet supported.
    ///
    /// Taking an **allow**-direction list from `local` to
    /// `remote-unsigned` needs `--accept-unsigned-allow`: that is where
    /// a file the operator wrote becomes a subscription somebody else
    /// can edit.
    SetTrust {
        list_id: String,
        /// `local` or `remote-unsigned`.
        trust: String,
        /// Declare that you accept a remote, unsigned source deciding
        /// which domains stop being blocked. Needed when moving an
        /// allow-direction list to `remote-unsigned`, unless the list
        /// already carries the declaration.
        #[arg(long, action = clap::ArgAction::SetTrue)]
        accept_unsigned_allow: bool,
        #[arg(long)]
        into: Option<PathBuf>,
    },
    /// Copy a local file into the managed lists directory and
    /// register it as a `trust = local` blocklist. The format is
    /// auto-detected from the file's content.
    ///
    /// The list applies in its `--kind` direction to every profile that
    /// does not override it; use `warden profile list-policy set` to
    /// change that for one profile.
    ImportLocal {
        /// Path to the local file (one entry per line for `domains`
        /// format; AdGuard rules / hosts files are auto-detected).
        path: PathBuf,
        /// Stable id for the new blocklist.
        #[arg(long)]
        id: String,
        /// Direction (`deny`, `allow`, or `ignore`).
        #[arg(long)]
        kind: String,
        /// Optional human-readable name (defaults to the id).
        #[arg(long)]
        display_name: Option<String>,
        #[arg(long)]
        into: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub enum StatsAction {
    /// Show top blocked domains
    TopBlocked {
        /// Number of entries to show
        #[arg(long, default_value = "20")]
        limit: usize,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Show top queried domains
    TopQueried {
        /// Number of entries to show
        #[arg(long, default_value = "20")]
        limit: usize,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Show hourly query trends
    Hourly {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Show daily query trends
    Daily {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub enum TokenAction {
    /// Generate a new API token (fails if one already exists)
    Generate,
    /// Regenerate API token (replaces existing)
    Regenerate,
}

#[derive(Subcommand)]
pub enum ClusterAction {
    /// Primary: generate the cluster bearer token. The plaintext is
    /// printed ONCE — carry it to the secondary. Only its SHA-256 hash is
    /// stored, in `[cluster] token_hash`.
    Token,
    /// Secondary: configure this node to follow a primary. Writes the
    /// `[cluster]` section (role = secondary, peer, token_hash, enabled).
    /// The peer and token are recorded, not contacted: nothing here proves
    /// the primary is reachable or the token correct — the first sync does.
    /// Undo with `warden cluster leave`.
    Join {
        /// The primary's API base URL, e.g. https://10.10.1.94:8053
        #[arg(long)]
        peer: String,
        /// Read the cluster bearer token from this file (0600). Preferred —
        /// keeps the secret off the command line.
        #[arg(long, value_name = "PATH")]
        token_file: Option<PathBuf>,
        /// The cluster bearer token, inline. DISCOURAGED: visible via `ps` /
        /// /proc/<pid>/cmdline and saved to shell history — prefer --token-file
        /// or piping it on stdin. When neither this nor --token-file is given,
        /// the token is read from stdin.
        #[arg(long)]
        token: Option<String>,
        /// PEM certificate of the primary's API listener, pinned as the ONLY
        /// trust anchor for the sync channel. Neither node has a
        /// publicly-issued certificate, so without this the secondary cannot
        /// complete a single poll against a non-loopback peer. Copy it from
        /// the primary's `api.tls_cert`.
        #[arg(long, value_name = "PATH")]
        peer_cert: Option<PathBuf>,
    },
    /// Undo a join: turn clustering off and forget the peer this node was
    /// following, leaving it standalone. Use this to recover a node whose
    /// daemon refuses to start because its config still claims cluster
    /// membership. Other settings, and any stored cluster token, are kept.
    Leave {
        /// Set this node's own resolver while leaving, e.g. 10.0.0.1:53.
        /// Required only on a secondary that joined but never synced: its
        /// upstream would have arrived in the primary's bundle, and a
        /// secondary's own master may not carry one, so leaving without this
        /// would strand the node with no resolver. Cleared membership and this
        /// value are written together — neither order works alone.
        #[arg(long, value_name = "ADDR:PORT")]
        upstream: Option<String>,
    },
    /// Primary: turn clustering on and mint the TLS material a secondary
    /// will pin. Writes `[cluster]` and `[api]` in ONE validated write —
    /// they cannot be separate, because `api.enabled = true` is refused at
    /// load until the token hash and the TLS pair are all present together.
    Enable {
        /// This node's cluster role.
        #[arg(long, value_enum)]
        role: EnableRole,
        /// An address a secondary will use to reach this node. Repeatable.
        /// Required when this node has no `api.tls_cert` yet. Bare host or
        /// IP — no scheme, no port, no path.
        #[arg(long = "san", value_name = "ADDR")]
        sans: Vec<String>,
        /// Bind address for the API server, e.g. 192.0.2.10:8053. A primary
        /// must be reachable by its secondaries, and the default listen is
        /// loopback — without this the operator is back to hand-editing
        /// TOML, which is what this verb exists to remove.
        #[arg(long, value_name = "IP:PORT")]
        api_listen: Option<SocketAddr>,
        /// Certificate validity in days. A pinned self-signed certificate
        /// has no CA to expire against, and rotating it means touching both
        /// nodes — so the default is long on purpose.
        #[arg(long, default_value_t = 3650)]
        validity_days: u32,
    },
    /// Print this node's cluster role / peer / enabled state.
    Status,
}

// Both variants exist so `--role secondary` reaches the verb and is refused
// by name, pointing at `cluster join`. With only `Primary`, clap's own
// "invalid value for '--role'" is what a mistaken operator sees, and that
// error cannot name the verb they actually wanted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum EnableRole {
    Primary,
    Secondary,
}

#[derive(Subcommand)]
pub enum AuditAction {
    /// Print the last N entries from the audit log.
    Tail {
        /// Number of records to show (newest last).
        #[arg(short = 'n', long = "number", default_value_t = 20)]
        n: usize,
    },
}

#[derive(Subcommand)]
pub enum DefaultAction {
    /// Allow a domain across the default-profile resolver
    /// chain (every unmapped device). Typed-confirm `DEFAULT` is
    /// required even on the CLI to surface the broad blast radius.
    Allow {
        domain: String,
        /// Optional explicit rule id. On add, the id given to the new
        /// `[[admin_rules]]` row (default: auto-generated
        /// `auto-<action>-<8hex>` via OsRng). With `--remove`, selects the
        /// rule carrying this id instead of the first one matching the
        /// domain — several rules may share an (action, domain).
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        remove: bool,
        #[arg(long)]
        into: Option<PathBuf>,
        /// Skip the typed-`DEFAULT` confirm prompt. Required for
        /// non-TTY callers (scripts, CI).
        #[arg(long)]
        yes: bool,
    },
    /// Block a domain across the default-profile chain.
    Deny {
        domain: String,
        /// Optional explicit rule id. On add, the id given to the new
        /// `[[admin_rules]]` row (default: auto-generated
        /// `auto-<action>-<8hex>` via OsRng). With `--remove`, selects the
        /// rule carrying this id instead of the first one matching the
        /// domain — several rules may share an (action, domain).
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        remove: bool,
        #[arg(long)]
        into: Option<PathBuf>,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
pub enum RuleVerb {
    /// Pop the last `[[admin_rules]]` row and cascade the
    /// reference drop across every profile / device / group / subnet
    /// that named it.
    Undo,
}

#[derive(Subcommand)]
pub enum DeviceRulesAction {
    /// Walk a device's `allow_rules` + `deny_rules` and
    /// drop ids that no longer exist in `[[admin_rules]]`. The recovery
    /// path for `LIST_PRUNE_WARN`.
    Prune {
        #[arg(long)]
        into: Option<PathBuf>,
    },
}

/// Local DNS record verbs. Maps each clap subcommand to one of the
/// local-DNS handlers; the
/// single-seat `add_inner` / `remove_inner` helpers underneath do the
/// actual TOML mutation + audit emit + reload trigger so the future
/// TUI tab modal can call the same code path.
#[derive(Subcommand)]
pub enum LocalDnsAction {
    /// Add a static A / AAAA / CNAME record. Without `--profile` the
    /// record lands in the global `[[local_dns.records]]` table; with
    /// `--profile <id>` it lands on that profile only.
    Add {
        /// Domain to define a record for (lowercased automatically).
        domain: String,
        /// Record type: `A`, `AAAA`, or `CNAME` (case-insensitive).
        record_type: String,
        /// Target value: IPv4 / IPv6 address for A/AAAA, FQDN for
        /// CNAME.
        value: String,
        /// Profile id this record applies to. Omit to write to the
        /// global table.
        #[arg(long)]
        profile: Option<String>,
        /// Match the apex AND every descendant via longest-suffix-match.
        /// The validator refuses public suffixes and the empty
        /// domain. Defaults to `false`, i.e. exact-match only.
        #[arg(long)]
        match_subdomains: bool,
        /// Per-record TTL override (1..=86_400 seconds). Default falls
        /// back to `[local_dns].ttl_secs`.
        #[arg(long)]
        ttl_secs: Option<u32>,
        /// Optional `profiles.d/*.toml` slice to edit. Requires
        /// `--profile`: the global table only ever lives in the master
        /// config, so there is nothing to target without one.
        #[arg(long, requires = "profile")]
        into: Option<PathBuf>,
    },
    /// Remove a record by domain. With `--record-type` only the named
    /// record type is removed; without it every type matching the
    /// domain in the requested scope is dropped.
    Remove {
        /// Domain whose records should be removed.
        domain: String,
        /// Profile id; omit for the global table.
        #[arg(long)]
        profile: Option<String>,
        /// Optionally restrict to a single record type.
        #[arg(long, value_name = "A|AAAA|CNAME")]
        record_type: Option<String>,
        /// Optional `profiles.d/*.toml` slice to edit. Requires
        /// `--profile`: the global table only ever lives in the master
        /// config, so there is nothing to target without one.
        #[arg(long, requires = "profile")]
        into: Option<PathBuf>,
    },
    /// List configured local DNS records.
    List {
        /// Profile id; selects this profile's records only.
        #[arg(long)]
        profile: Option<String>,
        /// Scope filter: `global`, `profile`, or `all` (default `all`).
        /// Mutually exclusive with `--profile` — the handler resolved the
        /// pair by letting `--profile` win and dropping `--scope` on the
        /// floor, so the promise in this line is now enforced by clap.
        #[arg(long, value_name = "global|profile|all", conflicts_with = "profile")]
        scope: Option<String>,
        /// Filter by record type.
        #[arg(long, value_name = "A|AAAA|CNAME")]
        record_type: Option<String>,
    },
    /// Show the detail (type / value / subdomain / ttl / scope) of every
    /// record matching `domain`. Without `--profile`, the global table
    /// + every profile is searched.
    Show {
        /// Domain to look up.
        domain: String,
        /// Profile id; restricts the search to that profile.
        #[arg(long)]
        profile: Option<String>,
    },
}

/// `warden rewrite` subcommands. Profile-scoped only.
#[derive(Subcommand)]
pub enum RewriteAction {
    /// Add a rewrite rule on the named profile. Single-pass at runtime
    /// (no chaining). `--match-subdomains` opts the rule into longest-
    /// suffix matching with prefix preservation (`api.x.old.com →
    /// api.x.new.com`). Validator refuses public-suffix wildcards,
    /// reserved TLDs (`localhost`, `local`, `arpa`, `invalid`,
    /// `example`, `test`, `onion`), identity rules, and config-time
    /// cycles (`A→B→A`).
    Add {
        /// Source FQDN (lowercased automatically).
        from: String,
        /// Replacement FQDN.
        to: String,
        /// Profile id this rule applies to. Required — rewrite rules
        /// have no global scope.
        #[arg(long)]
        profile: String,
        /// Match the apex AND every descendant. Default `false`
        /// (exact-match only).
        #[arg(long)]
        match_subdomains: bool,
        /// Optional `profiles.d/*.toml` slice to edit.
        #[arg(long)]
        into: Option<PathBuf>,
    },
    /// Remove every rule matching `from` on the named profile.
    Remove {
        /// Source FQDN whose rules should be removed.
        from: String,
        /// Profile id.
        #[arg(long)]
        profile: String,
        /// Optional `profiles.d/*.toml` slice to edit.
        #[arg(long)]
        into: Option<PathBuf>,
    },
    /// List configured rewrite rules. Without `--profile` every
    /// profile is listed.
    List {
        /// Profile id; selects this profile only.
        #[arg(long)]
        profile: Option<String>,
    },
}

#[cfg(test)]
mod plp_s5c_tag_surface_tests {
    use clap::CommandFactory;

    /// Every page in the compiled clap tree, as `(path, text)` pairs.
    ///
    /// Walks [`super::Cli::command()`] — the tree the binary dispatches
    /// from — rather than grepping `///` lines, for the reason the help
    /// fence in `tests/cli_help_no_internal_refs.rs` already documents: a
    /// grep cannot tell a clap doc comment from an ordinary rustdoc one,
    /// and it cannot see help set through `#[arg(help = …)]` at all.
    ///
    /// Both `about` and `long_about` are collected. `-h` renders the
    /// first, `--help` the second; scanning one would leave half the
    /// surface unchecked.
    fn help_pages() -> Vec<(String, String)> {
        fn walk(cmd: &clap::Command, path: &str, out: &mut Vec<(String, String)>) {
            let here = if path.is_empty() {
                cmd.get_name().to_string()
            } else {
                format!("{path} {}", cmd.get_name())
            };
            for t in [cmd.get_about(), cmd.get_long_about()]
                .into_iter()
                .flatten()
            {
                out.push((here.clone(), t.to_string()));
            }
            for a in cmd.get_arguments() {
                for t in [a.get_help(), a.get_long_help()].into_iter().flatten() {
                    out.push((format!("{here} --{}", a.get_id()), t.to_string()));
                }
            }
            for sub in cmd.get_subcommands() {
                walk(sub, &here, out);
            }
        }
        let mut out = Vec::new();
        walk(&super::Cli::command(), "", &mut out);
        out
    }

    /// No verb named `tag` / `tags` survives below a noun.
    ///
    /// `warden tags` itself is the deliberate exception: it is the
    /// signpost, and `tags_verb_is_the_only_survivor_and_it_refuses` in
    /// `main.rs` holds it to actually refusing.
    #[test]
    fn no_noun_carries_a_tag_sub_verb() {
        fn walk(cmd: &clap::Command, path: &str, out: &mut Vec<String>) {
            for sub in cmd.get_subcommands() {
                let name = sub.get_name();
                if (name == "tag" || name == "tags") && !path.is_empty() {
                    out.push(format!("{path} {name}"));
                }
                walk(sub, &format!("{path} {name}"), out);
            }
        }
        let mut found = Vec::new();
        walk(&super::Cli::command(), "", &mut found);
        assert!(
            found.is_empty(),
            "tags decide nothing since plp-s3; a verb that writes one is a \
             silent no-op. Found: {found:?}"
        );
    }

    /// No argument named `tag` / `tags` survives anywhere.
    ///
    /// Keyed on the argument **id**, not on the rendered help: `hide =
    /// true` removes a flag from every help page and leaves it perfectly
    /// typeable, so a page-scraping check would pass on exactly the flag
    /// that still works.
    #[test]
    fn no_verb_carries_a_tag_flag() {
        fn walk(cmd: &clap::Command, path: &str, out: &mut Vec<String>) {
            let here = format!("{path} {}", cmd.get_name());
            for a in cmd.get_arguments() {
                let id = a.get_id().as_str();
                if id == "tag" || id == "tags" {
                    out.push(format!("{here} --{id}"));
                }
            }
            for sub in cmd.get_subcommands() {
                walk(sub, &here, out);
            }
        }
        let mut found = Vec::new();
        walk(&super::Cli::command(), "", &mut found);
        assert!(found.is_empty(), "tag flags survive: {found:?}");
    }

    /// The needles above have to be able to fire.
    ///
    /// A guard that cannot fail is indistinguishable from one that passes,
    /// and both walks would report an empty list against a tree they
    /// failed to descend — which is the likelier bug than a missed match.
    /// This proves the recursion reaches real nouns and real flags.
    #[test]
    fn the_walks_actually_descend_the_tree() {
        let pages = help_pages();
        assert!(
            pages.len() > 100,
            "only {} pages — walk is shallow",
            pages.len()
        );

        let paths: Vec<&str> = pages.iter().map(|(p, _)| p.as_str()).collect();
        for expect in [
            "warden profile list-policy set",
            "warden blocklist set-kind",
            "warden device set-unfiltered",
        ] {
            assert!(
                paths.contains(&expect),
                "walk never reached `{expect}` — the tag needles proved nothing"
            );
        }
        assert!(
            paths.iter().any(|p| p.ends_with("--accept_unsigned_allow")),
            "walk never reached an argument — the flag needle proved nothing"
        );
    }

    /// No help page may claim a tag decides what a client filters.
    ///
    /// This is the defect class lane 4a measured: seven pages still said
    /// tags decided a profile's applicability, long after `plp-s3` made
    /// that false. A stale claim in help is worse than a missing one — the
    /// operator acts on it, and the action silently does nothing.
    ///
    /// Deliberately narrow. It does NOT ban the word: `device
    /// set-unfiltered` legitimately says it clears the `tags` array (the
    /// D14 mutual exclusion is live and the validator still enforces it),
    /// `label` legitimately offers a `tag` vocabulary dimension, and
    /// `migrate v2-to-v3` must describe the tags it is translating. What
    /// is banned is the *claim of effect*.
    #[test]
    fn no_help_page_claims_a_tag_still_decides_anything() {
        let claims = [
            "carry at least one tag",
            "requires at least one tag",
            "needs at least one tag",
            "tags intersect",
            "tag intersection",
            "which lists apply",
        ];
        let mut hits = Vec::new();
        for (path, text) in help_pages() {
            if path.starts_with("warden migrate") {
                continue; // the v2→v3 migrator must describe the old model
            }
            let lower = text.to_lowercase();
            for c in claims {
                if lower.contains(c) {
                    hits.push(format!("{path}: {c:?}"));
                }
            }
        }
        assert!(
            hits.is_empty(),
            "help pages still claim tags decide something: {hits:#?}"
        );
    }

    /// The claim needles can fire too.
    #[test]
    fn the_claim_needles_discriminate() {
        let sample = "needs the list to carry at least one tag; both are checked";
        assert!(sample.to_lowercase().contains("carry at least one tag"));
        let innocent = "also clears the `tags` array in the same write";
        for c in [
            "carry at least one tag",
            "tag intersection",
            "which lists apply",
        ] {
            assert!(
                !innocent.to_lowercase().contains(c),
                "needle {c:?} would fire on the legitimate set-unfiltered wording"
            );
        }
    }
}
