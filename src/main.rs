#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::path::{Path, PathBuf};

use clap::Parser;

use purge_warden::*;

/// Whether a command connects to the running daemon over the IPC socket and
/// therefore needs `[socket].path` resolved up front.
///
/// main-01: the eager config parse that derives the socket path runs for every
/// command and prints a "cannot read config" warning on failure — actively
/// wrong on a fresh box where `warden init` is about to CREATE that config, and
/// a wasted second parse for `Start` / `FirewallRules` (which load the config
/// themselves). The non-IPC commands below never read `socket_path`, so they
/// skip the eager load. Default is `true` (load): any command not explicitly
/// listed here — including future ones — keeps the safe behaviour of resolving
/// the socket path, so a forgotten entry fails safe (a needless parse) rather
/// than connecting an IPC command to the wrong socket.
fn command_needs_socket(command: &cli::Commands) -> bool {
    !matches!(
        command,
        cli::Commands::Start { .. }
            | cli::Commands::Init { .. }
            | cli::Commands::Resolve { .. }
            // `lists refresh` (ex-`warden update`) drives the daemon over
            // SIGHUP, not IPC — it never reads `socket_path`. Every other
            // `lists` action does: `forget` over IPC, and the rest to ask
            // whether the corpus is frozen. So the skip is scoped to this
            // one action rather than the whole subcommand.
            | cli::Commands::Lists {
                action: cli::ListsAction::Refresh
            }
            | cli::Commands::Config { .. }
            | cli::Commands::Completion { .. }
            | cli::Commands::FirewallRules
            | cli::Commands::Migrate { .. }
            // `cluster token|join|leave` edit TOML and never open the socket
            // — only `cluster status` queries the daemon. Scoped per-action
            // like `lists refresh` above, for the same reason.
            //
            // Since S2 these three legitimately run against a config that
            // does NOT load: `init --cluster-secondary` writes a policy-free
            // master that is refused until `enabled = true`, which is what
            // `join` writes, and `leave` exists to rescue configs that are
            // unloadable by construction. Warning "cannot read config …" on
            // those is not a stale edge — it fires on the DOCUMENTED happy
            // path, and a warning printed on success is how operators learn
            // to skip reading them.
            | cli::Commands::Cluster {
                action: cli::ClusterAction::Token
                    | cli::ClusterAction::Join { .. }
                    | cli::ClusterAction::Leave { .. }
                    | cli::ClusterAction::Enable { .. }
            }
    )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();

    // `init` needs to know whether `--config` was actually *given*, not just
    // what discovery settled on: discovery's no-config fallback is
    // `/etc/purge-warden/config.toml` under root, while `init`'s unflagged
    // default must stay `/var/lib/purge-warden/config.toml` for
    // `scripts/install.sh`. Captured before the resolve consumes it.
    let explicit_config = cli.config.clone();

    // Resolve the config path: honor --config if given, otherwise walk the
    // standard search list (dev → user → system). A discovery warning is
    // produced only when none of the candidates exist.
    let (config_path, discovery_warning) = cli::config_discovery::resolve_config_path(cli.config);

    // Derive the PID file: explicit --pid-file wins; otherwise track
    // the resolved config path so a systemd install (config under
    // /etc/ or /var/lib/) reaches the daemon's /run/... PID file
    // without a flag, while the dev workflow stays on the repo-local
    // `purge-warden.pid`.
    let pid_file = cli::config_discovery::resolve_pid_file(cli.pid_file, &config_path);

    let command = cli.command.unwrap_or(cli::Commands::Dashboard);

    // Load socket path from the v1 config (needed by commands that connect to
    // the running daemon via IPC). main-01: only IPC-bound commands need it, so
    // skip the eager parse for Init/Config/Migrate/Completion/Start/… — a fresh
    // box running `warden init` no longer prints a spurious "cannot read
    // config" warning, and Start/FirewallRules parse the config exactly once
    // (in their own arm). For the commands that DO need it, warn on a real
    // parse error rather than silently using the default path, or an IPC
    // command on a misconfigured install would connect to the wrong socket and
    // report "daemon not running".
    let now = time::OffsetDateTime::now_utc();
    let socket_path = if command_needs_socket(&command) {
        match config::loader::load_config(&config_path, now) {
            Ok(loaded) => loaded.config.socket.path,
            Err(errs) => {
                eprintln!(
                    "warning: cannot read config {} ({} error(s)); using fallback socket path ./control.sock",
                    config_path.display(),
                    errs.len(),
                );
                PathBuf::from("./control.sock")
            }
        }
    } else {
        // Non-IPC command: never reads `socket_path`, so don't parse the config
        // just to derive a value we won't use (and don't warn on a missing one).
        PathBuf::from("./control.sock")
    };

    // Non-TUI commands get the discovery warning on stderr. The Dashboard
    // passes it into the TUI so it lands in the footer instead of being
    // swallowed by the alternate screen buffer.
    if let Some(ref msg) = discovery_warning {
        if !matches!(command, cli::Commands::Dashboard) {
            // stderr is the one surface with unbounded width, so it gets both
            // halves. The TUI takes them apart: headline to the footer, detail
            // to the notice overlay (see `DiscoveryWarning`).
            eprintln!("warning: {}", msg.one_line());
        }
    }

    match command {
        cli::Commands::Start {
            listen,
            upstream,
            blocklist,
            lists,
            update_interval,
            daemon,
            safe_mode,
        } => {
            // Safe mode bypasses every on-disk config file and runs a
            // hardcoded minimum-risk configuration — see
            // `cli::commands::start::safe_mode_config` for the exact shape.
            let (config, custom_lists) = if safe_mode {
                print_safe_mode_banner();
                (
                    cli::commands::start::safe_mode_config(),
                    config::custom_list::CustomListStore::new(),
                )
            } else {
                // Load and validate the v1 config. `load_config` returns
                // `LoadedConfig`, carrying `ConfigV1` + provenance
                // metadata. Validation errors are collected and printed
                // with the `(file, line, entity, suggestion)` context
                // attached by the loader — each line is one actionable
                // fix.
                let now = time::OffsetDateTime::now_utc();
                let mut loaded = match config::loader::load_config(&config_path, now) {
                    Ok(l) => l,
                    Err(errs) => {
                        eprintln!("config validation failed ({} error(s)):", errs.len());
                        for err in &errs {
                            eprintln!("  - {err}");
                        }
                        // CLI/IPC mutations are validated against the merged
                        // tree before the rename (target::write_value_validated),
                        // so a killed mutation can no longer leave a
                        // cross-reference-invalid tree. A start-time load
                        // failure here therefore means a hand-edited or
                        // externally-corrupted config — point the operator at
                        // the recovery tooling regardless.
                        eprintln!(
                            "\nrun `warden config lint` to see the actionable fixes, then \
                             restart. To bring the daemon up on a known-good fallback while \
                             you fix the file, run `warden start --safe-mode`."
                        );
                        anyhow::bail!("invalid v1 config at {}", config_path.display());
                    }
                };

                // Apply CLI overrides directly to the `ConfigV1`. The
                // overrides mirror the legacy `apply_cli_overrides` logic:
                // `--listen` replaces `[server].listen`; `--upstream`
                // replaces `[upstream].servers`; `--lists` and
                // `--update-interval` replace the corresponding
                // `[lists]` fields.
                apply_cli_overrides_v1(
                    &mut loaded.config,
                    listen,
                    upstream,
                    lists,
                    update_interval,
                )?;
                // `--listen` lands after the load-time validator ran, so the
                // open-resolver refusal (unspecified bind + empty allow_from)
                // must be re-asserted on the flag path — otherwise
                // `warden start --listen 0.0.0.0:53` on a loopback-shaped
                // config silently answers the world.
                // `binds_every_interface`, not `is_unspecified`: the
                // IPv4-mapped wildcard `[::ffff:0.0.0.0]` binds every
                // interface but is not "unspecified", so the plain check
                // let it through — see the helper's doc comment.
                if purge_warden::config::schema::validator::binds_every_interface(
                    loaded.config.server.listen.ip(),
                ) && loaded.config.server.allow_from.is_empty()
                {
                    anyhow::bail!(
                        "--listen {} binds every interface but server.allow_from is empty — \
                         an open resolver: anyone who can reach this host can query it. \
                         Set allow_from in the config (e.g. [\"192.168.1.0/24\", \
                         \"127.0.0.0/8\"]), or [\"0.0.0.0/0\", \"::/0\"] to deliberately \
                         answer everyone.",
                        loaded.config.server.listen
                    );
                }
                (loaded.config, loaded.custom_lists)
            };

            // Init tracing (skip for daemon fork — the child re-inits).
            if !daemon {
                init_tracing(&config.server.log_level);
            }

            cli::commands::start::run_start(
                &config,
                &custom_lists,
                &config_path,
                &pid_file,
                blocklist.as_deref(),
                daemon,
            )
            .await?;
        }

        cli::Commands::Stop { force } => {
            cli::commands::stop::run_stop(&pid_file, &socket_path, force).await?;
        }

        cli::Commands::Status { json } => {
            let code =
                cli::commands::status::run_status(&config_path, &pid_file, &socket_path, json)
                    .await?;
            cli::exit_codes::exit_with(code);
        }

        cli::Commands::Query { domain, blocklist } => {
            let code = cli::commands::query::run_query(&domain, blocklist.as_deref(), &socket_path)
                .await?;
            cli::exit_codes::exit_with(code);
        }

        cli::Commands::Init {
            force,
            yes,
            listen,
            upstream,
            upstream_catalog,
            allow_from,
            lists,
            cluster_secondary,
            peer,
            install_manpages,
            man_dir,
        } => {
            let overrides = cli::commands::init::InitOverrides {
                listen,
                upstream,
                upstream_catalog,
                allow_from,
                lists,
                // clap's `requires = "peer"` makes the `Some` the only
                // reachable state when the flag is set; the `filter` keeps
                // that a local fact rather than an assumption baked into
                // `run_init`.
                cluster_secondary_peer: peer.filter(|_| cluster_secondary),
            };
            cli::commands::init::run_init(explicit_config.as_deref(), force, yes, &overrides)?;
            if install_manpages {
                let dir = man_dir
                    .unwrap_or_else(|| PathBuf::from(cli::commands::manpages::DEFAULT_MAN_DIR));
                let written = cli::commands::manpages::install(&dir)?;
                println!(
                    "installed {} manpage(s) under {}",
                    written.len(),
                    dir.display()
                );
            }
        }

        cli::Commands::Resolve { ip } => {
            let code = cli::commands::resolve::run_resolve(&config_path, ip)?;
            if code != 0 {
                std::process::exit(code);
            }
        }

        cli::Commands::Lists { action } => match action {
            cli::ListsAction::Add { source } => {
                cli::commands::lists::run_add(&config_path, &socket_path, &source).await?;
            }
            cli::ListsAction::Remove { source } => {
                cli::commands::lists::run_remove(&config_path, &socket_path, &source).await?;
            }
            cli::ListsAction::List => {
                cli::commands::lists::run_list(&config_path, &socket_path).await?;
            }
            cli::ListsAction::Show => {
                cli::commands::lists_knobs::run_show(&config_path, &socket_path).await?;
            }
            cli::ListsAction::Set { key, value } => {
                cli::commands::lists_knobs::run_set(&config_path, &socket_path, &key, &value)
                    .await?;
            }
            cli::ListsAction::Refresh => {
                init_tracing("info");
                let code = cli::commands::update::run_update(&config_path, &pid_file, &socket_path)
                    .await?;
                cli::exit_codes::exit_with(code);
            }
            cli::ListsAction::Catalog { scope } => {
                cli::commands::lists::run_catalog(&config_path, &socket_path, scope.as_deref())
                    .await?;
            }
            cli::ListsAction::Forget { source } => {
                cli::commands::lists::run_forget(&socket_path, &source).await?;
            }
        },

        cli::Commands::Config { action } => match action {
            cli::ConfigAction::Show {
                resolved,
                annotate,
                section,
            } => {
                cli::commands::config::run_show(
                    &config_path,
                    resolved,
                    annotate,
                    section.as_deref(),
                )?;
            }
            cli::ConfigAction::Edit => {
                let code = cli::commands::config::run_edit(&config_path)?;
                cli::exit_codes::exit_with(code);
            }
            cli::ConfigAction::Lint { strict } => {
                let code = cli::commands::config::run_lint(&config_path, strict)?;
                if code != 0 {
                    std::process::exit(code);
                }
            }
            cli::ConfigAction::Diff { other } => {
                let code = cli::commands::config::run_diff(&config_path, &other)?;
                if code != 0 {
                    std::process::exit(code);
                }
            }
            cli::ConfigAction::Backup {
                out,
                auto,
                reset_auto_failure,
            } => {
                if reset_auto_failure {
                    // Operator recovery from the Q5 auto-disable latch.
                    // No backup runs — clears `.auto_state` and returns.
                    cli::commands::config::run_reset_auto_failure(&config_path)?;
                } else {
                    let now = time::OffsetDateTime::now_utc();
                    // --auto reads the resolved backup dir inside the
                    // managed orchestrator. Manual mode honours --out or
                    // falls back to the [backup] dir for parity with the
                    // TUI / restore --list.
                    let resolved_out = if auto {
                        None
                    } else {
                        Some(match out {
                            Some(p) => p,
                            None => cli::commands::config::resolved_backup_dir(&config_path),
                        })
                    };
                    let code = cli::commands::config::run_backup_managed(
                        &config_path,
                        resolved_out.as_deref(),
                        auto,
                        now,
                    )?;
                    if code != 0 {
                        std::process::exit(code);
                    }
                }
            }
            cli::ConfigAction::Restore {
                archive,
                list,
                latest,
            } => {
                if list {
                    cli::commands::config::run_list_restore_points(&config_path)?;
                } else {
                    // --latest resolves the newest archive in the backup
                    // dir; otherwise clap guarantees an explicit path.
                    // Both feed the unchanged staged+validated swap.
                    let archive = if latest {
                        cli::commands::config::latest_archive(&config_path)?
                    } else {
                        archive.expect("clap requires archive unless --list/--latest")
                    };
                    let code = cli::commands::config::run_restore(
                        &config_path,
                        &archive,
                        Some(&pid_file),
                    )?;
                    if code != 0 {
                        std::process::exit(code);
                    }
                }
            }
            cli::ConfigAction::RenderDefault => {
                cli::commands::config::run_render_default();
            }
        },

        cli::Commands::Cache { action } => match action {
            cli::CacheAction::Flush { domain } => {
                cli::commands::cache::run_flush(&pid_file, &socket_path, domain.as_deref()).await?;
            }
        },

        cli::Commands::Profile { action } => match action {
            cli::ProfileAction::List => {
                cli::commands::profiles_v1::run_list(&config_path)?;
            }
            cli::ProfileAction::Show { id } => {
                cli::commands::profiles_v1::run_show(&config_path, &id)?;
            }
            cli::ProfileAction::Add { id, display_name } => {
                cli::commands::profiles_v1::run_create(&socket_path, &id, &display_name).await?;
            }
            cli::ProfileAction::Set { id, field, value } => {
                cli::commands::profiles_v1::run_set(&socket_path, &id, &field, &value).await?;
            }
            cli::ProfileAction::AdminRule { action } => {
                use cli::commands::profiles_v1::ProfileAdminRuleAction as AdminRule;
                match action {
                    AdminRule::Add { id, rule_id } => {
                        cli::commands::profiles_v1::run_admin_rule_add(&socket_path, &id, &rule_id)
                            .await?;
                    }
                    AdminRule::Remove { id, rule_id } => {
                        cli::commands::profiles_v1::run_admin_rule_remove(
                            &socket_path,
                            &id,
                            &rule_id,
                        )
                        .await?;
                    }
                }
            }
            cli::ProfileAction::ListPolicy { action } => {
                use cli::commands::profiles_v1::ProfileListPolicyAction as ListPolicy;
                match action {
                    ListPolicy::Set {
                        id,
                        list_id,
                        policy,
                    } => {
                        cli::commands::profiles_v1::run_list_policy_set(
                            &socket_path,
                            &id,
                            &list_id,
                            &policy,
                        )
                        .await?;
                    }
                    ListPolicy::Clear { id, list_id } => {
                        cli::commands::profiles_v1::run_list_policy_clear(
                            &socket_path,
                            &id,
                            &list_id,
                        )
                        .await?;
                    }
                    ListPolicy::Show { id } => {
                        cli::commands::profiles_v1::run_list_policy_show(&config_path, &id)?;
                    }
                }
            }
            cli::ProfileAction::Remove { id } => {
                cli::commands::profiles_v1::run_remove(&socket_path, &id).await?;
            }
            cli::ProfileAction::Allow {
                profile_id,
                domain,
                id,
                remove,
                into,
            } => {
                cli::commands::rules::run_apply(
                    &config_path,
                    &socket_path,
                    cli::commands::rules::Scope::Profile(&profile_id),
                    cli::commands::rules::Action::Allow,
                    &domain,
                    id.as_deref(),
                    remove,
                    into.as_deref(),
                )
                .await?;
            }
            cli::ProfileAction::Deny {
                profile_id,
                domain,
                id,
                remove,
                into,
            } => {
                cli::commands::rules::run_apply(
                    &config_path,
                    &socket_path,
                    cli::commands::rules::Scope::Profile(&profile_id),
                    cli::commands::rules::Action::Deny,
                    &domain,
                    id.as_deref(),
                    remove,
                    into.as_deref(),
                )
                .await?;
            }
        },

        cli::Commands::Device { action } => match action {
            cli::DeviceAction::List { live, json } => {
                if live {
                    cli::commands::devices::run_live_list(&socket_path, json).await?;
                } else {
                    cli::commands::devices::run_list(&config_path)?;
                }
            }
            cli::DeviceAction::Add {
                id,
                display_name,
                ip,
                mac,
                profile,
                groups,
                owner,
                device_type,
                department,
                notes,
                into,
            } => {
                cli::commands::devices::run_add(
                    &config_path,
                    &socket_path,
                    &id,
                    display_name.as_deref(),
                    ip,
                    mac.as_deref(),
                    profile.as_deref(),
                    &groups,
                    owner.as_deref(),
                    device_type.as_deref(),
                    department.as_deref(),
                    notes.as_deref(),
                    into.as_deref(),
                )
                .await?;
            }
            cli::DeviceAction::Set {
                id,
                field,
                value,
                into,
            } => {
                cli::commands::devices::run_set(
                    &config_path,
                    &socket_path,
                    &id,
                    &field,
                    &value,
                    into.as_deref(),
                )
                .await?;
            }
            cli::DeviceAction::Remove { id, into } => {
                cli::commands::devices::run_remove(
                    &config_path,
                    &socket_path,
                    &id,
                    into.as_deref(),
                )
                .await?;
            }
            cli::DeviceAction::Show { id } => {
                cli::commands::devices::run_show(&config_path, &id)?;
            }
            cli::DeviceAction::Block { id, into } => {
                cli::commands::devices::run_block(&config_path, &socket_path, &id, into.as_deref())
                    .await?;
            }
            cli::DeviceAction::Unblock { id, profile, into } => {
                cli::commands::devices::run_unblock(
                    &config_path,
                    &socket_path,
                    &id,
                    &profile,
                    into.as_deref(),
                )
                .await?;
            }
            cli::DeviceAction::Quiet {
                id,
                r#for,
                until,
                into,
            } => {
                cli::commands::devices::run_quiet(
                    &config_path,
                    &socket_path,
                    &id,
                    r#for.as_deref(),
                    until.as_deref(),
                    into.as_ref(),
                )
                .await?;
            }
            cli::DeviceAction::Allow {
                device_id,
                domain,
                id,
                remove,
                into,
            } => {
                cli::commands::rules::run_apply(
                    &config_path,
                    &socket_path,
                    cli::commands::rules::Scope::Device(&device_id),
                    cli::commands::rules::Action::Allow,
                    &domain,
                    id.as_deref(),
                    remove,
                    into.as_deref(),
                )
                .await?;
            }
            cli::DeviceAction::Deny {
                device_id,
                domain,
                id,
                remove,
                into,
            } => {
                cli::commands::rules::run_apply(
                    &config_path,
                    &socket_path,
                    cli::commands::rules::Scope::Device(&device_id),
                    cli::commands::rules::Action::Deny,
                    &domain,
                    id.as_deref(),
                    remove,
                    into.as_deref(),
                )
                .await?;
            }
            cli::DeviceAction::Rules { device_id, action } => match action {
                cli::DeviceRulesAction::Prune { into } => {
                    cli::commands::rules::run_prune(
                        &config_path,
                        &socket_path,
                        &device_id,
                        into.as_deref(),
                    )
                    .await?;
                }
            },
            cli::DeviceAction::SetUnfiltered { id, value, into } => {
                let parsed = match value.to_ascii_lowercase().as_str() {
                    "true" | "on" | "yes" | "1" => true,
                    "false" | "off" | "no" | "0" => false,
                    other => anyhow::bail!(
                        "invalid value '{other}'. Use one of: true, false, on, off, yes, no, 1, 0."
                    ),
                };
                cli::commands::devices::run_set_unfiltered(
                    &config_path,
                    &socket_path,
                    &id,
                    parsed,
                    into.as_deref(),
                )
                .await?
            }
        },

        cli::Commands::Label { action } => match action {
            cli::LabelAction::List => cli::commands::labels::run_list(&config_path)?,
            cli::LabelAction::Show { id, kind } => {
                cli::commands::labels::run_show(&config_path, &id, kind.as_deref())?
            }
            cli::LabelAction::Add {
                id,
                kind,
                display_name,
                description,
                into,
            } => {
                cli::commands::labels::run_add(
                    &config_path,
                    &socket_path,
                    &id,
                    &kind,
                    display_name.as_deref(),
                    description.as_deref(),
                    into.as_deref(),
                )
                .await?
            }
            cli::LabelAction::Set {
                id,
                field,
                value,
                kind,
                into,
            } => {
                cli::commands::labels::run_set(
                    &config_path,
                    &socket_path,
                    &id,
                    &field,
                    &value,
                    kind.as_deref(),
                    into.as_deref(),
                )
                .await?
            }
            cli::LabelAction::Remove { id, kind, into } => {
                cli::commands::labels::run_remove(
                    &config_path,
                    &socket_path,
                    &id,
                    kind.as_deref(),
                    into.as_deref(),
                )
                .await?
            }
        },

        cli::Commands::Group { action } => match action {
            cli::GroupAction::List => cli::commands::groups::run_list(&config_path)?,
            cli::GroupAction::Show { id } => cli::commands::groups::run_show(&config_path, &id)?,
            cli::GroupAction::Add {
                id,
                display_name,
                profile,
                priority,
                devices,
                into,
            } => {
                cli::commands::groups::run_add(
                    &config_path,
                    &socket_path,
                    &id,
                    display_name.as_deref(),
                    &profile,
                    priority,
                    &devices,
                    into.as_deref(),
                )
                .await?
            }
            cli::GroupAction::Set {
                id,
                field,
                value,
                into,
            } => {
                cli::commands::groups::run_set(
                    &config_path,
                    &socket_path,
                    &id,
                    &field,
                    &value,
                    into.as_deref(),
                )
                .await?
            }
            cli::GroupAction::Remove { id, into } => {
                cli::commands::groups::run_remove(&config_path, &socket_path, &id, into.as_deref())
                    .await?
            }
            cli::GroupAction::ProfileAllow {
                group_id,
                domain,
                id,
                remove,
                into,
            } => {
                cli::commands::rules::run_apply(
                    &config_path,
                    &socket_path,
                    cli::commands::rules::Scope::Group(&group_id),
                    cli::commands::rules::Action::Allow,
                    &domain,
                    id.as_deref(),
                    remove,
                    into.as_deref(),
                )
                .await?
            }
            cli::GroupAction::ProfileDeny {
                group_id,
                domain,
                id,
                remove,
                into,
            } => {
                cli::commands::rules::run_apply(
                    &config_path,
                    &socket_path,
                    cli::commands::rules::Scope::Group(&group_id),
                    cli::commands::rules::Action::Deny,
                    &domain,
                    id.as_deref(),
                    remove,
                    into.as_deref(),
                )
                .await?
            }
        },

        cli::Commands::Subnet { action } => match action {
            cli::SubnetAction::List => cli::commands::subnets::run_list(&config_path)?,
            cli::SubnetAction::Show { id } => cli::commands::subnets::run_show(&config_path, &id)?,
            cli::SubnetAction::Add {
                id,
                display_name,
                cidrs,
                profile,
                priority,
                into,
            } => {
                cli::commands::subnets::run_add(
                    &config_path,
                    &socket_path,
                    &id,
                    display_name.as_deref(),
                    &cidrs,
                    &profile,
                    priority,
                    into.as_deref(),
                )
                .await?
            }
            cli::SubnetAction::Set {
                id,
                field,
                value,
                into,
            } => {
                cli::commands::subnets::run_set(
                    &config_path,
                    &socket_path,
                    &id,
                    &field,
                    &value,
                    into.as_deref(),
                )
                .await?
            }
            cli::SubnetAction::Remove { id, into } => {
                cli::commands::subnets::run_remove(&config_path, &socket_path, &id, into.as_deref())
                    .await?
            }
            cli::SubnetAction::ProfileAllow {
                subnet_or_cidr,
                domain,
                id,
                remove,
                into,
            } => {
                cli::commands::rules::run_apply(
                    &config_path,
                    &socket_path,
                    cli::commands::rules::Scope::Subnet(&subnet_or_cidr),
                    cli::commands::rules::Action::Allow,
                    &domain,
                    id.as_deref(),
                    remove,
                    into.as_deref(),
                )
                .await?
            }
            cli::SubnetAction::ProfileDeny {
                subnet_or_cidr,
                domain,
                id,
                remove,
                into,
            } => {
                cli::commands::rules::run_apply(
                    &config_path,
                    &socket_path,
                    cli::commands::rules::Scope::Subnet(&subnet_or_cidr),
                    cli::commands::rules::Action::Deny,
                    &domain,
                    id.as_deref(),
                    remove,
                    into.as_deref(),
                )
                .await?
            }
        },

        cli::Commands::Schedule { action } => match action {
            cli::ScheduleAction::List => cli::commands::schedules::run_list(&config_path)?,
            cli::ScheduleAction::Remove { id } => {
                cli::commands::schedules::run_remove(&config_path, &socket_path, &id).await?
            }
        },

        cli::Commands::Blocklist { action } => match action {
            cli::BlocklistAction::List => cli::commands::blocklists::run_list(&config_path)?,
            cli::BlocklistAction::Show { id } => {
                cli::commands::blocklists::run_show(&config_path, &socket_path, &id).await?
            }
            cli::BlocklistAction::Add {
                id,
                display_name,
                url,
                format,
                update_interval_hours,
                max_entries,
                enabled,
                auth_token_ref,
                skip_head_check,
                kind,
                accept_unsigned_allow,
                into,
            } => {
                cli::commands::blocklists::run_add_with_direction(
                    &config_path,
                    &socket_path,
                    &id,
                    display_name.as_deref(),
                    &url,
                    format.as_deref(),
                    update_interval_hours,
                    max_entries,
                    enabled,
                    auth_token_ref.as_deref(),
                    skip_head_check,
                    into.as_deref(),
                    cli::commands::blocklists::AddDirection {
                        kind: kind.as_deref(),
                        accept_unsigned_allow,
                    },
                )
                .await?
            }
            cli::BlocklistAction::Set {
                id,
                field,
                value,
                into,
            } => {
                cli::commands::blocklists::run_set(
                    &config_path,
                    &socket_path,
                    &id,
                    &field,
                    &value,
                    into.as_deref(),
                )
                .await?
            }
            cli::BlocklistAction::Remove { id, into } => {
                cli::commands::blocklists::run_remove(
                    &config_path,
                    &socket_path,
                    &id,
                    into.as_deref(),
                )
                .await?
            }
            cli::BlocklistAction::SetKind {
                list_id,
                kind,
                accept_unsigned_allow,
                into,
            } => {
                cli::commands::blocklists::run_set_kind_with_ack(
                    &config_path,
                    &socket_path,
                    &list_id,
                    &kind,
                    accept_unsigned_allow,
                    into.as_deref(),
                )
                .await?
            }
            cli::BlocklistAction::SetTrust {
                list_id,
                trust,
                accept_unsigned_allow,
                into,
            } => {
                cli::commands::blocklists::run_set_trust(
                    &config_path,
                    &socket_path,
                    &list_id,
                    &trust,
                    accept_unsigned_allow,
                    into.as_deref(),
                )
                .await?
            }
            cli::BlocklistAction::ImportLocal {
                path,
                id,
                kind,
                display_name,
                into,
            } => {
                cli::commands::blocklists::run_import_local(
                    &config_path,
                    &socket_path,
                    &path,
                    &id,
                    &kind,
                    display_name.as_deref(),
                    into.as_deref(),
                )
                .await?
            }
        },

        cli::Commands::Completion { shell } => {
            cli::commands::completion::run(shell)?;
        }

        cli::Commands::Default { action } => match action {
            cli::DefaultAction::Allow {
                domain,
                id,
                remove,
                into,
                yes,
            } => {
                if !remove && !yes && !confirm_default_phrase()? {
                    eprintln!("default-scope rule not applied (confirmation aborted).");
                    std::process::exit(1);
                }
                cli::commands::rules::run_apply(
                    &config_path,
                    &socket_path,
                    cli::commands::rules::Scope::Default,
                    cli::commands::rules::Action::Allow,
                    &domain,
                    id.as_deref(),
                    remove,
                    into.as_deref(),
                )
                .await?;
            }
            cli::DefaultAction::Deny {
                domain,
                id,
                remove,
                into,
                yes,
            } => {
                if !remove && !yes && !confirm_default_phrase()? {
                    eprintln!("default-scope rule not applied (confirmation aborted).");
                    std::process::exit(1);
                }
                cli::commands::rules::run_apply(
                    &config_path,
                    &socket_path,
                    cli::commands::rules::Scope::Default,
                    cli::commands::rules::Action::Deny,
                    &domain,
                    id.as_deref(),
                    remove,
                    into.as_deref(),
                )
                .await?;
            }
        },

        cli::Commands::Rule { action } => match action {
            cli::RuleVerb::Undo => {
                cli::commands::rules::run_undo(&config_path, &socket_path).await?;
            }
        },

        cli::Commands::FirewallRules => {
            // `ConfigV1` derives `Default`, so a missing or broken config
            // still falls back to the default listen address rather than
            // failing this command outright.
            let listen = config::loader::load_config(&config_path, time::OffsetDateTime::now_utc())
                .map(|loaded| loaded.config)
                .unwrap_or_default()
                .server
                .listen;
            cli::commands::firewall_rules::run_firewall_rules(listen);
        }

        cli::Commands::Token { action } => {
            // Token commands operate on the v1 master and optionally
            // trigger a hot IPC reload, so we need both a plaintext
            // location and the daemon socket.
            let token_path =
                purge_warden::ipc::auth_token::default_token_path().ok_or_else(|| {
                    anyhow::anyhow!(
                        "cannot determine a token file location — set HOME or XDG_CONFIG_HOME"
                    )
                })?;
            match action {
                cli::TokenAction::Generate => {
                    cli::commands::token::run_generate(&config_path, &socket_path, &token_path)
                        .await?;
                }
                cli::TokenAction::Regenerate => {
                    cli::commands::token::run_regenerate(&config_path, &socket_path, &token_path)
                        .await?;
                }
            }
        }

        cli::Commands::Cluster { action } => match action {
            cli::ClusterAction::Token => {
                cli::commands::cluster::run_token(&config_path)?;
            }
            cli::ClusterAction::Join {
                peer,
                token,
                token_file,
                peer_cert,
            } => {
                cli::commands::cluster::run_join_pinned(
                    &config_path,
                    &peer,
                    token.as_deref(),
                    token_file.as_deref(),
                    peer_cert.as_deref(),
                )?;
            }
            cli::ClusterAction::Enable {
                role,
                sans,
                api_listen,
                validity_days,
            } => {
                cli::commands::cluster::run_enable(
                    &config_path,
                    role,
                    &sans,
                    api_listen,
                    validity_days,
                )?;
            }
            cli::ClusterAction::Leave { upstream } => {
                cli::commands::cluster::run_leave(&config_path, upstream.as_deref())?;
            }
            cli::ClusterAction::Status => {
                cli::commands::cluster::run_status(&socket_path, &config_path).await?;
            }
        },

        cli::Commands::Stats { action } => match action {
            cli::StatsAction::TopBlocked { limit, json } => {
                cli::commands::stats::run_top_blocked(&socket_path, limit, json).await?;
            }
            cli::StatsAction::TopQueried { limit, json } => {
                cli::commands::stats::run_top_queried(&socket_path, limit, json).await?;
            }
            cli::StatsAction::Hourly { json } => {
                cli::commands::stats::run_hourly(&socket_path, json).await?;
            }
            cli::StatsAction::Daily { json } => {
                cli::commands::stats::run_daily(&socket_path, json).await?;
            }
        },

        cli::Commands::Dashboard => {
            tui::run(&socket_path, &config_path, discovery_warning).await?;
        }

        cli::Commands::Audit { action } => match action {
            cli::AuditAction::Tail { n } => {
                let rc = cli::commands::audit::run_tail(&config_path, n)?;
                std::process::exit(rc);
            }
        },

        cli::Commands::Logs {
            limit,
            client,
            blocked,
            domain,
            since,
            format,
        } => {
            // `legacy_json = false`: the deprecated `--json` alias is gone,
            // so `--format` is now the only selector.
            cli::commands::logs::run_logs(
                &socket_path,
                limit,
                client.as_deref(),
                blocked,
                domain.as_deref(),
                since,
                format,
                false,
            )
            .await?;
        }

        // `warden tags <anything>` — the verb parses so that the
        // refusal, not clap, is what the operator reads. Binding `..`
        // rather than the argument vector is deliberate: it is the
        // compiler's proof that no argument can steer this arm.
        cli::Commands::Tags { .. } => refuse_retired_tags_verb()?,

        cli::Commands::Migrate { action } => match action {
            cli::MigrateAction::V0ToV1 {
                legacy_config,
                target,
                single_file,
                force,
            } => {
                let rc = cli::commands::migrate::run(&legacy_config, &target, single_file, force)?;
                std::process::exit(rc);
            }
            cli::MigrateAction::V1ToV3 {
                from_config,
                target,
                force,
            } => {
                let rc = cli::commands::migrate::run_v1_to_v3(&from_config, &target, force)?;
                std::process::exit(rc);
            }
            cli::MigrateAction::V1ToV2 {
                from_config,
                target,
                force,
            } => {
                let rc = cli::commands::migrate::run_v1_to_v2(&from_config, &target, force)?;
                std::process::exit(rc);
            }
            cli::MigrateAction::V2ToV3 {
                from_config,
                target,
                force,
            } => {
                let rc = cli::commands::migrate::run_v2_to_v3(&from_config, &target, force)?;
                std::process::exit(rc);
            }
        },

        cli::Commands::Reload => {
            let code = cli::commands::reload::run(&socket_path).await?;
            cli::exit_codes::exit_with(code);
        }

        cli::Commands::LocalDns { action } => match action {
            cli::LocalDnsAction::Add {
                domain,
                record_type,
                value,
                profile,
                match_subdomains,
                ttl_secs,
                into,
            } => {
                cli::commands::local_dns::run_add(
                    &config_path,
                    &socket_path,
                    &domain,
                    &record_type,
                    &value,
                    profile.as_deref(),
                    match_subdomains,
                    ttl_secs,
                    into.as_deref(),
                )
                .await?;
            }
            cli::LocalDnsAction::Remove {
                domain,
                profile,
                record_type,
                into,
            } => {
                cli::commands::local_dns::run_remove(
                    &config_path,
                    &socket_path,
                    &domain,
                    profile.as_deref(),
                    record_type.as_deref(),
                    into.as_deref(),
                )
                .await?;
            }
            cli::LocalDnsAction::List {
                profile,
                scope,
                record_type,
            } => {
                cli::commands::local_dns::run_list(
                    &config_path,
                    profile.as_deref(),
                    scope.as_deref(),
                    record_type.as_deref(),
                )?;
            }
            cli::LocalDnsAction::Show { domain, profile } => {
                cli::commands::local_dns::run_show(&config_path, &domain, profile.as_deref())?;
            }
        },

        cli::Commands::Rewrite { action } => match action {
            cli::RewriteAction::Add {
                from,
                to,
                profile,
                match_subdomains,
                into,
            } => {
                cli::commands::rewrite::run_add(
                    &config_path,
                    &socket_path,
                    &from,
                    &to,
                    &profile,
                    match_subdomains,
                    into.as_deref(),
                )
                .await?;
            }
            cli::RewriteAction::Remove {
                from,
                profile,
                into,
            } => {
                cli::commands::rewrite::run_remove(
                    &config_path,
                    &socket_path,
                    &from,
                    &profile,
                    into.as_deref(),
                )
                .await?;
            }
            cli::RewriteAction::List { profile } => {
                cli::commands::rewrite::run_list(&config_path, profile.as_deref())?;
            }
        },
        cli::Commands::Security { action } => match action {
            cli::SecurityAction::Show => {
                cli::commands::security::run_show(&config_path)?;
            }
            cli::SecurityAction::Set { key, value } => {
                cli::commands::security::run_set(&config_path, &socket_path, &key, &value).await?;
            }
            cli::SecurityAction::Tunneling { action } => match action {
                cli::TunnelingAction::Exempt { domain } => {
                    cli::commands::security::run_tunneling_exempt(
                        &config_path,
                        &socket_path,
                        &domain,
                        false,
                    )
                    .await?;
                }
                cli::TunnelingAction::Unexempt { domain } => {
                    cli::commands::security::run_tunneling_exempt(
                        &config_path,
                        &socket_path,
                        &domain,
                        true,
                    )
                    .await?;
                }
            },
        },
    }

    Ok(())
}

/// Typed-`DEFAULT` confirm for the CLI, mirroring the TUI scope modal's
/// tier-3 behaviour. Returns `true` when the operator typed `DEFAULT`
/// exactly (case-sensitive). Returns `false` (with a friendly hint) on
/// any other input including EOF / non-TTY callers — those should pass
/// `--yes` to skip the prompt.
fn confirm_default_phrase() -> anyhow::Result<bool> {
    use std::io::{BufRead, Write};
    print!("{}", cli::commands::rules::RULES_BATCH_DEFAULT_CONFIRM_CLI);
    std::io::stdout().flush().ok();
    let stdin = std::io::stdin();
    let mut line = String::new();
    let read = stdin.lock().read_line(&mut line)?;
    if read == 0 {
        // EOF: non-TTY caller. Treat as decline.
        return Ok(false);
    }
    Ok(line.trim() == "DEFAULT")
}

/// `warden tags …` — retired in full, and the verb survives only to say
/// where the capability went.
///
/// A function rather than an inline `bail!` so the refusal is reachable
/// from a test: `run()` needs a config, a socket and a runtime, and a
/// signpost nobody can test is a signpost that rots.
///
/// Reuses [`TAGS_RETIRED`](cli::commands::entity_tags::TAGS_RETIRED)
/// rather than restating it. Two copies of one message drifting apart is
/// the defect this whole workstream is unwinding.
fn refuse_retired_tags_verb() -> anyhow::Result<()> {
    anyhow::bail!("{}", cli::commands::entity_tags::TAGS_RETIRED)
}

/// Print the safe-mode banner. A single call point shared between the
/// CLI dispatch and the daemon boot so the warning is impossible to miss
/// even when someone eventually pipes stderr into a log aggregator.
fn print_safe_mode_banner() {
    eprintln!("╔══════════════════════════════════════════════════════════════════╗");
    eprintln!("║                                                                  ║");
    eprintln!("║   SAFE MODE — all filtering DISABLED. Listening 127.0.0.1:5335.  ║");
    eprintln!("║                                                                  ║");
    eprintln!("║   Fix the on-disk config and restart without --safe-mode to      ║");
    eprintln!("║   resume normal operation.                                       ║");
    eprintln!("║                                                                  ║");
    eprintln!("╚══════════════════════════════════════════════════════════════════╝");
}

/// Refusal shown when `warden start --lists` is used.
///
/// The flag wrote the list ids into the part of the configuration that
/// downloads lists but cannot filter with them, so the daemon came up
/// looking subscribed and blocked nothing. Rather than quietly make the
/// flag mean something new, it now names the verb that works.
const START_LISTS_FLAG_RETIRED: &str = "\
`--lists` cannot subscribe to a list. It set a form of subscription that downloads on \
schedule but that no profile can filter with, so the daemon started up reporting the \
lists as active while blocking nothing from them.

Subscribe first, then start:
  warden lists add <list-id|url>
  warden start

`warden lists catalog` shows the available list ids.";

/// Apply CLI overrides to a [`config::schema::ConfigV1`] in place.
/// Replaces the retired v0 `Settings::apply_cli_overrides` so
/// `--listen` / `--upstream` / `--update-interval` keep working against
/// the v1 config format. `--lists` is refused — see
/// [`START_LISTS_FLAG_RETIRED`].
fn apply_cli_overrides_v1(
    config: &mut config::schema::ConfigV1,
    listen: Option<std::net::SocketAddr>,
    upstream: Vec<String>,
    lists: Vec<String>,
    update_interval: Option<u64>,
) -> anyhow::Result<()> {
    if !lists.is_empty() {
        anyhow::bail!("{START_LISTS_FLAG_RETIRED}");
    }
    if let Some(addr) = listen {
        config.server.listen = addr;
    }
    if !upstream.is_empty() {
        config.upstream.servers = upstream;
    }
    if let Some(secs) = update_interval {
        config.lists.update_interval_secs = secs;
    }
    Ok(())
}

/// Environment variable set by `fork_daemon()` to communicate the log
/// directory to the child process. The child reads this in `main()`
/// before calling `init_tracing` and routes through the daemon log
/// path that installs a `RollingFileAppender`.
///
/// Plain env var (not a CLI flag) so it survives the
/// `std::env::args().filter(|a| a != "--daemon")` rewrite that
/// `fork_daemon` does to prevent infinite fork loops.
const DAEMON_LOGS_DIR_ENV: &str = "PURGE_WARDEN_DAEMON_LOGS_DIR";

/// Tracing initialization mode — `Foreground` writes to stderr,
/// `Daemon` installs a daily-rotating file appender via tracing-appender.
enum LogMode {
    Foreground,
    Daemon { logs_dir: PathBuf },
}

fn init_tracing(log_level: &str) {
    init_tracing_with_mode(log_level, current_log_mode());
}

/// Resolve the log mode from the environment. The child process spawned
/// by `fork_daemon` inherits `PURGE_WARDEN_DAEMON_LOGS_DIR=<path>`; in
/// every other invocation the env var is absent and we fall back to the
/// foreground path.
///
/// That path writes to **stdout**, not stderr: `init_tracing_with_mode`
/// passes the writer explicitly, and `tracing_subscriber::fmt()` defaults
/// to `io::stdout` — the explicit argument preserves that default rather
/// than overriding it, so don't "correct" this to stderr without checking
/// the call site.
///
/// **Every systemd-run instance takes the `Foreground` arm.** `Type=simple`
/// units have no `EnvironmentFile`, so `PURGE_WARDEN_DAEMON_LOGS_DIR` is
/// absent from the running process's environment — only `fork_daemon` sets
/// that variable, and systemd does not use it. So the `Daemon` arm below —
/// the `tracing_appender` writer and the dir-creation-failure fallback
/// alike — is exercised only by `fork_daemon`, never by a systemd-managed
/// process; `current_log_mode`'s *selection* is tested, the `install` call
/// inside that arm is not.
fn current_log_mode() -> LogMode {
    match std::env::var_os(DAEMON_LOGS_DIR_ENV) {
        Some(dir) if !dir.is_empty() => LogMode::Daemon {
            logs_dir: PathBuf::from(dir),
        },
        _ => LogMode::Foreground,
    }
}

/// The directive that keeps per-query resolver logging out of the
/// journal, or `None` when the operator has asked to see it.
///
/// `hickory_server` emits one INFO line per query. At household volume
/// that is tens of thousands of lines a day, and warden's own WARN and
/// ERROR lines — a refused refresh, a list that failed to download —
/// land between them at a ratio that makes them unfindable by reading.
/// Damping that one target is what makes the journal legible.
///
/// Three ways to turn it off, all explicit. Raising the level to `debug`
/// or `trace` says the operator is debugging queries. Lowering it to
/// `warn` or `error` already silences the per-query INFO stream — and a
/// target-bearing directive outranks a bare level, so adding
/// `hickory_server=warn` under `error` would *admit* resolver warnings
/// the operator had silenced. Naming `hickory_server` in `RUST_LOG` says
/// they have already decided what they want for that target — and since
/// a later directive on the SAME target replaces an earlier one, damping
/// anyway would not compete with their choice, it would silently
/// overwrite it. Only `info` (and an unparseable level, which the
/// subscriber treats as `info`) is damped.
pub(crate) fn per_query_noise_directive(
    log_level: &str,
    rust_log: Option<&str>,
) -> Option<&'static str> {
    // Parsed rather than compared, so the spellings `Level` accepts are
    // the spellings this accepts — including the upper-case ones.
    if matches!(
        log_level.trim().parse::<tracing::Level>(),
        Ok(tracing::Level::DEBUG
            | tracing::Level::TRACE
            | tracing::Level::WARN
            | tracing::Level::ERROR)
    ) {
        return None;
    }
    if rust_log.is_some_and(|s| s.contains("hickory_server")) {
        return None;
    }
    Some("hickory_server=warn")
}

/// Build the subscriber's filter: `RUST_LOG` directives, then the level,
/// then the per-query damper.
///
/// `rust_log` is a parameter rather than a read so the composition can be
/// tested; the caller reads the variable once. Passing
/// `env::var("RUST_LOG").ok()` reproduces `EnvFilter::from_default_env()`
/// exactly — the same lossy parse of the same variable, and the same
/// empty string when it is unset or not UTF-8.
///
/// Order is load-bearing. `EnvFilter` resolves an event against the most
/// specific matching directive, so the damper — which names a target —
/// wins over the bare level added before it.
fn build_log_filter(log_level: &str, rust_log: Option<&str>) -> tracing_subscriber::EnvFilter {
    let filter = tracing_subscriber::EnvFilter::new(rust_log.unwrap_or_default()).add_directive(
        log_level
            .parse()
            .unwrap_or_else(|_| tracing::Level::INFO.into()),
    );
    match per_query_noise_directive(log_level, rust_log) {
        // Parsed, not constructed: a literal that stopped parsing would
        // otherwise disappear into a filter that logs everything again,
        // which is the failure this whole function exists to prevent.
        Some(d) => filter.add_directive(d.parse().expect("static directive literal must parse")),
        None => filter,
    }
}

fn init_tracing_with_mode(log_level: &str, mode: LogMode) {
    use std::io::IsTerminal;

    let filter = build_log_filter(log_level, std::env::var("RUST_LOG").ok().as_deref());

    match mode {
        LogMode::Foreground => {
            // Disable ANSI colors when stderr is not a terminal (piped
            // output, systemd journal). The child process spawned by
            // fork_daemon() takes the Daemon branch above instead, so
            // this branch only runs for foreground starts and CLI
            // commands like `warden lists refresh`.
            let ansi = std::io::stderr().is_terminal();
            // `log_ring::install` also feeds the in-daemon ring buffer the
            // TUI's Logs leaf reads over IPC. `std::io::stdout` is passed
            // explicitly because that is what `tracing_subscriber::fmt()`
            // defaulted to here — the writer must not change silently while
            // the composition does.
            tracking::log_ring::install(filter, ansi, std::io::stdout);
        }
        LogMode::Daemon { logs_dir } => {
            // Best-effort directory creation. If this fails (permission,
            // disk full), fall back to stderr so the operator still sees
            // the first-run error and can fix it. Without this fallback,
            // a fresh install with a missing /var/lib/purge-warden/logs
            // would silently swallow startup errors.
            if let Err(e) = std::fs::create_dir_all(&logs_dir) {
                eprintln!(
                    "warning: cannot create logs directory {}: {} \
                     — falling back to stderr-only logging",
                    logs_dir.display(),
                    e
                );
                tracking::log_ring::install(filter, false, std::io::stdout);
                return;
            }
            // Mode 0750 on the logs directory (operator + group only —
            // PII can land in query logs at debug level).
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&logs_dir, std::fs::Permissions::from_mode(0o750));
            }

            // Retention: drop purge-warden.log.YYYY-MM-DD files older
            // than 7 days. Failure is non-fatal — we'd rather log too
            // much than refuse to start.
            sweep_old_log_files(&logs_dir, 7);

            let appender = tracing_appender::rolling::daily(&logs_dir, "purge-warden.log");
            let (writer, guard) = tracing_appender::non_blocking(appender);
            // Leak the guard for the process lifetime — it must be
            // alive when the worker thread flushes pending writes on
            // shutdown. Tracing subscribers are by design global +
            // process-scoped, so leaking is the canonical pattern
            // (matches the tracing-appender README example).
            Box::leak(Box::new(guard));

            tracking::log_ring::install(filter, false, writer);
        }
    }
}

/// Delete `purge-warden.log.YYYY-MM-DD` files in `logs_dir` older than
/// `keep_days` days. Returns the number of files removed. Non-fatal:
/// any I/O error logs a warning to stderr (tracing is not initialized
/// yet at the call site) and the function returns whatever it managed
/// to delete so far.
fn sweep_old_log_files(logs_dir: &Path, keep_days: i64) -> usize {
    let cutoff = time::OffsetDateTime::now_utc().date() - time::Duration::days(keep_days);
    let entries = match std::fs::read_dir(logs_dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!(
                "warning: cannot enumerate logs dir {}: {}",
                logs_dir.display(),
                e
            );
            return 0;
        }
    };
    // Format is a hardcoded literal — parse once, reuse across every
    // entry. Anything that fails to parse against it is left alone so a
    // future format upgrade does not nuke files it doesn't recognize.
    let format = time::format_description::parse("[year]-[month]-[day]")
        .expect("hardcoded YYYY-MM-DD format always parses");
    let mut removed = 0usize;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(date_str) = name.strip_prefix("purge-warden.log.") else {
            continue;
        };
        let parsed = match time::Date::parse(date_str, &format) {
            Ok(d) => d,
            Err(_) => continue,
        };
        if parsed < cutoff {
            if let Err(e) = std::fs::remove_file(entry.path()) {
                eprintln!(
                    "warning: cannot remove old log {}: {}",
                    entry.path().display(),
                    e
                );
            } else {
                removed += 1;
            }
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `cluster token|join|leave` edit TOML; only `status` talks to the
    /// daemon. Asking for the socket path makes main parse the config and
    /// warn when it does not load — and since S2 an unloadable config is the
    /// EXPECTED state for all three (`init --cluster-secondary` writes a
    /// policy-free master that is refused until `join` sets `enabled`), so
    /// the warning fired on the documented happy path.
    ///
    /// `status` is asserted in the same test on purpose: it is the boundary.
    /// An implementation that skips the whole `Cluster` subcommand instead of
    /// the three verbs reds here, and would otherwise send `status` to
    /// `./control.sock` on any install whose socket is elsewhere.
    #[test]
    fn only_cluster_status_needs_the_socket() {
        for action in [
            cli::ClusterAction::Token,
            cli::ClusterAction::Join {
                peer: "https://192.0.2.1:8053".into(),
                token: None,
                token_file: None,
                peer_cert: None,
            },
            cli::ClusterAction::Leave { upstream: None },
            // S4. The array is not exhaustive over `ClusterAction`, so
            // nothing but this line makes a new config-editing verb assert
            // it does not force a socket.
            cli::ClusterAction::Enable {
                role: cli::EnableRole::Primary,
                sans: vec!["192.0.2.10".into()],
                api_listen: None,
                validity_days: 3650,
            },
        ] {
            assert!(
                !command_needs_socket(&cli::Commands::Cluster { action }),
                "config-editing cluster verbs must not force a config parse"
            );
        }
        assert!(
            command_needs_socket(&cli::Commands::Cluster {
                action: cli::ClusterAction::Status
            }),
            "cluster status queries the daemon and DOES need the real socket path"
        );
    }

    /// The skip must not leak to unrelated verbs: a config that fails to load
    /// for any other reason still has to warn, or an IPC command on a
    /// misconfigured install connects to the wrong socket and reports
    /// "daemon not running".
    #[test]
    fn ipc_commands_still_need_the_socket() {
        assert!(command_needs_socket(&cli::Commands::Reload));
        assert!(command_needs_socket(&cli::Commands::Dashboard));
    }

    /// `--lists` is refused rather than silently writing a subscription
    /// that cannot filter. The other overrides must keep working.
    #[test]
    fn lists_flag_is_refused_and_leaves_the_config_alone() {
        let mut c = config::schema::ConfigV1::default();
        let err = apply_cli_overrides_v1(
            &mut c,
            None,
            Vec::new(),
            vec!["privacy/ads".to_string()],
            None,
        )
        .expect_err("--lists must not be honoured");
        let msg = err.to_string();
        assert!(msg.contains("--lists"), "must name the flag: {msg}");
        assert!(
            msg.contains("warden lists add"),
            "must name the verb that subscribes: {msg}"
        );
        assert!(
            c.lists.sources.is_empty(),
            "a refused flag must not have written anything"
        );
    }

    #[test]
    fn other_start_overrides_still_apply() {
        let mut c = config::schema::ConfigV1::default();
        apply_cli_overrides_v1(
            &mut c,
            Some("127.0.0.1:15353".parse().unwrap()),
            vec!["9.9.9.9:53".to_string()],
            Vec::new(),
            Some(900),
        )
        .unwrap();
        assert_eq!(c.server.listen, "127.0.0.1:15353".parse().unwrap());
        assert_eq!(c.upstream.servers, vec!["9.9.9.9:53".to_string()]);
        assert_eq!(c.lists.update_interval_secs, 900);
    }

    /// Build a `purge-warden.log.YYYY-MM-DD` file at the given date in
    /// `dir`. Used by the retention sweep tests below.
    fn write_log_at(dir: &Path, date: time::Date) {
        let format = time::format_description::parse("[year]-[month]-[day]").unwrap();
        let name = format!("purge-warden.log.{}", date.format(&format).unwrap());
        std::fs::write(dir.join(name), b"sample log line\n").unwrap();
    }

    #[test]
    fn sweep_keeps_recent_logs() {
        let dir = tempfile::tempdir().unwrap();
        let today = time::OffsetDateTime::now_utc().date();
        // Files at today, yesterday, three days ago — all within
        // the 7-day window, none should be deleted.
        write_log_at(dir.path(), today);
        write_log_at(dir.path(), today - time::Duration::days(1));
        write_log_at(dir.path(), today - time::Duration::days(3));

        let removed = sweep_old_log_files(dir.path(), 7);
        assert_eq!(removed, 0);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 3);
    }

    #[test]
    fn sweep_removes_logs_older_than_keep_window() {
        let dir = tempfile::tempdir().unwrap();
        let today = time::OffsetDateTime::now_utc().date();
        // 8 days ago and 30 days ago — both stale, both should go.
        write_log_at(dir.path(), today - time::Duration::days(8));
        write_log_at(dir.path(), today - time::Duration::days(30));
        // 6 days ago — within window, should survive.
        write_log_at(dir.path(), today - time::Duration::days(6));

        let removed = sweep_old_log_files(dir.path(), 7);
        assert_eq!(removed, 2);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn sweep_ignores_unrelated_files() {
        // The retention sweep must not touch files it does not own —
        // operators occasionally drop their own notes or scripts in
        // the logs directory and would be unhappy if we deleted them.
        let dir = tempfile::tempdir().unwrap();
        let today = time::OffsetDateTime::now_utc().date();
        write_log_at(dir.path(), today - time::Duration::days(30)); // stale, will go
        std::fs::write(dir.path().join("daemon-stderr.log"), b"panic backtrace").unwrap();
        std::fs::write(dir.path().join("notes.txt"), b"operator note").unwrap();
        std::fs::write(
            dir.path().join("purge-warden.log.not-a-date"),
            b"corrupt name",
        )
        .unwrap();

        let removed = sweep_old_log_files(dir.path(), 7);
        assert_eq!(removed, 1);
        assert!(dir.path().join("daemon-stderr.log").exists());
        assert!(dir.path().join("notes.txt").exists());
        assert!(dir.path().join("purge-warden.log.not-a-date").exists());
    }

    #[test]
    fn sweep_missing_dir_returns_zero() {
        // Best-effort: a nonexistent logs dir is not an error, the
        // sweep simply does nothing and returns 0.
        let removed = sweep_old_log_files(Path::new("/nonexistent/purge-warden-logs"), 7);
        assert_eq!(removed, 0);
    }

    /// Serialises every test that mutates [`DAEMON_LOGS_DIR_ENV`].
    ///
    /// The env var is **process-global** and `cargo test` runs the two
    /// `current_log_mode_*` tests on parallel threads of ONE process, so
    /// without this they race: `..._default_is_foreground` removes the var
    /// between the other test's `set_var` and its read, and
    /// `..._with_env_var_returns_daemon` fails on
    /// `expected Daemon mode when env var is set`. Intermittent, and it
    /// passes in isolation, which is why it read as flake for a long time.
    ///
    /// The save/restore dance in each test was never the problem — it makes
    /// each test clean up after *itself*, which does nothing about a sibling
    /// observing the window in between. Only mutual exclusion closes it.
    ///
    /// Poisoning is recovered rather than propagated: if one of these tests
    /// panics while holding the lock, the *other* must still report its own
    /// verdict instead of a `PoisonError` that hides which one really broke.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn current_log_mode_default_is_foreground() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Save and restore the env var so the test does not leak
        // state to other tests in the same process.
        let saved = std::env::var_os(DAEMON_LOGS_DIR_ENV);
        // SAFETY: tests mutating this var are serialised by `ENV_LOCK`, so no
        // other thread reads it while it is cleared here. The previous comment
        // claimed no concurrent test touched it "(the LogMode tests are the
        // only ones)" — true of the rest of the module and false of exactly
        // the pair it was defending: these two touch it against each other.
        unsafe { std::env::remove_var(DAEMON_LOGS_DIR_ENV) };
        assert!(matches!(current_log_mode(), LogMode::Foreground));
        if let Some(v) = saved {
            unsafe { std::env::set_var(DAEMON_LOGS_DIR_ENV, v) };
        }
    }

    #[test]
    fn current_log_mode_with_env_var_returns_daemon() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var_os(DAEMON_LOGS_DIR_ENV);
        // SAFETY: serialised by `ENV_LOCK` — see the sibling test above.
        unsafe { std::env::set_var(DAEMON_LOGS_DIR_ENV, "/tmp/test-logs-dir") };
        match current_log_mode() {
            LogMode::Daemon { logs_dir } => {
                assert_eq!(logs_dir, PathBuf::from("/tmp/test-logs-dir"))
            }
            LogMode::Foreground => panic!("expected Daemon mode when env var is set"),
        }
        match saved {
            Some(v) => unsafe { std::env::set_var(DAEMON_LOGS_DIR_ENV, v) },
            None => unsafe { std::env::remove_var(DAEMON_LOGS_DIR_ENV) },
        }
    }

    // ── Per-query journal noise. The damper is applied at the default
    // level and stood down whenever the operator has asked for the
    // per-query stream, either by level or by target. ───────────────

    #[test]
    fn the_default_level_damps_per_query_logging() {
        assert_eq!(
            per_query_noise_directive("info", None),
            Some("hickory_server=warn")
        );
        // An explicit RUST_LOG that says nothing about the resolver is
        // not a decision about the resolver.
        assert_eq!(
            per_query_noise_directive("info", Some("warn")),
            Some("hickory_server=warn")
        );
    }

    /// Asking for `debug` or `trace` IS asking for the per-query stream —
    /// it is the only place a single query's path is visible — so the
    /// damper must not survive the request that needs it gone.
    #[test]
    fn debugging_turns_the_damper_off() {
        assert_eq!(per_query_noise_directive("debug", None), None);
        assert_eq!(per_query_noise_directive("trace", None), None);
        // The level is parsed, so case is not a way to lose the opt-out.
        assert_eq!(per_query_noise_directive("DEBUG", None), None);
        assert_eq!(per_query_noise_directive("  trace  ", None), None);
    }

    /// A quieter level needs no damper, and must not get one: a directive
    /// that names a target outranks a bare level, so `hickory_server=warn`
    /// under `error` would let resolver warnings through that the level
    /// had silenced. An unparseable level falls back to `info` in the
    /// subscriber and stays damped.
    #[test]
    fn a_quieter_level_turns_the_damper_off_too() {
        assert_eq!(per_query_noise_directive("warn", None), None);
        assert_eq!(per_query_noise_directive("error", None), None);
        assert_eq!(per_query_noise_directive("ERROR", None), None);
        assert_eq!(
            per_query_noise_directive("info", None),
            Some("hickory_server=warn")
        );
        assert_eq!(
            per_query_noise_directive("bogus", None),
            Some("hickory_server=warn")
        );
    }

    /// An operator who has named the target in `RUST_LOG` has already
    /// decided. The damper names the same target, so adding it would
    /// replace their directive rather than lose to it — silently
    /// inverting an explicit instruction.
    #[test]
    fn a_rust_log_directive_for_the_resolver_wins_outright() {
        assert_eq!(
            per_query_noise_directive("info", Some("hickory_server=info")),
            None
        );
        assert_eq!(
            per_query_noise_directive("info", Some("warn,hickory_server=trace")),
            None
        );
    }

    /// The damper is a string literal that is parsed at startup. If it
    /// ever stops parsing, `build_log_filter` panics — so the parse is
    /// pinned here rather than left to the `expect`.
    #[test]
    fn the_damper_directive_parses() {
        let d = per_query_noise_directive("info", None).expect("damper at the default level");
        assert!(
            d.parse::<tracing_subscriber::filter::Directive>().is_ok(),
            "{d} must parse as a directive"
        );
    }

    /// Records every event the filter admits, so both the absence of one
    /// event and the presence of another are measurable.
    struct Captured(std::sync::Arc<std::sync::Mutex<Vec<(String, tracing::Level)>>>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Captured {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let m = event.metadata();
            self.0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((m.target().to_string(), *m.level()));
        }
    }

    fn captured_under(
        filter: tracing_subscriber::EnvFilter,
        emit: impl FnOnce(),
    ) -> Vec<(String, tracing::Level)> {
        use tracing_subscriber::layer::SubscriberExt;
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry()
            .with(filter)
            .with(Captured(std::sync::Arc::clone(&seen)));
        tracing::subscriber::with_default(subscriber, emit);
        let out = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
        out
    }

    /// The composed filter, not just the directive string: at the
    /// default level a resolver INFO event must be dropped while
    /// warden's own WARN still arrives.
    ///
    /// The `purge_warden` assertion is the positive control and is
    /// load-bearing — without it, "no `hickory_server` event" would also
    /// hold if the capture layer had received nothing at all.
    #[test]
    fn at_info_the_filter_drops_resolver_noise_and_keeps_warden_warnings() {
        // Emitted from this test's own source lines: callsite interest is
        // cached per invocation site, so sharing them with the `debug`
        // test below could carry one filter's verdict into the other.
        let seen = captured_under(build_log_filter("info", None), || {
            tracing::info!(target: "hickory_server", "query received");
            tracing::warn!(target: "purge_warden", "refresh refused");
        });
        assert!(
            seen.iter()
                .any(|(t, l)| t == "purge_warden" && *l == tracing::Level::WARN),
            "warden's own warning must survive the damper: {seen:?}"
        );
        assert!(
            !seen.iter().any(|(t, _)| t == "hickory_server"),
            "per-query logging must not reach the journal at the default level: {seen:?}"
        );
    }

    /// At `debug` the damper stands down and both arrive — the operator
    /// asked for the per-query stream and must get it.
    #[test]
    fn at_debug_the_filter_keeps_both() {
        let seen = captured_under(build_log_filter("debug", None), || {
            tracing::info!(target: "hickory_server", "query received");
            tracing::warn!(target: "purge_warden", "refresh refused");
        });
        assert!(
            seen.iter().any(|(t, _)| t == "hickory_server"),
            "debug must not suppress the per-query stream: {seen:?}"
        );
        assert!(seen.iter().any(|(t, _)| t == "purge_warden"), "{seen:?}");
    }

    // ── Interval flags: only the canonical spelling parses. The
    // `--refresh-interval` / `--refresh-interval-hours` aliases and
    // their argv-scanning deprecation detector were deleted, so clap
    // now rejects the legacy forms outright. ───────────────────────

    #[test]
    fn clap_accepts_canonical_update_interval() {
        use clap::Parser;
        let cli = cli::Cli::try_parse_from(["warden", "start", "--update-interval", "7200"])
            .expect("canonical flag must parse");
        match cli.command {
            Some(cli::Commands::Start {
                update_interval, ..
            }) => assert_eq!(update_interval, Some(7200)),
            _ => panic!("unexpected command shape"),
        }
    }

    #[test]
    fn clap_rejects_deleted_refresh_interval_alias() {
        use clap::Parser;
        // `.map(|_| ())` discards the parsed `Cli` so the error path is
        // printable — clap's derived `Cli` does not implement `Debug`.
        let err = cli::Cli::try_parse_from(["warden", "start", "--refresh-interval", "7200"])
            .map(|_| ())
            .expect_err("deleted alias must not parse");
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn clap_accepts_canonical_update_interval_hours_on_blocklist_add() {
        use clap::Parser;
        let cli = cli::Cli::try_parse_from([
            "warden",
            "blocklist",
            "add",
            "priv-ads",
            "--url",
            "https://lists.purge.cc/privacy/ads.txt",
            "--update-interval-hours",
            "6",
        ])
        .expect("canonical flag must parse");
        match cli.command {
            Some(cli::Commands::Blocklist {
                action:
                    cli::BlocklistAction::Add {
                        update_interval_hours,
                        ..
                    },
            }) => assert_eq!(update_interval_hours, Some(6)),
            _ => panic!("unexpected command shape"),
        }
    }

    #[test]
    fn clap_rejects_deleted_refresh_interval_hours_alias_on_blocklist_add() {
        use clap::Parser;
        let err = cli::Cli::try_parse_from([
            "warden",
            "blocklist",
            "add",
            "priv-ads",
            "--url",
            "https://lists.purge.cc/privacy/ads.txt",
            "--refresh-interval-hours",
            "6",
        ])
        .map(|_| ())
        .expect_err("deleted alias must not parse");
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    /// The compatibility surfaces retired alongside the two interval
    /// aliases. Each must be an unrecognised token, not a
    /// silently-honoured legacy spelling.
    ///
    /// **`warden tags …` left this list in `plp-s5c` and did not lapse —
    /// it moved to [`tags_verb_parses_so_the_refusal_can_speak`].** Its
    /// contract inverted rather than ending: the tag verbs are retired,
    /// but retiring them into clap's `unrecognized subcommand` tells an
    /// operator the command is misspelt when it is actually gone. The
    /// surface is still pinned; what is pinned about it is the opposite.
    #[test]
    fn clap_rejects_deleted_compatibility_surfaces() {
        use clap::Parser;
        for argv in [
            ["warden", "logs", "--json"].as_slice(),
            ["warden", "config", "validate"].as_slice(),
        ] {
            assert!(
                cli::Cli::try_parse_from(argv).is_err(),
                "`{}` must not parse — the surface was deleted",
                argv.join(" ")
            );
        }
    }

    /// `warden tags <anything>` must reach the refusal, which means it
    /// must first *parse*.
    ///
    /// The four slugs that existed when tags were retired are here, and
    /// so are two that never did (`create`, `add`). That is the whole
    /// reason the arm is a catch-all: an operator reaching for a tag verb
    /// from muscle memory does not reliably reach for one that used to
    /// exist, and every miss must land on the signpost rather than on a
    /// parse error.
    ///
    /// **The singular `warden tag …` is deliberately NOT here, and the
    /// first draft of this test asserted it was.** That row was wrong and
    /// only the gate caught it: there has never been a top-level `warden
    /// tag` verb — the singular was always a sub-verb (`warden device tag
    /// add`) — so requiring it to parse would have invented a surface
    /// rather than quarantining one. It is left to clap, whose rejection
    /// lists the valid top-level commands with `tags` among them, and
    /// `tags`'s own summary line says it is retired. One hop, not a dead
    /// end.
    #[test]
    fn tags_verb_parses_so_the_refusal_can_speak() {
        use clap::Parser;
        for argv in [
            ["warden", "tags"].as_slice(),
            ["warden", "tags", "list"].as_slice(),
            ["warden", "tags", "check", "work"].as_slice(),
            ["warden", "tags", "rename", "old", "new"].as_slice(),
            ["warden", "tags", "remove", "work"].as_slice(),
            ["warden", "tags", "create", "work"].as_slice(),
            ["warden", "tags", "add", "work"].as_slice(),
            ["warden", "tags", "--json"].as_slice(),
        ] {
            let parsed = cli::Cli::try_parse_from(argv);
            assert!(
                parsed.is_ok(),
                "`{}` must parse so the refusal — not clap — is what the \
                 operator reads; got {:?}",
                argv.join(" "),
                parsed.err().map(|e| e.kind())
            );
        }
    }

    /// Bare `warden tags` must refuse, not print help.
    ///
    /// A `Vec<String>` positional is satisfied by zero arguments, so the
    /// no-argument case is the one that could silently fall through to
    /// clap's help renderer and exit 0. An operator who types the verb
    /// alone gets the same signpost as one who types a sub-verb.
    #[test]
    fn bare_tags_verb_is_the_refusal_not_help() {
        use clap::Parser;
        let cli = cli::Cli::try_parse_from(["warden", "tags"]).expect("must parse");
        assert!(
            matches!(cli.command, Some(cli::Commands::Tags { .. })),
            "bare `warden tags` must reach the Tags arm, not a help exit"
        );
    }

    /// The refusal names the replacement, and names it as a config key.
    ///
    /// Mutate check: point [`refuse_retired_tags_verb`] at any other
    /// string and this goes red. It is deliberately not a substring
    /// match on one word — "tags are retired" alone would pass while
    /// telling the operator nothing about where the capability went,
    /// which is the exact failure the quarantine exists to prevent.
    #[test]
    fn tags_refusal_names_the_replacement_key() {
        let err = refuse_retired_tags_verb().expect_err("the verb must refuse");
        let msg = err.to_string();
        assert!(
            msg.contains("profiles.<id>.lists"),
            "the refusal must name the config key that replaced tags; got: {msg}"
        );
        for direction in ["deny", "allow", "ignore"] {
            assert!(
                msg.contains(direction),
                "the refusal must show the `{direction}` direction; got: {msg}"
            );
        }
    }

    /// No argument can steer the refusal.
    ///
    /// The arm binds `..`, so this is a property the compiler already
    /// holds — the test pins the *reason* rather than re-proving it, and
    /// goes red if someone later gives the arm a binding and branches on
    /// it (a "helpful" per-sub-verb message is the likely regression,
    /// and it is exactly the message duplication this workstream is
    /// unwinding).
    #[test]
    fn the_tags_refusal_does_not_read_its_arguments() {
        let a = refuse_retired_tags_verb().unwrap_err().to_string();
        let b = refuse_retired_tags_verb().unwrap_err().to_string();
        assert_eq!(a, b);
        assert_eq!(
            a,
            cli::commands::entity_tags::TAGS_RETIRED,
            "the refusal must be TAGS_RETIRED verbatim — a second copy of \
             this message is the drift this workstream removed"
        );
    }
}
