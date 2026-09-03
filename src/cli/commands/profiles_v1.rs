//! §4.26 Phase 1: v1 profile CLI handlers.
//!
//! `warden profile <verb>` operates on the v1 schema `Profile`
//! ([`crate::config::schema::profile::Profile`]). Mutations are dispatched
//! to the daemon over IPC ([`IpcCommand::ProfileCreate`] /
//! [`IpcCommand::ProfileUpdate`] / [`IpcCommand::ProfileDelete`]); the
//! handler runs `atomic_write_and_validate` + reload + audit emit.
//!
//! Read-only verbs (`list`, `show`) read the merged config tree locally
//! via [`crate::config::loader::load_config`].

use std::path::Path;

use anyhow::{bail, Result};
use clap::Subcommand;
use time::OffsetDateTime;

use super::format_config_errors;
use crate::config::loader::load_config;
use crate::config::schema::blocklist::{effective_direction, Blocklist, ListPolicy};
use crate::config::schema::profile::{BlockResponseV1, Profile};
use crate::config::settings::EcsMode;
use crate::ipc::protocol::{
    AdminRulesPatch, EcsPatch, IpcCommand, IpcResponse, ListPolicyPatch, ProfileUpdatePatch,
};
use crate::ipc::socket_client;

// ── read-only ────────────────────────────────────────────────────

/// `warden profile list` — tabulate every v1 profile with summary stats.
pub fn run_list(config_path: &Path) -> Result<()> {
    let now = OffsetDateTime::now_utc();
    let loaded = load_config(config_path, now).map_err(format_config_errors)?;

    if loaded.config.profiles.is_empty() {
        println!("no profiles configured");
        return Ok(());
    }

    println!("configured v1 profiles:");
    for (id, prof) in &loaded.config.profiles {
        let display = if prof.display_name.is_empty() {
            "(no display name)"
        } else {
            prof.display_name.as_str()
        };
        let overrides = prof.lists.len();
        let admin = prof.admin_rules.len();
        let local = prof.local_records.len();
        let rewrites = prof.rewrite_rules.len();
        let ecs = match &prof.ecs {
            None => "inherit",
            Some(e) => match e.mode {
                Some(EcsMode::Off) => "off",
                Some(EcsMode::Coarse) => "coarse",
                Some(EcsMode::Subnet) => "subnet",
                None => "inherit",
            },
        };
        // `safe_search` sits beside `block_all` for the same reason: both
        // change what the profile does and neither is visible in the
        // per-profile counters below.
        let mut flags = String::new();
        if prof.block_all {
            flags.push_str(" [block_all]");
        }
        if prof.safe_search {
            flags.push_str(" [safe_search]");
        }
        println!("  {id}: {display}{flags}");
        println!(
            "    list_overrides={overrides} admin_rules={admin} \
             local_records={local} rewrites={rewrites} ecs={ecs}"
        );
    }
    Ok(())
}

/// `warden profile show <id>` — dump every v1 field for one profile.
pub fn run_show(config_path: &Path, id: &str) -> Result<()> {
    let now = OffsetDateTime::now_utc();
    let loaded = load_config(config_path, now).map_err(format_config_errors)?;

    let prof = loaded
        .config
        .profiles
        .get(id)
        .ok_or_else(|| anyhow::anyhow!("profile not found: {id}"))?;

    for line in render_profile_show(id, prof, &loaded.config.blocklists) {
        println!("{line}");
    }
    Ok(())
}

/// Every field of [`Profile`], one per line.
///
/// Pure so the exhaustive-destructure test can read the output back: the
/// doc above promises *every* field, and prose does not fail a build. A
/// field added to `Profile` breaks
/// `run_show_renders_every_field_of_profile` at compile time rather than
/// going quietly unprinted, which is how `safe_search` and `custom_lists`
/// stayed invisible.
fn render_profile_show(id: &str, prof: &Profile, blocklists: &[Blocklist]) -> Vec<String> {
    let mut out = vec![
        format!("profile: {id}"),
        format!("  display_name: {}", prof.display_name),
        format!("  block_all: {}", prof.block_all),
        format!(
            "  block_response: {}",
            prof.block_response
                .map(block_response_label)
                .unwrap_or("inherit")
        ),
        format!(
            "  blocked_ttl_secs: {}",
            prof.blocked_ttl_secs
                .map(|t| t.to_string())
                .unwrap_or_else(|| "inherit".into())
        ),
        // Opt-in, applied at resolve time, and with no verb to set it —
        // so this line is the only way an operator learns it is on.
        format!("  safe_search: {}", prof.safe_search),
    ];

    out.extend(list_policy_lines(prof, blocklists));

    out.push(format!("  custom_lists ({}):", prof.custom_lists.len()));
    for c in &prof.custom_lists {
        out.push(format!("    - {} (manage via `warden list`)", c.as_str()));
    }
    out.push(format!("  admin_rules ({}):", prof.admin_rules.len()));
    for r in &prof.admin_rules {
        out.push(format!(
            "    - {} (added by profile allow/deny; `warden rule undo` reverses the most recent)",
            r.as_str()
        ));
    }
    out.push(format!("  local_records ({}):", prof.local_records.len()));
    for r in &prof.local_records {
        out.push(format!(
            "    - {} → {} (manage via `warden local-dns`)",
            r.domain, r.value
        ));
    }
    out.push(format!("  rewrite_rules ({}):", prof.rewrite_rules.len()));
    for r in &prof.rewrite_rules {
        out.push(format!(
            "    - {} → {} (manage via `warden rewrite`)",
            r.from, r.to
        ));
    }
    match &prof.ecs {
        None => out.push("  ecs: inherit ([upstream.ecs] defaults)".to_string()),
        Some(e) => {
            out.push("  ecs:".to_string());
            out.push(format!(
                "    mode: {}",
                e.mode.map(ecs_mode_label).unwrap_or("inherit")
            ));
            out.push(format!(
                "    source_prefix_v4: {}",
                e.source_prefix_v4
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "inherit".into())
            ));
            out.push(format!(
                "    source_prefix_v6: {}",
                e.source_prefix_v6
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "inherit".into())
            ));
        }
    }
    out
}

// ── mutate (via IPC) ─────────────────────────────────────────────

/// `warden profile add <id> --display-name <s>`
pub async fn run_create(socket_path: &Path, id: &str, display_name: &str) -> Result<()> {
    let cmd = IpcCommand::ProfileCreate {
        id: id.to_string(),
        display_name: display_name.to_string(),
        token: None,
    };
    send_and_print(socket_path, cmd).await
}

// ── `warden profile set <field> <value>` ─────────────────────────

/// One settable field, the spelling an operator types, and what it does.
///
/// A table rather than a `match` arm per field, so the dispatcher, the
/// unknown-field error and the `set --help` text all read the SAME
/// source. Where those drifted apart elsewhere the result was a verb
/// accepting a field the help never named.
struct Field {
    /// Canonical spelling, as the operator types it.
    key: &'static str,
    /// Alternate spelling accepted for the same field: the raw TOML key
    /// `warden profile show` prints. An operator who reads `show` and
    /// types back what they read lands on the field they meant instead
    /// of an "unknown field" error.
    alias: Option<&'static str>,
    /// What the field controls, printed by the unknown-field error.
    help: &'static str,
}

const FIELDS: &[Field] = &[
    Field {
        key: "display_name",
        alias: None,
        help: "human-readable label",
    },
    Field {
        key: "block_response",
        alias: None,
        help: "shape of a blocked answer: zero, nxdomain, refused, soa_nodata, or clear",
    },
    Field {
        key: "blocked_ttl",
        alias: Some("blocked_ttl_secs"),
        help: "seconds to live on a blocked answer; 0 inherits the server default",
    },
    Field {
        key: "block_all",
        alias: None,
        help: "block every query unless an allow rule matches: true or false",
    },
    Field {
        key: "ecs.mode",
        alias: None,
        help: "EDNS Client Subnet policy: off, coarse, or subnet",
    },
    Field {
        key: "ecs.prefix_v4",
        alias: Some("ecs.source_prefix_v4"),
        help: "IPv4 prefix length sent upstream, 0-32",
    },
    Field {
        key: "ecs.prefix_v6",
        alias: Some("ecs.source_prefix_v6"),
        help: "IPv6 prefix length sent upstream, 0-128",
    },
    Field {
        key: "ecs",
        alias: None,
        help: "the literal none — drop the subtree and inherit the upstream defaults",
    },
];

/// Field names with their meanings, for the unknown-field error.
///
/// The three ecs settings are one subtree rather than one scalar, which
/// is why they are the only dotted keys: three values do not fit a
/// single `set <field> <value>` call.
fn field_list() -> String {
    FIELDS
        .iter()
        .map(|f| match f.alias {
            Some(a) => format!("{:<16} {} (also accepted: {a})", f.key, f.help),
            None => format!("{:<16} {}", f.key, f.help),
        })
        .collect::<Vec<_>>()
        .join("\n  ")
}

/// Map an operator-typed field name onto its canonical spelling.
fn resolve_field(field: &str) -> Result<&'static str> {
    FIELDS
        .iter()
        .find(|f| f.key == field || f.alias == Some(field))
        .map(|f| f.key)
        .ok_or_else(|| {
            anyhow::anyhow!("unknown field '{field}'\nvalid fields:\n  {}", field_list())
        })
}

/// `warden profile set <id> <field> <value>` — change one field.
pub async fn run_set(socket_path: &Path, id: &str, field: &str, value: &str) -> Result<()> {
    let patch = build_patch(field, value)?;
    let cmd = IpcCommand::ProfileUpdate {
        id: id.to_string(),
        patch,
        token: None,
    };
    send_and_print(socket_path, cmd).await
}

/// Build the single-field patch a `set` call sends.
///
/// Split from [`run_set`] so every parse rule is testable without a
/// daemon on the other end of the socket.
fn build_patch(field: &str, value: &str) -> Result<ProfileUpdatePatch> {
    let mut patch = ProfileUpdatePatch::default();
    match resolve_field(field)? {
        "display_name" => {
            if value.is_empty() {
                bail!("display_name cannot be empty");
            }
            patch.display_name = Some(value.to_string());
        }
        "block_response" => {
            patch.block_response = Some(parse_block_response(value)?);
        }
        "blocked_ttl" => {
            let secs = parse_u32(value, "blocked_ttl")?;
            // `0` is the clear spelling, not a zero-second TTL: the
            // inner `None` removes the key so the profile falls back to
            // `[server].default_blocked_ttl_secs`.
            patch.blocked_ttl_secs = Some(if secs == 0 { None } else { Some(secs) });
        }
        "block_all" => {
            patch.block_all = Some(parse_bool(value)?);
        }
        "ecs" => {
            if value != "none" {
                bail!(
                    "ecs takes only the literal \"none\", which drops the whole subtree. \
                     To change one setting, use ecs.mode, ecs.prefix_v4, or ecs.prefix_v6."
                );
            }
            patch.ecs = Some(EcsPatch {
                clear: true,
                ..Default::default()
            });
        }
        // The three dotted keys each send an `EcsPatch` carrying that
        // one field. The daemon merges a patch into the existing
        // `[profiles.X.ecs]` table field by field, so the two settings
        // this call leaves absent keep whatever they had — setting one
        // never clobbers its siblings.
        "ecs.mode" => {
            reject_per_field_clear("ecs.mode", value)?;
            patch.ecs = Some(EcsPatch {
                mode: Some(parse_ecs_mode(value)?),
                ..Default::default()
            });
        }
        "ecs.prefix_v4" => {
            reject_per_field_clear("ecs.prefix_v4", value)?;
            patch.ecs = Some(EcsPatch {
                source_prefix_v4: Some(parse_prefix(value, 32, "ecs.prefix_v4")?),
                ..Default::default()
            });
        }
        "ecs.prefix_v6" => {
            reject_per_field_clear("ecs.prefix_v6", value)?;
            patch.ecs = Some(EcsPatch {
                source_prefix_v6: Some(parse_prefix(value, 128, "ecs.prefix_v6")?),
                ..Default::default()
            });
        }
        // `resolve_field` only ever yields a key from `FIELDS`, so the
        // arms above are exhaustive by construction. The inline test
        // `every_field_has_a_dispatch_arm` is what keeps it that way
        // when a row is added.
        other => unreachable!("FIELDS carries `{other}` with no dispatch arm"),
    }
    Ok(patch)
}

/// Refuse `none` on a dotted ecs key.
///
/// It would mean "clear just this one setting back to inherit", and the
/// wire patch cannot say that: its ecs sub-fields are single-valued, so
/// absent means "leave alone", never "clear". Point at the spelling that
/// does work rather than accepting the word and writing nothing. The
/// profile editor in the dashboard refuses the same input for the same
/// reason.
fn reject_per_field_clear(key: &str, value: &str) -> Result<()> {
    if value == "none" || value == "inherit" {
        bail!(
            "cannot clear {key} on its own — the ecs settings clear as a group. \
             Use `warden profile set <id> ecs none` to drop the whole subtree, or \
             give {key} an explicit value."
        );
    }
    Ok(())
}

fn parse_block_response(variant: &str) -> Result<Option<BlockResponseV1>> {
    match variant {
        "clear" => Ok(None),
        "zero" => Ok(Some(BlockResponseV1::Zero)),
        "nxdomain" => Ok(Some(BlockResponseV1::Nxdomain)),
        "refused" => Ok(Some(BlockResponseV1::Refused)),
        "soa_nodata" => Ok(Some(BlockResponseV1::SoaNodata)),
        other => bail!(
            "unknown block_response variant: \"{other}\" \
             (expected zero, nxdomain, refused, soa_nodata, or clear)"
        ),
    }
}

fn parse_ecs_mode(mode: &str) -> Result<EcsMode> {
    match mode {
        "off" => Ok(EcsMode::Off),
        "coarse" => Ok(EcsMode::Coarse),
        "subnet" => Ok(EcsMode::Subnet),
        other => bail!("unknown ecs mode: \"{other}\" (expected off, coarse, or subnet)"),
    }
}

fn parse_bool(value: &str) -> Result<bool> {
    match value {
        "true" | "1" | "on" | "yes" => Ok(true),
        "false" | "0" | "off" | "no" => Ok(false),
        other => bail!("expected true/false (or on/off/yes/no/1/0), got: {other}"),
    }
}

fn parse_u32(value: &str, key: &str) -> Result<u32> {
    value
        .parse()
        .map_err(|_| anyhow::anyhow!("{key} must be a whole number of seconds, got: {value}"))
}

/// Parse a prefix length and bound it here rather than letting the
/// round-trip carry an impossible value to the daemon: the config
/// validator refuses anything past these limits anyway, and refusing at
/// the keyboard names the field the operator typed.
fn parse_prefix(value: &str, max: u8, key: &str) -> Result<u8> {
    let n: u8 = value
        .parse()
        .map_err(|_| anyhow::anyhow!("{key} must be a whole number in 0..={max}, got: {value}"))?;
    if n > max {
        bail!("{key} must be in 0..={max}, got: {n}");
    }
    Ok(n)
}

// ── `warden profile admin-rule add|remove` ───────────────────────

/// Sub-commands for `warden profile admin-rule …`.
///
/// Admin rules are a list of references, not a scalar field, so they
/// keep add/remove sub-verbs instead of folding into `set` — the same
/// shape `warden profile tag add|remove` uses.
///
/// Declared beside its handlers rather than with the other action enums
/// in `cli/mod.rs`; clap derives `Subcommand` across modules either way.
#[derive(Subcommand)]
pub enum ProfileAdminRuleAction {
    /// Reference an existing `[[admin_rules]]` row from this profile,
    /// so the profile starts enforcing it.
    Add {
        /// Profile id (the map key in `[profiles.<id>]`).
        id: String,
        /// Admin rule id, as `warden profile show` prints it.
        rule_id: String,
    },
    /// Drop an admin rule reference from this profile. The
    /// `[[admin_rules]]` row itself stays, and no verb deletes a row by
    /// id: `warden rule undo` pops the most recently added row and
    /// cascades the reference drop across every entity that named it.
    Remove {
        /// Profile id (the map key in `[profiles.<id>]`).
        id: String,
        /// Admin rule id, as `warden profile show` prints it.
        rule_id: String,
    },
}

/// `warden profile admin-rule add <id> <rule-id>`
pub async fn run_admin_rule_add(socket_path: &Path, id: &str, rule_id: &str) -> Result<()> {
    let cmd = IpcCommand::ProfileUpdate {
        id: id.to_string(),
        patch: ProfileUpdatePatch {
            admin_rules: Some(AdminRulesPatch {
                add: vec![rule_id.to_string()],
                remove: vec![],
            }),
            ..Default::default()
        },
        token: None,
    };
    send_and_print(socket_path, cmd).await
}

/// `warden profile admin-rule remove <id> <rule-id>`
pub async fn run_admin_rule_remove(socket_path: &Path, id: &str, rule_id: &str) -> Result<()> {
    let cmd = IpcCommand::ProfileUpdate {
        id: id.to_string(),
        patch: ProfileUpdatePatch {
            admin_rules: Some(AdminRulesPatch {
                add: vec![],
                remove: vec![rule_id.to_string()],
            }),
            ..Default::default()
        },
        token: None,
    };
    send_and_print(socket_path, cmd).await
}

/// `warden profile remove <id>` — refuses if any device, subnet, or
/// schedule still references the profile.
pub async fn run_remove(socket_path: &Path, id: &str) -> Result<()> {
    let cmd = IpcCommand::ProfileDelete {
        id: id.to_string(),
        token: None,
    };
    send_and_print(socket_path, cmd).await
}

// ── list policy: the direction a profile applies to each list ─────

/// One list, as one profile sees it: the direction in force, and whether
/// this profile *declared* it or inherited the list's own `base`.
///
/// **Provenance is `lists.contains_key`, never a comparison against
/// `base`.** A list whose `base` is `deny` and which this profile
/// overrides to `deny` has the same *effect* as one it never mentions and
/// a different *intention*: the override survives a later change to
/// `base`, the inheritance does not. A renderer that derived provenance by
/// comparing the two would print "inherited" for that row, hiding exactly
/// what the operator went to the trouble of declaring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListPolicyRow {
    /// Blocklist id, as `warden blocklist list` prints it.
    pub list_id: String,
    /// The direction in force for this `(profile, list)` pair.
    pub policy: ListPolicy,
    /// `true` when this profile carries an explicit entry for the list.
    pub overridden: bool,
    /// Mirrors `Blocklist::enabled`. Carried rather than folded into
    /// `policy` because a disabled list is not the same thing as one this
    /// profile ignores — see [`list_policy_rows`].
    pub enabled: bool,
}

/// Every configured blocklist, in config order, as `profile` sees it.
///
/// **Why `enabled` is a separate field and not folded into `policy`.**
/// `effective_direction` deliberately says nothing about
/// [`Blocklist::enabled`]: a disabled list holds no source bit and
/// produces no verdict, but that is the operator having switched it off,
/// not this profile ignoring it. Collapsing the two would answer "what
/// does this profile apply?" with a direction the list cannot currently
/// deliver, and would make re-enabling the list look like a policy change
/// on every profile. The caller renders the two facts side by side.
#[must_use]
pub fn list_policy_rows(profile: &Profile, blocklists: &[Blocklist]) -> Vec<ListPolicyRow> {
    blocklists
        .iter()
        .map(|list| ListPolicyRow {
            list_id: list.id.as_str().to_string(),
            policy: effective_direction(profile, list),
            overridden: profile.lists.contains_key(&list.id),
            enabled: list.enabled,
        })
        .collect()
}

/// Render one row, without the leading indent.
///
/// One renderer, two callers (`warden profile show` and `warden profile
/// list-policy show`). Two renderers for one question is how the same
/// question starts having two answers.
#[must_use]
pub fn format_list_policy_row(row: &ListPolicyRow) -> String {
    let provenance = if row.overridden {
        LIST_POLICY_OVERRIDDEN
    } else {
        LIST_POLICY_INHERITED
    };
    let mut line = format!("{}: {} ({provenance})", row.list_id, row.policy.wire_str());
    if !row.enabled {
        line.push_str(LIST_POLICY_DISABLED_NOTE);
    }
    line
}

/// Said of a direction this profile declared for itself.
pub const LIST_POLICY_OVERRIDDEN: &str = "set on this profile";
/// Said of a direction taken from the list's own `base`.
pub const LIST_POLICY_INHERITED: &str = "inherited from the list";
/// Appended when the list is switched off.
///
/// A disabled list contributes nothing whatever its direction says, and an
/// operator reading `deny` on a list that is answering no queries has been
/// told the opposite of what is happening.
pub const LIST_POLICY_DISABLED_NOTE: &str = " — list disabled, applies nothing";
/// What `warden profile show` says beside a tag it still finds on disk.
///
/// **Names a verb that exists.** The line used to read `manage via
/// `warden profile tag add|remove``, which had become an instruction to
/// run a command that refuses: a refusal an operator cannot satisfy in
/// its own terms. The tags themselves are still printed — an operator
/// with tags in their file should see them — but what they are told about
/// them is that they decide nothing, and where the decision now lives.
pub const PROFILE_TAGS_INERT: &str =
    "inert — decides nothing; set the direction with `warden profile list-policy set`";

/// Printed instead of the rows when no `[[blocklists]]` are configured.
///
/// The header above it already says `lists (0 configured)`, so repeating
/// that is a wasted line. What the operator cannot see from the count is
/// what to do about it, so this says that instead.
pub const LIST_POLICY_NO_LISTS: &str =
    "nothing for this profile to apply — subscribe to one with `warden blocklist add`";

/// The `lists (N):` block shared by both read verbs, indent included.
fn print_list_policy_block(profile: &Profile, blocklists: &[Blocklist]) {
    for line in list_policy_lines(profile, blocklists) {
        println!("{line}");
    }
}

/// The `lists (N configured):` block, one string per line.
fn list_policy_lines(profile: &Profile, blocklists: &[Blocklist]) -> Vec<String> {
    let rows = list_policy_rows(profile, blocklists);
    let mut out = vec![format!("  lists ({} configured):", rows.len())];
    if rows.is_empty() {
        out.push(format!("    {LIST_POLICY_NO_LISTS}"));
        return out;
    }
    for row in &rows {
        out.push(format!("    - {}", format_list_policy_row(row)));
    }
    out
}

/// Sub-commands for `warden profile list-policy …`.
///
/// The third list-shaped verb beside `admin-rule`, and the operator's way
/// into the three-state direction model: a profile either declares what it
/// does with a list, or inherits what the list itself declares.
///
/// Declared beside its handlers rather than in `cli/mod.rs`, matching
/// [`ProfileAdminRuleAction`].
#[derive(Subcommand)]
pub enum ProfileListPolicyAction {
    /// Declare what this profile does with one blocklist, overriding its `base`.
    ///
    /// deny    treat it as a block list here
    /// allow   treat it as an allow list here — its domains stop being
    ///         blocked for devices on this profile
    /// ignore  this profile does not apply the list at all
    ///
    /// `ignore` is not the same as `clear`: it is a standing declaration
    /// that survives a later change to the list's `base`, where a cleared
    /// pair follows `base` wherever it goes.
    #[command(verbatim_doc_comment)]
    Set {
        /// Profile id (the map key in `[profiles.<id>]`).
        id: String,
        /// Blocklist id, as `warden blocklist list` prints it.
        list_id: String,
        /// One of deny, allow, ignore.
        policy: String,
    },
    /// Drop this profile's declaration for one list — NOT the same as `set … ignore`.
    ///
    /// The pair goes back to following the list's own `base`, wherever a
    /// later edit takes `base`. `set … ignore` instead declares that this
    /// profile applies nothing from the list, and keeps saying so after
    /// `base` changes.
    Clear {
        /// Profile id (the map key in `[profiles.<id>]`).
        id: String,
        /// Blocklist id, as `warden blocklist list` prints it.
        list_id: String,
    },
    /// Print the direction this profile applies to every configured
    /// blocklist, and whether it was set here or inherited.
    Show {
        /// Profile id (the map key in `[profiles.<id>]`).
        id: String,
    },
}

/// Parse the operator's direction token into a [`ListPolicy`].
///
/// Accepted tokens come from [`ListPolicy::wire_str`] rather than a local
/// table, so the CLI cannot start accepting a spelling the config file
/// does not, or refusing one it does. `plp_s4a_parse_list_policy_covers_
/// every_variant` walks the enum with an exhaustive `match`, so a fourth
/// variant fails that build instead of quietly having no CLI spelling.
pub fn parse_list_policy(raw: &str) -> Result<ListPolicy> {
    for policy in LIST_POLICY_TOKENS {
        if raw == policy.wire_str() {
            return Ok(policy);
        }
    }
    let accepted = LIST_POLICY_TOKENS
        .iter()
        .map(|p| p.wire_str())
        .collect::<Vec<_>>()
        .join(", ");
    bail!("unknown direction \"{raw}\" — expected one of: {accepted}")
}

/// Every direction an operator may type, in the order the help lists them.
pub const LIST_POLICY_TOKENS: [ListPolicy; 3] =
    [ListPolicy::Deny, ListPolicy::Allow, ListPolicy::Ignore];

/// Build the command `warden profile list-policy set` sends.
///
/// Pure, and the whole command rather than the patch: the run function
/// below is one expression over it, so there is no second construction
/// site to drift from what the tests measure.
pub fn list_policy_set_command(id: &str, list_id: &str, policy: ListPolicy) -> IpcCommand {
    IpcCommand::ProfileUpdate {
        id: id.to_string(),
        patch: ProfileUpdatePatch {
            lists: Some(ListPolicyPatch {
                set: [(list_id.to_string(), policy)].into_iter().collect(),
                clear: vec![],
            }),
            ..Default::default()
        },
        token: None,
    }
}

/// Build the command `warden profile list-policy clear` sends.
///
/// **`clear` is not `set … ignore`**, and the two build different patches
/// on purpose: this one removes the key so the pair follows the list's
/// `base` again, where `set … ignore` writes a key that keeps saying "not
/// here" after `base` changes.
pub fn list_policy_clear_command(id: &str, list_id: &str) -> IpcCommand {
    IpcCommand::ProfileUpdate {
        id: id.to_string(),
        patch: ProfileUpdatePatch {
            lists: Some(ListPolicyPatch {
                set: Default::default(),
                clear: vec![list_id.to_string()],
            }),
            ..Default::default()
        },
        token: None,
    }
}

/// `warden profile list-policy set <id> <list-id> <deny|allow|ignore>`
///
/// **The consent gate is not re-checked here.** An `allow` direction on a
/// remote unsigned list whose `[[blocklists]]` row does not carry
/// `accept_unsigned_allow = true` is refused by the daemon, which is the
/// one place every override write passes through; this verb surfaces that
/// refusal verbatim. A second copy of the predicate here would be a second
/// place for it to be wrong.
pub async fn run_list_policy_set(
    socket_path: &Path,
    id: &str,
    list_id: &str,
    policy: &str,
) -> Result<()> {
    let policy = parse_list_policy(policy)?;
    send_and_print(socket_path, list_policy_set_command(id, list_id, policy)).await
}

/// `warden profile list-policy clear <id> <list-id>`
pub async fn run_list_policy_clear(socket_path: &Path, id: &str, list_id: &str) -> Result<()> {
    send_and_print(socket_path, list_policy_clear_command(id, list_id)).await
}

/// `warden profile list-policy show <id>` — what this profile actually
/// applies, per list, and where each direction came from.
pub fn run_list_policy_show(config_path: &Path, id: &str) -> Result<()> {
    let now = OffsetDateTime::now_utc();
    let loaded = load_config(config_path, now).map_err(format_config_errors)?;

    let prof = loaded
        .config
        .profiles
        .get(id)
        .ok_or_else(|| anyhow::anyhow!("profile not found: {id}"))?;

    println!("profile: {id}");
    print_list_policy_block(prof, &loaded.config.blocklists);
    Ok(())
}

// ── helpers ──────────────────────────────────────────────────────

fn block_response_label(b: BlockResponseV1) -> &'static str {
    match b {
        BlockResponseV1::Zero => "zero",
        BlockResponseV1::Nxdomain => "nxdomain",
        BlockResponseV1::Refused => "refused",
        BlockResponseV1::SoaNodata => "soa_nodata",
    }
}

fn ecs_mode_label(m: EcsMode) -> &'static str {
    match m {
        EcsMode::Off => "off",
        EcsMode::Coarse => "coarse",
        EcsMode::Subnet => "subnet",
    }
}

async fn send_and_print(socket_path: &Path, cmd: IpcCommand) -> Result<()> {
    match socket_client::send_command(socket_path, &cmd).await {
        Ok(IpcResponse::Ok { message }) => {
            println!("{message}");
            Ok(())
        }
        Ok(IpcResponse::Error { message }) => {
            anyhow::bail!("daemon refused: {message}");
        }
        Ok(_) => anyhow::bail!("unexpected response from daemon"),
        Err(e) => {
            anyhow::bail!(
                "could not reach the daemon over IPC: {e}\n\n\
                 `warden profile` goes through the authenticated IPC socket. Check:\n  \
                 • the daemon is running (`warden status`)\n  \
                 • the socket path matches your config\n  \
                 • you have a valid token (`warden token generate` if not)"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A value each field accepts, so a test can walk `FIELDS` without
    /// knowing per-field grammar. Adding a row to `FIELDS` without one
    /// here fails `every_field_has_a_dispatch_arm` rather than waiting
    /// for an operator to find the gap.
    fn sample_value(key: &str) -> &'static str {
        match key {
            "display_name" => "Kids",
            "block_response" => "nxdomain",
            "blocked_ttl" => "30",
            "block_all" => "true",
            "ecs.mode" => "subnet",
            "ecs.prefix_v4" => "24",
            "ecs.prefix_v6" => "56",
            "ecs" => "none",
            other => panic!("FIELDS carries `{other}` with no sample value in this test"),
        }
    }

    /// Guards the `unreachable!` in [`build_patch`]: every declared
    /// field must dispatch, and must actually touch the patch.
    #[test]
    fn every_field_has_a_dispatch_arm() {
        for f in FIELDS {
            let patch = build_patch(f.key, sample_value(f.key))
                .unwrap_or_else(|e| panic!("field `{}` failed to dispatch: {e}", f.key));
            assert_ne!(
                patch,
                ProfileUpdatePatch::default(),
                "field `{}` dispatched but left the patch empty",
                f.key
            );
        }
    }

    /// `set --help` is the only place an operator can discover the legal
    /// field names, and the doc comment carrying them is a static string
    /// clap cannot interpolate from `FIELDS`. Assert they agree.
    #[test]
    fn set_help_names_every_field() {
        use clap::CommandFactory;
        let cli = crate::cli::Cli::command();
        let profile = cli
            .get_subcommands()
            .find(|c| c.get_name() == "profile")
            .expect("`warden profile` must exist");
        let mut set = profile
            .get_subcommands()
            .find(|c| c.get_name() == "set")
            .expect("`warden profile set` must exist")
            .clone();
        let help = set.render_long_help().to_string();
        for f in FIELDS {
            assert!(
                help.contains(f.key),
                "`profile set --help` never names the field `{}`:\n{help}",
                f.key
            );
        }
    }

    #[test]
    fn unknown_field_error_lists_every_field() {
        let err = build_patch("nonsense", "x").unwrap_err().to_string();
        assert!(err.contains("nonsense"), "error must quote the typo: {err}");
        for f in FIELDS {
            assert!(
                err.contains(f.key),
                "unknown-field error omits `{}`:\n{err}",
                f.key
            );
        }
    }

    #[test]
    fn toml_spellings_resolve_to_their_canonical_field() {
        for (typed, canonical) in [
            ("blocked_ttl_secs", "blocked_ttl"),
            ("ecs.source_prefix_v4", "ecs.prefix_v4"),
            ("ecs.source_prefix_v6", "ecs.prefix_v6"),
        ] {
            assert_eq!(resolve_field(typed).unwrap(), canonical);
        }
    }

    #[test]
    fn blocked_ttl_zero_clears_and_nonzero_sets() {
        assert_eq!(
            build_patch("blocked_ttl", "0").unwrap().blocked_ttl_secs,
            Some(None),
            "0 must clear the key so the profile inherits the server default"
        );
        assert_eq!(
            build_patch("blocked_ttl", "90").unwrap().blocked_ttl_secs,
            Some(Some(90))
        );
        assert!(build_patch("blocked_ttl", "soon").is_err());
    }

    #[test]
    fn block_response_clear_is_distinct_from_unset() {
        assert_eq!(
            build_patch("block_response", "clear")
                .unwrap()
                .block_response,
            Some(None)
        );
        assert_eq!(
            build_patch("block_response", "refused")
                .unwrap()
                .block_response,
            Some(Some(BlockResponseV1::Refused))
        );
        let err = build_patch("block_response", "nxdomian")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("soa_nodata"),
            "error must list variants: {err}"
        );
    }

    #[test]
    fn block_all_accepts_the_usual_spellings() {
        for yes in ["true", "1", "on", "yes"] {
            assert_eq!(build_patch("block_all", yes).unwrap().block_all, Some(true));
        }
        for no in ["false", "0", "off", "no"] {
            assert_eq!(build_patch("block_all", no).unwrap().block_all, Some(false));
        }
        assert!(build_patch("block_all", "maybe").is_err());
    }

    /// The no-clobber invariant: a dotted key must carry ONLY its own
    /// field. The daemon merges an `EcsPatch` into the existing table
    /// field by field, so a `None` here means "leave that setting alone"
    /// — but only because we never fill it in speculatively.
    #[test]
    fn a_dotted_ecs_key_carries_only_its_own_field() {
        let mode = build_patch("ecs.mode", "coarse").unwrap().ecs.unwrap();
        assert_eq!(mode.mode, Some(EcsMode::Coarse));
        assert_eq!(mode.source_prefix_v4, None);
        assert_eq!(mode.source_prefix_v6, None);
        assert!(!mode.clear);

        let v4 = build_patch("ecs.prefix_v4", "24").unwrap().ecs.unwrap();
        assert_eq!(v4.source_prefix_v4, Some(24));
        assert_eq!(v4.mode, None);
        assert_eq!(v4.source_prefix_v6, None);
        assert!(!v4.clear);

        let v6 = build_patch("ecs.prefix_v6", "56").unwrap().ecs.unwrap();
        assert_eq!(v6.source_prefix_v6, Some(56));
        assert_eq!(v6.mode, None);
        assert_eq!(v6.source_prefix_v4, None);
        assert!(!v6.clear);
    }

    #[test]
    fn ecs_none_clears_the_whole_subtree() {
        let ecs = build_patch("ecs", "none").unwrap().ecs.unwrap();
        assert!(ecs.clear);
        let err = build_patch("ecs", "subnet").unwrap_err().to_string();
        assert!(
            err.contains("ecs.mode"),
            "rejecting a mode typed at `ecs` must point at the dotted keys: {err}"
        );
    }

    /// Per-field clear has no wire representation, so it must be refused
    /// out loud — accepting `none` and sending an empty patch would look
    /// like success and change nothing.
    #[test]
    fn clearing_one_ecs_field_is_refused_and_points_at_the_group_spelling() {
        for key in ["ecs.mode", "ecs.prefix_v4", "ecs.prefix_v6"] {
            for value in ["none", "inherit"] {
                let err = build_patch(key, value).unwrap_err().to_string();
                assert!(
                    err.contains("ecs none"),
                    "`{key} {value}` must name the working spelling: {err}"
                );
            }
        }
    }

    #[test]
    fn prefix_lengths_are_bounded_at_the_keyboard() {
        assert!(build_patch("ecs.prefix_v4", "32").is_ok());
        assert!(build_patch("ecs.prefix_v4", "33").is_err());
        assert!(build_patch("ecs.prefix_v6", "128").is_ok());
        assert!(build_patch("ecs.prefix_v6", "129").is_err());
        // Past u8 entirely — must read as out of range, not as a parse
        // failure the operator cannot act on.
        let err = build_patch("ecs.prefix_v6", "300").unwrap_err().to_string();
        assert!(err.contains("0..=128"), "{err}");
    }

    #[test]
    fn display_name_cannot_be_emptied() {
        assert!(build_patch("display_name", "").is_err());
        assert_eq!(
            build_patch("display_name", "Kids").unwrap().display_name,
            Some("Kids".into())
        );
    }
    // ── every read verb reports a broken config in one voice ────────

    /// The three read verbs collapse the loader's error list through the
    /// shared CLI seat, so a broken config reads identically whichever
    /// verb hit it. Their own collapser emitted a bare newline-joined
    /// list — no error count, no bullets — which is a different product
    /// speaking to the operator depending on which command they ran.
    #[test]
    fn read_verbs_report_a_broken_config_in_the_shared_wording() {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        std::fs::write(&master, "server = { listen = \"not-an-address\" }\n").unwrap();

        for (verb, err) in [
            ("profile list", run_list(&master).unwrap_err()),
            ("profile show", run_show(&master, "default").unwrap_err()),
            (
                "profile list-policy show",
                run_list_policy_show(&master, "default").unwrap_err(),
            ),
        ] {
            let msg = err.to_string();
            assert!(
                msg.starts_with("cannot load config ("),
                "`warden {verb}` must use the shared header: {msg}"
            );
            assert!(
                msg.contains("\n  - "),
                "`warden {verb}` must bullet each loader error: {msg}"
            );
        }
    }

    // ── `profile show` dumps EVERY field, and stays that way ─────────

    /// The doc on `run_show` promises "every v1 field", and prose does
    /// not fail a build: `safe_search` and `custom_lists` were both on
    /// `Profile` and neither was printed. `safe_search` is the
    /// consequential one — opt-in, applied at resolve time, and with no
    /// CLI verb to set it, so an operator who enabled it by hand-editing
    /// TOML had no command that would tell them it was on.
    ///
    /// The trip-wire is the destructure below: it names all eleven
    /// fields with NO `..` rest pattern, so adding a field to `Profile`
    /// stops this compiling. `let Profile { .. } = …` would keep
    /// compiling and defend nothing.
    #[test]
    fn run_show_renders_every_field_of_profile() {
        use crate::config::schema::profile::ProfileEcsConfig;
        use crate::config::settings::{LocalDnsRecord, LocalDnsRecordType};
        use std::collections::BTreeMap;

        let prof = Profile {
            display_name: "Kids".into(),
            block_response: Some(BlockResponseV1::Nxdomain),
            blocked_ttl_secs: Some(30),
            admin_rules: vec![crate::config::schema::Id::new("allow-school").unwrap()],
            block_all: true,
            local_records: vec![LocalDnsRecord {
                domain: "nas.home".into(),
                record_type: LocalDnsRecordType::A,
                value: "10.0.0.9".into(),
                match_subdomains: false,
                ttl_secs: None,
            }],
            ecs: Some(ProfileEcsConfig {
                mode: Some(EcsMode::Subnet),
                source_prefix_v4: Some(24),
                source_prefix_v6: Some(56),
            }),
            rewrite_rules: vec![crate::config::settings::RewriteRule {
                from: "old.example".into(),
                to: "new.example".into(),
                match_subdomains: false,
            }],
            safe_search: true,
            custom_lists: vec![crate::config::schema::Id::new("family-allow").unwrap()],
            lists: BTreeMap::from([(
                crate::config::schema::Id::new("social").unwrap(),
                ListPolicy::Ignore,
            )]),
        };

        let Profile {
            display_name,
            block_response,
            blocked_ttl_secs,
            admin_rules,
            block_all,
            local_records,
            ecs,
            rewrite_rules,
            safe_search,
            custom_lists,
            lists,
        } = &prof;

        // The `lists` block renders one row per CONFIGURED blocklist, not
        // per profile override — an override naming a list that does not
        // exist is refused by the validator, so it cannot reach a
        // renderer. The list has to be present for the row to exist.
        let configured: Vec<Blocklist> = vec![toml::from_str(
            "id = \"social\"\ndisplay_name = \"Social\"\nurl = \"https://example.com/s.txt\"\n",
        )
        .unwrap()];

        let out = render_profile_show("kids", &prof, &configured).join("\n");

        assert!(out.contains(display_name.as_str()), "display_name: {out}");
        assert!(
            out.contains(block_response.map(block_response_label).unwrap()),
            "block_response: {out}"
        );
        assert!(
            out.contains(&blocked_ttl_secs.unwrap().to_string()),
            "blocked_ttl_secs: {out}"
        );
        assert!(out.contains(admin_rules[0].as_str()), "admin_rules: {out}");
        assert!(
            out.contains(&format!("block_all: {block_all}")),
            "block_all: {out}"
        );
        assert!(
            out.contains(&local_records[0].domain),
            "local_records: {out}"
        );
        assert!(
            out.contains(ecs_mode_label(ecs.as_ref().unwrap().mode.unwrap())),
            "ecs: {out}"
        );
        assert!(out.contains(&rewrite_rules[0].from), "rewrite_rules: {out}");
        assert!(
            out.contains(&format!("safe_search: {safe_search}")),
            "safe_search: {out}"
        );
        assert!(
            out.contains(custom_lists[0].as_str()),
            "custom_lists: {out}"
        );
        // Every declared override must be visible, with its policy: this
        // is the one field whose rendering can silently drop an entry.
        for (list_id, policy) in lists {
            assert!(
                out.contains(list_id.as_str()),
                "lists override {list_id} missing: {out}"
            );
            assert!(
                out.contains(&format!("{policy:?}").to_lowercase()),
                "lists policy {policy:?} missing: {out}"
            );
        }
    }

    /// Negative control on the two that were missing: a profile with
    /// `safe_search` off and no custom lists must not read as one that
    /// has them. Without this, hardcoded `safe_search: true` output
    /// would satisfy the test above.
    #[test]
    fn run_show_reports_safe_search_off_as_off() {
        let prof = Profile::default();
        let out = render_profile_show("plain", &prof, &[]).join("\n");

        assert!(out.contains("safe_search: false"), "{out}");
        assert!(out.contains("custom_lists (0)"), "{out}");
    }
}
