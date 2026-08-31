//! Sprint §4.26 Phase 1 — Profile Editor v1 frozen strings.
//!
//! Pins byte-for-byte the operator-facing audit action strings + CLI
//! parse error templates coined in §4.26 §1/2. Audit strings flow into
//! `tracing::info!(target = "audit", action = "...", ...)` from the
//! three new IPC handlers (`handle_profile_{create,update,delete}` in
//! `src/ipc/socket_server.rs`). CLI parse errors flow from
//! `src/cli/commands/profiles_v1.rs::run_{block_response,ecs}`.
//!
//! When one of these strings MUST change for legitimate reasons (UX
//! re-wording, typo fix), update the literal here AND the corresponding
//! row in `CONFIG_GUIDE.md` + `CONFIG_GUIDE.public.md` in the same
//! commit. Byte-for-byte equality has no escape hatch — that is the
//! entire point of this trip-wire (pattern `frozen_strings_s48_ecs.rs`).

const AUDIT_ACTION_CREATE: &str = "profile.create.v1";
const AUDIT_ACTION_UPDATE: &str = "profile.update.v1";
const AUDIT_ACTION_DELETE: &str = "profile.delete.v1";

const BLOCK_RESPONSE_PARSE_ERR_PREFIX: &str = "unknown block_response variant: ";
const BLOCK_RESPONSE_PARSE_ERR_SUFFIX: &str =
    " (expected zero, nxdomain, refused, soa_nodata, or clear)";

const ECS_MODE_PARSE_ERR_PREFIX: &str = "unknown ecs mode: ";
const ECS_MODE_PARSE_ERR_SUFFIX: &str = " (expected off, coarse, or subnet)";

const IPC_DAEMON_REFUSED_PREFIX: &str = "daemon refused: ";
const IPC_UNEXPECTED_RESPONSE: &str = "unexpected response from daemon";

// ── audit emit strings (socket_server.rs) ────────────────────────

#[test]
fn s49_audit_action_create_is_pinned() {
    let src = include_str!("../src/ipc/socket_server.rs");
    let needle = format!(r#"action = "{AUDIT_ACTION_CREATE}""#);
    assert!(
        src.contains(&needle),
        "ProfileCreate audit emit must spell action exactly as `{AUDIT_ACTION_CREATE}` \
         (looked for literal `{needle}` in socket_server.rs)"
    );
}

#[test]
fn s49_audit_action_update_is_pinned() {
    let src = include_str!("../src/ipc/socket_server.rs");
    let needle = format!(r#"action = "{AUDIT_ACTION_UPDATE}""#);
    assert!(
        src.contains(&needle),
        "ProfileUpdate audit emit must spell action exactly as `{AUDIT_ACTION_UPDATE}` \
         (looked for literal `{needle}` in socket_server.rs)"
    );
}

#[test]
fn s49_audit_action_delete_is_pinned() {
    let src = include_str!("../src/ipc/socket_server.rs");
    let needle = format!(r#"action = "{AUDIT_ACTION_DELETE}""#);
    assert!(
        src.contains(&needle),
        "ProfileDelete audit emit must spell action exactly as `{AUDIT_ACTION_DELETE}` \
         (looked for literal `{needle}` in socket_server.rs)"
    );
}

#[test]
fn s49_audit_actions_follow_profile_v1_shape() {
    for action in [
        AUDIT_ACTION_CREATE,
        AUDIT_ACTION_UPDATE,
        AUDIT_ACTION_DELETE,
    ] {
        assert!(
            action.starts_with("profile."),
            "audit action `{action}` must use the `profile.<verb>.v1` shape"
        );
        assert!(
            action.ends_with(".v1"),
            "audit action `{action}` must carry the `.v1` schema-version suffix"
        );
        let parts: Vec<&str> = action.split('.').collect();
        assert_eq!(
            parts.len(),
            3,
            "audit action `{action}` must have exactly 3 dot-separated parts: profile.<verb>.v1"
        );
    }
}

// ── CLI parse error templates (profiles_v1.rs) ───────────────────

#[test]
fn s49_block_response_parse_error_template_pinned() {
    let src = include_str!("../src/cli/commands/profiles_v1.rs");
    assert!(
        src.contains(BLOCK_RESPONSE_PARSE_ERR_PREFIX),
        "block-response parse error must start with `{BLOCK_RESPONSE_PARSE_ERR_PREFIX}` \
         (operator-facing recovery hint)"
    );
    assert!(
        src.contains(BLOCK_RESPONSE_PARSE_ERR_SUFFIX),
        "block-response parse error must end with `{BLOCK_RESPONSE_PARSE_ERR_SUFFIX}` \
         (lists the accepted variants)"
    );
}

#[test]
fn s49_ecs_mode_parse_error_template_pinned() {
    let src = include_str!("../src/cli/commands/profiles_v1.rs");
    assert!(
        src.contains(ECS_MODE_PARSE_ERR_PREFIX),
        "ecs mode parse error must start with `{ECS_MODE_PARSE_ERR_PREFIX}`"
    );
    assert!(
        src.contains(ECS_MODE_PARSE_ERR_SUFFIX),
        "ecs mode parse error must end with `{ECS_MODE_PARSE_ERR_SUFFIX}` \
         (lists the accepted modes)"
    );
}

// ── IPC client error envelope (profiles_v1.rs::send_and_print) ───

#[test]
fn s49_ipc_daemon_refused_prefix_pinned() {
    let src = include_str!("../src/cli/commands/profiles_v1.rs");
    assert!(
        src.contains(IPC_DAEMON_REFUSED_PREFIX),
        "IPC error envelope must use prefix `{IPC_DAEMON_REFUSED_PREFIX}` so operator log \
         filters keep matching (consistent with `warden lists forget`)"
    );
}

#[test]
fn s49_ipc_unexpected_response_message_pinned() {
    let src = include_str!("../src/cli/commands/profiles_v1.rs");
    assert!(
        src.contains(IPC_UNEXPECTED_RESPONSE),
        "out-of-shape daemon response must surface as `{IPC_UNEXPECTED_RESPONSE}`"
    );
}

// ── IPC verb dispatch shape (protocol.rs) ────────────────────────

#[test]
fn s49_ipc_command_profile_variants_exist() {
    let src = include_str!("../src/ipc/protocol.rs");
    for variant in ["ProfileCreate", "ProfileUpdate", "ProfileDelete"] {
        assert!(
            src.contains(variant),
            "IpcCommand must declare `{variant}` variant (Sprint §4.26 §1/2 wire protocol)"
        );
    }
}

#[test]
fn s49_profile_update_patch_struct_shape_pinned() {
    let src = include_str!("../src/ipc/protocol.rs");
    for field in [
        "display_name",
        "block_response",
        "blocked_ttl_secs",
        "block_all",
        "admin_rules",
        "ecs",
    ] {
        assert!(
            src.contains(&format!("pub {field}:")),
            "ProfileUpdatePatch must expose `pub {field}:` field (D4 MUTATE 6 coverage)"
        );
    }
}
