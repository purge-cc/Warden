//! §4.33 — frozen-strings trip-wire for [`crate::ipc::errors::IpcError`].
//!
//! Pins each variant's operator message byte-for-byte and grep-checks
//! `src/ipc/socket_server.rs` so a future refactor cannot
//! silently re-introduce an inline `IpcResponse::Error { message:
//! format!(...) }` site (which would leak daemon filesystem paths back
//! onto the wire — the §4.28 b7 ipc-m3 finding this sprint closes).
//!
//! This is the IPC-side companion to:
//! - `frozen_strings_s43.rs` (S43 `RULE_RELOAD_BATCHED`)
//! - `frozen_strings_s48_audit.rs` (S48 audit target name)
//! - the other `frozen_strings_*.rs` files in this directory
//!
//! When a literal here MUST change (UX re-wording, typo fix), update
//! the const in `src/ipc/errors.rs` AND the matching `assert_eq!`
//! literal here in the same commit. Byte-for-byte equality is the
//! whole point of the trip-wire.

use purge_warden::ipc::errors::{
    ipc_error, IpcError, IPC_ERROR_COMMAND_TOO_LARGE, IPC_ERROR_CONCURRENT_EDIT,
    IPC_ERROR_CONFIG_READ_FAILED, IPC_ERROR_CONFIG_SAVED_RELOAD_CLOSED,
    IPC_ERROR_CONFIG_WRITE_FAILED, IPC_ERROR_DEVICE_NOT_FOUND, IPC_ERROR_DUPLICATE_DEVICE_IP,
    IPC_ERROR_DUPLICATE_DEVICE_NAME, IPC_ERROR_DUPLICATE_PROFILE_ID, IPC_ERROR_INTERNAL,
    IPC_ERROR_INVALID_ARGUMENT, IPC_ERROR_INVALID_COMMAND, IPC_ERROR_INVALID_PROFILE_ID,
    IPC_ERROR_LIST_MANAGER_CHANNEL_CLOSED, IPC_ERROR_LIST_MANAGER_NOT_RUNNING,
    IPC_ERROR_LIST_MANAGER_NO_ACK, IPC_ERROR_LOG_MODE_RATE_OUT_OF_RANGE,
    IPC_ERROR_NO_ARP_MAC_FOR_IP, IPC_ERROR_NO_CONFIG_PATH, IPC_ERROR_NO_PROFILES_RESOLVER_PROMOTE,
    IPC_ERROR_NO_PROFILE_RESOLVER, IPC_ERROR_PROFILE_NOT_FOUND, IPC_ERROR_RELOAD_CHANNEL_CLOSED,
    IPC_ERROR_RELOAD_NOT_AVAILABLE, IPC_ERROR_RETENTION_OUT_OF_RANGE,
    IPC_ERROR_SHUTDOWN_CHANNEL_CLOSED, IPC_ERROR_SHUTDOWN_NOT_AVAILABLE, IPC_ERROR_STAGE_FAILED,
    IPC_ERROR_TARGET_READ_FAILED, IPC_ERROR_TARGET_SCAN_FAILED, IPC_ERROR_TARGET_WRITE_FAILED,
    IPC_ERROR_TOKEN_MISMATCH, IPC_ERROR_TOKEN_REQUIRED, IPC_ERROR_TRACKING_NOT_ENABLED,
    IPC_ERROR_VALIDATION_FAILED, IPC_ERROR_VALIDATOR_REJECTED,
};
use purge_warden::ipc::protocol::IpcResponse;

// ─────────────────────────────────────────────────────────────────────
// Byte-for-byte literal pins.
//
// Each `assert_eq!` carries the canonical operator text inline so a
// `git grep` for the literal turns up this file as the place the
// change must be reviewed.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn ipc_error_command_too_large_is_frozen() {
    assert_eq!(IPC_ERROR_COMMAND_TOO_LARGE, "command too large");
}

#[test]
fn ipc_error_invalid_command_is_frozen() {
    assert_eq!(IPC_ERROR_INVALID_COMMAND, "invalid command; see daemon log");
}

#[test]
fn ipc_error_token_required_is_frozen() {
    assert_eq!(
        IPC_ERROR_TOKEN_REQUIRED,
        "this command needs an admin token but none was attached. \
         Use the `warden` CLI (not a raw socket client) — it will \
         auto-discover the token from /var/lib/purge-warden/token."
    );
}

#[test]
fn ipc_error_token_mismatch_is_frozen() {
    assert_eq!(
        IPC_ERROR_TOKEN_MISMATCH,
        "the provided token does not match the daemon's. \
         This usually means the token was regenerated on one side but \
         not the other. Run `warden token regenerate` to create a new \
         matching pair, or copy the token file from the host where the \
         daemon runs."
    );
}

#[test]
fn ipc_error_list_manager_not_running_is_frozen() {
    assert_eq!(
        IPC_ERROR_LIST_MANAGER_NOT_RUNNING,
        "list manager is not running (no `[lists].sources` configured)"
    );
}

#[test]
fn ipc_error_list_manager_channel_closed_is_frozen() {
    assert_eq!(
        IPC_ERROR_LIST_MANAGER_CHANNEL_CLOSED,
        "list manager command channel is closed (manager may have crashed; \
         try `warden reload`)"
    );
}

#[test]
fn ipc_error_list_manager_no_ack_is_frozen() {
    assert_eq!(
        IPC_ERROR_LIST_MANAGER_NO_ACK,
        "list manager dropped the forget ack channel without responding"
    );
}

#[test]
fn ipc_error_reload_channel_closed_is_frozen() {
    assert_eq!(IPC_ERROR_RELOAD_CHANNEL_CLOSED, "reload channel closed");
}

#[test]
fn ipc_error_reload_not_available_is_frozen() {
    assert_eq!(IPC_ERROR_RELOAD_NOT_AVAILABLE, "reload not available");
}

#[test]
fn ipc_error_shutdown_channel_closed_is_frozen() {
    assert_eq!(IPC_ERROR_SHUTDOWN_CHANNEL_CLOSED, "shutdown channel closed");
}

#[test]
fn ipc_error_shutdown_not_available_is_frozen() {
    assert_eq!(IPC_ERROR_SHUTDOWN_NOT_AVAILABLE, "shutdown not available");
}

#[test]
fn ipc_error_tracking_not_enabled_is_frozen() {
    assert_eq!(IPC_ERROR_TRACKING_NOT_ENABLED, "tracking not enabled");
}

#[test]
fn ipc_error_no_profile_resolver_is_frozen() {
    assert_eq!(
        IPC_ERROR_NO_PROFILE_RESOLVER,
        "profile resolver not available — daemon started without [[clients]] \
         wired, so this verb is disabled"
    );
}

#[test]
fn ipc_error_no_profiles_resolver_promote_is_frozen() {
    assert_eq!(
        IPC_ERROR_NO_PROFILES_RESOLVER_PROMOTE,
        "no profile resolver wired into this daemon — promote needs \
         access to the live ARP table to pin a MAC, and that lives on \
         the resolver. Restart the daemon via `warden --config <path> start`."
    );
}

#[test]
fn ipc_error_no_config_path_is_frozen() {
    assert_eq!(
        IPC_ERROR_NO_CONFIG_PATH,
        "this daemon was started without a config path bound to its IPC \
         interface; mutating verbs are disabled. Restart the daemon via \
         `warden --config <path> start`."
    );
}

#[test]
fn ipc_error_retention_out_of_range_is_frozen() {
    assert_eq!(
        IPC_ERROR_RETENTION_OUT_OF_RANGE,
        "retention_days must be between 1 and 365."
    );
}

#[test]
fn ipc_error_log_mode_rate_out_of_range_is_frozen() {
    assert_eq!(
        IPC_ERROR_LOG_MODE_RATE_OUT_OF_RANGE,
        "log_mode sampled allowed_rate must be between 0.0 and 1.0."
    );
}

#[test]
fn ipc_error_config_read_failed_is_frozen() {
    assert_eq!(
        IPC_ERROR_CONFIG_READ_FAILED,
        "could not read the config file; see daemon log for path + details. \
         The change was NOT saved — the original file is unchanged."
    );
}

#[test]
fn ipc_error_config_write_failed_is_frozen() {
    assert_eq!(
        IPC_ERROR_CONFIG_WRITE_FAILED,
        "could not write the config file; see daemon log for path + details. \
         The change was NOT saved — the original file is unchanged."
    );
}

#[test]
fn ipc_error_target_read_failed_is_frozen() {
    assert_eq!(
        IPC_ERROR_TARGET_READ_FAILED,
        "could not read the target include file; see daemon log for path + details. \
         The change was NOT saved."
    );
}

#[test]
fn ipc_error_target_write_failed_is_frozen() {
    assert_eq!(
        IPC_ERROR_TARGET_WRITE_FAILED,
        "could not write the target include file; see daemon log for path + details. \
         The change was NOT saved."
    );
}

#[test]
fn ipc_error_validator_rejected_is_frozen() {
    assert_eq!(
        IPC_ERROR_VALIDATOR_REJECTED,
        "the change would leave the configuration invalid; see daemon log for the validator's full report. \
         The change was NOT saved — the original file is unchanged."
    );
}

#[test]
fn ipc_error_validation_failed_is_frozen() {
    assert_eq!(
        IPC_ERROR_VALIDATION_FAILED,
        "the change does not pass validation; see daemon log. \
         The change was NOT saved."
    );
}

#[test]
fn ipc_error_stage_failed_is_frozen() {
    assert_eq!(
        IPC_ERROR_STAGE_FAILED,
        "could not stage the change; see daemon log. \
         The change was NOT saved."
    );
}

#[test]
fn ipc_error_invalid_argument_is_frozen() {
    assert_eq!(
        IPC_ERROR_INVALID_ARGUMENT,
        "invalid argument; see daemon log for details."
    );
}

#[test]
fn ipc_error_concurrent_edit_is_frozen() {
    assert_eq!(
        IPC_ERROR_CONCURRENT_EDIT,
        "the target include file changed unexpectedly underneath the daemon (likely a \
         concurrent edit). The change was NOT saved — retry the verb."
    );
}

#[test]
fn ipc_error_target_scan_failed_is_frozen() {
    assert_eq!(
        IPC_ERROR_TARGET_SCAN_FAILED,
        "could not scan the config or its includes for the target file; see daemon log. \
         The change was NOT saved."
    );
}

#[test]
fn ipc_error_internal_is_frozen() {
    assert_eq!(IPC_ERROR_INTERNAL, "internal error; see daemon log");
}

#[test]
fn ipc_error_config_saved_reload_closed_is_frozen() {
    assert_eq!(
        IPC_ERROR_CONFIG_SAVED_RELOAD_CLOSED,
        "the change was saved to disk but the daemon's reload channel is closed. \
         Restart the daemon to pick up the change."
    );
}

// ─────────────────────────────────────────────────────────────────────
// Payload-bearing templates: the placeholder template stays pinned,
// AND the formatted output for a known fixture is pinned. A refactor
// that drops the substitution layer trips both halves.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn ipc_error_duplicate_device_name_template_is_frozen() {
    assert_eq!(
        IPC_ERROR_DUPLICATE_DEVICE_NAME,
        "a device named \"{name}\" already exists. Pick a different name, or use \
         `warden device set {name} ...` to update the existing one."
    );
}

#[test]
fn ipc_error_duplicate_device_name_substitutes_name() {
    let msg = IpcError::DuplicateDeviceName {
        name: "laptop".into(),
    }
    .operator_message();
    assert_eq!(
        msg,
        "a device named \"laptop\" already exists. Pick a different name, or use \
         `warden device set laptop ...` to update the existing one."
    );
    assert!(!msg.contains("{name}"), "leftover placeholder in {msg:?}");
}

#[test]
fn ipc_error_duplicate_device_ip_template_is_frozen() {
    assert_eq!(
        IPC_ERROR_DUPLICATE_DEVICE_IP,
        "IP {ip} is already assigned to another client. Each client must have a unique IP."
    );
}

#[test]
fn ipc_error_duplicate_device_ip_substitutes_ip() {
    let msg = IpcError::DuplicateDeviceIp {
        ip: "10.0.0.5".into(),
    }
    .operator_message();
    assert_eq!(
        msg,
        "IP 10.0.0.5 is already assigned to another client. Each client must have a unique IP."
    );
}

#[test]
fn ipc_error_device_not_found_template_is_frozen() {
    assert_eq!(
        IPC_ERROR_DEVICE_NOT_FOUND,
        "no device named \"{name}\" is configured. Run `warden device list` to see what is."
    );
}

#[test]
fn ipc_error_device_not_found_substitutes_name() {
    let msg = IpcError::DeviceNotFound {
        name: "tablet".into(),
    }
    .operator_message();
    assert_eq!(
        msg,
        "no device named \"tablet\" is configured. Run `warden device list` to see what is."
    );
}

#[test]
fn ipc_error_profile_not_found_template_is_frozen() {
    assert_eq!(
        IPC_ERROR_PROFILE_NOT_FOUND,
        "no profile with id \"{id}\" is configured. Run `warden profile list` to see what is."
    );
}

#[test]
fn ipc_error_profile_not_found_substitutes_id() {
    let msg = IpcError::ProfileNotFound { id: "kids".into() }.operator_message();
    assert_eq!(
        msg,
        "no profile with id \"kids\" is configured. Run `warden profile list` to see what is."
    );
}

#[test]
fn ipc_error_duplicate_profile_id_template_is_frozen() {
    assert_eq!(
        IPC_ERROR_DUPLICATE_PROFILE_ID,
        "a profile with id \"{id}\" already exists. Pick a different id, or use \
         `warden profile set {id} ...` to update the existing one."
    );
}

#[test]
fn ipc_error_duplicate_profile_id_substitutes_id() {
    let msg = IpcError::DuplicateProfileId {
        id: "default".into(),
    }
    .operator_message();
    assert_eq!(
        msg,
        "a profile with id \"default\" already exists. Pick a different id, or use \
         `warden profile set default ...` to update the existing one."
    );
}

#[test]
fn ipc_error_invalid_profile_id_template_is_frozen() {
    assert_eq!(
        IPC_ERROR_INVALID_PROFILE_ID,
        "invalid profile id \"{id}\"; see daemon log for the validator's exact reason."
    );
}

#[test]
fn ipc_error_invalid_profile_id_substitutes_id() {
    let msg = IpcError::InvalidProfileId {
        id: "Bad ID".into(),
    }
    .operator_message();
    assert_eq!(
        msg,
        "invalid profile id \"Bad ID\"; see daemon log for the validator's exact reason."
    );
}

#[test]
fn ipc_error_no_arp_mac_for_promote_template_is_frozen() {
    assert_eq!(
        IPC_ERROR_NO_ARP_MAC_FOR_IP,
        "no MAC address for {ip} in the ARP table. The device must be active on the \
         local network so the daemon can resolve its MAC before promotion. Wait a \
         few seconds (try `ping {ip}` from this host to refresh ARP), then retry. \
         Identification by IP alone is not allowed because DHCP can reassign the \
         IP to a different physical device."
    );
}

#[test]
fn ipc_error_no_arp_mac_for_promote_substitutes_ip() {
    let msg = IpcError::NoArpMacForPromote {
        ip: "192.168.1.42".into(),
    }
    .operator_message();
    assert!(
        msg.contains("192.168.1.42"),
        "expected IP substituted twice, got: {msg}"
    );
    assert!(!msg.contains("{ip}"), "leftover placeholder in {msg:?}");
}

// ─────────────────────────────────────────────────────────────────────
// Helper round-trip.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn ipc_error_helper_wraps_message_into_response() {
    match ipc_error(IpcError::CommandTooLarge) {
        IpcResponse::Error { message } => {
            assert_eq!(message, IPC_ERROR_COMMAND_TOO_LARGE);
        }
        other => panic!("expected IpcResponse::Error, got {other:?}"),
    }
}

#[test]
fn ipc_error_helper_wraps_payload_bearing_variant() {
    match ipc_error(IpcError::DeviceNotFound {
        name: "phone".into(),
    }) {
        IpcResponse::Error { message } => {
            assert_eq!(
                message,
                "no device named \"phone\" is configured. Run `warden device list` to see what is."
            );
        }
        other => panic!("expected IpcResponse::Error, got {other:?}"),
    }
}

#[test]
fn ipc_error_wire_payload_carries_no_path() {
    // Defensive: no operator_message output may contain a leading "/"
    // path-like substring (would indicate a path-leak regression where
    // somebody plumbed an `&Path` through the formatter). Catches the
    // most common variant of the ipc-m3 finding this sprint closes.
    //
    // §4.40 exception: `NoTokenConfigured` deliberately names the
    // canonical FHS path `/var/lib/purge-warden/token` as part of the
    // operator-facing "run `warden token generate`" copy — the operator
    // needs to know where the file will land. This is a hard-coded
    // const literal, not a runtime `format!()` plumbing an `&Path`, so
    // the §4.33 threat (variable-content path leak via formatter) does
    // not apply. Whitelisting the const literal substring keeps the
    // tripwire useful for unintended `&Path` plumbing while letting the
    // documented FHS path stay in operator copy.
    const FHS_TOKEN_PATH_OK: &str = "/var/lib/purge-warden/token";
    for kind in [
        IpcError::CommandTooLarge,
        IpcError::InvalidCommand,
        IpcError::TokenRequired,
        IpcError::TokenMismatch,
        IpcError::NoTokenConfigured,
        IpcError::ListManagerNotRunning,
        IpcError::ListManagerChannelClosed,
        IpcError::ListManagerNoAck,
        IpcError::ReloadChannelClosed,
        IpcError::ReloadNotAvailable,
        IpcError::ShutdownChannelClosed,
        IpcError::ShutdownNotAvailable,
        IpcError::TrackingNotEnabled,
        IpcError::NoProfileResolver,
        IpcError::NoProfilesResolverPromote,
        IpcError::NoConfigPath,
        IpcError::RetentionDaysOutOfRange,
        IpcError::LogModeRateOutOfRange,
        IpcError::ConfigReadFailed,
        IpcError::ConfigWriteFailed,
        IpcError::TargetReadFailed,
        IpcError::TargetWriteFailed,
        IpcError::ValidatorRejected,
        IpcError::ValidationFailed,
        IpcError::StageFailed,
        IpcError::InvalidArgument,
        IpcError::ConcurrentEdit,
        IpcError::TargetScanFailed,
        IpcError::ConfigSavedReloadClosed,
        IpcError::Internal,
    ] {
        let msg = kind.operator_message();
        // Strip the §4.40 whitelisted FHS token path before scanning
        // for leak indicators.
        let scrubbed = msg.replace(FHS_TOKEN_PATH_OK, "<fhs-token>");
        assert!(
            !scrubbed.contains("/etc/")
                && !scrubbed.contains("/var/")
                && !scrubbed.contains("/run/"),
            "operator message for {kind:?} leaks an absolute path-looking substring: {msg}"
        );
    }
}

// ── plp-s4b: the two list-policy refusals ────────────────────────────

/// An override naming a list that no `[[blocklists]]` entry declares.
///
/// Refused in the handler rather than left to the post-write validator's
/// `CrossRefMiss`, which rejects the whole file and would take the other
/// fields of the same patch down with the typo — so this message has to
/// carry both identifiers itself.
#[test]
fn list_policy_unknown_list_names_profile_and_list() {
    let msg = IpcError::ListPolicyUnknownList {
        id: "kids".into(),
        list: "no-such-list".into(),
    }
    .operator_message();
    assert!(msg.contains("\"kids\""), "{msg}");
    assert!(msg.contains("\"no-such-list\""), "{msg}");
    assert!(
        msg.contains("warden blocklist list"),
        "must point at the verb that shows what exists: {msg}"
    );
    assert!(!msg.contains("{id}") && !msg.contains("{list}"), "{msg}");
}

/// The override consent refusal.
///
/// It must name the **verb** that declares the ack, not merely the field:
/// the old TUI consent gate earned its reputation by telling operators to
/// set a TOML key the interface gave them no way to set (project rules
/// §Neutrality). It must also name the profile as well as the list — the
/// ack lives on the list's row, the offence lives in the profile.
#[test]
fn override_allow_needs_consent_names_the_verb_that_sets_the_ack() {
    let msg = IpcError::OverrideAllowNeedsConsent {
        id: "kids".into(),
        list: "vendor-allow".into(),
    }
    .operator_message();
    assert!(msg.contains("\"kids\""), "{msg}");
    assert!(msg.contains("\"vendor-allow\""), "{msg}");
    assert!(
        msg.contains(
            "warden blocklist set-trust vendor-allow remote-unsigned --accept-unsigned-allow"
        ),
        "the remedy must be a command the operator can paste: {msg}"
    );
    assert!(
        msg.contains("accept_unsigned_allow"),
        "must name the field the verb writes: {msg}"
    );
    assert!(!msg.contains("{id}") && !msg.contains("{list}"), "{msg}");
}

// ─────────────────────────────────────────────────────────────────────
// Trip-wire: no IpcResponse::Error { message: format!(...) } sites.
//
// The whole point of §4.33 — every operator-facing IPC error MUST flow
// through `ipc_error(IpcError::Variant)`. If anybody re-adds an inline
// `format!()` site in `socket_server.rs` (the recognised vector for
// the ipc-m3 path-leak finding), this test fails byte-for-byte on the
// substring.
// ─────────────────────────────────────────────────────────────────────

const SOCKET_SERVER_SRC: &str = include_str!("../src/ipc/socket_server.rs");

#[test]
fn socket_server_has_no_inline_format_in_ipc_response_error() {
    assert!(
        !SOCKET_SERVER_SRC.contains("IpcResponse::Error { message: format!"),
        "§4.33: re-introduced inline `IpcResponse::Error {{ message: format!(...) }}` site \
         in src/ipc/socket_server.rs — route every operator-facing IPC error through \
         `ipc_error(IpcError::Variant)` instead. The `format!()` detail (path, validator \
         dump, internal type name) belongs on the daemon log via \
         `tracing::warn!(target: \"ipc.error\", ...)`."
    );
}

#[test]
fn socket_server_routes_every_error_through_helper() {
    // Every constructor site of `IpcResponse::Error` should be the
    // ipc_error helper (or destructuring matches `IpcResponse::Error
    // { message }` in tests). Count of explicit `IpcResponse::Error {`
    // constructors should be zero — they all live in `errors.rs` now.
    //
    // Test-side destructuring patterns like
    // `IpcResponse::Error { message }` (no opening `{` on next line)
    // are allowed; the catch is the multi-line struct-init form
    // typified by a trailing `{` on its own line.
    let constructor_sites = SOCKET_SERVER_SRC.matches("IpcResponse::Error {\n").count();
    assert_eq!(
        constructor_sites, 0,
        "§4.33: {constructor_sites} inline IpcResponse::Error {{ ... }} constructor sites \
         remain in socket_server.rs — use ipc_error(IpcError::Variant) instead",
    );
}

// ─────────────────────────────────────────────────────────────────────
// §4.32 audit action names: the additions this sprint introduces
// (device.promote.v1, daemon.reload, daemon.shutdown, cache.flush)
// and the existing names m5 augments with `uid`.
//
// Action names travel through `journalctl` and operator grep pipelines.
// Pin them here so a refactor can't silently rename one.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn socket_server_emits_device_promote_v1_audit() {
    // §4.32 m1: handle_device_promote emits its own audit line before
    // delegating to handle_device_add.
    assert!(
        SOCKET_SERVER_SRC.contains("action = \"device.promote.v1\""),
        "§4.32 m1: missing device.promote.v1 audit emit"
    );
}

#[test]
fn socket_server_emits_daemon_reload_audit() {
    // §4.32 DISC-1: handle_reload emits action=daemon.reload before
    // hitting the coalescer / reload_tx.
    assert!(
        SOCKET_SERVER_SRC.contains("action = \"daemon.reload\""),
        "§4.32 DISC-1: missing daemon.reload audit emit"
    );
}

#[test]
fn socket_server_emits_daemon_shutdown_audit() {
    // §4.32 DISC-1: handle_shutdown emits action=daemon.shutdown.
    assert!(
        SOCKET_SERVER_SRC.contains("action = \"daemon.shutdown\""),
        "§4.32 DISC-1: missing daemon.shutdown audit emit"
    );
}

#[test]
fn socket_server_emits_cache_flush_audit() {
    // §4.32 DISC-2: handle_cache_flush emits action=cache.flush.
    assert!(
        SOCKET_SERVER_SRC.contains("action = \"cache.flush\""),
        "§4.32 DISC-2: missing cache.flush audit emit"
    );
}

#[test]
fn socket_server_audit_emits_carry_uid_field() {
    // §4.32 m5: every audit emit from a mutating handler must carry a
    // `uid = ?peer_uid` field for attribution. We don't enumerate the
    // 11 sites — instead, we assert that the count of `target: "audit"`
    // emit lines matches the count of `uid = ?peer_uid` lines that
    // sit nearby.
    //
    // Approximate proxy: count `action = "..."` audit emits and
    // assert at least as many `uid = ?peer_uid` field occurrences.
    let action_emits = SOCKET_SERVER_SRC.matches("target: \"audit\"").count();
    let uid_fields = SOCKET_SERVER_SRC.matches("uid = ?peer_uid").count();
    assert!(
        uid_fields >= action_emits.saturating_sub(2),
        "§4.32 m5: audit emits ({action_emits}) should carry uid fields ({uid_fields}); \
         allow up to 2 audit emits without uid (e.g. the ipc.peer_uid.refused gate emit \
         which carries `peer_uid = ?other` for the rejected uid, and notify_reload's \
         `uid = ?peer_uid` which is in a separate macro form)"
    );
}
