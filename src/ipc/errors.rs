//! Frozen IPC error envelope.
//!
//! Every operator-facing error path the daemon writes onto the IPC
//! socket flows through [`IpcError`]. The on-wire shape is
//! `IpcResponse::Error { message: String }` — a JSON string field —
//! but daemon-side code must not pass arbitrary `format!()` payloads
//! into that field. Per-site detail (file paths, validator dumps,
//! internal type names) lives on the daemon log via
//! `tracing::warn!(target: "ipc.error", ...)`; the wire-side
//! `message` is one of a small set of frozen operator strings indexed
//! by [`IpcError`] variant.
//!
//! Why this exists:
//!
//! 1. **The IPC socket's permissions gate who can connect, not what a
//!    connected peer can read on the wire.** Putting
//!    `config_path.display()` or similar detail into an error payload
//!    would disclose the daemon's filesystem layout to any process
//!    that can open the socket. Keeping paths off the wire is a
//!    second line of defense independent of the socket's mode bits.
//! 2. **Frozen strings let operator tooling depend on exact text.**
//!    Other modules pin operator-facing strings via byte-for-byte
//!    test gates so a refactor cannot silently re-word a message that
//!    scripts grep on. This module brings the IPC error path under
//!    the same invariant.
//!
//! How to use:
//!
//! ```ignore
//! use crate::ipc::errors::{ipc_error, IpcError};
//!
//! // Path-leaking:
//! return IpcResponse::Error {
//!     message: format!("couldn't write {}: {e}.", config_path.display()),
//! };
//!
//! // Instead:
//! tracing::warn!(
//!     target: "ipc.error",
//!     path = %config_path.display(),
//!     error = %e,
//!     "config write failed",
//! );
//! return ipc_error(IpcError::ConfigWriteFailed);
//! ```
//!
//! The companion test `tests/frozen_strings_ipc_errors.rs` pins each
//! variant's `operator_message()` output byte-for-byte and grep-checks
//! that no `IpcResponse::Error { message: format!` literal slips back
//! into `src/ipc/socket_server.rs` on a future commit.

use super::protocol::IpcResponse;

// ─────────────────────────────────────────────────────────────────────
// Frozen operator strings.
//
// Each `pub const` IS the canonical wire-side text for its IpcError
// variant. Tests pin every literal byte-for-byte. A reword here is a
// breaking change to operators who grep `journalctl` / CLI output —
// only edit alongside the matching frozen-string test update.
// ─────────────────────────────────────────────────────────────────────

pub const IPC_ERROR_COMMAND_TOO_LARGE: &str = "command too large";
pub const IPC_ERROR_INVALID_COMMAND: &str = "invalid command; see daemon log";

pub const IPC_ERROR_TOKEN_REQUIRED: &str =
    "this command needs an admin token but none was attached. \
     Use the `warden` CLI (not a raw socket client) — it will \
     auto-discover the token from /var/lib/purge-warden/token.";
pub const IPC_ERROR_TOKEN_MISMATCH: &str = "the provided token does not match the daemon's. \
     This usually means the token was regenerated on one side but \
     not the other. Run `warden token regenerate` to create a new \
     matching pair, or copy the token file from the host where the \
     daemon runs.";

pub const IPC_ERROR_LIST_MANAGER_NOT_RUNNING: &str =
    "list manager is not running (no `[lists].sources` configured)";
pub const IPC_ERROR_LIST_MANAGER_CHANNEL_CLOSED: &str =
    "list manager command channel is closed (manager may have crashed; \
     try `warden reload`)";
pub const IPC_ERROR_LIST_MANAGER_NO_ACK: &str =
    "list manager dropped the forget ack channel without responding";

pub const IPC_ERROR_RELOAD_CHANNEL_CLOSED: &str = "reload channel closed";
pub const IPC_ERROR_RELOAD_NOT_AVAILABLE: &str = "reload not available";
pub const IPC_ERROR_SHUTDOWN_CHANNEL_CLOSED: &str = "shutdown channel closed";
pub const IPC_ERROR_SHUTDOWN_NOT_AVAILABLE: &str = "shutdown not available";

pub const IPC_ERROR_TRACKING_NOT_ENABLED: &str = "tracking not enabled";
pub const IPC_ERROR_NO_PROFILE_RESOLVER: &str =
    "profile resolver not available — daemon started without [[clients]] \
     wired, so this verb is disabled";
pub const IPC_ERROR_NO_PROFILES_RESOLVER_PROMOTE: &str =
    "no profile resolver wired into this daemon — promote needs \
     access to the live ARP table to pin a MAC, and that lives on \
     the resolver. Restart the daemon via `warden --config <path> start`.";
pub const IPC_ERROR_NO_CONFIG_PATH: &str =
    "this daemon was started without a config path bound to its IPC \
     interface; mutating verbs are disabled. Restart the daemon via \
     `warden --config <path> start`.";

pub const IPC_ERROR_RETENTION_OUT_OF_RANGE: &str = "retention_days must be between 1 and 365.";
pub const IPC_ERROR_LOG_MODE_RATE_OUT_OF_RANGE: &str =
    "log_mode sampled allowed_rate must be between 0.0 and 1.0.";

pub const IPC_ERROR_CONFIG_READ_FAILED: &str =
    "could not read the config file; see daemon log for path + details. \
     The change was NOT saved — the original file is unchanged.";
pub const IPC_ERROR_CONFIG_WRITE_FAILED: &str =
    "could not write the config file; see daemon log for path + details. \
     The change was NOT saved — the original file is unchanged.";
pub const IPC_ERROR_TARGET_READ_FAILED: &str =
    "could not read the target include file; see daemon log for path + details. \
     The change was NOT saved.";
pub const IPC_ERROR_TARGET_WRITE_FAILED: &str =
    "could not write the target include file; see daemon log for path + details. \
     The change was NOT saved.";
pub const IPC_ERROR_VALIDATOR_REJECTED: &str =
    "the change would leave the configuration invalid; see daemon log for the validator's full report. \
     The change was NOT saved — the original file is unchanged.";
pub const IPC_ERROR_VALIDATION_FAILED: &str =
    "the change does not pass validation; see daemon log. \
     The change was NOT saved.";
pub const IPC_ERROR_STAGE_FAILED: &str = "could not stage the change; see daemon log. \
     The change was NOT saved.";
pub const IPC_ERROR_INVALID_ARGUMENT: &str = "invalid argument; see daemon log for details.";
pub const IPC_ERROR_CONCURRENT_EDIT: &str =
    "the target include file changed unexpectedly underneath the daemon (likely a \
     concurrent edit). The change was NOT saved — retry the verb.";
pub const IPC_ERROR_TARGET_SCAN_FAILED: &str =
    "could not scan the config or its includes for the target file; see daemon log. \
     The change was NOT saved.";

pub const IPC_ERROR_INTERNAL: &str = "internal error; see daemon log";

// Payload-bearing variants substitute one or more `{...}` placeholders
// into a fixed template. Templates are pinned byte-for-byte by the
// frozen-strings test; the formatting helpers below substitute the
// per-call user-supplied value (a device name, profile id, IP, etc. —
// never an internal filesystem path).
pub const IPC_ERROR_DUPLICATE_DEVICE_NAME: &str =
    "a device named \"{name}\" already exists. Pick a different name, or use \
     `warden device set {name} ...` to update the existing one.";
pub const IPC_ERROR_DUPLICATE_DEVICE_IP: &str =
    "IP {ip} is already assigned to another client. Each client must have a unique IP.";
pub const IPC_ERROR_DEVICE_NOT_FOUND: &str =
    "no device named \"{name}\" is configured. Run `warden device list` to see what is.";
pub const IPC_ERROR_PROFILE_NOT_FOUND: &str =
    "no profile with id \"{id}\" is configured. Run `warden profile list` to see what is.";
pub const IPC_ERROR_DUPLICATE_PROFILE_ID: &str =
    "a profile with id \"{id}\" already exists. Pick a different id, or use \
     `warden profile set {id} ...` to update the existing one.";
pub const IPC_ERROR_INVALID_PROFILE_ID: &str =
    "invalid profile id \"{id}\"; see daemon log for the validator's exact reason.";
pub const IPC_ERROR_CONFIG_SAVED_RELOAD_CLOSED: &str =
    "the change was saved to disk but the daemon's reload channel is closed. \
     Restart the daemon to pick up the change.";
pub const IPC_ERROR_NO_ARP_MAC_FOR_IP: &str =
    "no MAC address for {ip} in the ARP table. The device must be active on the \
     local network so the daemon can resolve its MAC before promotion. Wait a \
     few seconds (try `ping {ip}` from this host to refresh ARP), then retry. \
     Identification by IP alone is not allowed because DHCP can reassign the \
     IP to a different physical device.";
pub const IPC_ERROR_LIST_POLICY_UNKNOWN_LIST: &str =
    "profile \"{id}\" names blocklist \"{list}\" in its list policy, but no \
     [[blocklists]] entry with that id is configured. Run `warden blocklist list` \
     to see what is.";
pub const IPC_ERROR_OVERRIDE_ALLOW_NEEDS_CONSENT: &str =
    "profile \"{id}\" cannot override blocklist \"{list}\" to \"allow\": that list \
     is remote and unsigned, and its [[blocklists]] entry does not carry \
     accept_unsigned_allow = true. Whoever controls that URL would decide which \
     domains stop being blocked, at every refresh. Declare it on the list first \
     with `warden blocklist set-trust {list} remote-unsigned --accept-unsigned-allow`; \
     a profile override cannot declare it on the list's behalf, because the \
     declaration belongs to the list and reaches every profile that allows it.";

// ─────────────────────────────────────────────────────────────────────
// IpcError enum.
//
// One variant per error class the daemon can land on. Payload-free
// variants carry no fields and resolve to a `pub const` literal.
// Payload-bearing variants carry user-supplied identifiers (device
// name, profile id, IP) that substitute into a frozen template — the
// template stays pinned, only the operator-typed value travels through.
// Filesystem paths and internal type names never appear in the
// payload; those move to `tracing::warn!(target: "ipc.error", ...)`
// at the call site.
// ─────────────────────────────────────────────────────────────────────

/// Frozen classification of every operator-facing IPC error.
///
/// Per-site detail that is NOT operator-typed (paths, validator
/// dumps, internal type names) is written to the daemon log via
/// `tracing::warn!(target: "ipc.error", ...)` at the call site;
/// only the variant + any operator-supplied identifiers travel over
/// the wire, surfacing as the frozen string returned by
/// [`IpcError::operator_message`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcError {
    CommandTooLarge,
    InvalidCommand,

    TokenRequired,
    TokenMismatch,
    NoTokenConfigured,

    ListManagerNotRunning,
    ListManagerChannelClosed,
    ListManagerNoAck,

    ReloadChannelClosed,
    ReloadNotAvailable,
    ShutdownChannelClosed,
    ShutdownNotAvailable,

    TrackingNotEnabled,
    NoProfileResolver,
    NoProfilesResolverPromote,
    NoConfigPath,

    RetentionDaysOutOfRange,
    LogModeRateOutOfRange,

    ConfigReadFailed,
    ConfigWriteFailed,
    TargetReadFailed,
    TargetWriteFailed,
    ValidatorRejected,
    ValidationFailed,
    StageFailed,
    InvalidArgument,
    ConcurrentEdit,
    TargetScanFailed,
    ConfigSavedReloadClosed,

    /// Operator-typed value echoes back in the message (never a path
    /// or internal type name). Templates pinned in this module's
    /// `pub const IPC_ERROR_*` block.
    DuplicateDeviceName {
        name: String,
    },
    DuplicateDeviceIp {
        ip: String,
    },
    DeviceNotFound {
        name: String,
    },
    ProfileNotFound {
        id: String,
    },
    DuplicateProfileId {
        id: String,
    },
    InvalidProfileId {
        id: String,
    },
    NoArpMacForPromote {
        ip: String,
    },

    /// A `ListPolicyPatch.set` key that no `[[blocklists]]` entry
    /// declares. Refused in the handler rather than left to the
    /// post-write validator's `CrossRefMiss`: that rejects the WHOLE
    /// file, so the other fields of the same patch are lost along with
    /// the typo.
    ListPolicyUnknownList {
        id: String,
        list: String,
    },

    /// A per-profile `allow` override on a `trust = remote-unsigned`
    /// list whose row does not already carry
    /// `accept_unsigned_allow = true`. An override cannot declare that
    /// consent: at the daemon there is no operator to ask, and
    /// rewriting the list's row would widen the declaration to every
    /// other profile overriding it.
    OverrideAllowNeedsConsent {
        id: String,
        list: String,
    },

    Internal,
}

impl IpcError {
    /// Operator-facing message. Tests pin the byte-for-byte output of
    /// this method (with known-input fixtures for payload-bearing
    /// variants).
    pub fn operator_message(&self) -> String {
        match self {
            Self::CommandTooLarge => IPC_ERROR_COMMAND_TOO_LARGE.to_string(),
            Self::InvalidCommand => IPC_ERROR_INVALID_COMMAND.to_string(),
            Self::TokenRequired => IPC_ERROR_TOKEN_REQUIRED.to_string(),
            Self::TokenMismatch => IPC_ERROR_TOKEN_MISMATCH.to_string(),
            Self::NoTokenConfigured => super::auth_token::NO_TOKEN_CONFIGURED_MSG.to_string(),
            Self::ListManagerNotRunning => IPC_ERROR_LIST_MANAGER_NOT_RUNNING.to_string(),
            Self::ListManagerChannelClosed => IPC_ERROR_LIST_MANAGER_CHANNEL_CLOSED.to_string(),
            Self::ListManagerNoAck => IPC_ERROR_LIST_MANAGER_NO_ACK.to_string(),
            Self::ReloadChannelClosed => IPC_ERROR_RELOAD_CHANNEL_CLOSED.to_string(),
            Self::ReloadNotAvailable => IPC_ERROR_RELOAD_NOT_AVAILABLE.to_string(),
            Self::ShutdownChannelClosed => IPC_ERROR_SHUTDOWN_CHANNEL_CLOSED.to_string(),
            Self::ShutdownNotAvailable => IPC_ERROR_SHUTDOWN_NOT_AVAILABLE.to_string(),
            Self::TrackingNotEnabled => IPC_ERROR_TRACKING_NOT_ENABLED.to_string(),
            Self::NoProfileResolver => IPC_ERROR_NO_PROFILE_RESOLVER.to_string(),
            Self::NoProfilesResolverPromote => IPC_ERROR_NO_PROFILES_RESOLVER_PROMOTE.to_string(),
            Self::NoConfigPath => IPC_ERROR_NO_CONFIG_PATH.to_string(),
            Self::RetentionDaysOutOfRange => IPC_ERROR_RETENTION_OUT_OF_RANGE.to_string(),
            Self::LogModeRateOutOfRange => IPC_ERROR_LOG_MODE_RATE_OUT_OF_RANGE.to_string(),
            Self::ConfigReadFailed => IPC_ERROR_CONFIG_READ_FAILED.to_string(),
            Self::ConfigWriteFailed => IPC_ERROR_CONFIG_WRITE_FAILED.to_string(),
            Self::TargetReadFailed => IPC_ERROR_TARGET_READ_FAILED.to_string(),
            Self::TargetWriteFailed => IPC_ERROR_TARGET_WRITE_FAILED.to_string(),
            Self::ValidatorRejected => IPC_ERROR_VALIDATOR_REJECTED.to_string(),
            Self::ValidationFailed => IPC_ERROR_VALIDATION_FAILED.to_string(),
            Self::StageFailed => IPC_ERROR_STAGE_FAILED.to_string(),
            Self::InvalidArgument => IPC_ERROR_INVALID_ARGUMENT.to_string(),
            Self::ConcurrentEdit => IPC_ERROR_CONCURRENT_EDIT.to_string(),
            Self::TargetScanFailed => IPC_ERROR_TARGET_SCAN_FAILED.to_string(),
            Self::ConfigSavedReloadClosed => IPC_ERROR_CONFIG_SAVED_RELOAD_CLOSED.to_string(),
            Self::DuplicateDeviceName { name } => {
                IPC_ERROR_DUPLICATE_DEVICE_NAME.replace("{name}", name)
            }
            Self::DuplicateDeviceIp { ip } => IPC_ERROR_DUPLICATE_DEVICE_IP.replace("{ip}", ip),
            Self::DeviceNotFound { name } => IPC_ERROR_DEVICE_NOT_FOUND.replace("{name}", name),
            Self::ProfileNotFound { id } => IPC_ERROR_PROFILE_NOT_FOUND.replace("{id}", id),
            Self::DuplicateProfileId { id } => IPC_ERROR_DUPLICATE_PROFILE_ID.replace("{id}", id),
            Self::InvalidProfileId { id } => IPC_ERROR_INVALID_PROFILE_ID.replace("{id}", id),
            Self::NoArpMacForPromote { ip } => IPC_ERROR_NO_ARP_MAC_FOR_IP.replace("{ip}", ip),
            Self::ListPolicyUnknownList { id, list } => IPC_ERROR_LIST_POLICY_UNKNOWN_LIST
                .replace("{id}", id)
                .replace("{list}", list),
            Self::OverrideAllowNeedsConsent { id, list } => IPC_ERROR_OVERRIDE_ALLOW_NEEDS_CONSENT
                .replace("{id}", id)
                .replace("{list}", list),
            Self::Internal => IPC_ERROR_INTERNAL.to_string(),
        }
    }
}

/// Build an [`IpcResponse::Error`] from a frozen [`IpcError`] variant.
///
/// This is the only sanctioned constructor for `IpcResponse::Error` in
/// `socket_server.rs`. The trip-wire test
/// `tests/frozen_strings_ipc_errors.rs` greps `socket_server.rs` for
/// any direct `IpcResponse::Error { message: format!` and fails CI if
/// one slips back in.
pub fn ipc_error(kind: IpcError) -> IpcResponse {
    IpcResponse::Error {
        message: kind.operator_message(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipc_error_helper_constructs_response_with_frozen_message() {
        match ipc_error(IpcError::CommandTooLarge) {
            IpcResponse::Error { message } => {
                assert_eq!(message, IPC_ERROR_COMMAND_TOO_LARGE);
            }
            other => panic!("expected IpcResponse::Error, got {other:?}"),
        }
    }

    #[test]
    fn operator_message_is_idempotent() {
        // Calling twice must return the same byte sequence — defensive
        // against a future refactor that swaps the impl to a lazy
        // String allocation that builds a different value each call.
        assert_eq!(
            IpcError::ConfigWriteFailed.operator_message(),
            IpcError::ConfigWriteFailed.operator_message()
        );
    }
}
