// IPC: Unix socket CLI↔daemon communication
pub mod auth_token;
pub mod errors;
pub mod protocol;
pub mod reload_coalescer;
pub mod socket_client;
pub mod socket_server;

pub use errors::{ipc_error, IpcError};
pub use reload_coalescer::{
    format_rule_reload_batched, ReloadCoalescer, DEFAULT_WINDOW as RELOAD_COALESCE_WINDOW,
    RULE_RELOAD_BATCHED,
};
