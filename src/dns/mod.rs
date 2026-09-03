//! DNS server: UDP listener, query handler, validation, cache, and canned responses.

pub mod audit_ecs;
pub mod cache;
/// DNSSEC response-path consumer (the `dnssec.mode` wiring).
#[cfg(feature = "dnssec")]
pub mod dnssec_validator;
pub mod edns;
pub mod error;
pub mod handler;
pub mod local;
pub mod local_profile;
pub mod rewrite;
pub mod server;
pub mod validation;
