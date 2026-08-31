//! Authentication for the HTTP API: bearer-token verification and the
//! per-IP failure lockout that fronts it.
//!
//! **HTTP only.** The IPC control socket authenticates separately, in
//! [`crate::ipc`], under its own rules — so a change made here reaches one
//! of warden's two authenticated surfaces, not both.
//!
//! Not hot path: nothing in this module runs on the DNS query path. Tokens
//! are held only as hashes; the plaintext exists for the request that
//! presents it and is never stored.

pub mod middleware;
pub mod token;
