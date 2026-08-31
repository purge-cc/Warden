//! EDNS extensions: outbound option codecs for upstream queries.
//!
//! §4.8 Sprint 1/2: EDNS Client Subnet (RFC 7871) codec + injection.

pub mod client_subnet;

pub use client_subnet::{AddressFamily, EcsError, EcsPrefix, EdnsClientSubnet};
