//! List management: download, parse, and feed blocklists into the filter engine.
//!
//! This module handles the full list lifecycle:
//! - [`catalog`] — Resolve list IDs to download URLs via purge.cc index.json
//! - [`parser`] — Parse domain-per-line text files into `CompactString` sets
//! - [`manager`] — Download lists, cache bodies, and periodically refresh via ArcSwap
//! - [`readiness`] — The latching "a generation has been installed" gate the
//!   manager opens and the DNS handler reads

pub mod catalog;
pub mod detector;
pub mod http_client;
pub mod manager;
pub mod parser;
pub mod readiness;
pub mod source_key;
pub mod status;
