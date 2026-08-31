//! Domain filter engine — lock-free blocklist with subdomain walk and per-profile bitmasks.

pub mod cname;
pub mod engine;
pub mod evaluator;
pub mod ip_filter;
pub mod rules;

pub use engine::FilterEngine;
