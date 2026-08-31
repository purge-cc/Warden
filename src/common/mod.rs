//! Shared utilities used across more than one top-level module.
//!
//! Helpers here have no dependency on `filter`, `lists`, `dns`, etc., and
//! are safe for any module to import. Add new helpers only when the same
//! logic is needed in two or more modules — single-consumer helpers belong
//! next to their consumer.

pub mod domain;
