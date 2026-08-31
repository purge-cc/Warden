//! §4.7 Phase 2 T3 integration: cache-body byte-size sanity check
//! catches corrupted `.cache` files at boot.
//!
//! The unit suite in `src/lists/manager.rs` covers the predicate
//! across the integer-arithmetic edge cases. This integration test
//! pins the **operationally relevant** scenarios — typical 5 MB
//! list sizes, the ~50 KB / 1000-entry floor discussed in §11.3, the
//! back-compat path for pre-T3 `.meta` files, and the exact 1 %
//! boundary that separates "supply-chain churn" from "corruption".
//!
//! The black-box angle here is the predicate's public contract:
//! anything not strictly under 1 % is rejected, regardless of which
//! side of `expected` the actual lands on.

use purge_warden::lists::manager::validate_cached_body_size;

/// Typical purge.cc privacy list — a couple of MB. Used as a
/// realistic anchor for the percentage assertions below.
const TYPICAL_LIST_SIZE_BYTES: usize = 5_000_000;

#[test]
fn typical_supply_chain_churn_under_one_percent_accepted() {
    // +0.5 % — a list that grew by ~25 KB / ~500 entries.
    assert!(validate_cached_body_size(
        Some(TYPICAL_LIST_SIZE_BYTES),
        TYPICAL_LIST_SIZE_BYTES + 25_000
    ));
    // -0.5 % — a list that shrank by the same amount.
    assert!(validate_cached_body_size(
        Some(TYPICAL_LIST_SIZE_BYTES),
        TYPICAL_LIST_SIZE_BYTES - 25_000
    ));
    // Exact match always passes.
    assert!(validate_cached_body_size(
        Some(TYPICAL_LIST_SIZE_BYTES),
        TYPICAL_LIST_SIZE_BYTES
    ));
}

#[test]
fn corruption_above_one_percent_rejected_symmetrically() {
    // +1.5 % drift — 75 KB above expected.
    assert!(!validate_cached_body_size(
        Some(TYPICAL_LIST_SIZE_BYTES),
        TYPICAL_LIST_SIZE_BYTES + 75_000
    ));
    // -1.5 % drift — 75 KB below expected (the "truncated cache"
    // scenario the CT smoke step exercises via `truncate -s 50%`).
    assert!(!validate_cached_body_size(
        Some(TYPICAL_LIST_SIZE_BYTES),
        TYPICAL_LIST_SIZE_BYTES - 75_000
    ));
    // 50 % truncation — extreme corruption, well past the 1 % gate.
    assert!(!validate_cached_body_size(
        Some(TYPICAL_LIST_SIZE_BYTES),
        TYPICAL_LIST_SIZE_BYTES / 2
    ));
    // Exact 1 % rejects: the predicate is strict less-than.
    assert!(!validate_cached_body_size(
        Some(TYPICAL_LIST_SIZE_BYTES),
        TYPICAL_LIST_SIZE_BYTES + 50_000
    ));
}

#[test]
fn legacy_pre_t3_meta_files_pass_unconditionally() {
    // None expected => trust the body, regardless of actual size.
    // This is the back-compat path for `.meta` files written by
    // pre-Phase-2 daemons (no `size=` line).
    assert!(validate_cached_body_size(None, 0));
    assert!(validate_cached_body_size(None, TYPICAL_LIST_SIZE_BYTES));
    assert!(validate_cached_body_size(None, usize::MAX));

    // Some(0) — degenerate case (empty-body claim). Accept rather
    // than reject so an upgrade from Phase 1 with a zero-byte
    // legacy meta does not force an HTTP burst on the next boot.
    assert!(validate_cached_body_size(Some(0), 0));
    assert!(validate_cached_body_size(Some(0), TYPICAL_LIST_SIZE_BYTES));
}
