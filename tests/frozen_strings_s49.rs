//! Sprint 49 (Lists & Categories v1) — T5 frozen-strings test.
//!
//! **This file is now a tombstone. Both strings it pinned are gone.**
//!
//! It originally pinned the two operator-facing messages coined in S49
//! T2 (`ALLOW_LIST_REQUIRES_LOCAL_TRUST` + `CATEGORY_NOT_FOUND` in
//! `src/config/schema/validator.rs`) and exercised their format helpers
//! so a refactor of the substitution path would also break loudly.
//!
//! - `CATEGORY_NOT_FOUND` + `format_category_not_found` went with the
//!   `Category` entity in Sprint A of `lists_categories_v2` (Q2-A).
//! - `ALLOW_LIST_REQUIRES_LOCAL_TRUST` +
//!   `format_allow_list_requires_local_trust` went with the fall of the
//!   categorical W2.1 gate. The rule it described — "allow-direction
//!   lists require trust=local" — is no longer true: a remote
//!   allow-list is now accepted when the operator declares
//!   `accept_unsigned_allow = true` on it. The string was **deleted
//!   rather than reworded** because a softened version of a sentence
//!   that states a rule which no longer exists is worse than no
//!   sentence: it reads as authoritative and is wrong.
//!
//! Its replacements are pinned in `tests/frozen_strings_unsigned_allow.rs`
//! (`UNSIGNED_ALLOW_LIST_REQUIRES_ACK` — the refusal when no consent is
//! declared, and `UNSIGNED_ALLOW_LIST_ACCEPTED` — the WARN emitted at
//! every load once it is).
//!
//! **The file is kept, empty, on purpose.** Deleting it would erase the
//! only breadcrumb from the S49 design-doc references (§6 R3, §9) and
//! from `DONE.md` / `VERSION.md`, which name this path directly and are
//! append-only. A future agent following one of those references lands
//! here and is told where the strings went; a 404 would send them
//! grepping. Delete it only once nothing points at it any more.
