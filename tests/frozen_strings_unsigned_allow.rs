//! Frozen-string pins for the fall of the W2.1 categorical gate.
//!
//! Until this change a blocklist with `base = allow` was refused unless
//! it carried `trust = local`. The rule cost an operator who wanted to
//! guarantee a service a manual download + re-import as a local file —
//! an internal copy that then never updated — and the interface lied:
//! the TUI offered a Block/Allow toggle on remote lists, the save
//! wrote, and the validator rolled it back.
//!
//! The gate is now a **per-list declared consent**. An operator who
//! sets `accept_unsigned_allow = true` gets the list, plus a WARN at
//! every load; an operator who does not gets an error that explains
//! what the risk actually is. The risk did not go away — it became
//! visible in the operator's own TOML.
//!
//! These two strings are the operator's entire view of that trade, so
//! they are pinned byte-for-byte here: the constant **and** the
//! substitution helper, so a refactor of the formatting path breaks
//! loudly rather than silently reshaping the message.
//!
//! When a string MUST change for legitimate reasons (UX re-wording,
//! typo fix), update the literal here in the same commit. Byte-for-byte
//! equality has no escape hatch — that is the entire point of this
//! trip-wire.

use purge_warden::config::schema::validator::{
    format_profile_list_policy_unsigned_allow_requires_ack, format_unsigned_allow_list_accepted,
    format_unsigned_allow_list_requires_ack, PROFILE_LIST_POLICY_UNSIGNED_ALLOW_REQUIRES_ACK,
    PROFILE_LIST_POLICY_UNSIGNED_ALLOW_REQUIRES_ACK_SUGGESTION, UNSIGNED_ALLOW_LIST_ACCEPTED,
    UNSIGNED_ALLOW_LIST_REQUIRES_ACK, UNSIGNED_ALLOW_LIST_REQUIRES_ACK_SUGGESTION,
};
use purge_warden::config::schema::BlocklistTrust;

// ── the refusal (no consent declared) ─────────────────────────────────

#[test]
fn unsigned_allow_list_requires_ack_byte_for_byte() {
    // The backticks around `warden blocklist import-local`, the single
    // quotes on {id} / {got}, and the leading capital are part of the
    // locked wire format — this file's style follows the validator's:
    // ERROR uses '{id}' and starts capitalised.
    assert_eq!(
        UNSIGNED_ALLOW_LIST_REQUIRES_ACK,
        "Blocklist '{id}' has kind=allow but trust='{got}'. A remote allow-list can unblock any domain it lists, and its content can change at every refresh with no review. Set accept_unsigned_allow = true on the list to accept that risk, or use `warden blocklist import-local` to import a local file."
    );
}

#[test]
fn format_unsigned_allow_list_requires_ack_remote_unsigned_full_string() {
    // `RemoteUnsigned` must render as the kebab-case `remote-unsigned`
    // an operator typed in TOML. Pinning the full substituted output
    // covers both the template and the kebab mapping in one assert.
    assert_eq!(
        format_unsigned_allow_list_requires_ack("priv-ads", BlocklistTrust::RemoteUnsigned),
        "Blocklist 'priv-ads' has kind=allow but trust='remote-unsigned'. A remote allow-list can unblock any domain it lists, and its content can change at every refresh with no review. Set accept_unsigned_allow = true on the list to accept that risk, or use `warden blocklist import-local` to import a local file."
    );
}

#[test]
fn format_unsigned_allow_list_requires_ack_signed_full_string() {
    // `signed` reaches this message through the co-occurrence path:
    // `base = allow` + `trust = signed` emits BOTH this error and
    // `TRUST_SIGNED_NOT_YET_SUPPORTED`, exactly as it did before the
    // gate fell. The `{got}` placeholder exists for precisely this
    // case — if the error only ever fired on `remote-unsigned`, both
    // the placeholder and the helper's `trust` parameter would be dead
    // weight.
    assert_eq!(
        format_unsigned_allow_list_requires_ack("trusted-internal", BlocklistTrust::Signed),
        "Blocklist 'trusted-internal' has kind=allow but trust='signed'. A remote allow-list can unblock any domain it lists, and its content can change at every refresh with no review. Set accept_unsigned_allow = true on the list to accept that risk, or use `warden blocklist import-local` to import a local file."
    );
}

/// The remedy is part of the frozen surface, not incidental prose. An
/// error that refuses without naming the field which unblocks it is
/// exactly how the previous categorical gate earned its reputation —
/// operators hit "allow-direction lists require trust=local" and went
/// looking for a workaround instead of a setting.
#[test]
fn unsigned_allow_list_requires_ack_suggestion_byte_for_byte() {
    assert_eq!(
        UNSIGNED_ALLOW_LIST_REQUIRES_ACK_SUGGESTION,
        "set accept_unsigned_allow = true on this list if you trust its publisher, or set base = \"deny\" if this is a deny-direction list"
    );
}

// ── the acceptance (consent declared) ─────────────────────────────────

#[test]
fn unsigned_allow_list_accepted_byte_for_byte() {
    // WARN style in this validator is lowercase-initial with "{id}" in
    // double quotes — matches `ALLOW_LIST_NO_TAGS_NO_EFFECT`. The dash
    // is U+2014 EM DASH, not a hyphen; a normalising editor that
    // rewrites it trips this assert, which is intended.
    assert_eq!(
        UNSIGNED_ALLOW_LIST_ACCEPTED,
        "allow-list \"{id}\" is remote and unsigned — whoever controls its URL can unblock any domain by adding it, at every refresh, with no review"
    );
}

#[test]
fn format_unsigned_allow_list_accepted_full_string() {
    assert_eq!(
        format_unsigned_allow_list_accepted("vendor-allow"),
        "allow-list \"vendor-allow\" is remote and unsigned — whoever controls its URL can unblock any domain by adding it, at every refresh, with no review"
    );
}

// ── the retired string must not come back ─────────────────────────────

/// The old categorical refusal told the operator that allow-direction
/// lists *require* `trust=local`. After this change that sentence is
/// simply false, which is why it was deleted rather than softened.
///
/// Pinning its absence matters because the substring is the kind of
/// thing a well-meaning revert or a merge from a stale branch puts
/// back: the constant would compile, the config would refuse, and the
/// only symptom would be an operator being lied to. Asserting on the
/// *text* rather than the identifier is deliberate — a resurrection
/// under a new name is caught just the same.
#[test]
fn retired_local_trust_requirement_is_not_reintroduced() {
    for (label, s) in [
        ("error", UNSIGNED_ALLOW_LIST_REQUIRES_ACK),
        ("warn", UNSIGNED_ALLOW_LIST_ACCEPTED),
    ] {
        assert!(
            !s.contains("require trust=local"),
            "{label} string reintroduces the retired categorical gate: {s}"
        );
    }
}

// ── plp-s4b: the same property at override scope ──────────────────────

/// The override-scope refusal is pinned byte-for-byte, like its list-scope
/// sibling above.
#[test]
fn profile_list_policy_unsigned_allow_requires_ack_is_frozen() {
    assert_eq!(
        PROFILE_LIST_POLICY_UNSIGNED_ALLOW_REQUIRES_ACK,
        "profile \"{profile}\" sets lists.{list} = \"allow\" but blocklist '{list}' has trust='{got}' and no accept_unsigned_allow. A remote allow-list can unblock any domain it lists, and its content can change at every refresh with no review."
    );
    assert_eq!(
        PROFILE_LIST_POLICY_UNSIGNED_ALLOW_REQUIRES_ACK_SUGGESTION,
        "set accept_unsigned_allow = true on that blocklist if you trust its publisher, or drop the \"allow\" override from this profile"
    );
}

/// Substitution renders both identifiers and the observed trust.
///
/// Naming the profile is not decoration: the ack lives on the list's row
/// while the offence lives in the profile, so an error carrying only the
/// list id sends the operator to inspect a row that looks perfectly fine.
#[test]
fn profile_list_policy_unsigned_allow_substitutes_profile_list_and_trust() {
    let msg = format_profile_list_policy_unsigned_allow_requires_ack(
        "kids",
        "vendor-allow",
        BlocklistTrust::RemoteUnsigned,
    );
    assert!(msg.contains("\"kids\""), "{msg}");
    assert!(msg.contains("lists.vendor-allow"), "{msg}");
    assert!(msg.contains("'vendor-allow'"), "{msg}");
    assert!(msg.contains("trust='remote-unsigned'"), "{msg}");
    assert!(
        !msg.contains("{profile}") && !msg.contains("{list}") && !msg.contains("{got}"),
        "an unsubstituted placeholder reached the operator: {msg}"
    );
}
