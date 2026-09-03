//! `profile_list_policy.md` §4 S2 — schema for profile-scoped list policy.
//!
//! S2 is deliberately **additive and inert**: it lands `ListPolicy`, the
//! `profiles.<id>.lists` map, and the cross-reference validation that refuses
//! an override naming a list that does not exist. Nothing consumes the field
//! yet — the resolver and filter engine still take direction from the list's
//! global `kind`, and the cutover is S3.
//!
//! That inertness is exactly what makes these tests worth writing carefully.
//! A field nobody reads cannot be caught misbehaving by any other test in the
//! suite, so the properties below are the only thing standing between S2 and a
//! schema that looks right and is not:
//!
//! 1. **Back-compat is proved, not asserted.** The fixtures are the real
//!    configs measured on the two live hosts (design doc §1.1), not synthesized
//!    minimal ones, and the comparison is against a whole `Profile` value
//!    rather than a field-by-field spot check — so a new field that perturbs an
//!    old one fails here even if nobody thought to assert on it.
//! 2. **The wire name is pinned by a config that uses it.** An absent-field
//!    test passes whatever the field is called; only a config that spells
//!    `lists` and is accepted can distinguish `lists` from `list`.
//! 3. **The refusal names the offending id.** The defect this workstream
//!    exists to repair (E2) is an intent silently discarded, so "it errored" is
//!    not enough — the operator has to be told which id was unresolvable.

use std::collections::BTreeMap;

use purge_warden::config::error::ConfigError;
use purge_warden::config::schema::validator::{
    validate, PROFILE_LIST_POLICY_UNKNOWN_LIST_SUGGESTION,
};
use purge_warden::config::schema::{ConfigV1, Id, ListPolicy, Profile};
use time::OffsetDateTime;

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_715_500_000).unwrap()
}

/// The `[[blocklists]]` + `[profiles]` shape measured on `the lab host`
/// 2026-08-24 (design doc §1.1), verbatim apart from the upstream stanza a
/// config needs to validate at all.
///
/// The upstream address is RFC 5737 TEST-NET-1 rather than the host's real
/// one: warden ships no provider defaults (CLAUDE.md §Neutrality) and a
/// fixture is not a place to reintroduce one by habit.
///
/// **The `tags` arrays are gone, and the host's file still has them.** That
/// is not a drift: this fixture is parsed with bare `toml::from_str`,
/// deliberately outside the loader, so it is the shape **serde** must
/// accept — and `plp-s5a` removed the field from the schema. On disk the
/// key survives until an operator deletes it, and the loader strips it
/// before serde ever sees it, on both of its deserialise paths. That half
/// is pinned by `tests/plp_s5a_retired_tags_key.rs`, which is where it
/// belongs; carrying it here as well would make eleven tests about `lists`
/// overrides depend on the strip.
const ZIMA_SHAPE: &str = r#"
schema_version = 3

[upstream]
mode = "plain"
servers = ["192.0.2.1:53"]

[[blocklists]]
id = "security-malicious"
display_name = "Security: Malicious"
url = "https://lists.purge.cc/security/malicious.txt"

[[blocklists]]
id = "privacy-ads"
display_name = "Privacy: Ads"
url = "https://lists.purge.cc/privacy/ads.txt"

[[blocklists]]
id = "privacy-tracking"
display_name = "Privacy: Tracking"
url = "https://lists.purge.cc/privacy/tracking.txt"

[[blocklists]]
id = "content-gambling"
display_name = "Content: Gambling"
url = "https://lists.purge.cc/content/gambling.txt"

[profiles.default]

[profiles.kids]
"#;

// ── 1. back-compat: a config written before S2 is untouched by S2 ──

/// DoD #2. A config with no `lists` anywhere deserialises, and the profiles
/// come out **whole-value identical** to what the same TOML produced before
/// the field existed.
///
/// The comparison is deliberately against a complete `Profile` built with
/// `..Default::default()` rather than a series of field assertions. `Profile`
/// derives `PartialEq`, so this covers every field — including any added
/// after this test is written. A spot check of `display_name` and `tags`
/// would pass while a new field quietly changed `block_all`; this will not.
#[test]
fn plp_s2_pre_s2_config_deserialises_with_profiles_unchanged() {
    let cfg: ConfigV1 = toml::from_str(ZIMA_SHAPE).expect("the live host's shape must still parse");

    let expected_default = Profile {
        ..Default::default()
    };
    let expected_kids = Profile {
        ..Default::default()
    };

    assert_eq!(
        cfg.profiles.get("default"),
        Some(&expected_default),
        "the `default` profile must deserialise exactly as it did before S2"
    );
    assert_eq!(
        cfg.profiles.get("kids"),
        Some(&expected_kids),
        "the `kids` profile must deserialise exactly as it did before S2"
    );
}

/// The blocklist side of the same property: adding `ListPolicy` next to
/// `BlocklistBase` must not have disturbed how `kind` reads.
///
/// Pinned separately because the two types share a vocabulary and live in one
/// file — a rename or a stray `rename_all` edit on one is exactly the kind of
/// change that lands on the other by accident.
#[test]
fn plp_s2_pre_s2_config_leaves_blocklist_base_at_deny() {
    let cfg: ConfigV1 = toml::from_str(ZIMA_SHAPE).unwrap();
    assert_eq!(cfg.blocklists.len(), 4);
    for b in &cfg.blocklists {
        assert_eq!(
            b.base,
            purge_warden::config::schema::BlocklistBase::Deny,
            "list {} must still default to deny",
            b.id
        );
    }
}

/// And the whole pre-S2 config still passes validation — the new check must
/// not fire on a config that has no overrides to check.
///
/// This is the one that would catch a check written against the wrong
/// emptiness (e.g. iterating `blocklist_ids` and demanding an override for
/// each, rather than the other way round).
#[test]
fn plp_s2_pre_s2_config_still_validates() {
    let cfg: ConfigV1 = toml::from_str(ZIMA_SHAPE).unwrap();
    assert!(
        validate(&cfg, now()).is_ok(),
        "S2 must not make an existing config invalid: {:?}",
        validate(&cfg, now()).unwrap_err()
    );
}

// ── 2. the field exists under the name the design doc gives it ──

/// The wire name is `lists`, and the values are the three lowercase tokens.
///
/// **This is the test the absent-field one cannot be.** `Profile` carries
/// `#[serde(deny_unknown_fields)]`, so if the field were named anything else
/// this config fails to parse with `unknown field `lists``. Renaming the Rust
/// field (or adding a `#[serde(rename)]`) turns this red; the back-compat test
/// above stays green either way, which is precisely why both exist.
#[test]
fn plp_s2_lists_override_parses_under_its_documented_wire_name() {
    let src = format!(
        r#"{ZIMA_SHAPE}
[profiles.finance]
lists = {{ privacy-ads = "deny", privacy-tracking = "allow", content-gambling = "ignore" }}
"#
    );
    let cfg: ConfigV1 = toml::from_str(&src).expect("`lists` must be the wire name");
    let finance = cfg.profiles.get("finance").expect("profile present");

    assert_eq!(finance.lists.len(), 3);
    assert_eq!(
        finance.lists.get(&Id::new("privacy-ads").unwrap()),
        Some(&ListPolicy::Deny)
    );
    assert_eq!(
        finance.lists.get(&Id::new("privacy-tracking").unwrap()),
        Some(&ListPolicy::Allow)
    );
    assert_eq!(
        finance.lists.get(&Id::new("content-gambling").unwrap()),
        Some(&ListPolicy::Ignore)
    );
}

/// A profile that omits `lists` gets an empty map, and `lists = {}` written
/// out by hand deserialises to the same thing.
///
/// The two spellings being one state is what licenses the
/// `skip_serializing_if` on the field; if they ever diverge, that attribute
/// starts losing information and this test is where it shows.
#[test]
fn plp_s2_absent_and_explicitly_empty_lists_are_the_same_state() {
    let absent: ConfigV1 = toml::from_str(ZIMA_SHAPE).unwrap();
    let explicit: ConfigV1 = toml::from_str(&format!(
        r#"{ZIMA_SHAPE}
[profiles.empty-override]
lists = {{}}
"#
    ))
    .unwrap();

    assert!(absent.profiles["default"].lists.is_empty());
    assert!(explicit.profiles["empty-override"].lists.is_empty());
    assert_eq!(
        absent.profiles["default"].lists,
        explicit.profiles["empty-override"].lists
    );
}

/// An unknown direction token is refused rather than silently coerced.
///
/// The three-state vocabulary is the point of the model (design doc §2.1 P2);
/// a fourth token quietly reading as one of the three would be the same class
/// of silent-discard defect the workstream exists to remove.
#[test]
fn plp_s2_unknown_list_policy_token_is_refused() {
    let src = format!(
        r#"{ZIMA_SHAPE}
[profiles.finance]
lists = {{ privacy-ads = "redirect" }}
"#
    );
    let err = toml::from_str::<ConfigV1>(&src).unwrap_err();
    assert!(
        err.to_string().contains("unknown variant"),
        "expected an unknown-variant refusal, got: {err}"
    );
}

// ── 3. serialize side — pinned in both directions ──

/// An empty `lists` map is **not** emitted, so no operator's profile grows an
/// empty table on the next config-rewriting save.
///
/// Diverges deliberately from `accept_unsigned_allow`, which is always
/// serialised: a `false` there is a standing declaration about risk that must
/// stay legible; an empty override map declares nothing. See the field's
/// doc-comment for the full argument.
#[test]
fn plp_s2_empty_lists_is_not_serialised() {
    let p = Profile::default();
    let s = toml::to_string(&p).unwrap();
    // Keyed on the exact key, not on `contains("lists")`: that substring also
    // matches `custom_lists`, so the loose form reported this field's arrival
    // as a regression in a field it does not name. A needle that matches more
    // than the thing it is aimed at cannot report which one it found.
    let keys: Vec<&str> = s
        .lines()
        .filter_map(|l| l.split('=').next())
        .map(str::trim)
        .collect();
    assert!(
        !keys.contains(&"lists"),
        "an empty override map must not reach the operator's file, got:\n{s}"
    );
    assert!(
        !keys.contains(&"custom_lists"),
        "an empty mount list must not reach the operator's file either, got:\n{s}"
    );
}

/// The other direction for `custom_lists`: a non-empty mount list survives a
/// serialize/deserialize round-trip.
///
/// Without this, `skip_serializing_if` could be widened to skip everything and
/// the test above would still pass while an operator's mounts silently vanished
/// on the next config-rewriting save.
#[test]
fn a_non_empty_custom_lists_round_trips() {
    let p = Profile {
        custom_lists: vec![Id::new("minecraft").unwrap(), Id::new("homework").unwrap()],
        ..Default::default()
    };
    let s = toml::to_string(&p).unwrap();
    assert!(
        s.contains("custom_lists"),
        "the mounts must be emitted, got:\n{s}"
    );
    let back: Profile = toml::from_str(&s).unwrap();
    assert_eq!(
        back.custom_lists, p.custom_lists,
        "a save must not drop or reorder the operator's mounts"
    );
}

/// The other direction: a non-empty map survives a serialize/deserialize
/// round-trip intact.
///
/// Without this, `skip_serializing_if` could be widened to skip everything and
/// the test above would still pass while overrides silently vanished on save.
#[test]
fn plp_s2_non_empty_lists_round_trips() {
    let mut lists = BTreeMap::new();
    lists.insert(Id::new("privacy-ads").unwrap(), ListPolicy::Deny);
    lists.insert(Id::new("privacy-tracking").unwrap(), ListPolicy::Allow);
    lists.insert(Id::new("content-gambling").unwrap(), ListPolicy::Ignore);
    let p = Profile {
        display_name: "Finance".into(),
        lists,
        ..Default::default()
    };

    let s = toml::to_string(&p).expect("a Profile carrying overrides must serialise");
    let back: Profile = toml::from_str(&s).expect("and must read back");
    assert_eq!(back, p, "round-trip lost or altered the overrides:\n{s}");
}

// ── 4. the validator refuses an override naming a list that is not there ──

/// DoD #4. An id in `lists` that matches no `[[blocklists]]` entry is an
/// ERROR, and the message **names the id**.
///
/// Asserting only that validation failed would pass on any unrelated error in
/// the fixture; asserting the id appears is what ties the refusal to the
/// override. That matters more than usual here: the defect being repaired (E2)
/// is an operator intent accepted and discarded without a word, so a refusal
/// that does not say which word was wrong repeats half of it.
#[test]
fn plp_s2_validator_refuses_override_for_unknown_list() {
    let src = format!(
        r#"{ZIMA_SHAPE}
[profiles.finance]
lists = {{ no-such-list = "deny" }}
"#
    );
    let cfg: ConfigV1 = toml::from_str(&src).expect("schema-valid, cross-ref invalid");

    let errs = validate(&cfg, now()).expect_err("an unknown list id must refuse the config");
    let hit = errs
        .iter()
        .find(|e| matches!(e, ConfigError::CrossRefMiss(_)))
        .unwrap_or_else(|| panic!("expected a CrossRefMiss, got: {errs:?}"));

    let text = hit.to_string();
    assert!(
        text.contains("no-such-list"),
        "the refusal must name the unresolvable id, got: {text}"
    );
    assert!(
        text.contains("finance"),
        "the refusal must name the profile that carries it, got: {text}"
    );
    assert!(
        text.contains(PROFILE_LIST_POLICY_UNKNOWN_LIST_SUGGESTION),
        "the refusal must carry its repair suggestion, got: {text}"
    );
}

/// Every unknown id in one profile is reported, not just the first.
///
/// A loop that `break`s or a `find` would pass the single-id test above and
/// leave the operator fixing typos one reload at a time.
#[test]
fn plp_s2_validator_reports_every_unknown_list_not_just_the_first() {
    let src = format!(
        r#"{ZIMA_SHAPE}
[profiles.finance]
lists = {{ ghost-one = "deny", ghost-two = "allow", privacy-ads = "deny" }}
"#
    );
    let cfg: ConfigV1 = toml::from_str(&src).unwrap();
    let errs = validate(&cfg, now()).expect_err("two unknown ids must refuse the config");

    let joined = errs
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(joined.contains("ghost-one"), "missing ghost-one:\n{joined}");
    assert!(joined.contains("ghost-two"), "missing ghost-two:\n{joined}");
    assert!(
        !joined.contains("privacy-ads"),
        "the one id that DOES exist must not be reported:\n{joined}"
    );
}

/// The control arm. An override naming a list that **does** exist validates
/// clean.
///
/// Without this, a check that refused every override — or one that inverted
/// the `contains` — would pass every test above. This is the arm that makes
/// the two refusal tests mean "refuses the unknown" rather than "refuses".
///
/// **`plp-s4b`: the `allow` override moved onto a consented list, and the
/// reason is a real behaviour change, not test maintenance.** This arm used
/// to allow `privacy-ads`, which `ZIMA_SHAPE` declares with no `trust` key —
/// and `BlocklistTrust`'s default is `RemoteUnsigned`, not `Local`. S4b added
/// a load-time refusal for an `allow` override on a remote list whose row
/// carries no `accept_unsigned_allow`, so this config is now correctly
/// refused: the consent gate that already guarded `base = allow` at list
/// scope now also guards it at override scope.
///
/// The fix appends a consented list rather than editing `ZIMA_SHAPE`. That
/// const documents itself as the shape measured on the live host verbatim, so
/// adding an ack to it would have made its provenance a lie to keep a test
/// green — and the id it would have been added to is the one the assertion
/// above checks is *not* reported.
#[test]
fn plp_s2_validator_accepts_override_for_a_list_that_exists() {
    let src = format!(
        r#"{ZIMA_SHAPE}
[[blocklists]]
id = "vendor-allow"
display_name = "Consented allow-direction source"
url = "https://lists.purge.cc/vendor/allow.txt"
accept_unsigned_allow = true

[profiles.finance]
lists = {{ vendor-allow = "allow", content-gambling = "ignore" }}
"#
    );
    let cfg: ConfigV1 = toml::from_str(&src).unwrap();
    assert!(
        validate(&cfg, now()).is_ok(),
        "an override naming a real list must validate: {:?}",
        validate(&cfg, now()).unwrap_err()
    );
}

// ── 5. wire tokens round-trip (DoD #3, integration-level) ──

/// Every `ListPolicy` variant's `wire_str` token reads back as that variant,
/// observed from **outside** the crate.
///
/// The unit test in `config::schema::blocklist` walks the same variants; this
/// one exists because the values here travel through operator-authored TOML
/// and the re-export in `config::schema`, and a `pub(crate)` slip or a lost
/// re-export would break the operator path while the in-module test stayed
/// green.
#[test]
fn plp_s2_list_policy_wire_tokens_round_trip_from_outside_the_crate() {
    for p in [ListPolicy::Deny, ListPolicy::Allow, ListPolicy::Ignore] {
        let src = format!(
            r#"{ZIMA_SHAPE}
[profiles.probe]
lists = {{ privacy-ads = "{}" }}
"#,
            p.wire_str()
        );
        let cfg: ConfigV1 = toml::from_str(&src)
            .unwrap_or_else(|e| panic!("token {:?} is unreadable: {e}", p.wire_str()));
        assert_eq!(
            cfg.profiles["probe"].lists[&Id::new("privacy-ads").unwrap()],
            p,
            "token {:?} decoded to the wrong variant",
            p.wire_str()
        );
    }
}

// ── 6. the key is a validated `Id`, not a bare string ──

/// A malformed id in **key** position is refused at parse time.
///
/// Worth its own test because a map key is not deserialised the way a field
/// value is: `Id` is a parse-don't-validate newtype whose invariants come from
/// `Id::new` running inside its `Deserialize` impl, and a serde map-key
/// deserialiser that handed the key over as a borrowed `&str` without routing
/// through it would leave `BTreeMap<Id, _>` holding ids the charset forbids —
/// silently, since nothing downstream re-validates a type whose whole contract
/// is that it need not be re-validated.
///
/// `"Bad Id"` violates the charset twice (uppercase, space), so this cannot
/// pass for an unrelated reason.
#[test]
fn plp_s2_malformed_id_in_key_position_is_refused() {
    let src = format!(
        r#"{ZIMA_SHAPE}
[profiles.finance]
lists = {{ "Bad Id" = "deny" }}
"#
    );
    let err = toml::from_str::<ConfigV1>(&src).err().unwrap_or_else(|| {
        panic!("a map key must be validated as an Id, not accepted as a string")
    });
    assert!(
        err.to_string().contains("invalid character"),
        "expected the Id charset refusal, got: {err}"
    );
}
