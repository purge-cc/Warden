//! Retired **schema keys** — TOML keys a shipped config may still carry
//! for a field the product no longer has.
//!
//! Distinct from [`super::retired`], which quarantines retired entity
//! **ids**. This module is about the *shape* of the file: a key that used
//! to deserialise into a struct field and now deserialises into nothing.
//!
//! # Why this exists at all
//!
//! Every one of the five entity structs (`Blocklist`, `Profile`, `Device`,
//! `Group`, `Subnet`) carries `#[serde(deny_unknown_fields)]`. That is
//! deliberate — a typo'd key is refused instead of silently ignored — but
//! it makes field *removal* a breaking change for configs already on disk:
//! the minute the field goes, `unknown field `tags`` refuses the whole
//! load and the daemon does not start.
//!
//! `plp-s5a` removed `tags` from all five. The remedy is the
//! `ip_denylists` shape already used by
//! `config::loader::normalise_deprecated_keys`: strip the retired key from
//! the raw [`toml::Table`] **before serde sees it**, and tell the operator.
//! The alternative shape in that same function — the `kind` arm, which
//! *refuses* rather than rewrites — is the wrong one here: `tags` decided
//! nothing after the `plp-s3` cutover, so dropping it changes no verdict,
//! and a refusal would be exactly the outage this module exists to prevent.
//!
//! # Both loader exits, or neither
//!
//! The loader has **two** deserialise sites and they do not share one:
//!
//! * the multi-file merge (`loader.rs`) feeds serde the merged, already
//!   normalised table — a strip in `normalise_deprecated_keys` covers it;
//! * the single-file fast path **re-parses the raw bytes** through
//!   [`super::load::load_from_str_collect`], so it never observes the
//!   normalised table at all.
//!
//! The shipped layout is single-file, so a strip wired only into the
//! loader would test green on a multi-file fixture and brick every real
//! install. Both call [`strip_retired_tag_keys`] — the same function, so
//! the two paths cannot disagree about what a config means.

/// Entity sections whose entries are TOML **arrays of tables**.
///
/// `clients` is the pre-S42 spelling of `devices`. It is listed because
/// `ConfigV1` still accepts it via `#[serde(alias = "clients")]`, so a
/// config reaching serde through the single-file path can carry
/// `[[clients]]` with a `tags` key on it and never pass through the
/// loader's `clients` → `devices` rename.
const ARRAY_SECTIONS: [&str; 5] = ["blocklists", "devices", "clients", "groups", "subnets"];

/// The retired key itself.
const RETIRED_TAGS_KEY: &str = "tags";

/// The retired `[[labels]]` kind.
///
/// A **second** brick, on a different channel from the `tags` key and one
/// step easier to miss. `LabelKind` is a serde enum, so deleting its `Tag`
/// variant does not make `kind = "tag"` an ignorable unknown *field* — it
/// makes it an unknown *variant*, and serde refuses the load for it
/// whether or not the struct denies unknown fields.
///
/// `kind = "tag"` shipped on 2026-08-08 and was retired on 2026-08-26, so
/// the window in which an operator could have declared one is short but
/// real — and a config that does not load is the same outage regardless of
/// how few rows caused it.
///
/// The **whole row** goes, not a key inside it: a label is a
/// (kind, id) pair, and a row stripped of its kind is not a label. Warden
/// does not guess a replacement kind — that would be warden deciding what
/// the operator meant.
const RETIRED_LABEL_KIND: &str = "tag";

/// Remove every retired `tags` key from `table`, returning the entity
/// paths that carried one (e.g. `blocklists.social`, `profiles.kids`).
///
/// An empty return means the config is already clean — the steady state
/// after `warden migrate`, and the state of every fresh install.
///
/// Entries are identified by their `id` where they have one so the note
/// names something the operator can find in their file; array entries
/// without an `id` fall back to their index.
pub fn strip_retired_tag_keys(table: &mut toml::Table) -> Vec<String> {
    let mut stripped = Vec::new();

    for section in ARRAY_SECTIONS {
        let Some(entries) = table.get_mut(section).and_then(|v| v.as_array_mut()) else {
            continue;
        };
        for (idx, entry) in entries.iter_mut().enumerate() {
            let Some(entry_table) = entry.as_table_mut() else {
                continue;
            };
            if entry_table.remove(RETIRED_TAGS_KEY).is_some() {
                let label = entry_table
                    .get("id")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned)
                    .unwrap_or_else(|| idx.to_string());
                stripped.push(format!("{section}.{label}"));
            }
        }
    }

    // `[[labels]] kind = "tag"` — the row, not a key inside it.
    if let Some(labels) = table.get_mut("labels").and_then(|v| v.as_array_mut()) {
        let mut kept = Vec::with_capacity(labels.len());
        for (idx, entry) in labels.iter().enumerate() {
            let is_retired_kind = entry
                .as_table()
                .and_then(|t| t.get("kind"))
                .and_then(|v| v.as_str())
                == Some(RETIRED_LABEL_KIND);
            if is_retired_kind {
                let label = entry
                    .as_table()
                    .and_then(|t| t.get("id"))
                    .and_then(|v| v.as_str())
                    .map(str::to_owned)
                    .unwrap_or_else(|| idx.to_string());
                stripped.push(format!("labels.{label}"));
            } else {
                kept.push(entry.clone());
            }
        }
        if kept.len() != labels.len() {
            *labels = kept;
        }
    }

    // `[profiles.<id>]` is a named map, not an array — the key IS the id.
    if let Some(profiles) = table.get_mut("profiles").and_then(|v| v.as_table_mut()) {
        for (name, value) in profiles.iter_mut() {
            let Some(profile_table) = value.as_table_mut() else {
                continue;
            };
            if profile_table.remove(RETIRED_TAGS_KEY).is_some() {
                stripped.push(format!("profiles.{name}"));
            }
        }
    }

    stripped
}

/// Cheap pre-check: could `src` carry a retired `tags` key at all?
///
/// Exists so the single-file fast path keeps its byte-identical,
/// span-preserving `toml::from_str::<ConfigV1>` parse for every config
/// that does *not* carry the retired key — which is every config after a
/// `warden migrate v2-to-v3`, and every fresh install. Only a file that
/// still has one pays the table round-trip (and the weaker error spans
/// that come with it).
///
/// Deliberately conservative: it matches the *key* position (`tags`
/// followed by optional whitespace and `=`) but does not attempt to know
/// which table the key sits in, and it does not exclude comments. A false
/// positive costs one extra parse; a false negative would cost the daemon
/// its start, so the asymmetry runs the safe way.
///
/// The preceding-byte guard is what keeps `retired_tags = …` and
/// `inherited_tags = …` from matching: both end in `tags` but are a
/// different key.
///
/// **A quoted key counts.** TOML lets a key be written `"tags" = [...]`
/// or `'tags' = [...]`, and serde resolves all three spellings to the same
/// field — so [`strip_retired_tag_keys`] finds it either way, because it
/// works on the parsed table. A scan that only matched the bare form would
/// have skipped the slow path on exactly such a file, and skipping it here
/// is the daemon refusing to start. The asymmetry is the reason to be
/// generous: a spurious match costs one parse.
pub fn src_may_carry_retired_tag_key(src: &str) -> bool {
    // A `kind = "tag"` label row is the other thing this gate must let
    // through. It has no `tags` key, so the key scan below cannot see it.
    if src.contains("\"tag\"") || src.contains("'tag'") {
        return true;
    }
    let bytes = src.as_bytes();
    let mut from = 0usize;
    while let Some(rel) = src[from..].find(RETIRED_TAGS_KEY) {
        let start = from + rel;
        let end = start + RETIRED_TAGS_KEY.len();
        let preceded_by_ident = start > 0 && is_bare_key_byte(bytes[start - 1]);
        if !preceded_by_ident {
            let mut i = end;
            // An optional closing quote, for `"tags" = …` / `'tags' = …`.
            if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
                i += 1;
            }
            while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
                i += 1;
            }
            if i < bytes.len() && bytes[i] == b'=' {
                return true;
            }
        }
        from = end;
    }
    false
}

/// Bytes TOML allows inside a bare key. Used only to decide whether a
/// `tags` match is the whole key or the tail of a longer one.
fn is_bare_key_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table_of(src: &str) -> toml::Table {
        toml::from_str(src).expect("fixture parses as a table")
    }

    /// The two entities both shipped hosts actually carry tags on
    /// (`[[blocklists]]` and `[profiles.<id>]`) must both be stripped, and
    /// the note must name them by id.
    #[test]
    fn blocklist_and_profile_tags_are_stripped_and_named() {
        let mut t = table_of(
            r#"
[[blocklists]]
id = "social"
tags = ["uncategorized"]

[profiles.kids]
display_name = "Kids"
tags = ["ads", "tracking"]
"#,
        );
        let stripped = strip_retired_tag_keys(&mut t);
        assert_eq!(stripped, vec!["blocklists.social", "profiles.kids"]);
        assert!(!t["blocklists"][0].as_table().unwrap().contains_key("tags"));
        assert!(!t["profiles"]["kids"]
            .as_table()
            .unwrap()
            .contains_key("tags"));
        // Everything else is untouched — the strip is surgical, not a
        // section rewrite.
        assert_eq!(t["blocklists"][0]["id"].as_str(), Some("social"));
        assert_eq!(t["profiles"]["kids"]["display_name"].as_str(), Some("Kids"));
    }

    /// All five entity shapes, plus the pre-S42 `[[clients]]` spelling
    /// that `ConfigV1` still accepts via serde alias.
    #[test]
    fn every_entity_shape_including_the_clients_alias_is_covered() {
        let mut t = table_of(
            r#"
[[blocklists]]
id = "b"
tags = ["x"]

[[devices]]
id = "d"
tags = ["x"]

[[clients]]
id = "c"
tags = ["x"]

[[groups]]
id = "g"
tags = ["x"]

[[subnets]]
id = "s"
tags = ["x"]

[profiles.p]
tags = ["x"]
"#,
        );
        let stripped = strip_retired_tag_keys(&mut t);
        assert_eq!(
            stripped,
            vec![
                "blocklists.b",
                "devices.d",
                "clients.c",
                "groups.g",
                "subnets.s",
                "profiles.p",
            ]
        );
        for section in ["blocklists", "devices", "clients", "groups", "subnets"] {
            assert!(
                !t[section][0].as_table().unwrap().contains_key("tags"),
                "{section} still carries the retired key"
            );
        }
        assert!(!t["profiles"]["p"].as_table().unwrap().contains_key("tags"));
    }

    /// A clean config must report nothing — the note is what tells the
    /// operator to migrate, so it must not fire on a file that is already
    /// on the new model.
    #[test]
    fn a_clean_config_strips_nothing() {
        let mut t = table_of(
            r#"
[[blocklists]]
id = "social"
base = "deny"

[profiles.kids]
display_name = "Kids"
lists = { social = "allow" }
"#,
        );
        assert!(strip_retired_tag_keys(&mut t).is_empty());
    }

    /// The pre-check gates the slow path, so a miss is an outage. Pin both
    /// directions, and pin the two neighbouring keys that end in `tags`
    /// and must NOT trigger it.
    #[test]
    fn pre_check_matches_the_key_and_not_its_lookalikes() {
        assert!(src_may_carry_retired_tag_key("tags = [\"a\"]"));
        assert!(src_may_carry_retired_tag_key("  tags=[\"a\"]"));
        assert!(src_may_carry_retired_tag_key(
            "[profiles.p]\nlists = { a = \"deny\" }\ntags = []"
        ));
        // Inline-table form — `profiles.p = { tags = [...] }`.
        assert!(src_may_carry_retired_tag_key("p = { tags = [\"a\"] }"));
        // Quoted keys. TOML allows all three spellings and serde resolves
        // them to one field, so `strip_retired_tag_keys` would find these —
        // a pre-check that missed them would skip the strip on exactly the
        // file that needs it, and that is the daemon not starting.
        assert!(src_may_carry_retired_tag_key("\"tags\" = [\"a\"]"));
        assert!(src_may_carry_retired_tag_key("'tags' = [\"a\"]"));
        assert!(src_may_carry_retired_tag_key("  \"tags\"   = []"));

        assert!(!src_may_carry_retired_tag_key("retired_tags = [\"a\"]"));
        assert!(!src_may_carry_retired_tag_key("inherited_tags = [\"a\"]"));
        // A bare mention with no `=` after it is not a key.
        assert!(!src_may_carry_retired_tag_key("# tags used to live here"));
        assert!(!src_may_carry_retired_tag_key(
            "display_name = \"tags are gone\""
        ));
        assert!(!src_may_carry_retired_tag_key(""));
    }

    /// A retired `kind = "tag"` label row is dropped whole, and its
    /// neighbours are not. Serde would refuse the whole config over the
    /// unknown variant, so a missed row here is an outage, not a warning.
    #[test]
    fn a_retired_tag_label_row_is_dropped_and_its_neighbours_kept() {
        let mut t = table_of(
            r#"
[[labels]]
id = "alex"
kind = "owner"
display_name = "Alex"

[[labels]]
id = "ads"
kind = "tag"
display_name = "Ads"

[[labels]]
id = "famiglia"
kind = "department"
display_name = "Famiglia"
"#,
        );
        let stripped = strip_retired_tag_keys(&mut t);
        assert_eq!(stripped, vec!["labels.ads"]);
        let rows = t["labels"].as_array().unwrap();
        assert_eq!(
            rows.iter()
                .map(|r| r["id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["alex", "famiglia"],
            "the surrounding vocabulary must survive intact"
        );
    }

    /// And the pre-check must route such a config down the stripping path
    /// even though it carries no `tags` key at all.
    #[test]
    fn pre_check_sees_a_tag_label_row_with_no_tags_key() {
        assert!(src_may_carry_retired_tag_key(
            "[[labels]]\nid = \"ads\"\nkind = \"tag\"\n"
        ));
    }

    /// A `tags` key on something that is not an entity table must be left
    /// alone: the strip is scoped to the five sections, not to the name.
    #[test]
    fn a_tags_key_outside_the_entity_sections_is_left_alone() {
        let mut t = table_of(
            r#"
[server]
tags = ["not-ours"]
"#,
        );
        assert!(strip_retired_tag_keys(&mut t).is_empty());
        assert!(t["server"].as_table().unwrap().contains_key("tags"));
    }
}
