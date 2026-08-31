//! Operator-authored rule files declared as `[[custom_lists]]`.
//!
//! A custom list is a locally-authored `.txt` holding both allow and deny
//! rules. It is mounted on profiles and compiles into the same admin-rule
//! seat as `[[admin_rules]]` — it consumes no source bit and never crosses
//! the external-list parser, whose sandbox exists for third-party content
//! re-fetched on a timer. These files have neither property.

use serde::{Deserialize, Serialize};

use super::id::Id;

/// Default ceiling on a single pack file, in bytes.
///
/// Deliberately not shared with `lists.max_body_bytes`: that one governs a
/// remote body two orders of magnitude larger, and coupling them means an
/// operator tightening the list pipeline silently changes what their own
/// files are allowed to be.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 1024 * 1024;

/// Ceilings for the custom-list file reader.
///
/// The table is named `custom_list_limits`, not `custom_lists`: in TOML a
/// table and an array of tables sharing a name cannot coexist, and the
/// entity already owns `custom_lists`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CustomListLimits {
    #[serde(default = "default_max_file_bytes")]
    pub max_file_bytes: u64,
}

fn default_max_file_bytes() -> u64 {
    DEFAULT_MAX_FILE_BYTES
}

impl Default for CustomListLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
        }
    }
}

/// One operator-authored rule file.
///
/// There is no `file` field: the path is derived from the id, so an absolute
/// path, a `..` traversal, two entries sharing one file, a symlink out of the
/// config tree and a FIFO are not refused — they are unrepresentable.
///
/// There is no `enabled` field either: suspending a list means unmounting it
/// from the profile. A third way of not filtering, alongside "mounted by
/// nobody" and "empty", would need its own row state, badge and key.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CustomList {
    pub id: Id,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub description: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::ConfigV1;

    const MASTER: &str = r#"
schema_version = 1

[upstream]
servers = ["192.0.2.1:53"]

[custom_list_limits]
max_file_bytes = 2097152

[[custom_lists]]
id = "minecraft"
display_name = "Minecraft"
description = "Domains unblocked from the query log"

[profiles.kids]
custom_lists = ["minecraft"]
lists = { ads = "deny" }
"#;

    #[test]
    fn custom_list_limits_table_coexists_with_the_entity_array() {
        // `[custom_lists]` and `[[custom_lists]]` are the SAME name in TOML
        // and cannot coexist — a cap named `custom_lists.max_file_bytes`
        // would make every master carrying an entity unparseable.
        let cfg: ConfigV1 = toml::from_str(MASTER).expect("master must deserialise");
        assert_eq!(cfg.custom_list_limits.max_file_bytes, 2_097_152);
        assert_eq!(cfg.custom_lists.len(), 1);
        assert_eq!(cfg.custom_lists[0].id.as_str(), "minecraft");
    }

    #[test]
    fn the_colliding_table_name_is_rejected_by_the_parser() {
        // The negative half. Without it the test above passes for a build
        // that never had the collision hazard, and the name could drift
        // back to `custom_lists` unnoticed.
        let colliding = MASTER.replace("[custom_list_limits]", "[custom_lists]");
        let err = toml::from_str::<ConfigV1>(&colliding)
            .expect_err("a table and an array of tables sharing a name must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains("overwrite") || msg.contains("duplicate") || msg.contains("expected"),
            "unexpected refusal reason: {msg}"
        );
    }

    #[test]
    fn a_profile_carrying_both_custom_lists_and_lists_round_trips() {
        // Declaration order on `Profile` is load-bearing: TOML cannot emit
        // a bare value after a table in the same table, so `custom_lists`
        // (a value) must be declared before `lists` (a map). A round-trip
        // over a profile carrying only ONE of the two is green either way.
        let cfg: ConfigV1 = toml::from_str(MASTER).unwrap();
        let emitted = toml::to_string(&cfg).expect("serialise");
        let back: ConfigV1 = toml::from_str(&emitted).expect("emitted TOML must parse back");
        assert_eq!(
            back.profiles["kids"].custom_lists, cfg.profiles["kids"].custom_lists,
            "custom_lists was lost or misparsed on round-trip — check field order on Profile"
        );
        assert_eq!(back.profiles["kids"].lists, cfg.profiles["kids"].lists);
    }

    #[test]
    fn the_row_constructor_cannot_silently_drop_a_field() {
        // Trip-wire. `upsert_id_keyed` replaces a row outright (`*item = entry`),
        // so any field a TOML row builder omits is reset to its serde default
        // on the next save of ANY field. Today `CustomList` has three fields
        // and two of them are strings with harmless defaults, so the loss this
        // catches is small — which is the reason to write it now. The first
        // field without an innocuous default is the one that would cost, and
        // a trip-wire is not something you add after losing a field.
        let entry = CustomList {
            id: Id::new("minecraft").unwrap(),
            display_name: "Minecraft".to_string(),
            description: "d".to_string(),
        };
        let CustomList {
            id,
            display_name,
            description,
        } = &entry;
        assert_eq!(id.as_str(), "minecraft");
        assert_eq!(display_name, "Minecraft");
        assert_eq!(description, "d");
    }

    #[test]
    fn an_unknown_field_is_refused() {
        let bad = r#"id = "a"
display_name = "A"
colour = "red"
"#;
        toml::from_str::<CustomList>(bad)
            .expect_err("deny_unknown_fields must refuse an unknown key");
    }
}
