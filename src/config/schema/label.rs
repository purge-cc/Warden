//! [`Label`] — the declared vocabulary for the free-form device metadata
//! fields `owner`, `device_type` and `department` (§4.66 L1).
//!
//! §4.66 L1. The problem is measurable on the live deployment, not
//! hypothetical: a census of the two household CTs found 26 metadata
//! assignments across 16 devices carrying `department = "Personal"`
//! *and* `department = "Persona"` — a near-duplicate born of a typo —
//! plus a `device_type` that was really the name of one device. Nothing
//! in the schema could notice, because all three fields are
//! `Option<String>` that no resolver ever reads.
//!
//! A `[[labels]]` entry declares one legal value in one dimension. It is
//! **advisory, not referential**:
//!
//! - [`Device::owner`](super::device::Device::owner),
//!   [`device_type`](super::device::Device::device_type) and
//!   [`department`](super::device::Device::department) stay
//!   `Option<String>`. Promoting them to `Option<Id>` would make every
//!   config on disk unloadable — `"Operator"` and `"Apple TV"` are not
//!   valid [`Id`]s, and the boxes holding those values serve real
//!   household DNS.
//! - A value outside the vocabulary still loads. The validator emits
//!   [`DEVICE_METADATA_UNKNOWN_LABEL`](super::validator::DEVICE_METADATA_UNKNOWN_LABEL)
//!   as a WARN and the daemon continues.
//! - Nothing is ever rewritten on the operator's behalf. No
//!   normalisation, no adoption of legacy spellings — the validator
//!   reports, the operator decides.
//!
//! # The `tag` kind is gone — `plp-s5a`
//!
//! `kind = "tag"` was a fifth[^1] vocabulary that declared a tag *name*.
//! It shipped 2026-08-08 and was removed with the rest of the tag model:
//! the thing it named a vocabulary *for* — a `tags` array on five entity
//! types — no longer exists, so a declaration of one could only ever be
//! inert. Direction is now a per-profile, per-list property
//! (`profiles.<id>.lists`), and it needs no name registry: the ids it
//! joins on are the blocklist ids the operator already declared.
//!
//! [^1]: fourth variant, but the fifth thing the module ever governed —
//! it was rejected on 2026-08-05, reinstated on 2026-08-06, and retired
//! on 2026-08-26.
//!
//! Removing it made [`LabelKind::device_field`] total again. It had been
//! widened to `Option` for the single reason that a tag was not a device
//! field; with the variant gone the `None` arm was unreachable in every
//! caller, and an `Option` whose `None` cannot occur is an invitation to
//! `unwrap_or` a plausible-looking default (`tui/label_modal.rs` had one).
//!
//! The three metadata kinds are the opposite case: no derived
//! vocabulary is possible for them, because a free-form string that
//! nothing reads leaves no trace to derive from. The registry is the
//! only source there can be.
//!
//! The consumers of this vocabulary are the CLI (`warden label …`) and,
//! in a later sprint, the TUI pickers that will offer these values
//! instead of asking the operator to retype them.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use super::super::error::{ConfigError, ErrorContext};
use super::id::Id;

/// The dimension a [`Label`] belongs to.
///
/// Serialised in kebab-case, so `LabelKind::DeviceType` is `"device-type"`
/// in TOML — matching the `--kind` values the CLI accepts.
///
/// All three are the same kind of thing: an inert `Option<String>` on
/// [`Device`](super::device::Device) that no resolver reads. There was a
/// fourth, `Tag`, and it was the exception in exactly one place —
/// [`Self::device_field`] had to return `Option` for it. `plp-s5a`
/// removed it with the rest of the tag model, and the enum is
/// homogeneous again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LabelKind {
    /// Vocabulary for [`Device::owner`](super::device::Device::owner).
    Owner,
    /// Vocabulary for
    /// [`Device::device_type`](super::device::Device::device_type).
    DeviceType,
    /// Vocabulary for
    /// [`Device::department`](super::device::Device::department).
    Department,
}

impl LabelKind {
    /// Every kind, in declaration order. The order is the one
    /// `warden label list` groups by, so it is also the order the
    /// operator reads the vocabulary in.
    pub const ALL: [LabelKind; 3] = [
        LabelKind::Owner,
        LabelKind::DeviceType,
        LabelKind::Department,
    ];

    /// The kebab-case wire form — identical in TOML, on the CLI, and in
    /// operator-facing messages.
    pub fn as_str(self) -> &'static str {
        match self {
            LabelKind::Owner => "owner",
            LabelKind::DeviceType => "device-type",
            LabelKind::Department => "department",
        }
    }

    /// The `[[devices]]` field this kind supplies values for.
    ///
    /// **Total again since `plp-s5a`, and the totality is the claim:**
    /// every kind is a device-metadata dimension. It was widened to
    /// `Option` when `LabelKind::Tag` falsified that — a tag lived in
    /// `tags` arrays on five entity types, not in one scalar on
    /// [`Device`](super::device::Device) — and narrowed back when the
    /// variant went. Every caller's `None` arm was unreachable by then;
    /// one of them (`tui/label_modal.rs`) had already picked a
    /// plausible-looking default for it, which is the failure the
    /// `Option` was meant to prevent and instead invited.
    ///
    /// Used by the validator to name the offending field in
    /// [`DEVICE_METADATA_UNKNOWN_LABEL`](super::validator::DEVICE_METADATA_UNKNOWN_LABEL),
    /// and by `warden label remove` to find the devices still using a
    /// label.
    pub fn device_field(self) -> &'static str {
        match self {
            LabelKind::Owner => "owner",
            LabelKind::DeviceType => "device_type",
            LabelKind::Department => "department",
        }
    }

    /// The kinds as a comma-separated list, for error messages that have
    /// to enumerate the valid values.
    pub fn valid_values() -> String {
        Self::ALL
            .iter()
            .map(|k| k.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl fmt::Display for LabelKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for LabelKind {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|k| k.as_str() == s)
            .ok_or_else(|| {
                ConfigError::UnknownVariant(
                    ErrorContext::new(format!("unknown label kind \"{s}\""))
                        .with_entity("labels.kind")
                        .with_suggestion(format!("use one of: {}", Self::valid_values())),
                )
            })
    }
}

/// One declared value in one vocabulary dimension.
///
/// ```toml
/// [[labels]]
/// id           = "operator"
/// kind         = "owner"
/// display_name = "Operator"
/// description  = "Dispositivi personali"
/// ```
///
/// Identity is the **pair** `(kind, id)`, not `id` alone: `personal` may
/// exist as a `department` and as a `device-type` at the same time, and
/// the two are unrelated entries. The validator enforces uniqueness on
/// the pair (R1); every CLI verb that selects a single label therefore
/// accepts an optional `--kind` to disambiguate.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Label {
    /// Stable identifier, unique within its [`Self::kind`].
    pub id: Id,
    /// Which vocabulary this entry belongs to.
    pub kind: LabelKind,
    /// The value as a human writes it. This is also what the metadata
    /// fields on `[[devices]]` are matched against — a device with
    /// `owner = "Operator"` is inside the vocabulary if some `owner`
    /// label has either that `id` or that `display_name`, so declaring
    /// the vocabulary never forces a mass rewrite of existing configs.
    pub display_name: String,
    /// Free-form note explaining why this label exists.
    ///
    /// **Inert at runtime**, and that is still the important half:
    /// nothing on the query path reads it — not the resolver, not the
    /// filter engine, not the stats. It exists so the operator who
    /// declared a label six months ago can recall what they meant.
    ///
    /// **Write-only again since `plp-s5a`.** It briefly was not: the Tags
    /// tab carried the description of every `kind = "tag"` row onto
    /// `TagUsage`, so it reached that table's NOTE column and
    /// `warden tags list --json`. Both readers left with the tag model,
    /// and the only surface echoing it back is `warden label show` once
    /// more. Recorded rather than reverted to the older wording, because
    /// "nothing reads it" is the claim a future session would use to
    /// justify dropping the field, and it has been false once already.
    #[serde(default)]
    pub description: Option<String>,
}

impl Label {
    /// Does this label declare `value` as written on a device?
    ///
    /// Matches the [`Self::id`] **or** the [`Self::display_name`],
    /// exactly and case-sensitively. Accepting the display name is the
    /// whole reason declaring a vocabulary does not force a mass rewrite:
    /// the live configs hold `owner = "Operator"`, which can never equal
    /// an [`Id`] (uppercase), so an id-only rule would WARN on every
    /// device that is already correct and push the operator toward
    /// exactly the bulk edit this feature is meant to avoid.
    ///
    /// Case-sensitive on purpose. The defect this vocabulary exists to
    /// surface is `"Personal"` vs `"Persona"` — a pair that stays
    /// distinct under any case folding — so fuzzier matching would
    /// dilute the check without catching anything more.
    ///
    /// Every kind has a [`device_field`](LabelKind::device_field), so
    /// this is meaningful for all of them. That was not true while
    /// `LabelKind::Tag` existed — a tag was never carried as a device
    /// metadata string — and the caveat that stood here went with the
    /// variant in `plp-s5a`.
    pub fn matches_value(&self, value: &str) -> bool {
        self.id.as_str() == value || self.display_name == value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_label_deserialises() {
        let l: Label = toml::from_str(
            r#"
id = "operator"
kind = "owner"
display_name = "Operator"
"#,
        )
        .unwrap();
        assert_eq!(l.id.as_str(), "operator");
        assert_eq!(l.kind, LabelKind::Owner);
        assert_eq!(l.display_name, "Operator");
        assert!(l.description.is_none());
    }

    #[test]
    fn full_label_deserialises() {
        let l: Label = toml::from_str(
            r#"
id = "operator"
kind = "owner"
display_name = "Operator"
description = "Dispositivi personali"
"#,
        )
        .unwrap();
        assert_eq!(l.description.as_deref(), Some("Dispositivi personali"));
    }

    /// The wire spelling is kebab-case. A config written with the Rust
    /// variant name (`DeviceType`) or with snake_case must not parse —
    /// the CLI, the TOML, and the operator docs all say `device-type`.
    #[test]
    fn kind_wire_form_is_kebab_case() {
        let l: Label = toml::from_str(
            r#"
id = "laptop"
kind = "device-type"
display_name = "Laptop"
"#,
        )
        .unwrap();
        assert_eq!(l.kind, LabelKind::DeviceType);

        for bad in ["device_type", "DeviceType", "deviceType"] {
            let src = format!("id = \"laptop\"\nkind = \"{bad}\"\ndisplay_name = \"Laptop\"\n");
            assert!(
                toml::from_str::<Label>(&src).is_err(),
                "kind = \"{bad}\" must not parse — the wire form is kebab-case"
            );
        }
    }

    #[test]
    fn unknown_kind_rejected() {
        let err = toml::from_str::<Label>(
            r#"
id = "x"
kind = "colour"
display_name = "X"
"#,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("colour") || err.to_string().contains("unknown variant"),
            "got: {err}"
        );
    }

    #[test]
    fn unknown_field_rejected() {
        let err = toml::from_str::<Label>(
            r#"
id = "x"
kind = "owner"
display_name = "X"
colour = "red"
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field"), "got: {err}");
    }

    /// `id` routes through `Id`'s validation at deserialise time, so an
    /// uppercase or dash-led id is refused at load rather than becoming
    /// a vocabulary entry no picker can round-trip.
    #[test]
    fn invalid_id_rejected() {
        for bad in ["Operator", "-operator", "operator-", "edo ardo"] {
            let src = format!("id = \"{bad}\"\nkind = \"owner\"\ndisplay_name = \"E\"\n");
            assert!(
                toml::from_str::<Label>(&src).is_err(),
                "id = \"{bad}\" must not parse"
            );
        }
    }

    #[test]
    fn kind_round_trips_through_from_str() {
        for k in LabelKind::ALL {
            assert_eq!(LabelKind::from_str(k.as_str()).unwrap(), k);
        }
    }

    #[test]
    fn from_str_error_lists_every_valid_value() {
        let err = LabelKind::from_str("colour").unwrap_err().to_string();
        for k in LabelKind::ALL {
            assert!(
                err.contains(k.as_str()),
                "the error must name {k}, so the operator can fix it without \
                 opening the docs. got: {err}"
            );
        }
    }

    #[test]
    fn matches_the_id_and_the_display_name_but_nothing_else() {
        let l: Label =
            toml::from_str("id = \"operator\"\nkind = \"owner\"\ndisplay_name = \"Operator\"\n")
                .unwrap();
        assert!(l.matches_value("operator"));
        assert!(l.matches_value("Operator"));
        // Case folding is deliberately absent: `Personal` vs `Persona`
        // is the defect being hunted, and no folding would merge those.
        assert!(!l.matches_value("OPERATOR"));
        assert!(!l.matches_value("edoard"));
    }

    #[test]
    fn serialises_back_to_kebab_case() {
        let l: Label =
            toml::from_str("id = \"tv\"\nkind = \"device-type\"\ndisplay_name = \"TV\"\n").unwrap();
        let out = toml::to_string(&l).unwrap();
        assert!(out.contains("kind = \"device-type\""), "got: {out}");
    }
}
