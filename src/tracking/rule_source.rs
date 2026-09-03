//! Per-query attribution of WHICH layer matched.
//!
//! When the resolver chain + per-device overlay decide a query, the
//! winning rule belongs to one of three layers:
//!
//! - **Profile** (`||domain^` / `@@||domain^` admin rule listed in a
//!   `[profiles.<id>].admin_rules` reference). The profile id is what
//!   the operator sees in the query log.
//! - **Device** (`Device.allow_rules` / `Device.deny_rules` reference).
//!   The device id attribution lets the TUI Rules tab and the audit
//!   log reflect "this rule fired for THIS device, not the profile".
//! - **AdminBuiltin** — reserved for built-in safety rails (e.g.
//!   anti-bypass NXDOMAIN canaries shipped by the binary itself, never
//!   serialised to config). Not currently emitted; declared so a future
//!   producer can extend the enum without a wire-format break.
//!
//! Used by `crate::tracking` (query log + per-device stats),
//! `crate::profiles::resolver::apply_overlay` (which computes the source
//! as a side effect of its decision), and `crate::audit`, where every
//! `RuleAdd` / `RuleRemove` entry carries the source so an operator
//! post-hoc can tell who-allowed-what.
//!
//! `RuleSource` derives `Debug + Clone + PartialEq + Eq` but not `Hash` —
//! nothing keys a collection by `RuleSource` today. If a future module
//! needs it as a HashMap key, derive `Hash` then.

use crate::config::schema::Id;

/// Which layer of the resolver chain produced a matching rule for a
/// given (domain, device) query.
///
/// See module docs for the layer taxonomy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleSource {
    /// A `[[admin_rules]]` entry referenced by a `[profiles.<id>]`
    /// block matched. The carried `Id` is the profile id (NOT the
    /// admin_rule id) — that is the layer attribution the operator
    /// wants to see ("default profile blocked this", not "rule
    /// auto-block-abc12345 blocked this").
    Profile(Id),
    /// A `Device.allow_rules` / `Device.deny_rules` reference matched.
    /// The carried `Id` is the device id. This can also represent an
    /// `[OVERRIDE]` allow that beats a profile-level deny — the override
    /// marker rides separately on the audit entry, not on this enum.
    Device(Id),
    /// Reserved: built-in / anti-bypass rules shipped by the binary
    /// itself (no `[[admin_rules]]` row). Not currently emitted; kept on
    /// the enum so a future producer doesn't need a wire-format migration.
    AdminBuiltin,
}

impl RuleSource {
    /// Stable short label used by audit log + query log filtering. The
    /// label is intentionally compact — appears as a column header in
    /// `warden audit tail` output.
    pub fn as_label(&self) -> &'static str {
        match self {
            Self::Profile(_) => "profile",
            Self::Device(_) => "device",
            Self::AdminBuiltin => "admin-builtin",
        }
    }

    /// Borrowed access to the carried id, for callers that want to
    /// render the entity that owned the rule. `AdminBuiltin` returns
    /// `None` because there is no entity id (the rule is hard-coded).
    pub fn entity_id(&self) -> Option<&Id> {
        match self {
            Self::Profile(id) => Some(id),
            Self::Device(id) => Some(id),
            Self::AdminBuiltin => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_attribution_carries_profile_id() {
        let src = RuleSource::Profile(Id::new("default").unwrap());
        assert_eq!(src.as_label(), "profile");
        assert_eq!(src.entity_id().map(|i| i.as_str()), Some("default"));
    }

    #[test]
    fn device_attribution_carries_device_id() {
        let src = RuleSource::Device(Id::new("operator-iphone").unwrap());
        assert_eq!(src.as_label(), "device");
        assert_eq!(src.entity_id().map(|i| i.as_str()), Some("operator-iphone"));
    }

    #[test]
    fn admin_builtin_has_no_entity_id() {
        let src = RuleSource::AdminBuiltin;
        assert_eq!(src.as_label(), "admin-builtin");
        assert!(src.entity_id().is_none());
    }

    #[test]
    fn equality_is_per_layer_and_per_id() {
        let p1 = RuleSource::Profile(Id::new("default").unwrap());
        let p2 = RuleSource::Profile(Id::new("default").unwrap());
        let p3 = RuleSource::Profile(Id::new("kids").unwrap());
        let d1 = RuleSource::Device(Id::new("default").unwrap());
        assert_eq!(p1, p2);
        assert_ne!(p1, p3);
        assert_ne!(p1, d1, "Profile and Device with same id are distinct");
    }
}
