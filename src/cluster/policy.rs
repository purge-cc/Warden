//! Cluster policy bundle (CS3) — the replicated §3.1 sections of [`ConfigV1`].
//!
//! The primary re-serialises only its *policy* sections into a normalised
//! `cluster-policy.toml`. Every node-local section/field (doc §3.2) is EXCLUDED
//! **by construction**: [`ClusterPolicyBundle`] is a partial-`ConfigV1` mirror
//! that simply has no field for `listen`, `log_level`, `tcp_timeout_secs`,
//! `[api]`, `[socket]`, `[cluster]`, `[tracking]`, `[resource_budget]`,
//! `[backup]`, or `includes` — so a leak is a compile-time impossibility, not a
//! runtime filter that could silently regress.
//!
//! **That guarantee is real and it is only half of the problem — the missing
//! half cost us `[[labels]]`.** "No field" makes a *leak* (node-local flowing
//! OUT) impossible. It says nothing about an *omission* (policy failing to flow
//! out), which is silent by exactly the same mechanism:
//! [`ClusterPolicyBundle::from_config`] copies field by field, so a section
//! nobody adds simply never replicates, and every test in this module was
//! *negative* — asserting node-local sentinels do NOT appear — which can never
//! observe a positive that is absent.
//!
//! `[[labels]]` landed after this struct was written, and the bundle shipped
//! carrying blocklists, devices and profiles that *reference* tags without the
//! vocabulary declaring them. The trip-wire for the whole class now lives in
//! `config::schema::tests::every_config_section_is_classified_replicated_or_node_local`
//! — deliberately **outside** this feature-gated module, so it fires in the
//! default build where `src/cluster/` does not even compile.
//!
//! `[server]` is the one mixed section. [`ClusterServerPolicy`] carries only the
//! five policy fields (doc §3.1) and never the three identity fields. Field
//! names + `#[serde(default)]` mirror [`crate::config::schema::ServerGlobals`] exactly so the emitted
//! `[server]` table reparses straight into a real `ServerGlobals` on the
//! secondary (the three absent keys fall back to that node's own defaults,
//! which the §4.11-3 merge then overlays with the node's master).
//!
//! Note: like [`ConfigV1`] itself, this struct cannot derive `PartialEq` — the
//! pass-through legacy types (`UpstreamConfig`, `CacheConfig`, …) don't
//! implement it. Equality in tests is asserted on `to_toml()` output, the same
//! idiom `config::schema` documents.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::schema::{
    AdminRule, BlockResponseV1, Blocklist, ConfigV1, Device, Group, Id, Label, Profile,
    RetiredEntry, Schedule, Subnet,
};
use crate::config::settings::{
    AntiBypassConfig, CacheConfig, DnssecConfig, ForwardingZoneConfig, IpBlocklistConfig,
    ListsConfig, LocalDnsConfig, SecurityConfig, UpstreamConfig,
};

/// The policy-only fields of `ServerGlobals` (doc §3.1). The identity fields
/// (`listen`, `log_level`, `tcp_timeout_secs`) are intentionally absent — they
/// are node-local (doc §3.2) and must never cross the wire. Field order matches
/// `ServerGlobals` so the TOML key order (and therefore the content hash) is
/// stable and the scalar-before-table TOML grammar constraint is preserved.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterServerPolicy {
    /// Defaults via the SAME function as the schema
    /// ([`crate::config::schema::default_enforce_device_mac`]), not via
    /// `bool::default()`.
    ///
    /// A bare `#[serde(default)]` here resolved to `false` while the real
    /// schema default is `true`, so a bundle carrying a present-but-partial
    /// `[server]` table silently turned MAC enforcement OFF. The manual
    /// `impl Default` below does say `true`, but serde only consults it when
    /// `[server]` is missing **entirely** — which is why the two disagreed
    /// without either looking wrong on its own (spec §10).
    #[serde(default = "crate::config::schema::default_enforce_device_mac")]
    pub enforce_device_mac: bool,
    #[serde(default)]
    pub allow_from: Vec<String>,
    #[serde(default)]
    pub default_profile: Option<Id>,
    #[serde(default)]
    pub default_block_response: BlockResponseV1,
    #[serde(default)]
    pub default_blocked_ttl_secs: u32,
}

/// The replicated §3.1 policy sections of a loaded [`ConfigV1`], serialised to a
/// single normalised `cluster-policy.toml`. Field order follows `ConfigV1` so
/// the emitted document is `ConfigV1`-shaped (the secondary reparses it as one)
/// and the content hash is deterministic.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterPolicyBundle {
    pub schema_version: u32,
    #[serde(default)]
    pub server: ClusterServerPolicy,
    #[serde(default)]
    pub retired: Vec<RetiredEntry>,
    #[serde(default)]
    pub blocklists: Vec<Blocklist>,
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
    #[serde(default)]
    pub devices: Vec<Device>,
    #[serde(default)]
    pub groups: Vec<Group>,
    #[serde(default)]
    pub subnets: Vec<Subnet>,
    #[serde(default)]
    pub schedules: Vec<Schedule>,
    #[serde(default)]
    pub admin_rules: Vec<AdminRule>,
    /// §4.66 L1 — the controlled vocabulary for tag slugs and the device
    /// metadata fields.
    ///
    /// **Replicated, and it was not until S2.** The bundle already carries
    /// blocklists, devices and profiles that *reference* tags; without the
    /// declarations the secondary receives references to a vocabulary it does
    /// not have. The entity landed after this struct was written and nothing
    /// forced the omission to be noticed — [`ClusterPolicyBundle::from_config`]
    /// copies field by field, so a missing field is silent, and every existing
    /// test here is negative (see `the_bundle_replicates_the_label_vocabulary`).
    ///
    /// Field order follows [`ConfigV1`] so the emitted document stays
    /// `ConfigV1`-shaped and the content hash stays deterministic.
    #[serde(default)]
    pub labels: Vec<Label>,
    #[serde(default)]
    pub upstream: UpstreamConfig,
    #[serde(default)]
    pub dnssec: DnssecConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub anti_bypass: AntiBypassConfig,
    #[serde(default)]
    pub forwarding: Vec<ForwardingZoneConfig>,
    #[serde(default)]
    pub local_dns: LocalDnsConfig,
    #[serde(default)]
    pub ip_blocklists: IpBlocklistConfig,
    #[serde(default)]
    pub lists: ListsConfig,
}

impl Default for ClusterServerPolicy {
    fn default() -> Self {
        Self {
            enforce_device_mac: true,
            allow_from: Vec::new(),
            default_profile: None,
            default_block_response: BlockResponseV1::default(),
            default_blocked_ttl_secs: 60,
        }
    }
}

impl ClusterPolicyBundle {
    /// Extract the §3.1 policy sections from a loaded config. Clones the
    /// sections (policy is KB–low-MB) — only run on reload, never on the hot
    /// path.
    ///
    /// The clause "cheap relative to the separately-shipped domain map" was
    /// removed with S1: nothing is shipped alongside this any more, so the
    /// comparison had no second term left.
    #[must_use]
    pub fn from_config(config: &ConfigV1) -> Self {
        let s = &config.server;
        Self {
            schema_version: config.schema_version,
            server: ClusterServerPolicy {
                enforce_device_mac: s.enforce_device_mac,
                allow_from: s.allow_from.clone(),
                default_profile: s.default_profile.clone(),
                default_block_response: s.default_block_response,
                default_blocked_ttl_secs: s.default_blocked_ttl_secs,
            },
            retired: config.retired.clone(),
            blocklists: config.blocklists.clone(),
            profiles: config.profiles.clone(),
            devices: config.devices.clone(),
            groups: config.groups.clone(),
            subnets: config.subnets.clone(),
            schedules: config.schedules.clone(),
            admin_rules: config.admin_rules.clone(),
            labels: config.labels.clone(),
            upstream: config.upstream.clone(),
            dnssec: config.dnssec.clone(),
            cache: config.cache.clone(),
            security: config.security.clone(),
            anti_bypass: config.anti_bypass.clone(),
            forwarding: config.forwarding.clone(),
            local_dns: config.local_dns.clone(),
            ip_blocklists: config.ip_blocklists.clone(),
            lists: config.lists.clone(),
        }
    }

    /// Serialise to the normalised `cluster-policy.toml` document.
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string(self)
    }

    /// SHA-256 (hex) of a serialised bundle — the CS4 config content hash. The
    /// robust cross-restart change signal (the generation counter resets on
    /// restart; the hash does not).
    #[must_use]
    pub fn hash_of(toml_str: &str) -> String {
        hex::encode(Sha256::digest(toml_str.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Test-only: `LabelKind` is named by the vocabulary test below and by
    // nothing in the production path, so importing it at module scope would
    // be dead in the non-test lib build (`clippy --all-targets` catches the
    // lib target too, not just the test one).
    use crate::config::schema::LabelKind;

    /// Build a config with both policy sections populated AND every node-local
    /// field set to a distinctive sentinel, so the leak test can assert on the
    /// sentinel values (more robust than grepping field names).
    fn sample_config() -> ConfigV1 {
        let mut c = ConfigV1 {
            schema_version: 3,
            ..Default::default()
        };
        // ── policy (must survive) ──
        c.server.allow_from = vec!["192.0.2.0/24".to_string()];
        c.server.enforce_device_mac = true;
        c.server.default_blocked_ttl_secs = 90;
        // ── node-local (must NOT appear) ──
        c.server.listen = "203.0.113.7:5399".parse().unwrap();
        c.server.log_level = "trace-NODELOCAL".to_string();
        c.server.tcp_timeout_secs = 4242;
        c.api.enabled = true;
        c.api.token_hash = Some("APITOKENSENTINEL".to_string());
        c.cluster.enabled = true;
        c.cluster.token_hash = Some("CLUSTERTOKENSENTINEL".to_string());
        c.includes = vec!["INCLUDESENTINEL/*.toml".to_string()];
        c
    }

    #[test]
    fn bundle_round_trips_via_toml() {
        let bundle = ClusterPolicyBundle::from_config(&sample_config());
        let toml1 = bundle.to_toml().unwrap();
        let reparsed: ClusterPolicyBundle = toml::from_str(&toml1).unwrap();
        let toml2 = reparsed.to_toml().unwrap();
        // ConfigV1-family types lack PartialEq — compare on serialised form.
        assert_eq!(toml1, toml2);
    }

    #[test]
    fn bundle_reparses_as_configv1() {
        // Proves the bundle is ConfigV1-shaped, i.e. the §4.11-3 secondary can
        // load it through the normal loader.
        let toml = ClusterPolicyBundle::from_config(&sample_config())
            .to_toml()
            .unwrap();
        let _cfg: ConfigV1 = toml::from_str(&toml).unwrap();
    }

    #[test]
    fn bundle_excludes_every_node_local_field() {
        let toml = ClusterPolicyBundle::from_config(&sample_config())
            .to_toml()
            .unwrap();
        // No node-local *value* leaks (sentinels chosen to be unique).
        for needle in [
            "203.0.113.7",
            "5399",
            "trace-NODELOCAL",
            "4242",
            "APITOKENSENTINEL",
            "CLUSTERTOKENSENTINEL",
            "INCLUDESENTINEL",
        ] {
            assert!(
                !toml.contains(needle),
                "node-local value `{needle}` leaked into bundle:\n{toml}"
            );
        }
        // No node-local *section headers* leak (CS3 proof, mirrors CT-smoke grep).
        for header in [
            "[api]",
            "[socket]",
            "[cluster]",
            "[tracking]",
            "[resource_budget]",
            "[backup]",
            "includes",
            "listen",
            "log_level",
            "tcp_timeout",
        ] {
            assert!(
                !toml.contains(header),
                "node-local section/key `{header}` leaked into bundle:\n{toml}"
            );
        }
    }

    #[test]
    fn policy_fields_survive() {
        let toml = ClusterPolicyBundle::from_config(&sample_config())
            .to_toml()
            .unwrap();
        assert!(
            toml.contains("[server]"),
            "policy [server] missing:\n{toml}"
        );
        assert!(toml.contains("192.0.2.0/24"), "allow_from lost:\n{toml}");
        assert!(
            toml.contains("enforce_device_mac"),
            "policy field lost:\n{toml}"
        );
        assert!(
            toml.contains("default_blocked_ttl_secs"),
            "policy field lost:\n{toml}"
        );
    }

    #[test]
    fn fence_rejects_node_local_sections() {
        // apply-01: the consume-side fence. `deny_unknown_fields` means a
        // received bundle carrying ANY node-local section/field fails to parse
        // as a ClusterPolicyBundle — so it can never be staged into cluster.d.
        for hostile in [
            "schema_version = 3\n[api]\ntoken_hash = \"attacker\"\nenabled = true\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
            "schema_version = 3\nincludes = [\"/etc/passwd\"]\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
            "schema_version = 3\n[socket]\npath = \"/run/evil.sock\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
            "schema_version = 3\n[cluster]\nrole = \"primary\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
            "schema_version = 3\n[server]\nlisten = \"0.0.0.0:53\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
        ] {
            assert!(
                toml::from_str::<ClusterPolicyBundle>(hostile).is_err(),
                "node-local config must be fenced out, but parsed:\n{hostile}"
            );
        }
    }

    #[test]
    fn fence_accepts_a_legit_policy_bundle() {
        // The exact document the primary emits must still round-trip.
        let toml = ClusterPolicyBundle::from_config(&sample_config())
            .to_toml()
            .unwrap();
        toml::from_str::<ClusterPolicyBundle>(&toml)
            .expect("a primary-emitted bundle must reparse under the fence");
    }

    #[test]
    fn hash_is_deterministic() {
        let b = ClusterPolicyBundle::from_config(&sample_config());
        let t = b.to_toml().unwrap();
        assert_eq!(
            ClusterPolicyBundle::hash_of(&t),
            ClusterPolicyBundle::hash_of(&t)
        );
        assert_eq!(ClusterPolicyBundle::hash_of(&t).len(), 64);
    }

    /// §4.1 — the vocabulary must ride along with the entities that cite it.
    ///
    /// The bundle already replicates blocklists, devices and profiles that
    /// **reference** a label vocabulary; before S2 it carried no
    /// `[[labels]]`, so the secondary received the references without the
    /// declarations. (This test was written against `LabelKind::Tag`, which
    /// the tag eradication removed; the property is about `labels` being
    /// copied at all, so any surviving variant exercises it.)
    ///
    /// The existing tests in this module could not catch that. They are all
    /// *negative* — they assert node-local sentinels do NOT leak into the
    /// bundle — and a negative test never sees a missing positive. That
    /// asymmetry is the whole lesson: the module doc calls a leak "a
    /// compile-time impossibility", which is true, and says nothing about an
    /// omission, which is silent.
    #[test]
    fn the_bundle_replicates_the_label_vocabulary() {
        let mut c = sample_config();
        c.labels = vec![Label {
            id: Id::new("kids").expect("valid id"),
            kind: LabelKind::Department,
            display_name: "Kids".to_string(),
            description: None,
        }];

        let bundle = ClusterPolicyBundle::from_config(&c);
        assert_eq!(
            bundle.labels.len(),
            1,
            "from_config must copy `labels`; it copies field by field, so an \
             omission here is silent by construction"
        );

        let toml = bundle.to_toml().expect("bundle serialises");
        let back: ClusterPolicyBundle = toml::from_str(&toml).expect("bundle round-trips");
        assert_eq!(
            back.labels.len(),
            1,
            "the vocabulary must survive the wire, not merely the struct"
        );
        assert_eq!(back.labels[0].display_name, "Kids");
    }

    /// §10 — a bundle whose `[server]` table is PRESENT but omits
    /// `enforce_device_mac` must default it to **true**, matching the schema.
    ///
    /// The field carried a bare `#[serde(default)]`, i.e. `bool::default()` =
    /// `false`, while `ServerGlobals` defaults it via
    /// `default_enforce_device_mac()` = `true`. The manual
    /// `impl Default for ClusterServerPolicy` does say `true`, but it only
    /// applies when `[server]` is absent **entirely** — a present-but-partial
    /// table falls through to the field default instead.
    ///
    /// Our own `from_config` always writes the key, so this is not reachable in
    /// everyday operation; the realistic trigger is **version skew** (a bundle
    /// from a primary that predates the field) or a hand-edited bundle. Small
    /// blast radius, wrong direction: a missing key must not silently disable
    /// MAC enforcement.
    #[test]
    fn a_bundle_server_table_missing_enforce_device_mac_defaults_it_on() {
        let toml = r#"
schema_version = 3

[server]
allow_from = []
"#;
        let b: ClusterPolicyBundle =
            toml::from_str(toml).expect("a bundle with a partial [server] parses");
        assert!(
            b.server.enforce_device_mac,
            "a MISSING key must not turn MAC enforcement off"
        );
    }
}
