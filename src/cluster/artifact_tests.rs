use std::collections::BTreeMap;
use std::sync::Arc;

use crate::config::schema::{ConfigV5, Id};
use crate::config::target_v5::PackBodiesV5;
use crate::filter::operator_rules::{CompileAdmission, CompiledCostV1, RuleCompileLimits};

use super::artifact::{verify_objects, PolicySnapshot, ARTIFACT_NODE_LOCAL_SERVER_FIELDS};
use super::manifest::{digest, Manifest, ObjectRef, Requirements, RuleRequirements};

const ACTIVE: &str = concat!(
    "||exact.example.test^$important\n",
    "@@||*.allowed.example.test^$noapex\n",
    "||*.apex.example.test^\n",
    "/track[0-9]+\\.example\\.test/\n",
);
const DORMANT: &str = "||unmounted.example.test^\n";
const GOLDEN_HASH: &str = "50ba31ba3c833ff6ba47cf587dfd58790ca84e51ead2d42d67fd2618f8dc7aeb";
const GOLDEN_MANIFEST: &str = concat!(
    r#"{"artifact_format":2,"schema_version":5,"operator_rule_grammar":"1","compiled_cost_version":2,"primary_lineage":"1111111111111111111111111111111111111111111111111111111111111111","policy_epoch":7,"config_revision":"2222222222222222222222222222222222222222222222222222222222222222","operator_policy_hash":"3333333333333333333333333333333333333333333333333333333333333333","policy_toml":{"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","bytes":0},"packs":[],"mounts":{},"requirements":{"version":1,"compiler_version":1,"pack_bytes":0,"store":{"source_rules":0,"indexed":0,"advanced":0,"regex":0,"regex_source_bytes":0,"max_regex_source_bytes":0,"max_rule_bytes":0,"skipped_rows":0},"profiles":{},"packs":{}},"artifact_hash":""#,
    "50ba31ba3c833ff6ba47cf587dfd58790ca84e51ead2d42d67fd2618f8dc7aeb\"}",
);

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn fixture() -> (ConfigV5, PackBodiesV5) {
    let config: ConfigV5 = toml::from_str(
        r#"
schema_version = 5

[server]
default_profile = "default"

[upstream]
servers = ["192.0.2.1:53"]

[[custom_lists]]
id = "active"

[[custom_lists]]
id = "dormant"

[profiles.default]
custom_lists = ["active"]
"#,
    )
    .unwrap();
    let bodies = PackBodiesV5::new(BTreeMap::from([
        (id("active"), Arc::from(ACTIVE)),
        (id("dormant"), Arc::from(DORMANT)),
    ]));
    (config, bodies)
}

fn snapshot(revision: &str) -> PolicySnapshot {
    let (config, bodies) = fixture();
    PolicySnapshot::from_target_v5(&config, &bodies, revision.repeat(64)).unwrap()
}

fn publication(snapshot: &PolicySnapshot) -> (Manifest, BTreeMap<String, Arc<[u8]>>) {
    let candidate = snapshot.publication(&"1".repeat(64), 7).unwrap();
    let manifest = Manifest::decode(&candidate.manifest).unwrap();
    assert_eq!(candidate.artifact_hash, manifest.artifact_hash);
    assert_eq!(candidate.config_revision, manifest.config_revision);
    (manifest, candidate.objects)
}

fn resign(manifest: &mut Manifest) {
    manifest.artifact_hash = manifest.canonical_hash().unwrap();
}

fn assert_error<T>(result: anyhow::Result<T>, expected: &str) {
    let error = format!("{:#}", result.err().expect("mutation must be rejected"));
    assert!(error.contains(expected), "expected {expected:?}: {error}");
}

#[test]
fn snapshot_captures_unmounted_declarations_and_advanced_rule_accounting() {
    let snapshot = snapshot("2");
    let (manifest, objects) = publication(&snapshot);
    let recovered = verify_objects(&manifest, &objects).unwrap();

    assert_eq!(snapshot.declarations().len(), 2);
    assert_eq!(snapshot.packs().len(), 2);
    assert_eq!(recovered.custom_lists.len(), 2);
    assert_eq!(manifest.mounts["default"], [id("active")]);
    assert_eq!(
        snapshot.packs()[&id("dormant")].bytes.as_ref(),
        DORMANT.as_bytes()
    );
    assert_eq!(manifest.requirements.store.source_rules, 5);
    assert_eq!(manifest.requirements.store.indexed, 3);
    assert_eq!(manifest.requirements.store.advanced, 3);
    assert_eq!(manifest.requirements.store.regex, 1);
    assert_eq!(manifest.requirements.profiles["default"].advanced, 3);
    assert_eq!(manifest.requirements.packs["dormant"].indexed, 1);
}

#[test]
fn captured_bytes_and_publication_are_immutable_after_input_changes() {
    let snapshot = snapshot("2");
    let clone = snapshot.clone();
    let before = snapshot.publication(&"1".repeat(64), 7).unwrap();
    let (config, mut changed) = fixture();
    changed.insert(id("active"), Arc::from("||changed.example.test^\n"));
    let changed_snapshot =
        PolicySnapshot::from_target_v5(&config, &changed, "4".repeat(64)).unwrap();
    let retained = snapshot.publication(&"1".repeat(64), 7).unwrap();

    assert_eq!(
        snapshot.packs()[&id("active")].bytes.as_ref(),
        ACTIVE.as_bytes()
    );
    assert!(Arc::ptr_eq(
        &snapshot.packs()[&id("active")].bytes,
        &clone.packs()[&id("active")].bytes,
    ));
    assert_eq!(before.manifest, retained.manifest);
    assert_eq!(before.objects, retained.objects);
    assert_ne!(
        snapshot.config_revision(),
        changed_snapshot.config_revision()
    );
    assert_ne!(
        snapshot.operator_policy_hash(),
        changed_snapshot.operator_policy_hash()
    );
}

#[test]
fn target_snapshot_rejects_missing_extra_and_invalid_unmounted_bodies() {
    let (config, bodies) = fixture();
    let missing = PackBodiesV5::new(BTreeMap::from([(
        id("active"),
        Arc::clone(bodies.get(&id("active")).unwrap()),
    )]));
    assert_error(
        PolicySnapshot::from_target_v5(&config, &missing, "2".repeat(64)),
        "declaration roster",
    );
    let mut extra = bodies.clone();
    extra.insert(id("unknown"), Arc::from("||unknown.example.test^\n"));
    assert_error(
        PolicySnapshot::from_target_v5(&config, &extra, "2".repeat(64)),
        "declaration roster",
    );
    let mut invalid = bodies;
    invalid.insert(id("dormant"), Arc::from("/[ /\n"));
    assert!(PolicySnapshot::from_target_v5(&config, &invalid, "2".repeat(64)).is_err());
}

#[test]
fn artifact_toml_excludes_only_node_local_server_identity_fields() {
    let (mut config, bodies) = fixture();
    config.server.listen = "127.0.0.1:15354".parse().unwrap();
    config.server.log_level = "trace".into();
    config.server.tcp_timeout_secs = 37;
    config.server.enforce_device_mac = false;
    config.server.allow_from = vec!["192.0.2.0/24".into()];
    config.server.default_blocked_ttl_secs = 42;
    let snapshot = PolicySnapshot::from_target_v5(&config, &bodies, "2".repeat(64)).unwrap();
    let value: toml::Value = toml::from_str(std::str::from_utf8(snapshot.toml()).unwrap()).unwrap();
    let server = value["server"].as_table().unwrap();

    for field in ARTIFACT_NODE_LOCAL_SERVER_FIELDS {
        assert!(
            !server.contains_key(*field),
            "{field} leaked into artifact TOML"
        );
    }
    for field in [
        "enforce_device_mac",
        "allow_from",
        "default_profile",
        "default_block_response",
        "default_blocked_ttl_secs",
    ] {
        assert!(
            server.contains_key(field),
            "{field} missing from artifact TOML"
        );
    }
}

#[test]
fn verifier_rejects_forged_node_local_server_fields_before_defaults() {
    let (manifest, objects) = publication(&snapshot("2"));
    for (field, value) in [
        ("listen", "\"127.0.0.1:15354\""),
        ("log_level", "\"trace\""),
        ("tcp_timeout_secs", "37"),
    ] {
        let mut forged = manifest.clone();
        let mut forged_objects = objects.clone();
        forged_objects.remove(&forged.policy_toml.sha256);
        let toml = format!("schema_version = 5\n[server]\n{field} = {value}\n");
        forged.policy_toml = ObjectRef::of(toml.as_bytes());
        resign(&mut forged);
        forged_objects.insert(
            forged.policy_toml.sha256.clone(),
            Arc::from(toml.into_bytes()),
        );
        assert_error(
            verify_objects(&forged, &forged_objects),
            &format!("ArtifactNodeLocalLeak: server.{field}"),
        );
    }
}

#[test]
fn verifier_rejects_missing_extra_corrupt_and_wrong_size_objects() {
    let (manifest, objects) = publication(&snapshot("2"));
    for key in objects.keys() {
        let mut missing = objects.clone();
        missing.remove(key);
        assert_error(
            verify_objects(&manifest, &missing),
            "ArtifactInventoryMismatch",
        );

        let mut corrupt = objects.clone();
        let mut bytes = corrupt[key].to_vec();
        bytes[0] ^= 1;
        corrupt.insert(key.clone(), Arc::from(bytes));
        assert_error(
            verify_objects(&manifest, &corrupt),
            "ArtifactObjectMismatch",
        );
    }
    let mut extra = objects.clone();
    extra.insert(digest(b"unreferenced"), Arc::from(&b"unreferenced"[..]));
    assert_error(verify_objects(&manifest, &extra), "extra object");

    let mut wrong_size = manifest.clone();
    wrong_size.policy_toml.bytes += 1;
    resign(&mut wrong_size);
    assert_error(
        verify_objects(&wrong_size, &objects),
        "ArtifactObjectMismatch",
    );
}

#[test]
fn verifier_rejects_forged_requirements_and_semantic_hashes() {
    let (manifest, objects) = publication(&snapshot("2"));
    for scope in [
        "/requirements/store",
        "/requirements/profiles/default",
        "/requirements/packs/dormant",
    ] {
        for counter in ["source_rules", "indexed", "advanced", "regex"] {
            let mut value = serde_json::to_value(&manifest).unwrap();
            let field = value.pointer_mut(&format!("{scope}/{counter}")).unwrap();
            *field = serde_json::Value::from(field.as_u64().unwrap() + 1);
            let mut forged: Manifest = serde_json::from_value(value).unwrap();
            resign(&mut forged);
            assert_error(
                verify_objects(&forged, &objects),
                "ArtifactRequirementsMismatch",
            );
        }
    }
    let mut forged_hash = manifest;
    forged_hash.operator_policy_hash = "a".repeat(64);
    resign(&mut forged_hash);
    assert_error(
        verify_objects(&forged_hash, &objects),
        "ArtifactPolicyHashMismatch",
    );
}

#[test]
fn manifest_rejects_unknown_references_and_wire_fields() {
    let (manifest, objects) = publication(&snapshot("2"));
    let mut unknown = manifest.clone();
    let dormant = unknown
        .packs
        .iter_mut()
        .find(|pack| pack.id == id("dormant"))
        .unwrap();
    dormant.id = id("unknown");
    let counts = unknown.requirements.packs.remove("dormant").unwrap();
    unknown.requirements.packs.insert("unknown".into(), counts);
    resign(&mut unknown);
    unknown.validate().unwrap();
    assert_error(verify_objects(&unknown, &objects), "declarations");

    for pointer in [
        "",
        "/policy_toml",
        "/packs/0",
        "/requirements",
        "/requirements/store",
        "/requirements/profiles/default",
        "/requirements/packs/active",
    ] {
        let mut value = serde_json::to_value(&manifest).unwrap();
        value
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("future_field".into(), true.into());
        assert_error(
            Manifest::decode(&serde_json::to_vec(&value).unwrap()),
            "unknown field",
        );
    }
}

#[test]
fn manifest_format2_encoding_and_domain_separated_hash_match_golden() {
    let manifest = Manifest {
        artifact_format: 2,
        schema_version: 5,
        operator_rule_grammar: "1".into(),
        compiled_cost_version: CompiledCostV1::VERSION,
        primary_lineage: "1".repeat(64),
        policy_epoch: 7,
        config_revision: "2".repeat(64),
        operator_policy_hash: "3".repeat(64),
        policy_toml: ObjectRef::of(b""),
        packs: Vec::new(),
        mounts: BTreeMap::new(),
        requirements: Requirements {
            version: 1,
            compiler_version: 1,
            pack_bytes: 0,
            store: RuleRequirements::default(),
            profiles: BTreeMap::new(),
            packs: BTreeMap::new(),
        },
        artifact_hash: GOLDEN_HASH.into(),
    };
    assert_eq!(manifest.canonical_hash().unwrap(), GOLDEN_HASH);
    assert_eq!(manifest.encode().unwrap(), GOLDEN_MANIFEST.as_bytes());
    assert_eq!(
        Manifest::decode(GOLDEN_MANIFEST.as_bytes()).unwrap(),
        manifest
    );
    let duplicated = GOLDEN_MANIFEST.replace(
        "\"policy_epoch\":7,",
        "\"policy_epoch\":7,\"policy_epoch\":7,",
    );
    assert_error(Manifest::decode(duplicated.as_bytes()), "duplicate field");
    let mut changed = manifest;
    changed.policy_epoch += 1;
    assert_ne!(changed.canonical_hash().unwrap(), GOLDEN_HASH);
    assert_error(changed.validate(), "ArtifactHashMismatch");
}

#[test]
fn receiver_admission_keeps_its_lease_until_the_compiled_snapshot_drops() {
    let (manifest, objects) = publication(&snapshot("2"));
    let limits = RuleCompileLimits::default();
    let admission = CompileAdmission::new(limits.max_compiled_bytes_total, 1).unwrap();
    let compiled = super::admission::admit(&manifest, &objects, &limits, &admission).unwrap();
    assert!(admission.reserved_bytes() > 0);
    assert_eq!(admission.active_builds(), 0);
    drop(compiled);
    assert_eq!(admission.reserved_bytes(), 0);
    assert_eq!(admission.active_builds(), 0);
}
