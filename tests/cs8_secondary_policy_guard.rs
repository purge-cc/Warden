//! CS8 — a cluster secondary refuses policy edits.
//!
//! `cluster_sync.md:126-130` promises a frozen refusal; until this suite
//! landed, grepping `src/` for it returned zero hits. What existed was a set
//! of side effects that happen to point the same way — no list refresh, the
//! reload early-return, and (since S2) the loader-level
//! `CLUSTER_SECONDARY_MASTER_CARRIES_POLICY` check — not an enforcement at
//! the write path.
//!
//! **The choke point under test is `promote_validated`, reached through BOTH
//! public validating writers.** The compound test below is the one that fails
//! if the guard is ever moved onto `write_value_validated`: `rule add` /
//! `remove` / `move` and `tags rename` stage several policy files in one
//! mutation and reach `promote_validated` via `write_values_validated`,
//! which never calls the singular writer.
//!
//! Ungated on purpose. `[cluster]` parses on every build
//! (`config::schema::cluster`) and `REPLICATED_SECTIONS` is always compiled,
//! so the guard — and this suite — must behave identically with and without
//! `--features cluster`. The `apply.rs` carve-out is the one test that needs
//! the feature; it lives in `tests/cs8_apply_carveout.rs`.

use std::path::Path;

use purge_warden::cli::commands::target::{
    write_value_validated, write_values_validated, StagedWrite,
};

// ── fixtures ────────────────────────────────────────────────────────────
//
// RFC 5737 TEST-NET-1/TEST-NET-3 only — never a real provider (neutrality).

/// 64 hex chars: a `token_hash` shaped the way `cluster join` writes one.
const TOKEN_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// The primary this secondary points at. Load-bearing: the refusal names it,
/// so the operator learns WHERE the edit belongs.
const PEER: &str = "https://192.0.2.10:8053";

/// A secondary's master, shaped per §5.3: the node-local keep-list and
/// nothing else. Policy arrives in `cluster.d/`.
fn secondary_master(enabled: bool) -> String {
    format!(
        r#"schema_version = 3
includes = ["cluster.d/*.toml", "devices.d/*.toml", "profiles.d/*.toml"]

[server]
listen = "127.0.0.1:15353"
default_profile = "default"

[api]
token_hash = ""

[cluster]
enabled = {enabled}
role = "secondary"
peer = "{PEER}"
token_hash = "{TOKEN_HASH}"
"#
    )
}

/// The policy bundle as the poll loop would have installed it. Supplies
/// everything §5.3 forbids the secondary's own master from carrying.
///
/// Deliberately carries no `[server]`: split-merging that singleton across the
/// master and the drop-in is `#[cfg(feature = "cluster")]`
/// (`loader::SPLIT_MERGE_SINGLETONS`), so a bundle declaring it is a hard
/// `DuplicateId` in the DEFAULT build. This suite must behave identically in
/// both feature configs, so the fixture keeps `[server]` in one file.
const BUNDLE: &str = r#"[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#;

/// A primary's master: authoritative, carries its own policy.
const PRIMARY_MASTER: &str = r#"schema_version = 3
includes = ["devices.d/*.toml", "profiles.d/*.toml"]

[server]
listen = "127.0.0.1:15353"
default_profile = "default"

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]

[api]
token_hash = ""

[cluster]
enabled = true
role = "primary"
token_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"#;

/// A stand-alone node that is not clustered at all, but whose `role` still
/// reads `secondary`. `enabled` is the load-bearing conjunct — mirrors the S2
/// precedent in `validator::policy_arrives_from_a_primary`.
const DISABLED_SECONDARY_MASTER: &str = r#"schema_version = 3
includes = ["devices.d/*.toml", "profiles.d/*.toml"]

[server]
listen = "127.0.0.1:15353"
default_profile = "default"

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]

[cluster]
enabled = false
role = "secondary"
peer = "https://192.0.2.10:8053"
"#;

/// One `[[devices]]` slice — an unambiguously POLICY write.
const DEVICE_SLICE: &str = r#"[[devices]]
id = "tablet"
display_name = "Tablet"
ip = "192.0.2.50"
"#;

/// One `[profiles.*]` slice — the second half of a compound policy mutation.
const PROFILE_SLICE: &str = r#"[profiles.extra]
display_name = "Extra"
"#;

struct Node {
    _dir: tempfile::TempDir,
    master: std::path::PathBuf,
}

impl Node {
    /// `master_toml` is written raw: these fixtures deliberately model states
    /// a validating writer would refuse to CREATE but must still be able to
    /// read (a secondary's master is not loadable without its bundle), which
    /// is exactly what a real `join` produces. Same exemption the in-crate
    /// cluster tests take; `scripts/check_no_raw_fs_write.sh` scans `src/`
    /// only, so nothing here is in its scope either way.
    fn new(master_toml: &str, bundle: Option<&str>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("config.toml");
        std::fs::write(&master, master_toml).unwrap();
        if let Some(bundle) = bundle {
            let dropin = dir.path().join("cluster.d");
            std::fs::create_dir_all(&dropin).unwrap();
            std::fs::write(dropin.join("00-cluster-policy.toml"), bundle).unwrap();
        }
        Node { _dir: dir, master }
    }

    fn secondary() -> Self {
        Node::new(&secondary_master(true), Some(BUNDLE))
    }

    fn slice(&self, rel: &str) -> std::path::PathBuf {
        self.master.parent().unwrap().join(rel)
    }

    /// Stage `content` at `rel` through the SINGLE-file validating writer.
    fn write_one(&self, rel: &str, content: &str) -> anyhow::Result<()> {
        let path = self.slice(rel);
        write_value_validated(&self.master, &path, &toml_value(content))
    }

    /// Stage several files through the COMPOUND writer — the seat that never
    /// touches `write_value_validated`.
    fn write_many(&self, files: &[(&str, &str)]) -> anyhow::Result<()> {
        let writes: Vec<StagedWrite> = files
            .iter()
            .map(|(rel, content)| StagedWrite {
                final_path: self.slice(rel),
                content: (*content).to_string(),
            })
            .collect();
        write_values_validated(&self.master, &writes)
    }
}

fn toml_value(content: &str) -> toml::Value {
    toml::from_str(content).expect("fixture parses as TOML")
}

/// The refusal must be recognisable as CS8's and not some other bail.
fn assert_is_cs8_refusal(err: &anyhow::Error) {
    let msg = err.to_string();
    assert!(
        msg.contains("policy is read-only on a cluster secondary"),
        "expected the CS8 refusal, got: {msg}"
    );
}

fn assert_absent(path: &Path) {
    assert!(
        !path.exists(),
        "a refused write must leave nothing behind: {} exists",
        path.display()
    );
}

// ── the guard ───────────────────────────────────────────────────────────

/// CS8 — a secondary refuses a POLICY write.
#[test]
fn a_secondary_refuses_a_policy_write() {
    let node = Node::secondary();
    let err = node
        .write_one("devices.d/tablet.toml", DEVICE_SLICE)
        .expect_err("a secondary must refuse a [[devices]] write");
    assert_is_cs8_refusal(&err);
    assert_absent(&node.slice("devices.d/tablet.toml"));
}

/// The refusal names the primary, so the operator learns where the edit
/// belongs rather than only that it is forbidden here.
#[test]
fn the_refusal_names_the_primary() {
    let node = Node::secondary();
    let err = node
        .write_one("devices.d/tablet.toml", DEVICE_SLICE)
        .expect_err("refused");
    let msg = err.to_string();
    assert!(msg.contains(PEER), "refusal must name the peer, got: {msg}");
    assert!(
        msg.contains("devices"),
        "refusal must name the offending section, got: {msg}"
    );
}

/// …and still permits its NODE-LOCAL ones. `cluster join` / `leave` must keep
/// working and `server.listen` is the secondary's own. A guard that blocks
/// these has bricked the node's own administration — and `leave` is the verb
/// an operator uses to RESCUE a stuck node.
#[test]
fn a_secondary_still_permits_a_cluster_and_listen_write() {
    let node = Node::secondary();

    // `server.listen` — the one field of a REPLICATED section that a
    // secondary's master owns (`REPLICATED_BUT_ALLOWED_IN_A_SECONDARY_MASTER`).
    let relisten = secondary_master(true).replace("127.0.0.1:15353", "127.0.0.1:15354");
    write_value_validated(&node.master, &node.master, &toml_value(&relisten))
        .expect("a secondary must keep control of its own server.listen");

    // `[cluster]` — node-local identity. This is the shape `join`/`leave`
    // produce; they bypass this path today, and the guard must not become the
    // reason they cannot be routed through it.
    let renamed = secondary_master(true).replace(
        "role = \"secondary\"",
        "role = \"secondary\"\nnode_name = \"second\"",
    );
    write_value_validated(&node.master, &node.master, &toml_value(&renamed))
        .expect("a secondary must keep control of its own [cluster] section");
}

/// The guard covers the COMPOUND writer too.
///
/// **This is the test that fails if the guard is placed on
/// `write_value_validated`.** `write_values_validated` is a direct call to
/// `promote_validated` — it never touches the singular writer — and it is the
/// seat used by `rule add` / `remove` / `move` and `tags rename`, precisely
/// the mutations that touch several policy files at once.
#[test]
fn a_secondary_refuses_a_compound_multi_file_policy_write() {
    let node = Node::secondary();
    let err = node
        .write_many(&[
            ("devices.d/tablet.toml", DEVICE_SLICE),
            ("profiles.d/extra.toml", PROFILE_SLICE),
        ])
        .expect_err("a secondary must refuse a compound policy write");
    assert_is_cs8_refusal(&err);
    assert_absent(&node.slice("devices.d/tablet.toml"));
    assert_absent(&node.slice("profiles.d/extra.toml"));
}

/// A write INTO the sync-owned drop-in is refused too.
///
/// This is the case S2's loader check structurally cannot see: it filters
/// `is_cluster_drop_in`, so policy written there passes validation, lands,
/// and is silently overwritten by the next sync. CS8 is the only thing
/// standing in front of it.
#[test]
fn a_secondary_refuses_a_write_into_the_sync_owned_drop_in() {
    let node = Node::secondary();
    let err = node
        .write_one("cluster.d/01-local.toml", DEVICE_SLICE)
        .expect_err("a secondary must refuse a policy write into cluster.d/");
    assert_is_cs8_refusal(&err);
    assert_absent(&node.slice("cluster.d/01-local.toml"));
}

/// A PRIMARY is unaffected.
#[test]
fn a_primary_permits_every_policy_write() {
    let node = Node::new(PRIMARY_MASTER, None);
    node.write_one("devices.d/tablet.toml", DEVICE_SLICE)
        .expect("a primary is authoritative for its own policy");
    let second = DEVICE_SLICE
        .replace("tablet", "phone")
        .replace("Tablet", "Phone")
        .replace("192.0.2.50", "192.0.2.51");
    node.write_many(&[
        ("devices.d/second.toml", second.as_str()),
        ("profiles.d/extra.toml", PROFILE_SLICE),
    ])
    .expect("a primary is authoritative for compound policy writes too");
}

/// `enabled` is the load-bearing conjunct, exactly as in S2's
/// `policy_arrives_from_a_primary`. A node that merely *says*
/// `role = "secondary"` while clustering is off is a standalone warden and
/// owns its policy.
#[test]
fn a_node_with_clustering_disabled_is_unaffected_whatever_its_role() {
    let node = Node::new(DISABLED_SECONDARY_MASTER, None);
    node.write_one("devices.d/tablet.toml", DEVICE_SLICE)
        .expect("clustering is off — this node owns its policy");
}

/// A master with no `[cluster]` section at all is a standalone node.
#[test]
fn a_master_with_no_cluster_section_is_unaffected() {
    let master = DISABLED_SECONDARY_MASTER
        .split("[cluster]")
        .next()
        .unwrap()
        .to_string();
    let node = Node::new(&master, None);
    node.write_one("devices.d/tablet.toml", DEVICE_SLICE)
        .expect("no [cluster] section — standalone");
}

// ── the frozen string ───────────────────────────────────────────────────

/// Pinned byte-for-byte. The template, not the substituted result — the same
/// idiom as `CLUSTER_ALLOW_PEER_INVALID_CIDR` in
/// `tests/frozen_strings_cluster.rs`.
///
/// The shape is deliberate and is NOT free to reorder. `promote_validated`'s
/// error reaches the TUI's fixed 2-row band (~105 usable cells, ellipsised —
/// see the comment at the `bail!` in `target.rs`, and the incident it
/// records). The actionable half — *where* the edit belongs, and the peer's
/// URL — must land inside those cells; the section list is the part that can
/// afford to fall off the end, because the operator already knows what they
/// typed.
#[test]
fn cs8_refusal_is_frozen_byte_for_byte() {
    assert_eq!(
        purge_warden::cli::commands::target::CLUSTER_SECONDARY_POLICY_READ_ONLY,
        "policy is read-only on a cluster secondary — edit it on the primary ({peer}); \
         it arrives at the next sync. Nothing written. Sections: {sections}"
    );
    assert_eq!(
        purge_warden::cli::commands::target::CLUSTER_PEER_UNSET,
        "`cluster.peer` unset"
    );
}

/// The actionable half must fit the band it is rendered in. A regression here
/// is silent: the string still says the right thing, the operator just never
/// sees it.
#[test]
fn the_actionable_half_of_the_refusal_fits_the_tui_band() {
    let template = purge_warden::cli::commands::target::CLUSTER_SECONDARY_POLICY_READ_ONLY;
    let head = template
        .split_once("{peer}")
        .expect("template names the peer")
        .0;
    let prefix_cells = head.chars().count() + PEER.chars().count() + 1;
    assert!(
        prefix_cells <= 105,
        "'…{{peer}})' occupies {prefix_cells} cells; the TUI band ellipsises past ~105"
    );
}
