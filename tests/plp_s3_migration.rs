//! `warden migrate v2-to-v3` against the two configs that actually exist.
//!
//! `_docs/features/profile_list_policy.md` §5 asks for the migration to be
//! proved on the real shapes, not on a fixture written to make it pass. Both
//! live hosts were read on 2026-08-24 and committed here sanitised:
//! `tests/fixtures/plp_v2_{zima,proxmox}.toml` — 14 and 15 blocklists, 2 and
//! 1 profiles, 6 devices each, one disabled list on proxmox. Counts verified
//! identical to the originals, so this is the *shape* the migration touches.
//!
//! # The two properties that go wrong in silence
//!
//! Both are asserted below rather than eyeballed, because neither produces a
//! failure anyone would notice on a live box:
//!
//! 1. **The disabled list.** `privacy-ads` is `enabled = false` on proxmox.
//!    A migration that special-cased it — writing `ignore`, or skipping it —
//!    would look correct until the operator re-enabled the list, at which
//!    point it would come back with a direction nobody chose.
//! 2. **The synthesised tag.** 11 of zima's 14 lists and 12 of proxmox's 15
//!    carry no `tags` in the file; `auto_promote_blocklists` gives them
//!    `uncategorized` at load. The migration must *use* that promotion and
//!    must not *write* it: a value the loader synthesises turning into a
//!    value on disk promotes a default to data. This repo has already paid
//!    for that once, in the TUI's Lists modal.
//!
//! Which is why every read here goes through the RAW TOML. Post-promotion
//! every deny-list looks tagged, so a check written against a loaded
//! `ConfigV1` passes on exactly the rows that must be treated as untagged.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use purge_warden::cli::commands::migrate::migrate_v2_to_v3;
use purge_warden::config::loader::load_config;

const ZIMA: &str = include_str!("fixtures/plp_v2_node_a.toml");
const PROXMOX: &str = include_str!("fixtures/plp_v2_node_b.toml");

// ── raw-TOML helpers: the oracle, and the anti-promotion check ─────────

fn raw(path: &Path) -> toml::value::Table {
    match std::fs::read_to_string(path).unwrap().parse().unwrap() {
        toml::Value::Table(t) => t,
        other => panic!("root is not a table: {other:?}"),
    }
}

fn str_array(t: &toml::value::Table, key: &str) -> Option<Vec<String>> {
    match t.get(key) {
        Some(toml::Value::Array(a)) => Some(
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect(),
        ),
        _ => None,
    }
}

/// The v2 association, recomputed from the raw input.
///
/// **Deliberately an independent reimplementation**, not a call back into the
/// migration: a test that asked the migration to check its own arithmetic
/// would be green for any self-consistent answer. Same reasoning as
/// `e2e_config_to_verdict.rs`'s unsharded oracle.
///
/// Returns `profile id -> {list id -> "deny" | "allow"}` for the pairs the
/// tag intersection reached. Pairs it did not reach are simply absent.
fn v2_association(root: &toml::value::Table) -> BTreeMap<String, BTreeMap<String, String>> {
    let lists: Vec<(String, Vec<String>, String)> = match root.get("blocklists") {
        Some(toml::Value::Array(rows)) => rows
            .iter()
            .filter_map(|row| {
                let toml::Value::Table(t) = row else {
                    return None;
                };
                let id = t.get("id")?.as_str()?.to_string();
                let kind = t
                    .get("kind")
                    .and_then(toml::Value::as_str)
                    .unwrap_or("deny")
                    .to_string();
                // `auto_promote_blocklists`: untagged deny-lists become
                // `uncategorized`; allow-lists deliberately do not (D2).
                let tags = str_array(t, "tags").unwrap_or_else(|| {
                    if kind == "allow" {
                        Vec::new()
                    } else {
                        vec!["uncategorized".to_string()]
                    }
                });
                Some((id, tags, kind))
            })
            .collect(),
        _ => Vec::new(),
    };

    let mut out = BTreeMap::new();
    let Some(toml::Value::Table(profiles)) = root.get("profiles") else {
        return out;
    };
    for (pid, pv) in profiles {
        let toml::Value::Table(p) = pv else { continue };
        let ptags: BTreeSet<String> = str_array(p, "tags")
            .unwrap_or_default()
            .into_iter()
            .collect();
        let mut reached = BTreeMap::new();
        for (lid, ltags, kind) in &lists {
            if ltags.iter().any(|t| ptags.contains(t)) {
                reached.insert(lid.clone(), kind.clone());
            }
        }
        out.insert(pid.clone(), reached);
    }
    out
}

/// `profile id -> {list id -> direction}` as the migrated file states it.
fn v3_policy(root: &toml::value::Table) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    let Some(toml::Value::Table(profiles)) = root.get("profiles") else {
        return out;
    };
    for (pid, pv) in profiles {
        let toml::Value::Table(p) = pv else { continue };
        let mut pol = BTreeMap::new();
        if let Some(toml::Value::Table(l)) = p.get("lists") {
            for (lid, dv) in l {
                pol.insert(
                    lid.clone(),
                    dv.as_str().unwrap_or("<not a string>").to_string(),
                );
            }
        }
        out.insert(pid.clone(), pol);
    }
    out
}

/// Every entity that carries a `tags` key in the raw file, with its value.
fn all_raw_tags(root: &toml::value::Table) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    for kind in ["blocklists", "devices", "groups", "subnets"] {
        if let Some(toml::Value::Array(rows)) = root.get(kind) {
            for row in rows {
                let toml::Value::Table(t) = row else { continue };
                if let Some(tags) = str_array(t, "tags") {
                    let id = t.get("id").and_then(toml::Value::as_str).unwrap_or("?");
                    out.insert(format!("{kind}/{id}"), tags);
                }
            }
        }
    }
    if let Some(toml::Value::Table(profiles)) = root.get("profiles") {
        for (pid, pv) in profiles {
            let toml::Value::Table(t) = pv else { continue };
            if let Some(tags) = str_array(t, "tags") {
                out.insert(format!("profiles/{pid}"), tags);
            }
        }
    }
    out
}

// ── the harness ───────────────────────────────────────────────────────

struct Migrated {
    _dir: tempfile::TempDir,
    before: PathBuf,
    after: PathBuf,
}

fn migrate(body: &str) -> Migrated {
    let dir = tempfile::tempdir().unwrap();
    let before = dir.path().join("v2.toml");
    let after = dir.path().join("v3.toml");
    std::fs::write(&before, body).unwrap();
    migrate_v2_to_v3(&before, &after, false).expect("the fixture must migrate");
    Migrated {
        _dir: dir,
        before,
        after,
    }
}

// ── the properties ────────────────────────────────────────────────────

/// **The acceptance test of the cutover, on the real shapes.**
///
/// Every `(profile, list)` pair the tag model reached keeps its direction;
/// every pair it did not reach is written `ignore`. The second half is the
/// one that matters: in v3 a list with no override is inherited by *every*
/// profile, so an omitted `ignore` is a list silently starting to apply.
#[test]
fn both_live_shapes_migrate_to_exactly_what_the_tag_model_resolved() {
    for (label, body) in [("zima", ZIMA), ("proxmox", PROXMOX)] {
        let m = migrate(body);
        let want = v2_association(&raw(&m.before));
        let got = v3_policy(&raw(&m.after));

        assert_eq!(
            want.keys().collect::<Vec<_>>(),
            got.keys().collect::<Vec<_>>(),
            "{label}: the migration must cover exactly the configured profiles"
        );

        for (pid, reached) in &want {
            let policy = &got[pid];
            for (lid, kind) in reached {
                assert_eq!(
                    policy.get(lid),
                    Some(kind),
                    "{label}/{pid}: `{lid}` was reached by tags as `{kind}` and must \
                     keep that direction"
                );
            }
            for (lid, dir) in policy {
                if !reached.contains_key(lid) {
                    assert_eq!(
                        dir, "ignore",
                        "{label}/{pid}: `{lid}` was NOT reached by tags, so it must be \
                         written `ignore` — without it, v3 inheritance would start \
                         applying a list this profile never had"
                    );
                }
            }
        }
    }
}

/// The migrated file must load, and every profile must state its policy.
///
/// A `lint` pass is a necessary condition, never the proof — it exits 0 on
/// warnings and does not see loader deprecations. The proof is the golden
/// replay in `tests/plp_s1_verdict_golden.rs`, which runs this same verb.
#[test]
fn the_migrated_config_loads_and_every_profile_states_its_policy() {
    for (label, body) in [("zima", ZIMA), ("proxmox", PROXMOX)] {
        let m = migrate(body);
        let loaded = load_config(&m.after, time::OffsetDateTime::now_utc())
            .unwrap_or_else(|e| panic!("{label}: migrated config must load: {e:?}"));
        assert!(
            !loaded.config.profiles.is_empty(),
            "{label}: fixture must carry profiles"
        );
        for (pid, p) in &loaded.config.profiles {
            assert!(
                !p.lists.is_empty(),
                "{label}/{pid}: the migration must leave an explicit policy, not an \
                 inherited one — the point of the workstream is that the association \
                 stops being emergent"
            );
        }
    }
}

/// **The disabled list.** `privacy-ads` is `enabled = false` on proxmox.
///
/// It keeps the direction its tags gave it, exactly like an enabled list. The
/// alternatives both fail silently: writing `ignore` (or omitting it) looks
/// right until the operator flips `enabled = true`, at which point the list
/// comes back with a direction nobody chose — and for an allow-list that is a
/// standing exemption appearing out of a config edit that had nothing to do
/// with it.
#[test]
fn a_disabled_list_keeps_the_direction_its_tags_gave_it() {
    let m = migrate(PROXMOX);
    let before = raw(&m.before);

    let disabled: Vec<String> = match before.get("blocklists") {
        Some(toml::Value::Array(rows)) => rows
            .iter()
            .filter_map(|row| {
                let toml::Value::Table(t) = row else {
                    return None;
                };
                (t.get("enabled").and_then(toml::Value::as_bool) == Some(false))
                    .then(|| t.get("id")?.as_str().map(str::to_string))
                    .flatten()
            })
            .collect(),
        _ => Vec::new(),
    };
    assert_eq!(
        disabled,
        vec!["privacy-ads".to_string()],
        "fixture drift: proxmox is the shape with exactly one disabled list, and \
         without it this test asserts nothing"
    );

    let want = v2_association(&before);
    let got = v3_policy(&raw(&m.after));
    for (pid, reached) in &want {
        assert_eq!(
            got[pid].get("privacy-ads"),
            reached.get("privacy-ads"),
            "{pid}: the disabled list must be migrated by the same rule as every \
             other, so re-enabling it restores what the operator had"
        );
    }
}

/// **The synthesised tag must not round-trip.**
///
/// 12 of proxmox's 15 lists and 11 of zima's 14 carry no `tags` key.
/// `auto_promote_blocklists` gives them `uncategorized` at load, and the
/// migration uses that — but writing it back would promote a loader default
/// to a value on disk, which is a defect this repo has already had.
///
/// Asserted as "the set of tag arrays in the file is unchanged", which also
/// catches the migration inventing tags anywhere else.
#[test]
fn the_migration_never_writes_a_tag_the_file_did_not_have() {
    for (label, body) in [("zima", ZIMA), ("proxmox", PROXMOX)] {
        let m = migrate(body);
        let before = all_raw_tags(&raw(&m.before));
        let after = all_raw_tags(&raw(&m.after));

        // The property is "the migration must not write a tag the file did not
        // have", and the original defect it guards is a loader-synthesised
        // `uncategorized` becoming a value on disk.
        //
        // This used to be asserted as `before == after` — a PROXY that was
        // exact while the migration left the key alone. `plp-s5a` retired
        // `tags` from the data model, and the loader now strips it and NOTES
        // it on every load, so a migrated config that still carried it would
        // warn forever with no CLI way to silence it. The migration therefore
        // removes it, and the proxy stopped tracking the property.
        //
        // The replacement is STRICTLY STRONGER, not a loosening: inventing a
        // tag anywhere still fails, because any invented tag makes `after`
        // non-empty. Round-tripping a synthesised one fails for the same
        // reason. What it no longer does is forbid the removal itself.
        assert!(
            after.is_empty(),
            "{label}: the migration left `tags` on disk. It must read them \
             (promotion included) and write none — a value the loader \
             synthesises must never become a value on disk, and the key is \
             retired besides. Survivors: {after:?}"
        );
        // Non-vacuous in the other direction: if the fixture carried no tags
        // to begin with, `after.is_empty()` would hold against a migration
        // that does nothing at all.
        assert!(
            !before.is_empty(),
            "{label}: fixture drift — the input carries no `tags` at all, so \
             the assertion above cannot distinguish a working strip from a \
             no-op"
        );
        // Non-vacuous: the fixture really does have untagged lists for the
        // promotion to apply to.
        let untagged = match raw(&m.before).get("blocklists") {
            Some(toml::Value::Array(rows)) => rows
                .iter()
                .filter(|r| matches!(r, toml::Value::Table(t) if t.get("tags").is_none()))
                .count(),
            _ => 0,
        };
        assert!(
            untagged >= 10,
            "{label}: fixture drift — only {untagged} untagged list(s), so the \
             anti-promotion assertion above has almost nothing to catch"
        );
    }
}

/// Running it twice gives the same file.
#[test]
fn the_migration_is_idempotent() {
    for (label, body) in [("zima", ZIMA), ("proxmox", PROXMOX)] {
        let dir = tempfile::tempdir().unwrap();
        let v2 = dir.path().join("v2.toml");
        let once = dir.path().join("once.toml");
        let twice = dir.path().join("twice.toml");
        std::fs::write(&v2, body).unwrap();

        migrate_v2_to_v3(&v2, &once, false).expect("first run");
        migrate_v2_to_v3(&once, &twice, false).expect("second run over its own output");

        assert_eq!(
            std::fs::read_to_string(&once).unwrap(),
            std::fs::read_to_string(&twice).unwrap(),
            "{label}: a re-run must be byte-stable, or an operator who runs the verb \
             twice gets a diff they cannot explain"
        );
    }
}

/// **The refusal, and it names the offender.**
///
/// A device carrying its own `tags` has no v3 form: `effective_tags` unioned
/// them into what that one device filtered, and v3's finest grain is the
/// profile. Flattening would silently change that device's verdicts, so the
/// verb refuses — and the message has to say which device, or the operator
/// has nowhere to start.
///
/// Measured 2026-08-24: zero tagged devices on either live host, so this is a
/// net for third-party configs rather than something this rollout trips over.
#[test]
fn a_device_carrying_its_own_tags_is_refused_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let v2 = dir.path().join("v2.toml");
    let target = dir.path().join("v3.toml");
    let body = ZIMA.replace("[[devices]]", "[[devices]]\ntags = [\"kids\"]\n#");
    // The replace above tags the FIRST device row and comments out its next
    // line; guard that it produced something that still parses, so a failure
    // here is the refusal and not a broken fixture.
    assert!(
        body.parse::<toml::Value>().is_ok(),
        "fixture must stay valid TOML"
    );
    std::fs::write(&v2, &body).unwrap();

    let err = migrate_v2_to_v3(&v2, &target, false)
        .expect_err("a config with device tags must be refused, not flattened");
    let msg = err.to_string();
    assert!(
        msg.contains("device/"),
        "the refusal must name the offending entities, got:\n{msg}"
    );
    assert!(
        !target.exists(),
        "a refused migration must leave no output behind"
    );
}

/// A group or a subnet carrying tags is the same defect through a different
/// door, and is refused for the same reason.
///
/// `effective_tags` unioned a device's groups' tags, and an anonymous
/// source's subnet tags, into what that client filtered. §4 S3 names devices;
/// leaving the other two accepted would let a config migrate "cleanly" while
/// losing a whole population's list set.
#[test]
fn a_tagged_group_or_subnet_is_refused_too() {
    for (kind, extra) in [
        (
            "group",
            "\n[[groups]]\nid = \"iot\"\ndisplay_name = \"IoT\"\nprofile = \"default\"\npriority = 5\ntags = [\"iot\"]\n",
        ),
        (
            "subnet",
            "\n[[subnets]]\nid = \"guest\"\ndisplay_name = \"Guest\"\ncidrs = [\"10.9.0.0/24\"]\nprofile = \"default\"\npriority = 0\ntags = [\"guest\"]\n",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let v2 = dir.path().join("v2.toml");
        let target = dir.path().join("v3.toml");
        std::fs::write(&v2, format!("{PROXMOX}{extra}")).unwrap();

        let err = migrate_v2_to_v3(&v2, &target, false)
            .err()
            .unwrap_or_else(|| panic!("a tagged {kind} was migrated instead of refused"));
        let msg = err.to_string();
        assert!(
            msg.contains(&format!("{kind}/")),
            "the refusal must name the offending {kind}, got:\n{msg}"
        );
        assert!(
            !target.exists(),
            "a refused migration must leave no output behind"
        );
    }
}
