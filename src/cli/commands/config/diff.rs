//! `warden config diff <other>` — structured diff between two v1 configs.
//!
//! S31 implements the offline variant recommended in
//! `_docs/features/config_architecture.md` §16.3 follow-up #2 option (b):
//! the CLI re-reads both files from disk, merges via
//! [`crate::config::loader::load_config`], and renders a per-entity
//! delta. An online variant (an IPC endpoint that streams the live
//! daemon's `LoadedConfig` snapshot) is a future extension once
//! operators ask for "on-disk vs live" comparison.
//!
//! The diff groups changes by top-level entity class and reports:
//!
//! - added entities (present in `other`, absent in the current)
//! - removed entities (present in the current, absent in `other`)
//! - changed entities (present in both, differing TOML serialisation)
//!
//! # Exit codes
//!
//! - [`SUCCESS`](crate::cli::exit_codes::SUCCESS) (0) — the two configs are identical.
//! - [`NEGATIVE`](crate::cli::exit_codes::NEGATIVE) (3) — they differ.
//! - [`CONFIG`](crate::cli::exit_codes::CONFIG) (2) — one of them could not be loaded.
//! - [`FAILURE`](crate::cli::exit_codes::FAILURE) (1) — the diff itself failed
//!   (this function returned `Err`, which `main` renders as 1).
//!
//! "Differences found" used to be 1, the same code as "the diff itself
//! failed" — so `warden config diff live backup.toml` could not tell a
//! script the two apart, which is precisely the ambiguity the exit-code
//! contract exists to remove. It matters here more than most: the script
//! reading this is deciding whether to restore a backup, and the two
//! answers demand opposite actions. Finding a difference is this verb
//! succeeding, so it takes the code reserved for a read-only diagnostic
//! answering no.

use std::collections::BTreeMap;
use std::path::Path;

use crate::cli::exit_codes::{CONFIG, NEGATIVE, SUCCESS};
use crate::config::loader;
use crate::config::schema::{
    AdminRule, Blocklist, ConfigV1, CustomList, Device, Group, Label, Profile, Schedule, Subnet,
};

/// Run the diff. Returns the intended process exit code.
pub fn run_diff(current: &Path, other: &Path) -> anyhow::Result<i32> {
    let now = time::OffsetDateTime::now_utc();
    let left = match loader::load_config(current, now) {
        Ok(l) => l,
        Err(errs) => {
            print_load_errors(current, &errs);
            return Ok(CONFIG);
        }
    };
    let right = match loader::load_config(other, now) {
        Ok(l) => l,
        Err(errs) => {
            print_load_errors(other, &errs);
            return Ok(CONFIG);
        }
    };

    let report = diff_configs(&left.config, &right.config);
    println!("# diff: {} → {}", current.display(), other.display());
    let any = report.print();
    if any {
        Ok(NEGATIVE)
    } else {
        println!("(no differences)");
        Ok(SUCCESS)
    }
}

fn print_load_errors(path: &Path, errs: &[crate::config::error::ConfigError]) {
    eprintln!("cannot load {} ({} error(s)):", path.display(), errs.len());
    for err in errs {
        eprintln!("  - {err}");
    }
}

/// Accumulates all classes of change so the printer can render them in
/// a stable order regardless of traversal.
#[derive(Default)]
struct DiffReport {
    sections: Vec<SectionDiff>,
}

struct SectionDiff {
    name: &'static str,
    added: Vec<String>,
    removed: Vec<String>,
    changed: Vec<String>,
}

impl SectionDiff {
    /// True when this section reports nothing. One definition so the
    /// printer and the coverage fence cannot disagree about what
    /// "changed" means.
    fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

impl DiffReport {
    fn print(&self) -> bool {
        let mut any_change = false;
        for s in &self.sections {
            if s.is_empty() {
                continue;
            }
            any_change = true;
            println!("## {}", s.name);
            for id in &s.added {
                println!("  + {id}");
            }
            for id in &s.removed {
                println!("  - {id}");
            }
            for id in &s.changed {
                println!("  ~ {id}");
            }
        }
        any_change
    }
}

/// Diff two merged configs section by section.
///
/// Takes `&ConfigV1` rather than `&LoadedConfig` so the coverage fence can
/// drive it on in-memory configs — no temp file, no validator in the loop.
/// That is what makes a per-field differential possible for fields the
/// validator would refuse to load (`schema_version`).
fn diff_configs(a: &ConfigV1, b: &ConfigV1) -> DiffReport {
    let mut r = DiffReport::default();

    // Structural, then the entity model, then the daemon-wide settings in
    // `ConfigV1` declaration order. Every top-level field appears exactly
    // once — enforced by `h10_diff_covers_every_config_v1_field`.
    r.sections.push(diff_settings_section(
        "schema_version",
        &a.schema_version,
        &b.schema_version,
    ));
    r.sections
        .push(diff_settings_section("includes", &a.includes, &b.includes));
    r.sections
        .push(diff_settings_section("server", &a.server, &b.server));
    r.sections.push(diff_entity_vec(
        "devices", &a.devices, &b.devices, device_key, toml_eq,
    ));
    r.sections.push(diff_entity_vec(
        "groups", &a.groups, &b.groups, group_key, toml_eq,
    ));
    r.sections.push(diff_entity_vec(
        "subnets", &a.subnets, &b.subnets, subnet_key, toml_eq,
    ));
    r.sections.push(diff_entity_vec(
        "schedules",
        &a.schedules,
        &b.schedules,
        schedule_key,
        toml_eq,
    ));
    r.sections.push(diff_entity_vec(
        "blocklists",
        &a.blocklists,
        &b.blocklists,
        blocklist_key,
        toml_eq,
    ));
    r.sections.push(diff_entity_vec(
        "admin_rules",
        &a.admin_rules,
        &b.admin_rules,
        admin_rule_key,
        toml_eq,
    ));
    r.sections.push(diff_entity_vec(
        "labels", &a.labels, &b.labels, label_key, toml_eq,
    ));
    r.sections.push(diff_entity_vec(
        "custom_lists",
        &a.custom_lists,
        &b.custom_lists,
        custom_list_key,
        toml_eq,
    ));
    r.sections.push(diff_profiles(&a.profiles, &b.profiles));

    // ── daemon-wide settings ───────────────────────────────────────────
    //
    // These are the sections an operator is *most* likely to have diverged
    // between a hand-maintained live config and a backup, and until
    // cli-h10 the diff could not see any of them: swapping your upstream
    // resolvers, your cache sizing, your rate limits or your API binding
    // printed `(no differences)` and exited 0.
    //
    // Compared whole-section, not field-by-field. "Your `[upstream]` will
    // change" is enough to stop a blind restore, which is the question the
    // verb exists to answer; a field-level delta is a later refinement.
    r.sections
        .push(diff_settings_section("retired", &a.retired, &b.retired));
    r.sections
        .push(diff_settings_section("upstream", &a.upstream, &b.upstream));
    r.sections
        .push(diff_settings_section("dnssec", &a.dnssec, &b.dnssec));
    r.sections
        .push(diff_settings_section("cache", &a.cache, &b.cache));
    r.sections
        .push(diff_settings_section("tracking", &a.tracking, &b.tracking));
    r.sections
        .push(diff_settings_section("security", &a.security, &b.security));
    r.sections.push(diff_settings_section(
        "anti_bypass",
        &a.anti_bypass,
        &b.anti_bypass,
    ));
    r.sections
        .push(diff_settings_section("socket", &a.socket, &b.socket));
    r.sections
        .push(diff_settings_section("api", &a.api, &b.api));
    r.sections.push(diff_settings_section(
        "forwarding",
        &a.forwarding,
        &b.forwarding,
    ));
    r.sections.push(diff_settings_section(
        "local_dns",
        &a.local_dns,
        &b.local_dns,
    ));
    r.sections.push(diff_settings_section(
        "ip_blocklists",
        &a.ip_blocklists,
        &b.ip_blocklists,
    ));
    r.sections
        .push(diff_settings_section("lists", &a.lists, &b.lists));
    r.sections.push(diff_settings_section(
        "resource_budget",
        &a.resource_budget,
        &b.resource_budget,
    ));
    r.sections.push(diff_settings_section(
        "custom_list_limits",
        &a.custom_list_limits,
        &b.custom_list_limits,
    ));
    r.sections
        .push(diff_settings_section("backup", &a.backup, &b.backup));
    r.sections
        .push(diff_settings_section("cluster", &a.cluster, &b.cluster));

    r
}

/// Compare one whole section and report it as changed if it differs.
///
/// Used for every non-entity top-level field, including the bare scalars
/// (`schema_version`) and the `Vec`-valued pass-throughs (`forwarding`,
/// `retired`). Entity collections keep their per-id treatment — knowing
/// *which* device changed is worth the extra code; knowing *which*
/// `[cache]` key changed is not, when the operator's next move is to open
/// the file anyway.
fn diff_settings_section<T: serde::Serialize>(name: &'static str, a: &T, b: &T) -> SectionDiff {
    let mut sd = SectionDiff {
        name,
        added: Vec::new(),
        removed: Vec::new(),
        changed: Vec::new(),
    };
    if !value_eq(a, b) {
        sd.changed.push(name.to_string());
    }
    sd
}

fn diff_entity_vec<T, K, E>(name: &'static str, a: &[T], b: &[T], key_of: K, eq: E) -> SectionDiff
where
    K: Fn(&T) -> String,
    E: Fn(&T, &T) -> bool,
{
    let left: BTreeMap<String, &T> = a.iter().map(|x| (key_of(x), x)).collect();
    let right: BTreeMap<String, &T> = b.iter().map(|x| (key_of(x), x)).collect();
    let mut sd = SectionDiff {
        name,
        added: Vec::new(),
        removed: Vec::new(),
        changed: Vec::new(),
    };
    for (k, rv) in &right {
        match left.get(k) {
            None => sd.added.push(k.clone()),
            Some(lv) if !eq(lv, rv) => sd.changed.push(k.clone()),
            _ => {}
        }
    }
    for k in left.keys() {
        if !right.contains_key(k) {
            sd.removed.push(k.clone());
        }
    }
    sd
}

fn diff_profiles(a: &BTreeMap<String, Profile>, b: &BTreeMap<String, Profile>) -> SectionDiff {
    let mut sd = SectionDiff {
        name: "profiles",
        added: Vec::new(),
        removed: Vec::new(),
        changed: Vec::new(),
    };
    for (k, rv) in b {
        match a.get(k) {
            None => sd.added.push(k.clone()),
            Some(lv) if !toml_eq(lv, rv) => sd.changed.push(k.clone()),
            _ => {}
        }
    }
    for k in a.keys() {
        if !b.contains_key(k) {
            sd.removed.push(k.clone());
        }
    }
    sd
}

// Key extractors: every entity class carries an `Id` — use its string form.
fn device_key(d: &Device) -> String {
    d.id.as_str().to_string()
}
fn group_key(g: &Group) -> String {
    g.id.as_str().to_string()
}
fn subnet_key(s: &Subnet) -> String {
    s.id.as_str().to_string()
}
fn schedule_key(s: &Schedule) -> String {
    s.id.as_str().to_string()
}
fn blocklist_key(b: &Blocklist) -> String {
    b.id.as_str().to_string()
}
fn admin_rule_key(r: &AdminRule) -> String {
    r.id.as_str().to_string()
}
/// The one exception to the comment above: a label's identity is the
/// `(kind, id)` PAIR, so an id-only key would collapse the legal
/// cross-kind homonym into one row and report a real addition as a
/// modification.
fn label_key(l: &Label) -> String {
    format!("{}/{}", l.kind.as_str(), l.id.as_str())
}

/// Keyed on the id alone. Unlike a label there is no second axis: the
/// validator refuses a `custom_lists` id that collides with a blocklist id,
/// so the id identifies the row on its own.
fn custom_list_key(c: &CustomList) -> String {
    c.id.as_str().to_string()
}

/// Semantic equality via TOML serialisation — entity structs don't all
/// derive `PartialEq`, and even for the ones that do, a TOML round-trip
/// is a stronger "same on disk" guarantee than field-by-field equality.
fn toml_eq<T: serde::Serialize>(a: &T, b: &T) -> bool {
    match (toml::to_string(a), toml::to_string(b)) {
        (Ok(sa), Ok(sb)) => sa == sb,
        _ => false,
    }
}

/// Semantic equality via JSON serialisation, for the sections
/// [`diff_settings_section`] handles.
///
/// Not [`toml_eq`]: `toml::to_string` cannot serialise a bare scalar, so it
/// returns `Err` for `schema_version: u32` — and `Err` falls into the
/// "not equal" arm, which would report that section as changed on *every*
/// invocation. A comparator that cries wolf on identical configs is worse
/// than no comparator, because the operator learns to ignore it.
fn value_eq<T: serde::Serialize>(a: &T, b: &T) -> bool {
    match (serde_json::to_value(a), serde_json::to_value(b)) {
        (Ok(va), Ok(vb)) => va == vb,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::writer::write_config_v1;

    fn load(src: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, src).unwrap();
        (dir, path)
    }

    const BASE: &str = r#"schema_version = 3

[server]
listen = "127.0.0.1:15353"
default_profile = "default"

[[blocklists]]
id = "privacy-ads"
display_name = "Privacy: ads"
url = "https://lists.purge.cc/privacy/ads.txt"

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#;

    #[test]
    fn identical_configs_report_no_difference() {
        let (_d1, p1) = load(BASE);
        let (_d2, p2) = load(BASE);
        let rc = run_diff(&p1, &p2).unwrap();
        assert_eq!(rc, SUCCESS);
    }

    /// The three outcomes an operator's restore script branches on must
    /// land on three different codes.
    ///
    /// Driven through the real verb, and asserted pairwise rather than
    /// against three literals: the defect this closes was two outcomes
    /// sharing code 1, and "they are all distinct" is the property, not
    /// "one of them happens to be 3". `FAILURE` is checked separately
    /// below because nothing in this test can produce it — it is the code
    /// `main` renders for an `Err`, and `run_diff` returns `Ok` on all
    /// three paths here.
    #[test]
    fn the_three_diff_outcomes_are_pairwise_distinct_codes() {
        let (_d1, p1) = load(BASE);
        let (_same, p_same) = load(BASE);
        let (_diff, p_diff) = load(&format!("{BASE}\n[cache]\nmax_entries = 4242\n"));
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("nonexistent.toml");

        let identical = run_diff(&p1, &p_same).unwrap();
        let differs = run_diff(&p1, &p_diff).unwrap();
        let unloadable = run_diff(&p1, &missing).unwrap();

        let outcomes = [
            ("identical", identical),
            ("differs", differs),
            ("unloadable", unloadable),
        ];
        for (i, (name_a, a)) in outcomes.iter().enumerate() {
            for (name_b, b) in &outcomes[i + 1..] {
                assert_ne!(
                    a, b,
                    "`{name_a}` and `{name_b}` both exit {a} — a restore script \
                     cannot tell them apart, which is the whole reason the \
                     exit-code contract exists"
                );
            }
        }

        assert_eq!(
            differs, NEGATIVE,
            "finding differences is this verb SUCCEEDING at a read-only \
             question, so it takes the contract's negative-answer code"
        );
        assert_ne!(
            differs,
            crate::cli::exit_codes::FAILURE,
            "differences-found must never share a code with `the diff itself \
             failed` — that collision is the defect being closed here, and it \
             makes a blind restore look safe"
        );
    }

    #[test]
    fn added_blocklist_shows_as_added() {
        let (_d1, p1) = load(BASE);
        let extra = format!(
            r#"{BASE}
[[blocklists]]
id = "privacy-tracking"
display_name = "Privacy: tracking"
url = "https://lists.purge.cc/privacy/tracking.txt"
"#
        );
        let (_d2, p2) = load(&extra);
        let rc = run_diff(&p1, &p2).unwrap();
        assert_eq!(
            rc, NEGATIVE,
            "a difference must produce the negative-answer code"
        );
    }

    #[test]
    fn diff_roundtrips_via_write_config_v1() {
        // Loading, writing via v1 writer, then reloading should produce
        // a config that diffs clean against itself.
        let (_d1, p1) = load(BASE);
        let now = time::OffsetDateTime::now_utc();
        let loaded = loader::load_config(&p1, now).unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let p2 = d2.path().join("config.toml");
        write_config_v1(&p2, &loaded.config).unwrap();
        let rc = run_diff(&p1, &p2).unwrap();
        assert_eq!(rc, SUCCESS, "writer roundtrip must diff clean");
    }

    #[test]
    fn missing_file_returns_two() {
        let (_d1, p1) = load(BASE);
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("nonexistent.toml");
        let rc = run_diff(&p1, &missing).unwrap();
        assert_eq!(rc, CONFIG, "load failure must exit 2");
    }

    /// A settings-only difference, through the real verb: two files that
    /// are byte-identical except for `[cache].max_entries`.
    ///
    /// The fence above drives `diff_configs` directly. This one goes
    /// through `run_diff` — load, merge, compare, exit code — because that
    /// is what the operator runs before restoring a backup, and the
    /// pre-cli-h10 verb answered `(no differences)` / exit 0 to this pair.
    /// The `BASE`-vs-`BASE` arm above (`identical_configs_report_no_difference`)
    /// is the control: without it, exit 1 here would prove nothing.
    #[test]
    fn h10_settings_only_difference_is_visible_to_the_verb() {
        let (_d1, p1) = load(BASE);
        let (_d2, p2) = load(&format!("{BASE}\n[cache]\nmax_entries = 12345\n"));
        let rc = run_diff(&p1, &p2).unwrap();
        assert_eq!(
            rc, NEGATIVE,
            "a config differing only in [cache] must be reported as \
             different — reporting `(no differences)` here is how an \
             operator silently re-sizes their cache by restoring a backup"
        );
    }

    // ── cli-h10: the coverage fence ────────────────────────────────────
    //
    // `config diff` answers "what will change if I restore this backup?".
    // A field it does not compare is a field an operator can swap without
    // ever being told — the verb prints `(no differences)` and exits 0,
    // which a script reads as "safe". Before cli-h10 the diff compared the
    // entity model and *none* of the settings: upstream, cache, security,
    // dnssec, api, forwarding, local_dns, … were all invisible.
    //
    // Two halves, because either alone is a fence with a hole:
    //
    // 1. [`h10_diff_covers_every_config_v1_field`] — set equality between
    //    the section names the diff emits and `ConfigV1`'s field names,
    //    the latter DERIVED from a serialised value. A hand-written list
    //    of 26 names would be the bug wearing a test's clothes: it rots
    //    the moment field 27 lands, and it rots silently.
    // 2. [`h10_each_field_mutation_fires_exactly_its_own_section`] — one
    //    mutation per field, asserting the reported set is exactly that
    //    field's section. Names alone cannot catch a section labelled
    //    `"security"` that was handed `&a.cache` — only a differential
    //    can, and a differential is also the only thing that distinguishes
    //    "identical configs" from "the comparison never ran": both print
    //    `(no differences)` and exit 0.
    //
    // # The fence's boundary — read this before trusting it
    //
    // The key set comes from `serde_json::to_value`, which emits every
    // field of a struct including `Option::None` (as `null`). It would NOT
    // see a future field carrying `#[serde(skip_serializing_if = …)]` or
    // `#[serde(skip)]`, because such a field is absent from the serialised
    // value when its predicate holds. `ConfigV1` has zero such attributes
    // today (and `deny_unknown_fields`, so nothing enters off-schema); a
    // commit that adds one moves that field outside this fence and must
    // extend the diff by hand.

    use std::collections::BTreeSet;

    /// Every top-level `ConfigV1` field name, derived from a serialised
    /// value rather than typed out here.
    ///
    /// `serde_json` and not `toml`: the TOML serialiser drops a `None`
    /// field entirely, so an `Option` field 27 would slip through a
    /// TOML-derived key set. JSON renders it as `null` — present.
    fn config_v1_field_keys() -> BTreeSet<String> {
        let v = serde_json::to_value(ConfigV1::test_scaffold())
            .expect("ConfigV1 must serialise to JSON for the fence to derive its key set");
        v.as_object()
            .expect("ConfigV1 must serialise to a JSON object")
            .keys()
            .cloned()
            .collect()
    }

    /// Section names the diff actually emits, derived by running it.
    fn diff_section_names() -> BTreeSet<String> {
        let c = ConfigV1::test_scaffold();
        diff_configs(&c, &c)
            .sections
            .iter()
            .map(|s| s.name.to_string())
            .collect()
    }

    /// Sections that report a change for this pair — the same emptiness
    /// predicate the printer uses, via [`SectionDiff::is_empty`].
    fn changed_sections(a: &ConfigV1, b: &ConfigV1) -> BTreeSet<String> {
        diff_configs(a, b)
            .sections
            .iter()
            .filter(|s| !s.is_empty())
            .map(|s| s.name.to_string())
            .collect()
    }

    #[test]
    fn h10_diff_covers_every_config_v1_field() {
        let fields = config_v1_field_keys();
        let sections = diff_section_names();

        // A floor on the DERIVATION, not on the coverage claim. Both
        // `difference()` assertions below are vacuously true if `fields`
        // ever comes back empty or truncated — a serde change that makes
        // `to_value` yield something thinner, or a future `skip_serializing_if`
        // — and a fence that passes while fencing nothing is the exact trap
        // this sprint was written to close. Bumping this number is the
        // correct response to adding a field; deleting it is not.
        assert!(
            fields.len() >= 26,
            "the ConfigV1 key derivation returned only {} field(s) — it must \
             enumerate the struct. Both coverage assertions below are \
             meaningless until this holds. Derived: {:?}",
            fields.len(),
            fields
        );

        let uncompared: Vec<&str> = fields.difference(&sections).map(|s| s.as_str()).collect();
        assert!(
            uncompared.is_empty(),
            "config diff does not compare {} ConfigV1 field(s): {:?}\n\
             Every one of these can differ between two configs while the verb \
             prints `(no differences)` and exits 0. Add a section for each in \
             diff_configs(), and a mutation in MUTATIONS.",
            uncompared.len(),
            uncompared
        );

        let phantom: Vec<&str> = sections.difference(&fields).map(|s| s.as_str()).collect();
        assert!(
            phantom.is_empty(),
            "config diff emits section(s) that are not ConfigV1 fields: {phantom:?}\n\
             Either the field was renamed and the section was not, or the \
             section name is a typo — a section nobody can map back to a \
             field is a section nobody can act on."
        );
    }

    /// Deserialise a fixture entity from minimal TOML. Goes through the
    /// real deserialiser so serde defaults apply — none of these structs
    /// implements `Default`.
    fn entity<T: serde::de::DeserializeOwned>(src: &str) -> T {
        toml::from_str(src).expect("fence fixture entity must deserialise")
    }

    /// One mutation per `ConfigV1` field. Each must change the
    /// serialisation of its own field and nothing else.
    ///
    /// This table is hand-written, but it cannot rot silently: the test
    /// below asserts its key set equals the DERIVED key set, so field 27
    /// fails here by name too.
    #[allow(clippy::type_complexity)]
    const MUTATIONS: &[(&str, fn(&mut ConfigV1))] = &[
        ("schema_version", |c| c.schema_version += 1),
        ("includes", |c| c.includes.push("conf.d/*.toml".to_string())),
        ("server", |c| c.server.tcp_timeout_secs += 1),
        ("retired", |c| {
            c.retired.push(entity(
                "id = \"h10-retired\"\ntype = \"device\"\n\
                 retired_at = \"2026-01-15T00:00:00Z\"\n",
            ))
        }),
        ("blocklists", |c| {
            c.blocklists.push(entity(
                "id = \"h10-list\"\ndisplay_name = \"H10\"\n\
                 url = \"https://lists.purge.cc/h10.txt\"\n",
            ))
        }),
        ("profiles", |c| {
            c.profiles
                .insert("h10-profile".to_string(), Profile::default());
        }),
        ("devices", |c| {
            c.devices
                .push(entity("id = \"h10-dev\"\ndisplay_name = \"H10\"\n"))
        }),
        ("groups", |c| {
            c.groups.push(entity(
                "id = \"h10-group\"\ndisplay_name = \"H10\"\nprofile = \"default\"\n",
            ))
        }),
        ("subnets", |c| {
            c.subnets.push(entity(
                "id = \"h10-subnet\"\ndisplay_name = \"H10\"\n\
                 cidrs = [\"10.10.9.0/24\"]\nprofile = \"default\"\n",
            ))
        }),
        ("schedules", |c| {
            c.schedules.push(entity(
                "id = \"h10-sched\"\ndisplay_name = \"H10\"\n\
                 target_type = \"group\"\ntarget_id = \"h10-group\"\n\
                 profile = \"default\"\ndays = [\"all\"]\nhours = \"21:00-07:00\"\n",
            ))
        }),
        ("admin_rules", |c| {
            c.admin_rules
                .push(entity("id = \"h10-rule\"\nrule = \"||h10.example^\"\n"))
        }),
        ("labels", |c| {
            c.labels.push(entity(
                "id = \"h10-owner\"\nkind = \"owner\"\ndisplay_name = \"H10\"\n",
            ))
        }),
        ("custom_lists", |c| {
            c.custom_lists
                .push(entity("id = \"h10-pack\"\ndisplay_name = \"H10\"\n"))
        }),
        ("custom_list_limits", |c| {
            c.custom_list_limits.max_file_bytes += 1
        }),
        ("upstream", |c| {
            c.upstream.servers.push("9.9.9.9:53".to_string())
        }),
        ("dnssec", |c| c.dnssec.max_chain_depth += 1),
        ("cache", |c| c.cache.max_entries += 1),
        ("tracking", |c| c.tracking.top_n_limit += 1),
        ("security", |c| c.security.enabled = !c.security.enabled),
        ("anti_bypass", |c| {
            c.anti_bypass.enabled = !c.anti_bypass.enabled
        }),
        ("socket", |c| {
            c.socket.path = std::path::PathBuf::from("/run/h10/control.sock")
        }),
        ("api", |c| c.api.enabled = !c.api.enabled),
        ("forwarding", |c| {
            c.forwarding.push(entity(
                "suffix = \"h10.lan\"\nservers = [\"10.10.1.1:53\"]\n",
            ))
        }),
        ("local_dns", |c| c.local_dns.ttl_secs += 1),
        ("ip_blocklists", |c| {
            c.ip_blocklists.enabled = !c.ip_blocklists.enabled
        }),
        ("lists", |c| c.lists.update_interval_secs += 1),
        ("resource_budget", |c| c.resource_budget.tick_secs += 1),
        ("backup", |c| {
            c.backup.dir = Some(std::path::PathBuf::from("/var/lib/purge-warden/h10"))
        }),
        ("cluster", |c| c.cluster.enabled = !c.cluster.enabled),
    ];

    #[test]
    fn h10_mutation_table_covers_every_config_v1_field() {
        let table: BTreeSet<String> = MUTATIONS.iter().map(|(k, _)| k.to_string()).collect();
        assert_eq!(
            table.len(),
            MUTATIONS.len(),
            "MUTATIONS has a duplicate key — a duplicate silently hides a \
             missing field behind a covered one"
        );
        assert_eq!(
            table,
            config_v1_field_keys(),
            "MUTATIONS must probe every ConfigV1 field, no more and no less"
        );
    }

    #[test]
    fn h10_identical_configs_report_no_changed_section() {
        // The control arm. Without it, every assertion below could be
        // satisfied by a diff that reports every section as changed
        // always — and `(no differences)` + exit 0 is also exactly what
        // the "comparison never ran" bug prints.
        let c = ConfigV1::test_scaffold();
        assert_eq!(
            changed_sections(&c, &c),
            BTreeSet::new(),
            "a config compared against itself must report nothing"
        );
    }

    #[test]
    fn h10_each_field_mutation_fires_exactly_its_own_section() {
        let base = ConfigV1::test_scaffold();
        for (field, mutate) in MUTATIONS {
            let mut variant = base.clone();
            mutate(&mut variant);

            let expected: BTreeSet<String> = std::iter::once(field.to_string()).collect();
            assert_eq!(
                changed_sections(&base, &variant),
                expected,
                "mutating `{field}` must be reported as a change to `{field}` \
                 and to nothing else — a mismatch here means the section is \
                 wired to the wrong field, or does not compare it at all"
            );
            // Symmetric: a removal must be seen as readily as an addition.
            assert_eq!(
                changed_sections(&variant, &base),
                expected,
                "the diff of `{field}` must be symmetric — `warden config diff \
                 live backup` and `… backup live` must agree on what differs"
            );
        }
    }
}
