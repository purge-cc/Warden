use super::*;

fn tmpdir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

#[test]
fn resolve_target_file_explicit_into_accepted() {
    let dir = tmpdir();
    let master = dir.path().join("config.toml");
    std::fs::write(&master, "").unwrap();
    let target = dir.path().join("devices.d").join("fam.toml");
    std::fs::create_dir_all(target.parent().unwrap()).unwrap();
    let out = resolve_target_file(&master, EntityClass::Devices, Some(&target)).expect("accepts");
    assert_eq!(out, target);
}

#[test]
fn resolve_target_file_absent_dir_falls_through_to_master() {
    let dir = tmpdir();
    let master = dir.path().join("config.toml");
    std::fs::write(&master, "").unwrap();
    let out = resolve_target_file(&master, EntityClass::Devices, None).unwrap();
    assert_eq!(out, master);
}

#[test]
fn resolve_target_file_single_candidate_auto_selects() {
    let dir = tmpdir();
    let master = dir.path().join("config.toml");
    std::fs::write(&master, "").unwrap();
    let dd = dir.path().join("devices.d");
    std::fs::create_dir_all(&dd).unwrap();
    let only = dd.join("one.toml");
    std::fs::write(&only, "").unwrap();
    let out = resolve_target_file(&master, EntityClass::Devices, None).unwrap();
    assert_eq!(out, only);
}

#[test]
fn resolve_target_file_multiple_candidates_error_hints_into() {
    let dir = tmpdir();
    let master = dir.path().join("config.toml");
    std::fs::write(&master, "").unwrap();
    let dd = dir.path().join("devices.d");
    std::fs::create_dir_all(&dd).unwrap();
    std::fs::write(dd.join("fam.toml"), "").unwrap();
    std::fs::write(dd.join("iot.toml"), "").unwrap();
    let err = resolve_target_file(&master, EntityClass::Devices, None).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("ambiguous"), "got: {msg}");
    assert!(msg.contains("--into"), "got: {msg}");
    assert!(
        msg.contains("fam.toml") && msg.contains("iot.toml"),
        "got: {msg}"
    );
}

#[test]
fn resolve_target_file_rejects_escape() {
    let dir = tmpdir();
    let master = dir.path().join("config.toml");
    std::fs::write(&master, "").unwrap();
    // Escape attempt via `..`
    let bogus = Path::new("../../../etc/passwd");
    let err = resolve_target_file(&master, EntityClass::Devices, Some(bogus)).unwrap_err();
    assert!(
        err.to_string().contains("escapes") || err.to_string().contains("must live under"),
        "got: {err}"
    );
}

#[test]
fn upsert_id_keyed_appends_new_entry() {
    let mut doc: Value = "".parse().unwrap();
    let entry: Value = toml::from_str(
        r#"
id = "iphone"
display_name = "iPhone"
"#,
    )
    .unwrap();
    let created = upsert_id_keyed(&mut doc, "devices", "iphone", entry).unwrap();
    assert!(created);
    let out = toml::to_string(&doc).unwrap();
    assert!(out.contains("iphone"));
}

#[test]
fn upsert_id_keyed_replaces_existing() {
    let src = r#"
[[devices]]
id = "iphone"
display_name = "old"
"#;
    let mut doc: Value = src.parse().unwrap();
    let entry: Value = toml::from_str(
        r#"
id = "iphone"
display_name = "new"
"#,
    )
    .unwrap();
    let created = upsert_id_keyed(&mut doc, "devices", "iphone", entry).unwrap();
    assert!(!created, "existing id replaced, not appended");
    let out = toml::to_string(&doc).unwrap();
    assert!(out.contains("new"));
    assert!(!out.contains("old"));
}

#[test]
fn remove_id_keyed_drops_match() {
    let src = r#"
[[devices]]
id = "a"
display_name = "A"

[[devices]]
id = "b"
display_name = "B"
"#;
    let mut doc: Value = src.parse().unwrap();
    let removed = remove_id_keyed(&mut doc, "devices", "a").unwrap();
    assert!(removed);
    let out = toml::to_string(&doc).unwrap();
    assert!(!out.contains("id = \"a\""));
    assert!(out.contains("id = \"b\""));
}

#[test]
fn remove_id_keyed_missing_returns_false() {
    let mut doc: Value = "".parse().unwrap();
    let removed = remove_id_keyed(&mut doc, "devices", "ghost").unwrap();
    assert!(!removed);
}

#[test]
fn upsert_profile_creates_named_map_entry() {
    let mut doc: Value = "".parse().unwrap();
    let entry: Value = toml::from_str(
        r#"
display_name = "Default"
"#,
    )
    .unwrap();
    let created = upsert_profile(&mut doc, "default", entry).unwrap();
    assert!(created);
    let out = toml::to_string(&doc).unwrap();
    assert!(out.contains("[profiles.default]"));
}

#[test]
fn read_or_empty_missing_returns_empty_table() {
    let dir = tmpdir();
    let missing = dir.path().join("nope.toml");
    let (val, orig) = read_or_empty(&missing).unwrap();
    assert!(val.as_table().unwrap().is_empty());
    assert!(orig.is_none());
}

#[test]
fn read_or_empty_reads_existing_file() {
    let dir = tmpdir();
    let p = dir.path().join("x.toml");
    std::fs::write(
        &p,
        "schema_version = 3\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    )
    .unwrap();
    let (val, orig) = read_or_empty(&p).unwrap();
    assert_eq!(val.get("schema_version").unwrap().as_integer(), Some(3));
    assert_eq!(
        orig.as_deref(),
        Some("schema_version = 3\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n")
    );
}

#[test]
fn revert_removes_file_when_original_absent() {
    // `revert(path, None)` deletes a file that did not exist before the
    // (now rolled-back) write — the compound-writer mid-sequence rollback
    // relies on this for a freshly-created slice.
    let dir = tmpdir();
    let created = dir.path().join("new.toml");
    std::fs::write(&created, "whatever").unwrap();
    let res = revert(&created, None);
    assert!(res.is_ok());
    assert!(!created.exists(), "file removed when original was None");
}

// ── §4.26 hotfix: find_target_for_id shape coverage ──────────
//
// Six tests pinning the dual-shape lookup. The §4.26 §1/2 bug
// (mutate verbs broken post-create) was a silent `Ok(None)` from
// this function on the v1 named-map `[profiles.<id>]` shape: the
// old implementation hard-coded `as_array()` which only handled
// `[[profiles]]` array-of-tables. These tests pin both shapes so
// a future refactor that drops the named-map branch fails loudly.

#[test]
fn find_target_for_id_hits_array_of_tables_in_master() {
    let dir = tmpdir();
    let master = dir.path().join("config.toml");
    std::fs::write(
        &master,
        r#"
[[devices]]
id = "iphone"
display_name = "iPhone"
ip = "10.0.0.1"

[[devices]]
id = "laptop"
display_name = "Laptop"
ip = "10.0.0.2"
"#,
    )
    .unwrap();
    let hit = find_target_for_id(&master, EntityClass::Devices, "laptop").unwrap();
    assert_eq!(hit, Some(master));
}

#[test]
fn find_target_for_id_hits_named_map_profile_in_master() {
    // Regression for §4.26 §1/2: previously returned Ok(None)
    // because the implementation called `as_array()` on the
    // `[profiles]` value, which is a `Value::Table` in v1.
    let dir = tmpdir();
    let master = dir.path().join("config.toml");
    std::fs::write(
        &master,
        r#"
[profiles.default]
display_name = "Default"

[profiles.kids]
display_name = "Kids"
block_all = true
"#,
    )
    .unwrap();
    let hit = find_target_for_id(&master, EntityClass::Profiles, "kids").unwrap();
    assert_eq!(hit, Some(master));
}

#[test]
fn find_target_for_id_named_map_miss_returns_none() {
    let dir = tmpdir();
    let master = dir.path().join("config.toml");
    std::fs::write(
        &master,
        r#"
[profiles.default]
display_name = "Default"
"#,
    )
    .unwrap();
    let hit = find_target_for_id(&master, EntityClass::Profiles, "ghost").unwrap();
    assert_eq!(hit, None);
}

#[test]
fn find_target_for_id_array_of_tables_miss_returns_none() {
    let dir = tmpdir();
    let master = dir.path().join("config.toml");
    std::fs::write(
        &master,
        r#"
[[devices]]
id = "iphone"
display_name = "iPhone"
ip = "10.0.0.1"
"#,
    )
    .unwrap();
    let hit = find_target_for_id(&master, EntityClass::Devices, "ghost").unwrap();
    assert_eq!(hit, None);
}

#[test]
fn find_target_for_id_named_map_searches_class_dir() {
    // Operator put profiles in a sibling `profiles.d/family.toml`
    // rather than the master — the lookup must still find them.
    let dir = tmpdir();
    let master = dir.path().join("config.toml");
    std::fs::write(
        &master,
        "schema_version = 3\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    )
    .unwrap();
    std::fs::create_dir_all(dir.path().join("profiles.d")).unwrap();
    let split = dir.path().join("profiles.d").join("family.toml");
    std::fs::write(
        &split,
        r#"
[profiles.parents]
display_name = "Parents"

[profiles.kids]
display_name = "Kids"
"#,
    )
    .unwrap();
    let hit = find_target_for_id(&master, EntityClass::Profiles, "kids").unwrap();
    assert_eq!(hit, Some(split));
}

/// cli-h4: the owner lives in an include the config declares by a name
/// the `<class>.d` convention can never produce. Pre-fix the candidate
/// set was `[master] + parent/<class>.d/*.toml`, so this returned
/// `None` — and `resolve_existing_target_file` then fell through to the
/// creation heuristic, which writes a SECOND `[profiles.kids]` into the
/// master. The loader's named-map duplicate-key detection rejects that,
/// so the operator's `profile set` failed on a config that is valid.
///
/// Both asserts matter: `find_target_for_id` naming the right file, and
/// `resolve_existing_target_file` agreeing — the second is what every
/// mutating verb actually calls.
#[test]
fn find_target_for_id_reaches_a_non_conventional_declared_include() {
    let dir = tmpdir();
    let master = dir.path().join("config.toml");
    std::fs::write(
        &master,
        "schema_version = 3\nincludes = [\"custom/*.toml\"]\n\n\
         [server]\ndefault_profile = \"kids\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    )
    .unwrap();
    std::fs::create_dir_all(dir.path().join("custom")).unwrap();
    let split = dir.path().join("custom").join("policy.toml");
    std::fs::write(
        &split,
        "[profiles.kids]\ndisplay_name = \"Kids\"\n\n\
         [[devices]]\nid = \"laptop\"\ndisplay_name = \"Laptop\"\n\
         ip = \"10.0.0.5\"\nprofile = \"kids\"\n",
    )
    .unwrap();

    // `custom` is not, and cannot be, any EntityClass::dir_name().
    assert!(
        !EntityClass::Profiles.dir_name().starts_with("custom"),
        "fixture must not accidentally match the convention"
    );

    let hit = find_target_for_id(&master, EntityClass::Profiles, "kids").unwrap();
    assert_eq!(hit.as_deref(), Some(split.as_path()));
    let hit = find_target_for_id(&master, EntityClass::Devices, "laptop").unwrap();
    assert_eq!(hit.as_deref(), Some(split.as_path()));

    // The seat every mutating verb goes through must agree, or the
    // write still lands in the master and trips duplicate detection.
    let got = resolve_existing_target_file(&master, EntityClass::Devices, "laptop", None).unwrap();
    assert_eq!(got, split);
}

/// cli-h4 companion: widening the candidate set must not cost the
/// pre-existing coverage of an UNDECLARED `<class>.d/`. Such a tree is
/// inert as far as the daemon is concerned, but `set` / `remove` used
/// to resolve into it and operators may still be running one. The
/// convention is searched as a superset of the declared graph, never
/// as a replacement — this pins that.
#[test]
fn owner_candidate_files_keeps_an_undeclared_class_dir() {
    let dir = tmpdir();
    let master = dir.path().join("config.toml");
    // No `includes` line at all — the loader reads only the master.
    std::fs::write(
        &master,
        "schema_version = 3\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    )
    .unwrap();
    std::fs::create_dir_all(dir.path().join("devices.d")).unwrap();
    let orphan = dir.path().join("devices.d").join("laptop.toml");
    std::fs::write(
        &orphan,
        "[[devices]]\nid = \"laptop\"\ndisplay_name = \"L\"\nip = \"10.0.0.5\"\n",
    )
    .unwrap();

    let files = owner_candidate_files(&master, &[EntityClass::Devices]);
    assert_eq!(files[0], master, "master must stay first");
    assert!(
        files.contains(&orphan),
        "undeclared devices.d/ dropped from the candidate set: {files:?}"
    );
}

/// A file reachable both through the convention AND through a declared
/// glob is visited once, in the caller's own path spelling. A duplicate
/// would make `undo_inner` stage two writes for one file.
#[test]
fn owner_candidate_files_dedups_a_doubly_reachable_file() {
    let dir = tmpdir();
    let master = dir.path().join("config.toml");
    std::fs::write(
        &master,
        "schema_version = 3\nincludes = [\"devices.d/*.toml\"]\n\n\
         [server]\ndefault_profile = \"default\"\n\n\
         [profiles.default]\ndisplay_name = \"D\"\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    )
    .unwrap();
    std::fs::create_dir_all(dir.path().join("devices.d")).unwrap();
    let slice = dir.path().join("devices.d").join("a.toml");
    std::fs::write(
        &slice,
        "[[devices]]\nid = \"a\"\ndisplay_name = \"A\"\nip = \"10.0.0.1\"\n\
         profile = \"default\"\n",
    )
    .unwrap();

    let files = owner_candidate_files(&master, &[EntityClass::Devices]);
    assert_eq!(files.len(), 2, "master + one slice, not three: {files:?}");
    assert_eq!(files[0], master);
    assert_eq!(files[1], slice, "caller's spelling, not the canonical one");
}

#[test]
fn find_target_for_id_ignores_cross_shape_class_sections() {
    // A file that holds Devices (array-of-tables) but NO profiles
    // section must not yield a false positive when we ask for a
    // Profile id. Also pins that the shape-detection match arm
    // for `None` doesn't accidentally fall through.
    let dir = tmpdir();
    let master = dir.path().join("config.toml");
    std::fs::write(
        &master,
        r#"
[[devices]]
id = "iphone"
display_name = "iPhone"
ip = "10.0.0.1"
"#,
    )
    .unwrap();
    let hit = find_target_for_id(&master, EntityClass::Profiles, "iphone").unwrap();
    assert_eq!(hit, None);
}

// ── resolve_existing_target_file (rev2606 target-02) ──────────────

#[test]
fn resolve_existing_target_file_locates_owner_in_class_dir() {
    // A device lives in devices.d/laptop.toml; a decoy slice makes the
    // directory ambiguous for the heuristic, so only owner-resolution
    // can pick the right file.
    let dir = tmpdir();
    let master = dir.path().join("config.toml");
    std::fs::write(
        &master,
        "schema_version = 3\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    )
    .unwrap();
    std::fs::create_dir_all(dir.path().join("devices.d")).unwrap();
    let owner = dir.path().join("devices.d").join("laptop.toml");
    std::fs::write(
        &owner,
        "[[devices]]\nid = \"laptop\"\ndisplay_name = \"Laptop\"\nip = \"10.0.0.5\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("devices.d").join("other.toml"),
        "[[devices]]\nid = \"phone\"\ndisplay_name = \"Phone\"\nip = \"10.0.0.6\"\n",
    )
    .unwrap();

    // The heuristic alone would bail "ambiguous" with two files.
    assert!(resolve_target_file(&master, EntityClass::Devices, None).is_err());
    // Owner resolution finds the file the id actually lives in.
    let got = resolve_existing_target_file(&master, EntityClass::Devices, "laptop", None).unwrap();
    assert_eq!(got, owner);
}

#[test]
fn resolve_existing_target_file_explicit_into_wins() {
    // `--into` is honored verbatim, even if the id lives elsewhere.
    let dir = tmpdir();
    let master = dir.path().join("config.toml");
    std::fs::write(
        &master,
        "schema_version = 3\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    )
    .unwrap();
    let into = dir.path().join("devices.d").join("explicit.toml");
    let got =
        resolve_existing_target_file(&master, EntityClass::Devices, "laptop", Some(&into)).unwrap();
    assert_eq!(got, into);
}

#[test]
fn resolve_existing_target_file_falls_back_to_master_when_absent() {
    // Unknown id + no class dir → fall back to the master (the pre-fix
    // default), so a genuine not-found still surfaces downstream rather
    // than mis-writing.
    let dir = tmpdir();
    let master = dir.path().join("config.toml");
    std::fs::write(
        &master,
        "schema_version = 3\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    )
    .unwrap();
    let got = resolve_existing_target_file(&master, EntityClass::Devices, "ghost", None).unwrap();
    assert_eq!(got, master);
}

// ── effective_profile_for_device / count (rev2606 verbs-03) ───────
#[test]
fn effective_profile_counts_subnet_assigned_device() {
    // A device with no direct profile and no group, but whose IP falls
    // in a subnet, resolves to that subnet's profile. The old per-verb
    // count copies skipped the subnet level and would have returned the
    // global default instead.
    let dir = tmpdir();
    let master = dir.path().join("config.toml");
    std::fs::write(
        &master,
        r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[profiles.kids]
display_name = "Kids"

[[subnets]]
id = "lan-kids"
display_name = "Kids LAN"
cidrs = ["10.0.5.0/24"]
profile = "kids"

[[devices]]
id = "tablet"
display_name = "Tablet"
ip = "10.0.5.10"

[upstream]
servers = ["192.0.2.1:53"]
"#,
    )
    .unwrap();
    let now = time::OffsetDateTime::now_utc();
    let cfg = load_config(&master, now).unwrap().config;
    let dev = cfg
        .devices
        .iter()
        .find(|d| d.id.as_str() == "tablet")
        .unwrap();
    assert_eq!(
        effective_profile_for_device(&cfg, dev).map(|p| p.as_str().to_string()),
        Some("kids".to_string()),
    );
    assert_eq!(count_devices_on_profile(&master, "kids"), 1);
    assert_eq!(count_devices_on_profile(&master, "default"), 0);
}

// ── resolve_explicit_into_under containment (rev2606 rewrite-01) ──
#[test]
fn resolve_explicit_into_under_rejects_escapes_accepts_in_tree() {
    let dir = tmpdir();
    let master = dir.path().join("config.toml");
    std::fs::write(
        &master,
        "schema_version = 3\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    )
    .unwrap();
    // Absolute path outside the config tree → rejected.
    assert!(resolve_explicit_into_under(&master, Path::new("/etc/passwd")).is_err());
    // `..` traversal escaping the tree → rejected.
    assert!(resolve_explicit_into_under(&master, Path::new("../evil.toml")).is_err());
    // In-tree relative path → accepted.
    let ok = resolve_explicit_into_under(&master, Path::new("rules.d/x.toml")).unwrap();
    assert!(ok.ends_with("rules.d/x.toml"));
}

// ── pre-promote validating writers (rev2606 target-01) ──────────

/// Minimal valid multi-file tree: master + one device slice (profile
/// `default`) + the `default` profile. Returns (tempdir, master, slice).
fn valid_tree() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tmpdir();
    let root = dir.path();
    std::fs::create_dir_all(root.join("devices.d")).unwrap();
    std::fs::create_dir_all(root.join("profiles.d")).unwrap();
    std::fs::write(
        root.join("profiles.d/default.toml"),
        "[profiles.default]\ndisplay_name = \"Default\"\n",
    )
    .unwrap();
    let dev = root.join("devices.d/dev.toml");
    std::fs::write(
        &dev,
        "[[devices]]\nid = \"dev-one\"\ndisplay_name = \"One\"\nip = \"10.0.0.1\"\nprofile = \"default\"\n",
    )
    .unwrap();
    let master = root.join("config.toml");
    std::fs::write(
        &master,
        "schema_version = 3\nincludes = [\"devices.d/*.toml\", \"profiles.d/*.toml\"]\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    )
    .unwrap();
    (dir, master, dev)
}

fn device_entry(id: &str, ip: &str, profile: &str) -> Value {
    toml::from_str(&format!(
        "id = \"{id}\"\ndisplay_name = \"{id}\"\nip = \"{ip}\"\nprofile = \"{profile}\"\n"
    ))
    .unwrap()
}

#[test]
fn write_value_validated_refuses_crossref_invalid() {
    let (_d, master, dev) = valid_tree();
    let before = std::fs::read_to_string(&dev).unwrap();
    let (mut doc, _orig) = read_or_empty(&dev).unwrap();
    upsert_id_keyed(
        &mut doc,
        "devices",
        "dev-two",
        device_entry("dev-two", "10.0.0.2", "ghost"),
    )
    .unwrap();
    let err = write_value_validated(&master, &dev, &doc).unwrap_err();
    assert!(err.to_string().contains("ghost"), "must cite ghost: {err}");
    assert_eq!(
        std::fs::read_to_string(&dev).unwrap(),
        before,
        "slice must be byte-identical after a refused write"
    );
}

/// `s-tui-lists-edit-save-rejected`, message half. A rejected write has
/// to say *what* was rejected inside the space the operator can
/// actually see. The TUI renders this string in a fixed 2-row band and
/// hard-ellipsises the overflow, so a long preamble is not cosmetic —
/// it deletes the diagnosis. Two independent regressions are fenced:
/// the wrong category ("unknown field" for a bad *value*) and the
/// offending value being pushed past the visible budget.
#[test]
fn refusal_names_the_bad_value_early_and_does_not_call_it_a_bad_field() {
    // 2 rows x ~60 usable cells, minus the modal's own "⚠ " and
    // "validator: " prefixes. Anything past this is never read.
    const MODAL_VISIBLE_BUDGET: usize = 105;

    let (_d, master, _dev) = valid_tree();
    let (mut doc, _orig) = read_or_empty(&master).unwrap();
    upsert_id_keyed(
        &mut doc,
        "blocklists",
        "bad-list",
        toml::from_str(
            "id = \"bad-list\"\ndisplay_name = \"Bad\"\n\
             url = \"https://lists.purge.cc/privacy/ads.txt\"\nbase = \"block\"\n",
        )
        .unwrap(),
    )
    .unwrap();
    let err = write_value_validated(&master, &master, &doc)
        .unwrap_err()
        .to_string();

    assert!(
        !err.contains("unknown field"),
        "a bad value must not be reported as a bad field: {err}"
    );
    let at = err
        .find("block")
        .unwrap_or_else(|| panic!("offending value absent entirely: {err}"));
    assert!(
        at < MODAL_VISIBLE_BUDGET,
        "offending value sits at char {at}, past the {MODAL_VISIBLE_BUDGET}-char \
         band the operator can see — it would be ellipsised away: {err}"
    );
}

#[test]
fn write_value_validated_accepts_and_promotes() {
    let (_d, master, dev) = valid_tree();
    let (mut doc, _orig) = read_or_empty(&dev).unwrap();
    upsert_id_keyed(
        &mut doc,
        "devices",
        "dev-two",
        device_entry("dev-two", "10.0.0.2", "default"),
    )
    .unwrap();
    write_value_validated(&master, &dev, &doc).unwrap();
    assert!(std::fs::read_to_string(&dev).unwrap().contains("dev-two"));
}

/// The seat takes the tree's write lock.
///
/// Goes red if the `acquire` at the top of [`promote_validated`] is
/// removed, which is the mutation that reopens the rollback-clobbers-a-
/// committed-change interleaving described in
/// [`crate::config::write_lock`].
///
/// **The mutation this test canNOT catch is closed elsewhere, by the type
/// system rather than by a test.** Dropping the guard early (`let _ =`)
/// leaves the lock file created and every step unprotected, so this
/// assertion still passes — measured. That is why
/// [`promote_validated_locked`] takes `&ConfigWriteLock`: with the guard as
/// a parameter there is no binding left to mutate, and the early-drop shape
/// stops compiling instead of stopping protecting.
#[test]
fn the_promote_seat_takes_the_tree_write_lock() {
    let (_d, master, dev) = valid_tree();
    let lock = crate::config::write_lock::lock_path_for(&master);
    assert!(
        !lock.exists(),
        "fixture must start without a lock file, else this proves nothing"
    );

    let (mut doc, _orig) = read_or_empty(&dev).unwrap();
    upsert_id_keyed(
        &mut doc,
        "devices",
        "dev-two",
        device_entry("dev-two", "10.0.0.2", "default"),
    )
    .unwrap();
    write_value_validated(&master, &dev, &doc).unwrap();

    assert!(
        lock.exists(),
        "promote_validated must have taken {} — no lock file means no lock",
        lock.display()
    );
}

/// A REFUSED write still went through the lock.
///
/// The validation failure path returns before step 3, so a lock taken
/// "just before promoting" instead of at the top would leave the snapshot
/// and the whole validation unprotected and still pass the test above.
/// This one pins that the critical section starts at the function's first
/// line.
#[test]
fn even_a_refused_write_passed_through_the_lock() {
    let (_d, master, dev) = valid_tree();
    let lock = crate::config::write_lock::lock_path_for(&master);
    assert!(!lock.exists());

    // Reuse the existing invalid-cross-reference shape: a device pointing
    // at a profile that does not exist.
    let (mut doc, _orig) = read_or_empty(&dev).unwrap();
    upsert_id_keyed(
        &mut doc,
        "devices",
        "dev-bad",
        device_entry("dev-bad", "10.0.0.9", "no-such-profile"),
    )
    .unwrap();
    write_value_validated(&master, &dev, &doc)
        .expect_err("a dangling profile reference must be refused");

    assert!(
        lock.exists(),
        "the lock must be taken before validation, not just before promotion"
    );
}

/// The killer proof: a mutation the pre-write overlay accepts must load
/// clean through the daemon's own (no-overlay) loader afterwards.
#[test]
fn validate_write_reload_agreement() {
    let (_d, master, dev) = valid_tree();
    let (mut doc, _orig) = read_or_empty(&dev).unwrap();
    upsert_id_keyed(
        &mut doc,
        "devices",
        "dev-two",
        device_entry("dev-two", "10.0.0.2", "default"),
    )
    .unwrap();
    write_value_validated(&master, &dev, &doc).unwrap();
    let loaded = load_config(&master, time::OffsetDateTime::now_utc())
        .expect("post-write daemon load must agree with the pre-write verdict");
    assert_eq!(loaded.config.devices.len(), 2);
}

#[test]
fn write_values_validated_refuses_compound_dup_id() {
    let (_d, master, _dev) = valid_tree();
    let root = master.parent().unwrap();
    let a = root.join("devices.d/a.toml");
    let b = root.join("devices.d/b.toml");
    // Both NEW slices declare the same id → the COMBINED tree is invalid,
    // even though each slice is fine in isolation.
    let writes = vec![
        StagedWrite {
            final_path: a.clone(),
            content: "[[devices]]\nid = \"dup\"\ndisplay_name = \"A\"\nip = \"10.0.1.1\"\nprofile = \"default\"\n".to_string(),
        },
        StagedWrite {
            final_path: b.clone(),
            content: "[[devices]]\nid = \"dup\"\ndisplay_name = \"B\"\nip = \"10.0.1.2\"\nprofile = \"default\"\n".to_string(),
        },
    ];
    assert!(write_values_validated(&master, &writes).is_err());
    assert!(!a.exists() && !b.exists(), "nothing promoted on refusal");
}

#[test]
fn write_values_validated_promotes_all_on_success() {
    let (_d, master, _dev) = valid_tree();
    let root = master.parent().unwrap();
    let a = root.join("devices.d/a.toml");
    let b = root.join("devices.d/b.toml");
    let writes = vec![
        StagedWrite {
            final_path: a.clone(),
            content: "[[devices]]\nid = \"aa\"\ndisplay_name = \"A\"\nip = \"10.0.1.1\"\nprofile = \"default\"\n".to_string(),
        },
        StagedWrite {
            final_path: b.clone(),
            content: "[[devices]]\nid = \"bb\"\ndisplay_name = \"B\"\nip = \"10.0.1.2\"\nprofile = \"default\"\n".to_string(),
        },
    ];
    write_values_validated(&master, &writes).unwrap();
    assert!(a.exists() && b.exists());
    let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
    assert_eq!(loaded.config.devices.len(), 3, "dev-one + aa + bb");
}
