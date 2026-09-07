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
fn locked_target_resolution_handles_monolithic_one_and_many_candidates() {
    let monolithic = tmpdir();
    let master = monolithic.path().join("config.toml");
    std::fs::write(&master, "").unwrap();
    let guard = crate::config::write_lock::acquire_for_write(&master).unwrap();
    assert_eq!(
        resolve_target_file_locked(&guard, &master, EntityClass::Devices, None).unwrap(),
        master
    );

    let one = tmpdir();
    let master = one.path().join("config.toml");
    std::fs::write(&master, "").unwrap();
    let only = one.path().join("devices.d/one.toml");
    std::fs::create_dir_all(only.parent().unwrap()).unwrap();
    std::fs::write(&only, "").unwrap();
    std::fs::create_dir(one.path().join("devices.d/ignored.toml")).unwrap();
    let guard = crate::config::write_lock::acquire_for_write(&master).unwrap();
    assert_eq!(
        resolve_target_file_locked(&guard, &master, EntityClass::Devices, None).unwrap(),
        only
    );

    let many = tmpdir();
    let master = many.path().join("config.toml");
    std::fs::write(&master, "").unwrap();
    let slices = many.path().join("devices.d");
    std::fs::create_dir(&slices).unwrap();
    std::fs::write(slices.join("a.toml"), "").unwrap();
    std::fs::write(slices.join("b.toml"), "").unwrap();
    let guard = crate::config::write_lock::acquire_for_write(&master).unwrap();
    assert!(resolve_target_file_locked(&guard, &master, EntityClass::Devices, None).is_err());
}

#[test]
fn locked_target_resolution_bounds_candidate_names() {
    let dir = tmpdir();
    let master = dir.path().join("config.toml");
    std::fs::write(&master, "").unwrap();
    let slices = dir.path().join("devices.d");
    std::fs::create_dir(&slices).unwrap();
    for index in 0..=crate::config::loader::MAX_INCLUDE_FILES {
        std::fs::write(slices.join(format!("{index:04}.toml")), "").unwrap();
    }
    let guard = crate::config::write_lock::acquire_for_write(&master).unwrap();

    let error =
        resolve_target_file_locked(&guard, &master, EntityClass::Devices, None).unwrap_err();

    assert!(error.to_string().contains("hard cap"), "{error:#}");
}

#[test]
fn locked_target_helpers_reject_wrong_tree_and_outside_symlinks() {
    let dir = tmpdir();
    let master = dir.path().join("config.toml");
    let other = dir.path().join("other.toml");
    std::fs::write(&master, "").unwrap();
    std::fs::write(&other, "").unwrap();
    let guard = crate::config::write_lock::acquire_for_write(&master).unwrap();
    assert!(resolve_target_file_locked(&guard, &other, EntityClass::Devices, None).is_err());

    let outside = tmpdir();
    std::fs::create_dir(outside.path().join("devices.d")).unwrap();
    std::fs::write(outside.path().join("devices.d/external.toml"), "").unwrap();
    std::os::unix::fs::symlink(
        outside.path().join("devices.d"),
        dir.path().join("devices.d"),
    )
    .unwrap();
    assert!(resolve_target_file_locked(&guard, &master, EntityClass::Devices, None).is_err());
    assert!(resolve_explicit_into_under_locked(
        &guard,
        &master,
        outside.path().join("external.toml").as_path(),
    )
    .is_err());
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
        "schema_version = 4\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    )
    .unwrap();
    let (val, orig) = read_or_empty(&p).unwrap();
    assert_eq!(val.get("schema_version").unwrap().as_integer(), Some(4));
    assert_eq!(
        orig.as_deref(),
        Some("schema_version = 4\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n")
    );
}

#[test]
fn locked_read_missing_is_empty_and_parent_leaf_swap_cannot_redirect_it() {
    let dir = tmpdir();
    let master = dir.path().join("config.toml");
    std::fs::write(&master, "").unwrap();
    let missing = dir.path().join("missing.toml");
    let guard = crate::config::write_lock::acquire_for_write(&master).unwrap();
    let (empty, original) = read_or_empty_locked(&guard, &master, &missing).unwrap();
    assert!(empty.as_table().unwrap().is_empty());
    assert!(original.is_none());

    let parent = dir.path().join("slices");
    let leaf = parent.join("device.toml");
    std::fs::create_dir(&parent).unwrap();
    std::fs::write(&leaf, "name = \"original\"\n").unwrap();
    let outside = tmpdir();
    std::fs::write(
        outside.path().join("device.toml"),
        "name = \"redirected\"\n",
    )
    .unwrap();
    let old_parent = dir.path().join("slices.old");
    let alias = parent.clone();
    let replacement = outside.path().to_path_buf();
    let mut swapped = false;
    let (value, _) = crate::config::write_lock::with_test_hook(
        move |event| {
            if event == crate::config::write_lock::TestEvent::BeforeDataOpen && !swapped {
                swapped = true;
                std::fs::rename(&alias, &old_parent).unwrap();
                std::os::unix::fs::symlink(&replacement, &alias).unwrap();
            }
        },
        || read_or_empty_locked(&guard, &master, &leaf).unwrap(),
    );
    assert_eq!(value.get("name").and_then(Value::as_str), Some("original"));
}

#[test]
fn revert_removes_file_when_original_absent() {
    // `revert(path, None)` deletes a file that did not exist before the
    // (now rolled-back) write — the compound-writer mid-sequence rollback
    // relies on this for a freshly-created slice.
    let dir = tmpdir();
    let created = dir.path().join("new.toml");
    let guard =
        crate::config::write_lock::acquire_for_write(&dir.path().join("config.toml")).unwrap();
    let target = guard
        .tree_io()
        .plan_target(&created)
        .unwrap()
        .materialize()
        .unwrap();
    write_slice_syntax_checked(&target, "# newly promoted\n").unwrap();
    let res = revert(&target, None);
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
        "schema_version = 4\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
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
        "schema_version = 4\nincludes = [\"custom/*.toml\"]\n\n\
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

#[test]
fn locked_owner_lookup_reaches_a_non_conventional_declared_include() {
    let dir = tmpdir();
    let master = dir.path().join("config.toml");
    std::fs::write(
        &master,
        "schema_version = 4\nincludes = [\"custom/*.toml\"]\n\n\
         [server]\ndefault_profile = \"kids\"\n\n\
         [upstream]\nservers = [\"192.0.2.1:53\"]\n",
    )
    .unwrap();
    let custom = dir.path().join("custom");
    std::fs::create_dir(&custom).unwrap();
    let owner = custom.join("policy.toml");
    std::fs::write(
        &owner,
        "[profiles.kids]\ndisplay_name = \"Kids\"\n\n\
         [[devices]]\nid = \"laptop\"\ndisplay_name = \"Laptop\"\n\
         ip = \"10.0.0.5\"\nprofile = \"kids\"\n",
    )
    .unwrap();
    let guard = crate::config::write_lock::acquire_for_write(&master).unwrap();
    assert_eq!(
        find_target_for_id_locked(&guard, &master, EntityClass::Devices, "laptop").unwrap(),
        Some(owner.clone())
    );
    assert_eq!(
        resolve_existing_target_file_locked(&guard, &master, EntityClass::Profiles, "kids", None,)
            .unwrap(),
        owner
    );
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
        "schema_version = 4\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
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
        "schema_version = 4\nincludes = [\"devices.d/*.toml\"]\n\n\
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
        "schema_version = 4\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
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
        "schema_version = 4\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
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
        "schema_version = 4\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
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
        r#"schema_version = 4

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
        "schema_version = 4\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    )
    .unwrap();
    let guard = crate::config::write_lock::acquire_for_write(&master).unwrap();
    // Absolute path outside the config tree → rejected.
    assert!(resolve_explicit_into_under_locked(&guard, &master, Path::new("/etc/passwd")).is_err());
    // `..` traversal escaping the tree → rejected.
    assert!(
        resolve_explicit_into_under_locked(&guard, &master, Path::new("../evil.toml")).is_err()
    );
    // In-tree relative path → accepted.
    let ok =
        resolve_explicit_into_under_locked(&guard, &master, Path::new("rules.d/x.toml")).unwrap();
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
        "schema_version = 4\nincludes = [\"devices.d/*.toml\", \"profiles.d/*.toml\"]\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
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
fn locked_write_refuses_crossref_invalid() {
    let (_d, master, dev) = valid_tree();
    let guard = crate::config::write_lock::acquire_for_write(&master).unwrap();
    let before = std::fs::read_to_string(&dev).unwrap();
    let (mut doc, _orig) = read_or_empty_locked(&guard, &master, &dev).unwrap();
    upsert_id_keyed(
        &mut doc,
        "devices",
        "dev-two",
        device_entry("dev-two", "10.0.0.2", "ghost"),
    )
    .unwrap();
    let err = write_value_validated_locked(&guard, &master, &dev, &doc).unwrap_err();
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
    let guard = crate::config::write_lock::acquire_for_write(&master).unwrap();
    let (mut doc, _orig) = read_or_empty_locked(&guard, &master, &master).unwrap();
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
    let err = write_value_validated_locked(&guard, &master, &master, &doc)
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
fn locked_write_accepts_and_promotes() {
    let (_d, master, dev) = valid_tree();
    let guard = crate::config::write_lock::acquire_for_write(&master).unwrap();
    let (mut doc, _orig) = read_or_empty_locked(&guard, &master, &dev).unwrap();
    upsert_id_keyed(
        &mut doc,
        "devices",
        "dev-two",
        device_entry("dev-two", "10.0.0.2", "default"),
    )
    .unwrap();
    write_value_validated_locked(&guard, &master, &dev, &doc).unwrap();
    assert!(std::fs::read_to_string(&dev).unwrap().contains("dev-two"));
}

#[test]
fn locked_write_rejects_a_guard_from_another_tree_before_change() {
    let (_dir, master, dev) = valid_tree();
    let (_other_dir, other_master, _) = valid_tree();
    let before = std::fs::read_to_string(&dev).unwrap();
    let (doc, _) = read_or_empty(&dev).unwrap();
    let guard = crate::config::write_lock::acquire_for_write(&other_master).unwrap();

    let error = write_value_validated_locked(&guard, &master, &dev, &doc).unwrap_err();

    assert!(
        error.to_string().contains("config guard belongs to"),
        "{error:#}"
    );
    assert_eq!(std::fs::read_to_string(&dev).unwrap(), before);
}

#[test]
fn locked_write_resolves_members_inside_its_guarded_tree() {
    let (_dir, master, dev) = valid_tree();
    let outside_dir = tmpdir();
    let outside = outside_dir.path().join("outside.toml");
    let (doc, _) = read_or_empty(&dev).unwrap();
    let guard = crate::config::write_lock::acquire_for_write(&master).unwrap();

    let error = write_value_validated_locked(&guard, &master, &outside, &doc).unwrap_err();

    assert!(
        error.to_string().contains("escapes config root"),
        "{error:#}"
    );
    assert!(!outside.exists(), "outside-tree target must remain absent");
}

#[test]
fn locked_write_completes_under_a_live_guard() {
    let (_dir, master, dev) = valid_tree();
    let (mut doc, _) = read_or_empty(&dev).unwrap();
    upsert_id_keyed(
        &mut doc,
        "devices",
        "dev-two",
        device_entry("dev-two", "10.0.0.2", "default"),
    )
    .unwrap();
    let guard = crate::config::write_lock::acquire_for_write(&master).unwrap();

    write_value_validated_locked(&guard, &master, &dev, &doc).unwrap();

    assert!(std::fs::read_to_string(&dev).unwrap().contains("dev-two"));
}

#[test]
fn locked_single_write_refuses_replacements_after_preparation() {
    for replacement in ["existing leaf", "absent leaf", "parent directory"] {
        let (dir, master, dev) = valid_tree();
        let destination = if replacement == "absent leaf" {
            dir.path().join("devices.d/new.toml")
        } else {
            dev.clone()
        };
        let (mut doc, _) = read_or_empty(&destination).unwrap();
        upsert_id_keyed(
            &mut doc,
            "devices",
            "intended",
            device_entry("intended", "10.0.0.8", "default"),
        )
        .unwrap();
        let guard = crate::config::write_lock::acquire_for_write(&master).unwrap();
        let replacement_bytes = device_slice("replacement", "10.0.0.9");
        let replacement_path = destination.clone();
        let root = dir.path().to_path_buf();
        let saved_parent = root.join("saved-devices");
        let parent = root.join("devices.d");

        let error = write_value_validated_locked_after_prepare(
            &guard,
            &master,
            &destination,
            &doc,
            move || match replacement {
                "existing leaf" => {
                    let source = root.join("replacement.toml");
                    std::fs::write(&source, &replacement_bytes).unwrap();
                    std::fs::rename(source, replacement_path).unwrap();
                }
                "absent leaf" => std::fs::write(replacement_path, &replacement_bytes).unwrap(),
                "parent directory" => {
                    std::fs::rename(&parent, &saved_parent).unwrap();
                    std::fs::create_dir(&parent).unwrap();
                    std::fs::write(replacement_path, &replacement_bytes).unwrap();
                }
                _ => unreachable!(),
            },
        )
        .unwrap_err();

        assert_eq!(
            std::fs::read_to_string(&destination).unwrap(),
            device_slice("replacement", "10.0.0.9"),
            "{replacement} replacement must survive: {error:#}"
        );
    }
}

#[test]
fn locked_batch_rejects_wrong_guard_before_change() {
    let (_dir, master, dev) = valid_tree();
    let (_other_dir, other_master, _) = valid_tree();
    let before = std::fs::read_to_string(&dev).unwrap();
    let guard = crate::config::write_lock::acquire_for_write(&other_master).unwrap();

    let error = write_values_validated_locked(
        &guard,
        &master,
        &[StagedWrite {
            final_path: dev.clone(),
            content: device_slice("changed", "10.0.0.8"),
        }],
    )
    .unwrap_err();

    assert!(error.to_string().contains("config guard belongs to"));
    assert_eq!(std::fs::read_to_string(dev).unwrap(), before);
}

#[test]
fn locked_batch_rejects_mixed_out_of_tree_destinations_without_changes() {
    let (dir, master, dev) = valid_tree();
    let before = std::fs::read_to_string(&dev).unwrap();
    let outside_dir = tmpdir();
    let outside = outside_dir.path().join("new/escape.toml");
    let guard = crate::config::write_lock::acquire_for_write(&master).unwrap();

    let error = write_values_validated_locked(
        &guard,
        &master,
        &[
            StagedWrite {
                final_path: dev.clone(),
                content: device_slice("changed", "10.0.0.8"),
            },
            StagedWrite {
                final_path: outside.clone(),
                content: device_slice("escape", "10.0.0.9"),
            },
        ],
    )
    .unwrap_err();

    assert!(
        error.to_string().contains("escapes config root"),
        "{error:#}"
    );
    assert_eq!(std::fs::read_to_string(dev).unwrap(), before);
    assert!(!outside.parent().unwrap().exists());
    assert!(dir.path().join("devices.d").exists());
}

/// The caller takes the tree's write lock before its first protected read.
///
/// **The mutation this test canNOT catch is closed elsewhere, by the type
/// system rather than by a test.** Dropping the guard early (`let _ =`)
/// leaves the lock file created and every step unprotected, so this
/// assertion still passes — measured. That is why
/// [`promote_validated_locked`] takes `&ConfigWriteLock`: with the guard as
/// a parameter there is no binding left to mutate, and the early-drop shape
/// stops compiling instead of stopping protecting.
#[test]
fn the_locked_promote_seat_requires_an_explicit_tree_write_lock() {
    let (_d, master, dev) = valid_tree();
    let lock = crate::config::write_lock::ConfigTreeIdentity::resolve(&master)
        .unwrap()
        .lock_path;
    assert!(
        !lock.exists(),
        "fixture must start without a lock file, else this proves nothing"
    );

    let guard = crate::config::write_lock::acquire_for_write(&master).unwrap();
    let (mut doc, _orig) = read_or_empty_locked(&guard, &master, &dev).unwrap();
    upsert_id_keyed(
        &mut doc,
        "devices",
        "dev-two",
        device_entry("dev-two", "10.0.0.2", "default"),
    )
    .unwrap();
    write_value_validated_locked(&guard, &master, &dev, &doc).unwrap();

    assert!(
        lock.exists(),
        "the explicit acquiring route must create {} — no lock file means no lock",
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
fn even_a_refused_locked_write_holds_the_explicit_lock() {
    let (_d, master, dev) = valid_tree();
    let lock = crate::config::write_lock::ConfigTreeIdentity::resolve(&master)
        .unwrap()
        .lock_path;
    assert!(!lock.exists());

    // Reuse the existing invalid-cross-reference shape: a device pointing
    // at a profile that does not exist.
    let guard = crate::config::write_lock::acquire_for_write(&master).unwrap();
    let (mut doc, _orig) = read_or_empty_locked(&guard, &master, &dev).unwrap();
    upsert_id_keyed(
        &mut doc,
        "devices",
        "dev-bad",
        device_entry("dev-bad", "10.0.0.9", "no-such-profile"),
    )
    .unwrap();
    write_value_validated_locked(&guard, &master, &dev, &doc)
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
    let guard = crate::config::write_lock::acquire_for_write(&master).unwrap();
    let (mut doc, _orig) = read_or_empty_locked(&guard, &master, &dev).unwrap();
    upsert_id_keyed(
        &mut doc,
        "devices",
        "dev-two",
        device_entry("dev-two", "10.0.0.2", "default"),
    )
    .unwrap();
    write_value_validated_locked(&guard, &master, &dev, &doc).unwrap();
    drop(guard);
    let loaded = load_config(&master, time::OffsetDateTime::now_utc())
        .expect("post-write daemon load must agree with the pre-write verdict");
    assert_eq!(loaded.config.devices.len(), 2);
}

#[test]
fn promoting_a_master_alias_preserves_the_symlink_and_lock_identity() {
    let (_dir, master, _dev) = valid_tree();
    let alias = master.parent().unwrap().join("master-alias.toml");
    std::os::unix::fs::symlink("config.toml", &alias).unwrap();
    use std::os::unix::fs::MetadataExt;
    let alias_inode = std::fs::symlink_metadata(&alias).unwrap().ino();
    let identity = crate::config::write_lock::ConfigTreeIdentity::resolve(&alias).unwrap();
    let guard = crate::config::write_lock::acquire_for_write(&alias).unwrap();
    let (mut doc, _) = read_or_empty_locked(&guard, &alias, &alias).unwrap();
    doc.as_table_mut().unwrap().insert(
        "server".into(),
        toml::from_str("default_blocked_ttl_secs = 123").unwrap(),
    );
    let before = std::fs::read(&master).unwrap();
    write_value_validated_locked(&guard, &alias, &alias, &doc).unwrap();
    drop(guard);
    let after = std::fs::read_to_string(&master).unwrap();
    assert_eq!(
        std::fs::symlink_metadata(&alias).unwrap().ino(),
        alias_inode
    );
    assert_ne!(after.as_bytes(), before);
    assert_eq!(
        after.parse::<Value>().unwrap()["server"]["default_blocked_ttl_secs"].as_integer(),
        Some(123)
    );
    assert!(std::fs::symlink_metadata(&alias)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(
        crate::config::write_lock::ConfigTreeIdentity::resolve(&alias).unwrap(),
        identity
    );
    assert!(load_config(&alias, time::OffsetDateTime::now_utc()).is_ok());
}

#[test]
fn locked_batch_refuses_compound_dup_id() {
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
    let guard = crate::config::write_lock::acquire_for_write(&master).unwrap();
    assert!(write_values_validated_locked(&guard, &master, &writes).is_err());
    assert!(!a.exists() && !b.exists(), "nothing promoted on refusal");
}

#[test]
fn locked_write_seats_reject_reserved_master_and_member_names() {
    let (dir, master, _) = valid_tree();
    let guard = crate::config::write_lock::acquire_for_write(&master).unwrap();
    let before = std::fs::read(&master).unwrap();
    let (doc, _) = read_or_empty_locked(&guard, &master, &master).unwrap();
    for (index, name) in [
        ".warden-config.lock",
        ".warden-migration",
        ".warden-migration.cleanup-",
        ".warden-migration.cleanup-id",
        ".warden-write-",
        ".warden-write-residue",
    ]
    .iter()
    .enumerate()
    {
        let path = dir.path().join(name);
        assert!(write_value_validated_locked(&guard, &master, &path, &doc).is_err());
        let alias = dir.path().join(format!("reserved-alias-{index}.toml"));
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        assert!(write_value_validated_locked(&guard, &master, &alias, &doc).is_err());
        assert!(write_values_validated_locked(
            &guard,
            &master,
            &[StagedWrite {
                final_path: path.join("member.toml"),
                content: "schema_version = 4".into()
            }]
        )
        .is_err());
        if *name != ".warden-config.lock" {
            assert!(!path.exists());
        }
    }
    assert_eq!(std::fs::read(&master).unwrap(), before);
}

#[test]
fn locked_batch_promotes_all_on_success() {
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
    let guard = crate::config::write_lock::acquire_for_write(&master).unwrap();
    write_values_validated_locked(&guard, &master, &writes).unwrap();
    drop(guard);
    assert!(a.exists() && b.exists());
    let loaded = load_config(&master, time::OffsetDateTime::now_utc()).unwrap();
    assert_eq!(loaded.config.devices.len(), 3, "dev-one + aa + bb");
}

#[test]
fn historical_batch_uses_its_supplied_schema_contract() {
    let (_d, master, _dev) = valid_tree();
    let before = std::fs::read(&master).unwrap();
    let writes = [StagedWrite {
        final_path: master.clone(),
        content: String::from("schema_version = 4\n[upstream]\nservers = [\"192.0.2.1:53\"]\n"),
    }];
    let guard = crate::config::write_lock::acquire_for_write(&master).unwrap();

    let err = write_historical_values_validated_locked(&guard, &master, &writes, 2)
        .expect_err("the supplied historical schema must be enforced");
    assert!(
        err.to_string().contains("historical schema 2"),
        "got: {err}"
    );
    assert_eq!(std::fs::read(&master).unwrap(), before);
}

#[test]
fn historical_batch_refuses_a_new_member_unselected_by_final_includes() {
    let (_d, master, _dev) = valid_tree();
    let unselected = master.parent().unwrap().join("unselected.d/ignored.toml");
    let writes = [StagedWrite {
        final_path: unselected.clone(),
        content: "[upstream]\nservers = [\"192.0.2.1:53\"]\n".into(),
    }];
    let guard = crate::config::write_lock::acquire_for_write(&master).unwrap();

    let err = write_historical_values_validated_locked(&guard, &master, &writes, 3)
        .expect_err("an unselected output must not be promoted");
    assert!(
        err.to_string()
            .contains("not reached during overlay validation"),
        "got: {err}"
    );
    assert!(
        !unselected.exists(),
        "unselected member must not be promoted"
    );
}

#[test]
fn historical_batch_does_not_apply_secondary_mutation_gate() {
    let dir = tmpdir();
    let root = dir.path();
    std::fs::create_dir(root.join("cluster.d")).unwrap();
    let master = root.join("config.toml");
    std::fs::write(
        &master,
        format!(
            "schema_version = 3\nincludes = [\"cluster.d/*.toml\"]\n\
             [cluster]\nenabled = true\nrole = \"secondary\"\n\
             peer = \"https://10.10.1.94:8053\"\ntoken_hash = \"{}\"\n",
            "00".repeat(32),
        ),
    )
    .unwrap();
    std::fs::write(
        root.join("cluster.d/00-synced.toml"),
        "[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    )
    .unwrap();
    let local_policy = root.join("cluster.d/01-historical.toml");
    let writes = [StagedWrite {
        final_path: local_policy.clone(),
        content: "[[blocklists]]\nid = \"historical\"\ndisplay_name = \"Historical\"\n\
                  url = \"https://example.invalid/list.txt\"\n"
            .into(),
    }];
    let guard = crate::config::write_lock::acquire_for_write(&master).unwrap();

    write_historical_values_validated_locked(&guard, &master, &writes, 3)
        .expect("historical batches must not inherit the normal secondary mutation gate");
    assert!(local_policy.exists());
}

#[test]
fn historical_batch_rolls_back_malformed_before_image_raw() {
    use crate::config::atomic_write::AtomicWriteTestFailure;

    let (_d, master, _dev) = valid_tree();
    let final_master = std::fs::read_to_string(&master).unwrap().replacen(
        "schema_version = 4",
        "schema_version = 3",
        1,
    );
    let malformed = "this = [ is deliberately malformed\n";
    std::fs::write(&master, malformed).unwrap();
    let writes = [StagedWrite {
        final_path: master.clone(),
        content: final_master,
    }];
    let guard = crate::config::write_lock::acquire_for_write(&master).unwrap();

    let err = promote_historical_prepared_locked_with_ops(
        &guard,
        &master,
        &writes,
        3,
        |path, content| {
            write_slice_raw_with_opts(
                path,
                content,
                AtomicWriteAtOpts {
                    test_failure: Some(AtomicWriteTestFailure::ParentFsync),
                    ..Default::default()
                },
            )
        },
        revert_raw,
    )
    .expect_err("post-rename failure must roll back");

    assert!(err.to_string().contains("rolled back"), "got: {err}");
    assert_eq!(std::fs::read_to_string(&master).unwrap(), malformed);
}

fn device_slice(id: &str, ip: &str) -> String {
    format!(
        "[[devices]]\nid = \"{id}\"\ndisplay_name = \"{id}\"\nip = \"{ip}\"\nprofile = \"default\"\n"
    )
}

#[test]
fn post_rename_failure_rolls_back_current_and_earlier_slices() {
    use crate::config::atomic_write::AtomicWriteTestFailure;

    let (_d, master, _dev) = valid_tree();
    let root = master.parent().unwrap();
    let earlier = root.join("devices.d/earlier.toml");
    let current = root.join("devices.d/current.toml");
    let earlier_before = device_slice("earlier-old", "10.0.2.1");
    let current_before = device_slice("current-old", "10.0.2.2");
    let earlier_after = device_slice("earlier-new", "10.0.2.3");
    let current_after = device_slice("current-new", "10.0.2.4");
    std::fs::write(&earlier, &earlier_before).unwrap();
    std::fs::write(&current, &current_before).unwrap();
    let writes = vec![
        StagedWrite {
            final_path: earlier.clone(),
            content: earlier_after,
        },
        StagedWrite {
            final_path: current.clone(),
            content: current_after,
        },
    ];
    let lock = crate::config::write_lock::acquire_for_write(&master).unwrap();

    let err = promote_validated_locked_with_ops(
        &lock,
        &master,
        &writes,
        |path, content| {
            let opts = if path.display() == current {
                AtomicWriteAtOpts {
                    test_failure: Some(AtomicWriteTestFailure::ParentFsync),
                    ..Default::default()
                }
            } else {
                AtomicWriteAtOpts::default()
            };
            write_slice_syntax_checked_with_opts(path, content, opts)
        },
        revert,
    )
    .unwrap_err();

    let message = err.to_string();
    assert!(message.contains("renamed the target"), "got: {message}");
    assert!(message.contains("current and 1 earlier"), "got: {message}");
    assert_eq!(std::fs::read_to_string(&current).unwrap(), current_before);
    assert_eq!(std::fs::read_to_string(&earlier).unwrap(), earlier_before);
}

#[test]
fn post_rename_failure_with_rollback_failure_requires_recovery() {
    use crate::config::atomic_write::AtomicWriteTestFailure;

    let (_d, master, _dev) = valid_tree();
    let root = master.parent().unwrap();
    let earlier = root.join("devices.d/earlier.toml");
    let current = root.join("devices.d/current.toml");
    let earlier_before = device_slice("earlier-old", "10.0.3.1");
    let current_before = device_slice("current-old", "10.0.3.2");
    let earlier_after = device_slice("earlier-new", "10.0.3.3");
    let current_after = device_slice("current-new", "10.0.3.4");
    std::fs::write(&earlier, &earlier_before).unwrap();
    std::fs::write(&current, &current_before).unwrap();
    let writes = vec![
        StagedWrite {
            final_path: earlier.clone(),
            content: earlier_after.clone(),
        },
        StagedWrite {
            final_path: current.clone(),
            content: current_after,
        },
    ];
    let lock = crate::config::write_lock::acquire_for_write(&master).unwrap();

    let err = promote_validated_locked_with_ops(
        &lock,
        &master,
        &writes,
        |path, content| {
            let opts = if path.display() == current {
                AtomicWriteAtOpts {
                    test_failure: Some(AtomicWriteTestFailure::ParentOpen),
                    ..Default::default()
                }
            } else {
                AtomicWriteAtOpts::default()
            };
            write_slice_syntax_checked_with_opts(path, content, opts)
        },
        |path, original| {
            if path.display() == earlier {
                anyhow::bail!("injected rollback failure")
            }
            revert(path, original)
        },
    )
    .unwrap_err();

    let message = err.to_string();
    assert!(message.contains("rollback incomplete"), "got: {message}");
    assert!(message.contains("recovery required"), "got: {message}");
    assert!(
        message.contains(&earlier.display().to_string()),
        "got: {message}"
    );
    assert_eq!(std::fs::read_to_string(&current).unwrap(), current_before);
    assert_eq!(
        std::fs::read_to_string(&earlier).unwrap(),
        earlier_after,
        "the reported failed rollback must leave evidence for recovery"
    );
}

#[test]
fn promotion_uses_pinned_parent_after_root_swap() {
    let (dir, master, dev) = valid_tree();
    let moved = tempfile::tempdir().unwrap();
    let old = moved.path().join("old");
    let old_for_hook = old.clone();
    let root = dir.path().to_path_buf();
    let replacement = root.clone();
    let after = device_slice("changed", "10.0.8.1");
    let lock = crate::config::write_lock::acquire_for_write(&master).unwrap();
    crate::config::write_lock::with_test_hook(
        move |event| {
            if event == crate::config::write_lock::TestEvent::BeforePromotion {
                std::fs::rename(&replacement, &old_for_hook).unwrap();
                std::fs::create_dir(&replacement).unwrap();
                std::fs::create_dir(replacement.join("devices.d")).unwrap();
                std::fs::write(
                    replacement.join("devices.d/dev.toml"),
                    "replacement sentinel",
                )
                .unwrap();
            }
        },
        || {
            promote_validated_locked(
                &lock,
                &master,
                &[StagedWrite {
                    final_path: dev.clone(),
                    content: after.clone(),
                }],
            )
            .unwrap()
        },
    );
    assert_eq!(
        std::fs::read_to_string(old.join("devices.d/dev.toml")).unwrap(),
        after
    );
    assert_eq!(
        std::fs::read_to_string(&dev).unwrap(),
        "replacement sentinel"
    );
}

#[test]
fn promotion_uses_original_parent_after_alias_retarget() {
    let (dir, master, dev) = valid_tree();
    let outside = tempfile::tempdir().unwrap();
    let alias = dir.path().join("alias");
    std::os::unix::fs::symlink("devices.d", &alias).unwrap();
    let external = outside.path().to_path_buf();
    std::fs::write(external.join("dev.toml"), "external sentinel").unwrap();
    let destination = alias.join("dev.toml");
    let after = device_slice("changed", "10.0.8.2");
    let lock = crate::config::write_lock::acquire_for_write(&master).unwrap();
    crate::config::write_lock::with_test_hook(
        move |event| {
            if event == crate::config::write_lock::TestEvent::BeforePromotion {
                std::fs::remove_file(&alias).unwrap();
                std::os::unix::fs::symlink(&external, &alias).unwrap();
            }
        },
        || {
            promote_validated_locked(
                &lock,
                &master,
                &[StagedWrite {
                    final_path: destination,
                    content: after.clone(),
                }],
            )
            .unwrap()
        },
    );
    assert_eq!(std::fs::read_to_string(&dev).unwrap(), after);
    assert_eq!(
        std::fs::read_to_string(outside.path().join("dev.toml")).unwrap(),
        "external sentinel"
    );
}

#[test]
fn leaf_swap_refuses_promotion_without_writing_external_bytes() {
    let (_dir, master, dev) = valid_tree();
    let outside = tempfile::tempdir().unwrap();
    let external = outside.path().join("sentinel");
    std::fs::write(&external, "external sentinel").unwrap();
    let planted = dev.clone();
    let link = external.clone();
    let lock = crate::config::write_lock::acquire_for_write(&master).unwrap();
    let err = crate::config::write_lock::with_test_hook(
        move |event| {
            if event == crate::config::write_lock::TestEvent::BeforePromotion {
                std::fs::remove_file(&planted).unwrap();
                std::os::unix::fs::symlink(&link, &planted).unwrap();
            }
        },
        || {
            promote_validated_locked(
                &lock,
                &master,
                &[StagedWrite {
                    final_path: dev.clone(),
                    content: device_slice("changed", "10.0.8.3"),
                }],
            )
            .unwrap_err()
        },
    );
    assert!(err.to_string().contains("failed before its rename"));
    assert!(std::fs::symlink_metadata(&dev)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(
        std::fs::read_to_string(external).unwrap(),
        "external sentinel"
    );
}

#[test]
fn rollback_restores_current_and_earlier_files_in_moved_root() {
    use crate::config::atomic_write::AtomicWriteTestFailure;
    let (dir, master, earlier) = valid_tree();
    let moved = tempfile::tempdir().unwrap();
    let old = moved.path().join("old");
    let current = dir.path().join("devices.d/current.toml");
    let earlier_before = std::fs::read_to_string(&earlier).unwrap();
    let current_before = device_slice("current-old", "10.0.8.4");
    std::fs::write(&current, &current_before).unwrap();
    let writes = [
        StagedWrite {
            final_path: earlier.clone(),
            content: device_slice("earlier-new", "10.0.8.5"),
        },
        StagedWrite {
            final_path: current.clone(),
            content: device_slice("current-new", "10.0.8.6"),
        },
    ];
    let lock = crate::config::write_lock::acquire_for_write(&master).unwrap();
    let mut rollback_order = Vec::new();
    let err = promote_validated_locked_with_ops(
        &lock,
        &master,
        &writes,
        |target, content| {
            if target.display() == current {
                let result = write_slice_syntax_checked_with_opts(
                    target,
                    content,
                    AtomicWriteAtOpts {
                        test_failure: Some(AtomicWriteTestFailure::ParentFsync),
                        ..Default::default()
                    },
                );
                std::fs::rename(dir.path(), &old).unwrap();
                std::fs::create_dir(dir.path()).unwrap();
                std::fs::create_dir(dir.path().join("devices.d")).unwrap();
                std::fs::write(&earlier, "replacement earlier").unwrap();
                std::fs::write(&current, "replacement current").unwrap();
                result
            } else {
                write_slice_syntax_checked(target, content)
            }
        },
        |target, before| {
            rollback_order.push(target.display().to_path_buf());
            revert(target, before)
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("current and 1 earlier"));
    assert_eq!(rollback_order, vec![current.clone(), earlier.clone()]);
    assert_eq!(
        std::fs::read_to_string(old.join("devices.d/dev.toml")).unwrap(),
        earlier_before
    );
    assert_eq!(
        std::fs::read_to_string(old.join("devices.d/current.toml")).unwrap(),
        current_before
    );
    assert_eq!(
        std::fs::read_to_string(earlier).unwrap(),
        "replacement earlier"
    );
    assert_eq!(
        std::fs::read_to_string(current).unwrap(),
        "replacement current"
    );
}

#[test]
fn absent_rollback_refuses_a_replacement_symlink() {
    let (dir, master, current) = valid_tree();
    let outside = tempfile::tempdir().unwrap();
    let sentinel = outside.path().join("sentinel");
    std::fs::write(&sentinel, "external sentinel").unwrap();
    let earlier = dir.path().join("devices.d/new.toml");
    let current_before = std::fs::read_to_string(&current).unwrap();
    let writes = [
        StagedWrite {
            final_path: earlier.clone(),
            content: device_slice("new-first", "10.0.8.7"),
        },
        StagedWrite {
            final_path: current.clone(),
            content: device_slice("changed-second", "10.0.8.8"),
        },
    ];
    let lock = crate::config::write_lock::acquire_for_write(&master).unwrap();
    let err = promote_validated_locked_with_ops(
        &lock,
        &master,
        &writes,
        |target, content| {
            if target.display() == current {
                std::fs::remove_file(&earlier).unwrap();
                std::os::unix::fs::symlink(&sentinel, &earlier).unwrap();
                Err(AtomicWriteError::Validation {
                    target: current.clone(),
                    reason: "injected".into(),
                })
            } else {
                write_slice_syntax_checked(target, content)
            }
        },
        revert,
    )
    .unwrap_err();
    assert!(err
        .to_string()
        .contains("rollback incomplete and recovery required"));
    assert!(std::fs::symlink_metadata(&earlier)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(std::fs::read_to_string(&current).unwrap(), current_before);
    assert_eq!(
        std::fs::read_to_string(sentinel).unwrap(),
        "external sentinel"
    );
}

#[test]
fn overlay_requires_the_staged_document_after_include_parent_drift_and_restoration() {
    use crate::config::write_lock::{with_test_hook, TestEvent};
    let (dir, master, dev) = valid_tree();
    let before = std::fs::read_to_string(&dev).unwrap();
    let original_parent = dir.path().join("devices.d");
    let saved_parent = dir.path().join("saved-devices");
    let decoy = dir.path().join("decoy");
    std::fs::create_dir(&decoy).unwrap();
    std::fs::write(decoy.join("dev.toml"), &before).unwrap();
    let staged = before.replace("profile = \"default\"", "profile = \"ghost\"");
    let restored = std::rc::Rc::new(std::cell::Cell::new(false));
    let restored_hook = restored.clone();
    let lock = crate::config::write_lock::acquire_for_write(&master).unwrap();
    let error = with_test_hook(
        move |event| {
            if event == TestEvent::BeforeOverlay {
                std::fs::rename(&original_parent, &saved_parent).unwrap();
                std::os::unix::fs::symlink("decoy", &original_parent).unwrap();
            } else if event == TestEvent::OverlayResolved {
                std::fs::remove_file(&original_parent).unwrap();
                std::fs::rename(&saved_parent, &original_parent).unwrap();
                restored_hook.set(true);
            }
        },
        || {
            promote_validated_locked_with_ops(
                &lock,
                &master,
                &[StagedWrite {
                    final_path: dev.clone(),
                    content: staged,
                }],
                |_, _| panic!("unvalidated cross-reference bytes reached promotion"),
                revert,
            )
            .unwrap_err()
        },
    );
    assert!(
        restored.get(),
        "the include spelling was restored before the verdict"
    );
    assert!(
        error
            .to_string()
            .contains("staged config document was not reached"),
        "{error:#}"
    );
    assert_eq!(std::fs::read_to_string(&dev).unwrap(), before);
    assert_eq!(
        std::fs::read_to_string(decoy.join("dev.toml")).unwrap(),
        before
    );
}

#[test]
fn overlay_binds_parent_inodes_even_when_the_member_key_does_not_change() {
    use crate::config::write_lock::{with_test_hook, TestEvent};
    let (dir, master, dev) = valid_tree();
    let before = std::fs::read_to_string(&dev).unwrap();
    let parent = dir.path().join("devices.d");
    let saved = dir.path().join("saved");
    let swapped_parent = parent.clone();
    let saved_parent = saved.clone();
    let decoy = before.clone();
    let lock = crate::config::write_lock::acquire_for_write(&master).unwrap();
    let error = with_test_hook(
        move |event| {
            if event == TestEvent::BeforeOverlay {
                std::fs::rename(&swapped_parent, &saved_parent).unwrap();
                std::fs::create_dir(&swapped_parent).unwrap();
                std::fs::write(swapped_parent.join("dev.toml"), &decoy).unwrap();
            }
        },
        || {
            promote_validated_locked(
                &lock,
                &master,
                &[StagedWrite {
                    final_path: dev.clone(),
                    content: device_slice("changed", "10.0.9.1"),
                }],
            )
            .unwrap_err()
        },
    );
    assert!(
        error.to_string().contains("overlay destination changed"),
        "{error:#}"
    );
    assert_eq!(std::fs::read_to_string(&dev).unwrap(), before);
    assert_eq!(
        std::fs::read_to_string(saved.join("dev.toml")).unwrap(),
        before
    );
}

#[test]
fn rollback_preserves_snapshot_bytes_mode_and_owner_despite_metadata_changes() {
    use crate::config::atomic_write::AtomicWriteTestFailure;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let (dir, master, earlier) = valid_tree();
    let current = dir.path().join("devices.d/current.toml");
    std::fs::write(&current, device_slice("current", "10.0.9.2")).unwrap();
    for path in [&earlier, &current] {
        if unsafe { libc::geteuid() } == 0 {
            std::os::unix::fs::lchown(path, Some(65534), Some(65534)).unwrap();
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640)).unwrap();
    }
    let before: Vec<_> = [&earlier, &current]
        .into_iter()
        .map(|path| {
            (
                std::fs::read(path).unwrap(),
                std::fs::metadata(path).unwrap(),
            )
        })
        .collect();
    let lock = crate::config::write_lock::acquire_for_write(&master).unwrap();
    let writes = [
        StagedWrite {
            final_path: earlier.clone(),
            content: device_slice("earlier-new", "10.0.9.3"),
        },
        StagedWrite {
            final_path: current.clone(),
            content: device_slice("current-new", "10.0.9.4"),
        },
    ];
    let error = promote_validated_locked_with_ops(
        &lock,
        &master,
        &writes,
        |target, content| {
            // The retained before inode can still be chmod'ed after its snapshot.
            std::fs::set_permissions(target.display(), std::fs::Permissions::from_mode(0o666))
                .unwrap();
            write_slice_syntax_checked_with_opts(
                target,
                content,
                AtomicWriteAtOpts {
                    mode: Some(0o600),
                    test_failure: (target.display() == current)
                        .then_some(AtomicWriteTestFailure::ParentFsync),
                    ..Default::default()
                },
            )
        },
        revert,
    )
    .unwrap_err();
    assert!(error.to_string().contains("were rolled back"), "{error:#}");
    for (path, (bytes, metadata)) in [&earlier, &current].into_iter().zip(before) {
        let restored = std::fs::metadata(path).unwrap();
        assert_eq!(std::fs::read(path).unwrap(), bytes);
        assert_eq!(
            (restored.mode() & 0o7777, restored.uid(), restored.gid()),
            (metadata.mode() & 0o7777, metadata.uid(), metadata.gid())
        );
    }
}

#[test]
fn rollback_refuses_unexpected_regular_leaf_for_existing_and_absent_before_images() {
    for present in [false, true] {
        let (dir, master, current) = valid_tree();
        let earlier = dir.path().join("devices.d/earlier.toml");
        if present {
            std::fs::write(&earlier, device_slice("earlier", "10.0.9.5")).unwrap();
        }
        let replacement = dir.path().join("replacement");
        std::fs::write(&replacement, "replacement sentinel").unwrap();
        let writes = [
            StagedWrite {
                final_path: earlier.clone(),
                content: device_slice("earlier-new", "10.0.9.6"),
            },
            StagedWrite {
                final_path: current.clone(),
                content: device_slice("current-new", "10.0.9.7"),
            },
        ];
        let lock = crate::config::write_lock::acquire_for_write(&master).unwrap();
        let error = promote_validated_locked_with_ops(
            &lock,
            &master,
            &writes,
            |target, content| {
                if target.display() == current {
                    std::fs::rename(&replacement, &earlier).unwrap();
                    Err(AtomicWriteError::Validation {
                        target: current.clone(),
                        reason: "injected failure after external replacement".into(),
                    })
                } else {
                    write_slice_syntax_checked(target, content)
                }
            },
            revert,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("rollback incomplete and recovery required"),
            "{error:#}"
        );
        assert!(error.to_string().contains("rollback target was replaced"));
        assert_eq!(
            std::fs::read_to_string(&earlier).unwrap(),
            "replacement sentinel"
        );
    }
}

#[test]
fn locked_invalid_overlay_does_not_materialize_missing_parents() {
    let (dir, master, _) = valid_tree();
    let destination = dir.path().join("new/deep/file.toml");
    let guard = crate::config::write_lock::acquire_for_write(&master).unwrap();
    let err = write_values_validated_locked(
        &guard,
        &master,
        &[StagedWrite {
            final_path: destination,
            content:
                "[[devices]]\nid = \"invalid\"\nip = \"10.0.8.9\"\nprofile = \"nonexistent\"\n"
                    .into(),
        }],
    )
    .unwrap_err();
    assert!(err.to_string().contains("nothing written"));
    assert!(!dir.path().join("new").exists());
}

#[test]
fn duplicate_target_aliases_are_refused_before_promotion() {
    let (dir, master, dev) = valid_tree();
    let alias = dir.path().join("alias");
    std::os::unix::fs::symlink("devices.d/dev.toml", &alias).unwrap();
    let content = device_slice("changed", "10.0.8.10");
    let guard = crate::config::write_lock::acquire_for_write(&master).unwrap();
    let before = std::fs::read(&dev).unwrap();
    let err = write_values_validated_locked(
        &guard,
        &master,
        &[
            StagedWrite {
                final_path: dev.clone(),
                content: content.clone(),
            },
            StagedWrite {
                final_path: alias,
                content,
            },
        ],
    )
    .unwrap_err();
    assert!(err.to_string().contains("duplicate staged"));
    assert_eq!(std::fs::read(dev).unwrap(), before);
}

#[test]
fn guarded_promotion_refuses_a_master_leaf_redirected_into_another_locked_tree() {
    for present in [false, true] {
        let dir = tmpdir();
        let master = dir.path().join("config.toml");
        let content = "schema_version = 4\n[upstream]\nservers = [\"192.0.2.1:53\"]\n";
        if present {
            std::fs::write(&master, content).unwrap();
        }
        let lock = crate::config::write_lock::acquire_for_write(&master).unwrap();
        let nested = dir.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        let nested_master = nested.join("config.toml");
        std::fs::write(&nested_master, content).unwrap();
        let other = crate::config::write_lock::acquire_for_migration(&nested_master).unwrap();
        crate::config::migration_journal::create_fence(&other).unwrap();
        if present {
            std::fs::remove_file(&master).unwrap();
        }
        std::os::unix::fs::symlink("nested/config.toml", &master).unwrap();
        let error = promote_validated_locked(
            &lock,
            &master,
            &[StagedWrite {
                final_path: master.clone(),
                content: content.replace("192.0.2.1", "192.0.2.2"),
            }],
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("canonical master changed"),
            "{error:#}"
        );
        assert_eq!(std::fs::read_to_string(nested_master).unwrap(), content);
        assert!(std::fs::symlink_metadata(master)
            .unwrap()
            .file_type()
            .is_symlink());
    }
}

mod cs8_secondary_policy_guard {
    use super::*;
    use std::path::Path;

    const TOKEN_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PEER: &str = "https://192.0.2.10:8053";

    fn secondary_master(enabled: bool) -> String {
        format!(
            r#"schema_version = 4
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

    const BUNDLE: &str = r#"[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#;

    const PRIMARY_MASTER: &str = r#"schema_version = 4
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

    const DISABLED_SECONDARY_MASTER: &str = r#"schema_version = 4
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

    const DEVICE_SLICE: &str = r#"[[devices]]
id = "tablet"
display_name = "Tablet"
ip = "192.0.2.50"
"#;
    const PROFILE_SLICE: &str = "[profiles.extra]\ndisplay_name = \"Extra\"\n";

    struct Node {
        _dir: tempfile::TempDir,
        master: std::path::PathBuf,
    }

    impl Node {
        fn new(master_toml: &str, bundle: Option<&str>) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let master = dir.path().join("config.toml");
            std::fs::write(&master, master_toml).unwrap();
            if let Some(bundle) = bundle {
                let dropin = dir.path().join("cluster.d");
                std::fs::create_dir_all(&dropin).unwrap();
                std::fs::write(dropin.join("00-cluster-policy.toml"), bundle).unwrap();
            }
            Self { _dir: dir, master }
        }

        fn secondary() -> Self {
            Self::new(&secondary_master(true), Some(BUNDLE))
        }

        fn slice(&self, rel: &str) -> std::path::PathBuf {
            self.master.parent().unwrap().join(rel)
        }

        fn write_one(&self, rel: &str, content: &str) -> anyhow::Result<()> {
            let guard = crate::config::write_lock::acquire_for_write(&self.master)?;
            let path = self.slice(rel);
            write_value_validated_locked(&guard, &self.master, &path, &toml_value(content))
        }

        fn write_many(&self, files: &[(&str, &str)]) -> anyhow::Result<()> {
            let guard = crate::config::write_lock::acquire_for_write(&self.master)?;
            let writes = files
                .iter()
                .map(|(rel, content)| StagedWrite {
                    final_path: self.slice(rel),
                    content: (*content).to_string(),
                })
                .collect::<Vec<_>>();
            write_values_validated_locked(&guard, &self.master, &writes)
        }
    }

    fn toml_value(content: &str) -> Value {
        toml::from_str(content).expect("fixture parses as TOML")
    }

    fn assert_is_cs8_refusal(err: &anyhow::Error) {
        assert!(
            err.to_string()
                .contains("policy is read-only on a cluster secondary"),
            "expected the CS8 refusal, got: {err}"
        );
    }

    fn assert_absent(path: &Path) {
        assert!(
            !path.exists(),
            "refused write left {} behind",
            path.display()
        );
    }

    #[test]
    fn secondary_refuses_single_policy_write() {
        let node = Node::secondary();
        let err = node
            .write_one("devices.d/tablet.toml", DEVICE_SLICE)
            .expect_err("secondary policy must be read-only");
        assert_is_cs8_refusal(&err);
        assert_absent(&node.slice("devices.d/tablet.toml"));
    }

    #[test]
    fn secondary_refusal_names_primary_and_section() {
        let node = Node::secondary();
        let err = node
            .write_one("devices.d/tablet.toml", DEVICE_SLICE)
            .expect_err("refused");
        let message = err.to_string();
        assert!(message.contains(PEER), "got: {message}");
        assert!(message.contains("devices"), "got: {message}");
    }

    #[test]
    fn secondary_permits_cluster_and_listen_writes() {
        let node = Node::secondary();
        let guard = crate::config::write_lock::acquire_for_write(&node.master).unwrap();
        let relisten = secondary_master(true).replace("127.0.0.1:15353", "127.0.0.1:15354");
        write_value_validated_locked(&guard, &node.master, &node.master, &toml_value(&relisten))
            .expect("secondary owns server.listen");
        let renamed = secondary_master(true).replace(
            "role = \"secondary\"",
            "role = \"secondary\"\nnode_name = \"second\"",
        );
        write_value_validated_locked(&guard, &node.master, &node.master, &toml_value(&renamed))
            .expect("secondary owns cluster identity");
    }

    #[test]
    fn secondary_refuses_compound_policy_write() {
        let node = Node::secondary();
        let err = node
            .write_many(&[
                ("devices.d/tablet.toml", DEVICE_SLICE),
                ("profiles.d/extra.toml", PROFILE_SLICE),
            ])
            .expect_err("compound policy must be read-only");
        assert_is_cs8_refusal(&err);
        assert_absent(&node.slice("devices.d/tablet.toml"));
        assert_absent(&node.slice("profiles.d/extra.toml"));
    }

    #[test]
    fn secondary_refuses_writes_into_sync_owned_drop_in() {
        let node = Node::secondary();
        let err = node
            .write_one("cluster.d/01-local.toml", DEVICE_SLICE)
            .expect_err("sync-owned policy must be read-only");
        assert_is_cs8_refusal(&err);
        assert_absent(&node.slice("cluster.d/01-local.toml"));
    }

    #[test]
    fn primary_permits_single_and_compound_policy_writes() {
        let node = Node::new(PRIMARY_MASTER, None);
        node.write_one("devices.d/tablet.toml", DEVICE_SLICE)
            .unwrap();
        let second = DEVICE_SLICE
            .replace("tablet", "phone")
            .replace("Tablet", "Phone")
            .replace("192.0.2.50", "192.0.2.51");
        node.write_many(&[
            ("devices.d/second.toml", &second),
            ("profiles.d/extra.toml", PROFILE_SLICE),
        ])
        .unwrap();
    }

    #[test]
    fn disabled_or_missing_cluster_is_unaffected() {
        for master in [
            DISABLED_SECONDARY_MASTER.to_string(),
            DISABLED_SECONDARY_MASTER
                .split("[cluster]")
                .next()
                .unwrap()
                .to_string(),
        ] {
            Node::new(&master, None)
                .write_one("devices.d/tablet.toml", DEVICE_SLICE)
                .expect("standalone node owns its policy");
        }
    }

    #[test]
    fn cs8_refusal_strings_are_frozen() {
        assert_eq!(
            CLUSTER_SECONDARY_POLICY_READ_ONLY,
            "policy is read-only on a cluster secondary — edit it on the primary ({peer}); \
             it arrives at the next sync. Nothing written. Sections: {sections}"
        );
        assert_eq!(CLUSTER_PEER_UNSET, "`cluster.peer` unset");
        let head = CLUSTER_SECONDARY_POLICY_READ_ONLY
            .split_once("{peer}")
            .expect("template names peer")
            .0;
        let prefix_cells = head.chars().count() + PEER.chars().count() + 1;
        assert!(
            prefix_cells <= 105,
            "actionable refusal prefix occupies {prefix_cells} cells"
        );
    }
}
