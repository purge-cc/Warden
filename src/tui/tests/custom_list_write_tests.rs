use super::*;

/// A master carrying a profile with fields a naive rebuild would drop:
/// a display name, an admin rule and a per-list policy map.
fn master_with(dir: &tempfile::TempDir, kids_extra: &str) -> PathBuf {
    std::fs::create_dir_all(dir.path().join("packs")).unwrap();
    std::fs::write(
        dir.path().join("packs").join("videogames.txt"),
        "# hand-written\n||tracking.example.com^\n",
    )
    .unwrap();
    let master = dir.path().join("config.toml");
    std::fs::write(
        &master,
        format!(
            r#"schema_version = 3

[upstream]
servers = ["192.0.2.1:53"]

[server]
default_profile = "default"

[[blocklists]]
id = "privacy-ads"
display_name = "Ads"
url = "https://lists.purge.cc/ads.txt"
tags = ["uncategorized"]

[[custom_lists]]
id = "videogames"
display_name = "Video games"

[profiles.default]
display_name = "Default"

[profiles.kids]
display_name = "Kids"
{kids_extra}
"#
        ),
    )
    .unwrap();
    master
}

fn reload(master: &Path) -> crate::config::loader::LoadedConfig {
    match crate::config::loader::load_config(master, time::OffsetDateTime::now_utc()) {
        Ok(c) => c,
        Err(e) => panic!("fixture invalid: {e:?}"),
    }
}

/// **A field added to `CustomList` must break the BUILD, not vanish on
/// the next save.**
///
/// `upsert_id_keyed` replaces the entry it finds, so any field
/// `custom_list_value` omits is reset to its serde default on the next
/// save — of anything, not of that field. This is the class project rules
/// records as `build_blocklist_value`, where the omitted field was
/// `accept_unsigned_allow` and the loss was silent.
///
/// Two halves, and both are needed: the destructuring fails to compile
/// when a field is added, and the length check fails when one is
/// dropped from the builder.
#[test]
fn every_custom_list_field_is_written() {
    use crate::config::schema::{CustomList, Id};
    let entity = CustomList {
        id: Id::new("videogames").unwrap(),
        display_name: "Video games".to_string(),
        description: "the kids' allowances".to_string(),
    };
    let CustomList {
        id,
        display_name,
        description,
    } = &entity;

    let value = custom_list_value(&custom_list_modal::ResolvedForm {
        id: id.as_str().to_string(),
        display_name: display_name.clone(),
        description: description.clone(),
    });
    let t = value.as_table().expect("a [[custom_lists]] row is a table");
    assert_eq!(t.get("id").and_then(|v| v.as_str()), Some(id.as_str()));
    assert_eq!(
        t.get("display_name").and_then(|v| v.as_str()),
        Some(display_name.as_str())
    );
    assert_eq!(
        t.get("description").and_then(|v| v.as_str()),
        Some(description.as_str())
    );
    assert_eq!(
        t.len(),
        3,
        "the builder writes a different number of keys than CustomList \
             has fields — one of them will reset on the next save"
    );
}

/// The file goes down BEFORE the declaration, because
/// `write_value_validated` runs the whole loader and `build_store`
/// fails the entire config on one unreadable pack.
#[test]
fn creating_writes_the_pack_file_and_the_declaration() {
    let dir = tempfile::tempdir().unwrap();
    let master = master_with(&dir, "");

    create_custom_list(
        &master,
        &custom_list_modal::ResolvedForm {
            id: "tv".to_string(),
            display_name: "Telly".to_string(),
            description: String::new(),
        },
    )
    .expect("create must succeed");

    assert!(
        dir.path().join("packs").join("tv.txt").exists(),
        "the pack file must exist, so `missing` is unambiguously a fault"
    );
    let after = reload(&master);
    assert!(after
        .config
        .custom_lists
        .iter()
        .any(|c| c.id.as_str() == "tv"));
    assert!(
        after
            .custom_lists
            .contains_key(&crate::config::schema::Id::new("tv").unwrap()),
        "the new list must load, not just parse"
    );
}

/// **`create_pack` OVERWRITES and `upsert_id_keyed` REPLACES**, so a
/// create on a taken id would destroy that list's rules before the
/// config write was even attempted. It is refused up front.
#[test]
fn creating_refuses_a_taken_id_without_touching_its_file() {
    let dir = tempfile::tempdir().unwrap();
    let master = master_with(&dir, "");
    let pack = dir.path().join("packs").join("videogames.txt");
    let before = std::fs::read_to_string(&pack).unwrap();

    let err = create_custom_list(
        &master,
        &custom_list_modal::ResolvedForm {
            id: "videogames".to_string(),
            display_name: "Clash".to_string(),
            description: String::new(),
        },
    )
    .expect_err("a taken id must be refused");
    assert!(err.contains("already exists"), "got: {err}");
    assert_eq!(
        std::fs::read_to_string(&pack).unwrap(),
        before,
        "the existing pack must be byte-identical — this is where 32 \
             hand-written rules would have gone"
    );
}

/// Removing drops the declaration and LEAVES the file.
///
/// Unlinking first and then failing the config write would leave the
/// config naming a file that is gone, and `build_store` fails the whole
/// config on one missing pack — the next reload would drop every other
/// list too.
#[test]
fn removing_drops_the_declaration_and_leaves_the_pack_file() {
    let dir = tempfile::tempdir().unwrap();
    let master = master_with(&dir, "");

    remove_custom_list(&master, "videogames").expect("remove must succeed");

    assert!(reload(&master).config.custom_lists.is_empty());
    assert!(
        dir.path().join("packs").join("videogames.txt").exists(),
        "the operator's rules must survive the declaration going"
    );
}

/// Editing metadata must not touch the rules.
#[test]
fn editing_metadata_leaves_the_pack_file_byte_identical() {
    let dir = tempfile::tempdir().unwrap();
    let master = master_with(&dir, "");
    let pack = dir.path().join("packs").join("videogames.txt");
    let before = std::fs::read_to_string(&pack).unwrap();

    update_custom_list_meta(
        &master,
        &custom_list_modal::ResolvedForm {
            id: "videogames".to_string(),
            display_name: "Renamed".to_string(),
            description: "a note".to_string(),
        },
    )
    .expect("edit must succeed");

    assert_eq!(std::fs::read_to_string(&pack).unwrap(), before);
    let after = reload(&master);
    let e = &after.config.custom_lists[0];
    assert_eq!(e.display_name, "Renamed");
    assert_eq!(e.description, "a note");
}

/// A pack shaped like a real one: comment headings organising the
/// rules, a blank between sections, and a line the grammar refuses.
const MESSY_PACK: &str = "\
# ---- Minecraft / Mojang ----
@@||minecraft.net^
||tracking.example.com^

# ---- broken on purpose ----
*.wildcard.example.com
||ads.example.com^
";

fn app_on(master: &Path) -> App {
    let mut app = App::new();
    app.active_leaf = Leaf::CustomLists;
    app.loaded_config = load_v1_config(master);
    app.custom_lists.selected_id = Some("videogames".to_string());
    app
}

fn count_comments(text: &str) -> usize {
    text.lines()
        .filter(|l| l.trim_start().starts_with('#'))
        .count()
}

fn count_refused(text: &str) -> usize {
    use crate::config::custom_list::parse_pack_line;
    text.lines().filter(|l| parse_pack_line(l).is_err()).count()
}

/// **The trip-wire that outranks every other test here.**
///
/// Reading a pack is permissive — an unparseable line is skipped and
/// counted, and the file loads. Writing one with `write_pack` is
/// strict: the first invalid line rejects the whole write. So a save
/// that rebuilt the file from the rows the rule pane drew would either
/// FAIL on a file that had loaded cleanly, or "repair" it by deleting
/// every comment and every skipped line. A pack in the field carries
/// more comment lines than rules.
///
/// This adds a rule through the TUI's own path and recounts both. They
/// must be untouched — and the new line must be at the END, because
/// that is what `add_rule` guarantees and what keeps every other rule
/// under the comment heading that describes it.
#[test]
fn adding_a_rule_from_the_tui_destroys_no_comment_and_no_broken_line() {
    let dir = tempfile::tempdir().unwrap();
    let master = master_with(&dir, "");
    let pack = dir.path().join("packs").join("videogames.txt");
    std::fs::write(&pack, MESSY_PACK).unwrap();

    let before = std::fs::read_to_string(&pack).unwrap();
    let comments_before = count_comments(&before);
    let refused_before = count_refused(&before);
    assert!(comments_before >= 2, "the fixture must carry comments");
    assert!(
        refused_before >= 1,
        "the fixture must carry a line the reader refuses, or this \
             test cannot see the loss it exists for"
    );

    let app = app_on(&master);
    add_rule_to_pack(&app, "videogames", "new.example.com", false).expect("the add must land");

    let after = std::fs::read_to_string(&pack).unwrap();
    assert_eq!(
        count_comments(&after),
        comments_before,
        "a comment was destroyed:\n{after}"
    );
    assert_eq!(
        count_refused(&after),
        refused_before,
        "a line the reader had skipped was destroyed:\n{after}"
    );
    assert!(
        before.lines().all(|l| after.lines().any(|a| a == l)),
        "every original line must survive verbatim:\n{after}"
    );
    assert_eq!(
        after.lines().last(),
        Some("||new.example.com^"),
        "the new rule appends at the END, so nothing is torn out of \
             the section its comment heading describes"
    );
}

/// Removing is the same contract from the other side.
#[test]
fn removing_a_rule_from_the_tui_destroys_no_comment_and_no_broken_line() {
    let dir = tempfile::tempdir().unwrap();
    let master = master_with(&dir, "");
    let pack = dir.path().join("packs").join("videogames.txt");
    std::fs::write(&pack, MESSY_PACK).unwrap();
    let before = std::fs::read_to_string(&pack).unwrap();

    let app = app_on(&master);
    remove_rule_from_pack(&app, "videogames", "tracking.example.com")
        .expect("the remove must land");

    let after = std::fs::read_to_string(&pack).unwrap();
    assert_eq!(count_comments(&after), count_comments(&before));
    assert_eq!(count_refused(&after), count_refused(&before));
    assert!(!after.contains("tracking.example.com"));
    assert!(
        after.contains("@@||minecraft.net^"),
        "the neighbouring rules must survive:\n{after}"
    );
}

/// **`remove_rule` matches the domain and ignores the direction.** A
/// domain carrying both an allow and a deny loses two lines to one
/// keystroke, which is why the confirm counts them.
#[test]
fn removing_takes_both_directions_of_the_same_domain() {
    let dir = tempfile::tempdir().unwrap();
    let master = master_with(&dir, "");
    let pack = dir.path().join("packs").join("videogames.txt");
    std::fs::write(
        &pack,
        "# both ways\n@@||both.example.com^\n||both.example.com^\n||other.example.com^\n",
    )
    .unwrap();

    let app = app_on(&master);
    remove_rule_from_pack(&app, "videogames", "both.example.com").unwrap();

    let after = std::fs::read_to_string(&pack).unwrap();
    assert!(
        !after.contains("both.example.com"),
        "both directions must go — this is what the confirm warns about:\n{after}"
    );
    assert!(after.contains("||other.example.com^"));
    assert!(after.contains("# both ways"));
}

/// Adding the same rule twice is idempotent and says so, rather than
/// reporting a no-op as a fresh write.
#[test]
fn adding_a_rule_that_is_already_there_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let master = master_with(&dir, "");
    let pack = dir.path().join("packs").join("videogames.txt");
    std::fs::write(&pack, MESSY_PACK).unwrap();
    let before = std::fs::read_to_string(&pack).unwrap();

    let app = app_on(&master);
    let msg = add_rule_to_pack(&app, "videogames", "ads.example.com", false).unwrap();

    assert!(msg.contains("already"), "got: {msg}");
    assert_eq!(std::fs::read_to_string(&pack).unwrap(), before);
}

/// The grammar admits two forms and nothing else. A wildcard belongs in
/// `[[admin_rules]]`, which is scanned linearly on every query — a file
/// an operator can grow to tens of thousands of lines must not reach it.
#[test]
fn a_wildcard_is_refused_rather_than_written() {
    let dir = tempfile::tempdir().unwrap();
    let master = master_with(&dir, "");
    let pack = dir.path().join("packs").join("videogames.txt");
    std::fs::write(&pack, MESSY_PACK).unwrap();
    let before = std::fs::read_to_string(&pack).unwrap();

    let app = app_on(&master);
    add_rule_to_pack(&app, "videogames", "*.evil.example.com", false)
        .expect_err("a wildcard must be refused");

    assert_eq!(
        std::fs::read_to_string(&pack).unwrap(),
        before,
        "a refused rule must write nothing at all"
    );
}

/// **The trip-wire for the whole mount path.**
///
/// `upsert_profile` does `profiles.insert(id, entry)`, and inserting
/// into a TOML table replaces the value whole — so a mount built by
/// constructing a fresh profile value would silently drop everything
/// else on that table. This asserts the neighbours survive; it fails
/// on any implementation that rebuilds the profile instead of editing
/// the one already there.
#[test]
fn mounting_preserves_every_other_field_of_the_profile() {
    let dir = tempfile::tempdir().unwrap();
    let master = master_with(
        &dir,
        "block_all = true\nadmin_rules = []\n\n[profiles.kids.lists]\nprivacy-ads = \"deny\"",
    );

    apply_custom_list_mounts(&master, "videogames", &[("kids".to_string(), true)])
        .expect("the mount must apply");

    let after = reload(&master);
    let kids = &after.config.profiles["kids"];
    assert_eq!(
        kids.custom_lists
            .iter()
            .map(|i| i.as_str())
            .collect::<Vec<_>>(),
        vec!["videogames"],
        "the mount itself must land"
    );
    assert_eq!(kids.display_name, "Kids", "display_name must survive");
    assert!(kids.block_all, "block_all must survive");
    assert!(
        !kids.lists.is_empty(),
        "the per-list policy map must survive — this is the field a \
             rebuilt profile value loses most quietly"
    );
    // And the OTHER profile is untouched.
    assert_eq!(after.config.profiles["default"].display_name, "Default");
}

/// Unmounting the last list REMOVES the key. `Profile::custom_lists`
/// carries `skip_serializing_if` precisely so an empty mount list does
/// not grow `custom_lists = []` into files that never opted in.
#[test]
fn unmounting_the_last_list_removes_the_key_rather_than_emptying_it() {
    let dir = tempfile::tempdir().unwrap();
    let master = master_with(&dir, "custom_lists = [\"videogames\"]");

    apply_custom_list_mounts(&master, "videogames", &[("kids".to_string(), false)])
        .expect("the unmount must apply");

    let text = std::fs::read_to_string(&master).unwrap();
    assert!(
        !text.contains("custom_lists = []"),
        "an empty array must not be written; got:\n{text}"
    );
    assert!(reload(&master).config.profiles["kids"]
        .custom_lists
        .is_empty());
}

/// Two profiles in one file are two edits to one document. Reading the
/// current mounts off the merged config instead of off the document
/// being edited would make the second edit overwrite the first.
#[test]
fn mounting_two_profiles_in_one_file_keeps_both() {
    let dir = tempfile::tempdir().unwrap();
    let master = master_with(&dir, "");

    apply_custom_list_mounts(
        &master,
        "videogames",
        &[("kids".to_string(), true), ("default".to_string(), true)],
    )
    .expect("both mounts must apply");

    let after = reload(&master);
    for p in ["kids", "default"] {
        assert_eq!(
            after.config.profiles[p]
                .custom_lists
                .iter()
                .map(|i| i.as_str())
                .collect::<Vec<_>>(),
            vec!["videogames"],
            "{p} lost its mount"
        );
    }
}

/// Mounting must not duplicate an id a profile already carries.
#[test]
fn mounting_something_already_mounted_does_not_duplicate_it() {
    let dir = tempfile::tempdir().unwrap();
    let master = master_with(&dir, "custom_lists = [\"videogames\"]");

    apply_custom_list_mounts(&master, "videogames", &[("kids".to_string(), true)])
        .expect("re-mounting must be idempotent");

    assert_eq!(
        reload(&master).config.profiles["kids"].custom_lists.len(),
        1
    );
}

/// The writer edits the profile that is there; it never creates one.
/// A mount that invented `[profiles.<id>]` would install a profile
/// with no policy at all, which the resolver would then hand to
/// whatever device pointed at it.
#[test]
fn the_writer_refuses_a_profile_the_document_does_not_declare() {
    let mut doc: toml::Value = "[profiles.kids]\ndisplay_name = \"Kids\"\n"
        .parse()
        .unwrap();
    let err = set_profile_custom_lists(&mut doc, "ghost", &["videogames".to_string()])
        .expect_err("an undeclared profile must be refused, not created");
    assert!(err.contains("ghost"), "the error must name it; got {err}");
    assert!(
        doc.get("profiles").unwrap().get("ghost").is_none(),
        "nothing may be created"
    );
}

/// Comments in the operator's own file survive the mount. The write
/// goes through `render_preserving` for this reason.
#[test]
fn the_operators_comments_survive_a_mount() {
    let dir = tempfile::tempdir().unwrap();
    let master = master_with(&dir, "");
    let extra = "\n# ---- household policy, do not reorder ----\n";
    let mut text = std::fs::read_to_string(&master).unwrap();
    text.push_str(extra);
    std::fs::write(&master, &text).unwrap();

    apply_custom_list_mounts(&master, "videogames", &[("kids".to_string(), true)])
        .expect("the mount must apply");

    let after = std::fs::read_to_string(&master).unwrap();
    assert!(
        after.contains("# ---- household policy, do not reorder ----"),
        "a comment was destroyed by the write; got:\n{after}"
    );
}
