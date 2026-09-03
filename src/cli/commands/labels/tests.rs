use super::*;

fn mk_master(dir: &tempfile::TempDir) -> PathBuf {
    let master = dir.path().join("config.toml");
    std::fs::write(
        &master,
        r#"schema_version = 3

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[[devices]]
id = "iphone"
display_name = "iPhone"
mac = "AA:BB:CC:DD:EE:01"
owner = "Dweller"

[[devices]]
id = "tv"
display_name = "TV"
mac = "AA:BB:CC:DD:EE:02"

[upstream]
servers = ["192.0.2.1:53"]
"#,
    )
    .unwrap();
    master
}

/// Socket path that does not exist → `attempt_reload` lands on
/// `DaemonUnreachable`, which is benign here.
fn fake_socket(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("ghost.sock")
}

fn labels_of(master: &Path) -> Vec<Label> {
    load_config(master, time::OffsetDateTime::now_utc())
        .unwrap()
        .config
        .labels
}

#[tokio::test]
async fn add_label_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    run_add(
        &master,
        &sock,
        "dweller",
        "owner",
        Some("Dweller"),
        Some("Dispositivi personali"),
        None,
    )
    .await
    .unwrap();
    let labels = labels_of(&master);
    assert_eq!(labels.len(), 1);
    assert_eq!(labels[0].kind, LabelKind::Owner);
    assert_eq!(labels[0].display_name, "Dweller");
    assert_eq!(
        labels[0].description.as_deref(),
        Some("Dispositivi personali")
    );
}

#[tokio::test]
async fn add_defaults_display_name_to_the_id() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    run_add(&master, &sock, "laptop", "device-type", None, None, None)
        .await
        .unwrap();
    assert_eq!(labels_of(&master)[0].display_name, "laptop");
}

#[tokio::test]
async fn add_rejects_unknown_kind() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    let err = run_add(&master, &sock, "x", "colour", None, None, None)
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("colour"), "got: {msg}");
    assert!(msg.contains("device-type"), "must list valid kinds: {msg}");
}

/// When BOTH arguments are bad, the id is named first — and this test
/// is the only thing holding that order in place.
///
/// The monolithic verb ran `Id::new` before `parse_kind`. The seam
/// takes an already-parsed `LabelKind`, so `parse_kind` necessarily
/// moved ahead of it; `run_add` re-validates the id deliberately to
/// put the original order back. Nothing else can see that:
/// `add_rejects_unknown_kind` above passes a VALID id, and the
/// byte-for-byte CLI capture never pairs two bad arguments. Without
/// this, a later reader deletes the "redundant" re-check, the message
/// silently flips to naming the kind, and every gate stays green —
/// the comment on that line cannot fail a build, so it is not the
/// guard. This is.
#[tokio::test]
async fn add_names_the_bad_id_before_the_bad_kind() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    let err = run_add(&master, &sock, "Bad_Id", "colour", None, None, None)
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("invalid id"), "must name the id first: {msg}");
    assert!(
        !msg.contains("colour"),
        "naming the kind means the id check no longer runs first: {msg}"
    );
}

/// The same id under a different kind must still be accepted — that
/// is R1, and it is the reason this module does not use
/// `upsert_id_keyed`.
#[tokio::test]
async fn same_id_under_two_kinds_coexists() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    run_add(&master, &sock, "personal", "department", None, None, None)
        .await
        .unwrap();
    run_add(&master, &sock, "personal", "device-type", None, None, None)
        .await
        .unwrap();
    let labels = labels_of(&master);
    assert_eq!(
        labels.len(),
        2,
        "the department row must survive the device-type add"
    );
    let kinds: Vec<LabelKind> = labels.iter().map(|l| l.kind).collect();
    assert!(kinds.contains(&LabelKind::Department));
    assert!(kinds.contains(&LabelKind::DeviceType));
}

/// A `kind` move reaches the same end state as `remove`: the row leaves
/// the vocabulary its referents read, and every device pointing at it is
/// left naming a value no label of that kind declares. `remove` refuses
/// that, so `set` refuses it too, in the same words.
#[tokio::test]
async fn set_kind_refuses_while_a_device_still_reads_the_old_kind() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    // `iphone` carries `owner = "Dweller"`, which this label declares.
    run_add(
        &master,
        &sock,
        "dweller",
        "owner",
        Some("Dweller"),
        None,
        None,
    )
    .await
    .unwrap();

    let err = run_set(&master, &sock, "dweller", "kind", "department", None, None)
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("still used by"), "got: {msg}");
    assert!(
        msg.contains("device iphone.owner"),
        "the refusal must name the referent: {msg}"
    );

    let labels = labels_of(&master);
    assert_eq!(labels.len(), 1);
    assert_eq!(
        labels[0].kind,
        LabelKind::Owner,
        "a refused move must leave the row where it was"
    );
}

/// The guard is on the referents, not on the move — an unreferenced
/// label still changes kind. Without this, a guard that simply refused
/// every move would pass the test above.
#[tokio::test]
async fn set_kind_still_moves_an_unreferenced_label() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    run_add(&master, &sock, "spare", "owner", None, None, None)
        .await
        .unwrap();

    run_set(&master, &sock, "spare", "kind", "department", None, None)
        .await
        .unwrap();

    let labels = labels_of(&master);
    assert_eq!(labels.len(), 1);
    assert_eq!(labels[0].kind, LabelKind::Department);
}

/// `add_inner` builds a WHOLE ROW and `upsert_label` replaces a matched
/// `(kind, id)` row outright, so any field the builder omits is reset to
/// its serde default on a replace.
///
/// The defence is this destructuring, NOT a comment: prose does not fail
/// a build. `let Label { .. }` is exhaustive on purpose — no `..` — so a
/// fifth field on `Label` stops this compiling and someone has to decide
/// whether `add` should write it.
#[tokio::test]
async fn every_label_field_is_considered_by_the_row_builder() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);

    run_add(
        &master,
        &sock,
        "dweller",
        "owner",
        Some("Dweller"),
        Some("primary account"),
        None,
    )
    .await
    .expect("add");

    let labels = labels_of(&master);
    let l = labels
        .iter()
        .find(|l| l.id.as_str() == "dweller")
        .expect("label present after add");

    // Exhaustive. Adding a field to `Label` breaks THIS LINE first.
    let Label {
        id,
        kind,
        display_name,
        description,
    } = l;

    assert_eq!(id.as_str(), "dweller");
    assert_eq!(*kind, LabelKind::Owner);
    assert_eq!(display_name, "Dweller");
    assert_eq!(description.as_deref(), Some("primary account"));
}

#[tokio::test]
async fn add_refuses_duplicate_pair() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    run_add(&master, &sock, "dweller", "owner", None, None, None)
        .await
        .unwrap();
    let err = run_add(&master, &sock, "dweller", "owner", None, None, None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("already exists"), "got: {err}");
}

#[tokio::test]
async fn set_display_name_and_clear_description() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    run_add(&master, &sock, "dweller", "owner", None, Some("note"), None)
        .await
        .unwrap();
    run_set(
        &master,
        &sock,
        "dweller",
        "display_name",
        "Dweller",
        None,
        None,
    )
    .await
    .unwrap();
    run_set(&master, &sock, "dweller", "description", "", None, None)
        .await
        .unwrap();
    let labels = labels_of(&master);
    assert_eq!(labels[0].display_name, "Dweller");
    assert!(labels[0].description.is_none());
}

/// Without `--kind`, an id carried by two kinds must be refused —
/// never silently resolved to whichever row is first on disk.
#[tokio::test]
async fn set_refuses_an_ambiguous_id_without_kind() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    run_add(&master, &sock, "personal", "department", None, None, None)
        .await
        .unwrap();
    run_add(&master, &sock, "personal", "device-type", None, None, None)
        .await
        .unwrap();
    let err = run_set(&master, &sock, "personal", "display_name", "P", None, None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("--kind"), "got: {err}");
}

#[tokio::test]
async fn set_with_kind_edits_only_that_row() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    run_add(&master, &sock, "personal", "department", None, None, None)
        .await
        .unwrap();
    run_add(&master, &sock, "personal", "device-type", None, None, None)
        .await
        .unwrap();
    run_set(
        &master,
        &sock,
        "personal",
        "display_name",
        "Personal",
        Some("device-type"),
        None,
    )
    .await
    .unwrap();
    let labels = labels_of(&master);
    let dt = labels
        .iter()
        .find(|l| l.kind == LabelKind::DeviceType)
        .unwrap();
    let dept = labels
        .iter()
        .find(|l| l.kind == LabelKind::Department)
        .unwrap();
    assert_eq!(dt.display_name, "Personal");
    assert_eq!(
        dept.display_name, "personal",
        "the department row must be untouched"
    );
}

#[tokio::test]
async fn set_kind_refuses_a_collision() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    run_add(&master, &sock, "personal", "department", None, None, None)
        .await
        .unwrap();
    run_add(&master, &sock, "personal", "device-type", None, None, None)
        .await
        .unwrap();
    let err = run_set(
        &master,
        &sock,
        "personal",
        "kind",
        "device-type",
        Some("department"),
        None,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("already exists"), "got: {err}");
}

#[tokio::test]
async fn set_unknown_field_refused() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    run_add(&master, &sock, "dweller", "owner", None, None, None)
        .await
        .unwrap();
    let err = run_set(&master, &sock, "dweller", "colour", "red", None, None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("unknown field"), "got: {err}");
}

#[tokio::test]
async fn remove_clean() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    run_add(&master, &sock, "laptop", "device-type", None, None, None)
        .await
        .unwrap();
    run_remove(&master, &sock, "laptop", None, None)
        .await
        .unwrap();
    assert!(labels_of(&master).is_empty());
}

#[tokio::test]
async fn remove_absent_label_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    assert!(run_remove(&master, &sock, "ghost", None, None)
        .await
        .is_ok());
}

/// The verb refuses; the validator only warns. A label a device
/// still uses cannot be deleted out from under it.
#[tokio::test]
async fn remove_refuses_while_a_device_uses_it() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    let sock = fake_socket(&dir);
    // The fixture device carries `owner = "Dweller"`, matched by
    // this label's display_name.
    run_add(
        &master,
        &sock,
        "dweller",
        "owner",
        Some("Dweller"),
        None,
        None,
    )
    .await
    .unwrap();
    let err = run_remove(&master, &sock, "dweller", None, None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("iphone"), "got: {err}");
    assert_eq!(labels_of(&master).len(), 1, "nothing may be removed");
}

// ── multi-file layout ──────────────────────────────────────────
//
// Every test above runs on a single master, which leaves
// `find_label_file`'s scan over `owner_candidate_files` — the
// hand-rolled replacement for the id-keyed
// `resolve_existing_target_file` — never actually executed against a
// split tree. That is the exact bug `cli-h4` records for the other
// entity verbs (`target.rs:400`): `set` / `remove` wrote into the
// default creation target instead of the owning file.

/// A master whose `includes` glob pulls in a `labels.d/` slice.
fn mk_split_tree(dir: &tempfile::TempDir) -> PathBuf {
    let master = dir.path().join("config.toml");
    std::fs::write(
        &master,
        r#"schema_version = 3
includes = ["labels.d/*.toml"]

[server]
default_profile = "default"

[profiles.default]
display_name = "Default"

[upstream]
servers = ["192.0.2.1:53"]
"#,
    )
    .unwrap();
    std::fs::create_dir(dir.path().join("labels.d")).unwrap();
    master
}

/// `add` with no `--into` lands in the single `labels.d/` slice, not
/// in the master — `resolve_target_file`'s directory heuristic.
#[tokio::test]
async fn add_targets_the_labels_d_slice() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_split_tree(&dir);
    let slice = dir.path().join("labels.d").join("vocab.toml");
    std::fs::write(&slice, "").unwrap();
    let sock = fake_socket(&dir);

    run_add(&master, &sock, "dweller", "owner", None, None, None)
        .await
        .unwrap();

    let slice_src = std::fs::read_to_string(&slice).unwrap();
    assert!(slice_src.contains("dweller"), "got slice:\n{slice_src}");
    let master_src = std::fs::read_to_string(&master).unwrap();
    assert!(
        !master_src.contains("dweller"),
        "the master must be untouched. got:\n{master_src}"
    );
    assert_eq!(labels_of(&master).len(), 1, "and the merged view sees it");
}

/// `set` with no `--into` must edit the OWNING slice. If
/// `find_label_file` missed, it would fall back to the master, find
/// no row there, and bail — so this test fails loudly rather than
/// corrupting anything, which is why the deviation is safe but still
/// worth pinning.
#[tokio::test]
async fn set_edits_the_owning_slice_not_the_master() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_split_tree(&dir);
    let slice = dir.path().join("labels.d").join("vocab.toml");
    std::fs::write(
        &slice,
        "[[labels]]\nid = \"dweller\"\nkind = \"owner\"\ndisplay_name = \"dweller\"\n",
    )
    .unwrap();
    let sock = fake_socket(&dir);

    run_set(
        &master,
        &sock,
        "dweller",
        "display_name",
        "Dweller",
        None,
        None,
    )
    .await
    .unwrap();

    let slice_src = std::fs::read_to_string(&slice).unwrap();
    assert!(
        slice_src.contains("Dweller"),
        "the edit must land in the owning slice. got:\n{slice_src}"
    );
    let master_src = std::fs::read_to_string(&master).unwrap();
    // Not `contains("labels")` — the master's own `includes` glob is
    // `labels.d/*.toml`, so that needle matches a healthy master.
    assert!(
        !master_src.contains("[[labels]]"),
        "the master must not grow a [[labels]] array. got:\n{master_src}"
    );
}

/// `remove` resolves the owning slice the same way, and the merged
/// view reflects it.
#[tokio::test]
async fn remove_deletes_from_the_owning_slice() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_split_tree(&dir);
    let slice = dir.path().join("labels.d").join("vocab.toml");
    std::fs::write(
        &slice,
        "[[labels]]\nid = \"dweller\"\nkind = \"owner\"\ndisplay_name = \"Dweller\"\n\
         \n[[labels]]\nid = \"laptop\"\nkind = \"device-type\"\ndisplay_name = \"Laptop\"\n",
    )
    .unwrap();
    let sock = fake_socket(&dir);

    run_remove(&master, &sock, "dweller", None, None)
        .await
        .unwrap();

    let remaining = labels_of(&master);
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].id.as_str(), "laptop");
    let slice_src = std::fs::read_to_string(&slice).unwrap();
    assert!(!slice_src.contains("dweller"), "got slice:\n{slice_src}");
}

/// The homonym across two DIFFERENT slices: `find_label_file` must
/// pick the file holding the `(kind, id)` pair, not the first file
/// merely holding the id. The id-keyed helper would return `a.toml`
/// for both.
#[tokio::test]
async fn set_picks_the_slice_holding_the_pair_not_the_id() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_split_tree(&dir);
    let a = dir.path().join("labels.d").join("a.toml");
    let b = dir.path().join("labels.d").join("b.toml");
    std::fs::write(
        &a,
        "[[labels]]\nid = \"personal\"\nkind = \"department\"\ndisplay_name = \"dept\"\n",
    )
    .unwrap();
    std::fs::write(
        &b,
        "[[labels]]\nid = \"personal\"\nkind = \"device-type\"\ndisplay_name = \"dt\"\n",
    )
    .unwrap();
    let sock = fake_socket(&dir);

    run_set(
        &master,
        &sock,
        "personal",
        "display_name",
        "Personal device",
        Some("device-type"),
        None,
    )
    .await
    .unwrap();

    let b_src = std::fs::read_to_string(&b).unwrap();
    assert!(
        b_src.contains("Personal device"),
        "the device-type row lives in b.toml. got:\n{b_src}"
    );
    let a_src = std::fs::read_to_string(&a).unwrap();
    assert!(
        a_src.contains("display_name = \"dept\""),
        "a.toml holds the department homonym and must be untouched. got:\n{a_src}"
    );
}

#[test]
fn show_renders_every_field() {
    let l: Label = toml::from_str(
        "id = \"dweller\"\nkind = \"owner\"\ndisplay_name = \"Dweller\"\n\
         description = \"Dispositivi personali\"\n",
    )
    .unwrap();
    let out = render_label_detail(&l);
    assert!(out.contains("kind:         owner"), "got:\n{out}");
    assert!(
        out.contains("description:  Dispositivi personali"),
        "the description is inert everywhere else — `show` is the only \
         place it comes back. got:\n{out}"
    );
}

#[test]
fn show_renders_a_missing_description_as_none() {
    // Differential against the test above: without it, a renderer
    // printing a hardcoded description line would pass.
    let l: Label =
        toml::from_str("id = \"tv\"\nkind = \"device-type\"\ndisplay_name = \"TV\"\n").unwrap();
    let out = render_label_detail(&l);
    assert!(out.contains("description:  (none)"), "got:\n{out}");
}

#[test]
fn upsert_is_keyed_on_the_pair_not_the_id() {
    // The precise failure `upsert_id_keyed` would have caused: two
    // rows sharing an id, the second overwriting the first.
    let mut doc = Value::Table(Default::default());
    let row = |kind: &str| {
        let mut t = toml::map::Map::new();
        t.insert("id".into(), Value::String("personal".into()));
        t.insert("kind".into(), Value::String(kind.into()));
        t.insert("display_name".into(), Value::String(kind.into()));
        Value::Table(t)
    };
    assert!(upsert_label(
        &mut doc,
        LabelKind::Department,
        "personal",
        row("department")
    )
    .unwrap());
    assert!(upsert_label(
        &mut doc,
        LabelKind::DeviceType,
        "personal",
        row("device-type")
    )
    .unwrap());
    let arr = doc.get("labels").unwrap().as_array().unwrap();
    assert_eq!(arr.len(), 2, "the department row must survive");

    // Same pair again → replace, not append.
    assert!(!upsert_label(
        &mut doc,
        LabelKind::Department,
        "personal",
        row("department")
    )
    .unwrap());
    assert_eq!(doc.get("labels").unwrap().as_array().unwrap().len(), 2);
}

#[test]
fn remove_is_keyed_on_the_pair_too() {
    let mut doc = Value::Table(Default::default());
    let row = |kind: &str| {
        let mut t = toml::map::Map::new();
        t.insert("id".into(), Value::String("personal".into()));
        t.insert("kind".into(), Value::String(kind.into()));
        Value::Table(t)
    };
    upsert_label(
        &mut doc,
        LabelKind::Department,
        "personal",
        row("department"),
    )
    .unwrap();
    upsert_label(
        &mut doc,
        LabelKind::DeviceType,
        "personal",
        row("device-type"),
    )
    .unwrap();
    assert!(remove_label(&mut doc, LabelKind::DeviceType, "personal").unwrap());
    let arr = doc.get("labels").unwrap().as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0].get("kind").unwrap().as_str(), Some("department"));
}

#[test]
fn elide_caps_the_reference_list() {
    let refs: Vec<String> = (0..8).map(|i| format!("device d{i}")).collect();
    let out = elide(&refs);
    assert!(out.contains("and 3 more"), "got: {out}");
    assert!(!out.contains("device d7"), "got: {out}");
}

// ── the writing seam ───────────────────────────────────────────
//
// These call `add_inner` / `set_inner` / `remove_inner` DIRECTLY —
// sync, no socket, no async runtime, which is itself half the point:
// a `#[test]` rather than a `#[tokio::test]` only compiles if the
// seam really is sync.
//
// They assert on the BYTES ON DISK, not on the reloaded struct. A
// reload proves the loader can still parse what was written; only the
// file proves *what* was written. The two differ in ways that have
// already cost this project a bug: the loader synthesises values
// (`uncategorized` onto untagged deny-lists) that were never in the
// file, so a test reading the merged view can pass on a writer that
// wrote the wrong thing — or nothing.

/// The `[[labels]]` rows exactly as they sit in `path`: raw TOML, no
/// loader, no include merge, no auto-promotion.
fn rows_on_disk(path: &Path) -> Vec<Value> {
    let raw = std::fs::read_to_string(path).expect("target file must exist");
    let doc: Value = raw.parse().expect("target must be valid TOML");
    doc.get("labels")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
}

/// Look a row up by the PAIR, the same identity the writers use.
fn row_of<'a>(rows: &'a [Value], kind: &str, id: &str) -> Option<&'a Value> {
    rows.iter()
        .find(|r| row_matches(r, kind.parse::<LabelKind>().unwrap(), id))
}

fn field_of(row: &Value, field: &str) -> Option<String> {
    row.get(field)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

#[test]
fn add_inner_writes_the_row_and_reports_where() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);

    let report = add_inner(
        &master,
        "dweller",
        LabelKind::Owner,
        Some("Dweller"),
        Some("Dispositivi personali"),
        None,
    )
    .expect("the seam writes with no runtime and no socket");

    assert_eq!(report.id, "dweller");
    assert_eq!(
        report.target_path, master,
        "single-file tree: the master is the target"
    );

    let rows = rows_on_disk(&master);
    assert_eq!(rows.len(), 1, "got: {rows:?}");
    let row = row_of(&rows, "owner", "dweller").expect("the pair must be on disk");
    assert_eq!(field_of(row, "display_name").as_deref(), Some("Dweller"));
    assert_eq!(
        field_of(row, "description").as_deref(),
        Some("Dispositivi personali")
    );
}

/// `display_name` defaults to the id, and `description` is OMITTED
/// rather than written as `""` — an empty description in the file is
/// not the same thing as no description, and `set description ""`
/// exists to remove it.
#[test]
fn add_inner_defaults_the_display_name_and_omits_an_absent_description() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    add_inner(&master, "laptop", LabelKind::DeviceType, None, None, None).unwrap();

    let rows = rows_on_disk(&master);
    let row = row_of(&rows, "device-type", "laptop").expect("the pair must be on disk");
    assert_eq!(field_of(row, "display_name").as_deref(), Some("laptop"));
    assert!(
        row.get("description").is_none(),
        "an absent description must not be written at all. got: {row:?}"
    );
}

/// The trap this module exists to avoid, reached through the SEAM
/// rather than through the verb: `upsert_id_keyed` compares `id`
/// alone, so a `device-type` add would replace the `owner` row of the
/// same id. The TUI is about to become a second caller of this
/// pipeline, so the property is pinned on the entry point it will
/// actually use.
#[test]
fn add_inner_is_keyed_on_the_pair_so_a_homonym_survives() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    add_inner(&master, "personal", LabelKind::Department, None, None, None).unwrap();
    add_inner(&master, "personal", LabelKind::DeviceType, None, None, None).unwrap();

    let rows = rows_on_disk(&master);
    assert_eq!(rows.len(), 2, "the department row must survive: {rows:?}");
    assert!(row_of(&rows, "department", "personal").is_some());
    assert!(row_of(&rows, "device-type", "personal").is_some());
}

#[test]
fn set_inner_edits_the_named_pair_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    add_inner(&master, "personal", LabelKind::Department, None, None, None).unwrap();
    add_inner(&master, "personal", LabelKind::DeviceType, None, None, None).unwrap();

    let report = set_inner(
        &master,
        "personal",
        Some(LabelKind::DeviceType),
        "display_name",
        "Personal device",
        None,
    )
    .expect("an unambiguous selector edits one row");

    assert_eq!(report.id, "personal");
    assert_eq!(report.fields, vec!["display_name".to_string()]);
    assert_eq!(report.target_path, master);

    let rows = rows_on_disk(&master);
    assert_eq!(
        field_of(
            row_of(&rows, "device-type", "personal").unwrap(),
            "display_name"
        )
        .as_deref(),
        Some("Personal device")
    );
    assert_eq!(
        field_of(
            row_of(&rows, "department", "personal").unwrap(),
            "display_name"
        )
        .as_deref(),
        Some("personal"),
        "the department homonym must be untouched: {rows:?}"
    );
}

/// `kind: None` disambiguates through `select_label`, which REFUSES an
/// id carried by two kinds. A TUI that passes `None` gets the refusal,
/// not a coin flip over which row to edit.
#[test]
fn set_inner_refuses_an_ambiguous_id_without_a_kind() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    add_inner(&master, "personal", LabelKind::Department, None, None, None).unwrap();
    add_inner(&master, "personal", LabelKind::DeviceType, None, None, None).unwrap();

    let err = set_inner(&master, "personal", None, "display_name", "P", None).unwrap_err();
    assert!(err.to_string().contains("--kind"), "got: {err}");

    let rows = rows_on_disk(&master);
    assert!(
        rows.iter()
            .all(|r| field_of(r, "display_name").as_deref() != Some("P")),
        "a refused set writes nothing: {rows:?}"
    );
}

/// Moving a row between vocabularies re-runs the destination-pair
/// collision check, inside the seam.
///
/// **It used to check two guards.** The first arm moved `4chan` into
/// `--kind tag` and expected a `tag slug` refusal — the stricter,
/// letter-led contract a tag id had to satisfy on top of `Id`. That
/// kind is gone (`plp-s5a`), and the three that remain share one id
/// contract, so a move has nothing extra to re-check. The collision
/// half is untouched and is what this now pins.
#[test]
fn set_inner_kind_move_re_runs_the_collision_guard() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    add_inner(&master, "personal", LabelKind::Department, None, None, None).unwrap();
    add_inner(&master, "personal", LabelKind::DeviceType, None, None, None).unwrap();
    let err = set_inner(
        &master,
        "personal",
        Some(LabelKind::Department),
        "kind",
        "device-type",
        None,
    )
    .unwrap_err();
    assert!(err.to_string().contains("already exists"), "got: {err}");
}

#[test]
fn remove_inner_deletes_only_the_named_pair_from_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    add_inner(&master, "personal", LabelKind::Department, None, None, None).unwrap();
    add_inner(&master, "personal", LabelKind::DeviceType, None, None, None).unwrap();

    let report = remove_inner(&master, "personal", Some(LabelKind::DeviceType), None)
        .expect("the pair exists");
    assert_eq!(report.id, "personal");
    assert_eq!(report.target_path, master);

    let rows = rows_on_disk(&master);
    assert_eq!(rows.len(), 1, "got: {rows:?}");
    assert!(
        row_of(&rows, "department", "personal").is_some(),
        "the homonym under the other kind must survive: {rows:?}"
    );
}

/// The reference guard is in the seam, so the TUI cannot delete a
/// declaration out from under a device that still carries the value.
#[test]
fn remove_inner_refuses_while_a_device_uses_it() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);
    // The fixture device carries `owner = "Dweller"`, matched by this
    // label's display_name.
    add_inner(
        &master,
        "dweller",
        LabelKind::Owner,
        Some("Dweller"),
        None,
        None,
    )
    .unwrap();

    let err = remove_inner(&master, "dweller", None, None).unwrap_err();
    assert!(err.to_string().contains("iphone"), "got: {err}");
    assert!(
        row_of(&rows_on_disk(&master), "owner", "dweller").is_some(),
        "nothing may be removed"
    );
}

/// The one place the seam and the verb deliberately DISAGREE, and the
/// reason `remove_if_present` exists.
///
/// `warden label remove ghost` is a no-op that exits 0
/// (`remove_absent_label_is_idempotent`, above). The seam cannot say
/// that — `Result<RemoveReport>` has no "nothing happened" — so it
/// returns the error instead. For the TUI that is the better answer:
/// it holds a row it just rendered, and "that row is gone" is news,
/// not a success.
#[test]
fn remove_inner_errors_where_the_verb_no_ops() {
    let dir = tempfile::tempdir().unwrap();
    let master = mk_master(&dir);

    let err = remove_inner(&master, "ghost", None, None).unwrap_err();
    assert_eq!(err.to_string(), "label not found: ghost");
    let err = remove_inner(&master, "ghost", Some(LabelKind::Owner), None).unwrap_err();
    assert_eq!(
        err.to_string(),
        "label not found: ghost (kind owner)",
        "the selector is named, exactly as `select_label` names it"
    );
}

// ── no print may be reachable from the seam ────────────────────

/// Attribute every print macro in `src` to the top-level `fn` it sits
/// in. Returns `"<fn>:<line>: <macro>"` per site.
///
/// Line-based and deliberately simple; the two subtleties are both
/// scars:
///
/// * **Comment lines are skipped.** The doc comments in this module
///   name the macros they forbid — including this one. A needle that
///   also matches prose is how a detector dies
///   (`tui_never_reaches_the_printing_tag_helper` records the same
///   lesson from the other side).
/// * **Test modules are skipped by brace, not by `break`.** Cutting
///   the file at the first `#[cfg(test)]` is only correct while the
///   test module is the last thing in it — and this file's is, today.
///   That is exactly the assumption that stops holding the moment
///   someone appends a helper below it, which is where helpers get
///   appended. §4.66 measured the cost elsewhere: `src/tui/mod.rs`
///   carries 26 top-level test modules, the first at line 1732 of
///   15538, so a `break` read 11% of the file and both offending call
///   sites lived in the 89% no version of that guard had ever looked
///   at. A detector blind to the region the offence is in reads
///   exactly like one that found nothing.
///
/// A top-level test module opens with `#[cfg(test)]` in column 0 and
/// closes with `}` in column 0, so that pair delimits the skip. That
/// holds because `cargo fmt --check` is a gate, not because rustfmt is
/// a convention: drop the fmt gate and this becomes a heuristic.
fn print_sites(src: &str) -> Vec<String> {
    fn top_level_fn_name(line: &str) -> Option<String> {
        if line.starts_with(char::is_whitespace) {
            return None;
        }
        let mut rest = line;
        loop {
            let mut stripped = false;
            for p in ["pub(crate) ", "pub(super) ", "pub ", "async ", "unsafe "] {
                if let Some(r) = rest.strip_prefix(p) {
                    rest = r;
                    stripped = true;
                }
            }
            if !stripped {
                break;
            }
        }
        let rest = rest.strip_prefix("fn ")?;
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        (!name.is_empty()).then_some(name)
    }

    let mut sites = Vec::new();
    let mut in_test_mod = false;
    let mut current_fn = String::from("<module scope>");
    for (i, line) in src.lines().enumerate() {
        if in_test_mod {
            if line == "}" {
                in_test_mod = false;
            }
            continue;
        }
        if line.starts_with("#[cfg(test)]") {
            in_test_mod = true;
            continue;
        }
        if line.trim_start().starts_with("//") {
            continue;
        }
        if let Some(name) = top_level_fn_name(line) {
            current_fn = name;
        }
        // Order matters: `eprintln!(` CONTAINS `println!(`, so the
        // longer needle is tested first or every stderr site would be
        // reported as a stdout one. `print!(` is not a substring of
        // `println!(` — the character after `print` differs.
        let found = if line.contains("eprintln!(") {
            Some("eprintln!")
        } else if line.contains("eprint!(") {
            Some("eprint!")
        } else if line.contains("println!(") {
            Some("println!")
        } else if line.contains("print!(") {
            Some("print!")
        } else {
            None
        };
        if let Some(m) = found {
            sites.push(format!("{current_fn}:{}: {m}", i + 1));
        }
    }
    sites
}

/// Every print in this module lives in a `run_*` verb — so none is
/// reachable from `add_inner` / `set_inner` / `remove_inner`, which
/// call only helpers from this same file.
///
/// The TUI runs on a raw-mode alternate screen. A `println!` from
/// under a Save bypasses ratatui's diff buffer, staircases one column
/// per line, and survives every later redraw — the v0.29.1 defect. No
/// unit test can see that: the line vector stays correct and the
/// damage is in bytes that never reach the buffer under test. So the
/// invariant is enforced at the source instead.
///
/// **Scoped to this module's own source, and the claim stops there.**
/// `audit()` reaches `persist_cli_mutation_audit`, which `eprintln!`s
/// when the audit log cannot be written (`audit_emit.rs:44`, `:58`) —
/// stderr, on a failure path, shared with `groups::add_inner` and
/// every other CLI writer. Widening this test to the call graph would
/// mean either claiming something false or vendoring a rule about a
/// file this lane does not own.
#[test]
fn only_the_run_verbs_print() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/cli/commands/labels.rs");
    let src = std::fs::read_to_string(&path).expect("this module's own source is readable");
    let sites = print_sites(&src);

    const PRINTING_VERBS: [&str; 5] = ["run_list", "run_show", "run_add", "run_set", "run_remove"];
    let strays: Vec<&String> = sites
        .iter()
        .filter(|s| {
            let owner = s.split(':').next().unwrap_or_default();
            !PRINTING_VERBS.contains(&owner)
        })
        .collect();
    assert!(
        strays.is_empty(),
        "a print outside the printing verbs is reachable from the TUI seam: {strays:?}"
    );

    // Non-vacuous: a scanner that matched nothing would pass the
    // assertion above on any file at all.
    for verb in ["run_list", "run_add", "run_remove"] {
        assert!(
            sites.iter().any(|s| s.starts_with(&format!("{verb}:"))),
            "the scanner found no print in {verb}, so it is not reading this file: {sites:?}"
        );
    }
    assert!(
        sites.iter().any(|s| s.ends_with("print!")),
        "`run_show` prints with `print!`, and a scanner that only knows \
         `println!` would miss a whole macro: {sites:?}"
    );
}

/// The negative controls for the scanner above. Each is a source
/// string this file could plausibly grow, and each would make
/// `only_the_run_verbs_print` useless if the scanner mishandled it.
///
/// These live inside the test module — which the scanner skips — so
/// the skip is what keeps them from being reported as real findings
/// when the file scans itself.
#[test]
fn the_print_scanner_catches_what_it_must_and_ignores_what_it_must() {
    let planted = "pub(crate) fn add_inner(config_path: &Path) -> anyhow::Result<()> {\n\
                       println!(\"added\");\n\
                   }\n";
    assert_eq!(
        print_sites(planted),
        vec!["add_inner:2: println!".to_string()],
        "a print planted in the seam must be reported, and named"
    );

    let stderr_variant = "fn set_inner() {\n    eprintln!(\"oops\");\n}\n";
    assert_eq!(
        print_sites(stderr_variant),
        vec!["set_inner:2: eprintln!".to_string()],
        "stderr is forbidden too, and must not be mis-reported as `println!`"
    );

    let prose = "/// Never `println!(` from here — see the module header.\n\
                 pub(crate) fn add_inner() {\n    let _ = 1;\n}\n";
    assert!(
        print_sites(prose).is_empty(),
        "a doc comment NAMING the macro is not a call: {:?}",
        print_sites(prose)
    );

    let below_the_test_mod = "#[cfg(test)]\n\
                              mod tests {\n    println!(\"in a test\");\n}\n\
                              fn appended_later() {\n    println!(\"real code\");\n}\n";
    assert_eq!(
        print_sites(below_the_test_mod),
        vec!["appended_later:6: println!".to_string()],
        "the test module is skipped, and scanning RESUMES after it — a `break` \
         here would report nothing and look identical to a clean file"
    );
}
