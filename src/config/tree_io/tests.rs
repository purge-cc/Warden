use crate::config::write_lock::acquire_for_write;
use std::io::Read;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

#[test]
fn external_directory_plan_maps_retained_ancestors() {
    let workspace = tempfile::tempdir().unwrap();
    let source = workspace.path().join("source");
    let unrelated = workspace.path().join("unrelated");
    std::fs::create_dir(&source).unwrap();
    std::fs::create_dir(&unrelated).unwrap();
    let source_fd = std::fs::File::open(&source).unwrap();
    let workspace_fd = std::fs::File::open(workspace.path()).unwrap();
    let unrelated_fd = std::fs::File::open(&unrelated).unwrap();

    let root = super::plan_external_directory_from(&source, workspace.path()).unwrap();
    assert_eq!(root.relative_to(&source_fd).unwrap(), Some(PathBuf::new()));

    for name in ["existing", "missing"] {
        let output = source.join(name);
        if name == "existing" {
            std::fs::create_dir(&output).unwrap();
        }
        let plan = super::plan_external_directory_from(&output, workspace.path()).unwrap();
        assert_eq!(
            plan.relative_to(&source_fd).unwrap(),
            Some(PathBuf::from(name))
        );
        assert_eq!(
            plan.relative_to(&workspace_fd).unwrap(),
            Some(PathBuf::from("source").join(name))
        );
        assert_eq!(plan.relative_to(&unrelated_fd).unwrap(), None);
    }

    let alias = workspace.path().join("source-alias");
    symlink(&source, &alias).unwrap();
    let via_alias =
        super::plan_external_directory_from(&alias.join("via-alias"), workspace.path()).unwrap();
    assert_eq!(
        via_alias.relative_to(&source_fd).unwrap(),
        Some(PathBuf::from("via-alias"))
    );
}

#[test]
fn trailing_slashes_require_directories_in_paths_and_symlink_targets() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("file.toml"), "original").unwrap();
    std::fs::write(root.path().join("config.toml"), "master").unwrap();
    std::fs::create_dir(root.path().join("directory")).unwrap();
    symlink("file.toml/", root.path().join("relative-link")).unwrap();
    symlink(
        root.path().join("file.toml/"),
        root.path().join("absolute-link"),
    )
    .unwrap();
    symlink("directory/", root.path().join("directory-link")).unwrap();
    let guard = acquire_for_write(&root.path().join("config.toml")).unwrap();
    for spelling in [
        "file.toml/",
        "file.toml/.",
        "config.toml/",
        "relative-link",
        "absolute-link",
    ] {
        let path = root.path().join(spelling);
        for error in [
            guard
                .tree_io()
                .resolve_member(&path)
                .err()
                .expect("member must fail"),
            super::resolve_global_from(&path, root.path()).unwrap_err(),
            crate::config::write_lock::ConfigTreeIdentity::resolve(&path).unwrap_err(),
        ] {
            assert_eq!(
                error
                    .downcast_ref::<std::io::Error>()
                    .and_then(|e| e.raw_os_error()),
                Some(libc::ENOTDIR),
                "{spelling}: {error:#}"
            );
        }
    }
    assert!(guard
        .tree_io()
        .directory_from(
            &guard.tree_io().master_key(),
            std::path::Path::new("directory-link")
        )
        .unwrap()
        .is_some());
}

#[test]
fn external_directory_plans_accept_a_terminal_directory_marker() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("existing")).unwrap();

    for name in ["existing/", "missing/", "repeated//./"] {
        let plan =
            super::plan_external_directory_from(&root.path().join(name), root.path()).unwrap();
        let dir = plan.open_or_create().unwrap();
        assert!(dir.metadata().unwrap().is_dir(), "{name}");
    }
    assert!(root.path().join("missing").is_dir());
    assert!(root.path().join("repeated").is_dir());

    std::fs::write(root.path().join("file"), "not a directory").unwrap();
    let plan =
        super::plan_external_directory_from(&root.path().join("file/"), root.path()).unwrap();
    assert!(plan.open_or_create().is_err());
}

#[test]
fn pinned_entry_survives_parent_link_replacement() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("inside")).unwrap();
    std::fs::write(root.path().join("inside/file.toml"), "original").unwrap();
    std::fs::write(outside.path().join("file.toml"), "external").unwrap();
    symlink("inside", root.path().join("alias")).unwrap();
    let guard = acquire_for_write(&root.path().join("config.toml")).unwrap();
    let tree = guard.tree_io();
    let entry = tree
        .resolve_member(&root.path().join("alias/file.toml"))
        .unwrap();
    std::fs::remove_file(root.path().join("alias")).unwrap();
    symlink(outside.path(), root.path().join("alias")).unwrap();
    let (mut file, _) = tree.open_regular(&entry).unwrap();
    let mut bytes = String::new();
    file.read_to_string(&mut bytes).unwrap();
    assert_eq!(bytes, "original");
    assert!(tree
        .resolve_member(&root.path().join("alias/file.toml"))
        .is_err());
    assert_eq!(
        std::fs::read_to_string(outside.path().join("file.toml")).unwrap(),
        "external"
    );
}

#[test]
fn absolute_in_root_link_rebinds_to_held_root() {
    let root = tempfile::tempdir().unwrap();
    let moved = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("file.toml"), "original").unwrap();
    symlink(root.path().join("file.toml"), root.path().join("alias")).unwrap();
    let guard = acquire_for_write(&root.path().join("config.toml")).unwrap();
    std::fs::rename(root.path(), moved.path().join("old")).unwrap();
    std::fs::create_dir(root.path()).unwrap();
    std::fs::write(root.path().join("file.toml"), "replacement").unwrap();
    let tree = guard.tree_io();
    let entry = tree.resolve_member(&root.path().join("alias")).unwrap();
    let (mut file, _) = tree.open_regular(&entry).unwrap();
    let mut bytes = String::new();
    file.read_to_string(&mut bytes).unwrap();
    assert_eq!(bytes, "original");
    assert_eq!(
        std::fs::read_to_string(root.path().join("file.toml")).unwrap(),
        "replacement"
    );
}

#[test]
fn materialization_accepts_a_concurrent_directory_winner() {
    let root = tempfile::tempdir().unwrap();
    let guard = acquire_for_write(&root.path().join("config.toml")).unwrap();
    let parent = root.path().join("new");
    let plan = guard
        .tree_io()
        .plan_target(&parent.join("file.toml"))
        .unwrap();
    let winner = parent.clone();
    crate::config::write_lock::with_test_hook(
        move |event| {
            if event == crate::config::write_lock::TestEvent::BeforeMkdir {
                std::fs::create_dir(&winner).unwrap();
            }
        },
        || {
            plan.materialize().unwrap();
        },
    );
    assert!(parent.is_dir());
    assert!(!parent.join("file.toml").exists());
}

#[test]
fn materialization_refuses_a_planted_parent_symlink() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let guard = acquire_for_write(&root.path().join("config.toml")).unwrap();
    let parent = root.path().join("new");
    let plan = guard
        .tree_io()
        .plan_target(&parent.join("file.toml"))
        .unwrap();
    symlink(outside.path(), &parent).unwrap();
    assert!(plan.materialize().is_err());
    assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
}

#[test]
fn root_file_no_follow_planner_refuses_symlink_parents_and_leaves() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("real")).unwrap();
    symlink(outside.path(), root.path().join("linked-parent")).unwrap();
    symlink("real", root.path().join("linked-leaf")).unwrap();
    symlink("missing", root.path().join("dangling-leaf")).unwrap();
    let guard = acquire_for_write(&root.path().join("config.toml")).unwrap();

    for path in [
        Path::new("linked-parent/new.toml"),
        Path::new("linked-leaf"),
        Path::new("dangling-leaf"),
    ] {
        let error = guard
            .tree_io()
            .plan_root_file_no_follow(path)
            .err()
            .expect("root-file planner must not follow symlinks");
        assert!(
            error.to_string().contains("symlink")
                || error.to_string().contains("regular file with one link"),
            "{}: {error:#}",
            path.display()
        );
    }
    assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
}

#[test]
fn root_file_no_follow_planner_accepts_only_regular_single_link_existing_leaves() {
    let root = tempfile::tempdir().unwrap();
    let guard = acquire_for_write(&root.path().join("config.toml")).unwrap();
    let outside = root.path().join("outside");
    std::fs::write(&outside, "outside").unwrap();

    for kind in ["regular", "hardlink", "directory", "symlink", "dangling"] {
        let path = root.path().join("candidate");
        match kind {
            "regular" => std::fs::write(&path, "sentinel").unwrap(),
            "hardlink" => std::fs::hard_link(&outside, &path).unwrap(),
            "directory" => std::fs::create_dir(&path).unwrap(),
            "symlink" => symlink("outside", &path).unwrap(),
            "dangling" => symlink("not-here", &path).unwrap(),
            _ => unreachable!(),
        }
        let plan = guard
            .tree_io()
            .plan_root_file_no_follow(Path::new("candidate"));
        if kind == "regular" {
            assert!(!plan.unwrap().is_new());
        } else {
            assert!(plan.is_err(), "{kind} leaf must be refused");
        }
        if kind == "directory" {
            std::fs::remove_dir(&path).unwrap();
        } else {
            std::fs::remove_file(&path).unwrap();
        }
    }
}

#[test]
fn root_file_no_follow_planner_materializes_missing_parents_with_a_canonical_key() {
    let root = tempfile::tempdir().unwrap();
    let guard = acquire_for_write(&root.path().join("config.toml")).unwrap();
    let plan = guard
        .tree_io()
        .plan_root_file_no_follow(Path::new("./one/two/new.toml"))
        .unwrap();
    assert!(plan.is_new());
    assert_eq!(plan.key().0, PathBuf::from("one/two/new.toml"));
    assert_eq!(plan.display(), root.path().join("one/two/new.toml"));
    let target = plan.materialize().unwrap();
    assert!(root.path().join("one/two").is_dir());
    assert!(target.check_original().is_ok());
    assert!(!root.path().join("one/two/new.toml").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn rename_noreplace_at_preserves_an_existing_sentinel() {
    use std::os::unix::fs::OpenOptionsExt;

    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    let target = root.path().join("target");
    std::fs::write(&source, "new").unwrap();
    std::fs::write(&target, "sentinel").unwrap();
    let parent = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open(root.path())
        .unwrap();

    let error = super::rename_noreplace_at(
        &parent,
        std::ffi::OsStr::new("source"),
        &parent,
        std::ffi::OsStr::new("target"),
    )
    .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::EEXIST));
    assert_eq!(std::fs::read(&target).unwrap(), b"sentinel");
    assert_eq!(std::fs::read(&source).unwrap(), b"new");
}
