//! A CLI verb whose stdout reader has gone exits 141 without panic text.
//!
//! The Rust runtime ignores SIGPIPE, so `println!` into a closed pipe panics
//! with `failed printing to stdout: Broken pipe`; under the release profile's
//! `panic = "abort"` that is a SIGABRT and a core dump for `warden … | head`.
//! The read end is closed before the spawn, so the write always fails: piping
//! into a real `head` would race (head may read everything before it exits).

use std::path::Path;
use std::process::{Command, Stdio};

#[test]
fn closed_stdout_exits_141_without_panic_text() {
    // `config render-default` reads no config and drops the discovery
    // warning, so its only output is the stdout write under test.
    // `completion` writes through clap_complete, whose own panic text
    // the hook does not match: it must reach stdout through `print!`.
    for args in [&["config", "render-default"][..], &["completion", "bash"]] {
        let dir = tempfile::tempdir().unwrap();
        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);

        let out = Command::new(env!("CARGO_BIN_EXE_warden"))
            .arg("--config")
            .arg(dir.path().join("absent.toml"))
            .args(args)
            .stdin(Stdio::null())
            .stdout(writer)
            .stderr(Stdio::piped())
            .output()
            .expect("spawn warden");

        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(141), "{args:?} stderr: {stderr}");
        assert!(!stderr.contains("panicked"), "{args:?}: {stderr}");
        assert!(!stderr.contains("failed printing"), "{args:?}: {stderr}");
    }
}

/// `custom-list export` writes the pack bytes with `write_all`, not
/// `println!`: its EPIPE is an error value that the panic hook never sees.
#[test]
fn custom_list_export_into_closed_stdout_exits_141() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("valid.toml");
    std::fs::write(
        &config,
        "schema_version = 5\n\n[server]\nlisten = \"127.0.0.1:15353\"\n\
         default_profile = \"default\"\n\n[socket]\npath = \"/nonexistent/pipe.sock\"\n\n\
         [profiles.default]\ndisplay_name = \"Default\"\ntags = [\"uncategorized\"]\n\n[upstream]\nservers = [\"192.0.2.1:53\"]\n",
    )
    .unwrap();
    // No daemon acknowledges the offline commits, so 5 (pending) is expected.
    for args in [
        &["create", "mine"][..],
        &["add", "mine", "example.com", "--deny"],
    ] {
        let out = custom_list(&config, args).output().expect("spawn warden");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            matches!(out.status.code(), Some(0 | 5)),
            "{args:?}: {stderr}"
        );
    }
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);

    let out = custom_list(&config, &["export", "mine"])
        .stdout(writer)
        .stderr(Stdio::piped())
        .output()
        .expect("spawn warden");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(141), "stderr: {stderr}");
    assert!(stderr.is_empty(), "{stderr}");
}

fn custom_list(config: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_warden"));
    command
        .arg("--config")
        .arg(config)
        .args(["custom-list", "--offline"])
        .args(args)
        .stdin(Stdio::null());
    command
}
