use super::*;
use crate::ipc::protocol::{IpcCommand, IpcResponse};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

const MASTER: &str = "schema_version = 5\n[upstream]\nservers = [\"192.0.2.1:53\"]\n[server]\ndefault_profile = \"home\"\n[profiles.home]\ndisplay_name = \"Home\"\n";

pub(super) fn isolated_auth_process(test: &str) -> bool {
    const MARKER: &str = "WARDEN_PROFILE_CREATE_AUTH_TEST";
    if std::env::var(MARKER).as_deref() == Ok(test) {
        return false;
    }
    assert!(
        !Path::new("/var/lib/purge-warden/token").exists(),
        "refuse to use an installed token in a mock test"
    );
    let dir = tempfile::tempdir().unwrap();
    crate::ipc::auth_token::save_token_at(
        &dir.path().join("purge-warden/token"),
        "profile-create-test-token",
    )
    .unwrap();
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env(MARKER, test)
        .env("XDG_CONFIG_HOME", dir.path())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "isolated test failed: {}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    true
}

fn draft() -> profile_modal::ProfileModal {
    let mut form = profile_modal::ProfileForm::new_add();
    form.id = "created".into();
    form.display_name = "Created".into();
    form.block_all = true;
    form.custom_lists_draft
        .insert(crate::config::schema::Id::try_from("local-policy").unwrap());
    profile_modal::ProfileModal {
        stage: profile_modal::Stage::EditingForm(form),
    }
}

fn form(app: &App) -> &profile_modal::ProfileForm {
    match &app.profiles.modal.as_ref().unwrap().stage {
        profile_modal::Stage::EditingForm(form) => form,
        profile_modal::Stage::ReviewingError(review) => &review.form,
        stage => panic!("draft must survive: {stage:?}"),
    }
}

#[tokio::test]
async fn created_profile_keeps_pending_properties_and_mounts_for_review() {
    if isolated_auth_process("tui::profile_creation_tests::created_profile_keeps_pending_properties_and_mounts_for_review") { return; }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, MASTER).unwrap();
    let socket = dir.path().join("create.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let master = path.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept())
            .await
            .expect("creation request reaches the socket")
            .unwrap();
        let mut line = String::new();
        BufReader::new(&mut stream)
            .read_line(&mut line)
            .await
            .unwrap();
        let command: IpcCommand = serde_json::from_str(&line).unwrap();
        assert!(matches!(&command, IpcCommand::ProfileCreate { id, .. } if id == "created"));
        std::fs::write(
            master,
            format!("{MASTER}\n[profiles.created]\ndisplay_name = \"Created\"\n"),
        )
        .unwrap();
        let mut response = serde_json::to_vec(&IpcResponse::Ok {
            message: "created".into(),
        })
        .unwrap();
        response.push(b'\n');
        stream.write_all(&response).await.unwrap();
        stream.shutdown().await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "creation must not dispatch legacy property/mount updates"
        );
    });
    let mut app = App::known_standalone_for_test();
    app.active_leaf = Leaf::Profiles;
    let poller = IpcPoller::new(&socket);
    action_handlers::profile(&mut app, draft(), &poller, &path).await;
    server.await.unwrap();
    let form = form(&app);
    assert_eq!(form.mode, profile_modal::FormMode::Edit);
    assert!(form.block_all);
    assert!(form
        .custom_lists_draft
        .iter()
        .any(|id| id.as_str() == "local-policy"));
    let original = form.original.as_ref().unwrap();
    assert!(!original.block_all);
    assert!(original.custom_lists.is_empty());
    let patch = profile_modal::resolve_edit_patch(form, original).unwrap();
    assert_eq!(patch.block_all, Some(true));
    assert_eq!(
        patch.custom_lists.unwrap().mount,
        vec!["local-policy".to_string()]
    );
    let modal = app.profiles.modal.take().unwrap();
    action_handlers::profile(&mut app, modal, &poller, &path).await;
    assert!(
        app.operator_policy.is_some(),
        "remaining mounts open retained policy review"
    );
    assert!(
        app.profiles.modal.is_some(),
        "the draft survives unavailable policy preparation"
    );
}

#[tokio::test]
async fn uncertain_creation_retains_draft_and_refuses_duplicate_create() {
    if isolated_auth_process("tui::profile_creation_tests::uncertain_creation_retains_draft_and_refuses_duplicate_create") { return; }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, MASTER).unwrap();
    let socket = dir.path().join("create.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept())
            .await
            .expect("creation request reaches the socket")
            .unwrap();
        let mut line = String::new();
        BufReader::new(&mut stream)
            .read_line(&mut line)
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
        drop(stream);
        assert!(
            tokio::time::timeout(Duration::from_millis(200), listener.accept())
                .await
                .is_err(),
            "retry must not create again after an unknown outcome"
        );
    });
    let poller = IpcPoller::new(&socket);
    let mut app = App::known_standalone_for_test();
    app.active_leaf = Leaf::Profiles;
    action_handlers::profile(&mut app, draft(), &poller, &path).await;
    let retained = form(&app).clone();
    assert!(retained.creation_attempted);
    assert!(!retained.creation_confirmed);
    action_handlers::profile(
        &mut app,
        profile_modal::ProfileModal {
            stage: profile_modal::Stage::EditingForm(retained),
        },
        &poller,
        &path,
    )
    .await;
    server.await.unwrap();
    assert_eq!(form(&app).id, "created");
    assert!(form(&app).block_all);
}

#[tokio::test]
async fn refused_create_keeps_identity_editable_for_correction() {
    if isolated_auth_process(
        "tui::profile_creation_tests::refused_create_keeps_identity_editable_for_correction",
    ) {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, MASTER).unwrap();
    let socket = dir.path().join("create.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut line = String::new();
        BufReader::new(&mut stream)
            .read_line(&mut line)
            .await
            .unwrap();
        let mut response = serde_json::to_vec(&IpcResponse::Error {
            message: "duplicate profile id".into(),
        })
        .unwrap();
        response.push(b'\n');
        stream.write_all(&response).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let mut app = App::known_standalone_for_test();
    action_handlers::profile(&mut app, draft(), &IpcPoller::new(&socket), &path).await;
    server.await.unwrap();
    let mut retained = form(&app).clone();
    assert!(!retained.creation_attempted);
    retained.focused = profile_modal::FormField::Id;
    assert!(retained.text_field_buf().is_some());
    assert!(retained.block_all);
}
