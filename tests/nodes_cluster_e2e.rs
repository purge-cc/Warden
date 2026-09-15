#![cfg(feature = "cluster")]

//! Real TLS lifecycle and coherent policy/corpus replication across three daemons.

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{rdata::A, Name, RData, Record, RecordType};
use purge_warden::cluster::lifecycle::{self, LifecycleRequest, LifecycleStatus, NodeRole};
use purge_warden::cluster::membership::{MemberState, SecretString};
use purge_warden::config::schema::{ConfigV5, CustomList, Id, ProfileV5};
use purge_warden::ipc::protocol::{IpcCommand, IpcResponse};
use std::cell::Cell;
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::net::UdpSocket;

#[test]
fn normal_cli_refuses_legacy_membership_setup_before_writing() {
    let root = tempfile::tempdir().unwrap();
    let master = root.path().join("config.toml");
    for args in [
        vec![
            "init",
            "--yes",
            "--cluster-secondary",
            "--peer",
            "https://127.0.0.1:8053",
        ],
        vec!["cluster", "token"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_warden"))
            .arg("--config")
            .arg(&master)
            .args(args)
            .current_dir(root.path())
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("retired"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!master.exists());
    }
}

struct Node {
    label: &'static str,
    pid: Cell<Option<u32>>,
    root: TempDir,
    master: PathBuf,
    socket: PathBuf,
    dns: SocketAddr,
    log: PathBuf,
    admin: String,
}
struct Daemon {
    child: Option<Child>,
}
impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
impl Daemon {
    fn spawn(node: &Node) -> Self {
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&node.log)
            .unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_warden"))
            .arg("--config")
            .arg(&node.master)
            .arg("start")
            .current_dir(node.root.path())
            .env("XDG_CONFIG_HOME", node.root.path().join("xdg"))
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        node.pid.set(Some(child.id()));
        eprintln!(
            "nodes E2E spawn node={} pid={} master={} dns={}",
            node.label,
            child.id(),
            node.master.display(),
            node.dns
        );
        Self { child: Some(child) }
    }
    async fn ready(&mut self, node: &Node) {
        let until = Instant::now() + Duration::from_secs(35);
        loop {
            if let Some(exit) = self.child.as_mut().unwrap().try_wait().unwrap() {
                panic!(
                    "daemon exited {exit}: {}",
                    node.diagnostics("daemon readiness")
                );
            }
            if node.socket.exists()
                && dns(node, "ready.example.test").await == Some(Ipv4Addr::new(203, 0, 113, 7))
            {
                return;
            }
            assert!(
                Instant::now() < until,
                "daemon readiness timeout: {}",
                node.diagnostics("daemon readiness")
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    fn hup(&self) {
        assert_eq!(
            unsafe { libc::kill(self.child.as_ref().unwrap().id() as i32, libc::SIGHUP) },
            0
        );
    }
    async fn stop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        if child.try_wait().unwrap().is_none() {
            assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
        }
        let until = Instant::now() + Duration::from_secs(10);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() > until {
                let _ = child.kill();
                let _ = child.wait();
                panic!("isolated daemon did not stop");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}
impl Node {
    fn new(label: &'static str, upstream: SocketAddr) -> Self {
        let root = tempfile::tempdir().unwrap();
        let master = root.path().join("config.toml");
        let socket = root.path().join("control.sock");
        let dns = free_dns();
        let log = root.path().join("daemon.log");
        let admin = purge_warden::auth::token::generate_token().0;
        let mut config = ConfigV5::default();
        config.server.listen = dns;
        config.server.default_profile = Some(Id::new("default").unwrap());
        config.server.log_level = "warn".into();
        config.upstream.servers = vec![upstream.to_string()];
        config.upstream.timeout_ms = 500;
        config.socket.path = socket.clone();
        config.tracking.enabled = false;
        config.tracking.query_log_enabled = false;
        config.api.token_hash = Some(purge_warden::auth::token::hash_token(&admin));
        config.cluster.poll_interval_secs = 1;
        config.lists.update_interval_secs = 86400;
        config.profiles.insert(
            "default".into(),
            ProfileV5 {
                display_name: "Default".into(),
                custom_lists: vec![Id::new("local").unwrap()],
                ..Default::default()
            },
        );
        config.custom_lists.push(CustomList {
            id: Id::new("local").unwrap(),
            display_name: "Local policy".into(),
            description: String::new(),
        });
        std::fs::create_dir(root.path().join("packs")).unwrap();
        write(
            &root.path().join("packs/local.txt"),
            b"||old-local.example.test^\n",
        );
        write(&master, toml::to_string_pretty(&config).unwrap().as_bytes());
        Self {
            label,
            pid: Cell::new(None),
            root,
            master,
            socket,
            dns,
            log,
            admin,
        }
    }
    fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
    fn diagnostics(&self, stage: &str) -> String {
        let mut waits = Vec::new();
        if let Some(pid) = self.pid.get() {
            if let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) {
                for task in tasks.flatten().take(64) {
                    let channel =
                        std::fs::read_to_string(task.path().join("wchan")).unwrap_or_default();
                    waits.push(format!(
                        "{}:{}",
                        task.file_name().to_string_lossy(),
                        channel.trim()
                    ));
                }
            }
        }
        format!("stage={stage} node={} pid={:?} master={} socket={} dns={}\nthread waits: {}\ndaemon log:\n{}",
            self.label, self.pid.get(), self.master.display(), self.socket.display(), self.dns, waits.join(", "), self.log_text())
    }
    async fn status(&self, stage: &str) -> LifecycleStatus {
        let started = Instant::now();
        eprintln!(
            "nodes E2E status request stage={stage} node={} pid={:?}",
            self.label,
            self.pid.get()
        );
        let response =
            purge_warden::ipc::socket_client::send_command(&self.socket, &IpcCommand::NodesStatus)
                .await
                .unwrap_or_else(|error| {
                    panic!(
                        "NodesStatus failed after {:?}: {error:#}\n{}",
                        started.elapsed(),
                        self.diagnostics(stage)
                    )
                });
        match response {
            IpcResponse::NodesStatus { status } => {
                eprintln!("nodes E2E status reply stage={stage} node={} elapsed={:?} saved={:?} active_epoch={:?} last_error={:?}",
                    self.label, started.elapsed(), status.saved_role, status.active_policy.as_ref().map(|p| p.policy_epoch), status.last_error);
                *status
            }
            other => panic!(
                "unexpected node status: {other:?}\n{}",
                self.diagnostics(stage)
            ),
        }
    }
}
impl Drop for Node {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("{}", self.diagnostics("failure cleanup"));
        }
    }
}
fn write(path: &std::path::Path, bytes: &[u8]) {
    purge_warden::config::atomic_write::hardened_atomic_write(path, bytes, Default::default())
        .unwrap();
}
fn free_tcp() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}
fn free_dns() -> SocketAddr {
    for _ in 0..32 {
        let socket = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        if std::net::UdpSocket::bind(addr).is_ok() {
            return addr;
        }
    }
    panic!("no TCP+UDP port")
}
async fn dns(node: &Node, domain: &str) -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.ok()?;
    let mut request = Message::new(123, MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(
        Name::from_ascii(format!("{domain}.")).ok()?,
        RecordType::A,
    ));
    socket
        .send_to(&request.to_vec().ok()?, node.dns)
        .await
        .ok()?;
    let mut bytes = [0; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_millis(700), socket.recv_from(&mut bytes))
        .await
        .ok()?
        .ok()?;
    let response = Message::from_vec(&bytes[..n]).ok()?;
    response.answers.iter().find_map(|answer| {
        if let RData::A(A(ip)) = &answer.data {
            Some(*ip)
        } else {
            None
        }
    })
}
async fn wait_dns(node: &Node, domain: &str, blocked: bool) {
    let expected = if blocked {
        Ipv4Addr::UNSPECIFIED
    } else {
        Ipv4Addr::new(203, 0, 113, 7)
    };
    let until = Instant::now() + Duration::from_secs(35);
    loop {
        if dns(node, domain).await == Some(expected) {
            return;
        }
        assert!(
            Instant::now() < until,
            "DNS {domain} blocked={blocked} timed out: {}",
            node.diagnostics("wait for DNS policy")
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}
async fn upstream() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        loop {
            let (n, peer) = socket.recv_from(&mut bytes).await.unwrap();
            let request = Message::from_vec(&bytes[..n]).unwrap();
            let mut reply = Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
            reply.metadata.recursion_available = true;
            for query in &request.queries {
                reply.add_query(query.clone());
                reply.add_answer(Record::from_rdata(
                    query.name().clone(),
                    0,
                    RData::A(A(Ipv4Addr::new(203, 0, 113, 7))),
                ));
            }
            socket
                .send_to(&reply.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    (addr, task)
}
struct Origin {
    path: PathBuf,
    watcher: std::fs::File,
    reads: Cell<usize>,
}
impl Origin {
    fn new(primary: &Node) -> Self {
        let directory = primary.root.path().join("lists");
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("fixture.txt");
        write(&path, b"list-initial.example.test\n");
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        assert!(fd >= 0);
        let watcher = unsafe { std::fs::File::from_raw_fd(fd) };
        let name = std::ffi::CString::new(directory.as_os_str().as_bytes()).unwrap();
        assert!(unsafe { libc::inotify_add_watch(fd, name.as_ptr(), libc::IN_OPEN) } >= 0);
        Self {
            path,
            watcher,
            reads: Cell::new(0),
        }
    }
    fn acquisitions(&self) -> usize {
        let mut bytes = [0_u8; 8192];
        loop {
            let n = match (&self.watcher).read(&mut bytes) {
                Ok(0) => break,
                Ok(n) => n,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("origin observation failed: {error}"),
            };
            let mut offset = 0;
            while offset < n {
                let mask = u32::from_ne_bytes(bytes[offset + 4..offset + 8].try_into().unwrap());
                let len = u32::from_ne_bytes(bytes[offset + 12..offset + 16].try_into().unwrap())
                    as usize;
                let name = &bytes[offset + 16..offset + 16 + len];
                if mask & libc::IN_OPEN != 0
                    && name.split(|byte| *byte == 0).next() == Some(b"fixture.txt")
                {
                    self.reads.set(self.reads.get() + 1);
                }
                assert_eq!(
                    mask & libc::IN_Q_OVERFLOW,
                    0,
                    "origin observation overflowed"
                );
                offset += 16 + len;
            }
        }
        self.reads.get()
    }
}
async fn invite(primary: &Node) -> SecretString {
    let plan = lifecycle::preview(&primary.master, LifecycleRequest::Invite)
        .await
        .unwrap();
    lifecycle::apply(&primary.master, &plan.id)
        .await
        .unwrap()
        .invitation
        .unwrap()
}
async fn join(primary: &Node, node: &Node, url: &str) -> String {
    let invitation = invite(primary).await;
    let plan = lifecycle::preview(
        &node.master,
        LifecycleRequest::Join {
            primary: url.into(),
            invitation,
            node_name: Some("duplicate".into()),
        },
    )
    .await
    .unwrap_or_else(|error| {
        panic!(
            "join preview failed: {error:#}; primary {}",
            primary.log_text()
        )
    });
    let id = plan.local_node_id.clone();
    let result = lifecycle::apply(&node.master, &plan.id).await.unwrap();
    assert_eq!(result.status.saved_role, NodeRole::Secondary);
    assert!(result.status.restart_required);
    id
}
async fn wait_pair(node: &Node, stage: &str) -> LifecycleStatus {
    let until = Instant::now() + Duration::from_secs(35);
    loop {
        let state = node.status(stage).await;
        if state.active_policy.is_some()
            && state.active_corpus.is_some()
            && state.last_error.is_none()
        {
            return state;
        }
        assert!(
            Instant::now() < until,
            "active pair not confirmed {state:?}: {}",
            node.diagnostics(stage)
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_nodes_pair_over_tls_replicate_policy_and_corpus_and_keep_dns_after_revocation_outage(
) {
    let (upstream, upstream_task) = upstream().await;
    let primary = Node::new("primary", upstream);
    let origin = Origin::new(&primary);
    let first = Node::new("secondary-one", upstream);
    let second = Node::new("secondary-two", upstream);
    let mut config: ConfigV5 =
        toml::from_str(&std::fs::read_to_string(&primary.master).unwrap()).unwrap();
    config.blocklists.push(
        toml::from_str("id=\"fixture\"\ndisplay_name=\"Isolated origin\"\nurl=\"https://imported.local/fixture.txt\"\ntrust=\"local\"\n")
        .unwrap(),
    );
    write(
        &primary.master,
        toml::to_string_pretty(&config).unwrap().as_bytes(),
    );
    write(
        &primary.root.path().join("packs/local.txt"),
        b"||policy-initial.example.test^\n",
    );
    let api = free_tcp();
    let url = format!("https://{api}");
    eprintln!("nodes E2E stage: create primary");
    let creation = lifecycle::preview(
        &primary.master,
        LifecycleRequest::Create {
            san: vec!["127.0.0.1".into()],
            api_listen: Some(api),
            migrate_legacy: false,
        },
    )
    .await
    .unwrap();
    lifecycle::apply(&primary.master, &creation.id)
        .await
        .unwrap();
    eprintln!("nodes E2E stage: start primary");
    let mut primary_daemon = Daemon::spawn(&primary);
    primary_daemon.ready(&primary).await;
    wait_dns(&primary, "list-initial.example.test", true).await;
    wait_pair(&primary, "initial primary pair").await;
    let initial_origin_requests = origin.acquisitions();
    assert!(initial_origin_requests >= 1);
    let primary_status = primary.status("verify primary TLS identity").await;
    let fingerprint = primary_status.primary_fingerprint.clone().unwrap();
    let pinned = purge_warden::cluster::pinned::build_fingerprint_client(
        &url,
        &fingerprint,
        Duration::from_secs(3),
    )
    .unwrap();
    assert_eq!(
        pinned
            .get(format!("{url}/api/cluster/v2/status"))
            .bearer_auth(&primary.admin)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "general API admin token must not authenticate as a node"
    );
    eprintln!("nodes E2E stage: join secondary one");
    let first_id = join(&primary, &first, &url).await;
    eprintln!("nodes E2E stage: join secondary two");
    let second_id = join(&primary, &second, &url).await;
    assert_ne!(first_id, second_id);
    eprintln!("nodes E2E stage: start both secondaries");
    let mut first_daemon = Daemon::spawn(&first);
    let mut second_daemon = Daemon::spawn(&second);
    first_daemon.ready(&first).await;
    second_daemon.ready(&second).await;
    for node in [&first, &second] {
        wait_dns(node, "policy-initial.example.test", true).await;
        wait_dns(node, "list-initial.example.test", true).await;
        wait_dns(node, "old-local.example.test", false).await;
        wait_pair(node, "initial secondary pair").await;
    }
    assert_eq!(
        origin.acquisitions(),
        initial_origin_requests,
        "joining and booting two secondaries must make no source acquisitions"
    );
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        let roster = primary
            .status("confirm distinct peers behind NAT")
            .await
            .roster;
        if roster
            .iter()
            .filter(|p| {
                p.state == MemberState::Active
                    && p.name == "duplicate"
                    && p.last_confirmation_secs.is_some()
            })
            .count()
            == 2
        {
            assert!(roster.iter().any(|p| p.node_id == first_id));
            assert!(roster.iter().any(|p| p.node_id == second_id));
            assert!(roster
                .iter()
                .filter(|p| p.state == MemberState::Active)
                .all(|p| p.endpoint.as_deref() == Some("127.0.0.1")));
            break;
        }
        assert!(
            Instant::now() < until,
            "NAT roster conflated stable IDs: {roster:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let before = first
        .status("before list-only refresh")
        .await
        .active_policy
        .unwrap();
    write(
        &origin.path,
        b"list-initial.example.test\nlist-later.example.test\n",
    );
    eprintln!("nodes E2E stage: request primary list-only refresh");
    let refreshed = purge_warden::ipc::socket_client::send_command(
        &primary.socket,
        &IpcCommand::ForceListRefresh {
            token: Some(primary.admin.clone()),
        },
    )
    .await
    .unwrap_or_else(|error| {
        panic!(
            "ForceListRefresh failed: {error:#}\n{}",
            primary.diagnostics("primary list-only refresh")
        )
    });
    eprintln!("nodes E2E primary list-only refresh reply: {refreshed:?}");
    assert!(
        !matches!(refreshed, IpcResponse::Error { .. }),
        "{refreshed:?}"
    );
    for node in [&first, &second] {
        wait_dns(node, "list-later.example.test", true).await;
        wait_pair(node, "after list-only refresh").await;
    }
    assert_eq!(
        first
            .status("check list-only policy identity")
            .await
            .active_policy
            .as_ref(),
        Some(&before),
        "list-only update changed policy identity"
    );
    assert!(
        origin.acquisitions() > initial_origin_requests,
        "primary refresh did not acquire changed origin"
    );
    for node in [&first, &second] {
        assert!(
            !node.root.path().join("lists/fixture.txt").exists(),
            "secondary acquired a local origin"
        );
    }
    write(
        &primary.root.path().join("packs/local.txt"),
        b"||policy-initial.example.test^\n||policy-later.example.test^\n",
    );
    eprintln!("nodes E2E stage: reload primary policy");
    primary_daemon.hup();
    for node in [&first, &second] {
        wait_dns(node, "policy-later.example.test", true).await;
    }
    eprintln!("nodes E2E stage: revoke secondary two");
    let revoked = lifecycle::preview(
        &primary.master,
        LifecycleRequest::Revoke {
            node_id: second_id.clone(),
        },
    )
    .await
    .unwrap();
    lifecycle::apply(&primary.master, &revoked.id)
        .await
        .unwrap();
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        if second
            .status("wait for revocation")
            .await
            .last_error
            .is_some()
        {
            break;
        }
        assert!(
            Instant::now() < until,
            "revocation never made replication stale"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    write(&primary.root.path().join("packs/local.txt"),b"||policy-initial.example.test^\n||policy-later.example.test^\n||after-revoke.example.test^\n");
    primary_daemon.hup();
    wait_dns(&first, "after-revoke.example.test", true).await;
    wait_dns(&second, "after-revoke.example.test", false).await;
    wait_dns(&second, "policy-later.example.test", true).await;
    eprintln!("nodes E2E stage: reload inline IP policy after revocation");
    let mut current: ConfigV5 =
        toml::from_str(&std::fs::read_to_string(&primary.master).unwrap()).unwrap();
    current.ip_blocklists.enabled = true;
    current.ip_blocklists.inline = vec!["203.0.113.7".into()];
    write(
        &primary.master,
        toml::to_string_pretty(&current).unwrap().as_bytes(),
    );
    primary_daemon.hup();
    wait_dns(&primary, "ip-after-revoke.example.test", true).await;
    wait_dns(&first, "ip-after-revoke.example.test", true).await;
    wait_dns(&second, "ip-after-revoke.example.test", false).await;
    eprintln!("nodes E2E stage: stop primary and revoked secondary");
    primary_daemon.stop().await;
    second_daemon.stop().await;
    let count_before_restart = origin.acquisitions();
    eprintln!("nodes E2E stage: restart revoked secondary during primary outage");
    let mut restarted = Daemon::spawn(&second);
    restarted.ready(&second).await;
    wait_dns(&second, "policy-later.example.test", true).await;
    wait_dns(&second, "list-later.example.test", true).await;
    wait_dns(&second, "after-revoke.example.test", false).await;
    assert_eq!(
        origin.acquisitions(),
        count_before_restart,
        "outage restart must not acquire list origins"
    );
    let state = second.status("restarted revoked node during outage").await;
    assert_eq!(state.node_id.as_deref(), Some(second_id.as_str()));
    assert_eq!(state.saved_role, NodeRole::Secondary);
    assert!(!state.can_edit_policy);
    assert!(state.last_error.is_some());
    eprintln!("nodes E2E stage: final cleanup");
    restarted.stop().await;
    first_daemon.stop().await;
    upstream_task.abort();
}
