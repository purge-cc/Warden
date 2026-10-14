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
async fn primary_pack_only_reload_rebinds_without_fetching_sources() {
    let (upstream, upstream_task) = upstream().await;
    let primary = Node::new("primary", upstream);
    let origin = Origin::new(&primary);
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
    let creation = lifecycle::preview(
        &primary.master,
        LifecycleRequest::Create {
            san: vec!["127.0.0.1".into()],
            api_listen: Some(free_tcp()),
            migrate_legacy: false,
        },
    )
    .await
    .unwrap();
    lifecycle::apply(&primary.master, &creation.id)
        .await
        .unwrap();
    let mut daemon = Daemon::spawn(&primary);
    daemon.ready(&primary).await;
    wait_dns(&primary, "list-initial.example.test", true).await;
    wait_pair(&primary, "before pack-only reload").await;
    let reads_before = origin.acquisitions();
    let cycle_before = list_cycle(&primary).await.seq;
    write(
        &primary.root.path().join("packs/local.txt"),
        b"||old-local.example.test^\n||policy-later.example.test^\n",
    );
    daemon.hup();
    wait_dns(&primary, "policy-later.example.test", true).await;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let cycle = list_cycle(&primary).await;
        if cycle.seq > cycle_before {
            assert_eq!(
                cycle.outcome,
                Some(purge_warden::lists::status::CycleOutcome::SkippedUnchanged),
                "pack-only reload rebuilt the external list corpus"
            );
            break;
        }
        assert!(Instant::now() < deadline, "primary reload did not complete");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        origin.acquisitions(),
        reads_before,
        "origin was fetched again"
    );
    daemon.stop().await;
    upstream_task.abort();
}

async fn list_cycle(node: &Node) -> purge_warden::lists::status::CycleMark {
    let response =
        purge_warden::ipc::socket_client::send_command(&node.socket, &IpcCommand::Status)
            .await
            .unwrap();
    match response {
        IpcResponse::Status {
            lists_cycle: Some(cycle),
            ..
        } => cycle,
        response => panic!("primary list cycle unavailable: {response:?}"),
    }
}

async fn stale_lists(node: &Node) -> u32 {
    match purge_warden::ipc::socket_client::send_command(&node.socket, &IpcCommand::Status)
        .await
        .unwrap()
    {
        IpcResponse::Status {
            lc2_list_diagnostics,
            ..
        } => lc2_list_diagnostics.stale_over_7d,
        response => panic!("status unavailable: {response:?}"),
    }
}

/// A rebuild reload on a Nodes primary prepares its generation without
/// writing state; once installed, that generation must own the state
/// `warden status` reads and both ledgers on disk, and keep the status of
/// every source it did not refresh.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn primary_rebuild_reload_persists_list_state_and_reports_it() {
    let (upstream, upstream_task) = upstream().await;
    let primary = Node::new("primary", upstream);
    let _origin = Origin::new(&primary);
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
    let creation = lifecycle::preview(
        &primary.master,
        LifecycleRequest::Create {
            san: vec!["127.0.0.1".into()],
            api_listen: Some(free_tcp()),
            migrate_legacy: false,
        },
    )
    .await
    .unwrap();
    lifecycle::apply(&primary.master, &creation.id)
        .await
        .unwrap();
    // The boot generation never fetches `later`, so only a reload can
    // refresh this 8-day-old success.
    let data = primary.root.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    let state_path = data.join("list_state.toml");
    let schedule_path = data.join("list_schedule_state.toml");
    let old = (time::OffsetDateTime::now_utc() - time::Duration::days(8))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    write(
        &state_path,
        format!("[lists.later]\nstatus = \"active\"\nlast_success = \"{old}\"\n").as_bytes(),
    );
    let mut daemon = Daemon::spawn(&primary);
    daemon.ready(&primary).await;
    wait_dns(&primary, "list-initial.example.test", true).await;
    wait_pair(&primary, "before list-adding reload").await;
    assert_eq!(stale_lists(&primary).await, 1);

    // `later` has no body yet: the reload serves the Partial corpus and the
    // node corpus waits for a complete cycle.
    let mut config: ConfigV5 =
        toml::from_str(&std::fs::read_to_string(&primary.master).unwrap()).unwrap();
    config.blocklists.push(
        toml::from_str("id=\"later\"\ndisplay_name=\"Added on reload\"\nurl=\"https://imported.local/later.txt\"\ntrust=\"local\"\n")
            .unwrap(),
    );
    write(
        &primary.master,
        toml::to_string_pretty(&config).unwrap().as_bytes(),
    );
    let partial_before = list_cycle(&primary).await.seq;
    daemon.hup();
    next_list_cycle(&primary, partial_before).await;
    let log = primary.log_text();
    assert!(log.contains("partial list corpus serving locally"), "{log}");
    assert!(!log.contains("node corpus rejected"), "{log}");
    assert_eq!(stale_lists(&primary).await, 1);

    write(
        &primary.root.path().join("lists/later.txt"),
        b"list-added.example.test\n",
    );
    let cycle_before = list_cycle(&primary).await.seq;
    daemon.hup();
    wait_dns(&primary, "list-added.example.test", true).await;
    let deadline = Instant::now() + Duration::from_secs(15);
    while list_cycle(&primary).await.seq <= cycle_before || stale_lists(&primary).await != 0 {
        assert!(
            Instant::now() < deadline,
            "reload left stale_over_7d at {}: {}",
            stale_lists(&primary).await,
            primary.diagnostics("after list-adding reload")
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // `fixture` is not due, so the reload must not reset its status.
    match purge_warden::ipc::socket_client::send_command(&primary.socket, &IpcCommand::Status)
        .await
        .unwrap()
    {
        IpcResponse::Status {
            lists_active,
            lists_total,
            ..
        } => assert_eq!(
            (lists_active, lists_total),
            (2, 2),
            "the reload reset a source it did not refresh"
        ),
        response => panic!("status unavailable: {response:?}"),
    }
    let state = std::fs::read_to_string(&state_path).unwrap();
    assert!(state.contains("[lists.fixture]") && state.contains("[lists.later]"));
    assert!(
        !state.contains(&old),
        "the refreshed success never reached disk"
    );
    let schedules: toml::Table =
        toml::from_str(&std::fs::read_to_string(&schedule_path).unwrap()).unwrap();
    assert_eq!(
        schedules["schedules"].as_table().unwrap().len(),
        2,
        "the added source has no scheduling row"
    );

    // The new controller's command channel opens just after the cycle mark.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match purge_warden::ipc::socket_client::send_command(
            &primary.socket,
            &IpcCommand::ForceListRefresh {
                token: Some(primary.admin.clone()),
            },
        )
        .await
        {
            Ok(IpcResponse::ListRefreshCompleted { .. }) => break,
            other => assert!(Instant::now() < deadline, "forced refresh: {other:?}"),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_ne!(
        std::fs::read_to_string(&state_path).unwrap(),
        state,
        "a transition after the reload did not write through"
    );
    daemon.stop().await;
    upstream_task.abort();
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

/// An API private key the daemon cannot read turns the REST API off; the
/// daemon keeps serving DNS instead of exiting after the bind.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn missing_api_tls_key_disables_rest_and_keeps_dns_serving() {
    let (upstream, task) = upstream().await;
    let node = Node::new("tls", upstream);
    let api_listen = free_tcp();
    let certificate = node.root.path().join("api.crt");
    write(&certificate, b"placeholder certificate\n");
    let mut config: ConfigV5 =
        toml::from_str(&std::fs::read_to_string(&node.master).unwrap()).unwrap();
    config.api.enabled = true;
    config.api.listen = api_listen;
    config.api.tls_cert = Some(certificate);
    // A missing file fails to read even when the test runs as root.
    config.api.tls_key = Some(node.root.path().join("missing.key"));
    write(
        &node.master,
        toml::to_string_pretty(&config).unwrap().as_bytes(),
    );

    let mut daemon = Daemon::spawn(&node);
    daemon.ready(&node).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        daemon.child.as_mut().unwrap().try_wait().unwrap().is_none(),
        "daemon exited: {}",
        node.diagnostics("unreadable API key")
    );
    assert!(
        std::net::TcpStream::connect(api_listen).is_err(),
        "REST API must stay off"
    );
    let log = node.log_text();
    assert!(log.contains("failed to start REST API server"), "{log}");
    assert!(log.contains("failed to read API private key"), "{log}");
    daemon.stop().await;
    task.abort();
}

async fn node_control(
    node: &Node,
    request: purge_warden::cluster::node_control::NodeControlCommand,
) -> purge_warden::cluster::node_control::NodeControlReply {
    let response = purge_warden::ipc::socket_client::send_command(
        &node.socket,
        &IpcCommand::NodeControl {
            request,
            token: Some(node.admin.clone()),
        },
    )
    .await
    .unwrap();
    match response {
        IpcResponse::NodeControl { reply } => *reply,
        other => panic!(
            "unexpected node control reply: {other:?}\n{}",
            node.diagnostics("node control")
        ),
    }
}

/// A stored Nodes listener whose port is taken at restart is skipped and
/// reported under the Nodes status; DNS keeps serving.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn occupied_nodes_endpoint_is_skipped_at_restart_and_reported() {
    use purge_warden::cluster::node_control::NodeControlCommand;
    let (upstream, task) = upstream().await;
    let node = Node::new("occupied", upstream);
    let mut daemon = Daemon::spawn(&node);
    daemon.ready(&node).await;
    let endpoint = free_tcp();
    // Over IPC with the node's own token: the CLI may read the host's
    // global token file.
    let issued = node_control(
        &node,
        NodeControlCommand::TokenPrepare {
            listen: Some(endpoint),
        },
    )
    .await;
    assert!(issued.token.is_some());
    daemon.stop().await;

    let _hold = TcpListener::bind(endpoint).unwrap();
    let mut daemon = Daemon::spawn(&node);
    daemon.ready(&node).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        daemon.child.as_mut().unwrap().try_wait().unwrap().is_none(),
        "daemon exited: {}",
        node.diagnostics("occupied Nodes endpoint")
    );
    let status = node_control(&node, NodeControlCommand::Status).await.status;
    assert!(
        status
            .runtime_problems
            .iter()
            .any(|problem| problem.contains(&endpoint.to_string())),
        "{:?}\n{}",
        status.runtime_problems,
        node.diagnostics("occupied Nodes endpoint")
    );
    daemon.stop().await;
    task.abort();
}

/// A Nodes store the daemon cannot read at start keeps DNS serving; the
/// bring-up is reported and retried until the store is fixed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn corrupt_nodes_state_keeps_dns_serving_until_it_is_fixed() {
    use purge_warden::cluster::node_control::NodeControlCommand;
    let (upstream, task) = upstream().await;
    let node = Node::new("corrupt", upstream);
    // A first start writes the store (one namespace per master) in its
    // Nodes bring-up, which may finish after DNS is ready. Wait for it, then
    // corrupt the state in place, keeping the owner and mode the store checks.
    let mut daemon = Daemon::spawn(&node);
    daemon.ready(&node).await;
    let store = node.root.path().join(".warden-node-control");
    let until = Instant::now() + Duration::from_secs(15);
    let state = loop {
        let written = std::fs::read_dir(&store)
            .into_iter()
            .flatten()
            .map(|entry| entry.unwrap().path().join("state.json"))
            .find(|state| state.exists());
        if let Some(state) = written {
            break state;
        }
        assert!(
            Instant::now() < until,
            "{}",
            node.diagnostics("Nodes store")
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    daemon.stop().await;
    std::fs::write(&state, b"{").unwrap();

    let mut daemon = Daemon::spawn(&node);
    daemon.ready(&node).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        daemon.child.as_mut().unwrap().try_wait().unwrap().is_none(),
        "daemon exited: {}",
        node.diagnostics("corrupt Nodes state")
    );
    // A never-paired host answers status without opening the store.
    let status = node_control(&node, NodeControlCommand::Status).await.status;
    assert!(
        status
            .runtime_problems
            .iter()
            .any(|problem| problem.contains("runtime start pending")),
        "{:?}",
        status.runtime_problems
    );

    std::fs::remove_file(&state).unwrap();
    let until = Instant::now() + Duration::from_secs(15);
    loop {
        let status = node_control(&node, NodeControlCommand::Status).await.status;
        if status.runtime_problems.is_empty() {
            break;
        }
        assert!(
            Instant::now() < until,
            "{:?}\n{}",
            status.runtime_problems,
            node.diagnostics("fixed Nodes state")
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    daemon.stop().await;
    task.abort();
}

/// Start once so the Nodes store exists, stop, and hold its lock: the next
/// start serves DNS while its Nodes bring-up waits on this lock (up to 30 s).
/// The boot before DNS does not take this lock.
async fn hold_nodes_store_lock(node: &Node) -> std::fs::File {
    use std::os::fd::AsRawFd;
    let mut daemon = Daemon::spawn(node);
    daemon.ready(node).await;
    let store = node.root.path().join(".warden-node-control");
    let until = Instant::now() + Duration::from_secs(15);
    let namespace = loop {
        let written = std::fs::read_dir(&store)
            .into_iter()
            .flatten()
            .map(|entry| entry.unwrap().path())
            .find(|namespace| namespace.join("state.json").exists());
        if let Some(namespace) = written {
            break namespace;
        }
        assert!(
            Instant::now() < until,
            "{}",
            node.diagnostics("Nodes store")
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    daemon.stop().await;
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(namespace.join(".lock"))
        .unwrap();
    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    lock
}

/// A SIGHUP while the Nodes bring-up waits on a lock does not end a daemon
/// that serves DNS; it is applied as a reload once the bring-up ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sighup_during_nodes_bring_up_is_applied_after_it() {
    let (upstream, task) = upstream().await;
    let node = Node::new("bring-up-hup", upstream);
    let lock = hold_nodes_store_lock(&node).await;
    let mut daemon = Daemon::spawn(&node);
    daemon.ready(&node).await;
    write(
        &node.root.path().join("packs/local.txt"),
        b"||old-local.example.test^\n||after-hup.example.test^\n",
    );
    daemon.hup();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        daemon.child.as_mut().unwrap().try_wait().unwrap().is_none(),
        "daemon exited: {}",
        node.diagnostics("SIGHUP during the Nodes bring-up")
    );
    assert_eq!(
        dns(&node, "ready.example.test").await,
        Some(Ipv4Addr::new(203, 0, 113, 7))
    );
    drop(lock);
    wait_dns(&node, "after-hup.example.test", true).await;
    assert!(daemon.child.as_mut().unwrap().try_wait().unwrap().is_none());
    daemon.stop().await;
    task.abort();
}

/// A SIGTERM while the Nodes bring-up waits on a lock stops the daemon at
/// once and cleanly: DNS stops while the lock is still held, the process
/// exits 0 and removes its PID file.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sigterm_during_nodes_bring_up_stops_cleanly() {
    let (upstream, task) = upstream().await;
    let node = Node::new("bring-up-term", upstream);
    let lock = hold_nodes_store_lock(&node).await;
    let mut daemon = Daemon::spawn(&node);
    daemon.ready(&node).await;
    let pid_file = node.root.path().join("purge-warden.pid");
    assert!(pid_file.exists());
    let child = daemon.child.as_mut().unwrap();
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
    let until = Instant::now() + Duration::from_secs(5);
    while dns(&node, "ready.example.test").await.is_some() {
        assert!(
            Instant::now() < until,
            "DNS still serving after SIGTERM: {}",
            node.diagnostics("SIGTERM during the Nodes bring-up")
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    drop(lock);
    let until = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < until,
            "daemon did not stop: {}",
            node.diagnostics("SIGTERM during the Nodes bring-up")
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert!(
        status.success(),
        "{status}: {}",
        node.diagnostics("SIGTERM during the Nodes bring-up")
    );
    assert!(!pid_file.exists());
    task.abort();
}

/// A SIGHUP while the boot has not yet bound DNS does not end it; the daemon
/// then serves DNS and applies the SIGHUP as a reload. The boot waits
/// on the config tree lock this test holds: the recovery before the config
/// load takes it, with a 30 s deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sighup_before_dns_is_bound_is_applied_after_the_boot() {
    use std::os::fd::AsRawFd;
    let (upstream, task) = upstream().await;
    let node = Node::new("pre-bind-hup", upstream);
    let mut config: ConfigV5 =
        toml::from_str(&std::fs::read_to_string(&node.master).unwrap()).unwrap();
    config.server.log_level = "info".into();
    write(
        &node.master,
        toml::to_string_pretty(&config).unwrap().as_bytes(),
    );
    let lock = std::fs::File::open(node.root.path()).unwrap();
    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    let mut daemon = Daemon::spawn(&node);
    // Send once the boot catches SIGHUP, or after 5 s when it does not.
    let status = format!("/proc/{}/status", node.pid.get().unwrap());
    let until = Instant::now() + Duration::from_secs(5);
    while Instant::now() < until {
        let caught = std::fs::read_to_string(&status)
            .unwrap_or_default()
            .lines()
            .find_map(|line| line.strip_prefix("SigCgt:"))
            .and_then(|mask| u64::from_str_radix(mask.trim(), 16).ok())
            .is_some_and(|mask| mask & (1 << (libc::SIGHUP - 1)) != 0);
        if caught {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    daemon.hup();
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        daemon.child.as_mut().unwrap().try_wait().unwrap().is_none(),
        "daemon exited: {}",
        node.diagnostics("SIGHUP before DNS is bound")
    );
    assert_eq!(dns(&node, "ready.example.test").await, None);
    drop(lock);
    daemon.ready(&node).await;
    let until = Instant::now() + Duration::from_secs(15);
    while !node
        .log_text()
        .contains("SIGHUP received, reloading config and lists")
    {
        assert!(
            Instant::now() < until,
            "SIGHUP not applied: {}",
            node.diagnostics("SIGHUP before DNS is bound")
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(daemon.child.as_mut().unwrap().try_wait().unwrap().is_none());
    daemon.stop().await;
    task.abort();
}

/// A SIGTERM in the Nodes bring-up of a secondary stops it without starting
/// the secondary poll loop, which could otherwise write the configuration
/// although the acknowledgement never ran.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sigterm_during_secondary_bring_up_does_not_start_the_poll_loop() {
    let (upstream, task) = upstream().await;
    let primary = Node::new("bring-up-term-primary", upstream);
    let api = free_tcp();
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
    let mut primary_daemon = Daemon::spawn(&primary);
    primary_daemon.ready(&primary).await;
    wait_pair(&primary, "bring-up-term primary").await;
    let node = Node::new("bring-up-term-secondary", upstream);
    let mut config: ConfigV5 =
        toml::from_str(&std::fs::read_to_string(&node.master).unwrap()).unwrap();
    config.server.log_level = "info".into();
    write(
        &node.master,
        toml::to_string_pretty(&config).unwrap().as_bytes(),
    );
    join(&primary, &node, &format!("https://{api}")).await;
    // Without a SIGTERM the secondary starts its poll loop.
    let poll_loop = "cluster: starting secondary poll loop";
    let mut daemon = Daemon::spawn(&node);
    daemon.ready(&node).await;
    let until = Instant::now() + Duration::from_secs(35);
    while !node.log_text().contains(poll_loop) {
        assert!(
            Instant::now() < until,
            "{}",
            node.diagnostics("secondary poll loop")
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    daemon.stop().await;

    let lock = hold_nodes_store_lock(&node).await;
    let before = node.log_text().len();
    let mut daemon = Daemon::spawn(&node);
    daemon.ready(&node).await;
    let child = daemon.child.as_mut().unwrap();
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
    let until = Instant::now() + Duration::from_secs(5);
    while dns(&node, "ready.example.test").await.is_some() {
        assert!(
            Instant::now() < until,
            "DNS still serving after SIGTERM: {}",
            node.diagnostics("SIGTERM during the secondary bring-up")
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    drop(lock);
    let until = Instant::now() + Duration::from_secs(15);
    while child.try_wait().unwrap().is_none() {
        assert!(
            Instant::now() < until,
            "daemon did not stop: {}",
            node.diagnostics("SIGTERM during the secondary bring-up")
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let log = node.log_text();
    assert!(log[before..].contains("SIGTERM received during the Nodes bring-up"));
    assert!(!log[before..].contains(poll_loop), "{}", &log[before..]);
    primary_daemon.stop().await;
    task.abort();
}

/// A Nodes primary whose first cycle is Partial binds and serves its usable
/// lists; the node corpus waits for the first complete cycle.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn partial_cluster_primary_boots_and_serves() {
    let (upstream, upstream_task) = upstream().await;
    let primary = Node::new("primary", upstream);
    let _origin = Origin::new(&primary);
    let mut config: ConfigV5 =
        toml::from_str(&std::fs::read_to_string(&primary.master).unwrap()).unwrap();
    // The second source has no local body, so it fails on every cycle.
    for id in ["fixture", "unreachable"] {
        config.blocklists.push(
            toml::from_str(&format!(
                "id=\"{id}\"\ndisplay_name=\"Isolated origin\"\nurl=\"https://imported.local/{id}.txt\"\ntrust=\"local\"\n"
            ))
            .unwrap(),
        );
    }
    write(
        &primary.master,
        toml::to_string_pretty(&config).unwrap().as_bytes(),
    );
    let creation = lifecycle::preview(
        &primary.master,
        LifecycleRequest::Create {
            san: vec!["127.0.0.1".into()],
            api_listen: Some(free_tcp()),
            migrate_legacy: false,
        },
    )
    .await
    .unwrap();
    lifecycle::apply(&primary.master, &creation.id)
        .await
        .unwrap();
    let mut daemon = Daemon::spawn(&primary);
    daemon.ready(&primary).await;
    wait_dns(&primary, "list-initial.example.test", true).await;
    assert!(
        primary
            .log_text()
            .contains("partial list corpus serving locally"),
        "{}",
        primary.diagnostics("partial primary boot")
    );
    // The node pair waits for the first complete cycle, then publishes.
    let state = primary.status("partial primary boot").await;
    assert!(state.active_corpus.is_none(), "{state:?}");
    write(
        &primary.root.path().join("lists/unreachable.txt"),
        b"later.example.test\n",
    );
    force_refresh(&primary).await;
    wait_pair(&primary, "after the first complete cycle").await;
    daemon.stop().await;
    upstream_task.abort();
}

fn rejected_reloads(node: &Node) -> usize {
    std::fs::read_to_string(node.root.path().join("audit/audit.log"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|record| record["event"] == "reload" && record["result"] == "rejected")
        .count()
}

async fn next_list_cycle(node: &Node, after: u64) -> purge_warden::lists::status::CycleMark {
    let until = Instant::now() + Duration::from_secs(35);
    loop {
        let cycle = list_cycle(node).await;
        if cycle.seq > after {
            return cycle;
        }
        assert!(
            Instant::now() < until,
            "reload did not close a cycle: {}",
            node.diagnostics("wait for reload cycle")
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn add_local_blocklist(node: &Node, id: &str) {
    let mut config: ConfigV5 =
        toml::from_str(&std::fs::read_to_string(&node.master).unwrap()).unwrap();
    config.blocklists.push(
        toml::from_str(&format!(
            "id=\"{id}\"\ndisplay_name=\"Isolated origin\"\nurl=\"https://imported.local/{id}.txt\"\ntrust=\"local\"\n"
        ))
        .unwrap(),
    );
    write(
        &node.master,
        toml::to_string_pretty(&config).unwrap().as_bytes(),
    );
}

/// A reload that cannot isolate the live list cache (a rollback journal is
/// pending) is rejected with one audit record, and DNS keeps serving.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reload_with_cache_journal_rejects_with_one_audit_record() {
    let (upstream, upstream_task) = upstream().await;
    let node = Node::new("standalone", upstream);
    let _origin = Origin::new(&node);
    add_local_blocklist(&node, "fixture");
    let mut daemon = Daemon::spawn(&node);
    daemon.ready(&node).await;
    wait_dns(&node, "list-initial.example.test", true).await;
    write(
        &node
            .root
            .path()
            .join("lists/.warden-cache-rollback-v1.json"),
        b"{}",
    );
    // A second source changes the list fingerprint, so the reload rebuilds.
    write(
        &node.root.path().join("lists/second.txt"),
        b"second.example.test\n",
    );
    add_local_blocklist(&node, "second");
    let before = list_cycle(&node).await.seq;
    daemon.hup();
    let cycle = next_list_cycle(&node, before).await;
    assert_eq!(
        cycle.outcome,
        Some(purge_warden::lists::status::CycleOutcome::ConfigRejected)
    );
    assert_eq!(rejected_reloads(&node), 1, "{}", node.diagnostics("audit"));
    wait_dns(&node, "list-initial.example.test", true).await;
    daemon.stop().await;
    upstream_task.abort();
}

async fn create_primary(node: &Node) {
    let creation = lifecycle::preview(
        &node.master,
        LifecycleRequest::Create {
            san: vec!["127.0.0.1".into()],
            api_listen: Some(free_tcp()),
            migrate_legacy: false,
        },
    )
    .await
    .unwrap();
    lifecycle::apply(&node.master, &creation.id).await.unwrap();
}

/// A reload whose IP list source cannot be fetched is rejected with one
/// audit record, and DNS keeps serving. IP lists reload without a restart
/// only on a Nodes primary.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reload_with_failing_ip_source_writes_rejected_audit() {
    let (upstream, upstream_task) = upstream().await;
    let node = Node::new("primary", upstream);
    let _origin = Origin::new(&node);
    add_local_blocklist(&node, "fixture");
    create_primary(&node).await;
    let mut daemon = Daemon::spawn(&node);
    daemon.ready(&node).await;
    wait_dns(&node, "list-initial.example.test", true).await;
    let mut config: ConfigV5 =
        toml::from_str(&std::fs::read_to_string(&node.master).unwrap()).unwrap();
    config.ip_blocklists.enabled = true;
    // Lint accepts a name; preparation fails because `.invalid` never resolves.
    config.ip_blocklists.sources = vec!["https://ips.invalid/ips".into()];
    write(
        &node.master,
        toml::to_string_pretty(&config).unwrap().as_bytes(),
    );
    let before = list_cycle(&node).await.seq;
    daemon.hup();
    let cycle = next_list_cycle(&node, before).await;
    assert_eq!(
        cycle.outcome,
        Some(purge_warden::lists::status::CycleOutcome::ConfigRejected)
    );
    assert_eq!(rejected_reloads(&node), 1, "{}", node.diagnostics("audit"));
    assert!(
        node.log_text()
            .contains("reload rejected: IP corpus preparation failed"),
        "{}",
        node.diagnostics("reload")
    );
    wait_dns(&node, "list-initial.example.test", true).await;
    daemon.stop().await;
    upstream_task.abort();
}

async fn force_refresh(node: &Node) {
    // The controller's command channel opens just after the cycle mark.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match purge_warden::ipc::socket_client::send_command(
            &node.socket,
            &IpcCommand::ForceListRefresh {
                token: Some(node.admin.clone()),
            },
        )
        .await
        {
            Ok(IpcResponse::ListRefreshCompleted { .. }) => return,
            other => assert!(Instant::now() < deadline, "forced refresh: {other:?}"),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn active_generation(node: &Node) -> Option<String> {
    let pair: serde_json::Value = serde_json::from_slice(
        &std::fs::read(node.root.path().join(".warden-node-corpus/pair.json")).unwrap(),
    )
    .unwrap();
    pair["active"].as_str().map(str::to_owned)
}

/// A pack-only reload on a standalone host rebinds the policy to the live
/// list corpus instead of fetching every source again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn standalone_pack_only_reload_rebinds_without_fetching_sources() {
    let (upstream, upstream_task) = upstream().await;
    let node = Node::new("standalone", upstream);
    let origin = Origin::new(&node);
    add_local_blocklist(&node, "fixture");
    let mut daemon = Daemon::spawn(&node);
    daemon.ready(&node).await;
    wait_dns(&node, "list-initial.example.test", true).await;
    let reads_before = origin.acquisitions();
    let before = list_cycle(&node).await.seq;
    write(
        &node.root.path().join("packs/local.txt"),
        b"||old-local.example.test^\n||policy-later.example.test^\n",
    );
    daemon.hup();
    wait_dns(&node, "policy-later.example.test", true).await;
    assert_eq!(
        next_list_cycle(&node, before).await.outcome,
        Some(purge_warden::lists::status::CycleOutcome::SkippedUnchanged),
        "pack-only reload rebuilt the external list corpus"
    );
    assert_eq!(
        origin.acquisitions(),
        reads_before,
        "origin was fetched again"
    );
    daemon.stop().await;
    upstream_task.abort();
}

/// A standalone reload whose new source cannot be fetched serves the new
/// policy with the lists it has; the node corpus keeps its last complete
/// pair until a complete cycle publishes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn standalone_reload_with_missing_body_applies_policy() {
    let (upstream, upstream_task) = upstream().await;
    let node = Node::new("standalone", upstream);
    let _origin = Origin::new(&node);
    add_local_blocklist(&node, "fixture");
    let mut daemon = Daemon::spawn(&node);
    daemon.ready(&node).await;
    wait_dns(&node, "list-initial.example.test", true).await;
    let active = active_generation(&node);
    assert!(active.is_some(), "{}", node.diagnostics("boot"));
    // The new source has no local body, so its fetch fails at once.
    add_local_blocklist(&node, "missing");
    write(
        &node.root.path().join("packs/local.txt"),
        b"||old-local.example.test^\n||policy-later.example.test^\n",
    );
    daemon.hup();
    wait_dns(&node, "policy-later.example.test", true).await;
    wait_dns(&node, "list-initial.example.test", true).await;
    let log = node.log_text();
    assert!(!log.contains("node corpus rejected"), "{log}");
    assert!(log.contains("partial list corpus serving locally"), "{log}");
    assert_eq!(rejected_reloads(&node), 0, "{}", node.diagnostics("audit"));
    assert_eq!(active_generation(&node), active);
    write(
        &node.root.path().join("lists/missing.txt"),
        b"missing-later.example.test\n",
    );
    force_refresh(&node).await;
    wait_dns(&node, "missing-later.example.test", true).await;
    assert_ne!(
        active_generation(&node),
        active,
        "the complete cycle did not publish"
    );
    daemon.stop().await;
    upstream_task.abort();
}
