#![cfg(feature = "cluster")]

//! One real primary/secondary composition for the v2 schema-5 artifact path.
//!
//! This deliberately uses two `warden` processes and the public wire/IPC
//! surfaces. The detailed malformed-object matrix belongs to the artifact and
//! poll unit tests; this test pins their most valuable composition boundary:
//! an empty receiver only promotes a complete, activated artifact and keeps
//! its previous active policy when the next advertised artifact is unavailable.

use std::fs::OpenOptions;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use purge_warden::config::schema::{ClusterRole, ConfigV5, CustomList, Id, ProfileV5};
use purge_warden::ipc::protocol::{ClusterStatusDto, IpcCommand, IpcResponse};
use tempfile::TempDir;
use tokio::net::UdpSocket;

const CLUSTER_TOKEN: &str = "ps_uor8_cluster_replica_token";
const MOUNTED: &str = "mounted";
const UNMOUNTED: &str = "unmounted";
const MUTATED_DOMAIN: &str = "newer.example.test";
const MISSING_DOMAIN: &str = "missing.example.test";
const FIRST_UPSTREAM_A: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 71);
const FIRST_UPSTREAM_AAAA: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 71);
const SECOND_UPSTREAM_A: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 72);
const SECOND_UPSTREAM_AAAA: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 72);

struct Node {
    root: TempDir,
    config: PathBuf,
    socket: PathBuf,
    xdg: PathBuf,
    api: Option<SocketAddr>,
    dns_addr: SocketAddr,
    log: PathBuf,
}

struct Daemon {
    child: Option<Child>,
    log: PathBuf,
}

impl Daemon {
    fn spawn(node: &Node) -> Self {
        let log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&node.log)
            .expect("open daemon log");
        let stderr = log_file.try_clone().expect("clone daemon log");
        let child = Command::new(env!("CARGO_BIN_EXE_warden"))
            .arg("--config")
            .arg(&node.config)
            .arg("start")
            .current_dir(node.root.path())
            .env("XDG_CONFIG_HOME", &node.xdg)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("spawn daemon");
        Self {
            child: Some(child),
            log: node.log.clone(),
        }
    }

    async fn wait_ready(&mut self, node: &Node) {
        let deadline = Instant::now() + Duration::from_secs(12);
        loop {
            if let Some(status) = self
                .child
                .as_mut()
                .expect("daemon child")
                .try_wait()
                .expect("poll daemon")
            {
                panic!(
                    "daemon exited before readiness ({status}); log:\n{}",
                    self.log()
                );
            }
            let api_ready = match node.api {
                Some(api) => reqwest::get(format!("http://{api}/healthz")).await.is_ok(),
                None => true,
            };
            let ipc_ready = matches!(
                tokio::time::timeout(
                    Duration::from_millis(250),
                    purge_warden::ipc::socket_client::send_command(
                        &node.socket,
                        &IpcCommand::Status,
                    ),
                )
                .await,
                Ok(Ok(IpcResponse::Status { .. }))
            );
            if ipc_ready && api_ready {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "daemon did not become ready; log:\n{}",
                self.log()
            );
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
    }

    async fn stop(&mut self) {
        let Some(child) = self.child.as_mut() else {
            return;
        };
        if child.try_wait().expect("poll before SIGTERM").is_none() {
            let sent = unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
            assert_eq!(sent, 0, "SIGTERM: {}", io::Error::last_os_error());
        }
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            if child.try_wait().expect("wait for daemon").is_some() {
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("daemon did not stop; log:\n{}", self.log());
            }
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
        self.child = None;
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("daemon log {}:\n{}", self.log.display(), self.log());
        }
        if let Some(child) = self.child.as_mut() {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
    }
}

fn free_tcp_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .expect("reserve TCP port")
        .local_addr()
        .unwrap()
}

fn free_dns_addr() -> SocketAddr {
    for _ in 0..32 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("reserve TCP DNS port");
        let address = listener.local_addr().unwrap();
        if std::net::UdpSocket::bind(address).is_ok() {
            return address;
        }
    }
    panic!("could not reserve a TCP+UDP DNS address");
}

#[tokio::test]
async fn readiness_requires_a_responding_daemon_not_a_socket_path() {
    let node = empty_secondary("127.0.0.1:9".parse().unwrap());
    let stale = std::os::unix::net::UnixListener::bind(&node.socket).unwrap();
    drop(stale);
    assert!(node.socket.exists());
    let child = Command::new("sleep")
        .arg("30")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut daemon = Daemon {
        child: Some(child),
        log: node.log.clone(),
    };
    assert!(
        tokio::time::timeout(Duration::from_millis(100), daemon.wait_ready(&node))
            .await
            .is_err(),
        "an unserved socket path must not satisfy daemon readiness"
    );
}

fn primary(upstream: SocketAddr) -> Node {
    let root = tempfile::tempdir().expect("primary tempdir");
    let config = root.path().join("config.toml");
    let socket = root.path().join("control.sock");
    let xdg = root.path().join("xdg");
    let log = root.path().join("daemon.log");
    let api = free_tcp_addr();
    let dns_addr = free_dns_addr();
    let mut policy = ConfigV5::default();
    let default = Id::new("default").unwrap();
    policy.server.listen = dns_addr;
    policy.server.log_level = "warn".into();
    policy.server.default_profile = Some(default.clone());
    policy.upstream.servers = vec![upstream.to_string()];
    policy.upstream.timeout_ms = 1_000;
    policy.socket.path = socket.clone();
    policy.api.enabled = true;
    policy.api.listen = api;
    policy.api.token_hash = Some(purge_warden::auth::token::hash_token(CLUSTER_TOKEN));
    policy.api.rate_limit_per_minute = 0;
    policy.tracking.enabled = false;
    policy.tracking.query_log_enabled = false;
    policy.cluster.enabled = true;
    policy.cluster.role = ClusterRole::Primary;
    policy.cluster.token_hash = Some(purge_warden::auth::token::hash_token(CLUSTER_TOKEN));
    policy.profiles.insert(
        default.to_string(),
        ProfileV5 {
            display_name: "Default".into(),
            custom_lists: vec![Id::new(MOUNTED).unwrap()],
            ..ProfileV5::default()
        },
    );
    policy.custom_lists = vec![
        CustomList {
            id: Id::new(MOUNTED).unwrap(),
            display_name: "Mounted".into(),
            description: String::new(),
        },
        CustomList {
            id: Id::new(UNMOUNTED).unwrap(),
            display_name: "Unmounted".into(),
            description: String::new(),
        },
    ];
    std::fs::create_dir_all(root.path().join("packs")).unwrap();
    std::fs::write(
        root.path().join("packs/mounted.txt"),
        b"||mounted.example.test^\n",
    )
    .unwrap();
    std::fs::write(
        root.path().join("packs/unmounted.txt"),
        b"||unmounted.example.test^\n",
    )
    .unwrap();
    std::fs::write(&config, toml::to_string_pretty(&policy).unwrap()).unwrap();

    let api_token = xdg.join("purge-warden/token");
    std::fs::create_dir_all(api_token.parent().unwrap()).unwrap();
    purge_warden::ipc::auth_token::save_token_at(&api_token, CLUSTER_TOKEN).unwrap();
    Node {
        root,
        config,
        socket,
        xdg,
        api: Some(api),
        dns_addr,
        log,
    }
}

fn empty_secondary(peer: SocketAddr) -> Node {
    let root = tempfile::tempdir().expect("secondary tempdir");
    let config = root.path().join("config.toml");
    let socket = root.path().join("control.sock");
    let xdg = root.path().join("xdg");
    let log = root.path().join("daemon.log");
    let dns_addr = free_dns_addr();
    std::fs::create_dir_all(root.path().join("cluster.d")).unwrap();
    std::fs::write(
        &config,
        format!(
            r#"schema_version = 5
includes = ["cluster.d/*.toml"]

[server]
listen = "{}"
log_level = "warn"

[socket]
path = "{}"

[tracking]
enabled = false
query_log_enabled = false

[cluster]
enabled = true
role = "secondary"
node_name = "uor8-secondary"
peer = "http://{peer}"
token_hash = "{}"
poll_interval_secs = 1
"#,
            dns_addr,
            socket.display(),
            purge_warden::auth::token::hash_token(CLUSTER_TOKEN),
        ),
    )
    .unwrap();
    purge_warden::cluster::secret::save_cluster_token(&config, CLUSTER_TOKEN).unwrap();
    Node {
        root,
        config,
        socket,
        xdg,
        api: None,
        dns_addr,
        log,
    }
}

async fn primary_desired(node: &Node) -> serde_json::Value {
    let api = node.api.expect("primary API address");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let response = reqwest::Client::new()
            .get(format!("http://{api}/api/cluster/v2/status"))
            .bearer_auth(CLUSTER_TOKEN)
            .send()
            .await
            .expect("request v2 status");
        assert!(response.status().is_success());
        let status: serde_json::Value = response.json().await.expect("v2 status JSON");
        if !status["desired"].is_null() {
            return status["desired"].clone();
        }
        assert!(
            Instant::now() < deadline,
            "primary never advertised an artifact"
        );
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
}

async fn primary_manifest(node: &Node, desired: &serde_json::Value) -> serde_json::Value {
    let api = node.api.expect("primary API address");
    let response = reqwest::Client::new()
        .get(format!(
            "http://{api}/api/cluster/v2/artifacts/{}/manifest",
            desired["artifact_hash"].as_str().expect("artifact hash")
        ))
        .bearer_auth(CLUSTER_TOKEN)
        .send()
        .await
        .expect("request v2 manifest");
    assert!(response.status().is_success());
    response.json().await.expect("v2 manifest JSON")
}

async fn secondary_metadata(node: &Node) -> purge_warden::operator_rules::Metadata {
    match purge_warden::ipc::socket_client::send_command(
        &node.socket,
        &IpcCommand::CustomListsMetadata,
    )
    .await
    .expect("read secondary metadata")
    {
        IpcResponse::CustomListsMetadata { metadata } => metadata,
        other => panic!("unexpected metadata response: {other:?}"),
    }
}

async fn secondary_status(node: &Node) -> ClusterStatusDto {
    match purge_warden::ipc::socket_client::send_command(&node.socket, &IpcCommand::ClusterStatus)
        .await
        .expect("read secondary cluster status")
    {
        IpcResponse::ClusterStatus { status } => status,
        other => panic!("unexpected cluster status response: {other:?}"),
    }
}

async fn wait_for_activation(
    node: &Node,
    desired: &serde_json::Value,
) -> purge_warden::operator_rules::Metadata {
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        let metadata = secondary_metadata(node).await;
        let status = secondary_status(node).await;
        if status.converged
            && status.last_poll_ok
            && status.config_hash == desired["artifact_hash"].as_str().unwrap()
            && metadata.activation_in_sync
            && metadata.desired_operator_policy_hash
                == desired["operator_policy_hash"].as_str().unwrap()
            && metadata.lists == 2
            && metadata.mounted_lists == 1
        {
            let active = metadata
                .active_policy
                .as_ref()
                .expect("active policy identity");
            assert_eq!(active.config_revision, metadata.config_revision);
            assert_eq!(
                active.operator_policy_hash,
                metadata.desired_operator_policy_hash
            );
            return metadata;
        }
        assert!(
            Instant::now() < deadline,
            "secondary never activated: metadata={metadata:?}, cluster={status:?}"
        );
        tokio::time::sleep(Duration::from_millis(60)).await;
    }
}

fn cli(node: &Node, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_warden"))
        .arg("--config")
        .arg(&node.config)
        .args(args)
        .current_dir(node.root.path())
        .env("XDG_CONFIG_HOME", &node.xdg)
        .output()
        .expect("run primary CLI")
}

async fn spawn_upstream(
    ipv4: Ipv4Addr,
    ipv6: Ipv6Addr,
) -> (SocketAddr, Arc<AtomicU64>, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let queries = Arc::new(AtomicU64::new(0));
    let observed = Arc::clone(&queries);
    let task = tokio::spawn(async move {
        let mut buffer = [0_u8; 4096];
        loop {
            let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let request = Message::from_vec(&buffer[..length]).unwrap();
            let query = request.queries.first().expect("upstream question");
            let data = match query.query_type() {
                RecordType::A => RData::A(A(ipv4)),
                RecordType::AAAA => RData::AAAA(AAAA(ipv6)),
                _ => continue,
            };
            if query.name().to_ascii().trim_end_matches('.') == MUTATED_DOMAIN {
                observed.fetch_add(1, Ordering::SeqCst);
            }
            let mut response =
                Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
            response.metadata.response_code = ResponseCode::NoError;
            response.metadata.recursion_available = true;
            response.add_query(query.clone());
            response.add_answer(Record::from_rdata(query.name().clone(), 300, data));
            socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    (address, queries, task)
}

async fn assert_dns(
    node: &Node,
    domain: &str,
    record_type: RecordType,
    blocked: bool,
    allowed_ipv4: Ipv4Addr,
    allowed_ipv6: Ipv6Addr,
) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut request = Message::new(0x8a18, MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
    request.add_query(hickory_proto::op::Query::query(
        Name::from_ascii(format!("{domain}.")).unwrap(),
        record_type,
    ));
    socket
        .send_to(&request.to_vec().unwrap(), node.dns_addr)
        .await
        .unwrap();
    let mut buffer = [0_u8; 4096];
    let (length, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buffer))
        .await
        .expect("secondary DNS response timeout")
        .unwrap();
    let response = Message::from_vec(&buffer[..length]).unwrap();
    let expected = match (record_type, blocked) {
        (RecordType::A, false) => RData::A(A(allowed_ipv4)),
        (RecordType::AAAA, false) => RData::AAAA(AAAA(allowed_ipv6)),
        (RecordType::A, true) => RData::A(A(Ipv4Addr::UNSPECIFIED)),
        (RecordType::AAAA, true) => RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)),
        _ => unreachable!(),
    };
    assert_eq!(response.metadata.id, request.metadata.id);
    assert_eq!(response.queries, request.queries);
    assert_eq!(
        response.metadata.response_code,
        ResponseCode::NoError,
        "{domain} {record_type:?}; daemon log: {}",
        std::fs::read_to_string(&node.log).unwrap_or_default()
    );
    assert_eq!(response.answers.len(), 1, "{domain}: {response:?}");
    assert_eq!(response.answers[0].data, expected, "{domain}");
}

fn replace_primary_upstream(primary: &Node, upstream: SocketAddr) {
    let mut policy: ConfigV5 =
        toml::from_str(&std::fs::read_to_string(&primary.config).expect("read primary config"))
            .expect("decode primary config");
    policy.upstream.servers = vec![upstream.to_string()];
    let encoded = toml::to_string_pretty(&policy).expect("encode primary config");
    purge_warden::config::atomic_write::hardened_atomic_write(
        &primary.config,
        encoded.as_bytes(),
        purge_warden::config::atomic_write::AtomicWriteOpts::default(),
    )
    .expect("replace primary upstream");
}

async fn assert_secondary_upstream_status(node: &Node, expected: SocketAddr) {
    let response =
        purge_warden::ipc::socket_client::send_command(&node.socket, &IpcCommand::Status)
            .await
            .expect("read secondary daemon status");
    let IpcResponse::Status {
        upstream_count,
        upstream_servers,
        ..
    } = response
    else {
        panic!("unexpected secondary status response: {response:?}")
    };
    assert_eq!(upstream_count, 1);
    assert_eq!(upstream_servers.len(), 1);
    assert_eq!(upstream_servers[0].address, expected.to_string());
}

async fn wait_for_changed_artifact(
    primary: &Node,
    previous: &serde_json::Value,
) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let desired = primary_desired(primary).await;
        if desired["artifact_hash"] != previous["artifact_hash"] {
            return desired;
        }
        assert!(
            Instant::now() < deadline,
            "primary never advertised the mutation"
        );
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
}

fn add_deny(primary: &Node, domain: &str, request_id: &str) {
    let mutation = cli(
        primary,
        &[
            "custom-list",
            "add",
            MOUNTED,
            domain,
            "--deny",
            "--request-id",
            request_id,
            "--json",
        ],
    );
    assert_eq!(
        mutation.status.code(),
        Some(5),
        "primary mutation failed: {}",
        String::from_utf8_lossy(&mutation.stderr)
    );
}

fn remove_advertised_object(primary: &Node, desired: &serde_json::Value) {
    let digest = desired["artifact_hash"]
        .as_str()
        .expect("advertised artifact hash");
    let expected = desired["config_revision"]
        .as_str()
        .expect("advertised revision");
    let store = primary.root.path().join(".warden-cluster-publications");
    let namespace = std::fs::read_dir(&store)
        .expect("publication store")
        .flatten()
        .find(|entry| entry.file_name() != ".lock")
        .expect("publication namespace")
        .path();
    let state: serde_json::Value = serde_json::from_slice(
        &std::fs::read(namespace.join("state.json")).expect("publication state"),
    )
    .expect("publication state JSON");
    let record = state["records"]
        .as_object()
        .unwrap()
        .values()
        .find(|record| {
            record["reservation"]["artifact_hash"].as_str() == Some(digest)
                && record["reservation"]["config_revision"].as_str() == Some(expected)
        })
        .expect("advertised publication record");
    let object = record["objects"]
        .as_object()
        .unwrap()
        .keys()
        .next()
        .expect("artifact object");
    std::fs::remove_file(namespace.join(format!("object-{object}")))
        .expect("remove artifact object");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn schema5_v2_replica_promotes_complete_packs_and_retains_prior_policy_on_missing_artifact() {
    let (first_upstream, first_queries, first_upstream_task) =
        spawn_upstream(FIRST_UPSTREAM_A, FIRST_UPSTREAM_AAAA).await;
    let (second_upstream, _second_queries, second_upstream_task) =
        spawn_upstream(SECOND_UPSTREAM_A, SECOND_UPSTREAM_AAAA).await;
    let primary = primary(first_upstream);
    let mut primary_daemon = Daemon::spawn(&primary);
    primary_daemon.wait_ready(&primary).await;

    let first = primary_desired(&primary).await;
    assert_eq!(first["artifact_hash"].as_str().unwrap().len(), 64);
    let manifest = primary_manifest(&primary, &first).await;
    assert_eq!(manifest["manifest"]["artifact_format"], 2);
    assert_eq!(manifest["manifest"]["schema_version"], 5);
    assert_eq!(manifest["manifest"]["packs"].as_array().unwrap().len(), 2);
    assert_eq!(
        manifest["manifest"]["mounts"]["default"],
        serde_json::json!([MOUNTED])
    );
    let legacy = reqwest::Client::new()
        .get(format!(
            "http://{}/api/cluster/bundle",
            primary.api.expect("primary API")
        ))
        .bearer_auth(CLUSTER_TOKEN)
        .send()
        .await
        .expect("call retired bundle route");
    assert_eq!(legacy.status(), reqwest::StatusCode::UPGRADE_REQUIRED);

    let secondary = empty_secondary(primary.api.unwrap());
    assert!(!secondary.root.path().join("packs").exists());
    let mut secondary_daemon = Daemon::spawn(&secondary);
    secondary_daemon.wait_ready(&secondary).await;
    wait_for_activation(&secondary, &first).await;
    assert_eq!(
        std::fs::read(secondary.root.path().join("packs/mounted.txt")).unwrap(),
        b"||mounted.example.test^\n"
    );
    assert_eq!(
        std::fs::read(secondary.root.path().join("packs/unmounted.txt")).unwrap(),
        b"||unmounted.example.test^\n"
    );

    for record_type in [RecordType::A, RecordType::AAAA] {
        assert_dns(
            &secondary,
            "mounted.example.test",
            record_type,
            true,
            FIRST_UPSTREAM_A,
            FIRST_UPSTREAM_AAAA,
        )
        .await;
        assert_dns(
            &secondary,
            MUTATED_DOMAIN,
            record_type,
            false,
            FIRST_UPSTREAM_A,
            FIRST_UPSTREAM_AAAA,
        )
        .await;
        assert_dns(
            &secondary,
            "unmounted.example.test",
            record_type,
            false,
            FIRST_UPSTREAM_A,
            FIRST_UPSTREAM_AAAA,
        )
        .await;
    }
    assert_eq!(first_queries.load(Ordering::SeqCst), 2);
    for record_type in [RecordType::A, RecordType::AAAA] {
        assert_dns(
            &secondary,
            MUTATED_DOMAIN,
            record_type,
            false,
            FIRST_UPSTREAM_A,
            FIRST_UPSTREAM_AAAA,
        )
        .await;
    }
    assert_eq!(
        first_queries.load(Ordering::SeqCst),
        2,
        "repeated A/AAAA queries must use the secondary cache"
    );

    replace_primary_upstream(&primary, second_upstream);
    add_deny(&primary, MUTATED_DOMAIN, "uor8-replica-new-revision");
    let second = wait_for_changed_artifact(&primary, &first).await;
    let second_secondary = wait_for_activation(&secondary, &second).await;
    assert_secondary_upstream_status(&secondary, second_upstream).await;
    // A restart would clear the cache and hide a stale-answer regression here.
    for record_type in [RecordType::A, RecordType::AAAA] {
        assert_dns(
            &secondary,
            MUTATED_DOMAIN,
            record_type,
            true,
            SECOND_UPSTREAM_A,
            SECOND_UPSTREAM_AAAA,
        )
        .await;
        assert_dns(
            &secondary,
            "unmounted.example.test",
            record_type,
            false,
            SECOND_UPSTREAM_A,
            SECOND_UPSTREAM_AAAA,
        )
        .await;
    }
    assert_eq!(first_queries.load(Ordering::SeqCst), 2);

    secondary_daemon.stop().await;
    let mut restarted_secondary = Daemon::spawn(&secondary);
    restarted_secondary.wait_ready(&secondary).await;
    let restarted = wait_for_activation(&secondary, &second).await;
    assert_eq!(restarted.config_revision, second_secondary.config_revision);
    for record_type in [RecordType::A, RecordType::AAAA] {
        assert_dns(
            &secondary,
            MUTATED_DOMAIN,
            record_type,
            true,
            SECOND_UPSTREAM_A,
            SECOND_UPSTREAM_AAAA,
        )
        .await;
        assert_dns(
            &secondary,
            MISSING_DOMAIN,
            record_type,
            false,
            SECOND_UPSTREAM_A,
            SECOND_UPSTREAM_AAAA,
        )
        .await;
    }

    // Keep the receiver on the known-good artifact while the primary advertises
    // a new revision, then make that new artifact incomplete before the next
    // fresh receiver process polls it.
    restarted_secondary.stop().await;
    add_deny(&primary, MISSING_DOMAIN, "uor8-replica-missing-revision");
    let third = wait_for_changed_artifact(&primary, &second).await;
    remove_advertised_object(&primary, &third);

    let mut refused_secondary = Daemon::spawn(&secondary);
    refused_secondary.wait_ready(&secondary).await;
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let metadata = secondary_metadata(&secondary).await;
        let status = secondary_status(&secondary).await;
        if !status.last_poll_ok && status.last_error.is_some() {
            assert!(
                metadata.activation_in_sync,
                "prior policy was not kept active"
            );
            assert_eq!(
                metadata.config_revision, second_secondary.config_revision,
                "missing artifact changed the local policy revision"
            );
            assert_eq!(
                metadata.desired_operator_policy_hash,
                second_secondary.desired_operator_policy_hash,
                "missing artifact changed the desired policy hash"
            );
            assert_eq!(
                metadata
                    .active_policy
                    .expect("prior active policy")
                    .config_revision,
                second_secondary.config_revision,
                "missing artifact changed the active policy revision"
            );
            assert!(
                status
                    .last_error
                    .as_deref()
                    .expect("failed poll error")
                    .contains("artifact"),
                "unexpected secondary refusal: {status:?}"
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "missing artifact was unexpectedly promoted"
        );
        tokio::time::sleep(Duration::from_millis(80)).await;
    }
    assert_eq!(
        std::fs::read(secondary.root.path().join("packs/unmounted.txt")).unwrap(),
        b"||unmounted.example.test^\n"
    );
    for record_type in [RecordType::A, RecordType::AAAA] {
        assert_dns(
            &secondary,
            MUTATED_DOMAIN,
            record_type,
            true,
            SECOND_UPSTREAM_A,
            SECOND_UPSTREAM_AAAA,
        )
        .await;
        assert_dns(
            &secondary,
            MISSING_DOMAIN,
            record_type,
            false,
            SECOND_UPSTREAM_A,
            SECOND_UPSTREAM_AAAA,
        )
        .await;
    }

    refused_secondary.stop().await;
    primary_daemon.stop().await;
    first_upstream_task.abort();
    second_upstream_task.abort();
}
