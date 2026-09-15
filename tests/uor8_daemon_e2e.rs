use std::fs::OpenOptions;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use purge_warden::config::schema::{ConfigV5, Id, ProfileV5};
use purge_warden::operator_rules::{
    BatchRequest, Operation, PageRequest, RuleAction, TransportLimits, CONTRACT_VERSION,
};
use reqwest::StatusCode;
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::net::UdpSocket;

const TOKEN: &str = "ps_uor8_real_process_test_token";
const CLI_DOMAIN: &str = "cli-policy.example";
const REST_DOMAIN: &str = "rest-policy.example";
const UPSTREAM_A: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 71);
const UPSTREAM_AAAA: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 71);

struct Daemon {
    child: Option<Child>,
    log_path: PathBuf,
}

impl Daemon {
    fn spawn(fixture: &Fixture) -> Self {
        let log_path = fixture.root.path().join("daemon.log");
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .expect("open daemon log");
        let stderr = log.try_clone().expect("clone daemon log");
        let child = Command::new(env!("CARGO_BIN_EXE_warden"))
            .arg("--config")
            .arg(&fixture.config)
            .arg("--pid-file")
            .arg(&fixture.pid_file)
            .arg("start")
            .current_dir(fixture.root.path())
            .env("XDG_CONFIG_HOME", &fixture.xdg)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("spawn foreground daemon");
        Self {
            child: Some(child),
            log_path,
        }
    }

    async fn wait_ready(&mut self, fixture: &Fixture) {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(250))
            .build()
            .unwrap();
        let health = format!("http://{}/healthz", fixture.api_addr);
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
            // `/healthz` remains 503 until the empty-list readiness latch is
            // opened; any HTTP response proves the real listener is bound.
            if fixture.socket.exists() && client.get(&health).send().await.is_ok() {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "daemon did not become ready; log:\n{}",
                self.log()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn stop(&mut self) {
        let Some(child) = self.child.as_mut() else {
            return;
        };
        if child.try_wait().expect("poll daemon before stop").is_none() {
            // The process is ours and SIGTERM is the daemon's normal foreground
            // shutdown path, so this also exercises socket and PID cleanup.
            let result = unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
            assert_eq!(
                result,
                0,
                "send SIGTERM to daemon: {}",
                io::Error::last_os_error()
            );
        }
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            if child.try_wait().expect("wait for daemon").is_some() {
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("daemon did not stop after SIGTERM; log:\n{}", self.log());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        self.child = None;
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
    }
}

struct Fixture {
    root: TempDir,
    config: PathBuf,
    pid_file: PathBuf,
    socket: PathBuf,
    xdg: PathBuf,
    dns_addr: SocketAddr,
    api_addr: SocketAddr,
}

impl Fixture {
    fn new(upstream_addr: SocketAddr) -> Self {
        let root = tempfile::tempdir().expect("create fixture root");
        let config = root.path().join("config.toml");
        let pid_file = root.path().join("warden.pid");
        let socket = root.path().join("control.sock");
        let xdg = root.path().join("xdg");
        let dns_addr = free_dns_addr();
        let api_addr = free_tcp_addr();

        let token_path = xdg.join("purge-warden/token");
        std::fs::create_dir_all(token_path.parent().unwrap()).expect("create token directory");
        purge_warden::ipc::auth_token::save_token_at(&token_path, TOKEN).expect("write CLI token");

        let mut target = ConfigV5::default();
        let household = Id::new("household").unwrap();
        target.server.listen = dns_addr;
        target.server.log_level = "warn".into();
        target.server.default_profile = Some(household.clone());
        target.server.enforce_device_mac = false;
        target.upstream.servers = vec![upstream_addr.to_string()];
        target.upstream.timeout_ms = 1_000;
        target.socket.path = socket.clone();
        target.api.enabled = true;
        target.api.listen = api_addr;
        target.api.token_hash = Some(purge_warden::auth::token::hash_token(TOKEN));
        target.api.rate_limit_per_minute = 0;
        target.tracking.enabled = false;
        target.tracking.query_log_enabled = false;
        target.profiles.insert(
            household.to_string(),
            ProfileV5 {
                display_name: "Household".into(),
                ..ProfileV5::default()
            },
        );
        std::fs::write(&config, toml::to_string_pretty(&target).unwrap())
            .expect("write schema-5 config");

        Self {
            root,
            config,
            pid_file,
            socket,
            xdg,
            dns_addr,
            api_addr,
        }
    }

    fn cli(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_warden"))
            .arg("--config")
            .arg(&self.config)
            .args(args)
            .current_dir(self.root.path())
            .env("XDG_CONFIG_HOME", &self.xdg)
            .output()
            .expect("run warden CLI")
    }

    fn revision(&self) -> String {
        purge_warden::operator_rules::OperatorRulesService::new(&self.config)
            .read(PageRequest::default(), TransportLimits::IPC)
            .expect("read current revision")
            .config_revision
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
        let tcp = TcpListener::bind("127.0.0.1:0").expect("reserve DNS TCP port");
        let addr = tcp.local_addr().unwrap();
        if std::net::UdpSocket::bind(addr).is_ok() {
            return addr;
        }
    }
    panic!("could not find a port free for both UDP and TCP");
}

fn assert_cli_receipt(output: &Output) -> Value {
    assert_eq!(
        output.status.code(),
        Some(5),
        "CLI mutation failed; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let receipt: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "CLI stdout is not a receipt ({error}); stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    assert_eq!(receipt["persistence"], "committed");
    assert_eq!(receipt["activation"]["state"], "applied");
    assert_eq!(receipt["activation"]["reload_outcome"], "reloaded");
    assert!(receipt["activation"]["active_config_revision"].is_string());
    receipt
}

async fn spawn_upstream() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind upstream");
    let addr = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut buf = [0_u8; 4096];
        loop {
            let Ok((length, peer)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let request = Message::from_vec(&buf[..length]).expect("parse daemon query");
            let mut response =
                Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
            response.metadata.response_code = ResponseCode::NoError;
            response.metadata.recursion_available = true;
            if let Some(query) = request.queries.first() {
                response.add_query(query.clone());
                let data = match query.query_type() {
                    RecordType::A => RData::A(A(UPSTREAM_A)),
                    RecordType::AAAA => RData::AAAA(AAAA(UPSTREAM_AAAA)),
                    _ => continue,
                };
                response.add_answer(Record::from_rdata(query.name().clone(), 300, data));
            }
            let bytes = response.to_vec().expect("encode upstream response");
            socket.send_to(&bytes, peer).await.expect("reply to daemon");
        }
    });
    (addr, task)
}

async fn dns_query(addr: SocketAddr, domain: &str, record_type: RecordType) -> Message {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind DNS client");
    let mut request = Message::new(0x8a17, MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
    request.add_query(hickory_proto::op::Query::query(
        Name::from_ascii(domain).unwrap(),
        record_type,
    ));
    socket
        .send_to(&request.to_vec().unwrap(), addr)
        .await
        .expect("send DNS query");
    let mut buf = [0_u8; 4096];
    let (length, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
        .await
        .expect("DNS response timeout")
        .expect("receive DNS response");
    Message::from_vec(&buf[..length]).expect("parse DNS response")
}

fn assert_answer(message: &Message, expected: RData) {
    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        message.answers.len(),
        1,
        "unexpected DNS answers: {:?}",
        message.answers
    );
    assert_eq!(message.answers[0].data, expected);
}

async fn assert_allowed(fixture: &Fixture, domain: &str, record_type: RecordType) {
    let expected = match record_type {
        RecordType::A => RData::A(A(UPSTREAM_A)),
        RecordType::AAAA => RData::AAAA(AAAA(UPSTREAM_AAAA)),
        _ => unreachable!(),
    };
    assert_answer(
        &dns_query(fixture.dns_addr, domain, record_type).await,
        expected,
    );
}

async fn assert_blocked(fixture: &Fixture, domain: &str, record_type: RecordType) {
    let expected = match record_type {
        RecordType::A => RData::A(A(Ipv4Addr::UNSPECIFIED)),
        RecordType::AAAA => RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)),
        _ => unreachable!(),
    };
    assert_answer(
        &dns_query(fixture.dns_addr, domain, record_type).await,
        expected,
    );
}

async fn wait_for_active(client: &reqwest::Client, base: &str, location: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let response = client
            .get(format!("{base}{location}"))
            .bearer_auth(TOKEN)
            .send()
            .await
            .expect("poll REST operation");
        assert_eq!(response.status(), StatusCode::OK);
        let receipt: Value = response.json().await.expect("operation receipt JSON");
        match receipt["activation"]["state"].as_str() {
            Some("applied") => return receipt,
            Some("failed" | "unknown" | "superseded") => {
                panic!("operation did not activate: {receipt}")
            }
            _ => {}
        }
        assert!(
            Instant::now() < deadline,
            "operation stayed pending: {receipt}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_daemon_cli_rest_reload_dns_and_restart_round_trip() {
    let (upstream_addr, upstream_task) = spawn_upstream().await;
    let fixture = Fixture::new(upstream_addr);
    let mut daemon = Daemon::spawn(&fixture);
    daemon.wait_ready(&fixture).await;

    for record_type in [RecordType::A, RecordType::AAAA] {
        assert_allowed(&fixture, CLI_DOMAIN, record_type).await;
    }
    assert_allowed(&fixture, REST_DOMAIN, RecordType::A).await;

    assert_cli_receipt(&fixture.cli(&[
        "custom-list",
        "create",
        "e2e-policy",
        "--display-name",
        "E2E policy",
        "--request-id",
        "uor8-cli-create",
        "--json",
    ]));
    assert_cli_receipt(&fixture.cli(&[
        "custom-list",
        "add",
        "e2e-policy",
        CLI_DOMAIN,
        "--deny",
        "--request-id",
        "uor8-cli-add",
        "--json",
    ]));

    let mount_revision = fixture.revision();
    let mount_args = [
        "profile",
        "mount",
        "household",
        "--custom-list",
        "e2e-policy",
        "--expect-revision",
        &mount_revision,
        "--request-id",
        "uor8-cli-mount",
        "--json",
    ];
    let first_mount = assert_cli_receipt(&fixture.cli(&mount_args));
    for record_type in [RecordType::A, RecordType::AAAA] {
        assert_blocked(&fixture, CLI_DOMAIN, record_type).await;
    }

    let config_after_mount = std::fs::read(&fixture.config).unwrap();
    let pack_after_mount = std::fs::read(fixture.root.path().join("packs/e2e-policy.txt")).unwrap();
    let revision_after_mount = fixture.revision();
    let retry_mount = assert_cli_receipt(&fixture.cli(&mount_args));
    assert_eq!(retry_mount["operation_id"], first_mount["operation_id"]);
    assert_eq!(std::fs::read(&fixture.config).unwrap(), config_after_mount);
    assert_eq!(
        std::fs::read(fixture.root.path().join("packs/e2e-policy.txt")).unwrap(),
        pack_after_mount
    );
    assert_eq!(fixture.revision(), revision_after_mount);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let base = format!("http://{}", fixture.api_addr);
    let retired_before = std::fs::read(&fixture.config).unwrap();
    let retired = client
        .get(format!("{base}/api/whitelist"))
        .bearer_auth(TOKEN)
        .send()
        .await
        .expect("call retired client route");
    assert_eq!(retired.status(), StatusCode::GONE);
    assert_eq!(std::fs::read(&fixture.config).unwrap(), retired_before);

    let rest_revision = fixture.revision();
    let batch = BatchRequest {
        contract_version: CONTRACT_VERSION,
        request_id: "uor8-rest-add".into(),
        expected_config_revision: rest_revision.clone(),
        operations: vec![Operation::AddDomainRule {
            id: "e2e-policy".into(),
            domain: REST_DOMAIN.into(),
            action: RuleAction::Deny,
        }],
        expected_plan_hash: None,
    };
    let plan_response = client
        .post(format!("{base}/api/v1/operator-rules/plans"))
        .bearer_auth(TOKEN)
        .json(&batch)
        .send()
        .await
        .expect("create REST plan");
    assert_eq!(plan_response.status(), StatusCode::OK);
    let plan: Value = plan_response.json().await.expect("REST plan JSON");
    let plan_id = plan["plan_id"].as_str().unwrap();
    let plan_hash = plan["plan"]["plan_hash"].as_str().unwrap();
    let apply_response = client
        .post(format!("{base}/api/v1/operator-rules/apply"))
        .bearer_auth(TOKEN)
        .header("if-match", format!("\"config:{rest_revision}\""))
        .header("idempotency-key", "uor8-rest-add")
        .json(&json!({
            "contract_version": CONTRACT_VERSION,
            "plan_id": plan_id,
            "plan_hash": plan_hash,
            "expected_config_revision": rest_revision,
            "request_id": "uor8-rest-add"
        }))
        .send()
        .await
        .expect("apply REST plan");
    assert_eq!(apply_response.status(), StatusCode::ACCEPTED);
    let location = apply_response
        .headers()
        .get("location")
        .expect("202 Location header")
        .to_str()
        .unwrap()
        .to_string();
    let accepted: Value = apply_response.json().await.expect("REST apply JSON");
    assert_eq!(accepted["state"], "accepted");
    let active = wait_for_active(&client, &base, &location).await;
    assert_eq!(active["persistence"], "committed");
    assert_blocked(&fixture, REST_DOMAIN, RecordType::A).await;

    daemon.stop().await;
    let mut restarted = Daemon::spawn(&fixture);
    restarted.wait_ready(&fixture).await;
    for record_type in [RecordType::A, RecordType::AAAA] {
        assert_blocked(&fixture, CLI_DOMAIN, record_type).await;
    }
    assert_blocked(&fixture, REST_DOMAIN, RecordType::A).await;
    restarted.stop().await;
    upstream_task.abort();
}
