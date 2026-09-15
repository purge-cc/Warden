//! Graceful, supervisor-driven daemon restarts.

use std::fmt;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use thiserror::Error;
use tokio::sync::mpsc;

/// Exit status used to ask a verified systemd unit to start a fresh daemon.
pub const MANAGED_RESTART_EXIT_CODE: u8 = 75;
const SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(3);
const SYSTEMCTL_OUTPUT_LIMIT: usize = 64 * 1024;

/// Durable operation step that is ready for a supervised restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedRestartRequest {
    pub operation_id: String,
    pub step_id: String,
}

/// Effective supervisor settings verified immediately before mutation or exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupervisorSupport {
    unit: String,
    restart_policy: String,
}

impl SupervisorSupport {
    pub fn unit(&self) -> &str {
        &self.unit
    }

    pub fn restart_policy(&self) -> &str {
        &self.restart_policy
    }
}

/// Why the daemon cannot safely promise a managed restart.
#[derive(Debug, Error)]
pub enum ManagedRestartError {
    #[error("managed restart requires this daemon to be the main process of a systemd service")]
    NotSupervised,
    #[error("could not inspect the effective systemd service: {0}")]
    Inspection(String),
    #[error("systemd unit {unit} does not support managed restart: {reason}")]
    Unsupported { unit: String, reason: String },
    #[error("the daemon is already shutting down")]
    ShuttingDown,
}

trait SupervisorProbe: Send + Sync {
    fn inspect(&self) -> Result<SupervisorSupport, ManagedRestartError>;
}

#[derive(Debug)]
struct SystemdProbe;

impl SupervisorProbe for SystemdProbe {
    fn inspect(&self) -> Result<SupervisorSupport, ManagedRestartError> {
        inspect_systemd(std::process::id(), &systemctl_path())
    }
}

/// Cloneable request side held by the node coordinator.
#[derive(Clone)]
pub struct ManagedRestartHandle {
    tx: mpsc::Sender<ManagedRestartRequest>,
    probe: Arc<dyn SupervisorProbe>,
}

impl fmt::Debug for ManagedRestartHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagedRestartHandle")
            .finish_non_exhaustive()
    }
}

/// Single-consumer side polled by the daemon signal loop.
#[derive(Debug)]
pub struct ManagedRestartReceiver {
    rx: mpsc::Receiver<ManagedRestartRequest>,
}

/// Create the bounded restart request channel.
pub fn channel(capacity: usize) -> (ManagedRestartHandle, ManagedRestartReceiver) {
    assert!(capacity > 0, "managed restart channel must be bounded");
    let (tx, rx) = mpsc::channel(capacity);
    (
        ManagedRestartHandle {
            tx,
            probe: Arc::new(SystemdProbe),
        },
        ManagedRestartReceiver { rx },
    )
}

impl ManagedRestartHandle {
    /// Verify that exit 75 is both successful and restart-forcing for the
    /// effective unit that owns this process.
    pub async fn preflight(&self) -> Result<SupervisorSupport, ManagedRestartError> {
        let probe = Arc::clone(&self.probe);
        tokio::task::spawn_blocking(move || probe.inspect())
            .await
            .map_err(|error| {
                ManagedRestartError::Inspection(format!("supervisor probe panicked: {error}"))
            })?
    }

    /// Consume fresh preflight evidence and enqueue one graceful restart request.
    ///
    /// The operation owner persists the step as requested before calling this
    /// method. Recovery consumes that durable state; this channel never retries
    /// or re-arms a request after a process restart.
    pub async fn request(
        &self,
        _support: SupervisorSupport,
        request: ManagedRestartRequest,
    ) -> Result<(), ManagedRestartError> {
        self.tx
            .send(request)
            .await
            .map_err(|_| ManagedRestartError::ShuttingDown)?;
        Ok(())
    }
}

impl ManagedRestartReceiver {
    pub async fn recv(&mut self) -> Option<ManagedRestartRequest> {
        self.rx.recv().await
    }
}

fn systemctl_path() -> std::path::PathBuf {
    for candidate in ["/usr/bin/systemctl", "/bin/systemctl"] {
        let path = Path::new(candidate);
        if path.is_file() {
            return path.to_path_buf();
        }
    }
    std::path::PathBuf::from("systemctl")
}

fn inspect_systemd(pid: u32, systemctl: &Path) -> Result<SupervisorSupport, ManagedRestartError> {
    let mut unit_command = Command::new(systemctl);
    unit_command.args([
        "--system",
        "--no-pager",
        "--no-ask-password",
        "whoami",
        &pid.to_string(),
    ]);
    let unit_output = bounded_output(unit_command, SYSTEMCTL_TIMEOUT)?;
    if !unit_output.status.success() {
        return Err(ManagedRestartError::NotSupervised);
    }
    let unit = parse_service_unit(&unit_output.stdout)?;

    let mut property_command = Command::new(systemctl);
    property_command.args([
        "--system",
        "--no-pager",
        "--no-ask-password",
        "show",
        &unit,
        "--property=MainPID",
        "--property=Type",
        "--property=Restart",
        "--property=SuccessExitStatus",
        "--property=RestartForceExitStatus",
        "--property=RestartPreventExitStatus",
    ]);
    let properties = bounded_output(property_command, SYSTEMCTL_TIMEOUT)?;
    if !properties.status.success() {
        return Err(ManagedRestartError::Inspection(command_stderr(&properties)));
    }
    validate_properties(pid, unit, &properties.stdout)
}

fn bounded_output(
    mut command: Command,
    timeout: Duration,
) -> Result<std::process::Output, ManagedRestartError> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| ManagedRestartError::Inspection(error.to_string()))?;
    let mut stdout = child.stdout.take().ok_or_else(|| {
        ManagedRestartError::Inspection("systemctl stdout pipe is unavailable".to_string())
    })?;
    let mut stderr = child.stderr.take().ok_or_else(|| {
        ManagedRestartError::Inspection("systemctl stderr pipe is unavailable".to_string())
    })?;
    let stdout_reader = std::thread::spawn(move || drain_bounded(&mut stdout));
    let stderr_reader = std::thread::spawn(move || drain_bounded(&mut stderr));

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(ManagedRestartError::Inspection(error.to_string()));
            }
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(ManagedRestartError::Inspection(
                    "systemctl inspection timed out".to_string(),
                ));
            }
        }
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| ManagedRestartError::Inspection("stdout reader panicked".to_string()))?
        .map_err(|error| ManagedRestartError::Inspection(error.to_string()))?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| ManagedRestartError::Inspection("stderr reader panicked".to_string()))?
        .map_err(|error| ManagedRestartError::Inspection(error.to_string()))?;
    Ok(std::process::Output {
        status,
        stdout,
        stderr,
    })
}

fn drain_bounded(reader: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut retained = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let count = reader.read(&mut chunk)?;
        if count == 0 {
            return Ok(retained);
        }
        let remaining = SYSTEMCTL_OUTPUT_LIMIT.saturating_sub(retained.len());
        retained.extend_from_slice(&chunk[..count.min(remaining)]);
    }
}

fn parse_service_unit(stdout: &[u8]) -> Result<String, ManagedRestartError> {
    let unit = std::str::from_utf8(stdout)
        .map_err(|error| ManagedRestartError::Inspection(error.to_string()))?
        .trim();
    if unit.is_empty()
        || !unit.ends_with(".service")
        || unit.chars().any(char::is_whitespace)
        || unit.starts_with('-')
    {
        return Err(ManagedRestartError::NotSupervised);
    }
    Ok(unit.to_owned())
}

fn command_stderr(output: &std::process::Output) -> String {
    let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    if detail.is_empty() {
        format!("systemctl exited with {}", output.status)
    } else {
        detail
    }
}

fn validate_properties(
    pid: u32,
    unit: String,
    stdout: &[u8],
) -> Result<SupervisorSupport, ManagedRestartError> {
    let text = std::str::from_utf8(stdout)
        .map_err(|error| ManagedRestartError::Inspection(error.to_string()))?;
    let mut main_pid = None;
    let mut service_type = None;
    let mut restart_policy = None;
    let mut success_status = None;
    let mut force_status = None;
    let mut prevent_status = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "MainPID" => main_pid = value.parse::<u32>().ok(),
            "Type" => service_type = Some(value),
            "Restart" => restart_policy = Some(value),
            "SuccessExitStatus" => success_status = Some(value),
            "RestartForceExitStatus" => force_status = Some(value),
            "RestartPreventExitStatus" => prevent_status = Some(value),
            _ => {}
        }
    }

    let mut missing = Vec::new();
    if main_pid != Some(pid) {
        missing.push(format!("MainPID is not this daemon ({pid})"));
    }
    if service_type != Some("simple") {
        missing.push("service Type is not simple".to_string());
    }
    if !success_status.is_some_and(contains_exit_75) {
        missing.push("SuccessExitStatus does not contain 75".to_string());
    }
    if !force_status.is_some_and(contains_exit_75) {
        missing.push("RestartForceExitStatus does not contain 75".to_string());
    }
    if prevent_status.is_none() {
        missing.push("RestartPreventExitStatus is unavailable".to_string());
    } else if prevent_status.is_some_and(contains_exit_75) {
        missing.push("RestartPreventExitStatus contains 75".to_string());
    }
    let Some(restart_policy) = restart_policy.filter(|value| !value.is_empty()) else {
        missing.push("Restart policy is unavailable".to_string());
        return Err(ManagedRestartError::Unsupported {
            unit,
            reason: missing.join("; "),
        });
    };
    if !missing.is_empty() {
        return Err(ManagedRestartError::Unsupported {
            unit,
            reason: missing.join("; "),
        });
    }

    Ok(SupervisorSupport {
        unit,
        restart_policy: restart_policy.to_owned(),
    })
}

fn contains_exit_75(value: &str) -> bool {
    value.split_whitespace().any(|token| {
        let token = token.trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_');
        token == "75" || token == "TEMPFAIL" || token == "EX_TEMPFAIL"
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_properties_require_both_exit_status_contracts() {
        let support = validate_properties(
            812,
            "purge-warden.service".to_string(),
            b"Type=simple\nRestart=on-failure\nMainPID=812\nSuccessExitStatus=75 SIGTERM\nRestartForceExitStatus=TEMPFAIL\nRestartPreventExitStatus=\n",
        )
        .unwrap();
        assert_eq!(support.unit(), "purge-warden.service");
        assert_eq!(support.restart_policy(), "on-failure");

        let error = validate_properties(
            812,
            "purge-warden.service".to_string(),
            b"Type=simple\nRestart=on-failure\nMainPID=812\nSuccessExitStatus=75\nRestartForceExitStatus=\nRestartPreventExitStatus=\n",
        )
        .unwrap_err();
        assert!(error.to_string().contains("RestartForceExitStatus"));
    }

    #[test]
    fn child_process_and_oneshot_service_are_refused() {
        for properties in [
            b"Type=simple\nRestart=always\nMainPID=811\nSuccessExitStatus=75\nRestartForceExitStatus=75\nRestartPreventExitStatus=\n".as_slice(),
            b"Type=oneshot\nRestart=always\nMainPID=812\nSuccessExitStatus=75\nRestartForceExitStatus=75\nRestartPreventExitStatus=\n".as_slice(),
        ] {
            assert!(validate_properties(812, "warden.service".to_string(), properties).is_err());
        }
    }

    #[test]
    fn prevent_status_overrides_force_status() {
        let error = validate_properties(
            812,
            "purge-warden.service".to_string(),
            b"Type=simple\nRestart=on-failure\nMainPID=812\nSuccessExitStatus=75\nRestartForceExitStatus=75\nRestartPreventExitStatus=75\n",
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("RestartPreventExitStatus contains 75"));
    }

    #[test]
    fn unit_identity_must_be_one_service_name() {
        assert_eq!(
            parse_service_unit(b"purge-warden.service\n").unwrap(),
            "purge-warden.service"
        );
        for invalid in [
            b"".as_slice(),
            b"purge-warden.scope\n".as_slice(),
            b"purge-warden.service other.service\n".as_slice(),
            b"-purge-warden.service\n".as_slice(),
        ] {
            assert!(parse_service_unit(invalid).is_err());
        }
    }

    #[test]
    fn supervisor_probe_command_has_a_hard_deadline() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "while :; do :; done"]);
        let started = Instant::now();
        let error = bounded_output(command, Duration::from_millis(20)).unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn unsupported_preflight_does_not_enqueue_restart() {
        struct Unsupported;
        impl SupervisorProbe for Unsupported {
            fn inspect(&self) -> Result<SupervisorSupport, ManagedRestartError> {
                Err(ManagedRestartError::NotSupervised)
            }
        }

        let (tx, rx) = mpsc::channel(1);
        let handle = ManagedRestartHandle {
            tx,
            probe: Arc::new(Unsupported),
        };
        let error = handle.preflight().await.unwrap_err();
        assert!(matches!(error, ManagedRestartError::NotSupervised));
        assert!(rx.is_empty());
    }

    #[tokio::test]
    async fn fresh_support_permit_enqueues_exactly_one_step() {
        struct Supported;
        impl SupervisorProbe for Supported {
            fn inspect(&self) -> Result<SupervisorSupport, ManagedRestartError> {
                Ok(SupervisorSupport {
                    unit: "purge-warden.service".to_string(),
                    restart_policy: "on-failure".to_string(),
                })
            }
        }

        let (tx, mut rx) = mpsc::channel(1);
        let handle = ManagedRestartHandle {
            tx,
            probe: Arc::new(Supported),
        };
        let permit = handle.preflight().await.unwrap();
        let request = ManagedRestartRequest {
            operation_id: "op-1".to_string(),
            step_id: "primary".to_string(),
        };
        handle.request(permit, request.clone()).await.unwrap();
        assert_eq!(rx.recv().await, Some(request));
        assert!(rx.is_empty());
    }
}
