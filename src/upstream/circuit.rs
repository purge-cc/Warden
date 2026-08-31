//! Circuit breaker for upstream DNS resolvers.
//!
//! When an upstream fails repeatedly, the circuit opens and queries are
//! rejected immediately — allowing the fallback chain to take over.
//! A probe query is sent every 10 seconds; on success, the circuit closes.
//!
//! State machine: Closed → (10 failures) → Open → (10s) → HalfOpen → probe
//!   - probe succeeds → Closed
//!   - probe fails → Open (reset timer)
//!
//! **The probe window is timed on a monotonic clock** ([`Instant`]), never on
//! [`std::time::SystemTime`] — see [`CircuitBreaker::anchor`].

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Instant;

use hickory_proto::rr::{Name, RecordType};

use super::{Upstream, UpstreamResponse};
use crate::dns::error::DnsError;

const FAILURE_THRESHOLD: u32 = 10;
/// How long an open circuit waits before allowing one probe query through.
///
/// Measured against the breaker's own monotonic [`Instant`] anchor, so an NTP
/// slew, a manual clock set, or a DST jump cannot lengthen or shorten it.
const PROBE_INTERVAL_SECS: u64 = 10;

/// Circuit breaker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Normal operation — queries flow through.
    Closed,
    /// Upstream is failing — reject immediately, wait for probe window.
    Open,
    /// Probe window — one query allowed to test upstream health.
    HalfOpen,
}

/// Lock-free circuit breaker wrapping an upstream resolver.
pub struct CircuitBreaker {
    inner: Box<dyn Upstream>,
    /// Consecutive failure count.
    failures: AtomicU32,
    /// Monotonic origin for [`Self::opened_at`].
    ///
    /// **M5** This used to be absent and `opened_at` held epoch seconds read
    /// from `SystemTime::now()` — a wall clock. `should_probe` subtracts the
    /// two readings, so any *backward* wall-clock movement between them (NTP
    /// slew, `date -s`, a DST jump on a box that keeps local time in the RTC)
    /// made the difference negative, `saturating_sub` clamped it to `0`, and
    /// the breaker stayed **stuck open** until real time caught back up.
    /// A *forward* jump fired the probe early. `Instant` is monotonic by
    /// contract, so neither is expressible.
    ///
    /// Not an `AtomicU64` of its own: `Instant` is not atomic-storable and a
    /// `Mutex<Instant>` here would add a fourteenth shard-scoped lock site to
    /// project rules's enumerated table on a per-cache-miss path. The anchor is
    /// immutable after construction, so it needs no synchronisation at all and
    /// the struct stays lock-free.
    anchor: Instant,
    /// Whole seconds since [`Self::anchor`] at which the circuit opened.
    opened_at: AtomicU64,
    /// 0 = Closed, 1 = Open, 2 = HalfOpen
    state: AtomicU32,
}

impl CircuitBreaker {
    pub fn new(inner: Box<dyn Upstream>) -> Self {
        Self::with_anchor(inner, Instant::now())
    }

    /// Construct with an explicit monotonic origin.
    ///
    /// Backdating the anchor is how tests move the probe window without
    /// sleeping: `elapsed_secs()` reads as if the breaker had already been
    /// alive that long.
    fn with_anchor(inner: Box<dyn Upstream>, anchor: Instant) -> Self {
        Self {
            inner,
            failures: AtomicU32::new(0),
            anchor,
            opened_at: AtomicU64::new(0),
            state: AtomicU32::new(0),
        }
    }

    pub fn state(&self) -> State {
        match self.state.load(Ordering::Acquire) {
            0 => State::Closed,
            1 => State::Open,
            _ => State::HalfOpen,
        }
    }

    fn set_state(&self, state: State) {
        let val = match state {
            State::Closed => 0,
            State::Open => 1,
            State::HalfOpen => 2,
        };
        self.state.store(val, Ordering::Release);
    }

    /// Whole seconds elapsed on the monotonic clock since [`Self::anchor`].
    ///
    /// The only clock the breaker reads. Both the writes to `opened_at` and
    /// the comparison in [`Self::should_probe`] go through here, so the two
    /// are always in the same clock domain.
    fn elapsed_secs(&self) -> u64 {
        self.anchor.elapsed().as_secs()
    }

    // roundup-01 (rev-2606): `failures` and `state` are two independent atomics,
    // so a concurrent success+failure can momentarily observe them inconsistent
    // (e.g. `failures = 0` while `state = Open`). This self-heals on the next
    // probe / Closed transition and is per-query benign — the breaker is an
    // availability optimisation, not a correctness gate — so the multi-field
    // state is left as separate atomics rather than a lock or packed word.
    fn record_success(&self) {
        if self.failures.load(Ordering::Relaxed) > 0 {
            self.failures.store(0, Ordering::Release);
        }
        if self.state.load(Ordering::Relaxed) != 0 {
            self.set_state(State::Closed);
        }
    }

    fn record_failure(&self) {
        let count = self.failures.fetch_add(1, Ordering::AcqRel) + 1;
        if count >= FAILURE_THRESHOLD {
            self.opened_at.store(self.elapsed_secs(), Ordering::Release);
            self.set_state(State::Open);
            if count == FAILURE_THRESHOLD {
                tracing::warn!(failures = count, "circuit breaker OPEN — upstream failing");
            }
            // Cap to prevent eventual u32 wraparound
            if count > FAILURE_THRESHOLD * 2 {
                self.failures.store(FAILURE_THRESHOLD, Ordering::Release);
            }
        }
    }

    fn should_probe(&self) -> bool {
        let opened = self.opened_at.load(Ordering::Acquire);
        // `saturating_sub` is now belt-and-braces rather than load-bearing:
        // both operands come from `elapsed_secs()`, which is monotonic
        // non-decreasing, so the subtraction cannot underflow. [M5] — under the
        // old wall clock it *was* load-bearing, and clamping to 0 is precisely
        // how a backward jump wedged the breaker open.
        self.elapsed_secs().saturating_sub(opened) >= PROBE_INTERVAL_SECS
    }
}

#[async_trait::async_trait]
impl Upstream for CircuitBreaker {
    async fn lookup(
        &self,
        name: &Name,
        record_type: RecordType,
        ecs: Option<crate::dns::edns::EdnsClientSubnet>,
    ) -> Result<UpstreamResponse, DnsError> {
        match self.state() {
            State::Closed => match self.inner.lookup(name, record_type, ecs).await {
                Ok(resp) => {
                    self.record_success();
                    Ok(resp)
                }
                Err(e) => {
                    self.record_failure();
                    Err(e)
                }
            },
            State::Open => {
                if self.should_probe()
                    && self
                        .state
                        .compare_exchange(1, 2, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                {
                    // CAS succeeded: we atomically transitioned Open→HalfOpen.
                    // Only one thread wins the CAS; others fall through to reject.
                    tracing::debug!("circuit breaker HALF-OPEN — probing upstream");
                    match self.inner.lookup(name, record_type, ecs).await {
                        Ok(resp) => {
                            tracing::info!("circuit breaker CLOSED — upstream recovered");
                            self.record_success();
                            Ok(resp)
                        }
                        Err(e) => {
                            self.opened_at.store(self.elapsed_secs(), Ordering::Release);
                            self.set_state(State::Open);
                            Err(e)
                        }
                    }
                } else {
                    Err(DnsError::CircuitBreakerOpen)
                }
            }
            State::HalfOpen => {
                // Another query arrived while probing — reject to avoid
                // hammering a recovering upstream.
                Err(DnsError::CircuitBreakerOpen)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock upstream that always fails.
    struct FailingUpstream;

    #[async_trait::async_trait]
    impl Upstream for FailingUpstream {
        async fn lookup(
            &self,
            _: &Name,
            _: RecordType,
            _: Option<crate::dns::edns::EdnsClientSubnet>,
        ) -> Result<UpstreamResponse, DnsError> {
            Err(DnsError::UpstreamRequestFailed("mock failure".into()))
        }
    }

    /// Mock upstream that always succeeds.
    struct SuccessUpstream;

    #[async_trait::async_trait]
    impl Upstream for SuccessUpstream {
        async fn lookup(
            &self,
            _: &Name,
            _: RecordType,
            _: Option<crate::dns::edns::EdnsClientSubnet>,
        ) -> Result<UpstreamResponse, DnsError> {
            Ok(UpstreamResponse {
                records: vec![],
                response_code: hickory_proto::op::ResponseCode::NoError,
                soa_minimum_ttl: None,
                #[cfg(feature = "dnssec")]
                authority: vec![],
            })
        }
    }

    #[test]
    fn initial_state_is_closed() {
        let cb = CircuitBreaker::new(Box::new(SuccessUpstream));
        assert_eq!(cb.state(), State::Closed);
    }

    #[tokio::test]
    async fn opens_after_threshold_failures() {
        let cb = CircuitBreaker::new(Box::new(FailingUpstream));
        let name: Name = "example.com.".parse().unwrap();

        for _ in 0..FAILURE_THRESHOLD {
            let _ = cb.lookup(&name, RecordType::A, None).await;
        }

        assert_eq!(cb.state(), State::Open);
    }

    #[tokio::test]
    async fn stays_closed_below_threshold() {
        let cb = CircuitBreaker::new(Box::new(FailingUpstream));
        let name: Name = "example.com.".parse().unwrap();

        for _ in 0..(FAILURE_THRESHOLD - 1) {
            let _ = cb.lookup(&name, RecordType::A, None).await;
        }

        assert_eq!(cb.state(), State::Closed);
    }

    #[tokio::test]
    async fn open_rejects_immediately() {
        let cb = CircuitBreaker::new(Box::new(FailingUpstream));
        let name: Name = "example.com.".parse().unwrap();

        // Trip the breaker
        for _ in 0..FAILURE_THRESHOLD {
            let _ = cb.lookup(&name, RecordType::A, None).await;
        }
        assert_eq!(cb.state(), State::Open);

        // Next query should fail with CircuitBreakerOpen (not mock failure)
        let err = cb.lookup(&name, RecordType::A, None).await.unwrap_err();
        assert!(matches!(err, DnsError::CircuitBreakerOpen));
    }

    /// M5 The probe window must be timed on the process-monotonic clock, not
    /// on the wall clock.
    ///
    /// The needle discriminates by *magnitude*, which is what makes it a real
    /// test rather than a restatement: seconds-since-this-breaker-was-built is
    /// a handful at most, while `SystemTime::now().duration_since(UNIX_EPOCH)`
    /// is ~1.8e9 and rising. Restoring the old `now_secs()` turns this red on
    /// the first assertion without touching anything else.
    #[tokio::test]
    async fn opened_at_is_monotonic_elapsed_not_epoch_seconds() {
        let cb = CircuitBreaker::new(Box::new(FailingUpstream));
        let name: Name = "example.com.".parse().unwrap();

        for _ in 0..FAILURE_THRESHOLD {
            let _ = cb.lookup(&name, RecordType::A, None).await;
        }
        assert_eq!(cb.state(), State::Open);

        let stored = cb.opened_at.load(Ordering::Acquire);
        assert!(
            stored < 86_400,
            "opened_at={stored} looks like a wall-clock epoch value, not \
             seconds since this breaker's monotonic anchor"
        );

        let epoch_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(
            stored < epoch_now / 2,
            "opened_at={stored} is in the same order of magnitude as epoch \
             seconds ({epoch_now}) — the wall clock is back on the probe path"
        );
    }

    /// M5 The probe window opens purely as a function of monotonic elapsed
    /// time since the anchor — the two arms differ *only* in how far back the
    /// anchor is dated.
    #[tokio::test]
    async fn should_probe_tracks_the_monotonic_anchor() {
        let name: Name = "example.com.".parse().unwrap();

        // Arm A: anchor is now, so no monotonic time has passed. A circuit
        // that just opened must not be probed.
        let fresh = CircuitBreaker::with_anchor(Box::new(FailingUpstream), Instant::now());
        for _ in 0..FAILURE_THRESHOLD {
            let _ = fresh.lookup(&name, RecordType::A, None).await;
        }
        assert_eq!(fresh.state(), State::Open);
        assert!(
            !fresh.should_probe(),
            "a circuit opened this instant is inside its probe window"
        );

        // Arm B: identical breaker, anchor backdated past the probe interval,
        // and `opened_at` left at its construction value of 0 — i.e. "opened
        // at anchor time, PROBE_INTERVAL_SECS * 3 ago".
        let aged = CircuitBreaker::with_anchor(
            Box::new(FailingUpstream),
            Instant::now() - std::time::Duration::from_secs(PROBE_INTERVAL_SECS * 3),
        );
        aged.set_state(State::Open);
        assert_eq!(aged.opened_at.load(Ordering::Acquire), 0);
        assert!(
            aged.should_probe(),
            "a circuit open for 3x the probe interval must admit a probe"
        );

        // And the probe actually flows: the CAS moves Open → HalfOpen and the
        // inner upstream is dialled (it fails, so we land back on Open).
        let err = aged.lookup(&name, RecordType::A, None).await.unwrap_err();
        assert!(
            matches!(err, DnsError::UpstreamRequestFailed(_)),
            "expected the probe to reach the inner upstream, got {err:?}"
        );
    }

    #[tokio::test]
    async fn success_resets_failures() {
        let cb = CircuitBreaker::new(Box::new(SuccessUpstream));
        let name: Name = "example.com.".parse().unwrap();

        // Simulate some failures by directly incrementing
        cb.failures.store(FAILURE_THRESHOLD - 1, Ordering::Release);

        // A success should reset
        let _ = cb.lookup(&name, RecordType::A, None).await;
        assert_eq!(cb.failures.load(Ordering::Acquire), 0);
        assert_eq!(cb.state(), State::Closed);
    }
}
