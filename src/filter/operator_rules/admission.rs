use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use super::BudgetExceeded;

/// Shared node-local quota for builders and every live compiled snapshot.
/// Clones share counters; callers use one controller for all publication paths.
/// Bytes are deterministic compiled quota, not a bound on allocator RSS or the
/// compiler's temporary workspace. Build concurrency bounds that workspace.
#[derive(Debug, Clone)]
pub struct CompileAdmission(Arc<State>);

#[derive(Debug)]
struct State {
    max_bytes: usize,
    max_builds: usize,
    bytes: AtomicUsize,
    builds: AtomicUsize,
}

impl CompileAdmission {
    pub fn new(max_bytes: usize, max_builds: usize) -> Result<Self, BudgetExceeded> {
        for (limit, value) in [
            ("admission_bytes", max_bytes),
            ("concurrent_builds", max_builds),
        ] {
            if value == 0 {
                return Err(BudgetExceeded {
                    limit,
                    actual: Some(0),
                    maximum: usize::MAX,
                });
            }
        }
        Ok(Self(Arc::new(State {
            max_bytes,
            max_builds,
            bytes: AtomicUsize::new(0),
            builds: AtomicUsize::new(0),
        })))
    }

    pub fn reserved_bytes(&self) -> usize {
        self.0.bytes.load(Ordering::Acquire)
    }

    pub fn active_builds(&self) -> usize {
        self.0.builds.load(Ordering::Acquire)
    }

    pub(super) fn begin(&self, ceiling: usize) -> Result<BuildLease, BudgetExceeded> {
        reserve(&self.0.builds, 1, self.0.max_builds, "concurrent_builds")?;
        let mut build = BuildLease {
            state: Arc::clone(&self.0),
            lease: None,
        };
        reserve(&self.0.bytes, ceiling, self.0.max_bytes, "admission_bytes")?;
        build.lease = Some(SnapshotLease {
            state: Arc::clone(&self.0),
            bytes: ceiling,
        });
        Ok(build)
    }
}

fn reserve(
    counter: &AtomicUsize,
    amount: usize,
    maximum: usize,
    limit: &'static str,
) -> Result<(), BudgetExceeded> {
    let mut old = counter.load(Ordering::Acquire);
    loop {
        let new = old.checked_add(amount);
        let Some(new) = new.filter(|&new| new <= maximum) else {
            return Err(BudgetExceeded {
                limit,
                actual: new,
                maximum,
            });
        };
        match counter.compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Ok(()),
            Err(current) => old = current,
        }
    }
}

#[derive(Debug)]
pub(super) struct SnapshotLease {
    state: Arc<State>,
    bytes: usize,
}

impl Drop for SnapshotLease {
    fn drop(&mut self) {
        self.state.bytes.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

pub(super) struct BuildLease {
    state: Arc<State>,
    lease: Option<SnapshotLease>,
}

impl BuildLease {
    pub(super) fn charge(&mut self, bytes: usize) {
        let lease = self.lease.as_mut().expect("builder owns reservation");
        assert!(
            bytes <= lease.bytes,
            "preflight must enforce candidate ceiling"
        );
        self.state
            .bytes
            .fetch_sub(lease.bytes - bytes, Ordering::AcqRel);
        lease.bytes = bytes;
    }

    pub(super) fn finish(mut self) -> SnapshotLease {
        self.lease.take().expect("builder owns reservation")
    }
}

impl Drop for BuildLease {
    fn drop(&mut self) {
        self.state.builds.fetch_sub(1, Ordering::AcqRel);
    }
}
