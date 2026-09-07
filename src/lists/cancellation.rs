//! Worker-scoped cancellation. Synchronous readers share the scope without
//! threading an optional signal through foreground parser/cache APIs.
use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc,
};
use tokio::sync::Notify;

const RUNNING: u8 = 0;
const CANCELLED: u8 = 1;
const COMMITTING: u8 = 2;

#[cfg(test)]
pub(super) type WorkerHook = Box<dyn FnMut(&str) + Send>;

#[derive(Clone, Default)]
pub(super) struct RefreshCancellation(Arc<State>);
#[derive(Default)]
struct State {
    phase: AtomicU8,
    changed: Notify,
    #[cfg(test)]
    hook: std::sync::Mutex<Option<WorkerHook>>,
}

#[derive(Debug, thiserror::Error)]
#[error("list refresh cancelled")]
pub struct Cancelled;

tokio::task_local! {
    static WORKER: RefreshCancellation;
}

impl RefreshCancellation {
    pub(super) fn cancel(&self) {
        if self
            .0
            .phase
            .compare_exchange(RUNNING, CANCELLED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.0.changed.notify_waiters();
        }
    }

    pub(super) async fn scope<F: std::future::Future>(&self, future: F) -> F::Output {
        WORKER.scope(self.clone(), future).await
    }

    async fn cancelled(&self) {
        let notified = self.0.changed.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.0.phase.load(Ordering::Acquire) == CANCELLED {
            return;
        }
        notified.await;
    }

    #[cfg(test)]
    pub(super) fn set_hook(&self, hook: impl FnMut(&str) + Send + 'static) {
        *self.0.hook.lock().unwrap() = Some(Box::new(hook));
    }
}

pub(super) fn checkpoint(at: &str) -> Result<(), Cancelled> {
    #[cfg(not(test))]
    let _ = at;
    WORKER
        .try_with(|signal| {
            #[cfg(test)]
            if let Some(hook) = signal.0.hook.lock().unwrap().as_mut() {
                hook(at);
            }
            if signal.0.phase.load(Ordering::Acquire) == CANCELLED {
                Err(Cancelled)
            } else {
                Ok(())
            }
        })
        .unwrap_or(Ok(()))
}

pub(super) fn io_checkpoint(at: &str) -> std::io::Result<()> {
    // Interrupted is retried by read_exact/read_until and would never unwind.
    checkpoint(at).map_err(std::io::Error::other)
}

pub(super) fn checked<T>(result: T) -> Result<T, Cancelled> {
    checkpoint("result")?;
    Ok(result)
}

pub(super) fn begin_commit() -> Result<(), Cancelled> {
    checkpoint("before_commit")?;
    // Linearize retirement against the first swap; later checks must become
    // inert so cancellation can never strand a partially replaced corpus.
    WORKER
        .try_with(|signal| {
            match signal.0.phase.compare_exchange(
                RUNNING,
                COMMITTING,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) | Err(COMMITTING) => Ok(()),
                Err(_) => Err(Cancelled),
            }
        })
        .unwrap_or(Ok(()))
}

pub(super) async fn wait<F: std::future::Future>(
    future: F,
    at: &str,
) -> Result<F::Output, Cancelled> {
    checkpoint(at)?;
    let result = if let Ok(signal) = WORKER.try_with(Clone::clone) {
        tokio::select! {
            biased;
            _ = signal.cancelled() => return Err(Cancelled),
            result = future => result,
        }
    } else {
        future.await
    };
    checked(result)
}
