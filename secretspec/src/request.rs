//! Ownership boundary for cancellable resolutions.
//!
//! The synchronous resolution engine runs on a joined blocking worker. Native
//! async backends use this request's runtime, never the shared provider runtime.
//! Dropping that runtime normally also joins DNS and other blocking tasks hidden
//! inside dependencies. Do not replace it with shutdown_timeout/background.

use crate::{Result, SecretSpecError};
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::Poll;
use tokio_util::sync::CancellationToken;

/// Cancellation for one resolution (0.22+).
///
/// Clones notify the same request. A handle may be used for exactly one call;
/// cancelling before the call and repeated cancellation are both supported.
/// Await the resolution after cancelling to observe cleanup. It waits for
/// resolver workers, direct children and pipe workers and requests termination
/// of process groups or Windows Jobs. Descendant exit can complete after return.
/// Blocking OS operations and synchronous cryptography can delay cleanup.
#[derive(Clone, Default)]
pub struct CancellationHandle {
    control: Arc<Control>,
}

#[derive(Default)]
struct Control {
    state: Mutex<State>,
    notification: CancellationToken,
}

#[derive(Default)]
struct State {
    used: bool,
    cancelled: bool,
    committed: bool,
    cleanup_failure: Option<&'static str>,
    finalizers: Vec<Finalizer>,
}

impl Control {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

impl CancellationHandle {
    pub fn new() -> Self {
        Self::default()
    }

    /// Request cancellation. A committed result is never overwritten.
    pub fn cancel(&self) {
        let mut state = self.control.state();
        if state.committed {
            return;
        }
        state.cancelled = true;
        drop(state);
        // Waking a waiter may re-enter this handle.
        self.control.notification.cancel();
    }

    pub fn is_cancelled(&self) -> bool {
        self.control.state().cancelled
    }

    fn begin(&self) -> Result<()> {
        let mut state = self.control.state();
        if state.used {
            return Err(SecretSpecError::CancellationHandleUsed);
        }
        state.used = true;
        Ok(())
    }

    fn commit<T>(&self, result: Result<T>) -> Result<T> {
        let mut state = self.control.state();
        state.committed = true;
        if let Some(phase) = state.cleanup_failure {
            Err(SecretSpecError::CleanupFailed {
                phase,
                cancelled: state.cancelled,
            })
        } else if state.cancelled {
            Err(SecretSpecError::Cancelled)
        } else {
            result
        }
    }
}

type Finalizer = Box<dyn FnOnce(Option<&'static str>) + Send>;

/// Passed explicitly to opted-in providers; never installed in a task/thread local.
#[derive(Clone)]
pub(crate) struct RequestContext {
    cancellation: CancellationHandle,
    runtime: tokio::runtime::Handle,
}

impl RequestContext {
    /// Admit a synchronous unit of work. Already admitted work must be joined.
    pub(crate) fn checkpoint(&self) -> Result<()> {
        let state = self.cancellation.control.state();
        if let Some(phase) = state.cleanup_failure {
            Err(SecretSpecError::CleanupFailed {
                phase,
                cancelled: state.cancelled,
            })
        } else if state.cancelled {
            Err(SecretSpecError::Cancelled)
        } else {
            Ok(())
        }
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    pub(crate) fn cleanup_failed(&self, phase: &'static str) {
        self.cancellation
            .control
            .state()
            .cleanup_failure
            .get_or_insert(phase);
    }

    pub(crate) fn on_finish(&self, finalizer: Finalizer) {
        self.cancellation.control.state().finalizers.push(finalizer);
    }

    /// Poll an audited native async operation on the owned runtime. Each poll
    /// is admitted through a checkpoint; an admitted poll may finish after
    /// cancellation. Never hold the state lock across dependency code or wakes.
    /// Spawned dependency tasks are drained by runtime drop.
    pub(crate) fn block_on<T>(&self, future: impl Future<Output = Result<T>>) -> Result<T> {
        self.runtime.block_on(async {
            let notification = self.cancellation.control.notification.cancelled();
            tokio::pin!(notification);
            tokio::pin!(future);
            std::future::poll_fn(|cx| {
                if let Err(error) = self.checkpoint() {
                    return Poll::Ready(Err(error));
                }
                // Register before polling so cancellation cannot lose a wakeup.
                if notification.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Err(SecretSpecError::Cancelled));
                }
                future.as_mut().poll(cx)
            })
            .await
        })
    }

    /// Short interruptible wait for synchronous locks and child supervision.
    pub(crate) fn wait(&self, duration: std::time::Duration) -> Result<()> {
        self.block_on(async {
            tokio::time::sleep(duration).await;
            Ok(())
        })
    }
}

/// Runs the unchanged value-resolution state machine on a joined worker and
/// confines its opted-in I/O to a dedicated runtime. One runtime thread drives
/// timers and transport tasks while the synchronous engine waits for a provider.
pub(crate) async fn run<T, F>(cancellation: &CancellationHandle, body: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(RequestContext) -> Result<T> + Send + 'static,
{
    cancellation.begin()?;
    struct CancelOnDrop(Option<CancellationHandle>);
    impl Drop for CancelOnDrop {
        fn drop(&mut self) {
            if let Some(handle) = &self.0 {
                handle.cancel();
            }
        }
    }
    let mut guard = CancelOnDrop(Some(cancellation.clone()));
    let handle = cancellation.clone();
    // Once started, this supervisor is deliberately never aborted. Even if its
    // caller drops the future, it owns cleanup through runtime shutdown.
    let worker = crate::provider::runtime::runtime().spawn_blocking(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()?;
            let context = RequestContext {
                cancellation: handle.clone(),
                runtime: runtime.handle().clone(),
            };
            let result = {
                // Dependency spawns from synchronous code must also belong to
                // this request, not the supervisor's shared runtime.
                let _entered = runtime.enter();
                context.checkpoint()?;
                body(context)
            };
            // This waits for blocking dependency tasks, including DNS. Every
            // provider/client must have been dropped by the body before here.
            drop(runtime);
            result
        }))
        .unwrap_or(Err(SecretSpecError::ResolutionPanicked));
        let result = handle.commit(result);
        let kind = result.as_ref().err().map(SecretSpecError::kind);
        let finalizers = std::mem::take(&mut handle.control.state().finalizers);
        for finalizer in finalizers {
            finalizer(kind);
        }
        result
    });
    let result = worker
        .await
        .unwrap_or(Err(SecretSpecError::ResolutionPanicked));
    guard.0 = None;
    result
}

pub(crate) fn unsupported(operation: impl Into<String>) -> SecretSpecError {
    SecretSpecError::CancellationUnsupported {
        operation: operation.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pre_cancel_and_reuse_never_enter_body() {
        let cancellation = CancellationHandle::new();
        cancellation.cancel();
        assert!(matches!(
            run::<(), _>(&cancellation, |_| panic!("entered")).await,
            Err(SecretSpecError::Cancelled)
        ));
        assert!(matches!(
            run::<(), _>(&cancellation, |_| panic!("reused")).await,
            Err(SecretSpecError::CancellationHandleUsed)
        ));
    }

    #[tokio::test]
    async fn committed_success_survives_late_cancellation() {
        let cancellation = CancellationHandle::new();
        let handle = cancellation.clone();
        let result = run(&cancellation, move |context| {
            context.on_finish(Box::new(move |kind| {
                assert!(kind.is_none());
                let state = handle.control.state.try_lock().unwrap();
                assert!(state.committed);
            }));
            Ok(42)
        })
        .await;
        assert_eq!(result.unwrap(), 42);
        cancellation.cancel();
        assert!(!cancellation.is_cancelled());
    }

    #[test]
    fn cancellation_wakes_without_holding_the_state_lock() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::task::{Context, Wake, Waker};

        struct CheckLock {
            control: Arc<Control>,
            unlocked: AtomicBool,
        }
        impl Wake for CheckLock {
            fn wake(self: Arc<Self>) {
                self.unlocked
                    .store(self.control.state.try_lock().is_ok(), Ordering::SeqCst);
            }
        }
        let cancellation = CancellationHandle::new();
        let wake = Arc::new(CheckLock {
            control: cancellation.control.clone(),
            unlocked: AtomicBool::new(false),
        });
        let waker = Waker::from(wake.clone());
        let mut notification = std::pin::pin!(cancellation.control.notification.cancelled());
        assert!(
            notification
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        cancellation.cancel();
        assert!(wake.unlocked.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn cancellation_does_not_wait_for_an_admitted_poll() {
        let cancellation = CancellationHandle::new();
        let handle = cancellation.clone();
        let (started, start) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let task = tokio::spawn(async move {
            run(&handle, |context| {
                context.block_on(async move {
                    started.send(()).unwrap();
                    released.recv().unwrap();
                    Ok(())
                })
            })
            .await
        });
        start.await.unwrap();
        let (notified, notification) = std::sync::mpsc::channel();
        let canceller = std::thread::spawn(move || {
            cancellation.cancel();
            notified.send(()).unwrap();
        });
        let timely = notification
            .recv_timeout(std::time::Duration::from_secs(2))
            .is_ok();
        assert!(!task.is_finished());
        // Always release and join, including on a regression, so the test cannot hang.
        release.send(()).unwrap();
        canceller.join().unwrap();
        let result = task.await.unwrap();
        assert!(
            timely,
            "cancellation waited for provider code to release the state lock"
        );
        assert!(matches!(result, Err(SecretSpecError::Cancelled)));
    }

    #[tokio::test]
    async fn cancellation_waits_for_blocking_dependency_and_drops_async_tasks() {
        let cancellation = CancellationHandle::new();
        let (started, start) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let (dropped, drop_rx) = tokio::sync::oneshot::channel();
        struct OnDrop(Option<tokio::sync::oneshot::Sender<()>>);
        impl Drop for OnDrop {
            fn drop(&mut self) {
                let _ = self.0.take().unwrap().send(());
            }
        }
        let handle = cancellation.clone();
        let task = tokio::spawn(async move {
            run(&handle, |context| {
                // Direct spawns by synchronous dependencies must use the
                // request runtime, even outside RequestContext::block_on.
                tokio::task::spawn_blocking(move || {
                    started.send(()).unwrap();
                    released.recv().unwrap();
                });
                let guard = OnDrop(Some(dropped));
                tokio::spawn(async move {
                    let _guard = guard;
                    std::future::pending::<()>().await;
                });
                context.block_on(std::future::pending::<Result<()>>())
            })
            .await
        });
        start.await.unwrap();
        cancellation.cancel();
        assert!(!task.is_finished());
        release.send(()).unwrap();
        assert!(matches!(
            task.await.unwrap(),
            Err(SecretSpecError::Cancelled)
        ));
        drop_rx.await.unwrap();
    }

    #[tokio::test]
    async fn cleanup_failure_is_distinct_from_cancellation() {
        for cancelled in [false, true] {
            let cancellation = CancellationHandle::new();
            let cancel = cancellation.clone();
            let error = run::<(), _>(&cancellation, move |context| {
                if cancelled {
                    cancel.cancel();
                }
                context.cleanup_failed("child_wait");
                context.checkpoint()?;
                panic!("cleanup failure must prevent subsequent I/O");
            })
            .await
            .unwrap_err();
            assert!(matches!(error, SecretSpecError::CleanupFailed {
                phase: "child_wait", cancelled: actual
            } if actual == cancelled));
        }
    }

    #[tokio::test]
    async fn dropping_caller_still_runs_supervisor_cleanup() {
        let cancellation = CancellationHandle::new();
        let handle = cancellation.clone();
        let (started, start) = tokio::sync::oneshot::channel();
        let (finished, finish) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            run::<(), _>(&handle, move |context| {
                context.on_finish(Box::new(move |kind| {
                    let _ = finished.send(kind);
                }));
                started.send(()).unwrap();
                context.block_on(std::future::pending())
            })
            .await
        });
        start.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(5), finish)
                .await
                .unwrap()
                .unwrap(),
            Some("cancelled")
        );
        assert!(cancellation.is_cancelled());
    }

    #[tokio::test]
    async fn panic_also_waits_for_started_dependency() {
        let cancellation = CancellationHandle::new();
        let (started, start) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let task = tokio::spawn(async move {
            run::<(), _>(&cancellation, move |context| {
                context.block_on(async move {
                    tokio::task::spawn_blocking(move || {
                        started.send(()).unwrap();
                        released.recv().unwrap();
                    });
                    Ok(())
                })?;
                panic!("test body panic");
            })
            .await
        });
        start.await.unwrap();
        assert!(!task.is_finished());
        release.send(()).unwrap();
        assert_eq!(
            task.await.unwrap().unwrap_err().kind(),
            "resolution_panicked"
        );
    }
}
