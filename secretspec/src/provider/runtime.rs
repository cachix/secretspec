/// Process-wide runtime for provider SDK and HTTP work.
///
/// `get_many` invokes its synchronous fetch closures from several OS threads.
/// Running each call on the caller's runtime, or on a temporary one, can
/// strand pooled connections and background tasks when that runtime is
/// dropped. One long-lived runtime keeps them alive across requests and
/// providers.
fn runtime() -> &'static tokio::runtime::Runtime {
    static PROVIDER_RUNTIME: std::sync::LazyLock<tokio::runtime::Runtime> =
        std::sync::LazyLock::new(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("Failed to create provider runtime")
        });
    &PROVIDER_RUNTIME
}

/// Executes an async future in a blocking context on the provider runtime.
///
/// Safe to call from any context: outside a runtime it blocks directly; on a
/// multi-thread runtime worker it uses `block_in_place`; on a current-thread
/// runtime, where `block_in_place` panics, it blocks a helper thread instead
/// so embedders using `#[tokio::main(flavor = "current_thread")]` work too.
#[allow(dead_code)]
pub(crate) fn block_on<F>(future: F) -> F::Output
where
    F: std::future::Future + Send,
    F::Output: Send,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(|| runtime().block_on(future))
        }
        Ok(_) => std::thread::scope(|scope| {
            let worker = scope.spawn(move || runtime().block_on(future));
            match worker.join() {
                Ok(output) => output,
                Err(panic) => std::panic::resume_unwind(panic),
            }
        }),
        Err(_) => runtime().block_on(future),
    }
}

#[cfg(test)]
mod tests {
    use super::block_on;

    fn provider_runtime_id() -> tokio::runtime::Id {
        block_on(async { tokio::runtime::Handle::current().id() })
    }

    #[test]
    fn runs_outside_a_runtime() {
        assert_eq!(block_on(async { 42 }), 42);
    }

    #[test]
    fn runs_inside_a_current_thread_runtime() {
        let outer = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let answer = outer.block_on(async { block_on(async { 42 }) });

        assert_eq!(answer, 42);
    }

    #[test]
    fn runs_inside_a_multi_thread_runtime_worker() {
        let outer = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();

        let answer = outer.block_on(async {
            tokio::spawn(async { block_on(async { 42 }) })
                .await
                .unwrap()
        });

        assert_eq!(answer, 42);
    }

    #[test]
    fn runs_inside_spawn_blocking_of_the_provider_runtime() {
        let answer = block_on(async {
            tokio::task::spawn_blocking(|| block_on(async { 42 }))
                .await
                .unwrap()
        });

        assert_eq!(answer, 42);
    }

    #[test]
    fn uses_one_runtime_regardless_of_the_callers_runtime() {
        let expected = provider_runtime_id();

        let from_thread = std::thread::spawn(provider_runtime_id).join().unwrap();
        let from_current_thread = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async { provider_runtime_id() });
        let from_multi_thread = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .build()
            .unwrap()
            .block_on(async { tokio::spawn(async { provider_runtime_id() }).await.unwrap() });

        assert_eq!(from_thread, expected);
        assert_eq!(from_current_thread, expected);
        assert_eq!(from_multi_thread, expected);
    }

    #[test]
    fn propagates_panics_from_a_current_thread_runtime() {
        let outer = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            outer.block_on(async { block_on(async { panic!("provider future panicked") }) })
        }));

        let panic = result.unwrap_err();
        assert_eq!(
            panic.downcast_ref::<&str>(),
            Some(&"provider future panicked")
        );
    }
}
