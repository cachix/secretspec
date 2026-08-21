/// Executes an async future in a blocking context.
///
/// If already inside a tokio runtime, uses `block_in_place` with the
/// existing runtime handle. Otherwise, uses a process-wide runtime so
/// background tasks owned by long-lived providers remain alive between calls.
#[allow(dead_code)]
pub(crate) fn block_on<F: std::future::Future>(future: F) -> F::Output {
    static PROVIDER_RUNTIME: std::sync::LazyLock<tokio::runtime::Runtime> =
        std::sync::LazyLock::new(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("Failed to create provider runtime")
        });
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => tokio::task::block_in_place(|| handle.block_on(future)),
        Err(_) => PROVIDER_RUNTIME.block_on(future),
    }
}
