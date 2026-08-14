/// Executes an async future in a blocking context.
///
/// If already inside a tokio runtime, uses `block_in_place` with the
/// existing runtime handle. Otherwise, creates a new runtime.
#[allow(dead_code)]
pub(crate) fn block_on<F: std::future::Future>(future: F) -> F::Output {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => tokio::task::block_in_place(|| handle.block_on(future)),
        Err(_) => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime")
            .block_on(future),
    }
}
