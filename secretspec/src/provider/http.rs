//! Shared HTTP client configuration for providers that call a REST API.

use std::time::Duration;

/// How long establishing a connection, TLS included, may take.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long one request may take from sending to its last response byte.
///
/// Without a bound a stalled connection, or a proxy that accepts and never
/// answers, hangs `secretspec run` forever, and retry logic that acts on a
/// timeout can never fire.
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// A client builder with SecretSpec's connection and request timeouts applied.
pub(crate) fn client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
}

/// A client with SecretSpec's timeouts and reqwest's other defaults.
#[cfg(any(feature = "infisical", feature = "openbao", feature = "vault"))]
pub(crate) fn default_client() -> reqwest::Client {
    client_builder()
        .build()
        .expect("building an HTTP client without custom TLS settings")
}

/// Asserts that `client` was built by [`client_builder`].
///
/// reqwest exposes no accessor for its timeouts, so this reads them from the
/// client's `Debug` form.
#[cfg(test)]
pub(crate) fn assert_bounded(client: &reqwest::Client) {
    let debug = format!("{client:?}");
    assert!(
        debug.contains(&format!("{REQUEST_TIMEOUT:?}")),
        "client has no request timeout: {debug}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_bounds_connect_and_request_time() {
        let builder = format!("{:?}", client_builder());
        assert!(
            builder.contains(&format!("connect_timeout: {CONNECT_TIMEOUT:?}")),
            "{builder}"
        );
        assert_bounded(&client_builder().build().unwrap());
    }
}
