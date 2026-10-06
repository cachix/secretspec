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

/// Only statuses representing throttling or temporary service failure.
pub(crate) fn transient_status(status: u16) -> bool {
    matches!(status, 429 | 500 | 502 | 503 | 504)
}

/// Retains a typed reqwest cause and classifies only temporary transport errors.
pub(crate) fn transport_error(
    provider: &'static str,
    error: reqwest::Error,
) -> crate::SecretSpecError {
    let error = error.without_url();
    let retryable = transient_transport(&error);
    let message = format!(
        "Failed to connect to {provider}: {}",
        crate::error::display_error_chain(&error)
    );
    let failure = crate::SecretSpecError::ProviderBackend {
        message,
        source: Box::new(error),
    };
    if retryable {
        super::retry::transient(failure, None)
    } else {
        failure
    }
}

pub(crate) fn transient_transport(error: &reqwest::Error) -> bool {
    if error.is_timeout() {
        return true;
    }
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            return matches!(
                io.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::Interrupted
            );
        }
        source = cause.source();
    }
    false
}

/// Classifies a failed HTTP response before interpreting its provider-specific body.
/// Successful bodies are buffered inside the same request attempt budget.
pub(crate) async fn checked_response(
    provider: &str,
    response: reqwest::Response,
) -> crate::Result<reqwest::Response> {
    checked_response_mode(provider, response, true).await
}

#[cfg(feature = "infisical")]
pub(crate) async fn checked_status(
    provider: &str,
    response: reqwest::Response,
) -> crate::Result<reqwest::Response> {
    checked_response_mode(provider, response, false).await
}

async fn checked_response_mode(
    provider: &str,
    response: reqwest::Response,
    consume_success: bool,
) -> crate::Result<reqwest::Response> {
    let status = response.status();
    if !transient_status(status.as_u16()) {
        if !status.is_success() || !consume_success {
            return Ok(response);
        }
        // Finish the successful body within the request's attempt budget.
        // The provider parser then consumes these same bytes without another network read.
        let mut buffered = ::http::Response::builder()
            .status(status)
            .version(response.version());
        *buffered.headers_mut().expect("valid response headers") = response.headers().clone();
        let bytes = response.bytes().await.map_err(|error| {
            body_error(
                crate::SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to read {provider} response: {}",
                    crate::error::display_error_chain(&error)
                )),
                error,
            )
        })?;
        return Ok(reqwest::Response::from(
            buffered.body(bytes).expect("valid buffered response"),
        ));
    }
    let hint = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(retry_after);
    let mut response = response;
    let mut bytes = Vec::new();
    while let Ok(Some(chunk)) = response.chunk().await {
        let remaining = 2048usize.saturating_sub(bytes.len());
        bytes.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        if chunk.len() >= remaining {
            break;
        }
    }
    let detail = String::from_utf8_lossy(&bytes);
    Err(super::retry::transient(
        crate::SecretSpecError::ProviderOperationFailed(format!(
            "{provider} returned HTTP {status}: {detail}"
        )),
        hint,
    ))
}

pub(crate) fn retry_after(value: &str) -> Option<Duration> {
    if let Ok(seconds) = value.trim().parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let date = jiff::fmt::rfc2822::parse(value).ok()?;
    let seconds = date
        .timestamp()
        .as_second()
        .saturating_sub(jiff::Timestamp::now().as_second());
    Some(Duration::from_secs(seconds.max(0) as u64))
}

/// Retries read-only requests at their own boundary, including reads before an unsafe write.
/// The outer wrapper sees an exhausted marker and cannot multiply this budget.
#[cfg(any(
    feature = "aac",
    feature = "cloudflare",
    feature = "doppler",
    feature = "infisical",
    feature = "scaleway",
    feature = "setec"
))]
pub(crate) async fn send(
    policy: super::RetryPolicy,
    provider: &'static str,
    request: reqwest::RequestBuilder,
    read_post: bool,
) -> crate::Result<reqwest::Response> {
    send_checked(policy, provider, request, read_post, |response| {
        checked_response(provider, response)
    })
    .await
}

/// Allows a provider to retain its sanitized diagnostics and status-only probes.
#[cfg(any(
    feature = "aac",
    feature = "cloudflare",
    feature = "doppler",
    feature = "infisical",
    feature = "scaleway",
    feature = "setec"
))]
pub(crate) async fn send_checked<F, Fut>(
    policy: super::RetryPolicy,
    provider: &'static str,
    request: reqwest::RequestBuilder,
    read_post: bool,
    check: F,
) -> crate::Result<reqwest::Response>
where
    F: Fn(reqwest::Response) -> Fut,
    Fut: std::future::Future<Output = crate::Result<reqwest::Response>>,
{
    let retryable_read = read_post
        || request
            .try_clone()
            .and_then(|request| request.build().ok())
            .is_some_and(|request| {
                matches!(
                    *request.method(),
                    reqwest::Method::GET | reqwest::Method::HEAD
                )
            });
    if !retryable_read {
        let response = request
            .send()
            .await
            .map_err(|error| transport_error(provider, error))?;
        return check(response).await;
    }
    // Every built-in provider uses replayable in-memory request bodies.
    policy
        .run_async(provider, || {
            let request = request.try_clone();
            let check = &check;
            async move {
                let request = request.ok_or_else(|| {
                    crate::SecretSpecError::ProviderOperationFailed(
                        "provider request body cannot be replayed".into(),
                    )
                })?;
                let response = request
                    .send()
                    .await
                    .map_err(|error| transport_error(provider, error))?;
                check(response).await
            }
        })
        .await
}

pub(crate) fn body_error(
    diagnostic: crate::SecretSpecError,
    error: reqwest::Error,
) -> crate::SecretSpecError {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
    let mut retryable = transient_transport(&error);
    while let Some(cause) = source {
        if let Some(http) = cause.downcast_ref::<reqwest::Error>() {
            retryable |= http.is_body();
        }
        source = cause.source();
    }
    let failure = crate::SecretSpecError::ProviderBackend {
        message: diagnostic.to_string(),
        source: Box::new(error),
    };
    if retryable {
        super::retry::transient(failure, None)
    } else {
        failure
    }
}

#[cfg(all(
    test,
    any(
        feature = "aac",
        feature = "cloudflare",
        feature = "doppler",
        feature = "infisical",
        feature = "scaleway",
        feature = "setec"
    )
))]
mod retry_tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    fn server(responses: Vec<String>) -> (String, std::thread::JoinHandle<usize>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let thread = std::thread::spawn(move || {
            let mut count = 0;
            for response in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                }
                stream.write_all(response.as_bytes()).unwrap();
                count += 1;
            }
            count
        });
        (url, thread)
    }
    #[tokio::test]
    async fn dropped_response_body_retries_the_same_read() {
        let (url, server) = server(vec![
            "HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\nshort".into(),
            "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\ncomplete".into(),
        ]);
        let response = send(
            super::super::RetryPolicy::default(),
            "fixture",
            client_builder().build().unwrap().get(url),
            false,
        )
        .await
        .unwrap();
        assert_eq!(response.text().await.unwrap(), "complete");
        assert_eq!(server.join().unwrap(), 2);
    }
    #[tokio::test]
    async fn transient_status_budget_is_not_multiplied_and_unknown_status_is_permanent() {
        let failure = "HTTP/1.1 503 Service Unavailable\r\nRetry-After: 0\r\nContent-Length: 6\r\nConnection: close\r\n\r\noutage".to_string();
        let (url, server) = server(vec![failure; 3]);
        let error = send(
            super::super::RetryPolicy::default(),
            "fixture",
            client_builder().build().unwrap().get(url),
            false,
        )
        .await
        .unwrap_err();
        assert_eq!(super::super::retry::retry_hint(&error), None);
        assert!(error.to_string().contains("outage"));
        assert_eq!(server.join().unwrap(), 3);
        assert!(!transient_status(501));
        assert!(!transient_status(401));
        assert_eq!(retry_after("60"), Some(Duration::from_secs(60)));
        assert_eq!(retry_after("nonsense"), None);
    }
}
