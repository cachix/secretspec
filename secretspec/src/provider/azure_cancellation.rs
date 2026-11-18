//! Azure Identity hooks that keep CLI and token-file work owned by the request.
use crate::command::CommandOutput as _;
use crate::request::RequestContext;
use azure_core::credentials::TokenCredential;
use azure_identity::{
    ClientAssertion, ClientAssertionCredential, DeveloperToolsCredentialOptions,
    WorkloadIdentityCredential,
};
use std::ffi::OsStr;
use std::path::PathBuf;
use std::sync::Arc;

pub(super) fn operation_error(error: &azure_core::Error, context: &str) -> crate::SecretSpecError {
    let mut source = Some(error as &(dyn std::error::Error + 'static));
    while let Some(cause) = source {
        if let Some(error) = cause.downcast_ref::<Arc<crate::SecretSpecError>>()
            && error.is_resolution_terminal()
        {
            return crate::SecretSpecError::SharedProvider(Arc::clone(error));
        }
        source = cause.source();
    }
    crate::SecretSpecError::ProviderOperationFailed(format!(
        "{context}: {}",
        crate::error::display_error_chain(error)
    ))
}

pub(super) fn developer_options(
    request: Option<&RequestContext>,
) -> Option<DeveloperToolsCredentialOptions> {
    request.map(|request| DeveloperToolsCredentialOptions {
        executor: Some(Arc::new(Executor(request.clone()))),
    })
}

struct Executor(RequestContext);

impl std::fmt::Debug for Executor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretSpecAzureExecutor")
    }
}

#[async_trait::async_trait]
impl azure_identity::Executor for Executor {
    async fn run(&self, program: &OsStr, args: &[&OsStr]) -> std::io::Result<std::process::Output> {
        let mut command = std::process::Command::new(program);
        command.args(args);
        let request = self.0.clone();
        // The request runtime joins this worker even when the SDK drops the
        // awaiting future. The runner kills and reaps the entire child group.
        tokio::task::spawn_blocking(move || command.output_for(Some(&request)))
            .await
            .map_err(std::io::Error::other)?
            .map_err(|error| match error {
                crate::SecretSpecError::Io(error) => error,
                error => std::io::Error::other(Arc::new(error)),
            })
    }
}

pub(super) fn workload_identity(
    request: Option<&RequestContext>,
) -> azure_core::Result<Arc<dyn TokenCredential>> {
    let Some(request) = request else {
        return WorkloadIdentityCredential::new(None)
            .map(|credential| credential as Arc<dyn TokenCredential>);
    };
    let env = |name| {
        std::env::var(name).map_err(|error| {
            azure_core::Error::with_error(
                azure_core::error::ErrorKind::Credential,
                error,
                format!("workload identity requires {name}"),
            )
        })
    };
    // WorkloadIdentityCredential uses this same assertion credential, but its
    // file refresh starts a detached OS thread. Supply only that file hook;
    // tenant validation, authority selection, token caching and HTTP stay in
    // the SDK. Read at each token refresh so projected token rotation works.
    ClientAssertionCredential::new(
        env("AZURE_TENANT_ID")?,
        env("AZURE_CLIENT_ID")?,
        FederatedTokenFile {
            path: PathBuf::from(env("AZURE_FEDERATED_TOKEN_FILE")?),
            request: request.clone(),
        },
        None,
    )
    .map(|credential| credential as Arc<dyn TokenCredential>)
}

struct FederatedTokenFile {
    path: PathBuf,
    request: RequestContext,
}

impl std::fmt::Debug for FederatedTokenFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretSpecFederatedTokenFile")
    }
}

#[async_trait::async_trait]
impl ClientAssertion for FederatedTokenFile {
    async fn secret(
        &self,
        _: Option<azure_core::http::ClientMethodOptions<'_>>,
    ) -> azure_core::Result<String> {
        let path = self.path.clone();
        let request = self.request.clone();
        let read = tokio::task::spawn_blocking(move || {
            crate::managed_io::read_to_string(&path, Some(&request))
        })
        .await
        .unwrap_or(Err(crate::SecretSpecError::ResolutionPanicked));
        read.map_err(|error| {
            azure_core::Error::with_error(
                azure_core::error::ErrorKind::Credential,
                // Preserve the typed error through the SDK's authentication wrappers.
                Arc::new(error),
                "failed to read federated token file",
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azure_core::http::{AsyncRawResponse, ClientOptions, HttpClient, Request, Transport};
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Debug, Default)]
    struct PendingHttp {
        started: tokio::sync::Notify,
        dropped: AtomicBool,
    }

    #[async_trait::async_trait]
    impl HttpClient for PendingHttp {
        async fn execute_request(&self, _: &Request) -> azure_core::Result<AsyncRawResponse> {
            struct Dropped<'a>(&'a AtomicBool);
            impl Drop for Dropped<'_> {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::Release);
                }
            }
            let _dropped = Dropped(&self.dropped);
            self.started.notify_one();
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn cancellation_drops_sdk_token_request_before_returning() {
        let http = Arc::new(PendingHttp::default());
        let transport = Arc::clone(&http);
        let cancellation = crate::CancellationHandle::new();
        let handle = cancellation.clone();
        let task = tokio::spawn(async move {
            crate::request::run(&handle, move |request| {
                let credential = azure_identity::ClientSecretCredential::new(
                    "tenant",
                    "client".into(),
                    azure_core::credentials::Secret::new("secret"),
                    Some(azure_identity::ClientSecretCredentialOptions {
                        client_options: ClientOptions {
                            transport: Some(Transport::new(transport)),
                            ..Default::default()
                        },
                    }),
                )
                .unwrap();
                request.block_on(async {
                    credential
                        .get_token(&["https://vault.azure.net/.default"], None)
                        .await
                        .map(|_| ())
                        .map_err(|error| {
                            crate::SecretSpecError::ProviderOperationFailed(error.to_string())
                        })
                })
            })
            .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), http.started.notified())
            .await
            .unwrap();
        cancellation.cancel();
        let error = tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), "cancelled");
        assert!(http.dropped.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn workload_assertion_reads_rotated_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "first").unwrap();
        let cancellation = crate::CancellationHandle::new();
        crate::request::run(&cancellation, move |request| {
            let assertion = FederatedTokenFile {
                path: path.clone(),
                request: request.clone(),
            };
            request.block_on(async {
                assert_eq!(assertion.secret(None).await.unwrap(), "first");
                std::fs::write(&path, "rotated").unwrap();
                assert_eq!(assertion.secret(None).await.unwrap(), "rotated");
                Ok(())
            })
        })
        .await
        .unwrap();
    }

    #[cfg(feature = "aac")]
    #[tokio::test]
    async fn unsupported_token_file_is_not_hidden_by_a_default() {
        let _lock = crate::tests::scrub_resolution_env();
        let dir = tempfile::tempdir().unwrap();
        let _tenant = crate::tests::EnvVarGuard::set("AZURE_TENANT_ID", "tenant");
        let _client = crate::tests::EnvVarGuard::set("AZURE_CLIENT_ID", "client");
        let _token = crate::tests::EnvVarGuard::set(
            "AZURE_FEDERATED_TOKEN_FILE",
            dir.path().to_str().unwrap(),
        );
        let config =
                "[project]\nname = 'azure-cancel'\nrevision = '1.0'\nrequire_reason = false\n\
                 [profiles.default]\n\
                 VALUE = { providers = ['aac://fixture?auth=workload_identity', 'null://'], default = 'must-not-mask-error' }"
            .parse().unwrap();
        let secrets = crate::Secrets::new(config, None, None, None);
        let error = secrets
            .resolve_cancellable(&crate::CancellationHandle::new())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), "cancellation_unsupported", "{error}");
    }
}
