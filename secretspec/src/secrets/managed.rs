//! Managed execution reuses ResolutionExecution's routing and value semantics.
use super::*;
use crate::request::{CancellationHandle, RequestContext};

impl Secrets {
    /// Resolve with cancellation and wait for owned I/O to finish (0.22+).
    ///
    /// Only explicitly registered read paths are permitted. Unregistered providers
    /// return `cancellation_unsupported` before construction or discovery. Cancel
    /// through a clone of the handle and keep awaiting this future. Dropping
    /// the future requests cancellation but cannot synchronously await cleanup.
    /// Blocking filesystem calls and cryptography can delay completion.
    pub async fn resolve_cancellable(
        &self,
        cancellation: &CancellationHandle,
    ) -> Result<ResolveResponse> {
        let snapshot = self.request_snapshot();
        crate::request::run(cancellation, move |request| {
            snapshot.into_request(request).resolve()
        })
        .await
    }

    /// Byte-preserving variant of [`Self::resolve_cancellable`] (0.22+).
    pub async fn resolve_bytes_cancellable(
        &self,
        cancellation: &CancellationHandle,
    ) -> Result<ResolveResponse<SecretBytes>> {
        let snapshot = self.request_snapshot();
        crate::request::run(cancellation, move |request| {
            snapshot.into_request(request).resolve_bytes()
        })
        .await
    }

    pub(crate) fn load_for_request(path: Option<&Path>, request: &RequestContext) -> Result<Self> {
        request.checkpoint()?;
        let path = match path {
            Some(path) => path.to_path_buf(),
            None => find_config_file()?,
        };
        let path = if path.is_absolute() {
            path
        } else {
            std::env::current_dir()?.join(path)
        };
        let config = Config::load_with_request(&path, request)?;
        let spec = Spec::from_config_document(config)?;
        Self::from_spec_for_request(spec, path.parent().unwrap().to_path_buf(), request)
    }

    pub(crate) fn from_spec_for_request(
        spec: Spec,
        base_dir: PathBuf,
        request: &RequestContext,
    ) -> Result<Self> {
        request.checkpoint()?;
        let (config, manifest) = spec.into_parts();
        Self::from_compiled_spec(config, manifest, base_dir, true, Some(request))
    }

    fn request_snapshot(&self) -> Self {
        Self {
            retry_policy: self.retry_policy,
            provider: self.explicit_provider_spec(None),
            profile: Some(self.resolve_profile_name(None)),
            scope: self.resolve_scope_name(None),
            reason: self.reason.clone(),
            requested_authorization_duration: self.requested_authorization_duration,
            caller: self.caller.clone(),
            require_reason: self.require_reason,
            audit: self.audit.clone(),
            as_path_materializer: self.as_path_materializer.clone(),
            refuse_file_values: self.refuse_file_values,
            ..Self::from_config_parts(
                self.config.clone(),
                self.manifest.clone(),
                self.config_dir.clone(),
                self.global_config.clone(),
                false,
            )
        }
    }

    pub(crate) fn into_request(mut self, request: RequestContext) -> Self {
        self.request = Some(request);
        self.refuse_produced_writes = true;
        self.progress = false;
        self
    }

    pub(crate) fn managed_request(&self) -> Option<&RequestContext> {
        self.request.as_ref()
    }

    pub(crate) fn request_checkpoint(&self) -> Result<()> {
        self.request
            .as_ref()
            .map_or(Ok(()), RequestContext::checkpoint)
    }

    pub(super) fn check_managed_plan(
        &self,
        plan: &ResolutionPlan,
        materialize: Materialize,
    ) -> Result<()> {
        if self.request.is_none() && !self.refuse_file_values {
            return Ok(());
        }
        self.request_checkpoint()?;
        for secret in &plan.secrets {
            if self.refuse_file_values && secret.as_path() {
                return Err(SecretSpecError::FileValueRefused(secret.name.clone()));
            }
            if self.request.is_some() {
                if materialize.values() && secret.as_path() {
                    return Err(crate::request::unsupported("as_path materialization"));
                }
                if materialize.values() && secret.config().typed_contract().is_some() {
                    return Err(crate::request::unsupported(
                        "registered typed decoding/projection",
                    ));
                }
                if secret
                    .route
                    .as_ref()
                    .is_some_and(|route| route.cache().is_some())
                {
                    return Err(crate::request::unsupported("cached provider routes"));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(body: &str) -> Secrets {
        let config: Config = format!(
            "[project]\nname = 'cancel-test'\nrevision = '1.0'\nrequire_reason = false\n{body}"
        )
        .parse()
        .unwrap();
        // Other tests exercise ambient selection; keep these fixtures local.
        Secrets {
            ignore_ambient_provider: true,
            ignore_ambient_profile: true,
            ignore_ambient_scope: true,
            ..Secrets::new(config, None, None, None)
        }
    }

    #[tokio::test]
    async fn local_resolution_preserves_fallback_scope_composition_and_bytes() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".env"), b"USER=alice\nPASS=private\n").unwrap();
        let mut secrets = app(r#"
[providers]
empty = "null://"
local = "dotenv://.env"
[profiles.default]
USER = { providers = ["local", "unsupported-never-used://"] }
PASS = { providers = ["empty", "local"] }
URL = { composed = "${USER}:${PASS}" }
IGNORED = { providers = ["unsupported-out-of-scope://"] }
[scopes.only_url]
secrets = ["URL"]
"#);
        secrets.config_dir = dir.path().to_path_buf();
        secrets.set_scope("only_url".to_string());
        let legacy = serde_json::to_value(secrets.resolve().unwrap()).unwrap();
        let managed = serde_json::to_value(
            secrets
                .resolve_cancellable(&CancellationHandle::new())
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(managed, legacy);
        assert_eq!(managed["secrets"]["URL"]["value"], "alice:private");
        assert!(managed["secrets"].get("PASS").is_none());
    }

    #[tokio::test]
    async fn unsupported_primary_and_reached_fallback_are_terminal() {
        for providers in [
            "['unregistered://', 'null://']",
            "['null://', 'unregistered://']",
        ] {
            let secrets = app(&format!(
                "[profiles.default]\nVALUE = {{ providers = {providers}, default = 'must-not-mask-error' }}"
            ));
            let error = secrets
                .resolve_cancellable(&CancellationHandle::new())
                .await
                .unwrap_err();
            assert_eq!(error.kind(), "cancellation_unsupported");
        }
    }

    #[cfg(feature = "vault")]
    #[tokio::test]
    async fn invalid_target_uri_is_rejected_before_credential_reads() {
        let secrets = app(r#"
[providers.target]
uri = "vault://user:must-not-leak@secret/app"
credentials = { token = "null://" }
[profiles.default]
VALUE = { providers = ["target"] }
"#);
        let error = secrets
            .resolve_cancellable(&CancellationHandle::new())
            .await
            .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("carries a password"), "{message}");
        assert!(!message.contains("must-not-leak"));
    }

    #[cfg(feature = "vault")]
    #[tokio::test]
    async fn every_credential_source_is_validated_before_any_are_read() {
        for source in ["keyring", "keyring://", "unsupported-source://"] {
            let secrets = app(&format!(
                r#"
[providers.target]
uri = "vault://secret/app?auth=approle"
credentials = {{ role_id = "null://", secret_id = "{source}" }}
[profiles.default]
VALUE = {{ providers = ["target"], default = "must-not-mask-error" }}
"#
            ));
            let error = secrets
                .resolve_cancellable(&CancellationHandle::new())
                .await
                .unwrap_err();
            // Reading role_id first would fail as missing; wrapping the second
            // source's terminal error would let the default hide it.
            assert_eq!(error.kind(), "cancellation_unsupported", "{error}");
        }
    }

    #[tokio::test]
    async fn cancellable_resolves_preserve_custom_materializer_ownership() {
        let mut secrets = app("[profiles.default]\nVALUE = { default = 'inline' }");
        secrets.set_provider("null://");
        secrets.set_as_path_materializer(|_, _| panic!("an inline value must not create a file"));

        for error in [
            secrets.resolve().unwrap_err(),
            secrets
                .resolve_cancellable(&CancellationHandle::new())
                .await
                .unwrap_err(),
            secrets
                .resolve_bytes_cancellable(&CancellationHandle::new())
                .await
                .unwrap_err(),
        ] {
            assert!(
                matches!(&error, SecretSpecError::Io(e) if e.kind() == std::io::ErrorKind::Unsupported),
                "{error}"
            );
        }
    }

    #[tokio::test]
    async fn restrictions_include_hidden_dependencies_and_cached_routes() {
        let mut secrets = app(r#"
[profiles.default]
INPUT = { as_path = true, providers = ["null://"], default = "value" }
OUTPUT = { composed = "${INPUT}" }
[scopes.output]
secrets = ["OUTPUT"]
"#);
        secrets.set_scope("output");
        let error = secrets
            .resolve_cancellable(&CancellationHandle::new())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), "cancellation_unsupported");
        let mut no_files = secrets.request_snapshot();
        no_files.refuse_file_values();
        assert_eq!(
            no_files.resolve_without_values().unwrap_err().kind(),
            "file_value_refused"
        );
        let cached = app(r#"
[providers]
cached = { fallback = ["must-not-discover://"], cache = { provider = "dotenv:.cache", max_age = "1h" } }
[profiles.default]
VALUE = { providers = ["cached"] }
"#);
        assert_eq!(
            cached
                .resolve_cancellable(&CancellationHandle::new())
                .await
                .unwrap_err()
                .kind(),
            "cancellation_unsupported"
        );
    }

    #[tokio::test]
    async fn undefined_alias_is_distinct_from_unsupported_provider() {
        let secrets = app("[profiles.default]\nVALUE = { providers = ['undefined_alias'] }");
        assert_eq!(
            secrets
                .resolve_cancellable(&CancellationHandle::new())
                .await
                .unwrap_err()
                .kind(),
            "provider_not_found"
        );
    }

    #[tokio::test]
    async fn ephemeral_generation_is_allowed_and_persistent_generation_never_runs() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("must-not-exist");
        let command = format!("touch {}; printf value", marker.display());
        let mut secrets = app(&format!(
            r#"
[profiles.default]
VALUE = {{ providers = ["dotenv://.env"], type = "command", generate = {{ command = {:?} }} }}
"#,
            command
        ));
        secrets.config_dir = dir.path().to_path_buf();
        assert_eq!(
            secrets
                .resolve_cancellable(&CancellationHandle::new())
                .await
                .unwrap_err()
                .kind(),
            "produced_value_write_refused"
        );
        assert!(!marker.exists());
        secrets.set_provider("null://".to_string());
        let result = secrets
            .resolve_cancellable(&CancellationHandle::new())
            .await
            .unwrap();
        assert_eq!(
            serde_json::to_value(result).unwrap()["secrets"]["VALUE"]["value"],
            "value"
        );
        assert!(marker.exists());
    }

    #[cfg(feature = "setec")]
    #[tokio::test]
    async fn cancelled_http_is_closed_and_does_not_use_default() {
        use std::io::Read;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (started, started_rx) = tokio::sync::oneshot::channel();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut byte = [0];
            while !request.ends_with(b"\r\n\r\n") {
                socket.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            started.send(()).unwrap();
            let mut bytes = [0; 4096];
            loop {
                match socket.read(&mut bytes) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
                    Err(error) => panic!("transport outlived cancellation: {error}"),
                }
            }
        });
        let secrets = app(&format!(
            "[profiles.default]\nVALUE = {{ providers = ['setec://{addr}?tls=false'], default = 'must-not-return' }}"
        ));
        let cancellation = CancellationHandle::new();
        let handle = cancellation.clone();
        let task = tokio::spawn(async move { secrets.resolve_cancellable(&handle).await });
        started_rx.await.unwrap();
        cancellation.cancel();
        let error = tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), "cancelled");
        server.join().unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_is_rejected_before_open() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pipe");
        let cpath = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: cpath is a valid NUL-terminated temporary path.
        assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
        let secrets = app(&format!(
            "[profiles.default]\nVALUE = {{ providers = ['dotenv:{}'] }}",
            path.display()
        ));
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            secrets.resolve_cancellable(&CancellationHandle::new()),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(error.kind(), "cancellation_unsupported");
    }
}
