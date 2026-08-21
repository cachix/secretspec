use crate::client::{CallbackHandler, Client};
use crate::deadline::instant_from_unix_ms;
use crate::error::{ErrorKind, RpcError};
use crate::protocol::callback;
use crate::protocol::provider::{
    self as provider_protocol, InitializeApplication as ProviderInitializeApplication,
    InitializedApplication as ProviderInitializedApplication, Metadata,
};
use crate::protocol::resolver::{
    self as resolver_protocol, InitializeApplication as ResolverInitializeApplication,
    InitializedApplication as ResolverInitializedApplication,
};
use crate::protocol::{
    InitializeParams, InitializeResult, Limits, PROTOCOL_VERSION, PROVIDER_PROTOCOL, Product,
    RESOLVER_PROTOCOL,
};
use crate::{Error, Result, deadline_unix_ms_after};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::HashSet;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

/// Budget for reaping a child that had to be killed, and for draining its
/// stderr afterwards. Both are bounded local operations, so they are measured
/// from the moment they start rather than from the caller's shutdown deadline
/// (which the graceful wait has already spent by then).
const REAP_GRACE: Duration = Duration::from_secs(2);

pub use crate::launch::{Environment, LaunchOptions};

/// An owned child and its initialized wire session.
pub struct ChildSession {
    client: Client,
    child: Arc<Mutex<Child>>,
    monitor_cancel: CancellationToken,
    monitor: Mutex<Option<JoinHandle<()>>>,
    stderr: Mutex<Option<JoinHandle<Zeroizing<Vec<u8>>>>>,
    closed: AtomicBool,
}

impl ChildSession {
    pub fn client(&self) -> &Client {
        &self.client
    }

    pub async fn close(&self, deadline_unix_ms: u64) -> Result<()> {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let protocol_outcome = self.client.close(deadline_unix_ms).await;
        self.monitor_cancel.cancel();
        if let Some(monitor) = self.monitor.lock().await.take() {
            let _ = monitor.await;
        }

        let requested = instant_from_unix_ms(deadline_unix_ms);
        let cap = Instant::now() + Duration::from_secs(5);
        let deadline = requested.min(cap);
        let wait_outcome = wait_until(&self.child, deadline).await;
        let mut kill_error = None;
        if !matches!(&wait_outcome, Ok(true)) {
            // The graceful wait above runs until `deadline` elapses, so reusing
            // it here would leave the kill no budget at all and the child would
            // never be reaped. Reaping a killed child is bounded work, so it
            // gets its own small budget measured from now.
            let kill_deadline = Instant::now() + REAP_GRACE;
            let mut child = self.child.lock().await;
            if let Err(error) = child.start_kill() {
                kill_error = Some(error);
            } else {
                let _ = tokio::time::timeout_at(kill_deadline, child.wait()).await;
            }
        }
        if let Some(stderr) = self.stderr.lock().await.take() {
            // Likewise measured from now: `deadline` is already spent whenever
            // the child needed killing, and draining a closed pipe is bounded.
            finish_stderr(stderr, Instant::now() + REAP_GRACE).await;
        }
        wait_outcome?;
        if let Some(error) = kill_error {
            return Err(Error::Io(error));
        }
        protocol_outcome
    }
}

/// An initialized `secretspec.provider/1` client together with the child
/// process that owns its private transport.
pub struct ProviderSession {
    child: ChildSession,
    capabilities: HashSet<String>,
    metadata: Metadata,
}

macro_rules! provider_calls {
    ($(($name:ident, $method:ty)),+ $(,)?) => {
        $(
            pub async fn $name(
                &self,
                params: &<$method as provider_protocol::method::Method>::Params,
                deadline_unix_ms: u64,
            ) -> Result<<$method as provider_protocol::method::Method>::Result> {
                self.execute::<$method>(params, deadline_unix_ms).await
            }
        )+
    };
}

impl ProviderSession {
    /// Launch and validate a provider endpoint. The returned session owns both
    /// process and transport.
    pub async fn launch(
        options: LaunchOptions,
        client: Product,
        limits: Limits,
        application: ProviderInitializeApplication,
        startup_deadline_unix_ms: u64,
    ) -> Result<Self> {
        application.validate()?;
        let expected_scheme = application.scheme.clone();
        let initialize = InitializeParams {
            protocol: PROVIDER_PROTOCOL.to_string(),
            versions: vec![PROTOCOL_VERSION],
            client,
            limits,
            client_methods: Vec::new(),
            application,
        };
        let (child, initialized) = spawn::<_, ProviderInitializedApplication>(
            options,
            initialize,
            startup_deadline_unix_ms,
        )
        .await?;
        let validation = initialized
            .application
            .provider
            .validate()
            .and_then(|_| provider_protocol::validate_capabilities(&initialized.methods))
            .and_then(|_| {
                if initialized.application.provider.name == expected_scheme {
                    Ok(())
                } else {
                    Err(Error::Protocol(
                        "provider metadata name does not match its scheme",
                    ))
                }
            });
        if let Err(error) = validation {
            let _ = child
                .close(deadline_unix_ms_after(Duration::from_secs(1)))
                .await;
            return Err(error);
        }
        Ok(Self {
            child,
            capabilities: initialized.methods.into_iter().collect(),
            metadata: initialized.application.provider,
        })
    }

    pub fn raw(&self) -> &Client {
        self.child.client()
    }

    pub async fn execute<M>(&self, params: &M::Params, deadline_unix_ms: u64) -> Result<M::Result>
    where
        M: provider_protocol::method::Method,
    {
        self.call(M::NAME, params, deadline_unix_ms).await
    }

    pub async fn call<P: Serialize, R: DeserializeOwned>(
        &self,
        method: &str,
        params: &P,
        deadline_unix_ms: u64,
    ) -> Result<R> {
        self.child
            .client()
            .call(method, params, deadline_unix_ms)
            .await
    }

    provider_calls!(
        (resolve_address, provider_protocol::method::ResolveAddress),
        (get, provider_protocol::method::Get),
        (get_many, provider_protocol::method::GetMany),
        (exists, provider_protocol::method::Exists),
        (set, provider_protocol::method::Set),
        (set_expiring, provider_protocol::method::SetExpiring),
        (delete, provider_protocol::method::Delete),
        (clear, provider_protocol::method::Clear),
        (
            describe_write_target,
            provider_protocol::method::DescribeWriteTarget
        ),
        (reflect, provider_protocol::method::Reflect),
    );

    pub async fn check_writable(
        &self,
        params: &provider_protocol::AddressParams,
        deadline_unix_ms: u64,
    ) -> Result<()> {
        self.execute::<provider_protocol::method::CheckWritable>(params, deadline_unix_ms)
            .await
            .map(|_| ())
    }

    pub async fn check_deletable(
        &self,
        params: &provider_protocol::AddressParams,
        deadline_unix_ms: u64,
    ) -> Result<()> {
        self.execute::<provider_protocol::method::CheckDeletable>(params, deadline_unix_ms)
            .await
            .map(|_| ())
    }

    pub fn capabilities(&self) -> &HashSet<String> {
        &self.capabilities
    }

    pub fn supports(&self, method: &str) -> bool {
        self.capabilities.contains(method)
    }

    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    pub fn is_closed(&self) -> bool {
        self.child.client().is_closed()
    }

    pub async fn close(&self, deadline_unix_ms: u64) -> Result<()> {
        self.child.close(deadline_unix_ms).await
    }
}

/// An initialized `secretspec.resolver/1` client together with the child process
/// that owns its private transport.
pub struct ResolverSession {
    child: ChildSession,
    capabilities: HashSet<String>,
    initialized: ResolverInitializedApplication,
}

/// Obtains one secret value from a person on the resolver's behalf (0.20+).
///
/// A resolver in stdio mode has no terminal: its stdin and stdout are the
/// protocol. When a declaration says `prompt = true` and no value is stored,
/// the process that can ask is the one that launched the resolver, so the
/// resolver asks it. A session that installs no responder advertises nothing,
/// and such a declaration fails immediately with `interaction_required` rather
/// than waiting out a deadline.
///
/// The answer is a secret. Implementations must read it without echo, must not
/// log it, and should hand it straight back.
#[async_trait::async_trait]
pub trait PromptResponder: Send + Sync + 'static {
    async fn prompt(
        &self,
        params: callback::PromptParams,
    ) -> std::result::Result<callback::PromptResult, RpcError>;
}

struct PromptCallbacks {
    responder: Arc<dyn PromptResponder>,
}

#[async_trait::async_trait]
impl CallbackHandler for PromptCallbacks {
    async fn call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> std::result::Result<serde_json::Value, RpcError> {
        if method != callback::method::PROMPT {
            return Err(RpcError::new(ErrorKind::MethodNotFound));
        }
        let params: callback::PromptParams =
            serde_json::from_value(params).map_err(|_| RpcError::new(ErrorKind::InvalidParams))?;
        params
            .validate()
            .map_err(|_| RpcError::new(ErrorKind::InvalidParams))?;
        let result = self.responder.prompt(params).await?;
        // Validated on the way out too: an answer this client would refuse to
        // accept from a peer is one it must not send as a peer either.
        result
            .validate()
            .map_err(|_| RpcError::new(ErrorKind::InvalidParams))?;
        serde_json::to_value(result).map_err(|_| RpcError::new(ErrorKind::Internal))
    }
}

impl ResolverSession {
    pub async fn launch(
        options: LaunchOptions,
        client: Product,
        limits: Limits,
        application: ResolverInitializeApplication,
        startup_deadline_unix_ms: u64,
    ) -> Result<Self> {
        Self::launch_with_prompt(
            options,
            client,
            limits,
            application,
            startup_deadline_unix_ms,
            None,
        )
        .await
    }

    /// As [`Self::launch`], letting the resolver ask this process for a value a
    /// `prompt = true` declaration has no stored value for (0.20+).
    pub async fn launch_with_prompt(
        options: LaunchOptions,
        client: Product,
        limits: Limits,
        application: ResolverInitializeApplication,
        startup_deadline_unix_ms: u64,
        responder: Option<Arc<dyn PromptResponder>>,
    ) -> Result<Self> {
        application.validate()?;
        let (client_methods, callbacks): (Vec<String>, Option<Arc<dyn CallbackHandler>>) =
            match responder {
                Some(responder) => (
                    vec![callback::method::PROMPT.to_string()],
                    Some(Arc::new(PromptCallbacks { responder })),
                ),
                None => (Vec::new(), None),
            };
        let initialize = InitializeParams {
            protocol: RESOLVER_PROTOCOL.to_string(),
            versions: vec![PROTOCOL_VERSION],
            client,
            limits,
            client_methods: client_methods,
            application,
        };
        let (child, initialized) = spawn_with_callbacks::<_, ResolverInitializedApplication>(
            options,
            initialize,
            startup_deadline_unix_ms,
            callbacks,
        )
        .await?;
        if let Err(error) = initialized.application.validate() {
            let _ = child
                .close(deadline_unix_ms_after(Duration::from_secs(1)))
                .await;
            return Err(error);
        }
        let capabilities: HashSet<_> = initialized.methods.into_iter().collect();
        if !resolver_protocol::CAPABILITIES
            .iter()
            .all(|method| capabilities.contains(*method))
        {
            let _ = child
                .close(deadline_unix_ms_after(Duration::from_secs(1)))
                .await;
            return Err(Error::Protocol(
                "resolution endpoint did not advertise all required methods",
            ));
        }
        Ok(Self {
            child,
            capabilities,
            initialized: initialized.application,
        })
    }

    pub fn raw(&self) -> &Client {
        self.child.client()
    }

    pub async fn get(
        &self,
        params: &resolver_protocol::GetParams,
        deadline_unix_ms: u64,
    ) -> Result<resolver_protocol::GetResult> {
        self.child
            .client()
            .call(resolver_protocol::method::GET, params, deadline_unix_ms)
            .await
    }

    pub async fn release(
        &self,
        params: &resolver_protocol::ReleaseParams,
        deadline_unix_ms: u64,
    ) -> Result<resolver_protocol::ReleaseResult> {
        self.child
            .client()
            .call(resolver_protocol::method::RELEASE, params, deadline_unix_ms)
            .await
    }

    /// Report that a resolved value was refused by whatever it was presented
    /// to (0.20+), so a cached copy revoked before its expiry is discarded
    /// rather than served again. Every endpoint answers this.
    pub async fn reject(
        &self,
        params: &resolver_protocol::RejectParams,
        deadline_unix_ms: u64,
    ) -> Result<resolver_protocol::RejectResult> {
        self.child
            .client()
            .call(resolver_protocol::method::REJECT, params, deadline_unix_ms)
            .await
    }

    /// Store one declared name (0.20+). Only endpoints that advertise
    /// `resolver.set` accept it, so check [`Self::supports`] first when the
    /// caller can explain a read-only endpoint better than the wire error does.
    pub async fn set(
        &self,
        params: &resolver_protocol::SetParams,
        deadline_unix_ms: u64,
    ) -> Result<resolver_protocol::SetResult> {
        self.child
            .client()
            .call(resolver_protocol::method::SET, params, deadline_unix_ms)
            .await
    }

    /// Remove one declared name's stored value (0.20+), advertised as
    /// `resolver.delete` under the same rule as [`Self::set`].
    pub async fn delete(
        &self,
        params: &resolver_protocol::DeleteParams,
        deadline_unix_ms: u64,
    ) -> Result<resolver_protocol::DeleteResult> {
        self.child
            .client()
            .call(resolver_protocol::method::DELETE, params, deadline_unix_ms)
            .await
    }

    pub fn capabilities(&self) -> &HashSet<String> {
        &self.capabilities
    }

    /// Whether the endpoint advertised one method, such as
    /// [`resolver_protocol::method::SET`].
    pub fn supports(&self, method: &str) -> bool {
        self.capabilities.contains(method)
    }

    pub fn initialized(&self) -> &ResolverInitializedApplication {
        &self.initialized
    }

    pub fn is_closed(&self) -> bool {
        self.child.client().is_closed()
    }

    pub async fn close(&self, deadline_unix_ms: u64) -> Result<()> {
        self.child.close(deadline_unix_ms).await
    }
}

impl Drop for ChildSession {
    fn drop(&mut self) {
        // Emergency best effort only; the explicit async close path reaps and
        // joins every worker. Never block a foreign/runtime destructor.
        self.monitor_cancel.cancel();
        if let Ok(mut child) = self.child.try_lock() {
            let _ = child.start_kill();
        }
    }
}

pub async fn spawn<A, B>(
    options: LaunchOptions,
    initialize: InitializeParams<A>,
    startup_deadline_unix_ms: u64,
) -> Result<(ChildSession, InitializeResult<B>)>
where
    A: Serialize,
    B: DeserializeOwned,
{
    spawn_with_callbacks(options, initialize, startup_deadline_unix_ms, None).await
}

/// As [`spawn`], installing the handler for the callbacks this client
/// advertised in `client_methods` (0.20+).
pub async fn spawn_with_callbacks<A, B>(
    options: LaunchOptions,
    initialize: InitializeParams<A>,
    startup_deadline_unix_ms: u64,
    callbacks: Option<Arc<dyn CallbackHandler>>,
) -> Result<(ChildSession, InitializeResult<B>)>
where
    A: Serialize,
    B: DeserializeOwned,
{
    options.validate()?;
    let mut command = Command::new(&options.executable);
    command
        .args(&options.arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(false);
    match &options.environment {
        Environment::Inherit(overrides) => {
            command.envs(overrides);
        }
        Environment::Replace(environment) => {
            command.env_clear().envs(environment);
        }
    }

    let mut child = command.spawn()?;
    let stdin = child
        .stdin
        .take()
        .ok_or(Error::Protocol("child stdin was not piped"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or(Error::Protocol("child stdout was not piped"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or(Error::Protocol("child stderr was not piped"))?;

    let stderr_limit = options.max_stderr_bytes;
    let stderr_task = tokio::spawn(async move {
        let mut retained = Zeroizing::new(Vec::with_capacity(stderr_limit.min(4096)));
        let mut buffer = Zeroizing::new(vec![0_u8; 4096]);
        loop {
            let read: usize = stderr.read(&mut buffer).await.unwrap_or_default();
            if read == 0 {
                break;
            }
            let available = stderr_limit.saturating_sub(retained.len());
            retained.extend_from_slice(&buffer[..read.min(available)]);
        }
        retained
    });

    let child = Arc::new(Mutex::new(child));
    let connect = Client::connect_with_callbacks(
        stdout,
        stdin,
        initialize,
        startup_deadline_unix_ms,
        callbacks,
    )
    .await;
    let (client, initialized) = match connect {
        Ok(value) => value,
        Err(error) => {
            let mut child = child.lock().await;
            let _ = child.start_kill();
            // Initialization commonly fails because its deadline has already
            // elapsed. Killing and reaping are bounded cleanup from this
            // point, so they need a fresh budget rather than that spent
            // startup deadline.
            let _ = tokio::time::timeout(REAP_GRACE, child.wait()).await;
            drop(child);
            finish_stderr(stderr_task, Instant::now() + REAP_GRACE).await;
            return Err(error);
        }
    };

    let monitor_cancel = CancellationToken::new();
    let monitor_child = child.clone();
    let monitor_client = client.clone();
    let monitor_stop = monitor_cancel.clone();
    let monitor = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = monitor_stop.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_millis(25)) => {
                    let exited = monitor_child
                        .lock()
                        .await
                        .try_wait()
                        .ok()
                        .flatten()
                        .is_some();
                    if exited {
                        monitor_client
                            .abandon_after_process_exit(REAP_GRACE)
                            .await;
                        break;
                    }
                }
            }
        }
    });

    Ok((
        ChildSession {
            client,
            child,
            monitor_cancel,
            monitor: Mutex::new(Some(monitor)),
            stderr: Mutex::new(Some(stderr_task)),
            closed: AtomicBool::new(false),
        },
        initialized,
    ))
}

async fn wait_until(child: &Arc<Mutex<Child>>, deadline: Instant) -> Result<bool> {
    loop {
        if child.lock().await.try_wait()?.is_some() {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn finish_stderr(mut task: JoinHandle<Zeroizing<Vec<u8>>>, deadline: Instant) {
    if tokio::time::timeout_at(deadline, &mut task).await.is_err() {
        task.abort();
        let _ = task.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::InitializeResult;
    use crate::server::{ApplicationHandler, RequestContext, RpcResult, ServerConfig, serve};
    use async_trait::async_trait;
    use serde_json::{Value, json};
    use tokio::sync::Notify;

    struct GatedShutdown {
        entered: Arc<Notify>,
        release: Arc<Notify>,
    }

    #[async_trait]
    impl ApplicationHandler for GatedShutdown {
        fn protocol(&self) -> &'static str {
            RESOLVER_PROTOCOL
        }

        fn capabilities(&self) -> Vec<String> {
            vec!["resolver.get".to_string()]
        }

        async fn initialize(
            &self,
            _context: &RequestContext,
            _application: Value,
        ) -> RpcResult<Value> {
            Ok(json!({}))
        }

        async fn call(
            &self,
            _context: RequestContext,
            _method: &str,
            _params: Value,
        ) -> RpcResult<Value> {
            Ok(json!({}))
        }

        async fn shutdown(&self) {
            self.entered.notify_one();
            self.release.notified().await;
        }
    }

    #[tokio::test]
    async fn stderr_cleanup_is_bounded() {
        let task = tokio::spawn(async {
            std::future::pending::<()>().await;
            Zeroizing::new(Vec::new())
        });
        tokio::time::timeout(
            Duration::from_millis(250),
            finish_stderr(task, Instant::now() + Duration::from_millis(20)),
        )
        .await
        .expect("stderr cleanup exceeded its deadline");
    }

    /// A process watcher can observe exit immediately after the endpoint
    /// commits its shutdown response, before the reader consumes that buffered
    /// frame. Start the simulated watcher while shutdown is gated (an even
    /// stricter ordering), then repeat enough times to exercise scheduler
    /// choices.
    #[tokio::test]
    async fn process_exit_waits_for_a_buffered_shutdown_response() {
        for _ in 0..32 {
            let entered = Arc::new(Notify::new());
            let release = Arc::new(Notify::new());
            let handler = Arc::new(GatedShutdown {
                entered: entered.clone(),
                release: release.clone(),
            });
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let (client_read, client_write) = tokio::io::split(client_io);
            let (server_read, server_write) = tokio::io::split(server_io);
            let server = tokio::spawn(serve(
                server_read,
                server_write,
                handler,
                ServerConfig::default(),
            ));
            let initialize = InitializeParams {
                protocol: RESOLVER_PROTOCOL.to_string(),
                versions: vec![PROTOCOL_VERSION],
                client: Product {
                    name: "exit-race-test".to_string(),
                    version: "1".to_string(),
                },
                limits: Limits {
                    max_frame_bytes: 32 * 1024,
                    max_in_flight: 4,
                },
                client_methods: Vec::new(),
                application: json!({}),
            };
            let (client, _): (Client, InitializeResult<Value>) = Client::connect(
                client_read,
                client_write,
                initialize,
                deadline_unix_ms_after(Duration::from_secs(2)),
            )
            .await
            .unwrap();

            let close_client = client.clone();
            let close = tokio::spawn(async move {
                close_client
                    .close(deadline_unix_ms_after(Duration::from_secs(2)))
                    .await
            });
            entered.notified().await;
            let monitor_client = client.clone();
            let monitor = tokio::spawn(async move {
                monitor_client
                    .abandon_after_process_exit(Duration::from_secs(1))
                    .await;
            });
            release.notify_one();

            close.await.unwrap().unwrap();
            monitor.await.unwrap();
            server.await.unwrap().unwrap();
        }
    }
}
