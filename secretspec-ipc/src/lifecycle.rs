use crate::client::Client;
use crate::deadline::instant_from_unix_ms;
use crate::protocol::client::{
    self as client_protocol, InitializeApplication as ResolutionInitializeApplication,
    InitializedApplication as ResolutionInitializedApplication,
};
use crate::protocol::provider::{
    self as provider_protocol, InitializeApplication as ProviderInitializeApplication,
    InitializedApplication as ProviderInitializedApplication, Metadata,
};
use crate::protocol::{
    CLIENT_PROTOCOL, InitializeParams, InitializeResult, Limits, PROTOCOL_VERSION,
    PROVIDER_PROTOCOL, Product,
};
use crate::{Error, Result, deadline_unix_ms_after};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::{BTreeMap, HashSet};
use std::ffi::OsString;
use std::path::PathBuf;
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

#[derive(Debug, Clone)]
pub enum Environment {
    /// Inherit the caller environment and apply these overrides.
    Inherit(BTreeMap<OsString, OsString>),
    /// Clear the environment and install exactly these entries.
    Replace(BTreeMap<OsString, OsString>),
}

#[derive(Debug, Clone)]
pub struct LaunchOptions {
    pub executable: PathBuf,
    pub arguments: Vec<OsString>,
    pub environment: Environment,
    pub allow_path_discovery: bool,
    pub max_stderr_bytes: usize,
}

impl LaunchOptions {
    pub fn validate(&self) -> Result<()> {
        if self.executable.as_os_str().is_empty() {
            return Err(Error::Protocol("executable is empty"));
        }
        if !self.allow_path_discovery && !self.executable.is_absolute() {
            return Err(Error::Protocol(
                "executable must be absolute unless discovery is enabled",
            ));
        }
        if self.max_stderr_bytes > 1_048_576 {
            return Err(Error::Protocol(
                "stderr capture exceeds the version 1 bound",
            ));
        }
        Ok(())
    }
}

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
            .and_then(|_| provider_protocol::validate_capabilities(&initialized.capabilities))
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
            capabilities: initialized.capabilities.into_iter().collect(),
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

/// An initialized `secretspec.client/1` client together with the child process
/// that owns its private transport.
pub struct ResolutionSession {
    child: ChildSession,
    capabilities: HashSet<String>,
    initialized: ResolutionInitializedApplication,
}

impl ResolutionSession {
    pub async fn launch(
        options: LaunchOptions,
        client: Product,
        limits: Limits,
        application: ResolutionInitializeApplication,
        startup_deadline_unix_ms: u64,
    ) -> Result<Self> {
        application.validate()?;
        let initialize = InitializeParams {
            protocol: CLIENT_PROTOCOL.to_string(),
            versions: vec![PROTOCOL_VERSION],
            client,
            limits,
            application,
        };
        let (child, initialized) = spawn::<_, ResolutionInitializedApplication>(
            options,
            initialize,
            startup_deadline_unix_ms,
        )
        .await?;
        if let Err(error) = initialized.application.validate() {
            let _ = child
                .close(deadline_unix_ms_after(Duration::from_secs(1)))
                .await;
            return Err(error);
        }
        let capabilities: HashSet<_> = initialized.capabilities.into_iter().collect();
        if !client_protocol::CAPABILITIES
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

    pub async fn resolve(
        &self,
        params: &client_protocol::ResolveParams,
        deadline_unix_ms: u64,
    ) -> Result<client_protocol::ResolveResult> {
        self.child
            .client()
            .call(client_protocol::method::RESOLVE, params, deadline_unix_ms)
            .await
    }

    pub async fn release(
        &self,
        params: &client_protocol::ReleaseParams,
        deadline_unix_ms: u64,
    ) -> Result<client_protocol::ReleaseResult> {
        self.child
            .client()
            .call(client_protocol::method::RELEASE, params, deadline_unix_ms)
            .await
    }

    pub fn capabilities(&self) -> &HashSet<String> {
        &self.capabilities
    }

    pub fn initialized(&self) -> &ResolutionInitializedApplication {
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
    let connect = Client::connect(stdout, stdin, initialize, startup_deadline_unix_ms).await;
    let (client, initialized) = match connect {
        Ok(value) => value,
        Err(error) => {
            let requested = instant_from_unix_ms(startup_deadline_unix_ms);
            let deadline = requested.min(Instant::now() + Duration::from_secs(5));
            let mut child = child.lock().await;
            let _ = child.start_kill();
            let _ = tokio::time::timeout_at(deadline, child.wait()).await;
            drop(child);
            finish_stderr(stderr_task, deadline).await;
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
                        monitor_client.abandon().await;
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
}
