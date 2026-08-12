//! Read-only SSH agent backed by SecretSpec provider routes.

use crate::{SecretSpecError, Secrets};
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use secrecy::ExposeSecret;
use sha2::{Sha256, Sha512};
use ssh_agent_lib::agent::{Session, listen};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, PublicCredential, SignRequest, signature};
use ssh_agent_lib::ssh_key::private::{KeypairData, PrivateKey};
use ssh_agent_lib::ssh_key::{Algorithm, HashAlg, Signature};
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
#[cfg(unix)]
use std::path::Path;

/// Shortest RSA modulus the agent will advertise or sign with, matching the
/// floor `ssh-key` applies in the conversion [`sign_rsa`] has to bypass.
const RSA_MIN_KEY_SIZE: usize = 2048;

#[derive(Clone)]
struct ManagedIdentity {
    name: String,
    identity: Identity,
}

#[derive(Clone)]
struct SecretSpecAgent {
    secrets: Arc<Secrets>,
    identities: Arc<Vec<ManagedIdentity>>,
}

impl SecretSpecAgent {
    fn load(secrets: Secrets) -> crate::Result<Self> {
        let names = secrets.ssh_agent_key_names()?;
        if names.is_empty() {
            return Err(operation_error(
                "the active profile has no SSH keys; add `type = \"ssh_private_key\"` to at least one stored OpenSSH private-key declaration",
            ));
        }

        let mut identities: Vec<ManagedIdentity> = Vec::with_capacity(names.len());
        for name in names {
            let private_key = load_private_key(&secrets, &name)?;
            let credential = PublicCredential::Key(private_key.public_key().key_data().clone());
            if let Some(existing) = identities
                .iter()
                .find(|managed| managed.identity.credential == credential)
            {
                return Err(operation_error(format!(
                    "SSH private key secrets '{}' and '{name}' contain the same public identity; keep only one declaration in the active profile or scope",
                    existing.name
                )));
            }
            identities.push(ManagedIdentity {
                identity: Identity {
                    credential,
                    comment: format!("secretspec:{name}"),
                },
                name,
            });
        }

        Ok(Self {
            secrets: Arc::new(secrets),
            identities: Arc::new(identities),
        })
    }

    fn managed(&self, credential: &PublicCredential) -> Option<&ManagedIdentity> {
        self.identities
            .iter()
            .find(|managed| &managed.identity.credential == credential)
    }
}

#[ssh_agent_lib::async_trait]
impl Session for SecretSpecAgent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        Ok(self
            .identities
            .iter()
            .map(|managed| managed.identity.clone())
            .collect())
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        let managed = self
            .managed(&request.credential)
            .ok_or(AgentError::Failure)?;
        let private_key = load_private_key(&self.secrets, &managed.name).map_err(agent_error)?;
        let actual = PublicCredential::Key(private_key.public_key().key_data().clone());
        if actual != request.credential {
            return Err(agent_error(operation_error(format!(
                "SSH private key stored for '{}' no longer matches the identity advertised by this agent; restart the agent after rotating the key",
                managed.name
            ))));
        }

        sign(&private_key, &request).map_err(agent_error)
    }
}

fn operation_error(message: impl Into<String>) -> SecretSpecError {
    SecretSpecError::ProviderOperationFailed(message.into())
}

fn agent_error(error: SecretSpecError) -> AgentError {
    eprintln!("SecretSpec SSH agent: {error}");
    AgentError::other(error)
}

fn load_private_key(secrets: &Secrets, name: &str) -> crate::Result<PrivateKey> {
    let value = secrets.ssh_agent_key(name)?;
    let private_key = PrivateKey::from_openssh(value.expose_secret()).map_err(|error| {
        operation_error(format!(
            "secret '{name}' is not a valid OpenSSH private key: {error}"
        ))
    })?;
    ensure_agent_usable(name, &private_key)?;
    Ok(private_key)
}

/// Reject, at load time, every stored key this agent must not advertise, so a
/// rejected key never reaches an identity listing or a signature.
fn ensure_agent_usable(name: &str, private_key: &PrivateKey) -> crate::Result<()> {
    if private_key.is_encrypted() {
        return Err(operation_error(format!(
            "SSH private key secret '{name}' is passphrase-encrypted; store an unencrypted OpenSSH key in the secure provider so the non-interactive agent can sign with it"
        )));
    }
    match private_key.key_data() {
        KeypairData::Rsa(keypair) => {
            // `sign_rsa` builds the signing key by hand, which also bypasses the
            // minimum-size check `ssh-key` applies in its own conversion. Nothing
            // on the decode path enforces it, so check it here instead.
            let bits = keypair
                .public
                .n
                .as_positive_bytes()
                .map_or(0, |modulus| modulus.len().saturating_mul(8));
            if bits < RSA_MIN_KEY_SIZE {
                return Err(operation_error(format!(
                    "SSH private key secret '{name}' is a {bits}-bit RSA key; SecretSpec signs with RSA keys of at least {RSA_MIN_KEY_SIZE} bits"
                )));
            }
            Ok(())
        }
        KeypairData::Ed25519(_) | KeypairData::Ecdsa(_) => Ok(()),
        _ => Err(operation_error(format!(
            "SSH private key secret '{name}' uses an unsupported algorithm; use Ed25519, ECDSA, or RSA"
        ))),
    }
}

/// The RSA/SHA-2 flags are the only ones this agent understands. They are
/// meaningful for RSA alone, and the agent protocol requires ignoring them for
/// other key types rather than failing, which clients that set them
/// unconditionally depend on.
fn reject_unknown_flags(flags: u32) -> crate::Result<()> {
    let unknown = flags & !(signature::RSA_SHA2_256 | signature::RSA_SHA2_512);
    if unknown != 0 {
        return Err(operation_error(format!(
            "unsupported SSH agent signature flags {unknown:#x}"
        )));
    }
    Ok(())
}

fn sign(private_key: &PrivateKey, request: &SignRequest) -> crate::Result<Signature> {
    match private_key.key_data() {
        KeypairData::Rsa(keypair) => sign_rsa(keypair, request),
        _ => {
            reject_unknown_flags(request.flags)?;
            private_key
                .try_sign(&request.data)
                .map_err(|error| operation_error(format!("failed to sign SSH request: {error}")))
        }
    }
}

fn sign_rsa(
    keypair: &ssh_agent_lib::ssh_key::private::RsaKeypair,
    request: &SignRequest,
) -> crate::Result<Signature> {
    reject_unknown_flags(request.flags)?;

    // ssh-key 0.6.7's `TryFrom<&RsaKeypair>` accidentally supplies `p` twice.
    // Build the key from both primes until ssh-agent-lib moves to a fixed
    // release. `ensure_agent_usable` re-applies the minimum-size check that
    // conversion also carries.
    let private_key = rsa::RsaPrivateKey::from_components(
        rsa::BigUint::try_from(&keypair.public.n)
            .map_err(|error| operation_error(format!("failed to load RSA modulus: {error}")))?,
        rsa::BigUint::try_from(&keypair.public.e)
            .map_err(|error| operation_error(format!("failed to load RSA exponent: {error}")))?,
        rsa::BigUint::try_from(&keypair.private.d).map_err(|error| {
            operation_error(format!("failed to load RSA private exponent: {error}"))
        })?,
        vec![
            rsa::BigUint::try_from(&keypair.private.p).map_err(|error| {
                operation_error(format!("failed to load first RSA prime: {error}"))
            })?,
            rsa::BigUint::try_from(&keypair.private.q).map_err(|error| {
                operation_error(format!("failed to load second RSA prime: {error}"))
            })?,
        ],
    )
    .map_err(|error| operation_error(format!("failed to load RSA private key: {error}")))?;
    let (algorithm, signature) = if request.flags & signature::RSA_SHA2_256 != 0
        && request.flags & signature::RSA_SHA2_512 == 0
    {
        let signature = SigningKey::<Sha256>::new(private_key)
            .try_sign(&request.data)
            .map_err(|error| operation_error(format!("failed to sign SSH request: {error}")))?;
        (
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha256),
            },
            signature.to_bytes().to_vec(),
        )
    } else {
        // Prefer SHA-512 when the client allows either algorithm. In particular,
        // OpenSSH's `ssh-add -T` probe sends zero flags while accepting an
        // RFC 8332 RSA/SHA-2 signature. Never fall back to legacy RSA/SHA-1.
        let signature = SigningKey::<Sha512>::new(private_key)
            .try_sign(&request.data)
            .map_err(|error| operation_error(format!("failed to sign SSH request: {error}")))?;
        (
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
            signature.to_bytes().to_vec(),
        )
    };

    Signature::new(algorithm, signature)
        .map_err(|error| operation_error(format!("failed to encode SSH signature: {error}")))
}

/// Run the agent in the foreground, optionally for the lifetime of one child.
/// Returns the child's exit code, or `None` when serving indefinitely.
pub(crate) fn run(
    secrets: Secrets,
    socket: Option<PathBuf>,
    command: Vec<String>,
) -> crate::Result<Option<i32>> {
    let agent = SecretSpecAgent::load(secrets)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(SecretSpecError::Io)?;

    #[cfg(unix)]
    {
        let bound = {
            let _runtime_context = runtime.enter();
            UnixSocket::bind(socket)?
        };
        let socket_path = bound.path.clone();
        let listener = bound.listener;
        let result = runtime.block_on(run_with_listener(
            listener,
            agent,
            socket_path.as_os_str(),
            command,
        ));
        drop(runtime);
        drop(bound.guard);
        result
    }

    #[cfg(windows)]
    {
        use ssh_agent_lib::agent::NamedPipeListener;
        let pipe = match socket {
            Some(path) => path.into_os_string(),
            None => format!(r"\\.\pipe\secretspec-agent-{}", std::process::id()).into(),
        };
        let listener = {
            let _runtime_context = runtime.enter();
            NamedPipeListener::bind(&pipe).map_err(SecretSpecError::Io)?
        };
        runtime.block_on(run_with_listener(listener, agent, &pipe, command))
    }
}

async fn run_with_listener<L>(
    listener: L,
    agent: SecretSpecAgent,
    socket: &std::ffi::OsStr,
    command: Vec<String>,
) -> crate::Result<Option<i32>>
where
    L: ssh_agent_lib::agent::ListeningSocket + std::fmt::Debug + Send + 'static,
    SecretSpecAgent: ssh_agent_lib::agent::Agent<L>,
{
    // Register handlers before serving or spawning a child so a shutdown that
    // arrives immediately cannot bypass cleanup during a setup race.
    let mut shutdown = ShutdownSignals::new().map_err(SecretSpecError::Io)?;
    if command.is_empty() {
        // Not `println!`: a consumer that closes the pipe early (`… | head -1`)
        // would make it panic instead of exiting through the shutdown path.
        let mut stdout = std::io::stdout();
        writeln!(stdout, "{}", socket_environment_command(socket)).map_err(SecretSpecError::Io)?;
        stdout.flush().map_err(SecretSpecError::Io)?;
        eprintln!("SecretSpec SSH agent is running in the foreground; press Ctrl-C to stop it.");
        return tokio::select! {
            result = listen(listener, agent) => {
                result.map_err(|error| operation_error(format!("SSH agent stopped: {error}")))?;
                Ok(None)
            }
            // Report a signalled stop the way command mode does, so a
            // supervisor can tell it apart from a voluntary exit.
            signal = shutdown.recv() => Ok(Some(signal.exit_code())),
        };
    }

    let mut child_command = tokio::process::Command::new(&command[0]);
    child_command.args(&command[1..]);
    configure_child_environment(
        &mut child_command,
        socket,
        agent
            .identities
            .iter()
            .map(|identity| identity.name.as_str()),
    );
    // Isolate the command and its descendants so a shutdown forwarded to the
    // process group cannot miss a grandchild or signal SecretSpec itself.
    #[cfg(unix)]
    child_command.process_group(0);

    let mut server = tokio::spawn(listen(listener, agent));
    let mut child = match child_command.spawn() {
        Ok(child) => child,
        Err(error) => {
            server.abort();
            let _ = server.await;
            return Err(SecretSpecError::Io(error));
        }
    };
    // That isolation also makes the command a *background* process group for
    // the terminal, and the kernel stops a background reader with SIGTTIN, so
    // an interactive `ssh` hangs on its first prompt. Hand the terminal to the
    // command for its lifetime, as a shell does for a foreground job.
    #[cfg(unix)]
    let terminal = ControllingTerminal::capture().inspect(|terminal| {
        if let Some(pid) = child.id() {
            terminal.give_to(pid);
        }
    });

    let status = tokio::select! {
        biased;
        status = child.wait() => status
            .map(|status| Some(child_exit_code(status)))
            .map_err(SecretSpecError::Io),
        signal = shutdown.recv() => terminate_child(&mut child, signal)
            .await
            .map(|_| Some(signal.exit_code()))
            .map_err(SecretSpecError::Io),
        // A listener that stops accepting silently disables signing for the
        // rest of the command: every later `git fetch` would fail to reach the
        // agent while SecretSpec still reported the command's own status. Stop
        // and say why instead.
        outcome = &mut server => {
            let _ = terminate_child(&mut child, ShutdownSignal::Terminate).await;
            Err(listener_stopped(outcome))
        }
    };
    server.abort();
    let _ = server.await;
    // Restores the terminal to SecretSpec's own process group, which must
    // happen after the command is reaped.
    #[cfg(unix)]
    drop(terminal);
    status
}

/// Why the listener task ended. Any outcome is a failure here: it is spawned to
/// run for the whole command.
fn listener_stopped(
    outcome: std::result::Result<std::result::Result<(), AgentError>, tokio::task::JoinError>,
) -> SecretSpecError {
    match outcome {
        Ok(Ok(())) => operation_error("the SSH agent stopped accepting connections"),
        Ok(Err(error)) => {
            operation_error(format!("the SSH agent stopped serving requests: {error}"))
        }
        Err(error) => operation_error(format!("the SSH agent listener panicked: {error}")),
    }
}

/// The command's exit status as a process exit code, using the shell's
/// `128 + signal` convention for a command killed by a signal. Ctrl-C reaches
/// the command directly once it owns the terminal, so signal deaths are an
/// ordinary outcome rather than an edge case.
fn child_exit_code(status: std::process::ExitStatus) -> i32 {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        status
            .code()
            .or_else(|| status.signal().map(|signal| 128 + signal))
            .unwrap_or(1)
    }

    #[cfg(windows)]
    {
        status.code().unwrap_or(1)
    }
}

/// The terminal a command-mode agent was started on, borrowed for the command's
/// lifetime and handed back on drop.
#[cfg(unix)]
struct ControllingTerminal {
    terminal: std::os::fd::OwnedFd,
    previous: libc::pid_t,
}

#[cfg(unix)]
impl ControllingTerminal {
    /// Capture the terminal, if SecretSpec has one and currently owns it.
    /// `None` covers a redirected stdin (CI) and a SecretSpec already running in
    /// the background, neither of which may take the terminal from another job.
    fn capture() -> Option<Self> {
        use std::os::fd::AsFd as _;

        let stdin = std::io::stdin();
        if unsafe { libc::isatty(stdin.as_raw_fd()) } != 1 {
            return None;
        }
        // Duplicate it: the descriptor has to outlive whatever the command does
        // to its own stdin.
        let terminal = stdin.as_fd().try_clone_to_owned().ok()?;
        let previous = unsafe { libc::tcgetpgrp(terminal.as_raw_fd()) };
        (previous >= 0 && previous == unsafe { libc::getpgrp() })
            .then_some(Self { terminal, previous })
    }

    /// Make the command's process group the terminal's foreground group.
    fn give_to(&self, pid: u32) {
        let Ok(pid) = libc::pid_t::try_from(pid) else {
            return;
        };
        with_sigttou_ignored(|| unsafe { libc::tcsetpgrp(self.terminal.as_raw_fd(), pid) });
        // A command that read the terminal before the handoff landed was already
        // stopped by SIGTTIN. SIGCONT resumes it and is a no-op for anything
        // still running; after the handoff no further SIGTTIN can arrive.
        unsafe { libc::kill(-pid, libc::SIGCONT) };
    }
}

#[cfg(unix)]
impl Drop for ControllingTerminal {
    fn drop(&mut self) {
        with_sigttou_ignored(|| unsafe {
            libc::tcsetpgrp(self.terminal.as_raw_fd(), self.previous)
        });
    }
}

/// Run `action` with SIGTTOU ignored, as a process must when it hands a terminal
/// back from a background process group. The default disposition would stop
/// SecretSpec instead.
#[cfg(unix)]
fn with_sigttou_ignored<T>(action: impl FnOnce() -> T) -> T {
    let previous = unsafe { libc::signal(libc::SIGTTOU, libc::SIG_IGN) };
    let result = action();
    if previous != libc::SIG_ERR {
        unsafe { libc::signal(libc::SIGTTOU, previous) };
    }
    result
}

fn configure_child_environment<'a>(
    command: &mut tokio::process::Command,
    socket: &std::ffi::OsStr,
    key_names: impl IntoIterator<Item = &'a str>,
) {
    command.env("SSH_AUTH_SOCK", socket);
    // `env_remove` overrides both inherited values and earlier overlays. An
    // env:// key (or a stale export from a parent shell) must be reachable only
    // through the agent protocol, never as raw private-key material.
    for name in key_names {
        command.env_remove(name);
    }
}

#[derive(Clone, Copy)]
enum ShutdownSignal {
    Interrupt,
    #[cfg(unix)]
    Terminate,
    #[cfg(unix)]
    Hangup,
}

struct ShutdownSignals {
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
    // Without a handler, closing the terminal kills the agent outright and the
    // socket guard never runs, leaving a stale socket that refuses the next
    // start.
    #[cfg(unix)]
    hangup: tokio::signal::unix::Signal,
    #[cfg(windows)]
    interrupt: tokio::signal::windows::CtrlC,
}

impl ShutdownSignals {
    fn new() -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            Ok(Self {
                interrupt: tokio::signal::unix::signal(
                    tokio::signal::unix::SignalKind::interrupt(),
                )?,
                terminate: tokio::signal::unix::signal(
                    tokio::signal::unix::SignalKind::terminate(),
                )?,
                hangup: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?,
            })
        }

        #[cfg(windows)]
        {
            Ok(Self {
                interrupt: tokio::signal::windows::ctrl_c()?,
            })
        }
    }

    async fn recv(&mut self) -> ShutdownSignal {
        #[cfg(unix)]
        {
            tokio::select! {
                _ = self.interrupt.recv() => ShutdownSignal::Interrupt,
                _ = self.terminate.recv() => ShutdownSignal::Terminate,
                _ = self.hangup.recv() => ShutdownSignal::Hangup,
            }
        }

        #[cfg(windows)]
        {
            self.interrupt.recv().await;
            ShutdownSignal::Interrupt
        }
    }
}

impl ShutdownSignal {
    fn exit_code(self) -> i32 {
        match self {
            Self::Interrupt => 130,
            #[cfg(unix)]
            Self::Terminate => 143,
            #[cfg(unix)]
            Self::Hangup => 129,
        }
    }
}

async fn terminate_child(
    child: &mut tokio::process::Child,
    signal: ShutdownSignal,
) -> std::io::Result<std::process::ExitStatus> {
    if let Err(error) = forward_shutdown_signal(child, signal) {
        let _ = force_kill_child(child);
        let _ = child.wait().await;
        return Err(error);
    }

    match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
        Ok(status) => status,
        Err(_) => {
            force_kill_child(child)?;
            child.wait().await
        }
    }
}

#[cfg(unix)]
fn forward_shutdown_signal(
    child: &mut tokio::process::Child,
    signal: ShutdownSignal,
) -> std::io::Result<()> {
    let raw_signal = match signal {
        ShutdownSignal::Interrupt => libc::SIGINT,
        ShutdownSignal::Terminate => libc::SIGTERM,
        ShutdownSignal::Hangup => libc::SIGHUP,
    };
    signal_child_process_group(child, raw_signal)
}

#[cfg(windows)]
fn forward_shutdown_signal(
    child: &mut tokio::process::Child,
    _signal: ShutdownSignal,
) -> std::io::Result<()> {
    // Console Ctrl-C is delivered to the child by Windows. Also request
    // termination explicitly so a non-console signal source cannot orphan it.
    child.start_kill()
}

#[cfg(unix)]
fn force_kill_child(child: &mut tokio::process::Child) -> std::io::Result<()> {
    signal_child_process_group(child, libc::SIGKILL)
}

#[cfg(windows)]
fn force_kill_child(child: &mut tokio::process::Child) -> std::io::Result<()> {
    child.start_kill()
}

#[cfg(unix)]
fn signal_child_process_group(
    child: &tokio::process::Child,
    signal: libc::c_int,
) -> std::io::Result<()> {
    let Some(id) = child.id() else {
        return Ok(());
    };
    let pid = libc::pid_t::try_from(id).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("child process id {id} does not fit in pid_t"),
        )
    })?;
    // The child was spawned into a process group whose id is its pid.
    // Negative `kill(2)` targets the complete group.
    if unsafe { libc::kill(-pid, signal) } == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(error)
    }
}

#[cfg(unix)]
fn socket_environment_command(socket: &std::ffi::OsStr) -> String {
    format!(
        "SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK",
        shell_quote(socket)
    )
}

#[cfg(windows)]
fn socket_environment_command(socket: &std::ffi::OsStr) -> String {
    let socket = socket.to_string_lossy();
    format!("$env:SSH_AUTH_SOCK='{}'", socket.replace('\'', "''"))
}

#[cfg(unix)]
fn shell_quote(value: &std::ffi::OsStr) -> String {
    let value = value.to_string_lossy();
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(unix)]
struct UnixSocket {
    listener: tokio::net::UnixListener,
    path: PathBuf,
    guard: UnixSocketGuard,
}

#[cfg(unix)]
struct UnixSocketGuard {
    path: PathBuf,
    _temporary: Option<tempfile::TempDir>,
}

#[cfg(unix)]
impl Drop for UnixSocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(unix)]
impl UnixSocket {
    fn bind(socket: Option<PathBuf>) -> crate::Result<Self> {
        let (path, temporary) = match socket {
            Some(path) => {
                prepare_socket_parent(&path)?;
                (path, None)
            }
            None => {
                let directory = tempfile::Builder::new()
                    .prefix("secretspec-agent-")
                    .tempdir()
                    .map_err(SecretSpecError::Io)?;
                let path = directory.path().join("agent.sock");
                (path, Some(directory))
            }
        };
        if path.exists() {
            return Err(operation_error(format!(
                "refusing to replace existing SSH-agent socket '{}'",
                path.display()
            )));
        }

        let listener = tokio::net::UnixListener::bind(&path).map_err(SecretSpecError::Io)?;
        let guard = UnixSocketGuard {
            path: path.clone(),
            _temporary: temporary,
        };
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(SecretSpecError::Io)?;
        Ok(Self {
            listener,
            path: path.clone(),
            guard,
        })
    }
}

#[cfg(unix)]
fn prepare_socket_parent(path: &Path) -> crate::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !parent.exists() {
        // Create it already private: a create-then-chmod leaves a window in
        // which another local user can open the directory.
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(SecretSpecError::Io)?;
    }
    // `symlink_metadata` does not follow links, so a symlinked parent is not a
    // directory here and fails this check.
    let metadata = std::fs::symlink_metadata(parent).map_err(SecretSpecError::Io)?;
    if !metadata.is_dir() {
        return Err(operation_error(format!(
            "SSH-agent socket parent '{}' must be a real directory",
            parent.display()
        )));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(operation_error(format!(
            "SSH-agent socket parent '{}' is accessible by other users; use a directory with mode 0700",
            parent.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: &str = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYgAAAJgAIAxdACAM
XQAAAAtzc2gtZWQyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYg
AAAEC2BsIi0QwW2uFscKTUUXNHLsYX4FxlaSDSblbAj7WR7bM+rvN+ot98qgEN796jTiQf
ZfG1KaT0PtFDJ/XFSqtiAAAAEHVzZXJAZXhhbXBsZS5jb20BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----"#;

    /// A 1024-bit RSA key, below the size this agent will sign with.
    const WEAK_RSA_KEY: &str = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAIEAyq05aE8rBXifvvtDNA7TnFWodLECrXVEaSwocAiD/8asAdkwbG8e
F73TvsCFjzxjhd7L9pqB0Fqf90KIgpFCShTEa0lU6xbiPV5oiZHMwFnOo/74S8NIbQ/9LK
NY9ManuwyVc5Tfhov7GhNMoNlG+fPOGxCvo5oxd4VuhhgfZJsAAAIIYd86F2HfOhcAAAAH
c3NoLXJzYQAAAIEAyq05aE8rBXifvvtDNA7TnFWodLECrXVEaSwocAiD/8asAdkwbG8eF7
3TvsCFjzxjhd7L9pqB0Fqf90KIgpFCShTEa0lU6xbiPV5oiZHMwFnOo/74S8NIbQ/9LKNY
9ManuwyVc5Tfhov7GhNMoNlG+fPOGxCvo5oxd4VuhhgfZJsAAAADAQABAAAAgQCS96fQRt
A4iG62S3dA8ZtrGwYrkAwUAhwYc8fi7ZniSIuET5z4lF7q8mDwSqTO6Ah3E8ctTH7jukOT
RfC9VV4OFTyol4/kyj/hsr28xYicE8dwHKRHcPomB6uMTAHFB+G2u61eh8y4GL3BaiVNqG
/upf8eDc705GrXOSDl76DmoQAAAEEAzHmmpv9FJn6wYWmfIZcU2DZNAxflfEiS8jY7eTMn
TCGW5BiTcnvDNN26GsPuu2l41AAbgdkYaECh7gB2jdBzwAAAAEEA8Rmfr9TZtaBdapD4H9
7HZfvkxoReOx99CRPIYFnXlCSs3JRugNJgdgB0fNdoHGSWEjRrg/+iND0l998T59suCwAA
AEEA1zO21QGgICzL2ctSL4SsEEje59d4ptRdIM8ByAvetMdK/KlFpldTk1DqqJz3jCFJZ7
qp8pc+YCS0kE/3hXoNsQAAABB3ZWFrQGV4YW1wbGUuY29tAQ==
-----END OPENSSH PRIVATE KEY-----"#;

    #[test]
    fn signs_ed25519_agent_requests() {
        let key = PrivateKey::from_openssh(TEST_KEY).unwrap();
        let request = SignRequest {
            credential: PublicCredential::Key(key.public_key().key_data().clone()),
            data: b"ssh authentication request".to_vec(),
            flags: 0,
        };
        let signature = sign(&key, &request).unwrap();
        assert_eq!(signature.algorithm(), Algorithm::Ed25519);
    }

    #[test]
    fn ignores_rsa_signature_flags_on_other_algorithms() {
        // The protocol reserves these flags for RSA and requires other key
        // types to ignore them; clients that set them unconditionally would
        // otherwise fail to authenticate with an Ed25519 key.
        let key = PrivateKey::from_openssh(TEST_KEY).unwrap();
        let request = SignRequest {
            credential: PublicCredential::Key(key.public_key().key_data().clone()),
            data: b"ssh authentication request".to_vec(),
            flags: signature::RSA_SHA2_512,
        };
        let signature = sign(&key, &request).unwrap();
        assert_eq!(signature.algorithm(), Algorithm::Ed25519);
    }

    #[test]
    fn rejects_unknown_signature_flags() {
        let key = PrivateKey::from_openssh(TEST_KEY).unwrap();
        let request = SignRequest {
            credential: PublicCredential::Key(key.public_key().key_data().clone()),
            data: b"ssh authentication request".to_vec(),
            flags: 0x40,
        };
        let error = sign(&key, &request).unwrap_err().to_string();
        assert!(error.contains("0x40"), "unexpected error: {error}");
    }

    #[test]
    fn rejects_rsa_keys_below_the_minimum_size() {
        let key = PrivateKey::from_openssh(WEAK_RSA_KEY).unwrap();
        let error = ensure_agent_usable("DEPLOY_KEY", &key)
            .unwrap_err()
            .to_string();
        assert!(error.contains("1024-bit RSA"), "unexpected error: {error}");
    }

    #[test]
    fn accepts_ed25519_keys() {
        let key = PrivateKey::from_openssh(TEST_KEY).unwrap();
        ensure_agent_usable("DEPLOY_KEY", &key).unwrap();
    }

    #[test]
    fn signs_and_verifies_rsa_agent_requests_with_sha2() {
        use rsa::signature::Verifier as _;

        let rsa_key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
        let keypair = ssh_agent_lib::ssh_key::private::RsaKeypair::try_from(&rsa_key).unwrap();
        let key = PrivateKey::new(KeypairData::Rsa(keypair), "test RSA key").unwrap();
        ensure_agent_usable("DEPLOY_KEY", &key).unwrap();
        let data = b"ssh authentication request".to_vec();

        for (flags, expected_hash) in [
            (0, HashAlg::Sha512),
            (signature::RSA_SHA2_256, HashAlg::Sha256),
            (signature::RSA_SHA2_512, HashAlg::Sha512),
        ] {
            let request = SignRequest {
                credential: PublicCredential::Key(key.public_key().key_data().clone()),
                data: data.clone(),
                flags,
            };
            let signature = sign(&key, &request).unwrap();
            assert_eq!(
                signature.algorithm(),
                Algorithm::Rsa {
                    hash: Some(expected_hash)
                }
            );
            key.public_key()
                .key_data()
                .verify(&request.data, &signature)
                .unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn shell_output_quotes_socket_paths() {
        assert_eq!(
            shell_quote(std::ffi::OsStr::new("/tmp/team's agent.sock")),
            "'/tmp/team'\\''s agent.sock'"
        );
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn child_environment_omits_every_advertised_key() {
        let mut command = tokio::process::Command::new("sh");
        command
            .arg("-c")
            .arg("test -z \"${SSH_KEY_ONE+x}\" && test -z \"${SSH_KEY_TWO+x}\" && test \"$SSH_AUTH_SOCK\" = /tmp/agent.sock")
            .env("SSH_KEY_ONE", "raw-private-key-one")
            .env("SSH_KEY_TWO", "raw-private-key-two");

        configure_child_environment(
            &mut command,
            std::ffi::OsStr::new("/tmp/agent.sock"),
            ["SSH_KEY_ONE", "SSH_KEY_TWO"],
        );

        assert!(command.status().await.unwrap().success());
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_signal_is_forwarded_to_the_child_process_group() {
        use tokio::io::{AsyncBufReadExt as _, BufReader};

        let mut command = tokio::process::Command::new("sh");
        command
            .arg("-c")
            // The shell announces itself only once its trap is installed, so
            // reading that line synchronizes the test with the child instead of
            // racing it on a timer.
            .arg("trap 'exit 42' TERM; echo ready; while :; do :; done")
            .stdout(std::process::Stdio::piped())
            .process_group(0);
        let mut child = command.spawn().unwrap();
        let mut ready = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut ready)
            .await
            .unwrap();
        assert_eq!(ready.trim(), "ready");

        let status = terminate_child(&mut child, ShutdownSignal::Terminate)
            .await
            .unwrap();

        assert_eq!(status.code(), Some(42));
    }
}
