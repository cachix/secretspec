//! Provider that reads secrets from an EJSON file.
//!
//! The encrypted file path comes from the provider URI. The matching private
//! key is an injected `private_key` provider credential, so its source can be
//! any existing SecretSpec provider and native reference. Reads invoke the
//! official `ejson` CLI with the key on stdin, parse its JSON output, and select
//! one value with an RFC 6901 JSON Pointer.
//!
//! # URI format
//!
//! - `ejson:config/secrets.production.ejson`
//! - `ejson:///absolute/path/secrets.ejson`
//!
//! # Private key
//!
//! Configure the `private_key` provider credential on an alias. Its provider
//! reference names the stored private key and may pin an exact version. The key
//! never belongs in the URI or environment.

use super::{Address, Provider, ProviderCredentials, ProviderUrl};
use crate::SecretBytes;
use crate::config::NativeAddress;
use crate::{Result, SecretSpecError};
use percent_encoding::{AsciiSet, CONTROLS, percent_encode};
use secrecy::zeroize::Zeroizing;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::os::windows::{io::AsRawHandle, process::CommandExt};
#[cfg(unix)]
use std::os::{fd::AsRawFd, fd::FromRawFd, unix::process::CommandExt};
#[cfg(not(unix))]
use wait_timeout::ChildExt;
#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
#[cfg(windows)]
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
#[cfg(windows)]
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, OpenThread, ResumeThread, THREAD_SUSPEND_RESUME,
};

const PRIVATE_KEY: &str = "private_key";
const MAX_EJSON_BYTES: u64 = 16 * 1024 * 1024;
const DEFAULT_CLI_TIMEOUT: Duration = Duration::from_secs(30);

/// URI structural delimiters and path characters that must round-trip as data.
/// Path separators stay literal, while Windows separators and drive colons are
/// encoded into the opaque `ejson:` path form.
const EJSON_PATH_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'%')
    .add(b'@')
    .add(b'#')
    .add(b'?')
    .add(b'<')
    .add(b'>')
    .add(b'[')
    .add(b']')
    .add(b'|')
    .add(b'^')
    .add(b'\\')
    .add(b':');

fn provider_err(message: impl Into<String>) -> SecretSpecError {
    SecretSpecError::ProviderOperationFailed(message.into())
}

/// An opened ciphertext snapshot. On Unix it is anonymous and inherited by the
/// child through a descriptor path; other platforms use a private named file.
struct EncryptedSnapshot {
    #[cfg(unix)]
    file: File,
    #[cfg(not(unix))]
    file: tempfile::NamedTempFile,
}

impl EncryptedSnapshot {
    fn new() -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            let file = tempfile::tempfile()?;
            let fd = file.as_raw_fd();
            if fd >= 3 {
                return Ok(Self { file });
            }
            // Keep the inherited snapshot out of stdin/stdout/stderr slots,
            // which `Command` replaces while constructing the child.
            // SAFETY: `fd` belongs to `file`; F_DUPFD_CLOEXEC returns a new
            // independently owned descriptor at or above the requested floor.
            let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
            if duplicate == -1 {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: `duplicate` is a fresh owned descriptor returned above.
            let file = unsafe { File::from_raw_fd(duplicate) };
            Ok(Self { file })
        }
        #[cfg(not(unix))]
        {
            tempfile::NamedTempFile::new().map(|file| Self { file })
        }
    }

    fn file_mut(&mut self) -> &mut File {
        #[cfg(unix)]
        {
            &mut self.file
        }
        #[cfg(not(unix))]
        {
            self.file.as_file_mut()
        }
    }

    fn rewind(&mut self) -> std::io::Result<()> {
        self.file_mut().seek(SeekFrom::Start(0)).map(|_| ())
    }

    #[cfg(unix)]
    fn command_path(&self) -> PathBuf {
        let fd = self.file.as_raw_fd();
        if cfg!(target_os = "linux") {
            PathBuf::from(format!("/proc/self/fd/{fd}"))
        } else {
            PathBuf::from(format!("/dev/fd/{fd}"))
        }
    }

    #[cfg(not(unix))]
    fn command_path(&self) -> PathBuf {
        self.file.path().to_path_buf()
    }

    #[cfg(unix)]
    fn configure_command(&self, command: &mut Command) {
        let fd = self.file.as_raw_fd();
        // SAFETY: `pre_exec` runs after fork and before exec. The closure uses
        // only async-signal-safe `fcntl` calls and changes only the child's
        // descriptor table, leaving the parent's close-on-exec flag unchanged.
        unsafe {
            command.pre_exec(move || {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags == -1 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    #[cfg(not(unix))]
    fn configure_command(&self, _command: &mut Command) {}
}

#[cfg(windows)]
struct OwnedWindowsHandle {
    handle: HANDLE,
}

#[cfg(windows)]
impl Drop for OwnedWindowsHandle {
    fn drop(&mut self) {
        // SAFETY: this type owns the live handle and closes it exactly once.
        let _ = unsafe { CloseHandle(self.handle) };
    }
}

#[cfg(windows)]
fn resume_suspended_process(process_id: u32) -> std::io::Result<()> {
    // SAFETY: this requests a read-only system snapshot handle.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    let snapshot = OwnedWindowsHandle { handle: snapshot };
    let mut entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };

    // SAFETY: `entry` advertises its exact size and remains writable while the
    // owned snapshot handle is live.
    let mut found = unsafe { Thread32First(snapshot.handle, &mut entry) };
    while found != 0 {
        if entry.th32OwnerProcessID == process_id {
            // SAFETY: the thread ID belongs to the newly created suspended
            // process, and the requested access permits only suspend/resume.
            let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
            if thread.is_null() {
                return Err(std::io::Error::last_os_error());
            }
            let thread = OwnedWindowsHandle { handle: thread };
            // SAFETY: CREATE_SUSPENDED created this initial thread with a
            // suspend count of one. `u32::MAX` reports failure.
            if unsafe { ResumeThread(thread.handle) } == u32::MAX {
                return Err(std::io::Error::last_os_error());
            }
            return Ok(());
        }
        // SAFETY: same initialized entry and live snapshot as Thread32First.
        found = unsafe { Thread32Next(snapshot.handle, &mut entry) };
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "failed to find the suspended EJSON CLI thread",
    ))
}

#[cfg(windows)]
struct WindowsJob {
    handle: HANDLE,
}

#[cfg(windows)]
impl WindowsJob {
    fn assign(child: &Child) -> std::io::Result<Self> {
        // SAFETY: null attributes and name create a private job object. Every
        // returned handle is closed on error or by `Drop`.
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error());
        }

        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: `limits` has the exact layout and size required by this job
        // information class, and `handle` remains live for the call.
        if unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&limits).cast(),
                std::mem::size_of_val(&limits) as u32,
            )
        } == 0
        {
            let error = std::io::Error::last_os_error();
            // SAFETY: `handle` is live and owned by this function.
            let _ = unsafe { CloseHandle(handle) };
            return Err(error);
        }

        // SAFETY: the child process handle stays live while `child` is live,
        // and the job handle is valid. Descendants join the same job unless the
        // job explicitly permits breakaway, which this job does not.
        if unsafe { AssignProcessToJobObject(handle, child.as_raw_handle() as HANDLE) } == 0 {
            let error = std::io::Error::last_os_error();
            // SAFETY: `handle` is live and owned by this function.
            let _ = unsafe { CloseHandle(handle) };
            return Err(error);
        }

        Ok(Self { handle })
    }

    fn terminate(&self) -> std::io::Result<()> {
        // SAFETY: `self.handle` remains valid until `Drop`.
        if unsafe { TerminateJobObject(self.handle, 1) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for WindowsJob {
    fn drop(&mut self) {
        // Closing a kill-on-close job stops any descendant that still holds an
        // inherited stdout handle after the direct EJSON process exits.
        // SAFETY: this type owns the live handle and closes it exactly once.
        let _ = unsafe { CloseHandle(self.handle) };
    }
}

struct ManagedChild {
    child: Child,
    child_reaped: bool,
    cleanup_complete: bool,
    exit_observed: bool,
    exit_status: Option<ExitStatus>,
    #[cfg(windows)]
    job: WindowsJob,
}

impl ManagedChild {
    fn new(child: Child) -> std::io::Result<Self> {
        #[cfg(windows)]
        {
            let mut child = child;
            let job = match WindowsJob::assign(&child) {
                Ok(job) => job,
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(error);
                }
            };
            if let Err(error) = resume_suspended_process(child.id()) {
                let _ = job.terminate();
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
            Ok(Self {
                child,
                child_reaped: false,
                cleanup_complete: false,
                exit_observed: false,
                exit_status: None,
                job,
            })
        }
        #[cfg(not(windows))]
        {
            Ok(Self {
                child,
                child_reaped: false,
                cleanup_complete: false,
                exit_observed: false,
                exit_status: None,
            })
        }
    }

    #[cfg(unix)]
    fn wait_for_exit(&mut self, timeout: Duration) -> std::io::Result<bool> {
        let deadline = Instant::now() + timeout;
        loop {
            let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
            // `WNOWAIT` observes exit without reaping the group leader. Its PID
            // therefore cannot be reused before process-group cleanup.
            // SAFETY: `info` points to writable storage for one `siginfo_t`, and
            // this call observes only the child PID owned by `self.child`.
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.child.id() as libc::id_t,
                    info.as_mut_ptr(),
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if result == -1 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            // SAFETY: a successful `waitid` initialized `info`; `si_pid == 0`
            // means the nonblocking observation found no exited child yet.
            if unsafe { info.assume_init().si_pid() } != 0 {
                self.exit_observed = true;
                return Ok(true);
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(false);
            }
            std::thread::sleep(remaining.min(Duration::from_millis(10)));
        }
    }

    #[cfg(not(unix))]
    fn wait_for_exit(&mut self, timeout: Duration) -> std::io::Result<bool> {
        match self.child.wait_timeout(timeout)? {
            Some(status) => {
                self.child_reaped = true;
                self.exit_observed = true;
                self.exit_status = Some(status);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn terminate_tree(&self) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            let process_group = -(self.child.id() as libc::pid_t);
            // SAFETY: the child starts as leader of its own process group and
            // remains unreaped until this signal succeeds or reports no group.
            // macOS reports EPERM when only the unsignalable zombie leader
            // remains; after exit observation that also means no live member
            // owned by this process remains to stop.
            if unsafe { libc::kill(process_group, libc::SIGKILL) } == -1 {
                let error = std::io::Error::last_os_error();
                let no_signalable_descendant =
                    self.exit_observed && error.raw_os_error() == Some(libc::EPERM);
                if error.raw_os_error() != Some(libc::ESRCH) && !no_signalable_descendant {
                    return Err(error);
                }
            }
        }
        #[cfg(windows)]
        self.job.terminate()?;
        Ok(())
    }

    fn finish_after_exit(&mut self) -> std::io::Result<ExitStatus> {
        self.terminate_tree()?;
        let status = match self.exit_status.take() {
            Some(status) => status,
            None => self.child.wait()?,
        };
        self.child_reaped = true;
        self.cleanup_complete = true;
        Ok(status)
    }

    fn stop(&mut self) -> std::io::Result<()> {
        if self.cleanup_complete {
            return Ok(());
        }
        self.terminate_tree()?;
        if !self.child_reaped {
            let _ = self.child.kill();
            self.child.wait()?;
            self.child_reaped = true;
        }
        self.cleanup_complete = true;
        Ok(())
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        // Explicit error paths call `stop` first. A failed attempt leaves the
        // state incomplete so this final attempt can retry before handles drop.
        let _ = self.stop();
    }
}

/// Configuration for one encrypted EJSON file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EjsonConfig {
    /// Path to the encrypted EJSON document.
    pub path: PathBuf,
}

impl Default for EjsonConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("secrets.ejson"),
        }
    }
}

impl TryFrom<&ProviderUrl> for EjsonConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "ejson" {
            return Err(provider_err(format!(
                "Invalid scheme '{}' for ejson provider",
                url.scheme()
            )));
        }
        if !url.username().is_empty()
            || url.password().is_some()
            || url.has_port()
            || url.has_query()
            || url.has_fragment()
        {
            return Err(provider_err(
                "ejson provider URIs take only an encrypted file path; user information, ports, query options, and fragments are not supported",
            ));
        }

        let path_str = url.path();
        #[cfg(windows)]
        let path_str = if path_str.as_bytes().first() == Some(&b'/')
            && path_str.as_bytes().get(2) == Some(&b':')
            && path_str
                .as_bytes()
                .get(1)
                .is_some_and(u8::is_ascii_alphabetic)
        {
            path_str[1..].to_string()
        } else {
            path_str
        };
        let path = if !path_str.is_empty() && path_str != "/" {
            match url.host() {
                Some(host) => PathBuf::from(format!("{}{}", host, path_str)),
                None => PathBuf::from(path_str),
            }
        } else if let Some(host) = url.host() {
            PathBuf::from(host)
        } else {
            PathBuf::from("secrets.ejson")
        };

        Ok(Self { path })
    }
}

/// Reads string values from one EJSON document.
pub struct EjsonProvider {
    config: EjsonConfig,
    credentials: ProviderCredentials,
    cli_binary_path: PathBuf,
    cli_timeout: Duration,
}

crate::register_provider! {
    struct: EjsonProvider,
    config: EjsonConfig,
    metadata: &super::catalog::EJSON,
}

impl EjsonProvider {
    pub fn new(config: EjsonConfig) -> Self {
        Self {
            config,
            credentials: ProviderCredentials::new(),
            cli_binary_path: PathBuf::from("ejson"),
            cli_timeout: DEFAULT_CLI_TIMEOUT,
        }
    }

    #[cfg(test)]
    fn with_cli_binary(mut self, path: PathBuf) -> Self {
        self.cli_binary_path = path;
        self
    }

    #[cfg(test)]
    fn with_cli_timeout(mut self, timeout: Duration) -> Self {
        self.cli_timeout = timeout;
        self
    }

    fn pointer_segment(value: &str) -> String {
        value.replace('~', "~0").replace('/', "~1")
    }

    fn validate_pointer(pointer: &str) -> Result<()> {
        if !pointer.is_empty() && !pointer.starts_with('/') {
            return Err(provider_err(format!(
                "invalid ejson item '{pointer}': expected an RFC 6901 JSON Pointer beginning with '/'"
            )));
        }

        let bytes = pointer.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'~' {
                let escape = bytes.get(index + 1).copied();
                if !matches!(escape, Some(b'0' | b'1')) {
                    return Err(provider_err(format!(
                        "invalid ejson item '{pointer}': JSON Pointer '~' escapes must be '~0' or '~1'"
                    )));
                }
                index += 2;
            } else {
                index += 1;
            }
        }
        Ok(())
    }

    fn pointer<'a>(&self, addr: Address<'a>) -> Result<Cow<'a, str>> {
        match self.resolve_coords(addr)? {
            Cow::Borrowed(native) => {
                Self::validate_pointer(&native.item)?;
                Ok(Cow::Borrowed(native.item.as_str()))
            }
            Cow::Owned(native) => {
                Self::validate_pointer(&native.item)?;
                Ok(Cow::Owned(native.item))
            }
        }
    }

    #[cfg(unix)]
    fn open_source(path: &Path) -> std::io::Result<File> {
        use std::os::unix::fs::OpenOptionsExt;

        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
    }

    #[cfg(not(unix))]
    fn open_source(path: &Path) -> std::io::Result<File> {
        OpenOptions::new().read(true).open(path)
    }

    #[cfg(unix)]
    fn is_symlink_open_error(error: &std::io::Error) -> bool {
        error.raw_os_error() == Some(libc::ELOOP)
    }

    #[cfg(not(unix))]
    fn is_symlink_open_error(_error: &std::io::Error) -> bool {
        false
    }

    /// Opens the configured source and copies its ciphertext into a private
    /// temporary file. The CLI receives only this immutable snapshot, so a
    /// replacement of the configured pathname cannot change the decrypted data.
    fn encrypted_snapshot(&self) -> Result<Option<EncryptedSnapshot>> {
        let source = match Self::open_source(&self.config.path) {
            Ok(source) => source,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) if Self::is_symlink_open_error(&error) => {
                return Err(provider_err(format!(
                    "ejson file '{}' is a symbolic link; symbolic links are not followed",
                    self.config.path.display()
                )));
            }
            Err(error) => {
                return Err(provider_err(format!(
                    "failed to open ejson file '{}': {error}",
                    self.config.path.display()
                )));
            }
        };
        let metadata = source.metadata().map_err(|error| {
            provider_err(format!(
                "failed to inspect opened ejson file '{}': {error}",
                self.config.path.display()
            ))
        })?;
        if !metadata.is_file() {
            return Err(provider_err(format!(
                "ejson path '{}' is not a regular file",
                self.config.path.display()
            )));
        }
        if metadata.len() > MAX_EJSON_BYTES {
            return Err(provider_err(format!(
                "ejson file '{}' is {} bytes; the maximum supported size is {} bytes",
                self.config.path.display(),
                metadata.len(),
                MAX_EJSON_BYTES
            )));
        }

        let mut snapshot = EncryptedSnapshot::new().map_err(|error| {
            provider_err(format!(
                "failed to create a temporary EJSON ciphertext snapshot: {error}"
            ))
        })?;
        let mut limited = source.take(MAX_EJSON_BYTES + 1);
        let copied = std::io::copy(&mut limited, snapshot.file_mut()).map_err(|error| {
            provider_err(format!(
                "failed to copy EJSON ciphertext into a temporary snapshot: {error}"
            ))
        })?;
        if copied as u64 > MAX_EJSON_BYTES {
            return Err(provider_err(format!(
                "ejson file '{}' exceeds the maximum supported size of {MAX_EJSON_BYTES} bytes",
                self.config.path.display()
            )));
        }
        snapshot.file_mut().flush().map_err(|error| {
            provider_err(format!(
                "failed to flush the temporary EJSON ciphertext snapshot: {error}"
            ))
        })?;
        snapshot.rewind().map_err(|error| {
            provider_err(format!(
                "failed to rewind the temporary EJSON ciphertext snapshot: {error}"
            ))
        })?;
        Ok(Some(snapshot))
    }

    fn private_key(&self) -> Result<Zeroizing<String>> {
        let value = self.credentials.get(PRIVATE_KEY).ok_or_else(|| {
            provider_err(
                "No EJSON private key configured. Add the `private_key` provider credential to this provider alias.",
            )
        })?;
        let value = super::require_utf8("ejson", value)?.trim();
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(provider_err(
                "Invalid EJSON `private_key` credential: expected exactly 64 hexadecimal characters.",
            ));
        }
        Ok(Zeroizing::new(value.to_string()))
    }

    fn stop_child(child: &mut ManagedChild) {
        let _ = child.stop();
    }

    /// Decrypts the file once. The official CLI currently emits the complete
    /// document; callers select only declared pointers from the parsed value.
    fn decrypt(&self) -> Result<Option<serde_json::Value>> {
        let Some(snapshot) = self.encrypted_snapshot()? else {
            return Ok(None);
        };
        let private_key = self.private_key()?;
        let deadline = Instant::now() + self.cli_timeout;

        let mut command = Command::new(&self.cli_binary_path);
        command
            .arg("decrypt")
            .arg("--key-from-stdin")
            .arg(snapshot.command_path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Child diagnostics are not trusted: a substituted executable sees
            // the private key on stdin and could echo it. Return a generic error.
            .stderr(Stdio::null());
        snapshot.configure_command(&mut command);
        #[cfg(unix)]
        command.process_group(0);
        #[cfg(windows)]
        command.creation_flags(CREATE_SUSPENDED);

        let spawn_result = command.spawn();
        let child = match spawn_result {
            Ok(child) => child,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(provider_err(
                    "The 'ejson' CLI is not installed. Install it through your package manager.",
                ));
            }
            Err(error) => {
                return Err(provider_err(format!(
                    "failed to start the EJSON CLI: {error}"
                )));
            }
        };
        let mut child = ManagedChild::new(child).map_err(|error| {
            provider_err(format!(
                "failed to secure the EJSON CLI process lifetime: {error}"
            ))
        })?;

        let Some(stdout) = child.child.stdout.take() else {
            Self::stop_child(&mut child);
            return Err(provider_err("failed to open stdout for the EJSON CLI"));
        };
        let (output_sender, output_receiver) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut plaintext = Vec::new();
            let result = stdout
                .take(MAX_EJSON_BYTES + 1)
                .read_to_end(&mut plaintext)
                .map(|_| plaintext);
            let _ = output_sender.send(result);
        });

        let Some(mut stdin) = child.child.stdin.take() else {
            Self::stop_child(&mut child);
            drop(output_receiver);
            return Err(provider_err("failed to open stdin for the EJSON CLI"));
        };
        let (input_sender, input_receiver) = mpsc::sync_channel(1);
        let key_terminator: &'static [u8] = if cfg!(windows) { b"\r\n" } else { b"\n" };
        std::thread::spawn(move || {
            let result = stdin
                .write_all(private_key.as_bytes())
                .and_then(|()| stdin.write_all(key_terminator));
            let _ = input_sender.send(result);
        });
        let remaining = deadline.saturating_duration_since(Instant::now());
        match input_receiver.recv_timeout(remaining) {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                Self::stop_child(&mut child);
                drop(output_receiver);
                return Err(provider_err(format!(
                    "failed to send the private key to the EJSON CLI: {error}"
                )));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                Self::stop_child(&mut child);
                drop(output_receiver);
                return Err(provider_err(format!(
                    "EJSON private-key delivery timed out after {} seconds",
                    self.cli_timeout.as_secs_f64()
                )));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Self::stop_child(&mut child);
                drop(output_receiver);
                return Err(provider_err(
                    "EJSON private-key writer stopped unexpectedly",
                ));
            }
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        match child.wait_for_exit(remaining) {
            Ok(true) => {}
            Ok(false) => {
                Self::stop_child(&mut child);
                drop(output_receiver);
                return Err(provider_err(format!(
                    "EJSON decryption timed out after {} seconds",
                    self.cli_timeout.as_secs_f64()
                )));
            }
            Err(error) => {
                Self::stop_child(&mut child);
                drop(output_receiver);
                return Err(provider_err(format!(
                    "failed to wait for the EJSON CLI: {error}"
                )));
            }
        }
        let status = child.finish_after_exit().map_err(|error| {
            provider_err(format!(
                "failed to clean up the EJSON CLI process tree: {error}"
            ))
        })?;

        let remaining = deadline.saturating_duration_since(Instant::now());
        let plaintext = match output_receiver.recv_timeout(remaining) {
            Ok(Ok(plaintext)) => plaintext,
            Ok(Err(error)) => {
                return Err(provider_err(format!(
                    "failed to read output from the EJSON CLI: {error}"
                )));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                Self::stop_child(&mut child);
                return Err(provider_err(format!(
                    "EJSON output did not close within {} seconds",
                    self.cli_timeout.as_secs_f64()
                )));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(provider_err("EJSON output reader stopped unexpectedly"));
            }
        };
        if plaintext.len() as u64 > MAX_EJSON_BYTES {
            return Err(provider_err(format!(
                "EJSON decrypted output exceeds the maximum supported size of {MAX_EJSON_BYTES} bytes"
            )));
        }
        if !status.success() {
            return Err(provider_err(format!(
                "EJSON decryption failed ({status}). Check the encrypted file, EJSON CLI compatibility, and `private_key` credential."
            )));
        }

        serde_json::from_slice(&plaintext)
            .map(Some)
            .map_err(|error| {
                provider_err(format!("failed to parse JSON emitted by EJSON: {error}"))
            })
    }

    fn select(document: &serde_json::Value, pointer: &str) -> Result<Option<SecretBytes>> {
        match document.pointer(pointer) {
            None => Ok(None),
            Some(serde_json::Value::String(value)) => {
                Ok(Some(SecretBytes::new(value.clone().into())))
            }
            Some(_) => Err(provider_err(format!(
                "ejson item '{pointer}' does not select a string value"
            ))),
        }
    }
}

impl Provider for EjsonProvider {
    fn convention_address(&self, project: &str, profile: &str, key: &str) -> Result<NativeAddress> {
        Ok(NativeAddress {
            item: format!(
                "/{}/{}/{}",
                Self::pointer_segment(project),
                Self::pointer_segment(profile),
                Self::pointer_segment(key)
            ),
            ..Default::default()
        })
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        let path = self.config.path.display().to_string();
        format!(
            "ejson:{}",
            percent_encode(path.as_bytes(), EJSON_PATH_ENCODE_SET)
        )
    }

    fn with_base_dir(&mut self, base_dir: &Path) {
        if self.config.path.is_relative() {
            self.config.path = base_dir.join(&self.config.path);
        }
    }

    fn with_credentials(&mut self, credentials: ProviderCredentials) {
        self.credentials = credentials;
    }

    fn physical_store_path(&self) -> Option<&Path> {
        Some(&self.config.path)
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretBytes>> {
        let pointer = self.pointer(addr)?;
        let Some(document) = self.decrypt()? else {
            return Ok(None);
        };
        Self::select(&document, &pointer)
    }

    fn get_many(&self, requests: &[(&str, Address<'_>)]) -> Result<HashMap<String, SecretBytes>> {
        let pointers = requests
            .iter()
            .map(|(name, addr)| Ok((name.to_string(), self.pointer(*addr)?.into_owned())))
            .collect::<Result<Vec<_>>>()?;
        if pointers.is_empty() {
            return Ok(HashMap::new());
        }
        let Some(document) = self.decrypt()? else {
            return Ok(HashMap::new());
        };

        let mut values = HashMap::new();
        for (name, pointer) in pointers {
            if let Some(value) = Self::select(&document, &pointer)? {
                values.insert(name, value);
            }
        }
        Ok(values)
    }

    fn check_writable(&self, _addr: Address<'_>) -> Result<()> {
        Err(provider_err(
            "the ejson provider is read-only; edit and encrypt the EJSON file through its owning workflow",
        ))
    }

    fn set(&self, addr: Address<'_>, _value: &SecretBytes) -> Result<()> {
        self.check_writable(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use url::Url;

    const TEST_PRIVATE_KEY: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";

    fn config_from(uri: &str) -> EjsonConfig {
        let url = ProviderUrl::new(Url::parse(uri).unwrap());
        (&url).try_into().unwrap()
    }

    #[test]
    fn registration_advertises_private_key_credential() {
        assert_eq!(
            crate::provider::credential_names_for_spec("ejson:secrets.ejson"),
            &[PRIVATE_KEY]
        );
    }

    #[test]
    fn parses_relative_absolute_and_default_paths() {
        assert_eq!(
            config_from("ejson:config/secrets.ejson").path,
            Path::new("config/secrets.ejson")
        );
        assert_eq!(
            config_from("ejson://config/secrets.ejson").path,
            Path::new("config/secrets.ejson")
        );
        assert_eq!(
            config_from("ejson:///var/run/secrets.ejson").path,
            Path::new("/var/run/secrets.ejson")
        );
        assert_eq!(config_from("ejson:").path, Path::new("secrets.ejson"));
    }

    #[test]
    fn rejects_non_path_uri_components() {
        for spec in [
            "ejson:config/secrets.ejson?private_key=nope",
            "ejson:secrets#prod.ejson",
            "ejson:dir:123/file.ejson",
        ] {
            let Err(error) = Box::<dyn Provider>::try_from(spec) else {
                panic!("{spec} unexpectedly built an EJSON provider");
            };
            assert!(
                error.to_string().contains("only an encrypted file path"),
                "{spec}: {error}"
            );
        }
    }

    #[test]
    fn convention_address_uses_escaped_json_pointer() {
        let provider = EjsonProvider::new(EjsonConfig::default());
        let address = provider
            .convention_address("my/app", "prod~blue", "API/TOKEN")
            .unwrap();
        assert_eq!(address.item, "/my~1app/prod~0blue/API~1TOKEN");
    }

    #[test]
    fn uri_round_trips_structural_path_characters() {
        for path in [
            "config/secrets #1?.ejson",
            "config/100% secrets.ejson",
            "config/name@host.ejson",
            r"C:\\Users\\app\\secrets.ejson",
        ] {
            let provider = EjsonProvider::new(EjsonConfig {
                path: PathBuf::from(path),
            });
            let reparsed = Box::<dyn Provider>::try_from(provider.uri().as_str()).unwrap();
            assert_eq!(reparsed.physical_store_path(), Some(Path::new(path)));
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_paths_round_trip_through_provider_factory() {
        for spec in [
            r"ejson://C:\Users\app\secrets.ejson",
            "ejson:///C:/Users/app/secrets.ejson",
        ] {
            let provider = Box::<dyn Provider>::try_from(spec).unwrap();
            assert_eq!(provider.name(), "ejson");
            assert_eq!(
                provider.physical_store_path(),
                Some(Path::new(r"C:\Users\app\secrets.ejson"))
            );
            let reparsed = Box::<dyn Provider>::try_from(provider.uri().as_str()).unwrap();
            assert_eq!(
                reparsed.physical_store_path(),
                provider.physical_store_path()
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_decrypts_through_a_named_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let encrypted = directory.path().join("secrets.ejson");
        fs::write(&encrypted, "{\"_public_key\":\"placeholder\"}").unwrap();
        let cli = directory.path().join("ejson.cmd");
        fs::write(
            &cli,
            format!(
                "@echo off\r\nset /p private_key=\r\nif not \"%private_key%\" == \"{TEST_PRIVATE_KEY}\" exit /b 3\r\nif not exist \"%~3\" exit /b 4\r\necho {{\"TOKEN\":\"value\"}}\r\n"
            ),
        )
        .unwrap();
        let mut provider = EjsonProvider::new(EjsonConfig { path: encrypted })
            .with_cli_binary(cli)
            .with_cli_timeout(Duration::from_secs(5));
        provider.credentials.insert(
            PRIVATE_KEY.to_string(),
            SecretBytes::new(TEST_PRIVATE_KEY.into()),
        );

        let value = provider
            .get(Address::Native(&NativeAddress {
                item: "/TOKEN".into(),
                ..Default::default()
            }))
            .unwrap()
            .unwrap();
        assert_eq!(value.expose_secret(), b"value");
    }

    #[cfg(windows)]
    #[test]
    fn windows_suspended_job_stops_a_descendant_holding_stdout() {
        use std::os::windows::process::CommandExt as _;
        use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
        };

        let directory = tempfile::tempdir().unwrap();
        let descendant_pid = directory.path().join("descendant-pid");
        let pid_path = descendant_pid.display().to_string().replace('\'', "''");
        let script = format!(
            "$child = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoLogo','-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 60') -NoNewWindow -PassThru; $child.Id | Set-Content -NoNewline -Encoding Ascii -LiteralPath '{pid_path}'; Wait-Process -Id $child.Id"
        );
        let mut command = Command::new("powershell.exe");
        command
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &script,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .creation_flags(CREATE_SUSPENDED);
        let child = command.spawn().unwrap();
        let mut child = ManagedChild::new(child).unwrap();

        let deadline = Instant::now() + Duration::from_secs(10);
        while !descendant_pid.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        if !descendant_pid.exists() {
            let _ = child.stop();
            panic!("suspended Windows helper did not record its descendant");
        }
        let pid: u32 = fs::read_to_string(descendant_pid)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        child.stop().unwrap();

        // SAFETY: this opens only the test descendant for synchronization. The
        // returned handle is closed below and grants no mutation rights.
        let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
        if !handle.is_null() {
            // SAFETY: `handle` is live for this bounded wait.
            let wait = unsafe { WaitForSingleObject(handle, 2_000) };
            // SAFETY: this test owns the live process handle.
            let _ = unsafe { CloseHandle(handle) };
            assert_eq!(wait, WAIT_OBJECT_0, "EJSON descendant {pid} survived");
        }
    }

    #[test]
    fn validates_json_pointer_escapes() {
        for valid in ["", "/API_KEY", "/nested/key", "/a~0b/c~1d"] {
            EjsonProvider::validate_pointer(valid).unwrap();
        }
        for invalid in ["API_KEY", "/bad~", "/bad~2escape"] {
            assert!(
                EjsonProvider::validate_pointer(invalid).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn rebases_relative_file_path() {
        let mut provider = EjsonProvider::new(EjsonConfig {
            path: PathBuf::from("config/secrets.ejson"),
        });
        provider.with_base_dir(Path::new("/project"));
        assert_eq!(
            provider.config.path,
            Path::new("/project/config/secrets.ejson")
        );
    }

    #[test]
    fn missing_file_is_an_absent_value_without_key_access() {
        let directory = tempfile::tempdir().unwrap();
        let provider = EjsonProvider::new(EjsonConfig {
            path: directory.path().join("missing.ejson"),
        });
        assert!(
            provider
                .get(Address::convention("app", "default", "MISSING"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn read_only_error_is_consistent() {
        let provider = EjsonProvider::new(EjsonConfig::default());
        let addr = Address::convention("app", "default", "TOKEN");
        let preflight = provider.check_writable(addr).unwrap_err().to_string();
        let write = provider
            .set(addr, &SecretBytes::new("value".into()))
            .unwrap_err()
            .to_string();
        assert_eq!(preflight, write);
        assert!(write.contains("read-only"));
    }

    #[test]
    fn native_address_rejects_unsupported_coordinates() {
        let provider = EjsonProvider::new(EjsonConfig::default());
        let address = NativeAddress {
            item: "/TOKEN".into(),
            field: Some("value".into()),
            ..Default::default()
        };
        let error = provider.get(Address::Native(&address)).unwrap_err();
        assert!(error.to_string().contains("`field`"));
    }

    #[test]
    fn selects_only_string_values() {
        let document = serde_json::json!({
            "string": "value",
            "number": 42,
        });
        assert_eq!(
            EjsonProvider::select(&document, "/string")
                .unwrap()
                .unwrap()
                .expose_secret(),
            b"value"
        );
        assert!(
            EjsonProvider::select(&document, "/missing")
                .unwrap()
                .is_none()
        );
        assert!(EjsonProvider::select(&document, "/number").is_err());
        assert!(EjsonProvider::select(&document, "").is_err());
    }

    #[cfg(unix)]
    fn fake_cli(directory: &Path, output: &str, count_file: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let script = directory.join("ejson");
        let escaped_output = output.replace('\\', "\\\\").replace('\'', "'\\''");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\nset -eu\n[ \"$1\" = decrypt ]\n[ \"$2\" = --key-from-stdin ]\n[ -f \"$3\" ]\nkey=$(cat)\n[ \"$key\" = '{}' ]\nprintf x >> '{}'\nprintf '%s' '{}'\n",
                TEST_PRIVATE_KEY,
                count_file.display(),
                escaped_output,
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        script
    }

    #[cfg(unix)]
    #[test]
    fn decrypts_when_parent_stdio_is_closed() {
        const CHILD_ENV: &str = "SECRETSPEC_EJSON_CLOSED_STDIO_CHILD";
        const TEST_NAME: &str = "provider::ejson::tests::decrypts_when_parent_stdio_is_closed";

        if std::env::var_os(CHILD_ENV).is_some() {
            let directory = tempfile::tempdir().unwrap();
            let encrypted = directory.path().join("secrets.ejson");
            let count = directory.path().join("count");
            fs::write(&encrypted, "{\"_public_key\":\"placeholder\"}").unwrap();
            let cli = fake_cli(directory.path(), r#"{"TOKEN":"value"}"#, &count);
            let mut provider =
                EjsonProvider::new(EjsonConfig { path: encrypted }).with_cli_binary(cli);
            provider.credentials.insert(
                PRIVATE_KEY.to_string(),
                SecretBytes::new(TEST_PRIVATE_KEY.into()),
            );
            assert_eq!(
                provider
                    .get(Address::Native(&NativeAddress {
                        item: "/TOKEN".into(),
                        ..Default::default()
                    }))
                    .unwrap()
                    .unwrap()
                    .expose_secret(),
                b"value"
            );
            return;
        }

        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .arg("--exact")
            .arg(TEST_NAME)
            .env(CHILD_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: the closure runs in the child after fork and uses only the
        // async-signal-safe close operation. The parent descriptors are intact.
        unsafe {
            command.pre_exec(|| {
                libc::close(libc::STDIN_FILENO);
                libc::close(libc::STDOUT_FILENO);
                libc::close(libc::STDERR_FILENO);
                Ok(())
            });
        }
        assert!(command.status().unwrap().success());
    }

    #[cfg(unix)]
    #[test]
    fn decrypts_with_a_low_descriptor_limit() {
        const CHILD_ENV: &str = "SECRETSPEC_EJSON_LOW_NOFILE_CHILD";
        const TEST_NAME: &str = "provider::ejson::tests::decrypts_with_a_low_descriptor_limit";

        if std::env::var_os(CHILD_ENV).is_some() {
            let directory = tempfile::tempdir().unwrap();
            let encrypted = directory.path().join("secrets.ejson");
            let count = directory.path().join("count");
            fs::write(&encrypted, "{\"_public_key\":\"placeholder\"}").unwrap();
            let cli = fake_cli(directory.path(), r#"{"TOKEN":"value"}"#, &count);
            let mut provider =
                EjsonProvider::new(EjsonConfig { path: encrypted }).with_cli_binary(cli);
            provider.credentials.insert(
                PRIVATE_KEY.to_string(),
                SecretBytes::new(TEST_PRIVATE_KEY.into()),
            );
            assert_eq!(
                provider
                    .get(Address::Native(&NativeAddress {
                        item: "/TOKEN".into(),
                        ..Default::default()
                    }))
                    .unwrap()
                    .unwrap()
                    .expose_secret(),
                b"value"
            );
            return;
        }

        let status = Command::new("/bin/sh")
            .arg("-c")
            .arg("ulimit -n 64; exec \"$1\" --exact \"$2\" --nocapture")
            .arg("sh")
            .arg(std::env::current_exe().unwrap())
            .arg(TEST_NAME)
            .env(CHILD_ENV, "1")
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[cfg(unix)]
    #[test]
    fn batch_decrypts_once_and_selects_requested_pointers() {
        let directory = tempfile::tempdir().unwrap();
        let encrypted = directory.path().join("secrets.ejson");
        fs::write(&encrypted, "{\"_public_key\":\"placeholder\"}").unwrap();
        let count = directory.path().join("count");
        let cli = fake_cli(
            directory.path(),
            r#"{"app":{"production":{"API_KEY":"one","OTHER":"two"}}}"#,
            &count,
        );
        let mut provider = EjsonProvider::new(EjsonConfig { path: encrypted }).with_cli_binary(cli);
        provider.credentials.insert(
            PRIVATE_KEY.to_string(),
            SecretBytes::new(TEST_PRIVATE_KEY.into()),
        );

        let results = provider
            .get_many(&[
                (
                    "API_KEY",
                    Address::convention("app", "production", "API_KEY"),
                ),
                ("OTHER", Address::convention("app", "production", "OTHER")),
                (
                    "MISSING",
                    Address::convention("app", "production", "MISSING"),
                ),
            ])
            .unwrap();

        assert_eq!(results.len(), 2);
        assert_eq!(results["API_KEY"].expose_secret(), b"one");
        assert_eq!(results["OTHER"].expose_secret(), b"two");
        assert_eq!(fs::read_to_string(count).unwrap(), "x");
    }

    #[test]
    fn empty_batch_needs_no_file_or_private_key() {
        let provider = EjsonProvider::new(EjsonConfig {
            path: PathBuf::from("does-not-exist.ejson"),
        });
        assert!(provider.get_many(&[]).unwrap().is_empty());
    }

    #[test]
    fn private_key_requires_exact_hex_and_trims_outer_whitespace() {
        let mut provider = EjsonProvider::new(EjsonConfig::default());
        for invalid in [
            "1".repeat(63),
            "1".repeat(65),
            "g".repeat(64),
            "１".repeat(64),
        ] {
            provider
                .credentials
                .insert(PRIVATE_KEY.to_string(), SecretBytes::new(invalid.into()));
            assert!(provider.private_key().is_err());
        }

        provider.credentials.insert(
            PRIVATE_KEY.to_string(),
            SecretBytes::new(format!("  {TEST_PRIVATE_KEY}\n").into()),
        );
        assert_eq!(provider.private_key().unwrap().as_str(), TEST_PRIVATE_KEY);
    }

    #[cfg(unix)]
    #[test]
    fn missing_private_key_fails_before_cli_receives_input() {
        let directory = tempfile::tempdir().unwrap();
        let encrypted = directory.path().join("secrets.ejson");
        fs::write(&encrypted, "{\"_public_key\":\"placeholder\"}").unwrap();
        let count = directory.path().join("count");
        let cli = fake_cli(directory.path(), r#"{"TOKEN":"value"}"#, &count);
        let provider = EjsonProvider::new(EjsonConfig { path: encrypted }).with_cli_binary(cli);

        let error = provider
            .get(Address::Native(&NativeAddress {
                item: "/TOKEN".into(),
                ..Default::default()
            }))
            .unwrap_err();
        assert!(error.to_string().contains("private_key"));
        assert!(!count.exists());
    }

    #[cfg(unix)]
    #[test]
    fn invalid_or_oversized_private_key_fails_before_cli_starts() {
        let directory = tempfile::tempdir().unwrap();
        let encrypted = directory.path().join("secrets.ejson");
        fs::write(&encrypted, "{\"_public_key\":\"placeholder\"}").unwrap();
        let count = directory.path().join("count");
        let cli = fake_cli(directory.path(), r#"{"TOKEN":"value"}"#, &count);
        let mut provider = EjsonProvider::new(EjsonConfig { path: encrypted }).with_cli_binary(cli);
        provider.credentials.insert(
            PRIVATE_KEY.to_string(),
            SecretBytes::new("x".repeat(1024 * 1024).into()),
        );

        let error = provider
            .get(Address::Native(&NativeAddress {
                item: "/TOKEN".into(),
                ..Default::default()
            }))
            .unwrap_err()
            .to_string();
        assert!(error.contains("64 hexadecimal"));
        assert!(!count.exists());
    }

    #[cfg(unix)]
    #[test]
    fn fifo_source_is_rejected_without_blocking() {
        let directory = tempfile::tempdir().unwrap();
        let fifo = directory.path().join("secrets.ejson");
        let status = Command::new("mkfifo").arg(&fifo).status().unwrap();
        assert!(status.success());
        let provider = EjsonProvider::new(EjsonConfig { path: fifo });

        let error = provider
            .get(Address::Native(&NativeAddress {
                item: "/TOKEN".into(),
                ..Default::default()
            }))
            .unwrap_err()
            .to_string();
        assert!(error.contains("not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn cli_failure_is_generic_and_does_not_expose_key() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let encrypted = directory.path().join("secrets.ejson");
        fs::write(&encrypted, "{\"_public_key\":\"placeholder\"}").unwrap();
        let cli = directory.path().join("ejson");
        fs::write(&cli, "#!/bin/sh\nkey=$(cat)\necho \"$key\" >&2\nexit 1\n").unwrap();
        fs::set_permissions(&cli, fs::Permissions::from_mode(0o700)).unwrap();
        let mut provider = EjsonProvider::new(EjsonConfig { path: encrypted }).with_cli_binary(cli);
        provider.credentials.insert(
            PRIVATE_KEY.to_string(),
            SecretBytes::new(TEST_PRIVATE_KEY.into()),
        );

        let error = provider
            .get(Address::Native(&NativeAddress {
                item: "/TOKEN".into(),
                ..Default::default()
            }))
            .unwrap_err()
            .to_string();
        assert!(error.contains("EJSON CLI compatibility"));
        assert!(!error.contains(TEST_PRIVATE_KEY));
        assert!(!error.contains("unknown flag"));
    }

    #[cfg(unix)]
    #[test]
    fn hung_cli_that_never_reads_stdin_is_stopped_at_timeout() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::Instant;

        let directory = tempfile::tempdir().unwrap();
        let encrypted = directory.path().join("secrets.ejson");
        fs::write(&encrypted, "{\"_public_key\":\"placeholder\"}").unwrap();
        let cli = directory.path().join("ejson");
        fs::write(&cli, "#!/bin/sh\nsleep 60\n").unwrap();
        fs::set_permissions(&cli, fs::Permissions::from_mode(0o700)).unwrap();
        let mut provider = EjsonProvider::new(EjsonConfig { path: encrypted })
            .with_cli_binary(cli)
            .with_cli_timeout(Duration::from_millis(500));
        provider.credentials.insert(
            PRIVATE_KEY.to_string(),
            SecretBytes::new(TEST_PRIVATE_KEY.into()),
        );

        let started = Instant::now();
        let error = provider
            .get(Address::Native(&NativeAddress {
                item: "/TOKEN".into(),
                ..Default::default()
            }))
            .unwrap_err()
            .to_string();
        assert!(error.contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[cfg(unix)]
    #[test]
    fn hung_cli_and_descendants_are_stopped_at_timeout() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::Instant;

        let directory = tempfile::tempdir().unwrap();
        let encrypted = directory.path().join("secrets.ejson");
        fs::write(&encrypted, "{\"_public_key\":\"placeholder\"}").unwrap();
        let cli = directory.path().join("ejson");
        let descendant_pid = directory.path().join("descendant-pid");
        fs::write(
            &cli,
            format!(
                "#!/bin/sh\nsleep 60 &\necho $! > '{}'\ncat >/dev/null\nwait\n",
                descendant_pid.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&cli, fs::Permissions::from_mode(0o700)).unwrap();
        let mut provider = EjsonProvider::new(EjsonConfig { path: encrypted })
            .with_cli_binary(cli)
            .with_cli_timeout(Duration::from_secs(2));
        provider.credentials.insert(
            PRIVATE_KEY.to_string(),
            SecretBytes::new(TEST_PRIVATE_KEY.into()),
        );

        let started = Instant::now();
        let error = provider
            .get(Address::Native(&NativeAddress {
                item: "/TOKEN".into(),
                ..Default::default()
            }))
            .unwrap_err()
            .to_string();
        assert!(error.contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(4));

        let pid: libc::pid_t = fs::read_to_string(&descendant_pid)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            // SAFETY: signal 0 only probes a PID recorded by the test child.
            if unsafe { libc::kill(pid, 0) } == -1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        // SAFETY: same non-mutating existence probe as above.
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
    }

    #[cfg(unix)]
    #[test]
    fn exited_cli_stops_descendant_holding_stdout_without_waiting_for_deadline() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::Instant;

        let directory = tempfile::tempdir().unwrap();
        let encrypted = directory.path().join("secrets.ejson");
        fs::write(&encrypted, "{\"_public_key\":\"placeholder\"}").unwrap();
        let cli = directory.path().join("ejson");
        let descendant_pid = directory.path().join("descendant-pid");
        fs::write(
            &cli,
            format!(
                "#!/bin/sh\ncat >/dev/null\nsleep 60 &\necho $! > '{}'\nexit 0\n",
                descendant_pid.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&cli, fs::Permissions::from_mode(0o700)).unwrap();
        let mut provider = EjsonProvider::new(EjsonConfig { path: encrypted })
            .with_cli_binary(cli)
            .with_cli_timeout(Duration::from_secs(5));
        provider.credentials.insert(
            PRIVATE_KEY.to_string(),
            SecretBytes::new(TEST_PRIVATE_KEY.into()),
        );

        let started = Instant::now();
        let error = provider
            .get(Address::Native(&NativeAddress {
                item: "/TOKEN".into(),
                ..Default::default()
            }))
            .unwrap_err()
            .to_string();
        assert!(error.contains("failed to parse JSON"));
        assert!(started.elapsed() < Duration::from_secs(2));

        let pid: libc::pid_t = fs::read_to_string(&descendant_pid)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            // SAFETY: signal 0 only probes a PID recorded by the test child.
            if unsafe { libc::kill(pid, 0) } == -1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        // SAFETY: same non-mutating existence probe as above.
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_oversized_encrypted_files_before_key_access() {
        let directory = tempfile::tempdir().unwrap();
        let encrypted = directory.path().join("oversized.ejson");
        File::create(&encrypted)
            .unwrap()
            .set_len(MAX_EJSON_BYTES + 1)
            .unwrap();
        let provider = EjsonProvider::new(EjsonConfig { path: encrypted });

        let error = provider
            .get(Address::Native(&NativeAddress {
                item: "/TOKEN".into(),
                ..Default::default()
            }))
            .unwrap_err()
            .to_string();
        assert!(error.contains("maximum supported size"));
        assert!(!error.contains("private_key"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_oversized_decrypted_output() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let encrypted = directory.path().join("secrets.ejson");
        fs::write(&encrypted, "{\"_public_key\":\"placeholder\"}").unwrap();
        let cli = directory.path().join("ejson");
        fs::write(
            &cli,
            "#!/bin/sh\ncat >/dev/null\nhead -c 16777217 /dev/zero\n",
        )
        .unwrap();
        fs::set_permissions(&cli, fs::Permissions::from_mode(0o700)).unwrap();
        let mut provider = EjsonProvider::new(EjsonConfig { path: encrypted }).with_cli_binary(cli);
        provider.credentials.insert(
            PRIVATE_KEY.to_string(),
            SecretBytes::new(TEST_PRIVATE_KEY.into()),
        );

        let error = provider
            .get(Address::Native(&NativeAddress {
                item: "/TOKEN".into(),
                ..Default::default()
            }))
            .unwrap_err()
            .to_string();
        assert!(error.contains("decrypted output exceeds"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_malformed_successful_cli_output() {
        let directory = tempfile::tempdir().unwrap();
        let encrypted = directory.path().join("secrets.ejson");
        fs::write(&encrypted, "{\"_public_key\":\"placeholder\"}").unwrap();
        let count = directory.path().join("count");
        let cli = fake_cli(directory.path(), "not-json", &count);
        let mut provider = EjsonProvider::new(EjsonConfig { path: encrypted }).with_cli_binary(cli);
        provider.credentials.insert(
            PRIVATE_KEY.to_string(),
            SecretBytes::new(TEST_PRIVATE_KEY.into()),
        );

        let error = provider
            .get(Address::Native(&NativeAddress {
                item: "/TOKEN".into(),
                ..Default::default()
            }))
            .unwrap_err()
            .to_string();
        assert!(error.contains("failed to parse JSON emitted by EJSON"));
    }

    #[cfg(unix)]
    #[test]
    fn malformed_output_stops_descendants_that_closed_stdout() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let encrypted = directory.path().join("secrets.ejson");
        fs::write(&encrypted, "{\"_public_key\":\"placeholder\"}").unwrap();
        let descendant_pid = directory.path().join("descendant-pid");
        let cli = directory.path().join("ejson");
        fs::write(
            &cli,
            format!(
                "#!/bin/sh\nsleep 60 </dev/null >/dev/null 2>&1 &\necho $! > '{}'\ncat >/dev/null\nprintf not-json\n",
                descendant_pid.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&cli, fs::Permissions::from_mode(0o700)).unwrap();
        let mut provider = EjsonProvider::new(EjsonConfig { path: encrypted }).with_cli_binary(cli);
        provider.credentials.insert(
            PRIVATE_KEY.to_string(),
            SecretBytes::new(TEST_PRIVATE_KEY.into()),
        );

        let error = provider
            .get(Address::Native(&NativeAddress {
                item: "/TOKEN".into(),
                ..Default::default()
            }))
            .unwrap_err()
            .to_string();
        assert!(error.contains("failed to parse JSON"));

        let pid: libc::pid_t = fs::read_to_string(descendant_pid)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            // SAFETY: signal 0 only probes a PID recorded by the test child.
            if unsafe { libc::kill(pid, 0) } == -1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        // SAFETY: same non-mutating existence probe as above.
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
    }

    #[cfg(unix)]
    #[test]
    fn configured_file_replacement_does_not_change_open_snapshot() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{Duration, Instant};

        let directory = tempfile::tempdir().unwrap();
        let encrypted = directory.path().join("secrets.ejson");
        fs::write(&encrypted, r#"{"TOKEN":"original"}"#).unwrap();
        let ready = directory.path().join("ready");
        let proceed = directory.path().join("proceed");
        let cli = directory.path().join("ejson");
        fs::write(
            &cli,
            format!(
                "#!/bin/sh\nset -eu\ncat >/dev/null\ntouch '{}'\nwhile [ ! -f '{}' ]; do sleep 0.01; done\ncat \"$3\"\n",
                ready.display(),
                proceed.display(),
            ),
        )
        .unwrap();
        fs::set_permissions(&cli, fs::Permissions::from_mode(0o700)).unwrap();
        let mut provider = EjsonProvider::new(EjsonConfig {
            path: encrypted.clone(),
        })
        .with_cli_binary(cli);
        provider.credentials.insert(
            PRIVATE_KEY.to_string(),
            SecretBytes::new(TEST_PRIVATE_KEY.into()),
        );

        let reader = std::thread::spawn(move || {
            provider.get(Address::Native(&NativeAddress {
                item: "/TOKEN".into(),
                ..Default::default()
            }))
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(ready.exists(), "fake EJSON CLI did not start");
        fs::write(&encrypted, r#"{"TOKEN":"replacement"}"#).unwrap();
        fs::write(&proceed, "go").unwrap();

        let value = reader.join().unwrap().unwrap().unwrap();
        assert_eq!(value.expose_secret(), b"original");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symbolic_link_files() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target.ejson");
        let link = directory.path().join("link.ejson");
        fs::write(&target, "{}").unwrap();
        symlink(&target, &link).unwrap();
        let provider = EjsonProvider::new(EjsonConfig { path: link });

        let error = provider
            .get(Address::Native(&NativeAddress {
                item: "/TOKEN".into(),
                ..Default::default()
            }))
            .unwrap_err();
        assert!(error.to_string().contains("symbolic link"));
    }
}
