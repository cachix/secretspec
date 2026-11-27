//! Joined subprocess execution for cancellable reads and generators (0.22+).
use crate::request::RequestContext;
use crate::{Result, SecretSpecError};
use secrecy::zeroize::Zeroizing;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
#[cfg(windows)]
use std::os::windows::{io::AsRawHandle, process::CommandExt};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
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

#[cfg(unix)]
fn nonblocking(pipe: &impl std::os::fd::AsRawFd) -> std::io::Result<()> {
    let fd = pipe.as_raw_fd();
    // SAFETY: this modifies flags of the pipe owned by the caller, not its lifetime.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
#[cfg(not(unix))]
fn nonblocking<T>(_: &T) -> std::io::Result<()> {
    Ok(())
}

fn read_pipe(
    mut pipe: impl Read,
    limit: usize,
    stop: &AtomicBool,
) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    let mut chunk = Zeroizing::new([0u8; 8192]);
    loop {
        if stop.load(Ordering::Acquire) {
            return Ok(bytes);
        }
        match pipe.read(&mut chunk[..]) {
            Ok(0) => return Ok(bytes),
            Ok(count) => {
                if count > limit.saturating_sub(bytes.len()) {
                    return Err(std::io::Error::other("command output limit exceeded"));
                }
                bytes.extend_from_slice(&chunk[..count]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5))
            }
            Err(error) => return Err(error),
        }
    }
}

#[derive(Debug)]
pub(crate) struct Output {
    pub status: ExitStatus,
    pub stdout: crate::SecretBytes,
    pub stderr: crate::SecretBytes,
}

impl Output {
    pub(crate) fn into_std(self) -> std::process::Output {
        std::process::Output {
            status: self.status,
            stdout: self.stdout.to_vec(),
            stderr: self.stderr.to_vec(),
        }
    }
}

/// Keep legacy CLI behavior while opting request-owned commands into supervision.
pub(crate) trait CommandOutput {
    fn output_for(&mut self, request: Option<&RequestContext>) -> Result<std::process::Output>;
}

impl CommandOutput for Command {
    fn output_for(&mut self, request: Option<&RequestContext>) -> Result<std::process::Output> {
        match request {
            Some(request) => {
                output(self, None, usize::MAX, None, Some(request), true).map(Output::into_std)
            }
            None => Ok(self.output()?),
        }
    }
}

/// Run one child in an owned process group/Job. Request group termination and
/// wait for the direct child and pipe workers on success, cancellation, timeout
/// and panic. Descendant exit can complete after the call returns. Diagnostics
/// omit argv, stdin, stdout and stderr, which can all carry secret values.
/// Stderr is captured only for consumers that need CLI diagnostics. Temporary
/// output buffers are wiped on error as well as when handing off protected bytes.
pub(crate) fn output(
    command: &mut Command,
    input: Option<Zeroizing<Vec<u8>>>,
    limit: usize,
    timeout: Option<Duration>,
    request: Option<&RequestContext>,
    capture_stderr: bool,
) -> Result<Output> {
    let checkpoint = || request.map_or(Ok(()), RequestContext::checkpoint);
    checkpoint()?;
    command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(if capture_stderr {
            Stdio::piped()
        } else {
            Stdio::null()
        });
    #[cfg(unix)]
    command.process_group(0);
    #[cfg(windows)]
    command.creation_flags(CREATE_SUSPENDED);
    checkpoint()?;
    let child = command.spawn()?;
    let mut child = ManagedChild::new(child).inspect_err(|error| {
        if let SecretSpecError::CleanupFailed { phase, .. } = error
            && let Some(request) = request
        {
            request.cleanup_failed(phase);
        }
    })?;
    let deadline = timeout.map(|timeout| Instant::now() + timeout);
    let timed_out = || deadline.is_some_and(|deadline| Instant::now() >= deadline);
    let stop = AtomicBool::new(false);
    let failed = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let stop = &stop;
        let failed = &failed;
        let mut writer = None;
        let mut reader = None;
        let mut error_reader = None;
        let supervision_result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
                let stdout = child
                    .child
                    .stdout
                    .take()
                    .ok_or_else(|| std::io::Error::other("child stdout unavailable"))?;
                nonblocking(&stdout)?;
                if let Some(stderr) = child.child.stderr.take() {
                    nonblocking(&stderr)?;
                    error_reader = Some(scope.spawn(move || {
                        let result = read_pipe(stderr, limit, stop);
                        if result.is_err() {
                            failed.store(true, Ordering::Release);
                        }
                        result
                    }));
                }
                if let Some(bytes) = input {
                    let mut stdin = child
                        .child
                        .stdin
                        .take()
                        .ok_or_else(|| std::io::Error::other("child stdin unavailable"))?;
                    nonblocking(&stdin)?;
                    writer = Some(scope.spawn(move || {
                        let result = (|| {
                            let mut offset = 0;
                            while offset < bytes.len() && !stop.load(Ordering::Acquire) {
                                match stdin.write(&bytes[offset..]) {
                                    Ok(0) => {
                                        return Err(std::io::Error::other("child stdin closed"));
                                    }
                                    Ok(count) => offset += count,
                                    Err(error)
                                        if error.kind() == std::io::ErrorKind::Interrupted =>
                                    {
                                        continue;
                                    }
                                    Err(error)
                                        if error.kind() == std::io::ErrorKind::WouldBlock =>
                                    {
                                        std::thread::sleep(Duration::from_millis(5))
                                    }
                                    Err(error) => return Err(error),
                                }
                            }
                            Ok(())
                        })();
                        if result.is_err() {
                            failed.store(true, Ordering::Release);
                        }
                        result
                    }));
                }
                reader = Some(scope.spawn(move || {
                    let result = read_pipe(stdout, limit, stop);
                    if result.is_err() {
                        failed.store(true, Ordering::Release);
                    }
                    result
                }));
                loop {
                    checkpoint()?;
                    if failed.load(Ordering::Acquire) {
                        return Err(SecretSpecError::ProviderOperationFailed(
                            "command I/O failed or exceeded its output limit".into(),
                        ));
                    }
                    if child.has_exited()? {
                        return Ok(());
                    }
                    if timed_out() {
                        return Err(SecretSpecError::ProviderOperationFailed(
                            "command timed out".into(),
                        ));
                    }
                    match request {
                        Some(request) => request.wait(Duration::from_millis(10))?,
                        None => std::thread::sleep(Duration::from_millis(10)),
                    }
                }
            }))
            .unwrap_or(Err(SecretSpecError::ResolutionPanicked));
        // Try all cleanup steps even if termination fails. The direct child
        // remains owned until its wait, independent of pipe worker results.
        let status = child.stop();
        // Close the Windows kill-on-close Job before pipe joins, including
        // when explicit termination failed. Drop retries incomplete cleanup.
        drop(child);
        if supervision_result.is_err() || status.is_err() {
            stop.store(true, Ordering::Release);
        }
        let mut pipes_timed_out = false;
        while supervision_result.is_ok()
            && status.is_ok()
            && (writer.as_ref().is_some_and(|worker| !worker.is_finished())
                || reader.as_ref().is_some_and(|worker| !worker.is_finished())
                || error_reader
                    .as_ref()
                    .is_some_and(|worker| !worker.is_finished()))
        {
            if request.is_some_and(RequestContext::is_cancelled) || timed_out() {
                stop.store(true, Ordering::Release);
                pipes_timed_out = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        // Join both before examining either result, including failures/panics.
        let written = writer.map(|worker| worker.join());
        let read = reader.map(|worker| worker.join());
        let error_read = error_reader.map(|worker| worker.join());
        let status = status.map_err(|_| {
            if let Some(request) = request {
                request.cleanup_failed("child_wait");
            }
            SecretSpecError::CleanupFailed {
                phase: "child_wait",
                cancelled: request.is_some_and(RequestContext::is_cancelled),
            }
        })?;
        supervision_result?;
        checkpoint()?;
        if pipes_timed_out {
            return Err(SecretSpecError::ProviderOperationFailed(
                "command output did not close before its deadline".into(),
            ));
        }
        let (mut stdout, mut stderr) = match (written, read, error_read) {
            (None | Some(Ok(Ok(()))), Some(Ok(Ok(stdout))), None) => {
                (stdout, Zeroizing::new(Vec::new()))
            }
            (None | Some(Ok(Ok(()))), Some(Ok(Ok(stdout))), Some(Ok(Ok(stderr)))) => {
                (stdout, stderr)
            }
            (Some(Err(_)), _, _) | (_, Some(Err(_)), _) | (_, _, Some(Err(_))) => {
                return Err(SecretSpecError::ResolutionPanicked);
            }
            _ => {
                return Err(SecretSpecError::ProviderOperationFailed(
                    "command I/O failed or exceeded its output limit".into(),
                ));
            }
        };
        Ok(Output {
            status,
            stdout: crate::SecretBytes::from_vec(std::mem::take(&mut *stdout)),
            stderr: crate::SecretBytes::from_vec(std::mem::take(&mut *stderr)),
        })
    })
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
        "failed to find the suspended managed child thread",
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
        let job = Self { handle };

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
            return Err(std::io::Error::last_os_error());
        }

        // SAFETY: the child process handle stays live while `child` is live,
        // and the job handle is valid. Descendants join the same job unless the
        // job explicitly permits breakaway, which this job does not.
        if unsafe { AssignProcessToJobObject(handle, child.as_raw_handle() as HANDLE) } == 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(job)
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
        // inherited stdout handle after the direct child exits.
        // SAFETY: this type owns the live handle and closes it exactly once.
        let _ = unsafe { CloseHandle(self.handle) };
    }
}

struct ManagedChild {
    child: Child,
    cleanup_complete: bool,
    #[cfg(windows)]
    job: WindowsJob,
}

impl ManagedChild {
    fn new(child: Child) -> Result<Self> {
        #[cfg(windows)]
        let mut child = child;
        #[cfg(windows)]
        let job = match WindowsJob::assign(&child).and_then(|job| {
            resume_suspended_process(child.id())?;
            Ok(job)
        }) {
            Ok(job) => job,
            Err(error) => {
                let _ = child.kill();
                child.wait().map_err(|_| SecretSpecError::CleanupFailed {
                    phase: "child_setup",
                    cancelled: false,
                })?;
                return Err(error.into());
            }
        };
        Ok(Self {
            child,
            cleanup_complete: false,
            #[cfg(windows)]
            job,
        })
    }

    #[cfg(unix)]
    fn has_exited(&self) -> std::io::Result<bool> {
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
            return Ok(unsafe { info.assume_init().si_pid() } != 0);
        }
    }

    #[cfg(not(unix))]
    fn has_exited(&mut self) -> std::io::Result<bool> {
        Ok(self.child.try_wait()?.is_some())
    }

    #[cfg(unix)]
    fn signal_group(&self, signal: libc::c_int) -> std::io::Result<()> {
        let group = -(self.child.id() as libc::pid_t);
        // SAFETY: the child leads its own group. Only signal 0 (an existence
        // check) is used after reaping, when the numeric ID could be reused.
        if unsafe { libc::kill(group, signal) } == -1 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn terminate_tree(&self) -> std::io::Result<()> {
        #[cfg(unix)]
        if let Err(error) = self.signal_group(libc::SIGKILL)
            && error.raw_os_error() != Some(libc::ESRCH)
        {
            return Err(error);
        }
        #[cfg(windows)]
        self.job.terminate()?;
        Ok(())
    }

    fn stop(&mut self) -> std::io::Result<ExitStatus> {
        if self.cleanup_complete {
            return self.child.wait();
        }
        let tree_error = self.terminate_tree().err();
        if let Err(error) = self.child.kill()
            && self.child.try_wait()?.is_none()
        {
            return Err(tree_error.unwrap_or(error));
        }
        let status = self.child.wait()?;
        self.cleanup_complete = true;
        if let Some(error) = tree_error {
            // macOS reports EPERM when only the zombie leader is left. Once
            // it is reaped, ESRCH confirms there is no group left to stop.
            #[cfg(unix)]
            if error.raw_os_error() == Some(libc::EPERM)
                && self
                    .signal_group(0)
                    .is_err_and(|e| e.raw_os_error() == Some(libc::ESRCH))
            {
                return Ok(status);
            }
            return Err(error);
        }
        Ok(status)
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        // Explicit error paths call `stop` first. A failed attempt leaves the
        // state incomplete so this final attempt can retry before handles drop.
        let _ = self.stop();
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::CancellationHandle;

    #[tokio::test]
    async fn cancellation_joins_child_and_blocked_stdin() {
        let directory = tempfile::tempdir().unwrap();
        let ready = directory.path().join("ready");
        let child_ready = ready.clone();
        let cancellation = CancellationHandle::new();
        let handle = cancellation.clone();
        let task = tokio::spawn(async move {
            crate::request::run(&handle, move |request| {
                output(
                    Command::new("sh")
                        .arg("-c")
                        .arg("printf '%s' $$ > \"$1\"; sleep 60 & wait")
                        .arg("fixture")
                        .arg(child_ready),
                    Some(secrecy::zeroize::Zeroizing::new(vec![42; 1024 * 1024])),
                    1024,
                    Some(Duration::from_secs(60)),
                    Some(&request),
                    false,
                )
            })
            .await
        });
        let pid = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(pid) = std::fs::read_to_string(&ready)
                    && let Ok(pid) = pid.parse::<i32>()
                {
                    break pid;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        cancellation.cancel();
        let result = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(result, Err(SecretSpecError::Cancelled)));
        // The direct child must be reaped, not just signalled or left a zombie.
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }

    #[tokio::test]
    async fn output_limit_stops_and_joins_the_writer() {
        let cancellation = CancellationHandle::new();
        let error = crate::request::run(&cancellation, |request| {
            output(
                Command::new("sh")
                    .arg("-c")
                    .arg("while :; do printf 12345678; done"),
                None,
                64,
                Some(Duration::from_secs(5)),
                Some(&request),
                false,
            )
        })
        .await
        .unwrap_err();
        assert_eq!(error.kind(), "provider_operation_failed");
        assert!(!error.to_string().contains("12345678"));
    }

    #[tokio::test]
    async fn success_keeps_all_output_and_closes_inherited_pipes() {
        let cancellation = CancellationHandle::new();
        let output = crate::request::run(&cancellation, |request| {
            output(
                Command::new("sh")
                    .arg("-c")
                    .arg("cat >/dev/null; printf complete; sleep 60 &"),
                None,
                1024,
                Some(Duration::from_secs(5)),
                Some(&request),
                false,
            )
        })
        .await
        .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout.expose_secret(), b"complete");
    }

    #[tokio::test]
    async fn captures_stdout_and_stderr_without_pipe_deadlock() {
        let result = crate::request::run(&CancellationHandle::new(), |request| {
            output(Command::new("sh").args(["-c", "i=0; while [ $i -lt 40000 ]; do printf out; printf err >&2; i=$((i+1)); done; exit 7"]),
                None, 131072, Some(Duration::from_secs(5)), Some(&request), true)
        }).await.unwrap();
        assert_eq!(result.status.code(), Some(7));
        assert_eq!(result.stdout.expose_secret(), b"out".repeat(40000));
        assert_eq!(result.stderr.expose_secret(), b"err".repeat(40000));
    }

    #[tokio::test]
    async fn stderr_limit_stops_the_child_without_disclosing_output() {
        let error = crate::request::run(&CancellationHandle::new(), |request| {
            output(
                Command::new("sh").args(["-c", "while :; do printf sensitive >&2; done"]),
                None,
                64,
                Some(Duration::from_secs(5)),
                Some(&request),
                true,
            )
        })
        .await
        .unwrap_err();
        assert_eq!(error.kind(), "provider_operation_failed");
        assert!(!error.to_string().contains("sensitive"));
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};

    fn windows_job_helper_command(role: &str, ready: &Path) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "command::windows_tests::windows_job_helper",
                "--nocapture",
            ])
            .env("SECRETSPEC_COMMAND_JOB_HELPER", role)
            .env("SECRETSPEC_COMMAND_JOB_READY", ready);
        command
    }

    #[test]
    fn windows_job_helper() {
        let Ok(role) = std::env::var("SECRETSPEC_COMMAND_JOB_HELPER") else {
            return;
        };
        let ready = PathBuf::from(std::env::var_os("SECRETSPEC_COMMAND_JOB_READY").unwrap());
        match role.as_str() {
            "parent" => {
                let status = windows_job_helper_command("descendant", &ready)
                    .stdin(Stdio::null())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit())
                    .spawn()
                    .unwrap()
                    .wait()
                    .unwrap();
                assert!(status.success());
            }
            "descendant" => {
                // Publish only after this process has started and inherited
                // stdout. Rename prevents the observer from reading a partial PID.
                let pending = ready.with_extension("pending");
                fs::write(&pending, std::process::id().to_string()).unwrap();
                fs::rename(pending, ready).unwrap();
                std::thread::sleep(Duration::from_secs(120));
            }
            _ => panic!("unknown command job helper role"),
        }
    }

    #[test]
    fn windows_suspended_job_requests_termination_of_a_descendant_holding_stdout() {
        use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
        };

        let directory = tempfile::tempdir().unwrap();
        let descendant_pid = directory.path().join("descendant-pid");
        let diagnostics = directory.path().join("helper-stderr");
        let mut command = windows_job_helper_command("parent", &descendant_pid);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(fs::File::create(&diagnostics).unwrap())
            .creation_flags(CREATE_SUSPENDED);
        let child = command.spawn().unwrap();
        let mut child = ManagedChild::new(child).unwrap();

        let deadline = Instant::now() + Duration::from_secs(30);
        while !descendant_pid.exists() && Instant::now() < deadline {
            if child.has_exited().unwrap() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        if !descendant_pid.exists() {
            let _ = child.stop();
            panic!(
                "suspended Windows helper did not record its descendant: {}",
                fs::read_to_string(&diagnostics).unwrap(),
            );
        }
        let pid: u32 = fs::read_to_string(descendant_pid)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        // SAFETY: this opens only the test descendant for synchronization. The
        // returned handle is owned below and grants no mutation rights.
        let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
        assert!(!handle.is_null(), "command descendant {pid} is missing");
        let handle = OwnedWindowsHandle { handle };
        // SAFETY: the owned process handle remains live through both waits.
        assert_eq!(
            unsafe { WaitForSingleObject(handle.handle, 0) },
            WAIT_TIMEOUT
        );
        child.stop().unwrap();
        // The job requests termination. The test waits separately for descendant exit.
        // SAFETY: the owned handle still identifies the same descendant after stop.
        let wait = unsafe { WaitForSingleObject(handle.handle, 2_000) };
        assert_eq!(wait, WAIT_OBJECT_0, "command descendant {pid} survived");
    }
}
