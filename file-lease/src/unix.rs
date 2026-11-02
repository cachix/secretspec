use super::*;
use std::{
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{net::UnixStream, process::CommandExt},
    },
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
};

#[cfg(target_os = "linux")]
use super::linux::{Storage, watch_owner};
#[cfg(target_os = "macos")]
use super::macos::{Storage, watch_owner};

const SOCKET_ENV: &str = "_FILE_LEASE_KEEPER_SOCKET";
const OWNER_ENV: &str = "_FILE_LEASE_KEEPER_OWNER";
const ALLOCATE: u8 = 1;
const HANDOFF: u8 = 2;
const CLOSE: u8 = 3;
const RELEASE: u8 = 4;
const MAX_SECRET_BYTES: u64 = 64 * 1024 * 1024;
const ALLOCATION_ERROR: u32 = u32::MAX;
// Version 2 requires locked Linux storage and framed allocation errors. Reject
// older helpers before sending payloads rather than accepting pageable files.
const READY: &[u8; 4] = b"SFL2";

pub(super) struct Keeper {
    stream: Mutex<UnixStream>,
    child: Mutex<Option<Child>>,
    handed_off: AtomicBool,
}

fn valid_pid(pid: u32) -> io::Result<()> {
    if pid == 0 || pid > i32::MAX as u32 {
        Err(io::Error::other("Invalid file lease owner PID"))
    } else {
        Ok(())
    }
}

// Descriptors inherited through exec must not collide with child stdio setup.
fn above_stdio<T: Into<OwnedFd> + From<OwnedFd>>(descriptor: T) -> io::Result<T> {
    let descriptor = descriptor.into();
    if descriptor.as_raw_fd() >= 3 {
        return Ok(descriptor.into());
    }
    let duplicate = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) }.into())
}

impl Keeper {
    #[cfg(test)]
    pub(super) fn pid(&self) -> u32 {
        self.child.lock().unwrap().as_ref().unwrap().id()
    }

    pub(super) fn spawn(owner: u32, executable: Option<&Path>) -> io::Result<Self> {
        valid_pid(owner)?;
        #[cfg(target_os = "macos")]
        let owner_info = super::macos::process_info(owner)?;
        #[cfg(target_os = "macos")]
        let owner_arg = owner.to_string();
        #[cfg(target_os = "linux")]
        let owner = above_stdio(watch_owner(owner)?)?;
        let (stream, remote) = UnixStream::pair()?;
        let mut stream = above_stdio(stream)?;
        let remote = above_stdio(remote)?;
        let socket_fd = remote.as_raw_fd();
        #[cfg(target_os = "linux")]
        let owner_fd = owner.as_raw_fd();
        #[cfg(target_os = "linux")]
        let owner_arg = owner_fd.to_string();
        let executable = match executable {
            Some(path) => path.to_path_buf(),
            None => {
                #[cfg(test)]
                {
                    std::env::current_exe()?
                }
                #[cfg(not(test))]
                {
                    let sibling = std::env::current_exe()?.with_file_name("file-lease");
                    if sibling.is_file() {
                        sibling
                    } else {
                        PathBuf::from("file-lease")
                    }
                }
            }
        };
        let mut command = Command::new(executable);
        command
            .env(SOCKET_ENV, socket_fd.to_string())
            .env(OWNER_ENV, owner_arg)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        #[cfg(target_os = "macos")]
        command.env(
            "_FILE_LEASE_OWNER_BIRTH",
            format!(
                "{}:{}",
                owner_info.pbi_start_tvsec, owner_info.pbi_start_tvusec
            ),
        );
        // kqueues are not inherited across fork. macOS registers its exit
        // watcher inside the new helper and validates the process birth time.
        #[cfg(target_os = "linux")]
        let inherited = vec![socket_fd, owner_fd];
        #[cfg(target_os = "macos")]
        let inherited = vec![socket_fd];
        unsafe {
            command.pre_exec(move || {
                for fd in &inherited {
                    if libc::fcntl(*fd, libc::F_SETFD, 0) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        #[cfg(test)]
        command
            .args(["--exact", "tests::keeper_entry", "--nocapture"])
            .stderr(Stdio::inherit());
        let mut child = command.spawn()?;
        drop(remote);
        #[cfg(target_os = "linux")]
        drop(owner);
        let mut ready = [0; 4];
        if let Err(error) = stream.read_exact(&mut ready) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        if &ready != READY {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::other("Incompatible file lease keeper"));
        }
        Ok(Self {
            stream: Mutex::new(stream),
            child: Mutex::new(Some(child)),
            handed_off: AtomicBool::new(false),
        })
    }

    pub(super) fn materialize(&self, bytes: &[u8], suffix: &str) -> io::Result<PathBuf> {
        if bytes.len() as u64 > MAX_SECRET_BYTES {
            return Err(io::Error::other("Secret exceeds file lease size limit"));
        }
        if suffix.len() > 80
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        {
            return Err(io::Error::other("Invalid secret file suffix"));
        }
        let mut stream = self
            .stream
            .lock()
            .map_err(|_| io::Error::other("File keeper lock poisoned"))?;
        if self.handed_off.load(Ordering::Acquire) {
            return Err(io::Error::other("File lease has been handed off"));
        }
        stream.write_all(&[ALLOCATE])?;
        stream.write_all(&(bytes.len() as u64).to_le_bytes())?;
        stream.write_all(&(suffix.len() as u32).to_le_bytes())?;
        stream.write_all(suffix.as_bytes())?;
        stream.write_all(bytes)?;
        let mut length = [0; 4];
        stream.read_exact(&mut length)?;
        let reply = u32::from_le_bytes(length);
        let failed = reply == ALLOCATION_ERROR;
        let length = if failed {
            stream.read_exact(&mut length)?;
            u32::from_le_bytes(length) as usize
        } else {
            reply as usize
        };
        if length > 16384 {
            return Err(io::Error::other("Invalid file keeper reply"));
        }
        let mut path = vec![0; length];
        stream.read_exact(&mut path)?;
        let path = String::from_utf8(path).map_err(io::Error::other)?;
        if failed {
            return Err(io::Error::other(format!(
                "File keeper could not allocate secret storage: {path}"
            )));
        }
        if length == 0 {
            return Err(io::Error::other(
                "File keeper could not allocate secret storage",
            ));
        }
        Ok(PathBuf::from(path))
    }

    pub(super) fn release(&self, path: &Path) -> io::Result<()> {
        let path = path
            .to_str()
            .ok_or_else(|| io::Error::other("Non-UTF-8 lease path"))?;
        if path.len() > 16384 {
            return Err(io::Error::other("Oversized lease path"));
        }
        let mut stream = self
            .stream
            .lock()
            .map_err(|_| io::Error::other("File keeper lock poisoned"))?;
        stream.write_all(&[RELEASE])?;
        stream.write_all(&(path.len() as u32).to_le_bytes())?;
        stream.write_all(path.as_bytes())?;
        let mut ack = [0];
        stream.read_exact(&mut ack)?;
        if ack != [1] {
            return Err(io::Error::other("File lease release failed"));
        }
        Ok(())
    }

    pub(super) fn handoff_to(&self, owner: Option<u32>) -> io::Result<()> {
        if let Some(pid) = owner {
            valid_pid(pid)?;
        }
        let mut stream = self
            .stream
            .lock()
            .map_err(|_| io::Error::other("File keeper lock poisoned"))?;
        if !self.handed_off.load(Ordering::Acquire) || owner.is_some() {
            stream.write_all(&[HANDOFF])?;
            stream.write_all(&owner.unwrap_or(0).to_le_bytes())?;
            let mut ack = [0];
            stream.read_exact(&mut ack)?;
            if ack != [1] {
                return Err(io::Error::other("File lease handoff failed"));
            }
            self.handed_off.store(true, Ordering::Release);
        }
        Ok(())
    }
}

impl Drop for Keeper {
    fn drop(&mut self) {
        if let Ok(child) = self.child.get_mut()
            && let Some(mut child) = child.take()
        {
            if self.handed_off.load(Ordering::Acquire) {
                reap_when_exited(child);
            } else {
                // Graceful shutdown also unmounts macOS volumes. If the keeper
                // was killed, its macOS guardian independently cleans up.
                if let Ok(stream) = self.stream.get_mut() {
                    let _ = stream.write_all(&[CLOSE]);
                }
                let _ = child.wait();
            }
        }
    }
}

pub(super) fn maybe_run_keeper() -> Option<i32> {
    #[cfg(target_os = "macos")]
    if let Some(result) = super::macos::maybe_run_setup() {
        return Some(result.map_or_else(|_| 1, |_| 0));
    }
    let socket = std::env::var(SOCKET_ENV).ok()?;
    Some(run_keeper(&socket).map_or_else(
        |error| {
            eprintln!("File lease keeper: {error}");
            1
        },
        |_| 0,
    ))
}

fn run_keeper(socket: &str) -> io::Result<()> {
    let socket: i32 = socket.parse().map_err(io::Error::other)?;
    let owner: i32 = std::env::var(OWNER_ENV)
        .map_err(io::Error::other)?
        .parse()
        .map_err(io::Error::other)?;
    if socket < 3 {
        return Err(io::Error::other("Invalid file keeper socket"));
    }
    // This descriptor is inherited exclusively by the keeper executable.
    let mut stream = unsafe { UnixStream::from_raw_fd(socket) };
    // macOS storage starts system tools. Do not let them inherit the private
    // control channel or keep its EOF alive in a DiskImages helper.
    if unsafe { libc::fcntl(socket, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    #[cfg(target_os = "linux")]
    let owner = {
        if owner < 3 || socket == owner {
            return Err(io::Error::other("Invalid file keeper owner descriptor"));
        }
        if unsafe { libc::fcntl(owner, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        unsafe { OwnedFd::from_raw_fd(owner) }
    };
    #[cfg(target_os = "macos")]
    let owner = {
        valid_pid(owner as u32)?;
        let expected = std::env::var("_FILE_LEASE_OWNER_BIRTH").map_err(io::Error::other)?;
        let verify = || -> io::Result<()> {
            let info = super::macos::process_info(owner as u32)?;
            if format!("{}:{}", info.pbi_start_tvsec, info.pbi_start_tvusec) != expected {
                return Err(io::Error::other(
                    "File lease owner process changed during startup",
                ));
            }
            Ok(())
        };
        verify()?;
        let watch = watch_owner(owner as u32)?;
        verify()?;
        watch
    };
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) } < 0 {
        return Err(io::Error::last_os_error());
    }
    limit.rlim_cur = 0;
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let storage = Arc::new(Mutex::new(Storage::default()));
    let mut owner_watch = OwnerWatch::start(owner, storage.clone())?;
    stream.write_all(READY)?;
    let mut handed_off = false;
    loop {
        let mut op = [0];
        match stream.read_exact(&mut op) {
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                if handed_off {
                    loop {
                        let _ = &owner_watch;
                        std::thread::park();
                    }
                }
                break;
            }
            result => result?,
        }
        match op[0] {
            ALLOCATE => {
                if handed_off {
                    return Err(io::Error::other("Cannot allocate after file lease handoff"));
                }
                let mut length = [0; 8];
                stream.read_exact(&mut length)?;
                let length = u64::from_le_bytes(length);
                let mut suffix_length = [0; 4];
                stream.read_exact(&mut suffix_length)?;
                let suffix_length = u32::from_le_bytes(suffix_length) as usize;
                if length > MAX_SECRET_BYTES || suffix_length > 80 {
                    return Err(io::Error::other("Oversized secret file request"));
                }
                let mut suffix = vec![0; suffix_length];
                stream.read_exact(&mut suffix)?;
                let suffix = String::from_utf8(suffix).map_err(io::Error::other)?;
                if !suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
                {
                    return Err(io::Error::other("Invalid secret file suffix"));
                }
                let mut bytes = zeroize::Zeroizing::new(vec![0; length as usize]);
                stream.read_exact(&mut bytes)?;
                let path = storage
                    .lock()
                    .map_err(|_| io::Error::other("Storage lock poisoned"))?
                    .materialize(&bytes, &suffix);
                match path {
                    Ok(path) => {
                        let path = path
                            .to_str()
                            .ok_or_else(|| io::Error::other("Non-UTF-8 file lease path"))?;
                        stream.write_all(&(path.len() as u32).to_le_bytes())?;
                        stream.write_all(path.as_bytes())?;
                    }
                    Err(error) => {
                        eprintln!("SecretSpec file storage: {error}");
                        let message = error.to_string();
                        let message = if message.len() <= 16384 {
                            &message
                        } else {
                            "Secret storage allocation failed (oversized helper error)"
                        };
                        // The versioned handshake rejects clients that do not
                        // understand this bounded error-message frame.
                        stream.write_all(&ALLOCATION_ERROR.to_le_bytes())?;
                        stream.write_all(&(message.len() as u32).to_le_bytes())?;
                        stream.write_all(message.as_bytes())?;
                    }
                }
            }
            HANDOFF => {
                let mut pid = [0; 4];
                stream.read_exact(&mut pid)?;
                let pid = u32::from_le_bytes(pid);
                if pid != 0 {
                    valid_pid(pid)?;
                    let next = OwnerWatch::start(watch_owner(pid)?, storage.clone())?;
                    drop(owner_watch);
                    owner_watch = next;
                }
                handed_off = true;
                stream.write_all(&[1])?;
            }
            RELEASE => {
                let mut length = [0; 4];
                stream.read_exact(&mut length)?;
                let length = u32::from_le_bytes(length) as usize;
                if length > 16384 {
                    return Err(io::Error::other("Oversized lease path"));
                }
                let mut path = vec![0; length];
                stream.read_exact(&mut path)?;
                let path = String::from_utf8(path).map_err(io::Error::other)?;
                let result = storage
                    .lock()
                    .map_err(|_| io::Error::other("Storage lock poisoned"))?
                    .release(Path::new(&path));
                stream.write_all(&[u8::from(result.is_ok())])?;
            }
            CLOSE => break,
            _ => return Err(io::Error::other("Invalid file keeper operation")),
        }
    }
    drop(owner_watch);
    storage
        .lock()
        .map_err(|_| io::Error::other("Storage lock poisoned"))?
        .cleanup()
}

struct OwnerWatch {
    cancel: UnixStream,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl OwnerWatch {
    fn start(owner: OwnedFd, storage: Arc<Mutex<Storage>>) -> io::Result<Self> {
        let (cancel, listener) = UnixStream::pair()?;
        let thread = std::thread::spawn(move || {
            let mut descriptors = [
                libc::pollfd {
                    fd: owner.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: listener.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            loop {
                let result =
                    unsafe { libc::poll(descriptors.as_mut_ptr(), descriptors.len() as _, -1) };
                if result > 0 {
                    if descriptors[1].revents != 0 {
                        return;
                    }
                    if descriptors[0].revents != 0 {
                        let result = storage
                            .lock()
                            .map_err(|_| io::Error::other("Storage lock poisoned"))
                            .and_then(|mut storage| storage.cleanup());
                        std::process::exit(if result.is_ok() { 0 } else { 1 });
                    }
                }
                if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                    if let Ok(mut storage) = storage.lock() {
                        let _ = storage.cleanup();
                    }
                    std::process::exit(1);
                }
            }
        });
        Ok(Self {
            cancel,
            thread: Some(thread),
        })
    }
}
impl Drop for OwnerWatch {
    fn drop(&mut self) {
        let _ = self.cancel.write_all(&[1]);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
pub(super) fn reap_when_exited(child: Child) {
    use std::sync::{OnceLock, mpsc};
    static REAPER: OnceLock<mpsc::Sender<Child>> = OnceLock::new();
    let sender = REAPER.get_or_init(|| {
        let (sender, receiver) = mpsc::channel::<Child>();
        std::thread::spawn(move || {
            let mut children = Vec::new();
            loop {
                match receiver.recv_timeout(std::time::Duration::from_millis(100)) {
                    Ok(child) => children.push(child),
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => return,
                }
                children.retain_mut(|child| matches!(child.try_wait(), Ok(None)));
            }
        });
        sender
    });
    let _ = sender.send(child);
}
