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

const SOCKET_ENV: &str = "_SECRETSPEC_FILE_KEEPER_SOCKET";
const OWNER_ENV: &str = "_SECRETSPEC_FILE_KEEPER_OWNER";
const ALLOCATE: u8 = 1;
const HANDOFF: u8 = 2;
const CLOSE: u8 = 3;
const MAX_SECRET_BYTES: u64 = 64 * 1024 * 1024;

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

impl Keeper {
    #[cfg(test)]
    pub(super) fn pid(&self) -> u32 {
        self.child.lock().unwrap().as_ref().unwrap().id()
    }

    pub(super) fn spawn(owner: u32, executable: Option<&Path>) -> io::Result<Self> {
        valid_pid(owner)?;
        let owner = watch_owner(owner)?;
        let (mut stream, remote) = UnixStream::pair()?;
        let socket_fd = remote.as_raw_fd();
        let owner_fd = owner.as_raw_fd();
        let executable = match executable {
            Some(path) => path.to_path_buf(),
            None => {
                #[cfg(test)]
                {
                    std::env::current_exe()?
                }
                #[cfg(not(test))]
                {
                    let sibling = std::env::current_exe()?.with_file_name("secretspec");
                    if sibling.is_file() {
                        sibling
                    } else {
                        PathBuf::from("secretspec")
                    }
                }
            }
        };
        let mut command = Command::new(executable);
        command
            .env(SOCKET_ENV, socket_fd.to_string())
            .env(OWNER_ENV, owner_fd.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        // Only the forked child inherits these two control descriptors.
        unsafe {
            command.pre_exec(move || {
                for fd in [socket_fd, owner_fd] {
                    if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        #[cfg(test)]
        command
            .args(["--exact", "file_lease::tests::keeper_entry", "--nocapture"])
            .stderr(Stdio::inherit());
        let mut child = command.spawn()?;
        drop(remote);
        drop(owner);
        let mut ready = [0; 4];
        if let Err(error) = stream.read_exact(&mut ready) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        if &ready != b"SFL1" {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::other("Incompatible SecretSpec file keeper"));
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
        let length = u32::from_le_bytes(length) as usize;
        if length > 16384 {
            return Err(io::Error::other("Invalid file keeper reply"));
        }
        let mut path = vec![0; length];
        stream.read_exact(&mut path)?;
        let path = String::from_utf8(path).map_err(io::Error::other)?;
        if length == 0 {
            return Err(io::Error::other(
                "File keeper could not allocate secret storage",
            ));
        }
        Ok(PathBuf::from(path))
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
                // was killed, its journal is recovered by the next lease.
                if let Ok(stream) = self.stream.get_mut() {
                    let _ = stream.write_all(&[CLOSE]);
                }
                let _ = child.wait();
            }
        }
    }
}

pub(super) fn maybe_run_keeper() -> Option<i32> {
    let socket = std::env::var(SOCKET_ENV).ok()?;
    Some(run_keeper(&socket).map_or_else(
        |error| {
            eprintln!("SecretSpec file keeper: {error}");
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
    if socket < 3 || owner < 3 || socket == owner {
        return Err(io::Error::other("Invalid file keeper descriptors"));
    }
    // These descriptors are inherited exclusively by the keeper executable.
    let mut stream = unsafe { UnixStream::from_raw_fd(socket) };
    let owner = unsafe { OwnedFd::from_raw_fd(owner) };
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
    stream.write_all(b"SFL1")?;
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
                let mut bytes = secrecy::zeroize::Zeroizing::new(vec![0; length as usize]);
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
                        stream.write_all(&0u32.to_le_bytes())?;
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
fn reap_when_exited(child: Child) {
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
