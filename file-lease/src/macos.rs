use super::macos_registry as registry;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    mem::MaybeUninit,
    os::unix::process::CommandExt,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub(super) fn watch_owner(pid: u32) -> io::Result<OwnedFd> {
    let fd = unsafe { libc::kqueue() };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let queue = unsafe { OwnedFd::from_raw_fd(fd) };
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let event = libc::kevent {
        ident: pid as _,
        filter: libc::EVFILT_PROC,
        flags: libc::EV_ADD | libc::EV_ONESHOT,
        fflags: libc::NOTE_EXIT,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    if unsafe { libc::kevent(fd, &event, 1, std::ptr::null_mut(), 0, std::ptr::null()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(queue)
}

pub(super) fn process_info(pid: u32) -> io::Result<libc::proc_bsdinfo> {
    let mut info = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = std::mem::size_of::<libc::proc_bsdinfo>();
    let result = unsafe {
        libc::proc_pidinfo(
            pid as _,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size as _,
        )
    };
    if result as usize != size {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { info.assume_init() })
}

const TOOL_TIMEOUT: Duration = Duration::from_secs(10);
const SETUP_TIMEOUT: Duration = Duration::from_secs(120);
const REQUIRED_MOUNT_FLAGS: u32 =
    (libc::MNT_NOEXEC | libc::MNT_NOSUID | libc::MNT_NODEV | libc::MNT_DONTBROWSE) as u32;

fn validate_mount_flags(flags: u32) -> io::Result<()> {
    if flags & REQUIRED_MOUNT_FLAGS != REQUIRED_MOUNT_FLAGS
        || flags & libc::MNT_IGNORE_OWNERSHIP as u32 != 0
    {
        return Err(io::Error::other("RAM-disk security mount flags changed"));
    }
    Ok(())
}

fn command(program: &str, args: &[&std::ffi::OsStr]) -> io::Result<()> {
    // Volume tools operate only on metadata. Avoid pipe-draining threads which
    // could themselves wait forever if a tool leaves descendants holding pipes.
    super::command::run(
        Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            // During setup stdout is the lock file; all in-flight tools must
            // retain it if the guardian dies. After setup stdout is /dev/null.
            .stdout(Stdio::inherit())
            .stderr(Stdio::null()),
        TOOL_TIMEOUT,
    )
    .map_err(|error| io::Error::new(error.kind(), format!("{program}: {error}")))
}

fn mount_info(path: &Path) -> io::Result<libc::statfs> {
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)?;
    let mut info = MaybeUninit::<libc::statfs>::zeroed();
    if unsafe { libc::statfs(path.as_ptr(), info.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { info.assume_init() })
}

fn c_string(bytes: &[libc::c_char]) -> &[u8] {
    let length = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    // c_char has the same representation and alignment as u8.
    unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast(), length) }
}

fn runtime_root() -> io::Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .ok_or_else(|| io::Error::other("Cannot locate SecretSpec file lease metadata"))?;
    let root = PathBuf::from(home).join("Library/Application Support/file-lease");
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&root)?;
    let metadata = fs::symlink_metadata(&root)?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(io::Error::other(
            "SecretSpec file lease metadata directory must be private and user-owned",
        ));
    }
    root.canonicalize()
}

fn device_identity(metadata: &fs::Metadata) -> [u64; 4] {
    [
        metadata.ino(),
        metadata.rdev(),
        metadata.ctime() as u64,
        metadata.ctime_nsec() as u64,
    ]
}

#[derive(Serialize, Deserialize)]
struct Journal {
    keeper: u32,
    birth: [u64; 2],
    #[serde(default)]
    lease_id: Option<uuid::Uuid>,
    device: String,
    mount: PathBuf,
    filesystem: Option<u64>,
    device_identity: Option<[u64; 4]>,
}

impl Journal {
    fn identify_device(&mut self, directory: &Path) -> io::Result<()> {
        if self.device.is_empty() {
            let device = self
                .lease_id
                .map(registry::device)
                .transpose()?
                .flatten()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "RAM-disk attachment has not been identified yet",
                    )
                })?;
            self.device_identity = Some(device_identity(&fs::metadata(&device)?));
            self.device = device;
            self.save(directory)?;
        }
        Ok(())
    }

    fn read(directory: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(directory.join("lease.json"))?;
        if file.metadata()?.uid() != unsafe { libc::geteuid() } {
            return Err(io::Error::other("File lease journal is not user-owned"));
        }
        serde_json::from_reader(file.take(16384)).map_err(io::Error::other)
    }

    fn save(&self, directory: &Path) -> io::Result<()> {
        // Keep the previous complete record if a writer dies during an update.
        let mut file = tempfile::NamedTempFile::new_in(directory)?;
        serde_json::to_writer(&mut file, self).map_err(io::Error::other)?;
        file.as_file().sync_all()?;
        file.persist(directory.join("lease.json"))
            .map_err(|error| error.error)?;
        fs::File::open(directory)?.sync_all()
    }

    fn validate_mount(&self) -> io::Result<bool> {
        Ok(self.mounted_root()?.is_some())
    }

    fn mounted_root(&self) -> io::Result<Option<(fs::File, libc::statfs)>> {
        if !self.device.strip_prefix("/dev/disk").is_some_and(|digits| {
            !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
        }) {
            return Err(io::Error::other(
                "Invalid RAM-disk device in file lease journal",
            ));
        }
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.mount)?;
        let mut info = MaybeUninit::<libc::statfs>::zeroed();
        if unsafe { libc::fstatfs(root.as_raw_fd(), info.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let info = unsafe { info.assume_init() };
        if c_string(&info.f_mntonname) != self.mount.as_os_str().as_bytes() {
            return Ok(None);
        }
        if c_string(&info.f_fstypename) != b"hfs"
            || c_string(&info.f_mntfromname) != self.device.as_bytes()
            || self.filesystem.is_some_and(|device| {
                root.metadata()
                    .map_or(true, |metadata| metadata.dev() != device)
            })
            || info.f_owner != unsafe { libc::geteuid() }
        {
            return Err(io::Error::other(
                "RAM-disk identity changed; refusing file lease cleanup",
            ));
        }
        Ok(Some((root, info)))
    }

    fn validate_device(&self) -> io::Result<bool> {
        if self.device.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Cannot discard an unfinished RAM-disk attachment",
            ));
        }
        let metadata = match fs::metadata(&self.device) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        if let Some(id) = self.lease_id
            && registry::device(id)?.as_deref() != Some(self.device.as_str())
        {
            return Err(io::Error::other("RAM-disk lease identifier changed"));
        }
        if Some(device_identity(&metadata)) != self.device_identity {
            return Err(io::Error::other("RAM-disk device identity changed"));
        }
        Ok(true)
    }

    fn cleanup(&self) -> io::Result<()> {
        if !self.validate_device()? {
            return Ok(());
        }
        let Some((root, _)) = self.mounted_root()? else {
            command(
                "/usr/bin/hdiutil",
                &["detach".as_ref(), "-force".as_ref(), self.device.as_ref()],
            )?;
            return Ok(());
        };
        // Revalidate after pinning the root: a recycled disk number must not
        // turn a previous device check into permission to clean another mount.
        if !self.validate_device()? {
            return Err(io::Error::other(
                "RAM-disk device disappeared during cleanup",
            ));
        }
        // Remove all readable names first, even if a later unmount fails.
        for entry in fs::read_dir(&self.mount)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let name = std::ffi::CString::new(entry.file_name().as_bytes())
                    .map_err(io::Error::other)?;
                if unsafe { libc::unlinkat(root.as_raw_fd(), name.as_ptr(), 0) } < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }
        drop(root);
        command("/sbin/umount", &["-f".as_ref(), self.mount.as_os_str()])?;
        command(
            "/usr/bin/hdiutil",
            &["detach".as_ref(), "-force".as_ref(), self.device.as_ref()],
        )?;
        Ok(())
    }
}

/// Recover only journals belonging to dead keepers, comparing process birth
/// times and the mounted filesystem identity before removing any resource.
fn recover_orphans(root: &Path) -> io::Result<()> {
    for directory in fs::read_dir(root)? {
        let directory = directory?;
        if !directory.file_type()?.is_dir() {
            continue;
        }
        let journal = match Journal::read(&directory.path()) {
            Ok(journal) => journal,
            Err(_) => continue,
        };
        if journal.mount != directory.path().join("memory") {
            continue;
        }
        match process_info(journal.keeper) {
            Ok(info) if [info.pbi_start_tvsec, info.pbi_start_tvusec] == journal.birth => continue,
            Err(error) if !matches!(error.raw_os_error(), Some(libc::ESRCH | libc::ENOENT)) => {
                continue;
            }
            _ => {}
        }
        // Recovery skips busy setup or cleanup without delaying other leases.
        let _ = cleanup_directory(&directory.path());
    }
    Ok(())
}

// All cleanup paths share this lock and re-read metadata after acquiring it.
// Never recursively remove the directory: it may still contain a mounted disk.
fn cleanup_directory(directory: &Path) -> io::Result<()> {
    if !directory.try_exists()? {
        return Ok(());
    }
    let Some(_lock) = try_setup_lock(directory)? else {
        return if !directory.try_exists()? {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "File lease is busy",
            ))
        };
    };
    let mut journal = match Journal::read(directory) {
        Err(error) if error.kind() == io::ErrorKind::NotFound && !directory.try_exists()? => {
            return Ok(());
        }
        result => result?,
    };
    if journal.mount != directory.join("memory") {
        return Err(io::Error::other("Invalid file lease mount path"));
    }
    journal.identify_device(directory)?;
    journal.cleanup()?;
    match fs::remove_dir(&journal.mount) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_type()?.is_file() && entry.file_name() != "setup.lock" {
            fs::remove_file(entry.path())?;
        }
    }
    // Remove the lock last. Cleanup opens existing locks only, so contenders
    // cannot create a new lock inode while this one is being removed.
    fs::remove_file(directory.join("setup.lock"))?;
    fs::remove_dir(directory)
}

fn retry_cleanup(mut cleanup: impl FnMut() -> io::Result<()>) -> io::Result<()> {
    for attempt in 0..3 {
        match cleanup() {
            Ok(()) => return Ok(()),
            Err(error) if attempt == 2 => return Err(error),
            Err(_) => std::thread::sleep(Duration::from_millis(100 << attempt)),
        }
    }
    unreachable!()
}

fn cleanup_with_retry(directory: &Path) -> io::Result<()> {
    retry_cleanup(|| cleanup_directory(directory))
}

const SETUP_ENV: &str = "_FILE_LEASE_SETUP_DIRECTORY";

fn try_setup_lock(directory: &Path) -> io::Result<Option<fs::File>> {
    let lock = match OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(directory.join("setup.lock"))
    {
        Ok(lock) => lock,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if lock.metadata()?.uid() != unsafe { libc::geteuid() } {
        return Ok(None);
    }
    if lock_exclusive(&lock, libc::LOCK_NB)? {
        Ok(Some(lock))
    } else {
        Ok(None)
    }
}

fn lock_exclusive(file: &fs::File, flags: i32) -> io::Result<bool> {
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | flags) } == 0 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::WouldBlock {
            return Ok(false);
        }
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

pub(super) fn maybe_run_setup() -> Option<io::Result<()>> {
    let directory = std::env::var_os(SETUP_ENV)?;
    Some(setup_and_guard(Path::new(&directory)))
}

fn setup_and_guard(directory: &Path) -> io::Result<()> {
    let setup = (|| {
        let journal = Journal::read(directory)?;
        // Register before starting attachment, then check birth time to close
        // the PID reuse race between reading the journal and registration.
        let watch = watch_owner(journal.keeper)?;
        let info = process_info(journal.keeper)?;
        if [info.pbi_start_tvsec, info.pbi_start_tvusec] != journal.birth {
            return Err(io::Error::other("File lease keeper identity changed"));
        }
        setup_device(directory)?;
        Ok(watch)
    })();
    // Publish readiness while setup is still locked. After unlocking, orphan
    // recovery may remove the directory, so the guardian must not create any
    // further metadata files there.
    let signal = (|| -> io::Result<()> {
        let mut ready = tempfile::NamedTempFile::new_in(directory)?;
        write!(
            ready,
            "{}",
            if setup.is_ok() { std::process::id() } else { 0 }
        )?;
        ready
            .persist(directory.join("setup.ready"))
            .map_err(|error| error.error)?;
        Ok(())
    })();
    // stdout was the inherited setup lock. The guardian must release that
    // reference before competing with the keeper or orphan recovery for cleanup.
    let null = fs::File::open("/dev/null")?;
    if unsafe { libc::dup2(null.as_raw_fd(), libc::STDOUT_FILENO) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if let Ok(watch) = &setup
        && signal.is_ok()
    {
        let mut event = libc::pollfd {
            fd: watch.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            // Normal cleanup also ends the keeper. Block on its exit instead
            // of periodically waking every idle lease to inspect metadata.
            let result = unsafe { libc::poll(&mut event, 1, -1) };
            if result > 0 && event.revents != 0 {
                break;
            }
            if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                break; // Revoke storage if monitoring fails.
            }
        }
    }
    let cleanup = cleanup_with_retry(directory);
    setup.map(|_| ()).and(signal).and(cleanup)
}

fn setup_device(directory: &Path) -> io::Result<()> {
    let mut journal = Journal::read(directory)?;
    // stdout holds the inherited lock throughout setup. The guardian closes
    // it after setup, before monitoring the keeper and competing for cleanup.
    let id = journal
        .lease_id
        .ok_or_else(|| io::Error::other("Missing file lease identifier"))?;
    // hdiutil inherits the setup lock through stdout. If this worker dies
    // while attachment is in flight, recovery skips it until hdiutil exits.
    // The identifier was journaled before launching either process and is
    // attached to the IOKit device independently of this worker's output.
    let mut attach = Command::new("/usr/bin/hdiutil");
    attach
        .args([
            "attach",
            "-nomount",
            "-drivekey",
            &format!("{}={id}", registry::LEASE_KEY),
            "ram://131072",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::null());
    // The checkpoint is before the bounded wait, so tests can still kill a
    // worker while attachment is running. The tool retains the setup lock.
    let attach = attach.process_group(0).spawn()?;
    if let Err(error) = checkpoint("attaching", directory, "") {
        super::command::terminate(attach);
        return Err(error);
    }
    super::command::wait(attach, TOOL_TIMEOUT)
        .map_err(|error| io::Error::new(error.kind(), format!("hdiutil attach: {error}")))?;
    match registry::device(id)? {
        Some(device) => {
            journal.device_identity = Some(device_identity(&fs::metadata(&device)?));
            journal.device = device;
        }
        None => {
            // Fail closed on systems without drive-key support, but detach the
            // device reported directly by our completed attachment command.
            let output = fs::read_to_string(directory.join("setup.lock"))?;
            if let Some(device) = output.split_whitespace().find(|value| {
                value.strip_prefix("/dev/disk").is_some_and(|digits| {
                    !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
                })
            }) {
                command(
                    "/usr/bin/hdiutil",
                    &["detach".as_ref(), "-force".as_ref(), device.as_ref()],
                )?;
            }
            return Err(io::Error::other(
                "RAM-disk lease identifier was not registered",
            ));
        }
    }
    let mount = journal.mount.clone();
    let uid = unsafe { libc::geteuid() }.to_string();
    let gid = unsafe { libc::getegid() }.to_string();
    checkpoint("attached", directory, &journal.device)?;
    journal.save(directory)?;
    let device = &journal.device;
    command(
        "/sbin/newfs_hfs",
        &[
            "-U".as_ref(),
            uid.as_ref(),
            "-G".as_ref(),
            gid.as_ref(),
            "-M".as_ref(),
            "700".as_ref(),
            "-v".as_ref(),
            "SecretSpec".as_ref(),
            device.as_ref(),
        ],
    )?;
    checkpoint("formatted", directory, device)?;
    command(
        "/sbin/mount",
        &[
            "-t".as_ref(),
            "hfs".as_ref(),
            "-o".as_ref(),
            "owners,nobrowse,nodev,nosuid,noexec".as_ref(),
            device.as_ref(),
            mount.as_os_str(),
        ],
    )?;
    let info = mount_info(&mount)?;
    validate_mount_flags(info.f_flags)?;
    checkpoint("mounted", directory, device)?;
    journal.filesystem = Some(fs::metadata(&mount)?.dev());
    if !journal.validate_mount()? {
        return Err(io::Error::other("RAM-disk mount did not appear"));
    }
    let metadata = fs::metadata(&mount)?;
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o777 != 0o700 {
        return Err(io::Error::other(
            "RAM-disk root permissions are not private",
        ));
    }
    journal.save(directory)?;
    Ok(())
}

fn checkpoint(stage: &str, directory: &Path, device: &str) -> io::Result<()> {
    #[cfg(test)]
    if let Some(test) = std::env::var_os("_FILE_LEASE_SETUP_TEST") {
        let test = PathBuf::from(test);
        if fs::read_to_string(test.join("stage"))? == stage {
            fs::write(
                test.join("ready"),
                serde_json::to_vec(&(directory, device, std::process::id()))?,
            )?;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            while !test.join("resume").exists() {
                if std::time::Instant::now() >= deadline {
                    return Err(io::Error::other("Setup checkpoint timed out"));
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }
    let _ = (stage, directory, device);
    Ok(())
}

struct Volume {
    directory: PathBuf,
    journal: Journal,
}
impl Volume {
    /// Pin and verify the mounted root before accessing payloads. A path-based
    /// check followed by a path-based write could reach the disk-backed mount
    /// directory if the RAM volume were unmounted between those operations.
    fn open_root(&self) -> io::Result<fs::File> {
        let (root, info) = self
            .journal
            .mounted_root()?
            .ok_or_else(|| io::Error::other("RAM-disk storage is no longer mounted"))?;
        if !self.journal.validate_device()? {
            return Err(io::Error::other("RAM-disk storage device disappeared"));
        }
        let metadata = root.metadata()?;
        if Some(metadata.dev()) != self.journal.filesystem
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o777 != 0o700
        {
            return Err(io::Error::other(
                "RAM-disk storage identity or permissions changed",
            ));
        }
        validate_mount_flags(info.f_flags)?;
        Ok(root)
    }

    fn create() -> io::Result<Self> {
        let root = runtime_root()?;
        recover_orphans(&root)?;
        let directory = tempfile::Builder::new()
            .prefix("lease-")
            .tempdir_in(&root)?;
        let mount = directory.path().join("memory");
        fs::DirBuilder::new().mode(0o700).create(&mount)?;
        let process = process_info(std::process::id())?;
        let journal = Journal {
            keeper: std::process::id(),
            birth: [process.pbi_start_tvsec, process.pbi_start_tvusec],
            lease_id: Some(uuid::Uuid::new_v4()),
            device: String::new(),
            mount: mount.clone(),
            filesystem: None,
            device_identity: None,
        };
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.path().join("setup.lock"))?;
        lock_exclusive(&lock, 0)?;
        journal.save(directory.path())?;
        // After attachment can start, metadata must survive every error path.
        let directory = directory.keep();
        let setup = (|| -> io::Result<Journal> {
            let mut worker = Command::new(std::env::current_exe()?);
            worker
                .env(SETUP_ENV, &directory)
                .stdin(Stdio::null())
                .stdout(Stdio::from(lock.try_clone()?))
                .stderr(Stdio::null())
                .process_group(0);
            #[cfg(test)]
            worker.args(["--exact", "tests::keeper_entry", "--nocapture"]);
            let mut worker = worker.spawn()?;
            let deadline = Instant::now() + SETUP_TIMEOUT;
            loop {
                if let Some(status) = worker.try_wait()? {
                    return Err(io::Error::other(format!(
                        "RAM-disk guardian exited during setup: {status}"
                    )));
                }
                if let Ok(ready) = fs::read_to_string(directory.join("setup.ready"))
                    && let Ok(pid) = ready.parse::<u32>()
                {
                    super::platform::reap_when_exited(worker);
                    if pid == 0 {
                        return Err(io::Error::other("RAM-disk setup failed"));
                    }
                    return Journal::read(&directory);
                }
                if Instant::now() >= deadline {
                    super::command::terminate(worker);
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "RAM-disk setup timed out",
                    ));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        })();
        drop(lock);
        match setup {
            Ok(journal) => Ok(Self { directory, journal }),
            Err(error) => {
                let _ = cleanup_with_retry(&directory);
                Err(error)
            }
        }
    }
}

#[derive(Default)]
pub(super) struct Storage {
    volume: Option<Volume>,
    counter: u64,
    files: std::collections::HashSet<PathBuf>,
}
impl Storage {
    pub(super) fn materialize(&mut self, bytes: &[u8], suffix: &str) -> io::Result<PathBuf> {
        if self.volume.is_none() {
            self.volume = Some(Volume::create()?);
        }
        let volume = self.volume.as_ref().unwrap();
        let root = volume.open_root()?;
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or_else(|| io::Error::other("Secret file namespace exhausted"))?;
        let name = format!("secret-{}{suffix}", self.counter);
        let name = std::ffi::CString::new(name).map_err(io::Error::other)?;
        let path = volume
            .journal
            .mount
            .join(std::ffi::OsStr::from_bytes(name.as_bytes()));
        let fd = unsafe {
            libc::openat(
                root.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600 as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut file = unsafe { fs::File::from_raw_fd(fd) };
        if let Err(error) = file
            .write_all(bytes)
            .and_then(|_| file.set_permissions(fs::Permissions::from_mode(0o400)))
        {
            unsafe { libc::unlinkat(root.as_raw_fd(), name.as_ptr(), 0) };
            return Err(error);
        }
        self.files.insert(path.clone());
        Ok(path)
    }
    pub(super) fn release(&mut self, path: &Path) -> io::Result<()> {
        if !self.files.contains(path) {
            return Err(io::Error::other("Path does not belong to this lease"));
        }
        let volume = self
            .volume
            .as_ref()
            .ok_or_else(|| io::Error::other("Secret storage is closed"))?;
        let root = volume.open_root()?;
        let name = path
            .strip_prefix(&volume.journal.mount)
            .ok()
            .filter(|name| name.components().count() == 1)
            .ok_or_else(|| io::Error::other("Invalid secret file path"))?;
        let name = std::ffi::CString::new(name.as_os_str().as_bytes()).map_err(io::Error::other)?;
        if unsafe { libc::unlinkat(root.as_raw_fd(), name.as_ptr(), 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
        self.files.remove(path);
        Ok(())
    }
    pub(super) fn cleanup(&mut self) -> io::Result<()> {
        if let Some(volume) = self.volume.take() {
            // Failed cleanup stays journaled. The guardian retries after this
            // keeper exits, and later leases remain a fallback if both die.
            cleanup_with_retry(&volume.directory)?;
        }
        Ok(())
    }
}
impl Drop for Storage {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        process::Child,
        sync::mpsc,
        time::{Duration, Instant},
    };

    #[test]
    fn all_security_mount_flags_are_required() {
        validate_mount_flags(REQUIRED_MOUNT_FLAGS).unwrap();
        for flag in [
            libc::MNT_NOEXEC,
            libc::MNT_NOSUID,
            libc::MNT_NODEV,
            libc::MNT_DONTBROWSE,
        ] {
            assert!(validate_mount_flags(REQUIRED_MOUNT_FLAGS & !(flag as u32)).is_err());
        }
        assert!(
            validate_mount_flags(REQUIRED_MOUNT_FLAGS | libc::MNT_IGNORE_OWNERSHIP as u32).is_err()
        );
    }

    #[test]
    fn unmounted_storage_never_writes_or_releases_on_the_backing_disk() {
        let lease = crate::FileLease::new(std::process::id());
        let path = lease.materialize(b"ram-only-fixture", None).unwrap();
        let mount = path.parent().unwrap();
        validate_mount_flags(mount_info(mount).unwrap().f_flags).unwrap();
        command("/sbin/umount", &["-f".as_ref(), mount.as_os_str()]).unwrap();
        // This is now the ordinary disk directory hidden by the RAM mount.
        // A release must not delete its unrelated file, and another allocation
        // must not put any payload bytes here.
        fs::write(&path, b"unrelated-disk-fixture").unwrap();
        let allocation = lease.materialize(b"must-not-reach-disk", None);
        let release = lease.release(&path);
        let disk_contents = fs::read(&path).unwrap();
        let disk_entries = fs::read_dir(mount).unwrap().count();
        fs::remove_file(&path).unwrap();
        let replacement = tempfile::tempdir().unwrap();
        fs::remove_dir(mount).unwrap();
        std::os::unix::fs::symlink(replacement.path(), mount).unwrap();
        let symlink_allocation = lease.materialize(b"must-not-follow-symlink", None);
        let replacement_entries = fs::read_dir(replacement.path()).unwrap().count();
        fs::remove_file(mount).unwrap();
        fs::DirBuilder::new().mode(0o700).create(mount).unwrap();
        drop(lease);
        assert!(allocation.is_err());
        assert!(release.is_err());
        assert!(symlink_allocation.is_err());
        assert_eq!(disk_contents, b"unrelated-disk-fixture");
        assert_eq!(disk_entries, 1);
        assert_eq!(replacement_entries, 0);
    }

    #[test]
    fn storage_rejects_weakened_root_permissions() {
        let lease = crate::FileLease::new(std::process::id());
        let path = lease.materialize(b"private-fixture", None).unwrap();
        let mount = path.parent().unwrap();
        fs::set_permissions(mount, fs::Permissions::from_mode(0o755)).unwrap();
        let allocation = lease.materialize(b"must-stay-private", None);
        fs::set_permissions(mount, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(allocation.is_err());
        assert_eq!(fs::read(&path).unwrap(), b"private-fixture");
    }

    #[test]
    fn storage_rejects_replaced_device_identity() {
        let lease = crate::FileLease::new(std::process::id());
        let path = lease.materialize(b"device-identity-fixture", None).unwrap();
        let directory = path.parent().unwrap().parent().unwrap().to_path_buf();
        let mut journal = Journal::read(&directory).unwrap();
        journal.device_identity = Some([0; 4]);
        let stale_volume = Volume { directory, journal };
        assert!(stale_volume.open_root().is_err());
        assert_eq!(fs::read(path).unwrap(), b"device-identity-fixture");
    }

    struct PausedSetup {
        test: tempfile::TempDir,
        keeper: Child,
        directory: PathBuf,
        worker: u32,
        id: uuid::Uuid,
    }
    impl PausedSetup {
        fn start(stage: &str) -> Self {
            let test = tempfile::tempdir().unwrap();
            fs::write(test.path().join("stage"), stage).unwrap();
            let mut keeper = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "macos::tests::create_entry", "--nocapture"])
                .env("_FILE_LEASE_CREATE_TEST", "1")
                .env("_FILE_LEASE_SETUP_TEST", test.path())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(30);
            let (directory, _device, worker): (PathBuf, String, u32) = loop {
                if let Ok(bytes) = fs::read(test.path().join("ready"))
                    && let Ok(ready) = serde_json::from_slice(&bytes)
                {
                    break ready;
                }
                if Instant::now() >= deadline || keeper.try_wait().unwrap().is_some() {
                    let _ = keeper.kill();
                    let _ = keeper.wait();
                    panic!("did not reach {stage} setup checkpoint");
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            let id = Journal::read(&directory).unwrap().lease_id.unwrap();
            Self {
                test,
                keeper,
                directory,
                worker,
                id,
            }
        }
        fn resume(&self) {
            unsafe {
                libc::kill(self.worker as _, libc::SIGCONT);
            }
            fs::write(self.test.path().join("resume"), "").unwrap();
        }
        fn wait_for_cleanup(&self, recover: bool) {
            let deadline = Instant::now() + Duration::from_secs(15);
            while (self.directory.exists() || registry::device(self.id).unwrap().is_some())
                && Instant::now() < deadline
            {
                if recover {
                    recover_orphans(&runtime_root().unwrap()).unwrap();
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            assert!(!self.directory.exists(), "journal survived recovery");
            // A concurrently starting lease may reuse the old disk number.
            // Its unique drive identifier must disappear, not every disk node
            // that happens to have the same name later.
            assert!(registry::device(self.id).unwrap().is_none());
        }
    }
    impl Drop for PausedSetup {
        fn drop(&mut self) {
            unsafe {
                libc::kill(self.worker as _, libc::SIGCONT);
            }
            let _ = fs::write(self.test.path().join("resume"), "");
            let _ = self.keeper.kill();
            let _ = self.keeper.wait();
        }
    }

    #[test]
    fn create_entry() {
        if std::env::var_os("_FILE_LEASE_CREATE_TEST").is_some() {
            let _volume = Volume::create().unwrap();
            panic!("setup checkpoint was not interrupted");
        }
    }

    #[test]
    fn guardian_cleans_keeper_death_during_setup_without_another_lease() {
        for stage in ["attaching", "attached", "formatted", "mounted"] {
            let mut paused = PausedSetup::start(stage);
            paused.keeper.kill().unwrap();
            paused.keeper.wait().unwrap();
            paused.resume();
            paused.wait_for_cleanup(false);
        }
    }

    #[test]
    fn worker_death_during_setup_is_recoverable() {
        for stage in ["attaching", "attached", "formatted", "mounted"] {
            let mut paused = PausedSetup::start(stage);
            assert_eq!(unsafe { libc::kill(paused.worker as _, libc::SIGKILL) }, 0);
            assert!(!paused.keeper.wait().unwrap().success());
            paused.wait_for_cleanup(true);
        }
    }

    #[test]
    fn stopped_setup_worker_does_not_block_other_leases() {
        let mut paused = PausedSetup::start("attached");
        assert_eq!(unsafe { libc::kill(paused.worker as _, libc::SIGSTOP) }, 0);
        paused.keeper.kill().unwrap();
        paused.keeper.wait().unwrap();
        let (sender, receiver) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let lease = crate::FileLease::new(std::process::id());
            let result = lease
                .materialize(b"independent-lease", None)
                .map(|path| (lease, path));
            let _ = sender.send(result);
        });
        let result = receiver.recv_timeout(Duration::from_secs(8));
        // Release the old worker even when a regression blocked the new lease.
        paused.resume();
        thread.join().unwrap();
        paused.wait_for_cleanup(true);
        let (_lease, path) = result
            .expect("a busy orphan blocked an unrelated lease")
            .unwrap();
        assert_eq!(fs::read(path).unwrap(), b"independent-lease");
    }

    fn lease_state(lease: &crate::FileLease) -> (PathBuf, PathBuf, uuid::Uuid, u32) {
        let path = lease.materialize(b"guardian-test", None).unwrap();
        let directory = path.parent().unwrap().parent().unwrap().to_path_buf();
        let journal = Journal::read(&directory).unwrap();
        let guardian = fs::read_to_string(directory.join("setup.ready"))
            .unwrap()
            .parse()
            .unwrap();
        (path, directory, journal.lease_id.unwrap(), guardian)
    }

    fn removed(directory: &Path, id: uuid::Uuid) {
        let deadline = Instant::now() + Duration::from_secs(15);
        while (directory.exists() || registry::device(id).unwrap().is_some())
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!directory.exists(), "guardian did not remove the journal");
        assert!(registry::device(id).unwrap().is_none());
    }

    #[test]
    fn guardian_survives_keeper_process_group_sigkill() {
        let lease = crate::FileLease::new(std::process::id());
        let (path, directory, id, _) = lease_state(&lease);
        let keeper = lease.keeper.lock().unwrap().as_ref().unwrap().pid();
        assert_eq!(unsafe { libc::kill(-(keeper as i32), libc::SIGKILL) }, 0);
        drop(lease);
        removed(&directory, id);
        assert!(!path.exists());
    }

    #[test]
    fn keeper_still_cleans_up_if_guardian_is_killed() {
        let lease = crate::FileLease::new(std::process::id());
        let (path, directory, id, guardian) = lease_state(&lease);
        assert_eq!(unsafe { libc::kill(guardian as i32, libc::SIGKILL) }, 0);
        assert_eq!(fs::read(&path).unwrap(), b"guardian-test");
        drop(lease);
        removed(&directory, id);
    }

    #[test]
    fn killing_both_processes_leaves_recoverable_metadata() {
        let lease = crate::FileLease::new(std::process::id());
        let (_, directory, id, guardian) = lease_state(&lease);
        let keeper = lease.keeper.lock().unwrap().as_ref().unwrap().pid();
        assert_eq!(unsafe { libc::kill(guardian as i32, libc::SIGKILL) }, 0);
        assert_eq!(unsafe { libc::kill(keeper as i32, libc::SIGKILL) }, 0);
        drop(lease);
        recover_orphans(&runtime_root().unwrap()).unwrap();
        removed(&directory, id);
    }

    #[test]
    fn transient_cleanup_failures_are_retried() {
        let mut attempts = 0;
        retry_cleanup(|| {
            attempts += 1;
            if attempts == 1 {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            } else {
                Ok(())
            }
        })
        .unwrap();
        assert_eq!(attempts, 2);
    }

    #[test]
    fn persistent_cleanup_failures_return_after_bounded_retries() {
        let mut attempts = 0;
        assert!(
            retry_cleanup(|| {
                attempts += 1;
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            })
            .is_err()
        );
        assert_eq!(attempts, 3);
    }
}
