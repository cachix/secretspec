use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    mem::MaybeUninit,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
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

fn command(program: &str, args: &[&std::ffi::OsStr]) -> io::Result<Vec<u8>> {
    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()?;
    if !output.status.success() {
        // All commands here operate on volume metadata, never secret bytes.
        return Err(io::Error::other(format!(
            "{program}: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(output.stdout)
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
    let root = PathBuf::from(home).join("Library/Application Support/secretspec/file-leases");
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
    device: String,
    mount: PathBuf,
    filesystem: Option<u64>,
    device_identity: Option<[u64; 4]>,
}

impl Journal {
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
        if !self.device.strip_prefix("/dev/disk").is_some_and(|digits| {
            !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
        }) {
            return Err(io::Error::other(
                "Invalid RAM-disk device in file lease journal",
            ));
        }
        let info = mount_info(&self.mount)?;
        if c_string(&info.f_mntonname) != self.mount.as_os_str().as_bytes() {
            return Ok(false);
        }
        if c_string(&info.f_fstypename) != b"hfs"
            || c_string(&info.f_mntfromname) != self.device.as_bytes()
            || self.filesystem.is_some_and(|device| {
                fs::metadata(&self.mount).map_or(true, |metadata| metadata.dev() != device)
            })
            || info.f_owner != unsafe { libc::geteuid() }
        {
            return Err(io::Error::other(
                "RAM-disk identity changed; refusing file lease cleanup",
            ));
        }
        Ok(true)
    }

    fn cleanup(&self) -> io::Result<()> {
        if self.device.is_empty() {
            return Ok(());
        }
        let metadata = match fs::metadata(&self.device) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        if Some(device_identity(&metadata)) != self.device_identity {
            return Err(io::Error::other("RAM-disk device identity changed"));
        }
        if !self.validate_mount()? {
            command(
                "/usr/bin/hdiutil",
                &["detach".as_ref(), "-force".as_ref(), self.device.as_ref()],
            )?;
            return Ok(());
        }
        // Remove all readable names first, even if a later unmount fails.
        for entry in fs::read_dir(&self.mount)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                fs::remove_file(entry.path())?;
            }
        }
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
        let mut journal = match Journal::read(&directory.path()) {
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
        // The setup worker inherits this lock, so killing the keeper
        // cannot expose an attached device before its identity is journaled.
        let lock = match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(directory.path().join("setup.lock"))
        {
            Ok(lock) => lock,
            Err(_) => continue,
        };
        if lock.metadata()?.uid() != unsafe { libc::geteuid() } {
            continue;
        }
        flock(&lock)?;
        if let Ok(updated) = Journal::read(&directory.path()) {
            journal = updated;
        } else {
            continue;
        }
        // Another recovery process may win the race. A failed recovery remains
        // journaled for the next lease instead of causing a disk-file fallback.
        if journal.cleanup().is_ok() {
            let _ = fs::remove_dir(&journal.mount);
            // Also remove atomic-write remnants left by an interrupted setup.
            for entry in fs::read_dir(directory.path())? {
                let entry = entry?;
                if entry.file_type()?.is_file() {
                    let _ = fs::remove_file(entry.path());
                }
            }
            let _ = fs::remove_dir(directory.path());
        }
    }
    Ok(())
}

const SETUP_ENV: &str = "_SECRETSPEC_FILE_SETUP_DIRECTORY";

fn flock(file: &fs::File) -> io::Result<()> {
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

pub(super) fn maybe_run_setup() -> Option<io::Result<()>> {
    let directory = std::env::var_os(SETUP_ENV)?;
    Some(setup_device(Path::new(&directory)))
}

fn setup_device(directory: &Path) -> io::Result<()> {
    let mut journal = Journal::read(directory)?;
    // stdout holds the inherited setup lock until this worker exits. It must
    // finish or roll back setup even if the keeper is killed meanwhile.
    let output = command(
        "/usr/bin/hdiutil",
        &[
            "attach".as_ref(),
            "-nomount".as_ref(),
            "ram://131072".as_ref(),
        ],
    )?;
    let device = String::from_utf8(output)
        .map_err(io::Error::other)?
        .split_whitespace()
        .next()
        .ok_or_else(|| io::Error::other("RAM-disk attachment returned no device"))?
        .to_owned();
    if !device.strip_prefix("/dev/disk").is_some_and(|digits| {
        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
    }) {
        return Err(io::Error::other(
            "RAM-disk attachment returned an invalid device",
        ));
    }
    journal.device_identity = Some(device_identity(&fs::metadata(&device)?));
    journal.device = device;
    let mount = journal.mount.clone();
    let uid = unsafe { libc::geteuid() }.to_string();
    let gid = unsafe { libc::getegid() }.to_string();
    let result = (|| -> io::Result<()> {
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
        // MNT_UNKNOWNPERMISSIONS: the filesystem must honor ownership.
        if info.f_flags & libc::MNT_IGNORE_OWNERSHIP as u32 != 0 {
            return Err(io::Error::other("RAM disk does not honor file ownership"));
        }
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
    })();
    let owner_alive = process_info(journal.keeper)
        .is_ok_and(|info| [info.pbi_start_tvsec, info.pbi_start_tvusec] == journal.birth);
    if result.is_err() || !owner_alive {
        journal.cleanup()?;
    }
    result
}

fn checkpoint(stage: &str, directory: &Path, device: &str) -> io::Result<()> {
    #[cfg(test)]
    if let Some(test) = std::env::var_os("_SECRETSPEC_FILE_SETUP_TEST") {
        let test = PathBuf::from(test);
        if fs::read_to_string(test.join("stage"))? == stage {
            fs::write(
                test.join("ready"),
                serde_json::to_vec(&(directory, device))?,
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
    directory: tempfile::TempDir,
    journal: Journal,
}
impl Volume {
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
        flock(&lock)?;
        journal.save(directory.path())?;
        let setup = (|| -> io::Result<Journal> {
            let mut worker = Command::new(std::env::current_exe()?);
            worker
                .env(SETUP_ENV, directory.path())
                .stdin(Stdio::null())
                .stdout(Stdio::from(lock.try_clone()?))
                .stderr(Stdio::null());
            #[cfg(test)]
            worker.args(["--exact", "file_lease::tests::keeper_entry", "--nocapture"]);
            if !worker.status()?.success() {
                return Err(io::Error::other("RAM-disk setup worker failed"));
            }
            Journal::read(directory.path())
        })();
        match setup {
            Ok(journal) => Ok(Self { directory, journal }),
            Err(error) => {
                // Keep a recoverable record if detachment itself fails.
                if Journal::read(directory.path())
                    .and_then(|journal| journal.cleanup())
                    .is_err()
                {
                    let _ = directory.keep();
                }
                Err(error)
            }
        }
    }
}

#[derive(Default)]
pub(super) struct Storage {
    volume: Option<Volume>,
    counter: u64,
}
impl Storage {
    pub(super) fn materialize(&mut self, bytes: &[u8], suffix: &str) -> io::Result<PathBuf> {
        if self.volume.is_none() {
            self.volume = Some(Volume::create()?);
        }
        let volume = self.volume.as_ref().unwrap();
        self.counter += 1;
        let path = volume
            .journal
            .mount
            .join(format!("secret-{}{suffix}", self.counter));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        if let Err(error) = file
            .write_all(bytes)
            .and_then(|_| file.set_permissions(fs::Permissions::from_mode(0o400)))
        {
            let _ = fs::remove_file(&path);
            return Err(error);
        }
        Ok(path)
    }
    pub(super) fn cleanup(&mut self) -> io::Result<()> {
        if let Some(volume) = self.volume.take() {
            if let Err(error) = volume.journal.cleanup() {
                // Preserve the metadata for automatic orphan recovery. It has
                // no secret contents, only process and volume identities.
                let _ = volume.directory.keep();
                return Err(error);
            }
            volume.directory.close()?;
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
    use std::time::{Duration, Instant};

    #[test]
    fn create_entry() {
        if std::env::var_os("_SECRETSPEC_FILE_CREATE_TEST").is_some() {
            let _volume = Volume::create().unwrap();
            // The parent test kills this process at a setup checkpoint.
            panic!("setup checkpoint was not reached");
        }
    }

    #[test]
    fn keeper_death_during_setup_is_recoverable() {
        for stage in ["attached", "formatted", "mounted"] {
            let test = tempfile::tempdir().unwrap();
            fs::write(test.path().join("stage"), stage).unwrap();
            let mut keeper = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "file_lease::macos::tests::create_entry",
                    "--nocapture",
                ])
                .env("_SECRETSPEC_FILE_CREATE_TEST", "1")
                .env("_SECRETSPEC_FILE_SETUP_TEST", test.path())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(30);
            let (directory, device): (PathBuf, String) = loop {
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
            assert!(Path::new(&device).exists());
            keeper.kill().unwrap();
            keeper.wait().unwrap();
            fs::write(test.path().join("resume"), "").unwrap();
            // Recovery waits for an in-flight attachment to journal its device.
            recover_orphans(&runtime_root().unwrap()).unwrap();
            assert!(
                !Path::new(&device).exists(),
                "{stage}: device survived recovery"
            );
            assert!(!directory.exists(), "{stage}: journal survived recovery");
        }
    }
}
