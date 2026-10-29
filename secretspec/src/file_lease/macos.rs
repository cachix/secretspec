use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    mem::MaybeUninit,
    os::{
        fd::{FromRawFd, OwnedFd},
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
    filesystem: u64,
    device_identity: [u64; 4],
}

impl Journal {
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
            || fs::metadata(&self.mount)?.dev() != self.filesystem
            || info.f_owner != unsafe { libc::geteuid() }
        {
            return Err(io::Error::other(
                "RAM-disk identity changed; refusing file lease cleanup",
            ));
        }
        Ok(true)
    }

    fn cleanup(&self) -> io::Result<()> {
        let metadata = match fs::metadata(&self.device) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        if device_identity(&metadata) != self.device_identity {
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
        let journal_path = directory.path().join("lease.json");
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&journal_path)
        {
            Ok(file) => file,
            Err(_) => continue,
        };
        if file.metadata()?.uid() != unsafe { libc::geteuid() } {
            continue;
        }
        let journal: Journal = match serde_json::from_reader(file.take(16384)) {
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
        // Another recovery process may win the race. A failed recovery remains
        // journaled for the next lease instead of causing a disk-file fallback.
        if journal.cleanup().is_ok() {
            let _ = fs::remove_file(journal_path);
            let _ = fs::remove_dir(&journal.mount);
            let _ = fs::remove_dir(directory.path());
        }
    }
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
        // This is a RAM-backed block device. No disk image file is created.
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
        let uid = unsafe { libc::geteuid() }.to_string();
        let gid = unsafe { libc::getegid() }.to_string();
        let setup = (|| -> io::Result<Journal> {
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
            let process = process_info(std::process::id())?;
            let journal = Journal {
                keeper: std::process::id(),
                birth: [process.pbi_start_tvsec, process.pbi_start_tvusec],
                device: device.clone(),
                mount: mount.clone(),
                filesystem: fs::metadata(&mount)?.dev(),
                device_identity: device_identity(&fs::metadata(&device)?),
            };
            if !journal.validate_mount()? {
                return Err(io::Error::other("RAM-disk mount did not appear"));
            }
            let metadata = fs::metadata(&mount)?;
            if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o777 != 0o700 {
                return Err(io::Error::other(
                    "RAM-disk root permissions are not private",
                ));
            }
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(directory.path().join("lease.json"))?;
            serde_json::to_writer(&mut file, &journal).map_err(io::Error::other)?;
            file.sync_all()?;
            Ok(journal)
        })();
        match setup {
            Ok(journal) => Ok(Self { directory, journal }),
            Err(error) => {
                // Setup has not received or written any secret bytes yet.
                if let Ok(info) = mount_info(&mount)
                    && c_string(&info.f_mntonname) == mount.as_os_str().as_bytes()
                {
                    let _ = command("/sbin/umount", &["-f".as_ref(), mount.as_os_str()]);
                }
                let _ = command(
                    "/usr/bin/hdiutil",
                    &["detach".as_ref(), "-force".as_ref(), device.as_ref()],
                );
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
