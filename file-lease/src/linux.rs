use std::{
    fs::File,
    io::{self, Write},
    os::fd::{AsRawFd, OwnedFd},
    path::PathBuf,
};

pub(super) fn watch_owner(pid: u32) -> io::Result<OwnedFd> {
    let pid = rustix::process::Pid::from_raw(pid as i32)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid owner PID"))?;
    Ok(rustix::process::pidfd_open(
        pid,
        rustix::process::PidfdFlags::empty(),
    )?)
}

#[derive(Default)]
pub(super) struct Storage {
    files: Vec<LockedFile>,
    next_fd: i32,
}
impl Storage {
    pub(super) fn materialize(&mut self, bytes: &[u8], _suffix: &str) -> io::Result<PathBuf> {
        let mut file = anonymous_file(bytes)?;
        // Never reuse a revoked pathname for a later allocation in this helper.
        file.file = File::from(rustix::io::fcntl_dupfd_cloexec(
            &file.file,
            self.next_fd.max(3),
        )?);
        self.next_fd = file
            .file
            .as_raw_fd()
            .checked_add(1)
            .ok_or_else(|| io::Error::other("File lease descriptor space exhausted"))?;
        let path = PathBuf::from(format!(
            "/proc/{}/fd/{}",
            std::process::id(),
            file.file.as_raw_fd()
        ));
        self.files.push(file);
        Ok(path)
    }
    pub(super) fn release(&mut self, path: &std::path::Path) -> io::Result<()> {
        let prefix = PathBuf::from(format!("/proc/{}/fd", std::process::id()));
        let fd = path
            .strip_prefix(prefix)
            .ok()
            .and_then(|p| p.to_str())
            .and_then(|fd| fd.parse::<i32>().ok());
        let index = self
            .files
            .iter()
            .position(|file| Some(file.file.as_raw_fd()) == fd)
            .ok_or_else(|| io::Error::other("Path does not belong to this lease"))?;
        self.files.swap_remove(index);
        Ok(())
    }
    pub(super) fn cleanup(&mut self) -> io::Result<()> {
        self.files.clear();
        Ok(())
    }
}

// Close the descriptor before unmapping and unlocking its pages on drop.
struct LockedFile {
    file: File,
    _mapping: Option<LockedMapping>,
}

struct LockedMapping {
    address: *mut libc::c_void,
    length: usize,
}

// The mapping is exclusively owned and exposes no Rust references. Moving its
// guard between threads does not change the mapping or its process-wide lock.
unsafe impl Send for LockedMapping {}

impl LockedMapping {
    fn new(file: &File, length: usize) -> io::Result<Self> {
        // A read-only descriptor prevents VM_MAYWRITE on this shared mapping,
        // allowing F_SEAL_WRITE while the mapping remains locked and alive.
        let reader = File::open(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_READ,
                libc::MAP_SHARED,
                reader.as_raw_fd(),
                0,
            )
        };
        if address == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let mapping = Self { address, length };
        if unsafe { libc::madvise(address, length, libc::MADV_DONTDUMP) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // Populate and lock zero-filled pages before any secret bytes reach
        // the memfd. Do not silently accept pageable storage on failure.
        if unsafe { libc::mlock(address, length) } < 0 {
            return Err(io::Error::other(format!(
                "Could not lock secret file pages into RAM; check RLIMIT_MEMLOCK: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(mapping)
    }
}

impl Drop for LockedMapping {
    fn drop(&mut self) {
        // Unmapping also releases the memory lock, including on error paths.
        unsafe { libc::munmap(self.address, self.length) };
    }
}

fn anonymous_file(bytes: &[u8]) -> io::Result<LockedFile> {
    use rustix::fs::{MemfdFlags, Mode, SealFlags, fchmod, fcntl_add_seals, memfd_create};

    let fd = memfd_create(
        "file-lease",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )?;
    let file = File::from(fd);
    fchmod(&file, Mode::RUSR)?;
    file.set_len(bytes.len() as u64)?;
    let mut file = LockedFile {
        file,
        _mapping: None,
    };
    if !bytes.is_empty() {
        file._mapping = Some(LockedMapping::new(&file.file, bytes.len())?);
    }
    file.file.write_all(bytes)?;
    fcntl_add_seals(
        &file.file,
        SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL,
    )?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use crate::FileLease;
    use std::{fs, process::Command};

    fn page_size() -> usize {
        let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        assert!(size > 0);
        size as usize
    }

    fn keeper_pid(lease: &FileLease) -> u32 {
        lease.keeper.lock().unwrap().as_ref().unwrap().pid()
    }

    fn locked_bytes(pid: u32) -> usize {
        let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        status
            .lines()
            .find(|line| line.starts_with("VmLck:"))
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse::<usize>()
            .unwrap()
            * 1024
    }

    #[test]
    fn lease_pages_are_locked_excluded_from_dumps_and_unlocked_on_release() {
        let lease = FileLease::new(std::process::id());
        let first = lease.materialize(b"first", None).unwrap();
        let pid = keeper_pid(&lease);
        let page = page_size();
        assert_eq!(locked_bytes(pid), page);
        let bytes = vec![b'x'; page + 1];
        let second = lease.materialize(&bytes, None).unwrap();
        assert_eq!(fs::read(&second).unwrap(), bytes);
        assert_eq!(locked_bytes(pid), page * 3);
        let maps = fs::read_to_string(format!("/proc/{pid}/smaps")).unwrap();
        let flags = maps
            .split_once("/memfd:file-lease")
            .unwrap()
            .1
            .lines()
            .find(|line| line.starts_with("VmFlags:"))
            .unwrap();
        for flag in ["lo", "dd"] {
            assert!(
                flags.split_whitespace().any(|value| value == flag),
                "missing {flag}: {flags}"
            );
        }
        lease.release(&first).unwrap();
        assert_eq!(locked_bytes(pid), page * 2);
        lease.release(&second).unwrap();
        assert_eq!(locked_bytes(pid), 0);
        let empty = lease.materialize(b"", None).unwrap();
        assert!(fs::read(empty).unwrap().is_empty());
        assert_eq!(locked_bytes(pid), 0);
    }

    #[test]
    fn memlock_limit_child() {
        let Ok(mode) = std::env::var("_FILE_LEASE_MEMLOCK_TEST") else {
            return;
        };
        let status = fs::read_to_string("/proc/self/status").unwrap();
        let caps = status
            .lines()
            .find(|line| line.starts_with("CapEff:"))
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap();
        if u64::from_str_radix(caps, 16).unwrap() & (1 << 14) != 0 {
            // Privileged processes deliberately bypass this kernel limit.
            eprintln!("Skipping RLIMIT_MEMLOCK assertions: CAP_IPC_LOCK is effective");
            return;
        }
        let budget = if mode == "zero" { 0 } else { page_size() };
        let limit = libc::rlimit {
            rlim_cur: budget as _,
            rlim_max: budget as _,
        };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) }, 0);
        let lease = FileLease::new(std::process::id());
        if budget == 0 {
            let error = lease
                .materialize(b"must-not-be-pageable", None)
                .unwrap_err();
            assert!(error.to_string().contains("RLIMIT_MEMLOCK"), "{error}");
            // Failure must leave the helper usable and the reply stream aligned.
            let empty = lease.materialize(b"", None).unwrap();
            assert!(fs::read(empty).unwrap().is_empty());
            assert_eq!(locked_bytes(keeper_pid(&lease)), 0);
        } else {
            let first = lease.materialize(b"budget-fixture", None).unwrap();
            let pid = keeper_pid(&lease);
            let error = lease.materialize(b"over-budget", None).unwrap_err();
            assert!(error.to_string().contains("RLIMIT_MEMLOCK"), "{error}");
            assert_eq!(fs::read(&first).unwrap(), b"budget-fixture");
            assert_eq!(locked_bytes(pid), budget);
            lease.release(&first).unwrap();
            assert_eq!(locked_bytes(pid), 0);
            let next = lease.materialize(b"reclaimed-budget", None).unwrap();
            assert_ne!(first, next);
            assert_eq!(fs::read(&next).unwrap(), b"reclaimed-budget");
            lease.release(&next).unwrap();
            assert_eq!(locked_bytes(pid), 0);
        }
    }

    #[test]
    fn insufficient_lock_budget_fails_closed_and_release_reclaims_it() {
        for mode in ["zero", "page"] {
            assert!(
                Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "linux::tests::memlock_limit_child",
                        "--nocapture"
                    ])
                    .env("_FILE_LEASE_MEMLOCK_TEST", mode)
                    .status()
                    .unwrap()
                    .success()
            );
        }
    }
}
