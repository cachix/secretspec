use std::{
    fs::File,
    io::{self, Write},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::PathBuf,
};

pub(super) fn syscall_fd(result: libc::c_long) -> io::Result<OwnedFd> {
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    // A successful syscall returns a newly owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(result as i32) })
}

pub(super) fn watch_owner(pid: u32) -> io::Result<OwnedFd> {
    syscall_fd(unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) })
}

#[derive(Default)]
pub(super) struct Storage {
    files: Vec<File>,
}
impl Storage {
    pub(super) fn materialize(&mut self, bytes: &[u8], suffix: &str) -> io::Result<PathBuf> {
        if !suffix.is_empty() {
            return Err(io::Error::other(
                "File suffixes are unsupported for anonymous Linux files",
            ));
        }
        let file = anonymous_file(bytes)?;
        let path = PathBuf::from(format!(
            "/proc/{}/fd/{}",
            std::process::id(),
            file.as_raw_fd()
        ));
        self.files.push(file);
        Ok(path)
    }
    pub(super) fn cleanup(&mut self) -> io::Result<()> {
        self.files.clear();
        Ok(())
    }
}
fn anonymous_file(bytes: &[u8]) -> io::Result<File> {
    let fd = syscall_fd(unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            c"secretspec-secret".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    })?;
    let mut file = File::from(fd);
    file.write_all(bytes)?;
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o400) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}
