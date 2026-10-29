use std::{ffi::OsString, io, path::PathBuf};

/// Process metadata for embedders selecting a file lease consumer (0.22+).
///
/// This reports kernel metadata; the embedding application decides whether a
/// shell, export caller, or detached manager should own its paths.
pub struct ProcessInfo {
    /// Process ID.
    pub pid: u32,
    /// Parent process ID.
    pub parent: u32,
    /// Process group ID.
    pub group: u32,
    /// Whether this process has executed a program since being forked.
    pub executed: bool,
    /// Executable path.
    pub executable: PathBuf,
    /// Argument vector, including argv[0].
    pub arguments: Vec<OsString>,
}

impl ProcessInfo {
    /// Inspect a process without invoking a shell or exposing its environment.
    pub fn read(pid: u32) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::ffi::OsStringExt;
            let root = PathBuf::from(format!("/proc/{pid}"));
            let stat = std::fs::read_to_string(root.join("stat"))?;
            let fields: Vec<_> = stat
                .rsplit_once(')')
                .ok_or_else(|| io::Error::other("Invalid process status"))?
                .1
                .split_whitespace()
                .collect();
            let field = |index: usize| -> io::Result<u64> {
                fields
                    .get(index)
                    .and_then(|value| value.parse().ok())
                    .ok_or_else(|| io::Error::other("Invalid process status field"))
            };
            let mut arguments = std::fs::read(root.join("cmdline"))?;
            if arguments.last() == Some(&0) {
                arguments.pop();
            }
            Ok(Self {
                pid,
                parent: field(1)?.try_into().map_err(io::Error::other)?,
                group: field(2)?.try_into().map_err(io::Error::other)?,
                // PF_FORKNOEXEC from include/linux/sched.h.
                executed: field(6)? & 0x40 == 0,
                executable: std::fs::read_link(root.join("exe"))?,
                arguments: arguments
                    .split(|byte| *byte == 0)
                    .map(|arg| OsString::from_vec(arg.to_vec()))
                    .collect(),
            })
        }
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::ffi::OsStringExt;
            let info = super::macos::process_info(pid)?;
            let mut executable = vec![0u8; 4096];
            let length = unsafe {
                libc::proc_pidpath(
                    pid as _,
                    executable.as_mut_ptr().cast(),
                    executable.len() as _,
                )
            };
            if length <= 0 {
                return Err(io::Error::last_os_error());
            }
            executable.truncate(
                executable
                    .iter()
                    .position(|byte| *byte == 0)
                    .unwrap_or(length as usize),
            );
            let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as i32];
            let mut length = 0usize;
            if unsafe {
                libc::sysctl(
                    mib.as_mut_ptr(),
                    3,
                    std::ptr::null_mut(),
                    &mut length,
                    std::ptr::null_mut(),
                    0,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
            if length > 4 * 1024 * 1024 {
                return Err(io::Error::other("Oversized process argument buffer"));
            }
            // The kernel also returns the environment in this buffer. Erase it
            // when done and expose only the declared number of argv entries.
            let mut bytes = secrecy::zeroize::Zeroizing::new(vec![0u8; length]);
            if unsafe {
                libc::sysctl(
                    mib.as_mut_ptr(),
                    3,
                    bytes.as_mut_ptr().cast(),
                    &mut length,
                    std::ptr::null_mut(),
                    0,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
            bytes.truncate(length);
            let argc = i32::from_ne_bytes(
                bytes
                    .get(..4)
                    .ok_or_else(|| io::Error::other("Missing process argc"))?
                    .try_into()
                    .unwrap(),
            );
            if !(0..=65536).contains(&argc) {
                return Err(io::Error::other("Invalid process argc"));
            }
            let mut offset = 4;
            while offset < bytes.len() && bytes[offset] != 0 {
                offset += 1;
            }
            while offset < bytes.len() && bytes[offset] == 0 {
                offset += 1;
            }
            let mut arguments = Vec::new();
            for _ in 0..argc {
                let end = bytes
                    .get(offset..)
                    .and_then(|rest| rest.iter().position(|byte| *byte == 0))
                    .map(|end| offset + end)
                    .ok_or_else(|| io::Error::other("Truncated process arguments"))?;
                arguments.push(OsString::from_vec(bytes[offset..end].to_vec()));
                offset = end + 1;
            }
            Ok(Self {
                pid,
                parent: info.pbi_ppid,
                group: info.pbi_pgid,
                executed: info.pbi_flags & 0x4000 != 0,
                executable: PathBuf::from(OsString::from_vec(executable)),
                arguments,
            })
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = pid;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "File lease process inspection requires Linux or macOS",
            ))
        }
    }
}
