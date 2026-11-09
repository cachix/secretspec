//! SecretSpec integration for process-owned file delivery (0.22+).
//!
//! Storage and process lifecycle management are provided by [`::file_lease`].

pub use ::file_lease::ProcessInfo;
#[cfg(feature = "cli")]
pub(crate) use ::file_lease::maybe_run_helper as maybe_run_keeper;
use std::{
    io,
    path::{Path, PathBuf},
};

/// A cloneable lease on memory-backed secret files (0.22+).
///
/// SecretSpec allocates leases automatically. Install an explicit lease before
/// validation to choose its consuming process. Resolved values retain it. Dropping the
/// final owner releases files unless ownership has been handed to a consumer.
/// The matching SecretSpec executable must be alongside the host or on PATH.
#[derive(Clone)]
pub struct FileLease(::file_lease::FileLease);

impl FileLease {
    /// Create a lease, lazily allocating resources on the first file secret.
    pub fn new(owner: u32) -> Self {
        let configured = std::env::var_os("SECRETSPEC_BIN")
            .filter(|path| !path.is_empty())
            .map(PathBuf::from);
        let sibling = std::env::current_exe()
            .ok()
            .map(|path| {
                // Cargo places test executables in `deps`, beside the directory
                // containing the matching CLI built by `cargo test`.
                if cfg!(debug_assertions)
                    && path.parent().and_then(Path::file_name) == Some(std::ffi::OsStr::new("deps"))
                {
                    path.parent().unwrap().parent().unwrap().join("secretspec")
                } else {
                    path.with_file_name("secretspec")
                }
            })
            .filter(|path| path.is_file());
        Self(
            ::file_lease::FileLease::new(owner).with_helper_executable(
                configured
                    .or(sibling)
                    .unwrap_or_else(|| PathBuf::from("secretspec")),
            ),
        )
    }

    /// Select the matching SecretSpec executable before cloning or installing.
    pub fn with_keeper_executable(self, executable: impl Into<PathBuf>) -> Self {
        Self(self.0.with_helper_executable(executable))
    }

    /// Deliver validated file secrets directly into this lease's storage.
    pub fn install(&self, secrets: &mut crate::Secrets) {
        let lease = self.clone();
        secrets.set_as_path_materializer(move |bytes, suffix| lease.materialize(bytes, suffix));
    }

    /// Materialize logical bytes directly into memory-backed storage.
    pub fn materialize(&self, bytes: &[u8], suffix: Option<&str>) -> io::Result<PathBuf> {
        self.materialize_file(bytes, suffix)
            .map(::file_lease::LeasedFile::into_path)
    }

    fn materialize_file(
        &self,
        bytes: &[u8],
        suffix: Option<&str>,
    ) -> io::Result<::file_lease::LeasedFile> {
        let mut options = ::file_lease::FileOptions::new();
        if let Some(suffix) = suffix {
            options = options.suffix(suffix);
        }
        self.0.materialize_with(bytes, &options).map_err(Into::into)
    }

    /// Keep exported files until the original consuming process exits.
    pub fn handoff(&self) -> io::Result<()> {
        self.0.handoff().map_err(Into::into)
    }

    /// Transfer an existing lease to another consuming process.
    pub fn handoff_to(&self, owner: u32) -> io::Result<()> {
        self.0.handoff_to(owner).map_err(Into::into)
    }
}

#[derive(Clone, Copy)]
pub(crate) enum DetachedOwner {
    Process(u32),
    #[cfg(feature = "cli")]
    Invoker,
}

/// Reuse storage while files from this manager remain live. Weak ownership
/// releases idle helpers and RAM volumes without keeping results alive.
#[derive(Default)]
pub(crate) struct FileStorage(std::sync::Mutex<std::sync::Weak<FileLease>>);

impl FileStorage {
    pub(crate) fn materialize(&self, bytes: &[u8], suffix: Option<&str>) -> io::Result<SecretFile> {
        let mut cached = self
            .0
            .lock()
            .map_err(|_| io::Error::other("Secret file storage poisoned"))?;
        let lease = cached.upgrade();
        let (lease, file) = match lease {
            Some(lease) => match lease.materialize_file(bytes, suffix) {
                Ok(file) => (lease, file),
                Err(_) => {
                    // A full volume, exhausted descriptor namespace, or failed
                    // helper must not affect existing readers. Try fresh memory
                    // storage once; never fall back to a disk-backed file.
                    let lease = std::sync::Arc::new(FileLease::new(std::process::id()));
                    let file = lease.materialize_file(bytes, suffix)?;
                    (lease, file)
                }
            },
            None => {
                let lease = std::sync::Arc::new(FileLease::new(std::process::id()));
                let file = lease.materialize_file(bytes, suffix)?;
                (lease, file)
            }
        };
        *cached = std::sync::Arc::downgrade(&lease);
        Ok(SecretFile(std::sync::Arc::new(SecretFileInner {
            file,
            lease,
            revoke_on_drop: std::sync::atomic::AtomicBool::new(true),
        })))
    }
}

/// One secret path. Files from a resolution share a helper, but can be revoked
/// independently, including when a resolver client releases an individual path.
#[derive(Clone)]
pub(crate) struct SecretFile(std::sync::Arc<SecretFileInner>);

struct SecretFileInner {
    file: ::file_lease::LeasedFile,
    lease: std::sync::Arc<FileLease>,
    revoke_on_drop: std::sync::atomic::AtomicBool,
}

impl SecretFile {
    pub(crate) fn path(&self) -> &Path {
        self.0.file.path()
    }

    pub(crate) fn storage_id(&self) -> usize {
        std::sync::Arc::as_ptr(&self.0.lease) as usize
    }

    pub(crate) fn handoff_to(&self, owner: u32) -> io::Result<()> {
        self.0.lease.handoff_to(owner)
    }

    pub(crate) fn keep(self, owner: DetachedOwner) -> io::Result<PathBuf> {
        if matches!(owner, DetachedOwner::Process(pid) if pid == std::process::id()) {
            retained_files()
                .lock()
                .map_err(|_| io::Error::other("Secret file registry poisoned"))?
                .insert(self.path().to_path_buf(), self.clone());
            return Ok(self.path().to_path_buf());
        }
        let owner = match owner {
            DetachedOwner::Process(pid) => pid,
            #[cfg(feature = "cli")]
            DetachedOwner::Invoker => invoking_process()?,
        };
        self.0.lease.handoff_to(owner)?;
        self.0
            .revoke_on_drop
            .store(false, std::sync::atomic::Ordering::Release);
        Ok(self.path().to_path_buf())
    }
}

fn retained_files() -> &'static std::sync::Mutex<std::collections::HashMap<PathBuf, SecretFile>> {
    static FILES: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<PathBuf, SecretFile>>,
    > = std::sync::OnceLock::new();
    FILES.get_or_init(Default::default)
}

fn retained_groups() -> &'static std::sync::Mutex<std::collections::HashMap<String, Vec<PathBuf>>> {
    static GROUPS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, Vec<PathBuf>>>,
    > = std::sync::OnceLock::new();
    GROUPS.get_or_init(Default::default)
}

pub(crate) fn retain_group(paths: Vec<PathBuf>) -> io::Result<Option<String>> {
    if paths.is_empty() {
        return Ok(None);
    }
    let id = uuid::Uuid::new_v4().to_string();
    retained_groups()
        .lock()
        .map_err(|_| io::Error::other("Secret file registry poisoned"))?
        .insert(id.clone(), paths);
    Ok(Some(id))
}

/// Read only a file retained by this result, opening its original lease path
/// without the pathname canonicalization performed by PHP's file wrapper.
pub(crate) fn read_group_file(id: &str, path: &Path) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let groups = retained_groups()
        .lock()
        .map_err(|_| io::Error::other("Secret file registry poisoned"))?;
    if !groups
        .get(id)
        .is_some_and(|paths| paths.iter().any(|p| p == path))
    {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "File does not belong to a live result",
        ));
    }
    let files = retained_files()
        .lock()
        .map_err(|_| io::Error::other("Secret file registry poisoned"))?;
    let file = files
        .get(path)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Secret file has been released"))?;
    // Open while holding the registry locks so concurrent release cannot revoke
    // the path before the descriptor is acquired. The read can then finish even
    // if the result closes, like any already-open file consumer.
    let file = std::fs::File::open(file.path())?;
    drop(files);
    drop(groups);
    const MAX_BYTES: u64 = 64 * 1024 * 1024;
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Secret file exceeds 64 MiB",
        ));
    }
    Ok(bytes)
}

/// Release a result's visible and hidden file dependencies. Tokens are local to
/// this process, idempotent, and can never request deletion of arbitrary paths.
pub(crate) fn release_group(id: &str) -> io::Result<usize> {
    let paths = retained_groups()
        .lock()
        .map_err(|_| io::Error::other("Secret file registry poisoned"))?
        .remove(id)
        .unwrap_or_default();
    let mut released = 0;
    let mut failed = Vec::new();
    let mut first_error = None;
    for path in paths {
        let file = retained_files()
            .lock()
            .map_err(|_| io::Error::other("Secret file registry poisoned"))?
            .remove(&path);
        if let Some(file) = file {
            if let Err(error) = file
                .0
                .lease
                .0
                .release(&file.0.file)
                .map_err(io::Error::from)
                && path.exists()
            {
                retained_files()
                    .lock()
                    .map_err(|_| io::Error::other("Secret file registry poisoned"))?
                    .insert(path.clone(), file);
                failed.push(path);
                first_error.get_or_insert(error);
                continue;
            }
            file.0
                .revoke_on_drop
                .store(false, std::sync::atomic::Ordering::Release);
            released += 1;
        }
    }
    if let Some(error) = first_error {
        retained_groups()
            .lock()
            .map_err(|_| io::Error::other("Secret file registry poisoned"))?
            .insert(id.to_owned(), failed);
        return Err(error);
    }
    Ok(released)
}

impl Drop for SecretFileInner {
    fn drop(&mut self) {
        if self
            .revoke_on_drop
            .load(std::sync::atomic::Ordering::Acquire)
        {
            let _ = self.lease.0.release(&self.file);
        }
    }
}

/// Select the invoking process for CLI paths that outlive SecretSpec. Shell
/// command substitutions may insert forked shell processes that have never
/// exec'd; their parent owns the exported paths.
#[cfg(feature = "cli")]
pub(crate) fn invoking_process() -> io::Result<u32> {
    let mut pid = ProcessInfo::read(std::process::id())?.parent;
    for _ in 0..64 {
        let process = ProcessInfo::read(pid)?;
        if process.executed {
            return Ok(pid);
        }
        if process.parent == 0 || process.parent == pid {
            break;
        }
        pid = process.parent;
    }
    Err(io::Error::other(
        "Cannot identify the consumer of exported secret paths",
    ))
}
