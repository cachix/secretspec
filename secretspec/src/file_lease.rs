//! Temporary files and opt-in process-owned file delivery (0.22+).
//!
//! Ordinary files use `tempfile`; memory-backed storage and process lifecycle
//! management are provided by [`::file_lease`].

#[cfg(feature = "cli")]
use ::file_lease::ProcessInfo;
#[cfg(feature = "cli")]
pub(crate) use ::file_lease::maybe_run_helper as maybe_run_keeper;
use std::{
    collections::HashMap,
    io,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard, OnceLock, Weak,
        atomic::{AtomicBool, Ordering},
    },
};

/// A cloneable lease on memory-backed secret files (0.22+).
///
/// Temporary files are the default. Install an explicit lease before
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

/// Storage used for `as_path` secret delivery (0.22+).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum FileStorageMode {
    /// Ordinary private temporary files, removed when their owner is dropped.
    #[default]
    Temp,
    /// Process-owned memory-backed files, without a disk fallback.
    FileLease,
}

/// Reuse leased storage without retaining resolved results.
#[derive(Default)]
pub(crate) struct FileStorage {
    mode: FileStorageMode,
    cached: Mutex<Weak<FileLease>>,
}

impl FileStorage {
    pub(crate) fn new(mode: FileStorageMode) -> Self {
        Self {
            mode,
            cached: Default::default(),
        }
    }

    pub(crate) fn fresh(&self) -> Self {
        Self {
            mode: self.mode,
            cached: Default::default(),
        }
    }

    pub(crate) fn materialize(&self, bytes: &[u8], suffix: Option<&str>) -> io::Result<SecretFile> {
        if self.mode == FileStorageMode::Temp {
            use std::io::Write;
            let mut file = tempfile::Builder::new()
                .suffix(suffix.unwrap_or(""))
                .tempfile_in(std::path::absolute(std::env::temp_dir())?)?;
            file.write_all(bytes)?;
            file.flush()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.as_file()
                    .set_permissions(std::fs::Permissions::from_mode(0o400))?;
            }
            return Ok(SecretFile(Arc::new(SecretFileInner {
                path: file.path().to_owned(),
                resource: FileResource::Temporary(Mutex::new(file)),
                revoke_on_drop: AtomicBool::new(true),
            })));
        }
        let mut cached = self
            .cached
            .lock()
            .map_err(|_| io::Error::other("Secret file storage poisoned"))?;
        let existing = cached.upgrade().and_then(|lease| {
            lease
                .materialize_file(bytes, suffix)
                .ok()
                .map(|file| (lease, file))
        });
        let (lease, file) = match existing {
            Some(existing) => existing,
            None => {
                // If existing storage failed, retry once with a fresh lease,
                // preserving existing readers and never falling back to disk.
                let lease = Arc::new(FileLease::new(std::process::id()));
                let file = lease.materialize_file(bytes, suffix)?;
                (lease, file)
            }
        };
        *cached = Arc::downgrade(&lease);
        Ok(SecretFile(Arc::new(SecretFileInner {
            path: file.path().to_owned(),
            resource: FileResource::Leased { file, lease },
            revoke_on_drop: AtomicBool::new(true),
        })))
    }
}

/// One owned secret path, backed by a temporary file or an explicit lease.
#[derive(Clone)]
pub(crate) struct SecretFile(Arc<SecretFileInner>);

enum FileResource {
    Temporary(Mutex<tempfile::NamedTempFile>),
    Leased {
        file: ::file_lease::LeasedFile,
        lease: Arc<FileLease>,
    },
}

struct SecretFileInner {
    path: PathBuf,
    resource: FileResource,
    revoke_on_drop: AtomicBool,
}

impl SecretFileInner {
    fn release(&self) -> io::Result<()> {
        match &self.resource {
            FileResource::Temporary(file) => {
                let mut file = file
                    .lock()
                    .map_err(|_| io::Error::other("Temporary file poisoned"))?;
                match std::fs::remove_file(&self.path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
                file.disable_cleanup(true);
                Ok(())
            }
            FileResource::Leased { file, lease } => lease.0.release(file).map_err(Into::into),
        }
    }
}

impl SecretFile {
    pub(crate) fn path(&self) -> &Path {
        &self.0.path
    }

    pub(crate) fn storage_id(&self) -> usize {
        match &self.0.resource {
            FileResource::Temporary(_) => Arc::as_ptr(&self.0) as usize,
            FileResource::Leased { lease, .. } => Arc::as_ptr(lease) as usize,
        }
    }

    pub(crate) fn handoff_to(&self, owner: u32) -> io::Result<()> {
        match &self.0.resource {
            FileResource::Temporary(_) => Ok(()),
            FileResource::Leased { lease, .. } => lease.handoff_to(owner),
        }
    }

    pub(crate) fn keep(self, owner: DetachedOwner) -> io::Result<PathBuf> {
        if matches!(owner, DetachedOwner::Process(pid) if pid == std::process::id()) {
            registry()?
                .files
                .insert(self.path().to_path_buf(), self.clone());
            return Ok(self.path().to_path_buf());
        }
        match &self.0.resource {
            FileResource::Temporary(file) => {
                file.lock()
                    .map_err(|_| io::Error::other("Temporary file poisoned"))?
                    .disable_cleanup(true);
            }
            FileResource::Leased { lease, .. } => {
                let owner = match owner {
                    DetachedOwner::Process(pid) => pid,
                    #[cfg(feature = "cli")]
                    DetachedOwner::Invoker => invoking_process()?,
                };
                lease.handoff_to(owner)?;
            }
        }
        self.0.revoke_on_drop.store(false, Ordering::Release);
        Ok(self.path().to_path_buf())
    }
}

#[derive(Default)]
struct FileRegistry {
    files: HashMap<PathBuf, SecretFile>,
    groups: HashMap<String, Vec<PathBuf>>,
}

fn registry() -> io::Result<MutexGuard<'static, FileRegistry>> {
    static REGISTRY: OnceLock<Mutex<FileRegistry>> = OnceLock::new();
    REGISTRY
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| io::Error::other("Secret file registry poisoned"))
}

pub(crate) fn retain_group(paths: Vec<PathBuf>) -> io::Result<Option<String>> {
    if paths.is_empty() {
        return Ok(None);
    }
    let id = uuid::Uuid::new_v4().to_string();
    registry()?.groups.insert(id.clone(), paths);
    Ok(Some(id))
}

/// Read only a file retained by this result, opening its original lease path
/// without the pathname canonicalization performed by PHP's file wrapper.
pub(crate) fn read_group_file(id: &str, path: &Path) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let registry = registry()?;
    if !registry
        .groups
        .get(id)
        .is_some_and(|paths| paths.iter().any(|p| p == path))
    {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "File does not belong to a live result",
        ));
    }
    let file = registry
        .files
        .get(path)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Secret file has been released"))?;
    // Open while holding the registry lock so concurrent release cannot revoke
    // the path before the descriptor is acquired. The read can then finish even
    // if the result closes, like any already-open file consumer.
    let file = std::fs::File::open(file.path())?;
    drop(registry);
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
    let paths = registry()?.groups.remove(id).unwrap_or_default();
    let mut released = 0;
    let mut failed = Vec::new();
    let mut first_error = None;
    for path in paths {
        let file = registry()?.files.remove(&path);
        if let Some(file) = file {
            if let Err(error) = file.0.release()
                && path.exists()
            {
                registry()?.files.insert(path.clone(), file);
                failed.push(path);
                first_error.get_or_insert(error);
                continue;
            }
            file.0.revoke_on_drop.store(false, Ordering::Release);
            released += 1;
        }
    }
    if let Some(error) = first_error {
        registry()?.groups.insert(id.to_owned(), failed);
        return Err(error);
    }
    Ok(released)
}

impl Drop for SecretFileInner {
    fn drop(&mut self) {
        if self.revoke_on_drop.load(Ordering::Acquire)
            && let FileResource::Leased { file, lease } = &self.resource
        {
            let _ = lease.0.release(file);
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
