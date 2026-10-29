//! Process-owned file delivery for `as_path` secrets (0.22+).
//!
//! Linux uses sealed anonymous files. macOS uses a private RAM disk and an
//! exit watcher, with orphan recovery when a subsequent lease starts. A killed
//! macOS keeper can leave its volume attached until recovery or reboot.

use std::{
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[path = "unix.rs"]
mod platform;

/// A cloneable lease on memory-backed secret files (0.22+).
///
/// Install before validation. Resolved values retain the lease. By default,
/// dropping the final owner releases files; call [`Self::handoff`] before
/// exporting paths or exec to retain them until the consuming process exits.
/// The matching `secretspec` executable must be installed alongside the host
/// application or available on PATH. No host application helper hook is needed.
#[derive(Clone)]
pub struct FileLease {
    owner: u32,
    executable: Option<PathBuf>,
    keeper: Arc<Mutex<Option<Arc<platform::Keeper>>>>,
}

impl FileLease {
    /// Create a lease, lazily allocating resources on the first file secret.
    pub fn new(owner: u32) -> Self {
        Self {
            owner,
            executable: None,
            keeper: Arc::new(Mutex::new(None)),
        }
    }

    /// Select the matching SecretSpec executable in an embedding application's
    /// deployment. Set this before cloning or installing the lease.
    pub fn with_keeper_executable(mut self, executable: impl Into<PathBuf>) -> Self {
        self.executable = Some(executable.into());
        self
    }

    /// Deliver validated file secrets directly into this lease's storage.
    pub fn install(&self, secrets: &mut crate::Secrets) {
        let lease = self.clone();
        secrets.set_as_path_materializer(move |bytes, suffix| lease.materialize(bytes, suffix));
    }

    /// Materialize logical bytes, without creating an initial temporary file.
    pub fn materialize(&self, bytes: &[u8], suffix: Option<&str>) -> io::Result<PathBuf> {
        let mut keeper = self
            .keeper
            .lock()
            .map_err(|_| io::Error::other("File lease lock poisoned"))?;
        if keeper.is_none() {
            *keeper = Some(Arc::new(platform::Keeper::spawn(
                self.owner,
                self.executable.as_deref(),
            )?));
        }
        keeper
            .as_ref()
            .unwrap()
            .materialize(bytes, suffix.unwrap_or(""))
    }

    /// Keep exported files until the original consuming process exits.
    pub fn handoff(&self) -> io::Result<()> {
        self.handoff_inner(None)
    }

    /// Transfer an existing lease to a detached manager or another consumer.
    pub fn handoff_to(&self, owner: u32) -> io::Result<()> {
        self.handoff_inner(Some(owner))
    }

    fn handoff_inner(&self, owner: Option<u32>) -> io::Result<()> {
        if let Some(keeper) = self
            .keeper
            .lock()
            .map_err(|_| io::Error::other("File lease lock poisoned"))?
            .as_ref()
        {
            keeper.handoff_to(owner)?;
        }
        Ok(())
    }
}

/// Private executable entry point. Embedding applications do not call this.
pub(crate) fn maybe_run_keeper() -> Option<i32> {
    platform::maybe_run_keeper()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod platform {
    use super::*;
    pub(super) struct Keeper;
    impl Keeper {
        pub(super) fn spawn(_: u32, _: Option<&Path>) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Process-owned file delivery requires Linux or macOS",
            ))
        }
        pub(super) fn materialize(&self, _: &[u8], _: &str) -> io::Result<PathBuf> {
            unreachable!()
        }
        pub(super) fn handoff_to(&self, _: Option<u32>) -> io::Result<()> {
            unreachable!()
        }
    }
    pub(super) fn maybe_run_keeper() -> Option<i32> {
        None
    }
}

mod process;
pub use process::ProcessInfo;

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };

    #[test]
    fn keeper_entry() {
        if let Some(code) = maybe_run_keeper() {
            std::process::exit(code);
        }
    }

    fn revoked(path: &Path) {
        let deadline = Instant::now() + Duration::from_secs(15);
        while path.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !path.exists(),
            "secret survived its lease: {}",
            path.display()
        );
    }

    #[test]
    fn files_are_read_only_and_released_on_drop() {
        use std::os::unix::fs::PermissionsExt;
        let lease = FileLease::new(std::process::id());
        let path = lease.materialize(b"public-test-key", None).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"public-test-key");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o400
        );
        #[cfg(target_os = "linux")]
        {
            use std::io::Write;
            assert!(
                std::fs::read_link(&path)
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("/memfd:secretspec-secret")
            );
            if let Ok(mut file) = std::fs::OpenOptions::new().write(true).open(&path) {
                assert!(file.write_all(b"overwrite").is_err());
            }
        }
        drop(lease);
        revoked(&path);
    }

    #[test]
    fn owner_sigkill_releases_handed_off_files_with_open_readers() {
        let mut owner = Command::new("sleep")
            .arg("60")
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let lease = FileLease::new(owner.id());
        let path = lease.materialize(b"leased-key", None).unwrap();
        let reader = std::fs::File::open(&path).unwrap();
        lease.handoff().unwrap();
        lease.handoff().unwrap();
        assert!(lease.materialize(b"too-late", None).is_err());
        drop(lease);
        assert_eq!(std::fs::read(&path).unwrap(), b"leased-key");
        owner.kill().unwrap();
        owner.wait().unwrap();
        revoked(&path);
        drop(reader);
    }

    #[test]
    fn daemon_handoff_survives_launcher_exit() {
        let mut launcher = Command::new("sleep").arg("60").spawn().unwrap();
        let mut daemon = Command::new("sleep").arg("60").spawn().unwrap();
        let lease = FileLease::new(launcher.id());
        let path = lease.materialize(b"daemon-key", None).unwrap();
        lease.handoff().unwrap();
        lease.handoff_to(daemon.id()).unwrap();
        drop(lease);
        launcher.kill().unwrap();
        launcher.wait().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"daemon-key");
        daemon.kill().unwrap();
        daemon.wait().unwrap();
        revoked(&path);
    }

    #[test]
    fn separate_leases_do_not_overwrite_or_revoke_each_other() {
        let first = FileLease::new(std::process::id());
        let second = FileLease::new(std::process::id());
        let one = first.materialize(b"one", None).unwrap();
        let two = second.materialize(b"two", None).unwrap();
        assert_ne!(one, two);
        drop(second);
        revoked(&two);
        assert_eq!(std::fs::read(one).unwrap(), b"one");
    }

    #[test]
    fn killed_keeper_releases_or_recovers_storage() {
        let lease = FileLease::new(std::process::id());
        let path = lease.materialize(b"crash-key", None).unwrap();
        let pid = lease.keeper.lock().unwrap().as_ref().unwrap().pid();
        assert_eq!(unsafe { libc::kill(pid as _, libc::SIGKILL) }, 0);
        drop(lease);
        #[cfg(target_os = "macos")]
        {
            let recovery = FileLease::new(std::process::id());
            let new_path = recovery.materialize(b"recovery-key", None).unwrap();
            assert_eq!(std::fs::read(new_path).unwrap(), b"recovery-key");
        }
        revoked(&path);
    }

    #[test]
    fn validated_and_cloned_values_retain_the_lease() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("secretspec.toml"), "[project]\nname='file-lease-test'\nrevision='1.0'\nrequire_reason=false\n[profiles.default]\nKEY={description='key',as_path=true}\n").unwrap();
        std::fs::write(root.path().join(".env"), "KEY=public-test-key\n").unwrap();
        let mut spec = crate::Secrets::load_from(&root.path().join("secretspec.toml")).unwrap();
        spec.set_provider("dotenv:.env");
        let lease = FileLease::new(std::process::id());
        lease.install(&mut spec);
        let validated = spec.validate().unwrap().unwrap();
        let path = PathBuf::from(
            std::str::from_utf8(validated.resolved.secrets["KEY"].expose_secret()).unwrap(),
        );
        let cloned = validated.resolved.clone();
        drop(validated);
        drop(spec);
        drop(lease);
        assert_eq!(std::fs::read(&path).unwrap(), b"public-test-key");
        drop(cloned);
        revoked(&path);
    }

    #[test]
    fn invalid_owners_and_suffixes_fail_closed() {
        assert!(FileLease::new(0).materialize(b"key", None).is_err());
        let lease = FileLease::new(std::process::id());
        assert!(lease.materialize(b"key", Some("/outside")).is_err());
    }

    #[test]
    fn process_metadata_identifies_the_current_executable() {
        let info = ProcessInfo::read(std::process::id()).unwrap();
        assert!(info.executed);
        assert_eq!(info.executable, std::env::current_exe().unwrap());
        assert!(!info.arguments.is_empty());
    }
}
