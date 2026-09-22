//! Resolver connection configuration (0.21+).
//!
//! Transport authentication is established before the IPC handshake. Nothing
//! in resolver initialization authenticates a caller or grants filesystem access.

use crate::launch::{Environment, LaunchOptions};
use crate::protocol::resolver::{GetParams, GetResult, Representation};
use crate::{Error, Result};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Whether resolver-owned paths are usable by this client (0.21+).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemAccess {
    /// Separate filesystems. Only inline values may cross this connection.
    #[default]
    Remote,
    /// The caller explicitly guarantees identical paths and access permissions.
    Shared,
}

impl FilesystemAccess {
    pub(crate) fn prepare_get(self, params: &GetParams) -> Result<Cow<'_, GetParams>> {
        params.validate()?;
        if self == Self::Shared {
            return Ok(Cow::Borrowed(params));
        }
        match params.representation {
            Representation::Path => Err(Error::Protocol(
                "path resolution requires an explicitly shared filesystem",
            )),
            Representation::Auto => {
                let mut params = params.clone();
                // Asking for Value makes the resolver reject as_path before
                // resolving it or creating a file. It never exports its contents.
                params.representation = Representation::Value;
                Ok(Cow::Owned(params))
            }
            Representation::Value => Ok(Cow::Borrowed(params)),
        }
    }

    pub(crate) fn accepts(self, result: &GetResult) -> bool {
        self == Self::Shared || !matches!(result, GetResult::Path(_))
    }
}

/// Launch a private resolver through OpenSSH (0.21+).
///
/// Configuration must come from the application or user, never an untrusted
/// project. The remote account is the authorization boundary; this does not
/// sandbox the resolver to a project. Authentication and host-key enrollment
/// must already be configured. The remote login shell must support POSIX quoting.
#[derive(Debug, Clone)]
pub struct SshOptions {
    /// Local OpenSSH executable. Privileged callers must use an absolute path.
    pub executable: PathBuf,
    /// Local SSH process environment. Privileged hosts should use an allowlist.
    pub environment: Environment,
    /// Trusted SSH host alias, hostname, or user@host.
    pub destination: String,
    /// Remote executable, interpreted on the resolver machine, not locally.
    pub remote_executable: String,
    /// Refuse mutation methods and resolution that would persist a new secret.
    pub read_only: bool,
    pub filesystem: FilesystemAccess,
}

impl SshOptions {
    /// Use existing SSH configuration, read-only access, and separate filesystems.
    pub fn new(destination: impl Into<String>) -> Self {
        Self {
            executable: PathBuf::from("ssh"),
            environment: Environment::Inherit(BTreeMap::new()),
            destination: destination.into(),
            remote_executable: "secretspec".into(),
            read_only: true,
            filesystem: FilesystemAccess::Remote,
        }
    }

    pub(crate) fn launch_options(&self) -> Result<LaunchOptions> {
        if self.destination.is_empty()
            || self.destination.starts_with('-')
            || !self
                .destination
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".-_@:/[]".contains(&byte))
        {
            return Err(Error::Protocol("invalid SSH destination"));
        }
        if self.remote_executable.is_empty()
            || self.remote_executable.starts_with('-')
            || self.remote_executable.chars().any(char::is_control)
        {
            return Err(Error::Protocol("invalid remote resolver executable"));
        }
        // SSH sends a command string to the remote shell, even when launched
        // locally with argv. Quote the executable as one POSIX shell word.
        let executable = self.remote_executable.replace('\'', "'\\''");
        let command = format!(
            "exec '{executable}' serve{}",
            if self.read_only { " --read-only" } else { "" }
        );
        let mut arguments: Vec<_> = [
            "-T",
            "-oBatchMode=yes",
            "-oStrictHostKeyChecking=yes",
            "-oClearAllForwardings=yes",
            "-oForwardAgent=no",
            "-oForwardX11=no",
            "-oPermitLocalCommand=no",
            "-oRemoteCommand=none",
            "-oSessionType=default",
            "-oStdinNull=no",
            "-oForkAfterAuthentication=no",
            "-oServerAliveInterval=15",
            "-oServerAliveCountMax=3",
            "--",
        ]
        .into_iter()
        .map(Into::into)
        .collect();
        arguments.push(self.destination.clone().into());
        arguments.push(command.into());
        let options = LaunchOptions {
            executable: self.executable.clone(),
            arguments,
            environment: self.environment.clone(),
            allow_path_discovery: !self.executable.is_absolute(),
            max_stderr_bytes: 64 * 1024,
        };
        options.validate()?;
        Ok(options)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::resolver::{InitializeApplication, Manifest};

    #[test]
    fn ssh_rejects_option_injection_and_control_characters() {
        for destination in [
            "",
            "-oProxyCommand=command",
            "host name",
            "host\ncommand",
            "host;command",
            "host$(command)",
        ] {
            assert!(SshOptions::new(destination).launch_options().is_err());
        }
        for destination in [
            "developer",
            "alice@host",
            "alice@[::1]",
            "ssh://alice@host:2222",
        ] {
            assert!(SshOptions::new(destination).launch_options().is_ok());
        }
        let mut options = SshOptions::new("developer");
        options.remote_executable = "resolver\ncommand".into();
        assert!(options.launch_options().is_err());
    }

    #[test]
    fn client_validates_paths_in_the_resolvers_namespace() {
        let mut application = InitializeApplication {
            manifest: Manifest::Path {
                path: String::new(),
            },
            provider: None,
            profile: None,
            scope: None,
            reason: None,
            requested_authorization_duration_ms: None,
        };
        for path in [
            "/srv/project/secretspec.toml",
            "C:\\project\\secretspec.toml",
            "\\\\server\\share\\secretspec.toml",
        ] {
            application.manifest = Manifest::Path { path: path.into() };
            application.validate_for_connection().unwrap();
        }
        for path in [
            "project/secretspec.toml",
            "C:relative",
            "/srv/../secret",
            "C:\\project\\..\\secret",
            "/srv/./secret",
            "/srv/secret\0",
        ] {
            application.manifest = Manifest::Path { path: path.into() };
            assert!(application.validate_for_connection().is_err(), "{path:?}");
        }
        application.manifest = Manifest::Inline {
            toml: String::new(),
            base_dir: "relative".into(),
        };
        assert!(application.validate_for_connection().is_err());
    }
}
