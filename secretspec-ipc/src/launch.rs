//! Child-process launch configuration shared by every transport.
//!
//! Version 1 endpoints are directly launched children, so both the async
//! [`crate::lifecycle`] transport and the synchronous [`crate::blocking`] one
//! need the same executable, argument, environment, and capture rules. Keeping
//! them here means a caller can move between transports without rewriting its
//! launch configuration, and the trust rules below are stated once.

use crate::{Error, Result};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub enum Environment {
    /// Inherit the caller environment and apply these overrides.
    Inherit(BTreeMap<OsString, OsString>),
    /// Clear the environment and install exactly these entries.
    Replace(BTreeMap<OsString, OsString>),
}

#[derive(Debug, Clone)]
pub struct LaunchOptions {
    pub executable: PathBuf,
    pub arguments: Vec<OsString>,
    pub environment: Environment,
    pub allow_path_discovery: bool,
    pub max_stderr_bytes: usize,
}

impl LaunchOptions {
    pub fn validate(&self) -> Result<()> {
        if self.executable.as_os_str().is_empty() {
            return Err(Error::Protocol("executable is empty"));
        }
        if !self.allow_path_discovery && !self.executable.is_absolute() {
            return Err(Error::Protocol(
                "executable must be absolute unless discovery is enabled",
            ));
        }
        if self.max_stderr_bytes > 1_048_576 {
            return Err(Error::Protocol(
                "stderr capture exceeds the version 1 bound",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(executable: &str, allow_path_discovery: bool) -> LaunchOptions {
        LaunchOptions {
            executable: PathBuf::from(executable),
            arguments: Vec::new(),
            environment: Environment::Inherit(BTreeMap::new()),
            allow_path_discovery,
            max_stderr_bytes: 4096,
        }
    }

    #[test]
    fn relative_executables_require_explicit_discovery() {
        assert!(options("secretspec", false).validate().is_err());
        assert!(options("secretspec", true).validate().is_ok());
        assert!(options("", true).validate().is_err());
    }

    #[test]
    fn stderr_capture_is_bounded() {
        let mut options = options("secretspec", true);
        options.max_stderr_bytes = 1_048_577;
        assert!(options.validate().is_err());
    }
}
