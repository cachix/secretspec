//! Secret byte storage for SecretSpec's provider and resolution APIs.

use crate::{Result, SecretSpecError};
use secrecy::{ExposeSecret, SecretSlice};
use std::fmt;

/// An owned, zeroizing secret byte sequence.
///
/// Available starting with SecretSpec 0.21. This type deliberately has no
/// generic Serde implementation: each serialized boundary must explicitly
/// choose a byte representation such as base64 or validated UTF-8.
pub struct SecretBytes(SecretSlice<u8>);

impl SecretBytes {
    /// Moves an owned byte buffer into zeroizing secret storage.
    pub fn from_vec(value: Vec<u8>) -> Self {
        Self(value.into())
    }

    /// Copies bytes into zeroizing secret storage.
    pub fn from_slice(value: &[u8]) -> Self {
        Self::from_vec(value.to_vec())
    }

    /// Moves owned UTF-8 text, or copies borrowed text, into zeroizing secret
    /// storage.
    pub fn from_utf8(value: impl Into<String>) -> Self {
        Self::from_vec(value.into().into_bytes())
    }

    /// Exposes the secret bytes to code that must consume them.
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }

    /// Borrows the value as UTF-8, or returns a redacted conversion error.
    pub fn try_as_utf8(&self) -> Result<&str> {
        std::str::from_utf8(self.expose_secret()).map_err(|_| {
            SecretSpecError::ProviderOperationFailed(
                "secret value contains bytes that are not valid UTF-8".to_string(),
            )
        })
    }

    /// Borrows the value as UTF-8, naming the secret in the error (0.21+).
    ///
    /// The error is [`SecretSpecError::SecretNotText`] and reports the offset
    /// of the first invalid byte, never the bytes themselves.
    pub fn try_as_utf8_for(&self, name: &str) -> Result<&str> {
        std::str::from_utf8(self.expose_secret()).map_err(|error| SecretSpecError::SecretNotText {
            name: name.to_string(),
            reason: format!(
                "it contains bytes that are not valid UTF-8 (first invalid byte at offset {}); \
                     declare `as_path = true` to receive a file path or resolve it as bytes",
                error.valid_up_to()
            ),
        })
    }

    /// Borrows bytes for a process environment, naming the secret in the
    /// error (0.21+). See [`Self::try_as_env_value`] for the platform rules.
    pub fn try_as_env_value_for(&self, name: &str) -> Result<&std::ffi::OsStr> {
        if self.expose_secret().contains(&0) {
            return Err(SecretSpecError::SecretNotText {
                name: name.to_string(),
                reason: "it contains a NUL byte, which cannot be passed in a process environment"
                    .to_string(),
            });
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            Ok(std::ffi::OsStr::from_bytes(self.expose_secret()))
        }
        #[cfg(not(unix))]
        {
            self.try_as_utf8_for(name).map(std::ffi::OsStr::new)
        }
    }

    /// Borrows bytes for a process environment (0.21+).
    ///
    /// Unix preserves non-UTF-8 bytes. Other platforms require UTF-8 for this
    /// conversion. NUL bytes cannot be represented in an environment value.
    pub fn try_as_env_value(&self) -> Result<&std::ffi::OsStr> {
        if self.expose_secret().contains(&0) {
            return Err(SecretSpecError::ProviderOperationFailed(
                "secret value contains a NUL byte and cannot be passed in a process environment"
                    .to_string(),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            Ok(std::ffi::OsStr::from_bytes(self.expose_secret()))
        }
        #[cfg(not(unix))]
        {
            self.try_as_utf8().map(std::ffi::OsStr::new)
        }
    }

    /// Copies the value out of secret storage for an API that requires
    /// ownership. The returned allocation is the caller's responsibility.
    pub fn to_vec(&self) -> Vec<u8> {
        self.expose_secret().to_vec()
    }
}

impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        self.expose_secret() == other.expose_secret()
    }
}

impl Eq for SecretBytes {}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes([REDACTED])")
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(value: Vec<u8>) -> Self {
        Self::from_vec(value)
    }
}

impl From<&[u8]> for SecretBytes {
    fn from(value: &[u8]) -> Self {
        Self::from_slice(value)
    }
}

impl From<String> for SecretBytes {
    fn from(value: String) -> Self {
        Self::from_vec(value.into_bytes())
    }
}

impl From<&str> for SecretBytes {
    fn from(value: &str) -> Self {
        Self::from_utf8(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_arbitrary_bytes_and_redacts_debug() {
        let value = SecretBytes::from_slice(&[0x00, 0xff, 0x80, 0x0a]);
        assert_eq!(value.expose_secret(), &[0x00, 0xff, 0x80, 0x0a]);
        assert_eq!(value.clone(), value);
        assert_eq!(format!("{value:?}"), "SecretBytes([REDACTED])");
        assert!(value.try_as_utf8().is_err());
    }

    #[test]
    fn environment_values_reject_nul_without_exposing_bytes() {
        let value = SecretBytes::from_slice(b"do-not-leak\0");
        let error = value.try_as_env_value().unwrap_err().to_string();
        assert!(error.contains("NUL"));
        assert!(!error.contains("do-not-leak"));
    }

    #[cfg(unix)]
    #[test]
    fn unix_environment_values_preserve_non_utf8() {
        use std::os::unix::ffi::OsStrExt;

        let value = SecretBytes::from_slice(b"raw\xff\x80\n");
        assert_eq!(
            value.try_as_env_value().unwrap().as_bytes(),
            value.expose_secret()
        );
    }

    #[cfg(not(unix))]
    #[test]
    fn non_unix_environment_values_require_utf8() {
        let value = SecretBytes::from_slice(b"raw\xff\x80");
        assert!(value.try_as_env_value().is_err());
    }
}
