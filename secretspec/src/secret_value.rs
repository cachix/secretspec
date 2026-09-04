//! Secret byte storage for SecretSpec's provider and resolution APIs.

use crate::{Result, SecretSpecError};
use secrecy::{ExposeSecret, SecretSlice};
use std::fmt;

/// An owned, zeroizing secret byte sequence.
///
/// Available starting with SecretSpec 0.20. This type deliberately has no
/// generic Serde implementation: each serialized boundary must explicitly
/// choose a byte representation such as base64 or validated UTF-8.
pub struct SecretBytes(SecretSlice<u8>);

impl SecretBytes {
    /// Moves UTF-8 text into zeroizing byte storage.
    pub fn new(value: String) -> Self {
        Self::from(value)
    }

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
}
