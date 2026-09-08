use crate::{Result, SecretBytes, SecretSpecError};
use std::collections::HashMap;
use std::ffi::OsStr;

/// Credentials handed to a provider at construction.
///
/// Maps semantic provider-specific names (for example `access_token`) to
/// secret values. Providers may retain environment-variable fallback for
/// standalone compatibility, but environment names are not part of this API.
pub(crate) type ProviderCredentials = HashMap<String, SecretBytes>;

/// Resolves a semantic provider credential, falling back to the provider's
/// conventional environment variable when no explicit credential was supplied.
pub(crate) fn credential_or_env(
    credentials: &ProviderCredentials,
    name: &str,
    env_var: &str,
) -> Option<SecretBytes> {
    credential_or_envs(credentials, name, &[env_var])
}

/// Resolves a semantic provider credential, falling back through the provider's
/// conventional environment variables in order. Explicit values are preserved
/// as bytes, including empty values; only absence permits an environment fallback.
pub(crate) fn credential_or_envs(
    credentials: &ProviderCredentials,
    name: &str,
    env_vars: &[&str],
) -> Option<SecretBytes> {
    credentials.get(name).cloned().or_else(|| {
        for name in env_vars {
            if let Some(value) = std::env::var_os(name) {
                return (!value.is_empty())
                    .then(|| SecretBytes::from_vec(value.into_encoded_bytes()));
            }
        }
        None
    })
}

/// Borrows a credential for a subprocess environment. Unix accepts raw bytes;
/// other platforms require text. NUL cannot be represented on either platform.
pub(crate) fn credential_env_value(value: &SecretBytes) -> Result<&OsStr> {
    if value.expose_secret().contains(&0) {
        return Err(SecretSpecError::ProviderOperationFailed(
            "provider credential contains a NUL byte and cannot be passed in a process environment"
                .to_string(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(OsStr::from_bytes(value.expose_secret()))
    }
    #[cfg(not(unix))]
    {
        value.try_as_utf8().map(OsStr::new)
    }
}

/// Builds a sensitive bearer header directly from credential bytes, validating
/// the HTTP header syntax without imposing a UTF-8 requirement.
#[cfg(any(feature = "cloudflare", feature = "infisical"))]
pub(crate) fn credential_bearer_header(value: &[u8]) -> Result<reqwest::header::HeaderValue> {
    let mut bearer = b"Bearer ".to_vec();
    bearer.extend_from_slice(value);
    let bearer = SecretBytes::from_vec(bearer);
    let mut header =
        reqwest::header::HeaderValue::from_bytes(bearer.expose_secret()).map_err(|_| {
            SecretSpecError::ProviderOperationFailed(
                "provider credential cannot be represented in an HTTP Authorization header"
                    .to_string(),
            )
        })?;
    header.set_sensitive(true);
    Ok(header)
}

/// Returns the first configured environment variable in precedence order.
///
/// A present but empty (or non-Unicode) value resolves to `None` without
/// falling through to the next name. This matches OpenBao's `BAO_*` behavior:
/// presence overrides the corresponding `VAULT_*` compatibility variable.
#[cfg(any(
    feature = "cloudflare",
    feature = "openbao",
    feature = "scaleway",
    feature = "vault",
    test
))]
pub(crate) fn preferred_env(names: &[&str]) -> Option<String> {
    for name in names {
        if let Some(value) = std::env::var_os(name) {
            return value.into_string().ok().filter(|value| !value.is_empty());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{
        ProviderCredentials, credential_env_value, credential_or_env, credential_or_envs,
        preferred_env,
    };
    use crate::SecretBytes;
    use crate::tests::EnvVarGuard;

    fn credentials(name: &str, value: &str) -> ProviderCredentials {
        let mut credentials = ProviderCredentials::new();
        credentials.insert(name.to_string(), SecretBytes::from_utf8(value));
        credentials
    }

    #[test]
    fn explicit_credential_wins_over_environment() {
        // The lock guard serializes all env mutation across the test binary;
        // the var guard restores the previous value even if an assert panics.
        let _lock = crate::tests::scrub_resolution_env();
        const NAME: &str = "access_token";
        const ENV_VAR: &str = "SECRETSPEC_TEST_PROVIDER_CREDENTIAL";
        let _var = EnvVarGuard::set(ENV_VAR, "from-env");

        assert_eq!(
            credential_or_env(&credentials(NAME, "explicit"), NAME, ENV_VAR),
            Some(SecretBytes::from("explicit")),
        );
    }

    #[test]
    fn environment_is_a_fallback() {
        let _lock = crate::tests::scrub_resolution_env();
        const NAME: &str = "access_token";
        const ENV_VAR: &str = "SECRETSPEC_TEST_PROVIDER_CREDENTIAL_FALLBACK";
        let _var = EnvVarGuard::set(ENV_VAR, "from-env");

        // With no explicit credential, the provider's conventional environment
        // variable remains available as a fallback.
        assert_eq!(
            credential_or_env(&ProviderCredentials::new(), NAME, ENV_VAR),
            Some(SecretBytes::from("from-env")),
        );
    }

    #[test]
    fn explicit_bytes_never_select_an_environment_fallback() {
        let _lock = crate::tests::scrub_resolution_env();
        const ENV: &str = "SECRETSPEC_TEST_PROVIDER_CREDENTIAL_BYTES";
        let _env = EnvVarGuard::set(ENV, "another-identity");
        for bytes in [b"private-credential\xff".as_slice(), b"with\0nul", b""] {
            let explicit =
                ProviderCredentials::from([("token".into(), SecretBytes::from_slice(bytes))]);
            assert_eq!(
                credential_or_env(&explicit, "token", ENV)
                    .unwrap()
                    .expose_secret(),
                bytes,
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn environment_credentials_preserve_non_utf8_bytes_and_precedence() {
        use std::os::unix::ffi::OsStrExt;
        let _lock = crate::tests::scrub_resolution_env();
        const PREFERRED: &str = "SECRETSPEC_TEST_CREDENTIAL_BYTES_ENV";
        const FALLBACK: &str = "SECRETSPEC_TEST_CREDENTIAL_BYTES_FALLBACK";
        let bytes = b"credential\xff";
        let _preferred = EnvVarGuard::set(PREFERRED, std::ffi::OsStr::from_bytes(bytes));
        let _fallback = EnvVarGuard::set(FALLBACK, "another-identity");
        let credential =
            credential_or_envs(&ProviderCredentials::new(), "token", &[PREFERRED, FALLBACK])
                .unwrap();
        assert_eq!(credential.expose_secret(), bytes);
        assert_eq!(credential_env_value(&credential).unwrap().as_bytes(), bytes);
    }

    #[test]
    fn process_environment_errors_do_not_expose_credentials() {
        let secret = SecretBytes::from_slice(b"private-credential\0");
        let error = credential_env_value(&secret).unwrap_err();
        assert!(error.to_string().contains("NUL"));
        assert!(!format!("{error:?}: {error}").contains("private-credential"));
    }

    #[cfg(not(unix))]
    #[test]
    fn process_environment_rejects_non_utf8_on_text_platforms() {
        let secret = SecretBytes::from_slice(b"private-credential\xff");
        let error = credential_env_value(&secret).unwrap_err();
        assert!(error.to_string().contains("UTF-8"));
        assert!(!format!("{error:?}: {error}").contains("private-credential"));
    }

    #[cfg(any(feature = "cloudflare", feature = "infisical"))]
    #[test]
    fn bearer_headers_preserve_bytes_and_reject_invalid_header_syntax() {
        let header = super::credential_bearer_header(b"private-credential\xff").unwrap();
        assert_eq!(header.as_bytes(), b"Bearer private-credential\xff");
        assert!(header.is_sensitive());
        for bytes in [
            b"private-credential\0".as_slice(),
            b"private-credential\r\n",
        ] {
            let error = super::credential_bearer_header(bytes).unwrap_err();
            assert!(!format!("{error:?}: {error}").contains("private-credential"));
        }
    }

    #[test]
    fn a_present_preferred_environment_variable_blocks_compatibility_fallback() {
        let _lock = crate::tests::scrub_resolution_env();
        const PREFERRED: &str = "SECRETSPEC_TEST_PREFERRED_ENV";
        const FALLBACK: &str = "SECRETSPEC_TEST_COMPATIBILITY_ENV";

        {
            let _preferred = EnvVarGuard::set(PREFERRED, "");
            let _fallback = EnvVarGuard::set(FALLBACK, "from-fallback");
            assert_eq!(preferred_env(&[PREFERRED, FALLBACK]), None);
            assert_eq!(
                credential_or_envs(&ProviderCredentials::new(), "token", &[PREFERRED, FALLBACK]),
                None
            );
        }

        {
            let _preferred = EnvVarGuard::remove(PREFERRED);
            let _fallback = EnvVarGuard::set(FALLBACK, "from-fallback");
            assert_eq!(
                preferred_env(&[PREFERRED, FALLBACK]).as_deref(),
                Some("from-fallback")
            );
        }
    }
}
