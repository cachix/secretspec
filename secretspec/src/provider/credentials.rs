use crate::SecretBytes;
use std::collections::HashMap;

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
) -> Option<String> {
    credential_or_envs(credentials, name, &[env_var])
}

/// Resolves a semantic provider credential, falling back through the provider's
/// conventional environment variables in order.
pub(crate) fn credential_or_envs(
    credentials: &ProviderCredentials,
    name: &str,
    env_vars: &[&str],
) -> Option<String> {
    credentials
        .get(name)
        .and_then(|secret| secret.try_as_utf8().ok().map(str::to_string))
        .filter(|value| !value.is_empty())
        .or_else(|| preferred_env(env_vars))
}

/// Returns the first configured environment variable in precedence order.
///
/// A present but empty (or non-Unicode) value resolves to `None` without
/// falling through to the next name. This matches OpenBao's `BAO_*` behavior:
/// presence overrides the corresponding `VAULT_*` compatibility variable.
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
    use super::{ProviderCredentials, credential_or_env, preferred_env};
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
            credential_or_env(&credentials(NAME, "explicit"), NAME, ENV_VAR).as_deref(),
            Some("explicit"),
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
            credential_or_env(&ProviderCredentials::new(), NAME, ENV_VAR).as_deref(),
            Some("from-env"),
        );
        // Empty explicit values are ignored and fall through as well.
        assert_eq!(
            credential_or_env(&credentials(NAME, ""), NAME, ENV_VAR).as_deref(),
            Some("from-env"),
        );
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
