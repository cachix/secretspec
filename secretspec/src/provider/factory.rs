use super::preflight::PreflightGuard;
use super::registry::{registration_for_scheme, split_spec};
use super::url::{WINDOWS_PATH_ENCODE_SET, is_windows_abs_path};
use super::{
    PROVIDER_REGISTRY, Provider, ProviderCredentials, ProviderUrl, URI_ENCODE_SET,
    spec_names_known_provider,
};
use crate::{Result, SecretSpecError};
use percent_encoding::percent_encode;
use std::convert::TryFrom;
use url::Url;

impl TryFrom<String> for Box<dyn Provider> {
    type Error = SecretSpecError;

    /// Creates a provider instance from a URI string.
    ///
    /// This function handles various URI formats and normalizes them before parsing.
    /// It supports both full URIs and shorthand notations.
    ///
    /// # URI Formats
    ///
    /// - **Full URI**: `scheme://authority/path` (e.g., `onepassword://Production`)
    ///
    /// # Special Cases
    ///
    /// - **1password**: Will error suggesting to use `onepassword` instead
    /// - **Bare provider names**: Automatically converted to `provider://`
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use std::convert::TryFrom;
    ///
    /// // Simple provider name
    /// let provider = Box::<dyn Provider>::try_from("keyring".to_string())?;
    ///
    /// // Full URI with configuration
    /// let provider = Box::<dyn Provider>::try_from("onepassword://Production".to_string())?;
    ///
    /// // Dotenv with path
    /// let provider = Box::<dyn Provider>::try_from("dotenv:.env.production".to_string())?;
    /// ```
    fn try_from(s: String) -> Result<Self> {
        Self::try_from(&s as &str)
    }
}

impl TryFrom<&str> for Box<dyn Provider> {
    type Error = SecretSpecError;

    fn try_from(s: &str) -> Result<Self> {
        provider_from_spec(s, ProviderCredentials::new())
    }
}

/// Builds a boxed provider from a spec string (a bare name, `scheme:...`
/// shorthand, or full URI), handing it the supplied credentials. The shared
/// body of the string `TryFrom` impls: construction funnels here so URL
/// normalization and credential injection have exactly one home.
pub(crate) fn provider_from_spec(
    s: &str,
    credentials: ProviderCredentials,
) -> Result<Box<dyn Provider>> {
    // Parse the scheme from the input string
    let (scheme, rest) = split_spec(s);

    // Reject the `1password` misspelling (with its corrective error) and
    // check the scheme against the registry, through the same gate alias
    // resolution uses.
    if !spec_names_known_provider(s)? {
        // Check if it's a known provider name to give a better error
        if PROVIDER_REGISTRY
            .iter()
            .any(|reg| reg.metadata.info.name == scheme)
        {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Provider '{}' exists but URI parsing failed",
                scheme
            )));
        } else {
            return Err(SecretSpecError::ProviderNotFound(scheme.to_string()));
        }
    }

    // Build a proper URL with the correct scheme.
    //
    // Windows absolute paths (e.g. `dotenv://C:\path\.env`) need special care:
    // the drive-letter colon looks like a `host:port` separator and parsing
    // fails with "invalid port number". Custom schemes carry the encoded path
    // in an opaque host so it round-trips through `ProviderUrl::host()`; the
    // special `file` scheme uses its standard `file:///C:/...` form instead. A
    // Unix absolute path already parses cleanly as `scheme:///abs/path`.
    let path_candidate = rest.trim_start_matches('/');
    let url_string = if is_windows_abs_path(path_candidate) {
        if scheme == "file" {
            // `file` is a special URL scheme, so an encoded drive path cannot
            // live in its host as it does for custom schemes. Use the standard
            // authority-less file URL and normalize Windows separators.
            let path = path_candidate.replace('\\', "/");
            format!(
                "file:///{}",
                percent_encode(path.as_bytes(), URI_ENCODE_SET)
            )
        } else {
            format!(
                "{}://{}",
                scheme,
                percent_encode(path_candidate.as_bytes(), WINDOWS_PATH_ENCODE_SET)
            )
        }
    } else {
        let url_string = match rest {
            // Just scheme name (e.g., "keyring")
            "" | ":" => format!("{}://", scheme),
            // Standard URI format already has // (e.g., "onepassword://vault")
            s if s.starts_with("//") => format!("{}:{}", scheme, s),
            // Path only format (e.g., "dotenv:/path/to/.env")
            s if s.starts_with('/') => format!("{}://{}", scheme, s),
            // Everything else - assume it's a host or path component
            s => format!("{}://{}", scheme, s),
        };

        // Percent-encode characters that are invalid in URIs but might appear in
        // provider config values (e.g., spaces in 1Password vault names like "Home Lab")
        let scheme_end = url_string.find("://").unwrap() + 3;
        let (prefix, rest) = url_string.split_at(scheme_end);
        format!(
            "{}{}",
            prefix,
            percent_encode(rest.as_bytes(), URI_ENCODE_SET)
        )
    };

    let proper_url = Url::parse(&url_string).map_err(|e| {
        // Redacted: a spec that fails to parse can still carry a credential in
        // its userinfo, and this message is printed. The rejection in
        // `reject_uri_credential` only runs once parsing succeeds.
        SecretSpecError::ProviderOperationFailed(format!(
            "Invalid provider specification '{}': {}",
            crate::audit::redact_uri_strict(s),
            e
        ))
    })?;

    provider_from_url(&ProviderUrl::new(proper_url), credentials)
}

impl TryFrom<&Url> for Box<dyn Provider> {
    type Error = SecretSpecError;

    fn try_from(url: &Url) -> Result<Self> {
        provider_from_url(&ProviderUrl::new(url.clone()), ProviderCredentials::new())
    }
}

/// Refuses a provider URI that carries a credential in its password position.
///
/// A URI is the wrong place for a secret: it is committed to `secretspec.toml`,
/// echoed into shell history, and printed by CI. Redacting it at the terminal
/// does not unpublish it from any of those. Provider credentials exist for this
/// (`credentials = { … }` on the alias, `secretspec config provider login`, or
/// the provider's environment fallback), so the password position is rejected
/// outright rather than read, ignored, or scrubbed.
///
/// Only the password position is universal. Every provider that reads the
/// username reads a non-secret from it (a Vault namespace, an AWS profile, a
/// Bitwarden organization, a 1Password account), so a scheme whose username
/// carries a credential rejects it itself.
///
/// Since SecretSpec 0.19.
fn reject_uri_credential(url: &ProviderUrl) -> Result<()> {
    if url.password().is_none() {
        return Ok(());
    }
    let scheme = url.scheme();
    let registration = registration_for_scheme(scheme);
    // Name the credentials this provider actually accepts, straight from its
    // registration, so the remedy is concrete rather than a pointer to the
    // general mechanism. A provider that accepts none never had a use for the
    // password either, so say that instead of suggesting a credential.
    let remedy = match registration {
        Some(reg) if !reg.metadata.credential_names.is_empty() => {
            let names = reg
                .metadata
                .credential_names
                .iter()
                .map(|name| format!("`{name}`"))
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "Supply it as the {names} provider credential instead \
                 (`secretspec config provider login <alias>`, or `credentials = \
                 {{ ... }}` on the alias), or use the provider's environment \
                 variable. See https://secretspec.dev/providers/{}/",
                reg.metadata.info.name
            )
        }
        Some(reg) => format!(
            "The {} provider takes no credentials, so remove the userinfo from \
             the URI. See https://secretspec.dev/providers/{}/",
            reg.metadata.info.name, reg.metadata.info.name
        ),
        None => "See https://secretspec.dev/reference/provider-credentials/".to_string(),
    };
    Err(SecretSpecError::ProviderOperationFailed(format!(
        "provider URI '{}' carries a password. SecretSpec does not accept \
         credentials in URIs: a URI reaches committed manifests, shell history, \
         and CI logs, so a credential written there is already disclosed. {remedy}",
        crate::audit::redact_uri_strict(url.as_url().as_str()),
    )))
}

pub(crate) fn provider_from_url(
    url: &ProviderUrl,
    credentials: ProviderCredentials,
) -> Result<Box<dyn Provider>> {
    reject_uri_credential(url)?;
    let scheme = url.scheme();

    let registration = registration_for_scheme(scheme)
        .ok_or_else(|| SecretSpecError::ProviderNotFound(scheme.to_string()))?;

    let pwp = (registration.factory)(url, credentials)?;
    if pwp.preflight.is_some() {
        Ok(Box::new(PreflightGuard::new(pwp)))
    } else {
        Ok(pwp.provider)
    }
}
