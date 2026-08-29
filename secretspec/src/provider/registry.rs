use super::{PROVIDER_REGISTRY, ProviderRegistration, file};
use crate::{Result, SecretSpecError};

/// Information about a secret storage provider.
///
/// Contains metadata used for displaying available providers to users,
/// including the provider's name, description, and example URIs.
#[derive(Debug, Clone)]
pub struct ProviderInfo {
    /// The canonical name of the provider (e.g., "keyring", "1password").
    pub name: &'static str,
    /// A human-readable description of what the provider does.
    #[cfg_attr(not(any(feature = "cli", test)), allow(dead_code))]
    pub description: &'static str,
    /// Example URIs showing how to configure this provider.
    #[cfg_attr(not(any(feature = "cli", test)), allow(dead_code))]
    pub examples: &'static [&'static str],
}

impl ProviderInfo {
    /// Formats the provider information for display, including examples if available.
    ///
    /// # Returns
    ///
    /// A formatted string in one of two formats:
    /// - Without examples: "name: description"
    /// - With examples: "name: description (e.g., example1, example2)"
    ///
    /// # Example
    ///
    /// ```ignore
    /// let info = ProviderInfo {
    ///     name: "onepassword",
    ///     description: "OnePassword password manager",
    ///     examples: &["onepassword://vault", "onepassword://work@Production"],
    /// };
    /// assert_eq!(
    ///     info.display_with_examples(),
    ///     "onepassword: OnePassword password manager (e.g., onepassword://vault, onepassword://work@Production)"
    /// );
    /// ```
    #[cfg(any(feature = "cli", test))]
    pub fn display_with_examples(&self) -> String {
        if self.examples.is_empty() {
            format!("{}: {}", self.name, self.description)
        } else {
            format!(
                "{}: {} (e.g., {})",
                self.name,
                self.description,
                self.examples.join(", ")
            )
        }
    }
}

/// Returns a list of all supported providers with their metadata.
///
/// This includes providers whose implementation was disabled at compile time;
/// attempting to construct one reports the Cargo feature the build requires.
#[cfg(feature = "cli")]
pub fn providers() -> Vec<ProviderInfo> {
    PROVIDER_REGISTRY
        .iter()
        .map(|reg| reg.metadata.info.clone())
        .collect()
}

/// Splits a provider spec at the first `:` into its scheme token and the rest
/// (empty for a bare provider name). The one definition of "the scheme",
/// shared by the string URI parser and [`spec_names_known_provider`], so the
/// two cannot disagree on how a spec is split.
pub(super) fn split_spec(spec: &str) -> (&str, &str) {
    match spec.find(':') {
        Some(pos) => (&spec[..pos], &spec[pos + 1..]),
        None => (spec, ""),
    }
}

/// The registry entry whose schemes contain `scheme`. The one definition of
/// "which registration a scheme resolves to", shared by every registry lookup
/// and provider construction.
pub(super) fn registration_for_scheme(scheme: &str) -> Option<&'static ProviderRegistration> {
    PROVIDER_REGISTRY
        .iter()
        .find(|reg| reg.metadata.schemes.contains(&scheme))
}

/// Whether `spec` names a registered provider: a bare name (`keyring`), a
/// `scheme:path` shorthand (`dotenv:.env.production`), or a full URI. Checks
/// the leading scheme token against the registry without constructing a
/// provider, so alias resolution can distinguish a valid provider spec from an
/// undefined alias.
///
/// The common `1password` misspelling of `onepassword` errors with its
/// corrective message here, regardless of which parsing path sees it first.
pub(crate) fn spec_names_known_provider(spec: &str) -> Result<bool> {
    let (scheme, rest) = split_spec(spec);
    if scheme == "1password" {
        return Err(SecretSpecError::ProviderOperationFailed(
            "Invalid scheme '1password'. Use 'onepassword' instead (e.g., onepassword://vault)"
                .to_string(),
        ));
    }
    // The URL parser normalizes `file://` to `file:///`, making an omitted
    // path indistinguishable from an explicitly selected filesystem root.
    if scheme == "file" && (rest.is_empty() || rest == "//") {
        return Err(SecretSpecError::ProviderOperationFailed(
            file::MISSING_DIRECTORY_ERROR.to_string(),
        ));
    }
    Ok(registration_for_scheme(scheme).is_some())
}

/// The semantic credential names accepted by the provider named by `spec`, or
/// an empty slice for an unknown scheme. Lets alias validation reject a
/// declaration the provider would silently ignore.
pub(crate) fn credential_names_for_spec(spec: &str) -> &'static [&'static str] {
    let (scheme, _) = split_spec(spec);
    registration_for_scheme(scheme).map_or(&[], |reg| reg.metadata.credential_names)
}

/// Whether the provider named by `spec` can return plaintext secret values.
///
/// Read from registration metadata so CLI guidance can inspect an alias target
/// without constructing it, fetching its credentials, or running preflight.
#[cfg_attr(not(any(feature = "cli", test)), allow(dead_code))]
pub(crate) fn spec_provider_reads(spec: &str) -> bool {
    let (scheme, _) = split_spec(spec);
    registration_for_scheme(scheme).is_some_and(|reg| reg.metadata.reads)
}

/// Whether the provider `spec` names implements deletion.
///
/// Read from registration metadata so routing can validate an invalidatable
/// store while planning, before a provider is constructed.
pub(crate) fn spec_provider_deletes(spec: &str) -> bool {
    let (scheme, _) = split_spec(spec);
    registration_for_scheme(scheme).is_some_and(|reg| reg.metadata.deletes)
}

/// The names of every provider that implements deletion, sorted. Used to say
/// which providers a cache can live in without hardcoding a drifting list.
pub(crate) fn deleting_provider_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = PROVIDER_REGISTRY
        .iter()
        .filter(|reg| reg.metadata.deletes)
        .map(|reg| reg.metadata.info.name)
        .collect();
    names.sort_unstable();
    names
}

/// The registered display name for the provider `spec` names, falling back to
/// the spec's scheme token. This pure lookup lets callers describe routing
/// without constructing a provider or fetching its credentials.
pub(crate) fn provider_display_name_for_spec(spec: &str) -> String {
    let (scheme, _) = split_spec(spec);
    registration_for_scheme(scheme)
        .map(|reg| reg.metadata.info.name.to_string())
        .unwrap_or_else(|| scheme.to_string())
}

#[cfg(test)]
mod tests {
    use super::ProviderInfo;

    #[test]
    fn provider_info_display_with_and_without_examples() {
        let with = ProviderInfo {
            name: "onepassword",
            description: "OnePassword",
            examples: &["onepassword://vault", "onepassword://work@Production"],
        };
        assert_eq!(
            with.display_with_examples(),
            "onepassword: OnePassword (e.g., onepassword://vault, onepassword://work@Production)"
        );

        let without = ProviderInfo {
            name: "env",
            description: "Environment variables",
            examples: &[],
        };
        assert_eq!(
            without.display_with_examples(),
            "env: Environment variables"
        );
    }
}
