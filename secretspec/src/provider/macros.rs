use super::{ProviderCredentials, ProviderInfo, ProviderUrl, ProviderWithPreflight};
use crate::Result;

/// Provider identity and capability metadata shared by enabled and disabled
/// registrations.
#[doc(hidden)]
pub struct ProviderMetadata {
    pub info: ProviderInfo,
    pub schemes: &'static [&'static str],
    /// Semantic credential names accepted by the provider. Empty for providers
    /// that accept no injected credentials; used to reject unsupported names.
    pub credential_names: &'static [&'static str],
    /// Whether the provider can return plaintext secret values through
    /// [`Provider::get`](super::Provider::get).
    ///
    /// Most providers can, so registrations opt out only for write-only stores.
    /// CLI workflows use this to avoid recommending read-dependent commands.
    #[cfg_attr(not(any(feature = "cli", test)), allow(dead_code))]
    pub reads: bool,
    /// Whether the provider implements [`Provider::delete`](super::Provider::delete).
    ///
    /// Declared here rather than probed on an instance, so routing that needs an
    /// invalidatable store can be checked while planning — which never
    /// constructs a provider, because construction fetches credentials.
    pub deletes: bool,
}

/// Internal registration structure used by the macro.
#[doc(hidden)]
pub struct ProviderRegistration {
    pub metadata: &'static ProviderMetadata,
    pub factory: fn(&ProviderUrl, ProviderCredentials) -> Result<ProviderWithPreflight>,
}

/// Folds an optional macro flag into a plain `bool`: `register_provider!` passes
/// an empty slice when the field is omitted and a one-element slice otherwise.
#[doc(hidden)]
pub const fn declared_flag(values: &[bool]) -> bool {
    matches!(values, [true, ..])
}

/// Folds an optional read-capability flag, defaulting to `true` for existing
/// providers and requiring only write-only providers to opt out.
#[doc(hidden)]
pub const fn declared_read_capability(values: &[bool]) -> bool {
    match values {
        [reads, ..] => *reads,
        [] => true,
    }
}

/// Distributed slice that collects all provider registrations.
#[doc(hidden)]
#[linkme::distributed_slice]
pub static PROVIDER_REGISTRY: [ProviderRegistration];

/// Registers the metadata for a provider whose implementation was omitted at
/// compile time. Keeping these entries in the normal registry lets provider
/// lookup distinguish a disabled feature from an unknown provider.
#[doc(hidden)]
#[macro_export]
macro_rules! register_disabled_provider {
    (
        feature: $feature:literal,
        metadata: $metadata:expr $(,)?
    ) => {
        const _: () = {
            #[linkme::distributed_slice($crate::provider::PROVIDER_REGISTRY)]
            #[doc(hidden)]
            static PROVIDER_REGISTRATION: $crate::provider::ProviderRegistration =
                $crate::provider::ProviderRegistration {
                    metadata: $metadata,
                    factory: |_url, _credentials| {
                        Err($crate::SecretSpecError::ProviderFeatureDisabled {
                            provider: $metadata.info.name.to_string(),
                            feature: $feature,
                        })
                    },
                };
        };
    };
}

/// Declarative macro for registering providers.
///
/// This macro handles the boilerplate of registering a provider with the global registry.
///
/// # Usage
///
/// ```ignore
/// register_provider! {
///     struct: KeyringProvider,
///     config: KeyringConfig,
///     name: "keyring",
///     description: "Uses system keychain (Recommended)",
///     schemes: ["keyring"],
///     examples: ["keyring://"],
/// }
/// ```
///
/// Providers that accept injected credentials declare their semantic names in
/// a `credential_names` field, so an alias declaring an unsupported credential
/// can be diagnosed:
///
/// ```ignore
/// register_provider! {
///     struct: BwsProvider,
///     config: BwsConfig,
///     name: "bws",
///     description: "Bitwarden Secrets Manager",
///     schemes: ["bws"],
///     examples: ["bws://project-uuid"],
///     credential_names: ["access_token"],
/// }
/// ```
///
/// Write-only providers declare that `get` cannot return plaintext values, so
/// CLI workflows do not recommend read-dependent follow-up commands:
///
/// ```ignore
/// register_provider! {
///     struct: WriteOnlyProvider,
///     config: WriteOnlyConfig,
///     name: "write-only",
///     description: "A write-only store",
///     schemes: ["write-only"],
///     examples: ["write-only://store"],
///     reads: false,
/// }
/// ```
///
/// Providers that implement [`Provider::delete`](super::Provider::delete)
/// declare it, so routing that requires an invalidatable store — a cached
/// alias's `cache.provider` — can be validated while planning:
///
/// ```ignore
/// register_provider! {
///     struct: DotEnvProvider,
///     config: DotEnvConfig,
///     name: "dotenv",
///     description: "Traditional .env files",
///     schemes: ["dotenv"],
///     examples: ["dotenv://.env"],
///     deletes: true,
/// }
/// ```
///
/// Providers that need an authentication check before use can add a `preflight` field.
/// The value must be a method name on the provider struct that returns `Result<()>`:
///
/// ```ignore
/// register_provider! {
///     struct: OnePasswordProvider,
///     config: OnePasswordConfig,
///     name: "onepassword",
///     description: "OnePassword integration",
///     schemes: ["onepassword"],
///     examples: ["onepassword://vault"],
///     preflight: check_auth,
/// }
/// ```
#[doc(hidden)]
#[macro_export]
macro_rules! register_provider {
    // Shared catalog metadata, without preflight.
    (
        struct: $struct_name:ident,
        config: $config_type:ty,
        metadata: $metadata:expr $(,)?) => {
        $crate::register_provider!(@register
            $struct_name, $config_type, $metadata,
            |provider| {
                Ok($crate::provider::ProviderWithPreflight {
                    provider: Box::new(provider),
                    preflight: None,
                })
            }
        );
    };

    // Shared catalog metadata, with preflight.
    (
        struct: $struct_name:ident,
        config: $config_type:ty,
        metadata: $metadata:expr,
        preflight: $preflight:ident $(,)?) => {
        $crate::register_provider!(@register
            $struct_name, $config_type, $metadata,
            |provider| {
                let provider = std::sync::Arc::new(provider);
                let preflight_provider = std::sync::Arc::clone(&provider);
                Ok($crate::provider::ProviderWithPreflight {
                    provider: Box::new(provider),
                    preflight: Some(Box::new(move || preflight_provider.$preflight())),
                })
            }
        );
    };

    // Without preflight
    (
        struct: $struct_name:ident,
        config: $config_type:ty,
        name: $name:expr,
        description: $description:expr,
        schemes: [$($scheme:expr),* $(,)?],
        examples: [$($example:expr),* $(,)?]
        $(, credential_names: [$($credential_name:expr),* $(,)?])?
        $(, reads: $reads:literal)?
        $(, deletes: $deletes:literal)? $(,)?
    ) => {
        $crate::register_provider!(@register
            $struct_name, $config_type,
            &$crate::provider::ProviderMetadata {
                info: $crate::provider::ProviderInfo {
                    name: $name,
                    description: $description,
                    examples: &[$($example,)*],
                },
                schemes: &[$($scheme,)*],
                credential_names: &[$($($credential_name,)*)?],
                reads: $crate::provider::declared_read_capability(&[$($reads,)?]),
                deletes: $crate::provider::declared_flag(&[$($deletes,)?]),
            },
            |provider| {
                Ok($crate::provider::ProviderWithPreflight {
                    provider: Box::new(provider),
                    preflight: None,
                })
            }
        );
    };

    // With preflight
    (
        struct: $struct_name:ident,
        config: $config_type:ty,
        name: $name:expr,
        description: $description:expr,
        schemes: [$($scheme:expr),* $(,)?],
        examples: [$($example:expr),* $(,)?],
        $(credential_names: [$($credential_name:expr),* $(,)?],)?
        $(reads: $reads:literal,)?
        $(deletes: $deletes:literal,)?
        preflight: $preflight:ident $(,)?
    ) => {
        $crate::register_provider!(@register
            $struct_name, $config_type,
            &$crate::provider::ProviderMetadata {
                info: $crate::provider::ProviderInfo {
                    name: $name,
                    description: $description,
                    examples: &[$($example,)*],
                },
                schemes: &[$($scheme,)*],
                credential_names: &[$($($credential_name,)*)?],
                reads: $crate::provider::declared_read_capability(&[$($reads,)?]),
                deletes: $crate::provider::declared_flag(&[$($deletes,)?]),
            },
            |provider| {
                let provider = std::sync::Arc::new(provider);
                let preflight_provider = std::sync::Arc::clone(&provider);
                Ok($crate::provider::ProviderWithPreflight {
                    provider: Box::new(provider),
                    preflight: Some(Box::new(move || preflight_provider.$preflight())),
                })
            }
        );
    };

    // Internal: shared registration logic
    (@register
        $struct_name:ident, $config_type:ty, $metadata:expr,
        $wrap:expr
    ) => {
        impl $struct_name {
            const PROVIDER_NAME: &'static str = $metadata.info.name;
        }

        const _: () = {
            #[linkme::distributed_slice($crate::provider::PROVIDER_REGISTRY)]
            #[doc(hidden)]
            static PROVIDER_REGISTRATION: $crate::provider::ProviderRegistration = $crate::provider::ProviderRegistration {
                metadata: $metadata,
                factory: |url, credentials| {
                    let config = <$config_type>::try_from(url)?;
                    let mut provider = <$struct_name>::new(config);
                    // Inject credentials while the provider is still a
                    // concrete `&mut` value, before any Arc/Box wrapping — a
                    // preflight provider becomes `Box<Arc<P>>`, through which a
                    // `&mut self` hook cannot be forwarded.
                    $crate::provider::Provider::with_credentials(&mut provider, credentials);
                    let wrap: fn($struct_name) -> $crate::Result<$crate::provider::ProviderWithPreflight> = $wrap;
                    wrap(provider)
                },
            };
        };
    };
}
