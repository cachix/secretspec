use super::{ProviderCredentials, ProviderInfo, ProviderUrl, ProviderWithPreflight};
use crate::Result;

/// Internal registration structure used by the macro.
#[doc(hidden)]
pub struct ProviderRegistration {
    pub info: ProviderInfo,
    pub schemes: &'static [&'static str],
    /// Semantic credential names accepted by the provider. Empty for providers
    /// that accept no injected credentials; used to reject unsupported names.
    pub credential_names: &'static [&'static str],
    pub factory: fn(&ProviderUrl, ProviderCredentials) -> Result<ProviderWithPreflight>,
}

/// Distributed slice that collects all provider registrations.
#[doc(hidden)]
#[linkme::distributed_slice]
pub static PROVIDER_REGISTRY: [ProviderRegistration];

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
    // Without preflight
    (
        struct: $struct_name:ident,
        config: $config_type:ty,
        name: $name:expr,
        description: $description:expr,
        schemes: [$($scheme:expr),* $(,)?],
        examples: [$($example:expr),* $(,)?]
        $(, credential_names: [$($credential_name:expr),* $(,)?])? $(,)?
    ) => {
        $crate::register_provider!(@register
            $struct_name, $config_type, $name, $description,
            [$($scheme,)*], [$($example,)*],
            [$($($credential_name,)*)?],
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
        preflight: $preflight:ident $(,)?
    ) => {
        $crate::register_provider!(@register
            $struct_name, $config_type, $name, $description,
            [$($scheme,)*], [$($example,)*],
            [$($($credential_name,)*)?],
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
        $struct_name:ident, $config_type:ty, $name:expr, $description:expr,
        [$($scheme:expr,)*], [$($example:expr,)*],
        [$($credential_name:expr,)*],
        $wrap:expr
    ) => {
        impl $struct_name {
            const PROVIDER_NAME: &'static str = $name;
        }

        const _: () = {
            #[linkme::distributed_slice($crate::provider::PROVIDER_REGISTRY)]
            #[doc(hidden)]
            static PROVIDER_REGISTRATION: $crate::provider::ProviderRegistration = $crate::provider::ProviderRegistration {
                info: $crate::provider::ProviderInfo {
                    name: $name,
                    description: $description,
                    examples: &[$($example,)*],
                },
                schemes: &[$($scheme,)*],
                credential_names: &[$($credential_name,)*],
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
