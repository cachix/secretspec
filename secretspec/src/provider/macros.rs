use super::{ProviderInfo, ProviderWithPreflight};
use crate::Result;

/// Internal registration structure used by the macro.
#[doc(hidden)]
pub struct ProviderRegistration {
    pub info: ProviderInfo,
    pub schemes: &'static [&'static str],
    pub factory: fn(&url::Url) -> Result<ProviderWithPreflight>,
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
        examples: [$($example:expr),* $(,)?] $(,)?
    ) => {
        $crate::register_provider!(@register
            $struct_name, $config_type, $name, $description,
            [$($scheme,)*], [$($example,)*],
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
        preflight: $preflight:ident $(,)?
    ) => {
        $crate::register_provider!(@register
            $struct_name, $config_type, $name, $description,
            [$($scheme,)*], [$($example,)*],
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
                factory: |url| {
                    let config = <$config_type>::try_from(url)?;
                    let provider = <$struct_name>::new(config);
                    let wrap: fn($struct_name) -> $crate::Result<$crate::provider::ProviderWithPreflight> = $wrap;
                    wrap(provider)
                },
            };
        };
    };
}
