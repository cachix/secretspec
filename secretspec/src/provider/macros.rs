use super::{BootstrapEnv, ProviderInfo, ProviderUrl, ProviderWithPreflight};
use crate::Result;

/// Internal registration structure used by the macro.
#[doc(hidden)]
pub struct ProviderRegistration {
    pub info: ProviderInfo,
    pub schemes: &'static [&'static str],
    /// Environment variables the provider reads through the bootstrap overlay
    /// (see [`super::BootstrapEnv`]). Empty for providers that consult no
    /// bootstrap credentials; used to warn when an alias declares a variable
    /// the provider would silently ignore.
    pub bootstrap_vars: &'static [&'static str],
    pub factory: fn(&ProviderUrl, BootstrapEnv) -> Result<ProviderWithPreflight>,
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
/// Providers that read bootstrap credentials through the overlay (see
/// [`Provider::with_bootstrap_env`](super::Provider::with_bootstrap_env)) declare
/// the variable names in a `bootstrap_vars` field, so an alias declaring a
/// variable the provider never reads can be diagnosed:
///
/// ```ignore
/// register_provider! {
///     struct: BwsProvider,
///     config: BwsConfig,
///     name: "bws",
///     description: "Bitwarden Secrets Manager",
///     schemes: ["bws"],
///     examples: ["bws://project-uuid"],
///     bootstrap_vars: ["BWS_ACCESS_TOKEN"],
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
        $(, bootstrap_vars: [$($bootstrap_var:expr),* $(,)?])? $(,)?
    ) => {
        $crate::register_provider!(@register
            $struct_name, $config_type, $name, $description,
            [$($scheme,)*], [$($example,)*],
            [$($($bootstrap_var,)*)?],
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
        $(bootstrap_vars: [$($bootstrap_var:expr),* $(,)?],)?
        preflight: $preflight:ident $(,)?
    ) => {
        $crate::register_provider!(@register
            $struct_name, $config_type, $name, $description,
            [$($scheme,)*], [$($example,)*],
            [$($($bootstrap_var,)*)?],
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
        [$($bootstrap_var:expr,)*],
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
                bootstrap_vars: &[$($bootstrap_var,)*],
                factory: |url, bootstrap| {
                    let config = <$config_type>::try_from(url)?;
                    let mut provider = <$struct_name>::new(config);
                    // Inject the bootstrap overlay while the provider is still a
                    // concrete `&mut` value, before any Arc/Box wrapping — a
                    // preflight provider becomes `Box<Arc<P>>`, through which a
                    // `&mut self` hook cannot be forwarded.
                    $crate::provider::Provider::with_bootstrap_env(&mut provider, bootstrap);
                    let wrap: fn($struct_name) -> $crate::Result<$crate::provider::ProviderWithPreflight> = $wrap;
                    wrap(provider)
                },
            };
        };
    };
}
