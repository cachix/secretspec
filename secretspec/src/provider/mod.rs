//! # Provider System
//!
//! The provider module implements a trait-based plugin architecture for managing secrets
//! across different storage backends. Providers handle the actual storage and retrieval
//! of secrets, supporting everything from local files to cloud-based secret managers.
//!
//! ## Architecture
//!
//! The provider system is built around the [`Provider`] trait, which defines a common
//! interface for all storage backends. Each provider implementation handles:
//!
//! - Profile-aware storage (e.g., development vs production secrets)
//! - Project isolation (secrets are namespaced by project)
//! - Optional write support (some providers are read-only)
//!
//! ## Available Providers
//!
//! - [`keyring::KeyringProvider`]: System keyring integration (default)
//! - [`kdbx::KdbxProvider`]: KeePass KDBX database integration (0.17+)
//! - [`keeper::KeeperProvider`]: Keeper Secrets Manager integration (0.18+)
//! - [`doppler::DopplerProvider`]: Doppler integration (0.21+)
//! - [`dotenv::DotEnvProvider`]: `.env` file support
//! - [`env::EnvProvider`]: Environment variables (read-only)
//! - [`ejson::EjsonProvider`]: EJSON encrypted files (0.20+)
//! - [`null::NullProvider`]: Defaults, generation, or run prompts without storage (0.19+)
//! - [`file::FileProvider`]: Plaintext file-per-secret storage (0.19+)
//! - [`fly::FlyProvider`]: Fly.io application secrets, write-only (0.20+)
//! - [`cloudflare::CloudflareProvider`]: Cloudflare Secrets Store, write-only (0.20+)
//! - [`pass::PassProvider`]: Pass integration
//! - [`gopass::GoPassProvider`]: Gopass integration
//! - [`systemd_credential::SystemdCredentialProvider`]: systemd service credentials (0.17+)
//! - [`protonpass::ProtonPassProvider`]: Proton Pass integration
//! - [`passbolt::PassboltProvider`]: Passbolt integration through go-passbolt-cli (0.19+)
//! - [`onepassword::OnePasswordProvider`]: 1Password integration
//! - [`lastpass::LastPassProvider`]: LastPass integration
//! - [`dashlane::DashlaneProvider`]: Dashlane integration, read-only (0.18+)
//! - [`gcsm::GcsmProvider`]: Google Cloud Secret Manager integration
//! - [`awssm::AwssmProvider`]: AWS Secrets Manager integration
//! - [`awsps::AwspsProvider`]: AWS Systems Manager Parameter Store integration (0.18+)
//! - [`vault::VaultProvider`]: HashiCorp Vault integration
//! - [`openbao::OpenBaoProvider`]: OpenBao integration (0.17+)
//! - [`bws::BwsProvider`]: Bitwarden Secrets Manager integration
//! - [`akv::AkvProvider`]: Azure Key Vault integration
//! - [`aac::AacProvider`]: Azure App Configuration integration (0.20+)
//! - [`infisical::InfisicalProvider`]: Infisical integration (0.16+)
//! - [`bw::BitwardenProvider`]: Bitwarden Password Manager (0.18+)
//! - [`sops::SopsProvider`]: SOPS-encrypted file integration (0.17+)
//! - [`kubernetes::KubernetesProvider`]: Kubernetes integration (0.20+)
//! - [`setec::SetecProvider`]: Tailscale Setec integration (0.21+)
//!
//! ## URI-Based Configuration
//!
//! Providers support URI-based configuration for flexibility:
//!
//! ```text
//! keyring://
//! dotenv://.env.production
//! null://  # Use defaults, generation, or run prompts without storage, 0.19+
//! file:./.secrets  # One plaintext file per secret, 0.19+
//! onepassword://vault
//! lastpass://folder
//! keeper://SHARED_FOLDER_UID  # Keeper, 0.18+
//! doppler://myapp/prd         # Doppler, 0.21+
//! ```
//!
//! ## Example
//!
//! ```rust,ignore
//! use secretspec::provider::{Address, Provider};
//! use std::convert::TryFrom;
//!
//! // Create a provider from a URI string
//! let provider = Box::<dyn Provider>::try_from("keyring://")?;
//!
//! let addr = Address::convention("myproject", "production", "API_KEY");
//!
//! // Store a secret
//! provider.set(addr, &"secret123".to_string().into())?;
//!
//! // Retrieve a secret
//! if let Some(value) = provider.get(addr)? {
//!     println!("API_KEY retrieved");
//! }
//! ```

mod address;
mod catalog;
mod credentials;
// Every item inside is cfg-gated out in an all-features build.
#[allow(unused_imports, unused_macros)]
mod disabled;
mod factory;
#[cfg(any(
    feature = "aac",
    feature = "cloudflare",
    feature = "doppler",
    feature = "infisical",
    feature = "openbao",
    feature = "scaleway",
    feature = "setec",
    feature = "vault"
))]
mod http;
#[macro_use]
pub mod macros;
#[cfg(any(feature = "awssm", feature = "infisical", feature = "scaleway", test))]
mod path;
mod preflight;
mod registry;
mod runtime;
mod traits;
mod url;

// Public provider API.
pub use address::Address;
pub use macros::{
    PROVIDER_REGISTRY, ProviderMetadata, ProviderRegistration, declared_flag,
    declared_read_capability,
};
pub use registry::ProviderInfo;
pub use registry::providers;
#[cfg(test)]
pub(crate) use traits::get_each;
pub use traits::{DiscoveryContext, ProducedValuePersistence, Provider, ProviderValue};

/// Validates a value at a provider boundary that only accepts text.
pub(crate) fn require_utf8<'a>(
    provider: &str,
    value: &'a crate::SecretBytes,
) -> crate::Result<&'a str> {
    std::str::from_utf8(value.expose_secret()).map_err(|_| {
        crate::SecretSpecError::ProviderOperationFailed(format!(
            "provider '{provider}' requires UTF-8 secret values"
        ))
    })
}

/// Removes the single newline a password-store CLI appends to a stored entry
/// or its display output, leaving every other byte untouched.
pub(crate) fn strip_one_trailing_newline(text: &str) -> &str {
    text.strip_suffix('\n').unwrap_or(text)
}

// Shared implementation support used by provider backends and orchestration.
pub(crate) use address::{OwnedAddress, flat_item};
#[cfg(any(
    feature = "cloudflare",
    feature = "openbao",
    feature = "scaleway",
    feature = "vault"
))]
pub(crate) use credentials::preferred_env;
pub(crate) use credentials::{
    ProviderCredentials, credential_env_value, credential_or_env, credential_or_envs,
};
pub(crate) use factory::{
    external_provider_from_spec, provider_from_spec, provider_url_from_spec, reject_uri_credential,
};
#[cfg(test)]
pub(crate) use factory::{provider_from_url, provider_from_url_with_discovery};
#[cfg(any(feature = "awssm", feature = "infisical", feature = "scaleway", test))]
pub(crate) use path::join_slash_path;
pub(crate) use preflight::ProviderWithPreflight;
#[cfg(any(feature = "cli", test))]
pub(crate) use registry::spec_provider_reads;
pub(crate) use registry::{
    credential_names_for_spec, deleting_provider_names, provider_display_name_for_spec,
    spec_names_known_provider, spec_uses_dynamic_credentials, static_delete_capability,
};
pub(crate) use runtime::block_on;
#[cfg(test)]
pub(crate) use traits::GET_EACH_CONCURRENCY_ENV;
pub(crate) use traits::exists_each;
pub(crate) use traits::get_each_with;
pub(crate) use traits::{
    get_each_concurrency, map_concurrently, same_configured_entries, same_storage_container,
};
pub(crate) use url::{ProviderUrl, URI_ENCODE_SET};

// Provider implementations.
#[cfg(feature = "aac")]
pub mod aac;
#[cfg(feature = "age")]
pub mod age;
#[cfg(feature = "akv")]
pub mod akv;
#[cfg(feature = "awsps")]
pub mod awsps;
#[cfg(feature = "awssm")]
pub mod awssm;
#[cfg(feature = "bw")]
pub mod bw;
#[cfg(feature = "bws")]
pub mod bws;
#[cfg(feature = "cloudflare")]
pub mod cloudflare;
pub mod dashlane;
#[cfg(feature = "doppler")]
pub mod doppler;
pub mod dotenv;
#[cfg(feature = "ejson")]
pub mod ejson;
pub mod env;
pub mod external;
pub mod file;
pub mod fly;
#[cfg(feature = "gcsm")]
pub mod gcsm;
pub mod gopass;
#[cfg(feature = "infisical")]
pub mod infisical;
#[cfg(feature = "kdbx")]
pub mod kdbx;
#[cfg(feature = "keeper")]
pub mod keeper;
#[cfg(feature = "keyring")]
pub mod keyring;
#[cfg(feature = "kubernetes")]
pub mod kubernetes;
pub mod lastpass;
pub mod null;
pub mod onepassword;
#[cfg(feature = "openbao")]
pub mod openbao;
pub mod pass;
pub mod passbolt;
pub mod protonpass;
#[cfg(feature = "scaleway")]
pub mod scaleway;
#[cfg(feature = "setec")]
pub mod setec;
#[cfg(feature = "sops")]
pub mod sops;
pub mod systemd_credential;
#[cfg(feature = "vault")]
pub mod vault;
#[cfg(any(feature = "openbao", feature = "vault"))]
mod vault_common;

#[cfg(test)]
pub(crate) mod tests;
