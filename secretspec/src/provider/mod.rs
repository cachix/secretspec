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
//! - [`dotenv::DotEnvProvider`]: `.env` file support
//! - [`env::EnvProvider`]: Environment variables (read-only)
//! - [`null::NullProvider`]: Defaults, generation, or run prompts without storage (0.19+)
//! - [`file::FileProvider`]: Plaintext file-per-secret storage (0.19+)
//! - [`fly::FlyProvider`]: Fly.io application secrets, write-only (0.20+)
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
mod credentials;
mod factory;
#[macro_use]
pub mod macros;
mod path;
mod preflight;
mod registry;
mod runtime;
mod traits;
mod url;

// Public provider API.
pub use address::Address;
pub use macros::{
    PROVIDER_REGISTRY, ProviderRegistration, declared_flag, declared_read_capability,
};
pub use registry::ProviderInfo;
#[cfg(feature = "cli")]
pub use registry::providers;
pub use traits::{DiscoveryContext, ProducedValuePersistence, Provider};

// Shared implementation support used by provider backends and orchestration.
pub(crate) use address::{OwnedAddress, flat_item};
#[cfg(any(feature = "openbao", feature = "scaleway", feature = "vault"))]
pub(crate) use credentials::preferred_env;
pub(crate) use credentials::{ProviderCredentials, credential_or_env, credential_or_envs};
pub(crate) use factory::provider_from_spec;
#[cfg(test)]
pub(crate) use factory::provider_from_url;
#[cfg(any(feature = "awssm", feature = "infisical", feature = "scaleway", test))]
pub(crate) use path::join_slash_path;
pub(crate) use preflight::ProviderWithPreflight;
#[cfg(any(feature = "cli", test))]
pub(crate) use registry::spec_provider_reads;
pub(crate) use registry::{
    credential_names_for_spec, deleting_provider_names, provider_display_name_for_spec,
    spec_names_known_provider, spec_provider_deletes,
};
#[cfg(any(
    feature = "akv",
    feature = "awsps",
    feature = "awssm",
    feature = "gcsm",
    feature = "infisical",
    feature = "scaleway"
))]
pub(crate) use runtime::block_on;
#[cfg(test)]
pub(crate) use traits::GET_EACH_CONCURRENCY_ENV;
#[cfg(test)]
pub(crate) use traits::get_each;
#[cfg(any(feature = "infisical", feature = "openbao", feature = "vault"))]
pub(crate) use traits::get_each_with;
pub(crate) use traits::{get_each_concurrency, map_concurrently, same_storage_container};
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
pub mod dashlane;
pub mod dotenv;
pub mod env;
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
#[cfg(feature = "sops")]
pub mod sops;
pub mod systemd_credential;
#[cfg(feature = "vault")]
pub mod vault;
#[cfg(any(feature = "openbao", feature = "vault"))]
mod vault_common;

#[cfg(test)]
pub(crate) mod tests;
