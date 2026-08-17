//! Google Cloud Secret Manager provider
//!
//! This provider integrates with Google Cloud Secret Manager to store and retrieve secrets.
//!
//! # Authentication
//!
//! Uses Application Default Credentials (ADC). Set up via:
//! - `gcloud auth application-default login` for local development
//! - Service account with `GOOGLE_APPLICATION_CREDENTIALS` environment variable
//! - Workload Identity for GKE environments
//!
//! # URI Format
//!
//! `gcsm://project-id`
//!
//! # Secret Naming
//!
//! Starting in SecretSpec 0.20, convention secrets are stored as
//! `secretspec2--{project}--{profile}--{key}`. The versioned prefix separates
//! the new namespace from every legacy id, while validated `--` delimiters keep
//! project, profile, and key boundaries unambiguous. Releases through 0.19 used
//! the ambiguous `secretspec-{project}-{profile}-{key}` form. A read falls back
//! to the legacy id when the new one holds no value, so a 0.19 project keeps
//! working untouched; writes always use the new id, so setting a secret is what
//! moves it.
//!
//! # Example
//!
//! ```bash
//! # Set up authentication
//! gcloud auth application-default login
//!
//! # Set a secret
//! secretspec set DATABASE_URL --provider gcsm://my-gcp-project
//!
//! # Check secrets from GCP
//! secretspec check --provider gcsm://my-gcp-project
//! ```

use super::{Address, Provider, ProviderUrl};
use crate::{Result, SecretSpecError};
use google_cloud_secretmanager_v1::client::SecretManagerService;
use google_cloud_secretmanager_v1::model::{Replication, Secret, SecretPayload, replication};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

/// Configuration for the Google Cloud Secret Manager provider.
///
/// Contains the GCP project ID where secrets are stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcsmConfig {
    /// The GCP project ID (e.g., "my-gcp-project")
    pub project_id: String,
}

/// Validates a GCP project ID format.
///
/// GCP project IDs must:
/// - Be 6-30 characters long
/// - Start with a lowercase letter
/// - Contain only lowercase letters, digits, and hyphens
/// - Not end with a hyphen
fn validate_gcp_project_id(project_id: &str) -> std::result::Result<(), SecretSpecError> {
    let len = project_id.len();
    if !(6..=30).contains(&len) {
        return Err(SecretSpecError::ProviderOperationFailed(format!(
            "GCP project ID must be 6-30 characters, got {}",
            len
        )));
    }

    let mut chars = project_id.chars().peekable();

    // First character must be a lowercase letter
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => {
            return Err(SecretSpecError::ProviderOperationFailed(
                "GCP project ID must start with a lowercase letter".to_string(),
            ));
        }
    }

    // Check remaining characters
    for c in chars {
        if !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '-' {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "GCP project ID contains invalid character '{}'. \
                Only lowercase letters, digits, and hyphens are allowed",
                c
            )));
        }
    }

    // Cannot end with a hyphen
    if project_id.ends_with('-') {
        return Err(SecretSpecError::ProviderOperationFailed(
            "GCP project ID cannot end with a hyphen".to_string(),
        ));
    }

    Ok(())
}

impl TryFrom<&ProviderUrl> for GcsmConfig {
    type Error = SecretSpecError;

    fn try_from(url: &ProviderUrl) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "gcsm" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for gcsm provider. Expected 'gcsm'.",
                url.scheme()
            )));
        }

        // Extract project ID from host portion: gcsm://project-id
        let project_id = url.host().filter(|s| !s.is_empty()).ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(
                "GCP project ID is required. Use format: gcsm://project-id".to_string(),
            )
        })?;

        // Validate project ID format
        validate_gcp_project_id(&project_id)?;

        // The path reference form from earlier iterations is rejected with a
        // pointer at the `ref` table, instead of being silently ignored and
        // reading the conventional layout.
        let path = url.path();
        let trimmed = path.trim_start_matches('/');
        if !trimmed.is_empty() {
            let id = trimmed
                .strip_prefix("secrets/")
                .unwrap_or(trimmed)
                .split('/')
                .next()
                .unwrap_or(trimmed);
            let hint = crate::config::ref_table_hint(None, id, None, None);
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "gcsm URIs take no path: address the secret with \
                 {hint} on the secret instead \
                 (add version = \"<n>\" to pin a version)"
            )));
        }

        Ok(Self { project_id })
    }
}

/// Google Cloud Secret Manager provider.
///
/// This provider stores and retrieves secrets from Google Cloud Secret Manager using
/// Application Default Credentials for authentication.
pub struct GcsmProvider {
    config: GcsmConfig,
}

/// A project still on the 0.19 layout, or whose name the current convention
/// cannot represent, reads the same way for every secret in a run. These
/// warnings print once per process so a `run` over dozens of secrets stays
/// readable.
static LEGACY_FALLBACK_WARNING: std::sync::Once = std::sync::Once::new();
static UNREPRESENTABLE_NAME_WARNING: std::sync::Once = std::sync::Once::new();

/// The three GCSM operations the provider needs. Keeping the orchestration
/// above the generated Google client makes reads, writes, and the legacy
/// fallback independently testable.
trait GcsmBackend {
    async fn access_secret_version(
        &self,
        secret_name: &str,
        version: &str,
    ) -> Result<Option<SecretString>>;

    /// Creating a secret that already exists succeeds: callers only need the
    /// resource to be there before adding a version.
    async fn create_secret(&self, secret_name: &str) -> Result<()>;

    async fn add_secret_version(&self, secret_name: &str, value: &SecretString) -> Result<()>;
}

struct GoogleGcsmBackend<'a> {
    project_id: &'a str,
    client: SecretManagerService,
}

impl GcsmBackend for GoogleGcsmBackend<'_> {
    async fn access_secret_version(
        &self,
        secret_name: &str,
        version: &str,
    ) -> Result<Option<SecretString>> {
        let secret_version_path = format!(
            "projects/{}/secrets/{secret_name}/versions/{version}",
            self.project_id
        );

        match self
            .client
            .access_secret_version()
            .set_name(&secret_version_path)
            .send()
            .await
        {
            Ok(response) => {
                if let Some(payload) = response.payload {
                    let data = String::from_utf8(payload.data.to_vec()).map_err(|error| {
                        SecretSpecError::ProviderOperationFailed(format!(
                            "Secret data is not valid UTF-8: {error}"
                        ))
                    })?;
                    Ok(Some(SecretString::new(data.into())))
                } else {
                    Ok(None)
                }
            }
            Err(error) if GcsmProvider::is_not_found_error(&error) => Ok(None),
            Err(error) => Err(SecretSpecError::ProviderOperationFailed(format!(
                "Failed to access secret '{secret_name}': {}",
                crate::error::display_error_chain(&error)
            ))),
        }
    }

    async fn create_secret(&self, secret_name: &str) -> Result<()> {
        let result = self
            .client
            .create_secret()
            .set_parent(format!("projects/{}", self.project_id))
            .set_secret_id(secret_name)
            .set_secret(Secret::default().set_replication(
                Replication::default().set_automatic(replication::Automatic::default()),
            ))
            .send()
            .await;

        match result {
            Ok(_) => Ok(()),
            Err(error) if GcsmProvider::is_already_exists_error(&error) => Ok(()),
            Err(error) => Err(SecretSpecError::ProviderOperationFailed(format!(
                "Failed to create secret '{secret_name}': {}",
                crate::error::display_error_chain(&error)
            ))),
        }
    }

    async fn add_secret_version(&self, secret_name: &str, value: &SecretString) -> Result<()> {
        self.client
            .add_secret_version()
            .set_parent(format!(
                "projects/{}/secrets/{secret_name}",
                self.project_id
            ))
            .set_payload(
                SecretPayload::default().set_data(value.expose_secret().as_bytes().to_vec()),
            )
            .send()
            .await
            .map_err(|error| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to add secret version for '{secret_name}': {}",
                    crate::error::display_error_chain(&error)
                ))
            })?;

        Ok(())
    }
}

crate::register_provider! {
    struct: GcsmProvider,
    config: GcsmConfig,
    name: "gcsm",
    description: "Google Cloud Secret Manager",
    schemes: ["gcsm"],
    examples: ["gcsm://my-gcp-project"],
}

impl GcsmProvider {
    /// Creates a new GcsmProvider with the given configuration.
    pub fn new(config: GcsmConfig) -> Self {
        Self { config }
    }

    /// Validates a secret name component for GCP Secret Manager.
    ///
    /// Components contain only alphanumeric characters, underscores, and
    /// internal single hyphens. A component may not contain `--` or begin or
    /// end with `-`: either shape could consume or overlap a `--` boundary.
    fn validate_name_component(name: &str, component: &str) -> Result<()> {
        if component.is_empty() {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "{} cannot be empty",
                name
            )));
        }

        for c in component.chars() {
            if !c.is_ascii_alphanumeric() && c != '_' && c != '-' {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "{} contains invalid character '{}'. \
                    Only alphanumeric characters, underscores, and hyphens are allowed",
                    name, c
                )));
            }
        }

        if component.starts_with('-') || component.ends_with('-') || component.contains("--") {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "{name} '{component}' cannot start or end with a hyphen or contain `--`: the \
                 GCSM convention separates project, profile, and key with `--`, so only single \
                 internal hyphens stay unambiguous. Rename it and run `secretspec set` to store \
                 the value under the new name, or address the secret with a `ref` entry."
            )));
        }

        Ok(())
    }

    /// Formats and validates the secret name for GCP Secret Manager.
    ///
    /// Converts the SecretSpec path format to the readable, injective,
    /// GCP-compatible name `secretspec2--{project}--{profile}--{key}`.
    ///
    /// GCP Secret Manager secret IDs must:
    /// - Be 1-255 characters long
    /// - Contain only alphanumeric characters, hyphens, and underscores
    fn format_secret_name(project: &str, profile: &str, key: &str) -> Result<String> {
        // Validate each component
        Self::validate_name_component("project", project)?;
        Self::validate_name_component("profile", profile)?;
        Self::validate_name_component("key", key)?;

        let secret_name = format!("secretspec2--{project}--{profile}--{key}");

        // GCP secret IDs must be 1-255 characters
        if secret_name.len() > 255 {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Secret name too long: {} characters (max 255)",
                secret_name.len()
            )));
        }

        Ok(secret_name)
    }

    /// The ambiguous convention used through SecretSpec 0.19. This is only a
    /// read fallback; writes and normal addressing never emit a legacy id.
    fn format_legacy_secret_name(project: &str, profile: &str, key: &str) -> String {
        format!("secretspec-{project}-{profile}-{key}")
    }

    /// Checks if an error indicates the resource was not found.
    fn is_not_found_error(e: &(impl std::error::Error + 'static)) -> bool {
        let s = crate::error::display_error_chain(e);
        s.contains("NOT_FOUND") || s.contains("notFound")
    }

    /// Checks if an error indicates the resource already exists.
    fn is_already_exists_error(e: &(impl std::error::Error + 'static)) -> bool {
        let s = crate::error::display_error_chain(e);
        s.contains("ALREADY_EXISTS") || s.contains("alreadyExists")
    }

    /// Creates a SecretManagerService client.
    async fn create_client(&self) -> Result<SecretManagerService> {
        SecretManagerService::builder().build().await.map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!(
                "Failed to create GCP Secret Manager client: {}\n\n\
                Ensure Application Default Credentials are configured:\n  \
                - Local development: Run 'gcloud auth application-default login'\n  \
                - Service account: Set GOOGLE_APPLICATION_CREDENTIALS environment variable\n  \
                - GKE: Configure Workload Identity",
                crate::error::display_error_chain(&e)
            ))
        })
    }

    async fn get_coords_with_backend(
        backend: &impl GcsmBackend,
        coords: &crate::config::NativeAddress,
    ) -> Result<Option<SecretString>> {
        let version = coords.version.as_deref().unwrap_or("latest");
        backend.access_secret_version(&coords.item, version).await
    }

    /// Resolves coordinates to a version resource and reads it, mapping "not
    /// found" to `None`: `item` is the secret id, `version` the version to read
    /// (defaulting to the latest).
    async fn get_coords_async(
        &self,
        coords: &crate::config::NativeAddress,
    ) -> Result<Option<SecretString>> {
        let client = self.create_client().await?;
        let backend = GoogleGcsmBackend {
            project_id: &self.config.project_id,
            client,
        };
        Self::get_coords_with_backend(&backend, coords).await
    }

    /// Reads the legacy id as a best-effort compatibility source. That id is an
    /// implementation detail of the fallback rather than an address the caller
    /// chose: a project with secret-level IAM answers PERMISSION_DENIED rather
    /// than NOT_FOUND for an id nobody was granted a binding on, and that must
    /// not turn an unset secret into a failed read.
    async fn read_legacy_value(
        backend: &impl GcsmBackend,
        legacy_name: &str,
    ) -> Option<SecretString> {
        backend
            .access_secret_version(legacy_name, "latest")
            .await
            .ok()
            .flatten()
    }

    /// Reads the 0.20 convention id, falling back to the 0.19 id when the new
    /// one holds no value.
    ///
    /// The fallback is a read: nothing is created, copied, or deleted. So
    /// credentials that can read secrets but not create them, the common CI
    /// setup, keep working across the upgrade; no write can race with a
    /// concurrent writer or shadow a newer value; and the next `secretspec set`
    /// moves the secret to the current id on its own.
    async fn get_convention_with_backend(
        backend: &impl GcsmBackend,
        project: &str,
        profile: &str,
        key: &str,
    ) -> Result<Option<SecretString>> {
        let legacy_name = Self::format_legacy_secret_name(project, profile, key);
        let secret_name = match Self::format_secret_name(project, profile, key) {
            Ok(name) => name,
            // Releases through 0.19 accepted names the 0.20 layout cannot
            // represent. Serve what is already stored rather than failing the
            // read; `set` still carries the rename instruction.
            Err(naming_error) => {
                let Some(value) = Self::read_legacy_value(backend, &legacy_name).await else {
                    return Err(naming_error);
                };
                UNREPRESENTABLE_NAME_WARNING.call_once(|| {
                    eprintln!(
                        "Warning: reading the SecretSpec 0.19 GCSM secret '{legacy_name}' because \
                         the current naming convention cannot represent this address: \
                         {naming_error} Writes keep failing until the name changes. Further \
                         secrets with this problem are not reported again."
                    )
                });
                return Ok(Some(value));
            }
        };

        if let Some(value) = backend
            .access_secret_version(&secret_name, "latest")
            .await?
        {
            return Ok(Some(value));
        }

        let Some(value) = Self::read_legacy_value(backend, &legacy_name).await else {
            return Ok(None);
        };

        LEGACY_FALLBACK_WARNING.call_once(|| {
            eprintln!(
                "Warning: reading the SecretSpec 0.19 GCSM secret '{legacy_name}' because \
                 '{secret_name}' holds no value. Run `secretspec set` for this secret to store it \
                 under the current name; the 0.19 secret is left in place either way. Further \
                 secrets read this way are not reported again."
            )
        });
        Ok(Some(value))
    }

    async fn get_convention_async(
        &self,
        project: &str,
        profile: &str,
        key: &str,
    ) -> Result<Option<SecretString>> {
        let client = self.create_client().await?;
        let backend = GoogleGcsmBackend {
            project_id: &self.config.project_id,
            client,
        };
        Self::get_convention_with_backend(&backend, project, profile, key).await
    }

    /// Creates or updates a secret in GCP Secret Manager.
    ///
    /// Always attempts to create the secret first (idempotent operation), then adds a new version.
    /// This avoids TOCTOU race conditions by not checking existence before creation.
    async fn set_secret_with_backend(
        backend: &impl GcsmBackend,
        secret_name: &str,
        value: &SecretString,
    ) -> Result<()> {
        backend.create_secret(secret_name).await?;
        backend.add_secret_version(secret_name, value).await
    }

    async fn set_secret_async(&self, secret_name: &str, value: &SecretString) -> Result<()> {
        let client = self.create_client().await?;
        let backend = GoogleGcsmBackend {
            project_id: &self.config.project_id,
            client,
        };
        Self::set_secret_with_backend(&backend, secret_name, value).await
    }
}

impl Provider for GcsmProvider {
    /// Convention names use validated `--` boundaries so distinct accepted
    /// project/profile/key triples always produce distinct GCSM secret ids.
    fn convention_address(
        &self,
        project: &str,
        profile: &str,
        key: &str,
    ) -> Result<crate::config::NativeAddress> {
        Ok(crate::config::NativeAddress {
            item: Self::format_secret_name(project, profile, key)?,
            ..Default::default()
        })
    }

    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn uri(&self) -> String {
        format!("gcsm://{}", self.config.project_id)
    }

    /// An optional `version` pins the secret version to read.
    fn supported_coords(&self) -> &'static [&'static str] {
        &["version"]
    }

    fn get(&self, addr: Address<'_>) -> Result<Option<SecretString>> {
        match addr {
            Address::Convention {
                project,
                profile,
                key,
            } => super::block_on(self.get_convention_async(project, profile, key)),
            Address::Native(_) => {
                let coords = self.resolve_coords(addr)?;
                super::block_on(self.get_coords_async(&coords))
            }
        }
    }

    fn set(&self, addr: Address<'_>, value: &SecretString) -> Result<()> {
        self.check_writable(addr)?;
        let coords = self.resolve_coords(addr)?;
        super::block_on(self.set_secret_async(&coords.item, value))
    }

    /// Native addresses are read-only: they name an existing (often
    /// version-pinned) secret, and writing would mean minting a new version of
    /// someone else's secret.
    fn check_writable(&self, addr: Address<'_>) -> Result<()> {
        match addr {
            Address::Convention { .. } => Ok(()),
            Address::Native(_) => Err(SecretSpecError::ProviderOperationFailed(
                "gcsm secret references are read-only and cannot be written".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod reference_tests {
    use super::*;
    use url::Url;

    /// A path that is not a `secrets/...` resource is rejected.
    #[test]
    fn path_is_rejected_with_ref_hint() {
        let err = GcsmConfig::try_from(&ProviderUrl::new(
            Url::parse("gcsm://my-project/secrets/db-url/versions/3").unwrap(),
        ))
        .unwrap_err();
        assert!(
            err.to_string().contains("ref = { item = \"db-url\" }"),
            "{err}"
        );
    }

    /// Native addresses are read-only: writing would mint a new version of a
    /// secret managed outside SecretSpec.
    #[test]
    fn native_address_is_read_only() {
        let c = GcsmConfig::try_from(&ProviderUrl::new(Url::parse("gcsm://my-project").unwrap()))
            .unwrap();
        let p = GcsmProvider::new(c);
        let addr = crate::config::NativeAddress {
            item: "db-url".into(),
            ..Default::default()
        };
        let refusal = p.check_writable(Address::Native(&addr)).unwrap_err();
        assert!(refusal.to_string().contains("read-only"), "{refusal}");
        // `set` refuses with the same reason, so the pre-check cannot drift.
        let err = p
            .set(
                Address::Native(&addr),
                &secrecy::SecretString::new("v".into()),
            )
            .unwrap_err();
        assert_eq!(err.to_string(), refusal.to_string());
    }

    /// GCSM secrets have no fields; the coordinate is rejected before any
    /// network I/O.
    #[test]
    fn native_address_rejects_field() {
        let c = GcsmConfig::try_from(&ProviderUrl::new(Url::parse("gcsm://my-project").unwrap()))
            .unwrap();
        let p = GcsmProvider::new(c);
        let addr = crate::config::NativeAddress {
            item: "db-url".into(),
            field: Some("x".into()),
            ..Default::default()
        };
        let err = p.get(Address::Native(&addr)).unwrap_err();
        assert!(err.to_string().contains("`field`"), "{err}");
    }

    #[test]
    fn convention_name_is_collision_safe() {
        let first = GcsmProvider::format_secret_name("my-app", "prod", "K").unwrap();
        let second = GcsmProvider::format_secret_name("my", "app-prod", "K").unwrap();

        assert_ne!(first, second);
        assert_eq!(first, "secretspec2--my-app--prod--K");
        assert_eq!(second, "secretspec2--my--app-prod--K");
    }

    #[test]
    fn convention_name_rejects_ambiguous_hyphen_shapes() {
        for component in ["-app", "app-", "app--prod"] {
            let error = GcsmProvider::format_secret_name(component, "prod", "K").unwrap_err();
            assert!(
                error.to_string().contains("cannot start or end")
                    && error.to_string().contains("contain `--`"),
                "{component}: {error}"
            );
        }
    }

    #[test]
    fn convention_name_enforces_gcsm_length_limit_after_framing() {
        let largest_project = "a".repeat(236);
        let name = GcsmProvider::format_secret_name(&largest_project, "p", "K").unwrap();
        assert_eq!(name.len(), 255);

        let error =
            GcsmProvider::format_secret_name(&format!("{largest_project}a"), "p", "K").unwrap_err();
        assert!(error.to_string().contains("256 characters"), "{error}");
    }

    #[test]
    fn legacy_name_is_retained_only_as_a_read_fallback() {
        assert_eq!(
            GcsmProvider::format_legacy_secret_name("my-app", "prod", "K"),
            "secretspec-my-app-prod-K"
        );
    }
}

/// Property tests for the injective convention-name mapping.
#[cfg(test)]
mod name_properties {
    use super::*;
    use proptest::prelude::*;

    /// Components contain internal single hyphens but never a delimiter or a
    /// leading/trailing hyphen, exactly matching the structural validator.
    fn component() -> impl Strategy<Value = String> {
        prop::collection::vec(
            proptest::string::string_regex("[A-Za-z0-9_]{1,8}").unwrap(),
            1..4,
        )
        .prop_map(|parts| parts.join("-"))
    }

    fn triple() -> impl Strategy<Value = (String, String, String)> {
        (component(), component(), component())
    }

    /// A left inverse proves that every formatted name identifies exactly the
    /// triple that produced it.
    fn decode_secret_name(name: &str) -> Option<(String, String, String)> {
        let body = name.strip_prefix("secretspec2--")?;
        let parts: Vec<&str> = body.split("--").collect();
        let [project, profile, key] = parts.as_slice() else {
            return None;
        };
        Some((
            (*project).to_string(),
            (*profile).to_string(),
            (*key).to_string(),
        ))
    }

    proptest! {
        #[test]
        fn convention_name_decodes_to_its_original_triple(
            (project, profile, key) in triple()
        ) {
            let name = GcsmProvider::format_secret_name(&project, &profile, &key)
                .expect("a valid component must format");
            prop_assert_eq!(
                decode_secret_name(&name),
                Some((project, profile, key)),
            );
        }

        #[test]
        fn distinct_triples_never_share_a_convention_name(
            triples in prop::collection::vec(triple(), 2..24)
        ) {
            let mut seen = std::collections::HashMap::new();
            for (project, profile, key) in triples {
                let triple = (project, profile, key);
                let name = GcsmProvider::format_secret_name(&triple.0, &triple.1, &triple.2)
                    .expect("a valid component must format");
                if let Some(previous) = seen.insert(name.clone(), triple.clone()) {
                    prop_assert_eq!(previous, triple, "collision at {}", name);
                }
            }
        }
    }
}

#[cfg(test)]
mod legacy_fallback_tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;

    const LEGACY: &str = "secretspec-my-app-prod-K";
    const CURRENT: &str = "secretspec2--my-app--prod--K";

    #[derive(Default)]
    struct FakeGcsmBackend {
        /// An empty vector means that the Secret resource exists without a
        /// version. Vector indices are the zero-based form of GCSM version ids.
        secrets: Mutex<HashMap<String, Vec<String>>>,
        accesses: Mutex<Vec<String>>,
        writes: Mutex<Vec<String>>,
        unreadable: Mutex<HashSet<String>>,
    }

    impl FakeGcsmBackend {
        fn insert(&self, name: &str, value: &str) {
            self.secrets
                .lock()
                .unwrap()
                .insert(name.to_string(), vec![value.to_string()]);
        }

        fn insert_empty(&self, name: &str) {
            self.secrets
                .lock()
                .unwrap()
                .insert(name.to_string(), Vec::new());
        }

        fn value(&self, name: &str) -> Option<String> {
            self.secrets
                .lock()
                .unwrap()
                .get(name)
                .and_then(|versions| versions.last())
                .cloned()
        }

        /// Simulates the secret-level IAM binding a caller was never granted:
        /// GCSM answers PERMISSION_DENIED rather than NOT_FOUND.
        fn deny_access(&self, name: &str) {
            self.unreadable.lock().unwrap().insert(name.to_string());
        }
    }

    impl GcsmBackend for FakeGcsmBackend {
        async fn access_secret_version(
            &self,
            secret_name: &str,
            version: &str,
        ) -> Result<Option<SecretString>> {
            self.accesses
                .lock()
                .unwrap()
                .push(format!("{secret_name}@{version}"));
            if self.unreadable.lock().unwrap().contains(secret_name) {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Failed to access secret '{secret_name}': PERMISSION_DENIED"
                )));
            }

            let secrets = self.secrets.lock().unwrap();
            let value = secrets.get(secret_name).and_then(|versions| {
                if version == "latest" {
                    versions.last()
                } else {
                    version
                        .parse::<usize>()
                        .ok()
                        .and_then(|number| number.checked_sub(1))
                        .and_then(|index| versions.get(index))
                }
            });
            Ok(value.cloned().map(|value| SecretString::new(value.into())))
        }

        async fn create_secret(&self, secret_name: &str) -> Result<()> {
            self.writes
                .lock()
                .unwrap()
                .push(format!("create {secret_name}"));
            self.secrets
                .lock()
                .unwrap()
                .entry(secret_name.to_string())
                .or_default();
            Ok(())
        }

        async fn add_secret_version(&self, secret_name: &str, value: &SecretString) -> Result<()> {
            self.writes
                .lock()
                .unwrap()
                .push(format!("add {secret_name}"));
            let mut secrets = self.secrets.lock().unwrap();
            let versions = secrets.get_mut(secret_name).ok_or_else(|| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "secret '{secret_name}' was not created"
                ))
            })?;
            versions.push(value.expose_secret().to_string());
            Ok(())
        }
    }

    fn read(backend: &FakeGcsmBackend) -> Result<Option<SecretString>> {
        read_project(backend, "my-app")
    }

    fn read_project(backend: &FakeGcsmBackend, project: &str) -> Result<Option<SecretString>> {
        crate::provider::block_on(GcsmProvider::get_convention_with_backend(
            backend, project, "prod", "K",
        ))
    }

    fn write(backend: &FakeGcsmBackend, value: &str) -> Result<()> {
        crate::provider::block_on(GcsmProvider::set_secret_with_backend(
            backend,
            CURRENT,
            &SecretString::new(value.into()),
        ))
    }

    /// A project written by 0.19 keeps reading after the upgrade, and the read
    /// leaves GCSM untouched: no create, no version, no delete.
    #[test]
    fn a_missing_current_id_falls_back_to_the_legacy_value() {
        let backend = FakeGcsmBackend::default();
        backend.insert(LEGACY, "legacy-value");

        let value = read(&backend).unwrap().unwrap();
        assert_eq!(value.expose_secret(), "legacy-value");
        assert!(backend.writes.lock().unwrap().is_empty());
        assert_eq!(backend.value(LEGACY).as_deref(), Some("legacy-value"));
        assert!(!backend.secrets.lock().unwrap().contains_key(CURRENT));
    }

    /// A Secret resource without a version reads as unset, so the fallback
    /// covers a destination that a 0.20 write only partly created.
    #[test]
    fn a_current_id_without_a_version_falls_back_to_the_legacy_value() {
        let backend = FakeGcsmBackend::default();
        backend.insert(LEGACY, "legacy-value");
        backend.insert_empty(CURRENT);

        let value = read(&backend).unwrap().unwrap();
        assert_eq!(value.expose_secret(), "legacy-value");
        assert!(backend.writes.lock().unwrap().is_empty());
    }

    #[test]
    fn the_current_id_wins_without_reading_the_legacy_id() {
        let backend = FakeGcsmBackend::default();
        backend.insert(LEGACY, "legacy-value");
        backend.insert(CURRENT, "current-value");

        let value = read(&backend).unwrap().unwrap();
        assert_eq!(value.expose_secret(), "current-value");
        assert_eq!(
            backend.accesses.lock().unwrap().as_slice(),
            &[format!("{CURRENT}@latest")]
        );
    }

    /// Writing is what moves a secret onto the current convention. The 0.19
    /// secret is left in place, so an older SecretSpec keeps working until the
    /// project chooses to delete it.
    #[test]
    fn a_write_moves_the_secret_to_the_current_id() {
        let backend = FakeGcsmBackend::default();
        backend.insert(LEGACY, "legacy-value");

        write(&backend, "new-value").unwrap();
        backend.accesses.lock().unwrap().clear();

        let value = read(&backend).unwrap().unwrap();
        assert_eq!(value.expose_secret(), "new-value");
        assert_eq!(
            backend.accesses.lock().unwrap().as_slice(),
            &[format!("{CURRENT}@latest")]
        );
        assert_eq!(backend.value(LEGACY).as_deref(), Some("legacy-value"));
    }

    /// The legacy id is a compatibility source rather than an address the
    /// caller chose, so being unable to read it means "nothing stored".
    #[test]
    fn an_unreadable_legacy_id_leaves_an_unset_secret_unset() {
        let backend = FakeGcsmBackend::default();
        backend.deny_access(LEGACY);

        assert!(read(&backend).unwrap().is_none());
    }

    /// The current id is the address the caller did choose, so it still fails
    /// loudly instead of silently serving a stale 0.19 value.
    #[test]
    fn an_unreadable_current_id_fails_the_read() {
        let backend = FakeGcsmBackend::default();
        backend.insert(LEGACY, "legacy-value");
        backend.deny_access(CURRENT);

        let error = read(&backend).unwrap_err();
        assert!(error.to_string().contains("PERMISSION_DENIED"), "{error}");
    }

    #[test]
    fn absent_current_and_legacy_ids_remain_a_miss() {
        let backend = FakeGcsmBackend::default();

        assert!(read(&backend).unwrap().is_none());
        assert!(backend.secrets.lock().unwrap().is_empty());
        assert!(backend.writes.lock().unwrap().is_empty());
    }

    /// Releases through 0.19 stored triples the current layout cannot
    /// represent, such as a project directory named `my--app`. Reads keep
    /// serving what is already stored.
    #[test]
    fn an_unrepresentable_name_still_reads_its_legacy_secret() {
        let backend = FakeGcsmBackend::default();
        backend.insert("secretspec-my--app-prod-K", "legacy-value");

        let value = read_project(&backend, "my--app").unwrap().unwrap();
        assert_eq!(value.expose_secret(), "legacy-value");
        assert!(backend.writes.lock().unwrap().is_empty());
    }

    /// With nothing stored under either name there is no value to serve, so the
    /// naming error carries the rename that makes the project usable.
    #[test]
    fn an_unrepresentable_name_reports_the_rename_when_nothing_is_stored() {
        let backend = FakeGcsmBackend::default();

        let error = read_project(&backend, "my--app").unwrap_err();
        assert!(error.to_string().contains("Rename it"), "{error}");
    }
}
