//! Format-independent SecretSpec declarations.
//!
//! [`Spec`] is the semantic boundary shared by file-based configuration and
//! declarations assembled directly in Rust. The TOML representation remains
//! an implementation detail in `config`; callers construct the same model with
//! [`SpecBuilder`], [`Profile`], and [`Secret`].

use crate::compiled_spec::CompiledSpec;
use crate::config::{
    Config, CredentialBinding, GenerateConfig, GenerateOptions, NativeAddress,
    Profile as ConfigProfile, ProfileDefaults, Project, ProviderAlias, RequireReason, Scope,
    Secret as ConfigSecret, SecretEncoding, SecretExtract,
};
use crate::error::{Result, SecretSpecError};
use std::collections::BTreeMap;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// A validated, format-independent description of a SecretSpec project.
///
/// A `Spec` may be loaded from `secretspec.toml` with [`Spec::try_from`] or
/// assembled directly in Rust with [`Spec::builder`]. Both paths perform the
/// same semantic validation and produce the same compiled representation.
///
/// Available starting with SecretSpec 0.20.
#[derive(Debug, Clone)]
pub struct Spec {
    /// Effective configuration after applying inheritance.
    pub(crate) config: Config,
    pub(crate) compiled: CompiledSpec,
    pub(crate) base_dir: Option<PathBuf>,
    /// Unmerged declarations from the root spec.
    pub(crate) root_config: Option<Config>,
    /// Exact root document text when builder edits can preserve it.
    pub(crate) source: Option<String>,
    /// Root profile tables created by builder edits and removable on undo.
    pub(crate) synthesized_profiles: HashSet<String>,
}

impl Spec {
    /// Begin describing a project directly in Rust.
    pub fn builder(project: impl Into<String>) -> SpecBuilder {
        SpecBuilder::new(project)
    }

    /// Parse and validate one complete TOML document.
    ///
    /// A string has no location against which `extends` paths can be resolved,
    /// so use [`Spec::try_from`] with a path when the document uses inheritance.
    pub fn from_toml(source: &str) -> Result<Self> {
        let config = Config::from_str(source)?;
        if config
            .project
            .extends
            .as_ref()
            .is_some_and(|extends| !extends.is_empty())
        {
            return Err(SecretSpecError::InvalidSpec(
                "a TOML string cannot resolve `project.extends`; load it from a path with Spec::try_from"
                    .to_string(),
            ));
        }
        let mut spec = Self::from_config_document(config.clone())?;
        spec.root_config = Some(config);
        spec.source = Some(source.to_string());
        Ok(spec)
    }

    /// The project name used for provider namespacing.
    pub fn project(&self) -> &str {
        &self.compiled.project
    }

    /// Declared profile names in deterministic order.
    pub fn profiles(&self) -> impl ExactSizeIterator<Item = &str> {
        self.compiled.profiles.keys().map(String::as_str)
    }

    /// Effective secret names for `profile`, including inherited declarations.
    pub fn secrets(&self, profile: &str) -> Option<impl ExactSizeIterator<Item = &str>> {
        self.compiled
            .profile(profile)
            .map(|profile| profile.secrets.keys().map(String::as_str))
    }

    /// Emit a JSON Schema for this specification's typed shape.
    ///
    /// `None` emits the union `SecretSpec`, which is safe for any profile.
    /// `Some(profile)` emits that profile's effective fields, including fields
    /// inherited from `default`.
    ///
    /// This reads declarations only and never resolves secret values or contacts
    /// a provider.
    ///
    /// Available starting with SecretSpec 0.20.
    pub fn schema_json(&self, profile: Option<&str>) -> Result<String> {
        crate::codegen::schema::emit(&crate::codegen::build_ir(self), profile)
            .map_err(SecretSpecError::InvalidProfile)
    }

    /// Consume this validated specification and reopen its declarations for editing.
    ///
    /// [`SpecBuilder::build`] validates and compiles the edited declarations into a
    /// new `Spec`. The original `Spec` is consumed so its declarations and compiled
    /// view can never drift apart. Secret edits to a TOML-backed spec preserve its
    /// comments and ordering. Use [`Self::to_builder`] to retain it.
    pub fn into_builder(self) -> SpecBuilder {
        self.into()
    }

    /// Copy this validated specification into a builder for editing.
    ///
    /// The original `Spec` remains unchanged. Secret edits to a TOML-backed spec
    /// preserve its comments and ordering. Prefer [`Self::into_builder`] when it
    /// is no longer needed.
    pub fn to_builder(&self) -> SpecBuilder {
        self.into()
    }

    pub(crate) fn from_config_document(config: Config) -> Result<Self> {
        if config.project.revision != "1.0" {
            return Err(SecretSpecError::UnsupportedRevision(
                config.project.revision,
            ));
        }
        let compiled = config.validate_and_compile()?;
        Ok(Self {
            config,
            compiled,
            base_dir: None,
            root_config: None,
            source: None,
            synthesized_profiles: HashSet::new(),
        })
    }

    pub(crate) fn into_parts(self) -> (Config, CompiledSpec) {
        (self.config, self.compiled)
    }

    /// The exact root TOML retained from parsing and format-preserving edits.
    ///
    /// This is `None` for specs built directly in Rust or after a builder
    /// operation without format-preserving behavior.
    ///
    /// Available starting with SecretSpec 0.20.
    pub fn preserved_text(&self) -> Option<&str> {
        self.source.as_deref()
    }

    /// Render the root specification as freshly formatted TOML. Inherited
    /// declarations remain in their parent specs rather than being inlined.
    ///
    /// Use [`Self::preserved_text`] when comments and original ordering matter.
    ///
    /// Available starting with SecretSpec 0.20.
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self.root_config.as_ref().unwrap_or(&self.config))
            .map_err(|error| SecretSpecError::InvalidSpec(error.to_string()))
    }
}

/// Derive-crate bridge that preserves configuration-loader diagnostics while
/// still returning the same validated [`Spec`] every other frontend consumes.
#[doc(hidden)]
pub fn load_for_codegen(path: &Path) -> std::result::Result<Spec, String> {
    let config = Config::try_from(path).map_err(|error| error.to_string())?;
    Spec::from_config_document(config).map_err(|error| error.to_string())
}

impl FromStr for Spec {
    type Err = SecretSpecError;

    fn from_str(source: &str) -> Result<Self> {
        Self::from_toml(source)
    }
}

impl TryFrom<&Path> for Spec {
    type Error = SecretSpecError;

    /// Load, merge, and validate a `secretspec.toml` file.
    ///
    /// Relative `extends` paths are resolved from the file that declares them.
    fn try_from(path: &Path) -> Result<Self> {
        // Keep the caller's lexical path (including symlink location) while
        // making it independent from subsequent working-directory changes.
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        let config = Config::try_from(path.as_path())?;
        let source = std::fs::read_to_string(&path)?;
        let root_config = Config::from_str(&source)?;
        let mut spec = Self::from_config_document(config)?;
        spec.base_dir = Some(
            path.parent()
                .expect("an absolute spec path always has a parent")
                .to_path_buf(),
        );
        spec.root_config = Some(root_config);
        spec.source = Some(source);
        Ok(spec)
    }
}

/// Rust-first construction of a [`Spec`].
///
/// Available starting with SecretSpec 0.20.
#[derive(Debug)]
pub struct SpecBuilder {
    config: Config,
    base_dir: Option<PathBuf>,
    root_config: Option<Config>,
    source: Option<String>,
    synthesized_profiles: HashSet<String>,
    errors: Vec<String>,
}

impl SpecBuilder {
    fn new(project: impl Into<String>) -> Self {
        Self {
            config: Config {
                project: Project {
                    name: project.into(),
                    ..Project::default()
                },
                profiles: HashMap::new(),
                providers: None,
                scopes: None,
            },
            base_dir: None,
            root_config: None,
            source: None,
            synthesized_profiles: HashSet::new(),
            errors: Vec::new(),
        }
    }

    /// Set the policy for requiring an access reason.
    ///
    /// This semantic edit clears any retained source document.
    pub fn require_reason(mut self, policy: RequireReason) -> Self {
        self.source = None;
        self.declarations_mut().project.require_reason = Some(policy);
        self.refresh_effective_config();
        self
    }

    /// Add a secret to the `default` profile.
    ///
    /// When this builder came from parsed TOML, the declaration is added without
    /// reformatting the rest of the document.
    pub fn secret(mut self, name: impl Into<String>, secret: Secret) -> Self {
        let name = name.into();
        if self.try_edit_source(|source| {
            crate::spec_edit::add_secret(source, "default", &name, &secret.config)
        }) {
            return self;
        }

        let mut errors = Vec::new();
        let profile = self
            .declarations_mut()
            .profiles
            .entry("default".to_string())
            .or_default();
        insert_secret(profile, name, secret, &mut errors, "default");
        self.errors.extend(errors);
        self.refresh_effective_config();
        self
    }

    /// Add a declaration to an existing profile.
    ///
    /// This is the edit-oriented counterpart to [`Self::secret`], which creates
    /// the `default` profile when needed. A missing profile or an existing
    /// declaration is reported by [`Self::build`] rather than silently creating
    /// or replacing it. When editing parsed TOML, an inherited declaration can
    /// be overridden locally without inlining its parent document.
    pub fn add_secret(
        mut self,
        profile: impl Into<String>,
        name: impl Into<String>,
        secret: Secret,
    ) -> Self {
        let profile = profile.into();
        let name = name.into();
        if !self.config.profiles.contains_key(&profile) {
            self.errors.push(format!(
                "cannot add secret '{name}': profile '{profile}' does not exist"
            ));
            return self;
        }
        let synthesized_profile = !self.declarations().profiles.contains_key(&profile);
        let error_count = self.errors.len();
        if self.try_edit_source(|source| {
            crate::spec_edit::add_secret(source, &profile, &name, &secret.config)
        }) {
            if synthesized_profile && self.errors.len() == error_count {
                self.synthesized_profiles.insert(profile);
            }
            return self;
        }

        let declarations = self
            .declarations_mut()
            .profiles
            .entry(profile.clone())
            .or_default();
        if declarations.secrets.contains_key(&name) {
            self.errors.push(format!(
                "cannot add secret '{name}': profile '{profile}' already contains that declaration"
            ));
            return self;
        }
        declarations.secrets.insert(name, secret.config);
        if synthesized_profile {
            self.synthesized_profiles.insert(profile);
        }
        self.refresh_effective_config();
        self
    }

    /// Replace an existing declaration in one profile.
    ///
    /// The replacement is not applied when either the profile or declaration is
    /// absent; [`Self::build`] reports the collected edit error. In parsed TOML,
    /// the declaration keeps its position and unrelated formatting is preserved.
    pub fn replace_secret(
        mut self,
        profile: impl Into<String>,
        name: impl Into<String>,
        secret: Secret,
    ) -> Self {
        let profile = profile.into();
        let name = name.into();
        if self.try_edit_source(|source| {
            crate::spec_edit::replace_secret(source, &profile, &name, &secret.config)
        }) {
            return self;
        }

        let Some(declarations) = self.declarations_mut().profiles.get_mut(&profile) else {
            self.errors.push(format!(
                "cannot replace secret '{name}': profile '{profile}' does not exist"
            ));
            return self;
        };
        let Some(existing) = declarations.secrets.get_mut(&name) else {
            self.errors.push(format!(
                "cannot replace secret '{name}': profile '{profile}' does not contain that declaration"
            ));
            return self;
        };
        *existing = secret.config;
        self.refresh_effective_config();
        self
    }

    /// Remove a declaration from one profile.
    ///
    /// This removes the profile-local declaration, not necessarily the secret
    /// from the profile's effective view. Removing an override can reveal a
    /// declaration inherited from `default`; removing a `default` declaration
    /// also removes it from profiles that only inherited it. References from
    /// scopes, compositions, or constraints are checked again by [`Self::build`].
    /// In parsed TOML, unrelated comments and formatting are preserved.
    pub fn remove_secret(mut self, profile: impl Into<String>, name: impl Into<String>) -> Self {
        let profile = profile.into();
        let name = name.into();
        let remove_empty_profile = self.synthesized_profiles.contains(&profile);
        let error_count = self.errors.len();
        if self.try_edit_source(|source| {
            crate::spec_edit::remove_secret(source, &profile, &name, remove_empty_profile)
        }) {
            if remove_empty_profile
                && self.errors.len() == error_count
                && !self.declarations().profiles.contains_key(&profile)
            {
                self.synthesized_profiles.remove(&profile);
            }
            return self;
        }

        let Some(declarations) = self.declarations_mut().profiles.get_mut(&profile) else {
            self.errors.push(format!(
                "cannot remove secret '{name}': profile '{profile}' does not exist"
            ));
            return self;
        };
        if declarations.secrets.remove(&name).is_none() {
            self.errors.push(format!(
                "cannot remove secret '{name}': profile '{profile}' does not contain that declaration"
            ));
        } else if remove_empty_profile && declarations.secrets.is_empty() {
            self.declarations_mut().profiles.remove(&profile);
            self.synthesized_profiles.remove(&profile);
        }
        self.refresh_effective_config();
        self
    }

    /// Add a named profile.
    ///
    /// This semantic edit clears any retained source document.
    pub fn profile(mut self, name: impl Into<String>, profile: Profile) -> Self {
        self.source = None;
        let name = name.into();
        self.errors.extend(
            profile
                .errors
                .into_iter()
                .map(|error| format!("profile '{name}': {error}")),
        );
        if self
            .declarations_mut()
            .profiles
            .insert(name.clone(), profile.config)
            .is_some()
        {
            self.errors.push(format!("duplicate profile '{name}'"));
        }
        self.refresh_effective_config();
        self
    }

    /// Define a project-local provider alias.
    ///
    /// This semantic edit clears any retained source document.
    pub fn provider(mut self, name: impl Into<String>, provider: impl Into<ProviderAlias>) -> Self {
        self.source = None;
        let name = name.into();
        let providers = self
            .declarations_mut()
            .providers
            .get_or_insert_with(HashMap::new);
        if providers.insert(name.clone(), provider.into()).is_some() {
            self.errors
                .push(format!("duplicate provider alias '{name}'"));
        }
        self.refresh_effective_config();
        self
    }

    /// Define a named, membership-only subset of secrets.
    ///
    /// This semantic edit clears any retained source document.
    pub fn scope<I, S>(mut self, name: impl Into<String>, secrets: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.source = None;
        let name = name.into();
        let scopes = self
            .declarations_mut()
            .scopes
            .get_or_insert_with(HashMap::new);
        let scope = Scope {
            secrets: secrets.into_iter().map(Into::into).collect(),
        };
        if scopes.insert(name.clone(), scope).is_some() {
            self.errors.push(format!("duplicate scope '{name}'"));
        }
        self.refresh_effective_config();
        self
    }

    /// Validate and compile this declaration.
    pub fn build(self) -> Result<Spec> {
        if !self.errors.is_empty() {
            return Err(SecretSpecError::InvalidSpec(self.errors.join("; ")));
        }
        let mut spec = Spec::from_config_document(self.config)?;
        spec.base_dir = self.base_dir;
        spec.root_config = self.root_config;
        spec.source = self.source;
        spec.synthesized_profiles = self.synthesized_profiles;
        Ok(spec)
    }

    /// Apply an edit to retained TOML and refresh the merged semantic model.
    /// `true` means a source-backed edit was attempted, including an error
    /// deferred to [`Self::build`].
    fn try_edit_source<F>(&mut self, edit: F) -> bool
    where
        F: FnOnce(&str) -> miette::Result<String>,
    {
        let Some(source) = self.source.as_deref() else {
            return false;
        };
        let edited = match edit(source) {
            Ok(edited) => edited,
            Err(error) => {
                self.errors.push(error.to_string());
                return true;
            }
        };
        let root_config = match Config::from_str(&edited) {
            Ok(config) => config,
            Err(error) => {
                self.errors.push(error.to_string());
                return true;
            }
        };
        let config = match self.base_dir.as_deref() {
            Some(base_dir) => Config::from_root_in(root_config.clone(), base_dir),
            None => Ok(root_config.clone()),
        };
        match config {
            Ok(config) => {
                self.config = config;
                self.root_config = Some(root_config);
                self.source = Some(edited);
            }
            Err(error) => self.errors.push(error.to_string()),
        }
        true
    }

    fn declarations(&self) -> &Config {
        self.root_config.as_ref().unwrap_or(&self.config)
    }

    fn declarations_mut(&mut self) -> &mut Config {
        self.root_config.as_mut().unwrap_or(&mut self.config)
    }

    fn refresh_effective_config(&mut self) {
        let Some(root_config) = self.root_config.clone() else {
            return;
        };
        let config = match self.base_dir.as_deref() {
            Some(base_dir) => Config::from_root_in(root_config, base_dir),
            None => Ok(root_config),
        };
        match config {
            Ok(config) => self.config = config,
            Err(error) => self.errors.push(error.to_string()),
        }
    }
}

impl From<Spec> for SpecBuilder {
    fn from(spec: Spec) -> Self {
        Self {
            config: spec.config,
            base_dir: spec.base_dir,
            root_config: spec.root_config,
            source: spec.source,
            synthesized_profiles: spec.synthesized_profiles,
            errors: Vec::new(),
        }
    }
}

impl From<&Spec> for SpecBuilder {
    fn from(spec: &Spec) -> Self {
        Self {
            config: spec.config.clone(),
            base_dir: spec.base_dir.clone(),
            root_config: spec.root_config.clone(),
            source: spec.source.clone(),
            synthesized_profiles: spec.synthesized_profiles.clone(),
            errors: Vec::new(),
        }
    }
}

/// One profile in a Rust-built [`Spec`].
///
/// Available starting with SecretSpec 0.20.
#[derive(Debug, Default)]
pub struct Profile {
    config: ConfigProfile,
    errors: Vec<String>,
}

impl Profile {
    /// Create an empty profile.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a secret to this profile.
    pub fn secret(mut self, name: impl Into<String>, secret: Secret) -> Self {
        insert_secret(
            &mut self.config,
            name.into(),
            secret,
            &mut self.errors,
            "this profile",
        );
        self
    }

    /// Choose whether this profile inherits declarations from `default`.
    pub fn inherit_default(mut self, inherit: bool) -> Self {
        self.defaults().inherit = Some(inherit);
        self
    }

    /// Set the requiredness inherited by secrets that omit it.
    pub fn required_by_default(mut self, required: bool) -> Self {
        self.defaults().required = Some(required);
        self
    }

    /// Set the value inherited by secrets that do not declare their own default.
    pub fn default_value(mut self, value: impl Into<String>) -> Self {
        self.defaults().default = Some(value.into());
        self
    }

    /// Set the provider chain inherited by secrets that omit one.
    pub fn providers<I, S>(mut self, providers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.defaults().providers = Some(providers.into_iter().map(Into::into).collect());
        self
    }

    fn defaults(&mut self) -> &mut ProfileDefaults {
        self.config.defaults.get_or_insert(ProfileDefaults {
            inherit: None,
            required: None,
            default: None,
            providers: None,
        })
    }
}

fn insert_secret(
    profile: &mut ConfigProfile,
    name: String,
    secret: Secret,
    errors: &mut Vec<String>,
    profile_name: &str,
) {
    if profile
        .secrets
        .insert(name.clone(), secret.config)
        .is_some()
    {
        errors.push(format!("duplicate secret '{name}' in {profile_name}"));
    }
}

/// One secret declaration in a Rust-built [`Spec`].
///
/// Descriptions are required at construction time. [`Secret::new`] inherits
/// its requiredness from the profile, while [`Secret::required`],
/// [`Secret::optional`], and [`Secret::defaulted`] declare it explicitly.
///
/// Available starting with SecretSpec 0.20.
#[derive(Debug, Clone)]
pub struct Secret {
    config: ConfigSecret,
}

impl Secret {
    /// Declare a secret whose requiredness comes from its profile defaults.
    ///
    /// Without a profile-level requiredness default, the secret is required.
    pub fn new(description: impl Into<String>) -> Self {
        Self {
            config: ConfigSecret {
                description: Some(description.into()),
                ..ConfigSecret::default()
            },
        }
    }

    /// Declare a required secret.
    pub fn required(description: impl Into<String>) -> Self {
        let mut secret = Self::new(description);
        secret.config.required = Some(true);
        secret
    }

    /// The human-readable purpose of this declaration.
    pub fn description(&self) -> &str {
        self.config
            .description
            .as_deref()
            .expect("Rust-built secrets always carry a description")
    }

    /// The explicitly declared requiredness, if this secret uses an individual
    /// required policy rather than a presence group.
    pub fn required_setting(&self) -> Option<bool> {
        self.config.required
    }

    /// Declare a secret that may be absent.
    pub fn optional(description: impl Into<String>) -> Self {
        let mut secret = Self::new(description);
        secret.config.required = Some(false);
        secret
    }

    /// Declare a secret with a committed fallback value.
    pub fn defaulted(description: impl Into<String>, value: impl Into<String>) -> Self {
        let mut secret = Self::optional(description);
        secret.config.default = Some(value.into());
        secret
    }

    /// Add this secret to one or more `at_least_one` presence groups.
    pub fn at_least_one<I, S>(mut self, groups: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.config.required = None;
        self.config.at_least_one = Some(groups.into_iter().map(Into::into).collect());
        self
    }

    /// Add this secret to one or more `exactly_one` presence groups.
    pub fn exactly_one<I, S>(mut self, groups: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.config.required = None;
        self.config.exactly_one = Some(groups.into_iter().map(Into::into).collect());
        self
    }

    /// Derive this value from a `${NAME}` template over other secrets.
    pub fn composed(mut self, template: impl Into<String>) -> Self {
        self.config.composed = Some(template.into());
        self
    }

    /// Select an ordered provider fallback chain.
    pub fn providers<I, S>(mut self, providers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.config.providers = Some(providers.into_iter().map(Into::into).collect());
        self
    }

    /// Address an externally managed value using provider-native coordinates.
    pub fn reference(mut self, address: NativeAddress) -> Self {
        self.config.reference = Some(address);
        self
    }

    /// Override provider-native coordinates for one provider alias.
    pub fn reference_for(mut self, provider: impl Into<String>, address: NativeAddress) -> Self {
        self.config
            .refs
            .get_or_insert_with(HashMap::new)
            .insert(provider.into(), address);
        self
    }

    /// Choose whether to materialize the resolved value in a temporary file.
    pub fn as_path(mut self, as_path: bool) -> Self {
        self.config.as_path = Some(as_path);
        self
    }

    /// Set the provider-side storage encoding.
    pub fn encoding(mut self, encoding: SecretEncoding) -> Self {
        self.config.encoding = Some(encoding);
        self
    }

    /// Extract a value from a structured provider result, or from the text of
    /// the secret named by [`from`](Self::from).
    pub fn extract(mut self, extract: SecretExtract) -> Self {
        self.config.extract = Some(extract);
        self
    }

    /// Set the semantic type. For the typed contracts (`x509_identity` and the
    /// `pkcs12`, `pkcs8_private_key`, `x509_certificate`,
    /// `x509_certificate_chain`, and `x509_issuer_chain` targets, 0.21+) the
    /// type governs decoding, conversion, credentials, and delivery.
    pub fn secret_type(mut self, secret_type: impl Into<String>) -> Self {
        self.config.secret_type = Some(secret_type.into());
        self
    }

    /// Choose the serialization of a typed value that offers more than one,
    /// such as DER instead of the default PEM (0.21+).
    pub fn format(mut self, format: crate::typed::Format) -> Self {
        self.config.format = Some(format.as_str().to_string());
        self
    }

    /// Derive this value from another declared secret: convert it with a
    /// derivable type or select from it with `extract` (0.21+).
    pub fn from(mut self, source: impl Into<String>) -> Self {
        self.config.from = Some(source.into());
        self
    }

    /// Bind a credential role of this typed value, such as the `password`
    /// that opens or protects a PKCS#12 archive, to a declared secret (0.21+).
    pub fn credential(mut self, role: impl Into<String>, secret: impl Into<String>) -> Self {
        self.config
            .credentials
            .get_or_insert_with(BTreeMap::new)
            .insert(role.into(), CredentialBinding::Secret(secret.into()));
        self
    }

    /// Generate the value when it is absent.
    pub fn generate(mut self, generation: Generation) -> Self {
        let (secret_type, config) = generation.into_config();
        self.config.secret_type = Some(secret_type.to_string());
        self.config.generate = Some(config);
        self
    }

    /// Disable generation inherited from the `default` profile.
    pub fn disable_generation(mut self) -> Self {
        self.config.generate = Some(GenerateConfig::Bool(false));
        self
    }

    /// Choose whether to prompt securely when `secretspec run` cannot resolve
    /// the value.
    pub fn prompt(mut self, prompt: bool) -> Self {
        self.config.prompt = Some(prompt);
        self
    }

    #[cfg(feature = "cli")]
    pub(crate) fn into_config(self) -> ConfigSecret {
        self.config
    }
}

/// A typed secret-generation strategy.
///
/// Available starting with SecretSpec 0.20.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Generation {
    /// A randomly generated password.
    Password {
        /// Character count; `None` uses SecretSpec's default.
        length: Option<usize>,
        /// Characters from which the password is drawn.
        charset: PasswordCharset,
    },
    /// A human-readable passphrase composed from independently selected words (0.21+).
    Passphrase {
        /// Word count; `None` uses SecretSpec's seven-word default.
        words: Option<usize>,
        /// Text placed between words.
        separator: String,
    },
    /// A checksum-protected recovery mnemonic (0.21+).
    Mnemonic {
        /// Mnemonic encoding algorithm.
        algorithm: MnemonicAlgorithm,
        /// Word count; `None` uses SecretSpec's 24-word default.
        words: Option<usize>,
        /// Word-list language.
        language: MnemonicLanguage,
    },
    /// Random bytes rendered as hexadecimal.
    Hex {
        /// Byte count; `None` uses SecretSpec's default.
        bytes: Option<usize>,
    },
    /// Random bytes rendered as Base64.
    Base64 {
        /// Byte count; `None` uses SecretSpec's default.
        bytes: Option<usize>,
    },
    /// A random version-4 UUID.
    Uuid,
    /// The trimmed stdout of a shell command.
    Command(String),
    /// A PEM-encoded RSA private key.
    RsaPrivateKey {
        /// Key size in bits; `None` uses SecretSpec's default.
        bits: Option<usize>,
    },
    /// An ASCII-armored OpenPGP transferable secret key (0.21+).
    OpenPgpPrivateKey {
        /// User ID certified by the generated key.
        user_id: String,
        /// Cryptographic profile used for the primary key and subkeys.
        algorithm: OpenPgpAlgorithm,
        /// Capabilities placed on separate subkeys.
        capabilities: Vec<OpenPgpCapability>,
    },
    /// An unencrypted OpenSSH private key (0.21+).
    SshPrivateKey {
        /// Cryptographic algorithm and optional RSA key size.
        algorithm: SshKeyAlgorithm,
        /// Optional comment embedded in the OpenSSH key.
        comment: Option<String>,
    },
    /// A Base64-encoded WireGuard private key (0.21+).
    WireguardPrivateKey,
    /// A private signing key serialized as a JSON Web Key (0.21+).
    JwkPrivateKey {
        /// JOSE signing algorithm and optional RSA key size.
        algorithm: JwkKeyAlgorithm,
        /// Optional JWK `kid` metadata.
        kid: Option<String>,
    },
    /// A native X25519 age identity (0.21+).
    AgeIdentity,
    /// A self-signed P-256 X.509 identity stored as PKCS#12 (0.21+).
    X509Identity {
        /// DNS and IP subject alternative names (`dns:name` or `ip:address`).
        subject_alt_names: Vec<String>,
        /// Extended key usages placed on the certificate.
        usages: Vec<X509Usage>,
        /// Validity in days; `None` uses SecretSpec's 30-day default.
        valid_for_days: Option<u32>,
    },
}

impl Generation {
    /// A password with SecretSpec's default length and alphanumeric charset.
    pub fn password() -> Self {
        Self::Password {
            length: None,
            charset: PasswordCharset::Alphanumeric,
        }
    }

    /// A seven-word passphrase separated with hyphens (0.21+).
    pub fn passphrase() -> Self {
        Self::Passphrase {
            words: None,
            separator: "-".to_string(),
        }
    }

    /// A 24-word English BIP-39 mnemonic (0.21+).
    pub fn mnemonic() -> Self {
        Self::Mnemonic {
            algorithm: MnemonicAlgorithm::Bip39,
            words: None,
            language: MnemonicLanguage::English,
        }
    }

    /// Hexadecimal output with SecretSpec's default random-byte count.
    pub fn hex() -> Self {
        Self::Hex { bytes: None }
    }

    /// Base64 output with SecretSpec's default random-byte count.
    pub fn base64() -> Self {
        Self::Base64 { bytes: None }
    }

    /// A random version-4 UUID.
    pub fn uuid() -> Self {
        Self::Uuid
    }

    /// Generate from the trimmed stdout of `command`.
    pub fn command(command: impl Into<String>) -> Self {
        Self::Command(command.into())
    }

    /// An RSA private key with SecretSpec's default key size.
    pub fn rsa_private_key() -> Self {
        Self::RsaPrivateKey { bits: None }
    }

    /// An OpenPGP private key with signing and encryption subkeys (0.21+).
    pub fn openpgp_private_key(user_id: impl Into<String>) -> Self {
        Self::OpenPgpPrivateKey {
            user_id: user_id.into(),
            algorithm: OpenPgpAlgorithm::Ed25519,
            capabilities: vec![OpenPgpCapability::Sign, OpenPgpCapability::Encrypt],
        }
    }

    /// An Ed25519 OpenSSH private key without an embedded comment (0.21+).
    pub fn ssh_private_key() -> Self {
        Self::SshPrivateKey {
            algorithm: SshKeyAlgorithm::Ed25519,
            comment: None,
        }
    }

    /// A Base64-encoded WireGuard private key (0.21+).
    pub fn wireguard_private_key() -> Self {
        Self::WireguardPrivateKey
    }

    /// An Ed25519 private signing JWK (0.21+).
    pub fn jwk_private_key() -> Self {
        Self::JwkPrivateKey {
            algorithm: JwkKeyAlgorithm::Ed25519,
            kid: None,
        }
    }

    /// A native X25519 age identity (0.21+).
    pub fn age_identity() -> Self {
        Self::AgeIdentity
    }

    /// A self-signed P-256 X.509 server identity with a 30-day validity (0.21+).
    pub fn x509_identity(subject_alt_names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::X509Identity {
            subject_alt_names: subject_alt_names.into_iter().map(Into::into).collect(),
            usages: vec![X509Usage::ServerAuth],
            valid_for_days: None,
        }
    }

    fn into_config(self) -> (&'static str, GenerateConfig) {
        match self {
            Self::Password { length, charset } => (
                "password",
                GenerateConfig::Options(GenerateOptions {
                    length,
                    charset: Some(charset.as_str().to_string()),
                    ..GenerateOptions::default()
                }),
            ),
            Self::Passphrase { words, separator } => (
                "passphrase",
                GenerateConfig::Options(GenerateOptions {
                    words,
                    separator: Some(separator),
                    ..GenerateOptions::default()
                }),
            ),
            Self::Mnemonic {
                algorithm,
                words,
                language,
            } => (
                "mnemonic",
                GenerateConfig::Options(GenerateOptions {
                    algorithm: Some(algorithm.as_str().to_string()),
                    words,
                    language: Some(language.as_str().to_string()),
                    ..GenerateOptions::default()
                }),
            ),
            Self::Hex { bytes } => (
                "hex",
                GenerateConfig::Options(GenerateOptions {
                    bytes,
                    ..GenerateOptions::default()
                }),
            ),
            Self::Base64 { bytes } => (
                "base64",
                GenerateConfig::Options(GenerateOptions {
                    bytes,
                    ..GenerateOptions::default()
                }),
            ),
            Self::Uuid => ("uuid", GenerateConfig::Bool(true)),
            Self::Command(command) => (
                "command",
                GenerateConfig::Options(GenerateOptions {
                    command: Some(command),
                    ..GenerateOptions::default()
                }),
            ),
            Self::RsaPrivateKey { bits } => (
                "rsa_private_key",
                GenerateConfig::Options(GenerateOptions {
                    bits,
                    ..GenerateOptions::default()
                }),
            ),
            Self::OpenPgpPrivateKey {
                user_id,
                algorithm,
                capabilities,
            } => (
                "openpgp_private_key",
                GenerateConfig::Options(GenerateOptions {
                    user_id: Some(user_id),
                    algorithm: Some(algorithm.as_str().to_string()),
                    bits: algorithm.bits(),
                    capabilities: Some(
                        capabilities
                            .into_iter()
                            .map(|capability| capability.as_str().to_string())
                            .collect(),
                    ),
                    ..GenerateOptions::default()
                }),
            ),
            Self::SshPrivateKey { algorithm, comment } => (
                "ssh_private_key",
                GenerateConfig::Options(GenerateOptions {
                    algorithm: Some(algorithm.as_str().to_string()),
                    bits: algorithm.bits(),
                    comment,
                    ..GenerateOptions::default()
                }),
            ),
            Self::WireguardPrivateKey => ("wireguard_private_key", GenerateConfig::Bool(true)),
            Self::JwkPrivateKey { algorithm, kid } => (
                "jwk_private_key",
                GenerateConfig::Options(GenerateOptions {
                    algorithm: Some(algorithm.as_str().to_string()),
                    bits: algorithm.bits(),
                    kid,
                    ..GenerateOptions::default()
                }),
            ),
            Self::AgeIdentity => ("age_identity", GenerateConfig::Bool(true)),
            Self::X509Identity {
                subject_alt_names,
                usages,
                valid_for_days,
            } => (
                "x509_identity",
                GenerateConfig::Options(GenerateOptions {
                    issuer: Some("self_signed".to_string()),
                    algorithm: Some("p256".to_string()),
                    san: Some(subject_alt_names),
                    usages: Some(
                        usages
                            .into_iter()
                            .map(|usage| usage.as_str().to_string())
                            .collect(),
                    ),
                    valid_for: valid_for_days.map(|days| format!("{days}d")),
                    ..GenerateOptions::default()
                }),
            ),
        }
    }
}

/// Extended key usage for a generated X.509 identity.
///
/// Available starting with SecretSpec 0.21.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum X509Usage {
    /// TLS server authentication.
    ServerAuth,
    /// TLS client authentication.
    ClientAuth,
}

impl X509Usage {
    fn as_str(self) -> &'static str {
        match self {
            Self::ServerAuth => "server_auth",
            Self::ClientAuth => "client_auth",
        }
    }
}

/// The encoding algorithm for a generated recovery mnemonic.
///
/// Available starting with SecretSpec 0.21.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MnemonicAlgorithm {
    /// BIP-39 entropy and checksum encoding.
    Bip39,
}

impl MnemonicAlgorithm {
    fn as_str(self) -> &'static str {
        match self {
            Self::Bip39 => "bip39",
        }
    }
}

/// The word-list language for a generated recovery mnemonic.
///
/// Available starting with SecretSpec 0.21.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MnemonicLanguage {
    /// The BIP-39 English word list.
    English,
}

impl MnemonicLanguage {
    fn as_str(self) -> &'static str {
        match self {
            Self::English => "english",
        }
    }
}

/// The algorithm for a generated private JSON Web Key.
///
/// Available starting with SecretSpec 0.21.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JwkKeyAlgorithm {
    /// Ed25519 with the fully specified JOSE algorithm `Ed25519` (RFC 9864).
    Ed25519,
    /// NIST P-256 with JOSE algorithm `ES256`.
    P256,
    /// RSA with JOSE algorithm `RS256`. `None` uses the 3072-bit default.
    Rsa { bits: Option<usize> },
}

impl JwkKeyAlgorithm {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::P256 => "p256",
            Self::Rsa { .. } => "rsa",
        }
    }

    fn bits(self) -> Option<usize> {
        match self {
            Self::Rsa { bits } => bits,
            Self::Ed25519 | Self::P256 => None,
        }
    }
}

/// The algorithm for a generated OpenSSH private key.
///
/// Available starting with SecretSpec 0.21.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SshKeyAlgorithm {
    /// Ed25519, the default for new SSH keys.
    Ed25519,
    /// RSA for compatibility. `None` uses the 3072-bit default.
    Rsa { bits: Option<usize> },
}

impl SshKeyAlgorithm {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::Rsa { .. } => "rsa",
        }
    }

    fn bits(self) -> Option<usize> {
        match self {
            Self::Ed25519 => None,
            Self::Rsa { bits } => bits,
        }
    }
}

/// The cryptographic profile for a generated OpenPGP key.
///
/// Available starting with SecretSpec 0.21.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OpenPgpAlgorithm {
    /// Ed25519 certification/signing keys and Curve25519 encryption subkeys.
    Ed25519,
    /// RSA primary key and subkeys. `None` uses the 3072-bit default.
    Rsa { bits: Option<usize> },
}

impl OpenPgpAlgorithm {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::Rsa { .. } => "rsa",
        }
    }

    fn bits(self) -> Option<usize> {
        match self {
            Self::Ed25519 => None,
            Self::Rsa { bits } => bits,
        }
    }
}

/// A capability assigned to a generated OpenPGP subkey.
///
/// Available starting with SecretSpec 0.21.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OpenPgpCapability {
    /// Generate a signing subkey using the selected algorithm.
    Sign,
    /// Generate an encryption subkey using the selected algorithm.
    Encrypt,
}

impl OpenPgpCapability {
    fn as_str(self) -> &'static str {
        match self {
            Self::Sign => "sign",
            Self::Encrypt => "encrypt",
        }
    }
}

/// Character set used by [`Generation::Password`].
///
/// Available starting with SecretSpec 0.20.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PasswordCharset {
    /// ASCII letters and decimal digits.
    Alphanumeric,
    /// Printable ASCII characters.
    Ascii,
}

impl PasswordCharset {
    fn as_str(self) -> &'static str {
        match self {
            Self::Alphanumeric => "alphanumeric",
            Self::Ascii => "ascii",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_builder_and_toml_compile_to_the_same_shape() {
        let rust = Spec::builder("embedded")
            .secret("TOKEN", Secret::required("API token").providers(["env"]))
            .secret("OPTIONAL", Secret::optional("Optional value"))
            .profile(
                "production",
                Profile::new().secret("TOKEN", Secret::required("Production API token")),
            )
            .scope("api", ["TOKEN"])
            .build()
            .unwrap();

        let toml = Spec::from_toml(
            r#"
                [project]
                name = "embedded"
                revision = "1.0"

                [profiles.default]
                TOKEN = { description = "API token", required = true, providers = ["env"] }
                OPTIONAL = { description = "Optional value", required = false }

                [profiles.production]
                TOKEN = { description = "Production API token", required = true }

                [scopes.api]
                secrets = ["TOKEN"]
            "#,
        )
        .unwrap();

        assert_eq!(rust.project(), toml.project());
        assert_eq!(
            rust.profiles().collect::<Vec<_>>(),
            toml.profiles().collect::<Vec<_>>()
        );
        for profile in rust.profiles() {
            assert_eq!(
                rust.secrets(profile).unwrap().collect::<Vec<_>>(),
                toml.secrets(profile).unwrap().collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn builder_rejects_duplicates_without_silent_overwrite() {
        let error = Spec::builder("embedded")
            .secret("TOKEN", Secret::required("first"))
            .secret("TOKEN", Secret::required("second"))
            .build()
            .unwrap_err();

        assert!(error.to_string().contains("duplicate secret 'TOKEN'"));
    }

    #[test]
    fn openpgp_generation_builder_uses_the_interoperable_default_profile() {
        let (secret_type, config) =
            Generation::openpgp_private_key("Release Bot <releases@example.com>").into_config();
        assert_eq!(secret_type, "openpgp_private_key");
        let GenerateConfig::Options(options) = config else {
            panic!("OpenPGP generation must use options");
        };
        assert_eq!(
            options.user_id.as_deref(),
            Some("Release Bot <releases@example.com>")
        );
        assert_eq!(options.algorithm.as_deref(), Some("ed25519"));
        assert_eq!(options.bits, None);
        assert_eq!(
            options.capabilities,
            Some(vec!["sign".to_string(), "encrypt".to_string()])
        );
    }

    #[test]
    fn openpgp_generation_builder_maps_an_explicit_rsa_profile() {
        let generation = Generation::OpenPgpPrivateKey {
            user_id: "Legacy Bot <legacy@example.com>".to_string(),
            algorithm: OpenPgpAlgorithm::Rsa { bits: Some(4096) },
            capabilities: vec![OpenPgpCapability::Encrypt],
        };
        let (_, GenerateConfig::Options(options)) = generation.into_config() else {
            panic!("OpenPGP generation must use options");
        };
        assert_eq!(options.algorithm.as_deref(), Some("rsa"));
        assert_eq!(options.bits, Some(4096));
        assert_eq!(options.capabilities, Some(vec!["encrypt".to_string()]));
    }

    #[test]
    fn ssh_generation_builder_maps_default_and_rsa_profiles() {
        let (secret_type, GenerateConfig::Options(default)) =
            Generation::ssh_private_key().into_config()
        else {
            panic!("SSH generation must use options");
        };
        assert_eq!(secret_type, "ssh_private_key");
        assert_eq!(default.algorithm.as_deref(), Some("ed25519"));
        assert_eq!(default.bits, None);
        assert_eq!(default.comment, None);

        let generation = Generation::SshPrivateKey {
            algorithm: SshKeyAlgorithm::Rsa { bits: Some(4096) },
            comment: Some("deploy@example.com".to_string()),
        };
        let (_, GenerateConfig::Options(rsa)) = generation.into_config() else {
            panic!("SSH generation must use options");
        };
        assert_eq!(rsa.algorithm.as_deref(), Some("rsa"));
        assert_eq!(rsa.bits, Some(4096));
        assert_eq!(rsa.comment.as_deref(), Some("deploy@example.com"));
    }

    #[test]
    fn additional_credential_generation_builders_map_to_document_options() {
        let (secret_type, GenerateConfig::Options(passphrase)) = Generation::Passphrase {
            words: Some(8),
            separator: " ".to_string(),
        }
        .into_config() else {
            panic!("passphrase generation must use options");
        };
        assert_eq!(secret_type, "passphrase");
        assert_eq!(passphrase.words, Some(8));
        assert_eq!(passphrase.separator.as_deref(), Some(" "));

        let (secret_type, GenerateConfig::Options(mnemonic)) = Generation::Mnemonic {
            algorithm: MnemonicAlgorithm::Bip39,
            words: Some(12),
            language: MnemonicLanguage::English,
        }
        .into_config() else {
            panic!("mnemonic generation must use options");
        };
        assert_eq!(secret_type, "mnemonic");
        assert_eq!(mnemonic.algorithm.as_deref(), Some("bip39"));
        assert_eq!(mnemonic.words, Some(12));
        assert_eq!(mnemonic.language.as_deref(), Some("english"));

        let (secret_type, GenerateConfig::Options(default_mnemonic)) =
            Generation::mnemonic().into_config()
        else {
            panic!("mnemonic generation must use options");
        };
        assert_eq!(secret_type, "mnemonic");
        assert_eq!(default_mnemonic.words, None);

        let (secret_type, GenerateConfig::Options(jwk)) = Generation::JwkPrivateKey {
            algorithm: JwkKeyAlgorithm::Rsa { bits: Some(4096) },
            kid: Some("release-2026".to_string()),
        }
        .into_config() else {
            panic!("JWK generation must use options");
        };
        assert_eq!(secret_type, "jwk_private_key");
        assert_eq!(jwk.algorithm.as_deref(), Some("rsa"));
        assert_eq!(jwk.bits, Some(4096));
        assert_eq!(jwk.kid.as_deref(), Some("release-2026"));

        assert!(matches!(
            Generation::wireguard_private_key().into_config(),
            ("wireguard_private_key", GenerateConfig::Bool(true))
        ));
        assert!(matches!(
            Generation::age_identity().into_config(),
            ("age_identity", GenerateConfig::Bool(true))
        ));

        let (secret_type, GenerateConfig::Options(x509)) =
            Generation::x509_identity(["dns:localhost", "ip:127.0.0.1"]).into_config()
        else {
            panic!("X.509 generation must use options");
        };
        assert_eq!(secret_type, "x509_identity");
        assert_eq!(x509.algorithm.as_deref(), Some("p256"));
        assert_eq!(
            x509.san,
            Some(vec![
                "dns:localhost".to_string(),
                "ip:127.0.0.1".to_string()
            ])
        );
        assert_eq!(x509.usages, Some(vec!["server_auth".to_string()]));
    }

    #[test]
    fn builder_edits_a_copy_without_mutating_the_original_spec() {
        let original = Spec::builder("embedded")
            .secret("KEEP", Secret::required("Kept declaration"))
            .secret("REMOVE", Secret::required("Removed declaration"))
            .profile(
                "production",
                Profile::new().secret("OVERRIDE", Secret::required("Original declaration")),
            )
            .build()
            .unwrap();

        let edited = original
            .to_builder()
            .remove_secret("default", "REMOVE")
            .add_secret("production", "ADDED", Secret::required("Added declaration"))
            .replace_secret(
                "production",
                "OVERRIDE",
                Secret::optional("Replacement declaration"),
            )
            .build()
            .unwrap();

        assert!(
            original
                .secrets("default")
                .unwrap()
                .any(|name| name == "REMOVE")
        );
        assert!(
            !edited
                .secrets("default")
                .unwrap()
                .any(|name| name == "REMOVE")
        );
        assert!(
            edited
                .secrets("production")
                .unwrap()
                .any(|name| name == "ADDED")
        );

        let replacement = &edited.compiled.profile("production").unwrap().secrets["OVERRIDE"];
        assert_eq!(
            replacement.config.description.as_deref(),
            Some("Replacement declaration")
        );
        assert!(!replacement.declared_required);
    }

    #[test]
    fn removing_an_override_reveals_the_default_declaration() {
        let spec = Spec::builder("embedded")
            .secret("TOKEN", Secret::required("Default token"))
            .profile(
                "production",
                Profile::new()
                    .secret("TOKEN", Secret::optional("Production override"))
                    .secret("LOCAL", Secret::required("Production-only value")),
            )
            .build()
            .unwrap();

        let edited = spec
            .into_builder()
            .remove_secret("production", "TOKEN")
            .build()
            .unwrap();

        let token = &edited.compiled.profile("production").unwrap().secrets["TOKEN"];
        assert_eq!(token.config.description.as_deref(), Some("Default token"));
        assert!(token.declared_required);
    }

    #[test]
    fn edit_operations_report_missing_or_duplicate_targets() {
        let spec = Spec::builder("embedded")
            .secret("TOKEN", Secret::required("API token"))
            .build()
            .unwrap();

        let error = spec
            .to_builder()
            .add_secret("default", "TOKEN", Secret::required("Duplicate"))
            .replace_secret("default", "MISSING", Secret::required("Missing"))
            .remove_secret("production", "TOKEN")
            .build()
            .unwrap_err()
            .to_string();

        assert!(error.contains("already contains that declaration"));
        assert!(error.contains("does not contain that declaration"));
        assert!(error.contains("profile 'production' does not exist"));
    }

    #[test]
    fn removing_a_declaration_revalidates_its_dependents() {
        let spec = Spec::builder("embedded")
            .secret("KEEP", Secret::required("Kept declaration"))
            .secret("TOKEN", Secret::required("API token"))
            .scope("api", ["TOKEN"])
            .build()
            .unwrap();

        let error = spec
            .into_builder()
            .remove_secret("default", "TOKEN")
            .build()
            .unwrap_err()
            .to_string();

        assert!(error.contains("Scope 'api' references secret 'TOKEN'"));
    }

    #[test]
    fn string_input_rejects_unresolvable_extends() {
        let error = Spec::from_toml(
            r#"
                [project]
                name = "embedded"
                revision = "1.0"
                extends = ["../shared"]

                [profiles.default]
                TOKEN = { description = "API token" }
            "#,
        )
        .unwrap_err();

        assert!(error.to_string().contains("Spec::try_from"));
    }

    #[test]
    fn every_frontend_rejects_an_empty_declaration() {
        let error = Spec::builder("embedded").build().unwrap_err();
        assert!(error.to_string().contains("At least one profile"));

        let error = Spec::from_toml(
            r#"
                [project]
                name = "embedded"
                revision = "1.0"

                [profiles.default]
            "#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("at least one secret"));
    }

    #[test]
    fn loaded_spec_remembers_its_base_directory() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("secretspec.toml");
        std::fs::write(
            &path,
            r#"
                [project]
                name = "loaded"
                revision = "1.0"

                [profiles.default]
                TOKEN = { description = "API token" }
            "#,
        )
        .unwrap();

        let spec = Spec::try_from(path.as_path()).unwrap();

        assert_eq!(spec.base_dir.as_deref(), Some(directory.path()));

        let edited = spec
            .into_builder()
            .replace_secret("default", "TOKEN", Secret::optional("Edited API token"))
            .build()
            .unwrap();
        assert_eq!(edited.base_dir.as_deref(), Some(directory.path()));
    }

    #[test]
    fn whitespace_descriptions_have_the_same_semantics_for_every_builder_origin() {
        let parsed = Spec::from_toml(
            r#"
                [project]
                name = "parsed"
                revision = "1.0"

                [profiles.default]
                TOKEN = { description = "token" }
            "#,
        )
        .unwrap()
        .into_builder()
        .add_secret("default", "SPACE", Secret::required(" "))
        .build();
        let rust_built = Spec::builder("rust")
            .secret("SPACE", Secret::required(" "))
            .build();

        assert!(parsed.is_ok());
        assert!(rust_built.is_ok());
    }

    #[test]
    fn profile_required_default_applies_to_secrets_that_inherit_it() {
        let declaration = Secret::new("Deployment token");
        assert_eq!(declaration.required_setting(), None);

        let spec = Spec::builder("embedded")
            .profile(
                "optional",
                Profile::new()
                    .inherit_default(false)
                    .required_by_default(false)
                    .secret("TOKEN", declaration),
            )
            .build()
            .unwrap();

        let secret = &spec.compiled.profile("optional").unwrap().secrets["TOKEN"];
        assert_eq!(secret.config.required, Some(false));
        assert!(!secret.declared_required);
    }

    #[test]
    fn child_profile_can_disable_inherited_boolean_settings() {
        let spec = Spec::builder("embedded")
            .secret("PATH", Secret::required("Path value").as_path(true))
            .secret("PROMPT", Secret::required("Prompted value").prompt(true))
            .secret(
                "GENERATED",
                Secret::required("Generated value").generate(Generation::uuid()),
            )
            .profile(
                "production",
                Profile::new()
                    .secret("PATH", Secret::required("Plain value").as_path(false))
                    .secret("PROMPT", Secret::required("Stored value").prompt(false))
                    .secret(
                        "GENERATED",
                        Secret::required("Stored value").disable_generation(),
                    ),
            )
            .build()
            .unwrap();

        let secrets = &spec.compiled.profile("production").unwrap().secrets;
        assert_eq!(secrets["PATH"].config.as_path, Some(false));
        assert_eq!(secrets["PROMPT"].config.prompt, Some(false));
        assert!(matches!(
            secrets["GENERATED"].config.generate,
            Some(GenerateConfig::Bool(false))
        ));
    }

    #[test]
    fn typed_generation_lowers_to_the_document_model() {
        let secret = Secret::required("Random password").generate(Generation::Password {
            length: Some(48),
            charset: PasswordCharset::Ascii,
        });

        assert_eq!(secret.config.secret_type.as_deref(), Some("password"));
        let Some(GenerateConfig::Options(options)) = secret.config.generate else {
            panic!("password generation should carry its typed options");
        };
        assert_eq!(options.length, Some(48));
        assert_eq!(options.charset.as_deref(), Some("ascii"));
    }

    mod format_preserving_edits {
        use super::*;

        const SPEC_TEXT: &str = r#"[project]
name = "demo"
revision = "1.0"

# Team convention: transport secrets first.
[profiles.default]
ZULU = { description = "sorts last on purpose" }
ALPHA = { description = "sorts first on purpose" } # Keep this explanation.

[profiles.default.NESTED]
description = "declared as a full table"
required = false
"#;

        #[test]
        fn parsed_specs_retain_their_exact_root_text() {
            let spec = Spec::from_toml(SPEC_TEXT).unwrap();

            assert_eq!(spec.preserved_text(), Some(SPEC_TEXT));
        }

        #[test]
        fn chained_add_and_remove_restore_the_original_bytes() {
            let restored = Spec::from_toml(SPEC_TEXT)
                .unwrap()
                .to_builder()
                .add_secret("default", "SCRATCH", Secret::required("temporary"))
                .replace_secret("default", "SCRATCH", Secret::optional("replacement"))
                .remove_secret("default", "SCRATCH")
                .build()
                .unwrap();

            assert_eq!(restored.preserved_text(), Some(SPEC_TEXT));
        }

        #[test]
        fn edits_preserve_comments_ordering_and_unrelated_table_shapes() {
            let original = Spec::from_toml(SPEC_TEXT).unwrap();
            let edited = original
                .to_builder()
                .add_secret("default", "SCRATCH", Secret::required("temporary"))
                .replace_secret("default", "ALPHA", Secret::optional("replacement"))
                .build()
                .unwrap();
            let text = edited.preserved_text().unwrap();

            assert!(text.contains("# Team convention:"), "{text}");
            assert!(text.contains("# Keep this explanation."), "{text}");
            assert!(
                text.find("ZULU").unwrap() < text.find("ALPHA").unwrap(),
                "replacement moved the declaration: {text}"
            );
            assert!(text.contains("[profiles.default.NESTED]"), "{text}");
            assert!(text.contains("replacement"), "{text}");
            assert!(
                edited
                    .secrets("default")
                    .unwrap()
                    .any(|name| name == "SCRATCH")
            );
            assert!(
                !original
                    .secrets("default")
                    .unwrap()
                    .any(|name| name == "SCRATCH")
            );
        }

        #[test]
        fn complete_secret_declarations_round_trip_through_the_editor() {
            let added = Spec::from_toml(SPEC_TEXT)
                .unwrap()
                .to_builder()
                .add_secret(
                    "default",
                    "RICH",
                    Secret::required("fully specified")
                        .providers(["env", "keyring"])
                        .as_path(true)
                        .reference(NativeAddress {
                            item: "db".into(),
                            field: Some("password".into()),
                            ..NativeAddress::default()
                        }),
                )
                .build()
                .unwrap();
            let text = added.preserved_text().unwrap();

            assert!(text.contains(r#"providers = ["env", "keyring"]"#), "{text}");
            assert!(text.contains("as_path = true"), "{text}");
            assert!(text.contains(r#"item = "db""#), "{text}");
            assert!(text.contains(r#"field = "password""#), "{text}");
        }

        #[test]
        fn invalid_source_edits_are_reported_by_build() {
            let spec = Spec::from_toml(SPEC_TEXT).unwrap();

            let duplicate = spec
                .to_builder()
                .add_secret("default", "ALPHA", Secret::required("duplicate"))
                .build()
                .unwrap_err();
            assert!(duplicate.to_string().contains("already declared"));

            let absent = spec
                .to_builder()
                .remove_secret("default", "ABSENT")
                .build()
                .unwrap_err();
            assert!(absent.to_string().contains("not declared"));

            let invalid = spec
                .to_builder()
                .add_secret(
                    "default",
                    "COMPOSED",
                    Secret::required("bad template").composed("${NO_SUCH_SECRET}"),
                )
                .build()
                .unwrap_err();
            assert!(invalid.to_string().contains("NO_SUCH_SECRET"));
        }

        #[test]
        fn semantic_only_builder_operations_clear_preserved_text() {
            let edited = Spec::from_toml(SPEC_TEXT)
                .unwrap()
                .to_builder()
                .require_reason(RequireReason::Always)
                .build()
                .unwrap();

            assert_eq!(edited.preserved_text(), None);
            assert!(edited.to_toml().unwrap().contains("require_reason = true"));
        }

        #[test]
        fn rust_built_specs_render_without_claiming_to_preserve_text() {
            let spec = Spec::builder("embedded")
                .secret("TOKEN", Secret::required("API token"))
                .build()
                .unwrap();

            assert_eq!(spec.preserved_text(), None);
            assert!(spec.to_toml().unwrap().contains("TOKEN"));
        }
    }

    mod format_preserving_edits_with_inheritance {
        use super::*;
        use std::fs;

        fn project_with_parent() -> tempfile::TempDir {
            let dir = tempfile::tempdir().unwrap();
            fs::write(
                dir.path().join("base.toml"),
                r#"[project]
name = "demo"
revision = "1.0"

[profiles.default]
INHERITED = { description = "declared by the parent" }
"#,
            )
            .unwrap();
            fs::write(
                dir.path().join("secretspec.toml"),
                r#"[project]
name = "demo"
revision = "1.0"
extends = ["base.toml"]

[profiles.default]
OWN = { description = "declared by the child" }
"#,
            )
            .unwrap();
            dir
        }

        #[test]
        fn edits_keep_the_root_document_separate_from_its_parents() {
            let dir = project_with_parent();
            let spec = Spec::try_from(dir.path().join("secretspec.toml").as_path()).unwrap();
            let original = spec.preserved_text().unwrap().to_string();

            assert!(!original.contains("INHERITED"));
            assert!(
                spec.secrets("default")
                    .unwrap()
                    .any(|name| name == "INHERITED")
            );

            let added = spec
                .to_builder()
                .add_secret("default", "SCRATCH", Secret::required("temporary"))
                .build()
                .unwrap();
            assert!(!added.preserved_text().unwrap().contains("INHERITED"));
            assert!(
                added
                    .secrets("default")
                    .unwrap()
                    .any(|name| name == "INHERITED")
            );
            assert!(
                added
                    .secrets("default")
                    .unwrap()
                    .any(|name| name == "SCRATCH")
            );
        }

        #[test]
        fn inherited_declarations_can_be_overridden_then_revealed_again() {
            let dir = project_with_parent();
            let spec = Spec::try_from(dir.path().join("secretspec.toml").as_path()).unwrap();
            let original = spec.preserved_text().unwrap().to_string();

            let overridden = spec
                .to_builder()
                .add_secret(
                    "default",
                    "INHERITED",
                    Secret::required("declared by the child"),
                )
                .build()
                .unwrap();
            assert_eq!(
                overridden.compiled.profiles["default"].secrets["INHERITED"]
                    .config
                    .description
                    .as_deref(),
                Some("declared by the child")
            );

            let restored = overridden
                .into_builder()
                .remove_secret("default", "INHERITED")
                .build()
                .unwrap();
            assert_eq!(restored.preserved_text(), Some(original.as_str()));
            assert_eq!(
                restored.compiled.profiles["default"].secrets["INHERITED"]
                    .config
                    .description
                    .as_deref(),
                Some("declared by the parent")
            );
        }

        #[test]
        fn inherited_declarations_cannot_be_removed_from_the_child() {
            let dir = project_with_parent();
            let spec = Spec::try_from(dir.path().join("secretspec.toml").as_path()).unwrap();

            let error = spec
                .to_builder()
                .remove_secret("default", "INHERITED")
                .build()
                .unwrap_err();

            assert!(error.to_string().contains("not declared"));
        }

        #[test]
        fn semantic_edits_keep_root_declaration_provenance() {
            let dir = project_with_parent();
            let spec = Spec::try_from(dir.path().join("secretspec.toml").as_path()).unwrap();

            let overridden = spec
                .to_builder()
                .require_reason(RequireReason::Always)
                .add_secret(
                    "default",
                    "INHERITED",
                    Secret::required("declared by the child"),
                )
                .build()
                .unwrap();
            let rendered = overridden.to_toml().unwrap();
            assert!(rendered.contains("extends = [\"base.toml\"]"), "{rendered}");
            assert_eq!(rendered.matches("INHERITED").count(), 1, "{rendered}");

            let revealed = overridden
                .into_builder()
                .remove_secret("default", "INHERITED")
                .build()
                .unwrap();
            assert_eq!(
                revealed.compiled.profiles["default"].secrets["INHERITED"]
                    .config
                    .description
                    .as_deref(),
                Some("declared by the parent")
            );

            let error = spec
                .into_builder()
                .require_reason(RequireReason::Always)
                .remove_secret("default", "INHERITED")
                .build()
                .unwrap_err();
            assert!(error.to_string().contains("not contain that declaration"));
        }

        #[test]
        fn relative_loads_keep_resolving_extends_after_cwd_changes() {
            let _cwd = crate::secrets::lock_cwd();
            let workspace = tempfile::tempdir().unwrap();
            let project = workspace.path().join("project");
            let elsewhere = workspace.path().join("elsewhere");
            fs::create_dir_all(&project).unwrap();
            fs::create_dir_all(&elsewhere).unwrap();
            fs::write(
                project.join("base.toml"),
                r#"[project]
name = "demo"
revision = "1.0"

[profiles.default]
INHERITED = { description = "parent" }
"#,
            )
            .unwrap();
            fs::write(
                project.join("secretspec.toml"),
                r#"[project]
name = "demo"
revision = "1.0"
extends = ["base.toml"]

[profiles.default]
OWN = { description = "child" }
"#,
            )
            .unwrap();

            let original_cwd = std::env::current_dir().unwrap();
            std::env::set_current_dir(workspace.path()).unwrap();
            let spec = Spec::try_from(Path::new("project/secretspec.toml")).unwrap();
            std::env::set_current_dir(&elsewhere).unwrap();
            let edited = spec
                .into_builder()
                .add_secret("default", "ADDED", Secret::required("added"))
                .build();
            std::env::set_current_dir(original_cwd).unwrap();

            let edited = edited.unwrap();
            assert!(
                edited
                    .secrets("default")
                    .unwrap()
                    .any(|name| name == "INHERITED")
            );
        }

        #[test]
        fn undoing_an_add_removes_only_synthesized_profile_tables() {
            let dir = project_with_parent();
            fs::write(
                dir.path().join("base.toml"),
                r#"[project]
name = "demo"
revision = "1.0"

[profiles.default]
INHERITED = { description = "declared by the parent" }

[profiles.production]
PRODUCTION = { description = "parent-only profile" }
"#,
            )
            .unwrap();
            let spec = Spec::try_from(dir.path().join("secretspec.toml").as_path()).unwrap();
            let original = spec.preserved_text().unwrap().to_string();

            let restored = spec
                .into_builder()
                .add_secret("production", "SCRATCH", Secret::required("temporary"))
                .add_secret("production", "SECOND", Secret::required("temporary"))
                .build()
                .unwrap()
                .into_builder()
                .remove_secret("production", "SCRATCH")
                .remove_secret("production", "SECOND")
                .build()
                .unwrap();
            assert_eq!(restored.preserved_text(), Some(original.as_str()));

            let spec_with_empty_profile = original + "\n[profiles.production]\n";
            fs::write(dir.path().join("secretspec.toml"), &spec_with_empty_profile).unwrap();
            let restored = Spec::try_from(dir.path().join("secretspec.toml").as_path())
                .unwrap()
                .into_builder()
                .add_secret("production", "SCRATCH", Secret::required("temporary"))
                .remove_secret("production", "SCRATCH")
                .build()
                .unwrap();
            assert_eq!(
                restored.preserved_text(),
                Some(spec_with_empty_profile.as_str())
            );
        }
    }
}
