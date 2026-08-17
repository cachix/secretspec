//! Format-independent SecretSpec declarations.
//!
//! [`Spec`] is the semantic boundary shared by file-based configuration and
//! declarations assembled directly in Rust. The TOML representation remains
//! an implementation detail in `config`; callers construct the same model with
//! [`SpecBuilder`], [`Profile`], and [`Secret`].

use crate::config::{
    Config, GenerateConfig, GenerateOptions, NativeAddress, Profile as ConfigProfile,
    ProfileDefaults, Project, ProviderAlias, RequireReason, Scope, Secret as ConfigSecret,
    SecretEncoding, SecretExtract,
};
use crate::error::{Result, SecretSpecError};
use crate::manifest::CompiledSpec;
use std::collections::HashMap;
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
    pub(crate) config: Config,
    pub(crate) compiled: CompiledSpec,
    pub(crate) base_dir: Option<PathBuf>,
    /// The exact text this spec was parsed from, when there is one.
    ///
    /// The **root document only**, never the merged result of `extends`:
    /// [`Config::try_from`] folds parents into the child, so retaining the
    /// merged text and writing it back would silently inline every inherited
    /// declaration into a file that had only referenced them.
    ///
    /// `None` for a [`SpecBuilder`]-built spec, which was never text.
    pub(crate) source: Option<String>,
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
        let mut spec = Self::from_config_document(config)?;
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

    /// Consume this validated specification and reopen its declarations for editing.
    ///
    /// [`SpecBuilder::build`] validates and compiles the edited declarations into a
    /// new `Spec`. The original `Spec` is consumed so its declarations and compiled
    /// view can never drift apart. Use [`Self::to_builder`] to retain it.
    pub fn into_builder(self) -> SpecBuilder {
        self.into()
    }

    /// Copy this validated specification into a builder for editing.
    ///
    /// The original `Spec` remains unchanged. Prefer [`Self::into_builder`] when it
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
            source: None,
        })
    }

    pub(crate) fn into_parts(self) -> (Config, CompiledSpec) {
        (self.config, self.compiled)
    }

    /// This spec's exact backing text, when the byte-exactness guarantee holds.
    ///
    /// `Spec::from_toml(s)?.preserved_text() == Some(s)`, and for a spec loaded
    /// from a path this is the root file's own bytes — not the merged result of
    /// `extends`.
    ///
    /// `None` for a [`SpecBuilder`]-built spec, which never had a document.
    /// That is why this and [`Self::to_toml`] are separate methods: a single
    /// renderer whose exactness depended on hidden state would silently hand a
    /// regenerated document to exactly the callers who needed the original.
    ///
    /// Available starting with SecretSpec 0.20.
    pub fn preserved_text(&self) -> Option<&str> {
        self.source.as_deref()
    }

    /// Render these declarations as freshly formatted TOML.
    ///
    /// Always available, and never byte-exact: key order, whitespace, and
    /// comments come from the serializer, not from any original document. Use
    /// [`Self::preserved_text`] when the original formatting matters.
    ///
    /// Available starting with SecretSpec 0.20.
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(&self.config)
            .map_err(|error| SecretSpecError::InvalidSpec(error.to_string()))
    }

    /// Whether `profile` declares `name` in this spec's own source text.
    ///
    /// Scoped to the retained document, so a declaration this spec only sees
    /// through `extends` reads as absent — the question being answered is "is
    /// this name editable here", which is what [`Self::remove_secret_from_text`]
    /// can act on. [`Self::secrets`] answers the inherited-inclusive question.
    ///
    /// Parsed, not searched. A substring test would match the name inside a
    /// comment or another secret's description, and would do so silently.
    /// `false` for a spec with no source text, and for one whose text does not
    /// parse — callers needing to distinguish those should check
    /// [`Self::preserved_text`] first.
    ///
    /// Available starting with SecretSpec 0.20.
    #[cfg(feature = "manifest-edit")]
    pub fn declares_secret_in_text(&self, profile: &str, name: &str) -> bool {
        self.source.as_deref().is_some_and(|source| {
            crate::manifest_edit::declares_secret(source, profile, name).unwrap_or(false)
        })
    }

    /// Add one declaration, returning a new fully revalidated `Spec` whose text
    /// differs from this one's only by that declaration.
    ///
    /// Everything else in the document survives byte for byte: comments, key
    /// order, quoting, and any syntax the semantic model does not represent.
    ///
    /// The new spec's `config` and `compiled` views are re-derived by reparsing
    /// the edited text through the same validated path every other `Spec` goes
    /// through, rather than being mutated in parallel with it. There is one
    /// synchronization point instead of one per method, so the text and the
    /// semantic view cannot disagree — and an edit that produces an invalid
    /// spec fails here rather than at some later load.
    ///
    /// Errors when this spec has no source text (see [`Self::preserved_text`]),
    /// when `profile` already declares `name`, or when the result would not
    /// validate.
    ///
    /// Available starting with SecretSpec 0.20.
    #[cfg(feature = "manifest-edit")]
    pub fn add_secret_to_text(&self, profile: &str, name: &str, secret: Secret) -> Result<Self> {
        let source = self.editable_source()?;
        let edited = crate::manifest_edit::add_secret_value_to_manifest(
            source,
            profile,
            name,
            &secret.config,
        )
        .map_err(|error| SecretSpecError::InvalidSpec(error.to_string()))?;
        self.reparse(edited)
    }

    /// Remove one declaration, returning a new fully revalidated `Spec`.
    ///
    /// The inverse of [`Self::add_secret_to_text`] and byte-exact in the same
    /// way: adding a declaration and then removing it restores the original
    /// document exactly, which is what makes an "undo" usable by callers that
    /// compare manifests as bytes rather than semantically.
    ///
    /// Removing a name the profile does not declare *in this text* is an error
    /// rather than a silent no-op — including a name it inherits through
    /// `extends`, which is declared in the parent and cannot be edited here.
    ///
    /// Available starting with SecretSpec 0.20.
    #[cfg(feature = "manifest-edit")]
    pub fn remove_secret_from_text(&self, profile: &str, name: &str) -> Result<Self> {
        let source = self.editable_source()?;
        let edited = crate::manifest_edit::remove_secret_from_manifest(source, profile, name)
            .map_err(|error| SecretSpecError::InvalidSpec(error.to_string()))?;
        self.reparse(edited)
    }

    #[cfg(feature = "manifest-edit")]
    fn editable_source(&self) -> Result<&str> {
        self.source.as_deref().ok_or_else(|| {
            SecretSpecError::InvalidSpec(
                "this spec has no source text to edit; it was built with Spec::builder".to_string(),
            )
        })
    }

    /// Rebuild from edited text, preserving this spec's inheritance context.
    ///
    /// `Spec::from_toml` cannot serve here: it rejects a non-empty
    /// `project.extends`, having no location to resolve the paths against. This
    /// spec does have one — `base_dir`, recorded when it was loaded — so the
    /// reparse resolves inheritance exactly as the original load did.
    #[cfg(feature = "manifest-edit")]
    fn reparse(&self, edited: String) -> Result<Self> {
        let config = match self.base_dir.as_deref() {
            Some(base_dir) => Config::from_text_in(&edited, base_dir)?,
            None => Config::from_str(&edited)?,
        };
        let mut spec = Self::from_config_document(config)?;
        spec.base_dir = self.base_dir.clone();
        spec.source = Some(edited);
        Ok(spec)
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
        let mut spec = Self::from_config_document(Config::try_from(path)?)?;
        spec.base_dir = Some(
            path.parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from(".")),
        );
        // Read the root file again rather than reusing the loader's merged
        // result: `config` above is every ancestor folded together, and the
        // text has to stay the one document a caller could write back.
        // A file that parsed but cannot be re-read leaves `source` unset, which
        // degrades editing to unavailable rather than failing the load.
        spec.source = std::fs::read_to_string(path).ok();
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
            errors: Vec::new(),
        }
    }

    /// Set the policy for requiring an access reason.
    pub fn require_reason(mut self, policy: RequireReason) -> Self {
        self.config.project.require_reason = Some(policy);
        self
    }

    /// Add a secret to the `default` profile.
    pub fn secret(mut self, name: impl Into<String>, secret: Secret) -> Self {
        let profile = self
            .config
            .profiles
            .entry("default".to_string())
            .or_default();
        insert_secret(profile, name.into(), secret, &mut self.errors, "default");
        self
    }

    /// Add a declaration to an existing profile.
    ///
    /// This is the edit-oriented counterpart to [`Self::secret`], which creates
    /// the `default` profile when needed. A missing profile or an existing
    /// declaration is reported by [`Self::build`] rather than silently creating
    /// or replacing it.
    pub fn add_secret(
        mut self,
        profile: impl Into<String>,
        name: impl Into<String>,
        secret: Secret,
    ) -> Self {
        let profile = profile.into();
        let name = name.into();
        let Some(declarations) = self.config.profiles.get_mut(&profile) else {
            self.errors.push(format!(
                "cannot add secret '{name}': profile '{profile}' does not exist"
            ));
            return self;
        };
        if declarations.secrets.contains_key(&name) {
            self.errors.push(format!(
                "cannot add secret '{name}': profile '{profile}' already contains that declaration"
            ));
            return self;
        }
        declarations.secrets.insert(name, secret.config);
        self
    }

    /// Replace an existing declaration in one profile.
    ///
    /// The replacement is not applied when either the profile or declaration is
    /// absent; [`Self::build`] reports the collected edit error.
    pub fn replace_secret(
        mut self,
        profile: impl Into<String>,
        name: impl Into<String>,
        secret: Secret,
    ) -> Self {
        let profile = profile.into();
        let name = name.into();
        let Some(declarations) = self.config.profiles.get_mut(&profile) else {
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
        self
    }

    /// Remove a declaration from one profile.
    ///
    /// This removes the profile-local declaration, not necessarily the secret
    /// from the profile's effective view. Removing an override can reveal a
    /// declaration inherited from `default`; removing a `default` declaration
    /// also removes it from profiles that only inherited it. References from
    /// scopes, compositions, or constraints are checked again by [`Self::build`].
    pub fn remove_secret(mut self, profile: impl Into<String>, name: impl Into<String>) -> Self {
        let profile = profile.into();
        let name = name.into();
        let Some(declarations) = self.config.profiles.get_mut(&profile) else {
            self.errors.push(format!(
                "cannot remove secret '{name}': profile '{profile}' does not exist"
            ));
            return self;
        };
        if declarations.secrets.remove(&name).is_none() {
            self.errors.push(format!(
                "cannot remove secret '{name}': profile '{profile}' does not contain that declaration"
            ));
        }
        self
    }

    /// Add a named profile.
    pub fn profile(mut self, name: impl Into<String>, profile: Profile) -> Self {
        let name = name.into();
        self.errors.extend(
            profile
                .errors
                .into_iter()
                .map(|error| format!("profile '{name}': {error}")),
        );
        if self
            .config
            .profiles
            .insert(name.clone(), profile.config)
            .is_some()
        {
            self.errors.push(format!("duplicate profile '{name}'"));
        }
        self
    }

    /// Define a project-local provider alias.
    pub fn provider(mut self, name: impl Into<String>, provider: impl Into<ProviderAlias>) -> Self {
        let name = name.into();
        let providers = self.config.providers.get_or_insert_with(HashMap::new);
        if providers.insert(name.clone(), provider.into()).is_some() {
            self.errors
                .push(format!("duplicate provider alias '{name}'"));
        }
        self
    }

    /// Define a named, membership-only subset of secrets.
    pub fn scope<I, S>(mut self, name: impl Into<String>, secrets: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let name = name.into();
        let scopes = self.config.scopes.get_or_insert_with(HashMap::new);
        let scope = Scope {
            secrets: secrets.into_iter().map(Into::into).collect(),
        };
        if scopes.insert(name.clone(), scope).is_some() {
            self.errors.push(format!("duplicate scope '{name}'"));
        }
        self
    }

    /// Validate and compile this declaration.
    pub fn build(self) -> Result<Spec> {
        if !self.errors.is_empty() {
            return Err(SecretSpecError::InvalidSpec(self.errors.join("; ")));
        }
        let mut spec = Spec::from_config_document(self.config)?;
        spec.base_dir = self.base_dir;
        Ok(spec)
    }
}

impl From<Spec> for SpecBuilder {
    fn from(spec: Spec) -> Self {
        Self {
            config: spec.config,
            base_dir: spec.base_dir,
            errors: Vec::new(),
        }
    }
}

impl From<&Spec> for SpecBuilder {
    fn from(spec: &Spec) -> Self {
        Self {
            config: spec.config.clone(),
            base_dir: spec.base_dir.clone(),
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

    /// Extract a value from a structured provider result.
    pub fn extract(mut self, extract: SecretExtract) -> Self {
        self.config.extract = Some(extract);
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
}

impl Generation {
    /// A password with SecretSpec's default length and alphanumeric charset.
    pub fn password() -> Self {
        Self::Password {
            length: None,
            charset: PasswordCharset::Alphanumeric,
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

    #[cfg(feature = "manifest-edit")]
    mod text_edits {
        use super::*;

        /// Deliberately awkward: a comment, non-alphabetical key order, a
        /// blank line, and a full `[profiles.x.NAME]` table beside inline
        /// ones. Every one of these is something a regenerating writer would
        /// silently normalize away.
        const MANIFEST: &str = r#"[project]
name = "demo"
revision = "1.0"

# Team convention: transport secrets first, then credentials.
[profiles.default]
ZULU = { description = "sorts last on purpose" }
ALPHA = { description = "sorts first on purpose" }

[profiles.default.NESTED]
description = "declared as a full table"
required = false
"#;

        #[test]
        fn a_parsed_spec_preserves_the_exact_text_it_came_from() {
            // The guarantee the whole surface rests on, stated as the issue
            // states it: from_toml(s).preserved_text() == Some(s).
            let spec = Spec::from_toml(MANIFEST).unwrap();

            assert_eq!(spec.preserved_text(), Some(MANIFEST));
        }

        #[test]
        fn adding_then_removing_a_declaration_restores_the_original_bytes() {
            // Byte-exact, not merely semantically equivalent. Callers that
            // compare manifests as raw bytes -- a drift checker diffing a
            // runtime manifest against a tracked template -- get a permanent
            // false positive from anything weaker.
            let spec = Spec::from_toml(MANIFEST).unwrap();

            let added = spec
                .add_secret_to_text("default", "SCRATCH", Secret::required("temporary"))
                .unwrap();
            assert_ne!(added.preserved_text(), Some(MANIFEST));

            let removed = added.remove_secret_from_text("default", "SCRATCH").unwrap();

            assert_eq!(removed.preserved_text(), Some(MANIFEST));
        }

        #[test]
        fn an_edit_leaves_comments_ordering_and_table_shapes_alone() {
            // The point of doing this with toml_edit rather than a round-trip
            // through the semantic model, asserted directly rather than only
            // via the round-trip: a regenerated document would lose the
            // comment, sort ZULU after ALPHA, and inline the NESTED table.
            let spec = Spec::from_toml(MANIFEST).unwrap();

            let text = spec
                .add_secret_to_text("default", "SCRATCH", Secret::required("temporary"))
                .unwrap();
            let text = text.preserved_text().unwrap().to_string();

            assert!(text.contains("# Team convention:"), "{text}");
            assert!(
                text.find("ZULU").unwrap() < text.find("ALPHA").unwrap(),
                "declaration order was not preserved: {text}"
            );
            assert!(text.contains("[profiles.default.NESTED]"), "{text}");
        }

        #[test]
        fn an_edited_spec_is_revalidated_not_just_rewritten() {
            // The synchronization point. The returned Spec's semantic view is
            // re-derived from the edited text, so it must already see the new
            // declaration -- a version that edited text and left `compiled`
            // stale would pass a bytes-only assertion and fail this.
            let spec = Spec::from_toml(MANIFEST).unwrap();

            let added = spec
                .add_secret_to_text("default", "SCRATCH", Secret::required("temporary"))
                .unwrap();

            let secrets: Vec<&str> = added.secrets("default").unwrap().collect();
            assert!(secrets.contains(&"SCRATCH"), "{secrets:?}");
            // ...and the spec it was derived from is untouched.
            let original: Vec<&str> = spec.secrets("default").unwrap().collect();
            assert!(!original.contains(&"SCRATCH"), "{original:?}");
        }

        #[test]
        fn an_edit_that_would_not_validate_fails_at_the_edit() {
            // Reparsing through the validated path is what makes this a
            // failure here rather than a surprise at some later load.
            let spec = Spec::from_toml(MANIFEST).unwrap();

            let err = spec
                .add_secret_to_text(
                    "default",
                    "COMPOSED",
                    Secret::required("bad template").composed("${NO_SUCH_SECRET}"),
                )
                .unwrap_err();

            assert!(
                err.to_string().contains("NO_SUCH_SECRET"),
                "unexpected error: {err}"
            );
        }

        #[test]
        fn a_declaration_survives_every_field_it_was_given() {
            // add_secret_to_text takes a whole `Secret`, not a description and
            // a bool, so the richer fields have to reach the document -- and
            // `ref`, which serializes as a nested table rather than a scalar,
            // is exactly where a writer that only knows how to emit scalars
            // into an inline table breaks.
            let spec = Spec::from_toml(MANIFEST).unwrap();

            let added = spec
                .add_secret_to_text(
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
                .unwrap();

            let text = added.preserved_text().unwrap();
            assert!(text.contains("RICH = {"), "{text}");
            assert!(text.contains(r#"providers = ["env", "keyring"]"#), "{text}");
            assert!(text.contains("as_path = true"), "{text}");
            assert!(text.contains(r#"item = "db""#), "{text}");
            assert!(text.contains(r#"field = "password""#), "{text}");

            // And it round-trips: the parser accepts every key the writer
            // emitted, which is the property that keeps them from drifting.
            let removed = added.remove_secret_from_text("default", "RICH").unwrap();
            assert_eq!(removed.preserved_text(), Some(MANIFEST));
        }

        #[test]
        fn declaring_a_name_twice_is_an_error() {
            let spec = Spec::from_toml(MANIFEST).unwrap();

            let err = spec
                .add_secret_to_text("default", "ALPHA", Secret::required("duplicate"))
                .unwrap_err();

            assert!(err.to_string().contains("already declared"), "{err}");
        }

        #[test]
        fn removing_a_name_that_is_not_declared_is_an_error() {
            // Not a silent no-op: a caller undeclaring something already
            // absent has a wrong model of the manifest.
            let spec = Spec::from_toml(MANIFEST).unwrap();

            let err = spec
                .remove_secret_from_text("default", "ABSENT")
                .unwrap_err();

            assert!(err.to_string().contains("not declared"), "{err}");
        }

        #[test]
        fn declares_secret_in_text_is_parsed_rather_than_searched() {
            // Why this is not a substring test. Both of these carry the name
            // as text while declaring nothing of the sort, and the inverse
            // mistake would be silent.
            let manifest = r#"[project]
name = "demo"
revision = "1.0"

[profiles.default]
# TODO: declare LOOKALIKE next release
OTHER = { description = "unrelated, mentions LOOKALIKE in prose" }
"#;
            let spec = Spec::from_toml(manifest).unwrap();

            assert!(spec.declares_secret_in_text("default", "OTHER"));
            assert!(!spec.declares_secret_in_text("default", "LOOKALIKE"));
        }

        #[test]
        fn a_builder_built_spec_has_no_text_and_says_so_rather_than_inventing_one() {
            // The reason preserved_text() returns Option and to_toml() does
            // not: a single renderer whose exactness depended on hidden state
            // would hand this caller a regenerated document and call it the
            // original.
            let spec = Spec::builder("embedded")
                .secret("TOKEN", Secret::required("API token"))
                .build()
                .unwrap();

            assert_eq!(spec.preserved_text(), None);

            let err = spec
                .add_secret_to_text("default", "SCRATCH", Secret::required("temporary"))
                .unwrap_err();
            assert!(err.to_string().contains("Spec::builder"), "{err}");

            // to_toml still works -- it never promised exactness.
            let rendered = spec.to_toml().unwrap();
            assert!(rendered.contains("TOKEN"), "{rendered}");
        }

        #[test]
        fn to_toml_renders_a_spec_that_never_had_a_document() {
            // Round-trips through the parser, so "freshly formatted" still
            // means "valid", not merely "printable".
            let spec = Spec::builder("embedded")
                .secret("TOKEN", Secret::required("API token"))
                .build()
                .unwrap();

            let reparsed = Spec::from_toml(&spec.to_toml().unwrap()).unwrap();

            assert_eq!(reparsed.project(), "embedded");
            let secrets: Vec<&str> = reparsed.secrets("default").unwrap().collect();
            assert_eq!(secrets, vec!["TOKEN"]);
        }
    }

    /// The `extends` wrinkle, which needs real files on disk.
    #[cfg(feature = "manifest-edit")]
    mod text_edits_with_inheritance {
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
        fn the_retained_text_is_the_root_file_not_the_merged_result() {
            // Config::try_from folds every parent into the child. Retaining
            // that merged document as the child's text and writing it back
            // would silently inline the parent's declarations into a file that
            // had only referenced them -- turning inheritance into a copy.
            let dir = project_with_parent();

            let spec = Spec::try_from(dir.path().join("secretspec.toml").as_path()).unwrap();

            let text = spec.preserved_text().unwrap();
            assert!(text.contains("OWN"), "{text}");
            assert!(
                !text.contains("INHERITED"),
                "the parent's declaration leaked into the child's text: {text}"
            );
            // ...while the semantic view still sees both.
            let secrets: Vec<&str> = spec.secrets("default").unwrap().collect();
            assert!(secrets.contains(&"INHERITED"), "{secrets:?}");
        }

        #[test]
        fn editing_a_spec_that_extends_another_revalidates_against_the_parent() {
            // The wrinkle. Spec::from_toml rejects a non-empty project.extends
            // outright -- a string has nowhere to resolve the paths from -- so
            // reparsing the edited text through it would fail on every
            // inheriting project. The reparse is seeded with base_dir instead.
            let dir = project_with_parent();
            let spec = Spec::try_from(dir.path().join("secretspec.toml").as_path()).unwrap();

            let added = spec
                .add_secret_to_text("default", "SCRATCH", Secret::required("temporary"))
                .unwrap();

            // Inheritance survived the edit rather than being dropped...
            let secrets: Vec<&str> = added.secrets("default").unwrap().collect();
            assert!(secrets.contains(&"INHERITED"), "{secrets:?}");
            assert!(secrets.contains(&"SCRATCH"), "{secrets:?}");
            // ...and the edited text is still root-only.
            assert!(!added.preserved_text().unwrap().contains("INHERITED"));

            // Control: the same text has no chance through from_toml.
            assert!(Spec::from_toml(added.preserved_text().unwrap()).is_err());
        }

        #[test]
        fn an_inherited_declaration_is_not_editable_here() {
            // declares_secret_in_text answers "can this be edited in this
            // document", which is what remove_secret_from_text can act on --
            // deliberately a different question from `secrets()`.
            let dir = project_with_parent();
            let spec = Spec::try_from(dir.path().join("secretspec.toml").as_path()).unwrap();

            assert!(spec.declares_secret_in_text("default", "OWN"));
            assert!(!spec.declares_secret_in_text("default", "INHERITED"));

            let err = spec
                .remove_secret_from_text("default", "INHERITED")
                .unwrap_err();
            assert!(err.to_string().contains("not declared"), "{err}");
        }

        #[test]
        fn the_round_trip_still_holds_through_inheritance() {
            let dir = project_with_parent();
            let spec = Spec::try_from(dir.path().join("secretspec.toml").as_path()).unwrap();
            let original = spec.preserved_text().unwrap().to_string();

            let restored = spec
                .add_secret_to_text("default", "SCRATCH", Secret::required("temporary"))
                .unwrap()
                .remove_secret_from_text("default", "SCRATCH")
                .unwrap();

            assert_eq!(restored.preserved_text(), Some(original.as_str()));
        }
    }
}
