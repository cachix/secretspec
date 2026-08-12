use crate::provider::{Provider, providers, spec_names_known_provider};
use crate::{Config, ExportFormat, GlobalConfig, GlobalDefaults, Profile, Project, Secrets};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use miette::{IntoDiagnostic, Result, WrapErr, miette};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{IsTerminal, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Main CLI structure for the secretspec application.
///
/// This is the entry point for the command-line interface, parsing user commands
/// and delegating to the appropriate subcommands for secrets management.
#[derive(Parser)]
#[command(name = "secretspec")]
#[command(about = "A declarative interface for every secret provider. https://secretspec.dev", long_about = None)]
#[command(version)]
struct Cli {
    /// Path to secretspec.toml (default: auto-detect by walking up from current directory)
    #[arg(short = 'f', long, global = true, env = "SECRETSPEC_FILE")]
    file: Option<PathBuf>,

    /// Reason for accessing secrets, recorded by providers that support audit
    /// logging (e.g. Proton Pass agent sessions). Takes precedence over the
    /// PROTON_PASS_AGENT_REASON environment variable.
    #[arg(long, global = true, env = "SECRETSPEC_REASON")]
    reason: Option<String>,

    /// The subcommand to execute
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum CompletionShell {
    /// Bourne Again Shell
    Bash,
    /// Elvish shell
    Elvish,
    /// Friendly Interactive Shell
    Fish,
    /// Nushell
    Nushell,
    /// PowerShell
    #[value(name = "powershell")]
    PowerShell,
    /// Z shell
    Zsh,
}

/// Available commands for the secretspec CLI.
///
/// This enum defines all the subcommands that can be executed, including
/// initialization, secret management, configuration, and import operations.
#[derive(Subcommand)]
enum Commands {
    /// Initialize a new secretspec.toml (optionally, from a provider)
    Init {
        /// Discover declarations from a provider (additional providers in 0.18+)
        ///
        /// Note: no short flag here — `-f` is the global `--file` option.
        #[arg(long, default_value = "dotenv://.env")]
        from: String,
        /// Project used to select the provider namespace (0.18+; defaults to directory name)
        #[arg(long)]
        project: Option<String>,
        /// Profile used to select the provider namespace (0.18+)
        #[arg(short = 'P', long, default_value = "default")]
        profile: String,
    },
    /// Add a secret declaration to secretspec.toml (0.18+)
    Add {
        /// Name of the secret
        name: String,
        /// Human-readable description (prompts when omitted)
        #[arg(short, long)]
        description: Option<String>,
        /// Profile to add the secret to
        #[arg(short = 'P', long, env = "SECRETSPEC_PROFILE")]
        profile: Option<String>,
    },
    /// Set a secret value
    Set {
        /// Name of the secret
        name: String,
        /// Value of the secret (will prompt if not provided)
        value: Option<String>,
        /// Provider backend to use
        #[arg(short, long, env = "SECRETSPEC_PROVIDER")]
        provider: Option<String>,
        /// Profile to use
        #[arg(short = 'P', long, env = "SECRETSPEC_PROFILE")]
        profile: Option<String>,
    },
    /// Get a secret value
    Get {
        /// Name of the secret
        name: String,
        /// Provider backend to use
        #[arg(short, long, env = "SECRETSPEC_PROVIDER")]
        provider: Option<String>,
        /// Profile to use
        #[arg(short = 'P', long, env = "SECRETSPEC_PROFILE")]
        profile: Option<String>,
    },
    /// Delete stored secret values from a provider (0.18+)
    Delete {
        /// Names of the secrets to delete
        #[arg(required_unless_present = "all", conflicts_with = "all")]
        names: Vec<String>,
        /// Delete every provider-backed secret declared in the active profile
        #[arg(long)]
        all: bool,
        /// Skip the confirmation required by --all
        #[arg(short, long, requires = "all", conflicts_with = "names")]
        yes: bool,
        /// Provider backend to delete from
        #[arg(short, long, env = "SECRETSPEC_PROVIDER")]
        provider: Option<String>,
        /// Profile to use
        #[arg(short = 'P', long, env = "SECRETSPEC_PROFILE")]
        profile: Option<String>,
    },
    /// Run a command with secrets injected
    Run {
        /// Provider backend to use
        #[arg(short, long, env = "SECRETSPEC_PROVIDER")]
        provider: Option<String>,
        /// Profile to use
        #[arg(short = 'P', long, env = "SECRETSPEC_PROFILE")]
        profile: Option<String>,
        /// Scope to resolve (a `[scopes]` subset of the profile). Excluded
        /// secrets are removed from the child environment even if inherited.
        #[arg(short = 'S', long, env = "SECRETSPEC_SCOPE")]
        scope: Option<String>,
        /// Command and arguments to run
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// Resolve secrets and print them for another tool to consume
    Export {
        /// Provider backend to use
        #[arg(short, long, env = "SECRETSPEC_PROVIDER")]
        provider: Option<String>,
        /// Profile to use
        #[arg(short = 'P', long, env = "SECRETSPEC_PROFILE")]
        profile: Option<String>,
        /// Scope to resolve (a `[scopes]` subset of the profile)
        #[arg(short = 'S', long, env = "SECRETSPEC_SCOPE")]
        scope: Option<String>,
        /// Output format
        #[arg(long, value_enum, default_value = "shell")]
        format: ExportFormat,
    },
    /// Check if all required secrets are in the provider, if not set them
    Check {
        /// Provider backend to use
        #[arg(short, long, env = "SECRETSPEC_PROVIDER")]
        provider: Option<String>,
        /// Profile to use
        #[arg(short = 'P', long, env = "SECRETSPEC_PROFILE")]
        profile: Option<String>,
        /// Scope to check (a `[scopes]` subset of the profile)
        #[arg(short = 'S', long, env = "SECRETSPEC_SCOPE")]
        scope: Option<String>,
        /// Don't prompt for missing secrets (exit with error if any are missing)
        #[arg(short = 'n', long)]
        no_prompt: bool,
        /// Print the value-free resolution report as JSON (no secret values).
        /// Never prompts; exits non-zero if a required secret is missing.
        #[arg(long, conflicts_with = "explain")]
        json: bool,
        /// Print a value-free, human-readable resolution trace (no secret
        /// values). Never prompts; exits non-zero if a required secret is missing.
        #[arg(long)]
        explain: bool,
    },
    /// Emit a JSON Schema for the manifest's typed shape.
    ///
    /// Feed this to [quicktype](https://quicktype.io) to generate an idiomatic
    /// typed accessor (plus a deserializer) for any language, then hand the
    /// deserializer the flat map from each SDK's `fields()` helper. By default it
    /// describes the union `SecretSpec` (safe for any profile); `--profile` gives
    /// that profile's exact fields. Value-free: reads only the manifest.
    ///
    /// Example: `secretspec schema | quicktype -s schema --top-level SecretSpec --lang typescript`
    Schema {
        /// Emit the schema for this profile's fields instead of the union
        #[arg(short = 'P', long)]
        profile: Option<String>,
        /// Write to this file instead of stdout
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Generate shell completion scripts (0.20+)
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: CompletionShell,
    },
    /// Manage SecretSpec configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Import secrets from a provider to another provider
    Import {
        /// Provider backend to import from (secrets will be imported to the default provider)
        from_provider: String,
        /// Delete a source value only after the destination contains the same value (0.18+)
        #[arg(long)]
        delete_source: bool,
    },
    /// Manage cached provider values (0.17+)
    Cache {
        #[command(subcommand)]
        action: CacheAction,
    },
    /// Show the local audit log of secret access
    Audit {
        /// Only show entries for this project
        #[arg(long)]
        project: Option<String>,
        /// Only show entries for this action (get, set, delete, check, run, import, export, cache_clear)
        #[arg(long)]
        action: Option<String>,
        /// Show only the last N entries
        #[arg(short = 'n', long)]
        tail: Option<usize>,
        /// Output raw JSON Lines instead of a formatted summary
        #[arg(long)]
        json: bool,
    },
}

fn generate_completions(shell: CompletionShell, output: &mut dyn Write) {
    let mut command = Cli::command();
    match shell {
        CompletionShell::Bash => clap_complete::generate(
            clap_complete::Shell::Bash,
            &mut command,
            "secretspec",
            output,
        ),
        CompletionShell::Elvish => clap_complete::generate(
            clap_complete::Shell::Elvish,
            &mut command,
            "secretspec",
            output,
        ),
        CompletionShell::Fish => clap_complete::generate(
            clap_complete::Shell::Fish,
            &mut command,
            "secretspec",
            output,
        ),
        CompletionShell::Nushell => clap_complete::generate(
            clap_complete_nushell::Nushell,
            &mut command,
            "secretspec",
            output,
        ),
        CompletionShell::PowerShell => clap_complete::generate(
            clap_complete::Shell::PowerShell,
            &mut command,
            "secretspec",
            output,
        ),
        CompletionShell::Zsh => clap_complete::generate(
            clap_complete::Shell::Zsh,
            &mut command,
            "secretspec",
            output,
        ),
    }
}

/// Cached provider maintenance commands (0.17+).
#[derive(Subcommand)]
enum CacheAction {
    /// Delete cached values for one secret, or all cached secrets (0.17+)
    Clear {
        /// Secret to clear; omit to clear every cached secret in the profile
        name: Option<String>,
        /// Profile whose cache entries should be cleared
        #[arg(short = 'P', long, env = "SECRETSPEC_PROFILE")]
        profile: Option<String>,
    },
}

/// Configuration-related subcommands.
///
/// User-global configuration has an explicit `global` namespace. Legacy
/// spellings remain hidden aliases for backwards compatibility.
#[derive(Subcommand)]
enum ConfigAction {
    /// Manage user-global configuration (0.17+)
    Global {
        #[command(subcommand)]
        action: GlobalConfigAction,
    },
    /// Initialize user configuration
    #[command(hide = true)]
    Init {
        /// Provider backend to save without prompting (0.17+)
        #[arg(short, long, env = "SECRETSPEC_PROVIDER")]
        provider: Option<String>,
        /// Default profile to save without prompting; use "none" to clear it (0.17+)
        #[arg(short = 'P', long, env = "SECRETSPEC_PROFILE")]
        profile: Option<String>,
    },
    /// Show current configuration
    #[command(hide = true)]
    Show,
    /// Store project-scoped provider credentials
    #[command(subcommand)]
    Provider(ProviderAction),
}

/// User-global configuration subcommands.
#[derive(Subcommand)]
enum GlobalConfigAction {
    /// Initialize user-global defaults
    Init {
        /// Provider backend to save without prompting
        #[arg(short, long, env = "SECRETSPEC_PROVIDER")]
        provider: Option<String>,
        /// Default profile to save without prompting; use "none" to clear it
        #[arg(short = 'P', long, env = "SECRETSPEC_PROFILE")]
        profile: Option<String>,
    },
    /// Show user-global configuration
    Show,
    /// Manage user-global provider aliases
    #[command(subcommand)]
    Provider(GlobalProviderAction),
}

/// User-global provider alias management subcommands.
#[derive(Subcommand)]
enum GlobalProviderAction {
    /// Add or update a provider alias
    Add {
        /// Name of the provider alias
        name: String,
        /// Provider URI (e.g., "keyring://", "onepassword://Shared", "dotenv://.env.local")
        uri: String,
        /// Provider credential binding `NAME=PROVIDER` (repeatable). `NAME` is
        /// semantic and provider-specific, such as `access_token` or `role_id`.
        /// Only the bare-string source form is expressible here; add a `ref` by
        /// editing the config.
        #[arg(long = "credential", value_name = "NAME=PROVIDER")]
        credential: Vec<String>,
    },
    /// Remove a provider alias
    Remove {
        /// Name of the provider alias to remove
        name: String,
    },
    /// List all configured provider aliases
    List,
}

/// Legacy provider alias commands plus project-scoped credential login.
///
/// Alias mutation commands remain hidden for backwards compatibility; new
/// invocations should use `config global provider`.
#[derive(Subcommand)]
enum ProviderAction {
    /// Add or update a provider alias
    #[command(hide = true)]
    Add {
        /// Name of the provider alias
        name: String,
        /// Provider URI (e.g., "keyring://", "onepassword://Shared", "dotenv://.env.local")
        uri: String,
        /// Provider credential binding `NAME=PROVIDER` (repeatable). `NAME` is
        /// semantic and provider-specific, such as `access_token` or `role_id`.
        /// Only the bare-string source form is expressible here; add a `ref` by
        /// editing the config.
        #[arg(long = "credential", value_name = "NAME=PROVIDER")]
        credential: Vec<String>,
    },
    /// Remove a provider alias
    #[command(hide = true)]
    Remove {
        /// Name of the provider alias to remove
        name: String,
    },
    /// List all configured provider aliases
    #[command(hide = true)]
    List,
    /// Store the credentials declared by a provider alias
    Login {
        /// Name of the provider alias to store credentials for
        name: String,
    },
}

impl From<GlobalConfigAction> for ConfigAction {
    fn from(action: GlobalConfigAction) -> Self {
        match action {
            GlobalConfigAction::Init { provider, profile } => Self::Init { provider, profile },
            GlobalConfigAction::Show => Self::Show,
            GlobalConfigAction::Provider(action) => Self::Provider(action.into()),
        }
    }
}

impl From<GlobalProviderAction> for ProviderAction {
    fn from(action: GlobalProviderAction) -> Self {
        match action {
            GlobalProviderAction::Add {
                name,
                uri,
                credential,
            } => Self::Add {
                name,
                uri,
                credential,
            },
            GlobalProviderAction::Remove { name } => Self::Remove { name },
            GlobalProviderAction::List => Self::List,
        }
    }
}

/// Maps the explicit `config global` namespace onto the legacy internal action
/// variants so both CLI spellings share exactly one implementation.
fn normalize_config_action(action: ConfigAction) -> ConfigAction {
    match action {
        ConfigAction::Global { action } => action.into(),
        action => action,
    }
}

/// Returns an example TOML configuration string
///
/// This function provides a template for creating new `secretspec.toml` files,
/// showing the recommended structure and commenting conventions.
///
/// # Returns
///
/// A static string containing an example TOML configuration
fn get_example_toml() -> &'static str {
    r#"# DATABASE_URL = { description = "Database connection string", required = true }

# [profiles.development]
# Development profile inherits all secrets from default profile
# Only define secrets here that need different values or settings than default
# DATABASE_URL = { default = "sqlite:///dev.db" }
#
# New secrets
# REDIS_URL = { description = "Redis connection URL for caching", required = false, default = "redis://localhost:6379" }
"#
}

/// Builds a copyable POSIX-shell command for importing discovered values.
fn migration_command(from: &str, profile: &str) -> String {
    let from = crate::secrets::shell_single_quote(from);
    if profile == "default" {
        format!("secretspec import {from}")
    } else {
        let profile = crate::secrets::shell_single_quote(profile);
        format!("SECRETSPEC_PROFILE={profile} secretspec import {from}")
    }
}

/// Generates a `secretspec.toml` document from a [`Config`] with helpful comments.
///
/// String values and keys are serialized through `toml_edit`, so anything that
/// needs quoting or escaping (a description containing a double-quote, a secret
/// name containing a dot, a control character, ...) is emitted as valid,
/// round-trippable TOML rather than hand-interpolated. Secrets are written as
/// inline tables and profiles/secrets are sorted for deterministic output, while
/// instructional comments are preserved for users editing the file by hand.
///
/// # Arguments
///
/// * `config` - The project configuration to serialize
///
/// # Returns
///
/// A TOML string with the configuration and helpful comments
///
/// # Errors
///
/// Returns an error if the configuration cannot be serialized
fn generate_toml_with_comments(config: &Config) -> crate::Result<String> {
    use toml_edit::{Array, DocumentMut, InlineTable, Item, Table, Value};

    let mut doc = DocumentMut::new();

    // [project]
    let mut project = Table::new();
    project.insert("name", toml_edit::value(config.project.name.as_str()));
    project.insert(
        "revision",
        toml_edit::value(config.project.revision.as_str()),
    );
    if let Some(extends) = &config.project.extends {
        let mut arr = Array::new();
        for entry in extends {
            arr.push(entry.as_str());
        }
        project.insert("extends", toml_edit::value(arr));
    }
    doc.insert("project", Item::Table(project));

    // [profiles.<name>] tables, each secret an inline table. Sorted so the output
    // is deterministic regardless of the source HashMap ordering.
    let mut profiles = Table::new();
    profiles.set_implicit(true);

    let mut profile_names: Vec<&String> = config.profiles.keys().collect();
    profile_names.sort();

    for (index, profile_name) in profile_names.iter().enumerate() {
        let profile_config = &config.profiles[*profile_name];
        let mut profile_table = Table::new();

        for secret_name in profile_config.sorted_secret_names() {
            let secret_config = &profile_config.secrets[&secret_name];
            let mut inline = InlineTable::new();
            inline.insert(
                "description",
                Value::from(secret_config.description.as_deref().unwrap_or("")),
            );
            if let Some(required) = secret_config.required {
                inline.insert("required", Value::from(required));
            } else if secret_config.at_least_one.is_some() || secret_config.exactly_one.is_some() {
                let mut groups = InlineTable::new();
                for (name, memberships) in [
                    ("at_least_one", &secret_config.at_least_one),
                    ("exactly_one", &secret_config.exactly_one),
                ] {
                    let Some(memberships) = memberships else {
                        continue;
                    };
                    let value = match memberships.as_slice() {
                        [membership] => Value::from(membership.as_str()),
                        memberships => {
                            let mut array = Array::new();
                            for membership in memberships {
                                array.push(membership.as_str());
                            }
                            Value::Array(array)
                        }
                    };
                    groups.insert(name, value);
                }
                inline.insert("required", Value::InlineTable(groups));
            }
            if let Some(default) = &secret_config.default {
                inline.insert("default", Value::from(default.as_str()));
            }
            if let Some(composed) = &secret_config.composed {
                inline.insert("composed", Value::from(composed.as_str()));
            }
            profile_table.insert(&secret_name, toml_edit::value(inline));
        }

        // Surface the `extends` option as a comment before the first profile,
        // unless the project already declares an explicit `extends`.
        if index == 0 && config.project.extends.is_none() {
            profile_table.decor_mut().set_prefix(
                "\n# Extend configurations from subdirectories\n# extends = [ \"subdir1\", \"subdir2\" ]\n\n",
            );
        }

        profiles.insert(profile_name.as_str(), Item::Table(profile_table));
    }
    doc.insert("profiles", Item::Table(profiles));

    Ok(doc.to_string())
}

/// Rejects names that cannot occupy a flattened secret key in [`Profile`].
fn validate_add_secret_name(name: &str) -> Result<()> {
    if !crate::config::is_valid_identifier(name) {
        return Err(miette!(
            "Invalid secret name '{}': must be a valid identifier (alphanumeric and underscores, not starting with a number)",
            name
        ));
    }
    // `Profile` reserves this key for its defaults table before flattening all
    // remaining keys into secret declarations. Without an explicit check, the
    // edit would be valid TOML but would not actually declare a secret.
    if name == "defaults" {
        return Err(miette!(
            "Secret name 'defaults' is reserved for profile defaults"
        ));
    }
    Ok(())
}

/// Ensures `add` will create a new effective declaration in an existing profile.
fn validate_add_target(app: &Secrets, profile: &str, name: &str) -> Result<()> {
    validate_add_secret_name(name)?;

    if !app.config().profiles.contains_key(profile) {
        let mut available: Vec<&str> = app.config().profiles.keys().map(String::as_str).collect();
        available.sort_unstable();
        return Err(miette!(
            "Profile '{}' is not defined in secretspec.toml. Available profiles: {}",
            profile,
            available.join(", ")
        ));
    }
    if app.resolve_secret_config(name, Some(profile)).is_some() {
        return Err(miette!(
            "Secret '{}' is already declared for profile '{}'",
            name,
            profile
        ));
    }

    Ok(())
}

/// Adds one secret to a manifest document without re-serializing the rest.
///
/// `toml_edit` retains the user's comments, whitespace, ordering, and any syntax
/// that is not represented by [`Config`]. The caller validates the selected
/// profile against the fully loaded configuration first; this helper creates a
/// local profile table when that profile currently comes only from `extends`.
fn add_secret_to_manifest(
    source: &str,
    profile: &str,
    name: &str,
    description: &str,
) -> Result<String> {
    use toml_edit::{DocumentMut, InlineTable, Item, Table, Value};

    validate_add_secret_name(name)?;
    if description.trim().is_empty() {
        return Err(miette!("Secret description cannot be empty"));
    }

    let mut doc = source
        .parse::<DocumentMut>()
        .into_diagnostic()
        .wrap_err("Failed to parse secretspec.toml for editing")?;
    let profiles = doc
        .get_mut("profiles")
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| miette!("secretspec.toml does not contain a [profiles] table"))?;

    if !profiles.contains_key(profile) {
        profiles.insert(profile, Item::Table(Table::new()));
    }
    let profile_table = profiles
        .get_mut(profile)
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| miette!("Profile '{}' is not a TOML table", profile))?;

    if profile_table.contains_key(name) {
        return Err(miette!(
            "Secret '{}' is already declared in profile '{}'",
            name,
            profile
        ));
    }

    let mut secret = InlineTable::new();
    secret.insert("description", Value::from(description));
    profile_table.insert(name, toml_edit::value(secret));

    Ok(doc.to_string())
}

/// Replaces an existing manifest only after its complete replacement has been
/// written and flushed to a temporary file in the same directory.
fn replace_manifest_atomically(
    path: &Path,
    write: impl FnOnce(&mut fs::File) -> std::io::Result<()>,
) -> Result<()> {
    let metadata = fs::metadata(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("Failed to read permissions for {}", path.display()))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::Builder::new()
        .prefix(".secretspec-")
        .tempfile_in(parent)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "Failed to create a temporary manifest next to {}",
                path.display()
            )
        })?;

    write(temporary.as_file_mut())
        .into_diagnostic()
        .wrap_err_with(|| format!("Failed to write temporary manifest for {}", path.display()))?;
    temporary
        .flush()
        .into_diagnostic()
        .wrap_err_with(|| format!("Failed to flush temporary manifest for {}", path.display()))?;
    temporary
        .as_file()
        .set_permissions(metadata.permissions())
        .into_diagnostic()
        .wrap_err_with(|| format!("Failed to preserve permissions for {}", path.display()))?;
    temporary
        .as_file()
        .sync_all()
        .into_diagnostic()
        .wrap_err_with(|| format!("Failed to sync temporary manifest for {}", path.display()))?;
    temporary.persist(path).map_err(|error| {
        miette!(
            "Failed to atomically replace {}: {}",
            path.display(),
            error.error
        )
    })?;

    Ok(())
}

fn write_manifest_atomically(path: &Path, contents: &str) -> Result<()> {
    replace_manifest_atomically(path, |temporary| temporary.write_all(contents.as_bytes()))
}

/// Quotes one argument for copying into a POSIX-compatible shell.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn add_follow_up_command(name: &str, profile: &str, file: Option<&Path>) -> String {
    let mut command = format!("secretspec set {name} --profile {}", shell_quote(profile));
    if let Some(path) = file {
        command.push_str(" --file ");
        command.push_str(&shell_quote(&path.to_string_lossy()));
    }
    command
}

/// Loads secrets using an explicit path or auto-detection, applying the optional
/// session reason (from `--reason`/`SECRETSPEC_REASON`).
fn load_secrets(file: &Option<PathBuf>, reason: &Option<String>) -> miette::Result<Secrets> {
    let mut secrets = match file {
        Some(path) => Secrets::load_from(path),
        None => Secrets::load(),
    }
    .into_diagnostic()
    .wrap_err("Failed to load secretspec configuration")?;

    // Destination previews are CLI presentation. The core computes the
    // provider-specific metadata and invokes this observer only when a CLI
    // caller installs it; SDK/library writes remain free of preview output.
    secrets.set_write_target_reporter(|target| {
        eprintln!(
            "Writing secret '{}' to {} (profile: {})\n  target: {}",
            target.name, target.provider_uri, target.profile, target.target
        );
    });

    Ok(match reason {
        Some(reason) => secrets.with_reason(reason.clone()),
        None => secrets,
    })
}

/// Applies a `--scope` selection to `app`. Clap resolves the flag and its
/// `SECRETSPEC_SCOPE` fallback into the same `Option`, so `None` here means
/// neither was given.
///
/// A **blank** value is the caller opting out explicitly, not an absent one: it
/// selects no scope *and* suppresses the library's ambient `SECRETSPEC_SCOPE`
/// fallback, so `--scope ""` clears an inherited scope instead of silently
/// deferring to it. Dropping the blank on its own would not be enough — the
/// library would read the environment and narrow the operation anyway, which is
/// the one direction a blank must never take (CI templates and workflow `env:`
/// maps routinely materialize an unset value as an empty string).
fn apply_scope(app: &mut Secrets, scope: Option<String>) {
    let Some(scope) = scope else {
        return;
    };
    if scope.trim().is_empty() {
        app.set_ignore_ambient_scope(true);
    } else {
        app.set_scope(scope);
    }
}

/// Resolves an explicitly supplied config-init provider or prompts for one.
///
/// Explicit values are checked against the same provider registry used for
/// runtime provider construction, without constructing a provider or doing I/O.
fn select_config_init_provider(provider: Option<String>) -> Result<String> {
    if let Some(provider) = provider {
        let provider = provider.trim();
        if provider.is_empty() {
            return Err(miette!("Provider backend cannot be empty"));
        }
        if !spec_names_known_provider(provider).into_diagnostic()? {
            let mut available: Vec<_> = providers().into_iter().map(|info| info.name).collect();
            available.sort_unstable();
            return Err(miette!(
                "Provider backend '{}' not found. Available providers: {}",
                provider,
                available.join(", ")
            ));
        }
        if provider.split(':').next() == Some("file") {
            Box::<dyn Provider>::try_from(provider).into_diagnostic()?;
        }
        return Ok(provider.to_string());
    }

    use inquire::Select;

    let provider_choices: Vec<String> = providers()
        .into_iter()
        .map(|info| info.display_with_examples())
        .collect();
    let selected_choice = Select::new("Select your preferred provider backend:", provider_choices)
        .prompt()
        .into_diagnostic()?;

    let selected_provider = selected_choice
        .split(':')
        .next()
        .unwrap_or("keyring")
        .to_string();

    if selected_provider == "file" {
        use inquire::Text;

        let directory = Text::new("File provider root directory:")
            .with_help_message("Use a relative path such as ./.secrets or an absolute path")
            .prompt()
            .into_diagnostic()?;
        let spec = format!("file:{}", directory.trim());
        Box::<dyn Provider>::try_from(spec.as_str())
            .into_diagnostic()
            .wrap_err("Invalid file provider configuration")?;
        Ok(spec)
    } else {
        Ok(selected_provider)
    }
}

/// Resolves an explicitly supplied config-init profile or prompts for one.
fn select_config_init_profile(profile: Option<String>) -> Result<Option<String>> {
    if let Some(profile) = profile {
        let profile = profile.trim();
        if profile.is_empty() {
            return Err(miette!(
                "Default profile cannot be empty; use 'none' to clear it"
            ));
        }
        return Ok((profile != "none").then(|| profile.to_string()));
    }

    use inquire::Select;

    let profiles = vec!["development", "default", "none"];
    let profile_choice = Select::new("Select your default profile:", profiles)
        .with_help_message("'development' is recommended for local development environments")
        .prompt()
        .into_diagnostic()?;

    Ok((profile_choice != "none").then(|| profile_choice.to_string()))
}

/// Main entry point for the secretspec CLI application.
///
/// Parses command-line arguments and executes the appropriate command.
/// All commands are delegated to the SecretSpec library for processing.
///
/// # Returns
///
/// * `Ok(())` - If the command executed successfully
/// * `Err` - If any error occurred during execution
#[doc(hidden)]
pub fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        // Initialize a new secretspec.toml configuration file
        Commands::Init {
            from,
            project,
            profile,
        } => {
            // Check if secretspec.toml already exists
            if PathBuf::from("secretspec.toml").exists() {
                use inquire::Confirm;
                let overwrite = Confirm::new("secretspec.toml already exists. Overwrite?")
                    .with_default(false)
                    .prompt()
                    .into_diagnostic()?;

                if !overwrite {
                    println!("Cancelled.");
                    return Ok(());
                }
            }

            let project_name = match project {
                Some(project) => project,
                None => std::env::current_dir()
                    .into_diagnostic()?
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
            };
            if project_name.is_empty() {
                return Err(miette!("init project cannot be empty"));
            }
            if profile.is_empty() {
                return Err(miette!("init profile cannot be empty"));
            }

            // Create provider from the specification string.
            let provider: Box<dyn Provider> = from.as_str().try_into().into_diagnostic()?;

            // Discover declarations in the namespace the new manifest will use.
            let secrets = provider
                .reflect(crate::DiscoveryContext::new(&project_name, &profile))
                .into_diagnostic()?;

            // Create a new project config
            let mut profiles = HashMap::new();
            profiles.insert(
                profile.clone(),
                Profile {
                    defaults: None,
                    secrets,
                },
            );

            let project_config = Config {
                project: Project {
                    name: project_name,
                    ..Default::default()
                },
                profiles,
                providers: None,
                scopes: None,
            };
            let mut content = generate_toml_with_comments(&project_config).into_diagnostic()?;

            // Append comprehensive example
            content.push_str(get_example_toml());

            fs::write("secretspec.toml", content).into_diagnostic()?;

            // Set file permissions to 600 (owner read/write only) on Unix systems
            #[cfg(unix)]
            {
                let metadata = fs::metadata("secretspec.toml").into_diagnostic()?;
                let mut permissions = metadata.permissions();
                permissions.set_mode(0o600);
                fs::set_permissions("secretspec.toml", permissions).into_diagnostic()?;
            }

            let secret_count = project_config
                .profiles
                .values()
                .map(|p| p.secrets.len())
                .sum::<usize>();
            println!("✓ Created secretspec.toml with {} secrets", secret_count);

            // If we discovered a populated provider, explain how to copy its
            // values after reviewing the declarations.
            if secret_count > 0 {
                println!("\nTo migrate your secrets from {}:", from);
                println!("  1. Review secretspec.toml and adjust as needed");
                println!(
                    "  2. {}    # Import secret values",
                    migration_command(&from, &profile)
                );
            }

            println!("\nNext steps:");
            println!("  1. secretspec config global init    # Set up user defaults (0.17+)");
            println!("  2. secretspec check          # Verify all secrets and set them");
            println!("  3. secretspec run -- your-command  # Run with secrets");

            Ok(())
        }
        Commands::Add {
            name,
            description,
            profile,
        } => {
            let app = load_secrets(&cli.file, &cli.reason)?;
            let profile = app.resolve_profile_name(profile.as_deref());
            validate_add_target(&app, &profile, &name)?;

            let description = match description {
                Some(description) => description,
                None => inquire::Text::new(&format!("Description for {name}:"))
                    .prompt()
                    .into_diagnostic()?,
            };
            let description = description.trim();
            if description.is_empty() {
                return Err(miette!("Secret description cannot be empty"));
            }

            let manifest_path = match &cli.file {
                Some(path) => path.clone(),
                None => crate::secrets::find_config_file().into_diagnostic()?,
            };
            let source = fs::read_to_string(&manifest_path)
                .into_diagnostic()
                .wrap_err_with(|| format!("Failed to read {}", manifest_path.display()))?;
            let updated = add_secret_to_manifest(&source, &profile, &name, description)?;
            write_manifest_atomically(&manifest_path, &updated)?;

            println!(
                "✓ Added secret '{}' to profile '{}' in {}",
                name,
                profile,
                manifest_path.display()
            );
            println!(
                "Set its value with: {}",
                add_follow_up_command(&name, &profile, cli.file.as_deref())
            );
            Ok(())
        }
        // Handle configuration management commands
        Commands::Config { action } => match normalize_config_action(action) {
            ConfigAction::Global { .. } => unreachable!("global action was normalized"),
            // Initialize user configuration, prompting only for omitted values.
            ConfigAction::Init { provider, profile } => {
                let provider = select_config_init_provider(provider)?;
                let profile = select_config_init_profile(profile)?;

                // Preserve any existing config (audit settings, provider aliases)
                // rather than overwriting the whole file: re-running `config init`
                // must not silently drop a user's `[audit]` table — which would
                // re-enable disabled logging — or their saved provider aliases.
                let mut config = GlobalConfig::load().into_diagnostic()?.unwrap_or_default();
                config.defaults.provider = Some(provider);
                config.defaults.profile = profile;

                config.save().into_diagnostic()?;
                println!(
                    "\n✓ Configuration saved to {}",
                    GlobalConfig::path().into_diagnostic()?.display()
                );
                Ok(())
            }
            // Display current user configuration
            ConfigAction::Show => {
                match GlobalConfig::load().into_diagnostic()? {
                    Some(config) => {
                        println!(
                            "Configuration file: {}\n",
                            GlobalConfig::path().into_diagnostic()?.display()
                        );
                        match config.defaults.provider {
                            Some(provider) => println!("Provider: {}", provider),
                            None => println!("Provider: (none)"),
                        }
                        match config.defaults.profile {
                            Some(profile) => println!("Profile:  {}", profile),
                            None => println!("Profile:  (none)"),
                        }
                        if let Some(providers) = &config.defaults.providers {
                            println!("\nProvider Aliases:");
                            let mut aliases: Vec<_> = providers.iter().collect();
                            aliases.sort_by(|(a, _), (b, _)| a.cmp(b));
                            for (alias, uri) in aliases {
                                println!("  {} = {}", alias, uri);
                            }
                        } else {
                            println!("\nProvider Aliases: (none)");
                        }
                    }
                    None => {
                        println!(
                            "No configuration found. Run 'secretspec config global init' to create one."
                        );
                    }
                }
                Ok(())
            }
            // Manage provider aliases
            ConfigAction::Provider(action) => {
                match action {
                    ProviderAction::Add {
                        name,
                        uri,
                        credential,
                    } => {
                        // Parse each `NAME=PROVIDER` binding into a credential source.
                        let mut credentials = HashMap::new();
                        for binding in &credential {
                            let (credential_name, spec) =
                                binding.split_once('=').ok_or_else(|| {
                                    miette!("--credential expects NAME=PROVIDER, got '{binding}'")
                                })?;
                            if credential_name.is_empty() || spec.is_empty() {
                                return Err(miette!(
                                    "--credential expects a non-empty NAME=PROVIDER, got '{binding}'"
                                ));
                            }
                            credentials.insert(
                                credential_name.to_string(),
                                crate::config::CredentialSource::from(spec),
                            );
                        }
                        // An empty map keeps the compact bare-string alias form.
                        let alias_value =
                            crate::config::ProviderAlias::leaf(uri.clone(), credentials);

                        // Load or create config
                        let mut config =
                            GlobalConfig::load()
                                .into_diagnostic()?
                                .unwrap_or(GlobalConfig {
                                    defaults: GlobalDefaults {
                                        provider: None,
                                        profile: None,
                                        providers: None,
                                    },
                                    audit: None,
                                });

                        // Initialize providers map if needed
                        if config.defaults.providers.is_none() {
                            config.defaults.providers = Some(HashMap::new());
                        }

                        // Add or update the provider alias
                        if let Some(providers) = &mut config.defaults.providers {
                            let display = providers
                                .insert(name.clone(), alias_value)
                                .map_or("added", |_| "updated");
                            config.save().into_diagnostic()?;
                            println!("✓ Provider alias '{name}' {display}: '{uri}'");
                            if !credential.is_empty() {
                                println!("  credentials: {}", credential.join(", "));
                                println!(
                                    "  run 'secretspec config provider login {name}' to store the credentials"
                                );
                            }
                        }
                        Ok(())
                    }
                    ProviderAction::Remove { name } => {
                        // Load config
                        match GlobalConfig::load().into_diagnostic()? {
                            Some(mut config) => {
                                if let Some(providers) = &mut config.defaults.providers {
                                    if providers.remove(&name).is_some() {
                                        config.save().into_diagnostic()?;
                                        println!("✓ Provider alias '{}' removed", name);
                                    } else {
                                        println!("✗ Provider alias '{}' not found", name);
                                    }
                                } else {
                                    println!("✗ No provider aliases configured");
                                }
                            }
                            None => {
                                println!(
                                    "✗ No configuration found. Run 'secretspec config global init' first."
                                );
                            }
                        }
                        Ok(())
                    }
                    ProviderAction::List => {
                        match GlobalConfig::load().into_diagnostic()? {
                            Some(config) => {
                                if let Some(providers) = config.defaults.providers {
                                    if providers.is_empty() {
                                        println!("No provider aliases configured.");
                                    } else {
                                        println!("Provider Aliases:");
                                        let mut aliases: Vec<_> = providers.into_iter().collect();
                                        aliases.sort_by(|(a, _), (b, _)| a.cmp(b));
                                        for (alias, uri) in aliases {
                                            println!("  {} = {}", alias, uri);
                                        }
                                    }
                                } else {
                                    println!("No provider aliases configured.");
                                }
                            }
                            None => {
                                println!(
                                    "No configuration found. Run 'secretspec config global init' first."
                                );
                            }
                        }
                        Ok(())
                    }
                    ProviderAction::Login { name } => {
                        let app = load_secrets(&cli.file, &cli.reason)?;
                        let credentials =
                            app.declared_provider_credentials(&name).into_diagnostic()?;
                        if credentials.is_empty() {
                            println!("Provider alias '{name}' declares no credentials.");
                            return Ok(());
                        }
                        for (credential_name, source) in credentials {
                            let entered = inquire::Password::new(&format!(
                                "Enter {credential_name} for provider '{name}' (source: {}):",
                                source.display_provider()
                            ))
                            .without_confirmation()
                            .prompt()
                            .into_diagnostic()?;
                            if entered.is_empty() {
                                println!("✗ Skipped {credential_name} (empty)");
                                continue;
                            }
                            let location = app
                                .store_provider_credential(
                                    &source,
                                    &credential_name,
                                    &secrecy::SecretString::new(entered.into()),
                                )
                                .into_diagnostic()?;
                            println!("✓ stored {credential_name} in {location}");
                        }
                        println!(
                            "\nRun 'secretspec check --provider {name}' to verify authentication."
                        );
                        Ok(())
                    }
                }
            }
        },
        // Set a secret value in the specified provider
        Commands::Set {
            name,
            value,
            provider,
            profile,
        } => {
            let mut app = load_secrets(&cli.file, &cli.reason)?;
            if let Some(p) = provider {
                app.set_provider(p);
            }
            if let Some(p) = profile {
                app.set_profile(p);
            }
            app.set(&name, value)
                .into_diagnostic()
                .wrap_err("Failed to set secret")?;
            Ok(())
        }
        // Retrieve and display a secret value
        Commands::Get {
            name,
            provider,
            profile,
        } => {
            let mut app = load_secrets(&cli.file, &cli.reason)?;
            if let Some(p) = provider {
                app.set_provider(p);
            }
            if let Some(p) = profile {
                app.set_profile(p);
            }
            app.get(&name)
                .into_diagnostic()
                .wrap_err("Failed to get secret")?;
            Ok(())
        }
        Commands::Delete {
            mut names,
            all,
            yes,
            provider,
            profile,
        } => {
            let mut app = load_secrets(&cli.file, &cli.reason)?;
            if let Some(provider) = provider {
                app.set_provider(provider);
            }
            if let Some(profile) = profile {
                app.set_profile(profile);
            }

            if all {
                names = app
                    .profile_secret_names_unscoped(None)
                    .into_diagnostic()
                    .wrap_err("Failed to list secrets for deletion")?;
                // Composed secrets have no stored value. An explicit name gets
                // a useful error from `Secrets::delete`; a whole-profile sweep
                // simply has nothing to do for them.
                names.retain(|name| {
                    app.resolve_secret_config(name, None)
                        .is_some_and(|secret| secret.composed.is_none())
                });
            } else {
                // Repeating a name should not turn the second occurrence into a
                // confusing "already absent" result.
                let mut seen = HashSet::new();
                names.retain(|name| seen.insert(name.clone()));
            }

            if all && !yes && !names.is_empty() {
                if !std::io::stdin().is_terminal() {
                    return Err(miette!(
                        "refusing to delete all stored secret values without confirmation; pass --yes for non-interactive use"
                    ));
                }
                use inquire::Confirm;
                let profile = app.resolve_profile_name(None);
                let confirmed = Confirm::new(&format!(
                    "Delete {} stored secret {} from profile '{profile}'?",
                    names.len(),
                    if names.len() == 1 { "value" } else { "values" }
                ))
                .with_default(false)
                .prompt()
                .into_diagnostic()?;
                if !confirmed {
                    println!("Cancelled.");
                    return Ok(());
                }
            }

            let mut deleted = 0;
            let mut absent = 0;
            let mut failures = Vec::new();
            for name in names {
                match app.delete(&name) {
                    Ok(true) => {
                        println!("Deleted '{name}'");
                        deleted += 1;
                    }
                    Ok(false) => {
                        println!("'{name}' was already absent");
                        absent += 1;
                    }
                    Err(error) => failures.push((name, error.to_string())),
                }
            }

            println!(
                "Deleted {deleted} secret {}; {absent} already absent",
                if deleted == 1 { "value" } else { "values" }
            );
            if !failures.is_empty() {
                return Err(miette!(
                    "{} secret {} could not be deleted: {}",
                    failures.len(),
                    if failures.len() == 1 {
                        "value"
                    } else {
                        "values"
                    },
                    failures
                        .into_iter()
                        .map(|(name, error)| format!("'{name}': {error}"))
                        .collect::<Vec<_>>()
                        .join("; ")
                ));
            }
            Ok(())
        }
        // Execute a command with secrets injected as environment variables
        Commands::Run {
            command,
            provider,
            profile,
            scope,
        } => {
            let mut app = load_secrets(&cli.file, &cli.reason)?;
            if let Some(p) = provider {
                app.set_provider(p);
            }
            if let Some(p) = profile {
                app.set_profile(p);
            }
            apply_scope(&mut app, scope);
            app.run(command)
                .into_diagnostic()
                .wrap_err("Failed to run command")?;
            Ok(())
        }
        // Resolve secrets and print them without running a command
        Commands::Export {
            provider,
            profile,
            scope,
            format,
        } => {
            let mut app = load_secrets(&cli.file, &cli.reason)?;
            if let Some(p) = provider {
                app.set_provider(p);
            }
            if let Some(p) = profile {
                app.set_profile(p);
            }
            apply_scope(&mut app, scope);
            let mut out = std::io::stdout().lock();
            app.export(format, &mut out)
                .into_diagnostic()
                .wrap_err("Failed to export secrets")?;
            Ok(())
        }
        // Verify all required secrets are available
        Commands::Check {
            provider,
            profile,
            scope,
            no_prompt,
            json,
            explain,
        } => {
            let mut app = load_secrets(&cli.file, &cli.reason)?;
            if let Some(p) = provider {
                app.set_provider(p);
            }
            if let Some(p) = profile {
                app.set_profile(p);
            }
            apply_scope(&mut app, scope);

            // `--json`/`--explain` surface the value-free resolution report
            // instead of the interactive prompt-for-missing flow. They report
            // on every declared secret (including missing required ones) and
            // exit non-zero when a required secret is missing, so CI can gate.
            if json || explain {
                // Value-free report: never mints, stores, or writes a secret as
                // a side effect of this read-only preflight (unlike `validate()`,
                // which is the value-injecting path).
                let report = app
                    .report()
                    .into_diagnostic()
                    .wrap_err("Failed to resolve secrets")?;

                if json {
                    let rendered = serde_json::to_string_pretty(&report)
                        .into_diagnostic()
                        .wrap_err("Failed to serialize resolution report")?;
                    println!("{}", rendered);
                } else {
                    print!("{}", report.to_explain_string());
                }

                if !report.all_required_present() {
                    std::process::exit(1);
                }
                return Ok(());
            }

            let mut validated = app
                .check(no_prompt)
                .into_diagnostic()
                .wrap_err("Failed to check secrets")?;
            // Persist temp files so they outlive the command
            validated
                .keep_temp_files()
                .into_diagnostic()
                .wrap_err("Failed to persist temporary files")?;
            Ok(())
        }
        // Generate typed accessors for another language (value-free)
        Commands::Schema { profile, output } => {
            let app = load_secrets(&cli.file, &cli.reason)?;
            let ir = crate::codegen::build_ir(app.config());
            let schema = crate::codegen::schema::emit(&ir, profile.as_deref())
                .map_err(|e| miette!("{e}"))?;
            match output {
                Some(path) => fs::write(&path, schema)
                    .into_diagnostic()
                    .wrap_err_with(|| format!("Failed to write {}", path.display()))?,
                None => print!("{}", schema),
            }
            Ok(())
        }
        Commands::Completions { shell } => {
            generate_completions(shell, &mut std::io::stdout().lock());
            Ok(())
        }
        // Import secrets from one provider to another
        Commands::Import {
            from_provider,
            delete_source,
        } => {
            let app = load_secrets(&cli.file, &cli.reason)?;
            if delete_source {
                app.import_with_delete_source(&from_provider)
                    .into_diagnostic()
                    .wrap_err("Failed to import and delete source secrets")?;
            } else {
                app.import(&from_provider)
                    .into_diagnostic()
                    .wrap_err("Failed to import secrets")?;
            }
            Ok(())
        }
        Commands::Cache { action } => match action {
            CacheAction::Clear { name, profile } => {
                let mut app = load_secrets(&cli.file, &cli.reason)?;
                if let Some(profile) = profile {
                    app.set_profile(profile);
                }
                let cleared = app
                    .clear_cache(name.as_deref())
                    .into_diagnostic()
                    .wrap_err("Failed to clear cache")?;
                println!(
                    "Cleared {cleared} cache {}",
                    if cleared == 1 { "entry" } else { "entries" }
                );
                Ok(())
            }
        },
        // Show the local audit log
        Commands::Audit {
            project,
            action,
            tail,
            json,
        } => show_audit_log(project, action, tail, json),
    }
}

/// Reads and prints the local audit log, applying optional filters.
fn show_audit_log(
    project: Option<String>,
    action: Option<String>,
    tail: Option<usize>,
    json: bool,
) -> Result<()> {
    let audit = GlobalConfig::load()
        .into_diagnostic()
        .wrap_err("Failed to load global configuration")?
        .and_then(|g| g.audit)
        .unwrap_or_default();

    let path = audit.resolved_path().ok_or_else(|| {
        if audit.has_relative_path() {
            miette!(
                "[audit] path {} is not absolute; set an absolute path in ~/.config/secretspec/config.toml",
                audit.path.as_deref().map(|p| p.display().to_string()).unwrap_or_default()
            )
        } else {
            miette!("Could not determine the audit log location")
        }
    })?;

    if !path.exists() {
        eprintln!("No audit log found at {}", path.display());
        return Ok(());
    }

    let content = fs::read_to_string(&path)
        .into_diagnostic()
        .wrap_err_with(|| format!("Failed to read audit log at {}", path.display()))?;

    for (line, value) in filter_audit_entries(&content, project.as_deref(), action.as_deref(), tail)
    {
        if json {
            println!("{line}");
        } else {
            println!("{}", format_audit_line(&value));
        }
    }

    Ok(())
}

/// Parses the audit log, keeps the entries matching the optional `project` and
/// `action` filters, then retains only the last `tail` of them. Each surviving
/// entry is returned as its raw line text (for `--json`) paired with its parsed
/// JSON value (for formatting). A line that is not valid JSON — e.g. a torn write
/// — is dropped, so it never reaches output. Pure (no I/O) so it can be tested.
fn filter_audit_entries<'a>(
    content: &'a str,
    project: Option<&str>,
    action: Option<&str>,
    tail: Option<usize>,
) -> Vec<(&'a str, serde_json::Value)> {
    let mut entries: Vec<(&str, serde_json::Value)> = content
        .lines()
        .filter_map(|line| {
            let v = serde_json::from_str::<serde_json::Value>(line).ok()?;
            let field = |k: &str| v.get(k).and_then(|x| x.as_str());
            if let Some(p) = project
                && field("project") != Some(p)
            {
                return None;
            }
            // Actions serialize lowercase (`get`/`set`/...); match case-insensitively
            // so `--action Get` is not silently dropped. (`project` stays exact: a
            // project name is an identity, not an enum.)
            if let Some(a) = action
                && !field("action").is_some_and(|x| x.eq_ignore_ascii_case(a))
            {
                return None;
            }
            Some((line, v))
        })
        .collect();

    if let Some(n) = tail
        && entries.len() > n
    {
        entries.drain(0..entries.len() - n);
    }

    entries
}

/// Renders control characters in a field harmlessly so caller controlled audit
/// content (reason, command, key, ...) cannot inject escape sequences that
/// erase, overwrite, or forge lines in the formatted `secretspec audit` view.
///
/// ASCII control bytes (0x00..=0x1F) and DEL (0x7F) are replaced with a visible
/// `\xNN` rendering; all other characters pass through unchanged so normal
/// entries look identical.
fn sanitize_field(s: &str) -> String {
    if !s.chars().any(|c| c.is_control()) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() {
            out.push_str(&format!("\\x{:02x}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// Renders one parsed JSON Lines audit entry as a readable, colored summary line.
/// The value has already been validated as JSON by `show_audit_log`.
fn format_audit_line(v: &serde_json::Value) -> String {
    use colored::Colorize;

    let str_field = |k: &str| v.get(k).and_then(|x| x.as_str());

    let ts = sanitize_field(str_field("ts").unwrap_or(""));
    let action = sanitize_field(str_field("action").unwrap_or("?"));
    let outcome = sanitize_field(str_field("outcome").unwrap_or("?"));
    let project = sanitize_field(str_field("project").unwrap_or(""));
    let profile = sanitize_field(str_field("profile").unwrap_or(""));
    let scope = str_field("scope").map(sanitize_field);

    let target = if let Some(key) = str_field("key") {
        sanitize_field(key)
    } else if let Some(arr) = v.get("keys").and_then(|x| x.as_array()) {
        arr.iter()
            .filter_map(|x| x.as_str())
            .map(sanitize_field)
            .collect::<Vec<_>>()
            .join(",")
    } else {
        String::new()
    };

    let outcome_colored = match outcome.as_str() {
        "found" | "written" | "started" => outcome.green(),
        "missing" | "error" => outcome.red(),
        _ => outcome.yellow(),
    };

    let mut s = format!("{}  {:<6} {}", ts.dimmed(), action.bold(), outcome_colored);
    if let Some(cmd) = str_field("command") {
        s += &format!("  {}", sanitize_field(cmd).bold());
    }
    if !target.is_empty() {
        s += &format!("  {target}");
    }
    s += &format!("  ({project}/{profile}");
    if let Some(scope) = scope {
        s += &format!(" scope:{scope}");
    }
    if let Some(provider) = str_field("provider") {
        s += &format!(" via {}", sanitize_field(provider));
    }
    s += ")";
    if let Some(reason) = str_field("reason") {
        s += &format!("  reason: {}", sanitize_field(reason).italic());
    }
    if let Some(agent) = v
        .get("actor")
        .and_then(|a| a.get("agent"))
        .and_then(|x| x.as_str())
    {
        s += &format!("  [{}]", sanitize_field(agent));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Secret;

    /// Builds a Config with a single secret named `S` under the `default` profile.
    fn config_with_secret(secret: Secret) -> Config {
        let mut secrets = HashMap::new();
        secrets.insert("S".to_string(), secret);
        Config {
            project: Project {
                name: "myproj".to_string(),
                ..Default::default()
            },
            profiles: HashMap::from([(
                "default".to_string(),
                Profile {
                    defaults: None,
                    secrets,
                },
            )]),
            providers: None,
            scopes: None,
        }
    }

    /// Clap folds `--scope` and its `SECRETSPEC_SCOPE` fallback into one
    /// `Option`, so a blank value must mean "no scope" rather than "no opinion".
    /// Dropping it and letting the library re-read the environment would narrow
    /// the operation and scrub the excluded secrets, which is exactly what an
    /// operator writing `--scope ""` is trying to prevent.
    #[test]
    fn a_blank_scope_clears_an_ambient_one() {
        let _env = crate::tests::scrub_resolution_env();
        let _ambient = crate::tests::EnvVarGuard::set("SECRETSPEC_SCOPE", "api");
        let config = config_with_secret(Secret::default());

        // Control: nothing applied, so the ambient scope is in force.
        let inherited = Secrets::new(config.clone(), None, None, None);
        assert_eq!(inherited.resolve_scope_name(None).as_deref(), Some("api"));

        // A blank `--scope` (or a blank `SECRETSPEC_SCOPE`) selects nothing and
        // suppresses the ambient fallback.
        let mut blank = Secrets::new(config.clone(), None, None, None);
        apply_scope(&mut blank, Some("   ".to_string()));
        assert_eq!(blank.resolve_scope_name(None), None);

        // An absent flag leaves the ambient scope alone, and an explicit one wins.
        let mut absent = Secrets::new(config.clone(), None, None, None);
        apply_scope(&mut absent, None);
        assert_eq!(absent.resolve_scope_name(None).as_deref(), Some("api"));

        let mut explicit = Secrets::new(config, None, None, None);
        apply_scope(&mut explicit, Some("worker".to_string()));
        assert_eq!(explicit.resolve_scope_name(None).as_deref(), Some("worker"));
    }

    #[test]
    fn sanitize_field_neutralizes_control_characters() {
        // A clean string passes through unchanged (and takes the early-return path).
        assert_eq!(sanitize_field("DATABASE_URL"), "DATABASE_URL");
        assert_eq!(sanitize_field(""), "");

        // ASCII control bytes and DEL become a visible `\xNN` rendering so a
        // caller-controlled field (reason, command, key) cannot inject an escape
        // sequence that erases or forges lines in the formatted audit view.
        assert_eq!(sanitize_field("a\nb"), "a\\x0ab");
        assert_eq!(sanitize_field("a\tb"), "a\\x09b");
        assert_eq!(sanitize_field("a\x00b"), "a\\x00b");
        assert_eq!(sanitize_field("a\x7fb"), "a\\x7fb");

        // A real ANSI clear-line sequence is defanged: the ESC byte is escaped,
        // so the literal control character no longer reaches the terminal.
        let injected = sanitize_field("ok\x1b[2Kforged");
        assert_eq!(injected, "ok\\x1b[2Kforged");
        assert!(!injected.contains('\x1b'));
    }

    /// Three audit lines for two projects/actions, used by the filter tests.
    fn sample_log() -> String {
        [
            r#"{"action":"get","project":"alpha","key":"A"}"#,
            r#"{"action":"set","project":"beta","key":"B"}"#,
            r#"{"action":"get","project":"beta","key":"C"}"#,
        ]
        .join("\n")
    }

    fn keys_of(entries: &[(&str, serde_json::Value)]) -> Vec<String> {
        entries
            .iter()
            .map(|(_, v)| v["key"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn filter_audit_entries_filters_by_project_and_action() {
        let log = sample_log();

        // No filters -> every entry, in order.
        assert_eq!(
            keys_of(&filter_audit_entries(&log, None, None, None)),
            vec!["A", "B", "C"]
        );

        // Project is matched exactly.
        assert_eq!(
            keys_of(&filter_audit_entries(&log, Some("beta"), None, None)),
            vec!["B", "C"]
        );

        // Action is matched case-insensitively, so `--action GET` still matches.
        assert_eq!(
            keys_of(&filter_audit_entries(&log, None, Some("GET"), None)),
            vec!["A", "C"]
        );

        // Both filters combine.
        assert_eq!(
            keys_of(&filter_audit_entries(&log, Some("beta"), Some("get"), None)),
            vec!["C"]
        );
    }

    #[test]
    fn filter_audit_entries_applies_tail_and_drops_invalid_lines() {
        let log = sample_log();

        // `tail` keeps only the last N (after filtering).
        assert_eq!(
            keys_of(&filter_audit_entries(&log, None, None, Some(2))),
            vec!["B", "C"]
        );
        // A tail larger than the entry count is a no-op.
        assert_eq!(
            keys_of(&filter_audit_entries(&log, None, None, Some(99))),
            vec!["A", "B", "C"]
        );

        // Non-JSON lines (e.g. a torn write) and blank lines are dropped.
        let torn = format!("{}\nnot json\n\n", sample_log());
        assert_eq!(
            keys_of(&filter_audit_entries(&torn, None, None, None)),
            vec!["A", "B", "C"]
        );
    }

    #[test]
    fn format_audit_line_renders_fields() {
        // Color is disabled so assertions are on stable plain text.
        colored::control::set_override(false);

        let single: serde_json::Value = serde_json::from_str(
            r#"{"ts":"2026-06-07T00:00:00Z","action":"get","outcome":"found",
                "project":"demo","profile":"prod","key":"DB","provider":"dotenv://.env",
                "reason":"deploy","actor":{"agent":"claude-code"}}"#,
        )
        .unwrap();
        let line = format_audit_line(&single);
        assert!(line.contains("get"));
        assert!(line.contains("found"));
        assert!(line.contains("DB"));
        assert!(line.contains("(demo/prod via dotenv://.env)"));
        assert!(line.contains("reason: deploy"));
        assert!(line.contains("[claude-code]"));

        // A bulk entry joins `keys[]` and shows the executed command.
        let bulk: serde_json::Value = serde_json::from_str(
            r#"{"ts":"t","action":"run","outcome":"started","project":"demo",
                "profile":"prod","scope":"api","keys":["A","B"],"command":"./deploy.sh"}"#,
        )
        .unwrap();
        let line = format_audit_line(&bulk);
        assert!(line.contains("./deploy.sh"));
        assert!(line.contains("A,B"));
        assert!(line.contains("(demo/prod scope:api)"));

        colored::control::unset_override();
    }

    #[test]
    fn generate_toml_quotes_dotted_secret_name_and_round_trips() {
        // dotenvy accepts keys containing dots (e.g. `FOO.BAR`). A bare TOML key
        // `FOO.BAR` would be parsed as a *dotted* (nested) key, silently losing
        // the secret; toml_edit quotes it so the name round-trips intact.
        let mut secrets = HashMap::new();
        secrets.insert(
            "FOO.BAR".to_string(),
            Secret {
                description: Some("dotted".to_string()),
                ..Default::default()
            },
        );
        let mut config = config_with_secret(Secret::default());
        config.profiles.get_mut("default").unwrap().secrets = secrets;

        let generated = generate_toml_with_comments(&config).unwrap();
        assert!(
            generated.contains("\"FOO.BAR\" = {"),
            "key must be quoted, got: {generated}"
        );
        let parsed: Config = toml::from_str(&generated).expect("must round-trip");
        assert!(parsed.profiles["default"].secrets.contains_key("FOO.BAR"));
    }

    #[test]
    fn generate_toml_emits_and_round_trips_extends() {
        let mut config = config_with_secret(Secret {
            description: Some("desc".to_string()),
            ..Default::default()
        });
        config.project.extends = Some(vec!["../shared".to_string()]);

        let generated = generate_toml_with_comments(&config).unwrap();
        let parsed: Config = toml::from_str(&generated).expect("must round-trip");
        assert_eq!(
            parsed.project.extends.as_deref(),
            Some(["../shared".to_string()].as_slice())
        );
    }

    #[test]
    fn generate_toml_round_trips_control_character() {
        // U+007F (DEL) must be escaped: TOML forbids it unescaped in a basic
        // string. toml_edit handles it; a raw byte would fail to re-parse.
        let config = config_with_secret(Secret {
            description: Some("a\u{7f}b".to_string()),
            ..Default::default()
        });
        let generated = generate_toml_with_comments(&config).unwrap();
        let parsed: Config = toml::from_str(&generated).expect("must round-trip");
        assert_eq!(
            parsed.profiles["default"].secrets["S"]
                .description
                .as_deref(),
            Some("a\u{7f}b")
        );
    }

    #[test]
    fn generate_toml_round_trips_values_with_special_chars() {
        // Description and default contain quotes, a backslash and a newline; the
        // project name contains a quote. Before escaping was added these produced
        // malformed TOML that failed to parse back.
        let config = Config {
            project: Project {
                name: "weird \"name\"".to_string(),
                ..Default::default()
            },
            profiles: HashMap::from([(
                "default".to_string(),
                Profile {
                    defaults: None,
                    secrets: HashMap::from([(
                        "DATABASE_URL".to_string(),
                        Secret {
                            description: Some("he said \"hi\"\nthen left\\".to_string()),
                            default: Some("a\"b\\c".to_string()),
                            ..Default::default()
                        },
                    )]),
                },
            )]),
            providers: None,
            scopes: None,
        };

        let generated = generate_toml_with_comments(&config).unwrap();
        let parsed: Config =
            toml::from_str(&generated).expect("generated TOML must be valid and re-parseable");

        assert_eq!(parsed.project.name, "weird \"name\"");
        let secret = &parsed.profiles["default"].secrets["DATABASE_URL"];
        assert_eq!(
            secret.description.as_deref(),
            Some("he said \"hi\"\nthen left\\")
        );
        assert_eq!(secret.default.as_deref(), Some("a\"b\\c"));
    }

    #[test]
    fn generate_toml_none_branch_emits_empty_description_and_omits_fields() {
        let out = generate_toml_with_comments(&config_with_secret(Secret::default())).unwrap();
        assert!(out.contains("S = { description = \"\" }"), "got: {out}");
        assert!(!out.contains("required = "));
        assert!(!out.contains("default = "));
    }

    #[test]
    fn generate_toml_some_branch_emits_required_and_default() {
        let secret = Secret {
            description: Some("desc".to_string()),
            required: Some(false),
            default: Some("v".to_string()),
            ..Default::default()
        };
        let out = generate_toml_with_comments(&config_with_secret(secret)).unwrap();
        assert!(out.contains(", required = false"), "got: {out}");
        assert!(out.contains(", default = \"v\""), "got: {out}");
    }

    #[test]
    fn generate_toml_emits_grouped_requiredness() {
        let secret = Secret {
            description: Some("desc".to_string()),
            at_least_one: Some(vec!["auth".to_string(), "deploy".to_string()]),
            exactly_one: Some(vec!["identity".to_string()]),
            ..Default::default()
        };
        let out = generate_toml_with_comments(&config_with_secret(secret)).unwrap();
        assert!(
            out.contains(
                "required = { at_least_one = [\"auth\", \"deploy\"], exactly_one = \"identity\" }"
            ),
            "got: {out}"
        );
        let parsed: Config = toml::from_str(&out).expect("must round-trip");
        let secret = &parsed.profiles["default"].secrets["S"];
        assert_eq!(
            secret.at_least_one.as_deref(),
            Some(["auth".to_string(), "deploy".to_string()].as_slice())
        );
        assert_eq!(
            secret.exactly_one.as_deref(),
            Some(["identity".to_string()].as_slice())
        );
    }

    #[test]
    fn generate_toml_preserves_composed_templates() {
        let out = generate_toml_with_comments(&config_with_secret(Secret {
            description: Some("dsn".to_string()),
            composed: Some("postgres://${USER}@${HOST}/db".to_string()),
            ..Default::default()
        }))
        .unwrap();
        assert!(
            out.contains(", composed = \"postgres://${USER}@${HOST}/db\""),
            "got: {out}"
        );
    }

    #[test]
    fn generated_config_with_example_template_is_valid_for_every_profile() {
        for profile in ["default", "development", "production"] {
            let mut config = config_with_secret(Secret {
                description: Some("desc".to_string()),
                ..Default::default()
            });
            if profile != "default" {
                let declarations = config.profiles.remove("default").unwrap();
                config.profiles.insert(profile.to_string(), declarations);
            }

            let mut out = generate_toml_with_comments(&config).unwrap();
            out.push_str(get_example_toml());

            let parsed: Config = toml::from_str(&out)
                .unwrap_or_else(|error| panic!("init output for {profile} must parse: {error}"));
            parsed
                .validate()
                .unwrap_or_else(|error| panic!("init output for {profile} must validate: {error}"));
            assert_eq!(parsed.profiles.len(), 1);
            assert!(parsed.profiles.contains_key(profile));
        }
    }

    #[test]
    fn migration_command_shell_quotes_provider_and_profile() {
        assert_eq!(
            migration_command(
                "awsps://us-east-1?template=/{profile}/{project}/{key}&tier=advanced",
                "default"
            ),
            "secretspec import 'awsps://us-east-1?template=/{profile}/{project}/{key}&tier=advanced'"
        );
        assert_eq!(
            migration_command("dotenv://.env production", "team's production"),
            "SECRETSPEC_PROFILE='team'\\''s production' secretspec import 'dotenv://.env production'"
        );
    }

    #[test]
    fn cli_command_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn completions_accept_every_supported_shell() {
        let cases = [
            ("bash", CompletionShell::Bash),
            ("elvish", CompletionShell::Elvish),
            ("fish", CompletionShell::Fish),
            ("nushell", CompletionShell::Nushell),
            ("powershell", CompletionShell::PowerShell),
            ("zsh", CompletionShell::Zsh),
        ];

        for (name, expected) in cases {
            let cli = Cli::try_parse_from(["secretspec", "completions", name]).unwrap();
            match cli.command {
                Commands::Completions { shell } => assert_eq!(shell, expected),
                _ => panic!("expected completions command"),
            }
        }
    }

    #[test]
    fn completions_reject_an_unknown_shell() {
        assert!(Cli::try_parse_from(["secretspec", "completions", "tcsh"]).is_err());
    }

    #[test]
    fn completion_scripts_cover_the_full_cli() {
        let shells = [
            CompletionShell::Bash,
            CompletionShell::Elvish,
            CompletionShell::Fish,
            CompletionShell::Nushell,
            CompletionShell::PowerShell,
            CompletionShell::Zsh,
        ];

        for shell in shells {
            let mut output = Vec::new();
            generate_completions(shell, &mut output);
            let output = String::from_utf8(output).unwrap();
            assert!(
                output.contains("secretspec"),
                "missing binary for {shell:?}"
            );
            assert!(
                output.contains("config"),
                "missing subcommands for {shell:?}"
            );
            assert!(
                output.contains("provider"),
                "missing nested commands for {shell:?}"
            );
        }
    }

    #[test]
    fn fish_completions_do_not_evaluate_value_descriptions() {
        let mut output = Vec::new();
        generate_completions(CompletionShell::Fish, &mut output);
        let output = String::from_utf8(output).unwrap();
        assert!(!output.contains("$("));
        assert!(!output.contains("$GITHUB_ENV"));
    }

    #[test]
    fn completion_scripts_include_descriptions_where_supported() {
        let shells = [
            CompletionShell::Elvish,
            CompletionShell::Fish,
            CompletionShell::Nushell,
            CompletionShell::PowerShell,
            CompletionShell::Zsh,
        ];

        for shell in shells {
            let mut output = Vec::new();
            generate_completions(shell, &mut output);
            let output = String::from_utf8(output).unwrap();
            assert!(
                output.contains("Initialize a new secretspec.toml"),
                "missing descriptions for {shell:?}"
            );
        }
    }

    #[test]
    fn init_defaults_from_to_dotenv() {
        let cli = Cli::try_parse_from(["secretspec", "init"]).unwrap();
        match cli.command {
            Commands::Init {
                from,
                project,
                profile,
            } => {
                assert_eq!(from, "dotenv://.env");
                assert_eq!(project, None);
                assert_eq!(profile, "default");
            }
            _ => panic!("expected Init command"),
        }
    }

    #[test]
    fn init_accepts_discovery_context() {
        let cli = Cli::try_parse_from([
            "secretspec",
            "init",
            "--from",
            "awsps://us-east-1?template=/{profile}/{project}/{key}",
            "--project",
            "payments",
            "--profile",
            "production",
        ])
        .unwrap();
        match cli.command {
            Commands::Init {
                from,
                project,
                profile,
            } => {
                assert_eq!(
                    from,
                    "awsps://us-east-1?template=/{profile}/{project}/{key}"
                );
                assert_eq!(project.as_deref(), Some("payments"));
                assert_eq!(profile, "production");
            }
            _ => panic!("expected Init command"),
        }
    }

    #[test]
    fn add_parses_description_and_profile() {
        let cli = Cli::try_parse_from([
            "secretspec",
            "add",
            "API_KEY",
            "--description",
            "API access token",
            "--profile",
            "production",
        ])
        .unwrap();

        match cli.command {
            Commands::Add {
                name,
                description,
                profile,
            } => {
                assert_eq!(name, "API_KEY");
                assert_eq!(description.as_deref(), Some("API access token"));
                assert_eq!(profile.as_deref(), Some("production"));
            }
            _ => panic!("expected Add command"),
        }
    }

    #[test]
    fn add_secret_to_manifest_preserves_comments_and_other_tables() {
        let source = r#"# Project documentation
[project]
name = "demo"
revision = "1.0"

[profiles.default]
# Keep this explanation attached to the existing secret.
DATABASE_URL = { description = "Database connection string" }

[providers]
local = "dotenv://.env"
"#;

        let updated =
            add_secret_to_manifest(source, "default", "API_KEY", "API access token").unwrap();

        assert!(updated.contains("# Project documentation"));
        assert!(updated.contains("# Keep this explanation attached to the existing secret."));
        assert!(updated.contains("local = \"dotenv://.env\""));
        assert!(updated.contains("API_KEY = { description = \"API access token\" }"));

        let config: Config = toml::from_str(&updated).expect("edited manifest must parse");
        config.validate().expect("edited manifest must validate");
        assert_eq!(
            config.profiles["default"].secrets["API_KEY"]
                .description
                .as_deref(),
            Some("API access token")
        );
    }

    #[test]
    fn add_secret_to_manifest_can_overlay_an_inherited_profile() {
        let source = r#"[project]
name = "demo"
revision = "1.0"
extends = ["../shared"]

[profiles.default]
LOCAL = { description = "Local secret" }
"#;

        let updated =
            add_secret_to_manifest(source, "production", "API_KEY", "API access token").unwrap();

        assert!(updated.contains("[profiles.production]"));
        assert!(updated.contains("API_KEY = { description = \"API access token\" }"));
    }

    #[test]
    fn add_target_rejects_inherited_secrets_and_unknown_profiles() {
        let config: Config = toml::from_str(
            r#"[project]
name = "demo"
revision = "1.0"

[profiles.default]
API_KEY = { description = "API access token" }

[profiles.development]
"#,
        )
        .unwrap();
        let app = Secrets::new(config, None, None, None);

        let inherited = validate_add_target(&app, "development", "API_KEY")
            .unwrap_err()
            .to_string();
        assert!(inherited.contains("already declared for profile 'development'"));

        let unknown = validate_add_target(&app, "production", "NEW_KEY")
            .unwrap_err()
            .to_string();
        assert!(unknown.contains("Available profiles: default, development"));

        validate_add_target(&app, "development", "NEW_KEY").unwrap();
    }

    #[test]
    fn add_secret_to_manifest_rejects_invalid_or_duplicate_declarations() {
        let source = r#"[profiles.default]
API_KEY = { description = "Existing" }
"#;

        let invalid = add_secret_to_manifest(source, "default", "1BAD", "Description")
            .unwrap_err()
            .to_string();
        assert!(invalid.contains("Invalid secret name"));

        let reserved = add_secret_to_manifest(source, "default", "defaults", "Description")
            .unwrap_err()
            .to_string();
        assert!(reserved.contains("reserved for profile defaults"));

        let duplicate = add_secret_to_manifest(source, "default", "API_KEY", "Description")
            .unwrap_err()
            .to_string();
        assert!(duplicate.contains("already declared"));

        let empty = add_secret_to_manifest(source, "default", "NEW_KEY", "   ")
            .unwrap_err()
            .to_string();
        assert!(empty.contains("description cannot be empty"));
    }

    #[test]
    fn atomic_manifest_write_failure_leaves_original_unchanged() {
        let directory = tempfile::tempdir().unwrap();
        let manifest = directory.path().join("secretspec.toml");
        fs::write(&manifest, "original manifest\n").unwrap();

        let error = replace_manifest_atomically(&manifest, |temporary| {
            temporary.write_all(b"partial replacement")?;
            Err(std::io::Error::other("simulated interrupted write"))
        })
        .unwrap_err()
        .to_string();

        assert!(error.contains("Failed to write temporary manifest"));
        assert_eq!(
            fs::read_to_string(&manifest).unwrap(),
            "original manifest\n"
        );
    }

    #[test]
    fn atomic_manifest_write_preserves_permissions() {
        let directory = tempfile::tempdir().unwrap();
        let manifest = directory.path().join("secretspec.toml");
        fs::write(&manifest, "original manifest\n").unwrap();

        #[cfg(unix)]
        fs::set_permissions(&manifest, fs::Permissions::from_mode(0o640)).unwrap();
        let permissions = fs::metadata(&manifest).unwrap().permissions();

        write_manifest_atomically(&manifest, "updated manifest\n").unwrap();

        assert_eq!(fs::read_to_string(&manifest).unwrap(), "updated manifest\n");
        assert_eq!(fs::metadata(&manifest).unwrap().permissions(), permissions);
    }

    #[test]
    fn add_follow_up_command_quotes_profile_and_explicit_file() {
        assert_eq!(
            add_follow_up_command(
                "API_KEY",
                "qa west",
                Some(Path::new("/tmp/project's manifest.toml"))
            ),
            "secretspec set API_KEY --profile 'qa west' --file '/tmp/project'\\''s manifest.toml'"
        );
        assert_eq!(
            add_follow_up_command("API_KEY", "default", None),
            "secretspec set API_KEY --profile 'default'"
        );
    }

    #[test]
    fn run_captures_trailing_args() {
        let cli =
            Cli::try_parse_from(["secretspec", "run", "--", "npm", "start", "--flag"]).unwrap();
        match cli.command {
            Commands::Run { command, .. } => {
                assert_eq!(command, vec!["npm", "start", "--flag"]);
            }
            _ => panic!("expected Run command"),
        }
    }

    #[test]
    fn check_parses_no_prompt_short_flag() {
        let cli = Cli::try_parse_from(["secretspec", "check", "-n"]).unwrap();
        match cli.command {
            Commands::Check { no_prompt, .. } => assert!(no_prompt),
            _ => panic!("expected Check command"),
        }
    }

    #[test]
    fn delete_requires_names_or_explicit_all() {
        let cli = Cli::try_parse_from([
            "secretspec",
            "delete",
            "API_KEY",
            "DATABASE_URL",
            "--provider",
            "dotenv://.env",
            "--profile",
            "production",
        ])
        .unwrap();
        match cli.command {
            Commands::Delete {
                names,
                all,
                yes,
                provider,
                profile,
            } => {
                assert_eq!(names, vec!["API_KEY", "DATABASE_URL"]);
                assert!(!all);
                assert!(!yes);
                assert_eq!(provider.as_deref(), Some("dotenv://.env"));
                assert_eq!(profile.as_deref(), Some("production"));
            }
            _ => panic!("expected delete"),
        }

        assert!(Cli::try_parse_from(["secretspec", "delete"]).is_err());
        let cli = Cli::try_parse_from(["secretspec", "delete", "--all", "--yes"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Delete {
                names,
                all: true,
                yes: true,
                ..
            } if names.is_empty()
        ));
        assert!(
            Cli::try_parse_from(["secretspec", "delete", "API_KEY", "--all"]).is_err(),
            "a named delete and --all must be mutually exclusive"
        );
        assert!(
            Cli::try_parse_from(["secretspec", "delete", "API_KEY", "--yes"]).is_err(),
            "--yes is meaningful only with --all"
        );
    }

    #[test]
    fn import_parses_delete_source() {
        let cli = Cli::try_parse_from(["secretspec", "import", "dotenv://.env", "--delete-source"])
            .unwrap();
        assert!(matches!(
            cli.command,
            Commands::Import {
                from_provider,
                delete_source: true,
            } if from_provider == "dotenv://.env"
        ));
    }

    #[test]
    fn cache_clear_parses_optional_name_and_profile() {
        let cli = Cli::try_parse_from([
            "secretspec",
            "cache",
            "clear",
            "API_KEY",
            "--profile",
            "production",
        ])
        .unwrap();
        match cli.command {
            Commands::Cache {
                action: CacheAction::Clear { name, profile },
            } => {
                assert_eq!(name.as_deref(), Some("API_KEY"));
                assert_eq!(profile.as_deref(), Some("production"));
            }
            _ => panic!("expected cache clear"),
        }

        let cli = Cli::try_parse_from(["secretspec", "cache", "clear"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Cache {
                action: CacheAction::Clear {
                    name: None,
                    profile: None
                }
            }
        ));
    }

    #[test]
    fn config_init_parses_non_interactive_defaults() {
        let cli = Cli::try_parse_from([
            "secretspec",
            "config",
            "global",
            "init",
            "--provider",
            "env",
            "--profile",
            "default",
        ])
        .unwrap();

        match cli.command {
            Commands::Config {
                action:
                    ConfigAction::Global {
                        action: GlobalConfigAction::Init { provider, profile },
                    },
            } => {
                assert_eq!(provider.as_deref(), Some("env"));
                assert_eq!(profile.as_deref(), Some("default"));
            }
            _ => panic!("expected config init"),
        }
    }

    #[test]
    fn config_init_explicit_values_skip_selection_and_are_validated() {
        assert_eq!(
            select_config_init_provider(Some(" env:// ".to_string())).unwrap(),
            "env://"
        );
        assert!(
            select_config_init_provider(Some("unknown".to_string()))
                .unwrap_err()
                .to_string()
                .contains("Provider backend 'unknown' not found")
        );
        assert_eq!(
            select_config_init_provider(Some("file:./.secrets".to_string())).unwrap(),
            "file:./.secrets"
        );
        assert!(
            select_config_init_provider(Some("file".to_string()))
                .unwrap_err()
                .to_string()
                .contains("requires an explicit relative or absolute directory path")
        );

        assert_eq!(
            select_config_init_profile(Some(" default ".to_string())).unwrap(),
            Some("default".to_string())
        );
        assert_eq!(
            select_config_init_profile(Some("none".to_string())).unwrap(),
            None
        );
        assert!(select_config_init_profile(Some(" ".to_string())).is_err());
    }

    #[test]
    fn provider_add_parses_repeated_credential_bindings() {
        let cli = Cli::try_parse_from([
            "secretspec",
            "config",
            "global",
            "provider",
            "add",
            "bws",
            "bws://proj",
            "--credential",
            "access_token=keyring",
            "--credential",
            "other=dotenv://.env",
        ])
        .unwrap();
        match cli.command {
            Commands::Config {
                action:
                    ConfigAction::Global {
                        action:
                            GlobalConfigAction::Provider(GlobalProviderAction::Add {
                                name,
                                uri,
                                credential,
                            }),
                    },
            } => {
                assert_eq!(name, "bws");
                assert_eq!(uri, "bws://proj");
                assert_eq!(
                    credential,
                    vec!["access_token=keyring", "other=dotenv://.env"]
                );
            }
            _ => panic!("expected config provider add"),
        }
    }

    #[test]
    fn provider_add_help_describes_semantic_credentials() {
        let help = Cli::try_parse_from([
            "secretspec",
            "config",
            "global",
            "provider",
            "add",
            "--help",
        ])
        .err()
        .expect("--help should stop parsing")
        .to_string();

        assert!(help.contains("semantic and provider-specific"));
        assert!(help.contains("access_token"));
    }

    #[test]
    fn provider_add_rejects_the_environment_shaped_flag() {
        let error = Cli::try_parse_from([
            "secretspec",
            "config",
            "global",
            "provider",
            "add",
            "bws",
            "bws://proj",
            "--env",
            "BWS_ACCESS_TOKEN=keyring",
        ])
        .err()
        .expect("--env should be rejected");

        assert!(error.to_string().contains("--env"));
    }

    #[test]
    fn provider_login_parses() {
        let cli =
            Cli::try_parse_from(["secretspec", "config", "provider", "login", "bws"]).unwrap();
        match cli.command {
            Commands::Config {
                action: ConfigAction::Provider(ProviderAction::Login { name }),
            } => {
                assert_eq!(name, "bws");
            }
            _ => panic!("expected config provider login"),
        }
    }

    #[test]
    fn legacy_global_config_spellings_remain_supported() {
        let commands: &[&[&str]] = &[
            &[
                "secretspec",
                "config",
                "init",
                "--provider",
                "env",
                "--profile",
                "default",
            ],
            &["secretspec", "config", "show"],
            &[
                "secretspec",
                "config",
                "provider",
                "add",
                "shared",
                "keyring://",
            ],
            &["secretspec", "config", "provider", "list"],
            &["secretspec", "config", "provider", "remove", "shared"],
        ];

        for command in commands {
            assert!(
                Cli::try_parse_from(*command).is_ok(),
                "legacy command should remain accepted: {command:?}"
            );
        }
    }

    #[test]
    fn global_provider_namespace_rejects_project_scoped_login() {
        let error =
            Cli::try_parse_from(["secretspec", "config", "global", "provider", "login", "bws"])
                .err()
                .expect("global provider namespace must not expose project-scoped login");
        assert!(
            error
                .to_string()
                .contains("unrecognized subcommand 'login'")
        );
    }
}
