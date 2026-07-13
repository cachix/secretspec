use crate::provider::{Provider, providers};
use crate::{Config, GlobalConfig, GlobalDefaults, Profile, Project, Secrets};
use clap::{Parser, Subcommand};
use miette::{IntoDiagnostic, Result, WrapErr, miette};
use std::collections::HashMap;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

/// Main CLI structure for the secretspec application.
///
/// This is the entry point for the command-line interface, parsing user commands
/// and delegating to the appropriate subcommands for secrets management.
#[derive(Parser)]
#[command(name = "secretspec")]
#[command(about = "Declarative secrets, every environment, any provider - https://secretspec.dev", long_about = None)]
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

/// Available commands for the secretspec CLI.
///
/// This enum defines all the subcommands that can be executed, including
/// initialization, secret management, configuration, and import operations.
#[derive(Subcommand)]
enum Commands {
    /// Initialize a new secretspec.toml (optionally, from a provider)
    Init {
        /// Provider URL to import from (e.g., dotenv://.env, dotenv://.env.production)
        /// Currently only dotenv provider is supported.
        ///
        /// Note: no short flag here — `-f` is the global `--file` option.
        #[arg(long, default_value = "dotenv://.env")]
        from: String,
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
    /// Run a command with secrets injected
    Run {
        /// Provider backend to use
        #[arg(short, long, env = "SECRETSPEC_PROVIDER")]
        provider: Option<String>,
        /// Profile to use
        #[arg(short = 'P', long, env = "SECRETSPEC_PROFILE")]
        profile: Option<String>,
        /// Command and arguments to run
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// Check if all required secrets are in the provider, if not set them
    Check {
        /// Provider backend to use
        #[arg(short, long, env = "SECRETSPEC_PROVIDER")]
        provider: Option<String>,
        /// Profile to use
        #[arg(short = 'P', long, env = "SECRETSPEC_PROFILE")]
        profile: Option<String>,
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
    /// Init or show ~/.config/secretspec/config.toml
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Import secrets from a provider to another provider
    Import {
        /// Provider backend to import from (secrets will be imported to the default provider)
        from_provider: String,
    },
    /// Show the local audit log of secret access
    Audit {
        /// Only show entries for this project
        #[arg(long)]
        project: Option<String>,
        /// Only show entries for this action (get, set, check, run, import)
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

/// Configuration-related subcommands.
///
/// These actions handle the user's global configuration settings,
/// including initialization, viewing current settings, and managing provider aliases.
#[derive(Subcommand)]
enum ConfigAction {
    /// Initialize user configuration
    Init,
    /// Show current configuration
    Show,
    /// Manage provider aliases
    #[command(subcommand)]
    Provider(ProviderAction),
}

/// Provider alias management subcommands.
///
/// These actions allow managing named provider aliases in the global configuration.
#[derive(Subcommand)]
enum ProviderAction {
    /// Add or update a provider alias
    Add {
        /// Name of the provider alias
        name: String,
        /// Provider URI (e.g., "keyring://", "onepassword://Shared", "dotenv://.env.local")
        uri: String,
    },
    /// Remove a provider alias
    Remove {
        /// Name of the provider alias to remove
        name: String,
    },
    /// List all configured provider aliases
    List,
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

[profiles.development]
# Development profile inherits all secrets from default profile
# Only define secrets here that need different values or settings than default
# DATABASE_URL = { default = "sqlite:///dev.db" }
#
# New secrets
# REDIS_URL = { description = "Redis connection URL for caching", required = false, default = "redis://localhost:6379" }
"#
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
            }
            if let Some(default) = &secret_config.default {
                inline.insert("default", Value::from(default.as_str()));
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

/// Loads secrets using an explicit path or auto-detection, applying the optional
/// session reason (from `--reason`/`SECRETSPEC_REASON`).
fn load_secrets(file: &Option<PathBuf>, reason: &Option<String>) -> miette::Result<Secrets> {
    let secrets = match file {
        Some(path) => Secrets::load_from(path),
        None => Secrets::load(),
    }
    .into_diagnostic()
    .wrap_err("Failed to load secretspec configuration")?;

    Ok(match reason {
        Some(reason) => secrets.with_reason(reason.clone()),
        None => secrets,
    })
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
        Commands::Init { from } => {
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

            // Create provider from the specification string
            // This handles various formats like "dotenv", "dotenv:.env", "dotenv://.env.production"
            let provider: Box<dyn Provider> = from.as_str().try_into().into_diagnostic()?;

            // Check if it's a dotenv provider
            if provider.name() != "dotenv" {
                return Err(miette!(
                    "Only 'dotenv' provider is currently supported for init --from. Got provider: {}",
                    provider.name()
                ));
            }

            // Reflect secrets from the provider
            let secrets = provider.reflect().into_diagnostic()?;

            // Create a new project config
            let mut profiles = HashMap::new();
            profiles.insert(
                "default".to_string(),
                Profile {
                    defaults: None,
                    secrets,
                },
            );

            let project_config = Config {
                project: Project {
                    name: std::env::current_dir()
                        .into_diagnostic()?
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string(),
                    ..Default::default()
                },
                profiles,
                providers: None,
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

            // If we imported from a provider, suggest migration
            if provider.name() == "dotenv" && secret_count > 0 {
                println!("\nTo migrate your secrets from {}:", from);
                println!("  1. Review secretspec.toml and adjust as needed");
                println!("  2. secretspec import {}    # Import secret values", from);
            }

            println!("\nNext steps:");
            println!("  1. secretspec config init    # Set up user configuration");
            println!("  2. secretspec check          # Verify all secrets and set them");
            println!("  3. secretspec run -- your-command  # Run with secrets");

            Ok(())
        }
        // Handle configuration management commands
        Commands::Config { action } => match action {
            // Initialize user configuration with interactive prompts
            ConfigAction::Init => {
                use inquire::Select;

                // Get provider choices from the centralized registry
                let provider_choices: Vec<String> = providers()
                    .into_iter()
                    .map(|info| info.display_with_examples())
                    .collect();

                let selected_choice =
                    Select::new("Select your preferred provider backend:", provider_choices)
                        .prompt()
                        .into_diagnostic()?;

                // Extract provider name from the selected choice
                let provider = selected_choice.split(':').next().unwrap_or("keyring");

                let profiles = vec!["development", "default", "none"];
                let profile_choice = Select::new("Select your default profile:", profiles)
                    .with_help_message(
                        "'development' is recommended for local development environments",
                    )
                    .prompt()
                    .into_diagnostic()?;

                let profile = if profile_choice == "none" {
                    None
                } else {
                    Some(profile_choice.to_string())
                };

                // Preserve any existing config (audit settings, provider aliases)
                // rather than overwriting the whole file: re-running `config init`
                // must not silently drop a user's `[audit]` table — which would
                // re-enable disabled logging — or their saved provider aliases.
                let mut config = GlobalConfig::load().into_diagnostic()?.unwrap_or_default();
                config.defaults.provider = Some(provider.to_string());
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
                            "No configuration found. Run 'secretspec config init' to create one."
                        );
                    }
                }
                Ok(())
            }
            // Manage provider aliases
            ConfigAction::Provider(action) => {
                match action {
                    ProviderAction::Add { name, uri } => {
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
                            let existing = providers.insert(name.clone(), uri.clone());
                            config.save().into_diagnostic()?;

                            if existing.is_some() {
                                println!("✓ Provider alias '{}' updated to '{}'", name, uri);
                            } else {
                                println!("✓ Provider alias '{}' added: '{}'", name, uri);
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
                                    "✗ No configuration found. Run 'secretspec config init' first."
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
                                    "No configuration found. Run 'secretspec config init' first."
                                );
                            }
                        }
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
        // Execute a command with secrets injected as environment variables
        Commands::Run {
            command,
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
            app.run(command)
                .into_diagnostic()
                .wrap_err("Failed to run command")?;
            Ok(())
        }
        // Verify all required secrets are available
        Commands::Check {
            provider,
            profile,
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
        // Import secrets from one provider to another
        Commands::Import { from_provider } => {
            let app = load_secrets(&cli.file, &cli.reason)?;
            app.import(&from_provider)
                .into_diagnostic()
                .wrap_err("Failed to import secrets")?;
            Ok(())
        }
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
        }
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
                "profile":"prod","keys":["A","B"],"command":"./deploy.sh"}"#,
        )
        .unwrap();
        let line = format_audit_line(&bulk);
        assert!(line.contains("./deploy.sh"));
        assert!(line.contains("A,B"));

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
    fn generated_config_with_example_template_is_valid_toml() {
        let mut out = generate_toml_with_comments(&config_with_secret(Secret {
            description: Some("desc".to_string()),
            ..Default::default()
        }))
        .unwrap();
        out.push_str(get_example_toml());
        // The appended example only adds commented secrets, so it must remain
        // syntactically valid TOML.
        toml::from_str::<Config>(&out).expect("init output template must be valid TOML");
    }

    #[test]
    fn cli_command_definition_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn init_defaults_from_to_dotenv() {
        let cli = Cli::try_parse_from(["secretspec", "init"]).unwrap();
        match cli.command {
            Commands::Init { from } => assert_eq!(from, "dotenv://.env"),
            _ => panic!("expected Init command"),
        }
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
}
