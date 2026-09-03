use super::credential_integration::{
    confirm, ensure_unchanged, manifest_path, read_credential, read_optional, resolve_path,
    restore_file, validate_credential_value, write_bytes_atomically,
};
use super::{TypedArgs, shell_quote};
use crate::config::GlobalConfig;
use crate::{CallerContext, NamedResolution, Secret, Secrets, Spec};
use clap::Subcommand;
use miette::{IntoDiagnostic, Result, WrapErr, miette};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use toml_edit::{Array, DocumentMut, Item, Table};
use url::{Host, Url};
use uuid::Uuid;

const STATE_VERSION: u8 = 1;
const DEFAULT_BASE_URL: &str = "https://api.openai.com/v1";
const DEFAULT_REASON: &str = "Codex model authentication";
const EMBEDDED_SECRET: &str = "CODEX_API_KEY";

#[derive(Subcommand)]
pub(super) enum CodexAction {
    #[command(about = "Configure Codex to retrieve an API key through SecretSpec (0.21+)")]
    Configure {
        #[arg(long, help = "Custom manifest key containing the API or gateway key")]
        token_secret: Option<String>,
        #[arg(
            short = 'P',
            long,
            env = "SECRETSPEC_PROFILE",
            help = "Custom manifest profile the token command should use"
        )]
        profile: Option<String>,
        #[arg(
            short,
            long,
            env = "SECRETSPEC_PROVIDER",
            help = "Provider override the token command should use"
        )]
        provider: Option<String>,
        #[arg(
            long,
            default_value = DEFAULT_BASE_URL,
            help = "OpenAI-compatible Responses API base URL"
        )]
        base_url: String,
        #[arg(
            long,
            help = "Codex model to set when config.toml has no top-level model"
        )]
        model: Option<String>,
        #[arg(
            short,
            long,
            help = "Confirm the user-level Codex configuration change non-interactively"
        )]
        yes: bool,
    },
    #[command(about = "Store a Codex API key in the embedded SecretSpec store (0.21+)")]
    Login {
        #[arg(
            short,
            long,
            env = "SECRETSPEC_PROVIDER",
            help = "Override the configured provider for this operation"
        )]
        provider: Option<String>,
    },
    #[command(about = "Remove a Codex API key from the embedded SecretSpec store (0.21+)")]
    Logout {
        #[arg(
            short,
            long,
            env = "SECRETSPEC_PROVIDER",
            help = "Override the configured provider for this operation"
        )]
        provider: Option<String>,
    },
    #[command(about = "Remove Codex API-key configuration managed by SecretSpec (0.21+)")]
    Unconfigure {
        #[arg(
            short,
            long,
            help = "Confirm the user-level Codex configuration change non-interactively"
        )]
        yes: bool,
    },
    #[command(hide = true)]
    Credential {
        #[arg(long)]
        configuration: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ManagedConfig {
    id: String,
    config: PathBuf,
    model_provider: String,
    previous_model_provider: Option<String>,
    managed_model: Option<String>,
    created_model_providers_table: bool,
    provider: Option<String>,
    reason: String,
    resource: String,
    base_url: String,
    source: CredentialSource,
    configured: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "kind")]
enum CredentialSource {
    Embedded,
    Manifest {
        manifest: PathBuf,
        profile: String,
        token_secret: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ManagedState {
    version: u8,
    configs: Vec<ManagedConfig>,
}

impl Default for ManagedState {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            configs: Vec::new(),
        }
    }
}

pub(super) fn run(
    action: CodexAction,
    file: &Option<PathBuf>,
    reason: &Option<String>,
    caller: &Option<CallerContext>,
    typed: TypedArgs,
) -> Result<()> {
    let file = typed.file.then(|| file.clone()).flatten();
    match action {
        CodexAction::Configure {
            token_secret,
            profile,
            provider,
            base_url,
            model,
            yes,
        } => configure(ConfigureOptions {
            token_secret,
            profile,
            provider,
            base_url,
            model,
            yes,
            file,
            reason,
            typed,
        }),
        CodexAction::Login { provider } => login(provider, &file, reason, caller),
        CodexAction::Logout { provider } => logout(provider, &file, reason, caller),
        CodexAction::Unconfigure { yes } => unconfigure(yes),
        CodexAction::Credential { configuration } => credential(&configuration, &file, caller),
    }
}

struct ConfigureOptions<'a> {
    token_secret: Option<String>,
    profile: Option<String>,
    provider: Option<String>,
    base_url: String,
    model: Option<String>,
    yes: bool,
    file: Option<PathBuf>,
    reason: &'a Option<String>,
    typed: TypedArgs,
}

fn configure(options: ConfigureOptions<'_>) -> Result<()> {
    let (base_url, resource) = normalize_base_url(&options.base_url)?;
    let config_path = config_path()?;
    let source = match &options.file {
        Some(file) => {
            let token_secret = options.token_secret.as_deref().ok_or_else(|| {
                miette!("--token-secret is required when --file selects a custom manifest")
            })?;
            let manifest = manifest_path(file)?;
            let mut secrets = Secrets::load_from(&manifest)
                .into_diagnostic()
                .wrap_err("Failed to load custom Codex API-key manifest")?;
            let profile = if options.typed.profile {
                options
                    .profile
                    .clone()
                    .ok_or_else(|| miette!("--profile was selected without a profile value"))?
            } else {
                GlobalConfig::load()
                    .into_diagnostic()?
                    .and_then(|config| config.defaults.profile)
                    .unwrap_or_else(|| "default".to_string())
            };
            secrets.set_profile(&profile);
            validate_secret(&secrets, token_secret, &profile)?;
            CredentialSource::Manifest {
                manifest,
                profile,
                token_secret: token_secret.to_string(),
            }
        }
        None => {
            if options.token_secret.is_some() || options.typed.profile {
                return Err(miette!(
                    "--token-secret and --profile require --file; the embedded Codex credential store uses its built-in declaration"
                ));
            }
            CredentialSource::Embedded
        }
    };
    let provider = options
        .typed
        .provider
        .then(|| options.provider.clone())
        .flatten();
    let reason = if options.typed.reason {
        options
            .reason
            .as_deref()
            .filter(|reason| !reason.trim().is_empty())
            .ok_or_else(|| miette!("--reason cannot be empty"))?
            .to_string()
    } else {
        DEFAULT_REASON.to_string()
    };

    let original_config = read_optional(&config_path)?;
    let mut config = parse_config(original_config.as_deref(), &config_path)?;
    let state_file = state_path()?;
    let original_state = read_optional(&state_file)?;
    let mut state = parse_state(original_state.as_deref(), &state_file)?;
    let existing_index = state
        .configs
        .iter()
        .position(|managed| managed.config == config_path);

    if let Some(index) = existing_index
        && state.configs[index].configured
    {
        verify_owned_config(&config, &state.configs[index], &config_path)?;
        remove_owned_provider(&mut config, &state.configs[index], &config_path)?;
    }

    let id = existing_index
        .map(|index| state.configs[index].id.clone())
        .unwrap_or_else(|| Uuid::new_v4().simple().to_string());
    let model_provider = model_provider_id(&id);
    if provider_entry(&config, &model_provider, &config_path)?.is_some() {
        return Err(miette!(
            "Codex model provider '{model_provider}' in {} is not available for SecretSpec to manage",
            config_path.display()
        ));
    }
    let previous_model_provider = match existing_index {
        Some(index) if state.configs[index].configured => {
            state.configs[index].previous_model_provider.clone()
        }
        _ => current_model_provider(&config, &config_path)?,
    };
    let current_model = current_model(&config, &config_path)?;
    let managed_model = match existing_index {
        Some(index) if state.configs[index].configured => {
            let managed_model = state.configs[index].managed_model.clone();
            if let Some(requested) = &options.model
                && managed_model.as_deref().or(current_model.as_deref()) != Some(requested)
            {
                return Err(miette!(
                    "Codex model is already managed as '{}'; unconfigure before selecting '{requested}'",
                    current_model.as_deref().unwrap_or("missing")
                ));
            }
            managed_model
        }
        _ => match (&current_model, &options.model) {
            (Some(current), Some(requested)) if current != requested => {
                return Err(miette!(
                    "Codex config already selects model '{current}'; omit --model or update Codex configuration separately"
                ));
            }
            (Some(_), _) => None,
            (None, Some(requested)) => Some(validate_model(requested)?.to_string()),
            (None, None) => {
                return Err(miette!(
                    "Codex config must select a top-level model before using a custom provider; pass --model with a model supported by this Codex installation"
                ));
            }
        },
    };
    let created_model_providers_table = match existing_index {
        Some(index) if state.configs[index].configured => {
            state.configs[index].created_model_providers_table
        }
        _ => !config.as_table().contains_key("model_providers"),
    };
    let desired = ManagedConfig {
        id,
        config: config_path.clone(),
        model_provider,
        previous_model_provider,
        managed_model,
        created_model_providers_table,
        provider,
        reason,
        resource,
        base_url,
        source,
        configured: true,
    };
    set_owned_config(&mut config, &desired, &config_path)?;
    let rendered = config.to_string();
    let config_changed = original_config.as_deref() != Some(rendered.as_bytes());
    let state_changed = match existing_index {
        Some(index) if state.configs[index] == desired => false,
        Some(index) => {
            state.configs[index] = desired;
            true
        }
        None => {
            state.configs.push(desired);
            true
        }
    };
    validate_state(&state, &state_file)?;
    if !state_changed && !config_changed {
        println!(
            "Codex API-key integration is already configured in {}.",
            config_path.display()
        );
        return Ok(());
    }
    if !confirm(
        options.yes,
        "Configure the current user's Codex API-key provider?",
    )? {
        return Ok(());
    }

    ensure_unchanged(&config_path, original_config.as_deref())?;
    ensure_unchanged(&state_file, original_state.as_deref())?;
    if state_changed {
        write_state(&state_file, &state)?;
    }
    if config_changed
        && let Err(error) = write_bytes_atomically(&config_path, rendered.as_bytes(), true)
    {
        if state_changed {
            restore_file(&state_file, original_state.as_deref(), true)?;
        }
        return Err(error);
    }

    println!(
        "Configured Codex API-key integration in {}.",
        config_path.display()
    );
    let configured = state
        .configs
        .iter()
        .find(|managed| managed.config == config_path)
        .expect("configured state entry exists");
    match &configured.source {
        CredentialSource::Embedded => {
            println!("Store the API key with: secretspec codex login");
        }
        CredentialSource::Manifest {
            manifest,
            profile,
            token_secret,
        } => {
            println!("SecretSpec manifest: {}", manifest.display());
            let mut set = format!(
                "secretspec --file {} set {} --profile {}",
                shell_quote(&manifest.to_string_lossy()),
                shell_quote(token_secret),
                shell_quote(profile)
            );
            if let Some(provider) = &configured.provider {
                set.push_str(" --provider ");
                set.push_str(&shell_quote(provider));
            }
            println!("Store the API key with: {set}");
        }
    }
    println!("Undo with: secretspec codex unconfigure");
    if !options.typed.provider && options.provider.is_some() {
        println!(
            "Note: SECRETSPEC_PROVIDER was not recorded in the Codex token command; pass --provider to pin it."
        );
    }
    if !options.typed.reason && options.reason.is_some() {
        println!(
            "Note: SECRETSPEC_REASON was not recorded in the Codex token command; pass --reason to pin it."
        );
    }
    Ok(())
}

fn login(
    provider: Option<String>,
    file: &Option<PathBuf>,
    reason: &Option<String>,
    caller: &Option<CallerContext>,
) -> Result<()> {
    let managed = lifecycle_config(file)?;
    if !managed.configured {
        return Err(miette!(
            "Codex API-key integration is not active; rerun secretspec codex configure"
        ));
    }
    let (secrets, secret) =
        embedded_cli_secrets(&managed, provider.as_deref(), reason, caller, "login")?;
    let value = read_credential("Enter Codex API or gateway key:")?;
    validate_credential_value(&value)?;
    secrets
        .set(&secret, Some(value))
        .into_diagnostic()
        .wrap_err("Failed to store Codex API key")?;
    println!("Stored Codex API key.");
    Ok(())
}

fn logout(
    provider: Option<String>,
    file: &Option<PathBuf>,
    reason: &Option<String>,
    caller: &Option<CallerContext>,
) -> Result<()> {
    let managed = lifecycle_config(file)?;
    let (secrets, secret) =
        embedded_cli_secrets(&managed, provider.as_deref(), reason, caller, "logout")?;
    if secrets
        .delete(&secret)
        .into_diagnostic()
        .wrap_err("Failed to remove Codex API key")?
    {
        println!("Removed stored Codex API key.");
    } else {
        println!("No stored Codex API key was found.");
    }
    Ok(())
}

fn credential(
    configuration: &str,
    file: &Option<PathBuf>,
    caller: &Option<CallerContext>,
) -> Result<()> {
    if file.is_some() {
        return Err(miette!(
            "secretspec codex credential uses the manifest recorded by configure; omit --file"
        ));
    }
    let state_file = state_path()?;
    let state = parse_state(read_optional(&state_file)?.as_deref(), &state_file)?;
    let managed = state
        .configs
        .iter()
        .find(|managed| managed.id == configuration)
        .ok_or_else(|| miette!("Codex API-key configuration was not found"))?;
    if !managed.configured {
        return Err(miette!(
            "Codex API-key configuration is not active; rerun secretspec codex configure"
        ));
    }
    let (mut secrets, secret) = secrets_for_config(managed)?;
    if let Some(provider) = &managed.provider {
        secrets.set_provider(provider);
    }
    secrets = secrets.with_reason(&managed.reason);
    let caller = caller.clone().unwrap_or_else(|| {
        CallerContext::new("codex")
            .with_operation("credential_get")
            .with_resource(&managed.resource)
    });
    secrets = secrets.with_caller(caller);
    validate_secret(&secrets, &secret, &secrets.resolve_profile_name(None))?;
    match secrets.resolve_named(&secret).into_diagnostic()? {
        NamedResolution::Resolved(resolved) => {
            let value = resolved
                .value
                .ok_or_else(|| miette!("Codex API key cannot be returned as a file path"))?;
            validate_credential_value(&value)?;
            println!("{value}");
            Ok(())
        }
        NamedResolution::Missing { .. } => Err(miette!("Codex API key is not stored")),
        NamedResolution::Undeclared => {
            Err(miette!("Codex API-key secret '{secret}' is not declared"))
        }
    }
}

fn unconfigure(yes: bool) -> Result<()> {
    let config_path = config_path()?;
    let state_file = state_path()?;
    let original_state = read_optional(&state_file)?;
    let mut state = parse_state(original_state.as_deref(), &state_file)?;
    let Some(index) = state
        .configs
        .iter()
        .position(|managed| managed.config == config_path)
    else {
        println!("No matching SecretSpec-managed Codex integration found.");
        return Ok(());
    };
    if !state.configs[index].configured {
        println!("No matching active SecretSpec-managed Codex integration found.");
        return Ok(());
    }
    let managed = state.configs[index].clone();
    let original_config = read_optional(&config_path)?;
    let mut config = parse_config(original_config.as_deref(), &config_path)?;
    verify_owned_config(&config, &managed, &config_path)?;
    if !confirm(
        yes,
        "Remove the current user's SecretSpec-managed Codex API-key provider?",
    )? {
        return Ok(());
    }

    remove_owned_provider(&mut config, &managed, &config_path)?;
    restore_model_provider(
        &mut config,
        managed.previous_model_provider.as_deref(),
        &config_path,
    )?;
    let rendered = config.to_string();
    ensure_unchanged(&config_path, original_config.as_deref())?;
    ensure_unchanged(&state_file, original_state.as_deref())?;
    write_bytes_atomically(&config_path, rendered.as_bytes(), true)?;
    state.configs[index].configured = false;
    if let Err(error) = write_state(&state_file, &state) {
        restore_file(&config_path, original_config.as_deref(), true)?;
        return Err(error);
    }
    println!(
        "Removed SecretSpec-managed Codex integration from {}.",
        config_path.display()
    );
    Ok(())
}

fn lifecycle_config(file: &Option<PathBuf>) -> Result<ManagedConfig> {
    if file.is_some() {
        return Err(miette!(
            "secretspec codex login and logout use the manifest recorded by configure; omit --file"
        ));
    }
    let config = config_path()?;
    let state_file = state_path()?;
    let state = parse_state(read_optional(&state_file)?.as_deref(), &state_file)?;
    state
        .configs
        .into_iter()
        .find(|managed| managed.config == config)
        .ok_or_else(|| {
            miette!(
                "Codex API-key integration is not configured for this CODEX_HOME; run secretspec codex configure first"
            )
        })
}

fn embedded_cli_secrets(
    managed: &ManagedConfig,
    provider: Option<&str>,
    reason: &Option<String>,
    caller: &Option<CallerContext>,
    action: &str,
) -> Result<(Secrets, String)> {
    if !matches!(managed.source, CredentialSource::Embedded) {
        return Err(miette!(
            "this Codex integration uses a custom manifest; use secretspec set or delete with that manifest"
        ));
    }
    let (mut secrets, secret) = embedded_secrets(managed)?;
    if let Some(provider) = provider.or(managed.provider.as_deref()) {
        secrets.set_provider(provider);
    }
    secrets = secrets.with_reason(reason.as_deref().unwrap_or(&managed.reason));
    let caller = caller.clone().unwrap_or_else(|| {
        CallerContext::new("codex")
            .with_operation(format!("credential_{action}"))
            .with_resource(&managed.resource)
    });
    secrets = secrets.with_caller(caller);
    secrets.set_write_target_reporter(|target| {
        eprintln!(
            "Writing secret '{}' to {} (profile: {})\n  target: {}",
            target.name, target.provider_uri, target.profile, target.target
        );
    });
    Ok((secrets, secret))
}

fn embedded_secrets(managed: &ManagedConfig) -> Result<(Secrets, String)> {
    let mut digest = Sha256::new();
    digest.update(managed.config.as_os_str().as_encoded_bytes());
    digest.update([0]);
    digest.update(managed.base_url.as_bytes());
    let identity = data_encoding::HEXLOWER.encode(&digest.finalize());
    let secret = format!("{EMBEDDED_SECRET}_{}", identity.to_ascii_uppercase());
    let spec = Spec::builder(format!("codex-api-key-{identity}"))
        .secret(
            secret.clone(),
            Secret::required("OpenAI or gateway API key used by Codex"),
        )
        .build()
        .into_diagnostic()?;
    let config = GlobalConfig::path().into_diagnostic()?;
    let base = config
        .parent()
        .ok_or_else(|| miette!("SecretSpec config path has no parent directory"))?;
    let mut secrets = Secrets::from_spec_at(spec, base).into_diagnostic()?;
    secrets.set_profile("default");
    secrets.set_ignore_ambient_scope(true);
    Ok((secrets, secret))
}

fn secrets_for_config(managed: &ManagedConfig) -> Result<(Secrets, String)> {
    match &managed.source {
        CredentialSource::Embedded => embedded_secrets(managed),
        CredentialSource::Manifest {
            manifest,
            profile,
            token_secret,
        } => {
            let mut secrets = Secrets::load_from(manifest)
                .into_diagnostic()
                .wrap_err("Failed to load custom Codex API-key manifest")?;
            secrets.set_profile(profile);
            secrets.set_ignore_ambient_scope(true);
            Ok((secrets, token_secret.clone()))
        }
    }
}

fn validate_secret(secrets: &Secrets, name: &str, profile: &str) -> Result<()> {
    if name.is_empty() {
        return Err(miette!("Secret name cannot be empty"));
    }
    let secret = secrets.resolve_secret_config(name, None).ok_or_else(|| {
        miette!("Secret '{name}' is not declared in SecretSpec profile '{profile}'")
    })?;
    if secret.as_path == Some(true) {
        return Err(miette!(
            "Secret '{name}' uses as_path and cannot be returned as a Codex API key"
        ));
    }
    Ok(())
}

fn normalize_base_url(input: &str) -> Result<(String, String)> {
    let mut url = Url::parse(input)
        .into_diagnostic()
        .wrap_err("Codex API base URL is invalid")?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(miette!("Codex API base URL must use HTTP or HTTPS"));
    }
    if url.host().is_none() {
        return Err(miette!("Codex API base URL must include a host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(miette!("Codex API base URL must not include credentials"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(miette!(
            "Codex API base URL must not include a query or fragment"
        ));
    }
    if url.scheme() == "http" && !is_loopback(&url) {
        return Err(miette!(
            "Codex API base URL must use HTTPS unless the host is loopback"
        ));
    }
    let path = url.path().trim_end_matches('/').to_string();
    url.set_path(&path);
    let host = match url.host().expect("validated URL has a host") {
        Host::Ipv6(address) => format!("[{address}]"),
        host => host.to_string(),
    };
    let resource = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    };
    Ok((url.to_string().trim_end_matches('/').to_string(), resource))
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

fn config_path() -> Result<PathBuf> {
    let home = match std::env::var_os("CODEX_HOME").filter(|value| !value.is_empty()) {
        Some(path) => PathBuf::from(path),
        None => etcetera::home_dir()
            .into_diagnostic()
            .wrap_err("Failed to locate the user home directory")?
            .join(".codex"),
    };
    resolve_path(&home.join("config.toml"))
}

fn state_path() -> Result<PathBuf> {
    let config = GlobalConfig::path().into_diagnostic()?;
    let directory = config
        .parent()
        .ok_or_else(|| miette!("SecretSpec config path has no parent directory"))?;
    resolve_path(&directory.join("codex.json"))
}

fn model_provider_id(id: &str) -> String {
    format!("secretspec-{id}")
}

fn helper_args(id: &str) -> Array {
    let mut args = Array::new();
    for argument in ["codex", "credential", "--configuration", id] {
        args.push(argument);
    }
    args
}

fn expected_provider(managed: &ManagedConfig) -> Item {
    let mut provider = Table::new();
    provider.insert("name", toml_edit::value("OpenAI API through SecretSpec"));
    provider.insert("base_url", toml_edit::value(&managed.base_url));
    provider.insert("wire_api", toml_edit::value("responses"));
    let mut auth = Table::new();
    auth.insert("command", toml_edit::value("secretspec"));
    auth.insert("args", toml_edit::value(helper_args(&managed.id)));
    auth.insert("refresh_interval_ms", toml_edit::value(300_000));
    auth.insert("timeout_ms", toml_edit::value(5_000));
    provider.insert("auth", Item::Table(auth));
    Item::Table(provider)
}

fn parse_config(contents: Option<&[u8]>, path: &Path) -> Result<DocumentMut> {
    let Some(contents) = contents else {
        return Ok(DocumentMut::new());
    };
    let contents = std::str::from_utf8(contents)
        .into_diagnostic()
        .wrap_err_with(|| format!("{} must be UTF-8", path.display()))?;
    contents
        .parse::<DocumentMut>()
        .into_diagnostic()
        .wrap_err_with(|| format!("Failed to parse {}", path.display()))
}

fn current_model_provider(config: &DocumentMut, path: &Path) -> Result<Option<String>> {
    let Some(value) = config.as_table().get("model_provider") else {
        return Ok(None);
    };
    value
        .as_str()
        .map(|value| Some(value.to_string()))
        .ok_or_else(|| {
            miette!(
                "Codex model_provider in {} must be a string",
                path.display()
            )
        })
}

fn current_model(config: &DocumentMut, path: &Path) -> Result<Option<String>> {
    let Some(value) = config.as_table().get("model") else {
        return Ok(None);
    };
    value
        .as_str()
        .map(|value| Some(value.to_string()))
        .ok_or_else(|| miette!("Codex model in {} must be a string", path.display()))
}

fn validate_model(model: &str) -> Result<&str> {
    if model.trim().is_empty()
        || model.trim() != model
        || model.chars().any(|character| character.is_ascii_control())
    {
        return Err(miette!(
            "Codex model cannot be empty or contain surrounding whitespace or control characters"
        ));
    }
    Ok(model)
}

fn provider_entry<'a>(config: &'a DocumentMut, id: &str, path: &Path) -> Result<Option<&'a Item>> {
    let Some(providers) = config.as_table().get("model_providers") else {
        return Ok(None);
    };
    let providers = providers.as_table_like().ok_or_else(|| {
        miette!(
            "Codex model_providers in {} must be a table",
            path.display()
        )
    })?;
    Ok(providers.get(id))
}

fn providers_table_mut<'a>(
    config: &'a mut DocumentMut,
    path: &Path,
) -> Result<&'a mut dyn toml_edit::TableLike> {
    if !config.as_table().contains_key("model_providers") {
        config
            .as_table_mut()
            .insert("model_providers", Item::Table(Table::new()));
    }
    config
        .as_table_mut()
        .get_mut("model_providers")
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| {
            miette!(
                "Codex model_providers in {} must be a table",
                path.display()
            )
        })
}

fn set_owned_config(config: &mut DocumentMut, managed: &ManagedConfig, path: &Path) -> Result<()> {
    if let Some(model) = &managed.managed_model {
        config
            .as_table_mut()
            .insert("model", toml_edit::value(model));
    }
    let providers = providers_table_mut(config, path)?;
    if providers.contains_key(&managed.model_provider) {
        return Err(miette!(
            "Codex model provider '{}' in {} is not available for SecretSpec to manage",
            managed.model_provider,
            path.display()
        ));
    }
    providers.insert(&managed.model_provider, expected_provider(managed));
    config
        .as_table_mut()
        .insert("model_provider", toml_edit::value(&managed.model_provider));
    Ok(())
}

fn verify_owned_config(config: &DocumentMut, managed: &ManagedConfig, path: &Path) -> Result<()> {
    if let Some(model) = &managed.managed_model
        && current_model(config, path)?.as_deref() != Some(model)
    {
        return Err(miette!(
            "Codex model in {} changed outside SecretSpec; refusing to replace it",
            path.display()
        ));
    }
    if current_model_provider(config, path)?.as_deref() != Some(&managed.model_provider) {
        return Err(miette!(
            "Codex model_provider in {} changed outside SecretSpec; refusing to replace it",
            path.display()
        ));
    }
    let actual = provider_entry(config, &managed.model_provider, path)?;
    let actual = actual.map(provider_value).transpose()?;
    if actual != Some(provider_value(&expected_provider(managed))?) {
        return Err(miette!(
            "Codex model provider '{}' in {} changed outside SecretSpec; refusing to replace it",
            managed.model_provider,
            path.display()
        ));
    }
    Ok(())
}

fn provider_value(provider: &Item) -> Result<toml::Value> {
    let mut document = DocumentMut::new();
    document.as_table_mut().insert("provider", provider.clone());
    let parsed = toml::from_str::<toml::Value>(&document.to_string())
        .into_diagnostic()
        .wrap_err("Failed to compare the SecretSpec-managed Codex model provider")?;
    parsed
        .get("provider")
        .cloned()
        .ok_or_else(|| miette!("Failed to compare the SecretSpec-managed Codex model provider"))
}

fn remove_owned_provider(
    config: &mut DocumentMut,
    managed: &ManagedConfig,
    path: &Path,
) -> Result<()> {
    if managed.managed_model.is_some() {
        config.as_table_mut().remove("model");
    }
    let providers = providers_table_mut(config, path)?;
    providers.remove(&managed.model_provider);
    if managed.created_model_providers_table && providers.is_empty() {
        config.as_table_mut().remove("model_providers");
    }
    Ok(())
}

fn restore_model_provider(
    config: &mut DocumentMut,
    previous: Option<&str>,
    path: &Path,
) -> Result<()> {
    match previous {
        Some(previous) => {
            config
                .as_table_mut()
                .insert("model_provider", toml_edit::value(previous));
        }
        None => {
            config.as_table_mut().remove("model_provider");
        }
    }
    if current_model_provider(config, path)?.as_deref() != previous {
        return Err(miette!(
            "Failed to restore Codex model_provider in {}",
            path.display()
        ));
    }
    Ok(())
}

fn parse_state(contents: Option<&[u8]>, path: &Path) -> Result<ManagedState> {
    let Some(contents) = contents else {
        return Ok(ManagedState::default());
    };
    let state: ManagedState = serde_json::from_slice(contents)
        .into_diagnostic()
        .wrap_err_with(|| format!("Failed to parse {}", path.display()))?;
    validate_state(&state, path)?;
    Ok(state)
}

fn validate_state(state: &ManagedState, path: &Path) -> Result<()> {
    if state.version != STATE_VERSION {
        return Err(miette!(
            "Unsupported Codex integration state version {} in {}",
            state.version,
            path.display()
        ));
    }
    let mut ids = std::collections::HashSet::new();
    let mut paths = std::collections::HashSet::new();
    for managed in &state.configs {
        if Uuid::parse_str(&managed.id).is_err() {
            return Err(miette!(
                "Invalid Codex configuration identifier in {}",
                path.display()
            ));
        }
        if !ids.insert(&managed.id) || !paths.insert(&managed.config) {
            return Err(miette!(
                "Duplicate Codex integration entry in {}",
                path.display()
            ));
        }
        if !managed.config.is_absolute()
            || managed.model_provider != model_provider_id(&managed.id)
            || managed.managed_model.as_deref().is_some_and(|model| {
                model.trim().is_empty()
                    || model.trim() != model
                    || model.chars().any(|character| character.is_ascii_control())
            })
            || managed.reason.trim().is_empty()
            || managed.resource.trim().is_empty()
            || managed
                .resource
                .chars()
                .any(|character| character.is_ascii_control())
        {
            return Err(miette!(
                "Invalid Codex integration entry in {}",
                path.display()
            ));
        }
        let (base_url, resource) = normalize_base_url(&managed.base_url)?;
        if base_url != managed.base_url || resource != managed.resource {
            return Err(miette!("Invalid Codex API endpoint in {}", path.display()));
        }
        if let Some(provider) = &managed.provider
            && (provider.trim().is_empty()
                || provider
                    .chars()
                    .any(|character| character.is_ascii_control()))
        {
            return Err(miette!("Invalid Codex provider in {}", path.display()));
        }
        if let CredentialSource::Manifest {
            manifest,
            profile,
            token_secret,
        } = &managed.source
            && (!manifest.is_absolute()
                || profile.trim().is_empty()
                || token_secret.trim().is_empty())
        {
            return Err(miette!(
                "Invalid Codex manifest credential source in {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn write_state(path: &Path, state: &ManagedState) -> Result<()> {
    validate_state(state, path)?;
    let mut contents = serde_json::to_vec_pretty(state).into_diagnostic()?;
    contents.push(b'\n');
    write_bytes_atomically(path, &contents, true)
}
