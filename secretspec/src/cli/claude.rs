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
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;

const STATE_VERSION: u8 = 1;
const EMBEDDED_SECRET: &str = "CLAUDE_CODE_API_KEY";
const DEFAULT_REASON: &str = "Claude Code model authentication";
const DEFAULT_RESOURCE: &str = "api.anthropic.com";

#[derive(Subcommand)]
pub(super) enum ClaudeAction {
    #[command(
        about = "Configure Claude Code to retrieve an API credential through SecretSpec (0.21+)"
    )]
    Configure {
        #[arg(
            long,
            help = "Custom manifest key containing the API or gateway credential"
        )]
        token_secret: Option<String>,
        #[arg(
            short = 'P',
            long,
            env = "SECRETSPEC_PROFILE",
            help = "Custom manifest profile the helper should use"
        )]
        profile: Option<String>,
        #[arg(
            short,
            long,
            env = "SECRETSPEC_PROVIDER",
            help = "Provider override the helper should use"
        )]
        provider: Option<String>,
        #[arg(
            long,
            default_value = DEFAULT_RESOURCE,
            help = "Non-secret API host recorded as the audit resource"
        )]
        resource: String,
        #[arg(long, help = "Configure the current user's Claude Code settings")]
        global: bool,
        #[arg(
            short,
            long,
            requires = "global",
            help = "Confirm a user-level settings change non-interactively"
        )]
        yes: bool,
    },
    #[command(about = "Store a Claude Code credential in the embedded SecretSpec store (0.21+)")]
    Login {
        #[arg(
            short,
            long,
            env = "SECRETSPEC_PROVIDER",
            help = "Override the configured provider for this operation"
        )]
        provider: Option<String>,
        #[arg(long, help = "Use the current user's Claude Code configuration")]
        global: bool,
    },
    #[command(about = "Remove a Claude Code credential from the embedded SecretSpec store (0.21+)")]
    Logout {
        #[arg(
            short,
            long,
            env = "SECRETSPEC_PROVIDER",
            help = "Override the configured provider for this operation"
        )]
        provider: Option<String>,
        #[arg(long, help = "Use the current user's Claude Code configuration")]
        global: bool,
    },
    #[command(about = "Remove Claude Code credential configuration managed by SecretSpec (0.21+)")]
    Unconfigure {
        #[arg(long, help = "Remove the current user's Claude Code configuration")]
        global: bool,
        #[arg(
            short,
            long,
            requires = "global",
            help = "Confirm a user-level settings change non-interactively"
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
struct ManagedSetting {
    id: String,
    settings: PathBuf,
    helper: String,
    provider: Option<String>,
    reason: String,
    resource: String,
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
    settings: Vec<ManagedSetting>,
}

impl Default for ManagedState {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            settings: Vec::new(),
        }
    }
}

pub(super) fn run(
    action: ClaudeAction,
    file: &Option<PathBuf>,
    reason: &Option<String>,
    caller: &Option<CallerContext>,
    typed: TypedArgs,
) -> Result<()> {
    let file = typed.file.then(|| file.clone()).flatten();
    match action {
        ClaudeAction::Configure {
            token_secret,
            profile,
            provider,
            resource,
            global,
            yes,
        } => configure(ConfigureOptions {
            token_secret,
            profile,
            provider,
            resource,
            global,
            yes,
            file,
            reason,
            typed,
        }),
        ClaudeAction::Login { provider, global } => login(provider, global, &file, reason, caller),
        ClaudeAction::Logout { provider, global } => {
            logout(provider, global, &file, reason, caller)
        }
        ClaudeAction::Unconfigure { global, yes } => unconfigure(global, yes),
        ClaudeAction::Credential { configuration } => credential(&configuration, &file, caller),
    }
}

struct ConfigureOptions<'a> {
    token_secret: Option<String>,
    profile: Option<String>,
    provider: Option<String>,
    resource: String,
    global: bool,
    yes: bool,
    file: Option<PathBuf>,
    reason: &'a Option<String>,
    typed: TypedArgs,
}

fn configure(options: ConfigureOptions<'_>) -> Result<()> {
    validate_resource(&options.resource)?;
    let settings_path = settings_path(options.global)?;
    let source = match &options.file {
        Some(file) => {
            let token_secret = options.token_secret.as_deref().ok_or_else(|| {
                miette!("--token-secret is required when --file selects a custom manifest")
            })?;
            let manifest = manifest_path(file)?;
            let mut secrets = Secrets::load_from(&manifest)
                .into_diagnostic()
                .wrap_err("Failed to load custom Claude Code credential manifest")?;
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
                    "--token-secret and --profile require --file; the embedded Claude Code credential store uses its built-in declaration"
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

    let original_settings = read_optional(&settings_path)?;
    let mut settings = parse_settings(original_settings.as_deref(), &settings_path)?;
    let state_file = state_path()?;
    let original_state = read_optional(&state_file)?;
    let mut state = parse_state(original_state.as_deref(), &state_file)?;
    let existing_index = state
        .settings
        .iter()
        .position(|setting| setting.settings == settings_path);
    let id = existing_index
        .map(|index| state.settings[index].id.clone())
        .unwrap_or_else(|| Uuid::new_v4().simple().to_string());
    let helper = helper_command(&id);
    let existing_helper = api_key_helper(&settings, &settings_path)?;

    match existing_index {
        Some(index) => {
            if let Some(existing_helper) = existing_helper
                && existing_helper != state.settings[index].helper
            {
                return Err(miette!(
                    "Claude Code apiKeyHelper in {} changed outside SecretSpec; refusing to replace it",
                    settings_path.display()
                ));
            }
        }
        None if existing_helper.is_some() => {
            return Err(miette!(
                "Claude Code apiKeyHelper in {} is not managed by SecretSpec; refusing to replace it",
                settings_path.display()
            ));
        }
        None => {}
    }

    let desired = ManagedSetting {
        id,
        settings: settings_path.clone(),
        helper: helper.clone(),
        provider,
        reason,
        resource: options.resource,
        source,
        configured: true,
    };
    let state_changed = match existing_index {
        Some(index) if state.settings[index] == desired => false,
        Some(index) => {
            state.settings[index] = desired;
            true
        }
        None => {
            state.settings.push(desired);
            true
        }
    };
    let settings_changed = existing_helper != Some(helper.as_str());
    if !state_changed && !settings_changed {
        println!(
            "Claude Code credential integration is already configured in {}.",
            settings_path.display()
        );
        return Ok(());
    }
    if options.global
        && !confirm(
            options.yes,
            "Configure the current user's Claude Code API credential helper?",
        )?
    {
        return Ok(());
    }

    ensure_unchanged(&settings_path, original_settings.as_deref())?;
    ensure_unchanged(&state_file, original_state.as_deref())?;
    set_api_key_helper(&mut settings, &helper, &settings_path)?;
    if state_changed {
        write_json_atomically(
            &state_file,
            &serde_json::to_value(&state).into_diagnostic()?,
            true,
        )?;
    }
    if settings_changed && let Err(error) = write_json_atomically(&settings_path, &settings, false)
    {
        if state_changed {
            restore_file(&state_file, original_state.as_deref(), true)?;
        }
        return Err(error);
    }

    println!(
        "Configured Claude Code credential integration in {}.",
        settings_path.display()
    );
    let configured = state
        .settings
        .iter()
        .find(|setting| setting.settings == settings_path)
        .expect("configured state entry exists");
    match &configured.source {
        CredentialSource::Embedded => {
            let mut login = "secretspec claude login".to_string();
            if options.global {
                login.push_str(" --global");
            }
            println!("Store the credential with: {login}");
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
            println!("Store the credential with: {set}");
        }
    }
    let scope = if options.global { " --global" } else { "" };
    println!("Undo with: secretspec claude unconfigure{scope}");
    if !options.global {
        println!(
            "Keep {} out of version control; it contains a machine-local SecretSpec configuration identifier.",
            settings_path.display()
        );
    }
    if !options.typed.provider && options.provider.is_some() {
        println!(
            "Note: SECRETSPEC_PROVIDER was not recorded in the Claude Code helper; pass --provider to pin it."
        );
    }
    if !options.typed.reason && options.reason.is_some() {
        println!(
            "Note: SECRETSPEC_REASON was not recorded in the Claude Code helper; pass --reason to pin it."
        );
    }
    Ok(())
}

fn login(
    provider: Option<String>,
    global: bool,
    file: &Option<PathBuf>,
    reason: &Option<String>,
    caller: &Option<CallerContext>,
) -> Result<()> {
    let setting = lifecycle_setting(global, file)?;
    if !setting.configured {
        let scope = if global { " --global" } else { "" };
        return Err(miette!(
            "Claude Code credential integration is not active for this scope; rerun secretspec claude configure{scope} before login"
        ));
    }
    let (secrets, secret) =
        embedded_cli_secrets(&setting, provider.as_deref(), reason, caller, "login")?;
    let value = read_credential("Enter Claude Code API or gateway credential:")?;
    validate_credential_value(&value)?;
    secrets
        .set(&secret, Some(value))
        .into_diagnostic()
        .wrap_err("Failed to store Claude Code API credential")?;
    println!("Stored Claude Code API credential.");
    Ok(())
}

fn logout(
    provider: Option<String>,
    global: bool,
    file: &Option<PathBuf>,
    reason: &Option<String>,
    caller: &Option<CallerContext>,
) -> Result<()> {
    let setting = lifecycle_setting(global, file)?;
    let (secrets, secret) =
        embedded_cli_secrets(&setting, provider.as_deref(), reason, caller, "logout")?;
    if secrets
        .delete(&secret)
        .into_diagnostic()
        .wrap_err("Failed to remove Claude Code API credential")?
    {
        println!("Removed stored Claude Code API credential.");
    } else {
        println!("No stored Claude Code API credential was found.");
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
            "secretspec claude credential uses the manifest recorded by configure; omit --file"
        ));
    }
    let state_file = state_path()?;
    let state = parse_state(read_optional(&state_file)?.as_deref(), &state_file)?;
    let setting = state
        .settings
        .iter()
        .find(|setting| setting.id == configuration)
        .ok_or_else(|| miette!("Claude Code credential configuration was not found"))?;
    if !setting.configured {
        return Err(miette!(
            "Claude Code credential configuration is not active; rerun secretspec claude configure"
        ));
    }
    let (mut secrets, secret) = secrets_for_setting(setting)?;
    if let Some(provider) = &setting.provider {
        secrets.set_provider(provider);
    }
    secrets = secrets.with_reason(&setting.reason);
    let caller = caller.clone().unwrap_or_else(|| {
        CallerContext::new("claude-code")
            .with_operation("credential_get")
            .with_resource(&setting.resource)
    });
    secrets = secrets.with_caller(caller);
    validate_secret(&secrets, &secret, &secrets.resolve_profile_name(None))?;
    match secrets.resolve_named(&secret).into_diagnostic()? {
        NamedResolution::Resolved(resolved) => {
            let value = resolved.value.ok_or_else(|| {
                miette!("Claude Code credential cannot be returned as a file path")
            })?;
            validate_credential_value(&value)?;
            println!("{value}");
            Ok(())
        }
        NamedResolution::Missing { .. } => Err(miette!("Claude Code API credential is not stored")),
        NamedResolution::Undeclared => Err(miette!(
            "Claude Code credential secret '{secret}' is not declared"
        )),
    }
}

fn unconfigure(global: bool, yes: bool) -> Result<()> {
    let settings_path = settings_path(global)?;
    let state_file = state_path()?;
    let original_state = read_optional(&state_file)?;
    let mut state = parse_state(original_state.as_deref(), &state_file)?;
    let Some(index) = state
        .settings
        .iter()
        .position(|setting| setting.settings == settings_path)
    else {
        println!("No matching SecretSpec-managed Claude Code integration found.");
        return Ok(());
    };
    if !state.settings[index].configured {
        println!("No matching active SecretSpec-managed Claude Code integration found.");
        return Ok(());
    }
    let managed = state.settings[index].clone();
    let original_settings = read_optional(&settings_path)?;
    let mut settings = parse_settings(original_settings.as_deref(), &settings_path)?;
    let existing_helper = api_key_helper(&settings, &settings_path)?.map(str::to_string);
    if let Some(existing_helper) = existing_helper.as_deref()
        && existing_helper != managed.helper
    {
        return Err(miette!(
            "Claude Code apiKeyHelper in {} changed outside SecretSpec; refusing to remove it",
            settings_path.display()
        ));
    }
    if global
        && !confirm(
            yes,
            "Remove the current user's SecretSpec-managed Claude Code API credential helper?",
        )?
    {
        return Ok(());
    }

    ensure_unchanged(&settings_path, original_settings.as_deref())?;
    ensure_unchanged(&state_file, original_state.as_deref())?;
    if existing_helper.is_some() {
        remove_api_key_helper(&mut settings, &settings_path)?;
        write_json_atomically(&settings_path, &settings, false)?;
    }
    state.settings[index].configured = false;
    if let Err(error) = write_json_atomically(
        &state_file,
        &serde_json::to_value(&state).into_diagnostic()?,
        true,
    ) {
        if existing_helper.is_some() {
            restore_file(&settings_path, original_settings.as_deref(), false)?;
        }
        return Err(error);
    }
    println!(
        "Removed SecretSpec-managed Claude Code integration from {}.",
        settings_path.display()
    );
    Ok(())
}

fn lifecycle_setting(global: bool, file: &Option<PathBuf>) -> Result<ManagedSetting> {
    if file.is_some() {
        return Err(miette!(
            "secretspec claude login and logout use the manifest recorded by configure; omit --file"
        ));
    }
    let settings = settings_path(global)?;
    let state_file = state_path()?;
    let state = parse_state(read_optional(&state_file)?.as_deref(), &state_file)?;
    state
        .settings
        .into_iter()
        .find(|setting| setting.settings == settings)
        .ok_or_else(|| {
            let scope = if global { " --global" } else { "" };
            miette!(
                "Claude Code credential integration is not configured for this scope; run secretspec claude configure{scope} first"
            )
        })
}

fn embedded_cli_secrets(
    setting: &ManagedSetting,
    provider: Option<&str>,
    reason: &Option<String>,
    caller: &Option<CallerContext>,
    action: &str,
) -> Result<(Secrets, String)> {
    if !matches!(setting.source, CredentialSource::Embedded) {
        return Err(miette!(
            "this Claude Code integration uses a custom manifest; use secretspec set or delete with that manifest"
        ));
    }
    let (mut secrets, secret) = embedded_secrets(setting)?;
    if let Some(provider) = provider.or(setting.provider.as_deref()) {
        secrets.set_provider(provider);
    }
    secrets = secrets.with_reason(reason.as_deref().unwrap_or(&setting.reason));
    let caller = caller.clone().unwrap_or_else(|| {
        CallerContext::new("claude-code")
            .with_operation(format!("credential_{action}"))
            .with_resource(&setting.resource)
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

fn embedded_secrets(setting: &ManagedSetting) -> Result<(Secrets, String)> {
    let mut digest = Sha256::new();
    digest.update(setting.settings.as_os_str().as_encoded_bytes());
    digest.update([0]);
    digest.update(setting.resource.as_bytes());
    let identity = data_encoding::HEXLOWER.encode(&digest.finalize());
    let secret = format!("{EMBEDDED_SECRET}_{}", identity.to_ascii_uppercase());
    let spec = Spec::builder(format!("claude-code-credential-{identity}"))
        .secret(
            secret.clone(),
            Secret::required("API or gateway credential used by Claude Code"),
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

fn secrets_for_setting(setting: &ManagedSetting) -> Result<(Secrets, String)> {
    match &setting.source {
        CredentialSource::Embedded => embedded_secrets(setting),
        CredentialSource::Manifest {
            manifest,
            profile,
            token_secret,
        } => {
            let mut secrets = Secrets::load_from(manifest)
                .into_diagnostic()
                .wrap_err("Failed to load custom Claude Code credential manifest")?;
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
            "Secret '{name}' uses as_path and cannot be returned as a Claude Code credential"
        ));
    }
    Ok(())
}

fn validate_resource(resource: &str) -> Result<()> {
    if resource.trim().is_empty()
        || resource
            .chars()
            .any(|character| character.is_ascii_control())
    {
        return Err(miette!(
            "Claude Code audit resource cannot be empty or contain control characters"
        ));
    }
    Ok(())
}

fn settings_path(global: bool) -> Result<PathBuf> {
    let path = if global {
        claude_config_dir()?.join("settings.json")
    } else {
        project_settings_root()?.join(".claude/settings.local.json")
    };
    resolve_path(&path)
}

fn claude_config_dir() -> Result<PathBuf> {
    match std::env::var_os("CLAUDE_CONFIG_DIR").filter(|value| !value.is_empty()) {
        Some(path) => resolve_path(Path::new(&path)),
        None => {
            let home = etcetera::home_dir()
                .into_diagnostic()
                .wrap_err("Failed to locate the user home directory")?;
            resolve_path(&home.join(".claude"))
        }
    }
}

fn project_settings_root() -> Result<PathBuf> {
    let current = std::env::current_dir()
        .into_diagnostic()
        .wrap_err("Failed to resolve the current directory")?;
    let output = match Command::new("git")
        .args([
            "rev-parse",
            "--path-format=absolute",
            "--git-common-dir",
            "--show-toplevel",
        ])
        .current_dir(&current)
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => return resolve_path(&current),
    };
    let output = String::from_utf8(output.stdout)
        .into_diagnostic()
        .wrap_err("Git returned a non-UTF-8 repository path")?;
    let mut lines = output.lines();
    let common = lines
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| miette!("Git did not return its common directory"))?;
    let checkout = lines
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| miette!("Git did not return its checkout root"))?;
    let root = if common.file_name().is_some_and(|name| name == ".git") {
        common
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| miette!("Git common directory has no parent"))?
    } else {
        checkout
    };
    let root = resolve_path(&root)?;
    let home = etcetera::home_dir()
        .into_diagnostic()
        .wrap_err("Failed to locate the user home directory")?;
    if root == resolve_path(&home)? {
        resolve_path(&current)
    } else {
        Ok(root)
    }
}

fn state_path() -> Result<PathBuf> {
    let config = GlobalConfig::path().into_diagnostic()?;
    let directory = config
        .parent()
        .ok_or_else(|| miette!("SecretSpec config path has no parent directory"))?;
    resolve_path(&directory.join("claude-code.json"))
}

fn helper_command(id: &str) -> String {
    format!("secretspec claude credential --configuration {id}")
}

fn parse_state(contents: Option<&[u8]>, path: &Path) -> Result<ManagedState> {
    let Some(contents) = contents else {
        return Ok(ManagedState::default());
    };
    let state: ManagedState = serde_json::from_slice(contents)
        .into_diagnostic()
        .wrap_err_with(|| format!("Failed to parse {}", path.display()))?;
    if state.version != STATE_VERSION {
        return Err(miette!(
            "Unsupported Claude Code integration state version {} in {}",
            state.version,
            path.display()
        ));
    }
    let mut ids = std::collections::HashSet::new();
    let mut paths = std::collections::HashSet::new();
    for setting in &state.settings {
        if Uuid::parse_str(&setting.id).is_err() {
            return Err(miette!(
                "Invalid Claude Code configuration identifier in {}",
                path.display()
            ));
        }
        if !ids.insert(&setting.id) || !paths.insert(&setting.settings) {
            return Err(miette!(
                "Duplicate Claude Code integration entry in {}",
                path.display()
            ));
        }
        if setting.helper != helper_command(&setting.id) {
            return Err(miette!(
                "Invalid Claude Code helper command in {}",
                path.display()
            ));
        }
        if !setting.settings.is_absolute() {
            return Err(miette!(
                "Claude Code settings path in {} must be absolute",
                path.display()
            ));
        }
        validate_resource(&setting.resource)?;
        if setting.reason.trim().is_empty() {
            return Err(miette!(
                "Invalid empty Claude Code access reason in {}",
                path.display()
            ));
        }
        if let Some(provider) = &setting.provider
            && (provider.trim().is_empty()
                || provider
                    .chars()
                    .any(|character| character.is_ascii_control()))
        {
            return Err(miette!(
                "Invalid Claude Code provider in {}",
                path.display()
            ));
        }
        if let CredentialSource::Manifest {
            manifest,
            profile,
            token_secret,
        } = &setting.source
            && (!manifest.is_absolute()
                || profile.trim().is_empty()
                || token_secret.trim().is_empty())
        {
            return Err(miette!(
                "Invalid Claude Code manifest credential source in {}",
                path.display()
            ));
        }
    }
    Ok(state)
}

fn parse_settings(contents: Option<&[u8]>, path: &Path) -> Result<Value> {
    let settings = match contents {
        Some(contents) => serde_json::from_slice(contents)
            .into_diagnostic()
            .wrap_err_with(|| format!("Failed to parse {}", path.display()))?,
        None => serde_json::json!({}),
    };
    if !settings.is_object() {
        return Err(miette!(
            "Claude Code settings in {} must be a JSON object",
            path.display()
        ));
    }
    Ok(settings)
}

fn api_key_helper<'a>(settings: &'a Value, path: &Path) -> Result<Option<&'a str>> {
    let Some(value) = settings.get("apiKeyHelper") else {
        return Ok(None);
    };
    value.as_str().map(Some).ok_or_else(|| {
        miette!(
            "Claude Code apiKeyHelper in {} must be a string",
            path.display()
        )
    })
}

fn set_api_key_helper(settings: &mut Value, helper: &str, path: &Path) -> Result<()> {
    settings
        .as_object_mut()
        .ok_or_else(|| {
            miette!(
                "Claude Code settings in {} must be an object",
                path.display()
            )
        })?
        .insert(
            "apiKeyHelper".to_string(),
            Value::String(helper.to_string()),
        );
    Ok(())
}

fn remove_api_key_helper(settings: &mut Value, path: &Path) -> Result<()> {
    settings
        .as_object_mut()
        .ok_or_else(|| {
            miette!(
                "Claude Code settings in {} must be an object",
                path.display()
            )
        })?
        .remove("apiKeyHelper");
    Ok(())
}

fn write_json_atomically(path: &Path, value: &Value, owner_only: bool) -> Result<()> {
    let mut contents = serde_json::to_vec_pretty(value).into_diagnostic()?;
    contents.push(b'\n');
    write_bytes_atomically(path, &contents, owner_only)
}
