use super::{TypedArgs, load_secrets, shell_quote};
use crate::integration::docker::{
    CredentialSource, EmbeddedDockerCredentials, HELPER_NAME, ManagedCredential, UsernameSource,
    canonical_registry, docker_config_path, load_embedded_docker_credentials, load_state,
    state_entry_path, state_path, valid_username,
};
use crate::{CallerContext, Secrets};
use clap::Subcommand;
use miette::{IntoDiagnostic, Result, WrapErr, miette};
use serde_json::{Map, Value};
use std::fs;
use std::io::{ErrorKind, IsTerminal, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

#[derive(Subcommand)]
pub(super) enum DockerAction {
    #[command(
        about = "Configure Docker to retrieve a registry credential through SecretSpec (0.20+)"
    )]
    Configure {
        #[arg(long, help = "Registry hostname, optionally including a port")]
        registry: String,
        #[arg(long, help = "Custom manifest key containing the password or token")]
        token_secret: Option<String>,
        #[arg(
            long,
            conflicts_with = "username_secret",
            help = "Non-secret username to store in the managed Docker configuration"
        )]
        username: Option<String>,
        #[arg(
            long,
            conflicts_with = "username",
            help = "Custom manifest key containing the username"
        )]
        username_secret: Option<String>,
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
            short,
            long,
            help = "Confirm the Docker configuration change non-interactively"
        )]
        yes: bool,
    },
    #[command(
        about = "Store a Docker registry credential in the embedded SecretSpec store (0.20+)"
    )]
    Login {
        #[arg(help = "Registry hostname, optionally including a port")]
        registry: String,
        #[arg(
            short,
            long,
            env = "SECRETSPEC_PROVIDER",
            help = "Provider override to store the credential in"
        )]
        provider: Option<String>,
    },
    #[command(
        about = "Remove a Docker registry credential from the embedded SecretSpec store (0.20+)"
    )]
    Logout {
        #[arg(help = "Registry hostname, optionally including a port")]
        registry: String,
        #[arg(
            short,
            long,
            env = "SECRETSPEC_PROVIDER",
            help = "Provider override to remove the credential from"
        )]
        provider: Option<String>,
    },
    #[command(about = "Remove Docker credential configuration managed by SecretSpec (0.20+)")]
    Unconfigure {
        #[arg(
            long,
            required_unless_present = "all",
            conflicts_with = "all",
            help = "Registry whose managed credential should be removed"
        )]
        registry: Option<String>,
        #[arg(long, help = "Remove every Docker credential managed by SecretSpec")]
        all: bool,
        #[arg(
            short,
            long,
            help = "Confirm the Docker configuration change non-interactively"
        )]
        yes: bool,
    },
}

pub(super) fn run(
    action: DockerAction,
    file: &Option<PathBuf>,
    reason: &Option<String>,
    caller: &Option<CallerContext>,
    typed: TypedArgs,
) -> Result<()> {
    let file = if typed.file { file.clone() } else { None };
    let file = &file;
    match action {
        DockerAction::Configure {
            registry,
            token_secret,
            username,
            username_secret,
            profile,
            provider,
            yes,
        } => configure(ConfigureOptions {
            registry,
            token_secret,
            username,
            username_secret,
            profile,
            provider,
            yes,
            file,
            reason,
            caller,
            typed,
        }),
        DockerAction::Login { registry, provider } => {
            login(registry, provider, file, reason, caller)
        }
        DockerAction::Logout { registry, provider } => {
            logout(registry, provider, file, reason, caller)
        }
        DockerAction::Unconfigure { registry, all, yes } => unconfigure(registry, all, yes),
    }
}

struct ConfigureOptions<'a> {
    registry: String,
    token_secret: Option<String>,
    username: Option<String>,
    username_secret: Option<String>,
    profile: Option<String>,
    provider: Option<String>,
    yes: bool,
    file: &'a Option<PathBuf>,
    reason: &'a Option<String>,
    caller: &'a Option<CallerContext>,
    typed: TypedArgs,
}

fn configure(options: ConfigureOptions<'_>) -> Result<()> {
    let registry = canonical_registry(&options.registry).map_err(|error| miette!(error))?;
    let docker_config = docker_config_path().map_err(|error| miette!(error))?;
    let (mut secrets, source, manifest) = if options.file.is_some() {
        let token_secret = options.token_secret.as_deref().ok_or_else(|| {
            miette!("--token-secret is required when --file selects a custom manifest")
        })?;
        let username = match (options.username, options.username_secret) {
            (Some(username), None) => {
                validate_literal_username(&username)?;
                UsernameSource::Literal(username)
            }
            (None, Some(secret)) => UsernameSource::Secret(secret),
            (None, None) => {
                return Err(miette!(
                    "--username or --username-secret is required when --file selects a custom manifest"
                ));
            }
            (Some(_), Some(_)) => unreachable!("clap rejects conflicting username options"),
        };
        let manifest = manifest_path(options.file)?;
        let mut secrets = load_secrets(options.file, options.reason, options.caller)?;
        if let Some(profile) = &options.profile {
            secrets.set_profile(profile);
        }
        let profile = secrets.resolve_profile_name(None);
        validate_secret(&secrets, token_secret, &profile)?;
        if let UsernameSource::Secret(secret) = &username {
            validate_secret(&secrets, secret, &profile)?;
        }
        (
            secrets,
            CredentialSource::Manifest {
                manifest: manifest.clone(),
                profile,
                username,
                password_secret: token_secret.to_string(),
            },
            Some(manifest),
        )
    } else {
        if options.token_secret.is_some()
            || options.username_secret.is_some()
            || options.typed.profile
        {
            return Err(miette!(
                "--token-secret, --username-secret, and --profile require --file; the embedded Docker credential store uses PASSWORD and the default profile"
            ));
        }
        let username = options.username.ok_or_else(|| {
            miette!("--username is required when using the embedded Docker credential store")
        })?;
        validate_literal_username(&username)?;
        (
            load_embedded_docker_credentials(&registry, &docker_config)
                .map_err(|error| miette!(error))?
                .secrets,
            CredentialSource::Embedded { username },
            None,
        )
    };
    if let Some(provider) = &options.provider {
        secrets.set_provider(provider);
    }

    let persisted_provider = options
        .typed
        .provider
        .then_some(options.provider.as_deref())
        .flatten();
    let persisted_reason = options
        .typed
        .reason
        .then_some(options.reason.as_deref())
        .flatten();

    let original_docker = read_optional(&docker_config)?;
    let mut docker = parse_docker_config(original_docker.as_deref(), &docker_config)?;
    let existing_helper = credential_helper(&docker, &registry)?;
    let state_file = state_path().map_err(|error| miette!(error))?;
    let original_state = read_optional(&state_file)?;
    let mut state = load_state().map_err(|error| miette!(error))?;
    let existing_index = state.credentials.iter().position(|credential| {
        credential.registry == registry && credential.docker_config == docker_config
    });
    if let Some(helper) = existing_helper
        && helper != HELPER_NAME
    {
        return Err(miette!(
            "Docker registry '{registry}' already uses credential helper '{helper}'; refusing to replace it"
        ));
    }
    if existing_helper == Some(HELPER_NAME) && existing_index.is_none() {
        return Err(miette!(
            "Docker registry '{registry}' already names the SecretSpec helper but is not managed by this configuration; remove that entry manually before configuring it"
        ));
    }

    let credential = ManagedCredential {
        registry: registry.clone(),
        docker_config: docker_config.clone(),
        provider: persisted_provider.map(str::to_string),
        reason: persisted_reason.map(str::to_string),
        source,
    };
    let state_changed = match existing_index {
        Some(index) if state.credentials[index] == credential => false,
        Some(index) => {
            state.credentials[index] = credential;
            true
        }
        None => {
            state.credentials.push(credential);
            true
        }
    };
    let replaced = existing_index.is_some() && state_changed;
    let docker_changed = existing_helper != Some(HELPER_NAME);
    if !state_changed && !docker_changed {
        println!("Docker credential for {registry} is already configured.");
        return Ok(());
    }
    if !confirm(
        options.yes,
        &format!("Configure Docker credential for {registry}?"),
    )? {
        return Ok(());
    }

    ensure_unchanged(&docker_config, original_docker.as_deref())?;
    ensure_unchanged(&state_file, original_state.as_deref())?;
    set_credential_helper(&mut docker, &registry, HELPER_NAME)?;
    write_json_atomically(
        &state_file,
        &serde_json::to_value(&state).into_diagnostic()?,
        true,
    )?;
    if let Err(error) = ensure_unchanged(&docker_config, original_docker.as_deref()) {
        restore_file(&state_file, original_state.as_deref(), true)?;
        return Err(error);
    }
    if let Err(error) = write_json_atomically(&docker_config, &docker, false) {
        restore_file(&state_file, original_state.as_deref(), true)?;
        return Err(error);
    }

    println!("Configured Docker credential for {registry}.");
    if replaced {
        println!(
            "Replaced the previous SecretSpec configuration for {registry}. No stored credential was removed."
        );
    }
    println!("Docker configuration: {}", docker_config.display());
    if let Some(manifest) = manifest {
        println!("SecretSpec manifest: {}", manifest.display());
    } else {
        let mut login = format!("secretspec docker login {}", shell_quote(&registry));
        if let Some(provider) = persisted_provider {
            login.push_str(" --provider ");
            login.push_str(&shell_quote(provider));
        }
        println!("Store the credential with: {login}");
        if persisted_provider.is_none() && options.provider.is_some() {
            println!(
                "Note: SECRETSPEC_PROVIDER was not recorded in the Docker helper; pass --provider to pin it."
            );
        }
    }
    println!(
        "Undo with: secretspec docker unconfigure --registry {}",
        shell_quote(&registry)
    );
    Ok(())
}

fn embedded_cli_secrets(
    registry: &str,
    docker_config: &Path,
    provider: Option<&str>,
    file: &Option<PathBuf>,
    reason: &Option<String>,
    caller: &Option<CallerContext>,
    action: &str,
) -> Result<EmbeddedDockerCredentials> {
    if file.is_some() {
        return Err(miette!(
            "secretspec docker {action} manages the embedded Docker credential store; omit --file and use secretspec set or delete for a custom manifest"
        ));
    }
    let mut embedded = load_embedded_docker_credentials(registry, docker_config)
        .map_err(|error| miette!(error))?;
    if let Some(provider) = provider {
        embedded.secrets.set_provider(provider);
    }
    if let Some(reason) = reason {
        embedded.secrets = embedded.secrets.with_reason(reason.clone());
    }
    let caller = caller.clone().unwrap_or_else(|| {
        CallerContext::new("docker")
            .with_operation(format!("credential_{action}"))
            .with_resource(registry)
    });
    embedded.secrets = embedded.secrets.with_caller(caller);
    embedded.secrets.set_write_target_reporter(|target| {
        eprintln!(
            "Writing secret '{}' to {} (profile: {})\n  target: {}",
            target.name, target.provider_uri, target.profile, target.target
        );
    });
    Ok(embedded)
}

fn login(
    registry: String,
    provider: Option<String>,
    file: &Option<PathBuf>,
    reason: &Option<String>,
    caller: &Option<CallerContext>,
) -> Result<()> {
    let registry = canonical_registry(&registry).map_err(|error| miette!(error))?;
    let docker_config = docker_config_path().map_err(|error| miette!(error))?;
    let embedded = embedded_cli_secrets(
        &registry,
        &docker_config,
        provider.as_deref(),
        file,
        reason,
        caller,
        "login",
    )?;
    embedded
        .secrets
        .set(&embedded.password_secret, None)
        .into_diagnostic()
        .wrap_err("Failed to store Docker password or token")?;
    println!("Stored Docker credential for {registry}.");
    Ok(())
}

fn logout(
    registry: String,
    provider: Option<String>,
    file: &Option<PathBuf>,
    reason: &Option<String>,
    caller: &Option<CallerContext>,
) -> Result<()> {
    let registry = canonical_registry(&registry).map_err(|error| miette!(error))?;
    let docker_config = docker_config_path().map_err(|error| miette!(error))?;
    let embedded = embedded_cli_secrets(
        &registry,
        &docker_config,
        provider.as_deref(),
        file,
        reason,
        caller,
        "logout",
    )?;
    if embedded
        .secrets
        .delete(&embedded.password_secret)
        .into_diagnostic()
        .wrap_err("Failed to remove Docker password or token")?
    {
        println!("Removed stored Docker credential for {registry}.");
    } else {
        println!("No stored Docker credential for {registry} was found.");
    }
    Ok(())
}

fn unconfigure(registry: Option<String>, all: bool, yes: bool) -> Result<()> {
    let registry = registry
        .as_deref()
        .map(canonical_registry)
        .transpose()
        .map_err(|error| miette!(error))?;
    let docker_config = docker_config_path().map_err(|error| miette!(error))?;
    let original_docker = read_optional(&docker_config)?;
    let mut docker = parse_docker_config(original_docker.as_deref(), &docker_config)?;
    let state_entry = state_entry_path().map_err(|error| miette!(error))?;
    let state_file = state_path().map_err(|error| miette!(error))?;
    let original_state = read_optional(&state_file)?;
    let mut state = load_state().map_err(|error| miette!(error))?;

    let selected: Vec<_> = state
        .credentials
        .iter()
        .filter(|credential| {
            credential.docker_config == docker_config
                && (all || registry.as_deref() == Some(&credential.registry))
        })
        .map(|credential| credential.registry.clone())
        .collect();
    if selected.is_empty() {
        println!("No matching SecretSpec-managed Docker credentials found.");
        return Ok(());
    }
    let mut configured = Vec::new();
    for registry in &selected {
        match credential_helper(&docker, registry)? {
            Some(HELPER_NAME) => configured.push(registry.clone()),
            Some(helper) => {
                return Err(miette!(
                    "Docker credential helper for '{registry}' changed to '{helper}'; refusing to modify it"
                ));
            }
            None => {}
        }
    }
    if !confirm(
        yes,
        if all {
            "Remove all SecretSpec-managed Docker credentials from this Docker configuration?"
        } else {
            "Remove this SecretSpec-managed Docker credential?"
        },
    )? {
        return Ok(());
    }
    ensure_unchanged(&docker_config, original_docker.as_deref())?;
    ensure_unchanged(&state_file, original_state.as_deref())?;

    for registry in &configured {
        remove_credential_helper(&mut docker, registry)?;
    }
    state.credentials.retain(|credential| {
        credential.docker_config != docker_config || !selected.contains(&credential.registry)
    });
    if !configured.is_empty() {
        write_json_atomically(&docker_config, &docker, false)?;
    }
    if let Err(error) = ensure_unchanged(&state_file, original_state.as_deref()) {
        if !configured.is_empty() {
            restore_file(&docker_config, original_docker.as_deref(), false)?;
        }
        return Err(error);
    }
    let state_result = if state.credentials.is_empty() {
        match fs::symlink_metadata(&state_entry) {
            Ok(metadata) if metadata.file_type().is_symlink() => write_json_atomically(
                &state_file,
                &serde_json::to_value(&state).into_diagnostic()?,
                true,
            ),
            Ok(_) => fs::remove_file(&state_file)
                .into_diagnostic()
                .wrap_err_with(|| format!("Failed to remove {}", state_file.display())),
            Err(error) => Err(error)
                .into_diagnostic()
                .wrap_err_with(|| format!("Failed to inspect {}", state_entry.display())),
        }
    } else {
        write_json_atomically(
            &state_file,
            &serde_json::to_value(&state).into_diagnostic()?,
            true,
        )
    };
    if let Err(error) = state_result {
        if !configured.is_empty() {
            restore_file(&docker_config, original_docker.as_deref(), false)?;
        }
        return Err(error);
    }
    println!(
        "Removed {} SecretSpec-managed Docker credential{}.",
        selected.len(),
        if selected.len() == 1 { "" } else { "s" }
    );
    Ok(())
}

fn validate_literal_username(username: &str) -> Result<()> {
    if !valid_username(username) {
        return Err(miette!(
            "Docker username cannot be empty or contain control characters"
        ));
    }
    Ok(())
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
            "Secret '{name}' uses as_path and cannot be returned as a Docker credential"
        ));
    }
    Ok(())
}

fn manifest_path(file: &Option<PathBuf>) -> Result<PathBuf> {
    let path = match file {
        Some(path) => path.clone(),
        None => crate::secrets::find_config_file().into_diagnostic()?,
    };
    if path.is_absolute() {
        Ok(path)
    } else {
        std::env::current_dir()
            .into_diagnostic()
            .wrap_err("Failed to resolve the current directory")
            .map(|directory| directory.join(path))
    }
}

fn parse_docker_config(contents: Option<&[u8]>, path: &Path) -> Result<Value> {
    match contents {
        Some(contents) => {
            let value: Value = serde_json::from_slice(contents)
                .into_diagnostic()
                .wrap_err_with(|| format!("Failed to parse {}", path.display()))?;
            if !value.is_object() {
                return Err(miette!("{} must contain a JSON object", path.display()));
            }
            Ok(value)
        }
        None => Ok(Value::Object(Map::new())),
    }
}

fn credential_helpers(config: &Value) -> Result<Option<&Map<String, Value>>> {
    match config.get("credHelpers") {
        Some(Value::Object(helpers)) => Ok(Some(helpers)),
        Some(_) => Err(miette!(
            "Docker config field 'credHelpers' must be an object"
        )),
        None => Ok(None),
    }
}

fn credential_helper<'a>(config: &'a Value, registry: &str) -> Result<Option<&'a str>> {
    let Some(value) = credential_helpers(config)?.and_then(|helpers| helpers.get(registry)) else {
        return Ok(None);
    };
    value
        .as_str()
        .map(Some)
        .ok_or_else(|| miette!("Docker credential helper for '{registry}' must be a string"))
}

fn set_credential_helper(config: &mut Value, registry: &str, helper: &str) -> Result<()> {
    let object = config
        .as_object_mut()
        .ok_or_else(|| miette!("Docker configuration must be an object"))?;
    let helpers = object
        .entry("credHelpers")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| miette!("Docker config field 'credHelpers' must be an object"))?;
    helpers.insert(registry.to_string(), Value::String(helper.to_string()));
    Ok(())
}

fn remove_credential_helper(config: &mut Value, registry: &str) -> Result<()> {
    let object = config
        .as_object_mut()
        .ok_or_else(|| miette!("Docker configuration must be an object"))?;
    let remove_field = match object.get_mut("credHelpers") {
        Some(Value::Object(helpers)) => {
            helpers.remove(registry);
            helpers.is_empty()
        }
        Some(_) => {
            return Err(miette!(
                "Docker config field 'credHelpers' must be an object"
            ));
        }
        None => false,
    };
    if remove_field {
        object.remove("credHelpers");
    }
    Ok(())
}

fn confirm(yes: bool, prompt: &str) -> Result<bool> {
    if yes {
        return Ok(true);
    }
    if !std::io::stdin().is_terminal() {
        return Err(miette!(
            "refusing to change Docker configuration without confirmation; pass --yes for non-interactive use"
        ));
    }
    if !inquire::Confirm::new(prompt)
        .with_default(false)
        .prompt()
        .into_diagnostic()?
    {
        println!("Cancelled.");
        return Ok(false);
    }
    Ok(true)
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(contents) => Ok(Some(contents)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error)
            .into_diagnostic()
            .wrap_err_with(|| format!("Failed to read {}", path.display())),
    }
}

fn ensure_unchanged(path: &Path, expected: Option<&[u8]>) -> Result<()> {
    if read_optional(path)?.as_deref() != expected {
        return Err(miette!(
            "{} changed during this operation; no changes were made; rerun the command",
            path.display()
        ));
    }
    Ok(())
}

fn write_json_atomically(path: &Path, value: &Value, owner_only: bool) -> Result<()> {
    let directory = path
        .parent()
        .ok_or_else(|| miette!("{} has no parent directory", path.display()))?;
    fs::create_dir_all(directory)
        .into_diagnostic()
        .wrap_err_with(|| format!("Failed to create {}", directory.display()))?;
    let permissions = (!owner_only)
        .then(|| {
            fs::metadata(path)
                .ok()
                .map(|metadata| metadata.permissions())
        })
        .flatten();
    let mut temporary = NamedTempFile::new_in(directory)
        .into_diagnostic()
        .wrap_err_with(|| format!("Failed to create temporary file in {}", directory.display()))?;
    serde_json::to_writer_pretty(&mut temporary, value).into_diagnostic()?;
    temporary.write_all(b"\n").into_diagnostic()?;
    temporary.flush().into_diagnostic()?;
    if let Some(permissions) = permissions {
        temporary
            .as_file()
            .set_permissions(permissions)
            .into_diagnostic()?;
    } else {
        #[cfg(unix)]
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .into_diagnostic()?;
    }
    temporary.as_file().sync_all().into_diagnostic()?;
    temporary.persist(path).map_err(|error| {
        miette!(
            "Failed to atomically replace {}: {}",
            path.display(),
            error.error
        )
    })?;
    Ok(())
}

fn restore_file(path: &Path, contents: Option<&[u8]>, owner_only: bool) -> Result<()> {
    match contents {
        Some(contents) => {
            let directory = path
                .parent()
                .ok_or_else(|| miette!("{} has no parent directory", path.display()))?;
            let permissions = (!owner_only)
                .then(|| {
                    fs::metadata(path)
                        .ok()
                        .map(|metadata| metadata.permissions())
                })
                .flatten();
            let mut temporary = NamedTempFile::new_in(directory).into_diagnostic()?;
            temporary.write_all(contents).into_diagnostic()?;
            temporary.flush().into_diagnostic()?;
            if let Some(permissions) = permissions {
                temporary
                    .as_file()
                    .set_permissions(permissions)
                    .into_diagnostic()?;
            } else {
                #[cfg(unix)]
                temporary
                    .as_file()
                    .set_permissions(fs::Permissions::from_mode(0o600))
                    .into_diagnostic()?;
            }
            temporary.as_file().sync_all().into_diagnostic()?;
            temporary.persist(path).map_err(|error| {
                miette!("Failed to restore {}: {}", path.display(), error.error)
            })?;
        }
        None => {
            if path.try_exists().into_diagnostic()? {
                fs::remove_file(path).into_diagnostic()?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    use tempfile::TempDir;

    #[test]
    fn preserves_unrelated_docker_configuration() {
        let mut config = serde_json::json!({
            "auths": {"example.com": {"auth": "encoded"}},
            "credsStore": "desktop",
            "credHelpers": {"existing.example.com": "pass"},
            "plugins": {"debug": {"hooks": "exec"}}
        });
        set_credential_helper(&mut config, "ghcr.io", HELPER_NAME).unwrap();
        assert_eq!(
            credential_helper(&config, "ghcr.io").unwrap(),
            Some("secretspec")
        );
        remove_credential_helper(&mut config, "ghcr.io").unwrap();
        assert_eq!(
            credential_helper(&config, "existing.example.com").unwrap(),
            Some("pass")
        );
        assert_eq!(config["credsStore"], "desktop");
        assert_eq!(config["auths"]["example.com"]["auth"], "encoded");
        assert_eq!(config["plugins"]["debug"]["hooks"], "exec");
    }

    #[test]
    fn rejects_invalid_credential_helpers_shape() {
        let config = serde_json::json!({"credHelpers": []});
        assert!(credential_helper(&config, "ghcr.io").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn manifest_path_avoids_a_windows_verbatim_prefix() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("secretspec.toml");
        fs::write(&path, "").unwrap();
        let resolved = manifest_path(&Some(path)).unwrap();
        assert!(!resolved.to_string_lossy().starts_with(r"\\?\"));
    }
}
