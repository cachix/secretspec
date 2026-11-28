use super::*;
use crate::prompt::CheckedPrompt;
use std::collections::HashSet;
use std::ffi::{CString, OsString};
use std::fs::{self, OpenOptions};
use std::io::{IsTerminal, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::TempDir;

const CREDENTIALS_DIRECTORY_ENV: &str = "CREDENTIALS_DIRECTORY";
const KEEP_GENERATIONS: usize = 3;

pub(super) fn ensure_root() -> Result<()> {
    if unsafe { libc::geteuid() } == 0 || std::env::var_os("SECRETSPEC_NIXOS_NO_ELEVATE").is_some()
    {
        return Ok(());
    }
    let exe = std::env::current_exe().map_err(SecretSpecError::Io)?;
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let status = Command::new("sudo")
            .arg("--preserve-env=SECRETSPEC_FILE,SECRETSPEC_PROFILE,SECRETSPEC_PROVIDER,SECRETSPEC_REASON")
            .arg(exe)
            .args(args)
            .status()
            .map_err(|error| {
                SecretSpecError::ProviderOperationFailed(format!(
                    "NixOS credential operations must run as root: {error}; rerun with sudo"
                ))
            })?;
    std::process::exit(status.code().unwrap_or(1));
}

pub(super) fn refresh(
    plan: &Plan,
    check: bool,
    no_restart: bool,
    reason: Option<&str>,
    caller: Option<&CallerContext>,
) -> Result<RefreshReport> {
    let _path = PlanPath::apply(plan);
    let _credentials = ProviderCredentials::prepare(plan)?;
    let mut secrets = Secrets::load_from(&plan.manifest)?;
    secrets.set_profile(plan.profile.clone());
    if let Some(reason) = reason {
        secrets = secrets.with_reason(reason.to_string());
    }
    if let Some(caller) = caller {
        secrets = secrets.with_caller(caller.clone());
    }

    let mut values = BTreeMap::new();
    let mut cached = BTreeSet::new();
    let mut errors = Vec::new();

    for secret in &plan.secrets {
        match secrets.resolve_named_bytes(&secret.name) {
            Ok(NamedResolution::Resolved(resolved)) => {
                values.insert(secret.name.clone(), value_from_resolution(resolved)?);
            }
            Ok(NamedResolution::Missing { .. }) | Ok(NamedResolution::Undeclared) => {
                match cached_value(plan, secret)? {
                    Some(value) => {
                        values.insert(secret.name.clone(), value);
                        cached.insert(secret.name.clone());
                    }
                    None if secret.required => errors.push(format!(
                        "required secret '{}' is missing and has no cached value",
                        secret.name
                    )),
                    None => {
                        if let Some(value) = current_value(plan, &secret.name) {
                            values.insert(secret.name.clone(), value);
                        }
                    }
                }
            }
            Err(error) => match cached_value(plan, secret)? {
                Some(value) => {
                    values.insert(secret.name.clone(), value);
                    cached.insert(secret.name.clone());
                }
                None if secret.required => errors.push(format!(
                    "cannot resolve required secret '{}': {error}",
                    secret.name
                )),
                None => {
                    if let Some(value) = current_value(plan, &secret.name) {
                        values.insert(secret.name.clone(), value);
                    }
                }
            },
        }
    }

    if !errors.is_empty() {
        return Err(SecretSpecError::ProviderOperationFailed(errors.join("; ")));
    }

    let templates = render_templates(plan, &values)?;
    let mut report = RefreshReport {
        resolved: values.len().saturating_sub(cached.len()),
        cached: cached.len(),
        templates: templates.len(),
        ..Default::default()
    };

    let changed = changed_names(plan, &values, &templates)?;
    report.changed = changed.len();
    report.unchanged = values.len() + templates.len() - changed.len();

    if check {
        return Ok(report);
    }

    write_generation(plan, &values, &templates)?;
    for secret in &plan.secrets {
        if !secret.cache {
            continue;
        }
        if let Some(value) = values.get(&secret.name) {
            // A cache failure must not discard a successful online refresh.
            if let Err(error) = write_cache(plan, &secret.name, value) {
                eprintln!("secretspec: warning: {error}");
            }
        }
    }

    if plan.restart_units && !no_restart {
        let units: BTreeSet<String> = plan
            .secrets
            .iter()
            .filter(|secret| changed.contains(&secret.name))
            .flat_map(|secret| secret.units.iter().cloned())
            .chain(
                plan.templates
                    .iter()
                    .filter(|template| changed.contains(&template.name))
                    .flat_map(|template| template.units.iter().cloned()),
            )
            .collect();
        report.restarted_units = restart_units(
            plan.systemctl.as_deref().unwrap_or(Path::new("systemctl")),
            &units,
        );
    }
    Ok(report)
}

pub(super) fn link(
    secrets: &Secrets,
    store: &Path,
    force: bool,
    systemd_creds: Option<&Path>,
) -> Result<LinkReport> {
    let systemd_creds = systemd_creds
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("systemd-creds"));
    create_private_dir(store)?;

    let mut report = LinkReport::default();
    let mut seen = HashSet::new();
    for alias in secrets.known_provider_aliases() {
        let credentials = match secrets.declared_provider_credentials(&alias) {
            Ok(credentials) => credentials,
            Err(error) => {
                eprintln!("secretspec: warning: provider '{alias}': {error}");
                continue;
            }
        };
        for (credential_name, source) in credentials {
            if !is_systemd_credential_source(secrets, &source) {
                continue;
            }
            let item = source
                .reference
                .as_ref()
                .map(|reference| reference.item.clone())
                .unwrap_or_else(|| credential_name.clone());
            validate_name("credential", &item)?;
            if !seen.insert(item.clone()) {
                continue;
            }
            let destination = store.join(format!("{item}.cred"));
            if destination.exists() && !force {
                report.skipped.push(item);
                continue;
            }
            if !std::io::stdin().is_terminal() {
                return Err(SecretSpecError::PromptUnavailable(credential_name));
            }
            let prompt = format!(
                "Enter {} for provider '{}' (host-sealed):",
                credential_name, alias
            );
            let entered = inquire::Password::new(&prompt)
                .without_confirmation()
                .prompt_checked()?;
            if entered.is_empty() {
                report.skipped.push(item);
                continue;
            }
            let value = SecretBytes::from_utf8(entered);
            seal_credential(&systemd_creds, &item, &value, &destination)?;
            report.sealed.push(item);
        }
    }

    if report.sealed.is_empty() && report.skipped.is_empty() {
        return Err(SecretSpecError::ProviderOperationFailed(
                "no host-sealed provider credentials were found; declare a \
                 systemd-credential source, for example \
                 `bootstrap = \"systemd-credential://\"` and \
                 `credentials = { token = { provider = \"bootstrap\", ref = { item = \"vault.token\" } } }`"
                    .to_string(),
            ));
    }
    Ok(report)
}

fn is_systemd_credential_source(secrets: &Secrets, source: &crate::CredentialSource) -> bool {
    secrets
        .resolve_provider_spec(source.provider.clone())
        .starts_with("systemd-credential://")
}

struct ProviderCredentials {
    temp: Option<TempDir>,
    previous: Option<std::ffi::OsString>,
}

impl ProviderCredentials {
    fn prepare(plan: &Plan) -> Result<Self> {
        let entries = match fs::read_dir(&plan.credentials_dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    temp: None,
                    previous: None,
                });
            }
            Err(error) => return Err(SecretSpecError::Io(error)),
        };
        let mut credentials: Vec<PathBuf> = entries
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "cred"))
            .collect();
        credentials.sort();
        if credentials.is_empty() {
            return Ok(Self {
                temp: None,
                previous: None,
            });
        }

        fs::create_dir_all(&plan.runtime_dir)?;
        let temp = tempfile::Builder::new()
            .prefix("secretspec-credentials-")
            .tempdir_in(&plan.runtime_dir)?;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))?;
        for path in credentials {
            let name = path
                .file_stem()
                .and_then(|name| name.to_str())
                .ok_or_else(|| {
                    SecretSpecError::InvalidSpec(format!(
                        "invalid sealed credential name '{}'",
                        path.display()
                    ))
                })?;
            validate_name("credential", name)?;
            let value = decrypt_file(&plan.systemd_creds(), &path)?;
            write_private_file(&temp.path().join(name), value.expose_secret())?;
        }
        let previous = std::env::var_os(CREDENTIALS_DIRECTORY_ENV);
        // SAFETY: refresh is a single-threaded CLI operation and this is
        // set before any provider is constructed. The temp directory lives
        // until `ProviderCredentials` is dropped.
        unsafe { std::env::set_var(CREDENTIALS_DIRECTORY_ENV, temp.path()) };
        Ok(Self {
            temp: Some(temp),
            previous,
        })
    }
}

impl Drop for ProviderCredentials {
    fn drop(&mut self) {
        if self.temp.is_some() {
            // SAFETY: same single-threaded initialization contract.
            match &self.previous {
                Some(previous) => unsafe { std::env::set_var(CREDENTIALS_DIRECTORY_ENV, previous) },
                None => unsafe { std::env::remove_var(CREDENTIALS_DIRECTORY_ENV) },
            }
        }
    }
}

/// Adds the provider tool paths from the plan to `PATH` for the lifetime of
/// this guard. The service unit gets these paths from `cfg.extraPackages`;
/// manual `nixos exec`/`nixos refresh` runs need the same environment.
struct PlanPath {
    previous: Option<Option<OsString>>,
}

impl PlanPath {
    fn apply(plan: &Plan) -> Self {
        if plan.path.is_empty() {
            return Self { previous: None };
        }
        let previous = std::env::var_os("PATH");
        let mut value = OsString::from(&plan.path);
        if let Some(previous) = &previous {
            value.push(":");
            value.push(previous);
        }
        // SAFETY: CLI operations are single-threaded and this is set before
        // provider processes are started.
        unsafe { std::env::set_var("PATH", value) };
        Self {
            previous: Some(previous),
        }
    }
}

impl Drop for PlanPath {
    fn drop(&mut self) {
        if let Some(previous) = &self.previous {
            match previous {
                Some(previous) => unsafe { std::env::set_var("PATH", previous) },
                None => unsafe { std::env::remove_var("PATH") },
            }
        }
    }
}

/// Runs a command with the plan manifest, provider credentials, and provider
/// tool paths. This is how interactive operations use the same configuration
/// as `secretspec.service` without installing `bws` or exporting its token.
pub(super) fn exec(plan: &Plan, command: &[String]) -> Result<()> {
    let (program, args) = command.split_first().ok_or_else(|| {
        SecretSpecError::ProviderOperationFailed("nixos exec requires a command".to_string())
    })?;

    let _path = PlanPath::apply(plan);
    let _credentials = ProviderCredentials::prepare(plan)?;

    let mut child = Command::new(program);
    child.args(args);
    child.env("SECRETSPEC_FILE", &plan.manifest);
    child.env("SECRETSPEC_PROFILE", &plan.profile);

    // Make `secretspec` inside the child resolve to the same binary the user
    // invoked, even when it came from `nix run`.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(directory) = exe.parent() {
            let mut paths = vec![directory.to_path_buf()];
            if let Some(path) = std::env::var_os("PATH") {
                paths.extend(std::env::split_paths(&path));
            }
            if let Ok(joined) = std::env::join_paths(paths) {
                child.env("PATH", joined);
            }
        }
    }

    let status = child.status().map_err(SecretSpecError::Io)?;
    if !status.success() {
        return Err(SecretSpecError::ProviderOperationFailed(format!(
            "command '{}' exited with {status}",
            program
        )));
    }
    Ok(())
}

fn cached_value(plan: &Plan, secret: &PlanSecret) -> Result<Option<SecretBytes>> {
    if !secret.cache {
        return Ok(None);
    }
    let path = plan.cache_dir.join(format!("{}.cred", secret.name));
    if !path.exists() {
        return Ok(None);
    }
    decrypt_file(&plan.systemd_creds(), &path).map(Some)
}

fn current_value(plan: &Plan, name: &str) -> Option<SecretBytes> {
    fs::read(plan.runtime_dir.join("current/secrets").join(name))
        .ok()
        .map(SecretBytes::from_vec)
}

fn write_cache(plan: &Plan, name: &str, value: &SecretBytes) -> Result<()> {
    create_private_dir(&plan.cache_dir)?;
    encrypt_atomically(
        &plan.systemd_creds(),
        name,
        value,
        &plan.cache_dir.join(format!("{name}.cred")),
    )
}

fn seal_credential(
    systemd_creds: &Path,
    name: &str,
    value: &SecretBytes,
    destination: &Path,
) -> Result<()> {
    create_private_dir(destination.parent().unwrap_or(Path::new(".")))?;
    encrypt_atomically(systemd_creds, name, value, destination)
}

fn encrypt_atomically(
    systemd_creds: &Path,
    name: &str,
    value: &SecretBytes,
    destination: &Path,
) -> Result<()> {
    let temp = temp_path(destination);
    let _ = fs::remove_file(&temp);
    encrypt_to_file(systemd_creds, name, value, &temp)?;
    fs::set_permissions(&temp, fs::Permissions::from_mode(0o600))?;
    fs::File::open(&temp)?.sync_all()?;
    fs::rename(&temp, destination)?;
    Ok(())
}

fn encrypt_to_file(
    systemd_creds: &Path,
    name: &str,
    value: &SecretBytes,
    destination: &Path,
) -> Result<()> {
    let mut child = Command::new(systemd_creds)
        .args(["encrypt", "--name", name, "--with-key=auto", "-"])
        .arg(destination)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            SecretSpecError::ProviderOperationFailed(format!(
                "failed to run '{}': {error}",
                systemd_creds.display()
            ))
        })?;
    child
        .stdin
        .take()
        .expect("stdin was piped")
        .write_all(value.expose_secret())?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        let _ = fs::remove_file(destination);
        return Err(SecretSpecError::ProviderOperationFailed(format!(
            "'{}' failed: {}",
            systemd_creds.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

fn decrypt_file(systemd_creds: &Path, path: &Path) -> Result<SecretBytes> {
    // systemd compares the embedded credential name with the input file name
    // including the `.cred` suffix, while SecretSpec embeds the item name and
    // writes `<item>.cred`. Pass the canonical item name explicitly so the
    // check uses the name the file was sealed with. A renamed file still fails
    // because neither candidate matches the embedded name.
    let stem = path
        .file_stem()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            SecretSpecError::InvalidSpec(format!(
                "invalid sealed credential path '{}'",
                path.display()
            ))
        })?;
    let full = path.file_name().and_then(|name| name.to_str());

    // Files sealed by the initial NixOS integration used the item name. A
    // short-lived build embedded the full `.cred` name instead; accept both so
    // either credential generation keeps working.
    let mut candidates = vec![stem];
    if let Some(full) = full {
        if full != stem {
            candidates.push(full);
        }
    }

    let mut last_error = String::new();
    for name in candidates {
        let output = run_decrypt(systemd_creds, path, name)?;
        if output.status.success() {
            return Ok(SecretBytes::from_vec(output.stdout));
        }
        last_error = String::from_utf8_lossy(&output.stderr).trim().to_string();
    }

    Err(SecretSpecError::ProviderOperationFailed(format!(
        "'{}' could not decrypt '{}': {last_error}",
        systemd_creds.display(),
        path.display()
    )))
}

fn run_decrypt(systemd_creds: &Path, path: &Path, name: &str) -> Result<std::process::Output> {
    Command::new(systemd_creds)
        .args(["decrypt", "--name", name])
        .arg(path)
        .arg("-")
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| {
            SecretSpecError::ProviderOperationFailed(format!(
                "failed to run '{}': {error}",
                systemd_creds.display()
            ))
        })
}

fn render_templates(plan: &Plan, values: &BTreeMap<String, SecretBytes>) -> Result<Vec<Rendered>> {
    let mut rendered = Vec::with_capacity(plan.templates.len());
    for template in &plan.templates {
        let content = render_template(&template.content, values)?;
        rendered.push(Rendered {
            name: template.name.clone(),
            owner: template.owner.clone(),
            group: template.group.clone(),
            mode: parse_mode(&template.mode)?,
            content,
        });
    }
    Ok(rendered)
}

fn render_template(content: &str, values: &BTreeMap<String, SecretBytes>) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(content.len());
    let mut rest = content;
    while let Some(start) = rest.find(PLACEHOLDER_PREFIX) {
        out.extend_from_slice(&rest.as_bytes()[..start]);
        let after = &rest[start + PLACEHOLDER_PREFIX.len()..];
        let Some(end) = after.find('@') else {
            return Err(SecretSpecError::InvalidSpec(
                "unterminated @secretspec: placeholder in template".to_string(),
            ));
        };
        let name = &after[..end];
        validate_name("placeholder", name)?;
        let value = values.get(name).ok_or_else(|| {
            SecretSpecError::ProviderOperationFailed(format!(
                "template references secret '{name}', which was not resolved"
            ))
        })?;
        out.extend_from_slice(value.expose_secret());
        rest = &after[end + 1..];
    }
    out.extend_from_slice(rest.as_bytes());
    Ok(out)
}

struct Rendered {
    name: String,
    owner: String,
    group: String,
    mode: u32,
    content: Vec<u8>,
}

fn changed_names(
    plan: &Plan,
    values: &BTreeMap<String, SecretBytes>,
    templates: &[Rendered],
) -> Result<BTreeSet<String>> {
    let current = plan.runtime_dir.join("current");
    let mut changed = BTreeSet::new();
    for (name, value) in values {
        if read_current(&current.join("secrets").join(name))
            .is_none_or(|old| old != value.expose_secret())
        {
            changed.insert(name.clone());
        }
    }
    for template in templates {
        if read_current(&current.join("templates").join(&template.name))
            .is_none_or(|old| old != template.content)
        {
            changed.insert(template.name.clone());
        }
    }
    Ok(changed)
}

fn read_current(path: &Path) -> Option<Vec<u8>> {
    fs::read(path).ok()
}

fn write_generation(
    plan: &Plan,
    values: &BTreeMap<String, SecretBytes>,
    templates: &[Rendered],
) -> Result<()> {
    fs::create_dir_all(&plan.runtime_dir)?;
    let generation = plan.runtime_dir.join("generations").join(generation_id());
    fs::create_dir_all(generation.join("secrets"))?;
    fs::create_dir_all(generation.join("templates"))?;
    set_mode(&generation, 0o755)?;
    set_mode(&generation.join("secrets"), 0o755)?;
    set_mode(&generation.join("templates"), 0o755)?;

    for secret in &plan.secrets {
        let Some(value) = values.get(&secret.name) else {
            continue;
        };
        let path = generation.join("secrets").join(&secret.name);
        write_owned_file(
            &path,
            value.expose_secret(),
            &secret.owner,
            &secret.group,
            parse_mode(&secret.mode)?,
        )?;
    }
    for template in templates {
        let path = generation.join("templates").join(&template.name);
        write_owned_file(
            &path,
            &template.content,
            &template.owner,
            &template.group,
            template.mode,
        )?;
    }

    let link = plan.runtime_dir.join("current");
    atomic_symlink(
        Path::new("generations").join(generation_id_from(&generation)?),
        &link,
    )?;
    prune_generations(&plan.runtime_dir.join("generations"));
    Ok(())
}

fn generation_id_from(path: &Path) -> Result<PathBuf> {
    path.file_name()
        .map(PathBuf::from)
        .ok_or_else(|| SecretSpecError::InvalidSpec("invalid generation path".to_string()))
}

fn generation_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("{nanos}-{}", std::process::id())
}

fn atomic_symlink(target: PathBuf, link: &Path) -> Result<()> {
    let temp = temp_path(link);
    let _ = fs::remove_file(&temp);
    symlink(target, &temp)?;
    fs::rename(&temp, link)?;
    Ok(())
}

fn prune_generations(root: &Path) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    let mut generations: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    generations.sort();
    let remove = generations.len().saturating_sub(KEEP_GENERATIONS);
    for path in generations.into_iter().take(remove) {
        let _ = fs::remove_dir_all(path);
    }
}

fn write_owned_file(path: &Path, bytes: &[u8], owner: &str, group: &str, mode: u32) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    chown(path, owner, group)?;
    set_mode(path, mode)?;
    Ok(())
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    set_mode(path, 0o700)?;
    Ok(())
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn temp_path(destination: &Path) -> PathBuf {
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("secretspec");
    destination.with_file_name(format!(".{name}.{}.tmp", std::process::id()))
}

fn chown(path: &Path, owner: &str, group: &str) -> Result<()> {
    let uid = lookup_uid(owner)?;
    let gid = lookup_gid(group)?;
    if unsafe { libc::chown(cstring(path)?.as_ptr(), uid, gid) } != 0 {
        return Err(SecretSpecError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

fn lookup_uid(owner: &str) -> Result<libc::uid_t> {
    if let Ok(uid) = owner.parse::<libc::uid_t>() {
        return Ok(uid);
    }
    let name = CString::new(owner)
        .map_err(|_| SecretSpecError::InvalidSpec(format!("invalid owner '{owner}'")))?;
    let entry = unsafe { libc::getpwnam(name.as_ptr()) };
    if entry.is_null() {
        return Err(SecretSpecError::InvalidSpec(format!(
            "unknown user '{owner}'"
        )));
    }
    Ok(unsafe { (*entry).pw_uid })
}

fn lookup_gid(group: &str) -> Result<libc::gid_t> {
    if let Ok(gid) = group.parse::<libc::gid_t>() {
        return Ok(gid);
    }
    let name = CString::new(group)
        .map_err(|_| SecretSpecError::InvalidSpec(format!("invalid group '{group}'")))?;
    let entry = unsafe { libc::getgrnam(name.as_ptr()) };
    if entry.is_null() {
        return Err(SecretSpecError::InvalidSpec(format!(
            "unknown group '{group}'"
        )));
    }
    Ok(unsafe { (*entry).gr_gid })
}

fn cstring(path: &Path) -> Result<CString> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        SecretSpecError::InvalidSpec(format!("path contains NUL: '{}'", path.display()))
    })
}

fn restart_units(systemctl: &Path, units: &BTreeSet<String>) -> Vec<String> {
    if units.is_empty() {
        return Vec::new();
    }
    let mut command = Command::new(systemctl);
    command.args(["try-restart", "--no-block"]);
    command.args(units);
    match command.status() {
        Ok(status) if status.success() => units.iter().cloned().collect(),
        Ok(status) => {
            eprintln!(
                "secretspec: warning: '{}' try-restart exited with {status}",
                systemctl.display()
            );
            Vec::new()
        }
        Err(error) => {
            eprintln!(
                "secretspec: warning: could not run '{}': {error}",
                systemctl.display()
            );
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests;
