//! NixOS integration: link host-sealed provider credentials and provision
//! runtime secret files from a value-free deployment plan.
//!
//! Nix evaluation only sees secret names, paths, and template placeholders.
//! Values are resolved by an explicit `refresh` on the target and written to a
//! tmpfs generation under `/run/secretspec`. The last successful values are
//! also encrypted with `systemd-creds` so a reboot can recover them while the
//! provider is unreachable.
//!
//! This module is Linux-oriented. The public entry points return an actionable
//! error instead of panicking on platforms without the NixOS primitives.

use crate::{CallerContext, Result, SecretSpecError, Secrets};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use crate::{NamedResolution, SecretBytes};
#[cfg(unix)]
use std::collections::BTreeMap;

pub const PLAN_SCHEMA: u32 = 1;
pub const DEFAULT_PLAN: &str = "/etc/secretspec/plan.json";
pub const DEFAULT_CREDENTIALS: &str = "/var/lib/secretspec/credentials";
pub const DEFAULT_RUNTIME: &str = "/run/secretspec";
pub const DEFAULT_CACHE: &str = "/var/lib/secretspec/cache";
pub const PLACEHOLDER_PREFIX: &str = "@secretspec:";

const DEFAULT_MODE: &str = "0400";
const DEFAULT_OWNER: &str = "root";
const DEFAULT_GROUP: &str = "root";

/// A value-free deployment plan emitted by the NixOS module.
///
/// The JSON document is safe to keep in the Nix store: it contains names,
/// paths, modes, and template text, but never a resolved value.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema: u32,
    pub manifest: PathBuf,
    pub profile: String,
    #[serde(default = "default_runtime")]
    pub runtime_dir: PathBuf,
    #[serde(default = "default_cache")]
    pub cache_dir: PathBuf,
    #[serde(default = "default_credentials")]
    pub credentials_dir: PathBuf,
    /// Absolute path to the matching `systemd-creds`, when the module knows it.
    #[serde(default)]
    pub systemd_creds: Option<PathBuf>,
    /// Absolute path to `systemctl`, when the module knows it.
    #[serde(default)]
    pub systemctl: Option<PathBuf>,
    /// Extra `bin` directories for provider CLIs such as `bws`.
    #[serde(default)]
    pub path: String,
    #[serde(default = "default_true")]
    pub restart_units: bool,
    #[serde(default)]
    pub secrets: Vec<PlanSecret>,
    #[serde(default)]
    pub templates: Vec<PlanTemplate>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanSecret {
    pub name: String,
    #[serde(default = "default_owner")]
    pub owner: String,
    #[serde(default = "default_group")]
    pub group: String,
    #[serde(default = "default_mode")]
    pub mode: String,
    /// Keep an encrypted last-known-good value for offline boots.
    #[serde(default = "default_true")]
    pub cache: bool,
    /// Whether a missing value with no cache aborts the refresh.
    #[serde(default = "default_true")]
    pub required: bool,
    /// Units restarted when this secret changes.
    #[serde(default)]
    pub units: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanTemplate {
    pub name: String,
    /// Text containing `@secretspec:NAME@` placeholders.
    pub content: String,
    #[serde(default = "default_owner")]
    pub owner: String,
    #[serde(default = "default_group")]
    pub group: String,
    #[serde(default = "default_mode")]
    pub mode: String,
    /// Units restarted when this template changes.
    #[serde(default)]
    pub units: Vec<String>,
}

/// Result of one `refresh`.
#[derive(Debug, Default)]
pub struct RefreshReport {
    pub resolved: usize,
    pub cached: usize,
    pub unchanged: usize,
    pub changed: usize,
    pub templates: usize,
    pub restarted_units: Vec<String>,
}

/// Result of one `link`.
#[derive(Debug, Default)]
pub struct LinkReport {
    pub sealed: Vec<String>,
    pub skipped: Vec<String>,
}

fn default_runtime() -> PathBuf {
    PathBuf::from(DEFAULT_RUNTIME)
}

fn default_cache() -> PathBuf {
    PathBuf::from(DEFAULT_CACHE)
}

fn default_credentials() -> PathBuf {
    PathBuf::from(DEFAULT_CREDENTIALS)
}

fn default_mode() -> String {
    DEFAULT_MODE.to_string()
}

fn default_owner() -> String {
    DEFAULT_OWNER.to_string()
}

fn default_group() -> String {
    DEFAULT_GROUP.to_string()
}

fn default_true() -> bool {
    true
}

impl Plan {
    /// Parses and validates a plan without resolving any secret.
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).map_err(|error| {
            let hint = if error.kind() == std::io::ErrorKind::NotFound {
                format!(
                    "; the plan is installed by `nixos-rebuild switch`. Run the switch first, or pass --plan <path>"
                )
            } else {
                String::new()
            };
            SecretSpecError::ProviderOperationFailed(format!(
                "cannot read NixOS plan '{}': {error}{hint}",
                path.display()
            ))
        })?;
        let plan: Self = serde_json::from_slice(&bytes).map_err(|error| {
            SecretSpecError::InvalidSpec(format!(
                "invalid NixOS plan '{}': {error}",
                path.display()
            ))
        })?;
        plan.validate()?;
        Ok(plan)
    }

    fn validate(&self) -> Result<()> {
        if self.schema != PLAN_SCHEMA {
            return Err(SecretSpecError::InvalidSpec(format!(
                "unsupported NixOS plan schema {} (expected {PLAN_SCHEMA})",
                self.schema
            )));
        }
        if self.profile.trim().is_empty() {
            return Err(SecretSpecError::InvalidSpec(
                "NixOS plan profile cannot be empty".to_string(),
            ));
        }
        for (label, path) in [
            ("manifest", &self.manifest),
            ("runtime_dir", &self.runtime_dir),
            ("cache_dir", &self.cache_dir),
            ("credentials_dir", &self.credentials_dir),
        ] {
            if !path.is_absolute() {
                return Err(SecretSpecError::InvalidSpec(format!(
                    "NixOS plan {label} must be absolute, got '{}'",
                    path.display()
                )));
            }
        }
        if let Some(path) = &self.systemd_creds
            && !path.is_absolute()
        {
            return Err(SecretSpecError::InvalidSpec(format!(
                "NixOS plan systemd_creds must be absolute, got '{}'",
                path.display()
            )));
        }
        if let Some(path) = &self.systemctl
            && !path.is_absolute()
        {
            return Err(SecretSpecError::InvalidSpec(format!(
                "NixOS plan systemctl must be absolute, got '{}'",
                path.display()
            )));
        }

        let mut names = BTreeSet::new();
        for secret in &self.secrets {
            validate_name("secret", &secret.name)?;
            if !names.insert(secret.name.as_str()) {
                return Err(SecretSpecError::InvalidSpec(format!(
                    "duplicate NixOS secret '{}'",
                    secret.name
                )));
            }
            parse_mode(&secret.mode)?;
            validate_units(&secret.units)?;
        }
        for template in &self.templates {
            validate_name("template", &template.name)?;
            if !names.insert(template.name.as_str()) {
                return Err(SecretSpecError::InvalidSpec(format!(
                    "duplicate NixOS secret or template '{}'",
                    template.name
                )));
            }
            parse_mode(&template.mode)?;
            validate_units(&template.units)?;
        }
        Ok(())
    }

    fn systemd_creds(&self) -> PathBuf {
        self.systemd_creds
            .clone()
            .unwrap_or_else(|| PathBuf::from("systemd-creds"))
    }
}

fn validate_name(kind: &str, name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 255
        || name == "."
        || name == ".."
        || name.contains(['/', '\\', '\0'])
    {
        return Err(SecretSpecError::InvalidSpec(format!(
            "invalid NixOS {kind} name '{name}': expected one filename"
        )));
    }
    Ok(())
}

fn validate_units(units: &[String]) -> Result<()> {
    for unit in units {
        if unit.trim().is_empty() || unit.contains(['/', '\0']) {
            return Err(SecretSpecError::InvalidSpec(format!(
                "invalid systemd unit name '{unit}'"
            )));
        }
    }
    Ok(())
}

fn parse_mode(mode: &str) -> Result<u32> {
    let trimmed = mode.trim();
    let digits = trimmed
        .strip_prefix("0o")
        .unwrap_or(trimmed)
        .trim_start_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits };
    let value = u32::from_str_radix(digits, 8).map_err(|_| {
        SecretSpecError::InvalidSpec(format!(
            "invalid file mode '{mode}': expected octal such as 0400"
        ))
    })?;
    if value > 0o7777 {
        return Err(SecretSpecError::InvalidSpec(format!(
            "invalid file mode '{mode}': out of range"
        )));
    }
    Ok(value)
}

#[cfg(unix)]
fn value_from_resolution(resolution: crate::ResolvedSecret<SecretBytes>) -> Result<SecretBytes> {
    if let Some(value) = resolution.value {
        return Ok(value);
    }
    if let Some(path) = resolution.path {
        return std::fs::read(&path)
            .map(SecretBytes::from_vec)
            .map_err(SecretSpecError::Io);
    }
    Err(SecretSpecError::ProviderOperationFailed(
        "secret resolution returned neither a value nor a path".to_string(),
    ))
}

/// Runs `nixos refresh` from a plan.
///
/// `check` resolves and reports without writing anything. `no_restart`
/// overrides the plan's unit-restart policy for callers that only want to
/// refresh files.
pub fn refresh(
    plan_path: &Path,
    check: bool,
    no_restart: bool,
    reason: Option<&str>,
    caller: Option<&CallerContext>,
) -> Result<RefreshReport> {
    ensure_root()?;
    let plan = Plan::load(plan_path)?;
    platform::refresh(&plan, check, no_restart, reason, caller)
}

/// Runs a command with the installed plan's manifest, provider credentials,
/// and provider tool paths.
pub fn exec(plan_path: &Path, command: &[String], reason: Option<&str>) -> Result<()> {
    ensure_root()?;
    let plan = Plan::load(plan_path)?;
    platform::exec(&plan, command, reason)
}

/// Runs `nixos link`: prompts for provider credentials declared with a
/// `systemd-credential` source and seals them for this host.
pub fn link(
    manifest: Option<&Path>,
    store: Option<&Path>,
    force: bool,
    systemd_creds: Option<&Path>,
) -> Result<LinkReport> {
    ensure_root()?;
    let mut secrets = match manifest {
        Some(path) => Secrets::load_from(path),
        None => Secrets::load(),
    }?;
    // The plan uses the project manifest; keep link's reads audited under the
    // same caller identity as refresh.
    secrets = secrets.with_caller(CallerContext::new("secretspec-nixos").with_operation("link"));
    platform::link(
        &secrets,
        store.unwrap_or(Path::new(DEFAULT_CREDENTIALS)),
        force,
        systemd_creds,
    )
}

/// Re-executes the current command through `sudo` when the caller is not root.
///
/// Secrets are never part of argv here: the elevated process prompts after
/// privilege escalation. Set `SECRETSPEC_NIXOS_NO_ELEVATE=1` in automation that
/// already runs as root.
pub fn ensure_root() -> Result<()> {
    #[cfg(unix)]
    {
        platform::ensure_root()
    }
    #[cfg(not(unix))]
    {
        Err(unsupported())
    }
}

#[cfg(not(unix))]
fn unsupported() -> SecretSpecError {
    SecretSpecError::ProviderOperationFailed(
        "the NixOS integration is only available on Unix systems".to_string(),
    )
}

#[cfg(unix)]
mod platform;
#[cfg(not(unix))]
mod platform {
    use super::*;

    pub(super) fn refresh(
        _plan: &Plan,
        _check: bool,
        _no_restart: bool,
        _reason: Option<&str>,
        _caller: Option<&CallerContext>,
    ) -> Result<RefreshReport> {
        Err(unsupported())
    }

    pub(super) fn link(
        _secrets: &Secrets,
        _store: &Path,
        _force: bool,
        _systemd_creds: Option<&Path>,
    ) -> Result<LinkReport> {
        Err(unsupported())
    }

    pub(super) fn ensure_root() -> Result<()> {
        Err(unsupported())
    }
}
