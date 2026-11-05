//! Inspect configuration selection without resolving values or building providers.

use super::{TypedArgs, apply_scope};
use crate::audit::redact_uri_strict;
use crate::config::{GlobalConfig, ProviderAlias};
use crate::secrets::{find_config_file, non_blank, normalize_reason};
use crate::{Secrets, Spec};
use miette::{IntoDiagnostic, Result, WrapErr, miette};
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Serialize)]
struct Setting {
    value: Option<String>,
    source: String,
}

impl Setting {
    fn new(value: Option<String>, source: impl Into<String>) -> Self {
        Self {
            value,
            source: source.into(),
        }
    }
}

#[derive(Serialize)]
struct ComputedConfig {
    manifest: Setting,
    project: Setting,
    profile: Setting,
    provider: Setting,
    provider_is_override: bool,
    scope: Setting,
    reason: Setting,
    global_config: PathBuf,
    discovered_manifest: Option<PathBuf>,
    provider_aliases: BTreeMap<String, Setting>,
    errors: Vec<String>,
}

// Blank profile/provider flags are ignored by the runtime setters. In that case
// their ambient fallback can still win, and must be attributed to the environment.
fn selection_source(
    argument: Option<&str>,
    typed: bool,
    flag: &str,
    env: &str,
    fallback: String,
) -> String {
    if argument.and_then(non_blank).is_some() {
        return if typed { flag } else { env }.to_string();
    }
    if std::env::var(env)
        .ok()
        .as_deref()
        .and_then(non_blank)
        .is_some()
    {
        return env.to_string();
    }
    fallback
}

fn argument_source<'a>(present: bool, typed: bool, flag: &'a str, env: &'a str) -> &'a str {
    if !present {
        "default"
    } else if typed {
        flag
    } else {
        env
    }
}

fn alias_summary(alias: &ProviderAlias) -> String {
    let mut summary = match alias.authoritative_uri() {
        Some(uri) => redact_uri_strict(uri),
        None => format!(
            "fallback [{}]",
            alias
                .fallback()
                .iter()
                .map(|spec| redact_uri_strict(spec))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    };
    if let Some(cache) = alias.cache() {
        summary.push_str(&format!(
            ", cached in {} for {}",
            redact_uri_strict(cache.provider()),
            cache.max_age()
        ));
    }
    summary
}

pub(super) fn run(
    file: &Option<PathBuf>,
    reason: &Option<String>,
    provider: Option<String>,
    profile: Option<String>,
    scope: Option<String>,
    json: bool,
    typed: TypedArgs,
) -> Result<()> {
    let discovered = match find_config_file() {
        Ok(path) => Some(path),
        Err(crate::SecretSpecError::NoManifest) => None,
        Err(error) => return Err(error).into_diagnostic(),
    };
    let manifest = file
        .as_ref()
        .or(discovered.as_ref())
        .ok_or(crate::SecretSpecError::NoManifest)
        .into_diagnostic()?;
    let manifest = std::path::absolute(manifest).into_diagnostic()?;
    let spec = Spec::try_from(manifest.as_path())
        .into_diagnostic()
        .wrap_err("Failed to load secretspec configuration")?;
    let global_path = GlobalConfig::path().into_diagnostic()?;
    let global = GlobalConfig::load().into_diagnostic()?;
    let mut app = Secrets::for_config_display(spec, global.clone());
    if let Some(provider) = &provider {
        app.set_provider(provider);
    }
    if let Some(profile) = &profile {
        app.set_profile(profile);
    }
    apply_scope(&mut app, scope.clone());

    let global_source = |field: &str| format!("{} [defaults.{field}]", global_path.display());
    let profile_fallback = if global
        .as_ref()
        .and_then(|g| g.defaults.profile.as_ref())
        .is_some()
    {
        global_source("profile")
    } else {
        "default".into()
    };
    let explicit_provider = app.explicit_provider_spec(None);
    let provider_is_override = explicit_provider.is_some();
    let provider_value = explicit_provider.or_else(|| app.configured_default_provider_spec());
    let provider_fallback = if provider_value.is_some() {
        global_source("provider")
    } else {
        "default".into()
    };

    let mut aliases = BTreeMap::new();
    if let Some(providers) = global.as_ref().and_then(|g| g.defaults.providers.as_ref()) {
        for (name, alias) in providers {
            aliases.insert(
                name.clone(),
                Setting::new(Some(alias_summary(alias)), global_source("providers")),
            );
        }
    }
    if let Some(providers) = &app.config().providers {
        for (name, alias) in providers {
            aliases.insert(
                name.clone(),
                Setting::new(
                    Some(alias_summary(alias)),
                    format!("{} [providers] (including extends)", manifest.display()),
                ),
            );
        }
    }
    let errors = app
        .validate_ipc_selection()
        .err()
        .map(|error| error.to_string())
        .into_iter()
        .collect();
    let report = ComputedConfig {
        manifest: Setting::new(
            Some(manifest.display().to_string()),
            match (file.is_some(), typed.file) {
                (true, true) => "--file",
                (true, false) => "SECRETSPEC_FILE",
                (false, _) => "discovery",
            },
        ),
        project: Setting::new(
            Some(app.project_name().to_string()),
            format!("{} [project].name", manifest.display()),
        ),
        profile: Setting::new(
            Some(app.resolve_profile_name(None)),
            selection_source(
                profile.as_deref(),
                typed.profile,
                "--profile",
                "SECRETSPEC_PROFILE",
                profile_fallback,
            ),
        ),
        provider: Setting::new(
            provider_value.as_deref().map(redact_uri_strict),
            selection_source(
                provider.as_deref(),
                typed.provider,
                "--provider",
                "SECRETSPEC_PROVIDER",
                provider_fallback,
            ),
        ),
        provider_is_override,
        scope: Setting::new(
            app.resolve_scope_name(None),
            argument_source(scope.is_some(), typed.scope, "--scope", "SECRETSPEC_SCOPE"),
        ),
        reason: Setting::new(
            reason.as_deref().and_then(normalize_reason),
            argument_source(
                reason.is_some(),
                typed.reason,
                "--reason",
                "SECRETSPEC_REASON",
            ),
        ),
        global_config: global_path,
        discovered_manifest: discovered,
        provider_aliases: aliases,
        errors,
    };

    let mut out = std::io::stdout().lock();
    if json {
        serde_json::to_writer_pretty(&mut out, &report).into_diagnostic()?;
        writeln!(out).into_diagnostic()?;
    } else {
        report.write_text(&mut out).into_diagnostic()?;
    }
    out.flush().into_diagnostic()?;
    if !report.errors.is_empty() {
        return Err(miette!(
            "Invalid configuration selection; see config show output"
        ));
    }
    Ok(())
}

impl ComputedConfig {
    fn write_text(&self, out: &mut impl Write) -> std::io::Result<()> {
        for (name, setting) in [
            ("Manifest", &self.manifest),
            ("Project", &self.project),
            ("Profile", &self.profile),
            (
                if self.provider_is_override {
                    "Provider override"
                } else {
                    "Provider default"
                },
                &self.provider,
            ),
            ("Scope", &self.scope),
            ("Reason", &self.reason),
        ] {
            writeln!(
                out,
                "{name}: {} (from {})",
                setting.value.as_deref().unwrap_or("(none)"),
                setting.source
            )?;
        }
        writeln!(
            out,
            "Global configuration: {}",
            self.global_config.display()
        )?;
        if let Some(discovered) = &self.discovered_manifest {
            let selected = self.manifest.value.as_deref().map(Path::new);
            // Canonicalization avoids reporting symlink spellings as disagreement.
            if selected.and_then(|p| p.canonicalize().ok()) != discovered.canonicalize().ok() {
                writeln!(
                    out,
                    "Discovery from current directory: {} (overridden)",
                    discovered.display()
                )?;
            }
        }
        if !self.provider_aliases.is_empty() {
            writeln!(
                out,
                "\nProvider aliases (project entries override global entries):"
            )?;
            for (name, setting) in &self.provider_aliases {
                writeln!(
                    out,
                    "  {name}: {} (from {})",
                    setting.value.as_deref().unwrap_or("(none)"),
                    setting.source
                )?;
            }
        }
        writeln!(
            out,
            "\nProvider selection can vary by secret. No secret values were resolved."
        )?;
        for error in &self.errors {
            writeln!(out, "Error: {error}")?;
        }
        Ok(())
    }
}
