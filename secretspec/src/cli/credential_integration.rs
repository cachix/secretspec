use miette::{IntoDiagnostic, Result, WrapErr, miette};
use std::fs;
use std::io::{ErrorKind, IsTerminal, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

pub(super) fn read_credential(prompt: &str) -> Result<String> {
    if std::io::stdin().is_terminal() {
        inquire::Password::new(prompt)
            .without_confirmation()
            .prompt()
            .into_diagnostic()
    } else {
        let mut value = String::new();
        std::io::stdin()
            .read_to_string(&mut value)
            .into_diagnostic()?;
        Ok(value.trim().to_string())
    }
}

pub(super) fn validate_credential_value(value: &str) -> Result<()> {
    if value.is_empty()
        || value.trim() != value
        || value.chars().any(|character| character.is_ascii_control())
    {
        return Err(miette!(
            "Credential cannot be empty or contain surrounding whitespace or control characters"
        ));
    }
    Ok(())
}

pub(super) fn manifest_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .into_diagnostic()
            .wrap_err("Failed to resolve the current directory")
            .map(|directory| directory.join(path))
    }
}

pub(super) fn resolve_path(path: &Path) -> Result<PathBuf> {
    match fs::symlink_metadata(path) {
        Ok(_) => fs::canonicalize(path)
            .into_diagnostic()
            .wrap_err_with(|| format!("Failed to resolve {}", path.display())),
        Err(error) if error.kind() == ErrorKind::NotFound => resolve_missing_path(path)
            .into_diagnostic()
            .wrap_err_with(|| format!("Failed to resolve {}", path.display())),
        Err(error) => Err(error)
            .into_diagnostic()
            .wrap_err_with(|| format!("Failed to inspect {}", path.display())),
    }
}

fn resolve_missing_path(path: &Path) -> std::io::Result<PathBuf> {
    let absolute = std::path::absolute(path)?;
    let mut prefix = absolute.as_path();
    let mut suffix = Vec::new();
    loop {
        match fs::canonicalize(prefix) {
            Ok(mut resolved) => {
                for component in suffix.iter().rev() {
                    resolved.push(component);
                }
                return Ok(resolved);
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                let Some(component) = prefix.file_name() else {
                    return Err(error);
                };
                suffix.push(component.to_os_string());
                let Some(parent) = prefix.parent() else {
                    return Err(error);
                };
                prefix = parent;
            }
            Err(error) => return Err(error),
        }
    }
}

pub(super) fn confirm(yes: bool, prompt: &str) -> Result<bool> {
    if yes {
        return Ok(true);
    }
    if !std::io::stdin().is_terminal() {
        return Err(miette!(
            "refusing to change user-level settings without confirmation; pass --yes for non-interactive use"
        ));
    }
    inquire::Confirm::new(prompt)
        .with_default(false)
        .prompt()
        .into_diagnostic()
}

pub(super) fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(contents) => Ok(Some(contents)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error)
            .into_diagnostic()
            .wrap_err_with(|| format!("Failed to read {}", path.display())),
    }
}

pub(super) fn ensure_unchanged(path: &Path, expected: Option<&[u8]>) -> Result<()> {
    if read_optional(path)?.as_deref() != expected {
        return Err(miette!(
            "{} changed during this operation; no changes were made; rerun the command",
            path.display()
        ));
    }
    Ok(())
}

pub(super) fn write_bytes_atomically(path: &Path, contents: &[u8], owner_only: bool) -> Result<()> {
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
        miette!(
            "Failed to atomically replace {}: {}",
            path.display(),
            error.error
        )
    })?;
    Ok(())
}

pub(super) fn restore_file(path: &Path, contents: Option<&[u8]>, owner_only: bool) -> Result<()> {
    match contents {
        Some(contents) => write_bytes_atomically(path, contents, owner_only)?,
        None => {
            if path.try_exists().into_diagnostic()? {
                fs::remove_file(path).into_diagnostic()?;
            }
        }
    }
    Ok(())
}
