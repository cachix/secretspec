use super::Provider;
use crate::provider::sops::config::SopsConfig;
use crate::provider::sops::format::SopsFormat;
use crate::{Result, SecretSpecError};
use saphyr::{LoadableYamlNode, Yaml};
use secrecy::ExposeSecret;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

mod config;
mod fields;
mod format;

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SopsMode {
    SingleFile(PathBuf),
    Directory {
        path: PathBuf,
        pattern: String,
        default_format: SopsFormat,
    },
}

pub struct SopsProvider {
    config: SopsConfig,
}

crate::register_provider! {
    struct: SopsProvider,
    config: SopsConfig,
    name: "sops",
    description: "SOPS encrypted file provider supporting YAML, JSON, ENV, INI, and binary files",
    schemes: ["sops"],
    examples: [
        "sops://.enc.yaml",
        "sops://config/secrets.enc.json",
        "sops://secrets-dir",
        "sops://secrets-dir?pattern={project}.{profile}.enc.json",
        "sops://secrets-dir?pattern={project}/{profile}.enc.env",
        "sops://binary-secrets.enc.bin?format=binary",
        "sops://.enc.yaml?age_key_file=/home/user/.config/sops/age/keys.txt",
        "sops://secrets-dir?format=json&kms_arn=arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
    ],
}

impl SopsProvider {
    pub fn new(config: SopsConfig) -> Self {
        Self { config }
    }

    fn resolve_file_path(&self, project: &str, profile: &str) -> Result<Option<PathBuf>> {
        match &self.config.mode {
            SopsMode::SingleFile(path) => {
                if path.exists() {
                    Ok(Some(path.clone()))
                } else {
                    Ok(None)
                }
            }
            SopsMode::Directory {
                path,
                pattern,
                default_format,
            } => self.find_matching_file(path, pattern, project, profile, default_format),
        }
    }

    fn find_matching_file(
        &self,
        dir_path: &Path,
        pattern: &str,
        project: &str,
        profile: &str,
        default_format: &SopsFormat,
    ) -> Result<Option<PathBuf>> {
        // Try multiple organizational patterns in order of preference

        // 1. Try hierarchical directory structure first (<project>/<profile>.enc.<ext>)
        if !project.is_empty()
            && let Some(path) =
                self.try_hierarchical_structure(dir_path, project, profile, default_format)?
        {
            return Ok(Some(path));
        }

        // 2. Try explicit pattern matching
        if let Some(path) =
            self.try_pattern_matching(dir_path, pattern, project, profile, default_format)?
        {
            return Ok(Some(path));
        }

        // 3. Try flat directory fallback patterns
        self.try_flat_fallback_patterns(dir_path, project, profile, default_format)
    }

    fn try_hierarchical_structure(
        &self,
        base_path: &Path,
        project: &str,
        profile: &str,
        default_format: &SopsFormat,
    ) -> Result<Option<PathBuf>> {
        let project_dir = base_path.join(project);

        if !project_dir.exists() || !project_dir.is_dir() {
            return Ok(None);
        }

        // Try various profile file naming patterns within the project directory
        let profile_patterns = [
            format!("{}.enc.{}", profile, default_format.as_str()),
            format!("{}.sops.{}", profile, default_format.as_str()),
            format!("{}.{}", profile, default_format.as_str()),
            format!("sops.{}.{}", profile, default_format.as_str()),
            format!("{}.sops", profile),
        ];

        // Also try all extensions for the format
        let mut all_patterns = profile_patterns.to_vec();
        for ext in default_format.extensions() {
            all_patterns.extend([
                format!("{}.enc.{}", profile, ext),
                format!("{}.sops.{}", profile, ext),
                format!("{}.{}", profile, ext),
                format!("sops.{}.{}", profile, ext),
            ]);
        }

        for pattern in all_patterns {
            let file_path = project_dir.join(&pattern);
            if file_path.exists() && file_path.is_file() {
                return Ok(Some(file_path));
            }
        }

        Ok(None)
    }

    fn try_pattern_matching(
        &self,
        dir_path: &Path,
        pattern: &str,
        project: &str,
        profile: &str,
        default_format: &SopsFormat,
    ) -> Result<Option<PathBuf>> {
        // Replace placeholders in pattern
        let mut resolved_pattern = pattern.replace("{project}", project);
        resolved_pattern = resolved_pattern.replace("{profile}", profile);
        resolved_pattern = resolved_pattern.replace("{format}", default_format.as_str());

        let full_path = dir_path.join(&resolved_pattern);
        if full_path.exists() && full_path.is_file() {
            return Ok(Some(full_path));
        }

        // Try with different extensions if no explicit format in pattern
        if !pattern.contains("{format}")
            && !default_format
                .extensions()
                .iter()
                .any(|ext| pattern.contains(ext))
        {
            for ext in default_format.extensions() {
                let pattern_with_ext = if pattern.ends_with(".sops") {
                    format!("{}.{}", pattern, ext)
                } else if pattern.contains(".sops.") {
                    pattern.to_string()
                } else {
                    format!("{}.sops.{}", pattern, ext)
                };

                let mut resolved = pattern_with_ext.replace("{project}", project);
                resolved = resolved.replace("{profile}", profile);
                resolved = resolved.replace("{format}", ext);

                let full_path = dir_path.join(&resolved);
                if full_path.exists() && full_path.is_file() {
                    return Ok(Some(full_path));
                }
            }
        }

        Ok(None)
    }

    fn try_flat_fallback_patterns(
        &self,
        dir_path: &Path,
        project: &str,
        profile: &str,
        default_format: &SopsFormat,
    ) -> Result<Option<PathBuf>> {
        let fallback_patterns = [
            // Standard flat patterns
            format!("{}.{}.sops.{}", project, profile, default_format.as_str()),
            format!("{}-{}.sops.{}", project, profile, default_format.as_str()),
            format!("{}_{}.sops.{}", project, profile, default_format.as_str()),
            format!("{}.sops.{}", project, default_format.as_str()),
            format!("{}.{}", project, default_format.as_str()),
        ];

        // Try all extensions for the format
        let mut all_patterns = fallback_patterns.to_vec();
        for ext in default_format.extensions() {
            all_patterns.extend([
                format!("{}.{}.sops.{}", project, profile, ext),
                format!("{}-{}.sops.{}", project, profile, ext),
                format!("{}_{}.sops.{}", project, profile, ext),
                format!("{}.sops.{}", project, ext),
                format!("{}.{}", project, ext),
            ]);
        }

        for pattern in &all_patterns {
            let file_path = dir_path.join(pattern);
            if file_path.exists() {
                return Ok(Some(file_path));
            }
        }

        Ok(None)
    }

    fn detect_format(&self, path: &Path) -> SopsFormat {
        // Use explicit format if provided
        if let Some(format) = &self.config.format {
            return format.clone();
        }

        // Otherwise detect from file extension
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(SopsFormat::from_extension)
            .unwrap_or(SopsFormat::Yaml)
    }

    fn execute_sops_command(&self, args: &[&str]) -> Result<Vec<u8>> {
        let mut cmd = Command::new("sops");

        cmd.args(args);

        self.config.apply_env(&mut cmd);

        let output = match cmd.output() {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(SecretSpecError::ProviderOperationFailed(
                    "The 'sops' CLI is not installed.\n\
                    Install it from https://github.com/getsops/sops or via your package manager."
                        .to_string(),
                ));
            }
            Err(e) => return Err(e.into()),
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);

            return Err(SecretSpecError::ProviderOperationFailed(stderr.to_string()));
        }

        Ok(output.stdout)
    }

    fn navigate_nested_value(&self, data: &serde_json::Value, path: &[&str]) -> Option<String> {
        let mut current = data;

        for segment in path {
            match current {
                serde_json::Value::Object(map) => {
                    current = map.get(*segment)?;
                }
                _ => return None,
            }
        }

        match current {
            serde_json::Value::String(s) => Some(s.clone()),
            other => Some(other.to_string()),
        }
    }

    fn navigate_yaml_value(&self, yaml: &Yaml, path: &[&str]) -> Option<String> {
        let mut current = yaml;

        for segment in path {
            if current.is_mapping() {
                current = current.as_mapping_get(segment)?;
            } else {
                return None;
            }
        }

        Some(self.yaml_to_string(current))
    }

    fn yaml_to_string(&self, yaml: &Yaml) -> String {
        if yaml.is_null() {
            String::new()
        } else if let Some(s) = yaml.as_str() {
            s.to_string()
        } else if let Some(i) = yaml.as_integer() {
            i.to_string()
        } else if let Some(f) = yaml.as_floating_point() {
            f.to_string()
        } else if let Some(b) = yaml.as_bool() {
            b.to_string()
        } else {
            format!("{:?}", yaml)
        }
    }

    fn build_lookup_paths<'a>(
        &self,
        project: &'a str,
        key: &'a str,
        profile: &'a str,
    ) -> Vec<Vec<&'a str>> {
        match &self.config.mode {
            SopsMode::SingleFile(_) => {
                // For single file mode, use hierarchical lookup within the file
                let mut paths = Vec::new();
                if !project.is_empty() {
                    if !profile.is_empty() && profile != "default" {
                        paths.push(vec![project, profile, key]);
                    }
                    paths.push(vec![project, key]);
                }
                paths.push(vec![key]);
                paths
            }
            SopsMode::Directory { .. } => {
                let mut paths = Vec::new();
                paths.push(vec![profile, key]);
                paths

                // For directory mode, the file already contains the right data
                // so we just look for the key directly
                // vec![vec![key]]
            }
        }
    }

    fn parse_decrypted_content(
        &self,
        content: &[u8],
        format: &SopsFormat,
        project: &str,
        key: &str,
        profile: &str,
    ) -> Result<Option<String>> {
        match format {
            SopsFormat::Yaml => {
                let content_str = String::from_utf8_lossy(content);
                let docs = Yaml::load_from_str(&content_str).map_err(|e| {
                    SecretSpecError::ProviderOperationFailed(format!("Failed to parse YAML: {}", e))
                })?;

                let lookup_paths = self.build_lookup_paths(project, key, profile);

                for doc in &docs {
                    for path in &lookup_paths {
                        if let Some(value) = self.navigate_yaml_value(doc, path) {
                            return Ok(Some(value));
                        }
                    }
                }
                Ok(None)
            }
            SopsFormat::Json => {
                let data: serde_json::Value = serde_json::from_slice(content).map_err(|e| {
                    SecretSpecError::ProviderOperationFailed(format!("Failed to parse JSON: {}", e))
                })?;

                let lookup_paths = self.build_lookup_paths(project, key, profile);

                for path in lookup_paths {
                    if let Some(value) = self.navigate_nested_value(&data, &path) {
                        return Ok(Some(value));
                    }
                }

                Ok(None)
            }
            SopsFormat::Env => {
                let content_str = String::from_utf8_lossy(content);

                for line in content_str.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }

                    if let Some((env_key, value)) = line.split_once('=')
                        && env_key.trim() == key
                    {
                        let value = value.trim();
                        let value = if (value.starts_with('"') && value.ends_with('"'))
                            || (value.starts_with('\'') && value.ends_with('\''))
                        {
                            &value[1..value.len() - 1]
                        } else {
                            value
                        };
                        return Ok(Some(value.to_string()));
                    }
                }
                Ok(None)
            }
            SopsFormat::Ini => {
                // For INI files, we could implement proper INI parsing
                // For now, treat similar to ENV files but could be enhanced
                let content_str = String::from_utf8_lossy(content);
                for line in content_str.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
                        continue;
                    }

                    if let Some((ini_key, value)) = line.split_once('=')
                        && ini_key.trim() == key
                    {
                        return Ok(Some(value.trim().to_string()));
                    }
                }
                Ok(None)
            }
            SopsFormat::Binary => {
                // For binary files, SOPS stores the encrypted data as base64 under tree['data']
                // The decrypted content should be the raw binary data
                // Since we're looking for a specific key, this doesn't make much sense for binary files
                // Return the entire content as a hex string for consistency
                let hex_string = content
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>();
                Ok(Some(hex_string))
            }
        }
    }

    // Add a method to inspect the SOPS file metadata
    fn inspect_sops_file(&self, file_path: &Path) -> Result<()> {
        match std::fs::metadata(file_path) {
            Err(e) => {
                return Err(SecretSpecError::ProviderOperationFailed(format!(
                    "Cannot access SOPS file {}: {}",
                    file_path.display(),
                    e
                )));
            }
            _ => {}
        }

        // Try to read the file and inspect its structure
        match std::fs::read_to_string(file_path) {
            Ok(content) => {
                eprintln!("DEBUG: File content length: {} characters", content.len());

                // Try to parse as JSON to inspect SOPS metadata
                if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(sops_obj) = json_value.get("sops") {
                        eprintln!("DEBUG: Found SOPS metadata section");

                        // Check for age recipients
                        if let Some(age_section) = sops_obj.get("age")
                            && let Some(recipients) = age_section.as_array()
                        {
                            eprintln!("DEBUG: Found {} age recipients", recipients.len());
                            for (i, recipient) in recipients.iter().enumerate() {
                                if let Some(recipient_str) =
                                    recipient.get("recipient").and_then(|r| r.as_str())
                                {
                                    eprintln!("DEBUG: Age recipient {}: {}", i, recipient_str);
                                }
                            }
                        }

                        // Check for KMS keys
                        if let Some(kms_section) = sops_obj.get("kms")
                            && let Some(kms_keys) = kms_section.as_array()
                        {
                            eprintln!("DEBUG: Found {} KMS keys", kms_keys.len());
                            for (i, key) in kms_keys.iter().enumerate() {
                                if let Some(arn) = key.get("arn").and_then(|a| a.as_str()) {
                                    eprintln!("DEBUG: KMS key {}: {}", i, arn);
                                }
                            }
                        }

                        // Check for PGP keys
                        if let Some(pgp_section) = sops_obj.get("pgp")
                            && let Some(pgp_keys) = pgp_section.as_array()
                        {
                            eprintln!("DEBUG: Found {} PGP keys", pgp_keys.len());
                            for (i, key) in pgp_keys.iter().enumerate() {
                                if let Some(fp) = key.get("fp").and_then(|f| f.as_str()) {
                                    eprintln!("DEBUG: PGP key {}: {}", i, fp);
                                }
                            }
                        }
                    } else {
                        eprintln!("WARNING: No SOPS metadata section found in file");
                    }
                } else {
                    eprintln!("DEBUG: File is not valid JSON, might be YAML or other format");
                }
            }
            Err(e) => {
                eprintln!("WARNING: Cannot read SOPS file content: {}", e);
            }
        }

        Ok(())
    }
}

impl Provider for SopsProvider {
    fn name(&self) -> &'static str {
        Self::PROVIDER_NAME
    }

    fn get(&self, project: &str, key: &str, profile: &str) -> Result<Option<SecretString>> {
        let file_path = match self.resolve_file_path(project, profile)? {
            Some(p) => p,
            None => return Ok(None),
        };

        let format = self.detect_format(&file_path);
        let path_str = file_path.to_string_lossy().to_string();

        // Decrypt using CLI
        let decrypted = match self.execute_sops_command(&["-d", &path_str]) {
            Ok(out) => out,
            Err(e) => return Err(e),
        };

        // Parse decrypted content using your existing logic
        match self.parse_decrypted_content(&decrypted, &format, project, key, profile)? {
            Some(v) => Ok(Some(SecretString::from(v))),
            None => Ok(None),
        }
    }

    fn set(&self, project: &str, key: &str, value: &SecretString, profile: &str) -> Result<()> {
        let file_path = match self.resolve_file_path(project, profile)? {
            Some(p) => p,
            None => {
                return Err(SecretSpecError::ProviderOperationFailed(
                    "SOPS file not found; cannot set key".to_string(),
                ));
            }
        };

        let format = self.detect_format(&file_path);

        if let Err(e) = self.inspect_sops_file(&file_path) {
            eprintln!("WARNING: File inspection failed: {}", e);
        }

        if !format.is_structured() {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Cannot set key '{}' in non-structured SOPS file format {}",
                key, format
            )));
        }

        let path_str = file_path.to_string_lossy().to_string();

        let escaped = value.expose_secret().replace('"', "\\\"");

        // SOPS path syntax: ["foo"]["bar"]
        let sops_path = format!(r#"["{}"]"#, key.replace('.', r#""][""#));

        let set_arg = format!(r#"{}="{}""#, sops_path, escaped);

        self.execute_sops_command(&["--set", &set_arg, &path_str])?;

        Ok(())
    }

    fn allows_set(&self) -> bool {
        true
    }

    fn uri(&self) -> String {
        "".to_string()
    }
}
