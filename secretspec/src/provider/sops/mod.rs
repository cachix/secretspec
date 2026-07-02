use super::Provider;
use crate::provider::sops::config::SopsConfig;
use crate::provider::sops::fields::{PATHBUF_FIELDS, STRING_FIELDS};
use crate::provider::sops::format::SopsFormat;
use crate::provider::sops::pattern::SopsPathPattern;
use crate::{Result, SecretSpecError};
use ini::Ini;
use saphyr::{LoadableYamlNode, Yaml};
use secrecy::ExposeSecret;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;

mod config;
mod fields;
mod format;
mod pattern;

#[cfg(all(test, feature = "sops"))]
mod tests;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SopsMode {
    SingleFile(PathBuf),
    Directory {
        path: PathBuf,
        pattern: SopsPathPattern,
        format: SopsFormat,
    },
    Uninitialized,
}

pub struct SopsProvider {
    config: SopsConfig,
}

crate::register_provider! {
    struct: SopsProvider,
    config: SopsConfig,
    name: "sops",
    description: "Secret OPerationS",
    schemes: ["sops"],
    examples: [
    "sops:///absolute/path/to/secrets.enc.yaml",
    "sops://relative/path/to/secrets.enc.json",
    "sops://secrets-dir/{project}.{profile}.enc.json",
    "sops://secrets-dir/{project}/{profile}.enc.yaml",
    "sops://binary-secrets.enc?format=binary",
    "sops://secrets.enc.yaml?age_key_file=/home/user/.config/sops/age/keys.txt&age_recipients=age1jpa8rf5qmrg6pw444fcgpkaxg8x4neueszrexzagdjpunjlgeyzq304w34",
    "sops://secrets.enc.ini?format=json&kms_arn=arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
    ],
}

pub struct BuildLookupPathsParams<'a> {
    pub project: &'a str,
    pub key: &'a str,
    pub profile: &'a str,
}

pub struct ParseDecryptedContentParams<'a> {
    pub content: &'a [u8],
    pub format: &'a SopsFormat,
    pub project: &'a str,
    pub key: &'a str,
    pub profile: &'a str,
}

impl SopsProvider {
    pub fn new(config: SopsConfig) -> Self {
        Self { config }
    }

    fn resolve_file_path(&self, project: &str, profile: &str) -> Result<Option<PathBuf>> {
        match &self.config.mode {
            SopsMode::SingleFile(path) => {
                let rebased_path = self.config.rebase_path(path.to_path_buf());

                if rebased_path.exists() {
                    Ok(Some(rebased_path))
                } else {
                    Ok(None)
                }
            },
            SopsMode::Directory {
                path,
                pattern,
                format: _,
            } => self.find_matching_file(path, pattern, project, profile),
            SopsMode::Uninitialized => Err(SecretSpecError::ProviderOperationFailed(
            "SOPS provider's mode was 'Uninitialized', but must be initialized to either 'SingleFile' or 'Directory'".to_string(),
            )),
        }
    }

    fn find_matching_file(
        &self,
        dir_path: &Path,
        pattern: &SopsPathPattern,
        project: &str,
        profile: &str,
    ) -> Result<Option<PathBuf>> {
        let rel_path = pattern.render(project, profile);

        let full_path = self.config.rebase_path(dir_path.join(rel_path));

        if full_path.exists() && full_path.is_file() {
            Ok(Some(full_path))
        } else {
            Ok(None)
        }
    }

    fn detect_format(&self, path: &Path) -> SopsFormat {
        if let Some(format) = &self.config.format {
            return format.clone();
        }

        path.extension()
            .and_then(|ext| ext.to_str())
            .map(SopsFormat::from_str)
            .map(|v| v.expect("SOPS provider failed to infer format"))
            .unwrap()
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
        params: BuildLookupPathsParams<'a>,
    ) -> Result<Vec<Vec<&'a str>>> {
        let BuildLookupPathsParams {
            key,
            profile,
            project,
        } = params;

        match &self.config.mode {
            SopsMode::SingleFile(_) => {
                let mut paths = Vec::new();

                if !project.is_empty() {
                    if !profile.is_empty() && profile != "default" {
                        paths.push(vec![project, profile, key]);
                    }
                    paths.push(vec![profile, key]);
                }
                paths.push(vec![key]);

                Ok(paths)
            }
            SopsMode::Directory { .. } => {
                Ok(vec![vec![key]])
            }
            SopsMode::Uninitialized => Err(SecretSpecError::ProviderOperationFailed(
            "SOPS provider's mode was 'Uninitialized', but must be initialized to either 'SingleFile' or 'Directory'".to_string(),
            ))
        }
    }

    fn parse_decrypted_content(
        &self,
        params: ParseDecryptedContentParams,
    ) -> Result<Option<String>> {
        let ParseDecryptedContentParams {
            content,
            format,
            project,
            key,
            profile,
        } = params;

        match format {
            SopsFormat::Yaml => {
                let content_str = String::from_utf8_lossy(content);

                let docs = Yaml::load_from_str(&content_str).map_err(|e| {
                    SecretSpecError::ProviderOperationFailed(format!("Failed to parse YAML: {}", e))
                })?;

                match self.build_lookup_paths(BuildLookupPathsParams {
                    key,
                    profile,
                    project,
                }) {
                    Ok(paths) => {
                        for doc in &docs {
                            for path in &paths {
                                if let Some(value) = self.navigate_yaml_value(doc, path) {
                                    return Ok(Some(value));
                                }
                            }
                        }
                        Ok(None)
                    }
                    Err(error) => Err(error),
                }
            }
            SopsFormat::Json => {
                let data: serde_json::Value = serde_json::from_slice(content).map_err(|e| {
                    SecretSpecError::ProviderOperationFailed(format!("Failed to parse JSON: {}", e))
                })?;

                match self.build_lookup_paths(BuildLookupPathsParams {
                    key,
                    profile,
                    project,
                }) {
                    Ok(paths) => {
                        for path in paths {
                            if let Some(value) = self.navigate_nested_value(&data, &path) {
                                return Ok(Some(value));
                            }
                        }
                        Ok(None)
                    }
                    Err(error) => Err(error),
                }
            }
            SopsFormat::Env => {
                for item in dotenvy::from_read_iter(BufReader::new(content)) {
                    if let Ok((key, value)) = item {
                        if key.eq(params.key) {
                            return Ok(Some(value));
                        }
                    }
                }

                Ok(None)
            }
            SopsFormat::Ini => {
                let content_str = String::from_utf8_lossy(content);

                let conf = Ini::load_from_str(&content_str).map_err(|e| {
                    SecretSpecError::ProviderOperationFailed(format!(
                        "Failed to parse INI content for project '{}', profile '{}': {}",
                        project, profile, e
                    ))
                })?;

                for (sec, prop) in conf.iter() {
                    match (sec, prop) {
                        (None, properties) => {
                            if let Some(value) = properties.get(key) {
                                return Ok(Some(value.to_string()));
                            }
                        }
                        (Some(s), properties) if s == profile => {
                            if let Some(value) = properties.get(key) {
                                return Ok(Some(value.to_string()));
                            }
                        }
                        _ => {}
                    }
                }

                // INI always stores top-level keys under DEFAULT
                if let Some(default) = conf.section(Some("DEFAULT")) {
                    if let Some(value) = default.get(key) {
                        return Ok(Some(value.to_string()));
                    }
                }

                if let Some(section) = conf.section(Some(profile)) {
                    if let Some(value) = section.get(key) {
                        return Ok(Some(value.to_string()));
                    }
                }

                Ok(None)
            }
        }
    }

    fn create_new_sops_file(&self, project: &str, profile: &str) -> Result<PathBuf> {
        let path = match &self.config.mode {
            SopsMode::SingleFile(p) => p.clone(),
            SopsMode::Directory { path, pattern, .. } => {
                path.join(pattern.render(project, profile))
            }
            SopsMode::Uninitialized => {
                return Err(SecretSpecError::ProviderOperationFailed(
                    "SOPS provider uninitialized".into(),
                ));
            }
        };

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| SecretSpecError::ProviderOperationFailed(format!("mkdir: {}", e)))?;
        }

        let initial = match self.config.format {
            Some(SopsFormat::Json) => "{}\n",
            Some(SopsFormat::Yaml) => "---\n",
            Some(SopsFormat::Env) => "",
            Some(SopsFormat::Ini) => "",
            None => "---\n",
        };

        std::fs::write(&path, initial)
            .map_err(|e| SecretSpecError::ProviderOperationFailed(format!("write: {}", e)))?;

        self.execute_sops_command(&["encrypt", "-i", &path.to_string_lossy()])?;

        Ok(path)
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

        let format = self.detect_format(file_path.as_path());

        let path_str = file_path.to_string_lossy().to_string();

        let decrypted = match self.execute_sops_command(&["-d", &path_str]) {
            Ok(out) => out,
            Err(e) => return Err(e),
        };

        match self.parse_decrypted_content(ParseDecryptedContentParams {
            content: &decrypted,
            format: &format,
            project,
            key,
            profile,
        })? {
            Some(v) => Ok(Some(SecretString::from(v))),
            None => Ok(None),
        }
    }

    fn set(&self, project: &str, key: &str, value: &SecretString, profile: &str) -> Result<()> {
        let file_path = match self.resolve_file_path(project, profile)? {
            Some(p) => p,
            None => self.create_new_sops_file(project, profile)?,
        };

        let format = self.detect_format(&file_path);

        let sops_path = {
            let mut lookup_paths = self.build_lookup_paths(BuildLookupPathsParams {
                key,
                project,
                profile,
            })?;

            // INI files do not supported nested sections.
            //
            // Secrets can either be stored at the "top level" under "[DEFAULT]",
            // or under a single section heading which necessarily means "[<profile>]".
            //
            // Need to always filter out the fully qualified project.profile.key lookup path, and if the
            // secrets live in multiple files in a directory tree, then also drop the profile.key lookup path,
            // as the files themselves will only contain top-level entries.
            if !lookup_paths.is_empty() && SopsFormat::Ini == format {
                let specificity_count = if matches!(self.config.mode, SopsMode::Directory { .. }) {
                    1 // Just the key
                } else {
                    2 // Profile and key
                };

                while let Some(first) = lookup_paths.first() {
                    if first.len() <= specificity_count {
                        break;
                    }

                    lookup_paths.remove(0);
                }

                // In the case of just using the key to qualify the secret, we need to re-add a section named "DEFAULT"
                // to the front of the lookup path. See: https://github.com/getsops/sops/issues/2121
                if 1 == specificity_count {
                    if let Some(last) = lookup_paths.last_mut() {
                        if 1 == last.len() {
                            last.insert(0, "DEFAULT");
                        }
                    }
                }
            }

            let lookup_paths = lookup_paths;

            let chosen_path = lookup_paths.first().ok_or_else(|| {
                SecretSpecError::ProviderOperationFailed("No lookup paths available".into())
            })?;

            chosen_path
                .iter()
                .map(|segment| format!(r#"["{}"]"#, segment))
                .collect::<String>()
        };

        let json_value = serde_json::to_string(value.expose_secret()).map_err(|e| {
            SecretSpecError::ProviderOperationFailed(format!("JSON encode error: {}", e))
        })?;

        let file_str = file_path.to_string_lossy().to_string();

        // If file exists but is not a SOPS file, encrypt it first
        if file_path.exists() {
            // Try decrypting; if it fails, encrypt it
            match self.execute_sops_command(&["decrypt", &file_str]) {
                Ok(_) => {} // already a SOPS file
                Err(_) => {
                    self.execute_sops_command(&["encrypt", "-i", &file_str])?;
                }
            }
        }

        self.execute_sops_command(&["set", &file_str, &sops_path, &json_value])?;

        Ok(())
    }

    fn allows_set(&self) -> bool {
        true
    }

    fn uri(&self) -> String {
        let mut params: HashMap<&str, &str> = HashMap::new();

        PATHBUF_FIELDS
            .iter()
            .filter(|field_spec| !field_spec.sensitive)
            .for_each(|field_spec| {
                if let Some(value) = (field_spec.field)(&self.config) {
                    params.insert(field_spec.url_key, value.to_str().unwrap());
                }
            });

        STRING_FIELDS
            .iter()
            .filter(|field_spec| !field_spec.sensitive)
            .for_each(|field_spec| {
                if let Some(value) = (field_spec.field)(&self.config) {
                    params.insert(field_spec.url_key, value);
                }
            });

        let mut host_and_path = String::new();

        match &self.config.mode {
            SopsMode::SingleFile(path) => host_and_path = path.to_string_lossy().into_owned(),
            SopsMode::Directory {
                path,
                pattern,
                format: _,
            } => host_and_path = format!("{}/{}", path.to_string_lossy(), pattern.debug_template()),
            SopsMode::Uninitialized => (),
        }

        let query = params
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");

        format!("sops://{host_and_path}?{query}")
    }

    fn with_base_dir(&mut self, base_dir: &std::path::Path) {
        self.config.with_base_dir(base_dir);
    }
}
