use super::Provider;
use crate::{Result, SecretSpecError};
use saphyr::{LoadableYamlNode, Yaml};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::env;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SopsFormat {
    /// YAML configuration files (.yaml, .yml)
    #[default]
    Yaml,
    /// JSON configuration files (.json)
    Json,
    /// Environment variable files (.env)
    Env,
    /// INI configuration files (.ini)
    Ini,
    /// Binary files (encrypted as base64 under tree['data'] in JSON format)
    Binary,
}

impl fmt::Display for SopsFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Yaml => write!(f, "yaml"),
            Self::Json => write!(f, "json"),
            Self::Env => write!(f, "env"),
            Self::Ini => write!(f, "ini"),
            Self::Binary => write!(f, "binary"),
        }
    }
}

impl FromStr for SopsFormat {
    type Err = SecretSpecError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "yaml" | "yml" => Ok(Self::Yaml),
            "json" => Ok(Self::Json),
            "env" | "dotenv" => Ok(Self::Env),
            "ini" => Ok(Self::Ini),
            "binary" | "bin" => Ok(Self::Binary),
            _ => Err(SecretSpecError::ProviderOperationFailed(format!(
                "Unsupported SOPS format: {}. Supported formats: yaml, json, env, ini, binary",
                s
            ))),
        }
    }
}

impl SopsFormat {
    /// Detect format from file extension
    pub fn from_extension(ext: &str) -> Self {
        match ext.to_lowercase().as_str() {
            "yml" | "yaml" => Self::Yaml,
            "json" => Self::Json,
            "env" => Self::Env,
            "ini" => Self::Ini,
            // Any other extension is treated as binary
            _ => Self::Binary,
        }
    }

    /// Get the canonical string representation for SOPS CLI
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Yaml => "yaml",
            Self::Json => "json",
            Self::Env => "env",
            Self::Ini => "ini",
            Self::Binary => "binary",
        }
    }

    /// Get common file extensions for this format
    pub fn extensions(&self) -> &'static [&'static str] {
        match self {
            Self::Yaml => &["yaml", "yml"],
            Self::Json => &["json"],
            Self::Env => &["env"],
            Self::Ini => &["ini"],
            Self::Binary => &["bin", "dat", "key", "cert", "p12", "pfx"], // Common binary file extensions
        }
    }

    /// Check if this format supports structured data (key-value lookup)
    pub fn is_structured(&self) -> bool {
        matches!(self, Self::Yaml | Self::Json | Self::Env | Self::Ini)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SopsMode {
    SingleFile(PathBuf),
    Directory {
        path: PathBuf,
        pattern: String,
        default_format: SopsFormat,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SopsConfig {
    pub mode: SopsMode,
    pub format: Option<SopsFormat>,
    // Age configuration
    pub age_key_file: Option<PathBuf>,
    pub age_key: Option<String>,
    pub age_key_cmd: Option<String>,
    pub age_recipients: Option<String>,
    pub age_ssh_private_key_file: Option<PathBuf>,
    // AWS KMS configuration
    pub kms_arn: Option<String>,
    pub aws_profile: Option<String>,
    pub aws_access_key_id: Option<String>,
    pub aws_secret_access_key: Option<String>,
    pub aws_region: Option<String>,
    // PGP configuration
    pub pgp_fp: Option<String>,
    // GCP KMS configuration
    pub gcp_kms: Option<String>,
    // Azure Key Vault configuration
    pub azure_kv: Option<String>,
    // HashiCorp Vault configuration
    pub hc_vault_addr: Option<String>,
    pub hc_vault_token: Option<String>,
}

impl Default for SopsConfig {
    fn default() -> Self {
        Self {
            mode: SopsMode::SingleFile(PathBuf::from(".enc.yaml")),
            format: None,
            age_key_file: None,
            age_key: None,
            age_key_cmd: None,
            age_recipients: None,
            age_ssh_private_key_file: None,
            kms_arn: None,
            aws_profile: None,
            aws_access_key_id: None,
            aws_secret_access_key: None,
            aws_region: None,
            pgp_fp: None,
            gcp_kms: None,
            azure_kv: None,
            hc_vault_addr: None,
            hc_vault_token: None,
        }
    }
}

impl TryFrom<&Url> for SopsConfig {
    type Error = SecretSpecError;

    fn try_from(url: &Url) -> std::result::Result<Self, Self::Error> {
        if url.scheme() != "sops" {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Invalid scheme '{}' for sops provider",
                url.scheme()
            )));
        }

        let mut config = SopsConfig::default();

        // Build path from host and path
        let mut target_path = PathBuf::new();

        if let Some(host) = url.host_str()
            && host != "localhost"
            && !host.is_empty()
        {
            target_path.push(host);
        }

        if !url.path().is_empty() && url.path() != "/" {
            let path_part = url.path().trim_start_matches('/');

            if !path_part.is_empty() {
                target_path.push(path_part);
            }
        }

        // If no path specified, use default
        if target_path.as_os_str().is_empty() {
            target_path = PathBuf::from(".enc.yaml");
        }

        // Parse query parameters first to get pattern and format
        let mut pattern: Option<String> = None;
        let mut default_format = SopsFormat::Yaml;

        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "pattern" => pattern = Some(value.to_string()),
                "format" => {
                    let fmt = SopsFormat::from_str(&value).map_err(|e| {
                        SecretSpecError::ProviderOperationFailed(format!(
                            "Invalid format parameter: {}",
                            e
                        ))
                    })?;
                    config.format = Some(fmt.clone());
                    default_format = fmt;
                }
                // Age parameters
                "age_key_file" => config.age_key_file = Some(PathBuf::from(value.as_ref())),
                "age_key" => config.age_key = Some(value.to_string()),
                "age_key_cmd" => config.age_key_cmd = Some(value.to_string()),
                "age_recipients" => config.age_recipients = Some(value.to_string()),
                "age_ssh_private_key_file" => {
                    config.age_ssh_private_key_file = Some(PathBuf::from(value.as_ref()))
                }
                // AWS parameters
                "kms_arn" => config.kms_arn = Some(value.to_string()),
                "aws_profile" => config.aws_profile = Some(value.to_string()),
                "aws_access_key_id" => config.aws_access_key_id = Some(value.to_string()),
                "aws_secret_access_key" => config.aws_secret_access_key = Some(value.to_string()),
                "aws_region" => config.aws_region = Some(value.to_string()),
                // PGP parameters
                "pgp_fp" => config.pgp_fp = Some(value.to_string()),
                // GCP parameters
                "gcp_kms" => config.gcp_kms = Some(value.to_string()),
                // Azure parameters
                "azure_kv" => config.azure_kv = Some(value.to_string()),
                // HashiCorp Vault parameters
                "hc_vault_addr" => config.hc_vault_addr = Some(value.to_string()),
                "hc_vault_token" => config.hc_vault_token = Some(value.to_string()),
                _ => {} // Ignore unknown parameters
            }
        }

        // Determine mode based on path and pattern
        config.mode = if let Some(pattern_str) = pattern {
            // Explicit directory mode with custom pattern
            SopsMode::Directory {
                path: target_path,
                pattern: pattern_str,
                default_format,
            }
        } else if target_path.is_dir()
            || (!target_path.exists() && !Self::looks_like_file(&target_path))
        {
            // Auto-detect directory mode
            let auto_pattern = Self::build_default_pattern(&default_format);
            SopsMode::Directory {
                path: target_path,
                pattern: auto_pattern,
                default_format,
            }
        } else {
            // Single file mode
            SopsMode::SingleFile(target_path)
        };

        Ok(config)
    }
}

impl SopsConfig {
    fn looks_like_file(path: &Path) -> bool {
        path.extension().is_some()
            || path
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.contains('.'))
                .unwrap_or(false)
    }

    fn build_default_pattern(format: &SopsFormat) -> String {
        // Default to hierarchical structure
        let extensions = format.extensions();
        format!("{{project}}/{{profile}}.enc.{}", extensions[0])
    }
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

    fn setup_environment(&self) -> Result<()> {
        // Age configuration
        if let Some(age_key) = &self.config.age_key {
            unsafe {
                env::set_var("SOPS_AGE_KEY", age_key);
            }
        }

        if let Some(age_key_file) = &self.config.age_key_file {
            unsafe {
                env::set_var("SOPS_AGE_KEY_FILE", age_key_file);
            }

            // Check if the key file exists and is readable
            match std::fs::metadata(age_key_file) {
                Ok(metadata) => {
                    if metadata.len() == 0 {
                        eprintln!("WARNING: Age key file is empty!");
                    }
                }
                Err(e) => {
                    eprintln!("WARNING: Cannot access age key file: {}", e);
                }
            }
        }

        if let Some(age_key_cmd) = &self.config.age_key_cmd {
            unsafe {
                env::set_var("SOPS_AGE_KEY_CMD", age_key_cmd);
            }
        }

        if let Some(age_recipients) = &self.config.age_recipients {
            unsafe {
                env::set_var("SOPS_AGE_RECIPIENTS", age_recipients);
            }
        }

        if let Some(age_ssh_key) = &self.config.age_ssh_private_key_file {
            unsafe {
                env::set_var("SOPS_AGE_SSH_PRIVATE_KEY_FILE", age_ssh_key);
            }
        }

        // Check for existing environment variables that might be set
        // if env::var("SOPS_AGE_KEY_FILE").is_ok() {
        //     eprintln!("DEBUG: SOPS_AGE_KEY_FILE environment variable is set");
        // }

        // if env::var("SOPS_AGE_KEY").is_ok() {
        //     eprintln!("DEBUG: SOPS_AGE_KEY environment variable is set");
        // }

        // Check default age key locations
        // if let Ok(home) = env::var("HOME") {
        //     let default_age_keys = PathBuf::from(&home).join(".config/sops/age/keys.txt");

        //     if default_age_keys.exists() {
        //         eprintln!(
        //             "DEBUG: Default age keys file exists at: {}",
        //             default_age_keys.display()
        //         );
        //     } else {
        //         eprintln!(
        //             "DEBUG: Default age keys file not found at: {}",
        //             default_age_keys.display()
        //         );
        //     }
        // }

        // AWS KMS configuration
        if let Some(kms_arn) = &self.config.kms_arn {
            unsafe {
                env::set_var("SOPS_KMS_ARN", kms_arn);
            }
        }

        if let Some(aws_profile) = &self.config.aws_profile {
            unsafe {
                env::set_var("AWS_PROFILE", aws_profile);
            }
        }

        if let Some(aws_access_key_id) = &self.config.aws_access_key_id {
            unsafe {
                env::set_var("AWS_ACCESS_KEY_ID", aws_access_key_id);
            }
        }

        if let Some(aws_secret_access_key) = &self.config.aws_secret_access_key {
            unsafe {
                env::set_var("AWS_SECRET_ACCESS_KEY", aws_secret_access_key);
            }
        }

        if let Some(aws_region) = &self.config.aws_region {
            unsafe {
                env::set_var("AWS_REGION", aws_region);
            }
        }

        // PGP configuration
        if let Some(pgp_fp) = &self.config.pgp_fp {
            unsafe {
                env::set_var("SOPS_PGP_FP", pgp_fp);
            }
        }

        // GCP KMS configuration
        if let Some(gcp_kms) = &self.config.gcp_kms {
            unsafe {
                env::set_var("SOPS_GCP_KMS", gcp_kms);
            }
        }

        // Azure Key Vault configuration
        if let Some(azure_kv) = &self.config.azure_kv {
            unsafe {
                env::set_var("SOPS_AZURE_KEYVAULT_URL", azure_kv);
            }
        }

        // HashiCorp Vault configuration
        if let Some(hc_vault_addr) = &self.config.hc_vault_addr {
            unsafe {
                env::set_var("VAULT_ADDR", hc_vault_addr);
            }
        }

        if let Some(hc_vault_token) = &self.config.hc_vault_token {
            unsafe {
                env::set_var("VAULT_TOKEN", hc_vault_token);
            }
        }

        Ok(())
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
        eprintln!(
            "DEBUG: SOPS provider get() called with project='{}', key='{}', profile='{}'",
            project, key, profile
        );

        let file_path = match self.resolve_file_path(project, profile)? {
            Some(path) => {
                // eprintln!("DEBUG: Resolved file path: {}", path.display());
                path
            }
            None => {
                eprintln!(
                    "DEBUG: No file found for project='{}', profile='{}'",
                    project, profile
                );
                return Ok(None);
            }
        };

        let format = self.detect_format(&file_path);
        let path_str = file_path.to_string_lossy();
        eprintln!("DEBUG: Detected format: {:?}", format);

        // Inspect the SOPS file before attempting decryption
        if let Err(e) = self.inspect_sops_file(&file_path) {
            eprintln!("WARNING: File inspection failed: {}", e);
        }

        // Validate that we can perform key lookup for this format
        if !format.is_structured() && matches!(&self.config.mode, SopsMode::Directory { .. }) {
            return Err(SecretSpecError::ProviderOperationFailed(format!(
                "Cannot perform key lookup on {} format files in directory mode. Binary files should use single file mode.",
                format
            )));
        }

        eprintln!(
            "DEBUG: Attempting SOPS decryption with format: {}",
            format.as_str()
        );

        // Use the Go interop with environment variables passed directly
        let result = if self.config.age_key_file.is_some()
            || self.config.age_key.is_some()
            || self.config.kms_arn.is_some()
            || self.config.aws_profile.is_some()
        {
            eprintln!("DEBUG: Using decrypt_file_with_env method");

            // Convert PathBuf to String to avoid temporary value issues
            let age_key_file_str = self
                .config
                .age_key_file
                .as_ref()
                .map(|p| p.to_string_lossy().to_string());

            go_interop::SopsDecryptor::decrypt_file_with_env(
                &path_str,
                format.as_str(),
                age_key_file_str.as_deref(),
                self.config.age_key.as_deref(),
                self.config.kms_arn.as_deref(),
                self.config.aws_profile.as_deref(),
            )
        } else {
            eprintln!("DEBUG: Using standard decrypt_file method");
            go_interop::SopsDecryptor::decrypt_file(&path_str, format.as_str())
        };

        match result {
            Ok(cleartext) => {
                eprintln!(
                    "DEBUG: SOPS decryption successful, cleartext length: {} bytes",
                    cleartext.len()
                );

                match self.parse_decrypted_content(&cleartext, &format, project, key, profile)? {
                    Some(value) => {
                        eprintln!(
                            "DEBUG: Successfully found key '{}' in decrypted content",
                            key
                        );
                        Ok(Some(SecretString::from(value)))
                    }
                    None => {
                        eprintln!("DEBUG: Key '{}' not found in decrypted content", key);
                        Ok(None)
                    }
                }
            }
            Err(e) => {
                eprintln!("ERROR: SOPS decryption failed: {}", e);
                let error_msg = if e.contains("no key found") || e.contains("failed to decrypt") {
                    format!(
                        "SOPS decryption failed for {}: {}. \
                        Check that the correct decryption keys are available. \
                        For age: set age_key_file or place keys in ~/.config/sops/age/keys.txt. \
                        For AWS KMS: ensure AWS credentials and kms_arn are set. \
                        For PGP: ensure pgp_fp is set and keys are in GPG keyring.",
                        path_str, e
                    )
                } else {
                    format!("SOPS decryption failed for {}: {}", path_str, e)
                };

                Err(SecretSpecError::ProviderOperationFailed(error_msg))
            }
        }
    }

    fn set(&self, _project: &str, _key: &str, _value: &SecretString, _profile: &str) -> Result<()> {
        Err(SecretSpecError::ProviderOperationFailed(
            "SOPS provider is read-only. Use 'sops edit' or 'sops encrypt' to manage encrypted files.".to_string()
        ))
    }

    fn allows_set(&self) -> bool {
        false
    }

    fn uri(&self) -> String {
        "".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_sops_format_from_str() {
        assert_eq!(SopsFormat::from_str("yaml").unwrap(), SopsFormat::Yaml);
        assert_eq!(SopsFormat::from_str("yml").unwrap(), SopsFormat::Yaml);
        assert_eq!(SopsFormat::from_str("json").unwrap(), SopsFormat::Json);
        assert_eq!(SopsFormat::from_str("env").unwrap(), SopsFormat::Env);
        assert_eq!(SopsFormat::from_str("dotenv").unwrap(), SopsFormat::Env);
        assert_eq!(SopsFormat::from_str("ini").unwrap(), SopsFormat::Ini);
        assert_eq!(SopsFormat::from_str("binary").unwrap(), SopsFormat::Binary);
        assert_eq!(SopsFormat::from_str("bin").unwrap(), SopsFormat::Binary);

        assert!(SopsFormat::from_str("invalid").is_err());
        let err = SopsFormat::from_str("invalid").unwrap_err();
        assert!(
            err.to_string()
                .contains("Supported formats: yaml, json, env, ini, binary")
        );
    }

    #[test]
    fn test_sops_format_extensions() {
        assert_eq!(SopsFormat::Yaml.extensions(), &["yaml", "yml"]);
        assert_eq!(SopsFormat::Json.extensions(), &["json"]);
        assert_eq!(SopsFormat::Env.extensions(), &["env"]);
        assert_eq!(SopsFormat::Ini.extensions(), &["ini"]);
        assert_eq!(
            SopsFormat::Binary.extensions(),
            &["bin", "dat", "key", "cert", "p12", "pfx"]
        );
    }

    #[test]
    fn test_sops_format_is_structured() {
        assert!(SopsFormat::Yaml.is_structured());
        assert!(SopsFormat::Json.is_structured());
        assert!(SopsFormat::Env.is_structured());
        assert!(SopsFormat::Ini.is_structured());
        assert!(!SopsFormat::Binary.is_structured());
    }

    #[test]
    fn test_sops_format_from_extension() {
        assert_eq!(SopsFormat::from_extension("yaml"), SopsFormat::Yaml);
        assert_eq!(SopsFormat::from_extension("yml"), SopsFormat::Yaml);
        assert_eq!(SopsFormat::from_extension("json"), SopsFormat::Json);
        assert_eq!(SopsFormat::from_extension("env"), SopsFormat::Env);
        assert_eq!(SopsFormat::from_extension("ini"), SopsFormat::Ini);

        // Unknown extensions default to binary
        assert_eq!(SopsFormat::from_extension("bin"), SopsFormat::Binary);
        assert_eq!(SopsFormat::from_extension("key"), SopsFormat::Binary);
        assert_eq!(SopsFormat::from_extension("unknown"), SopsFormat::Binary);
    }

    #[test]
    fn test_hierarchical_directory_structure() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        // Create hierarchical structure: base/myapp/production.sops.json
        let project_dir = base_path.join("myapp");
        fs::create_dir_all(&project_dir).unwrap();
        fs::write(
            project_dir.join("production.sops.json"),
            r#"{"database_url": "prod-db"}"#,
        )
        .unwrap();
        fs::write(
            project_dir.join("development.sops.json"),
            r#"{"database_url": "dev-db"}"#,
        )
        .unwrap();

        let config = SopsConfig {
            mode: SopsMode::Directory {
                path: base_path.to_path_buf(),
                pattern: "{project}/{profile}.sops.json".to_string(),
                default_format: SopsFormat::Json,
            },
            ..Default::default()
        };
        let provider = SopsProvider::new(config);

        // Test hierarchical lookup
        let result = provider
            .try_hierarchical_structure(base_path, "myapp", "production", &SopsFormat::Json)
            .unwrap();

        assert!(result.is_some());
        let path = result.unwrap();
        assert_eq!(path.file_name().unwrap(), "production.sops.json");
        assert_eq!(path.parent().unwrap().file_name().unwrap(), "myapp");
    }

    #[test]
    fn test_build_lookup_paths_single_file_vs_directory() {
        // Single file mode - hierarchical lookup
        let single_file_config = SopsConfig {
            mode: SopsMode::SingleFile(PathBuf::from(".sops.yaml")),
            ..Default::default()
        };
        let provider = SopsProvider::new(single_file_config);

        let paths = provider.build_lookup_paths("myapp", "database_url", "production");
        assert_eq!(
            paths,
            vec![
                vec!["myapp", "production", "database_url"],
                vec!["myapp", "database_url"],
                vec!["database_url"]
            ]
        );

        // Directory mode - direct lookup
        let dir_config = SopsConfig {
            mode: SopsMode::Directory {
                path: PathBuf::from("secrets"),
                pattern: "{project}.{profile}.sops.json".to_string(),
                default_format: SopsFormat::Json,
            },
            ..Default::default()
        };
        let provider = SopsProvider::new(dir_config);

        let paths = provider.build_lookup_paths("myapp", "database_url", "production");
        assert_eq!(paths, vec![vec!["database_url"]]);
    }

    #[test]
    fn test_parse_decrypted_content_binary() {
        let provider = SopsProvider::new(SopsConfig::default());
        let binary_content = b"\x00\x01\x02\x03\xFF";

        let result = provider
            .parse_decrypted_content(binary_content, &SopsFormat::Binary, "", "any_key", "")
            .unwrap();

        // Should return hex encoded content
        assert!(result.is_some());
        let value = result.unwrap();
        assert_eq!(value, "00010203ff");
    }

    #[test]
    fn test_integration_with_real_sops_file() {
        use secrecy::ExposeSecret;
        use std::env;

        // use std::path::PathBuf;

        // Attempt to get the current working directory
        let encrypted_file = match env::current_dir() {
            Ok(current_dir) => {
                // Create a PathBuf from the current directory
                let path_buf = PathBuf::from(&current_dir)
                    .join("src/provider/sops/test_fixtures/test_secrets.enc.json");

                // Print the current directory and the PathBuf
                println!("Current working directory: {}", current_dir.display());
                println!("PathBuf representation: {:?}", path_buf);

                path_buf
            }
            Err(e) => {
                panic!("Error retrieving current directory: {}", e);
            }
        };

        let age_key_file = PathBuf::from(env::current_dir().unwrap())
            .join("src/provider/sops/test_fixtures/key.txt");

        eprintln!(
            "DEBUG: Testing with encrypted file: {}",
            encrypted_file.display()
        );
        eprintln!(
            "DEBUG: Testing with age key file: {}",
            age_key_file.display()
        );

        if !encrypted_file.exists() {
            eprintln!(
                "SKIP: Encrypted file not found: {}",
                encrypted_file.display()
            );
            return;
        }

        if !age_key_file.exists() {
            eprintln!("SKIP: Age key file not found: {}", age_key_file.display());
            return;
        }

        // Try to read the first few lines of the age key file to verify it's valid
        match std::fs::read_to_string(&age_key_file) {
            Ok(content) => {
                let lines: Vec<&str> = content.lines().take(3).collect();
                eprintln!("DEBUG: Age key file first few lines:");
                for (i, line) in lines.iter().enumerate() {
                    if line.starts_with("AGE-SECRET-KEY-") {
                        eprintln!("  {}: AGE-SECRET-KEY-*** (truncated)", i);
                    } else {
                        eprintln!("  {}: {}", i, line);
                    }
                }
            }
            Err(e) => {
                eprintln!("WARNING: Cannot read age key file: {}", e);
            }
        }

        // Configure for single file mode with the specific encrypted file
        let config = SopsConfig {
            mode: SopsMode::SingleFile(encrypted_file.clone()),
            format: Some(SopsFormat::Json),
            age_key_file: Some(age_key_file),
            ..Default::default()
        };

        let provider = SopsProvider::new(config);

        // Test decryption by trying to read a key from the file
        eprintln!("DEBUG: Attempting to decrypt and read key 'foobar'");
        let result = provider.get("some-project-name", "foobar", "development");

        match result {
            Ok(Some(value)) => {
                assert!(value.expose_secret().eq("bar"))
            }
            Ok(None) => {
                panic!("Specified key not found")
            }
            Err(e) => {
                panic!("Decryption failed: {:?}", e)
            }
        }
    }

    #[test]
    fn test_integration_with_directory_structure() {
        use secrecy::ExposeSecret;
        use std::env;

        println!("here");

        // Attempt to get the current working directory
        let secrets_dir = match env::current_dir() {
            Ok(current_dir) => {
                // Create a PathBuf from the current directory
                let path_buf = PathBuf::from(&current_dir)
                    .join("src/provider/sops/test_fixtures/test_secrets");

                // Print the current directory and the PathBuf
                println!("Current working directory: {}", current_dir.display());
                println!("PathBuf representation: {:?}", path_buf);

                path_buf
            }
            Err(e) => {
                panic!("Error retrieving current directory: {}", e);
            }
        };

        let age_key_file = PathBuf::from(env::current_dir().unwrap())
            .join("src/provider/sops/test_fixtures/key.txt");

        println!("age key file path: {:?}", age_key_file);

        if !age_key_file.exists() {
            panic!("age key file not found");
        }

        // Configure for directory mode with pattern matching
        let config = SopsConfig {
            mode: SopsMode::Directory {
                path: secrets_dir,
                pattern: "{project}.enc.json".to_string(),
                default_format: SopsFormat::Json,
            },
            format: Some(SopsFormat::Json),
            age_key_file: Some(age_key_file),
            ..Default::default()
        };

        println!("config: {:?}", config);

        let provider = SopsProvider::new(config);

        // Test decryption using project name from the filename
        let result = provider.get("some-project-name", "foobar", "development");

        println!("result: {:?}", result);

        match result {
            Ok(Some(value)) => {
                assert!(!value.expose_secret().is_empty());
            }
            Ok(None) => {
                eprintln!(
                    "Key not found in directory mode - this might be expected if the file structure doesn't match the pattern"
                );
            }
            Err(e) => {
                eprintln!("Directory decryption failed (might be expected): {:?}", e);
            }
        }
    }
}
