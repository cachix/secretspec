use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

/// Test helper for creating temporary directories with test configs
pub struct TestFixture {
    _temp_dir: TempDir,
    pub base_path: PathBuf,
}

impl TestFixture {
    pub fn new() -> Self {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().to_path_buf();
        Self {
            _temp_dir: temp_dir,
            base_path,
        }
    }

    /// Create a directory structure for extends testing
    pub fn create_extends_structure(&self) -> (PathBuf, PathBuf, PathBuf) {
        // Create directories
        let common_dir = self.base_path.join("common");
        let auth_dir = self.base_path.join("auth");
        let base_dir = self.base_path.join("base");

        fs::create_dir_all(&common_dir).unwrap();
        fs::create_dir_all(&auth_dir).unwrap();
        fs::create_dir_all(&base_dir).unwrap();

        // Create common config
        let common_config = r#"
[project]
name = "common"
revision = "1.0"

[profiles.default]
DATABASE_URL = { description = "Database connection string", required = false, default = "sqlite:///dev.db" }
REDIS_URL = { description = "Redis connection URL", required = false, default = "redis://localhost:6379" }
"#;
        let common_path = common_dir.join("monosecret.toml");
        fs::write(&common_path, common_config).unwrap();

        // Create auth config
        let auth_config = r#"
[project]
name = "auth"
revision = "1.0"

[profiles.default]
JWT_SECRET = { description = "Secret key for JWT token signing", required = true }
OAUTH_CLIENT_ID = { description = "OAuth client ID", required = false }
"#;
        let auth_path = auth_dir.join("monosecret.toml");
        fs::write(&auth_path, auth_config).unwrap();

        // Create base config that extends from common and auth
        let base_config = r#"
[project]
name = "test_project"
revision = "1.0"
extends = ["../common", "../auth"]

[profiles.default]
API_KEY = { description = "API key for external service", required = true }
DATABASE_URL = { description = "Override database connection", required = true }

[profiles.development]
API_KEY = { description = "API key for external service", required = false, default = "dev-api-key" }
"#;
        let base_path = base_dir.join("monosecret.toml");
        fs::write(&base_path, base_config).unwrap();

        (common_path, auth_path, base_path)
    }
}

impl Default for TestFixture {
    fn default() -> Self {
        Self::new()
    }
}
