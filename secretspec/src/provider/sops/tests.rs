use crate::provider::sops::config::SopsConfig;

use super::*;
use std::{fs, str::FromStr};
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

    let age_key_file =
        PathBuf::from(env::current_dir().unwrap()).join("src/provider/sops/test_fixtures/key.txt");

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
            let path_buf =
                PathBuf::from(&current_dir).join("src/provider/sops/test_fixtures/test_secrets");

            // Print the current directory and the PathBuf
            println!("Current working directory: {}", current_dir.display());
            println!("PathBuf representation: {:?}", path_buf);

            path_buf
        }
        Err(e) => {
            panic!("Error retrieving current directory: {}", e);
        }
    };

    let age_key_file =
        PathBuf::from(env::current_dir().unwrap()).join("src/provider/sops/test_fixtures/key.txt");

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

    println!(
        "result: {:?}",
        result.as_ref().unwrap().as_ref().unwrap().expose_secret()
    );

    match result {
        Ok(Some(value)) => {
            assert!(!value.expose_secret().is_empty());

            assert!(value.expose_secret().eq("foo"));
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
