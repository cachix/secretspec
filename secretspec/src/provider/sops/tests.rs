use super::*;
use crate::provider::sops::config::SopsConfig;
use std::{
    collections::HashMap,
    fs,
    sync::{Arc, Barrier},
    thread,
};
use tempfile::TempDir;
use url::Url;

fn build_sops_provider(
    path: &str,
    query_parameters: Option<HashMap<&str, &str>>,
) -> Box<dyn Provider> {
    let mut params: HashMap<&str, &str> = HashMap::from([
        ("age_key_file", "./src/provider/sops/test_fixtures/key.txt"),
        (
            "age_recipients",
            "age1jpa8rf5qmrg6pw444fcgpkaxg8x4neueszrexzagdjpunjlgeyzq304w34",
        ),
    ]);

    if let Some(custom) = query_parameters {
        for (k, v) in custom {
            params.insert(k, v);
        }
    }

    let query = params
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");

    let spec = format!("sops://{path}?{query}");
    Box::<dyn Provider>::try_from(spec.as_str()).expect("Provider init failed")
}

#[test]
fn test_sops_build_lookup_paths_single_file_vs_directory() {
    let single_file_config = SopsConfig {
        mode: SopsMode::SingleFile(PathBuf::from(".sops.yaml")),
        ..Default::default()
    };

    let provider = SopsProvider::new(single_file_config);

    let paths = provider.lookup_paths(&AddressParts {
        key: "database_url",
        profile: "production",
        project: "myapp",
    });

    assert_eq!(
        paths.unwrap(),
        vec![
            vec!["myapp", "production", "database_url"],
            vec!["production", "database_url"],
            vec!["database_url"]
        ]
    );

    let dir_config = SopsConfig {
        format: SopsFormat::Json,
        mode: SopsMode::Directory {
            path: PathBuf::from("secrets"),
            pattern: SopsPathPattern::try_from("{project}.{profile}.sops.json").unwrap(),
            format: SopsFormat::Json,
        },
        ..Default::default()
    };

    let provider = SopsProvider::new(dir_config);

    let paths = provider.lookup_paths(&AddressParts {
        key: "database_url",
        profile: "production",
        project: "myapp",
    });
    assert_eq!(paths.unwrap(), vec![vec!["database_url"]]);
}

#[test]
fn test_sops_normalized_json_selects_the_requested_key() {
    let provider = SopsProvider::new(SopsConfig {
        format: SopsFormat::Env,
        mode: SopsMode::Directory {
            path: PathBuf::from("secrets"),
            pattern: SopsPathPattern::try_from("{project}.{profile}.env").unwrap(),
            format: SopsFormat::Env,
        },
        ..Default::default()
    });
    let content = br#"{"DB_PASSWORD":"hunter2","API_KEY":"abc"}"#;
    let requested = AddressParts {
        project: "app",
        profile: "production",
        key: "API_KEY",
    };
    assert_eq!(
        provider.parse_decrypted_json(content, &requested).unwrap(),
        Some("abc".to_string())
    );

    let missing = AddressParts {
        key: "MISSING",
        ..requested
    };
    assert_eq!(
        provider.parse_decrypted_json(content, &missing).unwrap(),
        None
    );
}

#[test]
fn test_sops_dotenv_writes_use_a_flat_key() {
    let provider = SopsProvider::new(SopsConfig {
        format: SopsFormat::Env,
        mode: SopsMode::SingleFile(PathBuf::from("secrets.env")),
        ..Default::default()
    });
    let parts = AddressParts {
        project: "app",
        profile: "production",
        key: "API_KEY",
    };
    assert_eq!(provider.set_path(&parts).unwrap(), r#"["API_KEY"]"#);
}

#[test]
fn test_sops_write_target_describes_file_and_nested_selector() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("secrets.enc.yaml");
    let provider = SopsProvider::new(SopsConfig {
        format: SopsFormat::Yaml,
        mode: SopsMode::SingleFile(path.clone()),
        ..Default::default()
    });

    let target = provider
        .describe_write_target(Address::convention("my-app", "production", "API_KEY"))
        .unwrap();
    let expected_path = temp.path().canonicalize().unwrap().join("secrets.enc.yaml");
    assert_eq!(
        target,
        format!(
            r#"{} ["my-app"]["production"]["API_KEY"]"#,
            expected_path.display()
        )
    );
}

#[cfg(unix)]
#[test]
fn test_sops_write_target_resolves_existing_file_symlink() {
    let temp = TempDir::new().unwrap();
    let physical_path = temp.path().join("physical.enc.yaml");
    fs::write(&physical_path, "").unwrap();
    let configured_path = temp.path().join("configured.enc.yaml");
    std::os::unix::fs::symlink(&physical_path, &configured_path).unwrap();
    let provider = SopsProvider::new(SopsConfig {
        format: SopsFormat::Yaml,
        mode: SopsMode::SingleFile(configured_path),
        ..Default::default()
    });

    let target = provider
        .describe_write_target(Address::convention("my-app", "production", "API_KEY"))
        .unwrap();
    assert_eq!(
        target,
        format!(
            r#"{} ["my-app"]["production"]["API_KEY"]"#,
            physical_path.canonicalize().unwrap().display()
        )
    );
}

#[test]
fn test_sops_templated_write_target_describes_flat_selector() {
    let temp = TempDir::new().unwrap();
    let provider = SopsProvider::new(SopsConfig {
        format: SopsFormat::Json,
        mode: SopsMode::Directory {
            path: temp.path().to_path_buf(),
            pattern: SopsPathPattern::try_from("{project}/{profile}.enc.json").unwrap(),
            format: SopsFormat::Json,
        },
        ..Default::default()
    });

    let target = provider
        .describe_write_target(Address::convention("my-app", "production", "API_KEY"))
        .unwrap();
    let expected_path = temp
        .path()
        .canonicalize()
        .unwrap()
        .join("my-app")
        .join("production.enc.json");
    assert_eq!(
        target,
        format!(r#"{} ["API_KEY"]"#, expected_path.display())
    );
}

#[test]
fn test_sops_ini_ref_write_target_describes_default_section() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("secrets.enc.ini");
    let provider = SopsProvider::new(SopsConfig {
        format: SopsFormat::Ini,
        mode: SopsMode::SingleFile(path.clone()),
        ..Default::default()
    });
    let native = NativeAddress {
        item: "existing_token".to_string(),
        ..Default::default()
    };

    let target = provider
        .describe_write_target(Address::Native(&native))
        .unwrap();
    let expected_path = temp.path().canonicalize().unwrap().join("secrets.enc.ini");
    assert_eq!(
        target,
        format!(
            r#"{} ["DEFAULT"]["existing_token"]"#,
            expected_path.display()
        )
    );
}

#[test]
fn test_sops_set_reads_the_value_from_stdin() {
    let provider = SopsProvider::new(SopsConfig {
        format: SopsFormat::Json,
        mode: SopsMode::SingleFile(PathBuf::from("secrets.enc.json")),
        ..Default::default()
    });
    let parts = AddressParts {
        project: "app",
        profile: "production",
        key: "API_KEY",
    };

    let args = provider
        .set_command_args(Path::new("temporary.enc.json"), &parts)
        .unwrap();

    assert!(args.iter().any(|arg| arg == "--value-stdin"));
    assert_eq!(
        &args[args.len() - 2..],
        ["temporary.enc.json", r#"["app"]["production"]["API_KEY"]"#]
    );
}

#[test]
fn test_sops_invalid_format() {
    let url = Url::parse("sops://./secrets.enc.json?format=invalid").unwrap();

    let provider_result: std::result::Result<Box<dyn Provider>, _> = (&url).try_into();

    assert!(provider_result.is_err());
}

fn run_sops_single_file_test(ext: &str) {
    let provider = build_sops_provider(
        format!("src/provider/sops/test_fixtures/single_file/some-project-name.enc.{ext}").as_str(),
        None,
    );

    let expected = [("development", "bar"), ("production", "baz")];

    for (profile, expected_value) in expected {
        if let Some(value) = provider
            .get(Address::convention("some-project-name", profile, "foobar"))
            .expect("Failed to fetch secret")
        {
            let secret = value.try_as_utf8().unwrap();

            assert_eq!(
                expected_value, secret,
                r#"Expected "{expected_value}", got "{secret}""#
            );
        }
    }
}

#[test]
fn test_sops_single_file_get_ini() {
    run_sops_single_file_test("ini");
}

#[test]
fn test_sops_single_file_get_yaml() {
    run_sops_single_file_test("yaml");
}

#[test]
fn test_sops_single_file_get_json() {
    run_sops_single_file_test("json");
}

#[test]
fn test_sops_directory_get_json() {
    let provider = build_sops_provider(
        "src/provider/sops/test_fixtures/directory/{project}/{profile}.enc.json",
        None,
    );

    let expected = [("development", "bar"), ("production", "baz")];

    for (profile, expected_value) in expected {
        match provider.get(Address::convention("some-project-name", profile, "foobar")) {
            Ok(value) => match value {
                Some(secret_box) => {
                    let secret = secret_box.try_as_utf8().unwrap();

                    assert_eq!(
                        expected_value, secret,
                        r#"Expected "{expected_value}", got "{secret}""#
                    );
                }
                None => panic!(
                    "'foobar' under profile '{}' in project 'some-project-name' not found",
                    profile,
                ),
            },
            Err(e) => {
                panic!("{}", e);
            }
        }
    }
}

#[test]
fn test_sops_directory_nested_get_json() {
    let provider = build_sops_provider(
        "src/provider/sops/test_fixtures/directory/{project}/{profile}/secrets.enc.json",
        None,
    );

    let expected = [("development", "bar"), ("production", "baz")];

    for (profile, expected_value) in expected {
        match provider.get(Address::convention("some-project-name", profile, "foobar")) {
            Ok(value) => match value {
                Some(secret_box) => {
                    let secret = secret_box.try_as_utf8().unwrap();

                    assert_eq!(
                        expected_value, secret,
                        r#"Expected "{expected_value}", got "{secret}""#
                    );
                }
                None => panic!(
                    "'foobar' under profile '{}' in project 'some-project-name' not found",
                    profile,
                ),
            },
            Err(e) => {
                panic!("{}", e);
            }
        }
    }
}

#[test]
fn test_sops_directory_get_dotenv() {
    let provider = build_sops_provider(
        "src/provider/sops/test_fixtures/directory/{project}/.env.{profile}.enc",
        Some(HashMap::from([("format", "dotenv")])),
    );

    let expected = [("development", "bar"), ("production", "baz")];

    for (profile, expected_value) in expected {
        match provider.get(Address::convention("some-project-name", profile, "foobar")) {
            Ok(value) => match value {
                Some(secret_box) => {
                    let secret = secret_box.try_as_utf8().unwrap();

                    assert_eq!(
                        expected_value, secret,
                        r#"Expected "{expected_value}", got "{secret}""#
                    );
                }
                None => panic!(
                    "'foobar' under profile '{}' in project 'some-project-name' not found",
                    profile,
                ),
            },
            Err(e) => {
                panic!("{}", e);
            }
        }
    }
}

#[test]
fn test_sops_set_directory_dotenv_with_format_override() {
    let temp = TempDir::new().unwrap();
    let provider = build_sops_provider(
        &format!("{}/{{project}}/.env.{{profile}}.enc", temp.path().display()),
        Some(HashMap::from([("format", "dotenv")])),
    );
    let addr = Address::convention("myapp", "production", "API_KEY");

    provider
        .set(addr, &SecretBytes::new("dotenv-value".into()))
        .expect("set failed");
    let value = provider.get(addr).unwrap().expect("missing value");

    assert_eq!(value.expose_secret(), b"dotenv-value");
}

#[test]
fn test_sops_set_single_file_dotenv_uses_a_flat_key() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("secrets.enc");
    let provider = build_sops_provider(
        &path.to_string_lossy(),
        Some(HashMap::from([("format", "dotenv")])),
    );
    let addr = Address::convention("myapp", "production", "API_KEY");

    provider
        .set(addr, &SecretBytes::new("flat-value".into()))
        .expect("set failed");
    let value = provider.get(addr).unwrap().expect("missing value");

    assert_eq!(value.expose_secret(), b"flat-value");
}

#[test]
fn test_sops_json_override_works_with_ini_extension() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("secrets.enc.ini");
    let provider = build_sops_provider(
        &path.to_string_lossy(),
        Some(HashMap::from([("format", "json")])),
    );
    let addr = Address::convention("myapp", "production", "API_KEY");

    provider
        .set(addr, &SecretBytes::new("json-value".into()))
        .expect("set failed");
    let value = provider.get(addr).unwrap().expect("missing value");

    assert_eq!(value.expose_secret(), b"json-value");
}

#[test]
fn test_sops_age_key_provider_credential_overrides_the_environment() {
    let url =
        Url::parse("sops://src/provider/sops/test_fixtures/single_file/some-project-name.enc.json")
            .unwrap();
    let provider_url = ProviderUrl::new(url);
    let config = SopsConfig::try_from(&provider_url).unwrap();
    let mut provider = SopsProvider::new(config);
    let key_file = fs::read_to_string("src/provider/sops/test_fixtures/key.txt").unwrap();
    let age_key = key_file
        .lines()
        .find(|line| line.starts_with("AGE-SECRET-KEY-"))
        .unwrap();
    let mut credentials = ProviderCredentials::new();
    credentials.insert(AGE_KEY.to_string(), SecretBytes::new(age_key.into()));
    provider.with_credentials(credentials);

    let value = provider
        .get(Address::convention(
            "some-project-name",
            "production",
            "foobar",
        ))
        .unwrap()
        .expect("missing value");

    assert_eq!(value.expose_secret(), b"baz");
}

#[test]
fn test_sops_set_single_file_creates_tree_and_sets_value() {
    let temp = TempDir::new().unwrap();

    let file_path = temp.path().join("secrets.enc.yaml");

    let provider = build_sops_provider(&file_path.to_string_lossy(), None);

    provider
        .set(
            Address::convention("myapp", "production", "database_url"),
            &SecretBytes::new("postgres://prod".into()),
        )
        .expect("set failed");

    let value = provider
        .get(Address::convention("myapp", "production", "database_url"))
        .expect("get failed")
        .expect("missing value");

    assert_eq!(value.expose_secret(), b"postgres://prod");
}

#[test]
fn test_sops_set_directory_creates_file_and_sets_value() {
    let temp = TempDir::new().unwrap();

    let base = temp.path();

    let provider = build_sops_provider(
        format!(
            "{}/{{project}}/{{profile}}.enc.json",
            &base.to_string_lossy()
        )
        .as_str(),
        None,
    );

    // Set a value into a file that does not exist yet
    provider
        .set(
            Address::convention("myapp", "development", "api_key"),
            &SecretBytes::new("xyz123".into()),
        )
        .expect("set failed");

    let expected_file = base.join("myapp/development.enc.json");

    assert!(expected_file.exists());

    let value = provider
        .get(Address::convention("myapp", "development", "api_key"))
        .expect("get failed")
        .expect("missing value");

    assert_eq!(value.expose_secret(), b"xyz123");
}

#[test]
fn test_sops_set_overwrites_existing_value() {
    let temp = TempDir::new().unwrap();

    let file_path = temp.path().join("secrets.enc.json");

    fs::write(&file_path, "{}").unwrap();

    let provider = build_sops_provider(&file_path.to_string_lossy(), None);

    provider
        .set(
            Address::convention("proj", "dev", "token"),
            &SecretBytes::new("first".into()),
        )
        .expect("set failed");

    provider
        .set(
            Address::convention("proj", "dev", "token"),
            &SecretBytes::new("second".into()),
        )
        .expect("set failed");

    let value = provider
        .get(Address::convention("proj", "dev", "token"))
        .expect("get failed")
        .expect("missing value");

    assert_eq!(value.expose_secret(), b"second");
}

#[test]
fn test_sops_set_single_file_default_profile() {
    let temp = TempDir::new().unwrap();

    let file_path = temp.path().join("secrets.enc.yaml");

    let provider = build_sops_provider(&file_path.to_string_lossy(), None);

    provider
        .set(
            Address::convention("myapp", "default", "service_url"),
            &SecretBytes::new("http://localhost".into()),
        )
        .expect("set failed");

    let value = provider
        .get(Address::convention("myapp", "default", "service_url"))
        .expect("get failed")
        .expect("missing value");

    assert_eq!(value.expose_secret(), b"http://localhost");
}

#[test]
fn test_sops_single_file_default_profile_keeps_project_namespaces_separate() {
    let temp = TempDir::new().unwrap();
    let file_path = temp.path().join("secrets.enc.json");
    let provider = build_sops_provider(&file_path.to_string_lossy(), None);

    provider
        .set(
            Address::convention("project-a", "default", "API_KEY"),
            &SecretBytes::new("value-a".into()),
        )
        .unwrap();
    provider
        .set(
            Address::convention("project-b", "default", "API_KEY"),
            &SecretBytes::new("value-b".into()),
        )
        .unwrap();

    for (project, expected) in [("project-a", "value-a"), ("project-b", "value-b")] {
        let value = provider
            .get(Address::convention(project, "default", "API_KEY"))
            .unwrap()
            .unwrap();
        assert_eq!(value.expose_secret(), expected.as_bytes());
    }
}

#[test]
fn test_sops_templated_ini_set_round_trips_through_default_section() {
    let temp = TempDir::new().unwrap();
    let provider = build_sops_provider(
        &format!("{}/{{project}}/{{profile}}.enc.ini", temp.path().display()),
        None,
    );
    let address = Address::convention("myapp", "production", "API_KEY");

    provider
        .set(address, &SecretBytes::new("ini-value".into()))
        .unwrap();
    let value = provider.get(address).unwrap().unwrap();

    assert_eq!(value.expose_secret(), b"ini-value");
}

#[test]
fn test_sops_single_file_ini_native_ref_uses_default_section() {
    let temp = TempDir::new().unwrap();
    let file_path = temp.path().join("secrets.enc.ini");
    let provider = build_sops_provider(&file_path.to_string_lossy(), None);
    let native = NativeAddress {
        item: "API_KEY".to_string(),
        ..Default::default()
    };
    let address = Address::Native(&native);

    provider
        .set(address, &SecretBytes::new("native-ini-value".into()))
        .unwrap();
    let value = provider.get(address).unwrap().unwrap();

    assert_eq!(value.expose_secret(), b"native-ini-value");
}

#[test]
fn test_sops_concurrent_writes_preserve_every_key() {
    let temp = TempDir::new().unwrap();
    let file_path = temp.path().join("secrets.enc.json");
    let path = file_path.to_string_lossy().into_owned();
    let barrier = Arc::new(Barrier::new(4));

    thread::scope(|scope| {
        for index in 0..4 {
            let provider = build_sops_provider(&path, None);
            let barrier = Arc::clone(&barrier);
            scope.spawn(move || {
                barrier.wait();
                provider
                    .set(
                        Address::convention("myapp", "production", &format!("KEY_{index}")),
                        &SecretBytes::new(format!("value-{index}").into()),
                    )
                    .unwrap();
            });
        }
    });

    let provider = build_sops_provider(&path, None);
    for index in 0..4 {
        let key = format!("KEY_{index}");
        let value = provider
            .get(Address::convention("myapp", "production", &key))
            .unwrap()
            .unwrap();
        assert_eq!(value.expose_secret(), format!("value-{index}").as_bytes());
    }
}

#[test]
fn test_sops_get_many_reads_multiple_keys_from_one_file() {
    let temp = TempDir::new().unwrap();
    let file_path = temp.path().join("secrets.enc.json");
    let provider = build_sops_provider(&file_path.to_string_lossy(), None);
    let database = Address::convention("myapp", "production", "DATABASE_URL");
    let token = Address::convention("myapp", "production", "API_TOKEN");

    provider
        .set(database, &SecretBytes::new("postgres://db".into()))
        .unwrap();
    provider
        .set(token, &SecretBytes::new("token-value".into()))
        .unwrap();

    let values = provider
        .get_many(&[("DATABASE_URL", database), ("API_TOKEN", token)])
        .unwrap();
    assert_eq!(
        values.get("DATABASE_URL").unwrap().expose_secret(),
        b"postgres://db"
    );
    assert_eq!(
        values.get("API_TOKEN").unwrap().expose_secret(),
        b"token-value"
    );
}

#[test]
fn test_sops_creation_rules_are_discovered_from_the_manifest_directory() {
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("project");
    fs::create_dir_all(&project).unwrap();
    fs::write(
        project.join(".sops.yaml"),
        "creation_rules:\n\
         \x20 - path_regex: 'secrets\\.enc\\.json$'\n\
         \x20   age: age1jpa8rf5qmrg6pw444fcgpkaxg8x4neueszrexzagdjpunjlgeyzq304w34\n",
    )
    .unwrap();
    let key_file = fs::canonicalize("src/provider/sops/test_fixtures/key.txt").unwrap();
    let spec = format!(
        "sops://secrets.enc.json?age_key_file={}",
        ProviderUrl::encode_query(&key_file.to_string_lossy())
    );
    let mut provider = Box::<dyn Provider>::try_from(spec.as_str()).unwrap();
    provider.with_base_dir(&project);
    let address = Address::convention("myapp", "production", "API_KEY");

    provider
        .set(address, &SecretBytes::new("project-config-value".into()))
        .unwrap();
    let value = provider.get(address).unwrap().unwrap();

    assert_eq!(value.expose_secret(), b"project-config-value");
}

#[test]
fn test_sops_failed_decrypt_does_not_modify_the_original_file() {
    let temp = TempDir::new().unwrap();
    let file_path = temp.path().join("secrets.enc.json");
    fs::copy(
        "src/provider/sops/test_fixtures/single_file/some-project-name.enc.json",
        &file_path,
    )
    .unwrap();
    let mut provider = SopsProvider::new(SopsConfig {
        format: SopsFormat::Json,
        mode: SopsMode::SingleFile(file_path.clone()),
        ..Default::default()
    });
    let mut credentials = ProviderCredentials::new();
    credentials.insert(
        AGE_KEY.to_string(),
        SecretBytes::new(
            "AGE-SECRET-KEY-1QYPQXPQ9QCRSSZG2PVXQ6RS0ZQG3YYC5Z5TPWXQERGD3C8G7RUSQGPQYEE".into(),
        ),
    );
    provider.with_credentials(credentials);
    let before = fs::read(&file_path).unwrap();

    let result = provider.set(
        Address::convention("some-project-name", "production", "foobar"),
        &SecretBytes::new("must-not-be-written".into()),
    );

    assert!(result.is_err());
    assert_eq!(fs::read(&file_path).unwrap(), before);
}

#[test]
fn test_sops_set_directory_multiple_profiles() {
    let temp = TempDir::new().unwrap();

    let base = temp.path();

    let provider = build_sops_provider(
        format!(
            "{}/{{project}}/{{profile}}.enc.yaml",
            &base.to_string_lossy()
        )
        .as_str(),
        None,
    );

    provider
        .set(
            Address::convention("myapp", "development", "db"),
            &SecretBytes::new("dev-db".into()),
        )
        .expect("set failed");

    provider
        .set(
            Address::convention("myapp", "production", "db"),
            &SecretBytes::new("prod-db".into()),
        )
        .expect("set failed");

    let dev = provider
        .get(Address::convention("myapp", "development", "db"))
        .unwrap()
        .unwrap()
        .try_as_utf8()
        .unwrap()
        .to_string();

    let prod = provider
        .get(Address::convention("myapp", "production", "db"))
        .unwrap()
        .unwrap()
        .try_as_utf8()
        .unwrap()
        .to_string();

    assert_eq!(dev, "dev-db");
    assert_eq!(prod, "prod-db");
}

#[test]
fn test_sops_provider_advertises_credentials() {
    let expected = [
        "age_key",
        "aws_secret_access_key",
        "azure_client_secret",
        "hc_vault_token",
        "huawei_sdk_ak",
        "huawei_sdk_sk",
        "google_oauth_access_token",
    ];
    assert_eq!(
        crate::provider::credential_names_for_spec("sops://secrets.enc.yaml"),
        expected
    );
}

#[test]
fn test_sops_provider_rejects_credentials_in_uri() {
    for name in CREDENTIAL_FIELDS.iter().map(|spec| spec.name) {
        let url = Url::parse(&format!(
            "sops://secrets.enc.yaml?{name}=must-not-be-in-config"
        ))
        .unwrap();
        let result: std::result::Result<Box<dyn Provider>, _> = (&url).try_into();
        assert!(result.is_err(), "{name} was accepted as a URI parameter");
    }
}
