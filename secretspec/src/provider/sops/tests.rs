use super::*;
use crate::provider::sops::config::SopsConfig;
use std::{collections::HashMap, fs};
use tempfile::TempDir;
use url::Url;

fn build_sops_url(path: &str, query_parameters: Option<HashMap<&str, &str>>) -> Url {
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

    Url::parse(&format!("sops://{path}?{query}")).unwrap()
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
fn test_sops_invalid_format() {
    let url = Url::parse("sops://./secrets.enc.json?format=invalid").unwrap();

    let provider_result: std::result::Result<Box<dyn Provider>, _> = (&url).try_into();

    assert!(provider_result.is_err());
}

fn run_sops_single_file_test(ext: &str) {
    let url = build_sops_url(
        format!("src/provider/sops/test_fixtures/single_file/some-project-name.enc.{ext}").as_str(),
        None,
    );

    let provider: Box<dyn Provider> = (&url).try_into().expect("Provider init failed");

    let expected = [("development", "bar"), ("production", "baz")];

    for (profile, expected_value) in expected {
        if let Some(value) = provider
            .get(Address::convention("some-project-name", profile, "foobar"))
            .expect("Failed to fetch secret")
        {
            let secret = value.expose_secret();

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
    let url = build_sops_url(
        "src/provider/sops/test_fixtures/directory/{project}/{profile}.enc.json",
        None,
    );

    let provider: Box<dyn Provider> = (&url).try_into().expect("Provider init failed");

    let expected = [("development", "bar"), ("production", "baz")];

    for (profile, expected_value) in expected {
        match provider.get(Address::convention("some-project-name", profile, "foobar")) {
            Ok(value) => match value {
                Some(secret_box) => {
                    let secret = secret_box.expose_secret();

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
    let url = build_sops_url(
        "src/provider/sops/test_fixtures/directory/{project}/{profile}/secrets.enc.json",
        None,
    );

    let provider: Box<dyn Provider> = (&url).try_into().expect("Provider init failed");

    let expected = [("development", "bar"), ("production", "baz")];

    for (profile, expected_value) in expected {
        match provider.get(Address::convention("some-project-name", profile, "foobar")) {
            Ok(value) => match value {
                Some(secret_box) => {
                    let secret = secret_box.expose_secret();

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
    let built_url = build_sops_url(
        "src/provider/sops/test_fixtures/directory/{project}/.env.{profile}.enc",
        Some(HashMap::from([("format", "dotenv")])),
    );

    let provider: Box<dyn Provider> = (&built_url).try_into().expect("Provider init failed");

    let expected = [("development", "bar"), ("production", "baz")];

    for (profile, expected_value) in expected {
        match provider.get(Address::convention("some-project-name", profile, "foobar")) {
            Ok(value) => match value {
                Some(secret_box) => {
                    let secret = secret_box.expose_secret();

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
    let url = build_sops_url(
        &format!("{}/{{project}}/.env.{{profile}}.enc", temp.path().display()),
        Some(HashMap::from([("format", "dotenv")])),
    );
    let provider: Box<dyn Provider> = (&url).try_into().expect("Provider init failed");
    let addr = Address::convention("myapp", "production", "API_KEY");

    provider
        .set(addr, &SecretString::new("dotenv-value".into()))
        .expect("set failed");
    let value = provider.get(addr).unwrap().expect("missing value");

    assert_eq!(value.expose_secret(), "dotenv-value");
}

#[test]
fn test_sops_set_single_file_dotenv_uses_a_flat_key() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("secrets.enc");
    let url = build_sops_url(
        &path.to_string_lossy(),
        Some(HashMap::from([("format", "dotenv")])),
    );
    let provider: Box<dyn Provider> = (&url).try_into().expect("Provider init failed");
    let addr = Address::convention("myapp", "production", "API_KEY");

    provider
        .set(addr, &SecretString::new("flat-value".into()))
        .expect("set failed");
    let value = provider.get(addr).unwrap().expect("missing value");

    assert_eq!(value.expose_secret(), "flat-value");
}

#[test]
fn test_sops_json_override_works_with_ini_extension() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("secrets.enc.ini");
    let url = build_sops_url(
        &path.to_string_lossy(),
        Some(HashMap::from([("format", "json")])),
    );
    let provider: Box<dyn Provider> = (&url).try_into().expect("Provider init failed");
    let addr = Address::convention("myapp", "production", "API_KEY");

    provider
        .set(addr, &SecretString::new("json-value".into()))
        .expect("set failed");
    let value = provider.get(addr).unwrap().expect("missing value");

    assert_eq!(value.expose_secret(), "json-value");
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
    credentials.insert(AGE_KEY.to_string(), SecretString::new(age_key.into()));
    provider.with_credentials(credentials);

    let value = provider
        .get(Address::convention(
            "some-project-name",
            "production",
            "foobar",
        ))
        .unwrap()
        .expect("missing value");

    assert_eq!(value.expose_secret(), "baz");
}

#[test]
fn test_sops_set_single_file_creates_tree_and_sets_value() {
    let temp = TempDir::new().unwrap();

    let file_path = temp.path().join("secrets.enc.yaml");

    let url = build_sops_url(&file_path.to_string_lossy(), None);

    let provider: Box<dyn Provider> = (&url).try_into().expect("Provider init failed");

    provider
        .set(
            Address::convention("myapp", "production", "database_url"),
            &SecretString::new("postgres://prod".into()),
        )
        .expect("set failed");

    let value = provider
        .get(Address::convention("myapp", "production", "database_url"))
        .expect("get failed")
        .expect("missing value");

    assert_eq!(value.expose_secret(), "postgres://prod");
}

#[test]
fn test_sops_set_directory_creates_file_and_sets_value() {
    let temp = TempDir::new().unwrap();

    let base = temp.path();

    let url = build_sops_url(
        format!(
            "{}/{{project}}/{{profile}}.enc.json",
            &base.to_string_lossy()
        )
        .as_str(),
        None,
    );

    let provider: Box<dyn Provider> = (&url).try_into().expect("Provider init failed");

    // Set a value into a file that does not exist yet
    provider
        .set(
            Address::convention("myapp", "development", "api_key"),
            &SecretString::new("xyz123".into()),
        )
        .expect("set failed");

    let expected_file = base.join("myapp/development.enc.json");

    assert!(expected_file.exists());

    let value = provider
        .get(Address::convention("myapp", "development", "api_key"))
        .expect("get failed")
        .expect("missing value");

    assert_eq!(value.expose_secret(), "xyz123");
}

#[test]
fn test_sops_set_overwrites_existing_value() {
    let temp = TempDir::new().unwrap();

    let file_path = temp.path().join("secrets.enc.json");

    fs::write(&file_path, "{}").unwrap();

    let url = build_sops_url(&file_path.to_string_lossy(), None);

    let provider: Box<dyn Provider> = (&url).try_into().expect("Provider init failed");

    provider
        .set(
            Address::convention("proj", "dev", "token"),
            &SecretString::new("first".into()),
        )
        .expect("set failed");

    provider
        .set(
            Address::convention("proj", "dev", "token"),
            &SecretString::new("second".into()),
        )
        .expect("set failed");

    let value = provider
        .get(Address::convention("proj", "dev", "token"))
        .expect("get failed")
        .expect("missing value");

    assert_eq!(value.expose_secret(), "second");
}

#[test]
fn test_sops_set_single_file_default_profile() {
    let temp = TempDir::new().unwrap();

    let file_path = temp.path().join("secrets.enc.yaml");

    let url = build_sops_url(&file_path.to_string_lossy(), None);

    let provider: Box<dyn Provider> = (&url).try_into().expect("Provider init failed");

    provider
        .set(
            Address::convention("myapp", "default", "service_url"),
            &SecretString::new("http://localhost".into()),
        )
        .expect("set failed");

    let value = provider
        .get(Address::convention("myapp", "default", "service_url"))
        .expect("get failed")
        .expect("missing value");

    assert_eq!(value.expose_secret(), "http://localhost");
}

#[test]
fn test_sops_set_directory_multiple_profiles() {
    let temp = TempDir::new().unwrap();

    let base = temp.path();

    let url = build_sops_url(
        format!(
            "{}/{{project}}/{{profile}}.enc.yaml",
            &base.to_string_lossy()
        )
        .as_str(),
        None,
    );

    let provider: Box<dyn Provider> = (&url).try_into().expect("Provider init failed");

    provider
        .set(
            Address::convention("myapp", "development", "db"),
            &SecretString::new("dev-db".into()),
        )
        .expect("set failed");

    provider
        .set(
            Address::convention("myapp", "production", "db"),
            &SecretString::new("prod-db".into()),
        )
        .expect("set failed");

    let dev = provider
        .get(Address::convention("myapp", "development", "db"))
        .unwrap()
        .unwrap()
        .expose_secret()
        .to_string();

    let prod = provider
        .get(Address::convention("myapp", "production", "db"))
        .unwrap()
        .unwrap()
        .expose_secret()
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
