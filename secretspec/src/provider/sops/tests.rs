use super::*;
use crate::provider::sops::config::SopsConfig;
use std::{
    collections::{HashMap, HashSet},
    fs,
};
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

    let paths = provider.build_lookup_paths(BuildLookupPathsParams {
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
        mode: SopsMode::Directory {
            path: PathBuf::from("secrets"),
            pattern: SopsPathPattern::try_from("{project}.{profile}.sops.json").unwrap(),
            format: SopsFormat::Json,
        },
        ..Default::default()
    };

    let provider = SopsProvider::new(dir_config);

    let paths = provider.build_lookup_paths(BuildLookupPathsParams {
        key: "database_url",
        profile: "production",
        project: "myapp",
    });
    assert_eq!(paths.unwrap(), vec![vec!["database_url"]]);
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
            .get("some-project-name", "foobar", profile)
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
        match provider.get("some-project-name", "foobar", profile) {
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
        match provider.get("some-project-name", "foobar", profile) {
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
        match provider.get("some-project-name", "foobar", profile) {
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
fn test_sops_set_single_file_creates_tree_and_sets_value() {
    let temp = TempDir::new().unwrap();

    let file_path = temp.path().join("secrets.enc.yaml");

    let url = build_sops_url(&file_path.to_string_lossy(), None);

    let provider: Box<dyn Provider> = (&url).try_into().expect("Provider init failed");

    provider
        .set(
            "myapp",
            "database_url",
            &SecretString::new("postgres://prod".into()),
            "production",
        )
        .expect("set failed");

    let value = provider
        .get("myapp", "database_url", "production")
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
            "myapp",
            "api_key",
            &SecretString::new("xyz123".into()),
            "development",
        )
        .expect("set failed");

    let expected_file = base.join("myapp/development.enc.json");

    assert!(expected_file.exists());

    let value = provider
        .get("myapp", "api_key", "development")
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
        .set("proj", "token", &SecretString::new("first".into()), "dev")
        .expect("set failed");

    provider
        .set("proj", "token", &SecretString::new("second".into()), "dev")
        .expect("set failed");

    let value = provider
        .get("proj", "token", "dev")
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
            "myapp",
            "service_url",
            &SecretString::new("http://localhost".into()),
            "default",
        )
        .expect("set failed");

    let value = provider
        .get("myapp", "service_url", "default")
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
            "myapp",
            "db",
            &SecretString::new("dev-db".into()),
            "development",
        )
        .expect("set failed");

    provider
        .set(
            "myapp",
            "db",
            &SecretString::new("prod-db".into()),
            "production",
        )
        .expect("set failed");

    let dev = provider
        .get("myapp", "db", "development")
        .unwrap()
        .unwrap()
        .expose_secret()
        .to_string();

    let prod = provider
        .get("myapp", "db", "production")
        .unwrap()
        .unwrap()
        .expose_secret()
        .to_string();

    assert_eq!(dev, "dev-db");
    assert_eq!(prod, "prod-db");
}

fn get_names_of_sensitive_fields() -> HashSet<String> {
    let mut secret_parameters: HashSet<String> = HashSet::new();

    STRING_FIELDS
        .iter()
        .filter(|field_spec| field_spec.sensitive)
        .for_each(|field_spec| {
            secret_parameters.insert(field_spec.url_key.to_owned());
        });

    PATHBUF_FIELDS
        .iter()
        .filter(|field_spec| field_spec.sensitive)
        .for_each(|field_spec| {
            secret_parameters.insert(field_spec.url_key.to_owned());
        });

    secret_parameters
}

#[test]
fn test_sops_provider_sensitive_fields_correctly_marked() {
    let secret_parameters = [
        "age_key",
        "aws_secret_access_key",
        "azure_client_secret",
        "hc_vault_token",
        "huawei_sdk_ak",
        "huawei_sdk_sk",
        "google_oauth_access_token",
    ]
    .iter()
    .map(|name| name.to_string())
    .collect::<HashSet<String>>();

    assert_eq!(secret_parameters, get_names_of_sensitive_fields());
}

#[test]
fn test_sops_provider_uri_drops_sensitive_fields() {
    let secret_parameters = get_names_of_sensitive_fields();

    let provider = SopsProvider::new(SopsConfig::default());

    if let Ok(url) = Url::parse(provider.uri().as_str()) {
        for (parameter, _value) in url.query_pairs().into_iter() {
            if secret_parameters.contains(parameter.as_ref()) {
                panic!("{parameter} is sensitive, and should not be exposed via Provider::uri.");
            }
        }
    } else {
        panic!("Failed to parse URI");
    }
}
