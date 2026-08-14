use std::convert::TryFrom;
use std::fs;

use monosecret::Provider;
use monosecret::ResolvedSource;
use monosecret::Secrets;

#[test]
fn generic_ref_resolves_provider_native_item() {
	let dir = tempfile::tempdir().expect("temp dir");
	let env_path = dir.path().join("secrets.env");
	fs::write(&env_path, "STORE_NATIVE_NAME=from-native-ref\n").expect("write dotenv");
	let config_path = dir.path().join("monosecret.toml");
	fs::write(
		&config_path,
		r#"
[project]
name = "native-ref-test"
revision = "1.0"

[profiles.default]
APP_TOKEN = { description = "application token", ref = { item = "STORE_NATIVE_NAME" } }
"#,
	)
	.expect("write config");

	let mut secrets = Secrets::load_from(&config_path).expect("load valid config");
	secrets.set_provider(format!(
		"dotenv:{}",
		env_path.display().to_string().replace('\\', "/")
	));
	let response = secrets.resolve().expect("resolve native reference");
	let token = response.secrets.get("APP_TOKEN").expect("resolved token");
	assert_eq!(token.value.as_deref(), Some("from-native-ref"));
	assert_eq!(token.source, ResolvedSource::Provider);
}

#[test]
fn legacy_op_uri_paths_are_rejected_with_ref_guidance() {
	for uri in [
		"op://Production/github/password",
		"op://Production/github/credentials/password",
	] {
		let Err(error) = Box::<dyn Provider>::try_from(uri) else {
			panic!("item paths require a ref");
		};
		let message = error.to_string();
		assert!(message.contains("secret's `ref`"), "{message}");
	}

	let Err(error) =
		Box::<dyn Provider>::try_from("onepassword+token://token@Production/github/password")
	else {
		panic!("tokens in provider URIs are unsafe");
	};
	assert!(
		error
			.to_string()
			.contains("no longer accepts the service account token"),
		"{error}"
	);
}

#[test]
fn value_free_resolve_does_not_generate_or_write_ref() {
	let dir = tempfile::tempdir().expect("temp dir");
	let env_path = dir.path().join("generated.env");
	let config_path = dir.path().join("monosecret.toml");
	fs::write(
		&config_path,
		r#"
[project]
name = "native-ref-generation"
revision = "1.0"

[profiles.default]
TOKEN = { description = "generated token", type = "password", generate = { length = 16 }, ref = { item = "NATIVE_TOKEN" } }
"#,
	)
	.expect("write config");

	let mut secrets = Secrets::load_from(&config_path).expect("load valid config");
	secrets.set_provider(format!(
		"dotenv:{}",
		env_path.display().to_string().replace('\\', "/")
	));
	let response = secrets
		.resolve_without_values()
		.expect("value-free resolution succeeds");
	let token = response.secrets.get("TOKEN").expect("generated provenance");
	assert_eq!(token.source, ResolvedSource::Generated);
	assert_eq!(token.value, None);
	assert!(!env_path.exists(), "value-free resolution must not write");

	let response = secrets.resolve().expect("materialized resolution succeeds");
	assert!(
		response
			.secrets
			.get("TOKEN")
			.expect("resolved token")
			.value
			.is_some()
	);
	let stored = fs::read_to_string(&env_path).expect("generated ref is stored");
	assert!(stored.contains("NATIVE_TOKEN="));
}

#[test]
fn reference_is_inherited_from_default_profile() {
	let dir = tempfile::tempdir().expect("temp dir");
	let env_path = dir.path().join("secrets.env");
	fs::write(&env_path, "SHARED_NATIVE=value\n").expect("write dotenv");
	let config_path = dir.path().join("monosecret.toml");
	fs::write(
		&config_path,
		r#"
[project]
name = "native-ref-inheritance"
revision = "1.0"

[profiles.default]
TOKEN = { description = "shared token", ref = { item = "SHARED_NATIVE" } }

[profiles.production]
TOKEN = { description = "production token", required = true }
"#,
	)
	.expect("write config");

	let mut secrets = Secrets::load_from(&config_path).expect("load valid config");
	secrets.set_provider(format!(
		"dotenv:{}",
		env_path.display().to_string().replace('\\', "/")
	));
	secrets.set_profile("production");
	let response = secrets.resolve().expect("resolve inherited ref");
	assert_eq!(
		response
			.secrets
			.get("TOKEN")
			.expect("resolved token")
			.value
			.as_deref(),
		Some("value")
	);
}

#[test]
fn generic_ref_rejects_unsupported_coordinates() {
	let dir = tempfile::tempdir().expect("temp dir");
	let env_path = dir.path().join("secrets.env");
	fs::write(&env_path, "TOKEN=value\n").expect("write dotenv");
	let config_path = dir.path().join("monosecret.toml");
	fs::write(
		&config_path,
		r#"
[project]
name = "native-ref-test"
revision = "1.0"

[profiles.default]
TOKEN = { description = "token", ref = { item = "TOKEN", field = "password" } }
"#,
	)
	.expect("write config");

	let mut secrets = Secrets::load_from(&config_path).expect("load valid config");
	secrets.set_provider(format!(
		"dotenv:{}",
		env_path.display().to_string().replace('\\', "/")
	));
	let error = secrets
		.resolve()
		.expect_err("dotenv has no field coordinate");
	assert!(
		error
			.to_string()
			.contains("does not support the `field` coordinate")
	);
}
