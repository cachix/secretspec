//! Snapshot tests for the code-generation input shape used by `declare_secrets!`.
//!
//! The proc macro expands at compile time, so integration tests cannot ask it for a
//! runtime token stream. These snapshots cover the normalized, secret-value-free
//! manifest derived from the same fixture files that feed the macro tests.

use monosecret::Config;

fn manifest_json(toml_content: &str) -> serde_json::Value {
	let config: Config = toml_content.parse().expect("fixture should parse");
	serde_json::to_value(config.to_manifest()).expect("manifest should serialize")
}

#[test]
fn basic_generation_manifest_snapshot() {
	insta::assert_json_snapshot!(manifest_json(include_str!("fixtures/basic.toml")));
}

#[test]
fn profile_generation_manifest_snapshot() {
	insta::assert_json_snapshot!(manifest_json(include_str!("fixtures/profiles.toml")));
}

#[test]
fn complex_generation_manifest_snapshot() {
	insta::assert_json_snapshot!(manifest_json(include_str!("fixtures/complex.toml")));
}
