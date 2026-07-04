use monosecret_derive::declare_secrets;

// Note: These tests validate that the macro generates correct code
// They don't actually run the generated code since that would require
// the full monosecret runtime

#[test]
fn test_basic_secrets() {
	// This should compile without errors
	declare_secrets!("tests/fixtures/basic.toml");

	// The macro should generate:
	// - struct Monosecret with api_key: String, database_url: String, optional_secret: Option<String>
	// - enum MonosecretProfile (empty since no profiles defined)
	// - enum Profile (empty since no profiles defined)
}

#[test]
fn test_profile_specific_secrets() {
	// This should compile without errors
	declare_secrets!("tests/fixtures/profiles.toml");

	// The macro should generate:
	// - struct Monosecret with:
	//   - api_key: Option<String> (optional in development)
	//   - database_url: String (always required, but has default in dev)
	//   - redis_url: Option<String> (optional by default, required in prod)
	// - enum Profile with Development, Staging, Production variants
	// - enum MonosecretProfile with profile-specific field types
}

#[test]
fn test_empty_secrets() {
	// This should compile without errors
	declare_secrets!("tests/fixtures/empty.toml");

	// The macro should generate empty structs
}
