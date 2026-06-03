// These tests verify that the macro generates compilable code
// and handles errors appropriately

#[test]
fn test_file_not_found() {
	// This should produce a compile error
	let t = trybuild::TestCases::new();
	t.compile_fail("tests/ui/file_not_found.rs");
}

#[test]
fn test_invalid_toml() {
	// This should produce a compile error
	let t = trybuild::TestCases::new();
	t.compile_fail("tests/ui/invalid_toml.rs");
}

#[test]
fn test_invalid_toml_embedded() {
	// This should produce a compile error with embedded TOML
	let t = trybuild::TestCases::new();
	t.compile_fail("tests/ui/invalid_toml_embedded.rs");
}
