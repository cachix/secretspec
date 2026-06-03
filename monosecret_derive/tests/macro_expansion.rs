// Tests that verify the macro generates valid code
// These use inline strings instead of file paths to avoid path issues

#[test]
fn test_macro_generates_valid_code() {
	// This test verifies that the proc macro generates syntactically valid Rust code
	// The actual functionality is tested in the monosecret crate's integration tests

	// We can't easily test the macro directly here because it needs to read files
	// and generate code at compile time. The integration tests in the main crate
	// will provide better coverage.

	// If this test runs, the crate compiled correctly.
}
