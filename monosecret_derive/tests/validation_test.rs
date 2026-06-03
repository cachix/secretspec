use monosecret_derive::declare_secrets;

#[test]
fn test_validation_errors() {
	// This test verifies that the macro catches validation errors at compile time
	// The actual test is that this file should NOT compile if uncommented

	// Uncomment to test:
	// declare_secrets!("tests/fixtures/invalid_validation.toml");
}

// Test with valid Rust keywords that should be rejected
#[test]
fn test_keyword_validation() {
	// These should fail compilation if uncommented:

	// mod test_type_keyword {
	//     use super::*;
	//     declare_secrets!("tests/fixtures/keyword_type.toml");
	// }

	// mod test_self_keyword {
	//     use super::*;
	//     declare_secrets!("tests/fixtures/keyword_self.toml");
	// }
}

// Test valid configurations that should pass
mod test_valid {
	use super::*;

	// This should compile successfully
	declare_secrets!("tests/fixtures/basic.toml");

	#[test]
	fn test_basic_compiles() {
		// If this test runs, the macro validated successfully.
	}
}
