use crate::common::TestFixture;
use secretspec::Spec;

// Integration tests for profile inheritance using the public API
// (Unit tests for detailed inheritance logic are in src/tests.rs)

#[test]
fn test_profile_inheritance_end_to_end() {
    let fixture = TestFixture::new();
    let (_, _, base_path) = fixture.create_extends_structure();

    let spec = Spec::try_from(base_path.as_path()).unwrap();

    // Verify basic inheritance functionality through public API
    assert_eq!(spec.project(), "test_project");

    let default_profile: Vec<_> = spec.secrets("default").unwrap().collect();
    assert!(default_profile.contains(&"API_KEY"));
    assert!(default_profile.contains(&"DATABASE_URL"));
    assert!(default_profile.contains(&"REDIS_URL"));
    assert!(default_profile.contains(&"JWT_SECRET"));
    assert!(default_profile.contains(&"OAUTH_CLIENT_ID"));
}
