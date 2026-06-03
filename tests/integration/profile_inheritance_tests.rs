use crate::common::TestFixture;
use monosecret::Config;

// Integration tests for profile inheritance using the public API
// (Unit tests for detailed inheritance logic are in src/tests.rs)

#[test]
fn test_profile_inheritance_end_to_end() {
    let fixture = TestFixture::new();
    let (_, _, base_path) = fixture.create_extends_structure();

    let config = Config::try_from(base_path.as_path()).unwrap();

    // Verify basic inheritance functionality through public API
    assert_eq!(config.project.name, "test_project");

    let default_profile = config.profiles.get("default").unwrap();
    assert!(default_profile.secrets.contains_key("API_KEY"));
    assert!(default_profile.secrets.contains_key("DATABASE_URL"));
    assert!(default_profile.secrets.contains_key("REDIS_URL"));
    assert!(default_profile.secrets.contains_key("JWT_SECRET"));
    assert!(default_profile.secrets.contains_key("OAUTH_CLIENT_ID"));
}
