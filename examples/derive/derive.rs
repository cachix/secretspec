// Use the proc macro to generate typed structs from monosecret.toml
// This generates: Monosecret, MonosecretProfile, Profile, and MonosecretBuilder types
monosecret_derive::declare_secrets!("monosecret.toml");

fn main() -> Result<(), Box<dyn std::error::Error>> {
	println!("Monosecret Code Generation Example\n");

	// Create a .env file for testing
	std::fs::write(
		".env",
		"DATABASE_URL=postgres://localhost/testdb\nAPI_KEY=test-key-123\nREDIS_URL=redis://localhost:6379\nSESSION_SECRET=test-session-secret\n",
	)?;

	// Example 1: Load with builder pattern
	println!("1. Loading secrets with builder pattern:");
	match Monosecret::builder().with_provider("dotenv").load() {
		Ok(result) => {
			println!(
				"   ✓ Loaded successfully using provider: {:?}, profile: {}",
				result.provider, result.profile
			);
			let secrets = &result.secrets;
			println!("   - Database URL: {}", secrets.database_url);
			println!("   - API Key: {} (found)", secrets.api_key);
			println!("   - Redis URL: {}", secrets.redis_url);
			println!("   - Session secret: {} (found)", secrets.session_secret);
		}
		Err(e) => {
			println!("   ✗ Failed to load secrets: {e}");
		}
	}

	// Example 2: Load with specific profile
	println!("\n2. Loading with specific profile:");
	match Monosecret::builder()
		.with_provider("dotenv")
		.with_profile(Profile::Development)
		.load()
	{
		Ok(result) => {
			println!(
				"   ✓ Loaded using provider: {:?}, profile: {}",
				result.provider, result.profile
			);
			let secrets = &result.secrets;
			println!("   - Database URL: {}", secrets.database_url);
			println!("   - API Key: {} (found)", secrets.api_key);
			println!("   - Redis URL: {}", secrets.redis_url);
			println!("   - Session secret: {} (found)", secrets.session_secret);
		}
		Err(e) => {
			println!("   ✗ Failed to load development profile: {e}");
		}
	}

	// Example 3: Using string profile
	println!("\n3. Loading with string profile:");
	match Monosecret::builder()
		.with_provider("dotenv")
		.with_profile("production")
		.load()
	{
		Ok(result) => {
			println!("   ✓ Loaded with string profile successfully");
			println!(
				"   - Provider: {:?}, Profile: {}",
				result.provider, result.profile
			);
		}
		Err(e) => {
			println!("   ✗ Failed to load with string profile: {e}");
		}
	}

	// Example 4: Using provider URIs
	println!("\n4. Loading with provider URI:");
	match Monosecret::builder().with_provider("dotenv:.env").load() {
		Ok(result) => {
			println!("   ✓ Loaded with URI successfully");
			println!("   - Provider: {:?}", result.provider);
		}
		Err(e) => {
			println!("   ✗ Failed to load with URI: {e}");
		}
	}

	println!("\n5. Setting secrets as environment variables:");
	if let Ok(result) = Monosecret::builder().with_provider("dotenv").load() {
		result.secrets.set_as_env_vars();
		println!("   ✓ Set all secrets as environment variables");

		// Verify they were set
		println!(
			"   - DATABASE_URL env: {:?}",
			std::env::var("DATABASE_URL").ok()
		);
		println!("   - API_KEY env: {:?}", std::env::var("API_KEY").ok());
	}

	// Example 6: Loading profile-specific types
	println!("\n6. Loading profile-specific types:");
	match Monosecret::builder()
		.with_provider("dotenv")
		.with_profile("production")
		.load_profile()
	{
		Ok(result) => {
			println!("   ✓ Loaded profile-specific types");
			match result.secrets {
				MonosecretProfile::Production {
					database_url,
					api_key,
					redis_url,
					session_secret,
				} => {
					println!("   - Production secrets are strongly typed");
					println!("   - Database URL: {database_url}"); // String, not Option<String>
					println!("   - API Key: {api_key}"); // String, not Option<String>
					println!("   - Redis URL: {redis_url}"); // String, not Option<String>
					println!("   - Session secret: {session_secret}"); // String, not Option<String>
				}
				_ => println!("   - Got different profile"),
			}
		}
		Err(e) => {
			println!("   ✗ Failed to load profile: {e}");
		}
	}

	// Clean up
	std::fs::remove_file(".env").ok();

	Ok(())
}
