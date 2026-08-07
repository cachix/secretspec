secretspec_derive::declare_secrets!("secretspec.toml");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let resolved = SecretSpec::builder()
        .with_provider("keyring://")
        .with_profile("development")
        .with_reason("start application")
        .load()?;

    println!("Database: {}", resolved.secrets.database_url);

    if let Some(redis_url) = &resolved.secrets.redis_url {
        println!("Redis: {redis_url}");
    }

    resolved.secrets.set_as_env_vars();

    println!("Profile: {}", resolved.profile);
    println!("Provider: {}", resolved.provider);

    Ok(())
}
