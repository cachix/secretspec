secretspec_derive::declare_secrets!("secretspec.toml");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let resolved = SecretSpec::builder()
        .with_provider("keyring://")
        .with_profile("development")
        .with_reason("start application")
        .prompt_missing(true)
        .load()?;

    println!("Database: {}", resolved.secrets.database_url);

    Ok(())
}
