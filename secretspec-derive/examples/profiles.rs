secretspec_derive::declare_secrets!("secretspec.toml");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let resolved = SecretSpec::builder()
        .with_provider("keyring://")
        .with_profile(Profile::Production)
        .with_reason("start production application")
        .load_profile()?;

    match resolved.secrets {
        SecretSpecProfile::Production {
            database_url,
            api_key,
            ..
        } => {
            println!("Database: {database_url}");
            println!("API key loaded: {} bytes", api_key.len());
        }
        _ => unreachable!("the production profile was selected"),
    }

    Ok(())
}
