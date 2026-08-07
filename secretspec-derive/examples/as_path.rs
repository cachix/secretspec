secretspec_derive::declare_secrets!("secretspec.toml");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let resolved = SecretSpec::builder()
        .with_provider("keyring://")
        .with_reason("configure TLS")
        .load()?;

    let certificate: &std::path::PathBuf = &resolved.secrets.tls_cert;
    println!("Certificate: {}", certificate.display());

    if let Some(private_key) = &resolved.secrets.tls_key {
        println!("Private key: {}", private_key.display());
    }

    // The materialized files remain valid until `resolved` is dropped.
    Ok(())
}
