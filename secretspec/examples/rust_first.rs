use secretspec::{Profile, Secret, Secrets, Spec};

fn main() -> secretspec::Result<()> {
    let spec = Spec::builder("checkout")
        .provider("env", "env://")
        .secret(
            "DATABASE_URL",
            Secret::required("PostgreSQL connection URL").providers(["env"]),
        )
        .secret(
            "SENTRY_DSN",
            Secret::optional("Sentry error-reporting endpoint"),
        )
        .profile(
            "production",
            Profile::new().secret("SENTRY_DSN", Secret::required("Production Sentry endpoint")),
        )
        .scope("web", ["DATABASE_URL", "SENTRY_DSN"])
        .build()?;

    let mut secrets = Secrets::from_spec(spec)?;
    secrets.set_profile("production");
    secrets.set_scope("web");

    let resolved = secrets.resolve()?;
    println!("resolved profile: {}", resolved.profile);
    Ok(())
}
