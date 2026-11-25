{:ok, %SecretSpec.Secret{value: database_url}} =
  SecretSpec.with_session(
    [manifest: "secretspec.toml", profile: "production", reason: "boot web app"],
    fn session ->
      SecretSpec.Session.get(session, "DATABASE_URL",
        representation: :value,
        purpose: %{consumer: "my_app", operation: "connect"}
      )
    end
  )

# Use database_url to configure the database connection.
is_binary(database_url)
