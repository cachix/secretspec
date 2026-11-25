{:ok, %SecretSpec.Secret{value: database_url}} =
  SecretSpec.with_session(
    [manifest: "secretspec.toml", scope: "api", reason: "boot API server"],
    fn session ->
      SecretSpec.Session.get(session, "DATABASE_URL",
        representation: :value,
        purpose: %{consumer: "api", operation: "connect"}
      )
    end
  )

is_binary(database_url)
