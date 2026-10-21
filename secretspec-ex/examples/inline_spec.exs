manifest = %{
  toml: """
  [project]
  name = "inline-app"
  revision = "1.0"

  [profiles.default]
  DATABASE_URL = { description = "Database URL", default = "postgres://localhost/app" }
  """,
  base_dir: File.cwd!()
}

{:ok, %SecretSpec.Secret{value: database_url}} =
  SecretSpec.with_session(
    [manifest: manifest, provider: "null://", reason: "configure local database"],
    fn session ->
      SecretSpec.Session.get(session, "DATABASE_URL",
        representation: :value,
        purpose: %{consumer: "my_app", operation: "connect"}
      )
    end
  )

is_binary(database_url)
