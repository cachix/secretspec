# SecretSpec Elixir SDK

The Elixir SDK (0.21+) is a pure Elixir IPC client for a compatible `secretspec` executable (0.21+). It launches `secretspec serve` directly, negotiates `secretspec.resolver/1`, and resolves exact declared names. No Rust code, NIF, or downloaded native archive is included in the Hex package.

```elixir
{:ok, session} =
  SecretSpec.Session.start_link(
    manifest: "/project/secretspec.toml",
    profile: "production",
    scope: "deploy",
    reason: "start application"
  )

{:ok, secret} =
  SecretSpec.Session.get(session, "DATABASE_URL",
    representation: :value,
    purpose: %{consumer: "my_app", operation: "connect", host: "db.example.com"}
  )

SecretSpec.Session.close(session)
```

`get/3` returns `{:ok, %SecretSpec.Secret{}}`, `{:missing, required}`, `:undeclared`, or `{:error, %SecretSpec.Error{}}`. `purpose` attribution is mandatory. Path results are leases owned by the resolver and must be released with `SecretSpec.Session.release/2` or by closing the session.

For one-shot usage, call `SecretSpec.with_session(options, fun)`. Configure `executable:` when discovery through `PATH` is not appropriate.

Build and test with `mix test`.
