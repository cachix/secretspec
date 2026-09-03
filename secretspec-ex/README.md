# SecretSpec Elixir SDK

The Elixir SDK is a thin Rustler binding over the shared SecretSpec Rust
resolver. The Elixir layer builds the JSON request and exposes the response as
small structs; providers, profiles, fallback chains, and materialized paths
remain in Rust.

```elixir
resolved =
  SecretSpec.builder()
  |> SecretSpec.Builder.with_provider("dotenv://.env")
  |> SecretSpec.Builder.with_reason("start application")
  |> SecretSpec.Builder.load()

resolved.secrets["DATABASE_URL"] |> SecretSpec.ResolvedSecret.get()
SecretSpec.Resolved.set_as_env(resolved)
SecretSpec.Resolved.close(resolved)
```

Build and test a checkout with `mix test`. A Rust toolchain and a C compiler
are required.
