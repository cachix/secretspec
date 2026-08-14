---
monosecret: breaking
---

# Sync upstream SecretSpec through v0.19.0

Merge `cachix/secretspec` v0.15.0 through v0.19.0 and rebrand into the
`crates/monosecret`, `crates/monosecret_derive`, and per-language
`monosecret_*` SDK layout.

## What breaks

- Provider URIs may no longer carry credentials (`scheme://user:secret@host`
  is rejected) and `onepassword+token://` no longer accepts the service
  account token in its userinfo. Supply credentials through provider
  credentials (`monosecret config provider login <alias>`, or
  `credentials = { ... }` on the provider) instead.
- Native secret `ref` coordinates replace provider-specific addressing for
  externally managed secrets; provider implementations must migrate to the
  address-oriented `Provider` trait APIs.

## What's new

- Native secret references (`ref`) with provider-independent coordinates,
  `resolve_named` / `with_default_reason` Rust SDK APIs, `prompt = true`
  hidden-value prompting, `set`/`check` preview, profile opt-out of
  `[profiles.default]` inheritance.
- New providers: passbolt, null, file, age, akv, awsps, dashlane, gopass,
  infisical, kdbx, keeper, openbao, scaleway, systemd_credential.
- SOPS provider (directory + single-file, multiple formats).
- Cached provider aliases, provider credential declarations, base64/urlsafe
  /hex value decoders, RFC 6901 JSON pointer selection, composition,
  manifest scopes.
- PHP, C#/.NET, and Swift language SDKs (rebranded under `monosecret_*`).
- FFI static-link contract, `cinstall` header, `schema`/`check --json`,
  non-UTF-8 env handling.

## Preserved fork-only behavior

- `monosecret env` / `load-env` shell command and `monosecret audit` CLI.
- Dart typed SDK generator (`monosecret_builder`), `@monosecret/client`
  TypeScript client, `@monosecret/cli` npm packages.
- `monochange` release workflows and `SECRETSPEC_*` legacy env-var aliases.
