---
title: "SecretSpec 0.19: Moving and importing secrets between providers"
description: Move secrets safely between storage layouts, keep config and ephemeral values in the same declaration model, and make remote providers faster.
date: 2026-08-11
authors:
  - domen
---

Secret storage changes as a project grows. Values move from local files to
password managers, from one naming convention to another, and sometimes
between providers with completely different data models. The application still
expects the same `API_KEY` or `DATABASE_URL` at the end.

[SecretSpec 0.19](https://github.com/cachix/secretspec/releases/tag/v0.19.0 "SecretSpec 0.19 release")
treats those changes as a normal workflow instead of a one-off migration
script.

This release includes:

- **[Provider-specific storage
  layouts](#provider-specific-storage-layouts)**: give each provider its own
  address, transform stored values, import existing files, and preview exact
  write references.
- **[Config belongs in secrets](#config-belongs-in-secrets)**: resolve
  profile-specific config alongside stored secrets, generate ephemeral values,
  and securely prompt during `secretspec run`.
- **[Passbolt provider](#passbolt-provider)**: read and write secrets in a
  self-hosted Passbolt server, with credentials supplied by another provider
  when needed.
- **[Faster remote-provider
  workflows](#faster-remote-provider-workflows)**: attach a cache directly to
  an authoritative provider and batch 1Password field reads.
- **[Smaller improvements](#smaller-improvements)**: create standalone profiles
  and install complete pkg-config metadata for native SDK consumers.

## Provider-specific storage layouts

`API_KEY` is the name used by your application. In 1Password, the same value
might be the `token` field of an item named `old-api-item`.

A [`ref`](/concepts/references/) gives SecretSpec this store address. `item`
names the entry. Coordinates such as `field`, `section`, and `vault` locate a
value inside structured stores. The `providers` list still decides which
stores to try.

Before 0.19, every provider in a secret's route received the same `ref`, even
though stores such as 1Password and dotenv organize secrets differently. Now
each provider alias can template its usual layout, while `refs.<alias>` handles
exceptions:

```toml title="secretspec.toml"
[providers]
legacy = "onepassword://Legacy"
production = {
  uri = "onepassword://Production",
  ref = { item = "{project}-{profile}", field = "{key}" }
}
local = { uri = "dotenv://.env", ref = { item = "{key}" } }

[profiles.production]
API_KEY = {
  description = "API key",
  providers = ["production", "local"],
  refs = { legacy = { item = "old-api-item", field = "token" } }
}
```

`production` reads the `API_KEY` field from a `<project>-production` 1Password
item. The `local` fallback reads the dotenv key `API_KEY`. If `legacy` is
selected explicitly, `refs.legacy` reads the `token` field from `old-api-item`.

For each provider, `refs.<alias>` takes precedence over the alias's `ref`
template, which takes precedence over the provider convention. Templates
accept `{project}`, `{profile}`, and `{key}` in every address field. Existing
route-wide `ref` declarations remain supported.

Because scoped references also apply to imports, that exception can describe a
migration source without joining the normal fallback route:

```bash
secretspec import legacy --profile production --delete-source
```

This reads from `refs.legacy` and writes through the `production` template. It
also works between distinct entries in one physical store. SecretSpec rejects
the import if both addresses resolve to the same entry.

### Transform stored values

Two new secret fields transform a stored value before it reaches the
application.

`extract` selects a value from JSON with an
[RFC 6901 JSON Pointer](https://www.rfc-editor.org/rfc/rfc6901):

```toml title="secretspec.toml"
[providers]
runtime = "file:///run/secrets"

[profiles.production]
DATABASE_PASSWORD = {
  description = "Database password",
  providers = ["runtime"],
  ref = { item = "application.json" },
  extract = { format = "json", pointer = "/database/password" }
}
```

JSON strings become their unquoted contents. Numbers, booleans, objects, and
arrays keep their JSON representation. Extracted declarations are read-only.
`set`, `delete`, prompting, generation, and import cannot overwrite the source
document.

`encoding` defines the textual representation in provider storage:

```toml title="secretspec.toml"
[profiles.production]
TEXT_CONFIG = { description = "Encoded configuration", encoding = "base64" }
CLIENT_KEYSTORE = {
  description = "Binary client keystore",
  providers = ["runtime"],
  ref = { item = "client.p12.b64" },
  encoding = "base64",
  as_path = true
}
```

Supported encodings are standard Base64, URL-safe Base64, and hexadecimal.
Writes encode the logical value. Reads decode the stored value. Decoded UTF-8
can be returned directly. Set `as_path = true` to materialize arbitrary bytes
in a file.

Transforms run in this order:

```text
provider or cache → encoding decode → JSON extraction → as_path
```

This allows, for example, one declaration to decode a Base64-encoded JSON
document and select one field from it.

### Import without reshaping the source

**[File](/providers/file/)** stores one plaintext UTF-8 file per secret beneath
a required root. Convention paths use `{project}/{profile}/{key}`. `ref.item`
selects an existing relative path, including a file mounted at runtime.

Writes use atomic replacement and create private Unix files and directories.
The provider rejects traversal and nested symlinks. It does not encrypt its
contents.

The file provider is also a migration adapter for directories that already
contain one file per secret. A provider `ref` template maps the source layout,
while the destination alias independently maps the same declarations into its
native store:

```toml title="secretspec.toml"
[providers]
legacy_files = {
  uri = "file:./old-secrets",
  ref = { item = "{profile}/{key}" }
}
production = {
  uri = "onepassword://Production",
  ref = { item = "{project}-{profile}", field = "{key}" }
}

[profiles.production.defaults]
providers = ["production"]

[profiles.production]
API_KEY = { description = "Production API key" }
```

```bash
secretspec import legacy_files --profile production --delete-source
```

For `API_KEY`, the source is `old-secrets/production/API_KEY`. The destination
is the `API_KEY` field in the `<project>-production` 1Password item. The source
files do not need to follow the SecretSpec convention. With
`--delete-source`, 0.19 preflights every mapped source and destination, verifies
every copied value, and only then removes the plaintext source files.

Preflight, write, or verification failures leave every source untouched. A
destination with a different existing value keeps its corresponding source.

### See the reference before writing

`secretspec set` and interactive `secretspec check` now print the resolved
write reference before reading a value:

```console
$ secretspec set API_KEY --profile production --provider sops://secrets.enc.yaml
Writing secret 'API_KEY' to sops://secrets.enc.yaml?format=yaml (profile: production)
  target: /work/my-app/secrets.enc.yaml ["my-app"]["production"]["API_KEY"]
Enter value for API_KEY (profile: production): ********
```

SOPS reports the canonical encrypted file and exact `sops set` selector. Other
providers report their native item or path. A missing profile or unexpected
template is visible before SecretSpec receives the new value.

## Config belongs in secrets

**[Null](/providers/null/)** always reports a missing value and stores nothing.
This lets manifest defaults provide non-sensitive values without adding a
storage backend. One resolution can now return profile-specific configuration
and provider-backed secrets together. This follows the separation described in
[Secrets Don't Belong in Config](/blog/secrets-dont-belong-in-config/).

```toml title="secretspec.toml"
[profiles.default]
APP_MODE = { description = "Application mode", default = "local", providers = ["null"] }

[profiles.staging]
APP_MODE = { default = "staging" }

[profiles.production]
APP_MODE = { default = "production" }
```

`APP_MODE` resolves to `local`, `staging`, or `production` based on the selected
profile. Each override inherits the description and `null` route from
`[profiles.default]`. Only the value is repeated.

The result is one declaration model for values the application needs, whether
they come from a secret store or directly from the manifest. Config can travel
through the same profile, scope, SDK, and `run` workflow without pretending it
needs encrypted persistence.

### Ephemeral values

The null provider can also generate a fresh value for each resolution. Use it
for session tokens, test credentials, and other values that should exist only
for one process invocation. Persistent credentials should continue to use a
writable provider.

### Prompt for missing secrets during run

Set `prompt = true` on a declaration to let `secretspec run` securely request
its value when the configured providers do not have one:

```toml title="secretspec.toml"
[profiles.default]
DEPLOY_PASSWORD = {
  description = "One-time deployment password",
  prompt = true,
  providers = ["null"]
}
```

```console
$ secretspec run -- ./deploy
? Enter value for DEPLOY_PASSWORD (profile: default):
```

A writable provider saves the answer, turning the prompt into first-use
provisioning. The `null` provider keeps it ephemeral and injects it only into
that invocation. The hidden prompt reads from the controlling terminal, so the
child's stdin remains available for pipes and redirects. If no controlling
terminal exists, `run` fails before starting the child. Declarations without
`prompt = true` retain the existing fail-on-missing behavior.

## Passbolt provider

Passbolt is the third new provider in 0.19. SecretSpec now has 27 providers.

**[Passbolt](/providers/passbolt/)** reads and writes resources in a
self-hosted Passbolt server through `go-passbolt-cli`. Convention values use
the resource `secretspec/{project}/{profile}/{key}` and its `password` field.
References can select existing resources by UUID or exact name and address the
`password`, `username`, `uri`, or `description` field.

```toml title="secretspec.toml"
[providers]
bootstrap = "keyring://"

[providers.passbolt_team]
uri = "passbolt://?server=https://pass.example.com&folder=a9230ec4-5507-4870-b8b5-b3f500587e4c"
credentials = { private_key = "bootstrap", passphrase = "bootstrap" }
```

The OpenPGP private key and passphrase can come from another SecretSpec
provider. Environment fallbacks and the Passbolt CLI configuration are also
supported. Folder-scoped providers support declaration discovery with
`init --from`.

## Faster remote-provider workflows

Remote secret reads pay for authentication, process startup, and network
round-trips before the application can start. SecretSpec 0.19 reduces that work
both across invocations and within one resolution.

### Cache one authoritative provider

A single authoritative provider can now define `uri`, `credentials`, and
`cache` on the same alias:

```toml title="secretspec.toml"
[providers]
local = "keyring://secretspec/cache/{project}/{profile}/{key}"
azure = {
  uri = "akv://team-vault",
  credentials = { client_secret = "keyring" },
  cache = { provider = "local", max_age = "8h" }
}

[profiles.development.defaults]
providers = ["azure"]
```

The cached `fallback` form introduced in 0.17 remains available when several
authoritative providers can answer.

Cache entries now include their absolute expiration time and originating
`max_age`. SecretSpec removes an expired entry whenever it encounters one, and
changing `max_age` invalidates entries written under the previous policy.

Fallback resolution also reuses provider instances and handles independent
primary misses concurrently. Azure Key Vault reuses its client and serializes
initial challenge-based authentication, avoiding repeated Azure CLI processes
within one resolution.

### Batch 1Password field reads

1Password field references now resolve together through one `op inject` call,
instead of starting `op read` separately for every field. This reduces CLI
startup and repeated unlock overhead when one profile loads several fields. If
the batch contains a missing reference, SecretSpec falls back to bounded
concurrent reads so it can preserve per-secret missing-value behavior without
serializing the whole profile.

In the cold-cache benchmark from
[the implementation PR](https://github.com/cachix/secretspec/pull/317), a
representative profile with 25 field references resolved in 11.890 seconds,
down from 96.294 seconds. The batch used 3 `op` processes instead of 27, making
that run 8.10 times faster.

## Smaller improvements

### Standalone profiles

Profiles inherit `[profiles.default]` unless their defaults set
`inherit = false`:

```toml title="secretspec.toml"
[profiles.default]
DEV_DATABASE_URL = { description = "Developer database" }
LOCAL_DEBUG_TOKEN = { description = "Local debugging token", required = false }

[profiles.production.defaults]
inherit = false
providers = ["vault://vault.example.com:8200/secret"]

[profiles.production]
DATABASE_URL = { description = "Production database" }
API_KEY = { description = "Production API key" }
```

`production` contains only its own declarations and fields. Other profiles in
the same manifest can continue to inherit the default profile.

### pkg-config metadata for secretspec-ffi

`cargo cinstall -p secretspec-ffi` now installs the library, C header, and a
`secretspec_ffi.pc` file containing the complete link metadata. Go builds can
use the `pkgconfig` tag, Ruby native extensions accept `--enable-pkg-config`,
and Haskell builds use the `use-pkg-config` Cabal flag. The same metadata
supports installed static or shared libraries.

Haskell now declares its required macOS system frameworks. The Rust SDK's
`ProviderAlias` type also exposes `leaf`, `credentials`, and `credentials_mut`
helpers for configuration tooling.

## Upgrading

```bash
cargo install secretspec
```

Existing route-wide `ref` declarations, inheriting profiles, and cached
fallback aliases remain compatible. All new configuration fields and providers
are opt-in.

0.19 also:

- fixes [concurrent keyring
  initialization](https://github.com/cachix/secretspec/issues/268).
- preserves [non-UTF-8 environment values in `run` on
  Unix](https://github.com/cachix/secretspec/issues/140).
- renders [SOPS path templates in one
  pass](https://github.com/cachix/secretspec/pull/271) and [validates
  deserialized path
  templates](https://github.com/cachix/secretspec/commit/bd448ad821d251f1d38a4235a1db868372bb2bd3).
- preserves [complete multi-segment LastPass templates in route
  comparisons](https://github.com/cachix/secretspec/issues/272).
- [refreshes fallback providers when a Rust `Secrets` instance is
  reused](https://github.com/cachix/secretspec/issues/283).
- adds [`Secrets::resolve_named`](https://github.com/cachix/secretspec/pull/315)
  for resolving one secret without unrelated missing requirements.
- rejects [credentials embedded in provider
  URIs](https://github.com/cachix/secretspec/pull/315). Use alias credentials or
  provider environment variables instead.

See the [full changelog](https://github.com/cachix/secretspec/blob/main/CHANGELOG.md)
for every change and fix in this release.

## Future work

These items are not part of 0.19. They are open work for future releases:

- **Native Windows ARM64 CLI archive (target: 0.19.1)**: add
  `secretspec-aarch64-pc-windows-msvc.zip` and its checksum to GitHub Releases
  so the CLI can run natively on Windows ARM64. The static installer will
  continue to select the x64 build on Windows ARM devices until it supports the
  native archive, and standalone updates depend on
  [axoupdater supporting Windows ARM64](https://github.com/axodotdev/axoupdater/pull/357).
- **WinGet packaging**: publish the initial package tracked in
  [microsoft/winget-pkgs#413776](https://github.com/microsoft/winget-pkgs/pull/413776),
  then automate stable updates through
  [SecretSpec #297](https://github.com/cachix/secretspec/pull/297).
- **[Notification and approval
  integrations](https://github.com/cachix/secretspec/issues/300)**: send new
  secret access requests to services such as email, Slack, or WhatsApp for
  approval.
- **[JVM SDK](https://github.com/cachix/secretspec/issues/310)**: expose the
  shared SecretSpec resolver to Java, Kotlin, and other JVM languages.
- **[Dart SDK](https://github.com/cachix/secretspec/issues/240)**: bring the
  shared resolver to Dart and Flutter applications.

Every team has a secrets story. Come tell us yours on
[Discord](https://discord.gg/naMgvexb6q).
