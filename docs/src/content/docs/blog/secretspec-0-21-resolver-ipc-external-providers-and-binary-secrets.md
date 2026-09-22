---
title: "SecretSpec 0.21: Resolver IPC, external providers, and binary secrets"
description: Resolve secrets over IPC, build providers outside the Rust workspace, connect Claude Code to your secret store, and preserve binary values end to end.
date: 2026-09-22T12:00:00-05:00
authors:
  - domen
draft: false
---

SecretSpec 0.21 adds two JSON-RPC protocols: one lets tools request secrets
from a separate resolver process; the other lets external executables act as
providers.

This release includes:

- **[Secret Resolution Protocol](#secret-resolution-protocol)**: request one
  secret at a time over JSON-RPC.
- **[Secret Provider Protocol](#secret-provider-protocol)**: add providers as
  external executables.
- **[Binary secrets](#binary-secrets)**: preserve exact bytes through storage,
  imports, caches, and temporary files.
- **[Default providers for a project](#default-providers-for-a-project) (0.21+)**:
  set one provider chain for profiles and secrets that do not choose their own.
- **[Claude Code](#new-integration-claude-code)**: retrieve API and gateway
  credentials from SecretSpec.
- **[Doppler and Tailscale Setec](#new-providers)**: use Doppler configs or a
  Setec service through Tailscale.
- **[Key generation](#key-generation)**: generate eight more credential types
  and derive files from an X.509 identity.
- **[Editor support](#editor-support)**: export JSON Schemas for autocomplete
  and validation.

## Secret Resolution Protocol

Work on [Nix support](https://github.com/NixOS/nix/pull/16300) drove this
protocol. Nix needs forge tokens, netrc files, and build secrets at use time,
without putting values in its configuration. The Nix integration is separate
upstream work; 0.21 provides the protocol it can use.

With `secretspec serve`, a tool can request one declared secret over a private
stdio JSON-RPC connection. The [resolver](/reference/resolver-protocol/) applies
the manifest and provider routing, resolving the named secret and its
dependencies without requiring unrelated secrets.

Results can be inline values or leased temporary files that the resolver
cleans up when the session closes. Clients can answer prompts, and credential
helpers can use the same session for login and logout. Read-only mode disables
provider writes.

Applications can use JSON-RPC directly or a packaged client. The protocol
also works over authenticated streams, including SSH. Existing SDKs still
offer embedded resolution.

## Secret Provider Protocol

The [Secret Provider Protocol](/reference/provider-protocol/) lets an external
executable connect an internal vault, approval service, or other secret store
to SecretSpec. SecretSpec launches the provider executable named in its
trusted configuration.

[FactorSeal](https://github.com/cachix/factorseal) is a desktop and CLI secrets
vault for Linux, macOS, and Windows, being developed as a first-class SecretSpec
integration through the provider protocol.

External providers declare credentials at runtime. `login` can collect them:

```bash
$ secretspec config provider login company_vault
```

External providers can also request missing credentials during writes and
return approval references that link their requests to the local audit log.
See the [implementation guide](/development/ipc-implementation/) for protocol
and registration details.

## Binary secrets

SecretSpec now preserves arbitrary bytes through providers, fallback chains,
imports, and caches. Use `as_path` for applications that need a file:

```toml title="secretspec.toml"
[profiles.default]
CLIENT_KEYSTORE = { description = "Client TLS keystore", as_path = true }
```

```bash
$ secretspec set CLIENT_KEYSTORE --from-file client.p12
$ secretspec run -- ./my-application
```

`CLIENT_KEYSTORE` becomes a temporary path containing the original bytes.
`--from-file -` preserves exact stdin bytes, including trailing newlines.
Byte-capable providers store values natively; use `encoding = "base64"` with
text-only providers.

Rust callers can use `resolve_bytes()` or `resolve_named_bytes()`. Text SDK
responses and exports still require UTF-8 and error on non-UTF-8 values.

## Default providers for a project

In SecretSpec 0.21+, set `[defaults].providers` in `secretspec.toml` to give
secrets stored by providers in every profile one default chain:

```toml title="secretspec.toml"
[defaults]
providers = ["developer"]

[profiles.default]
DATABASE_URL = { description = "Development database URL" }
API_TOKEN = { description = "Development API token" }
```

Each developer can map `developer` to their own backend in the user config:

```toml title="~/.config/secretspec/config.toml"
[defaults.providers]
developer = "keyring://"
```

The project `[defaults].providers` selects a chain; the user
`[defaults.providers]` table defines aliases. A secret's own `providers` chain
takes precedence, followed by its profile defaults, then the project default.
See the [provider guide](/concepts/providers/#configure-a-project-default-provider-chain-021)
for an example with personal provider coordinates.

## New integration: Claude Code

The [Claude Code integration](/integrations/claude-code/) supplies API and
gateway credentials from any SecretSpec provider through Claude Code's native
`apiKeyHelper`:

```bash
$ secretspec claude configure
$ secretspec claude login
$ claude
```

`configure` adds a managed helper to the repository's personal
`.claude/settings.local.json`; `login` stores the credential. Settings retain
only a machine-local configuration identifier. The helper works in worktrees
and with `--global`; SecretSpec preserves unrelated settings.

This covers API and gateway authentication. Claude Code keeps subscription
OAuth credentials. Usage is billed to the account behind the active
credential. See the integration guide for authentication precedence and custom
manifests.

## New providers

### Doppler

The **[Doppler provider](/providers/doppler/)** reads, writes, and deletes
secrets through Doppler's REST API without the Doppler CLI. It keeps names
unchanged, so values also work with `doppler run` and the dashboard.

```toml title="secretspec.toml"
[providers]
production = "doppler://myapp/prd"

[profiles.production]
DATABASE_URL = { description = "Production database", providers = ["production"] }
```

Authenticate with `DOPPLER_TOKEN` or a `token` provider credential. Without a
config in the URI, the SecretSpec profile selects one. Projects and configs
must already exist. `init --from` discovers names without reading values.

### Tailscale Setec

The **[Setec provider](/providers/setec/)** uses the caller's Tailscale identity
and Setec grants. It needs no separate API token:

```bash
$ secretspec set DATABASE_URL --provider setec://secrets.example.ts.net
$ secretspec run --provider setec://secrets.example.ts.net -- npm start
```

Setec supports reads, writes, deletion, discovery, binary values, and pinned
version reads.

## Key generation

Generate a recovery passphrase on first use:

```toml title="secretspec.toml"
[profiles.default.RECOVERY_CODE]
description = "Operator recovery code"
type = "passphrase"
generate = true
```

SecretSpec stores it through the configured provider, so later runs reuse it.
0.21 adds eight generation types:

| Type | Use case |
| --- | --- |
| `passphrase` | Human-readable recovery codes, with configurable word count and separator |
| `mnemonic` | Checksum-valid BIP-39 recovery mnemonics |
| `openpgp_private_key` | OpenPGP signing and encryption |
| `ssh_private_key` | SSH authentication |
| `wireguard_private_key` | WireGuard tunnel credentials |
| `jwk_private_key` | Private signing keys in JWK format, including public parameters |
| `age_identity` | Native X25519 identities for age encryption |
| `x509_identity` | A private key and self-signed certificate stored together as a PKCS#12 archive |

Generated private keys are not passphrase-protected, so store them in an
encrypted provider. See [secret generation](/concepts/generation/) for the
options and defaults.

### One TLS identity, several application formats

One `x509_identity` can supply a PKCS#12 archive or separate certificate and
key files:

```toml title="secretspec.toml"
[profiles.default.TLS_IDENTITY]
description = "Local development TLS identity"
type = "x509_identity"
generate = { san = ["dns:localhost", "ip:127.0.0.1"] }

[profiles.default.TLS_CERT]
description = "TLS certificate"
type = "x509_certificate"
from = "TLS_IDENTITY"
as_path = true

[profiles.default.TLS_KEY]
description = "TLS private key"
type = "pkcs8_private_key"
from = "TLS_IDENTITY"
as_path = true
```

Derived declarations are read-only; scopes can expose their files without
exposing the source identity. See the
[credential generation work](https://github.com/cachix/secretspec/pull/417)
for formats and conversion options.

## Editor support

JSON Schemas for project and user configuration give editors autocomplete,
hover descriptions, and validation. Export schemas matching your CLI:

```bash
$ secretspec schema --config project --output secretspec.schema.json
$ secretspec schema --config global --output config.schema.json
```

See [editor autocomplete](/reference/configuration/#editor-autocomplete) to
associate them with your TOML files.

## Other changes

- Bitwarden Password Manager accepts exact item UUIDs and batches reads from
  one vault listing.
- KeePassXC KDBX 4.0 databases can be written; writes upgrade them to 4.1
  while preserving encryption and key-derivation settings.
- Cache planning avoids redundant reads and rejects a cache that points to
  the same physical secret as its authoritative provider.
- pass, gopass, and LastPass preserve whitespace and multiline values.
  LastPass rejects NUL bytes before writing.

## Upgrading

Once 0.21 is released:

```bash
$ cargo install secretspec --version 0.21.0
```

The new integrations and providers are opt-in. Check these behavior changes:

- `secretspec get` adds no newline when writing to a pipe or file. Terminal
  output still gets one.
- Command generators preserve stdout bytes, including trailing newlines. Trim
  them in the generator if needed. Empty or whitespace-only output is rejected.
- Piped `secretspec set` input remains trimmed text; use `--from-file -` for
  exact bytes.
- Existing gopass text entries return their trimmed first line until rewritten.
  New multiline, whitespace-padded, and binary entries use a lossless format.
- On macOS, an unsigned build may need one **Always Allow** prompt per
  SecretSpec keyring item after an upgrade. The
  [keyring upgrade fix](https://github.com/cachix/secretspec/pull/450) then
  transfers ownership to the new build so later reads stay silent. Choosing
  **Allow** can leave repeated prompts.
- Rust provider and consumer code must handle byte-valued secrets and convert
  to text where required.

Building `libsecretspec-resolver` requires system yyjson. Static linking also
requires yyjson; the installed pkg-config metadata records that dependency.

See the [full changelog](https://github.com/cachix/secretspec/blob/main/CHANGELOG.md)
for every change and fix in this release.

Questions or feedback? Join us on
[Discord](https://discord.gg/naMgvexb6q).
