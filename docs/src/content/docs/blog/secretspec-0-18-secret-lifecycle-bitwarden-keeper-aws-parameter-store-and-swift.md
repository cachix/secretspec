---
title: "SecretSpec 0.18: Secret lifecycle, Bitwarden, Keeper, AWS Parameter Store, and Swift"
description: Declare, discover, migrate, and delete secrets from the CLI; use four new providers; and resolve the same manifests from Swift.
date: 2026-08-03
authors:
  - domen
---

[SecretSpec 0.18](https://github.com/cachix/secretspec/releases/tag/v0.18.0 "SecretSpec 0.18 release")
ships:

- **[Secret lifecycle commands](#secret-lifecycle-commands)**: add
  declarations, delete stored values, and move secrets between providers
  without leaving the source copy behind.
- **[Provider-backed discovery](#provider-backed-discovery)**:
  initialize a manifest from an age file, an AWS Parameter Store hierarchy, or
  a Bitwarden collection without writing any values to it.
- **[Four new providers](#four-new-providers)**: use [Bitwarden Password
  Manager](/providers/bw/), [Keeper Secrets Manager](/providers/keeper/), [AWS
  Systems Manager Parameter Store](/providers/awsps/), and
  [Dashlane](/providers/dashlane/) through the same CLI and SDK interface.
- **[Swift SDK](#swift-sdk)**: resolve manifests natively on macOS
  through a checksummed XCFramework that includes the shared Rust resolver.
- **[Vault and OpenBao authentication](#vault-and-openbao-authentication)**:
  use custom AppRole and JWT mounts, AppRoles without SecretID binding, and
  server-configured default JWT roles.

## We have a new logo!

![The new SecretSpec document-and-keyhole logo](../../../assets/logo.png)

## Secret lifecycle commands

SecretSpec has always kept the declaration in `secretspec.toml` separate from
the stored value. 0.18 brings both sides of that lifecycle into the CLI.

[`secretspec add`](/reference/cli/#add-018) adds a declaration to the selected
profile while preserving the manifest's comments, formatting, and unrelated
tables:

```console
$ secretspec add STRIPE_API_KEY --description "Stripe API access token"
✓ Added secret 'STRIPE_API_KEY' to profile 'default' in secretspec.toml
Set its value with: secretspec set STRIPE_API_KEY --profile default

$ secretspec set STRIPE_API_KEY
Enter value for STRIPE_API_KEY: ********
✓ Secret 'STRIPE_API_KEY' saved to keyring (profile: default)
```

`add` never asks for or stores the value. The declaration can be reviewed and
committed before each developer or deployment supplies its own value.

[`secretspec delete`](/reference/cli/#delete-018) does the inverse on the
storage side: it removes a value without changing the declaration. The next
`check` therefore reports the secret as missing instead of quietly removing
the application's requirement:

```console
$ secretspec delete STRIPE_API_KEY
Deleted 'STRIPE_API_KEY'
Deleted 1 secret value; 0 already absent
```

Deletion is idempotent, invalidates an associated cache entry, and follows the
same primary-write-provider routing as `set`. `delete --all` requires an
interactive confirmation, or an explicit `--yes` in non-interactive use.

Provider migrations can now remove each source value after proving the move
succeeded:

```bash
$ secretspec import dotenv:~/.config/payments/.env --delete-source
```

[`import --delete-source`](/reference/cli/#import) reads the destination back
and compares it with the source before deleting anything. An identical value
already at the destination is safe to remove from the source; a conflicting
value leaves the source intact. SecretSpec also rejects a source without
deletion support before writing the destination and recognizes equivalent
provider spellings as the same store, so a migration cannot delete the value
it just wrote through another alias.

Together these commands keep the distinction explicit: `add` changes what the
application declares, `set` and `delete` change one environment's stored
value, and `import --delete-source` moves that value between stores.

## Provider-backed discovery

The first SecretSpec command in an existing project is often
`secretspec init --from .env`. In 0.18,
[`init --from`](/reference/cli/#init) accepts every provider that can discover
declarations, including age, AWS Parameter Store, and Bitwarden Password
Manager.

Hierarchical stores also receive an explicit project and profile so SecretSpec
looks only inside the namespace the new manifest will use:

```console
$ secretspec init \
    --from 'awsps://production@us-east-1?template=/{profile}/{project}/{key}' \
    --project payments \
    --profile production
✓ Created secretspec.toml with 12 secrets
```

For a password-manager vault, scope discovery to the collection and item type
that belong to the application:

```console
$ secretspec init --from 'bw://Acme%20Inc@dev-secrets?type=login'
✓ Created secretspec.toml with 8 secrets
```

Discovery writes names and generated descriptions, never secret values. After
reviewing the manifest, keep the discovered provider as the profile's source
or use `secretspec import` to copy the now-declared values somewhere else.

## Four new providers

0.18 brings SecretSpec to 24 providers, with four additions spanning personal
password managers, machine-oriented vaults, and cloud parameter storage.

**[Bitwarden Password Manager](/providers/bw/)** is separate from the existing
Bitwarden Secrets Manager provider. The new `bw://` provider uses the official
`bw` CLI to read and write regular vault items: logins, secure notes, cards,
identities, and SSH keys. It can address organizations and collections by name
or ID, restrict a provider to one item type or field, discover declarations,
and point [`ref`](/concepts/references/) secrets at existing items. A
`?server=` guard verifies that the CLI is logged into the expected self-hosted
instance instead of silently reading the wrong vault.

**[Keeper Secrets Manager](/providers/keeper/)** uses Keeper's official Rust
SDK, so it does not need a separate CLI. A `keeper://FOLDER_UID` provider reads,
writes, batches, and deletes convention records shared with a KSM application;
refs can select an existing record and field. Its client configuration can
come from `KSM_CONFIG`, a protected configuration file, or SecretSpec
[provider credentials](/concepts/providers/#provider-credentials).

**[AWS Systems Manager Parameter Store](/providers/awsps/)** stores every
value as a KMS-encrypted `SecureString`. The `awsps://` provider uses the
standard AWS credential and region chains and supports shared-config profiles,
hierarchy prefixes, complete `{project}` / `{profile}` / `{key}` templates,
customer-managed KMS keys, and parameter tiers. Refs can select an existing
parameter by name, version, label, or ARN; unversioned name refs are writable,
while pinned revisions remain read-only. Its bounded hierarchy discovery uses
`GetParametersByPath` without decrypting values.

**[Dashlane](/providers/dashlane/)** reads secrets, secure notes, and logins
through the `dcli` CLI. It is intentionally read-only because `dcli` cannot
create or edit vault items. A ref can address an existing item by title or
identifier and select one of its fields. CI can provide
`DASHLANE_SERVICE_DEVICE_KEYS` directly or source the same
`service_device_keys` input from another SecretSpec provider.

A project can route different secrets through any combination of them:

```toml title="secretspec.toml"
[providers]
team_vault = "bw://Acme%20Inc@dev-secrets"
keeper_ci = "keeper://SHARED_FOLDER_UID"
parameters = "awsps://production@us-east-1?prefix=/platform"
dashlane_notes = "dashlane://note"
```

Provider choice still stays outside application code. The CLI and every SDK
resolve the same declaration regardless of which of these aliases supplies a
value.

## Swift SDK

The new [Swift SDK](/sdk/swift/) brings the shared SecretSpec resolver to macOS
12 or later on Intel and Apple silicon. Add the repository as a Swift package:

```swift
dependencies: [
    .package(
        url: "https://github.com/cachix/secretspec",
        from: "0.18.0"
    ),
]
```

Then use the same builder vocabulary as the other SDKs:

```swift
import SecretSpec

let resolved = try SecretSpec.builder()
    .withProfile("production")
    .withScope("api")
    .withReason("boot web app")
    .load()
defer { try? resolved.close() }

print(resolved.secrets["DATABASE_URL"]?.get() ?? "")
try resolved.setAsEnvironment()
```

The SDK exposes fluent and one-shot resolution, typed failures, value-free
preflight reports, scopes, provenance, environment export, and JSON input for
generated Swift models. Calling `close()` deterministically removes temporary
files created for `as_path` secrets.

The SwiftPM release contains a checksummed XCFramework with the Rust resolver,
so an application needs neither a Rust toolchain nor a separately installed
SecretSpec library.

## Vault and OpenBao authentication

[Vault](/providers/vault/) and [OpenBao](/providers/openbao/) deployments do
not always use the default `approle` and `jwt` mount names. Their provider URIs
can now choose a mount relative to `/v1/auth`:

```text
vault://vault.example.com:8200/secret?auth=approle&auth_mount=platform-approle
openbao://bao.example.com:8200/secret?auth=jwt&auth_mount=ci-jwt&role=deploy
```

AppRole authentication can omit `secret_id` when the server role is configured
with `bind_secret_id=false`. JWT authentication can likewise omit its role when
the selected mount has a server-configured `default_role`. Explicit URI,
environment, or provider-credential inputs continue to take precedence.

## Upgrading

```bash
$ cargo install secretspec
```

0.18 also makes two local workflows less dependent on machine-specific setup:

- custom [dotenv](/providers/dotenv/) paths accept a leading `~`, resolved to
  the current user's home directory;
- Linux [keyring](/providers/keyring/) builds use keyring 4's Rust-native
  Secret Service transport, so SecretSpec binaries no longer require system
  `libdbus`.

Existing manifests and providers continue to work unchanged. The new commands,
providers, and SDK are opt-in.

See the [full changelog](https://github.com/cachix/secretspec/blob/main/CHANGELOG.md)
for every change and fix in this release.

Questions or feedback? Join us on
[Discord](https://discord.gg/naMgvexb6q).
