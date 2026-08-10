---
title: Proton Pass Provider
description: Proton Pass integration via the official pass-cli
---

:::caution[Why `pass-cli` upgrades can break this provider]
Proton Pass has no public API and no SDK, so this provider drives the official
`pass-cli` executable and inherits whatever that executable does.

Proton support confirmed in August 2026 that its support for `pass-cli` covers
only what the
[`pass-cli` changelog](https://github.com/protonpass/pass-cli/blob/main/CHANGELOG.md)
publishes, that backward incompatible changes can ship in a patch release with
no advance notice, and that it is reasonable to expect more of them. Three such
releases have already changed behaviour SecretSpec depends on, most recently
`pass-cli` 2.2.4, which broke every Proton Pass operation until SecretSpec
0.19. See [`pass-cli` compatibility](#pass-cli-compatibility).

The practical consequence is that upgrading `pass-cli` can break secret
resolution on a machine where nothing about SecretSpec changed, and the repair
then waits on a SecretSpec release. Install a `pass-cli` version you have
tested and upgrade it deliberately, as described in
[Pinning a `pass-cli` version](#pinning-a-pass-cli-version).

This is unfortunate. Providers built on a versioned API or on a vendor
interface with a compatibility policy do not break this way. If Proton
publishes a stable API, an SDK, or a compatibility policy for `pass-cli`, we
would build on it instead.
:::

The Proton Pass provider integrates with [Proton Pass](https://proton.me/pass) for end-to-end encrypted cloud secret storage.

## At a glance

| | |
| --- | --- |
| Provider | `protonpass` |
| URI | `protonpass://[vault_name[/title-template]]` |
| Access | Read and write |
| Best for | End-to-end encrypted cloud storage through Proton Pass |
| Authentication | A `pass-cli` login or personal access token |
| Default storage | Note item `{project}/{profile}/{key}` in the `secretspec` vault |
| Requires | Official `pass-cli`, pinned to a version you have tested (see [compatibility](#pass-cli-compatibility)) |

## Quick start

```bash
# Set a secret
$ secretspec set DATABASE_URL --provider protonpass://Personal
Enter value for DATABASE_URL: postgresql://localhost/mydb

# Get a secret
$ secretspec get DATABASE_URL --provider protonpass://Personal

# Run with secrets
$ secretspec run --provider protonpass://Personal -- npm start
```

## Setup

### Prerequisites

- Proton Pass CLI (`pass-cli`) - download from [proton.me/pass/download](https://proton.me/pass/download)
- A Proton account, signed in via `pass-cli login`
- A vault to store secrets in (e.g. `pass-cli vault create secretspec`)
- A `pass-cli` version that works with your SecretSpec release, see
  [`pass-cli` compatibility](#pass-cli-compatibility)

### Authentication

For local use, sign in interactively:

```bash
$ pass-cli login
```

For CI, use a personal access token as shown in [CI/CD](#cicd).

## `pass-cli` compatibility

Each of these `pass-cli` releases changed behaviour the provider relies on:

| `pass-cli` | What changed | SecretSpec |
| --- | --- | --- |
| 2.0.3 (2026-05-19) | `item list` output shape | Handled in 0.12.1+ |
| 2.1.0 (2026-05-20) | Agent sessions reject audited item operations that carry no reason | Handled in 0.12.0+, see [Agent sessions](#agent-sessions) |
| 2.2.4 (2026-07-31) | `pass-cli test` removed | Handled in 0.19+ ([#279](https://github.com/cachix/secretspec/issues/279)) |

SecretSpec probes the session once per run before any read or write. SecretSpec
0.18.0 and earlier probe with `pass-cli test`, so on `pass-cli` 2.2.4 and later
every Proton Pass operation fails with:

```text
Provider operation failed: error: unrecognized subcommand 'test'
```

SecretSpec 0.19+ tries `pass-cli info` and falls back to `pass-cli test`, so it
works with every `pass-cli` release regardless of which check that release
carries. `info` is preferred because it runs behind the CLI's authentication
gate and so reports whether a valid session is present, while `test` only
proved that Proton's servers were reachable. A `pass-cli` carrying neither is
reported as incompatible with your SecretSpec release rather than surfacing the
CLI's usage text.

On SecretSpec 0.18.0 and earlier, use `pass-cli` 2.2.3, the last release
published before `pass-cli test` was removed.

### Pinning a `pass-cli` version

Install a specific release instead of tracking the latest build, and point
SecretSpec at it with `SECRETSPEC_PROTONPASS_CLI_PATH`:

```bash
$ curl -Lo ~/.local/bin/pass-cli-2.2.3 \
    https://github.com/protonpass/pass-cli/releases/download/2.2.3/pass-cli-linux-x86_64

$ chmod +x ~/.local/bin/pass-cli-2.2.3

$ export SECRETSPEC_PROTONPASS_CLI_PATH="$HOME/.local/bin/pass-cli-2.2.3"
```

Every [release](https://github.com/protonpass/pass-cli/releases) publishes a
`.sha256` file next to each binary; verify it before use. Pin the same version
in CI rather than installing the latest `pass-cli` on each run, and treat a
`pass-cli` upgrade as a change worth testing: run `secretspec check` against
the new version before rolling it out.

## Configuration

### URI format

```
protonpass://[vault_name[/title-template]]
```

- `vault_name`: Target vault (defaults to `secretspec`)
- `title-template`: Item title pattern supporting `{project}`, `{profile}`, `{key}` placeholders

### URI examples

```text
# Default vault ("secretspec")
protonpass://

# Specific vault
protonpass://Work

# Specific vault and custom title template
protonpass://Work/{project}/{profile}/{key}
```

### Project configuration

```toml title="secretspec.toml"
[providers]
team = "protonpass://Work"

[profiles.production]
DATABASE_URL = { description = "Database URL", providers = ["team"] }
```

## Storage model

Secrets are stored as note items. The vault defaults to `secretspec`, and the
item title defaults to `{project}/{profile}/{key}`. The URI can select another
vault or replace the title template.

## Use existing secrets

A secret's [`ref`](/reference/configuration/#secret-references) field names an
existing item instead: `item` is the exact item title, whose note is read
(`field` is not supported). Reads and writes target that item in place.

```toml
[profiles.production]
DATABASE_URL = { description = "DB", ref = { item = "Production Database" }, providers = ["protonpass://Work"] }
```

## CI/CD

```bash
# Create a token
$ pass-cli personal-access-token create --name ci --expiration 1y

# Authenticate in CI (store the token as a CI secret)
$ pass-cli login --pat $PROTON_PASS_PAT

$ secretspec run -- deploy
```

## Advanced configuration

### Agent sessions

`pass-cli` 2.1.0 introduced agent sessions, which require a
`PROTON_PASS_AGENT_REASON` to be set for audited item operations (reading,
creating, and deleting items). SecretSpec sets this automatically, so existing
secrets resolve correctly under an agent session.

The reason recorded in the Proton Pass audit log is resolved in this order:

1. The `--reason` flag (or `SECRETSPEC_REASON` environment variable):

   ```bash
   $ secretspec run --reason "Deploying app from CI" -- ./deploy.sh
   ```

   When using the Rust SDK, set it for the session with `with_reason`:

   ```rust
   use secretspec::Secrets;

   let spec = Secrets::load()?.with_reason("Deploying app from CI");
   ```

2. The `PROTON_PASS_AGENT_REASON` environment variable read by `pass-cli`:

   ```bash
   $ export PROTON_PASS_AGENT_REASON="Deploying app from CI"
   ```

3. A default that identifies the secretspec version (e.g. `secretspec/0.11.0 (https://secretspec.dev)`).

To force a meaningful reason instead of falling back to the default, use the
[`require_reason`](/reference/configuration/#requiring-a-reason-for-secret-access)
policy in `secretspec.toml`. It defaults to `"agents"`, so sessions SecretSpec
detects as AI agents must explain why they read a secret. Detection is
heuristic; set it to `true` to require a reason from every SecretSpec caller.
secretspec then refuses operations through SecretSpec that do not supply an
explicit reason.
