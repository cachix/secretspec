---
title: sec Provider
description: Local single-file encrypted store built for agent-safe workflows
---

The sec provider integrates with [sec](https://github.com/kaidstor/sec), a
local secrets manager that keeps every value in one
XChaCha20-Poly1305-encrypted file with the master key in the OS keychain. sec
is built for agent-safe workflows: values never appear on argv, in shell
history, or in an AI agent's chat transcript.

:::note[Version compatibility]
Available since SecretSpec 0.19. Requires sec 1.0 or newer — the first sec
release with the machine-interface contract (distinct "not found" exit code)
this provider relies on.
:::

## At a glance

| | |
| --- | --- |
| Provider | `sec` |
| URI | `sec://[?template=PATTERN]` |
| Access | Read and write |
| Best for | Local development with an encrypted store shared between humans and AI agents |
| Authentication | The OS keychain unlocks the master key (or `SEC_KEY` in headless environments) |
| Availability | SecretSpec 0.19+ |
| Default storage | `{project}@{profile}/{key}` in sec's own address space |

## Quick start

```bash
# Set a secret
$ secretspec set DATABASE_URL --provider sec
Enter value for DATABASE_URL: postgresql://localhost/mydb
✓ Secret DATABASE_URL saved to sec

# Get a secret
$ secretspec get DATABASE_URL --provider sec
postgresql://localhost/mydb

# Run with secrets
$ secretspec run --provider sec -- npm start
```

## Setup

### Prerequisites

Install the `sec` CLI (version 1.0+):

```bash
# macOS
brew install kaidstor/tap/sec

# Nix
nix profile install github:kaidstor/sec

# Other platforms: binaries on GitHub Releases
# https://github.com/kaidstor/sec/releases
```

No initialization step is needed: the store and master key are created on
first write.

### Authentication

On desktops the master key lives in the system keychain (macOS Keychain,
Secret Service on Linux, Credential Manager on Windows) and is unlocked by
the OS session. In headless environments (CI, servers) set `SEC_KEY` (a
64-hex-character key) and optionally `SEC_STORE` (path to the store file);
the provider inherits both from the environment.

## Configuration

### URI format

```
sec://[?template=PATTERN]
```

The optional `template` query parameter replaces the complete convention
layout and supports the `{project}`, `{profile}`, and `{key}` placeholders.

### URI examples

```bash
sec://                                    # sec's native layout
sec://?template={project}@{profile}/{key} # Keep "default" as a named profile (no base-set collapse)
sec://?template=shared@{profile}/{key}    # One shared sec project for all secretspec projects
```

### Project configuration

```toml
# secretspec.toml
[project]
name = "my-app"
revision = "1.0"

[profiles.default]
DATABASE_URL = { description = "PostgreSQL connection string", required = true }
```

```toml
# ~/.config/secretspec/config.toml
[defaults]
provider = "sec"
profile = "default"
```

## Storage model

Convention secrets map onto sec's **own** address space rather than a
secretspec-specific folder:

| SecretSpec profile | sec address |
| --- | --- |
| `default` | `{project}@/{key}` — the project's base (profile-less) set |
| any other, e.g. `production` | `{project}@production/{key}` — a sec profile |

The `default` profile deliberately collapses to sec's base set, so secrets
that already live in a sec store (`myapp/API_TOKEN`) are picked up without
migration, and secrets written through SecretSpec remain at the addresses sec
users expect (`sec get myapp/API_TOKEN`). SecretSpec profiles and sec
profiles are the same concept and map one-to-one.

Addresses always use sec's explicit `@` form (`myapp@/KEY`, not `myapp/KEY`)
so resolution does not depend on the working directory: a local `.sec`
manifest may declare a default profile that would otherwise rewrite bare
addresses.

## Use existing secrets

`secretspec init --from sec://` discovers the keys of an existing sec project
(names and non-secret metadata only — sec never prints values in listings)
and turns them into declarations. sec key notes become declaration
descriptions. Discovery with a custom `template` is not supported.

```bash
$ secretspec init --from sec:// --project myapp --profile production
```

## Troubleshooting and limitations

- **Outcome detection is exit-code based.** sec's diagnostics are localized
  (Russian); the provider never parses stderr. It relies on sec's documented
  machine interface: exit code 3 means "no such key/project", everything else
  non-zero is a real failure whose stderr is passed through.
- **`sec: command not found`** — install sec 1.0+ and make sure it is on
  `PATH` for the process running secretspec.
- **Empty values are rejected** by sec (a deliberate guard against
  accidentally storing nothing); writing an empty secret fails.
- **Values are single-line by design**: sec trims trailing newlines at write
  time, and the provider strips the single trailing newline `sec get`
  prints. Secrets whose value must end in a newline are not preserved
  byte-exactly.
- **Binary (file) secrets** stored in sec (`sec set --from-file`) are not
  readable through this provider — sec refuses to print them to stdout.
  Environment-style secrets are unaffected.
