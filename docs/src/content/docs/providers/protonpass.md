---
title: Proton Pass Provider
description: Proton Pass integration via the official pass-cli
---

The Proton Pass provider integrates with [Proton Pass](https://proton.me/pass) for end-to-end encrypted cloud secret storage.

## Prerequisites

- Proton Pass CLI (`pass-cli`) - download from [proton.me/pass/download](https://proton.me/pass/download)
- A Proton account, signed in via `pass-cli login`
- A vault to store secrets in (e.g. `pass-cli vault create monosecret`)

## Configuration

### URI Format

```
protonpass://[vault_name[/title-template]]
```

- `vault_name`: Target vault (defaults to `monosecret`)
- `title-template`: Item title pattern supporting `{project}`, `{profile}`, `{key}` placeholders

### Examples

```bash
# Default vault ("monosecret")
protonpass://

# Specific vault
protonpass://Work

# Specific vault and custom title template
protonpass://Work/{project}/{profile}/{key}
```

## Secret References

By default each secret maps to an item titled `{project}/{profile}/{key}`. A
secret's [`ref`](/reference/configuration/#secret-references) field names an
existing item instead: `item` is the exact item title, whose note is read
(`field` is not supported). Reads and writes target that item in place.

```toml
[profiles.production]
DATABASE_URL = { description = "DB", ref = { item = "Production Database" }, providers = [
  "protonpass://Work",
] }
```

## Usage

```bash
# Set a secret
$ monosecret set DATABASE_URL --provider protonpass://Personal
Enter value for DATABASE_URL: postgresql://localhost/mydb

# Get a secret
$ monosecret get DATABASE_URL --provider protonpass://Personal

# Run with secrets
$ monosecret run --provider protonpass://Personal -- npm start

# Profile-specific vault
$ monosecret set DATABASE_URL --profile prod --provider protonpass://Production
```

Secrets are stored as note items; the item title defaults to `{project}/{profile}/{key}`.

### CI/CD with Personal Access Tokens

```bash
# Create a token
$ pass-cli personal-access-token create --name ci --expiration 1y

# Authenticate in CI (store the token as a CI secret)
$ pass-cli login --pat $PROTON_PASS_PAT
$ monosecret run -- deploy
```

### Agent sessions

`pass-cli` 2.1.0 introduced agent sessions, which require a
`PROTON_PASS_AGENT_REASON` to be set for audited item operations (reading,
creating, and deleting items). Monosecret sets this automatically, so existing
secrets resolve correctly under an agent session.

The reason recorded in the Proton Pass audit log is resolved in this order:

1. The `--reason` flag (or `MONOSECRET_REASON` environment variable; legacy:
   `SECRETSPEC_REASON`):

   ```bash
   $ monosecret run --reason "Deploying app from CI" -- ./deploy.sh
   ```

   When using the Rust SDK, set it for the session with `with_reason`:

   ```rust
   use monosecret::Secrets;

   let secrets = Secrets::load()?.with_reason("Deploying app from CI");
   ```

2. The `PROTON_PASS_AGENT_REASON` environment variable read by `pass-cli`:

   ```bash
   $ export PROTON_PASS_AGENT_REASON="Deploying app from CI"
   ```

3. A default that identifies the Monosecret version (for example,
   `monosecret/0.1.0 (https://ifiokjr.github.io/monosecret/)`).

To force a meaningful reason instead of falling back to the default, use the
[`require_reason`](/reference/configuration/#requiring-a-reason-for-secret-access)
policy in `monosecret.toml`. It defaults to `"agents"`, so AI agents must always
explain why they read a secret (humans are unaffected); set it to `true` to require
a reason from every caller. Monosecret then refuses any access that does not supply
an explicit reason.
