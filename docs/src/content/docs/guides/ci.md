---
title: CI/CD Setup
description: Load Monosecret-managed secrets safely in GitHub Actions and other CI systems.
---

Monosecret works well in CI because the committed `monosecret.toml` declares **which**
secrets a workflow needs, while the workflow only receives the minimum credential required
to read those values from your provider.

The Monosecret repository uses this pattern for release automation:

1. Store release secrets in 1Password.
2. Store only `OP_SERVICE_ACCOUNT_TOKEN` as a GitHub Actions secret.
3. Declare a `ci` profile in `monosecret.toml`.
4. Run `monosecret env --shell github --profile ci` to append masked values to
   `$GITHUB_ENV` for later steps.

## 1. Create a CI provider alias

For headless CI, use a provider that supports non-interactive authentication. With
1Password, create a service account token and store it in GitHub Actions as
`OP_SERVICE_ACCOUNT_TOKEN`.

Then commit a provider alias without embedding the token:

```toml
# monosecret.toml
[project]
name = "my-app"
revision = "1.0"

[providers]
onepassword-ci = "op+token://Production/my-app"
```

The `op+token://` provider reads the token from `OP_SERVICE_ACCOUNT_TOKEN` at runtime.
You can also use other CI-friendly providers such as `env`, `vault`, `gcsm`, `awssm`,
or `bws`.

## 2. Declare a CI profile

Create a profile for automation-only secrets. This keeps deploy/publish credentials out
of local development profiles and makes workflow requirements reviewable.

```toml
[profiles.ci]
NPM_TOKEN = { description = "npm automation token used by the publish workflow", providers = [
  "onepassword-ci",
] }
DEPLOY_API_KEY = { description = "Production deploy API key", providers = [
  "onepassword-ci",
] }
```

If a value is already supplied by GitHub Actions, do not add it to Monosecret. For
example, `${{ secrets.GITHUB_TOKEN }}` is created per workflow run and should be passed
through directly.

## 3. Load secrets in GitHub Actions

Install Monosecret, expose the provider credential for the loading step, then ask
Monosecret to write GitHub-compatible environment exports.

```yaml
name: deploy

on:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: checkout repository
        uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: install monosecret
        run: npm install --global @monosecret/cli

      - name: load deployment secrets
        env:
          OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
        run: |
          monosecret \
            --reason "Load deployment secrets for $GITHUB_WORKFLOW run $GITHUB_RUN_ID." \
            env --shell github --profile ci --include NPM_TOKEN --include DEPLOY_API_KEY

      - name: deploy
        run: ./scripts/deploy.sh
```

`--shell github` appends `KEY<<DELIM` blocks to `$GITHUB_ENV` and emits `::add-mask::`
commands, so later steps receive the variables while logs stay redacted.

:::tip[This repository]
The Monosecret repository builds the CLI from source in CI, so its workflows use
`cargo run -p monosecret -- ... env --shell github --profile ci` instead of installing
the released binary. Downstream projects should normally use the installed `monosecret`
command.
:::

## 4. Limit what each job loads

Prefer `--include` or `--group` so each job gets only the values it needs.

```toml
[groups]
publish = "Package publishing jobs"
deploy = "Production deployment jobs"

[profiles.ci.NPM_TOKEN]
description = "npm automation token"
groups = ["publish"]
providers = ["onepassword-ci"]

[profiles.ci.DEPLOY_API_KEY]
description = "deploy API key"
groups = ["deploy"]
providers = ["onepassword-ci"]
```

```yaml
- name: load publish secrets
  env:
    OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
  run: |
    monosecret \
      --reason "Load publish secrets." \
      env --shell github --profile ci --group publish
```

## Environment-variable-only CI

If your CI platform already injects every secret as environment variables, use the
read-only `env` provider to validate declarations before running a command:

```yaml
- name: validate required secrets
  env:
    DATABASE_URL: ${{ secrets.DATABASE_URL }}
    API_KEY: ${{ secrets.API_KEY }}
  run: monosecret check --provider env --profile ci

- name: deploy with injected secrets
  env:
    DATABASE_URL: ${{ secrets.DATABASE_URL }}
    API_KEY: ${{ secrets.API_KEY }}
  run: monosecret run --provider env --profile ci -- ./scripts/deploy.sh
```

This is useful when you are adopting Monosecret incrementally, but a dedicated provider
such as 1Password, Vault, AWS Secrets Manager, Google Secret Manager, or Bitwarden keeps
GitHub Actions secrets smaller and easier to rotate.

## Checklist

- Commit secret declarations in `monosecret.toml`; never commit secret values.
- Use a CI-specific profile such as `ci`, `production`, or `deploy`.
- Keep the provider bootstrap credential (`OP_SERVICE_ACCOUNT_TOKEN`, Vault role, cloud
  identity, etc.) in the CI platform's native secret store.
- Pass `--reason` for audit-friendly providers and long-lived automation.
- Use `--include` or `--group` to load the smallest set of secrets per job.
- Keep `persist-credentials: false` on checkout unless a job explicitly needs Git push
  access.
