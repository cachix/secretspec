---
title: GitHub Actions
description: Resolve secrets from secretspec.toml in GitHub Actions, Forgejo Actions, and other CI systems
---

In a GitHub or Forgejo Actions job, `secretspec-action` installs the CLI and runs `secretspec export --format gha`, which masks every value in the runner log and appends `KEY=value` to `$GITHUB_ENV`. Every later step, including third-party actions, then sees the secrets as ordinary environment variables.

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: cachix/secretspec-action@main
        with:
          profile: production
      - run: ./deploy.sh
```

A missing required secret fails the step before the job runs anything with an incomplete environment.

## Fetching from a secret manager

For secrets kept in a dedicated store, resolve them on the runner with the matching provider, shown here with [Vault or OpenBao](/providers/vault/). Other stores plug in the same way with their own credentials.

Grant the job `id-token: write` and select `?auth=jwt` with a `role`. Vault exchanges the runner's OIDC token for a client token, so nothing is stored on the platform.

```yaml
      - uses: cachix/secretspec-action@main
        with:
          profile: production
          provider: vault://vault.example.com:8200/secret?auth=jwt&role=ci
```

Without an OIDC identity to draw on, select `?auth=approle` instead and pass `VAULT_ROLE_ID` and `VAULT_SECRET_ID` as CI secrets.

```yaml
      - uses: cachix/secretspec-action@main
        with:
          profile: production
          provider: vault://vault.example.com:8200/secret?auth=approle
        env:
          VAULT_ROLE_ID: ${{ secrets.VAULT_ROLE_ID }}
          VAULT_SECRET_ID: ${{ secrets.VAULT_SECRET_ID }}
```

## Other CI systems

`secretspec-action` is a convenience wrapper around commands that work anywhere the CLI is installed.

- `secretspec run -- <command>` runs a single command with the secrets confined to its environment.
- `secretspec export` writes the resolved secrets to stdout for a tool that cannot be wrapped, such as a containerized pipeline. `eval "$(secretspec export)"` loads them into the current shell, while `--format dotenv` and `--format json` feed other consumers.

Both resolve through the same provider chain and fail on a missing required secret.
