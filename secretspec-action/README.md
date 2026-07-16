# secretspec-action

Resolve the secrets declared in `secretspec.toml` and expose them to the rest of a GitHub or Forgejo Actions job.

The action installs the `secretspec` CLI and runs `secretspec export --format gha`, which masks every value in the runner log (`::add-mask::`) and appends `KEY=value` to `$GITHUB_ENV`. Every later step in the job sees the secrets as ordinary environment variables.

## Usage

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: cachix/secretspec/secretspec-action@main
        with:
          profile: production
          provider: env
      - run: ./deploy.sh   # DATABASE_URL etc. are in the environment
```

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `profile` | project default | secretspec profile to resolve |
| `provider` | user/project config | provider name, alias, or URI to resolve from |
| `version` | `latest` | secretspec release tag to install, or `latest` |
| `working-directory` | `.` | directory containing `secretspec.toml` |

A missing required secret fails the step, so the action doubles as a CI gate.

## Requirements

- A secretspec release that includes `secretspec export`.
- Linux, macOS, or Windows runners. The prebuilt Linux binary links glibc and libdbus (for the keyring provider); GitHub-hosted runner images ship both, but a minimal `container:` image (alpine, distroless) will not.
- Provider credentials must already be available to the job, e.g. `provider: env` with repo secrets, or a Vault/OpenBao token obtained from an earlier OIDC exchange step.
