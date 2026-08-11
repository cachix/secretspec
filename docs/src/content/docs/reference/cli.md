---
title: CLI Commands Reference
description: Complete reference for SecretSpec CLI commands
---

The SecretSpec CLI provides commands for managing secrets across different providers and profiles.

## Global Options

These options are available on every command:

| Option | Description |
|--------|-------------|
| `-f, --file <FILE>` | Path to `secretspec.toml` (default: auto-detect). Env: `SECRETSPEC_FILE` |
| `--reason <REASON>` | Reason for accessing secrets, recorded by providers that support audit logging (e.g. Proton Pass agent sessions). Takes precedence over `PROTON_PASS_AGENT_REASON`. Env: `SECRETSPEC_REASON` |

```bash
$ secretspec run --reason "Deploying web frontend" -- ./deploy.sh
```

## Commands

### init
Initialize a new `secretspec.toml` from declarations discovered in a provider.
Dotenv files are supported in every current release. SecretSpec 0.18+ accepts
any provider that implements reflection, including age files, AWS Parameter
Store, and Bitwarden Password Manager vaults.

```bash
$ secretspec init [--from <PROVIDER>] [--project <PROJECT>] [--profile <PROFILE>]
```

**Options:**

- `--from <PROVIDER>` - Provider URI to discover (default: `dotenv://.env`);
  use a `dotenv://` URI for dotenv files
- `--project <PROJECT>` - Project used to render the provider namespace
  (SecretSpec 0.18+; default: current directory name)
- `-P, --profile <PROFILE>` - Profile used to render the provider namespace
  and written to the manifest (SecretSpec 0.18+; default: `default`)

Reflection creates declarations only: values are never written to the
manifest. Configure the discovered provider as the profile's source to keep
using it, or run `secretspec import` afterward to copy the declared values to a
different destination.

**Examples:**

```bash
$ secretspec init --from dotenv://.env.example
✓ Created secretspec.toml with 5 secrets

# SecretSpec 0.18+: discover one rendered Parameter Store hierarchy
$ secretspec init \
    --from 'awsps://us-east-1?template=/{profile}/{project}/{key}' \
    --project payments \
    --profile production
✓ Created secretspec.toml with 12 secrets

# SecretSpec 0.18+: discover items in one Bitwarden collection
$ secretspec init --from 'bw://dev-secrets?type=login'
✓ Created secretspec.toml with 8 secrets
```

### config global init
Initialize user-global configuration. The explicit `global` namespace is
available in SecretSpec 0.17+; without options, the command prompts for the
provider and profile.

```bash
$ secretspec config global init [--provider <PROVIDER>] [--profile <PROFILE>] # 0.17+
```

SecretSpec 0.17+ accepts `--provider` and `--profile` so installations can save
both defaults without interaction. Each omitted option still prompts; use
`--profile none` to clear the saved default profile. The corresponding
`SECRETSPEC_PROVIDER` and `SECRETSPEC_PROFILE` environment variables are also
accepted. Project requirements remain in `secretspec.toml`; the namespace makes
it clear that this command writes user-wide defaults. The legacy
`secretspec config init` spelling remains supported as a hidden alias.

**Example:**
```bash
$ secretspec config global init  # 0.17+
? Select your preferred provider backend:
> keyring: System keychain
? Select your default profile:
> development
✓ Configuration saved to ~/.config/secretspec/config.toml
```

```bash
# SecretSpec 0.17+: save both defaults without prompting
$ secretspec config global init --provider env --profile default
✓ Configuration saved to ~/.config/secretspec/config.toml
```

### config global show
Display current user-global configuration. The explicit namespace is available
in SecretSpec 0.17+; `secretspec config show` remains a hidden alias.

```bash
$ secretspec config global show # 0.17+
```

**Example:**
```bash
$ secretspec config global show  # 0.17+
Provider: keyring
Profile:  development
```

### config global provider add
Add a provider alias to your user-level configuration (`~/.config/secretspec/config.toml`).

To share aliases with your team, declare them in a top-level `[providers]` table in `secretspec.toml` instead — they take precedence over user-level aliases on name conflict.

:::note[Version compatibility]
SecretSpec 0.14 supports adding aliases with `<ALIAS>` and `<URI>`.
The `--credential` option is available starting with SecretSpec 0.15.
The explicit `global` namespace is available starting with SecretSpec 0.17;
the legacy `config provider add` spelling remains a hidden alias.
:::

```bash
$ secretspec config global provider add <ALIAS> <URI> [--credential NAME=PROVIDER]... # 0.17+
```

**Arguments:**
- `<ALIAS>` - Short name for the provider (e.g., `prod_vault`, `shared`)
- `<URI>` - Provider URI (e.g., `onepassword://Production`, `env://`)

**Options:**
- `--credential <NAME=PROVIDER>` - Declare a [provider credential](/reference/provider-credentials/) and its source. `NAME` is semantic and provider-specific, such as `access_token` or `role_id`. Repeatable. Only the bare-string source form is expressible on the command line; add a `ref` by editing the config.

**Example:**
```bash
$ secretspec config global provider add prod_vault "onepassword://Production" # 0.17+
✓ Provider alias 'prod_vault' added: 'onepassword://Production'

$ secretspec config global provider add bws "bws://project-uuid" --credential access_token=keyring # 0.17+
✓ Provider alias 'bws' added: 'bws://project-uuid'
  credentials: access_token=keyring
  run 'secretspec config provider login bws' to store the credentials
```

### config global provider list
List all configured user-level provider aliases. Project-level aliases declared in `secretspec.toml` are not shown by this command.

```bash
$ secretspec config global provider list # 0.17+
```

**Example:**
```bash
$ secretspec config global provider list  # 0.17+
prod_vault  → onepassword://Production
shared      → onepassword://Shared
env         → env://
```

### config global provider remove
Remove a provider alias from your user-level configuration. To remove a project-level alias, edit the `[providers]` table in `secretspec.toml` directly.

```bash
$ secretspec config global provider remove <ALIAS> # 0.17+
```

**Arguments:**
- `<ALIAS>` - Name of the alias to remove

**Example:**
```bash
$ secretspec config global provider remove prod_vault  # 0.17+
✓ Provider alias 'prod_vault' removed
```

### config provider login
Store the [credentials](/reference/provider-credentials/) a provider alias declares. Prompts (hidden input) for each credential and writes it to its source provider at the exact location resolution reads it back from. Runs in a project, like `set` and `check`.

:::note[Version compatibility]
`config provider login` is available starting with SecretSpec 0.15. In
SecretSpec 0.14, supply provider credentials through the provider's existing
environment variables.
:::

```bash
$ secretspec config provider login <ALIAS>
```

**Arguments:**
- `<ALIAS>` - Name of the alias whose credentials to store

**Example:**
```bash
$ secretspec config provider login bws
Enter access_token for provider 'bws' (source: keyring): ****
✓ stored access_token in keyring at myproject/default/access_token

Run 'secretspec check --provider bws' to verify authentication.
```

A read-only source provider is rejected. An alias that declares no credentials reports that there is nothing to store.

### check
Check if all required secrets are available, with interactive prompting for missing secrets.

```bash
$ secretspec check [OPTIONS]
```

**Options:**
- `-p, --provider <PROVIDER>` - Provider backend to use
- `-P, --profile <PROFILE>` - Profile to use
- `-S, --scope <SCOPE>` - Resolve only a `[scopes]` subset of the profile (SecretSpec 0.17+)
- `-n, --no-prompt` - Don't prompt for missing secrets (exit with error if any are missing)
- `--json` - Print a value-free resolution report as JSON instead of prompting
- `--explain` - Print a value-free, human-readable resolution trace instead of prompting

**Example:**
```bash
$ secretspec check --profile production
✓ DATABASE_URL - Database connection string
✗ API_KEY - API key for external service (required)
# SecretSpec 0.19+: the exact write destination is shown before prompting.
Writing secret 'API_KEY' to keyring (profile: production)
  target: item=secretspec/my-app/production/API_KEY
[1/1] Enter value for API_KEY: ****
✓ Secret 'API_KEY' saved to keyring (profile: production)
```

#### Resolution report (`--json` / `--explain`)

`--json` and `--explain` report how every declared secret resolved for the
active profile without prompting and without ever printing a secret value. Both
exit non-zero when a required secret is missing, so they work as a CI gate.

`--explain` prints a human-readable trace:

```bash
$ secretspec check --profile development --explain
profile:  development
provider: keyring://
  DATABASE_URL        ok        source keyring://
  DEV_SESSION_SECRET  ok        default value
  JWT_SECRET          ok        generated
  SENTRY_DSN          missing   optional
  STRIPE_KEY          MISSING   required
```

`--json` emits a versioned, machine-readable object for tooling and CI. Each
entry reports the `status` (`resolved`, `missing_required`, `missing_optional`),
whether the value came from a provider (`source_provider`, credential-free), a
generator (`generated`), or a committed default (`default_applied`), and whether
it is exposed `as_path`. No secret values appear. The canonical JSON Schema is
committed at `schema/resolution-report.schema.json`.

```bash
$ secretspec check --profile production --json
{
  "schema_version": 1,
  "provider": "keyring://",
  "profile": "production",
  "secrets": [
    { "name": "DATABASE_URL", "status": "resolved", "required": true, "source_provider": "keyring://", "default_applied": false, "generated": false, "as_path": false },
    { "name": "STRIPE_KEY", "status": "missing_required", "required": true, "default_applied": false, "generated": false, "as_path": false }
  ]
}
```

### get
Get a secret value.

```bash
$ secretspec get [OPTIONS] <NAME>
```

**Options:**
- `-p, --provider <PROVIDER>` - Provider backend to use
- `-P, --profile <PROFILE>` - Profile to use

**Example:**
```bash
$ secretspec get DATABASE_URL --profile production
postgresql://prod.example.com/mydb
```

For a composed secret, `get` resolves its transitive dependencies and prints
the derived value. Available since SecretSpec 0.16.

### schema
Emit a single-root JSON Schema for the manifest's typed shape: by default the
union `SecretSpec` (safe for any profile); with `--profile`, that profile's exact
fields. Value-free: reads only the manifest, never a provider.

```bash
$ secretspec schema [OPTIONS]
```

**Options:**
- `-P, --profile <PROFILE>` - Emit the schema for this profile's fields instead of the union
- `-o, --output <FILE>` - Write to this file instead of stdout

Rather than ship a typed-accessor generator per language, feed this schema to
[quicktype](https://quicktype.io), which generates an idiomatic type **and**
deserializer for any language. Name the type with `--top-level`. At runtime, hand
the generated deserializer the flat `{SECRET_NAME: value}` map from the SDK's
`fields()` helper:

```bash
$ secretspec schema | quicktype -s schema --top-level SecretSpec --lang python -o secrets_gen.py
```
```python
from secretspec import SecretSpec
from secrets_gen import SecretSpec as Secrets  # quicktype-generated, typed

resolved = SecretSpec.builder().with_reason("boot").load()
s = Secrets.from_dict(resolved.fields())
print(s.database_url)   # typed str
```

The same pattern works in every SDK: Go `UnmarshalSecretSpec(resolved.FieldsJSON())`,
TypeScript `Convert.toSecretSpec(resolved.fieldsJson())`, Ruby
`SecretSpec.from_dynamic!(resolved.fields)`.

### add (0.18+)

:::caution[Version compatibility]
`add` is available starting with SecretSpec 0.18.
:::

Add a secret declaration to an existing `secretspec.toml`. This edits only the
selected profile and preserves the manifest's comments, formatting, and
unrelated tables. The new declaration follows the profile's defaults; without
a `required` profile default, it is required like any other declaration.

```bash
$ secretspec add <NAME> [--description <DESCRIPTION>] [--profile <PROFILE>] # 0.18+
```

**Arguments and options:**

- `<NAME>` - Secret name. It must be a valid identifier: letters, numbers, and
  underscores, without a leading number.
- `-d, --description <DESCRIPTION>` - Human-readable description. When omitted,
  SecretSpec prompts for it.
- `-P, --profile <PROFILE>` - Profile to edit. When omitted, SecretSpec uses the
  normal active-profile resolution, including `SECRETSPEC_PROFILE` and the
  user-global default.

```bash
$ secretspec add API_KEY --description "API access token" # 0.18+
✓ Added secret 'API_KEY' to profile 'development' in secretspec.toml
Set its value with: secretspec set API_KEY --profile development
```

`add` changes only the declaration; it never asks for or stores the secret
value. Use `secretspec set` afterward to store the value. It rejects names that
are already available in the selected profile, including declarations inherited
from `default` or an extended manifest.

### set
Set a secret value.

```bash
$ secretspec set [OPTIONS] <NAME> [VALUE]
```

**Options:**
- `-p, --provider <PROVIDER>` - Provider backend to use
- `-P, --profile <PROFILE>` - Profile to use

**Example:**
```bash
$ secretspec set API_KEY sk-1234567890 --profile production --provider sops://secrets.enc.yaml
# SecretSpec 0.19+:
Writing secret 'API_KEY' to sops://secrets.enc.yaml?format=yaml (profile: production)
  target: /work/my-app/secrets.enc.yaml ["my-app"]["production"]["API_KEY"]
✓ Secret 'API_KEY' saved to sops (profile: production)
```

In SecretSpec 0.19+, `set` shows the resolved provider, profile, and native
write target before reading a piped value or opening the password prompt. For
SOPS this includes the exact encrypted file and `sops set` selector, making a
missing `--profile` visible before the write.

`set` rejects composed secrets because their values are derived and read-only.
Available since SecretSpec 0.16.

### delete (0.18+)

:::caution[Version compatibility]
`delete` is available starting with SecretSpec 0.18.
:::

Delete stored provider values without changing their declarations in
`secretspec.toml`.

```bash
$ secretspec delete <NAME>... [--provider <PROVIDER>] [--profile <PROFILE>]

$ secretspec delete --all [--yes] [--provider <PROVIDER>] [--profile <PROFILE>]
```

**Arguments and options:**

- `<NAME>...` - One or more declared secrets to delete.
- `--all` - Delete every provider-backed secret declared in the active profile.
  It cannot be combined with a name.
- `-y, --yes` - Skip the interactive confirmation for `--all`. Non-interactive
  use of `--all` requires this option.
- `-p, --provider <PROVIDER>` - Delete from this provider instead of the
  manifest's primary write provider.
- `-P, --profile <PROFILE>` - Profile whose values are addressed.

```bash
# Delete one value from its primary write provider
$ secretspec delete API_KEY
Deleted 'API_KEY'
Deleted 1 secret value; 0 already absent

# Delete selected values from an old dotenv provider
$ secretspec delete API_KEY DATABASE_URL --provider dotenv://.env.old

# Explicitly delete every stored value in production
$ secretspec delete --all --profile production --yes
```

Deletion is idempotent: an already-absent value is reported as such and does
not fail the command. Without `--provider`, routing mirrors `set`: only the
primary write provider is changed, never every provider in a fallback chain.
Any cache entry declared for the secret is invalidated so it cannot continue to
serve the deleted value.

The providers that support deletion in 0.18 are keyring, dotenv, pass, gopass,
Vault, OpenBao, and Keeper Secrets Manager. Other providers return an explicit
unsupported-operation error. Vault, OpenBao, and Keeper refuse to delete native
`ref` entries because their backends would have to destroy a whole externally
managed path or record rather than only the referenced field.

### run
Run a command with secrets injected as environment variables.

```bash
$ secretspec run [OPTIONS] -- <COMMAND>
```

**Options:**
- `-p, --provider <PROVIDER>` - Provider backend to use
- `-P, --profile <PROFILE>` - Profile to use
- `-S, --scope <SCOPE>` - Inject only a `[scopes]` subset of the profile (SecretSpec 0.17+)

**Examples:**
```bash
# Run npm with secrets available as environment variables
$ secretspec run --profile production -- npm run deploy

# Verify secrets are injected
$ secretspec run -- env | grep DATABASE_URL
DATABASE_URL=postgresql://localhost/mydb

# Inject only the `api` scope's secrets (SecretSpec 0.17+); secrets the
# scope excludes are removed from the child even if the parent exported them
$ secretspec run --scope api -- ./api-server
```

SecretSpec 0.19+ can securely request a declared missing value before the child
starts. The selected provider normally saves the answer; choose `null` when it
must be ephemeral:

```toml title="secretspec.toml"
[profiles.default]
DEPLOY_PASSWORD = { description = "One-time deployment password", required = true, prompt = true, providers = ["null"] }
```

```bash
$ secretspec run -- ./deploy
? Enter value for DEPLOY_PASSWORD (profile: default):
```

The hidden prompt reads from the controlling terminal, leaving the child's
stdin unchanged even when it is piped or redirected. The answer is injected
only for that invocation when the provider is `null`; writable providers save
it and make the prompt a first-use provisioning step. If no controlling
terminal exists, `run` fails before starting the child. Only declarations with
`prompt = true` opt into this behavior; ordinary missing secrets still fail
without a prompt.

The `--provider` override applies to every secret, including those with a
[`ref`](/reference/configuration/#secret-references) field: refs are redirected
to the overriding provider just like convention secrets. This makes it easy to
point refs at fixtures during tests without editing the manifest:

```bash
# Resolve every secret, refs included, from a fixtures file
$ secretspec run --provider dotenv:.env.fixtures -- cargo test
```

:::note[Shell Variable Expansion]
Variables like `$DATABASE_URL` in the command line are expanded by your **shell before** secretspec runs. To use injected secrets in the command itself, wrap it in a subshell:

```bash
# This won't work - $DATABASE_URL is expanded before secretspec runs
$ secretspec run -- echo $DATABASE_URL
# Output: (empty, because DATABASE_URL isn't set in current shell)

# This works - variable expansion happens in the subprocess
$ secretspec run -- sh -c 'echo $DATABASE_URL'
# Output: postgresql://localhost/mydb
```

For most use cases, simply run your application and it will read secrets from its environment:
```bash
$ secretspec run -- node app.js  # app.js reads process.env.DATABASE_URL
```
:::

### export
Resolve every secret for the active profile and write it to stdout in a chosen format, without running a command. Unlike `run`, it never prompts and exits non-zero when a required secret is missing, so CI can gate on it.

```bash
$ secretspec export [OPTIONS]
```

Options are `-p, --provider <PROVIDER>`, `-P, --profile <PROFILE>`, `-S, --scope <SCOPE>` (a `[scopes]` subset of the profile, SecretSpec 0.17+), and `--format <FORMAT>` (default `shell`).

Unlike [`run --scope`](#run), `export --scope` only emits the scoped subset; it
unsets nothing, because no output format can express an unset. A shell that
already holds a wider set keeps those values after a scoped `export`, so use
`run --scope` when the point is to narrow an existing environment.

| Format | Output |
|--------|--------|
| `shell` | `export KEY='value'` lines, ready for `eval "$(secretspec export)"` |
| `dotenv` | `KEY="value"` lines in dotenv syntax (double-quoted, with `\`, `"`, `$`, and newline escaped) |
| `json` | a single compact JSON object mapping each secret name to its value |
| `gha` | appends `KEY=value` to the file named by `$GITHUB_ENV` and prints an `::add-mask::` command per value to stdout, so later workflow steps and third-party actions see the secrets |

```bash
# Load secrets into the current shell
$ eval "$(secretspec export --profile production)"

# Emit JSON for another tool to consume
$ secretspec export --profile production --format json
{"DATABASE_URL":"postgresql://prod.example.com/mydb"}
```

The `gha` format targets a `secretspec export --format gha` step in a GitHub or Forgejo Actions job: it masks the values in the runner log and persists them to the job environment for the steps that follow.

### import
Import secrets from one provider to another.

```bash
$ secretspec import <FROM_PROVIDER> [--delete-source]
```

The destination provider and profile are determined from your configuration. Secrets that already exist in the destination provider will not be overwritten.

In SecretSpec 0.19+, the source and destination resolve their addresses
independently. A source alias can use its own [provider `ref` template or
per-secret scoped ref](/concepts/references/#different-coordinates-per-provider-019),
while the destination uses its selected alias's mapping.

Also in SecretSpec 0.19+, a literal source remains convention-addressed, but
`import` warns when it shares a storage container with a defined alias whose
template or active scoped refs resolve any imported secret to a different
entry. The warning is informational: keep the literal to migrate
convention-named entries, or select the alias when its alias-specific
coordinates describe the intended source. Import output retains the selected
alias name alongside its resolved, credential-free provider URI.

**Arguments:**
- `<FROM_PROVIDER>` - Provider to import from (e.g., `env`, `dotenv:/path/to/.env`)
- `--delete-source` - After copying, delete a source value only when the
  destination is verified to contain the same value. Available in SecretSpec
  0.18+.

**Example:**
```bash
# Import from environment variables to your default provider
$ secretspec import env
Importing secrets from env to keyring (profile: development)...

✓ DATABASE_URL - Database connection string
○ API_KEY - API key for external service (already exists in target)
✗ REDIS_URL - Redis connection URL (not found in source)

Summary: 1 imported, 1 already exists, 1 not found in source

# Import from a specific .env file
$ secretspec import dotenv:/home/user/old-project/.env

# Move values out of an old provider (SecretSpec 0.18+)
$ secretspec import dotenv:/home/user/old-project/.env --delete-source
```

**Use Cases:**
- Migrate from .env files to a secure provider like keyring or 1Password
- Copy secrets between different profiles or projects
- Import existing environment variables into SecretSpec management

`import` skips composed secrets because they have no stored value to copy; their
component secrets are imported normally. Available since SecretSpec 0.16.

With `--delete-source`, source and destination must resolve to different
physical entries. In SecretSpec 0.19+, distinct scoped refs in the same store
are allowed. SecretSpec preflights every source and destination, performs all
writes, reads back and validates every copied value, and only then begins
source cleanup. If a destination already contains an identical value, the
source is also safe to delete; if it differs, SecretSpec retains the source and
reports the conflict. A source provider that does not support deletion fails
explicitly instead of pretending the migration completed. Source deletion was
introduced in SecretSpec 0.18; independent endpoint refs and operation-wide
preflight are available in 0.19+.

### cache clear (0.17+)

:::caution[Version compatibility]
`cache clear` is available starting with SecretSpec 0.17.
:::

Delete cached provider values for one secret, or for every cached secret in the
active profile. Authoritative fallback providers are not modified.

```bash
$ secretspec cache clear [NAME] [--profile <PROFILE>]
```

**Arguments and options:**

- `[NAME]` - Cached secret to clear. Omit it to clear all cached secrets in the
  profile.
- `-P, --profile <PROFILE>` - Profile whose logical cache entries are cleared.

The reported count is the number of entries that were actually removed, so a
profile with nothing cached reports `Cleared 0 cache entries`. `--provider` and
`SECRETSPEC_PROVIDER` are ignored: clearing always addresses the cache of the
route the manifest declares. When one cache store cannot be cleared, the
remaining secrets are still cleared and the command then reports what failed.

```bash
# Force the next API_KEY read through its authoritative fallback route
$ secretspec cache clear API_KEY
Cleared 1 cache entry

# Clear every cached secret in production
$ secretspec cache clear --profile production
Cleared 4 cache entries
```

See [Provider caching](/concepts/providers/caching/)
for configuration and resolution behavior.

### audit

Show the local [audit log](/concepts/audit/) of secret access.

```bash
$ secretspec audit [--project <NAME>] [--action <ACTION>] [-n <N>] [--json]
```

**Options:**
- `--project <NAME>` - Only show entries for this project
- `--action <ACTION>` - Only show entries for this action (`get`, `set`, `check`, `run`, `import`, `export`, `cache_clear` and `cache_refresh` in 0.17+, or `delete` in 0.18+)
- `-n, --tail <N>` - Show only the last N entries
- `--json` - Output raw JSON Lines instead of the formatted summary

The log location is read from your user-global config (`[audit]` in `~/.config/secretspec/config.toml`), defaulting to the per-user state directory.

**Example:**
```bash
$ secretspec audit --action run -n 5
2026-06-04T18:06:29Z  run    found  ./deploy.sh  API_KEY,DATABASE_URL  (my-app/production)  reason: deploy  [claude-code]

# Pipe raw entries to jq
$ secretspec audit --json | jq 'select(.outcome == "missing")'
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SECRETSPEC_PROFILE` | Default profile to use |
| `SECRETSPEC_PROVIDER` | Default provider to use |
| `SECRETSPEC_FILE` | Path to `secretspec.toml` (same as `--file`) |
| `SECRETSPEC_REASON` | Reason for accessing secrets (same as `--reason`) |

## Quick Start Workflow

```bash
# Initialize from existing .env
$ secretspec init --from .env

# Set up user-global defaults (0.17+)
$ secretspec config global init

# Import existing secrets (optional)
$ secretspec import env  # or: secretspec import dotenv:.env.old

# Check and set missing secrets
$ secretspec check

# Run your application
$ secretspec run -- npm start
```
