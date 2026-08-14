---
title: CLI Commands Reference
description: Complete reference for Monosecret CLI commands
---

The Monosecret CLI provides commands for managing secrets across different providers and profiles.

## Global Options

These options are available on every command:

| Option              | Description                                                                                                                                                                                  |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-f, --file <FILE>` | Path to `monosecret.toml` (default: auto-detect). Env: `MONOSECRET_FILE`                                                                                                                     |
| `--reason <REASON>` | Reason for accessing secrets, recorded by providers that support audit logging (e.g. Proton Pass agent sessions). Takes precedence over `PROTON_PASS_AGENT_REASON`. Env: `MONOSECRET_REASON` |

```bash
$ monosecret run --reason "Deploying web frontend" -- ./deploy.sh
```

## Commands

### init

Initialize a new `monosecret.toml` from declarations discovered in a provider.
Dotenv files are supported in every current release. Monosecret 0.2+ accepts
any provider that implements reflection, including age files, AWS Parameter
Store, and Bitwarden Password Manager vaults.

```bash
$ monosecret init [--from <PROVIDER>] [--project <PROJECT>] [--profile <PROFILE>]
```

**Options:**

- `--from <PROVIDER>` - Provider URI to discover (default: `dotenv://.env`);
  use a `dotenv://` URI for dotenv files
- `--project <PROJECT>` - Project used to render the provider namespace
  (Monosecret 0.2+; default: current directory name)
- `-P, --profile <PROFILE>` - Profile used to render the provider namespace
  and written to the manifest (Monosecret 0.2+; default: `default`)

Reflection creates declarations only: values are never written to the
manifest. Configure the discovered provider as the profile's source to keep
using it, or run `monosecret import` afterward to copy the declared values to a
different destination.

**Examples:**

```bash
$ monosecret init --from dotenv://.env.example
✓ Created monosecret.toml with 5 secrets

# Monosecret 0.2+: discover one rendered Parameter Store hierarchy
$ monosecret init \
    --from 'awsps://us-east-1?template=/{profile}/{project}/{key}' \
    --project payments \
    --profile production
✓ Created monosecret.toml with 12 secrets

# Monosecret 0.2+: discover items in one Bitwarden collection
$ monosecret init --from 'bw://dev-secrets?type=login'
✓ Created monosecret.toml with 8 secrets
```

### config global init

Initialize user-global configuration. The explicit `global` namespace is
available in Monosecret 0.2+; without options, the command prompts for the
provider and profile.

```bash
$ monosecret config global init [--provider <PROVIDER>] [--profile <PROFILE>] # 0.2+
```

Monosecret 0.2+ accepts `--provider` and `--profile` so installations can save
both defaults without interaction. Each omitted option still prompts; use
`--profile none` to clear the saved default profile. The corresponding
`MONOSECRET_PROVIDER` and `MONOSECRET_PROFILE` environment variables are also
accepted. Project requirements remain in `monosecret.toml`; the namespace makes
it clear that this command writes user-wide defaults. The legacy
`monosecret config init` spelling remains supported as a hidden alias.

**Example:**

```bash
$ monosecret config global init  # 0.2+
? Select your preferred provider backend:
> keyring: System keychain
? Select your default profile:
> development
✓ Configuration saved to ~/.config/monosecret/config.toml
```

```bash
# Monosecret 0.2+: save both defaults without prompting
$ monosecret config global init --provider env --profile default
✓ Configuration saved to ~/.config/monosecret/config.toml
```

### config global show

Display current user-global configuration. The explicit namespace is available
in Monosecret 0.2+; `monosecret config show` remains a hidden alias.

```bash
$ monosecret config global show # 0.2+
```

**Example:**

```bash
$ monosecret config global show  # 0.2+
Provider: keyring
Profile:  development
```

### config global provider add

Add a provider alias to your user-level configuration (`~/.config/monosecret/config.toml`).

To share aliases with your team, declare them in a top-level `[providers]` table in `monosecret.toml` instead — they take precedence over user-level aliases on name conflict.

:::note[Version compatibility]
Monosecret 0.1 supports adding aliases with `<ALIAS>` and `<URI>`.
The `--credential` option is available starting with Monosecret 0.2.
The explicit `global` namespace is available starting with Monosecret 0.2;
the legacy `config provider add` spelling remains a hidden alias.
:::

```bash
$ monosecret config global provider add <ALIAS> <URI> [--credential NAME=PROVIDER]... # 0.2+
```

**Arguments:**

- `<ALIAS>` - Short name for the provider (e.g., `prod_vault`, `shared`)
- `<URI>` - Provider URI (e.g., `onepassword://Production`, `env://`)

**Options:**

- `--credential <NAME=PROVIDER>` - Declare a [provider credential](/reference/provider-credentials/) and its source. `NAME` is semantic and provider-specific, such as `access_token` or `role_id`. Repeatable. Only the bare-string source form is expressible on the command line; add a `ref` by editing the config.

**Example:**

```bash
$ monosecret config global provider add prod_vault "onepassword://Production" # 0.2+
✓ Provider alias 'prod_vault' added: 'onepassword://Production'

$ monosecret config global provider add bws "bws://project-uuid" --credential access_token=keyring # 0.2+
✓ Provider alias 'bws' added: 'bws://project-uuid'
  credentials: access_token=keyring
  run 'monosecret config provider login bws' to store the credentials
```

### config global provider list

List all configured user-level provider aliases. Project-level aliases declared in `monosecret.toml` are not shown by this command.

```bash
$ monosecret config global provider list # 0.2+
```

**Example:**

```bash
$ monosecret config global provider list  # 0.2+
prod_vault  → onepassword://Production
shared      → onepassword://Shared
env         → env://
```

### config global provider remove

Remove a provider alias from your user-level configuration. To remove a project-level alias, edit the `[providers]` table in `monosecret.toml` directly.

```bash
$ monosecret config global provider remove <ALIAS> # 0.2+
```

**Arguments:**

- `<ALIAS>` - Name of the alias to remove

**Example:**

```bash
$ monosecret config global provider remove prod_vault  # 0.2+
✓ Provider alias 'prod_vault' removed
```

### config provider login

Store the [credentials](/reference/provider-credentials/) a provider alias declares. Prompts (hidden input) for each credential and writes it to its source provider at the exact location resolution reads it back from. Runs in a project, like `set` and `check`.

:::note[Version compatibility]
`config provider login` is available starting with Monosecret 0.2. In
Monosecret 0.1, supply provider credentials through the provider's existing
environment variables.
:::

```bash
$ monosecret config provider login <ALIAS>
```

**Arguments:**

- `<ALIAS>` - Name of the alias whose credentials to store

**Example:**

```bash
$ monosecret config provider login bws
Enter access_token for provider 'bws' (source: keyring): ****
✓ stored access_token in keyring at myproject/default/access_token

Run 'monosecret check --provider bws' to verify authentication.
```

A read-only source provider is rejected. An alias that declares no credentials reports that there is nothing to store.

### check

Check if all required secrets are available, with interactive prompting for missing secrets.

```bash
$ monosecret check [OPTIONS]
```

**Options:**

- `-p, --provider <PROVIDER>` - Provider backend to use
- `-P, --profile <PROFILE>` - Profile to use
- `-S, --scope <SCOPE>` - Resolve only a `[scopes]` subset of the profile (Monosecret 0.2+)
- `-n, --no-prompt` - Don't prompt for missing secrets (exit with error if any are missing)
- `--json` - Print a value-free resolution report as JSON instead of prompting
- `--explain` - Print a value-free, human-readable resolution trace instead of prompting

**Example:**

```bash
$ monosecret check --profile production
✓ DATABASE_URL - Database connection string
✗ API_KEY - API key for external service (required)
# Monosecret 0.2+: the exact write destination is shown before prompting.
Writing secret 'API_KEY' to keyring (profile: production)
  target: item=monosecret/my-app/production/API_KEY
[1/1] Enter value for API_KEY: ****
✓ Secret 'API_KEY' saved to keyring (profile: production)
```

#### Resolution report (`--json` / `--explain`)

`--json` and `--explain` report how every declared secret resolved for the
active profile without prompting and without ever printing a secret value. Both
exit non-zero when a required secret is missing, so they work as a CI gate.

`--explain` prints a human-readable trace:

```bash
$ monosecret check --profile development --explain
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
$ monosecret check --profile production --json
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
$ monosecret get [OPTIONS] <NAME>
```

**Options:**

- `-p, --provider <PROVIDER>` - Provider backend to use
- `-P, --profile <PROFILE>` - Profile to use

**Example:**

```bash
$ monosecret get DATABASE_URL --profile production
postgresql://prod.example.com/mydb
```

For a composed secret, `get` resolves its transitive dependencies and prints
the derived value. Available since Monosecret 0.2.

### schema

Emit a single-root JSON Schema for the manifest's typed shape: by default the
union `Monosecret` (safe for any profile); with `--profile`, that profile's exact
fields. Value-free: reads only the manifest, never a provider.

```bash
$ monosecret schema [OPTIONS]
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
$ monosecret schema | quicktype -s schema --top-level Monosecret --lang python -o secrets_gen.py
```

```python
from monosecret import Monosecret
from secrets_gen import Monosecret as Secrets  # quicktype-generated, typed

resolved = Monosecret.builder().with_reason("boot").load()
s = Secrets.from_dict(resolved.fields())
print(s.database_url)   # typed str
```

The same pattern works in every SDK: Go `UnmarshalMonosecret(resolved.FieldsJSON())`,
TypeScript `Convert.toMonosecret(resolved.fieldsJson())`, Ruby
`Monosecret.from_dynamic!(resolved.fields)`.

### add (0.2+)

:::caution[Version compatibility]
`add` is available starting with Monosecret 0.2.
:::

Add a secret declaration to an existing `monosecret.toml`. This edits only the
selected profile and preserves the manifest's comments, formatting, and
unrelated tables. The new declaration follows the profile's defaults; without
a `required` profile default, it is required like any other declaration.

```bash
$ monosecret add <NAME> [--description <DESCRIPTION>] [--profile <PROFILE>] # 0.2+
```

**Arguments and options:**

- `<NAME>` - Secret name. It must be a valid identifier: letters, numbers, and
  underscores, without a leading number.
- `-d, --description <DESCRIPTION>` - Human-readable description. When omitted,
  Monosecret prompts for it.
- `-P, --profile <PROFILE>` - Profile to edit. When omitted, Monosecret uses the
  normal active-profile resolution, including `MONOSECRET_PROFILE` and the
  user-global default.

```bash
$ monosecret add API_KEY --description "API access token" # 0.2+
✓ Added secret 'API_KEY' to profile 'development' in monosecret.toml
Set its value with: monosecret set API_KEY --profile development
```

`add` changes only the declaration; it never asks for or stores the secret
value. Use `monosecret set` afterward to store the value. It rejects names that
are already available in the selected profile, including declarations inherited
from `default` or an extended manifest.

### set

Set a secret value.

```bash
$ monosecret set [OPTIONS] <NAME> [VALUE]
```

**Options:**

- `-p, --provider <PROVIDER>` - Provider backend to use
- `-P, --profile <PROFILE>` - Profile to use

**Example:**

```bash
$ monosecret set API_KEY sk-1234567890 --profile production --provider sops://secrets.enc.yaml
# Monosecret 0.2+:
Writing secret 'API_KEY' to sops://secrets.enc.yaml?format=yaml (profile: production)
  target: /work/my-app/secrets.enc.yaml ["my-app"]["production"]["API_KEY"]
✓ Secret 'API_KEY' saved to sops (profile: production)
```

In Monosecret 0.2+, `set` shows the resolved provider, profile, and native
write target before reading a piped value or opening the password prompt. For
SOPS this includes the exact encrypted file and `sops set` selector, making a
missing `--profile` visible before the write.

`set` rejects composed secrets because their values are derived and read-only.
Available since Monosecret 0.2.

### delete (0.2+)

:::caution[Version compatibility]
`delete` is available starting with Monosecret 0.2.
:::

Delete stored provider values without changing their declarations in
`monosecret.toml`.

```bash
$ monosecret delete <NAME>... [--provider <PROVIDER>] [--profile <PROFILE>]

$ monosecret delete --all [--yes] [--provider <PROVIDER>] [--profile <PROFILE>]
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
$ monosecret delete API_KEY
Deleted 'API_KEY'
Deleted 1 secret value; 0 already absent

# Delete selected values from an old dotenv provider
$ monosecret delete API_KEY DATABASE_URL --provider dotenv://.env.old

# Explicitly delete every stored value in production
$ monosecret delete --all --profile production --yes
```

Deletion is idempotent: an already-absent value is reported as such and does
not fail the command. Without `--provider`, routing mirrors `set`: only the
primary write provider is changed, never every provider in a fallback chain.
Any cache entry declared for the secret is invalidated so it cannot continue to
serve the deleted value.

The providers that support deletion in 0.2 are keyring, dotenv, pass, gopass,
Vault, OpenBao, and Keeper Secrets Manager. Other providers return an explicit
unsupported-operation error. Vault, OpenBao, and Keeper refuse to delete native
`ref` entries because their backends would have to destroy a whole externally
managed path or record rather than only the referenced field.

### run

Run a command with secrets injected as environment variables.

```bash
$ monosecret run [OPTIONS] -- <COMMAND>
```

**Options:**

- `-p, --provider <PROVIDER>` - Provider backend to use
- `-P, --profile <PROFILE>` - Profile to use
- `-S, --scope <SCOPE>` - Inject only a `[scopes]` subset of the profile (Monosecret 0.2+)

**Examples:**

```bash
# Run npm with secrets available as environment variables
$ monosecret run --profile production -- npm run deploy

# Verify secrets are injected
$ monosecret run -- env | grep DATABASE_URL
DATABASE_URL=postgresql://localhost/mydb

# Inject only the `api` scope's secrets (Monosecret 0.2+); secrets the
# scope excludes are removed from the child even if the parent exported them
$ monosecret run --scope api -- ./api-server
```

Monosecret 0.2+ can securely request a declared missing value before the child
starts. The selected provider normally saves the answer; choose `null` when it
must be ephemeral:

```toml title="monosecret.toml"
[profiles.default]
DEPLOY_PASSWORD = { description = "One-time deployment password", required = true, prompt = true, providers = [
  "null",
] }
```

```bash
$ monosecret run -- ./deploy
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
$ monosecret run --provider dotenv:.env.fixtures -- cargo test
```

:::note[Shell Variable Expansion]
Variables like `$DATABASE_URL` in the command line are expanded by your **shell before** monosecret runs. To use injected secrets in the command itself, wrap it in a subshell:

```bash
# This won't work - $DATABASE_URL is expanded before monosecret runs
$ monosecret run -- echo $DATABASE_URL
# Output: (empty, because DATABASE_URL isn't set in current shell)

# This works - variable expansion happens in the subprocess
$ monosecret run -- sh -c 'echo $DATABASE_URL'
# Output: postgresql://localhost/mydb
```

For most use cases, simply run your application and it will read secrets from its environment:

```bash
$ monosecret run -- node app.js  # app.js reads process.env.DATABASE_URL
```

:::

### export

Resolve every secret for the active profile and write it to stdout in a chosen format, without running a command. Unlike `run`, it never prompts and exits non-zero when a required secret is missing, so CI can gate on it.

```bash
$ monosecret export [OPTIONS]
```

Options are `-p, --provider <PROVIDER>`, `-P, --profile <PROFILE>`, `-S, --scope <SCOPE>` (a `[scopes]` subset of the profile, Monosecret 0.2+), and `--format <FORMAT>` (default `shell`).

Unlike [`run --scope`](#run), `export --scope` only emits the scoped subset; it
unsets nothing, because no output format can express an unset. A shell that
already holds a wider set keeps those values after a scoped `export`, so use
`run --scope` when the point is to narrow an existing environment.

| Format   | Output                                                                                                                                                                           |
| -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `shell`  | `export KEY='value'` lines, ready for `eval "$(monosecret export)"`                                                                                                              |
| `dotenv` | `KEY="value"` lines in dotenv syntax (double-quoted, with `\`, `"`, `$`, and newline escaped)                                                                                    |
| `json`   | a single compact JSON object mapping each secret name to its value                                                                                                               |
| `gha`    | appends `KEY=value` to the file named by `$GITHUB_ENV` and prints an `::add-mask::` command per value to stdout, so later workflow steps and third-party actions see the secrets |

```bash
# Load secrets into the current shell
$ eval "$(monosecret export --profile production)"

# Emit JSON for another tool to consume
$ monosecret export --profile production --format json
{"DATABASE_URL":"postgresql://prod.example.com/mydb"}
```

The `gha` format targets a `monosecret export --format gha` step in a GitHub or Forgejo Actions job: it masks the values in the runner log and persists them to the job environment for the steps that follow.

### import

Import secrets from one provider to another.

```bash
$ monosecret import <FROM_PROVIDER> [--delete-source]
```

The destination provider and profile are determined from your configuration. Secrets that already exist in the destination provider will not be overwritten.

In Monosecret 0.2+, the source and destination resolve their addresses
independently. A source alias can use its own [provider `ref` template or
per-secret scoped ref](/concepts/references/#different-coordinates-per-provider-019),
while the destination uses its selected alias's mapping.

Also in Monosecret 0.2+, a literal source remains convention-addressed, but
`import` warns when it shares a storage container with a defined alias whose
template or active scoped refs resolve any imported secret to a different
entry. The warning is informational: keep the literal to migrate
convention-named entries, or select the alias when its alias-specific
coordinates describe the intended source. Import output retains the selected
alias name alongside its resolved, credential-free provider URI.

**Arguments:**

- `<FROM_PROVIDER>` - Provider to import from (e.g., `env`, `dotenv:/path/to/.env`)
- `--delete-source` - After copying, delete a source value only when the
  destination is verified to contain the same value. Available in Monosecret
  0.2+.

**Example:**

```bash
# Import from environment variables to your default provider
$ monosecret import env
Importing secrets from env to keyring (profile: development)...

✓ DATABASE_URL - Database connection string
○ API_KEY - API key for external service (already exists in target)
✗ REDIS_URL - Redis connection URL (not found in source)

Summary: 1 imported, 1 already exists, 1 not found in source

# Import from a specific .env file
$ monosecret import dotenv:/home/user/old-project/.env

# Move values out of an old provider (Monosecret 0.2+)
$ monosecret import dotenv:/home/user/old-project/.env --delete-source
```

**Use Cases:**

- Migrate from .env files to a secure provider like keyring or 1Password
- Copy secrets between different profiles or projects
- Import existing environment variables into Monosecret management

`import` skips composed secrets because they have no stored value to copy; their
component secrets are imported normally. Available since Monosecret 0.2.

With `--delete-source`, source and destination must resolve to different
physical entries. In Monosecret 0.2+, distinct scoped refs in the same store
are allowed. Monosecret preflights every source and destination, performs all
writes, reads back and validates every copied value, and only then begins
source cleanup. If a destination already contains an identical value, the
source is also safe to delete; if it differs, Monosecret retains the source and
reports the conflict. A source provider that does not support deletion fails
explicitly instead of pretending the migration completed. Source deletion was
introduced in Monosecret 0.2; independent endpoint refs and operation-wide
preflight are available in 0.2+.

### cache clear (0.2+)

:::caution[Version compatibility]
`cache clear` is available starting with Monosecret 0.2.
:::

Delete cached provider values for one secret, or for every cached secret in the
active profile. Authoritative fallback providers are not modified.

```bash
$ monosecret cache clear [NAME] [--profile <PROFILE>]
```

**Arguments and options:**

- `[NAME]` - Cached secret to clear. Omit it to clear all cached secrets in the
  profile.
- `-P, --profile <PROFILE>` - Profile whose logical cache entries are cleared.

The reported count is the number of entries that were actually removed, so a
profile with nothing cached reports `Cleared 0 cache entries`. `--provider` and
`MONOSECRET_PROVIDER` are ignored: clearing always addresses the cache of the
route the manifest declares. When one cache store cannot be cleared, the
remaining secrets are still cleared and the command then reports what failed.

```bash
# Force the next API_KEY read through its authoritative fallback route
$ monosecret cache clear API_KEY
Cleared 1 cache entry

# Clear every cached secret in production
$ monosecret cache clear --profile production
Cleared 4 cache entries
```

See [Provider caching](/concepts/providers/caching/)
for configuration and resolution behavior.

### audit

Show the local [audit log](/concepts/audit/) of secret access.

```bash
$ monosecret audit [--project <NAME>] [--action <ACTION>] [-n <N>] [--json]
```

**Options:**

- `--project <NAME>` - Only show entries for this project
- `--action <ACTION>` - Only show entries for this action (`get`, `set`, `check`, `run`, `import`, `export`, `cache_clear` and `cache_refresh` in 0.2+, or `delete` in 0.2+)
- `-n, --tail <N>` - Show only the last N entries
- `--json` - Output raw JSON Lines instead of the formatted summary

The log location is read from your user-global config (`[audit]` in `~/.config/monosecret/config.toml`), defaulting to the per-user state directory.

**Example:**

```bash
$ monosecret audit --action run -n 5
2026-06-04T18:06:29Z  run    found  ./deploy.sh  API_KEY,DATABASE_URL  (my-app/production)  reason: deploy  [claude-code]

# Pipe raw entries to jq
$ monosecret audit --json | jq 'select(.outcome == "missing")'
```

## Environment Variables

| Variable              | Description                                       |
| --------------------- | ------------------------------------------------- |
| `MONOSECRET_PROFILE`  | Default profile to use                            |
| `MONOSECRET_PROVIDER` | Default provider to use                           |
| `MONOSECRET_FILE`     | Path to `monosecret.toml` (same as `--file`)      |
| `MONOSECRET_REASON`   | Reason for accessing secrets (same as `--reason`) |

## Quick Start Workflow

```bash
# Initialize from existing .env
$ monosecret init --from .env

# Set up user-global defaults (0.2+)
$ monosecret config global init

# Import existing secrets (optional)
$ monosecret import env  # or: monosecret import dotenv:.env.old

# Check and set missing secrets
$ monosecret check

# Run your application
$ monosecret run -- npm start
```
