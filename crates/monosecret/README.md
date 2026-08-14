<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="monosecret-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="monosecret.png">
    <img src="monosecret.png" alt="Monosecret logo" width="420">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/ifiokjr/monosecret/actions"><img src="https://img.shields.io/github/check-runs/ifiokjr/monosecret/main" alt="Build Status"></a>
  <a href="https://crates.io/crates/monosecret"><img src="https://img.shields.io/crates/v/monosecret" alt="Crates.io"></a>
  <a href="https://docs.rs/monosecret"><img src="https://docs.rs/monosecret/badge.svg" alt="docs.rs"></a>
  <a href="https://discord.gg/naMgvexb6q"><img src="https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fdiscord.com%2Fapi%2Finvites%2FnaMgvexb6q%3Fwith_counts%3Dtrue&amp;query=%24.approximate_member_count&amp;logo=discord&amp;logoColor=white&amp;label=Discord%20users&amp;color=green&amp;style=flat" alt="Discord users"></a>
</p>

Stop committing secrets to git and putting them to .env files.

Secrets end up in `.env` files that get accidentally committed, shared over Slack, or copy pasted between machines. Each developer has their own version, nobody knows which secrets are actually needed, and onboarding means asking around for values.

Monosecret fixes this by separating secret **declaration** from secret **storage**. You commit a `monosecret.toml` that declares what secrets your application needs, while the actual values live in a secure provider like your system keyring, 1Password, or any other backend. No secrets in git, no `.env` files to leak.

[Documentation](https://monosecret.dev) | [Quick Start](https://monosecret.dev/quick-start) | [Announcement Blog Post](https://devenv.sh/blog/2025/07/21/announcing-monosecret-declarative-secrets-management)

## Features

- **[Declarative Configuration](https://monosecret.dev/reference/configuration/)**: Define your secrets in `monosecret.toml` with descriptions and requirements
- **[Multiple Provider Backends](https://monosecret.dev/concepts/providers/)**:
  - [Keyring](https://monosecret.dev/providers/keyring)
  - [KeePass KDBX](https://monosecret.dev/providers/kdbx) (0.17+)
  - [.env](https://monosecret.dev/providers/dotenv)
  - [plaintext files](https://monosecret.dev/providers/file) (0.19+)
  - [1Password](https://monosecret.dev/providers/onepassword)
  - [Keeper Secrets Manager](https://monosecret.dev/providers/keeper) (0.18+)
  - [LastPass](https://monosecret.dev/providers/lastpass)
  - [Dashlane](https://monosecret.dev/providers/dashlane) (0.18+)
  - [Pass](https://monosecret.dev/providers/pass)
  - [Gopass](https://monosecret.dev/providers/gopass) (0.15+)
  - [Proton Pass](https://monosecret.dev/providers/protonpass)
  - [Passbolt](https://monosecret.dev/providers/passbolt) (0.19+)
  - [environment variables](https://monosecret.dev/providers/env)
  - [null](https://monosecret.dev/providers/null) (0.19+)
  - [systemd credentials](https://monosecret.dev/providers/systemd-credential) (0.17+)
  - [Google Cloud Secret Manager](https://monosecret.dev/providers/gcsm)
  - [AWS Secrets Manager](https://monosecret.dev/providers/awssm)
  - [AWS Systems Manager Parameter Store](https://monosecret.dev/providers/awsps) (0.18+)
  - [Scaleway Secret Manager](https://monosecret.dev/providers/scaleway) (0.17+)
  - [Vault](https://monosecret.dev/providers/vault)
  - [OpenBao](https://monosecret.dev/providers/openbao) (0.17+)
  - [Bitwarden Password Manager](https://monosecret.dev/providers/bw) (0.18+)
  - [Bitwarden Secrets Manager](https://monosecret.dev/providers/bws) (official `bws` CLI required in Monosecret 0.17+)
  - [Azure Key Vault](https://monosecret.dev/providers/akv)
  - [Infisical](https://monosecret.dev/providers/infisical) (0.16+)
  - [age](https://monosecret.dev/providers/age) (0.17+)
  - [SOPS](https://monosecret.dev/providers/sops) (0.17+)
- **[Type-Safe Rust SDK](https://monosecret.dev/sdk/rust/)**: Generate strongly-typed structs from your `monosecret.toml` for compile-time safety
- **[Profile Support](https://monosecret.dev/concepts/profiles/)**: Override secret requirements and defaults per profile (development, production, etc.)
- **[Secret Generation](https://monosecret.dev/concepts/generation/)**: Auto-generate passwords, tokens, UUIDs, and more when secrets are missing — declarative "generate if absent"
- **Run prompts (0.19+)**: Set `prompt = true` to request a hidden missing value; writable providers save it, while `null` keeps it invocation-only
- **Composed Secrets (0.16+)**: Derive read-only values such as DSNs from declared secrets with strict, order-independent `${UPPERCASE_NAME}` references
- **[Configuration Inheritance](https://monosecret.dev/concepts/inheritance/)**: Extend and override shared configurations using the `extends` feature
- **[Audit Logging](https://monosecret.dev/concepts/audit/)**: Every secret access recorded locally (who, when, why, outcome) — on by default, secret values never logged
- **[Discovery](https://monosecret.dev/reference/cli#init)**: `monosecret init` to discover secrets from existing `.env` files

## Quick Start

```shell-session
# 1. Initialize monosecret.toml (discovers secrets from .env)
$ monosecret init
✓ Created monosecret.toml with 0 secrets

Next steps:
  1. monosecret config global init    # Set up user defaults (0.17+)
  2. monosecret check          # Verify all secrets are set
  3. monosecret run -- your-command  # Run with secrets

# 2. Set up provider backend
$ monosecret config global init  # 0.17+
? Select your preferred provider backend:
> keyring: Uses system keychain (Recommended)
  kdbx: KeePass KDBX databases (0.17+)
  onepassword: 1Password password manager
  keeper: Keeper Secrets Manager (0.18+) via official Rust SDK
  dotenv: Traditional .env files
  file: Plaintext files, one per secret (0.19+)
  env: Read-only environment variables
  null: Use defaults, generation, or run prompts without storage (0.19+)
  systemd-credential: Read-only systemd service credentials (0.17+)
  pass: Unix password manager with GPG encryption
  gopass: Gopass CLI password manager with GPG encryption (0.15+)
  protonpass: Proton Pass via official pass-cli
  passbolt: Passbolt self-hosted password manager (0.19+) via go-passbolt-cli
  lastpass: LastPass password manager
  dashlane: Dashlane password manager, read-only (0.18+)
  gcsm: Google Cloud Secret Manager
  awssm: AWS Secrets Manager
  awsps: AWS Systems Manager Parameter Store (0.18+)
  scaleway: Scaleway Secret Manager (0.17+)
  vault: HashiCorp Vault secret management
  openbao: OpenBao secret management (0.17+)
  bw: Bitwarden Password Manager (0.18+)
  bws: Bitwarden Secrets Manager
  akv: Azure Key Vault
  infisical: Infisical secret management (0.16+)
  age: age-encrypted file (0.17+)
  sops: SOPS encrypted files (0.17+)
? Select your default profile:
> development
  default
  none
✓ Configuration saved to /home/user/.config/monosecret/config.toml

# 3. Check and configure secrets
$ monosecret check

# 4. Run your application with secrets
$ monosecret run -- npm start

# Or with a specific profile and provider
$ monosecret run --profile production --provider dotenv -- npm start
```

See the [Quick Start Guide](https://monosecret.dev/quick-start) for detailed instructions.

## Installation

```shell-session
$ npm install --global @monosecret/cli
```

See the [installation guide](https://monosecret.dev/quick-start#installation) for more options including Nix and Devenv.

## Configuration

Each project has a `monosecret.toml` file that declares the required secrets:

```toml
[project]
name = "my-app"  # Inferred from current directory name when using `monosecret init`
revision = "1.0"
# Optional: extend other configuration files
extends = ["../shared/common", "../shared/auth"]

[profiles.default]
DATABASE_URL = { description = "PostgreSQL connection string" }
REDIS_URL = { description = "Redis connection string" }

# Profile-specific configurations
[profiles.development]
DATABASE_URL = { required = false, default = "sqlite://./dev.db" }
REDIS_URL = { required = false, default = "redis://localhost:6379" }

[profiles.production]
DATABASE_URL = { required = true }
REDIS_URL = { required = true }

# Monosecret 0.19+: a profile can use an independent secret set.
[profiles.deployment.defaults]
inherit = false

[profiles.deployment]
DEPLOY_TOKEN = { description = "Deployment credential", required = true }
```

Monosecret 0.19+ can map one logical secret to different native coordinates per
provider alias, including independent import source and destination refs:

```toml
[providers]
remote = { uri = "onepassword://Production", ref = { item = "{project}-{profile}", field = "{key}" } }
local = "keyring://"

[profiles.production]
API_KEY = { description = "API key", providers = [
  "local",
], refs = { remote = { item = "legacy-api", field = "token" } } }
```

See the [configuration reference](https://monosecret.dev/reference/configuration/) for all available options.

## Profiles

Profiles allow you to define different secret requirements for each environment (development, production, etc.):

```shell-session
$ monosecret run --profile development -- npm start
$ monosecret run --profile production -- npm start

# Set a user-global default profile (0.17+)
$ monosecret config global init

# Monosecret 0.17+: set provider and profile defaults without prompting
$ monosecret config global init --provider env --profile default
```

Learn more about [profiles](https://monosecret.dev/concepts/profiles) and [profile selection](https://monosecret.dev/concepts/profiles#profile-selection).

## Providers

Monosecret supports multiple storage backends for secrets:

- **[Keyring](https://monosecret.dev/providers/keyring)** - System credential store (recommended)
- **[KeePass KDBX](https://monosecret.dev/providers/kdbx)** (0.17+) - Local KeePass-compatible encrypted database
- **[.env files](https://monosecret.dev/providers/dotenv)** - Traditional dotenv files
- **[Plaintext files](https://monosecret.dev/providers/file)** (0.19+) - One UTF-8 file per secret in a local directory tree
- **[Environment variables](https://monosecret.dev/providers/env)** - Read-only for CI/CD
- **[Null](https://monosecret.dev/providers/null)** (0.19+) - Use committed defaults, ephemeral generation, or ephemeral run prompts without secret storage
- **[systemd credentials](https://monosecret.dev/providers/systemd-credential)** (0.17+) - Read-only credentials passed to the current service
- **[Pass](https://monosecret.dev/providers/pass)** - Unix password manager with GPG encryption
- **[Gopass](https://monosecret.dev/providers/gopass)** (0.15+) - GPG-based password manager with git-synced password store
- **[Proton Pass](https://monosecret.dev/providers/protonpass)** - End-to-end encrypted via Proton's official pass-cli
- **[Passbolt](https://monosecret.dev/providers/passbolt)** (0.19+) - Self-hosted Passbolt through go-passbolt-cli
- **[1Password](https://monosecret.dev/providers/onepassword)** - Team secret management
- **[Keeper Secrets Manager](https://monosecret.dev/providers/keeper)** (0.18+) - Machine secrets through Keeper's official Rust SDK
- **[LastPass](https://monosecret.dev/providers/lastpass)** - Cloud password manager
- **[Dashlane](https://monosecret.dev/providers/dashlane)** (0.18+) - Read-only access to a Dashlane vault via the `dcli` CLI
- **[Google Cloud Secret Manager](https://monosecret.dev/providers/gcsm)** - GCP secret management
- **[AWS Secrets Manager](https://monosecret.dev/providers/awssm)** - AWS secret management
- **[AWS Systems Manager Parameter Store](https://monosecret.dev/providers/awsps)** (0.18+) - Encrypted hierarchical parameters in AWS
- **[Scaleway Secret Manager](https://monosecret.dev/providers/scaleway)** (0.17+) - Scaleway secret management
- **[Vault](https://monosecret.dev/providers/vault)** - HashiCorp Vault KV engine
- **[OpenBao](https://monosecret.dev/providers/openbao)** (0.17+) - OpenBao KV integration; Monosecret 0.16 accepts `openbao://` through the Vault provider
- **[Bitwarden Password Manager](https://monosecret.dev/providers/bw)** (0.18+) - Bitwarden Password Manager vault via the `bw` CLI
- **[Bitwarden Secrets Manager](https://monosecret.dev/providers/bws)** - Bitwarden Secrets Manager integration (official `bws` CLI required in Monosecret 0.17+)
- **[Azure Key Vault](https://monosecret.dev/providers/akv)** - Azure secret management
- **[Infisical](https://monosecret.dev/providers/infisical)** (0.16+) - Infisical secret management
- **[age](https://monosecret.dev/providers/age)** (0.17+) - age-encrypted file
- **[SOPS](https://monosecret.dev/providers/sops)** (0.17+) - SOPS-encrypted files

```bash
$ monosecret run --provider keyring -- npm start
$ monosecret run --provider dotenv -- npm start

# Configure a user-global default provider (0.17+)
$ monosecret config global init
```

See [provider concepts](https://monosecret.dev/concepts/providers) and [provider reference](https://monosecret.dev/reference/providers) for details.

## Rust SDK

Generate strongly-typed Rust structs from your `monosecret.toml`:

```rust
monosecret_derive::declare_secrets!("monosecret.toml");

fn main() -> Result<(), Box<dyn std::error::Error>> {
	// Load secrets with type safety
	let secrets = Monosecret::load(Provider::Keyring)?;

	// Access secrets as struct fields
	println!("Database: {}", secrets.database_url);

	// Optional secrets are Option<String>
	if let Some(redis) = &secrets.redis_url {
		println!("Redis: {}", redis);
	}

	Ok(())
}
```

See the [Rust SDK documentation](https://monosecret.dev/sdk/rust) for advanced usage including profile-specific types.

## Language SDKs

Beyond Rust, Monosecret ships SDKs for other languages. Each is a thin client
over the same native core, so every provider, chain, profile, and generator
works identically with no per-language resolution logic:

- [Python](https://monosecret.dev/sdk/python) (via a pyo3 extension)
- [Go](https://monosecret.dev/sdk/go) (via purego, no cgo, over the `monosecret-ffi` C ABI)
- [Ruby](https://monosecret.dev/sdk/ruby) (via a native C extension)
- [Node.js / TypeScript](https://monosecret.dev/sdk/nodejs) (napi-rs addon)
- [Haskell](https://monosecret.dev/sdk/haskell) (build-time FFI link)
- [PHP](https://monosecret.dev/sdk/php) (ext-php-rs extension, with an `ext-ffi` fallback)
- [C# (0.16+)](https://monosecret.dev/sdk/csharp) (P/Invoke with native assets in the NuGet package)
- [Swift (0.18+)](https://monosecret.dev/sdk/swift) (SwiftPM XCFramework for macOS Intel and Apple silicon)

```python
from monosecret import Monosecret

resolved = Monosecret.builder().with_provider("keyring://").with_reason("boot").load()
print(resolved.secrets["DATABASE_URL"].get)
```

For typed access, `monosecret schema` emits a JSON Schema you feed to
[quicktype](https://quicktype.io) to generate typed classes for any language,
built from the SDK's `fields()` map.

## CLI Reference

Common commands:

```bash
# Initialize and configure
monosecret init                    # Create monosecret.toml
monosecret config global init    # Set up user defaults (0.17+)

# Manage secrets
monosecret check                  # Verify all secrets are set
monosecret add KEY --description "Purpose" # Declare a secret (0.18+)
monosecret set KEY               # Set a secret interactively
monosecret get KEY               # Retrieve a secret
monosecret delete KEY            # Delete a stored provider value (0.18+)
monosecret import PROVIDER       # Import secrets from another provider
monosecret import PROVIDER --delete-source # Move verified values (0.18+)
monosecret cache clear [KEY]     # Clear cached provider values (0.17+)

# Run with secrets
monosecret run -- command        # Run command with secrets as env vars

# Inspect access
monosecret audit                 # Show the local audit log of secret access
```

See the [full CLI reference](https://monosecret.dev/reference/cli) for all commands and options.

## Contributing

We welcome contributions! Areas where you can help:

- **New provider backends** - See the [provider implementation guide](https://monosecret.dev/development/adding-providers)
- **Language SDKs** - Help us support more languages beyond Rust
- **Package managers** - Get Monosecret into your favorite package manager
- **Documentation** - Improve guides and examples

See our [GitHub repository](https://github.com/ifiokjr/monosecret) to get started.

## License

This project is licensed under the Apache License 2.0.

<img referrerpolicy="no-referrer-when-downgrade" src="https://static.scarf.sh/a.png?x-pxid=ddbe4178-cff6-4549-9365-facbc08f3b6f" />
