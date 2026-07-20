---
title: "Secrets Don’t Belong in Config"
description: An audit of 445 NixOS modules shows the cost of making configuration and secrets share one interface.
date: 2026-07-20
authors:
  - domen
---

Applications should not require passwords, API keys, or tokens in their
configuration files.

Configuration describes behavior. It belongs in git, code review, bug reports,
and developer machines. 

A secret grants authority. It needs restricted access and independent rotation.

Putting both in one file couples different lifecycles and audiences. If rotating
a password requires regenerating application configuration, the interface has
coupled them too tightly.

## NixOS contains 110 workarounds for this

We [audited all 445 NixOS modules that handle a real secret](https://github.com/NixOS/nixpkgs/issues/24288#issuecomment-5024009774)
in nixpkgs at commit `141f212`, classifying each by where its secret value ends
up.

| Where the secret value ends up | Modules | Share |
|---|--:|--:|
| Merged into a config file at runtime | 110 | 25% |
| Inlined into a config in `/nix/store` | 42 | 9% |
| Delivered as an environment variable | 161 | 36% |
| Left in a dedicated file opened by the app | 58 | 13% |
| Loaded through systemd credentials | 53 | 12% |
| Passed as a command-line argument | 19 | 4% |
| Classification uncertain | 2 | — |

The interesting number is 110. A quarter of the modules retrieve a secret
safely, then copy it into configuration because that is the only interface the
application accepts.

These modules use `envsubst`, `replace-secret`, `jq`, `yq`, `sed`, or custom
code to assemble a restricted file at startup. The result can be secure, but
every module now owns application-specific, security-sensitive glue just to
combine two inputs that should have remained separate.

This is not unique to NixOS. The same workaround appears as an entrypoint
script, Helm template, init container, or CI interpolation step on other
platforms.

As a side note, 42 modules can inline secrets into the world-readable
`/nix/store`. That direct security problem is tracked in
[nixpkgs issue #24288](https://github.com/NixOS/nixpkgs/issues/24288). The 110
runtime mergers make the broader point: even when deployment authors avoid the
leak, the missing separation still creates work.

## Give secrets their own interface

Applications should accept secret values through a dedicated runtime channel,
such as:

- a `password_file` or `token_file` setting;
- a systemd credential;
- a narrowly scoped environment variable;
- or an external secret provider.

These mechanisms are not equally safe: environment variables can be inherited,
arguments can appear in process listings, and files still need correct
permissions. What separation does guarantee is that the deployer no longer has
to manufacture a second, secret-bearing version of the configuration.

The principle is simple; implementing it across environments is not. Local
development might use a system keyring, CI environment variables, and
production 1Password or Vault. Without a shared abstraction, each environment
needs its own naming, lookup, validation, and injection glue.

## How I got it wrong in Cachix

Cachix historically stored its auth token and per-cache signing keys in
`~/.config/cachix/cachix.dhall`, alongside cache names and other configuration.
It was convenient, but the file had to be treated as a secret even though much
of it was ordinary configuration.

A typical file mixed them directly:

```dhall title="~/.config/cachix/cachix.dhall"
{ authToken = "XXX-AUTH-TOKEN"
, binaryCaches =
    [ { name = "mycache"
      , secretKey = "XXX-SIGNING-KEY"
      }
    ]
}
```

The cache name is configuration; the auth token and signing key are secrets.
You could not share the cache configuration without also sharing credentials.

[devenv 2.2 separates the token through SecretSpec](https://devenv.sh/binary-caching/#setup-with-secretspec-recommended).
The project declares `CACHIX_AUTH_TOKEN`, devenv resolves it from the configured
provider, and the value is passed to Cachix without being added to devenv's
configuration.

[Cachix PR #737](https://github.com/cachix/cachix/pull/737) brings the same
boundary into the client through the SecretSpec Haskell SDK. It resolves
`CACHIX_AUTH_TOKEN` and `CACHIX_SIGNING_KEY` from SecretSpec and can store them
in the user's chosen provider instead of `cachix.dhall`. Existing environment
variables and config files remain higher-priority fallbacks for compatibility.
The PR is still open and is not available in a released Cachix version yet.

That is the problem SecretSpec is designed to solve: configuration declares the
requirement, while each environment chooses where the value lives.

## Declare once, resolve anywhere

SecretSpec applies that separation by making `secretspec.toml` a declaration of
what an application needs, without storing the values:

```toml title="secretspec.toml"
[project]
name = "myapp"

[profiles.production]
DATABASE_URL = { description = "Postgres connection string" }
STRIPE_API_KEY = { description = "Stripe secret key" }
```

[Providers](/concepts/providers/) decide where the values live. A developer can
use the system keyring, CI can use environment variables, and production can use
1Password, Vault/OpenBao, or a cloud secret manager without changing the
declaration.

An existing application can receive the resolved values at startup:

```bash
secretspec run -- ./myapp
```

Applications can also resolve them directly through the
[SecretSpec SDKs](/sdk/overview/) for Rust, Python, Go, Ruby,
Node.js/TypeScript, Haskell, PHP, and C#, all sharing the same resolver
so behavior stays consistent across languages.

Providers own where secret values come from. SDKs give applications an
idiomatic way to consume them. Configuration remains a shareable declaration of
what is required.

## Making the boundary practical

If you maintain an application, stop adding passwords and tokens to ordinary
configuration schemas. Accept a file reference, credential, environment
variable, or provider instead.

For NixOS, [SecretSpec issue #65](https://github.com/cachix/secretspec/issues/65)
tracks how an official integration could declare and resolve secrets without
per-module substitution glue.

Consistent secret handling across developer machines, CI, and production used
to require infrastructure that only dedicated platform teams could build. A
project of any size should be able to separate secrets from configuration
without building its own secrets platform first.
