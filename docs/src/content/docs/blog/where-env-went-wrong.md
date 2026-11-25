---
title: "Where .env Went Wrong"
description: A local convenience became a secrets interface, an environment model, and a deployment format. It was never designed to be any of them.
date: 2026-07-30
authors:
  - domen
---

`.env` is one of software's most successful accidents.

It starts as a shortcut for three `export` commands. Then it becomes the
project's configuration schema, secret store, environment model, onboarding
guide, CI interface, and deployment format.

Environment variables do one job well: deliver strings to a process. `.env`
turned that delivery mechanism into a source of truth.

A convenience became architecture. That is where `.env` went wrong.

## Environment variables only deliver values

Environment variables solve a small problem: getting values into a running
process. The application can read `DATABASE_URL` without knowing whether a
developer, CI system, or secrets manager supplied it.

A `.env` file makes those values easy to save and reload. That is useful. But
teams also use the file to describe what the application needs. `KEY=value`
cannot say whether a value is required, secret, safe to commit, available only
in production, or restricted to one service.

Those requirements outlive any process and any developer laptop. They belong
in a durable project declaration. `.env` stores values for delivery; it cannot
define the application's secret model.

:::note[How does SecretSpec solve this?]
SecretSpec separates the committed
[declaration](/concepts/declarative/) from value
[storage](/concepts/providers/) and delivery. The CLI and
[SDKs](/sdk/overview/) resolve the same declaration regardless of where values
live or how applications receive them.
:::

## A string is not a schema

Consider a typical example file:

```dotenv title=".env.example"
DATABASE_URL=
REDIS_URL=redis://localhost:6379
STRIPE_API_KEY=
DEBUG=false
```

The file raises more questions than it answers. Does an empty value mean
required or optional? Is `REDIS_URL` a development default? Is
`STRIPE_API_KEY` production-only? Is `DEBUG` a boolean?

Dotenv cannot encode those answers. Node.js documents that
[every value becomes a
string](https://nodejs.org/api/environment_variables.html#variable-values).
A [dotenv issue about
booleans](https://github.com/motdotla/dotenv/issues/51), opened in 2015, still
collects reactions from developers surprised that `"false"` is truthy.

Teams put the missing information elsewhere: validation code, a README,
`.env.example`, or a teammate's memory. These sources drift.

The file also makes `DEBUG` and `STRIPE_API_KEY` look equivalent. One is an
ordinary setting that belongs in Git. The other grants authority and needs
access control and rotation. Mixing them makes the whole file sensitive.

Without an explicit declaration, missing values fail late: the application
discovers them only when code tries to use them.

:::note[How does SecretSpec solve this?]
The [SecretSpec declaration](/reference/configuration/) records names,
descriptions, required values, and safe defaults. `secretspec check` and
`secretspec run` validate those requirements before the application starts,
while ordinary settings such as `DEBUG` remain in application configuration.
:::

## Then the file starts to multiply

A new requirement usually creates another file:

```text
.env
.env.local
.env.development
.env.development.local
.env.test
.env.production
```

The filenames become an environment model. Suffixes define scope, load order
defines inheritance, and copying a file becomes deployment.

This reverses the
[Twelve-Factor App's guidance](https://12factor.net/config). Its point was that
environment variables should be independent controls because named
environments become brittle as deployments multiply. `.env.production`
recreates that grouping in a filename.

Now every new value must be added to `.env.example`, documented in a README,
validated in code, and copied into the right real files. Miss one and the
environments drift.

:::note[How does SecretSpec solve this?]
[Profiles](/concepts/profiles/) express real requirement differences as sparse
overlays on `profiles.default`. Each deployment selects its values through
providers instead of maintaining a complete, copied secret file.
:::

## There is no `.env` spec

`.env` looks standardized, but every parser defines its own format.
[Node.js documents the lack of a formal
specification](https://nodejs.org/api/environment_variables.html#env-files),
as does
[python-dotenv](https://github.com/theskumar/python-dotenv#file-format). Each
loader makes its own choices.

python-dotenv expands `${NAME}` but not `$NAME`. Node dotenv delegates [variable
expansion](https://github.com/motdotla/dotenv#variable-expansion) to another
tool. Docker Compose supports its own
[shell-style operators](https://github.com/compose-spec/compose-spec/blob/main/spec.md#interpolation).
Vite even supports references in reverse order, then
[warns](https://main.vite.dev/guide/env-and-mode#expanding-variables-in-reverse-order)
that the same expression will not work in a shell or Docker Compose.

Comments and quotes differ too. Node dotenv changed the meaning of `#` in
unquoted values in version 15 as a [breaking
change](https://github.com/motdotla/dotenv#comments). One devenv user found
that
[quotes became part of an exported
key](https://github.com/cachix/devenv/issues/1333).

:::note[How does SecretSpec solve this?]
SecretSpec defines one TOML declaration and one resolution model shared by its
CLI and [SDKs](/sdk/overview/). Dotenv parsing is confined to the
[compatibility provider](/providers/dotenv/), so changing loaders or storage
backends does not change the application's declaration.
:::

## Which value wins?

Parsers also disagree about precedence.
[Node dotenv](https://github.com/motdotla/dotenv#path) normally lets the first
file win. [Docker
Compose](https://github.com/compose-spec/compose-spec/blob/main/spec.md#env_file)
lets the last `env_file` win, then lets the `environment` section override
that. [Vite](https://main.vite.dev/guide/env-and-mode#env-loading-priorities)
gives an existing process variable priority over its files.

Docker Compose gives two similar names different behavior. `env_file:` supplies
variables to a container but does not use them to interpolate `compose.yaml`.
`docker compose --env-file` does affect interpolation. In [an issue closed as
working as
designed](https://github.com/docker/compose/issues/9443), a maintainer described
the option's name as unfortunately chosen.

:::note[How does SecretSpec solve this?]
SecretSpec applies one deterministic [provider resolution
order](/concepts/providers/fallback/#provider-selection-order). Per-secret
routes and fallbacks are explicit in the declaration, and the same resolver
applies them across the CLI and SDKs.
:::

## Who loaded `.env` first?

Precedence also depends on timing. Node dotenv's [ES module
guidance](https://github.com/motdotla/dotenv/blob/94f6542d5c8b1ab211cab0dcd8f7aa907dd39124/README.md#L406-L435)
needs special handling when imported modules read the environment during
initialization. Vite warns that Bun's automatic `.env` loading can interfere
with [Vite's own loading
order](https://main.vite.dev/guide/env-and-mode#env-files). `VITE_*` values are
replaced at build time and become part of the
[client bundle](https://main.vite.dev/guide/env-and-mode#env-variables).

The same line can become a runtime secret, a build-time constant, or a public
browser value. The loader decides based on timing and context.

At that point `.env` behaves like a small program, with control flow spread
across filenames, flags, working directories, parent processes, and library
versions.

:::note[How does SecretSpec solve this?]
[`secretspec run`](/reference/cli/#run) resolves and validates secrets before
launching the child, so its complete environment exists from process startup.
Applications using an SDK load the declaration explicitly instead of depending
on a module-import side effect.
:::

## An ignored file is still a file

The dotenv project says [not to commit
`.env`](https://github.com/motdotla/dotenv#should-i-commit-my-env-file).
`.gitignore` prevents one accident. It does not add encryption, access control,
auditing, or revocation.

The file can still end up in editor backups, chat messages, archives, support
bundles, container build contexts, and old laptops. A devenv integration was
[reported to copy `.env` contents into the Nix
store](https://github.com/cachix/devenv/issues/1694), where paths are not
confidential. When a developer leaves, there is no file access to revoke.
Each credential they received is a separate copy.

Even a secret stored in 1Password, Vault, a cloud secret manager, or a system
keyring must be copied into plaintext before a dotenv-based application can use
it. The local copy has fewer controls than the original.

Environment-variable delivery has limits too. Docker mounts managed secrets as
files because environment variables can
[leak between
containers](https://docs.docker.com/engine/swarm/secrets/#build-support-for-docker-secrets-into-your-images).
A process also gets one global map, so a frontend build, worker, migration, and
web service often receive the same secrets even when each needs only a few.
Dotenv has no way to express that scope.

:::note[How does SecretSpec solve this?]
The committed declaration contains no secret values. Providers supply storage,
encryption, identity, and access control, while the
[metadata-only audit log](/concepts/audit/) records local access. [Scopes
(0.17+)](/concepts/scopes/) let each service or command resolve only its
declared subset.
:::

## Let `.env` become small again

The useful part of `.env` is the short path from “this application needs a
value” to “the application can run.”

Keep it as an adapter for tools that expect `KEY=value`, or use it for ordinary
local settings. Do not make it define the project's requirements, store durable
copies of secrets, encode environments in filenames, or decide which services
receive which values.

A durable design separates three jobs:

- a committed declaration says which secrets the application needs;
- protected storage controls who can read their values;
- explicit delivery gives each process only the values it needs.

Each piece can then change independently. A team can change storage without
rewriting the application, validate requirements before startup, and limit each
component to its own secrets.

## How SecretSpec applies this

SecretSpec puts the declaration in a file that is safe to commit:

```toml title="secretspec.toml"
[project]
name = "payments"
revision = "1.0"

[profiles.default]
DATABASE_URL = { description = "Postgres connection string" }
REDIS_URL = { description = "Redis connection string", required = false }
STRIPE_API_KEY = { description = "Stripe API key" }

[profiles.development]
REDIS_URL = { default = "redis://localhost:6379" }
```

This file records requirements, defaults, and descriptions without containing
secret values. [Providers](/concepts/providers/) choose where values live, and
[profiles](/concepts/profiles/) describe real differences in requirements.

Existing programs can adopt SecretSpec without code changes:

```bash
$ secretspec run -- ./server
```

This command injects resolved secrets into the child process environment. It is
useful during migration, while the preferred integration is a
[SecretSpec SDK](/sdk/overview/).

With an SDK, the application resolves its declaration directly. This removes
the environment-variable handoff used by `secretspec run`. Values stored in a
keyring, password manager, or Vault never enter the global process environment.
Applications that require a file can receive a
[temporary file](/reference/configuration/#as_path-option) instead. [Scopes
(0.17+)](/concepts/scopes/) let each component resolve only the secrets it
declares.

Migration can be gradual. SecretSpec initializes a declaration from an existing
file:

```bash
$ secretspec init --from dotenv:.env
```

This copies names without copying values. The current file can remain a
provider during the transition:

```bash
$ secretspec check --provider dotenv:.env

$ secretspec run --provider dotenv:.env -- ./server
```

Values can then move to a system keyring, password manager, Vault, or another
provider without changing the names the application reads.

`.env` can remain for ordinary local settings. Existing applications can keep
environment-variable delivery while they migrate. Applications using an SDK or
file-based delivery can remove secrets from their process environments.

**SecretSpec aims to eliminate environment variables for secrets altogether.**
