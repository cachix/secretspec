---
title: Scopes
description: Resolve and expose only the secrets a service or task needs
---

:::caution[Version compatibility]
Scopes are available starting with SecretSpec 0.17.
:::

A profile defines how secrets behave in an environment. A scope selects which
of those secrets one service, command, or task receives.

This lets several consumers share one profile without giving every consumer the
complete secret set. An API and a background worker can use the same
`production` profile, for example, while receiving different credentials.

## Define scopes

Add a top-level `[scopes]` table to `secretspec.toml`. Each named scope contains
an allowlist of secret names:

```toml title="secretspec.toml"
[profiles.default]
DATABASE_URL = { description = "Database" }
API_KEY = { description = "API key" }
QUEUE_TOKEN = { description = "Queue token" }

[scopes.api]
secrets = ["DATABASE_URL", "API_KEY"]

[scopes.worker]
secrets = ["DATABASE_URL", "QUEUE_TOKEN"]
```

The active profile still controls requirements, defaults, providers,
references, generation, composition, and storage addresses. Selecting `api`
only narrows the resolved set to `DATABASE_URL` and `API_KEY`; it does not
create another profile or another copy of either secret.

A scope must contain at least one unique, non-blank name. Every name must be
declared by at least one profile, although the active profile does not need to
declare every member.

## Select a scope

`check`, `run`, and `export` accept `--scope`:

```bash
$ secretspec check --profile production --scope api

$ secretspec run --profile production --scope api -- ./api-server

$ secretspec export --profile production --scope worker --format dotenv
```

Set `SECRETSPEC_SCOPE` to select one without repeating the flag:

```bash
$ export SECRETSPEC_SCOPE=worker

$ secretspec run --profile production -- ./worker
```

The command-line flag takes precedence over the environment variable. With no
scope selected, SecretSpec resolves the complete profile as before.

The untyped language SDK builders also accept an explicit scope and return its
name in resolved and report results. See the [SDK
overview](/sdk/overview/#the-runtime-api) for the shared behavior and each SDK
guide for its language-specific method.

## What gets resolved

The visible set is the intersection of the selected scope and the merged active
profile:

- a required secret outside the scope does not block scoped resolution;
- a secret outside the scope is not fetched unless a visible composed secret
  needs it;
- a valid scope whose intersection with the profile is empty resolves nothing
  and contacts no provider;
- a scope member absent from the active profile is simply absent from the
  resolved result, allowing one scope to be reused across profiles with
  different shapes.

Scopes never change a secret's `{project}/{profile}/{key}` storage address. A
scoped and unscoped read of the same secret addresses the same provider value.

### Composed secrets

A visible [composed secret](/concepts/composed-secrets/) may depend on values
the scope excludes:

```toml title="secretspec.toml"
[profiles.default]
DB_USER = { description = "Database user" }
DB_PASSWORD = { description = "Database password" }
DB_HOST = { description = "Database host" }
DATABASE_URL = {
  description = "Application database URL",
  composed = "postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}/app"
}

[scopes.api]
secrets = ["DATABASE_URL"]
```

SecretSpec resolves the three inputs to build `DATABASE_URL`, then exposes only
`DATABASE_URL`. A secret that is neither visible nor a dependency of a visible
composition is never fetched.

## Narrow a process environment

`run --scope` removes every manifest-declared secret the scope does not admit
from the child environment, even when the parent shell had already exported
it. The removal covers names declared in every profile, preventing a value
inherited from another profile from leaking into the launched process.

`export --scope` only emits the selected values. It cannot remove variables
that already exist in the current shell because its output formats cannot
express an unset. Use `run --scope` when narrowing an existing environment is
the goal.

Scopes minimize secret delivery; they are not an authorization boundary. A
child that has access to `secretspec.toml` and valid provider credentials may
resolve another scope itself. Use provider permissions, service isolation, and
operating-system controls when the process must be prevented from reading
other values.

## Validate scoped requirements

[Cross-secret presence constraints](/reference/configuration/#cross-secret-presence-constraints-017)
are evaluated over the group members visible to the scope. A group with no
visible members is not enforced for that consumer. When some members are
visible, `at_least_one` or `exactly_one` is enforced over those members so a
scoped consumer cannot rely on a credential it never receives.

Run an unscoped `secretspec check` when validating the complete profile rather
than one consumer's view.

## Profiles and inheritance

Scopes are orthogonal to profiles and reusable across them. They do not inherit
from the `default` profile; instead, the selected scope is applied after normal
profile inheritance produces the effective profile.

In SecretSpec 0.19+, a profile with `defaults.inherit = false` does not include
any default-profile secrets. A scope still intersects the effective profile, so
it cannot bring an inherited secret into a standalone profile.

When a project uses [`extends`](/concepts/inheritance/), a child scope replaces
a parent scope with the same name. The lists are not unioned, so extending a
configuration cannot silently widen an allowlist. Scopes defined only by a
parent remain available to the child.

## Commands that ignore scopes

`set` and `import` ignore `SECRETSPEC_SCOPE`: a resolution allowlist must not
silently restrict which secrets a write or migration command manages.

Rust's generated typed loaders also ignore the ambient scope because their
structs contain a field for every secret in the profile. Use the untyped
resolver API when a Rust consumer needs scoped resolution.

See the [`[scopes]` configuration reference](/reference/configuration/#scopes-section)
for validation details, empty-selection behavior, audit semantics, and clearing
an inherited scope selection.
