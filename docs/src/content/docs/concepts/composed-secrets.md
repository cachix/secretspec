---
title: Composed Secrets
description: Derive read-only values from other declared secrets with strict templates
---

:::caution[Version compatibility]
Available since SecretSpec 0.16.
:::

Composed secrets derive one exported value from other secrets in the active
profile. They are useful for connection strings, command arguments, and other
formats whose components should remain independently stored:

```toml
[profiles.default]
DB_USER = { description = "Database user" }
DB_PASSWORD = { description = "Database password" }
DB_HOST = { description = "Database host" }

DATABASE_URL = {
  description = "PostgreSQL connection string",
  composed = "postgres://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/app"
}
```

`DB_USER`, `DB_PASSWORD`, and `DB_HOST` resolve through their ordinary
providers. `DATABASE_URL` is then rendered in memory and exported alongside
them. The composed result is never read from or written to a provider.

## Static dependency graph

Every `{NAME}` must name a secret declared in the effective profile.
SecretSpec validates the complete graph while loading `secretspec.toml`, before
accessing a provider:

- declaration order does not matter;
- a composition may reference another composition;
- unknown references are errors;
- dependency cycles are errors.

```toml
[profiles.default]
USER = { description = "Database user" }
PASSWORD = { description = "Database password" }
HOST = { description = "Database host" }

AUTHORITY = { description = "Database authority", composed = "{USER}:{PASSWORD}" }
DATABASE_URL = { description = "Database URL", composed = "postgres://{AUTHORITY}@{HOST}/app" }
```

This differs deliberately from dotenv expansion, where behavior can depend on
file order, process environment, and how a particular parser handles undefined
or recursive variables.

## Template syntax

Composition is a small, strict language:

| Syntax | Meaning |
|---|---|
| `{SECRET_NAME}` | Insert one declared secret's exported value |
| `{{` | Insert a literal `{` |
| `}}` | Insert a literal `}` |

The following are intentionally unsupported:

- `${NAME}` and shell-style expressions such as `${NAME:-fallback}`;
- ambient environment-variable lookup;
- command substitution;
- recursive expansion.

Substitution is one pass. If `PASSWORD` contains the literal text `{HOST}`,
inserting `{PASSWORD}` produces `{HOST}`; it is not scanned again. This keeps
secret bytes opaque and prevents values from unexpectedly becoming executable
template syntax.

## Missing, empty, and optional values

Missing and empty are different:

- an empty dependency inserts an empty string;
- a missing dependency makes a required composition missing;
- when the composed secret sets `required = false`, a missing dependency omits
  the composed result instead.

SecretSpec never silently replaces a missing reference with empty text.
Interactive `secretspec check` prompts for the unresolved provider-backed
dependencies, not for the derived result.

## Read-only behavior

A composed secret cannot also declare `default`, `providers`, `ref`, `type`, or
enabled `generate`. These fields would give the same name two competing value
sources.

- `get` resolves the target's transitive dependencies and prints the result;
- `set` rejects the composed name as read-only;
- `import` skips composed names because there is no stored value to copy;
- `check`, `run`, `export`, and SDK resolution include the composed value like
  any other resolved secret.

## Profiles and inheritance

References are checked against the effective profile after `default` profile
inheritance. A profile may override the template while inheriting component
declarations:

```toml
[profiles.default]
DB_USER = { description = "Database user" }
DB_PASSWORD = { description = "Database password" }
DB_HOST = { description = "Database host" }
DATABASE_URL = { description = "Database URL", composed = "postgres://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/app" }

[profiles.development]
DATABASE_URL = { composed = "postgres://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/app_dev" }
```

Profile-level storage defaults do not apply to composed secrets, because their
source is the dependency graph rather than a provider. Profile-level
`required` defaults still apply.

## Paths and encoding

When a dependency uses `as_path = true`, its exported temporary-file path is
inserted. Setting `as_path = true` on the composed secret instead writes the
final rendered value to a temporary file.

Composition performs raw string concatenation. It does not URL-encode values:
SecretSpec cannot infer whether a component is a username, password, host,
path, or query parameter. Store each component in the representation required
by the destination format.

See the [`composed` configuration reference](/reference/configuration/#composed-secrets)
for the field-level constraints.
