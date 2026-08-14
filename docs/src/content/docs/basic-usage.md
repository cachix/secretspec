---
title: Basic Usage
description: The Monosecret commands you will use most often
---

Once your project has a `monosecret.toml` file and you have selected a default
provider, most day-to-day work uses a small set of commands.

## Check required secrets

Check that every required secret can be resolved. Missing values are shown
without printing any secrets, and Monosecret offers to set them interactively:

```bash
$ monosecret check
```

Use `monosecret check --no-prompt` in CI or other non-interactive environments.
It exits with an error when a required secret is missing.

## Store or replace a value

Set a secret without putting its value in your shell history:

```bash
$ monosecret set API_KEY
Enter value for API_KEY (profile: development): ********
✓ Secret 'API_KEY' saved to keyring (profile: development)
```

Running `set` again replaces the stored value. The secret must already be
declared in `monosecret.toml`.

## Read one value

Resolve and print a single secret:

```bash
$ monosecret get DATABASE_URL
postgresql://localhost/myapp
```

:::caution
`get` prints the secret as plain text. Avoid using it in shared terminals,
logs, or scripts. Use `run` or an SDK when an application needs the value.
:::

## Run your application

Start a command with the resolved secrets available as environment variables:

```bash
$ monosecret run -- npm start
```

The `--` separates Monosecret's options from the command you want to run.
Monosecret stops before starting the command if a required secret is missing.

## Add a declaration (0.2+)

:::caution[Version compatibility]
`add` is available starting with Monosecret 0.2.
:::

Declare a new secret without editing `monosecret.toml` by hand, then store its
value:

```bash
$ monosecret add API_KEY --description "API access token"
$ monosecret set API_KEY
```

`add` changes only the declaration. It never asks for or stores the secret
value.

## Delete stored values (0.2+)

:::caution[Version compatibility]
`delete` is available starting with Monosecret 0.2.
:::

Remove a stored value from its provider:

```bash
$ monosecret delete API_KEY
```

This leaves the declaration in `monosecret.toml`, so the project still records
that it expects `API_KEY`. See the [CLI reference](/reference/cli/#delete-018)
for deleting multiple values or using `--all`.

## Use another profile or provider

Your configured defaults apply automatically. Override them for one command
with `--profile` or `--provider`:

```bash
$ monosecret check --profile production
$ monosecret run --provider dotenv://.env.test -- npm test
```

These options do not change your saved preferences.

## Next steps

- See every option in the [CLI command reference](/reference/cli/)
- Learn how [profiles](/concepts/profiles/) separate environments
- Explore available [providers](/concepts/providers/)
