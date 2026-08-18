---
title: Codex
description: Let Codex retrieve OpenAI and gateway API keys through SecretSpec providers
---

The Codex API-key integration is available in SecretSpec 0.20+. It configures
Codex's native command-backed custom-provider authentication to retrieve an
OpenAI or compatible gateway API key from any SecretSpec provider.

:::note[Authentication scope]
This integration manages static API-key authentication only. It does not read,
write, or refresh ChatGPT OAuth credentials, Codex access tokens, or
`auth.json`. Codex cloud requires ChatGPT sign-in and does not use this local
credential command.
:::

## Prerequisites

- Codex CLI 0.118.0 or newer
- SecretSpec 0.20 or newer, with `secretspec` on `PATH`

## Quick start

These commands are available in SecretSpec 0.20+.

Configure the current user's `$CODEX_HOME/config.toml`, or
`~/.codex/config.toml` when `CODEX_HOME` is unset:

```bash
$ secretspec codex configure --model gpt-5.6
? Configure the current user's Codex API-key provider? No
```

This is a user-level change, so confirmation defaults to **No**. Confirm it
interactively, or pass `--yes` for non-interactive setup:

```bash
$ secretspec codex configure --yes --model gpt-5.6
Configured Codex API-key integration in /home/me/.codex/config.toml.
Store the API key with: secretspec codex login
Undo with: secretspec codex unconfigure
```

SecretSpec preserves unrelated Codex settings and the previously selected
`model_provider`. It refuses to replace or remove its provider after the
managed provider or selection changes outside SecretSpec.

Omit `--model` when the user configuration already has a top-level `model`.
For a fresh configuration, choose a model supported by the installed Codex
version and API account. SecretSpec requires that explicit choice because
current Codex releases can omit agent tools when a custom provider relies on
an implicit default model. A model added through `--model` is owned by this
integration and removed by `unconfigure`; an existing model is never changed.

Store the API key without putting it in shell history:

```bash
$ secretspec codex login
? Enter Codex API or gateway key:
```

Start Codex normally:

```bash
$ codex
```

Codex invokes the generated structured command whenever it needs the bearer
token. SecretSpec writes neither the key nor a shell command containing it to
Codex configuration. Codex caches the returned value for five minutes and
refreshes it after an authentication retry.

The CLI and IDE extension share Codex configuration layers. Use the same
`CODEX_HOME` for `configure`, `login`, `logout`, `unconfigure`, and the Codex
client. Each `CODEX_HOME` receives a separate embedded credential, including
with providers that flatten project namespaces.

To pin a SecretSpec provider instead of using the current default, pass it to
`configure`. Later lifecycle and credential calls automatically reuse it:

```bash
$ secretspec codex configure --yes --provider onepassword
$ secretspec codex login
```

An exported `SECRETSPEC_FILE`, `SECRETSPEC_PROFILE`, `SECRETSPEC_PROVIDER`, or
`SECRETSPEC_REASON` is not saved as durable helper configuration. Pass the
corresponding option explicitly when it should be pinned.

## Configuration and precedence

User-level Codex API-key configuration is available in SecretSpec 0.20+.

SecretSpec creates a uniquely named custom provider in the user's
`config.toml`, points `model_provider` at it, and records only owner-only
lifecycle metadata in SecretSpec's configuration directory. The generated
provider uses the Responses API and Codex's separate `command` and `args`
fields, so no shell evaluates the credential command.

Codex command-line overrides, trusted project `.codex/config.toml` files, and
selected profiles have higher precedence than user configuration. A higher
layer that changes `model_provider` prevents the SecretSpec provider from being
selected. `secretspec codex unconfigure` also refuses to guess ownership until
that selection is restored.

Do not copy the generated provider into a project `.codex/config.toml`. Its
configuration identifier belongs to one user's owner-only SecretSpec state and
should not be committed or shared.

## Use an OpenAI-compatible gateway

Gateway configuration is available in SecretSpec 0.20+.

Set the non-secret Responses API base URL during configuration:

```bash
$ secretspec codex configure --yes \
  --base-url https://gateway.example.com/openai/v1
$ secretspec codex login
```

SecretSpec accepts HTTPS endpoints and loopback HTTP endpoints. It rejects
remote plaintext HTTP, URL credentials, queries, and fragments. Confirm that
the gateway accepts an OpenAI-compatible Responses API bearer token before
using it.

The normalized endpoint participates in the embedded credential identity, and
its host is recorded as the non-secret audit resource. Changing `--base-url`
selects a new embedded credential and does not delete the old one. Run `logout`
before reconfiguring when the old credential should be removed.

## Use a custom manifest

Custom Codex credential configuration is available in SecretSpec 0.20+.

Pass `--file` when the API key already has a project or company declaration.
In this mode, `--token-secret` is required and `--profile` is available:

```toml title="company-codex.toml"
[project]
name = "company-codex"
revision = "1.0"

[profiles.default]
OPENAI_API_KEY = { description = "OpenAI API key for Codex" }
```

```bash
$ secretspec --file company-codex.toml set OPENAI_API_KEY
$ secretspec --file company-codex.toml codex configure --yes \
  --token-secret OPENAI_API_KEY
```

The managed state records the manifest's absolute logical path, resolved
profile, secret name, and an explicitly supplied provider. It does not copy the
credential. If the manifest moves, rerun `configure`. Manage custom-manifest
values with ordinary `secretspec set` and `secretspec delete`; `codex login`
and `logout` intentionally manage only the embedded store.

## Remove credentials and configuration

These removal commands are available in SecretSpec 0.20+.

Remove the embedded API key without changing Codex configuration:

```bash
$ secretspec codex logout
```

Remove the SecretSpec-managed custom provider and restore the previous
`model_provider`. If SecretSpec added the top-level model during configuration,
it removes that model too:

```bash
$ secretspec codex unconfigure
```

User-level removal also defaults to **No** and accepts `--yes` for
non-interactive use.

`logout` and `unconfigure` are independent. Unconfigure preserves the stored
credential, its owner-only lifecycle metadata, unrelated Codex settings, and
the configuration file. You can still run `logout` after `unconfigure`. For a
custom manifest, use `secretspec delete` instead.

## Native Codex login is separate

Codex supports native ChatGPT and API-key sign-in through `codex login`. Those
credentials are cached separately in the operating-system keyring or
`$CODEX_HOME/auth.json`. SecretSpec's selected custom provider supplies its own
bearer token and never modifies that login state.

Run `codex login status` to inspect native Codex login state. Use `secretspec
codex login` and `logout` only for the SecretSpec-managed embedded API key.
Removing one does not remove the other.

API-key usage is billed through the account behind that key and can lack
features that require ChatGPT workspace access. Transcript redaction and OAuth
token lifecycle are separate concerns and are not provided by this integration.

## Manual configuration

SecretSpec 0.20+ management commands are optional when a declarative Codex
configuration is preferred. Declare the credential in a manifest and configure
a custom provider directly:

```toml title="~/.codex/config.toml"
model = "gpt-5.6"
model_provider = "secretspec"

[model_providers.secretspec]
name = "OpenAI API through SecretSpec"
base_url = "https://api.openai.com/v1"
wire_api = "responses"

[model_providers.secretspec.auth]
command = "secretspec"
args = ["--reason", "Codex model authentication", "get", "OPENAI_API_KEY"]
refresh_interval_ms = 300000
timeout_ms = 5000
```

This provider is not recorded as SecretSpec-managed, so `secretspec codex
unconfigure` does not remove it. Keep an explicit `--file` in `args` when Codex
can start outside the manifest's directory. In SecretSpec 0.20+, add `--caller
codex --caller-operation credential_get --caller-resource api.openai.com` when
the manual command should carry the same structured audit context.
