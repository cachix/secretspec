---
title: Claude Code
description: Let Claude Code retrieve API and gateway credentials through SecretSpec providers
---

The Claude Code credential integration is available in SecretSpec 0.20+. It
configures Claude Code's native
[`apiKeyHelper`](https://code.claude.com/docs/en/settings#available-settings) to
retrieve an Anthropic API or LLM gateway credential from any SecretSpec
provider.

:::note[Authentication scope]
This integration configures API or gateway authentication. When `apiKeyHelper`
is the active credential, it replaces a Claude Pro, Max, Team, or Enterprise
subscription for the session and bills the account behind the configured
credential. Claude Code's `/login` OAuth credentials have a separate lifecycle
and remain managed by Claude Code.
:::

## Prerequisites

- Claude Code 2.1.211 or newer
- SecretSpec 0.20 or newer, with `secretspec` on `PATH`

## Quick start

These commands are available in SecretSpec 0.20+.

From anywhere in a Git repository, configure its personal
`.claude/settings.local.json` in the main checkout root:

```bash
$ secretspec claude configure
Configured Claude Code credential integration in /work/my-project/.claude/settings.local.json.
Store the credential with: secretspec claude login
Undo with: secretspec claude unconfigure
Keep /work/my-project/.claude/settings.local.json out of version control; it contains a machine-local SecretSpec configuration identifier.
```

SecretSpec preserves unrelated Claude settings and refuses to replace an
existing `apiKeyHelper` that it does not manage.

Claude Code uses `settings.local.json` for machine-specific project settings.
SecretSpec prints a reminder to keep that file out of version control. Do not
move the generated helper into the team-shared `.claude/settings.json`, because
its configuration identifier belongs to one user's SecretSpec state. Outside a
Git repository, SecretSpec follows Claude Code and uses the current directory.

Store the API key without putting it in shell history:

```bash
$ secretspec claude login
? Enter Claude Code API or gateway credential:
```

Claude Code now invokes the managed SecretSpec command whenever it needs the
credential:

```bash
$ claude
```

`configure` stores no credential. It adds only a short configuration identifier
to Claude settings. The matching owner-only SecretSpec state records the
provider selection, access reason, audit resource, and credential declaration,
but never the resolved value. Each settings scope and audit resource receives a
deterministic embedded identity. Credentials therefore remain separate across
projects, user configurations, and gateways, including in providers that
flatten project namespaces. Lookup still works when Claude Code starts from a
subdirectory.

To pin a provider instead of using the current SecretSpec default, pass it to
`configure`. Later `login`, `logout`, and helper calls automatically reuse it:

```bash
$ secretspec claude configure --provider onepassword
$ secretspec claude login
```

An exported `SECRETSPEC_FILE`, `SECRETSPEC_PROFILE`, `SECRETSPEC_PROVIDER`, or
`SECRETSPEC_REASON` is not saved as durable helper configuration. Pass the
corresponding option explicitly when it should be pinned.

## Configure every project

User-level Claude Code configuration is available in SecretSpec 0.20+.

::::danger[This changes your user-level Claude Code settings]
`--global` updates `$CLAUDE_CONFIG_DIR/settings.json` when
`CLAUDE_CONFIG_DIR` is set, or `~/.claude/settings.json` otherwise. The helper
provides the user-level default for Claude Code projects. SecretSpec asks for
confirmation that defaults to **No**. Undo it with
`secretspec claude unconfigure --global`.
::::

Use the same `CLAUDE_CONFIG_DIR` value for `configure`, `login`, `logout`, and
`unconfigure`; each directory represents a separate Claude Code account and
receives an isolated embedded credential.

```bash
$ secretspec claude configure --global
$ secretspec claude login --global
```

Pass `--yes` only for non-interactive setup. User, project, and local settings
have separate embedded credentials. Claude Code project or local settings can
override the user-level helper, while managed settings and command-line
settings have higher precedence than every user-controlled settings file.

## Use an LLM gateway

Gateway audit attribution is available in SecretSpec 0.20+.

Set Claude Code's non-secret gateway URL normally, then record its host as the
SecretSpec audit resource:

```json title=".claude/settings.json"
{
  "env": {
    "ANTHROPIC_BASE_URL": "https://gateway.example.com"
  }
}
```

```bash
$ secretspec claude configure --resource gateway.example.com
$ secretspec claude login
```

The audit resource participates in the embedded credential identity, so two
projects or settings scopes can use different gateway credentials in the same
provider without collision. `login`, `logout`, and retrieval all record the
configured gateway host in caller context. Changing `--resource` selects a new
embedded credential and does not delete the old one. Run `logout` before
reconfiguring when the old credential should be removed.

`apiKeyHelper` sends the returned value using Claude Code's model credential
headers. Confirm that the gateway accepts that authentication shape before
using it. The gateway URL itself is ordinary configuration and does not belong
in SecretSpec.

## Use a project manifest

Custom Claude Code credential configuration is available in SecretSpec 0.20+.

Pass `--file` when the credential already has a project or company declaration.
In this mode, `--token-secret` is required and `--profile` is available:

```toml title="company-claude.toml"
[project]
name = "company-claude"
revision = "1.0"

[profiles.default]
ANTHROPIC_API_KEY = { description = "Anthropic API key for Claude Code" }
```

```bash
$ secretspec --file company-claude.toml set ANTHROPIC_API_KEY
$ secretspec --file company-claude.toml claude configure \
  --token-secret ANTHROPIC_API_KEY
```

The managed state records the manifest's absolute logical path, resolved
profile, secret name, and an explicitly supplied provider. It does not copy the
credential. If the manifest moves, rerun `configure`. Manage custom-manifest
values with ordinary `secretspec set` and `secretspec delete`; `claude login`
and `logout` intentionally manage only the embedded store.

## Remove credentials and configuration

These removal commands are available in SecretSpec 0.20+.

Remove the embedded credential without changing Claude Code settings:

```bash
$ secretspec claude logout
$ secretspec claude logout --global
```

The first command removes the current project's embedded credential; the second
removes the user-level credential. A provider pinned by `configure` is selected
automatically. For a custom manifest, use `secretspec delete` instead.

Remove SecretSpec's `apiKeyHelper` from the current project:

```bash
$ secretspec claude unconfigure
```

Add `--global` to remove the user-level setting. User-level removal also
defaults to **No** and accepts `--yes` for non-interactive use:

```bash
$ secretspec claude unconfigure --global
```

`logout` and `unconfigure` are independent. Unconfigure preserves the stored
credential, its owner-only lifecycle metadata, unrelated Claude settings, and
the settings file itself. You can still run `logout` after `unconfigure`. If
the managed `apiKeyHelper` changes outside SecretSpec, unconfigure refuses to
remove it.

## Refresh and precedence

Claude Code caches an `apiKeyHelper` result for five minutes by default and
calls the helper again after an HTTP 401. Set
`CLAUDE_CODE_API_KEY_HELPER_TTL_MS` when the credential has a shorter lifetime.

In Claude Code's
[authentication precedence](https://code.claude.com/docs/en/authentication#authentication-precedence),
Claude apps gateway sessions and enabled cloud providers take precedence over
API credentials. Among ordinary model credentials, `ANTHROPIC_AUTH_TOKEN` and
`ANTHROPIC_API_KEY` take precedence over `apiKeyHelper`; the helper takes
precedence over `CLAUDE_CODE_OAUTH_TOKEN`, Anthropic profiles, and `/login`
credentials. Remove either static API variable before relying on SecretSpec:

```bash
$ unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN
$ claude
```

Run `/status` inside Claude Code to confirm that the intended settings file
loaded and API authentication is active. Do not run the generated credential
command merely to test the setup: it deliberately prints the credential.

Organization policy can block `apiKeyHelper` when Claude Code is forced to
verify membership through a particular login method.

`apiKeyHelper`, `ANTHROPIC_API_KEY`, and `ANTHROPIC_AUTH_TOKEN` apply to the
terminal CLI and surfaces that wrap it, including the VS Code extension, Agent
SDK, and GitHub Actions. Claude Desktop and cloud sessions do not invoke the
helper.

## Manual configuration

SecretSpec 0.20+ management commands are optional when a declarative settings
file is preferred. Declare the credential in a manifest and set `apiKeyHelper`
to an ordinary `secretspec get` command:

```json
{
  "apiKeyHelper": "secretspec --reason \"Claude Code model authentication\" get ANTHROPIC_API_KEY"
}
```

This setting is not recorded as SecretSpec-managed, so `secretspec claude
unconfigure` does not remove it. Keep an explicit `--file` in the command when
the helper can run outside the manifest's directory. In SecretSpec 0.20+, add
`--caller claude-code --caller-operation credential_get --caller-resource
api.anthropic.com` when the manual command should carry the same structured
audit context as the managed integration.
