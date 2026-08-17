---
title: Git credentials
description: Let Git retrieve HTTPS and SMTP credentials through SecretSpec providers
---

The Git credential helper is available in SecretSpec 0.20+. It lets ordinary
`git clone`, `git fetch`, `git pull`, and `git push` commands retrieve HTTPS
credentials from any SecretSpec provider. It also supports SMTP authentication
for `git send-email`.

Use it when your Git token already lives in a provider such as 1Password,
Bitwarden, or Vault and you do not want to copy it into a separate Git
credential store. The integration does not manage SSH keys or inject secrets
into repositories.

## Prerequisites

- Git
- SecretSpec 0.20 or newer, including `git-credential-secretspec` on `PATH`

## Configure Git

These commands are available in SecretSpec 0.20+.

Register the helper, keeping the non-secret username in Git:

```bash
$ secretspec git configure \
  --url https://github.com \
  --username YOUR_USERNAME
```

Then store the password or token through your configured default provider:

```bash
$ secretspec git login https://github.com
? Enter value for PASSWORD (profile: default):
```

The built-in manifest declares a required `PASSWORD` and optional `USERNAME`.
It is embedded in the binary: the helper never searches the current directory
for `secretspec.toml`, so clone, fetch, and push resolve the same declarations
inside or outside a repository. Git configuration records no manifest path.

Each canonical credential target has a separate provider namespace. The
identity includes the protocol and host, plus the configured path when
`useHttpPath` is enabled, so credentials for different hosts or path scopes
cannot share a value accidentally.

To keep the username in the provider too, omit `--username` from `configure`
and supply it when logging in:

```bash
$ secretspec git configure --url https://github.com
$ secretspec git login https://github.com --username YOUR_USERNAME
```

`login` prompts securely on a terminal and reads the password or token from
standard input when piped. Use the same `--provider` override on `configure`
and `login` when the credential should not use your default provider.

The helper checks the URL independently before loading the provider. A token
configured for `https://github.com` is not returned for another host or for an
HTTP remote.

::::danger[Use HTTPS for credentials]
Although the helper accepts `http://` URLs for trusted local or test systems,
HTTP does not encrypt the credential in transit. Use `https://` for remote
services.
::::

To limit a credential to part of a host, include the path in the URL:

```bash
$ secretspec git configure \
  --url https://github.com/cachix \
  --username YOUR_USERNAME
$ secretspec git login https://github.com/cachix
```

SecretSpec also enables Git's `useHttpPath` setting for that URL. This example
answers for repositories below `https://github.com/cachix/`, but not for
another GitHub organization. The path-scoped credential is stored separately
from one configured for all of `https://github.com`.

## Send patches with SMTP

SMTP credential support is available in SecretSpec 0.20+. Git queries
credential helpers when `sendemail.smtpUser` is set and
`sendemail.smtpPass` is omitted:

```bash
$ git config --global sendemail.smtpServer smtp.example.com
$ git config --global sendemail.smtpServerPort 587
$ git config --global sendemail.smtpEncryption tls
$ git config --global sendemail.smtpUser user@example.com
$ secretspec git configure \
  --url smtp://smtp.example.com:587 \
  --username user@example.com \
  --global
$ secretspec git login smtp://smtp.example.com:587
```

The SMTP URL must include the port that Git uses. The username on `configure`
must match `sendemail.smtpUser`. `login` and `logout` read it back from Git
configuration; pass `--username` explicitly if the helper has already been
unconfigured or another account is being managed. Protocol, server, port, and
username form the embedded storage identity, so two accounts on the same SMTP
server never share a password.

Git resolves a single helper per credential URL, so one account is configured
for a given server and port at a time. Running `configure` again with a
different `--username` switches to that account and says which entry it
replaced. The other account's password stays in its own storage identity and
is used again as soon as you switch back, and `logout` is what removes a
stored password.

Server names are matched case-insensitively, so `smtp://SMTP.Example.COM:587`
and `smtp://smtp.example.com:587` are the same target.

The `smtp` URL is Git's credential-context name, not a transport-security
setting. Encryption remains controlled by
`sendemail.smtpEncryption=tls|ssl`. SecretSpec never writes
`sendemail.smtpPass` or any other `sendemail.*` setting, and the helper rejects
HTTP(S), a different port, or another username when answering an SMTP request.

## Clone private repositories

Configure the embedded credential globally before the destination repository
exists:

::::danger[This changes your global Git configuration]
Using `--global` enables this credential helper for matching URLs in every Git
repository owned by your user. Review the URL before confirming. To roll back
the example below, run
`secretspec git unconfigure --url https://github.com --global`; see
[Remove the configuration](#remove-the-configuration) for all removal options.
::::

```bash
$ secretspec git configure \
  --url https://github.com \
  --username YOUR_USERNAME \
  --global
$ secretspec git login https://github.com
```

Then clone normally:

```bash
$ git clone https://github.com/OWNER/REPOSITORY.git
```

Git invokes the SecretSpec credential helper automatically. The token does not
need to appear in the clone URL or your shell history.

Global changes require a confirmation that defaults to **No**. Pass `--yes`
only for non-interactive setup.

`configure` records `--provider` and `--reason` in the generated helper only
when you pass them on the command line. An exported `SECRETSPEC_PROVIDER` or
`SECRETSPEC_REASON` still applies to the command you are running, but is never
written into Git configuration, so a variable set for one shell session cannot
pin the helper to a provider or attribute every later fetch to an unrelated
reason. `login` and `logout` honour the exported variables as usual.

## Use a custom manifest

Custom Git helper configuration is available in SecretSpec 0.20+.

Pass `--file` when the credential should use declarations from a project or
company manifest. In this mode, `--token-secret` is required and
`--username-secret` and `--profile` are available:

```toml
[project]
name = "company-git"
revision = "1.0"

[profiles.default]
GITHUB_TOKEN = { description = "GitHub token for HTTPS authentication" }
```

```bash
$ secretspec set GITHUB_TOKEN --file company-git.toml
$ secretspec --file company-git.toml git configure \
  --url https://github.com \
  --token-secret GITHUB_TOKEN \
  --username YOUR_USERNAME
```

The managed helper records the custom manifest's absolute path and resolved
profile. Only a `--file` passed on the command line selects a custom manifest:
`secretspec git` ignores an exported `SECRETSPEC_FILE` so that a variable set
for a project cannot silently redirect credential configuration. Use ordinary
`secretspec set` and `delete` commands with the same file to manage custom
credential values; `git login` and `logout` intentionally operate only on the
embedded store and reject an explicit `--file`.

## Remove stored values

`secretspec git logout` is available in SecretSpec 0.20+.

Remove the embedded username and password or token for one exact target:

```bash
$ secretspec git logout https://github.com
```

This leaves the Git helper configured. Repeat `login` to replace the credential,
or use `unconfigure` when Git should stop invoking SecretSpec for that target.
If `login` used a provider override, pass the same override to `logout`.

## Remove the configuration

`secretspec git unconfigure` is available in SecretSpec 0.20+.

Remove one credential helper from the current repository:

```bash
$ secretspec git unconfigure --url https://github.com
```

Remove every Git credential helper that SecretSpec configured in the current
repository:

```bash
$ secretspec git unconfigure --all
```

Add `--global` to operate on global configuration. Global removal also defaults
to **No** and accepts `--yes` for non-interactive use:

```bash
$ secretspec git unconfigure --all --global
```

SecretSpec stores generated entries in its own included Git configuration
file. Configure and unconfigure never replace existing credential helpers,
usernames, or unrelated includes. Removing the final managed credential removes
the SecretSpec include and its file. If that file contains anything SecretSpec
does not recognize, the command refuses to modify it and asks you to inspect it
manually.

## Manual configuration

The Git credential helper is available in SecretSpec 0.20+.

The default convenience command is equivalent to registering the embedded
helper yourself. For example:

```bash
$ git config --local credential.https://github.com.username YOUR_USERNAME
$ git config --local credential.https://github.com.helper \
  'secretspec --url https://github.com --password-secret PASSWORD --username-secret USERNAME'
```

When configuring a path manually, set `useHttpPath` and use the same URL in the
helper:

```bash
$ git config --local credential.https://github.com/cachix.useHttpPath true
$ git config --local credential.https://github.com/cachix.helper \
  'secretspec --url https://github.com/cachix --password-secret PASSWORD --username-secret USERNAME'
```

These entries are not recorded in SecretSpec's managed file, so
`secretspec git unconfigure` does not remove them. Remove manually configured
entries with `git config` as well.

For SMTP, include the expected username in the helper command and keep
transport settings under `sendemail.*`:

```bash
$ git config --global credential.smtp://smtp.example.com:587.helper \
  "secretspec --url smtp://smtp.example.com:587 --username user@example.com \
  --password-secret PASSWORD --username-secret USERNAME"
```

## Read-only behavior

In SecretSpec 0.20+, the helper only answers Git's `get` operation. It safely
ignores automatic `store` and `erase` requests, so a rejected credential cannot
delete or overwrite a value in a shared provider. Manage embedded values
explicitly with `secretspec git login` and `logout`, or custom-manifest values
with `secretspec set` and `delete`.

Git can continue to try another configured helper or prompt when SecretSpec has
no stored value for the selected target.
