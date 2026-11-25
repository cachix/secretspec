---
title: "Claude Code Stores OAuth Tokens in Plaintext"
description: On Linux, Claude Code protects MCP OAuth credentials with file permissions—not encryption. It should let users choose a real secret store.
date: 2026-09-02
authors:
  - domen
---

Claude Code's [MCP documentation says authentication tokens are “stored
securely”](https://code.claude.com/docs/en/mcp#authenticate-with-remote-mcp-servers).
On Linux, that currently means plaintext JSON protected by file permissions.

I checked Claude Code 2.1.257 after authenticating to several remote MCP
servers. The file `~/.claude/.credentials.json` had mode `0600`, as it should,
but it also contained a top-level `mcpOAuth` object with the access tokens.
Here is the shape of one Cloudflare entry, with every credential value
redacted:

```json title="~/.claude/.credentials.json"
{
  "mcpOAuth": {
    "cloudflare-observability|…": {
      "accessToken": "<redacted>",
      "clientId": "<redacted>",
      "discoveryState": "<redacted>",
      "redirectUri": "<redacted>",
      "serverName": "cloudflare-observability",
      "serverUrl": "<redacted>"
    }
  }
}
```

This matches Anthropic's [credential-management
documentation](https://code.claude.com/docs/en/team#credential-management).

- **macOS:** uses the encrypted macOS Keychain, falling back to
  `~/.claude/.credentials.json` when the Keychain is unavailable.
- **Linux:** uses `~/.claude/.credentials.json` with mode `0600`.
- **Windows:** uses `%USERPROFILE%\.claude\.credentials.json`, inheriting the
  access controls of the user's profile directory.

That is a much narrower claim than most people hear when a product says a
credential is “stored securely.”

## OAuth did not solve secret storage

The browser flow makes the secret easy to miss. Run `claude mcp login`, approve
access in the browser, and return to a connected MCP server. Nobody manually
created a token, copied it from a dashboard, or pasted it into a configuration
file.

But Claude Code still received a credential. It must persist that credential
if the connection is to survive a restart.

OAuth is valuable here. Claude Code can discover the authorization server,
request specific scopes, complete the authorization-code exchange, refresh an
access token, and revoke the grant. Anthropic's [MCP
documentation](https://code.claude.com/docs/en/mcp#authenticate-with-remote-mcp-servers)
also lets users pin the scopes Claude Code requests.

What OAuth does not specify is a secure local vault.

API tokens can also be scoped, limited to particular resources, assigned an
expiry, rotated, and revoked independently. OAuth standardizes delegation and
renewal, while avoiding the copy-and-paste ceremony. Those are substantial
benefits, but they do not turn the resulting bearer token into something that
is safe to leave in plaintext.

| Property | OAuth credential | Scoped API token |
| --- | --- | --- |
| Must be stored by the client | Yes | Yes |
| Can have limited permissions | Yes | Yes |
| Can expire | Yes | Yes |
| Can be revoked independently | Usually | Yes |
| Can be replayed if stolen | Yes | Yes |
| Standard interactive delegation | Yes | Provider-specific |
| Standard automatic renewal | Often | Usually external |

OAuth solves how Claude Code obtains and renews a delegated credential.
Secret storage solves what happens to that credential between uses. They are
separate concerns.

## Claude Code needs a credential-store interface

Claude Code should not decide that every Linux user's MCP tokens belong in the
same plaintext file. The persistence layer should be replaceable:

```text
Claude Code OAuth client
        │
        ▼
credential-store interface
        │
        ▼
SecretSpec TypeScript SDK
        │
        ▼
user-selected SecretSpec provider
```

The right integration point is the [SecretSpec Node.js / TypeScript
SDK](/sdk/nodejs/). It embeds the Rust resolver, so the TypeScript side does not
need bespoke code for each backend. Claude Code could serialize one MCP OAuth
credential per server and ask SecretSpec to load, save, or delete it using the
provider the user or organization selected.

SecretSpec 0.20 has [33 provider
integrations](/concepts/providers/#available-providers). They cover local
keyrings, password managers, encrypted files, cloud secret managers, and
deployment destinations. Providers declare their capabilities, so a credential
store can require readable and writable storage while still using the same
interface everywhere.

The current TypeScript SDK exposes SecretSpec's provider-independent resolver.
We would add the small `get`/`set`/`delete` credential-store surface Claude
Code needs rather than reimplement 33 integrations in its codebase.

For example, set the [system keyring](/providers/keyring/) as the default
provider in the local user configuration:

```bash
$ secretspec config global init --provider keyring --profile default
```

A team might instead require [OpenBao](/providers/openbao/) or a cloud secret
manager. A headless workstation might use an [age-encrypted
store](/providers/age/). The OAuth flow would stay exactly the same; only
persistence would change.

> **What Codex does:** Codex makes MCP OAuth storage configurable. Its
> [configuration
> reference](https://learn.chatgpt.com/docs/config-file/config-reference#mcp_oauth_credentials_store)
> documents `auto`, `file`, and `keyring` backends. Setting
> `mcp_oauth_credentials_store = "keyring"` selects the system keyring. This is
> not a general secret-provider interface, but it avoids making a plaintext
> credential file the only option on Linux.

> **Coming in SecretSpec 0.21:** We are working on [versioned resolver and
> provider IPC](https://github.com/cachix/secretspec/pull/362) for
> zero-dependency integrations. Applications will be able to use SecretSpec
> providers over a local protocol without embedding an SDK or provider code.

## Making open source software more secure

We are working to make open source tools retrieve credentials from a
user-selected secret store instead of copying them into another plaintext
file. SecretSpec now provides [Git](/integrations/git/) and
[Docker](/integrations/docker/) credential helpers, and we have proposed a
generic, operation-scoped [secret resolver interface for
Nix](https://github.com/NixOS/nix/pull/16339).

Because these projects are open source, we can inspect their credential
boundaries and contribute safer ones upstream.

We cannot make the equivalent fix in Claude Code. Its [public
repository](https://github.com/anthropics/claude-code) does not include the
core CLI implementation, and its [license is all rights
reserved](https://github.com/anthropics/claude-code/blob/main/LICENSE.md).
We can support the [open request for secure, pluggable credential
storage](https://github.com/anthropics/claude-code/issues/73582) and propose a
SecretSpec TypeScript integration, but only Anthropic can change Claude Code's
MCP OAuth storage today.

That is one of the practical security benefits of open source: when a secret
crosses the wrong boundary, users do not have to wait for the vendor to decide
that the boundary matters.
