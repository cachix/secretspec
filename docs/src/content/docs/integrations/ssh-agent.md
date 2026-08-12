---
title: SSH agent
description: Use provider-backed OpenSSH private keys with SSH and Git without materializing key files
---

:::caution[Version compatibility]
The `ssh_private_key` type and `secretspec ssh-agent` integration are available
starting with SecretSpec 0.19.
:::

SecretSpec 0.19+ can expose stored OpenSSH private keys through a read-only SSH
agent. SSH and Git send signing requests through `SSH_AUTH_SOCK`; the child
process does not receive the private-key value or a temporary key file.

## Configure a key

Store the key in any provider that can return its complete OpenSSH private-key
value. This example uses a 1Password provider alias:

```toml title="secretspec.toml"
[providers]
team = "onepassword://Production"

[profiles.production]
# `type = "ssh_private_key"` requires SecretSpec 0.19+.
DEPLOY_SSH_KEY = {
  description = "Deployment SSH key",
  providers = ["team"],
  type = "ssh_private_key"
}
```

The stored value must begin with:

```text
-----BEGIN OPENSSH PRIVATE KEY-----
```

SecretSpec 0.19+ supports Ed25519, ECDSA, and RSA keys. RSA keys must be at
least 2048 bits, and RSA signatures always use RSA/SHA-2 (`rsa-sha2-256` or
`rsa-sha2-512`). The agent never issues a legacy `ssh-rsa` (SHA-1) signature, so
a server that accepts nothing newer cannot authenticate an RSA key through this
agent; use Ed25519 for those hosts. The stored key must not be
passphrase-encrypted because the agent is non-interactive.

## Run SSH or Git

The recommended form starts a private agent for exactly one command:

```bash
$ secretspec ssh-agent --profile production -- ssh deploy@example.com # 0.19+
```

Git uses OpenSSH for SSH remotes, so the same integration works without Git
configuration:

```bash
$ secretspec ssh-agent --profile production -- \
    git clone git@example.com:team/repo.git # 0.19+
```

SecretSpec 0.19+ sets `SSH_AUTH_SOCK` for the child and removes every advertised
key's secret-name variable from its environment. This includes a key read from
`env://` and a stale value inherited from the parent shell: the child can use
the key only through agent signing requests.

When the command exits, the agent exits with its status and removes its Unix
socket. On Unix, Ctrl-C and SIGTERM are forwarded to the command's process
group; SecretSpec waits for shutdown and force-terminates a command that does
not exit before cleaning up. Windows uses a private named pipe and terminates
the child on shutdown.

## Limit the available identities

Every `ssh_private_key` declaration in the active profile is advertised unless
a scope narrows the set. SecretSpec 0.19+ supports SSH-agent scopes:

```toml title="secretspec.toml"
[profiles.production]
# `type = "ssh_private_key"` requires SecretSpec 0.19+.
DEPLOY_SSH_KEY = { description = "Deployment key", providers = ["team"], type = "ssh_private_key" }
GIT_SIGNING_KEY = { description = "Git signing key", providers = ["team"], type = "ssh_private_key" }

[scopes.deploy]
secrets = ["DEPLOY_SSH_KEY"]
```

```bash
$ secretspec ssh-agent --profile production --scope deploy -- \
    ssh deploy@example.com # 0.19+
```

The scope controls which identities the agent advertises and which provider
keys it may retrieve. It does not change the provider route, native `ref` or
`refs` coordinates, cache policy, decoding, or extraction configured for those
keys.

## Run a foreground agent

Without a child command, SecretSpec 0.19+ stays in the foreground and prints the
shell assignment for its socket:

```bash
$ secretspec ssh-agent --profile production # 0.19+
SSH_AUTH_SOCK='/tmp/secretspec-agent-.../agent.sock'; export SSH_AUTH_SOCK
SecretSpec SSH agent is running in the foreground; press Ctrl-C to stop it.
```

Keep that process running and copy the printed assignment into the shell that
will run SSH or Git. Ctrl-C or SIGTERM stops the agent and removes its Unix
socket.

Use `--socket <PATH>` (0.19+) only when another process needs a predictable
address. On Unix, the socket's parent must be a real directory with mode
`0700`, and SecretSpec refuses to replace an existing path.

## Security model

- Possession of the socket grants signing access while the agent runs. Do not
  share it with untrusted users, processes, or containers.
- The agent advertises public identities, then retrieves only the selected
  private key for each signature. Parsed private-key material is dropped after
  the operation.
- Provider access follows the normal SecretSpec audit policy. Startup identity
  reads and signature reads are attributed to the provider endpoint and native
  reference that actually answered, including cache and fallback routes.
- The agent is read-only. Key addition, removal, locking, smart-card, and
  extension requests are rejected.
- Duplicate declarations containing the same public identity are rejected.

## Troubleshooting

### No SSH keys are available

Confirm that the active profile or scope contains at least one stored secret
with `type = "ssh_private_key"` (0.19+). A key cannot use `default`, enabled
`generate`, `prompt = true`, `as_path = true`, or `composed`.

### The key cannot be parsed

Check that the provider returns an OpenSSH private key, not a public key, PKCS#1
PEM key, or encrypted OpenSSH key. You can convert an existing key with
OpenSSH tooling before storing it, but do not write provider values to disk
just to diagnose a production secret.

### SSH does not select the expected key

Run a command inside the same agent boundary to inspect its public identities:

```bash
$ secretspec ssh-agent --profile production -- ssh-add -L # 0.19+
```

Then use `ssh -v` inside the same boundary to inspect SSH's identity selection.
Use a SecretSpec scope when the server or client should see only one of several
declared keys.

### An explicit socket path is rejected

On Unix, create a private parent directory first:

```bash
$ install -d -m 0700 "$XDG_RUNTIME_DIR/secretspec"
$ secretspec ssh-agent --socket "$XDG_RUNTIME_DIR/secretspec/agent.sock" # 0.19+
```

Remove only a stale path that you have verified is not owned by a running
agent. SecretSpec never replaces an existing socket automatically.

## Reference

- [`ssh-agent` command options (0.19+)](/reference/cli/#ssh-agent-019)
- [`ssh_private_key` configuration constraints (0.19+)](/reference/configuration/#ssh-agent-keys-019)
- [Scopes](/concepts/scopes/)
- [Audit logging](/concepts/audit/)
