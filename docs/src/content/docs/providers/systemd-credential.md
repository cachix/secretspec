---
title: systemd Credential Provider
description: Read secrets passed to a service through systemd credentials
---

:::caution[Version compatibility]
The `systemd-credential` provider is added in Monosecret 0.2.
:::

The systemd credential provider reads credentials that the service manager
passed to the current process. It is a read-only delivery provider: systemd
selects and optionally decrypts each credential before Monosecret starts, and
Monosecret reads the resulting file from `$CREDENTIALS_DIRECTORY`.

## At a glance

|                |                                                                        |
| -------------- | ---------------------------------------------------------------------- |
| Provider       | `systemd-credential` (0.2+)                                            |
| URI            | `systemd-credential://`                                                |
| Access         | Read-only                                                              |
| Best for       | Services that receive application or provider credentials from systemd |
| Authentication | Filesystem access granted by systemd to the service user               |
| Storage        | Immutable runtime files managed by systemd                             |

## Quick start

Declare a secret that reads from the credential with the same name:

```toml title="monosecret.toml"
[profiles.production]
DATABASE_PASSWORD = { description = "Production database password", providers = [
  "systemd-credential",
] }
```

Pass that credential to the service:

```ini title="/etc/systemd/system/myapp.service"
[Service]
LoadCredential=DATABASE_PASSWORD:/etc/myapp/database-password
Environment=MONOSECRET_PROFILE=production
ExecStart=/usr/bin/monosecret --file /etc/myapp/monosecret.toml run -- /usr/bin/myapp
```

systemd copies the value into the service's private credential directory.
Monosecret reads it there and resolves `DATABASE_PASSWORD` normally.

For confidential data stored in a unit or credential store, prefer
`LoadCredentialEncrypted=` or `SetCredentialEncrypted=`. systemd decrypts the
credential before Monosecret reads it, so the provider behaves the same way for
encrypted and plaintext sources.

## Setup

The process must be started by systemd with at least one service credential.
systemd sets `$CREDENTIALS_DIRECTORY` to an absolute directory containing one
immutable file per credential. Running the provider outside that execution
context returns an error explaining that the variable is missing.

The provider has no build feature and takes no URI configuration:

```toml
[providers]
service = "systemd-credential://"
```

An authority, path, or query on the URI is rejected. Select a differently named
credential with a secret reference instead.

## Use an existing credential name

Convention addresses use the Monosecret key as the systemd credential name and
do not include the project or profile. If the names differ, set `ref.item`:

```toml
[profiles.production]
DATABASE_PASSWORD = { description = "Production database password", providers = [
  "systemd-credential",
], ref = { item = "myapp.database-password" } }
```

```ini
[Service]
LoadCredential=myapp.database-password:/etc/myapp/database-password
```

Only the `item` coordinate is supported. Credential names must be a single
filename; nested paths and traversal components are rejected.

## Supply another provider's credential

Because `systemd-credential` is a regular read-only Monosecret provider, an
alias can use it as a provider-credential source:

```toml
[providers]
bootstrap = "systemd-credential://"
remote = {
  uri = "onepassword://Production",
  credentials = { service_account_token = "bootstrap" }
}
```

The service unit must pass a credential named `service_account_token`.
Monosecret reads it into memory and hands it directly to the target provider.

:::caution[Service isolation]
Every process in the same service runs under the same credential access
boundary. If `monosecret run` starts the application in that service, the
application can also access the service's credential directory. Put a
high-value bootstrap credential in a separate Monosecret broker or provisioning
service when the application itself must not be able to read it.
:::

## Storage and security model

This provider does not persist, encrypt, or decrypt values. Those properties
come from the systemd unit:

- `LoadCredential=` loads a file or socket source.
- `LoadCredentialEncrypted=` loads a systemd-encrypted credential.
- `SetCredentialEncrypted=` embeds encrypted credential data in the unit.
- `$CREDENTIALS_DIRECTORY` contains the plaintext runtime value while the
  service is active.

Monosecret refuses symlinks, directories, non-UTF-8 values, and credential
names that could escape the credential directory. Monosecret's provider API is
text-based; binary systemd credentials are therefore not supported.

Changing a source credential does not modify an already-running service's
immutable runtime credential. Restart the service to load the new value.
