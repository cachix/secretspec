---
title: Secret Resolution Protocol
description: Version 1 IPC contract between an SDK or application and the SecretSpec broker
---

The Secret Resolution Protocol is the northbound IPC boundary between an
application and a complete SecretSpec resolver. It lets a consumer resolve one
declared name without linking SecretSpec or any provider SDK into the consumer.

It uses the [shared IPC wire protocol](/reference/ipc-wire) with application
protocol name `secretspec.client` and version `1`.

:::caution[Version compatibility]
The Secret Resolution Protocol and `secretspec broker --stdio` are available
starting with SecretSpec 0.20.
:::

## Scope

Version 1 deliberately exposes less than the embedded Rust API:

- bind one session to a fixed manifest, provider override, profile, scope, and
  access reason;
- resolve one exact declared secret name and only its composed dependencies;
- return an inline UTF-8 value or a broker-owned temporary file;
- release file leases explicitly or by closing the session.

The broker owns manifest parsing, inheritance, routing, caching, generation,
prompting, composition, audit events, provider credentials, and provider IPC.
Those internals are not represented in this protocol.

Whole-profile resolution, mutation, provider enumeration, and arbitrary
manifest queries are not part of `secretspec.client/1`. Existing SDKs that need
the complete embedded API continue to use the Rust core or `libsecretspec`.
New client methods can be added behind capabilities after their least-authority
semantics are specified.

## Starting the broker

The version 1 broker transport is a directly launched child:

```text
secretspec broker --stdio
```

The executable and arguments come from trusted application or administrator
configuration. The launcher MUST invoke the executable directly rather than
through a shell. A privileged caller MUST use an absolute executable path and
must not let a project manifest, flake, repository, or working directory
select it. An interactive unprivileged SDK may resolve `secretspec` through its
normal installation mechanism.

The caller sends `rpc.initialize` immediately and applies a 5-second startup
timeout by default. A successful response is the readiness signal. The broker
must not open a global socket, daemonize, or detach from its parent in stdio
mode.

Protocol stdin and stdout are exclusively reserved for framed IPC messages.
The stdio broker MUST NOT prompt through stdin, stdout, or stderr. Secret
Resolution Protocol version 1 defines no user-interaction channel. Resolution
may wait for an independent provider-owned interaction channel within the
request deadline; when no such channel is available, the broker returns
`interaction_required`. Neither the broker nor the client automatically
replays that request.

## Session initialization

The initialization `application` object fixes the resolver configuration for
the lifetime of the connection:

```json
{
  "manifest": {
    "kind": "path",
    "path": "/home/alice/project/secretspec.toml"
  },
  "provider": null,
  "profile": "production",
  "scope": "deploy",
  "reason": "build api container"
}
```

`manifest` is one of:

```json
{ "kind": "path", "path": "/absolute/path/secretspec.toml" }
```

```json
{
  "kind": "inline",
  "toml": "[project]\nname = \"example\"\nrevision = \"1.0\"\n",
  "base_dir": "/absolute/project/directory"
}
```

Rules:

- A path and an inline `base_dir` MUST be absolute and lexically normalized by
  the client. The broker resolves filesystem identity and symlinks according to
  the same rules as the embedded resolver.
- Working-directory discovery is not supported. The broker's working directory
  must never select a manifest implicitly.
- `provider`, when non-null, is the same provider override accepted by the
  embedded `Secrets` builder. The broker treats it as sensitive because an
  input URI may contain credentials even though provider display URIs may not.
- `profile`, `scope`, and `reason` are nullable strings with the embedded API's
  meaning. Null requests the resolver's configured/default value; it does not
  consult a broker-specific environment variable.
- The complete object is immutable after initialization. A caller needing
  another profile, scope, reason, or manifest opens another session.
- Inline TOML is sensitive transport data because a manifest can contain
  defaults. It must never be logged.

The broker parses and validates the configuration before returning successful
initialization. Provider I/O remains lazy until a resolve request. On success,
the initialization response contains:

```json
{
  "manifest_kind": "path",
  "supports_inline_manifest": true
}
```

The response does not echo paths, configuration, provider URIs, profile names,
scope names, or reasons.

The server-advertised application capabilities MUST include:

- `client.resolve`
- `client.release`

## Resolve an exact name

`client.resolve` resolves one exact name on the session's active profile and
scope. The broker uses the same least-access behavior as
`Secrets::resolve_named`: an unrelated required secret cannot fail the request,
and only composition inputs of the requested secret may be read.

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "client.resolve",
  "deadline_unix_ms": 1786766405000,
  "params": {
    "name": "FORGE_TOKEN",
    "representation": "value",
    "purpose": {
      "consumer": "nix",
      "operation": "fetch",
      "host": "github.com",
      "path": "/acme/project"
    }
  }
}
```

`name` is a SecretSpec declaration name, not a provider-native address. It is
validated exactly as a manifest name and MUST fit within 4,096 UTF-8 bytes.

`representation` is:

| Value | Behavior |
| --- | --- |
| `auto` | Return the representation selected by the declaration's `as_path` setting |
| `value` | Require an inline value; fail with `representation_mismatch` for an `as_path` declaration |
| `file` | Require an `as_path` file; fail with `representation_mismatch` for an inline declaration |

Requiring the representation prevents a token consumer from accidentally
using a path as a token, or a file consumer from treating secret contents as a
path.

`purpose` is mandatory attribution for this call. `consumer` and `operation`
are non-empty strings of at most 256 UTF-8 bytes. `host` and `path` are optional
strings of at most 4,096 bytes; omit them when they do not apply. The broker may
include this context in its protected audit event, but must otherwise treat it
as sensitive metadata.

Purpose is not identity. The broker and providers MUST NOT use these
caller-supplied strings for authorization, and purpose does not satisfy a
manifest's required access `reason`. In particular, a provider-owned agent must
not treat `consumer: "nix"` or a forwarded path as authenticated delegation.

### Undeclared

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": { "status": "undeclared" }
}
```

The name is absent from the active profile or hidden by the active scope. These
cases intentionally have the same result so a scope does not reveal names it
hides. No provider is contacted.

### Missing

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "status": "missing",
    "required": true
  }
}
```

The declaration is visible but produced no value. This is a domain result, not
a transport error. The caller decides whether a missing required value is
fatal for its operation.

### Inline value

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "status": "resolved",
    "representation": "value",
    "value": "secret text",
    "source": "provider",
    "source_provider": "keyring://",
    "expires_at_unix_ms": null
  }
}
```

`source` is one of `provider`, `generated`, `default`, or `composed`.
`source_provider` is present only for provider results and MUST be the
credential-free display URI returned by `Provider::uri()`.
`expires_at_unix_ms` is required and null when the resolver knows no expiry;
otherwise it is the absolute Unix-millisecond time after which the caller must
discard the result. A fresh SecretSpec cache envelope supplies this timestamp;
legacy authoritative providers whose read API exposes no expiry return null.
It describes value freshness, not a file lease: a leased file must still be
released even if its value expires, and release may remove it earlier.

The result carries secret data. The client should copy it directly into its
final protected destination and release its JSON/frame buffers promptly.

### Leased file

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "status": "resolved",
    "representation": "file",
    "path": "/run/user/1000/secretspec/session-random/secret-random",
    "lease_id": "Qk7jXGfOLpLzmvYxjOxvMw",
    "source": "provider",
    "source_provider": "file:./credentials",
    "expires_at_unix_ms": 1786770000000
  }
}
```

The broker, not the client, owns the file. `lease_id` is an unpredictable,
session-local opaque token containing at least 128 bits of randomness. The
client must not parse it and must not send it on another connection.

On POSIX systems, the broker creates a mode-0700 session directory and a
mode-0400 regular file owned by the broker user. It must defend against
symlinks and path replacement. On Windows, the directory and file receive a
non-inheriting ACL limited to the broker user and required system identities.
The response path is absolute.

The broker retains the file until the first of:

- every lease referring to it has been released;
- the client disconnects;
- `rpc.shutdown` cleans the session;
- the broker exits.

If resolution is cancelled, its deadline expires, or its result cannot be
written, any newly created file is removed without creating a client-visible
lease. Broker startup should remove abandoned directories created by earlier
crashes only after verifying ownership, type, and a conservative age bound.

## Release file leases

`client.release` releases one or more leases:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "client.release",
  "deadline_unix_ms": 1786766406000,
  "params": {
    "lease_ids": ["Qk7jXGfOLpLzmvYxjOxvMw"]
  }
}
```

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": { "released": 1 }
}
```

Release is idempotent. An unknown, already released, or duplicate lease ID is a
successful no-op and is not included in `released`. One request may contain at
most 256 IDs.

SDK destructors MUST NOT perform an unbounded blocking call. They should queue
lease IDs in session-owned memory and flush them on an explicit close, the next
safe IPC call, or bounded session shutdown. Disconnect remains the final
cleanup mechanism.

## Failure mapping

The common [error table](/reference/ipc-wire#errors) is deliberately smaller
than `SecretSpecError`. Broker implementations map errors as follows:

| Resolver condition | IPC result or error |
| --- | --- |
| Name absent or hidden by scope | `status: undeclared` result |
| Visible declaration has no value | `status: missing` result |
| Wrong requested representation | `representation_mismatch` |
| Reason policy requires interaction with no available channel | `interaction_required` |
| Provider authorization refusal | `permission_denied` |
| Provider temporarily unreachable | `unavailable` only when retry safety is known; otherwise `operation_failed` |
| Manifest, profile, scope, generation, composition, or other resolver error | `operation_failed` |

The broker may retain a full local error for protected diagnostics, but the IPC
error must follow the wire protocol's redaction rules. In particular, it must
not serialize `SecretSpecError::to_string()` directly.

## Reconnect and retry

A child exit or broken pipe fails every in-flight request with a local
transport error and invalidates every lease. The client may launch a fresh
broker for later work, but it MUST NOT replay the failed request
automatically. Reads can prompt, generate and persist a secret, refresh a
cache, or emit an audit event, so even `client.resolve` is not assumed free of
side effects.

The new process performs initialization from the beginning. Session state,
request IDs, and lease IDs are never reused.

## SDK integration policy

The wire contract, not either implementation API, is canonical. SDKs have three supported runtime
strategies:

1. Keep embedding the Rust resolver, as existing SDKs do today.
2. Use the Rust `secretspec-ipc` client for Rust broker mode.
3. Bind the pure-C `libsecretspec-ipc` client for non-Rust broker mode.

Independent implementations may implement the canonical wire protocol directly,
but supported non-Rust SecretSpec SDKs must not create per-language client state
machines. The Rust and C clients pass the same language-neutral conformance
suite and differential tests. Language packages expose the backend choice
explicitly; silently changing an embedded SDK to launch a process would alter
deployment, prompting, lifecycle, and trust behavior.
