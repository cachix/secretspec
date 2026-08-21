---
title: Secret Provider Protocol
description: Version 1 IPC contract for out-of-tree SecretSpec provider endpoints
---

The Secret Provider Protocol is the southbound IPC boundary between
SecretSpec's resolver and an out-of-tree provider endpoint. The endpoint
implements provider naming and storage operations while its database,
encryption, agents, hardware keys, grants, and remote APIs remain private.

It uses the [shared IPC wire protocol](/reference/ipc-wire) with application
protocol name `secretspec.provider` and version `1`.

:::caution[Version compatibility]
External provider discovery and Secret Provider Protocol version 1 are
available starting with SecretSpec 0.20. This specification replaces the
direction explored by the closed, unmerged
[provider protocol PR #98](https://github.com/cachix/secretspec/pull/98).
:::

## Provider model

A session is bound to exactly one configured provider URI. The endpoint may
retain connections and authentication state for that session, but must not
serve another URI or another SecretSpec client through the same process.

The protocol uses SecretSpec's two canonical address forms:

- a convention address: `{project, profile, key}`, which the provider compiles
  into its native namespace;
- a native address: the coordinates from a declaration's `ref`.

Routing is not part of the address. SecretSpec chooses the provider instance,
fallback chain, authoritative provider, and cache before making the request.
The endpoint sees only the operation for its bound provider.

Version 1 covers naming, reads, presence checks, writes, expiring writes,
idempotent deletion, bounded cache clearing, mutation preflight, batch reads,
write-target descriptions, and declaration reflection. Every optional method
is capability-gated.

## Discovery and registration

A provider URI scheme matches `^[a-z][a-z0-9-]*$`. A scheme compiled into the
SecretSpec binary always selects that in-tree provider; an external
registration must not shadow it. Every other scheme is resolved in this order:

1. an endpoint supplied directly through the embedding API;
2. a user registration named `<scheme>.json`;
3. a system registration named `<scheme>.json`;
4. a `PATH` executable named `secretspec-provider-<scheme>` (or
   `secretspec-provider-<scheme>.exe` on Windows), only when PATH discovery is
   explicitly allowed.

The registration document has the same format on every platform:

```json
{
  "schema_version": 1,
  "scheme": "example",
  "executable": "/absolute/path/to/secretspec-provider-example",
  "arguments": [],
  "credential_names": []
}
```

`executable` MUST be absolute. `arguments` are fixed non-secret strings; the
launcher invokes the executable directly without a shell. A registration must
not contain a provider URI, credential, secret address, or secret value.
`credential_names` contains distinct semantic names accepted in a provider
alias's `credentials` map. It lets SecretSpec perform its existing pure
credential-source validation before resolving those values; the endpoint must
reject any key not registered here.

Default registration directories are:

| Platform | User | System |
| --- | --- | --- |
| Linux | `$XDG_CONFIG_HOME/secretspec/providers.d`, falling back to `$HOME/.config/secretspec/providers.d` | `/etc/secretspec/providers.d` |
| macOS | `$HOME/Library/Application Support/SecretSpec/providers.d` | `/Library/Application Support/SecretSpec/providers.d` |
| Windows | `%APPDATA%\SecretSpec\providers.d` | `%PROGRAMDATA%\SecretSpec\providers.d` |

The loader MUST validate the file name against `scheme`, reject unknown
registration fields, resolve the executable to an absolute canonical path, and
check that registration and executable ownership/ACLs are appropriate for the
trust domain. A privileged resolver MUST disable PATH discovery. A manifest may
select a registered scheme and URI but must never supply an executable path or
arguments.

On Unix the ownership and permission checks apply to every directory above the
endpoint, not only its immediate parent: a single writable ancestor lets an
attacker replace a component with a symlink to any executable that satisfies
the checks below it. Because the checks run over the resolved path, a symlinked
component is validated as the chain it points at, so the common cases where a
symlink is how software is installed — a Nix store path, macOS's `/var` — keep
working. A world-writable ancestor is trusted only when it is sticky, which
stops anyone but the owner replacing an entry inside it.

Windows applies the same full canonical-ancestor rule through ACL validation.
The executable and every directory above it must deny untrusted principals the
rights that permit replacement, including directory write access and
`FILE_DELETE_CHILD`; validating only the executable or its immediate parent is
not sufficient. The walk follows the canonical path so junctions and other
reparse points are checked where they resolve.

Once resolved, the executable identity is fixed for the session. Replacing a
registration file or changing PATH does not replace a running endpoint.

## Starting and initializing an endpoint

The host launches one child with private stdin/stdout pipes and immediately
sends `rpc.initialize`. The full initialization request follows the
[wire protocol](/reference/ipc-wire#initialization-and-capabilities).
Its `application` member is:

```json
{
  "scheme": "example",
  "uri": "example://default",
  "base_dir": "/absolute/project/directory",
  "credentials": {},
  "reason": "deploy production api"
}
```

Rules:

- `scheme` is the validated URI scheme used for discovery.
- `uri` is the original configured provider URI. It is sensitive input and is
  never logged or echoed because it may contain credentials.
- `base_dir` is the absolute directory against which provider-relative paths
  are resolved, or null when the provider has no project base directory.
- `credentials` maps registered semantic credential names to secret strings. The host
  obtains them through SecretSpec's provider-credential mechanism. They are
  sent in the private inherited pipe, never argv or protocol
  environment variables.
- `reason` is the session-wide access reason or null. An endpoint needing a
  different reason must use another session.
- The endpoint MUST reject a URI whose scheme differs from `scheme`.

The provider does not receive `config_file` and does not reread arbitrary
SecretSpec manifests. Provider-specific configuration belongs in the provider
URI, registered endpoint configuration, or a future explicitly typed
capability. This keeps the provider boundary deterministic and prevents an
endpoint from acquiring declarations outside the operation it was sent.

### Interaction model

Protocol stdin and stdout are exclusively reserved for framed IPC messages.
An endpoint MUST NOT read unframed user input from stdin, write prompts or
instructions to stdout, or rely on stderr as a user-interaction channel.

An endpoint MAY complete authentication through a provider-owned channel that
is independent of the protocol streams, such as an existing desktop agent,
browser session, hardware confirmation prompt, or operating-system credential
UI. That interaction consumes the request deadline.

If the operation cannot complete without unavailable user interaction, the
endpoint MUST return `interaction_required`. It MUST NOT include backend error
text or provider-supplied remediation instructions in the error response.

The host MUST NOT automatically replay the failed request. After the user
completes authentication out of band, the caller MAY explicitly issue a new
request with a fresh request ID. Configuration or credentials that changed
require a newly initialized provider session.

A host or CLI MAY display locally authored remediation selected from the
trusted provider scheme. Such instructions are product behavior and are not
provider-protocol data.

A successful initialization response includes this `application` object:

```json
{
  "provider": {
    "name": "example",
    "display_uri": "example://default",
    "supported_coordinates": ["field"],
    "generated_value_persistence": "persist",
    "prompted_value_persistence": "persist",
    "storage_identity": "example://default",
    "entry_container_identity": "example://default",
    "physical_store_path": null
  }
}
```

Metadata rules:

- The top-level initialization result `capabilities` list advertises the
  provider methods supported by the endpoint. It is the only
  operation-capability list; the `provider` metadata object does not duplicate
  it.
- `name` is lowercase and matches the registered provider scheme unless the
  registration explicitly aliases a protocol-compatible provider.
- `display_uri`, `storage_identity`, and `entry_container_identity` MUST be
  credential-free and MUST NOT contain secret names or values.
- `supported_coordinates` lists any accepted native coordinate beyond the
  required `item`. Version 1 names are `field`, `vault`, `section`, and
  `version`.
- persistence values are `persist` or `ephemeral` and map to the corresponding
  `Provider` trait methods. They are pure capability metadata.
- `physical_store_path` is an absolute path or null. The host treats it as
  provider-supplied identity metadata and applies its ordinary same-file rules.
- `provider.resolve_address` is mandatory. At least one of `provider.get`,
  `provider.exists`, or `provider.set` MUST be present.

The endpoint is ready when this response has been validated. Authentication or
unlock that requires I/O may stay lazy until the first operation.

## Address schema

Every operation uses one of these closed tagged objects.

Convention address:

```json
{
  "kind": "convention",
  "project": "payments",
  "profile": "production",
  "key": "DATABASE_PASSWORD"
}
```

Native address:

```json
{
  "kind": "native",
  "coordinates": {
    "item": "databases/payments",
    "field": "password",
    "vault": "Production",
    "section": null,
    "version": null
  }
}
```

All strings are UTF-8 and individually limited to 4,096 bytes. `item` is
required and must be non-empty. Optional coordinates may be omitted or null;
the two forms are equivalent. Unknown coordinates are rejected. An endpoint
MUST reject a present coordinate it did not advertise in
`supported_coordinates`.

The endpoint must use one address resolution path for `get`, `exists`, `set`,
`set_expiring`, `delete`, preflight, and identity comparisons. It must never
guess how to translate an unsupported native coordinate.

## Operation summary

| Method | Capability | Result |
| --- | --- | --- |
| `provider.resolve_address` | Required | Canonical native coordinates |
| `provider.get` | `provider.get` | Found value or miss |
| `provider.get_many` | `provider.get_many` and `provider.get` | Per-name found value or miss |
| `provider.exists` | `provider.exists` | Presence without exposing a value |
| `provider.set` | `provider.set` | Stored |
| `provider.set_expiring` | `provider.set_expiring` and `provider.set` | Stored with backend lifetime bound |
| `provider.delete` | `provider.delete` | Idempotent deleted/not present |
| `provider.clear` | `provider.clear` | Idempotent bounded bulk invalidation |
| `provider.check_writable` | `provider.check_writable` | Address-specific mutation preflight |
| `provider.check_deletable` | `provider.check_deletable` | Address-specific deletion preflight |
| `provider.describe_write_target` | `provider.describe_write_target` | Non-secret destination description |
| `provider.reflect` | `provider.reflect` | Value-free declarations |

No data operation is implicitly mandatory. A write-only CI secret sink can
advertise `set`, `exists`, `delete`, and `reflect` without `get`. The host MUST
fail a value read with `capability_required`; it must never turn the absence of
`get` into a false miss.

## Resolve an address

`provider.resolve_address` compiles a convention address or validates a native
address and returns the exact native coordinates used by all operations. It
backs `Provider::convention_address`, `Provider::entry_coordinates`, and
destructive same-entry checks.

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "provider.resolve_address",
  "_meta": { "deadline_unix_ms": 1786766405000 },
  "params": {
    "address": {
      "kind": "convention",
      "project": "payments",
      "profile": "production",
      "key": "DATABASE_PASSWORD"
    }
  }
}
```

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "coordinates": {
      "item": "payments/production/DATABASE_PASSWORD",
      "field": null,
      "vault": null,
      "section": null,
      "version": null
    }
  }
}
```

The result is naming only and must not perform provider I/O. Repeated calls
with the same initialized session and address MUST return the same coordinates.

## Read operations

### `provider.get`

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "provider.get",
  "_meta": { "deadline_unix_ms": 1786766405000 },
  "params": {
    "address": {
      "kind": "native",
      "coordinates": { "item": "database", "field": "password" }
    }
  }
}
```

A hit and a miss are successful, distinct results:

```json
{ "jsonrpc": "2.0", "id": 3, "result": { "status": "found", "value": "secret text" } }
```

```json
{ "jsonrpc": "2.0", "id": 3, "result": { "status": "missing" } }
```

An unavailable, unauthorized, malformed, or otherwise failed lookup is an
error, never `missing`.

### `provider.get_many`

Batch reads carry names only as correlation keys. Each address retains its
canonical form and a batch may mix convention and native addresses.

```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "provider.get_many",
  "_meta": { "deadline_unix_ms": 1786766405000 },
  "params": {
    "requests": [
      {
        "name": "DATABASE_PASSWORD",
        "address": {
          "kind": "native",
          "coordinates": { "item": "database", "field": "password" }
        }
      },
      {
        "name": "API_TOKEN",
        "address": {
          "kind": "convention",
          "project": "payments",
          "profile": "production",
          "key": "API_TOKEN"
        }
      }
    ]
  }
}
```

```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "result": {
    "results": [
      { "name": "DATABASE_PASSWORD", "status": "found", "value": "secret text" },
      { "name": "API_TOKEN", "status": "missing" }
    ]
  }
}
```

The request and response preserve input order and contain one result per input
name. Names MUST be unique and there may be at most 1,024 requests. Identical
addresses should be fetched once and share the outcome. A backend failure fails
the whole batch; version 1 has no partial per-item errors.

When `provider.get_many` is absent, the host performs bounded concurrent
`provider.get` calls. It must honor the negotiated in-flight limit.

### `provider.exists`

Presence checks support providers that can list names but intentionally cannot
return values, such as CI secret sinks.

```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "provider.exists",
  "_meta": { "deadline_unix_ms": 1786766405000 },
  "params": {
    "address": {
      "kind": "convention",
      "project": "payments",
      "profile": "production",
      "key": "DEPLOY_TOKEN"
    }
  }
}
```

```json
{ "jsonrpc": "2.0", "id": 5, "result": { "exists": true } }
```

When `exists` is absent but `get` is available, the adapter may implement a
presence check with `get` and discard the value in zeroizing storage. It must
not do the reverse: an `exists: true` result cannot satisfy a value read.

## Write operations

### `provider.set`

```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "method": "provider.set",
  "_meta": { "deadline_unix_ms": 1786766405000 },
  "params": {
    "address": {
      "kind": "native",
      "coordinates": { "item": "database", "field": "password" }
    },
    "value": "new secret text"
  }
}
```

```json
{ "jsonrpc": "2.0", "id": 6, "result": { "stored": true } }
```

The endpoint MUST apply the same address policy as
`provider.check_writable`. A successful response means a subsequent operation
in the same backend consistency domain can observe the write.

### `provider.set_expiring`

```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "method": "provider.set_expiring",
  "_meta": { "deadline_unix_ms": 1786766405000 },
  "params": {
    "address": {
      "kind": "native",
      "coordinates": { "item": "database", "field": "password" }
    },
    "value": "cached secret text",
    "ttl_ms": 3600000
  }
}
```

```json
{ "jsonrpc": "2.0", "id": 7, "result": { "stored": true } }
```

`ttl_ms` is a positive integer. Its interval begins when the endpoint accepts
the request. An endpoint advertising this capability MUST ensure the stored
copy becomes unavailable no later than that interval, including without
another SecretSpec process running. It may expire it earlier only if the
backend's documented precision requires rounding.

When this capability is absent, the external adapter follows the embedded
`Provider::set_expiring` fallback policy and calls ordinary `set` only when the
SecretSpec cache layer remains the freshness authority. A caller that requires
store-enforced expiry must check the capability and fail closed.

### `provider.delete`

```json
{
  "jsonrpc": "2.0",
  "id": 8,
  "method": "provider.delete",
  "_meta": { "deadline_unix_ms": 1786766405000 },
  "params": {
    "address": {
      "kind": "native",
      "coordinates": { "item": "database", "field": "password" }
    }
  }
}
```

```json
{ "jsonrpc": "2.0", "id": 8, "result": { "deleted": false } }
```

Deletion is idempotent. `deleted` is true only when this request removed an
existing entry; an absent entry is a successful `false` result.

### `provider.clear`

`clear` is an optional bulk invalidation operation intended for providers that
act as caches. Its scope is always bounded by the provider URI used to
initialize the endpoint.

Clear all entries owned by that configured provider instance:

```json
{
  "jsonrpc": "2.0",
  "id": 9,
  "method": "provider.clear",
  "_meta": { "deadline_unix_ms": 1786766405000 },
  "params": {
    "scope": { "kind": "all" }
  }
}
```

Clear one convention namespace:

```json
{
  "jsonrpc": "2.0",
  "id": 9,
  "method": "provider.clear",
  "_meta": { "deadline_unix_ms": 1786766405000 },
  "params": {
    "scope": {
      "kind": "convention",
      "project": "payments",
      "profile": "production"
    }
  }
}
```

```json
{ "jsonrpc": "2.0", "id": 9, "result": { "cleared": 12 } }
```

Clear is idempotent. `cleared` is the number of entries actually removed.
`all` MUST NOT mean an entire account, vault, or agent unless the initialized
provider URI itself denotes exactly that bounded namespace. An endpoint unable
to prove the bound must reject the request with `conflict`.

The current Rust `Provider` trait has no bulk-clear method. Implementing this
capability requires adding a capability-aware `clear` seam or routing it only
through the external cache adapter. It must not be simulated by enumerating an
unbounded backend.

## Mutation preflight

Address-specific policies require optional preflight calls:

```json
{
  "jsonrpc": "2.0",
  "id": 10,
  "method": "provider.check_writable",
  "_meta": { "deadline_unix_ms": 1786766405000 },
  "params": {
    "address": {
      "kind": "native",
      "coordinates": { "item": "database", "version": "3" }
    }
  }
}
```

A writable/deletable address returns `{}`. A refusal uses
`permission_denied`, `conflict`, or `capability_required` without echoing the
address. `provider.set`/`set_expiring` and `provider.delete` MUST enforce the
same decision even if the host skipped preflight.

If the endpoint advertises a mutation but not its preflight capability, the
adapter treats the operation capability as a global preflight success. This is
appropriate only when every accepted address has the same policy.

## Describe a write target

`provider.describe_write_target` returns the non-secret destination shown
before a CLI prompt:

```json
{
  "jsonrpc": "2.0",
  "id": 11,
  "method": "provider.describe_write_target",
  "_meta": { "deadline_unix_ms": 1786766405000 },
  "params": {
    "address": {
      "kind": "convention",
      "project": "payments",
      "profile": "production",
      "key": "DATABASE_PASSWORD"
    }
  }
}
```

```json
{
  "jsonrpc": "2.0",
  "id": 11,
  "result": { "description": "Example provider namespace payments/production" }
}
```

The description MUST NOT contain a secret value, credential, full sensitive
URI, or data obtained by reading the backing store. When the capability is
absent, the adapter renders the coordinates returned by
`provider.resolve_address`.

## Reflect declarations

`provider.reflect` discovers declarations without returning their values:

```json
{
  "jsonrpc": "2.0",
  "id": 12,
  "method": "provider.reflect",
  "_meta": { "deadline_unix_ms": 1786766405000 },
  "params": {
    "project": "payments",
    "profile": "production"
  }
}
```

```json
{
  "jsonrpc": "2.0",
  "id": 12,
  "result": {
    "schema_version": 1,
    "declarations": {
      "DATABASE_PASSWORD": {
        "description": "Discovered from the example provider",
        "required": true,
        "ref": { "item": "database", "field": "password" }
      }
    }
  }
}
```

Declaration objects use the version 1 SecretSpec secret-declaration schema.
They MUST NOT contain `default`, generated values, provider values, credentials,
or values disguised as descriptions. Discovery must be bounded by the supplied
project/profile and provider URI. Empty results are successful.

## Lifecycle, reconnect, and concurrency

- One endpoint process serves one provider URI and one reason.
- Successful `rpc.initialize` is readiness on Linux, macOS, and Windows.
- The endpoint must keep reading while operations run, accept cancellation,
  and enforce the negotiated in-flight limit.
- EOF, `rpc.shutdown`, or host death closes backend sessions and zeroizes
  credentials and values held for the session.
- Shutdown has a 5-second maximum grace period before platform process
  termination.
- A crashed endpoint may be relaunched for a later request. The host MUST NOT
  automatically replay the request that observed the disconnect. `get` can
  unlock, prompt, refresh, or audit; mutations may already have committed.
- A new endpoint receives a new initialization exchange. Request IDs,
  authentication state, and any endpoint-local replay cache are not reused.

Exactly one terminal response is guaranteed as described by the wire protocol;
exactly-once backend execution is not. Endpoints should make `set` naturally
idempotent for one address/value where their backend permits it. `delete` and
`clear` are required to be idempotent.

## Errors and redaction

Provider endpoints map failures to the common
[structured errors](/reference/ipc-wire#errors). Recommended mappings are:

| Provider condition | Kind |
| --- | --- |
| Invalid or unsupported address | `invalid_params` |
| Method not advertised | `capability_required` |
| Authenticated caller lacks a grant | `permission_denied` |
| Unlock or interactive login needed | `interaction_required` |
| Temporary backend outage or capacity limit | `unavailable` |
| Version-pinned write, ambiguous clear, or same-entry conflict | `conflict` |
| Other backend failure | `operation_failed` |

Backend error text is not stable and may contain values, names, URLs, HTTP
bodies, paths, or account data. An endpoint MUST NOT copy it into the IPC
`message`, `data`, stdout diagnostics, or stderr. Logs use method, request ID,
duration, and stable error kind only; whether secret names are safe is not left
to individual providers.

## Authorization boundary

The stdio pipes authenticate possession of the child-process handles; they do
not authenticate an original application to a provider-owned service behind
the endpoint.

For version 1, the installed provider endpoint executable is the principal for
that second hop. A provider-owned service can therefore grant operations to the
exact endpoint executable it authenticates over its native transport.

The endpoint MUST NOT accept `application_id`, executable path, PID, user ID,
or signer identity from the provider request and forward it as authenticated
identity. No such field exists in version 1. Per-application grants across both
hops require the cryptographic delegation described in the
[IPC architecture](/reference/ipc-architecture#principal-and-delegation-decision).

This decision also means every process able to control or legitimately invoke
the authorized endpoint can exercise its service grant. Package permissions
and endpoint registration are therefore part of the security boundary.
