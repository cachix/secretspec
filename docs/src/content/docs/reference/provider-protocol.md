---
title: Secret Provider Protocol (v1)
description: Wire-format specification for out-of-tree secretspec providers, exchanged as line-delimited JSON over stdio.
---

A wire-format specification for out-of-tree secretspec providers. Plugins implementing this protocol are discovered as subprocess binaries on `$PATH` and exchange line-delimited JSON over stdio. The protocol is transport-agnostic at the JSON level; the v1 transport is stdio.

This document uses the keywords MUST, SHOULD, and MAY per RFC 2119.

:::caution
This specification is a **draft proposal**. It is not yet implemented in the host. See [issue #64](https://github.com/cachix/secretspec/issues/64) for the design discussion.
:::

## 1. Discovery

A provider URI scheme `<scheme>://...` is bound to a plugin binary named `secretspec-provider-<scheme>`. The host locates the binary by searching `$PATH` in order; the first match wins.

The scheme MUST match `^[a-z][a-z0-9_-]*$`. Hyphens in the scheme map literally to hyphens in the binary name (`opproxy://` resolves to `secretspec-provider-opproxy`).

If no binary is found, the host MUST return an error to the caller distinguishing "plugin not installed" from "plugin returned an error."

## 2. Invocation model

The host spawns the plugin once per session. A session corresponds to a single resolution pass (e.g., one `secretspec run`, one `secretspec check`). Within a session the plugin MAY process any number of requests.

On spawn, the host sets the following environment variables:

| Variable | Value |
|---|---|
| `SECRETSPEC_PROTOCOL_VERSION` | Highest protocol version the host supports (e.g., `1`) |
| `SECRETSPEC_PROVIDER_URI` | The full URI that selected this plugin |

No command-line arguments are passed in v1. The host MUST NOT pass secrets via `argv` or environment.

The plugin reads newline-delimited JSON requests from stdin and writes newline-delimited JSON responses to stdout. The plugin exits on stdin EOF or after responding to a `bye` request. Stderr is free-form and the host MUST NOT parse it; plugins SHOULD use stderr for diagnostic output only and MUST NOT write secret values to stderr.

The host closes stdin to signal end-of-session. The plugin SHOULD exit within 5 seconds of stdin EOF; the host MAY send `SIGTERM` and then `SIGKILL` after a grace period.

## 3. Wire format

Each request and each response is exactly one JSON object terminated by a single `\n`. Embedded newlines inside JSON strings MUST be escaped per RFC 8259. The encoding is UTF-8.

The host MUST NOT pipeline: it sends one request, waits for the matching response, then sends the next. Responses MUST appear on stdout in the same order as their requests.

## 4. Handshake

The first request in every session is `hello`. The plugin MUST NOT process any other request before responding to `hello`.

**Request:**

```json
{
  "op": "hello",
  "protocol_version": 1,
  "uri": "opproxy://vault/Production?reason=build",
  "context": { "reason": "building api image" }
}
```

**Successful response:**

```json
{
  "ok": true,
  "protocol_version": 1,
  "name": "opproxy",
  "capabilities": ["get", "set", "batch_get", "reflect"]
}
```

The plugin's `protocol_version` MUST be less than or equal to the host's. If the plugin cannot support the host's version, it responds with an error of kind `unsupported_version` and exits.

The plugin advertises its supported operations in `capabilities`. The host MUST NOT send an operation absent from this list. `get` is mandatory; all others are optional.

## 5. Operations

All requests carry `"op": "<name>"`. All successful responses carry `"ok": true`; failures carry `"ok": false` and an `error` object (see section 6).

### 5.1 get

Retrieves a single secret.

**Request:**

```json
{ "op": "get", "project": "myapp", "key": "DATABASE_URL", "profile": "production" }
```

**Response (hit):**

```json
{ "ok": true, "value": "postgres://..." }
```

**Response (miss):**

```json
{ "ok": true, "value": null }
```

A miss is distinct from an error. Missing secrets MUST return `value: null`, not an error.

### 5.2 set

Stores a single secret. Only callable if the plugin advertised the `set` capability.

**Request:**

```json
{ "op": "set", "project": "myapp", "key": "DATABASE_URL", "value": "postgres://...", "profile": "production" }
```

**Response:**

```json
{ "ok": true }
```

### 5.3 batch_get

Retrieves multiple secrets in a single round trip. Only callable if the plugin advertised the `batch_get` capability. The host SHOULD use `batch_get` over repeated `get` calls when fetching more than one secret.

**Request:**

```json
{ "op": "batch_get", "project": "myapp", "profile": "production", "keys": ["DB_URL", "API_KEY"] }
```

**Response:**

```json
{ "ok": true, "values": { "DB_URL": "postgres://...", "API_KEY": null } }
```

Missing keys MUST appear in `values` with a `null` value. Partial failure (some keys retrievable, some not) is reported as a top-level error only if no values could be fetched at all; otherwise individual misses use `null`.

### 5.4 reflect

Discovers all secrets the plugin knows about for a project. Only callable if the plugin advertised the `reflect` capability. Used by `secretspec import`.

**Request:**

```json
{ "op": "reflect", "project": "myapp" }
```

**Response:**

```json
{
  "ok": true,
  "secrets": {
    "DATABASE_URL": { "description": "Postgres connection string", "required": true },
    "REDIS_URL":    { "description": "Redis URL", "required": false, "default": "redis://localhost:6379" }
  }
}
```

The shape of each secret entry mirrors `secretspec.toml`'s secret definition. Unknown fields MUST be ignored by the host so plugins can include richer metadata over time.

### 5.5 bye (optional)

Signals graceful shutdown. The host MAY send `bye` before closing stdin; plugins SHOULD respond and exit.

**Request:**

```json
{ "op": "bye" }
```

**Response:**

```json
{ "ok": true }
```

## 6. Errors

Failed responses carry a structured error:

```json
{ "ok": false, "error": { "kind": "auth_failed", "message": "1Password CLI not signed in" } }
```

The following `kind` values are defined in v1:

| Kind | Meaning |
|---|---|
| `not_found` | Resource (e.g., project, profile) does not exist. NOT used for missing secret values; use `value: null` instead. |
| `auth_failed` | Plugin could not authenticate to its backend. |
| `permission_denied` | Authenticated but not authorized for this secret. |
| `rate_limited` | Backend throttled the request. The host MAY retry. |
| `unsupported` | Operation not supported (should not occur if capabilities are honored). |
| `unsupported_version` | Plugin cannot speak the requested protocol version. |
| `invalid_request` | Request was malformed. |
| `internal` | Plugin internal error. |

Unknown `kind` values MUST be treated as `internal` by the host. Plugins MAY include additional fields on the error object for diagnostic purposes; the host MUST ignore unknown fields.

## 7. Context

The `context` map in `hello` carries per-session metadata supplied by the caller. The host populates it from:

* CLI flag: `secretspec run --context key=value ...`
* SDK builder: `SecretSpec::builder().context("key", "value").load()?`
* Environment: `SECRETSPEC_CONTEXT_<KEY>=value` (uppercase mapping)

Plugins decide what context they require. The `opproxy` plugin, for example, requires `context.reason`. If a required context value is missing, the plugin SHOULD fail the `hello` response with an `invalid_request` error explaining what is missing, so the host can surface a clear message to the user.

Context values are strings. Nested objects are NOT supported in v1.

## 8. Security

* Plugins inherit the user's privileges. The protocol provides no sandbox. Users SHOULD only install plugins from trusted sources.
* Secret values pass through the plugin's process memory and stdout pipe. The host pipe is not visible to other users on the system; plugin authors are responsible for not logging values.
* The host MUST NOT pass secrets via `argv` or environment to the plugin process. Secrets travel only on the JSON stdio channel.
* Plugins MUST NOT write secret values to stderr.
* The host SHOULD redact plugin output from any debug logging it produces.
* The plugin binary's path resolution is governed by `$PATH`. Users SHOULD audit their `$PATH` to ensure no untrusted directory precedes trusted ones.

## 9. Versioning

`protocol_version` is a monotonically increasing integer. The current version is `1`.

Backward-compatible changes (new optional fields, new error kinds, new capabilities) do NOT increment the version. Backward-incompatible changes (renamed fields, changed semantics) MUST increment it.

The host MUST tolerate unknown fields in plugin responses. The plugin MUST tolerate unknown fields in host requests. This is what allows additive evolution without bumping the version.

## 10. Non-goals (v1)

The following are intentionally out of scope and may be addressed in later versions:

* Streaming responses for lease refresh (see [issue #11](https://github.com/cachix/secretspec/issues/11)). A `subscribe` operation that yields multiple responses for one request is a natural v2 addition.
* Host-initiated push (server-sent updates).
* Binary encodings (CBOR, msgpack). JSON is the wire format for v1.
* Sandboxed execution. A future WASM-based transport may share this same JSON schema.
* gRPC adapter. The JSON schema is transport-agnostic and a gRPC facade may be added later if needed; it is not part of this specification.

## 11. Reference example

A minimal `secretspec-provider-echo` plugin in shell, useful for testing:

```bash
#!/usr/bin/env bash
set -euo pipefail

while IFS= read -r line; do
  op=$(echo "$line" | jq -r .op)
  case "$op" in
    hello) printf '%s\n' '{"ok":true,"protocol_version":1,"name":"echo","capabilities":["get"]}' ;;
    get)   key=$(echo "$line" | jq -r .key)
           printf '%s\n' "{\"ok\":true,\"value\":\"echoed:$key\"}" ;;
    bye)   printf '%s\n' '{"ok":true}'; exit 0 ;;
    *)     printf '%s\n' '{"ok":false,"error":{"kind":"unsupported","message":"unknown op"}}' ;;
  esac
done
```

Drop into `$PATH`, then `secretspec run --provider echo:// -- env | grep echoed`.

A production-quality reference plugin in Rust will live under `examples/provider-plugin/` in the secretspec repository.

## 12. Conformance

A conformant plugin:

1. Reads line-delimited JSON from stdin until EOF.
2. Responds to `hello` first, advertising a `protocol_version` `<= 1` and the capabilities it implements.
3. Never sends a response without a preceding request.
4. Never writes secret values to stderr.
5. Exits within 5 seconds of stdin EOF.
6. Reports missing secret values as `value: null`, not as errors.

A conformant host:

1. Resolves `<scheme>://...` to `secretspec-provider-<scheme>` on `$PATH`.
2. Sends `hello` first and validates the response before any other request.
3. Only invokes operations the plugin advertised.
4. Treats unknown response fields as forward-compatibility hooks (ignores them).
5. Distinguishes "plugin not installed" from "plugin error" in user-facing messages.
