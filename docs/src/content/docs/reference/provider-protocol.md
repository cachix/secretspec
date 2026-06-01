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
| `SECRETSPEC_FILE` | Absolute path to the loaded `secretspec.toml`, or unset if none (mirrors `hello.config_file`) |

No command-line arguments are passed in v1. The host MUST NOT pass secrets via `argv` or environment.

A session is bound to exactly one provider URI for its entire lifetime. The host MUST NOT reuse a plugin process across different URIs. The plugin therefore MAY parse the URI (and any query parameters, e.g. `opproxy://?cache=12h`) once during `hello` and apply the result to every subsequent request in the session. The URI is sent in the `hello` request and is also available as `SECRETSPEC_PROVIDER_URI`; it is not repeated on later requests.

The plugin reads newline-delimited JSON requests from stdin and writes newline-delimited JSON responses to stdout. The plugin exits on stdin EOF or after responding to a `bye` request. Stderr is free-form and the host MUST NOT parse it; plugins SHOULD use stderr for diagnostic output only and MUST NOT write secret values to stderr.

The host closes stdin to signal end-of-session. The plugin SHOULD exit within 5 seconds of stdin EOF; the host MAY send `SIGTERM` and then `SIGKILL` after a grace period.

## 3. Wire format

Each request and each response is exactly one JSON object terminated by a single `\n`. Embedded newlines inside JSON strings MUST be escaped per RFC 8259. The encoding is UTF-8.

The host MUST NOT pipeline: it sends one request, waits for the matching response, then sends the next. Responses MUST appear on stdout in the same order as their requests.

### 3.1 Transports

The JSON contract above (handshake, capabilities, operations, errors) is transport-neutral: nothing in a request or response object depends on how the bytes are carried. **The only transport defined in v1 is local stdio** — a subprocess discovered on `$PATH` (§1) and driven over stdin/stdout (§2). A conformant v1 host and v1 plugin speak stdio.

A v1 plugin reaches a remote system by acting as a **local adapter**: the plugin binary runs on the host, speaks stdio to secretspec, and is itself a network client to whatever lives across the network. This is the supported way to integrate a remote backend today and requires no protocol extension — the `opproxy://` plugin is exactly this shape (local binary, remote `op-proxy`). Because the adapter shares the host's filesystem, `config_file` (§4) and `SECRETSPEC_FILE` resolve normally.

Carrying the protocol *itself* over a network transport (a socket or HTTP endpoint with no local process) is **out of scope for v1**. It would require, beyond the wire schema: a discovery mechanism that resolves a scheme to an endpoint rather than a `$PATH` binary, a framing definition for the chosen transport, a connection lifecycle replacing spawn/stdin-EOF, transport authentication and confidentiality (TLS) absent from the §8 trust model, and a substitute for `config_file` since a remote endpoint cannot read the host's filesystem path (the host would send config *contents* instead). These are deferred to a later version (see [Non-goals](#10-non-goals-v1)).

## 4. Handshake

The first request in every session is `hello`. The plugin MUST NOT process any other request before responding to `hello`.

**Request:**

```json
{
  "op": "hello",
  "protocol_version": 1,
  "uri": "opproxy://vault/Production?reason=build",
  "config_file": "/abs/path/to/secretspec.toml",
  "context": { "reason": "building api image" }
}
```

`config_file` is the absolute path to the `secretspec.toml` the host loaded for this session, or `null` if the host resolved secrets without an on-disk config (e.g. a purely programmatic SDK caller). It is a first-class field rather than hidden env coupling so that plugins which derive backend references from the committed config can read it deterministically. The same value is also exported as `SECRETSPEC_FILE` for plugins that prefer to read it from the environment. A plugin that does not need the config file MUST ignore this field.

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

### 4.1 Plugin-owned extension tables

Table names in `secretspec.toml` prefixed with `x-` are reserved for tool and provider extensions. The host MUST NOT interpret `x-*` tables and MUST preserve them unmodified when it rewrites the config. Plugins MAY read `x-*` tables from `config_file` to obtain per-key backend references and per-key overrides that have no representation in the core schema. A plugin SHOULD namespace its table after its own scheme, e.g. a plugin discovered as `secretspec-provider-opproxy` reads `[x-op-proxy.refs]`:

```toml
[x-op-proxy.refs]
APP_TOKEN = "external-secret-ref-for-app-token"
BOT_TOKEN = { ref = "external-secret-ref-for-bot-token", reason = "bot-runtime", cache = "12h" }
```

Reading extension metadata from `config_file` is the v1 mechanism for plugin-specific per-key configuration. The host does not parse or forward these tables on individual `get` / `batch_get` requests; the plugin owns and validates its own table shape.

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

The `context` map in `hello` carries per-session metadata supplied by the caller. Because a session corresponds to one resolution pass, the context established at `hello` applies to every operation in that session. It is not specific to `run`: the same context flows to the backend reads behind `secretspec check`, `secretspec get`, `batch_get`, and `secretspec import`. There is no per-request context override in v1.

The host populates it from:

* CLI flag: `secretspec run --context key=value ...` (and the equivalent flag on `check`, `get`, `import`)
* SDK builder: `SecretSpec::builder().context("key", "value").load()?`
* Environment: `SECRETSPEC_CONTEXT_<KEY>=value` (uppercase mapping)

Plugins decide what context they require. The `opproxy` plugin, for example, requires `context.reason` for any backend read — including `check` and `batch_get`, not just `run`. If a required context value is missing, the plugin SHOULD fail the `hello` response with an `invalid_request` error explaining what is missing, so the host can surface a clear message to the user.

To keep non-interactive commands usable against providers that require an audit reason, the host SHOULD synthesize a fallback `context.reason` when the caller supplies none, derived from the command and project — for example `secretspec:<project>:run`, `secretspec:<project>:check`, or `secretspec:<project>:<key>` for a single `get`. A caller-supplied `reason` always takes precedence over the synthesized one. Plugins remain free to reject a session whose `reason` does not meet their policy.

Context values are strings. Nested objects are NOT supported in v1.

## 8. Security

* Plugins inherit the user's privileges. The protocol provides no sandbox. Users SHOULD only install plugins from trusted sources.
* Secret values pass through the plugin's process memory and stdout pipe. The host pipe is not visible to other users on the system; plugin authors are responsible for not logging values.
* The host MUST NOT pass secrets via `argv` or environment to the plugin process. Secrets travel only on the JSON stdio channel.
* Plugins MUST NOT write secret values to stderr.
* The host MAY surface plugin stderr and the `error.message` of a failed response to the user (for diagnostics) and MAY include them in logs. Plugins MUST therefore treat both their stderr and their `error.message` strings as non-secret and MUST NOT embed secret values in either. This matters most once `set` exists, where the request itself carries a value.
* The host SHOULD avoid including request or response values (anything from `value`, `values`, or a `set` request body) in debug logging, even when logging is otherwise verbose.
* The plugin binary's path resolution is governed by `$PATH`. Users SHOULD audit their `$PATH` to ensure no untrusted directory precedes trusted ones.

## 9. Versioning

`protocol_version` is a monotonically increasing integer. The current version is `1`.

Backward-compatible changes (new optional fields, new error kinds, new capabilities) do NOT increment the version. Backward-incompatible changes (renamed fields, changed semantics) MUST increment it.

The host MUST tolerate unknown fields in plugin responses. The plugin MUST tolerate unknown fields in host requests. This is what allows additive evolution without bumping the version.

## 10. Non-goals (v1)

The following are intentionally out of scope and may be addressed in later versions:

* Streaming responses for lease refresh (see [issue #11](https://github.com/cachix/secretspec/issues/11)). A `subscribe` operation that yields multiple responses for one request is a natural v2 addition.
* Host-initiated push (server-sent updates).
* A network transport for the protocol itself (socket/HTTP endpoint with no local process), including its discovery, framing, and authentication. Remote backends are reached via a local adapter plugin in v1 (see [§3.1](#31-transports)).
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
6. Provides `config_file` (and `SECRETSPEC_FILE`) and binds one session to one provider URI.
7. Synthesizes a fallback `context.reason` for non-interactive commands when the caller supplies none.
