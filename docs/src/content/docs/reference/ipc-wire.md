---
title: IPC wire protocol
description: Shared framing, negotiation, cancellation, errors, and lifecycle for SecretSpec IPC
---

This document defines the transport-neutral wire contract shared by the
[Secret Resolution Protocol](/reference/client-protocol) and the
[Secret Provider Protocol](/reference/provider-protocol).

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**,
and **MAY** are interpreted as described by
[BCP 14](https://www.rfc-editor.org/rfc/rfc8174).

:::caution[Version compatibility]
SecretSpec IPC wire protocol version 1 is available starting with SecretSpec
0.20.
:::

## Quick reference

| Property | Version 1 |
| --- | --- |
| RPC envelope | [JSON-RPC 2.0](https://www.jsonrpc.org/specification) |
| JSON encoding | UTF-8 JSON as defined by [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259) |
| Frame | 4-byte unsigned big-endian length, followed by that many payload bytes |
| Absolute frame limit | 1,048,576 bytes, including the JSON payload but excluding the 4-byte prefix |
| Request IDs | Positive JSON integers from 1 through 9,007,199,254,740,991; never reused in a session |
| Concurrency | Negotiated, at least 1 and at most 32 in-flight requests in version 1 |
| Deadline | Mandatory absolute Unix time in milliseconds on every request |
| Cancellation | `rpc.cancel` notification naming the original request ID |
| Shutdown | `rpc.shutdown`, then EOF and bounded process termination |

## Framing

Each message is encoded as:

```text
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                  payload length (big endian)                  |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                  UTF-8 JSON payload ...                       |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The receiver MUST use an exact read for both the prefix and payload. Partial
pipe reads are normal and are not message boundaries.

- A zero length is a protocol violation.
- A length greater than 1,048,576 MUST be rejected before allocating the
  claimed buffer. The receiver closes the transport without a JSON response
  because no request ID has been authenticated.
- EOF before a complete prefix is a clean disconnect only when zero prefix
  bytes were read. EOF in a prefix or payload is a truncated-frame protocol
  violation.
- The payload MUST be one JSON object. JSON-RPC batch arrays are not supported.
- A payload MUST be valid UTF-8 and MUST NOT contain duplicate object keys.
- Implementations SHOULD reject JSON nested more than 64 containers deep.
- A writer MUST serialize a complete frame. Concurrent writers must use one
  frame-level lock or a single writer task so bytes from two messages cannot
  interleave.

The initialization exchange uses the same absolute limit. It negotiates a
possibly smaller `max_frame_bytes` for the rest of the session.

## JSON-RPC profile

Version 1 uses the JSON-RPC string `"2.0"`. Requests and responses use the
standard `method`, `params`, `result`, and `error` members.
`rpc.initialize`, `rpc.cancel`, and `rpc.shutdown` are the RPC-internal
extensions defined by this profile; application methods use the `client.` or
`provider.` prefix.

Request IDs are positive integers no larger than JavaScript's exactly
representable integer limit. The client MUST choose a new ID for every request
and MUST NOT reuse it during a connection, including after the previous request
has completed. Notifications omit `id`; version 1 defines only the
`rpc.cancel` notification.

A response repeats the corresponding request ID. An error response uses a null
ID only when a parse or invalid-request failure made the supplied ID unavailable
or unusable; null is never a valid request ID.

The receiver MUST reject:

- a string, fractional, zero, negative, null, or out-of-range request ID;
- an ID already seen on the connection;
- unknown top-level members;
- unknown members in a method's `params` object;
- a request sent before successful initialization, other than
  `rpc.initialize`;
- a second `rpc.initialize` request.

A malformed notification or an unknown notification method cannot receive an
error response and is a protocol violation that closes the connection. A valid
`rpc.cancel` for an unknown or completed request ID remains the intentional
no-op described below.

Unknown advertised capabilities are ignored. Strict parameter parsing is
intentional: extensions use capabilities and protocol versions rather than
silently ignored security-sensitive fields.

## Initialization and capabilities

`rpc.initialize` MUST be the first request. Its envelope carries the startup
deadline; clients commonly choose 5 seconds, and servers may enforce a shorter
local startup bound. Its
`application` member is defined by the selected application protocol.

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "rpc.initialize",
  "deadline_unix_ms": 1786766405000,
  "params": {
    "protocol": "secretspec.client",
    "versions": [1],
    "client": { "name": "nix", "version": "2.34.0" },
    "limits": {
      "max_frame_bytes": 1048576,
      "max_in_flight": 8
    },
    "application": {}
  }
}
```

The server selects the highest version it supports from `versions`, advertises
its application methods, and selects limits no larger than either
implementation's limits. `rpc.cancel` is fixed wire behavior rather than an
application capability.

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocol": "secretspec.client",
    "version": 1,
    "server": { "name": "secretspec-broker", "version": "0.20.0" },
    "capabilities": ["client.resolve", "client.release"],
    "limits": {
      "max_frame_bytes": 1048576,
      "max_in_flight": 8
    },
    "application": {}
  }
}
```

Rules:

- `versions` MUST contain distinct positive integers.
- `max_frame_bytes` MUST be between 4,096 and 1,048,576.
- `max_in_flight` MUST be between 1 and 32.
- `client.name`, `client.version`, `server.name`, and `server.version` are
  diagnostic product identifiers, not authorization inputs.
- The returned protocol name MUST exactly equal the requested name.
- Application methods and fields gated by a capability MUST NOT be used unless
  the server advertised it.
- Unsupported protocols or versions return `unsupported_version`; the server
  then closes the connection.

An initialization request is constrained by the pre-negotiation limits of one
frame and one in-flight request.

## Application requests

Every request contains top-level `deadline_unix_ms`. It is an unsigned integer
containing milliseconds since the Unix epoch. Notifications do not carry a
deadline.

A deadline more than 300 seconds in the future is clamped to that horizon
rather than rejected. Senders apply the clamp before writing the value, so a
receiver never enforces a longer deadline than the sender waits for. Without a
bound, one request could hold an in-flight slot for the life of the process and
no timeout would reclaim it.

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

On receipt, the server MUST compare the value with its wall clock and convert
the remaining interval into an internal monotonic deadline. It MUST NOT start
an already expired request. Queueing, provider access, interaction, response
serialization, and frame writing all consume the deadline.

The server MUST continue reading frames while handlers run so cancellation and
other requests can be accepted. It MUST enforce the negotiated in-flight limit
without allocating unbounded queues. A request over the limit receives an
`unavailable` error with `retryable: true`.

## Cancellation and terminal responses

The client cancels an in-flight request with a notification:

```json
{
  "jsonrpc": "2.0",
  "method": "rpc.cancel",
  "params": { "id": 2 }
}
```

Cancellation has these race rules:

1. The server associates a cancellation token with every accepted request.
2. A cancellation for an unknown or already terminal ID is ignored.
3. If cancellation wins before the terminal response is committed to the
   writer, the original request receives one `cancelled` error.
4. If the terminal response was already committed, it remains the response and
   cancellation has no effect.
5. The notification itself never receives a response.

An **accepted request** is a complete, valid JSON-RPC request with a fresh ID
that has passed initialization, capability, parameter, and in-flight-limit
checks. Every accepted request MUST produce exactly one terminal `result` or
`error` response unless the transport disconnects before it can be written.
The writer owns the atomic terminal-state transition so a handler, deadline,
and cancellation race cannot emit two responses.

Cancellation and deadlines stop waiting; they do not promise rollback. A
provider mutation may have reached its backend even when the caller receives
`cancelled`, `deadline_exceeded`, or loses the connection. Clients MUST NOT
automatically retry such a request. Servers should propagate cancellation to
the underlying operation and must discard any late result.

## Errors

All failures use the JSON-RPC error object. `message` is a short stable summary.
Machine handling uses `data.kind`.

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "error": {
    "code": -32005,
    "message": "permission denied",
    "data": {
      "kind": "permission_denied",
      "retryable": false
    }
  }
}
```

Standard JSON-RPC errors retain their standard codes:

| Code | Kind |
| --- | --- |
| `-32700` | `parse_error` |
| `-32600` | `invalid_request` |
| `-32601` | `method_not_found` |
| `-32602` | `invalid_params` |
| `-32603` | `internal` |

SecretSpec reserves these server-error codes for both protocols:

| Code | Kind | Retryable by default | Meaning |
| --- | --- | --- | --- |
| `-32000` | `unsupported_version` | No | No common application protocol version |
| `-32001` | `capability_required` | No | The requested operation was not advertised |
| `-32002` | `deadline_exceeded` | No | The request deadline elapsed |
| `-32003` | `cancelled` | No | The caller cancelled the request |
| `-32004` | `unavailable` | Yes | Endpoint, dependency, or capacity temporarily unavailable |
| `-32005` | `permission_denied` | No | The authenticated principal is not authorized |
| `-32006` | `interaction_required` | No | User interaction is required but unavailable |
| `-32007` | `conflict` | No | State or destructive-operation identity conflict |
| `-32008` | `operation_failed` | No | Stable catch-all for a provider or resolver failure |
| `-32009` | `message_too_large` | No | A result cannot fit the negotiated frame limit |
| `-32010` | `representation_mismatch` | No | The requested value/file representation does not match the declaration |

`data` MUST contain exactly `kind` and `retryable`, plus an optional
`retry_after_ms` for `unavailable`. A receiver MUST use `kind`, not parse
`message`.

Errors are non-secret. `message` and `data` MUST NOT contain secret values,
provider credentials, full provider URIs, addresses, secret names, manifest
contents, file paths, executable paths, delegation material, or backend error
bodies. Detailed diagnostics belong in a separately protected local diagnostic
channel and must be redacted before display. A provider endpoint maps arbitrary
backend failures to this stable set; it must not forward their text blindly.

## Shutdown and disconnect

The client requests orderly shutdown after all ordinary calls have completed:

```json
{
  "jsonrpc": "2.0",
  "id": 99,
  "method": "rpc.shutdown",
  "deadline_unix_ms": 1786766410000,
  "params": {}
}
```

The server stops accepting application requests, cancels outstanding work,
releases all session resources, and responds with an empty result:

```json
{ "jsonrpc": "2.0", "id": 99, "result": {} }
```

The client then closes its write pipe. The child SHOULD exit within the
remaining shutdown deadline, capped at 5 seconds. After that grace period the
launcher terminates it with the platform process API and waits for it to exit.

EOF or process exit without `rpc.shutdown` performs the same resource cleanup.
The server cannot send pending responses after a disconnect, but it must cancel
their handlers and prevent late handlers from retaining leases or secret
buffers.

## Secret handling

- Neither side may log complete frames, request parameters, response results,
  environment snapshots, or provider stderr at normal or debug levels.
- Frame buffers that may contain values or credentials SHOULD use zeroizing
  storage and be dropped promptly. This is best-effort in garbage-collected
  languages and does not replace process isolation.
- Crash reports, tracing fields, and panic messages must contain method names
  and error kinds only.
- Stderr is a diagnostic channel, not part of the protocol. Endpoints MUST NOT
  write secret-bearing data to it. A host must treat stderr as sensitive until
  it has applied an explicit redaction policy.
- Backpressure must be bounded on stdin, stdout, stderr capture, handler queues,
  and completed responses waiting for the writer.
