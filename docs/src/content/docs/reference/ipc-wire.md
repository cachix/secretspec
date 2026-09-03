---
title: IPC wire protocol
description: Shared framing, negotiation, cancellation, errors, and lifecycle for SecretSpec IPC
---

This document defines the transport-neutral wire contract shared by the
[Secret Resolution Protocol](/reference/resolver-protocol) and the
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
| Frame | One UTF-8 JSON object followed by LF (bounded NDJSON) |
| Absolute frame limit | 1,048,576 JSON bytes, excluding the terminating LF |
| Request IDs | Positive JSON integers from 1 through 9,007,199,254,740,991; strictly increasing within one direction of a session |
| Concurrency | Negotiated, at least 1 and at most 32 in-flight requests in version 1 |
| Deadline | Mandatory absolute Unix time in milliseconds on every request |
| Discovery | Side-effect-free `rpc.discover` before or after initialization (0.20+) |
| Cancellation | `rpc.cancel` notification naming the original request ID |
| Callbacks | `client.`-prefixed requests an endpoint sends to its client, only when advertised (0.20+) |
| Shutdown | `rpc.shutdown`, then EOF and bounded process termination |

## Framing

Each message is encoded as one JSON object followed by one LF byte:

```text
{"jsonrpc":"2.0","id":1,...}\n
```

Partial pipe reads are normal. A receiver accumulates bytes until LF, and MUST
close the transport if LF has not arrived before `max_frame_bytes` JSON bytes.

- An empty line is a protocol violation.
- LF is the only delimiter; CR and literal line breaks in the JSON bytes are
  rejected. JSON string newlines are encoded as `\n` and remain one line.
- EOF between lines is a clean disconnect; EOF after any JSON byte is a
  truncated-frame protocol violation.
- The payload MUST be one JSON object. JSON-RPC batch arrays are not supported.
- A payload MUST be valid UTF-8 and MUST NOT contain duplicate object keys.
- Implementations SHOULD reject JSON nested more than 64 containers deep.
- A writer MUST serialize a complete frame. Concurrent writers must use one
  frame-level lock or a single writer task so bytes from two messages cannot
  interleave.

Discovery (0.20+) and initialization use the same absolute limit.
Initialization negotiates a possibly smaller `max_frame_bytes` for the rest of
the session.

## JSON-RPC profile

Version 1 uses the JSON-RPC string `"2.0"`. Requests and responses use the
standard `method`, `params`, `result`, and `error` members.
`rpc.discover` (0.20+), `rpc.initialize`, `rpc.cancel`, and `rpc.shutdown` are
the RPC-internal extensions defined by this profile. Application methods a
client calls on an endpoint use the `resolver.` or `provider.` prefix; the
[callbacks](#callbacks) an endpoint calls on its client use the `client.`
prefix.

Request IDs are positive integers no larger than JavaScript's exactly
representable integer limit. A sender MUST choose IDs in strictly increasing
order for every request it makes. A receiver stores only the last ID it saw in
that direction and rejects an ID less than or equal to it. Notifications omit `id`; version 1 defines only the
`rpc.cancel` notification.

Each direction has its own ID space. A server that calls back on the client
(see [callbacks](#callbacks)) allocates its request IDs independently, so the
same integer may be in flight in both directions at once and means a different
request in each. A response is matched against the requests the receiving side
itself sent; a response naming an ID that side never used is a protocol
violation, not an application error.

A response repeats the corresponding request ID. An error response uses a null
ID only when a parse or invalid-request failure made the supplied ID unavailable
or unusable; null is never a valid request ID.

The receiver MUST reject requests with:

- a string, fractional, zero, negative, null, or out-of-range request ID;
- an ID less than or equal to the last request ID received in that direction;
- unknown top-level members;
- unknown members in a method's `params` object;
- a request sent before successful initialization, other than `rpc.discover`
  (0.20+) or `rpc.initialize`;
- a second `rpc.initialize` request.

A notification has no response channel. Unknown notifications, cancellation
for an unknown or completed ID, and malformed cancellation parameters are
ignored (and may produce redacted diagnostics). Malformed JSON, duplicate keys,
and an oversize or unterminated frame remain transport-fatal.

Unknown advertised capabilities are ignored. Strict parameter parsing is
intentional: extensions use capabilities and protocol versions rather than
silently ignored security-sensitive fields.

This has a standing consequence for anyone extending a method. Protocols that
discard unknown fields let a sender add one and degrade quietly against an older
peer; that leniency is how a value meant for one destination gets accepted by
another. Here the receiver rejects the request instead, so **adding a field to
an existing method is a breaking change unless a capability gates it**. An
optional field is only optional to a peer that advertised the capability naming
it, and a sender must not write the field to a peer that did not. Reviewers
should read a new `params` member as a new capability until shown otherwise.

## Runtime discovery (0.20+)

`rpc.discover` returns the endpoint's self-contained
[OpenRPC](https://spec.open-rpc.org/) document without initializing application
state. It is the only request other than `rpc.initialize` that a server accepts
before initialization.

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "rpc.discover",
  "_meta": { "deadline_unix_ms": 1786766405000 },
  "params": {}
}
```

The result is the OpenRPC document itself. Its `x-secretspec` extension carries
the endpoint-specific facts that do not belong to the application interface:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "openrpc": "1.3.2",
    "info": {
      "title": "SecretSpec Secret Resolution Protocol",
      "version": "1"
    },
    "methods": [
      {
        "name": "rpc.discover",
        "params": [
          { "name": "params", "required": true, "schema": { "type": "object" } }
        ],
        "result": {
          "name": "OpenRPC document",
          "schema": { "type": "object" }
        }
      }
    ],
    "components": {
      "schemas": { "...": "..." }
    },
    "x-secretspec": {
      "protocol": "secretspec.resolver",
      "versions": [1],
      "server": {
        "name": "secretspec-resolver",
        "version": "0.20.0"
      },
      "methods": ["resolver.get", "resolver.release"],
      "absolute_max_frame_bytes": 1048576
    }
  }
}
```

Rules:

- Discovery MUST NOT load a manifest, initialize a provider, obtain a
  credential, send a callback, or create application session state.
- The returned OpenRPC document MUST include all referenced schemas. A caller
  does not need network access, an installed schema directory, or a source
  checkout to interpret it.
- `x-secretspec.methods` lists the application methods this endpoint can
  advertise. It is descriptive only; a client still uses the `methods` selected
  by `rpc.initialize` as the authority for application calls.
- Discovery does not select a protocol version, negotiate limits, or make the
  endpoint ready. After replying, an uninitialized endpoint continues waiting
  for `rpc.initialize` or EOF.
- Discovery may be repeated with fresh, increasing request IDs. After
  initialization its response is subject to the negotiated frame limit; before
  initialization it is subject to the absolute frame limit.
- Invalid parameters receive `invalid_params`; an expired deadline receives
  `deadline_exceeded`. Either response leaves the session usable.

## Initialization and capabilities

`rpc.initialize` MUST be the first request that creates or addresses application
state. It MAY be preceded only by `rpc.discover` (0.20+) requests. Clients that
do not need discovery send initialization as request ID 1. Its envelope carries
the startup deadline; clients commonly choose 5 seconds, and servers may enforce
a shorter local startup bound. Its `application` member is defined by the
selected application protocol.

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "rpc.initialize",
  "_meta": { "deadline_unix_ms": 1786766405000 },
  "params": {
    "protocol": "secretspec.resolver",
    "versions": [1],
    "client": { "name": "nix", "version": "2.34.0" },
    "limits": {
      "max_frame_bytes": 1048576,
      "max_in_flight": 8
    },
    "client_methods": [],
    "application": {}
  }
}
```

`client_methods` (0.20+) lists the [callbacks](#callbacks) this client can
answer. It is optional and defaults to empty, which is what a client that
answers none sends, so omitting it is the same as listing nothing.

The server selects the highest version it supports from `versions`, advertises
its application `methods` separately from optional boolean `capabilities`, and selects limits no larger than either
implementation's limits. `rpc.cancel` is fixed wire behavior rather than an
application capability.

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocol": "secretspec.resolver",
    "version": 1,
    "server": { "name": "secretspec-resolver", "version": "0.20.0" },
    "methods": ["resolver.get", "resolver.release"],
    "capabilities": {},
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

Discovery and initialization requests are constrained by the pre-negotiation
limits of one frame and one in-flight request.

## Application requests

Every request contains `_meta.deadline_unix_ms`. It is an unsigned integer
containing milliseconds since the Unix epoch. Notifications do not carry a
deadline.

A deadline more than 300 seconds in the future is clamped to that horizon
rather than rejected. Senders apply the clamp before writing the value, so a
receiver never enforces a longer deadline than the sender waits for. Without a
bound, one request could hold an in-flight slot for the life of the process and
no timeout would reclaim it.

A deadline that has already passed when the caller supplies it is reported as
`deadline_exceeded` and nothing is written, so the session stays usable. It is
not an argument error: the same call a millisecond earlier succeeds, and a
caller that computed its deadline just before a slow code path should not see
the failure change kind because of where the boundary fell.

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "resolver.get",
  "_meta": { "deadline_unix_ms": 1786766405000 },
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

## Callbacks

:::caution[Version compatibility]
Server-initiated requests are available starting with SecretSpec 0.20.
:::

Almost every request travels from client to server. One case does not, and it
exists because the side that discovers a value is missing is never the side that
can obtain it: a stdio endpoint has no terminal, since its stdin and stdout are
the protocol. Rather than let an endpoint touch the terminal behind the
protocol's back, it asks its client, on the same connection, and the client
decides how to obtain the answer.

Callback methods use the `client.` prefix and are listed by the client in
`client_methods` during initialization. The rules are deliberately the
mirror image of an ordinary request, with one addition:

- A server MUST NOT send a method the client did not advertise. A client that
  advertised nothing is never called back, and an endpoint that needed to ask
  must fail the originating request instead of waiting.
- A client MUST answer every callback it accepted with exactly one terminal
  response, under the same rules an endpoint follows.
- A callback's `_meta.parent_request_id` MUST name the active request it serves;
  its deadline MUST NOT be later than that request's deadline, and
  cancelling that request cancels the callback.
- Both sides MUST keep reading while a callback is outstanding. The connection
  that carries the callback also carries the response the client is waiting for,
  so a client that blocks its reader to answer deadlocks the session until the
  deadline elapses.
- The negotiated `max_in_flight` also bounds server-to-client callbacks. A
  client MUST reject callbacks beyond that selected limit, so a peer cannot
  grow its state by never letting callbacks finish.
- Callbacks carry secrets in the same way responses do, and are subject to the
  same logging and redaction rules.

An implementation that answers no callbacks needs none of this: it advertises
nothing, never receives a request, and continues to treat an inbound request as
the protocol violation it is.

Version 1 defines two callbacks (both available in SecretSpec 0.20+):

- `client.prompt` lets a resolver ask its launching client for one declared
  secret value;
- `client.credential` lets an external provider request one semantic,
  URI-scoped provider credential. Its closed request and result shapes are
  specified by the [provider protocol](/reference/provider-protocol/#credential-brokerage-020).

The server read loop must remain live during `rpc.initialize` as well as during
ordinary methods. A credential callback commonly occurs inside provider
initialization; waiting for initialization to return before consuming the
callback response deadlocks both peers.

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

An **accepted application request** is a complete, valid JSON-RPC request with a
fresh ID that has passed initialization, capability, parameter, and
in-flight-limit checks. Every accepted application or `rpc.discover` (0.20+)
request MUST produce exactly one terminal `result` or `error` response unless
the transport disconnects before it can be written.
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
| `-32010` | `representation_mismatch` | No | The requested value/path representation does not match the declaration |

`data` MUST contain `kind` and `retryable`. It may contain `retry_after_ms` only
for `unavailable`. Starting in 0.20, an `interaction_required` error may instead
contain an `interaction` reference with a bounded opaque `id`, an interaction
`kind`, and a nullable absolute expiry. Version 1 defines the `authorization`
interaction kind. The reference correlates provider-owned interaction; it is
neither a bearer credential nor permission to retry automatically. A receiver
MUST use `kind`, not parse `message`.

Codes `-32011` and below in the SecretSpec range are reserved for later
revisions. A receiver MUST accept an error whose code and kind it does not know
and report it as a failure it cannot name; see
[forward compatibility](#forward-compatibility).

Errors are non-secret. Apart from the bounded opaque interaction ID and expiry,
`message` and `data` MUST NOT contain secret values, provider credentials, full
provider URIs, addresses, secret names, manifest contents, file paths,
executable paths, delegation material, or backend error bodies. Detailed
diagnostics belong in a separately protected local diagnostic channel and must
be redacted before display. A provider endpoint maps arbitrary backend failures
to this stable set; it must not forward their text blindly.

## Forward compatibility

Version 1 is strict on the way in and tolerant on the way out. Those are not in
tension: a misspelled parameter must never weaken a security decision, while a
descriptive value a receiver does not recognize must never take down a session.
A protocol that is strict in both directions cannot grow at all, because the
first addition breaks every deployed peer and the only remaining move is a new
protocol version.

The rules an implementation must follow to keep version 1 extensible:

1. **Enumerations are closed for senders and open for receivers.** A sender
   emits only the values this document defines. A receiver that meets a value it
   does not know MUST decode it as an explicit unrecognized value rather than
   failing the frame. This applies to `error.data.kind` and to descriptive
   result enumerations such as the resolver's `source`.
2. **An unrecognized error is a failure.** A receiver treats an unknown
   `kind` as a non-retryable failure unless `retryable` is true, and never as a
   success or as a reason to retry blindly.
3. **A defined code must carry its defined kind.** Only a code a receiver has
   never seen may arrive with a kind it has never seen. A known code paired with
   an unknown kind is a peer defect and is still rejected, so tolerance never
   becomes a way to smuggle one error past a receiver as another.
4. **Requests are strict and results are tolerant.** Request and notification
   objects reject unknown members. Receivers ignore unknown members in response
   and result objects, so descriptive output can grow without a new capability.
5. **New methods, notifications, and callbacks are capability-gated.** An
   unknown notification method remains a protocol violation, so a later
   notification is sent only to a peer that advertised it.
6. **Codes and names are reserved, not recycled.** A server-error code, a method
   name, or a capability name that this document has assigned is never reused
   for a different meaning in the same protocol version.

None of this weakens strict request parsing. An endpoint still rejects an
unknown member of a `params` object, an unknown method, and a request that used
a capability it did not advertise.

## Shutdown and disconnect

The client requests orderly shutdown after all ordinary calls have completed:

```json
{
  "jsonrpc": "2.0",
  "id": 99,
  "method": "rpc.shutdown",
  "_meta": { "deadline_unix_ms": 1786766410000 },
  "params": {}
}
```

The server enters `DRAINING`: it rejects new application requests, lets accepted
work finish, and cancels what remains only when the shutdown deadline expires.
It then releases session resources and responds with an empty result:

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
