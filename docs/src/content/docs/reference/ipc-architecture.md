---
title: IPC architecture
description: Design and trust boundaries for SecretSpec client and external-provider IPC
---

SecretSpec needs two local IPC boundaries with different authority and method
sets:

```text
application or SDK
        |
        | Secret Resolution Protocol
        v
SecretSpec resolver
        |
        | Secret Provider Protocol
        v
external provider endpoint ----> provider-owned service or agent
```

The protocols share the [IPC wire protocol](/reference/ipc-wire), but they are
not one API:

| Boundary | Purpose | Authority |
| --- | --- | --- |
| [Secret Resolution Protocol](/reference/resolver-protocol) | Resolve an exact declared name through a complete SecretSpec configuration | The caller receives the resolved value or a leased path to it |
| [Secret Provider Protocol](/reference/provider-protocol) | Implement one provider behind SecretSpec's resolver | The endpoint receives provider addresses and values, but not SecretSpec's storage or resolver internals |

The [implementation guide](/development/ipc-implementation) turns these
contracts into crates, handlers, tests, and an implementation order.

:::caution[Version compatibility]
The IPC libraries, resolver, external-provider adapter, and protocol version 1
are available starting with SecretSpec 0.20.
:::

## Decision

The canonical interface is the wire specification. SecretSpec ships two
first-class implementations:

- `libsecretspec-resolver`, a portable C11 client for the Secret Resolution
  Protocol, distributed as source plus static and shared libraries. It is C, not
  a C ABI over Rust. It speaks that one protocol: the Secret Provider Protocol's
  client is always the SecretSpec resolver, so a C client for it would serve
  nobody.
- `secretspec-ipc`, a Rust client/server crate with typed resolution and provider
  handlers.

Nix and non-Rust resolver-mode SDKs use the C client. Rust consumers, the
SecretSpec external-provider adapter, the resolver, and Rust provider endpoints
use the Rust implementation. Both implementations are tested against the same
language-neutral conformance suite and differential state-machine tests.

The initial transport is a child process over inherited stdin and stdout on
Linux, macOS, and Windows. Messages are JSON-RPC 2.0 objects inside bounded
bounded newline-delimited JSON frames. A later Unix-domain socket or Windows named-pipe
transport may carry the same messages after separately specifying endpoint
authentication and discovery.

### Why C and Rust implementations?

A shared C client avoids duplicating the security-sensitive state machine across
non-Rust SDKs. C11 gives native consumers one stable ABI without imposing a Rust
toolchain or Rust static-link closure. The library uses opaque handles,
explicit-length buffers, and no callbacks into foreign runtimes, so C++, Go,
Swift, Python, and other bindings can wrap it. A native Rust implementation
avoids routing SecretSpec's own async handlers through FFI and gives Rust
consumers typed APIs.

Neither implementation is the protocol. Independent or constrained clients may
implement the canonical wire contract directly, but every implementation must
pass the same conformance suite. The C and Rust implementations additionally
run differential tests so a shared bug is less likely to redefine the contract.

The intended deliverables are therefore:

- `libsecretspec-resolver`: the pure-C resolution client, process launcher, frame
  codec, JSON-RPC session, and public C header, with no Rust or provider
  dependencies;
- `secretspec-ipc`: Rust wire types, client, server dispatcher, process
  lifecycle, and typed resolution/provider handlers;
- thin non-Rust SDK bindings around the C ABI for resolver mode;
- one language-neutral conformance suite plus C/Rust differential tests.

The existing `libsecretspec` remains the embedded resolver ABI used by current
language SDKs. It is not silently changed into an IPC client. An SDK may later
offer `embedded` and `resolver` backends behind the same language-level API.

### Why not Varlink?

[Varlink](https://varlink.org/) supplies an interface language, local service
discovery conventions, framing, typed errors, streaming replies, and runtime
introspection. The maintained [zlink](https://docs.rs/zlink/0.7.0/zlink/)
implementation also provides async Rust clients and services, code generation,
and Tokio and smol integrations. SecretSpec does not use it for these reasons:

- **No multiplexing.** Varlink pipelines calls in order but has no request IDs.
  One blocked call delays later replies and cannot be cancelled independently.
  A pool of connections avoids this, but adds channel scheduling, descriptor
  limits, and replacement after cancellation.
- **Portability.** Version 1 requires private stdio sessions on Linux, macOS,
  and Windows plus a pure-C client. zlink is Rust-only. systemd's
  [`varlinkctl`](https://www.freedesktop.org/software/systemd/man/latest/varlinkctl.html)
  can launch a private endpoint over an AF_UNIX socket pair passed as file
  descriptor 3, but that Linux-specific process contract does not supply the
  portable stdio and Windows behavior SecretSpec needs.
- **No bidirectional calls.** Varlink streams replies from a service, but does
  not define a service issuing a new call to its client and awaiting the answer
  on that connection. SecretSpec needs exactly that for `client.prompt` and
  `client.credential` (0.20+); a second connection would add discovery,
  correlation, authentication, and lifecycle state.
- **Missing lifecycle semantics.** SecretSpec would still have to define
  version and capability negotiation, deadlines, cancellation, message bounds,
  leases, shutdown, and the trust model.
- **No net simplification.** Varlink's direct-executable form avoids a named
  socket, but not the portability, lifecycle, or callback work above. Its
  persistent named-socket form additionally requires authentication,
  permissions, discovery, and stale-socket cleanup. Connection pools replace
  the current request-ID table with another security-sensitive state machine.

See Varlink's documentation on
[ordered connections](https://varlink.org/FAQ.html#why-are-there-no-sequence-numbers-in-calls-and-replies)
and [transport-specific file descriptors](https://varlink.org/FAQ.html#can-i-transmit-file-descriptors).

[JSON-RPC 2.0](https://www.jsonrpc.org/specification) gives SecretSpec stable
request correlation, method names, results, and errors while leaving transport
and application semantics explicit. The missing stream framing and
cancellation rules are small enough to specify here and implement without a
large runtime.

SecretSpec adopts Varlink's most useful operator-facing property without
adopting its wire protocol: `rpc.discover` (0.20+) returns a self-contained
OpenRPC interface description before application initialization. It provides a
safe foundation for generic inspection tooling without loading a manifest,
opening a provider, or changing the private transport model.

This is a portability and dependency decision, not a claim that Varlink is a
bad protocol. Varlink improves interface description and generated Rust APIs,
but does not simplify SecretSpec's required lifecycle. A Unix Varlink adapter
could still be added later without changing the canonical application methods.

## Layer ownership

The layers are independently owned and versioned:

1. The wire layer owns frames, JSON-RPC envelopes, side-effect-free discovery
   (0.20+), initialization, request IDs, deadlines, cancellation, shutdown,
   common errors, resource bounds, and the callback direction an endpoint uses
   to ask its client something.
2. `secretspec.resolver/1` owns resolver configuration, exact-name resolution,
   value/path representations, and path leases.
3. `secretspec.provider/1` owns provider discovery, provider metadata,
   canonical addresses, secret-validity expiry, provider operations, and
   provider error mapping.
4. A provider owns its storage, encryption, synchronization, hardware keys,
   grants, and any protocol used behind its endpoint.

An external provider exposes only the SecretSpec endpoint contract. Its
storage engine, encryption, synchronization, hardware keys, and grants stay
behind that endpoint and are never modeled in SecretSpec IPC. In-tree providers
may instead call a provider-owned Rust client directly.

Application methods from the two protocols must never be mixed on one
connection. Initialization selects exactly one protocol name and major
version.

Version 1 reverses direction in exactly one place. A stdio endpoint has no
terminal, so when a value can only come from a person it asks the client that
launched it rather than reaching for one behind the protocol's back. The client
declares during initialization whether it can answer, and an endpoint never
sends a callback that was not declared. See the wire protocol's
[callbacks](/reference/ipc-wire#callbacks).

## Process and transport model

Version 1 has one mandatory transport: a directly launched child with a private
stdin/stdout pair. This choice has the same security shape on all target
platforms:

- no global endpoint name is discoverable or connectable by another process;
- possession of the inherited pipe handles is the session authority;
- `rpc.discover` (0.20+) describes the endpoint but does not make it ready;
- readiness is the successful `rpc.initialize` response;
- EOF, `rpc.shutdown`, or child exit ends the session and releases every
  session resource;
- executables are launched directly, never through a shell;
- secrets are sent only in framed requests and responses, never in command-line
  arguments.

The launcher owns environment inheritance policy. Interactive SDK use may
inherit the caller environment because providers currently use ambient
credentials. Privileged integrations should construct an allowlisted
environment. Protocol fields must not also be mirrored into environment
variables.

A persistent service transport is intentionally not version 1. It requires a
separate specification for owner-only endpoint permissions, peer credentials,
endpoint selection, stale endpoint cleanup, multi-client fairness, and
platform-specific identity. Merely finding a socket or pipe is not
authorization.

## Principal and delegation decision

For protocol version 1, an external provider endpoint acts as its own
application principal when it connects to a provider-owned agent. This rule
does not apply to compiled providers, where the SecretSpec CLI or embedding
application is the process that connects to the provider-owned agent and is
therefore its authenticated principal.

The endpoint must not authorize an original application identity copied from a
JSON field. A process path, PID, `application_id`, user name, or similar value
forwarded by the resolver is only an assertion and is not authenticated
delegation.

The provider initialization context (0.20+) follows the same rule. Its project,
profile, base directory, reason, and requested authorization duration let an
endpoint render useful approval and audit records and apply consent policy
consistently to convention and native addresses. They remain resolver-declared
assertions, not authenticated subject identity or authorization.

If grants must instead follow the application that invoked SecretSpec, a later
capability must define a cryptographic delegation that is:

- issued from an identity authenticated on the client-to-resolver transport;
- signed by an issuer trusted by the provider or provider-owned agent;
- audience-bound to that provider endpoint or agent;
- scoped to operations and addresses;
- short-lived and bound to a nonce or request;
- resistant to replay, substitution, and downgrade.

Version 1 contains no caller-identity field and no delegation capability.
Adding unverified identity metadata before that design exists would create a
confused-deputy boundary.

## Compatibility rules

- Wire and application protocol versions are integers. A breaking change uses
  a new integer version.
- Optional behavior is introduced through named capabilities. A sender must
  not use a method or field gated by a capability the server did not
  advertise.
- Unknown capabilities are ignored. Unknown methods receive
  `method_not_found`. Unknown parameters are rejected so misspellings do not
  weaken a security decision.
- The C library/ABI, an SDK package, the Rust handler crate, resolver binary, and
  provider endpoint each have their own product versions. None of those version
  strings replaces protocol negotiation.
- No request that might have reached a handler is automatically replayed after
  a disconnect. A new connection is a new session.

## Reserved for dynamic secrets

Dynamic secrets are issued on demand, have a backend-bounded lifetime, and may
be renewed or revoked rather than merely read. Version 1 carries a
provider-reported secret expiry on reads starting with SecretSpec 0.20. It does
not model issuance, renewal, an explicit credential-lease handle, revocation,
or feedback from an application whose use of a value failed. Those lifecycle
operations remain reserved here because the wire protocol's compatibility
rules are decided once, and an extension point that was not reserved before the
protocol shipped costs a new protocol version rather than a capability.

The design constraint is that every item below lands additively, under the
[forward-compatibility rules](/reference/ipc-wire#forward-compatibility):

| What dynamic issuance needs | How it lands on `secretspec.resolver/1` |
| --- | --- |
| A new provenance value on a resolved result | `source` gains a value. Receivers already decode an unknown `source` rather than failing, so no version change |
| A "this name needs a live session" failure | A new error kind and a reserved code. Receivers already decode an unknown kind as a failure |
| Secret validity expiry | Already represented by `expires_at_unix_ms`; cache freshness is separately represented by `refresh_at_unix_ms` |
| Lifecycle facts such as renewable/revocable state and a credential-lease handle | New result members, sent only to a client that advertised the matching capability |
| A caller asking for a value with a minimum lifetime left | A new capability-gated request member. Deliberately absent from version 1 even though provider reads can report expiry: minimum lifetime affects provider selection and issuance policy, so silently adding it to an existing strict request would be unsafe |
| Atomic multi-output resolution | A new capability-gated method. One issuance can feed several declared names, so they must be read as one consistent set rather than name by name |
| Session health, and a warning that a lease is nearing its bound | A capability-gated notification, or a callback in the direction `client.prompt` established |
| Replacement, where reissued bytes differ and the consumer must adopt them | A callback, since adoption needs an answer from the consumer rather than a fire-and-forget signal |

Three constraints follow from this, and version 1 already honors them:

- **A session is the lifecycle unit.** A dynamic lease outlives no connection:
  it belongs to the session that issued it, and disconnect is already the
  release path for every session-owned resource. This is why the transport binds
  one session to one connection with no reconnection or resumption.
- **"Lease" is two different things.** `resolver.get` returns a `path_lease_id`,
  a local lifetime handle over a resolver-owned file. A dynamic credential lease
  is a backend resource with issuance, renewal, and revocation. They are
  unrelated, which is why the existing field is named for the path it releases
  rather than for leases in general; a credential lease gets its own distinctly
  named members.
- **A snapshot is not whole-profile access.** Version 1's non-goal is arbitrary
  access for a consumer that asked for one name. A future atomic snapshot is
  bounded by the profile and scope the session already fixed at initialization,
  so it does not reach past what this session was opened for.

Nothing here reserves authority the protocol does not already grant. In
particular, a dynamic provider still attests its own principal, and no
caller-supplied field becomes an authorization input; see the principal and
delegation decision above.

## Non-goals for version 1

- Remote network RPC, TLS, or service-to-service authentication.
- Client-to-daemon or client-to-remote-store forwarding of secret authority.
- Exposing provider storage, caches, encryption, databases, or synchronization
  engines through the resolution protocol.
- Replacing all existing embedded language SDKs.
- Arbitrary whole-profile or arbitrary-provider access for consumers that ask
  for one declared name.
- Authenticated delegation of the original application identity.
- Exactly-once execution of provider side effects. The contract guarantees one
  terminal response, not transactional rollback after cancellation or a lost
  connection.
