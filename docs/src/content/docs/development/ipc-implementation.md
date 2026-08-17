---
title: Implementing SecretSpec IPC
description: Repository layout, handler design, trait mapping, conformance tests, and delivery order for IPC version 1
---

This guide is the implementation plan for the
[IPC architecture](/reference/ipc-architecture),
[wire protocol](/reference/ipc-wire),
[Secret Resolution Protocol](/reference/client-protocol), and
[Secret Provider Protocol](/reference/provider-protocol).

:::caution[Version compatibility]
These IPC implementation APIs and repository components are available starting
with SecretSpec 0.20. Release validation still requires the pure-C client, Rust
client/server, typed handlers, and conformance suite to pass on Linux, macOS,
and Windows.
:::

## Required deliverables

Version 1 is complete when the repository contains:

1. protocol types, JSON Schemas, and OpenRPC descriptions independent of the
   SecretSpec core;
2. a portable C11 client library with bounded framing, JSON-RPC calls,
   cancellation, deadlines, child lifecycle, and shutdown;
3. a Rust client/server implementation, reusable resolution request handler,
   and `secretspec broker --stdio`;
4. an external-provider adapter plus endpoint-side handler API;
5. trusted provider registration and subprocess lifecycle support on all three
   platforms;
6. golden fixtures, a black-box conformance runner, C/Rust differential
   property tests, and native end-to-end tests;
7. C source plus static and shared client artifacts whose dependency closure
   contains no Rust, resolver, broker, or provider code.

The wire protocol is the product contract. Rust handler traits and C client
symbols are implementations of it and may evolve compatibly without changing
the wire version.

## Suggested repository layout

```text
schema/ipc/v1/
  common.schema.json
  client.schema.json
  provider.schema.json
  client.openrpc.json
  provider.openrpc.json
  fixtures/
    wire/
    client/
    provider/

libsecretspec-ipc/
  include/
    secretspec_ipc.h
  src/
    frame.c
    json.c
    session.c
    call.c
    process_posix.c
    process_windows.c
    secure_memory.c
  vendor/
    yyjson.c
    yyjson.h
  tests/
  CMakeLists.txt
  meson.build

secretspec-ipc/                  # Full Rust client/server implementation
  src/
    frame.rs
    client.rs
    jsonrpc.rs
    lifecycle.rs
    server.rs
    resolution.rs
    provider.rs
  tests/

secretspec/src/
  broker.rs
  provider/external.rs

conformance/ipc/
  README.md
  runner/
  cases/
```

`libsecretspec-ipc` is C11 and must not contain or link Rust. Its only bundled
third-party code is a pinned, audited C JSON parser; the initial implementation
uses yyjson behind a private adapter and never exposes yyjson types in the ABI.
The library must not depend on the SecretSpec core, provider SDKs, CLI parsing,
cloud clients, keyrings, manifest parsing, TLS, networking frameworks, GLib, or
libuv.

`secretspec-ipc` is an independent Rust implementation of the same client and
server state machines plus typed handler traits. It does not call the C library.
The two implementations share schemas, fixtures, and tests—not implementation
code—so differential testing can expose interpretation differences.

Keeping application wire types outside the core prevents a dependency cycle:

```text
libsecretspec-ipc (C client) <--- Nix and non-Rust broker-mode SDK bindings

secretspec-ipc (Rust client/server/handlers) <--- Rust SDK, core, CLI/broker,
                                                  provider adapter or endpoint
```

## Schema-first implementation

Write JSON Schema Draft 2020-12 documents, matching
[OpenRPC](https://spec.open-rpc.org/) method descriptions, and checked-in JSON
fixtures before the handlers. Schemas must use closed objects
(`additionalProperties: false`), integer bounds, string byte-length checks in
code, and tagged unions for addresses and results. OpenRPC documents enumerate
methods and reference the same schemas; they must not define a second copy of a
request or result shape.

The schema set should define:

- JSON-RPC request, response, notification, and error envelopes;
- initialization for `secretspec.client/1` and `secretspec.provider/1`;
- every method's parameter and result object;
- the common error-kind enum;
- convention/native addresses and native coordinates;
- resolved value/file/missing/undeclared result variants;
- provider capabilities and metadata.

JSON Schema validates characters, not UTF-8 byte counts, duplicate keys, frame
length, deadlines, capability selection, request-ID reuse, or exactly-one
terminal behavior. The codec and session state must enforce those separately.

Generate or test Rust serialization against the schemas, but do not generate
the public protocol solely from Rust types. Golden JSON is the language-neutral
source of truth. CI validates OpenRPC references and examples against the JSON
Schemas.

## Frame codec

Implement framing before RPC dispatch. The reader state machine is:

1. read exactly four prefix bytes;
2. decode an unsigned big-endian length;
3. reject zero or anything above the active limit without allocating it;
4. allocate exactly the accepted length in zeroizing storage;
5. read exactly that many bytes;
6. validate UTF-8, duplicate keys, nesting, and one-object shape;
7. deserialize into the closed JSON-RPC envelope.

The writer accepts already serialized payloads, verifies their size, and writes
prefix plus payload under one writer task. Neither layer logs payloads.

Before initialization the active limits are one 1,048,576-byte frame and one
in-flight request. Swap to the negotiated limits only after the successful
initialization response has been committed.

## Dispatcher and terminal-state ownership

The read loop must remain live while operations run; a sequential
read-handle-write loop cannot receive cancellation for a blocked request.

Use one session table keyed by request ID. Each entry owns:

- an atomic state: `running`, `terminal_committed`, or `abandoned`;
- a cancellation token;
- a monotonic deadline;
- the in-flight semaphore permit;
- a response sender to the single writer;
- zeroizing request storage where practical.

Only one `complete(id, outcome)` function may transition `running` to
`terminal_committed` and enqueue a response. Normal completion, explicit
cancellation, and deadline expiry all call it. A late handler loses the compare
and discards its output. Disconnect changes all running entries to `abandoned`
and cancels them without attempting writes.

The semaphore permit remains held until the underlying task actually exits,
even if cancellation has already produced a terminal response. This prevents a
series of cancelled, non-cooperative blocking calls from creating unbounded
threads. New work receives bounded `unavailable` responses while capacity is
exhausted.

The synchronous `Provider` trait means some handlers will run through a bounded
blocking pool. Cancellation is cooperative where a backend supports it and
best-effort elsewhere. Never claim cancellation rolled back a mutation.

## Reusable handler API

Keep transport and application logic separate. The exact Rust names may vary,
but the abstraction should have this shape:

```rust
pub struct RequestContext {
    pub request_id: u64,
    pub deadline: Instant,
    pub cancellation: CancellationToken,
}

pub trait ApplicationHandler: Send + Sync + 'static {
    fn protocol(&self) -> &'static str;
    fn versions(&self) -> &'static [u32];
    fn initialize(
        &self,
        context: &RequestContext,
        application: serde_json::Value,
    ) -> impl Future<Output = RpcResult<InitializedApplication>> + Send;
    fn call(
        &self,
        context: RequestContext,
        method: &str,
        params: serde_json::Value,
    ) -> impl Future<Output = RpcResult<serde_json::Value>> + Send;
    fn shutdown(&self) -> impl Future<Output = ()> + Send;
}
```

The protocol crate should provide typed resolution/provider handler traits on
top of this lower-level dispatcher so endpoint authors do not parse JSON-RPC or
manage terminal races themselves. Endpoint mains call `serve_resolution` or
`serve_provider` directly with that typed handler; the internal JSON adapter is
not another public assembly step.

The endpoint-facing provider API should accept owned, zeroizing values and
canonical owned addresses. It should expose one operation enum or individual
methods matching the provider protocol. A Factorseal endpoint then implements
that API by translating into `AgentClient`; it does not reimplement the frame
reader, negotiation, cancellation races, or error envelope.

## Core changes for the resolution broker

The current `Secrets::resolve_named` persists an `as_path` temporary file and
returns its path without retaining an owner. The broker requires an internal
owned variant, for example:

```rust
pub(crate) enum OwnedNamedResolution {
    Undeclared,
    Missing { required: bool },
    ResolvedValue(ResolvedSecret),
    ResolvedFile {
        metadata: ResolvedSecretMetadata,
        file: tempfile::NamedTempFile,
    },
}
```

Both the embedded and broker paths should call one least-access resolution
implementation:

- the embedded API may keep/persist the file to preserve current behavior;
- the broker inserts the owner into a session lease table and returns only its
  protected path plus an opaque lease ID;
- cancellation or response-write failure drops the owner immediately;
- release and session shutdown remove owners from the table.

Do not implement the broker by calling the existing one-shot JSON FFI. That API
cannot recover ownership of a persisted file and would make disconnect cleanup
impossible.

The broker builder must consume only the immutable initialization
configuration. It must not fall back to its process working directory or
ambient profile/scope/reason variables.

Thread the client request's structured purpose into the broker's protected
audit context without using it as identity, authorization, or a replacement for
`reason`. Extend owned resolved metadata with an optional absolute expiry when
the cache/provider resolution path knows one; serialize null/absence when it
does not. Expiry never owns a materialized file—the lease table does.

## External-provider adapter

Add one `ExternalProvider` implementing the core `Provider` trait and backed by
a provider-protocol session. The adapter mapping is:

| Core behavior | Protocol behavior |
| --- | --- |
| `name`, credential-free `uri`, storage/container identity, persistence policy | initialization metadata |
| `supported_coords` | `supported_coordinates` metadata |
| `convention_address`, `entry_coordinates` | `provider.resolve_address` |
| `get` | `provider.get` |
| `get_many` | `provider.get_many`, otherwise bounded `get` fallback |
| `set` | optional `provider.check_writable`, then `provider.set` |
| `set_expiring` | optional preflight, then `provider.set_expiring`; documented core fallback when absent |
| `delete` | optional `provider.check_deletable`, then `provider.delete` |
| `describe_write_target` | protocol method or resolved-coordinate rendering |
| `reflect` | `provider.reflect` |
| `physical_store_path` | initialization metadata |

Two existing trait signatures assume compile-time provider metadata and need a
small compatibility seam before a dynamic adapter is sound:

- change `Provider::name()` from `&'static str` to a borrow tied to `&self`, so
  the adapter can return the validated endpoint name it owns;
- add a dynamic `supports_coord(&self, name: &str) -> bool` hook and make
  `resolve_coords` use it. Its default can consult the existing static
  `supported_coords()` list, while the external adapter consults the
  initialization bitset. This avoids leaking runtime strings merely to satisfy
  a `'static` return type.

In-tree implementations keep their static names and coordinate slices; these
changes only relax the trait boundary. Add compile tests for direct providers,
`Box<dyn Provider>`, `Arc<T>`, and the preflight wrappers.

Two protocol capabilities are not represented directly by the current trait:

- `provider.exists`: add a capability-aware presence seam if write-only
  providers are to participate in `check` and import without exposing values.
  Until the core commands understand that seam, they must reject write-only
  use rather than reporting a false miss.
- `provider.clear`: add a bounded `ClearScope` trait method for cache providers
  or keep the operation on a cache-specific external adapter. Never emulate it
  with an unbounded reflection/list operation.

Capability checks must happen before method dispatch. A missing operation
becomes `ProviderOperationFailed` with a locally generated, non-secret message;
it must not be treated as `None`, `false`, or success.

Provider endpoints are blocking from the current trait's perspective. Share a
session safely across `Arc` wrappers, keep the response reader independent of
calling threads, and make interruption/cancellation callable from another
thread.

Delay endpoint initialization until `with_base_dir`, `with_credentials`, and
the initial `set_reason` have been applied. If a live provider instance receives
a different reason later, close its endpoint and lazily open a new session;
session initialization is immutable.

## Provider registration implementation

Create one registration loader with platform path adapters, not three subtly
different discovery algorithms. Its inputs should be explicit:

```rust
pub struct ProviderDiscovery {
    pub explicit: BTreeMap<String, ProviderEndpoint>,
    pub user_directory: Option<PathBuf>,
    pub system_directory: Option<PathBuf>,
    pub allow_path: bool,
}
```

For each registration:

1. open the file without following an attacker-controlled final symlink where
   platform APIs permit;
2. bound its size before parsing;
3. parse a closed schema and verify the scheme/file-name match;
4. validate distinct semantic `credential_names` and expose them through the
   same provider-info lookup used by credential-source preflight;
5. require an absolute executable and no shell metacharacter interpretation;
6. inspect owner and permissions/ACL according to whether the directory is
   user or system scoped;
7. canonicalize and retain the resolved executable identity;
8. launch that exact target with fixed arguments and private pipe handles.

Provider construction checks the compiled in-tree registry first and only then
uses external discovery. Update `provider_from_url`, known-provider checks,
display-name lookup, and credential-name lookup together so planning and actual
construction cannot disagree. External registrations never shadow a compiled
provider scheme.

The executable security check must be testable through an injectable platform
trait. Linux, macOS, and Windows tests need both accepted and rejected
ownership/permission fixtures.

## Child lifecycle

The C and Rust clients each implement the same observable lifecycle contract for
brokers and provider endpoints:

- create private stdin, stdout, and bounded stderr pipes;
- launch without a shell and retain a process handle;
- send initialization and wait for readiness within the startup timeout;
- run independent reader, writer, stderr-drain, deadline, and process-watch
  tasks;
- on orderly close, send `rpc.shutdown`, close stdin, wait within the remaining
  deadline, then terminate and reap;
- on crash, close the session, fail in-flight callers, release leases, and reap;
- never use detached cleanup threads.

POSIX signals and Windows process termination are platform adapters to the same
observable contract. Tests assert outcomes and time bounds rather than a
particular signal name. The conformance harness applies each lifecycle script to
both clients and compares normalized outcomes.

## Portable C client library

`libsecretspec-ipc` is one of two reference clients and the supported non-Rust
broker-mode SDK boundary. It is authored in C11, not Rust compiled behind C
symbols. Release it as source, a static archive, and a shared library for every
supported native target. Use hidden visibility by default and export only
`secretspec_ipc_*` symbols.

The public header uses opaque client and call handles, explicit byte lengths,
library-owned output buffers, and size-tagged option structs. It exposes
operations equivalent to:

```c
#include <stddef.h>
#include <stdint.h>

#define SECRETSPEC_IPC_ABI_VERSION ((1u << 16) | 0u)

typedef struct secretspec_ipc_client secretspec_ipc_client;
typedef struct secretspec_ipc_call secretspec_ipc_call;

typedef struct {
    const unsigned char *data;
    size_t size;
} secretspec_ipc_slice;

enum {
    SECRETSPEC_IPC_DISCOVER_EXECUTABLE = 1u << 0,
    SECRETSPEC_IPC_INHERIT_ENVIRONMENT = 1u << 1
};

typedef struct {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t flags;
    uint32_t reserved;
    secretspec_ipc_slice executable;
    const secretspec_ipc_slice *arguments;
    size_t argument_count;
    const secretspec_ipc_slice *environment;
    size_t environment_count;
    secretspec_ipc_slice initialize_params_json;
    size_t max_stderr_bytes;
} secretspec_ipc_options;

typedef enum {
    SECRETSPEC_IPC_OK = 0,
    SECRETSPEC_IPC_INVALID_ARGUMENT = 1,
    SECRETSPEC_IPC_UNAVAILABLE = 2,
    SECRETSPEC_IPC_IO = 3,
    SECRETSPEC_IPC_PROTOCOL = 4,
    SECRETSPEC_IPC_REMOTE_ERROR = 5,
    SECRETSPEC_IPC_CANCELLED = 6,
    SECRETSPEC_IPC_DEADLINE_EXCEEDED = 7
} secretspec_ipc_status;

typedef struct {
    unsigned char *data;
    size_t size;
} secretspec_ipc_buffer;

uint32_t secretspec_ipc_abi_version(void);

secretspec_ipc_status secretspec_ipc_client_open(
    const secretspec_ipc_options *options,
    uint64_t deadline_unix_ms,
    secretspec_ipc_client **client,
    secretspec_ipc_buffer *server_info,
    secretspec_ipc_buffer *error);

secretspec_ipc_status secretspec_ipc_call_start(
    secretspec_ipc_client *client,
    const unsigned char *method,
    size_t method_size,
    const unsigned char *params_json,
    size_t params_size,
    uint64_t deadline_unix_ms,
    secretspec_ipc_call **call,
    secretspec_ipc_buffer *error);

secretspec_ipc_status secretspec_ipc_client_call(
    secretspec_ipc_client *client,
    const unsigned char *method,
    size_t method_size,
    const unsigned char *params_json,
    size_t params_size,
    uint64_t deadline_unix_ms,
    secretspec_ipc_buffer *result,
    secretspec_ipc_buffer *error);

secretspec_ipc_status secretspec_ipc_call_wait(
    secretspec_ipc_call *call,
    secretspec_ipc_buffer *result,
    secretspec_ipc_buffer *error);

void secretspec_ipc_call_cancel(secretspec_ipc_call *call);
void secretspec_ipc_call_free(secretspec_ipc_call *call);
secretspec_ipc_status secretspec_ipc_client_close(
    secretspec_ipc_client *client,
    uint64_t deadline_unix_ms,
    secretspec_ipc_buffer *error);
void secretspec_ipc_client_free(secretspec_ipc_client *client);
void secretspec_ipc_buffer_free(secretspec_ipc_buffer buffer);
```

The final header defines flags for opt-in executable discovery and environment
inheritance. With no inheritance flag, `environment` is the complete child
environment; with it, entries override inherited values. Privileged callers use
an absolute executable and a complete allowlisted environment. Every input slice
is borrowed only for the duration of its function call. Every extensible options
struct starts with its byte size and header ABI version; fixed buffer and opaque
handle types do not. Every returned buffer is owned by the library and must be released with
`secretspec_ipc_buffer_free`. The library clears secret-bearing allocations
before release where the platform and optimizer permit. ABI major and minor are
encoded separately from every wire protocol version.

Callers set `reserved` to zero. The library rejects unknown flags and option
bytes it cannot interpret rather than silently changing launch authority. It
sets every output buffer to `{NULL, 0}` before work and
`secretspec_ipc_buffer_free` accepts that value. Non-success statuses return a
stable redacted error object when one is available; no error buffer contains a
request or response body.

`client_open` accepts the exact executable and argument vector, initialization
JSON, environment-inheritance policy, startup deadline, and resource limits. It
launches directly, never through a shell. `call_start` validates and copies its
inputs, allocates a unique wire ID, and returns without waiting for a response.
`call_wait` produces exactly one terminal result. `call_cancel` is safe from
another thread and queues `rpc.cancel`; it never claims that a completed or
non-cooperative mutation was rolled back. `client_call` is the synchronous
`call_start` plus `call_wait` convenience path for callers that do not need a
handle.

Every request carries one absolute deadline in its wire envelope. C callers
supply it as the ABI argument; the library adds the envelope member without
interpreting or modifying the application parameters.

Each client owns a bounded joinable I/O worker and a request table. The worker
continues reading while handlers run, serializes writes, correlates responses,
fires deadlines, watches the child, and commits each call terminal exactly once.
There are no callbacks into foreign runtimes, detached threads, mutable global
clients, or background work after `client_close` returns. Call handles remain
valid until explicitly freed; closing a client first makes all outstanding calls
terminal before joining its worker.

`call_free` on a nonterminal, unwaited call requests cancellation and releases
the caller handle without blocking. The internal request entry remains until it
becomes terminal or the session closes. A caller must not free a call while
another thread is inside `call_wait` for that handle. `client_close` makes all
outstanding calls terminal and joins the worker; `client_free` never performs
unbounded I/O.

Threading rules are explicit:

- `call_start` may run concurrently for one client up to its negotiated limit;
- exactly one thread may wait on a given call;
- `call_cancel` may race that waiter and is idempotent;
- `client_close` excludes new calls, makes existing calls terminal, and may run
  only once;
- `client_free` performs an emergency bounded close if necessary, forcibly
  terminates and reaps an owned child, joins workers, and then frees the handle;
- no other function may race `client_free`.

Use a private C JSON adapter around the pinned yyjson source. Reject duplicate
keys, invalid UTF-8, excessive nesting, non-object envelopes, and overlong
strings explicitly; parser defaults are not the protocol contract. Never hand
write a partial JSON parser and never expose parser objects in the public ABI.

Build and test with the strictest available warnings, ASan, UBSan, TSan where
supported, property-based malformed-input coverage, and Windows runtime
diagnostics. CI must inspect the static
and shared dependency closure and fail if any Rust artifact, resolver, broker,
provider SDK, TLS stack, or unrelated runtime appears.

Current language SDKs continue to use the embedded `libsecretspec`. Moving an
SDK to broker mode is a separate explicit behavior and packaging change. Rust
uses `secretspec-ipc`; every supported non-Rust broker-mode SDK binds
`libsecretspec-ipc` rather than implementing another client.

## Rust client and server

`secretspec-ipc` is a full independent Rust implementation, not bindings to the
C library. Keep framing, envelope validation, session transitions, and terminal
ownership in a runtime-independent state-machine core. An optional default
`tokio` feature supplies async stdio transports, direct child launch, reader and
writer tasks, deadlines, cancellation tokens, process watching, and typed
client/server APIs.

The Rust client exposes generic opaque-JSON calls at the wire layer and typed
resolution/provider sessions above it. `ResolutionSession` and
`ProviderSession` own child launch, initialization validation, transport,
advertised methods, and shutdown as one lifecycle object. The server exposes
the reusable handler API described earlier. Both layers use the checked-in
schemas and fixtures; no
Rust type definition becomes a second source of truth.

The Rust implementation must satisfy the same observable rules as C: bounded
pre-initialization allocation, negotiated concurrency, continued reads while
handlers run, exactly one terminal result, no uncertain replay, direct launch
without a shell, bounded child reaping, and value-free errors and logs. Its
async API may differ ergonomically from C call handles, but normalized wire and
lifecycle outcomes must agree.

## Conformance suite

The conformance runner must test any client, broker, provider endpoint, or
codec through public bytes and process behavior. It should support a command
template so third-party implementations can run the same cases. Cases are
language-neutral but role-specific:

| Target | Mandatory coverage |
| --- | --- |
| C client | Wire, client lifecycle, generic resolution/provider calls, and C ABI cases |
| Rust client | The same wire, lifecycle, and generic call cases as the C client, plus typed-client cases |
| Rust server and handlers | Server wire/lifecycle cases plus resolution and provider semantics |
| Broker and external provider endpoints | Their applicable server, lifecycle, and application cases |
| C/Rust pair | Identical generated client histories with normalized differential outcomes |

"Both implementations pass conformance" means that the C and Rust clients pass
every common client case. It does not imply a C server API. Server cases apply
to the Rust implementation and every conforming endpoint.

### Wire cases

- one-byte-at-a-time prefix and payload reads;
- multiple frames in one OS read;
- zero, oversized, truncated, invalid UTF-8, malformed JSON, duplicate-key,
  excessive-nesting, and batch-array frames;
- invalid, duplicate, and reused request IDs;
- request before initialize and repeated initialize;
- no common protocol version and invalid required-method advertisement;
- negotiated smaller frame and in-flight limits;
- unknown capability, method, top-level field, and parameter;
- cancellation-before-completion, completion-before-cancellation, deadline,
  and three-way races, repeated thousands of times;
- one terminal response for every accepted request;
- non-cooperative cancelled handlers retaining capacity until they exit;
- EOF, orderly shutdown, stuck shutdown, and child crash;
- a canary secret absent from logs, stderr, errors, panic text, and fixtures.

### C client ABI cases

- dynamic and static linking from a C-only smoke program;
- runtime/header ABI agreement, compatible trailing option fields, unknown
  flags, nonzero reserved fields, and invalid slice pointer/length pairs;
- exact executable/argument delivery, empty and allowlisted environments,
  opt-in inheritance, and no shell interpretation;
- concurrent `call_start`, one waiter per call, cancellation racing a waiter,
  abandoned `call_free`, and close racing outstanding calls;
- allocator ownership, null-buffer free, repeated open/close, emergency free,
  worker joining, and absence of use-after-free under sanitizers;
- static/shared dependency inspection proving that no Rust or SecretSpec core,
  resolver, broker, or provider artifact is linked.

### C/Rust differential cases

The checked-in `ipc-client-conformance-driver` exposes independent `c` and
`rust` modes behind one small test-control protocol. The conformance runner
executes every common wire/client case against both modes as external
processes. For each generated differential case, it also runs the same abstract
action sequence against both implementations and compares normalized event
transcripts. The fake peer is deterministic and scriptable at the byte
boundary, including fragmented initialization and malformed-frame responses.

Normalize only implementation-irrelevant data such as generated request IDs,
JSON object member order, platform process identifiers, and elapsed times within
the specified bound. Never normalize method names, parameters, error kinds,
terminal counts, retry behavior, frames, state transitions, or cleanup effects.

Differential generation covers:

- arbitrary read chunking, write backpressure, and several frames per read;
- valid and invalid envelopes, limits, capabilities, and application messages;
- concurrent calls, cancellations, deadlines, shutdown, EOF, and child exit in
  every reachable state;
- abandoned handles/futures and late handler completion;
- the same scripted fake resolution and provider endpoints;
- semantic results plus observable lifecycle events, not byte-identical JSON
  serialization.

Implement the generator and shrinker in Rust with `proptest`. A generated
history is pure serializable data, independent of either client. The runner
executes that history first against `ipc-client-c` and then against
`ipc-client-rust`; it must not use one implementation to generate expectations
for the other.

Strategies are state-aware so most histories exercise meaningful initialized
and in-flight states, while explicit raw-frame strategies cover invalid input.
Shrinking preserves the preconditions needed to reproduce the mismatch and
minimizes the history, frames, chunk boundaries, limits, and payloads. Every
failure prints the replay seed and saves the minimized history, C transcript,
Rust transcript, and fake-peer transcript as CI artifacts. The minimized case
then becomes a permanent regression fixture.

The differential properties are:

- C and Rust normalized outcomes are equal;
- every accepted request has at most one terminal response and has one after
  the scripted peer terminates or the session is drained;
- cancelled, expired, or disconnected requests are never replayed;
- close/free leaves no owned child, worker, call, task, or lease alive;
- negotiated frame, in-flight, task, stderr, and allocation bounds hold;
- the canary secret never appears in errors, logs, stderr, or transcripts.

The property runner launches both drivers directly as ordinary native host
processes and requires no external testing service. Every change runs a bounded
case count on Linux, macOS, and Windows; scheduled and pre-release CI increase
the case count using the same runner and retain every replay seed.

The SecretSpec 0.20+ repository also links the pure-C client into the native
conformance test process and runs serialized echo, cancellation, and deadline
histories against that ABI and the independent Rust client through one
deterministic child peer. This bounded local differential property is additive
to, not a substitute for, the complete cross-platform driver matrix above.

### Executable provider and broker cases

The checked-in provider matrix launches a deterministic stateful endpoint as a
real subprocess. One driver mode calls it through the public Rust provider
client and endpoint-author handler API; the other calls the same endpoint
through SecretSpec's external-provider adapter. The matrix covers shared frame
acceptance and rejection, every provider operation, store-enforced expiry,
bounded clear, idempotent deletion, preflight, reflection, cancellation,
deadlines, structured error preservation, non-replay of one-shot failures,
endpoint crash, reconnect for later work, and provider-URI and reason session
isolation.

Run it with:

```console
cargo test -p secretspec-ipc-conformance --test provider_cases
```

The broker case is executable test data too. Its integration driver launches
the actual `secretspec broker --stdio` binary, initializes it with an inline
manifest and explicit provider/profile selection, and verifies exact-name
value, missing, undeclared, and file results. It checks owner-only file mode,
duplicate release, explicit lease removal, and removal of an unreleased lease
when the session closes.

Run it with:

```console
cargo test -p secretspec --test ipc_broker
```

### Resolution cases

- path and inline manifests; reject relative paths and implicit discovery;
- fixed provider/profile/scope/reason session configuration;
- mandatory per-call purpose reaches protected audit context but never
  authorization;
- exact-name resolution ignores an unrelated missing required secret;
- composed dependencies resolve but unrelated names are not read;
- undeclared and scope-hidden names have the same result;
- missing required and optional results;
- `auto`, `value`, and `file` representation matching;
- value results and all four source variants;
- known and unknown expiry metadata, independent of file-lease lifetime;
- mode/ACL of materialized files;
- random opaque leases, duplicate release, release batching, disconnect
  cleanup, cancelled-result cleanup, and response-write-failure cleanup;
- broker crash and conservative stale-directory cleanup;
- no automatic replay after disconnect.

### Provider cases

- registration precedence and scheme validation on all platforms;
- disallow PATH discovery in privileged mode;
- initialization URI/scheme mismatch and metadata redaction;
- convention and native addresses, all coordinates, unknown and unsupported
  coordinates, and deterministic `resolve_address`;
- read hit/miss/error, batch ordering/deduplication, and batch fallback;
- write-only capability sets and `exists` without `get`;
- set, store-enforced expiry, idempotent delete, and bounded idempotent clear;
- mutation preflight agreement with the mutation itself;
- credential-free write descriptions and value-free reflection;
- cancellation/deadline during reads and mutations without replay;
- endpoint crash, relaunch for later work, and no failed-request replay;
- Factorseal endpoint translation exercised against its native test agent.

Property strategies cover the length-prefix decoder, JSON envelope parser,
every tagged union, and terminal-state races. Keep protocol fixtures free of
real credentials and use an unmistakable canary value for redaction assertions.

## Delivery order

Implement in reviewable stages:

1. **Schemas and fixtures:** land versioned common, client, and provider
   schemas, OpenRPC method documents, and golden examples.
2. **Pure-C client:** public header, framing, strict JSON-RPC envelopes,
   process lifecycle, concurrent call handles, cancellation, shutdown, platform
   adapters, sanitizers, and property-test driver.
3. **Rust client, server, and handlers:** independent client and server framing,
   async transport, dispatcher, typed resolution and provider traits, plus
   byte-for-byte fixture parity with the C implementation.
4. **Shared verification:** run every common client conformance case through
   both clients and every server case through the Rust server, add normalized
   C/Rust differential properties, shrinking, and replay fixtures.
5. **Resolution ownership:** add the internal owned named-materialization path
   and lease table without exposing IPC yet.
6. **Broker:** reusable resolution handler and `secretspec broker --stdio`, then
   black-box lifecycle tests.
7. **Provider handler:** endpoint-author API and a deterministic fake endpoint
   that implements every capability.
8. **External adapter and discovery:** use the Rust IPC client for the trait
   bridge, registrations, readiness, crash behavior, and native platform tests.
9. **Factorseal integration:** the Factorseal repository provides the
   `secretspec-provider-factorseal` thin endpoint translation and stable error
   mapping for SecretSpec 0.20+; native end-to-end conformance remains the
   release gate.
10. **Consumer activation:** integrate Nix and non-Rust broker-mode SDKs through
    the released C client, and Rust consumers through the released Rust client,
    only after their conformance and differential gates pass.

Each stage should leave the existing embedded SDK and in-tree provider paths
passing unchanged.

## Release checklist

- [ ] Schemas, C envelopes, Rust client/server types, fixtures, and rendered
      documentation agree.
- [ ] The C client has no Rust, SecretSpec core, resolver, broker, or provider
      dependency.
- [ ] Static and shared C artifacts and the public header build on Linux, macOS,
      and Windows.
- [ ] The independent Rust client, server, and typed handlers build on Linux,
      macOS, and Windows with the documented async runtime support.
- [ ] Every common client conformance case passes against both clients, every
      applicable server case passes against the Rust server and endpoints, and
      normalized C/Rust outcomes agree for differential histories.
- [ ] Differential failures retain a reproducible seed, minimized action trace,
      and redacted byte transcript.
- [ ] The native property runner needs no external service and its bounded,
      scheduled, and pre-release case sets report no counterexample.
- [ ] Frame, in-flight, task, stderr, and shutdown bounds are enforced.
- [ ] Cancellation is readable while an operation is running.
- [ ] Every accepted request has exactly one terminal response in race tests.
- [ ] No uncertain request is automatically replayed.
- [ ] Named resolution retains file ownership until lease release or session
      cleanup.
- [ ] Provider discovery and lifecycle pass on Linux, macOS, and Windows.
- [ ] Write-only providers fail value reads instead of returning false misses.
- [ ] Clear is demonstrably bounded to the initialized provider namespace.
- [ ] Error and logging tests never expose values, names, addresses, URIs,
      credentials, paths, or backend bodies.
- [ ] Version 1 endpoint principal semantics are documented in Factorseal and
      no forwarded JSON identity is trusted.
- [ ] C warnings, sanitizers, Windows diagnostics, Rust formatting/lint, docs,
      schema, conformance, property, and native end-to-end checks pass.
