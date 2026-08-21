---
title: Secret Resolution Protocol
description: Version 1 IPC contract between an SDK or application and the SecretSpec resolver
---

The Secret Resolution Protocol is the northbound IPC boundary between an
application and a complete SecretSpec resolver. It lets a consumer resolve one
declared name without linking SecretSpec or any provider SDK into the consumer.

It uses the [shared IPC wire protocol](/reference/ipc-wire) with application
protocol name `secretspec.resolver` and version `1`.

:::caution[Version compatibility]
The Secret Resolution Protocol and `secretspec serve` are available
starting with SecretSpec 0.20.
:::

## Scope

Version 1 deliberately exposes less than the embedded Rust API:

- bind one session to a fixed manifest, provider override, profile, scope, and
  access reason;
- resolve one exact declared secret name and only its composed dependencies;
- return an inline UTF-8 value or a resolver-owned temporary file;
- release path leases explicitly or by closing the session;
- report that a resolved value was refused by its consumer, so a cached copy is
  discarded rather than served again (0.20+);
- store or remove one exact declared secret name (0.20+), when the endpoint
  advertises the optional mutation capabilities.

The resolver owns manifest parsing, inheritance, routing, caching, generation,
prompting, composition, audit events, provider credentials, and provider IPC.
Those internals are not represented in this protocol.

Whole-profile resolution, provider enumeration, and arbitrary manifest queries
are not part of `secretspec.resolver/1`. Existing SDKs that need the complete
embedded API continue to use the Rust core or `libsecretspec`. New client
methods can be added behind capabilities after their least-authority semantics
are specified.

## Starting the resolver

The version 1 resolver transport is a directly launched child:

```text
secretspec serve
```

An endpoint that must not accept writes is launched as `secretspec serve
--read-only` (0.20+), which advertises resolution only.

The executable and arguments come from trusted application or administrator
configuration. The launcher MUST invoke the executable directly rather than
through a shell. A privileged caller MUST use an absolute executable path and
must not let a project manifest, flake, repository, or working directory
select it. An interactive unprivileged SDK may resolve `secretspec` through its
normal installation mechanism.

The caller sends `rpc.initialize` immediately and applies a 5-second startup
timeout by default. A successful response is the readiness signal. The resolver
must not open a global socket, daemonize, or detach from its parent in stdio
mode.

Protocol stdin and stdout are exclusively reserved for framed IPC messages.
The stdio resolver MUST NOT prompt through stdin, stdout, or stderr. It has no
terminal of its own: the one process that can reach a person is the one that
launched it. When a value can only come from a person, the resolver therefore
asks the client, over the same session, with the
[`client.prompt` callback](#ask-the-client-for-a-value) (0.20+).

Resolution may also wait for an independent provider-owned interaction channel
within the request deadline; when neither that nor a client callback is
available, the resolver returns `interaction_required`. Neither the resolver nor
the client automatically replays that request.

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
  the client. The resolver resolves filesystem identity and symlinks according to
  the same rules as the embedded resolver.
- Working-directory discovery is not supported. The resolver's working directory
  must never select a manifest implicitly.
- `provider`, when non-null, is the same provider override accepted by the
  embedded `Secrets` builder. The resolver treats it as sensitive because an
  input URI may contain credentials even though provider display URIs may not.
- `profile`, `scope`, and `reason` are nullable strings with the embedded API's
  meaning. Null requests the resolver's configured/default value; it does not
  consult a resolver-specific environment variable.
- The complete object is immutable after initialization. A caller needing
  another profile, scope, reason, or manifest opens another session.
- Inline TOML is sensitive transport data because a manifest can contain
  defaults. It must never be logged.

The resolver parses and validates the configuration before returning successful
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

- `resolver.get`
- `resolver.release`
- `resolver.reject` (0.20+)

They MAY additionally include the mutation capabilities (0.20+):

- `resolver.set`
- `resolver.delete`

A client MUST NOT send a method the endpoint did not advertise, and an endpoint
answers one it did not advertise with `capability_required`. Storage is
advertised separately from resolution because a consumer that reads a token
usually has no business replacing it, and because an operator may run the
endpoint read-only. `secretspec serve` advertises both mutation methods;
`secretspec serve --read-only` advertises neither.

A read-only endpoint also refuses any resolution that would store what it
produced. Withholding the two mutation methods does not by itself make a session
read-only, because minting a `generate = true` value or accepting a `prompt =
true` answer writes it back; see [failure mapping](#failure-mapping).

`resolver.reject` is required rather than optional, and a read-only endpoint
advertises it too. It discards a derived copy and never an authoritative value,
and a consumer with no write authority is precisely the one that otherwise has
no way to retire a credential its issuer revoked.

## Resolve an exact name

`resolver.get` resolves one exact name on the session's active profile and
scope. The resolver uses the same least-access behavior as
`Secrets::resolve_named`: an unrelated required secret cannot fail the request,
and only composition inputs of the requested secret may be read.

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

`name` is a SecretSpec declaration name, not a provider-native address. It is
validated exactly as a manifest name and MUST fit within 4,096 UTF-8 bytes.

`representation` is:

| Value | Behavior |
| --- | --- |
| `auto` | Return the representation selected by the declaration's `as_path` setting |
| `value` | Require an inline value; fail with `representation_mismatch` for an `as_path` declaration |
| `path` | Require an `as_path` declaration and return a location to read the secret from; fail with `representation_mismatch` for an inline declaration |

Both spellings describe what the returned string contains: the secret itself,
or a location to read it from. The file the resolver writes for the `path` form
is how that location is produced, not something the caller selects.

Requiring the representation prevents a token consumer from accidentally using a
path as a token, or a path consumer from treating secret contents as a path.

`purpose` is mandatory attribution for this call. `consumer` and `operation`
are non-empty strings of at most 256 UTF-8 bytes. `host` and `path` are optional
strings of at most 4,096 bytes; omit them when they do not apply. The resolver may
include this context in its protected audit event, but must otherwise treat it
as sensitive metadata.

Purpose is not identity. The resolver and providers MUST NOT use these
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

`source` is one of `provider`, `generated`, `default`, or `composed`. The set is
closed for the resolver and open for the client: a later revision may name
another origin, so a client MUST decode a value it does not know as an
unrecognized origin rather than failing the response. A client that treats
provenance as security-relevant reads an unrecognized origin as one it cannot
vouch for and decides accordingly.
`source_provider` is present only for provider results and MUST be the
credential-free display URI returned by `Provider::uri()`.

`expires_at_unix_ms` is required, and it is narrower than its name suggests.
Read it as **how long this copy of the value is considered current**, never as
how long the credential works.

It is non-null only when the value was served from a SecretSpec cache, where it
is the moment that cache entry goes stale: the time the entry was written plus
the operator's configured `max_age`. It is null for every value read from an
authoritative provider, including a credential that genuinely expires, because
version 1 providers report values on read and not lifetimes.

Two consequences a consumer must not get wrong:

- **Passing this time does not mean the credential stopped working.** It means
  SecretSpec would re-read the upstream store rather than serve its copy again.
  Resolving the name again typically returns the same bytes with a later
  timestamp.
- **A credential can stop working long before this time, or when it is null.**
  Nothing in a clock detects revocation. That is what
  [`resolver.reject`](#report-a-refused-value) is for: a consumer that was
  refused reports it, and the cached copy is discarded regardless of how much
  of its window remained.

A caller may still use the timestamp to avoid holding a copy indefinitely. It
must not use it as the sole trigger for re-authentication, and it must not treat
a null as "this never expires".

It is also unrelated to a path lease: a leased path must still be released even
if its value goes stale, and release may remove it earlier.

The result carries secret data. The client should copy it directly into its
final protected destination and release its JSON/frame buffers promptly.

### Leased path

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "status": "resolved",
    "representation": "path",
    "path": "/run/user/1000/secretspec/session-random/secret-random",
    "path_lease_id": "Qk7jXGfOLpLzmvYxjOxvMw",
    "source": "provider",
    "source_provider": "file:./credentials",
    "expires_at_unix_ms": 1786770000000
  }
}
```

The resolver, not the client, owns the file behind the path. `path_lease_id` is
an unpredictable, session-local opaque token containing at least 128 bits of
randomness. The client must not parse it and must not send it on another
connection.

A lease here is a handle over a file this resolver owns, and nothing else. It is
unrelated to the credential leases a dynamic provider issues, renews, and
revokes; those are a
[reserved extension](/reference/ipc-architecture#reserved-for-dynamic-secrets)
that will carry their own distinctly named members. This one is named for the
path it releases so the two can never be confused.

A lease is a lifetime handle, not a read capability. Holding the lease ID is
not what permits reading the file, and not holding it is not what prevents it:
the file is protected by its own permissions, so any process running as the
resolver user can open the path for as long as the file exists. Releasing a
lease shortens that window; it does not narrow who may read within it. A caller
that needs a secret withheld from other processes at the same privilege level
needs process isolation, not a lease, and should prefer the `value`
representation so nothing reaches the filesystem at all.

On POSIX systems, the resolver creates a mode-0700 session directory and a
mode-0400 regular file owned by the resolver user. It must defend against
symlinks and path replacement. On Windows, the directory and file receive a
non-inheriting ACL limited to the resolver user and required system identities.
The response path is absolute.

The resolver retains the file until the first of:

- every lease referring to it has been released;
- the client disconnects;
- `rpc.shutdown` cleans the session;
- the resolver exits.

If resolution is cancelled, its deadline expires, or its result cannot be
written, any newly created file is removed without creating a client-visible
lease. Resolver startup should remove abandoned directories created by earlier
crashes only after verifying ownership, type, and a conservative age bound.

## Release path leases

`resolver.release` releases one or more leases:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "resolver.release",
  "_meta": { "deadline_unix_ms": 1786766406000 },
  "params": {
    "path_lease_ids": ["Qk7jXGfOLpLzmvYxjOxvMw"]
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

## Ask the client for a value

:::caution[Version compatibility]
`client.prompt` is available starting with SecretSpec 0.20.
:::

This is the one method the resolver sends and the client answers. A declaration
with `prompt = true` and no stored value can only be satisfied by a person, and
the resolver cannot reach one: its stdin and stdout are the protocol, and its
stderr is a diagnostic channel the launcher captures. So it asks the process
that launched it, which does have a terminal or a window.

A client that can ask a person advertises the callback during initialization:

```json
{
  "protocol": "secretspec.resolver",
  "versions": [1],
  "client": { "name": "cargo", "version": "1.94.0" },
  "client_methods": ["client.prompt"],
  "limits": { "max_frame_bytes": 1048576, "max_in_flight": 8 },
  "application": {}
}
```

The resolver then sends, on the same connection, while a `resolver.get` is in
flight:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "client.prompt",
  "_meta": { "deadline_unix_ms": 1786766405000 },
  "params": {
    "name": "DEPLOY_PASSWORD",
    "profile": "production",
    "target_provider": "keyring://"
  }
}
```

The client answers with the value the person entered:

```json
{ "jsonrpc": "2.0", "id": 1, "result": { "value": "entered by a person" } }
```

Rules:

- The resolver MUST NOT send `client.prompt` unless the client advertised it. A
  client that did not is never asked, and a `prompt = true` declaration with no
  stored value resolves to `status: missing` immediately. That is the point of
  advertising: a headless consumer gets its answer at once instead of waiting
  out a deadline on a question nobody would see.
- The request IDs the resolver allocates for callbacks are its own. They are
  independent of the client's request IDs, and the two spaces may overlap.
- The callback carries no free-form message. The client composes what a person
  reads from `name`, `profile`, and `target_provider`, so the resolver cannot
  put arbitrary text in front of the person answering.
- `target_provider` is the credential-free display URI of the provider that
  will store the answer. It is absent when the answer is used for this
  resolution only and never stored.
- `value` is a secret. It is at least one byte, is treated exactly like a
  resolved value in both directions, and MUST NOT be logged. An empty answer is
  refused, for the same reason `resolver.set` refuses an empty value.
- The callback's deadline is never later than the `resolver.get` that raised it,
  and cancelling that request cancels the callback. A person who never answers
  cannot hold the resolver past the caller's own deadline.
- A client that declines answers with an error rather than an empty value; the
  resolve then fails as `interaction_required`.
- Both sides MUST keep reading while a callback is outstanding. A client that
  blocks its reader to ask a person deadlocks the session, because the same
  connection carries the response it is waiting for.
- `libsecretspec-resolver` answers prompts without a callback (0.20+). Its ABI
  deliberately hands no function pointer to a foreign runtime, so the caller
  drives the answer instead: a session opened with the answer-prompts flag has
  its calls report that a prompt is pending, and the caller takes it, answers or
  declines it, and waits again. A session that does not set the flag advertises
  nothing and is never asked.

## Report a refused value

:::caution[Version compatibility]
`resolver.reject` is available starting with SecretSpec 0.20. Every endpoint
advertises it.
:::

Nothing in a clock detects revocation. `expires_at_unix_ms` says when
SecretSpec's copy of a value goes stale, and it is null altogether for a value
read straight from a provider, so it can never be what retires a credential the
issuer withdrew. Only the consumer that was refused knows that happened.

`resolver.reject` is how it says so: it reports that a value this session
resolved was refused by whatever it was presented to, and the resolver discards
its cached copy so the next resolve consults the authoritative store again. It
applies whatever the timestamp said, including to a copy with hours of window
left and to one that never had a timestamp at all.

```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "method": "resolver.reject",
  "_meta": { "deadline_unix_ms": 1786766409000 },
  "params": {
    "name": "FORGE_TOKEN",
    "purpose": {
      "consumer": "nix",
      "operation": "fetch",
      "host": "github.com",
      "path": "/acme/project"
    }
  }
}
```

```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "result": {
    "status": "rejected",
    "invalidated": true
  }
}
```

`name` and `purpose` carry the meaning they have for `resolver.get`. Send this
only for a value this session actually resolved and actually had refused; it is
a report, not a way to ask the resolver to re-read a name.

Rules:

- Only SecretSpec's own cached copy is discarded. The authoritative store behind
  the cached route is not read, written, or removed, so this is not a mutation
  and a read-only endpoint answers it.
- `invalidated` is `true` when a cached copy was discarded. It is `false` when
  there was nothing to discard, and that is a success, not an error.
- Every "nothing to discard" reason reports the same result: no cached copy,
  a name whose route has no cache, a composed declaration, and a name the
  active scope does not offer. Reporting them apart would make a scope disclose
  the names it hides, exactly as `resolver.get` reports a hidden name as
  `undeclared`.
- Rejection is idempotent. Sending it twice is not an error, and the second
  reports `invalidated: false`.
- A real invalidation is recorded in the resolver's protected audit event with
  the request's `purpose`. A rejection that discarded nothing is not, so an
  empty cache stays distinguishable from a credential that was actually retired.
- The resolver does not re-resolve the name, contact the issuer, or notify the
  provider. The consumer resolves again when it wants a fresh value.

## Store a value

:::caution[Version compatibility]
`resolver.set` and `resolver.delete` are available starting with SecretSpec
0.20, and only from endpoints that advertise them.
:::

`resolver.set` stores one exact declared name on the session's active profile
and scope:

```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "resolver.set",
  "_meta": { "deadline_unix_ms": 1786766407000 },
  "params": {
    "name": "FORGE_TOKEN",
    "value": "secret text",
    "purpose": {
      "consumer": "cargo",
      "operation": "login",
      "host": "crates.io"
    }
  }
}
```

```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "result": {
    "status": "stored",
    "target_provider": "keyring://"
  }
}
```

`name` and `purpose` carry the meaning they have for `resolver.get`. `value` is
the secret as a UTF-8 string of at least one byte, and it is transport-sensitive
in the same way a resolved value is. An empty value is rejected: stores disagree
about whether one means "absent" or "present and empty", and that difference
decides what a later read finds. A caller that wants the value gone sends
`resolver.delete`.

`target_provider`, when present, is the credential-free display URI of the
provider that took the write.

Rules:

- The value lands where `resolver.get` for the same name on the same session
  would look for it. A consumer that stores and then resolves never has to model
  the resolver's routing.
- Only the primary write provider of the name's route is written. A fallback
  chain is not traversed and no copy is written to the stores behind it.
- The active scope bounds a write exactly as it bounds a read: a name the scope
  does not offer is not a name the session may store.
- A name the profile does not declare has no address to write to. Unlike a
  missing value, this is not a state the caller can route around, so it is
  `operation_failed` rather than a status.
- A composed, extracted, or otherwise derived declaration is read-only, and so
  is a provider that does not accept writes. Both are refused before the value
  is sent anywhere.
- The resolver does not prompt, here as anywhere else in this protocol. A store
  that needs an interaction the resolver cannot provide returns
  `interaction_required`.

## Remove a value

`resolver.delete` removes one exact declared name's stored value from the same
provider `resolver.set` would write to:

```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "resolver.delete",
  "_meta": { "deadline_unix_ms": 1786766408000 },
  "params": {
    "name": "FORGE_TOKEN",
    "purpose": {
      "consumer": "cargo",
      "operation": "logout",
      "host": "crates.io"
    }
  }
}
```

```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "result": {
    "status": "deleted",
    "deleted": true,
    "target_provider": "keyring://"
  }
}
```

Removal is idempotent: a name the store held nothing for reports `deleted:
false` and is a success. Every rule listed for `resolver.set` applies, including
the scope bound and the single write provider. A successful removal also
invalidates any cached copy, so a later resolve cannot return the value that was
just removed.

## Failure mapping

The common [error table](/reference/ipc-wire#errors) is deliberately smaller
than `SecretSpecError`. Resolver implementations map errors as follows:

| Resolver condition | IPC result or error |
| --- | --- |
| Name absent or hidden by scope | `status: undeclared` result |
| Visible declaration has no value | `status: missing` result |
| Wrong requested representation | `representation_mismatch` |
| Reason policy requires interaction with no available channel | `interaction_required` |
| Provider authorization refusal | `permission_denied` |
| Read would store a generated or prompted value on a read-only endpoint | `permission_denied` |
| Provider temporarily unreachable | `unavailable` only when retry safety is known; otherwise `operation_failed` |
| Name absent or hidden by scope on a rejection | `invalidated: false` result |
| Cache store unreachable on a rejection | `operation_failed` |
| Name absent or hidden by scope on a mutation | `operation_failed` |
| Declaration or provider does not accept writes | `operation_failed` |
| Mutation method the endpoint did not advertise | `capability_required` |
| Manifest, profile, scope, generation, composition, or other resolver error | `operation_failed` |

The resolver may retain a full local error for protected diagnostics, but the IPC
error must follow the wire protocol's redaction rules. In particular, it must
not serialize `SecretSpecError::to_string()` directly.

## Reconnect and retry

A child exit or broken pipe fails every in-flight request with a local
transport error and invalidates every lease. The client may launch a fresh
resolver for later work, but it MUST NOT replay the failed request
automatically. Reads can prompt, generate and persist a secret, refresh a
cache, or emit an audit event, so even `resolver.get` is not assumed free of
side effects.

A `resolver.set` or `resolver.delete` that was cancelled, expired, or lost with
its transport has an outcome the client cannot infer: the write may already have
reached the store. The caller learns what happened by resolving the name on a
fresh session, not by repeating the mutation.

The new process performs initialization from the beginning. Session state,
request IDs, and lease IDs are never reused.

## SDK integration policy

The wire contract, not either implementation API, is canonical. SDKs have three supported runtime
strategies:

1. Keep embedding the Rust resolver, as existing SDKs do today.
2. Use the Rust `secretspec-ipc` client for Rust resolver mode. Its default client
   is async; its `blocking` feature serves consumers that have no async runtime
   and should not take on one, such as a build tool reading a single token.
3. Bind the pure-C `libsecretspec-resolver` client for non-Rust resolver mode.

Independent implementations may implement the canonical wire protocol directly,
but supported non-Rust SecretSpec SDKs must not create per-language client state
machines. The Rust and C clients pass the same language-neutral conformance
suite and differential tests. Language packages expose the backend choice
explicitly; silently changing an embedded SDK to launch a process would alter
deployment, prompting, lifecycle, and trust behavior.
