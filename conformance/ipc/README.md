# SecretSpec IPC conformance suite

This directory contains the language-neutral cases for
`secretspec.resolver/1`, `secretspec.provider/1`, and the shared wire protocol.
It is available with SecretSpec 0.20+.

Validate the checked-in case documents and the presence and JSON shape of the
schema/OpenRPC assets with:

```console
cargo run -p secretspec-ipc-conformance -- check
```

Validate every fixture against its JSON Schema, resolve all schema references,
and compare the OpenRPC method catalogs with the Rust constants with:

```console
cargo test -p secretspec-ipc --test fixtures
```

A target driver receives one case document on standard input and writes one
normalized JSON transcript on standard output:

```json
{"case":"wire.fragmented-frame","events":[{"kind":"accepted"}]}
```

Run a driver command directly (without a shell) with:

```console
cargo run -p secretspec-ipc-conformance -- run wire ./path/to/driver --stdio
```

The runner selects `common` plus the named target's cases, enforces each case's
timeout, rejects stderr or transcripts containing the canary, and checks the
required event kinds. A driver must implement public byte/process behavior; it
must not call private implementation internals. The same command protocol is
used by C and Rust client drivers so their normalized transcripts can be
compared by CI and by third-party provider endpoints. The checked-in
`ipc-client-conformance-driver` has independent `c` and `rust` modes and runs
the common wire cases plus `client.lifecycle` through each public client.

Rust server coverage includes `rpc.discover` (0.20+): it works before and after
initialization, returns a self-contained OpenRPC document, preserves increasing
request IDs into initialization, and never initializes application state or
issues a callback merely to describe the endpoint.

Run the executable client matrix directly with:

```console
cargo test -p secretspec-ipc-conformance --test client_cases
```

That test invokes the conformance runner as an external process twice. It does
not call runner internals or substitute the differential model for either
client.

The provider matrix launches a deterministic, stateful
`secretspec.provider/1` endpoint and runs the checked-in wire, operation,
expiry, clear, cancellation, deadline, crash, and reconnect cases through both
the Rust endpoint API and SecretSpec's external-provider adapter. It also
checks structured error preservation, one-shot failure non-replay, and process
isolation across provider URIs and reasons:

```console
cargo test -p secretspec-ipc-conformance --test provider_cases
```

Third-party endpoints can run the same target with a transport-only endpoint
profile (0.20+). The executable still comes from `--endpoint`; the profile
supplies its arguments, replacement environment, provider scheme/URI, expected
identity, and advertised method set:

```console
cargo run -p secretspec-ipc-conformance -- run provider-endpoint \
  ipc-provider-conformance-driver \
  --implementation endpoint \
  --endpoint /path/to/provider-endpoint \
  --profile conformance/ipc/profiles/transport-only.example.json
```

This profile runs framing, strict-wire, initialization, notification, and
connection-lifecycle cases without assuming provider storage semantics. Cases
that require the deterministic memory provider's disposable state, magic error
fixtures, or crash hooks are reported as `not applicable` rather than failed.
Because a transport-only profile has no operation that can safely trigger an
arbitrary provider's callbacks, callback brokerage is also outside this layer.
The bundled memory endpoint remains the full provider-operation matrix, and
callback paths require their own declared fixture. Profile `environment`
entries replace, rather than extend, the driver's environment so endpoint tests
do not accidentally depend on ambient secrets.

The resolver cases are consumed by integration tests that launch the real
`secretspec serve` executable. They verify inline initialization, exact-name
value/missing/undeclared results, file mode, duplicate release, disconnect
cleanup, cached-value rejection, and interactive versus headless prompt
handling:

```console
cargo test -p secretspec --test ipc_resolver
```

`cases/` is canonical test data rather than executable expectations hidden in
one language. The property tests additionally:

- generate frame histories and compare the production incremental decoder with
  an independent reference decoder; and
- serialize state-aware echo, cancellation, and deadline histories, run each
  history against the actual pure-C ABI and independent Rust client through the
  same deterministic child peer, and compare normalized outcomes.

Run those checks with `cargo test -p secretspec-ipc-conformance`. Proptest
prints the replay seed and the assertion includes the serialized history when a
difference is found. Minimized regressions belong in `cases/`.
