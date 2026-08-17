# SecretSpec IPC conformance suite

This directory contains the language-neutral cases for
`secretspec.client/1`, `secretspec.provider/1`, and the shared wire protocol.
It is available with SecretSpec 0.20+.

Run the checked-in case and fixture validation with:

```console
cargo run -p secretspec-ipc-conformance -- check
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

The broker case is consumed by an integration test that launches the real
`secretspec broker --stdio` executable. It verifies inline initialization,
exact-name value/missing/undeclared results, file mode, duplicate release, and
disconnect cleanup:

```console
cargo test -p secretspec --test ipc_broker
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
