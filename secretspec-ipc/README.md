# secretspec-ipc

Independent Rust implementation of SecretSpec IPC version 1 (SecretSpec
0.20+). The checked-in JSON Schema and OpenRPC documents under
`schema/ipc/v1/` are canonical; this crate supplies strict framing/envelopes,
multiplexed clients, a server dispatcher, child lifecycle management, and typed
resolution/provider handler APIs.

Endpoints also answer `rpc.discover` before or after initialization (SecretSpec
0.20+). Discovery returns a self-contained OpenRPC document with its JSON
Schemas and endpoint metadata without loading application or provider state.
The crate packages the canonical discovery assets under `schema/ipc/v1/`.

The runtime-independent codec builds without Tokio:

```console
cargo check -p secretspec-ipc --no-default-features
```

The default `tokio` feature enables async transports, clients, servers, process
launch, and handler adapters.

The `blocking` feature adds a synchronous `secretspec.resolver/1` session over
`std::process`, for a consumer that has no async runtime and should not acquire
one. It reuses the same framing, envelopes, and validation, and adds no
dependency beyond the runtime-independent set:

```console
cargo check -p secretspec-ipc --no-default-features --features blocking
```
