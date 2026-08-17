# secretspec-ipc

Independent Rust implementation of SecretSpec IPC version 1 (SecretSpec
0.20+). The checked-in JSON Schema and OpenRPC documents under
`schema/ipc/v1/` are canonical; this crate supplies strict framing/envelopes,
multiplexed clients, a server dispatcher, child lifecycle management, and typed
resolution/provider handler APIs.

The runtime-independent codec builds without Tokio:

```console
cargo check -p secretspec-ipc --no-default-features
```

The default `tokio` feature enables async transports, clients, servers, process
launch, and handler adapters.
