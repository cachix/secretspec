# libsecretspec-ipc

`libsecretspec-ipc` is the pure C11 client for SecretSpec IPC, available in
SecretSpec 0.20+. It contains no Rust or SecretSpec resolver/provider code. The
public ABI is [include/secretspec_ipc.h](include/secretspec_ipc.h); yyjson 0.12.0
is pinned behind a private adapter in `vendor/`.

One library serves both IPC boundaries: initialization selects either
`secretspec.client/1` (application/SDK to broker) or `secretspec.provider/1`
(SecretSpec to an external provider), and the method sets cannot be mixed on a
session. This is separate from `libsecretspec`, the embedded in-process resolver
ABI.

Build static and shared libraries plus the C-only smoke/session tests with
either build system:

```console
cmake -S . -B build -DSECRETSPEC_IPC_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

```console
meson setup build
meson compile -C build
meson test -C build
```

The client launches an exact executable without a shell, owns its child and
joinable workers, negotiates limits before application traffic, multiplexes
bounded calls, and performs deadline/cancellation/shutdown handling. Input
slices are borrowed only for a call. Returned buffers belong to the library and
must be released with `secretspec_ipc_buffer_free`.

Both build systems compile the library and C-only tests as strict C11 with
warnings treated as errors. The workspace conformance package additionally
links these C sources into its differential property test and compares their
normalized call outcomes with the independent Rust client.
