# libsecretspec-ipc

`libsecretspec-ipc` is the pure C11 client for SecretSpec IPC, available in
SecretSpec 0.20+. It contains no Rust or SecretSpec resolver/provider code. The
public ABI is [include/secretspec_ipc.h](include/secretspec_ipc.h); yyjson 0.12.0
is pinned behind a private adapter in `vendor/`.

## TODO: consume yyjson as a package instead of vendoring it

`vendor/` is roughly half of every diff that touches this library, and it makes
us responsible for tracking yyjson security releases. It stays vendored for now
because system discovery is currently unreliable:

- yyjson's `yyjson.pc` composes `libdir`/`includedir` by concatenating the
  prefix with the install dirs, which double-applies the prefix whenever a
  distribution passes absolute install dirs (nixpkgs does, to support split
  outputs). `pkg-config --cflags yyjson` then points at a directory that does
  not exist. Fix submitted upstream as
  [ibireme/yyjson#295](https://github.com/ibireme/yyjson/pull/295).
- nixpkgs has a `cmakePcfileCheckPhase` guard for this class of bug, but it
  greps for `}//nix/store` and yyjson expands `@CMAKE_INSTALL_PREFIX@` directly,
  so the broken file ships undetected. Worth reporting separately.

Once the upstream fix is released and reaches nixpkgs (which already pins
0.12.0, matching `vendor/`), drop `vendor/` and resolve yyjson through:

- `meson.build`: `dependency('yyjson')`
- `CMakeLists.txt`: `find_package(yyjson CONFIG REQUIRED)`
- `conformance/ipc/runner/build.rs`: pkg-config, and note that under Nix the
  header already resolves through `NIX_CFLAGS_COMPILE` with no pkg-config at all

Add `yyjson` to `devenv.nix`, and add CI coverage for the meson and cmake
builds at the same time: today no workflow exercises either, so both are
effectively untested. Only the cc-rs path in `build.rs` runs in CI.

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
