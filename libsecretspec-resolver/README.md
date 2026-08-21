# libsecretspec-resolver

`libsecretspec-resolver` is the pure C11 client for SecretSpec IPC, available in
SecretSpec 0.20+. It contains no Rust or SecretSpec resolver/provider code. The
public ABI is
[include/secretspec_resolver.h](include/secretspec_resolver.h); JSON goes
through yyjson behind a private adapter, and no yyjson type appears in the ABI.

## yyjson dependency

yyjson is a build dependency rather than vendored source, resolved through
pkg-config (Meson, and the cc-rs build script of the workspace conformance
package) and through its CMake package config (`find_package(yyjson CONFIG)`).
0.12.0 is the version CI builds and tests against. Releases back to 0.8.0
declare every API the client calls and compile it cleanly, so a distribution
package that lags behind should work as well, but only 0.12.0 is exercised
here.

Provide it however the platform prefers:

- Nix: `pkgs.yyjson`, already in `devenv.nix`. This needs a nixpkgs new enough
  to carry [ibireme/yyjson#295](https://github.com/ibireme/yyjson/pull/295).
  Without that patch `yyjson.pc` composes `libdir` and `includedir` by
  concatenating the prefix with install dirs that nixpkgs passes as absolute
  paths, so `pkg-config --cflags yyjson` points at a directory that does not
  exist. `devenv.yaml` pins a nixpkgs commit that carries the patch and says
  why.
- Homebrew: `brew install yyjson`.
- vcpkg: `vcpkg install yyjson`.
- Debian and Ubuntu: `libyyjson-dev`, present from Ubuntu 25.10 onward.
- From source, which is what CI does on every platform for one pinned version:
  `scripts/install-yyjson.sh`.

Runners without pkg-config can point the conformance build script at an install
prefix with `YYJSON_INCLUDE_DIR` and `YYJSON_LIB_DIR` instead.

Because yyjson ships as a static archive whose symbols carry default
visibility, both build systems pass a linker flag that keeps those symbols out
of the shared library's exports. Without it an application's own copy of yyjson
could interpose on the one this library calls. Check after touching either
build system that the shared library still exports only `secretspec_resolver_*`:

```console
nm -D --defined-only build/libsecretspec-resolver.so.1 | grep yyjson
```

Treat a yyjson security advisory as release-blocking whenever it affects
enabled parsing or writing code, even if no SecretSpec regression is known, and
bump the pinned version in `scripts/install-yyjson.sh` along with its digest.

This client serves only `secretspec.resolver/1` (application or SDK to
resolver). The provider protocol's client is always SecretSpec itself and is
implemented in Rust. This library is separate from `libsecretspec`, the
embedded in-process resolver ABI.

Build static and shared libraries plus the C-only smoke, session,
backpressure, and regression tests with either build system:

```console
cmake -S . -B build -DSECRETSPEC_RESOLVER_BUILD_TESTS=ON
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
must be released with `secretspec_resolver_buffer_free`.

Both build systems compile the library and C-only tests as strict C11 with
warnings treated as errors. The workspace conformance package additionally
links these C sources into its differential property test and compares their
normalized call outcomes with the independent Rust client.
