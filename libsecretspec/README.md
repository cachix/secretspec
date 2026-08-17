# libsecretspec

`libsecretspec` is SecretSpec's embedded C ABI. It links the Rust resolver and
all enabled in-tree providers into a shared or static native library, exposing
three JSON-in/JSON-out functions through
[`include/secretspec.h`](include/secretspec.h).

The public name is `libsecretspec` starting with SecretSpec 0.20. Earlier
releases called this component `secretspec-ffi` and emitted library filenames
containing `secretspec_ffi`; the 0.20 SDK runtime loaders continue to recognize
those older shared-library filenames.

Public artifacts are:

- `libsecretspec.so`, `libsecretspec.dylib`, or `secretspec.dll`;
- `libsecretspec.a` for static embedding;
- `secretspec.h`; and
- `libsecretspec.pc` when installed with cargo-c.

Build the native library directly with:

```console
cargo build -p libsecretspec --release
```

Or install one library form, its header, and pkg-config metadata:

```console
bash libsecretspec/scripts/cinstall.sh "$PREFIX" static
bash libsecretspec/scripts/cinstall.sh "$PREFIX" shared
```

This is distinct from [`libsecretspec-ipc`](../libsecretspec-ipc/), the pure-C
client for SecretSpec's out-of-process resolution and provider protocols.
