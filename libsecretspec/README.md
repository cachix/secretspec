# libsecretspec

`libsecretspec` is SecretSpec's embedded C ABI. It links the Rust resolver and
all enabled in-tree providers into a shared or static native library, exposing
three JSON-in/JSON-out functions through
[`include/secretspec.h`](include/secretspec.h).

The public name is `libsecretspec` starting with SecretSpec 0.20. Earlier
releases called this component `secretspec-ffi` and emitted library filenames
containing `secretspec_ffi`; the 0.20 SDK runtime loaders continue to recognize
those older shared-library filenames.

The rename changes packaging, not the three exported C symbols or their
ownership rules. Compatibility is intentionally asymmetric:

| Consumer | Pre-0.20 native library with a 0.20 SDK | 0.20 native library with a pre-0.20 SDK |
| --- | --- | --- |
| Go purego, .NET, PHP FFI | Supported by legacy filename fallback; only pre-0.20 behavior is available | Requires the old filename or an explicit `SECRETSPEC_FFI_LIB` path |
| Ruby native extension | New source builds accept `libsecretspec_ffi.a`; an already-built extension is unaffected | A pre-0.20 source build still looks for the old archive name |
| Go cgo/pkg-config and Haskell source builds | Rebuild against `libsecretspec.pc` | Rebuild or provide compatibility pkg-config/archive names |
| Python, Node, Swift, packaged .NET/PHP/Ruby artifacts | Native code is bundled or linked by the package; runtime filename discovery does not apply | Upgrade the package and native artifact together |

Filename fallback is not feature emulation: an older library cannot implement
0.20 request fields or behavior. SDK schema/ABI checks still decide whether a
particular old library is usable. `SECRETSPEC_FFI_LIB` keeps its established
environment-variable spelling across the rename.

Public artifacts are:

- `libsecretspec.so`, `libsecretspec.dylib`, or Cargo's `secretspec.dll`
  (some SDK packages stage the Windows DLL as `libsecretspec.dll`);
- `libsecretspec.a`, or the platform-equivalent static library, for static
  embedding;
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

This is distinct from
[`libsecretspec-resolver`](../libsecretspec-resolver/), the pure-C client for
SecretSpec's out-of-process resolution protocol.
