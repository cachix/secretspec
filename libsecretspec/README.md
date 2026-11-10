# libsecretspec

`libsecretspec` is SecretSpec's embedded C ABI. It links the Rust resolver and
all enabled in-tree providers into a shared or static native library, exposing
four JSON-in/JSON-out and ownership functions through
[`include/secretspec.h`](include/secretspec.h).

The public name is `libsecretspec` starting with SecretSpec 0.20. Earlier
releases called this component `secretspec-ffi` and emitted library filenames
containing `secretspec_ffi`; the 0.20 SDK runtime loaders continue to recognize
those older shared-library filenames.

The rename changes packaging, not the exported C symbols or their ownership
rules. Compatibility is intentionally asymmetric:

| Consumer | Pre-0.20 native library with a 0.20 SDK | 0.20 native library with a pre-0.20 SDK |
| --- | --- | --- |
| Go purego, .NET, PHP FFI | Supported by legacy filename fallback; only pre-0.20 behavior is available | Requires the old filename or an explicit `SECRETSPEC_FFI_LIB` path |
| Ruby native extension | Upgrade the static archive with the extension source; an already-built extension is unaffected | A pre-0.20 source build still looks for the old archive name |
| Go cgo/pkg-config and Haskell source builds | Rebuild against `libsecretspec.pc` and the 0.20 archive | Rebuild or provide compatibility pkg-config/archive names |
| Python, Node, Swift, JVM, packaged .NET/PHP/Ruby artifacts | Native code is bundled or linked by the package; runtime filename discovery does not apply | Upgrade the package and native artifact together |

Filename fallback is not feature emulation: an older library cannot implement
0.20 request fields or behavior such as inline specifications. SDK schema and
symbol checks still decide whether a particular old library is usable.
`SECRETSPEC_FFI_LIB` keeps its established environment-variable spelling across
the rename.

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

## Secret-file cleanup (0.22+)

`as_path` delivery uses private temporary files and does not need a helper.
Files remain until explicitly cleaned up; process exit does not remove them.

Resolve responses containing file dependencies carry an optional
`file_lease_id`, including when only a composition using a hidden file is
visible. Pass it to `secretspec_call` to revoke all files for that result:

```json
{"request_version":1,"operation":"release_files","source":{"lease_id":"<file_lease_id>"}}
```

The response is `{"ok":true,"response":{"schema_version":1,"released":1}}`.
Release is idempotent and tokens belong to the originating process. SDK cleanup
methods use this operation.

For consumers whose file API canonicalizes Linux memfd paths, **0.22+** also
supports a native read of a file belonging to a live result:

```json
{"request_version":1,"operation":"read_file","source":{"lease_id":"<file_lease_id>","path":"<original path>"}}
```

The response contains `schema_version: 1` and the file bytes in `base64`.
Unknown or released tokens and paths outside that result are rejected. Reads
are bounded to 64 MiB. PHP's `ResolvedSecret::open()` uses this operation to
populate a memory-only stream without canonicalizing the secret-file path.
