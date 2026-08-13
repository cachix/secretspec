---
monosecret: breaking
---

# Integrate native references and language SDKs

Add provider-independent table-form `ref` coordinates, address-based provider
resolution, batch reads, writable checks, and value-free resolution reports.
Provider implementations must migrate to the new address-oriented APIs.

Integrate the shared native resolver source, local build paths, and tests for
`monosecret_ffi`, Dart, `@monosecret/client`, Python, Go, Ruby, and Haskell
bindings. The Dart package now resolves through `dart:ffi` without a separately
installed CLI, and release builds publish verified C ABI assets for Linux,
macOS, and Windows servers. Registry distribution for the other new native SDK
artifacts remains deferred.
