# SecretSpec for Swift

> Available in SecretSpec 0.18+.

The `SecretSpec` Swift package resolves the same `secretspec.toml` manifests as
the CLI and every other SDK. It supports macOS 12 or later on Intel and Apple
silicon; the SwiftPM package includes the Rust resolver in an XCFramework.

> The embedded ABI packaged by the XCFramework is named `libsecretspec` in
> SecretSpec 0.20+. It was named `secretspec-ffi` through 0.19.

```swift
import SecretSpec

let resolved = try SecretSpec.builder()
    .withProvider("keyring://")
    .withProfile("production")
    .withReason("boot web app")
    .load()
defer { try? resolved.close() }

print(resolved.secrets["DATABASE_URL"]?.get() ?? "")
try resolved.setAsEnvironment()
```

A missing required secret throws `MissingRequiredError`. Other failures throw
`SecretSpecError`, whose `kind` is a stable machine-readable category.

## Local development

Build the Rust cdylib on macOS, turn it into the local XCFramework, and run the
Swift tests:

```bash
cargo build -p libsecretspec
mkdir -p secretspec-swift/Artifacts
bash scripts/build-swift-xcframework.sh \
  secretspec-swift/Artifacts/CSecretSpec.xcframework \
  target/debug/libsecretspec.dylib
swift test
```

The checked-in `Package.swift` selects that ignored local artifact when it
exists. Otherwise it downloads the checksummed release XCFramework.

The SDK deliberately wraps SecretSpec's existing, versioned JSON-over-C ABI
instead of adding UniFFI. The core already presents only four C functions and
all other language SDKs conform to its JSON schema; a generated object ABI would
duplicate that contract without removing meaningful Swift code. Swift imports
the C header as a Clang module, while the public package exposes only idiomatic
Swift `Codable` models and errors.

## Files and cleanup

In SecretSpec **0.22+**, `as_path` delivery uses memory-backed leases on Linux
and macOS. Install the matching `secretspec` executable beside the application
or on PATH to host the helper. `SECRETSPEC_BIN` can select its location (0.22+). Cleanup releases the complete result, including
hidden file dependencies, through the native lease API. Other platforms,
including Windows, and storage failures return an error without a disk fallback.
Older runtimes retain their existing temporary-file behavior.

Linux helpers require a sufficient `RLIMIT_MEMLOCK` for page-rounded live file
sizes (0.22+). See [file delivery limits](https://secretspec.dev/reference/configuration/#as_path-option).
