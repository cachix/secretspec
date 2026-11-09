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

`as_path` uses private temporary files by default. Set
`SECRETSPEC_FILE_STORAGE=file-lease` to opt into process-owned, memory-backed
files on Linux and macOS (0.22+). This mode requires the matching `secretspec`
executable beside the application or on PATH; `SECRETSPEC_BIN` selects it.
Linux leases require sufficient `RLIMIT_MEMLOCK`. Explicit lease failures and
unsupported platforms return errors without a disk fallback.

SDK cleanup releases visible files and hidden composition dependencies for
either backend. Temporary files must be explicitly cleaned up; they are not
revoked automatically on process exit. See
[file delivery and lifetimes](https://secretspec.dev/reference/configuration/#as_path-option).
