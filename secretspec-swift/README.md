# SecretSpec for Swift

> Available in SecretSpec 0.18+.

The `SecretSpec` Swift package resolves the same `secretspec.toml` manifests as
the CLI and every other SDK. It supports macOS 12 or later on Intel and Apple
silicon; the SwiftPM package includes the Rust resolver in an XCFramework.

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
cargo build -p secretspec-ffi
mkdir -p secretspec-swift/Artifacts
bash scripts/build-swift-xcframework.sh \
  secretspec-swift/Artifacts/CSecretSpec.xcframework \
  target/debug/libsecretspec_ffi.dylib
swift test
```

The checked-in `Package.swift` selects that ignored local artifact when it
exists. Otherwise it downloads the checksummed release XCFramework.

The SDK deliberately wraps SecretSpec's existing, versioned JSON-over-C ABI
instead of adding UniFFI. The core already presents only three C functions and
all other language SDKs conform to its JSON schema; a generated object ABI would
duplicate that contract without removing meaningful Swift code. Swift imports
the C header as a Clang module, while the public package exposes only idiomatic
Swift `Codable` models and errors.
