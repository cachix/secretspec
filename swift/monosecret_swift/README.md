# Monosecret for Swift

> Planned for Monosecret 0.2+. Source and local tests are integrated, but the
> tagged SwiftPM/XCFramework release remains deferred.

The `Monosecret` Swift package resolves the same `monosecret.toml` manifests as
the CLI and every other SDK. It supports macOS 12 or later on Intel and Apple
silicon; the SwiftPM package includes the Rust resolver in an XCFramework.

```swift
import Monosecret

let resolved = try Monosecret.builder()
    .withProvider("keyring://")
    .withProfile("production")
    .withReason("boot web app")
    .load()
defer { try? resolved.close() }

print(resolved.secrets["DATABASE_URL"]?.get() ?? "")
try resolved.setAsEnvironment()
```

A missing required secret throws `MissingRequiredError`. Other failures throw
`MonosecretError`, whose `kind` is a stable machine-readable category.

## Local development

Build the Rust cdylib on macOS, turn it into the local XCFramework, and run the
Swift tests:

```bash
cargo build -p monosecret_ffi
bash swift/monosecret_swift/scripts/stage-local-xcframework.sh
swift test
```

The checked-in `Package.swift` selects that ignored local artifact when it
exists. Until the planned 0.2+ release publishes a checksummed XCFramework,
the remote target intentionally carries an all-zero placeholder checksum.

The SDK deliberately wraps Monosecret's existing, versioned JSON-over-C ABI
instead of adding UniFFI. The core already presents only three C functions and
all other language SDKs conform to its JSON schema; a generated object ABI would
duplicate that contract without removing meaningful Swift code. Swift imports
the C header as a Clang module, while the public package exposes only idiomatic
Swift `Codable` models and errors.
