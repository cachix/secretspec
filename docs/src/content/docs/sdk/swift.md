---
title: Swift SDK
description: Resolve SecretSpec secrets from Swift on macOS
---

> **Version compatibility:** The Swift SDK is available in SecretSpec 0.18+.

The Swift SDK is a thin `Codable` wrapper over the same Rust resolver and
versioned C ABI as the other language SDKs. Every provider, fallback chain,
profile, scope, generator, reference, and `as_path` secret therefore works
without Swift-side resolution logic.

## Install (0.18+)

In Xcode, choose **File → Add Package Dependencies** and enter:

```text
https://github.com/cachix/secretspec
```

Or add the package to `Package.swift`:

```swift
dependencies: [
    .package(
        url: "https://github.com/cachix/secretspec",
        from: "0.18.0"
    ),
],
targets: [
    .target(
        name: "MyApp",
        dependencies: [
            .product(name: "SecretSpec", package: "secretspec"),
        ]
    ),
]
```

The package supports macOS 12 or later on Intel and Apple silicon. Its
checksummed XCFramework contains the native Rust resolver, so consumers need
neither Rust nor a separately installed SecretSpec library. SecretSpec is a
development-workflow secrets manager with filesystem, process, and desktop
credential-store integrations; the SDK does not target iOS, watchOS, tvOS, or
visionOS.

## Quick start

```swift
import SecretSpec

let resolved = try SecretSpec.builder()
    .withProvider("keyring://")
    .withProfile("production")
    .withReason("boot web app")
    .load()
defer { try? resolved.close() }

print(resolved.provider, resolved.profile)
print(resolved.secrets["DATABASE_URL"]?.get() ?? "")
try resolved.setAsEnvironment()
```

`get()` returns the inline value, or the readable file path for an `as_path`
secret. A missing required secret throws `MissingRequiredError`; its `missing`
property contains the unresolved names. Other failures throw
`SecretSpecError`, whose `kind` property is a stable error category:

```swift
do {
    let resolved = try SecretSpec.builder().load()
    defer { try? resolved.close() }
    // Use resolved.
} catch let error as MissingRequiredError {
    print("Missing:", error.missing.joined(separator: ", "))
} catch let error as SecretSpecError {
    print("\(error.kind): \(error.message)")
}
```

A one-shot form is also available:

```swift
let resolved = try SecretSpec.resolve(
    provider: "keyring://",
    profile: "production",
    reason: "boot web app"
)
```

## Scopes

Use `withScope("api")` to resolve only a named `[scopes.api]` subset. The
selected name is available through `resolved.scope` and `report.scope`:

```swift
let resolved = try SecretSpec.builder().withScope("api").load()
```

## Value-free preflight

`report()` returns the inventory view exposed by `secretspec check --json`. It
never carries values. A missing required secret appears with
`status == "missing_required"` rather than throwing, so an incomplete
deployment can still be inspected.

```swift
let report = try SecretSpec.builder()
    .withProfile("production")
    .withReason("deployment preflight")
    .report()

for secret in report.secrets {
    print("\(secret.name): \(secret.status)")
}
```

## Typed access

Generate an idiomatic Swift model from the manifest schema:

```bash
secretspec schema |
  quicktype -s schema --top-level AppSecrets --lang swift -o AppSecrets.swift
```

Then decode the SDK's flat field map:

```swift
let typed = try JSONDecoder().decode(
    AppSecrets.self,
    from: resolved.fieldsJSON()
)
print(typed.databaseURL)
```

The schema models successful resolution: required, defaulted, and generated
secrets are non-nullable, and profile schemas include inherited
default-profile fields.

## Files (`as_path`)

File-shaped secrets are materialized as mode-0400 temporary files. Call
`resolved.close()` after the last consumer finishes with those paths.
`Resolved` also performs best-effort cleanup when it is deinitialized, but
explicit cleanup gives deterministic lifetime and reports filesystem errors.
