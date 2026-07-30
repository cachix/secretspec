// swift-tools-version: 5.9

import Foundation
import PackageDescription

// Keep this in sync with the Cargo workspace version via
// scripts/sync-sdk-versions.sh. Release preparation replaces the checksum
// after building the versioned XCFramework; see RELEASE.md.
let secretSpecBinaryVersion = "0.17.0"
let secretSpecBinaryChecksum = "0000000000000000000000000000000000000000000000000000000000000000"

let localBinaryPath = "secretspec-swift/Artifacts/CSecretSpec.xcframework"
let packageRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
let hasLocalBinary = FileManager.default.fileExists(
    atPath: packageRoot.appendingPathComponent(localBinaryPath).path
)

let ffiTarget: Target = hasLocalBinary
    ? .binaryTarget(name: "CSecretSpec", path: localBinaryPath)
    : .binaryTarget(
        name: "CSecretSpec",
        url: "https://github.com/cachix/secretspec/releases/download/v\(secretSpecBinaryVersion)/CSecretSpec.xcframework.zip",
        checksum: secretSpecBinaryChecksum
    )

let package = Package(
    name: "SecretSpec",
    platforms: [
        .macOS(.v12),
    ],
    products: [
        .library(name: "SecretSpec", targets: ["SecretSpec"]),
    ],
    targets: [
        ffiTarget,
        .target(
            name: "SecretSpec",
            dependencies: ["CSecretSpec"],
            path: "secretspec-swift/Sources/SecretSpec"
        ),
        .testTarget(
            name: "SecretSpecTests",
            dependencies: ["SecretSpec"],
            path: "secretspec-swift/Tests/SecretSpecTests"
        ),
    ]
)
