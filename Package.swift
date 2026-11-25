// swift-tools-version: 5.9

import Foundation
import PackageDescription

// Keep this in sync with the Cargo workspace version via
// scripts/sync-sdk-versions.sh. Release preparation replaces the checksum
// after building the versioned XCFramework; see RELEASE.md.
let secretSpecBinaryVersion = "0.21.1"
let secretSpecBinaryChecksum = "5bf678226fe6a546a2a57d2901d3219fae8ddd5d3c0e5a8f62b13701f9e6d420"

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
        .executableTarget(
            name: "SecretSpecExamples",
            dependencies: ["SecretSpec"],
            path: "secretspec-swift/Examples"
        ),
        .testTarget(
            name: "SecretSpecTests",
            dependencies: ["SecretSpec"],
            path: "secretspec-swift/Tests/SecretSpecTests"
        ),
    ]
)
