// swift-tools-version: 5.9

import Foundation
import PackageDescription

// monochange.toml keeps this in sync with the Cargo workspace version.
// The all-zero checksum is an intentional placeholder while the first
// Monosecret XCFramework release remains deferred (planned for 0.2+).
let monosecretBinaryVersion = "0.1.0"
let monosecretBinaryChecksum = "0000000000000000000000000000000000000000000000000000000000000000"

let localBinaryPath = "swift/monosecret_swift/Artifacts/CMonosecret.xcframework"
let packageRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
let hasLocalBinary = FileManager.default.fileExists(
    atPath: packageRoot.appendingPathComponent(localBinaryPath).path
)

let ffiTarget: Target = hasLocalBinary
    ? .binaryTarget(name: "CMonosecret", path: localBinaryPath)
    : .binaryTarget(
        name: "CMonosecret",
        url: "https://github.com/ifiokjr/monosecret/releases/download/v\(monosecretBinaryVersion)/CMonosecret.xcframework.zip",
        checksum: monosecretBinaryChecksum
    )

let package = Package(
    name: "Monosecret",
    platforms: [
        .macOS(.v12),
    ],
    products: [
        .library(name: "Monosecret", targets: ["Monosecret"]),
    ],
    targets: [
        ffiTarget,
        .target(
            name: "Monosecret",
            dependencies: ["CMonosecret"],
            path: "swift/monosecret_swift/Sources/Monosecret"
        ),
        .executableTarget(
            name: "MonosecretExamples",
            dependencies: ["Monosecret"],
            path: "swift/monosecret_swift/Examples"
        ),
        .testTarget(
            name: "MonosecretTests",
            dependencies: ["Monosecret"],
            path: "swift/monosecret_swift/Tests/MonosecretTests"
        ),
    ]
)
