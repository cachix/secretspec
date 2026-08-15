import Foundation
import XCTest

#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

@testable import SecretSpec

final class SecretSpecTests: XCTestCase {
    private static let manifest = """
    [project]
    name = "swift-test"
    revision = "1.0"

    [profiles.default]
    DATABASE_URL = { description = "DB", required = true }
    DEV_SESSION_SECRET = { description = "Development-only session secret", required = false, default = "development-only-secret" }
    SENTRY_DSN = { description = "sentry", required = false }

    [scopes.database]
    secrets = ["DATABASE_URL"]
    """

    func testABIVersion() throws {
        XCTAssertFalse(try SecretSpec.abiVersion().isEmpty)
    }

    func testCallerContextCanAccompanyASeparateReason() throws {
        let project = try Project(
            manifest: Self.manifest,
            dotenv: "DATABASE_URL=postgres://db\n"
        )
        let resolved = try project.builder()
            .withCaller(CallerContext(
                name: "git",
                version: "2.51.0",
                operation: "credential_get",
                resource: "github.com"
            ))
            .withReason("push the release tag")
            .load()
        defer { try? resolved.close() }
        XCTAssertEqual(resolved.secrets["DATABASE_URL"]?.get(), "postgres://db")
    }

    func testLoadValuesAndProvenance() throws {
        let project = try Project(
            manifest: Self.manifest,
            dotenv: "DATABASE_URL=postgres://db\n"
        )
        let resolved = try project.builder().load()
        defer { try? resolved.close() }

        XCTAssertEqual(resolved.profile, "default")
        XCTAssertEqual(resolved.secrets["DATABASE_URL"]?.get(), "postgres://db")
        XCTAssertEqual(resolved.secrets["DATABASE_URL"]?.source, "provider")
        XCTAssertNotNil(resolved.secrets["DATABASE_URL"]?.sourceProvider)
        XCTAssertEqual(
            resolved.secrets["DEV_SESSION_SECRET"]?.get(),
            "development-only-secret"
        )
        XCTAssertEqual(resolved.secrets["DEV_SESSION_SECRET"]?.source, "default")
        XCTAssertEqual(resolved.missingOptional, ["SENTRY_DSN"])
        XCTAssertNil(resolved.secrets["SENTRY_DSN"])

        let fields = try JSONSerialization.jsonObject(with: resolved.fieldsJSON())
        let object = try XCTUnwrap(fields as? [String: Any])
        XCTAssertEqual(object["DATABASE_URL"] as? String, "postgres://db")
    }

    func testScopedResolveAndReport() throws {
        let project = try Project(
            manifest: Self.manifest,
            dotenv: "DATABASE_URL=postgres://db\nSENTRY_DSN=https://sentry\n"
        )
        let builder = project.builder().withScope("database")

        let resolved = try builder.load()
        defer { try? resolved.close() }
        XCTAssertEqual(resolved.scope, "database")
        XCTAssertEqual(Set(resolved.secrets.keys), ["DATABASE_URL"])

        let report = try builder.report()
        XCTAssertEqual(report.scope, "database")
        XCTAssertEqual(report.secrets.map(\.name), ["DATABASE_URL"])
    }

    func testMissingRequiredError() throws {
        let project = try Project(manifest: Self.manifest, dotenv: "")
        XCTAssertThrowsError(try project.builder().load()) { error in
            guard let missing = error as? MissingRequiredError else {
                return XCTFail("expected MissingRequiredError, got \(error)")
            }
            XCTAssertEqual(missing.missing, ["DATABASE_URL"])
            XCTAssertEqual(missing.kind, "missing_required")
        }
    }

    func testInvalidManifestError() {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
            .appendingPathComponent("secretspec.toml")
            .path

        XCTAssertThrowsError(
            try SecretSpec.builder().withPath(path).withReason("Swift test").load()
        ) { error in
            guard let failure = error as? SecretSpecError else {
                return XCTFail("expected SecretSpecError, got \(error)")
            }
            XCTAssertFalse(failure.kind.isEmpty)
        }
    }

    func testAsPathCleanup() throws {
        let manifest = """
        [project]
        name = "swift-test"
        revision = "1.0"

        [profiles.default]
        TLS_CERT = { description = "cert", required = true, as_path = true }
        """
        let project = try Project(manifest: manifest, dotenv: "TLS_CERT=----cert----\n")
        let resolved = try project.builder().load()
        let certificate = try XCTUnwrap(resolved.secrets["TLS_CERT"])
        XCTAssertTrue(certificate.asPath)
        XCTAssertNil(certificate.value)
        let path = try XCTUnwrap(certificate.get())
        XCTAssertEqual(try String(contentsOfFile: path), "----cert----")

        try resolved.close()
        XCTAssertFalse(FileManager.default.fileExists(atPath: path))
    }

    func testValueFreeReport() throws {
        let project = try Project(manifest: Self.manifest, dotenv: "")
        let report = try project.builder().report()

        XCTAssertEqual(report.profile, "default")
        let database = try XCTUnwrap(
            report.secrets.first { $0.name == "DATABASE_URL" }
        )
        XCTAssertEqual(database.status, "missing_required")
        XCTAssertTrue(database.required)
        let session = try XCTUnwrap(
            report.secrets.first { $0.name == "DEV_SESSION_SECRET" }
        )
        XCTAssertTrue(session.defaultApplied)
    }

    func testEnvironmentExport() throws {
        let project = try Project(
            manifest: Self.manifest,
            dotenv: "DATABASE_URL=postgres://environment\n"
        )
        let previous = getenv("DATABASE_URL").map { String(cString: $0) }
        defer {
            if let previous {
                setenv("DATABASE_URL", previous, 1)
            } else {
                unsetenv("DATABASE_URL")
            }
        }

        let resolved = try project.builder().load()
        defer { try? resolved.close() }
        try resolved.setAsEnvironment()
        XCTAssertEqual(
            getenv("DATABASE_URL").map { String(cString: $0) },
            "postgres://environment"
        )
    }

    func testOneShotAPI() throws {
        let project = try Project(
            manifest: Self.manifest,
            dotenv: "DATABASE_URL=postgres://one-shot\n"
        )
        let resolved = try SecretSpec.resolve(
            path: project.manifestPath,
            provider: project.provider,
            reason: "Swift test"
        )
        defer { try? resolved.close() }
        XCTAssertEqual(resolved.secrets["DATABASE_URL"]?.get(), "postgres://one-shot")

        let report = try SecretSpec.report(
            path: project.manifestPath,
            provider: project.provider,
            reason: "Swift test"
        )
        XCTAssertEqual(
            report.secrets.first { $0.name == "DATABASE_URL" }?.status,
            "resolved"
        )
    }

    func testCrossLanguageConformance() throws {
        let root = try repositoryRoot()
        let fixtures = root.appendingPathComponent("conformance/fixtures")
        let fixtureDirectories = try FileManager.default
            .contentsOfDirectory(
                at: fixtures,
                includingPropertiesForKeys: [.isDirectoryKey]
            )
            .filter { (try? $0.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
        XCTAssertFalse(
            fixtureDirectories.isEmpty,
            "no cross-language conformance fixtures were discovered"
        )

        for fixture in fixtureDirectories {
            let manifest = fixture.appendingPathComponent("secretspec.toml").path
            let provider = "dotenv://\(fixture.appendingPathComponent(".env").path)"
            let builder = SecretSpec.builder()
                .withPath(manifest)
                .withProvider(provider)
                .withReason("conformance")

            let resolved = try builder.load()
            try assertJSONEqual(
                expectedAt: fixture.appendingPathComponent("expected.json"),
                actual: try canonicalResolved(resolved)
            )
            try resolved.close()

            let noValues = try builder.withNoValues().load()
            try assertJSONEqual(
                expectedAt: fixture.appendingPathComponent("expected_no_values.json"),
                actualData: try noValues.fieldsJSON()
            )
            try noValues.close()

            let report = try builder.report()
            try assertJSONEqual(
                expectedAt: fixture.appendingPathComponent("expected_report.json"),
                actual: canonicalReport(report)
            )
        }
    }

    private func canonicalResolved(_ resolved: Resolved) throws -> [String: Any] {
        var secrets: [String: Any] = [:]
        for (name, secret) in resolved.secrets {
            let value: String?
            if secret.asPath {
                value = try secret.get().map { try String(contentsOfFile: $0) }
            } else {
                value = secret.value
            }
            let canonicalValue: Any = value.map { $0 as Any } ?? NSNull()
            let canonicalSecret: [String: Any] = [
                "value": canonicalValue,
                "source": secret.source,
                "as_path": secret.asPath,
            ]
            secrets[name] = canonicalSecret
        }
        return [
            "profile": resolved.profile,
            "secrets": secrets,
            "missing_required": [String](),
            "missing_optional": resolved.missingOptional,
        ]
    }

    private func canonicalReport(_ report: ResolutionReport) -> [String: Any] {
        var secrets: [String: Any] = [:]
        for secret in report.secrets {
            let canonicalSecret: [String: Any] = [
                "status": secret.status,
                "required": secret.required,
                "as_path": secret.asPath,
                "generated": secret.generated,
                "default_applied": secret.defaultApplied,
                "source_provider": secret.sourceProvider != nil,
            ]
            secrets[secret.name] = canonicalSecret
        }
        return [
            "profile": report.profile,
            "secrets": secrets,
        ]
    }

    private func repositoryRoot() throws -> URL {
        var candidate = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        while candidate.path != "/" {
            if FileManager.default.fileExists(
                atPath: candidate.appendingPathComponent("Cargo.toml").path
            ), FileManager.default.fileExists(
                atPath: candidate.appendingPathComponent("conformance").path
            ) {
                return candidate
            }
            candidate.deleteLastPathComponent()
        }
        throw SecretSpecError(
            kind: "test",
            message: "could not find the SecretSpec repository root"
        )
    }

    private func assertJSONEqual(
        expectedAt url: URL,
        actual: [String: Any]
    ) throws {
        let actualData = try JSONSerialization.data(
            withJSONObject: actual,
            options: [.sortedKeys]
        )
        try assertJSONEqual(expectedAt: url, actualData: actualData)
    }

    private func assertJSONEqual(
        expectedAt url: URL,
        actualData: Data
    ) throws {
        let expected = try JSONSerialization.jsonObject(with: Data(contentsOf: url))
        let actual = try JSONSerialization.jsonObject(with: actualData)
        let expectedObject = try XCTUnwrap(expected as? NSObject)
        XCTAssertTrue(
            expectedObject.isEqual(actual),
            "JSON mismatch for \(url.deletingLastPathComponent().lastPathComponent)"
        )
    }
}

private final class Project {
    let root: URL
    let manifestPath: String
    let provider: String

    init(manifest: String, dotenv: String) throws {
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent("secretspec-swift-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true
        )
        let manifestURL = root.appendingPathComponent("secretspec.toml")
        let dotenvURL = root.appendingPathComponent(".env")
        try Data(manifest.utf8).write(to: manifestURL)
        try Data(dotenv.utf8).write(to: dotenvURL)
        manifestPath = manifestURL.path
        provider = "dotenv://\(dotenvURL.path)"
    }

    deinit {
        try? FileManager.default.removeItem(at: root)
    }

    func builder() -> SecretSpecBuilder {
        SecretSpec.builder()
            .withPath(manifestPath)
            .withProvider(provider)
            .withReason("Swift test")
    }
}
