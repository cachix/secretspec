import Foundation

#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// One resolved secret and its provenance.
public struct ResolvedSecret: Decodable, Sendable {
    /// The inline value, or `nil` for an `as_path` secret.
    public let value: String?

    /// The materialized file path, or `nil` for an inline secret.
    public let path: String?

    public let asPath: Bool
    public let source: String
    public let sourceProvider: String?

    enum CodingKeys: String, CodingKey {
        case value
        case path
        case asPath = "as_path"
        case source
        case sourceProvider = "source_provider"
    }

    /// The usable string: the file path for `as_path`, otherwise the value.
    ///
    /// A value-free resolution returns `nil`.
    public func get() -> String? {
        asPath ? path : value
    }
}

/// A successful, value-carrying resolution.
///
/// Call ``close()`` when finished to remove files backing `as_path` secrets.
/// Deinitialization also attempts a best-effort cleanup.
public final class Resolved {
    public let provider: String
    public let profile: String
    public let scope: String?
    public let secrets: [String: ResolvedSecret]
    public let missingOptional: [String]

    private var closed = false

    init(
        provider: String,
        profile: String,
        scope: String?,
        secrets: [String: ResolvedSecret],
        missingOptional: [String]
    ) {
        self.provider = provider
        self.profile = profile
        self.scope = scope
        self.secrets = secrets
        self.missingOptional = missingOptional
    }

    deinit {
        try? close()
    }

    /// Exports every present secret into the current process environment.
    public func setAsEnvironment() throws {
        for (name, secret) in secrets {
            guard let value = secret.get() else {
                continue
            }
            guard !value.utf8.contains(0) else {
                throw SecretSpecError(
                    kind: "environment",
                    message: "secret \(name) contains a NUL byte and cannot be exported"
                )
            }

            let result = name.withCString { namePointer in
                value.withCString { valuePointer in
                    setenv(namePointer, valuePointer, 1)
                }
            }
            guard result == 0 else {
                throw SecretSpecError(
                    kind: "environment",
                    message: "could not export \(name): \(String(cString: strerror(errno)))"
                )
            }
        }
    }

    /// A flat secret-name-to-value map suitable for a generated decoder.
    ///
    /// File-shaped secrets map to their paths; stripped values map to `nil`.
    public func fields() -> [String: String?] {
        Dictionary(uniqueKeysWithValues: secrets.map { name, secret in
            (name, secret.get())
        })
    }

    /// Encodes ``fields()`` as the JSON input for a generated typed decoder.
    public func fieldsJSON() throws -> Data {
        try JSONEncoder().encode(fields())
    }

    /// Removes temporary files backing `as_path` secrets.
    public func close() throws {
        guard !closed else {
            return
        }
        closed = true

        var firstError: Error?
        for secret in secrets.values where secret.asPath {
            guard let path = secret.path else {
                continue
            }
            do {
                if FileManager.default.fileExists(atPath: path) {
                    try FileManager.default.removeItem(atPath: path)
                }
            } catch {
                firstError = firstError ?? error
            }
        }

        if let firstError {
            throw firstError
        }
    }
}

/// The value-free resolution outcome for one declared secret.
public struct SecretReport: Decodable, Sendable {
    public let name: String
    public let status: String
    public let required: Bool
    public let sourceProvider: String?
    public let defaultApplied: Bool
    public let generated: Bool
    public let asPath: Bool

    enum CodingKeys: String, CodingKey {
        case name
        case status
        case required
        case sourceProvider = "source_provider"
        case defaultApplied = "default_applied"
        case generated
        case asPath = "as_path"
    }
}

/// A value-free inventory/preflight snapshot.
public struct ResolutionReport: Sendable {
    public let provider: String
    public let profile: String
    public let scope: String?
    public let secrets: [SecretReport]
}
