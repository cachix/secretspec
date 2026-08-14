import Foundation

private let resolveSchemaVersion = 2
private let reportSchemaVersion = 1

private struct ResolveRequest: Encodable, Sendable {
    var path: String? = nil
    var provider: String? = nil
    var profile: String? = nil
    var scope: String? = nil
    var reason: String? = nil
    var noValues: Bool? = nil
    var mode: String? = nil

    enum CodingKeys: String, CodingKey {
        case path
        case provider
        case profile
        case scope
        case reason
        case noValues = "no_values"
        case mode
    }
}

private struct ErrorPayload: Decodable {
    let kind: String?
    let message: String?
}

private struct Envelope<Response: Decodable>: Decodable {
    let ok: Bool
    let response: Response?
    let error: ErrorPayload?
}

private struct ResolveResponse: Decodable {
    let schemaVersion: Int
    let provider: String
    let profile: String
    let scope: String?
    let secrets: [String: ResolvedSecret]
    let missingRequired: [String]
    let missingOptional: [String]

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case provider
        case profile
        case scope
        case secrets
        case missingRequired = "missing_required"
        case missingOptional = "missing_optional"
    }
}

private struct ReportResponse: Decodable {
    let schemaVersion: Int
    let provider: String
    let profile: String
    let scope: String?
    let secrets: [SecretReport]
    let constraintViolations: [ConstraintViolation]?

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case provider
        case profile
        case scope
        case secrets
        case constraintViolations = "constraint_violations"
    }
}

/// Configures a Monosecret resolution.
public struct MonosecretBuilder: Sendable {
    private var request = ResolveRequest()

    public init() {}

    public func withPath(_ path: String?) -> Self {
        setting(\.path, to: path)
    }

    public func withProvider(_ provider: String?) -> Self {
        setting(\.provider, to: provider)
    }

    public func withProfile(_ profile: String?) -> Self {
        setting(\.profile, to: profile)
    }

    /// Limits resolution to a named manifest scope.
    public func withScope(_ scope: String?) -> Self {
        setting(\.scope, to: scope)
    }

    public func withReason(_ reason: String?) -> Self {
        setting(\.reason, to: reason)
    }

    public func withNoValues(_ noValues: Bool = true) -> Self {
        setting(\.noValues, to: noValues)
    }

    /// Resolves the configured secrets.
    ///
    /// - Throws: ``MissingRequiredError`` when required secrets are absent, or
    ///   ``MonosecretError`` for any other failure.
    public func load() throws -> Resolved {
        let response: ResolveResponse = try call(mode: nil)
        try ensureSchemaVersion(
            actual: response.schemaVersion,
            expected: resolveSchemaVersion,
            kind: "resolve"
        )
        if !response.missingRequired.isEmpty {
            throw MissingRequiredError(missing: response.missingRequired)
        }

        return Resolved(
            provider: response.provider,
            profile: response.profile,
            scope: response.scope,
            secrets: response.secrets,
            missingOptional: response.missingOptional
        )
    }

    /// Builds a value-free inventory report.
    ///
    /// Missing required secrets appear in the report rather than throwing.
    public func report() throws -> ResolutionReport {
        let response: ReportResponse = try call(mode: "report")
        try ensureSchemaVersion(
            actual: response.schemaVersion,
            expected: reportSchemaVersion,
            kind: "report"
        )
        return ResolutionReport(
            provider: response.provider,
            profile: response.profile,
            scope: response.scope,
            secrets: response.secrets,
            constraintViolations: response.constraintViolations ?? []
        )
    }

    private func setting<Value>(
        _ keyPath: WritableKeyPath<ResolveRequest, Value>,
        to value: Value
    ) -> Self {
        var copy = self
        copy.request[keyPath: keyPath] = value
        return copy
    }

    private func call<Response: Decodable>(mode: String?) throws -> Response {
        var configured = request
        configured.mode = mode

        let requestData: Data
        do {
            requestData = try JSONEncoder().encode(configured)
        } catch {
            throw MonosecretError(kind: "encode", message: error.localizedDescription)
        }
        guard let requestJSON = String(data: requestData, encoding: .utf8) else {
            throw MonosecretError(
                kind: "encode",
                message: "could not encode the request as UTF-8"
            )
        }

        let responseJSON = try Native.resolve(requestJSON)
        let envelope: Envelope<Response>
        do {
            envelope = try JSONDecoder().decode(
                Envelope<Response>.self,
                from: Data(responseJSON.utf8)
            )
        } catch {
            throw MonosecretError(kind: "parse", message: error.localizedDescription)
        }

        guard envelope.ok else {
            throw MonosecretError(
                kind: envelope.error?.kind ?? "unknown",
                message: envelope.error?.message
                    ?? "native resolver returned an unspecified error"
            )
        }
        guard let response = envelope.response else {
            throw MonosecretError(
                kind: "ffi",
                message: "monosecret_resolve reported ok with no response"
            )
        }
        return response
    }

    private func ensureSchemaVersion(
        actual: Int,
        expected: Int,
        kind: String
    ) throws {
        guard actual == expected else {
            throw MonosecretError(
                kind: "version",
                message: "unsupported \(kind) schema version \(actual) "
                    + "(expected \(expected)); the libmonosecret_ffi library "
                    + "and this SDK are out of sync"
            )
        }
    }
}

/// Entry point for the Monosecret Swift SDK.
public enum Monosecret {
    public static func builder() -> MonosecretBuilder {
        MonosecretBuilder()
    }

    /// Resolves secrets in one call.
    public static func resolve(
        path: String? = nil,
        provider: String? = nil,
        profile: String? = nil,
        scope: String? = nil,
        reason: String? = nil
    ) throws -> Resolved {
        try configured(
            path: path,
            provider: provider,
            profile: profile,
            scope: scope,
            reason: reason
        ).load()
    }

    /// Builds a value-free inventory report in one call.
    public static func report(
        path: String? = nil,
        provider: String? = nil,
        profile: String? = nil,
        scope: String? = nil,
        reason: String? = nil
    ) throws -> ResolutionReport {
        try configured(
            path: path,
            provider: provider,
            profile: profile,
            scope: scope,
            reason: reason
        ).report()
    }

    /// The ABI version reported by the bundled native resolver.
    public static func abiVersion() throws -> String {
        try Native.abiVersion()
    }

    private static func configured(
        path: String?,
        provider: String?,
        profile: String?,
        scope: String?,
        reason: String?
    ) -> MonosecretBuilder {
        builder()
            .withPath(path)
            .withProvider(provider)
            .withProfile(profile)
            .withScope(scope)
            .withReason(reason)
    }
}
