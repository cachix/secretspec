import Foundation

private let resolveSchemaVersion = 2
private let reportSchemaVersion = 1

/// Caller-asserted software-integration context (SecretSpec 0.20+).
public struct CallerContext: Encodable, Sendable {
    public let name: String
    public let version: String?
    public let operation: String?
    public let resource: String?

    public init(
        name: String,
        version: String? = nil,
        operation: String? = nil,
        resource: String? = nil
    ) {
        self.name = name
        self.version = version
        self.operation = operation
        self.resource = resource
    }
}

private struct ResolveRequest: Encodable, Sendable {
    var path: String? = nil
    var provider: String? = nil
    var profile: String? = nil
    var scope: String? = nil
    var reason: String? = nil
    var caller: CallerContext? = nil
    var noValues: Bool? = nil
    var mode: String? = nil

    enum CodingKeys: String, CodingKey {
        case path
        case provider
        case profile
        case scope
        case reason
        case caller
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

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case provider
        case profile
        case scope
        case secrets
    }
}

/// Configures a SecretSpec resolution.
public struct SecretSpecBuilder: Sendable {
    private var request = ResolveRequest()
    private var inline: InlineSpec? = nil

    private struct InlineSpec: Sendable {
        let declaration: Data
        let baseDir: String
    }

    public init() {}

    public func withPath(_ path: String?) -> Self {
        var copy = setting(\.path, to: path)
        copy.inline = nil
        return copy
    }

    /// Resolves strict inline-spec v1 at `baseDir` (SecretSpec 0.20+).
    ///
    /// The declaration is encoded once into the dedicated native wire format.
    /// An older native library reports a capability error rather than searching
    /// for a filesystem manifest.
    public func withInlineSpec<Declaration: Encodable & Sendable>(
        _ declaration: Declaration,
        baseDir: String
    ) throws -> Self {
        var copy = self
        copy.request.path = nil
        copy.inline = InlineSpec(
            declaration: try JSONEncoder().encode(declaration), baseDir: baseDir
        )
        return copy
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

    /// Identifies the invoking software integration (SecretSpec 0.20+).
    public func withCaller(_ caller: CallerContext?) -> Self {
        setting(\.caller, to: caller)
    }

    public func withNoValues(_ noValues: Bool = true) -> Self {
        setting(\.noValues, to: noValues)
    }

    /// Resolves the configured secrets.
    ///
    /// - Throws: ``MissingRequiredError`` when required secrets are absent, or
    ///   ``SecretSpecError`` for any other failure.
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
            secrets: response.secrets
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
            if let inline {
                let declaration = try JSONSerialization.jsonObject(with: inline.declaration)
                requestData = try JSONSerialization.data(withJSONObject: [
                    "request_version": 1,
                    "operation": "resolve",
                    "source": [
                        "kind": "inline", "spec_version": 2,
                        "base_dir": inline.baseDir, "spec": declaration,
                    ],
                    "options": try JSONSerialization.jsonObject(with: JSONEncoder().encode(configured)),
                ])
            } else {
                requestData = try JSONEncoder().encode(configured)
            }
        } catch {
            throw SecretSpecError(kind: "encode", message: error.localizedDescription)
        }
        guard let requestJSON = String(data: requestData, encoding: .utf8) else {
            throw SecretSpecError(
                kind: "encode",
                message: "could not encode the request as UTF-8"
            )
        }

        let responseJSON: String
        if inline == nil {
            responseJSON = try Native.resolve(requestJSON)
        } else {
            responseJSON = try Native.call(requestJSON)
        }
        let envelope: Envelope<Response>
        do {
            envelope = try JSONDecoder().decode(
                Envelope<Response>.self,
                from: Data(responseJSON.utf8)
            )
        } catch {
            throw SecretSpecError(kind: "parse", message: error.localizedDescription)
        }

        guard envelope.ok else {
            throw SecretSpecError(
                kind: envelope.error?.kind ?? "unknown",
                message: envelope.error?.message
                    ?? "native resolver returned an unspecified error"
            )
        }
        guard let response = envelope.response else {
            throw SecretSpecError(
                kind: "ffi",
                message: "secretspec_resolve reported ok with no response"
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
            throw SecretSpecError(
                kind: "version",
                message: "unsupported \(kind) schema version \(actual) "
                    + "(expected \(expected)); the libsecretspec library "
                    + "and this SDK are out of sync"
            )
        }
    }
}

/// Entry point for the SecretSpec Swift SDK.
public enum SecretSpec {
    public static func builder() -> SecretSpecBuilder {
        SecretSpecBuilder()
    }

    /// Resolves secrets in one call.
    public static func resolve(
        path: String? = nil,
        provider: String? = nil,
        profile: String? = nil,
        scope: String? = nil,
        reason: String? = nil,
        caller: CallerContext? = nil
    ) throws -> Resolved {
        try configured(
            path: path,
            provider: provider,
            profile: profile,
            scope: scope,
            reason: reason,
            caller: caller
        ).load()
    }

    /// Builds a value-free inventory report in one call.
    public static func report(
        path: String? = nil,
        provider: String? = nil,
        profile: String? = nil,
        scope: String? = nil,
        reason: String? = nil,
        caller: CallerContext? = nil
    ) throws -> ResolutionReport {
        try configured(
            path: path,
            provider: provider,
            profile: profile,
            scope: scope,
            reason: reason,
            caller: caller
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
        reason: String?,
        caller: CallerContext?
    ) -> SecretSpecBuilder {
        builder()
            .withPath(path)
            .withProvider(provider)
            .withProfile(profile)
            .withScope(scope)
            .withReason(reason)
            .withCaller(caller)
    }
}
