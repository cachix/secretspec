import Foundation

/// A manifest, provider, policy, native-boundary, or wire-format failure.
public struct SecretSpecError: Error, LocalizedError, CustomStringConvertible, Sendable {
    /// A stable machine-readable error category.
    public let kind: String

    /// The human-readable failure detail.
    public let message: String

    public init(kind: String, message: String) {
        self.kind = kind
        self.message = message
    }

    public var description: String {
        "\(message) (kind: \(kind))"
    }

    public var errorDescription: String? {
        description
    }
}

/// Required secrets that could not be resolved.
public struct MissingRequiredError: Error, LocalizedError, CustomStringConvertible, Sendable {
    public let missing: [String]

    public init(missing: [String]) {
        self.missing = missing
    }

    public var kind: String {
        "missing_required"
    }

    public var description: String {
        "missing required secret(s): \(missing.joined(separator: ", "))"
    }

    public var errorDescription: String? {
        description
    }
}
