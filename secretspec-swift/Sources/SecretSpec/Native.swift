import CSecretSpec
import Foundation

enum Native {
    static func resolve(_ requestJSON: String) throws -> String {
        guard let response = requestJSON.withCString({ secretspec_resolve($0) }) else {
            throw SecretSpecError(
                kind: "ffi",
                message: "secretspec_resolve returned null"
            )
        }
        defer {
            secretspec_free(response)
        }

        guard let result = String(validatingUTF8: response) else {
            throw SecretSpecError(
                kind: "ffi",
                message: "secretspec_resolve returned invalid UTF-8"
            )
        }
        return result
    }

    static func abiVersion() throws -> String {
        guard
            let pointer = secretspec_abi_version(),
            let version = String(validatingUTF8: pointer)
        else {
            throw SecretSpecError(
                kind: "ffi",
                message: "secretspec_abi_version returned null or invalid UTF-8"
            )
        }
        return version
    }
}
