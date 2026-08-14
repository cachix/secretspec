import CMonosecret
import Foundation

enum Native {
    static func resolve(_ requestJSON: String) throws -> String {
        guard let response = requestJSON.withCString({ monosecret_resolve($0) }) else {
            throw MonosecretError(
                kind: "ffi",
                message: "monosecret_resolve returned null"
            )
        }
        defer {
            monosecret_free(response)
        }

        guard let result = String(validatingUTF8: response) else {
            throw MonosecretError(
                kind: "ffi",
                message: "monosecret_resolve returned invalid UTF-8"
            )
        }
        return result
    }

    static func abiVersion() throws -> String {
        guard
            let pointer = monosecret_abi_version(),
            let version = String(validatingUTF8: pointer)
        else {
            throw MonosecretError(
                kind: "ffi",
                message: "monosecret_abi_version returned null or invalid UTF-8"
            )
        }
        return version
    }
}
