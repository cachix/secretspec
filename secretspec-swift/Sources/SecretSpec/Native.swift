import CSecretSpec
import Darwin
import Foundation

enum Native {
    static func resolve(_ requestJSON: String) throws -> String {
        guard let response = requestJSON.withCString({ secretspec_resolve($0) }) else {
            throw SecretSpecError(kind: "ffi", message: "secretspec_resolve returned null")
        }
        defer { secretspec_free(response) }
        guard let result = String(validatingUTF8: response) else {
            throw SecretSpecError(kind: "ffi", message: "secretspec_resolve returned invalid UTF-8")
        }
        return result
    }

    static func call(_ requestJSON: String) throws -> String {
        typealias CallFunction = @convention(c) (UnsafePointer<CChar>?)
            -> UnsafeMutablePointer<CChar>?

        // The checked-in package still downloads the 0.19.1 XCFramework. Look
        // up the 0.20+ entry point only when inline specs are used, so ordinary
        // calls continue to compile and run against that older binary.
        guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "secretspec_call") else {
            throw SecretSpecError(
                kind: "capability",
                message: "the loaded libsecretspec library does not support inline specs "
                    + "(missing secretspec_call)"
            )
        }
        let call = unsafeBitCast(symbol, to: CallFunction.self)
        guard let response = requestJSON.withCString({ call($0) }) else {
            throw SecretSpecError(kind: "ffi", message: "secretspec_call returned null")
        }
        defer {
            secretspec_free(response)
        }
        guard let result = String(validatingUTF8: response) else {
            throw SecretSpecError(kind: "ffi", message: "secretspec_call returned invalid UTF-8")
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
