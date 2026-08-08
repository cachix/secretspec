import SecretSpec

func handleErrors() {
    do {
        let resolved = try SecretSpec.builder().load()
        defer { try? resolved.close() }
        // Use resolved.
    } catch let error as MissingRequiredError {
        print("Missing:", error.missing.joined(separator: ", "))
    } catch let error as SecretSpecError {
        print("\(error.kind): \(error.message)")
    } catch {
        print(error)
    }
}
