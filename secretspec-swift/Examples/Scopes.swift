import SecretSpec

func scopes() throws {
    let resolved = try SecretSpec.builder().withScope("api").load()
    try resolved.close()
}
