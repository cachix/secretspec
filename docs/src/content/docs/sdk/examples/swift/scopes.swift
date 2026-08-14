import Monosecret

func scopes() throws {
    let resolved = try Monosecret.builder().withScope("api").load()
    try resolved.close()
}
