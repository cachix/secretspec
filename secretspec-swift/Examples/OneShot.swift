import SecretSpec

func oneShot() throws {
    let resolved = try SecretSpec.resolve(
        provider: "keyring://",
        profile: "production",
        reason: "boot web app"
    )
    try resolved.close()
}
