import Monosecret

func oneShot() throws {
    let resolved = try Monosecret.resolve(
        provider: "keyring://",
        profile: "production",
        reason: "boot web app"
    )
    try resolved.close()
}
