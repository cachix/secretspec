import Monosecret

func quickStart() throws {
    let resolved = try Monosecret.builder()
        .withProvider("keyring://")
        .withProfile("production")
        .withReason("boot web app")
        .load()
    defer { try? resolved.close() }

    print(resolved.provider, resolved.profile)
    print(resolved.secrets["DATABASE_URL"]?.get() ?? "")
    try resolved.setAsEnvironment()
}
