import SecretSpec

func report() throws {
    let report = try SecretSpec.builder()
        .withProfile("production")
        .withReason("deployment preflight")
        .report()

    for secret in report.secrets {
        print("\(secret.name): \(secret.status)")
    }
}
