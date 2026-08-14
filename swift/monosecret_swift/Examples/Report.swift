import Monosecret

func report() throws {
    let report = try Monosecret.builder()
        .withProfile("production")
        .withReason("deployment preflight")
        .report()

    for secret in report.secrets {
        print("\(secret.name): \(secret.status)")
    }
}
