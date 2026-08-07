using Cachix.SecretSpec;

var report = SecretSpec.Builder()
    .WithProfile("production")
    .WithReason("deployment preflight")
    .Report();

foreach (var secret in report.Secrets)
    Console.WriteLine($"{secret.Name}: {secret.Status}");
