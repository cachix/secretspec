using Monosecret;

var report = Monosecret.Builder()
    .WithProfile("production")
    .WithReason("deployment preflight")
    .Report();

foreach (var secret in report.Secrets)
    Console.WriteLine($"{secret.Name}: {secret.Status}");
