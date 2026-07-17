using Cachix.SecretSpec;
using SecretSpecClient = Cachix.SecretSpec.SecretSpec;

var root = Path.Combine(
    Path.GetTempPath(),
    $"secretspec-dotnet-package-smoke-{Guid.NewGuid()}");

try
{
    Directory.CreateDirectory(root);
    var manifest = Path.Combine(root, "secretspec.toml");
    var dotenv = Path.Combine(root, ".env");

    File.WriteAllText(
        manifest,
        """
        [project]
        name = "dotnet-package-smoke"
        revision = "1.0"

        [profiles.default]
        PACKAGE_SMOKE = { description = "Package smoke value", required = true }
        """);
    File.WriteAllText(dotenv, "PACKAGE_SMOKE=loaded-from-packaged-native-resolver\n");

    var abiVersion = SecretSpecClient.AbiVersion();
    if (string.IsNullOrWhiteSpace(abiVersion))
        throw new Exception("native resolver returned an empty ABI version");

    using var resolved = SecretSpecClient.Builder()
        .WithPath(manifest)
        .WithProvider($"dotenv://{dotenv}")
        .WithReason("NuGet package smoke test")
        .Load();

    var value = resolved.Secrets["PACKAGE_SMOKE"].Get();
    if (value != "loaded-from-packaged-native-resolver")
        throw new Exception($"unexpected resolved value: {value}");

    Console.WriteLine($"PASS packaged native resolver ABI {abiVersion}");
}
finally
{
    if (Directory.Exists(root))
        Directory.Delete(root, recursive: true);
}
