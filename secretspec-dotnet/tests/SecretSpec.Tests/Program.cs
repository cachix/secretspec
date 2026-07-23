using System.Text.Json;
using System.Text.Json.Nodes;
using Cachix.SecretSpec;
using SecretSpecClient = Cachix.SecretSpec.SecretSpec;

internal static class Program
{
    private const string Manifest = """
        [project]
        name = "dotnet-test"
        revision = "1.0"

        [profiles.default]
        DATABASE_URL = { description = "DB", required = true }
        LOG_LEVEL = { description = "log", required = false, default = "info" }
        SENTRY_DSN = { description = "sentry", required = false }

        [scopes.database]
        secrets = ["DATABASE_URL"]
        """;

    private static readonly List<(string Name, Action Test)> Tests =
    [
        ("ABI version", TestAbiVersion),
        ("load values and provenance", TestLoad),
        ("scoped resolution", TestScope),
        ("missing required exception", TestMissingRequired),
        ("invalid manifest exception", TestInvalidManifest),
        ("as_path cleanup", TestAsPathCleanup),
        ("value-free report", TestReport),
        ("environment export", TestSetAsEnv),
        ("one-shot API", TestOneShot),
        ("cross-language conformance", TestConformance),
    ];

    public static int Main()
    {
        var failures = new List<string>();
        foreach (var (name, test) in Tests)
        {
            try
            {
                test();
                Console.WriteLine($"PASS {name}");
            }
            catch (Exception error)
            {
                failures.Add(name);
                Console.Error.WriteLine($"FAIL {name}: {error}");
            }
        }

        if (failures.Count == 0)
        {
            Console.WriteLine($"All {Tests.Count} C# SDK tests passed");
            return 0;
        }

        Console.Error.WriteLine($"{failures.Count} C# SDK test(s) failed: {string.Join(", ", failures)}");
        return 1;
    }

    private static void TestAbiVersion() =>
        Assert(!string.IsNullOrWhiteSpace(SecretSpecClient.AbiVersion()), "ABI version was empty");

    private static void TestLoad()
    {
        using var project = Project.Create(Manifest, "DATABASE_URL=postgres://db\n");
        using var resolved = project.Builder().Load();

        Equal("default", resolved.Profile);
        Equal("postgres://db", resolved.Secrets["DATABASE_URL"].Get());
        Equal("provider", resolved.Secrets["DATABASE_URL"].Source);
        Assert(resolved.Secrets["DATABASE_URL"].SourceProvider is not null, "provider provenance missing");
        Equal("info", resolved.Secrets["LOG_LEVEL"].Get());
        Equal("default", resolved.Secrets["LOG_LEVEL"].Source);
        SequenceEqual(["SENTRY_DSN"], resolved.MissingOptional);
        Assert(!resolved.Secrets.ContainsKey("SENTRY_DSN"), "missing optional secret was returned");

        var fields = JsonNode.Parse(resolved.FieldsJson());
        Equal("postgres://db", fields?["DATABASE_URL"]?.GetValue<string>());
    }

    private static void TestScope()
    {
        using var project = Project.Create(
            Manifest,
            "DATABASE_URL=postgres://db\nSENTRY_DSN=https://sentry\n");
        var builder = project.Builder().WithScope("database");

        using var resolved = builder.Load();
        Equal("database", resolved.Scope);
        SequenceEqual(["DATABASE_URL"], resolved.Secrets.Keys);

        var report = builder.Report();
        Equal("database", report.Scope);
        SequenceEqual(["DATABASE_URL"], report.Secrets.Select(secret => secret.Name));
    }

    private static void TestMissingRequired()
    {
        using var project = Project.Create(Manifest, "");
        var error = Throws<MissingRequiredException>(() => project.Builder().Load());
        SequenceEqual(["DATABASE_URL"], error.Missing);
        Equal("missing_required", error.Kind);
    }

    private static void TestInvalidManifest()
    {
        var error = Throws<SecretSpecException>(() =>
            SecretSpecClient.Builder()
                .WithPath(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString(), "secretspec.toml"))
                .WithReason("C# test")
                .Load());
        Assert(error is not MissingRequiredException, "transport failure became missing-required");
        Assert(!string.IsNullOrWhiteSpace(error.Kind), "error kind was empty");
    }

    private static void TestAsPathCleanup()
    {
        const string manifest = """
            [project]
            name = "dotnet-test"
            revision = "1.0"

            [profiles.default]
            TLS_CERT = { description = "cert", required = true, as_path = true }
            """;
        using var project = Project.Create(manifest, "TLS_CERT=----cert----\n");
        string path;
        using (var resolved = project.Builder().Load())
        {
            var cert = resolved.Secrets["TLS_CERT"];
            Assert(cert.AsPath, "TLS_CERT was not marked as_path");
            Assert(cert.Value is null, "as_path secret exposed an inline value");
            path = cert.Get() ?? throw new Exception("as_path secret had no path");
            Equal("----cert----", File.ReadAllText(path));
        }
        Assert(!File.Exists(path), "Dispose did not remove the secret temp file");
    }

    private static void TestReport()
    {
        using var project = Project.Create(Manifest, "");
        var report = project.Builder().Report();

        Equal("default", report.Profile);
        var database = report.Secrets.Single(secret => secret.Name == "DATABASE_URL");
        Equal("missing_required", database.Status);
        Assert(database.Required, "DATABASE_URL was not reported as required");
        var logLevel = report.Secrets.Single(secret => secret.Name == "LOG_LEVEL");
        Assert(logLevel.DefaultApplied, "LOG_LEVEL default was not reported");
    }

    private static void TestSetAsEnv()
    {
        using var project = Project.Create(Manifest, "DATABASE_URL=postgres://environment\n");
        var previous = Environment.GetEnvironmentVariable("DATABASE_URL");
        try
        {
            using var resolved = project.Builder().Load();
            resolved.SetAsEnv();
            Equal("postgres://environment", Environment.GetEnvironmentVariable("DATABASE_URL"));
        }
        finally
        {
            Environment.SetEnvironmentVariable("DATABASE_URL", previous);
        }
    }

    private static void TestOneShot()
    {
        using var project = Project.Create(Manifest, "DATABASE_URL=postgres://one-shot\n");
        using var resolved = SecretSpecClient.Resolve(
            path: project.ManifestPath,
            provider: project.Provider,
            reason: "C# test");
        Equal("postgres://one-shot", resolved.Secrets["DATABASE_URL"].Get());

        var report = SecretSpecClient.Report(
            path: project.ManifestPath,
            provider: project.Provider,
            reason: "C# test");
        Equal("resolved", report.Secrets.Single(secret => secret.Name == "DATABASE_URL").Status);
    }

    private static void TestConformance()
    {
        var root = FindRepositoryRoot();
        var fixtures = Path.Combine(root, "conformance", "fixtures");
        foreach (var directory in Directory.EnumerateDirectories(fixtures).Order())
        {
            var manifest = Path.Combine(directory, "secretspec.toml");
            var provider = $"dotenv://{Path.Combine(directory, ".env")}";
            SecretSpecBuilder Fixture() => SecretSpecClient.Builder()
                .WithPath(manifest)
                .WithProvider(provider)
                .WithReason("conformance");

            using (var resolved = Fixture().Load())
            {
                AssertJsonEqual(
                    File.ReadAllText(Path.Combine(directory, "expected.json")),
                    CanonicalResolved(resolved).ToJsonString());
            }

            using (var noValues = Fixture().WithNoValues().Load())
            {
                AssertJsonEqual(
                    File.ReadAllText(Path.Combine(directory, "expected_no_values.json")),
                    noValues.FieldsJson());
            }

            var report = Fixture().Report();
            AssertJsonEqual(
                File.ReadAllText(Path.Combine(directory, "expected_report.json")),
                CanonicalReport(report).ToJsonString());
        }
    }

    private static JsonObject CanonicalResolved(Resolved resolved)
    {
        var secrets = new JsonObject();
        foreach (var (name, secret) in resolved.Secrets)
        {
            var value = secret.AsPath
                ? File.ReadAllText(secret.Get() ?? throw new Exception($"{name} had no path"))
                : secret.Value;
            secrets[name] = new JsonObject
            {
                ["value"] = value,
                ["source"] = secret.Source,
                ["as_path"] = secret.AsPath,
            };
        }

        return new JsonObject
        {
            ["profile"] = resolved.Profile,
            ["secrets"] = secrets,
            ["missing_required"] = new JsonArray(),
            ["missing_optional"] = new JsonArray(
                resolved.MissingOptional
                    .Select(value => (JsonNode?)JsonValue.Create(value))
                    .ToArray()),
        };
    }

    private static JsonObject CanonicalReport(ResolutionReport report)
    {
        var secrets = new JsonObject();
        foreach (var secret in report.Secrets)
        {
            secrets[secret.Name] = new JsonObject
            {
                ["status"] = secret.Status,
                ["required"] = secret.Required,
                ["as_path"] = secret.AsPath,
                ["generated"] = secret.Generated,
                ["default_applied"] = secret.DefaultApplied,
                ["source_provider"] = secret.SourceProvider is not null,
            };
        }

        return new JsonObject
        {
            ["profile"] = report.Profile,
            ["secrets"] = secrets,
        };
    }

    private static string FindRepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory);
             directory is not null;
             directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "Cargo.toml")) &&
                Directory.Exists(Path.Combine(directory.FullName, "conformance")))
                return directory.FullName;
        }
        throw new DirectoryNotFoundException("could not find the SecretSpec repository root");
    }

    private static void AssertJsonEqual(string expected, string actual)
    {
        var expectedNode = JsonNode.Parse(expected);
        var actualNode = JsonNode.Parse(actual);
        Assert(
            JsonNode.DeepEquals(expectedNode, actualNode),
            $"JSON mismatch\nactual:   {actual}\nexpected: {expected}");
    }

    private static T Throws<T>(Action action) where T : Exception
    {
        try
        {
            action();
        }
        catch (T error)
        {
            return error;
        }
        throw new Exception($"expected {typeof(T).Name}");
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition)
            throw new Exception(message);
    }

    private static void Equal<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
            throw new Exception($"expected {expected}, got {actual}");
    }

    private static void SequenceEqual<T>(IEnumerable<T> expected, IEnumerable<T> actual)
    {
        if (!expected.SequenceEqual(actual))
            throw new Exception($"expected [{string.Join(", ", expected)}], got [{string.Join(", ", actual)}]");
    }

    private sealed class Project : IDisposable
    {
        private Project(string root)
        {
            Root = root;
            ManifestPath = Path.Combine(root, "secretspec.toml");
            Provider = $"dotenv://{Path.Combine(root, ".env")}";
        }

        private string Root { get; }
        internal string ManifestPath { get; }
        internal string Provider { get; }

        internal SecretSpecBuilder Builder() => SecretSpecClient.Builder()
            .WithPath(ManifestPath)
            .WithProvider(Provider)
            .WithReason("C# test");

        internal static Project Create(string manifest, string dotenv)
        {
            var project = new Project(Path.Combine(Path.GetTempPath(), $"secretspec-dotnet-{Guid.NewGuid()}"));
            Directory.CreateDirectory(project.Root);
            File.WriteAllText(project.ManifestPath, manifest);
            File.WriteAllText(Path.Combine(project.Root, ".env"), dotenv);
            return project;
        }

        public void Dispose() => Directory.Delete(Root, recursive: true);
    }
}
