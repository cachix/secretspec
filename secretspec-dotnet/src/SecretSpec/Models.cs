using System.Collections.ObjectModel;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Cachix.SecretSpec;

/// <summary>One resolved secret and its provenance.</summary>
public sealed class ResolvedSecret
{
    /// <summary>The inline value, or null for an <c>as_path</c> secret.</summary>
    [JsonPropertyName("value")]
    public string? Value { get; init; }

    /// <summary>The materialized file path, or null for an inline secret.</summary>
    [JsonPropertyName("path")]
    public string? Path { get; init; }

    [JsonPropertyName("as_path")]
    public bool AsPath { get; init; }

    [JsonPropertyName("source")]
    public string Source { get; init; } = "";

    [JsonPropertyName("source_provider")]
    public string? SourceProvider { get; init; }

    /// <summary>
    /// Returns the usable string: the file path for an <c>as_path</c> secret,
    /// otherwise its inline value. A value-less resolution returns null.
    /// </summary>
    public string? Get() => AsPath ? Path : Value;
}

/// <summary>A successful, value-carrying resolution.</summary>
public sealed class Resolved : IDisposable
{
    private bool _disposed;

    internal Resolved(
        string provider,
        string profile,
        string? scope,
        Dictionary<string, ResolvedSecret> secrets,
        IEnumerable<string> missingOptional)
    {
        Provider = provider;
        Profile = profile;
        Scope = scope;
        Secrets = new ReadOnlyDictionary<string, ResolvedSecret>(secrets);
        MissingOptional = Array.AsReadOnly(missingOptional.ToArray());
    }

    public string Provider { get; }
    public string Profile { get; }
    /// <summary>Selected manifest scope, or null for a full-profile resolve (0.17+).</summary>
    public string? Scope { get; }
    public IReadOnlyDictionary<string, ResolvedSecret> Secrets { get; }
    public IReadOnlyList<string> MissingOptional { get; }

    /// <summary>Exports every present secret into the current process environment.</summary>
    public void SetAsEnv()
    {
        foreach (var (name, secret) in Secrets)
        {
            var value = secret.Get();
            if (value is not null)
                Environment.SetEnvironmentVariable(name, value);
        }
    }

    /// <summary>
    /// Returns a flat secret-name-to-value map suitable for a generated typed
    /// deserializer. File-shaped secrets map to their paths; stripped values map to null.
    /// </summary>
    public IReadOnlyDictionary<string, string?> Fields() =>
        new ReadOnlyDictionary<string, string?>(
            Secrets.ToDictionary(
                pair => pair.Key,
                pair => pair.Value.Get(),
                StringComparer.Ordinal));

    /// <summary>Serializes <see cref="Fields"/> for a generated deserializer.</summary>
    public string FieldsJson() =>
        JsonSerializer.Serialize(
            Fields(),
            typeof(IReadOnlyDictionary<string, string?>),
            SecretSpecJsonContext.Default);

    /// <summary>Removes temporary files backing <c>as_path</c> secrets.</summary>
    public void Close()
    {
        if (_disposed)
            return;

        _disposed = true;
        Exception? firstError = null;
        foreach (var secret in Secrets.Values)
        {
            if (!secret.AsPath || secret.Path is null)
                continue;

            try
            {
                File.Delete(secret.Path);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                firstError ??= error;
            }
        }

        if (firstError is not null)
            throw firstError;
    }

    public void Dispose()
    {
        Close();
        GC.SuppressFinalize(this);
    }
}

/// <summary>The value-free resolution outcome for one declared secret.</summary>
public sealed class SecretReport
{
    [JsonPropertyName("name")]
    public string Name { get; init; } = "";

    [JsonPropertyName("status")]
    public string Status { get; init; } = "";

    [JsonPropertyName("required")]
    public bool Required { get; init; }

    [JsonPropertyName("source_provider")]
    public string? SourceProvider { get; init; }

    [JsonPropertyName("default_applied")]
    public bool DefaultApplied { get; init; }

    [JsonPropertyName("generated")]
    public bool Generated { get; init; }

    [JsonPropertyName("as_path")]
    public bool AsPath { get; init; }
}

/// <summary>A value-free inventory/preflight snapshot.</summary>
public sealed class ResolutionReport
{
    internal ResolutionReport(
        string provider,
        string profile,
        string? scope,
        IEnumerable<SecretReport> secrets)
    {
        Provider = provider;
        Profile = profile;
        Scope = scope;
        Secrets = Array.AsReadOnly(secrets.ToArray());
    }

    public string Provider { get; }
    public string Profile { get; }
    /// <summary>Selected manifest scope, or null for a full-profile report (0.17+).</summary>
    public string? Scope { get; }
    public IReadOnlyList<SecretReport> Secrets { get; }
}
