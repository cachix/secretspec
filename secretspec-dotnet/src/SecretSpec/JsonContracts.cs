using System.Text.Json;
using System.Text.Json.Serialization;

namespace Cachix.SecretSpec;

internal static class JsonContracts
{
    internal const int ResolveSchemaVersion = 1;
    internal const int ReportSchemaVersion = 1;
}

[JsonSourceGenerationOptions(
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(
    typeof(ResolveRequest),
    TypeInfoPropertyName = "ResolveRequest")]
[JsonSerializable(
    typeof(Envelope<ResolveResponseContract>),
    TypeInfoPropertyName = "ResolveEnvelope")]
[JsonSerializable(
    typeof(Envelope<ReportResponseContract>),
    TypeInfoPropertyName = "ReportEnvelope")]
[JsonSerializable(
    typeof(IReadOnlyDictionary<string, string?>),
    TypeInfoPropertyName = "SecretFields")]
internal sealed partial class SecretSpecJsonContext : JsonSerializerContext;

internal sealed record ResolveRequest
{
    [JsonPropertyName("path")]
    public string? Path { get; set; }

    [JsonPropertyName("provider")]
    public string? Provider { get; set; }

    [JsonPropertyName("profile")]
    public string? Profile { get; set; }

    [JsonPropertyName("reason")]
    public string? Reason { get; set; }

    [JsonPropertyName("no_values")]
    public bool? NoValues { get; set; }

    [JsonPropertyName("mode")]
    public string? Mode { get; set; }
}

internal sealed class Envelope<T>
{
    [JsonPropertyName("ok")]
    public bool Ok { get; set; }

    [JsonPropertyName("response")]
    public T? Response { get; set; }

    [JsonPropertyName("error")]
    public ErrorContract? Error { get; set; }
}

internal sealed class ErrorContract
{
    [JsonPropertyName("kind")]
    public string? Kind { get; set; }

    [JsonPropertyName("message")]
    public string? Message { get; set; }
}

internal sealed class ResolveResponseContract
{
    [JsonPropertyName("schema_version")]
    public int SchemaVersion { get; set; }

    [JsonPropertyName("provider")]
    public string Provider { get; set; } = "";

    [JsonPropertyName("profile")]
    public string Profile { get; set; } = "";

    [JsonPropertyName("secrets")]
    public Dictionary<string, ResolvedSecret> Secrets { get; set; } = [];

    [JsonPropertyName("missing_required")]
    public List<string> MissingRequired { get; set; } = [];

    [JsonPropertyName("missing_optional")]
    public List<string> MissingOptional { get; set; } = [];
}

internal sealed class ReportResponseContract
{
    [JsonPropertyName("schema_version")]
    public int SchemaVersion { get; set; }

    [JsonPropertyName("provider")]
    public string Provider { get; set; } = "";

    [JsonPropertyName("profile")]
    public string Profile { get; set; } = "";

    [JsonPropertyName("secrets")]
    public List<SecretReport> Secrets { get; set; } = [];
}
