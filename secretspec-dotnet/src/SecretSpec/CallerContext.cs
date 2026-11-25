using System.Text.Json.Serialization;

namespace Cachix.SecretSpec;

/// <summary>
/// Caller-asserted software-integration context. It is audit metadata and never
/// supplies the user access reason. Available since SecretSpec 0.20.
/// </summary>
public sealed record CallerContext
{
    [JsonPropertyName("name")]
    public required string Name { get; init; }

    [JsonPropertyName("version")]
    public string? Version { get; init; }

    [JsonPropertyName("operation")]
    public string? Operation { get; init; }

    [JsonPropertyName("resource")]
    public string? Resource { get; init; }
}
