using System.Text.Json;
using System.Text.Json.Serialization;

public sealed class AppSecrets
{
    [JsonPropertyName("DATABASE_URL")]
    public string DatabaseURL { get; init; } = "";

    public static AppSecrets FromJson(string json) =>
        JsonSerializer.Deserialize<AppSecrets>(json)
        ?? throw new JsonException("Unable to deserialize generated secrets");
}
