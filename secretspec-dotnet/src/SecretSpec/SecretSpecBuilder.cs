using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace Cachix.SecretSpec;

/// <summary>Configures a SecretSpec resolution.</summary>
public sealed class SecretSpecBuilder
{
    private readonly ResolveRequest _request = new();
    private bool _hasInlineSpec;
    private JsonElement _inlineSpec;
    private string? _inlineBaseDir;

    public SecretSpecBuilder WithPath(string? path)
    {
        _inlineSpec = default;
        _inlineBaseDir = null;
        _hasInlineSpec = false;
        _request.Path = path;
        return this;
    }

    /// <summary>Resolve strict inline-spec v1 at <paramref name="baseDir"/> (SecretSpec 0.20+).</summary>
    public SecretSpecBuilder WithInlineSpec(JsonElement spec, string baseDir)
    {
        if (spec.ValueKind == JsonValueKind.Undefined)
            throw new ArgumentException("The inline specification must be a JSON value.", nameof(spec));

        _request.Path = null;
        _hasInlineSpec = true;
        _inlineSpec = spec.Clone();
        _inlineBaseDir = baseDir;
        return this;
    }

    /// <summary>
    /// Resolve a pre-serialized strict inline-spec v1 at <paramref name="baseDir"/>
    /// (SecretSpec 0.20+).
    /// </summary>
    public SecretSpecBuilder WithInlineSpec(string specJson, string baseDir)
    {
        using var document = JsonDocument.Parse(specJson);
        return WithInlineSpec(document.RootElement, baseDir);
    }

    /// <summary>
    /// Resolve strict inline-spec v1 using source-generated JSON metadata
    /// (SecretSpec 0.20+).
    /// </summary>
    public SecretSpecBuilder WithInlineSpec<T>(T spec, string baseDir, JsonTypeInfo<T> jsonTypeInfo)
        => WithInlineSpec(JsonSerializer.SerializeToElement(spec, jsonTypeInfo), baseDir);

    public SecretSpecBuilder WithProvider(string? provider)
    {
        _request.Provider = provider;
        return this;
    }

    public SecretSpecBuilder WithProfile(string? profile)
    {
        _request.Profile = profile;
        return this;
    }

    /// <summary>Limits resolution to a named manifest scope (SecretSpec 0.17+).</summary>
    public SecretSpecBuilder WithScope(string? scope)
    {
        _request.Scope = scope;
        return this;
    }

    public SecretSpecBuilder WithReason(string? reason)
    {
        _request.Reason = reason;
        return this;
    }

    /// <summary>Identifies the invoking software integration (SecretSpec 0.20+).</summary>
    public SecretSpecBuilder WithCaller(CallerContext? caller)
    {
        _request.Caller = caller;
        return this;
    }

    public SecretSpecBuilder WithNoValues(bool noValues = true)
    {
        _request.NoValues = noValues;
        return this;
    }

    /// <summary>Resolves the configured secrets.</summary>
    /// <exception cref="MissingRequiredException">A required secret was missing.</exception>
    /// <exception cref="SecretSpecException">Resolution otherwise failed.</exception>
    public Resolved Load()
    {
        var response = Call(
            _request,
            "resolve",
            SecretSpecJsonContext.Default.ResolveEnvelope);
        EnsureSchemaVersion(response.SchemaVersion, JsonContracts.ResolveSchemaVersion, "resolve");

        if (response.MissingRequired.Count > 0)
            throw new MissingRequiredException(response.MissingRequired);

        return new Resolved(
            response.Provider,
            response.Profile,
            response.Scope,
            response.Secrets,
            response.MissingOptional);
    }

    /// <summary>
    /// Resolves a value-free inventory/preflight report. Missing required
    /// secrets appear in the report rather than throwing.
    /// </summary>
    public ResolutionReport Report()
    {
        var request = _request with { Mode = "report" };
        var response = Call(
            request,
            "report",
            SecretSpecJsonContext.Default.ReportEnvelope);
        EnsureSchemaVersion(response.SchemaVersion, JsonContracts.ReportSchemaVersion, "report");

        return new ResolutionReport(
            response.Provider,
            response.Profile,
            response.Scope,
            response.Secrets);
    }

    private T Call<T>(
        ResolveRequest request,
        string kind,
        JsonTypeInfo<Envelope<T>> envelopeTypeInfo)
        where T : class
    {
        var versioned = _hasInlineSpec;
        var options = JsonSerializer.SerializeToElement(
            request,
            SecretSpecJsonContext.Default.ResolveRequest);
        var payload = versioned
            ? SerializeInlineRequest(options)
            : JsonSerializer.Serialize(request, SecretSpecJsonContext.Default.ResolveRequest);
        var raw = versioned ? Native.Call(payload) : Native.Resolve(payload);
        Envelope<T>? envelope;
        try
        {
            envelope = JsonSerializer.Deserialize(raw, envelopeTypeInfo);
        }
        catch (JsonException error)
        {
            throw new SecretSpecException("parse", error.Message, error);
        }

        if (envelope is null)
            throw new SecretSpecException("parse", "native resolver returned an empty response");

        if (!envelope.Ok)
            throw new SecretSpecException(
                envelope.Error?.Kind ?? "unknown",
                envelope.Error?.Message ?? "native resolver returned an unspecified error");

        return envelope.Response
            ?? throw new SecretSpecException(
                "ffi",
                $"secretspec_resolve reported ok with no {kind} response");
    }

    private string SerializeInlineRequest(JsonElement options)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteNumber("request_version", 1);
            writer.WriteString("operation", "resolve");
            writer.WritePropertyName("source");
            writer.WriteStartObject();
            writer.WriteString("kind", "inline");
            writer.WriteNumber("spec_version", 2);
            writer.WriteString("base_dir", _inlineBaseDir);
            writer.WritePropertyName("spec");
            _inlineSpec.WriteTo(writer);
            writer.WriteEndObject();
            writer.WritePropertyName("options");
            options.WriteTo(writer);
            writer.WriteEndObject();
        }
        return System.Text.Encoding.UTF8.GetString(stream.ToArray());
    }

    private static void EnsureSchemaVersion(int actual, int expected, string kind)
    {
        if (actual != expected)
        {
            throw new SecretSpecException(
                "version",
                $"unsupported {kind} schema version {actual} (expected {expected}); " +
                "the libsecretspec library and this SDK are out of sync");
        }
    }
}
