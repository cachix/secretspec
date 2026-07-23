using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace Cachix.SecretSpec;

/// <summary>Configures a SecretSpec resolution.</summary>
public sealed class SecretSpecBuilder
{
    private readonly ResolveRequest _request = new();

    public SecretSpecBuilder WithPath(string? path)
    {
        _request.Path = path;
        return this;
    }

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

    private static T Call<T>(
        ResolveRequest request,
        string kind,
        JsonTypeInfo<Envelope<T>> envelopeTypeInfo)
        where T : class
    {
        var payload = JsonSerializer.Serialize(
            request,
            SecretSpecJsonContext.Default.ResolveRequest);
        var raw = Native.Resolve(payload);
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

    private static void EnsureSchemaVersion(int actual, int expected, string kind)
    {
        if (actual != expected)
        {
            throw new SecretSpecException(
                "version",
                $"unsupported {kind} schema version {actual} (expected {expected}); " +
                "the secretspec-ffi library and this SDK are out of sync");
        }
    }
}
