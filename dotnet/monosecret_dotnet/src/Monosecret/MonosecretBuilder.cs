using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace Monosecret;

/// <summary>Configures a Monosecret resolution.</summary>
public sealed class MonosecretBuilder
{
    private readonly ResolveRequest _request = new();

    public MonosecretBuilder WithPath(string? path)
    {
        _request.Path = path;
        return this;
    }

    public MonosecretBuilder WithProvider(string? provider)
    {
        _request.Provider = provider;
        return this;
    }

    public MonosecretBuilder WithProfile(string? profile)
    {
        _request.Profile = profile;
        return this;
    }

    /// <summary>Limits resolution to a named manifest scope (schema v2).</summary>
    public MonosecretBuilder WithScope(string? scope)
    {
        _request.Scope = scope;
        return this;
    }

    public MonosecretBuilder WithReason(string? reason)
    {
        _request.Reason = reason;
        return this;
    }

    public MonosecretBuilder WithNoValues(bool noValues = true)
    {
        _request.NoValues = noValues;
        return this;
    }

    /// <summary>Resolves the configured secrets.</summary>
    /// <exception cref="MissingRequiredException">A required secret was missing.</exception>
    /// <exception cref="MonosecretException">Resolution otherwise failed.</exception>
    public Resolved Load()
    {
        var response = Call(
            _request,
            "resolve",
            MonosecretJsonContext.Default.ResolveEnvelope);
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
            MonosecretJsonContext.Default.ReportEnvelope);
        EnsureSchemaVersion(response.SchemaVersion, JsonContracts.ReportSchemaVersion, "report");

        return new ResolutionReport(
            response.Provider,
            response.Profile,
            response.Scope,
            response.Secrets,
            response.ConstraintViolations.Select(violation => new ConstraintViolation(
                ParseConstraintViolationKind(violation.Kind),
                violation.Group,
                violation.Secrets.AsReadOnly(),
                violation.Present.AsReadOnly())));
    }

    private static ConstraintViolationKind ParseConstraintViolationKind(string kind) => kind switch
    {
        "at_least_one" => ConstraintViolationKind.AtLeastOne,
        "exactly_one" => ConstraintViolationKind.ExactlyOne,
        _ => throw new MonosecretException("ffi", $"Unknown constraint violation kind: {kind}"),
    };

    private static T Call<T>(
        ResolveRequest request,
        string kind,
        JsonTypeInfo<Envelope<T>> envelopeTypeInfo)
        where T : class
    {
        var payload = JsonSerializer.Serialize(
            request,
            MonosecretJsonContext.Default.ResolveRequest);
        var raw = Native.Resolve(payload);
        Envelope<T>? envelope;
        try
        {
            envelope = JsonSerializer.Deserialize(raw, envelopeTypeInfo);
        }
        catch (JsonException error)
        {
            throw new MonosecretException("parse", error.Message, error);
        }

        if (envelope is null)
            throw new MonosecretException("parse", "native resolver returned an empty response");

        if (!envelope.Ok)
            throw new MonosecretException(
                envelope.Error?.Kind ?? "unknown",
                envelope.Error?.Message ?? "native resolver returned an unspecified error");

        return envelope.Response
            ?? throw new MonosecretException(
                "ffi",
                $"monosecret_resolve reported ok with no {kind} response");
    }

    private static void EnsureSchemaVersion(int actual, int expected, string kind)
    {
        if (actual != expected)
        {
            throw new MonosecretException(
                "version",
                $"unsupported {kind} schema version {actual} (expected {expected}); " +
                "the libmonosecret_ffi library and this SDK are out of sync");
        }
    }
}
