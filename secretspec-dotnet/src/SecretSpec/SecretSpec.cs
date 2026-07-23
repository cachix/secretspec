namespace Cachix.SecretSpec;

/// <summary>Entry point for the SecretSpec C# SDK.</summary>
public static class SecretSpec
{
    /// <summary>Starts a fluent resolution builder.</summary>
    public static SecretSpecBuilder Builder() => new();

    /// <summary>Resolves secrets in one call.</summary>
    public static Resolved Resolve(
        string? path = null,
        string? provider = null,
        string? profile = null,
        string? reason = null,
        string? scope = null) =>
        Configured(path, provider, profile, scope, reason).Load();

    /// <summary>Builds a value-free inventory report in one call.</summary>
    public static ResolutionReport Report(
        string? path = null,
        string? provider = null,
        string? profile = null,
        string? reason = null,
        string? scope = null) =>
        Configured(path, provider, profile, scope, reason).Report();

    /// <summary>The ABI version reported by the loaded native resolver.</summary>
    public static string AbiVersion() => Native.AbiVersion();

    private static SecretSpecBuilder Configured(
        string? path,
        string? provider,
        string? profile,
        string? scope,
        string? reason) =>
        Builder()
            .WithPath(path)
            .WithProvider(provider)
            .WithProfile(profile)
            .WithScope(scope)
            .WithReason(reason);
}
