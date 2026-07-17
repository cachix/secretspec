namespace Cachix.SecretSpec;

/// <summary>A manifest, provider, policy, native-loading, or wire-format failure.</summary>
public class SecretSpecException : Exception
{
    public SecretSpecException(string kind, string message)
        : base($"{message} (kind: {kind})")
    {
        Kind = kind;
    }

    public SecretSpecException(string kind, string message, Exception innerException)
        : base($"{message} (kind: {kind})", innerException)
    {
        Kind = kind;
    }

    /// <summary>A stable machine-readable error category.</summary>
    public string Kind { get; }
}

/// <summary>Required secrets that could not be resolved.</summary>
public sealed class MissingRequiredException : SecretSpecException
{
    internal MissingRequiredException(IEnumerable<string> missing)
        : base("missing_required", BuildMessage(missing))
    {
        Missing = Array.AsReadOnly(missing.ToArray());
    }

    /// <summary>The unresolved required secret names.</summary>
    public IReadOnlyList<string> Missing { get; }

    private static string BuildMessage(IEnumerable<string> missing) =>
        $"missing required secret(s): {string.Join(", ", missing)}";
}
