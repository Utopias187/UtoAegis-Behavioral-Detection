using UtoAegis.Core.Response;

namespace UtoAegis.Core.RuntimeIntegrity;

public sealed record RuntimePolicyManifest
{
    public const int CurrentSchemaVersion = 1;
    public const string SignatureAlgorithm = "ecdsa-p256-sha256";
    public const int MaximumServiceCount = 16;
    public const int MaximumPathCount = 128;

    private static readonly StringComparer PathComparer = OperatingSystem.IsWindows()
        ? StringComparer.OrdinalIgnoreCase
        : StringComparer.Ordinal;

    public RuntimePolicyManifest(
        long sequence,
        string policyId,
        string keyId,
        DateTimeOffset issuedUtc,
        DateTimeOffset expiresUtc,
        ResponsePolicy responsePolicy,
        IReadOnlyCollection<RuntimeServicePolicy> services,
        IReadOnlyCollection<RuntimePathPolicy> paths,
        TimeSpan auditInterval,
        int maximumRecoveriesPerWindow,
        TimeSpan recoveryWindow)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(sequence);
        PolicyId = ValidateIdentifier(policyId, nameof(policyId));
        KeyId = ValidateIdentifier(keyId, nameof(keyId));
        ArgumentNullException.ThrowIfNull(responsePolicy);
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(paths);

        var normalizedIssuedUtc = issuedUtc.ToUniversalTime();
        var normalizedExpiresUtc = expiresUtc.ToUniversalTime();
        if (normalizedExpiresUtc <= normalizedIssuedUtc ||
            normalizedExpiresUtc - normalizedIssuedUtc > TimeSpan.FromDays(366))
        {
            throw new ArgumentException(
                "Runtime policy validity must be greater than zero and no longer than 366 days.",
                nameof(expiresUtc));
        }

        if (services.Count is 0 or > MaximumServiceCount)
        {
            throw new ArgumentOutOfRangeException(
                nameof(services),
                $"A runtime policy must contain 1 to {MaximumServiceCount} services.");
        }

        if (paths.Count > MaximumPathCount)
        {
            throw new ArgumentOutOfRangeException(
                nameof(paths),
                $"A runtime policy may contain at most {MaximumPathCount} protected paths.");
        }

        var normalizedServices = services.OrderBy(service => service.Name, StringComparer.Ordinal).ToArray();
        if (normalizedServices.Select(service => service.Name).Distinct(StringComparer.Ordinal).Count() !=
            normalizedServices.Length)
        {
            throw new ArgumentException("Runtime policy service names must be unique.", nameof(services));
        }

        var normalizedPaths = paths.OrderBy(path => path.Path, PathComparer).ToArray();
        if (normalizedPaths.Select(path => path.Path).Distinct(PathComparer).Count() != normalizedPaths.Length)
        {
            throw new ArgumentException("Runtime policy protected paths must be unique.", nameof(paths));
        }

        if (auditInterval < TimeSpan.FromMinutes(1) || auditInterval > TimeSpan.FromHours(24))
        {
            throw new ArgumentOutOfRangeException(
                nameof(auditInterval),
                "The integrity audit interval must be from one minute through 24 hours.");
        }

        if (maximumRecoveriesPerWindow is < 0 or > 100)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maximumRecoveriesPerWindow),
                "Maximum recoveries per window must be from 0 through 100.");
        }

        if (recoveryWindow < TimeSpan.FromMinutes(1) || recoveryWindow > TimeSpan.FromDays(7))
        {
            throw new ArgumentOutOfRangeException(
                nameof(recoveryWindow),
                "The recovery window must be from one minute through seven days.");
        }

        Sequence = sequence;
        SchemaVersion = CurrentSchemaVersion;
        Algorithm = SignatureAlgorithm;
        IssuedUtc = normalizedIssuedUtc;
        ExpiresUtc = normalizedExpiresUtc;
        ResponsePolicy = responsePolicy;
        Services = normalizedServices;
        Paths = normalizedPaths;
        AuditInterval = auditInterval;
        MaximumRecoveriesPerWindow = maximumRecoveriesPerWindow;
        RecoveryWindow = recoveryWindow;
    }

    public int SchemaVersion { get; }

    public string Algorithm { get; }

    public long Sequence { get; }

    public string PolicyId { get; }

    public string KeyId { get; }

    public DateTimeOffset IssuedUtc { get; }

    public DateTimeOffset ExpiresUtc { get; }

    public ResponsePolicy ResponsePolicy { get; }

    public IReadOnlyList<RuntimeServicePolicy> Services { get; }

    public IReadOnlyList<RuntimePathPolicy> Paths { get; }

    public TimeSpan AuditInterval { get; }

    public int MaximumRecoveriesPerWindow { get; }

    public TimeSpan RecoveryWindow { get; }

    private static string ValidateIdentifier(string value, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        var normalized = value.Trim();
        if (normalized.Length > 64 ||
            !char.IsAsciiLetterOrDigit(normalized[0]) ||
            !char.IsAsciiLetterOrDigit(normalized[^1]) ||
            normalized.Any(character =>
                !char.IsAsciiLetterOrDigit(character) &&
                character is not '.' and not '-' and not '_'))
        {
            throw new ArgumentException(
                "Policy identifiers must use 1 to 64 path-safe ASCII characters.",
                parameterName);
        }

        return normalized;
    }
}
