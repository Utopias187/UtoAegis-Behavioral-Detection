namespace UtoAegis.Core.Management;

public sealed record PolicyDistributionAuthorization
{
    public const int CurrentSchemaVersion = 1;
    public const string SignatureAlgorithm = "ecdsa-p256-sha256";
    public const int MaximumRolloutRingCount = 16;

    public PolicyDistributionAuthorization(
        long authorizationSequence,
        string policyId,
        long policySequence,
        string manifestSha256,
        IReadOnlyCollection<RolloutRing> allowedRolloutRings,
        DateTimeOffset issuedUtc,
        DateTimeOffset expiresUtc,
        string keyId)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(authorizationSequence);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(policySequence);
        ArgumentNullException.ThrowIfNull(allowedRolloutRings);
        if (allowedRolloutRings.Count is 0 or > MaximumRolloutRingCount)
        {
            throw new ArgumentOutOfRangeException(
                nameof(allowedRolloutRings),
                $"A policy authorization must contain 1 to {MaximumRolloutRingCount} rollout rings.");
        }

        var rings = allowedRolloutRings
            .Select(ring => ring ?? throw new ArgumentException(
                "A policy authorization cannot contain a null rollout ring.",
                nameof(allowedRolloutRings)))
            .OrderBy(ring => ring.Value, StringComparer.Ordinal)
            .ToArray();
        if (rings.Select(ring => ring.Value).Distinct(StringComparer.Ordinal).Count() != rings.Length)
        {
            throw new ArgumentException(
                "Policy authorization rollout rings must be unique.",
                nameof(allowedRolloutRings));
        }

        var issued = issuedUtc.ToUniversalTime();
        var expires = expiresUtc.ToUniversalTime();
        if (expires <= issued || expires - issued > TimeSpan.FromDays(90))
        {
            throw new ArgumentException(
                "A policy authorization must be valid for more than zero and no longer than 90 days.",
                nameof(expiresUtc));
        }

        SchemaVersion = CurrentSchemaVersion;
        Algorithm = SignatureAlgorithm;
        AuthorizationSequence = authorizationSequence;
        PolicyId = DeviceIdentityState.ValidateIdentifier(policyId, 64, nameof(policyId));
        PolicySequence = policySequence;
        ManifestSha256 = DeviceIdentityState.ValidateHex(
            manifestSha256,
            64,
            nameof(manifestSha256));
        AllowedRolloutRings = rings;
        IssuedUtc = issued;
        ExpiresUtc = expires;
        KeyId = DeviceIdentityState.ValidateIdentifier(keyId, 64, nameof(keyId));
    }

    public int SchemaVersion { get; }

    public string Algorithm { get; }

    public long AuthorizationSequence { get; }

    public string PolicyId { get; }

    public long PolicySequence { get; }

    public string ManifestSha256 { get; }

    public IReadOnlyList<RolloutRing> AllowedRolloutRings { get; }

    public DateTimeOffset IssuedUtc { get; }

    public DateTimeOffset ExpiresUtc { get; }

    public string KeyId { get; }
}
