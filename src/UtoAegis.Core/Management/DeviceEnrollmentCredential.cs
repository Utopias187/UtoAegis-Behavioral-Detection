namespace UtoAegis.Core.Management;

public sealed record DeviceEnrollmentCredential
{
    public const int CurrentSchemaVersion = 1;
    public const string SignatureAlgorithm = "ecdsa-p256-sha256";

    public DeviceEnrollmentCredential(
        long credentialSequence,
        string enrollmentId,
        string deviceId,
        string publicKeySha256,
        RolloutRing rolloutRing,
        DeviceEnrollmentStatus status,
        long revocationGeneration,
        DateTimeOffset issuedUtc,
        DateTimeOffset expiresUtc,
        Uri managementOrigin,
        string keyId)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(credentialSequence);
        ArgumentOutOfRangeException.ThrowIfNegative(revocationGeneration);
        if (!Enum.IsDefined(status))
        {
            throw new ArgumentOutOfRangeException(nameof(status));
        }

        ArgumentNullException.ThrowIfNull(rolloutRing);
        var issued = issuedUtc.ToUniversalTime();
        var expires = expiresUtc.ToUniversalTime();
        if (expires <= issued || expires - issued > TimeSpan.FromDays(90))
        {
            throw new ArgumentException(
                "An enrollment credential must be valid for more than zero and no longer than 90 days.",
                nameof(expiresUtc));
        }

        SchemaVersion = CurrentSchemaVersion;
        Algorithm = SignatureAlgorithm;
        CredentialSequence = credentialSequence;
        EnrollmentId = DeviceIdentityState.ValidateIdentifier(
            enrollmentId,
            128,
            nameof(enrollmentId));
        DeviceId = DeviceIdentityState.ValidateHex(deviceId, 32, nameof(deviceId));
        PublicKeySha256 = DeviceIdentityState.ValidateHex(
            publicKeySha256,
            64,
            nameof(publicKeySha256));
        RolloutRing = rolloutRing;
        Status = status;
        RevocationGeneration = revocationGeneration;
        IssuedUtc = issued;
        ExpiresUtc = expires;
        ManagementOrigin = NormalizeManagementOrigin(managementOrigin);
        KeyId = DeviceIdentityState.ValidateIdentifier(keyId, 64, nameof(keyId));
    }

    public int SchemaVersion { get; }

    public string Algorithm { get; }

    public long CredentialSequence { get; }

    public string EnrollmentId { get; }

    public string DeviceId { get; }

    public string PublicKeySha256 { get; }

    public RolloutRing RolloutRing { get; }

    public DeviceEnrollmentStatus Status { get; }

    public long RevocationGeneration { get; }

    public DateTimeOffset IssuedUtc { get; }

    public DateTimeOffset ExpiresUtc { get; }

    public Uri ManagementOrigin { get; }

    public string KeyId { get; }

    public static Uri NormalizeManagementOrigin(Uri value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (!value.IsAbsoluteUri ||
            !string.Equals(value.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
            !string.IsNullOrEmpty(value.UserInfo) ||
            !string.IsNullOrEmpty(value.Query) ||
            !string.IsNullOrEmpty(value.Fragment) ||
            value.AbsolutePath != "/")
        {
            throw new ArgumentException(
                "The management origin must be an HTTPS origin without credentials, path, query, or fragment.",
                nameof(value));
        }

        return new Uri(value.GetLeftPart(UriPartial.Authority) + "/", UriKind.Absolute);
    }
}
