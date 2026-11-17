using System.Text.Json;

namespace UtoAegis.Core.Management;

public sealed record DeviceRequestPayload
{
    public const int CurrentSchemaVersion = 1;
    public const string SignatureAlgorithm = "ecdsa-p256-sha256-p1363";
    public const int MaximumTargetLength = 2048;

    public DeviceRequestPayload(
        string deviceId,
        string enrollmentId,
        long credentialSequence,
        DateTimeOffset timestampUtc,
        string nonce,
        string method,
        string pathAndQuery,
        string bodySha256)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(credentialSequence);
        DeviceId = DeviceIdentityState.ValidateHex(deviceId, 32, nameof(deviceId));
        EnrollmentId = DeviceIdentityState.ValidateIdentifier(
            enrollmentId,
            128,
            nameof(enrollmentId));
        ArgumentOutOfRangeException.ThrowIfEqual(timestampUtc, default, nameof(timestampUtc));

        Nonce = DeviceIdentityState.ValidateHex(nonce, 32, nameof(nonce));
        Method = ValidateMethod(method);
        PathAndQuery = ValidateTarget(pathAndQuery);
        BodySha256 = DeviceIdentityState.ValidateHex(bodySha256, 64, nameof(bodySha256));
        SchemaVersion = CurrentSchemaVersion;
        Algorithm = SignatureAlgorithm;
        CredentialSequence = credentialSequence;
        TimestampUtc = timestampUtc.ToUniversalTime();
    }

    public int SchemaVersion { get; }

    public string Algorithm { get; }

    public string DeviceId { get; }

    public string EnrollmentId { get; }

    public long CredentialSequence { get; }

    public DateTimeOffset TimestampUtc { get; }

    public string Nonce { get; }

    public string Method { get; }

    public string PathAndQuery { get; }

    public string BodySha256 { get; }

    public byte[] GetCanonicalBytes()
    {
        using var stream = new MemoryStream(512);
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", SchemaVersion);
            writer.WriteString("algorithm", Algorithm);
            writer.WriteString("deviceId", DeviceId);
            writer.WriteString("enrollmentId", EnrollmentId);
            writer.WriteNumber("credentialSequence", CredentialSequence);
            writer.WriteString("timestampUtc", TimestampUtc.ToString("O"));
            writer.WriteString("nonce", Nonce);
            writer.WriteString("method", Method);
            writer.WriteString("pathAndQuery", PathAndQuery);
            writer.WriteString("bodySha256", BodySha256);
            writer.WriteEndObject();
        }

        return stream.ToArray();
    }

    private static string ValidateMethod(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        var normalized = value.Trim().ToUpperInvariant();
        if (normalized.Length > 16 || normalized.Any(character => !char.IsAsciiLetter(character)))
        {
            throw new ArgumentException(
                "The request method must contain 1 to 16 ASCII letters.",
                nameof(value));
        }

        return normalized;
    }

    private static string ValidateTarget(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Length > MaximumTargetLength ||
            value[0] != '/' ||
            value.StartsWith("//", StringComparison.Ordinal) ||
            value.Contains('#', StringComparison.Ordinal) ||
            value.Any(character => character is < '!' or > '~'))
        {
            throw new ArgumentException(
                "The request target must be an ASCII absolute path and optional query without a fragment.",
                nameof(value));
        }

        return value;
    }
}
