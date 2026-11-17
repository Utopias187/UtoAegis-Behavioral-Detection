using System.Security.Cryptography;
using System.Text.Json;

namespace UtoAegis.Core.Management;

public sealed record DeviceEnrollmentProofPayload
{
    public const int CurrentSchemaVersion = 1;
    public const string SignatureAlgorithm = "ecdsa-p256-sha256-p1363";
    public const int MaximumPublicKeyLength = 256;

    public DeviceEnrollmentProofPayload(
        string deviceId,
        string publicKeySpkiBase64,
        string bootstrapTokenSha256,
        DateTimeOffset timestampUtc,
        string nonce,
        Uri managementOrigin)
    {
        DeviceId = DeviceIdentityState.ValidateHex(deviceId, 32, nameof(deviceId));
        ArgumentException.ThrowIfNullOrWhiteSpace(publicKeySpkiBase64);
        byte[] publicKey;
        try
        {
            publicKey = Convert.FromBase64String(publicKeySpkiBase64);
        }
        catch (FormatException exception)
        {
            throw new ArgumentException(
                "The device public key must be base64 text.",
                nameof(publicKeySpkiBase64),
                exception);
        }

        if (publicKey.Length is <= 0 or > MaximumPublicKeyLength)
        {
            throw new ArgumentOutOfRangeException(nameof(publicKeySpkiBase64));
        }

        BootstrapTokenSha256 = DeviceIdentityState.ValidateHex(
            bootstrapTokenSha256,
            64,
            nameof(bootstrapTokenSha256));
        ArgumentOutOfRangeException.ThrowIfEqual(timestampUtc, default, nameof(timestampUtc));
        Nonce = DeviceIdentityState.ValidateHex(nonce, 32, nameof(nonce));
        ManagementOrigin = DeviceEnrollmentCredential.NormalizeManagementOrigin(managementOrigin);
        SchemaVersion = CurrentSchemaVersion;
        Algorithm = SignatureAlgorithm;
        PublicKeySpkiBase64 = Convert.ToBase64String(publicKey);
        PublicKeySha256 = Convert.ToHexString(SHA256.HashData(publicKey)).ToLowerInvariant();
        TimestampUtc = timestampUtc.ToUniversalTime();
    }

    public int SchemaVersion { get; }

    public string Algorithm { get; }

    public string DeviceId { get; }

    public string PublicKeySpkiBase64 { get; }

    public string PublicKeySha256 { get; }

    public string BootstrapTokenSha256 { get; }

    public DateTimeOffset TimestampUtc { get; }

    public string Nonce { get; }

    public Uri ManagementOrigin { get; }

    public byte[] GetCanonicalBytes()
    {
        using var stream = new MemoryStream(768);
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", SchemaVersion);
            writer.WriteString("algorithm", Algorithm);
            writer.WriteString("deviceId", DeviceId);
            writer.WriteString("publicKeySpkiBase64", PublicKeySpkiBase64);
            writer.WriteString("publicKeySha256", PublicKeySha256);
            writer.WriteString("bootstrapTokenSha256", BootstrapTokenSha256);
            writer.WriteString("timestampUtc", TimestampUtc.ToString("O"));
            writer.WriteString("nonce", Nonce);
            writer.WriteString("managementOrigin", ManagementOrigin.AbsoluteUri);
            writer.WriteEndObject();
        }

        return stream.ToArray();
    }
}
