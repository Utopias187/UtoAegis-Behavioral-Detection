using System.Security.Cryptography;
using System.Text.Json;
using UtoAegis.Core.Management;

namespace UtoAegis.Infrastructure.Management;

public sealed class DeviceEnrollmentCredentialIssuer
{
    private readonly ECDsa authorityKey;
    private readonly string keyId;

    public DeviceEnrollmentCredentialIssuer(ECDsa authorityKey, string keyId)
    {
        ArgumentNullException.ThrowIfNull(authorityKey);
        if (authorityKey.KeySize != 256)
        {
            throw new ArgumentException("Enrollment credentials require an ECDSA P-256 key.", nameof(authorityKey));
        }

        _ = new DeviceEnrollmentCredential(
            1, "validation", new string('a', 32), new string('b', 64),
            new RolloutRing("validation"), DeviceEnrollmentStatus.Active, 0,
            DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddHours(1),
            new Uri("https://validation.invalid/"), keyId);
        this.authorityKey = authorityKey;
        this.keyId = keyId;
    }

    public IssuedDeviceEnrollmentCredential Issue(CoordinatorDeviceEnrollment enrollment)
    {
        ArgumentNullException.ThrowIfNull(enrollment);
        using var stream = new MemoryStream(1024);
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", DeviceEnrollmentCredential.CurrentSchemaVersion);
            writer.WriteString("algorithm", DeviceEnrollmentCredential.SignatureAlgorithm);
            writer.WriteNumber("credentialSequence", enrollment.CredentialSequence);
            writer.WriteString("enrollmentId", enrollment.EnrollmentId);
            writer.WriteString("deviceId", enrollment.DeviceId);
            writer.WriteString("publicKeySha256", enrollment.PublicKeySha256);
            writer.WriteString("rolloutRing", enrollment.RolloutRing.Value);
            writer.WriteString("status", enrollment.Status.ToString());
            writer.WriteNumber("revocationGeneration", enrollment.RevocationGeneration);
            writer.WriteString("issuedUtc", enrollment.IssuedUtc.ToString("O"));
            writer.WriteString("expiresUtc", enrollment.ExpiresUtc.ToString("O"));
            writer.WriteString("managementOrigin", enrollment.ManagementOrigin.AbsoluteUri);
            writer.WriteString("keyId", keyId);
            writer.WriteEndObject();
        }

        var bytes = stream.ToArray();
        var signature = authorityKey.SignData(
            bytes,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence);
        return new IssuedDeviceEnrollmentCredential(
            bytes,
            Convert.ToBase64String(signature),
            enrollment);
    }
}
