using System.Security.Cryptography;
using UtoAegis.Core.Management;

namespace UtoAegis.Infrastructure.Management;

public sealed class DeviceEnrollmentProofSigner
{
    private readonly ECDsa signingKey;
    private readonly DeviceIdentityState identity;

    public DeviceEnrollmentProofSigner(ECDsa signingKey, DeviceIdentityState identity)
    {
        ArgumentNullException.ThrowIfNull(signingKey);
        ArgumentNullException.ThrowIfNull(identity);
        if (signingKey.KeySize != 256)
        {
            throw new ArgumentException("Enrollment proof requires an ECDSA P-256 key.", nameof(signingKey));
        }

        var fingerprint = Convert.ToHexString(
            SHA256.HashData(signingKey.ExportSubjectPublicKeyInfo())).ToLowerInvariant();
        if (!CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(fingerprint),
                Convert.FromHexString(identity.PublicKeySha256)))
        {
            throw new ArgumentException(
                "The device identity fingerprint does not match the enrollment key.",
                nameof(identity));
        }

        this.signingKey = signingKey;
        this.identity = identity;
    }

    public SignedDeviceEnrollmentProof Sign(
        EnrollmentBootstrapToken bootstrapToken,
        DateTimeOffset timestampUtc,
        string nonce,
        Uri managementOrigin)
    {
        ArgumentNullException.ThrowIfNull(bootstrapToken);
        var payload = new DeviceEnrollmentProofPayload(
            identity.DeviceId,
            Convert.ToBase64String(signingKey.ExportSubjectPublicKeyInfo()),
            bootstrapToken.ComputeSha256(),
            timestampUtc,
            nonce,
            managementOrigin);
        var signature = signingKey.SignData(
            payload.GetCanonicalBytes(),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return new SignedDeviceEnrollmentProof(payload, Convert.ToBase64String(signature));
    }
}
