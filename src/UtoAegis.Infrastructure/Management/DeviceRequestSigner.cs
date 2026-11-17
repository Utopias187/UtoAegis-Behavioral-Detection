using System.Security.Cryptography;
using UtoAegis.Core.Management;

namespace UtoAegis.Infrastructure.Management;

public sealed class DeviceRequestSigner
{
    private readonly ECDsa signingKey;
    private readonly DeviceIdentityState identity;

    public DeviceRequestSigner(ECDsa signingKey, DeviceIdentityState identity)
    {
        ArgumentNullException.ThrowIfNull(signingKey);
        ArgumentNullException.ThrowIfNull(identity);
        if (signingKey.KeySize != 256)
        {
            throw new ArgumentException("Device request signing requires an ECDSA P-256 key.", nameof(signingKey));
        }

        var fingerprint = Convert.ToHexString(
            SHA256.HashData(signingKey.ExportSubjectPublicKeyInfo())).ToLowerInvariant();
        if (!CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(fingerprint),
                Convert.FromHexString(identity.PublicKeySha256)))
        {
            throw new ArgumentException(
                "The device identity fingerprint does not match the signing key.",
                nameof(identity));
        }

        this.signingKey = signingKey;
        this.identity = identity;
    }

    public SignedDeviceRequest Sign(
        string enrollmentId,
        long credentialSequence,
        DateTimeOffset timestampUtc,
        string nonce,
        string method,
        string pathAndQuery,
        ReadOnlySpan<byte> body)
    {
        var payload = new DeviceRequestPayload(
            identity.DeviceId,
            enrollmentId,
            credentialSequence,
            timestampUtc,
            nonce,
            method,
            pathAndQuery,
            Convert.ToHexString(SHA256.HashData(body)).ToLowerInvariant());
        var signature = signingKey.SignData(
            payload.GetCanonicalBytes(),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return new SignedDeviceRequest(payload, Convert.ToBase64String(signature));
    }
}
