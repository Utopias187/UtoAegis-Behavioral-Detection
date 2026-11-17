using System.Security.Cryptography;
using UtoAegis.Core.Management;

namespace UtoAegis.Infrastructure.Management;

public sealed class DeviceRequestSignatureVerifier
{
    private readonly ECDsa verificationKey;

    public DeviceRequestSignatureVerifier(ECDsa verificationKey)
    {
        ArgumentNullException.ThrowIfNull(verificationKey);
        if (verificationKey.KeySize != 256)
        {
            throw new ArgumentException(
                "Device request verification requires an ECDSA P-256 key.",
                nameof(verificationKey));
        }

        this.verificationKey = verificationKey;
    }

    public bool Verify(
        SignedDeviceRequest request,
        string expectedMethod,
        string expectedPathAndQuery,
        ReadOnlySpan<byte> expectedBody)
    {
        ArgumentNullException.ThrowIfNull(request);
        var expected = new DeviceRequestPayload(
            request.Payload.DeviceId,
            request.Payload.EnrollmentId,
            request.Payload.CredentialSequence,
            request.Payload.TimestampUtc,
            request.Payload.Nonce,
            expectedMethod,
            expectedPathAndQuery,
            Convert.ToHexString(SHA256.HashData(expectedBody)).ToLowerInvariant());
        if (!CryptographicOperations.FixedTimeEquals(
                request.Payload.GetCanonicalBytes(),
                expected.GetCanonicalBytes()))
        {
            return false;
        }

        return verificationKey.VerifyData(
            request.Payload.GetCanonicalBytes(),
            request.GetSignatureBytes(),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }
}
