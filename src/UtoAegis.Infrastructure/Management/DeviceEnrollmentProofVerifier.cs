using System.Security.Cryptography;
using UtoAegis.Core.Management;

namespace UtoAegis.Infrastructure.Management;

public sealed class DeviceEnrollmentProofVerifier
{
    private readonly TimeProvider timeProvider;
    private readonly TimeSpan maximumAge;
    private readonly TimeSpan clockSkew;

    public DeviceEnrollmentProofVerifier(
        TimeProvider? timeProvider = null,
        TimeSpan? maximumAge = null,
        TimeSpan? clockSkew = null)
    {
        this.maximumAge = maximumAge ?? TimeSpan.FromMinutes(5);
        this.clockSkew = clockSkew ?? TimeSpan.FromMinutes(1);
        if (this.maximumAge <= TimeSpan.Zero || this.maximumAge > TimeSpan.FromMinutes(15))
        {
            throw new ArgumentOutOfRangeException(nameof(maximumAge));
        }

        if (this.clockSkew < TimeSpan.Zero || this.clockSkew > TimeSpan.FromMinutes(5))
        {
            throw new ArgumentOutOfRangeException(nameof(clockSkew));
        }

        this.timeProvider = timeProvider ?? TimeProvider.System;
    }

    public VerifiedDeviceEnrollmentProof Verify(
        SignedDeviceEnrollmentProof proof,
        EnrollmentBootstrapToken bootstrapToken,
        Uri expectedManagementOrigin)
    {
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(bootstrapToken);
        var expectedOrigin = DeviceEnrollmentCredential.NormalizeManagementOrigin(
            expectedManagementOrigin);
        if (proof.Payload.ManagementOrigin != expectedOrigin ||
            !CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(proof.Payload.BootstrapTokenSha256),
                Convert.FromHexString(bootstrapToken.ComputeSha256())))
        {
            throw new DeviceManagementException(
                "The enrollment proof is not bound to the expected request authority.");
        }

        var now = timeProvider.GetUtcNow();
        if (proof.Payload.TimestampUtc > now + clockSkew ||
            proof.Payload.TimestampUtc < now - maximumAge - clockSkew)
        {
            throw new DeviceManagementException("The enrollment proof is outside its validity window.");
        }

        try
        {
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(
                Convert.FromBase64String(proof.Payload.PublicKeySpkiBase64),
                out var bytesRead);
            if (bytesRead != Convert.FromBase64String(proof.Payload.PublicKeySpkiBase64).Length ||
                key.KeySize != 256 ||
                !key.VerifyData(
                    proof.Payload.GetCanonicalBytes(),
                    proof.GetSignatureBytes(),
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            {
                throw new DeviceManagementException("The enrollment proof signature is not valid.");
            }
        }
        catch (DeviceManagementException)
        {
            throw;
        }
        catch (Exception exception) when (exception is CryptographicException or FormatException)
        {
            throw new DeviceManagementException("The enrollment proof public key is not valid.", exception);
        }

        return new VerifiedDeviceEnrollmentProof(
            proof.Payload.DeviceId,
            proof.Payload.PublicKeySpkiBase64,
            proof.Payload.PublicKeySha256,
            proof.Payload.TimestampUtc,
            proof.Payload.Nonce);
    }
}
