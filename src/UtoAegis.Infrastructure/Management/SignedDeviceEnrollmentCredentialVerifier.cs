using System.Security.Cryptography;
using UtoAegis.Core.Management;
using UtoAegis.Infrastructure.ThreatIntelligence;

namespace UtoAegis.Infrastructure.Management;

public sealed class SignedDeviceEnrollmentCredentialVerifier
{
    public const int MaximumSignatureTextLength = 256;

    private readonly ThreatTrustStore trustStore;
    private readonly TimeProvider timeProvider;
    private readonly TimeSpan clockSkew;

    public SignedDeviceEnrollmentCredentialVerifier(
        ThreatTrustStore trustStore,
        TimeProvider? timeProvider = null,
        TimeSpan? clockSkew = null)
    {
        ArgumentNullException.ThrowIfNull(trustStore);
        this.clockSkew = clockSkew ?? TimeSpan.FromMinutes(5);
        if (this.clockSkew < TimeSpan.Zero || this.clockSkew > TimeSpan.FromHours(1))
        {
            throw new ArgumentOutOfRangeException(nameof(clockSkew));
        }

        this.trustStore = trustStore;
        this.timeProvider = timeProvider ?? TimeProvider.System;
    }

    public VerifiedDeviceEnrollmentCredential Verify(
        ReadOnlyMemory<byte> credentialBytes,
        string signatureBase64,
        DeviceIdentityState identity)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(signatureBase64);
        ArgumentNullException.ThrowIfNull(identity);
        if (signatureBase64.Length > MaximumSignatureTextLength)
        {
            throw new DeviceManagementException("The enrollment credential signature is oversized.");
        }

        byte[] signature;
        try
        {
            signature = Convert.FromBase64String(signatureBase64);
        }
        catch (FormatException exception)
        {
            throw new DeviceManagementException(
                "The enrollment credential signature must be base64 text.",
                exception);
        }

        var credential = EnrollmentCredentialReader.Read(credentialBytes.Span);
        if (!trustStore.TryGetKey(credential.KeyId, out var key) || key is null)
        {
            throw new DeviceManagementException(
                $"Enrollment authority key '{credential.KeyId}' is not trusted.");
        }

        if (!key.Verify(credentialBytes.Span, signature))
        {
            throw new DeviceManagementException(
                "The enrollment credential signature is not valid.");
        }

        if (!string.Equals(credential.DeviceId, identity.DeviceId, StringComparison.Ordinal) ||
            !CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(credential.PublicKeySha256),
                Convert.FromHexString(identity.PublicKeySha256)))
        {
            throw new DeviceManagementException(
                "The enrollment credential is bound to a different device identity.");
        }

        var now = timeProvider.GetUtcNow();
        if (credential.IssuedUtc > now + clockSkew)
        {
            throw new DeviceManagementException("The enrollment credential is not valid yet.");
        }

        if (credential.ExpiresUtc <= now - clockSkew)
        {
            throw new DeviceManagementException("The enrollment credential has expired.");
        }

        return new VerifiedDeviceEnrollmentCredential(
            credential,
            Convert.ToHexString(SHA256.HashData(credentialBytes.Span)).ToLowerInvariant());
    }
}
