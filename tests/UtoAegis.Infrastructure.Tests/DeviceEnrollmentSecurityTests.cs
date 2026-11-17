using System.Security.Cryptography;
using System.Text.Json;
using UtoAegis.Core.Management;
using UtoAegis.Infrastructure.Management;
using UtoAegis.Infrastructure.ThreatIntelligence;

namespace UtoAegis.Infrastructure.Tests;

[TestClass]
public sealed class DeviceEnrollmentSecurityTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 11, 17, 20, 0, 0, TimeSpan.Zero);

    private ECDsa deviceKey = null!;
    private ECDsa authorityKey = null!;
    private DeviceIdentityState identity = null!;

    [TestInitialize]
    public void Initialize()
    {
        deviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        authorityKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        identity = new DeviceIdentityState(
            Guid.NewGuid().ToString("N"),
            "UtoAegis.Device.Test",
            Convert.ToHexString(
                SHA256.HashData(deviceKey.ExportSubjectPublicKeyInfo())).ToLowerInvariant(),
            Now.AddMinutes(-1));
    }

    [TestCleanup]
    public void Cleanup()
    {
        deviceKey.Dispose();
        authorityKey.Dispose();
    }

    [TestMethod]
    public void EnrollmentProof_ExactAuthorityAndToken_VerifiesPossession()
    {
        using var token = EnrollmentBootstrapToken.Generate();
        var proof = new DeviceEnrollmentProofSigner(deviceKey, identity).Sign(
            token,
            Now,
            new string('a', 32),
            new Uri("https://management.example"));

        var verified = CreateProofVerifier().Verify(
            proof,
            token,
            new Uri("https://management.example/"));

        Assert.AreEqual(identity.DeviceId, verified.DeviceId);
        Assert.AreEqual(identity.PublicKeySha256, verified.PublicKeySha256);
    }

    [TestMethod]
    public void EnrollmentProof_DifferentToken_RejectsProof()
    {
        using var token = EnrollmentBootstrapToken.Generate();
        using var different = EnrollmentBootstrapToken.Generate();
        var proof = new DeviceEnrollmentProofSigner(deviceKey, identity).Sign(
            token,
            Now,
            new string('a', 32),
            new Uri("https://management.example"));

        Assert.ThrowsExactly<DeviceManagementException>(() =>
            CreateProofVerifier().Verify(
                proof,
                different,
                new Uri("https://management.example")));
    }

    [TestMethod]
    public void EnrollmentProof_OldTimestamp_RejectsProof()
    {
        using var token = EnrollmentBootstrapToken.Generate();
        var proof = new DeviceEnrollmentProofSigner(deviceKey, identity).Sign(
            token,
            Now.AddMinutes(-7),
            new string('a', 32),
            new Uri("https://management.example"));

        var exception = Assert.ThrowsExactly<DeviceManagementException>(() =>
            CreateProofVerifier().Verify(
                proof,
                token,
                new Uri("https://management.example")));

        StringAssert.Contains(exception.Message, "validity window");
    }

    [TestMethod]
    public void EnrollmentProof_TamperedPublicKey_RejectsProof()
    {
        using var token = EnrollmentBootstrapToken.Generate();
        var proof = new DeviceEnrollmentProofSigner(deviceKey, identity).Sign(
            token,
            Now,
            new string('a', 32),
            new Uri("https://management.example"));
        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var changedPayload = new DeviceEnrollmentProofPayload(
            proof.Payload.DeviceId,
            Convert.ToBase64String(otherKey.ExportSubjectPublicKeyInfo()),
            proof.Payload.BootstrapTokenSha256,
            proof.Payload.TimestampUtc,
            proof.Payload.Nonce,
            proof.Payload.ManagementOrigin);
        var changed = new SignedDeviceEnrollmentProof(changedPayload, proof.SignatureBase64);

        Assert.ThrowsExactly<DeviceManagementException>(() =>
            CreateProofVerifier().Verify(changed, token, proof.Payload.ManagementOrigin));
    }

    [TestMethod]
    public void Credential_ValidSignatureAndIdentity_AcceptsCredential()
    {
        var (bytes, signature) = CreateCredential();

        var verified = CreateCredentialVerifier().Verify(bytes, signature, identity);

        Assert.AreEqual(7L, verified.Credential.CredentialSequence);
        Assert.AreEqual("canary", verified.Credential.RolloutRing.Value);
        Assert.AreEqual(DeviceEnrollmentStatus.Active, verified.Credential.Status);
    }

    [TestMethod]
    public void Credential_TamperedRing_RejectsSignature()
    {
        var (bytes, signature) = CreateCredential();
        bytes = System.Text.Encoding.UTF8.GetBytes(
            System.Text.Encoding.UTF8.GetString(bytes).Replace("canary", "stable"));

        Assert.ThrowsExactly<DeviceManagementException>(() =>
            CreateCredentialVerifier().Verify(bytes, signature, identity));
    }

    [TestMethod]
    public void Credential_DifferentDevice_RejectsBinding()
    {
        var (bytes, signature) = CreateCredential(deviceId: new string('f', 32));

        var exception = Assert.ThrowsExactly<DeviceManagementException>(() =>
            CreateCredentialVerifier().Verify(bytes, signature, identity));

        StringAssert.Contains(exception.Message, "different device");
    }

    [TestMethod]
    public void Credential_Expired_RejectsCredential()
    {
        var (bytes, signature) = CreateCredential(
            issuedUtc: Now.AddDays(-2),
            expiresUtc: Now.AddHours(-1));

        var exception = Assert.ThrowsExactly<DeviceManagementException>(() =>
            CreateCredentialVerifier().Verify(bytes, signature, identity));

        StringAssert.Contains(exception.Message, "expired");
    }

    [TestMethod]
    public void Credential_RevokedStatus_RemainsAuthenticated()
    {
        var (bytes, signature) = CreateCredential(
            status: DeviceEnrollmentStatus.Revoked,
            revocationGeneration: 4);

        var verified = CreateCredentialVerifier().Verify(bytes, signature, identity);

        Assert.AreEqual(DeviceEnrollmentStatus.Revoked, verified.Credential.Status);
        Assert.AreEqual(4L, verified.Credential.RevocationGeneration);
    }

    private static DeviceEnrollmentProofVerifier CreateProofVerifier() =>
        new(new FixedTimeProvider(Now));

    private SignedDeviceEnrollmentCredentialVerifier CreateCredentialVerifier()
    {
        var key = new TrustedThreatSigningKey(
            "enrollment-key-1",
            authorityKey.ExportSubjectPublicKeyInfoPem());
        return new SignedDeviceEnrollmentCredentialVerifier(
            new ThreatTrustStore([key]),
            new FixedTimeProvider(Now));
    }

    private (byte[] Bytes, string Signature) CreateCredential(
        string? deviceId = null,
        DeviceEnrollmentStatus status = DeviceEnrollmentStatus.Active,
        long revocationGeneration = 1,
        DateTimeOffset? issuedUtc = null,
        DateTimeOffset? expiresUtc = null)
    {
        var document = new
        {
            schemaVersion = DeviceEnrollmentCredential.CurrentSchemaVersion,
            algorithm = DeviceEnrollmentCredential.SignatureAlgorithm,
            credentialSequence = 7,
            enrollmentId = "enrollment-1",
            deviceId = deviceId ?? identity.DeviceId,
            publicKeySha256 = identity.PublicKeySha256,
            rolloutRing = "canary",
            status = status.ToString(),
            revocationGeneration,
            issuedUtc = issuedUtc ?? Now.AddHours(-1),
            expiresUtc = expiresUtc ?? Now.AddDays(30),
            managementOrigin = "https://management.example/",
            keyId = "enrollment-key-1"
        };
        var bytes = JsonSerializer.SerializeToUtf8Bytes(document);
        var signature = authorityKey.SignData(
            bytes,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence);
        return (bytes, Convert.ToBase64String(signature));
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
