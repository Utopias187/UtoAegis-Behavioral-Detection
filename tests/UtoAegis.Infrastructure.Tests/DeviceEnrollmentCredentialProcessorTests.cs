using System.Security.Cryptography;
using System.Text.Json;
using UtoAegis.Core.Management;
using UtoAegis.Infrastructure.Management;
using UtoAegis.Infrastructure.ThreatIntelligence;

namespace UtoAegis.Infrastructure.Tests;

[TestClass]
public sealed class DeviceEnrollmentCredentialProcessorTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 11, 17, 20, 0, 0, TimeSpan.Zero);

    private string testDirectory = null!;
    private ECDsa deviceKey = null!;
    private ECDsa authorityKey = null!;
    private DeviceIdentityState identity = null!;

    [TestInitialize]
    public void Initialize()
    {
        testDirectory = Path.Combine(
            Path.GetTempPath(),
            "UtoAegis.CredentialProcessor.Tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(testDirectory);
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
        if (Directory.Exists(testDirectory))
        {
            Directory.Delete(testDirectory, recursive: true);
        }
    }

    [TestMethod]
    public async Task ApplyAsync_RevokedCredential_PersistsBeforeFailingClosed()
    {
        var processor = CreateProcessor();
        var (bytes, signature) = CreateCredential(
            2,
            DeviceEnrollmentStatus.Revoked,
            4);

        var exception = await Assert.ThrowsExactlyAsync<DeviceManagementException>(
            async () => await processor.ApplyAsync(bytes, signature, identity));
        var persisted = await CreateStateStore().LoadAsync();

        StringAssert.Contains(exception.Message, "revoked");
        Assert.AreEqual(DeviceEnrollmentStatus.Revoked, persisted!.Status);
        Assert.AreEqual(4L, persisted.RevocationGeneration);
    }

    [TestMethod]
    public async Task RequireActiveAsync_PersistedRevocation_RejectsAfterRestart()
    {
        var processor = CreateProcessor();
        var (bytes, signature) = CreateCredential(
            2,
            DeviceEnrollmentStatus.Revoked,
            4);
        await Assert.ThrowsExactlyAsync<DeviceManagementException>(
            async () => await processor.ApplyAsync(bytes, signature, identity));

        var exception = await Assert.ThrowsExactlyAsync<DeviceManagementException>(
            async () => await CreateProcessor().RequireActiveAsync());

        StringAssert.Contains(exception.Message, "revoked");
    }

    [TestMethod]
    public async Task ApplyAsync_ActiveAfterRevocation_RejectsReactivation()
    {
        var processor = CreateProcessor();
        var revoked = CreateCredential(2, DeviceEnrollmentStatus.Revoked, 4);
        await Assert.ThrowsExactlyAsync<DeviceManagementException>(
            async () => await processor.ApplyAsync(revoked.Bytes, revoked.Signature, identity));
        var active = CreateCredential(3, DeviceEnrollmentStatus.Active, 5);

        var exception = await Assert.ThrowsExactlyAsync<DeviceManagementException>(
            async () => await processor.ApplyAsync(active.Bytes, active.Signature, identity));

        StringAssert.Contains(exception.Message, "cannot be reactivated");
    }

    [TestMethod]
    public async Task RequireActiveAsync_ExpiredState_RejectsEnrollment()
    {
        var processor = CreateProcessor(Now.AddDays(-1));
        var active = CreateCredential(
            2,
            DeviceEnrollmentStatus.Active,
            1,
            Now.AddDays(-2),
            Now.AddHours(-1));
        await processor.ApplyAsync(active.Bytes, active.Signature, identity);

        var exception = await Assert.ThrowsExactlyAsync<DeviceManagementException>(
            async () => await CreateProcessor().RequireActiveAsync());

        StringAssert.Contains(exception.Message, "expired");
    }

    private DeviceEnrollmentCredentialProcessor CreateProcessor(DateTimeOffset? now = null) =>
        new(
            CreateVerifier(now),
            CreateStateStore(),
            new FixedTimeProvider(now ?? Now));

    private SignedDeviceEnrollmentCredentialVerifier CreateVerifier(DateTimeOffset? now = null)
    {
        var key = new TrustedThreatSigningKey(
            "enrollment-key-1",
            authorityKey.ExportSubjectPublicKeyInfoPem());
        return new SignedDeviceEnrollmentCredentialVerifier(
            new ThreatTrustStore([key]),
            new FixedTimeProvider(now ?? Now));
    }

    private DeviceEnrollmentStateStore CreateStateStore() =>
        new(Path.Combine(testDirectory, "state", "enrollment.json"));

    private (byte[] Bytes, string Signature) CreateCredential(
        long sequence,
        DeviceEnrollmentStatus status,
        long revocationGeneration,
        DateTimeOffset? issuedUtc = null,
        DateTimeOffset? expiresUtc = null)
    {
        var document = new
        {
            schemaVersion = DeviceEnrollmentCredential.CurrentSchemaVersion,
            algorithm = DeviceEnrollmentCredential.SignatureAlgorithm,
            credentialSequence = sequence,
            enrollmentId = "enrollment-1",
            deviceId = identity.DeviceId,
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
