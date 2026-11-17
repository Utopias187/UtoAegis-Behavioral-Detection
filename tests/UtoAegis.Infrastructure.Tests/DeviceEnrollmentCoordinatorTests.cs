using System.Security.Cryptography;
using UtoAegis.Core.Management;
using UtoAegis.Infrastructure.Management;
using UtoAegis.Infrastructure.ThreatIntelligence;

namespace UtoAegis.Infrastructure.Tests;

[TestClass]
public sealed class DeviceEnrollmentCoordinatorTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 11, 18, 0, 0, 0, TimeSpan.Zero);

    private string testDirectory = null!;
    private ECDsa deviceKey = null!;
    private ECDsa authorityKey = null!;
    private DeviceIdentityState identity = null!;
    private SqliteEnrollmentBootstrapStore enrollmentStore = null!;
    private SqliteDeviceRequestReplayStore replayStore = null!;

    [TestInitialize]
    public async Task Initialize()
    {
        testDirectory = Path.Combine(
            Path.GetTempPath(), "UtoAegis.EnrollmentCoordinator.Tests", Guid.NewGuid().ToString("N"));
        deviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        authorityKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        identity = new DeviceIdentityState(
            Guid.NewGuid().ToString("N"),
            "UtoAegis.Device.Test",
            Convert.ToHexString(SHA256.HashData(deviceKey.ExportSubjectPublicKeyInfo())).ToLowerInvariant(),
            Now);
        enrollmentStore = new SqliteEnrollmentBootstrapStore(Path.Combine(testDirectory, "enrollment.db"));
        replayStore = new SqliteDeviceRequestReplayStore(Path.Combine(testDirectory, "replay.db"));
        await enrollmentStore.InitializeAsync();
        await replayStore.InitializeAsync();
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
    public async Task EnrollAsync_ValidProof_IssuesBoundCredential()
    {
        using var token = await IssueTokenAsync();
        var proof = CreateProof(token, 'a');

        var issued = await CreateCoordinator().EnrollAsync(proof, token);
        var verified = CreateCredentialVerifier().Verify(
            issued.CredentialBytes,
            issued.SignatureBase64,
            identity);

        Assert.AreEqual(identity.DeviceId, verified.Credential.DeviceId);
        Assert.AreEqual("canary", verified.Credential.RolloutRing.Value);
        Assert.AreEqual(DeviceEnrollmentStatus.Active, verified.Credential.Status);
        Assert.AreEqual(1L, verified.Credential.CredentialSequence);
    }

    [TestMethod]
    public async Task EnrollAsync_ReplayedProof_RejectsNonce()
    {
        using var token = await IssueTokenAsync();
        var proof = CreateProof(token, 'b');
        await CreateCoordinator().EnrollAsync(proof, token);

        var exception = await Assert.ThrowsExactlyAsync<DeviceManagementException>(
            async () => await CreateCoordinator().EnrollAsync(proof, token));

        StringAssert.Contains(exception.Message, "nonce");
    }

    [TestMethod]
    public async Task EnrollAsync_ConsumedTokenWithFreshNonce_RejectsAdmission()
    {
        using var token = await IssueTokenAsync();
        await CreateCoordinator().EnrollAsync(CreateProof(token, 'c'), token);

        var exception = await Assert.ThrowsExactlyAsync<DeviceManagementException>(
            async () => await CreateCoordinator().EnrollAsync(CreateProof(token, 'd'), token));

        StringAssert.Contains(exception.Message, "unavailable");
    }

    [TestMethod]
    public async Task EnrollAsync_DuplicateDevice_RollsBackTokenConsumption()
    {
        using var first = await IssueTokenAsync();
        await CreateCoordinator().EnrollAsync(CreateProof(first, 'e'), first);
        using var second = await IssueTokenAsync();

        await Assert.ThrowsExactlyAsync<DeviceManagementException>(
            async () => await CreateCoordinator().EnrollAsync(CreateProof(second, 'f'), second));
        var stillAvailable = await enrollmentStore.ConsumeAsync(
            second,
            new string('f', 32),
            Now.AddMinutes(1));

        Assert.IsNotNull(stillAvailable);
    }

    private async Task<EnrollmentBootstrapToken> IssueTokenAsync()
    {
        var token = EnrollmentBootstrapToken.Generate();
        await enrollmentStore.IssueAsync(token, new RolloutRing("canary"), Now, Now.AddHours(1));
        return token;
    }

    private SignedDeviceEnrollmentProof CreateProof(EnrollmentBootstrapToken token, char nonce) =>
        new DeviceEnrollmentProofSigner(deviceKey, identity).Sign(
            token, Now, new string(nonce, 32), new Uri("https://management.example/"));

    private DeviceEnrollmentCoordinator CreateCoordinator() =>
        new(
            new DeviceEnrollmentProofVerifier(new FixedTimeProvider(Now)),
            replayStore,
            enrollmentStore,
            new DeviceEnrollmentCredentialIssuer(authorityKey, "enrollment-key-1"),
            new Uri("https://management.example/"),
            new FixedTimeProvider(Now));

    private SignedDeviceEnrollmentCredentialVerifier CreateCredentialVerifier() =>
        new(
            new ThreatTrustStore([
                new TrustedThreatSigningKey(
                    "enrollment-key-1",
                    authorityKey.ExportSubjectPublicKeyInfoPem())]),
            new FixedTimeProvider(Now));

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
