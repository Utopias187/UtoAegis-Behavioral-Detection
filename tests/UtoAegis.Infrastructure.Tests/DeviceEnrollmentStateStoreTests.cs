using UtoAegis.Core.Management;
using UtoAegis.Infrastructure.Management;

namespace UtoAegis.Infrastructure.Tests;

[TestClass]
public sealed class DeviceEnrollmentStateStoreTests
{
    private string testDirectory = null!;

    [TestInitialize]
    public void Initialize()
    {
        testDirectory = Path.Combine(
            Path.GetTempPath(),
            "UtoAegis.EnrollmentState.Tests",
            Guid.NewGuid().ToString("N"));
    }

    [TestCleanup]
    public void Cleanup()
    {
        if (Directory.Exists(testDirectory))
        {
            Directory.Delete(testDirectory, recursive: true);
        }
    }

    [TestMethod]
    public async Task AcceptAsync_HigherSequence_PersistsCredential()
    {
        var store = CreateStore();
        await store.AcceptAsync(CreateVerified(1, 'a'));

        var result = await store.AcceptAsync(CreateVerified(2, 'b', ring: "pilot"));
        var loaded = await store.LoadAsync();

        Assert.AreEqual(2L, result.CredentialSequence);
        Assert.AreEqual("pilot", loaded!.RolloutRing);
    }

    [TestMethod]
    public async Task AcceptAsync_LowerSequence_RejectsRollback()
    {
        var store = CreateStore();
        await store.AcceptAsync(CreateVerified(2, 'a'));

        var exception = await Assert.ThrowsExactlyAsync<DeviceManagementException>(
            async () => await store.AcceptAsync(CreateVerified(1, 'b')));

        StringAssert.Contains(exception.Message, "anti-rollback floor");
    }

    [TestMethod]
    public async Task AcceptAsync_SameSequenceChangedHash_RejectsEquivocation()
    {
        var store = CreateStore();
        await store.AcceptAsync(CreateVerified(1, 'a'));

        var exception = await Assert.ThrowsExactlyAsync<DeviceManagementException>(
            async () => await store.AcceptAsync(CreateVerified(1, 'b')));

        StringAssert.Contains(exception.Message, "without increasing");
    }

    [TestMethod]
    public async Task AcceptAsync_LowerRevocationGeneration_RejectsRollback()
    {
        var store = CreateStore();
        await store.AcceptAsync(CreateVerified(1, 'a', revocationGeneration: 4));

        var exception = await Assert.ThrowsExactlyAsync<DeviceManagementException>(
            async () => await store.AcceptAsync(CreateVerified(2, 'b', revocationGeneration: 3)));

        StringAssert.Contains(exception.Message, "revocation generation");
    }

    [TestMethod]
    public async Task AcceptAsync_RevokedThenActive_RejectsReactivation()
    {
        var store = CreateStore();
        await store.AcceptAsync(CreateVerified(
            1,
            'a',
            status: DeviceEnrollmentStatus.Revoked,
            revocationGeneration: 5));

        var exception = await Assert.ThrowsExactlyAsync<DeviceManagementException>(
            async () => await store.AcceptAsync(CreateVerified(
                2,
                'b',
                status: DeviceEnrollmentStatus.Active,
                revocationGeneration: 6)));

        StringAssert.Contains(exception.Message, "cannot be reactivated");
    }

    [TestMethod]
    public async Task AcceptAsync_ChangedEnrollmentId_RejectsReplacement()
    {
        var store = CreateStore();
        await store.AcceptAsync(CreateVerified(1, 'a'));
        var changed = CreateVerified(2, 'b', enrollmentId: "enrollment-2");

        var exception = await Assert.ThrowsExactlyAsync<DeviceManagementException>(
            async () => await store.AcceptAsync(changed));

        StringAssert.Contains(exception.Message, "explicit reset");
    }

    private DeviceEnrollmentStateStore CreateStore() =>
        new(Path.Combine(testDirectory, "state", "enrollment.json"));

    private static VerifiedDeviceEnrollmentCredential CreateVerified(
        long sequence,
        char hashCharacter,
        string ring = "canary",
        DeviceEnrollmentStatus status = DeviceEnrollmentStatus.Active,
        long revocationGeneration = 1,
        string enrollmentId = "enrollment-1")
    {
        var credential = new DeviceEnrollmentCredential(
            sequence,
            enrollmentId,
            new string('a', 32),
            new string('b', 64),
            new RolloutRing(ring),
            status,
            revocationGeneration,
            new DateTimeOffset(2026, 11, 17, 12, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 12, 17, 12, 0, 0, TimeSpan.Zero),
            new Uri("https://management.example/"),
            "enrollment-key-1");
        return new VerifiedDeviceEnrollmentCredential(
            credential,
            new string(hashCharacter, 64));
    }
}
