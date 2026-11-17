using UtoAegis.Core.Management;
using UtoAegis.Core.Response;
using UtoAegis.Core.RuntimeIntegrity;
using UtoAegis.Infrastructure.Management;
using UtoAegis.Infrastructure.RuntimeIntegrity;

namespace UtoAegis.Infrastructure.Tests;

[TestClass]
public sealed class PolicyAcknowledgementStoreTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 11, 17, 23, 30, 0, TimeSpan.Zero);

    private string testDirectory = null!;

    [TestInitialize]
    public void Initialize()
    {
        testDirectory = Path.Combine(
            Path.GetTempPath(),
            "UtoAegis.PolicyAcknowledgement.Tests",
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
    public async Task RecordPendingAsync_RetrySamePolicy_PreservesExactAcknowledgement()
    {
        var store = CreateStore();
        var first = await store.RecordPendingAsync(CreatePolicy(), CreateEnrollment(), Now);

        var retry = await store.RecordPendingAsync(
            CreatePolicy(),
            CreateEnrollment(),
            Now.AddMinutes(1));
        var loaded = await CreateStore().LoadAsync();

        Assert.IsTrue(retry.IsPending);
        Assert.AreEqual(first.Acknowledgement.AcknowledgementId, retry.Acknowledgement.AcknowledgementId);
        CollectionAssert.AreEqual(
            first.Acknowledgement.GetCanonicalBytes(),
            loaded!.Acknowledgement.GetCanonicalBytes());
    }

    [TestMethod]
    public async Task MarkDeliveredAsync_ExactConfirmation_PersistsDelivery()
    {
        var store = CreateStore();
        var pending = await store.RecordPendingAsync(CreatePolicy(), CreateEnrollment(), Now);

        var delivered = await store.MarkDeliveredAsync(
            pending.Acknowledgement.AcknowledgementId,
            Now.AddMinutes(2));

        Assert.IsFalse(delivered.IsPending);
        Assert.AreEqual(Now.AddMinutes(2), delivered.DeliveredUtc);
        Assert.IsFalse((await CreateStore().LoadAsync())!.IsPending);
    }

    [TestMethod]
    public async Task MarkDeliveredAsync_DifferentConfirmation_KeepsPending()
    {
        var store = CreateStore();
        await store.RecordPendingAsync(CreatePolicy(), CreateEnrollment(), Now);

        var exception = await Assert.ThrowsExactlyAsync<DeviceManagementException>(
            async () => await store.MarkDeliveredAsync(
                new string('f', 32),
                Now.AddMinutes(2)));

        StringAssert.Contains(exception.Message, "does not match");
        Assert.IsTrue((await store.LoadAsync())!.IsPending);
    }

    [TestMethod]
    public async Task RecordPendingAsync_HigherPolicyWhilePending_RejectsReplacement()
    {
        var store = CreateStore();
        await store.RecordPendingAsync(CreatePolicy(), CreateEnrollment(), Now);

        var exception = await Assert.ThrowsExactlyAsync<DeviceManagementException>(
            async () => await store.RecordPendingAsync(
                CreatePolicy(sequence: 18, hashCharacter: 'd'),
                CreateEnrollment(),
                Now.AddMinutes(3)));

        StringAssert.Contains(exception.Message, "must be delivered");
    }

    [TestMethod]
    public async Task RecordPendingAsync_HigherPolicyAfterDelivery_CreatesNewRecord()
    {
        var store = CreateStore();
        var first = await store.RecordPendingAsync(CreatePolicy(), CreateEnrollment(), Now);
        await store.MarkDeliveredAsync(first.Acknowledgement.AcknowledgementId, Now.AddMinutes(1));

        var next = await store.RecordPendingAsync(
            CreatePolicy(sequence: 18, hashCharacter: 'd'),
            CreateEnrollment(),
            Now.AddMinutes(2));

        Assert.IsTrue(next.IsPending);
        Assert.AreEqual(18L, next.Acknowledgement.PolicySequence);
        Assert.AreNotEqual(first.Acknowledgement.AcknowledgementId, next.Acknowledgement.AcknowledgementId);
    }

    [TestMethod]
    public async Task RecordPendingAsync_ChangedEnrollment_RejectsReplacement()
    {
        var store = CreateStore();
        var first = await store.RecordPendingAsync(CreatePolicy(), CreateEnrollment(), Now);
        await store.MarkDeliveredAsync(first.Acknowledgement.AcknowledgementId, Now.AddMinutes(1));
        var changed = CreateEnrollment() with { EnrollmentId = "enrollment-2" };

        var exception = await Assert.ThrowsExactlyAsync<DeviceManagementException>(
            async () => await store.RecordPendingAsync(
                CreatePolicy(sequence: 18, hashCharacter: 'd'),
                changed,
                Now.AddMinutes(2)));

        StringAssert.Contains(exception.Message, "cannot change");
    }

    [TestMethod]
    public async Task LoadAsync_UnknownProperty_RejectsState()
    {
        var store = CreateStore();
        await store.RecordPendingAsync(CreatePolicy(), CreateEnrollment(), Now);
        var path = GetStatePath();
        var json = await File.ReadAllTextAsync(path);
        await File.WriteAllTextAsync(path, json[..^1] + ",\"unexpected\":true}");

        await Assert.ThrowsExactlyAsync<DeviceManagementException>(
            async () => await CreateStore().LoadAsync());
    }

    private PolicyAcknowledgementStore CreateStore() => new(GetStatePath());

    private string GetStatePath() =>
        Path.Combine(testDirectory, "state", "policy-acknowledgement.json");

    private static DeviceEnrollmentStateSnapshot CreateEnrollment() =>
        new(
            3,
            new string('e', 64),
            "enrollment-1",
            new string('a', 32),
            new string('b', 64),
            "canary",
            DeviceEnrollmentStatus.Active,
            0,
            Now.AddDays(30),
            "https://management.example/");

    private static VerifiedRuntimePolicy CreatePolicy(
        long sequence = 17,
        char hashCharacter = 'c')
    {
        var manifest = new RuntimePolicyManifest(
            sequence,
            "endpoint-policy",
            "policy-key-1",
            Now.AddHours(-1),
            Now.AddDays(30),
            new ResponsePolicy(ResponseMode.ObserveOnly),
            [new RuntimeServicePolicy(
                "UtoAegis",
                @"C:\Program Files\UtoAegis\utoaegis-service.exe",
                new string('a', 64),
                @"NT SERVICE\UtoAegis",
                RuntimeServiceStartMode.DelayedAutomatic,
                true)],
            [],
            TimeSpan.FromMinutes(5),
            2,
            TimeSpan.FromHours(1));
        return new VerifiedRuntimePolicy(
            manifest,
            new string(hashCharacter, 64),
            @"C:\ProgramData\UtoAegis\policy");
    }
}
