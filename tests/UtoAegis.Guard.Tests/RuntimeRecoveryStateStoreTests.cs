using UtoAegis.Core.Response;
using UtoAegis.Core.RuntimeIntegrity;

namespace UtoAegis.Guard.Tests;

[TestClass]
public sealed class RuntimeRecoveryStateStoreTests
{
    private string testDirectory = null!;

    [TestInitialize]
    public void Initialize()
    {
        testDirectory = Path.Combine(
            Path.GetTempPath(),
            "UtoAegis.Guard.Tests",
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
    public async Task TryReserveAsync_AtBound_RejectsAdditionalRecovery()
    {
        var now = new DateTimeOffset(2026, 11, 12, 18, 0, 0, TimeSpan.Zero);
        var store = new RuntimeRecoveryStateStore(
            Path.Combine(testDirectory, "recovery.json"),
            new FixedTimeProvider(now));
        var policy = CreatePolicy(sequence: 7, maximumRecoveries: 2);

        Assert.IsTrue(await store.TryReserveAsync(policy, CancellationToken.None));
        Assert.IsTrue(await store.TryReserveAsync(policy, CancellationToken.None));
        Assert.IsFalse(await store.TryReserveAsync(policy, CancellationToken.None));
    }

    [TestMethod]
    public async Task TryReserveAsync_NewSignedSequence_ResetsBound()
    {
        var now = new DateTimeOffset(2026, 11, 12, 18, 0, 0, TimeSpan.Zero);
        var store = new RuntimeRecoveryStateStore(
            Path.Combine(testDirectory, "recovery.json"),
            new FixedTimeProvider(now));
        Assert.IsTrue(await store.TryReserveAsync(
            CreatePolicy(sequence: 7, maximumRecoveries: 1),
            CancellationToken.None));

        Assert.IsTrue(await store.TryReserveAsync(
            CreatePolicy(sequence: 8, maximumRecoveries: 1),
            CancellationToken.None));
    }

    [TestMethod]
    public async Task TryReserveAsync_RecoveryDisabled_RejectsWithoutState()
    {
        var store = new RuntimeRecoveryStateStore(
            Path.Combine(testDirectory, "recovery.json"));

        var accepted = await store.TryReserveAsync(
            CreatePolicy(sequence: 7, maximumRecoveries: 0),
            CancellationToken.None);

        Assert.IsFalse(accepted);
        Assert.IsFalse(File.Exists(Path.Combine(testDirectory, "recovery.json")));
    }

    private static RuntimePolicyManifest CreatePolicy(
        long sequence,
        int maximumRecoveries) =>
        new(
            sequence,
            "endpoint-policy",
            "policy-key-1",
            DateTimeOffset.UtcNow.AddHours(-1),
            DateTimeOffset.UtcNow.AddDays(1),
            new ResponsePolicy(),
            [new RuntimeServicePolicy(
                "UtoAegis",
                Path.GetFullPath("utoaegis-service.exe"),
                new string('a', 64),
                @"NT SERVICE\UtoAegis",
                RuntimeServiceStartMode.DelayedAutomatic,
                true)],
            [],
            TimeSpan.FromMinutes(5),
            maximumRecoveries,
            TimeSpan.FromHours(1));

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
