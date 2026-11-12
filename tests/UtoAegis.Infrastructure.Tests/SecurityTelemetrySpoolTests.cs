using System.Text.Json;
using UtoAegis.Core.Telemetry;
using UtoAegis.Infrastructure.Telemetry;

namespace UtoAegis.Infrastructure.Tests;

[TestClass]
public sealed class SecurityTelemetrySpoolTests
{
    private string _testDirectory = null!;

    [TestInitialize]
    public void Initialize()
    {
        _testDirectory = Path.Combine(
            Path.GetTempPath(),
            "UtoAegis.Tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testDirectory);
    }

    [TestCleanup]
    public void Cleanup()
    {
        if (Directory.Exists(_testDirectory))
        {
            Directory.Delete(_testDirectory, recursive: true);
        }
    }

    [TestMethod]
    public async Task AppendAndReadBatch_PreservesVerifiedSequenceAndPayload()
    {
        using var spool = new SecurityTelemetrySpool(Path.Combine(_testDirectory, "spool"));

        var first = await spool.AppendAsync(CreateEvent("detection", "one"));
        var second = await spool.AppendAsync(CreateEvent("response", "two"));
        var batch = await spool.ReadBatchAsync(SecurityTelemetryCheckpoint.Empty, 10);

        Assert.AreEqual(1L, first.Sequence);
        Assert.AreEqual(2L, second.Sequence);
        Assert.AreEqual(first.Hash, second.PreviousHash);
        Assert.HasCount(2, batch);
        Assert.AreEqual("detection", batch[0].EventType);
        Assert.AreEqual("two", batch[1].Payload.GetProperty("value").GetString());
    }

    [TestMethod]
    public async Task InitializeAsync_ModifiedRecord_RejectsTamperedChain()
    {
        var root = Path.Combine(_testDirectory, "spool");
        using (var spool = new SecurityTelemetrySpool(root))
        {
            await spool.AppendAsync(CreateEvent("detection", "original"));
        }

        var recordPath = Directory.GetFiles(Path.Combine(root, "records"), "*.json").Single();
        var text = await File.ReadAllTextAsync(recordPath);
        await File.WriteAllTextAsync(recordPath, text.Replace("original", "modified", StringComparison.Ordinal));
        using var reopened = new SecurityTelemetrySpool(root);

        await Assert.ThrowsExactlyAsync<SecurityTelemetryException>(
            () => reopened.InitializeAsync().AsTask());
    }

    [TestMethod]
    public async Task BoundedSpool_StaleCheckpoint_ReportsDeliveryGap()
    {
        using var spool = new SecurityTelemetrySpool(
            Path.Combine(_testDirectory, "spool"),
            new SecurityTelemetrySpoolOptions(maximumRecords: 2));
        await spool.AppendAsync(CreateEvent("health", "one"));
        await spool.AppendAsync(CreateEvent("health", "two"));
        await spool.AppendAsync(CreateEvent("health", "three"));

        var exception = await Assert.ThrowsExactlyAsync<SecurityTelemetryException>(
            () => spool.ReadBatchAsync(SecurityTelemetryCheckpoint.Empty, 10).AsTask());

        StringAssert.Contains(exception.Message, "fallen behind");
        Assert.HasCount(2, Directory.GetFiles(Path.Combine(_testDirectory, "spool", "records")));
    }

    [TestMethod]
    public async Task InitializeAsync_PreAnchorRecordLeftByInterruptedPrune_IsIgnored()
    {
        var root = Path.Combine(_testDirectory, "spool");
        string prunedRecord;
        using (var spool = new SecurityTelemetrySpool(
                   root,
                   new SecurityTelemetrySpoolOptions(maximumRecords: 2)))
        {
            await spool.AppendAsync(CreateEvent("health", "one"));
            var firstPath = Path.Combine(root, "records", "00000000000000000001.json");
            prunedRecord = await File.ReadAllTextAsync(firstPath);
            await spool.AppendAsync(CreateEvent("health", "two"));
            await spool.AppendAsync(CreateEvent("health", "three"));
        }

        await File.WriteAllTextAsync(
            Path.Combine(root, "records", "00000000000000000001.json"),
            prunedRecord);
        using var reopened = new SecurityTelemetrySpool(
            root,
            new SecurityTelemetrySpoolOptions(maximumRecords: 2));
        using var prunedDocument = JsonDocument.Parse(prunedRecord);

        await reopened.InitializeAsync();
        var records = await reopened.ReadBatchAsync(
            new SecurityTelemetryCheckpoint(1, prunedDocument
                .RootElement.GetProperty("hash").GetString()!),
            10);

        Assert.HasCount(2, records);
        Assert.AreEqual(2L, records[0].Sequence);
        Assert.AreEqual(3L, records[1].Sequence);
    }

    [TestMethod]
    public async Task CheckpointStore_BackwardSave_IsRejected()
    {
        using var store = new SecurityTelemetryCheckpointStore(
            Path.Combine(_testDirectory, "checkpoints", "service.json"));
        var newer = new SecurityTelemetryCheckpoint(2, new string('a', 64));
        await store.SaveAsync(newer);

        await Assert.ThrowsExactlyAsync<SecurityTelemetryException>(
            () => store.SaveAsync(new SecurityTelemetryCheckpoint(1, new string('b', 64))).AsTask());
        Assert.AreEqual(newer, await store.LoadAsync());
    }

    [TestMethod]
    public void Event_NonObjectPayload_IsRejected()
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => new SecurityTelemetryEvent(
                DateTimeOffset.UtcNow,
                "service",
                "health",
                "endpoint-001",
                "run-1",
                "[\"not\",\"an\",\"object\"]"));
    }

    private static SecurityTelemetryEvent CreateEvent(string eventType, string value) =>
        new(
            new DateTimeOffset(2026, 11, 11, 12, 0, 0, TimeSpan.Zero),
            "monitor",
            eventType,
            "endpoint-001",
            $"correlation-{value}",
            JsonSerializer.Serialize(new { value }));
}
