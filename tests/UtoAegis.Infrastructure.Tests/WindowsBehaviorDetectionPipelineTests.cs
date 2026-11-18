using UtoAegis.Core.Behavior;
using UtoAegis.Infrastructure.Behavior;

namespace UtoAegis.Infrastructure.Tests;

[TestClass]
public sealed class WindowsBehaviorDetectionPipelineTests
{
    private static readonly Guid Generation = Guid.Parse("3dd28516-bda0-445d-b875-b0af5715b8e1");

    [TestMethod]
    public void Process_CorrelatedProviderRecords_ReturnsReviewAssessment()
    {
        using var pipeline = new WindowsBehaviorDetectionPipeline(16, Generation);
        pipeline.Process(Start());

        pipeline.Process(new WindowsRegistryChangedRecord(
            42,
            100,
            @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Demo",
            BehaviorOperation.Modified));
        var results = pipeline.Process(new WindowsNetworkConnectedRecord(
            42,
            100,
            BehaviorNetworkProtocol.Tcp,
            BehaviorNetworkDirection.Outbound,
            System.Net.IPAddress.Parse("8.8.8.8"),
            443));

        Assert.HasCount(1, results);
        Assert.AreEqual(38, results[0].Score);
    }

    [TestMethod]
    public void Process_MalformedProviderRecord_IsIgnored()
    {
        using var pipeline = new WindowsBehaviorDetectionPipeline(16, Generation);
        pipeline.Process(Start());

        var results = pipeline.Process(new WindowsFileChangedRecord(
            42,
            100,
            "bad\npath",
            BehaviorOperation.Modified));

        Assert.IsEmpty(results);
    }

    [TestMethod]
    public void CompareSnapshots_EmitsStartsBeforeStopsDeterministically()
    {
        var previous = new[]
        {
            new WindowsProcessSnapshotSource.ProcessSnapshot(8, 80, null),
            new WindowsProcessSnapshotSource.ProcessSnapshot(7, 70, null)
        };
        var current = new[]
        {
            new WindowsProcessSnapshotSource.ProcessSnapshot(9, 90, null),
            new WindowsProcessSnapshotSource.ProcessSnapshot(8, 80, null)
        };

        var records = WindowsProcessSnapshotSource.CompareSnapshots(
            previous,
            current,
            DateTimeOffset.UnixEpoch);

        Assert.HasCount(2, records);
        Assert.IsInstanceOfType<WindowsProcessStartedRecord>(records[0]);
        Assert.IsInstanceOfType<WindowsProcessStoppedRecord>(records[1]);
    }

    private static WindowsProcessStartedRecord Start() => new(
        42,
        100,
        null,
        null,
        @"C:\sample.exe",
        null,
        BehaviorIntegrityClass.Medium);
}
