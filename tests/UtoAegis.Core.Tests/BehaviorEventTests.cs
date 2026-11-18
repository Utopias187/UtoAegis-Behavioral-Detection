using UtoAegis.Core.Behavior;

namespace UtoAegis.Core.Tests;

[TestClass]
public sealed class BehaviorEventTests
{
    private static readonly Guid Generation = Guid.Parse("a3093028-22f2-4437-b5d2-f3936c61d55e");

    [TestMethod]
    public void ProcessInstance_InvalidIdentity_Throws()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new BehaviorProcessInstance(Guid.Empty, 1, 1));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
            new BehaviorProcessInstance(Generation, 0, 1));
    }

    [TestMethod]
    public void ProcessInstance_ReusedProcessId_RemainsDistinct()
    {
        var first = new BehaviorProcessInstance(Generation, 42, 1);
        var second = new BehaviorProcessInstance(Generation, 42, 9);

        Assert.AreNotEqual(first, second);
    }

    [TestMethod]
    public void ArtifactIdentity_InvalidTextOrHash_Throws()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new BehaviorArtifactIdentity("bad\npath", null));
        Assert.ThrowsExactly<ArgumentException>(() => new BehaviorArtifactIdentity(null, "bad"));
        Assert.ThrowsExactly<ArgumentException>(() => new BehaviorArtifactIdentity(null, null));
    }

    [TestMethod]
    public void Event_MismatchedPayload_Throws()
    {
        var process = new BehaviorProcessInstance(Generation, 42, 1);

        Assert.ThrowsExactly<ArgumentException>(() => new BehaviorEvent(
            Guid.NewGuid(),
            Generation,
            1,
            DateTimeOffset.UnixEpoch,
            null,
            BehaviorEventSource.Process,
            BehaviorEventKind.ProcessStarted,
            process,
            null,
            new ProcessStoppedPayload(0)));
    }

    [TestMethod]
    public void Ingestor_AssignsMonotonicSequences()
    {
        using var ingestor = new BoundedBehaviorEventIngestor(4, Generation);
        var process = new BehaviorProcessInstance(Generation, 42, 1);

        Assert.IsTrue(ingestor.TryIngest(Started(process), out var first));
        Assert.IsTrue(ingestor.TryIngest(Stopped(process), out var second));

        Assert.AreEqual(1L, first!.Sequence);
        Assert.AreEqual(2L, second!.Sequence);
        Assert.AreEqual(2, ingestor.Count);
    }

    [TestMethod]
    public void Ingestor_Overflow_EmitsDegradedHealthEventWhenCapacityReturns()
    {
        using var ingestor = new BoundedBehaviorEventIngestor(2, Generation);
        var process = new BehaviorProcessInstance(Generation, 42, 1);
        Assert.IsTrue(ingestor.TryIngest(Started(process), out _));
        Assert.IsTrue(ingestor.TryIngest(Stopped(process), out _));
        Assert.IsFalse(ingestor.TryIngest(Stopped(process), out _));

        Assert.IsTrue(ingestor.TryRead(out _));
        Assert.IsTrue(ingestor.TryRead(out _));
        Assert.IsTrue(ingestor.TryRead(out var health));

        Assert.AreEqual(3L, health!.Sequence);
        Assert.AreEqual(BehaviorEventKind.ProviderHealth, health.Kind);
        var payload = (ProviderHealthPayload)health.Payload;
        Assert.AreEqual(1L, payload.DroppedEventCount);
        Assert.AreEqual(BehaviorProviderState.Degraded, payload.State);
        Assert.AreEqual(1L, ingestor.DroppedEventCount);
    }

    [TestMethod]
    public void Ingestor_ForeignGeneration_Throws()
    {
        using var ingestor = new BoundedBehaviorEventIngestor(2, Generation);
        var foreign = new BehaviorProcessInstance(Guid.NewGuid(), 42, 1);

        Assert.ThrowsExactly<ArgumentException>(() => ingestor.TryIngest(Started(foreign), out _));
    }

    [TestMethod]
    public void Ingestor_InvalidCapacity_Throws()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new BoundedBehaviorEventIngestor(1));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
            new BoundedBehaviorEventIngestor(BoundedBehaviorEventIngestor.MaximumCapacity + 1));
    }

    private static BehaviorEventDraft Started(BehaviorProcessInstance process) => new(
        null,
        BehaviorEventSource.Process,
        BehaviorEventKind.ProcessStarted,
        process,
        null,
        new ProcessStartedPayload(
            new BehaviorArtifactIdentity("sha256:test", null),
            BehaviorIntegrityClass.Medium));

    private static BehaviorEventDraft Stopped(BehaviorProcessInstance process) => new(
        null,
        BehaviorEventSource.Process,
        BehaviorEventKind.ProcessStopped,
        process,
        null,
        new ProcessStoppedPayload(0));
}
