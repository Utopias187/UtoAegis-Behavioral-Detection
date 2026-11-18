using UtoAegis.Core.Behavior;

namespace UtoAegis.Core.Tests;

[TestClass]
public sealed class BehaviorDetectionCoordinatorTests
{
    private static readonly Guid Generation = Guid.Parse("2ddf5e60-d0ee-4a9e-b173-b077a3185e95");
    private static readonly BehaviorProcessInstance Process = new(Generation, 100, 1);

    [TestMethod]
    public void Accept_ProcessEvents_MaintainsOneWindowAndClosesOnStop()
    {
        var coordinator = new BehaviorDetectionCoordinator();

        var started = coordinator.Accept(Event(1, BehaviorEventKind.ProcessStarted,
            new ProcessStartedPayload(
                new BehaviorArtifactIdentity("path-unavailable", null),
                BehaviorIntegrityClass.Medium)));
        var stopped = coordinator.Accept(Event(2, BehaviorEventKind.ProcessStopped,
            new ProcessStoppedPayload(0)));

        Assert.HasCount(1, started);
        Assert.HasCount(1, stopped);
        Assert.AreEqual(0, coordinator.ActiveProcessCount);
    }

    [TestMethod]
    public void Accept_ProviderHealth_ReassessesAllActiveProcesses()
    {
        var coordinator = new BehaviorDetectionCoordinator();
        coordinator.Accept(Event(1, BehaviorEventKind.ProcessStarted,
            new ProcessStartedPayload(
                new BehaviorArtifactIdentity("path-unavailable", null),
                BehaviorIntegrityClass.Medium)));

        var results = coordinator.Accept(Event(
            2,
            BehaviorEventKind.ProviderHealth,
            new ProviderHealthPayload(
                BehaviorEventSource.Collector,
                BehaviorProviderState.Unreliable,
                2),
            subject: null));

        Assert.HasCount(1, results);
        Assert.AreEqual(BehaviorProviderState.Unreliable, results[0].ProviderState);
    }

    [TestMethod]
    public void Accept_OutOfOrderOrForeignGeneration_Throws()
    {
        var coordinator = new BehaviorDetectionCoordinator();
        coordinator.Accept(Event(2, BehaviorEventKind.ProcessStopped, new ProcessStoppedPayload(0)));

        Assert.ThrowsExactly<ArgumentException>(() =>
            coordinator.Accept(Event(1, BehaviorEventKind.ProcessStopped, new ProcessStoppedPayload(0))));
        var foreign = new BehaviorProcessInstance(Guid.NewGuid(), 100, 1);
        Assert.ThrowsExactly<ArgumentException>(() => coordinator.Accept(new BehaviorEvent(
            Guid.NewGuid(),
            foreign.CollectorGenerationId,
            3,
            DateTimeOffset.UnixEpoch,
            null,
            BehaviorEventSource.Process,
            BehaviorEventKind.ProcessStopped,
            foreign,
            null,
            new ProcessStoppedPayload(0))));
    }

    private static BehaviorEvent Event(
        long sequence,
        BehaviorEventKind kind,
        BehaviorEventPayload payload,
        BehaviorProcessInstance? subject = null) => new(
            Guid.NewGuid(),
            Generation,
            sequence,
            DateTimeOffset.UnixEpoch.AddSeconds(sequence),
            null,
            kind == BehaviorEventKind.ProviderHealth
                ? BehaviorEventSource.Collector
                : BehaviorEventSource.Process,
            kind,
            kind == BehaviorEventKind.ProviderHealth ? null : subject ?? Process,
            null,
            payload);
}
