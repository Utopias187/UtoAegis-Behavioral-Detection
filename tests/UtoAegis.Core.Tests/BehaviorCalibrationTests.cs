using System.Text.Json;
using UtoAegis.Core.Behavior;

namespace UtoAegis.Core.Tests;

[TestClass]
public sealed class BehaviorCalibrationTests
{
    private static readonly Guid Generation = Guid.Parse("85a084d7-c35e-4583-9341-145eaa4863b9");
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    [TestMethod]
    public void CalibrationCorpus_MatchesLockedScoresVerdictsAndConfidence()
    {
        var engine = new BehaviorCorrelationEngine();
        foreach (var item in ReadCorpus())
        {
            var assessment = engine.Assess(BuildEvents(item));

            Assert.AreEqual(item.ExpectedScore, assessment.Score, item.Id);
            Assert.AreEqual(item.ExpectedVerdict, assessment.Verdict.ToString(), item.Id);
            Assert.AreEqual(item.ExpectedConfidence, assessment.Confidence, item.Id);
            Assert.AreEqual("utoaegis.behavior.default", assessment.PolicyId, item.Id);
            Assert.AreEqual(1, assessment.PolicyVersion, item.Id);
        }
    }

    [TestMethod]
    public void TwoHundredBenignFileChanges_RemainBelowReviewThreshold()
    {
        var item = new CalibrationCase(
            "high-volume-benign-file-activity",
            "Medium",
            0,
            0,
            0,
            200,
            "Healthy",
            20,
            "NoKnownThreat",
            100);

        var result = new BehaviorCorrelationEngine().Assess(BuildEvents(item));

        Assert.AreEqual(20, result.Score);
        Assert.AreEqual("NoKnownThreat", result.Verdict.ToString());
    }

    [TestMethod]
    public void Coordinator_LongProcessWindow_RemainsAtEventBound()
    {
        var coordinator = new BehaviorDetectionCoordinator();
        BehaviorAssessment? last = null;
        for (var sequence = 1; sequence <= 500; sequence++)
        {
            last = coordinator.Accept(Event(
                sequence,
                new BehaviorProcessInstance(Generation, 42, 1),
                BehaviorEventSource.FileSystem,
                BehaviorEventKind.FileChanged,
                new FileChangedPayload(
                    "path-sha256:" + new string('a', 64),
                    BehaviorOperation.Modified)))[0];
        }

        Assert.IsNotNull(last);
        Assert.IsLessThanOrEqualTo(BehaviorCorrelationEngine.MaximumEventCount, last!.EventCount);
    }

    [TestMethod]
    [Timeout(30_000)]
    public void Coordinator_ActiveProcesses_RemainAtProcessBound()
    {
        var coordinator = new BehaviorDetectionCoordinator();
        for (var sequence = 1; sequence <= BehaviorDetectionCoordinator.MaximumActiveProcessCount + 1; sequence++)
        {
            var process = new BehaviorProcessInstance(Generation, sequence, sequence);
            coordinator.Accept(Event(
                sequence,
                process,
                BehaviorEventSource.Process,
                BehaviorEventKind.ProcessStarted,
                new ProcessStartedPayload(
                    new BehaviorArtifactIdentity("path-unavailable", null),
                    BehaviorIntegrityClass.Medium)));
        }

        Assert.AreEqual(BehaviorDetectionCoordinator.MaximumActiveProcessCount, coordinator.ActiveProcessCount);
    }

    [TestMethod]
    [Timeout(30_000)]
    public void Ingestor_TenThousandCycles_RemainsEmptyAndLossless()
    {
        using var ingestor = new BoundedBehaviorEventIngestor(64, Generation);
        var process = new BehaviorProcessInstance(Generation, 42, 1);
        var draft = new BehaviorEventDraft(
            null,
            BehaviorEventSource.Process,
            BehaviorEventKind.ProcessStopped,
            process,
            null,
            new ProcessStoppedPayload(0));

        for (var index = 0; index < 10_000; index++)
        {
            Assert.IsTrue(ingestor.TryIngest(draft, out _));
            Assert.IsTrue(ingestor.TryRead(out _));
        }

        Assert.AreEqual(0, ingestor.Count);
        Assert.AreEqual(0L, ingestor.DroppedEventCount);
    }

    private static CalibrationCase[] ReadCorpus()
    {
        var path = Path.Combine(
            AppContext.BaseDirectory,
            "Fixtures",
            "Behavior",
            "behavior-calibration-corpus.json");
        return JsonSerializer.Deserialize<CalibrationCase[]>(File.ReadAllText(path), JsonOptions) ??
            throw new InvalidOperationException("The behavior calibration corpus is invalid.");
    }

    private static BehaviorEvent[] BuildEvents(CalibrationCase item)
    {
        var process = new BehaviorProcessInstance(Generation, 42, 1);
        var sequence = 1L;
        var events = new List<BehaviorEvent>
        {
            Event(
                sequence++,
                process,
                BehaviorEventSource.Process,
                BehaviorEventKind.ProcessStarted,
                new ProcessStartedPayload(
                    new BehaviorArtifactIdentity("path-unavailable", null),
                    Enum.Parse<BehaviorIntegrityClass>(item.Integrity)))
        };
        Add(item.PersistenceChanges, () => new RegistryChangedPayload(
            BehaviorRegistryLocation.RunKey,
            BehaviorOperation.Modified), BehaviorEventSource.Registry, BehaviorEventKind.RegistryChanged);
        Add(item.PublicConnections, () => new NetworkConnectedPayload(
            BehaviorNetworkProtocol.Tcp,
            BehaviorNetworkDirection.Outbound,
            BehaviorAddressScope.Public,
            443), BehaviorEventSource.Network, BehaviorEventKind.NetworkConnected);
        Add(item.InvalidImageLoads, () => new ImageLoadedPayload(
            new BehaviorArtifactIdentity("path-sha256:" + new string('b', 64), null),
            BehaviorSignatureState.Invalid), BehaviorEventSource.Image, BehaviorEventKind.ImageLoaded);
        Add(item.FileChanges, () => new FileChangedPayload(
            "path-sha256:" + new string('c', 64),
            BehaviorOperation.Modified), BehaviorEventSource.FileSystem, BehaviorEventKind.FileChanged);
        var state = Enum.Parse<BehaviorProviderState>(item.ProviderState);
        if (state != BehaviorProviderState.Healthy)
        {
            events.Add(Event(
                sequence++,
                subject: null,
                BehaviorEventSource.Collector,
                BehaviorEventKind.ProviderHealth,
                new ProviderHealthPayload(BehaviorEventSource.Collector, state, 1)));
        }

        return events.ToArray();

        void Add(
            int count,
            Func<BehaviorEventPayload> payload,
            BehaviorEventSource source,
            BehaviorEventKind kind)
        {
            for (var index = 0; index < count; index++)
            {
                events.Add(Event(sequence++, process, source, kind, payload()));
            }
        }
    }

    private static BehaviorEvent Event(
        long sequence,
        BehaviorProcessInstance? subject,
        BehaviorEventSource source,
        BehaviorEventKind kind,
        BehaviorEventPayload payload) => new(
            GuidFrom(sequence),
            Generation,
            sequence,
            DateTimeOffset.UnixEpoch.AddMilliseconds(sequence),
            null,
            source,
            kind,
            subject,
            null,
            payload);

    private static Guid GuidFrom(long value)
    {
        Span<byte> bytes = stackalloc byte[16];
        BitConverter.TryWriteBytes(bytes, value);
        return new Guid(bytes);
    }

    private sealed record CalibrationCase(
        string Id,
        string Integrity,
        int PersistenceChanges,
        int PublicConnections,
        int InvalidImageLoads,
        int FileChanges,
        string ProviderState,
        int ExpectedScore,
        string ExpectedVerdict,
        int ExpectedConfidence);
}
